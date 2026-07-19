use std::{env, error::Error, fmt, future::poll_fn, pin::Pin, thread, time::Duration};

use sd_notify::NotifyState;
use visa_local_rpc::{MAX_INNER_REQUEST_BYTES, MAX_INNER_RESPONSE_BYTES, ownership};
use visa_ownership_service::OwnershipServiceError;
use zbus::{
    Connection,
    export::futures_core::Stream,
    fdo::{DBusProxy, RequestNameFlags, RequestNameReply},
    message::Header,
    names::{BusName, WellKnownName},
};

use crate::{
    config::RuntimeConfig,
    fence::{ActivationError, AdmissionGate, GateError},
    peer::{LivePeerAdmission, PeerAdmissionError},
    sequencer::{StoreCallError, StoreSequencer, SubmitError},
};

const RECONNECT_DELAY: Duration = Duration::from_millis(100);
const DRAIN_POLL_DELAY: Duration = Duration::from_millis(1);
const MAX_QUEUED_MESSAGES_PER_CONNECTION: usize = 16;

#[derive(Debug)]
pub enum ServiceError {
    Bus(zbus::Error),
    Fdo(zbus::fdo::Error),
    Gate,
    NameNotAcquired(RequestNameReply),
    MissingNotifySocket,
    EmptyNotifySocket,
    Notify(std::io::Error),
    AuthorityTerminated(visa_ownership_service::OwnershipServiceError),
    WorkerStopped,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bus(error) => write!(formatter, "ownership D-Bus failure: {error}"),
            Self::Fdo(error) => write!(formatter, "ownership bus-daemon failure: {error}"),
            Self::Gate => formatter.write_str("ownership admission gate invariant failed"),
            Self::NameNotAcquired(reply) => {
                write!(formatter, "ownership service name was not acquired: {reply}")
            }
            Self::MissingNotifySocket => {
                formatter.write_str("NOTIFY_SOCKET is missing; ownership service is not ready")
            }
            Self::EmptyNotifySocket => {
                formatter.write_str("NOTIFY_SOCKET is empty; ownership service is not ready")
            }
            Self::Notify(error) => write!(formatter, "cannot deliver ownership READY=1: {error}"),
            Self::AuthorityTerminated(error) => {
                write!(formatter, "ownership authority terminated fail-closed: {error:?}")
            }
            Self::WorkerStopped => {
                formatter.write_str("ownership authority worker stopped fail-closed")
            }
        }
    }
}

impl Error for ServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bus(error) => Some(error),
            Self::Fdo(error) => Some(error),
            Self::Notify(error) => Some(error),
            Self::Gate
            | Self::NameNotAcquired(_)
            | Self::MissingNotifySocket
            | Self::EmptyNotifySocket
            | Self::AuthorityTerminated(_)
            | Self::WorkerStopped => None,
        }
    }
}

#[derive(Clone, Debug)]
struct OwnershipInterface {
    gate: AdmissionGate,
    sequencer: StoreSequencer,
    admission: LivePeerAdmission,
}

#[zbus::interface(name = "io.github.chenty2333.vISA.Ownership1")]
impl OwnershipInterface {
    async fn execute(
        &self,
        request_bytes: Vec<u8>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> zbus::fdo::Result<Vec<u8>> {
        if request_bytes.len() > MAX_INNER_REQUEST_BYTES {
            return Err(zbus::fdo::Error::LimitsExceeded(
                "ownership request exceeds the frozen inner-byte limit".to_owned(),
            ));
        }
        if header.unix_fds().unwrap_or(0) != 0 {
            return Err(zbus::fdo::Error::InvalidArgs(
                "ownership Execute does not accept business file descriptors".to_owned(),
            ));
        }
        let sender = header.sender().ok_or_else(|| {
            zbus::fdo::Error::AccessDenied(
                "ownership request has no bus-controlled unique sender".to_owned(),
            )
        })?;
        let permit = self.gate.reserve(sender.as_str()).map_err(map_gate_error)?;
        let admitted =
            self.admission.admit(&header, &request_bytes).await.map_err(map_peer_error)?;
        if admitted.bus_epoch != permit.epoch() {
            return Err(zbus::fdo::Error::Disconnected(
                "ownership request crossed a bus-connection epoch".to_owned(),
            ));
        }
        let bus_epoch = admitted.bus_epoch;
        let caller = admitted.caller;
        let process_fd = admitted.process_fd;
        let reply = self
            .sequencer
            .submit(&self.gate, permit, caller, request_bytes)
            .map_err(map_submit_error)?;
        // Queue insertion is the final application admission barrier. The
        // pidfd must pin the caller through that point, but O1 completion no
        // longer depends on the client process remaining alive.
        drop(process_fd);
        let reply = match reply.await {
            Ok(reply) => reply,
            Err(error) => {
                if error.is_terminal() {
                    self.gate.close_epoch(bus_epoch);
                    let _ = connection.clone().close().await;
                }
                return Err(map_store_error(error));
            }
        };
        if reply.len() > MAX_INNER_RESPONSE_BYTES {
            return Err(zbus::fdo::Error::LimitsExceeded(
                "ownership response exceeds the frozen inner-byte limit".to_owned(),
            ));
        }
        Ok(reply)
    }
}

/// Runs the ownership D-Bus process lifecycle on the async-io backend.
///
/// The first successfully acquired connection opens its epoch and delivers
/// READY while holding the same gate mutex used by request reservation. Later
/// same-process bus reconnects acquire a fresh epoch but never repeat READY.
pub(crate) fn run(
    gate: AdmissionGate,
    sequencer: StoreSequencer,
    config: RuntimeConfig,
) -> Result<(), ServiceError> {
    require_notify_socket()?;
    let mut ready_delivered = false;
    loop {
        let result = zbus::block_on(run_connection_epoch(
            gate.clone(),
            sequencer.clone(),
            &config,
            !ready_delivered,
        ));
        if !sequencer.is_healthy() {
            return Err(terminal_service_error(&sequencer));
        }
        match result {
            Ok(()) => ready_delivered = true,
            Err(error) if ready_delivered && reconnectable(&error) => {}
            Err(error) => return Err(error),
        }

        // A queued O1 call admitted before loss is allowed to finish. A new
        // epoch cannot open until its CompletionLease has been released.
        while !gate.is_drained() {
            if !sequencer.is_healthy() {
                return Err(terminal_service_error(&sequencer));
            }
            thread::sleep(DRAIN_POLL_DELAY);
        }
        thread::sleep(RECONNECT_DELAY);
    }
}

async fn run_connection_epoch(
    gate: AdmissionGate,
    sequencer: StoreSequencer,
    config: &RuntimeConfig,
    notify_on_activation: bool,
) -> Result<(), ServiceError> {
    let connection = zbus::connection::Builder::session()
        .map_err(ServiceError::Bus)?
        .max_queued(MAX_QUEUED_MESSAGES_PER_CONNECTION)
        .build()
        .await
        .map_err(ServiceError::Bus)?;
    let epoch = gate.begin_next_epoch().map_err(|_| ServiceError::Gate)?;
    let admission = LivePeerAdmission::new(&connection, config, epoch);
    let interface = OwnershipInterface { gate: gate.clone(), sequencer, admission };

    connection
        .object_server()
        .at(ownership::OBJECT_PATH, interface)
        .await
        .map_err(ServiceError::Bus)?;

    // Install the stream before RequestName so a loss cannot fall into the
    // acquire/subscription gap documented by zbus.
    let proxy = DBusProxy::new(&connection).await.map_err(ServiceError::Bus)?;
    let mut name_lost = proxy
        .receive_name_lost_with_args(&[(0, ownership::WELL_KNOWN_NAME)])
        .await
        .map_err(ServiceError::Bus)?;
    let reply = connection
        .request_name_with_flags(ownership::WELL_KNOWN_NAME, RequestNameFlags::DoNotQueue.into())
        .await
        .map_err(|error| match error {
            zbus::Error::NameTaken => ServiceError::NameNotAcquired(RequestNameReply::Exists),
            error => ServiceError::Bus(error),
        })?;
    if !matches!(reply, RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner) {
        return Err(ServiceError::NameNotAcquired(reply));
    }

    // Confirm the acquired name still resolves to this exact unique
    // connection immediately before opening admission and (once) READY.
    let service_name: WellKnownName<'_> =
        ownership::WELL_KNOWN_NAME.try_into().expect("frozen ownership service name is valid");
    let current_owner =
        proxy.get_name_owner(BusName::from(service_name)).await.map_err(ServiceError::Fdo)?;
    if connection.unique_name() != Some(&current_owner) {
        return Err(ServiceError::NameNotAcquired(RequestNameReply::Exists));
    }

    gate.activate_epoch_with(epoch, || if notify_on_activation { notify_ready() } else { Ok(()) })
        .map_err(|error| match error {
            ActivationError::Gate(_) => ServiceError::Gate,
            ActivationError::Callback(error) => error,
        })?;

    // Any exact NameLost signal, malformed signal, or stream termination is a
    // bus/name loss. Close admission before dropping the connection; already
    // admitted work remains protected by its CompletionLease and may finish.
    loop {
        let signal = poll_stream_next(&mut name_lost).await;
        let lost = match signal {
            Some(signal) => signal
                .args()
                .map(|arguments| arguments.name.as_str() == ownership::WELL_KNOWN_NAME)
                .unwrap_or(true),
            None => true,
        };
        if lost {
            gate.close_epoch(epoch);
            return Ok(());
        }
    }
}

async fn poll_stream_next<S>(stream: &mut S) -> Option<S::Item>
where
    S: Stream + Unpin,
{
    poll_fn(|context| Pin::new(&mut *stream).poll_next(context)).await
}

fn notify_ready() -> Result<(), ServiceError> {
    require_notify_socket()?;
    sd_notify::notify(&[NotifyState::Ready]).map_err(ServiceError::Notify)
}

fn require_notify_socket() -> Result<(), ServiceError> {
    let socket = env::var_os("NOTIFY_SOCKET").ok_or(ServiceError::MissingNotifySocket)?;
    if socket.is_empty() {
        return Err(ServiceError::EmptyNotifySocket);
    }
    Ok(())
}

fn reconnectable(error: &ServiceError) -> bool {
    matches!(error, ServiceError::Bus(_) | ServiceError::Fdo(_))
}

fn terminal_service_error(sequencer: &StoreSequencer) -> ServiceError {
    match sequencer.terminal_error() {
        Some(StoreCallError::Authority(error)) => ServiceError::AuthorityTerminated(error),
        Some(StoreCallError::WorkerStopped) | None => ServiceError::WorkerStopped,
    }
}

fn map_gate_error(error: GateError) -> zbus::fdo::Error {
    match error {
        GateError::AlreadyInFlight | GateError::NotDrained => {
            zbus::fdo::Error::LimitsExceeded("ownership mutation is already in flight".to_owned())
        }
        GateError::Closed | GateError::StaleEpoch | GateError::GenerationOverflow => {
            zbus::fdo::Error::Disconnected("ownership admission epoch is closed".to_owned())
        }
    }
}

fn map_peer_error(error: PeerAdmissionError) -> zbus::fdo::Error {
    match error {
        PeerAdmissionError::RequestTooLarge => zbus::fdo::Error::LimitsExceeded(
            "ownership request exceeds the frozen inner-byte limit".to_owned(),
        ),
        PeerAdmissionError::InvalidRequest => {
            zbus::fdo::Error::InvalidArgs("ownership request is not canonical wire v1".to_owned())
        }
        PeerAdmissionError::Bus => {
            zbus::fdo::Error::Disconnected("ownership peer admission lost the user bus".to_owned())
        }
        PeerAdmissionError::Host => zbus::fdo::Error::IOError(
            "ownership peer admission cannot inspect the local process".to_owned(),
        ),
        PeerAdmissionError::BusinessFileDescriptors
        | PeerAdmissionError::MissingSender
        | PeerAdmissionError::BindingMismatch
        | PeerAdmissionError::RoleOwnerMismatch
        | PeerAdmissionError::MissingCredential
        | PeerAdmissionError::WrongUid
        | PeerAdmissionError::InvalidPid
        | PeerAdmissionError::CredentialChanged
        | PeerAdmissionError::StrongerCredentialAppeared
        | PeerAdmissionError::ProcessExited
        | PeerAdmissionError::InvalidProcfs
        | PeerAdmissionError::InvalidExecutable
        | PeerAdmissionError::ExecutableChanged
        | PeerAdmissionError::ExecutableDigestMismatch => zbus::fdo::Error::AccessDenied(
            "ownership caller failed exact local peer admission".to_owned(),
        ),
    }
}

fn map_submit_error(error: SubmitError) -> zbus::fdo::Error {
    match error {
        SubmitError::Gate(error) => map_gate_error(error),
        SubmitError::QueueFull => {
            zbus::fdo::Error::LimitsExceeded("ownership mutation queue is full".to_owned())
        }
        SubmitError::WorkerStopped => {
            zbus::fdo::Error::Failed("ownership store sequencer stopped".to_owned())
        }
    }
}

fn map_store_error(error: StoreCallError) -> zbus::fdo::Error {
    match error {
        StoreCallError::Authority(OwnershipServiceError::CallerBindingConflict) => {
            zbus::fdo::Error::AccessDenied(
                "ownership caller process binding is stale or conflicting".to_owned(),
            )
        }
        StoreCallError::Authority(_) => {
            zbus::fdo::Error::Failed("ownership authority call failed".to_owned())
        }
        StoreCallError::WorkerStopped => {
            zbus::fdo::Error::Failed("ownership store sequencer stopped".to_owned())
        }
    }
}
