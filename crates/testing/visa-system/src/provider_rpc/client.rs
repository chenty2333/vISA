use std::{
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::Mutex,
    time::Duration,
};

use contract_core::{
    AuthorityGrant, BindingReceipt, EffectOutcome, EffectRequest, EntityRef, Extension,
    IdempotencyKey, Identity, JournalEntry, JournalPosition, LeaseEpoch, NodeIdentity, Rights,
    VersionedValue,
};
use substrate_api::{
    ActivationBundle, AuthorityPolicy, AuthorityPort, BindingPort, BindingRequest, CommitBundle,
    EffectRequestBinding, JournalPort, JournalScope, KvPort, LeasePort, LeaseRecord,
    OperationObservation, PreparedLeaseTransitions, ProfileDispatchAuthorization, ProfilePort,
    ProviderError, ProviderErrorKind, ReauthorizationRequest, TimerObservation, TimerPort,
    TimerRecovery,
};
use substrate_host::{FaultObservation, FaultPoint};

use super::{
    PROVIDER_RPC_SCHEMA_VERSION, ProviderLocator, ProviderLocatorError,
    wire::{
        MAX_FRAME_BYTES, Request, RequestEnvelope, ResponseEnvelope, ResponseOutcome, Value,
        WireActivationBundle, WireAuthorityPolicy, WireBindingRequest, WireCommitBundle,
        WireEffectRequestBinding, WireFaultPoint, WireJournalScope, WireLeaseRecord,
        WireProfileDispatchAuthorization, WireReauthorizationRequest, WireTimerRecovery,
    },
};

const RPC_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum ProviderRpcError {
    Locator(ProviderLocatorError),
    Io { operation: &'static str, path: PathBuf, source: io::Error },
    Protocol(String),
    Provider(ProviderError),
}

impl std::fmt::Display for ProviderRpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locator(source) => write!(formatter, "{source}"),
            Self::Io { operation, path, source } => {
                write!(formatter, "{operation} {}: {source}", path.display())
            }
            Self::Protocol(detail) => write!(formatter, "provider RPC protocol error: {detail}"),
            Self::Provider(error) => {
                write!(formatter, "provider error {:?} (retryable={})", error.kind, error.retryable)
            }
        }
    }
}

impl std::error::Error for ProviderRpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Locator(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Protocol(_) | Self::Provider(_) => None,
        }
    }
}

impl From<ProviderLocatorError> for ProviderRpcError {
    fn from(value: ProviderLocatorError) -> Self {
        Self::Locator(value)
    }
}

impl From<ProviderRpcError> for ProviderError {
    fn from(value: ProviderRpcError) -> Self {
        match value {
            ProviderRpcError::Locator(_) => {
                ProviderError::new(ProviderErrorKind::InvalidRequest, false)
            }
            ProviderRpcError::Io { .. } => ProviderError::new(ProviderErrorKind::Unavailable, true),
            ProviderRpcError::Protocol(_) => integrity_error(),
            ProviderRpcError::Provider(error) => error,
        }
    }
}

pub fn probe(locator: &str) -> Result<(), ProviderRpcError> {
    let locator = ProviderLocator::parse(locator)?;
    let mut session = RpcSession::connect(&locator)?;
    match session.call(Request::Ping)? {
        Value::Unit => Ok(()),
        _ => Err(ProviderRpcError::Protocol("ping returned the wrong value type".to_owned())),
    }
}

macro_rules! rpc_expect {
    ($provider:expr, $request:expr, $pattern:pat => $value:expr) => {{
        match $provider.call($request)? {
            $pattern => Ok($value),
            _ => Err(integrity_error()),
        }
    }};
}

pub struct NetworkProvider {
    locator: ProviderLocator,
    session: Mutex<RpcSession>,
}

impl NetworkProvider {
    pub fn connect(locator: &str, scope: JournalScope) -> Result<Self, ProviderRpcError> {
        let locator = ProviderLocator::parse(locator)?;
        let mut session = RpcSession::connect(&locator)?;
        match session.call(Request::Open {
            database_id: locator.database_id().to_owned(),
            scope: WireJournalScope::from(scope),
        })? {
            Value::Unit => Ok(Self { locator, session: Mutex::new(session) }),
            _ => Err(ProviderRpcError::Protocol("open returned the wrong value type".to_owned())),
        }
    }

    pub fn probe(locator: &str) -> Result<(), ProviderRpcError> {
        probe(locator)
    }

    pub fn locator(&self) -> &ProviderLocator {
        &self.locator
    }

    pub fn inject_failure_once(&mut self, point: FaultPoint) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::InjectFailure {
                point: WireFaultPoint::from(point)
            },
            Value::Unit => ()
        )
    }

    pub fn fault_observation(&self) -> Result<Option<FaultObservation>, ProviderError> {
        rpc_expect!(
            self,
            Request::FaultObservation,
            Value::OptionalFaultObservation(value) => value.map(Into::into)
        )
    }

    pub fn inspect_key_value(
        &self,
        resource: EntityRef,
        key: &[u8],
    ) -> Result<Option<VersionedValue>, ProviderError> {
        rpc_expect!(
            self,
            Request::InspectKeyValue {
                resource,
                key: key.to_vec()
            },
            Value::VersionedValueOption(value) => value
        )
    }

    pub fn provision_key_value_namespace(
        &mut self,
        resource: EntityRef,
        namespace: Identity,
    ) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::ProvisionKeyValueNamespace {
                resource,
                namespace
            },
            Value::Unit => ()
        )
    }

    pub fn provision_key_value_namespace_availability(
        &mut self,
        node: NodeIdentity,
        namespace: Identity,
    ) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::ProvisionKeyValueNamespaceAvailability { node, namespace },
            Value::Unit => ()
        )
    }

    fn call(&self, request: Request) -> Result<Value, ProviderError> {
        let mut session = self.session.lock().map_err(|_| integrity_error())?;
        session.call(request).map_err(rpc_error_as_provider)
    }
}

impl JournalPort for NetworkProvider {
    fn append_entry(&mut self, entry: &JournalEntry) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::AppendEntry {
                entry: entry.clone()
            },
            Value::Unit => ()
        )
    }

    fn commit_activation(&mut self, bundle: &ActivationBundle) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::CommitActivation {
                bundle: WireActivationBundle::from(bundle)
            },
            Value::Unit => ()
        )
    }

    fn commit_bundle(&mut self, bundle: &CommitBundle) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::CommitBundle {
                bundle: WireCommitBundle::from(bundle)
            },
            Value::Unit => ()
        )
    }

    fn entry(&self, position: JournalPosition) -> Result<Option<JournalEntry>, ProviderError> {
        rpc_expect!(
            self,
            Request::Entry { position },
            Value::OptionalJournalEntry(value) => value
        )
    }

    fn operation(
        &self,
        operation: Identity,
    ) -> Result<Option<OperationObservation>, ProviderError> {
        rpc_expect!(
            self,
            Request::Operation { operation },
            Value::OptionalOperationObservation(value) => value.map(Into::into)
        )
    }

    fn idempotency(
        &self,
        key: IdempotencyKey,
    ) -> Result<Option<OperationObservation>, ProviderError> {
        rpc_expect!(
            self,
            Request::Idempotency { key },
            Value::OptionalOperationObservation(value) => value.map(Into::into)
        )
    }

    fn replay_from(
        &self,
        after: Option<JournalPosition>,
    ) -> Result<Vec<JournalEntry>, ProviderError> {
        rpc_expect!(
            self,
            Request::ReplayFrom { after },
            Value::JournalEntries(value) => value
        )
    }
}

impl KvPort for NetworkProvider {
    fn read(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        rpc_expect!(
            self,
            Request::KvRead {
                request: request.clone()
            },
            Value::EffectOutcome(value) => value
        )
    }

    fn compare_and_set(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        rpc_expect!(
            self,
            Request::KvCompareAndSet {
                request: request.clone()
            },
            Value::EffectOutcome(value) => value
        )
    }

    fn query_operation(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        rpc_expect!(
            self,
            Request::KvQueryOperation {
                operation,
                idempotency_key
            },
            Value::OptionalEffectOutcome(value) => value
        )
    }
}

impl TimerPort for NetworkProvider {
    fn arm(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        rpc_expect!(
            self,
            Request::TimerArm {
                request: request.clone()
            },
            Value::EffectOutcome(value) => value
        )
    }

    fn cancel(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        rpc_expect!(
            self,
            Request::TimerCancel {
                request: request.clone()
            },
            Value::EffectOutcome(value) => value
        )
    }

    fn restore_timer_binding(
        &mut self,
        request: &EffectRequest,
        recovery: TimerRecovery,
    ) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::TimerRestoreBinding {
                request: request.clone(),
                recovery: WireTimerRecovery::from(recovery)
            },
            Value::Unit => ()
        )
    }

    fn observe(&mut self, operation: Identity) -> Result<TimerObservation, ProviderError> {
        rpc_expect!(
            self,
            Request::TimerObserve { operation },
            Value::TimerObservation(value) => value.into()
        )
    }

    fn suspend_timer(&mut self, operation: Identity) -> Result<TimerObservation, ProviderError> {
        rpc_expect!(
            self,
            Request::TimerSuspend { operation },
            Value::TimerObservation(value) => value.into()
        )
    }

    fn resume_suspended(&mut self, operation: Identity) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::TimerResume { operation },
            Value::Unit => ()
        )
    }

    fn cleanup_timer(&mut self, operation: Identity) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::TimerCleanup { operation },
            Value::Unit => ()
        )
    }
}

impl AuthorityPort for NetworkProvider {
    fn install_policy(&mut self, policy: AuthorityPolicy) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::InstallPolicy {
                policy: WireAuthorityPolicy::from(policy)
            },
            Value::Unit => ()
        )
    }

    fn install_grant(&mut self, grant: &AuthorityGrant) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::InstallGrant {
                grant: grant.clone()
            },
            Value::Unit => ()
        )
    }

    fn attenuate(
        &mut self,
        handoff: Identity,
        snapshot: Identity,
        parent: EntityRef,
        derived: &AuthorityGrant,
    ) -> Result<AuthorityGrant, ProviderError> {
        rpc_expect!(
            self,
            Request::Attenuate {
                handoff,
                snapshot,
                parent,
                derived: derived.clone()
            },
            Value::AuthorityGrant(value) => value
        )
    }

    fn revoke(&mut self, authority: EntityRef) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::Revoke { authority },
            Value::Unit => ()
        )
    }

    fn reauthorize(
        &mut self,
        request: ReauthorizationRequest,
    ) -> Result<AuthorityGrant, ProviderError> {
        rpc_expect!(
            self,
            Request::Reauthorize {
                request: WireReauthorizationRequest::from(request)
            },
            Value::AuthorityGrant(value) => value
        )
    }

    fn authorize_effect(
        &self,
        request: &EffectRequest,
        required_rights: Rights,
    ) -> Result<Rights, ProviderError> {
        rpc_expect!(
            self,
            Request::AuthorizeEffect {
                request: request.clone(),
                required_rights
            },
            Value::Rights(value) => value
        )
    }

    fn revoke_prepared(&mut self, snapshot: Identity) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::RevokePrepared { snapshot },
            Value::Unit => ()
        )
    }
}

impl LeasePort for NetworkProvider {
    fn initialize_lease(&mut self, lease: LeaseRecord) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::InitializeLease {
                lease: WireLeaseRecord::from(lease)
            },
            Value::Unit => ()
        )
    }

    fn prepare_transitions(
        &mut self,
        request: &EffectRequest,
        resources: &[EntityRef],
    ) -> Result<PreparedLeaseTransitions, ProviderError> {
        rpc_expect!(
            self,
            Request::PrepareTransitions {
                request: request.clone(),
                resources: resources.to_vec()
            },
            Value::PreparedLeaseTransitions(value) => value.into()
        )
    }

    fn current_lease(&self, resource: EntityRef) -> Result<Option<LeaseRecord>, ProviderError> {
        rpc_expect!(
            self,
            Request::CurrentLease { resource },
            Value::OptionalLeaseRecord(value) => value.map(Into::into)
        )
    }

    fn check_lease(
        &self,
        resource: EntityRef,
        owner: NodeIdentity,
        epoch: LeaseEpoch,
    ) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::CheckLease {
                resource,
                owner,
                epoch
            },
            Value::Unit => ()
        )
    }
}

impl BindingPort for NetworkProvider {
    fn prepare_binding(
        &mut self,
        request: BindingRequest,
    ) -> Result<BindingReceipt, ProviderError> {
        rpc_expect!(
            self,
            Request::PrepareBinding {
                request: WireBindingRequest::from(request)
            },
            Value::BindingReceipt(value) => value
        )
    }

    fn binding(
        &self,
        snapshot: Identity,
        claim: EntityRef,
    ) -> Result<Option<BindingReceipt>, ProviderError> {
        rpc_expect!(
            self,
            Request::Binding { snapshot, claim },
            Value::OptionalBindingReceipt(value) => value
        )
    }

    fn cleanup_binding(
        &mut self,
        snapshot: Identity,
        claim: EntityRef,
    ) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::CleanupBinding { snapshot, claim },
            Value::Unit => ()
        )
    }
}

impl ProfilePort for NetworkProvider {
    fn require_profile_dispatch_authorization(
        &mut self,
        profile: Identity,
    ) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::RequireProfileDispatchAuthorization { profile },
            Value::Unit => ()
        )
    }

    fn arm_profile_dispatch(
        &mut self,
        authorization: ProfileDispatchAuthorization,
    ) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::ArmProfileDispatch {
                authorization: WireProfileDispatchAuthorization::from(&authorization)
            },
            Value::Unit => ()
        )
    }

    fn finish_profile_dispatch(
        &mut self,
        binding: EffectRequestBinding,
    ) -> Result<bool, ProviderError> {
        rpc_expect!(
            self,
            Request::FinishProfileDispatch {
                binding: WireEffectRequestBinding::from(binding)
            },
            Value::Bool(value) => value
        )
    }

    fn execute_profile(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
    ) -> Result<EffectOutcome, ProviderError> {
        rpc_expect!(
            self,
            Request::ExecuteProfile {
                request: request.clone(),
                extension: extension.clone()
            },
            Value::EffectOutcome(value) => value
        )
    }

    fn query_profile_operation(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        rpc_expect!(
            self,
            Request::QueryProfileOperation {
                operation,
                idempotency_key
            },
            Value::OptionalEffectOutcome(value) => value
        )
    }

    fn reconcile_profile_operation(
        &mut self,
        request: &EffectRequest,
        extension: &Extension,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        rpc_expect!(
            self,
            Request::ReconcileProfileOperation {
                request: request.clone(),
                extension: extension.clone()
            },
            Value::OptionalEffectOutcome(value) => value
        )
    }

    fn cleanup_profile_operation(&mut self, request: &EffectRequest) -> Result<(), ProviderError> {
        rpc_expect!(
            self,
            Request::CleanupProfileOperation {
                request: request.clone()
            },
            Value::Unit => ()
        )
    }
}

struct RpcSession {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    socket_path: PathBuf,
    next_request_id: u64,
}

impl RpcSession {
    fn connect(locator: &ProviderLocator) -> Result<Self, ProviderRpcError> {
        let stream =
            UnixStream::connect(locator.socket_path()).map_err(|source| ProviderRpcError::Io {
                operation: "connect provider RPC socket",
                path: locator.socket_path().to_path_buf(),
                source,
            })?;
        stream.set_read_timeout(Some(RPC_TIMEOUT)).map_err(|source| ProviderRpcError::Io {
            operation: "set provider RPC read timeout",
            path: locator.socket_path().to_path_buf(),
            source,
        })?;
        stream.set_write_timeout(Some(RPC_TIMEOUT)).map_err(|source| ProviderRpcError::Io {
            operation: "set provider RPC write timeout",
            path: locator.socket_path().to_path_buf(),
            source,
        })?;
        let reader_stream = stream.try_clone().map_err(|source| ProviderRpcError::Io {
            operation: "clone provider RPC socket",
            path: locator.socket_path().to_path_buf(),
            source,
        })?;
        Ok(Self {
            reader: BufReader::new(reader_stream),
            writer: stream,
            socket_path: locator.socket_path().to_path_buf(),
            next_request_id: 0,
        })
    }

    fn call(&mut self, request: Request) -> Result<Value, ProviderRpcError> {
        let request_id = self.next_request_id;
        self.next_request_id = request_id
            .checked_add(1)
            .ok_or_else(|| ProviderRpcError::Protocol("request id overflow".to_owned()))?;
        let envelope = RequestEnvelope::new(request_id, request);
        let bytes = serde_json::to_vec(&envelope).map_err(|source| {
            ProviderRpcError::Protocol(format!("cannot encode request: {source}"))
        })?;
        if bytes.len() + 1 > MAX_FRAME_BYTES {
            return Err(ProviderRpcError::Protocol("request frame is too large".to_owned()));
        }
        self.writer
            .write_all(&bytes)
            .and_then(|()| self.writer.write_all(b"\n"))
            .and_then(|()| self.writer.flush())
            .map_err(|source| ProviderRpcError::Io {
                operation: "write provider RPC request",
                path: self.socket_path.clone(),
                source,
            })?;

        let mut frame = Vec::new();
        let read = (&mut self.reader)
            .take(u64::try_from(MAX_FRAME_BYTES + 1).unwrap_or(u64::MAX))
            .read_until(b'\n', &mut frame)
            .map_err(|source| ProviderRpcError::Io {
                operation: "read provider RPC response",
                path: self.socket_path.clone(),
                source,
            })?;
        if read == 0 {
            return Err(ProviderRpcError::Io {
                operation: "read provider RPC response",
                path: self.socket_path.clone(),
                source: io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "provider closed the RPC session",
                ),
            });
        }
        if frame.len() > MAX_FRAME_BYTES || frame.last() != Some(&b'\n') {
            return Err(ProviderRpcError::Protocol("response frame is invalid".to_owned()));
        }
        frame.pop();
        let response: ResponseEnvelope = serde_json::from_slice(&frame).map_err(|source| {
            ProviderRpcError::Protocol(format!("cannot decode response: {source}"))
        })?;
        if response.schema_version != PROVIDER_RPC_SCHEMA_VERSION {
            return Err(ProviderRpcError::Protocol(
                "response uses an unsupported RPC schema".to_owned(),
            ));
        }
        if response.request_id != request_id {
            return Err(ProviderRpcError::Protocol(format!(
                "response request id {} does not match {request_id}",
                response.request_id
            )));
        }
        match response.outcome {
            ResponseOutcome::Ok { value } => Ok(*value),
            ResponseOutcome::ProviderError { error } => {
                Err(ProviderRpcError::Provider(error.into()))
            }
            ResponseOutcome::ProtocolError { detail } => Err(ProviderRpcError::Protocol(detail)),
        }
    }
}

fn rpc_error_as_provider(error: ProviderRpcError) -> ProviderError {
    match error {
        ProviderRpcError::Provider(error) => error,
        ProviderRpcError::Io { .. } => ProviderError::new(ProviderErrorKind::OutcomeUnknown, true),
        ProviderRpcError::Locator(_) | ProviderRpcError::Protocol(_) => integrity_error(),
    }
}

const fn integrity_error() -> ProviderError {
    ProviderError::new(ProviderErrorKind::Integrity, false)
}
