//! Engine-neutral composite component state and its portable encoding.
//!
//! The record is the concatenation of a timer/key-value segment owned here and
//! the two existing profile segments, each carried verbatim in its own
//! published encoding. Reusing those encodings keeps the file and request
//! halves byte-identical to what the single-resource cells produce.

use contract_core::{DeliveryPolicy, Digest};
use visa_component_adapter::{
    LogicalRequestComponentState, LogicalRequestStateCodecError, LogicalRequestWorkloadLifecycle,
    PortableLogicalRequestState, PortableRegularFileState, RegularFileComponentState,
    RegularFileStateCodecError, RegularFileWorkloadPhase,
};
use visa_profile::{
    ContinuityDisposition, FileDurability, FileLockState, LogicalRequestIdempotency,
    LogicalRequestPhase, LogicalRequestRejection, LogicalRequestReplay, LogicalRequestState,
    LogicalRequestTransport, LogicalResponseMetadata, RegularFileState,
};

use crate::bindings::{
    exports::visa::composite_continuity::workload::{
        CompositePhase as WitCompositePhase, CompositeState as WitCompositeState,
        FilePhase as WitFilePhase, FileState as WitFileState,
        RequestLifecycle as WitRequestLifecycle, RequestState as WitRequestState,
        TimerKvState as WitTimerKvState,
    },
    visa::{
        file_continuity::regular_file::Durability as WitDurability,
        request_continuity::logical_request::{
            ContinuityDisposition as WitDisposition, DeliveryPolicy as WitDelivery,
            Idempotency as WitIdempotency, ReplayPolicy as WitReplay, RequestPhase as WitPhase,
            RequestRejection as WitRejection, ResponseMetadata as WitResponse,
            Transport as WitTransport,
        },
    },
};

const MAGIC: &[u8; 8] = b"VISACX01";

pub const COMPOSITE_COMPONENT_STATE_ENCODING: &str = "visa-composite-state-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositePhase {
    Active,
    Frozen,
}

/// The timer and key-value half of the composite record. The file and request
/// halves reuse the profile component-state types unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimerKvComponentState {
    pub key: String,
    pub expected_version: u64,
    pub completion_value: Vec<u8>,
    pub timer_operation_id: Option<String>,
    pub timer_idempotency_key: String,
    pub completion_idempotency_key: String,
    pub timer_completed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositeComponentState {
    pub session_id: String,
    pub timer_kv: TimerKvComponentState,
    pub file: RegularFileComponentState,
    pub request: LogicalRequestComponentState,
    pub phase: CompositePhase,
}

impl CompositeComponentState {
    pub fn from_canonical(
        session_id: String,
        timer_kv: TimerKvComponentState,
        file: &RegularFileState,
        request: &LogicalRequestState,
        phase: CompositePhase,
    ) -> Result<Self, CompositeStateCodecError> {
        let file_phase = match phase {
            CompositePhase::Active => RegularFileWorkloadPhase::Active,
            CompositePhase::Frozen => RegularFileWorkloadPhase::Frozen,
        };
        let lifecycle = match phase {
            CompositePhase::Active => LogicalRequestWorkloadLifecycle::Active,
            CompositePhase::Frozen => LogicalRequestWorkloadLifecycle::Frozen,
        };
        Ok(Self {
            session_id: session_id.clone(),
            timer_kv,
            file: RegularFileComponentState::from_canonical(session_id.clone(), file, file_phase)?,
            request: LogicalRequestComponentState::from_canonical(session_id, request, lifecycle)?,
            phase,
        })
    }

    /// Cross-check every segment against the canonical truth the coordinator
    /// owns. The profile segments delegate to their own validators; the
    /// timer/key-value segment is checked against canonical timer and
    /// key-value state here.
    pub fn validate_canonical(
        &self,
        canonical: &contract_core::CanonicalState,
        file: &RegularFileState,
        request: &LogicalRequestState,
    ) -> Result<(), CompositeStateCodecError> {
        self.file.validate_canonical(file)?;
        self.request.validate_canonical(request)?;
        if self.file.session_id != self.session_id || self.request.session_id != self.session_id {
            return Err(CompositeStateCodecError::CanonicalMismatch);
        }
        // A component that believes it armed a timer must name the operation
        // the coordinator is tracking, and one that believes it has not must
        // leave the canonical timer without an active operation.
        let canonical_arm =
            canonical.timer.active_operation.map(visa_component_adapter::identity_string);
        match (&self.timer_kv.timer_operation_id, &canonical_arm) {
            (Some(guest), Some(canonical)) if guest == canonical => {}
            (None, None) => {}
            // After the completion write the coordinator retires the arm
            // operation while the guest keeps naming it for evidence.
            (Some(_), None) if self.timer_kv.timer_completed => {}
            _ => return Err(CompositeStateCodecError::CanonicalMismatch),
        }
        if let Some(last_version) = canonical.key_value.last_version
            && self.timer_kv.expected_version != last_version
        {
            return Err(CompositeStateCodecError::CanonicalMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableCompositeState(Vec<u8>);

impl PortableCompositeState {
    pub fn encode(state: &CompositeComponentState) -> Result<Self, CompositeStateCodecError> {
        let file = PortableRegularFileState::encode(&state.file)?;
        let request = PortableLogicalRequestState::encode(&state.request)?;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        push_bytes(&mut bytes, state.session_id.as_bytes())?;
        push_bytes(&mut bytes, state.timer_kv.key.as_bytes())?;
        bytes.extend_from_slice(&state.timer_kv.expected_version.to_be_bytes());
        push_bytes(&mut bytes, &state.timer_kv.completion_value)?;
        match &state.timer_kv.timer_operation_id {
            Some(operation) => {
                bytes.push(1);
                push_bytes(&mut bytes, operation.as_bytes())?;
            }
            None => bytes.push(0),
        }
        push_bytes(&mut bytes, state.timer_kv.timer_idempotency_key.as_bytes())?;
        push_bytes(&mut bytes, state.timer_kv.completion_idempotency_key.as_bytes())?;
        bytes.push(u8::from(state.timer_kv.timer_completed));
        push_bytes(&mut bytes, file.as_bytes())?;
        push_bytes(&mut bytes, request.as_bytes())?;
        bytes.push(match state.phase {
            CompositePhase::Active => 0,
            CompositePhase::Frozen => 1,
        });
        Ok(Self(bytes))
    }

    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, CompositeStateCodecError> {
        decode(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn decode(&self) -> Result<CompositeComponentState, CompositeStateCodecError> {
        decode(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositeStateCodecError {
    InvalidMagic,
    Truncated,
    InvalidUtf8,
    InvalidOptional,
    InvalidPhase,
    TrailingBytes,
    FieldTooLarge,
    CanonicalMismatch,
    File(RegularFileStateCodecError),
    Request(LogicalRequestStateCodecError),
}

impl From<RegularFileStateCodecError> for CompositeStateCodecError {
    fn from(error: RegularFileStateCodecError) -> Self {
        Self::File(error)
    }
}

impl From<LogicalRequestStateCodecError> for CompositeStateCodecError {
    fn from(error: LogicalRequestStateCodecError) -> Self {
        Self::Request(error)
    }
}

fn decode(bytes: &[u8]) -> Result<CompositeComponentState, CompositeStateCodecError> {
    let mut decoder = Decoder { bytes, offset: 0 };
    if decoder.take(MAGIC.len())? != MAGIC {
        return Err(CompositeStateCodecError::InvalidMagic);
    }
    let session_id = decoder.string()?;
    let key = decoder.string()?;
    let expected_version = decoder.u64()?;
    let completion_value = decoder.bytes()?;
    let timer_operation_id = match decoder.byte()? {
        0 => None,
        1 => Some(decoder.string()?),
        _ => return Err(CompositeStateCodecError::InvalidOptional),
    };
    let timer_idempotency_key = decoder.string()?;
    let completion_idempotency_key = decoder.string()?;
    let timer_completed = match decoder.byte()? {
        0 => false,
        1 => true,
        _ => return Err(CompositeStateCodecError::InvalidOptional),
    };
    let file = PortableRegularFileState::try_from_bytes(decoder.bytes()?)?.decode()?;
    let request = PortableLogicalRequestState::try_from_bytes(decoder.bytes()?)?.decode()?;
    let phase = match decoder.byte()? {
        0 => CompositePhase::Active,
        1 => CompositePhase::Frozen,
        _ => return Err(CompositeStateCodecError::InvalidPhase),
    };
    if decoder.offset != bytes.len() {
        return Err(CompositeStateCodecError::TrailingBytes);
    }
    Ok(CompositeComponentState {
        session_id,
        timer_kv: TimerKvComponentState {
            key,
            expected_version,
            completion_value,
            timer_operation_id,
            timer_idempotency_key,
            completion_idempotency_key,
            timer_completed,
        },
        file,
        request,
        phase,
    })
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CompositeStateCodecError> {
    let length = u32::try_from(value.len()).map_err(|_| CompositeStateCodecError::FieldTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], CompositeStateCodecError> {
        let end = self.offset.checked_add(length).ok_or(CompositeStateCodecError::Truncated)?;
        let value = self.bytes.get(self.offset..end).ok_or(CompositeStateCodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, CompositeStateCodecError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, CompositeStateCodecError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| CompositeStateCodecError::Truncated)?,
        ))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, CompositeStateCodecError> {
        let length = u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| CompositeStateCodecError::Truncated)?,
        ) as usize;
        Ok(self.take(length)?.to_vec())
    }

    fn string(&mut self) -> Result<String, CompositeStateCodecError> {
        String::from_utf8(self.bytes()?).map_err(|_| CompositeStateCodecError::InvalidUtf8)
    }
}

pub(crate) fn to_wit_state(state: &CompositeComponentState) -> WitCompositeState {
    WitCompositeState {
        session_id: state.session_id.clone(),
        timer_kv: WitTimerKvState {
            key: state.timer_kv.key.clone(),
            expected_version: state.timer_kv.expected_version,
            completion_value: state.timer_kv.completion_value.clone(),
            timer_operation_id: state.timer_kv.timer_operation_id.clone(),
            timer_idempotency_key: state.timer_kv.timer_idempotency_key.clone(),
            completion_idempotency_key: state.timer_kv.completion_idempotency_key.clone(),
            timer_completed: state.timer_kv.timer_completed,
        },
        file: to_wit_file_state(&state.file),
        request: to_wit_request_state(&state.request),
        phase: match state.phase {
            CompositePhase::Active => WitCompositePhase::Active,
            CompositePhase::Frozen => WitCompositePhase::Frozen,
        },
    }
}

pub(crate) fn from_wit_state(
    state: WitCompositeState,
) -> Result<CompositeComponentState, CompositeStateCodecError> {
    Ok(CompositeComponentState {
        session_id: state.session_id,
        timer_kv: TimerKvComponentState {
            key: state.timer_kv.key,
            expected_version: state.timer_kv.expected_version,
            completion_value: state.timer_kv.completion_value,
            timer_operation_id: state.timer_kv.timer_operation_id,
            timer_idempotency_key: state.timer_kv.timer_idempotency_key,
            completion_idempotency_key: state.timer_kv.completion_idempotency_key,
            timer_completed: state.timer_kv.timer_completed,
        },
        file: from_wit_file_state(state.file)?,
        request: from_wit_request_state(state.request)?,
        phase: match state.phase {
            WitCompositePhase::Active => CompositePhase::Active,
            WitCompositePhase::Frozen => CompositePhase::Frozen,
        },
    })
}

fn to_wit_file_state(state: &RegularFileComponentState) -> WitFileState {
    WitFileState {
        session_id: state.session_id.clone(),
        relative_path: state.relative_path.clone(),
        logical_offset: state.logical_offset,
        version: state.version,
        size: state.size,
        content_digest: state.content_digest.0.to_vec(),
        durable_through: to_wit_durability(state.durable_through),
        lock_held: state.lock_state == FileLockState::Held,
        last_operation_id: state.last_operation.clone(),
        phase: match state.phase {
            RegularFileWorkloadPhase::Active => WitFilePhase::Active,
            RegularFileWorkloadPhase::Frozen => WitFilePhase::Frozen,
        },
    }
}

fn from_wit_file_state(
    state: WitFileState,
) -> Result<RegularFileComponentState, CompositeStateCodecError> {
    let content_digest: [u8; 32] = state
        .content_digest
        .try_into()
        .map_err(|_| CompositeStateCodecError::File(RegularFileStateCodecError::Truncated))?;
    Ok(RegularFileComponentState {
        session_id: state.session_id,
        relative_path: state.relative_path,
        logical_offset: state.logical_offset,
        version: state.version,
        size: state.size,
        content_digest: Digest::from_bytes(content_digest),
        durable_through: from_wit_durability(state.durable_through),
        lock_state: if state.lock_held { FileLockState::Held } else { FileLockState::Unlocked },
        last_operation: state.last_operation_id,
        phase: match state.phase {
            WitFilePhase::Active => RegularFileWorkloadPhase::Active,
            WitFilePhase::Frozen => RegularFileWorkloadPhase::Frozen,
        },
    })
}

fn to_wit_request_state(state: &LogicalRequestComponentState) -> WitRequestState {
    WitRequestState {
        session_id: state.session_id.clone(),
        peer_identity: state.peer_identity.clone(),
        credential_reference: state.credential_reference.clone(),
        transport: to_wit_transport(state.transport),
        delivery: to_wit_delivery(state.delivery),
        replay: to_wit_replay(state.replay),
        idempotency: to_wit_idempotency(state.idempotency),
        timeout_ms: state.timeout_millis,
        max_request_size: state.max_request_size,
        max_response_size: state.max_response_size,
        operation_id: state.operation_id.clone(),
        request_size: state.request_size,
        request_digest: state.request_digest.0.to_vec(),
        request_phase: to_wit_request_phase(state.request_phase),
        response_cursor: state.response_cursor,
        response: state.response.map(to_wit_response),
        rejection: state.rejection.map(to_wit_rejection),
        disposition: to_wit_disposition(state.disposition),
        lifecycle: match state.lifecycle {
            LogicalRequestWorkloadLifecycle::Active => WitRequestLifecycle::Active,
            LogicalRequestWorkloadLifecycle::Frozen => WitRequestLifecycle::Frozen,
        },
    }
}

fn from_wit_request_state(
    state: WitRequestState,
) -> Result<LogicalRequestComponentState, CompositeStateCodecError> {
    Ok(LogicalRequestComponentState {
        session_id: state.session_id,
        peer_identity: state.peer_identity,
        credential_reference: state.credential_reference,
        transport: from_wit_transport(state.transport),
        delivery: from_wit_delivery(state.delivery),
        replay: from_wit_replay(state.replay),
        idempotency: from_wit_idempotency(state.idempotency),
        timeout_millis: state.timeout_ms,
        max_request_size: state.max_request_size,
        max_response_size: state.max_response_size,
        operation_id: state.operation_id,
        request_size: state.request_size,
        request_digest: request_digest(state.request_digest)?,
        request_phase: from_wit_request_phase(state.request_phase),
        response_cursor: state.response_cursor,
        response: state.response.map(from_wit_response).transpose()?,
        rejection: state.rejection.map(from_wit_rejection),
        disposition: from_wit_disposition(state.disposition),
        lifecycle: match state.lifecycle {
            WitRequestLifecycle::Active => LogicalRequestWorkloadLifecycle::Active,
            WitRequestLifecycle::Frozen => LogicalRequestWorkloadLifecycle::Frozen,
        },
    })
}

fn request_digest(bytes: Vec<u8>) -> Result<Digest, CompositeStateCodecError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CompositeStateCodecError::Request(LogicalRequestStateCodecError::Truncated))?;
    Ok(Digest::from_bytes(bytes))
}

pub(crate) fn to_wit_response(value: LogicalResponseMetadata) -> WitResponse {
    WitResponse { size: value.size, digest: value.digest.0.to_vec() }
}

fn from_wit_response(
    value: WitResponse,
) -> Result<LogicalResponseMetadata, CompositeStateCodecError> {
    Ok(LogicalResponseMetadata { size: value.size, digest: request_digest(value.digest)? })
}

pub(crate) const fn to_wit_durability(value: FileDurability) -> WitDurability {
    match value {
        FileDurability::Visible => WitDurability::Visible,
        FileDurability::Data => WitDurability::Data,
        FileDurability::DataAndMetadata => WitDurability::DataAndMetadata,
    }
}

pub(crate) const fn from_wit_durability(value: WitDurability) -> FileDurability {
    match value {
        WitDurability::Visible => FileDurability::Visible,
        WitDurability::Data => FileDurability::Data,
        WitDurability::DataAndMetadata => FileDurability::DataAndMetadata,
    }
}

const fn to_wit_transport(value: LogicalRequestTransport) -> WitTransport {
    match value {
        LogicalRequestTransport::Reconnectable => WitTransport::Reconnectable,
        LogicalRequestTransport::RawLiveTcp => WitTransport::RawLiveTcp,
    }
}

const fn from_wit_transport(value: WitTransport) -> LogicalRequestTransport {
    match value {
        WitTransport::Reconnectable => LogicalRequestTransport::Reconnectable,
        WitTransport::RawLiveTcp => LogicalRequestTransport::RawLiveTcp,
    }
}

const fn to_wit_delivery(value: DeliveryPolicy) -> WitDelivery {
    match value {
        DeliveryPolicy::Deduplicated => WitDelivery::Deduplicated,
        DeliveryPolicy::AtMostOnce => WitDelivery::AtMostOnce,
        DeliveryPolicy::AtLeastOnce => WitDelivery::AtLeastOnce,
        DeliveryPolicy::NonRecoverable => WitDelivery::NonRecoverable,
    }
}

const fn from_wit_delivery(value: WitDelivery) -> DeliveryPolicy {
    match value {
        WitDelivery::Deduplicated => DeliveryPolicy::Deduplicated,
        WitDelivery::AtMostOnce => DeliveryPolicy::AtMostOnce,
        WitDelivery::AtLeastOnce => DeliveryPolicy::AtLeastOnce,
        WitDelivery::NonRecoverable => DeliveryPolicy::NonRecoverable,
    }
}

const fn to_wit_replay(value: LogicalRequestReplay) -> WitReplay {
    match value {
        LogicalRequestReplay::Never => WitReplay::Never,
        LogicalRequestReplay::BeforeSend => WitReplay::BeforeSend,
        LogicalRequestReplay::IfIdempotent => WitReplay::IfIdempotent,
        LogicalRequestReplay::WithOperationId => WitReplay::WithOperationId,
    }
}

const fn from_wit_replay(value: WitReplay) -> LogicalRequestReplay {
    match value {
        WitReplay::Never => LogicalRequestReplay::Never,
        WitReplay::BeforeSend => LogicalRequestReplay::BeforeSend,
        WitReplay::IfIdempotent => LogicalRequestReplay::IfIdempotent,
        WitReplay::WithOperationId => LogicalRequestReplay::WithOperationId,
    }
}

const fn to_wit_idempotency(value: LogicalRequestIdempotency) -> WitIdempotency {
    match value {
        LogicalRequestIdempotency::NonIdempotent => WitIdempotency::NonIdempotent,
        LogicalRequestIdempotency::Idempotent => WitIdempotency::Idempotent,
        LogicalRequestIdempotency::OperationIdDeduplicated => {
            WitIdempotency::OperationIdDeduplicated
        }
    }
}

const fn from_wit_idempotency(value: WitIdempotency) -> LogicalRequestIdempotency {
    match value {
        WitIdempotency::NonIdempotent => LogicalRequestIdempotency::NonIdempotent,
        WitIdempotency::Idempotent => LogicalRequestIdempotency::Idempotent,
        WitIdempotency::OperationIdDeduplicated => {
            LogicalRequestIdempotency::OperationIdDeduplicated
        }
    }
}

pub(crate) const fn to_wit_request_phase(value: LogicalRequestPhase) -> WitPhase {
    match value {
        LogicalRequestPhase::Ready => WitPhase::Ready,
        LogicalRequestPhase::Pending => WitPhase::Pending,
        LogicalRequestPhase::PartialResponse => WitPhase::PartialResponse,
        LogicalRequestPhase::UnknownCompletion => WitPhase::UnknownCompletion,
        LogicalRequestPhase::Reconciling => WitPhase::Reconciling,
        LogicalRequestPhase::Replaying => WitPhase::Replaying,
        LogicalRequestPhase::Cancelling => WitPhase::Cancelling,
        LogicalRequestPhase::Completed => WitPhase::Completed,
        LogicalRequestPhase::TimedOut => WitPhase::TimedOut,
        LogicalRequestPhase::Cancelled => WitPhase::Cancelled,
        LogicalRequestPhase::Rejected => WitPhase::Rejected,
    }
}

const fn from_wit_request_phase(value: WitPhase) -> LogicalRequestPhase {
    match value {
        WitPhase::Ready => LogicalRequestPhase::Ready,
        WitPhase::Pending => LogicalRequestPhase::Pending,
        WitPhase::PartialResponse => LogicalRequestPhase::PartialResponse,
        WitPhase::UnknownCompletion => LogicalRequestPhase::UnknownCompletion,
        WitPhase::Reconciling => LogicalRequestPhase::Reconciling,
        WitPhase::Replaying => LogicalRequestPhase::Replaying,
        WitPhase::Cancelling => LogicalRequestPhase::Cancelling,
        WitPhase::Completed => LogicalRequestPhase::Completed,
        WitPhase::TimedOut => LogicalRequestPhase::TimedOut,
        WitPhase::Cancelled => LogicalRequestPhase::Cancelled,
        WitPhase::Rejected => LogicalRequestPhase::Rejected,
    }
}

pub(crate) const fn to_wit_rejection(value: LogicalRequestRejection) -> WitRejection {
    match value {
        LogicalRequestRejection::PeerMismatch => WitRejection::PeerMismatch,
        LogicalRequestRejection::CredentialDenied => WitRejection::CredentialDenied,
        LogicalRequestRejection::UnsafeReplay => WitRejection::UnsafeReplay,
        LogicalRequestRejection::UnsupportedTransport => WitRejection::UnsupportedTransport,
        LogicalRequestRejection::PolicyDenied => WitRejection::PolicyDenied,
    }
}

const fn from_wit_rejection(value: WitRejection) -> LogicalRequestRejection {
    match value {
        WitRejection::PeerMismatch => LogicalRequestRejection::PeerMismatch,
        WitRejection::CredentialDenied => LogicalRequestRejection::CredentialDenied,
        WitRejection::UnsafeReplay => LogicalRequestRejection::UnsafeReplay,
        WitRejection::UnsupportedTransport => LogicalRequestRejection::UnsupportedTransport,
        WitRejection::PolicyDenied => LogicalRequestRejection::PolicyDenied,
    }
}

const fn to_wit_disposition(value: ContinuityDisposition) -> WitDisposition {
    match value {
        ContinuityDisposition::Revalidate => WitDisposition::Revalidate,
        ContinuityDisposition::Reconnect => WitDisposition::Reconnect,
        ContinuityDisposition::Replay => WitDisposition::Replay,
        ContinuityDisposition::Reject => WitDisposition::Reject,
    }
}

const fn from_wit_disposition(value: WitDisposition) -> ContinuityDisposition {
    match value {
        WitDisposition::Revalidate => ContinuityDisposition::Revalidate,
        WitDisposition::Reconnect => ContinuityDisposition::Reconnect,
        WitDisposition::Replay => ContinuityDisposition::Replay,
        WitDisposition::Reject => ContinuityDisposition::Reject,
    }
}
