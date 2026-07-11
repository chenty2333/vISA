use contract_core::{
    ActivationStatus, AuthorityStatus, CanonicalState, EffectKind, EffectOutcome, EffectRequest,
    EffectResult, EntityRef, FailureClass, HandoffPhase, IdempotencyKey, Identity, LeaseEpoch,
    LogicalDurationNanos, NodeIdentity, Rejection, Replay, Rights, VersionedValue,
};
use sha2::{Digest as _, Sha256};
use substrate_api::{AuthorityPort, JournalPort, KvPort, LeasePort, ProviderErrorKind, TimerPort};
use visa_runtime::{CommandReceipt, Coordinator, RuntimeError, canonical_digest};

use crate::{KvFailure, ResourceBindingError, TimerFailure};

/// Provider capabilities required by component imports. Adapter code can only
/// reach them through the canonical coordinator.
pub trait AdapterProvider: JournalPort + AuthorityPort + LeasePort + KvPort + TimerPort {}

impl<T> AdapterProvider for T where T: JournalPort + AuthorityPort + LeasePort + KvPort + TimerPort {}

#[derive(Clone, Debug)]
struct BindingContext {
    resource: EntityRef,
    authority: EntityRef,
    subject: EntityRef,
    node: NodeIdentity,
    epoch: LeaseEpoch,
    exposed_rights: Rights,
}

/// Engine-local resource tables store this opaque receipt, never a native
/// handle or a second copy of canonical authority state.
#[derive(Clone, Debug)]
pub struct KvBinding {
    context: BindingContext,
    completion_parent: Option<Identity>,
}

impl KvBinding {
    pub fn set_completion_parent(&mut self, parent: Identity) {
        self.completion_parent = Some(parent);
    }

    pub fn clear_completion_parent(&mut self) {
        self.completion_parent = None;
    }
}

#[derive(Clone, Debug)]
pub struct TimerBinding(BindingContext);

#[derive(Clone, Debug)]
pub struct BindingSet {
    pub key_value: KvBinding,
    pub timer: TimerBinding,
}

impl BindingSet {
    pub fn for_state(state: &CanonicalState) -> Result<Self, BindingError> {
        let key_value = binding_for(
            state,
            state.key_value.claim.resource,
            state.key_value.claim.required_rights,
        )?;
        let timer =
            binding_for(state, state.timer.claim.resource, state.timer.claim.required_rights)?;
        Ok(Self {
            key_value: KvBinding { context: key_value, completion_parent: None },
            timer: TimerBinding(timer),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingError {
    Inactive,
    Missing,
    Ambiguous,
    InvalidReceipt,
    LiveResources,
    ResourceTable,
}

impl From<BindingError> for ResourceBindingError {
    fn from(error: BindingError) -> Self {
        match error {
            BindingError::Inactive => Self::Inactive,
            BindingError::Missing => Self::Missing,
            BindingError::Ambiguous => Self::Ambiguous,
            BindingError::InvalidReceipt => Self::InvalidReceipt,
            BindingError::LiveResources => Self::LiveResources,
            BindingError::ResourceTable => Self::ResourceTable,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvWriteResult {
    pub operation_id: String,
    pub version: u64,
    pub applied: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimerArmResult {
    pub operation_id: String,
}

pub fn kv_read<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &KvBinding,
    key: String,
) -> Result<Option<VersionedValue>, KvFailure> {
    validate_binding(coordinator.state(), &binding.context, Rights::KV_READ)
        .map_err(kv_binding_error)?;
    let operation =
        read_operation(&binding.context, coordinator.journal_position(), key.as_bytes());
    let idempotency_key = idempotency_from_identity(operation);
    let request = effect_request(
        &binding.context,
        operation,
        idempotency_key,
        None,
        EffectKind::KeyValueRead { key: key.into_bytes() },
    )
    .map_err(|error| kv_runtime_error(error, operation))?;
    let outcome = execute(coordinator, command_for(operation), request)
        .map_err(|error| kv_runtime_error(error, operation))?;
    match outcome {
        EffectOutcome::Succeeded { result: EffectResult::KeyValueRead { value }, .. } => Ok(value),
        other => Err(kv_outcome_error(other, operation)),
    }
}

pub fn kv_conditional_put<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &KvBinding,
    idempotency_key: String,
    key: String,
    expected_version: Option<u64>,
    value: Vec<u8>,
) -> Result<KvWriteResult, KvFailure> {
    validate_binding(coordinator.state(), &binding.context, Rights::KV_WRITE)
        .map_err(kv_binding_error)?;
    let idempotency = idempotency_key_for(&binding.context, b"kv-cas", idempotency_key.as_bytes());
    let operation = operation_for(b"kv-cas", &binding.context, idempotency);
    let request = effect_request(
        &binding.context,
        operation,
        idempotency,
        binding.completion_parent,
        EffectKind::KeyValueCompareAndSet { key: key.into_bytes(), expected_version, value },
    )
    .map_err(|error| kv_runtime_error(error, operation))?;
    let outcome = execute(coordinator, command_for(operation), request)
        .map_err(|error| kv_runtime_error(error, operation))?;
    match outcome {
        EffectOutcome::Succeeded {
            result: EffectResult::KeyValue { version, applied }, ..
        } => Ok(KvWriteResult { operation_id: identity_string(operation), version, applied }),
        other => Err(kv_outcome_error(other, operation)),
    }
}

pub fn timer_arm<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &TimerBinding,
    idempotency_key: String,
    duration_ns: u64,
) -> Result<TimerArmResult, TimerFailure> {
    validate_binding(coordinator.state(), &binding.0, Rights::TIMER_ARM)
        .map_err(timer_binding_error)?;
    let idempotency = idempotency_key_for(&binding.0, b"timer-arm", idempotency_key.as_bytes());
    let operation = operation_for(b"timer-arm", &binding.0, idempotency);
    let causal_parent = match coordinator.state().timer.status {
        contract_core::TimerStatus::Frozen(contract_core::TimerDisposition::Pending {
            arm_operation,
            ..
        }) => Some(arm_operation),
        _ => None,
    };
    let request = effect_request(
        &binding.0,
        operation,
        idempotency,
        causal_parent,
        EffectKind::TimerArm { remaining: LogicalDurationNanos(duration_ns) },
    )
    .map_err(|error| timer_runtime_error(error, operation))?;
    let outcome = execute(coordinator, command_for(operation), request)
        .map_err(|error| timer_runtime_error(error, operation))?;
    match outcome {
        EffectOutcome::Succeeded { result: EffectResult::TimerArmed { .. }, .. } => {
            Ok(TimerArmResult { operation_id: identity_string(operation) })
        }
        other => Err(timer_outcome_error(other)),
    }
}

pub fn timer_cancel<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &TimerBinding,
    operation_id: String,
) -> Result<(), TimerFailure> {
    validate_binding(coordinator.state(), &binding.0, Rights::TIMER_CANCEL)
        .map_err(timer_binding_error)?;
    let Some(target) = parse_identity(&operation_id) else {
        return Err(TimerFailure::NotPending);
    };
    if coordinator.state().timer.active_operation != Some(target) {
        return Err(TimerFailure::NotPending);
    }
    let idempotency = idempotency_key_for(&binding.0, b"timer-cancel", &target.0);
    let operation = operation_for(b"timer-cancel", &binding.0, idempotency);
    let request = effect_request(
        &binding.0,
        operation,
        idempotency,
        Some(target),
        EffectKind::TimerCancel { target_operation: target },
    )
    .map_err(|error| timer_runtime_error(error, operation))?;
    let outcome = execute(coordinator, command_for(operation), request)
        .map_err(|error| timer_runtime_error(error, operation))?;
    match outcome {
        EffectOutcome::Succeeded { result: EffectResult::TimerCancelled, .. } => Ok(()),
        other => Err(timer_outcome_error(other)),
    }
}

fn binding_for(
    state: &CanonicalState,
    resource: EntityRef,
    required_rights: Rights,
) -> Result<BindingContext, BindingError> {
    if state.activation.status != ActivationStatus::Active
        || state.ownership.owner != Some(state.activation.node)
    {
        return Err(BindingError::Inactive);
    }
    if state.phase == HandoffPhase::Committed && state.prepared_destination.is_some() {
        return destination_binding(state, resource, required_rights);
    }
    let mut grants = state.authorities.iter().filter(|grant| {
        grant.subject == state.component
            && grant.resource == resource
            && grant.status == AuthorityStatus::Active
            && grant.rights.contains(required_rights)
    });
    let grant = grants.next().ok_or(BindingError::Missing)?;
    if grants.next().is_some() {
        return Err(BindingError::Ambiguous);
    }
    Ok(BindingContext {
        resource,
        authority: grant.authority,
        subject: state.component,
        node: state.activation.node,
        epoch: state.ownership.epoch,
        exposed_rights: grant.rights,
    })
}

fn destination_binding(
    state: &CanonicalState,
    resource: EntityRef,
    required_rights: Rights,
) -> Result<BindingContext, BindingError> {
    let prepared = state.prepared_destination.as_ref().ok_or(BindingError::Missing)?;
    let mut receipts = prepared.bindings.iter().filter(|receipt| receipt.claim == resource);
    let receipt = receipts.next().ok_or(BindingError::Missing)?;
    if receipts.next().is_some()
        || receipt.node != state.activation.node
        || receipt.lease_epoch != state.ownership.epoch
        || !receipt.exposed_rights.contains(required_rights)
    {
        return Err(BindingError::InvalidReceipt);
    }
    let grant = state.authorities.iter().find(|grant| {
        grant.authority == receipt.authority
            && grant.subject == state.component
            && grant.resource == resource
            && grant.status == AuthorityStatus::Active
            && grant.rights.contains(required_rights)
    });
    if grant.is_none() {
        return Err(BindingError::InvalidReceipt);
    }
    Ok(BindingContext {
        resource,
        authority: receipt.authority,
        subject: state.component,
        node: receipt.node,
        epoch: receipt.lease_epoch,
        exposed_rights: receipt.exposed_rights,
    })
}

#[derive(Clone, Copy)]
enum BindingCheckError {
    Stale,
    Denied,
}

fn validate_binding(
    state: &CanonicalState,
    binding: &BindingContext,
    required: Rights,
) -> Result<(), BindingCheckError> {
    let expected_resource = if required == Rights::KV_READ || required == Rights::KV_WRITE {
        state.key_value.claim.resource
    } else {
        state.timer.claim.resource
    };
    if binding.resource != expected_resource
        || binding.subject != state.component
        || binding.node != state.activation.node
        || state.ownership.owner != Some(binding.node)
        || binding.epoch != state.ownership.epoch
    {
        return Err(BindingCheckError::Stale);
    }
    if !binding.exposed_rights.contains(required) {
        return Err(BindingCheckError::Denied);
    }
    let authorized = state.authorities.iter().any(|grant| {
        grant.authority == binding.authority
            && grant.subject == binding.subject
            && grant.resource == binding.resource
            && grant.status == AuthorityStatus::Active
            && grant.rights.contains(required)
    });
    if authorized { Ok(()) } else { Err(BindingCheckError::Denied) }
}

fn effect_request(
    binding: &BindingContext,
    operation: Identity,
    idempotency_key: IdempotencyKey,
    causal_parent: Option<Identity>,
    kind: EffectKind,
) -> Result<EffectRequest, RuntimeError> {
    let request_digest = canonical_digest(&kind)?;
    Ok(EffectRequest {
        operation,
        idempotency_key,
        causal_parent,
        node: binding.node,
        subject: binding.subject,
        resource: binding.resource,
        authority: binding.authority,
        lease_epoch: binding.epoch,
        request_digest,
        kind,
    })
}

fn execute<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    command: Identity,
    request: EffectRequest,
) -> Result<EffectOutcome, RuntimeError> {
    match coordinator.effect(command, request)? {
        CommandReceipt::Effect(receipt) => Ok(receipt.outcome),
        CommandReceipt::Replayed(Replay::Operation(record)) => record
            .outcome
            .ok_or(RuntimeError::OperationOutcomeUnknown { operation: record.request.operation }),
        CommandReceipt::Committed(_) | CommandReceipt::Replayed(_) => {
            Err(RuntimeError::InvalidProviderOutcome { operation: command })
        }
    }
}

// The v2 domains intentionally change Stage 1 derived identities: provider operations are
// globally keyed, so their identity must include the complete activation-local binding scope.
fn operation_for(domain: &[u8], binding: &BindingContext, key: IdempotencyKey) -> Identity {
    hash_identity(&[
        b"visa-operation-v2",
        domain,
        &binding.resource.identity.0,
        &binding.resource.generation.0.to_be_bytes(),
        &binding.subject.identity.0,
        &binding.subject.generation.0.to_be_bytes(),
        &binding.node.0.0,
        &binding.epoch.0.to_be_bytes(),
        &key.0,
    ])
}

fn read_operation(
    binding: &BindingContext,
    position: contract_core::JournalPosition,
    key: &[u8],
) -> Identity {
    hash_identity(&[
        b"visa-read-v2",
        &binding.resource.identity.0,
        &binding.resource.generation.0.to_be_bytes(),
        &binding.subject.identity.0,
        &binding.subject.generation.0.to_be_bytes(),
        &binding.node.0.0,
        &binding.epoch.0.to_be_bytes(),
        &position.0.to_be_bytes(),
        key,
    ])
}

fn command_for(operation: Identity) -> Identity {
    hash_identity(&[b"visa-command-v1", &operation.0])
}

fn idempotency_key_for(binding: &BindingContext, domain: &[u8], value: &[u8]) -> IdempotencyKey {
    IdempotencyKey(
        hash_identity(&[
            b"visa-idempotency-v2",
            domain,
            &binding.resource.identity.0,
            &binding.resource.generation.0.to_be_bytes(),
            &binding.subject.identity.0,
            &binding.subject.generation.0.to_be_bytes(),
            &binding.node.0.0,
            &binding.epoch.0.to_be_bytes(),
            value,
        ])
        .0,
    )
}

fn idempotency_from_identity(identity: Identity) -> IdempotencyKey {
    IdempotencyKey(hash_identity(&[b"visa-read-idempotency-v1", &identity.0]).0)
}

fn hash_identity(parts: &[&[u8]]) -> Identity {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    let bytes: [u8; 32] = digest.finalize().into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&bytes[..16]);
    Identity::from_bytes(identity)
}

pub fn identity_string(identity: Identity) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in identity.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub fn parse_identity(value: &str) -> Option<Identity> {
    if value.len() != 32 {
        return None;
    }
    let mut output = [0; 16];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        output[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(Identity::from_bytes(output))
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

const fn kv_binding_error(error: BindingCheckError) -> KvFailure {
    match error {
        BindingCheckError::Stale => KvFailure::StaleBinding,
        BindingCheckError::Denied => KvFailure::Denied,
    }
}

const fn timer_binding_error(error: BindingCheckError) -> TimerFailure {
    match error {
        BindingCheckError::Stale => TimerFailure::StaleBinding,
        BindingCheckError::Denied => TimerFailure::Denied,
    }
}

fn kv_runtime_error(error: RuntimeError, operation: Identity) -> KvFailure {
    match error {
        RuntimeError::Rejected(Rejection::StaleGeneration { .. })
        | RuntimeError::Rejected(Rejection::LeaseEpochMismatch { .. })
        | RuntimeError::Rejected(Rejection::NodeMismatch { .. }) => KvFailure::StaleBinding,
        RuntimeError::Rejected(Rejection::UnknownAuthority { .. })
        | RuntimeError::Rejected(Rejection::AuthorityRevoked { .. })
        | RuntimeError::Rejected(Rejection::AuthorityAmplification { .. })
        | RuntimeError::Rejected(Rejection::InsufficientAuthority { .. })
        | RuntimeError::Rejected(Rejection::AuthoritySubjectMismatch)
        | RuntimeError::Rejected(Rejection::AuthorityResourceMismatch) => KvFailure::Denied,
        RuntimeError::Rejected(Rejection::DuplicateOperation { .. })
        | RuntimeError::Rejected(Rejection::IdempotencyConflict { .. })
        | RuntimeError::Rejected(Rejection::OutcomeMismatch) => KvFailure::Conflict,
        RuntimeError::OperationOutcomeUnknown { .. }
        | RuntimeError::JournalOutcomeUnknown { .. } => {
            KvFailure::Indeterminate(identity_string(operation))
        }
        RuntimeError::Provider(error) => match error.kind {
            ProviderErrorKind::Denied | ProviderErrorKind::Revoked => KvFailure::Denied,
            ProviderErrorKind::StaleGeneration | ProviderErrorKind::StaleEpoch => {
                KvFailure::StaleBinding
            }
            ProviderErrorKind::Conflict => KvFailure::Conflict,
            ProviderErrorKind::OutcomeUnknown => {
                KvFailure::Indeterminate(identity_string(operation))
            }
            _ => KvFailure::Unavailable,
        },
        _ => KvFailure::Unavailable,
    }
}

fn kv_outcome_error(outcome: EffectOutcome, operation: Identity) -> KvFailure {
    match outcome {
        EffectOutcome::Failed(failure) => match failure.class {
            FailureClass::Denied => KvFailure::Denied,
            FailureClass::Conflict => KvFailure::Conflict,
            FailureClass::Unavailable | FailureClass::Integrity | FailureClass::Internal => {
                KvFailure::Unavailable
            }
        },
        EffectOutcome::Indeterminate { .. } => KvFailure::Indeterminate(identity_string(operation)),
        EffectOutcome::Cancelled { .. }
        | EffectOutcome::Unsupported { .. }
        | EffectOutcome::Succeeded { .. } => KvFailure::Unavailable,
    }
}

fn timer_runtime_error(error: RuntimeError, _operation: Identity) -> TimerFailure {
    match error {
        RuntimeError::Rejected(Rejection::StaleGeneration { .. })
        | RuntimeError::Rejected(Rejection::LeaseEpochMismatch { .. })
        | RuntimeError::Rejected(Rejection::NodeMismatch { .. }) => TimerFailure::StaleBinding,
        RuntimeError::Rejected(Rejection::UnknownAuthority { .. })
        | RuntimeError::Rejected(Rejection::AuthorityRevoked { .. })
        | RuntimeError::Rejected(Rejection::AuthorityAmplification { .. })
        | RuntimeError::Rejected(Rejection::InsufficientAuthority { .. })
        | RuntimeError::Rejected(Rejection::AuthoritySubjectMismatch)
        | RuntimeError::Rejected(Rejection::AuthorityResourceMismatch) => TimerFailure::Denied,
        RuntimeError::Rejected(Rejection::TimerStateConflict)
        | RuntimeError::Rejected(Rejection::UnknownOperation { .. }) => TimerFailure::NotPending,
        RuntimeError::Provider(error) => match error.kind {
            ProviderErrorKind::Denied | ProviderErrorKind::Revoked => TimerFailure::Denied,
            ProviderErrorKind::StaleGeneration | ProviderErrorKind::StaleEpoch => {
                TimerFailure::StaleBinding
            }
            ProviderErrorKind::NotFound | ProviderErrorKind::Conflict => TimerFailure::NotPending,
            _ => TimerFailure::Unavailable,
        },
        _ => TimerFailure::Unavailable,
    }
}

fn timer_outcome_error(outcome: EffectOutcome) -> TimerFailure {
    match outcome {
        EffectOutcome::Failed(failure) => match failure.class {
            FailureClass::Denied => TimerFailure::Denied,
            FailureClass::Conflict => TimerFailure::NotPending,
            FailureClass::Unavailable | FailureClass::Integrity | FailureClass::Internal => {
                TimerFailure::Unavailable
            }
        },
        EffectOutcome::Cancelled { .. } => TimerFailure::NotPending,
        EffectOutcome::Indeterminate { .. }
        | EffectOutcome::Unsupported { .. }
        | EffectOutcome::Succeeded { .. } => TimerFailure::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use contract_core::{Generation, JournalPosition};

    use super::*;

    fn binding(
        subject_identity: u128,
        subject_generation: u64,
        node_identity: u128,
        epoch: u64,
    ) -> BindingContext {
        BindingContext {
            resource: EntityRef::new(Identity::from_u128(1), Generation(2)),
            authority: EntityRef::new(Identity::from_u128(3), Generation(4)),
            subject: EntityRef::new(
                Identity::from_u128(subject_identity),
                Generation(subject_generation),
            ),
            node: NodeIdentity::new(Identity::from_u128(node_identity)),
            epoch: LeaseEpoch(epoch),
            exposed_rights: Rights::KV_READ.union(Rights::KV_WRITE),
        }
    }

    #[test]
    fn operation_identity_text_round_trips_and_rejects_noncanonical_text() {
        let identity = Identity::from_u128(0x1234);
        assert_eq!(parse_identity(&identity_string(identity)), Some(identity));
        assert_eq!(parse_identity("ABCDEF"), None);
        assert_eq!(parse_identity("gggggggggggggggggggggggggggggggg"), None);
    }

    #[test]
    fn provider_identities_cover_the_complete_binding_scope() {
        let base = binding(5, 6, 7, 8);
        let changed_scopes =
            [binding(9, 6, 7, 8), binding(5, 9, 7, 8), binding(5, 6, 9, 8), binding(5, 6, 7, 9)];
        let position = JournalPosition(10);
        let fixed_idempotency = IdempotencyKey(Identity::from_u128(11).0);
        let base_read = read_operation(&base, position, b"key");
        let base_idempotency = idempotency_key_for(&base, b"kv-cas", b"request-key");
        let base_write = operation_for(b"kv-cas", &base, fixed_idempotency);

        for changed in &changed_scopes {
            assert_ne!(read_operation(changed, position, b"key"), base_read);
            assert_ne!(idempotency_key_for(changed, b"kv-cas", b"request-key"), base_idempotency,);
            assert_ne!(operation_for(b"kv-cas", changed, fixed_idempotency), base_write);
        }
    }
}
