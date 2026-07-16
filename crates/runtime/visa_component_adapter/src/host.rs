use contract_core::{
    ActivationStatus, AuthorityStatus, CanonicalState, EffectKind, EffectOutcome, EffectRequest,
    EffectResult, EntityRef, FailureClass, HandoffPhase, IdempotencyKey, Identity, JournalPosition,
    LeaseEpoch, LogicalDurationNanos, NodeIdentity, OperationRecord, ProfileAccess, Rejection,
    Replay, Rights, VersionedValue,
};
use sha2::{Digest as _, Sha256};
use substrate_api::{
    AuthorityPort, JournalPort, KvPort, LeasePort, ProfilePort, ProviderErrorKind, TimerPort,
};
use visa_runtime::{CommandReceipt, Coordinator, RuntimeError, canonical_digest};

use crate::{KvFailure, ResourceBindingError, TimerFailure};

/// Provider capabilities required by component imports. Adapter code can only
/// reach them through the canonical coordinator.
pub trait AdapterProvider:
    JournalPort + AuthorityPort + LeasePort + KvPort + TimerPort + ProfilePort
{
}

impl<T> AdapterProvider for T where
    T: JournalPort + AuthorityPort + LeasePort + KvPort + TimerPort + ProfilePort
{
}

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

/// Opaque engine-local receipt for one versioned resource profile. Typed file
/// or request state remains in the canonical extension owned by that profile.
#[derive(Clone, Debug)]
pub struct ProfileBinding {
    context: BindingContext,
    profile: Identity,
    required_rights: Rights,
}

impl ProfileBinding {
    pub fn for_state(state: &CanonicalState, profile: Identity) -> Result<Self, BindingError> {
        let mut resources = visa_profile::profile_resources(&state.extensions)
            .map_err(|_| BindingError::InvalidReceipt)?
            .into_iter()
            .filter(|resource| resource.profile == profile);
        let resource = resources.next().ok_or(BindingError::Missing)?;
        if resources.next().is_some() {
            return Err(BindingError::Ambiguous);
        }
        Ok(Self {
            context: binding_for(state, resource.resource, resource.required_rights)?,
            profile,
            required_rights: resource.required_rights,
        })
    }

    pub const fn profile(&self) -> Identity {
        self.profile
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileCallResult {
    pub operation: Identity,
    pub operation_id: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileFailure {
    Denied,
    Conflict,
    StaleBinding,
    Invalid,
    Unsupported,
    Cancelled,
    Indeterminate(String),
    Unavailable,
}

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

/// Execute a read-only profile observation with an activation-local identity.
/// Reads deliberately do not accept a guest idempotency key. A new observation
/// is scoped by the current canonical journal position, while a durable
/// unresolved observation with the same binding and typed payload is retried
/// through its original request identity.
pub fn profile_observe<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    payload: Vec<u8>,
) -> Result<ProfileCallResult, ProfileFailure> {
    let access = ProfileAccess::Read;
    validate_profile_binding(coordinator.state(), binding, access)
        .map_err(profile_binding_error)?;
    let request = profile_observation_request(
        &coordinator.state().operations,
        coordinator.journal_position(),
        binding,
        payload,
    )
    .map_err(|(error, operation)| profile_runtime_error(error, operation))?;
    let operation = request.operation;
    execute_profile_request(coordinator, binding, operation, request)
}

/// Execute an idempotent mutating or control operation for a typed profile.
/// The profile owns payload validation and canonical state reduction.
pub fn profile_execute<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    access: ProfileAccess,
    idempotency_value: &[u8],
    payload: Vec<u8>,
) -> Result<ProfileCallResult, ProfileFailure> {
    let request =
        prepare_profile_effect(coordinator.state(), binding, access, idempotency_value, payload)?;
    let operation = request.operation;
    execute_profile_request(coordinator, binding, operation, request)
}

/// Construct the exact canonical effect request that [`profile_execute`] will
/// submit without mutating canonical state or dispatching to a provider.
/// Existing idempotency records retain their original request identity; a
/// non-equivalent reuse of the same idempotency key is rejected as a conflict.
pub fn prepare_profile_effect(
    state: &CanonicalState,
    binding: &ProfileBinding,
    access: ProfileAccess,
    idempotency_value: &[u8],
    payload: Vec<u8>,
) -> Result<EffectRequest, ProfileFailure> {
    if access == ProfileAccess::Read || idempotency_value.is_empty() {
        return Err(ProfileFailure::Invalid);
    }
    validate_profile_binding(state, binding, access).map_err(profile_binding_error)?;
    let access_tag = match access {
        ProfileAccess::Read => b"read".as_slice(),
        ProfileAccess::Write => b"write".as_slice(),
        ProfileAccess::Control => b"control".as_slice(),
    };
    let idempotency_key =
        profile_idempotency_key(&binding.context, binding.profile, access_tag, idempotency_value);
    let operation_domain = profile_operation_domain(binding.profile, access_tag);
    let operation = operation_for(&operation_domain, &binding.context, idempotency_key);
    let kind = EffectKind::Profile { profile: binding.profile, access, payload };
    let candidate = effect_request(&binding.context, operation, idempotency_key, None, kind)
        .map_err(|error| profile_runtime_error(error, operation))?;

    let mut matching =
        state.operations.iter().filter(|record| record.request.idempotency_key == idempotency_key);
    if let Some(record) = matching.next() {
        if matching.next().is_some()
            || !historical_profile_request_matches(
                state,
                &record.request,
                &binding.context,
                &candidate.kind,
                &operation_domain,
                access.required_rights(),
            )
            || state.operations.iter().any(|other| {
                !core::ptr::eq(other, record) && other.request.operation == record.request.operation
            })
        {
            return Err(ProfileFailure::Conflict);
        }
        return Ok(record.request.clone());
    }
    if state.operations.iter().any(|record| record.request.operation == candidate.operation) {
        return Err(ProfileFailure::Conflict);
    }
    Ok(candidate)
}

fn historical_profile_request_matches(
    state: &CanonicalState,
    request: &EffectRequest,
    current: &BindingContext,
    kind: &EffectKind,
    operation_domain: &[u8],
    required_rights: Rights,
) -> bool {
    if request.causal_parent.is_some()
        || request.resource != current.resource
        || request.subject.identity != current.subject.identity
        || request.kind != *kind
        || canonical_digest(&request.kind).ok() != Some(request.request_digest)
    {
        return false;
    }
    let historical = BindingContext {
        resource: request.resource,
        authority: request.authority,
        subject: request.subject,
        node: request.node,
        epoch: request.lease_epoch,
        exposed_rights: current.exposed_rights,
    };
    if request.operation != operation_for(operation_domain, &historical, request.idempotency_key) {
        return false;
    }

    let mut grants = state
        .authorities
        .iter()
        .filter(|grant| grant.authority.identity == request.authority.identity);
    let Some(grant) = grants.next() else {
        return false;
    };
    if grants.next().is_some()
        || grant.subject != request.subject
        || grant.resource != request.resource
        || !grant.rights.contains(required_rights)
    {
        return false;
    }
    match grant.status {
        AuthorityStatus::Active => grant.authority == request.authority,
        AuthorityStatus::Revoked => {
            request.authority.generation.next() == Some(grant.authority.generation)
        }
    }
}

fn profile_operation_domain(profile: Identity, access_tag: &[u8]) -> Vec<u8> {
    [b"profile:".as_slice(), profile.0.as_slice(), b":".as_slice(), access_tag].concat()
}

fn profile_observation_request(
    operations: &[OperationRecord],
    position: JournalPosition,
    binding: &ProfileBinding,
    payload: Vec<u8>,
) -> Result<EffectRequest, (RuntimeError, Identity)> {
    let kind =
        EffectKind::Profile { profile: binding.profile, access: ProfileAccess::Read, payload };
    if let Some(request) = operations
        .iter()
        .find(|record| {
            matches!(record.outcome.as_ref(), None | Some(EffectOutcome::Indeterminate { .. }))
                && profile_observation_matches(&record.request, &binding.context, &kind)
        })
        .map(|record| record.request.clone())
    {
        return Ok(request);
    }

    let EffectKind::Profile { payload, .. } = &kind else { unreachable!() };
    let operation = hash_identity(&[
        b"visa-profile-observe-v1",
        &binding.profile.0,
        &binding.context.resource.identity.0,
        &binding.context.resource.generation.0.to_be_bytes(),
        &binding.context.subject.identity.0,
        &binding.context.subject.generation.0.to_be_bytes(),
        &binding.context.node.0.0,
        &binding.context.epoch.0.to_be_bytes(),
        &position.0.to_be_bytes(),
        payload,
    ]);
    let idempotency_key =
        IdempotencyKey(hash_identity(&[b"visa-profile-observe-idempotency-v1", &operation.0]).0);
    effect_request(&binding.context, operation, idempotency_key, None, kind)
        .map_err(|error| (error, operation))
}

fn profile_observation_matches(
    request: &EffectRequest,
    binding: &BindingContext,
    kind: &EffectKind,
) -> bool {
    request.causal_parent.is_none()
        && request.node == binding.node
        && request.subject == binding.subject
        && request.resource == binding.resource
        && request.authority == binding.authority
        && request.lease_epoch == binding.epoch
        && request.kind == *kind
}

fn execute_profile_request<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    operation: Identity,
    request: EffectRequest,
) -> Result<ProfileCallResult, ProfileFailure> {
    let outcome = execute(coordinator, command_for(operation), request)
        .map_err(|error| profile_runtime_error(error, operation))?;
    match outcome {
        EffectOutcome::Succeeded { result: EffectResult::Profile { profile, payload }, .. }
            if profile == binding.profile =>
        {
            Ok(ProfileCallResult { operation, operation_id: identity_string(operation), payload })
        }
        other => Err(profile_outcome_error(other, operation)),
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
    validate_binding_for_resource(state, binding, expected_resource, required)
}

fn validate_profile_binding(
    state: &CanonicalState,
    binding: &ProfileBinding,
    access: ProfileAccess,
) -> Result<(), BindingCheckError> {
    let required = access.required_rights();
    if !binding.required_rights.contains(required) {
        return Err(BindingCheckError::Denied);
    }
    let mut resources = visa_profile::profile_resources(&state.extensions)
        .map_err(|_| BindingCheckError::Stale)?
        .into_iter()
        .filter(|resource| resource.profile == binding.profile);
    let Some(resource) = resources.next() else {
        return Err(BindingCheckError::Stale);
    };
    if resources.next().is_some() || resource.resource != binding.context.resource {
        return Err(BindingCheckError::Stale);
    }
    validate_binding_for_resource(state, &binding.context, resource.resource, required)
}

fn validate_binding_for_resource(
    state: &CanonicalState,
    binding: &BindingContext,
    expected_resource: EntityRef,
    required: Rights,
) -> Result<(), BindingCheckError> {
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

fn profile_idempotency_key(
    binding: &BindingContext,
    profile: Identity,
    access_tag: &[u8],
    value: &[u8],
) -> IdempotencyKey {
    IdempotencyKey(
        hash_identity(&[
            b"visa-profile-continuity-idempotency-v1",
            &binding.resource.identity.0,
            &binding.resource.generation.0.to_be_bytes(),
            &binding.subject.identity.0,
            &profile.0,
            access_tag,
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

const fn profile_binding_error(error: BindingCheckError) -> ProfileFailure {
    match error {
        BindingCheckError::Stale => ProfileFailure::StaleBinding,
        BindingCheckError::Denied => ProfileFailure::Denied,
    }
}

fn profile_runtime_error(error: RuntimeError, operation: Identity) -> ProfileFailure {
    match error {
        RuntimeError::Rejected(Rejection::StaleGeneration { .. })
        | RuntimeError::Rejected(Rejection::LeaseEpochMismatch { .. })
        | RuntimeError::Rejected(Rejection::NodeMismatch { .. }) => ProfileFailure::StaleBinding,
        RuntimeError::Rejected(Rejection::UnknownAuthority { .. })
        | RuntimeError::Rejected(Rejection::AuthorityRevoked { .. })
        | RuntimeError::Rejected(Rejection::AuthorityAmplification { .. })
        | RuntimeError::Rejected(Rejection::InsufficientAuthority { .. })
        | RuntimeError::Rejected(Rejection::AuthoritySubjectMismatch)
        | RuntimeError::Rejected(Rejection::AuthorityResourceMismatch) => ProfileFailure::Denied,
        RuntimeError::Rejected(Rejection::DuplicateOperation { .. })
        | RuntimeError::Rejected(Rejection::IdempotencyConflict { .. })
        | RuntimeError::Rejected(Rejection::OutcomeMismatch) => ProfileFailure::Conflict,
        RuntimeError::Rejected(Rejection::UnknownProfile { .. })
        | RuntimeError::Rejected(Rejection::InvalidProfilePayload { .. })
        | RuntimeError::Rejected(Rejection::ProfileMismatch)
        | RuntimeError::Rejected(Rejection::InvalidRights) => ProfileFailure::Invalid,
        RuntimeError::OperationOutcomeUnknown { .. }
        | RuntimeError::JournalOutcomeUnknown { .. } => {
            ProfileFailure::Indeterminate(identity_string(operation))
        }
        RuntimeError::Provider(error) => match error.kind {
            ProviderErrorKind::Denied | ProviderErrorKind::Revoked => ProfileFailure::Denied,
            ProviderErrorKind::StaleGeneration | ProviderErrorKind::StaleEpoch => {
                ProfileFailure::StaleBinding
            }
            ProviderErrorKind::Conflict => ProfileFailure::Conflict,
            ProviderErrorKind::InvalidRequest | ProviderErrorKind::Integrity => {
                ProfileFailure::Invalid
            }
            ProviderErrorKind::Unsupported => ProfileFailure::Unsupported,
            ProviderErrorKind::OutcomeUnknown => {
                ProfileFailure::Indeterminate(identity_string(operation))
            }
            _ => ProfileFailure::Unavailable,
        },
        _ => ProfileFailure::Unavailable,
    }
}

fn profile_outcome_error(outcome: EffectOutcome, operation: Identity) -> ProfileFailure {
    match outcome {
        EffectOutcome::Failed(failure) => match failure.class {
            FailureClass::Denied => ProfileFailure::Denied,
            FailureClass::Conflict => ProfileFailure::Conflict,
            FailureClass::Integrity => ProfileFailure::Invalid,
            FailureClass::Unavailable | FailureClass::Internal => ProfileFailure::Unavailable,
        },
        EffectOutcome::Indeterminate { .. } => {
            ProfileFailure::Indeterminate(identity_string(operation))
        }
        EffectOutcome::Cancelled { .. } => ProfileFailure::Cancelled,
        EffectOutcome::Unsupported { .. } => ProfileFailure::Unsupported,
        EffectOutcome::Succeeded { .. } => ProfileFailure::Invalid,
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
    use contract_core::{
        AuthorityGrant, DeliveryPolicy, Digest, EvidenceKind, EvidenceRef, Generation,
        JournalPosition, KeyValueClaim, Ownership, ResourceClaims, SchemaVersion, TimerClaim,
        TimerClock,
    };
    use visa_profile::{
        ContinuityDisposition, LOGICAL_REQUEST_EXTENSION_ID, LogicalRequestClaim,
        LogicalRequestIdempotency, LogicalRequestPhase, LogicalRequestReplay, LogicalRequestState,
        LogicalRequestTransport, logical_request_extension,
    };

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

    fn profile_preview_fixture() -> (CanonicalState, ProfileBinding, Vec<u8>, Vec<u8>) {
        let node = NodeIdentity::new(Identity::from_u128(20));
        let component = EntityRef::new(Identity::from_u128(21), Generation(2));
        let request_resource = EntityRef::new(Identity::from_u128(22), Generation(3));
        let request_authority = EntityRef::new(Identity::from_u128(23), Generation(4));
        let request = b"prepared logical request".to_vec();
        let logical_request = LogicalRequestState {
            claim: LogicalRequestClaim {
                resource: request_resource,
                peer_identity: b"service.example/v1".to_vec(),
                credential_reference: Identity::from_u128(24),
                required_rights: Rights::PROFILE_WRITE.union(Rights::REBIND),
                transport: LogicalRequestTransport::Reconnectable,
                delivery: DeliveryPolicy::Deduplicated,
                replay: LogicalRequestReplay::WithOperationId,
                idempotency: LogicalRequestIdempotency::OperationIdDeduplicated,
                timeout_millis: 5_000,
                max_request_size: 1024,
                max_response_size: 4096,
            },
            operation_id: Identity::from_u128(25),
            request_size: request.len() as u32,
            request_digest: canonical_digest(request.as_slice()).unwrap(),
            phase: LogicalRequestPhase::Ready,
            response_cursor: 0,
            response: None,
            rejection: None,
            disposition: ContinuityDisposition::Revalidate,
            last_operation: None,
        };
        let extension = logical_request_extension(&logical_request).unwrap();
        let authority = AuthorityGrant::active_root(
            request_authority,
            component,
            request_resource,
            Rights::PROFILE_WRITE.union(Rights::REBIND),
        );
        let mut state = CanonicalState::dormant_with_extensions(
            component,
            node,
            Digest::from_bytes([26; 32]),
            Digest::from_bytes([27; 32]),
            SchemaVersion::new(1, 0),
            ResourceClaims {
                timer: TimerClaim {
                    resource: EntityRef::initial(Identity::from_u128(28)),
                    clock: TimerClock::PausedMonotonicDuration,
                    required_rights: Rights::TIMER_ARM,
                },
                key_value: KeyValueClaim {
                    resource: EntityRef::initial(Identity::from_u128(29)),
                    namespace: Identity::from_u128(30),
                    required_rights: Rights::KV_READ,
                    delivery: DeliveryPolicy::Deduplicated,
                },
            },
            vec![authority],
            vec![extension],
        );
        state.phase = HandoffPhase::Running;
        state.activation.status = ActivationStatus::Active;
        state.ownership = Ownership::owned(node, LeaseEpoch(8));
        let binding = ProfileBinding::for_state(&state, LOGICAL_REQUEST_EXTENSION_ID).unwrap();
        let payload = visa_profile::encode_logical_request_operation(
            &visa_profile::LogicalRequestOperation::Start { request: request.clone() },
        )
        .unwrap();
        (state, binding, logical_request.operation_id.0.to_vec(), payload)
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

        let profile = Identity::from_u128(12);
        let base_profile_key = profile_idempotency_key(&base, profile, b"write", b"request-key");
        for changed in &changed_scopes {
            let changed_key = profile_idempotency_key(changed, profile, b"write", b"request-key");
            if changed.resource == base.resource
                && changed.subject.identity == base.subject.identity
            {
                assert_eq!(changed_key, base_profile_key);
            }
        }
    }

    #[test]
    fn profile_observation_retry_reuses_unresolved_intent_then_advances_after_resolution() {
        let mut context = binding(5, 6, 7, 8);
        context.exposed_rights = Rights::PROFILE_READ;
        let profile = Identity::from_u128(12);
        let binding = ProfileBinding { context, profile, required_rights: Rights::PROFILE_READ };
        let payload = b"typed-observation".to_vec();

        let first =
            profile_observation_request(&[], JournalPosition(10), &binding, payload.clone())
                .unwrap();
        let mut records = vec![OperationRecord::prepared(first.clone())];

        let retry =
            profile_observation_request(&records, JournalPosition(11), &binding, payload.clone())
                .unwrap();
        assert_eq!(retry, first);
        assert_eq!(records.len(), 1, "retry must not add a second durable intent");

        records[0].outcome = Some(EffectOutcome::Indeterminate { evidence: None });
        let reconcile =
            profile_observation_request(&records, JournalPosition(12), &binding, payload.clone())
                .unwrap();
        assert_eq!(reconcile, first);

        records[0].outcome = Some(EffectOutcome::Succeeded {
            result: EffectResult::Profile { profile, payload: b"observed".to_vec() },
            evidence: EvidenceRef {
                identity: Identity::from_u128(13),
                kind: EvidenceKind::EffectOutcome,
                digest: Digest::from_bytes([14; 32]),
            },
        });
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    matches!(
                        record.outcome.as_ref(),
                        None | Some(EffectOutcome::Indeterminate { .. })
                    )
                })
                .count(),
            0,
            "the retried intent must converge instead of leaving unresolved residue",
        );

        let next =
            profile_observation_request(&records, JournalPosition(13), &binding, payload).unwrap();
        assert_ne!(next.operation, first.operation);
        assert_ne!(next.idempotency_key, first.idempotency_key);
    }

    #[test]
    fn source_unresolved_exact_profile_request_is_replayed() {
        let (mut state, binding, idempotency, payload) = profile_preview_fixture();
        let candidate = prepare_profile_effect(
            &state,
            &binding,
            ProfileAccess::Write,
            &idempotency,
            payload.clone(),
        )
        .unwrap();
        state.operations.push(OperationRecord::prepared(candidate.clone()));
        assert_eq!(
            prepare_profile_effect(
                &state,
                &binding,
                ProfileAccess::Write,
                &idempotency,
                payload.clone(),
            ),
            Ok(candidate.clone()),
        );
    }

    #[test]
    fn profile_same_key_continuity_accepts_one_generation_revoked_source_grant() {
        let (mut state, source_binding, idempotency, payload) = profile_preview_fixture();
        let source = prepare_profile_effect(
            &state,
            &source_binding,
            ProfileAccess::Write,
            &idempotency,
            payload.clone(),
        )
        .unwrap();
        state.operations.push(OperationRecord::prepared(source.clone()));

        let destination_node = NodeIdentity::new(Identity::from_u128(40));
        let destination_component =
            EntityRef::new(state.component.identity, state.component.generation.next().unwrap());
        let destination_authority = EntityRef::initial(Identity::from_u128(41));
        state.component = destination_component;
        state.activation.node = destination_node;
        state.ownership = Ownership::owned(destination_node, LeaseEpoch(9));
        state.authorities.push(AuthorityGrant::active_root(
            destination_authority,
            destination_component,
            source.resource,
            Rights::PROFILE_WRITE.union(Rights::REBIND),
        ));
        let source_grant =
            state.authorities.iter_mut().find(|grant| grant.authority == source.authority).unwrap();
        source_grant.status = AuthorityStatus::Revoked;
        source_grant.authority.generation = source.authority.generation.next().unwrap();
        let destination_binding =
            ProfileBinding::for_state(&state, LOGICAL_REQUEST_EXTENSION_ID).unwrap();

        let mut without_history = state.clone();
        without_history.operations.clear();
        let destination_candidate = prepare_profile_effect(
            &without_history,
            &destination_binding,
            ProfileAccess::Write,
            &idempotency,
            payload.clone(),
        )
        .unwrap();
        assert_ne!(source.operation, destination_candidate.operation);
        assert_ne!(source.node, destination_candidate.node);
        assert_ne!(source.subject.generation, destination_candidate.subject.generation);
        assert_ne!(source.authority, destination_candidate.authority);
        assert_ne!(source.lease_epoch, destination_candidate.lease_epoch);
        assert_eq!(
            prepare_profile_effect(
                &state,
                &destination_binding,
                ProfileAccess::Write,
                &idempotency,
                payload.clone(),
            ),
            Ok(source.clone()),
        );

        let source_grant_index = state
            .authorities
            .iter()
            .position(|grant| grant.authority.identity == source.authority.identity)
            .unwrap();
        let invalid_grants: &[fn(&mut AuthorityGrant)] = &[
            |grant| grant.authority.generation = grant.authority.generation.next().unwrap(),
            |grant| grant.subject = EntityRef::initial(Identity::from_u128(42)),
            |grant| grant.resource = EntityRef::initial(Identity::from_u128(43)),
            |grant| grant.rights = Rights::REBIND,
        ];
        for mutate in invalid_grants {
            let mut invalid = state.clone();
            mutate(&mut invalid.authorities[source_grant_index]);
            assert_eq!(
                prepare_profile_effect(
                    &invalid,
                    &destination_binding,
                    ProfileAccess::Write,
                    &idempotency,
                    payload.clone(),
                ),
                Err(ProfileFailure::Conflict),
            );
        }
        let mut duplicate = state.clone();
        duplicate.authorities.push(duplicate.authorities[source_grant_index].clone());
        assert_eq!(
            prepare_profile_effect(
                &duplicate,
                &destination_binding,
                ProfileAccess::Write,
                &idempotency,
                payload,
            ),
            Err(ProfileFailure::Conflict),
        );
    }

    #[test]
    fn profile_preview_rejects_corrupt_historical_requests_and_operation_collisions() {
        let (mut state, binding, idempotency, payload) = profile_preview_fixture();
        let candidate = prepare_profile_effect(
            &state,
            &binding,
            ProfileAccess::Write,
            &idempotency,
            payload.clone(),
        )
        .unwrap();
        state.operations.push(OperationRecord::prepared(candidate.clone()));

        let mutations: &[fn(&mut EffectRequest)] = &[
            |request| request.operation = Identity::from_u128(31),
            |request| request.idempotency_key = IdempotencyKey::from_u128(31),
            |request| request.causal_parent = Some(Identity::from_u128(32)),
            |request| request.node = NodeIdentity::new(Identity::from_u128(32)),
            |request| request.subject.generation = Generation(33),
            |request| request.authority.generation = Generation(35),
            |request| request.lease_epoch = LeaseEpoch(36),
            |request| request.request_digest = Digest::from_bytes([37; 32]),
        ];
        for mutate in mutations {
            let mut changed = state.clone();
            mutate(&mut changed.operations[0].request);
            assert_eq!(
                prepare_profile_effect(
                    &changed,
                    &binding,
                    ProfileAccess::Write,
                    &idempotency,
                    payload.clone(),
                ),
                Err(ProfileFailure::Conflict),
            );
        }

        let mut collision = candidate;
        collision.idempotency_key = IdempotencyKey::from_u128(38);
        state.operations.push(OperationRecord::prepared(collision));
        assert_eq!(
            prepare_profile_effect(&state, &binding, ProfileAccess::Write, &idempotency, payload,),
            Err(ProfileFailure::Conflict),
        );
    }
}
