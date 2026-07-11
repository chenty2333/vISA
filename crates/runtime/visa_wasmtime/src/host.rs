use contract_core::{
    ActivationStatus, AuthorityStatus, CanonicalState, EffectKind, EffectOutcome, EffectRequest,
    EffectResult, EntityRef, FailureClass, HandoffPhase, IdempotencyKey, Identity, LeaseEpoch,
    LogicalDurationNanos, NodeIdentity, Rejection, Replay, Rights,
};
use sha2::{Digest as _, Sha256};
use substrate_api::{AuthorityPort, JournalPort, KvPort, LeasePort, ProviderErrorKind, TimerPort};
use visa_runtime::{CommandReceipt, Coordinator, RuntimeError, canonical_digest};
use wasmtime::component::{Resource, ResourceTable};

use crate::bindings::visa::continuity::{
    key_value::{
        Host as KvHost, HostNamespace, KvError, VersionedValue as WitVersionedValue, WriteResult,
    },
    timers::{ArmResult, Host as TimerHost, HostTimerBinding, TimerError},
};

/// Provider capabilities required by component imports. The adapter never
/// accesses these ports directly; the bound only makes `Coordinator::effect`
/// available for a generic provider.
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

/// Opaque host-local receipt behind an imported key-value resource handle.
#[derive(Clone, Debug)]
pub struct KvBinding {
    context: BindingContext,
    completion_parent: Option<Identity>,
}

/// Opaque host-local receipt behind an imported timer resource handle.
#[derive(Clone, Debug)]
pub struct TimerBinding(BindingContext);

#[cfg(any(test, feature = "test-control"))]
struct UnsupportedLiveResource;

/// Wasmtime store data. Canonical state and provider ownership remain solely
/// inside the coordinator; the resource table contains only local receipts.
pub struct StoreState<P> {
    coordinator: Coordinator<P>,
    table: ResourceTable,
    #[cfg(any(test, feature = "test-control"))]
    unsupported_live_resource: Option<Resource<UnsupportedLiveResource>>,
}

impl<P> StoreState<P> {
    pub(crate) fn new(coordinator: Coordinator<P>) -> Self {
        Self {
            coordinator,
            table: ResourceTable::new(),
            #[cfg(any(test, feature = "test-control"))]
            unsupported_live_resource: None,
        }
    }

    pub fn coordinator(&self) -> &Coordinator<P> {
        &self.coordinator
    }

    pub fn coordinator_mut(&mut self) -> &mut Coordinator<P> {
        &mut self.coordinator
    }

    pub fn resource_table_is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub(crate) fn into_coordinator(self) -> Coordinator<P> {
        self.coordinator
    }

    pub(crate) fn fresh_resources(
        &mut self,
    ) -> Result<(Resource<KvBinding>, Resource<TimerBinding>), BindingError> {
        if !self.table.is_empty() {
            return Err(BindingError::LiveResources);
        }
        self.push_profile_resources()
    }

    /// Recreate only the source profile handles after a rejected safe point.
    /// Unrelated local handles remain owned by the source; existing timer or
    /// KV handles would make this recovery ambiguous and are rejected.
    pub(crate) fn fresh_source_thaw_resources(
        &mut self,
    ) -> Result<(Resource<KvBinding>, Resource<TimerBinding>), BindingError> {
        if self.table.iter_mut().any(|entry| {
            entry.downcast_mut::<KvBinding>().is_some()
                || entry.downcast_mut::<TimerBinding>().is_some()
        }) {
            return Err(BindingError::LiveResources);
        }
        self.push_profile_resources()
    }

    fn push_profile_resources(
        &mut self,
    ) -> Result<(Resource<KvBinding>, Resource<TimerBinding>), BindingError> {
        let state = self.coordinator.state();
        let key_value = binding_for(
            state,
            state.key_value.claim.resource,
            state.key_value.claim.required_rights,
        )?;
        let timer =
            binding_for(state, state.timer.claim.resource, state.timer.claim.required_rights)?;
        let key_value = self
            .table
            .push(KvBinding { context: key_value, completion_parent: None })
            .map_err(|_| BindingError::ResourceTable)?;
        let timer = match self.table.push(TimerBinding(timer)) {
            Ok(timer) => timer,
            Err(_) => {
                self.table.delete(key_value).map_err(|_| BindingError::ResourceTable)?;
                return Err(BindingError::ResourceTable);
            }
        };
        Ok((key_value, timer))
    }

    pub(crate) fn set_completion_parent(&mut self, parent: Identity) -> Result<(), BindingError> {
        let mut count = 0;
        for entry in self.table.iter_mut() {
            if let Some(binding) = entry.downcast_mut::<KvBinding>() {
                binding.completion_parent = Some(parent);
                count += 1;
            }
        }
        match count {
            1 => Ok(()),
            0 => Err(BindingError::Missing),
            _ => {
                self.clear_completion_parent();
                Err(BindingError::Ambiguous)
            }
        }
    }

    pub(crate) fn clear_completion_parent(&mut self) {
        for entry in self.table.iter_mut() {
            if let Some(binding) = entry.downcast_mut::<KvBinding>() {
                binding.completion_parent = None;
            }
        }
    }

    #[cfg(any(test, feature = "test-control"))]
    pub(crate) fn inject_unsupported_live_resource(&mut self) -> Result<(), BindingError> {
        if self.unsupported_live_resource.is_some() {
            return Err(BindingError::LiveResources);
        }
        let resource =
            self.table.push(UnsupportedLiveResource).map_err(|_| BindingError::ResourceTable)?;
        self.unsupported_live_resource = Some(resource);
        Ok(())
    }

    #[cfg(any(test, feature = "test-control"))]
    pub(crate) fn clear_unsupported_live_resource(&mut self) -> Result<(), BindingError> {
        let resource = self.unsupported_live_resource.take().ok_or(BindingError::Missing)?;
        self.table.delete(resource).map(|_| ()).map_err(|_| BindingError::ResourceTable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindingError {
    Inactive,
    Missing,
    Ambiguous,
    InvalidReceipt,
    LiveResources,
    ResourceTable,
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

    if matches!(state.phase, HandoffPhase::Committed) && state.prepared_destination.is_some() {
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

impl<P> KvHost for StoreState<P> where P: AdapterProvider {}

impl<P> HostNamespace for StoreState<P>
where
    P: AdapterProvider,
{
    fn read(
        &mut self,
        resource: Resource<KvBinding>,
        key: String,
    ) -> wasmtime::Result<Result<Option<WitVersionedValue>, KvError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.context.clone();
        if let Err(error) = validate_binding(self.coordinator.state(), &binding, Rights::KV_READ) {
            return Ok(Err(kv_binding_error(error)));
        }
        let operation =
            read_operation(&binding, self.coordinator.journal_position(), key.as_bytes());
        let idempotency_key = idempotency_from_identity(operation);
        let kind = EffectKind::KeyValueRead { key: key.into_bytes() };
        let request = effect_request(&binding, operation, idempotency_key, None, kind)
            .map_err(kv_runtime_error_without_operation);
        let request = match request {
            Ok(request) => request,
            Err(error) => return Ok(Err(error)),
        };
        let outcome = match execute(&mut self.coordinator, command_for(operation), request) {
            Ok(outcome) => outcome,
            Err(error) => return Ok(Err(kv_runtime_error(error, operation))),
        };
        Ok(match outcome {
            EffectOutcome::Succeeded { result: EffectResult::KeyValueRead { value }, .. } => {
                Ok(value
                    .map(|value| WitVersionedValue { value: value.value, version: value.version }))
            }
            other => Err(kv_outcome_error(other, operation)),
        })
    }

    fn conditional_put(
        &mut self,
        resource: Resource<KvBinding>,
        idempotency_key: String,
        key: String,
        expected_version: Option<u64>,
        value: Vec<u8>,
    ) -> wasmtime::Result<Result<WriteResult, KvError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        if let Err(error) =
            validate_binding(self.coordinator.state(), &binding.context, Rights::KV_WRITE)
        {
            return Ok(Err(kv_binding_error(error)));
        }
        let idempotency =
            idempotency_key_for(&binding.context, b"kv-cas", idempotency_key.as_bytes());
        let operation = operation_for(b"kv-cas", &binding.context, idempotency);
        let kind =
            EffectKind::KeyValueCompareAndSet { key: key.into_bytes(), expected_version, value };
        let request = effect_request(
            &binding.context,
            operation,
            idempotency,
            binding.completion_parent,
            kind,
        )
        .map_err(kv_runtime_error_without_operation);
        let request = match request {
            Ok(request) => request,
            Err(error) => return Ok(Err(error)),
        };
        let outcome = match execute(&mut self.coordinator, command_for(operation), request) {
            Ok(outcome) => outcome,
            Err(error) => return Ok(Err(kv_runtime_error(error, operation))),
        };
        Ok(match outcome {
            EffectOutcome::Succeeded {
                result: EffectResult::KeyValue { version, applied },
                ..
            } => Ok(WriteResult { operation_id: identity_string(operation), version, applied }),
            other => Err(kv_outcome_error(other, operation)),
        })
    }

    fn drop(&mut self, resource: Resource<KvBinding>) -> wasmtime::Result<()> {
        self.table.delete(resource).map(|_| ()).map_err(wasmtime::Error::new)
    }
}

impl<P> TimerHost for StoreState<P> where P: AdapterProvider {}

impl<P> HostTimerBinding for StoreState<P>
where
    P: AdapterProvider,
{
    fn arm(
        &mut self,
        resource: Resource<TimerBinding>,
        idempotency_key: String,
        duration_ns: u64,
    ) -> wasmtime::Result<Result<ArmResult, TimerError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.0.clone();
        if let Err(error) = validate_binding(self.coordinator.state(), &binding, Rights::TIMER_ARM)
        {
            return Ok(Err(timer_binding_error(error)));
        }
        let idempotency = idempotency_key_for(&binding, b"timer-arm", idempotency_key.as_bytes());
        let operation = operation_for(b"timer-arm", &binding, idempotency);
        let causal_parent = match self.coordinator.state().timer.status {
            contract_core::TimerStatus::Frozen(contract_core::TimerDisposition::Pending {
                arm_operation,
                ..
            }) => Some(arm_operation),
            _ => None,
        };
        let kind = EffectKind::TimerArm { remaining: LogicalDurationNanos(duration_ns) };
        let request = effect_request(&binding, operation, idempotency, causal_parent, kind)
            .map_err(|error| timer_runtime_error(error, operation));
        let request = match request {
            Ok(request) => request,
            Err(error) => return Ok(Err(error)),
        };
        let outcome = match execute(&mut self.coordinator, command_for(operation), request) {
            Ok(outcome) => outcome,
            Err(error) => return Ok(Err(timer_runtime_error(error, operation))),
        };
        Ok(match outcome {
            EffectOutcome::Succeeded { result: EffectResult::TimerArmed { .. }, .. } => {
                Ok(ArmResult { operation_id: identity_string(operation) })
            }
            other => Err(timer_outcome_error(other)),
        })
    }

    fn cancel(
        &mut self,
        resource: Resource<TimerBinding>,
        operation_id: String,
    ) -> wasmtime::Result<Result<(), TimerError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.0.clone();
        if let Err(error) =
            validate_binding(self.coordinator.state(), &binding, Rights::TIMER_CANCEL)
        {
            return Ok(Err(timer_binding_error(error)));
        }
        let Some(target) = parse_identity(&operation_id) else {
            return Ok(Err(TimerError::NotPending));
        };
        if self.coordinator.state().timer.active_operation != Some(target) {
            return Ok(Err(TimerError::NotPending));
        }
        let idempotency = idempotency_key_for(&binding, b"timer-cancel", &target.0);
        let operation = operation_for(b"timer-cancel", &binding, idempotency);
        let kind = EffectKind::TimerCancel { target_operation: target };
        let request = effect_request(&binding, operation, idempotency, Some(target), kind)
            .map_err(|error| timer_runtime_error(error, operation));
        let request = match request {
            Ok(request) => request,
            Err(error) => return Ok(Err(error)),
        };
        let outcome = match execute(&mut self.coordinator, command_for(operation), request) {
            Ok(outcome) => outcome,
            Err(error) => return Ok(Err(timer_runtime_error(error, operation))),
        };
        Ok(match outcome {
            EffectOutcome::Succeeded { result: EffectResult::TimerCancelled, .. } => Ok(()),
            other => Err(timer_outcome_error(other)),
        })
    }

    fn drop(&mut self, resource: Resource<TimerBinding>) -> wasmtime::Result<()> {
        self.table.delete(resource).map(|_| ()).map_err(wasmtime::Error::new)
    }
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
    if binding.resource
        != if required == Rights::KV_READ || required == Rights::KV_WRITE {
            state.key_value.claim.resource
        } else {
            state.timer.claim.resource
        }
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

fn operation_for(domain: &[u8], binding: &BindingContext, key: IdempotencyKey) -> Identity {
    hash_identity(&[
        b"visa-operation-v1",
        domain,
        &binding.resource.identity.0,
        &binding.resource.generation.0.to_be_bytes(),
        &binding.subject.generation.0.to_be_bytes(),
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
        b"visa-read-v1",
        &binding.resource.identity.0,
        &binding.resource.generation.0.to_be_bytes(),
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
            b"visa-idempotency-v1",
            domain,
            &binding.resource.identity.0,
            &binding.resource.generation.0.to_be_bytes(),
            &binding.subject.generation.0.to_be_bytes(),
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

pub(crate) fn identity_string(identity: Identity) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in identity.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn parse_identity(value: &str) -> Option<Identity> {
    if value.len() != 32 {
        return None;
    }
    let mut output = [0; 16];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
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

fn kv_binding_error(error: BindingCheckError) -> KvError {
    match error {
        BindingCheckError::Stale => KvError::StaleBinding,
        BindingCheckError::Denied => KvError::Denied,
    }
}

fn timer_binding_error(error: BindingCheckError) -> TimerError {
    match error {
        BindingCheckError::Stale => TimerError::StaleBinding,
        BindingCheckError::Denied => TimerError::Denied,
    }
}

fn kv_runtime_error_without_operation(error: RuntimeError) -> KvError {
    kv_runtime_error(error, Identity::ZERO)
}

fn kv_runtime_error(error: RuntimeError, operation: Identity) -> KvError {
    match error {
        RuntimeError::Rejected(Rejection::StaleGeneration { .. })
        | RuntimeError::Rejected(Rejection::LeaseEpochMismatch { .. })
        | RuntimeError::Rejected(Rejection::NodeMismatch { .. }) => KvError::StaleBinding,
        RuntimeError::Rejected(Rejection::UnknownAuthority { .. })
        | RuntimeError::Rejected(Rejection::AuthorityRevoked { .. })
        | RuntimeError::Rejected(Rejection::AuthorityAmplification { .. })
        | RuntimeError::Rejected(Rejection::InsufficientAuthority { .. })
        | RuntimeError::Rejected(Rejection::AuthoritySubjectMismatch)
        | RuntimeError::Rejected(Rejection::AuthorityResourceMismatch) => KvError::Denied,
        RuntimeError::Rejected(Rejection::DuplicateOperation { .. })
        | RuntimeError::Rejected(Rejection::IdempotencyConflict { .. })
        | RuntimeError::Rejected(Rejection::OutcomeMismatch) => KvError::Conflict,
        RuntimeError::OperationOutcomeUnknown { .. }
        | RuntimeError::JournalOutcomeUnknown { .. } => {
            KvError::Indeterminate(identity_string(operation))
        }
        RuntimeError::Provider(error) => match error.kind {
            ProviderErrorKind::Denied | ProviderErrorKind::Revoked => KvError::Denied,
            ProviderErrorKind::StaleGeneration | ProviderErrorKind::StaleEpoch => {
                KvError::StaleBinding
            }
            ProviderErrorKind::Conflict => KvError::Conflict,
            ProviderErrorKind::OutcomeUnknown => KvError::Indeterminate(identity_string(operation)),
            _ => KvError::Unavailable,
        },
        _ => KvError::Unavailable,
    }
}

fn kv_outcome_error(outcome: EffectOutcome, operation: Identity) -> KvError {
    match outcome {
        EffectOutcome::Failed(failure) => match failure.class {
            FailureClass::Denied => KvError::Denied,
            FailureClass::Conflict => KvError::Conflict,
            FailureClass::Unavailable | FailureClass::Integrity | FailureClass::Internal => {
                KvError::Unavailable
            }
        },
        EffectOutcome::Indeterminate { .. } => KvError::Indeterminate(identity_string(operation)),
        EffectOutcome::Cancelled { .. }
        | EffectOutcome::Unsupported { .. }
        | EffectOutcome::Succeeded { .. } => KvError::Unavailable,
    }
}

fn timer_runtime_error(error: RuntimeError, _operation: Identity) -> TimerError {
    match error {
        RuntimeError::Rejected(Rejection::StaleGeneration { .. })
        | RuntimeError::Rejected(Rejection::LeaseEpochMismatch { .. })
        | RuntimeError::Rejected(Rejection::NodeMismatch { .. }) => TimerError::StaleBinding,
        RuntimeError::Rejected(Rejection::UnknownAuthority { .. })
        | RuntimeError::Rejected(Rejection::AuthorityRevoked { .. })
        | RuntimeError::Rejected(Rejection::AuthorityAmplification { .. })
        | RuntimeError::Rejected(Rejection::InsufficientAuthority { .. })
        | RuntimeError::Rejected(Rejection::AuthoritySubjectMismatch)
        | RuntimeError::Rejected(Rejection::AuthorityResourceMismatch) => TimerError::Denied,
        RuntimeError::Rejected(Rejection::TimerStateConflict)
        | RuntimeError::Rejected(Rejection::UnknownOperation { .. }) => TimerError::NotPending,
        RuntimeError::Provider(error) => match error.kind {
            ProviderErrorKind::Denied | ProviderErrorKind::Revoked => TimerError::Denied,
            ProviderErrorKind::StaleGeneration | ProviderErrorKind::StaleEpoch => {
                TimerError::StaleBinding
            }
            ProviderErrorKind::NotFound | ProviderErrorKind::Conflict => TimerError::NotPending,
            _ => TimerError::Unavailable,
        },
        _ => TimerError::Unavailable,
    }
}

fn timer_outcome_error(outcome: EffectOutcome) -> TimerError {
    match outcome {
        EffectOutcome::Failed(failure) => match failure.class {
            FailureClass::Denied => TimerError::Denied,
            FailureClass::Conflict => TimerError::NotPending,
            FailureClass::Unavailable | FailureClass::Integrity | FailureClass::Internal => {
                TimerError::Unavailable
            }
        },
        EffectOutcome::Cancelled { .. } => TimerError::NotPending,
        EffectOutcome::Indeterminate { .. }
        | EffectOutcome::Unsupported { .. }
        | EffectOutcome::Succeeded { .. } => TimerError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_identity_text_round_trips_and_rejects_noncanonical_text() {
        let identity = Identity::from_u128(0x1234);
        assert_eq!(parse_identity(&identity_string(identity)), Some(identity));
        assert_eq!(parse_identity("ABCDEF"), None);
        assert_eq!(parse_identity("gggggggggggggggggggggggggggggggg"), None);
    }

    #[test]
    fn runtime_failures_map_to_the_exact_wit_error_categories() {
        let operation = Identity::from_u128(77);
        let authority = EntityRef::initial(Identity::from_u128(78));
        assert!(matches!(
            kv_runtime_error(
                RuntimeError::Rejected(Rejection::AuthorityRevoked { authority }),
                operation
            ),
            KvError::Denied
        ));
        assert!(matches!(
            kv_runtime_error(
                RuntimeError::Provider(substrate_api::ProviderError::new(
                    ProviderErrorKind::Conflict,
                    false
                )),
                operation
            ),
            KvError::Conflict
        ));
        assert!(matches!(
            kv_runtime_error(
                RuntimeError::Provider(substrate_api::ProviderError::new(
                    ProviderErrorKind::StaleEpoch,
                    false
                )),
                operation
            ),
            KvError::StaleBinding
        ));
        match kv_runtime_error(RuntimeError::OperationOutcomeUnknown { operation }, operation) {
            KvError::Indeterminate(identity) => assert_eq!(identity, identity_string(operation)),
            _ => panic!("expected indeterminate error"),
        }
        assert!(matches!(
            kv_runtime_error(
                RuntimeError::Provider(substrate_api::ProviderError::new(
                    ProviderErrorKind::Unavailable,
                    true
                )),
                operation
            ),
            KvError::Unavailable
        ));

        assert!(matches!(
            timer_runtime_error(RuntimeError::Rejected(Rejection::TimerStateConflict), operation),
            TimerError::NotPending
        ));
        assert!(matches!(
            timer_runtime_error(
                RuntimeError::Provider(substrate_api::ProviderError::new(
                    ProviderErrorKind::StaleGeneration,
                    false
                )),
                operation
            ),
            TimerError::StaleBinding
        ));
    }
}
