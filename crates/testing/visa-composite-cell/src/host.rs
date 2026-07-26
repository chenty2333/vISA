//! Wasmtime store state for the composite world.
//!
//! A single store holds one resource table carrying all four bindings at once.
//! Canonical state stays with the coordinator; the table holds only opaque
//! receipts, so nothing engine-local can reach the portable record.

use contract_core::{CanonicalState, Identity, ProfileAccess};
use visa_component_adapter::{
    AdapterProvider, BindingError, BindingSet, KvBinding, ProfileBinding, ProfileCallResult,
    ProfileFailure, TimerBinding, identity_string, kv_conditional_put, kv_read, profile_execute,
    profile_observe, timer_arm, timer_cancel,
};
use visa_profile::{
    LOGICAL_REQUEST_EXTENSION_ID, LogicalRequestOperation, LogicalRequestResult,
    LogicalRequestState, LogicalRequestTransport, REGULAR_FILE_EXTENSION_ID, RegularFileOperation,
    RegularFileResult, RegularFileState, decode_logical_request_result, decode_regular_file_result,
    encode_logical_request_operation, encode_regular_file_operation, logical_request_state,
    regular_file_state,
};
use visa_runtime::Coordinator;
use wasmtime::component::{Resource, ResourceTable};

use crate::{
    bindings::{
        FileBinding, RequestBinding,
        visa::{
            continuity::{
                key_value::{
                    Host as KvHost, HostNamespace, KvError, VersionedValue as WitVersionedValue,
                    WriteResult,
                },
                timers::{ArmResult, Host as TimerHost, HostTimerBinding, TimerError},
            },
            file_continuity::regular_file::{
                Durability as WitDurability, FileError, FileObservation, Host as FileHost,
                HostFileBinding, ReadResult,
            },
            request_continuity::logical_request::{
                Host as RequestHost, HostRequestBinding, ObserveResult, RequestError,
                RequestObservation, Transport as WitTransport,
            },
        },
    },
    state::{to_wit_durability, to_wit_rejection, to_wit_request_phase, to_wit_response},
};

pub struct CompositeStoreState<P> {
    coordinator: Coordinator<P>,
    table: ResourceTable,
}

impl<P> CompositeStoreState<P> {
    pub(crate) fn new(coordinator: Coordinator<P>) -> Self {
        Self { coordinator, table: ResourceTable::new() }
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

    /// Push one handle per resource. All four are created together from an
    /// empty table so a partially bound component can never be observed.
    pub(crate) fn fresh_resources(&mut self) -> Result<CompositeResources, BindingError> {
        if !self.table.is_empty() {
            return Err(BindingError::LiveResources);
        }
        let BindingSet { key_value, timer } = BindingSet::for_state(self.coordinator.state())?;
        let file = FileBinding(ProfileBinding::for_state(
            self.coordinator.state(),
            REGULAR_FILE_EXTENSION_ID,
        )?);
        let request = RequestBinding(ProfileBinding::for_state(
            self.coordinator.state(),
            LOGICAL_REQUEST_EXTENSION_ID,
        )?);

        let key_value = self.push(key_value)?;
        let timer = match self.push(timer) {
            Ok(timer) => timer,
            Err(error) => return Err(self.unwind(error)),
        };
        let file = match self.push(file) {
            Ok(file) => file,
            Err(error) => return Err(self.unwind(error)),
        };
        let request = match self.push(request) {
            Ok(request) => request,
            Err(error) => return Err(self.unwind(error)),
        };
        Ok(CompositeResources { key_value, timer, file, request })
    }

    fn push<T: Send + 'static>(&mut self, value: T) -> Result<Resource<T>, BindingError> {
        self.table.push(value).map_err(|_| BindingError::ResourceTable)
    }

    /// Drop every handle pushed so far. A half-populated table would make a
    /// later safe point ambiguous, so binding failure clears it completely.
    fn unwind(&mut self, error: BindingError) -> BindingError {
        self.table = ResourceTable::new();
        error
    }

    /// Attribute the guest's completion write to the timer arm operation that
    /// released it, matching the cooperative-handoff adapter.
    pub(crate) fn set_completion_parent(&mut self, parent: Identity) -> Result<(), BindingError> {
        let mut count = 0;
        for entry in self.table.iter_mut() {
            if let Some(binding) = entry.downcast_mut::<KvBinding>() {
                binding.set_completion_parent(parent);
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
                binding.clear_completion_parent();
            }
        }
    }
}

pub(crate) struct CompositeResources {
    pub key_value: Resource<KvBinding>,
    pub timer: Resource<TimerBinding>,
    pub file: Resource<FileBinding>,
    pub request: Resource<RequestBinding>,
}

impl<P> KvHost for CompositeStoreState<P> where P: AdapterProvider {}

impl<P> HostNamespace for CompositeStoreState<P>
where
    P: AdapterProvider,
{
    fn read(
        &mut self,
        resource: Resource<KvBinding>,
        key: String,
    ) -> wasmtime::Result<Result<Option<WitVersionedValue>, KvError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(kv_read(&mut self.coordinator, &binding, key)
            .map(|value| {
                value.map(|value| WitVersionedValue { value: value.value, version: value.version })
            })
            .map_err(KvError::from))
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
        Ok(kv_conditional_put(
            &mut self.coordinator,
            &binding,
            idempotency_key,
            key,
            expected_version,
            value,
        )
        .map(|result| WriteResult {
            operation_id: result.operation_id,
            version: result.version,
            applied: result.applied,
        })
        .map_err(KvError::from))
    }

    fn drop(&mut self, resource: Resource<KvBinding>) -> wasmtime::Result<()> {
        self.table.delete(resource).map(|_| ()).map_err(wasmtime::Error::new)
    }
}

impl<P> TimerHost for CompositeStoreState<P> where P: AdapterProvider {}

impl<P> HostTimerBinding for CompositeStoreState<P>
where
    P: AdapterProvider,
{
    fn arm(
        &mut self,
        resource: Resource<TimerBinding>,
        idempotency_key: String,
        duration_ns: u64,
    ) -> wasmtime::Result<Result<ArmResult, TimerError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(timer_arm(&mut self.coordinator, &binding, idempotency_key, duration_ns)
            .map(|result| ArmResult { operation_id: result.operation_id })
            .map_err(TimerError::from))
    }

    fn cancel(
        &mut self,
        resource: Resource<TimerBinding>,
        operation_id: String,
    ) -> wasmtime::Result<Result<(), TimerError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(timer_cancel(&mut self.coordinator, &binding, operation_id).map_err(TimerError::from))
    }

    fn drop(&mut self, resource: Resource<TimerBinding>) -> wasmtime::Result<()> {
        self.table.delete(resource).map(|_| ()).map_err(wasmtime::Error::new)
    }
}

impl<P> FileHost for CompositeStoreState<P> where P: AdapterProvider {}

impl<P> HostFileBinding for CompositeStoreState<P>
where
    P: AdapterProvider,
{
    fn read(
        &mut self,
        resource: Resource<FileBinding>,
        max_bytes: u32,
    ) -> wasmtime::Result<Result<ReadResult, FileError>> {
        let binding = self.file_binding(&resource)?;
        Ok(file_read(&mut self.coordinator, &binding, max_bytes))
    }

    fn write(
        &mut self,
        resource: Resource<FileBinding>,
        idempotency_key: String,
        bytes: Vec<u8>,
        durability: WitDurability,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        let binding = self.file_binding(&resource)?;
        Ok(file_execute(
            &mut self.coordinator,
            &binding,
            ProfileAccess::Write,
            idempotency_key,
            RegularFileOperation::Write {
                bytes,
                durability: crate::state::from_wit_durability(durability),
            },
            ExpectedFileResult::Mutated,
        ))
    }

    fn append(
        &mut self,
        resource: Resource<FileBinding>,
        idempotency_key: String,
        bytes: Vec<u8>,
        durability: WitDurability,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        let binding = self.file_binding(&resource)?;
        Ok(file_execute(
            &mut self.coordinator,
            &binding,
            ProfileAccess::Write,
            idempotency_key,
            RegularFileOperation::Append {
                bytes,
                durability: crate::state::from_wit_durability(durability),
            },
            ExpectedFileResult::Mutated,
        ))
    }

    fn truncate(
        &mut self,
        resource: Resource<FileBinding>,
        idempotency_key: String,
        size: u64,
        durability: WitDurability,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        let binding = self.file_binding(&resource)?;
        Ok(file_execute(
            &mut self.coordinator,
            &binding,
            ProfileAccess::Write,
            idempotency_key,
            RegularFileOperation::Truncate {
                size,
                durability: crate::state::from_wit_durability(durability),
            },
            ExpectedFileResult::Mutated,
        ))
    }

    fn rename(
        &mut self,
        resource: Resource<FileBinding>,
        idempotency_key: String,
        relative_path: String,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        let binding = self.file_binding(&resource)?;
        Ok(file_execute(
            &mut self.coordinator,
            &binding,
            ProfileAccess::Write,
            idempotency_key,
            RegularFileOperation::Rename { relative_path: relative_path.into_bytes() },
            ExpectedFileResult::Renamed,
        ))
    }

    fn sync(
        &mut self,
        resource: Resource<FileBinding>,
        idempotency_key: String,
        durability: WitDurability,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        let binding = self.file_binding(&resource)?;
        Ok(file_execute(
            &mut self.coordinator,
            &binding,
            ProfileAccess::Control,
            idempotency_key,
            RegularFileOperation::Sync {
                durability: crate::state::from_wit_durability(durability),
            },
            ExpectedFileResult::Synced,
        ))
    }

    fn acquire_lock(
        &mut self,
        resource: Resource<FileBinding>,
        idempotency_key: String,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        let binding = self.file_binding(&resource)?;
        Ok(file_execute(
            &mut self.coordinator,
            &binding,
            ProfileAccess::Control,
            idempotency_key,
            RegularFileOperation::AcquireLock,
            ExpectedFileResult::Locked,
        ))
    }

    fn release_lock(
        &mut self,
        resource: Resource<FileBinding>,
        idempotency_key: String,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        let binding = self.file_binding(&resource)?;
        Ok(file_execute(
            &mut self.coordinator,
            &binding,
            ProfileAccess::Control,
            idempotency_key,
            RegularFileOperation::ReleaseLock,
            ExpectedFileResult::Unlocked,
        ))
    }

    fn drop(&mut self, resource: Resource<FileBinding>) -> wasmtime::Result<()> {
        self.table.delete(resource).map(|_| ()).map_err(wasmtime::Error::new)
    }
}

impl<P> RequestHost for CompositeStoreState<P> where P: AdapterProvider {}

impl<P> HostRequestBinding for CompositeStoreState<P>
where
    P: AdapterProvider,
{
    fn start(
        &mut self,
        resource: Resource<RequestBinding>,
        operation_id: String,
        peer_identity: String,
        credential_reference: String,
        request: Vec<u8>,
        timeout_ms: u64,
    ) -> wasmtime::Result<Result<RequestObservation, RequestError>> {
        let binding = self.request_binding(&resource)?;
        Ok(request_start(
            &mut self.coordinator,
            &binding,
            StartArguments {
                operation_id,
                peer_identity,
                credential_reference,
                request,
                timeout_ms,
            },
        ))
    }

    fn observe(
        &mut self,
        resource: Resource<RequestBinding>,
        operation_id: String,
        max_bytes: u32,
    ) -> wasmtime::Result<Result<ObserveResult, RequestError>> {
        let binding = self.request_binding(&resource)?;
        Ok(request_observe(&mut self.coordinator, &binding, operation_id, max_bytes))
    }

    fn reconcile(
        &mut self,
        resource: Resource<RequestBinding>,
        operation_id: String,
    ) -> wasmtime::Result<Result<RequestObservation, RequestError>> {
        let binding = self.request_binding(&resource)?;
        Ok(request_control(
            &mut self.coordinator,
            &binding,
            operation_id,
            LogicalRequestOperation::Reconcile,
            ControlKind::Reconcile,
        ))
    }

    fn cancel(
        &mut self,
        resource: Resource<RequestBinding>,
        operation_id: String,
    ) -> wasmtime::Result<Result<RequestObservation, RequestError>> {
        let binding = self.request_binding(&resource)?;
        Ok(request_control(
            &mut self.coordinator,
            &binding,
            operation_id,
            LogicalRequestOperation::Cancel,
            ControlKind::Cancel,
        ))
    }

    fn drop(&mut self, resource: Resource<RequestBinding>) -> wasmtime::Result<()> {
        self.table.delete(resource).map(|_| ()).map_err(wasmtime::Error::new)
    }
}

impl<P> CompositeStoreState<P> {
    fn file_binding(
        &mut self,
        resource: &Resource<FileBinding>,
    ) -> wasmtime::Result<ProfileBinding> {
        let binding = self.table.get(resource).map_err(wasmtime::Error::new)?.0.clone();
        if binding.profile() != REGULAR_FILE_EXTENSION_ID {
            return Err(wasmtime::Error::msg("file import received a non-file profile receipt"));
        }
        Ok(binding)
    }

    fn request_binding(
        &mut self,
        resource: &Resource<RequestBinding>,
    ) -> wasmtime::Result<ProfileBinding> {
        let binding = self.table.get(resource).map_err(wasmtime::Error::new)?.0.clone();
        if binding.profile() != LOGICAL_REQUEST_EXTENSION_ID {
            return Err(wasmtime::Error::msg(
                "request import received a non-request profile receipt",
            ));
        }
        Ok(binding)
    }
}

#[derive(Clone, Copy)]
enum ExpectedFileResult {
    Mutated,
    Renamed,
    Synced,
    Locked,
    Unlocked,
}

fn file_read<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    max_bytes: u32,
) -> Result<ReadResult, FileError> {
    let payload = encode_regular_file_operation(&RegularFileOperation::Read { max_bytes })
        .map_err(|_| FileError::Unsupported)?;
    let call = profile_observe(coordinator, binding, payload).map_err(FileError::from)?;
    let result = decode_regular_file_result(&call.payload).map_err(|_| FileError::Unavailable)?;
    let RegularFileResult::Read { bytes, .. } = result else {
        return Err(FileError::Unavailable);
    };
    let state = canonical_regular_file(coordinator.state()).map_err(|_| FileError::Unavailable)?;
    Ok(ReadResult { observation: file_observation(&call, &state)?, bytes })
}

fn file_execute<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    access: ProfileAccess,
    idempotency_key: String,
    operation: RegularFileOperation,
    expected: ExpectedFileResult,
) -> Result<FileObservation, FileError> {
    let payload = encode_regular_file_operation(&operation).map_err(|_| FileError::Unsupported)?;
    let call = profile_execute(coordinator, binding, access, idempotency_key.as_bytes(), payload)
        .map_err(FileError::from)?;
    let result = decode_regular_file_result(&call.payload).map_err(|_| FileError::Unavailable)?;
    let matches = matches!(
        (expected, result),
        (ExpectedFileResult::Mutated, RegularFileResult::Mutated { .. })
            | (ExpectedFileResult::Renamed, RegularFileResult::Renamed { .. })
            | (ExpectedFileResult::Synced, RegularFileResult::Synced { .. })
            | (
                ExpectedFileResult::Locked,
                RegularFileResult::Lock { state: visa_profile::FileLockState::Held }
            )
            | (
                ExpectedFileResult::Unlocked,
                RegularFileResult::Lock { state: visa_profile::FileLockState::Unlocked }
            )
    );
    if !matches {
        return Err(FileError::Unavailable);
    }
    let state = canonical_regular_file(coordinator.state()).map_err(|_| FileError::Unavailable)?;
    file_observation(&call, &state)
}

fn file_observation(
    call: &ProfileCallResult,
    state: &RegularFileState,
) -> Result<FileObservation, FileError> {
    if state.last_operation != Some(call.operation) {
        return Err(FileError::Unavailable);
    }
    Ok(FileObservation {
        operation_id: call.operation_id.clone(),
        logical_offset: state.logical_offset,
        version: state.version,
        size: state.size,
        content_digest: state.content_digest.0.to_vec(),
        durable_through: to_wit_durability(state.durable_through),
    })
}

struct StartArguments {
    operation_id: String,
    peer_identity: String,
    credential_reference: String,
    request: Vec<u8>,
    timeout_ms: u64,
}

fn request_start<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    arguments: StartArguments,
) -> Result<RequestObservation, RequestError> {
    let before = request_state_for_call(coordinator.state())?;
    validate_transport(&before)?;
    validate_operation_id(&before, &arguments.operation_id)?;
    if before.claim.peer_identity != arguments.peer_identity.as_bytes() {
        return Err(RequestError::PeerMismatch);
    }
    if identity_string(before.claim.credential_reference) != arguments.credential_reference {
        return Err(RequestError::CredentialDenied);
    }
    if before.claim.timeout_millis != arguments.timeout_ms {
        return Err(RequestError::PolicyDenied);
    }

    let payload = encode_logical_request_operation(&LogicalRequestOperation::Start {
        request: arguments.request,
    })
    .map_err(|_| RequestError::PolicyDenied)?;
    let call = profile_execute(
        coordinator,
        binding,
        ProfileAccess::Write,
        arguments.operation_id.as_bytes(),
        payload,
    )
    .map_err(|error| request_error(error, FailureContext::Start))?;
    let result =
        decode_logical_request_result(&call.payload).map_err(|_| RequestError::Unavailable)?;
    if !matches!(result, LogicalRequestResult::Started { .. }) {
        return Err(RequestError::Unavailable);
    }
    request_observation_after(coordinator.state(), &call)
}

fn request_observe<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    operation_id: String,
    max_bytes: u32,
) -> Result<ObserveResult, RequestError> {
    let before = request_state_for_call(coordinator.state())?;
    validate_transport(&before)?;
    validate_operation_id(&before, &operation_id)?;
    let payload = encode_logical_request_operation(&LogicalRequestOperation::Observe { max_bytes })
        .map_err(|_| RequestError::InvalidCursor)?;
    let call = profile_observe(coordinator, binding, payload)
        .map_err(|error| request_error(error, FailureContext::Observe))?;
    let result =
        decode_logical_request_result(&call.payload).map_err(|_| RequestError::Unavailable)?;
    let LogicalRequestResult::Observed { bytes, response_cursor, .. } = result else {
        return Err(RequestError::Unavailable);
    };
    let observation = request_observation_after(coordinator.state(), &call)?;
    let canonical = request_state_for_call(coordinator.state())?;
    if response_cursor != canonical.response_cursor {
        return Err(RequestError::InvalidCursor);
    }
    Ok(ObserveResult { observation, bytes, response_cursor })
}

#[derive(Clone, Copy)]
enum ControlKind {
    Reconcile,
    Cancel,
}

fn request_control<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    operation_id: String,
    operation: LogicalRequestOperation,
    kind: ControlKind,
) -> Result<RequestObservation, RequestError> {
    let before = request_state_for_call(coordinator.state())?;
    validate_transport(&before)?;
    validate_operation_id(&before, &operation_id)?;
    let idempotency = control_idempotency(kind, &before);
    let payload =
        encode_logical_request_operation(&operation).map_err(|_| RequestError::PolicyDenied)?;
    let call = profile_execute(coordinator, binding, ProfileAccess::Control, &idempotency, payload)
        .map_err(|error| request_error(error, FailureContext::Control))?;
    let result =
        decode_logical_request_result(&call.payload).map_err(|_| RequestError::Unavailable)?;
    let expected = matches!(
        (&kind, &result),
        (ControlKind::Reconcile, LogicalRequestResult::Reconciled { .. })
            | (ControlKind::Cancel, LogicalRequestResult::Cancelled { .. })
    );
    if !expected {
        return Err(RequestError::Unavailable);
    }
    request_observation_after(coordinator.state(), &call)
}

fn control_idempotency(kind: ControlKind, state: &LogicalRequestState) -> Vec<u8> {
    let mut value = Vec::with_capacity(64);
    value.extend_from_slice(match kind {
        ControlKind::Reconcile => b"composite-request-reconcile-v1".as_slice(),
        ControlKind::Cancel => b"composite-request-cancel-v1".as_slice(),
    });
    value.extend_from_slice(&state.operation_id.0);
    match state.last_operation {
        Some(operation) => value.extend_from_slice(&operation.0),
        None => value.extend_from_slice(&[0; 16]),
    }
    value
}

fn request_observation_after(
    state: &CanonicalState,
    call: &ProfileCallResult,
) -> Result<RequestObservation, RequestError> {
    let state = request_state_for_call(state)?;
    if state.last_operation != Some(call.operation) {
        return Err(RequestError::Unavailable);
    }
    Ok(RequestObservation {
        operation_id: identity_string(state.operation_id),
        phase: to_wit_request_phase(state.phase),
        response: state.response.map(to_wit_response),
        rejection: state.rejection.map(to_wit_rejection),
    })
}

fn validate_operation_id(state: &LogicalRequestState, supplied: &str) -> Result<(), RequestError> {
    if identity_string(state.operation_id) == supplied {
        Ok(())
    } else {
        Err(RequestError::PolicyDenied)
    }
}

fn validate_transport(state: &LogicalRequestState) -> Result<(), RequestError> {
    match state.claim.transport {
        LogicalRequestTransport::Reconnectable => Ok(()),
        LogicalRequestTransport::RawLiveTcp => {
            Err(RequestError::UnsupportedTransport(WitTransport::RawLiveTcp))
        }
    }
}

#[derive(Clone, Copy)]
enum FailureContext {
    Start,
    Observe,
    Control,
}

fn request_error(error: ProfileFailure, context: FailureContext) -> RequestError {
    match error {
        ProfileFailure::Denied if matches!(context, FailureContext::Start) => {
            RequestError::CredentialDenied
        }
        ProfileFailure::Denied => RequestError::Denied,
        ProfileFailure::Conflict if matches!(context, FailureContext::Start) => {
            RequestError::PeerMismatch
        }
        ProfileFailure::Conflict if matches!(context, FailureContext::Observe) => {
            RequestError::InvalidCursor
        }
        ProfileFailure::Conflict => RequestError::PolicyDenied,
        ProfileFailure::StaleBinding => RequestError::StaleBinding,
        ProfileFailure::Invalid => RequestError::PolicyDenied,
        ProfileFailure::Unsupported => RequestError::UnsupportedTransport(WitTransport::RawLiveTcp),
        ProfileFailure::Cancelled => RequestError::Unavailable,
        ProfileFailure::Indeterminate(operation) => RequestError::Indeterminate(operation),
        ProfileFailure::Unavailable => RequestError::Unavailable,
    }
}

fn request_state_for_call(state: &CanonicalState) -> Result<LogicalRequestState, RequestError> {
    canonical_logical_request(state).map_err(|_| RequestError::Unavailable)
}

pub(crate) fn canonical_regular_file(
    state: &CanonicalState,
) -> Result<RegularFileState, ProfileFailure> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == REGULAR_FILE_EXTENSION_ID);
    let extension = matching.next().ok_or(ProfileFailure::Invalid)?;
    if matching.next().is_some() {
        return Err(ProfileFailure::Invalid);
    }
    regular_file_state(extension).map_err(|_| ProfileFailure::Invalid)
}

pub(crate) fn canonical_logical_request(
    state: &CanonicalState,
) -> Result<LogicalRequestState, ProfileFailure> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == LOGICAL_REQUEST_EXTENSION_ID);
    let extension = matching.next().ok_or(ProfileFailure::Invalid)?;
    if matching.next().is_some() {
        return Err(ProfileFailure::Invalid);
    }
    logical_request_state(extension).map_err(|_| ProfileFailure::Invalid)
}

impl From<visa_component_adapter::KvFailure> for KvError {
    fn from(error: visa_component_adapter::KvFailure) -> Self {
        use visa_component_adapter::KvFailure;
        match error {
            KvFailure::Denied => Self::Denied,
            KvFailure::Conflict => Self::Conflict,
            KvFailure::StaleBinding => Self::StaleBinding,
            KvFailure::Indeterminate(operation) => Self::Indeterminate(operation),
            KvFailure::Unavailable => Self::Unavailable,
        }
    }
}

impl From<visa_component_adapter::TimerFailure> for TimerError {
    fn from(error: visa_component_adapter::TimerFailure) -> Self {
        use visa_component_adapter::TimerFailure;
        match error {
            TimerFailure::Denied => Self::Denied,
            TimerFailure::StaleBinding => Self::StaleBinding,
            TimerFailure::NotPending => Self::NotPending,
            TimerFailure::Unavailable => Self::Unavailable,
        }
    }
}

impl From<ProfileFailure> for FileError {
    fn from(error: ProfileFailure) -> Self {
        match error {
            ProfileFailure::Denied => Self::Denied,
            ProfileFailure::Conflict => Self::Conflict,
            ProfileFailure::StaleBinding => Self::StaleBinding,
            ProfileFailure::Invalid | ProfileFailure::Unsupported => Self::Unsupported,
            ProfileFailure::Cancelled | ProfileFailure::Unavailable => Self::Unavailable,
            ProfileFailure::Indeterminate(operation) => Self::Indeterminate(operation),
        }
    }
}
