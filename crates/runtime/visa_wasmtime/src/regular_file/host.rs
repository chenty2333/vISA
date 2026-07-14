use contract_core::{CanonicalState, ProfileAccess};
use visa_component_adapter::{
    AdapterProvider, BindingError, ProfileBinding, ProfileCallResult, ProfileFailure,
    profile_execute, profile_observe,
};
use visa_profile::{
    REGULAR_FILE_EXTENSION_ID, RegularFileOperation, RegularFileResult, RegularFileState,
    decode_regular_file_result, encode_regular_file_operation, regular_file_state,
};
use visa_runtime::Coordinator;
use wasmtime::component::{Resource, ResourceTable};

use super::{
    bindings::visa::file_continuity::regular_file::{
        FileError, FileObservation, Host, HostFileBinding, ReadResult,
    },
    state::to_wit_durability,
};

/// Wasmtime-local state for the Stage 3A world. The table owns only opaque
/// profile receipts; the coordinator remains the sole canonical state owner.
pub struct RegularFileStoreState<P> {
    coordinator: Coordinator<P>,
    table: ResourceTable,
}

impl<P> RegularFileStoreState<P> {
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

    pub(crate) fn fresh_file_resource(&mut self) -> Result<Resource<ProfileBinding>, BindingError> {
        if !self.table.is_empty() {
            return Err(BindingError::LiveResources);
        }
        let binding =
            ProfileBinding::for_state(self.coordinator.state(), REGULAR_FILE_EXTENSION_ID)?;
        self.table.push(binding).map_err(|_| BindingError::ResourceTable)
    }
}

impl<P> Host for RegularFileStoreState<P> where P: AdapterProvider {}

impl<P> HostFileBinding for RegularFileStoreState<P>
where
    P: AdapterProvider,
{
    fn read(
        &mut self,
        resource: Resource<ProfileBinding>,
        max_bytes: u32,
    ) -> wasmtime::Result<Result<ReadResult, FileError>> {
        let binding = self.table.get(&resource).map_err(wasmtime::Error::new)?.clone();
        Ok(read(&mut self.coordinator, &binding, max_bytes))
    }

    fn write(
        &mut self,
        resource: Resource<ProfileBinding>,
        idempotency_key: String,
        bytes: Vec<u8>,
        durability: super::bindings::visa::file_continuity::regular_file::Durability,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        Ok(execute(
            &mut self.coordinator,
            self.table.get(&resource).map_err(wasmtime::Error::new)?.clone(),
            ProfileAccess::Write,
            idempotency_key,
            RegularFileOperation::Write {
                bytes,
                durability: super::state::from_wit_durability(durability),
            },
            ExpectedResult::Mutated,
        ))
    }

    fn append(
        &mut self,
        resource: Resource<ProfileBinding>,
        idempotency_key: String,
        bytes: Vec<u8>,
        durability: super::bindings::visa::file_continuity::regular_file::Durability,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        Ok(execute(
            &mut self.coordinator,
            self.table.get(&resource).map_err(wasmtime::Error::new)?.clone(),
            ProfileAccess::Write,
            idempotency_key,
            RegularFileOperation::Append {
                bytes,
                durability: super::state::from_wit_durability(durability),
            },
            ExpectedResult::Mutated,
        ))
    }

    fn truncate(
        &mut self,
        resource: Resource<ProfileBinding>,
        idempotency_key: String,
        size: u64,
        durability: super::bindings::visa::file_continuity::regular_file::Durability,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        Ok(execute(
            &mut self.coordinator,
            self.table.get(&resource).map_err(wasmtime::Error::new)?.clone(),
            ProfileAccess::Write,
            idempotency_key,
            RegularFileOperation::Truncate {
                size,
                durability: super::state::from_wit_durability(durability),
            },
            ExpectedResult::Mutated,
        ))
    }

    fn rename(
        &mut self,
        resource: Resource<ProfileBinding>,
        idempotency_key: String,
        relative_path: String,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        Ok(execute(
            &mut self.coordinator,
            self.table.get(&resource).map_err(wasmtime::Error::new)?.clone(),
            ProfileAccess::Write,
            idempotency_key,
            RegularFileOperation::Rename { relative_path: relative_path.into_bytes() },
            ExpectedResult::Renamed,
        ))
    }

    fn sync(
        &mut self,
        resource: Resource<ProfileBinding>,
        idempotency_key: String,
        durability: super::bindings::visa::file_continuity::regular_file::Durability,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        Ok(execute(
            &mut self.coordinator,
            self.table.get(&resource).map_err(wasmtime::Error::new)?.clone(),
            ProfileAccess::Control,
            idempotency_key,
            RegularFileOperation::Sync {
                durability: super::state::from_wit_durability(durability),
            },
            ExpectedResult::Synced,
        ))
    }

    fn acquire_lock(
        &mut self,
        resource: Resource<ProfileBinding>,
        idempotency_key: String,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        Ok(execute(
            &mut self.coordinator,
            self.table.get(&resource).map_err(wasmtime::Error::new)?.clone(),
            ProfileAccess::Control,
            idempotency_key,
            RegularFileOperation::AcquireLock,
            ExpectedResult::Locked,
        ))
    }

    fn release_lock(
        &mut self,
        resource: Resource<ProfileBinding>,
        idempotency_key: String,
    ) -> wasmtime::Result<Result<FileObservation, FileError>> {
        Ok(execute(
            &mut self.coordinator,
            self.table.get(&resource).map_err(wasmtime::Error::new)?.clone(),
            ProfileAccess::Control,
            idempotency_key,
            RegularFileOperation::ReleaseLock,
            ExpectedResult::Unlocked,
        ))
    }

    fn drop(&mut self, resource: Resource<ProfileBinding>) -> wasmtime::Result<()> {
        self.table.delete(resource).map(|_| ()).map_err(wasmtime::Error::new)
    }
}

fn read<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: &ProfileBinding,
    max_bytes: u32,
) -> Result<ReadResult, FileError> {
    let operation = RegularFileOperation::Read { max_bytes };
    let payload = encode_regular_file_operation(&operation).map_err(|_| FileError::Unsupported)?;
    let call = profile_observe(coordinator, binding, payload).map_err(FileError::from)?;
    let result = decode_regular_file_result(&call.payload).map_err(|_| FileError::Unavailable)?;
    let RegularFileResult::Read { bytes, .. } = result else {
        return Err(FileError::Unavailable);
    };
    let state = canonical_regular_file(coordinator.state()).map_err(|_| FileError::Unavailable)?;
    let observation = observation(&call, &state)?;
    Ok(ReadResult { observation, bytes })
}

#[derive(Clone, Copy)]
enum ExpectedResult {
    Mutated,
    Renamed,
    Synced,
    Locked,
    Unlocked,
}

fn execute<P: AdapterProvider>(
    coordinator: &mut Coordinator<P>,
    binding: ProfileBinding,
    access: ProfileAccess,
    idempotency_key: String,
    operation: RegularFileOperation,
    expected: ExpectedResult,
) -> Result<FileObservation, FileError> {
    let payload = encode_regular_file_operation(&operation).map_err(|_| FileError::Unsupported)?;
    let call = profile_execute(coordinator, &binding, access, idempotency_key.as_bytes(), payload)
        .map_err(FileError::from)?;
    let result = decode_regular_file_result(&call.payload).map_err(|_| FileError::Unavailable)?;
    let matches = matches!(
        (expected, result),
        (ExpectedResult::Mutated, RegularFileResult::Mutated { .. })
            | (ExpectedResult::Renamed, RegularFileResult::Renamed { .. })
            | (ExpectedResult::Synced, RegularFileResult::Synced { .. })
            | (
                ExpectedResult::Locked,
                RegularFileResult::Lock { state: visa_profile::FileLockState::Held }
            )
            | (
                ExpectedResult::Unlocked,
                RegularFileResult::Lock { state: visa_profile::FileLockState::Unlocked }
            )
    );
    if !matches {
        return Err(FileError::Unavailable);
    }
    let state = canonical_regular_file(coordinator.state()).map_err(|_| FileError::Unavailable)?;
    observation(&call, &state)
}

fn observation(
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
