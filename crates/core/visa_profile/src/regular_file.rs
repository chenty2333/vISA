use alloc::vec::Vec;

use contract_core::{
    Digest, EntityRef, Extension, Identity, ProfileAccess, Rights, SchemaVersion, canonical_bytes,
    canonical_from_bytes,
};
use serde::{Deserialize, Serialize};

use crate::{ContinuityDisposition, ProfilePayloadError};

pub const REGULAR_FILE_EXTENSION_ID: Identity = Identity::from_bytes(*b"visa:file:v1\0\0\0\0");
pub const REGULAR_FILE_EXTENSION_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_OPERATION_BYTES: usize = 64 * 1024;
pub const MAX_REGULAR_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAccessMode {
    ReadOnly,
    ReadWrite,
    AppendOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDurability {
    Visible,
    Data,
    DataAndMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileLockPolicy {
    None,
    ExclusiveLease,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileLockState {
    Unlocked,
    Held,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegularFileClaim {
    pub resource: EntityRef,
    pub namespace: Identity,
    pub relative_path: Vec<u8>,
    pub required_rights: Rights,
    pub access_mode: FileAccessMode,
    pub durability: FileDurability,
    pub lock_policy: FileLockPolicy,
    pub max_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegularFileState {
    pub claim: RegularFileClaim,
    pub logical_offset: u64,
    pub version: u64,
    pub size: u64,
    pub content_digest: Digest,
    pub durable_through: FileDurability,
    pub lock_state: FileLockState,
    pub disposition: ContinuityDisposition,
    pub last_operation: Option<Identity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegularFileOperation {
    Read { max_bytes: u32 },
    Write { bytes: Vec<u8>, durability: FileDurability },
    Append { bytes: Vec<u8>, durability: FileDurability },
    Truncate { size: u64, durability: FileDurability },
    Rename { relative_path: Vec<u8> },
    Sync { durability: FileDurability },
    AcquireLock,
    ReleaseLock,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegularFileResult {
    Read {
        bytes: Vec<u8>,
        logical_offset: u64,
        version: u64,
        size: u64,
        content_digest: Digest,
    },
    Mutated {
        logical_offset: u64,
        version: u64,
        size: u64,
        content_digest: Digest,
        durable_through: FileDurability,
    },
    Renamed {
        relative_path: Vec<u8>,
        version: u64,
        content_digest: Digest,
    },
    Synced {
        version: u64,
        durable_through: FileDurability,
    },
    Lock {
        state: FileLockState,
    },
}

pub fn regular_file_extension(state: &RegularFileState) -> Result<Extension, ProfilePayloadError> {
    validate_state(state)?;
    Ok(Extension {
        id: REGULAR_FILE_EXTENSION_ID,
        version: REGULAR_FILE_EXTENSION_VERSION,
        required: true,
        payload: canonical_bytes(state).map_err(|_| ProfilePayloadError::InvalidPayload)?,
    })
}

pub fn regular_file_state(extension: &Extension) -> Result<RegularFileState, ProfilePayloadError> {
    decode_extension(extension)
}

pub(crate) fn decode_extension(
    extension: &Extension,
) -> Result<RegularFileState, ProfilePayloadError> {
    if extension.id != REGULAR_FILE_EXTENSION_ID {
        return Err(ProfilePayloadError::UnknownProfile);
    }
    if extension.version != REGULAR_FILE_EXTENSION_VERSION {
        return Err(ProfilePayloadError::VersionMismatch);
    }
    let state = canonical_from_bytes::<RegularFileState>(&extension.payload)
        .map_err(|_| ProfilePayloadError::InvalidPayload)?;
    validate_state(&state)?;
    Ok(state)
}

pub(crate) fn validate_effect(
    extension: &Extension,
    resource: EntityRef,
    access: ProfileAccess,
    payload: &[u8],
) -> Result<Rights, ProfilePayloadError> {
    let state = decode_extension(extension)?;
    if state.claim.resource != resource {
        return Err(ProfilePayloadError::ResourceMismatch);
    }
    let operation = decode_operation(payload)?;
    let expected_access = operation_access(&operation);
    if access != expected_access {
        return Err(ProfilePayloadError::AccessMismatch);
    }
    let required = access.required_rights();
    if !state.claim.required_rights.contains(required) {
        return Err(ProfilePayloadError::AccessMismatch);
    }
    validate_operation(&state, &operation)?;
    Ok(required)
}

pub(crate) fn validate_handoff(extension: &Extension) -> Result<(), ProfilePayloadError> {
    let state = decode_extension(extension)?;
    if state.lock_state == FileLockState::Held || state.disposition == ContinuityDisposition::Reject
    {
        return Err(ProfilePayloadError::StateConflict);
    }
    Ok(())
}

pub(crate) fn result_matches(
    access: ProfileAccess,
    operation_payload: &[u8],
    result_payload: &[u8],
) -> bool {
    let Ok(operation) = decode_operation(operation_payload) else {
        return false;
    };
    if operation_access(&operation) != access {
        return false;
    }
    let Ok(result) = decode_result(result_payload) else {
        return false;
    };
    matches!(
        (&operation, &result),
        (RegularFileOperation::Read { .. }, RegularFileResult::Read { .. })
            | (
                RegularFileOperation::Write { .. }
                    | RegularFileOperation::Append { .. }
                    | RegularFileOperation::Truncate { .. },
                RegularFileResult::Mutated { .. }
            )
            | (RegularFileOperation::Rename { .. }, RegularFileResult::Renamed { .. })
            | (RegularFileOperation::Sync { .. }, RegularFileResult::Synced { .. })
            | (
                RegularFileOperation::AcquireLock | RegularFileOperation::ReleaseLock,
                RegularFileResult::Lock { .. }
            )
    )
}

pub(crate) fn apply_result(
    extension: &mut Extension,
    access: ProfileAccess,
    operation_payload: &[u8],
    result_payload: &[u8],
    operation_id: Identity,
) -> Result<(), ProfilePayloadError> {
    let mut state = decode_extension(extension)?;
    let operation = decode_operation(operation_payload)?;
    let result = decode_result(result_payload)?;
    if operation_access(&operation) != access
        || !result_matches(access, operation_payload, result_payload)
    {
        return Err(ProfilePayloadError::AccessMismatch);
    }
    validate_operation(&state, &operation)?;

    match (operation, result) {
        (
            RegularFileOperation::Read { max_bytes },
            RegularFileResult::Read { bytes, logical_offset, version, size, content_digest },
        ) => {
            let consumed =
                u64::try_from(bytes.len()).map_err(|_| ProfilePayloadError::StateConflict)?;
            if bytes.len() > max_bytes as usize
                || logical_offset != state.logical_offset.saturating_add(consumed)
                || version != state.version
                || size != state.size
                || content_digest != state.content_digest
            {
                return Err(ProfilePayloadError::StateConflict);
            }
            state.logical_offset = logical_offset;
        }
        (
            RegularFileOperation::Write { bytes, durability },
            RegularFileResult::Mutated {
                logical_offset,
                version,
                size,
                content_digest,
                durable_through,
            },
        ) => {
            let written =
                u64::try_from(bytes.len()).map_err(|_| ProfilePayloadError::StateConflict)?;
            let expected_offset = state.logical_offset.saturating_add(written);
            apply_mutation(
                &mut state,
                logical_offset,
                version,
                size,
                content_digest,
                durable_through,
                durability,
                Some(expected_offset),
            )?;
        }
        (
            RegularFileOperation::Append { bytes, durability },
            RegularFileResult::Mutated {
                logical_offset,
                version,
                size,
                content_digest,
                durable_through,
            },
        ) => {
            let written =
                u64::try_from(bytes.len()).map_err(|_| ProfilePayloadError::StateConflict)?;
            let expected_offset = state.size.saturating_add(written);
            apply_mutation(
                &mut state,
                logical_offset,
                version,
                size,
                content_digest,
                durable_through,
                durability,
                Some(expected_offset),
            )?;
        }
        (
            RegularFileOperation::Truncate { size: requested, durability },
            RegularFileResult::Mutated {
                logical_offset,
                version,
                size,
                content_digest,
                durable_through,
            },
        ) => {
            if size != requested || logical_offset > size {
                return Err(ProfilePayloadError::StateConflict);
            }
            apply_mutation(
                &mut state,
                logical_offset,
                version,
                size,
                content_digest,
                durable_through,
                durability,
                None,
            )?;
        }
        (
            RegularFileOperation::Rename { relative_path },
            RegularFileResult::Renamed { relative_path: observed, version, content_digest },
        ) => {
            if relative_path != observed
                || version != state.version.saturating_add(1)
                || content_digest != state.content_digest
            {
                return Err(ProfilePayloadError::StateConflict);
            }
            state.claim.relative_path = observed;
            state.version = version;
        }
        (
            RegularFileOperation::Sync { durability },
            RegularFileResult::Synced { version, durable_through },
        ) => {
            if version != state.version || durable_through < durability {
                return Err(ProfilePayloadError::StateConflict);
            }
            state.durable_through = durable_through;
        }
        (RegularFileOperation::AcquireLock, RegularFileResult::Lock { state: lock }) => {
            if lock != FileLockState::Held {
                return Err(ProfilePayloadError::StateConflict);
            }
            state.lock_state = lock;
        }
        (RegularFileOperation::ReleaseLock, RegularFileResult::Lock { state: lock }) => {
            if lock != FileLockState::Unlocked {
                return Err(ProfilePayloadError::StateConflict);
            }
            state.lock_state = lock;
        }
        _ => return Err(ProfilePayloadError::InvalidPayload),
    }
    state.last_operation = Some(operation_id);
    extension.payload = canonical_bytes(&state).map_err(|_| ProfilePayloadError::InvalidPayload)?;
    Ok(())
}

pub fn encode_regular_file_operation(
    operation: &RegularFileOperation,
) -> Result<Vec<u8>, ProfilePayloadError> {
    canonical_bytes(operation).map_err(|_| ProfilePayloadError::InvalidPayload)
}

pub fn decode_regular_file_result(
    payload: &[u8],
) -> Result<RegularFileResult, ProfilePayloadError> {
    decode_result(payload)
}

pub fn encode_regular_file_result(
    result: &RegularFileResult,
) -> Result<Vec<u8>, ProfilePayloadError> {
    canonical_bytes(result).map_err(|_| ProfilePayloadError::InvalidPayload)
}

fn decode_operation(payload: &[u8]) -> Result<RegularFileOperation, ProfilePayloadError> {
    if payload.len() > MAX_OPERATION_BYTES.saturating_add(MAX_PATH_BYTES) {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    canonical_from_bytes(payload).map_err(|_| ProfilePayloadError::InvalidPayload)
}

fn decode_result(payload: &[u8]) -> Result<RegularFileResult, ProfilePayloadError> {
    if payload.len() > MAX_OPERATION_BYTES.saturating_add(256) {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    canonical_from_bytes(payload).map_err(|_| ProfilePayloadError::InvalidPayload)
}

fn validate_state(state: &RegularFileState) -> Result<(), ProfilePayloadError> {
    if state.claim.resource.identity.is_zero()
        || state.claim.namespace.is_zero()
        || state.claim.max_size == 0
        || state.claim.max_size > MAX_REGULAR_FILE_BYTES
        || state.size > state.claim.max_size
        || state.logical_offset > state.size
        || !valid_relative_path(&state.claim.relative_path)
        || !state.claim.required_rights.contains(Rights::REBIND)
    {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    Ok(())
}

fn validate_operation(
    state: &RegularFileState,
    operation: &RegularFileOperation,
) -> Result<(), ProfilePayloadError> {
    match operation {
        RegularFileOperation::Read { max_bytes } => {
            if *max_bytes == 0
                || *max_bytes as usize > MAX_OPERATION_BYTES
                || !matches!(
                    state.claim.access_mode,
                    FileAccessMode::ReadOnly | FileAccessMode::ReadWrite
                )
            {
                return Err(ProfilePayloadError::AccessMismatch);
            }
        }
        RegularFileOperation::Write { bytes, durability } => {
            if bytes.is_empty()
                || bytes.len() > MAX_OPERATION_BYTES
                || state.logical_offset.saturating_add(bytes.len() as u64) > state.claim.max_size
                || state.claim.access_mode != FileAccessMode::ReadWrite
                || *durability < state.claim.durability
            {
                return Err(ProfilePayloadError::AccessMismatch);
            }
        }
        RegularFileOperation::Append { bytes, durability } => {
            if bytes.is_empty()
                || bytes.len() > MAX_OPERATION_BYTES
                || state.size.saturating_add(bytes.len() as u64) > state.claim.max_size
                || !matches!(
                    state.claim.access_mode,
                    FileAccessMode::ReadWrite | FileAccessMode::AppendOnly
                )
                || *durability < state.claim.durability
            {
                return Err(ProfilePayloadError::AccessMismatch);
            }
        }
        RegularFileOperation::Truncate { size, durability } => {
            if *size > state.claim.max_size
                || state.claim.access_mode != FileAccessMode::ReadWrite
                || *durability < state.claim.durability
            {
                return Err(ProfilePayloadError::AccessMismatch);
            }
        }
        RegularFileOperation::Rename { relative_path } => {
            if state.claim.access_mode == FileAccessMode::ReadOnly
                || !valid_relative_path(relative_path)
                || *relative_path == state.claim.relative_path
            {
                return Err(ProfilePayloadError::AccessMismatch);
            }
        }
        RegularFileOperation::Sync { durability } => {
            if *durability < state.claim.durability {
                return Err(ProfilePayloadError::AccessMismatch);
            }
        }
        RegularFileOperation::AcquireLock => {
            if state.claim.lock_policy != FileLockPolicy::ExclusiveLease
                || state.lock_state != FileLockState::Unlocked
            {
                return Err(ProfilePayloadError::StateConflict);
            }
        }
        RegularFileOperation::ReleaseLock => {
            if state.claim.lock_policy != FileLockPolicy::ExclusiveLease
                || state.lock_state != FileLockState::Held
            {
                return Err(ProfilePayloadError::StateConflict);
            }
        }
    }
    Ok(())
}

fn operation_access(operation: &RegularFileOperation) -> ProfileAccess {
    match operation {
        RegularFileOperation::Read { .. } => ProfileAccess::Read,
        RegularFileOperation::Write { .. }
        | RegularFileOperation::Append { .. }
        | RegularFileOperation::Truncate { .. }
        | RegularFileOperation::Rename { .. } => ProfileAccess::Write,
        RegularFileOperation::Sync { .. }
        | RegularFileOperation::AcquireLock
        | RegularFileOperation::ReleaseLock => ProfileAccess::Control,
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_mutation(
    state: &mut RegularFileState,
    logical_offset: u64,
    version: u64,
    size: u64,
    content_digest: Digest,
    durable_through: FileDurability,
    requested_durability: FileDurability,
    expected_offset: Option<u64>,
) -> Result<(), ProfilePayloadError> {
    if version != state.version.saturating_add(1)
        || size > state.claim.max_size
        || logical_offset > size
        || expected_offset.is_some_and(|expected| logical_offset != expected)
        || durable_through < requested_durability
    {
        return Err(ProfilePayloadError::StateConflict);
    }
    state.logical_offset = logical_offset;
    state.version = version;
    state.size = size;
    state.content_digest = content_digest;
    state.durable_through = durable_through;
    Ok(())
}

fn valid_relative_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && path[0] != b'/'
        && !path.contains(&0)
        && path
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

#[cfg(test)]
mod tests {
    use contract_core::{Generation, canonical_digest};

    use super::*;

    fn state() -> RegularFileState {
        RegularFileState {
            claim: RegularFileClaim {
                resource: EntityRef::new(Identity::from_u128(1), Generation::INITIAL),
                namespace: Identity::from_u128(2),
                relative_path: b"work/state.bin".to_vec(),
                required_rights: Rights::PROFILE_READ
                    .union(Rights::PROFILE_WRITE)
                    .union(Rights::PROFILE_CONTROL)
                    .union(Rights::REBIND),
                access_mode: FileAccessMode::ReadWrite,
                durability: FileDurability::Data,
                lock_policy: FileLockPolicy::ExclusiveLease,
                max_size: MAX_REGULAR_FILE_BYTES,
            },
            logical_offset: 0,
            version: 1,
            size: 3,
            content_digest: canonical_digest(b"abc").unwrap(),
            durable_through: FileDurability::Data,
            lock_state: FileLockState::Unlocked,
            disposition: ContinuityDisposition::Revalidate,
            last_operation: None,
        }
    }

    #[test]
    fn extension_round_trips_and_rejects_path_escape() {
        let accepted = state();
        let extension = regular_file_extension(&accepted).unwrap();
        assert_eq!(decode_extension(&extension).unwrap(), accepted);

        let mut escaped = state();
        escaped.claim.relative_path = b"../state.bin".to_vec();
        assert_eq!(regular_file_extension(&escaped), Err(ProfilePayloadError::InvalidPayload));
    }

    #[test]
    fn read_result_advances_only_the_logical_offset() {
        let mut extension = regular_file_extension(&state()).unwrap();
        let operation = RegularFileOperation::Read { max_bytes: 2 };
        let operation_payload = encode_regular_file_operation(&operation).unwrap();
        let result = RegularFileResult::Read {
            bytes: b"ab".to_vec(),
            logical_offset: 2,
            version: 1,
            size: 3,
            content_digest: state().content_digest,
        };
        let result_payload = encode_regular_file_result(&result).unwrap();

        apply_result(
            &mut extension,
            ProfileAccess::Read,
            &operation_payload,
            &result_payload,
            Identity::from_u128(9),
        )
        .unwrap();
        let next = decode_extension(&extension).unwrap();
        assert_eq!(next.logical_offset, 2);
        assert_eq!(next.version, 1);
        assert_eq!(next.last_operation, Some(Identity::from_u128(9)));
    }

    #[test]
    fn operation_access_cannot_be_downgraded() {
        let extension = regular_file_extension(&state()).unwrap();
        let payload = encode_regular_file_operation(&RegularFileOperation::Write {
            bytes: b"x".to_vec(),
            durability: FileDurability::Data,
        })
        .unwrap();
        assert_eq!(
            validate_effect(&extension, state().claim.resource, ProfileAccess::Read, &payload,),
            Err(ProfilePayloadError::AccessMismatch)
        );
    }

    #[test]
    fn live_lock_cannot_cross_the_canonical_freeze_boundary() {
        let mut locked = state();
        locked.lock_state = FileLockState::Held;
        let extension = regular_file_extension(&locked).unwrap();
        assert_eq!(validate_handoff(&extension), Err(ProfilePayloadError::StateConflict));

        let unlocked = regular_file_extension(&state()).unwrap();
        assert_eq!(validate_handoff(&unlocked), Ok(()));
    }
}
