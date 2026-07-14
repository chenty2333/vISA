//! Capability-scoped compatibility profile for cooperative Stage 1 handoff.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use contract_core::{
    CONTRACT_VERSION, DeliveryPolicy, EffectKind, EffectResult, EntityRef, Extension,
    ExtensionSupport, Identity, ProfileAccess, Rights, SchemaVersion, TimerClock,
};
use serde::{Deserialize, Serialize};

mod logical_request;
mod regular_file;

pub use logical_request::{
    LOGICAL_REQUEST_EXTENSION_ID, LOGICAL_REQUEST_EXTENSION_VERSION, LogicalRequestClaim,
    LogicalRequestIdempotency, LogicalRequestObservation, LogicalRequestOperation,
    LogicalRequestPhase, LogicalRequestRejection, LogicalRequestReplay, LogicalRequestResult,
    LogicalRequestState, LogicalRequestTransport, LogicalResponseMetadata,
    MAX_LOGICAL_REQUEST_BYTES, MAX_LOGICAL_RESPONSE_BYTES, MAX_LOGICAL_RESPONSE_CHUNK_BYTES,
    decode_logical_request_operation, decode_logical_request_result,
    encode_logical_request_operation, encode_logical_request_result, logical_request_extension,
    logical_request_state,
};
pub use regular_file::{
    FileAccessMode, FileDurability, FileLockPolicy, FileLockState, MAX_REGULAR_FILE_BYTES,
    REGULAR_FILE_EXTENSION_ID, REGULAR_FILE_EXTENSION_VERSION, RegularFileClaim,
    RegularFileOperation, RegularFileResult, RegularFileState, decode_regular_file_result,
    encode_regular_file_operation, encode_regular_file_result, regular_file_extension,
    regular_file_state,
};

/// Current cooperative-handoff profile version.
pub const COOPERATIVE_HANDOFF_VERSION: ProfileVersion = ProfileVersion::new(1, 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityDisposition {
    Revalidate,
    Reconnect,
    Replay,
    Reject,
}

/// Generic header returned to the runtime after a typed profile payload has
/// been decoded and validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileResource {
    pub profile: Identity,
    pub resource: EntityRef,
    pub required_rights: Rights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfilePayloadError {
    UnknownProfile,
    MissingExtension,
    DuplicateExtension,
    VersionMismatch,
    InvalidPayload,
    ResourceMismatch,
    AccessMismatch,
    StateConflict,
    UnsupportedContinuity,
}

pub fn profile_resources(
    extensions: &[Extension],
) -> Result<Vec<ProfileResource>, ProfilePayloadError> {
    let mut resources = Vec::new();
    for extension in extensions {
        match extension.id {
            REGULAR_FILE_EXTENSION_ID => {
                let state = regular_file::decode_extension(extension)?;
                resources.push(ProfileResource {
                    profile: extension.id,
                    resource: state.claim.resource,
                    required_rights: state.claim.required_rights,
                });
            }
            LOGICAL_REQUEST_EXTENSION_ID => {
                let state = logical_request::decode_extension(extension)?;
                resources.push(ProfileResource {
                    profile: extension.id,
                    resource: state.claim.resource,
                    required_rights: state.claim.required_rights,
                });
            }
            _ => {}
        }
    }
    Ok(resources)
}

pub fn validate_profile_effect(
    extensions: &[Extension],
    profile: Identity,
    resource: EntityRef,
    access: ProfileAccess,
    payload: &[u8],
) -> Result<Rights, ProfilePayloadError> {
    let extension = unique_extension(extensions, profile)?;
    match profile {
        REGULAR_FILE_EXTENSION_ID => {
            regular_file::validate_effect(extension, resource, access, payload)
        }
        LOGICAL_REQUEST_EXTENSION_ID => {
            logical_request::validate_effect(extension, resource, access, payload)
        }
        _ => Err(ProfilePayloadError::UnknownProfile),
    }
}

pub fn profile_result_matches(kind: &EffectKind, result: &EffectResult) -> bool {
    let (
        EffectKind::Profile { profile, access, payload: operation },
        EffectResult::Profile { profile: result_profile, payload: result },
    ) = (kind, result)
    else {
        return false;
    };
    if profile != result_profile {
        return false;
    }
    match *profile {
        REGULAR_FILE_EXTENSION_ID => regular_file::result_matches(*access, operation, result),
        LOGICAL_REQUEST_EXTENSION_ID => logical_request::result_matches(*access, operation, result),
        _ => false,
    }
}

pub fn apply_profile_result(
    extensions: &mut [Extension],
    kind: &EffectKind,
    result: &EffectResult,
    operation: Identity,
) -> Result<(), ProfilePayloadError> {
    let (
        EffectKind::Profile { profile, access, payload: operation_payload },
        EffectResult::Profile { profile: result_profile, payload: result_payload },
    ) = (kind, result)
    else {
        return Err(ProfilePayloadError::InvalidPayload);
    };
    if profile != result_profile {
        return Err(ProfilePayloadError::InvalidPayload);
    }
    let extension = unique_extension_mut(extensions, *profile)?;
    match *profile {
        REGULAR_FILE_EXTENSION_ID => regular_file::apply_result(
            extension,
            *access,
            operation_payload,
            result_payload,
            operation,
        ),
        LOGICAL_REQUEST_EXTENSION_ID => logical_request::apply_result(
            extension,
            *access,
            operation_payload,
            result_payload,
            operation,
        ),
        _ => Err(ProfilePayloadError::UnknownProfile),
    }
}

/// Validate profile-owned state that must be safe before a canonical freeze.
/// This does not inspect native handles; it only enforces portable continuity
/// dispositions that the generic handoff reducer cannot interpret itself.
pub fn validate_profile_handoff(extensions: &[Extension]) -> Result<(), ProfilePayloadError> {
    for extension in extensions {
        match extension.id {
            REGULAR_FILE_EXTENSION_ID => {
                regular_file::validate_handoff(extension)?;
            }
            LOGICAL_REQUEST_EXTENSION_ID => {
                logical_request::validate_handoff(extension)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn unique_extension(
    extensions: &[Extension],
    profile: Identity,
) -> Result<&Extension, ProfilePayloadError> {
    let mut matching = extensions.iter().filter(|extension| extension.id == profile);
    let extension = matching.next().ok_or(ProfilePayloadError::MissingExtension)?;
    if matching.next().is_some() {
        return Err(ProfilePayloadError::DuplicateExtension);
    }
    Ok(extension)
}

fn unique_extension_mut(
    extensions: &mut [Extension],
    profile: Identity,
) -> Result<&mut Extension, ProfilePayloadError> {
    let mut found = None;
    for (index, extension) in extensions.iter().enumerate() {
        if extension.id == profile && found.replace(index).is_some() {
            return Err(ProfilePayloadError::DuplicateExtension);
        }
    }
    let index = found.ok_or(ProfilePayloadError::MissingExtension)?;
    Ok(&mut extensions[index])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProfileVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Profile versions are backward compatible only within the same major
    /// version, and only when the provider implements at least this minor.
    pub const fn is_satisfied_by(self, provided: Self) -> bool {
        self.major == provided.major && provided.minor >= self.minor
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimerFreezePolicy {
    PauseRemainingDuration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PausedTimerProfile {
    pub clock: TimerClock,
    pub freeze_policy: TimerFreezePolicy,
    pub cancellation_required: bool,
}

impl Default for PausedTimerProfile {
    fn default() -> Self {
        Self {
            clock: TimerClock::PausedMonotonicDuration,
            freeze_policy: TimerFreezePolicy::PauseRemainingDuration,
            cancellation_required: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalKvProfile {
    pub delivery: DeliveryPolicy,
    pub versioned_compare_and_set: bool,
    pub operation_lookup: bool,
}

impl Default for ConditionalKvProfile {
    fn default() -> Self {
        Self {
            delivery: DeliveryPolicy::Deduplicated,
            versioned_compare_and_set: true,
            operation_lookup: true,
        }
    }
}

/// The complete capability profile for Stage 1. This is intentionally one
/// concrete vertical capability, not an evidence-strength ladder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeHandoffProfile {
    pub version: ProfileVersion,
    pub contract_version: SchemaVersion,
    pub timer: PausedTimerProfile,
    pub key_value: ConditionalKvProfile,
    pub required_extensions: Vec<ExtensionSupport>,
}

impl CooperativeHandoffProfile {
    pub fn v1(required_extensions: Vec<ExtensionSupport>) -> Self {
        Self {
            version: COOPERATIVE_HANDOFF_VERSION,
            contract_version: CONTRACT_VERSION,
            timer: PausedTimerProfile::default(),
            key_value: ConditionalKvProfile::default(),
            required_extensions,
        }
    }

    pub fn validate(&self, support: &ProviderSupport) -> Result<(), CompatibilityError> {
        if self.contract_version.major != support.contract_version.major
            || support.contract_version.minor < self.contract_version.minor
        {
            return Err(CompatibilityError::ContractVersion);
        }
        if !self.version.is_satisfied_by(support.profile_version) {
            return Err(CompatibilityError::ProfileVersion);
        }
        if self.timer.clock != support.timer_clock
            || self.timer.freeze_policy != support.timer_freeze_policy
            || (self.timer.cancellation_required && !support.timer_cancellation)
        {
            return Err(CompatibilityError::TimerSemantics);
        }
        if self.key_value.delivery != support.key_value_delivery
            || (self.key_value.versioned_compare_and_set && !support.versioned_compare_and_set)
            || (self.key_value.operation_lookup && !support.operation_lookup)
        {
            return Err(CompatibilityError::KeyValueSemantics);
        }
        for required in &self.required_extensions {
            let Some(provided) =
                support.extensions.iter().find(|extension| extension.id == required.id)
            else {
                return Err(CompatibilityError::MissingRequiredExtension);
            };
            if required.version.major != provided.version.major
                || provided.version.minor < required.version.minor
            {
                return Err(CompatibilityError::ExtensionVersion);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderSupport {
    pub contract_version: SchemaVersion,
    pub profile_version: ProfileVersion,
    pub timer_clock: TimerClock,
    pub timer_freeze_policy: TimerFreezePolicy,
    pub timer_cancellation: bool,
    pub key_value_delivery: DeliveryPolicy,
    pub versioned_compare_and_set: bool,
    pub operation_lookup: bool,
    pub extensions: Vec<ExtensionSupport>,
}

impl ProviderSupport {
    pub fn cooperative_handoff_v1(extensions: Vec<ExtensionSupport>) -> Self {
        Self {
            contract_version: CONTRACT_VERSION,
            profile_version: COOPERATIVE_HANDOFF_VERSION,
            timer_clock: TimerClock::PausedMonotonicDuration,
            timer_freeze_policy: TimerFreezePolicy::PauseRemainingDuration,
            timer_cancellation: true,
            key_value_delivery: DeliveryPolicy::Deduplicated,
            versioned_compare_and_set: true,
            operation_lookup: true,
            extensions,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatibilityError {
    ContractVersion,
    ProfileVersion,
    TimerSemantics,
    KeyValueSemantics,
    MissingRequiredExtension,
    ExtensionVersion,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stage1_profile_accepts_exact_capabilities() {
        let profile = CooperativeHandoffProfile::v1(Vec::new());
        assert_eq!(profile.validate(&ProviderSupport::cooperative_handoff_v1(Vec::new())), Ok(()));
    }

    #[test]
    fn required_extensions_are_named_and_versioned() {
        let profile = CooperativeHandoffProfile::v1(alloc::vec![ExtensionSupport {
            id: contract_core::Identity::from_u128(88),
            version: SchemaVersion::new(1, 2),
        }]);

        assert_eq!(
            profile.validate(&ProviderSupport::cooperative_handoff_v1(Vec::new())),
            Err(CompatibilityError::MissingRequiredExtension)
        );
        assert_eq!(
            profile.validate(&ProviderSupport::cooperative_handoff_v1(alloc::vec![
                ExtensionSupport {
                    id: contract_core::Identity::from_u128(88),
                    version: SchemaVersion::new(1, 1),
                }
            ])),
            Err(CompatibilityError::ExtensionVersion)
        );
        assert_eq!(
            profile.validate(&ProviderSupport::cooperative_handoff_v1(alloc::vec![
                ExtensionSupport {
                    id: contract_core::Identity::from_u128(88),
                    version: SchemaVersion::new(1, 3),
                }
            ])),
            Ok(())
        );
    }

    #[test]
    fn timer_or_kv_downgrade_is_rejected() {
        let profile = CooperativeHandoffProfile::v1(Vec::new());
        let mut support = ProviderSupport::cooperative_handoff_v1(Vec::new());
        support.operation_lookup = false;
        assert_eq!(profile.validate(&support), Err(CompatibilityError::KeyValueSemantics));
    }
}
