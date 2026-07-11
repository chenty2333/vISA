//! Capability-scoped compatibility profile for cooperative Stage 1 handoff.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use contract_core::{
    CONTRACT_VERSION, DeliveryPolicy, ExtensionSupport, SchemaVersion, TimerClock,
};
use serde::{Deserialize, Serialize};

/// Current cooperative-handoff profile version.
pub const COOPERATIVE_HANDOFF_VERSION: ProfileVersion = ProfileVersion::new(1, 0);

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
