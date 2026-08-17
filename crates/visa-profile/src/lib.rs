//! Small, portable continuity-profile SDK.
//!
//! The profile crate deliberately contains no authority or runtime adapter.  A
//! profile can validate portable bytes and describe the logical resource that a
//! destination must obtain; it cannot create a binding or ask an authority for
//! one.  Binding grants and effect receipts are therefore only checked and
//! projected here.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use serde::{Serialize, de::DeserializeOwned};
use visa_core::{
    BindingGrant, Digest, EffectClosureReceipt, ProfileId, ProfileRef, ProfileVersion,
    RebindDisposition, RequirementId, ResourceRequirement, Rights, SchemaId, SchemaRef,
};

/// Upper bound used by the default state codec.
pub const DEFAULT_MAX_STATE_BYTES: usize = 4 * 1024;
/// Maximum portable session-key length for [`CounterSessionState`].
pub const MAX_SESSION_KEY_BYTES: usize = 256;

/// Errors returned by a portable state codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// The encoded state exceeded the codec's configured bound.
    Oversize { len: usize, max: usize },
    /// The input itself exceeded the codec's configured bound.
    InputOversize { len: usize, max: usize },
    /// The serializer could not represent the value.
    Serialize,
    /// The bytes were not a valid value of the requested type.
    Deserialize,
    /// A valid value was followed by bytes that were not consumed by it.
    TrailingBytes,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversize { len, max } => {
                write!(f, "encoded state is {len} bytes, maximum is {max}")
            }
            Self::InputOversize { len, max } => {
                write!(f, "state input is {len} bytes, maximum is {max}")
            }
            Self::Serialize => f.write_str("state serialization failed"),
            Self::Deserialize => f.write_str("state deserialization failed"),
            Self::TrailingBytes => f.write_str("state has trailing bytes"),
        }
    }
}

/// A codec for a typed portable state value.
pub trait PortableStateCodec<T> {
    /// Encode a value, enforcing the codec's output bound.
    fn encode(&self, value: &T) -> Result<Vec<u8>, CodecError>;
    /// Decode one complete value, enforcing the codec's input bound.
    fn decode(&self, bytes: &[u8]) -> Result<T, CodecError>;
}

/// Bounded postcard codec with strict whole-input decoding.
///
/// `postcard::take_from_bytes` is used instead of accepting a decoder prefix;
/// any remaining byte is rejected.  Bounds are checked before decoding and
/// after encoding so a hostile length prefix cannot allocate unbounded state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostcardCodec<T> {
    max_bytes: usize,
    marker: PhantomData<fn() -> T>,
}

impl<T> PostcardCodec<T> {
    /// Construct a codec with an explicit encoded-state bound.
    pub const fn new(max_bytes: usize) -> Self {
        Self { max_bytes, marker: PhantomData }
    }

    /// Return the configured encoded-state bound.
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }
}

impl<T> Default for PostcardCodec<T> {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_STATE_BYTES)
    }
}

impl<T> PortableStateCodec<T> for PostcardCodec<T>
where
    T: Serialize + DeserializeOwned,
{
    fn encode(&self, value: &T) -> Result<Vec<u8>, CodecError> {
        let bytes = postcard::to_allocvec(value).map_err(|_| CodecError::Serialize)?;
        if bytes.len() > self.max_bytes {
            return Err(CodecError::Oversize { len: bytes.len(), max: self.max_bytes });
        }
        Ok(bytes)
    }

    fn decode(&self, bytes: &[u8]) -> Result<T, CodecError> {
        if bytes.len() > self.max_bytes {
            return Err(CodecError::InputOversize { len: bytes.len(), max: self.max_bytes });
        }
        let (value, rest) =
            postcard::take_from_bytes(bytes).map_err(|_| CodecError::Deserialize)?;
        if !rest.is_empty() {
            return Err(CodecError::TrailingBytes);
        }
        Ok(value)
    }
}

impl<T> PostcardCodec<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Inherent convenience wrapper for [`PortableStateCodec::encode`].
    pub fn encode(&self, value: &T) -> Result<Vec<u8>, CodecError> {
        <Self as PortableStateCodec<T>>::encode(self, value)
    }

    /// Inherent convenience wrapper for [`PortableStateCodec::decode`].
    pub fn decode(&self, bytes: &[u8]) -> Result<T, CodecError> {
        <Self as PortableStateCodec<T>>::decode(self, bytes)
    }
}

/// The first typed portable state used by the reference profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct CounterSessionState {
    pub counter: u64,
    pub session_key: Vec<u8>,
    pub last_seen_version: Option<u64>,
}

/// Application-visible result of projecting external effect receipts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationRecoveryDecision {
    Continue,
    RecoveryRequired,
}

/// Short alias used by coordinators and callers.
pub type RecoveryDecision = ApplicationRecoveryDecision;

/// Errors returned by profile validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    EmptySessionKey,
    SessionKeyTooLong,
    WrongProfile,
    WrongVersion,
    WrongSchema,
    WrongRequirement,
    WrongResourceKind,
    WrongDisposition,
    WrongLogicalName,
    RightsMismatch,
}

/// The profile SDK contract implemented by a typed profile.
pub trait ContinuityProfile {
    type State;

    fn profile_ref(&self) -> ProfileRef;
    fn validate_state(&self, state: &Self::State) -> Result<(), ProfileError>;
    fn resource_requirements(
        &self,
        state: &Self::State,
    ) -> Result<Vec<ResourceRequirement>, ProfileError>;
    fn validate_binding_grant(
        &self,
        requirement: &ResourceRequirement,
        grant: &BindingGrant,
    ) -> Result<(), ProfileError>;
    fn validate_binding(
        &self,
        state: &Self::State,
        requirement: &ResourceRequirement,
        grant: &BindingGrant,
    ) -> Result<(), ProfileError>;
    fn project_effects(&self, receipts: &[EffectClosureReceipt]) -> ApplicationRecoveryDecision;
}

/// Opaque, stable identifiers for the first profile contract.
///
/// The byte identifiers are intentionally allocated by vISA rather than
/// derived from a host pointer, string interning table, or provider state.
pub const DURABLE_KV_PROFILE_ID: ProfileId = ProfileId::from_u128(1);
pub const DURABLE_KV_PROFILE_VERSION: ProfileVersion = ProfileVersion { major: 1, minor: 0 };
pub const DURABLE_KV_SCHEMA_ID: SchemaId = SchemaId::from_u128(1);
pub const DURABLE_KV_STATE_SCHEMA: SchemaRef = SchemaRef { id: DURABLE_KV_SCHEMA_ID, version: 1 };
pub const DURABLE_KV_REQUIREMENT_ID: RequirementId = RequirementId::from_u128(1);
pub const DURABLE_KV_RESOURCE_KIND: &[u8] = b"durable-kv";

/// Rights allocated by this profile in the core right-set namespace.
pub const DURABLE_KV_READ: Rights = Rights(1 << 0);
pub const DURABLE_KV_COMPARE_AND_SET: Rights = Rights(1 << 1);
pub const DURABLE_KV_REQUIRED_RIGHTS: Rights =
    Rights(DURABLE_KV_READ.0 | DURABLE_KV_COMPARE_AND_SET.0);

/// The durable key/value profile used by the first continuation path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DurableKvProfile;

impl DurableKvProfile {
    /// Return the exact profile reference carried by a portable snapshot.
    pub fn profile_ref(self) -> ProfileRef {
        ProfileRef {
            id: DURABLE_KV_PROFILE_ID,
            version: DURABLE_KV_PROFILE_VERSION,
            contract_digest: Digest::of_bytes(b"visa-profile/durable-kv/1.0/counter-session-v1"),
            state_schema: DURABLE_KV_STATE_SCHEMA,
        }
    }

    pub const fn profile_id(self) -> ProfileId {
        DURABLE_KV_PROFILE_ID
    }

    pub const fn version(self) -> ProfileVersion {
        DURABLE_KV_PROFILE_VERSION
    }

    pub const fn schema(self) -> SchemaRef {
        DURABLE_KV_STATE_SCHEMA
    }

    pub fn state_codec(self) -> PostcardCodec<CounterSessionState> {
        PostcardCodec::default()
    }

    pub fn validate_state(&self, state: &CounterSessionState) -> Result<(), ProfileError> {
        if state.session_key.is_empty() {
            return Err(ProfileError::EmptySessionKey);
        }
        if state.session_key.len() > MAX_SESSION_KEY_BYTES {
            return Err(ProfileError::SessionKeyTooLong);
        }
        Ok(())
    }

    pub fn resource_requirements(
        &self,
        state: &CounterSessionState,
    ) -> Result<Vec<ResourceRequirement>, ProfileError> {
        self.validate_state(state)?;
        Ok(alloc::vec![ResourceRequirement {
            id: DURABLE_KV_REQUIREMENT_ID,
            kind: DURABLE_KV_RESOURCE_KIND.to_vec(),
            profile_data: Vec::new(),
            required_rights: DURABLE_KV_REQUIRED_RIGHTS,
            disposition: RebindDisposition::Reconnect,
            logical_name: state.session_key.clone(),
        }])
    }

    /// Validate an exact authority grant without consulting an authority.
    pub fn validate_binding_grant(
        &self,
        requirement: &ResourceRequirement,
        grant: &BindingGrant,
    ) -> Result<(), ProfileError> {
        if requirement.id != DURABLE_KV_REQUIREMENT_ID {
            return Err(ProfileError::WrongRequirement);
        }
        if requirement.kind != DURABLE_KV_RESOURCE_KIND {
            return Err(ProfileError::WrongResourceKind);
        }
        if requirement.disposition != RebindDisposition::Reconnect {
            return Err(ProfileError::WrongDisposition);
        }
        if requirement.required_rights != DURABLE_KV_REQUIRED_RIGHTS {
            return Err(ProfileError::RightsMismatch);
        }
        if !requirement.profile_data.is_empty() {
            return Err(ProfileError::WrongSchema);
        }
        if grant.requirement != requirement.id {
            return Err(ProfileError::WrongRequirement);
        }
        if grant.granted_rights != DURABLE_KV_REQUIRED_RIGHTS {
            return Err(ProfileError::RightsMismatch);
        }
        if requirement.logical_name.is_empty() {
            return Err(ProfileError::WrongLogicalName);
        }
        Ok(())
    }

    /// Validate a grant against the typed state's exact logical name and the
    /// core requirement/grant vocabulary.  This remains a pure check: neither
    /// the provider nor the native binding coordinates are queried.
    pub fn validate_binding(
        &self,
        state: &CounterSessionState,
        requirement: &ResourceRequirement,
        grant: &BindingGrant,
    ) -> Result<(), ProfileError> {
        self.validate_state(state)?;
        self.validate_binding_grant(requirement, grant)?;
        if requirement.logical_name != state.session_key {
            return Err(ProfileError::WrongLogicalName);
        }
        Ok(())
    }

    /// Effects are intentionally not interpreted by this first profile.
    /// Presence of any closure therefore keeps activation fail-closed; the
    /// authority/coordinator owns the actual outcome truth.
    pub fn project_effects(
        &self,
        receipts: &[EffectClosureReceipt],
    ) -> ApplicationRecoveryDecision {
        if receipts.is_empty() {
            ApplicationRecoveryDecision::Continue
        } else {
            ApplicationRecoveryDecision::RecoveryRequired
        }
    }
}

impl ContinuityProfile for DurableKvProfile {
    type State = CounterSessionState;

    fn profile_ref(&self) -> ProfileRef {
        Self::profile_ref(*self)
    }

    fn validate_state(&self, state: &Self::State) -> Result<(), ProfileError> {
        Self::validate_state(self, state)
    }

    fn resource_requirements(
        &self,
        state: &Self::State,
    ) -> Result<Vec<ResourceRequirement>, ProfileError> {
        Self::resource_requirements(self, state)
    }

    fn validate_binding_grant(
        &self,
        requirement: &ResourceRequirement,
        grant: &BindingGrant,
    ) -> Result<(), ProfileError> {
        Self::validate_binding_grant(self, requirement, grant)
    }

    fn validate_binding(
        &self,
        state: &Self::State,
        requirement: &ResourceRequirement,
        grant: &BindingGrant,
    ) -> Result<(), ProfileError> {
        Self::validate_binding(self, state, requirement, grant)
    }

    fn project_effects(&self, receipts: &[EffectClosureReceipt]) -> ApplicationRecoveryDecision {
        Self::project_effects(self, receipts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn state(key: &[u8]) -> CounterSessionState {
        CounterSessionState { counter: 7, session_key: key.to_vec(), last_seen_version: Some(3) }
    }

    #[test]
    fn roundtrip_and_strict_decode() {
        let codec = PostcardCodec::<CounterSessionState>::new(128);
        let encoded = codec.encode(&state(b"session")).unwrap();
        assert_eq!(codec.decode(&encoded).unwrap(), state(b"session"));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(codec.decode(&trailing), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn encode_and_decode_reject_oversize() {
        let codec = PostcardCodec::<CounterSessionState>::new(2);
        assert!(matches!(codec.encode(&state(b"session")), Err(CodecError::Oversize { .. })));
        assert!(matches!(codec.decode(&[1, 2, 3]), Err(CodecError::InputOversize { .. })));
    }

    #[test]
    fn empty_session_is_rejected() {
        assert_eq!(
            DurableKvProfile.validate_state(&state(b"")),
            Err(ProfileError::EmptySessionKey)
        );
    }

    #[test]
    fn requirements_are_stable_and_exact() {
        let profile = DurableKvProfile;
        let first = profile.resource_requirements(&state(b"session")).unwrap();
        let second = profile.resource_requirements(&state(b"session")).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        let requirement = &first[0];
        assert_eq!(requirement.kind, b"durable-kv");
        assert_eq!(requirement.disposition, RebindDisposition::Reconnect);
        assert_eq!(requirement.logical_name, b"session");
        assert_eq!(requirement.required_rights, DURABLE_KV_REQUIRED_RIGHTS);
        assert_eq!(profile.profile_ref().version, DURABLE_KV_PROFILE_VERSION);
        assert_eq!(profile.profile_ref().state_schema, DURABLE_KV_STATE_SCHEMA);
    }

    #[test]
    fn wrong_requirement_and_grant_amplification_are_rejected() {
        use visa_core::{AuthorityId, ExternalCoordinate};

        let profile = DurableKvProfile;
        let requirement = profile.resource_requirements(&state(b"session")).unwrap().remove(0);
        let mut grant = BindingGrant {
            requirement: DURABLE_KV_REQUIREMENT_ID,
            provider: ExternalCoordinate { authority: AuthorityId::from_u128(1), value: vec![1] },
            provider_generation: 1,
            binding: ExternalCoordinate { authority: AuthorityId::from_u128(1), value: vec![2] },
            granted_rights: DURABLE_KV_REQUIRED_RIGHTS,
        };
        assert!(profile.validate_binding_grant(&requirement, &grant).is_ok());
        grant.granted_rights = Rights(DURABLE_KV_REQUIRED_RIGHTS.0 | (1 << 7));
        assert_eq!(
            profile.validate_binding_grant(&requirement, &grant),
            Err(ProfileError::RightsMismatch)
        );
        let mut wrong_logical_requirement = requirement.clone();
        wrong_logical_requirement.logical_name = b"other".to_vec();
        grant.granted_rights = DURABLE_KV_REQUIRED_RIGHTS;
        assert_eq!(
            profile.validate_binding(&state(b"session"), &wrong_logical_requirement, &grant),
            Err(ProfileError::WrongLogicalName)
        );
        grant.requirement = RequirementId::from_u128(99);
        assert_eq!(
            profile.validate_binding_grant(&requirement, &grant),
            Err(ProfileError::WrongRequirement)
        );
    }

    #[test]
    fn effects_fail_closed_when_empty_or_unresolved() {
        use visa_core::{AuthorityId, EffectId, EffectResolution};

        let profile = DurableKvProfile;
        assert_eq!(profile.project_effects(&[]), ApplicationRecoveryDecision::Continue);
        assert_eq!(
            profile.project_effects(&[EffectClosureReceipt {
                effect: EffectId::from_u128(1),
                authority: AuthorityId::from_u128(2),
                resolution: EffectResolution::RetainedBySource,
                receipt_digest: Digest::ZERO,
            }]),
            ApplicationRecoveryDecision::RecoveryRequired
        );
    }
}
