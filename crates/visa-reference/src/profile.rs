//! The one concrete portable profile used by the reference vertical.
//!
//! This is deliberately crate-private: it is not a profile SDK and does not
//! offer an effect-policy surface.  The vertical carries no escaped effects.

use std::fmt;

use serde::{Deserialize, Serialize};
use visa_core::{
    BindingGrant, Digest, OpaqueBytes, ProfileId, ProfileRef, ProfileVersion, RebindDisposition,
    RequirementId, ResourceRequirement, Rights, SchemaId, SchemaRef, SemanticDomainId,
    SemanticDomainRef,
};

const MAX_STATE_BYTES: usize = 4 * 1024;
const MAX_SESSION_KEY_BYTES: usize = 256;

pub(crate) const REQUIRED_RIGHTS: Rights = Rights((1 << 0) | (1 << 1));
const PROFILE_ID: ProfileId = ProfileId::from_u128(1);
const SEMANTIC_DOMAIN_ID: SemanticDomainId = SemanticDomainId::from_u128(1);
const PROFILE_VERSION: ProfileVersion = ProfileVersion { major: 1, minor: 0 };
const STATE_SCHEMA: SchemaRef = SchemaRef { id: SchemaId::from_u128(1), version: 1 };
const REQUIREMENT_ID: RequirementId = RequirementId::from_u128(1);
const RESOURCE_KIND: &[u8] = b"durable-kv";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CounterSessionState {
    pub(crate) counter: u64,
    pub(crate) session_key: Vec<u8>,
    pub(crate) last_seen_version: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileError {
    EmptySessionKey,
    SessionKeyTooLong,
    InvalidState,
    NonCanonicalState,
    RequirementMismatch,
    GrantMismatch,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptySessionKey => "session key is empty",
            Self::SessionKeyTooLong => "session key exceeds the reference bound",
            Self::InvalidState => "state is malformed or oversized",
            Self::NonCanonicalState => "state is not canonical postcard",
            Self::RequirementMismatch => {
                "resource requirements do not match the counter/KV profile"
            }
            Self::GrantMismatch => "binding grant does not match the counter/KV requirement",
        })
    }
}

impl std::error::Error for ProfileError {}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DurableKvProfile;

impl DurableKvProfile {
    pub(crate) fn profile_ref(self) -> ProfileRef {
        ProfileRef {
            id: PROFILE_ID,
            version: PROFILE_VERSION,
            contract_digest: Digest::of_bytes(b"visa-reference/counter-kv/1.0"),
            state_schema: STATE_SCHEMA,
        }
    }

    pub(crate) fn semantic_domain(self, artifact_digest: Digest) -> SemanticDomainRef {
        SemanticDomainRef {
            id: SEMANTIC_DOMAIN_ID,
            contract_digest: self.profile_ref().contract_digest,
            artifact_digest,
        }
    }

    pub(crate) fn capture_state(
        self,
        counter: u64,
        session_key: Vec<u8>,
        last_seen_version: Option<u64>,
    ) -> Result<CounterSessionState, ProfileError> {
        let state = CounterSessionState { counter, session_key, last_seen_version };
        self.validate_state(&state)?;
        Ok(state)
    }

    pub(crate) fn encode_state(self, state: &CounterSessionState) -> Result<Vec<u8>, ProfileError> {
        self.validate_state(state)?;
        let mut buffer = vec![0; MAX_STATE_BYTES];
        let encoded =
            postcard::to_slice(state, &mut buffer).map_err(|_| ProfileError::InvalidState)?;
        Ok(encoded.to_vec())
    }

    pub(crate) fn decode_state(self, bytes: &[u8]) -> Result<CounterSessionState, ProfileError> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(ProfileError::InvalidState);
        }
        let (state, remainder) =
            postcard::take_from_bytes(bytes).map_err(|_| ProfileError::InvalidState)?;
        if !remainder.is_empty() {
            return Err(ProfileError::InvalidState);
        }
        self.validate_state(&state)?;
        if self.encode_state(&state)?.as_slice() != bytes {
            return Err(ProfileError::NonCanonicalState);
        }
        Ok(state)
    }

    pub(crate) fn requirements(
        self,
        state: &CounterSessionState,
    ) -> Result<Vec<ResourceRequirement>, ProfileError> {
        self.validate_state(state)?;
        Ok(vec![ResourceRequirement {
            id: REQUIREMENT_ID,
            schema: STATE_SCHEMA,
            profile_data: OpaqueBytes(RESOURCE_KIND.to_vec()),
            required_rights: REQUIRED_RIGHTS,
            disposition: RebindDisposition::Recreate,
            logical_name: OpaqueBytes(state.session_key.clone()),
        }])
    }

    pub(crate) fn validate_resources(
        self,
        state: &CounterSessionState,
        resources: &[ResourceRequirement],
    ) -> Result<(), ProfileError> {
        if self.requirements(state)?.as_slice() == resources {
            Ok(())
        } else {
            Err(ProfileError::RequirementMismatch)
        }
    }

    pub(crate) fn validate_binding(
        self,
        state: &CounterSessionState,
        requirement: &ResourceRequirement,
        grant: &BindingGrant,
    ) -> Result<(), ProfileError> {
        self.validate_state(state)?;
        if requirement.id != REQUIREMENT_ID
            || requirement.schema != STATE_SCHEMA
            || requirement.profile_data.0.as_slice() != RESOURCE_KIND
            || requirement.required_rights != REQUIRED_RIGHTS
            || requirement.disposition != RebindDisposition::Recreate
            || requirement.logical_name.0 != state.session_key
        {
            return Err(ProfileError::RequirementMismatch);
        }
        if grant.requirement != REQUIREMENT_ID
            || grant.granted_rights != REQUIRED_RIGHTS
            || grant.disposition != RebindDisposition::Recreate
        {
            return Err(ProfileError::GrantMismatch);
        }
        Ok(())
    }

    fn validate_state(self, state: &CounterSessionState) -> Result<(), ProfileError> {
        if state.session_key.is_empty() {
            return Err(ProfileError::EmptySessionKey);
        }
        if state.session_key.len() > MAX_SESSION_KEY_BYTES {
            return Err(ProfileError::SessionKeyTooLong);
        }
        Ok(())
    }
}
