use std::{error::Error, fmt};

use contract_core::Digest;
use visa_profile::RegularFileResult;

use crate::{PortableRegularFileState, RegularFileStateCodecError, ResourceBindingError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegularFileCallResult {
    pub operation_id: String,
    pub result: RegularFileResult,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegularFileFailure {
    Denied,
    Conflict,
    StaleBinding,
    Unsupported,
    Indeterminate(String),
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegularFileWorkloadFailure {
    AlreadyActive,
    InvalidState,
    SafePointUnavailable,
    File(RegularFileFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegularFileAdapterError {
    ComponentDigestMismatch { expected: Digest, actual: Digest },
    Engine(String),
    InvalidComponent(String),
    Link(String),
    Instantiation(String),
    GuestTrap(String),
    Workload(RegularFileWorkloadFailure),
    ResourceBinding(ResourceBindingError),
    InvalidCanonicalProfile,
    InvalidOperation,
    LiveResourcesAtSafePoint { state: PortableRegularFileState },
    PortableStateMismatch { expected: Digest, actual: Digest },
    PortableState(RegularFileStateCodecError),
}

impl From<RegularFileStateCodecError> for RegularFileAdapterError {
    fn from(error: RegularFileStateCodecError) -> Self {
        Self::PortableState(error)
    }
}

impl From<ResourceBindingError> for RegularFileAdapterError {
    fn from(error: ResourceBindingError) -> Self {
        Self::ResourceBinding(error)
    }
}

impl fmt::Display for RegularFileAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ComponentDigestMismatch { .. } => {
                formatter.write_str("component digest mismatch")
            }
            Self::Engine(error) => write!(formatter, "creating runtime engine failed: {error}"),
            Self::InvalidComponent(error) => write!(formatter, "invalid component: {error}"),
            Self::Link(error) => write!(formatter, "linking component imports failed: {error}"),
            Self::Instantiation(error) => {
                write!(formatter, "instantiating component failed: {error}")
            }
            Self::GuestTrap(error) => write!(formatter, "component call trapped: {error}"),
            Self::Workload(error) => write!(formatter, "component rejected request: {error:?}"),
            Self::ResourceBinding(error) => write!(formatter, "resource binding failed: {error:?}"),
            Self::InvalidCanonicalProfile => {
                formatter.write_str("canonical regular-file profile is missing or invalid")
            }
            Self::InvalidOperation => formatter.write_str("invalid regular-file operation"),
            Self::LiveResourcesAtSafePoint { .. } => {
                formatter.write_str("component reported a safe point with live file handles")
            }
            Self::PortableStateMismatch { .. } => {
                formatter.write_str("provided portable file state does not match canonical state")
            }
            Self::PortableState(error) => {
                write!(formatter, "invalid portable file state: {error:?}")
            }
        }
    }
}

impl Error for RegularFileAdapterError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_taxonomy_keeps_semantic_and_transport_failures_distinct() {
        let semantic = RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(
            RegularFileFailure::Indeterminate("operation-a".into()),
        ));
        let transport = RegularFileAdapterError::GuestTrap("closed pipe".into());
        assert_ne!(semantic, transport);
    }
}
