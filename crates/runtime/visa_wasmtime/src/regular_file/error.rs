use std::{error::Error, fmt};

use contract_core::Digest;
use visa_component_adapter::{
    PortableRegularFileState, RegularFileStateCodecError, ResourceBindingError,
};

use super::bindings::{
    exports::visa::file_continuity::workload::WorkloadError as WitWorkloadError,
    visa::file_continuity::regular_file::FileError,
};

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

impl From<WitWorkloadError> for RegularFileWorkloadFailure {
    fn from(error: WitWorkloadError) -> Self {
        match error {
            WitWorkloadError::AlreadyActive => Self::AlreadyActive,
            WitWorkloadError::InvalidState => Self::InvalidState,
            WitWorkloadError::SafePointUnavailable => Self::SafePointUnavailable,
            WitWorkloadError::File(error) => Self::File(error.into()),
        }
    }
}

impl From<FileError> for RegularFileFailure {
    fn from(error: FileError) -> Self {
        match error {
            FileError::Denied => Self::Denied,
            FileError::Conflict => Self::Conflict,
            FileError::StaleBinding => Self::StaleBinding,
            FileError::Unsupported => Self::Unsupported,
            FileError::Indeterminate(operation) => Self::Indeterminate(operation),
            FileError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<visa_component_adapter::ProfileFailure> for FileError {
    fn from(error: visa_component_adapter::ProfileFailure) -> Self {
        use visa_component_adapter::ProfileFailure;

        match error {
            ProfileFailure::Denied => Self::Denied,
            ProfileFailure::Conflict => Self::Conflict,
            ProfileFailure::StaleBinding => Self::StaleBinding,
            ProfileFailure::Invalid | ProfileFailure::Unsupported => Self::Unsupported,
            ProfileFailure::Cancelled => Self::Unavailable,
            ProfileFailure::Indeterminate(operation) => Self::Indeterminate(operation),
            ProfileFailure::Unavailable => Self::Unavailable,
        }
    }
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
    use visa_component_adapter::ProfileFailure;

    use super::*;

    #[test]
    fn profile_failures_map_without_losing_indeterminate_operation_identity() {
        assert!(matches!(FileError::from(ProfileFailure::Denied), FileError::Denied));
        assert!(matches!(FileError::from(ProfileFailure::Conflict), FileError::Conflict));
        assert!(matches!(FileError::from(ProfileFailure::StaleBinding), FileError::StaleBinding));
        assert!(matches!(FileError::from(ProfileFailure::Invalid), FileError::Unsupported));
        assert!(matches!(FileError::from(ProfileFailure::Cancelled), FileError::Unavailable));
        assert!(matches!(
            FileError::from(ProfileFailure::Indeterminate("operation-a".into())),
            FileError::Indeterminate(operation) if operation == "operation-a"
        ));
    }
}
