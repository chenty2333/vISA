use std::{error::Error, fmt};

use contract_core::Digest;
use visa_component_adapter::{
    LogicalRequestStateCodecError, PortableLogicalRequestState, ResourceBindingError,
};
use visa_profile::LogicalRequestTransport;

use super::bindings::{
    exports::visa::request_continuity::workload::WorkloadError as WitWorkloadError,
    visa::request_continuity::logical_request::{RequestError, Transport},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicalRequestFailure {
    Denied,
    PeerMismatch,
    CredentialDenied,
    UnsafeReplay,
    UnsupportedTransport(LogicalRequestTransport),
    PolicyDenied,
    StaleBinding,
    InvalidCursor,
    Indeterminate(String),
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicalRequestWorkloadFailure {
    AlreadyActive,
    InvalidState,
    SafePointUnavailable,
    Request(LogicalRequestFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicalRequestAdapterError {
    ComponentDigestMismatch { expected: Digest, actual: Digest },
    Engine(String),
    InvalidComponent(String),
    Link(String),
    Instantiation(String),
    GuestTrap(String),
    Workload(LogicalRequestWorkloadFailure),
    ResourceBinding(ResourceBindingError),
    InvalidCanonicalProfile,
    UnsupportedTransport(LogicalRequestTransport),
    InvalidOperation,
    LiveResourcesAtSafePoint { state: PortableLogicalRequestState },
    PortableStateMismatch { expected: Digest, actual: Digest },
    PortableState(LogicalRequestStateCodecError),
}

impl From<WitWorkloadError> for LogicalRequestWorkloadFailure {
    fn from(error: WitWorkloadError) -> Self {
        match error {
            WitWorkloadError::AlreadyActive => Self::AlreadyActive,
            WitWorkloadError::InvalidState => Self::InvalidState,
            WitWorkloadError::SafePointUnavailable => Self::SafePointUnavailable,
            WitWorkloadError::Request(error) => Self::Request(error.into()),
        }
    }
}

impl From<RequestError> for LogicalRequestFailure {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::Denied => Self::Denied,
            RequestError::PeerMismatch => Self::PeerMismatch,
            RequestError::CredentialDenied => Self::CredentialDenied,
            RequestError::UnsafeReplay => Self::UnsafeReplay,
            RequestError::UnsupportedTransport(transport) => {
                Self::UnsupportedTransport(from_wit_transport(transport))
            }
            RequestError::PolicyDenied => Self::PolicyDenied,
            RequestError::StaleBinding => Self::StaleBinding,
            RequestError::InvalidCursor => Self::InvalidCursor,
            RequestError::Indeterminate(operation) => Self::Indeterminate(operation),
            RequestError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<LogicalRequestStateCodecError> for LogicalRequestAdapterError {
    fn from(error: LogicalRequestStateCodecError) -> Self {
        Self::PortableState(error)
    }
}

impl From<ResourceBindingError> for LogicalRequestAdapterError {
    fn from(error: ResourceBindingError) -> Self {
        Self::ResourceBinding(error)
    }
}

impl fmt::Display for LogicalRequestAdapterError {
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
                formatter.write_str("canonical logical-request profile is missing or invalid")
            }
            Self::UnsupportedTransport(transport) => {
                write!(formatter, "logical-request transport is unsupported: {transport:?}")
            }
            Self::InvalidOperation => formatter.write_str("invalid logical-request operation"),
            Self::LiveResourcesAtSafePoint { .. } => {
                formatter.write_str("component reported a safe point with live request handles")
            }
            Self::PortableStateMismatch { .. } => formatter
                .write_str("provided portable request state does not match canonical state"),
            Self::PortableState(error) => {
                write!(formatter, "invalid portable request state: {error:?}")
            }
        }
    }
}

impl Error for LogicalRequestAdapterError {}

const fn from_wit_transport(transport: Transport) -> LogicalRequestTransport {
    match transport {
        Transport::Reconnectable => LogicalRequestTransport::Reconnectable,
        Transport::RawLiveTcp => LogicalRequestTransport::RawLiveTcp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_errors_preserve_transport_and_indeterminate_operation_identity() {
        assert_eq!(
            LogicalRequestFailure::from(RequestError::UnsupportedTransport(Transport::RawLiveTcp)),
            LogicalRequestFailure::UnsupportedTransport(LogicalRequestTransport::RawLiveTcp)
        );
        assert_eq!(
            LogicalRequestFailure::from(RequestError::Indeterminate("effect-a".into())),
            LogicalRequestFailure::Indeterminate("effect-a".into())
        );
        assert_eq!(
            LogicalRequestFailure::from(RequestError::CredentialDenied),
            LogicalRequestFailure::CredentialDenied
        );
    }
}
