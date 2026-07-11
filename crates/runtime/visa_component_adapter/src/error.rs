use std::{error::Error, fmt};

use contract_core::Digest;
use visa_profile::CompatibilityError;
use visa_runtime::{RuntimeError, SafePointTimer};

use crate::{BindingError, PortableComponentState, StateCodecError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvFailure {
    Denied,
    Conflict,
    StaleBinding,
    Indeterminate(String),
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerFailure {
    Denied,
    StaleBinding,
    NotPending,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkloadFailure {
    AlreadyActive,
    InvalidState,
    WrongTimer,
    SafePointUnavailable,
    KeyValue(KvFailure),
    Timer(TimerFailure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadFailureKind {
    AlreadyActive,
    InvalidState,
    WrongTimer,
    SafePointUnavailable,
    KeyValueDenied,
    KeyValueConflict,
    KeyValueStaleBinding,
    KeyValueIndeterminate,
    KeyValueUnavailable,
    TimerDenied,
    TimerStaleBinding,
    TimerNotPending,
    TimerUnavailable,
}

impl WorkloadFailure {
    pub const fn kind(&self) -> WorkloadFailureKind {
        match self {
            Self::AlreadyActive => WorkloadFailureKind::AlreadyActive,
            Self::InvalidState => WorkloadFailureKind::InvalidState,
            Self::WrongTimer => WorkloadFailureKind::WrongTimer,
            Self::SafePointUnavailable => WorkloadFailureKind::SafePointUnavailable,
            Self::KeyValue(KvFailure::Denied) => WorkloadFailureKind::KeyValueDenied,
            Self::KeyValue(KvFailure::Conflict) => WorkloadFailureKind::KeyValueConflict,
            Self::KeyValue(KvFailure::StaleBinding) => WorkloadFailureKind::KeyValueStaleBinding,
            Self::KeyValue(KvFailure::Indeterminate(_)) => {
                WorkloadFailureKind::KeyValueIndeterminate
            }
            Self::KeyValue(KvFailure::Unavailable) => WorkloadFailureKind::KeyValueUnavailable,
            Self::Timer(TimerFailure::Denied) => WorkloadFailureKind::TimerDenied,
            Self::Timer(TimerFailure::StaleBinding) => WorkloadFailureKind::TimerStaleBinding,
            Self::Timer(TimerFailure::NotPending) => WorkloadFailureKind::TimerNotPending,
            Self::Timer(TimerFailure::Unavailable) => WorkloadFailureKind::TimerUnavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceBindingError {
    Inactive,
    Missing,
    Ambiguous,
    InvalidReceipt,
    LiveResources,
    ResourceTable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterFailureKind {
    IncompatibleProfile,
    ProfileEncoding,
    ProfileDigestMismatch,
    ComponentDigestMismatch,
    Engine,
    InvalidComponent,
    Link,
    UnsupportedRuntimeFeature,
    Instantiation,
    GuestTrap,
    Workload,
    ResourceBinding,
    LiveResourcesAtSafePoint,
    SafePointStateMismatch,
    PortableStateMismatch,
    PortableState,
    Coordinator,
    SafePointRollback,
    SafePointGuestRollback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    IncompatibleProfile(CompatibilityError),
    ProfileEncoding,
    ProfileDigestMismatch { expected: Digest, actual: Digest },
    ComponentDigestMismatch { expected: Digest, actual: Digest },
    Engine(String),
    InvalidComponent(String),
    Link(String),
    UnsupportedRuntimeFeature(String),
    Instantiation(String),
    GuestTrap(String),
    Workload(WorkloadFailure),
    ResourceBinding(ResourceBindingError),
    LiveResourcesAtSafePoint { state: PortableComponentState },
    SafePointStateMismatch { state: PortableComponentState, timer: SafePointTimer },
    PortableStateMismatch { expected: Digest, actual: Digest },
    PortableState(StateCodecError),
    Coordinator(RuntimeError),
    SafePointRollback { coordinator: RuntimeError, guest: Box<AdapterError> },
    SafePointGuestRollback { original: Box<AdapterError>, rollback: Box<AdapterError> },
}

impl AdapterError {
    pub const fn kind(&self) -> AdapterFailureKind {
        match self {
            Self::IncompatibleProfile(_) => AdapterFailureKind::IncompatibleProfile,
            Self::ProfileEncoding => AdapterFailureKind::ProfileEncoding,
            Self::ProfileDigestMismatch { .. } => AdapterFailureKind::ProfileDigestMismatch,
            Self::ComponentDigestMismatch { .. } => AdapterFailureKind::ComponentDigestMismatch,
            Self::Engine(_) => AdapterFailureKind::Engine,
            Self::InvalidComponent(_) => AdapterFailureKind::InvalidComponent,
            Self::Link(_) => AdapterFailureKind::Link,
            Self::UnsupportedRuntimeFeature(_) => AdapterFailureKind::UnsupportedRuntimeFeature,
            Self::Instantiation(_) => AdapterFailureKind::Instantiation,
            Self::GuestTrap(_) => AdapterFailureKind::GuestTrap,
            Self::Workload(_) => AdapterFailureKind::Workload,
            Self::ResourceBinding(_) => AdapterFailureKind::ResourceBinding,
            Self::LiveResourcesAtSafePoint { .. } => AdapterFailureKind::LiveResourcesAtSafePoint,
            Self::SafePointStateMismatch { .. } => AdapterFailureKind::SafePointStateMismatch,
            Self::PortableStateMismatch { .. } => AdapterFailureKind::PortableStateMismatch,
            Self::PortableState(_) => AdapterFailureKind::PortableState,
            Self::Coordinator(_) => AdapterFailureKind::Coordinator,
            Self::SafePointRollback { .. } => AdapterFailureKind::SafePointRollback,
            Self::SafePointGuestRollback { .. } => AdapterFailureKind::SafePointGuestRollback,
        }
    }

    pub const fn workload_kind(&self) -> Option<WorkloadFailureKind> {
        match self {
            Self::Workload(error) => Some(error.kind()),
            _ => None,
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompatibleProfile(error) => {
                write!(formatter, "incompatible cooperative-handoff profile: {error:?}")
            }
            Self::ProfileEncoding => formatter.write_str("encoding profile identity failed"),
            Self::ProfileDigestMismatch { .. } => formatter.write_str("profile digest mismatch"),
            Self::ComponentDigestMismatch { .. } => {
                formatter.write_str("component digest mismatch")
            }
            Self::Engine(error) => write!(formatter, "creating runtime engine failed: {error}"),
            Self::InvalidComponent(error) => write!(formatter, "invalid component: {error}"),
            Self::Link(error) => write!(formatter, "linking component imports failed: {error}"),
            Self::UnsupportedRuntimeFeature(error) => {
                write!(formatter, "runtime feature is unsupported: {error}")
            }
            Self::Instantiation(error) => {
                write!(formatter, "instantiating component failed: {error}")
            }
            Self::GuestTrap(error) => write!(formatter, "component call trapped: {error}"),
            Self::Workload(error) => write!(formatter, "component rejected request: {error:?}"),
            Self::ResourceBinding(error) => write!(formatter, "resource binding failed: {error:?}"),
            Self::LiveResourcesAtSafePoint { .. } => {
                formatter.write_str("component reported a safe point with live resource handles")
            }
            Self::SafePointStateMismatch { .. } => {
                formatter.write_str("component and canonical timer safe-point states disagree")
            }
            Self::PortableStateMismatch { .. } => formatter
                .write_str("provided portable component state does not match canonical state"),
            Self::PortableState(error) => write!(formatter, "invalid portable state: {error:?}"),
            Self::Coordinator(error) => write!(formatter, "runtime coordinator failed: {error:?}"),
            Self::SafePointRollback { coordinator, guest } => write!(
                formatter,
                "safe-point rollback failed in coordinator ({coordinator:?}) after guest error ({guest})"
            ),
            Self::SafePointGuestRollback { original, rollback } => write!(
                formatter,
                "safe-point guest rollback failed ({rollback}) after the original error ({original})"
            ),
        }
    }
}

impl Error for AdapterError {}

impl From<StateCodecError> for AdapterError {
    fn from(error: StateCodecError) -> Self {
        Self::PortableState(error)
    }
}

impl From<RuntimeError> for AdapterError {
    fn from(error: RuntimeError) -> Self {
        Self::Coordinator(error)
    }
}

impl From<ResourceBindingError> for AdapterError {
    fn from(error: ResourceBindingError) -> Self {
        Self::ResourceBinding(error)
    }
}

impl From<BindingError> for AdapterError {
    fn from(error: BindingError) -> Self {
        Self::ResourceBinding(error.into())
    }
}
