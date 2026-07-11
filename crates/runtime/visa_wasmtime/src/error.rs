use std::{error::Error, fmt};

use contract_core::Digest;
use visa_profile::CompatibilityError;
use visa_runtime::{RuntimeError, SafePointTimer};

use crate::{
    StateCodecError,
    bindings::{
        exports::visa::continuity::workload::WorkloadError as WitWorkloadError,
        visa::continuity::{key_value::KvError, timers::TimerError},
    },
    host::BindingError,
};

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
pub enum ResourceBindingError {
    Inactive,
    Missing,
    Ambiguous,
    InvalidReceipt,
    LiveResources,
    ResourceTable,
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
    Instantiation(String),
    GuestTrap(String),
    Workload(WorkloadFailure),
    ResourceBinding(ResourceBindingError),
    LiveResourcesAtSafePoint { state: crate::PortableComponentState },
    SafePointStateMismatch { state: crate::PortableComponentState, timer: SafePointTimer },
    PortableState(StateCodecError),
    Coordinator(RuntimeError),
    SafePointRollback { coordinator: RuntimeError, guest: Box<AdapterError> },
    SafePointGuestRollback { original: Box<AdapterError>, rollback: Box<AdapterError> },
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
            Self::Engine(error) => write!(formatter, "creating Wasmtime engine failed: {error}"),
            Self::InvalidComponent(error) => write!(formatter, "invalid component: {error}"),
            Self::Link(error) => write!(formatter, "linking component imports failed: {error}"),
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

impl From<BindingError> for AdapterError {
    fn from(error: BindingError) -> Self {
        let error = match error {
            BindingError::Inactive => ResourceBindingError::Inactive,
            BindingError::Missing => ResourceBindingError::Missing,
            BindingError::Ambiguous => ResourceBindingError::Ambiguous,
            BindingError::InvalidReceipt => ResourceBindingError::InvalidReceipt,
            BindingError::LiveResources => ResourceBindingError::LiveResources,
            BindingError::ResourceTable => ResourceBindingError::ResourceTable,
        };
        Self::ResourceBinding(error)
    }
}

impl From<WitWorkloadError> for WorkloadFailure {
    fn from(error: WitWorkloadError) -> Self {
        match error {
            WitWorkloadError::AlreadyActive => Self::AlreadyActive,
            WitWorkloadError::InvalidState => Self::InvalidState,
            WitWorkloadError::WrongTimer => Self::WrongTimer,
            WitWorkloadError::SafePointUnavailable => Self::SafePointUnavailable,
            WitWorkloadError::Kv(error) => Self::KeyValue(error.into()),
            WitWorkloadError::Timer(error) => Self::Timer(error.into()),
        }
    }
}

impl From<KvError> for KvFailure {
    fn from(error: KvError) -> Self {
        match error {
            KvError::Denied => Self::Denied,
            KvError::Conflict => Self::Conflict,
            KvError::StaleBinding => Self::StaleBinding,
            KvError::Indeterminate(operation) => Self::Indeterminate(operation),
            KvError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<TimerError> for TimerFailure {
    fn from(error: TimerError) -> Self {
        match error {
            TimerError::Denied => Self::Denied,
            TimerError::StaleBinding => Self::StaleBinding,
            TimerError::NotPending => Self::NotPending,
            TimerError::Unavailable => Self::Unavailable,
        }
    }
}
