use visa_component_adapter::{KvFailure, TimerFailure, WorkloadFailure};

use crate::bindings::{
    exports::visa::continuity::workload::WorkloadError as WitWorkloadError,
    visa::continuity::{key_value::KvError, timers::TimerError},
};

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

impl From<KvFailure> for KvError {
    fn from(error: KvFailure) -> Self {
        match error {
            KvFailure::Denied => Self::Denied,
            KvFailure::Conflict => Self::Conflict,
            KvFailure::StaleBinding => Self::StaleBinding,
            KvFailure::Indeterminate(operation) => Self::Indeterminate(operation),
            KvFailure::Unavailable => Self::Unavailable,
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

impl From<TimerFailure> for TimerError {
    fn from(error: TimerFailure) -> Self {
        match error {
            TimerFailure::Denied => Self::Denied,
            TimerFailure::StaleBinding => Self::StaleBinding,
            TimerFailure::NotPending => Self::NotPending,
            TimerFailure::Unavailable => Self::Unavailable,
        }
    }
}
