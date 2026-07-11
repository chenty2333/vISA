use visa_component_adapter::{AdapterError, KvFailure, TimerFailure, WorkloadFailure};

use crate::protocol::WireError;

pub(crate) fn guest_error(error: WireError) -> Result<AdapterError, AdapterError> {
    match error.domain.as_str() {
        "workload" => workload_error(&error).map(AdapterError::Workload).ok_or_else(|| {
            AdapterError::GuestTrap(format!(
                "Node returned an invalid workload error shape: {}",
                describe(&error)
            ))
        }),
        "trap" if error.kind == "guest-trap" && error.detail.is_some() => {
            Ok(AdapterError::GuestTrap(describe(&error)))
        }
        _ => Err(AdapterError::GuestTrap(format!(
            "Node returned an invalid terminal error shape: {}",
            describe(&error)
        ))),
    }
}

fn workload_error(error: &WireError) -> Option<WorkloadFailure> {
    if error.kind == "kv.indeterminate" {
        if error.detail.as_deref().is_none_or(str::is_empty) {
            return None;
        }
    } else if error.detail.is_some() {
        return None;
    }
    Some(match error.kind.as_str() {
        "already-active" => WorkloadFailure::AlreadyActive,
        "invalid-state" => WorkloadFailure::InvalidState,
        "wrong-timer" => WorkloadFailure::WrongTimer,
        "safe-point-unavailable" => WorkloadFailure::SafePointUnavailable,
        "kv.denied" => WorkloadFailure::KeyValue(KvFailure::Denied),
        "kv.conflict" => WorkloadFailure::KeyValue(KvFailure::Conflict),
        "kv.stale-binding" => WorkloadFailure::KeyValue(KvFailure::StaleBinding),
        "kv.indeterminate" => {
            WorkloadFailure::KeyValue(KvFailure::Indeterminate(error.detail.clone()?))
        }
        "kv.unavailable" => WorkloadFailure::KeyValue(KvFailure::Unavailable),
        "timer.denied" => WorkloadFailure::Timer(TimerFailure::Denied),
        "timer.stale-binding" => WorkloadFailure::Timer(TimerFailure::StaleBinding),
        "timer.not-pending" => WorkloadFailure::Timer(TimerFailure::NotPending),
        "timer.unavailable" => WorkloadFailure::Timer(TimerFailure::Unavailable),
        _ => return None,
    })
}

pub(crate) fn kv_wire_error(error: KvFailure) -> WireError {
    let (kind, detail) = match error {
        KvFailure::Denied => ("denied", None),
        KvFailure::Conflict => ("conflict", None),
        KvFailure::StaleBinding => ("stale-binding", None),
        KvFailure::Indeterminate(operation) => ("indeterminate", Some(operation)),
        KvFailure::Unavailable => ("unavailable", None),
    };
    WireError { domain: "kv".into(), kind: kind.into(), detail }
}

pub(crate) fn timer_wire_error(error: TimerFailure) -> WireError {
    let kind = match error {
        TimerFailure::Denied => "denied",
        TimerFailure::StaleBinding => "stale-binding",
        TimerFailure::NotPending => "not-pending",
        TimerFailure::Unavailable => "unavailable",
    };
    WireError { domain: "timer".into(), kind: kind.into(), detail: None }
}

pub(crate) fn protocol_error(kind: &str, detail: impl Into<String>) -> WireError {
    WireError { domain: "protocol".into(), kind: kind.into(), detail: Some(detail.into()) }
}

fn describe(error: &WireError) -> String {
    match &error.detail {
        Some(detail) => format!("{}:{}: {detail}", error.domain, error.kind),
        None => format!("{}:{}", error.domain, error.kind),
    }
}
