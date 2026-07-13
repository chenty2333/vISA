use visa_component_adapter::{AdapterError, KvFailure, TimerFailure, WorkloadFailure};

use crate::protocol::WireError;

pub(crate) fn terminal_error(
    error: WireError,
    operation: &str,
) -> Result<AdapterError, AdapterError> {
    match error.domain.as_str() {
        "workload" if operation != "instantiate" => workload_error(&error)
            .map(AdapterError::Workload)
            .ok_or_else(|| invalid_terminal(&error)),
        "trap" if error.detail.as_deref().is_some_and(not_empty) => {
            Ok(AdapterError::GuestTrap(describe(&error)))
        }
        "instantiation" if operation == "instantiate" => {
            exact_detail(&error).map(|detail| AdapterError::Instantiation(detail.to_owned()))
        }
        _ => Err(invalid_terminal(&error)),
    }
}

pub(crate) fn startup_error(error: WireError) -> AdapterError {
    let detail = error.detail.as_deref().filter(|detail| !detail.is_empty());
    match (error.domain.as_str(), error.kind.as_str(), detail) {
        ("preflight", "invalid-component" | "invalid-carrier", Some(detail)) => {
            AdapterError::InvalidComponent(detail.into())
        }
        ("preflight", "invalid-surface", Some(detail)) | ("link", _, Some(detail)) => {
            AdapterError::Link(detail.into())
        }
        ("preflight", "unsupported-runtime-feature" | "runtime-identity", Some(detail)) => {
            AdapterError::UnsupportedRuntimeFeature(detail.into())
        }
        ("preflight", "engine", Some(detail)) => AdapterError::Engine(detail.into()),
        _ => AdapterError::Engine(format!(
            "wacogo startup-error message had an invalid error shape: {}",
            describe(&error)
        )),
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

fn exact_detail(error: &WireError) -> Result<&str, AdapterError> {
    error.detail.as_deref().filter(|detail| !detail.is_empty()).ok_or_else(|| {
        AdapterError::GuestTrap(format!(
            "wacogo returned an invalid terminal error shape: {}",
            describe(error)
        ))
    })
}

fn invalid_terminal(error: &WireError) -> AdapterError {
    AdapterError::GuestTrap(format!(
        "wacogo returned an invalid terminal error shape: {}",
        describe(error)
    ))
}

fn describe(error: &WireError) -> String {
    match &error.detail {
        Some(detail) => format!("{}:{}: {detail}", error.domain, error.kind),
        None => format!("{}:{}", error.domain, error.kind),
    }
}

fn not_empty(value: &str) -> bool {
    !value.is_empty()
}

#[cfg(test)]
mod tests {
    use visa_component_adapter::{AdapterFailureKind, WorkloadFailureKind};

    use super::*;

    #[test]
    fn workload_wire_errors_map_only_exact_semantic_shapes() {
        let error = terminal_error(
            WireError {
                domain: "workload".into(),
                kind: "kv.indeterminate".into(),
                detail: Some("operation".into()),
            },
            "activate",
        )
        .unwrap();
        assert_eq!(error.kind(), AdapterFailureKind::Workload);
        assert_eq!(error.workload_kind(), Some(WorkloadFailureKind::KeyValueIndeterminate));

        for error in [
            WireError {
                domain: "workload".into(),
                kind: "already-active".into(),
                detail: Some("unexpected".into()),
            },
            WireError { domain: "workload".into(), kind: "kv.indeterminate".into(), detail: None },
            WireError { domain: "kv".into(), kind: "denied".into(), detail: None },
        ] {
            assert!(terminal_error(error, "activate").is_err());
        }
    }

    #[test]
    fn instantiation_errors_are_accepted_only_for_the_instantiation_command() {
        let wire = WireError {
            domain: "instantiation".into(),
            kind: "instantiate-failed".into(),
            detail: Some("typed failure".into()),
        };
        assert_eq!(
            terminal_error(wire.clone(), "instantiate").unwrap().kind(),
            AdapterFailureKind::Instantiation
        );
        assert!(terminal_error(wire, "status").is_err());
    }
}
