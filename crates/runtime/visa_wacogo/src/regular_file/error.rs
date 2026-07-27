use visa_component_adapter::{
    AdapterError, RegularFileAdapterError, RegularFileFailure, RegularFileWorkloadFailure,
};

use crate::protocol::WireError;

pub(super) fn transport_error(error: AdapterError) -> RegularFileAdapterError {
    match error {
        AdapterError::ComponentDigestMismatch { expected, actual } => {
            RegularFileAdapterError::ComponentDigestMismatch { expected, actual }
        }
        AdapterError::InvalidComponent(detail) => RegularFileAdapterError::InvalidComponent(detail),
        AdapterError::Link(detail) => RegularFileAdapterError::Link(detail),
        AdapterError::Instantiation(detail) => RegularFileAdapterError::Instantiation(detail),
        AdapterError::GuestTrap(detail) => RegularFileAdapterError::GuestTrap(detail),
        AdapterError::ResourceBinding(detail) => RegularFileAdapterError::ResourceBinding(detail),
        other => RegularFileAdapterError::Engine(other.to_string()),
    }
}

pub(super) fn terminal_error(error: WireError) -> Result<RegularFileAdapterError, String> {
    match error.domain.as_str() {
        "workload" => workload_error(error),
        "trap" => error
            .detail
            .filter(|detail| !detail.is_empty())
            .map(RegularFileAdapterError::GuestTrap)
            .ok_or_else(|| "regular-file trap omitted its detail".into()),
        other => Err(format!(
            "regular-file terminal error used invalid domain {other:?} and kind {:?}",
            error.kind
        )),
    }
}

fn workload_error(error: WireError) -> Result<RegularFileAdapterError, String> {
    let detail = error.detail;
    let no_detail = |failure| {
        if detail.is_none() {
            Ok(RegularFileAdapterError::Workload(failure))
        } else {
            Err(format!("regular-file workload error {:?} unexpectedly carried detail", error.kind))
        }
    };
    match error.kind.as_str() {
        "already-active" => no_detail(RegularFileWorkloadFailure::AlreadyActive),
        "invalid-state" => no_detail(RegularFileWorkloadFailure::InvalidState),
        "safe-point-unavailable" => no_detail(RegularFileWorkloadFailure::SafePointUnavailable),
        "file.denied" => no_detail(RegularFileWorkloadFailure::File(RegularFileFailure::Denied)),
        "file.conflict" => {
            no_detail(RegularFileWorkloadFailure::File(RegularFileFailure::Conflict))
        }
        "file.stale-binding" => {
            no_detail(RegularFileWorkloadFailure::File(RegularFileFailure::StaleBinding))
        }
        "file.unsupported" => {
            no_detail(RegularFileWorkloadFailure::File(RegularFileFailure::Unsupported))
        }
        "file.unavailable" => {
            no_detail(RegularFileWorkloadFailure::File(RegularFileFailure::Unavailable))
        }
        "file.indeterminate" => detail
            .filter(|detail| !detail.is_empty())
            .map(|operation| {
                RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(
                    RegularFileFailure::Indeterminate(operation),
                ))
            })
            .ok_or_else(|| "file.indeterminate omitted its operation identity".into()),
        other => Err(format!("unknown regular-file workload error kind {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_indeterminate_retains_the_operation_identity() {
        assert_eq!(
            terminal_error(WireError {
                domain: "workload".into(),
                kind: "file.indeterminate".into(),
                detail: Some("operation-a".into()),
            })
            .unwrap(),
            RegularFileAdapterError::Workload(RegularFileWorkloadFailure::File(
                RegularFileFailure::Indeterminate("operation-a".into()),
            ))
        );
    }
}
