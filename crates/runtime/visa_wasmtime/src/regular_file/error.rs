pub use visa_component_adapter::{
    RegularFileAdapterError, RegularFileFailure, RegularFileWorkloadFailure,
};

use super::bindings::{
    exports::visa::file_continuity::workload::WorkloadError as WitWorkloadError,
    visa::file_continuity::regular_file::FileError,
};

pub(crate) fn workload_failure(error: WitWorkloadError) -> RegularFileWorkloadFailure {
    match error {
        WitWorkloadError::AlreadyActive => RegularFileWorkloadFailure::AlreadyActive,
        WitWorkloadError::InvalidState => RegularFileWorkloadFailure::InvalidState,
        WitWorkloadError::SafePointUnavailable => RegularFileWorkloadFailure::SafePointUnavailable,
        WitWorkloadError::File(error) => RegularFileWorkloadFailure::File(file_failure(error)),
    }
}

fn file_failure(error: FileError) -> RegularFileFailure {
    match error {
        FileError::Denied => RegularFileFailure::Denied,
        FileError::Conflict => RegularFileFailure::Conflict,
        FileError::StaleBinding => RegularFileFailure::StaleBinding,
        FileError::Unsupported => RegularFileFailure::Unsupported,
        FileError::Indeterminate(operation) => RegularFileFailure::Indeterminate(operation),
        FileError::Unavailable => RegularFileFailure::Unavailable,
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
