//! Local, non-authoritative vISA controller operations.

mod cohort;

use std::{ffi::OsString, fmt};

pub use cohort::{CohortManager, CohortPlan, CohortRoots};

/// Stable command exit classes. They intentionally match the operational
/// classes used by the long-lived vISA services.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitClass {
    Usage = 64,
    Data = 65,
    Software = 70,
    Temporary = 75,
    Configuration = 78,
}

impl ExitClass {
    pub const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Debug)]
pub enum CliError {
    Usage(String),
    Data(String),
    Configuration(String),
    Conflict(String),
    Integrity(String),
    Temporary(String),
    Unsupported(String),
}

impl CliError {
    pub const fn exit_class(&self) -> ExitClass {
        match self {
            Self::Usage(_) | Self::Unsupported(_) => ExitClass::Usage,
            Self::Data(_) => ExitClass::Data,
            Self::Configuration(_) | Self::Conflict(_) => ExitClass::Configuration,
            Self::Integrity(_) => ExitClass::Software,
            Self::Temporary(_) => ExitClass::Temporary,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message)
            | Self::Data(message)
            | Self::Configuration(message)
            | Self::Conflict(message)
            | Self::Integrity(message)
            | Self::Temporary(message)
            | Self::Unsupported(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for CliError {}

/// Parse and execute the currently implemented local command surface.
///
/// The returned plan is useful to an embedding activation layer. The binary
/// entry point intentionally discards it because `StartUnit` is not part of
/// this slice yet.
pub fn run<I>(arguments: I) -> Result<CohortPlan, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let command = arguments.next().ok_or_else(|| {
        CliError::Usage("usage: visa cohort-create --cohort-id <32-lowercase-hex>".to_owned())
    })?;
    if command != "cohort-create" {
        return Err(CliError::Unsupported(format!(
            "unsupported command {:?}; only cohort-create is implemented in this slice",
            command
        )));
    }

    let flag = arguments.next().ok_or_else(|| {
        CliError::Usage("usage: visa cohort-create --cohort-id <32-lowercase-hex>".to_owned())
    })?;
    if flag != "--cohort-id" {
        return Err(CliError::Usage(
            "cohort-create requires --cohort-id <32-lowercase-hex>".to_owned(),
        ));
    }
    let value = arguments
        .next()
        .ok_or_else(|| CliError::Usage("cohort-create requires a cohort id".to_owned()))?;
    if arguments.next().is_some() {
        return Err(CliError::Usage("unexpected cohort-create argument".to_owned()));
    }
    let cohort_id = cohort::parse_cohort_id(&value).map_err(CliError::Data)?;
    CohortManager::from_environment()?.create(cohort_id)
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, fs, os::unix::fs::PermissionsExt};

    use tempfile::tempdir;
    use visa_agent_store::AgentStore;
    use visa_local_rpc::common::{BootId, CohortId, RuntimeSessionId};

    use super::*;

    #[test]
    fn command_parser_rejects_unsupported_or_malformed_input() {
        let missing = run([OsString::from("visa")]).expect_err("missing command");
        assert_eq!(missing.exit_class(), ExitClass::Usage);
        let unsupported = run([OsString::from("visa"), OsString::from("status")])
            .expect_err("unsupported command");
        assert_eq!(unsupported.exit_class(), ExitClass::Usage);
        let malformed = run([
            OsString::from("visa"),
            OsString::from("cohort-create"),
            OsString::from("--cohort-id"),
            OsString::from("ABC"),
        ])
        .expect_err("invalid cohort");
        assert_eq!(malformed.exit_class(), ExitClass::Data);
    }

    #[test]
    fn exact_cohort_create_is_idempotent_and_preserves_role_identities() {
        let runtime = tempdir().expect("runtime root");
        let state = tempdir().expect("state root");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).expect("state mode");
        let roots = CohortRoots::new(runtime.path().to_path_buf(), state.path().to_path_buf())
            .expect("roots");
        let manager =
            CohortManager::new(roots, BootId::from_u128(0x11), RuntimeSessionId::from_u128(0x22))
                .expect("manager");
        let cohort = CohortId::from_u128(0x33);

        let first = manager.create(cohort).expect("first create");
        let second = manager.create(cohort).expect("exact retry");
        assert_eq!(first.manifest_path, second.manifest_path);
        assert_eq!(first.source_identity, second.source_identity);
        assert_eq!(first.destination_identity, second.destination_identity);
        assert!(first.activation_pending);

        let source_store = first.state_path.join("source-agent.sqlite");
        let destination_store = first.state_path.join("destination-agent.sqlite");
        assert!(source_store.is_file());
        assert!(destination_store.is_file());
        assert!(first.active_manifest_path.is_file());
    }

    #[test]
    fn different_active_cohort_is_a_conflict_before_role_store_creation() {
        let runtime = tempdir().expect("runtime root");
        let state = tempdir().expect("state root");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).expect("state mode");
        let roots = CohortRoots::new(runtime.path().to_path_buf(), state.path().to_path_buf())
            .expect("roots");
        let manager =
            CohortManager::new(roots, BootId::from_u128(0x101), RuntimeSessionId::from_u128(0x202))
                .expect("manager");

        let first = manager.create(CohortId::from_u128(0x303)).expect("first create");
        let second = manager
            .create(CohortId::from_u128(0x404))
            .expect_err("different active cohort must conflict");
        assert_eq!(second.exit_class(), ExitClass::Configuration);
        assert!(!second.to_string().is_empty());
        assert!(
            !first
                .state_path
                .parent()
                .expect("cohort parent")
                .join("00000000000000000000000000000404/source-agent.sqlite")
                .exists()
        );
    }

    #[test]
    fn initialized_role_store_loss_is_not_recreated() {
        let runtime = tempdir().expect("runtime root");
        let state = tempdir().expect("state root");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).expect("state mode");
        let roots = CohortRoots::new(runtime.path().to_path_buf(), state.path().to_path_buf())
            .expect("roots");
        let manager =
            CohortManager::new(roots, BootId::from_u128(0x505), RuntimeSessionId::from_u128(0x606))
                .expect("manager");
        let plan = manager.create(CohortId::from_u128(0x707)).expect("first create");
        let source = plan.state_path.join("source-agent.sqlite");
        fs::remove_file(&source).expect("remove source store");

        let error = manager.create(plan.cohort_id).expect_err("state loss must conflict");
        assert_eq!(error.exit_class(), ExitClass::Configuration);
        assert!(!source.exists());
    }

    #[test]
    fn missing_state_root_is_created_during_create_after_root_validation() {
        let runtime = tempdir().expect("runtime root");
        let state_parent = tempdir().expect("state parent");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        fs::set_permissions(state_parent.path(), fs::Permissions::from_mode(0o700))
            .expect("state parent mode");
        let state = state_parent.path().join("new-state");
        let roots = CohortRoots::new(runtime.path().to_path_buf(), state.clone()).expect("roots");
        assert!(!state.exists());
        let manager =
            CohortManager::new(roots, BootId::from_u128(0x808), RuntimeSessionId::from_u128(0x909))
                .expect("manager");
        manager.create(CohortId::from_u128(0xa0a)).expect("create");
        assert!(state.join("visa/0.1/runtime-does-not-exist").parent().unwrap().exists());
    }

    #[cfg(unix)]
    #[test]
    fn active_manifest_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let runtime = tempdir().expect("runtime root");
        let state = tempdir().expect("state root");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).expect("state mode");
        let roots = CohortRoots::new(runtime.path().to_path_buf(), state.path().to_path_buf())
            .expect("roots");
        let manager =
            CohortManager::new(roots, BootId::from_u128(0xb0b), RuntimeSessionId::from_u128(0xc0c))
                .expect("manager");
        let runtime_base = runtime.path().join("visa/0.1");
        fs::create_dir_all(&runtime_base).expect("runtime base");
        fs::set_permissions(&runtime_base, fs::Permissions::from_mode(0o700))
            .expect("runtime base mode");
        let target = runtime.path().join("target");
        fs::write(&target, b"not-json").expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
        symlink(&target, runtime_base.join("active-cohort.json")).expect("active symlink");

        let error =
            manager.create(CohortId::from_u128(0xd0d)).expect_err("symlink must be rejected");
        assert_eq!(error.exit_class(), ExitClass::Configuration);
    }

    #[test]
    fn runtime_session_loss_with_retained_state_is_audit_only() {
        let runtime = tempdir().expect("runtime root");
        let state = tempdir().expect("state root");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).expect("state mode");
        let roots = CohortRoots::new(runtime.path().to_path_buf(), state.path().to_path_buf())
            .expect("roots");
        let manager =
            CohortManager::new(roots, BootId::from_u128(0xe0e), RuntimeSessionId::from_u128(0xf0f))
                .expect("manager");
        let plan = manager.create(CohortId::from_u128(0x111)).expect("first create");
        fs::remove_file(runtime.path().join("visa/0.1/runtime-session.json"))
            .expect("remove runtime session");
        fs::remove_file(runtime.path().join("visa/0.1/active-cohort.json"))
            .expect("remove active manifest");

        let error = manager.create(plan.cohort_id).expect_err("runtime loss must fail closed");
        assert_eq!(error.exit_class(), ExitClass::Configuration);
        assert!(!runtime.path().join("visa/0.1/runtime-session.json").exists());
    }

    #[test]
    fn missing_persistent_manifest_with_role_store_is_not_relabelled() {
        let runtime = tempdir().expect("runtime root");
        let state = tempdir().expect("state root");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).expect("state mode");
        let roots = CohortRoots::new(runtime.path().to_path_buf(), state.path().to_path_buf())
            .expect("roots");
        let manager =
            CohortManager::new(roots, BootId::from_u128(0x121), RuntimeSessionId::from_u128(0x131))
                .expect("manager");
        let plan = manager.create(CohortId::from_u128(0x141)).expect("first create");
        fs::remove_file(&plan.manifest_path).expect("remove persistent manifest");
        fs::remove_file(&plan.active_manifest_path).expect("remove active manifest");

        let error = manager.create(plan.cohort_id).expect_err("missing manifest must conflict");
        assert_eq!(error.exit_class(), ExitClass::Configuration);
        assert!(!plan.manifest_path.exists());
    }

    #[test]
    fn active_manifest_missing_both_role_store_files_is_not_recreated() {
        let runtime = tempdir().expect("runtime root");
        let state = tempdir().expect("state root");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).expect("state mode");
        let roots = CohortRoots::new(runtime.path().to_path_buf(), state.path().to_path_buf())
            .expect("roots");
        let manager =
            CohortManager::new(roots, BootId::from_u128(0x151), RuntimeSessionId::from_u128(0x161))
                .expect("manager");
        let plan = manager.create(CohortId::from_u128(0x171)).expect("first create");
        fs::remove_file(plan.state_path.join("source-agent.sqlite")).expect("remove source");
        fs::remove_file(plan.state_path.join("source-agent.initialized"))
            .expect("remove source marker");

        let error = manager.create(plan.cohort_id).expect_err("active loss must conflict");
        assert_eq!(error.exit_class(), ExitClass::Configuration);
        assert!(!plan.state_path.join("source-agent.sqlite").exists());
    }

    #[test]
    fn exact_retry_can_audit_a_live_role_without_taking_its_process_lock() {
        let runtime = tempdir().expect("runtime root");
        let state = tempdir().expect("state root");
        fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).expect("state mode");
        let roots = CohortRoots::new(runtime.path().to_path_buf(), state.path().to_path_buf())
            .expect("roots");
        let manager =
            CohortManager::new(roots, BootId::from_u128(0x181), RuntimeSessionId::from_u128(0x191))
                .expect("manager");
        let first = manager.create(CohortId::from_u128(0x1a1)).expect("first create");
        let live = AgentStore::reopen_existing(
            first.state_path.join("source-agent.sqlite"),
            first.source_identity,
            visa_local_rpc::common::ProcessNonce::from_u128(0x1b1),
        )
        .expect("live source");
        let second = manager.create(first.cohort_id).expect("exact retry");
        assert_eq!(second.source_identity, first.source_identity);
        drop(live);
    }

    #[test]
    fn relative_roots_are_rejected_before_any_mutation() {
        let error = CohortRoots::new("runtime".into(), "state".into()).expect_err("relative roots");
        assert!(error.contains("absolute normalized"));
    }
}
