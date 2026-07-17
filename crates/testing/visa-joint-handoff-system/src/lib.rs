mod admission_component;
mod artifact;
mod coordinator_cell;
mod durable_cell;
mod effects;
mod fault_projection_log;
mod logical_request_admission_cell;
mod logical_request_admission_verify;
mod logical_request_cell;
mod nexus_effect_wire;
mod nexus_process_cell;
mod ownership;
mod process_effect_peer;
mod projection_log;
mod reference_cell;
mod reference_cell_extra;
mod replay;

#[cfg(test)]
mod effect_tests;
#[cfg(test)]
mod ownership_tests;
#[cfg(test)]
mod provider_conformance;

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub use coordinator_cell::*;
pub use durable_cell::*;
pub use effects::*;
pub use fault_projection_log::*;
pub use logical_request_admission_cell::*;
pub use logical_request_admission_verify::*;
pub use logical_request_cell::*;
pub use nexus_process_cell::*;
pub use ownership::*;
pub use process_effect_peer::*;
pub use projection_log::*;
pub use reference_cell::*;
pub use replay::{ProductionReplayReport, replay_bundle_with_production_reducer};
use visa_conformance::{
    JointEvidenceExpectations, build_reference_joint_evidence_bundle,
    validate_joint_handoff_evidence_bundle,
};

static NEXT_DURABLE_CELL: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JointRunInputs {
    pub visa_sha: String,
    pub nexus_sha: String,
    pub neutral_sha: String,
    pub neutral_tree: String,
    pub neutral_bundle_sha256: String,
    pub source_lock_sha256: String,
    pub protocol_schema_sha256: String,
    pub machine_contract_sha256: String,
    pub refinement_map_sha256: String,
    pub abstract_registry_sha256: String,
}

impl JointRunInputs {
    pub fn expectations(&self) -> JointEvidenceExpectations {
        JointEvidenceExpectations {
            visa_git_sha: self.visa_sha.clone(),
            nexus_git_sha: self.nexus_sha.clone(),
            neutral_git_sha: self.neutral_sha.clone(),
            neutral_tree: self.neutral_tree.clone(),
            neutral_bundle_sha256: self.neutral_bundle_sha256.clone(),
            source_lock_sha256: self.source_lock_sha256.clone(),
            protocol_schema_sha256: self.protocol_schema_sha256.clone(),
            machine_contract_sha256: self.machine_contract_sha256.clone(),
            refinement_map_sha256: self.refinement_map_sha256.clone(),
            abstract_registry_sha256: self.abstract_registry_sha256.clone(),
        }
    }
}

pub fn run_joint_handoff_reference(
    root: impl AsRef<Path>,
    inputs: &JointRunInputs,
) -> Result<PathBuf, String> {
    validate_inputs(inputs)?;
    let expectations = inputs.expectations();
    let bundle = build_reference_joint_evidence_bundle(&expectations)?;

    let mut production = replay_bundle_with_production_reducer(&bundle)?;
    if production.case_count != visa_conformance::JOINT_HANDOFF_CASE_COUNT
        || !production.all_matched
    {
        return Err("production joint reducer did not match the fixed trace registry".to_owned());
    }
    let reference_cell = run_reference_peer_cell()?;
    if !reference_cell.all_passed {
        return Err("reference ownership/effect peer cell did not close".to_owned());
    }
    production.reference_cell = Some(reference_cell);
    let durable_path = std::env::temp_dir().join(format!(
        "visa-joint-durable-run-{}-{}.sqlite3",
        std::process::id(),
        NEXT_DURABLE_CELL.fetch_add(1, Ordering::Relaxed)
    ));
    remove_sqlite_files(&durable_path);
    let durable_projection = run_durable_projection_cell(&durable_path);
    remove_sqlite_files(&durable_path);
    production.durable_projection_cell = Some(durable_projection?);
    production.host_substrate_cell = Some(run_coordinator_vertical_cell()?);
    let validation = validate_joint_handoff_evidence_bundle(&bundle);
    if !validation.ok {
        return Err(format!(
            "independent joint verifier rejected publisher output: {:?}",
            validation.findings
        ));
    }
    artifact::publish(root.as_ref(), &bundle, &production, &expectations)
}

fn remove_sqlite_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}

fn validate_inputs(inputs: &JointRunInputs) -> Result<(), String> {
    for (label, value) in [
        ("vISA", &inputs.visa_sha),
        ("Nexus", &inputs.nexus_sha),
        ("neutral artifact", &inputs.neutral_sha),
    ] {
        if value.len() != 40
            || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!("{label} revision is not an exact lowercase 40-hex Git SHA"));
        }
    }
    if inputs.neutral_tree.len() != 40
        || !inputs
            .neutral_tree
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("neutral tree is not an exact lowercase 40-hex Git object ID".to_owned());
    }
    for (label, value) in [
        ("neutral Git bundle", &inputs.neutral_bundle_sha256),
        ("source lock", &inputs.source_lock_sha256),
        ("protocol Markdown", &inputs.protocol_schema_sha256),
        ("machine TOML", &inputs.machine_contract_sha256),
        ("refinement map", &inputs.refinement_map_sha256),
        ("abstract registry", &inputs.abstract_registry_sha256),
    ] {
        if value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!("{label} identity is not lowercase SHA-256"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn inputs() -> JointRunInputs {
        JointRunInputs {
            visa_sha: "1111111111111111111111111111111111111111".to_owned(),
            nexus_sha: "2222222222222222222222222222222222222222".to_owned(),
            neutral_sha: "3333333333333333333333333333333333333333".to_owned(),
            neutral_tree: "9999999999999999999999999999999999999999".to_owned(),
            neutral_bundle_sha256:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            source_lock_sha256: "4444444444444444444444444444444444444444444444444444444444444444"
                .to_owned(),
            protocol_schema_sha256:
                "5555555555555555555555555555555555555555555555555555555555555555".to_owned(),
            machine_contract_sha256:
                "6666666666666666666666666666666666666666666666666666666666666666".to_owned(),
            refinement_map_sha256:
                "7777777777777777777777777777777777777777777777777777777777777777".to_owned(),
            abstract_registry_sha256:
                "8888888888888888888888888888888888888888888888888888888888888888".to_owned(),
        }
    }

    #[test]
    fn reference_run_publishes_only_after_both_reducers_accept() {
        let root =
            std::env::temp_dir().join(format!("visa-joint-reference-{}-{}", std::process::id(), 1));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        let bundle = run_joint_handoff_reference(&root, &inputs()).unwrap();
        assert_eq!(bundle, root.join("joint-handoff-evidence.json"));
        assert!(!root.join("joint-handoff-incomplete").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reference_run_rejects_symbolic_or_moving_revisions() {
        let mut invalid = inputs();
        invalid.nexus_sha = "main".to_owned();
        assert!(validate_inputs(&invalid).is_err());
    }

    #[test]
    fn reference_peer_cell_executes_real_ownership_and_effect_boundaries() {
        let report = run_reference_peer_cell().unwrap();
        assert!(report.all_passed);
        assert!(report.ownership_effect_peers_observed);
        assert!(!report.runtime_projection_observed);
        assert_eq!(report.fixed_case_count, visa_conformance::JOINT_HANDOFF_CASE_COUNT);
        assert_eq!(report.scenario_count, report.fixed_case_count + 1);
        assert_eq!(report.traces.len(), report.scenario_count);
        assert!(report.traces.iter().all(|trace| {
            trace.terminal != "incomplete"
                && trace.events.iter().any(|event| event.receipt.is_some())
        }));
    }
}
