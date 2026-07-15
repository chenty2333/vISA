use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use visa_conformance::{
    JointEvidenceBundle, JointEvidenceExpectations,
    gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations,
    seal_joint_evidence_bundle_id, validate_joint_handoff_evidence_bundle,
};

use crate::ProductionReplayReport;

const INCOMPLETE_FILE: &str = "joint-handoff-incomplete";
const PRODUCTION_REPORT_FILE: &str = "production-replay.json";
const EVIDENCE_FILE: &str = "joint-handoff-evidence.json";

pub fn publish(
    root: &Path,
    bundle: &JointEvidenceBundle,
    production: &ProductionReplayReport,
    expectations: &JointEvidenceExpectations,
) -> Result<PathBuf, String> {
    if !production
        .reference_cell
        .as_ref()
        .is_some_and(|report| report.all_passed && report.scenario_count == report.traces.len())
    {
        return Err("reference peer cell is absent or incomplete".to_owned());
    }
    if !production.durable_projection_cell.as_ref().is_some_and(|report| {
        report.schema == "visa.joint-handoff.durable-projection-cell.v2"
            && report.record_count == 3
            && report.recovered_phase == "frozen-unsealed"
            && report.recovered_authentication_count == 2
            && report.abort_probe_authentication_count == 1
            && report.unknown_effect_freeze_retained
            && report.abort_blocked_while_unknown
            && report.pre_reopen == report.post_reopen
            && report.abort_probe.head_before == report.post_reopen.head
            && report.abort_probe.head_after == report.abort_probe.head_before
            && report.execution_observation.close_observed
            && report.execution_observation.reopen_observed
            && report.execution_observation.same_boot_only
    }) {
        return Err("durable SQLite projection cell is absent or incomplete".to_owned());
    }
    if !production.host_substrate_cell.as_ref().is_some_and(|report| {
        report.schema == crate::HOST_SUBSTRATE_CELL_SCHEMA
            && report.authenticated_receipt_count == 9
            && report.joint_phase == "destination-active"
            && report.source_reopened
            && report.source_phase == "committed"
            && report.source_activation == "fenced"
            && report.source_owner_is_destination
            && report.destination_phase == "running"
            && report.destination_activation == "active"
            && report.destination_owner_is_destination
            && report.independent_source_destination_databases
            && report.same_boot_only
            && report.exclusive_trusted_coordinator_api
            && report.authentication_scheme == crate::HOST_SUBSTRATE_AUTHENTICATION_SCHEME
            && report.authentication_key != [0; 32]
            && report.native_receipts.len() == 9
            && report.source_journal.len() == 5
            && report.destination_journal.len() == 4
            && report.source_leases.len() == 2
            && report.destination_leases.len() == 2
    }) {
        return Err("HostSubstrate coordinator cell is absent or incomplete".to_owned());
    }
    if root.exists() {
        return Err(format!("joint artifact root already exists: {}", root.display()));
    }
    fs::create_dir_all(root)
        .map_err(|error| format!("cannot create {}: {error}", root.display()))?;
    write_new(root.join(INCOMPLETE_FILE), b"joint handoff publication incomplete\n")?;
    let production_bytes = json_bytes(production, PRODUCTION_REPORT_FILE)?;
    let mut published_bundle = bundle.clone();
    published_bundle.production_replay_sha256 = Some(sha256_hex(&production_bytes));
    seal_joint_evidence_bundle_id(&mut published_bundle)?;
    let bundle_bytes = json_bytes(&published_bundle, EVIDENCE_FILE)?;
    write_new(root.join(PRODUCTION_REPORT_FILE), &production_bytes)?;
    let bundle_path = root.join(EVIDENCE_FILE);
    write_new(&bundle_path, &bundle_bytes)?;

    let bytes = fs::read(&bundle_path)
        .map_err(|error| format!("cannot read {}: {error}", bundle_path.display()))?;
    let decoded: JointEvidenceBundle = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot decode published bundle: {error}"))?;
    let validation = validate_joint_handoff_evidence_bundle(&decoded);
    if !validation.ok {
        return Err(format!("published bundle failed verification: {:?}", validation.findings));
    }
    fs::remove_file(root.join(INCOMPLETE_FILE))
        .map_err(|error| format!("cannot remove incomplete marker: {error}"))?;
    let gate = gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations(
        &bytes,
        root,
        expectations,
    );
    if !gate.ok {
        let _ = write_new(root.join(INCOMPLETE_FILE), b"joint handoff publication incomplete\n");
        return Err(format!("published artifact root failed verification: {gate:?}"));
    }
    Ok(bundle_path)
}

fn json_bytes(value: &impl Serialize, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("cannot encode {label}: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_new(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), String> {
    let path = path.as_ref();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::Value;
    use visa_conformance::{
        JointEvidenceExpectations, JointEvidenceGateResult, build_reference_joint_evidence_bundle,
        gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations,
        joint_evidence_bundle_id, seal_joint_evidence_bundle_id,
    };

    use super::*;
    use crate::{
        replay_bundle_with_production_reducer, run_coordinator_vertical_cell,
        run_durable_projection_cell, run_reference_peer_cell,
    };

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn reference_cell_semantic_mutations_are_rejected_after_rehash() {
        assert_mutation_rejected(
            "deleted-case",
            |report| {
                reference_traces(report).pop();
            },
            "joint-reference-cell-case-set-mismatch",
        );
        assert_mutation_rejected(
            "renamed-case",
            |report| {
                reference_traces(report)[0]["case_id"] = Value::String("renamed-case".to_owned());
            },
            "joint-reference-cell-case-set-mismatch",
        );
        assert_mutation_rejected(
            "false-terminal",
            |report| {
                let trace = trace_by_id(report, "effect-commit-wins-freeze");
                trace["terminal"] = Value::String("source-thawed".to_owned());
            },
            "joint-reference-cell-terminal-mismatch",
        );
        assert_mutation_rejected(
            "duplicate-log",
            |report| {
                let traces = reference_traces(report);
                let duplicated = traces[0]["ownership_log_id"].clone();
                traces[1]["ownership_log_id"] = duplicated;
            },
            "joint-reference-cell-namespace-alias",
        );
        assert_mutation_rejected(
            "substituted-commit",
            |report| {
                let replacement = event_by_step(
                    trace_by_id(report, "effect-commit-wins-freeze"),
                    "ownership-commit",
                )["receipt"]
                    .clone();
                event_by_step(
                    trace_by_id(report, "commit-ack-lost-query-close"),
                    "ownership-query-after-reopen",
                )["receipt"] = replacement;
            },
            "invalid-joint-reference-cell-receipt",
        );
        assert_mutation_rejected(
            "retained-parent",
            |report| {
                event_by_step(
                    trace_by_id(report, "supplemental-postcommit-retained-tombstone"),
                    "recovery-closure",
                )["receipt"]["header"]["previous_digest"] = Value::Null;
            },
            "invalid-joint-reference-cell-receipt",
        );
        assert_mutation_rejected(
            "registered-effect-identity-substitution",
            |report| {
                let trace = trace_by_id(report, "precommit-abort-preserves-uncommitted-effect");
                let replacement = event_by_step(trace, "registered-effect-before-freeze")
                    ["effect_record"]["domain"]
                    .clone();
                event_by_step(trace, "registered-effect-committed-after-thaw")["effect_record"]["effect"] =
                    replacement;
            },
            "invalid-joint-reference-cell-effect-transition",
        );
        assert_mutation_rejected(
            "durable-unknown-cleared",
            |report| {
                report["durable_projection_cell"]["unknown_effect_freeze_retained"] =
                    Value::Bool(false);
            },
            "invalid-joint-durable-projection-cell",
        );
        assert_mutation_rejected(
            "durable-projection-record-byte",
            |report| {
                let record =
                    report["durable_projection_cell"]["pre_reopen"]["canonical_record_bytes"][0]
                        .as_array_mut()
                        .unwrap();
                let byte = record[0].as_u64().unwrap();
                record[0] = Value::from(byte ^ 1);
            },
            "invalid-joint-durable-projection-cell",
        );
        assert_mutation_rejected(
            "durable-abort-probe-payload-byte",
            |report| {
                let payload = report["durable_projection_cell"]["abort_probe"]["payload_bytes"]
                    .as_array_mut()
                    .unwrap();
                let byte = payload[0].as_u64().unwrap();
                payload[0] = Value::from(byte ^ 1);
            },
            "invalid-joint-durable-projection-cell",
        );
        assert_mutation_rejected(
            "durable-abort-probe-request-byte",
            |report| {
                let request = report["durable_projection_cell"]["abort_probe"]["request_bytes"]
                    .as_array_mut()
                    .unwrap();
                let byte = request[0].as_u64().unwrap();
                request[0] = Value::from(byte ^ 1);
            },
            "invalid-joint-durable-projection-cell",
        );
        assert_mutation_rejected(
            "host-ownership-commit-raw-payload",
            |report| {
                let payload = report["host_substrate_cell"]["native_receipts"][5]["payload"]
                    .as_array_mut()
                    .unwrap();
                let byte = payload[0].as_u64().unwrap();
                payload[0] = Value::from(byte ^ 1);
            },
            "invalid-joint-host-substrate-cell",
        );
        assert_mutation_rejected(
            "host-typed-request-byte",
            |report| {
                let request =
                    report["host_substrate_cell"]["native_receipts"][5]["issuance_request"]
                        .as_array_mut()
                        .unwrap();
                let byte = request[0].as_u64().unwrap();
                request[0] = Value::from(byte ^ 1);
            },
            "invalid-joint-host-substrate-cell",
        );
        assert_mutation_rejected(
            "host-peer-invocation-byte",
            |report| {
                let invocation =
                    report["host_substrate_cell"]["native_receipts"][5]["peer_invocation"]
                        .as_array_mut()
                        .unwrap();
                let byte = invocation[0].as_u64().unwrap();
                invocation[0] = Value::from(byte ^ 1);
            },
            "invalid-joint-host-substrate-cell",
        );
        assert_mutation_rejected(
            "host-abort-issuer-alias",
            |report| {
                let source = report["host_substrate_cell"]["durable_projection"]["source_abort"]
                    ["issuer_set"]["visa_source"]
                    .clone();
                report["host_substrate_cell"]["durable_projection"]["source_abort"]["issuer_set"]
                    ["visa_destination"] = source;
            },
            "invalid-joint-host-substrate-cell",
        );
        assert_mutation_rejected(
            "host-abort-observation-record-byte",
            |report| {
                let record = report["host_substrate_cell"]["durable_projection"]["source_abort"]
                    ["transcript"]["canonical_record_bytes"][7]
                    .as_array_mut()
                    .unwrap();
                let byte = record[0].as_u64().unwrap();
                record[0] = Value::from(byte ^ 1);
            },
            "invalid-joint-host-substrate-cell",
        );
        assert_mutation_rejected(
            "host-source-fence-lost-ack-claim",
            |report| {
                report["host_substrate_cell"]["durable_projection"]["source_fence"]["completion_append_ack_lost"] =
                    Value::Bool(false);
            },
            "invalid-joint-host-substrate-cell",
        );
        assert_mutation_rejected(
            "host-destination-exposure-opened-early",
            |report| {
                report["host_substrate_cell"]["durable_projection"]["destination_activation"]["exposure_blocked_before_completion"] =
                    Value::Bool(false);
            },
            "invalid-joint-host-substrate-cell",
        );
        assert_mutation_rejected(
            "host-source-fence-head-substitution",
            |report| {
                let attempt = report["host_substrate_cell"]["durable_projection"]["source_fence"]
                    ["attempt_head"]
                    .clone();
                report["host_substrate_cell"]["durable_projection"]["source_fence"]["completion_head"] =
                    attempt;
            },
            "invalid-joint-host-substrate-cell",
        );
        assert_mutation_rejected(
            "host-destination-terminal",
            |report| {
                report["host_substrate_cell"]["destination_phase"] =
                    Value::String("committed".to_owned());
            },
            "invalid-joint-host-substrate-cell",
        );
    }

    #[test]
    fn sealed_bundle_still_requires_all_external_expectations() {
        let root = publish_reference_artifact("provenance-expectations");
        let bundle_bytes = fs::read(root.join(EVIDENCE_FILE)).unwrap();
        let bundle: JointEvidenceBundle = serde_json::from_slice(&bundle_bytes).unwrap();
        assert_eq!(bundle.bundle_id, joint_evidence_bundle_id(&bundle).unwrap());
        let expected = test_expectations();
        let gate = gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations(
            &bundle_bytes,
            &root,
            &expected,
        );
        assert!(gate.ok, "published fixture failed its exact expectations: {gate:#?}");

        let mut mismatches = Vec::new();
        let mut value = expected.clone();
        value.visa_git_sha = "9".repeat(40);
        mismatches.push(("visa revision", value));
        let mut value = expected.clone();
        value.nexus_git_sha = "9".repeat(40);
        mismatches.push(("Nexus revision", value));
        let mut value = expected.clone();
        value.neutral_git_sha = "9".repeat(40);
        mismatches.push(("neutral revision", value));
        let mut value = expected.clone();
        value.neutral_tree = "b".repeat(40);
        mismatches.push(("neutral tree", value));
        let mut value = expected.clone();
        value.neutral_bundle_sha256 = "9".repeat(64);
        mismatches.push(("neutral bundle", value));
        let mut value = expected.clone();
        value.source_lock_sha256 = "9".repeat(64);
        mismatches.push(("source lock", value));
        let mut value = expected.clone();
        value.protocol_schema_sha256 = "9".repeat(64);
        mismatches.push(("protocol schema", value));
        let mut value = expected.clone();
        value.machine_contract_sha256 = "9".repeat(64);
        mismatches.push(("machine contract", value));
        let mut value = expected.clone();
        value.refinement_map_sha256 = "9".repeat(64);
        mismatches.push(("refinement map", value));
        let mut value = expected;
        value.abstract_registry_sha256 = "9".repeat(64);
        mismatches.push(("abstract registry", value));

        for (label, mismatch) in mismatches {
            let gate = gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations(
                &bundle_bytes,
                &root,
                &mismatch,
            );
            assert!(!gate.ok, "{label} mismatch unexpectedly passed");
            assert!(
                gate_has_code(&gate, "joint-evidence-expectation-mismatch"),
                "{label} mismatch did not emit the expectation finding: {gate:#?}",
            );
        }

        let mut substituted = bundle;
        substituted.neutral.git_sha = "9".repeat(40);
        seal_joint_evidence_bundle_id(&mut substituted).unwrap();
        let substituted_bytes = json_bytes(&substituted, EVIDENCE_FILE).unwrap();
        fs::write(root.join(EVIDENCE_FILE), &substituted_bytes).unwrap();
        let gate = gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations(
            &substituted_bytes,
            &root,
            &test_expectations(),
        );
        assert!(!gate.ok);
        assert!(gate_has_code(&gate, "joint-evidence-expectation-mismatch"));
        assert!(!gate_has_code(&gate, "invalid-joint-bundle-id"));
        fs::remove_dir_all(root).unwrap();
    }

    fn assert_mutation_rejected(label: &str, mutate: impl FnOnce(&mut Value), expected_code: &str) {
        let root = publish_reference_artifact(label);
        let mut report: Value =
            serde_json::from_slice(&fs::read(root.join(PRODUCTION_REPORT_FILE)).unwrap()).unwrap();
        mutate(&mut report);
        let report_bytes = json_bytes(&report, PRODUCTION_REPORT_FILE).unwrap();
        fs::write(root.join(PRODUCTION_REPORT_FILE), &report_bytes).unwrap();

        let mut bundle: JointEvidenceBundle =
            serde_json::from_slice(&fs::read(root.join(EVIDENCE_FILE)).unwrap()).unwrap();
        bundle.production_replay_sha256 = Some(sha256_hex(&report_bytes));
        seal_joint_evidence_bundle_id(&mut bundle).unwrap();
        let bundle_bytes = json_bytes(&bundle, EVIDENCE_FILE).unwrap();
        fs::write(root.join(EVIDENCE_FILE), &bundle_bytes).unwrap();

        let gate = gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations(
            &bundle_bytes,
            &root,
            &test_expectations(),
        );
        assert!(!gate.ok, "{label} mutation unexpectedly passed");
        assert!(
            gate_has_code(&gate, expected_code),
            "{label} did not emit {expected_code}: {gate:#?}"
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn publish_reference_artifact(label: &str) -> PathBuf {
        let expectations = test_expectations();
        let bundle = build_reference_joint_evidence_bundle(&expectations).unwrap();
        let mut production = replay_bundle_with_production_reducer(&bundle).unwrap();
        production.reference_cell = Some(run_reference_peer_cell().unwrap());
        let durable_path = std::env::temp_dir().join(format!(
            "visa-joint-artifact-durable-{label}-{}-{}.sqlite3",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        super::super::remove_sqlite_files(&durable_path);
        production.durable_projection_cell =
            Some(run_durable_projection_cell(&durable_path).unwrap());
        super::super::remove_sqlite_files(&durable_path);
        production.host_substrate_cell = Some(run_coordinator_vertical_cell().unwrap());
        let root = std::env::temp_dir().join(format!(
            "visa-joint-artifact-mutation-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        publish(&root, &bundle, &production, &expectations).unwrap();
        root
    }

    fn test_expectations() -> JointEvidenceExpectations {
        JointEvidenceExpectations {
            visa_git_sha: "1".repeat(40),
            nexus_git_sha: "2".repeat(40),
            neutral_git_sha: "3".repeat(40),
            neutral_tree: "9".repeat(40),
            neutral_bundle_sha256: "a".repeat(64),
            source_lock_sha256: "4".repeat(64),
            protocol_schema_sha256: "5".repeat(64),
            machine_contract_sha256: "6".repeat(64),
            refinement_map_sha256: "7".repeat(64),
            abstract_registry_sha256: "8".repeat(64),
        }
    }

    fn reference_traces(report: &mut Value) -> &mut Vec<Value> {
        report["reference_cell"]["traces"].as_array_mut().unwrap()
    }

    fn trace_by_id<'a>(report: &'a mut Value, case_id: &str) -> &'a mut Value {
        reference_traces(report).iter_mut().find(|trace| trace["case_id"] == case_id).unwrap()
    }

    fn event_by_step<'a>(trace: &'a mut Value, step: &str) -> &'a mut Value {
        trace["events"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|event| event["step"] == step)
            .unwrap()
    }

    fn gate_has_code(gate: &JointEvidenceGateResult, code: &str) -> bool {
        gate.validation
            .as_ref()
            .is_some_and(|validation| validation.findings.iter().any(|item| item.code == code))
    }
}
