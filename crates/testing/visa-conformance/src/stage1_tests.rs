use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::stage1::*;

#[test]
fn stage1_case_registry_matches_the_complete_validation_matrix() {
    let expected = [
        "timer-positive-duration-at-freeze",
        "timer-paused-during-long-handoff",
        "timer-completes-during-quiescence",
        "timer-cancelled-during-quiescence",
        "authority-sufficient-narrower",
        "kv-duplicate-idempotent-request",
        "handoff-repeated-validation-prepare",
        "journal-replay",
        "source-post-commit-stale-attempt",
        "evidence-verification",
        "performance-observations",
        "safe-point-unreachable",
        "unsupported-live-resource-or-borrow",
        "kv-unknown-outcome",
        "corrupt-snapshot-or-component-digest",
        "incompatible-snapshot-or-profile-version",
        "unknown-extension-or-profile-mismatch",
        "destination-authority-missing-or-insufficient",
        "required-capability-revoked",
        "adapter-broader-authority",
        "kv-binding-wrong-or-missing",
        "timer-semantics-unsupported",
        "destination-crash-before-commit",
        "prepare-message-duplicate-or-lost",
        "commit-acknowledgement-lost",
        "source-races-with-commit",
        "destination-crash-after-commit",
        "duplicate-restore-or-stale-snapshot",
        "repeated-cancel-abort-cleanup",
        "durable-journal-or-commit-write-fails",
        "report-generation-fails-after-commit",
    ];

    assert_eq!(required_stage1_case_ids().collect::<Vec<_>>(), expected);
    assert_eq!(STAGE1_CASE_DEFINITIONS.len(), 31);
    assert_eq!(
        stage1_case_definition("kv-unknown-outcome").unwrap().allowed_outcomes,
        &[Stage1CaseOutcome::UnknownKvReconciled, Stage1CaseOutcome::UnknownKvBlockedIndeterminate]
    );
}

#[test]
fn complete_execution_bundle_passes_structural_validation_and_json_gate() {
    let bundle = complete_bundle();

    let validation = validate_stage1_evidence_bundle(&bundle);
    assert!(validation.ok, "{:#?}", validation.findings);

    let json = serde_json::to_vec(&bundle).unwrap();
    let parsed = parse_stage1_evidence_bundle_json(&json).unwrap();
    assert_eq!(parsed, bundle);
    let gate = gate_stage1_evidence_bundle_json(&json);
    assert!(gate.ok, "{gate:#?}");
}

#[test]
fn validator_rejects_missing_independent_dimensions() {
    let mut missing_carrier = complete_bundle();
    missing_carrier.environment.carrier.name.clear();
    assert_code(
        &validate_stage1_evidence_bundle(&missing_carrier),
        "missing-stage1-environment-dimension",
    );

    let mut missing_runtime_version = complete_bundle();
    missing_runtime_version.environment.destination_runtime.version.clear();
    assert_code(
        &validate_stage1_evidence_bundle(&missing_runtime_version),
        "missing-stage1-environment-dimension",
    );

    let mut missing_isa = complete_bundle();
    missing_isa.environment.source_isa.architecture.clear();
    assert_code(
        &validate_stage1_evidence_bundle(&missing_isa),
        "missing-stage1-environment-dimension",
    );

    let mut missing_provider = complete_bundle();
    missing_provider.environment.provider.implementation.name.clear();
    assert_code(
        &validate_stage1_evidence_bundle(&missing_provider),
        "missing-stage1-environment-dimension",
    );

    let mut missing_resource_profile = complete_bundle();
    missing_resource_profile
        .environment
        .resource_profiles
        .retain(|profile| profile.resource != Stage1ResourceKind::DurableKeyValue);
    assert_code(
        &validate_stage1_evidence_bundle(&missing_resource_profile),
        "missing-stage1-resource-profile",
    );

    let mut missing_provenance = complete_bundle();
    missing_provenance.provenance.toolchain_sha256.clear();
    assert_code(&validate_stage1_evidence_bundle(&missing_provenance), "invalid-stage1-digest");

    let mut missing_raw_observation = complete_bundle();
    missing_raw_observation.performance_observations.pop();
    assert_code(
        &validate_stage1_evidence_bundle(&missing_raw_observation),
        "missing-stage1-performance-observation",
    );
}

#[test]
fn validator_rejects_non_durable_or_mock_provider_evidence() {
    let mut bundle = complete_bundle();
    bundle.environment.provider.durable = false;
    bundle.environment.provider.mock = true;

    let validation = validate_stage1_evidence_bundle(&bundle);
    assert_code(&validation, "non-durable-stage1-provider");
    assert_code(&validation, "mock-stage1-provider");
}

#[test]
fn validator_rejects_missing_duplicate_and_unknown_cases() {
    let mut missing = complete_bundle();
    missing.cases.retain(|case| case.case_id != "journal-replay");
    assert_code(&validate_stage1_evidence_bundle(&missing), "missing-stage1-case");

    let mut duplicate = complete_bundle();
    duplicate.cases.push(duplicate.cases[0].clone());
    assert_code(&validate_stage1_evidence_bundle(&duplicate), "duplicate-stage1-case");

    let mut unknown = complete_bundle();
    unknown.cases[0].case_id = "not-in-the-stage1-matrix".to_string();
    assert_code(&validate_stage1_evidence_bundle(&unknown), "unknown-stage1-case");
}

#[test]
fn validator_rejects_digest_and_identity_disagreement() {
    let mut replay_mismatch = complete_bundle();
    replay_mismatch.cases[0].state.replay_state_sha256 = digest('a');
    assert_code(
        &validate_stage1_evidence_bundle(&replay_mismatch),
        "inconsistent-stage1-state-replay-digest",
    );

    let mut snapshot_mismatch = complete_bundle();
    snapshot_mismatch.cases[0].state.snapshot_sha256 = Some(digest('a'));
    assert_code(
        &validate_stage1_evidence_bundle(&snapshot_mismatch),
        "inconsistent-stage1-snapshot-digest",
    );

    let mut identity_mismatch = complete_bundle();
    identity_mismatch.cases[0].artifacts.semantic_traces[0].execution_id = "other-run".to_string();
    assert_code(
        &validate_stage1_evidence_bundle(&identity_mismatch),
        "inconsistent-stage1-artifact-identity",
    );
}

#[test]
fn validator_rejects_wrong_failure_outcome_and_authority_state() {
    let mut wrong_outcome = complete_bundle();
    let case = wrong_outcome
        .cases
        .iter_mut()
        .find(|case| case.case_id == "safe-point-unreachable")
        .unwrap();
    case.outcome = Stage1CaseOutcome::TimerRecreatedSingleExpiry;
    assert_code(&validate_stage1_evidence_bundle(&wrong_outcome), "incorrect-stage1-case-outcome");

    let mut wrong_epoch = complete_bundle();
    wrong_epoch.cases[0].authority.fencing_epoch = 99;
    assert_code(
        &validate_stage1_evidence_bundle(&wrong_epoch),
        "inconsistent-stage1-ownership-evidence",
    );
}

#[test]
fn validator_rejects_fixture_masquerade_and_stage1_overclaims() {
    let mut fixture = complete_bundle();
    fixture.evidence_kind = Stage1EvidenceKind::Fixture;
    assert_code(&validate_stage1_evidence_bundle(&fixture), "fixture-not-execution-evidence");

    let mut overclaim = complete_bundle();
    overclaim.claims.push(Stage1Claim::CrossRuntimePortability);
    assert_code(&validate_stage1_evidence_bundle(&overclaim), "stage1-overclaim");
}

#[test]
fn artifact_gate_reads_every_referenced_file_and_checks_its_digest() {
    let root = temp_dir("valid-artifacts");
    let mut bundle = complete_bundle();
    materialize_artifacts(&mut bundle, &root);

    let structural = validate_stage1_evidence_bundle(&bundle);
    assert!(structural.ok, "{:#?}", structural.findings);
    let artifacts = validate_stage1_evidence_artifacts(&bundle, &root);
    assert!(artifacts.ok, "{:#?}", artifacts.findings);
    let json = serde_json::to_vec(&bundle).unwrap();
    let gate = gate_stage1_evidence_bundle_json_with_artifacts(&json, &root);
    assert!(gate.ok, "{gate:#?}");

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn artifact_gate_rejects_missing_files_and_content_digest_mismatch() {
    let missing_root = temp_dir("missing-artifact");
    let mut missing = complete_bundle();
    materialize_artifacts(&mut missing, &missing_root);
    let missing_uri = missing.cases[0].artifacts.raw_execution[0].uri.clone();
    fs::remove_file(missing_root.join(missing_uri)).unwrap();
    assert_code(
        &validate_stage1_evidence_artifacts(&missing, &missing_root),
        "missing-stage1-artifact-file",
    );
    fs::remove_dir_all(missing_root).unwrap();

    let mismatch_root = temp_dir("artifact-digest-mismatch");
    let mut mismatch = complete_bundle();
    materialize_artifacts(&mut mismatch, &mismatch_root);
    let mismatch_uri = mismatch.cases[0].artifacts.semantic_traces[0].uri.clone();
    fs::write(mismatch_root.join(mismatch_uri), b"tampered").unwrap();
    assert_code(
        &validate_stage1_evidence_artifacts(&mismatch, &mismatch_root),
        "stage1-artifact-digest-mismatch",
    );
    fs::remove_dir_all(mismatch_root).unwrap();
}

#[test]
fn artifact_gate_rejects_snapshot_and_trace_semantic_tampering() {
    assert_artifact_tamper(
        "snapshot-integrity-tamper",
        &["invalid-stage1-snapshot-integrity"],
        |bundle, root| {
            let case_index = committed_case_index(bundle);
            let reference = bundle.cases[case_index].artifacts.snapshot.as_ref().unwrap().clone();
            let mut snapshot = read_json::<contract_core::SnapshotEnvelope>(root, &reference.uri);
            snapshot.body.portable_state.push(0xff);

            let case = &mut bundle.cases[case_index];
            let reference = case.artifacts.snapshot.as_mut().unwrap();
            write_case_ref(root, reference, &serde_json::to_vec_pretty(&snapshot).unwrap());
            case.state.snapshot_sha256 = Some(reference.sha256.clone());
        },
    );

    assert_artifact_tamper(
        "snapshot-resealed-body-tamper",
        &["inconsistent-stage1-snapshot-trace"],
        |bundle, root| {
            let case_index = committed_case_index(bundle);
            let reference = bundle.cases[case_index].artifacts.snapshot.as_ref().unwrap().clone();
            let mut snapshot = read_json::<contract_core::SnapshotEnvelope>(root, &reference.uri);
            snapshot.body.portable_state.push(0xfe);
            snapshot.integrity = contract_core::snapshot_integrity(&snapshot.body).unwrap();

            let case = &mut bundle.cases[case_index];
            let reference = case.artifacts.snapshot.as_mut().unwrap();
            write_case_ref(root, reference, &serde_json::to_vec_pretty(&snapshot).unwrap());
            case.state.snapshot_sha256 = Some(reference.sha256.clone());
        },
    );

    assert_artifact_tamper(
        "missing-source-snapshot-trace",
        &["missing-stage1-source-snapshot-trace"],
        |bundle, _root| {
            let case_index = committed_case_index(bundle);
            let case = &mut bundle.cases[case_index];
            case.artifacts
                .semantic_traces
                .retain(|reference| !reference.uri.ends_with("source.json"));
            case.state.trace_sha256s = case
                .artifacts
                .semantic_traces
                .iter()
                .map(|reference| reference.sha256.clone())
                .collect();
        },
    );

    assert_artifact_tamper(
        "trace-entry-output-tamper",
        &["invalid-stage1-semantic-replay"],
        |bundle, root| {
            rewrite_committed_trace(bundle, root, |trace| {
                trace.entries[0].output_state = contract_core::Digest::ZERO;
            });
        },
    );

    assert_artifact_tamper(
        "trace-final-state-tamper",
        &["inconsistent-stage1-trace-final-state"],
        |bundle, root| {
            rewrite_committed_trace(bundle, root, |trace| {
                trace.final_state.portable_state.push(0xff);
            });
        },
    );

    assert_artifact_tamper(
        "trace-claimed-role-tamper",
        &["inconsistent-stage1-claimed-final-state"],
        |bundle, root| {
            rewrite_committed_trace(bundle, root, |trace| {
                trace.role = Stage1TraceRole::Source;
            });
        },
    );

    assert_artifact_tamper(
        "revocation-running-phase-tamper",
        &["inconsistent-stage1-final-ownership-trace"],
        |bundle, root| {
            rewrite_source_trace_phase(
                bundle,
                root,
                "required-capability-revoked",
                contract_core::HandoffPhase::Running,
            );
        },
    );

    assert_artifact_tamper(
        "recoverable-source-exported-phase-tamper",
        &["inconsistent-stage1-final-ownership-trace"],
        |bundle, root| {
            rewrite_source_trace_phase(
                bundle,
                root,
                "safe-point-unreachable",
                contract_core::HandoffPhase::Exported,
            );
        },
    );
}

#[test]
fn artifact_gate_rejects_receipt_and_raw_dump_semantic_tampering() {
    assert_artifact_tamper(
        "authority-root-tamper",
        &[
            "inconsistent-stage1-source-authority-root",
            "inconsistent-stage1-destination-authority-root",
        ],
        |bundle, _root| {
            let case_index = committed_case_index(bundle);
            let case = &mut bundle.cases[case_index];
            case.authority.source_authority_root_sha256 = digest('d');
            case.authority.destination_authority_root_sha256 = digest('e');
        },
    );

    assert_artifact_tamper(
        "revocation-tombstone-tamper",
        &["missing-stage1-revoked-authority-tombstone"],
        |bundle, root| {
            rewrite_source_trace(bundle, root, "required-capability-revoked", |trace| {
                for state in [&mut trace.base_state, &mut trace.final_state] {
                    let revoked = state
                        .authorities
                        .iter_mut()
                        .find(|grant| grant.status == contract_core::AuthorityStatus::Revoked)
                        .unwrap();
                    revoked.status = contract_core::AuthorityStatus::Active;
                    revoked.authority.generation = contract_core::Generation::INITIAL;
                }
            });
        },
    );

    assert_artifact_tamper(
        "revocation-provider-observation-tamper",
        &["missing-stage1-revocation-provider-observation"],
        |bundle, root| {
            let case_index = bundle
                .cases
                .iter()
                .position(|case| case.case_id == "required-capability-revoked")
                .unwrap();
            rewrite_raw_transcript(bundle, root, case_index, "source.jsonl", |lines| {
                for line in lines {
                    if line.get("stream").and_then(serde_json::Value::as_str)
                        != Some("worker_response")
                    {
                        continue;
                    }
                    let mut response = serde_json::from_str::<serde_json::Value>(
                        line.get("line").and_then(serde_json::Value::as_str).unwrap(),
                    )
                    .unwrap();
                    if let Some(kind) = response.pointer_mut("/outcome/error/provider_kind") {
                        *kind = serde_json::Value::String("Denied".to_owned());
                    }
                    line["line"] =
                        serde_json::Value::String(serde_json::to_string(&response).unwrap());
                }
            });
        },
    );

    assert_artifact_tamper(
        "revocation-assertion-tamper",
        &["missing-stage1-revocation-assertion"],
        |bundle, root| {
            let case_index = bundle
                .cases
                .iter()
                .position(|case| case.case_id == "required-capability-revoked")
                .unwrap();
            rewrite_case_assertions(bundle, root, case_index, |assertions| {
                assertions.retain(|assertion| {
                    assertion.get("name").and_then(serde_json::Value::as_str)
                        != Some("source-recovery-requires-reauthorization")
                });
            });
        },
    );

    assert_artifact_tamper(
        "receipt-rights-amplification",
        &["inconsistent-stage1-binding-receipt-content"],
        |bundle, root| {
            rewrite_timer_receipt(bundle, root, |receipt| {
                receipt.exposed_rights =
                    receipt.exposed_rights.union(contract_core::Rights::KV_READ);
            });
        },
    );

    assert_artifact_tamper(
        "receipt-lease-epoch-tamper",
        &["inconsistent-stage1-binding-receipt-content"],
        |bundle, root| {
            rewrite_timer_receipt(bundle, root, |receipt| {
                receipt.lease_epoch = contract_core::LeaseEpoch(receipt.lease_epoch.0 + 1);
            });
        },
    );

    assert_artifact_tamper(
        "raw-portable-state-tamper",
        &["inconsistent-stage1-raw-dump"],
        |bundle, root| {
            let case_index = committed_case_index(bundle);
            let raw_index = bundle.cases[case_index]
                .artifacts
                .raw_execution
                .iter()
                .position(|reference| reference.uri.ends_with("destination.jsonl"))
                .unwrap();
            let uri = bundle.cases[case_index].artifacts.raw_execution[raw_index].uri.clone();
            let bytes = fs::read(root.join(uri)).unwrap();
            let mut lines = bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            let mut response = serde_json::from_str::<serde_json::Value>(
                lines[1].get("line").and_then(serde_json::Value::as_str).unwrap(),
            )
            .unwrap();
            *response.pointer_mut("/outcome/result/portable_component_state").unwrap() =
                serde_json::json!([0, 1, 2, 3]);
            lines[1]["line"] = serde_json::Value::String(serde_json::to_string(&response).unwrap());

            let reference = &mut bundle.cases[case_index].artifacts.raw_execution[raw_index];
            write_case_ref(root, reference, &json_lines(&lines));
        },
    );

    assert_artifact_tamper(
        "raw-transcript-role-swap",
        &["inconsistent-stage1-raw-dump"],
        |bundle, root| {
            let case_index = committed_case_index(bundle);
            let source_index = bundle.cases[case_index]
                .artifacts
                .raw_execution
                .iter()
                .position(|reference| reference.uri.ends_with("source.jsonl"))
                .unwrap();
            let destination_index = bundle.cases[case_index]
                .artifacts
                .raw_execution
                .iter()
                .position(|reference| reference.uri.ends_with("destination.jsonl"))
                .unwrap();
            let source_uri =
                bundle.cases[case_index].artifacts.raw_execution[source_index].uri.clone();
            let source_bytes = fs::read(root.join(source_uri)).unwrap();
            write_case_ref(
                root,
                &mut bundle.cases[case_index].artifacts.raw_execution[destination_index],
                &source_bytes,
            );
        },
    );

    assert_artifact_tamper(
        "missing-report-regeneration-assertion",
        &["missing-stage1-report-regeneration-assertion"],
        |bundle, root| {
            let case_index = bundle
                .cases
                .iter()
                .position(|case| case.case_id == "report-generation-fails-after-commit")
                .unwrap();
            rewrite_case_assertions(bundle, root, case_index, |assertions| {
                assertions.retain(|assertion| {
                    assertion.get("name").and_then(serde_json::Value::as_str)
                        != Some("report-publication-failed-and-regenerated")
                });
            });
        },
    );

    assert_artifact_tamper(
        "invalid-report-regeneration-assertion",
        &["invalid-stage1-report-regeneration-assertion"],
        |bundle, root| {
            let case_index = bundle
                .cases
                .iter()
                .position(|case| case.case_id == "report-generation-fails-after-commit")
                .unwrap();
            rewrite_case_assertions(bundle, root, case_index, |assertions| {
                let assertion = assertions
                    .iter_mut()
                    .find(|assertion| {
                        assertion.get("name").and_then(serde_json::Value::as_str)
                            == Some("report-publication-failed-and-regenerated")
                    })
                    .unwrap();
                assertion["detail"]["committed_state_sha256_after"] =
                    serde_json::Value::String(digest('f'));
            });
        },
    );

    assert_artifact_tamper(
        "misplaced-report-regeneration-assertion",
        &["invalid-stage1-report-regeneration-assertion"],
        |bundle, root| {
            let case_index = committed_case_index(bundle);
            let case = &bundle.cases[case_index];
            let state_sha256 = case.state.state_sha256.clone();
            let config_digest = digest_from_hex(&case.case_config_sha256);
            let policy_digest = digest_from_hex(&case.case_policy_sha256);
            rewrite_case_assertions(bundle, root, case_index, |assertions| {
                assertions.push(serde_json::json!({
                    "name": "report-publication-failed-and-regenerated",
                    "detail": {
                        "publish_error_kind": "io",
                        "publish_error_message": "injected publication failure",
                        "bundle_path": "stage1-evidence.json",
                        "case_manifest_count": STAGE1_CASE_DEFINITIONS.len(),
                        "case_manifest_set_sha256": digest('a'),
                        "regenerated_bundle_sha256": digest('b'),
                        "committed_state_sha256_before": state_sha256,
                        "committed_state_sha256_after": state_sha256,
                    },
                    "case_config_digest": config_digest,
                    "case_policy_digest": policy_digest,
                }));
            });
        },
    );
}

#[test]
fn artifact_gate_rejects_matrix_semantic_tampering() {
    assert_artifact_tamper(
        "matrix-case-digest-tamper",
        &[
            "inconsistent-stage1-case-matrix",
            "inconsistent-stage1-config-provenance",
            "inconsistent-stage1-policy-provenance",
        ],
        |bundle, root| {
            let reference = bundle.provenance.artifacts.matrix_manifest.clone();
            let mut matrix = read_json::<serde_json::Value>(root, &reference.uri);
            matrix["entries"][0]["config_digest"] =
                serde_json::to_value(contract_core::Digest::ZERO).unwrap();
            matrix["entries"][0]["policy_digest"] =
                serde_json::to_value(contract_core::Digest::ZERO).unwrap();
            write_provenance_ref(
                root,
                &mut bundle.provenance.artifacts.matrix_manifest,
                &serde_json::to_vec_pretty(&matrix).unwrap(),
            );
        },
    );

    assert_artifact_tamper(
        "matrix-fault-coverage-tamper",
        &["incomplete-stage1-provider-fault-coverage"],
        |bundle, root| {
            let reference = bundle.provenance.artifacts.matrix_manifest.clone();
            let mut matrix = read_json::<serde_json::Value>(root, &reference.uri);
            matrix["provider_fault_coverage"].as_array_mut().unwrap().pop();
            write_provenance_ref(
                root,
                &mut bundle.provenance.artifacts.matrix_manifest,
                &serde_json::to_vec_pretty(&matrix).unwrap(),
            );
        },
    );
}

#[test]
fn artifact_gate_rejects_build_and_contract_provenance_tampering() {
    assert_artifact_tamper(
        "build-source-tamper",
        &["inconsistent-stage1-source-provenance"],
        |bundle, root| {
            let reference = bundle.provenance.artifacts.build_source_manifest.clone();
            let mut manifest = read_json::<serde_json::Value>(root, &reference.uri);
            manifest["files"][0]["bytes"] = serde_json::json!(8);
            write_provenance_ref(
                root,
                &mut bundle.provenance.artifacts.build_source_manifest,
                &serde_json::to_vec_pretty(&manifest).unwrap(),
            );
        },
    );

    assert_artifact_tamper(
        "build-toolchain-tamper",
        &["inconsistent-stage1-build-toolchain-provenance"],
        |bundle, root| {
            write_provenance_ref(
                root,
                &mut bundle.provenance.artifacts.build_toolchain,
                b"different build toolchain",
            );
        },
    );

    assert_artifact_tamper(
        "executable-tamper",
        &["inconsistent-stage1-executable-provenance"],
        |bundle, root| {
            write_provenance_ref(
                root,
                &mut bundle.provenance.artifacts.executable,
                b"different executable",
            );
        },
    );

    assert_artifact_tamper(
        "component-tamper",
        &["inconsistent-stage1-component-provenance"],
        |bundle, root| {
            write_provenance_ref(
                root,
                &mut bundle.provenance.artifacts.component,
                b"different component bytes",
            );
        },
    );

    assert_artifact_tamper(
        "profile-tamper",
        &["inconsistent-stage1-profile-provenance"],
        |bundle, root| {
            let reference = bundle.provenance.artifacts.profile.clone();
            let mut profile = read_json::<serde_json::Value>(root, &reference.uri);
            profile["timer"]["cancellation_required"] = serde_json::json!(false);
            write_provenance_ref(
                root,
                &mut bundle.provenance.artifacts.profile,
                &serde_json::to_vec_pretty(&profile).unwrap(),
            );
        },
    );
}

#[cfg(unix)]
#[test]
fn artifact_gate_rejects_symlink_escape_from_bundle_root() {
    use std::os::unix::fs::symlink;

    let root = temp_dir("artifact-root");
    let outside = temp_dir("artifact-outside");
    let mut bundle = complete_bundle();
    materialize_artifacts(&mut bundle, &root);
    let artifact = &bundle.cases[0].artifacts.raw_execution[0];
    let path = root.join(&artifact.uri);
    fs::remove_file(&path).unwrap();
    let outside_file = outside.join("raw.log");
    fs::create_dir_all(&outside).unwrap();
    fs::write(&outside_file, b"outside").unwrap();
    symlink(&outside_file, &path).unwrap();

    assert_code(&validate_stage1_evidence_artifacts(&bundle, &root), "stage1-artifact-path-escape");
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}

#[cfg(unix)]
#[test]
fn artifact_gate_rejects_contained_symlink_in_hash_and_content_paths() {
    use std::os::unix::fs::symlink;

    let root = temp_dir("artifact-contained-symlink");
    let mut bundle = complete_bundle();
    materialize_artifacts(&mut bundle, &root);
    let artifact = &bundle.provenance.artifacts.component;
    let path = root.join(&artifact.uri);
    let target = path.with_file_name("component-copy.wasm");
    fs::copy(&path, &target).unwrap();
    fs::remove_file(&path).unwrap();
    symlink(&target, &path).unwrap();

    let report = validate_stage1_evidence_artifacts(&bundle, &root);
    let symlink_findings = report
        .findings
        .iter()
        .filter(|finding| finding.code == "stage1-artifact-symlink-rejected")
        .count();
    assert_eq!(
        symlink_findings, 2,
        "both the reference hash gate and typed content reader must reject the symlink: {:#?}",
        report.findings
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn json_gate_rejects_missing_typed_dimension_before_validation() {
    let mut value = serde_json::to_value(complete_bundle()).unwrap();
    value.as_object_mut().unwrap().remove("environment");
    let gate = gate_stage1_evidence_bundle_json(&serde_json::to_vec(&value).unwrap());

    assert!(!gate.ok);
    assert_eq!(gate.load_error.unwrap().code, "invalid-stage1-evidence-json");
}

fn complete_bundle() -> Stage1EvidenceBundle {
    let bundle_id = "stage1-bundle-001";
    let component_sha256 = digest('1');
    let profile_sha256 = digest('2');
    let policy_sha256 = digest('6');
    let cases = STAGE1_CASE_DEFINITIONS
        .iter()
        .enumerate()
        .map(|(index, definition)| {
            let execution_id = format!("{:032x}", (index as u128 + 1) * 16 + 1);
            let handoff_id = format!("{:032x}", (index as u128 + 1) * 16 + 2);
            let snapshot_id = format!("{:032x}", (index as u128 + 1) * 16 + 3);
            let outcome = definition.allowed_outcomes[0];
            let committed =
                stage1_expected_ownership(outcome) != Stage1ExpectedOwnership::SourceRetained;
            let authority = authority_for(outcome, &policy_sha256);
            let reference = |name: &str, sha256: String| Stage1ArtifactReference {
                uri: format!("{}/{name}", definition.id),
                sha256,
                bundle_id: bundle_id.to_string(),
                case_id: definition.id.to_string(),
                execution_id: execution_id.clone(),
                handoff_id: handoff_id.clone(),
                snapshot_id: snapshot_id.clone(),
                component_sha256: component_sha256.clone(),
                profile_sha256: profile_sha256.clone(),
            };
            let snapshot = committed.then(|| reference("snapshot.json", digest('b')));
            let binding_receipts = if committed {
                vec![
                    Stage1BindingReceiptReference {
                        resource: Stage1ResourceKind::PausedDurationTimer,
                        receipt_id: format!("{:032x}", (index as u128 + 1) * 16 + 4),
                        artifact: reference("receipts/timer.json", digest('d')),
                    },
                    Stage1BindingReceiptReference {
                        resource: Stage1ResourceKind::DurableKeyValue,
                        receipt_id: format!("{:032x}", (index as u128 + 1) * 16 + 5),
                        artifact: reference("receipts/key-value.json", digest('e')),
                    },
                ]
            } else {
                Vec::new()
            };
            let semantic_traces = if committed {
                vec![
                    reference("traces/source.json", digest('c')),
                    reference("traces/destination.json", digest('c')),
                ]
            } else {
                vec![reference("traces/source.json", digest('c'))]
            };
            let trace_sha256s =
                semantic_traces.iter().map(|reference| reference.sha256.clone()).collect();
            let mut raw_execution = vec![
                reference("raw/source.jsonl", digest('f')),
                reference("raw/destination.jsonl", digest('f')),
                reference("raw/assertions.jsonl", digest('f')),
            ];
            if definition.id == "performance-observations" {
                raw_execution.push(reference("raw/performance.json", digest('f')));
            }
            Stage1CaseEvidence {
                case_id: definition.id.to_string(),
                execution_id: execution_id.clone(),
                handoff_id: handoff_id.clone(),
                snapshot_id: snapshot_id.clone(),
                case_config_sha256: digest('3'),
                case_policy_sha256: digest('6'),
                outcome,
                exit_status: 0,
                fault_schedule: Stage1FaultSchedule {
                    schedule_id: if definition.class == Stage1CaseClass::FailureRecovery {
                        format!("inject-{}", definition.id)
                    } else {
                        "none".to_string()
                    },
                    injections: if definition.class == Stage1CaseClass::FailureRecovery {
                        vec![Stage1FaultInjection {
                            transition: definition.id.to_string(),
                            action: "inject-required-condition".to_string(),
                        }]
                    } else {
                        Vec::new()
                    },
                },
                authority,
                artifacts: Stage1CaseArtifacts {
                    snapshot,
                    semantic_traces,
                    binding_receipts,
                    raw_execution,
                },
                state: Stage1StateEvidence {
                    state_sha256: digest('0'),
                    replay_state_sha256: digest('0'),
                    snapshot_sha256: committed.then(|| digest('b')),
                    trace_sha256s,
                },
            }
        })
        .collect::<Vec<_>>();
    let performance_case =
        cases.iter().find(|case| case.case_id == "performance-observations").unwrap();

    let provenance_reference = |name: &str, sha256: String| Stage1ProvenanceArtifactReference {
        uri: format!("provenance/{name}"),
        sha256,
    };
    Stage1EvidenceBundle {
        schema_version: STAGE1_EVIDENCE_SCHEMA_VERSION.to_string(),
        capability_id: STAGE1_CAPABILITY_ID.to_string(),
        bundle_id: bundle_id.to_string(),
        evidence_kind: Stage1EvidenceKind::Execution,
        claims: vec![Stage1Claim::CooperativeStatefulComponentHandoff],
        started_at_unix_ms: 1_000,
        finished_at_unix_ms: 2_000,
        environment: Stage1ExecutionEnvironment {
            carrier: versioned("wit-checkpoint-restore", "1"),
            source_runtime: versioned("wasmtime", "43.0.2"),
            destination_runtime: versioned("wasmtime", "43.0.2"),
            source_isa: Stage1IsaIdentity {
                architecture: "x86_64".to_string(),
                abi: "linux-gnu".to_string(),
            },
            destination_isa: Stage1IsaIdentity {
                architecture: "x86_64".to_string(),
                abi: "linux-gnu".to_string(),
            },
            substrate: versioned("host-process-isolation", "1"),
            provider: Stage1ProviderIdentity {
                implementation: versioned("sqlite", "3"),
                durable: true,
                mock: false,
            },
            authority_enforcement: Stage1AuthorityEnforcementIdentity {
                implementation: versioned("visa-lease-fencing", "1"),
                policy_sha256: policy_sha256.clone(),
            },
            resource_profiles: vec![
                Stage1ResourceProfile {
                    resource: Stage1ResourceKind::PausedDurationTimer,
                    profile_id: "paused-duration-monotonic-timer".to_string(),
                    version: "1".to_string(),
                    profile_sha256: digest('9'),
                },
                Stage1ResourceProfile {
                    resource: Stage1ResourceKind::DurableKeyValue,
                    profile_id: "durable-versioned-kv".to_string(),
                    version: "1".to_string(),
                    profile_sha256: digest('a'),
                },
            ],
        },
        provenance: Stage1Provenance {
            component_sha256,
            profile_sha256,
            config_sha256: digest('3'),
            source_sha256: digest('4'),
            toolchain_sha256: digest('5'),
            executable_sha256: digest('b'),
            artifacts: Stage1ProvenanceArtifacts {
                component: provenance_reference("component.wasm", digest('1')),
                profile: provenance_reference("profile.json", digest('2')),
                source_manifest: provenance_reference("source-manifest.json", digest('4')),
                toolchain: provenance_reference("toolchain.txt", digest('5')),
                build_source_manifest: provenance_reference(
                    "build-source-manifest.json",
                    digest('4'),
                ),
                build_toolchain: provenance_reference("build-toolchain.txt", digest('5')),
                executable: provenance_reference("visa-system", digest('b')),
                matrix_manifest: provenance_reference("matrix.json", digest('3')),
            },
        },
        performance_observations: vec![
            Stage1PerformanceObservation {
                metric: Stage1PerformanceMetric::SteadyStateCost,
                unit: Stage1PerformanceUnit::Nanoseconds,
                samples: vec![100, 110, 105],
                execution_id: performance_case.execution_id.clone(),
                raw_artifact_sha256: digest('f'),
            },
            Stage1PerformanceObservation {
                metric: Stage1PerformanceMetric::SnapshotSize,
                unit: Stage1PerformanceUnit::Bytes,
                samples: vec![4096],
                execution_id: performance_case.execution_id.clone(),
                raw_artifact_sha256: digest('f'),
            },
            Stage1PerformanceObservation {
                metric: Stage1PerformanceMetric::HandoffInterruption,
                unit: Stage1PerformanceUnit::Nanoseconds,
                samples: vec![1_000_000, 1_100_000],
                execution_id: performance_case.execution_id.clone(),
                raw_artifact_sha256: digest('f'),
            },
        ],
        cases,
    }
}

fn authority_for(outcome: Stage1CaseOutcome, policy_sha256: &str) -> Stage1AuthorityEvidence {
    let (destination_lease_epoch, fencing_epoch, ownership, source_fenced) =
        match stage1_expected_ownership(outcome) {
            Stage1ExpectedOwnership::SourceRetained => {
                (None, 7, Stage1OwnershipStatus::SourceActive, false)
            }
            Stage1ExpectedOwnership::DestinationCommitted => {
                (Some(8), 8, Stage1OwnershipStatus::DestinationActive, true)
            }
            Stage1ExpectedOwnership::DestinationRecoveryRequired => {
                (Some(8), 8, Stage1OwnershipStatus::DestinationRecoveryRequired, true)
            }
        };
    Stage1AuthorityEvidence {
        enforcement_policy_sha256: policy_sha256.to_string(),
        source_authority_root_sha256: digest('7'),
        destination_authority_root_sha256: digest('8'),
        source_lease_epoch: 7,
        destination_lease_epoch,
        fencing_epoch,
        ownership,
        source_fenced,
    }
}

fn materialize_artifacts(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    fs::create_dir_all(root).unwrap();
    materialize_provenance(bundle, root);
    let mut performance_raw = None;
    for case in &mut bundle.cases {
        materialize_case(
            case,
            root,
            bundle.provenance.component_sha256.as_str(),
            bundle.provenance.profile_sha256.as_str(),
        );
        if case.case_id == "performance-observations" {
            performance_raw = case
                .artifacts
                .raw_execution
                .iter()
                .find(|artifact| artifact.uri.ends_with("performance.json"))
                .map(|artifact| artifact.sha256.clone());
        }
    }
    let performance_raw = performance_raw.unwrap();
    for observation in &mut bundle.performance_observations {
        observation.raw_artifact_sha256 = performance_raw.clone();
    }
}

#[derive(Serialize)]
struct TestSourceManifest<'a> {
    schema: &'a str,
    files: Vec<TestSourceFile<'a>>,
}

#[derive(Serialize)]
struct TestSourceFile<'a> {
    path: &'a str,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum TestNamespaceAvailability {
    Correct,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum TestAuthorityPolicyMode {
    Sufficient,
}

#[derive(Serialize)]
struct TestMatrixOptions {
    case_id: String,
    namespace_availability: TestNamespaceAvailability,
    authority_policy: TestAuthorityPolicyMode,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum TestFaultPoint {
    BeforeJournalWrite,
    AfterJournalWrite,
    BeforeActivationBundle,
    AfterActivationBundle,
    BeforeCommitBundle,
    AfterCommitBundle,
    AfterKvCommit,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum TestDestinationSupport {
    Compatible,
}

#[derive(Serialize)]
struct TestMatrixEntry {
    case_id: String,
    options: TestMatrixOptions,
    config_digest: contract_core::Digest,
    policy_digest: contract_core::Digest,
    source_fault: Option<TestFaultPoint>,
    destination_fault: Option<TestFaultPoint>,
    destination_support: TestDestinationSupport,
    scenario: String,
}

#[derive(Clone, Serialize)]
struct TestFaultCoverage {
    point: TestFaultPoint,
    case_id: String,
    role: String,
    trigger: String,
    expected: String,
}

#[derive(Serialize)]
struct TestMatrixManifest {
    schema: String,
    entries: Vec<TestMatrixEntry>,
    provider_fault_coverage: Vec<TestFaultCoverage>,
}

fn materialize_provenance(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    let component = b"\0asm\x01\0\0\0stage1-test-component";
    bundle.provenance.component_sha256 = sha256(component);
    write_provenance_ref(root, &mut bundle.provenance.artifacts.component, component);

    let profile = visa_profile::CooperativeHandoffProfile::v1(Vec::new());
    let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap();
    bundle.provenance.profile_sha256 =
        contract_hex(contract_core::canonical_digest(&profile).unwrap());
    write_provenance_ref(root, &mut bundle.provenance.artifacts.profile, &profile_bytes);

    let source = TestSourceManifest {
        schema: "visa-stage1-source-manifest-v1",
        files: vec![TestSourceFile { path: "Cargo.toml", bytes: 7, sha256: sha256(b"fixture") }],
    };
    let compact_source = serde_json::to_vec(&source).unwrap();
    let pretty_source = serde_json::to_vec_pretty(&source).unwrap();
    bundle.provenance.source_sha256 = sha256(&compact_source);
    write_provenance_ref(root, &mut bundle.provenance.artifacts.source_manifest, &pretty_source);
    write_provenance_ref(
        root,
        &mut bundle.provenance.artifacts.build_source_manifest,
        &pretty_source,
    );

    let toolchain = b"$ rustc -vV\nrustc test\n$ cargo -V\ncargo test\n";
    bundle.provenance.toolchain_sha256 = sha256(toolchain);
    write_provenance_ref(root, &mut bundle.provenance.artifacts.toolchain, toolchain);
    write_provenance_ref(root, &mut bundle.provenance.artifacts.build_toolchain, toolchain);

    let executable = b"stage1-test-executable";
    bundle.provenance.executable_sha256 = sha256(executable);
    write_provenance_ref(root, &mut bundle.provenance.artifacts.executable, executable);

    for case in &mut bundle.cases {
        case.case_config_sha256 = contract_hex(
            contract_core::canonical_digest(&(case.case_id.as_str(), "config")).unwrap(),
        );
        case.case_policy_sha256 = contract_hex(
            contract_core::canonical_digest(&(case.case_id.as_str(), "policy")).unwrap(),
        );
        for artifact in case_artifact_refs_mut(case) {
            artifact.component_sha256 = bundle.provenance.component_sha256.clone();
            artifact.profile_sha256 = bundle.provenance.profile_sha256.clone();
        }
    }

    let entries = bundle
        .cases
        .iter()
        .map(|case| TestMatrixEntry {
            case_id: case.case_id.clone(),
            options: TestMatrixOptions {
                case_id: case.case_id.clone(),
                namespace_availability: TestNamespaceAvailability::Correct,
                authority_policy: TestAuthorityPolicyMode::Sufficient,
            },
            config_digest: digest_from_hex(&case.case_config_sha256),
            policy_digest: digest_from_hex(&case.case_policy_sha256),
            source_fault: None,
            destination_fault: None,
            destination_support: TestDestinationSupport::Compatible,
            scenario: "typed-test-fixture".to_owned(),
        })
        .collect::<Vec<_>>();
    let coverage = vec![
        fault(TestFaultPoint::BeforeJournalWrite),
        fault(TestFaultPoint::AfterJournalWrite),
        fault(TestFaultPoint::BeforeActivationBundle),
        fault(TestFaultPoint::AfterActivationBundle),
        fault(TestFaultPoint::BeforeCommitBundle),
        fault(TestFaultPoint::AfterCommitBundle),
        fault(TestFaultPoint::AfterKvCommit),
    ];
    let config_projection = entries
        .iter()
        .map(|entry| {
            (
                entry.case_id.as_str(),
                &entry.options,
                entry.config_digest,
                entry.source_fault,
                entry.destination_fault,
                entry.destination_support,
                entry.scenario.as_str(),
            )
        })
        .collect::<Vec<_>>();
    let policy_projection = entries
        .iter()
        .map(|entry| {
            (
                entry.case_id.as_str(),
                entry.policy_digest,
                entry.options.authority_policy,
                entry.destination_support,
                entry.scenario.as_str(),
            )
        })
        .collect::<Vec<_>>();
    bundle.provenance.config_sha256 =
        contract_hex(contract_core::canonical_digest(&(config_projection, &coverage)).unwrap());
    let policy_sha256 = contract_hex(contract_core::canonical_digest(&policy_projection).unwrap());
    bundle.environment.authority_enforcement.policy_sha256 = policy_sha256.clone();
    for case in &mut bundle.cases {
        case.authority.enforcement_policy_sha256 = policy_sha256.clone();
    }
    let manifest = TestMatrixManifest {
        schema: "visa-stage1-matrix-provenance-v1".to_owned(),
        entries,
        provider_fault_coverage: coverage,
    };
    write_provenance_ref(
        root,
        &mut bundle.provenance.artifacts.matrix_manifest,
        &serde_json::to_vec_pretty(&manifest).unwrap(),
    );
}

fn fault(point: TestFaultPoint) -> TestFaultCoverage {
    TestFaultCoverage {
        point,
        case_id: "evidence-verification".to_owned(),
        role: "source".to_owned(),
        trigger: "typed test trigger".to_owned(),
        expected: "typed test outcome".to_owned(),
    }
}

fn case_artifact_refs_mut(case: &mut Stage1CaseEvidence) -> Vec<&mut Stage1ArtifactReference> {
    let mut references = Vec::new();
    if let Some(snapshot) = &mut case.artifacts.snapshot {
        references.push(snapshot);
    }
    references.extend(case.artifacts.semantic_traces.iter_mut());
    references
        .extend(case.artifacts.binding_receipts.iter_mut().map(|receipt| &mut receipt.artifact));
    references.extend(case.artifacts.raw_execution.iter_mut());
    references
}

fn materialize_case(
    case: &mut Stage1CaseEvidence,
    root: &Path,
    component_sha256: &str,
    profile_sha256: &str,
) {
    let component_digest = digest_from_hex(component_sha256);
    let profile_digest = digest_from_hex(profile_sha256);
    let mut source = source_state(case, component_digest, profile_digest);
    if case.outcome == Stage1CaseOutcome::RevocationRejectedNoResurrection {
        source.phase = contract_core::HandoffPhase::Exported;
        source.authorities[1].status = contract_core::AuthorityStatus::Revoked;
        source.authorities[1].authority.generation = contract_core::Generation(1);
    }
    let expected = stage1_expected_ownership(case.outcome);
    let (final_state, traces, snapshot, receipts) = match expected {
        Stage1ExpectedOwnership::SourceRetained => {
            let trace = Stage1SemanticTraceArtifact {
                schema_version: STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION.to_owned(),
                role: Stage1TraceRole::Source,
                scope: Stage1JournalScope {
                    node: source.activation.node,
                    component: source.component.identity,
                },
                base_cursor: contract_core::JournalPosition::ORIGIN,
                base_state: source.clone(),
                entries: Vec::new(),
                final_state: source.clone(),
                claimed_final: true,
            };
            (source, vec![trace], None, Vec::new())
        }
        Stage1ExpectedOwnership::DestinationCommitted
        | Stage1ExpectedOwnership::DestinationRecoveryRequired => {
            committed_case(case, source, expected)
        }
    };

    if let (Some(reference), Some(snapshot)) = (&mut case.artifacts.snapshot, snapshot) {
        write_case_ref(root, reference, &serde_json::to_vec(&snapshot).unwrap());
        case.state.snapshot_sha256 = Some(reference.sha256.clone());
    }
    let source_raw_state = traces
        .iter()
        .find(|trace| trace.role == Stage1TraceRole::Source)
        .map(|trace| trace.final_state.clone())
        .unwrap();
    let destination_raw_state = traces
        .iter()
        .find(|trace| trace.role == Stage1TraceRole::Destination)
        .map(|trace| trace.final_state.clone());
    case.authority.source_authority_root_sha256 = contract_hex(
        contract_core::canonical_digest(source_raw_state.authorities.as_slice()).unwrap(),
    );
    let destination_authorities = destination_raw_state
        .as_ref()
        .map_or_else(|| &[][..], |state| state.authorities.as_slice());
    case.authority.destination_authority_root_sha256 =
        contract_hex(contract_core::canonical_digest(destination_authorities).unwrap());
    assert_eq!(case.artifacts.semantic_traces.len(), traces.len());
    for (reference, trace) in case.artifacts.semantic_traces.iter_mut().zip(traces) {
        write_case_ref(root, reference, &serde_json::to_vec_pretty(&trace).unwrap());
    }
    case.state.trace_sha256s =
        case.artifacts.semantic_traces.iter().map(|reference| reference.sha256.clone()).collect();
    let final_digest = contract_core::state_digest(&final_state).unwrap();
    case.state.state_sha256 = contract_hex(final_digest);
    case.state.replay_state_sha256 = contract_hex(final_digest);

    for (reference, receipt) in case.artifacts.binding_receipts.iter_mut().zip(receipts) {
        reference.receipt_id = identity_hex(receipt.binding.identity);
        write_case_ref(root, &mut reference.artifact, &serde_json::to_vec(&receipt).unwrap());
    }
    materialize_raw(case, root, &source_raw_state, destination_raw_state.as_ref(), final_digest);
}

fn source_state(
    case: &Stage1CaseEvidence,
    component_digest: contract_core::Digest,
    profile_digest: contract_core::Digest,
) -> contract_core::CanonicalState {
    let seed = u128::from_str_radix(&case.handoff_id, 16).unwrap();
    let component =
        contract_core::EntityRef::initial(contract_core::Identity::from_u128(seed + 20));
    let source_node =
        contract_core::NodeIdentity::new(contract_core::Identity::from_u128(seed + 21));
    let timer = contract_core::EntityRef::initial(contract_core::Identity::from_u128(seed + 22));
    let key_value =
        contract_core::EntityRef::initial(contract_core::Identity::from_u128(seed + 23));
    let timer_rights = contract_core::Rights::TIMER_ARM
        .union(contract_core::Rights::TIMER_CANCEL)
        .union(contract_core::Rights::REBIND);
    let key_value_rights = contract_core::Rights::KV_READ
        .union(contract_core::Rights::KV_WRITE)
        .union(contract_core::Rights::REBIND);
    let authorities = vec![
        contract_core::AuthorityGrant::active_root(
            contract_core::EntityRef::initial(contract_core::Identity::from_u128(seed + 24)),
            component,
            component,
            contract_core::Rights::HANDOFF,
        ),
        contract_core::AuthorityGrant::active_root(
            contract_core::EntityRef::initial(contract_core::Identity::from_u128(seed + 25)),
            component,
            timer,
            timer_rights,
        ),
        contract_core::AuthorityGrant::active_root(
            contract_core::EntityRef::initial(contract_core::Identity::from_u128(seed + 26)),
            component,
            key_value,
            key_value_rights,
        ),
    ];
    let claims = contract_core::ResourceClaims {
        timer: contract_core::TimerClaim {
            resource: timer,
            clock: contract_core::TimerClock::PausedMonotonicDuration,
            required_rights: timer_rights,
        },
        key_value: contract_core::KeyValueClaim {
            resource: key_value,
            namespace: contract_core::Identity::from_u128(seed + 27),
            required_rights: key_value_rights,
            delivery: contract_core::DeliveryPolicy::Deduplicated,
        },
    };
    let mut state = contract_core::CanonicalState::dormant(
        component,
        source_node,
        component_digest,
        profile_digest,
        contract_core::SchemaVersion::new(1, 0),
        claims,
        authorities,
    );
    state.phase = contract_core::HandoffPhase::Running;
    state.activation.status = contract_core::ActivationStatus::Active;
    state.ownership = contract_core::Ownership::owned(source_node, contract_core::LeaseEpoch(7));
    state
}

fn committed_case(
    case: &Stage1CaseEvidence,
    mut source: contract_core::CanonicalState,
    expected: Stage1ExpectedOwnership,
) -> (
    contract_core::CanonicalState,
    Vec<Stage1SemanticTraceArtifact>,
    Option<contract_core::SnapshotEnvelope>,
    Vec<contract_core::BindingReceipt>,
) {
    let handoff = identity_from_hex(&case.handoff_id);
    let snapshot_id = identity_from_hex(&case.snapshot_id);
    let seed = u128::from_be_bytes(handoff.0);
    let source_base = source.clone();
    let mut source_position = contract_core::JournalPosition::ORIGIN;
    let mut source_entries = Vec::new();
    append_event(
        &mut source,
        &mut source_position,
        &mut source_entries,
        contract_core::Event::new(
            contract_core::Identity::from_u128(seed + 37),
            contract_core::EventKind::HandoffStarted,
        ),
    );
    append_event(
        &mut source,
        &mut source_position,
        &mut source_entries,
        contract_core::Event::new(
            contract_core::Identity::from_u128(seed + 38),
            contract_core::EventKind::Frozen {
                portable_state: b"opaque-stage1-component-state".to_vec(),
                timer: contract_core::TimerDisposition::Idle,
            },
        ),
    );
    let snapshot_evidence = evidence(seed + 40, contract_core::EvidenceKind::SnapshotIntegrity);
    let snapshot_record = contract_core::SnapshotRecord {
        handoff,
        snapshot: snapshot_id,
        journal_position: source_position.next().unwrap(),
        evidence: snapshot_evidence,
    };
    append_event(
        &mut source,
        &mut source_position,
        &mut source_entries,
        contract_core::Event::new(
            contract_core::Identity::from_u128(seed + 39),
            contract_core::EventKind::SnapshotExported { snapshot: snapshot_record.clone() },
        ),
    );
    let source_trace = Stage1SemanticTraceArtifact {
        schema_version: STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION.to_owned(),
        role: Stage1TraceRole::Source,
        scope: Stage1JournalScope {
            node: source.activation.node,
            component: source.component.identity,
        },
        base_cursor: contract_core::JournalPosition::ORIGIN,
        base_state: source_base,
        entries: source_entries,
        final_state: source.clone(),
        claimed_final: false,
    };
    let body = source.snapshot_body().unwrap();
    let envelope = contract_core::SnapshotEnvelope {
        version: contract_core::CONTRACT_VERSION,
        integrity: contract_core::snapshot_integrity(&body).unwrap(),
        body,
    };
    let destination =
        contract_core::NodeIdentity::new(contract_core::Identity::from_u128(seed + 41));
    let mut state = semantic_core::restore(
        &envelope,
        envelope.integrity,
        source.component_digest,
        source.profile_digest,
        source.profile_version,
        &[],
        destination,
    )
    .unwrap();
    let subject =
        contract_core::EntityRef::new(source.component.identity, contract_core::Generation(1));
    let grants = vec![
        derived_grant(
            seed + 42,
            source.authorities[0].authority,
            subject,
            subject,
            contract_core::Rights::HANDOFF,
        ),
        derived_grant(
            seed + 43,
            source.authorities[1].authority,
            subject,
            source.timer.claim.resource,
            source.timer.claim.required_rights,
        ),
        derived_grant(
            seed + 44,
            source.authorities[2].authority,
            subject,
            source.key_value.claim.resource,
            source.key_value.claim.required_rights,
        ),
    ];
    let receipts = vec![
        binding_receipt(
            case,
            Stage1ResourceKind::PausedDurationTimer,
            source.timer.claim.resource,
            grants[1].authority,
            source.timer.claim.required_rights,
            destination,
            seed + 45,
        ),
        binding_receipt(
            case,
            Stage1ResourceKind::DurableKeyValue,
            source.key_value.claim.resource,
            grants[2].authority,
            source.key_value.claim.required_rights,
            destination,
            seed + 47,
        ),
    ];
    let prepared = contract_core::PreparedDestination {
        handoff,
        snapshot: snapshot_id,
        destination,
        component_generation: contract_core::Generation(1),
        expected_epoch: contract_core::LeaseEpoch(7),
        next_epoch: contract_core::LeaseEpoch(8),
        authorities: grants,
        bindings: receipts.clone(),
    };
    let mut position = snapshot_record.journal_position;
    let mut entries = Vec::new();
    append_event(
        &mut state,
        &mut position,
        &mut entries,
        contract_core::Event::new(
            contract_core::Identity::from_u128(seed + 49),
            contract_core::EventKind::DestinationPrepared { prepared: prepared.clone() },
        ),
    );
    let operation = contract_core::Identity::from_u128(seed + 50);
    let kind = contract_core::EffectKind::LeaseCommit {
        handoff,
        snapshot: snapshot_id,
        destination,
        expected_epoch: contract_core::LeaseEpoch(7),
        next_epoch: contract_core::LeaseEpoch(8),
    };
    let idempotency_key = contract_core::IdempotencyKey::from_u128(seed + 51);
    let request = contract_core::EffectRequest {
        operation,
        idempotency_key,
        causal_parent: None,
        node: destination,
        subject,
        resource: subject,
        authority: prepared.authorities[0].authority,
        lease_epoch: contract_core::LeaseEpoch(7),
        request_digest: contract_core::canonical_digest(&(
            operation,
            idempotency_key,
            destination,
            subject,
            prepared.authorities[0].authority,
            kind.clone(),
        ))
        .unwrap(),
        kind,
    };
    append_event(
        &mut state,
        &mut position,
        &mut entries,
        contract_core::Event::new(
            contract_core::Identity::from_u128(seed + 52),
            contract_core::EventKind::EffectPrepared { request },
        ),
    );
    let source_fence = evidence(seed + 53, contract_core::EvidenceKind::SourceFence);
    let outcome = contract_core::EffectOutcome::Succeeded {
        result: contract_core::EffectResult::LeaseAdvanced {
            owner: destination,
            epoch: contract_core::LeaseEpoch(8),
            source_fence,
        },
        evidence: evidence(seed + 54, contract_core::EvidenceKind::LeaseCommit),
    };
    append_event(
        &mut state,
        &mut position,
        &mut entries,
        contract_core::Event::new(
            contract_core::Identity::from_u128(seed + 55),
            contract_core::EventKind::HandoffCommitted {
                operation,
                handoff,
                snapshot: snapshot_id,
                source: source.activation.node,
                destination,
                previous_epoch: contract_core::LeaseEpoch(7),
                new_epoch: contract_core::LeaseEpoch(8),
                outcome,
            },
        ),
    );
    if expected == Stage1ExpectedOwnership::DestinationCommitted {
        append_event(
            &mut state,
            &mut position,
            &mut entries,
            contract_core::Event::new(
                contract_core::Identity::from_u128(seed + 56),
                contract_core::EventKind::DestinationResumed,
            ),
        );
    }
    let destination_trace = Stage1SemanticTraceArtifact {
        schema_version: STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION.to_owned(),
        role: Stage1TraceRole::Destination,
        scope: Stage1JournalScope { node: destination, component: source.component.identity },
        base_cursor: snapshot_record.journal_position,
        base_state: semantic_core::restore(
            &envelope,
            envelope.integrity,
            source.component_digest,
            source.profile_digest,
            source.profile_version,
            &[],
            destination,
        )
        .unwrap(),
        entries,
        final_state: state.clone(),
        claimed_final: true,
    };
    (state, vec![source_trace, destination_trace], Some(envelope), receipts)
}

fn append_event(
    state: &mut contract_core::CanonicalState,
    position: &mut contract_core::JournalPosition,
    entries: &mut Vec<contract_core::JournalEntry>,
    event: contract_core::Event,
) {
    let input_state = contract_core::state_digest(state).unwrap();
    let next = semantic_core::apply(state, &event).unwrap().into_state();
    *position = position.next().unwrap();
    let output_state = contract_core::state_digest(&next).unwrap();
    entries.push(contract_core::JournalEntry {
        version: contract_core::CONTRACT_VERSION,
        position: *position,
        input_state,
        output_state,
        event,
    });
    *state = next;
}

fn derived_grant(
    id: u128,
    parent: contract_core::EntityRef,
    subject: contract_core::EntityRef,
    resource: contract_core::EntityRef,
    rights: contract_core::Rights,
) -> contract_core::AuthorityGrant {
    contract_core::AuthorityGrant {
        authority: contract_core::EntityRef::initial(contract_core::Identity::from_u128(id)),
        parent: Some(parent),
        subject,
        resource,
        rights,
        status: contract_core::AuthorityStatus::Active,
    }
}

fn binding_receipt(
    case: &Stage1CaseEvidence,
    resource_kind: Stage1ResourceKind,
    claim: contract_core::EntityRef,
    authority: contract_core::EntityRef,
    rights: contract_core::Rights,
    node: contract_core::NodeIdentity,
    evidence_seed: u128,
) -> contract_core::BindingReceipt {
    let reference = case
        .artifacts
        .binding_receipts
        .iter()
        .find(|reference| reference.resource == resource_kind)
        .unwrap();
    contract_core::BindingReceipt {
        handoff: identity_from_hex(&case.handoff_id),
        snapshot: identity_from_hex(&case.snapshot_id),
        claim,
        binding: contract_core::EntityRef::initial(identity_from_hex(&reference.receipt_id)),
        node,
        authority,
        exposed_rights: rights,
        lease_epoch: contract_core::LeaseEpoch(8),
        evidence: evidence(evidence_seed, contract_core::EvidenceKind::Binding),
    }
}

fn evidence(seed: u128, kind: contract_core::EvidenceKind) -> contract_core::EvidenceRef {
    contract_core::EvidenceRef {
        identity: contract_core::Identity::from_u128(seed),
        kind,
        digest: contract_core::Digest::from_bytes(Sha256::digest(seed.to_be_bytes()).into()),
    }
}

fn materialize_raw(
    case: &mut Stage1CaseEvidence,
    root: &Path,
    source_state: &contract_core::CanonicalState,
    destination_state: Option<&contract_core::CanonicalState>,
    final_digest: contract_core::Digest,
) {
    for reference in &mut case.artifacts.raw_execution {
        if reference.uri.ends_with("source.jsonl") || reference.uri.ends_with("destination.jsonl") {
            let role =
                if reference.uri.ends_with("source.jsonl") { "source" } else { "destination" };
            let worker = format!("{}-{role}", case.case_id);
            let request_id = format!("{worker}-000001");
            let dump_state = if role == "source" { Some(source_state) } else { destination_state };
            let request = serde_json::json!({
                "version": 1,
                "id": request_id,
                "command": { "kind": if dump_state.is_some() { "dump" } else { "validate_destination" } }
            });
            let result = dump_state.map_or_else(
                || serde_json::json!({ "kind": "ack" }),
                |state| {
                    serde_json::json!({
                        "kind": "dump",
                        "canonical_state": state,
                        "state_digest": contract_core::state_digest(state).unwrap(),
                        "portable_component_state": state.portable_state,
                    })
                },
            );
            let response = serde_json::json!({
                "version": 1,
                "id": request_id,
                "outcome": {
                    "status": "success",
                    "result": result,
                }
            });
            let mut transcript = vec![
                serde_json::json!({
                    "worker": worker.clone(),
                    "pid": 100,
                    "sequence": 1,
                    "stream": "parent_request",
                    "line": serde_json::to_string(&request).unwrap(),
                }),
                serde_json::json!({
                    "worker": worker.clone(),
                    "pid": 100,
                    "sequence": 2,
                    "stream": "worker_response",
                    "line": serde_json::to_string(&response).unwrap(),
                }),
            ];
            if case.outcome == Stage1CaseOutcome::RevocationRejectedNoResurrection {
                let revoked_id = format!("{worker}-000002");
                let revoked_request = serde_json::json!({
                    "version": 1,
                    "id": revoked_id,
                    "command": {
                        "kind": if role == "source" { "initialize" } else { "prepare_destination" }
                    }
                });
                let revoked_response = serde_json::json!({
                    "version": 1,
                    "id": revoked_id,
                    "outcome": {
                        "status": "error",
                        "error": {
                            "code": "provider",
                            "message": "required authority is revoked",
                            "retryable": false,
                            "provider_kind": "Revoked"
                        }
                    }
                });
                transcript.extend([
                    serde_json::json!({
                        "worker": worker.clone(),
                        "pid": 100,
                        "sequence": 3,
                        "stream": "parent_request",
                        "line": serde_json::to_string(&revoked_request).unwrap(),
                    }),
                    serde_json::json!({
                        "worker": worker,
                        "pid": 100,
                        "sequence": 4,
                        "stream": "worker_response",
                        "line": serde_json::to_string(&revoked_response).unwrap(),
                    }),
                ]);
            }
            let bytes = json_lines(&transcript);
            write_case_ref(root, reference, &bytes);
        } else if reference.uri.ends_with("assertions.jsonl") {
            let mut assertions = vec![serde_json::json!({
                "name": "typed-test-observation",
                "detail": "typed fixture",
                "case_config_digest": digest_from_hex(&case.case_config_sha256),
                "case_policy_digest": digest_from_hex(&case.case_policy_sha256),
            })];
            if case.case_id == "report-generation-fails-after-commit" {
                let state_sha256 = contract_hex(final_digest);
                assertions.push(serde_json::json!({
                    "name": "report-publication-failed-and-regenerated",
                    "detail": {
                        "publish_error_kind": "io",
                        "publish_error_message": "injected publication failure",
                        "bundle_path": "stage1-evidence.json",
                        "case_manifest_count": STAGE1_CASE_DEFINITIONS.len(),
                        "case_manifest_set_sha256": digest('a'),
                        "regenerated_bundle_sha256": digest('b'),
                        "committed_state_sha256_before": state_sha256,
                        "committed_state_sha256_after": state_sha256,
                    },
                    "case_config_digest": digest_from_hex(&case.case_config_sha256),
                    "case_policy_digest": digest_from_hex(&case.case_policy_sha256),
                }));
            }
            if case.outcome == Stage1CaseOutcome::RevocationRejectedNoResurrection {
                for name in [
                    "revoked-capability-not-resurrected",
                    "source-recovery-requires-reauthorization",
                ] {
                    assertions.push(serde_json::json!({
                        "name": name,
                        "detail": "typed revocation observation",
                        "case_config_digest": digest_from_hex(&case.case_config_sha256),
                        "case_policy_digest": digest_from_hex(&case.case_policy_sha256),
                    }));
                }
            }
            let bytes = json_lines(&assertions);
            write_case_ref(root, reference, &bytes);
        } else if reference.uri.ends_with("performance.json") {
            let bytes = serde_json::to_vec(&serde_json::json!([
                {"metric": "steady-state-cost", "samples": [1]},
                {"metric": "snapshot-size", "samples": [1]},
                {"metric": "handoff-interruption", "samples": [1]}
            ]))
            .unwrap();
            write_case_ref(root, reference, &bytes);
        }
    }
}

fn json_lines(values: &[serde_json::Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        serde_json::to_writer(&mut bytes, value).unwrap();
        bytes.push(b'\n');
    }
    bytes
}

fn write_case_ref(root: &Path, artifact: &mut Stage1ArtifactReference, bytes: &[u8]) {
    let path = root.join(&artifact.uri);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    artifact.sha256 = sha256(bytes);
}

fn write_provenance_ref(
    root: &Path,
    artifact: &mut Stage1ProvenanceArtifactReference,
    bytes: &[u8],
) {
    let path = root.join(&artifact.uri);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    artifact.sha256 = sha256(bytes);
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn contract_hex(digest: contract_core::Digest) -> String {
    digest.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest_from_hex(value: &str) -> contract_core::Digest {
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    contract_core::Digest::from_bytes(bytes)
}

fn identity_from_hex(value: &str) -> contract_core::Identity {
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    contract_core::Identity::from_bytes(bytes)
}

fn identity_hex(identity: contract_core::Identity) -> String {
    identity.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn versioned(name: &str, version: &str) -> Stage1VersionedIdentity {
    Stage1VersionedIdentity { name: name.to_string(), version: version.to_string() }
}

fn digest(character: char) -> String {
    character.to_string().repeat(64)
}

fn assert_code(report: &Stage1ValidationReport, code: &str) {
    assert!(
        report.findings.iter().any(|finding| finding.code == code),
        "missing finding {code}: {:#?}",
        report.findings
    );
}

fn assert_artifact_tamper(
    label: &str,
    expected_codes: &[&str],
    tamper: impl FnOnce(&mut Stage1EvidenceBundle, &Path),
) {
    let root = temp_dir(label);
    let mut bundle = complete_bundle();
    materialize_artifacts(&mut bundle, &root);
    tamper(&mut bundle, &root);

    let report = validate_stage1_evidence_artifacts(&bundle, &root);
    assert!(!report.ok, "tampered bundle unexpectedly passed");
    for code in expected_codes {
        assert_code(&report, code);
    }
    fs::remove_dir_all(root).unwrap();
}

fn committed_case_index(bundle: &Stage1EvidenceBundle) -> usize {
    bundle.cases.iter().position(|case| case.case_id == "evidence-verification").unwrap()
}

fn read_json<T: DeserializeOwned>(root: &Path, uri: &str) -> T {
    serde_json::from_slice(&fs::read(root.join(uri)).unwrap()).unwrap()
}

fn rewrite_committed_trace(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    mutate: impl FnOnce(&mut Stage1SemanticTraceArtifact),
) {
    let case_index = committed_case_index(bundle);
    let trace_index = bundle.cases[case_index]
        .artifacts
        .semantic_traces
        .iter()
        .position(|reference| reference.uri.ends_with("destination.json"))
        .unwrap();
    let reference = bundle.cases[case_index].artifacts.semantic_traces[trace_index].clone();
    let mut trace = read_json::<Stage1SemanticTraceArtifact>(root, &reference.uri);
    mutate(&mut trace);

    let case = &mut bundle.cases[case_index];
    let reference = &mut case.artifacts.semantic_traces[trace_index];
    write_case_ref(root, reference, &serde_json::to_vec_pretty(&trace).unwrap());
    case.state.trace_sha256s =
        case.artifacts.semantic_traces.iter().map(|reference| reference.sha256.clone()).collect();
}

fn rewrite_timer_receipt(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    mutate: impl FnOnce(&mut contract_core::BindingReceipt),
) {
    let case_index = committed_case_index(bundle);
    let receipt_index = bundle.cases[case_index]
        .artifacts
        .binding_receipts
        .iter()
        .position(|reference| reference.resource == Stage1ResourceKind::PausedDurationTimer)
        .unwrap();
    let reference =
        bundle.cases[case_index].artifacts.binding_receipts[receipt_index].artifact.clone();
    let mut receipt = read_json::<contract_core::BindingReceipt>(root, &reference.uri);
    mutate(&mut receipt);
    write_case_ref(
        root,
        &mut bundle.cases[case_index].artifacts.binding_receipts[receipt_index].artifact,
        &serde_json::to_vec_pretty(&receipt).unwrap(),
    );
}

fn rewrite_source_trace_phase(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_id: &str,
    phase: contract_core::HandoffPhase,
) {
    rewrite_source_trace(bundle, root, case_id, |trace| {
        assert!(trace.entries.is_empty());
        trace.base_state.phase = phase;
        trace.final_state.phase = phase;
    });
}

fn rewrite_source_trace(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_id: &str,
    mutate: impl FnOnce(&mut Stage1SemanticTraceArtifact),
) {
    let case_index = bundle.cases.iter().position(|case| case.case_id == case_id).unwrap();
    let trace_index = bundle.cases[case_index]
        .artifacts
        .semantic_traces
        .iter()
        .position(|reference| reference.uri.ends_with("source.json"))
        .unwrap();
    let reference = bundle.cases[case_index].artifacts.semantic_traces[trace_index].clone();
    let mut trace = read_json::<Stage1SemanticTraceArtifact>(root, &reference.uri);
    assert!(trace.claimed_final);
    mutate(&mut trace);
    let state_digest = contract_core::state_digest(&trace.final_state).unwrap();
    let source_authority_root =
        contract_core::canonical_digest(trace.final_state.authorities.as_slice()).unwrap();

    let case = &mut bundle.cases[case_index];
    write_case_ref(
        root,
        &mut case.artifacts.semantic_traces[trace_index],
        &serde_json::to_vec_pretty(&trace).unwrap(),
    );
    case.state.trace_sha256s =
        case.artifacts.semantic_traces.iter().map(|reference| reference.sha256.clone()).collect();
    case.state.state_sha256 = contract_hex(state_digest);
    case.state.replay_state_sha256 = contract_hex(state_digest);
    case.authority.source_authority_root_sha256 = contract_hex(source_authority_root);
}

fn rewrite_case_assertions(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_index: usize,
    mutate: impl FnOnce(&mut Vec<serde_json::Value>),
) {
    let raw_index = bundle.cases[case_index]
        .artifacts
        .raw_execution
        .iter()
        .position(|reference| reference.uri.ends_with("assertions.jsonl"))
        .unwrap();
    let uri = bundle.cases[case_index].artifacts.raw_execution[raw_index].uri.clone();
    let bytes = fs::read(root.join(uri)).unwrap();
    let mut assertions = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    mutate(&mut assertions);
    write_case_ref(
        root,
        &mut bundle.cases[case_index].artifacts.raw_execution[raw_index],
        &json_lines(&assertions),
    );
}

fn rewrite_raw_transcript(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_index: usize,
    file_name: &str,
    mutate: impl FnOnce(&mut Vec<serde_json::Value>),
) {
    let raw_index = bundle.cases[case_index]
        .artifacts
        .raw_execution
        .iter()
        .position(|reference| reference.uri.ends_with(file_name))
        .unwrap();
    let uri = bundle.cases[case_index].artifacts.raw_execution[raw_index].uri.clone();
    let bytes = fs::read(root.join(uri)).unwrap();
    let mut lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    mutate(&mut lines);
    write_case_ref(
        root,
        &mut bundle.cases[case_index].artifacts.raw_execution[raw_index],
        &json_lines(&lines),
    );
}

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("visa-stage1-{label}-{}-{nonce}", std::process::id()))
}
