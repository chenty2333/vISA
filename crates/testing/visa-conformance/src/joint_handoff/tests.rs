use std::{
    collections::BTreeSet,
    fs,
    sync::atomic::{AtomicU64, Ordering},
};

use contract_core::{Digest, Identity};
use sha2::{Digest as _, Sha256};

use super::*;

fn expectations() -> JointEvidenceExpectations {
    JointEvidenceExpectations {
        visa_git_sha: "a".repeat(40),
        nexus_git_sha: "b".repeat(40),
        neutral_git_sha: "c".repeat(40),
        neutral_tree: "3".repeat(40),
        neutral_bundle_sha256: "4".repeat(64),
        source_lock_sha256: "d".repeat(64),
        protocol_schema_sha256: "e".repeat(64),
        machine_contract_sha256: "f".repeat(64),
        refinement_map_sha256: "1".repeat(64),
        abstract_registry_sha256: "2".repeat(64),
    }
}

fn reference_bundle() -> JointEvidenceBundle {
    build_reference_joint_evidence_bundle(&expectations()).unwrap()
}

fn case_mut<'a>(bundle: &'a mut JointEvidenceBundle, id: &str) -> &'a mut JointCaseEvidence {
    bundle.cases.iter_mut().find(|case| case.case_id == id).unwrap()
}

fn refresh_trace(case: &mut JointCaseEvidence) {
    for (index, event) in case.trace.events.iter_mut().enumerate() {
        event.index = u64::try_from(index).unwrap();
    }
    case.trace_sha256 = joint_raw_trace_sha256(&case.trace).unwrap();
}

fn has_code(report: &JointValidationReport, code: &str) -> bool {
    report.findings.iter().any(|finding| finding.code == code)
}

fn gate_has_code(gate: &JointEvidenceGateResult, code: &str) -> bool {
    gate.validation.as_ref().is_some_and(|report| has_code(report, code))
}

fn sync_request_and_envelope(
    request: &mut ReceiptRequest,
    envelope: &mut ReceiptEnvelope,
    receipt: &JointReceipt,
) {
    *request = joint_receipt_request(receipt, request.operation);
    *envelope = joint_receipt_envelope(receipt, request).unwrap();
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn production_counts(bundle: &JointEvidenceBundle) -> (usize, usize, usize) {
    let mut accepted = 0_usize;
    let mut rejected = 0_usize;
    let mut replayed = 0_usize;
    for case in &bundle.cases {
        let mut seen = BTreeSet::new();
        for event in &case.trace.events {
            match &event.event {
                JointRawEventKind::ReceiptAccepted { receipt, .. } => {
                    let digest = joint_receipt_ref(receipt).unwrap().digest;
                    if seen.insert(digest) {
                        accepted += 1;
                    } else {
                        replayed += 1;
                    }
                }
                JointRawEventKind::ReceiptRejected { .. } => rejected += 1,
                _ => {}
            }
        }
    }
    (accepted, rejected, replayed)
}

#[test]
fn reference_bundle_passes_the_independent_oracle() {
    let report = validate_joint_handoff_evidence_bundle(&reference_bundle());
    assert!(report.ok, "{:#?}", report.findings);
}

#[test]
fn registry_lock_matches_the_exact_sixteen_case_catalog() {
    assert_eq!(JOINT_HANDOFF_CASE_DEFINITIONS.len(), JOINT_HANDOFF_CASE_COUNT);
    assert_eq!(joint_handoff_registry_sha256(), JOINT_HANDOFF_ACCEPTED_REGISTRY_SHA256);
}

#[test]
fn unknown_and_duplicate_json_fields_are_rejected() {
    let bundle = reference_bundle();
    let mut value = serde_json::to_value(&bundle).unwrap();
    value.as_object_mut().unwrap().insert("unexpected".to_owned(), serde_json::json!(true));
    let unknown = serde_json::to_vec(&value).unwrap();
    assert!(parse_joint_handoff_evidence_bundle_json(&unknown).is_err());

    let encoded = serde_json::to_string(&bundle).unwrap();
    let duplicate = encoded.replacen("\"claim_id\":", "\"claim_id\":\"forged\",\"claim_id\":", 1);
    assert!(parse_joint_handoff_evidence_bundle_json(duplicate.as_bytes()).is_err());
}

#[test]
fn authenticated_abort_and_commit_for_one_reservation_are_rejected() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "abort-commit-race-abort-wins");
    let event = case
        .trace
        .events
        .iter_mut()
        .find(|event| {
            matches!(
                event.event,
                JointRawEventKind::ReceiptRejected {
                    receipt: JointReceipt::OwnershipCommit(_),
                    ..
                }
            )
        })
        .unwrap();
    let replacement = match &event.event {
        JointRawEventKind::ReceiptRejected { request, envelope, receipt, .. } => {
            JointRawEventKind::ReceiptAccepted {
                request: request.clone(),
                envelope: envelope.clone(),
                receipt: receipt.clone(),
            }
        }
        _ => unreachable!(),
    };
    event.event = replacement;
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "accepted-joint-receipt-rejected-by-oracle"));
}

#[test]
fn effect_cohort_digest_is_recomputed_from_raw_publications() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "effect-commit-wins-freeze");
    for event in &mut case.trace.events {
        if let JointRawEventKind::ReceiptAccepted { request, envelope, receipt } = &mut event.event
            && let JointReceipt::EffectFreeze(freeze) = receipt
        {
            freeze.effect_cohort_digest = Digest::from_bytes([9; 32]);
            sync_request_and_envelope(request, envelope, receipt);
            break;
        }
    }
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "accepted-joint-receipt-rejected-by-oracle"));
}

#[test]
fn prepared_bindings_are_recomputed_instead_of_trusting_the_summary() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "commit-ack-lost-query-close");
    for event in &mut case.trace.events {
        if let JointRawEventKind::ReceiptAccepted { request, envelope, receipt } = &mut event.event
            && let JointReceipt::OwnershipPrepared(prepared) = receipt
        {
            prepared.bindings.destination_state_digest = Digest::from_bytes([8; 32]);
            sync_request_and_envelope(request, envelope, receipt);
            break;
        }
    }
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "accepted-joint-receipt-rejected-by-oracle"));
}

#[test]
fn receipt_parent_chain_tamper_is_rejected_after_payload_reauthentication() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "commit-ack-lost-query-close");
    for event in &mut case.trace.events {
        if let JointRawEventKind::ReceiptAccepted { request, envelope, receipt } = &mut event.event
            && let JointReceipt::Closure(closure) = receipt
        {
            closure.header.previous_digest = Some(Digest::from_bytes([7; 32]));
            sync_request_and_envelope(request, envelope, receipt);
            break;
        }
    }
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "accepted-joint-receipt-rejected-by-oracle"));
}

#[test]
fn activation_attempt_lineage_is_bound_by_the_typed_issuance_binding() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "destination-crash-before-activation");
    for event in &mut case.trace.events {
        if let JointRawEventKind::ReceiptAccepted { request: _, envelope, receipt } =
            &mut event.event
            && let JointReceipt::VisaDestinationActivation(activation) = receipt
        {
            activation.activation_attempt_record_digest = Digest::from_bytes([0xa1; 32]);
            envelope.payload_digest = joint_receipt_payload_digest(receipt).unwrap();
            envelope.authentication = joint_reference_authentication(envelope).unwrap();
            break;
        }
    }
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "accepted-joint-receipt-rejected-by-oracle"));
}

#[test]
fn reauthenticated_activation_cannot_fork_the_source_fence_lineage() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "destination-crash-before-activation");
    for event in &mut case.trace.events {
        if let JointRawEventKind::ReceiptAccepted { request, envelope, receipt } = &mut event.event
            && let JointReceipt::VisaDestinationActivation(activation) = receipt
        {
            activation.source_fence = activation.closure;
            sync_request_and_envelope(request, envelope, receipt);
            break;
        }
    }
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "accepted-joint-receipt-rejected-by-oracle"));
}

#[test]
fn destination_cannot_start_before_commit_closure_and_source_fence() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "destination-crash-before-activation");
    let (commit, closure, activation_command) = case
        .trace
        .events
        .iter()
        .find_map(|event| match &event.event {
            JointRawEventKind::DestinationActivationStarted {
                commit,
                closure,
                activation_command,
            } => Some((*commit, *closure, *activation_command)),
            _ => None,
        })
        .unwrap();
    let commit_position = case
        .trace
        .events
        .iter()
        .position(|event| {
            matches!(
                event.event,
                JointRawEventKind::ReceiptAccepted {
                    receipt: JointReceipt::OwnershipCommit(_),
                    ..
                }
            )
        })
        .unwrap();
    case.trace.events.insert(
        commit_position + 1,
        JointRawEvent {
            index: 0,
            event: JointRawEventKind::DestinationActivationStarted {
                commit,
                closure,
                activation_command,
            },
        },
    );
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "destination-activation-before-source-closure"));
}

#[test]
fn a_rejected_stale_probe_must_show_no_state_change() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "stale-token-scope-epoch-probes");
    for event in &mut case.trace.events {
        if let JointRawEventKind::ReceiptRejected { state_after_sha256, .. } = &mut event.event {
            *state_after_sha256 = "b".repeat(64);
            break;
        }
    }
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "joint-state-observation-mismatch"));
}

#[test]
fn post_freeze_effect_acceptance_is_rejected_even_if_summary_is_unchanged() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "freeze-wins-effect-commit");
    for event in &mut case.trace.events {
        if let JointRawEventKind::EffectPublication { accepted, rejection, .. } = &mut event.event {
            *accepted = true;
            *rejection = None;
            break;
        }
    }
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "joint-effect-publication-result-mismatch"));
}

#[test]
fn publisher_cannot_forge_terminal_or_assertions() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "unresolved-tombstone-blocks-seal");
    case.claimed_terminal = JointTerminal::DestinationActive;
    case.claimed_assertions.push(JointAssertion::ClosurePrecededActivation);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "joint-terminal-mismatch"));
    assert!(has_code(&report, "unearned-joint-assertion"));
}

#[test]
fn envelope_authentication_and_payload_digest_are_not_boolean_claims() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "effect-commit-wins-freeze");
    for event in &mut case.trace.events {
        if let JointRawEventKind::ReceiptAccepted { envelope, .. } = &mut event.event {
            envelope.authentication.clear();
            envelope.payload_digest = Digest::from_bytes([6; 32]);
            break;
        }
    }
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "accepted-joint-receipt-rejected-by-oracle"));
}

#[test]
fn exact_receipt_retry_requires_the_same_typed_issuance_binding_digest() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "duplicate-reordered-receipts");
    let mut seen = 0;
    for event in &mut case.trace.events {
        if let JointRawEventKind::ReceiptAccepted { request, envelope, receipt } = &mut event.event
            && matches!(receipt, JointReceipt::PrepareIntent(_))
        {
            seen += 1;
            if seen == 2 {
                request.operation = Identity::from_u128(0xfeed);
                *envelope = joint_receipt_envelope(receipt, request).unwrap();
                break;
            }
        }
    }
    assert_eq!(seen, 2);
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "accepted-joint-receipt-rejected-by-oracle"));
}

#[test]
fn issuance_sequence_and_causal_parameters_are_recomputed_after_outer_reauthentication() {
    for mutate in [
        |request: &mut ReceiptRequest| request.expected_state_sequence += 1,
        |request: &mut ReceiptRequest| {
            let ReceiptRequestParameters::VisaFreeze { intent } = &mut request.parameters else {
                panic!("expected visa-freeze request parameters")
            };
            intent.digest = Digest::from_bytes([0x51; 32]);
        },
    ] {
        let mut bundle = reference_bundle();
        let case = case_mut(&mut bundle, "effect-commit-wins-freeze");
        let (request, envelope) = case
            .trace
            .events
            .iter_mut()
            .find_map(|event| match &mut event.event {
                JointRawEventKind::ReceiptAccepted {
                    request,
                    envelope,
                    receipt: JointReceipt::VisaFreeze(_),
                } => Some((request, envelope)),
                _ => None,
            })
            .unwrap();
        mutate(request);
        envelope.request_digest = joint_receipt_request_digest(request).unwrap();
        envelope.authentication = joint_reference_authentication(envelope).unwrap();
        refresh_trace(case);
        let report = validate_joint_handoff_evidence_bundle(&bundle);
        assert!(!report.ok);
        assert!(has_code(&report, "accepted-joint-receipt-rejected-by-oracle"));
    }
}

#[test]
fn exact_case_set_and_tcb_nonclaims_are_fail_closed() {
    let mut missing = reference_bundle();
    missing.cases.pop();
    let report = validate_joint_handoff_evidence_bundle(&missing);
    assert!(!report.ok);
    assert!(has_code(&report, "invalid-joint-case-count"));

    let mut overclaim = reference_bundle();
    overclaim.tcb.exclusive_trusted_coordinator_api = false;
    overclaim.tcb.host_reboot_covered = true;
    overclaim.tcb.hostile_storage_rollback_covered = true;
    let report = validate_joint_handoff_evidence_bundle(&overclaim);
    assert!(!report.ok);
    assert!(has_code(&report, "invalid-joint-tcb-declaration"));
}

#[test]
fn every_case_has_a_unique_deterministic_authority_namespace() {
    let first = reference_bundle();
    let second = reference_bundle();
    assert_eq!(first, second);

    let mut handoffs = BTreeSet::new();
    let mut reservations = BTreeSet::new();
    let mut logs = BTreeSet::new();
    for case in &first.cases {
        assert!(handoffs.insert(case.trace.key.handoff));
        for issuer in [
            case.trace.issuers.ownership,
            case.trace.issuers.visa_source,
            case.trace.issuers.visa_destination,
            case.trace.issuers.effect_closure,
        ] {
            assert!(logs.insert((
                issuer.issuer,
                issuer.issuer_incarnation,
                issuer.key_id,
                issuer.log_id,
            )));
        }
        let reservation = case
            .trace
            .events
            .iter()
            .find_map(|event| match &event.event {
                JointRawEventKind::ReceiptAccepted {
                    receipt: JointReceipt::PrepareIntent(receipt),
                    ..
                } => Some(receipt.reservation),
                _ => None,
            })
            .unwrap();
        assert!(reservations.insert(reservation));
    }

    let mut aliased = first;
    aliased.cases[1].trace.key.handoff = aliased.cases[0].trace.key.handoff;
    let report = validate_joint_handoff_evidence_bundle(&aliased);
    assert!(!report.ok);
    assert!(has_code(&report, "duplicate-joint-case-handoff"));
}

#[test]
fn lost_commit_ack_is_recovered_by_exact_query_then_local_replay() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "commit-ack-lost-query-close");
    let fault_index = case
        .trace
        .events
        .iter()
        .position(|event| {
            matches!(
                event.event,
                JointRawEventKind::ExternalFault {
                    fault: JointExternalFault::CommitAcknowledgementLost { .. },
                    ..
                }
            )
        })
        .unwrap();
    assert!(matches!(
        case.trace.events[fault_index + 1].event,
        JointRawEventKind::OwnershipQuery { result: OwnershipQueryResult::Unavailable }
    ));
    let durable = match &case.trace.events[fault_index].event {
        JointRawEventKind::ExternalFault {
            fault: JointExternalFault::CommitAcknowledgementLost { durable_commit },
            ..
        } => durable_commit.as_ref().clone(),
        _ => unreachable!(),
    };
    let recovered = match &case.trace.events[fault_index + 2].event {
        JointRawEventKind::OwnershipQuery {
            result: OwnershipQueryResult::CommitDecided { observation },
        } => observation.clone(),
        _ => panic!("lost commit was not recovered by a terminal query"),
    };
    assert_eq!(recovered, durable);
    assert!(matches!(
        &case.trace.events[fault_index + 3].event,
        JointRawEventKind::ReceiptAccepted {
            request,
            envelope,
            receipt: JointReceipt::OwnershipCommit(receipt),
        } if *request == recovered.request
            && *envelope == recovered.envelope
            && *receipt == recovered.receipt
    ));

    if let JointRawEventKind::OwnershipQuery {
        result: OwnershipQueryResult::CommitDecided { observation },
    } = &mut case.trace.events[fault_index + 2].event
    {
        observation.receipt.non_equivocation_root = Digest::from_bytes([0x44; 32]);
        let receipt = JointReceipt::OwnershipCommit(observation.receipt.clone());
        observation.request = joint_receipt_request(&receipt, observation.request.operation);
        observation.envelope = joint_receipt_envelope(&receipt, &observation.request).unwrap();
    }
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "invalid-terminal-ownership-query"));
}

#[test]
fn restart_and_reference_authentication_are_not_publisher_booleans() {
    let mut bundle = reference_bundle();
    let case = case_mut(&mut bundle, "source-crash-after-commit-before-close");
    let trace_json = serde_json::to_string(&case.trace).unwrap();
    assert!(!trace_json.contains("fail_closed"));

    let (envelope, receipt) = case
        .trace
        .events
        .iter_mut()
        .find_map(|event| match &mut event.event {
            JointRawEventKind::ReceiptAccepted { envelope, receipt, .. } => {
                Some((envelope, receipt))
            }
            _ => None,
        })
        .unwrap();
    assert!(envelope.authentication.starts_with(JOINT_REFERENCE_AUTHENTICATION_SCHEME.as_bytes()));
    envelope.authentication[0] ^= 1;
    let _ = receipt;
    refresh_trace(case);
    let report = validate_joint_handoff_evidence_bundle(&bundle);
    assert!(!report.ok);
    assert!(has_code(&report, "accepted-joint-receipt-rejected-by-oracle"));
}

#[test]
fn artifact_verifier_binds_exact_inventory_and_production_report() {
    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);
    let mut bundle = reference_bundle();
    let (accepted, rejected, replayed) = production_counts(&bundle);
    let report = serde_json::json!({
        "case_count": bundle.cases.len(),
        "accepted_receipts": accepted,
        "rejected_receipts": rejected,
        "replayed_receipts": replayed,
        "all_matched": true,
        "reference_cell": {
            "schema_version": "visa-joint-reference-peer-cell-v1",
            "fixed_case_count": JOINT_HANDOFF_CASE_COUNT,
            "scenario_count": 1,
            "all_passed": true,
            "traces": [{"case_id": "placeholder"}],
        },
        "durable_projection_cell": {
            "schema": "visa.joint-handoff.durable-projection-cell.v1",
            "record_count": 3,
            "recovered_phase": "frozen-unsealed",
            "recovered_authentication_count": 3,
            "unknown_effect_freeze_retained": true,
            "abort_blocked_while_unknown": true,
        },
        "host_substrate_cell": {
            "schema": "visa.joint-handoff.host-substrate-cell.v1",
            "lifecycle": [
                "source-activated",
                "source-quiescing",
                "source-frozen",
                "source-exported",
                "destination-restored",
                "destination-prepared",
                "source-committed-fenced",
                "destination-committed",
                "destination-running-active",
                "source-reopened-committed-fenced",
            ],
            "receipt_chain": [
                "prepare-intent",
                "visa-freeze",
                "nexus-freeze",
                "destination-prepared",
                "ownership-prepared",
                "ownership-commit",
                "closure",
                "visa-source-fence",
                "visa-destination-activation",
            ],
            "authenticated_receipt_count": 9,
            "joint_phase": "destination-active",
            "source_reopened": true,
            "source_phase": "committed",
            "source_activation": "fenced",
            "source_owner_is_destination": true,
            "destination_phase": "running",
            "destination_activation": "active",
            "destination_owner_is_destination": true,
            "source_component_generation": 0,
            "destination_component_generation": 1,
            "source_journal_position": 5,
            "destination_journal_position": 8,
            "source_state_digest": vec![1; 32],
            "destination_state_digest": vec![2; 32],
            "snapshot_integrity": vec![3; 32],
            "prepared_destination_digest": vec![4; 32],
            "lease_commit_request_digest": vec![5; 32],
            "independent_source_destination_databases": true,
            "same_boot_only": true,
        },
    });
    let mut report_bytes = serde_json::to_vec_pretty(&report).unwrap();
    report_bytes.push(b'\n');
    bundle.production_replay_sha256 = Some(sha256_hex(&report_bytes));
    seal_joint_evidence_bundle_id(&mut bundle).unwrap();
    let mut bundle_bytes = serde_json::to_vec_pretty(&bundle).unwrap();
    bundle_bytes.push(b'\n');
    let root = std::env::temp_dir().join(format!(
        "visa-joint-artifact-verifier-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("joint-handoff-evidence.json"), &bundle_bytes).unwrap();
    fs::write(root.join("production-replay.json"), &report_bytes).unwrap();

    let gate = gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations(
        &bundle_bytes,
        &root,
        &expectations(),
    );
    assert!(!gate.ok);
    assert!(gate_has_code(&gate, "invalid-joint-reference-cell-report"));

    report_bytes.push(b' ');
    fs::write(root.join("production-replay.json"), &report_bytes).unwrap();
    let gate = gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations(
        &bundle_bytes,
        &root,
        &expectations(),
    );
    assert!(!gate.ok);
    assert!(gate_has_code(&gate, "joint-production-replay-digest-mismatch"));
    fs::remove_dir_all(root).unwrap();
}
