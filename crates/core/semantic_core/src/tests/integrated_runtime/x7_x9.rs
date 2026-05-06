use super::*;

pub(in crate::tests) fn x7_code_publish_smp_workload_graph() -> SemanticGraph {
    let mut graph = s15_stress_graph(true);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "x7-test",
        SemanticCommand::RecordSmpStressRun {
            run: 191,
            scenario: "s15-smp-stress-property".to_string(),
            iterations: 3,
            invariant_checks: 6,
            reason: "smp-stress-property-tests".to_string(),
            note: "stress code publish cleanup snapshot properties".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    graph
}

#[test]
pub(in crate::tests) fn integrated_runtime_x7_records_code_publish_smp_workload() {
    let mut graph = x7_code_publish_smp_workload_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        22,
        "x7-test",
        SemanticCommand::RecordIntegratedCodePublishSmpWorkload {
            integrated: 902,
            scenario: "x7-code-publish-while-smp-workload-active".to_string(),
            smp_stress_run: 191,
            smp_stress_run_generation: 1,
            smp_code_publish_barrier: 91,
            smp_code_publish_barrier_generation: 1,
            invariant_checks: 7,
            note: "integrate code publish barrier with SMP workload evidence".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.integrated_code_publish_smp_workload_count(), 1);
    let record = &graph.integrated_code_publish_smp_workloads()[0];
    assert_eq!(record.id, 902);
    assert_eq!(record.smp_stress_run, 191);
    assert_eq!(record.smp_code_publish_barrier, 91);
    assert_eq!(record.publish_rendezvous, 81);
    assert_eq!(record.publish_safe_point, 71);
    assert_eq!(record.hart_count, 2);
    assert_eq!(record.workload_iterations, 3);
    assert_eq!(record.observed_code_publish_barrier_count, 1);
    assert_eq!(record.code_publish_epoch_before, 0);
    assert_eq!(record.code_publish_epoch_after, 1);
    assert!(record.remote_icache_sync_required);
    assert!(!record.code_publish_executed);
    assert_eq!(record.participant_count, 2);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IntegratedCodePublishSmpWorkloadRecorded integrated=902 scenario=x7-code-publish-while-smp-workload-active stress_run=191@1 code_publish_barrier=91@1 rendezvous=81@1 safe_point=71@1 code_publish_epoch=0->1 harts=2 iterations=3 invariant_checks=7 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn integrated_runtime_x7_rejects_missing_or_stale_publish_evidence() {
    let missing = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x7-test",
        SemanticCommand::RecordIntegratedCodePublishSmpWorkload {
            integrated: 902,
            scenario: "x7-code-publish-while-smp-workload-active".to_string(),
            smp_stress_run: 191,
            smp_stress_run_generation: 1,
            smp_code_publish_barrier: 91,
            smp_code_publish_barrier_generation: 1,
            invariant_checks: 7,
            note: "missing evidence rejects".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    assert_eq!(
        missing.violations,
        vec!["integrated code-publish/SMP workload missing stress evidence".to_string()]
    );

    let stale = x7_code_publish_smp_workload_graph().apply_envelope(CommandEnvelope::new(
        22,
        "x7-test",
        SemanticCommand::RecordIntegratedCodePublishSmpWorkload {
            integrated: 902,
            scenario: "x7-code-publish-while-smp-workload-active".to_string(),
            smp_stress_run: 191,
            smp_stress_run_generation: 1,
            smp_code_publish_barrier: 91,
            smp_code_publish_barrier_generation: 2,
            invariant_checks: 7,
            note: "stale publish barrier rejects".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["integrated code-publish/SMP workload missing code publish barrier".to_string()]
    );
}

#[test]
pub(in crate::tests) fn integrated_runtime_x7_contract_graph_rejects_epoch_drift() {
    let mut graph = x7_code_publish_smp_workload_graph();
    assert!(graph.record_integrated_code_publish_smp_workload_with_id(
        902,
        "x7-code-publish-while-smp-workload-active",
        191,
        1,
        91,
        1,
        7,
        "integrated code publish smp workload",
    ));
    let mut integrated = graph.integrated_code_publish_smp_workloads().to_vec();
    integrated[0].code_publish_epoch_after = 2;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_code_publish_smp_workloads: integrated,
        smp_stress_runs: graph.smp_stress_runs().to_vec(),
        smp_code_publish_barriers: graph.smp_code_publish_barriers().to_vec(),
        stop_the_world_rendezvous: graph.stop_the_world_rendezvous().to_vec(),
        smp_safe_points: graph.smp_safe_points().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-code-publish-smp-workload->contract"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

pub(in crate::tests) fn x8_integrated_display_panic_graph() -> SemanticGraph {
    let (mut graph, owner_store, owner_store_generation, payload_digest, summary_digest) =
        g11_display_panic_last_frame_graph();
    assert!(graph.record_display_panic_last_frame_with_id(
        25_001,
        owner_store,
        owner_store_generation,
        24_011,
        1,
        23_801,
        1,
        23_501,
        1,
        23_601,
        1,
        payload_digest,
        summary_digest,
        512,
        1,
        "contract-panic-summary-v1",
        false,
        "x8 panic last-frame evidence",
    ));
    graph.record_substrate_panic(
        "PanicRing",
        "extract-after-substrate-panic",
        Some("substrate.panic".to_string()),
        None,
        None,
        1,
        0,
        1,
    );
    graph
}

#[test]
pub(in crate::tests) fn integrated_runtime_x8_records_panic_ring_extraction() {
    let mut graph = x8_integrated_display_panic_graph();
    let substrate_panic_event = graph.event_log_tail(1)[0].id;
    let result = graph.apply_envelope(CommandEnvelope::new(
        23,
        "x8-test",
        SemanticCommand::RecordIntegratedDisplayPanic {
            integrated: 903,
            scenario: "x8-panic-ring-extraction-after-substrate-panic".to_string(),
            substrate_panic_event,
            display_panic_last_frame: 25_001,
            display_panic_last_frame_generation: 1,
            panic_ring_bytes: 65_536,
            panic_record_max_bytes: 4_096,
            panic_ring_oldest_seq: 1,
            panic_ring_newest_seq: 3,
            panic_ring_record_count: 3,
            panic_ring_lost_count: 0,
            jsonl_frame_count: 5,
            contract_panic_summary_records: 1,
            last_frame_summary_records: 1,
            corrupt_record_count: 0,
            truncated_record_count: 0,
            invariant_checks: 8,
            note: "integrate substrate panic ring extraction with display panic evidence"
                .to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.integrated_display_panic_count(), 1);
    let record = &graph.integrated_display_panics()[0];
    assert_eq!(record.id, 903);
    assert_eq!(record.substrate_panic_event, substrate_panic_event);
    assert_eq!(record.display_panic_last_frame, 25_001);
    assert_eq!(record.panic_ring_record_count, 3);
    assert_eq!(record.jsonl_frame_count, 5);
    assert_eq!(record.contract_panic_summary_records, 1);
    assert_eq!(record.corrupt_record_count, 0);
    assert!(!record.raw_framebuffer_bytes_exported);
    assert!(!record.panic_path_allocates);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "IntegratedDisplayPanicRecorded integrated=903 scenario=x8-panic-ring-extraction-after-substrate-panic substrate_panic_event={substrate_panic_event} display_panic_last_frame=25001@1 panic_ring_records=3 lost=0 jsonl_frames=5 contract_panic_summary_records=1 last_frame_summary_records=1 corrupt_records=0 truncated_records=0 invariant_checks=8 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn integrated_runtime_x8_rejects_missing_or_corrupt_panic_evidence() {
    let missing = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x8-test",
        SemanticCommand::RecordIntegratedDisplayPanic {
            integrated: 903,
            scenario: "x8-panic-ring-extraction-after-substrate-panic".to_string(),
            substrate_panic_event: 1,
            display_panic_last_frame: 25_001,
            display_panic_last_frame_generation: 1,
            panic_ring_bytes: 65_536,
            panic_record_max_bytes: 4_096,
            panic_ring_oldest_seq: 1,
            panic_ring_newest_seq: 3,
            panic_ring_record_count: 3,
            panic_ring_lost_count: 0,
            jsonl_frame_count: 5,
            contract_panic_summary_records: 1,
            last_frame_summary_records: 1,
            corrupt_record_count: 0,
            truncated_record_count: 0,
            invariant_checks: 8,
            note: "missing display panic frame rejects".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    assert_eq!(
        missing.violations,
        vec!["integrated display panic missing last-frame evidence".to_string()]
    );

    let mut graph = x8_integrated_display_panic_graph();
    let substrate_panic_event = graph.event_log_tail(1)[0].id;
    let corrupt = graph.apply_envelope(CommandEnvelope::new(
        23,
        "x8-test",
        SemanticCommand::RecordIntegratedDisplayPanic {
            integrated: 903,
            scenario: "x8-panic-ring-extraction-after-substrate-panic".to_string(),
            substrate_panic_event,
            display_panic_last_frame: 25_001,
            display_panic_last_frame_generation: 1,
            panic_ring_bytes: 65_536,
            panic_record_max_bytes: 4_096,
            panic_ring_oldest_seq: 1,
            panic_ring_newest_seq: 3,
            panic_ring_record_count: 3,
            panic_ring_lost_count: 0,
            jsonl_frame_count: 5,
            contract_panic_summary_records: 1,
            last_frame_summary_records: 1,
            corrupt_record_count: 1,
            truncated_record_count: 0,
            invariant_checks: 8,
            note: "corrupt panic ring extraction rejects".to_string(),
        },
    ));
    assert_eq!(corrupt.status, CommandStatus::Rejected);
    assert_eq!(
        corrupt.violations,
        vec!["integrated display panic requires clean panic-ring extraction evidence".to_string()]
    );
}

#[test]
pub(in crate::tests) fn integrated_runtime_x8_contract_graph_rejects_last_frame_drift() {
    let mut graph = x8_integrated_display_panic_graph();
    let substrate_panic_event = graph.event_log_tail(1)[0].id;
    assert!(graph.record_integrated_display_panic_with_id(
        903,
        "x8-panic-ring-extraction-after-substrate-panic",
        substrate_panic_event,
        25_001,
        1,
        65_536,
        4_096,
        1,
        3,
        3,
        0,
        5,
        1,
        1,
        0,
        0,
        8,
        "integrated display panic",
    ));
    let mut frames = graph.display_panic_last_frames().to_vec();
    frames[0].raw_framebuffer_bytes_exported = true;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        display_panic_last_frames: frames,
        integrated_display_panics: graph.integrated_display_panics().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-panic-last-frame->contract"
            || violation.edge == "integrated-display-panic->last-frame-binding"
    }));
}

#[test]
pub(in crate::tests) fn integrated_runtime_x9_rejects_missing_or_incomplete_replay_evidence() {
    let missing_sources = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x9-test",
        SemanticCommand::RecordIntegratedOsctlTraceReplay {
            integrated: 904,
            scenario: "x9-full-osctl-trace-replay".to_string(),
            integrated_smp_preemption_cleanup: 301,
            integrated_smp_preemption_cleanup_generation: 1,
            integrated_smp_network_fault: 401,
            integrated_smp_network_fault_generation: 1,
            integrated_disk_preempt_fault: 501,
            integrated_disk_preempt_fault_generation: 1,
            integrated_simd_migration: 601,
            integrated_simd_migration_generation: 1,
            integrated_network_disk_io: 701,
            integrated_network_disk_io_generation: 1,
            integrated_display_scheduler_load: 801,
            integrated_display_scheduler_load_generation: 1,
            integrated_snapshot_io_lease_barrier: 901,
            integrated_snapshot_io_lease_barrier_generation: 1,
            integrated_code_publish_smp_workload: 902,
            integrated_code_publish_smp_workload_generation: 1,
            integrated_display_panic: 903,
            integrated_display_panic_generation: 1,
            replay_event_cursor: 1,
            stable_view_count: 9,
            historical_edge_count: 9,
            replayed_root_count: 9,
            integrated_scenario_count: 9,
            replay_fixture_count: 9,
            invariant_checks: 9,
            note: "missing integrated scenario evidence rejects".to_string(),
        },
    ));
    assert_eq!(missing_sources.status, CommandStatus::Rejected);
    assert_eq!(
        missing_sources.violations,
        vec!["integrated osctl trace replay missing integrated scenario evidence".to_string()]
    );

    let incomplete_evidence = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x9-test",
        SemanticCommand::RecordIntegratedOsctlTraceReplay {
            integrated: 904,
            scenario: "x9-full-osctl-trace-replay".to_string(),
            integrated_smp_preemption_cleanup: 301,
            integrated_smp_preemption_cleanup_generation: 1,
            integrated_smp_network_fault: 401,
            integrated_smp_network_fault_generation: 1,
            integrated_disk_preempt_fault: 501,
            integrated_disk_preempt_fault_generation: 1,
            integrated_simd_migration: 601,
            integrated_simd_migration_generation: 1,
            integrated_network_disk_io: 701,
            integrated_network_disk_io_generation: 1,
            integrated_display_scheduler_load: 801,
            integrated_display_scheduler_load_generation: 1,
            integrated_snapshot_io_lease_barrier: 901,
            integrated_snapshot_io_lease_barrier_generation: 1,
            integrated_code_publish_smp_workload: 902,
            integrated_code_publish_smp_workload_generation: 1,
            integrated_display_panic: 903,
            integrated_display_panic_generation: 1,
            replay_event_cursor: 1,
            stable_view_count: 8,
            historical_edge_count: 9,
            replayed_root_count: 9,
            integrated_scenario_count: 9,
            replay_fixture_count: 9,
            invariant_checks: 9,
            note: "incomplete stable view evidence rejects".to_string(),
        },
    ));
    assert_eq!(incomplete_evidence.status, CommandStatus::Rejected);
    assert_eq!(
        incomplete_evidence.violations,
        vec!["integrated osctl trace replay requires complete stable evidence".to_string()]
    );
}

#[test]
pub(in crate::tests) fn integrated_runtime_x9_contract_graph_rejects_dangling_integrated_history() {
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_osctl_trace_replays: vec![IntegratedOsctlTraceReplayRecord {
            id: 904,
            scenario: "x9-full-osctl-trace-replay".to_string(),
            integrated_smp_preemption_cleanup: 301,
            integrated_smp_preemption_cleanup_generation: 1,
            integrated_smp_network_fault: 401,
            integrated_smp_network_fault_generation: 1,
            integrated_disk_preempt_fault: 501,
            integrated_disk_preempt_fault_generation: 1,
            integrated_simd_migration: 601,
            integrated_simd_migration_generation: 1,
            integrated_network_disk_io: 701,
            integrated_network_disk_io_generation: 1,
            integrated_display_scheduler_load: 801,
            integrated_display_scheduler_load_generation: 1,
            integrated_snapshot_io_lease_barrier: 901,
            integrated_snapshot_io_lease_barrier_generation: 1,
            integrated_code_publish_smp_workload: 902,
            integrated_code_publish_smp_workload_generation: 1,
            integrated_display_panic: 903,
            integrated_display_panic_generation: 1,
            replay_event_cursor: 579,
            stable_view_count: 9,
            historical_edge_count: 9,
            replayed_root_count: 9,
            integrated_scenario_count: 9,
            replay_fixture_count: 9,
            contract_validation_ok: true,
            replay_validation_ok: true,
            graph_history_ok: true,
            roots_match_counts: true,
            invariant_checks: 9,
            generation: 1,
            state: IntegratedOsctlTraceReplayState::Recorded,
            recorded_at_event: 580,
            note: "missing referenced integrated history rejects".to_string(),
        }],
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-osctl-trace-replay->x0-smp-preemption-cleanup"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-osctl-trace-replay->x8-display-panic"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}
