use super::*;

pub(in crate::tests) fn g9_display_cleanup_graph() -> (SemanticGraph, StoreId, Generation) {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_dirty_region,
        framebuffer_dirty_region_generation,
        first_event,
        last_event,
        event_count,
        flush_count,
        dirty_region_count,
    ) = g8_display_event_log_graph();
    assert!(graph.record_display_event_log_with_id(
        23_801,
        owner_store,
        owner_store_generation,
        framebuffer_dirty_region,
        framebuffer_dirty_region_generation,
        first_event,
        last_event,
        event_count,
        flush_count,
        dirty_region_count,
        "g8 display event log for g9",
    ));
    (graph, owner_store, owner_store_generation)
}

#[test]
pub(in crate::tests) fn display_runtime_g9_cleanup_releases_leases_mappings_and_revokes_capability()
{
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        11,
        "display-runtime-g9",
        SemanticCommand::CleanupDisplay {
            cleanup: 23_901,
            owner_store,
            owner_store_generation,
            display_capability: 23_201,
            display_capability_generation: 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            reason: "display-window-cleanup".to_string(),
            note: "g9 display cleanup".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.display_cleanup_count(), 1);
    assert_eq!(graph.active_framebuffer_mapping_count(), 0);
    assert_eq!(graph.active_framebuffer_window_lease_count(), 0);
    assert_eq!(graph.framebuffer_mappings()[0].state, FramebufferMappingState::Unmapped);
    assert_eq!(graph.framebuffer_window_leases()[0].state, FramebufferWindowLeaseState::Released);
    assert_eq!(graph.display_capabilities()[0].state, DisplayCapabilityState::Revoked);
    let cleanup = &graph.display_cleanups()[0];
    assert_eq!(
        cleanup.object_ref(),
        ContractObjectRef::new(ContractObjectKind::DisplayCleanup, 23_901, 1)
    );
    assert_eq!(cleanup.unmapped_framebuffer_mappings.len(), 1);
    assert_eq!(cleanup.released_framebuffer_window_leases.len(), 1);
    assert_eq!(cleanup.revoked_display_capabilities.len(), 1);
    assert_eq!(cleanup.revoked_capabilities.len(), 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DisplayCleanupCompleted cleanup=23901 owner_store={owner_store}@{owner_store_generation} display_capability=23201@1 display=23101@1 framebuffer=23001@1 unmapped_framebuffer_mappings=1 released_framebuffer_window_leases=1 revoked_display_capabilities=1 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g9_rejects_stale_cleanup_and_blocks_post_cleanup_write() {
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();

    let stale = graph.apply_envelope(CommandEnvelope::new(
        11,
        "display-runtime-g9",
        SemanticCommand::CleanupDisplay {
            cleanup: 23_902,
            owner_store,
            owner_store_generation,
            display_capability: 23_201,
            display_capability_generation: 2,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            reason: "display-window-cleanup".to_string(),
            note: "g9 stale display cleanup".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    assert!(graph.cleanup_display_for_store_with_id(
        23_903,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "g9 cleanup before write rejection",
    ));
    let blocked_write = graph.apply_envelope(CommandEnvelope::new(
        12,
        "display-runtime-g9",
        SemanticCommand::RecordFramebufferWrite {
            framebuffer_write: 23_902,
            owner_store,
            owner_store_generation,
            framebuffer_mapping: 23_401,
            framebuffer_mapping_generation: 1,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest: SemanticGraph::expected_framebuffer_write_payload_digest_v1(
                23_401, 1, 23_001, 1, 0, 0, 800, 1, 0, 3_200,
            ),
            note: "g9 post-cleanup write must fail".to_string(),
        },
    ));
    assert_eq!(blocked_write.status, CommandStatus::Rejected);

    assert!(graph.cleanup_display_for_store_with_id(
        23_903,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "g9 idempotent cleanup",
    ));
    assert_eq!(graph.display_cleanup_count(), 1);
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g9_rejects_cleanup_when_underlying_capability_is_not_active()
 {
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();
    let display_capability = graph.display_capabilities()[0].clone();
    let subject =
        graph.capabilities().record(display_capability.capability).unwrap().subject.clone();

    graph.revoke_capabilities_for_subject(&subject);

    assert!(!graph.cleanup_display_for_store_with_id(
        23_906,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "g9 reject cleanup with stale ledger cap",
    ));
    assert_eq!(graph.display_cleanup_count(), 0);
    assert_eq!(graph.framebuffer_mappings()[0].state, FramebufferMappingState::Active);
    assert_eq!(graph.framebuffer_window_leases()[0].state, FramebufferWindowLeaseState::Active);
    assert_eq!(graph.display_capabilities()[0].state, DisplayCapabilityState::Active);
}

#[test]
pub(in crate::tests) fn display_runtime_g9_invariants_reject_cleanup_effect_generation_drift() {
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();
    assert!(graph.cleanup_display_for_store_with_id(
        23_904,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "g9 corrupt cleanup",
    ));
    graph.corrupt_display_cleanup_mapping_effect_for_test(23_904, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DisplayCleanupMissingEffectTarget {
            cleanup: 23_904,
            target: ContractObjectRef::new(ContractObjectKind::FramebufferMapping, 23_401, 99),
        })
    );
}

#[test]
pub(in crate::tests) fn display_runtime_g9_contract_graph_rejects_missing_cleanup_effect() {
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();
    assert!(graph.cleanup_display_for_store_with_id(
        23_905,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "g9 graph cleanup",
    ));
    let mut display_cleanups = graph.display_cleanups().to_vec();
    display_cleanups[0].released_framebuffer_window_leases[0].generation = 99;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        display_capabilities: graph.display_capabilities().to_vec(),
        framebuffer_window_leases: graph.framebuffer_window_leases().to_vec(),
        framebuffer_mappings: graph.framebuffer_mappings().to_vec(),
        framebuffer_writes: graph.framebuffer_writes().to_vec(),
        framebuffer_flush_regions: graph.framebuffer_flush_regions().to_vec(),
        framebuffer_dirty_regions: graph.framebuffer_dirty_regions().to_vec(),
        display_event_logs: graph.display_event_logs().to_vec(),
        display_cleanups,
        stores: graph.stores().to_vec(),
        capabilities: graph.capabilities().records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-cleanup->released-framebuffer-window-lease"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

#[test]
pub(in crate::tests) fn display_runtime_g10_snapshot_barrier_rejects_active_display_leases() {
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        12,
        "display-runtime-g10",
        SemanticCommand::ValidateDisplaySnapshotBarrier {
            barrier: 24_001,
            owner_store,
            owner_store_generation,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            display_cleanup: None,
            display_cleanup_generation: None,
            reason: "display-snapshot-barrier".to_string(),
            note: "g10 active lease must block snapshot".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Rejected);
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.contains("display state is not quiescent"))
    );
    assert_eq!(graph.display_snapshot_barrier_count(), 0);
}

#[test]
pub(in crate::tests) fn display_runtime_g10_snapshot_barrier_validates_after_cleanup() {
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();
    assert!(graph.cleanup_display_for_store_with_id(
        23_907,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "g10 cleanup before snapshot",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        12,
        "display-runtime-g10",
        SemanticCommand::ValidateDisplaySnapshotBarrier {
            barrier: 24_002,
            owner_store,
            owner_store_generation,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            display_cleanup: Some(23_907),
            display_cleanup_generation: Some(1),
            reason: "display-snapshot-barrier".to_string(),
            note: "g10 display snapshot after cleanup".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    let barrier = &graph.display_snapshot_barriers()[0];
    assert_eq!(
        barrier.object_ref(),
        ContractObjectRef::new(ContractObjectKind::DisplaySnapshotBarrier, 24_002, 1)
    );
    assert_eq!(barrier.active_framebuffer_window_lease_count, 0);
    assert_eq!(barrier.active_framebuffer_mapping_count, 0);
    assert_eq!(barrier.dirty_framebuffer_region_count, 0);
    assert!(barrier.snapshot_validation_ok);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DisplaySnapshotBarrierValidated barrier=24002 owner_store={owner_store}@{owner_store_generation} display=23101@1 framebuffer=23001@1 display_cleanup=23907:1 active_framebuffer_window_leases=0 active_framebuffer_mappings=0 dirty_framebuffer_regions=0 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g10_snapshot_barrier_rejects_dirty_framebuffer_region_after_cleanup()
 {
    let (mut graph, owner_store, owner_store_generation, mapping, mapping_generation) =
        g5_framebuffer_write_graph();
    let payload_digest = SemanticGraph::expected_framebuffer_write_payload_digest_v1(
        mapping,
        mapping_generation,
        23_001,
        1,
        0,
        0,
        800,
        1,
        0,
        3_200,
    );
    assert!(graph.record_framebuffer_write_with_id(
        23_508,
        owner_store,
        owner_store_generation,
        mapping,
        mapping_generation,
        0,
        0,
        800,
        1,
        0,
        3_200,
        payload_digest,
        "g10 dirty write",
    ));
    assert!(graph.record_framebuffer_dirty_region_with_id(
        23_708,
        owner_store,
        owner_store_generation,
        23_508,
        1,
        None,
        None,
        FramebufferDirtyRegionState::Dirty,
        0,
        0,
        800,
        1,
        0,
        3_200,
        payload_digest,
        "g10 dirty region must block snapshot",
    ));
    assert!(graph.cleanup_display_for_store_with_id(
        23_908,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "g10 cleanup leaves dirty region",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        12,
        "display-runtime-g10",
        SemanticCommand::ValidateDisplaySnapshotBarrier {
            barrier: 24_003,
            owner_store,
            owner_store_generation,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            display_cleanup: Some(23_908),
            display_cleanup_generation: Some(1),
            reason: "display-snapshot-barrier".to_string(),
            note: "g10 dirty framebuffer region rejects snapshot".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Rejected);
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.contains("display state is not quiescent"))
    );
    assert_eq!(graph.display_snapshot_barrier_count(), 0);
}

#[test]
pub(in crate::tests) fn display_runtime_g10_invariants_reject_snapshot_barrier_dirty_count_drift() {
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();
    assert!(graph.cleanup_display_for_store_with_id(
        23_909,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "g10 cleanup before corrupt barrier",
    ));
    assert!(graph.validate_display_snapshot_barrier_with_id(
        24_004,
        owner_store,
        owner_store_generation,
        23_101,
        1,
        23_001,
        1,
        Some(23_909),
        Some(1),
        "display-snapshot-barrier",
        "g10 corrupt barrier",
    ));
    graph.corrupt_display_snapshot_barrier_dirty_count_for_test(24_004, 1);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DisplaySnapshotBarrierInvalid { barrier: 24_004 })
    );
}

#[test]
pub(in crate::tests) fn display_runtime_g10_contract_graph_rejects_stale_cleanup_ref() {
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();
    assert!(graph.cleanup_display_for_store_with_id(
        23_910,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "g10 cleanup before graph validation",
    ));
    assert!(graph.validate_display_snapshot_barrier_with_id(
        24_005,
        owner_store,
        owner_store_generation,
        23_101,
        1,
        23_001,
        1,
        Some(23_910),
        Some(1),
        "display-snapshot-barrier",
        "g10 graph barrier",
    ));
    let mut barriers = graph.display_snapshot_barriers().to_vec();
    barriers[0].display_cleanup_generation = Some(99);
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        display_cleanups: graph.display_cleanups().to_vec(),
        display_snapshot_barriers: barriers,
        stores: graph.stores().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-snapshot-barrier->display-cleanup"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(in crate::tests) fn g11_display_panic_last_frame_graph()
-> (SemanticGraph, StoreId, Generation, u64, u64) {
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();
    assert!(graph.cleanup_display_for_store_with_id(
        23_911,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "g11 cleanup before panic summary",
    ));
    assert!(graph.validate_display_snapshot_barrier_with_id(
        24_011,
        owner_store,
        owner_store_generation,
        23_101,
        1,
        23_001,
        1,
        Some(23_911),
        Some(1),
        "display-snapshot-barrier",
        "g11 barrier before panic summary",
    ));
    let payload_digest = graph.framebuffer_flush_regions()[0].payload_digest;
    let summary_digest = SemanticGraph::expected_display_panic_last_frame_summary_digest_v1(
        owner_store,
        owner_store_generation,
        23_101,
        1,
        23_001,
        1,
        24_011,
        1,
        23_801,
        1,
        23_501,
        1,
        23_601,
        1,
        payload_digest,
        1,
        0,
        1,
    );
    (graph, owner_store, owner_store_generation, payload_digest, summary_digest)
}

#[test]
pub(in crate::tests) fn display_runtime_g11_records_panic_last_frame_summary() {
    let (mut graph, owner_store, owner_store_generation, payload_digest, summary_digest) =
        g11_display_panic_last_frame_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        13,
        "display-runtime-g11",
        SemanticCommand::RecordDisplayPanicLastFrame {
            panic_last_frame: 25_001,
            owner_store,
            owner_store_generation,
            display_snapshot_barrier: 24_011,
            display_snapshot_barrier_generation: 1,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            payload_digest,
            summary_digest,
            summary_record_bytes: 512,
            panic_epoch: 1,
            panic_record_kind: "contract-panic-summary-v1".to_string(),
            raw_framebuffer_bytes_exported: false,
            note: "g11 panic last-frame".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    let frame = &graph.display_panic_last_frames()[0];
    assert_eq!(
        frame.object_ref(),
        ContractObjectRef::new(ContractObjectKind::DisplayPanicLastFrame, 25_001, 1)
    );
    assert_eq!(frame.display_snapshot_barrier, 24_011);
    assert_eq!(frame.display_event_log, 23_801);
    assert_eq!(frame.framebuffer_flush_region, 23_601);
    assert_eq!(frame.payload_digest, payload_digest);
    assert_eq!(frame.summary_digest, summary_digest);
    assert!(!frame.raw_framebuffer_bytes_exported);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DisplayPanicLastFrameRecorded panic_last_frame=25001 owner_store={owner_store}@{owner_store_generation} display=23101@1 framebuffer=23001@1 barrier=24011@1 display_event_log=23801@1 framebuffer_write=23501@1 framebuffer_flush_region=23601@1 payload_digest={payload_digest} summary_digest={summary_digest} summary_record_bytes=512 panic_epoch=1 panic_cpu=0 panic_reason_code=1 raw_framebuffer_bytes_exported=false generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g11_rejects_raw_bytes_and_stale_barrier() {
    let (mut graph, owner_store, owner_store_generation, payload_digest, summary_digest) =
        g11_display_panic_last_frame_graph();

    let raw_bytes = graph.apply_envelope(CommandEnvelope::new(
        13,
        "display-runtime-g11",
        SemanticCommand::RecordDisplayPanicLastFrame {
            panic_last_frame: 25_002,
            owner_store,
            owner_store_generation,
            display_snapshot_barrier: 24_011,
            display_snapshot_barrier_generation: 1,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            payload_digest,
            summary_digest,
            summary_record_bytes: 512,
            panic_epoch: 1,
            panic_record_kind: "contract-panic-summary-v1".to_string(),
            raw_framebuffer_bytes_exported: true,
            note: "g11 raw bytes rejected".to_string(),
        },
    ));
    assert_eq!(raw_bytes.status, CommandStatus::Rejected);

    let stale_barrier = graph.apply_envelope(CommandEnvelope::new(
        14,
        "display-runtime-g11",
        SemanticCommand::RecordDisplayPanicLastFrame {
            panic_last_frame: 25_003,
            owner_store,
            owner_store_generation,
            display_snapshot_barrier: 24_011,
            display_snapshot_barrier_generation: 2,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            payload_digest,
            summary_digest,
            summary_record_bytes: 512,
            panic_epoch: 1,
            panic_record_kind: "contract-panic-summary-v1".to_string(),
            raw_framebuffer_bytes_exported: false,
            note: "g11 stale barrier rejected".to_string(),
        },
    ));
    assert_eq!(stale_barrier.status, CommandStatus::Rejected);
    assert_eq!(graph.display_panic_last_frame_count(), 0);
}

#[test]
pub(in crate::tests) fn display_runtime_g11_invariants_reject_summary_digest_drift() {
    let (mut graph, owner_store, owner_store_generation, payload_digest, summary_digest) =
        g11_display_panic_last_frame_graph();
    assert!(graph.record_display_panic_last_frame_with_id(
        25_004,
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
        "g11 invariant drift",
    ));
    graph.corrupt_display_panic_last_frame_summary_digest_for_test(25_004, summary_digest ^ 1);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DisplayPanicLastFrameInvalid { panic_last_frame: 25_004 })
    );
}

#[test]
pub(in crate::tests) fn display_runtime_g11_contract_graph_rejects_raw_bytes() {
    let (mut graph, owner_store, owner_store_generation, payload_digest, summary_digest) =
        g11_display_panic_last_frame_graph();
    assert!(graph.record_display_panic_last_frame_with_id(
        25_005,
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
        "g11 contract graph",
    ));
    let mut frames = graph.display_panic_last_frames().to_vec();
    frames[0].raw_framebuffer_bytes_exported = true;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        framebuffer_writes: graph.framebuffer_writes().to_vec(),
        framebuffer_flush_regions: graph.framebuffer_flush_regions().to_vec(),
        display_event_logs: graph.display_event_logs().to_vec(),
        display_snapshot_barriers: graph.display_snapshot_barriers().to_vec(),
        display_panic_last_frames: frames,
        stores: graph.stores().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-panic-last-frame->contract"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
pub(in crate::tests) fn display_runtime_g11_contract_graph_rejects_write_and_flush_binding_mismatch()
 {
    let (mut graph, owner_store, owner_store_generation, payload_digest, summary_digest) =
        g11_display_panic_last_frame_graph();
    assert!(graph.record_display_panic_last_frame_with_id(
        25_006,
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
        "g11 contract graph binding mismatch",
    ));
    let mut frames = graph.display_panic_last_frames().to_vec();
    frames[0].payload_digest ^= 1;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        framebuffer_writes: graph.framebuffer_writes().to_vec(),
        framebuffer_flush_regions: graph.framebuffer_flush_regions().to_vec(),
        display_event_logs: graph.display_event_logs().to_vec(),
        display_snapshot_barriers: graph.display_snapshot_barriers().to_vec(),
        display_panic_last_frames: frames,
        stores: graph.stores().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-panic-last-frame->write-binding"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
    assert!(violations.iter().any(|violation| {
        violation.edge == "display-panic-last-frame->flush-binding"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(in crate::tests) fn g12_framebuffer_benchmark_graph()
-> (SemanticGraph, StoreId, Generation, u64, u64) {
    let (graph, owner_store, owner_store_generation, _, _) = g11_display_panic_last_frame_graph();
    let flush = &graph.framebuffer_flush_regions()[0];
    let sample_bytes = flush.byte_len;
    let frame_area_pixels = u64::from(flush.width) * u64::from(flush.height);
    (graph, owner_store, owner_store_generation, sample_bytes, frame_area_pixels)
}

#[test]
pub(in crate::tests) fn display_runtime_g12_records_framebuffer_benchmark() {
    let (mut graph, owner_store, owner_store_generation, sample_bytes, frame_area_pixels) =
        g12_framebuffer_benchmark_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        15,
        "display-runtime-g12",
        SemanticCommand::RecordFramebufferBenchmark {
            benchmark: 25_101,
            scenario: "display-g12-single-flush".to_string(),
            owner_store,
            owner_store_generation,
            display_capability: 23_201,
            display_capability_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            display_snapshot_barrier: 24_011,
            display_snapshot_barrier_generation: 1,
            sample_frames: 1,
            sample_bytes,
            frame_area_pixels,
            write_nanos: 40_000,
            flush_nanos: 60_000,
            measured_nanos: 100_000,
            budget_nanos: 200_000,
            p50_latency_nanos: 100_000,
            p99_latency_nanos: 100_000,
            note: "g12 framebuffer benchmark".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    let benchmark = &graph.framebuffer_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FramebufferBenchmark, 25_101, 1)
    );
    assert_eq!(benchmark.sample_bytes, sample_bytes);
    assert_eq!(benchmark.frame_area_pixels, frame_area_pixels);
    assert_eq!(benchmark.throughput_bytes_per_sec, 32_000_000);
    assert_eq!(benchmark.flushes_per_sec_milli, 10_000_000);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "FramebufferBenchmarkRecorded benchmark=25101 owner_store={owner_store}@{owner_store_generation} display=23101@1 framebuffer=23001@1 display_capability=23201@1 framebuffer_write=23501@1 framebuffer_flush_region=23601@1 display_event_log=23801@1 display_snapshot_barrier=24011@1 sample_frames=1 sample_bytes={sample_bytes} frame_area_pixels={frame_area_pixels} write_nanos=40000 flush_nanos=60000 measured_nanos=100000 budget_nanos=200000 throughput_bytes_per_sec=32000000 flushes_per_sec_milli=10000000 p50_latency_nanos=100000 p99_latency_nanos=100000 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g12_rejects_stale_barrier_and_bad_timing() {
    let (mut graph, owner_store, owner_store_generation, sample_bytes, frame_area_pixels) =
        g12_framebuffer_benchmark_graph();

    let stale_barrier = graph.apply_envelope(CommandEnvelope::new(
        15,
        "display-runtime-g12",
        SemanticCommand::RecordFramebufferBenchmark {
            benchmark: 25_102,
            scenario: "display-g12-single-flush".to_string(),
            owner_store,
            owner_store_generation,
            display_capability: 23_201,
            display_capability_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            display_snapshot_barrier: 24_011,
            display_snapshot_barrier_generation: 2,
            sample_frames: 1,
            sample_bytes,
            frame_area_pixels,
            write_nanos: 40_000,
            flush_nanos: 60_000,
            measured_nanos: 100_000,
            budget_nanos: 200_000,
            p50_latency_nanos: 100_000,
            p99_latency_nanos: 100_000,
            note: "g12 stale barrier rejected".to_string(),
        },
    ));
    assert_eq!(stale_barrier.status, CommandStatus::Rejected);

    let bad_timing = graph.apply_envelope(CommandEnvelope::new(
        16,
        "display-runtime-g12",
        SemanticCommand::RecordFramebufferBenchmark {
            benchmark: 25_103,
            scenario: "display-g12-single-flush".to_string(),
            owner_store,
            owner_store_generation,
            display_capability: 23_201,
            display_capability_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            display_snapshot_barrier: 24_011,
            display_snapshot_barrier_generation: 1,
            sample_frames: 1,
            sample_bytes,
            frame_area_pixels,
            write_nanos: 40_000,
            flush_nanos: 60_000,
            measured_nanos: 90_000,
            budget_nanos: 200_000,
            p50_latency_nanos: 90_000,
            p99_latency_nanos: 90_000,
            note: "g12 bad timing rejected".to_string(),
        },
    ));
    assert_eq!(bad_timing.status, CommandStatus::Rejected);
    assert_eq!(graph.framebuffer_benchmark_count(), 0);
}

#[test]
pub(in crate::tests) fn display_runtime_g12_invariants_reject_throughput_drift() {
    let (mut graph, owner_store, owner_store_generation, sample_bytes, frame_area_pixels) =
        g12_framebuffer_benchmark_graph();
    assert!(graph.record_framebuffer_benchmark_with_id(
        25_104,
        "display-g12-single-flush",
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_501,
        1,
        23_601,
        1,
        23_801,
        1,
        24_011,
        1,
        1,
        sample_bytes,
        frame_area_pixels,
        40_000,
        60_000,
        100_000,
        200_000,
        100_000,
        100_000,
        "g12 invariant drift",
    ));
    graph.corrupt_framebuffer_benchmark_throughput_for_test(25_104, 1);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FramebufferBenchmarkInvalid { benchmark: 25_104 })
    );
}

#[test]
pub(in crate::tests) fn display_runtime_g12_contract_graph_rejects_metric_drift() {
    let (mut graph, owner_store, owner_store_generation, sample_bytes, frame_area_pixels) =
        g12_framebuffer_benchmark_graph();
    assert!(graph.record_framebuffer_benchmark_with_id(
        25_105,
        "display-g12-single-flush",
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_501,
        1,
        23_601,
        1,
        23_801,
        1,
        24_011,
        1,
        1,
        sample_bytes,
        frame_area_pixels,
        40_000,
        60_000,
        100_000,
        200_000,
        100_000,
        100_000,
        "g12 contract graph",
    ));
    let mut benchmarks = graph.framebuffer_benchmarks().to_vec();
    benchmarks[0].throughput_bytes_per_sec = 1;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        display_capabilities: graph.display_capabilities().to_vec(),
        framebuffer_writes: graph.framebuffer_writes().to_vec(),
        framebuffer_flush_regions: graph.framebuffer_flush_regions().to_vec(),
        display_event_logs: graph.display_event_logs().to_vec(),
        display_snapshot_barriers: graph.display_snapshot_barriers().to_vec(),
        framebuffer_benchmarks: benchmarks,
        integrated_smp_preemption_cleanups: graph.integrated_smp_preemption_cleanups().to_vec(),
        saved_contexts: graph.saved_contexts().to_vec(),
        timer_interrupts: graph.timer_interrupts().to_vec(),
        remote_preempts: graph.remote_preempts().to_vec(),
        activation_cleanups: graph.activation_cleanups().to_vec(),
        smp_cleanup_quiescence: graph.smp_cleanup_quiescence().to_vec(),
        smp_stress_runs: graph.smp_stress_runs().to_vec(),
        stores: graph.stores().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-benchmark->metrics"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}
