use super::*;

pub(in crate::tests) fn g7_framebuffer_dirty_region_graph() -> (
    SemanticGraph,
    StoreId,
    Generation,
    FramebufferWriteId,
    Generation,
    FramebufferFlushRegionId,
    Generation,
    u64,
) {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        payload_digest,
    ) = g6_framebuffer_flush_region_graph();
    assert!(graph.record_framebuffer_flush_region_with_id(
        23_601,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        0,
        0,
        800,
        1,
        0,
        3_200,
        payload_digest,
        "g6 framebuffer flush for g7",
    ));
    (
        graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        23_601,
        1,
        payload_digest,
    )
}

#[test]
pub(in crate::tests) fn display_runtime_g7_dirty_region_tracks_clean_state_after_flush() {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        framebuffer_flush_region,
        framebuffer_flush_region_generation,
        payload_digest,
    ) = g7_framebuffer_dirty_region_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        8,
        "display-runtime-g7",
        SemanticCommand::RecordFramebufferDirtyRegion {
            framebuffer_dirty_region: 23_701,
            owner_store,
            owner_store_generation,
            framebuffer_write,
            framebuffer_write_generation,
            framebuffer_flush_region: Some(framebuffer_flush_region),
            framebuffer_flush_region_generation: Some(framebuffer_flush_region_generation),
            state: FramebufferDirtyRegionState::Clean,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest,
            note: "g7 framebuffer dirty region clean".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.framebuffer_dirty_region_count(), 1);
    let dirty = &graph.framebuffer_dirty_regions()[0];
    assert_eq!(
        dirty.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FramebufferDirtyRegion, 23_701, 1)
    );
    assert_eq!(dirty.state, FramebufferDirtyRegionState::Clean);
    assert_eq!(dirty.framebuffer_write, framebuffer_write);
    assert_eq!(dirty.framebuffer_flush_region, Some(framebuffer_flush_region));
    assert_eq!(dirty.payload_digest, payload_digest);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "FramebufferDirtyRegionTracked framebuffer_dirty_region=23701 owner_store={owner_store}@{owner_store_generation} framebuffer_write={framebuffer_write}@{framebuffer_write_generation} framebuffer_flush_region={framebuffer_flush_region}:{framebuffer_flush_region_generation} display_capability=23201@1 display=23101@1 framebuffer=23001@1 region=0,0 800x1 byte_range=0+3200 pixel_format=xrgb8888 payload_digest={payload_digest} state=clean generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g7_rejects_clean_region_without_exact_flush_or_with_bad_digest()
 {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        framebuffer_flush_region,
        framebuffer_flush_region_generation,
        payload_digest,
    ) = g7_framebuffer_dirty_region_graph();

    let missing_flush = graph.apply_envelope(CommandEnvelope::new(
        8,
        "display-runtime-g7",
        SemanticCommand::RecordFramebufferDirtyRegion {
            framebuffer_dirty_region: 23_702,
            owner_store,
            owner_store_generation,
            framebuffer_write,
            framebuffer_write_generation,
            framebuffer_flush_region: None,
            framebuffer_flush_region_generation: None,
            state: FramebufferDirtyRegionState::Clean,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest,
            note: "g7 missing flush".to_string(),
        },
    ));
    assert_eq!(missing_flush.status, CommandStatus::Rejected);

    let stale_flush = graph.apply_envelope(CommandEnvelope::new(
        9,
        "display-runtime-g7",
        SemanticCommand::RecordFramebufferDirtyRegion {
            framebuffer_dirty_region: 23_703,
            owner_store,
            owner_store_generation,
            framebuffer_write,
            framebuffer_write_generation,
            framebuffer_flush_region: Some(framebuffer_flush_region),
            framebuffer_flush_region_generation: Some(framebuffer_flush_region_generation + 1),
            state: FramebufferDirtyRegionState::Clean,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest,
            note: "g7 stale flush".to_string(),
        },
    ));
    assert_eq!(stale_flush.status, CommandStatus::Rejected);

    let bad_digest = graph.apply_envelope(CommandEnvelope::new(
        10,
        "display-runtime-g7",
        SemanticCommand::RecordFramebufferDirtyRegion {
            framebuffer_dirty_region: 23_704,
            owner_store,
            owner_store_generation,
            framebuffer_write,
            framebuffer_write_generation,
            framebuffer_flush_region: Some(framebuffer_flush_region),
            framebuffer_flush_region_generation: Some(framebuffer_flush_region_generation),
            state: FramebufferDirtyRegionState::Clean,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest: payload_digest + 1,
            note: "g7 bad digest".to_string(),
        },
    ));
    assert_eq!(bad_digest.status, CommandStatus::Rejected);
}

#[test]
pub(in crate::tests) fn display_runtime_g7_invariants_reject_flush_generation_leak() {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        framebuffer_flush_region,
        framebuffer_flush_region_generation,
        payload_digest,
    ) = g7_framebuffer_dirty_region_graph();
    assert!(graph.record_framebuffer_dirty_region_with_id(
        23_705,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        Some(framebuffer_flush_region),
        Some(framebuffer_flush_region_generation),
        FramebufferDirtyRegionState::Clean,
        0,
        0,
        800,
        1,
        0,
        3_200,
        payload_digest,
        "g7 invariant dirty region",
    ));
    graph.corrupt_framebuffer_dirty_region_flush_generation_for_test(
        23_705,
        Some(framebuffer_flush_region_generation + 1),
    );

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FramebufferDirtyRegionMissingFlush {
            framebuffer_dirty_region: 23_705,
            framebuffer_flush_region,
        })
    );
}

#[test]
pub(in crate::tests) fn display_runtime_g7_contract_graph_rejects_missing_flush_edge_for_clean_region()
 {
    let dirty = FramebufferDirtyRegionRecord {
        id: 23_706,
        owner_store: 1,
        owner_store_generation: 1,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        framebuffer_flush_region: Some(23_601),
        framebuffer_flush_region_generation: Some(9),
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        x: 0,
        y: 0,
        width: 16,
        height: 1,
        byte_offset: 0,
        byte_len: 64,
        pixel_format: "xrgb8888".to_string(),
        payload_digest: 1,
        generation: 1,
        state: FramebufferDirtyRegionState::Clean,
        dirty_at_event: 1,
        cleaned_at_event: Some(2),
        recorded_at_event: 3,
        note: "g7 missing flush".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_dirty_regions: Vec::from([dirty]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-dirty-region->framebuffer-flush-region"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}

#[test]
pub(in crate::tests) fn display_runtime_g7_contract_graph_rejects_dirty_region_flush_binding_drift()
{
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        framebuffer_flush_region,
        framebuffer_flush_region_generation,
        payload_digest,
    ) = g7_framebuffer_dirty_region_graph();
    assert!(graph.record_framebuffer_dirty_region_with_id(
        23_707,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        Some(framebuffer_flush_region),
        Some(framebuffer_flush_region_generation),
        FramebufferDirtyRegionState::Clean,
        0,
        0,
        800,
        1,
        0,
        3_200,
        payload_digest,
        "g7 contract graph dirty region",
    ));
    let mut framebuffer_dirty_regions = graph.framebuffer_dirty_regions().to_vec();
    framebuffer_dirty_regions[0].byte_len = 3_196;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        display_capabilities: graph.display_capabilities().to_vec(),
        framebuffer_window_leases: graph.framebuffer_window_leases().to_vec(),
        framebuffer_mappings: graph.framebuffer_mappings().to_vec(),
        framebuffer_writes: graph.framebuffer_writes().to_vec(),
        framebuffer_flush_regions: graph.framebuffer_flush_regions().to_vec(),
        framebuffer_dirty_regions,
        stores: graph.stores().to_vec(),
        capabilities: graph.capabilities().records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-dirty-region->write-binding"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-dirty-region->flush-binding"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(in crate::tests) fn g8_display_event_log_graph() -> (
    SemanticGraph,
    StoreId,
    Generation,
    FramebufferDirtyRegionId,
    Generation,
    EventId,
    EventId,
    u64,
    u64,
    u64,
) {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        framebuffer_flush_region,
        framebuffer_flush_region_generation,
        payload_digest,
    ) = g7_framebuffer_dirty_region_graph();
    assert!(graph.record_framebuffer_dirty_region_with_id(
        23_701,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        Some(framebuffer_flush_region),
        Some(framebuffer_flush_region_generation),
        FramebufferDirtyRegionState::Clean,
        0,
        0,
        800,
        1,
        0,
        3_200,
        payload_digest,
        "g7 dirty region for g8",
    ));
    let first_event = graph
        .framebuffer_objects()
        .iter()
        .find(|record| record.id == 23_001)
        .map(|record| record.recorded_at_event)
        .expect("g0 framebuffer event exists");
    let last_event = graph.framebuffer_dirty_regions()[0].recorded_at_event;
    let display_events = graph
        .event_log()
        .events
        .iter()
        .filter(|event| {
            event.source == "display" && event.id >= first_event && event.id <= last_event
        })
        .collect::<Vec<_>>();
    let event_count = display_events.len() as u64;
    let flush_count = display_events
        .iter()
        .filter(|event| matches!(event.kind, EventKind::FramebufferFlushRegionRecorded { .. }))
        .count() as u64;
    let dirty_region_count = display_events
        .iter()
        .filter(|event| matches!(event.kind, EventKind::FramebufferDirtyRegionTracked { .. }))
        .count() as u64;
    (
        graph,
        owner_store,
        owner_store_generation,
        23_701,
        1,
        first_event,
        last_event,
        event_count,
        flush_count,
        dirty_region_count,
    )
}

#[test]
pub(in crate::tests) fn display_runtime_g8_records_display_event_log_summary() {
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

    let result = graph.apply_envelope(CommandEnvelope::new(
        8,
        "display-runtime-g8",
        SemanticCommand::RecordDisplayEventLog {
            display_event_log: 23_801,
            owner_store,
            owner_store_generation,
            framebuffer_dirty_region,
            framebuffer_dirty_region_generation,
            first_event,
            last_event,
            event_count,
            flush_count,
            dirty_region_count,
            note: "g8 display event log".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.display_event_log_count(), 1);
    let log = &graph.display_event_logs()[0];
    assert_eq!(
        log.object_ref(),
        ContractObjectRef::new(ContractObjectKind::DisplayEventLog, 23_801, 1)
    );
    assert_eq!(log.framebuffer_dirty_region, framebuffer_dirty_region);
    assert_eq!(log.first_event, first_event);
    assert_eq!(log.last_event, last_event);
    assert_eq!(log.event_count, event_count);
    assert_eq!(log.flush_count, flush_count);
    assert_eq!(log.dirty_region_count, dirty_region_count);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DisplayEventLogRecorded display_event_log=23801 owner_store={owner_store}@{owner_store_generation} display_capability=23201@1 display=23101@1 framebuffer=23001@1 framebuffer_dirty_region={framebuffer_dirty_region}@{framebuffer_dirty_region_generation} events={first_event}..{last_event} event_count={event_count} flush_count={flush_count} dirty_region_count={dirty_region_count} state=recorded generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g8_rejects_bad_event_window_and_count() {
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

    let stale_dirty = graph.apply_envelope(CommandEnvelope::new(
        8,
        "display-runtime-g8",
        SemanticCommand::RecordDisplayEventLog {
            display_event_log: 23_802,
            owner_store,
            owner_store_generation,
            framebuffer_dirty_region,
            framebuffer_dirty_region_generation: framebuffer_dirty_region_generation + 1,
            first_event,
            last_event,
            event_count,
            flush_count,
            dirty_region_count,
            note: "g8 stale dirty region".to_string(),
        },
    ));
    assert_eq!(stale_dirty.status, CommandStatus::Rejected);

    let bad_window = graph.apply_envelope(CommandEnvelope::new(
        9,
        "display-runtime-g8",
        SemanticCommand::RecordDisplayEventLog {
            display_event_log: 23_803,
            owner_store,
            owner_store_generation,
            framebuffer_dirty_region,
            framebuffer_dirty_region_generation,
            first_event: last_event + 1,
            last_event,
            event_count,
            flush_count,
            dirty_region_count,
            note: "g8 bad window".to_string(),
        },
    ));
    assert_eq!(bad_window.status, CommandStatus::Rejected);

    let bad_count = graph.apply_envelope(CommandEnvelope::new(
        10,
        "display-runtime-g8",
        SemanticCommand::RecordDisplayEventLog {
            display_event_log: 23_804,
            owner_store,
            owner_store_generation,
            framebuffer_dirty_region,
            framebuffer_dirty_region_generation,
            first_event,
            last_event,
            event_count: event_count + 1,
            flush_count,
            dirty_region_count,
            note: "g8 bad count".to_string(),
        },
    ));
    assert_eq!(bad_count.status, CommandStatus::Rejected);
}

#[test]
pub(in crate::tests) fn display_runtime_g8_invariants_reject_event_count_drift() {
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
        23_805,
        owner_store,
        owner_store_generation,
        framebuffer_dirty_region,
        framebuffer_dirty_region_generation,
        first_event,
        last_event,
        event_count,
        flush_count,
        dirty_region_count,
        "g8 invariant event log",
    ));
    graph.corrupt_display_event_log_event_count_for_test(23_805, event_count + 1);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DisplayEventLogInvalid { display_event_log: 23_805 })
    );
}

#[test]
pub(in crate::tests) fn display_runtime_g8_contract_graph_rejects_missing_dirty_region_edge() {
    let log = DisplayEventLogRecord {
        id: 23_806,
        owner_store: 1,
        owner_store_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        framebuffer_dirty_region: 23_701,
        framebuffer_dirty_region_generation: 9,
        first_event: 1,
        last_event: 8,
        event_count: 8,
        flush_count: 1,
        dirty_region_count: 1,
        generation: 1,
        state: DisplayEventLogState::Recorded,
        recorded_at_event: 9,
        note: "g8 missing dirty region".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        display_event_logs: Vec::from([log]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-event-log->framebuffer-dirty-region"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}

#[test]
pub(in crate::tests) fn display_runtime_g8_contract_graph_rejects_dirty_region_binding_drift() {
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
        23_807,
        owner_store,
        owner_store_generation,
        framebuffer_dirty_region,
        framebuffer_dirty_region_generation,
        first_event,
        last_event,
        event_count,
        flush_count,
        dirty_region_count,
        "g8 contract graph event log",
    ));
    let mut display_event_logs = graph.display_event_logs().to_vec();
    display_event_logs[0].last_event = first_event;
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
        display_event_logs,
        stores: graph.stores().to_vec(),
        capabilities: graph.capabilities().records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-event-log->dirty-region-binding"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}
