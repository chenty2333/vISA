use super::*;

pub(in crate::tests) fn g3_framebuffer_window_lease_graph()
-> (SemanticGraph, StoreId, Generation, DisplayCapabilityId, Generation) {
    let (mut graph, owner_store, owner_store_generation, capability) =
        g2_display_capability_graph();
    let capability_record = graph.capabilities().record(capability).unwrap().clone();
    let handle = handle_for(&capability_record, &["flush", "lease"]);
    assert!(graph.record_display_capability_with_id(
        23_201,
        owner_store,
        owner_store_generation,
        23_101,
        1,
        capability,
        capability_record.generation,
        handle,
        vec!["flush".to_string(), "lease".to_string()],
        "g2 display capability for g3",
    ));
    (graph, owner_store, owner_store_generation, 23_201, 1)
}

#[test]
pub(in crate::tests) fn display_runtime_g3_framebuffer_window_lease_records_exact_window() {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        display_capability,
        display_capability_generation,
    ) = g3_framebuffer_window_lease_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        4,
        "display-runtime-g3",
        SemanticCommand::RecordFramebufferWindowLease {
            framebuffer_window_lease: 23_301,
            owner_store,
            owner_store_generation,
            display_capability,
            display_capability_generation,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            byte_offset: 0,
            byte_len: 1_920_000,
            access: "write".to_string(),
            note: "g3 framebuffer window lease".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.framebuffer_window_lease_count(), 1);
    assert_eq!(graph.active_framebuffer_window_lease_count(), 1);
    let lease = &graph.framebuffer_window_leases()[0];
    assert_eq!(
        lease.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FramebufferWindowLease, 23_301, 1)
    );
    assert_eq!(lease.display_capability, display_capability);
    assert_eq!(lease.display_capability_generation, display_capability_generation);
    assert_eq!(lease.framebuffer, 23_001);
    assert_eq!(lease.byte_len, 1_920_000);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "FramebufferWindowLeaseRecorded framebuffer_window_lease=23301 owner_store={owner_store}@{owner_store_generation} display_capability={display_capability}@{display_capability_generation} display=23101@1 framebuffer=23001@1 window=0,0 800x600 byte_range=0+1920000 access=write state=active generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g3_rejects_stale_capability_and_oversized_window() {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        display_capability,
        display_capability_generation,
    ) = g3_framebuffer_window_lease_graph();

    let stale_capability = graph.apply_envelope(CommandEnvelope::new(
        4,
        "display-runtime-g3",
        SemanticCommand::RecordFramebufferWindowLease {
            framebuffer_window_lease: 23_302,
            owner_store,
            owner_store_generation,
            display_capability,
            display_capability_generation: display_capability_generation + 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            byte_offset: 0,
            byte_len: 1_920_000,
            access: "write".to_string(),
            note: "g3 stale display capability".to_string(),
        },
    ));
    assert_eq!(stale_capability.status, CommandStatus::Rejected);

    let oversized_window = graph.apply_envelope(CommandEnvelope::new(
        5,
        "display-runtime-g3",
        SemanticCommand::RecordFramebufferWindowLease {
            framebuffer_window_lease: 23_303,
            owner_store,
            owner_store_generation,
            display_capability,
            display_capability_generation,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            x: 799,
            y: 0,
            width: 2,
            height: 600,
            byte_offset: 0,
            byte_len: 1_920_000,
            access: "write".to_string(),
            note: "g3 oversized window".to_string(),
        },
    ));
    assert_eq!(oversized_window.status, CommandStatus::Rejected);

    let mismatched_byte_offset = graph.apply_envelope(CommandEnvelope::new(
        6,
        "display-runtime-g3",
        SemanticCommand::RecordFramebufferWindowLease {
            framebuffer_window_lease: 23_306,
            owner_store,
            owner_store_generation,
            display_capability,
            display_capability_generation,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            x: 1,
            y: 0,
            width: 16,
            height: 16,
            byte_offset: 0,
            byte_len: 48_064,
            access: "write".to_string(),
            note: "g3 mismatched byte offset".to_string(),
        },
    ));
    assert_eq!(mismatched_byte_offset.status, CommandStatus::Rejected);
}

#[test]
pub(in crate::tests) fn display_runtime_g3_invariants_reject_display_capability_generation_leak() {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        display_capability,
        display_capability_generation,
    ) = g3_framebuffer_window_lease_graph();
    assert!(graph.record_framebuffer_window_lease_with_id(
        23_304,
        owner_store,
        owner_store_generation,
        display_capability,
        display_capability_generation,
        23_101,
        1,
        23_001,
        1,
        0,
        0,
        800,
        600,
        0,
        1_920_000,
        "write",
        "g3 invariant lease",
    ));
    graph.corrupt_framebuffer_window_lease_display_capability_generation_for_test(
        23_304,
        display_capability_generation + 1,
    );

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FramebufferWindowLeaseMissingDisplayCapability {
            framebuffer_window_lease: 23_304,
            display_capability,
        })
    );
}

#[test]
pub(in crate::tests) fn display_runtime_g3_contract_graph_rejects_missing_display_capability_edge()
{
    let lease = FramebufferWindowLeaseRecord {
        id: 23_305,
        owner_store: 1,
        owner_store_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 7,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        x: 0,
        y: 0,
        width: 16,
        height: 16,
        byte_offset: 0,
        byte_len: 1024,
        access: "write".to_string(),
        generation: 1,
        state: FramebufferWindowLeaseState::Active,
        recorded_at_event: 1,
        note: "g3 missing display capability".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_window_leases: Vec::from([lease]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-window-lease->display-capability"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}

#[test]
pub(in crate::tests) fn display_runtime_g3_contract_graph_rejects_mismatched_byte_window() {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        display_capability,
        display_capability_generation,
    ) = g3_framebuffer_window_lease_graph();
    assert!(graph.record_framebuffer_window_lease_with_id(
        23_306,
        owner_store,
        owner_store_generation,
        display_capability,
        display_capability_generation,
        23_101,
        1,
        23_001,
        1,
        0,
        0,
        16,
        16,
        0,
        48_064,
        "write",
        "g3 contract graph byte window",
    ));
    let mut framebuffer_window_leases = graph.framebuffer_window_leases().to_vec();
    framebuffer_window_leases[0].x = 1;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        display_capabilities: graph.display_capabilities().to_vec(),
        framebuffer_window_leases,
        stores: graph.stores().to_vec(),
        capabilities: graph.capabilities().records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-window-lease->byte-window"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

pub(in crate::tests) fn g4_framebuffer_mapping_graph()
-> (SemanticGraph, StoreId, Generation, FramebufferWindowLeaseId, Generation) {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        display_capability,
        display_capability_generation,
    ) = g3_framebuffer_window_lease_graph();
    assert!(graph.record_framebuffer_window_lease_with_id(
        23_301,
        owner_store,
        owner_store_generation,
        display_capability,
        display_capability_generation,
        23_101,
        1,
        23_001,
        1,
        0,
        0,
        800,
        600,
        0,
        1_920_000,
        "write",
        "g3 framebuffer window lease for g4",
    ));
    (graph, owner_store, owner_store_generation, 23_301, 1)
}

#[test]
pub(in crate::tests) fn display_runtime_g4_framebuffer_mapping_records_handle_mode_mapping() {
    let (mut graph, owner_store, owner_store_generation, lease, lease_generation) =
        g4_framebuffer_mapping_graph();
    let tag = 0x4d41505f4642;

    let result = graph.apply_envelope(CommandEnvelope::new(
        6,
        "display-runtime-g4",
        SemanticCommand::RecordFramebufferMapping {
            framebuffer_mapping: 23_401,
            owner_store,
            owner_store_generation,
            framebuffer_window_lease: lease,
            framebuffer_window_lease_generation: lease_generation,
            map_handle_slot: 3,
            map_handle_generation: 1,
            map_handle_tag: tag,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            byte_offset: 0,
            byte_len: 1_920_000,
            access: "write".to_string(),
            mode: "handle-mode".to_string(),
            note: "g4 framebuffer mapping".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.framebuffer_mapping_count(), 1);
    assert_eq!(graph.active_framebuffer_mapping_count(), 1);
    let mapping = &graph.framebuffer_mappings()[0];
    assert_eq!(
        mapping.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FramebufferMapping, 23_401, 1)
    );
    assert_eq!(mapping.framebuffer_window_lease, lease);
    assert_eq!(mapping.framebuffer_window_lease_generation, lease_generation);
    assert_eq!(mapping.map_handle_slot, 3);
    assert_eq!(mapping.mode, "handle-mode");
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "FramebufferMappingRecorded framebuffer_mapping=23401 owner_store={owner_store}@{owner_store_generation} framebuffer_window_lease={lease}@{lease_generation} display_capability=23201@1 display=23101@1 framebuffer=23001@1 map_handle_slot=3 map_handle_generation=1 map_handle_tag={tag} window=0,0 800x600 byte_range=0+1920000 access=write mode=handle-mode state=active generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g4_rejects_stale_lease_raw_mode_and_mismatched_window() {
    let (mut graph, owner_store, owner_store_generation, lease, lease_generation) =
        g4_framebuffer_mapping_graph();

    let stale_lease = graph.apply_envelope(CommandEnvelope::new(
        6,
        "display-runtime-g4",
        SemanticCommand::RecordFramebufferMapping {
            framebuffer_mapping: 23_402,
            owner_store,
            owner_store_generation,
            framebuffer_window_lease: lease,
            framebuffer_window_lease_generation: lease_generation + 1,
            map_handle_slot: 3,
            map_handle_generation: 1,
            map_handle_tag: 0x4d41505f4642,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            byte_offset: 0,
            byte_len: 1_920_000,
            access: "write".to_string(),
            mode: "handle-mode".to_string(),
            note: "g4 stale lease".to_string(),
        },
    ));
    assert_eq!(stale_lease.status, CommandStatus::Rejected);

    let raw_pointer_mode = graph.apply_envelope(CommandEnvelope::new(
        7,
        "display-runtime-g4",
        SemanticCommand::RecordFramebufferMapping {
            framebuffer_mapping: 23_403,
            owner_store,
            owner_store_generation,
            framebuffer_window_lease: lease,
            framebuffer_window_lease_generation: lease_generation,
            map_handle_slot: 3,
            map_handle_generation: 1,
            map_handle_tag: 0x4d41505f4642,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            byte_offset: 0,
            byte_len: 1_920_000,
            access: "write".to_string(),
            mode: "raw-pointer".to_string(),
            note: "g4 raw mode rejected".to_string(),
        },
    ));
    assert_eq!(raw_pointer_mode.status, CommandStatus::Rejected);

    let mismatched_window = graph.apply_envelope(CommandEnvelope::new(
        8,
        "display-runtime-g4",
        SemanticCommand::RecordFramebufferMapping {
            framebuffer_mapping: 23_404,
            owner_store,
            owner_store_generation,
            framebuffer_window_lease: lease,
            framebuffer_window_lease_generation: lease_generation,
            map_handle_slot: 3,
            map_handle_generation: 1,
            map_handle_tag: 0x4d41505f4642,
            x: 0,
            y: 0,
            width: 799,
            height: 600,
            byte_offset: 0,
            byte_len: 1_920_000,
            access: "write".to_string(),
            mode: "handle-mode".to_string(),
            note: "g4 mismatched window".to_string(),
        },
    ));
    assert_eq!(mismatched_window.status, CommandStatus::Rejected);
}

#[test]
pub(in crate::tests) fn display_runtime_g4_invariants_reject_lease_generation_leak() {
    let (mut graph, owner_store, owner_store_generation, lease, lease_generation) =
        g4_framebuffer_mapping_graph();
    assert!(graph.record_framebuffer_mapping_with_id(
        23_405,
        owner_store,
        owner_store_generation,
        lease,
        lease_generation,
        3,
        1,
        0x4d41505f4642,
        0,
        0,
        800,
        600,
        0,
        1_920_000,
        "write",
        "handle-mode",
        "g4 invariant mapping",
    ));
    graph.corrupt_framebuffer_mapping_lease_generation_for_test(23_405, lease_generation + 1);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FramebufferMappingMissingLease {
            framebuffer_mapping: 23_405,
            framebuffer_window_lease: lease,
        })
    );
}

#[test]
pub(in crate::tests) fn display_runtime_g4_contract_graph_rejects_missing_lease_edge() {
    let mapping = FramebufferMappingRecord {
        id: 23_406,
        owner_store: 1,
        owner_store_generation: 1,
        framebuffer_window_lease: 23_301,
        framebuffer_window_lease_generation: 7,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        map_handle_slot: 3,
        map_handle_generation: 1,
        map_handle_tag: 0x4d41505f4642,
        x: 0,
        y: 0,
        width: 16,
        height: 16,
        byte_offset: 0,
        byte_len: 1024,
        access: "write".to_string(),
        mode: "handle-mode".to_string(),
        generation: 1,
        state: FramebufferMappingState::Active,
        recorded_at_event: 1,
        note: "g4 missing lease".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_mappings: Vec::from([mapping]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-mapping->framebuffer-window-lease"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}

#[test]
pub(in crate::tests) fn display_runtime_g4_contract_graph_rejects_mapping_lease_binding_drift() {
    let (mut graph, owner_store, owner_store_generation, lease, lease_generation) =
        g4_framebuffer_mapping_graph();
    assert!(graph.record_framebuffer_mapping_with_id(
        23_407,
        owner_store,
        owner_store_generation,
        lease,
        lease_generation,
        3,
        1,
        0x4d41505f4642,
        0,
        0,
        800,
        600,
        0,
        1_920_000,
        "write",
        "handle-mode",
        "g4 contract graph mapping",
    ));
    let mut framebuffer_mappings = graph.framebuffer_mappings().to_vec();
    framebuffer_mappings[0].width = 799;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        display_capabilities: graph.display_capabilities().to_vec(),
        framebuffer_window_leases: graph.framebuffer_window_leases().to_vec(),
        framebuffer_mappings,
        stores: graph.stores().to_vec(),
        capabilities: graph.capabilities().records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-mapping->lease-binding"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(in crate::tests) fn g5_framebuffer_write_graph()
-> (SemanticGraph, StoreId, Generation, FramebufferMappingId, Generation) {
    let (mut graph, owner_store, owner_store_generation, lease, lease_generation) =
        g4_framebuffer_mapping_graph();
    assert!(graph.record_framebuffer_mapping_with_id(
        23_401,
        owner_store,
        owner_store_generation,
        lease,
        lease_generation,
        3,
        1,
        0x4d41505f4642,
        0,
        0,
        800,
        600,
        0,
        1_920_000,
        "write",
        "handle-mode",
        "g4 framebuffer mapping for g5",
    ));
    (graph, owner_store, owner_store_generation, 23_401, 1)
}

#[test]
pub(in crate::tests) fn display_runtime_g5_framebuffer_write_records_semantic_pixel_write() {
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

    let result = graph.apply_envelope(CommandEnvelope::new(
        7,
        "display-runtime-g5",
        SemanticCommand::RecordFramebufferWrite {
            framebuffer_write: 23_501,
            owner_store,
            owner_store_generation,
            framebuffer_mapping: mapping,
            framebuffer_mapping_generation: mapping_generation,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest,
            note: "g5 framebuffer write".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.framebuffer_write_count(), 1);
    let write = &graph.framebuffer_writes()[0];
    assert_eq!(
        write.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FramebufferWrite, 23_501, 1)
    );
    assert_eq!(write.framebuffer_mapping, mapping);
    assert_eq!(write.framebuffer_mapping_generation, mapping_generation);
    assert_eq!(write.pixel_format, "xrgb8888");
    assert_eq!(write.payload_digest, payload_digest);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "FramebufferWriteRecorded framebuffer_write=23501 owner_store={owner_store}@{owner_store_generation} framebuffer_mapping={mapping}@{mapping_generation} framebuffer_window_lease=23301@1 display_capability=23201@1 display=23101@1 framebuffer=23001@1 map_handle_slot=3 map_handle_generation=1 map_handle_tag=84942916634178 region=0,0 800x1 byte_range=0+3200 pixel_format=xrgb8888 payload_digest={payload_digest} state=applied generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g5_rejects_stale_mapping_bad_region_and_digest() {
    let (mut graph, owner_store, owner_store_generation, mapping, mapping_generation) =
        g5_framebuffer_write_graph();
    let digest = SemanticGraph::expected_framebuffer_write_payload_digest_v1(
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

    let stale_mapping = graph.apply_envelope(CommandEnvelope::new(
        7,
        "display-runtime-g5",
        SemanticCommand::RecordFramebufferWrite {
            framebuffer_write: 23_502,
            owner_store,
            owner_store_generation,
            framebuffer_mapping: mapping,
            framebuffer_mapping_generation: mapping_generation + 1,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest: digest,
            note: "g5 stale mapping".to_string(),
        },
    ));
    assert_eq!(stale_mapping.status, CommandStatus::Rejected);

    let bad_region = graph.apply_envelope(CommandEnvelope::new(
        8,
        "display-runtime-g5",
        SemanticCommand::RecordFramebufferWrite {
            framebuffer_write: 23_503,
            owner_store,
            owner_store_generation,
            framebuffer_mapping: mapping,
            framebuffer_mapping_generation: mapping_generation,
            x: 799,
            y: 0,
            width: 2,
            height: 1,
            byte_offset: 3_196,
            byte_len: 8,
            payload_digest: digest,
            note: "g5 bad region".to_string(),
        },
    ));
    assert_eq!(bad_region.status, CommandStatus::Rejected);

    let bad_digest = graph.apply_envelope(CommandEnvelope::new(
        9,
        "display-runtime-g5",
        SemanticCommand::RecordFramebufferWrite {
            framebuffer_write: 23_504,
            owner_store,
            owner_store_generation,
            framebuffer_mapping: mapping,
            framebuffer_mapping_generation: mapping_generation,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest: digest + 1,
            note: "g5 bad digest".to_string(),
        },
    ));
    assert_eq!(bad_digest.status, CommandStatus::Rejected);
}

#[test]
pub(in crate::tests) fn display_runtime_g5_invariants_reject_mapping_generation_leak() {
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
        23_505,
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
        "g5 invariant write",
    ));
    graph.corrupt_framebuffer_write_mapping_generation_for_test(23_505, mapping_generation + 1);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FramebufferWriteMissingMapping {
            framebuffer_write: 23_505,
            framebuffer_mapping: mapping,
        })
    );
}

#[test]
pub(in crate::tests) fn display_runtime_g5_contract_graph_rejects_missing_mapping_edge() {
    let write = FramebufferWriteRecord {
        id: 23_506,
        owner_store: 1,
        owner_store_generation: 1,
        framebuffer_mapping: 23_401,
        framebuffer_mapping_generation: 7,
        framebuffer_window_lease: 23_301,
        framebuffer_window_lease_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        map_handle_slot: 3,
        map_handle_generation: 1,
        map_handle_tag: 0x4d41505f4642,
        x: 0,
        y: 0,
        width: 16,
        height: 1,
        byte_offset: 0,
        byte_len: 64,
        pixel_format: "xrgb8888".to_string(),
        payload_digest: 1,
        generation: 1,
        state: FramebufferWriteState::Applied,
        recorded_at_event: 1,
        note: "g5 missing mapping".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_writes: Vec::from([write]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-write->framebuffer-mapping"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}

#[test]
pub(in crate::tests) fn display_runtime_g5_contract_graph_rejects_write_mapping_binding_drift() {
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
        23_507,
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
        "g5 contract graph write",
    ));
    let mut framebuffer_writes = graph.framebuffer_writes().to_vec();
    framebuffer_writes[0].map_handle_generation = 2;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        display_capabilities: graph.display_capabilities().to_vec(),
        framebuffer_window_leases: graph.framebuffer_window_leases().to_vec(),
        framebuffer_mappings: graph.framebuffer_mappings().to_vec(),
        framebuffer_writes,
        stores: graph.stores().to_vec(),
        capabilities: graph.capabilities().records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-write->mapping-binding"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(in crate::tests) fn g6_framebuffer_flush_region_graph()
-> (SemanticGraph, StoreId, Generation, FramebufferWriteId, Generation, u64) {
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
        23_501,
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
        "g5 framebuffer write for g6",
    ));
    (graph, owner_store, owner_store_generation, 23_501, 1, payload_digest)
}

#[test]
pub(in crate::tests) fn display_runtime_g6_flush_region_records_semantic_flush() {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        payload_digest,
    ) = g6_framebuffer_flush_region_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        8,
        "display-runtime-g6",
        SemanticCommand::RecordFramebufferFlushRegion {
            framebuffer_flush_region: 23_601,
            owner_store,
            owner_store_generation,
            framebuffer_write,
            framebuffer_write_generation,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest,
            note: "g6 framebuffer flush".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.framebuffer_flush_region_count(), 1);
    let flush = &graph.framebuffer_flush_regions()[0];
    assert_eq!(
        flush.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FramebufferFlushRegion, 23_601, 1)
    );
    assert_eq!(flush.framebuffer_write, framebuffer_write);
    assert_eq!(flush.framebuffer_write_generation, framebuffer_write_generation);
    assert_eq!(flush.payload_digest, payload_digest);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "FramebufferFlushRegionRecorded framebuffer_flush_region=23601 owner_store={owner_store}@{owner_store_generation} framebuffer_write={framebuffer_write}@{framebuffer_write_generation} display_capability=23201@1 display=23101@1 framebuffer=23001@1 region=0,0 800x1 byte_range=0+3200 pixel_format=xrgb8888 payload_digest={payload_digest} state=applied generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn display_runtime_g6_rejects_stale_write_mismatched_region_and_digest() {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        payload_digest,
    ) = g6_framebuffer_flush_region_graph();

    let stale_write = graph.apply_envelope(CommandEnvelope::new(
        8,
        "display-runtime-g6",
        SemanticCommand::RecordFramebufferFlushRegion {
            framebuffer_flush_region: 23_602,
            owner_store,
            owner_store_generation,
            framebuffer_write,
            framebuffer_write_generation: framebuffer_write_generation + 1,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest,
            note: "g6 stale write".to_string(),
        },
    ));
    assert_eq!(stale_write.status, CommandStatus::Rejected);

    let mismatched_region = graph.apply_envelope(CommandEnvelope::new(
        9,
        "display-runtime-g6",
        SemanticCommand::RecordFramebufferFlushRegion {
            framebuffer_flush_region: 23_603,
            owner_store,
            owner_store_generation,
            framebuffer_write,
            framebuffer_write_generation,
            x: 0,
            y: 0,
            width: 799,
            height: 1,
            byte_offset: 0,
            byte_len: 3_196,
            payload_digest,
            note: "g6 mismatched region".to_string(),
        },
    ));
    assert_eq!(mismatched_region.status, CommandStatus::Rejected);

    let bad_digest = graph.apply_envelope(CommandEnvelope::new(
        10,
        "display-runtime-g6",
        SemanticCommand::RecordFramebufferFlushRegion {
            framebuffer_flush_region: 23_604,
            owner_store,
            owner_store_generation,
            framebuffer_write,
            framebuffer_write_generation,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3_200,
            payload_digest: payload_digest + 1,
            note: "g6 bad digest".to_string(),
        },
    ));
    assert_eq!(bad_digest.status, CommandStatus::Rejected);
}

#[test]
pub(in crate::tests) fn display_runtime_g6_invariants_reject_write_generation_leak() {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        payload_digest,
    ) = g6_framebuffer_flush_region_graph();
    assert!(graph.record_framebuffer_flush_region_with_id(
        23_605,
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
        "g6 invariant flush",
    ));
    graph.corrupt_framebuffer_flush_region_write_generation_for_test(
        23_605,
        framebuffer_write_generation + 1,
    );

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FramebufferFlushRegionMissingWrite {
            framebuffer_flush_region: 23_605,
            framebuffer_write,
        })
    );
}

#[test]
pub(in crate::tests) fn display_runtime_g6_contract_graph_rejects_missing_write_edge() {
    let flush = FramebufferFlushRegionRecord {
        id: 23_606,
        owner_store: 1,
        owner_store_generation: 1,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 7,
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
        state: FramebufferFlushRegionState::Applied,
        recorded_at_event: 1,
        note: "g6 missing write".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_flush_regions: Vec::from([flush]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-flush-region->framebuffer-write"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}

#[test]
pub(in crate::tests) fn display_runtime_g6_contract_graph_rejects_flush_write_binding_drift() {
    let (
        mut graph,
        owner_store,
        owner_store_generation,
        framebuffer_write,
        framebuffer_write_generation,
        payload_digest,
    ) = g6_framebuffer_flush_region_graph();
    assert!(graph.record_framebuffer_flush_region_with_id(
        23_607,
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
        "g6 contract graph flush",
    ));
    let mut framebuffer_flush_regions = graph.framebuffer_flush_regions().to_vec();
    framebuffer_flush_regions[0].byte_len = 3_196;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        display_capabilities: graph.display_capabilities().to_vec(),
        framebuffer_window_leases: graph.framebuffer_window_leases().to_vec(),
        framebuffer_mappings: graph.framebuffer_mappings().to_vec(),
        framebuffer_writes: graph.framebuffer_writes().to_vec(),
        framebuffer_flush_regions,
        stores: graph.stores().to_vec(),
        capabilities: graph.capabilities().records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-flush-region->write-binding"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}
