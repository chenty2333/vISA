use super::*;

#[test]
pub(super) fn display_runtime_g0_framebuffer_object_records_contract_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Framebuffer, None, "framebuffer:fb0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "display-runtime-g0",
        SemanticCommand::RecordFramebufferObject {
            framebuffer: 23_001,
            name: "fb0".to_string(),
            resource,
            resource_generation,
            width: 800,
            height: 600,
            stride_bytes: 3200,
            pixel_format: "xrgb8888".to_string(),
            byte_len: 1_920_000,
            note: "g0 framebuffer object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.framebuffer_object_count(), 1);
    let framebuffer = &graph.framebuffer_objects()[0];
    assert_eq!(
        framebuffer.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FramebufferObject, 23_001, 1)
    );
    assert_eq!(framebuffer.resource, resource);
    assert_eq!(framebuffer.resource_generation, resource_generation);
    assert_eq!(framebuffer.width, 800);
    assert_eq!(framebuffer.height, 600);
    assert_eq!(framebuffer.stride_bytes, 3200);
    assert_eq!(framebuffer.pixel_format, "xrgb8888");
    assert_eq!(framebuffer.byte_len, 1_920_000);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FramebufferObjectRecorded framebuffer=23001 resource=1@1 width=800 height=600 stride_bytes=3200 pixel_format=xrgb8888 byte_len=1920000 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn display_runtime_g0_rejects_bad_resource_or_geometry() {
    let mut graph = SemanticGraph::new();
    let wrong_resource = graph.register_resource(ResourceKind::Device, None, "device:not-fb");
    let wrong_generation = graph.resource_handle(wrong_resource).unwrap().generation;
    let wrong_kind = graph.apply_envelope(CommandEnvelope::new(
        1,
        "display-runtime-g0",
        SemanticCommand::RecordFramebufferObject {
            framebuffer: 23_002,
            name: "fb0".to_string(),
            resource: wrong_resource,
            resource_generation: wrong_generation,
            width: 800,
            height: 600,
            stride_bytes: 3200,
            pixel_format: "xrgb8888".to_string(),
            byte_len: 1_920_000,
            note: "g0 wrong resource".to_string(),
        },
    ));
    assert_eq!(wrong_kind.status, CommandStatus::Rejected);

    let fb_resource = graph.register_resource(ResourceKind::Framebuffer, None, "framebuffer:fb1");
    let fb_generation = graph.resource_handle(fb_resource).unwrap().generation;
    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "display-runtime-g0",
        SemanticCommand::RecordFramebufferObject {
            framebuffer: 23_003,
            name: "fb1".to_string(),
            resource: fb_resource,
            resource_generation: fb_generation + 1,
            width: 800,
            height: 600,
            stride_bytes: 3200,
            pixel_format: "xrgb8888".to_string(),
            byte_len: 1_920_000,
            note: "g0 stale resource generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let short_stride = graph.apply_envelope(CommandEnvelope::new(
        3,
        "display-runtime-g0",
        SemanticCommand::RecordFramebufferObject {
            framebuffer: 23_004,
            name: "fb1".to_string(),
            resource: fb_resource,
            resource_generation: fb_generation,
            width: 800,
            height: 600,
            stride_bytes: 3196,
            pixel_format: "xrgb8888".to_string(),
            byte_len: 1_920_000,
            note: "g0 short stride".to_string(),
        },
    ));
    assert_eq!(short_stride.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn display_runtime_g0_invariants_reject_resource_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Framebuffer, None, "framebuffer:fb0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_framebuffer_object_with_id(
        23_005,
        "fb0",
        resource,
        resource_generation,
        800,
        600,
        3200,
        "xrgb8888",
        1_920_000,
        "g0 invariant framebuffer",
    ));
    graph.corrupt_framebuffer_object_resource_generation_for_test(23_005, resource_generation + 1);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FramebufferObjectMissingResource {
            framebuffer: 23_005,
            resource,
        })
    );
}

#[test]
pub(super) fn display_runtime_g0_contract_graph_rejects_bad_framebuffer_geometry() {
    let framebuffer = FramebufferObjectRecord {
        id: 23_006,
        name: "fb0".to_string(),
        resource: 1,
        resource_generation: 1,
        width: 800,
        height: 600,
        stride_bytes: 3196,
        pixel_format: "xrgb8888".to_string(),
        byte_len: 1_920_000,
        generation: 1,
        state: FramebufferObjectState::Registered,
        recorded_at_event: 1,
        note: "g0 bad geometry".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        framebuffer_objects: Vec::from([framebuffer]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-object->geometry"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

pub(super) fn g1_framebuffer_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Framebuffer, None, "framebuffer:fb0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_framebuffer_object_with_id(
        23_001,
        "fb0",
        resource,
        resource_generation,
        800,
        600,
        3200,
        "xrgb8888",
        1_920_000,
        "g0 framebuffer object",
    ));
    graph
}

#[test]
pub(super) fn display_runtime_g1_display_object_records_framebuffer_mode() {
    let mut graph = g1_framebuffer_graph();
    let framebuffer = graph.framebuffer_objects()[0].object_ref();

    let result = graph.apply_envelope(CommandEnvelope::new(
        2,
        "display-runtime-g1",
        SemanticCommand::RecordDisplayObject {
            display: 23_101,
            name: "display0".to_string(),
            framebuffer: framebuffer.id,
            framebuffer_generation: framebuffer.generation,
            mode_name: "800x600@60".to_string(),
            width: 800,
            height: 600,
            refresh_millihz: 60_000,
            note: "g1 display object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.display_object_count(), 1);
    let display = &graph.display_objects()[0];
    assert_eq!(
        display.object_ref(),
        ContractObjectRef::new(ContractObjectKind::DisplayObject, 23_101, 1)
    );
    assert_eq!(display.framebuffer, 23_001);
    assert_eq!(display.framebuffer_generation, 1);
    assert_eq!(display.mode_name, "800x600@60");
    assert_eq!(display.refresh_millihz, 60_000);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "DisplayObjectRecorded display=23101 framebuffer=23001@1 mode_name=800x600@60 width=800 height=600 refresh_millihz=60000 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn display_runtime_g1_rejects_stale_or_oversized_framebuffer_mode() {
    let mut graph = g1_framebuffer_graph();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "display-runtime-g1",
        SemanticCommand::RecordDisplayObject {
            display: 23_102,
            name: "display0".to_string(),
            framebuffer: 23_001,
            framebuffer_generation: 2,
            mode_name: "800x600@60".to_string(),
            width: 800,
            height: 600,
            refresh_millihz: 60_000,
            note: "g1 stale framebuffer generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        3,
        "display-runtime-g1",
        SemanticCommand::RecordDisplayObject {
            display: 23_103,
            name: "display0".to_string(),
            framebuffer: 23_001,
            framebuffer_generation: 1,
            mode_name: "1024x768@60".to_string(),
            width: 1024,
            height: 768,
            refresh_millihz: 60_000,
            note: "g1 oversized mode".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn display_runtime_g1_invariants_reject_framebuffer_generation_leak() {
    let mut graph = g1_framebuffer_graph();
    assert!(graph.record_display_object_with_id(
        23_104,
        "display0",
        23_001,
        1,
        "800x600@60",
        800,
        600,
        60_000,
        "g1 invariant display",
    ));
    graph.corrupt_display_object_framebuffer_generation_for_test(23_104, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DisplayObjectMissingFramebuffer {
            display: 23_104,
            framebuffer: 23_001,
        })
    );
}

#[test]
pub(super) fn display_runtime_g1_contract_graph_rejects_missing_framebuffer_edge() {
    let display = DisplayObjectRecord {
        id: 23_105,
        name: "display0".to_string(),
        framebuffer: 23_001,
        framebuffer_generation: 9,
        mode_name: "800x600@60".to_string(),
        width: 800,
        height: 600,
        refresh_millihz: 60_000,
        generation: 1,
        state: DisplayObjectState::Registered,
        recorded_at_event: 1,
        note: "g1 bad framebuffer edge".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        display_objects: Vec::from([display]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-object->framebuffer-object"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}

pub(super) fn g2_display_capability_graph() -> (SemanticGraph, StoreId, Generation, CapabilityId) {
    let mut graph = g1_framebuffer_graph();
    assert!(graph.record_display_object_with_id(
        23_101,
        "display0",
        23_001,
        1,
        "800x600@60",
        800,
        600,
        60_000,
        "g1 display object",
    ));
    let owner_store =
        graph.register_store("wasm_app", "wasm_app", "frontend_guest", "kill-on-trap");
    graph.set_store_state(owner_store, StoreState::Running);
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let display_ref = graph.display_objects()[0].object_ref();
    let capability = graph.grant_capability_with_authority_ref(
        "wasm_app",
        "display.display0",
        AuthorityObjectRef::internal(CapabilityClass::Display, display_ref),
        &["flush", "lease"],
        "store",
        "g2-test",
        true,
    );
    (graph, owner_store, owner_store_generation, capability)
}

#[test]
pub(super) fn display_runtime_g2_display_capability_records_store_local_authority() {
    let (mut graph, owner_store, owner_store_generation, capability) =
        g2_display_capability_graph();
    let capability_record = graph.capabilities().record(capability).unwrap().clone();
    let handle = handle_for(&capability_record, &["flush", "lease"]);

    let result = graph.apply_envelope(CommandEnvelope::new(
        3,
        "display-runtime-g2",
        SemanticCommand::RecordDisplayCapability {
            display_capability: 23_201,
            owner_store,
            owner_store_generation,
            display: 23_101,
            display_generation: 1,
            capability,
            capability_generation: capability_record.generation,
            handle: handle.clone(),
            operations: vec!["flush".to_string(), "lease".to_string()],
            note: "g2 display capability".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.display_capability_count(), 1);
    let display_capability = &graph.display_capabilities()[0];
    assert_eq!(
        display_capability.object_ref(),
        ContractObjectRef::new(ContractObjectKind::DisplayCapability, 23_201, 1)
    );
    assert_eq!(display_capability.owner_store, owner_store);
    assert_eq!(display_capability.owner_store_generation, owner_store_generation);
    assert_eq!(display_capability.display, 23_101);
    assert_eq!(display_capability.display_generation, 1);
    assert_eq!(display_capability.framebuffer, 23_001);
    assert_eq!(display_capability.framebuffer_generation, 1);
    assert_eq!(display_capability.handle_slot, handle.slot);
    assert_eq!(display_capability.handle_generation, handle.generation);
    assert_eq!(display_capability.handle_tag, handle.tag);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DisplayCapabilityRecorded display_capability=23201 owner_store={owner_store}@{owner_store_generation} display=23101@1 framebuffer=23001@1 capability={capability}@{} handle_slot={} handle_generation={} handle_tag={} operations=flush|lease state=active generation=1",
            capability_record.generation, handle.slot, handle.generation, handle.tag,
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn display_runtime_g2_rejects_stale_display_and_forged_handle() {
    let (mut graph, owner_store, owner_store_generation, capability) =
        g2_display_capability_graph();
    let capability_record = graph.capabilities().record(capability).unwrap().clone();
    let handle = handle_for(&capability_record, &["flush", "lease"]);

    let stale_display = graph.apply_envelope(CommandEnvelope::new(
        3,
        "display-runtime-g2",
        SemanticCommand::RecordDisplayCapability {
            display_capability: 23_202,
            owner_store,
            owner_store_generation,
            display: 23_101,
            display_generation: 2,
            capability,
            capability_generation: capability_record.generation,
            handle: handle.clone(),
            operations: vec!["flush".to_string(), "lease".to_string()],
            note: "g2 stale display".to_string(),
        },
    ));
    assert_eq!(stale_display.status, CommandStatus::Rejected);

    let mut forged_handle = handle.clone();
    forged_handle.class_hint = CapabilityClass::Device;
    let bad_handle = graph.apply_envelope(CommandEnvelope::new(
        4,
        "display-runtime-g2",
        SemanticCommand::RecordDisplayCapability {
            display_capability: 23_203,
            owner_store,
            owner_store_generation,
            display: 23_101,
            display_generation: 1,
            capability,
            capability_generation: capability_record.generation,
            handle: forged_handle,
            operations: vec!["flush".to_string(), "lease".to_string()],
            note: "g2 forged handle".to_string(),
        },
    ));
    assert_eq!(bad_handle.status, CommandStatus::Rejected);
}

#[test]
pub(super) fn display_runtime_g2_invariants_reject_capability_generation_leak() {
    let (mut graph, owner_store, owner_store_generation, capability) =
        g2_display_capability_graph();
    let capability_record = graph.capabilities().record(capability).unwrap().clone();
    let handle = handle_for(&capability_record, &["flush", "lease"]);
    assert!(graph.record_display_capability_with_id(
        23_204,
        owner_store,
        owner_store_generation,
        23_101,
        1,
        capability,
        capability_record.generation,
        handle,
        vec!["flush".to_string(), "lease".to_string()],
        "g2 invariant capability",
    ));
    graph.corrupt_display_capability_generation_for_test(23_204, capability_record.generation + 1);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DisplayCapabilityInvalid { display_capability: 23_204 })
    );
}

#[test]
pub(super) fn display_runtime_g2_contract_graph_rejects_missing_capability_edge() {
    let display_capability = DisplayCapabilityRecord {
        id: 23_205,
        owner_store: 1,
        owner_store_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        capability: 77,
        capability_generation: 3,
        handle_slot: 1,
        handle_generation: 1,
        handle_tag: 42,
        operations: vec!["flush".to_string()],
        generation: 1,
        state: DisplayCapabilityState::Active,
        recorded_at_event: 1,
        note: "g2 missing capability edge".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        display_capabilities: Vec::from([display_capability]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-capability->capability"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}

#[test]
pub(super) fn display_runtime_g2_contract_graph_uses_exact_store_generation() {
    let (mut graph, owner_store, owner_store_generation, capability) =
        g2_display_capability_graph();
    let capability_record = graph.capabilities().record(capability).unwrap().clone();
    let handle = handle_for(&capability_record, &["flush", "lease"]);
    assert!(graph.record_display_capability_with_id(
        23_206,
        owner_store,
        owner_store_generation,
        23_101,
        1,
        capability,
        capability_record.generation,
        handle,
        vec!["flush".to_string(), "lease".to_string()],
        "g2 exact generation lookup",
    ));

    let mut stores = graph.stores().to_vec();
    let mut same_id_wrong_generation =
        stores.iter().find(|store| store.id == owner_store).unwrap().clone();
    same_id_wrong_generation.generation = owner_store_generation + 1;
    stores.insert(0, same_id_wrong_generation);
    let snapshot = ContractGraphSnapshot {
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        display_capabilities: graph.display_capabilities().to_vec(),
        stores,
        capabilities: graph.capabilities().records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(
        !violations.iter().any(|violation| violation.edge == "display-capability->owner-store"),
        "unexpected owner-store violations: {violations:?}"
    );
}

pub(super) fn g3_framebuffer_window_lease_graph()
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
pub(super) fn display_runtime_g3_framebuffer_window_lease_records_exact_window() {
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
pub(super) fn display_runtime_g3_rejects_stale_capability_and_oversized_window() {
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
pub(super) fn display_runtime_g3_invariants_reject_display_capability_generation_leak() {
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
pub(super) fn display_runtime_g3_contract_graph_rejects_missing_display_capability_edge() {
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
pub(super) fn display_runtime_g3_contract_graph_rejects_mismatched_byte_window() {
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

pub(super) fn g4_framebuffer_mapping_graph()
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
pub(super) fn display_runtime_g4_framebuffer_mapping_records_handle_mode_mapping() {
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
pub(super) fn display_runtime_g4_rejects_stale_lease_raw_mode_and_mismatched_window() {
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
pub(super) fn display_runtime_g4_invariants_reject_lease_generation_leak() {
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
pub(super) fn display_runtime_g4_contract_graph_rejects_missing_lease_edge() {
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
pub(super) fn display_runtime_g4_contract_graph_rejects_mapping_lease_binding_drift() {
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

pub(super) fn g5_framebuffer_write_graph()
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
pub(super) fn display_runtime_g5_framebuffer_write_records_semantic_pixel_write() {
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
pub(super) fn display_runtime_g5_rejects_stale_mapping_bad_region_and_digest() {
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
pub(super) fn display_runtime_g5_invariants_reject_mapping_generation_leak() {
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
pub(super) fn display_runtime_g5_contract_graph_rejects_missing_mapping_edge() {
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
pub(super) fn display_runtime_g5_contract_graph_rejects_write_mapping_binding_drift() {
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

pub(super) fn g6_framebuffer_flush_region_graph()
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
pub(super) fn display_runtime_g6_flush_region_records_semantic_flush() {
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
pub(super) fn display_runtime_g6_rejects_stale_write_mismatched_region_and_digest() {
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
pub(super) fn display_runtime_g6_invariants_reject_write_generation_leak() {
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
pub(super) fn display_runtime_g6_contract_graph_rejects_missing_write_edge() {
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
pub(super) fn display_runtime_g6_contract_graph_rejects_flush_write_binding_drift() {
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

pub(super) fn g7_framebuffer_dirty_region_graph() -> (
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
pub(super) fn display_runtime_g7_dirty_region_tracks_clean_state_after_flush() {
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
pub(super) fn display_runtime_g7_rejects_clean_region_without_exact_flush_or_with_bad_digest() {
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
pub(super) fn display_runtime_g7_invariants_reject_flush_generation_leak() {
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
pub(super) fn display_runtime_g7_contract_graph_rejects_missing_flush_edge_for_clean_region() {
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
pub(super) fn display_runtime_g7_contract_graph_rejects_dirty_region_flush_binding_drift() {
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

pub(super) fn g8_display_event_log_graph() -> (
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
pub(super) fn display_runtime_g8_records_display_event_log_summary() {
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
pub(super) fn display_runtime_g8_rejects_bad_event_window_and_count() {
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
pub(super) fn display_runtime_g8_invariants_reject_event_count_drift() {
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
pub(super) fn display_runtime_g8_contract_graph_rejects_missing_dirty_region_edge() {
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
pub(super) fn display_runtime_g8_contract_graph_rejects_dirty_region_binding_drift() {
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

pub(super) fn g9_display_cleanup_graph() -> (SemanticGraph, StoreId, Generation) {
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
pub(super) fn display_runtime_g9_cleanup_releases_leases_mappings_and_revokes_capability() {
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
pub(super) fn display_runtime_g9_rejects_stale_cleanup_and_blocks_post_cleanup_write() {
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
pub(super) fn display_runtime_g9_rejects_cleanup_when_underlying_capability_is_not_active() {
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
pub(super) fn display_runtime_g9_invariants_reject_cleanup_effect_generation_drift() {
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
pub(super) fn display_runtime_g9_contract_graph_rejects_missing_cleanup_effect() {
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
pub(super) fn display_runtime_g10_snapshot_barrier_rejects_active_display_leases() {
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
pub(super) fn display_runtime_g10_snapshot_barrier_validates_after_cleanup() {
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
pub(super) fn display_runtime_g10_snapshot_barrier_rejects_dirty_framebuffer_region_after_cleanup()
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
pub(super) fn display_runtime_g10_invariants_reject_snapshot_barrier_dirty_count_drift() {
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
pub(super) fn display_runtime_g10_contract_graph_rejects_stale_cleanup_ref() {
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

pub(super) fn g11_display_panic_last_frame_graph() -> (SemanticGraph, StoreId, Generation, u64, u64)
{
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
pub(super) fn display_runtime_g11_records_panic_last_frame_summary() {
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
pub(super) fn display_runtime_g11_rejects_raw_bytes_and_stale_barrier() {
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
pub(super) fn display_runtime_g11_invariants_reject_summary_digest_drift() {
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
pub(super) fn display_runtime_g11_contract_graph_rejects_raw_bytes() {
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
pub(super) fn display_runtime_g11_contract_graph_rejects_write_and_flush_binding_mismatch() {
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

pub(super) fn g12_framebuffer_benchmark_graph() -> (SemanticGraph, StoreId, Generation, u64, u64) {
    let (graph, owner_store, owner_store_generation, _, _) = g11_display_panic_last_frame_graph();
    let flush = &graph.framebuffer_flush_regions()[0];
    let sample_bytes = flush.byte_len;
    let frame_area_pixels = u64::from(flush.width) * u64::from(flush.height);
    (graph, owner_store, owner_store_generation, sample_bytes, frame_area_pixels)
}

#[test]
pub(super) fn display_runtime_g12_records_framebuffer_benchmark() {
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
pub(super) fn display_runtime_g12_rejects_stale_barrier_and_bad_timing() {
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
pub(super) fn display_runtime_g12_invariants_reject_throughput_drift() {
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
pub(super) fn display_runtime_g12_contract_graph_rejects_metric_drift() {
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
