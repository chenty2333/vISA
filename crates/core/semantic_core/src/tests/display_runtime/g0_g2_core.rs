use super::*;

#[test]
pub(in crate::tests) fn display_runtime_g0_framebuffer_object_records_contract_identity() {
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
pub(in crate::tests) fn display_runtime_g0_rejects_bad_resource_or_geometry() {
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
pub(in crate::tests) fn display_runtime_g0_invariants_reject_resource_generation_leak() {
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
pub(in crate::tests) fn display_runtime_g0_contract_graph_rejects_bad_framebuffer_geometry() {
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
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        framebuffer_objects: Vec::from([framebuffer]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "framebuffer-object->geometry"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

pub(in crate::tests) fn g1_framebuffer_graph() -> SemanticGraph {
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
pub(in crate::tests) fn display_runtime_g1_display_object_records_framebuffer_mode() {
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
pub(in crate::tests) fn display_runtime_g1_rejects_stale_or_oversized_framebuffer_mode() {
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
pub(in crate::tests) fn display_runtime_g1_invariants_reject_framebuffer_generation_leak() {
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
pub(in crate::tests) fn display_runtime_g1_contract_graph_rejects_missing_framebuffer_edge() {
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
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        display_objects: Vec::from([display]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-object->framebuffer-object"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}

pub(in crate::tests) fn g2_display_capability_graph()
-> (SemanticGraph, StoreId, Generation, CapabilityId) {
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
pub(in crate::tests) fn display_runtime_g2_display_capability_records_store_local_authority() {
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
pub(in crate::tests) fn display_runtime_g2_rejects_stale_display_and_forged_handle() {
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
pub(in crate::tests) fn display_runtime_g2_invariants_reject_capability_generation_leak() {
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
pub(in crate::tests) fn display_runtime_g2_contract_graph_rejects_missing_capability_edge() {
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
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
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
pub(in crate::tests) fn display_runtime_g2_contract_graph_uses_exact_store_generation() {
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
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
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
