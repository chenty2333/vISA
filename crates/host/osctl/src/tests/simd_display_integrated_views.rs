use super::*;

#[test]
fn target_feature_set_view_v1_exposes_simd_discovery() {
    let view = target_feature_set_view_v1(&TargetFeatureSetManifest {
        id: 21_000,
        name: "riscv64-qemu-virt-research-target".to_owned(),
        discovery_source: "target-runtime-default-profile".to_owned(),
        target_profile: "riscv64-qemu-virt-research".to_owned(),
        target_arch: "riscv64".to_owned(),
        base_isa: "rv64imac".to_owned(),
        simd_abi: "riscv-v".to_owned(),
        simd_supported: false,
        vector_register_count: 0,
        vector_register_bits: 0,
        scalar_fallback: true,
        unsupported_reason: "default profile does not declare RVV/SIMD".to_owned(),
        generation: 1,
        state: "discovered".to_owned(),
        recorded_at_event: 489,
        note: "target feature discovery".to_owned(),
    });
    assert_eq!(view["kind"], "target-feature-set");
    assert_eq!(view["owner"]["target_profile"], "riscv64-qemu-virt-research");
    assert_eq!(view["features"]["base_isa"], "rv64imac");
    assert_eq!(view["features"]["simd"]["abi"], "riscv-v");
    assert_eq!(view["features"]["simd"]["supported"], false);
    assert_eq!(view["features"]["simd"]["scalar_fallback"], true);
    assert_eq!(view["last_transition"]["recorded_at_event"], 489);
}

#[test]
fn vector_state_view_v1_exposes_owner_and_simd_shape() {
    let view = vector_state_view_v1(&VectorStateManifest {
        id: 22_000,
        owner_activation: ContractObjectRefManifest {
            kind: "activation".to_owned(),
            id: 7,
            generation: 3,
        },
        owner_store: ContractObjectRefManifest { kind: "store".to_owned(), id: 2, generation: 5 },
        code_object: ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 9,
            generation: 4,
        },
        target_feature_set: ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 21_000,
            generation: 1,
        },
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: "unavailable".to_owned(),
        recorded_at_event: 490,
        note: "v4 vector state".to_owned(),
    });
    assert_eq!(view["kind"], "vector-state");
    assert_eq!(view["owner"]["activation"]["generation"], 3);
    assert_eq!(view["owner"]["store"]["generation"], 5);
    assert_eq!(view["references"]["code_object"]["id"], 9);
    assert_eq!(view["references"]["target_feature_set"]["generation"], 1);
    assert_eq!(view["simd"]["register_bytes"], 512);
    assert_eq!(view["last_error"], "simd-unavailable");
}

#[test]
fn simd_fault_injection_view_v1_exposes_fault_and_exact_refs() {
    let view = simd_fault_injection_view_v1(&SimdFaultInjectionManifest {
        id: 22_010,
        activation: ContractObjectRefManifest {
            kind: "activation".to_owned(),
            id: 11,
            generation: 4,
        },
        code_object: ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 9,
            generation: 4,
        },
        trap: ContractObjectRefManifest { kind: "trap".to_owned(), id: 33, generation: 1 },
        target_feature_set: ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 21_010,
            generation: 1,
        },
        vector_state: None,
        kind: "unsupported-feature".to_owned(),
        effect: "activation-trapped".to_owned(),
        required_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        injected_faults: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 491,
        note: "v10 SIMD fault injection".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "simd-fault-injection");
    assert_eq!(view["owner"]["activation"]["generation"], 4);
    assert_eq!(view["references"]["code_object"]["id"], 9);
    assert_eq!(view["references"]["trap"]["generation"], 1);
    assert_eq!(view["references"]["target_feature_set"]["id"], 21_010);
    assert!(view["references"]["vector_state"].is_null());
    assert_eq!(view["fault"]["kind"], "unsupported-feature");
    assert_eq!(view["fault"]["effect"], "activation-trapped");
    assert_eq!(view["fault"]["required_abi"], "riscv-v");
    assert_eq!(view["fault"]["vector_register_count"], 32);
    assert_eq!(view["fault"]["vector_register_bits"], 128);
    assert_eq!(view["fault"]["injected_faults"], 1);
    assert_eq!(view["last_transition"]["recorded_at_event"], 491);
}

#[test]
fn simd_benchmark_view_v1_exposes_scalar_vector_metrics_and_refs() {
    let view = simd_benchmark_view_v1(&SimdBenchmarkManifest {
        id: 22_011,
        target_feature_set: ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 21_011,
            generation: 1,
        },
        scalar_code_object: ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 41,
            generation: 4,
        },
        vector_code_object: ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 42,
            generation: 5,
        },
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        workload_units: 4096,
        scalar_nanos: 120_000,
        vector_nanos: 40_000,
        speedup_milli: 3000,
        context_overhead_nanos: 80_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 492,
        note: "v11 SIMD benchmark".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "simd-benchmark");
    assert_eq!(view["owner"]["target_feature_set"]["id"], 21_011);
    assert_eq!(view["references"]["scalar_code_object"]["generation"], 4);
    assert_eq!(view["references"]["vector_code_object"]["generation"], 5);
    assert_eq!(view["simd"]["abi"], "riscv-v");
    assert_eq!(view["simd"]["vector_register_count"], 32);
    assert_eq!(view["metrics"]["workload_units"], 4096);
    assert_eq!(view["metrics"]["scalar_nanos"], 120_000);
    assert_eq!(view["metrics"]["vector_nanos"], 40_000);
    assert_eq!(view["metrics"]["speedup_milli"], 3000);
    assert_eq!(view["metrics"]["context_overhead_nanos"], 80_000);
    assert_eq!(view["last_transition"]["recorded_at_event"], 492);
}

#[test]
fn simd_context_switch_benchmark_view_v1_exposes_overhead_and_refs() {
    let view = simd_context_switch_benchmark_view_v1(&SimdContextSwitchBenchmarkManifest {
        id: 22_012,
        preemption: ContractObjectRefManifest {
            kind: "preemption".to_owned(),
            id: 9_070,
            generation: 1,
        },
        activation_resume: ContractObjectRefManifest {
            kind: "activation-resume".to_owned(),
            id: 9_071,
            generation: 1,
        },
        saved_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_002,
            generation: 1,
        },
        restored_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_003,
            generation: 1,
        },
        target_feature_set: ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 21_002,
            generation: 1,
        },
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        sample_count: 64,
        scalar_context_switch_nanos: 30_000,
        vector_context_switch_nanos: 46_384,
        overhead_nanos: 16_384,
        budget_nanos: 50_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 493,
        note: "v12 SIMD context switch benchmark".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "simd-context-switch-benchmark");
    assert_eq!(view["owner"]["activation_resume"]["id"], 9_071);
    assert_eq!(view["references"]["preemption"]["generation"], 1);
    assert_eq!(view["references"]["saved_vector_state"]["id"], 22_002);
    assert_eq!(view["references"]["restored_vector_state"]["id"], 22_003);
    assert_eq!(view["simd"]["abi"], "riscv-v");
    assert_eq!(view["metrics"]["sample_count"], 64);
    assert_eq!(view["metrics"]["scalar_context_switch_nanos"], 30_000);
    assert_eq!(view["metrics"]["vector_context_switch_nanos"], 46_384);
    assert_eq!(view["metrics"]["overhead_nanos"], 16_384);
    assert_eq!(view["metrics"]["budget_nanos"], 50_000);
    assert_eq!(view["last_transition"]["recorded_at_event"], 493);
}

#[test]
fn framebuffer_object_view_v1_exposes_geometry_and_authority_boundary() {
    let view = framebuffer_object_view_v1(&FramebufferObjectManifest {
        id: 23_001,
        name: "fb0".to_owned(),
        resource: 101,
        resource_generation: 2,
        width: 800,
        height: 600,
        stride_bytes: 3200,
        pixel_format: "xrgb8888".to_owned(),
        byte_len: 1_920_000,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 494,
        note: "g0 framebuffer object".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-object");
    assert_eq!(view["owner"]["resource"]["id"], 101);
    assert_eq!(view["references"]["resource"]["generation"], 2);
    assert_eq!(view["geometry"]["width"], 800);
    assert_eq!(view["geometry"]["height"], 600);
    assert_eq!(view["geometry"]["stride_bytes"], 3200);
    assert_eq!(view["geometry"]["pixel_format"], "xrgb8888");
    assert_eq!(view["geometry"]["byte_len"], 1_920_000);
    assert_eq!(
        view["authority"]["write_requires"],
        "display-capability-and-framebuffer-window-lease"
    );
    assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 494);
}

#[test]
fn display_object_view_v1_exposes_mode_and_framebuffer_ref() {
    let view = display_object_view_v1(&DisplayObjectManifest {
        id: 23_101,
        name: "display0".to_owned(),
        framebuffer: 23_001,
        framebuffer_generation: 1,
        mode_name: "800x600@60".to_owned(),
        width: 800,
        height: 600,
        refresh_millihz: 60_000,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 495,
        note: "g1 display object".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-object");
    assert_eq!(view["owner"]["framebuffer"]["id"], 23_001);
    assert_eq!(view["references"]["framebuffer"]["generation"], 1);
    assert_eq!(view["mode"]["name"], "800x600@60");
    assert_eq!(view["mode"]["width"], 800);
    assert_eq!(view["mode"]["height"], 600);
    assert_eq!(view["mode"]["refresh_millihz"], 60_000);
    assert_eq!(
        view["authority"]["write_requires"],
        "display-capability-and-framebuffer-window-lease"
    );
    assert_eq!(view["authority"]["flush_requires"], "display-capability");
    assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 495);
}

#[test]
fn display_capability_view_v1_exposes_handle_and_generation_refs() {
    let view = display_capability_view_v1(&DisplayCapabilityManifest {
        id: 23_201,
        owner_store: 12,
        owner_store_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        capability: 25,
        capability_generation: 1,
        handle_slot: 8,
        handle_generation: 1,
        handle_tag: 99,
        operations: vec!["flush".to_owned(), "lease".to_owned()],
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 496,
        note: "g2 display capability".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-capability");
    assert_eq!(view["owner"]["store"]["id"], 12);
    assert_eq!(view["references"]["display"]["id"], 23_101);
    assert_eq!(view["references"]["framebuffer"]["generation"], 1);
    assert_eq!(view["references"]["capability"]["id"], 25);
    assert_eq!(view["authority"]["class"], "display");
    assert_eq!(view["authority"]["operations"][0], "flush");
    assert_eq!(view["authority"]["operations"][1], "lease");
    assert_eq!(view["authority"]["handle"]["slot"], 8);
    assert_eq!(view["authority"]["write_requires_framebuffer_window_lease"], true);
    assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 496);
}

#[test]
fn framebuffer_window_lease_view_v1_exposes_window_and_authority_refs() {
    let view = framebuffer_window_lease_view_v1(&FramebufferWindowLeaseManifest {
        id: 23_301,
        owner_store: 12,
        owner_store_generation: 2,
        display_capability: 23_201,
        display_capability_generation: 1,
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
        access: "write".to_owned(),
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 497,
        note: "g3 framebuffer window lease".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-window-lease");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["display_capability"]["id"], 23_201);
    assert_eq!(view["references"]["display"]["generation"], 1);
    assert_eq!(view["references"]["framebuffer"]["id"], 23_001);
    assert_eq!(view["window"]["width"], 800);
    assert_eq!(view["window"]["byte_len"], 1_920_000);
    assert_eq!(view["authority"]["requires_display_capability_operation"], "lease");
    assert_eq!(view["authority"]["write_requires_this_lease"], true);
    assert_eq!(view["authority"]["raw_mapping_is_semantic_truth"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 497);
}

#[test]
fn framebuffer_mapping_view_v1_exposes_handle_mode_mapping_refs() {
    let view = framebuffer_mapping_view_v1(&FramebufferMappingManifest {
        id: 23_401,
        owner_store: 12,
        owner_store_generation: 2,
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
        width: 800,
        height: 600,
        byte_offset: 0,
        byte_len: 1_920_000,
        access: "write".to_owned(),
        mode: "handle-mode".to_owned(),
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 498,
        note: "g4 framebuffer mapping".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-mapping");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_window_lease"]["id"], 23_301);
    assert_eq!(view["references"]["display_capability"]["id"], 23_201);
    assert_eq!(view["references"]["framebuffer"]["id"], 23_001);
    assert_eq!(view["map_handle"]["slot"], 3);
    assert_eq!(view["map_handle"]["mode"], "handle-mode");
    assert_eq!(view["window"]["byte_len"], 1_920_000);
    assert_eq!(view["authority"]["requires_framebuffer_window_lease"], true);
    assert_eq!(view["authority"]["raw_pointer_exposed"], false);
    assert_eq!(view["authority"]["pixel_write_allowed"], false);
    assert_eq!(view["authority"]["flush_allowed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 498);
}

#[test]
fn framebuffer_write_view_v1_exposes_semantic_pixel_write_refs() {
    let view = framebuffer_write_view_v1(&FramebufferWriteManifest {
        id: 23_501,
        owner_store: 12,
        owner_store_generation: 2,
        framebuffer_mapping: 23_401,
        framebuffer_mapping_generation: 1,
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
        width: 800,
        height: 1,
        byte_offset: 0,
        byte_len: 3200,
        pixel_format: "xrgb8888".to_owned(),
        payload_digest: 12_345,
        generation: 1,
        state: "applied".to_owned(),
        recorded_at_event: 499,
        note: "g5 framebuffer write".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-write");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_mapping"]["id"], 23_401);
    assert_eq!(view["references"]["framebuffer_window_lease"]["id"], 23_301);
    assert_eq!(view["map_handle"]["slot"], 3);
    assert_eq!(view["write"]["byte_len"], 3200);
    assert_eq!(view["write"]["pixel_format"], "xrgb8888");
    assert_eq!(view["authority"]["requires_framebuffer_mapping"], true);
    assert_eq!(view["authority"]["raw_pointer_exposed"], false);
    assert_eq!(view["authority"]["flush_allowed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 499);
}

#[test]
fn framebuffer_flush_region_view_v1_exposes_flush_refs() {
    let view = framebuffer_flush_region_view_v1(&FramebufferFlushRegionManifest {
        id: 23_601,
        owner_store: 12,
        owner_store_generation: 2,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        x: 0,
        y: 0,
        width: 800,
        height: 1,
        byte_offset: 0,
        byte_len: 3200,
        pixel_format: "xrgb8888".to_owned(),
        payload_digest: 12_345,
        generation: 1,
        state: "applied".to_owned(),
        recorded_at_event: 500,
        note: "g6 framebuffer flush".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-flush-region");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_write"]["id"], 23_501);
    assert_eq!(view["references"]["display_capability"]["id"], 23_201);
    assert_eq!(view["flush"]["byte_len"], 3200);
    assert_eq!(view["flush"]["pixel_format"], "xrgb8888");
    assert_eq!(view["authority"]["requires_display_capability_flush"], true);
    assert_eq!(view["authority"]["requires_framebuffer_write"], true);
    assert_eq!(view["authority"]["raw_pointer_exposed"], false);
    assert_eq!(view["authority"]["real_present_executed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 500);
}

#[test]
fn framebuffer_dirty_region_view_v1_exposes_dirty_tracking_refs() {
    let view = framebuffer_dirty_region_view_v1(&FramebufferDirtyRegionManifest {
        id: 23_701,
        owner_store: 12,
        owner_store_generation: 2,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        framebuffer_flush_region: Some(23_601),
        framebuffer_flush_region_generation: Some(1),
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        x: 0,
        y: 0,
        width: 800,
        height: 1,
        byte_offset: 0,
        byte_len: 3200,
        pixel_format: "xrgb8888".to_owned(),
        payload_digest: 12_345,
        generation: 1,
        state: "clean".to_owned(),
        dirty_at_event: 499,
        cleaned_at_event: Some(500),
        recorded_at_event: 501,
        note: "g7 framebuffer dirty region".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-dirty-region");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_write"]["id"], 23_501);
    assert_eq!(view["references"]["framebuffer_flush_region"]["id"], 23_601);
    assert_eq!(view["region"]["byte_len"], 3200);
    assert_eq!(view["region"]["pixel_format"], "xrgb8888");
    assert_eq!(view["authority"]["requires_framebuffer_write"], true);
    assert_eq!(view["authority"]["clean_state_requires_flush_region"], true);
    assert_eq!(view["authority"]["raw_pointer_exposed"], false);
    assert_eq!(view["authority"]["real_present_executed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 501);
}

#[test]
fn display_event_log_view_v1_exposes_event_window_refs() {
    let view = display_event_log_view_v1(&DisplayEventLogManifest {
        id: 23_801,
        owner_store: 12,
        owner_store_generation: 2,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        framebuffer_dirty_region: 23_701,
        framebuffer_dirty_region_generation: 1,
        first_event: 494,
        last_event: 501,
        event_count: 8,
        flush_count: 1,
        dirty_region_count: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 502,
        note: "g8 display event log".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-event-log");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_dirty_region"]["id"], 23_701);
    assert_eq!(view["window"]["first_event"], 494);
    assert_eq!(view["window"]["last_event"], 501);
    assert_eq!(view["window"]["event_count"], 8);
    assert_eq!(view["window"]["flush_count"], 1);
    assert_eq!(view["window"]["dirty_region_count"], 1);
    assert_eq!(view["authority"]["read_only_control_plane"], true);
    assert_eq!(view["authority"]["raw_event_storage_exposed"], false);
    assert_eq!(view["authority"]["real_present_executed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 502);
}

#[test]
fn display_cleanup_view_v1_exposes_cleanup_effects_and_generations() {
    let view = display_cleanup_view_v1(&DisplayCleanupManifest {
        id: 23_901,
        owner_store: 12,
        owner_store_generation: 2,
        display_capability: 23_201,
        display_capability_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        generation: 1,
        state: "completed".to_owned(),
        reason: "display-window-cleanup".to_owned(),
        started_at_event: 503,
        completed_at_event: 505,
        unmapped_framebuffer_mappings: vec![ContractObjectRefManifest {
            kind: "framebuffer-mapping".to_owned(),
            id: 23_401,
            generation: 1,
        }],
        released_framebuffer_window_leases: vec![ContractObjectRefManifest {
            kind: "framebuffer-window-lease".to_owned(),
            id: 23_301,
            generation: 1,
        }],
        revoked_display_capabilities: vec![ContractObjectRefManifest {
            kind: "display-capability".to_owned(),
            id: 23_201,
            generation: 1,
        }],
        revoked_capabilities: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 77,
            generation: 2,
        }],
        steps: Vec::new(),
        note: "g9 display cleanup".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-cleanup");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["display_capability"]["id"], 23_201);
    assert_eq!(view["cleanup"]["reason"], "display-window-cleanup");
    assert_eq!(view["cleanup"]["unmapped_framebuffer_mappings"][0]["kind"], "framebuffer-mapping");
    assert_eq!(view["cleanup"]["released_framebuffer_window_leases"][0]["id"], 23_301);
    assert_eq!(view["cleanup"]["revoked_display_capabilities"][0]["generation"], 1);
    assert_eq!(view["cleanup"]["revoked_capabilities"][0]["generation"], 2);
    assert_eq!(view["authority"]["releases_handle_mode_mappings"], true);
    assert_eq!(view["authority"]["real_present_executed"], false);
    assert_eq!(view["last_transition"]["completed_at_event"], 505);
}

#[test]
fn display_snapshot_barrier_view_v1_exposes_quiescent_display_boundary() {
    let view = display_snapshot_barrier_view_v1(&DisplaySnapshotBarrierManifest {
        id: 24_001,
        owner_store: 12,
        owner_store_generation: 2,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        display_cleanup: Some(23_901),
        display_cleanup_generation: Some(1),
        active_framebuffer_window_lease_count: 0,
        active_framebuffer_mapping_count: 0,
        dirty_framebuffer_region_count: 0,
        snapshot_validation_ok: true,
        generation: 1,
        state: "validated".to_owned(),
        validated_at_event: 506,
        reason: "display-snapshot-barrier".to_owned(),
        note: "g10 display snapshot".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-snapshot-barrier");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["display_cleanup"]["id"], 23_901);
    assert_eq!(view["snapshot"]["snapshot_validation_ok"], true);
    assert_eq!(view["snapshot"]["active_framebuffer_window_lease_count"], 0);
    assert_eq!(view["authority"]["requires_no_active_framebuffer_lease"], true);
    assert_eq!(view["authority"]["real_snapshot_cow_executed"], false);
    assert_eq!(view["last_transition"]["validated_at_event"], 506);
}

#[test]
fn display_panic_last_frame_view_v1_exposes_panic_safe_summary() {
    let view = display_panic_last_frame_view_v1(&DisplayPanicLastFrameManifest {
        id: 25_001,
        owner_store: 12,
        owner_store_generation: 2,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        display_snapshot_barrier: 24_001,
        display_snapshot_barrier_generation: 1,
        display_event_log: 23_801,
        display_event_log_generation: 1,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        framebuffer_flush_region: 23_601,
        framebuffer_flush_region_generation: 1,
        x: 0,
        y: 0,
        width: 800,
        height: 1,
        byte_offset: 0,
        byte_len: 3200,
        pixel_format: "xrgb8888".to_owned(),
        payload_digest: 12_345,
        summary_digest: 54_321,
        summary_record_bytes: 512,
        panic_epoch: 1,
        panic_cpu: 0,
        panic_reason_code: 1,
        panic_record_kind: "contract-panic-summary-v1".to_owned(),
        raw_framebuffer_bytes_exported: false,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 507,
        note: "g11 display panic last-frame".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "display-panic-last-frame");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["display_snapshot_barrier"]["id"], 24_001);
    assert_eq!(view["references"]["display_event_log"]["id"], 23_801);
    assert_eq!(view["frame"]["payload_digest"], 12_345);
    assert_eq!(view["frame"]["summary_digest"], 54_321);
    assert_eq!(view["panic"]["record_kind"], "contract-panic-summary-v1");
    assert_eq!(view["panic"]["summary_record_bytes"], 512);
    assert_eq!(view["panic"]["raw_framebuffer_bytes_exported"], false);
    assert_eq!(view["authority"]["panic_path_allocates"], false);
    assert_eq!(view["authority"]["real_panic_ring_write_executed"], false);
    assert_eq!(view["last_transition"]["recorded_at_event"], 507);
}

#[test]
fn framebuffer_benchmark_view_v1_exposes_semantic_display_metrics() {
    let view = framebuffer_benchmark_view_v1(&FramebufferBenchmarkManifest {
        id: 25_101,
        scenario: "display-g12-single-flush".to_owned(),
        owner_store: 12,
        owner_store_generation: 2,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 1,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        framebuffer_flush_region: 23_601,
        framebuffer_flush_region_generation: 1,
        display_event_log: 23_801,
        display_event_log_generation: 1,
        display_snapshot_barrier: 24_001,
        display_snapshot_barrier_generation: 1,
        sample_frames: 1,
        sample_bytes: 3200,
        frame_area_pixels: 800,
        write_nanos: 40_000,
        flush_nanos: 60_000,
        measured_nanos: 100_000,
        budget_nanos: 200_000,
        throughput_bytes_per_sec: 32_000_000,
        flushes_per_sec_milli: 10_000_000,
        p50_latency_nanos: 100_000,
        p99_latency_nanos: 100_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 508,
        note: "g12 framebuffer benchmark".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "framebuffer-benchmark");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_write"]["id"], 23_501);
    assert_eq!(view["references"]["framebuffer_flush_region"]["id"], 23_601);
    assert_eq!(view["references"]["display_snapshot_barrier"]["id"], 24_001);
    assert_eq!(view["benchmark"]["sample_bytes"], 3200);
    assert_eq!(view["benchmark"]["throughput_bytes_per_sec"], 32_000_000);
    assert_eq!(view["benchmark"]["flushes_per_sec_milli"], 10_000_000);
    assert_eq!(view["authority"]["real_scanout_measured"], false);
    assert_eq!(view["authority"]["uses_semantic_write_flush_evidence"], true);
    assert_eq!(view["last_transition"]["recorded_at_event"], 508);
}

#[test]
fn integrated_smp_preemption_cleanup_view_v1_exposes_runtime_closure_refs() {
    let view = integrated_smp_preemption_cleanup_view_v1(&IntegratedSmpPreemptionCleanupManifest {
        id: 26_001,
        scenario: "x0-smp-preemption-cleanup".to_owned(),
        stress_run: 9_501,
        stress_run_generation: 1,
        preemption: 9_001,
        preemption_generation: 1,
        timer_interrupt: 9_001,
        timer_interrupt_generation: 1,
        saved_context: 9_002,
        saved_context_generation: 1,
        remote_preempt: 9_001,
        remote_preempt_generation: 1,
        activation_cleanup: 9_001,
        activation_cleanup_generation: 1,
        smp_cleanup_quiescence: 9_301,
        smp_cleanup_quiescence_generation: 1,
        cleanup_store: 14,
        target_store_generation: 2,
        result_store_generation: 3,
        cleanup_activation: 77,
        cleanup_activation_generation_after: 4,
        hart_count: 2,
        invariant_checks: 7,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 570,
        note: "x0 integrated runtime".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-smp-preemption-cleanup");
    assert_eq!(view["owner"]["cleanup_store"]["generation"], 2);
    assert_eq!(view["owner"]["runtime_activation"]["id"], 77);
    assert_eq!(view["owner"]["runtime_activation"]["generation_after_cleanup"], 4);
    assert_eq!(
        view["owner"]["runtime_activation"]["note"],
        "runtime-preemptive-activation-not-target-executor-object"
    );
    assert_eq!(view["references"]["smp_stress_run"]["id"], 9_501);
    assert_eq!(view["references"]["remote_preempt"]["generation"], 1);
    assert_eq!(view["references"]["activation_cleanup"]["id"], 9_001);
    assert_eq!(view["references"]["smp_cleanup_quiescence"]["id"], 9_301);
    assert_eq!(view["closure"]["hart_count"], 2);
    assert_eq!(view["closure"]["result_store_generation"], 3);
    assert_eq!(view["closure"]["invariant_checks"], 7);
    assert_eq!(view["authority"]["real_smp_preemption_executed"], false);
    assert_eq!(view["authority"]["uses_semantic_preemption_cleanup_evidence"], true);
    assert_eq!(view["last_transition"]["recorded_at_event"], 570);
}

#[test]
fn integrated_smp_network_fault_view_v1_exposes_network_fault_under_smp_refs() {
    let view = integrated_smp_network_fault_view_v1(&IntegratedSmpNetworkFaultManifest {
        id: 26_101,
        scenario: "x1-smp-network-driver-fault".to_owned(),
        network_driver_cleanup: 10_051,
        network_driver_cleanup_generation: 1,
        smp_stress_run: 9_501,
        smp_stress_run_generation: 1,
        remote_preempt: 9_001,
        remote_preempt_generation: 1,
        smp_cleanup_quiescence: 9_301,
        smp_cleanup_quiescence_generation: 1,
        driver_store: 7,
        driver_store_generation: 3,
        packet_device: 10_002,
        packet_device_generation: 1,
        adapter: 10_025,
        adapter_generation: 1,
        backend: ContractObjectRefManifest {
            kind: "virtio-net-backend-object".to_owned(),
            id: 10_010,
            generation: 1,
        },
        io_cleanup: 10_052,
        io_cleanup_generation: 1,
        cancelled_socket_wait_count: 1,
        cancelled_wait_token_count: 1,
        revoked_packet_capability_count: 1,
        hart_count: 2,
        invariant_checks: 7,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 571,
        note: "x1 integrated network fault".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-smp-network-fault");
    assert_eq!(view["owner"]["driver_store"]["generation"], 3);
    assert_eq!(view["owner"]["packet_device"]["id"], 10_002);
    assert_eq!(view["references"]["network_driver_cleanup"]["id"], 10_051);
    assert_eq!(view["references"]["smp_stress_run"]["id"], 9_501);
    assert_eq!(view["references"]["remote_preempt"]["generation"], 1);
    assert_eq!(view["references"]["smp_cleanup_quiescence"]["id"], 9_301);
    assert_eq!(view["references"]["backend"]["kind"], "virtio-net-backend-object");
    assert_eq!(view["references"]["io_cleanup"]["id"], 10_052);
    assert_eq!(view["closure"]["hart_count"], 2);
    assert_eq!(view["closure"]["cancelled_socket_wait_count"], 1);
    assert_eq!(view["closure"]["revoked_packet_capability_count"], 1);
    assert_eq!(view["authority"]["adapter_internal_state_is_not_semantic_truth"], true);
    assert_eq!(view["authority"]["real_network_driver_fault_executed"], false);
    assert_eq!(view["last_transition"]["event"], 571);
}

#[test]
fn integrated_disk_preempt_fault_view_v1_exposes_pending_io_and_preemption_refs() {
    let view = integrated_disk_preempt_fault_view_v1(&IntegratedDiskPreemptFaultManifest {
        id: 26_201,
        scenario: "x2-disk-pending-io-fault-under-preemption".to_owned(),
        preemption: 9_070,
        preemption_generation: 1,
        timer_interrupt: 9_070,
        timer_interrupt_generation: 1,
        block_pending_io_policy: 20_124,
        block_pending_io_policy_generation: 1,
        block_wait: 20_118,
        block_wait_generation: 1,
        wait: 20_117,
        wait_generation: 1,
        block_request: 20_116,
        block_request_generation: 1,
        retry_request: None,
        retry_request_generation: None,
        block_device: 20_002,
        block_device_generation: 1,
        block_range: 20_005,
        block_range_generation: 1,
        driver_store: Some(15),
        driver_store_generation: Some(2),
        action: "eio".to_owned(),
        errno: 5,
        preempted_activation: 88,
        preempted_activation_generation_after: 4,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 572,
        note: "x2 integrated disk preempt fault".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-disk-preempt-fault");
    assert_eq!(view["owner"]["driver_store"]["id"], 15);
    assert_eq!(view["references"]["preemption"]["id"], 9_070);
    assert_eq!(view["references"]["timer_interrupt"]["generation"], 1);
    assert_eq!(view["references"]["block_pending_io_policy"]["id"], 20_124);
    assert_eq!(view["references"]["block_wait"]["id"], 20_118);
    assert_eq!(view["references"]["wait"]["kind"], "wait-token");
    assert_eq!(view["references"]["block_request"]["id"], 20_116);
    assert_eq!(view["references"]["retry_request"], serde_json::Value::Null);
    assert_eq!(view["references"]["block_device"]["id"], 20_002);
    assert_eq!(view["references"]["block_range"]["id"], 20_005);
    assert_eq!(view["closure"]["action"], "eio");
    assert_eq!(view["closure"]["errno"], 5);
    assert_eq!(view["closure"]["preempted_activation"]["id"], 88);
    assert_eq!(view["authority"]["adapter_internal_state_is_not_semantic_truth"], true);
    assert_eq!(view["authority"]["real_disk_fault_executed"], false);
    assert_eq!(view["last_transition"]["event"], 572);
}

#[test]
fn integrated_simd_migration_view_v1_exposes_vector_rehome_refs() {
    let view = integrated_simd_migration_view_v1(&IntegratedSimdMigrationManifest {
        id: 26_301,
        scenario: "x3-simd-task-migration-across-harts".to_owned(),
        activation_migration: 9_080,
        activation_migration_generation: 1,
        target_feature_set: 21_003,
        target_feature_set_generation: 1,
        source_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_004,
            generation: 1,
        },
        migrated_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_005,
            generation: 1,
        },
        activation: 89,
        activation_generation_before: 2,
        activation_generation_after: 3,
        context: 9_080,
        context_generation_after: 3,
        source_hart: 8,
        source_hart_generation: 2,
        target_hart: 9,
        target_hart_generation: 2,
        source_queue: 9_080,
        source_queue_generation: 2,
        target_queue: 9_081,
        target_queue_generation: 2,
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 573,
        note: "x3 integrated SIMD migration".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-simd-migration");
    assert_eq!(view["owner"]["activation"]["id"], 89);
    assert_eq!(view["owner"]["source_hart"]["id"], 8);
    assert_eq!(view["owner"]["target_hart"]["id"], 9);
    assert_eq!(view["references"]["activation_migration"]["id"], 9_080);
    assert_eq!(view["references"]["target_feature_set"]["id"], 21_003);
    assert_eq!(view["references"]["source_vector_state"]["id"], 22_004);
    assert_eq!(view["references"]["migrated_vector_state"]["id"], 22_005);
    assert_eq!(view["references"]["context"]["generation"], 3);
    assert_eq!(view["closure"]["simd_abi"], "riscv-v");
    assert_eq!(view["closure"]["requires_clean_vector_context"], true);
    assert_eq!(view["closure"]["requires_source_vector_dropped"], true);
    assert_eq!(view["authority"]["adapter_internal_state_is_not_semantic_truth"], true);
    assert_eq!(view["authority"]["real_vector_register_payload_migrated"], false);
    assert_eq!(view["last_transition"]["event"], 573);
}

#[test]
fn integrated_simd_migration_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_simd_migration_count = 1;
    package.semantic.integrated_simd_migrations.push(IntegratedSimdMigrationManifest {
        id: 26_301,
        scenario: "x3-simd-task-migration-across-harts".to_owned(),
        activation_migration: 9_080,
        activation_migration_generation: 1,
        target_feature_set: 21_003,
        target_feature_set_generation: 1,
        source_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_004,
            generation: 1,
        },
        migrated_vector_state: ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_005,
            generation: 1,
        },
        activation: 89,
        activation_generation_before: 2,
        activation_generation_after: 3,
        context: 9_080,
        context_generation_after: 3,
        source_hart: 8,
        source_hart_generation: 2,
        target_hart: 9,
        target_hart_generation: 2,
        source_queue: 9_080,
        source_queue_generation: 2,
        target_queue: 9_081,
        target_queue_generation: 2,
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 573,
        note: "x3 integrated SIMD migration".to_owned(),
    });

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "integrated-simd-migration"));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-simd-migration"
        && edge["relation"] == "integrated-source-vector-state"
        && edge["to"]["kind"] == "vector-state"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-simd-migration"
        && edge["relation"] == "integrated-migrated-vector-state"
        && edge["to"]["kind"] == "vector-state"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-simd-migration"
        && edge["relation"] == "integrated-activation-migration"
        && edge["to"]["kind"] == "activation-migration"
        && edge["to"]["generation"] == 1));
}

#[test]
fn integrated_network_disk_io_view_v1_exposes_benchmark_refs() {
    let view = integrated_network_disk_io_view_v1(&IntegratedNetworkDiskIoManifest {
        id: 26_401,
        scenario: "x4-network-disk-concurrent-io".to_owned(),
        network_benchmark: 10_067,
        network_benchmark_generation: 1,
        block_benchmark: 20_132,
        block_benchmark_generation: 1,
        network_owner_store: 9,
        network_owner_store_generation: 3,
        network_adapter: 10_025,
        network_adapter_generation: 1,
        packet_device: 10_002,
        packet_device_generation: 1,
        socket: 10_031,
        socket_generation: 1,
        block_backend: ContractObjectRefManifest {
            kind: "fake-block-backend-object".to_owned(),
            id: 20_026,
            generation: 1,
        },
        block_device: 20_002,
        block_device_generation: 1,
        block_request_queue: 20_053,
        block_request_queue_generation: 1,
        block_dma_buffer: 20_061,
        block_dma_buffer_generation: 1,
        network_sample_bytes: 6_000,
        block_sample_bytes: 8_192,
        network_sample_packets: 3,
        block_sample_requests: 2,
        concurrent_window_nanos: 120_000,
        combined_throughput_bytes_per_sec: 118_266_666,
        max_p99_latency_nanos: 48_000,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 574,
        note: "x4 integrated IO concurrency".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-network-disk-io");
    assert_eq!(view["owner"]["network_owner_store"]["generation"], 3);
    assert_eq!(view["references"]["network_benchmark"]["id"], 10_067);
    assert_eq!(view["references"]["block_benchmark"]["id"], 20_132);
    assert_eq!(view["references"]["block_backend"]["kind"], "fake-block-backend-object");
    assert_eq!(view["references"]["block_dma_buffer"]["id"], 20_061);
    assert_eq!(view["closure"]["network_sample_bytes"], 6_000);
    assert_eq!(view["closure"]["block_sample_bytes"], 8_192);
    assert_eq!(view["closure"]["concurrent_window_nanos"], 120_000);
    assert_eq!(view["closure"]["combined_throughput_bytes_per_sec"], 118_266_666);
    assert_eq!(view["authority"]["adapter_internal_state_is_not_semantic_truth"], true);
    assert_eq!(view["authority"]["real_concurrent_hardware_io_executed"], false);
}

#[test]
fn integrated_network_disk_io_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_network_disk_io_count = 1;
    package.semantic.integrated_network_disk_ios.push(IntegratedNetworkDiskIoManifest {
        id: 26_401,
        scenario: "x4-network-disk-concurrent-io".to_owned(),
        network_benchmark: 10_067,
        network_benchmark_generation: 1,
        block_benchmark: 20_132,
        block_benchmark_generation: 1,
        network_owner_store: 9,
        network_owner_store_generation: 3,
        network_adapter: 10_025,
        network_adapter_generation: 1,
        packet_device: 10_002,
        packet_device_generation: 1,
        socket: 10_031,
        socket_generation: 1,
        block_backend: ContractObjectRefManifest {
            kind: "fake-block-backend-object".to_owned(),
            id: 20_026,
            generation: 1,
        },
        block_device: 20_002,
        block_device_generation: 1,
        block_request_queue: 20_053,
        block_request_queue_generation: 1,
        block_dma_buffer: 20_061,
        block_dma_buffer_generation: 1,
        network_sample_bytes: 6_000,
        block_sample_bytes: 8_192,
        network_sample_packets: 3,
        block_sample_requests: 2,
        concurrent_window_nanos: 120_000,
        combined_throughput_bytes_per_sec: 118_266_666,
        max_p99_latency_nanos: 48_000,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 574,
        note: "x4 integrated IO concurrency".to_owned(),
    });

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "integrated-network-disk-io"));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-network-disk-io"
        && edge["relation"] == "integrated-network-benchmark"
        && edge["to"]["kind"] == "network-benchmark"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-network-disk-io"
        && edge["relation"] == "integrated-block-dma-buffer"
        && edge["to"]["kind"] == "block-dma-buffer"
        && edge["to"]["generation"] == 1));
}

#[test]
fn integrated_display_scheduler_load_view_v1_exposes_display_and_scheduler_refs() {
    let view = integrated_display_scheduler_load_view_v1(&IntegratedDisplaySchedulerLoadManifest {
        id: 26_501,
        scenario: "x5-display-update-during-scheduler-load".to_owned(),
        framebuffer_benchmark: 25_101,
        framebuffer_benchmark_generation: 1,
        scheduler_decision: 9_001,
        scheduler_decision_generation: 1,
        owner_store: 1,
        owner_store_generation: 2,
        owner_task: 7,
        owner_task_generation: 1,
        queue: 9_002,
        queue_generation: 2,
        selected_activation: 9_002,
        selected_activation_generation: 4,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        display_capability: 23_201,
        display_capability_generation: 1,
        framebuffer_write: 23_501,
        framebuffer_write_generation: 1,
        framebuffer_flush_region: 23_601,
        framebuffer_flush_region_generation: 1,
        display_event_log: 23_801,
        display_event_log_generation: 1,
        sample_frames: 1,
        sample_bytes: 3_200,
        scheduler_load_units: 1,
        display_measured_nanos: 100_000,
        scheduler_decided_at_event: 50,
        display_recorded_at_event: 571,
        invariant_checks: 6,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 575,
        note: "x5 integrated display scheduler load".to_owned(),
    });

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-display-scheduler-load");
    assert_eq!(view["owner"]["store"]["generation"], 2);
    assert_eq!(view["references"]["framebuffer_benchmark"]["id"], 25_101);
    assert_eq!(view["references"]["scheduler_decision"]["id"], 9_001);
    assert_eq!(view["references"]["selected_activation"]["generation"], 4);
    assert_eq!(view["closure"]["sample_bytes"], 3_200);
    assert_eq!(view["closure"]["scheduler_load_units"], 1);
    assert_eq!(view["authority"]["real_display_hardware_executed"], false);
    assert_eq!(view["authority"]["real_preemptive_scheduler_executed"], false);
}

#[test]
fn integrated_display_scheduler_load_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_display_scheduler_load_count = 1;
    package.semantic.integrated_display_scheduler_loads.push(
        IntegratedDisplaySchedulerLoadManifest {
            id: 26_501,
            scenario: "x5-display-update-during-scheduler-load".to_owned(),
            framebuffer_benchmark: 25_101,
            framebuffer_benchmark_generation: 1,
            scheduler_decision: 9_001,
            scheduler_decision_generation: 1,
            owner_store: 1,
            owner_store_generation: 2,
            owner_task: 7,
            owner_task_generation: 1,
            queue: 9_002,
            queue_generation: 2,
            selected_activation: 9_002,
            selected_activation_generation: 4,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            display_capability: 23_201,
            display_capability_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            sample_frames: 1,
            sample_bytes: 3_200,
            scheduler_load_units: 1,
            display_measured_nanos: 100_000,
            scheduler_decided_at_event: 50,
            display_recorded_at_event: 571,
            invariant_checks: 6,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 575,
            note: "x5 integrated display scheduler load".to_owned(),
        },
    );

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(!live.iter().any(|edge| edge["from"]["kind"] == "integrated-display-scheduler-load"));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-display-scheduler-load"
        && edge["relation"] == "integrated-framebuffer-benchmark"
        && edge["to"]["kind"] == "framebuffer-benchmark"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-display-scheduler-load"
        && edge["relation"] == "integrated-scheduler-decision"
        && edge["to"]["kind"] == "scheduler-decision"
        && edge["to"]["generation"] == 1));
}

fn test_integrated_snapshot_io_lease_barrier_manifest() -> IntegratedSnapshotIoLeaseBarrierManifest
{
    IntegratedSnapshotIoLeaseBarrierManifest {
        id: 26_601,
        scenario: "x6-snapshot-barrier-blocks-active-io-leases".to_owned(),
        smp_snapshot_barrier: 9_401,
        smp_snapshot_barrier_generation: 1,
        io_cleanup: 9_967,
        io_cleanup_generation: 1,
        display_snapshot_barrier: 24_001,
        display_snapshot_barrier_generation: 1,
        driver_store: 2,
        driver_store_generation: 2,
        device: 9_701,
        device_generation: 1,
        display: 23_101,
        display_generation: 1,
        framebuffer: 23_001,
        framebuffer_generation: 1,
        active_dmw_lease_count: 0,
        in_flight_dma_count: 0,
        raw_dma_binding_count: 0,
        raw_mmio_binding_count: 0,
        active_framebuffer_window_lease_count: 0,
        active_framebuffer_mapping_count: 0,
        dirty_framebuffer_region_count: 0,
        released_dma_buffers: 1,
        released_mmio_regions: 1,
        released_irq_lines: 1,
        released_framebuffer_window_leases: 1,
        revoked_device_capabilities: 4,
        revoked_display_capabilities: 1,
        smp_barrier_event: 117,
        io_cleanup_completed_event: 152,
        display_barrier_event: 567,
        invariant_checks: 7,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 576,
        note: "x6 integrated snapshot/io lease barrier".to_owned(),
    }
}

#[test]
fn integrated_snapshot_io_lease_barrier_view_v1_exposes_barrier_and_cleanup_refs() {
    let view = integrated_snapshot_io_lease_barrier_view_v1(
        &test_integrated_snapshot_io_lease_barrier_manifest(),
    );

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-snapshot-io-lease-barrier");
    assert_eq!(view["owner"]["driver_store"]["generation"], 2);
    assert_eq!(view["owner"]["device"]["id"], 9_701);
    assert_eq!(view["owner"]["display"]["id"], 23_101);
    assert_eq!(view["references"]["smp_snapshot_barrier"]["id"], 9_401);
    assert_eq!(view["references"]["io_cleanup"]["id"], 9_967);
    assert_eq!(view["references"]["display_snapshot_barrier"]["id"], 24_001);
    assert_eq!(view["closure"]["active_dmw_lease_count"], 0);
    assert_eq!(view["closure"]["in_flight_dma_count"], 0);
    assert_eq!(view["closure"]["released_dma_buffers"], 1);
    assert_eq!(view["closure"]["released_mmio_regions"], 1);
    assert_eq!(view["closure"]["released_irq_lines"], 1);
    assert_eq!(view["closure"]["released_framebuffer_window_leases"], 1);
    assert_eq!(view["closure"]["requires_clean_smp_snapshot_barrier"], true);
    assert_eq!(view["closure"]["requires_completed_io_cleanup"], true);
    assert_eq!(view["closure"]["requires_clean_display_snapshot_barrier"], true);
    assert_eq!(view["authority"]["real_snapshot_or_dma_hardware_executed"], false);
    assert_eq!(view["authority"]["real_display_hardware_executed"], false);
    assert_eq!(view["last_transition"]["event"], 576);
}

#[test]
fn integrated_snapshot_io_lease_barrier_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_snapshot_io_lease_barrier_count = 1;
    package
        .semantic
        .integrated_snapshot_io_lease_barriers
        .push(test_integrated_snapshot_io_lease_barrier_manifest());

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(
        !live.iter().any(|edge| { edge["from"]["kind"] == "integrated-snapshot-io-lease-barrier" })
    );

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-snapshot-io-lease-barrier"
        && edge["relation"] == "integrated-smp-snapshot-barrier"
        && edge["to"]["kind"] == "smp-snapshot-barrier"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-snapshot-io-lease-barrier"
        && edge["relation"] == "integrated-io-cleanup"
        && edge["to"]["kind"] == "io-cleanup"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-snapshot-io-lease-barrier"
        && edge["relation"] == "integrated-display-snapshot-barrier"
        && edge["to"]["kind"] == "display-snapshot-barrier"
        && edge["to"]["generation"] == 1));
}

fn test_integrated_code_publish_smp_workload_manifest() -> IntegratedCodePublishSmpWorkloadManifest
{
    IntegratedCodePublishSmpWorkloadManifest {
        id: 26_701,
        scenario: "x7-code-publish-while-smp-workload-active".to_owned(),
        smp_stress_run: 9_501,
        smp_stress_run_generation: 1,
        smp_code_publish_barrier: 9_201,
        smp_code_publish_barrier_generation: 1,
        publish_rendezvous: 9_101,
        publish_rendezvous_generation: 1,
        publish_safe_point: 9_001,
        publish_safe_point_generation: 1,
        hart_count: 2,
        workload_iterations: 3,
        observed_safe_point_count: 3,
        observed_rendezvous_count: 3,
        observed_code_publish_barrier_count: 1,
        code_publish_epoch_before: 0,
        code_publish_epoch_after: 1,
        remote_icache_sync_required: true,
        code_publish_executed: false,
        participant_count: 2,
        stress_event_log_cursor: 117,
        barrier_event: 24,
        stress_recorded_at_event: 118,
        invariant_checks: 7,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 577,
        note: "x7 semantic code publish while smp workload is active".to_owned(),
    }
}

#[test]
fn integrated_code_publish_smp_workload_view_v1_exposes_publish_and_stress_refs() {
    let view = integrated_code_publish_smp_workload_view_v1(
        &test_integrated_code_publish_smp_workload_manifest(),
    );

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-code-publish-smp-workload");
    assert_eq!(view["owner"]["hart_count"], 2);
    assert_eq!(view["references"]["smp_stress_run"]["id"], 9_501);
    assert_eq!(view["references"]["smp_code_publish_barrier"]["id"], 9_201);
    assert_eq!(view["references"]["publish_rendezvous"]["id"], 9_101);
    assert_eq!(view["references"]["publish_safe_point"]["generation"], 1);
    assert_eq!(view["closure"]["code_publish_epoch_before"], 0);
    assert_eq!(view["closure"]["code_publish_epoch_after"], 1);
    assert_eq!(view["closure"]["remote_icache_sync_required"], true);
    assert_eq!(view["closure"]["code_publish_executed"], false);
    assert_eq!(view["authority"]["real_smp_dynamic_code_publish_executed"], false);
    assert_eq!(view["last_transition"]["event"], 577);
}

#[test]
fn integrated_code_publish_smp_workload_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_code_publish_smp_workload_count = 1;
    package
        .semantic
        .integrated_code_publish_smp_workloads
        .push(test_integrated_code_publish_smp_workload_manifest());

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(
        !live.iter().any(|edge| { edge["from"]["kind"] == "integrated-code-publish-smp-workload" })
    );

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-code-publish-smp-workload"
        && edge["relation"] == "integrated-smp-stress-run"
        && edge["to"]["kind"] == "smp-stress-run"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-code-publish-smp-workload"
        && edge["relation"] == "integrated-smp-code-publish-barrier"
        && edge["to"]["kind"] == "smp-code-publish-barrier"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-code-publish-smp-workload"
        && edge["relation"] == "integrated-publish-rendezvous"
        && edge["to"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["generation"] == 1));
}

fn test_integrated_display_panic_manifest() -> IntegratedDisplayPanicManifest {
    IntegratedDisplayPanicManifest {
        id: 26_801,
        scenario: "x8-panic-ring-extraction-after-substrate-panic".to_owned(),
        substrate_panic_event: 578,
        substrate_panic_epoch: 1,
        substrate_panic_cpu: 0,
        substrate_panic_reason_code: 1,
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
        summary_record_bytes: 128,
        raw_framebuffer_bytes_exported: false,
        panic_path_allocates: false,
        invariant_checks: 8,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 579,
        note: "x8 semantic panic ring extraction after substrate panic".to_owned(),
    }
}

#[test]
fn integrated_display_panic_view_v1_exposes_panic_ring_and_last_frame_refs() {
    let view = integrated_display_panic_view_v1(&test_integrated_display_panic_manifest());

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-display-panic");
    assert_eq!(view["owner"]["panic_epoch"], 1);
    assert_eq!(view["owner"]["panic_cpu"], 0);
    assert_eq!(view["references"]["substrate_panic_event"]["id"], 578);
    assert_eq!(view["references"]["display_panic_last_frame"]["id"], 25_001);
    assert_eq!(view["references"]["display_panic_last_frame"]["generation"], 1);
    assert_eq!(view["panic_ring"]["ring_bytes"], 65_536);
    assert_eq!(view["panic_ring"]["record_max_bytes"], 4_096);
    assert_eq!(view["panic_ring"]["record_count"], 3);
    assert_eq!(view["panic_ring"]["jsonl_frame_count"], 5);
    assert_eq!(view["panic_ring"]["contract_panic_summary_records"], 1);
    assert_eq!(view["panic_ring"]["corrupt_record_count"], 0);
    assert_eq!(view["panic_ring"]["truncated_record_count"], 0);
    assert_eq!(view["panic_ring"]["raw_framebuffer_bytes_exported"], false);
    assert_eq!(view["closure"]["requires_display_panic_last_frame"], true);
    assert_eq!(view["closure"]["requires_no_raw_framebuffer_bytes"], true);
    assert_eq!(view["authority"]["target_to_host_extraction_only"], true);
    assert_eq!(view["authority"]["real_substrate_halt_executed"], false);
    assert_eq!(view["last_transition"]["event"], 579);
}

#[test]
fn integrated_display_panic_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_display_panic_count = 1;
    package.semantic.integrated_display_panics.push(test_integrated_display_panic_manifest());

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(!live.iter().any(|edge| { edge["from"]["kind"] == "integrated-display-panic" }));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-display-panic"
        && edge["relation"] == "integrated-display-panic->display-panic-last-frame"
        && edge["to"]["kind"] == "display-panic-last-frame"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-display-panic"
        && edge["relation"] == "integrated-display-panic->substrate-panic-event"
        && edge["to"]["kind"] == "substrate-event"
        && edge["to"]["id"] == 578));
}

fn test_integrated_osctl_trace_replay_manifest() -> IntegratedOsctlTraceReplayManifest {
    IntegratedOsctlTraceReplayManifest {
        id: 26_901,
        scenario: "x9-full-osctl-trace-replay".to_owned(),
        integrated_smp_preemption_cleanup: 26_001,
        integrated_smp_preemption_cleanup_generation: 1,
        integrated_smp_network_fault: 26_101,
        integrated_smp_network_fault_generation: 1,
        integrated_disk_preempt_fault: 26_201,
        integrated_disk_preempt_fault_generation: 1,
        integrated_simd_migration: 26_301,
        integrated_simd_migration_generation: 1,
        integrated_network_disk_io: 26_401,
        integrated_network_disk_io_generation: 1,
        integrated_display_scheduler_load: 26_501,
        integrated_display_scheduler_load_generation: 1,
        integrated_snapshot_io_lease_barrier: 26_601,
        integrated_snapshot_io_lease_barrier_generation: 1,
        integrated_code_publish_smp_workload: 26_701,
        integrated_code_publish_smp_workload_generation: 1,
        integrated_display_panic: 26_801,
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
        state: "recorded".to_owned(),
        recorded_at_event: 580,
        note: "x9 full osctl trace replay closure across integrated scenarios".to_owned(),
    }
}

#[test]
fn integrated_osctl_trace_replay_view_v1_exposes_replay_closure() {
    let view =
        integrated_osctl_trace_replay_view_v1(&test_integrated_osctl_trace_replay_manifest());

    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "integrated-osctl-trace-replay");
    assert_eq!(view["id"], 26_901);
    assert_eq!(view["generation"], 1);
    assert_eq!(view["owner"]["scenario"], "x9-full-osctl-trace-replay");
    assert_eq!(view["owner"]["integrated_scenario_count"], 9);
    assert_eq!(
        view["references"]["x0_smp_preemption_cleanup"]["kind"],
        "integrated-smp-preemption-cleanup"
    );
    assert_eq!(view["references"]["x0_smp_preemption_cleanup"]["id"], 26_001);
    assert_eq!(view["references"]["x8_display_panic"]["id"], 26_801);
    assert_eq!(view["references"]["x8_display_panic"]["generation"], 1);
    assert_eq!(view["replay"]["event_cursor"], 579);
    assert_eq!(view["replay"]["stable_view_count"], 9);
    assert_eq!(view["replay"]["historical_edge_count"], 9);
    assert_eq!(view["replay"]["replay_fixture_count"], 9);
    assert_eq!(view["replay"]["contract_validation_ok"], true);
    assert_eq!(view["replay"]["replay_validation_ok"], true);
    assert_eq!(view["replay"]["graph_history_ok"], true);
    assert_eq!(view["closure"]["requires_x0_to_x8_integrated_evidence"], true);
    assert_eq!(view["authority"]["osctl_is_read_only_control_plane"], true);
    assert_eq!(view["authority"]["adapter_internal_state_is_not_semantic_truth"], true);
    assert_eq!(view["last_transition"]["event"], 580);
}

#[test]
fn integrated_osctl_trace_replay_graph_edges_are_history_only() {
    let mut package = minimal_graph_package();
    package.semantic.integrated_osctl_trace_replay_count = 1;
    package
        .semantic
        .integrated_osctl_trace_replays
        .push(test_integrated_osctl_trace_replay_manifest());

    let live = graph_edges_for_package(&package, GraphEdgeMode::Live);
    assert!(!live.iter().any(|edge| { edge["from"]["kind"] == "integrated-osctl-trace-replay" }));

    let history = graph_edges_for_package(&package, GraphEdgeMode::History);
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-osctl-trace-replay"
        && edge["relation"] == "integrated-osctl-trace-replay->x0-smp-preemption-cleanup"
        && edge["to"]["kind"] == "integrated-smp-preemption-cleanup"
        && edge["to"]["generation"] == 1));
    assert!(history.iter().any(|edge| edge["mode"] == "historical"
        && edge["from"]["kind"] == "integrated-osctl-trace-replay"
        && edge["relation"] == "integrated-osctl-trace-replay->x8-display-panic"
        && edge["to"]["kind"] == "integrated-display-panic"
        && edge["to"]["id"] == 26_801
        && edge["to"]["generation"] == 1));
}

#[test]
fn activation_context_view_v1_exposes_vector_clean_dirty_state() {
    let view = activation_context_view_v1(&ActivationContextManifest {
        id: 12,
        activation: 11,
        activation_generation: 3,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: Some(2),
        owner_store_generation: Some(5),
        generation: 4,
        state: "current".to_owned(),
        current_saved_context: None,
        current_saved_context_generation: None,
        vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_000,
            generation: 1,
        }),
        vector_status: "dirty".to_owned(),
        vector_state_event: Some(42),
        last_event: Some(42),
    });

    assert_eq!(view["kind"], "activation-context");
    assert_eq!(view["vector_context"]["status"], "dirty");
    assert_eq!(view["vector_context"]["vector_state"]["kind"], "vector-state");
    assert_eq!(view["vector_context"]["vector_state"]["generation"], 1);
    assert_eq!(view["references"]["vector_state"]["id"], 22_000);
    assert_eq!(view["vector_context"]["last_event"], 42);
}

#[test]
fn saved_context_view_v1_exposes_preempted_vector_state() {
    let view = saved_context_view_v1(&SavedContextManifest {
        id: 13,
        context: 12,
        context_generation: 4,
        activation: 11,
        activation_generation: 4,
        owner_task: 7,
        owner_task_generation: 1,
        source_preemption: Some(6),
        source_preemption_generation: Some(1),
        generation: 2,
        state: "captured".to_owned(),
        reason: "timer-preempt".to_owned(),
        pc: 0x2000,
        sp: 0x9000,
        flags: 0,
        integer_registers: 33,
        vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_002,
            generation: 1,
        }),
        vector_status: "clean".to_owned(),
        vector_saved_at_event: Some(77),
        saved_at_event: 41,
        note: "preempted vector frame".to_owned(),
    });

    assert_eq!(view["kind"], "saved-context");
    assert_eq!(view["references"]["vector_state"]["kind"], "vector-state");
    assert_eq!(view["references"]["vector_state"]["id"], 22_002);
    assert_eq!(view["vector_context"]["status"], "clean");
    assert_eq!(view["vector_context"]["saved_at_event"], 77);
}

#[test]
fn activation_resume_view_v1_exposes_vector_restore_refs() {
    let view = activation_resume_view_v1(&ActivationResumeManifest {
        id: 15,
        scheduler_decision: 14,
        scheduler_decision_generation: 1,
        activation: 11,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 7,
        owner_task_generation: 1,
        queue: 1,
        queue_generation: 1,
        context: Some(12),
        context_generation_before: Some(4),
        context_generation_after: Some(5),
        saved_context: Some(13),
        saved_context_generation: Some(3),
        saved_vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_002,
            generation: 1,
        }),
        restored_vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_003,
            generation: 1,
        }),
        vector_status: "clean".to_owned(),
        vector_restored_at_event: Some(88),
        generation: 1,
        state: "applied".to_owned(),
        resumed_at_event: 87,
        note: "resume restores vector state".to_owned(),
    });

    assert_eq!(view["kind"], "activation-resume");
    assert_eq!(view["vector_restore"]["status"], "clean");
    assert_eq!(view["references"]["saved_vector_state"]["id"], 22_002);
    assert_eq!(view["references"]["restored_vector_state"]["id"], 22_003);
    assert_eq!(view["vector_restore"]["restored_at_event"], 88);
}

#[test]
fn activation_migration_view_v1_exposes_vector_migration_refs() {
    let view = activation_migration_view_v1(&ActivationMigrationManifest {
        id: 71,
        activation: 11,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 7,
        owner_task_generation: 1,
        source_hart: 2,
        source_hart_generation: 4,
        target_hart: 1,
        target_hart_generation: 2,
        source_queue: 2,
        source_queue_generation: 2,
        source_queue_owner_hart_generation: 4,
        target_queue: 3,
        target_queue_generation: 2,
        target_queue_owner_hart_generation: 2,
        context: Some(12),
        context_generation_before: Some(2),
        context_generation_after: Some(3),
        source_vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_004,
            generation: 1,
        }),
        migrated_vector_state: Some(ContractObjectRefManifest {
            kind: "vector-state".to_owned(),
            id: 22_005,
            generation: 1,
        }),
        vector_status: "clean".to_owned(),
        vector_migrated_at_event: Some(99),
        generation: 1,
        state: "applied".to_owned(),
        migrated_at_event: 98,
        reason: "vector-rebalance".to_owned(),
        note: "cross-hart migration rehomes vector state".to_owned(),
    });

    assert_eq!(view["kind"], "activation-migration");
    assert_eq!(view["vector_migration"]["status"], "clean");
    assert_eq!(view["references"]["context"]["id"], 12);
    assert_eq!(view["references"]["source_vector_state"]["id"], 22_004);
    assert_eq!(view["references"]["migrated_vector_state"]["id"], 22_005);
    assert_eq!(view["vector_migration"]["event"], 99);
}
