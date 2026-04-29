use super::*;

#[test]
fn semantic_roots_reject_target_feature_set_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.target_feature_set_count = 1;
    package.semantic.target_feature_sets.push(artifact_manifest::TargetFeatureSetManifest {
        id: 86,
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
        recorded_at_event: 96,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "target feature set root/count mismatch");
}

#[test]
fn semantic_roots_reject_vector_state_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.vector_state_count = 1;
    package.semantic.vector_states.push(artifact_manifest::VectorStateManifest {
        id: 87,
        owner_activation: artifact_manifest::ContractObjectRefManifest {
            kind: "activation".to_owned(),
            id: 7,
            generation: 1,
        },
        owner_store: artifact_manifest::ContractObjectRefManifest {
            kind: "store".to_owned(),
            id: 2,
            generation: 1,
        },
        code_object: artifact_manifest::ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 9,
            generation: 1,
        },
        target_feature_set: artifact_manifest::ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 86,
            generation: 1,
        },
        simd_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: "unavailable".to_owned(),
        recorded_at_event: 97,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "vector state root/count mismatch");
}

#[test]
fn semantic_roots_reject_simd_fault_injection_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.simd_fault_injection_count = 1;
    package.semantic.simd_fault_injections.push(artifact_manifest::SimdFaultInjectionManifest {
        id: 88,
        activation: artifact_manifest::ContractObjectRefManifest {
            kind: "activation".to_owned(),
            id: 7,
            generation: 2,
        },
        code_object: artifact_manifest::ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 9,
            generation: 3,
        },
        trap: artifact_manifest::ContractObjectRefManifest {
            kind: "trap".to_owned(),
            id: 4,
            generation: 1,
        },
        target_feature_set: artifact_manifest::ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 86,
            generation: 1,
        },
        vector_state: None,
        kind: "unsupported-feature".to_owned(),
        effect: "trap-recorded".to_owned(),
        required_abi: "riscv-v".to_owned(),
        vector_register_count: 32,
        vector_register_bits: 128,
        injected_faults: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 98,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "simd fault injection root/count mismatch");
}

#[test]
fn semantic_roots_reject_simd_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.simd_benchmark_count = 1;
    package.semantic.simd_benchmarks.push(artifact_manifest::SimdBenchmarkManifest {
        id: 89,
        target_feature_set: artifact_manifest::ContractObjectRefManifest {
            kind: "target-feature-set".to_owned(),
            id: 86,
            generation: 1,
        },
        scalar_code_object: artifact_manifest::ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 9,
            generation: 3,
        },
        vector_code_object: artifact_manifest::ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 10,
            generation: 3,
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
        recorded_at_event: 99,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "simd benchmark root/count mismatch");
}

#[test]
fn semantic_roots_reject_simd_context_switch_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.simd_context_switch_benchmark_count = 1;
    package.semantic.simd_context_switch_benchmarks.push(
        artifact_manifest::SimdContextSwitchBenchmarkManifest {
            id: 90,
            preemption: artifact_manifest::ContractObjectRefManifest {
                kind: "preemption".to_owned(),
                id: 6,
                generation: 1,
            },
            activation_resume: artifact_manifest::ContractObjectRefManifest {
                kind: "activation-resume".to_owned(),
                id: 15,
                generation: 1,
            },
            saved_vector_state: artifact_manifest::ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 22_002,
                generation: 1,
            },
            restored_vector_state: artifact_manifest::ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 22_003,
                generation: 1,
            },
            target_feature_set: artifact_manifest::ContractObjectRefManifest {
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
            recorded_at_event: 100,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "simd context switch benchmark root/count mismatch");
}

#[test]
fn semantic_roots_reject_framebuffer_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.framebuffer_object_count = 1;
    package.semantic.framebuffer_objects.push(artifact_manifest::FramebufferObjectManifest {
        id: 90,
        name: "fb0".to_owned(),
        resource: 3,
        resource_generation: 1,
        width: 800,
        height: 600,
        stride_bytes: 3200,
        pixel_format: "xrgb8888".to_owned(),
        byte_len: 1_920_000,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 101,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "framebuffer object root/count mismatch");
}

#[test]
fn semantic_roots_reject_display_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.display_object_count = 1;
    package.semantic.display_objects.push(artifact_manifest::DisplayObjectManifest {
        id: 91,
        name: "display0".to_owned(),
        framebuffer: 90,
        framebuffer_generation: 1,
        mode_name: "800x600@60".to_owned(),
        width: 800,
        height: 600,
        refresh_millihz: 60_000,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 102,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "display object root/count mismatch");
}

#[test]
fn semantic_roots_reject_display_capability_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.display_capability_count = 1;
    package.semantic.display_capabilities.push(artifact_manifest::DisplayCapabilityManifest {
        id: 92,
        owner_store: 7,
        owner_store_generation: 1,
        display: 91,
        display_generation: 1,
        framebuffer: 90,
        framebuffer_generation: 1,
        capability: 3,
        capability_generation: 1,
        handle_slot: 1,
        handle_generation: 1,
        handle_tag: 42,
        operations: vec!["flush".to_owned(), "lease".to_owned()],
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 103,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "display capability root/count mismatch");
}

#[test]
fn semantic_roots_reject_framebuffer_window_lease_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.framebuffer_window_lease_count = 1;
    package.semantic.framebuffer_window_leases.push(
        artifact_manifest::FramebufferWindowLeaseManifest {
            id: 93,
            owner_store: 7,
            owner_store_generation: 1,
            display_capability: 92,
            display_capability_generation: 1,
            display: 91,
            display_generation: 1,
            framebuffer: 90,
            framebuffer_generation: 1,
            x: 0,
            y: 0,
            width: 16,
            height: 16,
            byte_offset: 0,
            byte_len: 1024,
            access: "write".to_owned(),
            generation: 1,
            state: "active".to_owned(),
            recorded_at_event: 104,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "framebuffer window lease root/count mismatch");
}

#[test]
fn semantic_roots_reject_framebuffer_mapping_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.framebuffer_mapping_count = 1;
    package.semantic.framebuffer_mappings.push(artifact_manifest::FramebufferMappingManifest {
        id: 94,
        owner_store: 7,
        owner_store_generation: 1,
        framebuffer_window_lease: 93,
        framebuffer_window_lease_generation: 1,
        display_capability: 92,
        display_capability_generation: 1,
        display: 91,
        display_generation: 1,
        framebuffer: 90,
        framebuffer_generation: 1,
        map_handle_slot: 3,
        map_handle_generation: 1,
        map_handle_tag: 43,
        x: 0,
        y: 0,
        width: 16,
        height: 16,
        byte_offset: 0,
        byte_len: 1024,
        access: "write".to_owned(),
        mode: "handle-mode".to_owned(),
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 105,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "framebuffer mapping root/count mismatch");
}

#[test]
fn semantic_roots_reject_framebuffer_write_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.framebuffer_write_count = 1;
    package.semantic.framebuffer_writes.push(artifact_manifest::FramebufferWriteManifest {
        id: 95,
        owner_store: 7,
        owner_store_generation: 1,
        framebuffer_mapping: 94,
        framebuffer_mapping_generation: 1,
        framebuffer_window_lease: 93,
        framebuffer_window_lease_generation: 1,
        display_capability: 92,
        display_capability_generation: 1,
        display: 91,
        display_generation: 1,
        framebuffer: 90,
        framebuffer_generation: 1,
        map_handle_slot: 3,
        map_handle_generation: 1,
        map_handle_tag: 43,
        x: 0,
        y: 0,
        width: 16,
        height: 16,
        byte_offset: 0,
        byte_len: 1024,
        pixel_format: "xrgb8888".to_owned(),
        payload_digest: 1,
        generation: 1,
        state: "applied".to_owned(),
        recorded_at_event: 106,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "framebuffer write root/count mismatch");
}

#[test]
fn semantic_roots_reject_framebuffer_flush_region_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.framebuffer_flush_region_count = 1;
    package.semantic.framebuffer_flush_regions.push(
        artifact_manifest::FramebufferFlushRegionManifest {
            id: 96,
            owner_store: 7,
            owner_store_generation: 1,
            framebuffer_write: 95,
            framebuffer_write_generation: 1,
            display_capability: 92,
            display_capability_generation: 1,
            display: 91,
            display_generation: 1,
            framebuffer: 90,
            framebuffer_generation: 1,
            x: 0,
            y: 0,
            width: 16,
            height: 16,
            byte_offset: 0,
            byte_len: 1024,
            pixel_format: "xrgb8888".to_owned(),
            payload_digest: 1,
            generation: 1,
            state: "applied".to_owned(),
            recorded_at_event: 107,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "framebuffer flush region root/count mismatch");
}

#[test]
fn semantic_roots_reject_framebuffer_dirty_region_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.framebuffer_dirty_region_count = 1;
    package.semantic.framebuffer_dirty_regions.push(
        artifact_manifest::FramebufferDirtyRegionManifest {
            id: 97,
            owner_store: 7,
            owner_store_generation: 1,
            framebuffer_write: 95,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: Some(96),
            framebuffer_flush_region_generation: Some(1),
            display_capability: 92,
            display_capability_generation: 1,
            display: 91,
            display_generation: 1,
            framebuffer: 90,
            framebuffer_generation: 1,
            x: 0,
            y: 0,
            width: 16,
            height: 16,
            byte_offset: 0,
            byte_len: 1024,
            pixel_format: "xrgb8888".to_owned(),
            payload_digest: 1,
            generation: 1,
            state: "clean".to_owned(),
            dirty_at_event: 106,
            cleaned_at_event: Some(107),
            recorded_at_event: 108,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "framebuffer dirty region root/count mismatch");
}

#[test]
fn semantic_roots_reject_display_event_log_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.display_event_log_count = 1;
    package.semantic.display_event_logs.push(artifact_manifest::DisplayEventLogManifest {
        id: 98,
        owner_store: 7,
        owner_store_generation: 1,
        display_capability: 92,
        display_capability_generation: 1,
        display: 91,
        display_generation: 1,
        framebuffer: 90,
        framebuffer_generation: 1,
        framebuffer_dirty_region: 97,
        framebuffer_dirty_region_generation: 1,
        first_event: 101,
        last_event: 108,
        event_count: 8,
        flush_count: 1,
        dirty_region_count: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 109,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "display event log root/count mismatch");
}

#[test]
fn semantic_roots_reject_display_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.display_cleanup_count = 1;
    package.semantic.display_cleanups.push(artifact_manifest::DisplayCleanupManifest {
        id: 99,
        owner_store: 7,
        owner_store_generation: 1,
        display_capability: 92,
        display_capability_generation: 1,
        display: 91,
        display_generation: 1,
        framebuffer: 90,
        framebuffer_generation: 1,
        generation: 1,
        state: "completed".to_owned(),
        reason: "test".to_owned(),
        started_at_event: 101,
        completed_at_event: 102,
        unmapped_framebuffer_mappings: Vec::new(),
        released_framebuffer_window_leases: Vec::new(),
        revoked_display_capabilities: Vec::new(),
        revoked_capabilities: Vec::new(),
        steps: Vec::new(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "display cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_display_snapshot_barrier_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.display_snapshot_barrier_count = 1;
    package.semantic.display_snapshot_barriers.push(
        artifact_manifest::DisplaySnapshotBarrierManifest {
            id: 100,
            owner_store: 7,
            owner_store_generation: 1,
            display: 91,
            display_generation: 1,
            framebuffer: 90,
            framebuffer_generation: 1,
            display_cleanup: Some(99),
            display_cleanup_generation: Some(1),
            active_framebuffer_window_lease_count: 0,
            active_framebuffer_mapping_count: 0,
            dirty_framebuffer_region_count: 0,
            snapshot_validation_ok: true,
            generation: 1,
            state: "validated".to_owned(),
            validated_at_event: 103,
            reason: "test".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "display snapshot barrier root/count mismatch");
}

#[test]
fn semantic_roots_reject_display_panic_last_frame_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.display_panic_last_frame_count = 1;
    package.semantic.display_panic_last_frames.push(
        artifact_manifest::DisplayPanicLastFrameManifest {
            id: 101,
            owner_store: 7,
            owner_store_generation: 1,
            display: 91,
            display_generation: 1,
            framebuffer: 90,
            framebuffer_generation: 1,
            display_snapshot_barrier: 100,
            display_snapshot_barrier_generation: 1,
            display_event_log: 99,
            display_event_log_generation: 1,
            framebuffer_write: 98,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 97,
            framebuffer_flush_region_generation: 1,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len: 3200,
            pixel_format: "xrgb8888".to_owned(),
            payload_digest: 11,
            summary_digest: 12,
            summary_record_bytes: 512,
            panic_epoch: 1,
            panic_cpu: 0,
            panic_reason_code: 1,
            panic_record_kind: "contract-panic-summary-v1".to_owned(),
            raw_framebuffer_bytes_exported: false,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 104,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "display panic last-frame root/count mismatch");
}

#[test]
fn semantic_roots_reject_framebuffer_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.framebuffer_benchmark_count = 1;
    package.semantic.framebuffer_benchmarks.push(artifact_manifest::FramebufferBenchmarkManifest {
        id: 102,
        scenario: "display-g12-single-flush".to_owned(),
        owner_store: 7,
        owner_store_generation: 1,
        display: 91,
        display_generation: 1,
        framebuffer: 90,
        framebuffer_generation: 1,
        display_capability: 92,
        display_capability_generation: 1,
        framebuffer_write: 98,
        framebuffer_write_generation: 1,
        framebuffer_flush_region: 97,
        framebuffer_flush_region_generation: 1,
        display_event_log: 99,
        display_event_log_generation: 1,
        display_snapshot_barrier: 100,
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
        recorded_at_event: 105,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "framebuffer benchmark root/count mismatch");
}
