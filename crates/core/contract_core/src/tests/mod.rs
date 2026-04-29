use artifact_manifest::{
    ArtifactBundleManifest, CommandResultManifest, CompilerManifest, ExternManifest,
    GuestStateManifest, InterfaceEventManifest, MigrationHostManifest, MigrationPackageManifest,
    MigrationTargetManifest, ModuleArtifactManifest, RequiredArtifactProfileManifest,
    RuntimeActivationRecordManifest, SemanticRootSetManifest, SemanticSnapshotManifest,
    SignatureManifest, SubstrateAuthorityRequirementManifest, SubstrateBoundaryManifest,
    SubstrateEventManifest, TargetManifest,
};
use service_core::net_contract::NETWORK_CONTRACT_VERSION;
use substrate_api::SubstrateCapabilitySet;
use supervisor_catalog::{
    ARTIFACT_SIGNATURE_PROFILE, DMW_LAYOUT, LINUX_ABI_PROFILE, MACHINE_ABI_VERSION,
    RUNTIME_ONLY_EXECUTOR_ABI, SUPERVISOR_ABI_VERSION, SUPERVISOR_ARTIFACT_FORMAT,
    SUPERVISOR_COMPILER_ENGINE, SUPERVISOR_EXECUTION_MODE, WASM_FEATURE_PROFILE, WasmModuleSpec,
    module_dependencies,
};

use super::*;

#[test]
fn wasmtime_config_fingerprint_is_stable_and_arch_sensitive() {
    let host_fingerprint = canonical_wasmtime_config_fingerprint("x86_64", "x86_64");
    assert_eq!(host_fingerprint.len(), 64);
    assert_eq!(host_fingerprint, canonical_wasmtime_config_fingerprint("x86_64", "x86_64"));
    assert_ne!(host_fingerprint, canonical_wasmtime_config_fingerprint("x86_64", "riscv64"));
}

fn valid_manifest() -> ArtifactBundleManifest {
    let modules = SUPERVISOR_WASM_MODULES
        .iter()
        .map(|spec| {
            let wasm_sha256 = format!("{}-wasm", spec.package);
            let cwasm_sha256 = format!("{}-cwasm", spec.package);
            let target_artifact_sha256 = format!("{}-target-artifact", spec.package);
            let abi_fingerprint = module_abi_fingerprint(spec);
            let manifest_binding_hash =
                manifest_binding_hash(spec, &wasm_sha256, &cwasm_sha256, &abi_fingerprint);
            ModuleArtifactManifest {
                package: spec.package.to_owned(),
                artifact_name: spec.artifact_name.to_owned(),
                role: spec.role.as_str().to_owned(),
                fault_policy: spec.fault_policy.as_str().to_owned(),
                wasm_path: format!("target/test/{}.wasm", spec.package),
                cwasm_path: format!("target/test/{}.cwasm", spec.package),
                target_artifact_path: format!("target/test/{}.tart", spec.package),
                wasm_sha256,
                cwasm_sha256: cwasm_sha256.clone(),
                target_artifact_sha256: target_artifact_sha256.clone(),
                code_payload_format: CODE_PAYLOAD_FORMAT_CWASM.to_owned(),
                expected_exports: spec
                    .expected_exports
                    .iter()
                    .map(|export| (*export).to_owned())
                    .collect(),
                exports: spec
                    .expected_exports
                    .iter()
                    .map(|export| ExternManifest {
                        name: (*export).to_owned(),
                        kind: if *export == "memory" { "memory" } else { "func" }.to_owned(),
                    })
                    .collect(),
                imports: Vec::new(),
                capabilities: spec
                    .capabilities
                    .iter()
                    .map(|capability| CapabilityManifest {
                        name: capability.name.to_owned(),
                        rights: capability.rights.iter().map(|right| (*right).to_owned()).collect(),
                        lifetime: capability.lifetime.to_owned(),
                    })
                    .collect(),
                abi_fingerprint,
                service_dependencies: module_dependencies(spec)
                    .iter()
                    .map(|dependency| (*dependency).to_owned())
                    .collect(),
                resource_limits: ResourceLimitsManifest {
                    max_memory_pages: 16,
                    max_table_elements: 0,
                    max_hostcalls_per_activation: 64,
                },
                interfaces: interface_manifest(spec),
                signature: SignatureManifest {
                    scheme: ARTIFACT_SIGNATURE_PROFILE.to_owned(),
                    artifact_hash: target_artifact_sha256,
                    manifest_binding_hash,
                    signer: "test-signer".to_owned(),
                    public_key_hint: "test-key".to_owned(),
                    signature: "test-signature".to_owned(),
                },
            }
        })
        .collect();

    ArtifactBundleManifest {
        schema_version: 1,
        artifact_profile: "host-validation".to_owned(),
        runtime_mode: RUNTIME_MODE_RESEARCH.to_owned(),
        contract: expected_supervisor_contract(),
        target: TargetManifest {
            arch: "x86_64".to_owned(),
            machine_abi_version: MACHINE_ABI_VERSION.to_owned(),
            supervisor_abi_version: SUPERVISOR_ABI_VERSION.to_owned(),
            wasm_feature_profile: WASM_FEATURE_PROFILE.to_owned(),
            memory64: false,
            multi_memory: false,
            dmw_layout: DMW_LAYOUT.to_owned(),
            linux_abi_profile: LINUX_ABI_PROFILE.to_owned(),
            artifact_signature_profile: ARTIFACT_SIGNATURE_PROFILE.to_owned(),
            network_contract_version: NETWORK_CONTRACT_VERSION.to_owned(),
        },
        compiler: CompilerManifest {
            engine: SUPERVISOR_COMPILER_ENGINE.to_owned(),
            engine_version: "test".to_owned(),
            execution_mode: SUPERVISOR_EXECUTION_MODE.to_owned(),
            artifact_format: SUPERVISOR_ARTIFACT_FORMAT.to_owned(),
            target_artifact_format: TARGET_ARTIFACT_FORMAT_V1.to_owned(),
            runtime_executor_abi: RUNTIME_ONLY_EXECUTOR_ABI.to_owned(),
        },
        modules,
    }
}

fn interface_manifest(spec: &WasmModuleSpec) -> InterfaceRequirementManifest {
    let interfaces = module_interface_spec(spec);
    InterfaceRequirementManifest {
        required_wasi_worlds: interfaces
            .required_wasi_worlds
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        optional_wasi_worlds: interfaces
            .optional_wasi_worlds
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        custom_wit_worlds: interfaces
            .custom_wit_worlds
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        wit_package_versions: interfaces
            .wit_package_versions
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        component_model_version: interfaces.component_model_version.to_owned(),
        wasi_profile: interfaces.wasi_profile.to_owned(),
        hostcall_abi_version: interfaces.hostcall_abi_version.to_owned(),
        capability_abi_version: interfaces.capability_abi_version.to_owned(),
        semantic_contract_version: interfaces.semantic_contract_version.to_owned(),
        substrate_profile_required: interfaces.substrate_profile_required.to_owned(),
        substrate_authorities: SubstrateAuthorityRequirementManifest {
            required: interfaces
                .substrate_required
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
            optional: interfaces
                .substrate_optional
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
            forbidden: interfaces
                .substrate_forbidden
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
        },
    }
}

fn minimal_migration_package() -> MigrationPackageManifest {
    MigrationPackageManifest {
        schema_version: 1,
        package_format: "vmos-semantic-package-v1".to_owned(),
        package_id: "contract-root-test".to_owned(),
        source: MigrationHostManifest { arch: "x86_64".to_owned() },
        target: MigrationTargetManifest { arch_requirement: "target-native".to_owned() },
        required_artifact_profile: RequiredArtifactProfileManifest {
            artifact_profile: "host-validation".to_owned(),
            target_arch: "target-native".to_owned(),
            machine_abi_version: MACHINE_ABI_VERSION.to_owned(),
            supervisor_abi_version: SUPERVISOR_ABI_VERSION.to_owned(),
            wasm_feature_profile: WASM_FEATURE_PROFILE.to_owned(),
            memory64: false,
            multi_memory: false,
            dmw_layout: DMW_LAYOUT.to_owned(),
            network_contract_version: NETWORK_CONTRACT_VERSION.to_owned(),
            compiler_engine: SUPERVISOR_COMPILER_ENGINE.to_owned(),
            compiler_execution_mode: SUPERVISOR_EXECUTION_MODE.to_owned(),
            artifact_format: SUPERVISOR_ARTIFACT_FORMAT.to_owned(),
            runtime_executor_abi: RUNTIME_ONLY_EXECUTOR_ABI.to_owned(),
        },
        guest: GuestStateManifest {
            canonical_isa: "riscv64".to_owned(),
            register_count: 33,
            memory_page_count: 0,
            vma_count: 0,
            signal_queue_count: 0,
            note: "root validation test".to_owned(),
        },
        semantic: SemanticSnapshotManifest {
            barrier_id: 1,
            event_log_cursor: 0,
            roots: SemanticRootSetManifest::default(),
            pending_wait_count: 0,
            hart_count: 0,
            task_count: 0,
            task_record_count: 0,
            runtime_activation_count: 0,
            runnable_queue_count: 0,
            activation_context_count: 0,
            saved_context_count: 0,
            timer_interrupt_count: 0,
            ipi_event_count: 0,
            remote_preempt_count: 0,
            remote_park_count: 0,
            preemption_count: 0,
            scheduler_decision_count: 0,
            cross_hart_scheduler_decision_count: 0,
            activation_migration_count: 0,
            smp_safe_point_count: 0,
            stop_the_world_rendezvous_count: 0,
            smp_code_publish_barrier_count: 0,
            smp_cleanup_quiescence_count: 0,
            smp_snapshot_barrier_count: 0,
            smp_stress_run_count: 0,
            smp_scaling_benchmark_count: 0,
            integrated_smp_preemption_cleanup_count: 0,
            integrated_smp_network_fault_count: 0,
            integrated_disk_preempt_fault_count: 0,
            integrated_simd_migration_count: 0,
            integrated_network_disk_io_count: 0,
            integrated_display_scheduler_load_count: 0,
            integrated_snapshot_io_lease_barrier_count: 0,
            integrated_code_publish_smp_workload_count: 0,
            device_object_count: 0,
            queue_object_count: 0,
            descriptor_object_count: 0,
            dma_buffer_object_count: 0,
            mmio_region_object_count: 0,
            irq_line_object_count: 0,
            irq_event_count: 0,
            device_capability_count: 0,
            driver_store_binding_count: 0,
            io_wait_count: 0,
            io_cleanup_count: 0,
            io_fault_injection_count: 0,
            io_validation_report_count: 0,
            packet_device_object_count: 0,
            packet_buffer_object_count: 0,
            packet_queue_object_count: 0,
            packet_descriptor_object_count: 0,
            fake_net_backend_object_count: 0,
            virtio_net_backend_object_count: 0,
            network_rx_interrupt_count: 0,
            network_rx_wait_resolution_count: 0,
            network_tx_capability_gate_count: 0,
            network_tx_completion_count: 0,
            network_stack_adapter_count: 0,
            socket_object_count: 0,
            endpoint_object_count: 0,
            socket_operation_count: 0,
            socket_wait_count: 0,
            network_backpressure_count: 0,
            network_driver_cleanup_count: 0,
            network_generation_audit_count: 0,
            network_fault_injection_count: 0,
            network_benchmark_count: 0,
            network_recovery_benchmark_count: 0,
            block_device_object_count: 0,
            block_range_object_count: 0,
            block_request_object_count: 0,
            block_completion_object_count: 0,
            block_wait_count: 0,
            fake_block_backend_object_count: 0,
            virtio_blk_backend_object_count: 0,
            block_read_path_count: 0,
            block_write_path_count: 0,
            block_request_queue_count: 0,
            block_dma_buffer_count: 0,
            block_page_object_count: 0,
            buffer_cache_object_count: 0,
            file_object_count: 0,
            directory_object_count: 0,
            fat_adapter_object_count: 0,
            ext4_adapter_object_count: 0,
            file_handle_capability_count: 0,
            fs_wait_count: 0,
            block_driver_cleanup_count: 0,
            block_pending_io_policy_count: 0,
            block_request_generation_audit_count: 0,
            block_benchmark_count: 0,
            block_recovery_benchmark_count: 0,
            target_feature_set_count: 0,
            vector_state_count: 0,
            simd_fault_injection_count: 0,
            simd_benchmark_count: 0,
            simd_context_switch_benchmark_count: 0,
            framebuffer_object_count: 0,
            display_object_count: 0,
            display_capability_count: 0,
            framebuffer_window_lease_count: 0,
            framebuffer_mapping_count: 0,
            framebuffer_write_count: 0,
            framebuffer_flush_region_count: 0,
            framebuffer_dirty_region_count: 0,
            display_event_log_count: 0,
            display_cleanup_count: 0,
            display_snapshot_barrier_count: 0,
            display_panic_last_frame_count: 0,
            integrated_display_panic_count: 0,
            integrated_osctl_trace_replay_count: 0,
            framebuffer_benchmark_count: 0,
            activation_resume_count: 0,
            activation_wait_count: 0,
            activation_cleanup_count: 0,
            preemption_latency_sample_count: 0,
            hart_event_attribution_count: 0,
            resource_count: 0,
            authority_count: 0,
            active_authority_count: 0,
            wait_token_count: 0,
            wait_record_count: 0,
            capability_count: 0,
            capability_record_count: 0,
            fault_domain_count: 0,
            store_count: 0,
            store_record_count: 0,
            transaction_count: 0,
            active_transaction_count: 0,
            fast_path_plan_count: 0,
            active_fast_path_plan_count: 0,
            boundary_count: 0,
            artifact_verification_count: 0,
            store_activation_count: 0,
            executor_transition_count: 0,
            target_artifact_count: 0,
            code_object_count: 0,
            activation_record_count: 0,
            trap_record_count: 0,
            hostcall_trace_count: 0,
            migration_object_count: 0,
            tombstone_count: 0,
            contract_violation_count: 0,
            cleanup_transaction_count: 0,
            memory_policy_count: 0,
            snapshot_validation_violation_count: 0,
            replay_validation_violation_count: 0,
            substrate_event_count: 0,
            command_result_count: 0,
            interface_event_count: 0,
            target_artifacts: Vec::new(),
            hart_records: Vec::new(),
            task_records: Vec::new(),
            runtime_activation_records: Vec::new(),
            runnable_queues: Vec::new(),
            activation_contexts: Vec::new(),
            saved_contexts: Vec::new(),
            timer_interrupts: Vec::new(),
            ipi_events: Vec::new(),
            remote_preempts: Vec::new(),
            remote_parks: Vec::new(),
            preemptions: Vec::new(),
            scheduler_decisions: Vec::new(),
            cross_hart_scheduler_decisions: Vec::new(),
            activation_migrations: Vec::new(),
            smp_safe_points: Vec::new(),
            stop_the_world_rendezvous: Vec::new(),
            smp_code_publish_barriers: Vec::new(),
            smp_cleanup_quiescence: Vec::new(),
            smp_snapshot_barriers: Vec::new(),
            smp_stress_runs: Vec::new(),
            smp_scaling_benchmarks: Vec::new(),
            integrated_smp_preemption_cleanups: Vec::new(),
            integrated_smp_network_faults: Vec::new(),
            integrated_disk_preempt_faults: Vec::new(),
            integrated_simd_migrations: Vec::new(),
            integrated_network_disk_ios: Vec::new(),
            integrated_display_scheduler_loads: Vec::new(),
            integrated_snapshot_io_lease_barriers: Vec::new(),
            integrated_code_publish_smp_workloads: Vec::new(),
            device_objects: Vec::new(),
            queue_objects: Vec::new(),
            descriptor_objects: Vec::new(),
            dma_buffer_objects: Vec::new(),
            mmio_region_objects: Vec::new(),
            irq_line_objects: Vec::new(),
            irq_events: Vec::new(),
            device_capabilities: Vec::new(),
            driver_store_bindings: Vec::new(),
            io_waits: Vec::new(),
            io_cleanups: Vec::new(),
            io_fault_injections: Vec::new(),
            io_validation_reports: Vec::new(),
            packet_device_objects: Vec::new(),
            packet_buffer_objects: Vec::new(),
            packet_queue_objects: Vec::new(),
            packet_descriptors: Vec::new(),
            fake_net_backends: Vec::new(),
            virtio_net_backends: Vec::new(),
            network_rx_interrupts: Vec::new(),
            network_rx_wait_resolutions: Vec::new(),
            network_tx_capability_gates: Vec::new(),
            network_tx_completions: Vec::new(),
            network_stack_adapters: Vec::new(),
            socket_objects: Vec::new(),
            endpoint_objects: Vec::new(),
            socket_operations: Vec::new(),
            socket_waits: Vec::new(),
            network_backpressures: Vec::new(),
            network_driver_cleanups: Vec::new(),
            network_generation_audits: Vec::new(),
            network_fault_injections: Vec::new(),
            network_benchmarks: Vec::new(),
            network_recovery_benchmarks: Vec::new(),
            block_device_objects: Vec::new(),
            block_range_objects: Vec::new(),
            block_request_objects: Vec::new(),
            block_completion_objects: Vec::new(),
            block_waits: Vec::new(),
            fake_block_backends: Vec::new(),
            virtio_blk_backends: Vec::new(),
            block_read_paths: Vec::new(),
            block_write_paths: Vec::new(),
            block_request_queues: Vec::new(),
            block_dma_buffers: Vec::new(),
            block_page_objects: Vec::new(),
            buffer_cache_objects: Vec::new(),
            file_objects: Vec::new(),
            directory_objects: Vec::new(),
            fat_adapter_objects: Vec::new(),
            ext4_adapter_objects: Vec::new(),
            file_handle_capabilities: Vec::new(),
            fs_waits: Vec::new(),
            block_driver_cleanups: Vec::new(),
            block_pending_io_policies: Vec::new(),
            block_request_generation_audits: Vec::new(),
            block_benchmarks: Vec::new(),
            block_recovery_benchmarks: Vec::new(),
            target_feature_sets: Vec::new(),
            vector_states: Vec::new(),
            simd_fault_injections: Vec::new(),
            simd_benchmarks: Vec::new(),
            simd_context_switch_benchmarks: Vec::new(),
            framebuffer_objects: Vec::new(),
            display_objects: Vec::new(),
            display_capabilities: Vec::new(),
            framebuffer_window_leases: Vec::new(),
            framebuffer_mappings: Vec::new(),
            framebuffer_writes: Vec::new(),
            framebuffer_flush_regions: Vec::new(),
            framebuffer_dirty_regions: Vec::new(),
            display_event_logs: Vec::new(),
            display_cleanups: Vec::new(),
            display_snapshot_barriers: Vec::new(),
            display_panic_last_frames: Vec::new(),
            integrated_display_panics: Vec::new(),
            integrated_osctl_trace_replays: Vec::new(),
            framebuffer_benchmarks: Vec::new(),
            activation_resumes: Vec::new(),
            activation_waits: Vec::new(),
            activation_cleanups: Vec::new(),
            preemption_latency_samples: Vec::new(),
            hart_event_attributions: Vec::new(),
            code_objects: Vec::new(),
            store_records: Vec::new(),
            capability_records: Vec::new(),
            wait_records: Vec::new(),
            activation_records: Vec::new(),
            trap_records: Vec::new(),
            hostcall_trace: Vec::new(),
            migration_objects: Vec::new(),
            tombstones: Vec::new(),
            contract_violations: Vec::new(),
            cleanup_transactions: Vec::new(),
            memory_policies: Vec::new(),
            snapshot_validation: Default::default(),
            replay_validation: Default::default(),
            substrate_events: Vec::new(),
            command_results: Vec::new(),
            interface_events: Vec::new(),
            network_socket_count: 0,
            network_rx_queue_bytes: 0,
        },
        logical_capabilities: Vec::new(),
        substrate_boundary: SubstrateBoundaryManifest {
            timer_epoch: 0,
            pending_irq_causes: 0,
            pending_dma_completions: 0,
            active_dmw_lease_count: 0,
            active_mmio_authority_count: 0,
            active_dma_authority_count: 0,
            active_irq_authority_count: 0,
            active_packet_device_authority_count: 0,
            active_virtio_queue_authority_count: 0,
            pending_network_inputs: 0,
            random_epoch: 0,
            scheduler_decision_cursor: 0,
            cow_epoch: 0,
            background_copy_pages: 0,
            native_state_policy: "test".to_owned(),
        },
        not_migrated: Vec::new(),
    }
}

#[test]
fn validated_plan_preserves_manifest_order_and_totals() {
    let manifest = valid_manifest();
    let plan = build_validated_artifact_plan(&manifest).expect("valid plan");

    assert_eq!(plan.module_count(), SUPERVISOR_WASM_MODULES.len());
    assert_eq!(plan.runtime_mode, RUNTIME_MODE_RESEARCH);
    assert_eq!(plan.modules[0].package, SUPERVISOR_WASM_MODULES[0].package);
    assert_eq!(plan.modules[0].hash_status, ARTIFACT_HASH_STATUS_MANIFEST_BOUND);
    assert_eq!(
        plan.modules[0].signature_status,
        ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED
    );
    assert!(!plan.modules[0].signature_verified);
    assert_eq!(
        plan.modules[0].interfaces.semantic_contract_version,
        SEMANTIC_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(plan.modules[0].interfaces.hostcall_abi_version, HOSTCALL_ABI_VERSION);
    assert_eq!(
        plan.capability_count(),
        SUPERVISOR_WASM_MODULES.iter().map(|spec| spec.capabilities.len()).sum()
    );
}

#[test]
fn manifest_validation_rejects_expected_export_tamper() {
    let mut manifest = valid_manifest();
    manifest.modules[0].expected_exports = vec!["evil_export".to_owned()];

    let err = validate_artifact_manifest(&manifest).expect_err("bad exports must fail");
    assert_eq!(err.to_string(), "console_service expected exports mismatch");
}

#[test]
fn manifest_validation_rejects_actual_export_tamper() {
    let mut manifest = valid_manifest();
    manifest.modules[0].exports[0].name = "evil_export".to_owned();

    let err = validate_artifact_manifest(&manifest).expect_err("bad exports must fail");
    assert_eq!(err.to_string(), "console_service unexpected export evil_export");
}

#[test]
fn validated_plan_derives_exports_from_catalog_spec() {
    let manifest = valid_manifest();
    let plan = build_validated_artifact_plan(&manifest).expect("valid plan");
    let expected = SUPERVISOR_WASM_MODULES[0]
        .expected_exports
        .iter()
        .map(|export| (*export).to_owned())
        .collect::<Vec<_>>();

    assert_eq!(plan.modules[0].expected_exports, expected);
}

#[test]
fn manifest_validation_rejects_resource_limit_tamper() {
    let mut manifest = valid_manifest();
    manifest.modules[0].resource_limits.max_memory_pages = u32::MAX;

    let err = validate_artifact_manifest(&manifest).expect_err("bad limits must fail");
    assert_eq!(err.to_string(), "console_service resource limits mismatch");
}

#[test]
fn manifest_validation_rejects_bad_entry_binding() {
    let mut manifest = valid_manifest();
    manifest.modules[0].signature.manifest_binding_hash = "stale-binding".to_owned();

    let err = validate_artifact_manifest(&manifest).expect_err("bad binding must fail");
    assert!(err.to_string().contains("manifest binding hash mismatch"));
}

#[test]
fn migration_against_manifest_rejects_missing_artifact_evidence() {
    let manifest = valid_manifest();
    let package = minimal_migration_package();

    let err = validate_migration_against_manifest(&package, &manifest)
        .expect_err("missing artifact evidence must fail");
    assert_eq!(err.to_string(), "package artifact verification count does not match manifest");
}

#[test]
fn semantic_roots_reject_substrate_event_count_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.substrate_events.push(SubstrateEventManifest {
        id: 1,
        epoch: 7,
        event_kind: "unsupported".to_owned(),
        authority: "DmaAuthority".to_owned(),
        operation: "dma_alloc".to_owned(),
        requester: Some("test".to_owned()),
        artifact: None,
        store: None,
        capability: None,
        explanation: "unsupported probe".to_owned(),
    });
    package
        .semantic
        .roots
        .substrate_event_roots
        .push("substrate-event:unsupported:DmaAuthority:dma_alloc".to_owned());

    let err = validate_migration_package(&package).expect_err("count mismatch must fail");
    assert_eq!(err.to_string(), "substrate event root/count mismatch");
}

#[test]
fn semantic_roots_reject_runtime_scheduler_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.runtime_activation_count = 1;
    package.semantic.runtime_activation_records.push(RuntimeActivationRecordManifest {
        id: 11,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: None,
        owner_store_generation: None,
        code_object: None,
        generation: 1,
        state: "runnable".to_owned(),
        runnable_queue: Some(1),
        runnable_queue_generation: Some(1),
        last_event: Some(3),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "runtime activation root/count mismatch");
}

#[test]
fn semantic_roots_reject_activation_context_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.activation_context_count = 1;
    package.semantic.activation_contexts.push(artifact_manifest::ActivationContextManifest {
        id: 12,
        activation: 11,
        activation_generation: 2,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: None,
        owner_store_generation: None,
        generation: 1,
        state: "created".to_owned(),
        current_saved_context: None,
        current_saved_context_generation: None,
        vector_state: None,
        vector_status: "absent".to_owned(),
        vector_state_event: None,
        last_event: Some(4),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "activation context root/count mismatch");
}

#[test]
fn semantic_roots_reject_timer_interrupt_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.timer_interrupt_count = 1;
    package.semantic.timer_interrupts.push(artifact_manifest::TimerInterruptManifest {
        id: 3,
        timer_epoch: 1,
        hart: 1,
        hart_generation: Some(2),
        hardware_hart: Some(0),
        target_activation: Some(11),
        target_activation_generation: Some(2),
        target_task: Some(7),
        target_task_generation: Some(1),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 5,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "timer interrupt root/count mismatch");
}

#[test]
fn semantic_roots_reject_ipi_event_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.ipi_event_count = 1;
    package.semantic.ipi_events.push(artifact_manifest::IpiEventManifest {
        id: 4,
        source_hart: 1,
        source_hart_generation: 2,
        source_hardware_hart: 0,
        target_hart: 2,
        target_hart_generation: 2,
        target_hardware_hart: 1,
        kind: "scheduler-kick".to_owned(),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 5,
        reason: "test".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "ipi event root/count mismatch");
}

#[test]
fn semantic_roots_reject_remote_preempt_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.remote_preempt_count = 1;
    package.semantic.remote_preempts.push(artifact_manifest::RemotePreemptManifest {
        id: 4,
        ipi: 3,
        ipi_generation: 1,
        source_hart: 1,
        source_hart_generation: 2,
        target_hart: 2,
        target_hart_generation_before: 3,
        target_hart_generation_after: 4,
        activation: 11,
        activation_generation_before: 3,
        activation_generation_after: 4,
        queue: 2,
        queue_generation: 1,
        generation: 1,
        state: "applied".to_owned(),
        preempted_at_event: 6,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "remote preempt root/count mismatch");
}

#[test]
fn semantic_roots_reject_remote_park_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.remote_park_count = 1;
    package.semantic.remote_parks.push(artifact_manifest::RemoteParkManifest {
        id: 5,
        ipi: 3,
        ipi_generation: 1,
        source_hart: 1,
        source_hart_generation: 2,
        target_hart: 2,
        target_hart_generation_before: 3,
        target_hart_generation_after: 4,
        generation: 1,
        state: "parked".to_owned(),
        parked_at_event: 6,
        reason: "test".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "remote park root/count mismatch");
}

#[test]
fn semantic_roots_reject_preemption_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.preemption_count = 1;
    package.semantic.preemptions.push(artifact_manifest::PreemptionManifest {
        id: 4,
        activation: 11,
        activation_generation_before: 3,
        activation_generation_after: 4,
        timer_interrupt: 3,
        timer_interrupt_generation: 1,
        queue: 1,
        queue_generation: 1,
        generation: 1,
        state: "applied".to_owned(),
        preempted_at_event: 6,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "preemption root/count mismatch");
}

#[test]
fn semantic_roots_reject_scheduler_decision_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.scheduler_decision_count = 1;
    package.semantic.scheduler_decisions.push(artifact_manifest::SchedulerDecisionManifest {
        id: 5,
        queue: 1,
        queue_generation: 1,
        selected_activation: 11,
        selected_activation_generation: 4,
        owner_task: 7,
        owner_task_generation: 1,
        generation: 1,
        state: "recorded".to_owned(),
        decided_at_event: 7,
        reason: "runnable-available".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "scheduler decision root/count mismatch");
}

#[test]
fn semantic_roots_reject_cross_hart_scheduler_decision_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.cross_hart_scheduler_decision_count = 1;
    package.semantic.cross_hart_scheduler_decisions.push(
        artifact_manifest::CrossHartSchedulerDecisionManifest {
            id: 6,
            scheduler_decision: 5,
            scheduler_decision_generation: 1,
            deciding_hart: 1,
            deciding_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 4,
            queue: 1,
            queue_generation: 2,
            queue_owner_hart_generation: 2,
            selected_activation: 11,
            selected_activation_generation: 4,
            generation: 1,
            state: "recorded".to_owned(),
            decided_at_event: 8,
            reason: "remote-runnable".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "cross-hart scheduler decision root/count mismatch");
}

#[test]
fn semantic_roots_reject_activation_migration_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.activation_migration_count = 1;
    package.semantic.activation_migrations.push(artifact_manifest::ActivationMigrationManifest {
        id: 7,
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
        source_queue_owner_hart_generation: 2,
        target_queue: 3,
        target_queue_generation: 2,
        target_queue_owner_hart_generation: 2,
        context: None,
        context_generation_before: None,
        context_generation_after: None,
        source_vector_state: None,
        migrated_vector_state: None,
        vector_status: "absent".to_owned(),
        vector_migrated_at_event: None,
        generation: 1,
        state: "applied".to_owned(),
        migrated_at_event: 9,
        reason: "rebalance".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "activation migration root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_safe_point_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_safe_point_count = 1;
    package.semantic.smp_safe_points.push(artifact_manifest::SmpSafePointManifest {
        id: 8,
        coordinator_hart: 1,
        coordinator_hart_generation: 2,
        participants: vec![
            artifact_manifest::SmpSafePointParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
                current_activation: None,
                current_activation_generation: None,
            },
            artifact_manifest::SmpSafePointParticipantManifest {
                hart: 2,
                hart_generation: 4,
                hardware_hart: 1,
                hart_state: "idle".to_owned(),
                current_activation: None,
                current_activation_generation: None,
            },
        ],
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 10,
        reason: "smp-safe-point".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp safe point root/count mismatch");
}

#[test]
fn semantic_roots_reject_stop_the_world_rendezvous_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.stop_the_world_rendezvous_count = 1;
    package.semantic.stop_the_world_rendezvous.push(
        artifact_manifest::StopTheWorldRendezvousManifest {
            id: 9,
            epoch: 1,
            safe_point: 8,
            safe_point_generation: 1,
            coordinator_hart: 1,
            coordinator_hart_generation: 2,
            participants: vec![
                artifact_manifest::StopTheWorldRendezvousParticipantManifest {
                    hart: 1,
                    hart_generation: 2,
                    hardware_hart: 0,
                    hart_state: "idle".to_owned(),
                },
                artifact_manifest::StopTheWorldRendezvousParticipantManifest {
                    hart: 2,
                    hart_generation: 4,
                    hardware_hart: 1,
                    hart_state: "idle".to_owned(),
                },
            ],
            stop_new_activations: true,
            generation: 1,
            state: "completed".to_owned(),
            completed_at_event: 11,
            reason: "stop-the-world".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "stop-the-world rendezvous root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_code_publish_barrier_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_code_publish_barrier_count = 1;
    package.semantic.smp_code_publish_barriers.push(
        artifact_manifest::SmpCodePublishBarrierManifest {
            id: 10,
            rendezvous: 9,
            rendezvous_generation: 1,
            rendezvous_epoch: 1,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            participants: vec![
                artifact_manifest::SmpCodePublishBarrierParticipantManifest {
                    hart: 1,
                    hart_generation: 2,
                    hardware_hart: 0,
                    last_seen_code_epoch_before: 0,
                    last_seen_code_epoch_after: 1,
                    semantic_icache_sync: true,
                },
                artifact_manifest::SmpCodePublishBarrierParticipantManifest {
                    hart: 2,
                    hart_generation: 4,
                    hardware_hart: 1,
                    last_seen_code_epoch_before: 0,
                    last_seen_code_epoch_after: 1,
                    semantic_icache_sync: true,
                },
            ],
            remote_icache_sync_required: true,
            code_publish_executed: false,
            generation: 1,
            state: "validated".to_owned(),
            validated_at_event: 12,
            reason: "smp-code-publish-barrier".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp code publish barrier root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_cleanup_quiescence_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_cleanup_quiescence_count = 1;
    package.semantic.smp_cleanup_quiescence.push(artifact_manifest::SmpCleanupQuiescenceManifest {
        id: 11,
        cleanup: 10,
        cleanup_generation: 1,
        store: 7,
        target_store_generation: 2,
        result_store_generation: 4,
        activation: 12,
        activation_generation_after: 5,
        rendezvous: 9,
        rendezvous_generation: 1,
        rendezvous_epoch: 2,
        participants: vec![
            artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                hart: 1,
                hart_generation: 4,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
                current_activation: None,
                current_activation_generation: None,
                current_store: None,
                current_store_generation: None,
                quiesced: true,
            },
            artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                hart: 2,
                hart_generation: 5,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
                current_activation: None,
                current_activation_generation: None,
                current_store: None,
                current_store_generation: None,
                quiesced: true,
            },
        ],
        no_running_activation: true,
        no_pending_wait: true,
        no_live_capability: true,
        no_live_resource: true,
        generation: 1,
        state: "validated".to_owned(),
        validated_at_event: 13,
        reason: "smp-cleanup-quiescence".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp cleanup quiescence root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_snapshot_barrier_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_snapshot_barrier_count = 1;
    package.semantic.smp_snapshot_barriers.push(artifact_manifest::SmpSnapshotBarrierManifest {
        id: 12,
        rendezvous: 9,
        rendezvous_generation: 1,
        rendezvous_epoch: 3,
        event_log_cursor: 42,
        participants: vec![
            artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                hart: 1,
                hart_generation: 4,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
                event_log_cursor_observed: 42,
                snapshot_safe: true,
            },
            artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                hart: 2,
                hart_generation: 5,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
                event_log_cursor_observed: 42,
                snapshot_safe: true,
            },
        ],
        pending_wait_count: 0,
        active_transaction_count: 0,
        active_dmw_lease_count: 0,
        active_nonconvertible_activation_count: 0,
        in_flight_dma_count: 0,
        unsealed_event_log: false,
        unflushed_trap_record_count: 0,
        pending_cleanup_count: 0,
        native_activation_stack_live: false,
        raw_dma_binding_count: 0,
        raw_mmio_binding_count: 0,
        snapshot_validation_ok: true,
        generation: 1,
        state: "validated".to_owned(),
        validated_at_event: 43,
        reason: "smp-snapshot-barrier".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp snapshot barrier root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_stress_run_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_stress_run_count = 1;
    package.semantic.smp_stress_runs.push(artifact_manifest::SmpStressRunManifest {
        id: 15,
        scenario: "smp-stress".to_owned(),
        iterations: 3,
        hart_count: 2,
        event_log_cursor: 50,
        observed_safe_point_count: 3,
        observed_rendezvous_count: 3,
        observed_code_publish_barrier_count: 1,
        observed_cleanup_quiescence_count: 1,
        observed_snapshot_barrier_count: 1,
        observed_activation_migration_count: 1,
        observed_remote_preempt_count: 1,
        observed_remote_park_count: 1,
        invariant_checks: 3,
        property_failures: 0,
        last_safe_point: 3,
        last_safe_point_generation: 1,
        last_rendezvous: 3,
        last_rendezvous_generation: 1,
        last_code_publish_barrier: 1,
        last_code_publish_barrier_generation: 1,
        last_cleanup_quiescence: 1,
        last_cleanup_quiescence_generation: 1,
        last_snapshot_barrier: 1,
        last_snapshot_barrier_generation: 1,
        last_activation_migration: 1,
        last_activation_migration_generation: 1,
        last_remote_preempt: 1,
        last_remote_preempt_generation: 1,
        last_remote_park: 1,
        last_remote_park_generation: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 51,
        reason: "smp-stress-property".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp stress run root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_scaling_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_scaling_benchmark_count = 1;
    package.semantic.smp_scaling_benchmarks.push(artifact_manifest::SmpScalingBenchmarkManifest {
        id: 16,
        scenario: "smp-scaling".to_owned(),
        stress_run: 15,
        stress_run_generation: 1,
        hart_count: 2,
        workload_units: 6,
        baseline_single_hart_nanos: 120_000,
        measured_smp_nanos: 72_000,
        budget_nanos: 90_000,
        speedup_milli: 1_666,
        efficiency_milli: 833,
        event_log_cursor: 51,
        stress_safe_point_count: 3,
        stress_rendezvous_count: 3,
        stress_property_failures: 0,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 52,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp scaling benchmark root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_smp_preemption_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_smp_preemption_cleanup_count = 1;
    package.semantic.integrated_smp_preemption_cleanups.push(
        artifact_manifest::IntegratedSmpPreemptionCleanupManifest {
            id: 17,
            scenario: "x0-smp-preemption-cleanup".to_owned(),
            stress_run: 15,
            stress_run_generation: 1,
            preemption: 1,
            preemption_generation: 1,
            timer_interrupt: 1,
            timer_interrupt_generation: 1,
            saved_context: 1,
            saved_context_generation: 1,
            remote_preempt: 1,
            remote_preempt_generation: 1,
            activation_cleanup: 1,
            activation_cleanup_generation: 1,
            smp_cleanup_quiescence: 1,
            smp_cleanup_quiescence_generation: 1,
            cleanup_store: 1,
            target_store_generation: 2,
            result_store_generation: 4,
            cleanup_activation: 1,
            cleanup_activation_generation_after: 5,
            hart_count: 2,
            invariant_checks: 7,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 53,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated smp preemption cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_smp_network_fault_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_smp_network_fault_count = 1;
    package.semantic.integrated_smp_network_faults.push(
        artifact_manifest::IntegratedSmpNetworkFaultManifest {
            id: 18,
            scenario: "x1-smp-network-driver-fault".to_owned(),
            network_driver_cleanup: 46,
            network_driver_cleanup_generation: 1,
            smp_stress_run: 15,
            smp_stress_run_generation: 1,
            remote_preempt: 3,
            remote_preempt_generation: 1,
            smp_cleanup_quiescence: 4,
            smp_cleanup_quiescence_generation: 1,
            driver_store: 7,
            driver_store_generation: 3,
            packet_device: 10,
            packet_device_generation: 1,
            adapter: 11,
            adapter_generation: 1,
            backend: artifact_manifest::ContractObjectRefManifest {
                kind: "virtio-net-backend-object".to_owned(),
                id: 12,
                generation: 1,
            },
            io_cleanup: 47,
            io_cleanup_generation: 1,
            cancelled_socket_wait_count: 1,
            cancelled_wait_token_count: 1,
            revoked_packet_capability_count: 1,
            hart_count: 2,
            invariant_checks: 7,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 54,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated smp network fault root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_disk_preempt_fault_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_disk_preempt_fault_count = 1;
    package.semantic.integrated_disk_preempt_faults.push(
        artifact_manifest::IntegratedDiskPreemptFaultManifest {
            id: 19,
            scenario: "x2-disk-pending-io-fault-under-preemption".to_owned(),
            preemption: 6,
            preemption_generation: 1,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            block_pending_io_policy: 71,
            block_pending_io_policy_generation: 1,
            block_wait: 55,
            block_wait_generation: 1,
            wait: 8,
            wait_generation: 1,
            block_request: 53,
            block_request_generation: 1,
            retry_request: None,
            retry_request_generation: None,
            block_device: 51,
            block_device_generation: 1,
            block_range: 52,
            block_range_generation: 1,
            driver_store: Some(7),
            driver_store_generation: Some(2),
            action: "eio".to_owned(),
            errno: 5,
            preempted_activation: 9,
            preempted_activation_generation_after: 4,
            invariant_checks: 6,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 55,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated disk preempt fault root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_simd_migration_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_simd_migration_count = 1;
    package.semantic.integrated_simd_migrations.push(
        artifact_manifest::IntegratedSimdMigrationManifest {
            id: 20,
            scenario: "x3-simd-task-migration-across-harts".to_owned(),
            activation_migration: 9,
            activation_migration_generation: 1,
            target_feature_set: 75,
            target_feature_set_generation: 1,
            source_vector_state: artifact_manifest::ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 76,
                generation: 1,
            },
            migrated_vector_state: artifact_manifest::ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 77,
                generation: 1,
            },
            activation: 8,
            activation_generation_before: 2,
            activation_generation_after: 3,
            context: 4,
            context_generation_after: 3,
            source_hart: 1,
            source_hart_generation: 1,
            target_hart: 2,
            target_hart_generation: 1,
            source_queue: 3,
            source_queue_generation: 2,
            target_queue: 4,
            target_queue_generation: 2,
            simd_abi: "riscv-v".to_owned(),
            vector_register_count: 32,
            vector_register_bits: 128,
            invariant_checks: 6,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 56,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated simd migration root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_network_disk_io_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_network_disk_io_count = 1;
    package.semantic.integrated_network_disk_ios.push(
        artifact_manifest::IntegratedNetworkDiskIoManifest {
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
            block_backend: artifact_manifest::ContractObjectRefManifest {
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
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated network disk io root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_display_scheduler_load_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_display_scheduler_load_count = 1;
    package.semantic.integrated_display_scheduler_loads.push(
        artifact_manifest::IntegratedDisplaySchedulerLoadManifest {
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
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated display scheduler load root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_snapshot_io_lease_barrier_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_snapshot_io_lease_barrier_count = 1;
    package.semantic.integrated_snapshot_io_lease_barriers.push(
        artifact_manifest::IntegratedSnapshotIoLeaseBarrierManifest {
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
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated snapshot io lease barrier root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_code_publish_smp_workload_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_code_publish_smp_workload_count = 1;
    package.semantic.integrated_code_publish_smp_workloads.push(
        artifact_manifest::IntegratedCodePublishSmpWorkloadManifest {
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
        },
    );

    let err = validate_semantic_roots(&package).unwrap_err();
    assert_eq!(err.to_string(), "integrated code publish smp workload root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_display_panic_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_display_panic_count = 1;
    package.semantic.integrated_display_panics.push(
        artifact_manifest::IntegratedDisplayPanicManifest {
            id: 26_801,
            scenario: "x8-panic-ring-extraction-after-substrate-panic".to_owned(),
            substrate_panic_event: 577,
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
            summary_record_bytes: 512,
            raw_framebuffer_bytes_exported: false,
            panic_path_allocates: false,
            invariant_checks: 8,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 578,
            note: "x8 panic ring extraction after substrate panic".to_owned(),
        },
    );

    let err = validate_semantic_roots(&package).unwrap_err();
    assert_eq!(err.to_string(), "integrated display panic root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_osctl_trace_replay_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_osctl_trace_replay_count = 1;
    package.semantic.integrated_osctl_trace_replays.push(
        artifact_manifest::IntegratedOsctlTraceReplayManifest {
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
            note: "x9 full osctl trace replay".to_owned(),
        },
    );

    let err = validate_semantic_roots(&package).unwrap_err();
    assert_eq!(err.to_string(), "integrated osctl trace replay root/count mismatch");
}

#[test]
fn semantic_roots_reject_device_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.device_object_count = 1;
    package.semantic.device_objects.push(artifact_manifest::DeviceObjectManifest {
        id: 17,
        name: "fake-io0".to_owned(),
        class: "fake-device".to_owned(),
        resource: 3,
        resource_generation: 1,
        backend: "fake-io-backend".to_owned(),
        bus: "semantic-harness".to_owned(),
        vendor: "vmos".to_owned(),
        model: "fake-io-v1".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 53,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "device object root/count mismatch");
}

#[test]
fn semantic_roots_reject_queue_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.queue_object_count = 1;
    package.semantic.queue_objects.push(artifact_manifest::QueueObjectManifest {
        id: 18,
        name: "fake-io0-rx".to_owned(),
        role: "rx".to_owned(),
        queue_index: 0,
        depth: 64,
        device: 17,
        device_generation: 1,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 54,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "queue object root/count mismatch");
}

#[test]
fn semantic_roots_reject_descriptor_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.descriptor_object_count = 1;
    package.semantic.descriptor_objects.push(artifact_manifest::DescriptorObjectManifest {
        id: 19,
        queue: 18,
        queue_generation: 1,
        slot: 0,
        access: "read-write".to_owned(),
        length: 2048,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 55,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "descriptor object root/count mismatch");
}

#[test]
fn semantic_roots_reject_dma_buffer_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.dma_buffer_object_count = 1;
    package.semantic.dma_buffer_objects.push(artifact_manifest::DmaBufferObjectManifest {
        id: 20,
        descriptor: 19,
        descriptor_generation: 1,
        resource: 21,
        resource_generation: 1,
        access: "read-write".to_owned(),
        length: 2048,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 56,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "dma buffer object root/count mismatch");
}

#[test]
fn semantic_roots_reject_mmio_region_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.mmio_region_object_count = 1;
    package.semantic.mmio_region_objects.push(artifact_manifest::MmioRegionObjectManifest {
        id: 21,
        device: 17,
        device_generation: 1,
        resource: 22,
        resource_generation: 1,
        region_index: 0,
        offset: 0x1000,
        length: 0x100,
        access: "read-write".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 57,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "mmio region object root/count mismatch");
}

#[test]
fn semantic_roots_reject_irq_line_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.irq_line_object_count = 1;
    package.semantic.irq_line_objects.push(artifact_manifest::IrqLineObjectManifest {
        id: 22,
        device: 17,
        device_generation: 1,
        resource: 23,
        resource_generation: 1,
        irq_number: 5,
        trigger: "level".to_owned(),
        polarity: "active-high".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 58,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "irq line object root/count mismatch");
}

#[test]
fn semantic_roots_reject_irq_event_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.irq_event_count = 1;
    package.semantic.irq_events.push(artifact_manifest::IrqEventManifest {
        id: 23,
        irq_line: 22,
        irq_line_generation: 1,
        device: 17,
        device_generation: 1,
        driver_store: 24,
        driver_store_generation: 3,
        irq_number: 5,
        sequence: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 59,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "irq event root/count mismatch");
}

#[test]
fn semantic_roots_reject_device_capability_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.device_capability_count = 1;
    package.semantic.device_capabilities.push(artifact_manifest::DeviceCapabilityManifest {
        id: 24,
        driver_store: 2,
        driver_store_generation: 2,
        target: artifact_manifest::ContractObjectRefManifest {
            kind: "mmio-region-object".to_owned(),
            id: 21,
            generation: 1,
        },
        class: "mmio-region".to_owned(),
        operation: "write32".to_owned(),
        capability: 7,
        capability_generation: 1,
        handle_slot: 1,
        handle_generation: 1,
        handle_tag: 99,
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 60,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "device capability root/count mismatch");
}

#[test]
fn semantic_roots_reject_driver_store_binding_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.driver_store_binding_count = 1;
    package.semantic.driver_store_bindings.push(artifact_manifest::DriverStoreBindingManifest {
        id: 25,
        driver_store: 2,
        driver_store_generation: 2,
        device: 17,
        device_generation: 1,
        device_capability: 24,
        device_capability_generation: 1,
        capability: 7,
        capability_generation: 1,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 61,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "driver store binding root/count mismatch");
}

#[test]
fn semantic_roots_reject_io_wait_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.io_wait_count = 1;
    package.semantic.io_waits.push(artifact_manifest::IoWaitManifest {
        id: 26,
        wait: 41,
        wait_generation: 1,
        driver_store: 2,
        driver_store_generation: 2,
        device: 17,
        device_generation: 1,
        driver_binding: 25,
        driver_binding_generation: 1,
        blocker: artifact_manifest::ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 23,
            generation: 1,
        },
        generation: 1,
        state: "pending".to_owned(),
        created_at_event: 62,
        completed_at_event: None,
        completion_irq_event: None,
        completion_irq_event_generation: None,
        cancel_reason: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "io wait root/count mismatch");
}

#[test]
fn semantic_roots_reject_io_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.io_cleanup_count = 1;
    package.semantic.io_cleanups.push(artifact_manifest::IoCleanupManifest {
        id: 27,
        driver_store: 2,
        driver_store_generation: 2,
        device: 17,
        device_generation: 1,
        driver_binding: 25,
        driver_binding_generation: 1,
        generation: 1,
        state: "completed".to_owned(),
        reason: "device-fault".to_owned(),
        started_at_event: 63,
        completed_at_event: 64,
        cancelled_io_waits: Vec::new(),
        revoked_device_capabilities: Vec::new(),
        revoked_capabilities: Vec::new(),
        released_dma_buffers: Vec::new(),
        released_mmio_regions: Vec::new(),
        released_irq_lines: Vec::new(),
        steps: Vec::new(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "io cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_io_fault_injection_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.io_fault_injection_count = 1;
    package.semantic.io_fault_injections.push(artifact_manifest::IoFaultInjectionManifest {
        id: 29,
        driver_store: 2,
        driver_store_generation: 2,
        device: 17,
        device_generation: 1,
        driver_binding: 25,
        driver_binding_generation: 1,
        target: artifact_manifest::ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 22,
            generation: 1,
        },
        cleanup: 27,
        cleanup_generation: 1,
        generation: 1,
        kind: "device-fault".to_owned(),
        state: "completed".to_owned(),
        injected_at_event: 65,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "io fault injection root/count mismatch");
}

#[test]
fn semantic_roots_reject_io_validation_report_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.io_validation_report_count = 1;
    package.semantic.io_validation_reports.push(artifact_manifest::IoValidationReportManifest {
        id: 30,
        generation: 1,
        state: "passed".to_owned(),
        validated_at_event: 66,
        event_log_cursor: 65,
        observed_device_count: 1,
        observed_queue_count: 1,
        observed_descriptor_count: 1,
        observed_dma_buffer_count: 1,
        observed_mmio_region_count: 1,
        observed_irq_line_count: 1,
        observed_irq_event_count: 1,
        observed_device_capability_count: 1,
        observed_driver_binding_count: 1,
        observed_io_wait_count: 1,
        observed_io_cleanup_count: 1,
        observed_io_fault_injection_count: 1,
        violation_count: 0,
        violations: Vec::new(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "io validation report root/count mismatch");
}

#[test]
fn semantic_roots_reject_packet_device_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.packet_device_object_count = 1;
    package.semantic.packet_device_objects.push(artifact_manifest::PacketDeviceObjectManifest {
        id: 31,
        name: "net0".to_owned(),
        device: 17,
        device_generation: 1,
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        frame_format_version: 2,
        max_payload_len: 512,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 67,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "packet device object root/count mismatch");
}

#[test]
fn semantic_roots_reject_packet_buffer_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.packet_buffer_object_count = 1;
    package.semantic.packet_buffer_objects.push(artifact_manifest::PacketBufferObjectManifest {
        id: 32,
        packet_device: 31,
        packet_device_generation: 1,
        direction: "rx".to_owned(),
        frame_format_version: 2,
        capacity: 512,
        payload_len: 64,
        sequence: 1,
        generation: 1,
        state: "filled".to_owned(),
        recorded_at_event: 68,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "packet buffer object root/count mismatch");
}

#[test]
fn semantic_roots_reject_packet_queue_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.packet_queue_object_count = 1;
    package.semantic.packet_queue_objects.push(artifact_manifest::PacketQueueObjectManifest {
        id: 33,
        name: "rx0".to_owned(),
        packet_device: 31,
        packet_device_generation: 1,
        role: "rx".to_owned(),
        queue_index: 0,
        depth: 4,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 69,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "packet queue object root/count mismatch");
}

#[test]
fn semantic_roots_reject_packet_descriptor_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.packet_descriptor_object_count = 1;
    package.semantic.packet_descriptors.push(artifact_manifest::PacketDescriptorObjectManifest {
        id: 34,
        packet_queue: 33,
        packet_queue_generation: 1,
        packet_buffer: 31,
        packet_buffer_generation: 1,
        slot: 0,
        length: 64,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 70,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "packet descriptor object root/count mismatch");
}

#[test]
fn semantic_roots_reject_fake_net_backend_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.fake_net_backend_object_count = 1;
    package.semantic.fake_net_backends.push(artifact_manifest::FakeNetBackendObjectManifest {
        id: 35,
        name: "fake-net0".to_owned(),
        packet_device: 31,
        packet_device_generation: 1,
        provider: "service_core".to_owned(),
        profile: "fake-net-v1".to_owned(),
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [2, 0x76, 0x6d, 0x6f, 0x73, 1],
        frame_format_version: 2,
        max_payload_len: 512,
        deterministic_seed: 1,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 71,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "fake net backend object root/count mismatch");
}

#[test]
fn semantic_roots_reject_fake_block_backend_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.fake_block_backend_object_count = 1;
    package.semantic.fake_block_backends.push(artifact_manifest::FakeBlockBackendObjectManifest {
        id: 56,
        name: "fake-block0".to_owned(),
        block_device: 51,
        block_device_generation: 1,
        provider: "service_core".to_owned(),
        profile: "fake-block-v1".to_owned(),
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        deterministic_seed: 1,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 72,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "fake block backend object root/count mismatch");
}

#[test]
fn semantic_roots_reject_virtio_net_backend_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.virtio_net_backend_object_count = 1;
    package.semantic.virtio_net_backends.push(artifact_manifest::VirtioNetBackendObjectManifest {
        id: 36,
        name: "virtio-net0".to_owned(),
        packet_device: 31,
        packet_device_generation: 1,
        driver_binding: 1202,
        driver_binding_generation: 1,
        device: 30,
        device_generation: 1,
        provider: "substrate_virtio".to_owned(),
        profile: "virtio-net-backend-skeleton-v1".to_owned(),
        model: "virtio-net".to_owned(),
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        mac: [2, 0x76, 0x6d, 0x6f, 0x73, 1],
        frame_format_version: 2,
        max_payload_len: 512,
        device_features: 0x1,
        driver_features: 0x1,
        negotiated_features: 0x1,
        rx_queue_index: 0,
        tx_queue_index: 1,
        queue_size: 4,
        irq_vector: 5,
        generation: 1,
        state: "skeleton-ready".to_owned(),
        recorded_at_event: 72,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "virtio net backend object root/count mismatch");
}

#[test]
fn semantic_roots_reject_virtio_blk_backend_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.virtio_blk_backend_object_count = 1;
    package.semantic.virtio_blk_backends.push(artifact_manifest::VirtioBlkBackendObjectManifest {
        id: 37,
        name: "virtio-blk0".to_owned(),
        block_device: 32,
        block_device_generation: 1,
        driver_binding: 1203,
        driver_binding_generation: 1,
        device: 30,
        device_generation: 1,
        provider: "substrate_virtio".to_owned(),
        profile: "virtio-blk-backend-skeleton-v1".to_owned(),
        model: "virtio-blk".to_owned(),
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        device_features: 0x40,
        driver_features: 0x40,
        negotiated_features: 0x40,
        request_queue_index: 0,
        queue_size: 8,
        irq_vector: 6,
        generation: 1,
        state: "skeleton-ready".to_owned(),
        recorded_at_event: 73,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "virtio block backend object root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_read_path_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_read_path_count = 1;
    package.semantic.block_read_paths.push(artifact_manifest::BlockReadPathManifest {
        id: 58,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 56,
        backend_generation: 1,
        block_request: 53,
        block_request_generation: 1,
        block_completion: 54,
        block_completion_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        sequence: 1,
        completed_bytes: 4096,
        data_digest: 1,
        generation: 1,
        state: "completed".to_owned(),
        recorded_at_event: 74,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block read path root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_write_path_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_write_path_count = 1;
    package.semantic.block_write_paths.push(artifact_manifest::BlockWritePathManifest {
        id: 59,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 56,
        backend_generation: 1,
        block_request: 53,
        block_request_generation: 1,
        block_completion: 54,
        block_completion_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        sequence: 2,
        completed_bytes: 4096,
        payload_digest: 1,
        generation: 1,
        state: "completed".to_owned(),
        recorded_at_event: 75,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block write path root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_request_queue_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_request_queue_count = 1;
    package.semantic.block_request_queues.push(artifact_manifest::BlockRequestQueueManifest {
        id: 60,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 56,
        backend_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        depth: 4,
        entries: vec![artifact_manifest::BlockRequestQueueEntryManifest {
            request: 53,
            request_generation: 1,
            completion: Some(54),
            completion_generation: Some(1),
            sequence: 2,
            operation: "write".to_owned(),
            byte_len: 4096,
            state: "completed".to_owned(),
        }],
        pending_count: 0,
        completed_count: 1,
        first_sequence: 2,
        last_sequence: 2,
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 76,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block request queue root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_dma_buffer_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_dma_buffer_count = 1;
    package.semantic.block_dma_buffers.push(artifact_manifest::BlockDmaBufferManifest {
        id: 61,
        backend_kind: "fake-block-backend-object".to_owned(),
        backend: 56,
        backend_generation: 1,
        block_request: 53,
        block_request_generation: 1,
        dma_buffer: 20,
        dma_buffer_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        descriptor: 19,
        descriptor_generation: 1,
        queue: 18,
        queue_generation: 1,
        operation: "write".to_owned(),
        access: "read-write".to_owned(),
        byte_len: 4096,
        buffer_len: 4096,
        buffer_digest: 1,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 77,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block dma buffer root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_page_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_page_object_count = 1;
    package.semantic.block_page_objects.push(artifact_manifest::BlockPageObjectManifest {
        id: 62,
        block_dma_buffer: 61,
        block_dma_buffer_generation: 1,
        block_request: 53,
        block_request_generation: 1,
        block_completion: 54,
        block_completion_generation: 1,
        dma_buffer: 20,
        dma_buffer_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        aspace: artifact_manifest::ContractObjectRefManifest {
            kind: "guest-address-space".to_owned(),
            id: 70,
            generation: 1,
        },
        vma_region: artifact_manifest::ContractObjectRefManifest {
            kind: "vma-region".to_owned(),
            id: 71,
            generation: 1,
        },
        page: artifact_manifest::ContractObjectRefManifest {
            kind: "page-object".to_owned(),
            id: 72,
            generation: 1,
        },
        page_dirty_generation: 1,
        page_backing: "file-backed".to_owned(),
        cow_state: "none".to_owned(),
        page_state: "live".to_owned(),
        page_offset: 0,
        byte_len: 4096,
        operation: "write".to_owned(),
        generation: 1,
        state: "integrated".to_owned(),
        recorded_at_event: 78,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block page object root/count mismatch");
}

#[test]
fn semantic_roots_reject_buffer_cache_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.buffer_cache_object_count = 1;
    package.semantic.buffer_cache_objects.push(artifact_manifest::BufferCacheObjectManifest {
        id: 63,
        block_page_object: 62,
        block_page_object_generation: 1,
        block_dma_buffer: 61,
        block_dma_buffer_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        aspace: artifact_manifest::ContractObjectRefManifest {
            kind: "guest-address-space".to_owned(),
            id: 70,
            generation: 1,
        },
        vma_region: artifact_manifest::ContractObjectRefManifest {
            kind: "vma-region".to_owned(),
            id: 71,
            generation: 1,
        },
        page: artifact_manifest::ContractObjectRefManifest {
            kind: "page-object".to_owned(),
            id: 72,
            generation: 1,
        },
        page_dirty_generation: 1,
        page_offset: 0,
        block_offset: 0,
        byte_len: 4096,
        operation: "write".to_owned(),
        cache_state: "dirty".to_owned(),
        coherency_epoch: 1,
        generation: 1,
        state: "dirty".to_owned(),
        recorded_at_event: 79,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "buffer cache object root/count mismatch");
}

#[test]
fn semantic_roots_reject_file_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.file_object_count = 1;
    package.semantic.file_objects.push(artifact_manifest::FileObjectManifest {
        id: 64,
        buffer_cache_object: 63,
        buffer_cache_object_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        block_range: 52,
        block_range_generation: 1,
        page: artifact_manifest::ContractObjectRefManifest {
            kind: "page-object".to_owned(),
            id: 72,
            generation: 1,
        },
        page_dirty_generation: 1,
        namespace: "rootfs".to_owned(),
        file_key: "demo-file".to_owned(),
        path: "/demo/file.txt".to_owned(),
        file_offset: 0,
        byte_len: 4096,
        file_size: 4096,
        content_digest: 1,
        cache_state: "dirty".to_owned(),
        generation: 1,
        state: "dirty".to_owned(),
        recorded_at_event: 80,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "file object root/count mismatch");
}

#[test]
fn semantic_roots_reject_directory_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.directory_object_count = 1;
    package.semantic.directory_objects.push(artifact_manifest::DirectoryObjectManifest {
        id: 65,
        file_object: 64,
        file_object_generation: 1,
        namespace: "rootfs".to_owned(),
        directory_key: "demo-dir".to_owned(),
        directory_path: "/demo".to_owned(),
        entry_name: "file.txt".to_owned(),
        child_file_key: "demo-file".to_owned(),
        child_path: "/demo/file.txt".to_owned(),
        entry_kind: "file".to_owned(),
        file_size: 4096,
        content_digest: 1,
        generation: 1,
        state: "cached".to_owned(),
        recorded_at_event: 81,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "directory object root/count mismatch");
}

#[test]
fn semantic_roots_reject_fat_adapter_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.fat_adapter_object_count = 1;
    package.semantic.fat_adapter_objects.push(artifact_manifest::FatAdapterObjectManifest {
        id: 66,
        directory_object: 65,
        directory_object_generation: 1,
        file_object: 64,
        file_object_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        implementation: "fatfs".to_owned(),
        version: "0.3.6".to_owned(),
        profile: "fatfs-read-write-demo-v1".to_owned(),
        volume_label: "VMOSFAT".to_owned(),
        image_bytes: 1_048_576,
        adapter_path: "DEMO.TXT".to_owned(),
        semantic_path: "/demo/file.txt".to_owned(),
        bytes_written: 32,
        bytes_read: 32,
        write_digest: 1,
        read_digest: 1,
        file_content_digest: 1,
        generation: 1,
        state: "verified".to_owned(),
        recorded_at_event: 82,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "fat adapter object root/count mismatch");
}

#[test]
fn semantic_roots_reject_ext4_adapter_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.ext4_adapter_object_count = 1;
    package.semantic.ext4_adapter_objects.push(artifact_manifest::Ext4AdapterObjectManifest {
        id: 67,
        directory_object: 65,
        directory_object_generation: 1,
        file_object: 64,
        file_object_generation: 1,
        block_device: 51,
        block_device_generation: 1,
        implementation: "ext4-view".to_owned(),
        version: "0.9.3".to_owned(),
        profile: "ext4-read-only-demo-v1".to_owned(),
        volume_label: "VMOSEXT4".to_owned(),
        image_bytes: 32_768,
        adapter_path: "/demo.txt".to_owned(),
        semantic_path: "/demo/file.txt".to_owned(),
        bytes_read: 32,
        read_digest: 1,
        file_content_digest: 1,
        directory_entries: 1,
        read_only_enforced: true,
        generation: 1,
        state: "verified".to_owned(),
        recorded_at_event: 83,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "ext4 adapter object root/count mismatch");
}

#[test]
fn semantic_roots_reject_file_handle_capability_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.file_handle_capability_count = 1;
    package.semantic.file_handle_capabilities.push(
        artifact_manifest::FileHandleCapabilityManifest {
            id: 68,
            owner_store: 7,
            owner_store_generation: 1,
            file_object: 64,
            file_object_generation: 1,
            directory_object: 65,
            directory_object_generation: 1,
            capability: 9,
            capability_generation: 1,
            handle_slot: 1,
            handle_generation: 1,
            handle_tag: 123,
            operation: "read".to_owned(),
            file_offset: 0,
            byte_len: 32,
            content_digest: 1,
            generation: 1,
            state: "allowed".to_owned(),
            recorded_at_event: 84,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "file handle capability root/count mismatch");
}

#[test]
fn semantic_roots_reject_fs_wait_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.fs_wait_count = 1;
    package.semantic.fs_waits.push(artifact_manifest::FsWaitManifest {
        id: 69,
        wait: 70,
        wait_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        file_object: 64,
        file_object_generation: 1,
        directory_object: 65,
        directory_object_generation: 1,
        file_handle_capability: 68,
        file_handle_capability_generation: 1,
        operation: "read".to_owned(),
        blocker: artifact_manifest::ContractObjectRefManifest {
            kind: "file-handle-capability".to_owned(),
            id: 68,
            generation: 1,
        },
        sequence: 1,
        byte_len: 32,
        generation: 1,
        state: "pending".to_owned(),
        created_at_event: 85,
        completed_at_event: None,
        cancel_reason: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "fs wait root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_driver_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_driver_cleanup_count = 1;
    package.semantic.block_driver_cleanups.push(artifact_manifest::BlockDriverCleanupManifest {
        id: 70,
        io_cleanup: 71,
        io_cleanup_generation: 1,
        driver_store: 7,
        driver_store_generation: 1,
        device: 72,
        device_generation: 1,
        driver_binding: 73,
        driver_binding_generation: 1,
        block_device: 74,
        block_device_generation: 1,
        backend: artifact_manifest::ContractObjectRefManifest {
            kind: "virtio-blk-backend-object".to_owned(),
            id: 75,
            generation: 1,
        },
        cancelled_block_waits: vec![artifact_manifest::ContractObjectRefManifest {
            kind: "block-wait".to_owned(),
            id: 76,
            generation: 1,
        }],
        cancelled_wait_tokens: vec![artifact_manifest::ContractObjectRefManifest {
            kind: "wait-token".to_owned(),
            id: 77,
            generation: 1,
        }],
        revoked_device_capabilities: Vec::new(),
        released_dma_buffers: Vec::new(),
        generation: 1,
        state: "completed".to_owned(),
        started_at_event: 86,
        completed_at_event: Some(87),
        reason: "device-fault".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block driver cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_pending_io_policy_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_pending_io_policy_count = 1;
    package.semantic.block_pending_io_policies.push(
        artifact_manifest::BlockPendingIoPolicyManifest {
            id: 71,
            block_wait: 72,
            block_wait_generation: 1,
            wait: 73,
            wait_generation: 1,
            block_request: 74,
            block_request_generation: 1,
            retry_request: Some(75),
            retry_request_generation: Some(1),
            block_device: 76,
            block_device_generation: 1,
            block_range: 77,
            block_range_generation: 1,
            operation: "read".to_owned(),
            sequence: 1,
            byte_len: 4096,
            action: "retry".to_owned(),
            errno: 11,
            retry_attempt: 1,
            max_retries: 2,
            generation: 1,
            state: "retry-scheduled".to_owned(),
            recorded_at_event: 88,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block pending io policy root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_request_generation_audit_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_request_generation_audit_count = 1;
    package.semantic.block_request_generation_audits.push(
        artifact_manifest::BlockRequestGenerationAuditManifest {
            id: 78,
            block_device: 76,
            block_device_generation: 1,
            block_range: 77,
            block_range_generation: 1,
            block_request: 74,
            block_request_generation: 1,
            backend: artifact_manifest::ContractObjectRefManifest {
                kind: "fake-block-backend-object".to_owned(),
                id: 79,
                generation: 1,
            },
            dma_buffer: artifact_manifest::ContractObjectRefManifest {
                kind: "dma-buffer-object".to_owned(),
                id: 80,
                generation: 1,
            },
            rejected_completion_generation_probes: 1,
            rejected_wait_generation_probes: 1,
            rejected_dma_generation_probes: 1,
            rejected_queue_generation_probes: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 89,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block request generation audit root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_benchmark_count = 1;
    package.semantic.block_benchmarks.push(artifact_manifest::BlockBenchmarkManifest {
        id: 79,
        scenario: "test".to_owned(),
        backend: artifact_manifest::ContractObjectRefManifest {
            kind: "fake-block-backend-object".to_owned(),
            id: 80,
            generation: 1,
        },
        block_device: 76,
        block_device_generation: 1,
        block_range: 77,
        block_range_generation: 1,
        read_path: 81,
        read_path_generation: 1,
        write_path: 82,
        write_path_generation: 1,
        request_queue: 83,
        request_queue_generation: 1,
        block_dma_buffer: 84,
        block_dma_buffer_generation: 1,
        sample_requests: 2,
        sample_bytes: 8192,
        read_completed_requests: 1,
        write_completed_requests: 1,
        queue_completed_requests: 2,
        measured_nanos: 1000,
        budget_nanos: 2000,
        iops: 2_000_000,
        throughput_bytes_per_sec: 8_192_000_000,
        p50_latency_nanos: 400,
        p99_latency_nanos: 900,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 90,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block benchmark root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_recovery_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_recovery_benchmark_count = 1;
    package.semantic.block_recovery_benchmarks.push(
        artifact_manifest::BlockRecoveryBenchmarkManifest {
            id: 85,
            scenario: "test".to_owned(),
            cleanup: 86,
            cleanup_generation: 1,
            io_cleanup: 87,
            io_cleanup_generation: 1,
            backend: artifact_manifest::ContractObjectRefManifest {
                kind: "virtio-blk-backend-object".to_owned(),
                id: 88,
                generation: 1,
            },
            block_device: 89,
            block_device_generation: 1,
            driver_store: 90,
            driver_store_generation: 1,
            device: 91,
            device_generation: 1,
            driver_binding: 92,
            driver_binding_generation: 1,
            recovery_start_event: 93,
            recovery_complete_event: 94,
            cancelled_block_waits: 1,
            cancelled_wait_tokens: 1,
            released_dma_buffers: 1,
            revoked_device_capabilities: 1,
            recovery_nanos: 1000,
            budget_nanos: 2000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 95,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block recovery benchmark root/count mismatch");
}

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

#[test]
fn semantic_roots_reject_network_rx_interrupt_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_rx_interrupt_count = 1;
    package.semantic.network_rx_interrupts.push(artifact_manifest::NetworkRxInterruptManifest {
        id: 37,
        virtio_net_backend: 36,
        virtio_net_backend_generation: 1,
        irq_event: 23,
        irq_event_generation: 1,
        packet_device: 31,
        packet_device_generation: 1,
        rx_queue: 32,
        rx_queue_generation: 1,
        ready_descriptors: 1,
        sequence: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 73,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network rx interrupt root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_rx_wait_resolution_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_rx_wait_resolution_count = 1;
    package.semantic.network_rx_wait_resolutions.push(
        artifact_manifest::NetworkRxWaitResolutionManifest {
            id: 38,
            io_wait: 24,
            io_wait_generation: 1,
            wait: 44,
            wait_generation: 1,
            rx_interrupt: 37,
            rx_interrupt_generation: 1,
            irq_event: 23,
            irq_event_generation: 1,
            packet_device: 31,
            packet_device_generation: 1,
            rx_queue: 32,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 1,
            generation: 1,
            state: "resolved".to_owned(),
            resolved_at_event: 74,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network rx wait resolution root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_tx_capability_gate_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_tx_capability_gate_count = 1;
    package.semantic.network_tx_capability_gates.push(
        artifact_manifest::NetworkTxCapabilityGateManifest {
            id: 39,
            driver_store: 12,
            driver_store_generation: 1,
            packet_device: 31,
            packet_device_generation: 1,
            tx_queue: 33,
            tx_queue_generation: 1,
            packet_descriptor: 34,
            packet_descriptor_generation: 1,
            packet_buffer: 32,
            packet_buffer_generation: 1,
            device_capability: 24,
            device_capability_generation: 1,
            capability: 44,
            capability_generation: 1,
            handle_slot: 1,
            handle_generation: 1,
            handle_tag: 9,
            operation: "tx".to_owned(),
            byte_len: 64,
            sequence: 1,
            generation: 1,
            state: "allowed".to_owned(),
            recorded_at_event: 75,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network tx capability gate root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_tx_completion_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_tx_completion_count = 1;
    package.semantic.network_tx_completions.push(artifact_manifest::NetworkTxCompletionManifest {
        id: 40,
        tx_gate: 39,
        tx_gate_generation: 1,
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 35,
        backend_generation: 1,
        driver_store: 12,
        driver_store_generation: 1,
        packet_device: 31,
        packet_device_generation: 1,
        tx_queue: 33,
        tx_queue_generation: 1,
        packet_descriptor: 34,
        packet_descriptor_generation: 1,
        packet_buffer: 32,
        packet_buffer_generation: 1,
        byte_len: 64,
        sequence: 1,
        completion_sequence: 1,
        generation: 1,
        state: "completed".to_owned(),
        completed_at_event: 76,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network tx completion root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_stack_adapter_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_stack_adapter_count = 1;
    package.semantic.network_stack_adapters.push(artifact_manifest::NetworkStackAdapterManifest {
        id: 41,
        implementation: "smoltcp".to_owned(),
        implementation_version: "0.13.0".to_owned(),
        profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_owned(),
        medium: "ethernet".to_owned(),
        backend_kind: "virtio-net-backend-object".to_owned(),
        backend: 35,
        backend_generation: 1,
        packet_device: 31,
        packet_device_generation: 1,
        rx_queue: 32,
        rx_queue_generation: 1,
        tx_queue: 33,
        tx_queue_generation: 1,
        mac: [2, 0x76, 0x6d, 0x6f, 0x73, 1],
        ipv4_addr: [10, 0, 2, 15],
        ipv4_prefix_len: 24,
        mtu: 1500,
        rx_queue_depth: 4,
        tx_queue_depth: 4,
        max_payload_len: 512,
        socket_capacity: 0,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 77,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network stack adapter root/count mismatch");
}

#[test]
fn semantic_roots_reject_socket_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.socket_object_count = 1;
    package.semantic.socket_objects.push(artifact_manifest::SocketObjectManifest {
        id: 42,
        adapter: 41,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        domain: 2,
        socket_type: 1,
        protocol: 0,
        canonical_protocol: 6,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        generation: 1,
        state: "created".to_owned(),
        created_at_event: 78,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "socket object root/count mismatch");
}

#[test]
fn semantic_roots_reject_endpoint_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.endpoint_object_count = 1;
    package.semantic.endpoint_objects.push(artifact_manifest::EndpointObjectManifest {
        id: 43,
        socket: 42,
        socket_generation: 1,
        adapter: 41,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        family: "inet".to_owned(),
        transport: "tcp".to_owned(),
        local_addr: [0, 0, 0, 0],
        local_port: 0,
        remote_addr: [0, 0, 0, 0],
        remote_port: 0,
        generation: 1,
        state: "allocated".to_owned(),
        created_at_event: 79,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "endpoint object root/count mismatch");
}

#[test]
fn semantic_roots_reject_socket_operation_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.socket_operation_count = 1;
    package.semantic.socket_operations.push(artifact_manifest::SocketOperationManifest {
        id: 44,
        endpoint: 43,
        endpoint_generation: 1,
        socket: 42,
        socket_generation: 1,
        adapter: 41,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        operation: "bind".to_owned(),
        local_addr: [10, 0, 2, 15],
        local_port: 8080,
        remote_addr: [0, 0, 0, 0],
        remote_port: 0,
        backlog: 0,
        byte_len: 0,
        sequence: 1,
        generation: 1,
        state: "applied".to_owned(),
        recorded_at_event: 80,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "socket operation root/count mismatch");
}

#[test]
fn semantic_roots_reject_socket_wait_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.socket_wait_count = 1;
    package.semantic.socket_waits.push(artifact_manifest::SocketWaitManifest {
        id: 45,
        wait: 46,
        wait_generation: 1,
        endpoint: 43,
        endpoint_generation: 1,
        socket: 42,
        socket_generation: 1,
        adapter: 41,
        adapter_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        wait_kind: "socket-readable".to_owned(),
        blocker: artifact_manifest::ContractObjectRefManifest {
            kind: "endpoint-object".to_owned(),
            id: 43,
            generation: 1,
        },
        generation: 1,
        state: "pending".to_owned(),
        created_at_event: 81,
        completed_at_event: None,
        cancel_reason: None,
        ready_sequence: None,
        byte_len: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "socket wait root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_backpressure_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_backpressure_count = 1;
    package.semantic.network_backpressures.push(artifact_manifest::NetworkBackpressureManifest {
        id: 47,
        adapter: 41,
        adapter_generation: 1,
        packet_device: 30,
        packet_device_generation: 1,
        packet_queue: 32,
        packet_queue_generation: 1,
        endpoint: Some(43),
        endpoint_generation: Some(1),
        socket: Some(42),
        socket_generation: Some(1),
        owner_store: Some(7),
        owner_store_generation: Some(1),
        direction: "tx".to_owned(),
        reason: "queue-full".to_owned(),
        action: "reject-send".to_owned(),
        queue_depth: 4,
        queue_limit: 4,
        dropped_packets: 0,
        dropped_bytes: 0,
        sequence: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 82,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network backpressure root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_driver_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_driver_cleanup_count = 1;
    package.semantic.network_driver_cleanups.push(
        artifact_manifest::NetworkDriverCleanupManifest {
            id: 48,
            io_cleanup: 88,
            io_cleanup_generation: 1,
            driver_store: 9,
            driver_store_generation: 3,
            device: 30,
            device_generation: 1,
            driver_binding: 31,
            driver_binding_generation: 1,
            packet_device: 32,
            packet_device_generation: 1,
            adapter: 33,
            adapter_generation: 1,
            backend: artifact_manifest::ContractObjectRefManifest {
                kind: "virtio-net-backend-object".to_owned(),
                id: 34,
                generation: 1,
            },
            cancelled_socket_waits: Vec::new(),
            cancelled_wait_tokens: Vec::new(),
            revoked_packet_capabilities: Vec::new(),
            generation: 1,
            state: "completed".to_owned(),
            started_at_event: 91,
            completed_at_event: Some(92),
            reason: "device-fault".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network driver cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_generation_audit_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_generation_audit_count = 1;
    package.semantic.network_generation_audits.push(
        artifact_manifest::NetworkGenerationAuditManifest {
            id: 49,
            adapter: 41,
            adapter_generation: 1,
            packet_device: 30,
            packet_device_generation: 1,
            packet_queue: 32,
            packet_queue_generation: 1,
            packet_descriptor: 33,
            packet_descriptor_generation: 1,
            packet_buffer: 34,
            packet_buffer_generation: 1,
            dma_buffer: artifact_manifest::ContractObjectRefManifest {
                kind: "dma-buffer-object".to_owned(),
                id: 35,
                generation: 1,
            },
            device_capability: artifact_manifest::ContractObjectRefManifest {
                kind: "device-capability".to_owned(),
                id: 36,
                generation: 1,
            },
            rejected_packet_generation_probes: 2,
            rejected_dma_generation_probes: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 93,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network generation audit root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_fault_injection_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_fault_injection_count = 1;
    package.semantic.network_fault_injections.push(
        artifact_manifest::NetworkFaultInjectionManifest {
            id: 50,
            adapter: 41,
            adapter_generation: 1,
            packet_device: 30,
            packet_device_generation: 1,
            packet_queue: 32,
            packet_queue_generation: 1,
            packet_descriptor: Some(33),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(34),
            packet_buffer_generation: Some(1),
            endpoint: Some(43),
            endpoint_generation: Some(1),
            socket: Some(42),
            socket_generation: Some(1),
            owner_store: Some(7),
            owner_store_generation: Some(1),
            direction: "tx".to_owned(),
            kind: "packet-loss".to_owned(),
            effect: "drop-packet".to_owned(),
            injected_packets: 1,
            dropped_packets: 1,
            error_packets: 0,
            error_code: String::new(),
            sequence: 1,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 94,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network fault injection root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_benchmark_count = 1;
    package.semantic.network_benchmarks.push(artifact_manifest::NetworkBenchmarkManifest {
        id: 51,
        scenario: "host-validation-network-throughput-latency".to_owned(),
        adapter: 41,
        adapter_generation: 1,
        packet_device: 30,
        packet_device_generation: 1,
        tx_queue: 33,
        tx_queue_generation: 1,
        rx_queue: 32,
        rx_queue_generation: 1,
        tx_completion: 40,
        tx_completion_generation: 1,
        rx_wait_resolution: 38,
        rx_wait_resolution_generation: 1,
        endpoint: 43,
        endpoint_generation: 1,
        socket: 42,
        socket_generation: 1,
        owner_store: 7,
        owner_store_generation: 1,
        backpressure: Some(47),
        backpressure_generation: Some(1),
        sample_packets: 3,
        sample_bytes: 6000,
        tx_completed_packets: 1,
        rx_resolved_packets: 1,
        dropped_packets: 1,
        measured_nanos: 120_000,
        budget_nanos: 250_000,
        throughput_bytes_per_sec: 50_000_000,
        p50_latency_nanos: 18_000,
        p99_latency_nanos: 48_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 95,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network benchmark root/count mismatch");
}

#[test]
fn semantic_roots_reject_network_recovery_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.network_recovery_benchmark_count = 1;
    package.semantic.network_recovery_benchmarks.push(
        artifact_manifest::NetworkRecoveryBenchmarkManifest {
            id: 52,
            scenario: "host-validation-network-driver-recovery".to_owned(),
            cleanup: 46,
            cleanup_generation: 1,
            io_cleanup: 32,
            io_cleanup_generation: 1,
            adapter: 41,
            adapter_generation: 1,
            packet_device: 30,
            packet_device_generation: 1,
            backend: artifact_manifest::ContractObjectRefManifest {
                kind: "virtio-net-backend-object".to_owned(),
                id: 35,
                generation: 1,
            },
            driver_store: 7,
            driver_store_generation: 1,
            fault_injection: Some(48),
            fault_injection_generation: Some(1),
            recovery_start_event: 80,
            recovery_complete_event: 90,
            cancelled_socket_waits: 1,
            revoked_packet_capabilities: 1,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 96,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "network recovery benchmark root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_device_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_device_object_count = 1;
    package.semantic.block_device_objects.push(artifact_manifest::BlockDeviceObjectManifest {
        id: 53,
        name: "fake-block0".to_owned(),
        device: 17,
        device_generation: 1,
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 99,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block device object root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_range_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_range_object_count = 1;
    package.semantic.block_range_objects.push(artifact_manifest::BlockRangeObjectManifest {
        id: 54,
        block_device: 53,
        block_device_generation: 1,
        start_sector: 64,
        sector_count: 8,
        byte_offset: 32768,
        byte_len: 4096,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 100,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block range object root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_request_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_request_object_count = 1;
    package.semantic.block_request_objects.push(artifact_manifest::BlockRequestObjectManifest {
        id: 55,
        block_device: 53,
        block_device_generation: 1,
        block_range: 54,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "submitted".to_owned(),
        recorded_at_event: 101,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block request object root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_completion_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_completion_object_count = 1;
    package.semantic.block_completion_objects.push(
        artifact_manifest::BlockCompletionObjectManifest {
            id: 56,
            block_request: 55,
            block_request_generation: 1,
            block_device: 53,
            block_device_generation: 1,
            block_range: 54,
            block_range_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: "success".to_owned(),
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 102,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block completion object root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_wait_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_wait_count = 1;
    package.semantic.block_waits.push(artifact_manifest::BlockWaitManifest {
        id: 57,
        wait: 58,
        wait_generation: 1,
        block_request: 55,
        block_request_generation: 1,
        block_device: 53,
        block_device_generation: 1,
        block_range: 54,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "pending".to_owned(),
        created_at_event: 103,
        completed_at_event: None,
        completion: None,
        completion_generation: None,
        cancel_reason: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block wait root/count mismatch");
}

#[test]
fn semantic_roots_reject_activation_resume_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.activation_resume_count = 1;
    package.semantic.activation_resumes.push(artifact_manifest::ActivationResumeManifest {
        id: 6,
        scheduler_decision: 5,
        scheduler_decision_generation: 1,
        activation: 11,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 7,
        owner_task_generation: 1,
        queue: 1,
        queue_generation: 1,
        context: None,
        context_generation_before: None,
        context_generation_after: None,
        saved_context: None,
        saved_context_generation: None,
        saved_vector_state: None,
        restored_vector_state: None,
        vector_status: "absent".to_owned(),
        vector_restored_at_event: None,
        generation: 1,
        state: "applied".to_owned(),
        resumed_at_event: 8,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "activation resume root/count mismatch");
}

#[test]
fn semantic_roots_reject_activation_wait_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.activation_wait_count = 1;
    package.semantic.activation_waits.push(artifact_manifest::ActivationWaitManifest {
        id: 9,
        activation: 11,
        activation_generation_before: 5,
        activation_generation_after_block: 6,
        activation_generation_after_cancel: None,
        wait: 41,
        wait_generation: 1,
        owner_task: 7,
        owner_task_generation: 2,
        queue: None,
        queue_generation: None,
        generation: 1,
        state: "pending".to_owned(),
        blocked_at_event: 8,
        completed_at_event: None,
        cancel_reason: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "activation wait root/count mismatch");
}

#[test]
fn semantic_roots_reject_activation_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.activation_cleanup_count = 1;
    package.semantic.activation_cleanups.push(artifact_manifest::ActivationCleanupManifest {
        id: 10,
        store: 7,
        target_store_generation: 2,
        result_store_generation: 4,
        activation: 11,
        activation_generation_before: 5,
        activation_generation_after: 6,
        wait: Some(41),
        wait_generation: Some(1),
        owner_task: 9,
        owner_task_generation_before: 2,
        owner_task_generation_after: 3,
        generation: 1,
        state: "completed".to_owned(),
        reason: "store-fault".to_owned(),
        started_at_event: 8,
        completed_at_event: 9,
        steps: Vec::new(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "activation cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_preemption_latency_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.preemption_latency_sample_count = 1;
    package.semantic.preemption_latency_samples.push(
        artifact_manifest::PreemptionLatencySampleManifest {
            id: 11,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            scheduler_decision: 7,
            scheduler_decision_generation: 1,
            activation_resume: 8,
            activation_resume_generation: 1,
            activation: 12,
            activation_generation_before: 3,
            activation_generation_after: 5,
            queue: 2,
            queue_generation: 1,
            interrupt_recorded_at_event: 10,
            preempted_at_event: 11,
            decided_at_event: 12,
            resumed_at_event: 13,
            interrupt_to_preempt_events: 1,
            preempt_to_decision_events: 1,
            decision_to_resume_events: 1,
            interrupt_to_resume_events: 3,
            measured_nanos: 500,
            budget_nanos: 50_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 14,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "preemption latency root/count mismatch");
}

#[test]
fn semantic_roots_reject_hart_event_attribution_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.hart_event_attribution_count = 1;
    package.semantic.hart_event_attributions.push(
        artifact_manifest::HartEventAttributionManifest {
            id: 12,
            hart: 1,
            hart_generation: 2,
            hardware_hart: 0,
            event: 10,
            event_source: "timer".to_owned(),
            event_kind: "TimerInterruptRecorded".to_owned(),
            activation: Some(11),
            activation_generation: Some(3),
            task: Some(7),
            task_generation: Some(1),
            store: None,
            store_generation: None,
            generation: 1,
            state: "recorded".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "hart event attribution root/count mismatch");
}

#[test]
fn semantic_roots_reject_hart_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.hart_count = 1;
    package.semantic.hart_records.push(artifact_manifest::HartRecordManifest {
        id: 1,
        hardware_id: 0,
        label: "boot-hart0".to_owned(),
        state: "idle".to_owned(),
        generation: 2,
        boot: true,
        current_activation: None,
        current_activation_generation: None,
        current_task: None,
        current_task_generation: None,
        current_store: None,
        current_store_generation: None,
        last_event: Some(2),
        last_current_event: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "hart root/count mismatch");
}

#[test]
fn semantic_roots_reject_command_result_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.command_result_count = 1;
    package.semantic.command_results.push(CommandResultManifest {
        id: 1,
        issuer: "contract-test".to_owned(),
        command: "create-wait".to_owned(),
        status: "rejected".to_owned(),
        events: Vec::new(),
        effects: Vec::new(),
        violations: vec!["missing owner".to_owned()],
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "command result root/count mismatch");
}

#[test]
fn semantic_roots_reject_interface_event_count_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.interface_event_count = 1;
    package.semantic.interface_events.push(InterfaceEventManifest {
        id: 1,
        epoch: 9,
        interface_kind: "standard-wasi".to_owned(),
        interface: "wasi:clocks/monotonic-clock".to_owned(),
        operation: "subscribe".to_owned(),
        requester: Some("contract-test".to_owned()),
        artifact: None,
        store: None,
        explanation: "unsupported interface".to_owned(),
    });
    package
        .semantic
        .roots
        .interface_event_roots
        .push("interface-event:standard-wasi:wasi:clocks/monotonic-clock:subscribe".to_owned());
    package.semantic.interface_events.clear();

    let err = validate_migration_package(&package).expect_err("vector mismatch must fail");
    assert_eq!(err.to_string(), "interface event root/count mismatch");
}

#[test]
fn substrate_compatibility_accepts_host_validation_capabilities() {
    let manifest = valid_manifest();
    let report = check_artifact_manifest_substrate_compatibility(
        &manifest,
        SubstrateCapabilitySet::host_validation(),
    )
    .expect("compatibility report");

    assert!(report.ok);
    assert_eq!(report.module_count, SUPERVISOR_WASM_MODULES.len());
    assert!(report.modules.iter().all(|module| module.ok));
}

#[test]
fn interface_compatibility_accepts_host_validation_worlds() {
    let manifest = valid_manifest();
    let capabilities = InterfaceHostCapabilitySet::host_validation();
    let report = check_artifact_manifest_interface_compatibility(&manifest, &capabilities)
        .expect("interface compatibility report");

    assert!(report.ok);
    assert_eq!(report.module_count, SUPERVISOR_WASM_MODULES.len());
    assert!(report.modules.iter().all(|module| module.ok));
}

#[test]
fn interface_compatibility_reports_missing_custom_wit_world() {
    let manifest = valid_manifest();
    let capabilities = InterfaceHostCapabilitySet::empty();
    let report = check_artifact_manifest_interface_compatibility(&manifest, &capabilities)
        .expect("interface compatibility report");
    let driver = report
        .modules
        .iter()
        .find(|module| module.package == "driver_virtio_net")
        .expect("driver report");

    assert!(!report.ok);
    assert!(!driver.ok);
    assert!(driver.missing_custom_wit_worlds.iter().any(|world| world == "semantic:driverkit"));
    assert!(driver.version_mismatches.is_empty());
}

#[test]
fn interface_compatibility_reports_version_mismatch_separately() {
    let manifest = valid_manifest();
    let mut capabilities = InterfaceHostCapabilitySet::host_validation();
    capabilities.hostcall_abi_version = "wire-v0".to_owned();
    let report = check_artifact_manifest_interface_compatibility(&manifest, &capabilities)
        .expect("interface compatibility report");
    let linux = report
        .modules
        .iter()
        .find(|module| module.package == "linux_syscall")
        .expect("linux report");

    assert!(!report.ok);
    assert!(
        linux.version_mismatches.iter().any(|mismatch| mismatch.field == "hostcall_abi_version"
            && mismatch.expected == HOSTCALL_ABI_VERSION
            && mismatch.actual == "wire-v0")
    );
}

#[test]
fn substrate_compatibility_reports_missing_required_authority() {
    let manifest = valid_manifest();
    let report = check_artifact_manifest_substrate_compatibility(
        &manifest,
        SubstrateCapabilitySet::semantic_harness(),
    )
    .expect("compatibility report");
    let driver = report
        .modules
        .iter()
        .find(|module| module.package == "driver_virtio_net")
        .expect("driver report");

    assert!(!report.ok);
    assert!(!driver.ok);
    assert!(driver.missing_required.iter().any(|item| item.authority == "dma"));
    assert!(driver.missing_required.iter().any(|item| item.authority == "mmio"));
    assert!(driver.forbidden_requested.is_empty());
}

#[test]
fn substrate_compatibility_rejects_unknown_required_authority() {
    let manifest = valid_manifest();
    let plan = build_validated_artifact_plan(&manifest).expect("valid plan");
    let mut linux = plan.entry("linux_syscall").expect("linux module").clone();
    linux.interfaces.substrate_authorities.required.push("raw-mmio".to_owned());

    let err =
        check_module_substrate_compatibility(&linux, SubstrateCapabilitySet::host_validation())
            .expect_err("raw requirement token must fail before load");

    assert!(err.to_string().contains("invalid required substrate authority token"));
}

#[test]
fn substrate_compatibility_rejects_forbidden_capability_manifest() {
    let manifest = valid_manifest();
    let plan = build_validated_artifact_plan(&manifest).expect("valid plan");
    let mut linux = plan.entry("linux_syscall").expect("linux module").clone();
    linux.capabilities.push(CapabilityManifest {
        name: "mmio.pci.bar0".to_owned(),
        rights: vec!["read".to_owned()],
        lifetime: "store".to_owned(),
    });

    let report =
        check_module_substrate_compatibility(&linux, SubstrateCapabilitySet::host_validation())
            .expect("compatibility report");

    assert!(!report.ok);
    assert_eq!(report.forbidden_requested, vec!["raw-mmio".to_owned()]);
}

#[test]
fn manifest_validation_rejects_interface_boundary_mismatch() {
    let mut manifest = valid_manifest();
    let linux = manifest
        .modules
        .iter_mut()
        .find(|entry| entry.package == "linux_syscall")
        .expect("linux syscall entry exists");
    linux.interfaces.substrate_profile_required = "device-capable".to_owned();

    let err = validate_artifact_manifest(&manifest).expect_err("bad interface must fail");
    assert!(err.to_string().contains("substrate profile mismatch"));
}

#[test]
fn manifest_validation_rejects_unknown_runtime_mode() {
    let mut manifest = valid_manifest();
    manifest.runtime_mode = "max-debug-production-replay".to_owned();

    assert_eq!(
        validate_artifact_manifest(&manifest).unwrap_err().to_string(),
        "unsupported runtime mode"
    );
}

#[test]
fn object_ref_rejects_null_identity() {
    assert!(ObjectRef::new(ObjectKind::Store, 0, 1).is_err());
    assert!(ObjectRef::new(ObjectKind::Store, 1, 0).is_err());
    assert!(ObjectRef::new(ObjectKind::External, 1, 0).is_ok());
}

#[test]
fn same_id_different_generation_is_distinct() {
    let first = ObjectRef::new(ObjectKind::Store, 7, 1).unwrap();
    let second = ObjectRef::new(ObjectKind::Store, 7, 2).unwrap();

    assert_ne!(first, second);
}

#[test]
fn typed_object_kind_mismatch_is_detected() {
    let cap = ObjectRef::new(ObjectKind::Capability, 3, 1).unwrap();

    assert!(matches!(
        StoreRef::try_from_ref(cap),
        Err(TypedRefError::KindMismatch {
            expected: ObjectKind::Store,
            actual: ObjectKind::Capability,
        })
    ));
    assert!(CapabilityRef::try_from_ref(cap).is_ok());
    let saved = ObjectRef::new(ObjectKind::SavedContext, 4, 1).unwrap();
    assert!(SavedContextRef::try_from_ref(saved).is_ok());
    assert!(matches!(
        ActivationContextRef::try_from_ref(saved),
        Err(TypedRefError::KindMismatch {
            expected: ObjectKind::ActivationContext,
            actual: ObjectKind::SavedContext,
        })
    ));
    let timer = ObjectRef::new(ObjectKind::TimerInterrupt, 5, 1).unwrap();
    assert!(TimerInterruptRef::try_from_ref(timer).is_ok());
    let ipi = ObjectRef::new(ObjectKind::IpiEvent, 6, 1).unwrap();
    assert!(IpiEventRef::try_from_ref(ipi).is_ok());
    let remote_preempt = ObjectRef::new(ObjectKind::RemotePreempt, 6, 1).unwrap();
    assert!(RemotePreemptRef::try_from_ref(remote_preempt).is_ok());
    let remote_park = ObjectRef::new(ObjectKind::RemotePark, 6, 1).unwrap();
    assert!(RemoteParkRef::try_from_ref(remote_park).is_ok());
    let preemption = ObjectRef::new(ObjectKind::Preemption, 6, 1).unwrap();
    assert!(PreemptionRef::try_from_ref(preemption).is_ok());
    let decision = ObjectRef::new(ObjectKind::SchedulerDecision, 7, 1).unwrap();
    assert!(SchedulerDecisionRef::try_from_ref(decision).is_ok());
    let cross_decision = ObjectRef::new(ObjectKind::CrossHartSchedulerDecision, 8, 1).unwrap();
    assert!(CrossHartSchedulerDecisionRef::try_from_ref(cross_decision).is_ok());
    let migration = ObjectRef::new(ObjectKind::ActivationMigration, 9, 1).unwrap();
    assert!(ActivationMigrationRef::try_from_ref(migration).is_ok());
    let safe_point = ObjectRef::new(ObjectKind::SmpSafePoint, 10, 1).unwrap();
    assert!(SmpSafePointRef::try_from_ref(safe_point).is_ok());
    let rendezvous = ObjectRef::new(ObjectKind::StopTheWorldRendezvous, 11, 1).unwrap();
    assert!(StopTheWorldRendezvousRef::try_from_ref(rendezvous).is_ok());
    let code_publish_barrier = ObjectRef::new(ObjectKind::SmpCodePublishBarrier, 12, 1).unwrap();
    assert!(SmpCodePublishBarrierRef::try_from_ref(code_publish_barrier).is_ok());
    let cleanup_quiescence = ObjectRef::new(ObjectKind::SmpCleanupQuiescence, 13, 1).unwrap();
    assert!(SmpCleanupQuiescenceRef::try_from_ref(cleanup_quiescence).is_ok());
    let snapshot_barrier = ObjectRef::new(ObjectKind::SmpSnapshotBarrier, 14, 1).unwrap();
    assert!(SmpSnapshotBarrierRef::try_from_ref(snapshot_barrier).is_ok());
    let stress_run = ObjectRef::new(ObjectKind::SmpStressRun, 15, 1).unwrap();
    assert!(SmpStressRunRef::try_from_ref(stress_run).is_ok());
    let scaling_benchmark = ObjectRef::new(ObjectKind::SmpScalingBenchmark, 16, 1).unwrap();
    assert!(SmpScalingBenchmarkRef::try_from_ref(scaling_benchmark).is_ok());
    let integrated_smp = ObjectRef::new(ObjectKind::IntegratedSmpPreemptionCleanup, 17, 1).unwrap();
    assert!(IntegratedSmpPreemptionCleanupRef::try_from_ref(integrated_smp).is_ok());
    let integrated_network_fault =
        ObjectRef::new(ObjectKind::IntegratedSmpNetworkFault, 18, 1).unwrap();
    assert!(IntegratedSmpNetworkFaultRef::try_from_ref(integrated_network_fault).is_ok());
    let integrated_disk_fault =
        ObjectRef::new(ObjectKind::IntegratedDiskPreemptFault, 19, 1).unwrap();
    assert!(IntegratedDiskPreemptFaultRef::try_from_ref(integrated_disk_fault).is_ok());
    let integrated_simd_migration =
        ObjectRef::new(ObjectKind::IntegratedSimdMigration, 20, 1).unwrap();
    assert!(IntegratedSimdMigrationRef::try_from_ref(integrated_simd_migration).is_ok());
    let integrated_network_disk_io =
        ObjectRef::new(ObjectKind::IntegratedNetworkDiskIo, 21, 1).unwrap();
    assert!(IntegratedNetworkDiskIoRef::try_from_ref(integrated_network_disk_io).is_ok());
    let integrated_display_scheduler_load =
        ObjectRef::new(ObjectKind::IntegratedDisplaySchedulerLoad, 22, 1).unwrap();
    assert!(
        IntegratedDisplaySchedulerLoadRef::try_from_ref(integrated_display_scheduler_load).is_ok()
    );
    let integrated_snapshot_io_lease_barrier =
        ObjectRef::new(ObjectKind::IntegratedSnapshotIoLeaseBarrier, 23, 1).unwrap();
    assert!(
        IntegratedSnapshotIoLeaseBarrierRef::try_from_ref(integrated_snapshot_io_lease_barrier)
            .is_ok()
    );
    let integrated_code_publish_smp_workload =
        ObjectRef::new(ObjectKind::IntegratedCodePublishSmpWorkload, 24, 1).unwrap();
    assert!(
        IntegratedCodePublishSmpWorkloadRef::try_from_ref(integrated_code_publish_smp_workload,)
            .is_ok()
    );
    let integrated_display_panic =
        ObjectRef::new(ObjectKind::IntegratedDisplayPanic, 25, 1).unwrap();
    assert!(IntegratedDisplayPanicRef::try_from_ref(integrated_display_panic).is_ok());
    let integrated_osctl_trace_replay =
        ObjectRef::new(ObjectKind::IntegratedOsctlTraceReplay, 26, 1).unwrap();
    assert!(IntegratedOsctlTraceReplayRef::try_from_ref(integrated_osctl_trace_replay).is_ok());
    let device_object = ObjectRef::new(ObjectKind::DeviceObject, 17, 1).unwrap();
    assert!(DeviceObjectRef::try_from_ref(device_object).is_ok());
    let packet_device_object = ObjectRef::new(ObjectKind::PacketDeviceObject, 30, 1).unwrap();
    assert!(PacketDeviceObjectRef::try_from_ref(packet_device_object).is_ok());
    let packet_buffer_object = ObjectRef::new(ObjectKind::PacketBufferObject, 31, 1).unwrap();
    assert!(PacketBufferObjectRef::try_from_ref(packet_buffer_object).is_ok());
    let packet_queue_object = ObjectRef::new(ObjectKind::PacketQueueObject, 32, 1).unwrap();
    assert!(PacketQueueObjectRef::try_from_ref(packet_queue_object).is_ok());
    let packet_descriptor_object =
        ObjectRef::new(ObjectKind::PacketDescriptorObject, 33, 1).unwrap();
    assert!(PacketDescriptorObjectRef::try_from_ref(packet_descriptor_object).is_ok());
    let fake_net_backend_object = ObjectRef::new(ObjectKind::FakeNetBackendObject, 34, 1).unwrap();
    assert!(FakeNetBackendObjectRef::try_from_ref(fake_net_backend_object).is_ok());
    let virtio_net_backend_object =
        ObjectRef::new(ObjectKind::VirtioNetBackendObject, 35, 1).unwrap();
    assert!(VirtioNetBackendObjectRef::try_from_ref(virtio_net_backend_object).is_ok());
    let network_rx_interrupt = ObjectRef::new(ObjectKind::NetworkRxInterrupt, 36, 1).unwrap();
    assert!(NetworkRxInterruptRef::try_from_ref(network_rx_interrupt).is_ok());
    let network_rx_wait_resolution =
        ObjectRef::new(ObjectKind::NetworkRxWaitResolution, 37, 1).unwrap();
    assert!(NetworkRxWaitResolutionRef::try_from_ref(network_rx_wait_resolution).is_ok());
    let network_tx_capability_gate =
        ObjectRef::new(ObjectKind::NetworkTxCapabilityGate, 38, 1).unwrap();
    assert!(NetworkTxCapabilityGateRef::try_from_ref(network_tx_capability_gate).is_ok());
    let network_tx_completion = ObjectRef::new(ObjectKind::NetworkTxCompletion, 39, 1).unwrap();
    assert!(NetworkTxCompletionRef::try_from_ref(network_tx_completion).is_ok());
    let network_stack_adapter = ObjectRef::new(ObjectKind::NetworkStackAdapter, 40, 1).unwrap();
    assert!(NetworkStackAdapterRef::try_from_ref(network_stack_adapter).is_ok());
    let socket_object = ObjectRef::new(ObjectKind::SocketObject, 41, 1).unwrap();
    assert!(SocketObjectRef::try_from_ref(socket_object).is_ok());
    let endpoint_object = ObjectRef::new(ObjectKind::EndpointObject, 42, 1).unwrap();
    assert!(EndpointObjectRef::try_from_ref(endpoint_object).is_ok());
    let socket_operation = ObjectRef::new(ObjectKind::SocketOperation, 43, 1).unwrap();
    assert!(SocketOperationRef::try_from_ref(socket_operation).is_ok());
    let socket_wait = ObjectRef::new(ObjectKind::SocketWait, 44, 1).unwrap();
    assert!(SocketWaitRef::try_from_ref(socket_wait).is_ok());
    let network_backpressure = ObjectRef::new(ObjectKind::NetworkBackpressure, 45, 1).unwrap();
    assert!(NetworkBackpressureRef::try_from_ref(network_backpressure).is_ok());
    let network_driver_cleanup = ObjectRef::new(ObjectKind::NetworkDriverCleanup, 46, 1).unwrap();
    assert!(NetworkDriverCleanupRef::try_from_ref(network_driver_cleanup).is_ok());
    let network_generation_audit =
        ObjectRef::new(ObjectKind::NetworkGenerationAudit, 47, 1).unwrap();
    assert!(NetworkGenerationAuditRef::try_from_ref(network_generation_audit).is_ok());
    let network_fault_injection = ObjectRef::new(ObjectKind::NetworkFaultInjection, 48, 1).unwrap();
    assert!(NetworkFaultInjectionRef::try_from_ref(network_fault_injection).is_ok());
    let network_benchmark = ObjectRef::new(ObjectKind::NetworkBenchmark, 49, 1).unwrap();
    assert!(NetworkBenchmarkRef::try_from_ref(network_benchmark).is_ok());
    let network_recovery_benchmark =
        ObjectRef::new(ObjectKind::NetworkRecoveryBenchmark, 50, 1).unwrap();
    assert!(NetworkRecoveryBenchmarkRef::try_from_ref(network_recovery_benchmark).is_ok());
    let block_device_object = ObjectRef::new(ObjectKind::BlockDeviceObject, 51, 1).unwrap();
    assert!(BlockDeviceObjectRef::try_from_ref(block_device_object).is_ok());
    let block_range_object = ObjectRef::new(ObjectKind::BlockRangeObject, 52, 1).unwrap();
    assert!(BlockRangeObjectRef::try_from_ref(block_range_object).is_ok());
    let block_request_object = ObjectRef::new(ObjectKind::BlockRequestObject, 53, 1).unwrap();
    assert!(BlockRequestObjectRef::try_from_ref(block_request_object).is_ok());
    let block_completion_object = ObjectRef::new(ObjectKind::BlockCompletionObject, 54, 1).unwrap();
    assert!(BlockCompletionObjectRef::try_from_ref(block_completion_object).is_ok());
    let block_wait = ObjectRef::new(ObjectKind::BlockWait, 55, 1).unwrap();
    assert!(BlockWaitRef::try_from_ref(block_wait).is_ok());
    let fake_block_backend_object =
        ObjectRef::new(ObjectKind::FakeBlockBackendObject, 56, 1).unwrap();
    assert!(FakeBlockBackendObjectRef::try_from_ref(fake_block_backend_object).is_ok());
    let virtio_blk_backend_object =
        ObjectRef::new(ObjectKind::VirtioBlkBackendObject, 57, 1).unwrap();
    assert!(VirtioBlkBackendObjectRef::try_from_ref(virtio_blk_backend_object).is_ok());
    let block_read_path = ObjectRef::new(ObjectKind::BlockReadPath, 58, 1).unwrap();
    assert!(BlockReadPathRef::try_from_ref(block_read_path).is_ok());
    let block_write_path = ObjectRef::new(ObjectKind::BlockWritePath, 59, 1).unwrap();
    assert!(BlockWritePathRef::try_from_ref(block_write_path).is_ok());
    let block_request_queue = ObjectRef::new(ObjectKind::BlockRequestQueue, 60, 1).unwrap();
    assert!(BlockRequestQueueRef::try_from_ref(block_request_queue).is_ok());
    let block_dma_buffer = ObjectRef::new(ObjectKind::BlockDmaBuffer, 61, 1).unwrap();
    assert!(BlockDmaBufferRef::try_from_ref(block_dma_buffer).is_ok());
    let block_page_object = ObjectRef::new(ObjectKind::BlockPageObject, 62, 1).unwrap();
    assert!(BlockPageObjectRef::try_from_ref(block_page_object).is_ok());
    let buffer_cache_object = ObjectRef::new(ObjectKind::BufferCacheObject, 63, 1).unwrap();
    assert!(BufferCacheObjectRef::try_from_ref(buffer_cache_object).is_ok());
    let file_object = ObjectRef::new(ObjectKind::FileObject, 64, 1).unwrap();
    assert!(FileObjectRef::try_from_ref(file_object).is_ok());
    let directory_object = ObjectRef::new(ObjectKind::DirectoryObject, 65, 1).unwrap();
    assert!(DirectoryObjectRef::try_from_ref(directory_object).is_ok());
    let fat_adapter_object = ObjectRef::new(ObjectKind::FatAdapterObject, 66, 1).unwrap();
    assert!(FatAdapterObjectRef::try_from_ref(fat_adapter_object).is_ok());
    let ext4_adapter_object = ObjectRef::new(ObjectKind::Ext4AdapterObject, 67, 1).unwrap();
    assert!(Ext4AdapterObjectRef::try_from_ref(ext4_adapter_object).is_ok());
    let file_handle_capability = ObjectRef::new(ObjectKind::FileHandleCapability, 68, 1).unwrap();
    assert!(FileHandleCapabilityRef::try_from_ref(file_handle_capability).is_ok());
    let fs_wait = ObjectRef::new(ObjectKind::FsWait, 69, 1).unwrap();
    assert!(FsWaitRef::try_from_ref(fs_wait).is_ok());
    let block_driver_cleanup = ObjectRef::new(ObjectKind::BlockDriverCleanup, 70, 1).unwrap();
    assert!(BlockDriverCleanupRef::try_from_ref(block_driver_cleanup).is_ok());
    let block_pending_io_policy = ObjectRef::new(ObjectKind::BlockPendingIoPolicy, 71, 1).unwrap();
    assert!(BlockPendingIoPolicyRef::try_from_ref(block_pending_io_policy).is_ok());
    let block_request_generation_audit =
        ObjectRef::new(ObjectKind::BlockRequestGenerationAudit, 72, 1).unwrap();
    assert!(BlockRequestGenerationAuditRef::try_from_ref(block_request_generation_audit).is_ok());
    let block_benchmark = ObjectRef::new(ObjectKind::BlockBenchmark, 73, 1).unwrap();
    assert!(BlockBenchmarkRef::try_from_ref(block_benchmark).is_ok());
    let block_recovery_benchmark =
        ObjectRef::new(ObjectKind::BlockRecoveryBenchmark, 74, 1).unwrap();
    assert!(BlockRecoveryBenchmarkRef::try_from_ref(block_recovery_benchmark).is_ok());
    let target_feature_set = ObjectRef::new(ObjectKind::TargetFeatureSet, 75, 1).unwrap();
    assert!(TargetFeatureSetRef::try_from_ref(target_feature_set).is_ok());
    let vector_state = ObjectRef::new(ObjectKind::VectorState, 76, 1).unwrap();
    assert!(VectorStateRef::try_from_ref(vector_state).is_ok());
    let simd_fault_injection = ObjectRef::new(ObjectKind::SimdFaultInjection, 77, 1).unwrap();
    assert!(SimdFaultInjectionRef::try_from_ref(simd_fault_injection).is_ok());
    let simd_benchmark = ObjectRef::new(ObjectKind::SimdBenchmark, 78, 1).unwrap();
    assert!(SimdBenchmarkRef::try_from_ref(simd_benchmark).is_ok());
    let simd_context_switch_benchmark =
        ObjectRef::new(ObjectKind::SimdContextSwitchBenchmark, 79, 1).unwrap();
    assert!(SimdContextSwitchBenchmarkRef::try_from_ref(simd_context_switch_benchmark).is_ok());
    let framebuffer_object = ObjectRef::new(ObjectKind::FramebufferObject, 80, 1).unwrap();
    assert!(FramebufferObjectRef::try_from_ref(framebuffer_object).is_ok());
    let display_object = ObjectRef::new(ObjectKind::DisplayObject, 81, 1).unwrap();
    assert!(DisplayObjectRef::try_from_ref(display_object).is_ok());
    let display_capability = ObjectRef::new(ObjectKind::DisplayCapability, 82, 1).unwrap();
    assert!(DisplayCapabilityRef::try_from_ref(display_capability).is_ok());
    let framebuffer_window_lease =
        ObjectRef::new(ObjectKind::FramebufferWindowLease, 83, 1).unwrap();
    assert!(FramebufferWindowLeaseRef::try_from_ref(framebuffer_window_lease).is_ok());
    let framebuffer_mapping = ObjectRef::new(ObjectKind::FramebufferMapping, 84, 1).unwrap();
    assert!(FramebufferMappingRef::try_from_ref(framebuffer_mapping).is_ok());
    let framebuffer_write = ObjectRef::new(ObjectKind::FramebufferWrite, 85, 1).unwrap();
    assert!(FramebufferWriteRef::try_from_ref(framebuffer_write).is_ok());
    let framebuffer_flush_region =
        ObjectRef::new(ObjectKind::FramebufferFlushRegion, 86, 1).unwrap();
    assert!(FramebufferFlushRegionRef::try_from_ref(framebuffer_flush_region).is_ok());
    let framebuffer_dirty_region =
        ObjectRef::new(ObjectKind::FramebufferDirtyRegion, 87, 1).unwrap();
    assert!(FramebufferDirtyRegionRef::try_from_ref(framebuffer_dirty_region).is_ok());
    let display_event_log = ObjectRef::new(ObjectKind::DisplayEventLog, 88, 1).unwrap();
    assert!(DisplayEventLogRef::try_from_ref(display_event_log).is_ok());
    let display_cleanup = ObjectRef::new(ObjectKind::DisplayCleanup, 89, 1).unwrap();
    assert!(DisplayCleanupRef::try_from_ref(display_cleanup).is_ok());
    let display_snapshot_barrier =
        ObjectRef::new(ObjectKind::DisplaySnapshotBarrier, 90, 1).unwrap();
    assert!(DisplaySnapshotBarrierRef::try_from_ref(display_snapshot_barrier).is_ok());
    let display_panic_last_frame =
        ObjectRef::new(ObjectKind::DisplayPanicLastFrame, 91, 1).unwrap();
    assert!(DisplayPanicLastFrameRef::try_from_ref(display_panic_last_frame).is_ok());
    let framebuffer_benchmark = ObjectRef::new(ObjectKind::FramebufferBenchmark, 92, 1).unwrap();
    assert!(FramebufferBenchmarkRef::try_from_ref(framebuffer_benchmark).is_ok());
    let queue_object = ObjectRef::new(ObjectKind::QueueObject, 18, 1).unwrap();
    assert!(QueueObjectRef::try_from_ref(queue_object).is_ok());
    let descriptor_object = ObjectRef::new(ObjectKind::DescriptorObject, 19, 1).unwrap();
    assert!(DescriptorObjectRef::try_from_ref(descriptor_object).is_ok());
    let dma_buffer_object = ObjectRef::new(ObjectKind::DmaBufferObject, 20, 1).unwrap();
    assert!(DmaBufferObjectRef::try_from_ref(dma_buffer_object).is_ok());
    let mmio_region_object = ObjectRef::new(ObjectKind::MmioRegionObject, 21, 1).unwrap();
    assert!(MmioRegionObjectRef::try_from_ref(mmio_region_object).is_ok());
    let irq_line_object = ObjectRef::new(ObjectKind::IrqLineObject, 22, 1).unwrap();
    assert!(IrqLineObjectRef::try_from_ref(irq_line_object).is_ok());
    let irq_event = ObjectRef::new(ObjectKind::IrqEvent, 23, 1).unwrap();
    assert!(IrqEventRef::try_from_ref(irq_event).is_ok());
    let device_capability = ObjectRef::new(ObjectKind::DeviceCapability, 24, 1).unwrap();
    assert!(DeviceCapabilityRef::try_from_ref(device_capability).is_ok());
    let driver_binding = ObjectRef::new(ObjectKind::DriverStoreBinding, 25, 1).unwrap();
    assert!(DriverStoreBindingRef::try_from_ref(driver_binding).is_ok());
    let io_wait = ObjectRef::new(ObjectKind::IoWait, 26, 1).unwrap();
    assert!(IoWaitRef::try_from_ref(io_wait).is_ok());
    let io_cleanup = ObjectRef::new(ObjectKind::IoCleanup, 27, 1).unwrap();
    assert!(IoCleanupRef::try_from_ref(io_cleanup).is_ok());
    let io_fault = ObjectRef::new(ObjectKind::IoFaultInjection, 28, 1).unwrap();
    assert!(IoFaultInjectionRef::try_from_ref(io_fault).is_ok());
    let io_report = ObjectRef::new(ObjectKind::IoValidationReport, 29, 1).unwrap();
    assert!(IoValidationReportRef::try_from_ref(io_report).is_ok());
    let resume = ObjectRef::new(ObjectKind::ActivationResume, 8, 1).unwrap();
    assert!(ActivationResumeRef::try_from_ref(resume).is_ok());
    let activation_wait = ObjectRef::new(ObjectKind::ActivationWait, 9, 1).unwrap();
    assert!(ActivationWaitRef::try_from_ref(activation_wait).is_ok());
    let hart_event = ObjectRef::new(ObjectKind::HartEventAttribution, 10, 1).unwrap();
    assert!(HartEventAttributionRef::try_from_ref(hart_event).is_ok());
}

#[test]
fn tombstone_preserves_exact_generation() {
    let dead_store = ObjectRef::new(ObjectKind::Store, 9, 4).unwrap();
    let tombstone = TombstoneRecord::new(dead_store, 88, "cleanup-store-dead");

    assert_eq!(tombstone.object, dead_store);
    assert_eq!(tombstone.object.generation, 4);
    assert_eq!(tombstone.died_at_event, 88);
}

#[test]
fn schema_versions_are_referenced_by_views_edges_events_and_traces() {
    let store = StoreRef::new(1, 1).unwrap().object_ref();
    let code = CodeObjectRef::new(2, 1).unwrap().object_ref();
    let edge = ContractEdge::new(store, code, RefMode::Live, "store->code", 7);
    let view = StoreViewV1 {
        schema: VIEW_SCHEMA_V1,
        kind: ObjectKind::Store,
        object: store,
        state: "running".to_owned(),
        owner: None,
        references: vec![edge.clone()],
        last_transition: Some("bound->running".to_owned()),
        last_error: None,
    };

    assert_eq!(CONTRACT_SCHEMA_VERSION.name, "semantic-contract-v0.1");
    assert_eq!(CONTRACT_SCHEMA, CONTRACT_SCHEMA_VERSION.name);
    assert_eq!(view.schema, VIEW_SCHEMA_V1);
    assert_eq!(edge.mode, RefMode::Live);
    assert_eq!(EDGE_SCHEMA_V1, 1);
    assert_eq!(EVENT_SCHEMA_V1, 1);
    assert_eq!(TRACE_SCHEMA_V1, 1);
}
