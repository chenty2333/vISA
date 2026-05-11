use artifact_manifest::{
    ArtifactBundleManifest, BoundaryValidationReportManifest, BoundaryValidationViolationManifest,
    CapabilityManifest, CommandResultManifest, CompilerManifest, ExternManifest,
    GuestStateManifest, InterfaceEventManifest, InterfaceRequirementManifest,
    MigrationHostManifest, MigrationPackageManifest, MigrationTargetManifest,
    ModuleArtifactManifest, RequiredArtifactProfileManifest, ResourceLimitsManifest,
    RuntimeActivationRecordManifest, SemanticRootSetManifest, SemanticSnapshotManifest,
    SignatureManifest, SubstrateAuthorityRequirementManifest, SubstrateBoundaryManifest,
    SubstrateEventManifest, TargetManifest,
};
use contract_core::*;
use service_core::net_contract::NETWORK_CONTRACT_VERSION;
use supervisor_catalog::{
    ARTIFACT_SIGNATURE_PROFILE, DMW_LAYOUT, LINUX_ABI_PROFILE, MACHINE_ABI_VERSION,
    RUNTIME_ONLY_EXECUTOR_ABI, SUPERVISOR_ABI_VERSION, SUPERVISOR_ARTIFACT_FORMAT,
    SUPERVISOR_COMPILER_ENGINE, SUPERVISOR_EXECUTION_MODE, SUPERVISOR_WASM_MODULES,
    WASM_FEATURE_PROFILE, WasmModuleSpec, module_dependencies, module_interface_spec,
};
use visa_profile::SubstrateCapabilitySet;

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

fn add_native_portable_execution_chain(package: &mut MigrationPackageManifest) {
    let hostcall = artifact_manifest::HostcallSpecManifest {
        number: 1,
        name: "visa.console.write".to_owned(),
        category: "service".to_owned(),
        object: "visa.console".to_owned(),
        operation: "write".to_owned(),
        may_pending: false,
    };
    let address_map = artifact_manifest::TargetAddressMapEntryManifest {
        symbol: "visa_start".to_owned(),
        offset: 0,
        len: 64,
    };
    package.semantic.target_artifact_count = 1;
    package.semantic.roots.target_artifact_roots = vec!["target-artifact id=1".to_owned()];
    package.semantic.target_artifacts = vec![artifact_manifest::TargetArtifactImageManifest {
        id: 1,
        package: "native-visa".to_owned(),
        artifact_name: "visa-native-artifact".to_owned(),
        role: "visa-native-workload".to_owned(),
        kind: "target-artifact-image".to_owned(),
        target_profile: "minimal-bare-metal".to_owned(),
        abi_fingerprint: "native-visa-abi".to_owned(),
        manifest_binding_hash: "native-visa-binding".to_owned(),
        code_hash: "native-visa-code".to_owned(),
        exports: vec!["visa_start".to_owned()],
        hostcalls: vec![hostcall.clone()],
        memory_plan: artifact_manifest::TargetMemoryPlanManifest {
            max_memory_pages: 16,
            max_table_elements: 0,
            max_hostcalls_per_activation: 16,
        },
        address_map: vec![address_map.clone()],
        payload_len: 64,
        ..Default::default()
    }];

    package.semantic.code_object_count = 1;
    package.semantic.roots.code_object_roots = vec!["code-object id=1".to_owned()];
    package.semantic.code_objects = vec![artifact_manifest::CodeObjectManifest {
        id: 1,
        artifact_id: 1,
        package: "native-visa".to_owned(),
        owner_profile: "minimal-bare-metal".to_owned(),
        generation: 1,
        state: "bound-to-store".to_owned(),
        bound_store: Some(1),
        bound_store_generation: Some(1),
        text_permission: "rx".to_owned(),
        rodata_permission: "ro".to_owned(),
        code_hash: "native-visa-code".to_owned(),
        hostcalls: vec![hostcall.clone()],
        address_map: vec![address_map],
        ..Default::default()
    }];

    package.semantic.activation_record_count = 1;
    package.semantic.roots.activation_record_roots = vec!["activation id=1".to_owned()];
    package.semantic.activation_records = vec![artifact_manifest::ActivationRecordManifest {
        id: 1,
        store: 1,
        store_generation: 1,
        code_object: 1,
        code_generation: 1,
        artifact: 1,
        entry: "symbol:visa_start".to_owned(),
        generation: 1,
        state: "running".to_owned(),
        ..Default::default()
    }];

    package.semantic.hostcall_trace_count = 1;
    package.semantic.roots.hostcall_trace_roots = vec!["hostcall id=1".to_owned()];
    package.semantic.hostcall_trace = vec![artifact_manifest::HostcallTraceManifest {
        id: 1,
        generation: 1,
        activation: 1,
        activation_generation: 1,
        store: 1,
        store_generation: 1,
        code_object: 1,
        code_generation: 1,
        artifact: 1,
        hostcall_number: 1,
        name: "visa.console.write".to_owned(),
        category: "service".to_owned(),
        subject: "native-visa".to_owned(),
        subject_source: "active-state".to_owned(),
        object: "visa.console".to_owned(),
        operation: "write".to_owned(),
        record_mode: "live".to_owned(),
        allowed: true,
        gate_status: "allowed".to_owned(),
        result: "ok".to_owned(),
        ret_tag: "ok".to_owned(),
        ..Default::default()
    }];
    add_portable_boundary_validation(package);
}

fn add_portable_boundary_validation(package: &mut MigrationPackageManifest) {
    add_boundary_validation(package, EvidenceBoundaryLevel::PortableArtifactExecution);
}

fn add_real_target_boundary_validation(package: &mut MigrationPackageManifest) {
    add_boundary_validation(package, EvidenceBoundaryLevel::RealTargetSubstrate);
}

fn add_boundary_validation(package: &mut MigrationPackageManifest, level: EvidenceBoundaryLevel) {
    package.semantic.snapshot_validation = BoundaryValidationReportManifest {
        validator: "snapshot-barrier".to_owned(),
        evidence_boundary: level.as_str().to_owned(),
        ok: true,
        violation_count: 0,
        violations: Vec::new(),
    };
    package.semantic.replay_validation = BoundaryValidationReportManifest {
        validator: "package-replay".to_owned(),
        evidence_boundary: level.as_str().to_owned(),
        ok: true,
        violation_count: 0,
        violations: Vec::new(),
    };
    package.semantic.roots.snapshot_validation_roots = vec![format!(
        "boundary-validation validator=snapshot-barrier evidence={} ok=true violations=0",
        level.as_str()
    )];
    package.semantic.roots.replay_validation_roots = vec![format!(
        "boundary-validation validator=package-replay evidence={} ok=true violations=0",
        level.as_str()
    )];
}

fn clear_boundary_validation(package: &mut MigrationPackageManifest) {
    package.semantic.snapshot_validation = Default::default();
    package.semantic.replay_validation = Default::default();
    package.semantic.snapshot_validation_violation_count = 0;
    package.semantic.replay_validation_violation_count = 0;
    package.semantic.roots.snapshot_validation_roots.clear();
    package.semantic.roots.replay_validation_roots.clear();
}

fn convert_native_chain_to_trap_only(package: &mut MigrationPackageManifest, trap_offset: u64) {
    let metadata = artifact_manifest::TargetTrapMetadataManifest {
        class: "fault".to_owned(),
        symbol: "visa_fault".to_owned(),
        offset: 16,
    };
    package.semantic.target_artifacts[0].trap_metadata = vec![metadata.clone()];
    package.semantic.code_objects[0].trap_metadata = vec![metadata];

    package.semantic.hostcall_trace_count = 0;
    package.semantic.roots.hostcall_trace_roots.clear();
    package.semantic.hostcall_trace.clear();

    package.semantic.trap_record_count = 1;
    package.semantic.roots.trap_roots = vec!["trap id=1".to_owned()];
    package.semantic.trap_records = vec![artifact_manifest::TrapRecordManifest {
        id: 1,
        generation: 1,
        class: "fault".to_owned(),
        store: Some(1),
        store_generation: Some(1),
        activation: Some(1),
        activation_generation: Some(1),
        code_object: Some(1),
        code_generation: Some(1),
        artifact: Some(1),
        offset: Some(trap_offset),
        attribution_status: "trap-map-attributed".to_owned(),
        fault_policy: "abort".to_owned(),
        effect: "trap".to_owned(),
        detail: "trap-only execution evidence".to_owned(),
        ..Default::default()
    }];
}

#[test]
fn external_audit_flags_missing_native_consumer_and_artifact_chain() {
    let package = minimal_migration_package();

    let report = audit_migration_package(&package);

    assert!(!report.ok());
    assert!(report.errors().any(|finding| finding.code == "missing-target-artifact-evidence"));
    assert!(report.warnings().any(|finding| finding.code == "missing-visa-native-consumer"));
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(!report.real_target_substrate_claim);
}

#[test]
fn external_audit_accepts_visa_native_portable_artifact_chain() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert!(report.replay_quiescent);
    assert!(report.ok(), "{:#?}", report.errors().collect::<Vec<_>>());
    assert!(report.portable_artifact_execution_claim);
    assert!(report.visa_native_portable_artifact_execution_claim);
    assert_eq!(report.visa_native_artifact_count, 1);
}

#[test]
fn external_audit_rejects_portable_chain_without_boundary_validation() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    clear_boundary_validation(&mut package);

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-without-validation" })
    );
}

#[test]
fn external_audit_rejects_portable_execution_with_unbacked_hostcall_capability() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.hostcall_trace[0].cap_args =
        vec![artifact_manifest::CapabilityHandleArgManifest {
            id: 77,
            object: "visa.timer".to_owned(),
            generation: 4,
            rights: vec!["now".to_owned()],
            ..Default::default()
        }];

    let report = audit_migration_package(&package);

    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_capability_gated_hostcall_without_cap_args() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.target_artifacts[0].hostcalls[0].name = "visa.timer.now".to_owned();
    package.semantic.target_artifacts[0].hostcalls[0].category = "timer".to_owned();
    package.semantic.target_artifacts[0].hostcalls[0].object = "visa.timer".to_owned();
    package.semantic.target_artifacts[0].hostcalls[0].operation = "now".to_owned();
    package.semantic.code_objects[0].hostcalls[0].name = "visa.timer.now".to_owned();
    package.semantic.code_objects[0].hostcalls[0].category = "timer".to_owned();
    package.semantic.code_objects[0].hostcalls[0].object = "visa.timer".to_owned();
    package.semantic.code_objects[0].hostcalls[0].operation = "now".to_owned();
    package.semantic.hostcall_trace[0].name = "visa.timer.now".to_owned();
    package.semantic.hostcall_trace[0].category = "timer".to_owned();
    package.semantic.hostcall_trace[0].object = "visa.timer".to_owned();
    package.semantic.hostcall_trace[0].operation = "now".to_owned();

    let report = audit_migration_package(&package);

    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_hostcall_cap_arg_without_required_right() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.target_artifacts[0].hostcalls[0].name = "visa.timer.now".to_owned();
    package.semantic.target_artifacts[0].hostcalls[0].category = "timer".to_owned();
    package.semantic.target_artifacts[0].hostcalls[0].object = "visa.timer".to_owned();
    package.semantic.target_artifacts[0].hostcalls[0].operation = "now".to_owned();
    package.semantic.code_objects[0].hostcalls[0].name = "visa.timer.now".to_owned();
    package.semantic.code_objects[0].hostcalls[0].category = "timer".to_owned();
    package.semantic.code_objects[0].hostcalls[0].object = "visa.timer".to_owned();
    package.semantic.code_objects[0].hostcalls[0].operation = "now".to_owned();
    package.semantic.hostcall_trace[0].name = "visa.timer.now".to_owned();
    package.semantic.hostcall_trace[0].category = "timer".to_owned();
    package.semantic.hostcall_trace[0].object = "visa.timer".to_owned();
    package.semantic.hostcall_trace[0].operation = "now".to_owned();
    package.semantic.hostcall_trace[0].cap_args =
        vec![artifact_manifest::CapabilityHandleArgManifest {
            id: 7,
            object: "visa.timer".to_owned(),
            generation: 2,
            rights: Vec::new(),
            rights_mask: 0,
            owner_store: Some(1),
            owner_store_generation: Some(1),
            ..Default::default()
        }];
    package.semantic.capability_record_count = 1;
    package.semantic.roots.target_capability_record_roots =
        vec!["capability-record id=7 generation=2".to_owned()];
    package.semantic.capability_records = vec![artifact_manifest::CapabilityRecordManifest {
        id: 7,
        subject: "native-visa".to_owned(),
        object: "visa.timer".to_owned(),
        rights: vec!["now".to_owned()],
        lifetime: "store".to_owned(),
        class: "timer".to_owned(),
        owner_store: Some(1),
        owner_store_generation: Some(1),
        source: "test".to_owned(),
        generation: 2,
        ..Default::default()
    }];

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
}

#[test]
fn external_audit_accepts_canonical_semantic_hostcall_success_trace() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.hostcall_trace[0].record_mode = "deterministic".to_owned();
    package.semantic.hostcall_trace[0].gate_status = "exit".to_owned();
    package.semantic.hostcall_trace[0].result = "complete".to_owned();
    package.semantic.hostcall_trace[0].ret_tag = "ok".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert!(report.portable_artifact_execution_claim);
    assert!(report.visa_native_portable_artifact_execution_claim);
}

#[test]
fn external_audit_does_not_accept_execution_claims_from_invalid_package() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.hostcall_trace_count = 2;

    let report = audit_migration_package(&package);

    assert!(!report.contract_package_valid);
    assert!(!report.ok());
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(report.errors().any(|finding| finding.code == "contract-package-invalid"));
}

#[test]
fn external_audit_distinguishes_generic_portable_chain_from_native_chain() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    let artifact = &mut package.semantic.target_artifacts[0];
    artifact.package = "frontend".to_owned();
    artifact.artifact_name = "frontend-artifact".to_owned();
    artifact.role = "frontend-personality".to_owned();
    artifact.hostcalls[0].object = "wasi.console".to_owned();
    package.semantic.code_objects[0].package = "frontend".to_owned();
    package.semantic.code_objects[0].hostcalls[0].object = "wasi.console".to_owned();
    package.semantic.hostcall_trace[0].object = "wasi.console".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert_eq!(report.visa_native_artifact_count, 0);
    assert!(report.warnings().any(|finding| {
        finding.code == "portable-artifact-execution-without-visa-native-chain"
    }));
}

#[test]
fn external_audit_rejects_name_only_visa_native_spoof() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    let artifact = &mut package.semantic.target_artifacts[0];
    artifact.package = "frontend".to_owned();
    artifact.artifact_name = "visa-native-spoof".to_owned();
    artifact.role = "frontend-personality".to_owned();
    artifact.hostcalls[0].object = "wasi.console".to_owned();
    package.semantic.code_objects[0].package = "frontend".to_owned();
    package.semantic.code_objects[0].hostcalls[0].object = "wasi.console".to_owned();
    package.semantic.hostcall_trace[0].object = "wasi.console".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert_eq!(report.visa_native_artifact_count, 0);
    assert!(report.warnings().any(|finding| finding.code == "missing-visa-native-consumer"));
}

#[test]
fn external_audit_rejects_personality_role_with_visa_hostcall_as_native_consumer() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    let artifact = &mut package.semantic.target_artifacts[0];
    artifact.package = "frontend".to_owned();
    artifact.role = "frontend-personality".to_owned();
    package.semantic.code_objects[0].package = "frontend".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert_eq!(report.visa_native_artifact_count, 0);
    assert!(report.warnings().any(|finding| finding.code == "missing-visa-native-consumer"));
}

#[test]
fn external_audit_rejects_case_variant_personality_role_as_native_consumer() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    let artifact = &mut package.semantic.target_artifacts[0];
    artifact.package = "frontend".to_owned();
    artifact.role = "frontend-Personality".to_owned();
    package.semantic.code_objects[0].package = "frontend".to_owned();

    let report = audit_migration_package(&package);

    assert_eq!(report.visa_native_artifact_count, 0);
    assert_eq!(report.frontend_personality_artifact_count, 1);
    assert!(report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(report.warnings().any(|finding| finding.code == "missing-visa-native-consumer"));
}

#[test]
fn external_audit_requires_linked_portable_execution_chain() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.code_objects[0].artifact_id = 99;

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_undeclared_hostcall_trace_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.hostcall_trace[0].hostcall_number = 99;
    package.semantic.hostcall_trace[0].name = "visa.console.unknown".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_activation_entry_not_declared_by_artifact_export() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.activation_records[0].entry = "hidden_entry".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_denied_hostcall_trace_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.hostcall_trace[0].allowed = false;
    package.semantic.hostcall_trace[0].gate_status = "denied".to_owned();
    package.semantic.hostcall_trace[0].result = "denied".to_owned();
    package.semantic.hostcall_trace[0].ret_tag = "denied".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_failed_hostcall_trace_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.hostcall_trace[0].result = "unsupported".to_owned();
    package.semantic.hostcall_trace[0].ret_tag = "error".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_replayed_hostcall_trace_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.hostcall_trace[0].record_mode = "replay".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_code_hash_mismatch_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.code_objects[0].code_hash = "different-code-hash".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_code_hostcall_table_mismatch_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.code_objects[0].hostcalls[0].operation = "debug-write".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_code_address_map_mismatch_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.code_objects[0].address_map[0].offset = 16;

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_unbound_code_object_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.code_objects[0].bound_store = None;
    package.semantic.code_objects[0].bound_store_generation = None;

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_retired_code_object_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.code_objects[0].state = "retired".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_non_executable_text_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.code_objects[0].text_permission = "rw".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_accepts_trap_only_portable_execution_with_declared_metadata() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    convert_native_chain_to_trap_only(&mut package, 16);

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert!(report.portable_artifact_execution_claim);
    assert!(report.visa_native_portable_artifact_execution_claim);
}

#[test]
fn external_audit_rejects_synthetic_trap_only_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    convert_native_chain_to_trap_only(&mut package, 16);
    package.semantic.trap_records[0].attribution_status = "synthetic".to_owned();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_trap_only_execution_without_effect_metadata() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    convert_native_chain_to_trap_only(&mut package, 16);
    package.semantic.trap_records[0].effect.clear();

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_trap_only_execution_without_declared_metadata_match() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    convert_native_chain_to_trap_only(&mut package, 24);

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_rejects_stale_hostcall_generation_as_portable_execution() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.hostcall_trace[0].activation_generation = 2;

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert_eq!(report.visa_native_artifact_count, 1);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.visa_native_portable_artifact_execution_claim);
    assert!(
        report
            .warnings()
            .any(|finding| { finding.code == "portable-artifact-execution-incomplete" })
    );
}

#[test]
fn external_audit_accepts_tombstoned_hostcall_activation_generation() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.activation_records[0].generation = 2;
    package.semantic.tombstone_count = 1;
    package.semantic.roots.tombstone_roots =
        vec!["tombstone kind=activation id=1 generation=1 died_at=7 reason=hostcall".to_owned()];
    package.semantic.tombstones = vec![artifact_manifest::TombstoneManifest {
        kind: "activation".to_owned(),
        id: 1,
        generation: 1,
        died_at: 7,
        reason: "activation-hostcall-previous-generation".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.contract_package_valid);
    assert!(report.portable_artifact_execution_claim);
    assert!(report.visa_native_portable_artifact_execution_claim);
}

#[test]
fn external_audit_reports_real_target_claim_gaps() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(!report.ok());
    assert_eq!(report.authority_extraction_event_count, 0);
    assert_eq!(report.linked_authority_extraction_event_count, 0);
    assert!(report.errors().any(|finding| finding.code == "real-target-without-concrete-arch"));
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn external_audit_rejects_real_target_arch_mismatch() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "x86_64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:mmio:read32 requester=real-target-smoke".to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "mmio".to_owned(),
        operation: "read32".to_owned(),
        requester: Some("real-target-smoke".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: None,
        explanation: "concrete substrate extraction event".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(!report.ok());
    assert!(report.errors().any(|finding| finding.code == "real-target-arch-mismatch"));
}

#[test]
fn external_audit_rejects_real_target_unknown_arch_token() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    add_real_target_boundary_validation(&mut package);
    package.target.arch_requirement = "banana64".to_owned();
    package.required_artifact_profile.target_arch = "banana64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:ConsoleAuthority:console_write requester=native-visa"
            .to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "ConsoleAuthority".to_owned(),
        operation: "console_write".to_owned(),
        requester: Some("native-visa".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: None,
        explanation: "real target extraction with unknown arch metadata".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(!report.ok());
    assert!(report.errors().any(|finding| finding.code == "real-target-unknown-arch"));
}

#[test]
fn external_audit_rejects_generic_substrate_event_as_real_target_extraction() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots =
        vec!["substrate-event:unsupported:mmio:read32 requester=real-target-smoke".to_owned()];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "unsupported".to_owned(),
        authority: "mmio".to_owned(),
        operation: "read32".to_owned(),
        requester: Some("real-target-smoke".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: None,
        explanation: "generic substrate event is not extraction evidence".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(!report.ok());
    assert_eq!(report.authority_extraction_event_count, 0);
    assert_eq!(report.linked_authority_extraction_event_count, 0);
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn external_audit_rejects_sparse_real_target_extraction_context() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:mmio:read32 requester=real-target-smoke".to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: String::new(),
        operation: "read32".to_owned(),
        requester: None,
        artifact: Some(1),
        store: Some(1),
        capability: None,
        explanation: String::new(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(!report.ok());
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn external_audit_rejects_count_only_real_target_extraction_claim() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.substrate_boundary.active_mmio_authority_count = 1;

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(!report.ok());
    assert!(!report.replay_quiescent);
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn external_audit_rejects_unlinked_real_target_extraction_event() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:mmio:read32 requester=real-target-smoke".to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "mmio".to_owned(),
        operation: "read32".to_owned(),
        requester: Some("real-target-smoke".to_owned()),
        artifact: Some(99),
        store: Some(1),
        capability: None,
        explanation: "extraction event is not linked to executed artifact".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(!report.ok());
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn external_audit_rejects_real_target_extraction_for_unexecuted_store() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:mmio:read32 requester=real-target-smoke".to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "mmio".to_owned(),
        operation: "read32".to_owned(),
        requester: Some("real-target-smoke".to_owned()),
        artifact: Some(1),
        store: Some(99),
        capability: None,
        explanation: "extraction event names an artifact but not its executed store".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(report.portable_artifact_execution_claim);
    assert!(!report.ok());
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn external_audit_rejects_real_target_extraction_for_unmatched_hostcall() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:mmio:read32 requester=real-target-smoke".to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "mmio".to_owned(),
        operation: "read32".to_owned(),
        requester: Some("real-target-smoke".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: None,
        explanation: "extraction event names an authority not used by the console hostcall"
            .to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(report.visa_native_portable_artifact_execution_claim);
    assert!(!report.ok());
    assert_eq!(report.authority_extraction_event_count, 1);
    assert_eq!(report.linked_authority_extraction_event_count, 0);
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn external_audit_rejects_real_target_extraction_from_unverified_code_object() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();

    let mmio_hostcall = artifact_manifest::HostcallSpecManifest {
        number: 2,
        name: "visa.mmio.read32".to_owned(),
        category: "device".to_owned(),
        object: "visa.mmio".to_owned(),
        operation: "read32".to_owned(),
        may_pending: false,
    };
    let mut unverified_code = package.semantic.code_objects[0].clone();
    unverified_code.id = 2;
    unverified_code.code_hash = "not-the-artifact-code".to_owned();
    unverified_code.hostcalls = vec![mmio_hostcall.clone()];
    package.semantic.code_object_count = 2;
    package.semantic.roots.code_object_roots.push("code-object id=2".to_owned());
    package.semantic.code_objects.push(unverified_code);

    let mut unverified_activation = package.semantic.activation_records[0].clone();
    unverified_activation.id = 2;
    unverified_activation.code_object = 2;
    package.semantic.activation_record_count = 2;
    package.semantic.roots.activation_record_roots.push("activation id=2".to_owned());
    package.semantic.activation_records.push(unverified_activation);

    package.semantic.hostcall_trace_count = 2;
    package.semantic.roots.hostcall_trace_roots.push("hostcall id=2".to_owned());
    package.semantic.hostcall_trace.push(artifact_manifest::HostcallTraceManifest {
        id: 2,
        generation: 1,
        activation: 2,
        activation_generation: 1,
        store: 1,
        store_generation: 1,
        code_object: 2,
        code_generation: 1,
        artifact: 1,
        hostcall_number: 2,
        name: "visa.mmio.read32".to_owned(),
        category: "device".to_owned(),
        subject: "native-visa".to_owned(),
        subject_source: "active-state".to_owned(),
        object: "visa.mmio".to_owned(),
        operation: "read32".to_owned(),
        record_mode: "live".to_owned(),
        allowed: true,
        gate_status: "allowed".to_owned(),
        result: "ok".to_owned(),
        ret_tag: "ok".to_owned(),
        ..Default::default()
    });

    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:MmioAuthority:mmio_read32 requester=native-visa"
            .to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "MmioAuthority".to_owned(),
        operation: "mmio_read32".to_owned(),
        requester: Some("native-visa".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: None,
        explanation: "extraction event follows a hostcall on an unverified code object".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(report.portable_artifact_execution_claim);
    assert!(report.visa_native_portable_artifact_execution_claim);
    assert!(!report.ok());
    assert_eq!(report.authority_extraction_event_count, 1);
    assert_eq!(report.linked_authority_extraction_event_count, 0);
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn external_audit_rejects_real_target_extraction_requester_subject_mismatch() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.hostcall_trace[0].subject = "native-visa".to_owned();
    package.semantic.hostcall_trace[0].subject_source = "active-state".to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:ConsoleAuthority:console_write requester=other-subject"
            .to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "ConsoleAuthority".to_owned(),
        operation: "console_write".to_owned(),
        requester: Some("other-subject".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: None,
        explanation: "extraction event requester does not match the hostcall subject".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(report.portable_artifact_execution_claim);
    assert!(report.visa_native_portable_artifact_execution_claim);
    assert!(!report.ok());
    assert_eq!(report.authority_extraction_event_count, 1);
    assert_eq!(report.linked_authority_extraction_event_count, 0);
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn external_audit_rejects_real_target_claim_with_only_portable_boundary_validation() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:ConsoleAuthority:console_write requester=native-visa"
            .to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "ConsoleAuthority".to_owned(),
        operation: "console_write".to_owned(),
        requester: Some("native-visa".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: None,
        explanation: "real target extraction with only portable boundary validation".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(report.portable_artifact_execution_claim);
    assert!(report.visa_native_portable_artifact_execution_claim);
    assert_eq!(report.linked_authority_extraction_event_count, 1);
    assert!(!report.ok());
    assert!(
        report.errors().any(|finding| finding.code == "real-target-without-boundary-validation")
    );
}

#[test]
fn external_audit_rejects_real_target_without_linked_portable_chain() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    package.semantic.activation_records[0].code_object = 99;
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:mmio:read32 requester=real-target-smoke".to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "mmio".to_owned(),
        operation: "read32".to_owned(),
        requester: Some("real-target-smoke".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: None,
        explanation: "real target extraction without linked portable chain".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert!(!report.portable_artifact_execution_claim);
    assert!(!report.ok());
    assert!(
        report
            .errors()
            .any(|finding| { finding.code == "real-target-without-portable-artifact-chain" })
    );
}

#[test]
fn external_audit_accepts_real_target_claim_with_concrete_arch_and_extraction_event() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    add_real_target_boundary_validation(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:ConsoleAuthority:console_write requester=native-visa"
            .to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "ConsoleAuthority".to_owned(),
        operation: "console_write".to_owned(),
        requester: Some("native-visa".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: None,
        explanation: "concrete substrate extraction event for the linked console hostcall"
            .to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.ok(), "{:#?}", report.findings);
    assert!(report.real_target_substrate_claim);
    assert!(report.visa_native_portable_artifact_execution_claim);
    assert_eq!(report.authority_extraction_event_count, 1);
    assert_eq!(report.linked_authority_extraction_event_count, 1);
    assert!(report.errors().next().is_none());
}

#[test]
fn external_audit_rejects_real_target_extraction_capability_not_consumed_by_hostcall() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    add_real_target_boundary_validation(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:ConsoleAuthority:console_write requester=native-visa"
            .to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "ConsoleAuthority".to_owned(),
        operation: "console_write".to_owned(),
        requester: Some("native-visa".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: Some(artifact_manifest::CapabilityHandleArgManifest {
            id: 99,
            object: "visa.timer".to_owned(),
            generation: 7,
            rights: vec!["now".to_owned()],
            ..Default::default()
        }),
        explanation: "real target extraction event claims a capability not consumed by hostcall"
            .to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert_eq!(report.authority_extraction_event_count, 1);
    assert_eq!(report.linked_authority_extraction_event_count, 0);
    assert!(!report.ok());
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn external_audit_rejects_real_target_extraction_with_unbacked_hostcall_capability() {
    let mut package = minimal_migration_package();
    add_native_portable_execution_chain(&mut package);
    add_real_target_boundary_validation(&mut package);
    package.target.arch_requirement = "riscv64".to_owned();
    package.required_artifact_profile.target_arch = "riscv64".to_owned();
    package.substrate_boundary.native_state_policy = REAL_TARGET_SUBSTRATE_POLICY.to_owned();
    package.semantic.hostcall_trace[0].cap_args =
        vec![artifact_manifest::CapabilityHandleArgManifest {
            id: 42,
            object: "visa.timer".to_owned(),
            generation: 3,
            rights: vec!["now".to_owned()],
            ..Default::default()
        }];
    package.semantic.substrate_event_count = 1;
    package.semantic.roots.substrate_event_roots = vec![
        "substrate-event:authority-extracted:ConsoleAuthority:console_write requester=native-visa"
            .to_owned(),
    ];
    package.semantic.substrate_events = vec![SubstrateEventManifest {
        id: 1,
        epoch: 1,
        event_kind: "authority-extracted".to_owned(),
        authority: "ConsoleAuthority".to_owned(),
        operation: "console_write".to_owned(),
        requester: Some("native-visa".to_owned()),
        artifact: Some(1),
        store: Some(1),
        capability: Some(artifact_manifest::CapabilityHandleArgManifest {
            id: 42,
            object: "visa.timer".to_owned(),
            generation: 3,
            rights: vec!["now".to_owned()],
            ..Default::default()
        }),
        explanation: "real target extraction event uses an unbacked hostcall capability".to_owned(),
    }];

    let report = audit_migration_package(&package);

    assert!(report.real_target_substrate_claim);
    assert_eq!(report.authority_extraction_event_count, 1);
    assert_eq!(report.linked_authority_extraction_event_count, 0);
    assert!(!report.ok());
    assert!(report.errors().any(|finding| finding.code == "real-target-without-extraction-events"));
}

#[test]
fn migration_package_rejects_unknown_snapshot_evidence_boundary() {
    let mut package = minimal_migration_package();
    package.semantic.snapshot_validation = BoundaryValidationReportManifest {
        validator: "snapshot-barrier".to_owned(),
        evidence_boundary: "host-side".to_owned(),
        ok: true,
        violation_count: 0,
        violations: Vec::new(),
    };
    package.semantic.roots.snapshot_validation_roots = vec![
        "boundary-validation validator=snapshot-barrier evidence=host-side ok=true violations=0"
            .to_owned(),
    ];

    let err = validate_migration_package(&package).expect_err("unknown boundary must fail");
    assert_eq!(err.to_string(), "snapshot validation evidence boundary is missing or unknown");
}

#[test]
fn migration_package_rejects_snapshot_evidence_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.snapshot_validation = BoundaryValidationReportManifest {
        validator: "snapshot-barrier".to_owned(),
        evidence_boundary: EvidenceBoundaryLevel::SemanticModel.as_str().to_owned(),
        ok: true,
        violation_count: 0,
        violations: Vec::new(),
    };
    package.semantic.roots.snapshot_validation_roots =
        vec!["boundary-validation validator=snapshot-barrier ok=true violations=0".to_owned()];

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "snapshot validation root evidence boundary mismatch");
}

#[test]
fn migration_package_rejects_boundary_validation_ok_with_violations() {
    let mut package = minimal_migration_package();
    package.semantic.snapshot_validation_violation_count = 1;
    package.semantic.snapshot_validation = BoundaryValidationReportManifest {
        validator: "snapshot-barrier".to_owned(),
        evidence_boundary: EvidenceBoundaryLevel::SemanticModel.as_str().to_owned(),
        ok: true,
        violation_count: 1,
        violations: vec![BoundaryValidationViolationManifest {
            validator: "snapshot-barrier".to_owned(),
            kind: "dangling-edge".to_owned(),
            object: "edge:1".to_owned(),
            detail: "test violation".to_owned(),
        }],
    };
    package.semantic.roots.snapshot_validation_roots = vec![format!(
        "boundary-validation validator=snapshot-barrier evidence={} ok=true violations=1",
        EvidenceBoundaryLevel::SemanticModel.as_str()
    )];

    let err = validate_migration_package(&package).expect_err("ok with violations must fail");
    assert_eq!(err.to_string(), "snapshot validation ok flag disagrees with violations");
}

#[test]
fn migration_package_rejects_boundary_validation_summary_status_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.snapshot_validation = BoundaryValidationReportManifest {
        validator: "snapshot-barrier".to_owned(),
        evidence_boundary: EvidenceBoundaryLevel::SemanticModel.as_str().to_owned(),
        ok: true,
        violation_count: 0,
        violations: Vec::new(),
    };
    package.semantic.roots.snapshot_validation_roots = vec![format!(
        "boundary-validation validator=snapshot-barrier evidence={} ok=false violations=0",
        EvidenceBoundaryLevel::SemanticModel.as_str()
    )];

    let err = validate_migration_package(&package).expect_err("summary mismatch must fail");
    assert_eq!(err.to_string(), "snapshot validation root summary mismatch");
}

#[test]
fn migration_package_rejects_missing_boundary_violation_root() {
    let mut package = minimal_migration_package();
    package.semantic.snapshot_validation_violation_count = 1;
    package.semantic.snapshot_validation = BoundaryValidationReportManifest {
        validator: "snapshot-barrier".to_owned(),
        evidence_boundary: EvidenceBoundaryLevel::SemanticModel.as_str().to_owned(),
        ok: false,
        violation_count: 1,
        violations: vec![BoundaryValidationViolationManifest {
            validator: "snapshot-barrier".to_owned(),
            kind: "dangling-edge".to_owned(),
            object: "edge:1".to_owned(),
            detail: "test violation".to_owned(),
        }],
    };
    package.semantic.roots.snapshot_validation_roots = vec![format!(
        "boundary-validation validator=snapshot-barrier evidence={} ok=false violations=1",
        EvidenceBoundaryLevel::SemanticModel.as_str()
    )];

    let err = validate_migration_package(&package).expect_err("missing violation root must fail");
    assert_eq!(err.to_string(), "snapshot validation root/count mismatch");
}

#[test]
fn migration_package_rejects_boundary_violation_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.snapshot_validation_violation_count = 1;
    package.semantic.snapshot_validation = BoundaryValidationReportManifest {
        validator: "snapshot-barrier".to_owned(),
        evidence_boundary: EvidenceBoundaryLevel::SemanticModel.as_str().to_owned(),
        ok: false,
        violation_count: 1,
        violations: vec![BoundaryValidationViolationManifest {
            validator: "snapshot-barrier".to_owned(),
            kind: "dangling-edge".to_owned(),
            object: "edge:1".to_owned(),
            detail: "test violation".to_owned(),
        }],
    };
    package.semantic.roots.snapshot_validation_roots = vec![
        format!(
            "boundary-validation validator=snapshot-barrier evidence={} ok=false violations=1",
            EvidenceBoundaryLevel::SemanticModel.as_str()
        ),
        "boundary-validation validator=snapshot-barrier kind=dangling-edge object=edge:1 detail=different"
            .to_owned(),
    ];

    let err = validate_migration_package(&package).expect_err("violation root mismatch must fail");
    assert_eq!(err.to_string(), "snapshot validation violation root mismatch");
}

mod compatibility;
mod manifest_validation;
mod object_refs;
mod roots_block_activation;
mod roots_block_fs;
mod roots_device_io;
mod roots_network_runtime;
mod roots_network_storage;
mod roots_scheduler_smp;
mod roots_simd_display;
