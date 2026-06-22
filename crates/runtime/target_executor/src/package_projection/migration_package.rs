use super::super::*;

pub(crate) fn prepare_migration_package(
    artifact_root: &Path,
    migration_path: Option<PathBuf>,
    manifest: &ArtifactBundleManifest,
    semantic: &SemanticGraph,
    target_v1: &TargetExecutorV1Report,
) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = migration_path {
        return Ok(path);
    }

    let path = artifact_root.join("semantic-package-v1.json");
    semantic
        .check_invariants()
        .map_err(|error| format!("semantic invariant failed before package write: {error:?}"))?;
    let package = demo_migration_package(manifest, semantic, target_v1);
    fs::write(&path, serde_json::to_vec_pretty(&package)?)?;
    Ok(path)
}

pub(crate) fn demo_migration_package(
    manifest: &ArtifactBundleManifest,
    semantic: &SemanticGraph,
    target_v1: &TargetExecutorV1Report,
) -> MigrationPackageManifest {
    let logical_capabilities = semantic
        .capabilities()
        .records()
        .iter()
        .map(|capability| MigrationCapabilityManifest {
            subject: capability.subject.clone(),
            object: capability.object.clone(),
            rights: capability.operations.as_slice().to_vec(),
            lifetime: capability.lifetime.clone(),
            class: capability.class.as_str().to_owned(),
            source: capability.source.clone(),
            owner_store: capability.owner_store,
            owner_store_generation: capability.owner_store_generation,
            owner_task: capability.owner_task.map(u64::from),
            generation: capability.generation,
            revoked: capability.revoked,
        })
        .collect::<Vec<_>>();
    let capability_count = logical_capabilities.len();
    let wait_records = target_v1
        .wait_records
        .iter()
        .cloned()
        .chain(semantic.wait_records().iter().map(wait_record_manifest))
        .collect::<Vec<_>>();
    let roots = semantic_roots(&logical_capabilities, semantic, target_v1);
    MigrationPackageManifest {
        schema_version: 1,
        package_format: "visa-semantic-package-v1".to_owned(),
        package_id: "target-executor-semantic-package-v1".to_owned(),
        source: MigrationHostManifest { arch: "x86_64".to_owned() },
        target: MigrationTargetManifest { arch_requirement: "target-native".to_owned() },
        required_artifact_profile: RequiredArtifactProfileManifest {
            artifact_profile: manifest.artifact_profile.clone(),
            target_arch: "target-native".to_owned(),
            machine_abi_version: manifest.target.machine_abi_version.clone(),
            supervisor_abi_version: manifest.target.supervisor_abi_version.clone(),
            wasm_feature_profile: manifest.target.wasm_feature_profile.clone(),
            memory64: manifest.target.memory64,
            multi_memory: manifest.target.multi_memory,
            dmw_layout: manifest.target.dmw_layout.clone(),
            network_contract_version: manifest.target.network_contract_version.clone(),
            compiler_engine: manifest.compiler.engine.clone(),
            compiler_execution_mode: manifest.compiler.execution_mode.clone(),
            artifact_format: manifest.compiler.artifact_format.clone(),
            runtime_executor_abi: manifest.compiler.runtime_executor_abi.clone(),
        },
        guest: GuestStateManifest {
            canonical_isa: "riscv64".to_owned(),
            register_count: 33,
            memory_page_count: semantic.page_object_count() as u64,
            vma_count: semantic.vma_region_count() as u32,
            signal_queue_count: 0,
            note: "host-side package proving cross-ISA restore/rebind boundaries".to_owned(),
        },
        semantic: SemanticSnapshotManifest {
            barrier_id: 1,
            event_log_cursor: semantic.event_log().cursor(),
            roots,
            pending_wait_count: semantic.pending_wait_count(),
            hart_count: semantic.hart_count(),
            task_count: semantic.task_count(),
            task_record_count: semantic.tasks().len(),
            runtime_activation_count: semantic.runtime_activation_count(),
            runnable_queue_count: semantic.runnable_queue_count(),
            activation_context_count: semantic.activation_context_count(),
            saved_context_count: semantic.saved_context_count(),
            timer_interrupt_count: semantic.timer_interrupt_count(),
            ipi_event_count: semantic.ipi_event_count(),
            remote_preempt_count: semantic.remote_preempt_count(),
            remote_park_count: semantic.remote_park_count(),
            preemption_count: semantic.preemption_count(),
            scheduler_decision_count: semantic.scheduler_decision_count(),
            cross_hart_scheduler_decision_count: semantic.cross_hart_scheduler_decision_count(),
            activation_migration_count: semantic.activation_migration_count(),
            smp_safe_point_count: semantic.smp_safe_point_count(),
            stop_the_world_rendezvous_count: semantic.stop_the_world_rendezvous_count(),
            smp_code_publish_barrier_count: semantic.smp_code_publish_barrier_count(),
            smp_cleanup_quiescence_count: semantic.smp_cleanup_quiescence_count(),
            smp_snapshot_barrier_count: semantic.smp_snapshot_barrier_count(),
            smp_stress_run_count: semantic.smp_stress_run_count(),
            smp_scaling_benchmark_count: semantic.smp_scaling_benchmark_count(),
            integrated_smp_preemption_cleanup_count: semantic
                .integrated_smp_preemption_cleanup_count(),
            integrated_smp_network_fault_count: semantic.integrated_smp_network_fault_count(),
            integrated_disk_preempt_fault_count: semantic.integrated_disk_preempt_fault_count(),
            integrated_simd_migration_count: semantic.integrated_simd_migration_count(),
            integrated_network_disk_io_count: semantic.integrated_network_disk_io_count(),
            integrated_display_scheduler_load_count: semantic
                .integrated_display_scheduler_load_count(),
            integrated_snapshot_io_lease_barrier_count: semantic
                .integrated_snapshot_io_lease_barrier_count(),
            integrated_code_publish_smp_workload_count: semantic
                .integrated_code_publish_smp_workload_count(),
            integrated_display_panic_count: semantic.integrated_display_panic_count(),
            integrated_osctl_trace_replay_count: semantic.integrated_osctl_trace_replay_count(),
            device_object_count: semantic.device_object_count(),
            queue_object_count: semantic.queue_object_count(),
            descriptor_object_count: semantic.descriptor_object_count(),
            dma_buffer_object_count: semantic.dma_buffer_object_count(),
            mmio_region_object_count: semantic.mmio_region_object_count(),
            irq_line_object_count: semantic.irq_line_object_count(),
            irq_event_count: semantic.irq_event_count(),
            device_capability_count: semantic.device_capability_count(),
            driver_store_binding_count: semantic.driver_store_binding_count(),
            io_wait_count: semantic.io_wait_count(),
            io_cleanup_count: semantic.io_cleanup_count(),
            io_fault_injection_count: semantic.io_fault_injection_count(),
            io_validation_report_count: semantic.io_validation_report_count(),
            packet_device_object_count: semantic.packet_device_object_count(),
            packet_buffer_object_count: semantic.packet_buffer_object_count(),
            packet_queue_object_count: semantic.packet_queue_object_count(),
            packet_descriptor_object_count: semantic.packet_descriptor_object_count(),
            fake_net_backend_object_count: semantic.fake_net_backend_object_count(),
            virtio_net_backend_object_count: semantic.virtio_net_backend_object_count(),
            network_rx_interrupt_count: semantic.network_rx_interrupt_count(),
            network_rx_wait_resolution_count: semantic.network_rx_wait_resolution_count(),
            network_tx_capability_gate_count: semantic.network_tx_capability_gate_count(),
            network_tx_completion_count: semantic.network_tx_completion_count(),
            network_stack_adapter_count: semantic.network_stack_adapter_count(),
            socket_object_count: semantic.socket_object_count(),
            endpoint_object_count: semantic.endpoint_object_count(),
            socket_operation_count: semantic.socket_operation_count(),
            socket_wait_count: semantic.socket_wait_count(),
            network_backpressure_count: semantic.network_backpressure_count(),
            network_driver_cleanup_count: semantic.network_driver_cleanup_count(),
            network_generation_audit_count: semantic.network_generation_audit_count(),
            network_fault_injection_count: semantic.network_fault_injection_count(),
            network_benchmark_count: semantic.network_benchmark_count(),
            network_recovery_benchmark_count: semantic.network_recovery_benchmark_count(),
            block_device_object_count: semantic.block_device_object_count(),
            block_range_object_count: semantic.block_range_object_count(),
            block_request_object_count: semantic.block_request_object_count(),
            block_completion_object_count: semantic.block_completion_object_count(),
            block_wait_count: semantic.block_wait_count(),
            fake_block_backend_object_count: semantic.fake_block_backend_object_count(),
            virtio_blk_backend_object_count: semantic.virtio_blk_backend_object_count(),
            block_read_path_count: semantic.block_read_path_count(),
            block_write_path_count: semantic.block_write_path_count(),
            block_request_queue_count: semantic.block_request_queue_count(),
            block_dma_buffer_count: semantic.block_dma_buffer_count(),
            block_page_object_count: semantic.block_page_object_count(),
            guest_address_space_count: semantic.guest_address_space_count(),
            vma_region_count: semantic.vma_region_count(),
            page_object_count: semantic.page_object_count(),
            guest_memory_fault_count: semantic.guest_memory_fault_count(),
            buffer_cache_object_count: semantic.buffer_cache_object_count(),
            file_object_count: semantic.file_object_count(),
            directory_object_count: semantic.directory_object_count(),
            fat_adapter_object_count: semantic.fat_adapter_object_count(),
            ext4_adapter_object_count: semantic.ext4_adapter_object_count(),
            file_handle_capability_count: semantic.file_handle_capability_count(),
            fs_wait_count: semantic.fs_wait_count(),
            block_driver_cleanup_count: semantic.block_driver_cleanup_count(),
            block_pending_io_policy_count: semantic.block_pending_io_policy_count(),
            block_request_generation_audit_count: semantic.block_request_generation_audit_count(),
            block_benchmark_count: semantic.block_benchmark_count(),
            block_recovery_benchmark_count: semantic.block_recovery_benchmark_count(),
            target_feature_set_count: semantic.target_feature_set_count(),
            vector_state_count: semantic.vector_state_count(),
            simd_fault_injection_count: semantic.simd_fault_injection_count(),
            simd_benchmark_count: semantic.simd_benchmark_count(),
            simd_context_switch_benchmark_count: semantic.simd_context_switch_benchmark_count(),
            framebuffer_object_count: semantic.framebuffer_object_count(),
            display_object_count: semantic.display_object_count(),
            display_capability_count: semantic.display_capability_count(),
            framebuffer_window_lease_count: semantic.framebuffer_window_lease_count(),
            framebuffer_mapping_count: semantic.framebuffer_mapping_count(),
            framebuffer_write_count: semantic.framebuffer_write_count(),
            framebuffer_flush_region_count: semantic.framebuffer_flush_region_count(),
            framebuffer_dirty_region_count: semantic.framebuffer_dirty_region_count(),
            display_event_log_count: semantic.display_event_log_count(),
            display_cleanup_count: semantic.display_cleanup_count(),
            display_snapshot_barrier_count: semantic.display_snapshot_barrier_count(),
            display_panic_last_frame_count: semantic.display_panic_last_frame_count(),
            framebuffer_benchmark_count: semantic.framebuffer_benchmark_count(),
            activation_resume_count: semantic.activation_resume_count(),
            activation_wait_count: semantic.activation_wait_count(),
            activation_cleanup_count: semantic.activation_cleanup_count(),
            preemption_latency_sample_count: semantic.preemption_latency_sample_count(),
            hart_event_attribution_count: semantic.hart_event_attribution_count(),
            resource_count: semantic.resource_count(),
            authority_count: semantic.authority_count(),
            active_authority_count: semantic.active_authority_count(),
            wait_token_count: wait_records.len(),
            wait_record_count: wait_records.len(),
            capability_count,
            capability_record_count: target_v1.capability_records.len(),
            fault_domain_count: semantic.fault_domain_count(),
            store_count: semantic.store_count(),
            store_record_count: target_v1.store_records.len(),
            transaction_count: 0,
            active_transaction_count: 0,
            fast_path_plan_count: semantic.fast_path_plan_count(),
            active_fast_path_plan_count: semantic.active_fast_path_plan_count(),
            boundary_count: semantic.boundary_count(),
            artifact_verification_count: semantic.artifact_verification_count(),
            store_activation_count: semantic.store_activation_count(),
            executor_transition_count: semantic.store_executor_transition_count(),
            target_artifact_count: target_v1.target_artifacts.len(),
            code_object_count: target_v1.code_objects.len(),
            activation_record_count: target_v1.activation_records.len(),
            trap_record_count: target_v1.trap_records.len(),
            hostcall_trace_count: target_v1.hostcall_trace.len(),
            migration_object_count: target_v1.migration_objects.len(),
            tombstone_count: target_v1.tombstones.len(),
            contract_violation_count: target_v1.contract_violations.len(),
            cleanup_transaction_count: target_v1.cleanup_transactions.len(),
            memory_policy_count: target_v1.memory_policies.len(),
            snapshot_validation_violation_count: target_v1.snapshot_validation.violation_count,
            replay_validation_violation_count: target_v1.replay_validation.violation_count,
            substrate_event_count: target_v1.substrate_events.len(),
            profile_gate_event_count: target_v1.profile_gate_events.len(),
            command_result_count: target_v1.command_results.len(),
            interface_event_count: target_v1.interface_events.len(),
            target_artifacts: target_v1.target_artifacts.clone(),
            hart_records: semantic.harts().iter().map(hart_record_manifest).collect(),
            task_records: semantic.tasks().iter().map(task_record_manifest).collect(),
            runtime_activation_records: semantic
                .runtime_activations()
                .iter()
                .map(runtime_activation_record_manifest)
                .collect(),
            runnable_queues: semantic
                .runnable_queues()
                .iter()
                .map(runnable_queue_manifest)
                .collect(),
            activation_contexts: semantic
                .activation_contexts()
                .iter()
                .map(activation_context_manifest)
                .collect(),
            saved_contexts: semantic.saved_contexts().iter().map(saved_context_manifest).collect(),
            timer_interrupts: semantic
                .timer_interrupts()
                .iter()
                .map(timer_interrupt_manifest)
                .collect(),
            ipi_events: semantic.ipi_events().iter().map(ipi_event_manifest).collect(),
            remote_preempts: semantic
                .remote_preempts()
                .iter()
                .map(remote_preempt_manifest)
                .collect(),
            remote_parks: semantic.remote_parks().iter().map(remote_park_manifest).collect(),
            preemptions: semantic.preemptions().iter().map(preemption_manifest).collect(),
            scheduler_decisions: semantic
                .scheduler_decisions()
                .iter()
                .map(scheduler_decision_manifest)
                .collect(),
            cross_hart_scheduler_decisions: semantic
                .cross_hart_scheduler_decisions()
                .iter()
                .map(cross_hart_scheduler_decision_manifest)
                .collect(),
            activation_migrations: semantic
                .activation_migrations()
                .iter()
                .map(activation_migration_manifest)
                .collect(),
            smp_safe_points: semantic
                .smp_safe_points()
                .iter()
                .map(smp_safe_point_manifest)
                .collect(),
            stop_the_world_rendezvous: semantic
                .stop_the_world_rendezvous()
                .iter()
                .map(stop_the_world_rendezvous_manifest)
                .collect(),
            smp_code_publish_barriers: semantic
                .smp_code_publish_barriers()
                .iter()
                .map(smp_code_publish_barrier_manifest)
                .collect(),
            smp_cleanup_quiescence: semantic
                .smp_cleanup_quiescence()
                .iter()
                .map(smp_cleanup_quiescence_manifest)
                .collect(),
            smp_snapshot_barriers: semantic
                .smp_snapshot_barriers()
                .iter()
                .map(smp_snapshot_barrier_manifest)
                .collect(),
            smp_stress_runs: semantic
                .smp_stress_runs()
                .iter()
                .map(smp_stress_run_manifest)
                .collect(),
            smp_scaling_benchmarks: semantic
                .smp_scaling_benchmarks()
                .iter()
                .map(smp_scaling_benchmark_manifest)
                .collect(),
            integrated_smp_preemption_cleanups: semantic
                .integrated_smp_preemption_cleanups()
                .iter()
                .map(integrated_smp_preemption_cleanup_manifest)
                .collect(),
            integrated_smp_network_faults: semantic
                .integrated_smp_network_faults()
                .iter()
                .map(integrated_smp_network_fault_manifest)
                .collect(),
            integrated_disk_preempt_faults: semantic
                .integrated_disk_preempt_faults()
                .iter()
                .map(integrated_disk_preempt_fault_manifest)
                .collect(),
            integrated_simd_migrations: semantic
                .integrated_simd_migrations()
                .iter()
                .map(integrated_simd_migration_manifest)
                .collect(),
            integrated_network_disk_ios: semantic
                .integrated_network_disk_ios()
                .iter()
                .map(integrated_network_disk_io_manifest)
                .collect(),
            integrated_display_scheduler_loads: semantic
                .integrated_display_scheduler_loads()
                .iter()
                .map(integrated_display_scheduler_load_manifest)
                .collect(),
            integrated_snapshot_io_lease_barriers: semantic
                .integrated_snapshot_io_lease_barriers()
                .iter()
                .map(integrated_snapshot_io_lease_barrier_manifest)
                .collect(),
            integrated_code_publish_smp_workloads: semantic
                .integrated_code_publish_smp_workloads()
                .iter()
                .map(integrated_code_publish_smp_workload_manifest)
                .collect(),
            integrated_display_panics: semantic
                .integrated_display_panics()
                .iter()
                .map(integrated_display_panic_manifest)
                .collect(),
            integrated_osctl_trace_replays: semantic
                .integrated_osctl_trace_replays()
                .iter()
                .map(integrated_osctl_trace_replay_manifest)
                .collect(),
            device_objects: semantic.device_objects().iter().map(device_object_manifest).collect(),
            queue_objects: semantic.queue_objects().iter().map(queue_object_manifest).collect(),
            descriptor_objects: semantic
                .descriptor_objects()
                .iter()
                .map(descriptor_object_manifest)
                .collect(),
            dma_buffer_objects: semantic
                .dma_buffer_objects()
                .iter()
                .map(dma_buffer_object_manifest)
                .collect(),
            mmio_region_objects: semantic
                .mmio_region_objects()
                .iter()
                .map(mmio_region_object_manifest)
                .collect(),
            irq_line_objects: semantic
                .irq_line_objects()
                .iter()
                .map(irq_line_object_manifest)
                .collect(),
            irq_events: semantic.irq_events().iter().map(irq_event_manifest).collect(),
            device_capabilities: semantic
                .device_capabilities()
                .iter()
                .map(device_capability_manifest)
                .collect(),
            driver_store_bindings: semantic
                .driver_store_bindings()
                .iter()
                .map(driver_store_binding_manifest)
                .collect(),
            io_waits: semantic.io_waits().iter().map(io_wait_manifest).collect(),
            io_cleanups: semantic.io_cleanups().iter().map(io_cleanup_manifest).collect(),
            io_fault_injections: semantic
                .io_fault_injections()
                .iter()
                .map(io_fault_injection_manifest)
                .collect(),
            io_validation_reports: semantic
                .io_validation_reports()
                .iter()
                .map(io_validation_report_manifest)
                .collect(),
            packet_device_objects: semantic
                .packet_device_objects()
                .iter()
                .map(packet_device_object_manifest)
                .collect(),
            packet_buffer_objects: semantic
                .packet_buffer_objects()
                .iter()
                .map(packet_buffer_object_manifest)
                .collect(),
            packet_queue_objects: semantic
                .packet_queue_objects()
                .iter()
                .map(packet_queue_object_manifest)
                .collect(),
            packet_descriptors: semantic
                .packet_descriptors()
                .iter()
                .map(packet_descriptor_object_manifest)
                .collect(),
            fake_net_backends: semantic
                .fake_net_backends()
                .iter()
                .map(fake_net_backend_object_manifest)
                .collect(),
            virtio_net_backends: semantic
                .virtio_net_backends()
                .iter()
                .map(virtio_net_backend_object_manifest)
                .collect(),
            network_rx_interrupts: semantic
                .network_rx_interrupts()
                .iter()
                .map(network_rx_interrupt_manifest)
                .collect(),
            network_rx_wait_resolutions: semantic
                .network_rx_wait_resolutions()
                .iter()
                .map(network_rx_wait_resolution_manifest)
                .collect(),
            network_tx_capability_gates: semantic
                .network_tx_capability_gates()
                .iter()
                .map(network_tx_capability_gate_manifest)
                .collect(),
            network_tx_completions: semantic
                .network_tx_completions()
                .iter()
                .map(network_tx_completion_manifest)
                .collect(),
            network_stack_adapters: semantic
                .network_stack_adapters()
                .iter()
                .map(network_stack_adapter_manifest)
                .collect(),
            socket_objects: semantic.socket_objects().iter().map(socket_object_manifest).collect(),
            endpoint_objects: semantic
                .endpoint_objects()
                .iter()
                .map(endpoint_object_manifest)
                .collect(),
            socket_operations: semantic
                .socket_operations()
                .iter()
                .map(socket_operation_manifest)
                .collect(),
            socket_waits: semantic.socket_waits().iter().map(socket_wait_manifest).collect(),
            network_backpressures: semantic
                .network_backpressures()
                .iter()
                .map(network_backpressure_manifest)
                .collect(),
            network_driver_cleanups: semantic
                .network_driver_cleanups()
                .iter()
                .map(network_driver_cleanup_manifest)
                .collect(),
            network_generation_audits: semantic
                .network_generation_audits()
                .iter()
                .map(network_generation_audit_manifest)
                .collect(),
            network_fault_injections: semantic
                .network_fault_injections()
                .iter()
                .map(network_fault_injection_manifest)
                .collect(),
            network_benchmarks: semantic
                .network_benchmarks()
                .iter()
                .map(network_benchmark_manifest)
                .collect(),
            network_recovery_benchmarks: semantic
                .network_recovery_benchmarks()
                .iter()
                .map(network_recovery_benchmark_manifest)
                .collect(),
            block_device_objects: semantic
                .block_device_objects()
                .iter()
                .map(block_device_object_manifest)
                .collect(),
            block_range_objects: semantic
                .block_range_objects()
                .iter()
                .map(block_range_object_manifest)
                .collect(),
            block_request_objects: semantic
                .block_request_objects()
                .iter()
                .map(block_request_object_manifest)
                .collect(),
            block_completion_objects: semantic
                .block_completion_objects()
                .iter()
                .map(block_completion_object_manifest)
                .collect(),
            block_waits: semantic.block_waits().iter().map(block_wait_manifest).collect(),
            fake_block_backends: semantic
                .fake_block_backends()
                .iter()
                .map(fake_block_backend_object_manifest)
                .collect(),
            virtio_blk_backends: semantic
                .virtio_blk_backends()
                .iter()
                .map(virtio_blk_backend_object_manifest)
                .collect(),
            block_read_paths: semantic
                .block_read_paths()
                .iter()
                .map(block_read_path_manifest)
                .collect(),
            block_write_paths: semantic
                .block_write_paths()
                .iter()
                .map(block_write_path_manifest)
                .collect(),
            block_request_queues: semantic
                .block_request_queues()
                .iter()
                .map(block_request_queue_manifest)
                .collect(),
            block_dma_buffers: semantic
                .block_dma_buffers()
                .iter()
                .map(block_dma_buffer_manifest)
                .collect(),
            block_page_objects: semantic
                .block_page_objects()
                .iter()
                .map(block_page_object_manifest)
                .collect(),
            guest_address_spaces: semantic
                .guest_address_spaces()
                .iter()
                .map(guest_address_space_manifest)
                .collect(),
            vma_regions: semantic.vma_regions().iter().map(vma_region_manifest).collect(),
            page_objects: semantic.page_objects().iter().map(page_object_manifest).collect(),
            guest_memory_faults: semantic
                .guest_memory_faults()
                .iter()
                .map(guest_memory_fault_manifest)
                .collect(),
            buffer_cache_objects: semantic
                .buffer_cache_objects()
                .iter()
                .map(buffer_cache_object_manifest)
                .collect(),
            file_objects: semantic.file_objects().iter().map(file_object_manifest).collect(),
            directory_objects: semantic
                .directory_objects()
                .iter()
                .map(directory_object_manifest)
                .collect(),
            fat_adapter_objects: semantic
                .fat_adapter_objects()
                .iter()
                .map(fat_adapter_object_manifest)
                .collect(),
            ext4_adapter_objects: semantic
                .ext4_adapter_objects()
                .iter()
                .map(ext4_adapter_object_manifest)
                .collect(),
            file_handle_capabilities: semantic
                .file_handle_capabilities()
                .iter()
                .map(file_handle_capability_manifest)
                .collect(),
            fs_waits: semantic.fs_waits().iter().map(fs_wait_manifest).collect(),
            block_driver_cleanups: semantic
                .block_driver_cleanups()
                .iter()
                .map(block_driver_cleanup_manifest)
                .collect(),
            block_pending_io_policies: semantic
                .block_pending_io_policies()
                .iter()
                .map(block_pending_io_policy_manifest)
                .collect(),
            block_request_generation_audits: semantic
                .block_request_generation_audits()
                .iter()
                .map(block_request_generation_audit_manifest)
                .collect(),
            block_benchmarks: semantic
                .block_benchmarks()
                .iter()
                .map(block_benchmark_manifest)
                .collect(),
            block_recovery_benchmarks: semantic
                .block_recovery_benchmarks()
                .iter()
                .map(block_recovery_benchmark_manifest)
                .collect(),
            target_feature_sets: semantic
                .target_feature_sets()
                .iter()
                .map(target_feature_set_manifest)
                .collect(),
            vector_states: semantic.vector_states().iter().map(vector_state_manifest).collect(),
            simd_fault_injections: semantic
                .simd_fault_injections()
                .iter()
                .map(simd_fault_injection_manifest)
                .collect(),
            simd_benchmarks: semantic
                .simd_benchmarks()
                .iter()
                .map(simd_benchmark_manifest)
                .collect(),
            simd_context_switch_benchmarks: semantic
                .simd_context_switch_benchmarks()
                .iter()
                .map(simd_context_switch_benchmark_manifest)
                .collect(),
            framebuffer_objects: semantic
                .framebuffer_objects()
                .iter()
                .map(framebuffer_object_manifest)
                .collect(),
            display_objects: semantic
                .display_objects()
                .iter()
                .map(display_object_manifest)
                .collect(),
            display_capabilities: semantic
                .display_capabilities()
                .iter()
                .map(display_capability_manifest)
                .collect(),
            framebuffer_window_leases: semantic
                .framebuffer_window_leases()
                .iter()
                .map(framebuffer_window_lease_manifest)
                .collect(),
            framebuffer_mappings: semantic
                .framebuffer_mappings()
                .iter()
                .map(framebuffer_mapping_manifest)
                .collect(),
            framebuffer_writes: semantic
                .framebuffer_writes()
                .iter()
                .map(framebuffer_write_manifest)
                .collect(),
            framebuffer_flush_regions: semantic
                .framebuffer_flush_regions()
                .iter()
                .map(framebuffer_flush_region_manifest)
                .collect(),
            framebuffer_dirty_regions: semantic
                .framebuffer_dirty_regions()
                .iter()
                .map(framebuffer_dirty_region_manifest)
                .collect(),
            display_event_logs: semantic
                .display_event_logs()
                .iter()
                .map(display_event_log_manifest)
                .collect(),
            display_cleanups: semantic
                .display_cleanups()
                .iter()
                .map(display_cleanup_manifest)
                .collect(),
            display_snapshot_barriers: semantic
                .display_snapshot_barriers()
                .iter()
                .map(display_snapshot_barrier_manifest)
                .collect(),
            display_panic_last_frames: semantic
                .display_panic_last_frames()
                .iter()
                .map(display_panic_last_frame_manifest)
                .collect(),
            framebuffer_benchmarks: semantic
                .framebuffer_benchmarks()
                .iter()
                .map(framebuffer_benchmark_manifest)
                .collect(),
            activation_resumes: semantic
                .activation_resumes()
                .iter()
                .map(activation_resume_manifest)
                .collect(),
            activation_waits: semantic
                .activation_waits()
                .iter()
                .map(activation_wait_manifest)
                .collect(),
            activation_cleanups: semantic
                .activation_cleanups()
                .iter()
                .map(activation_cleanup_manifest)
                .collect(),
            preemption_latency_samples: semantic
                .preemption_latency_samples()
                .iter()
                .map(preemption_latency_manifest)
                .collect(),
            hart_event_attributions: semantic
                .hart_event_attributions()
                .iter()
                .map(hart_event_attribution_manifest)
                .collect(),
            code_objects: target_v1.code_objects.clone(),
            store_records: target_v1.store_records.clone(),
            capability_records: target_v1.capability_records.clone(),
            wait_records,
            activation_records: target_v1.activation_records.clone(),
            trap_records: target_v1.trap_records.clone(),
            hostcall_trace: target_v1.hostcall_trace.clone(),
            migration_objects: target_v1.migration_objects.clone(),
            tombstones: target_v1.tombstones.clone(),
            contract_violations: target_v1.contract_violations.clone(),
            cleanup_transactions: target_v1.cleanup_transactions.clone(),
            memory_policies: target_v1.memory_policies.clone(),
            snapshot_validation: target_v1.snapshot_validation.clone(),
            replay_validation: target_v1.replay_validation.clone(),
            substrate_events: target_v1.substrate_events.clone(),
            profile_gate_events: target_v1.profile_gate_events.clone(),
            command_results: target_v1.command_results.clone(),
            interface_events: target_v1.interface_events.clone(),
            network_socket_count: 1,
            network_rx_queue_bytes: 0,
        },
        logical_capabilities,
        substrate_boundary: SubstrateBoundaryManifest {
            timer_epoch: semantic.timer_epoch(),
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
            scheduler_decision_cursor: semantic.event_count() as u64,
            cow_epoch: 1,
            background_copy_pages: 0,
            native_state_policy:
                "target rebuilds page tables, DMW slots, IRQ registrations, stores, and code cache"
                    .to_owned(),
        },
        not_migrated: vec![
            "host raw pointers".to_owned(),
            "native stacks".to_owned(),
            "active semantic transactions".to_owned(),
            "active DMW leases".to_owned(),
            "DMA/IOMMU mappings".to_owned(),
            "MMIO mappings".to_owned(),
            "IRQ registrations".to_owned(),
            "translated guest code cache".to_owned(),
        ],
    }
}

mod semantic_roots;

pub(crate) use semantic_roots::semantic_roots;
