use super::*;

pub fn validate_migration_package(package: &MigrationPackageManifest) -> ContractResult<()> {
    if package.schema_version != 1 {
        return Err(ContractError::new("unsupported semantic package schema version"));
    }
    if package.package_format != "visa-semantic-package-v1" {
        return Err(ContractError::new("unsupported semantic package format"));
    }
    if package.guest.canonical_isa != "riscv64" {
        return Err(ContractError::new("unsupported canonical guest ISA"));
    }
    if package.semantic.active_transaction_count != 0 {
        return Err(ContractError::new("package contains active semantic transactions"));
    }
    if package.logical_capabilities.len() != package.semantic.capability_count {
        return Err(ContractError::new("package capability list/count mismatch"));
    }
    for capability in &package.logical_capabilities {
        if capability.subject.is_empty()
            || capability.object.is_empty()
            || capability.rights.is_empty()
            || capability.generation == 0
        {
            return Err(ContractError::new("package contains an invalid logical capability"));
        }
    }
    validate_semantic_roots(package)?;
    validate_target_runtime_profile_provenance(package)?;
    validate_migration_contract_core_evidence(package)?;
    Ok(())
}

pub fn validate_migration_against_manifest(
    package: &MigrationPackageManifest,
    manifest: &ArtifactBundleManifest,
) -> ContractResult<()> {
    validate_artifact_manifest(manifest)?;
    let plan = build_validated_artifact_plan(manifest)?;
    validate_migration_package(package)?;
    let required = &package.required_artifact_profile;
    if required.target_arch != "target-native" && required.target_arch != manifest.target.arch {
        return Err(ContractError::new("package target arch is incompatible with manifest"));
    }
    if required.machine_abi_version != manifest.target.machine_abi_version {
        return Err(ContractError::new("package machine ABI mismatch"));
    }
    if required.supervisor_abi_version != manifest.target.supervisor_abi_version {
        return Err(ContractError::new("package supervisor ABI mismatch"));
    }
    if required.wasm_feature_profile != manifest.target.wasm_feature_profile {
        return Err(ContractError::new("package Wasm feature profile mismatch"));
    }
    if required.memory64 != manifest.target.memory64
        || required.multi_memory != manifest.target.multi_memory
    {
        return Err(ContractError::new("package Wasm memory model mismatch"));
    }
    if required.dmw_layout != manifest.target.dmw_layout {
        return Err(ContractError::new("package DMW layout mismatch"));
    }
    if required.network_contract_version != manifest.target.network_contract_version {
        return Err(ContractError::new("package network contract mismatch"));
    }
    if required.compiler_engine != manifest.compiler.engine
        || required.compiler_execution_mode != manifest.compiler.execution_mode
        || required.artifact_format != manifest.compiler.artifact_format
        || required.runtime_executor_abi != manifest.compiler.runtime_executor_abi
    {
        return Err(ContractError::new("package compiler/artifact mode mismatch"));
    }
    if package.semantic.artifact_verification_count != manifest.modules.len() {
        return Err(ContractError::new(
            "package artifact verification count does not match manifest",
        ));
    }
    if package.semantic.store_activation_count != manifest.modules.len() {
        return Err(ContractError::new("package store activation count does not match manifest"));
    }
    if package.semantic.target_artifact_count != manifest.modules.len() {
        return Err(ContractError::new("package target artifact count does not match manifest"));
    }
    for module in &plan.modules {
        let Some(artifact) = package.semantic.target_artifacts.iter().find(|artifact| {
            artifact.package == module.package && artifact.artifact_name == module.artifact_name
        }) else {
            return Err(ContractError::new(format!(
                "{} target artifact evidence missing",
                module.package
            )));
        };
        if artifact.target_profile != plan.artifact_profile {
            return Err(ContractError::new(format!(
                "{} target profile evidence mismatch",
                module.package
            )));
        }
        if artifact.artifact_hash != module.target_artifact_sha256
            || artifact.code_hash != module.cwasm_sha256
            || artifact.abi_fingerprint != module.abi_fingerprint
            || artifact.manifest_binding_hash != module.manifest_binding_hash
        {
            return Err(ContractError::new(format!(
                "{} artifact hash evidence mismatch",
                module.package
            )));
        }
        if artifact.hash_status != module.hash_status
            || artifact.signature_scheme != module.signature_scheme
            || artifact.signature_status != module.signature_status
            || artifact.signature_verified != module.signature_verified
            || artifact.signer != module.signer
        {
            return Err(ContractError::new(format!(
                "{} artifact policy evidence mismatch",
                module.package
            )));
        }
    }
    Ok(())
}

pub fn validate_replay_quiescent(package: &MigrationPackageManifest) -> ContractResult<()> {
    validate_migration_package(package)?;
    if package.substrate_boundary.pending_dma_completions != 0
        || package.substrate_boundary.pending_network_inputs != 0
        || package.substrate_boundary.active_dmw_lease_count != 0
        || package.substrate_boundary.active_mmio_authority_count != 0
        || package.substrate_boundary.active_dma_authority_count != 0
        || package.substrate_boundary.active_irq_authority_count != 0
        || package.substrate_boundary.active_packet_device_authority_count != 0
        || package.substrate_boundary.active_virtio_queue_authority_count != 0
    {
        return Err(ContractError::new("package is not replay-quiescent"));
    }
    if package.substrate_boundary.background_copy_pages != 0 {
        return Err(ContractError::new("package contains unfinished background COW copies"));
    }
    Ok(())
}

pub fn validate_semantic_roots(package: &MigrationPackageManifest) -> ContractResult<()> {
    let roots = &package.semantic.roots;
    if roots.hart_roots.len() != package.semantic.hart_count
        || package.semantic.hart_records.len() != package.semantic.hart_count
    {
        return Err(ContractError::new("hart root/count mismatch"));
    }
    if roots.task_roots.len() != package.semantic.task_count {
        return Err(ContractError::new("task root/count mismatch"));
    }
    if package.semantic.task_records.len() != package.semantic.task_record_count {
        return Err(ContractError::new("task record count mismatch"));
    }
    if roots.task_record_roots.len() != package.semantic.task_record_count {
        return Err(ContractError::new("task record root/count mismatch"));
    }
    if roots.runtime_activation_roots.len() != package.semantic.runtime_activation_count
        || package.semantic.runtime_activation_records.len()
            != package.semantic.runtime_activation_count
    {
        return Err(ContractError::new("runtime activation root/count mismatch"));
    }
    if roots.runnable_queue_roots.len() != package.semantic.runnable_queue_count
        || package.semantic.runnable_queues.len() != package.semantic.runnable_queue_count
    {
        return Err(ContractError::new("runnable queue root/count mismatch"));
    }
    if roots.activation_context_roots.len() != package.semantic.activation_context_count
        || package.semantic.activation_contexts.len() != package.semantic.activation_context_count
    {
        return Err(ContractError::new("activation context root/count mismatch"));
    }
    if roots.saved_context_roots.len() != package.semantic.saved_context_count
        || package.semantic.saved_contexts.len() != package.semantic.saved_context_count
    {
        return Err(ContractError::new("saved context root/count mismatch"));
    }
    if roots.timer_interrupt_roots.len() != package.semantic.timer_interrupt_count
        || package.semantic.timer_interrupts.len() != package.semantic.timer_interrupt_count
    {
        return Err(ContractError::new("timer interrupt root/count mismatch"));
    }
    if roots.ipi_event_roots.len() != package.semantic.ipi_event_count
        || package.semantic.ipi_events.len() != package.semantic.ipi_event_count
    {
        return Err(ContractError::new("ipi event root/count mismatch"));
    }
    if roots.remote_preempt_roots.len() != package.semantic.remote_preempt_count
        || package.semantic.remote_preempts.len() != package.semantic.remote_preempt_count
    {
        return Err(ContractError::new("remote preempt root/count mismatch"));
    }
    if roots.remote_park_roots.len() != package.semantic.remote_park_count
        || package.semantic.remote_parks.len() != package.semantic.remote_park_count
    {
        return Err(ContractError::new("remote park root/count mismatch"));
    }
    if roots.preemption_roots.len() != package.semantic.preemption_count
        || package.semantic.preemptions.len() != package.semantic.preemption_count
    {
        return Err(ContractError::new("preemption root/count mismatch"));
    }
    if roots.scheduler_decision_roots.len() != package.semantic.scheduler_decision_count
        || package.semantic.scheduler_decisions.len() != package.semantic.scheduler_decision_count
    {
        return Err(ContractError::new("scheduler decision root/count mismatch"));
    }
    if roots.cross_hart_scheduler_decision_roots.len()
        != package.semantic.cross_hart_scheduler_decision_count
        || package.semantic.cross_hart_scheduler_decisions.len()
            != package.semantic.cross_hart_scheduler_decision_count
    {
        return Err(ContractError::new("cross-hart scheduler decision root/count mismatch"));
    }
    if roots.activation_migration_roots.len() != package.semantic.activation_migration_count
        || package.semantic.activation_migrations.len()
            != package.semantic.activation_migration_count
    {
        return Err(ContractError::new("activation migration root/count mismatch"));
    }
    if roots.smp_safe_point_roots.len() != package.semantic.smp_safe_point_count
        || package.semantic.smp_safe_points.len() != package.semantic.smp_safe_point_count
    {
        return Err(ContractError::new("smp safe point root/count mismatch"));
    }
    if roots.stop_the_world_rendezvous_roots.len()
        != package.semantic.stop_the_world_rendezvous_count
        || package.semantic.stop_the_world_rendezvous.len()
            != package.semantic.stop_the_world_rendezvous_count
    {
        return Err(ContractError::new("stop-the-world rendezvous root/count mismatch"));
    }
    if roots.smp_code_publish_barrier_roots.len() != package.semantic.smp_code_publish_barrier_count
        || package.semantic.smp_code_publish_barriers.len()
            != package.semantic.smp_code_publish_barrier_count
    {
        return Err(ContractError::new("smp code publish barrier root/count mismatch"));
    }
    if roots.smp_cleanup_quiescence_roots.len() != package.semantic.smp_cleanup_quiescence_count
        || package.semantic.smp_cleanup_quiescence.len()
            != package.semantic.smp_cleanup_quiescence_count
    {
        return Err(ContractError::new("smp cleanup quiescence root/count mismatch"));
    }
    if roots.smp_snapshot_barrier_roots.len() != package.semantic.smp_snapshot_barrier_count
        || package.semantic.smp_snapshot_barriers.len()
            != package.semantic.smp_snapshot_barrier_count
    {
        return Err(ContractError::new("smp snapshot barrier root/count mismatch"));
    }
    if roots.smp_stress_run_roots.len() != package.semantic.smp_stress_run_count
        || package.semantic.smp_stress_runs.len() != package.semantic.smp_stress_run_count
    {
        return Err(ContractError::new("smp stress run root/count mismatch"));
    }
    if roots.smp_scaling_benchmark_roots.len() != package.semantic.smp_scaling_benchmark_count
        || package.semantic.smp_scaling_benchmarks.len()
            != package.semantic.smp_scaling_benchmark_count
    {
        return Err(ContractError::new("smp scaling benchmark root/count mismatch"));
    }
    if roots.integrated_smp_preemption_cleanup_roots.len()
        != package.semantic.integrated_smp_preemption_cleanup_count
        || package.semantic.integrated_smp_preemption_cleanups.len()
            != package.semantic.integrated_smp_preemption_cleanup_count
    {
        return Err(ContractError::new("integrated smp preemption cleanup root/count mismatch"));
    }
    if roots.integrated_smp_network_fault_roots.len()
        != package.semantic.integrated_smp_network_fault_count
        || package.semantic.integrated_smp_network_faults.len()
            != package.semantic.integrated_smp_network_fault_count
    {
        return Err(ContractError::new("integrated smp network fault root/count mismatch"));
    }
    if roots.integrated_disk_preempt_fault_roots.len()
        != package.semantic.integrated_disk_preempt_fault_count
        || package.semantic.integrated_disk_preempt_faults.len()
            != package.semantic.integrated_disk_preempt_fault_count
    {
        return Err(ContractError::new("integrated disk preempt fault root/count mismatch"));
    }
    if roots.integrated_simd_migration_roots.len()
        != package.semantic.integrated_simd_migration_count
        || package.semantic.integrated_simd_migrations.len()
            != package.semantic.integrated_simd_migration_count
    {
        return Err(ContractError::new("integrated simd migration root/count mismatch"));
    }
    if roots.integrated_network_disk_io_roots.len()
        != package.semantic.integrated_network_disk_io_count
        || package.semantic.integrated_network_disk_ios.len()
            != package.semantic.integrated_network_disk_io_count
    {
        return Err(ContractError::new("integrated network disk io root/count mismatch"));
    }
    if roots.integrated_display_scheduler_load_roots.len()
        != package.semantic.integrated_display_scheduler_load_count
        || package.semantic.integrated_display_scheduler_loads.len()
            != package.semantic.integrated_display_scheduler_load_count
    {
        return Err(ContractError::new("integrated display scheduler load root/count mismatch"));
    }
    if roots.integrated_snapshot_io_lease_barrier_roots.len()
        != package.semantic.integrated_snapshot_io_lease_barrier_count
        || package.semantic.integrated_snapshot_io_lease_barriers.len()
            != package.semantic.integrated_snapshot_io_lease_barrier_count
    {
        return Err(ContractError::new("integrated snapshot io lease barrier root/count mismatch"));
    }
    if roots.integrated_code_publish_smp_workload_roots.len()
        != package.semantic.integrated_code_publish_smp_workload_count
        || package.semantic.integrated_code_publish_smp_workloads.len()
            != package.semantic.integrated_code_publish_smp_workload_count
    {
        return Err(ContractError::new("integrated code publish smp workload root/count mismatch"));
    }
    if roots.device_object_roots.len() != package.semantic.device_object_count
        || package.semantic.device_objects.len() != package.semantic.device_object_count
    {
        return Err(ContractError::new("device object root/count mismatch"));
    }
    if roots.queue_object_roots.len() != package.semantic.queue_object_count
        || package.semantic.queue_objects.len() != package.semantic.queue_object_count
    {
        return Err(ContractError::new("queue object root/count mismatch"));
    }
    if roots.descriptor_object_roots.len() != package.semantic.descriptor_object_count
        || package.semantic.descriptor_objects.len() != package.semantic.descriptor_object_count
    {
        return Err(ContractError::new("descriptor object root/count mismatch"));
    }
    if roots.dma_buffer_object_roots.len() != package.semantic.dma_buffer_object_count
        || package.semantic.dma_buffer_objects.len() != package.semantic.dma_buffer_object_count
    {
        return Err(ContractError::new("dma buffer object root/count mismatch"));
    }
    if roots.mmio_region_object_roots.len() != package.semantic.mmio_region_object_count
        || package.semantic.mmio_region_objects.len() != package.semantic.mmio_region_object_count
    {
        return Err(ContractError::new("mmio region object root/count mismatch"));
    }
    if roots.irq_line_object_roots.len() != package.semantic.irq_line_object_count
        || package.semantic.irq_line_objects.len() != package.semantic.irq_line_object_count
    {
        return Err(ContractError::new("irq line object root/count mismatch"));
    }
    if roots.irq_event_roots.len() != package.semantic.irq_event_count
        || package.semantic.irq_events.len() != package.semantic.irq_event_count
    {
        return Err(ContractError::new("irq event root/count mismatch"));
    }
    if roots.device_capability_roots.len() != package.semantic.device_capability_count
        || package.semantic.device_capabilities.len() != package.semantic.device_capability_count
    {
        return Err(ContractError::new("device capability root/count mismatch"));
    }
    if roots.driver_store_binding_roots.len() != package.semantic.driver_store_binding_count
        || package.semantic.driver_store_bindings.len()
            != package.semantic.driver_store_binding_count
    {
        return Err(ContractError::new("driver store binding root/count mismatch"));
    }
    if roots.io_wait_roots.len() != package.semantic.io_wait_count
        || package.semantic.io_waits.len() != package.semantic.io_wait_count
    {
        return Err(ContractError::new("io wait root/count mismatch"));
    }
    if roots.io_cleanup_roots.len() != package.semantic.io_cleanup_count
        || package.semantic.io_cleanups.len() != package.semantic.io_cleanup_count
    {
        return Err(ContractError::new("io cleanup root/count mismatch"));
    }
    if roots.io_fault_injection_roots.len() != package.semantic.io_fault_injection_count
        || package.semantic.io_fault_injections.len() != package.semantic.io_fault_injection_count
    {
        return Err(ContractError::new("io fault injection root/count mismatch"));
    }
    if roots.io_validation_report_roots.len() != package.semantic.io_validation_report_count
        || package.semantic.io_validation_reports.len()
            != package.semantic.io_validation_report_count
    {
        return Err(ContractError::new("io validation report root/count mismatch"));
    }
    if roots.packet_device_object_roots.len() != package.semantic.packet_device_object_count
        || package.semantic.packet_device_objects.len()
            != package.semantic.packet_device_object_count
    {
        return Err(ContractError::new("packet device object root/count mismatch"));
    }
    if roots.packet_buffer_object_roots.len() != package.semantic.packet_buffer_object_count
        || package.semantic.packet_buffer_objects.len()
            != package.semantic.packet_buffer_object_count
    {
        return Err(ContractError::new("packet buffer object root/count mismatch"));
    }
    if roots.packet_queue_object_roots.len() != package.semantic.packet_queue_object_count
        || package.semantic.packet_queue_objects.len() != package.semantic.packet_queue_object_count
    {
        return Err(ContractError::new("packet queue object root/count mismatch"));
    }
    if roots.packet_descriptor_object_roots.len() != package.semantic.packet_descriptor_object_count
        || package.semantic.packet_descriptors.len()
            != package.semantic.packet_descriptor_object_count
    {
        return Err(ContractError::new("packet descriptor object root/count mismatch"));
    }
    if roots.fake_net_backend_object_roots.len() != package.semantic.fake_net_backend_object_count
        || package.semantic.fake_net_backends.len()
            != package.semantic.fake_net_backend_object_count
    {
        return Err(ContractError::new("fake net backend object root/count mismatch"));
    }
    if roots.virtio_net_backend_object_roots.len()
        != package.semantic.virtio_net_backend_object_count
        || package.semantic.virtio_net_backends.len()
            != package.semantic.virtio_net_backend_object_count
    {
        return Err(ContractError::new("virtio net backend object root/count mismatch"));
    }
    if roots.network_rx_interrupt_roots.len() != package.semantic.network_rx_interrupt_count
        || package.semantic.network_rx_interrupts.len()
            != package.semantic.network_rx_interrupt_count
    {
        return Err(ContractError::new("network rx interrupt root/count mismatch"));
    }
    if roots.network_rx_wait_resolution_roots.len()
        != package.semantic.network_rx_wait_resolution_count
        || package.semantic.network_rx_wait_resolutions.len()
            != package.semantic.network_rx_wait_resolution_count
    {
        return Err(ContractError::new("network rx wait resolution root/count mismatch"));
    }
    if roots.network_tx_capability_gate_roots.len()
        != package.semantic.network_tx_capability_gate_count
        || package.semantic.network_tx_capability_gates.len()
            != package.semantic.network_tx_capability_gate_count
    {
        return Err(ContractError::new("network tx capability gate root/count mismatch"));
    }
    if roots.network_tx_completion_roots.len() != package.semantic.network_tx_completion_count
        || package.semantic.network_tx_completions.len()
            != package.semantic.network_tx_completion_count
    {
        return Err(ContractError::new("network tx completion root/count mismatch"));
    }
    if roots.network_stack_adapter_roots.len() != package.semantic.network_stack_adapter_count
        || package.semantic.network_stack_adapters.len()
            != package.semantic.network_stack_adapter_count
    {
        return Err(ContractError::new("network stack adapter root/count mismatch"));
    }
    if roots.socket_object_roots.len() != package.semantic.socket_object_count
        || package.semantic.socket_objects.len() != package.semantic.socket_object_count
    {
        return Err(ContractError::new("socket object root/count mismatch"));
    }
    if roots.endpoint_object_roots.len() != package.semantic.endpoint_object_count
        || package.semantic.endpoint_objects.len() != package.semantic.endpoint_object_count
    {
        return Err(ContractError::new("endpoint object root/count mismatch"));
    }
    if roots.socket_operation_roots.len() != package.semantic.socket_operation_count
        || package.semantic.socket_operations.len() != package.semantic.socket_operation_count
    {
        return Err(ContractError::new("socket operation root/count mismatch"));
    }
    if roots.socket_wait_roots.len() != package.semantic.socket_wait_count
        || package.semantic.socket_waits.len() != package.semantic.socket_wait_count
    {
        return Err(ContractError::new("socket wait root/count mismatch"));
    }
    if roots.network_backpressure_roots.len() != package.semantic.network_backpressure_count
        || package.semantic.network_backpressures.len()
            != package.semantic.network_backpressure_count
    {
        return Err(ContractError::new("network backpressure root/count mismatch"));
    }
    if roots.network_driver_cleanup_roots.len() != package.semantic.network_driver_cleanup_count
        || package.semantic.network_driver_cleanups.len()
            != package.semantic.network_driver_cleanup_count
    {
        return Err(ContractError::new("network driver cleanup root/count mismatch"));
    }
    if roots.network_generation_audit_roots.len() != package.semantic.network_generation_audit_count
        || package.semantic.network_generation_audits.len()
            != package.semantic.network_generation_audit_count
    {
        return Err(ContractError::new("network generation audit root/count mismatch"));
    }
    if roots.network_fault_injection_roots.len() != package.semantic.network_fault_injection_count
        || package.semantic.network_fault_injections.len()
            != package.semantic.network_fault_injection_count
    {
        return Err(ContractError::new("network fault injection root/count mismatch"));
    }
    if roots.network_benchmark_roots.len() != package.semantic.network_benchmark_count
        || package.semantic.network_benchmarks.len() != package.semantic.network_benchmark_count
    {
        return Err(ContractError::new("network benchmark root/count mismatch"));
    }
    if roots.network_recovery_benchmark_roots.len()
        != package.semantic.network_recovery_benchmark_count
        || package.semantic.network_recovery_benchmarks.len()
            != package.semantic.network_recovery_benchmark_count
    {
        return Err(ContractError::new("network recovery benchmark root/count mismatch"));
    }
    if roots.block_device_object_roots.len() != package.semantic.block_device_object_count
        || package.semantic.block_device_objects.len() != package.semantic.block_device_object_count
    {
        return Err(ContractError::new("block device object root/count mismatch"));
    }
    if roots.block_range_object_roots.len() != package.semantic.block_range_object_count
        || package.semantic.block_range_objects.len() != package.semantic.block_range_object_count
    {
        return Err(ContractError::new("block range object root/count mismatch"));
    }
    if roots.block_request_object_roots.len() != package.semantic.block_request_object_count
        || package.semantic.block_request_objects.len()
            != package.semantic.block_request_object_count
    {
        return Err(ContractError::new("block request object root/count mismatch"));
    }
    if roots.block_completion_object_roots.len() != package.semantic.block_completion_object_count
        || package.semantic.block_completion_objects.len()
            != package.semantic.block_completion_object_count
    {
        return Err(ContractError::new("block completion object root/count mismatch"));
    }
    if roots.block_wait_roots.len() != package.semantic.block_wait_count
        || package.semantic.block_waits.len() != package.semantic.block_wait_count
    {
        return Err(ContractError::new("block wait root/count mismatch"));
    }
    if roots.fake_block_backend_object_roots.len()
        != package.semantic.fake_block_backend_object_count
        || package.semantic.fake_block_backends.len()
            != package.semantic.fake_block_backend_object_count
    {
        return Err(ContractError::new("fake block backend object root/count mismatch"));
    }
    if roots.virtio_blk_backend_object_roots.len()
        != package.semantic.virtio_blk_backend_object_count
        || package.semantic.virtio_blk_backends.len()
            != package.semantic.virtio_blk_backend_object_count
    {
        return Err(ContractError::new("virtio block backend object root/count mismatch"));
    }
    if roots.block_read_path_roots.len() != package.semantic.block_read_path_count
        || package.semantic.block_read_paths.len() != package.semantic.block_read_path_count
    {
        return Err(ContractError::new("block read path root/count mismatch"));
    }
    if roots.block_write_path_roots.len() != package.semantic.block_write_path_count
        || package.semantic.block_write_paths.len() != package.semantic.block_write_path_count
    {
        return Err(ContractError::new("block write path root/count mismatch"));
    }
    if roots.block_request_queue_roots.len() != package.semantic.block_request_queue_count
        || package.semantic.block_request_queues.len() != package.semantic.block_request_queue_count
    {
        return Err(ContractError::new("block request queue root/count mismatch"));
    }
    if roots.block_dma_buffer_roots.len() != package.semantic.block_dma_buffer_count
        || package.semantic.block_dma_buffers.len() != package.semantic.block_dma_buffer_count
    {
        return Err(ContractError::new("block dma buffer root/count mismatch"));
    }
    if roots.block_page_object_roots.len() != package.semantic.block_page_object_count
        || package.semantic.block_page_objects.len() != package.semantic.block_page_object_count
    {
        return Err(ContractError::new("block page object root/count mismatch"));
    }
    if roots.guest_address_space_roots.len() != package.semantic.guest_address_space_count
        || package.semantic.guest_address_spaces.len() != package.semantic.guest_address_space_count
    {
        return Err(ContractError::new("guest address space root/count mismatch"));
    }
    if roots.vma_region_roots.len() != package.semantic.vma_region_count
        || package.semantic.vma_regions.len() != package.semantic.vma_region_count
    {
        return Err(ContractError::new("vma region root/count mismatch"));
    }
    if roots.page_object_roots.len() != package.semantic.page_object_count
        || package.semantic.page_objects.len() != package.semantic.page_object_count
    {
        return Err(ContractError::new("page object root/count mismatch"));
    }
    if roots.guest_memory_fault_roots.len() != package.semantic.guest_memory_fault_count
        || package.semantic.guest_memory_faults.len() != package.semantic.guest_memory_fault_count
    {
        return Err(ContractError::new("guest memory fault root/count mismatch"));
    }
    if roots.buffer_cache_object_roots.len() != package.semantic.buffer_cache_object_count
        || package.semantic.buffer_cache_objects.len() != package.semantic.buffer_cache_object_count
    {
        return Err(ContractError::new("buffer cache object root/count mismatch"));
    }
    if roots.file_object_roots.len() != package.semantic.file_object_count
        || package.semantic.file_objects.len() != package.semantic.file_object_count
    {
        return Err(ContractError::new("file object root/count mismatch"));
    }
    if roots.directory_object_roots.len() != package.semantic.directory_object_count
        || package.semantic.directory_objects.len() != package.semantic.directory_object_count
    {
        return Err(ContractError::new("directory object root/count mismatch"));
    }
    if roots.fat_adapter_object_roots.len() != package.semantic.fat_adapter_object_count
        || package.semantic.fat_adapter_objects.len() != package.semantic.fat_adapter_object_count
    {
        return Err(ContractError::new("fat adapter object root/count mismatch"));
    }
    if roots.ext4_adapter_object_roots.len() != package.semantic.ext4_adapter_object_count
        || package.semantic.ext4_adapter_objects.len() != package.semantic.ext4_adapter_object_count
    {
        return Err(ContractError::new("ext4 adapter object root/count mismatch"));
    }
    if roots.file_handle_capability_roots.len() != package.semantic.file_handle_capability_count
        || package.semantic.file_handle_capabilities.len()
            != package.semantic.file_handle_capability_count
    {
        return Err(ContractError::new("file handle capability root/count mismatch"));
    }
    if roots.fs_wait_roots.len() != package.semantic.fs_wait_count
        || package.semantic.fs_waits.len() != package.semantic.fs_wait_count
    {
        return Err(ContractError::new("fs wait root/count mismatch"));
    }
    if roots.block_driver_cleanup_roots.len() != package.semantic.block_driver_cleanup_count
        || package.semantic.block_driver_cleanups.len()
            != package.semantic.block_driver_cleanup_count
    {
        return Err(ContractError::new("block driver cleanup root/count mismatch"));
    }
    if roots.block_pending_io_policy_roots.len() != package.semantic.block_pending_io_policy_count
        || package.semantic.block_pending_io_policies.len()
            != package.semantic.block_pending_io_policy_count
    {
        return Err(ContractError::new("block pending io policy root/count mismatch"));
    }
    if roots.block_request_generation_audit_roots.len()
        != package.semantic.block_request_generation_audit_count
        || package.semantic.block_request_generation_audits.len()
            != package.semantic.block_request_generation_audit_count
    {
        return Err(ContractError::new("block request generation audit root/count mismatch"));
    }
    if roots.block_benchmark_roots.len() != package.semantic.block_benchmark_count
        || package.semantic.block_benchmarks.len() != package.semantic.block_benchmark_count
    {
        return Err(ContractError::new("block benchmark root/count mismatch"));
    }
    if roots.block_recovery_benchmark_roots.len() != package.semantic.block_recovery_benchmark_count
        || package.semantic.block_recovery_benchmarks.len()
            != package.semantic.block_recovery_benchmark_count
    {
        return Err(ContractError::new("block recovery benchmark root/count mismatch"));
    }
    if roots.target_feature_set_roots.len() != package.semantic.target_feature_set_count
        || package.semantic.target_feature_sets.len() != package.semantic.target_feature_set_count
    {
        return Err(ContractError::new("target feature set root/count mismatch"));
    }
    if roots.vector_state_roots.len() != package.semantic.vector_state_count
        || package.semantic.vector_states.len() != package.semantic.vector_state_count
    {
        return Err(ContractError::new("vector state root/count mismatch"));
    }
    if roots.simd_fault_injection_roots.len() != package.semantic.simd_fault_injection_count
        || package.semantic.simd_fault_injections.len()
            != package.semantic.simd_fault_injection_count
    {
        return Err(ContractError::new("simd fault injection root/count mismatch"));
    }
    if roots.simd_benchmark_roots.len() != package.semantic.simd_benchmark_count
        || package.semantic.simd_benchmarks.len() != package.semantic.simd_benchmark_count
    {
        return Err(ContractError::new("simd benchmark root/count mismatch"));
    }
    if roots.simd_context_switch_benchmark_roots.len()
        != package.semantic.simd_context_switch_benchmark_count
        || package.semantic.simd_context_switch_benchmarks.len()
            != package.semantic.simd_context_switch_benchmark_count
    {
        return Err(ContractError::new("simd context switch benchmark root/count mismatch"));
    }
    if roots.framebuffer_object_roots.len() != package.semantic.framebuffer_object_count
        || package.semantic.framebuffer_objects.len() != package.semantic.framebuffer_object_count
    {
        return Err(ContractError::new("framebuffer object root/count mismatch"));
    }
    if roots.display_object_roots.len() != package.semantic.display_object_count
        || package.semantic.display_objects.len() != package.semantic.display_object_count
    {
        return Err(ContractError::new("display object root/count mismatch"));
    }
    if roots.display_capability_roots.len() != package.semantic.display_capability_count
        || package.semantic.display_capabilities.len() != package.semantic.display_capability_count
    {
        return Err(ContractError::new("display capability root/count mismatch"));
    }
    if roots.framebuffer_window_lease_roots.len() != package.semantic.framebuffer_window_lease_count
        || package.semantic.framebuffer_window_leases.len()
            != package.semantic.framebuffer_window_lease_count
    {
        return Err(ContractError::new("framebuffer window lease root/count mismatch"));
    }
    if roots.framebuffer_mapping_roots.len() != package.semantic.framebuffer_mapping_count
        || package.semantic.framebuffer_mappings.len() != package.semantic.framebuffer_mapping_count
    {
        return Err(ContractError::new("framebuffer mapping root/count mismatch"));
    }
    if roots.framebuffer_write_roots.len() != package.semantic.framebuffer_write_count
        || package.semantic.framebuffer_writes.len() != package.semantic.framebuffer_write_count
    {
        return Err(ContractError::new("framebuffer write root/count mismatch"));
    }
    if roots.framebuffer_flush_region_roots.len() != package.semantic.framebuffer_flush_region_count
        || package.semantic.framebuffer_flush_regions.len()
            != package.semantic.framebuffer_flush_region_count
    {
        return Err(ContractError::new("framebuffer flush region root/count mismatch"));
    }
    if roots.framebuffer_dirty_region_roots.len() != package.semantic.framebuffer_dirty_region_count
        || package.semantic.framebuffer_dirty_regions.len()
            != package.semantic.framebuffer_dirty_region_count
    {
        return Err(ContractError::new("framebuffer dirty region root/count mismatch"));
    }
    if roots.display_event_log_roots.len() != package.semantic.display_event_log_count
        || package.semantic.display_event_logs.len() != package.semantic.display_event_log_count
    {
        return Err(ContractError::new("display event log root/count mismatch"));
    }
    if roots.display_cleanup_roots.len() != package.semantic.display_cleanup_count
        || package.semantic.display_cleanups.len() != package.semantic.display_cleanup_count
    {
        return Err(ContractError::new("display cleanup root/count mismatch"));
    }
    if roots.display_snapshot_barrier_roots.len() != package.semantic.display_snapshot_barrier_count
        || package.semantic.display_snapshot_barriers.len()
            != package.semantic.display_snapshot_barrier_count
    {
        return Err(ContractError::new("display snapshot barrier root/count mismatch"));
    }
    if roots.display_panic_last_frame_roots.len() != package.semantic.display_panic_last_frame_count
        || package.semantic.display_panic_last_frames.len()
            != package.semantic.display_panic_last_frame_count
    {
        return Err(ContractError::new("display panic last-frame root/count mismatch"));
    }
    if roots.integrated_display_panic_roots.len() != package.semantic.integrated_display_panic_count
        || package.semantic.integrated_display_panics.len()
            != package.semantic.integrated_display_panic_count
    {
        return Err(ContractError::new("integrated display panic root/count mismatch"));
    }
    if roots.integrated_osctl_trace_replay_roots.len()
        != package.semantic.integrated_osctl_trace_replay_count
        || package.semantic.integrated_osctl_trace_replays.len()
            != package.semantic.integrated_osctl_trace_replay_count
    {
        return Err(ContractError::new("integrated osctl trace replay root/count mismatch"));
    }
    if roots.framebuffer_benchmark_roots.len() != package.semantic.framebuffer_benchmark_count
        || package.semantic.framebuffer_benchmarks.len()
            != package.semantic.framebuffer_benchmark_count
    {
        return Err(ContractError::new("framebuffer benchmark root/count mismatch"));
    }
    if roots.activation_resume_roots.len() != package.semantic.activation_resume_count
        || package.semantic.activation_resumes.len() != package.semantic.activation_resume_count
    {
        return Err(ContractError::new("activation resume root/count mismatch"));
    }
    if roots.activation_wait_roots.len() != package.semantic.activation_wait_count
        || package.semantic.activation_waits.len() != package.semantic.activation_wait_count
    {
        return Err(ContractError::new("activation wait root/count mismatch"));
    }
    if roots.activation_cleanup_roots.len() != package.semantic.activation_cleanup_count
        || package.semantic.activation_cleanups.len() != package.semantic.activation_cleanup_count
    {
        return Err(ContractError::new("activation cleanup root/count mismatch"));
    }
    if roots.preemption_latency_roots.len() != package.semantic.preemption_latency_sample_count
        || package.semantic.preemption_latency_samples.len()
            != package.semantic.preemption_latency_sample_count
    {
        return Err(ContractError::new("preemption latency root/count mismatch"));
    }
    if roots.hart_event_attribution_roots.len() != package.semantic.hart_event_attribution_count
        || package.semantic.hart_event_attributions.len()
            != package.semantic.hart_event_attribution_count
    {
        return Err(ContractError::new("hart event attribution root/count mismatch"));
    }
    if roots.resource_roots.len() != package.semantic.resource_count {
        return Err(ContractError::new("resource root/count mismatch"));
    }
    if roots.authority_roots.len() != package.semantic.authority_count {
        return Err(ContractError::new("authority root/count mismatch"));
    }
    if package.semantic.active_authority_count > package.semantic.authority_count {
        return Err(ContractError::new("active authority count exceeds authority count"));
    }
    if roots.wait_roots.len() != package.semantic.wait_token_count {
        return Err(ContractError::new("wait root/count mismatch"));
    }
    if roots.store_roots.len() != package.semantic.store_count {
        return Err(ContractError::new("store root/count mismatch"));
    }
    if roots.capability_roots.len() != package.semantic.capability_count {
        return Err(ContractError::new("capability root/count mismatch"));
    }
    if roots.fast_path_roots.len() != package.semantic.fast_path_plan_count {
        return Err(ContractError::new("fastpath root/count mismatch"));
    }
    if roots.boundary_roots.len() != package.semantic.boundary_count {
        return Err(ContractError::new("boundary root/count mismatch"));
    }
    if roots.artifact_verification_roots.len() != package.semantic.artifact_verification_count {
        return Err(ContractError::new("artifact verification root/count mismatch"));
    }
    if roots.store_activation_roots.len() != package.semantic.store_activation_count {
        return Err(ContractError::new("store activation root/count mismatch"));
    }
    if roots.executor_transition_roots.len() != package.semantic.executor_transition_count {
        return Err(ContractError::new("executor transition root/count mismatch"));
    }
    if roots.target_artifact_roots.len() != package.semantic.target_artifact_count
        || package.semantic.target_artifacts.len() != package.semantic.target_artifact_count
    {
        return Err(ContractError::new("target artifact root/count mismatch"));
    }
    if roots.code_object_roots.len() != package.semantic.code_object_count
        || package.semantic.code_objects.len() != package.semantic.code_object_count
    {
        return Err(ContractError::new("code object root/count mismatch"));
    }
    if package.semantic.store_records.len() != package.semantic.store_record_count {
        return Err(ContractError::new("store record count mismatch"));
    }
    if roots.target_store_record_roots.len() != package.semantic.store_record_count {
        return Err(ContractError::new("target store record root/count mismatch"));
    }
    if package.semantic.capability_records.len() != package.semantic.capability_record_count {
        return Err(ContractError::new("capability record count mismatch"));
    }
    if roots.target_capability_record_roots.len() != package.semantic.capability_record_count {
        return Err(ContractError::new("target capability record root/count mismatch"));
    }
    if roots.activation_record_roots.len() != package.semantic.activation_record_count
        || package.semantic.activation_records.len() != package.semantic.activation_record_count
    {
        return Err(ContractError::new("activation record root/count mismatch"));
    }
    if roots.trap_roots.len() != package.semantic.trap_record_count
        || package.semantic.trap_records.len() != package.semantic.trap_record_count
    {
        return Err(ContractError::new("trap record root/count mismatch"));
    }
    if roots.hostcall_trace_roots.len() != package.semantic.hostcall_trace_count
        || package.semantic.hostcall_trace.len() != package.semantic.hostcall_trace_count
    {
        return Err(ContractError::new("hostcall trace root/count mismatch"));
    }
    if roots.migration_object_roots.len() != package.semantic.migration_object_count
        || package.semantic.migration_objects.len() != package.semantic.migration_object_count
    {
        return Err(ContractError::new("migration object root/count mismatch"));
    }
    if roots.cleanup_roots.len() != package.semantic.cleanup_transaction_count
        || package.semantic.cleanup_transactions.len() != package.semantic.cleanup_transaction_count
    {
        return Err(ContractError::new("cleanup transaction root/count mismatch"));
    }
    if roots.memory_policy_roots.len() != package.semantic.memory_policy_count
        || package.semantic.memory_policies.len() != package.semantic.memory_policy_count
    {
        return Err(ContractError::new("memory policy root/count mismatch"));
    }
    if roots.substrate_event_roots.len() != package.semantic.substrate_event_count
        || package.semantic.substrate_events.len() != package.semantic.substrate_event_count
    {
        return Err(ContractError::new("substrate event root/count mismatch"));
    }
    if roots.profile_gate_event_roots.len() != package.semantic.profile_gate_event_count
        || package.semantic.profile_gate_events.len() != package.semantic.profile_gate_event_count
    {
        return Err(ContractError::new("profile gate event root/count mismatch"));
    }
    if roots.command_result_roots.len() != package.semantic.command_result_count
        || package.semantic.command_results.len() != package.semantic.command_result_count
    {
        return Err(ContractError::new("command result root/count mismatch"));
    }
    if roots.interface_event_roots.len() != package.semantic.interface_event_count
        || package.semantic.interface_events.len() != package.semantic.interface_event_count
    {
        return Err(ContractError::new("interface event root/count mismatch"));
    }
    if package.semantic.snapshot_validation.violations.len()
        != package.semantic.snapshot_validation_violation_count
    {
        return Err(ContractError::new("snapshot validation violation count mismatch"));
    }
    if package.semantic.replay_validation.violations.len()
        != package.semantic.replay_validation_violation_count
    {
        return Err(ContractError::new("replay validation violation count mismatch"));
    }
    validate_boundary_validation_report(
        "snapshot",
        &package.semantic.snapshot_validation,
        &roots.snapshot_validation_roots,
    )?;
    validate_boundary_validation_report(
        "replay",
        &package.semantic.replay_validation,
        &roots.replay_validation_roots,
    )?;
    if roots.event_log_tail.is_empty() && package.semantic.event_log_cursor != 0 {
        return Err(ContractError::new(
            "event log cursor is nonzero but package has no event tail",
        ));
    }
    Ok(())
}

fn validate_target_runtime_profile_provenance(
    package: &MigrationPackageManifest,
) -> ContractResult<()> {
    for artifact in &package.semantic.target_artifacts {
        if artifact.target_profile.is_empty() {
            return Err(ContractError::new(format!(
                "{} target artifact profile provenance is missing",
                artifact.package
            )));
        }
    }

    for code in &package.semantic.code_objects {
        let artifact = package
            .semantic
            .target_artifacts
            .iter()
            .find(|artifact| artifact.id == code.artifact_id)
            .ok_or_else(|| {
                ContractError::new(format!(
                    "{} code object artifact provenance is missing",
                    code.package
                ))
            })?;
        if code.owner_profile.is_empty() || code.owner_profile != artifact.target_profile {
            return Err(ContractError::new(format!(
                "{} code object profile provenance mismatch",
                code.package
            )));
        }
    }

    for store in &package.semantic.store_records {
        let artifact = package
            .semantic
            .target_artifacts
            .iter()
            .find(|artifact| {
                artifact.package == store.package && artifact.artifact_name == store.artifact
            })
            .ok_or_else(|| {
                ContractError::new(format!(
                    "{} store artifact provenance is missing",
                    store.package
                ))
            })?;
        if store.owner_profile.is_empty() || store.owner_profile != artifact.target_profile {
            return Err(ContractError::new(format!(
                "{} store profile provenance mismatch",
                store.package
            )));
        }
    }

    for activation in &package.semantic.activation_records {
        let code = package
            .semantic
            .code_objects
            .iter()
            .find(|code| {
                code.id == activation.code_object && code.artifact_id == activation.artifact
            })
            .ok_or_else(|| {
                ContractError::new(format!(
                    "activation {} code profile provenance is missing",
                    activation.id
                ))
            })?;
        if activation.profile.is_empty() || activation.profile != code.owner_profile {
            return Err(ContractError::new(format!(
                "activation {} profile provenance mismatch",
                activation.id
            )));
        }
        if let Some(store) =
            package.semantic.store_records.iter().find(|store| store.id == activation.store)
        {
            if store.owner_profile.is_empty() || store.owner_profile != activation.profile {
                return Err(ContractError::new(format!(
                    "activation {} store profile provenance mismatch",
                    activation.id
                )));
            }
        }
    }

    Ok(())
}

fn validate_boundary_validation_report(
    label: &str,
    report: &BoundaryValidationReportManifest,
    roots: &[String],
) -> ContractResult<()> {
    if report.validator.is_empty()
        && report.evidence_boundary.is_empty()
        && report.violation_count == 0
        && roots.is_empty()
    {
        return Ok(());
    }
    let Some(boundary) = EvidenceBoundaryLevel::parse(&report.evidence_boundary) else {
        return Err(ContractError::new(format!(
            "{label} validation evidence boundary is missing or unknown"
        )));
    };
    if report.validator.is_empty() {
        return Err(ContractError::new(format!("{label} validation validator is missing")));
    }
    if report.violations.len() != report.violation_count {
        return Err(ContractError::new(format!("{label} validation violation count mismatch")));
    }
    if report.ok != (report.violation_count == 0) {
        return Err(ContractError::new(format!(
            "{label} validation ok flag disagrees with violations"
        )));
    }
    let expected_root_fragment = format!("evidence={}", boundary.as_str());
    let Some(summary_root) = roots.first() else {
        return Err(ContractError::new(format!(
            "{label} validation roots missing evidence boundary summary"
        )));
    };
    if !summary_root.contains(&expected_root_fragment) {
        return Err(ContractError::new(format!(
            "{label} validation root evidence boundary mismatch"
        )));
    }
    let expected_summary = format!(
        "boundary-validation validator={} evidence={} ok={} violations={}",
        report.validator,
        boundary.as_str(),
        report.ok,
        report.violation_count
    );
    if summary_root != &expected_summary {
        return Err(ContractError::new(format!("{label} validation root summary mismatch")));
    }
    let expected_root_count = 1 + report.violation_count;
    if roots.len() != expected_root_count {
        return Err(ContractError::new(format!("{label} validation root/count mismatch")));
    }
    for (root, violation) in roots.iter().skip(1).zip(report.violations.iter()) {
        let expected_violation_root = format!(
            "boundary-validation validator={} kind={} object={} detail={}",
            violation.validator, violation.kind, violation.object, violation.detail
        );
        if root != &expected_violation_root {
            return Err(ContractError::new(format!("{label} validation violation root mismatch")));
        }
    }
    Ok(())
}
