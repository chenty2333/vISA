use super::*;
pub(crate) fn replay_until(
    cursor: u64,
    manifest_path: Option<&Path>,
    path: &Path,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let package = serde_json::from_slice::<MigrationPackageManifest>(&bytes)?;
    validate_replay_quiescent(&package)?;
    if let Some(manifest_path) = manifest_path {
        let manifest = serde_json::from_slice::<ArtifactBundleManifest>(&fs::read(manifest_path)?)?;
        validate_migration_against_manifest(&package, &manifest)?;
    }
    if cursor > package.semantic.event_log_cursor {
        return Err(format!(
            "requested cursor {} exceeds package cursor {}",
            cursor, package.semantic.event_log_cursor
        )
        .into());
    }
    if json {
        print_replay_json(cursor, &package)?;
        return Ok(());
    }
    println!(
        "replay plan accepted package={} format={} cursor={} guest_isa={} scheduler_cursor={} random_epoch={}",
        package.package_id,
        package.package_format,
        cursor,
        package.guest.canonical_isa,
        package.substrate_boundary.scheduler_decision_cursor,
        package.substrate_boundary.random_epoch
    );
    println!(
        "replay imports: waits={} resources={} fastpath={}/{} sockets={} rx_bytes={}",
        package.semantic.pending_wait_count,
        package.semantic.resource_count,
        package.semantic.active_fast_path_plan_count,
        package.semantic.fast_path_plan_count,
        package.semantic.network_socket_count,
        package.semantic.network_rx_queue_bytes
    );
    println!(
        "replay roots: harts={} tasks={} resources={} authorities={} stores={} caps={} target_stores={} target_caps={} boundaries={} artifacts={} activations={} executor_transitions={} target_artifacts={} code_objects={} activation_records={} traps={} hostcalls={} migration_objects={} smp_cleanup_quiescence={} smp_snapshot_barriers={} smp_stress_runs={} smp_scaling_benchmarks={} devices={} queues={} descriptors={} dma_buffers={} mmio_regions={} irq_lines={} irq_events={} device_capabilities={} driver_store_bindings={} io_waits={} io_cleanups={} io_fault_injections={} io_validation_reports={} packet_devices={} packet_buffers={} packet_queues={} packet_descriptors={} fake_net_backends={} virtio_net_backends={} network_tx_completions={} network_stack_adapters={} socket_objects={} endpoint_objects={} socket_operations={} socket_waits={} network_backpressures={} network_driver_cleanups={} network_generation_audits={} network_fault_injections={} network_benchmarks={} network_recovery_benchmarks={} block_devices={} block_ranges={} block_requests={} block_completions={} block_waits={} fake_block_backends={} virtio_blk_backends={} block_read_paths={} block_write_paths={} block_request_queues={} block_dma_buffers={} block_page_objects={} buffer_cache_objects={} file_objects={} directory_objects={} fat_adapter_objects={} ext4_adapter_objects={} file_handle_capabilities={} fs_waits={} block_driver_cleanups={} block_recovery_benchmarks={} target_feature_sets={} substrate_events={} command_results={} interface_events={} event_tail={}",
        package.semantic.roots.hart_roots.len(),
        package.semantic.roots.task_roots.len(),
        package.semantic.roots.resource_roots.len(),
        package.semantic.roots.authority_roots.len(),
        package.semantic.roots.store_roots.len(),
        package.semantic.roots.capability_roots.len(),
        package.semantic.roots.target_store_record_roots.len(),
        package.semantic.roots.target_capability_record_roots.len(),
        package.semantic.roots.boundary_roots.len(),
        package.semantic.roots.artifact_verification_roots.len(),
        package.semantic.roots.store_activation_roots.len(),
        package.semantic.roots.executor_transition_roots.len(),
        package.semantic.roots.target_artifact_roots.len(),
        package.semantic.roots.code_object_roots.len(),
        package.semantic.roots.activation_record_roots.len(),
        package.semantic.roots.trap_roots.len(),
        package.semantic.roots.hostcall_trace_roots.len(),
        package.semantic.roots.migration_object_roots.len(),
        package.semantic.roots.smp_cleanup_quiescence_roots.len(),
        package.semantic.roots.smp_snapshot_barrier_roots.len(),
        package.semantic.roots.smp_stress_run_roots.len(),
        package.semantic.roots.smp_scaling_benchmark_roots.len(),
        package.semantic.roots.device_object_roots.len(),
        package.semantic.roots.queue_object_roots.len(),
        package.semantic.roots.descriptor_object_roots.len(),
        package.semantic.roots.dma_buffer_object_roots.len(),
        package.semantic.roots.mmio_region_object_roots.len(),
        package.semantic.roots.irq_line_object_roots.len(),
        package.semantic.roots.irq_event_roots.len(),
        package.semantic.roots.device_capability_roots.len(),
        package.semantic.roots.driver_store_binding_roots.len(),
        package.semantic.roots.io_wait_roots.len(),
        package.semantic.roots.io_cleanup_roots.len(),
        package.semantic.roots.io_fault_injection_roots.len(),
        package.semantic.roots.io_validation_report_roots.len(),
        package.semantic.roots.packet_device_object_roots.len(),
        package.semantic.roots.packet_buffer_object_roots.len(),
        package.semantic.roots.packet_queue_object_roots.len(),
        package.semantic.roots.packet_descriptor_object_roots.len(),
        package.semantic.roots.fake_net_backend_object_roots.len(),
        package.semantic.roots.virtio_net_backend_object_roots.len(),
        package.semantic.roots.network_tx_completion_roots.len(),
        package.semantic.roots.network_stack_adapter_roots.len(),
        package.semantic.roots.socket_object_roots.len(),
        package.semantic.roots.endpoint_object_roots.len(),
        package.semantic.roots.socket_operation_roots.len(),
        package.semantic.roots.socket_wait_roots.len(),
        package.semantic.roots.network_backpressure_roots.len(),
        package.semantic.roots.network_driver_cleanup_roots.len(),
        package.semantic.roots.network_generation_audit_roots.len(),
        package.semantic.roots.network_fault_injection_roots.len(),
        package.semantic.roots.network_benchmark_roots.len(),
        package.semantic.roots.network_recovery_benchmark_roots.len(),
        package.semantic.roots.block_device_object_roots.len(),
        package.semantic.roots.block_range_object_roots.len(),
        package.semantic.roots.block_request_object_roots.len(),
        package.semantic.roots.block_completion_object_roots.len(),
        package.semantic.roots.block_wait_roots.len(),
        package.semantic.roots.fake_block_backend_object_roots.len(),
        package.semantic.roots.virtio_blk_backend_object_roots.len(),
        package.semantic.roots.block_read_path_roots.len(),
        package.semantic.roots.block_write_path_roots.len(),
        package.semantic.roots.block_request_queue_roots.len(),
        package.semantic.roots.block_dma_buffer_roots.len(),
        package.semantic.roots.block_page_object_roots.len(),
        package.semantic.roots.buffer_cache_object_roots.len(),
        package.semantic.roots.file_object_roots.len(),
        package.semantic.roots.directory_object_roots.len(),
        package.semantic.roots.fat_adapter_object_roots.len(),
        package.semantic.roots.ext4_adapter_object_roots.len(),
        package.semantic.roots.file_handle_capability_roots.len(),
        package.semantic.roots.fs_wait_roots.len(),
        package.semantic.roots.block_driver_cleanup_roots.len(),
        package.semantic.roots.block_recovery_benchmark_roots.len(),
        package.semantic.roots.target_feature_set_roots.len(),
        package.semantic.roots.substrate_event_roots.len(),
        package.semantic.roots.command_result_roots.len(),
        package.semantic.roots.interface_event_roots.len(),
        package.semantic.roots.event_log_tail.len()
    );
    for boundary in &package.semantic.roots.boundary_roots {
        println!("replay boundary {boundary}");
    }
    for artifact in &package.semantic.roots.artifact_verification_roots {
        println!("replay artifact {artifact}");
    }
    for activation in &package.semantic.roots.store_activation_roots {
        println!("replay activation {activation}");
    }
    for transition in &package.semantic.roots.executor_transition_roots {
        println!("replay executor {transition}");
    }
    for artifact in &package.semantic.roots.target_artifact_roots {
        println!("replay target-artifact {artifact}");
    }
    for code in &package.semantic.roots.code_object_roots {
        println!("replay code-object {code}");
    }
    for store in &package.semantic.roots.target_store_record_roots {
        println!("replay target-store {store}");
    }
    for capability in &package.semantic.roots.target_capability_record_roots {
        println!("replay target-capability {capability}");
    }
    for activation in &package.semantic.roots.activation_record_roots {
        println!("replay activation-record {activation}");
    }
    for trap in &package.semantic.roots.trap_roots {
        println!("replay trap {trap}");
    }
    for hostcall in &package.semantic.roots.hostcall_trace_roots {
        println!("replay hostcall {hostcall}");
    }
    for object in &package.semantic.roots.migration_object_roots {
        println!("replay migration-object {object}");
    }
    for quiescence in &package.semantic.roots.smp_cleanup_quiescence_roots {
        println!("replay smp-cleanup-quiescence {quiescence}");
    }
    for barrier in &package.semantic.roots.smp_snapshot_barrier_roots {
        println!("replay smp-snapshot-barrier {barrier}");
    }
    for run in &package.semantic.roots.smp_stress_run_roots {
        println!("replay smp-stress-run {run}");
    }
    for benchmark in &package.semantic.roots.smp_scaling_benchmark_roots {
        println!("replay smp-scaling-benchmark {benchmark}");
    }
    for integrated in &package.semantic.roots.integrated_smp_preemption_cleanup_roots {
        println!("replay integrated-smp-preemption-cleanup {integrated}");
    }
    for integrated in &package.semantic.roots.integrated_smp_network_fault_roots {
        println!("replay integrated-smp-network-fault {integrated}");
    }
    for integrated in &package.semantic.roots.integrated_disk_preempt_fault_roots {
        println!("replay integrated-disk-preempt-fault {integrated}");
    }
    for integrated in &package.semantic.roots.integrated_simd_migration_roots {
        println!("replay integrated-simd-migration {integrated}");
    }
    for integrated in &package.semantic.roots.integrated_network_disk_io_roots {
        println!("replay integrated-network-disk-io {integrated}");
    }
    for integrated in &package.semantic.roots.integrated_display_scheduler_load_roots {
        println!("replay integrated-display-scheduler-load {integrated}");
    }
    for integrated in &package.semantic.roots.integrated_snapshot_io_lease_barrier_roots {
        println!("replay integrated-snapshot-io-lease-barrier {integrated}");
    }
    for integrated in &package.semantic.roots.integrated_code_publish_smp_workload_roots {
        println!("replay integrated-code-publish-smp-workload {integrated}");
    }
    for integrated in &package.semantic.roots.integrated_display_panic_roots {
        println!("replay integrated-display-panic {integrated}");
    }
    for integrated in &package.semantic.roots.integrated_osctl_trace_replay_roots {
        println!("replay integrated-osctl-trace-replay {integrated}");
    }
    for device in &package.semantic.roots.device_object_roots {
        println!("replay device {device}");
    }
    for queue in &package.semantic.roots.queue_object_roots {
        println!("replay queue {queue}");
    }
    for descriptor in &package.semantic.roots.descriptor_object_roots {
        println!("replay descriptor {descriptor}");
    }
    for dma_buffer in &package.semantic.roots.dma_buffer_object_roots {
        println!("replay dma-buffer {dma_buffer}");
    }
    for mmio_region in &package.semantic.roots.mmio_region_object_roots {
        println!("replay mmio-region {mmio_region}");
    }
    for irq_line in &package.semantic.roots.irq_line_object_roots {
        println!("replay irq-line {irq_line}");
    }
    for irq_event in &package.semantic.roots.irq_event_roots {
        println!("replay irq-event {irq_event}");
    }
    for device_capability in &package.semantic.roots.device_capability_roots {
        println!("replay device-capability {device_capability}");
    }
    for binding in &package.semantic.roots.driver_store_binding_roots {
        println!("replay driver-store-binding {binding}");
    }
    for io_wait in &package.semantic.roots.io_wait_roots {
        println!("replay io-wait {io_wait}");
    }
    for cleanup in &package.semantic.roots.io_cleanup_roots {
        println!("replay io-cleanup {cleanup}");
    }
    for fault in &package.semantic.roots.io_fault_injection_roots {
        println!("replay io-fault-injection {fault}");
    }
    for report in &package.semantic.roots.io_validation_report_roots {
        println!("replay io-validation-report {report}");
    }
    for packet_device in &package.semantic.roots.packet_device_object_roots {
        println!("replay packet-device {packet_device}");
    }
    for block_device in &package.semantic.roots.block_device_object_roots {
        println!("replay block-device {block_device}");
    }
    for block_range in &package.semantic.roots.block_range_object_roots {
        println!("replay block-range {block_range}");
    }
    for request in &package.semantic.roots.block_request_object_roots {
        println!("replay block-request {request}");
    }
    for completion in &package.semantic.roots.block_completion_object_roots {
        println!("replay block-completion {completion}");
    }
    for block_wait in &package.semantic.roots.block_wait_roots {
        println!("replay block-wait {block_wait}");
    }
    for backend in &package.semantic.roots.fake_block_backend_object_roots {
        println!("replay fake-block-backend {backend}");
    }
    for backend in &package.semantic.roots.virtio_blk_backend_object_roots {
        println!("replay virtio-blk-backend {backend}");
    }
    for path in &package.semantic.roots.block_read_path_roots {
        println!("replay block-read-path {path}");
    }
    for path in &package.semantic.roots.block_write_path_roots {
        println!("replay block-write-path {path}");
    }
    for queue in &package.semantic.roots.block_request_queue_roots {
        println!("replay block-request-queue {queue}");
    }
    for buffer in &package.semantic.roots.block_dma_buffer_roots {
        println!("replay block-dma-buffer {buffer}");
    }
    for page in &package.semantic.roots.block_page_object_roots {
        println!("replay block-page-object {page}");
    }
    for cache in &package.semantic.roots.buffer_cache_object_roots {
        println!("replay buffer-cache-object {cache}");
    }
    for file in &package.semantic.roots.file_object_roots {
        println!("replay file-object {file}");
    }
    for directory in &package.semantic.roots.directory_object_roots {
        println!("replay directory-object {directory}");
    }
    for adapter in &package.semantic.roots.fat_adapter_object_roots {
        println!("replay fat-adapter-object {adapter}");
    }
    for adapter in &package.semantic.roots.ext4_adapter_object_roots {
        println!("replay ext4-adapter-object {adapter}");
    }
    for capability in &package.semantic.roots.file_handle_capability_roots {
        println!("replay file-handle-capability {capability}");
    }
    for wait in &package.semantic.roots.fs_wait_roots {
        println!("replay fs-wait {wait}");
    }
    for cleanup in &package.semantic.roots.block_driver_cleanup_roots {
        println!("replay block-driver-cleanup {cleanup}");
    }
    for policy in &package.semantic.roots.block_pending_io_policy_roots {
        println!("replay block-pending-io-policy {policy}");
    }
    for audit in &package.semantic.roots.block_request_generation_audit_roots {
        println!("replay block-request-generation-audit {audit}");
    }
    for benchmark in &package.semantic.roots.block_benchmark_roots {
        println!("replay block-benchmark {benchmark}");
    }
    for benchmark in &package.semantic.roots.block_recovery_benchmark_roots {
        println!("replay block-recovery-benchmark {benchmark}");
    }
    for feature in &package.semantic.roots.target_feature_set_roots {
        println!("replay target-feature-set {feature}");
    }
    for packet_buffer in &package.semantic.roots.packet_buffer_object_roots {
        println!("replay packet-buffer {packet_buffer}");
    }
    for packet_queue in &package.semantic.roots.packet_queue_object_roots {
        println!("replay packet-queue {packet_queue}");
    }
    for packet_descriptor in &package.semantic.roots.packet_descriptor_object_roots {
        println!("replay packet-descriptor {packet_descriptor}");
    }
    for backend in &package.semantic.roots.fake_net_backend_object_roots {
        println!("replay fake-net-backend {backend}");
    }
    for backend in &package.semantic.roots.virtio_net_backend_object_roots {
        println!("replay virtio-net-backend {backend}");
    }
    for rx in &package.semantic.roots.network_rx_interrupt_roots {
        println!("replay network-rx-interrupt {rx}");
    }
    for resolution in &package.semantic.roots.network_rx_wait_resolution_roots {
        println!("replay network-rx-wait-resolution {resolution}");
    }
    for gate in &package.semantic.roots.network_tx_capability_gate_roots {
        println!("replay network-tx-capability-gate {gate}");
    }
    for completion in &package.semantic.roots.network_tx_completion_roots {
        println!("replay network-tx-completion {completion}");
    }
    for adapter in &package.semantic.roots.network_stack_adapter_roots {
        println!("replay network-stack-adapter {adapter}");
    }
    for socket in &package.semantic.roots.socket_object_roots {
        println!("replay socket-object {socket}");
    }
    for endpoint in &package.semantic.roots.endpoint_object_roots {
        println!("replay endpoint-object {endpoint}");
    }
    for operation in &package.semantic.roots.socket_operation_roots {
        println!("replay socket-operation {operation}");
    }
    for wait in &package.semantic.roots.socket_wait_roots {
        println!("replay socket-wait {wait}");
    }
    for backpressure in &package.semantic.roots.network_backpressure_roots {
        println!("replay network-backpressure {backpressure}");
    }
    for cleanup in &package.semantic.roots.network_driver_cleanup_roots {
        println!("replay network-driver-cleanup {cleanup}");
    }
    for audit in &package.semantic.roots.network_generation_audit_roots {
        println!("replay network-generation-audit {audit}");
    }
    for injection in &package.semantic.roots.network_fault_injection_roots {
        println!("replay network-fault-injection {injection}");
    }
    for benchmark in &package.semantic.roots.network_benchmark_roots {
        println!("replay network-benchmark {benchmark}");
    }
    for benchmark in &package.semantic.roots.network_recovery_benchmark_roots {
        println!("replay network-recovery-benchmark {benchmark}");
    }
    Ok(())
}

pub(crate) fn print_replay_json(
    cursor: u64,
    package: &MigrationPackageManifest,
) -> Result<(), Box<dyn Error>> {
    let mut roots = serde_json::Map::new();
    roots.insert("tasks".to_owned(), serde_json::json!(package.semantic.roots.task_roots.len()));
    roots.insert(
        "timer_interrupts".to_owned(),
        serde_json::json!(package.semantic.roots.timer_interrupt_roots.len()),
    );
    roots.insert(
        "ipi_events".to_owned(),
        serde_json::json!(package.semantic.roots.ipi_event_roots.len()),
    );
    roots.insert(
        "remote_preempts".to_owned(),
        serde_json::json!(package.semantic.roots.remote_preempt_roots.len()),
    );
    roots.insert(
        "remote_parks".to_owned(),
        serde_json::json!(package.semantic.roots.remote_park_roots.len()),
    );
    roots.insert(
        "cross_hart_scheduler_decisions".to_owned(),
        serde_json::json!(package.semantic.roots.cross_hart_scheduler_decision_roots.len()),
    );
    roots.insert(
        "activation_migrations".to_owned(),
        serde_json::json!(package.semantic.roots.activation_migration_roots.len()),
    );
    roots.insert(
        "smp_safe_points".to_owned(),
        serde_json::json!(package.semantic.roots.smp_safe_point_roots.len()),
    );
    roots.insert(
        "stop_the_world_rendezvous".to_owned(),
        serde_json::json!(package.semantic.roots.stop_the_world_rendezvous_roots.len()),
    );
    roots.insert(
        "smp_code_publish_barriers".to_owned(),
        serde_json::json!(package.semantic.roots.smp_code_publish_barrier_roots.len()),
    );
    roots.insert(
        "smp_cleanup_quiescence".to_owned(),
        serde_json::json!(package.semantic.roots.smp_cleanup_quiescence_roots.len()),
    );
    roots.insert(
        "smp_snapshot_barriers".to_owned(),
        serde_json::json!(package.semantic.roots.smp_snapshot_barrier_roots.len()),
    );
    roots.insert(
        "smp_stress_runs".to_owned(),
        serde_json::json!(package.semantic.roots.smp_stress_run_roots.len()),
    );
    roots.insert(
        "smp_scaling_benchmarks".to_owned(),
        serde_json::json!(package.semantic.roots.smp_scaling_benchmark_roots.len()),
    );
    roots.insert(
        "devices".to_owned(),
        serde_json::json!(package.semantic.roots.device_object_roots.len()),
    );
    roots.insert(
        "queues".to_owned(),
        serde_json::json!(package.semantic.roots.queue_object_roots.len()),
    );
    roots.insert(
        "descriptors".to_owned(),
        serde_json::json!(package.semantic.roots.descriptor_object_roots.len()),
    );
    roots.insert(
        "dma_buffers".to_owned(),
        serde_json::json!(package.semantic.roots.dma_buffer_object_roots.len()),
    );
    roots.insert(
        "mmio_regions".to_owned(),
        serde_json::json!(package.semantic.roots.mmio_region_object_roots.len()),
    );
    roots.insert(
        "irq_lines".to_owned(),
        serde_json::json!(package.semantic.roots.irq_line_object_roots.len()),
    );
    roots.insert(
        "irq_events".to_owned(),
        serde_json::json!(package.semantic.roots.irq_event_roots.len()),
    );
    roots.insert(
        "device_capabilities".to_owned(),
        serde_json::json!(package.semantic.roots.device_capability_roots.len()),
    );
    roots.insert(
        "driver_store_bindings".to_owned(),
        serde_json::json!(package.semantic.roots.driver_store_binding_roots.len()),
    );
    roots.insert(
        "io_waits".to_owned(),
        serde_json::json!(package.semantic.roots.io_wait_roots.len()),
    );
    roots.insert(
        "io_cleanups".to_owned(),
        serde_json::json!(package.semantic.roots.io_cleanup_roots.len()),
    );
    roots.insert(
        "io_fault_injections".to_owned(),
        serde_json::json!(package.semantic.roots.io_fault_injection_roots.len()),
    );
    roots.insert(
        "io_validation_reports".to_owned(),
        serde_json::json!(package.semantic.roots.io_validation_report_roots.len()),
    );
    roots.insert(
        "packet_devices".to_owned(),
        serde_json::json!(package.semantic.roots.packet_device_object_roots.len()),
    );
    roots.insert(
        "packet_buffers".to_owned(),
        serde_json::json!(package.semantic.roots.packet_buffer_object_roots.len()),
    );
    roots.insert(
        "packet_queues".to_owned(),
        serde_json::json!(package.semantic.roots.packet_queue_object_roots.len()),
    );
    roots.insert(
        "packet_descriptors".to_owned(),
        serde_json::json!(package.semantic.roots.packet_descriptor_object_roots.len()),
    );
    roots.insert(
        "fake_net_backends".to_owned(),
        serde_json::json!(package.semantic.roots.fake_net_backend_object_roots.len()),
    );
    roots.insert(
        "virtio_net_backends".to_owned(),
        serde_json::json!(package.semantic.roots.virtio_net_backend_object_roots.len()),
    );
    roots.insert(
        "network_rx_interrupts".to_owned(),
        serde_json::json!(package.semantic.roots.network_rx_interrupt_roots.len()),
    );
    roots.insert(
        "network_rx_wait_resolutions".to_owned(),
        serde_json::json!(package.semantic.roots.network_rx_wait_resolution_roots.len()),
    );
    roots.insert(
        "network_tx_capability_gates".to_owned(),
        serde_json::json!(package.semantic.roots.network_tx_capability_gate_roots.len()),
    );
    roots.insert(
        "network_tx_completions".to_owned(),
        serde_json::json!(package.semantic.roots.network_tx_completion_roots.len()),
    );
    roots.insert(
        "network_stack_adapters".to_owned(),
        serde_json::json!(package.semantic.roots.network_stack_adapter_roots.len()),
    );
    roots.insert(
        "socket_objects".to_owned(),
        serde_json::json!(package.semantic.roots.socket_object_roots.len()),
    );
    roots.insert(
        "endpoint_objects".to_owned(),
        serde_json::json!(package.semantic.roots.endpoint_object_roots.len()),
    );
    roots.insert(
        "socket_operations".to_owned(),
        serde_json::json!(package.semantic.roots.socket_operation_roots.len()),
    );
    roots.insert(
        "socket_waits".to_owned(),
        serde_json::json!(package.semantic.roots.socket_wait_roots.len()),
    );
    roots.insert(
        "network_backpressures".to_owned(),
        serde_json::json!(package.semantic.roots.network_backpressure_roots.len()),
    );
    roots.insert(
        "network_driver_cleanups".to_owned(),
        serde_json::json!(package.semantic.roots.network_driver_cleanup_roots.len()),
    );
    roots.insert(
        "network_generation_audits".to_owned(),
        serde_json::json!(package.semantic.roots.network_generation_audit_roots.len()),
    );
    roots.insert(
        "network_fault_injections".to_owned(),
        serde_json::json!(package.semantic.roots.network_fault_injection_roots.len()),
    );
    roots.insert(
        "network_benchmarks".to_owned(),
        serde_json::json!(package.semantic.roots.network_benchmark_roots.len()),
    );
    roots.insert(
        "network_recovery_benchmarks".to_owned(),
        serde_json::json!(package.semantic.roots.network_recovery_benchmark_roots.len()),
    );
    roots.insert(
        "block_devices".to_owned(),
        serde_json::json!(package.semantic.roots.block_device_object_roots.len()),
    );
    roots.insert(
        "block_ranges".to_owned(),
        serde_json::json!(package.semantic.roots.block_range_object_roots.len()),
    );
    roots.insert(
        "block_requests".to_owned(),
        serde_json::json!(package.semantic.roots.block_request_object_roots.len()),
    );
    roots.insert(
        "block_completions".to_owned(),
        serde_json::json!(package.semantic.roots.block_completion_object_roots.len()),
    );
    roots.insert(
        "block_waits".to_owned(),
        serde_json::json!(package.semantic.roots.block_wait_roots.len()),
    );
    roots.insert(
        "fake_block_backends".to_owned(),
        serde_json::json!(package.semantic.roots.fake_block_backend_object_roots.len()),
    );
    roots.insert(
        "virtio_blk_backends".to_owned(),
        serde_json::json!(package.semantic.roots.virtio_blk_backend_object_roots.len()),
    );
    roots.insert(
        "block_read_paths".to_owned(),
        serde_json::json!(package.semantic.roots.block_read_path_roots.len()),
    );
    roots.insert(
        "block_write_paths".to_owned(),
        serde_json::json!(package.semantic.roots.block_write_path_roots.len()),
    );
    roots.insert(
        "block_request_queues".to_owned(),
        serde_json::json!(package.semantic.roots.block_request_queue_roots.len()),
    );
    roots.insert(
        "block_dma_buffers".to_owned(),
        serde_json::json!(package.semantic.roots.block_dma_buffer_roots.len()),
    );
    roots.insert(
        "block_page_objects".to_owned(),
        serde_json::json!(package.semantic.roots.block_page_object_roots.len()),
    );
    roots.insert(
        "buffer_cache_objects".to_owned(),
        serde_json::json!(package.semantic.roots.buffer_cache_object_roots.len()),
    );
    roots.insert(
        "file_objects".to_owned(),
        serde_json::json!(package.semantic.roots.file_object_roots.len()),
    );
    roots.insert(
        "directory_objects".to_owned(),
        serde_json::json!(package.semantic.roots.directory_object_roots.len()),
    );
    roots.insert(
        "fat_adapter_objects".to_owned(),
        serde_json::json!(package.semantic.roots.fat_adapter_object_roots.len()),
    );
    roots.insert(
        "ext4_adapter_objects".to_owned(),
        serde_json::json!(package.semantic.roots.ext4_adapter_object_roots.len()),
    );
    roots.insert(
        "file_handle_capabilities".to_owned(),
        serde_json::json!(package.semantic.roots.file_handle_capability_roots.len()),
    );
    roots.insert(
        "fs_waits".to_owned(),
        serde_json::json!(package.semantic.roots.fs_wait_roots.len()),
    );
    roots.insert(
        "block_driver_cleanups".to_owned(),
        serde_json::json!(package.semantic.roots.block_driver_cleanup_roots.len()),
    );
    roots.insert(
        "block_pending_io_policies".to_owned(),
        serde_json::json!(package.semantic.roots.block_pending_io_policy_roots.len()),
    );
    roots.insert(
        "block_request_generation_audits".to_owned(),
        serde_json::json!(package.semantic.roots.block_request_generation_audit_roots.len()),
    );
    roots.insert(
        "block_benchmarks".to_owned(),
        serde_json::json!(package.semantic.roots.block_benchmark_roots.len()),
    );
    roots.insert(
        "block_recovery_benchmarks".to_owned(),
        serde_json::json!(package.semantic.roots.block_recovery_benchmark_roots.len()),
    );
    roots.insert(
        "target_feature_sets".to_owned(),
        serde_json::json!(package.semantic.roots.target_feature_set_roots.len()),
    );
    roots.insert(
        "resources".to_owned(),
        serde_json::json!(package.semantic.roots.resource_roots.len()),
    );
    roots.insert(
        "authorities".to_owned(),
        serde_json::json!(package.semantic.roots.authority_roots.len()),
    );
    roots.insert("stores".to_owned(), serde_json::json!(package.semantic.roots.store_roots.len()));
    roots.insert(
        "capabilities".to_owned(),
        serde_json::json!(package.semantic.roots.capability_roots.len()),
    );
    roots.insert(
        "target_stores".to_owned(),
        serde_json::json!(package.semantic.roots.target_store_record_roots.len()),
    );
    roots.insert(
        "target_capabilities".to_owned(),
        serde_json::json!(package.semantic.roots.target_capability_record_roots.len()),
    );
    roots.insert(
        "boundaries".to_owned(),
        serde_json::json!(package.semantic.roots.boundary_roots.len()),
    );
    roots.insert(
        "artifacts".to_owned(),
        serde_json::json!(package.semantic.roots.artifact_verification_roots.len()),
    );
    roots.insert(
        "activations".to_owned(),
        serde_json::json!(package.semantic.roots.store_activation_roots.len()),
    );
    roots.insert(
        "executor_transitions".to_owned(),
        serde_json::json!(package.semantic.roots.executor_transition_roots.len()),
    );
    roots.insert(
        "target_artifacts".to_owned(),
        serde_json::json!(package.semantic.roots.target_artifact_roots.len()),
    );
    roots.insert(
        "code_objects".to_owned(),
        serde_json::json!(package.semantic.roots.code_object_roots.len()),
    );
    roots.insert(
        "activation_records".to_owned(),
        serde_json::json!(package.semantic.roots.activation_record_roots.len()),
    );
    roots.insert("traps".to_owned(), serde_json::json!(package.semantic.roots.trap_roots.len()));
    roots.insert(
        "hostcalls".to_owned(),
        serde_json::json!(package.semantic.roots.hostcall_trace_roots.len()),
    );
    roots.insert(
        "migration_objects".to_owned(),
        serde_json::json!(package.semantic.roots.migration_object_roots.len()),
    );
    roots.insert(
        "tombstones".to_owned(),
        serde_json::json!(package.semantic.roots.tombstone_roots.len()),
    );
    roots.insert(
        "contract_violations".to_owned(),
        serde_json::json!(package.semantic.roots.contract_violation_roots.len()),
    );
    roots.insert(
        "cleanup".to_owned(),
        serde_json::json!(package.semantic.roots.cleanup_roots.len()),
    );
    roots.insert(
        "activation_cleanup".to_owned(),
        serde_json::json!(package.semantic.roots.activation_cleanup_roots.len()),
    );
    roots.insert(
        "preemption_latency".to_owned(),
        serde_json::json!(package.semantic.roots.preemption_latency_roots.len()),
    );
    roots.insert(
        "hart_event_attribution".to_owned(),
        serde_json::json!(package.semantic.roots.hart_event_attribution_roots.len()),
    );
    roots.insert(
        "memory_policies".to_owned(),
        serde_json::json!(package.semantic.roots.memory_policy_roots.len()),
    );
    roots.insert(
        "snapshot_validation".to_owned(),
        serde_json::json!(package.semantic.roots.snapshot_validation_roots.len()),
    );
    roots.insert(
        "replay_validation".to_owned(),
        serde_json::json!(package.semantic.roots.replay_validation_roots.len()),
    );
    roots.insert(
        "substrate_events".to_owned(),
        serde_json::json!(package.semantic.roots.substrate_event_roots.len()),
    );
    roots.insert(
        "command_results".to_owned(),
        serde_json::json!(package.semantic.roots.command_result_roots.len()),
    );
    roots.insert(
        "interface_events".to_owned(),
        serde_json::json!(package.semantic.roots.interface_event_roots.len()),
    );
    roots.insert(
        "event_tail".to_owned(),
        serde_json::json!(package.semantic.roots.event_log_tail.len()),
    );
    roots.insert(
        "boundary_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.boundary_roots),
    );
    roots.insert(
        "artifact_verification_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.artifact_verification_roots),
    );
    roots.insert(
        "store_activation_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.store_activation_roots),
    );
    roots.insert(
        "executor_transition_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.executor_transition_roots),
    );
    roots.insert(
        "target_artifact_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.target_artifact_roots),
    );
    roots.insert(
        "target_store_record_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.target_store_record_roots),
    );
    roots.insert(
        "target_capability_record_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.target_capability_record_roots),
    );
    roots.insert(
        "code_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.code_object_roots),
    );
    roots.insert(
        "activation_record_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.activation_record_roots),
    );
    roots.insert("trap_roots".to_owned(), serde_json::json!(&package.semantic.roots.trap_roots));
    roots.insert(
        "hostcall_trace_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.hostcall_trace_roots),
    );
    roots.insert(
        "migration_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.migration_object_roots),
    );
    roots.insert(
        "tombstone_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.tombstone_roots),
    );
    roots.insert(
        "contract_violation_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.contract_violation_roots),
    );
    roots.insert(
        "timer_interrupt_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.timer_interrupt_roots),
    );
    roots.insert(
        "ipi_event_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.ipi_event_roots),
    );
    roots.insert(
        "remote_preempt_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.remote_preempt_roots),
    );
    roots.insert(
        "remote_park_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.remote_park_roots),
    );
    roots.insert(
        "cross_hart_scheduler_decision_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.cross_hart_scheduler_decision_roots),
    );
    roots.insert(
        "activation_migration_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.activation_migration_roots),
    );
    roots.insert(
        "smp_safe_point_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_safe_point_roots),
    );
    roots.insert(
        "stop_the_world_rendezvous_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.stop_the_world_rendezvous_roots),
    );
    roots.insert(
        "smp_code_publish_barrier_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_code_publish_barrier_roots),
    );
    roots.insert(
        "smp_cleanup_quiescence_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_cleanup_quiescence_roots),
    );
    roots.insert(
        "smp_snapshot_barrier_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_snapshot_barrier_roots),
    );
    roots.insert(
        "smp_stress_run_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_stress_run_roots),
    );
    roots.insert(
        "smp_scaling_benchmark_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.smp_scaling_benchmark_roots),
    );
    roots.insert(
        "device_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.device_object_roots),
    );
    roots.insert(
        "queue_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.queue_object_roots),
    );
    roots.insert(
        "descriptor_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.descriptor_object_roots),
    );
    roots.insert(
        "dma_buffer_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.dma_buffer_object_roots),
    );
    roots.insert(
        "mmio_region_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.mmio_region_object_roots),
    );
    roots.insert(
        "irq_line_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.irq_line_object_roots),
    );
    roots.insert(
        "irq_event_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.irq_event_roots),
    );
    roots.insert(
        "device_capability_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.device_capability_roots),
    );
    roots.insert(
        "driver_store_binding_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.driver_store_binding_roots),
    );
    roots.insert(
        "cleanup_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.cleanup_roots),
    );
    roots.insert(
        "activation_cleanup_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.activation_cleanup_roots),
    );
    roots.insert(
        "preemption_latency_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.preemption_latency_roots),
    );
    roots.insert(
        "hart_event_attribution_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.hart_event_attribution_roots),
    );
    roots.insert(
        "memory_policy_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.memory_policy_roots),
    );
    roots.insert(
        "snapshot_validation_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.snapshot_validation_roots),
    );
    roots.insert(
        "replay_validation_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.replay_validation_roots),
    );
    roots.insert(
        "substrate_event_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.substrate_event_roots),
    );
    roots.insert(
        "command_result_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.command_result_roots),
    );
    roots.insert(
        "interface_event_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.interface_event_roots),
    );
    roots.insert(
        "socket_operation_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.socket_operation_roots),
    );
    roots.insert(
        "socket_wait_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.socket_wait_roots),
    );
    roots.insert(
        "network_backpressure_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_backpressure_roots),
    );
    roots.insert(
        "network_driver_cleanup_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_driver_cleanup_roots),
    );
    roots.insert(
        "network_generation_audit_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_generation_audit_roots),
    );
    roots.insert(
        "network_fault_injection_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_fault_injection_roots),
    );
    roots.insert(
        "network_benchmark_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_benchmark_roots),
    );
    roots.insert(
        "network_recovery_benchmark_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.network_recovery_benchmark_roots),
    );
    roots.insert(
        "block_device_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_device_object_roots),
    );
    roots.insert(
        "block_range_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_range_object_roots),
    );
    roots.insert(
        "block_request_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_request_object_roots),
    );
    roots.insert(
        "block_completion_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_completion_object_roots),
    );
    roots.insert(
        "block_wait_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_wait_roots),
    );
    roots.insert(
        "fake_block_backend_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.fake_block_backend_object_roots),
    );
    roots.insert(
        "virtio_blk_backend_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.virtio_blk_backend_object_roots),
    );
    roots.insert(
        "block_read_path_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_read_path_roots),
    );
    roots.insert(
        "block_write_path_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_write_path_roots),
    );
    roots.insert(
        "block_request_queue_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_request_queue_roots),
    );
    roots.insert(
        "block_dma_buffer_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_dma_buffer_roots),
    );
    roots.insert(
        "block_page_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_page_object_roots),
    );
    roots.insert(
        "buffer_cache_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.buffer_cache_object_roots),
    );
    roots.insert(
        "file_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.file_object_roots),
    );
    roots.insert(
        "directory_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.directory_object_roots),
    );
    roots.insert(
        "fat_adapter_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.fat_adapter_object_roots),
    );
    roots.insert(
        "ext4_adapter_object_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.ext4_adapter_object_roots),
    );
    roots.insert(
        "file_handle_capability_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.file_handle_capability_roots),
    );
    roots.insert(
        "fs_wait_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.fs_wait_roots),
    );
    roots.insert(
        "block_driver_cleanup_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_driver_cleanup_roots),
    );
    roots.insert(
        "block_pending_io_policy_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_pending_io_policy_roots),
    );
    roots.insert(
        "block_request_generation_audit_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_request_generation_audit_roots),
    );
    roots.insert(
        "block_benchmark_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_benchmark_roots),
    );
    roots.insert(
        "block_recovery_benchmark_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.block_recovery_benchmark_roots),
    );
    roots.insert(
        "target_feature_set_roots".to_owned(),
        serde_json::json!(&package.semantic.roots.target_feature_set_roots),
    );

    let value = serde_json::json!({
        "status": "accepted",
        "package": package.package_id,
        "format": package.package_format,
        "cursor": cursor,
        "guest_isa": package.guest.canonical_isa,
        "scheduler_cursor": package.substrate_boundary.scheduler_decision_cursor,
        "random_epoch": package.substrate_boundary.random_epoch,
        "imports": {
            "pending_waits": package.semantic.pending_wait_count,
            "resources": package.semantic.resource_count,
            "active_fastpath": package.semantic.active_fast_path_plan_count,
            "fastpath": package.semantic.fast_path_plan_count,
            "sockets": package.semantic.network_socket_count,
            "rx_bytes": package.semantic.network_rx_queue_bytes
        },
        "substrate_boundary": {
            "pending_irq_causes": package.substrate_boundary.pending_irq_causes,
            "pending_dma_completions": package.substrate_boundary.pending_dma_completions,
            "active_dmw_lease_count": package.substrate_boundary.active_dmw_lease_count,
            "active_mmio_authority_count": package.substrate_boundary.active_mmio_authority_count,
            "active_dma_authority_count": package.substrate_boundary.active_dma_authority_count,
            "active_irq_authority_count": package.substrate_boundary.active_irq_authority_count,
            "active_packet_device_authority_count": package.substrate_boundary.active_packet_device_authority_count,
            "active_virtio_queue_authority_count": package.substrate_boundary.active_virtio_queue_authority_count
        },
        "roots": serde_json::Value::Object(roots)
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
