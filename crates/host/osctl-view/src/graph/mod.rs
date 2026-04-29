use super::*;

mod helpers;
mod history;
mod live;

pub(crate) use helpers::*;
pub(crate) use history::*;
pub(crate) use live::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphEdgeMode {
    Roots,
    Live,
    History,
}

impl GraphEdgeMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Roots => "roots",
            Self::Live => "live",
            Self::History => "history",
        }
    }
}

pub fn print_graph(path: &Path, mode: GraphEdgeMode, json: bool) -> Result<(), Box<dyn Error>> {
    let package = serde_json::from_slice::<MigrationPackageManifest>(&fs::read(path)?)?;
    if json || mode != GraphEdgeMode::Roots {
        let edges = graph_edges_for_package(&package, mode);
        if json {
            let value = serde_json::json!({
                "schema": VIEW_SCHEMA_V1,
                "schema_version": OSCTL_JSON_SCHEMA_VERSION,
                "kind": "contract-graph",
                "command": "graph",
                "mode": mode.as_str(),
                "package": package.package_id,
                "edge_count": edges.len(),
                "edges": edges,
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            println!(
                "graph package={} mode={} edges={}",
                package.package_id,
                mode.as_str(),
                edges.len()
            );
            for edge in edges {
                println!("{edge}");
            }
        }
        return Ok(());
    }
    println!(
        "graph package={} cursor={} hart_roots={} task_roots={} resource_roots={} authority_roots={} store_roots={} capability_roots={} target_store_record_roots={} target_capability_record_roots={} fastpath_roots={} boundary_roots={} artifact_verification_roots={} store_activation_roots={} executor_transition_roots={} target_artifact_roots={} code_object_roots={} activation_record_roots={} trap_roots={} hostcall_trace_roots={} migration_object_roots={} tombstone_roots={} contract_violation_roots={} timer_interrupt_roots={} ipi_event_roots={} remote_preempt_roots={} remote_park_roots={} cross_hart_scheduler_decision_roots={} activation_migration_roots={} smp_safe_point_roots={} stop_the_world_rendezvous_roots={} smp_code_publish_barrier_roots={} smp_cleanup_quiescence_roots={} smp_snapshot_barrier_roots={} smp_stress_run_roots={} smp_scaling_benchmark_roots={} device_roots={} queue_roots={} descriptor_roots={} dma_buffer_roots={} mmio_region_roots={} irq_line_roots={} irq_event_roots={} device_capability_roots={} driver_store_binding_roots={} io_wait_roots={} io_cleanup_roots={} io_fault_injection_roots={} io_validation_report_roots={} packet_device_roots={} packet_buffer_roots={} packet_queue_roots={} packet_descriptor_roots={} fake_net_backend_roots={} virtio_net_backend_roots={} socket_wait_roots={} network_backpressure_roots={} network_driver_cleanup_roots={} activation_resume_roots={} activation_wait_roots={} activation_cleanup_roots={} preemption_latency_roots={} hart_event_attribution_roots={}",
        package.package_id,
        package.semantic.event_log_cursor,
        package.semantic.roots.hart_roots.len(),
        package.semantic.roots.task_roots.len(),
        package.semantic.roots.resource_roots.len(),
        package.semantic.roots.authority_roots.len(),
        package.semantic.roots.store_roots.len(),
        package.semantic.roots.capability_roots.len(),
        package.semantic.roots.target_store_record_roots.len(),
        package.semantic.roots.target_capability_record_roots.len(),
        package.semantic.roots.fast_path_roots.len(),
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
        package.semantic.roots.tombstone_roots.len(),
        package.semantic.roots.contract_violation_roots.len(),
        package.semantic.roots.timer_interrupt_roots.len(),
        package.semantic.roots.ipi_event_roots.len(),
        package.semantic.roots.remote_preempt_roots.len(),
        package.semantic.roots.remote_park_roots.len(),
        package.semantic.roots.cross_hart_scheduler_decision_roots.len(),
        package.semantic.roots.activation_migration_roots.len(),
        package.semantic.roots.smp_safe_point_roots.len(),
        package.semantic.roots.stop_the_world_rendezvous_roots.len(),
        package.semantic.roots.smp_code_publish_barrier_roots.len(),
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
        package.semantic.roots.socket_wait_roots.len(),
        package.semantic.roots.network_backpressure_roots.len(),
        package.semantic.roots.network_driver_cleanup_roots.len(),
        package.semantic.roots.activation_resume_roots.len(),
        package.semantic.roots.activation_wait_roots.len(),
        package.semantic.roots.activation_cleanup_roots.len(),
        package.semantic.roots.preemption_latency_roots.len(),
        package.semantic.roots.hart_event_attribution_roots.len()
    );
    print_roots("hart", &package.semantic.roots.hart_roots);
    print_roots("task", &package.semantic.roots.task_roots);
    print_roots("activation-context", &package.semantic.roots.activation_context_roots);
    print_roots("saved-context", &package.semantic.roots.saved_context_roots);
    print_roots("timer-interrupt", &package.semantic.roots.timer_interrupt_roots);
    print_roots("ipi-event", &package.semantic.roots.ipi_event_roots);
    print_roots("remote-preempt", &package.semantic.roots.remote_preempt_roots);
    print_roots("remote-park", &package.semantic.roots.remote_park_roots);
    print_roots("preemption", &package.semantic.roots.preemption_roots);
    print_roots("scheduler-decision", &package.semantic.roots.scheduler_decision_roots);
    print_roots(
        "cross-hart-scheduler-decision",
        &package.semantic.roots.cross_hart_scheduler_decision_roots,
    );
    print_roots("activation-migration", &package.semantic.roots.activation_migration_roots);
    print_roots("smp-safe-point", &package.semantic.roots.smp_safe_point_roots);
    print_roots(
        "stop-the-world-rendezvous",
        &package.semantic.roots.stop_the_world_rendezvous_roots,
    );
    print_roots("smp-code-publish-barrier", &package.semantic.roots.smp_code_publish_barrier_roots);
    print_roots("smp-cleanup-quiescence", &package.semantic.roots.smp_cleanup_quiescence_roots);
    print_roots("smp-snapshot-barrier", &package.semantic.roots.smp_snapshot_barrier_roots);
    print_roots("smp-stress-run", &package.semantic.roots.smp_stress_run_roots);
    print_roots("smp-scaling-benchmark", &package.semantic.roots.smp_scaling_benchmark_roots);
    print_roots(
        "integrated-smp-preemption-cleanup",
        &package.semantic.roots.integrated_smp_preemption_cleanup_roots,
    );
    print_roots(
        "integrated-smp-network-fault",
        &package.semantic.roots.integrated_smp_network_fault_roots,
    );
    print_roots(
        "integrated-disk-preempt-fault",
        &package.semantic.roots.integrated_disk_preempt_fault_roots,
    );
    print_roots(
        "integrated-simd-migration",
        &package.semantic.roots.integrated_simd_migration_roots,
    );
    print_roots(
        "integrated-network-disk-io",
        &package.semantic.roots.integrated_network_disk_io_roots,
    );
    print_roots(
        "integrated-display-scheduler-load",
        &package.semantic.roots.integrated_display_scheduler_load_roots,
    );
    print_roots(
        "integrated-snapshot-io-lease-barrier",
        &package.semantic.roots.integrated_snapshot_io_lease_barrier_roots,
    );
    print_roots(
        "integrated-code-publish-smp-workload",
        &package.semantic.roots.integrated_code_publish_smp_workload_roots,
    );
    print_roots("integrated-display-panic", &package.semantic.roots.integrated_display_panic_roots);
    print_roots(
        "integrated-osctl-trace-replay",
        &package.semantic.roots.integrated_osctl_trace_replay_roots,
    );
    print_roots("device", &package.semantic.roots.device_object_roots);
    print_roots("queue", &package.semantic.roots.queue_object_roots);
    print_roots("descriptor", &package.semantic.roots.descriptor_object_roots);
    print_roots("dma-buffer", &package.semantic.roots.dma_buffer_object_roots);
    print_roots("mmio-region", &package.semantic.roots.mmio_region_object_roots);
    print_roots("irq-line", &package.semantic.roots.irq_line_object_roots);
    print_roots("irq-event", &package.semantic.roots.irq_event_roots);
    print_roots("device-capability", &package.semantic.roots.device_capability_roots);
    print_roots("driver-store-binding", &package.semantic.roots.driver_store_binding_roots);
    print_roots("io-wait", &package.semantic.roots.io_wait_roots);
    print_roots("io-cleanup", &package.semantic.roots.io_cleanup_roots);
    print_roots("io-fault-injection", &package.semantic.roots.io_fault_injection_roots);
    print_roots("io-validation-report", &package.semantic.roots.io_validation_report_roots);
    print_roots("packet-device", &package.semantic.roots.packet_device_object_roots);
    print_roots("packet-buffer", &package.semantic.roots.packet_buffer_object_roots);
    print_roots("packet-queue", &package.semantic.roots.packet_queue_object_roots);
    print_roots("packet-descriptor", &package.semantic.roots.packet_descriptor_object_roots);
    print_roots("fake-net-backend", &package.semantic.roots.fake_net_backend_object_roots);
    print_roots("virtio-net-backend", &package.semantic.roots.virtio_net_backend_object_roots);
    print_roots("network-rx-interrupt", &package.semantic.roots.network_rx_interrupt_roots);
    print_roots(
        "network-rx-wait-resolution",
        &package.semantic.roots.network_rx_wait_resolution_roots,
    );
    print_roots(
        "network-tx-capability-gate",
        &package.semantic.roots.network_tx_capability_gate_roots,
    );
    print_roots("network-tx-completion", &package.semantic.roots.network_tx_completion_roots);
    print_roots("network-stack-adapter", &package.semantic.roots.network_stack_adapter_roots);
    print_roots("socket-object", &package.semantic.roots.socket_object_roots);
    print_roots("endpoint-object", &package.semantic.roots.endpoint_object_roots);
    print_roots("socket-operation", &package.semantic.roots.socket_operation_roots);
    print_roots("socket-wait", &package.semantic.roots.socket_wait_roots);
    print_roots("network-backpressure", &package.semantic.roots.network_backpressure_roots);
    print_roots("network-driver-cleanup", &package.semantic.roots.network_driver_cleanup_roots);
    print_roots(
        "network-recovery-benchmark",
        &package.semantic.roots.network_recovery_benchmark_roots,
    );
    print_roots("block-device", &package.semantic.roots.block_device_object_roots);
    print_roots("block-range", &package.semantic.roots.block_range_object_roots);
    print_roots("block-request", &package.semantic.roots.block_request_object_roots);
    print_roots("block-completion", &package.semantic.roots.block_completion_object_roots);
    print_roots("block-wait", &package.semantic.roots.block_wait_roots);
    print_roots("fake-block-backend", &package.semantic.roots.fake_block_backend_object_roots);
    print_roots("virtio-blk-backend", &package.semantic.roots.virtio_blk_backend_object_roots);
    print_roots("block-read-path", &package.semantic.roots.block_read_path_roots);
    print_roots("block-write-path", &package.semantic.roots.block_write_path_roots);
    print_roots("block-request-queue", &package.semantic.roots.block_request_queue_roots);
    print_roots("block-dma-buffer", &package.semantic.roots.block_dma_buffer_roots);
    print_roots("block-page-object", &package.semantic.roots.block_page_object_roots);
    print_roots("buffer-cache-object", &package.semantic.roots.buffer_cache_object_roots);
    print_roots("file-object", &package.semantic.roots.file_object_roots);
    print_roots("directory-object", &package.semantic.roots.directory_object_roots);
    print_roots("fat-adapter-object", &package.semantic.roots.fat_adapter_object_roots);
    print_roots("ext4-adapter-object", &package.semantic.roots.ext4_adapter_object_roots);
    print_roots("file-handle-capability", &package.semantic.roots.file_handle_capability_roots);
    print_roots("fs-wait", &package.semantic.roots.fs_wait_roots);
    print_roots("block-driver-cleanup", &package.semantic.roots.block_driver_cleanup_roots);
    print_roots("activation-resume", &package.semantic.roots.activation_resume_roots);
    print_roots("activation-wait", &package.semantic.roots.activation_wait_roots);
    print_roots("activation-cleanup", &package.semantic.roots.activation_cleanup_roots);
    print_roots("preemption-latency", &package.semantic.roots.preemption_latency_roots);
    print_roots("hart-event-attribution", &package.semantic.roots.hart_event_attribution_roots);
    print_roots("resource", &package.semantic.roots.resource_roots);
    print_roots("authority", &package.semantic.roots.authority_roots);
    print_roots("store", &package.semantic.roots.store_roots);
    print_roots("capability", &package.semantic.roots.capability_roots);
    print_roots("target-store", &package.semantic.roots.target_store_record_roots);
    print_roots("target-capability", &package.semantic.roots.target_capability_record_roots);
    print_roots("fastpath", &package.semantic.roots.fast_path_roots);
    print_roots("boundary", &package.semantic.roots.boundary_roots);
    print_roots("artifact-verification", &package.semantic.roots.artifact_verification_roots);
    print_roots("store-activation", &package.semantic.roots.store_activation_roots);
    print_roots("executor-transition", &package.semantic.roots.executor_transition_roots);
    print_roots("target-artifact", &package.semantic.roots.target_artifact_roots);
    print_roots("code-object", &package.semantic.roots.code_object_roots);
    print_roots("activation-record", &package.semantic.roots.activation_record_roots);
    print_roots("trap", &package.semantic.roots.trap_roots);
    print_roots("hostcall", &package.semantic.roots.hostcall_trace_roots);
    print_roots("migration-object", &package.semantic.roots.migration_object_roots);
    print_roots("tombstone", &package.semantic.roots.tombstone_roots);
    print_roots("contract", &package.semantic.roots.contract_violation_roots);
    Ok(())
}

pub(crate) fn graph_edges_for_package(
    package: &MigrationPackageManifest,
    mode: GraphEdgeMode,
) -> Vec<serde_json::Value> {
    match mode {
        GraphEdgeMode::Roots => {
            let mut edges = live_graph_edges(package);
            edges.extend(history_graph_edges(package));
            edges
        }
        GraphEdgeMode::Live => live_graph_edges(package),
        GraphEdgeMode::History => history_graph_edges(package),
    }
}
