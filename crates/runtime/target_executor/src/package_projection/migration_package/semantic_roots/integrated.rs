use super::*;

pub(super) fn push_integrated_roots(
    roots: &mut SemanticRootSetManifest,
    semantic: &SemanticGraph,
    _capabilities: &[MigrationCapabilityManifest],
    _target_v1: &TargetExecutorV1Report,
) {
    roots.integrated_smp_preemption_cleanup_roots = semantic            .integrated_smp_preemption_cleanups()
            .iter()
            .map(|record| {
                format!(
                    "integrated-smp-preemption-cleanup id={} scenario={} stress_run={}@{} preemption={}@{} remote_preempt={}@{} activation_cleanup={}@{} smp_cleanup_quiescence={}@{} store={}@{}->{} harts={} generation={}",
                    record.id,
                    record.scenario,
                    record.stress_run,
                    record.stress_run_generation,
                    record.preemption,
                    record.preemption_generation,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                    record.activation_cleanup,
                    record.activation_cleanup_generation,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                    record.cleanup_store,
                    record.target_store_generation,
                    record.result_store_generation,
                    record.hart_count,
                    record.generation
                )
            })
            .collect();
    roots.integrated_smp_network_fault_roots = semantic            .integrated_smp_network_faults()
            .iter()
            .map(|record| {
                format!(
                    "integrated-smp-network-fault id={} scenario={} cleanup={}@{} stress_run={}@{} remote_preempt={}@{} smp_cleanup_quiescence={}@{} driver_store={}@{} packet_device={}@{} adapter={}@{} backend={}:{}@{} harts={} cancelled_socket_waits={} revoked_packet_capabilities={} generation={}",
                    record.id,
                    record.scenario,
                    record.network_driver_cleanup,
                    record.network_driver_cleanup_generation,
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                    record.driver_store,
                    record.driver_store_generation,
                    record.packet_device,
                    record.packet_device_generation,
                    record.adapter,
                    record.adapter_generation,
                    record.backend.kind.as_str(),
                    record.backend.id,
                    record.backend.generation,
                    record.hart_count,
                    record.cancelled_socket_wait_count,
                    record.revoked_packet_capability_count,
                    record.generation
                )
            })
            .collect();
    roots.integrated_disk_preempt_fault_roots = semantic            .integrated_disk_preempt_faults()
            .iter()
            .map(|record| {
                format!(
                    "integrated-disk-preempt-fault id={} scenario={} preemption={}@{} timer_interrupt={}@{} policy={}@{} block_wait={}@{} wait={}@{} block_request={}@{} block_device={}@{} action={} errno={} activation={}@{} generation={}",
                    record.id,
                    record.scenario,
                    record.preemption,
                    record.preemption_generation,
                    record.timer_interrupt,
                    record.timer_interrupt_generation,
                    record.block_pending_io_policy,
                    record.block_pending_io_policy_generation,
                    record.block_wait,
                    record.block_wait_generation,
                    record.wait,
                    record.wait_generation,
                    record.block_request,
                    record.block_request_generation,
                    record.block_device,
                    record.block_device_generation,
                    record.action.as_str(),
                    record.errno,
                    record.preempted_activation,
                    record.preempted_activation_generation_after,
                    record.generation
                )
            })
            .collect();
    roots.integrated_simd_migration_roots = semantic            .integrated_simd_migrations()
            .iter()
            .map(|record| {
                format!(
                    "integrated-simd-migration id={} scenario={} migration={}@{} target_feature_set={}@{} source_vector_state={} migrated_vector_state={} activation={}@{}->{} source_hart={}@{} target_hart={}@{} generation={}",
                    record.id,
                    record.scenario,
                    record.activation_migration,
                    record.activation_migration_generation,
                    record.target_feature_set,
                    record.target_feature_set_generation,
                    record.source_vector_state.summary(),
                    record.migrated_vector_state.summary(),
                    record.activation,
                    record.activation_generation_before,
                    record.activation_generation_after,
                    record.source_hart,
                    record.source_hart_generation,
                    record.target_hart,
                    record.target_hart_generation,
                    record.generation
                )
            })
            .collect();
    roots.integrated_network_disk_io_roots = semantic            .integrated_network_disk_ios()
            .iter()
            .map(|record| {
                format!(
                    "integrated-network-disk-io id={} scenario={} network_benchmark={}@{} block_benchmark={}@{} packet_device={}@{} block_device={}@{} network_bytes={} block_bytes={} window_nanos={} combined_throughput={} generation={}",
                    record.id,
                    record.scenario,
                    record.network_benchmark,
                    record.network_benchmark_generation,
                    record.block_benchmark,
                    record.block_benchmark_generation,
                    record.packet_device,
                    record.packet_device_generation,
                    record.block_device,
                    record.block_device_generation,
                    record.network_sample_bytes,
                    record.block_sample_bytes,
                    record.concurrent_window_nanos,
                    record.combined_throughput_bytes_per_sec,
                    record.generation
                )
            })
            .collect();
    roots.integrated_display_scheduler_load_roots = semantic            .integrated_display_scheduler_loads()
            .iter()
            .map(|record| {
                format!(
                    "integrated-display-scheduler-load id={} scenario={} framebuffer_benchmark={}@{} scheduler_decision={}@{} display={}@{} framebuffer={}@{} sample_frames={} sample_bytes={} scheduler_load_units={} display_measured_nanos={} generation={}",
                    record.id,
                    record.scenario,
                    record.framebuffer_benchmark,
                    record.framebuffer_benchmark_generation,
                    record.scheduler_decision,
                    record.scheduler_decision_generation,
                    record.display,
                    record.display_generation,
                    record.framebuffer,
                    record.framebuffer_generation,
                    record.sample_frames,
                    record.sample_bytes,
                    record.scheduler_load_units,
                    record.display_measured_nanos,
                    record.generation
                )
            })
            .collect();
    roots.integrated_snapshot_io_lease_barrier_roots = semantic            .integrated_snapshot_io_lease_barriers()
            .iter()
            .map(|record| {
                format!(
                    "integrated-snapshot-io-lease-barrier id={} scenario={} smp_snapshot_barrier={}@{} io_cleanup={}@{} display_snapshot_barrier={}@{} driver_store={}@{} device={}@{} display={}@{} framebuffer={}@{} released_dma_buffers={} released_mmio_regions={} released_irq_lines={} released_framebuffer_window_leases={} active_dmw_leases={} in_flight_dma={} active_framebuffer_window_leases={} generation={}",
                    record.id,
                    record.scenario,
                    record.smp_snapshot_barrier,
                    record.smp_snapshot_barrier_generation,
                    record.io_cleanup,
                    record.io_cleanup_generation,
                    record.display_snapshot_barrier,
                    record.display_snapshot_barrier_generation,
                    record.driver_store,
                    record.driver_store_generation,
                    record.device,
                    record.device_generation,
                    record.display,
                    record.display_generation,
                    record.framebuffer,
                    record.framebuffer_generation,
                    record.released_dma_buffers,
                    record.released_mmio_regions,
                    record.released_irq_lines,
                    record.released_framebuffer_window_leases,
                    record.active_dmw_lease_count,
                    record.in_flight_dma_count,
                    record.active_framebuffer_window_lease_count,
                    record.generation
                )
            })
            .collect();
    roots.integrated_code_publish_smp_workload_roots = semantic            .integrated_code_publish_smp_workloads()
            .iter()
            .map(|record| {
                format!(
                    "integrated-code-publish-smp-workload id={} scenario={} stress_run={}@{} code_publish_barrier={}@{} rendezvous={}@{} safe_point={}@{} code_publish_epoch={}->{} harts={} iterations={} generation={}",
                    record.id,
                    record.scenario,
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                    record.smp_code_publish_barrier,
                    record.smp_code_publish_barrier_generation,
                    record.publish_rendezvous,
                    record.publish_rendezvous_generation,
                    record.publish_safe_point,
                    record.publish_safe_point_generation,
                    record.code_publish_epoch_before,
                    record.code_publish_epoch_after,
                    record.hart_count,
                    record.workload_iterations,
                    record.generation
                )
            })
            .collect();
    roots.integrated_display_panic_roots = semantic            .integrated_display_panics()
            .iter()
            .map(|record| {
                format!(
                    "integrated-display-panic id={} scenario={} substrate_panic_event={} display_panic_last_frame={}@{} panic_ring_records={} lost={} jsonl_frames={} generation={}",
                    record.id,
                    record.scenario,
                    record.substrate_panic_event,
                    record.display_panic_last_frame,
                    record.display_panic_last_frame_generation,
                    record.panic_ring_record_count,
                    record.panic_ring_lost_count,
                    record.jsonl_frame_count,
                    record.generation
                )
            })
            .collect();
    roots.integrated_osctl_trace_replay_roots = semantic            .integrated_osctl_trace_replays()
            .iter()
            .map(|record| {
                format!(
                    "integrated-osctl-trace-replay id={} scenario={} replay_event_cursor={} integrated_scenarios={} stable_views={} historical_edges={} generation={}",
                    record.id,
                    record.scenario,
                    record.replay_event_cursor,
                    record.integrated_scenario_count,
                    record.stable_view_count,
                    record.historical_edge_count,
                    record.generation
                )
            })
            .collect();
}
