use super::*;

pub(crate) fn semantic_roots(
    capabilities: &[MigrationCapabilityManifest],
    semantic: &SemanticGraph,
    target_v1: &TargetExecutorV1Report,
) -> SemanticRootSetManifest {
    SemanticRootSetManifest {
        hart_roots: semantic
            .harts()
            .iter()
            .map(|hart| {
                format!(
                    "hart id={} hardware_id={} label={} state={} generation={} boot={} current={}@{}",
                    hart.id,
                    hart.hardware_id,
                    hart.label,
                    hart.state.as_str(),
                    hart.generation,
                    hart.boot,
                    hart.current_activation
                        .map(|activation| activation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    hart.current_activation_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned())
                )
            })
            .collect(),
        task_roots: semantic
            .tasks()
            .iter()
            .map(|task| {
                format!(
                    "task:{}:{}:{}:gen{}",
                    task.id,
                    task.frontend.as_str(),
                    task.state.as_str(),
                    task.generation
                )
            })
            .collect(),
        task_record_roots: semantic
            .tasks()
            .iter()
            .map(|task| format!("task-record id={} state={} generation={}", task.id, task.state.as_str(), task.generation))
            .collect(),
        runtime_activation_roots: semantic
            .runtime_activations()
            .iter()
            .map(|activation| {
                format!(
                    "runtime-activation id={} task={}@{} state={} generation={} queue={}@{}",
                    activation.id,
                    activation.owner_task,
                    activation.owner_task_generation,
                    activation.state.as_str(),
                    activation.generation,
                    activation
                        .runnable_queue
                        .map(|queue| queue.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    activation
                        .runnable_queue_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned())
                )
            })
            .collect(),
        runnable_queue_roots: semantic
            .runnable_queues()
            .iter()
            .map(|queue| {
                format!(
                    "runnable-queue id={} label={} state={} generation={} entries={}",
                    queue.id,
                    queue.label,
                    queue.state.as_str(),
                    queue.generation,
                    queue.entries.len()
                )
            })
            .collect(),
        activation_context_roots: semantic
            .activation_contexts()
            .iter()
            .map(|context| {
                format!(
                    "activation-context id={} activation={}@{} state={} generation={} saved={}@{} vector_status={} vector_state={}",
                    context.id,
                    context.activation,
                    context.activation_generation,
                    context.state.as_str(),
                    context.generation,
                    context
                        .current_saved_context
                        .map(|saved| saved.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    context
                        .current_saved_context_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    context.vector_status.as_str(),
                    context
                        .vector_state
                        .map(|vector_state| vector_state.summary())
                        .unwrap_or_else(|| "none".to_owned())
                )
            })
            .collect(),
        saved_context_roots: semantic
            .saved_contexts()
            .iter()
            .map(|saved| {
                format!(
                    "saved-context id={} context={}@{} activation={}@{} state={} reason={} pc={:#x} sp={:#x} vector_status={} vector_state={} generation={}",
                    saved.id,
                    saved.context,
                    saved.context_generation,
                    saved.activation,
                    saved.activation_generation,
                    saved.state.as_str(),
                    saved.reason.as_str(),
                    saved.pc,
                    saved.sp,
                    saved.vector_status.as_str(),
                    saved
                        .vector_state
                        .map(|vector_state| vector_state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    saved.generation
                )
            })
            .collect(),
        timer_interrupt_roots: semantic
            .timer_interrupts()
            .iter()
            .map(|interrupt| {
                format!(
                    "timer-interrupt id={} epoch={} hart={} target={}@{} state={} generation={}",
                    interrupt.id,
                    interrupt.timer_epoch,
                    interrupt.hart,
                    interrupt
                        .target_activation
                        .map(|activation| activation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    interrupt
                        .target_activation_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    interrupt.state.as_str(),
                    interrupt.generation
                )
            })
            .collect(),
        ipi_event_roots: semantic
            .ipi_events()
            .iter()
            .map(|ipi| {
                format!(
                    "ipi-event id={} kind={} source_hart={}@{} target_hart={}@{} state={} generation={}",
                    ipi.id,
                    ipi.kind.as_str(),
                    ipi.source_hart,
                    ipi.source_hart_generation,
                    ipi.target_hart,
                    ipi.target_hart_generation,
                    ipi.state.as_str(),
                    ipi.generation
                )
            })
            .collect(),
        remote_preempt_roots: semantic
            .remote_preempts()
            .iter()
            .map(|remote| {
                format!(
                    "remote-preempt id={} ipi={}@{} source_hart={}@{} target_hart={}@{}->{} activation={}@{}->{} queue={}@{} state={} generation={}",
                    remote.id,
                    remote.ipi,
                    remote.ipi_generation,
                    remote.source_hart,
                    remote.source_hart_generation,
                    remote.target_hart,
                    remote.target_hart_generation_before,
                    remote.target_hart_generation_after,
                    remote.activation,
                    remote.activation_generation_before,
                    remote.activation_generation_after,
                    remote.queue,
                    remote.queue_generation,
                    remote.state.as_str(),
                    remote.generation
                )
            })
            .collect(),
        remote_park_roots: semantic
            .remote_parks()
            .iter()
            .map(|remote| {
                format!(
                    "remote-park id={} ipi={}@{} source_hart={}@{} target_hart={}@{}->{} state={} reason={} generation={}",
                    remote.id,
                    remote.ipi,
                    remote.ipi_generation,
                    remote.source_hart,
                    remote.source_hart_generation,
                    remote.target_hart,
                    remote.target_hart_generation_before,
                    remote.target_hart_generation_after,
                    remote.state.as_str(),
                    remote.reason,
                    remote.generation
                )
            })
            .collect(),
        preemption_roots: semantic
            .preemptions()
            .iter()
            .map(|preemption| {
                format!(
                    "preemption id={} activation={}@{}->{} timer={}@{} queue={}@{} state={} generation={}",
                    preemption.id,
                    preemption.activation,
                    preemption.activation_generation_before,
                    preemption.activation_generation_after,
                    preemption.timer_interrupt,
                    preemption.timer_interrupt_generation,
                    preemption.queue,
                    preemption.queue_generation,
                    preemption.state.as_str(),
                    preemption.generation
                )
            })
            .collect(),
        scheduler_decision_roots: semantic
            .scheduler_decisions()
            .iter()
            .map(|decision| {
                format!(
                    "scheduler-decision id={} queue={}@{} activation={}@{} state={} generation={}",
                    decision.id,
                    decision.queue,
                    decision.queue_generation,
                    decision.selected_activation,
                    decision.selected_activation_generation,
                    decision.state.as_str(),
                    decision.generation
                )
            })
            .collect(),
        cross_hart_scheduler_decision_roots: semantic
            .cross_hart_scheduler_decisions()
            .iter()
            .map(|decision| {
                format!(
                    "cross-hart-scheduler-decision id={} decision={}@{} deciding_hart={}@{} target_hart={}@{} queue={}@{} activation={}@{} state={} generation={}",
                    decision.id,
                    decision.scheduler_decision,
                    decision.scheduler_decision_generation,
                    decision.deciding_hart,
                    decision.deciding_hart_generation,
                    decision.target_hart,
                    decision.target_hart_generation,
                    decision.queue,
                    decision.queue_generation,
                    decision.selected_activation,
                    decision.selected_activation_generation,
                    decision.state.as_str(),
                    decision.generation
                )
            })
            .collect(),
        activation_migration_roots: semantic
            .activation_migrations()
            .iter()
            .map(|migration| {
                format!(
                    "activation-migration id={} activation={}@{}->{} source_hart={}@{} target_hart={}@{} source_queue={}@{} target_queue={}@{} vector_status={} source_vector_state={} migrated_vector_state={} state={} generation={}",
                    migration.id,
                    migration.activation,
                    migration.activation_generation_before,
                    migration.activation_generation_after,
                    migration.source_hart,
                    migration.source_hart_generation,
                    migration.target_hart,
                    migration.target_hart_generation,
                    migration.source_queue,
                    migration.source_queue_generation,
                    migration.target_queue,
                    migration.target_queue_generation,
                    migration.vector_status.as_str(),
                    migration
                        .source_vector_state
                        .map(|vector_state| vector_state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    migration
                        .migrated_vector_state
                        .map(|vector_state| vector_state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    migration.state.as_str(),
                    migration.generation
                )
            })
            .collect(),
        smp_safe_point_roots: semantic
            .smp_safe_points()
            .iter()
            .map(|safe_point| {
                format!(
                    "smp-safe-point id={} coordinator_hart={}@{} participants={} state={} generation={}",
                    safe_point.id,
                    safe_point.coordinator_hart,
                    safe_point.coordinator_hart_generation,
                    safe_point.participants.len(),
                    safe_point.state.as_str(),
                    safe_point.generation
                )
            })
            .collect(),
        stop_the_world_rendezvous_roots: semantic
            .stop_the_world_rendezvous()
            .iter()
            .map(|rendezvous| {
                format!(
                    "stop-the-world-rendezvous id={} epoch={} safe_point={}@{} participants={} state={} generation={}",
                    rendezvous.id,
                    rendezvous.epoch,
                    rendezvous.safe_point,
                    rendezvous.safe_point_generation,
                    rendezvous.participants.len(),
                    rendezvous.state.as_str(),
                    rendezvous.generation
                )
            })
            .collect(),
        smp_code_publish_barrier_roots: semantic
            .smp_code_publish_barriers()
            .iter()
            .map(|barrier| {
                format!(
                    "smp-code-publish-barrier id={} rendezvous={}@{} code_publish_epoch={}->{} participants={} state={} generation={}",
                    barrier.id,
                    barrier.rendezvous,
                    barrier.rendezvous_generation,
                    barrier.code_publish_epoch_before,
                    barrier.code_publish_epoch_after,
                    barrier.participants.len(),
                    barrier.state.as_str(),
                    barrier.generation
                )
            })
            .collect(),
        smp_cleanup_quiescence_roots: semantic
            .smp_cleanup_quiescence()
            .iter()
            .map(|quiescence| {
                format!(
                    "smp-cleanup-quiescence id={} cleanup={}@{} store={}@{}->{} rendezvous={}@{} participants={} state={} generation={}",
                    quiescence.id,
                    quiescence.cleanup,
                    quiescence.cleanup_generation,
                    quiescence.store,
                    quiescence.target_store_generation,
                    quiescence.result_store_generation,
                    quiescence.rendezvous,
                    quiescence.rendezvous_generation,
                    quiescence.participants.len(),
                    quiescence.state.as_str(),
                    quiescence.generation
                )
            })
            .collect(),
        smp_snapshot_barrier_roots: semantic
            .smp_snapshot_barriers()
            .iter()
            .map(|barrier| {
                format!(
                    "smp-snapshot-barrier id={} rendezvous={}@{} cursor={} participants={} state={} generation={}",
                    barrier.id,
                    barrier.rendezvous,
                    barrier.rendezvous_generation,
                    barrier.event_log_cursor,
                    barrier.participants.len(),
                    barrier.state.as_str(),
                    barrier.generation
                )
            })
            .collect(),
        smp_stress_run_roots: semantic
            .smp_stress_runs()
            .iter()
            .map(|run| {
                format!(
                    "smp-stress-run id={} scenario={} iterations={} invariants={} failures={} cursor={} generation={}",
                    run.id,
                    run.scenario,
                    run.iterations,
                    run.invariant_checks,
                    run.property_failures,
                    run.event_log_cursor,
                    run.generation
                )
            })
            .collect(),
        smp_scaling_benchmark_roots: semantic
            .smp_scaling_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "smp-scaling-benchmark id={} scenario={} stress_run={}@{} harts={} workload_units={} measured_nanos={} speedup_milli={} efficiency_milli={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.stress_run,
                    benchmark.stress_run_generation,
                    benchmark.hart_count,
                    benchmark.workload_units,
                    benchmark.measured_smp_nanos,
                    benchmark.speedup_milli,
                    benchmark.efficiency_milli,
                    benchmark.generation
                )
            })
            .collect(),
        integrated_smp_preemption_cleanup_roots: semantic
            .integrated_smp_preemption_cleanups()
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
            .collect(),
        integrated_smp_network_fault_roots: semantic
            .integrated_smp_network_faults()
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
            .collect(),
        integrated_disk_preempt_fault_roots: semantic
            .integrated_disk_preempt_faults()
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
            .collect(),
        integrated_simd_migration_roots: semantic
            .integrated_simd_migrations()
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
            .collect(),
        integrated_network_disk_io_roots: semantic
            .integrated_network_disk_ios()
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
            .collect(),
        integrated_display_scheduler_load_roots: semantic
            .integrated_display_scheduler_loads()
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
            .collect(),
        integrated_snapshot_io_lease_barrier_roots: semantic
            .integrated_snapshot_io_lease_barriers()
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
            .collect(),
        integrated_code_publish_smp_workload_roots: semantic
            .integrated_code_publish_smp_workloads()
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
            .collect(),
        integrated_display_panic_roots: semantic
            .integrated_display_panics()
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
            .collect(),
        integrated_osctl_trace_replay_roots: semantic
            .integrated_osctl_trace_replays()
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
            .collect(),
        device_object_roots: semantic
            .device_objects()
            .iter()
            .map(|device| {
                format!(
                    "device-object id={} name={} class={} resource={}@{} backend={} state={} generation={}",
                    device.id,
                    device.name,
                    device.class,
                    device.resource,
                    device.resource_generation,
                    device.backend,
                    device.state.as_str(),
                    device.generation
                )
            })
            .collect(),
        queue_object_roots: semantic
            .queue_objects()
            .iter()
            .map(|queue| {
                format!(
                    "queue-object id={} name={} role={} index={} depth={} device={}@{} state={} generation={}",
                    queue.id,
                    queue.name,
                    queue.role.as_str(),
                    queue.queue_index,
                    queue.depth,
                    queue.device,
                    queue.device_generation,
                    queue.state.as_str(),
                    queue.generation
                )
            })
            .collect(),
        descriptor_object_roots: semantic
            .descriptor_objects()
            .iter()
            .map(|descriptor| {
                format!(
                    "descriptor-object id={} queue={}@{} slot={} access={} length={} state={} generation={}",
                    descriptor.id,
                    descriptor.queue,
                    descriptor.queue_generation,
                    descriptor.slot,
                    descriptor.access.as_str(),
                    descriptor.length,
                    descriptor.state.as_str(),
                    descriptor.generation
                )
            })
            .collect(),
        dma_buffer_object_roots: semantic
            .dma_buffer_objects()
            .iter()
            .map(|dma_buffer| {
                format!(
                    "dma-buffer-object id={} descriptor={}@{} resource={}@{} access={} length={} state={} generation={}",
                    dma_buffer.id,
                    dma_buffer.descriptor,
                    dma_buffer.descriptor_generation,
                    dma_buffer.resource,
                    dma_buffer.resource_generation,
                    dma_buffer.access.as_str(),
                    dma_buffer.length,
                    dma_buffer.state.as_str(),
                    dma_buffer.generation
                )
            })
            .collect(),
        mmio_region_object_roots: semantic
            .mmio_region_objects()
            .iter()
            .map(|mmio_region| {
                format!(
                    "mmio-region-object id={} device={}@{} resource={}@{} index={} offset={} length={} access={} state={} generation={}",
                    mmio_region.id,
                    mmio_region.device,
                    mmio_region.device_generation,
                    mmio_region.resource,
                    mmio_region.resource_generation,
                    mmio_region.region_index,
                    mmio_region.offset,
                    mmio_region.length,
                    mmio_region.access.as_str(),
                    mmio_region.state.as_str(),
                    mmio_region.generation
                )
            })
            .collect(),
        irq_line_object_roots: semantic
            .irq_line_objects()
            .iter()
            .map(|irq_line| {
                format!(
                    "irq-line-object id={} device={}@{} resource={}@{} irq_number={} trigger={} polarity={} state={} generation={}",
                    irq_line.id,
                    irq_line.device,
                    irq_line.device_generation,
                    irq_line.resource,
                    irq_line.resource_generation,
                    irq_line.irq_number,
                    irq_line.trigger.as_str(),
                    irq_line.polarity.as_str(),
                    irq_line.state.as_str(),
                    irq_line.generation
                )
            })
            .collect(),
        irq_event_roots: semantic
            .irq_events()
            .iter()
            .map(|irq_event| {
                format!(
                    "irq-event id={} irq_line={}@{} device={}@{} driver_store={}@{} irq_number={} sequence={} state={} generation={}",
                    irq_event.id,
                    irq_event.irq_line,
                    irq_event.irq_line_generation,
                    irq_event.device,
                    irq_event.device_generation,
                    irq_event.driver_store,
                    irq_event.driver_store_generation,
                    irq_event.irq_number,
                    irq_event.sequence,
                    irq_event.state.as_str(),
                    irq_event.generation
                )
            })
            .collect(),
        device_capability_roots: semantic
            .device_capabilities()
            .iter()
            .map(|device_capability| {
                format!(
                    "device-capability id={} driver_store={}@{} target={} class={} operation={} capability={}@{} state={} generation={}",
                    device_capability.id,
                    device_capability.driver_store,
                    device_capability.driver_store_generation,
                    device_capability.target.summary(),
                    device_capability.class.as_str(),
                    device_capability.operation,
                    device_capability.capability,
                    device_capability.capability_generation,
                    device_capability.state.as_str(),
                    device_capability.generation
                )
            })
            .collect(),
        driver_store_binding_roots: semantic
            .driver_store_bindings()
            .iter()
            .map(|binding| {
                format!(
                    "driver-store-binding id={} driver_store={}@{} device={}@{} device_capability={}@{} capability={}@{} state={} generation={}",
                    binding.id,
                    binding.driver_store,
                    binding.driver_store_generation,
                    binding.device,
                    binding.device_generation,
                    binding.device_capability,
                    binding.device_capability_generation,
                    binding.capability,
                    binding.capability_generation,
                    binding.state.as_str(),
                    binding.generation
                )
            })
            .collect(),
        io_wait_roots: semantic
            .io_waits()
            .iter()
            .map(|io_wait| {
                format!(
                    "io-wait id={} wait={}@{} driver_store={}@{} device={}@{} binding={}@{} blocker={} state={} generation={}",
                    io_wait.id,
                    io_wait.wait,
                    io_wait.wait_generation,
                    io_wait.driver_store,
                    io_wait.driver_store_generation,
                    io_wait.device,
                    io_wait.device_generation,
                    io_wait.driver_binding,
                    io_wait.driver_binding_generation,
                    io_wait.blocker.summary(),
                    io_wait.state.as_str(),
                    io_wait.generation
                )
            })
            .collect(),
        io_cleanup_roots: semantic
            .io_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "io-cleanup id={} driver_store={}@{} device={}@{} binding={}@{} state={} generation={} cancelled_io_waits={} revoked_device_capabilities={} released_dma_buffers={} released_mmio_regions={} released_irq_lines={}",
                    cleanup.id,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                    cleanup.device,
                    cleanup.device_generation,
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                    cleanup.state.as_str(),
                    cleanup.generation,
                    cleanup.cancelled_io_waits.len(),
                    cleanup.revoked_device_capabilities.len(),
                    cleanup.released_dma_buffers.len(),
                    cleanup.released_mmio_regions.len(),
                    cleanup.released_irq_lines.len()
                )
            })
            .collect(),
        io_fault_injection_roots: semantic
            .io_fault_injections()
            .iter()
            .map(|fault| {
                format!(
                    "io-fault-injection id={} kind={} driver_store={}@{} device={}@{} binding={}@{} target={} cleanup={}@{} state={} generation={}",
                    fault.id,
                    fault.kind.as_str(),
                    fault.driver_store,
                    fault.driver_store_generation,
                    fault.device,
                    fault.device_generation,
                    fault.driver_binding,
                    fault.driver_binding_generation,
                    fault.target.summary(),
                    fault.cleanup,
                    fault.cleanup_generation,
                    fault.state.as_str(),
                    fault.generation
                )
            })
            .collect(),
        io_validation_report_roots: semantic
            .io_validation_reports()
            .iter()
            .map(|report| {
                format!(
                    "io-validation-report id={} state={} violations={} devices={} dma_buffers={} irq_events={} cleanups={} fault_injections={} generation={}",
                    report.id,
                    report.state.as_str(),
                    report.violations.len(),
                    report.observed_device_count,
                    report.observed_dma_buffer_count,
                    report.observed_irq_event_count,
                    report.observed_io_cleanup_count,
                    report.observed_io_fault_injection_count,
                    report.generation
                )
            })
            .collect(),
        packet_device_object_roots: semantic
            .packet_device_objects()
            .iter()
            .map(|packet_device| {
                format!(
                    "packet-device-object id={} name={} device={}@{} mtu={} rx_queue_depth={} tx_queue_depth={} frame_format_version={} max_payload_len={} state={} generation={}",
                    packet_device.id,
                    packet_device.name,
                    packet_device.device,
                    packet_device.device_generation,
                    packet_device.mtu,
                    packet_device.rx_queue_depth,
                    packet_device.tx_queue_depth,
                    packet_device.frame_format_version,
                    packet_device.max_payload_len,
                    packet_device.state.as_str(),
                    packet_device.generation
                )
            })
            .collect(),
        packet_buffer_object_roots: semantic
            .packet_buffer_objects()
            .iter()
            .map(|packet_buffer| {
                format!(
                    "packet-buffer-object id={} packet_device={}@{} direction={} frame_format_version={} capacity={} payload_len={} sequence={} state={} generation={}",
                    packet_buffer.id,
                    packet_buffer.packet_device,
                    packet_buffer.packet_device_generation,
                    packet_buffer.direction.as_str(),
                    packet_buffer.frame_format_version,
                    packet_buffer.capacity,
                    packet_buffer.payload_len,
                    packet_buffer.sequence,
                    packet_buffer.state.as_str(),
                    packet_buffer.generation
                )
            })
            .collect(),
        packet_queue_object_roots: semantic
            .packet_queue_objects()
            .iter()
            .map(|packet_queue| {
                format!(
                    "packet-queue-object id={} name={} packet_device={}@{} role={} queue_index={} depth={} state={} generation={}",
                    packet_queue.id,
                    packet_queue.name,
                    packet_queue.packet_device,
                    packet_queue.packet_device_generation,
                    packet_queue.role.as_str(),
                    packet_queue.queue_index,
                    packet_queue.depth,
                    packet_queue.state.as_str(),
                    packet_queue.generation
                )
            })
            .collect(),
        packet_descriptor_object_roots: semantic
            .packet_descriptors()
            .iter()
            .map(|packet_descriptor| {
                format!(
                    "packet-descriptor-object id={} packet_queue={}@{} packet_buffer={}@{} slot={} length={} state={} generation={}",
                    packet_descriptor.id,
                    packet_descriptor.packet_queue,
                    packet_descriptor.packet_queue_generation,
                    packet_descriptor.packet_buffer,
                    packet_descriptor.packet_buffer_generation,
                    packet_descriptor.slot,
                    packet_descriptor.length,
                    packet_descriptor.state.as_str(),
                    packet_descriptor.generation
                )
            })
            .collect(),
        fake_net_backend_object_roots: semantic
            .fake_net_backends()
            .iter()
            .map(|backend| {
                format!(
                    "fake-net-backend-object id={} name={} packet_device={}@{} provider={} profile={} mtu={} rx_queue_depth={} tx_queue_depth={} frame_format_version={} max_payload_len={} deterministic_seed={} state={} generation={}",
                    backend.id,
                    backend.name,
                    backend.packet_device,
                    backend.packet_device_generation,
                    backend.provider,
                    backend.profile,
                    backend.mtu,
                    backend.rx_queue_depth,
                    backend.tx_queue_depth,
                    backend.frame_format_version,
                    backend.max_payload_len,
                    backend.deterministic_seed,
                    backend.state.as_str(),
                    backend.generation
                )
            })
            .collect(),
        virtio_net_backend_object_roots: semantic
            .virtio_net_backends()
            .iter()
            .map(|backend| {
                format!(
                    "virtio-net-backend-object id={} name={} packet_device={}@{} driver_binding={}@{} device={}@{} provider={} profile={} model={} mtu={} rx_queue_depth={} tx_queue_depth={} frame_format_version={} max_payload_len={} device_features={} driver_features={} negotiated_features={} rx_queue_index={} tx_queue_index={} queue_size={} irq_vector={} state={} generation={}",
                    backend.id,
                    backend.name,
                    backend.packet_device,
                    backend.packet_device_generation,
                    backend.driver_binding,
                    backend.driver_binding_generation,
                    backend.device,
                    backend.device_generation,
                    backend.provider,
                    backend.profile,
                    backend.model,
                    backend.mtu,
                    backend.rx_queue_depth,
                    backend.tx_queue_depth,
                    backend.frame_format_version,
                    backend.max_payload_len,
                    backend.device_features,
                    backend.driver_features,
                    backend.negotiated_features,
                    backend.rx_queue_index,
                    backend.tx_queue_index,
                    backend.queue_size,
                    backend.irq_vector,
                    backend.state.as_str(),
                    backend.generation
                )
            })
            .collect(),
        network_rx_interrupt_roots: semantic
            .network_rx_interrupts()
            .iter()
            .map(|rx_interrupt| {
                format!(
                    "network-rx-interrupt id={} virtio_net_backend={}@{} irq_event={}@{} packet_device={}@{} rx_queue={}@{} ready_descriptors={} sequence={} state={} generation={}",
                    rx_interrupt.id,
                    rx_interrupt.virtio_net_backend,
                    rx_interrupt.virtio_net_backend_generation,
                    rx_interrupt.irq_event,
                    rx_interrupt.irq_event_generation,
                    rx_interrupt.packet_device,
                    rx_interrupt.packet_device_generation,
                    rx_interrupt.rx_queue,
                    rx_interrupt.rx_queue_generation,
                    rx_interrupt.ready_descriptors,
                    rx_interrupt.sequence,
                    rx_interrupt.state.as_str(),
                    rx_interrupt.generation
                )
            })
            .collect(),
        network_rx_wait_resolution_roots: semantic
            .network_rx_wait_resolutions()
            .iter()
            .map(|resolution| {
                format!(
                    "network-rx-wait-resolution id={} io_wait={}@{} wait={}@{} rx_interrupt={}@{} irq_event={}@{} rx_queue={}@{} ready_descriptors={} state={} generation={}",
                    resolution.id,
                    resolution.io_wait,
                    resolution.io_wait_generation,
                    resolution.wait,
                    resolution.wait_generation,
                    resolution.rx_interrupt,
                    resolution.rx_interrupt_generation,
                    resolution.irq_event,
                    resolution.irq_event_generation,
                    resolution.rx_queue,
                    resolution.rx_queue_generation,
                    resolution.ready_descriptors,
                    resolution.state.as_str(),
                    resolution.generation
                )
            })
            .collect(),
        network_tx_capability_gate_roots: semantic
            .network_tx_capability_gates()
            .iter()
            .map(|gate| {
                format!(
                    "network-tx-capability-gate id={} driver_store={}@{} packet_device={}@{} tx_queue={}@{} packet_descriptor={}@{} packet_buffer={}@{} device_capability={}@{} capability={}@{} operation={} byte_len={} sequence={} state={} generation={}",
                    gate.id,
                    gate.driver_store,
                    gate.driver_store_generation,
                    gate.packet_device,
                    gate.packet_device_generation,
                    gate.tx_queue,
                    gate.tx_queue_generation,
                    gate.packet_descriptor,
                    gate.packet_descriptor_generation,
                    gate.packet_buffer,
                    gate.packet_buffer_generation,
                    gate.device_capability,
                    gate.device_capability_generation,
                    gate.capability,
                    gate.capability_generation,
                    gate.operation,
                    gate.byte_len,
                    gate.sequence,
                    gate.state.as_str(),
                    gate.generation
                )
            })
            .collect(),
        network_tx_completion_roots: semantic
            .network_tx_completions()
            .iter()
            .map(|completion| {
                format!(
                    "network-tx-completion id={} tx_gate={}@{} backend={} driver_store={}@{} packet_device={}@{} tx_queue={}@{} packet_descriptor={}@{} packet_buffer={}@{} byte_len={} sequence={} completion_sequence={} state={} generation={}",
                    completion.id,
                    completion.tx_gate,
                    completion.tx_gate_generation,
                    completion.backend.summary(),
                    completion.driver_store,
                    completion.driver_store_generation,
                    completion.packet_device,
                    completion.packet_device_generation,
                    completion.tx_queue,
                    completion.tx_queue_generation,
                    completion.packet_descriptor,
                    completion.packet_descriptor_generation,
                    completion.packet_buffer,
                    completion.packet_buffer_generation,
                    completion.byte_len,
                    completion.sequence,
                    completion.completion_sequence,
                    completion.state.as_str(),
                    completion.generation
                )
            })
            .collect(),
        network_stack_adapter_roots: semantic
            .network_stack_adapters()
            .iter()
            .map(|adapter| {
                format!(
                    "network-stack-adapter id={} implementation={} version={} profile={} medium={} backend={} packet_device={}@{} rx_queue={}@{} tx_queue={}@{} ipv4={}.{}.{}.{}/{} mtu={} rx_queue_depth={} tx_queue_depth={} max_payload_len={} socket_capacity={} state={} generation={}",
                    adapter.id,
                    adapter.implementation,
                    adapter.implementation_version,
                    adapter.profile,
                    adapter.medium,
                    adapter.backend.summary(),
                    adapter.packet_device,
                    adapter.packet_device_generation,
                    adapter.rx_queue,
                    adapter.rx_queue_generation,
                    adapter.tx_queue,
                    adapter.tx_queue_generation,
                    adapter.ipv4_addr[0],
                    adapter.ipv4_addr[1],
                    adapter.ipv4_addr[2],
                    adapter.ipv4_addr[3],
                    adapter.ipv4_prefix_len,
                    adapter.mtu,
                    adapter.rx_queue_depth,
                    adapter.tx_queue_depth,
                    adapter.max_payload_len,
                    adapter.socket_capacity,
                    adapter.state.as_str(),
                    adapter.generation
                )
            })
            .collect(),
        socket_object_roots: semantic
            .socket_objects()
            .iter()
            .map(|socket| {
                format!(
                    "socket-object id={} adapter={}@{} owner_store={}@{} domain={} type={} protocol={} canonical_protocol={} family={} transport={} state={} generation={}",
                    socket.id,
                    socket.adapter,
                    socket.adapter_generation,
                    socket.owner_store,
                    socket.owner_store_generation,
                    socket.domain,
                    socket.socket_type,
                    socket.protocol,
                    socket.canonical_protocol,
                    socket.family,
                    socket.transport,
                    socket.state.as_str(),
                    socket.generation
                )
            })
            .collect(),
        endpoint_object_roots: semantic
            .endpoint_objects()
            .iter()
            .map(|endpoint| {
                format!(
                    "endpoint-object id={} socket={}@{} adapter={}@{} owner_store={}@{} family={} transport={} local={}.{}.{}.{}:{} remote={}.{}.{}.{}:{} state={} generation={}",
                    endpoint.id,
                    endpoint.socket,
                    endpoint.socket_generation,
                    endpoint.adapter,
                    endpoint.adapter_generation,
                    endpoint.owner_store,
                    endpoint.owner_store_generation,
                    endpoint.family,
                    endpoint.transport,
                    endpoint.local_addr[0],
                    endpoint.local_addr[1],
                    endpoint.local_addr[2],
                    endpoint.local_addr[3],
                    endpoint.local_port,
                    endpoint.remote_addr[0],
                    endpoint.remote_addr[1],
                    endpoint.remote_addr[2],
                    endpoint.remote_addr[3],
                    endpoint.remote_port,
                    endpoint.state.as_str(),
                    endpoint.generation
                )
            })
            .collect(),
        socket_operation_roots: semantic
            .socket_operations()
            .iter()
            .map(|operation| {
                format!(
                    "socket-operation id={} operation={} endpoint={}@{} socket={}@{} adapter={}@{} owner_store={}@{} local={}.{}.{}.{}:{} remote={}.{}.{}.{}:{} backlog={} byte_len={} sequence={} state={} generation={}",
                    operation.id,
                    operation.operation.as_str(),
                    operation.endpoint,
                    operation.endpoint_generation,
                    operation.socket,
                    operation.socket_generation,
                    operation.adapter,
                    operation.adapter_generation,
                    operation.owner_store,
                    operation.owner_store_generation,
                    operation.local_addr[0],
                    operation.local_addr[1],
                    operation.local_addr[2],
                    operation.local_addr[3],
                    operation.local_port,
                    operation.remote_addr[0],
                    operation.remote_addr[1],
                    operation.remote_addr[2],
                    operation.remote_addr[3],
                    operation.remote_port,
                    operation.backlog,
                    operation.byte_len,
                    operation.sequence,
                    operation.state.as_str(),
                    operation.generation
                )
            })
            .collect(),
        socket_wait_roots: semantic
            .socket_waits()
            .iter()
            .map(|wait| {
                format!(
                    "socket-wait id={} wait={}@{} kind={} endpoint={}@{} socket={}@{} adapter={}@{} owner_store={}@{} blocker={}:{}@{} state={} generation={}",
                    wait.id,
                    wait.wait,
                    wait.wait_generation,
                    wait.wait_kind.as_str(),
                    wait.endpoint,
                    wait.endpoint_generation,
                    wait.socket,
                    wait.socket_generation,
                    wait.adapter,
                    wait.adapter_generation,
                    wait.owner_store,
                    wait.owner_store_generation,
                    wait.blocker.kind.as_str(),
                    wait.blocker.id,
                    wait.blocker.generation,
                    wait.state.as_str(),
                    wait.generation
                )
            })
            .collect(),
        network_backpressure_roots: semantic
            .network_backpressures()
            .iter()
            .map(|backpressure| {
                let endpoint =
                    optional_generation_ref(backpressure.endpoint, backpressure.endpoint_generation);
                let socket =
                    optional_generation_ref(backpressure.socket, backpressure.socket_generation);
                let owner_store = optional_generation_ref(
                    backpressure.owner_store,
                    backpressure.owner_store_generation,
                );
                format!(
                    "network-backpressure id={} adapter={}@{} packet_device={}@{} packet_queue={}@{} endpoint={} socket={} owner_store={} direction={} reason={} action={} queue_depth={} queue_limit={} dropped_packets={} dropped_bytes={} sequence={} state={} generation={}",
                    backpressure.id,
                    backpressure.adapter,
                    backpressure.adapter_generation,
                    backpressure.packet_device,
                    backpressure.packet_device_generation,
                    backpressure.packet_queue,
                    backpressure.packet_queue_generation,
                    endpoint,
                    socket,
                    owner_store,
                    backpressure.direction.as_str(),
                    backpressure.reason.as_str(),
                    backpressure.action.as_str(),
                    backpressure.queue_depth,
                    backpressure.queue_limit,
                    backpressure.dropped_packets,
                    backpressure.dropped_bytes,
                    backpressure.sequence,
                    backpressure.state.as_str(),
                    backpressure.generation
                )
            })
            .collect(),
        network_driver_cleanup_roots: semantic
            .network_driver_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "network-driver-cleanup id={} io_cleanup={}@{} driver_store={}@{} device={}@{} binding={}@{} packet_device={}@{} adapter={}@{} backend={}:{}@{} state={} generation={} cancelled_socket_waits={} revoked_packet_capabilities={}",
                    cleanup.id,
                    cleanup.io_cleanup,
                    cleanup.io_cleanup_generation,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                    cleanup.device,
                    cleanup.device_generation,
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                    cleanup.packet_device,
                    cleanup.packet_device_generation,
                    cleanup.adapter,
                    cleanup.adapter_generation,
                    cleanup.backend.kind.as_str(),
                    cleanup.backend.id,
                    cleanup.backend.generation,
                    cleanup.state.as_str(),
                    cleanup.generation,
                    cleanup.cancelled_socket_waits.len(),
                    cleanup.revoked_packet_capabilities.len()
                )
            })
            .collect(),
        network_generation_audit_roots: semantic
            .network_generation_audits()
            .iter()
            .map(|audit| {
                format!(
                    "network-generation-audit id={} adapter={}@{} packet_device={}@{} packet_queue={}@{} packet_descriptor={}@{} packet_buffer={}@{} dma_buffer={}:{}@{} device_capability={}:{}@{} rejected_packet_generation_probes={} rejected_dma_generation_probes={} state={} generation={}",
                    audit.id,
                    audit.adapter,
                    audit.adapter_generation,
                    audit.packet_device,
                    audit.packet_device_generation,
                    audit.packet_queue,
                    audit.packet_queue_generation,
                    audit.packet_descriptor,
                    audit.packet_descriptor_generation,
                    audit.packet_buffer,
                    audit.packet_buffer_generation,
                    audit.dma_buffer.kind.as_str(),
                    audit.dma_buffer.id,
                    audit.dma_buffer.generation,
                    audit.device_capability.kind.as_str(),
                    audit.device_capability.id,
                    audit.device_capability.generation,
                    audit.rejected_packet_generation_probes,
                    audit.rejected_dma_generation_probes,
                    audit.state.as_str(),
                    audit.generation
                )
            })
            .collect(),
        network_fault_injection_roots: semantic
            .network_fault_injections()
            .iter()
            .map(|injection| {
                format!(
                    "network-fault-injection id={} adapter={}@{} packet_device={}@{} packet_queue={}@{} packet_descriptor={} packet_buffer={} endpoint={} direction={} kind={} effect={} injected_packets={} dropped_packets={} error_packets={} error_code={} sequence={} state={} generation={}",
                    injection.id,
                    injection.adapter,
                    injection.adapter_generation,
                    injection.packet_device,
                    injection.packet_device_generation,
                    injection.packet_queue,
                    injection.packet_queue_generation,
                    optional_generation_ref(injection.packet_descriptor, injection.packet_descriptor_generation),
                    optional_generation_ref(injection.packet_buffer, injection.packet_buffer_generation),
                    optional_generation_ref(injection.endpoint, injection.endpoint_generation),
                    injection.direction.as_str(),
                    injection.kind.as_str(),
                    injection.effect.as_str(),
                    injection.injected_packets,
                    injection.dropped_packets,
                    injection.error_packets,
                    injection.error_code,
                    injection.sequence,
                    injection.state.as_str(),
                    injection.generation
                )
            })
            .collect(),
        network_benchmark_roots: semantic
            .network_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "network-benchmark id={} scenario={} adapter={}@{} packet_device={}@{} tx_queue={}@{} rx_queue={}@{} tx_completion={}@{} rx_wait_resolution={}@{} endpoint={}@{} socket={}@{} owner_store={}@{} backpressure={} sample_packets={} sample_bytes={} tx_completed_packets={} rx_resolved_packets={} dropped_packets={} measured_nanos={} budget_nanos={} throughput_bytes_per_sec={} p50_latency_nanos={} p99_latency_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.adapter,
                    benchmark.adapter_generation,
                    benchmark.packet_device,
                    benchmark.packet_device_generation,
                    benchmark.tx_queue,
                    benchmark.tx_queue_generation,
                    benchmark.rx_queue,
                    benchmark.rx_queue_generation,
                    benchmark.tx_completion,
                    benchmark.tx_completion_generation,
                    benchmark.rx_wait_resolution,
                    benchmark.rx_wait_resolution_generation,
                    benchmark.endpoint,
                    benchmark.endpoint_generation,
                    benchmark.socket,
                    benchmark.socket_generation,
                    benchmark.owner_store,
                    benchmark.owner_store_generation,
                    optional_generation_ref(benchmark.backpressure, benchmark.backpressure_generation),
                    benchmark.sample_packets,
                    benchmark.sample_bytes,
                    benchmark.tx_completed_packets,
                    benchmark.rx_resolved_packets,
                    benchmark.dropped_packets,
                    benchmark.measured_nanos,
                    benchmark.budget_nanos,
                    benchmark.throughput_bytes_per_sec,
                    benchmark.p50_latency_nanos,
                    benchmark.p99_latency_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect(),
        network_recovery_benchmark_roots: semantic
            .network_recovery_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "network-recovery-benchmark id={} scenario={} cleanup={}@{} io_cleanup={}@{} adapter={}@{} packet_device={}@{} backend={}:{}@{} driver_store={}@{} fault_injection={} recovery_start_event={} recovery_complete_event={} cancelled_socket_waits={} revoked_packet_capabilities={} recovery_nanos={} budget_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.cleanup,
                    benchmark.cleanup_generation,
                    benchmark.io_cleanup,
                    benchmark.io_cleanup_generation,
                    benchmark.adapter,
                    benchmark.adapter_generation,
                    benchmark.packet_device,
                    benchmark.packet_device_generation,
                    benchmark.backend.kind.as_str(),
                    benchmark.backend.id,
                    benchmark.backend.generation,
                    benchmark.driver_store,
                    benchmark.driver_store_generation,
                    optional_generation_ref(benchmark.fault_injection, benchmark.fault_injection_generation),
                    benchmark.recovery_start_event,
                    benchmark.recovery_complete_event,
                    benchmark.cancelled_socket_waits,
                    benchmark.revoked_packet_capabilities,
                    benchmark.recovery_nanos,
                    benchmark.budget_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect(),
        block_device_object_roots: semantic
            .block_device_objects()
            .iter()
            .map(|block_device| {
                format!(
                    "block-device-object id={} name={} device={}@{} sector_size={} sector_count={} read_only={} max_transfer_sectors={} state={} generation={}",
                    block_device.id,
                    block_device.name,
                    block_device.device,
                    block_device.device_generation,
                    block_device.sector_size,
                    block_device.sector_count,
                    block_device.read_only,
                    block_device.max_transfer_sectors,
                    block_device.state.as_str(),
                    block_device.generation
                )
            })
            .collect(),
        block_range_object_roots: semantic
            .block_range_objects()
            .iter()
            .map(|block_range| {
                format!(
                    "block-range-object id={} block_device={}@{} start_sector={} sector_count={} byte_offset={} byte_len={} state={} generation={}",
                    block_range.id,
                    block_range.block_device,
                    block_range.block_device_generation,
                    block_range.start_sector,
                    block_range.sector_count,
                    block_range.byte_offset,
                    block_range.byte_len,
                    block_range.state.as_str(),
                    block_range.generation
                )
            })
            .collect(),
        block_request_object_roots: semantic
            .block_request_objects()
            .iter()
            .map(|request| {
                format!(
                    "block-request-object id={} block_device={}@{} block_range={}@{} operation={} sequence={} byte_len={} state={} generation={}",
                    request.id,
                    request.block_device,
                    request.block_device_generation,
                    request.block_range,
                    request.block_range_generation,
                    request.operation.as_str(),
                    request.sequence,
                    request.byte_len,
                    request.state.as_str(),
                    request.generation
                )
            })
            .collect(),
        block_completion_object_roots: semantic
            .block_completion_objects()
            .iter()
            .map(|completion| {
                format!(
                    "block-completion-object id={} block_request={}@{} block_device={}@{} block_range={}@{} sequence={} completed_bytes={} status={} state={} generation={}",
                    completion.id,
                    completion.block_request,
                    completion.block_request_generation,
                    completion.block_device,
                    completion.block_device_generation,
                    completion.block_range,
                    completion.block_range_generation,
                    completion.sequence,
                    completion.completed_bytes,
                    completion.status.as_str(),
                    completion.state.as_str(),
                    completion.generation
                )
            })
            .collect(),
        block_wait_roots: semantic
            .block_waits()
            .iter()
            .map(|wait| {
                format!(
                    "block-wait id={} wait={}@{} block_request={}@{} block_device={}@{} block_range={}@{} operation={} sequence={} byte_len={} state={} generation={}",
                    wait.id,
                    wait.wait,
                    wait.wait_generation,
                    wait.block_request,
                    wait.block_request_generation,
                    wait.block_device,
                    wait.block_device_generation,
                    wait.block_range,
                    wait.block_range_generation,
                    wait.operation.as_str(),
                    wait.sequence,
                    wait.byte_len,
                    wait.state.as_str(),
                    wait.generation
                )
            })
            .collect(),
        fake_block_backend_object_roots: semantic
            .fake_block_backends()
            .iter()
            .map(|backend| {
                format!(
                    "fake-block-backend-object id={} name={} block_device={}@{} provider={} profile={} sector_size={} sector_count={} read_only={} max_transfer_sectors={} deterministic_seed={} state={} generation={}",
                    backend.id,
                    backend.name,
                    backend.block_device,
                    backend.block_device_generation,
                    backend.provider,
                    backend.profile,
                    backend.sector_size,
                    backend.sector_count,
                    backend.read_only,
                    backend.max_transfer_sectors,
                    backend.deterministic_seed,
                    backend.state.as_str(),
                    backend.generation
                )
            })
            .collect(),
        virtio_blk_backend_object_roots: semantic
            .virtio_blk_backends()
            .iter()
            .map(|backend| {
                format!(
                    "virtio-blk-backend-object id={} name={} block_device={}@{} driver_binding={}@{} device={}@{} provider={} profile={} model={} sector_size={} sector_count={} read_only={} max_transfer_sectors={} device_features={} driver_features={} negotiated_features={} request_queue_index={} queue_size={} irq_vector={} state={} generation={}",
                    backend.id,
                    backend.name,
                    backend.block_device,
                    backend.block_device_generation,
                    backend.driver_binding,
                    backend.driver_binding_generation,
                    backend.device,
                    backend.device_generation,
                    backend.provider,
                    backend.profile,
                    backend.model,
                    backend.sector_size,
                    backend.sector_count,
                    backend.read_only,
                    backend.max_transfer_sectors,
                    backend.device_features,
                    backend.driver_features,
                    backend.negotiated_features,
                    backend.request_queue_index,
                    backend.queue_size,
                    backend.irq_vector,
                    backend.state.as_str(),
                    backend.generation
                )
            })
            .collect(),
        block_read_path_roots: semantic
            .block_read_paths()
            .iter()
            .map(|read_path| {
                format!(
                    "block-read-path id={} backend={} block_request={}@{} block_completion={}@{} block_device={}@{} block_range={}@{} sequence={} completed_bytes={} data_digest={} state={} generation={}",
                    read_path.id,
                    read_path.backend.summary(),
                    read_path.block_request,
                    read_path.block_request_generation,
                    read_path.block_completion,
                    read_path.block_completion_generation,
                    read_path.block_device,
                    read_path.block_device_generation,
                    read_path.block_range,
                    read_path.block_range_generation,
                    read_path.sequence,
                    read_path.completed_bytes,
                    read_path.data_digest,
                    read_path.state.as_str(),
                    read_path.generation
                )
            })
            .collect(),
        block_write_path_roots: semantic
            .block_write_paths()
            .iter()
            .map(|write_path| {
                format!(
                    "block-write-path id={} backend={} block_request={}@{} block_completion={}@{} block_device={}@{} block_range={}@{} sequence={} completed_bytes={} payload_digest={} state={} generation={}",
                    write_path.id,
                    write_path.backend.summary(),
                    write_path.block_request,
                    write_path.block_request_generation,
                    write_path.block_completion,
                    write_path.block_completion_generation,
                    write_path.block_device,
                    write_path.block_device_generation,
                    write_path.block_range,
                    write_path.block_range_generation,
                    write_path.sequence,
                    write_path.completed_bytes,
                    write_path.payload_digest,
                    write_path.state.as_str(),
                    write_path.generation
                )
            })
            .collect(),
        block_request_queue_roots: semantic
            .block_request_queues()
            .iter()
            .map(|queue| {
                format!(
                    "block-request-queue id={} backend={} block_device={}@{} depth={} entries={} pending={} completed={} first_sequence={} last_sequence={} state={} generation={}",
                    queue.id,
                    queue.backend.summary(),
                    queue.block_device,
                    queue.block_device_generation,
                    queue.depth,
                    queue.entries.len(),
                    queue.pending_count,
                    queue.completed_count,
                    queue.first_sequence,
                    queue.last_sequence,
                    queue.state.as_str(),
                    queue.generation
                )
            })
            .collect(),
        block_dma_buffer_roots: semantic
            .block_dma_buffers()
            .iter()
            .map(|buffer| {
                format!(
                    "block-dma-buffer id={} backend={} block_request={}@{} dma_buffer={}@{} block_device={}@{} block_range={}@{} descriptor={}@{} queue={}@{} operation={} access={} byte_len={} buffer_len={} buffer_digest={} state={} generation={}",
                    buffer.id,
                    buffer.backend.summary(),
                    buffer.block_request,
                    buffer.block_request_generation,
                    buffer.dma_buffer,
                    buffer.dma_buffer_generation,
                    buffer.block_device,
                    buffer.block_device_generation,
                    buffer.block_range,
                    buffer.block_range_generation,
                    buffer.descriptor,
                    buffer.descriptor_generation,
                    buffer.queue,
                    buffer.queue_generation,
                    buffer.operation.as_str(),
                    buffer.access.as_str(),
                    buffer.byte_len,
                    buffer.buffer_len,
                    buffer.buffer_digest,
                    buffer.state.as_str(),
                    buffer.generation
                )
            })
            .collect(),
        block_page_object_roots: semantic
            .block_page_objects()
            .iter()
            .map(|page| {
                format!(
                    "block-page-object id={} block_dma_buffer={}@{} block_request={}@{} block_completion={}@{} dma_buffer={}@{} block_device={}@{} block_range={}@{} aspace={} vma_region={} page={} page_dirty_generation={} page_backing={} cow_state={} page_state={} page_offset={} byte_len={} operation={} state={} generation={}",
                    page.id,
                    page.block_dma_buffer,
                    page.block_dma_buffer_generation,
                    page.block_request,
                    page.block_request_generation,
                    page.block_completion,
                    page.block_completion_generation,
                    page.dma_buffer,
                    page.dma_buffer_generation,
                    page.block_device,
                    page.block_device_generation,
                    page.block_range,
                    page.block_range_generation,
                    page.aspace.summary(),
                    page.vma_region.summary(),
                    page.page.summary(),
                    page.page_dirty_generation,
                    page.page_backing.as_str(),
                    page.cow_state.as_str(),
                    page.page_state.as_str(),
                    page.page_offset,
                    page.byte_len,
                    page.operation.as_str(),
                    page.state.as_str(),
                    page.generation
                )
            })
            .collect(),
        buffer_cache_object_roots: semantic
            .buffer_cache_objects()
            .iter()
            .map(|cache| {
                format!(
                    "buffer-cache-object id={} block_page_object={}@{} block_dma_buffer={}@{} block_device={}@{} block_range={}@{} aspace={} vma_region={} page={} page_dirty_generation={} page_offset={} block_offset={} byte_len={} operation={} cache_state={} coherency_epoch={} state={} generation={}",
                    cache.id,
                    cache.block_page_object,
                    cache.block_page_object_generation,
                    cache.block_dma_buffer,
                    cache.block_dma_buffer_generation,
                    cache.block_device,
                    cache.block_device_generation,
                    cache.block_range,
                    cache.block_range_generation,
                    cache.aspace.summary(),
                    cache.vma_region.summary(),
                    cache.page.summary(),
                    cache.page_dirty_generation,
                    cache.page_offset,
                    cache.block_offset,
                    cache.byte_len,
                    cache.operation.as_str(),
                    cache.cache_state.as_str(),
                    cache.coherency_epoch,
                    cache.state.as_str(),
                    cache.generation
                )
            })
            .collect(),
        file_object_roots: semantic
            .file_objects()
            .iter()
            .map(|file| {
                format!(
                    "file-object id={} buffer_cache_object={}@{} block_device={}@{} block_range={}@{} page={} page_dirty_generation={} namespace={} file_key={} path={} file_offset={} byte_len={} file_size={} content_digest={} cache_state={} state={} generation={}",
                    file.id,
                    file.buffer_cache_object,
                    file.buffer_cache_object_generation,
                    file.block_device,
                    file.block_device_generation,
                    file.block_range,
                    file.block_range_generation,
                    file.page.summary(),
                    file.page_dirty_generation,
                    file.namespace,
                    file.file_key,
                    file.path,
                    file.file_offset,
                    file.byte_len,
                    file.file_size,
                    file.content_digest,
                    file.cache_state.as_str(),
                    file.state.as_str(),
                    file.generation
                )
            })
            .collect(),
        directory_object_roots: semantic
            .directory_objects()
            .iter()
            .map(|directory| {
                format!(
                    "directory-object id={} file_object={}@{} namespace={} directory_key={} directory_path={} entry_name={} child_file_key={} child_path={} entry_kind={} file_size={} content_digest={} state={} generation={}",
                    directory.id,
                    directory.file_object,
                    directory.file_object_generation,
                    directory.namespace,
                    directory.directory_key,
                    directory.directory_path,
                    directory.entry_name,
                    directory.child_file_key,
                    directory.child_path,
                    directory.entry_kind.as_str(),
                    directory.file_size,
                    directory.content_digest,
                    directory.state.as_str(),
                    directory.generation
                )
            })
            .collect(),
        fat_adapter_object_roots: semantic
            .fat_adapter_objects()
            .iter()
            .map(|adapter| {
                format!(
                    "fat-adapter-object id={} directory_object={}@{} file_object={}@{} block_device={}@{} implementation={} version={} profile={} volume_label={} image_bytes={} adapter_path={} semantic_path={} bytes_written={} bytes_read={} write_digest={} read_digest={} file_content_digest={} state={} generation={}",
                    adapter.id,
                    adapter.directory_object,
                    adapter.directory_object_generation,
                    adapter.file_object,
                    adapter.file_object_generation,
                    adapter.block_device,
                    adapter.block_device_generation,
                    adapter.implementation,
                    adapter.version,
                    adapter.profile,
                    adapter.volume_label,
                    adapter.image_bytes,
                    adapter.adapter_path,
                    adapter.semantic_path,
                    adapter.bytes_written,
                    adapter.bytes_read,
                    adapter.write_digest,
                    adapter.read_digest,
                    adapter.file_content_digest,
                    adapter.state.as_str(),
                    adapter.generation
                )
            })
            .collect(),
        ext4_adapter_object_roots: semantic
            .ext4_adapter_objects()
            .iter()
            .map(|adapter| {
                format!(
                    "ext4-adapter-object id={} directory_object={}@{} file_object={}@{} block_device={}@{} implementation={} version={} profile={} volume_label={} image_bytes={} adapter_path={} semantic_path={} bytes_read={} read_digest={} file_content_digest={} directory_entries={} read_only_enforced={} state={} generation={}",
                    adapter.id,
                    adapter.directory_object,
                    adapter.directory_object_generation,
                    adapter.file_object,
                    adapter.file_object_generation,
                    adapter.block_device,
                    adapter.block_device_generation,
                    adapter.implementation,
                    adapter.version,
                    adapter.profile,
                    adapter.volume_label,
                    adapter.image_bytes,
                    adapter.adapter_path,
                    adapter.semantic_path,
                    adapter.bytes_read,
                    adapter.read_digest,
                    adapter.file_content_digest,
                    adapter.directory_entries,
                    adapter.read_only_enforced,
                    adapter.state.as_str(),
                    adapter.generation
                )
            })
            .collect(),
        file_handle_capability_roots: semantic
            .file_handle_capabilities()
            .iter()
            .map(|capability| {
                format!(
                    "file-handle-capability id={} owner_store={}@{} file_object={}@{} directory_object={}@{} capability={}@{} handle_slot={} handle_generation={} handle_tag={} operation={} file_offset={} byte_len={} content_digest={} state={} generation={}",
                    capability.id,
                    capability.owner_store,
                    capability.owner_store_generation,
                    capability.file_object,
                    capability.file_object_generation,
                    capability.directory_object,
                    capability.directory_object_generation,
                    capability.capability,
                    capability.capability_generation,
                    capability.handle_slot,
                    capability.handle_generation,
                    capability.handle_tag,
                    capability.operation,
                    capability.file_offset,
                    capability.byte_len,
                    capability.content_digest,
                    capability.state.as_str(),
                    capability.generation
                )
            })
            .collect(),
        fs_wait_roots: semantic
            .fs_waits()
            .iter()
            .map(|wait| {
                format!(
                    "fs-wait id={} wait={}@{} owner_store={}@{} file_object={}@{} directory_object={}@{} file_handle_capability={}@{} operation={} blocker={} sequence={} byte_len={} state={} generation={}",
                    wait.id,
                    wait.wait,
                    wait.wait_generation,
                    wait.owner_store,
                    wait.owner_store_generation,
                    wait.file_object,
                    wait.file_object_generation,
                    wait.directory_object,
                    wait.directory_object_generation,
                    wait.file_handle_capability,
                    wait.file_handle_capability_generation,
                    wait.operation,
                    wait.blocker.summary(),
                    wait.sequence,
                    wait.byte_len,
                    wait.state.as_str(),
                    wait.generation
                )
            })
            .collect(),
        block_driver_cleanup_roots: semantic
            .block_driver_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "block-driver-cleanup id={} io_cleanup={}@{} driver_store={}@{} device={}@{} binding={}@{} block_device={}@{} backend={}:{}@{} state={} generation={} cancelled_block_waits={} released_dma_buffers={} revoked_device_capabilities={}",
                    cleanup.id,
                    cleanup.io_cleanup,
                    cleanup.io_cleanup_generation,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                    cleanup.device,
                    cleanup.device_generation,
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                    cleanup.block_device,
                    cleanup.block_device_generation,
                    cleanup.backend.kind.as_str(),
                    cleanup.backend.id,
                    cleanup.backend.generation,
                    cleanup.state.as_str(),
                    cleanup.generation,
                    cleanup.cancelled_block_waits.len(),
                    cleanup.released_dma_buffers.len(),
                    cleanup.revoked_device_capabilities.len()
                )
            })
            .collect(),
        block_pending_io_policy_roots: semantic
            .block_pending_io_policies()
            .iter()
            .map(|policy| {
                format!(
                    "block-pending-io-policy id={} block_wait={}@{} wait={}@{} block_request={}@{} retry_request={} block_device={}@{} block_range={}@{} action={} errno={} retry_attempt={} max_retries={} state={} generation={}",
                    policy.id,
                    policy.block_wait,
                    policy.block_wait_generation,
                    policy.wait,
                    policy.wait_generation,
                    policy.block_request,
                    policy.block_request_generation,
                    policy
                        .retry_request
                        .zip(policy.retry_request_generation)
                        .map(|(id, generation)| format!("{id}@{generation}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    policy.block_device,
                    policy.block_device_generation,
                    policy.block_range,
                    policy.block_range_generation,
                    policy.action.as_str(),
                    policy.errno,
                    policy.retry_attempt,
                    policy.max_retries,
                    policy.state.as_str(),
                    policy.generation
                )
            })
            .collect(),
        block_request_generation_audit_roots: semantic
            .block_request_generation_audits()
            .iter()
            .map(|audit| {
                format!(
                    "block-request-generation-audit id={} block_device={}@{} block_range={}@{} block_request={}@{} backend={}:{}@{} dma_buffer={}:{}@{} rejected_completion_generation_probes={} rejected_wait_generation_probes={} rejected_dma_generation_probes={} rejected_queue_generation_probes={} state={} generation={}",
                    audit.id,
                    audit.block_device,
                    audit.block_device_generation,
                    audit.block_range,
                    audit.block_range_generation,
                    audit.block_request,
                    audit.block_request_generation,
                    audit.backend.kind.as_str(),
                    audit.backend.id,
                    audit.backend.generation,
                    audit.dma_buffer.kind.as_str(),
                    audit.dma_buffer.id,
                    audit.dma_buffer.generation,
                    audit.rejected_completion_generation_probes,
                    audit.rejected_wait_generation_probes,
                    audit.rejected_dma_generation_probes,
                    audit.rejected_queue_generation_probes,
                    audit.state.as_str(),
                    audit.generation
                )
            })
            .collect(),
        block_benchmark_roots: semantic
            .block_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "block-benchmark id={} scenario={} backend={}:{}@{} block_device={}@{} block_range={}@{} read_path={}@{} write_path={}@{} request_queue={}@{} block_dma_buffer={}@{} sample_requests={} sample_bytes={} iops={} throughput_bytes_per_sec={} p50_latency_nanos={} p99_latency_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.backend.kind.as_str(),
                    benchmark.backend.id,
                    benchmark.backend.generation,
                    benchmark.block_device,
                    benchmark.block_device_generation,
                    benchmark.block_range,
                    benchmark.block_range_generation,
                    benchmark.read_path,
                    benchmark.read_path_generation,
                    benchmark.write_path,
                    benchmark.write_path_generation,
                    benchmark.request_queue,
                    benchmark.request_queue_generation,
                    benchmark.block_dma_buffer,
                    benchmark.block_dma_buffer_generation,
                    benchmark.sample_requests,
                    benchmark.sample_bytes,
                    benchmark.iops,
                    benchmark.throughput_bytes_per_sec,
                    benchmark.p50_latency_nanos,
                    benchmark.p99_latency_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect(),
        block_recovery_benchmark_roots: semantic
            .block_recovery_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "block-recovery-benchmark id={} scenario={} cleanup={}@{} io_cleanup={}@{} backend={}:{}@{} block_device={}@{} driver_store={}@{} device={}@{} driver_binding={}@{} recovery_start_event={} recovery_complete_event={} cancelled_block_waits={} cancelled_wait_tokens={} released_dma_buffers={} revoked_device_capabilities={} recovery_nanos={} budget_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.cleanup,
                    benchmark.cleanup_generation,
                    benchmark.io_cleanup,
                    benchmark.io_cleanup_generation,
                    benchmark.backend.kind.as_str(),
                    benchmark.backend.id,
                    benchmark.backend.generation,
                    benchmark.block_device,
                    benchmark.block_device_generation,
                    benchmark.driver_store,
                    benchmark.driver_store_generation,
                    benchmark.device,
                    benchmark.device_generation,
                    benchmark.driver_binding,
                    benchmark.driver_binding_generation,
                    benchmark.recovery_start_event,
                    benchmark.recovery_complete_event,
                    benchmark.cancelled_block_waits,
                    benchmark.cancelled_wait_tokens,
                    benchmark.released_dma_buffers,
                    benchmark.revoked_device_capabilities,
                    benchmark.recovery_nanos,
                    benchmark.budget_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect(),
        target_feature_set_roots: semantic
            .target_feature_sets()
            .iter()
            .map(|feature| {
                format!(
                    "target-feature-set id={} name={} profile={} arch={} base_isa={} simd_abi={} simd_supported={} vector_register_count={} vector_register_bits={} scalar_fallback={} state={} generation={}",
                    feature.id,
                    feature.name,
                    feature.target_profile,
                    feature.target_arch,
                    feature.base_isa,
                    feature.simd_abi,
                    feature.simd_supported,
                    feature.vector_register_count,
                    feature.vector_register_bits,
                    feature.scalar_fallback,
                    feature.state.as_str(),
                    feature.generation
                )
            })
            .collect(),
        vector_state_roots: semantic
            .vector_states()
            .iter()
            .map(|vector_state| {
                format!(
                    "vector-state id={} activation={}:{}@{} store={}:{}@{} code_object={}:{}@{} target_feature_set={}:{}@{} simd_abi={} vector_register_count={} vector_register_bits={} register_bytes={} state={} generation={}",
                    vector_state.id,
                    vector_state.owner_activation.kind.as_str(),
                    vector_state.owner_activation.id,
                    vector_state.owner_activation.generation,
                    vector_state.owner_store.kind.as_str(),
                    vector_state.owner_store.id,
                    vector_state.owner_store.generation,
                    vector_state.code_object.kind.as_str(),
                    vector_state.code_object.id,
                    vector_state.code_object.generation,
                    vector_state.target_feature_set.kind.as_str(),
                    vector_state.target_feature_set.id,
                    vector_state.target_feature_set.generation,
                    vector_state.simd_abi,
                    vector_state.vector_register_count,
                    vector_state.vector_register_bits,
                    vector_state.register_bytes,
                    vector_state.state.as_str(),
                    vector_state.generation
                )
            })
            .collect(),
        simd_fault_injection_roots: semantic
            .simd_fault_injections()
            .iter()
            .map(|injection| {
                format!(
                    "simd-fault-injection id={} activation={} code_object={} trap={} target_feature_set={} vector_state={} kind={} effect={} injected_faults={} state={} generation={}",
                    injection.id,
                    injection.activation.summary(),
                    injection.code_object.summary(),
                    injection.trap.summary(),
                    injection.target_feature_set.summary(),
                    injection
                        .vector_state
                        .map(|vector_state| vector_state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    injection.kind.as_str(),
                    injection.effect.as_str(),
                    injection.injected_faults,
                    injection.state.as_str(),
                    injection.generation
                )
            })
            .collect(),
        simd_benchmark_roots: semantic
            .simd_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "simd-benchmark id={} target_feature_set={} scalar_code_object={} vector_code_object={} simd_abi={} vector_register_count={} vector_register_bits={} workload_units={} scalar_nanos={} vector_nanos={} speedup_milli={} context_overhead_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.target_feature_set.summary(),
                    benchmark.scalar_code_object.summary(),
                    benchmark.vector_code_object.summary(),
                    benchmark.simd_abi,
                    benchmark.vector_register_count,
                    benchmark.vector_register_bits,
                    benchmark.workload_units,
                    benchmark.scalar_nanos,
                    benchmark.vector_nanos,
                    benchmark.speedup_milli,
                    benchmark.context_overhead_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect(),
        simd_context_switch_benchmark_roots: semantic
            .simd_context_switch_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "simd-context-switch-benchmark id={} preemption={} activation_resume={} saved_vector_state={} restored_vector_state={} target_feature_set={} simd_abi={} vector_register_count={} vector_register_bits={} sample_count={} scalar_context_switch_nanos={} vector_context_switch_nanos={} overhead_nanos={} budget_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.preemption.summary(),
                    benchmark.activation_resume.summary(),
                    benchmark.saved_vector_state.summary(),
                    benchmark.restored_vector_state.summary(),
                    benchmark.target_feature_set.summary(),
                    benchmark.simd_abi,
                    benchmark.vector_register_count,
                    benchmark.vector_register_bits,
                    benchmark.sample_count,
                    benchmark.scalar_context_switch_nanos,
                    benchmark.vector_context_switch_nanos,
                    benchmark.overhead_nanos,
                    benchmark.budget_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect(),
        framebuffer_object_roots: semantic
            .framebuffer_objects()
            .iter()
            .map(|framebuffer| {
                format!(
                    "framebuffer-object id={} name={} resource={}@{} width={} height={} stride_bytes={} pixel_format={} byte_len={} state={} generation={}",
                    framebuffer.id,
                    framebuffer.name,
                    framebuffer.resource,
                    framebuffer.resource_generation,
                    framebuffer.width,
                    framebuffer.height,
                    framebuffer.stride_bytes,
                    framebuffer.pixel_format,
                    framebuffer.byte_len,
                    framebuffer.state.as_str(),
                    framebuffer.generation
                )
            })
            .collect(),
        display_object_roots: semantic
            .display_objects()
            .iter()
            .map(|display| {
                format!(
                    "display-object id={} name={} framebuffer={}@{} mode_name={} width={} height={} refresh_millihz={} state={} generation={}",
                    display.id,
                    display.name,
                    display.framebuffer,
                    display.framebuffer_generation,
                    display.mode_name,
                    display.width,
                    display.height,
                    display.refresh_millihz,
                    display.state.as_str(),
                    display.generation
                )
            })
            .collect(),
        display_capability_roots: semantic
            .display_capabilities()
            .iter()
            .map(|capability| {
                format!(
                    "display-capability id={} owner_store={}@{} display={}@{} framebuffer={}@{} capability={}@{} handle_slot={} handle_generation={} operations={} state={} generation={}",
                    capability.id,
                    capability.owner_store,
                    capability.owner_store_generation,
                    capability.display,
                    capability.display_generation,
                    capability.framebuffer,
                    capability.framebuffer_generation,
                    capability.capability,
                    capability.capability_generation,
                    capability.handle_slot,
                    capability.handle_generation,
                    capability.operations.join("|"),
                    capability.state.as_str(),
                    capability.generation
                )
            })
            .collect(),
        framebuffer_window_lease_roots: semantic
            .framebuffer_window_leases()
            .iter()
            .map(|lease| {
                format!(
                    "framebuffer-window-lease id={} owner_store={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} window={},{} {}x{} byte_range={}+{} access={} state={} generation={}",
                    lease.id,
                    lease.owner_store,
                    lease.owner_store_generation,
                    lease.display_capability,
                    lease.display_capability_generation,
                    lease.display,
                    lease.display_generation,
                    lease.framebuffer,
                    lease.framebuffer_generation,
                    lease.x,
                    lease.y,
                    lease.width,
                    lease.height,
                    lease.byte_offset,
                    lease.byte_len,
                    lease.access,
                    lease.state.as_str(),
                    lease.generation
                )
            })
            .collect(),
        framebuffer_mapping_roots: semantic
            .framebuffer_mappings()
            .iter()
            .map(|mapping| {
                format!(
                    "framebuffer-mapping id={} owner_store={}@{} framebuffer_window_lease={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} map_handle_slot={} map_handle_generation={} window={},{} {}x{} byte_range={}+{} access={} mode={} state={} generation={}",
                    mapping.id,
                    mapping.owner_store,
                    mapping.owner_store_generation,
                    mapping.framebuffer_window_lease,
                    mapping.framebuffer_window_lease_generation,
                    mapping.display_capability,
                    mapping.display_capability_generation,
                    mapping.display,
                    mapping.display_generation,
                    mapping.framebuffer,
                    mapping.framebuffer_generation,
                    mapping.map_handle_slot,
                    mapping.map_handle_generation,
                    mapping.x,
                    mapping.y,
                    mapping.width,
                    mapping.height,
                    mapping.byte_offset,
                    mapping.byte_len,
                    mapping.access,
                    mapping.mode,
                    mapping.state.as_str(),
                    mapping.generation
                )
            })
            .collect(),
        framebuffer_write_roots: semantic
            .framebuffer_writes()
            .iter()
            .map(|write| {
                format!(
                    "framebuffer-write id={} owner_store={}@{} framebuffer_mapping={}@{} framebuffer_window_lease={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} map_handle_slot={} map_handle_generation={} region={},{} {}x{} byte_range={}+{} pixel_format={} payload_digest={} state={} generation={}",
                    write.id,
                    write.owner_store,
                    write.owner_store_generation,
                    write.framebuffer_mapping,
                    write.framebuffer_mapping_generation,
                    write.framebuffer_window_lease,
                    write.framebuffer_window_lease_generation,
                    write.display_capability,
                    write.display_capability_generation,
                    write.display,
                    write.display_generation,
                    write.framebuffer,
                    write.framebuffer_generation,
                    write.map_handle_slot,
                    write.map_handle_generation,
                    write.x,
                    write.y,
                    write.width,
                    write.height,
                    write.byte_offset,
                    write.byte_len,
                    write.pixel_format,
                    write.payload_digest,
                    write.state.as_str(),
                    write.generation
                )
            })
            .collect(),
        framebuffer_flush_region_roots: semantic
            .framebuffer_flush_regions()
            .iter()
            .map(|flush| {
                format!(
                    "framebuffer-flush-region id={} owner_store={}@{} framebuffer_write={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} region={},{} {}x{} byte_range={}+{} pixel_format={} payload_digest={} state={} generation={}",
                    flush.id,
                    flush.owner_store,
                    flush.owner_store_generation,
                    flush.framebuffer_write,
                    flush.framebuffer_write_generation,
                    flush.display_capability,
                    flush.display_capability_generation,
                    flush.display,
                    flush.display_generation,
                    flush.framebuffer,
                    flush.framebuffer_generation,
                    flush.x,
                    flush.y,
                    flush.width,
                    flush.height,
                    flush.byte_offset,
                    flush.byte_len,
                    flush.pixel_format,
                    flush.payload_digest,
                    flush.state.as_str(),
                    flush.generation
                )
            })
            .collect(),
        framebuffer_dirty_region_roots: semantic
            .framebuffer_dirty_regions()
            .iter()
            .map(|dirty| {
                format!(
                    "framebuffer-dirty-region id={} owner_store={}@{} framebuffer_write={}@{} framebuffer_flush_region={}:{} display_capability={}@{} display={}@{} framebuffer={}@{} region={},{} {}x{} byte_range={}+{} pixel_format={} payload_digest={} dirty_at_event={} cleaned_at_event={} state={} generation={}",
                    dirty.id,
                    dirty.owner_store,
                    dirty.owner_store_generation,
                    dirty.framebuffer_write,
                    dirty.framebuffer_write_generation,
                    dirty
                        .framebuffer_flush_region
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    dirty
                        .framebuffer_flush_region_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    dirty.display_capability,
                    dirty.display_capability_generation,
                    dirty.display,
                    dirty.display_generation,
                    dirty.framebuffer,
                    dirty.framebuffer_generation,
                    dirty.x,
                    dirty.y,
                    dirty.width,
                    dirty.height,
                    dirty.byte_offset,
                    dirty.byte_len,
                    dirty.pixel_format,
                    dirty.payload_digest,
                    dirty.dirty_at_event,
                    dirty
                        .cleaned_at_event
                        .map(|event| event.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    dirty.state.as_str(),
                    dirty.generation
                )
            })
            .collect(),
        display_event_log_roots: semantic
            .display_event_logs()
            .iter()
            .map(|log| {
                format!(
                    "display-event-log id={} owner_store={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} framebuffer_dirty_region={}@{} events={}..{} event_count={} flush_count={} dirty_region_count={} state={} generation={}",
                    log.id,
                    log.owner_store,
                    log.owner_store_generation,
                    log.display_capability,
                    log.display_capability_generation,
                    log.display,
                    log.display_generation,
                    log.framebuffer,
                    log.framebuffer_generation,
                    log.framebuffer_dirty_region,
                    log.framebuffer_dirty_region_generation,
                    log.first_event,
                    log.last_event,
                    log.event_count,
                    log.flush_count,
                    log.dirty_region_count,
                    log.state.as_str(),
                    log.generation
                )
            })
            .collect(),
        display_cleanup_roots: semantic
            .display_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "display-cleanup id={} owner_store={}@{} display_capability={}@{} display={}@{} framebuffer={}@{} unmapped_mappings={} released_leases={} revoked_display_capabilities={} state={} generation={}",
                    cleanup.id,
                    cleanup.owner_store,
                    cleanup.owner_store_generation,
                    cleanup.display_capability,
                    cleanup.display_capability_generation,
                    cleanup.display,
                    cleanup.display_generation,
                    cleanup.framebuffer,
                    cleanup.framebuffer_generation,
                    cleanup.unmapped_framebuffer_mappings.len(),
                    cleanup.released_framebuffer_window_leases.len(),
                    cleanup.revoked_display_capabilities.len(),
                    cleanup.state.as_str(),
                    cleanup.generation
                )
            })
            .collect(),
        display_snapshot_barrier_roots: semantic
            .display_snapshot_barriers()
            .iter()
            .map(|barrier| {
                format!(
                    "display-snapshot-barrier id={} owner_store={}@{} display={}@{} framebuffer={}@{} cleanup={}:{} active_leases={} active_mappings={} dirty_regions={} snapshot_ok={} state={} generation={}",
                    barrier.id,
                    barrier.owner_store,
                    barrier.owner_store_generation,
                    barrier.display,
                    barrier.display_generation,
                    barrier.framebuffer,
                    barrier.framebuffer_generation,
                    barrier
                        .display_cleanup
                        .map(|cleanup| cleanup.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    barrier
                        .display_cleanup_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    barrier.active_framebuffer_window_lease_count,
                    barrier.active_framebuffer_mapping_count,
                    barrier.dirty_framebuffer_region_count,
                    barrier.snapshot_validation_ok,
                    barrier.state.as_str(),
                    barrier.generation
                )
            })
            .collect(),
        display_panic_last_frame_roots: semantic
            .display_panic_last_frames()
            .iter()
            .map(|frame| {
                format!(
                    "display-panic-last-frame id={} owner_store={}@{} display={}@{} framebuffer={}@{} barrier={}@{} display_event_log={}@{} framebuffer_write={}@{} framebuffer_flush_region={}@{} payload_digest={} summary_digest={} summary_record_bytes={} panic_epoch={} raw_framebuffer_bytes_exported={} state={} generation={}",
                    frame.id,
                    frame.owner_store,
                    frame.owner_store_generation,
                    frame.display,
                    frame.display_generation,
                    frame.framebuffer,
                    frame.framebuffer_generation,
                    frame.display_snapshot_barrier,
                    frame.display_snapshot_barrier_generation,
                    frame.display_event_log,
                    frame.display_event_log_generation,
                    frame.framebuffer_write,
                    frame.framebuffer_write_generation,
                    frame.framebuffer_flush_region,
                    frame.framebuffer_flush_region_generation,
                    frame.payload_digest,
                    frame.summary_digest,
                    frame.summary_record_bytes,
                    frame.panic_epoch,
                    frame.raw_framebuffer_bytes_exported,
                    frame.state.as_str(),
                    frame.generation
                )
            })
            .collect(),
        framebuffer_benchmark_roots: semantic
            .framebuffer_benchmarks()
            .iter()
            .map(|benchmark| {
                format!(
                    "framebuffer-benchmark id={} scenario={} owner_store={}@{} display={}@{} framebuffer={}@{} display_capability={}@{} framebuffer_write={}@{} framebuffer_flush_region={}@{} display_event_log={}@{} display_snapshot_barrier={}@{} sample_frames={} sample_bytes={} frame_area_pixels={} measured_nanos={} budget_nanos={} throughput_bytes_per_sec={} flushes_per_sec_milli={} p50_latency_nanos={} p99_latency_nanos={} state={} generation={}",
                    benchmark.id,
                    benchmark.scenario,
                    benchmark.owner_store,
                    benchmark.owner_store_generation,
                    benchmark.display,
                    benchmark.display_generation,
                    benchmark.framebuffer,
                    benchmark.framebuffer_generation,
                    benchmark.display_capability,
                    benchmark.display_capability_generation,
                    benchmark.framebuffer_write,
                    benchmark.framebuffer_write_generation,
                    benchmark.framebuffer_flush_region,
                    benchmark.framebuffer_flush_region_generation,
                    benchmark.display_event_log,
                    benchmark.display_event_log_generation,
                    benchmark.display_snapshot_barrier,
                    benchmark.display_snapshot_barrier_generation,
                    benchmark.sample_frames,
                    benchmark.sample_bytes,
                    benchmark.frame_area_pixels,
                    benchmark.measured_nanos,
                    benchmark.budget_nanos,
                    benchmark.throughput_bytes_per_sec,
                    benchmark.flushes_per_sec_milli,
                    benchmark.p50_latency_nanos,
                    benchmark.p99_latency_nanos,
                    benchmark.state.as_str(),
                    benchmark.generation
                )
            })
            .collect(),
        activation_resume_roots: semantic
            .activation_resumes()
            .iter()
            .map(|resume| {
                format!(
                    "activation-resume id={} decision={}@{} activation={}@{}->{} vector_status={} saved_vector_state={} restored_vector_state={} state={} generation={}",
                    resume.id,
                    resume.scheduler_decision,
                    resume.scheduler_decision_generation,
                    resume.activation,
                    resume.activation_generation_before,
                    resume.activation_generation_after,
                    resume.vector_status.as_str(),
                    resume
                        .saved_vector_state
                        .map(|state| state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    resume
                        .restored_vector_state
                        .map(|state| state.summary())
                        .unwrap_or_else(|| "none".to_owned()),
                    resume.state.as_str(),
                    resume.generation
                )
            })
            .collect(),
        activation_wait_roots: semantic
            .activation_waits()
            .iter()
            .map(|activation_wait| {
                format!(
                    "activation-wait id={} activation={}@{}->{} wait={}@{} state={} generation={}",
                    activation_wait.id,
                    activation_wait.activation,
                    activation_wait.activation_generation_before,
                    activation_wait.activation_generation_after_block,
                    activation_wait.wait,
                    activation_wait.wait_generation,
                    activation_wait.state.as_str(),
                    activation_wait.generation
                )
            })
            .collect(),
        activation_cleanup_roots: semantic
            .activation_cleanups()
            .iter()
            .map(|cleanup| {
                format!(
                    "activation-cleanup id={} store={}@{}->{} activation={}@{}->{} wait={}@{} state={} generation={}",
                    cleanup.id,
                    cleanup.store,
                    cleanup.target_store_generation,
                    cleanup.result_store_generation,
                    cleanup.activation,
                    cleanup.activation_generation_before,
                    cleanup.activation_generation_after,
                    cleanup
                        .wait
                        .map(|wait| wait.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .wait_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup.state.as_str(),
                    cleanup.generation
                )
            })
            .collect(),
        preemption_latency_roots: semantic
            .preemption_latency_samples()
            .iter()
            .map(|sample| {
                format!(
                    "preemption-latency id={} timer={}@{} preemption={}@{} decision={}@{} resume={}@{} events={} measured_nanos={} budget_nanos={} state={} generation={}",
                    sample.id,
                    sample.timer_interrupt,
                    sample.timer_interrupt_generation,
                    sample.preemption,
                    sample.preemption_generation,
                    sample.scheduler_decision,
                    sample.scheduler_decision_generation,
                    sample.activation_resume,
                    sample.activation_resume_generation,
                    sample.interrupt_to_resume_events,
                    sample.measured_nanos,
                    sample.budget_nanos,
                    sample.state.as_str(),
                    sample.generation
                )
            })
            .collect(),
        hart_event_attribution_roots: semantic
            .hart_event_attributions()
            .iter()
            .map(|attribution| {
                format!(
                    "hart-event-attribution id={} hart={}@{} hardware_id={} event={} kind={} generation={}",
                    attribution.id,
                    attribution.hart,
                    attribution.hart_generation,
                    attribution.hardware_hart,
                    attribution.event,
                    attribution.event_kind,
                    attribution.generation
                )
            })
            .collect(),
        resource_roots: semantic
            .resources()
            .iter()
            .map(|resource| {
                format!(
                    "resource id={} kind={} generation={} live={}",
                    resource.id,
                    resource.kind.as_str(),
                    resource.generation,
                    resource.live
                )
            })
            .collect(),
        authority_roots: semantic
            .authority_bindings()
            .iter()
            .map(|authority| {
                format!(
                    "authority:{}:{}:{}:gen{}:{}",
                    authority.id,
                    authority.subject,
                    authority.object,
                    authority.generation,
                    authority.state.as_str()
                )
            })
            .collect(),
        wait_roots: target_v1
            .wait_records
            .iter()
            .map(|wait| {
                format!(
                    "wait id={} state={} generation={}",
                    wait.id, wait.state, wait.generation
                )
            })
            .chain(semantic.wait_records().iter().map(|wait| {
                format!(
                    "wait id={} state={} generation={}",
                    wait.id,
                    wait.state.as_str(),
                    wait.generation
                )
            }))
            .collect(),
        store_roots: semantic
            .stores()
            .iter()
            .map(|store| {
                format!(
                    "store id={} package={} state={} generation={}",
                    store.id,
                    store.package,
                    store.state.as_str(),
                    store.generation
                )
            })
            .collect(),
        capability_roots: capabilities
            .iter()
            .map(|capability| {
                format!(
                    "cap:{}:{}:{}:{}:gen{}:{}",
                    capability.subject,
                    capability.class,
                    capability.object,
                    capability.rights.join("+"),
                    capability.generation,
                    capability.source
                )
            })
            .collect(),
        target_store_record_roots: target_v1
            .store_records
            .iter()
            .map(|store| {
                format!(
                    "target-store id={} package={} artifact={} state={} generation={} fault_domain={}",
                    store.id,
                    store.package,
                    store.artifact,
                    store.state,
                    store.generation,
                    store.fault_domain
                )
            })
            .collect(),
        target_capability_record_roots: target_v1
            .capability_records
            .iter()
            .map(|capability| {
                format!(
                    "target-capability id={} subject={} object={} class={} rights={} generation={} owner_store={}@{} revoked={} source={}",
                    capability.id,
                    capability.subject,
                    capability.object,
                    capability.class,
                    capability.rights.join("+"),
                    capability.generation,
                    capability
                        .owner_store
                        .map(|store| store.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    capability
                        .owner_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    capability.revoked,
                    capability.source
                )
            })
            .collect(),
        fast_path_roots: semantic
            .fast_path_plans()
            .iter()
            .map(|plan| {
                format!(
                    "fastpath:{}:gen{}:valid{}",
                    plan.id, plan.generation, plan.valid
                )
            })
            .collect(),
        boundary_roots: semantic
            .boundaries()
            .iter()
            .map(|boundary| boundary.summary())
            .collect(),
        artifact_verification_roots: semantic
            .artifact_verifications()
            .iter()
            .map(|artifact| artifact.summary())
            .collect(),
        store_activation_roots: semantic
            .store_activations()
            .iter()
            .map(|activation| activation.summary())
            .collect(),
        executor_transition_roots: semantic
            .store_executor_transition_tail(semantic.store_executor_transition_count()),
        target_artifact_roots: target_v1
            .target_artifacts
            .iter()
            .map(|artifact| {
                format!(
                    "target-artifact id={} package={} artifact={} profile={} artifact_hash={} hash_status={} abi={} code_hash={} signature={} signature_status={} signature_verified={} signer={}",
                    artifact.id,
                    artifact.package,
                    artifact.artifact_name,
                    artifact.target_profile,
                    artifact.artifact_hash,
                    artifact.hash_status,
                    artifact.abi_fingerprint,
                    artifact.code_hash,
                    artifact.signature_scheme,
                    artifact.signature_status,
                    artifact.signature_verified,
                    artifact.signer
                )
            })
            .collect(),
        code_object_roots: target_v1
            .code_objects
            .iter()
            .map(|code| {
                let store = code
                    .bound_store
                    .map(|store| {
                        format!(
                            "{store}@{}",
                            code.bound_store_generation
                                .map(|generation| generation.to_string())
                                .unwrap_or_else(|| "unknown".to_owned())
                        )
                    })
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "code-object id={} artifact={} package={} state={} store={} generation={}",
                    code.id, code.artifact_id, code.package, code.state, store, code.generation
                )
            })
            .collect(),
        activation_record_roots: target_v1
            .activation_records
            .iter()
            .map(|activation| {
                let wait = activation
                    .blocked_wait
                    .map(|wait| wait.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                let trap = activation
                    .trap
                    .map(|trap| trap.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "activation id={} store={} store_generation={} code={} code_generation={} state={} entry={} wait={} trap={} dmw={}",
                    activation.id,
                    activation.store,
                    activation.store_generation,
                    activation.code_object,
                    activation.code_generation,
                    activation.state,
                    activation.entry,
                    wait,
                    trap,
                    activation.active_dmw_leases
                )
            })
            .collect(),
        trap_roots: target_v1
            .trap_records
            .iter()
            .map(|trap| {
                let store = trap
                    .store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                let activation = trap
                    .activation
                    .map(|activation| activation.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                let trap_kind = trap.trap_kind.as_deref().unwrap_or("none");
                let simd = trap
                    .simd_attribution
                    .as_ref()
                    .map(|attribution| attribution.classification.clone())
                    .unwrap_or_else(|| "none".to_owned());
                format!(
                    "trap id={} class={} kind={} store={} activation={} simd={} effect={} detail={}",
                    trap.id, trap.class, trap_kind, store, activation, simd, trap.effect, trap.detail
                )
            })
            .collect(),
        hostcall_trace_roots: target_v1
            .hostcall_trace
            .iter()
            .map(|trace| {
                format!(
                    "hostcall abi={} frame_size={} seq={} caller_offset={} record_mode={} activation={} activation_generation={} store={} code={} artifact={}@{} number={} category={} subject={} object={} op={} cap_args={} allowed={} result={} ret={}",
                    trace.abi_version,
                    trace.frame_size,
                    trace.hostcall_seq,
                    trace.caller_offset,
                    trace.record_mode,
                    trace.activation,
                    trace.activation_generation,
                    trace.store,
                    trace.code_object,
                    trace.artifact,
                    trace.artifact_generation,
                    trace.hostcall_number,
                    trace.category,
                    trace.subject,
                    trace.object,
                    trace.operation,
                    trace.cap_args.len(),
                    trace.allowed,
                    trace.result,
                    trace.ret_tag
                )
            })
            .collect(),
        migration_object_roots: target_v1
            .migration_objects
            .iter()
            .map(|object| {
                format!(
                    "migration-object object={} class={} reason={}",
                    object.object, object.class, object.reason
                )
            })
            .collect(),
        tombstone_roots: target_v1
            .tombstones
            .iter()
            .map(|tombstone| {
                format!(
                    "tombstone kind={} id={} generation={} died_at={} reason={}",
                    tombstone.kind,
                    tombstone.id,
                    tombstone.generation,
                    tombstone.died_at,
                    tombstone.reason
                )
            })
            .collect(),
        contract_violation_roots: target_v1
            .contract_violations
            .iter()
            .map(|violation| {
                let to = violation.to.as_ref().map_or_else(
                    || "none".to_owned(),
                    |to| format!("{}:{}@{}", to.kind, to.id, to.generation),
                );
                format!(
                    "contract-violation kind={} edge={} from={}:{}@{} to={} detail={}",
                    violation.kind,
                    violation.edge,
                    violation.from.kind,
                    violation.from.id,
                    violation.from.generation,
                    to,
                    violation.detail
                )
            })
            .collect(),
        cleanup_roots: target_v1
            .cleanup_transactions
            .iter()
            .map(|cleanup| {
                format!(
                    "cleanup id={} target_store={}@{} result_store_generation={} activation={} code={} generation={} state={} reason={} released_dmw={} cancelled_waits={} revoked_caps={} dropped_resources={} unbound_code={} effect={} steps={}",
                    cleanup.id,
                    cleanup.store,
                    cleanup.store_generation,
                    cleanup
                        .result_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .activation
                        .zip(cleanup.activation_generation)
                        .map(|(activation, generation)| format!("{activation}@{generation}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup
                        .code_object
                        .zip(cleanup.code_generation)
                        .map(|(code, generation)| format!("{code}@{generation}"))
                        .unwrap_or_else(|| "none".to_owned()),
                    cleanup.generation,
                    cleanup.state,
                    cleanup.reason,
                    cleanup.released_dmw_leases,
                    cleanup.cancelled_waits,
                    cleanup.revoked_capabilities.len(),
                    cleanup.dropped_resources,
                    cleanup.unbound_code_object,
                    cleanup.effect,
                    cleanup
                        .steps
                        .iter()
                        .map(|step| format!("{}:{}", step.step, step.state))
                        .collect::<Vec<_>>()
                        .join("|")
                )
            })
            .collect(),
        memory_policy_roots: target_v1
            .memory_policies
            .iter()
            .map(|policy| {
                format!(
                    "memory-policy class={} owner={} perms={} migration={} snapshot={} cleanup={} alias_guest={} cross_pending={} executable={}",
                    policy.class,
                    policy.owner_kind,
                    policy.permissions,
                    policy.migration_policy,
                    policy.snapshot_policy,
                    policy.cleanup_policy,
                    policy.can_alias_guest_memory,
                    policy.can_cross_pending,
                    policy.can_be_executable
                )
            })
            .collect(),
        snapshot_validation_roots: validation_roots(&target_v1.snapshot_validation),
        replay_validation_roots: validation_roots(&target_v1.replay_validation),
        substrate_event_roots: target_v1
            .substrate_events
            .iter()
            .map(|event| {
                format!(
                    "substrate-event:{}:{}:{} requester={}",
                    event.event_kind,
                    event.authority,
                    event.operation,
                    event.requester.as_deref().unwrap_or("none")
                )
            })
            .collect(),
        command_result_roots: target_v1
            .command_results
            .iter()
            .map(|result| {
                format!(
                    "command-result:{}:{}:{} issuer={}",
                    result.id, result.command, result.status, result.issuer
                )
            })
            .collect(),
        interface_event_roots: target_v1
            .interface_events
            .iter()
            .map(|event| {
                format!(
                    "interface-event:{}:{}:{} requester={}",
                    event.interface_kind,
                    event.interface,
                    event.operation,
                    event.requester.as_deref().unwrap_or("none")
                )
            })
            .collect(),
        event_log_tail: semantic
            .event_log_tail(16)
            .iter()
            .map(|event| event.summary())
            .chain(target_v1.target_event_tail.iter().cloned())
            .collect(),
    }
}
