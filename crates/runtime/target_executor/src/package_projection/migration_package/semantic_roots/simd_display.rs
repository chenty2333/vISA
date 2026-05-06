use super::*;

pub(super) fn push_simd_display_roots(
    roots: &mut SemanticRootSetManifest,
    semantic: &SemanticGraph,
    _capabilities: &[MigrationCapabilityManifest],
    _target_v1: &TargetExecutorV1Report,
) {
    roots.target_feature_set_roots = semantic            .target_feature_sets()
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
            .collect();
    roots.vector_state_roots = semantic            .vector_states()
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
            .collect();
    roots.simd_fault_injection_roots = semantic            .simd_fault_injections()
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
            .collect();
    roots.simd_benchmark_roots = semantic            .simd_benchmarks()
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
            .collect();
    roots.simd_context_switch_benchmark_roots = semantic            .simd_context_switch_benchmarks()
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
            .collect();
    roots.framebuffer_object_roots = semantic            .framebuffer_objects()
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
            .collect();
    roots.display_object_roots = semantic            .display_objects()
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
            .collect();
    roots.display_capability_roots = semantic            .display_capabilities()
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
            .collect();
    roots.framebuffer_window_lease_roots = semantic            .framebuffer_window_leases()
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
            .collect();
    roots.framebuffer_mapping_roots = semantic            .framebuffer_mappings()
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
            .collect();
    roots.framebuffer_write_roots = semantic            .framebuffer_writes()
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
            .collect();
    roots.framebuffer_flush_region_roots = semantic            .framebuffer_flush_regions()
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
            .collect();
    roots.framebuffer_dirty_region_roots = semantic            .framebuffer_dirty_regions()
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
            .collect();
    roots.display_event_log_roots = semantic            .display_event_logs()
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
            .collect();
    roots.display_cleanup_roots = semantic            .display_cleanups()
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
            .collect();
    roots.display_snapshot_barrier_roots = semantic            .display_snapshot_barriers()
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
            .collect();
    roots.display_panic_last_frame_roots = semantic            .display_panic_last_frames()
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
            .collect();
    roots.framebuffer_benchmark_roots = semantic            .framebuffer_benchmarks()
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
            .collect();
}
