use super::{super::super::*, *};

pub(crate) fn block_pending_io_policy_manifest(
    policy: &semantic_core::BlockPendingIoPolicyRecord,
) -> BlockPendingIoPolicyManifest {
    BlockPendingIoPolicyManifest {
        id: policy.id,
        block_wait: policy.block_wait,
        block_wait_generation: policy.block_wait_generation,
        wait: policy.wait,
        wait_generation: policy.wait_generation,
        block_request: policy.block_request,
        block_request_generation: policy.block_request_generation,
        retry_request: policy.retry_request,
        retry_request_generation: policy.retry_request_generation,
        block_device: policy.block_device,
        block_device_generation: policy.block_device_generation,
        block_range: policy.block_range,
        block_range_generation: policy.block_range_generation,
        operation: policy.operation.as_str().to_owned(),
        sequence: policy.sequence,
        byte_len: policy.byte_len,
        action: policy.action.as_str().to_owned(),
        errno: policy.errno,
        retry_attempt: policy.retry_attempt,
        max_retries: policy.max_retries,
        generation: policy.generation,
        state: policy.state.as_str().to_owned(),
        recorded_at_event: policy.recorded_at_event,
        note: policy.note.clone(),
    }
}

pub(crate) fn block_request_generation_audit_manifest(
    audit: &semantic_core::BlockRequestGenerationAuditRecord,
) -> BlockRequestGenerationAuditManifest {
    BlockRequestGenerationAuditManifest {
        id: audit.id,
        block_device: audit.block_device,
        block_device_generation: audit.block_device_generation,
        block_range: audit.block_range,
        block_range_generation: audit.block_range_generation,
        block_request: audit.block_request,
        block_request_generation: audit.block_request_generation,
        backend: contract_object_ref_manifest(audit.backend),
        dma_buffer: contract_object_ref_manifest(audit.dma_buffer),
        rejected_completion_generation_probes: audit.rejected_completion_generation_probes,
        rejected_wait_generation_probes: audit.rejected_wait_generation_probes,
        rejected_dma_generation_probes: audit.rejected_dma_generation_probes,
        rejected_queue_generation_probes: audit.rejected_queue_generation_probes,
        generation: audit.generation,
        state: audit.state.as_str().to_owned(),
        recorded_at_event: audit.recorded_at_event,
        note: audit.note.clone(),
    }
}

pub(crate) fn block_benchmark_manifest(
    benchmark: &semantic_core::BlockBenchmarkRecord,
) -> BlockBenchmarkManifest {
    BlockBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        backend: contract_object_ref_manifest(benchmark.backend),
        block_device: benchmark.block_device,
        block_device_generation: benchmark.block_device_generation,
        block_range: benchmark.block_range,
        block_range_generation: benchmark.block_range_generation,
        read_path: benchmark.read_path,
        read_path_generation: benchmark.read_path_generation,
        write_path: benchmark.write_path,
        write_path_generation: benchmark.write_path_generation,
        request_queue: benchmark.request_queue,
        request_queue_generation: benchmark.request_queue_generation,
        block_dma_buffer: benchmark.block_dma_buffer,
        block_dma_buffer_generation: benchmark.block_dma_buffer_generation,
        sample_requests: benchmark.sample_requests,
        sample_bytes: benchmark.sample_bytes,
        read_completed_requests: benchmark.read_completed_requests,
        write_completed_requests: benchmark.write_completed_requests,
        queue_completed_requests: benchmark.queue_completed_requests,
        measured_nanos: benchmark.measured_nanos,
        budget_nanos: benchmark.budget_nanos,
        iops: benchmark.iops,
        throughput_bytes_per_sec: benchmark.throughput_bytes_per_sec,
        p50_latency_nanos: benchmark.p50_latency_nanos,
        p99_latency_nanos: benchmark.p99_latency_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn block_recovery_benchmark_manifest(
    benchmark: &semantic_core::BlockRecoveryBenchmarkRecord,
) -> BlockRecoveryBenchmarkManifest {
    BlockRecoveryBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        cleanup: benchmark.cleanup,
        cleanup_generation: benchmark.cleanup_generation,
        io_cleanup: benchmark.io_cleanup,
        io_cleanup_generation: benchmark.io_cleanup_generation,
        backend: contract_object_ref_manifest(benchmark.backend),
        block_device: benchmark.block_device,
        block_device_generation: benchmark.block_device_generation,
        driver_store: benchmark.driver_store,
        driver_store_generation: benchmark.driver_store_generation,
        device: benchmark.device,
        device_generation: benchmark.device_generation,
        driver_binding: benchmark.driver_binding,
        driver_binding_generation: benchmark.driver_binding_generation,
        recovery_start_event: benchmark.recovery_start_event,
        recovery_complete_event: benchmark.recovery_complete_event,
        cancelled_block_waits: benchmark.cancelled_block_waits,
        cancelled_wait_tokens: benchmark.cancelled_wait_tokens,
        released_dma_buffers: benchmark.released_dma_buffers,
        revoked_device_capabilities: benchmark.revoked_device_capabilities,
        recovery_nanos: benchmark.recovery_nanos,
        budget_nanos: benchmark.budget_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn target_feature_set_manifest(
    feature: &semantic_core::TargetFeatureSetRecord,
) -> TargetFeatureSetManifest {
    TargetFeatureSetManifest {
        id: feature.id,
        name: feature.name.clone(),
        discovery_source: feature.discovery_source.clone(),
        target_profile: feature.target_profile.clone(),
        target_arch: feature.target_arch.clone(),
        base_isa: feature.base_isa.clone(),
        simd_abi: feature.simd_abi.clone(),
        simd_supported: feature.simd_supported,
        vector_register_count: feature.vector_register_count,
        vector_register_bits: feature.vector_register_bits,
        scalar_fallback: feature.scalar_fallback,
        unsupported_reason: feature.unsupported_reason.clone(),
        generation: feature.generation,
        state: feature.state.as_str().to_owned(),
        recorded_at_event: feature.recorded_at_event,
        note: feature.note.clone(),
    }
}

pub(crate) fn vector_state_manifest(
    vector_state: &semantic_core::VectorStateRecord,
) -> VectorStateManifest {
    VectorStateManifest {
        id: vector_state.id,
        owner_activation: contract_object_ref_manifest(vector_state.owner_activation),
        owner_store: contract_object_ref_manifest(vector_state.owner_store),
        code_object: contract_object_ref_manifest(vector_state.code_object),
        target_feature_set: contract_object_ref_manifest(vector_state.target_feature_set),
        simd_abi: vector_state.simd_abi.clone(),
        vector_register_count: vector_state.vector_register_count,
        vector_register_bits: vector_state.vector_register_bits,
        register_bytes: vector_state.register_bytes,
        generation: vector_state.generation,
        state: vector_state.state.as_str().to_owned(),
        recorded_at_event: vector_state.recorded_at_event,
        note: vector_state.note.clone(),
    }
}

pub(crate) fn simd_fault_injection_manifest(
    injection: &semantic_core::SimdFaultInjectionRecord,
) -> SimdFaultInjectionManifest {
    SimdFaultInjectionManifest {
        id: injection.id,
        activation: contract_object_ref_manifest(injection.activation),
        code_object: contract_object_ref_manifest(injection.code_object),
        trap: contract_object_ref_manifest(injection.trap),
        target_feature_set: contract_object_ref_manifest(injection.target_feature_set),
        vector_state: injection.vector_state.map(contract_object_ref_manifest),
        kind: injection.kind.as_str().to_owned(),
        effect: injection.effect.as_str().to_owned(),
        required_abi: injection.required_abi.clone(),
        vector_register_count: injection.vector_register_count,
        vector_register_bits: injection.vector_register_bits,
        injected_faults: injection.injected_faults,
        generation: injection.generation,
        state: injection.state.as_str().to_owned(),
        recorded_at_event: injection.recorded_at_event,
        note: injection.note.clone(),
    }
}

pub(crate) fn simd_benchmark_manifest(
    benchmark: &semantic_core::SimdBenchmarkRecord,
) -> SimdBenchmarkManifest {
    SimdBenchmarkManifest {
        id: benchmark.id,
        target_feature_set: contract_object_ref_manifest(benchmark.target_feature_set),
        scalar_code_object: contract_object_ref_manifest(benchmark.scalar_code_object),
        vector_code_object: contract_object_ref_manifest(benchmark.vector_code_object),
        simd_abi: benchmark.simd_abi.clone(),
        vector_register_count: benchmark.vector_register_count,
        vector_register_bits: benchmark.vector_register_bits,
        workload_units: benchmark.workload_units,
        scalar_nanos: benchmark.scalar_nanos,
        vector_nanos: benchmark.vector_nanos,
        speedup_milli: benchmark.speedup_milli,
        context_overhead_nanos: benchmark.context_overhead_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn simd_context_switch_benchmark_manifest(
    benchmark: &semantic_core::SimdContextSwitchBenchmarkRecord,
) -> SimdContextSwitchBenchmarkManifest {
    SimdContextSwitchBenchmarkManifest {
        id: benchmark.id,
        preemption: contract_object_ref_manifest(benchmark.preemption),
        activation_resume: contract_object_ref_manifest(benchmark.activation_resume),
        saved_vector_state: contract_object_ref_manifest(benchmark.saved_vector_state),
        restored_vector_state: contract_object_ref_manifest(benchmark.restored_vector_state),
        target_feature_set: contract_object_ref_manifest(benchmark.target_feature_set),
        simd_abi: benchmark.simd_abi.clone(),
        vector_register_count: benchmark.vector_register_count,
        vector_register_bits: benchmark.vector_register_bits,
        sample_count: benchmark.sample_count,
        scalar_context_switch_nanos: benchmark.scalar_context_switch_nanos,
        vector_context_switch_nanos: benchmark.vector_context_switch_nanos,
        overhead_nanos: benchmark.overhead_nanos,
        budget_nanos: benchmark.budget_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn framebuffer_object_manifest(
    framebuffer: &semantic_core::FramebufferObjectRecord,
) -> FramebufferObjectManifest {
    FramebufferObjectManifest {
        id: framebuffer.id,
        name: framebuffer.name.clone(),
        resource: framebuffer.resource,
        resource_generation: framebuffer.resource_generation,
        width: framebuffer.width,
        height: framebuffer.height,
        stride_bytes: framebuffer.stride_bytes,
        pixel_format: framebuffer.pixel_format.clone(),
        byte_len: framebuffer.byte_len,
        generation: framebuffer.generation,
        state: framebuffer.state.as_str().to_owned(),
        recorded_at_event: framebuffer.recorded_at_event,
        note: framebuffer.note.clone(),
    }
}

pub(crate) fn display_object_manifest(
    display: &semantic_core::DisplayObjectRecord,
) -> DisplayObjectManifest {
    DisplayObjectManifest {
        id: display.id,
        name: display.name.clone(),
        framebuffer: display.framebuffer,
        framebuffer_generation: display.framebuffer_generation,
        mode_name: display.mode_name.clone(),
        width: display.width,
        height: display.height,
        refresh_millihz: display.refresh_millihz,
        generation: display.generation,
        state: display.state.as_str().to_owned(),
        recorded_at_event: display.recorded_at_event,
        note: display.note.clone(),
    }
}

pub(crate) fn display_capability_manifest(
    capability: &semantic_core::DisplayCapabilityRecord,
) -> DisplayCapabilityManifest {
    DisplayCapabilityManifest {
        id: capability.id,
        owner_store: capability.owner_store,
        owner_store_generation: capability.owner_store_generation,
        display: capability.display,
        display_generation: capability.display_generation,
        framebuffer: capability.framebuffer,
        framebuffer_generation: capability.framebuffer_generation,
        capability: capability.capability,
        capability_generation: capability.capability_generation,
        handle_slot: capability.handle_slot,
        handle_generation: capability.handle_generation,
        handle_tag: capability.handle_tag,
        operations: capability.operations.clone(),
        generation: capability.generation,
        state: capability.state.as_str().to_owned(),
        recorded_at_event: capability.recorded_at_event,
        note: capability.note.clone(),
    }
}

pub(crate) fn framebuffer_window_lease_manifest(
    lease: &semantic_core::FramebufferWindowLeaseRecord,
) -> FramebufferWindowLeaseManifest {
    FramebufferWindowLeaseManifest {
        id: lease.id,
        owner_store: lease.owner_store,
        owner_store_generation: lease.owner_store_generation,
        display_capability: lease.display_capability,
        display_capability_generation: lease.display_capability_generation,
        display: lease.display,
        display_generation: lease.display_generation,
        framebuffer: lease.framebuffer,
        framebuffer_generation: lease.framebuffer_generation,
        x: lease.x,
        y: lease.y,
        width: lease.width,
        height: lease.height,
        byte_offset: lease.byte_offset,
        byte_len: lease.byte_len,
        access: lease.access.clone(),
        generation: lease.generation,
        state: lease.state.as_str().to_owned(),
        recorded_at_event: lease.recorded_at_event,
        note: lease.note.clone(),
    }
}

pub(crate) fn framebuffer_mapping_manifest(
    mapping: &semantic_core::FramebufferMappingRecord,
) -> FramebufferMappingManifest {
    FramebufferMappingManifest {
        id: mapping.id,
        owner_store: mapping.owner_store,
        owner_store_generation: mapping.owner_store_generation,
        framebuffer_window_lease: mapping.framebuffer_window_lease,
        framebuffer_window_lease_generation: mapping.framebuffer_window_lease_generation,
        display_capability: mapping.display_capability,
        display_capability_generation: mapping.display_capability_generation,
        display: mapping.display,
        display_generation: mapping.display_generation,
        framebuffer: mapping.framebuffer,
        framebuffer_generation: mapping.framebuffer_generation,
        map_handle_slot: mapping.map_handle_slot,
        map_handle_generation: mapping.map_handle_generation,
        map_handle_tag: mapping.map_handle_tag,
        x: mapping.x,
        y: mapping.y,
        width: mapping.width,
        height: mapping.height,
        byte_offset: mapping.byte_offset,
        byte_len: mapping.byte_len,
        access: mapping.access.clone(),
        mode: mapping.mode.clone(),
        generation: mapping.generation,
        state: mapping.state.as_str().to_owned(),
        recorded_at_event: mapping.recorded_at_event,
        note: mapping.note.clone(),
    }
}

pub(crate) fn framebuffer_write_manifest(
    write: &semantic_core::FramebufferWriteRecord,
) -> FramebufferWriteManifest {
    FramebufferWriteManifest {
        id: write.id,
        owner_store: write.owner_store,
        owner_store_generation: write.owner_store_generation,
        framebuffer_mapping: write.framebuffer_mapping,
        framebuffer_mapping_generation: write.framebuffer_mapping_generation,
        framebuffer_window_lease: write.framebuffer_window_lease,
        framebuffer_window_lease_generation: write.framebuffer_window_lease_generation,
        display_capability: write.display_capability,
        display_capability_generation: write.display_capability_generation,
        display: write.display,
        display_generation: write.display_generation,
        framebuffer: write.framebuffer,
        framebuffer_generation: write.framebuffer_generation,
        map_handle_slot: write.map_handle_slot,
        map_handle_generation: write.map_handle_generation,
        map_handle_tag: write.map_handle_tag,
        x: write.x,
        y: write.y,
        width: write.width,
        height: write.height,
        byte_offset: write.byte_offset,
        byte_len: write.byte_len,
        pixel_format: write.pixel_format.clone(),
        payload_digest: write.payload_digest,
        generation: write.generation,
        state: write.state.as_str().to_owned(),
        recorded_at_event: write.recorded_at_event,
        note: write.note.clone(),
    }
}

pub(crate) fn framebuffer_flush_region_manifest(
    flush: &semantic_core::FramebufferFlushRegionRecord,
) -> FramebufferFlushRegionManifest {
    FramebufferFlushRegionManifest {
        id: flush.id,
        owner_store: flush.owner_store,
        owner_store_generation: flush.owner_store_generation,
        framebuffer_write: flush.framebuffer_write,
        framebuffer_write_generation: flush.framebuffer_write_generation,
        display_capability: flush.display_capability,
        display_capability_generation: flush.display_capability_generation,
        display: flush.display,
        display_generation: flush.display_generation,
        framebuffer: flush.framebuffer,
        framebuffer_generation: flush.framebuffer_generation,
        x: flush.x,
        y: flush.y,
        width: flush.width,
        height: flush.height,
        byte_offset: flush.byte_offset,
        byte_len: flush.byte_len,
        pixel_format: flush.pixel_format.clone(),
        payload_digest: flush.payload_digest,
        generation: flush.generation,
        state: flush.state.as_str().to_owned(),
        recorded_at_event: flush.recorded_at_event,
        note: flush.note.clone(),
    }
}

pub(crate) fn framebuffer_dirty_region_manifest(
    dirty: &semantic_core::FramebufferDirtyRegionRecord,
) -> FramebufferDirtyRegionManifest {
    FramebufferDirtyRegionManifest {
        id: dirty.id,
        owner_store: dirty.owner_store,
        owner_store_generation: dirty.owner_store_generation,
        framebuffer_write: dirty.framebuffer_write,
        framebuffer_write_generation: dirty.framebuffer_write_generation,
        framebuffer_flush_region: dirty.framebuffer_flush_region,
        framebuffer_flush_region_generation: dirty.framebuffer_flush_region_generation,
        display_capability: dirty.display_capability,
        display_capability_generation: dirty.display_capability_generation,
        display: dirty.display,
        display_generation: dirty.display_generation,
        framebuffer: dirty.framebuffer,
        framebuffer_generation: dirty.framebuffer_generation,
        x: dirty.x,
        y: dirty.y,
        width: dirty.width,
        height: dirty.height,
        byte_offset: dirty.byte_offset,
        byte_len: dirty.byte_len,
        pixel_format: dirty.pixel_format.clone(),
        payload_digest: dirty.payload_digest,
        generation: dirty.generation,
        state: dirty.state.as_str().to_owned(),
        dirty_at_event: dirty.dirty_at_event,
        cleaned_at_event: dirty.cleaned_at_event,
        recorded_at_event: dirty.recorded_at_event,
        note: dirty.note.clone(),
    }
}

pub(crate) fn display_event_log_manifest(
    log: &semantic_core::DisplayEventLogRecord,
) -> DisplayEventLogManifest {
    DisplayEventLogManifest {
        id: log.id,
        owner_store: log.owner_store,
        owner_store_generation: log.owner_store_generation,
        display_capability: log.display_capability,
        display_capability_generation: log.display_capability_generation,
        display: log.display,
        display_generation: log.display_generation,
        framebuffer: log.framebuffer,
        framebuffer_generation: log.framebuffer_generation,
        framebuffer_dirty_region: log.framebuffer_dirty_region,
        framebuffer_dirty_region_generation: log.framebuffer_dirty_region_generation,
        first_event: log.first_event,
        last_event: log.last_event,
        event_count: log.event_count,
        flush_count: log.flush_count,
        dirty_region_count: log.dirty_region_count,
        generation: log.generation,
        state: log.state.as_str().to_owned(),
        recorded_at_event: log.recorded_at_event,
        note: log.note.clone(),
    }
}

pub(crate) fn display_cleanup_step_manifest(
    step: &semantic_core::DisplayCleanupStepRecord,
) -> DisplayCleanupStepManifest {
    DisplayCleanupStepManifest {
        kind: step.kind.as_str().to_owned(),
        target: contract_object_ref_manifest(step.target),
        observed_generation: step.observed_generation,
        status: step.status.as_str().to_owned(),
        event: step.event,
    }
}

pub(crate) fn display_cleanup_manifest(
    cleanup: &semantic_core::DisplayCleanupRecord,
) -> DisplayCleanupManifest {
    DisplayCleanupManifest {
        id: cleanup.id,
        owner_store: cleanup.owner_store,
        owner_store_generation: cleanup.owner_store_generation,
        display_capability: cleanup.display_capability,
        display_capability_generation: cleanup.display_capability_generation,
        display: cleanup.display,
        display_generation: cleanup.display_generation,
        framebuffer: cleanup.framebuffer,
        framebuffer_generation: cleanup.framebuffer_generation,
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        unmapped_framebuffer_mappings: cleanup
            .unmapped_framebuffer_mappings
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        released_framebuffer_window_leases: cleanup
            .released_framebuffer_window_leases
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_display_capabilities: cleanup
            .revoked_display_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        revoked_capabilities: cleanup
            .revoked_capabilities
            .iter()
            .copied()
            .map(contract_object_ref_manifest)
            .collect(),
        steps: cleanup.steps.iter().map(display_cleanup_step_manifest).collect(),
        note: cleanup.note.clone(),
    }
}

pub(crate) fn display_snapshot_barrier_manifest(
    barrier: &semantic_core::DisplaySnapshotBarrierRecord,
) -> DisplaySnapshotBarrierManifest {
    DisplaySnapshotBarrierManifest {
        id: barrier.id,
        owner_store: barrier.owner_store,
        owner_store_generation: barrier.owner_store_generation,
        display: barrier.display,
        display_generation: barrier.display_generation,
        framebuffer: barrier.framebuffer,
        framebuffer_generation: barrier.framebuffer_generation,
        display_cleanup: barrier.display_cleanup,
        display_cleanup_generation: barrier.display_cleanup_generation,
        active_framebuffer_window_lease_count: barrier.active_framebuffer_window_lease_count,
        active_framebuffer_mapping_count: barrier.active_framebuffer_mapping_count,
        dirty_framebuffer_region_count: barrier.dirty_framebuffer_region_count,
        snapshot_validation_ok: barrier.snapshot_validation_ok,
        generation: barrier.generation,
        state: barrier.state.as_str().to_owned(),
        validated_at_event: barrier.validated_at_event,
        reason: barrier.reason.clone(),
        note: barrier.note.clone(),
    }
}

pub(crate) fn display_panic_last_frame_manifest(
    frame: &semantic_core::DisplayPanicLastFrameRecord,
) -> DisplayPanicLastFrameManifest {
    DisplayPanicLastFrameManifest {
        id: frame.id,
        owner_store: frame.owner_store,
        owner_store_generation: frame.owner_store_generation,
        display: frame.display,
        display_generation: frame.display_generation,
        framebuffer: frame.framebuffer,
        framebuffer_generation: frame.framebuffer_generation,
        display_snapshot_barrier: frame.display_snapshot_barrier,
        display_snapshot_barrier_generation: frame.display_snapshot_barrier_generation,
        display_event_log: frame.display_event_log,
        display_event_log_generation: frame.display_event_log_generation,
        framebuffer_write: frame.framebuffer_write,
        framebuffer_write_generation: frame.framebuffer_write_generation,
        framebuffer_flush_region: frame.framebuffer_flush_region,
        framebuffer_flush_region_generation: frame.framebuffer_flush_region_generation,
        x: frame.x,
        y: frame.y,
        width: frame.width,
        height: frame.height,
        byte_offset: frame.byte_offset,
        byte_len: frame.byte_len,
        pixel_format: frame.pixel_format.clone(),
        payload_digest: frame.payload_digest,
        summary_digest: frame.summary_digest,
        summary_record_bytes: frame.summary_record_bytes,
        panic_epoch: frame.panic_epoch,
        panic_cpu: frame.panic_cpu,
        panic_reason_code: frame.panic_reason_code,
        panic_record_kind: frame.panic_record_kind.clone(),
        raw_framebuffer_bytes_exported: frame.raw_framebuffer_bytes_exported,
        generation: frame.generation,
        state: frame.state.as_str().to_owned(),
        recorded_at_event: frame.recorded_at_event,
        note: frame.note.clone(),
    }
}

pub(crate) fn framebuffer_benchmark_manifest(
    benchmark: &semantic_core::FramebufferBenchmarkRecord,
) -> FramebufferBenchmarkManifest {
    FramebufferBenchmarkManifest {
        id: benchmark.id,
        scenario: benchmark.scenario.clone(),
        owner_store: benchmark.owner_store,
        owner_store_generation: benchmark.owner_store_generation,
        display: benchmark.display,
        display_generation: benchmark.display_generation,
        framebuffer: benchmark.framebuffer,
        framebuffer_generation: benchmark.framebuffer_generation,
        display_capability: benchmark.display_capability,
        display_capability_generation: benchmark.display_capability_generation,
        framebuffer_write: benchmark.framebuffer_write,
        framebuffer_write_generation: benchmark.framebuffer_write_generation,
        framebuffer_flush_region: benchmark.framebuffer_flush_region,
        framebuffer_flush_region_generation: benchmark.framebuffer_flush_region_generation,
        display_event_log: benchmark.display_event_log,
        display_event_log_generation: benchmark.display_event_log_generation,
        display_snapshot_barrier: benchmark.display_snapshot_barrier,
        display_snapshot_barrier_generation: benchmark.display_snapshot_barrier_generation,
        sample_frames: benchmark.sample_frames,
        sample_bytes: benchmark.sample_bytes,
        frame_area_pixels: benchmark.frame_area_pixels,
        write_nanos: benchmark.write_nanos,
        flush_nanos: benchmark.flush_nanos,
        measured_nanos: benchmark.measured_nanos,
        budget_nanos: benchmark.budget_nanos,
        throughput_bytes_per_sec: benchmark.throughput_bytes_per_sec,
        flushes_per_sec_milli: benchmark.flushes_per_sec_milli,
        p50_latency_nanos: benchmark.p50_latency_nanos,
        p99_latency_nanos: benchmark.p99_latency_nanos,
        generation: benchmark.generation,
        state: benchmark.state.as_str().to_owned(),
        recorded_at_event: benchmark.recorded_at_event,
        note: benchmark.note.clone(),
    }
}

pub(crate) fn activation_resume_manifest(
    resume: &semantic_core::ActivationResumeRecord,
) -> ActivationResumeManifest {
    ActivationResumeManifest {
        id: resume.id,
        scheduler_decision: resume.scheduler_decision,
        scheduler_decision_generation: resume.scheduler_decision_generation,
        activation: resume.activation,
        activation_generation_before: resume.activation_generation_before,
        activation_generation_after: resume.activation_generation_after,
        owner_task: u64::from(resume.owner_task),
        owner_task_generation: resume.owner_task_generation,
        queue: resume.queue,
        queue_generation: resume.queue_generation,
        context: resume.context,
        context_generation_before: resume.context_generation_before,
        context_generation_after: resume.context_generation_after,
        saved_context: resume.saved_context,
        saved_context_generation: resume.saved_context_generation,
        saved_vector_state: resume.saved_vector_state.map(contract_object_ref_manifest),
        restored_vector_state: resume.restored_vector_state.map(contract_object_ref_manifest),
        vector_status: resume.vector_status.as_str().to_owned(),
        vector_restored_at_event: resume.vector_restored_at_event,
        generation: resume.generation,
        state: resume.state.as_str().to_owned(),
        resumed_at_event: resume.resumed_at_event,
        note: resume.note.clone(),
    }
}

pub(crate) fn activation_wait_manifest(
    wait: &semantic_core::ActivationWaitRecord,
) -> ActivationWaitManifest {
    ActivationWaitManifest {
        id: wait.id,
        activation: wait.activation,
        activation_generation_before: wait.activation_generation_before,
        activation_generation_after_block: wait.activation_generation_after_block,
        activation_generation_after_cancel: wait.activation_generation_after_cancel,
        wait: wait.wait,
        wait_generation: wait.wait_generation,
        owner_task: u64::from(wait.owner_task),
        owner_task_generation: wait.owner_task_generation,
        queue: wait.queue,
        queue_generation: wait.queue_generation,
        generation: wait.generation,
        state: wait.state.as_str().to_owned(),
        blocked_at_event: wait.blocked_at_event,
        completed_at_event: wait.completed_at_event,
        cancel_reason: wait.cancel_reason.map(|reason| reason.as_str().to_owned()),
        note: wait.note.clone(),
    }
}

pub(crate) fn activation_cleanup_manifest(
    cleanup: &semantic_core::ActivationCleanupRecord,
) -> ActivationCleanupManifest {
    ActivationCleanupManifest {
        id: cleanup.id,
        store: cleanup.store,
        target_store_generation: cleanup.target_store_generation,
        result_store_generation: cleanup.result_store_generation,
        activation: cleanup.activation,
        activation_generation_before: cleanup.activation_generation_before,
        activation_generation_after: cleanup.activation_generation_after,
        wait: cleanup.wait,
        wait_generation: cleanup.wait_generation,
        owner_task: u64::from(cleanup.owner_task),
        owner_task_generation_before: cleanup.owner_task_generation_before,
        owner_task_generation_after: cleanup.owner_task_generation_after,
        generation: cleanup.generation,
        state: cleanup.state.as_str().to_owned(),
        reason: cleanup.reason.clone(),
        started_at_event: cleanup.started_at_event,
        completed_at_event: cleanup.completed_at_event,
        steps: cleanup
            .steps
            .iter()
            .map(|step| ActivationCleanupStepManifest {
                kind: step.kind.as_str().to_owned(),
                target: contract_object_ref_manifest(step.target),
                observed_generation: step.observed_generation,
                status: step.status.as_str().to_owned(),
                event: step.event,
            })
            .collect(),
        note: cleanup.note.clone(),
    }
}

pub(crate) fn preemption_latency_manifest(
    sample: &semantic_core::PreemptionLatencySampleRecord,
) -> PreemptionLatencySampleManifest {
    PreemptionLatencySampleManifest {
        id: sample.id,
        timer_interrupt: sample.timer_interrupt,
        timer_interrupt_generation: sample.timer_interrupt_generation,
        preemption: sample.preemption,
        preemption_generation: sample.preemption_generation,
        scheduler_decision: sample.scheduler_decision,
        scheduler_decision_generation: sample.scheduler_decision_generation,
        activation_resume: sample.activation_resume,
        activation_resume_generation: sample.activation_resume_generation,
        activation: sample.activation,
        activation_generation_before: sample.activation_generation_before,
        activation_generation_after: sample.activation_generation_after,
        queue: sample.queue,
        queue_generation: sample.queue_generation,
        interrupt_recorded_at_event: sample.interrupt_recorded_at_event,
        preempted_at_event: sample.preempted_at_event,
        decided_at_event: sample.decided_at_event,
        resumed_at_event: sample.resumed_at_event,
        interrupt_to_preempt_events: sample.interrupt_to_preempt_events,
        preempt_to_decision_events: sample.preempt_to_decision_events,
        decision_to_resume_events: sample.decision_to_resume_events,
        interrupt_to_resume_events: sample.interrupt_to_resume_events,
        measured_nanos: sample.measured_nanos,
        budget_nanos: sample.budget_nanos,
        generation: sample.generation,
        state: sample.state.as_str().to_owned(),
        recorded_at_event: sample.recorded_at_event,
        note: sample.note.clone(),
    }
}
