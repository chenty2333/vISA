use super::super::super::*;

pub(crate) fn block_driver_cleanup_view_v1(
    cleanup: &BlockDriverCleanupManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-driver-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                cleanup.block_device,
                cleanup.block_device_generation,
            ),
        },
        "references": {
            "io_cleanup": object_ref_json(
                "io-cleanup",
                cleanup.io_cleanup,
                cleanup.io_cleanup_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "device": object_ref_json(
                "device",
                cleanup.device,
                cleanup.device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                cleanup.block_device,
                cleanup.block_device_generation,
            ),
            "backend": object_ref_manifest_json(&cleanup.backend),
            "cancelled_block_waits": cleanup
                .cancelled_block_waits
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "cancelled_wait_tokens": cleanup
                .cancelled_wait_tokens
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "revoked_device_capabilities": cleanup
                .revoked_device_capabilities
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "released_dma_buffers": cleanup
                .released_dma_buffers
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "started_event": {
                "id": cleanup.started_at_event,
            },
            "completed_event": cleanup.completed_at_event.map(|id| serde_json::json!({ "id": id })),
        },
        "cleanup": {
            "reason": cleanup.reason,
            "cancelled_block_wait_count": cleanup.cancelled_block_waits.len(),
            "released_dma_buffer_count": cleanup.released_dma_buffers.len(),
            "revoked_device_capability_count": cleanup.revoked_device_capabilities.len(),
        },
        "note": cleanup.note,
        "last_transition": {
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
            "io_cleanup_generation": cleanup.io_cleanup_generation,
            "driver_store_generation": cleanup.driver_store_generation,
            "block_device_generation": cleanup.block_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_pending_io_policy_view_v1(
    policy: &BlockPendingIoPolicyManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-pending-io-policy",
        "id": policy.id,
        "generation": policy.generation,
        "state": policy.state,
        "owner": {
            "block_wait": object_ref_json(
                "block-wait",
                policy.block_wait,
                policy.block_wait_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                policy.block_request,
                policy.block_request_generation,
            ),
        },
        "references": {
            "block_wait": object_ref_json(
                "block-wait",
                policy.block_wait,
                policy.block_wait_generation,
            ),
            "wait": object_ref_json("wait-token", policy.wait, policy.wait_generation),
            "block_request": object_ref_json(
                "block-request",
                policy.block_request,
                policy.block_request_generation,
            ),
            "retry_request": optional_object_ref_json(
                "block-request",
                policy.retry_request,
                policy.retry_request_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                policy.block_device,
                policy.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                policy.block_range,
                policy.block_range_generation,
            ),
            "event": {
                "id": policy.recorded_at_event,
            },
        },
        "policy": {
            "operation": policy.operation,
            "sequence": policy.sequence,
            "byte_len": policy.byte_len,
            "action": policy.action,
            "errno": policy.errno,
            "retry_attempt": policy.retry_attempt,
            "max_retries": policy.max_retries,
        },
        "note": policy.note,
        "last_transition": {
            "recorded_at_event": policy.recorded_at_event,
            "block_wait_generation": policy.block_wait_generation,
            "block_request_generation": policy.block_request_generation,
            "retry_request_generation": policy.retry_request_generation,
        },
        "last_error": if policy.action == "eio" {
            serde_json::json!({ "errno": policy.errno })
        } else {
            serde_json::Value::Null
        },
    })
}

pub(crate) fn block_request_generation_audit_view_v1(
    audit: &BlockRequestGenerationAuditManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-request-generation-audit",
        "id": audit.id,
        "generation": audit.generation,
        "state": audit.state,
        "owner": {
            "block_request": object_ref_json(
                "block-request",
                audit.block_request,
                audit.block_request_generation,
            ),
            "block_device": object_ref_json(
                "block-device",
                audit.block_device,
                audit.block_device_generation,
            ),
        },
        "references": {
            "block_device": object_ref_json(
                "block-device",
                audit.block_device,
                audit.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                audit.block_range,
                audit.block_range_generation,
            ),
            "block_request": object_ref_json(
                "block-request",
                audit.block_request,
                audit.block_request_generation,
            ),
            "backend": object_ref_manifest_json(&audit.backend),
            "dma_buffer": object_ref_manifest_json(&audit.dma_buffer),
            "event": {
                "id": audit.recorded_at_event,
            },
        },
        "audit": {
            "rejected_completion_generation_probes": audit.rejected_completion_generation_probes,
            "rejected_wait_generation_probes": audit.rejected_wait_generation_probes,
            "rejected_dma_generation_probes": audit.rejected_dma_generation_probes,
            "rejected_queue_generation_probes": audit.rejected_queue_generation_probes,
        },
        "note": audit.note,
        "last_transition": {
            "recorded_at_event": audit.recorded_at_event,
            "block_device_generation": audit.block_device_generation,
            "block_range_generation": audit.block_range_generation,
            "block_request_generation": audit.block_request_generation,
            "backend_generation": audit.backend.generation,
            "dma_buffer_generation": audit.dma_buffer.generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_benchmark_view_v1(benchmark: &BlockBenchmarkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
        },
        "references": {
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range",
                benchmark.block_range,
                benchmark.block_range_generation,
            ),
            "read_path": object_ref_json(
                "block-read-path",
                benchmark.read_path,
                benchmark.read_path_generation,
            ),
            "write_path": object_ref_json(
                "block-write-path",
                benchmark.write_path,
                benchmark.write_path_generation,
            ),
            "request_queue": object_ref_json(
                "block-request-queue",
                benchmark.request_queue,
                benchmark.request_queue_generation,
            ),
            "block_dma_buffer": object_ref_json(
                "block-dma-buffer",
                benchmark.block_dma_buffer,
                benchmark.block_dma_buffer_generation,
            ),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "sample_requests": benchmark.sample_requests,
            "sample_bytes": benchmark.sample_bytes,
            "read_completed_requests": benchmark.read_completed_requests,
            "write_completed_requests": benchmark.write_completed_requests,
            "queue_completed_requests": benchmark.queue_completed_requests,
            "measured_nanos": benchmark.measured_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "iops": benchmark.iops,
            "throughput_bytes_per_sec": benchmark.throughput_bytes_per_sec,
            "p50_latency_nanos": benchmark.p50_latency_nanos,
            "p99_latency_nanos": benchmark.p99_latency_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "backend_generation": benchmark.backend.generation,
            "block_device_generation": benchmark.block_device_generation,
            "block_range_generation": benchmark.block_range_generation,
            "read_path_generation": benchmark.read_path_generation,
            "write_path_generation": benchmark.write_path_generation,
            "request_queue_generation": benchmark.request_queue_generation,
            "block_dma_buffer_generation": benchmark.block_dma_buffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn block_recovery_benchmark_view_v1(
    benchmark: &BlockRecoveryBenchmarkManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "block-recovery-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
        },
        "references": {
            "cleanup": object_ref_json(
                "block-driver-cleanup",
                benchmark.cleanup,
                benchmark.cleanup_generation,
            ),
            "io_cleanup": object_ref_json(
                "io-cleanup",
                benchmark.io_cleanup,
                benchmark.io_cleanup_generation,
            ),
            "backend": object_ref_manifest_json(&benchmark.backend),
            "block_device": object_ref_json(
                "block-device",
                benchmark.block_device,
                benchmark.block_device_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
            "device": object_ref_json("device", benchmark.device, benchmark.device_generation),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                benchmark.driver_binding,
                benchmark.driver_binding_generation,
            ),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "recovery_start_event": benchmark.recovery_start_event,
            "recovery_complete_event": benchmark.recovery_complete_event,
            "cancelled_block_waits": benchmark.cancelled_block_waits,
            "cancelled_wait_tokens": benchmark.cancelled_wait_tokens,
            "released_dma_buffers": benchmark.released_dma_buffers,
            "revoked_device_capabilities": benchmark.revoked_device_capabilities,
            "recovery_nanos": benchmark.recovery_nanos,
            "budget_nanos": benchmark.budget_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "cleanup_generation": benchmark.cleanup_generation,
            "io_cleanup_generation": benchmark.io_cleanup_generation,
            "backend_generation": benchmark.backend.generation,
            "block_device_generation": benchmark.block_device_generation,
            "driver_store_generation": benchmark.driver_store_generation,
            "device_generation": benchmark.device_generation,
            "driver_binding_generation": benchmark.driver_binding_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn target_feature_set_view_v1(feature: &TargetFeatureSetManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "target-feature-set",
        "id": feature.id,
        "generation": feature.generation,
        "state": feature.state,
        "owner": {
            "target_profile": feature.target_profile,
            "target_arch": feature.target_arch,
        },
        "references": {
            "event": {
                "id": feature.recorded_at_event,
            },
        },
        "features": {
            "base_isa": feature.base_isa,
            "simd": {
                "abi": feature.simd_abi,
                "supported": feature.simd_supported,
                "vector_register_count": feature.vector_register_count,
                "vector_register_bits": feature.vector_register_bits,
                "scalar_fallback": feature.scalar_fallback,
                "unsupported_reason": feature.unsupported_reason,
            },
        },
        "discovery": {
            "name": feature.name,
            "source": feature.discovery_source,
        },
        "note": feature.note,
        "last_transition": {
            "recorded_at_event": feature.recorded_at_event,
            "simd_supported": feature.simd_supported,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn vector_state_view_v1(vector_state: &VectorStateManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "vector-state",
        "id": vector_state.id,
        "generation": vector_state.generation,
        "state": vector_state.state,
        "owner": {
            "activation": object_ref_manifest_json(&vector_state.owner_activation),
            "store": object_ref_manifest_json(&vector_state.owner_store),
        },
        "references": {
            "code_object": object_ref_manifest_json(&vector_state.code_object),
            "target_feature_set": object_ref_manifest_json(&vector_state.target_feature_set),
            "event": {
                "id": vector_state.recorded_at_event,
            },
        },
        "simd": {
            "abi": vector_state.simd_abi,
            "vector_register_count": vector_state.vector_register_count,
            "vector_register_bits": vector_state.vector_register_bits,
            "register_bytes": vector_state.register_bytes,
        },
        "note": vector_state.note,
        "last_transition": {
            "recorded_at_event": vector_state.recorded_at_event,
            "state": vector_state.state,
        },
        "last_error": if vector_state.state == "unavailable" {
            serde_json::json!("simd-unavailable")
        } else {
            serde_json::Value::Null
        },
    })
}

pub(crate) fn simd_fault_injection_view_v1(
    injection: &SimdFaultInjectionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "simd-fault-injection",
        "id": injection.id,
        "generation": injection.generation,
        "state": injection.state,
        "owner": {
            "activation": object_ref_manifest_json(&injection.activation),
        },
        "references": {
            "activation": object_ref_manifest_json(&injection.activation),
            "code_object": object_ref_manifest_json(&injection.code_object),
            "trap": object_ref_manifest_json(&injection.trap),
            "target_feature_set": object_ref_manifest_json(&injection.target_feature_set),
            "vector_state": injection.vector_state.as_ref().map(object_ref_manifest_json),
            "event": {
                "id": injection.recorded_at_event,
            },
        },
        "fault": {
            "kind": injection.kind,
            "effect": injection.effect,
            "required_abi": injection.required_abi,
            "vector_register_count": injection.vector_register_count,
            "vector_register_bits": injection.vector_register_bits,
            "injected_faults": injection.injected_faults,
        },
        "note": injection.note,
        "last_transition": {
            "recorded_at_event": injection.recorded_at_event,
            "effect": injection.effect,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn simd_benchmark_view_v1(benchmark: &SimdBenchmarkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "simd-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
        },
        "references": {
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
            "scalar_code_object": object_ref_manifest_json(&benchmark.scalar_code_object),
            "vector_code_object": object_ref_manifest_json(&benchmark.vector_code_object),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "simd": {
            "abi": benchmark.simd_abi,
            "vector_register_count": benchmark.vector_register_count,
            "vector_register_bits": benchmark.vector_register_bits,
        },
        "metrics": {
            "workload_units": benchmark.workload_units,
            "scalar_nanos": benchmark.scalar_nanos,
            "vector_nanos": benchmark.vector_nanos,
            "speedup_milli": benchmark.speedup_milli,
            "context_overhead_nanos": benchmark.context_overhead_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "state": benchmark.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn simd_context_switch_benchmark_view_v1(
    benchmark: &SimdContextSwitchBenchmarkManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "simd-context-switch-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
            "activation_resume": object_ref_manifest_json(&benchmark.activation_resume),
        },
        "references": {
            "preemption": object_ref_manifest_json(&benchmark.preemption),
            "activation_resume": object_ref_manifest_json(&benchmark.activation_resume),
            "saved_vector_state": object_ref_manifest_json(&benchmark.saved_vector_state),
            "restored_vector_state": object_ref_manifest_json(&benchmark.restored_vector_state),
            "target_feature_set": object_ref_manifest_json(&benchmark.target_feature_set),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "simd": {
            "abi": benchmark.simd_abi,
            "vector_register_count": benchmark.vector_register_count,
            "vector_register_bits": benchmark.vector_register_bits,
        },
        "metrics": {
            "sample_count": benchmark.sample_count,
            "scalar_context_switch_nanos": benchmark.scalar_context_switch_nanos,
            "vector_context_switch_nanos": benchmark.vector_context_switch_nanos,
            "overhead_nanos": benchmark.overhead_nanos,
            "budget_nanos": benchmark.budget_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "state": benchmark.state,
        },
        "last_error": serde_json::Value::Null,
    })
}
