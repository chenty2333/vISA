use super::super::super::*;

pub(crate) fn network_backpressure_view_v1(
    backpressure: &NetworkBackpressureManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-backpressure",
        "id": backpressure.id,
        "generation": backpressure.generation,
        "state": backpressure.state,
        "owner": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                backpressure.adapter,
                backpressure.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                backpressure.packet_device,
                backpressure.packet_device_generation,
            ),
            "packet_queue": object_ref_json(
                "packet-queue",
                backpressure.packet_queue,
                backpressure.packet_queue_generation,
            ),
            "endpoint": optional_object_ref_json(
                "endpoint-object",
                backpressure.endpoint,
                backpressure.endpoint_generation,
            ),
            "socket": optional_object_ref_json(
                "socket-object",
                backpressure.socket,
                backpressure.socket_generation,
            ),
            "store": optional_object_ref_json(
                "store",
                backpressure.owner_store,
                backpressure.owner_store_generation,
            ),
        },
        "references": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                backpressure.adapter,
                backpressure.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                backpressure.packet_device,
                backpressure.packet_device_generation,
            ),
            "packet_queue": object_ref_json(
                "packet-queue",
                backpressure.packet_queue,
                backpressure.packet_queue_generation,
            ),
            "endpoint": optional_object_ref_json(
                "endpoint-object",
                backpressure.endpoint,
                backpressure.endpoint_generation,
            ),
            "socket": optional_object_ref_json(
                "socket-object",
                backpressure.socket,
                backpressure.socket_generation,
            ),
            "owner_store": optional_object_ref_json(
                "store",
                backpressure.owner_store,
                backpressure.owner_store_generation,
            ),
            "event": {
                "id": backpressure.recorded_at_event,
            },
        },
        "policy": {
            "direction": backpressure.direction,
            "reason": backpressure.reason,
            "action": backpressure.action,
            "queue_depth": backpressure.queue_depth,
            "queue_limit": backpressure.queue_limit,
            "dropped_packets": backpressure.dropped_packets,
            "dropped_bytes": backpressure.dropped_bytes,
            "sequence": backpressure.sequence,
        },
        "note": backpressure.note,
        "last_transition": {
            "recorded_at_event": backpressure.recorded_at_event,
            "adapter_generation": backpressure.adapter_generation,
            "packet_device_generation": backpressure.packet_device_generation,
            "packet_queue_generation": backpressure.packet_queue_generation,
            "endpoint_generation": backpressure.endpoint_generation,
            "socket_generation": backpressure.socket_generation,
            "owner_store_generation": backpressure.owner_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn network_driver_cleanup_view_v1(
    cleanup: &NetworkDriverCleanupManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-driver-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                cleanup.driver_store,
                cleanup.driver_store_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                cleanup.packet_device,
                cleanup.packet_device_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                cleanup.adapter,
                cleanup.adapter_generation,
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
            "packet_device": object_ref_json(
                "packet-device",
                cleanup.packet_device,
                cleanup.packet_device_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                cleanup.adapter,
                cleanup.adapter_generation,
            ),
            "backend": object_ref_manifest_json(&cleanup.backend),
            "cancelled_socket_waits": cleanup
                .cancelled_socket_waits
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "cancelled_wait_tokens": cleanup
                .cancelled_wait_tokens
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
            "revoked_packet_capabilities": cleanup
                .revoked_packet_capabilities
                .iter()
                .map(object_ref_manifest_json)
                .collect::<Vec<_>>(),
        },
        "cleanup": {
            "reason": cleanup.reason,
            "cancelled_socket_wait_count": cleanup.cancelled_socket_waits.len(),
            "revoked_packet_capability_count": cleanup.revoked_packet_capabilities.len(),
        },
        "note": cleanup.note,
        "last_transition": {
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
            "io_cleanup_generation": cleanup.io_cleanup_generation,
            "driver_store_generation": cleanup.driver_store_generation,
            "device_generation": cleanup.device_generation,
            "driver_binding_generation": cleanup.driver_binding_generation,
            "packet_device_generation": cleanup.packet_device_generation,
            "adapter_generation": cleanup.adapter_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn network_generation_audit_view_v1(
    audit: &NetworkGenerationAuditManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-generation-audit",
        "id": audit.id,
        "generation": audit.generation,
        "state": audit.state,
        "owner": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                audit.adapter,
                audit.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                audit.packet_device,
                audit.packet_device_generation,
            ),
        },
        "references": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                audit.adapter,
                audit.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                audit.packet_device,
                audit.packet_device_generation,
            ),
            "packet_queue": object_ref_json(
                "packet-queue",
                audit.packet_queue,
                audit.packet_queue_generation,
            ),
            "packet_descriptor": object_ref_json(
                "packet-descriptor",
                audit.packet_descriptor,
                audit.packet_descriptor_generation,
            ),
            "packet_buffer": object_ref_json(
                "packet-buffer",
                audit.packet_buffer,
                audit.packet_buffer_generation,
            ),
            "dma_buffer": object_ref_manifest_json(&audit.dma_buffer),
            "device_capability": object_ref_manifest_json(&audit.device_capability),
            "event": {
                "id": audit.recorded_at_event,
            },
        },
        "audit": {
            "rejected_packet_generation_probes": audit.rejected_packet_generation_probes,
            "rejected_dma_generation_probes": audit.rejected_dma_generation_probes,
        },
        "note": audit.note,
        "last_transition": {
            "recorded_at_event": audit.recorded_at_event,
            "adapter_generation": audit.adapter_generation,
            "packet_device_generation": audit.packet_device_generation,
            "packet_queue_generation": audit.packet_queue_generation,
            "packet_descriptor_generation": audit.packet_descriptor_generation,
            "packet_buffer_generation": audit.packet_buffer_generation,
            "dma_buffer_generation": audit.dma_buffer.generation,
            "device_capability_generation": audit.device_capability.generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn network_fault_injection_view_v1(
    injection: &NetworkFaultInjectionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-fault-injection",
        "id": injection.id,
        "generation": injection.generation,
        "state": injection.state,
        "owner": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                injection.adapter,
                injection.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                injection.packet_device,
                injection.packet_device_generation,
            ),
            "packet_queue": object_ref_json(
                "packet-queue",
                injection.packet_queue,
                injection.packet_queue_generation,
            ),
            "endpoint": optional_object_ref_json(
                "endpoint-object",
                injection.endpoint,
                injection.endpoint_generation,
            ),
            "socket": optional_object_ref_json(
                "socket-object",
                injection.socket,
                injection.socket_generation,
            ),
            "store": optional_object_ref_json(
                "store",
                injection.owner_store,
                injection.owner_store_generation,
            ),
        },
        "references": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                injection.adapter,
                injection.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                injection.packet_device,
                injection.packet_device_generation,
            ),
            "packet_queue": object_ref_json(
                "packet-queue",
                injection.packet_queue,
                injection.packet_queue_generation,
            ),
            "packet_descriptor": optional_object_ref_json(
                "packet-descriptor",
                injection.packet_descriptor,
                injection.packet_descriptor_generation,
            ),
            "packet_buffer": optional_object_ref_json(
                "packet-buffer",
                injection.packet_buffer,
                injection.packet_buffer_generation,
            ),
            "endpoint": optional_object_ref_json(
                "endpoint-object",
                injection.endpoint,
                injection.endpoint_generation,
            ),
            "socket": optional_object_ref_json(
                "socket-object",
                injection.socket,
                injection.socket_generation,
            ),
            "owner_store": optional_object_ref_json(
                "store",
                injection.owner_store,
                injection.owner_store_generation,
            ),
            "event": {
                "id": injection.recorded_at_event,
            },
        },
        "injection": {
            "direction": injection.direction,
            "kind": injection.kind,
            "effect": injection.effect,
            "injected_packets": injection.injected_packets,
            "dropped_packets": injection.dropped_packets,
            "error_packets": injection.error_packets,
            "error_code": injection.error_code,
            "sequence": injection.sequence,
        },
        "note": injection.note,
        "last_transition": {
            "recorded_at_event": injection.recorded_at_event,
            "adapter_generation": injection.adapter_generation,
            "packet_device_generation": injection.packet_device_generation,
            "packet_queue_generation": injection.packet_queue_generation,
            "packet_descriptor_generation": injection.packet_descriptor_generation,
            "packet_buffer_generation": injection.packet_buffer_generation,
            "endpoint_generation": injection.endpoint_generation,
            "socket_generation": injection.socket_generation,
            "owner_store_generation": injection.owner_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn network_benchmark_view_v1(benchmark: &NetworkBenchmarkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                benchmark.adapter,
                benchmark.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                benchmark.packet_device,
                benchmark.packet_device_generation,
            ),
            "store": object_ref_json(
                "store",
                benchmark.owner_store,
                benchmark.owner_store_generation,
            ),
        },
        "references": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                benchmark.adapter,
                benchmark.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                benchmark.packet_device,
                benchmark.packet_device_generation,
            ),
            "tx_queue": object_ref_json(
                "packet-queue",
                benchmark.tx_queue,
                benchmark.tx_queue_generation,
            ),
            "rx_queue": object_ref_json(
                "packet-queue",
                benchmark.rx_queue,
                benchmark.rx_queue_generation,
            ),
            "tx_completion": object_ref_json(
                "network-tx-completion",
                benchmark.tx_completion,
                benchmark.tx_completion_generation,
            ),
            "rx_wait_resolution": object_ref_json(
                "network-rx-wait-resolution",
                benchmark.rx_wait_resolution,
                benchmark.rx_wait_resolution_generation,
            ),
            "endpoint": object_ref_json(
                "endpoint-object",
                benchmark.endpoint,
                benchmark.endpoint_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                benchmark.socket,
                benchmark.socket_generation,
            ),
            "owner_store": object_ref_json(
                "store",
                benchmark.owner_store,
                benchmark.owner_store_generation,
            ),
            "backpressure": optional_object_ref_json(
                "network-backpressure",
                benchmark.backpressure,
                benchmark.backpressure_generation,
            ),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "sample_packets": benchmark.sample_packets,
            "sample_bytes": benchmark.sample_bytes,
            "tx_completed_packets": benchmark.tx_completed_packets,
            "rx_resolved_packets": benchmark.rx_resolved_packets,
            "dropped_packets": benchmark.dropped_packets,
            "measured_nanos": benchmark.measured_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "throughput_bytes_per_sec": benchmark.throughput_bytes_per_sec,
            "p50_latency_nanos": benchmark.p50_latency_nanos,
            "p99_latency_nanos": benchmark.p99_latency_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "adapter_generation": benchmark.adapter_generation,
            "packet_device_generation": benchmark.packet_device_generation,
            "tx_queue_generation": benchmark.tx_queue_generation,
            "rx_queue_generation": benchmark.rx_queue_generation,
            "tx_completion_generation": benchmark.tx_completion_generation,
            "rx_wait_resolution_generation": benchmark.rx_wait_resolution_generation,
            "endpoint_generation": benchmark.endpoint_generation,
            "socket_generation": benchmark.socket_generation,
            "owner_store_generation": benchmark.owner_store_generation,
            "backpressure_generation": benchmark.backpressure_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn network_recovery_benchmark_view_v1(
    benchmark: &NetworkRecoveryBenchmarkManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-recovery-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                benchmark.adapter,
                benchmark.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                benchmark.packet_device,
                benchmark.packet_device_generation,
            ),
            "driver_store": object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
        },
        "references": {
            "cleanup": object_ref_json(
                "network-driver-cleanup",
                benchmark.cleanup,
                benchmark.cleanup_generation,
            ),
            "io_cleanup": object_ref_json(
                "io-cleanup",
                benchmark.io_cleanup,
                benchmark.io_cleanup_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                benchmark.adapter,
                benchmark.adapter_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                benchmark.packet_device,
                benchmark.packet_device_generation,
            ),
            "backend": object_ref_manifest_json(&benchmark.backend),
            "driver_store": object_ref_json(
                "store",
                benchmark.driver_store,
                benchmark.driver_store_generation,
            ),
            "fault_injection": optional_object_ref_json(
                "network-fault-injection",
                benchmark.fault_injection,
                benchmark.fault_injection_generation,
            ),
            "events": {
                "recovery_start_event": benchmark.recovery_start_event,
                "recovery_complete_event": benchmark.recovery_complete_event,
                "recorded_at_event": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "cancelled_socket_waits": benchmark.cancelled_socket_waits,
            "revoked_packet_capabilities": benchmark.revoked_packet_capabilities,
            "recovery_nanos": benchmark.recovery_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "within_budget": benchmark.recovery_nanos <= benchmark.budget_nanos,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "cleanup_generation": benchmark.cleanup_generation,
            "io_cleanup_generation": benchmark.io_cleanup_generation,
            "adapter_generation": benchmark.adapter_generation,
            "packet_device_generation": benchmark.packet_device_generation,
            "driver_store_generation": benchmark.driver_store_generation,
            "fault_injection_generation": benchmark.fault_injection_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}
