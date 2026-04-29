use super::super::*;
pub(crate) fn packet_buffer_object_view_v1(
    packet_buffer: &PacketBufferObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "packet-buffer",
        "id": packet_buffer.id,
        "generation": packet_buffer.generation,
        "state": packet_buffer.state,
        "owner": {
            "packet_device": object_ref_json(
                "packet-device",
                packet_buffer.packet_device,
                packet_buffer.packet_device_generation
            ),
        },
        "references": {
            "packet_device": object_ref_json(
                "packet-device",
                packet_buffer.packet_device,
                packet_buffer.packet_device_generation
            ),
            "event": {
                "id": packet_buffer.recorded_at_event,
            },
        },
        "contract": {
            "direction": packet_buffer.direction,
            "frame_format_version": packet_buffer.frame_format_version,
            "capacity": packet_buffer.capacity,
            "payload_len": packet_buffer.payload_len,
            "sequence": packet_buffer.sequence,
        },
        "note": packet_buffer.note,
        "last_transition": {
            "recorded_at_event": packet_buffer.recorded_at_event,
            "packet_device_generation": packet_buffer.packet_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn packet_queue_object_view_v1(
    packet_queue: &PacketQueueObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "packet-queue",
        "id": packet_queue.id,
        "generation": packet_queue.generation,
        "state": packet_queue.state,
        "owner": {
            "packet_device": object_ref_json(
                "packet-device",
                packet_queue.packet_device,
                packet_queue.packet_device_generation
            ),
        },
        "references": {
            "packet_device": object_ref_json(
                "packet-device",
                packet_queue.packet_device,
                packet_queue.packet_device_generation
            ),
            "event": {
                "id": packet_queue.recorded_at_event,
            },
        },
        "identity": {
            "name": packet_queue.name,
            "role": packet_queue.role,
            "queue_index": packet_queue.queue_index,
        },
        "contract": {
            "depth": packet_queue.depth,
        },
        "note": packet_queue.note,
        "last_transition": {
            "recorded_at_event": packet_queue.recorded_at_event,
            "packet_device_generation": packet_queue.packet_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn packet_descriptor_object_view_v1(
    packet_descriptor: &PacketDescriptorObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "packet-descriptor",
        "id": packet_descriptor.id,
        "generation": packet_descriptor.generation,
        "state": packet_descriptor.state,
        "owner": {
            "packet_queue": object_ref_json(
                "packet-queue",
                packet_descriptor.packet_queue,
                packet_descriptor.packet_queue_generation
            ),
            "packet_buffer": object_ref_json(
                "packet-buffer",
                packet_descriptor.packet_buffer,
                packet_descriptor.packet_buffer_generation
            ),
        },
        "references": {
            "packet_queue": object_ref_json(
                "packet-queue",
                packet_descriptor.packet_queue,
                packet_descriptor.packet_queue_generation
            ),
            "packet_buffer": object_ref_json(
                "packet-buffer",
                packet_descriptor.packet_buffer,
                packet_descriptor.packet_buffer_generation
            ),
            "event": {
                "id": packet_descriptor.recorded_at_event,
            },
        },
        "identity": {
            "slot": packet_descriptor.slot,
        },
        "contract": {
            "length": packet_descriptor.length,
        },
        "note": packet_descriptor.note,
        "last_transition": {
            "recorded_at_event": packet_descriptor.recorded_at_event,
            "packet_queue_generation": packet_descriptor.packet_queue_generation,
            "packet_buffer_generation": packet_descriptor.packet_buffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn fake_net_backend_object_view_v1(
    backend: &FakeNetBackendObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "fake-net-backend",
        "id": backend.id,
        "generation": backend.generation,
        "state": backend.state,
        "owner": {
            "packet_device": object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation
            ),
        },
        "references": {
            "packet_device": object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation
            ),
            "event": {
                "id": backend.recorded_at_event,
            },
        },
        "identity": {
            "name": backend.name,
            "provider": backend.provider,
            "profile": backend.profile,
            "deterministic_seed": backend.deterministic_seed,
        },
        "contract": {
            "mtu": backend.mtu,
            "rx_queue_depth": backend.rx_queue_depth,
            "tx_queue_depth": backend.tx_queue_depth,
            "mac": backend.mac,
            "frame_format_version": backend.frame_format_version,
            "max_payload_len": backend.max_payload_len,
        },
        "note": backend.note,
        "last_transition": {
            "recorded_at_event": backend.recorded_at_event,
            "packet_device_generation": backend.packet_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn virtio_net_backend_object_view_v1(
    backend: &VirtioNetBackendObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "virtio-net-backend",
        "id": backend.id,
        "generation": backend.generation,
        "state": backend.state,
        "owner": {
            "packet_device": object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
        },
        "references": {
            "packet_device": object_ref_json(
                "packet-device",
                backend.packet_device,
                backend.packet_device_generation,
            ),
            "driver_binding": object_ref_json(
                "driver-store-binding",
                backend.driver_binding,
                backend.driver_binding_generation,
            ),
            "device": object_ref_json("device", backend.device, backend.device_generation),
            "event": {
                "id": backend.recorded_at_event,
            },
        },
        "identity": {
            "name": backend.name,
            "provider": backend.provider,
            "profile": backend.profile,
            "model": backend.model,
        },
        "contract": {
            "mtu": backend.mtu,
            "rx_queue_depth": backend.rx_queue_depth,
            "tx_queue_depth": backend.tx_queue_depth,
            "mac": backend.mac,
            "frame_format_version": backend.frame_format_version,
            "max_payload_len": backend.max_payload_len,
            "device_features": backend.device_features,
            "driver_features": backend.driver_features,
            "negotiated_features": backend.negotiated_features,
            "rx_queue_index": backend.rx_queue_index,
            "tx_queue_index": backend.tx_queue_index,
            "queue_size": backend.queue_size,
            "irq_vector": backend.irq_vector,
        },
        "note": backend.note,
        "last_transition": {
            "recorded_at_event": backend.recorded_at_event,
            "packet_device_generation": backend.packet_device_generation,
            "driver_binding_generation": backend.driver_binding_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn network_rx_interrupt_view_v1(rx: &NetworkRxInterruptManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-rx-interrupt",
        "id": rx.id,
        "generation": rx.generation,
        "state": rx.state,
        "owner": {
            "virtio_net_backend": object_ref_json(
                "virtio-net-backend",
                rx.virtio_net_backend,
                rx.virtio_net_backend_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                rx.packet_device,
                rx.packet_device_generation,
            ),
        },
        "references": {
            "virtio_net_backend": object_ref_json(
                "virtio-net-backend",
                rx.virtio_net_backend,
                rx.virtio_net_backend_generation,
            ),
            "irq_event": object_ref_json(
                "irq-event",
                rx.irq_event,
                rx.irq_event_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                rx.packet_device,
                rx.packet_device_generation,
            ),
            "rx_queue": object_ref_json(
                "packet-queue",
                rx.rx_queue,
                rx.rx_queue_generation,
            ),
            "event": {
                "id": rx.recorded_at_event,
            },
        },
        "readiness": {
            "ready_descriptors": rx.ready_descriptors,
            "sequence": rx.sequence,
        },
        "note": rx.note,
        "last_transition": {
            "recorded_at_event": rx.recorded_at_event,
            "irq_event_generation": rx.irq_event_generation,
            "rx_queue_generation": rx.rx_queue_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn network_rx_wait_resolution_view_v1(
    resolution: &NetworkRxWaitResolutionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-rx-wait-resolution",
        "id": resolution.id,
        "generation": resolution.generation,
        "state": resolution.state,
        "owner": {
            "io_wait": object_ref_json(
                "io-wait",
                resolution.io_wait,
                resolution.io_wait_generation,
            ),
            "wait": object_ref_json(
                "wait-token",
                resolution.wait,
                resolution.wait_generation,
            ),
        },
        "references": {
            "io_wait": object_ref_json(
                "io-wait",
                resolution.io_wait,
                resolution.io_wait_generation,
            ),
            "wait": object_ref_json(
                "wait-token",
                resolution.wait,
                resolution.wait_generation,
            ),
            "rx_interrupt": object_ref_json(
                "network-rx-interrupt",
                resolution.rx_interrupt,
                resolution.rx_interrupt_generation,
            ),
            "irq_event": object_ref_json(
                "irq-event",
                resolution.irq_event,
                resolution.irq_event_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                resolution.packet_device,
                resolution.packet_device_generation,
            ),
            "rx_queue": object_ref_json(
                "packet-queue",
                resolution.rx_queue,
                resolution.rx_queue_generation,
            ),
            "event": {
                "id": resolution.resolved_at_event,
            },
        },
        "readiness": {
            "ready_descriptors": resolution.ready_descriptors,
            "sequence": resolution.sequence,
        },
        "note": resolution.note,
        "last_transition": {
            "resolved_at_event": resolution.resolved_at_event,
            "io_wait_generation": resolution.io_wait_generation,
            "rx_interrupt_generation": resolution.rx_interrupt_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn network_tx_capability_gate_view_v1(
    gate: &NetworkTxCapabilityGateManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-tx-capability-gate",
        "id": gate.id,
        "generation": gate.generation,
        "state": gate.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                gate.driver_store,
                gate.driver_store_generation,
            ),
        },
        "references": {
            "packet_device": object_ref_json(
                "packet-device",
                gate.packet_device,
                gate.packet_device_generation,
            ),
            "tx_queue": object_ref_json(
                "packet-queue",
                gate.tx_queue,
                gate.tx_queue_generation,
            ),
            "packet_descriptor": object_ref_json(
                "packet-descriptor",
                gate.packet_descriptor,
                gate.packet_descriptor_generation,
            ),
            "packet_buffer": object_ref_json(
                "packet-buffer",
                gate.packet_buffer,
                gate.packet_buffer_generation,
            ),
            "device_capability": object_ref_json(
                "device-capability",
                gate.device_capability,
                gate.device_capability_generation,
            ),
            "capability": object_ref_json(
                "capability",
                gate.capability,
                gate.capability_generation,
            ),
            "event": {
                "id": gate.recorded_at_event,
            },
        },
        "authority": {
            "class": "packet-device",
            "operation": gate.operation,
            "handle_slot": gate.handle_slot,
            "handle_generation": gate.handle_generation,
            "handle_tag": gate.handle_tag,
        },
        "tx": {
            "byte_len": gate.byte_len,
            "sequence": gate.sequence,
        },
        "note": gate.note,
        "last_transition": {
            "recorded_at_event": gate.recorded_at_event,
            "packet_descriptor_generation": gate.packet_descriptor_generation,
            "capability_generation": gate.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn network_tx_completion_view_v1(
    completion: &NetworkTxCompletionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-tx-completion",
        "id": completion.id,
        "generation": completion.generation,
        "state": completion.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                completion.driver_store,
                completion.driver_store_generation,
            ),
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&completion.backend_kind),
                completion.backend,
                completion.backend_generation,
            ),
        },
        "references": {
            "tx_gate": object_ref_json(
                "network-tx-capability-gate",
                completion.tx_gate,
                completion.tx_gate_generation,
            ),
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&completion.backend_kind),
                completion.backend,
                completion.backend_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                completion.packet_device,
                completion.packet_device_generation,
            ),
            "tx_queue": object_ref_json(
                "packet-queue",
                completion.tx_queue,
                completion.tx_queue_generation,
            ),
            "packet_descriptor": object_ref_json(
                "packet-descriptor",
                completion.packet_descriptor,
                completion.packet_descriptor_generation,
            ),
            "packet_buffer": object_ref_json(
                "packet-buffer",
                completion.packet_buffer,
                completion.packet_buffer_generation,
            ),
            "event": {
                "id": completion.completed_at_event,
            },
        },
        "tx": {
            "byte_len": completion.byte_len,
            "sequence": completion.sequence,
            "completion_sequence": completion.completion_sequence,
        },
        "note": completion.note,
        "last_transition": {
            "completed_at_event": completion.completed_at_event,
            "tx_gate_generation": completion.tx_gate_generation,
            "backend_generation": completion.backend_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn network_stack_adapter_view_v1(
    adapter: &NetworkStackAdapterManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "network-stack-adapter",
        "id": adapter.id,
        "generation": adapter.generation,
        "state": adapter.state,
        "owner": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&adapter.backend_kind),
                adapter.backend,
                adapter.backend_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                adapter.packet_device,
                adapter.packet_device_generation,
            ),
        },
        "references": {
            "backend": object_ref_json(
                osctl_kind_from_contract_kind(&adapter.backend_kind),
                adapter.backend,
                adapter.backend_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device",
                adapter.packet_device,
                adapter.packet_device_generation,
            ),
            "rx_queue": object_ref_json(
                "packet-queue",
                adapter.rx_queue,
                adapter.rx_queue_generation,
            ),
            "tx_queue": object_ref_json(
                "packet-queue",
                adapter.tx_queue,
                adapter.tx_queue_generation,
            ),
            "event": {
                "id": adapter.recorded_at_event,
            },
        },
        "adapter": {
            "implementation": adapter.implementation,
            "implementation_version": adapter.implementation_version,
            "profile": adapter.profile,
            "medium": adapter.medium,
            "socket_capacity": adapter.socket_capacity,
        },
        "network": {
            "mac": adapter.mac,
            "ipv4_addr": adapter.ipv4_addr,
            "ipv4_prefix_len": adapter.ipv4_prefix_len,
            "mtu": adapter.mtu,
            "rx_queue_depth": adapter.rx_queue_depth,
            "tx_queue_depth": adapter.tx_queue_depth,
            "max_payload_len": adapter.max_payload_len,
        },
        "note": adapter.note,
        "last_transition": {
            "recorded_at_event": adapter.recorded_at_event,
            "backend_generation": adapter.backend_generation,
            "packet_device_generation": adapter.packet_device_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn socket_object_view_v1(socket: &SocketObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "socket-object",
        "id": socket.id,
        "generation": socket.generation,
        "state": socket.state,
        "owner": {
            "store": object_ref_json("store", socket.owner_store, socket.owner_store_generation),
        },
        "references": {
            "adapter": object_ref_json(
                "network-stack-adapter",
                socket.adapter,
                socket.adapter_generation,
            ),
            "owner_store": object_ref_json("store", socket.owner_store, socket.owner_store_generation),
            "event": {
                "id": socket.created_at_event,
            },
        },
        "socket": {
            "domain": socket.domain,
            "type": socket.socket_type,
            "protocol": socket.protocol,
            "canonical_protocol": socket.canonical_protocol,
            "family": socket.family,
            "transport": socket.transport,
        },
        "note": socket.note,
        "last_transition": {
            "created_at_event": socket.created_at_event,
            "adapter_generation": socket.adapter_generation,
            "owner_store_generation": socket.owner_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn endpoint_object_view_v1(endpoint: &EndpointObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "endpoint-object",
        "id": endpoint.id,
        "generation": endpoint.generation,
        "state": endpoint.state,
        "owner": {
            "store": object_ref_json(
                "store",
                endpoint.owner_store,
                endpoint.owner_store_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                endpoint.socket,
                endpoint.socket_generation,
            ),
        },
        "references": {
            "socket": object_ref_json(
                "socket-object",
                endpoint.socket,
                endpoint.socket_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                endpoint.adapter,
                endpoint.adapter_generation,
            ),
            "owner_store": object_ref_json(
                "store",
                endpoint.owner_store,
                endpoint.owner_store_generation,
            ),
            "event": {
                "id": endpoint.created_at_event,
            },
        },
        "endpoint": {
            "family": endpoint.family,
            "transport": endpoint.transport,
            "local_addr": endpoint.local_addr,
            "local_port": endpoint.local_port,
            "remote_addr": endpoint.remote_addr,
            "remote_port": endpoint.remote_port,
        },
        "note": endpoint.note,
        "last_transition": {
            "created_at_event": endpoint.created_at_event,
            "socket_generation": endpoint.socket_generation,
            "adapter_generation": endpoint.adapter_generation,
            "owner_store_generation": endpoint.owner_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn socket_operation_view_v1(operation: &SocketOperationManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "socket-operation",
        "id": operation.id,
        "generation": operation.generation,
        "state": operation.state,
        "owner": {
            "store": object_ref_json(
                "store",
                operation.owner_store,
                operation.owner_store_generation,
            ),
            "endpoint": object_ref_json(
                "endpoint-object",
                operation.endpoint,
                operation.endpoint_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                operation.socket,
                operation.socket_generation,
            ),
        },
        "references": {
            "endpoint": object_ref_json(
                "endpoint-object",
                operation.endpoint,
                operation.endpoint_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                operation.socket,
                operation.socket_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                operation.adapter,
                operation.adapter_generation,
            ),
            "owner_store": object_ref_json(
                "store",
                operation.owner_store,
                operation.owner_store_generation,
            ),
            "event": {
                "id": operation.recorded_at_event,
            },
        },
        "operation": {
            "name": operation.operation,
            "sequence": operation.sequence,
            "local_addr": operation.local_addr,
            "local_port": operation.local_port,
            "remote_addr": operation.remote_addr,
            "remote_port": operation.remote_port,
            "backlog": operation.backlog,
            "byte_len": operation.byte_len,
        },
        "note": operation.note,
        "last_transition": {
            "recorded_at_event": operation.recorded_at_event,
            "endpoint_generation": operation.endpoint_generation,
            "socket_generation": operation.socket_generation,
            "adapter_generation": operation.adapter_generation,
            "owner_store_generation": operation.owner_store_generation,
            "sequence": operation.sequence,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn socket_wait_view_v1(wait: &SocketWaitManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "socket-wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "store": object_ref_json(
                "store",
                wait.owner_store,
                wait.owner_store_generation,
            ),
            "endpoint": object_ref_json(
                "endpoint-object",
                wait.endpoint,
                wait.endpoint_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                wait.socket,
                wait.socket_generation,
            ),
            "wait": object_ref_json(
                "wait-token",
                wait.wait,
                wait.wait_generation,
            ),
        },
        "references": {
            "wait": object_ref_json(
                "wait-token",
                wait.wait,
                wait.wait_generation,
            ),
            "endpoint": object_ref_json(
                "endpoint-object",
                wait.endpoint,
                wait.endpoint_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                wait.socket,
                wait.socket_generation,
            ),
            "adapter": object_ref_json(
                "network-stack-adapter",
                wait.adapter,
                wait.adapter_generation,
            ),
            "owner_store": object_ref_json(
                "store",
                wait.owner_store,
                wait.owner_store_generation,
            ),
            "blocker": object_ref_manifest_json(&wait.blocker),
            "event": {
                "id": wait.created_at_event,
            },
            "completed_event": wait.completed_at_event.map(|id| serde_json::json!({ "id": id })),
        },
        "wait": {
            "kind": wait.wait_kind,
            "ready_sequence": wait.ready_sequence,
            "byte_len": wait.byte_len,
            "cancel_reason": wait.cancel_reason,
        },
        "note": wait.note,
        "last_transition": {
            "created_at_event": wait.created_at_event,
            "completed_at_event": wait.completed_at_event,
            "wait_generation": wait.wait_generation,
            "endpoint_generation": wait.endpoint_generation,
            "socket_generation": wait.socket_generation,
            "adapter_generation": wait.adapter_generation,
            "owner_store_generation": wait.owner_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

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

pub(crate) fn framebuffer_object_view_v1(
    framebuffer: &FramebufferObjectManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-object",
        "id": framebuffer.id,
        "generation": framebuffer.generation,
        "state": framebuffer.state,
        "owner": {
            "resource": object_ref_json("resource", framebuffer.resource, framebuffer.resource_generation),
        },
        "references": {
            "resource": object_ref_json("resource", framebuffer.resource, framebuffer.resource_generation),
            "event": {
                "id": framebuffer.recorded_at_event,
            },
        },
        "identity": {
            "name": framebuffer.name,
        },
        "geometry": {
            "width": framebuffer.width,
            "height": framebuffer.height,
            "stride_bytes": framebuffer.stride_bytes,
            "pixel_format": framebuffer.pixel_format,
            "byte_len": framebuffer.byte_len,
        },
        "authority": {
            "write_requires": "display-capability-and-framebuffer-window-lease",
            "raw_mapping_is_semantic_truth": false,
        },
        "note": framebuffer.note,
        "last_transition": {
            "recorded_at_event": framebuffer.recorded_at_event,
            "state": framebuffer.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_object_view_v1(display: &DisplayObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-object",
        "id": display.id,
        "generation": display.generation,
        "state": display.state,
        "owner": {
            "framebuffer": object_ref_json(
                "framebuffer-object",
                display.framebuffer,
                display.framebuffer_generation,
            ),
        },
        "references": {
            "framebuffer": object_ref_json(
                "framebuffer-object",
                display.framebuffer,
                display.framebuffer_generation,
            ),
            "event": {
                "id": display.recorded_at_event,
            },
        },
        "identity": {
            "name": display.name,
        },
        "mode": {
            "name": display.mode_name,
            "width": display.width,
            "height": display.height,
            "refresh_millihz": display.refresh_millihz,
        },
        "authority": {
            "write_requires": "display-capability-and-framebuffer-window-lease",
            "flush_requires": "display-capability",
            "raw_mapping_is_semantic_truth": false,
        },
        "note": display.note,
        "last_transition": {
            "recorded_at_event": display.recorded_at_event,
            "state": display.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_capability_view_v1(
    capability: &DisplayCapabilityManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-capability",
        "id": capability.id,
        "generation": capability.generation,
        "state": capability.state,
        "owner": {
            "store": object_ref_json(
                "store",
                capability.owner_store,
                capability.owner_store_generation,
            ),
        },
        "references": {
            "display": object_ref_json(
                "display-object",
                capability.display,
                capability.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                capability.framebuffer,
                capability.framebuffer_generation,
            ),
            "capability": object_ref_json(
                "capability",
                capability.capability,
                capability.capability_generation,
            ),
            "event": {
                "id": capability.recorded_at_event,
            },
        },
        "authority": {
            "class": "display",
            "operations": capability.operations,
            "handle": {
                "slot": capability.handle_slot,
                "generation": capability.handle_generation,
                "tag": capability.handle_tag,
            },
            "write_requires_framebuffer_window_lease": true,
            "raw_mapping_is_semantic_truth": false,
        },
        "note": capability.note,
        "last_transition": {
            "recorded_at_event": capability.recorded_at_event,
            "owner_store_generation": capability.owner_store_generation,
            "display_generation": capability.display_generation,
            "framebuffer_generation": capability.framebuffer_generation,
            "capability_generation": capability.capability_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn framebuffer_window_lease_view_v1(
    lease: &FramebufferWindowLeaseManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-window-lease",
        "id": lease.id,
        "generation": lease.generation,
        "state": lease.state,
        "owner": {
            "store": object_ref_json(
                "store",
                lease.owner_store,
                lease.owner_store_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                lease.display_capability,
                lease.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                lease.display,
                lease.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                lease.framebuffer,
                lease.framebuffer_generation,
            ),
            "event": {
                "id": lease.recorded_at_event,
            },
        },
        "window": {
            "x": lease.x,
            "y": lease.y,
            "width": lease.width,
            "height": lease.height,
            "byte_offset": lease.byte_offset,
            "byte_len": lease.byte_len,
            "access": lease.access,
        },
        "authority": {
            "requires_display_capability_operation": "lease",
            "write_requires_this_lease": true,
            "raw_mapping_is_semantic_truth": false,
            "snapshot_barrier_must_release": true,
        },
        "note": lease.note,
        "last_transition": {
            "recorded_at_event": lease.recorded_at_event,
            "owner_store_generation": lease.owner_store_generation,
            "display_capability_generation": lease.display_capability_generation,
            "display_generation": lease.display_generation,
            "framebuffer_generation": lease.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn framebuffer_mapping_view_v1(
    mapping: &FramebufferMappingManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-mapping",
        "id": mapping.id,
        "generation": mapping.generation,
        "state": mapping.state,
        "owner": {
            "store": object_ref_json(
                "store",
                mapping.owner_store,
                mapping.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_window_lease": object_ref_json(
                "framebuffer-window-lease",
                mapping.framebuffer_window_lease,
                mapping.framebuffer_window_lease_generation,
            ),
            "display_capability": object_ref_json(
                "display-capability",
                mapping.display_capability,
                mapping.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                mapping.display,
                mapping.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                mapping.framebuffer,
                mapping.framebuffer_generation,
            ),
            "event": {
                "id": mapping.recorded_at_event,
            },
        },
        "map_handle": {
            "slot": mapping.map_handle_slot,
            "generation": mapping.map_handle_generation,
            "tag": mapping.map_handle_tag,
            "mode": mapping.mode,
        },
        "window": {
            "x": mapping.x,
            "y": mapping.y,
            "width": mapping.width,
            "height": mapping.height,
            "byte_offset": mapping.byte_offset,
            "byte_len": mapping.byte_len,
            "access": mapping.access,
        },
        "authority": {
            "requires_framebuffer_window_lease": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "pixel_write_allowed": false,
            "flush_allowed": false,
            "snapshot_barrier_must_release": true,
        },
        "note": mapping.note,
        "last_transition": {
            "recorded_at_event": mapping.recorded_at_event,
            "owner_store_generation": mapping.owner_store_generation,
            "framebuffer_window_lease_generation": mapping.framebuffer_window_lease_generation,
            "display_capability_generation": mapping.display_capability_generation,
            "display_generation": mapping.display_generation,
            "framebuffer_generation": mapping.framebuffer_generation,
            "map_handle_generation": mapping.map_handle_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn framebuffer_write_view_v1(write: &FramebufferWriteManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-write",
        "id": write.id,
        "generation": write.generation,
        "state": write.state,
        "owner": {
            "store": object_ref_json(
                "store",
                write.owner_store,
                write.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_mapping": object_ref_json(
                "framebuffer-mapping",
                write.framebuffer_mapping,
                write.framebuffer_mapping_generation,
            ),
            "framebuffer_window_lease": object_ref_json(
                "framebuffer-window-lease",
                write.framebuffer_window_lease,
                write.framebuffer_window_lease_generation,
            ),
            "display_capability": object_ref_json(
                "display-capability",
                write.display_capability,
                write.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                write.display,
                write.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                write.framebuffer,
                write.framebuffer_generation,
            ),
            "event": {
                "id": write.recorded_at_event,
            },
        },
        "map_handle": {
            "slot": write.map_handle_slot,
            "generation": write.map_handle_generation,
            "tag": write.map_handle_tag,
        },
        "write": {
            "x": write.x,
            "y": write.y,
            "width": write.width,
            "height": write.height,
            "byte_offset": write.byte_offset,
            "byte_len": write.byte_len,
            "pixel_format": write.pixel_format,
            "payload_digest": write.payload_digest,
        },
        "authority": {
            "requires_framebuffer_mapping": true,
            "requires_framebuffer_window_lease": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "flush_allowed": false,
        },
        "note": write.note,
        "last_transition": {
            "recorded_at_event": write.recorded_at_event,
            "owner_store_generation": write.owner_store_generation,
            "framebuffer_mapping_generation": write.framebuffer_mapping_generation,
            "framebuffer_window_lease_generation": write.framebuffer_window_lease_generation,
            "display_capability_generation": write.display_capability_generation,
            "display_generation": write.display_generation,
            "framebuffer_generation": write.framebuffer_generation,
            "map_handle_generation": write.map_handle_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn framebuffer_flush_region_view_v1(
    flush: &FramebufferFlushRegionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-flush-region",
        "id": flush.id,
        "generation": flush.generation,
        "state": flush.state,
        "owner": {
            "store": object_ref_json(
                "store",
                flush.owner_store,
                flush.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                flush.framebuffer_write,
                flush.framebuffer_write_generation,
            ),
            "display_capability": object_ref_json(
                "display-capability",
                flush.display_capability,
                flush.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                flush.display,
                flush.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                flush.framebuffer,
                flush.framebuffer_generation,
            ),
            "event": {
                "id": flush.recorded_at_event,
            },
        },
        "flush": {
            "x": flush.x,
            "y": flush.y,
            "width": flush.width,
            "height": flush.height,
            "byte_offset": flush.byte_offset,
            "byte_len": flush.byte_len,
            "pixel_format": flush.pixel_format,
            "payload_digest": flush.payload_digest,
        },
        "authority": {
            "requires_display_capability_flush": true,
            "requires_framebuffer_write": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "real_present_executed": false,
        },
        "note": flush.note,
        "last_transition": {
            "recorded_at_event": flush.recorded_at_event,
            "owner_store_generation": flush.owner_store_generation,
            "framebuffer_write_generation": flush.framebuffer_write_generation,
            "display_capability_generation": flush.display_capability_generation,
            "display_generation": flush.display_generation,
            "framebuffer_generation": flush.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn framebuffer_dirty_region_view_v1(
    dirty: &FramebufferDirtyRegionManifest,
) -> serde_json::Value {
    let flush_ref =
        match (dirty.framebuffer_flush_region, dirty.framebuffer_flush_region_generation) {
            (Some(id), Some(generation)) => {
                object_ref_json("framebuffer-flush-region", id, generation)
            }
            _ => serde_json::Value::Null,
        };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-dirty-region",
        "id": dirty.id,
        "generation": dirty.generation,
        "state": dirty.state,
        "owner": {
            "store": object_ref_json(
                "store",
                dirty.owner_store,
                dirty.owner_store_generation,
            ),
        },
        "references": {
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                dirty.framebuffer_write,
                dirty.framebuffer_write_generation,
            ),
            "framebuffer_flush_region": flush_ref,
            "display_capability": object_ref_json(
                "display-capability",
                dirty.display_capability,
                dirty.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                dirty.display,
                dirty.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                dirty.framebuffer,
                dirty.framebuffer_generation,
            ),
            "dirty_event": {
                "id": dirty.dirty_at_event,
            },
            "cleaned_event": dirty.cleaned_at_event
                .map(|id| serde_json::json!({"id": id}))
                .unwrap_or(serde_json::Value::Null),
            "recorded_event": {
                "id": dirty.recorded_at_event,
            },
        },
        "region": {
            "x": dirty.x,
            "y": dirty.y,
            "width": dirty.width,
            "height": dirty.height,
            "byte_offset": dirty.byte_offset,
            "byte_len": dirty.byte_len,
            "pixel_format": dirty.pixel_format,
            "payload_digest": dirty.payload_digest,
        },
        "authority": {
            "requires_framebuffer_write": true,
            "clean_state_requires_flush_region": true,
            "raw_pointer_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "real_present_executed": false,
        },
        "note": dirty.note,
        "last_transition": {
            "dirty_at_event": dirty.dirty_at_event,
            "cleaned_at_event": dirty.cleaned_at_event,
            "recorded_at_event": dirty.recorded_at_event,
            "owner_store_generation": dirty.owner_store_generation,
            "framebuffer_write_generation": dirty.framebuffer_write_generation,
            "framebuffer_flush_region_generation": dirty.framebuffer_flush_region_generation,
            "display_capability_generation": dirty.display_capability_generation,
            "display_generation": dirty.display_generation,
            "framebuffer_generation": dirty.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_event_log_view_v1(log: &DisplayEventLogManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-event-log",
        "id": log.id,
        "generation": log.generation,
        "state": log.state,
        "owner": {
            "store": object_ref_json(
                "store",
                log.owner_store,
                log.owner_store_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                log.display_capability,
                log.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                log.display,
                log.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                log.framebuffer,
                log.framebuffer_generation,
            ),
            "framebuffer_dirty_region": object_ref_json(
                "framebuffer-dirty-region",
                log.framebuffer_dirty_region,
                log.framebuffer_dirty_region_generation,
            ),
            "event": {
                "id": log.recorded_at_event,
            },
        },
        "window": {
            "first_event": log.first_event,
            "last_event": log.last_event,
            "event_count": log.event_count,
            "flush_count": log.flush_count,
            "dirty_region_count": log.dirty_region_count,
        },
        "authority": {
            "read_only_control_plane": true,
            "raw_event_storage_exposed": false,
            "raw_mapping_is_semantic_truth": false,
            "real_present_executed": false,
        },
        "note": log.note,
        "last_transition": {
            "recorded_at_event": log.recorded_at_event,
            "owner_store_generation": log.owner_store_generation,
            "display_capability_generation": log.display_capability_generation,
            "display_generation": log.display_generation,
            "framebuffer_generation": log.framebuffer_generation,
            "framebuffer_dirty_region_generation": log.framebuffer_dirty_region_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_cleanup_view_v1(cleanup: &DisplayCleanupManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "store": object_ref_json(
                "store",
                cleanup.owner_store,
                cleanup.owner_store_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                cleanup.display_capability,
                cleanup.display_capability_generation,
            ),
            "display": object_ref_json(
                "display-object",
                cleanup.display,
                cleanup.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                cleanup.framebuffer,
                cleanup.framebuffer_generation,
            ),
        },
        "cleanup": {
            "reason": cleanup.reason,
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
            "unmapped_framebuffer_mappings": cleanup.unmapped_framebuffer_mappings,
            "released_framebuffer_window_leases": cleanup.released_framebuffer_window_leases,
            "revoked_display_capabilities": cleanup.revoked_display_capabilities,
            "revoked_capabilities": cleanup.revoked_capabilities,
            "steps": cleanup.steps,
        },
        "authority": {
            "releases_handle_mode_mappings": true,
            "releases_framebuffer_leases": true,
            "revokes_display_capability": true,
            "real_present_executed": false,
        },
        "note": cleanup.note,
        "last_transition": {
            "completed_at_event": cleanup.completed_at_event,
            "owner_store_generation": cleanup.owner_store_generation,
            "display_capability_generation": cleanup.display_capability_generation,
            "display_generation": cleanup.display_generation,
            "framebuffer_generation": cleanup.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_snapshot_barrier_view_v1(
    barrier: &DisplaySnapshotBarrierManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-snapshot-barrier",
        "id": barrier.id,
        "generation": barrier.generation,
        "state": barrier.state,
        "owner": {
            "store": object_ref_json(
                "store",
                barrier.owner_store,
                barrier.owner_store_generation,
            ),
        },
        "references": {
            "display": object_ref_json(
                "display-object",
                barrier.display,
                barrier.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                barrier.framebuffer,
                barrier.framebuffer_generation,
            ),
            "display_cleanup": optional_object_ref_json(
                "display-cleanup",
                barrier.display_cleanup,
                barrier.display_cleanup_generation,
            ),
        },
        "snapshot": {
            "reason": barrier.reason,
            "snapshot_validation_ok": barrier.snapshot_validation_ok,
            "active_framebuffer_window_lease_count": barrier.active_framebuffer_window_lease_count,
            "active_framebuffer_mapping_count": barrier.active_framebuffer_mapping_count,
            "dirty_framebuffer_region_count": barrier.dirty_framebuffer_region_count,
            "validated_at_event": barrier.validated_at_event,
        },
        "authority": {
            "requires_no_active_framebuffer_lease": true,
            "requires_no_active_framebuffer_mapping": true,
            "requires_no_dirty_framebuffer_region": true,
            "real_snapshot_cow_executed": false,
            "real_present_executed": false,
        },
        "note": barrier.note,
        "last_transition": {
            "validated_at_event": barrier.validated_at_event,
            "owner_store_generation": barrier.owner_store_generation,
            "display_generation": barrier.display_generation,
            "framebuffer_generation": barrier.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn display_panic_last_frame_view_v1(
    frame: &DisplayPanicLastFrameManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "display-panic-last-frame",
        "id": frame.id,
        "generation": frame.generation,
        "state": frame.state,
        "owner": {
            "store": object_ref_json(
                "store",
                frame.owner_store,
                frame.owner_store_generation,
            ),
        },
        "references": {
            "display": object_ref_json(
                "display-object",
                frame.display,
                frame.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                frame.framebuffer,
                frame.framebuffer_generation,
            ),
            "display_snapshot_barrier": object_ref_json(
                "display-snapshot-barrier",
                frame.display_snapshot_barrier,
                frame.display_snapshot_barrier_generation,
            ),
            "display_event_log": object_ref_json(
                "display-event-log",
                frame.display_event_log,
                frame.display_event_log_generation,
            ),
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                frame.framebuffer_write,
                frame.framebuffer_write_generation,
            ),
            "framebuffer_flush_region": object_ref_json(
                "framebuffer-flush-region",
                frame.framebuffer_flush_region,
                frame.framebuffer_flush_region_generation,
            ),
        },
        "frame": {
            "x": frame.x,
            "y": frame.y,
            "width": frame.width,
            "height": frame.height,
            "byte_offset": frame.byte_offset,
            "byte_len": frame.byte_len,
            "pixel_format": frame.pixel_format,
            "payload_digest": frame.payload_digest,
            "summary_digest": frame.summary_digest,
        },
        "panic": {
            "epoch": frame.panic_epoch,
            "cpu": frame.panic_cpu,
            "reason_code": frame.panic_reason_code,
            "record_kind": frame.panic_record_kind,
            "summary_record_bytes": frame.summary_record_bytes,
            "raw_framebuffer_bytes_exported": frame.raw_framebuffer_bytes_exported,
            "recorded_at_event": frame.recorded_at_event,
        },
        "authority": {
            "panic_path_allocates": false,
            "raw_framebuffer_bytes_exported": frame.raw_framebuffer_bytes_exported,
            "real_panic_ring_write_executed": false,
        },
        "note": frame.note,
        "last_transition": {
            "recorded_at_event": frame.recorded_at_event,
            "owner_store_generation": frame.owner_store_generation,
            "display_generation": frame.display_generation,
            "framebuffer_generation": frame.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}
