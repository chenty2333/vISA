use super::super::super::*;

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
