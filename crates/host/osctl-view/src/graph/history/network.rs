use super::super::*;

pub(super) fn push_network_history_edges(
    package: &MigrationPackageManifest,
    edges: &mut Vec<serde_json::Value>,
) {
    for operation in &package.semantic.socket_operations {
        if operation.state != "applied" {
            continue;
        }
        let from = object_ref_json("socket-operation", operation.id, operation.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("endpoint-object", operation.endpoint, operation.endpoint_generation),
            "socket-operation->endpoint-object",
            "historical",
            Some(operation.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("socket-object", operation.socket, operation.socket_generation),
            "socket-operation->socket-object",
            "historical",
            Some(operation.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-stack-adapter",
                operation.adapter,
                operation.adapter_generation,
            ),
            "socket-operation->network-stack-adapter",
            "historical",
            Some(operation.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("store", operation.owner_store, operation.owner_store_generation),
            "socket-operation->owner-store",
            "historical",
            Some(operation.recorded_at_event),
        ));
    }
    for wait in &package.semantic.socket_waits {
        if wait.state == "pending" {
            continue;
        }
        let event = wait.completed_at_event.or(Some(wait.created_at_event));
        let from = object_ref_json("socket-wait", wait.id, wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", wait.wait, wait.wait_generation),
            "socket-wait->wait-token",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("endpoint-object", wait.endpoint, wait.endpoint_generation),
            "socket-wait->endpoint-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("socket-object", wait.socket, wait.socket_generation),
            "socket-wait->socket-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("network-stack-adapter", wait.adapter, wait.adapter_generation),
            "socket-wait->network-stack-adapter",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", wait.owner_store, wait.owner_store_generation),
            "socket-wait->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_manifest_json(&wait.blocker),
            "socket-wait->blocker",
            if wait.blocker.kind == "external" { "external" } else { "historical" },
            event,
        ));
    }
    for backpressure in &package.semantic.network_backpressures {
        let from =
            object_ref_json("network-backpressure", backpressure.id, backpressure.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-stack-adapter",
                backpressure.adapter,
                backpressure.adapter_generation,
            ),
            "network-backpressure->network-stack-adapter",
            "historical",
            Some(backpressure.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-device",
                backpressure.packet_device,
                backpressure.packet_device_generation,
            ),
            "network-backpressure->packet-device",
            "historical",
            Some(backpressure.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-queue",
                backpressure.packet_queue,
                backpressure.packet_queue_generation,
            ),
            "network-backpressure->packet-queue",
            "historical",
            Some(backpressure.recorded_at_event),
        ));
        if let (Some(endpoint), Some(endpoint_generation)) =
            (backpressure.endpoint, backpressure.endpoint_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("endpoint-object", endpoint, endpoint_generation),
                "network-backpressure->endpoint-object",
                "historical",
                Some(backpressure.recorded_at_event),
            ));
        }
        if let (Some(socket), Some(socket_generation)) =
            (backpressure.socket, backpressure.socket_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("socket-object", socket, socket_generation),
                "network-backpressure->socket-object",
                "historical",
                Some(backpressure.recorded_at_event),
            ));
        }
        if let (Some(store), Some(store_generation)) =
            (backpressure.owner_store, backpressure.owner_store_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("store", store, store_generation),
                "network-backpressure->owner-store",
                "historical",
                Some(backpressure.recorded_at_event),
            ));
        }
    }
    for cleanup in &package.semantic.network_driver_cleanups {
        let from = object_ref_json("network-driver-cleanup", cleanup.id, cleanup.generation);
        let event = cleanup.completed_at_event.or(Some(cleanup.started_at_event));
        for (target, relation) in [
            (
                object_ref_json("io-cleanup", cleanup.io_cleanup, cleanup.io_cleanup_generation),
                "network-driver-cleanup->io-cleanup",
            ),
            (
                object_ref_json("store", cleanup.driver_store, cleanup.driver_store_generation),
                "network-driver-cleanup->driver-store",
            ),
            (
                object_ref_json("device", cleanup.device, cleanup.device_generation),
                "network-driver-cleanup->device",
            ),
            (
                object_ref_json(
                    "driver-store-binding",
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                ),
                "network-driver-cleanup->driver-binding",
            ),
            (
                object_ref_json(
                    "packet-device",
                    cleanup.packet_device,
                    cleanup.packet_device_generation,
                ),
                "network-driver-cleanup->packet-device",
            ),
            (
                object_ref_json(
                    "network-stack-adapter",
                    cleanup.adapter,
                    cleanup.adapter_generation,
                ),
                "network-driver-cleanup->network-stack-adapter",
            ),
            (object_ref_manifest_json(&cleanup.backend), "network-driver-cleanup->backend"),
        ] {
            edges.push(graph_edge(from.clone(), target, relation, "historical", event));
        }
        for socket_wait in &cleanup.cancelled_socket_waits {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(socket_wait),
                "network-driver-cleanup->cancelled-socket-wait",
                "cleanup-effect",
                event,
            ));
        }
        for wait in &cleanup.cancelled_wait_tokens {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(wait),
                "network-driver-cleanup->cancelled-wait-token",
                "cleanup-effect",
                event,
            ));
        }
        for capability in &cleanup.revoked_packet_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(capability),
                "network-driver-cleanup->revoked-packet-capability",
                "cleanup-effect",
                event,
            ));
        }
    }
    for audit in &package.semantic.network_generation_audits {
        let from = object_ref_json("network-generation-audit", audit.id, audit.generation);
        let event = Some(audit.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json("network-stack-adapter", audit.adapter, audit.adapter_generation),
                "network-generation-audit->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    audit.packet_device,
                    audit.packet_device_generation,
                ),
                "network-generation-audit->packet-device",
            ),
            (
                object_ref_json("packet-queue", audit.packet_queue, audit.packet_queue_generation),
                "network-generation-audit->packet-queue",
            ),
            (
                object_ref_json(
                    "packet-descriptor",
                    audit.packet_descriptor,
                    audit.packet_descriptor_generation,
                ),
                "network-generation-audit->packet-descriptor",
            ),
            (
                object_ref_json(
                    "packet-buffer",
                    audit.packet_buffer,
                    audit.packet_buffer_generation,
                ),
                "network-generation-audit->packet-buffer",
            ),
            (object_ref_manifest_json(&audit.dma_buffer), "network-generation-audit->dma-buffer"),
            (
                object_ref_manifest_json(&audit.device_capability),
                "network-generation-audit->device-capability",
            ),
        ] {
            edges.push(graph_edge(from.clone(), target, relation, "historical", event));
        }
    }
    for injection in &package.semantic.network_fault_injections {
        let from = object_ref_json("network-fault-injection", injection.id, injection.generation);
        let event = Some(injection.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json(
                    "network-stack-adapter",
                    injection.adapter,
                    injection.adapter_generation,
                ),
                "network-fault-injection->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    injection.packet_device,
                    injection.packet_device_generation,
                ),
                "network-fault-injection->packet-device",
            ),
            (
                object_ref_json(
                    "packet-queue",
                    injection.packet_queue,
                    injection.packet_queue_generation,
                ),
                "network-fault-injection->packet-queue",
            ),
        ] {
            edges.push(graph_edge(from.clone(), target, relation, "historical", event));
        }
        if let (Some(packet_descriptor), Some(packet_descriptor_generation)) =
            (injection.packet_descriptor, injection.packet_descriptor_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "packet-descriptor",
                    packet_descriptor,
                    packet_descriptor_generation,
                ),
                "network-fault-injection->packet-descriptor",
                "historical",
                event,
            ));
        }
        if let (Some(packet_buffer), Some(packet_buffer_generation)) =
            (injection.packet_buffer, injection.packet_buffer_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("packet-buffer", packet_buffer, packet_buffer_generation),
                "network-fault-injection->packet-buffer",
                "historical",
                event,
            ));
        }
        if let (Some(endpoint), Some(endpoint_generation)) =
            (injection.endpoint, injection.endpoint_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("endpoint-object", endpoint, endpoint_generation),
                "network-fault-injection->endpoint-object",
                "historical",
                event,
            ));
        }
        if let (Some(socket), Some(socket_generation)) =
            (injection.socket, injection.socket_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("socket-object", socket, socket_generation),
                "network-fault-injection->socket-object",
                "historical",
                event,
            ));
        }
        if let (Some(owner_store), Some(owner_store_generation)) =
            (injection.owner_store, injection.owner_store_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("store", owner_store, owner_store_generation),
                "network-fault-injection->owner-store",
                "historical",
                event,
            ));
        }
    }
    for benchmark in &package.semantic.network_benchmarks {
        let from = object_ref_json("network-benchmark", benchmark.id, benchmark.generation);
        let event = Some(benchmark.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json(
                    "network-stack-adapter",
                    benchmark.adapter,
                    benchmark.adapter_generation,
                ),
                "network-benchmark->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    benchmark.packet_device,
                    benchmark.packet_device_generation,
                ),
                "network-benchmark->packet-device",
            ),
            (
                object_ref_json("packet-queue", benchmark.tx_queue, benchmark.tx_queue_generation),
                "network-benchmark->tx-queue",
            ),
            (
                object_ref_json("packet-queue", benchmark.rx_queue, benchmark.rx_queue_generation),
                "network-benchmark->rx-queue",
            ),
            (
                object_ref_json(
                    "network-tx-completion",
                    benchmark.tx_completion,
                    benchmark.tx_completion_generation,
                ),
                "network-benchmark->tx-completion",
            ),
            (
                object_ref_json(
                    "network-rx-wait-resolution",
                    benchmark.rx_wait_resolution,
                    benchmark.rx_wait_resolution_generation,
                ),
                "network-benchmark->rx-wait-resolution",
            ),
            (
                object_ref_json(
                    "endpoint-object",
                    benchmark.endpoint,
                    benchmark.endpoint_generation,
                ),
                "network-benchmark->endpoint-object",
            ),
            (
                object_ref_json("socket-object", benchmark.socket, benchmark.socket_generation),
                "network-benchmark->socket-object",
            ),
            (
                object_ref_json("store", benchmark.owner_store, benchmark.owner_store_generation),
                "network-benchmark->owner-store",
            ),
        ] {
            edges.push(graph_edge(from.clone(), target, relation, "historical", event));
        }
        if let (Some(backpressure), Some(backpressure_generation)) =
            (benchmark.backpressure, benchmark.backpressure_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("network-backpressure", backpressure, backpressure_generation),
                "network-benchmark->network-backpressure",
                "historical",
                event,
            ));
        }
    }
    for benchmark in &package.semantic.network_recovery_benchmarks {
        let from =
            object_ref_json("network-recovery-benchmark", benchmark.id, benchmark.generation);
        let event = Some(benchmark.recorded_at_event);
        for (target, relation) in [
            (
                object_ref_json(
                    "network-driver-cleanup",
                    benchmark.cleanup,
                    benchmark.cleanup_generation,
                ),
                "network-recovery-benchmark->network-driver-cleanup",
            ),
            (
                object_ref_json(
                    "io-cleanup",
                    benchmark.io_cleanup,
                    benchmark.io_cleanup_generation,
                ),
                "network-recovery-benchmark->io-cleanup",
            ),
            (
                object_ref_json(
                    "network-stack-adapter",
                    benchmark.adapter,
                    benchmark.adapter_generation,
                ),
                "network-recovery-benchmark->network-stack-adapter",
            ),
            (
                object_ref_json(
                    "packet-device",
                    benchmark.packet_device,
                    benchmark.packet_device_generation,
                ),
                "network-recovery-benchmark->packet-device",
            ),
            (object_ref_manifest_json(&benchmark.backend), "network-recovery-benchmark->backend"),
            (
                object_ref_json("store", benchmark.driver_store, benchmark.driver_store_generation),
                "network-recovery-benchmark->driver-store",
            ),
        ] {
            edges.push(graph_edge(from.clone(), target, relation, "historical", event));
        }
        if let (Some(fault_injection), Some(fault_injection_generation)) =
            (benchmark.fault_injection, benchmark.fault_injection_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "network-fault-injection",
                    fault_injection,
                    fault_injection_generation,
                ),
                "network-recovery-benchmark->network-fault-injection",
                "historical",
                event,
            ));
        }
    }
    for rx in &package.semantic.network_rx_interrupts {
        edges.push(graph_edge(
            object_ref_json("network-rx-interrupt", rx.id, rx.generation),
            object_ref_json("irq-event", rx.irq_event, rx.irq_event_generation),
            "network-rx-interrupt->irq-event",
            "historical",
            Some(rx.recorded_at_event),
        ));
    }
    for resolution in &package.semantic.network_rx_wait_resolutions {
        edges.push(graph_edge(
            object_ref_json("network-rx-wait-resolution", resolution.id, resolution.generation),
            object_ref_json("io-wait", resolution.io_wait, resolution.io_wait_generation),
            "network-rx-wait-resolution->io-wait",
            "historical",
            Some(resolution.resolved_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("network-rx-wait-resolution", resolution.id, resolution.generation),
            object_ref_json(
                "network-rx-interrupt",
                resolution.rx_interrupt,
                resolution.rx_interrupt_generation,
            ),
            "network-rx-wait-resolution->rx-interrupt",
            "historical",
            Some(resolution.resolved_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("network-rx-wait-resolution", resolution.id, resolution.generation),
            object_ref_json("packet-queue", resolution.rx_queue, resolution.rx_queue_generation),
            "network-rx-wait-resolution->rx-queue",
            "historical",
            Some(resolution.resolved_at_event),
        ));
    }
    for gate in &package.semantic.network_tx_capability_gates {
        let from = object_ref_json("network-tx-capability-gate", gate.id, gate.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-descriptor",
                gate.packet_descriptor,
                gate.packet_descriptor_generation,
            ),
            "network-tx-capability-gate->packet-descriptor",
            "historical",
            Some(gate.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("packet-device", gate.packet_device, gate.packet_device_generation),
            "network-tx-capability-gate->packet-device",
            "historical",
            Some(gate.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "device-capability",
                gate.device_capability,
                gate.device_capability_generation,
            ),
            "network-tx-capability-gate->device-capability",
            "historical",
            Some(gate.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("capability", gate.capability, gate.capability_generation),
            "network-tx-capability-gate->capability",
            "historical",
            Some(gate.recorded_at_event),
        ));
    }
    for completion in &package.semantic.network_tx_completions {
        let from = object_ref_json("network-tx-completion", completion.id, completion.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "network-tx-capability-gate",
                completion.tx_gate,
                completion.tx_gate_generation,
            ),
            "network-tx-completion->tx-gate",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                osctl_kind_from_contract_kind(&completion.backend_kind),
                completion.backend,
                completion.backend_generation,
            ),
            "network-tx-completion->backend",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-descriptor",
                completion.packet_descriptor,
                completion.packet_descriptor_generation,
            ),
            "network-tx-completion->packet-descriptor",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "packet-buffer",
                completion.packet_buffer,
                completion.packet_buffer_generation,
            ),
            "network-tx-completion->packet-buffer",
            "historical",
            Some(completion.completed_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "packet-device",
                completion.packet_device,
                completion.packet_device_generation,
            ),
            "network-tx-completion->packet-device",
            "historical",
            Some(completion.completed_at_event),
        ));
    }
}
