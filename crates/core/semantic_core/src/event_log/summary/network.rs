use alloc::{
    format,
    string::{String, ToString},
};

use super::super::{super::*, kind::EventKind};

pub(super) fn summary(kind: &EventKind) -> Option<String> {
    let summary = match kind {
        EventKind::PacketDeviceObjectRecorded {
            packet_device,
            device,
            device_generation,
            mtu,
            rx_queue_depth,
            tx_queue_depth,
            frame_format_version,
            max_payload_len,
            generation,
        } => format!(
            "PacketDeviceObjectRecorded packet_device={packet_device} device={device}@{device_generation} mtu={mtu} rx_queue_depth={rx_queue_depth} tx_queue_depth={tx_queue_depth} frame_format_version={frame_format_version} max_payload_len={max_payload_len} generation={generation}"
        ),
        EventKind::PacketBufferObjectRecorded {
            packet_buffer,
            packet_device,
            packet_device_generation,
            direction,
            frame_format_version,
            capacity,
            payload_len,
            sequence,
            state,
            generation,
        } => format!(
            "PacketBufferObjectRecorded packet_buffer={packet_buffer} packet_device={packet_device}@{packet_device_generation} direction={} frame_format_version={frame_format_version} capacity={capacity} payload_len={payload_len} sequence={sequence} state={} generation={generation}",
            direction.as_str(),
            state.as_str()
        ),
        EventKind::PacketQueueObjectRecorded {
            packet_queue,
            packet_device,
            packet_device_generation,
            role,
            queue_index,
            depth,
            generation,
        } => format!(
            "PacketQueueObjectRecorded packet_queue={packet_queue} packet_device={packet_device}@{packet_device_generation} role={} queue_index={queue_index} depth={depth} generation={generation}",
            role.as_str()
        ),
        EventKind::PacketDescriptorObjectRecorded {
            packet_descriptor,
            packet_queue,
            packet_queue_generation,
            packet_buffer,
            packet_buffer_generation,
            slot,
            length,
            generation,
        } => format!(
            "PacketDescriptorObjectRecorded packet_descriptor={packet_descriptor} packet_queue={packet_queue}@{packet_queue_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} slot={slot} length={length} generation={generation}"
        ),
        EventKind::FakeNetBackendObjectBound {
            fake_net_backend,
            packet_device,
            packet_device_generation,
            mtu,
            rx_queue_depth,
            tx_queue_depth,
            frame_format_version,
            max_payload_len,
            deterministic_seed,
            generation,
        } => format!(
            "FakeNetBackendObjectBound fake_net_backend={fake_net_backend} packet_device={packet_device}@{packet_device_generation} mtu={mtu} rx_queue_depth={rx_queue_depth} tx_queue_depth={tx_queue_depth} frame_format_version={frame_format_version} max_payload_len={max_payload_len} deterministic_seed={deterministic_seed} generation={generation}"
        ),
        EventKind::VirtioNetBackendSkeletonBound {
            virtio_net_backend,
            packet_device,
            packet_device_generation,
            driver_binding,
            driver_binding_generation,
            device,
            device_generation,
            queue_size,
            rx_queue_index,
            tx_queue_index,
            negotiated_features,
            generation,
        } => format!(
            "VirtioNetBackendSkeletonBound virtio_net_backend={virtio_net_backend} packet_device={packet_device}@{packet_device_generation} driver_binding={driver_binding}@{driver_binding_generation} device={device}@{device_generation} queue_size={queue_size} rx_queue_index={rx_queue_index} tx_queue_index={tx_queue_index} negotiated_features={negotiated_features} generation={generation}"
        ),
        EventKind::NetworkRxInterruptRecorded {
            rx_interrupt,
            virtio_net_backend,
            virtio_net_backend_generation,
            irq_event,
            irq_event_generation,
            packet_device,
            packet_device_generation,
            rx_queue,
            rx_queue_generation,
            ready_descriptors,
            sequence,
            generation,
        } => format!(
            "NetworkRxInterruptRecorded rx_interrupt={rx_interrupt} virtio_net_backend={virtio_net_backend}@{virtio_net_backend_generation} irq_event={irq_event}@{irq_event_generation} packet_device={packet_device}@{packet_device_generation} rx_queue={rx_queue}@{rx_queue_generation} ready_descriptors={ready_descriptors} sequence={sequence} generation={generation}"
        ),
        EventKind::NetworkRxWaitResolved {
            resolution,
            io_wait,
            io_wait_generation,
            wait,
            wait_generation,
            rx_interrupt,
            rx_interrupt_generation,
            rx_queue,
            rx_queue_generation,
            ready_descriptors,
            generation,
        } => format!(
            "NetworkRxWaitResolved resolution={resolution} io_wait={io_wait}@{io_wait_generation} wait={wait}@{wait_generation} rx_interrupt={rx_interrupt}@{rx_interrupt_generation} rx_queue={rx_queue}@{rx_queue_generation} ready_descriptors={ready_descriptors} generation={generation}"
        ),
        EventKind::NetworkTxCapabilityGateRecorded {
            tx_gate,
            driver_store,
            driver_store_generation,
            packet_device,
            packet_device_generation,
            tx_queue,
            tx_queue_generation,
            packet_descriptor,
            packet_descriptor_generation,
            packet_buffer,
            packet_buffer_generation,
            device_capability,
            device_capability_generation,
            capability,
            capability_generation,
            handle_slot,
            handle_generation,
            handle_tag,
            byte_len,
            sequence,
            generation,
        } => format!(
            "NetworkTxCapabilityGateRecorded tx_gate={tx_gate} driver_store={driver_store}@{driver_store_generation} packet_device={packet_device}@{packet_device_generation} tx_queue={tx_queue}@{tx_queue_generation} packet_descriptor={packet_descriptor}@{packet_descriptor_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} device_capability={device_capability}@{device_capability_generation} capability={capability}@{capability_generation} handle_slot={handle_slot} handle_generation={handle_generation} handle_tag={handle_tag} byte_len={byte_len} sequence={sequence} generation={generation}"
        ),
        EventKind::NetworkTxCompleted {
            completion,
            tx_gate,
            tx_gate_generation,
            backend,
            driver_store,
            driver_store_generation,
            packet_device,
            packet_device_generation,
            tx_queue,
            tx_queue_generation,
            packet_descriptor,
            packet_descriptor_generation,
            packet_buffer,
            packet_buffer_generation,
            byte_len,
            sequence,
            completion_sequence,
            generation,
        } => format!(
            "NetworkTxCompleted completion={completion} tx_gate={tx_gate}@{tx_gate_generation} backend={} driver_store={driver_store}@{driver_store_generation} packet_device={packet_device}@{packet_device_generation} tx_queue={tx_queue}@{tx_queue_generation} packet_descriptor={packet_descriptor}@{packet_descriptor_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} byte_len={byte_len} sequence={sequence} completion_sequence={completion_sequence} generation={generation}",
            backend.summary()
        ),
        EventKind::NetworkStackAdapterBound {
            adapter,
            implementation,
            implementation_version,
            profile,
            medium,
            backend,
            packet_device,
            packet_device_generation,
            rx_queue,
            rx_queue_generation,
            tx_queue,
            tx_queue_generation,
            mac,
            ipv4_addr,
            ipv4_prefix_len,
            mtu,
            rx_queue_depth,
            tx_queue_depth,
            max_payload_len,
            socket_capacity,
            generation,
        } => format!(
            "NetworkStackAdapterBound adapter={adapter} implementation={implementation} version={implementation_version} profile={profile} medium={medium} backend={} packet_device={packet_device}@{packet_device_generation} rx_queue={rx_queue}@{rx_queue_generation} tx_queue={tx_queue}@{tx_queue_generation} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ipv4={}.{}.{}.{}/{} mtu={mtu} rx_queue_depth={rx_queue_depth} tx_queue_depth={tx_queue_depth} max_payload_len={max_payload_len} socket_capacity={socket_capacity} generation={generation}",
            backend.summary(),
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
            ipv4_addr[0],
            ipv4_addr[1],
            ipv4_addr[2],
            ipv4_addr[3],
            ipv4_prefix_len
        ),
        EventKind::SocketObjectCreated {
            socket,
            adapter,
            adapter_generation,
            owner_store,
            owner_store_generation,
            domain,
            socket_type,
            protocol,
            canonical_protocol,
            family,
            transport,
            generation,
        } => format!(
            "SocketObjectCreated socket={socket} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} domain={domain} type={socket_type} protocol={protocol} canonical_protocol={canonical_protocol} family={family} transport={transport} generation={generation}"
        ),
        EventKind::EndpointObjectCreated {
            endpoint,
            socket,
            socket_generation,
            adapter,
            adapter_generation,
            owner_store,
            owner_store_generation,
            family,
            transport,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            generation,
        } => format!(
            "EndpointObjectCreated endpoint={endpoint} socket={socket}@{socket_generation} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} family={family} transport={transport} local={}.{}.{}.{}:{local_port} remote={}.{}.{}.{}:{remote_port} generation={generation}",
            local_addr[0],
            local_addr[1],
            local_addr[2],
            local_addr[3],
            remote_addr[0],
            remote_addr[1],
            remote_addr[2],
            remote_addr[3]
        ),
        EventKind::SocketOperationRecorded {
            operation_id,
            endpoint,
            endpoint_generation,
            socket,
            socket_generation,
            adapter,
            adapter_generation,
            owner_store,
            owner_store_generation,
            operation,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            backlog,
            byte_len,
            sequence,
            generation,
        } => format!(
            "SocketOperationRecorded operation_id={operation_id} operation={} endpoint={endpoint}@{endpoint_generation} socket={socket}@{socket_generation} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} local={}.{}.{}.{}:{local_port} remote={}.{}.{}.{}:{remote_port} backlog={backlog} byte_len={byte_len} sequence={sequence} generation={generation}",
            operation.as_str(),
            local_addr[0],
            local_addr[1],
            local_addr[2],
            local_addr[3],
            remote_addr[0],
            remote_addr[1],
            remote_addr[2],
            remote_addr[3]
        ),
        EventKind::SocketWaitCreated {
            socket_wait,
            wait,
            wait_generation,
            endpoint,
            endpoint_generation,
            socket,
            socket_generation,
            adapter,
            adapter_generation,
            owner_store,
            owner_store_generation,
            wait_kind,
            blocker,
            generation,
        } => format!(
            "SocketWaitCreated socket_wait={socket_wait} wait={wait}@{wait_generation} endpoint={endpoint}@{endpoint_generation} socket={socket}@{socket_generation} adapter={adapter}@{adapter_generation} owner_store={owner_store}@{owner_store_generation} kind={} blocker={}:{}@{} generation={generation}",
            wait_kind.as_str(),
            blocker.kind.as_str(),
            blocker.id,
            blocker.generation
        ),
        EventKind::SocketWaitResolved {
            socket_wait,
            wait,
            wait_generation,
            ready_sequence,
            byte_len,
            generation,
        } => format!(
            "SocketWaitResolved socket_wait={socket_wait} wait={wait}@{wait_generation} ready_sequence={ready_sequence} byte_len={byte_len} generation={generation}"
        ),
        EventKind::SocketWaitCancelled {
            socket_wait,
            wait,
            wait_generation,
            reason,
            generation,
        } => format!(
            "SocketWaitCancelled socket_wait={socket_wait} wait={wait}@{wait_generation} reason={} generation={generation}",
            reason.as_str()
        ),
        EventKind::NetworkBackpressureRecorded {
            backpressure,
            adapter,
            adapter_generation,
            packet_device,
            packet_device_generation,
            packet_queue,
            packet_queue_generation,
            endpoint,
            endpoint_generation,
            socket,
            socket_generation,
            owner_store,
            owner_store_generation,
            direction,
            reason,
            action,
            queue_depth,
            queue_limit,
            dropped_packets,
            dropped_bytes,
            sequence,
            generation,
        } => {
            let endpoint_summary = endpoint.map_or_else(
                || "none".to_string(),
                |id| format!("{id}@{}", endpoint_generation.unwrap_or(0)),
            );
            let socket_summary = socket.map_or_else(
                || "none".to_string(),
                |id| format!("{id}@{}", socket_generation.unwrap_or(0)),
            );
            let owner_store_summary = owner_store.map_or_else(
                || "none".to_string(),
                |id| format!("{id}@{}", owner_store_generation.unwrap_or(0)),
            );
            format!(
                "NetworkBackpressureRecorded backpressure={backpressure} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} packet_queue={packet_queue}@{packet_queue_generation} endpoint={endpoint_summary} socket={socket_summary} owner_store={owner_store_summary} direction={} reason={} action={} queue_depth={queue_depth} queue_limit={queue_limit} dropped_packets={dropped_packets} dropped_bytes={dropped_bytes} sequence={sequence} generation={generation}",
                direction.as_str(),
                reason.as_str(),
                action.as_str()
            )
        }
        EventKind::NetworkDriverCleanupStarted {
            cleanup,
            io_cleanup,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            driver_binding,
            driver_binding_generation,
            packet_device,
            packet_device_generation,
            adapter,
            adapter_generation,
            backend,
            generation,
        } => format!(
            "NetworkDriverCleanupStarted cleanup={cleanup} io_cleanup={io_cleanup} driver_store={driver_store}@{driver_store_generation} device={device}@{device_generation} driver_binding={driver_binding}@{driver_binding_generation} packet_device={packet_device}@{packet_device_generation} adapter={adapter}@{adapter_generation} backend={}:{}@{} generation={generation}",
            backend.kind.as_str(),
            backend.id,
            backend.generation
        ),
        EventKind::NetworkDriverCleanupCompleted {
            cleanup,
            io_cleanup,
            io_cleanup_generation,
            cancelled_socket_waits,
            revoked_packet_capabilities,
            generation,
        } => format!(
            "NetworkDriverCleanupCompleted cleanup={cleanup} io_cleanup={io_cleanup}@{io_cleanup_generation} cancelled_socket_waits={cancelled_socket_waits} revoked_packet_capabilities={revoked_packet_capabilities} generation={generation}"
        ),
        EventKind::NetworkGenerationAuditRecorded {
            audit,
            adapter,
            adapter_generation,
            packet_device,
            packet_device_generation,
            packet_queue,
            packet_queue_generation,
            packet_descriptor,
            packet_descriptor_generation,
            packet_buffer,
            packet_buffer_generation,
            dma_buffer,
            device_capability,
            rejected_packet_generation_probes,
            rejected_dma_generation_probes,
            generation,
        } => format!(
            "NetworkGenerationAuditRecorded audit={audit} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} packet_queue={packet_queue}@{packet_queue_generation} packet_descriptor={packet_descriptor}@{packet_descriptor_generation} packet_buffer={packet_buffer}@{packet_buffer_generation} dma_buffer={}:{}@{} device_capability={}:{}@{} rejected_packet_generation_probes={rejected_packet_generation_probes} rejected_dma_generation_probes={rejected_dma_generation_probes} generation={generation}",
            dma_buffer.kind.as_str(),
            dma_buffer.id,
            dma_buffer.generation,
            device_capability.kind.as_str(),
            device_capability.id,
            device_capability.generation
        ),
        EventKind::NetworkFaultInjectionRecorded {
            injection,
            adapter,
            adapter_generation,
            packet_device,
            packet_device_generation,
            packet_queue,
            packet_queue_generation,
            packet_descriptor,
            packet_descriptor_generation,
            packet_buffer,
            packet_buffer_generation,
            endpoint,
            endpoint_generation,
            socket,
            socket_generation,
            owner_store,
            owner_store_generation,
            direction,
            kind,
            effect,
            injected_packets,
            dropped_packets,
            error_packets,
            error_code,
            sequence,
            generation,
        } => {
            let descriptor_summary = packet_descriptor.map_or_else(
                || "none".to_string(),
                |id| format!("{id}@{}", packet_descriptor_generation.unwrap_or(0)),
            );
            let buffer_summary = packet_buffer.map_or_else(
                || "none".to_string(),
                |id| format!("{id}@{}", packet_buffer_generation.unwrap_or(0)),
            );
            let endpoint_summary = endpoint.map_or_else(
                || "none".to_string(),
                |id| format!("{id}@{}", endpoint_generation.unwrap_or(0)),
            );
            let socket_summary = socket.map_or_else(
                || "none".to_string(),
                |id| format!("{id}@{}", socket_generation.unwrap_or(0)),
            );
            let owner_store_summary = owner_store.map_or_else(
                || "none".to_string(),
                |id| format!("{id}@{}", owner_store_generation.unwrap_or(0)),
            );
            format!(
                "NetworkFaultInjectionRecorded injection={injection} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} packet_queue={packet_queue}@{packet_queue_generation} packet_descriptor={descriptor_summary} packet_buffer={buffer_summary} endpoint={endpoint_summary} socket={socket_summary} owner_store={owner_store_summary} direction={} kind={} effect={} injected_packets={injected_packets} dropped_packets={dropped_packets} error_packets={error_packets} error_code={error_code} sequence={sequence} generation={generation}",
                direction.as_str(),
                kind.as_str(),
                effect.as_str()
            )
        }
        EventKind::NetworkBenchmarkRecorded {
            benchmark,
            adapter,
            adapter_generation,
            packet_device,
            packet_device_generation,
            tx_completion,
            tx_completion_generation,
            rx_wait_resolution,
            rx_wait_resolution_generation,
            endpoint,
            endpoint_generation,
            socket,
            socket_generation,
            owner_store,
            owner_store_generation,
            sample_packets,
            sample_bytes,
            tx_completed_packets,
            rx_resolved_packets,
            dropped_packets,
            measured_nanos,
            budget_nanos,
            throughput_bytes_per_sec,
            p50_latency_nanos,
            p99_latency_nanos,
            generation,
        } => format!(
            "NetworkBenchmarkRecorded benchmark={benchmark} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} tx_completion={tx_completion}@{tx_completion_generation} rx_wait_resolution={rx_wait_resolution}@{rx_wait_resolution_generation} endpoint={endpoint}@{endpoint_generation} socket={socket}@{socket_generation} owner_store={owner_store}@{owner_store_generation} sample_packets={sample_packets} sample_bytes={sample_bytes} tx_completed_packets={tx_completed_packets} rx_resolved_packets={rx_resolved_packets} dropped_packets={dropped_packets} measured_nanos={measured_nanos} budget_nanos={budget_nanos} throughput_bytes_per_sec={throughput_bytes_per_sec} p50_latency_nanos={p50_latency_nanos} p99_latency_nanos={p99_latency_nanos} generation={generation}",
        ),
        EventKind::NetworkRecoveryBenchmarkRecorded {
            benchmark,
            cleanup,
            cleanup_generation,
            io_cleanup,
            io_cleanup_generation,
            adapter,
            adapter_generation,
            packet_device,
            packet_device_generation,
            driver_store,
            driver_store_generation,
            fault_injection,
            fault_injection_generation,
            recovery_start_event,
            recovery_complete_event,
            cancelled_socket_waits,
            revoked_packet_capabilities,
            recovery_nanos,
            budget_nanos,
            generation,
        } => {
            let fault_injection_summary = match (*fault_injection, *fault_injection_generation) {
                (Some(injection), Some(injection_generation)) => {
                    format!("{injection}@{injection_generation}")
                }
                _ => "none".to_string(),
            };
            format!(
                "NetworkRecoveryBenchmarkRecorded benchmark={benchmark} cleanup={cleanup}@{cleanup_generation} io_cleanup={io_cleanup}@{io_cleanup_generation} adapter={adapter}@{adapter_generation} packet_device={packet_device}@{packet_device_generation} driver_store={driver_store}@{driver_store_generation} fault_injection={fault_injection_summary} recovery_start_event={recovery_start_event} recovery_complete_event={recovery_complete_event} cancelled_socket_waits={cancelled_socket_waits} revoked_packet_capabilities={revoked_packet_capabilities} recovery_nanos={recovery_nanos} budget_nanos={budget_nanos} generation={generation}"
            )
        }
        EventKind::PacketReceived { interface, socket, ready_key, len } => {
            let socket =
                socket.map(|socket| socket.to_string()).unwrap_or_else(|| "none".to_string());
            format!(
                "PacketReceived interface={interface} socket={socket} ready_key=0x{ready_key:x} len={len}"
            )
        }
        EventKind::PacketTransmitted { interface, socket, ready_key, len } => {
            let socket =
                socket.map(|socket| socket.to_string()).unwrap_or_else(|| "none".to_string());
            format!(
                "PacketTransmitted interface={interface} socket={socket} ready_key=0x{ready_key:x} len={len}"
            )
        }
        EventKind::NetInterfaceStateChanged { interface, up } => {
            let state = if *up { "up" } else { "down" };
            format!("NetInterfaceStateChanged interface={interface} state={state}")
        }
        EventKind::SocketStateChanged { socket, state } => {
            format!("SocketStateChanged socket={socket} state={state}")
        }
        _ => return None,
    };
    Some(summary)
}
