use super::*;

pub(super) fn push_network_roots(
    roots: &mut SemanticRootSetManifest,
    semantic: &SemanticGraph,
    _capabilities: &[MigrationCapabilityManifest],
    _target_v1: &TargetExecutorV1Report,
) {
    roots.packet_device_object_roots = semantic            .packet_device_objects()
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
            .collect();
    roots.packet_buffer_object_roots = semantic            .packet_buffer_objects()
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
            .collect();
    roots.packet_queue_object_roots = semantic            .packet_queue_objects()
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
            .collect();
    roots.packet_descriptor_object_roots = semantic            .packet_descriptors()
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
            .collect();
    roots.fake_net_backend_object_roots = semantic            .fake_net_backends()
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
            .collect();
    roots.virtio_net_backend_object_roots = semantic            .virtio_net_backends()
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
            .collect();
    roots.network_rx_interrupt_roots = semantic            .network_rx_interrupts()
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
            .collect();
    roots.network_rx_wait_resolution_roots = semantic            .network_rx_wait_resolutions()
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
            .collect();
    roots.network_tx_capability_gate_roots = semantic            .network_tx_capability_gates()
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
            .collect();
    roots.network_tx_completion_roots = semantic            .network_tx_completions()
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
            .collect();
    roots.network_stack_adapter_roots = semantic            .network_stack_adapters()
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
            .collect();
    roots.socket_object_roots = semantic            .socket_objects()
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
            .collect();
    roots.endpoint_object_roots = semantic            .endpoint_objects()
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
            .collect();
    roots.socket_operation_roots = semantic            .socket_operations()
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
            .collect();
    roots.socket_wait_roots = semantic            .socket_waits()
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
            .collect();
    roots.network_backpressure_roots = semantic            .network_backpressures()
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
            .collect();
    roots.network_driver_cleanup_roots = semantic            .network_driver_cleanups()
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
            .collect();
    roots.network_generation_audit_roots = semantic            .network_generation_audits()
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
            .collect();
    roots.network_fault_injection_roots = semantic            .network_fault_injections()
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
            .collect();
    roots.network_benchmark_roots = semantic            .network_benchmarks()
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
            .collect();
    roots.network_recovery_benchmark_roots = semantic            .network_recovery_benchmarks()
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
            .collect();
}
