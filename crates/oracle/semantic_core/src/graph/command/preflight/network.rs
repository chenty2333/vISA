use super::*;

impl SemanticGraph {
    pub(super) fn preflight_network_command(
        &self,
        command: &SemanticCommand,
    ) -> Result<(), CommandError> {
        match command {
            SemanticCommand::RecordVirtioNetBackendObject {
                virtio_net_backend,
                name,
                packet_device,
                packet_device_generation,
                driver_binding,
                driver_binding_generation,
                provider,
                profile,
                model,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                device_features,
                driver_features,
                negotiated_features,
                rx_queue_index,
                tx_queue_index,
                queue_size,
                irq_vector,
                ..
            } => self
                .validate_virtio_net_backend_object(
                    *virtio_net_backend,
                    name,
                    *packet_device,
                    *packet_device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    provider,
                    profile,
                    model,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *mac,
                    *frame_format_version,
                    *max_payload_len,
                    *device_features,
                    *driver_features,
                    *negotiated_features,
                    *rx_queue_index,
                    *tx_queue_index,
                    *queue_size,
                    *irq_vector,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkRxInterrupt {
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
                ..
            } => self
                .validate_network_rx_interrupt(
                    *rx_interrupt,
                    *virtio_net_backend,
                    *virtio_net_backend_generation,
                    *irq_event,
                    *irq_event_generation,
                    *packet_device,
                    *packet_device_generation,
                    *rx_queue,
                    *rx_queue_generation,
                    *ready_descriptors,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveNetworkRxWait {
                resolution,
                io_wait,
                io_wait_generation,
                rx_interrupt,
                rx_interrupt_generation,
                ..
            } => self
                .validate_network_rx_wait_resolution(
                    *resolution,
                    *io_wait,
                    *io_wait_generation,
                    *rx_interrupt,
                    *rx_interrupt_generation,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkTxCapabilityGate {
                tx_gate,
                driver_store,
                driver_store_generation,
                packet_descriptor,
                packet_descriptor_generation,
                device_capability,
                device_capability_generation,
                handle,
                ..
            } => self
                .validate_network_tx_capability_gate(
                    *tx_gate,
                    *driver_store,
                    *driver_store_generation,
                    *packet_descriptor,
                    *packet_descriptor_generation,
                    *device_capability,
                    *device_capability_generation,
                    handle,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkTxCompletion {
                completion,
                tx_gate,
                tx_gate_generation,
                backend,
                completion_sequence,
                ..
            } => self
                .validate_network_tx_completion(
                    *completion,
                    *tx_gate,
                    *tx_gate_generation,
                    *backend,
                    *completion_sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkStackAdapter {
                adapter,
                backend,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                tx_queue,
                tx_queue_generation,
                implementation,
                implementation_version,
                profile,
                medium,
                mac,
                ipv4_addr,
                ipv4_prefix_len,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                max_payload_len,
                socket_capacity,
                ..
            } => self
                .validate_network_stack_adapter(
                    *adapter,
                    *backend,
                    *packet_device,
                    *packet_device_generation,
                    *rx_queue,
                    *rx_queue_generation,
                    *tx_queue,
                    *tx_queue_generation,
                    implementation,
                    implementation_version,
                    profile,
                    medium,
                    *mac,
                    *ipv4_addr,
                    *ipv4_prefix_len,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *max_payload_len,
                    *socket_capacity,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSocketObject {
                socket,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                domain,
                socket_type,
                protocol,
                ..
            } => self
                .validate_socket_object(
                    *socket,
                    *adapter,
                    *adapter_generation,
                    *owner_store,
                    *owner_store_generation,
                    *domain,
                    *socket_type,
                    *protocol,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordEndpointObject {
                endpoint,
                socket,
                socket_generation,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                ..
            } => self
                .validate_endpoint_object(
                    *endpoint,
                    *socket,
                    *socket_generation,
                    *local_addr,
                    *local_port,
                    *remote_addr,
                    *remote_port,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::BindSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                local_addr,
                local_port,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Bind,
                    *local_addr,
                    *local_port,
                    [0, 0, 0, 0],
                    0,
                    0,
                    0,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ListenSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                backlog,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Listen,
                    [0, 0, 0, 0],
                    0,
                    [0, 0, 0, 0],
                    0,
                    *backlog,
                    0,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ConnectSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                remote_addr,
                remote_port,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Connect,
                    [0, 0, 0, 0],
                    0,
                    *remote_addr,
                    *remote_port,
                    0,
                    0,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::SendSocket {
                operation_id,
                endpoint,
                endpoint_generation,
                byte_len,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Send,
                    [0, 0, 0, 0],
                    0,
                    [0, 0, 0, 0],
                    0,
                    0,
                    *byte_len,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecvSocket {
                operation_id,
                endpoint,
                endpoint_generation,
                byte_len,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Recv,
                    [0, 0, 0, 0],
                    0,
                    [0, 0, 0, 0],
                    0,
                    0,
                    *byte_len,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSocketWait {
                socket_wait,
                wait,
                wait_generation,
                endpoint,
                endpoint_generation,
                wait_kind,
                blocker,
                ..
            } => self
                .validate_socket_wait(
                    *socket_wait,
                    *wait,
                    *wait_generation,
                    *endpoint,
                    *endpoint_generation,
                    *wait_kind,
                    *blocker,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveSocketWait {
                socket_wait,
                socket_wait_generation,
                ready_sequence,
                byte_len,
                ..
            } => {
                if self.domains.network.socket_waits.iter().any(|record| {
                    record.id == *socket_wait
                        && record.generation == *socket_wait_generation
                        && record.state == SocketWaitState::Pending
                        && *ready_sequence > 0
                        && (!matches!(record.wait_kind, SemanticWaitKind::SocketReadable)
                            || *byte_len > 0)
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "socket wait is not pending or readiness is empty",
                    ))
                }
            }
            SemanticCommand::CancelSocketWait {
                socket_wait,
                socket_wait_generation,
                reason,
                ..
            } => {
                if self.domains.network.socket_waits.iter().any(|record| {
                    record.id == *socket_wait
                        && record.generation == *socket_wait_generation
                        && record.state == SocketWaitState::Pending
                }) && matches!(
                    reason,
                    WaitCancelReason::CloseFd
                        | WaitCancelReason::StoreFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::DeviceFault
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "socket wait is not pending or cancel reason is not socket-visible",
                    ))
                }
            }
            SemanticCommand::RecordNetworkBackpressure {
                backpressure,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                endpoint,
                endpoint_generation,
                direction,
                reason,
                action,
                queue_depth,
                queue_limit,
                dropped_packets,
                dropped_bytes,
                sequence,
                ..
            } => self
                .validate_network_backpressure(
                    *backpressure,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *packet_queue,
                    *packet_queue_generation,
                    *endpoint,
                    *endpoint_generation,
                    *direction,
                    *reason,
                    *action,
                    *queue_depth,
                    *queue_limit,
                    *dropped_packets,
                    *dropped_bytes,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::CleanupNetworkDriver {
                cleanup,
                io_cleanup,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                backend,
                reason,
                ..
            } => self
                .validate_network_driver_cleanup(
                    *cleanup,
                    *io_cleanup,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *backend,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkGenerationAudit {
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
                ..
            } => self
                .validate_network_generation_audit(
                    *audit,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *packet_queue,
                    *packet_queue_generation,
                    *packet_descriptor,
                    *packet_descriptor_generation,
                    *packet_buffer,
                    *packet_buffer_generation,
                    *dma_buffer,
                    *device_capability,
                    *rejected_packet_generation_probes,
                    *rejected_dma_generation_probes,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkFaultInjection {
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
                direction,
                kind,
                effect,
                injected_packets,
                dropped_packets,
                error_packets,
                error_code,
                sequence,
                ..
            } => self
                .validate_network_fault_injection(
                    *injection,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *packet_queue,
                    *packet_queue_generation,
                    *packet_descriptor,
                    *packet_descriptor_generation,
                    *packet_buffer,
                    *packet_buffer_generation,
                    *endpoint,
                    *endpoint_generation,
                    *direction,
                    *kind,
                    *effect,
                    *injected_packets,
                    *dropped_packets,
                    *error_packets,
                    error_code,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkBenchmark {
                benchmark,
                scenario,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                rx_queue,
                rx_queue_generation,
                tx_completion,
                tx_completion_generation,
                rx_wait_resolution,
                rx_wait_resolution_generation,
                endpoint,
                endpoint_generation,
                backpressure,
                backpressure_generation,
                sample_packets,
                sample_bytes,
                tx_completed_packets,
                rx_resolved_packets,
                dropped_packets,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                ..
            } => self
                .validate_network_benchmark(
                    *benchmark,
                    scenario,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *tx_queue,
                    *tx_queue_generation,
                    *rx_queue,
                    *rx_queue_generation,
                    *tx_completion,
                    *tx_completion_generation,
                    *rx_wait_resolution,
                    *rx_wait_resolution_generation,
                    *endpoint,
                    *endpoint_generation,
                    *backpressure,
                    *backpressure_generation,
                    *sample_packets,
                    *sample_bytes,
                    *tx_completed_packets,
                    *rx_resolved_packets,
                    *dropped_packets,
                    *measured_nanos,
                    *budget_nanos,
                    *p50_latency_nanos,
                    *p99_latency_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkRecoveryBenchmark {
                benchmark,
                scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                fault_injection,
                fault_injection_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                recovery_nanos,
                budget_nanos,
                ..
            } => self
                .validate_network_recovery_benchmark(
                    *benchmark,
                    scenario,
                    *cleanup,
                    *cleanup_generation,
                    *io_cleanup,
                    *io_cleanup_generation,
                    *fault_injection,
                    *fault_injection_generation,
                    *recovery_start_event,
                    *recovery_complete_event,
                    *cancelled_socket_waits,
                    *revoked_packet_capabilities,
                    *recovery_nanos,
                    *budget_nanos,
                )
                .map_err(CommandError::precondition),
            _ => unreachable!("preflight handler called with wrong command domain"),
        }
    }
}
