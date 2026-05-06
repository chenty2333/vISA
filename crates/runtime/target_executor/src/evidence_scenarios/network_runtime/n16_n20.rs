use super::super::super::*;

pub(crate) fn record_network_runtime_n16_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let linux_socket_store = semantic
        .store_id("linux_socket_service")
        .ok_or("linux_socket_service store is missing for n16 evidence")?;
    let linux_socket_store_generation = semantic
        .store_handle(linux_socket_store)
        .map(|handle| handle.generation)
        .ok_or("linux_socket_service store handle is missing for n16 evidence")?;
    let connected_endpoint = ContractObjectRef::new(ContractObjectKind::EndpointObject, 10_032, 1);
    let commands = [
        CommandEnvelope::new(
            186,
            "target-executor-n16",
            SemanticCommand::CreateWait {
                wait: 10_049,
                owner_task: None,
                owner_store: Some(linux_socket_store),
                owner_store_generation: Some(linux_socket_store_generation),
                kind: SemanticWaitKind::SocketReadable,
                generation: 1,
                blockers: vec![connected_endpoint],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("n16-recv-would-block-before-driver-fault".to_owned()),
            },
        ),
        CommandEnvelope::new(
            187,
            "target-executor-n16",
            SemanticCommand::RecordSocketWait {
                socket_wait: 10_050,
                wait: 10_049,
                wait_generation: 1,
                endpoint: 10_032,
                endpoint_generation: 1,
                wait_kind: SemanticWaitKind::SocketReadable,
                blocker: connected_endpoint,
                note: "n16-record-pending-socket-wait-before-driver-cleanup".to_owned(),
            },
        ),
        CommandEnvelope::new(
            188,
            "target-executor-n16",
            SemanticCommand::CleanupNetworkDriver {
                cleanup: 10_051,
                io_cleanup: 10_052,
                adapter: 10_025,
                adapter_generation: 1,
                packet_device: 10_002,
                packet_device_generation: 1,
                backend: ContractObjectRef::new(
                    ContractObjectKind::VirtioNetBackendObject,
                    10_010,
                    1,
                ),
                reason: "device-fault".to_owned(),
                note: "n16-cleanup-virtio-net-driver-fault".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n16 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let stale_cleanup = semantic.apply_envelope(CommandEnvelope::new(
        189,
        "target-executor-n16",
        SemanticCommand::CleanupNetworkDriver {
            cleanup: 10_053,
            io_cleanup: 10_054,
            adapter: 10_025,
            adapter_generation: 2,
            packet_device: 10_002,
            packet_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 10_010, 1),
            reason: "device-fault".to_owned(),
            note: "n16-reject-stale-adapter-cleanup".to_owned(),
        },
    ));
    if stale_cleanup.status != CommandStatus::Rejected
        || !stale_cleanup
            .violations
            .iter()
            .any(|violation| violation.contains("adapter generation"))
    {
        return Err(format!(
            "network runtime n16 stale cleanup command {} ({}) was not rejected: status={} violations={:?}",
            stale_cleanup.command_id,
            stale_cleanup.command,
            stale_cleanup.status.as_str(),
            stale_cleanup.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_network_runtime_n19_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let benchmark = semantic.apply_envelope(CommandEnvelope::new(
        190,
        "target-executor-n19",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 10_067,
            scenario: "host-validation-network-throughput-latency".to_owned(),
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            tx_queue: 10_005,
            tx_queue_generation: 1,
            rx_queue: 10_004,
            rx_queue_generation: 1,
            tx_completion: 10_023,
            tx_completion_generation: 1,
            rx_wait_resolution: 10_017,
            rx_wait_resolution_generation: 1,
            endpoint: 10_032,
            endpoint_generation: 1,
            backpressure: Some(10_047),
            backpressure_generation: Some(1),
            sample_packets: 3,
            sample_bytes: 6000,
            tx_completed_packets: 1,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 120_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19-record-host-validation-network-throughput-latency-benchmark".to_owned(),
        },
    ));
    if benchmark.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n19 benchmark command {} ({}) failed: status={} violations={:?}",
            benchmark.command_id,
            benchmark.command,
            benchmark.status.as_str(),
            benchmark.violations
        )
        .into());
    }

    let stale_adapter = semantic.apply_envelope(CommandEnvelope::new(
        191,
        "target-executor-n19",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 10_068,
            scenario: "host-validation-network-throughput-latency".to_owned(),
            adapter: 10_025,
            adapter_generation: 2,
            packet_device: 10_002,
            packet_device_generation: 1,
            tx_queue: 10_005,
            tx_queue_generation: 1,
            rx_queue: 10_004,
            rx_queue_generation: 1,
            tx_completion: 10_023,
            tx_completion_generation: 1,
            rx_wait_resolution: 10_017,
            rx_wait_resolution_generation: 1,
            endpoint: 10_032,
            endpoint_generation: 1,
            backpressure: Some(10_047),
            backpressure_generation: Some(1),
            sample_packets: 3,
            sample_bytes: 6000,
            tx_completed_packets: 1,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 120_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19-reject-stale-adapter-generation".to_owned(),
        },
    ));
    if stale_adapter.status != CommandStatus::Rejected
        || !stale_adapter
            .violations
            .iter()
            .any(|violation| violation.contains("adapter generation"))
    {
        return Err(format!(
            "network runtime n19 stale adapter command {} ({}) was not rejected: status={} violations={:?}",
            stale_adapter.command_id,
            stale_adapter.command,
            stale_adapter.status.as_str(),
            stale_adapter.violations
        )
        .into());
    }

    let budget_overrun = semantic.apply_envelope(CommandEnvelope::new(
        192,
        "target-executor-n19",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 10_069,
            scenario: "host-validation-network-throughput-latency".to_owned(),
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            tx_queue: 10_005,
            tx_queue_generation: 1,
            rx_queue: 10_004,
            rx_queue_generation: 1,
            tx_completion: 10_023,
            tx_completion_generation: 1,
            rx_wait_resolution: 10_017,
            rx_wait_resolution_generation: 1,
            endpoint: 10_032,
            endpoint_generation: 1,
            backpressure: Some(10_047),
            backpressure_generation: Some(1),
            sample_packets: 3,
            sample_bytes: 6000,
            tx_completed_packets: 1,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 260_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19-reject-network-benchmark-over-budget".to_owned(),
        },
    ));
    if budget_overrun.status != CommandStatus::Rejected
        || !budget_overrun
            .violations
            .iter()
            .any(|violation| violation.contains("exceeds latency budget"))
    {
        return Err(format!(
            "network runtime n19 budget command {} ({}) was not rejected: status={} violations={:?}",
            budget_overrun.command_id,
            budget_overrun.command,
            budget_overrun.status.as_str(),
            budget_overrun.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_network_runtime_n20_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let cleanup = semantic
        .network_driver_cleanups()
        .iter()
        .find(|record| record.id == 10_051 && record.generation == 1)
        .cloned()
        .ok_or("network driver cleanup 10051@1 is missing for n20 evidence")?;
    let cleanup_complete_event = cleanup
        .completed_at_event
        .ok_or("network driver cleanup completion event is missing for n20 evidence")?;
    let cancelled_socket_waits = cleanup.cancelled_socket_waits.len() as u32;
    let revoked_packet_capabilities = cleanup.revoked_packet_capabilities.len() as u32;
    let benchmark = semantic.apply_envelope(CommandEnvelope::new(
        193,
        "target-executor-n20",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 10_068,
            scenario: "host-validation-network-driver-recovery".to_owned(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(10_064),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup_complete_event,
            cancelled_socket_waits,
            revoked_packet_capabilities,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            note: "n20-record-host-validation-network-recovery-benchmark".to_owned(),
        },
    ));
    if benchmark.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n20 recovery benchmark command {} ({}) failed: status={} violations={:?}",
            benchmark.command_id,
            benchmark.command,
            benchmark.status.as_str(),
            benchmark.violations
        )
        .into());
    }

    let stale_cleanup = semantic.apply_envelope(CommandEnvelope::new(
        194,
        "target-executor-n20",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 10_069,
            scenario: "stale cleanup generation cannot record recovery benchmark".to_owned(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation.saturating_add(1),
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(10_064),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup_complete_event,
            cancelled_socket_waits,
            revoked_packet_capabilities,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            note: "n20-reject-stale-cleanup-generation".to_owned(),
        },
    ));
    if stale_cleanup.status != CommandStatus::Rejected
        || !stale_cleanup
            .violations
            .iter()
            .any(|violation| violation.contains("cleanup generation"))
    {
        return Err(format!(
            "network runtime n20 stale cleanup command {} ({}) was not rejected: status={} violations={:?}",
            stale_cleanup.command_id,
            stale_cleanup.command,
            stale_cleanup.status.as_str(),
            stale_cleanup.violations
        )
        .into());
    }

    let budget_overrun = semantic.apply_envelope(CommandEnvelope::new(
        195,
        "target-executor-n20",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 10_069,
            scenario: "recovery budget overrun cannot record benchmark".to_owned(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(10_064),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup_complete_event,
            cancelled_socket_waits,
            revoked_packet_capabilities,
            recovery_nanos: 210_000,
            budget_nanos: 200_000,
            note: "n20-reject-recovery-budget-overrun".to_owned(),
        },
    ));
    if budget_overrun.status != CommandStatus::Rejected
        || !budget_overrun.violations.iter().any(|violation| violation.contains("recovery budget"))
    {
        return Err(format!(
            "network runtime n20 budget command {} ({}) was not rejected: status={} violations={:?}",
            budget_overrun.command_id,
            budget_overrun.command,
            budget_overrun.status.as_str(),
            budget_overrun.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_network_runtime_n17_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n17 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n17 evidence")?;

    let dma_resource =
        semantic.register_resource(ResourceKind::DmaBuffer, None, "dma:virtio-net0-tx-stale-probe");
    let dma_resource_generation = semantic
        .resource_handle(dma_resource)
        .map(|handle| handle.generation)
        .ok_or("n17 dma resource handle is missing")?;
    let dma_ref = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 10_057, 1);
    let dma_capability = semantic.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "dma.virtio-net0.tx-stale-probe",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma_ref),
        &["sync-for-device"],
        "store",
        "n17-dma-generation-capability",
        true,
    );
    let dma_handle = semantic
        .capabilities()
        .record(dma_capability)
        .and_then(|record| record.store_local_handle(vec!["sync-for-device".to_owned()]))
        .ok_or("n17 dma capability handle is missing")?;

    let setup_commands = [
        CommandEnvelope::new(
            170,
            "target-executor-n17",
            SemanticCommand::RecordQueueObject {
                queue: 10_055,
                name: "virtio-net0-tx-dma".to_owned(),
                role: QueueObjectRole::Tx,
                queue_index: 1,
                depth: 4,
                device: 10_001,
                device_generation: 1,
                note: "n17-record-dma-queue-fixture".to_owned(),
            },
        ),
        CommandEnvelope::new(
            171,
            "target-executor-n17",
            SemanticCommand::RecordDescriptorObject {
                descriptor: 10_056,
                queue: 10_055,
                queue_generation: 1,
                slot: 0,
                access: DescriptorObjectAccess::ReadWrite,
                length: 2048,
                note: "n17-record-dma-descriptor-fixture".to_owned(),
            },
        ),
        CommandEnvelope::new(
            172,
            "target-executor-n17",
            SemanticCommand::RecordDmaBufferObject {
                dma_buffer: 10_057,
                descriptor: 10_056,
                descriptor_generation: 1,
                resource: dma_resource,
                resource_generation: dma_resource_generation,
                access: DmaBufferObjectAccess::ReadWrite,
                length: 2048,
                note: "n17-record-dma-buffer-fixture".to_owned(),
            },
        ),
        CommandEnvelope::new(
            173,
            "target-executor-n17",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 10_058,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                target: dma_ref,
                class: CapabilityClass::DmaBuffer,
                operation: "sync-for-device".to_owned(),
                handle: dma_handle.clone(),
                note: "n17-record-dma-capability-fixture".to_owned(),
            },
        ),
    ];
    for command in setup_commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n17 setup command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let stale_packet_buffer = semantic.apply_envelope(CommandEnvelope::new(
        174,
        "target-executor-n17",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 10_059,
            packet_queue: 10_005,
            packet_queue_generation: 1,
            packet_buffer: 10_018,
            packet_buffer_generation: 2,
            slot: 1,
            length: 52,
            note: "n17-reject-stale-packet-buffer-generation".to_owned(),
        },
    ));
    if stale_packet_buffer.status != CommandStatus::Rejected
        || !stale_packet_buffer
            .violations
            .iter()
            .any(|violation| violation.contains("buffer generation"))
    {
        return Err(format!(
            "network runtime n17 stale packet buffer command {} ({}) was not rejected: status={} violations={:?}",
            stale_packet_buffer.command_id,
            stale_packet_buffer.command,
            stale_packet_buffer.status.as_str(),
            stale_packet_buffer.violations
        )
        .into());
    }

    let stale_packet_descriptor = semantic.apply_envelope(CommandEnvelope::new(
        175,
        "target-executor-n17",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 10_060,
            driver_store: virtio_driver_store,
            driver_store_generation: virtio_driver_store_generation,
            packet_descriptor: 10_019,
            packet_descriptor_generation: 2,
            device_capability: 10_020,
            device_capability_generation: 1,
            handle: semantic
                .device_capabilities()
                .iter()
                .find(|record| record.id == 10_020)
                .and_then(|record| semantic.capabilities().record(record.capability))
                .and_then(|record| record.store_local_handle(vec!["tx".to_owned()]))
                .ok_or("n17 packet tx capability handle is missing")?,
            note: "n17-reject-stale-packet-descriptor-generation".to_owned(),
        },
    ));
    if stale_packet_descriptor.status != CommandStatus::Rejected
        || !stale_packet_descriptor
            .violations
            .iter()
            .any(|violation| violation.contains("descriptor generation"))
    {
        return Err(format!(
            "network runtime n17 stale packet descriptor command {} ({}) was not rejected: status={} violations={:?}",
            stale_packet_descriptor.command_id,
            stale_packet_descriptor.command,
            stale_packet_descriptor.status.as_str(),
            stale_packet_descriptor.violations
        )
        .into());
    }

    let stale_dma_target = semantic.apply_envelope(CommandEnvelope::new(
        176,
        "target-executor-n17",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 10_061,
            driver_store: virtio_driver_store,
            driver_store_generation: virtio_driver_store_generation,
            target: ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 10_057, 2),
            class: CapabilityClass::DmaBuffer,
            operation: "sync-for-device".to_owned(),
            handle: dma_handle,
            note: "n17-reject-stale-dma-buffer-generation".to_owned(),
        },
    ));
    if stale_dma_target.status != CommandStatus::Rejected
        || !stale_dma_target
            .violations
            .iter()
            .any(|violation| violation.contains("target generation"))
    {
        return Err(format!(
            "network runtime n17 stale dma command {} ({}) was not rejected: status={} violations={:?}",
            stale_dma_target.command_id,
            stale_dma_target.command,
            stale_dma_target.status.as_str(),
            stale_dma_target.violations
        )
        .into());
    }

    let audit = semantic.apply_envelope(CommandEnvelope::new(
        177,
        "target-executor-n17",
        SemanticCommand::RecordNetworkGenerationAudit {
            audit: 10_062,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_005,
            packet_queue_generation: 1,
            packet_descriptor: 10_019,
            packet_descriptor_generation: 1,
            packet_buffer: 10_018,
            packet_buffer_generation: 1,
            dma_buffer: dma_ref,
            device_capability: ContractObjectRef::new(
                ContractObjectKind::DeviceCapability,
                10_058,
                1,
            ),
            rejected_packet_generation_probes: 2,
            rejected_dma_generation_probes: 1,
            note: "n17-record-stale-packet-dma-generation-audit".to_owned(),
        },
    ));
    if audit.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n17 audit command {} ({}) failed: status={} violations={:?}",
            audit.command_id,
            audit.command,
            audit.status.as_str(),
            audit.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_network_runtime_n18_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let packet_loss = semantic.apply_envelope(CommandEnvelope::new(
        182,
        "target-executor-n18",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 10_063,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_005,
            packet_queue_generation: 1,
            packet_descriptor: Some(10_019),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(10_018),
            packet_buffer_generation: Some(1),
            endpoint: Some(10_032),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketLoss,
            effect: NetworkFaultInjectionEffect::DropPacket,
            injected_packets: 1,
            dropped_packets: 1,
            error_packets: 0,
            error_code: String::new(),
            sequence: 18,
            note: "n18-inject-tx-packet-loss".to_owned(),
        },
    ));
    if packet_loss.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n18 packet loss command {} ({}) failed: status={} violations={:?}",
            packet_loss.command_id,
            packet_loss.command,
            packet_loss.status.as_str(),
            packet_loss.violations
        )
        .into());
    }

    let packet_error = semantic.apply_envelope(CommandEnvelope::new(
        183,
        "target-executor-n18",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 10_064,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_005,
            packet_queue_generation: 1,
            packet_descriptor: Some(10_019),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(10_018),
            packet_buffer_generation: Some(1),
            endpoint: Some(10_032),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketError,
            effect: NetworkFaultInjectionEffect::ReportError,
            injected_packets: 1,
            dropped_packets: 0,
            error_packets: 1,
            error_code: "injected-checksum-error".to_owned(),
            sequence: 19,
            note: "n18-inject-tx-packet-error".to_owned(),
        },
    ));
    if packet_error.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n18 packet error command {} ({}) failed: status={} violations={:?}",
            packet_error.command_id,
            packet_error.command,
            packet_error.status.as_str(),
            packet_error.violations
        )
        .into());
    }

    let stale_queue = semantic.apply_envelope(CommandEnvelope::new(
        184,
        "target-executor-n18",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 10_065,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_005,
            packet_queue_generation: 2,
            packet_descriptor: Some(10_019),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(10_018),
            packet_buffer_generation: Some(1),
            endpoint: Some(10_032),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketLoss,
            effect: NetworkFaultInjectionEffect::DropPacket,
            injected_packets: 1,
            dropped_packets: 1,
            error_packets: 0,
            error_code: String::new(),
            sequence: 20,
            note: "n18-reject-stale-queue-generation".to_owned(),
        },
    ));
    if stale_queue.status != CommandStatus::Rejected
        || !stale_queue
            .violations
            .iter()
            .any(|violation| violation.contains("packet queue generation"))
    {
        return Err(format!(
            "network runtime n18 stale queue command {} ({}) was not rejected: status={} violations={:?}",
            stale_queue.command_id,
            stale_queue.command,
            stale_queue.status.as_str(),
            stale_queue.violations
        )
        .into());
    }

    let malformed_error = semantic.apply_envelope(CommandEnvelope::new(
        185,
        "target-executor-n18",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 10_066,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_005,
            packet_queue_generation: 1,
            packet_descriptor: Some(10_019),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(10_018),
            packet_buffer_generation: Some(1),
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketError,
            effect: NetworkFaultInjectionEffect::ReportError,
            injected_packets: 1,
            dropped_packets: 0,
            error_packets: 1,
            error_code: "injected-checksum-error".to_owned(),
            sequence: 21,
            note: "n18-reject-malformed-packet-error-injection".to_owned(),
        },
    ));
    if malformed_error.status != CommandStatus::Rejected
        || !malformed_error
            .violations
            .iter()
            .any(|violation| violation.contains("packet error injection requires endpoint"))
    {
        return Err(format!(
            "network runtime n18 malformed error command {} ({}) was not rejected: status={} violations={:?}",
            malformed_error.command_id,
            malformed_error.command,
            malformed_error.status.as_str(),
            malformed_error.violations
        )
        .into());
    }

    Ok(())
}
