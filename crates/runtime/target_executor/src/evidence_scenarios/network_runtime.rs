use super::super::*;

pub(crate) fn record_network_runtime_n5_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n5 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n5 evidence")?;
    let virtio_device_ref = ContractObjectRef::new(ContractObjectKind::DeviceObject, 10_001, 1);
    let virtio_device_capability = semantic.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "device.virtio-net0",
        AuthorityObjectRef::internal(CapabilityClass::Device, virtio_device_ref),
        &["probe"],
        "store",
        "n5-virtio-net-device-capability",
        true,
    );
    let virtio_device_handle = semantic
        .capabilities()
        .record(virtio_device_capability)
        .and_then(|record| record.store_local_handle(vec!["probe".to_owned()]))
        .ok_or("n5 virtio net device capability handle is missing")?;
    let virtio_config = VirtioNetBackendConfig::net0();
    let commands = [
        CommandEnvelope::new(
            127,
            "target-executor-n5",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 10_008,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                target: virtio_device_ref,
                class: CapabilityClass::Device,
                operation: "probe".to_owned(),
                handle: virtio_device_handle,
                note: "n5-record-virtio-net-device-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            128,
            "target-executor-n5",
            SemanticCommand::BindDriverStore {
                binding: 10_009,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                device: 10_001,
                device_generation: 1,
                device_capability: 10_008,
                device_capability_generation: 1,
                note: "n5-bind-virtio-net-driver-store-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            129,
            "target-executor-n5",
            SemanticCommand::RecordVirtioNetBackendObject {
                virtio_net_backend: 10_010,
                name: "virtio-net0-backend".to_owned(),
                packet_device: 10_002,
                packet_device_generation: 1,
                driver_binding: 10_009,
                driver_binding_generation: 1,
                provider: VIRTIO_NET_BACKEND_PROVIDER.to_owned(),
                profile: VIRTIO_NET_BACKEND_PROFILE.to_owned(),
                model: VIRTIO_NET_BACKEND_MODEL.to_owned(),
                mtu: VIRTIO_NET0_CONTRACT.mtu,
                rx_queue_depth: VIRTIO_NET0_CONTRACT.rx_queue_depth,
                tx_queue_depth: VIRTIO_NET0_CONTRACT.tx_queue_depth,
                mac: VIRTIO_NET0_CONTRACT.mac,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                max_payload_len: PACKET_MAX_PAYLOAD_LEN,
                device_features: virtio_config.device_features,
                driver_features: virtio_config.driver_features,
                negotiated_features: virtio_config.negotiated_features,
                rx_queue_index: virtio_config.rx_queue_index,
                tx_queue_index: virtio_config.tx_queue_index,
                queue_size: virtio_config.queue_size,
                irq_vector: virtio_config.irq_vector,
                note: "n5-bind-virtio-net-backend-skeleton-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n5 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn record_network_runtime_n6_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n6 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n6 evidence")?;
    let irq_line_resource =
        semantic.register_resource(ResourceKind::IrqLine, None, "irq:virtio-net0-rx");
    let irq_line_resource_generation = semantic
        .resource_handle(irq_line_resource)
        .map(|handle| handle.generation)
        .ok_or("n6 virtio net irq line resource handle is missing")?;
    let irq_ref = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 10_011, 1);
    let irq_capability = semantic.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "irq.net0",
        AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq_ref),
        &["ack"],
        "store",
        "n6-virtio-net-rx-irq-capability",
        true,
    );
    let irq_handle = semantic
        .capabilities()
        .record(irq_capability)
        .and_then(|record| record.store_local_handle(vec!["ack".to_owned()]))
        .ok_or("n6 virtio net irq capability handle is missing")?;
    let commands = [
        CommandEnvelope::new(
            130,
            "target-executor-n6",
            SemanticCommand::RecordIrqLineObject {
                irq_line: 10_011,
                device: 10_001,
                device_generation: 1,
                resource: irq_line_resource,
                resource_generation: irq_line_resource_generation,
                irq_number: 5,
                trigger: IrqLineTrigger::Level,
                polarity: IrqLinePolarity::ActiveHigh,
                note: "n6-record-virtio-net-rx-irq-line-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            131,
            "target-executor-n6",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 10_012,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                target: irq_ref,
                class: CapabilityClass::IrqLine,
                operation: "ack".to_owned(),
                handle: irq_handle,
                note: "n6-record-virtio-net-rx-irq-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            132,
            "target-executor-n6",
            SemanticCommand::RecordIrqEvent {
                irq_event: 10_013,
                irq_line: 10_011,
                irq_line_generation: 1,
                device: 10_001,
                device_generation: 1,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                sequence: 1,
                note: "n6-record-virtio-net-rx-irq-event-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            133,
            "target-executor-n6",
            SemanticCommand::RecordNetworkRxInterrupt {
                rx_interrupt: 10_014,
                virtio_net_backend: 10_010,
                virtio_net_backend_generation: 1,
                irq_event: 10_013,
                irq_event_generation: 1,
                packet_device: 10_002,
                packet_device_generation: 1,
                rx_queue: 10_004,
                rx_queue_generation: 1,
                ready_descriptors: 1,
                sequence: 1,
                note: "n6-record-network-rx-interrupt-path-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n6 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn record_network_runtime_n7_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n7 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n7 evidence")?;
    let rx_queue_ref = ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 10_004, 1);
    let commands = [
        CommandEnvelope::new(
            134,
            "target-executor-n7",
            SemanticCommand::CreateWait {
                wait: 10_015,
                owner_task: None,
                owner_store: Some(virtio_driver_store),
                owner_store_generation: Some(virtio_driver_store_generation),
                kind: semantic_core::SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![rx_queue_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("driver_virtio_net:rx-queue-wait".to_owned()),
            },
        ),
        CommandEnvelope::new(
            135,
            "target-executor-n7",
            SemanticCommand::RecordIoWait {
                io_wait: 10_016,
                wait: 10_015,
                wait_generation: 1,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                device: 10_001,
                device_generation: 1,
                driver_binding: 10_009,
                driver_binding_generation: 1,
                blocker: rx_queue_ref,
                note: "n7-record-rx-queue-io-wait-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            136,
            "target-executor-n7",
            SemanticCommand::ResolveNetworkRxWait {
                resolution: 10_017,
                io_wait: 10_016,
                io_wait_generation: 1,
                rx_interrupt: 10_014,
                rx_interrupt_generation: 1,
                note: "n7-resolve-rx-wait-from-network-interrupt-harness".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n7 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn record_network_runtime_n8_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let virtio_driver_store = semantic
        .store_id("driver_virtio_net")
        .ok_or("driver_virtio_net store is missing for n8 evidence")?;
    let virtio_driver_store_generation = semantic
        .store_handle(virtio_driver_store)
        .map(|handle| handle.generation)
        .ok_or("driver_virtio_net store handle is missing for n8 evidence")?;
    let packet_device_ref =
        ContractObjectRef::new(ContractObjectKind::PacketDeviceObject, 10_002, 1);
    let packet_tx_capability = semantic.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "packet-device.net0",
        AuthorityObjectRef::internal(CapabilityClass::PacketDevice, packet_device_ref),
        &["tx"],
        "store",
        "n8-packet-device-tx-capability",
        true,
    );
    let packet_tx_handle = semantic
        .capabilities()
        .record(packet_tx_capability)
        .and_then(|record| record.store_local_handle(vec!["tx".to_owned()]))
        .ok_or("n8 packet tx capability handle is missing")?;
    let mut forged_tx_handle = packet_tx_handle.clone();
    forged_tx_handle.generation = forged_tx_handle.generation.saturating_add(1);
    let commands = [
        CommandEnvelope::new(
            137,
            "target-executor-n8",
            SemanticCommand::RecordPacketBufferObject {
                packet_buffer: 10_018,
                packet_device: 10_002,
                packet_device_generation: 1,
                direction: PacketBufferDirection::Tx,
                frame_format_version: PACKET_FRAME_FORMAT_VERSION,
                capacity: PACKET_MAX_PAYLOAD_LEN,
                payload_len: 52,
                sequence: 2,
                state: PacketBufferObjectState::Filled,
                note: "n8-record-tx-packet-buffer-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            138,
            "target-executor-n8",
            SemanticCommand::RecordPacketDescriptorObject {
                packet_descriptor: 10_019,
                packet_queue: 10_005,
                packet_queue_generation: 1,
                packet_buffer: 10_018,
                packet_buffer_generation: 1,
                slot: 0,
                length: 52,
                note: "n8-record-tx-packet-descriptor-object-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            139,
            "target-executor-n8",
            SemanticCommand::RecordDeviceCapability {
                device_capability: 10_020,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                target: packet_device_ref,
                class: CapabilityClass::PacketDevice,
                operation: "tx".to_owned(),
                handle: packet_tx_handle.clone(),
                note: "n8-record-packet-device-tx-capability-harness".to_owned(),
            },
        ),
        CommandEnvelope::new(
            140,
            "target-executor-n8",
            SemanticCommand::RecordNetworkTxCapabilityGate {
                tx_gate: 10_021,
                driver_store: virtio_driver_store,
                driver_store_generation: virtio_driver_store_generation,
                packet_descriptor: 10_019,
                packet_descriptor_generation: 1,
                device_capability: 10_020,
                device_capability_generation: 1,
                handle: packet_tx_handle,
                note: "n8-allow-tx-descriptor-through-packet-device-capability".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n8 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    let denied = semantic.apply_envelope(CommandEnvelope::new(
        141,
        "target-executor-n8",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 10_022,
            driver_store: virtio_driver_store,
            driver_store_generation: virtio_driver_store_generation,
            packet_descriptor: 10_019,
            packet_descriptor_generation: 1,
            device_capability: 10_020,
            device_capability_generation: 1,
            handle: forged_tx_handle,
            note: "n8-deny-forged-packet-device-tx-capability-handle".to_owned(),
        },
    ));
    if denied.status != CommandStatus::Rejected
        || !denied.violations.iter().any(|violation| violation.contains("handle"))
    {
        return Err(format!(
            "network runtime n8 forged tx capability command {} ({}) was not rejected: status={} violations={:?}",
            denied.command_id,
            denied.command,
            denied.status.as_str(),
            denied.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn record_network_runtime_n9_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 10_010, 1);
    let command = CommandEnvelope::new(
        142,
        "target-executor-n9",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 10_023,
            tx_gate: 10_021,
            tx_gate_generation: 1,
            backend,
            completion_sequence: 1,
            note: "n9-record-tx-completion-after-capability-gate".to_owned(),
        },
    );
    let result = semantic.apply_envelope(command);
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n9 evidence command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        143,
        "target-executor-n9",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 10_024,
            tx_gate: 10_021,
            tx_gate_generation: 1,
            backend,
            completion_sequence: 2,
            note: "n9-reject-duplicate-tx-completion-for-gate".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate.violations.iter().any(|violation| violation.contains("already completed"))
    {
        return Err(format!(
            "network runtime n9 duplicate tx completion command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn record_network_runtime_n10_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let evidence = build_smoltcp_adapter_evidence(SmoltcpAdapterConfig::default_vmos())
        .map_err(|err| format!("network runtime n10 smoltcp adapter evidence failed: {err}"))?;
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 10_010, 1);
    let command = CommandEnvelope::new(
        144,
        "target-executor-n10",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 10_025,
            backend,
            packet_device: 10_002,
            packet_device_generation: 1,
            rx_queue: 10_004,
            rx_queue_generation: 1,
            tx_queue: 10_005,
            tx_queue_generation: 1,
            implementation: evidence.implementation.to_owned(),
            implementation_version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            medium: evidence.medium.to_owned(),
            mac: evidence.hardware_addr,
            ipv4_addr: evidence.ipv4_addr,
            ipv4_prefix_len: evidence.ipv4_prefix_len,
            mtu: evidence.mtu,
            rx_queue_depth: evidence.rx_queue_depth,
            tx_queue_depth: evidence.tx_queue_depth,
            max_payload_len: evidence.max_payload_len,
            socket_capacity: evidence.socket_capacity,
            note: "n10-bind-smoltcp-adapter-to-packet-device".to_owned(),
        },
    );
    let result = semantic.apply_envelope(command);
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n10 evidence command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        145,
        "target-executor-n10",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 10_026,
            backend,
            packet_device: 10_002,
            packet_device_generation: 1,
            rx_queue: 10_004,
            rx_queue_generation: 1,
            tx_queue: 10_005,
            tx_queue_generation: 1,
            implementation: evidence.implementation.to_owned(),
            implementation_version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            medium: evidence.medium.to_owned(),
            mac: evidence.hardware_addr,
            ipv4_addr: evidence.ipv4_addr,
            ipv4_prefix_len: evidence.ipv4_prefix_len,
            mtu: evidence.mtu,
            rx_queue_depth: evidence.rx_queue_depth,
            tx_queue_depth: evidence.tx_queue_depth,
            max_payload_len: evidence.max_payload_len,
            socket_capacity: evidence.socket_capacity,
            note: "n10-reject-duplicate-smoltcp-adapter".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate.violations.iter().any(|violation| violation.contains("already bound"))
    {
        return Err(format!(
            "network runtime n10 duplicate adapter command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn record_network_runtime_n11_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let linux_socket_store = semantic
        .store_id("linux_socket_service")
        .ok_or("linux_socket_service store is missing for n11 evidence")?;
    let linux_socket_store_generation = semantic
        .store_handle(linux_socket_store)
        .map(|handle| handle.generation)
        .ok_or("linux_socket_service store handle is missing for n11 evidence")?;
    let command = CommandEnvelope::new(
        146,
        "target-executor-n11",
        SemanticCommand::RecordSocketObject {
            socket: 10_027,
            adapter: 10_025,
            adapter_generation: 1,
            owner_store: linux_socket_store,
            owner_store_generation: linux_socket_store_generation,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            note: "n11-record-linux-inet-stream-socket-object".to_owned(),
        },
    );
    let result = semantic.apply_envelope(command);
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n11 evidence command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }

    let stale_adapter = semantic.apply_envelope(CommandEnvelope::new(
        147,
        "target-executor-n11",
        SemanticCommand::RecordSocketObject {
            socket: 10_028,
            adapter: 10_025,
            adapter_generation: 2,
            owner_store: linux_socket_store,
            owner_store_generation: linux_socket_store_generation,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            note: "n11-reject-stale-socket-adapter-generation".to_owned(),
        },
    ));
    if stale_adapter.status != CommandStatus::Rejected
        || !stale_adapter
            .violations
            .iter()
            .any(|violation| violation.contains("adapter generation"))
    {
        return Err(format!(
            "network runtime n11 stale adapter command {} ({}) was not rejected: status={} violations={:?}",
            stale_adapter.command_id,
            stale_adapter.command,
            stale_adapter.status.as_str(),
            stale_adapter.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn record_network_runtime_n12_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let command = CommandEnvelope::new(
        148,
        "target-executor-n12",
        SemanticCommand::RecordEndpointObject {
            endpoint: 10_029,
            socket: 10_027,
            socket_generation: 1,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12-record-unbound-inet-tcp-endpoint-object".to_owned(),
        },
    );
    let result = semantic.apply_envelope(command);
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "network runtime n12 evidence command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }

    let stale_socket = semantic.apply_envelope(CommandEnvelope::new(
        149,
        "target-executor-n12",
        SemanticCommand::RecordEndpointObject {
            endpoint: 10_030,
            socket: 10_027,
            socket_generation: 2,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12-reject-stale-endpoint-socket-generation".to_owned(),
        },
    ));
    if stale_socket.status != CommandStatus::Rejected
        || !stale_socket.violations.iter().any(|violation| violation.contains("socket generation"))
    {
        return Err(format!(
            "network runtime n12 stale socket command {} ({}) was not rejected: status={} violations={:?}",
            stale_socket.command_id,
            stale_socket.command,
            stale_socket.status.as_str(),
            stale_socket.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn record_network_runtime_n13_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let linux_socket_store = semantic
        .store_id("linux_socket_service")
        .ok_or("linux_socket_service store is missing for n13 evidence")?;
    let linux_socket_store_generation = semantic
        .store_handle(linux_socket_store)
        .map(|handle| handle.generation)
        .ok_or("linux_socket_service store handle is missing for n13 evidence")?;

    let commands = [
        CommandEnvelope::new(
            150,
            "target-executor-n13",
            SemanticCommand::RecordSocketObject {
                socket: 10_031,
                adapter: 10_025,
                adapter_generation: 1,
                owner_store: linux_socket_store,
                owner_store_generation: linux_socket_store_generation,
                domain: 2,
                socket_type: 1,
                protocol: 0,
                note: "n13-record-connected-inet-stream-socket-object".to_owned(),
            },
        ),
        CommandEnvelope::new(
            151,
            "target-executor-n13",
            SemanticCommand::RecordEndpointObject {
                endpoint: 10_032,
                socket: 10_031,
                socket_generation: 1,
                local_addr: [0, 0, 0, 0],
                local_port: 0,
                remote_addr: [0, 0, 0, 0],
                remote_port: 0,
                note: "n13-record-connected-endpoint-object".to_owned(),
            },
        ),
        CommandEnvelope::new(
            152,
            "target-executor-n13",
            SemanticCommand::BindSocketEndpoint {
                operation_id: 10_033,
                endpoint: 10_029,
                endpoint_generation: 1,
                local_addr: [10, 0, 2, 15],
                local_port: 8080,
                sequence: 1,
                note: "n13-bind-listening-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            153,
            "target-executor-n13",
            SemanticCommand::ListenSocketEndpoint {
                operation_id: 10_034,
                endpoint: 10_029,
                endpoint_generation: 1,
                backlog: 16,
                sequence: 2,
                note: "n13-listen-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            154,
            "target-executor-n13",
            SemanticCommand::BindSocketEndpoint {
                operation_id: 10_035,
                endpoint: 10_032,
                endpoint_generation: 1,
                local_addr: [10, 0, 2, 15],
                local_port: 40000,
                sequence: 1,
                note: "n13-bind-connected-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            155,
            "target-executor-n13",
            SemanticCommand::ConnectSocketEndpoint {
                operation_id: 10_036,
                endpoint: 10_032,
                endpoint_generation: 1,
                remote_addr: [10, 0, 2, 2],
                remote_port: 80,
                sequence: 2,
                note: "n13-connect-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            156,
            "target-executor-n13",
            SemanticCommand::SendSocket {
                operation_id: 10_037,
                endpoint: 10_032,
                endpoint_generation: 1,
                byte_len: 18,
                sequence: 3,
                note: "n13-send-socket".to_owned(),
            },
        ),
        CommandEnvelope::new(
            157,
            "target-executor-n13",
            SemanticCommand::RecvSocket {
                operation_id: 10_038,
                endpoint: 10_032,
                endpoint_generation: 1,
                byte_len: 19,
                sequence: 4,
                note: "n13-recv-socket".to_owned(),
            },
        ),
    ];

    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n13 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let invalid_send = semantic.apply_envelope(CommandEnvelope::new(
        158,
        "target-executor-n13",
        SemanticCommand::SendSocket {
            operation_id: 10_039,
            endpoint: 10_029,
            endpoint_generation: 1,
            byte_len: 1,
            sequence: 3,
            note: "n13-reject-send-on-listening-endpoint".to_owned(),
        },
    ));
    if invalid_send.status != CommandStatus::Rejected
        || !invalid_send.violations.iter().any(|violation| violation.contains("connected endpoint"))
    {
        return Err(format!(
            "network runtime n13 invalid send command {} ({}) was not rejected: status={} violations={:?}",
            invalid_send.command_id,
            invalid_send.command,
            invalid_send.status.as_str(),
            invalid_send.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_network_runtime_n14_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let linux_socket_store = semantic
        .store_id("linux_socket_service")
        .ok_or("linux_socket_service store is missing for n14 evidence")?;
    let linux_socket_store_generation = semantic
        .store_handle(linux_socket_store)
        .map(|handle| handle.generation)
        .ok_or("linux_socket_service store handle is missing for n14 evidence")?;
    let connected_endpoint = ContractObjectRef::new(ContractObjectKind::EndpointObject, 10_032, 1);
    let listening_endpoint = ContractObjectRef::new(ContractObjectKind::EndpointObject, 10_029, 1);

    let commands = [
        CommandEnvelope::new(
            159,
            "target-executor-n14",
            SemanticCommand::CreateWait {
                wait: 10_040,
                owner_task: None,
                owner_store: Some(linux_socket_store),
                owner_store_generation: Some(linux_socket_store_generation),
                kind: SemanticWaitKind::SocketReadable,
                generation: 1,
                blockers: vec![connected_endpoint],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("recv-would-block".to_owned()),
            },
        ),
        CommandEnvelope::new(
            160,
            "target-executor-n14",
            SemanticCommand::RecordSocketWait {
                socket_wait: 10_041,
                wait: 10_040,
                wait_generation: 1,
                endpoint: 10_032,
                endpoint_generation: 1,
                wait_kind: SemanticWaitKind::SocketReadable,
                blocker: connected_endpoint,
                note: "n14-record-readable-wait-on-connected-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            161,
            "target-executor-n14",
            SemanticCommand::ResolveSocketWait {
                socket_wait: 10_041,
                socket_wait_generation: 1,
                ready_sequence: 1,
                byte_len: 19,
                note: "n14-resolve-readable-wait".to_owned(),
            },
        ),
        CommandEnvelope::new(
            162,
            "target-executor-n14",
            SemanticCommand::CreateWait {
                wait: 10_042,
                owner_task: None,
                owner_store: Some(linux_socket_store),
                owner_store_generation: Some(linux_socket_store_generation),
                kind: SemanticWaitKind::SocketAccept,
                generation: 1,
                blockers: vec![listening_endpoint],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("accept-would-block".to_owned()),
            },
        ),
        CommandEnvelope::new(
            163,
            "target-executor-n14",
            SemanticCommand::RecordSocketWait {
                socket_wait: 10_043,
                wait: 10_042,
                wait_generation: 1,
                endpoint: 10_029,
                endpoint_generation: 1,
                wait_kind: SemanticWaitKind::SocketAccept,
                blocker: listening_endpoint,
                note: "n14-record-accept-wait-on-listening-endpoint".to_owned(),
            },
        ),
        CommandEnvelope::new(
            164,
            "target-executor-n14",
            SemanticCommand::CancelSocketWait {
                socket_wait: 10_043,
                socket_wait_generation: 1,
                errno: 9,
                reason: semantic_core::WaitCancelReason::CloseFd,
                note: "n14-cancel-accept-wait-on-close".to_owned(),
            },
        ),
    ];

    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n14 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let stale_wait = semantic.apply_envelope(CommandEnvelope::new(
        165,
        "target-executor-n14",
        SemanticCommand::RecordSocketWait {
            socket_wait: 10_044,
            wait: 10_040,
            wait_generation: 1,
            endpoint: 10_032,
            endpoint_generation: 1,
            wait_kind: SemanticWaitKind::SocketReadable,
            blocker: connected_endpoint,
            note: "n14-reject-record-socket-wait-on-resolved-token".to_owned(),
        },
    ));
    if stale_wait.status != CommandStatus::Rejected
        || !stale_wait.violations.iter().any(|violation| violation.contains("not pending"))
    {
        return Err(format!(
            "network runtime n14 stale wait command {} ({}) was not rejected: status={} violations={:?}",
            stale_wait.command_id,
            stale_wait.command,
            stale_wait.status.as_str(),
            stale_wait.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_linux_wait_service_d1_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let epoll_store = semantic_store_id(semantic, "epoll_service")?;
    let epoll_store_generation = semantic
        .store_handle(epoll_store)
        .map(|handle| handle.generation)
        .ok_or("epoll_service store handle is missing for d1 evidence")?;
    let futex_store = semantic_store_id(semantic, "futex_service")?;
    let futex_store_generation = semantic
        .store_handle(futex_store)
        .map(|handle| handle.generation)
        .ok_or("futex_service store handle is missing for d1 evidence")?;
    semantic_capability_ref(semantic, "epoll_service", "epoll.instance", "create")?;
    semantic_capability_ref(semantic, "epoll_service", "epoll.instance", "ctl")?;
    semantic_capability_ref(semantic, "epoll_service", "epoll.instance", "wait")?;
    semantic_capability_ref(semantic, "futex_service", "futex.waitset", "wait")?;
    let epoll_service_ref = semantic_store_resource_ref(semantic, epoll_store)?;
    let futex_service_ref = semantic_store_resource_ref(semantic, futex_store)?;

    let commands = vec![
        CommandEnvelope::new(
            270,
            "target-executor-d1",
            SemanticCommand::CreateWait {
                wait: 30_001,
                owner_task: None,
                owner_store: Some(epoll_store),
                owner_store_generation: Some(epoll_store_generation),
                kind: SemanticWaitKind::Epoll,
                generation: 1,
                blockers: vec![epoll_service_ref],
                deadline: Some(250),
                restart_policy: RestartPolicy::RestartWithAdjustedTimeout,
                saved_context: Some("linux-wait-service:epoll_wait:pending".to_owned()),
            },
        ),
        CommandEnvelope::new(
            271,
            "target-executor-d1",
            SemanticCommand::CreateWait {
                wait: 30_002,
                owner_task: None,
                owner_store: Some(epoll_store),
                owner_store_generation: Some(epoll_store_generation),
                kind: SemanticWaitKind::Epoll,
                generation: 1,
                blockers: vec![epoll_service_ref],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("linux-wait-service:epoll_wait:resume-ready".to_owned()),
            },
        ),
        CommandEnvelope::new(
            272,
            "target-executor-d1",
            SemanticCommand::ResolveWait { wait: 30_002, reason: "epoll-ready".to_owned() },
        ),
        CommandEnvelope::new(
            273,
            "target-executor-d1",
            SemanticCommand::CreateWait {
                wait: 30_003,
                owner_task: None,
                owner_store: Some(epoll_store),
                owner_store_generation: Some(epoll_store_generation),
                kind: SemanticWaitKind::Epoll,
                generation: 1,
                blockers: vec![epoll_service_ref],
                deadline: Some(500),
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("linux-wait-service:epoll_wait:cancel-signal".to_owned()),
            },
        ),
        CommandEnvelope::new(
            274,
            "target-executor-d1",
            SemanticCommand::CancelWait {
                wait: 30_003,
                errno: 4,
                reason: WaitCancelReason::Signal,
            },
        ),
        CommandEnvelope::new(
            275,
            "target-executor-d1",
            SemanticCommand::CreateWait {
                wait: 30_004,
                owner_task: None,
                owner_store: Some(epoll_store),
                owner_store_generation: Some(epoll_store_generation),
                kind: SemanticWaitKind::Epoll,
                generation: 1,
                blockers: vec![epoll_service_ref],
                deadline: Some(750),
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("linux-wait-service:epoll_wait:restart-driver".to_owned()),
            },
        ),
        CommandEnvelope::new(
            276,
            "target-executor-d1",
            SemanticCommand::CreateWait {
                wait: 30_005,
                owner_task: None,
                owner_store: Some(futex_store),
                owner_store_generation: Some(futex_store_generation),
                kind: SemanticWaitKind::Futex,
                generation: 1,
                blockers: vec![futex_service_ref],
                deadline: Some(1_000),
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("linux-wait-service:futex_wait:pending".to_owned()),
            },
        ),
        CommandEnvelope::new(
            277,
            "target-executor-d1",
            SemanticCommand::CreateWait {
                wait: 30_006,
                owner_task: None,
                owner_store: Some(futex_store),
                owner_store_generation: Some(futex_store_generation),
                kind: SemanticWaitKind::Futex,
                generation: 1,
                blockers: vec![futex_service_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("linux-wait-service:futex_wait:wake-resume".to_owned()),
            },
        ),
        CommandEnvelope::new(
            278,
            "target-executor-d1",
            SemanticCommand::ResolveWait { wait: 30_006, reason: "futex-wake".to_owned() },
        ),
        CommandEnvelope::new(
            279,
            "target-executor-d1",
            SemanticCommand::CreateWait {
                wait: 30_007,
                owner_task: None,
                owner_store: Some(futex_store),
                owner_store_generation: Some(futex_store_generation),
                kind: SemanticWaitKind::Futex,
                generation: 1,
                blockers: vec![futex_service_ref],
                deadline: Some(1_250),
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("linux-wait-service:futex_wait:timeout-cancel".to_owned()),
            },
        ),
        CommandEnvelope::new(
            280,
            "target-executor-d1",
            SemanticCommand::CancelWait {
                wait: 30_007,
                errno: 110,
                reason: WaitCancelReason::Timeout,
            },
        ),
    ];

    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "linux wait service d1 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    semantic.record_wait_consumed(30_002);
    semantic.record_wait_restarted(30_004, "driver-restart");
    Ok(())
}

pub(crate) fn record_network_runtime_n15_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let commands = [
        CommandEnvelope::new(
            166,
            "target-executor-n15",
            SemanticCommand::RecordNetworkBackpressure {
                backpressure: 10_045,
                adapter: 10_025,
                adapter_generation: 1,
                packet_device: 10_002,
                packet_device_generation: 1,
                packet_queue: 10_004,
                packet_queue_generation: 1,
                endpoint: None,
                endpoint_generation: None,
                direction: PacketBufferDirection::Rx,
                reason: NetworkBackpressureReason::QueueHighWatermark,
                action: NetworkBackpressureAction::ThrottleProducer,
                queue_depth: 4,
                queue_limit: 4,
                dropped_packets: 0,
                dropped_bytes: 0,
                sequence: 1,
                note: "n15-rx-high-watermark-throttle-producer".to_owned(),
            },
        ),
        CommandEnvelope::new(
            167,
            "target-executor-n15",
            SemanticCommand::RecordNetworkBackpressure {
                backpressure: 10_046,
                adapter: 10_025,
                adapter_generation: 1,
                packet_device: 10_002,
                packet_device_generation: 1,
                packet_queue: 10_005,
                packet_queue_generation: 1,
                endpoint: Some(10_032),
                endpoint_generation: Some(1),
                direction: PacketBufferDirection::Tx,
                reason: NetworkBackpressureReason::QueueFull,
                action: NetworkBackpressureAction::RejectSend,
                queue_depth: 4,
                queue_limit: 4,
                dropped_packets: 0,
                dropped_bytes: 0,
                sequence: 2,
                note: "n15-tx-queue-full-reject-send".to_owned(),
            },
        ),
        CommandEnvelope::new(
            168,
            "target-executor-n15",
            SemanticCommand::RecordNetworkBackpressure {
                backpressure: 10_047,
                adapter: 10_025,
                adapter_generation: 1,
                packet_device: 10_002,
                packet_device_generation: 1,
                packet_queue: 10_004,
                packet_queue_generation: 1,
                endpoint: None,
                endpoint_generation: None,
                direction: PacketBufferDirection::Rx,
                reason: NetworkBackpressureReason::QueueFull,
                action: NetworkBackpressureAction::DropNewest,
                queue_depth: 5,
                queue_limit: 4,
                dropped_packets: 1,
                dropped_bytes: 1514,
                sequence: 3,
                note: "n15-rx-queue-full-drop-newest".to_owned(),
            },
        ),
    ];

    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "network runtime n15 evidence command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }

    let invalid_drop = semantic.apply_envelope(CommandEnvelope::new(
        169,
        "target-executor-n15",
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 10_048,
            adapter: 10_025,
            adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            packet_queue: 10_004,
            packet_queue_generation: 1,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Rx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::DropNewest,
            queue_depth: 5,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 1514,
            sequence: 4,
            note: "n15-reject-drop-without-packet-count".to_owned(),
        },
    ));
    if invalid_drop.status != CommandStatus::Rejected
        || !invalid_drop.violations.iter().any(|violation| violation.contains("drop action"))
    {
        return Err(format!(
            "network runtime n15 invalid drop command {} ({}) was not rejected: status={} violations={:?}",
            invalid_drop.command_id,
            invalid_drop.command,
            invalid_drop.status.as_str(),
            invalid_drop.violations
        )
        .into());
    }

    Ok(())
}

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
