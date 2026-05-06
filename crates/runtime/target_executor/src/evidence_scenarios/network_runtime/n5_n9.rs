use super::super::super::*;

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
