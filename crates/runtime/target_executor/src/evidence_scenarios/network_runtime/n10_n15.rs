use super::super::super::*;

pub(crate) fn record_network_runtime_n10_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let evidence = build_smoltcp_adapter_evidence(SmoltcpAdapterConfig::default_visa())
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
