use super::*;

pub(in crate::tests) fn x0_integrated_smp_preemption_cleanup_graph() -> SemanticGraph {
    let mut graph = s15_stress_graph(true);
    assert!(graph.record_smp_stress_run_with_id(
        191,
        "s15-smp-stress-property",
        3,
        6,
        "smp-stress-property-tests",
        "stress run",
    ));
    graph.ensure_task(88, FrontendKind::LinuxElf, "x0-preempted-thread");
    let hart_generation =
        graph.harts().iter().find(|hart| hart.id == 1).map(|hart| hart.generation).unwrap();
    assert!(graph.create_runnable_queue_with_id(88, "x0-preempt-rq"));
    assert!(graph.bind_runnable_queue_owner(
        88,
        1,
        1,
        hart_generation,
        "x0 hart owns preempt queue",
    ));
    assert!(graph.create_runtime_activation_with_id(88, 88, 1, None, None, None,));
    assert!(graph.enqueue_runnable_activation(88, 88, 1));
    assert!(graph.dequeue_runnable_activation(88, 88));
    assert!(graph.record_timer_interrupt_with_id(
        88,
        10,
        1,
        hart_generation,
        Some(88),
        Some(3),
        "x0 timer preemption",
    ));
    assert!(graph.preempt_running_activation_with_id(
        88,
        88,
        3,
        88,
        1,
        88,
        "x0 preempt activation",
    ));
    assert!(graph.save_preempted_context_with_ids(
        88,
        89,
        88,
        1,
        0x4000,
        0xa000,
        0,
        "x0 save timer frame",
    ));
    graph
}

#[test]
pub(in crate::tests) fn integrated_runtime_x0_records_smp_preemption_cleanup_closure() {
    let mut graph = x0_integrated_smp_preemption_cleanup_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "x0-test",
        SemanticCommand::RecordIntegratedSmpPreemptionCleanup {
            integrated: 301,
            scenario: "x0-smp-preemption-cleanup".to_string(),
            stress_run: 191,
            stress_run_generation: 1,
            preemption: 88,
            preemption_generation: 1,
            timer_interrupt: 88,
            timer_interrupt_generation: 1,
            saved_context: 89,
            saved_context_generation: 1,
            remote_preempt: 31,
            remote_preempt_generation: 1,
            activation_cleanup: 170,
            activation_cleanup_generation: 1,
            smp_cleanup_quiescence: 171,
            smp_cleanup_quiescence_generation: 1,
            invariant_checks: 7,
            note: "integrate scheduler preemption with SMP cleanup quiescence".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.integrated_smp_preemption_cleanups().len(), 1);
    let record = &graph.integrated_smp_preemption_cleanups()[0];
    assert_eq!(record.id, 301);
    assert_eq!(record.hart_count, 2);
    assert_eq!(record.cleanup_store, graph.activation_cleanups()[0].store);
    assert_eq!(
        record.target_store_generation,
        graph.activation_cleanups()[0].target_store_generation
    );
    assert_eq!(
        record.result_store_generation,
        graph.activation_cleanups()[0].result_store_generation
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "IntegratedSmpPreemptionCleanupRecorded integrated=301 scenario=x0-smp-preemption-cleanup stress_run=191@1 preemption=88@1 remote_preempt=31@1 activation_cleanup=170@1 smp_cleanup_quiescence=171@1 cleanup_store={}@{}->{} harts=2 invariant_checks=7 generation=1",
            record.cleanup_store, record.target_store_generation, record.result_store_generation
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn integrated_runtime_x0_rejects_stale_or_incomplete_evidence() {
    let mut graph = x0_integrated_smp_preemption_cleanup_graph();
    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "x0-test",
        SemanticCommand::RecordIntegratedSmpPreemptionCleanup {
            integrated: 301,
            scenario: "x0-smp-preemption-cleanup".to_string(),
            stress_run: 191,
            stress_run_generation: 1,
            preemption: 88,
            preemption_generation: 1,
            timer_interrupt: 88,
            timer_interrupt_generation: 1,
            saved_context: 89,
            saved_context_generation: 2,
            remote_preempt: 31,
            remote_preempt_generation: 1,
            activation_cleanup: 170,
            activation_cleanup_generation: 1,
            smp_cleanup_quiescence: 171,
            smp_cleanup_quiescence_generation: 1,
            invariant_checks: 7,
            note: "stale saved context must reject".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["integrated smp/preemption/cleanup missing saved context evidence".to_string()]
    );

    assert!(graph.record_integrated_smp_preemption_cleanup_with_id(
        301,
        "x0-smp-preemption-cleanup",
        191,
        1,
        88,
        1,
        88,
        1,
        89,
        1,
        31,
        1,
        170,
        1,
        171,
        1,
        7,
        "integrated closure",
    ));
    graph.corrupt_integrated_smp_cleanup_hart_count_for_test(301, 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IntegratedSmpPreemptionCleanupInvalid { integrated: 301 })
    );
}

#[test]
pub(in crate::tests) fn integrated_runtime_x0_contract_graph_rejects_generation_drift() {
    let mut graph = x0_integrated_smp_preemption_cleanup_graph();
    assert!(graph.record_integrated_smp_preemption_cleanup_with_id(
        301,
        "x0-smp-preemption-cleanup",
        191,
        1,
        88,
        1,
        88,
        1,
        89,
        1,
        31,
        1,
        170,
        1,
        171,
        1,
        7,
        "integrated closure",
    ));
    let mut integrated = graph.integrated_smp_preemption_cleanups().to_vec();
    integrated[0].remote_preempt_generation = 99;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_smp_preemption_cleanups: integrated,
        saved_contexts: graph.saved_contexts().to_vec(),
        timer_interrupts: graph.timer_interrupts().to_vec(),
        remote_preempts: graph.remote_preempts().to_vec(),
        activation_cleanups: graph.activation_cleanups().to_vec(),
        smp_cleanup_quiescence: graph.smp_cleanup_quiescence().to_vec(),
        smp_stress_runs: graph.smp_stress_runs().to_vec(),
        preemptions: graph.preemptions().to_vec(),
        stores: graph.stores().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-smp-preemption-cleanup->remote-preempt"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(in crate::tests) fn x1_integrated_smp_network_fault_snapshot() -> ContractGraphSnapshot {
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let integrated = IntegratedSmpNetworkFaultRecord {
        id: 401,
        scenario: "x1-smp-network-driver-fault".to_string(),
        network_driver_cleanup: 1599,
        network_driver_cleanup_generation: 1,
        smp_stress_run: 191,
        smp_stress_run_generation: 1,
        remote_preempt: 31,
        remote_preempt_generation: 1,
        smp_cleanup_quiescence: 171,
        smp_cleanup_quiescence_generation: 1,
        driver_store: 7,
        driver_store_generation: 3,
        packet_device: 1541,
        packet_device_generation: 1,
        adapter: 1575,
        adapter_generation: 1,
        backend,
        io_cleanup: 1600,
        io_cleanup_generation: 1,
        cancelled_socket_wait_count: 1,
        cancelled_wait_token_count: 1,
        revoked_packet_capability_count: 1,
        hart_count: 2,
        invariant_checks: 7,
        generation: 1,
        state: IntegratedSmpNetworkFaultState::Recorded,
        recorded_at_event: 90,
        note: "integrated network fault under SMP".to_string(),
    };
    let network_cleanup = NetworkDriverCleanupRecord {
        id: 1599,
        io_cleanup: 1600,
        io_cleanup_generation: 1,
        driver_store: 7,
        driver_store_generation: 3,
        device: 1540,
        device_generation: 1,
        driver_binding: 1552,
        driver_binding_generation: 1,
        packet_device: 1541,
        packet_device_generation: 1,
        adapter: 1575,
        adapter_generation: 1,
        backend,
        cancelled_socket_waits: vec![ContractObjectRef::new(
            ContractObjectKind::SocketWait,
            1598,
            1,
        )],
        cancelled_wait_tokens: vec![ContractObjectRef::new(ContractObjectKind::WaitToken, 1597, 1)],
        revoked_packet_capabilities: vec![ContractObjectRef::new(
            ContractObjectKind::DeviceCapability,
            1570,
            1,
        )],
        generation: 1,
        state: NetworkDriverCleanupState::Completed,
        started_at_event: 80,
        completed_at_event: Some(89),
        reason: "device-fault".to_string(),
        note: "network cleanup".to_string(),
    };
    ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_smp_network_faults: vec![integrated],
        network_driver_cleanups: vec![network_cleanup],
        packet_device_objects: vec![PacketDeviceObjectRecord {
            id: 1541,
            name: "virtio-net2".to_string(),
            device: 1540,
            device_generation: 1,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            generation: 1,
            state: PacketDeviceObjectState::Registered,
            recorded_at_event: 10,
            note: "packet device".to_string(),
        }],
        network_stack_adapters: vec![NetworkStackAdapterRecord {
            id: 1575,
            implementation: "smoltcp".to_string(),
            implementation_version: "0.13.0".to_string(),
            profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_string(),
            medium: "ethernet".to_string(),
            backend,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            ipv4_addr: [10, 0, 2, 15],
            ipv4_prefix_len: 24,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            max_payload_len: 512,
            socket_capacity: 16,
            generation: 1,
            state: NetworkStackAdapterState::Bound,
            recorded_at_event: 20,
            note: "adapter".to_string(),
        }],
        virtio_net_backends: vec![VirtioNetBackendObjectRecord {
            id: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: 1552,
            driver_binding_generation: 1,
            device: 1540,
            device_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            generation: 1,
            state: VirtioNetBackendObjectState::SkeletonReady,
            recorded_at_event: 30,
            note: "backend".to_string(),
        }],
        io_cleanups: vec![IoCleanupRecord {
            id: 1600,
            driver_store: 7,
            driver_store_generation: 3,
            device: 1540,
            device_generation: 1,
            driver_binding: 1552,
            driver_binding_generation: 1,
            generation: 1,
            state: IoCleanupState::Completed,
            reason: "device-fault".to_string(),
            started_at_event: 81,
            completed_at_event: 88,
            cancelled_io_waits: Vec::new(),
            revoked_device_capabilities: vec![ContractObjectRef::new(
                ContractObjectKind::DeviceCapability,
                1570,
                1,
            )],
            revoked_capabilities: Vec::new(),
            released_dma_buffers: Vec::new(),
            released_mmio_regions: Vec::new(),
            released_irq_lines: Vec::new(),
            steps: Vec::new(),
            note: "io cleanup".to_string(),
        }],
        smp_stress_runs: vec![SmpStressRunRecord {
            id: 191,
            scenario: "s15-smp-stress-property".to_string(),
            iterations: 3,
            hart_count: 2,
            event_log_cursor: 77,
            observed_safe_point_count: 3,
            observed_rendezvous_count: 3,
            observed_code_publish_barrier_count: 1,
            observed_cleanup_quiescence_count: 1,
            observed_snapshot_barrier_count: 1,
            observed_activation_migration_count: 1,
            observed_remote_preempt_count: 1,
            observed_remote_park_count: 1,
            invariant_checks: 7,
            property_failures: 0,
            last_safe_point: 181,
            last_safe_point_generation: 1,
            last_rendezvous: 181,
            last_rendezvous_generation: 1,
            last_code_publish_barrier: 91,
            last_code_publish_barrier_generation: 1,
            last_cleanup_quiescence: 171,
            last_cleanup_quiescence_generation: 1,
            last_snapshot_barrier: 181,
            last_snapshot_barrier_generation: 1,
            last_activation_migration: 151,
            last_activation_migration_generation: 1,
            last_remote_preempt: 31,
            last_remote_preempt_generation: 1,
            last_remote_park: 171,
            last_remote_park_generation: 1,
            generation: 1,
            state: SmpStressRunState::Recorded,
            recorded_at_event: 78,
            reason: "smp-stress".to_string(),
            note: "stress".to_string(),
        }],
        remote_preempts: vec![RemotePreemptRecord {
            id: 31,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation_before: 3,
            target_hart_generation_after: 4,
            activation: 11,
            activation_generation_before: 3,
            activation_generation_after: 4,
            queue: 2,
            queue_generation: 1,
            generation: 1,
            state: RemotePreemptState::Applied,
            preempted_at_event: 70,
            note: "remote preempt".to_string(),
        }],
        smp_cleanup_quiescence: vec![SmpCleanupQuiescenceRecord {
            id: 171,
            cleanup: 170,
            cleanup_generation: 1,
            store: 42,
            target_store_generation: 2,
            result_store_generation: 4,
            activation: 70,
            activation_generation_after: 5,
            rendezvous: 171,
            rendezvous_generation: 1,
            rendezvous_epoch: 2,
            participants: vec![
                SmpCleanupQuiescenceParticipantRecord {
                    hart: 1,
                    hart_generation: 2,
                    hardware_hart: 0,
                    hart_state: HartState::Idle,
                    current_activation: None,
                    current_activation_generation: None,
                    current_store: None,
                    current_store_generation: None,
                    quiesced: true,
                },
                SmpCleanupQuiescenceParticipantRecord {
                    hart: 2,
                    hart_generation: 5,
                    hardware_hart: 1,
                    hart_state: HartState::Parked,
                    current_activation: None,
                    current_activation_generation: None,
                    current_store: None,
                    current_store_generation: None,
                    quiesced: true,
                },
            ],
            no_running_activation: true,
            no_pending_wait: true,
            no_live_capability: true,
            no_live_resource: true,
            generation: 1,
            state: SmpCleanupQuiescenceState::Validated,
            validated_at_event: 76,
            reason: "cleanup-quiescence".to_string(),
            note: "quiesced".to_string(),
        }],
        ..ContractGraphSnapshot::default()
    }
}

#[test]
pub(in crate::tests) fn integrated_runtime_x1_contract_graph_accepts_network_fault_under_smp() {
    let violations = validate_contract_graph(&x1_integrated_smp_network_fault_snapshot());
    assert_eq!(violations, Vec::new());
}

#[test]
pub(in crate::tests) fn integrated_runtime_x1_rejects_stale_or_incomplete_evidence() {
    let rejected = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x1-test",
        SemanticCommand::RecordIntegratedSmpNetworkFault {
            integrated: 401,
            scenario: "x1-smp-network-driver-fault".to_string(),
            network_driver_cleanup: 1599,
            network_driver_cleanup_generation: 1,
            smp_stress_run: 191,
            smp_stress_run_generation: 1,
            remote_preempt: 31,
            remote_preempt_generation: 1,
            smp_cleanup_quiescence: 171,
            smp_cleanup_quiescence_generation: 1,
            invariant_checks: 7,
            note: "missing evidence rejects".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["integrated smp/network fault missing network cleanup evidence".to_string()]
    );
}

#[test]
pub(in crate::tests) fn integrated_runtime_x1_contract_graph_rejects_generation_drift() {
    let mut snapshot = x1_integrated_smp_network_fault_snapshot();
    snapshot.integrated_smp_network_faults[0].remote_preempt_generation = 99;
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-smp-network-fault->remote-preempt"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(in crate::tests) fn x2_integrated_disk_preempt_fault_graph() -> SemanticGraph {
    let mut graph = setup_b20_pending_io_policy_graph();
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "x2-setup",
                SemanticCommand::ApplyBlockPendingIoPolicy {
                    policy: 1899,
                    block_wait: 1895,
                    block_wait_generation: 1,
                    action: BlockPendingIoAction::Eio,
                    retry_request: None,
                    retry_request_generation: None,
                    errno: 5,
                    retry_attempt: 0,
                    max_retries: 0,
                    note: "x2 return EIO for preempted pending disk IO".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    graph.ensure_task(1990, FrontendKind::LinuxElf, "x2-preempted-disk-io-thread");
    assert!(graph.register_hart_with_id(1, 0, "x2-hart0", true, "x2 timer hart"));
    let hart_generation =
        graph.harts().iter().find(|hart| hart.id == 1).map(|hart| hart.generation).unwrap();
    assert!(graph.create_runnable_queue_with_id(1990, "x2-disk-preempt-rq"));
    assert!(graph.bind_runnable_queue_owner(
        1990,
        1,
        1,
        hart_generation,
        "x2 hart owns disk preempt queue",
    ));
    assert!(graph.create_runtime_activation_with_id(1990, 1990, 1, None, None, None,));
    assert!(graph.enqueue_runnable_activation(1990, 1990, 1));
    assert!(graph.dequeue_runnable_activation(1990, 1990));
    assert!(graph.record_timer_interrupt_with_id(
        1990,
        11,
        1,
        hart_generation,
        Some(1990),
        Some(3),
        "x2 timer preemption during disk pending IO fault",
    ));
    assert!(graph.preempt_running_activation_with_id(
        1990,
        1990,
        3,
        1990,
        1,
        1990,
        "x2 preempt disk pending IO activation",
    ));
    graph
}

#[test]
pub(in crate::tests) fn integrated_runtime_x2_records_disk_pending_io_fault_under_preemption() {
    let mut graph = x2_integrated_disk_preempt_fault_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        2,
        "x2-test",
        SemanticCommand::RecordIntegratedDiskPreemptFault {
            integrated: 501,
            scenario: "x2-disk-pending-io-fault-under-preemption".to_string(),
            preemption: 1990,
            preemption_generation: 1,
            block_pending_io_policy: 1899,
            block_pending_io_policy_generation: 1,
            invariant_checks: 6,
            note: "integrate disk EIO policy with timer preemption".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.integrated_disk_preempt_faults().len(), 1);
    let record = &graph.integrated_disk_preempt_faults()[0];
    assert_eq!(record.id, 501);
    assert_eq!(record.action, BlockPendingIoAction::Eio);
    assert_eq!(record.errno, 5);
    assert_eq!(record.block_wait, 1895);
    assert_eq!(record.wait, 1894);
    assert_eq!(record.block_request, 1893);
    assert_eq!(record.preempted_activation, 1990);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IntegratedDiskPreemptFaultRecorded integrated=501 scenario=x2-disk-pending-io-fault-under-preemption preemption=1990@1 timer_interrupt=1990@1 policy=1899@1 block_wait=1895@1 wait=1894@1 block_request=1893@1 block_device=1791@1 action=eio errno=5 activation=1990@4 invariant_checks=6 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn integrated_runtime_x2_rejects_missing_or_non_fault_evidence() {
    let rejected = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x2-test",
        SemanticCommand::RecordIntegratedDiskPreemptFault {
            integrated: 501,
            scenario: "x2-disk-pending-io-fault-under-preemption".to_string(),
            preemption: 1990,
            preemption_generation: 1,
            block_pending_io_policy: 1899,
            block_pending_io_policy_generation: 1,
            invariant_checks: 6,
            note: "missing evidence rejects".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["integrated disk/preempt fault missing preemption evidence".to_string()]
    );

    let mut graph = setup_b20_pending_io_policy_graph();
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                2,
                "x2-test",
                SemanticCommand::ApplyBlockPendingIoPolicy {
                    policy: 1900,
                    block_wait: 1898,
                    block_wait_generation: 1,
                    action: BlockPendingIoAction::Cancel,
                    retry_request: None,
                    retry_request_generation: None,
                    errno: 125,
                    retry_attempt: 0,
                    max_retries: 0,
                    note: "cancel is not a device-fault pending IO policy".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    graph.ensure_task(1990, FrontendKind::LinuxElf, "x2-preempted-disk-io-thread");
    assert!(graph.register_hart_with_id(1, 0, "x2-hart0", true, "x2 timer hart"));
    let hart_generation =
        graph.harts().iter().find(|hart| hart.id == 1).map(|hart| hart.generation).unwrap();
    assert!(graph.create_runnable_queue_with_id(1990, "x2-disk-preempt-rq"));
    assert!(graph.bind_runnable_queue_owner(
        1990,
        1,
        1,
        hart_generation,
        "x2 hart owns disk preempt queue",
    ));
    assert!(graph.create_runtime_activation_with_id(1990, 1990, 1, None, None, None,));
    assert!(graph.enqueue_runnable_activation(1990, 1990, 1));
    assert!(graph.dequeue_runnable_activation(1990, 1990));
    assert!(graph.record_timer_interrupt_with_id(
        1990,
        11,
        1,
        hart_generation,
        Some(1990),
        Some(3),
        "x2 timer preemption during disk cancel",
    ));
    assert!(graph.preempt_running_activation_with_id(
        1990,
        1990,
        3,
        1990,
        1,
        1990,
        "x2 preempt disk cancel activation",
    ));
    let non_fault = graph.apply_envelope(CommandEnvelope::new(
        3,
        "x2-test",
        SemanticCommand::RecordIntegratedDiskPreemptFault {
            integrated: 502,
            scenario: "x2-disk-pending-io-fault-under-preemption".to_string(),
            preemption: 1990,
            preemption_generation: 1,
            block_pending_io_policy: 1900,
            block_pending_io_policy_generation: 1,
            invariant_checks: 6,
            note: "cancel policy must not satisfy disk fault evidence".to_string(),
        },
    ));
    assert_eq!(non_fault.status, CommandStatus::Rejected);
    assert_eq!(
        non_fault.violations,
        vec!["integrated disk/preempt fault requires device-fault retry or EIO policy".to_string()]
    );
}

#[test]
pub(in crate::tests) fn integrated_runtime_x2_contract_graph_rejects_generation_drift() {
    let mut graph = x2_integrated_disk_preempt_fault_graph();
    assert!(graph.record_integrated_disk_preempt_fault_with_id(
        501,
        "x2-disk-pending-io-fault-under-preemption",
        1990,
        1,
        1899,
        1,
        6,
        "integrated disk fault",
    ));
    let mut integrated = graph.integrated_disk_preempt_faults().to_vec();
    integrated[0].block_pending_io_policy_generation = 99;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_disk_preempt_faults: integrated,
        preemptions: graph.preemptions().to_vec(),
        timer_interrupts: graph.timer_interrupts().to_vec(),
        block_pending_io_policies: graph.block_pending_io_policies().to_vec(),
        block_waits: graph.block_waits().to_vec(),
        block_request_objects: graph.block_request_objects().to_vec(),
        block_device_objects: graph.block_device_objects().to_vec(),
        block_range_objects: graph.block_range_objects().to_vec(),
        waits: graph.wait_records().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-disk-preempt-fault->block-pending-io-policy"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(in crate::tests) fn x3_integrated_simd_migration_graph() -> SemanticGraph {
    let mut graph = v9_cross_hart_clean_vector_migration_graph(ActivationVectorState::Clean);
    assert!(graph.migrate_runnable_activation_with_id(
        71,
        11,
        4,
        2,
        2,
        3,
        2,
        2,
        4,
        1,
        2,
        "vector-rebalance",
        "x3 cross-hart migration rehomes clean vector state",
    ));
    graph
}

#[test]
pub(in crate::tests) fn integrated_runtime_x3_records_simd_task_migration_across_harts() {
    let mut graph = x3_integrated_simd_migration_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        3,
        "x3-test",
        SemanticCommand::RecordIntegratedSimdMigration {
            integrated: 601,
            scenario: "x3-simd-task-migration-across-harts".to_string(),
            activation_migration: 71,
            activation_migration_generation: 1,
            invariant_checks: 6,
            note: "integrate SIMD vector migration with cross-hart activation migration"
                .to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.integrated_simd_migrations().len(), 1);
    let record = &graph.integrated_simd_migrations()[0];
    assert_eq!(record.id, 601);
    assert_eq!(record.activation_migration, 71);
    assert_eq!(record.target_feature_set, 21_003);
    assert_eq!(
        record.source_vector_state,
        ContractObjectRef::new(ContractObjectKind::VectorState, 22_004, 1)
    );
    assert_eq!(
        record.migrated_vector_state,
        ContractObjectRef::new(ContractObjectKind::VectorState, 22_005, 1)
    );
    assert_eq!(record.activation, 11);
    assert_eq!(record.activation_generation_before, 4);
    assert_eq!(record.activation_generation_after, 5);
    assert_eq!(record.source_hart, 2);
    assert_eq!(record.target_hart, 1);
    assert_eq!(record.simd_abi, "riscv-v");
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IntegratedSimdMigrationRecorded integrated=601 scenario=x3-simd-task-migration-across-harts migration=71@1 target_feature_set=21003@1 source_vector_state=vector-state:22004@1 migrated_vector_state=vector-state:22005@1 activation=11@4->5 source_hart=2@4 target_hart=1@2 simd_abi=riscv-v invariant_checks=6 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn integrated_runtime_x3_rejects_missing_or_dirty_vector_migration() {
    let rejected = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x3-test",
        SemanticCommand::RecordIntegratedSimdMigration {
            integrated: 601,
            scenario: "x3-simd-task-migration-across-harts".to_string(),
            activation_migration: 71,
            activation_migration_generation: 1,
            invariant_checks: 6,
            note: "missing migration rejects".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["integrated SIMD migration missing activation migration evidence".to_string()]
    );

    let mut dirty = v9_cross_hart_clean_vector_migration_graph(ActivationVectorState::Dirty);
    let migration = dirty.apply_envelope(CommandEnvelope::new(
        2,
        "x3-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 71,
            activation: 11,
            activation_generation: 4,
            source_queue: 2,
            source_queue_generation: 2,
            target_queue: 3,
            target_queue_generation: 2,
            source_hart: 2,
            source_hart_generation: 4,
            target_hart: 1,
            target_hart_generation: 2,
            reason: "vector-rebalance".to_string(),
            note: "dirty vector migration must reject before X3 integration".to_string(),
        },
    ));
    assert_eq!(migration.status, CommandStatus::Rejected);
    assert_eq!(
        migration.violations,
        vec!["activation migration requires clean vector state".to_string()]
    );
}

#[test]
pub(in crate::tests) fn integrated_runtime_x3_contract_graph_rejects_vector_generation_drift() {
    let mut graph = x3_integrated_simd_migration_graph();
    assert!(graph.record_integrated_simd_migration_with_id(
        601,
        "x3-simd-task-migration-across-harts",
        71,
        1,
        6,
        "integrated SIMD migration",
    ));
    let mut integrated = graph.integrated_simd_migrations().to_vec();
    integrated[0].migrated_vector_state.generation = 99;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_simd_migrations: integrated,
        target_feature_sets: graph.target_feature_sets().to_vec(),
        vector_states: graph.vector_states().to_vec(),
        harts: graph.harts().to_vec(),
        runnable_queues: graph.runnable_queues().to_vec(),
        activation_contexts: graph.activation_contexts().to_vec(),
        activation_migrations: graph.activation_migrations().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-simd-migration->migrated-vector-state"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

#[test]
pub(in crate::tests) fn integrated_runtime_x3_contract_graph_rejects_context_binding_drift() {
    let mut graph = x3_integrated_simd_migration_graph();
    assert!(graph.record_integrated_simd_migration_with_id(
        601,
        "x3-simd-task-migration-across-harts",
        71,
        1,
        6,
        "integrated SIMD migration",
    ));
    let mut contexts = graph.activation_contexts().to_vec();
    let record = &graph.integrated_simd_migrations()[0];
    contexts
        .iter_mut()
        .find(|context| {
            context.id == record.context && context.generation == record.context_generation_after
        })
        .expect("x3 context")
        .vector_status = ActivationVectorState::Dirty;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_simd_migrations: graph.integrated_simd_migrations().to_vec(),
        target_feature_sets: graph.target_feature_sets().to_vec(),
        vector_states: graph.vector_states().to_vec(),
        harts: graph.harts().to_vec(),
        runnable_queues: graph.runnable_queues().to_vec(),
        activation_contexts: contexts,
        activation_migrations: graph.activation_migrations().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-simd-migration->context-binding"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}
