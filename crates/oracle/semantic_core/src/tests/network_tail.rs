use super::*;

#[test]
pub(super) fn authority_bindings_drive_resource_and_capability_lifecycle() {
    let mut graph = SemanticGraph::new();
    let mmio = graph.register_resource(ResourceKind::MmioRegion, None, "mmio:virtio-net0");
    let authority = graph
        .bind_authority_resource(
            mmio,
            "driver_virtio_net",
            "mmio.virtio-net0",
            &["read", "write"],
            "store",
        )
        .expect("authority binding");

    assert_eq!(graph.authority_count(), 1);
    assert_eq!(graph.active_authority_count(), 1);
    let cap_object_ref = graph.capabilities().records()[0]
        .object_ref
        .expect("authority binding capability carries object ref");
    assert!(
        graph
            .capabilities()
            .check_authority("driver_virtio_net", cap_object_ref, "write", None)
            .is_ok()
    );
    let old_generation = graph
        .capability_generation("driver_virtio_net", "mmio.virtio-net0")
        .expect("authority generation");
    assert!(graph.check_invariants().is_ok());

    assert!(graph.release_authority_binding(authority, "driver micro-reboot"));
    assert_eq!(graph.active_authority_count(), 0);
    assert_eq!(
        graph.capabilities().check_authority("driver_virtio_net", cap_object_ref, "write", None),
        Err(CapabilityDenyReason::Revoked)
    );
    assert_eq!(
        graph.validate_resource_handle(ResourceHandle::new(mmio, 1)),
        Err(GenerationCheckError::GenerationMismatch { expected: 1, actual: Some(2) })
    );
    assert!(graph.event_log_tail(8).iter().any(|event| matches!(
        event.kind,
        EventKind::AuthorityReleased {
            authority: recorded,
            resource: recorded_resource,
            ..
        } if recorded == authority && recorded_resource == mmio
    )));

    let rebound_mmio = graph.register_resource(ResourceKind::MmioRegion, None, "mmio:virtio-net0");
    graph
        .bind_authority_resource(
            rebound_mmio,
            "driver_virtio_net",
            "mmio.virtio-net0",
            &["read", "write"],
            "store",
        )
        .expect("rebound authority");
    let rebound_generation = graph
        .capability_generation("driver_virtio_net", "mmio.virtio-net0")
        .expect("rebound authority generation");
    assert!(rebound_generation > old_generation);
    assert_eq!(
        graph.check_capability_generation(
            "driver_virtio_net",
            "mmio.virtio-net0",
            "write",
            old_generation,
        ),
        Err(CapabilityDenyReason::GenerationMismatch)
    );
    assert!(graph.check_capability("driver_virtio_net", "mmio.virtio-net0", "write").is_ok());
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn packet_device_authority_is_part_of_the_hardware_ledger() {
    let mut graph = SemanticGraph::new();
    let device = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let authority = graph
        .bind_authority_resource(
            device,
            "driver_virtio_net",
            "packet-device.net0",
            &["rx", "tx", "poll"],
            "store",
        )
        .expect("packet device authority binding");

    assert_eq!(graph.authority_bindings()[0].kind, AuthorityKind::PacketDevice);
    let cap_object_ref = graph.capabilities().records()[0]
        .object_ref
        .expect("packet authority capability carries object ref");
    assert!(
        graph
            .capabilities()
            .check_authority("driver_virtio_net", cap_object_ref, "rx", None)
            .is_ok()
    );
    assert!(graph.revoke_authority_binding(authority, "driver restart"));
    assert_eq!(
        graph.capabilities().check_authority("driver_virtio_net", cap_object_ref, "rx", None),
        Err(CapabilityDenyReason::Revoked)
    );
}

#[test]
pub(super) fn invariants_reject_bound_authority_without_capability() {
    let mut graph = SemanticGraph::new();
    let irq = graph.register_resource(ResourceKind::IrqLine, None, "irq:net0");
    let authority = graph
        .bind_authority_resource(irq, "driver_virtio_net", "irq.net0", &["ack"], "store")
        .expect("authority binding");

    let (capability, capability_generation) = graph
        .authority_bindings()
        .iter()
        .find(|binding| binding.id == authority)
        .map(|binding| (binding.capability, binding.capability_generation))
        .expect("authority binding");
    assert!(graph.revoke_capability_generation(capability, capability_generation));

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::AuthorityCapabilityMissing { authority })
    );
}

#[test]
pub(super) fn migration_package_rejects_active_dmw_leases() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
    graph.record_snapshot_barrier_enter(1);
    graph.record_snapshot_barrier_exit(1);

    let package = graph.migration_package(
        "test",
        "x86_64",
        "aarch64",
        test_artifact_profile(),
        GuestStateSnapshot::riscv64_placeholder(),
        SubstrateBoundarySnapshot {
            timer_epoch: 0,
            pending_irq_causes: 0,
            pending_dma_completions: 0,
            active_dmw_lease_count: 1,
            active_mmio_authority_count: 0,
            active_dma_authority_count: 0,
            active_irq_authority_count: 0,
            active_packet_device_authority_count: 0,
            active_virtio_queue_authority_count: 0,
            pending_network_inputs: 0,
            random_epoch: 0,
            scheduler_decision_cursor: 0,
            cow_epoch: 0,
            background_copy_pages: 0,
            native_state_policy: "rebuild".to_string(),
        },
        1,
        false,
    );

    assert_eq!(package.validate_portability(), Err(MigrationValidationError::ActiveDmwLease));
}

#[test]
pub(super) fn migration_package_rejects_active_semantic_transactions() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
    graph.begin_transaction("net.recvmsg", None, Some(1));

    let package = graph.migration_package(
        "test",
        "x86_64",
        "aarch64",
        test_artifact_profile(),
        GuestStateSnapshot::riscv64_placeholder(),
        SubstrateBoundarySnapshot {
            timer_epoch: 0,
            pending_irq_causes: 0,
            pending_dma_completions: 0,
            active_dmw_lease_count: 0,
            active_mmio_authority_count: 0,
            active_dma_authority_count: 0,
            active_irq_authority_count: 0,
            active_packet_device_authority_count: 0,
            active_virtio_queue_authority_count: 0,
            pending_network_inputs: 0,
            random_epoch: 0,
            scheduler_decision_cursor: 0,
            cow_epoch: 0,
            background_copy_pages: 0,
            native_state_policy: "rebuild".to_string(),
        },
        1,
        true,
    );

    assert_eq!(
        package.validate_portability(),
        Err(MigrationValidationError::ActiveSemanticTransaction)
    );
}

#[test]
pub(super) fn migration_package_rejects_active_substrate_authorities() {
    let cases: [(fn(&mut SubstrateBoundarySnapshot), MigrationValidationError); 5] = [
        (
            |boundary| boundary.active_mmio_authority_count = 1,
            MigrationValidationError::ActiveMmioAuthority,
        ),
        (
            |boundary| boundary.active_dma_authority_count = 1,
            MigrationValidationError::ActiveDmaAuthority,
        ),
        (
            |boundary| boundary.active_irq_authority_count = 1,
            MigrationValidationError::ActiveIrqAuthority,
        ),
        (
            |boundary| boundary.active_packet_device_authority_count = 1,
            MigrationValidationError::ActivePacketDeviceAuthority,
        ),
        (
            |boundary| boundary.active_virtio_queue_authority_count = 1,
            MigrationValidationError::ActiveVirtioQueueAuthority,
        ),
    ];

    for (set_active, expected) in cases {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
        graph.record_snapshot_barrier_enter(1);
        graph.record_snapshot_barrier_exit(1);
        let mut boundary = test_substrate_boundary();
        set_active(&mut boundary);
        let package = graph.migration_package(
            "test",
            "x86_64",
            "aarch64",
            test_artifact_profile(),
            GuestStateSnapshot::riscv64_placeholder(),
            boundary,
            1,
            true,
        );

        assert_eq!(package.validate_portability(), Err(expected));
    }
}

#[test]
pub(super) fn substrate_unsupported_is_event_log_visible() {
    let mut graph = SemanticGraph::new();

    let event = graph.record_substrate_unsupported(
        "dma",
        "DmaAuthority",
        "dma_alloc",
        Some("driver.fake_net".to_string()),
        Some(9),
        Some(4),
    );

    let record = graph.event_log_tail(1).first().expect("event was recorded");
    assert_eq!(record.id, event);
    assert_eq!(
        record.kind.summary(),
        "SubstrateUnsupported family=dma authority=DmaAuthority op=dma_alloc requester=driver.fake_net artifact=9 store=4"
    );
}

#[test]
pub(super) fn substrate_capability_denied_is_event_log_visible() {
    let mut graph = SemanticGraph::new();

    let event = graph.record_substrate_capability_denied(
        "dma",
        "DmaAuthority",
        "dma_alloc",
        Some("driver.fake_net".to_string()),
        Some(9),
        Some(4),
        Some(7),
        Some(2),
    );

    let record = graph.event_log_tail(1).first().expect("event was recorded");
    assert_eq!(record.id, event);
    assert_eq!(
        record.kind.summary(),
        "SubstrateCapabilityDenied family=dma authority=DmaAuthority op=dma_alloc requester=driver.fake_net artifact=9 store=4 capability=7 generation=2"
    );
}

#[test]
pub(super) fn interface_unsupported_is_event_log_visible() {
    let mut graph = SemanticGraph::new();

    let event = graph.record_interface_unsupported(
        "custom-wit",
        "semantic:machine/mmio",
        "read32",
        Some("driver.fake_net".to_string()),
        Some(9),
        Some(4),
    );

    let record = graph.event_log_tail(1).first().expect("event was recorded");
    assert_eq!(record.id, event);
    assert_eq!(
        record.kind.summary(),
        "InterfaceUnsupported kind=custom-wit interface=semantic:machine/mmio op=read32 requester=driver.fake_net artifact=9 store=4"
    );
}

#[test]
pub(super) fn smp_runtime_s0_registers_hart_and_changes_state() {
    let mut graph = SemanticGraph::new();

    let registered = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s0-test",
        SemanticCommand::RegisterHart {
            hart: 1,
            hardware_id: 0,
            label: "boot-hart0".to_string(),
            boot: true,
            note: "s0 hart object".to_string(),
        },
    ));
    assert_eq!(registered.status, CommandStatus::Applied);
    assert_eq!(graph.hart_count(), 1);
    assert_eq!(graph.harts()[0].object_ref().summary(), "hart:1@1");

    let state = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s0-test",
        SemanticCommand::SetHartState {
            hart: 1,
            hart_generation: 1,
            state: HartState::Idle,
            reason: "scheduler-ready".to_string(),
            note: "hart ready for S1 current activation".to_string(),
        },
    ));
    assert_eq!(state.status, CommandStatus::Applied);
    assert_eq!(graph.harts()[0].state, HartState::Idle);
    assert_eq!(graph.harts()[0].generation, 2);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "HartStateChanged hart=1 from=created to=idle reason=scheduler-ready generation=2"
    );
}

#[test]
pub(super) fn smp_runtime_s0_rejects_duplicate_hart_and_stale_state_generation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));

    let duplicate_object = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s0-test",
        SemanticCommand::RegisterHart {
            hart: 1,
            hardware_id: 1,
            label: "duplicate-hart-object".to_string(),
            boot: false,
            note: "duplicate object".to_string(),
        },
    ));
    assert_eq!(duplicate_object.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("hart already exists".to_string());
    assert_eq!(duplicate_object.violations, expected);

    let duplicate_hardware = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s0-test",
        SemanticCommand::RegisterHart {
            hart: 2,
            hardware_id: 0,
            label: "duplicate-hardware-hart0".to_string(),
            boot: false,
            note: "duplicate hardware".to_string(),
        },
    ));
    assert_eq!(duplicate_hardware.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("hardware hart already exists".to_string());
    assert_eq!(duplicate_hardware.violations, expected);

    let stale_state = graph.apply_envelope(CommandEnvelope::new(
        3,
        "s0-test",
        SemanticCommand::SetHartState {
            hart: 1,
            hart_generation: 99,
            state: HartState::Running,
            reason: "stale-generation".to_string(),
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale_state.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("hart generation is missing".to_string());
    assert_eq!(stale_state.violations, expected);
    assert_eq!(graph.harts()[0].state, HartState::Created);
}

#[test]
pub(super) fn smp_runtime_s0_invariants_reject_invalid_hart_identity() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    graph.corrupt_hart_generation_for_test(1, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::HartInvalidObjectIdentity { hart: 1 })
    );
}

#[test]
pub(super) fn smp_runtime_s0_invariants_reject_duplicate_hardware_hart() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    let mut duplicate = graph.harts()[0].clone();
    duplicate.id = 2;
    graph.duplicate_hart_for_test(duplicate);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DuplicateHardwareHart { hardware_id: 0 })
    );
}

#[test]
pub(super) fn smp_runtime_s1_binds_and_clears_hart_local_current_activation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));

    let bound = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s1-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 1,
            hart_generation: 2,
            activation: 11,
            activation_generation: 3,
            note: "dispatch on hart0".to_string(),
        },
    ));
    assert_eq!(bound.status, CommandStatus::Applied);
    assert_eq!(graph.harts()[0].state, HartState::Running);
    assert_eq!(graph.harts()[0].generation, 3);
    assert_eq!(graph.harts()[0].current_activation, Some(11));
    assert_eq!(graph.harts()[0].current_activation_generation, Some(3));
    assert_eq!(graph.harts()[0].current_task, Some(7));
    assert_eq!(graph.harts()[0].current_task_generation, Some(1));
    assert!(graph.check_invariants().is_ok());

    let cleared = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s1-test",
        SemanticCommand::ClearHartCurrentActivation {
            hart: 1,
            hart_generation: 3,
            activation: 11,
            activation_generation: 3,
            reason: "timer-preempt".to_string(),
            note: "hart local slot cleared".to_string(),
        },
    ));
    assert_eq!(cleared.status, CommandStatus::Applied);
    assert_eq!(graph.harts()[0].state, HartState::Idle);
    assert_eq!(graph.harts()[0].generation, 4);
    assert_eq!(graph.harts()[0].current_activation, None);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "HartCurrentActivationCleared hart=1 activation=11@3 reason=timer-preempt generation=4"
    );
}

#[test]
pub(super) fn smp_runtime_s1_rejects_stale_hart_and_non_running_activation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));

    let non_running = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s1-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 1,
            hart_generation: 2,
            activation: 11,
            activation_generation: 1,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(non_running.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("current activation generation is missing or not running".to_string());
    assert_eq!(non_running.violations, expected);

    let stale_hart = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s1-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 1,
            hart_generation: 99,
            activation: 11,
            activation_generation: 1,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("hart generation is missing".to_string());
    assert_eq!(stale_hart.violations, expected);

    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    let non_idle_hart = graph.apply_envelope(CommandEnvelope::new(
        3,
        "s1-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 2,
            hart_generation: 1,
            activation: 11,
            activation_generation: 3,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(non_idle_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("hart is not idle".to_string());
    assert_eq!(non_idle_hart.violations, expected);
}

#[test]
pub(super) fn smp_runtime_s1_invariants_reject_stale_current_activation_generation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.bind_hart_current_activation(1, 2, 11, 3, "dispatch"));
    graph.corrupt_hart_current_activation_generation_for_test(1, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::HartCurrentActivationMissing { hart: 1, activation: 11 })
    );
}

pub(super) fn add_n17_dma_generation_fixture(
    graph: &mut SemanticGraph,
) -> (ContractObjectRef, ContractObjectRef, CapabilityHandle, StoreId, Generation) {
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    let dma_resource =
        graph.register_resource(ResourceKind::DmaBuffer, None, "dma:virtio-net2-tx0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_queue_object_with_id(
        1601,
        "virtio-net2-tx-dma",
        QueueObjectRole::Tx,
        1,
        4,
        1540,
        1,
        "n17 dma queue fixture",
    ));
    assert!(graph.record_descriptor_object_with_id(
        1602,
        1601,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "n17 dma descriptor fixture",
    ));
    assert!(graph.record_dma_buffer_object_with_id(
        1603,
        1602,
        1,
        dma_resource,
        dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        2048,
        "n17 dma buffer fixture",
    ));
    let dma_ref = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 1603, 1);
    let dma_capability = graph.grant_capability_with_authority_ref(
        "driver.virtio-net2",
        "dma.virtio-net2.tx0",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma_ref),
        &["sync-for-device"],
        "store",
        "n17-test",
        true,
    );
    let dma_handle = graph
        .capabilities()
        .record(dma_capability)
        .and_then(|record| record.store_local_handle(vec!["sync-for-device".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1604,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        dma_ref,
        CapabilityClass::DmaBuffer,
        "sync-for-device",
        dma_handle.clone(),
        "n17 dma capability fixture",
    ));
    (
        dma_ref,
        ContractObjectRef::new(ContractObjectKind::DeviceCapability, 1604, 1),
        dma_handle,
        binding_record.driver_store,
        binding_record.driver_store_generation,
    )
}

#[test]
pub(super) fn network_runtime_n17_records_stale_packet_dma_generation_audit() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();
    let (dma_ref, dma_capability_ref, dma_handle, driver_store, driver_store_generation) =
        add_n17_dma_generation_fixture(&mut graph);

    let stale_packet_buffer = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n17-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1605,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 2,
            slot: 1,
            length: 64,
            note: "n17 stale packet buffer generation".to_string(),
        },
    ));
    assert_eq!(stale_packet_buffer.status, CommandStatus::Rejected);
    assert_eq!(
        stale_packet_buffer.violations,
        vec!["packet descriptor object buffer generation is missing or inactive".to_string()]
    );

    let stale_packet_descriptor = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n17-test",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 1606,
            driver_store,
            driver_store_generation,
            packet_descriptor: 1547,
            packet_descriptor_generation: 2,
            device_capability: 1570,
            device_capability_generation: 1,
            handle: graph
                .device_capabilities()
                .iter()
                .find(|record| record.id == 1570)
                .and_then(|record| graph.capabilities().record(record.capability))
                .and_then(|record| record.store_local_handle(vec!["tx".to_string()]))
                .unwrap(),
            note: "n17 stale packet descriptor generation".to_string(),
        },
    ));
    assert_eq!(stale_packet_descriptor.status, CommandStatus::Rejected);
    assert_eq!(
        stale_packet_descriptor.violations,
        vec!["network tx capability gate descriptor generation is missing or inactive".to_string()]
    );

    let stale_dma_target = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n17-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1607,
            driver_store,
            driver_store_generation,
            target: ContractObjectRef::new(ContractObjectKind::DmaBufferObject, dma_ref.id, 2),
            class: CapabilityClass::DmaBuffer,
            operation: "sync-for-device".to_string(),
            handle: dma_handle,
            note: "n17 stale dma buffer generation".to_string(),
        },
    ));
    assert_eq!(stale_dma_target.status, CommandStatus::Rejected);
    assert_eq!(
        stale_dma_target.violations,
        vec!["device capability target generation is missing or inactive".to_string()]
    );

    let audit = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n17-test",
        SemanticCommand::RecordNetworkGenerationAudit {
            audit: 1608,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: 1547,
            packet_descriptor_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            dma_buffer: dma_ref,
            device_capability: dma_capability_ref,
            rejected_packet_generation_probes: 2,
            rejected_dma_generation_probes: 1,
            note: "n17 stale packet and dma generation audit".to_string(),
        },
    ));
    assert_eq!(audit.status, CommandStatus::Applied, "{audit:?}");
    assert_eq!(graph.network_generation_audit_count(), 1);
    let audit = &graph.network_generation_audits()[0];
    assert_eq!(
        audit.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkGenerationAudit, 1608, 1)
    );
    assert_eq!(audit.packet_descriptor_generation, 1);
    assert_eq!(audit.dma_buffer, dma_ref);
    assert_eq!(audit.device_capability, dma_capability_ref);
    assert_eq!(audit.rejected_packet_generation_probes, 2);
    assert_eq!(audit.rejected_dma_generation_probes, 1);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkGenerationAuditRecorded audit=1608")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n17_rejects_missing_probe_counts_and_stale_audit_refs() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();
    let (dma_ref, dma_capability_ref, _, _, _) = add_n17_dma_generation_fixture(&mut graph);

    let missing_packet_probe = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n17-test",
        SemanticCommand::RecordNetworkGenerationAudit {
            audit: 1608,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: 1547,
            packet_descriptor_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            dma_buffer: dma_ref,
            device_capability: dma_capability_ref,
            rejected_packet_generation_probes: 0,
            rejected_dma_generation_probes: 1,
            note: "n17 missing packet probe count".to_string(),
        },
    ));
    assert_eq!(missing_packet_probe.status, CommandStatus::Rejected);
    assert_eq!(
        missing_packet_probe.violations,
        vec!["network generation audit requires rejected packet and dma probes".to_string()]
    );

    let stale_descriptor = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n17-test",
        SemanticCommand::RecordNetworkGenerationAudit {
            audit: 1608,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: 1547,
            packet_descriptor_generation: 2,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            dma_buffer: dma_ref,
            device_capability: dma_capability_ref,
            rejected_packet_generation_probes: 2,
            rejected_dma_generation_probes: 1,
            note: "n17 stale descriptor ref".to_string(),
        },
    ));
    assert_eq!(stale_descriptor.status, CommandStatus::Rejected);
    assert_eq!(
        stale_descriptor.violations,
        vec![
            "network generation audit packet descriptor generation is missing or inactive"
                .to_string()
        ]
    );
}

#[test]
pub(super) fn network_runtime_n17_invariants_reject_packet_descriptor_generation_leak() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();
    let (dma_ref, dma_capability_ref, _, _, _) = add_n17_dma_generation_fixture(&mut graph);
    assert!(graph.record_network_generation_audit_with_id(
        1608,
        1575,
        1,
        1541,
        1,
        1545,
        1,
        1547,
        1,
        1543,
        1,
        dma_ref,
        dma_capability_ref,
        2,
        1,
        "n17 generation audit",
    ));
    graph.corrupt_network_generation_audit_descriptor_generation_for_test(1608, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkGenerationAuditMissingTarget {
            audit: 1608,
            target: ContractObjectRef::new(ContractObjectKind::PacketDescriptorObject, 1547, 2),
        })
    );
}

#[test]
pub(super) fn network_runtime_n18_records_packet_loss_and_error_injection() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();

    for (offset, command) in [
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 1609,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: Some(1547),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(1543),
            packet_buffer_generation: Some(1),
            endpoint: Some(connected_endpoint),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketLoss,
            effect: NetworkFaultInjectionEffect::DropPacket,
            injected_packets: 1,
            dropped_packets: 1,
            error_packets: 0,
            error_code: "".to_string(),
            sequence: 8,
            note: "n18 injected tx packet loss".to_string(),
        },
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 1610,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: Some(1547),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(1543),
            packet_buffer_generation: Some(1),
            endpoint: Some(connected_endpoint),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketError,
            effect: NetworkFaultInjectionEffect::ReportError,
            injected_packets: 1,
            dropped_packets: 0,
            error_packets: 1,
            error_code: "injected-checksum-error".to_string(),
            sequence: 9,
            note: "n18 injected tx checksum error".to_string(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let result =
            graph.apply_envelope(CommandEnvelope::new(1 + offset as u64, "n18-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }

    assert_eq!(graph.network_fault_injection_count(), 2);
    let loss = graph.network_fault_injections().iter().find(|record| record.id == 1609).unwrap();
    assert_eq!(
        loss.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkFaultInjection, 1609, 1)
    );
    assert_eq!(loss.kind, NetworkFaultInjectionKind::PacketLoss);
    assert_eq!(loss.effect, NetworkFaultInjectionEffect::DropPacket);
    assert_eq!(loss.dropped_packets, 1);
    assert_eq!(loss.error_packets, 0);
    assert_eq!(loss.endpoint, Some(connected_endpoint));

    let error = graph.network_fault_injections().iter().find(|record| record.id == 1610).unwrap();
    assert_eq!(error.kind, NetworkFaultInjectionKind::PacketError);
    assert_eq!(error.effect, NetworkFaultInjectionEffect::ReportError);
    assert_eq!(error.error_code, "injected-checksum-error");
    assert_eq!(error.packet_descriptor_generation, Some(1));
    assert_eq!(error.packet_buffer_generation, Some(1));
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkFaultInjectionRecorded injection=1610")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n18_rejects_stale_queue_and_malformed_error_injection() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let stale_queue = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n18-test",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 1609,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 2,
            packet_descriptor: Some(1547),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(1543),
            packet_buffer_generation: Some(1),
            endpoint: Some(connected_endpoint),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketLoss,
            effect: NetworkFaultInjectionEffect::DropPacket,
            injected_packets: 1,
            dropped_packets: 1,
            error_packets: 0,
            error_code: "".to_string(),
            sequence: 8,
            note: "n18 stale packet queue generation".to_string(),
        },
    ));
    assert_eq!(stale_queue.status, CommandStatus::Rejected);
    assert_eq!(
        stale_queue.violations,
        vec!["network fault injection packet queue generation is missing or inactive".to_string()]
    );

    let missing_endpoint = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n18-test",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 1610,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: Some(1547),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(1543),
            packet_buffer_generation: Some(1),
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketError,
            effect: NetworkFaultInjectionEffect::ReportError,
            injected_packets: 1,
            dropped_packets: 0,
            error_packets: 1,
            error_code: "injected-checksum-error".to_string(),
            sequence: 9,
            note: "n18 malformed packet error injection".to_string(),
        },
    ));
    assert_eq!(missing_endpoint.status, CommandStatus::Rejected);
    assert_eq!(
        missing_endpoint.violations,
        vec![
            "network packet error injection requires endpoint, descriptor, buffer, and error code"
                .to_string()
        ]
    );
}

#[test]
pub(super) fn network_runtime_n18_invariants_reject_packet_queue_generation_leak() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    assert!(graph.record_network_fault_injection_with_id(
        1609,
        1575,
        1,
        1541,
        1,
        1545,
        1,
        Some(1547),
        Some(1),
        Some(1543),
        Some(1),
        Some(connected_endpoint),
        Some(1),
        PacketBufferDirection::Tx,
        NetworkFaultInjectionKind::PacketLoss,
        NetworkFaultInjectionEffect::DropPacket,
        1,
        1,
        0,
        "",
        8,
        "n18 packet loss injection",
    ));
    graph.corrupt_network_fault_injection_queue_generation_for_test(1609, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkFaultInjectionMissingTarget {
            injection: 1609,
            target: ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1545, 2),
        })
    );
}

pub(super) fn setup_n19_network_benchmark_graph() -> (SemanticGraph, EndpointObjectId) {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    assert!(graph.record_network_tx_completion_with_id(
        1572,
        1571,
        1,
        ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
        1,
        "n19 tx completion evidence",
    ));
    assert!(graph.record_network_rx_interrupt_with_id(
        1556,
        1553,
        1,
        1555,
        1,
        1541,
        1,
        1544,
        1,
        1,
        1,
        "n19 rx interrupt evidence",
    ));
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    let rx_queue_ref = ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1544, 1);
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "n19-setup",
                SemanticCommand::CreateWait {
                    wait: 1611,
                    owner_task: None,
                    owner_store: Some(binding_record.driver_store),
                    owner_store_generation: Some(binding_record.driver_store_generation),
                    kind: SemanticWaitKind::DeviceIrq,
                    generation: 1,
                    blockers: vec![rx_queue_ref],
                    deadline: None,
                    restart_policy: RestartPolicy::InternalOnly,
                    saved_context: Some("n19 rx wait benchmark setup".to_string()),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert!(graph.record_io_wait_with_id(
        1612,
        1611,
        1,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1540,
        1,
        1552,
        1,
        rx_queue_ref,
        "n19 rx io wait evidence",
    ));
    assert!(graph.resolve_network_rx_wait_with_id(
        1613,
        1612,
        1,
        1556,
        1,
        "n19 rx wait resolution evidence",
    ));
    assert!(graph.record_network_backpressure_with_id(
        1596,
        1575,
        1,
        1541,
        1,
        1544,
        1,
        None,
        None,
        PacketBufferDirection::Rx,
        NetworkBackpressureReason::QueueFull,
        NetworkBackpressureAction::DropNewest,
        5,
        4,
        1,
        1514,
        3,
        "n19 rx drop newest evidence",
    ));
    (graph, connected_endpoint)
}

#[test]
pub(super) fn network_runtime_n19_benchmark_records_throughput_latency_evidence() {
    let (mut graph, connected_endpoint) = setup_n19_network_benchmark_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n19-test",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 1614,
            scenario: "host-validation-network-throughput-latency".to_string(),
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_completion: 1572,
            tx_completion_generation: 1,
            rx_wait_resolution: 1613,
            rx_wait_resolution_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            backpressure: Some(1596),
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
            note: "n19 throughput latency benchmark".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.network_benchmark_count(), 1);
    let benchmark = &graph.network_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkBenchmark, 1614, 1)
    );
    assert_eq!(benchmark.endpoint, connected_endpoint);
    assert_eq!(benchmark.socket, 1580);
    assert_eq!(benchmark.backpressure, Some(1596));
    assert_eq!(benchmark.throughput_bytes_per_sec, 50_000_000);
    assert_eq!(benchmark.p99_latency_nanos, 48_000);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkBenchmarkRecorded benchmark=1614")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n19_rejects_stale_adapter_and_budget_overrun() {
    let (mut graph, connected_endpoint) = setup_n19_network_benchmark_graph();
    let stale_adapter = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n19-test",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 1614,
            scenario: "host-validation-network-throughput-latency".to_string(),
            adapter: 1575,
            adapter_generation: 2,
            packet_device: 1541,
            packet_device_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_completion: 1572,
            tx_completion_generation: 1,
            rx_wait_resolution: 1613,
            rx_wait_resolution_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            backpressure: Some(1596),
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
            note: "n19 stale adapter".to_string(),
        },
    ));
    assert_eq!(stale_adapter.status, CommandStatus::Rejected);
    assert_eq!(
        stale_adapter.violations,
        vec!["network benchmark adapter generation is missing or inactive".to_string()]
    );

    let budget_overrun = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n19-test",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 1614,
            scenario: "host-validation-network-throughput-latency".to_string(),
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_completion: 1572,
            tx_completion_generation: 1,
            rx_wait_resolution: 1613,
            rx_wait_resolution_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            backpressure: Some(1596),
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
            note: "n19 budget overrun".to_string(),
        },
    ));
    assert_eq!(budget_overrun.status, CommandStatus::Rejected);
    assert_eq!(
        budget_overrun.violations,
        vec!["network benchmark exceeds latency budget".to_string()]
    );

    let packet_accounting_overflow = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n19-test",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 1614,
            scenario: "host-validation-network-throughput-latency".to_string(),
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_completion: 1572,
            tx_completion_generation: 1,
            rx_wait_resolution: 1613,
            rx_wait_resolution_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            backpressure: Some(1596),
            backpressure_generation: Some(1),
            sample_packets: 1,
            sample_bytes: 6000,
            tx_completed_packets: u32::MAX,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 120_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19 packet accounting overflow".to_string(),
        },
    ));
    assert_eq!(packet_accounting_overflow.status, CommandStatus::Rejected);
    assert_eq!(
        packet_accounting_overflow.violations,
        vec!["network benchmark packet accounting overflow".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n19_invariants_reject_throughput_metric_drift() {
    let (mut graph, connected_endpoint) = setup_n19_network_benchmark_graph();
    assert!(graph.record_network_benchmark_with_id(
        1614,
        "host-validation-network-throughput-latency",
        1575,
        1,
        1541,
        1,
        1545,
        1,
        1544,
        1,
        1572,
        1,
        1613,
        1,
        connected_endpoint,
        1,
        Some(1596),
        Some(1),
        3,
        6000,
        1,
        1,
        1,
        120_000,
        250_000,
        18_000,
        48_000,
        "n19 benchmark",
    ));
    graph.corrupt_network_benchmark_throughput_for_test(1614, 49_999_999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkBenchmarkInvalid { benchmark: 1614 })
    );
}

pub(super) fn setup_n20_network_recovery_graph() -> SemanticGraph {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "n20-setup",
                SemanticCommand::CreateWait {
                    wait: 1597,
                    owner_task: None,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    kind: SemanticWaitKind::SocketReadable,
                    generation: 1,
                    blockers: vec![blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: Some("n20 pending recv before driver fault".to_string()),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                2,
                "n20-setup",
                SemanticCommand::RecordSocketWait {
                    socket_wait: 1598,
                    wait: 1597,
                    wait_generation: 1,
                    endpoint: connected_endpoint,
                    endpoint_generation: 1,
                    wait_kind: SemanticWaitKind::SocketReadable,
                    blocker,
                    note: "n20 pending socket wait before driver fault".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                3,
                "n20-setup",
                SemanticCommand::RecordNetworkFaultInjection {
                    injection: 1609,
                    adapter: 1575,
                    adapter_generation: 1,
                    packet_device: 1541,
                    packet_device_generation: 1,
                    packet_queue: 1545,
                    packet_queue_generation: 1,
                    packet_descriptor: Some(1547),
                    packet_descriptor_generation: Some(1),
                    packet_buffer: Some(1543),
                    packet_buffer_generation: Some(1),
                    endpoint: Some(connected_endpoint),
                    endpoint_generation: Some(1),
                    direction: PacketBufferDirection::Tx,
                    kind: NetworkFaultInjectionKind::PacketError,
                    effect: NetworkFaultInjectionEffect::ReportError,
                    injected_packets: 1,
                    dropped_packets: 0,
                    error_packets: 1,
                    error_code: "injected-checksum-error".to_string(),
                    sequence: 19,
                    note: "n20 injected packet error before recovery".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert!(graph.cleanup_network_driver_with_id(
        1599,
        1600,
        1575,
        1,
        1541,
        1,
        ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
        "device-fault",
        "n20 network driver cleanup",
    ));
    graph
}

#[test]
pub(super) fn network_runtime_n20_recovery_benchmark_records_cleanup_latency_evidence() {
    let mut graph = setup_n20_network_recovery_graph();
    let cleanup = graph.network_driver_cleanups()[0].clone();
    let result = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n20-test",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 1615,
            scenario: "host-validation-network-driver-recovery".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(1609),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup.completed_at_event.unwrap(),
            cancelled_socket_waits: cleanup.cancelled_socket_waits.len() as u32,
            revoked_packet_capabilities: cleanup.revoked_packet_capabilities.len() as u32,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            note: "n20 recovery benchmark".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.network_recovery_benchmark_count(), 1);
    let benchmark = &graph.network_recovery_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkRecoveryBenchmark, 1615, 1)
    );
    assert_eq!(benchmark.cleanup, 1599);
    assert_eq!(benchmark.io_cleanup, 1600);
    assert_eq!(benchmark.fault_injection, Some(1609));
    assert_eq!(benchmark.cancelled_socket_waits, 1);
    assert_eq!(benchmark.revoked_packet_capabilities, 1);
    assert_eq!(benchmark.recovery_nanos, 90_000);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkRecoveryBenchmarkRecorded benchmark=1615")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn network_runtime_n20_rejects_stale_cleanup_and_budget_overrun() {
    let mut graph = setup_n20_network_recovery_graph();
    let cleanup = graph.network_driver_cleanups()[0].clone();
    let stale_cleanup = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n20-test",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 1615,
            scenario: "host-validation-network-driver-recovery".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation.saturating_add(1),
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(1609),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup.completed_at_event.unwrap(),
            cancelled_socket_waits: cleanup.cancelled_socket_waits.len() as u32,
            revoked_packet_capabilities: cleanup.revoked_packet_capabilities.len() as u32,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            note: "n20 stale cleanup generation".to_string(),
        },
    ));
    assert_eq!(stale_cleanup.status, CommandStatus::Rejected);
    assert_eq!(
        stale_cleanup.violations,
        vec!["network recovery benchmark cleanup generation is missing or incomplete".to_string()]
    );

    let budget_overrun = graph.apply_envelope(CommandEnvelope::new(
        5,
        "n20-test",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 1615,
            scenario: "host-validation-network-driver-recovery".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(1609),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup.completed_at_event.unwrap(),
            cancelled_socket_waits: cleanup.cancelled_socket_waits.len() as u32,
            revoked_packet_capabilities: cleanup.revoked_packet_capabilities.len() as u32,
            recovery_nanos: 210_000,
            budget_nanos: 200_000,
            note: "n20 recovery budget overrun".to_string(),
        },
    ));
    assert_eq!(budget_overrun.status, CommandStatus::Rejected);
    assert_eq!(
        budget_overrun.violations,
        vec!["network recovery benchmark exceeds recovery budget".to_string()]
    );
}

#[test]
pub(super) fn network_runtime_n20_invariants_reject_cleanup_generation_drift() {
    let mut graph = setup_n20_network_recovery_graph();
    let cleanup = graph.network_driver_cleanups()[0].clone();
    assert!(graph.record_network_recovery_benchmark_with_id(
        1615,
        "host-validation-network-driver-recovery",
        cleanup.id,
        cleanup.generation,
        cleanup.io_cleanup,
        cleanup.io_cleanup_generation,
        Some(1609),
        Some(1),
        cleanup.started_at_event,
        cleanup.completed_at_event.unwrap(),
        cleanup.cancelled_socket_waits.len() as u32,
        cleanup.revoked_packet_capabilities.len() as u32,
        90_000,
        200_000,
        "n20 recovery benchmark",
    ));
    graph.corrupt_network_recovery_benchmark_cleanup_generation_for_test(1615, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkRecoveryBenchmarkMissingTarget {
            benchmark: 1615,
            target: ContractObjectRef::new(ContractObjectKind::NetworkDriverCleanup, 1599, 2),
        })
    );
}

#[test]
pub(super) fn network_convergence_d4_preserves_dma_generation_audit_and_wait_cleanup_evidence() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let binding_record =
        graph.driver_store_bindings().iter().find(|record| record.id == 1552).cloned().unwrap();
    let tx_gate =
        graph.network_tx_capability_gates().iter().find(|record| record.id == 1571).unwrap();
    assert_eq!(tx_gate.tx_queue, 1545);
    assert_eq!(tx_gate.device_capability, 1570);
    assert_ne!(tx_gate.capability_generation, 0);
    let tx_queue = graph.packet_queue_objects().iter().find(|record| record.id == 1545).unwrap();
    assert_eq!(tx_queue.role, PacketQueueRole::Tx);
    assert_eq!(tx_queue.packet_device, 1541);

    let rx_queue_ref = ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1544, 1);
    for (command_id, command) in [
        (
            401,
            SemanticCommand::RecordNetworkRxInterrupt {
                rx_interrupt: 1620,
                virtio_net_backend: 1553,
                virtio_net_backend_generation: 1,
                irq_event: 1555,
                irq_event_generation: 1,
                packet_device: 1541,
                packet_device_generation: 1,
                rx_queue: 1544,
                rx_queue_generation: 1,
                ready_descriptors: 1,
                sequence: 4,
                note: "d4 rx queue interrupt evidence".to_string(),
            },
        ),
        (
            402,
            SemanticCommand::CreateWait {
                wait: 1621,
                owner_task: None,
                owner_store: Some(binding_record.driver_store),
                owner_store_generation: Some(binding_record.driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![rx_queue_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("d4-driver-rx-queue-wait".to_string()),
            },
        ),
        (
            403,
            SemanticCommand::RecordIoWait {
                io_wait: 1622,
                wait: 1621,
                wait_generation: 1,
                driver_store: binding_record.driver_store,
                driver_store_generation: binding_record.driver_store_generation,
                device: 1540,
                device_generation: 1,
                driver_binding: 1552,
                driver_binding_generation: 1,
                blocker: rx_queue_ref,
                note: "d4 rx packet queue wait token evidence".to_string(),
            },
        ),
        (
            404,
            SemanticCommand::ResolveNetworkRxWait {
                resolution: 1623,
                io_wait: 1622,
                io_wait_generation: 1,
                rx_interrupt: 1620,
                rx_interrupt_generation: 1,
                note: "d4 rx queue wait resolved by interrupt".to_string(),
            },
        ),
    ] {
        let result = graph.apply_envelope(CommandEnvelope::new(command_id, "d4-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }
    let rx_resolution =
        graph.network_rx_wait_resolutions().iter().find(|record| record.id == 1623).unwrap();
    assert_eq!(rx_resolution.rx_queue, 1544);
    assert_eq!(rx_resolution.wait, 1621);

    let (dma_ref, dma_capability_ref, dma_handle, driver_store, driver_store_generation) =
        add_n17_dma_generation_fixture(&mut graph);
    let stale_packet_buffer = graph.apply_envelope(CommandEnvelope::new(
        405,
        "d4-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1628,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 2,
            slot: 1,
            length: 64,
            note: "d4 stale packet buffer generation".to_string(),
        },
    ));
    assert_eq!(stale_packet_buffer.status, CommandStatus::Rejected);
    let stale_packet_descriptor = graph.apply_envelope(CommandEnvelope::new(
        406,
        "d4-test",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 1629,
            driver_store,
            driver_store_generation,
            packet_descriptor: 1547,
            packet_descriptor_generation: 2,
            device_capability: 1570,
            device_capability_generation: 1,
            handle: graph
                .device_capabilities()
                .iter()
                .find(|record| record.id == 1570)
                .and_then(|record| graph.capabilities().record(record.capability))
                .and_then(|record| record.store_local_handle(vec!["tx".to_string()]))
                .unwrap(),
            note: "d4 stale packet descriptor generation".to_string(),
        },
    ));
    assert_eq!(stale_packet_descriptor.status, CommandStatus::Rejected);
    let stale_dma_target = graph.apply_envelope(CommandEnvelope::new(
        407,
        "d4-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1630,
            driver_store,
            driver_store_generation,
            target: ContractObjectRef::new(ContractObjectKind::DmaBufferObject, dma_ref.id, 2),
            class: CapabilityClass::DmaBuffer,
            operation: "sync-for-device".to_string(),
            handle: dma_handle,
            note: "d4 stale dma buffer generation".to_string(),
        },
    ));
    assert_eq!(stale_dma_target.status, CommandStatus::Rejected);
    let audit = graph.apply_envelope(CommandEnvelope::new(
        408,
        "d4-test",
        SemanticCommand::RecordNetworkGenerationAudit {
            audit: 1608,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: 1547,
            packet_descriptor_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            dma_buffer: dma_ref,
            device_capability: dma_capability_ref,
            rejected_packet_generation_probes: 2,
            rejected_dma_generation_probes: 1,
            note: "d4 historical packet and dma generation audit".to_string(),
        },
    ));
    assert_eq!(audit.status, CommandStatus::Applied, "{audit:?}");

    let socket_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);
    let linux_socket_store = graph.store_id("linux_socket_service").unwrap();
    let linux_socket_store_generation =
        graph.store_handle(linux_socket_store).map(|handle| handle.generation).unwrap();
    for (command_id, command) in [
        (
            409,
            SemanticCommand::CreateWait {
                wait: 1624,
                owner_task: None,
                owner_store: Some(linux_socket_store),
                owner_store_generation: Some(linux_socket_store_generation),
                kind: SemanticWaitKind::SocketReadable,
                generation: 1,
                blockers: vec![socket_blocker],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("d4-pending-socket-wait-before-cleanup".to_string()),
            },
        ),
        (
            410,
            SemanticCommand::RecordSocketWait {
                socket_wait: 1625,
                wait: 1624,
                wait_generation: 1,
                endpoint: connected_endpoint,
                endpoint_generation: 1,
                wait_kind: SemanticWaitKind::SocketReadable,
                blocker: socket_blocker,
                note: "d4 pending socket wait before cleanup".to_string(),
            },
        ),
        (
            411,
            SemanticCommand::CleanupNetworkDriver {
                cleanup: 1626,
                io_cleanup: 1627,
                adapter: 1575,
                adapter_generation: 1,
                packet_device: 1541,
                packet_device_generation: 1,
                backend: ContractObjectRef::new(
                    ContractObjectKind::VirtioNetBackendObject,
                    1553,
                    1,
                ),
                reason: "device-fault".to_string(),
                note: "d4 cleanup after network convergence evidence".to_string(),
            },
        ),
    ] {
        let result = graph.apply_envelope(CommandEnvelope::new(command_id, "d4-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }

    let cleanup = graph.network_driver_cleanups().iter().find(|record| record.id == 1626).unwrap();
    assert_eq!(cleanup.state, NetworkDriverCleanupState::Completed);
    assert_eq!(
        cleanup.cancelled_socket_waits,
        vec![ContractObjectRef::new(ContractObjectKind::SocketWait, 1625, 1)]
    );
    assert_eq!(
        cleanup.cancelled_wait_tokens,
        vec![ContractObjectRef::new(ContractObjectKind::WaitToken, 1624, 1)]
    );
    assert_eq!(
        cleanup.revoked_packet_capabilities,
        vec![ContractObjectRef::new(ContractObjectKind::DeviceCapability, 1570, 1)]
    );
    let io_cleanup = graph.io_cleanups().iter().find(|record| record.id == 1627).unwrap();
    assert!(io_cleanup.released_dma_buffers.contains(&dma_ref));
    assert!(io_cleanup.revoked_device_capabilities.contains(&dma_capability_ref));
    assert!(io_cleanup.revoked_device_capabilities.contains(&ContractObjectRef::new(
        ContractObjectKind::DeviceCapability,
        1570,
        1,
    )));
    let audit = graph.network_generation_audits().iter().find(|record| record.id == 1608).unwrap();
    assert_eq!(audit.dma_buffer, dma_ref);
    assert_eq!(audit.device_capability, dma_capability_ref);
    assert_eq!(audit.state, NetworkGenerationAuditState::Recorded);
    let socket_wait = graph.socket_waits().iter().find(|record| record.id == 1625).unwrap();
    assert_eq!(socket_wait.state, SocketWaitState::Cancelled);
    assert_eq!(socket_wait.cancel_reason, Some(WaitCancelReason::DeviceFault));
    assert_eq!(
        graph.wait_records().iter().find(|record| record.id == 1624).unwrap().state,
        WaitState::Cancelled
    );
    assert!(graph.check_invariants().is_ok());
}
