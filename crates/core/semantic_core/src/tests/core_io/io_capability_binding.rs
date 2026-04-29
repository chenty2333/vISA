use super::*;

pub(in crate::tests) fn setup_i7_device_capability_graph() -> (
    SemanticGraph,
    StoreId,
    Generation,
    ContractObjectRef,
    ContractObjectRef,
    ContractObjectRef,
    ContractObjectRef,
) {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:fake-io0-rx0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    let mmio_resource = graph.register_resource(ResourceKind::MmioRegion, None, "mmio:fake-io0");
    let mmio_resource_generation = graph.resource_handle(mmio_resource).unwrap().generation;
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "queue object harness",
    ));
    assert!(graph.record_descriptor_object_with_id(
        601,
        501,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "descriptor object harness",
    ));
    assert!(graph.record_dma_buffer_object_with_id(
        701,
        601,
        1,
        dma_resource,
        dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        2048,
        "dma buffer object harness",
    ));
    assert!(graph.record_mmio_region_object_with_id(
        801,
        401,
        1,
        mmio_resource,
        mmio_resource_generation,
        0,
        0x1000,
        0x100,
        MmioRegionObjectAccess::ReadWrite,
        "mmio region object harness",
    ));
    assert!(graph.record_irq_line_object_with_id(
        901,
        401,
        1,
        irq_resource,
        irq_resource_generation,
        5,
        IrqLineTrigger::Level,
        IrqLinePolarity::ActiveHigh,
        "irq line object harness",
    ));
    let driver_store = graph.register_store(
        "driver.fake-io0",
        "driver.fake-io0.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    (
        graph,
        driver_store,
        driver_store_generation,
        ContractObjectRef::new(ContractObjectKind::DeviceObject, 401, 1),
        ContractObjectRef::new(ContractObjectKind::MmioRegionObject, 801, 1),
        ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 701, 1),
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
    )
}

#[test]
pub(super) fn io_runtime_i7_device_capability_records_store_local_authority() {
    let (mut graph, driver_store, driver_store_generation, _device, mmio, dma, irq) =
        setup_i7_device_capability_graph();
    let mmio_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "i7-test",
        true,
    );
    let dma_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "dma.fake-io0.rx0",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma),
        &["sync-for-device"],
        "store",
        "i7-test",
        true,
    );
    let irq_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "irq.fake-io0.rx",
        AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq),
        &["ack"],
        "store",
        "i7-test",
        true,
    );
    let mmio_handle = graph
        .capabilities()
        .record(mmio_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    let dma_handle = graph
        .capabilities()
        .record(dma_cap)
        .and_then(|record| record.store_local_handle(vec!["sync-for-device".to_string()]))
        .unwrap();
    let irq_handle = graph
        .capabilities()
        .record(irq_cap)
        .and_then(|record| record.store_local_handle(vec!["ack".to_string()]))
        .unwrap();
    let cursor_before = graph.event_log().cursor();

    let mmio_result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1101,
            driver_store,
            driver_store_generation,
            target: mmio,
            class: CapabilityClass::MmioRegion,
            operation: "write32".to_string(),
            handle: mmio_handle.clone(),
            note: "mmio capability harness".to_string(),
        },
    ));
    let dma_result = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1102,
            driver_store,
            driver_store_generation,
            target: dma,
            class: CapabilityClass::DmaBuffer,
            operation: "sync-for-device".to_string(),
            handle: dma_handle,
            note: "dma capability harness".to_string(),
        },
    ));
    let irq_result = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1103,
            driver_store,
            driver_store_generation,
            target: irq,
            class: CapabilityClass::IrqLine,
            operation: "ack".to_string(),
            handle: irq_handle,
            note: "irq capability harness".to_string(),
        },
    ));

    assert_eq!(mmio_result.status, CommandStatus::Applied);
    assert_eq!(dma_result.status, CommandStatus::Applied);
    assert_eq!(irq_result.status, CommandStatus::Applied);
    assert_eq!(graph.device_capabilities().len(), 3);
    let record = &graph.device_capabilities()[0];
    assert_eq!(record.id, 1101);
    assert_eq!(record.driver_store, driver_store);
    assert_eq!(record.driver_store_generation, driver_store_generation);
    assert_eq!(record.target, mmio);
    assert_eq!(record.class, CapabilityClass::MmioRegion);
    assert_eq!(record.operation, "write32");
    assert_eq!(record.capability, mmio_cap);
    assert_eq!(record.handle_slot, mmio_handle.slot);
    assert_eq!(record.handle_generation, mmio_handle.generation);
    assert_eq!(record.handle_tag, mmio_handle.tag);
    assert_eq!(record.state, DeviceCapabilityState::Active);
    assert!(record.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DeviceCapabilityRecorded device_capability=1103 driver_store={driver_store}@{driver_store_generation} target={} class=irq-line operation=ack capability={irq_cap}@1 handle_slot=3 handle_generation=1 generation=1",
            irq.summary()
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i7_rejects_label_only_stale_revoked_or_duplicate_capability() {
    let (mut graph, driver_store, driver_store_generation, _device, mmio, _dma, _irq) =
        setup_i7_device_capability_graph();
    let label_cap =
        graph.grant_capability("driver.fake-io0", "mmio.fake-io0.regs", &["write32"], "store");
    let label_handle = graph
        .capabilities()
        .record(label_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    let label_only = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1101,
            driver_store,
            driver_store_generation,
            target: mmio,
            class: CapabilityClass::MmioRegion,
            operation: "write32".to_string(),
            handle: label_handle,
            note: "debug label object ref must not authorize".to_string(),
        },
    ));
    assert_eq!(label_only.status, CommandStatus::Rejected);
    assert_eq!(
        label_only.violations,
        vec!["device capability handle is not authorized".to_string()]
    );

    let exact_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "i7-test",
        true,
    );
    let exact_handle = graph
        .capabilities()
        .record(exact_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    let exact_generation = graph.capabilities().record(exact_cap).unwrap().generation;
    let stale_target = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1101,
            driver_store,
            driver_store_generation,
            target: ContractObjectRef::new(ContractObjectKind::MmioRegionObject, 801, 2),
            class: CapabilityClass::MmioRegion,
            operation: "write32".to_string(),
            handle: exact_handle.clone(),
            note: "stale target generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_target.status, CommandStatus::Rejected);
    assert_eq!(
        stale_target.violations,
        vec!["device capability target generation is missing or inactive".to_string()]
    );

    assert!(graph.revoke_capability_generation(exact_cap, exact_generation));
    let revoked = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1101,
            driver_store,
            driver_store_generation,
            target: mmio,
            class: CapabilityClass::MmioRegion,
            operation: "write32".to_string(),
            handle: exact_handle,
            note: "revoked capability must reject".to_string(),
        },
    ));
    assert_eq!(revoked.status, CommandStatus::Rejected);
    assert_eq!(revoked.violations, vec!["device capability handle is not authorized".to_string()]);

    let fresh_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "i7-test",
        true,
    );
    let fresh_handle = graph
        .capabilities()
        .record(fresh_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1101,
        driver_store,
        driver_store_generation,
        mmio,
        CapabilityClass::MmioRegion,
        "write32",
        fresh_handle.clone(),
        "first device capability",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1102,
            driver_store,
            driver_store_generation,
            target: mmio,
            class: CapabilityClass::MmioRegion,
            operation: "write32".to_string(),
            handle: fresh_handle,
            note: "duplicate target operation must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["device capability target operation already has an active grant".to_string()]
    );

    graph.corrupt_device_capability_target_generation_for_test(1101, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DeviceCapabilityMissingTarget {
            device_capability: 1101,
            target: ContractObjectRef::new(ContractObjectKind::MmioRegionObject, 801, 2),
        })
    );
}

pub(in crate::tests) fn record_i8_device_probe_capability(
    graph: &mut SemanticGraph,
    driver_store: StoreId,
    driver_store_generation: Generation,
    device: ContractObjectRef,
    id: DeviceCapabilityId,
) -> DeviceCapabilityId {
    let cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "device.fake-io0",
        AuthorityObjectRef::internal(CapabilityClass::Device, device),
        &["probe"],
        "store",
        "i8-test",
        true,
    );
    let handle = graph
        .capabilities()
        .record(cap)
        .and_then(|record| record.store_local_handle(vec!["probe".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        id,
        driver_store,
        driver_store_generation,
        device,
        CapabilityClass::Device,
        "probe",
        handle,
        "device probe capability",
    ));
    id
}

#[test]
pub(super) fn io_runtime_i8_driver_store_binding_records_exact_driver_and_device_identity() {
    let (mut graph, driver_store, driver_store_generation, device, _mmio, _dma, _irq) =
        setup_i7_device_capability_graph();
    let device_capability = record_i8_device_probe_capability(
        &mut graph,
        driver_store,
        driver_store_generation,
        device,
        1201,
    );
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i8-test",
        SemanticCommand::BindDriverStore {
            binding: 1202,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            device_capability,
            device_capability_generation: 1,
            note: "driver store binding harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.driver_store_bindings().len(), 1);
    let binding = &graph.driver_store_bindings()[0];
    assert_eq!(binding.id, 1202);
    assert_eq!(binding.driver_store, driver_store);
    assert_eq!(binding.driver_store_generation, driver_store_generation);
    assert_eq!(binding.device, 401);
    assert_eq!(binding.device_generation, 1);
    assert_eq!(binding.device_capability, device_capability);
    assert_eq!(binding.device_capability_generation, 1);
    assert_eq!(binding.state, DriverStoreBindingState::Bound);
    assert!(binding.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DriverStoreBound binding=1202 driver_store={driver_store}@{driver_store_generation} device=401@1 device_capability=1201@1 capability={}@1 generation=1",
            binding.capability
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i8_rejects_stale_wrong_or_duplicate_driver_store_binding() {
    let (mut graph, driver_store, driver_store_generation, device, mmio, _dma, _irq) =
        setup_i7_device_capability_graph();
    let device_capability = record_i8_device_probe_capability(
        &mut graph,
        driver_store,
        driver_store_generation,
        device,
        1201,
    );

    let stale_device_capability = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i8-test",
        SemanticCommand::BindDriverStore {
            binding: 1202,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            device_capability,
            device_capability_generation: 2,
            note: "stale device capability generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_device_capability.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device_capability.violations,
        vec![
            "driver store binding device capability generation is missing or inactive".to_string()
        ]
    );

    let stale_device = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i8-test",
        SemanticCommand::BindDriverStore {
            binding: 1202,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 2,
            device_capability,
            device_capability_generation: 1,
            note: "stale device generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device.violations,
        vec!["driver store binding device generation is missing or inactive".to_string()]
    );

    let wrong_class_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "i8-test",
        true,
    );
    let wrong_class_handle = graph
        .capabilities()
        .record(wrong_class_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1203,
        driver_store,
        driver_store_generation,
        mmio,
        CapabilityClass::MmioRegion,
        "write32",
        wrong_class_handle,
        "wrong-class capability",
    ));
    let wrong_class = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i8-test",
        SemanticCommand::BindDriverStore {
            binding: 1202,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            device_capability: 1203,
            device_capability_generation: 1,
            note: "wrong target/class capability must reject".to_string(),
        },
    ));
    assert_eq!(wrong_class.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_class.violations,
        vec!["driver store binding device capability does not authorize binding".to_string()]
    );

    assert!(graph.record_driver_store_binding_with_id(
        1202,
        driver_store,
        driver_store_generation,
        401,
        1,
        device_capability,
        1,
        "first binding",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i8-test",
        SemanticCommand::BindDriverStore {
            binding: 1204,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            device_capability,
            device_capability_generation: 1,
            note: "duplicate active binding must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["driver store binding device already has an active driver".to_string()]
    );

    graph.corrupt_driver_store_binding_device_generation_for_test(1202, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DriverStoreBindingMissingDevice { binding: 1202, device: 401 })
    );
}
