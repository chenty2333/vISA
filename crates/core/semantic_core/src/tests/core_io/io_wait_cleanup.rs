use super::*;

pub(super) fn setup_i9_io_wait_graph()
-> (SemanticGraph, StoreId, Generation, ContractObjectRef, ContractObjectRef, DriverStoreBindingId)
{
    let (mut graph, driver_store, driver_store_generation, device, _mmio, _dma, irq) =
        setup_i7_device_capability_graph();
    let device_capability = record_i8_device_probe_capability(
        &mut graph,
        driver_store,
        driver_store_generation,
        device,
        1301,
    );
    assert!(graph.record_driver_store_binding_with_id(
        1302,
        driver_store,
        driver_store_generation,
        401,
        1,
        device_capability,
        1,
        "i9 binding harness",
    ));
    (graph, driver_store, driver_store_generation, device, irq, 1302)
}

#[test]
pub(super) fn io_runtime_i9_io_wait_resolves_from_irq_event_with_exact_generations() {
    let (mut graph, driver_store, driver_store_generation, _device, irq, binding) =
        setup_i9_io_wait_graph();

    let create_wait = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i9-test",
        SemanticCommand::CreateWait {
            wait: 1303,
            owner_task: None,
            owner_store: Some(driver_store),
            owner_store_generation: Some(driver_store_generation),
            kind: SemanticWaitKind::DeviceIrq,
            generation: 1,
            blockers: vec![irq],
            deadline: None,
            restart_policy: RestartPolicy::InternalOnly,
            saved_context: Some("driver.fake-io0:rx-irq".to_string()),
        },
    ));
    assert_eq!(create_wait.status, CommandStatus::Applied);

    let record_io_wait = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i9-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1304,
            wait: 1303,
            wait_generation: 1,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: irq,
            note: "io wait blocks on fake irq line".to_string(),
        },
    ));
    assert_eq!(record_io_wait.status, CommandStatus::Applied);
    let index = graph.wait_index();
    assert!(index.by_resource.contains(&(irq, 1303)));
    assert!(index.by_store.contains(&(driver_store, driver_store_generation, 1303)));

    assert_eq!(graph.io_waits().len(), 1);
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Pending);
    assert!(graph.record_irq_event_with_id(
        1305,
        901,
        1,
        401,
        1,
        driver_store,
        driver_store_generation,
        2,
        "fake irq resolves io wait",
    ));
    let resolve = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i9-test",
        SemanticCommand::ResolveIoWait {
            io_wait: 1304,
            io_wait_generation: 1,
            irq_event: 1305,
            irq_event_generation: 1,
            note: "fake irq event resolves wait".to_string(),
        },
    ));
    assert_eq!(resolve.status, CommandStatus::Applied);
    let wait = graph.wait_records().iter().find(|wait| wait.id == 1303).unwrap();
    assert_eq!(wait.state, WaitState::Resolved);
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Resolved);
    assert_eq!(graph.io_waits()[0].completion_irq_event, Some(1305));
    assert_eq!(graph.io_waits()[0].completion_irq_event_generation, Some(1));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IoWaitResolved io_wait=1304 wait=1303@1 irq_event=1305@1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i9_rejects_stale_waits_and_cancels_device_faults() {
    let (mut graph, driver_store, driver_store_generation, _device, irq, binding) =
        setup_i9_io_wait_graph();
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1310,
                owner_task: None,
                owner_store: Some(driver_store),
                owner_store_generation: Some(driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![irq],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: None,
            })
            .is_ok()
    );

    let stale_wait_generation = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i9-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1311,
            wait: 1310,
            wait_generation: 2,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: irq,
            note: "stale wait generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_wait_generation.status, CommandStatus::Rejected);
    assert_eq!(
        stale_wait_generation.violations,
        vec!["io wait token generation is missing or not pending".to_string()]
    );

    let stale_device_generation = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i9-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1311,
            wait: 1310,
            wait_generation: 1,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 2,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: irq,
            note: "stale device generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_device_generation.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device_generation.violations,
        vec!["io wait device generation is missing or inactive".to_string()]
    );

    let other_device_resource = graph.register_resource(ResourceKind::Device, None, "device:other");
    let other_device_resource_generation =
        graph.resource_handle(other_device_resource).unwrap().generation;
    let other_dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:other");
    let other_dma_resource_generation =
        graph.resource_handle(other_dma_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        402,
        "other-io",
        "fake-device",
        other_device_resource,
        other_device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "other-io-v1",
        "other device object",
    ));
    assert!(graph.record_queue_object_with_id(
        502,
        "other-io-rx",
        QueueObjectRole::Rx,
        0,
        64,
        402,
        1,
        "other queue object",
    ));
    assert!(graph.record_descriptor_object_with_id(
        602,
        502,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "other descriptor object",
    ));
    assert!(graph.record_dma_buffer_object_with_id(
        702,
        602,
        1,
        other_dma_resource,
        other_dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        2048,
        "other dma buffer object",
    ));
    let wrong_device_dma = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 702, 1);
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1313,
                owner_task: None,
                owner_store: Some(driver_store),
                owner_store_generation: Some(driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![wrong_device_dma],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: None,
            })
            .is_ok()
    );
    let wrong_dma_device = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i9-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1311,
            wait: 1313,
            wait_generation: 1,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: wrong_device_dma,
            note: "dma blocker from another device must reject".to_string(),
        },
    ));
    assert_eq!(wrong_dma_device.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_dma_device.violations,
        vec!["io wait blocker generation is missing or inactive".to_string()]
    );

    assert!(graph.record_io_wait_with_id(
        1311,
        1310,
        1,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        irq,
        "pending io wait",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i9-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1312,
            wait: 1310,
            wait_generation: 1,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: irq,
            note: "duplicate pending io wait must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["io wait token already has a pending io wait".to_string()]
    );

    let wrong_reason = graph.apply_envelope(CommandEnvelope::new(
        5,
        "i9-test",
        SemanticCommand::CancelIoWait {
            io_wait: 1311,
            io_wait_generation: 1,
            errno: 110,
            reason: WaitCancelReason::Timeout,
            note: "timeout is not an io fault reason".to_string(),
        },
    ));
    assert_eq!(wrong_reason.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_reason.violations,
        vec!["io wait cancellation reason is not an io reason".to_string()]
    );

    let cancel = graph.apply_envelope(CommandEnvelope::new(
        6,
        "i9-test",
        SemanticCommand::CancelIoWait {
            io_wait: 1311,
            io_wait_generation: 1,
            errno: 5,
            reason: WaitCancelReason::DeviceFault,
            note: "fake device fault cancels io wait".to_string(),
        },
    ));
    assert_eq!(cancel.status, CommandStatus::Applied);
    let wait = graph.wait_records().iter().find(|wait| wait.id == 1310).unwrap();
    assert_eq!(wait.state, WaitState::Cancelled);
    assert_eq!(wait.cancel_reason, Some(WaitCancelReason::DeviceFault));
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Cancelled);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IoWaitCancelled io_wait=1311 wait=1310@1 reason=device-fault generation=1"
    );
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_io_wait_blocker_generation_for_test(1311, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IoWaitMissingBlocker {
            io_wait: 1311,
            blocker: ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 2),
        })
    );
}

pub(super) fn setup_i10_io_cleanup_graph()
-> (SemanticGraph, StoreId, Generation, DriverStoreBindingId, IoWaitId) {
    let (mut graph, driver_store, driver_store_generation, device, mmio, dma, irq) =
        setup_i7_device_capability_graph();
    let device_capability = record_i8_device_probe_capability(
        &mut graph,
        driver_store,
        driver_store_generation,
        device,
        1401,
    );
    assert!(graph.record_driver_store_binding_with_id(
        1402,
        driver_store,
        driver_store_generation,
        401,
        1,
        device_capability,
        1,
        "i10 binding harness",
    ));

    let mmio_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "i10-test",
        true,
    );
    let dma_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "dma.fake-io0.rx0",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma),
        &["sync-for-device"],
        "store",
        "i10-test",
        true,
    );
    let irq_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "irq.fake-io0.rx",
        AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq),
        &["ack"],
        "store",
        "i10-test",
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
    assert!(graph.record_device_capability_with_id(
        1403,
        driver_store,
        driver_store_generation,
        mmio,
        CapabilityClass::MmioRegion,
        "write32",
        mmio_handle,
        "i10 mmio capability",
    ));
    assert!(graph.record_device_capability_with_id(
        1404,
        driver_store,
        driver_store_generation,
        dma,
        CapabilityClass::DmaBuffer,
        "sync-for-device",
        dma_handle,
        "i10 dma capability",
    ));
    assert!(graph.record_device_capability_with_id(
        1405,
        driver_store,
        driver_store_generation,
        irq,
        CapabilityClass::IrqLine,
        "ack",
        irq_handle,
        "i10 irq capability",
    ));
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1406,
                owner_task: None,
                owner_store: Some(driver_store),
                owner_store_generation: Some(driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![irq],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("driver.fake-io0:cleanup-rx".to_string()),
            })
            .is_ok()
    );
    assert!(graph.record_io_wait_with_id(
        1407,
        1406,
        1,
        driver_store,
        driver_store_generation,
        401,
        1,
        1402,
        1,
        irq,
        "i10 pending io wait",
    ));
    assert!(graph.record_irq_event_with_id(
        1409,
        901,
        1,
        401,
        1,
        driver_store,
        driver_store_generation,
        1,
        "i10 historical irq event before cleanup",
    ));
    (graph, driver_store, driver_store_generation, 1402, 1407)
}

#[test]
pub(super) fn io_runtime_i10_cleanup_cancels_waits_revokes_caps_and_releases_io_objects() {
    let (mut graph, driver_store, driver_store_generation, binding, io_wait) =
        setup_i10_io_cleanup_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i10-test",
        SemanticCommand::CleanupIoDriver {
            cleanup: 1408,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            reason: "device-fault".to_string(),
            note: "i10 io cleanup harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.io_cleanup_count(), 1);
    let cleanup = &graph.io_cleanups()[0];
    assert_eq!(cleanup.state, IoCleanupState::Completed);
    assert_eq!(cleanup.cancelled_io_waits.len(), 1);
    assert_eq!(cleanup.cancelled_io_waits[0].id, io_wait);
    assert_eq!(cleanup.revoked_device_capabilities.len(), 4);
    assert_eq!(cleanup.revoked_capabilities.len(), 4);
    assert_eq!(cleanup.released_dma_buffers.len(), 1);
    assert_eq!(cleanup.released_mmio_regions.len(), 1);
    assert_eq!(cleanup.released_irq_lines.len(), 1);
    assert!(cleanup.steps.iter().any(|step| step.kind == IoCleanupStepKind::CancelIoWaits
        && step.status == IoCleanupStepStatus::Done));

    let wait = graph.wait_records().iter().find(|record| record.id == 1406).unwrap();
    assert_eq!(wait.state, WaitState::Cancelled);
    assert_eq!(wait.cancel_reason, Some(WaitCancelReason::DeviceFault));
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Cancelled);
    assert!(
        graph
            .device_capabilities()
            .iter()
            .filter(|record| record.driver_store == driver_store
                && record.driver_store_generation == driver_store_generation)
            .all(|record| record.state == DeviceCapabilityState::Revoked)
    );
    assert_eq!(graph.driver_store_bindings()[0].state, DriverStoreBindingState::Released);
    assert_eq!(graph.dma_buffer_objects()[0].state, DmaBufferObjectState::Released);
    assert_eq!(graph.mmio_region_objects()[0].state, MmioRegionObjectState::Released);
    assert_eq!(graph.irq_line_objects()[0].state, IrqLineObjectState::Released);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IoCleanupCompleted cleanup=1408 driver_store=1@2 device=401@1 driver_binding=1402@1 cancelled_io_waits=1 revoked_device_capabilities=4 released_dma_buffers=1 released_mmio_regions=1 released_irq_lines=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());

    let cleanup_count = graph.io_cleanup_count();
    let replay = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i10-test",
        SemanticCommand::CleanupIoDriver {
            cleanup: 1408,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            reason: "device-fault".to_string(),
            note: "i10 idempotent replay".to_string(),
        },
    ));
    assert_eq!(replay.status, CommandStatus::Applied);
    assert_eq!(graph.io_cleanup_count(), cleanup_count);
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i10_rejects_stale_cleanup_and_blocks_post_cleanup_wait_reuse() {
    let (mut graph, driver_store, driver_store_generation, binding, _io_wait) =
        setup_i10_io_cleanup_graph();
    let stale_device = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i10-test",
        SemanticCommand::CleanupIoDriver {
            cleanup: 1410,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 2,
            driver_binding: binding,
            driver_binding_generation: 1,
            reason: "device-fault".to_string(),
            note: "stale device cleanup must reject".to_string(),
        },
    ));
    assert_eq!(stale_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device.violations,
        vec!["io cleanup device generation is missing or inactive".to_string()]
    );

    assert!(graph.cleanup_io_driver_for_device_fault_with_id(
        1410,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        "device-fault",
        "cleanup before wait reuse",
    ));
    let irq = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1);
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1411,
                owner_task: None,
                owner_store: Some(driver_store),
                owner_store_generation: Some(driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![irq],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: None,
            })
            .is_ok()
    );
    let post_cleanup_wait = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i10-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1412,
            wait: 1411,
            wait_generation: 1,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: irq,
            note: "released binding must reject new io wait".to_string(),
        },
    ));
    assert_eq!(post_cleanup_wait.status, CommandStatus::Rejected);
    assert_eq!(
        post_cleanup_wait.violations,
        vec!["io wait driver binding generation is missing or inactive".to_string()]
    );

    graph.corrupt_io_cleanup_cancelled_wait_for_test(1410, 1407);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IoWaitMissingBlocker { io_wait: 1407, blocker: irq })
    );
}

#[test]
pub(super) fn io_runtime_i11_fault_injection_triggers_cleanup_with_exact_generations() {
    let (mut graph, driver_store, driver_store_generation, binding, io_wait) =
        setup_i10_io_cleanup_graph();
    let target = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i11-test",
        SemanticCommand::InjectIoFault {
            fault: 1411,
            cleanup: 1412,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            target,
            kind: IoFaultInjectionKind::DeviceFault,
            note: "i11 injected irq fault".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.io_fault_injection_count(), 1);
    assert_eq!(graph.io_cleanup_count(), 1);
    let fault = &graph.io_fault_injections()[0];
    assert_eq!(fault.state, IoFaultInjectionState::Completed);
    assert_eq!(fault.kind, IoFaultInjectionKind::DeviceFault);
    assert_eq!(fault.target, target);
    assert_eq!(fault.cleanup, 1412);
    assert_eq!(fault.cleanup_generation, 1);
    assert_eq!(graph.io_cleanups()[0].cancelled_io_waits[0].id, io_wait);
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Cancelled);
    assert_eq!(graph.irq_line_objects()[0].state, IrqLineObjectState::Released);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IoFaultInjected fault=1411 kind=device-fault driver_store=1@2 device=401@1 driver_binding=1402@1 target=irq-line-object:901@1 cleanup=1412@1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());

    let replay = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i11-test",
        SemanticCommand::InjectIoFault {
            fault: 1411,
            cleanup: 1412,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            target,
            kind: IoFaultInjectionKind::DeviceFault,
            note: "i11 idempotent replay".to_string(),
        },
    ));
    assert_eq!(replay.status, CommandStatus::Applied);
    assert_eq!(graph.io_fault_injection_count(), 1);
    assert_eq!(graph.io_cleanup_count(), 1);
}

#[test]
pub(super) fn io_runtime_i11_rejects_stale_or_post_cleanup_fault_injection() {
    let (mut graph, driver_store, driver_store_generation, binding, _io_wait) =
        setup_i10_io_cleanup_graph();
    let stale_target = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i11-test",
        SemanticCommand::InjectIoFault {
            fault: 1413,
            cleanup: 1414,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            target: ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 2),
            kind: IoFaultInjectionKind::DeviceFault,
            note: "stale irq generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_target.status, CommandStatus::Rejected);
    assert_eq!(
        stale_target.violations,
        vec!["io fault injection target generation is missing or inactive".to_string()]
    );

    assert!(graph.inject_io_fault_with_id(
        1413,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
        1414,
        IoFaultInjectionKind::DeviceFault,
        "cleanup before second fault",
    ));
    let post_cleanup = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i11-test",
        SemanticCommand::InjectIoFault {
            fault: 1415,
            cleanup: 1416,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            target: ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
            kind: IoFaultInjectionKind::DeviceFault,
            note: "released binding must reject second fault".to_string(),
        },
    ));
    assert_eq!(post_cleanup.status, CommandStatus::Rejected);
    assert_eq!(
        post_cleanup.violations,
        vec!["io fault injection driver binding is not bound to target".to_string()]
    );

    graph.corrupt_io_fault_cleanup_ref_for_test(1413, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IoFaultInjectionMissingCleanup { fault: 1413, cleanup: 1414 })
    );
}

#[test]
pub(super) fn io_runtime_i12_validator_reports_clean_io_subgraph() {
    let (mut graph, driver_store, driver_store_generation, binding, _io_wait) =
        setup_i10_io_cleanup_graph();
    assert!(graph.inject_io_fault_with_id(
        1417,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
        1418,
        IoFaultInjectionKind::DeviceFault,
        "i12 cleanup before validation",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i12-test",
        SemanticCommand::ValidateIoRuntime {
            report: 1419,
            note: "i12 clean validator".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.io_validation_report_count(), 1);
    let report = &graph.io_validation_reports()[0];
    assert_eq!(report.state, IoValidationReportState::Passed);
    assert!(report.violations.is_empty());
    assert_eq!(report.observed_device_count, 1);
    assert_eq!(report.observed_io_cleanup_count, 1);
    assert_eq!(report.observed_io_fault_injection_count, 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IoValidationReportRecorded report=1419 ok=true violations=0 devices=1 dma_buffers=1 irq_events=1 cleanups=1 fault_injections=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn io_runtime_i12_validator_records_generation_violations_without_hiding_them() {
    let (mut graph, driver_store, driver_store_generation, binding, io_wait) =
        setup_i10_io_cleanup_graph();
    assert!(graph.inject_io_fault_with_id(
        1420,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
        1421,
        IoFaultInjectionKind::DeviceFault,
        "i12 cleanup before negative validation",
    ));
    graph.corrupt_io_wait_driver_binding_generation_for_test(io_wait, 2);

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i12-test",
        SemanticCommand::ValidateIoRuntime { report: 1422, note: "i12 bad validator".to_string() },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    let report = &graph.io_validation_reports()[0];
    assert_eq!(report.state, IoValidationReportState::Failed);
    assert!(report.violations.iter().any(|violation| {
        violation.code == IoValidationViolationCode::StaleGeneration
            && violation.subject.kind == ContractObjectKind::IoWait
            && violation.subject.id == io_wait
            && violation.relation == "io-wait->driver-binding"
    }));
}

#[test]
pub(super) fn io_runtime_i12_validator_rejects_future_cleanup_capability_generation() {
    let (mut graph, driver_store, driver_store_generation, binding, _io_wait) =
        setup_i10_io_cleanup_graph();
    assert!(graph.inject_io_fault_with_id(
        1423,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
        1424,
        IoFaultInjectionKind::DeviceFault,
        "i12 cleanup before capability-generation validation",
    ));
    graph.corrupt_io_cleanup_revoked_capability_generation_for_test(1424, 999);

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i12-test",
        SemanticCommand::ValidateIoRuntime {
            report: 1425,
            note: "i12 future capability generation validator".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    let report = &graph.io_validation_reports()[0];
    assert_eq!(report.state, IoValidationReportState::Failed);
    assert!(report.violations.iter().any(|violation| {
        violation.code == IoValidationViolationCode::StaleGeneration
            && violation.subject.kind == ContractObjectKind::IoCleanup
            && violation.subject.id == 1424
            && violation.relation == "io-cleanup->effect"
    }));
}
