use super::*;

pub(in crate::tests) fn add_x4_block_benchmark_evidence(graph: &mut SemanticGraph) {
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:x4-blk9");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1823,
        "fake-block9",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "x4 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1824,
        "blk9",
        1823,
        1,
        512,
        4096,
        false,
        128,
        "x4 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1825, 1824, 1, 128, 8, "x4 block range"));
    assert!(graph.record_block_request_object_with_id(
        1826,
        1824,
        1,
        1825,
        1,
        BlockRequestOperation::Read,
        1,
        "x4 completed read request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1827,
        1826,
        1,
        1,
        4096,
        BlockCompletionStatus::Success,
        "x4 read completion",
    ));
    assert!(graph.record_block_request_object_with_id(
        1828,
        1824,
        1,
        1825,
        1,
        BlockRequestOperation::Write,
        2,
        "x4 completed write request",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1829,
        "fake-block9",
        1824,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b39,
        "x4 fake block backend",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1830,
        1828,
        1,
        2,
        4096,
        BlockCompletionStatus::Success,
        "x4 write completion",
    ));
    assert!(graph.record_queue_object_with_id(
        1831,
        "fake-block9-submit",
        QueueObjectRole::Submission,
        0,
        8,
        1823,
        1,
        "x4 block submission queue",
    ));
    assert!(graph.record_descriptor_object_with_id(
        1832,
        1831,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        4096,
        "x4 block dma descriptor",
    ));
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:x4-block9-buf0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_dma_buffer_object_with_id(
        1833,
        1832,
        1,
        dma_resource,
        dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        4096,
        "x4 block dma buffer",
    ));
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let read_digest = SemanticGraph::expected_block_read_digest_v1(
        0x766d_6f73_626c_6b39,
        1824,
        1,
        1825,
        1,
        128,
        8,
        1,
        4096,
    );
    let write_digest = SemanticGraph::expected_block_write_payload_digest_v1(
        0x766d_6f73_626c_6b39,
        1824,
        1,
        1825,
        1,
        128,
        8,
        2,
        4096,
    );
    assert!(graph.record_block_read_path_with_id(
        1846,
        backend,
        1826,
        1,
        1827,
        1,
        read_digest,
        "x4 benchmark read path",
    ));
    assert!(graph.record_block_write_path_with_id(
        1847,
        backend,
        1828,
        1,
        1830,
        1,
        write_digest,
        "x4 benchmark write path",
    ));
    assert!(graph.record_block_request_queue_with_id(
        1848,
        backend,
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::completed(1828, 1, 1830, 1),
        ],
        "x4 benchmark completed queue",
    ));
    assert!(graph.record_block_dma_buffer_with_id(
        1849,
        backend,
        1828,
        1,
        1833,
        1,
        b10_expected_digest(DmaBufferObjectAccess::ReadWrite),
        "x4 benchmark dma-backed write",
    ));
}

pub(in crate::tests) fn x4_network_disk_concurrent_io_graph() -> SemanticGraph {
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
        "x4 network throughput latency benchmark",
    ));
    add_x4_block_benchmark_evidence(&mut graph);
    assert!(graph.record_block_benchmark_with_id(
        1850,
        "fake block read/write benchmark",
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        1825,
        1,
        1846,
        1,
        1847,
        1,
        1848,
        1,
        1849,
        1,
        2,
        8192,
        1,
        1,
        2,
        40_000,
        80_000,
        18_000,
        35_000,
        "x4 block IOPS latency benchmark",
    ));
    graph
}

#[test]
pub(in crate::tests) fn integrated_runtime_x4_records_network_disk_concurrent_io() {
    let mut graph = x4_network_disk_concurrent_io_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        4,
        "x4-test",
        SemanticCommand::RecordIntegratedNetworkDiskIo {
            integrated: 701,
            scenario: "x4-network-disk-concurrent-io".to_string(),
            network_benchmark: 1614,
            network_benchmark_generation: 1,
            block_benchmark: 1850,
            block_benchmark_generation: 1,
            invariant_checks: 6,
            note: "integrate network and disk concurrent IO benchmark evidence".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.integrated_network_disk_io_count(), 1);
    let record = &graph.integrated_network_disk_ios()[0];
    assert_eq!(record.id, 701);
    assert_eq!(record.network_benchmark, 1614);
    assert_eq!(record.block_benchmark, 1850);
    assert_eq!(record.network_sample_bytes, 6000);
    assert_eq!(record.block_sample_bytes, 8192);
    assert_eq!(record.concurrent_window_nanos, 120_000);
    assert_eq!(record.combined_throughput_bytes_per_sec, 118_266_666);
    assert_eq!(record.max_p99_latency_nanos, 48_000);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IntegratedNetworkDiskIoRecorded integrated=701 scenario=x4-network-disk-concurrent-io network_benchmark=1614@1 block_benchmark=1850@1 network_owner_store=2@2 packet_device=1541@1 block_device=1824@1 network_bytes=6000 block_bytes=8192 window_nanos=120000 combined_throughput=118266666 max_p99_latency=48000 invariant_checks=6 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn integrated_runtime_x4_rejects_missing_or_stale_benchmark_refs() {
    let missing = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x4-test",
        SemanticCommand::RecordIntegratedNetworkDiskIo {
            integrated: 701,
            scenario: "x4-network-disk-concurrent-io".to_string(),
            network_benchmark: 1614,
            network_benchmark_generation: 1,
            block_benchmark: 1850,
            block_benchmark_generation: 1,
            invariant_checks: 6,
            note: "missing evidence rejects".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    assert_eq!(
        missing.violations,
        vec!["integrated network/disk IO missing network benchmark evidence".to_string()]
    );

    let stale = x4_network_disk_concurrent_io_graph().apply_envelope(CommandEnvelope::new(
        2,
        "x4-test",
        SemanticCommand::RecordIntegratedNetworkDiskIo {
            integrated: 701,
            scenario: "x4-network-disk-concurrent-io".to_string(),
            network_benchmark: 1614,
            network_benchmark_generation: 1,
            block_benchmark: 1850,
            block_benchmark_generation: 2,
            invariant_checks: 6,
            note: "stale block benchmark rejects".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["integrated network/disk IO missing block benchmark evidence".to_string()]
    );
}

#[test]
pub(in crate::tests) fn integrated_runtime_x4_contract_graph_rejects_block_dma_generation_drift() {
    let mut graph = x4_network_disk_concurrent_io_graph();
    assert!(graph.record_integrated_network_disk_io_with_id(
        701,
        "x4-network-disk-concurrent-io",
        1614,
        1,
        1850,
        1,
        6,
        "integrated network/disk IO",
    ));
    let mut integrated = graph.integrated_network_disk_ios().to_vec();
    integrated[0].block_dma_buffer_generation = 99;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_network_disk_ios: integrated,
        network_benchmarks: graph.network_benchmarks().to_vec(),
        block_benchmarks: graph.block_benchmarks().to_vec(),
        stores: graph.stores().to_vec(),
        network_stack_adapters: graph.network_stack_adapters().to_vec(),
        packet_device_objects: graph.packet_device_objects().to_vec(),
        socket_objects: graph.socket_objects().to_vec(),
        fake_block_backends: graph.fake_block_backends().to_vec(),
        block_device_objects: graph.block_device_objects().to_vec(),
        block_request_queues: graph.block_request_queues().to_vec(),
        block_dma_buffers: graph.block_dma_buffers().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-network-disk-io->block-dma-buffer"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(in crate::tests) fn x5_display_scheduler_load_graph() -> SemanticGraph {
    let (mut graph, owner_store, owner_store_generation, sample_bytes, frame_area_pixels) =
        g12_framebuffer_benchmark_graph();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.record_timer_interrupt_with_id(
        5,
        1,
        1,
        hart_generation,
        Some(11),
        Some(3),
        "x5 timer tick"
    ));
    assert!(graph.preempt_running_activation_with_id(6, 11, 3, 5, 1, 1, "x5 timer preempt"));
    assert!(graph.record_scheduler_decision_with_id(
        14,
        1,
        1,
        11,
        4,
        "display-update-load",
        "x5 scheduler decision"
    ));
    assert!(graph.record_framebuffer_benchmark_with_id(
        25_101,
        "display-g12-single-flush",
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_501,
        1,
        23_601,
        1,
        23_801,
        1,
        24_011,
        1,
        1,
        sample_bytes,
        frame_area_pixels,
        40_000,
        60_000,
        100_000,
        200_000,
        100_000,
        100_000,
        "x5 framebuffer benchmark",
    ));
    graph
}

#[test]
pub(in crate::tests) fn integrated_runtime_x5_records_display_scheduler_load() {
    let mut graph = x5_display_scheduler_load_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        5,
        "x5-test",
        SemanticCommand::RecordIntegratedDisplaySchedulerLoad {
            integrated: 801,
            scenario: "x5-display-update-during-scheduler-load".to_string(),
            framebuffer_benchmark: 25_101,
            framebuffer_benchmark_generation: 1,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            invariant_checks: 6,
            note: "integrate display update and scheduler load evidence".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.integrated_display_scheduler_load_count(), 1);
    let record = &graph.integrated_display_scheduler_loads()[0];
    assert_eq!(record.id, 801);
    assert_eq!(record.framebuffer_benchmark, 25_101);
    assert_eq!(record.scheduler_decision, 14);
    assert_eq!(record.owner_task, 7);
    assert_eq!(record.queue, 1);
    assert_eq!(record.selected_activation, 11);
    assert_eq!(record.display, 23_101);
    assert_eq!(record.framebuffer, 23_001);
    assert_eq!(record.sample_frames, 1);
    assert_eq!(record.sample_bytes, 3_200);
    assert_eq!(record.scheduler_load_units, 1);
    assert_eq!(record.display_measured_nanos, 100_000);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IntegratedDisplaySchedulerLoadRecorded integrated=801 scenario=x5-display-update-during-scheduler-load framebuffer_benchmark=25101@1 scheduler_decision=14@1 owner_store=1@2 queue=1@1 activation=11@4 display=23101@1 framebuffer=23001@1 sample_frames=1 sample_bytes=3200 scheduler_load_units=1 display_measured_nanos=100000 invariant_checks=6 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn integrated_runtime_x5_rejects_missing_or_stale_evidence_refs() {
    let missing = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x5-test",
        SemanticCommand::RecordIntegratedDisplaySchedulerLoad {
            integrated: 801,
            scenario: "x5-display-update-during-scheduler-load".to_string(),
            framebuffer_benchmark: 25_101,
            framebuffer_benchmark_generation: 1,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            invariant_checks: 6,
            note: "missing evidence rejects".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    assert_eq!(
        missing.violations,
        vec![
            "integrated display/scheduler load missing framebuffer benchmark evidence".to_string()
        ]
    );

    let stale = x5_display_scheduler_load_graph().apply_envelope(CommandEnvelope::new(
        2,
        "x5-test",
        SemanticCommand::RecordIntegratedDisplaySchedulerLoad {
            integrated: 801,
            scenario: "x5-display-update-during-scheduler-load".to_string(),
            framebuffer_benchmark: 25_101,
            framebuffer_benchmark_generation: 1,
            scheduler_decision: 14,
            scheduler_decision_generation: 2,
            invariant_checks: 6,
            note: "stale scheduler decision rejects".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["integrated display/scheduler load missing scheduler decision evidence".to_string()]
    );
}

#[test]
pub(in crate::tests) fn integrated_runtime_x5_contract_graph_rejects_scheduler_generation_drift() {
    let mut graph = x5_display_scheduler_load_graph();
    assert!(graph.record_integrated_display_scheduler_load_with_id(
        801,
        "x5-display-update-during-scheduler-load",
        25_101,
        1,
        14,
        1,
        6,
        "integrated display scheduler load",
    ));
    let mut integrated = graph.integrated_display_scheduler_loads().to_vec();
    integrated[0].scheduler_decision_generation = 99;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_display_scheduler_loads: integrated,
        framebuffer_benchmarks: graph.framebuffer_benchmarks().to_vec(),
        scheduler_decisions: graph.scheduler_decisions().to_vec(),
        stores: graph.stores().to_vec(),
        tasks: graph.tasks().to_vec(),
        runtime_activations: graph.runtime_activations().to_vec(),
        runnable_queues: graph.runnable_queues().to_vec(),
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        display_capabilities: graph.display_capabilities().to_vec(),
        framebuffer_writes: graph.framebuffer_writes().to_vec(),
        framebuffer_flush_regions: graph.framebuffer_flush_regions().to_vec(),
        display_event_logs: graph.display_event_logs().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-display-scheduler-load->scheduler-decision"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(in crate::tests) fn add_i10_io_cleanup_setup_to_graph(
    graph: &mut SemanticGraph,
) -> (StoreId, Generation, DriverStoreBindingId) {
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
        "x6 device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "x6 queue object harness",
    ));
    assert!(graph.record_descriptor_object_with_id(
        601,
        501,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "x6 descriptor object harness",
    ));
    assert!(graph.record_dma_buffer_object_with_id(
        701,
        601,
        1,
        dma_resource,
        dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        2048,
        "x6 dma buffer object harness",
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
        "x6 mmio region object harness",
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
        "x6 irq line object harness",
    ));
    let driver_store = graph.register_store(
        "driver.fake-io0",
        "driver.fake-io0.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let device = ContractObjectRef::new(ContractObjectKind::DeviceObject, 401, 1);
    let mmio = ContractObjectRef::new(ContractObjectKind::MmioRegionObject, 801, 1);
    let dma = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 701, 1);
    let irq = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1);
    let device_capability = record_i8_device_probe_capability(
        graph,
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
        "x6 binding harness",
    ));

    let mmio_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "x6-test",
        true,
    );
    let dma_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "dma.fake-io0.rx0",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma),
        &["sync-for-device"],
        "store",
        "x6-test",
        true,
    );
    let irq_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "irq.fake-io0.rx",
        AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq),
        &["ack"],
        "store",
        "x6-test",
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
        "x6 mmio capability",
    ));
    assert!(graph.record_device_capability_with_id(
        1404,
        driver_store,
        driver_store_generation,
        dma,
        CapabilityClass::DmaBuffer,
        "sync-for-device",
        dma_handle,
        "x6 dma capability",
    ));
    assert!(graph.record_device_capability_with_id(
        1405,
        driver_store,
        driver_store_generation,
        irq,
        CapabilityClass::IrqLine,
        "ack",
        irq_handle,
        "x6 irq capability",
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
        "x6 pending io wait",
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
        "x6 historical irq event before cleanup",
    ));
    (driver_store, driver_store_generation, 1402)
}

pub(in crate::tests) fn add_s14_snapshot_barrier_to_graph(graph: &mut SemanticGraph) {
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "x6 hart0"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "x6 hart1"));
    assert!(graph.set_hart_state(2, 1, HartState::Parked, "scheduler-ready", "parked"));
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "snapshot-barrier-boundary",
        "x6 snapshot safe point",
    ));
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        3,
        71,
        1,
        true,
        "snapshot-barrier-rendezvous",
        "x6 all harts stopped for snapshot",
    ));
    assert!(graph.validate_smp_snapshot_barrier_with_id(
        101,
        81,
        1,
        SnapshotBarrierValidationState::default(),
        "smp-snapshot-barrier",
        "x6 clean SMP snapshot barrier",
    ));
}

pub(in crate::tests) fn x6_snapshot_io_lease_barrier_graph() -> SemanticGraph {
    let (mut graph, owner_store, owner_store_generation) = g9_display_cleanup_graph();
    assert!(graph.cleanup_display_for_store_with_id(
        23_907,
        owner_store,
        owner_store_generation,
        23_201,
        1,
        23_101,
        1,
        23_001,
        1,
        "display-window-cleanup",
        "x6 display cleanup before snapshot",
    ));
    assert!(graph.validate_display_snapshot_barrier_with_id(
        24_002,
        owner_store,
        owner_store_generation,
        23_101,
        1,
        23_001,
        1,
        Some(23_907),
        Some(1),
        "display-snapshot-barrier",
        "x6 display snapshot after cleanup",
    ));
    let (driver_store, driver_store_generation, binding) =
        add_i10_io_cleanup_setup_to_graph(&mut graph);
    let io_cleanup = graph.apply_envelope(CommandEnvelope::new(
        21,
        "x6-test",
        SemanticCommand::CleanupIoDriver {
            cleanup: 1408,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            reason: "device-fault".to_string(),
            note: "x6 io cleanup before snapshot".to_string(),
        },
    ));
    assert_eq!(io_cleanup.status, CommandStatus::Applied, "{io_cleanup:?}");
    add_s14_snapshot_barrier_to_graph(&mut graph);
    graph
}

#[test]
pub(in crate::tests) fn integrated_runtime_x6_records_snapshot_io_lease_barrier() {
    let mut graph = x6_snapshot_io_lease_barrier_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        22,
        "x6-test",
        SemanticCommand::RecordIntegratedSnapshotIoLeaseBarrier {
            integrated: 901,
            scenario: "x6-snapshot-barrier-blocks-active-io-leases".to_string(),
            smp_snapshot_barrier: 101,
            smp_snapshot_barrier_generation: 1,
            io_cleanup: 1408,
            io_cleanup_generation: 1,
            display_snapshot_barrier: 24_002,
            display_snapshot_barrier_generation: 1,
            invariant_checks: 7,
            note: "integrate snapshot barrier with IO and display lease cleanup".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.integrated_snapshot_io_lease_barrier_count(), 1);
    let record = &graph.integrated_snapshot_io_lease_barriers()[0];
    assert_eq!(record.id, 901);
    assert_eq!(record.smp_snapshot_barrier, 101);
    assert_eq!(record.io_cleanup, 1408);
    assert_eq!(record.display_snapshot_barrier, 24_002);
    assert_eq!(record.driver_store, 2);
    assert_eq!(record.device, 401);
    assert_eq!(record.display, 23_101);
    assert_eq!(record.framebuffer, 23_001);
    assert_eq!(record.active_dmw_lease_count, 0);
    assert_eq!(record.in_flight_dma_count, 0);
    assert_eq!(record.raw_dma_binding_count, 0);
    assert_eq!(record.raw_mmio_binding_count, 0);
    assert_eq!(record.active_framebuffer_window_lease_count, 0);
    assert_eq!(record.active_framebuffer_mapping_count, 0);
    assert_eq!(record.dirty_framebuffer_region_count, 0);
    assert_eq!(record.released_dma_buffers, 1);
    assert_eq!(record.released_mmio_regions, 1);
    assert_eq!(record.released_irq_lines, 1);
    assert_eq!(record.released_framebuffer_window_leases, 1);
    assert_eq!(record.revoked_display_capabilities, 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IntegratedSnapshotIoLeaseBarrierRecorded integrated=901 scenario=x6-snapshot-barrier-blocks-active-io-leases smp_snapshot_barrier=101@1 io_cleanup=1408@1 display_snapshot_barrier=24002@1 released_dma_buffers=1 released_mmio_regions=1 released_irq_lines=1 released_framebuffer_window_leases=1 active_dmw_leases=0 in_flight_dma=0 active_framebuffer_window_leases=0 invariant_checks=7 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn integrated_runtime_x6_rejects_missing_or_stale_barrier_refs() {
    let missing = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x6-test",
        SemanticCommand::RecordIntegratedSnapshotIoLeaseBarrier {
            integrated: 901,
            scenario: "x6-snapshot-barrier-blocks-active-io-leases".to_string(),
            smp_snapshot_barrier: 101,
            smp_snapshot_barrier_generation: 1,
            io_cleanup: 1408,
            io_cleanup_generation: 1,
            display_snapshot_barrier: 24_002,
            display_snapshot_barrier_generation: 1,
            invariant_checks: 7,
            note: "missing evidence rejects".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    assert_eq!(
        missing.violations,
        vec![
            "integrated snapshot/io lease barrier missing smp snapshot barrier evidence"
                .to_string()
        ]
    );

    let stale = x6_snapshot_io_lease_barrier_graph().apply_envelope(CommandEnvelope::new(
        22,
        "x6-test",
        SemanticCommand::RecordIntegratedSnapshotIoLeaseBarrier {
            integrated: 901,
            scenario: "x6-snapshot-barrier-blocks-active-io-leases".to_string(),
            smp_snapshot_barrier: 101,
            smp_snapshot_barrier_generation: 1,
            io_cleanup: 1408,
            io_cleanup_generation: 1,
            display_snapshot_barrier: 24_002,
            display_snapshot_barrier_generation: 2,
            invariant_checks: 7,
            note: "stale display barrier rejects".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec![
            "integrated snapshot/io lease barrier missing display snapshot barrier evidence"
                .to_string()
        ]
    );
}

#[test]
pub(in crate::tests) fn integrated_runtime_x6_contract_graph_rejects_cleanup_count_drift() {
    let mut graph = x6_snapshot_io_lease_barrier_graph();
    assert!(graph.record_integrated_snapshot_io_lease_barrier_with_id(
        901,
        "x6-snapshot-barrier-blocks-active-io-leases",
        101,
        1,
        1408,
        1,
        24_002,
        1,
        7,
        "integrated snapshot io lease barrier",
    ));
    let mut integrated = graph.integrated_snapshot_io_lease_barriers().to_vec();
    integrated[0].released_dma_buffers = 2;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_snapshot_io_lease_barriers: integrated,
        smp_snapshot_barriers: graph.smp_snapshot_barriers().to_vec(),
        io_cleanups: graph.io_cleanups().to_vec(),
        display_snapshot_barriers: graph.display_snapshot_barriers().to_vec(),
        display_cleanups: graph.display_cleanups().to_vec(),
        stores: graph.stores().to_vec(),
        device_objects: graph.device_objects().to_vec(),
        display_objects: graph.display_objects().to_vec(),
        framebuffer_objects: graph.framebuffer_objects().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-snapshot-io-lease-barrier->evidence-binding"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}
