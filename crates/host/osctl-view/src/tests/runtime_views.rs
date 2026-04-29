use super::*;

#[test]
fn preemptive_runtime_views_expose_task_activation_and_scheduler_state() {
    let task = task_view_v1(&TaskRecordManifest {
        id: 7,
        label: "linux-thread-7".to_owned(),
        frontend: "linux-elf".to_owned(),
        state: "runnable".to_owned(),
        generation: 1,
        fault_domain: None,
        pending_wait: None,
        resources: vec![3],
    });
    assert_eq!(task["kind"], "task");
    assert_eq!(task["owner"]["frontend"], "linux-elf");
    assert_eq!(task["references"]["resources"][0], 3);

    let activation = runtime_activation_view_v1(&RuntimeActivationRecordManifest {
        id: 11,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: None,
        owner_store_generation: None,
        code_object: Some(ContractObjectRefManifest {
            kind: "code-object".to_owned(),
            id: 4,
            generation: 1,
        }),
        generation: 2,
        state: "runnable".to_owned(),
        runnable_queue: Some(1),
        runnable_queue_generation: Some(1),
        last_event: Some(9),
    });
    assert_eq!(activation["kind"], "activation");
    assert_eq!(activation["owner"]["task"], 7);
    assert_eq!(activation["owner"]["task_generation"], 1);
    assert_eq!(activation["references"]["runnable_queue"]["id"], 1);
    assert_eq!(activation["references"]["runnable_queue"]["generation"], 1);

    let mut package = minimal_graph_package();
    package.package_id = "p0-test".to_owned();
    package.substrate_boundary.scheduler_decision_cursor = 12;
    package.semantic.hart_count = 2;
    package.semantic.task_record_count = 1;
    package.semantic.runtime_activation_count = 1;
    package.semantic.runnable_queue_count = 1;
    package.semantic.activation_context_count = 1;
    package.semantic.saved_context_count = 1;
    package.semantic.timer_interrupt_count = 1;
    package.semantic.ipi_event_count = 1;
    package.semantic.remote_preempt_count = 1;
    package.semantic.remote_park_count = 1;
    package.semantic.preemption_count = 1;
    package.semantic.scheduler_decision_count = 1;
    package.semantic.cross_hart_scheduler_decision_count = 1;
    package.semantic.activation_migration_count = 1;
    package.semantic.smp_safe_point_count = 1;
    package.semantic.stop_the_world_rendezvous_count = 1;
    package.semantic.smp_code_publish_barrier_count = 1;
    package.semantic.smp_cleanup_quiescence_count = 1;
    package.semantic.smp_snapshot_barrier_count = 1;
    package.semantic.smp_stress_run_count = 1;
    package.semantic.smp_scaling_benchmark_count = 1;
    package.semantic.device_object_count = 1;
    package.semantic.queue_object_count = 1;
    package.semantic.descriptor_object_count = 1;
    package.semantic.dma_buffer_object_count = 1;
    package.semantic.mmio_region_object_count = 1;
    package.semantic.irq_line_object_count = 1;
    package.semantic.irq_event_count = 1;
    package.semantic.device_capability_count = 2;
    package.semantic.driver_store_binding_count = 1;
    package.semantic.io_wait_count = 1;
    package.semantic.wait_token_count = 1;
    package.semantic.wait_record_count = 1;
    package.semantic.activation_resume_count = 1;
    package.semantic.activation_wait_count = 1;
    package.semantic.activation_cleanup_count = 1;
    package.semantic.preemption_latency_sample_count = 1;
    package.semantic.hart_event_attribution_count = 1;
    package.substrate_boundary.timer_epoch = 3;
    package.semantic.hart_records.push(HartRecordManifest {
        id: 1,
        hardware_id: 0,
        label: "boot-hart0".to_owned(),
        state: "idle".to_owned(),
        generation: 2,
        boot: true,
        current_activation: None,
        current_activation_generation: None,
        current_task: None,
        current_task_generation: None,
        current_store: None,
        current_store_generation: None,
        last_event: Some(2),
        last_current_event: None,
        note: "s0 hart object".to_owned(),
    });
    package.semantic.hart_records.push(HartRecordManifest {
        id: 2,
        hardware_id: 1,
        label: "hart1".to_owned(),
        state: "idle".to_owned(),
        generation: 2,
        boot: false,
        current_activation: None,
        current_activation_generation: None,
        current_task: None,
        current_task_generation: None,
        current_store: None,
        current_store_generation: None,
        last_event: Some(4),
        last_current_event: None,
        note: "s5 target hart".to_owned(),
    });
    package.semantic.task_records.push(TaskRecordManifest {
        id: 7,
        label: "linux-thread-7".to_owned(),
        frontend: "linux-elf".to_owned(),
        state: "runnable".to_owned(),
        generation: 1,
        fault_domain: None,
        pending_wait: None,
        resources: Vec::new(),
    });
    package.semantic.runtime_activation_records.push(RuntimeActivationRecordManifest {
        id: 11,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: None,
        owner_store_generation: None,
        code_object: None,
        generation: 2,
        state: "runnable".to_owned(),
        runnable_queue: Some(1),
        runnable_queue_generation: Some(1),
        last_event: Some(9),
    });
    package.semantic.runnable_queues.push(RunnableQueueManifest {
        id: 1,
        label: "main-rq".to_owned(),
        generation: 1,
        state: "active".to_owned(),
        owner_hart: Some(1),
        owner_hart_generation: Some(2),
        entries: vec![artifact_manifest::RunnableQueueEntryManifest {
            activation: 11,
            activation_generation: 2,
            enqueued_at: 9,
        }],
    });
    package.semantic.activation_contexts.push(ActivationContextManifest {
        id: 12,
        activation: 11,
        activation_generation: 2,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: None,
        owner_store_generation: None,
        generation: 2,
        state: "saved".to_owned(),
        current_saved_context: Some(13),
        current_saved_context_generation: Some(1),
        vector_state: None,
        vector_status: "absent".to_owned(),
        vector_state_event: None,
        last_event: Some(10),
    });
    package.semantic.saved_contexts.push(SavedContextManifest {
        id: 13,
        context: 12,
        context_generation: 2,
        activation: 11,
        activation_generation: 2,
        owner_task: 7,
        owner_task_generation: 1,
        source_preemption: Some(15),
        source_preemption_generation: Some(1),
        generation: 1,
        state: "captured".to_owned(),
        reason: "timer-preempt".to_owned(),
        pc: 0x1000,
        sp: 0x8000,
        flags: 0,
        integer_registers: 33,
        vector_state: None,
        vector_status: "absent".to_owned(),
        vector_saved_at_event: None,
        saved_at_event: 10,
        note: "preempted frame".to_owned(),
    });
    package.semantic.timer_interrupts.push(TimerInterruptManifest {
        id: 14,
        timer_epoch: 3,
        hart: 1,
        hart_generation: Some(2),
        hardware_hart: Some(0),
        target_activation: Some(11),
        target_activation_generation: Some(2),
        target_task: Some(7),
        target_task_generation: Some(1),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 11,
        note: "timer tick".to_owned(),
    });
    package.semantic.ipi_events.push(IpiEventManifest {
        id: 23,
        source_hart: 1,
        source_hart_generation: 2,
        source_hardware_hart: 0,
        target_hart: 2,
        target_hart_generation: 2,
        target_hardware_hart: 1,
        kind: "scheduler-kick".to_owned(),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 12,
        reason: "s5-scheduler-kick".to_owned(),
        note: "hart0 kicks hart1".to_owned(),
    });
    package.semantic.remote_preempts.push(RemotePreemptManifest {
        id: 24,
        ipi: 23,
        ipi_generation: 1,
        source_hart: 1,
        source_hart_generation: 2,
        target_hart: 2,
        target_hart_generation_before: 2,
        target_hart_generation_after: 3,
        activation: 11,
        activation_generation_before: 2,
        activation_generation_after: 3,
        queue: 1,
        queue_generation: 1,
        generation: 1,
        state: "applied".to_owned(),
        preempted_at_event: 13,
        note: "remote preempt activation".to_owned(),
    });
    package.semantic.remote_parks.push(RemoteParkManifest {
        id: 25,
        ipi: 23,
        ipi_generation: 1,
        source_hart: 1,
        source_hart_generation: 2,
        target_hart: 2,
        target_hart_generation_before: 3,
        target_hart_generation_after: 4,
        generation: 1,
        state: "parked".to_owned(),
        parked_at_event: 14,
        reason: "remote-maintenance".to_owned(),
        note: "remote park hart".to_owned(),
    });
    package.semantic.hart_event_attributions.push(HartEventAttributionManifest {
        id: 22,
        hart: 1,
        hart_generation: 2,
        hardware_hart: 0,
        event: 11,
        event_source: "timer".to_owned(),
        event_kind: "TimerInterruptRecorded".to_owned(),
        activation: Some(11),
        activation_generation: Some(2),
        task: Some(7),
        task_generation: Some(1),
        store: None,
        store_generation: None,
        generation: 1,
        state: "recorded".to_owned(),
        note: "timer event attributed to hart".to_owned(),
    });
    package.semantic.preemptions.push(PreemptionManifest {
        id: 15,
        activation: 11,
        activation_generation_before: 2,
        activation_generation_after: 3,
        timer_interrupt: 14,
        timer_interrupt_generation: 1,
        queue: 1,
        queue_generation: 1,
        generation: 1,
        state: "applied".to_owned(),
        preempted_at_event: 12,
        note: "preempted".to_owned(),
    });
    package.semantic.scheduler_decisions.push(SchedulerDecisionManifest {
        id: 16,
        queue: 1,
        queue_generation: 1,
        selected_activation: 11,
        selected_activation_generation: 3,
        owner_task: 7,
        owner_task_generation: 1,
        generation: 1,
        state: "recorded".to_owned(),
        decided_at_event: 13,
        reason: "runnable-available".to_owned(),
        note: "select activation".to_owned(),
    });
    package.semantic.cross_hart_scheduler_decisions.push(CrossHartSchedulerDecisionManifest {
        id: 26,
        scheduler_decision: 16,
        scheduler_decision_generation: 1,
        deciding_hart: 2,
        deciding_hart_generation: 2,
        target_hart: 1,
        target_hart_generation: 2,
        queue: 1,
        queue_generation: 1,
        queue_owner_hart_generation: 2,
        selected_activation: 11,
        selected_activation_generation: 3,
        generation: 1,
        state: "recorded".to_owned(),
        decided_at_event: 20,
        reason: "remote-runnable".to_owned(),
        note: "cross hart decision".to_owned(),
    });
    package.semantic.activation_migrations.push(ActivationMigrationManifest {
        id: 27,
        activation: 11,
        activation_generation_before: 3,
        activation_generation_after: 4,
        owner_task: 7,
        owner_task_generation: 1,
        source_hart: 2,
        source_hart_generation: 2,
        target_hart: 1,
        target_hart_generation: 2,
        source_queue: 2,
        source_queue_generation: 1,
        source_queue_owner_hart_generation: 2,
        target_queue: 1,
        target_queue_generation: 1,
        target_queue_owner_hart_generation: 2,
        context: None,
        context_generation_before: None,
        context_generation_after: None,
        source_vector_state: None,
        migrated_vector_state: None,
        vector_status: "absent".to_owned(),
        vector_migrated_at_event: None,
        generation: 1,
        state: "applied".to_owned(),
        migrated_at_event: 21,
        reason: "rebalance".to_owned(),
        note: "activation migration".to_owned(),
    });
    package.semantic.smp_safe_points.push(SmpSafePointManifest {
        id: 28,
        coordinator_hart: 1,
        coordinator_hart_generation: 2,
        participants: vec![
            artifact_manifest::SmpSafePointParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
                current_activation: None,
                current_activation_generation: None,
            },
            artifact_manifest::SmpSafePointParticipantManifest {
                hart: 2,
                hart_generation: 2,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
                current_activation: None,
                current_activation_generation: None,
            },
        ],
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 22,
        reason: "quiescent-boundary".to_owned(),
        note: "smp safe point".to_owned(),
    });
    package.semantic.stop_the_world_rendezvous.push(StopTheWorldRendezvousManifest {
        id: 29,
        epoch: 1,
        safe_point: 28,
        safe_point_generation: 1,
        coordinator_hart: 1,
        coordinator_hart_generation: 2,
        participants: vec![
            artifact_manifest::StopTheWorldRendezvousParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
            },
            artifact_manifest::StopTheWorldRendezvousParticipantManifest {
                hart: 2,
                hart_generation: 2,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
            },
        ],
        stop_new_activations: true,
        generation: 1,
        state: "completed".to_owned(),
        completed_at_event: 23,
        reason: "code-publish-boundary".to_owned(),
        note: "stop the world".to_owned(),
    });
    package.semantic.smp_code_publish_barriers.push(SmpCodePublishBarrierManifest {
        id: 30,
        rendezvous: 29,
        rendezvous_generation: 1,
        rendezvous_epoch: 1,
        code_publish_epoch_before: 0,
        code_publish_epoch_after: 1,
        participants: vec![
            artifact_manifest::SmpCodePublishBarrierParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                last_seen_code_epoch_before: 0,
                last_seen_code_epoch_after: 1,
                semantic_icache_sync: true,
            },
            artifact_manifest::SmpCodePublishBarrierParticipantManifest {
                hart: 2,
                hart_generation: 2,
                hardware_hart: 1,
                last_seen_code_epoch_before: 0,
                last_seen_code_epoch_after: 1,
                semantic_icache_sync: true,
            },
        ],
        remote_icache_sync_required: true,
        code_publish_executed: false,
        generation: 1,
        state: "validated".to_owned(),
        validated_at_event: 24,
        reason: "semantic-code-publish-barrier".to_owned(),
        note: "smp publish barrier".to_owned(),
    });
    package.semantic.smp_cleanup_quiescence.push(SmpCleanupQuiescenceManifest {
        id: 31,
        cleanup: 20,
        cleanup_generation: 1,
        store: 5,
        target_store_generation: 2,
        result_store_generation: 4,
        activation: 11,
        activation_generation_after: 6,
        rendezvous: 29,
        rendezvous_generation: 1,
        rendezvous_epoch: 1,
        participants: vec![
            artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
                current_activation: None,
                current_activation_generation: None,
                current_store: None,
                current_store_generation: None,
                quiesced: true,
            },
            artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                hart: 2,
                hart_generation: 2,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
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
        state: "validated".to_owned(),
        validated_at_event: 25,
        reason: "smp-cleanup-quiescence".to_owned(),
        note: "cleanup quiesced".to_owned(),
    });
    package.semantic.smp_snapshot_barriers.push(SmpSnapshotBarrierManifest {
        id: 32,
        rendezvous: 29,
        rendezvous_generation: 1,
        rendezvous_epoch: 1,
        event_log_cursor: 25,
        participants: vec![
            artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
                event_log_cursor_observed: 25,
                snapshot_safe: true,
            },
            artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                hart: 2,
                hart_generation: 2,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
                event_log_cursor_observed: 25,
                snapshot_safe: true,
            },
        ],
        pending_wait_count: 0,
        active_transaction_count: 0,
        active_dmw_lease_count: 0,
        active_nonconvertible_activation_count: 0,
        in_flight_dma_count: 0,
        unsealed_event_log: false,
        unflushed_trap_record_count: 0,
        pending_cleanup_count: 0,
        native_activation_stack_live: false,
        raw_dma_binding_count: 0,
        raw_mmio_binding_count: 0,
        snapshot_validation_ok: true,
        generation: 1,
        state: "validated".to_owned(),
        validated_at_event: 26,
        reason: "smp-snapshot-barrier".to_owned(),
        note: "snapshot barrier".to_owned(),
    });
    package.semantic.smp_stress_runs.push(SmpStressRunManifest {
        id: 33,
        scenario: "s15-smp-stress-property".to_owned(),
        iterations: 3,
        hart_count: 2,
        event_log_cursor: 26,
        observed_safe_point_count: 3,
        observed_rendezvous_count: 3,
        observed_code_publish_barrier_count: 1,
        observed_cleanup_quiescence_count: 1,
        observed_snapshot_barrier_count: 1,
        observed_activation_migration_count: 1,
        observed_remote_preempt_count: 1,
        observed_remote_park_count: 1,
        invariant_checks: 6,
        property_failures: 0,
        last_safe_point: 28,
        last_safe_point_generation: 1,
        last_rendezvous: 29,
        last_rendezvous_generation: 1,
        last_code_publish_barrier: 30,
        last_code_publish_barrier_generation: 1,
        last_cleanup_quiescence: 31,
        last_cleanup_quiescence_generation: 1,
        last_snapshot_barrier: 32,
        last_snapshot_barrier_generation: 1,
        last_activation_migration: 27,
        last_activation_migration_generation: 1,
        last_remote_preempt: 24,
        last_remote_preempt_generation: 1,
        last_remote_park: 25,
        last_remote_park_generation: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 27,
        reason: "smp-stress-property-tests".to_owned(),
        note: "stress run".to_owned(),
    });
    package.semantic.smp_scaling_benchmarks.push(SmpScalingBenchmarkManifest {
        id: 34,
        scenario: "s16-smp-scaling-benchmark".to_owned(),
        stress_run: 33,
        stress_run_generation: 1,
        hart_count: 2,
        workload_units: 6,
        baseline_single_hart_nanos: 120_000,
        measured_smp_nanos: 72_000,
        budget_nanos: 90_000,
        speedup_milli: 1_666,
        efficiency_milli: 833,
        event_log_cursor: 27,
        stress_safe_point_count: 3,
        stress_rendezvous_count: 3,
        stress_property_failures: 0,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 28,
        note: "scaling benchmark".to_owned(),
    });
    package.semantic.device_objects.push(DeviceObjectManifest {
        id: 35,
        name: "fake-io0".to_owned(),
        class: "fake-device".to_owned(),
        resource: 99,
        resource_generation: 1,
        backend: "fake-io-backend".to_owned(),
        bus: "semantic-harness".to_owned(),
        vendor: "vmos".to_owned(),
        model: "fake-io-v1".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 29,
        note: "device object".to_owned(),
    });
    package.semantic.queue_objects.push(QueueObjectManifest {
        id: 36,
        name: "fake-io0-rx".to_owned(),
        role: "rx".to_owned(),
        queue_index: 0,
        depth: 64,
        device: 35,
        device_generation: 1,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 30,
        note: "queue object".to_owned(),
    });
    package.semantic.descriptor_objects.push(DescriptorObjectManifest {
        id: 37,
        queue: 36,
        queue_generation: 1,
        slot: 0,
        access: "read-write".to_owned(),
        length: 2048,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 31,
        note: "descriptor object".to_owned(),
    });
    package.semantic.dma_buffer_objects.push(DmaBufferObjectManifest {
        id: 38,
        descriptor: 37,
        descriptor_generation: 1,
        resource: 100,
        resource_generation: 1,
        access: "read-write".to_owned(),
        length: 2048,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 32,
        note: "dma buffer object".to_owned(),
    });
    package.semantic.mmio_region_objects.push(MmioRegionObjectManifest {
        id: 39,
        device: 35,
        device_generation: 1,
        resource: 101,
        resource_generation: 1,
        region_index: 0,
        offset: 0x1000,
        length: 0x100,
        access: "read-write".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 33,
        note: "mmio region object".to_owned(),
    });
    package.semantic.irq_line_objects.push(IrqLineObjectManifest {
        id: 40,
        device: 35,
        device_generation: 1,
        resource: 102,
        resource_generation: 1,
        irq_number: 5,
        trigger: "level".to_owned(),
        polarity: "active-high".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 34,
        note: "irq line object".to_owned(),
    });
    package.semantic.irq_events.push(IrqEventManifest {
        id: 41,
        irq_line: 40,
        irq_line_generation: 1,
        device: 35,
        device_generation: 1,
        driver_store: 1,
        driver_store_generation: 2,
        irq_number: 5,
        sequence: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 35,
        note: "irq event".to_owned(),
    });
    package.semantic.device_capabilities.push(DeviceCapabilityManifest {
        id: 42,
        driver_store: 1,
        driver_store_generation: 2,
        target: ContractObjectRefManifest {
            kind: "mmio-region-object".to_owned(),
            id: 39,
            generation: 1,
        },
        class: "mmio-region".to_owned(),
        operation: "write32".to_owned(),
        capability: 7,
        capability_generation: 1,
        handle_slot: 3,
        handle_generation: 1,
        handle_tag: 9001,
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 36,
        note: "device capability".to_owned(),
    });
    package.semantic.device_capabilities.push(DeviceCapabilityManifest {
        id: 43,
        driver_store: 1,
        driver_store_generation: 2,
        target: ContractObjectRefManifest {
            kind: "device-object".to_owned(),
            id: 35,
            generation: 1,
        },
        class: "device".to_owned(),
        operation: "probe".to_owned(),
        capability: 8,
        capability_generation: 1,
        handle_slot: 4,
        handle_generation: 1,
        handle_tag: 9002,
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 37,
        note: "device capability".to_owned(),
    });
    package.semantic.driver_store_bindings.push(DriverStoreBindingManifest {
        id: 44,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        device_capability: 43,
        device_capability_generation: 1,
        capability: 8,
        capability_generation: 1,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 38,
        note: "driver store binding".to_owned(),
    });
    package.semantic.wait_records.push(WaitRecordManifest {
        id: 45,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(1),
        owner_store_generation: Some(2),
        kind: "device-irq".to_owned(),
        generation: 1,
        state: "resolved".to_owned(),
        blockers: vec![ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 40,
            generation: 1,
        }],
        deadline: None,
        cancel_reason: None,
        restart_policy: "internal-only".to_owned(),
        saved_context: Some("fake-io0:rx-irq".to_owned()),
    });
    package.semantic.io_waits.push(IoWaitManifest {
        id: 46,
        wait: 45,
        wait_generation: 1,
        driver_store: 1,
        driver_store_generation: 2,
        device: 35,
        device_generation: 1,
        driver_binding: 44,
        driver_binding_generation: 1,
        blocker: ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 40,
            generation: 1,
        },
        generation: 1,
        state: "resolved".to_owned(),
        created_at_event: 39,
        completed_at_event: Some(40),
        completion_irq_event: Some(41),
        completion_irq_event_generation: Some(1),
        cancel_reason: None,
        note: "io wait".to_owned(),
    });
    package.semantic.activation_resumes.push(ActivationResumeManifest {
        id: 17,
        scheduler_decision: 16,
        scheduler_decision_generation: 1,
        activation: 11,
        activation_generation_before: 3,
        activation_generation_after: 4,
        owner_task: 7,
        owner_task_generation: 1,
        queue: 1,
        queue_generation: 1,
        context: Some(12),
        context_generation_before: Some(2),
        context_generation_after: Some(3),
        saved_context: Some(13),
        saved_context_generation: Some(2),
        saved_vector_state: None,
        restored_vector_state: None,
        vector_status: "absent".to_owned(),
        vector_restored_at_event: None,
        generation: 1,
        state: "applied".to_owned(),
        resumed_at_event: 14,
        note: "resume activation".to_owned(),
    });
    package.semantic.activation_waits.push(ActivationWaitManifest {
        id: 18,
        activation: 11,
        activation_generation_before: 4,
        activation_generation_after_block: 5,
        activation_generation_after_cancel: Some(6),
        wait: 19,
        wait_generation: 1,
        owner_task: 7,
        owner_task_generation: 2,
        queue: None,
        queue_generation: None,
        generation: 1,
        state: "cancelled".to_owned(),
        blocked_at_event: 15,
        completed_at_event: Some(16),
        cancel_reason: Some("timeout".to_owned()),
        note: "activation wait".to_owned(),
    });
    package.semantic.activation_cleanups.push(ActivationCleanupManifest {
        id: 20,
        store: 3,
        target_store_generation: 2,
        result_store_generation: 4,
        activation: 11,
        activation_generation_before: 5,
        activation_generation_after: 6,
        wait: Some(19),
        wait_generation: Some(1),
        owner_task: 7,
        owner_task_generation_before: 2,
        owner_task_generation_after: 3,
        generation: 1,
        state: "completed".to_owned(),
        reason: "driver-store-fault".to_owned(),
        started_at_event: 17,
        completed_at_event: 18,
        steps: vec![artifact_manifest::ActivationCleanupStepManifest {
            kind: "cancel-wait".to_owned(),
            target: ContractObjectRefManifest {
                kind: "wait-token".to_owned(),
                id: 19,
                generation: 1,
            },
            observed_generation: 1,
            status: "done".to_owned(),
            event: Some(17),
        }],
        note: "cleanup".to_owned(),
    });
    package.semantic.preemption_latency_samples.push(PreemptionLatencySampleManifest {
        id: 21,
        timer_interrupt: 14,
        timer_interrupt_generation: 1,
        preemption: 15,
        preemption_generation: 1,
        scheduler_decision: 16,
        scheduler_decision_generation: 1,
        activation_resume: 17,
        activation_resume_generation: 1,
        activation: 11,
        activation_generation_before: 2,
        activation_generation_after: 4,
        queue: 1,
        queue_generation: 1,
        interrupt_recorded_at_event: 11,
        preempted_at_event: 12,
        decided_at_event: 13,
        resumed_at_event: 14,
        interrupt_to_preempt_events: 1,
        preempt_to_decision_events: 1,
        decision_to_resume_events: 1,
        interrupt_to_resume_events: 3,
        measured_nanos: 8_500,
        budget_nanos: 50_000,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 19,
        note: "latency sample".to_owned(),
    });
    let hart = hart_view_v1(&package.semantic.hart_records[0]);
    assert_eq!(hart["kind"], "hart");
    assert_eq!(hart["owner"]["hardware_id"], 0);
    assert_eq!(hart["generation"], 2);
    assert_eq!(hart["state"], "idle");
    let current_hart = hart_view_v1(&HartRecordManifest {
        id: 2,
        hardware_id: 1,
        label: "hart1".to_owned(),
        state: "running".to_owned(),
        generation: 3,
        boot: false,
        current_activation: Some(11),
        current_activation_generation: Some(2),
        current_task: Some(7),
        current_task_generation: Some(1),
        current_store: None,
        current_store_generation: None,
        last_event: Some(21),
        last_current_event: Some(21),
        note: "current activation".to_owned(),
    });
    assert_eq!(current_hart["references"]["current_activation"]["generation"], 2);
    assert_eq!(current_hart["references"]["current_task"]["id"], 7);
    let context = activation_context_view_v1(&package.semantic.activation_contexts[0]);
    assert_eq!(context["kind"], "activation-context");
    assert_eq!(context["references"]["activation"]["generation"], 2);
    assert_eq!(context["references"]["current_saved_context"]["generation"], 1);
    let saved = saved_context_view_v1(&package.semantic.saved_contexts[0]);
    assert_eq!(saved["kind"], "saved-context");
    assert_eq!(saved["reason"], "timer-preempt");
    assert_eq!(saved["machine_frame"]["integer_registers"], 33);
    assert_eq!(saved["references"]["activation_context"]["generation"], 2);
    assert_eq!(saved["references"]["source_preemption"]["id"], 15);
    assert_eq!(saved["references"]["source_preemption"]["generation"], 1);
    assert_eq!(saved["vector_context"]["status"], "absent");
    let timer = timer_interrupt_view_v1(&package.semantic.timer_interrupts[0]);
    assert_eq!(timer["kind"], "timer-interrupt");
    assert_eq!(timer["owner"]["timer_epoch"], 3);
    assert_eq!(timer["owner"]["hart"]["id"], 1);
    assert_eq!(timer["owner"]["hart"]["generation"], 2);
    assert_eq!(timer["owner"]["hart"]["hardware_id"], 0);
    assert_eq!(timer["references"]["activation"]["generation"], 2);
    let ipi = ipi_event_view_v1(&package.semantic.ipi_events[0]);
    assert_eq!(ipi["kind"], "ipi-event");
    assert_eq!(ipi["owner"]["source_hart"]["generation"], 2);
    assert_eq!(ipi["owner"]["target_hart"]["hardware_id"], 1);
    assert_eq!(ipi["ipi_kind"], "scheduler-kick");
    let remote = remote_preempt_view_v1(&package.semantic.remote_preempts[0]);
    assert_eq!(remote["kind"], "remote-preempt");
    assert_eq!(remote["references"]["ipi"]["generation"], 1);
    assert_eq!(remote["references"]["activation"]["generation_after"], 3);
    let remote_park = remote_park_view_v1(&package.semantic.remote_parks[0]);
    assert_eq!(remote_park["kind"], "remote-park");
    assert_eq!(remote_park["references"]["ipi"]["id"], 23);
    assert_eq!(remote_park["owner"]["target_hart"]["generation_after"], 4);
    let hart_event = hart_event_attribution_view_v1(&package.semantic.hart_event_attributions[0]);
    assert_eq!(hart_event["kind"], "hart-event-attribution");
    assert_eq!(hart_event["owner"]["hart"]["generation"], 2);
    assert_eq!(hart_event["references"]["event"]["kind"], "TimerInterruptRecorded");
    assert_eq!(hart_event["references"]["activation"]["id"], 11);
    let queue = runnable_queue_view_v1(&package.semantic.runnable_queues[0]);
    assert_eq!(queue["kind"], "runnable-queue");
    assert_eq!(queue["owner"]["hart"]["id"], 1);
    assert_eq!(queue["owner"]["hart"]["generation"], 2);
    let preemption = preemption_view_v1(&package.semantic.preemptions[0]);
    assert_eq!(preemption["kind"], "preemption");
    assert_eq!(preemption["references"]["activation"]["generation_before"], 2);
    assert_eq!(preemption["references"]["activation"]["generation_after"], 3);
    assert_eq!(preemption["references"]["timer_interrupt"]["generation"], 1);
    let decision = scheduler_decision_view_v1(&package.semantic.scheduler_decisions[0]);
    assert_eq!(decision["kind"], "scheduler-decision");
    assert_eq!(decision["references"]["selected_activation"]["generation"], 3);
    assert_eq!(decision["references"]["queue"]["generation"], 1);
    assert_eq!(decision["reason"], "runnable-available");
    let cross_decision =
        cross_hart_scheduler_decision_view_v1(&package.semantic.cross_hart_scheduler_decisions[0]);
    assert_eq!(cross_decision["kind"], "cross-hart-scheduler-decision");
    assert_eq!(cross_decision["owner"]["deciding_hart"]["id"], 2);
    assert_eq!(cross_decision["owner"]["target_hart"]["id"], 1);
    assert_eq!(cross_decision["references"]["scheduler_decision"]["generation"], 1);
    assert_eq!(cross_decision["references"]["queue"]["owner_hart_generation"], 2);
    let migration = activation_migration_view_v1(&package.semantic.activation_migrations[0]);
    assert_eq!(migration["kind"], "activation-migration");
    assert_eq!(migration["owner"]["source_hart"]["id"], 2);
    assert_eq!(migration["owner"]["target_hart"]["id"], 1);
    assert_eq!(migration["references"]["activation"]["generation_after"], 4);
    assert_eq!(migration["references"]["target_queue"]["id"], 1);
    let safe_point = smp_safe_point_view_v1(&package.semantic.smp_safe_points[0]);
    assert_eq!(safe_point["kind"], "smp-safe-point");
    assert_eq!(safe_point["owner"]["coordinator_hart"]["id"], 1);
    assert_eq!(safe_point["references"]["participants"][0]["hart"]["id"], 1);
    assert_eq!(safe_point["references"]["participants"][0]["hart"]["generation"], 2);
    assert_eq!(safe_point["last_transition"]["participant_count"], 2);
    let rendezvous =
        stop_the_world_rendezvous_view_v1(&package.semantic.stop_the_world_rendezvous[0]);
    assert_eq!(rendezvous["kind"], "stop-the-world-rendezvous");
    assert_eq!(rendezvous["epoch"], 1);
    assert_eq!(rendezvous["references"]["safe_point"]["id"], 28);
    assert_eq!(rendezvous["references"]["participants"][1]["hart"]["generation"], 2);
    assert_eq!(rendezvous["stop_new_activations"], true);
    let barrier = smp_code_publish_barrier_view_v1(&package.semantic.smp_code_publish_barriers[0]);
    assert_eq!(barrier["kind"], "smp-code-publish-barrier");
    assert_eq!(barrier["references"]["rendezvous"]["id"], 29);
    assert_eq!(barrier["references"]["participants"][0]["semantic_icache_sync"], true);
    assert_eq!(barrier["last_transition"]["code_publish_epoch_after"], 1);
    assert_eq!(barrier["code_publish_executed"], false);
    let quiescence = smp_cleanup_quiescence_view_v1(&package.semantic.smp_cleanup_quiescence[0]);
    assert_eq!(quiescence["kind"], "smp-cleanup-quiescence");
    assert_eq!(quiescence["references"]["cleanup"]["id"], 20);
    assert_eq!(quiescence["references"]["store"]["target_generation"], 2);
    assert_eq!(quiescence["references"]["store"]["result_generation"], 4);
    assert_eq!(quiescence["references"]["rendezvous"]["id"], 29);
    assert_eq!(quiescence["postconditions"]["no_running_activation"], true);
    assert_eq!(quiescence["references"]["participants"][1]["quiesced"], true);
    let snapshot_barrier = smp_snapshot_barrier_view_v1(&package.semantic.smp_snapshot_barriers[0]);
    assert_eq!(snapshot_barrier["kind"], "smp-snapshot-barrier");
    assert_eq!(snapshot_barrier["references"]["rendezvous"]["id"], 29);
    assert_eq!(snapshot_barrier["last_transition"]["event_log_cursor"], 25);
    assert_eq!(snapshot_barrier["references"]["participants"][1]["snapshot_safe"], true);
    assert_eq!(snapshot_barrier["postconditions"]["snapshot_validation_ok"], true);
    let stress = smp_stress_run_view_v1(&package.semantic.smp_stress_runs[0]);
    assert_eq!(stress["kind"], "smp-stress-run");
    assert_eq!(stress["owner"]["scenario"], "s15-smp-stress-property");
    assert_eq!(stress["coverage"]["iterations"], 3);
    assert_eq!(stress["coverage"]["property_failures"], 0);
    assert_eq!(stress["references"]["last_snapshot_barrier"]["generation"], 1);
    let scaling = smp_scaling_benchmark_view_v1(&package.semantic.smp_scaling_benchmarks[0]);
    assert_eq!(scaling["kind"], "smp-scaling-benchmark");
    assert_eq!(scaling["owner"]["scenario"], "s16-smp-scaling-benchmark");
    assert_eq!(scaling["references"]["stress_run"]["id"], 33);
    assert_eq!(scaling["metrics"]["workload_units"], 6);
    assert_eq!(scaling["metrics"]["measured_smp_nanos"], 72_000);
    assert_eq!(scaling["metrics"]["speedup_milli"], 1_666);
    assert_eq!(scaling["metrics"]["efficiency_milli"], 833);
    assert_eq!(scaling["coverage"]["stress_property_failures"], 0);
    let device = device_object_view_v1(&package.semantic.device_objects[0]);
    assert_eq!(device["kind"], "device");
    assert_eq!(device["owner"]["class"], "fake-device");
    assert_eq!(device["owner"]["backend"], "fake-io-backend");
    assert_eq!(device["references"]["resource"]["generation"], 1);
    assert_eq!(device["identity"]["model"], "fake-io-v1");
    let queue = queue_object_view_v1(&package.semantic.queue_objects[0]);
    assert_eq!(queue["kind"], "queue");
    assert_eq!(queue["owner"]["device"]["id"], 35);
    assert_eq!(queue["owner"]["device"]["generation"], 1);
    assert_eq!(queue["identity"]["role"], "rx");
    assert_eq!(queue["identity"]["queue_index"], 0);
    assert_eq!(queue["capacity"]["depth"], 64);
    let descriptor = descriptor_object_view_v1(&package.semantic.descriptor_objects[0]);
    assert_eq!(descriptor["kind"], "descriptor");
    assert_eq!(descriptor["owner"]["queue"]["id"], 36);
    assert_eq!(descriptor["owner"]["queue"]["generation"], 1);
    assert_eq!(descriptor["identity"]["slot"], 0);
    assert_eq!(descriptor["identity"]["access"], "read-write");
    assert_eq!(descriptor["capacity"]["length"], 2048);
    let dma_buffer = dma_buffer_object_view_v1(&package.semantic.dma_buffer_objects[0]);
    assert_eq!(dma_buffer["kind"], "dma-buffer");
    assert_eq!(dma_buffer["owner"]["descriptor"]["id"], 37);
    assert_eq!(dma_buffer["owner"]["descriptor"]["generation"], 1);
    assert_eq!(dma_buffer["references"]["resource"]["id"], 100);
    assert_eq!(dma_buffer["references"]["resource"]["generation"], 1);
    assert_eq!(dma_buffer["identity"]["access"], "read-write");
    assert_eq!(dma_buffer["capacity"]["length"], 2048);
    let mmio_region = mmio_region_object_view_v1(&package.semantic.mmio_region_objects[0]);
    assert_eq!(mmio_region["kind"], "mmio-region");
    assert_eq!(mmio_region["owner"]["device"]["id"], 35);
    assert_eq!(mmio_region["owner"]["device"]["generation"], 1);
    assert_eq!(mmio_region["references"]["resource"]["id"], 101);
    assert_eq!(mmio_region["references"]["resource"]["generation"], 1);
    assert_eq!(mmio_region["identity"]["region_index"], 0);
    assert_eq!(mmio_region["identity"]["offset"], 0x1000);
    assert_eq!(mmio_region["identity"]["access"], "read-write");
    assert_eq!(mmio_region["capacity"]["length"], 0x100);
    let irq_line = irq_line_object_view_v1(&package.semantic.irq_line_objects[0]);
    assert_eq!(irq_line["kind"], "irq-line");
    assert_eq!(irq_line["owner"]["device"]["id"], 35);
    assert_eq!(irq_line["owner"]["device"]["generation"], 1);
    assert_eq!(irq_line["references"]["resource"]["id"], 102);
    assert_eq!(irq_line["references"]["resource"]["generation"], 1);
    assert_eq!(irq_line["identity"]["irq_number"], 5);
    assert_eq!(irq_line["identity"]["trigger"], "level");
    assert_eq!(irq_line["identity"]["polarity"], "active-high");
    let irq_event = irq_event_view_v1(&package.semantic.irq_events[0]);
    assert_eq!(irq_event["kind"], "irq-event");
    assert_eq!(irq_event["owner"]["device"]["id"], 35);
    assert_eq!(irq_event["owner"]["driver_store"]["id"], 1);
    assert_eq!(irq_event["owner"]["driver_store"]["generation"], 2);
    assert_eq!(irq_event["references"]["irq_line"]["id"], 40);
    assert_eq!(irq_event["references"]["irq_line"]["generation"], 1);
    assert_eq!(irq_event["identity"]["irq_number"], 5);
    assert_eq!(irq_event["identity"]["sequence"], 1);
    let device_capability = device_capability_view_v1(&package.semantic.device_capabilities[0]);
    assert_eq!(device_capability["kind"], "device-capability");
    assert_eq!(device_capability["owner"]["driver_store"]["generation"], 2);
    assert_eq!(device_capability["references"]["target"]["id"], 39);
    assert_eq!(device_capability["references"]["target"]["generation"], 1);
    assert_eq!(device_capability["references"]["capability"]["id"], 7);
    assert_eq!(device_capability["authority"]["class"], "mmio-region");
    assert_eq!(device_capability["authority"]["operation"], "write32");
    assert_eq!(device_capability["authority"]["handle"]["slot"], 3);
    let binding = driver_store_binding_view_v1(&package.semantic.driver_store_bindings[0]);
    assert_eq!(binding["kind"], "driver-store-binding");
    assert_eq!(binding["owner"]["driver_store"]["generation"], 2);
    assert_eq!(binding["owner"]["device"]["id"], 35);
    assert_eq!(binding["references"]["device_capability"]["id"], 43);
    assert_eq!(binding["references"]["capability"]["generation"], 1);
    let io_wait = io_wait_view_v1(&package.semantic.io_waits[0]);
    assert_eq!(io_wait["kind"], "io-wait");
    assert_eq!(io_wait["owner"]["driver_store"]["generation"], 2);
    assert_eq!(io_wait["references"]["wait"]["id"], 45);
    assert_eq!(io_wait["references"]["blocker"]["kind"], "irq-line-object");
    assert_eq!(io_wait["references"]["completion_irq_event"]["id"], 41);
    assert_eq!(io_wait["last_transition"]["completed_at_event"], 40);
    let resume = activation_resume_view_v1(&package.semantic.activation_resumes[0]);
    assert_eq!(resume["kind"], "activation-resume");
    assert_eq!(resume["references"]["activation"]["generation_before"], 3);
    assert_eq!(resume["references"]["activation"]["generation_after"], 4);
    assert_eq!(resume["references"]["scheduler_decision"]["generation"], 1);
    assert_eq!(resume["references"]["saved_context"]["generation"], 2);
    let activation_wait = activation_wait_view_v1(&package.semantic.activation_waits[0]);
    assert_eq!(activation_wait["kind"], "activation-wait");
    assert_eq!(activation_wait["references"]["activation"]["generation_before"], 4);
    assert_eq!(activation_wait["references"]["activation"]["generation_after_block"], 5);
    assert_eq!(activation_wait["references"]["activation"]["generation_after_cancel"], 6);
    assert_eq!(activation_wait["references"]["wait"]["generation"], 1);
    assert_eq!(activation_wait["cancel_reason"], "timeout");
    let activation_cleanup = activation_cleanup_view_v1(&package.semantic.activation_cleanups[0]);
    assert_eq!(activation_cleanup["kind"], "activation-cleanup");
    assert_eq!(activation_cleanup["owner"]["target_store_generation"], 2);
    assert_eq!(activation_cleanup["owner"]["result_store_generation"], 4);
    assert_eq!(activation_cleanup["references"]["activation"]["generation_after"], 6);
    assert_eq!(activation_cleanup["references"]["steps"][0]["target"]["kind"], "wait-token");
    let latency = preemption_latency_view_v1(&package.semantic.preemption_latency_samples[0]);
    assert_eq!(latency["kind"], "preemption-latency");
    assert_eq!(latency["references"]["timer_interrupt"]["generation"], 1);
    assert_eq!(latency["event_window"]["interrupt_to_resume_events"], 3);
    assert_eq!(latency["metrics"]["measured_nanos"], 8_500);
    assert_eq!(latency["metrics"]["within_budget"], true);
    let scheduler = scheduler_view_v1(&package);
    assert_eq!(scheduler["kind"], "scheduler");
    assert_eq!(scheduler["references"]["harts"][0]["hardware_id"], 0);
    assert_eq!(scheduler["last_transition"]["hart_count"], 2);
    assert_eq!(scheduler["references"]["queues"][0]["entries"], 1);
    assert_eq!(scheduler["references"]["queues"][0]["owner_hart"], 1);
    assert_eq!(scheduler["references"]["queues"][0]["owner_hart_generation"], 2);
    assert_eq!(scheduler["references"]["preemptions"][0]["activation"], 11);
    assert_eq!(
        scheduler["references"]["scheduler_decisions"][0]["selected_activation_generation"],
        3
    );
    assert_eq!(scheduler["last_transition"]["activation_context_count"], 1);
    assert_eq!(scheduler["last_transition"]["saved_context_count"], 1);
    assert_eq!(scheduler["last_transition"]["timer_interrupt_count"], 1);
    assert_eq!(scheduler["last_transition"]["ipi_event_count"], 1);
    assert_eq!(scheduler["last_transition"]["remote_preempt_count"], 1);
    assert_eq!(scheduler["last_transition"]["remote_park_count"], 1);
    assert_eq!(scheduler["references"]["ipi_events"][0]["target_hart"], 2);
    assert_eq!(scheduler["references"]["remote_preempts"][0]["activation_generation_after"], 3);
    assert_eq!(scheduler["references"]["remote_parks"][0]["target_hart"], 2);
    assert_eq!(scheduler["last_transition"]["hart_event_attribution_count"], 1);
    assert_eq!(
        scheduler["references"]["hart_event_attributions"][0]["event_kind"],
        "TimerInterruptRecorded"
    );
    assert_eq!(scheduler["last_transition"]["preemption_count"], 1);
    assert_eq!(scheduler["last_transition"]["scheduler_decision_count"], 1);
    assert_eq!(scheduler["last_transition"]["cross_hart_scheduler_decision_count"], 1);
    assert_eq!(scheduler["references"]["cross_hart_scheduler_decisions"][0]["target_hart"], 1);
    assert_eq!(scheduler["last_transition"]["activation_migration_count"], 1);
    assert_eq!(
        scheduler["references"]["activation_migrations"][0]["activation_generation_after"],
        4
    );
    assert_eq!(scheduler["last_transition"]["smp_safe_point_count"], 1);
    assert_eq!(scheduler["references"]["smp_safe_points"][0]["participant_count"], 2);
    assert_eq!(scheduler["last_transition"]["stop_the_world_rendezvous_count"], 1);
    assert_eq!(scheduler["references"]["stop_the_world_rendezvous"][0]["safe_point"], 28);
    assert_eq!(scheduler["last_transition"]["smp_code_publish_barrier_count"], 1);
    assert_eq!(scheduler["references"]["smp_code_publish_barriers"][0]["rendezvous"], 29);
    assert_eq!(scheduler["last_transition"]["smp_cleanup_quiescence_count"], 1);
    assert_eq!(scheduler["references"]["smp_cleanup_quiescence"][0]["cleanup"], 20);
    assert_eq!(scheduler["last_transition"]["smp_snapshot_barrier_count"], 1);
    assert_eq!(scheduler["references"]["smp_snapshot_barriers"][0]["rendezvous"], 29);
    assert_eq!(scheduler["last_transition"]["smp_stress_run_count"], 1);
    assert_eq!(scheduler["references"]["smp_stress_runs"][0]["property_failures"], 0);
    assert_eq!(scheduler["last_transition"]["smp_scaling_benchmark_count"], 1);
    assert_eq!(scheduler["references"]["smp_scaling_benchmarks"][0]["efficiency_milli"], 833);
    assert_eq!(scheduler["last_transition"]["activation_resume_count"], 1);
    assert_eq!(scheduler["last_transition"]["activation_wait_count"], 1);
    assert_eq!(scheduler["last_transition"]["activation_cleanup_count"], 1);
    assert_eq!(scheduler["last_transition"]["preemption_latency_sample_count"], 1);
    assert_eq!(scheduler["last_transition"]["timer_epoch"], 3);
    assert_eq!(scheduler["last_transition"]["scheduler_decision_cursor"], 12);

    let live_edges = live_graph_edges(&package);
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "task"
        && edge["from"]["generation"] == 1
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 2));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "device"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 99
        && edge["relation"] == "device-resource"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "queue"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["to"]["generation"] == 1
        && edge["relation"] == "queue-device"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "descriptor"
        && edge["to"]["kind"] == "queue"
        && edge["to"]["id"] == 36
        && edge["to"]["generation"] == 1
        && edge["relation"] == "descriptor-queue"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "dma-buffer"
        && edge["to"]["kind"] == "descriptor"
        && edge["to"]["id"] == 37
        && edge["to"]["generation"] == 1
        && edge["relation"] == "dma-buffer-descriptor"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "dma-buffer"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 100
        && edge["to"]["generation"] == 1
        && edge["relation"] == "dma-buffer-resource"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "mmio-region"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["to"]["generation"] == 1
        && edge["relation"] == "mmio-region-device"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "mmio-region"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 101
        && edge["to"]["generation"] == 1
        && edge["relation"] == "mmio-region-resource"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "irq-line"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["to"]["generation"] == 1
        && edge["relation"] == "irq-line-device"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "irq-line"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 102
        && edge["to"]["generation"] == 1
        && edge["relation"] == "irq-line-resource"
        && edge["mode"] == "live"));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "activation"
        && edge["to"]["kind"] == "runnable-queue"
        && edge["to"]["generation"] == 1));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "activation"
        && edge["to"]["kind"] == "activation-context"
        && edge["to"]["generation"] == 2));
    assert!(live_edges.iter().any(|edge| edge["from"]["kind"] == "activation-context"
        && edge["to"]["kind"] == "saved-context"
        && edge["to"]["generation"] == 1));
    assert!(!live_edges.iter().any(|edge| edge["from"]["kind"] == "timer-interrupt"));
    let history_edges = history_graph_edges(&package);
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "timer-interrupt"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 2
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "preemption"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 3
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "saved-context"
        && edge["to"]["kind"] == "preemption"
        && edge["to"]["generation"] == 1
        && edge["relation"] == "captured-from-preemption"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "scheduler-decision"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 3
        && edge["relation"] == "selected"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"]
        == "cross-hart-scheduler-decision"
        && edge["to"]["kind"] == "hart"
        && edge["to"]["id"] == 1
        && edge["relation"] == "target-hart"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "activation-migration"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 4
        && edge["relation"] == "migrated-to"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-safe-point"
        && edge["to"]["kind"] == "hart"
        && edge["to"]["id"] == 1
        && edge["relation"] == "coordinator-hart"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-safe-point"
        && edge["to"]["kind"] == "hart"
        && edge["to"]["id"] == 2
        && edge["relation"] == "participant-hart"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["kind"] == "smp-safe-point"
        && edge["to"]["id"] == 28
        && edge["relation"] == "rendezvous-safe-point"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["kind"] == "hart"
        && edge["to"]["id"] == 2
        && edge["relation"] == "participant-hart"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-code-publish-barrier"
        && edge["to"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["id"] == 29
        && edge["relation"] == "publish-rendezvous"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-code-publish-barrier"
        && edge["to"]["kind"] == "hart"
        && edge["to"]["id"] == 2
        && edge["relation"] == "participant-hart"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-cleanup-quiescence"
        && edge["to"]["kind"] == "activation-cleanup"
        && edge["to"]["id"] == 20
        && edge["relation"] == "cleanup"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-cleanup-quiescence"
        && edge["to"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["id"] == 29
        && edge["relation"] == "cleanup-rendezvous"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-snapshot-barrier"
        && edge["to"]["kind"] == "stop-the-world-rendezvous"
        && edge["to"]["id"] == 29
        && edge["relation"] == "snapshot-rendezvous"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-stress-run"
        && edge["to"]["kind"] == "smp-snapshot-barrier"
        && edge["to"]["id"] == 32
        && edge["relation"] == "last-snapshot-barrier"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "smp-scaling-benchmark"
        && edge["to"]["kind"] == "smp-stress-run"
        && edge["to"]["id"] == 33
        && edge["relation"] == "scaling-stress-run"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "device"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 99
        && edge["relation"] == "device-resource"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "queue"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["relation"] == "queue-device"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "descriptor"
        && edge["to"]["kind"] == "queue"
        && edge["to"]["id"] == 36
        && edge["relation"] == "descriptor-queue"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "dma-buffer"
        && edge["to"]["kind"] == "descriptor"
        && edge["to"]["id"] == 37
        && edge["relation"] == "dma-buffer-descriptor"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "dma-buffer"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 100
        && edge["relation"] == "dma-buffer-resource"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "mmio-region"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["relation"] == "mmio-region-device"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "mmio-region"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 101
        && edge["relation"] == "mmio-region-resource"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "irq-line"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["relation"] == "irq-line-device"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "irq-line"
        && edge["to"]["kind"] == "resource"
        && edge["to"]["id"] == 102
        && edge["relation"] == "irq-line-resource"
        && edge["mode"] == "live"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "irq-event"
        && edge["to"]["kind"] == "irq-line"
        && edge["to"]["id"] == 40
        && edge["relation"] == "irq-event-line"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "irq-event"
        && edge["to"]["kind"] == "device"
        && edge["to"]["id"] == 35
        && edge["relation"] == "irq-event-device"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "irq-event"
        && edge["to"]["kind"] == "store"
        && edge["to"]["id"] == 1
        && edge["relation"] == "irq-event-driver-store"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "activation-resume"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 4
        && edge["relation"] == "resumed-to"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "activation-wait"
        && edge["to"]["kind"] == "activation"
        && edge["to"]["generation"] == 6
        && edge["relation"] == "cancelled-to"
        && edge["mode"] == "historical"));
    assert!(history_edges.iter().any(|edge| edge["from"]["kind"] == "preemption-latency"
        && edge["to"]["kind"] == "activation-resume"
        && edge["to"]["generation"] == 1
        && edge["relation"] == "measured-resume"
        && edge["mode"] == "historical"));
}

#[test]
fn scheduler_view_v1_exposes_current_activation_owners() {
    let mut package = minimal_graph_package();
    package.package_id = "s4-test".to_owned();
    package.semantic.hart_count = 1;
    package.semantic.hart_records.push(HartRecordManifest {
        id: 2,
        hardware_id: 1,
        label: "hart1".to_owned(),
        state: "running".to_owned(),
        generation: 3,
        boot: false,
        current_activation: Some(11),
        current_activation_generation: Some(4),
        current_task: Some(7),
        current_task_generation: Some(1),
        current_store: Some(5),
        current_store_generation: Some(2),
        last_event: Some(21),
        last_current_event: Some(21),
        note: "s4 current owner".to_owned(),
    });

    let scheduler = scheduler_view_v1(&package);
    assert_eq!(scheduler["references"]["current_activation_owners"][0]["hart"]["id"], 2);
    assert_eq!(
        scheduler["references"]["current_activation_owners"][0]["activation"]["generation"],
        4
    );
    assert_eq!(scheduler["references"]["current_activation_owners"][0]["store"]["generation"], 2);
}

#[test]
fn cleanup_view_v1_exposes_steps_effects_and_status() {
    let target = ContractObjectRefManifest { kind: "store".to_owned(), id: 1, generation: 2 };
    let view = cleanup_view_v1(&CleanupTransactionManifest {
        id: 5,
        store: 1,
        store_generation: 2,
        target_store_generation: 1,
        result_store_generation: Some(2),
        activation: None,
        activation_generation: None,
        code_object: None,
        code_generation: None,
        generation: 1,
        started_at: 10,
        finished_at: Some(11),
        state: "completed".to_owned(),
        reason: "fault".to_owned(),
        released_dmw_leases: 1,
        cancelled_waits: 0,
        revoked_capabilities: vec![4],
        revoked_capability_refs: vec![ContractObjectRefManifest {
            kind: "capability".to_owned(),
            id: 4,
            generation: 2,
        }],
        dropped_resources: 1,
        unbound_code_object: true,
        state_digest: "store:1@2:dead|code:none|activations=[]|leases=[]|caps=[]".to_owned(),
        effect: "errno".to_owned(),
        steps: vec![CleanupStepManifest {
            step: "mark-store-state".to_owned(),
            state: "done".to_owned(),
            detail: "store marked dead".to_owned(),
            target: Some(target.clone()),
            observed_generation: Some(2),
            error: None,
            idempotency_key: "mark-store-state".to_owned(),
            event_seq: 11,
        }],
        effects: vec![CleanupEffectManifest {
            kind: "mark-store-dead".to_owned(),
            target,
            expected_generation: 2,
            status: "applied".to_owned(),
            event_seq: 11,
        }],
    });
    assert_eq!(view["kind"], "cleanup");
    assert_eq!(view["steps"][0]["state"], "done");
    assert_eq!(view["effects"][0]["kind"], "mark-store-dead");
    assert_eq!(view["references"]["target_store"]["generation"], 1);
    assert_eq!(view["references"]["result_store"]["generation"], 2);
    assert_eq!(view["references"]["revoked_capabilities"][0]["id"], 4);
    assert_eq!(view["idempotence"]["state_digest_present"], true);
}

#[test]
fn executor_object_views_do_not_dump_internal_schema() {
    let artifact = artifact_view_v1(&TargetArtifactImageManifest {
        id: 2,
        package: "driver_virtio_net".to_owned(),
        artifact_name: "driver_virtio_net".to_owned(),
        role: "driver".to_owned(),
        kind: "target-artifact-image-v1".to_owned(),
        target_profile: "host-validation".to_owned(),
        artifact_hash: "artifact".to_owned(),
        hash_status: "manifest-bound".to_owned(),
        abi_fingerprint: "abi".to_owned(),
        manifest_binding_hash: "binding".to_owned(),
        code_hash: "code".to_owned(),
        signature_scheme: "prototype-self-signed-sha256".to_owned(),
        signature_status: "profile-bound-unverified".to_owned(),
        signature_verified: false,
        signer: "test-signer".to_owned(),
        exports: vec!["memory".to_owned()],
        payload_len: 4096,
        ..TargetArtifactImageManifest::default()
    });
    assert_eq!(artifact["schema"], VIEW_SCHEMA_V1);
    assert_eq!(artifact["kind"], "artifact");
    assert_eq!(artifact["state"], "accepted");
    assert_eq!(artifact["references"]["artifact_hash"], "artifact");
    assert_eq!(artifact["references"]["hash_status"], "manifest-bound");
    assert_eq!(artifact["references"]["manifest_binding_hash"], "binding");
    assert_eq!(artifact["verification"]["signature_status"], "profile-bound-unverified");
    assert_eq!(artifact["verification"]["signature_verified"], false);
    assert_eq!(artifact["last_transition"]["payload_len"], 4096);

    let code = code_object_view_v1(&CodeObjectManifest {
        id: 3,
        artifact_id: 2,
        package: "driver_virtio_net".to_owned(),
        owner_profile: "host-validation".to_owned(),
        generation: 4,
        state: "bound-to-store".to_owned(),
        bound_store: Some(1),
        bound_store_generation: Some(7),
        text_start: 0x1000,
        text_len: 128,
        text_permission: "rx".to_owned(),
        code_hash: "code".to_owned(),
        simd_requirement: artifact_manifest::CodeObjectSimdRequirementManifest {
            uses_simd: true,
            declared: true,
            required_abi: "riscv-v".to_owned(),
            min_vector_register_count: 32,
            min_vector_register_bits: 128,
            target_feature_set: Some(ContractObjectRefManifest {
                kind: "target-feature-set".to_owned(),
                id: 21_000,
                generation: 1,
            }),
            status: "declared".to_owned(),
            note: "requires RVV".to_owned(),
        },
        ..CodeObjectManifest::default()
    });
    assert_eq!(code["kind"], "code-object");
    assert_eq!(code["generation"], 4);
    assert_eq!(code["references"]["bound_store"]["generation"], 7);
    assert_eq!(code["memory"]["text"]["permission"], "rx");
    assert_eq!(code["simd_requirement"]["uses_simd"], true);
    assert_eq!(code["simd_requirement"]["required_abi"], "riscv-v");
    assert_eq!(code["simd_requirement"]["target_feature_set"]["kind"], "target-feature-set");
}

#[test]
fn trace_views_expose_attribution_generations() {
    let activation = activation_view_v1(&ActivationRecordManifest {
        id: 10,
        store: 1,
        store_generation: 2,
        code_object: 3,
        code_generation: 4,
        artifact: 5,
        entry: "_start".to_owned(),
        generation: 6,
        state: "running".to_owned(),
        start_event: 7,
        active_dmw_leases: 1,
        ..ActivationRecordManifest::default()
    });
    assert_eq!(activation["kind"], "activation");
    assert_eq!(activation["owner"]["store_generation"], 2);
    assert_eq!(activation["references"]["code_object"]["generation"], 4);

    let trap = trap_view_v1(&TrapRecordManifest {
        id: 11,
        generation: 1,
        class: "capability-trap".to_owned(),
        store: Some(1),
        store_generation: Some(2),
        activation: Some(10),
        activation_generation: Some(6),
        code_object: Some(3),
        code_generation: Some(4),
        artifact: Some(5),
        artifact_generation: Some(1),
        trap_kind: Some("simd-unsupported".to_owned()),
        attribution_status: "trap-map-attributed".to_owned(),
        simd_attribution: Some(artifact_manifest::SimdTrapAttributionManifest {
            classification: "unsupported-target-profile".to_owned(),
            required_abi: "riscv-v".to_owned(),
            min_vector_register_count: 32,
            min_vector_register_bits: 128,
            target_feature_set: Some(ContractObjectRefManifest {
                kind: "target-feature-set".to_owned(),
                id: 21_000,
                generation: 1,
            }),
            code_requirement_status: "declared".to_owned(),
            note: "SIMD trap attribution".to_owned(),
        }),
        fault_policy: "restart".to_owned(),
        effect: "cleanup".to_owned(),
        detail: "denied".to_owned(),
        ..TrapRecordManifest::default()
    });
    assert_eq!(trap["kind"], "trap");
    assert_eq!(trap["owner"]["activation_generation"], 6);
    assert_eq!(trap["references"]["code_object"]["generation"], 4);
    assert_eq!(trap["simd_attribution"]["classification"], "unsupported-target-profile");
    assert_eq!(trap["simd_attribution"]["target_feature_set"]["generation"], 1);
    assert_eq!(trap["last_error"], "denied");
    assert_eq!(trap["attribution"]["status"], "trap-map-attributed");

    let hostcall = hostcall_trace_view_v1(&HostcallTraceManifest {
        id: 12,
        generation: 1,
        abi_version: "vmos-target-hostcall-frame-v1".to_owned(),
        frame_size: 128,
        activation: 10,
        activation_generation: 6,
        store: 1,
        store_generation: 2,
        code_object: 3,
        code_generation: 4,
        artifact: 5,
        artifact_generation: 7,
        hostcall_number: 64,
        hostcall_seq: 99,
        caller_offset: 16,
        name: "mmio.read32".to_owned(),
        category: "mmio".to_owned(),
        subject: "driver_virtio_net".to_owned(),
        subject_source: "active-store-activation-code-object".to_owned(),
        object: "mmio.bar0".to_owned(),
        operation: "read32".to_owned(),
        allowed: false,
        gate_status: "denied".to_owned(),
        result: "cap-arg-generation".to_owned(),
        denial_reason: Some("cap-arg-generation".to_owned()),
        ..HostcallTraceManifest::default()
    });
    assert_eq!(hostcall["kind"], "hostcall");
    assert_eq!(hostcall["owner"]["activation_generation"], 6);
    assert_eq!(hostcall["references"]["artifact"]["generation"], 7);
    assert_eq!(hostcall["call"]["caller_offset"], 16);
    assert_eq!(hostcall["call"]["subject_source"], "active-store-activation-code-object");
    assert_eq!(hostcall["gate"]["status"], "denied");
    assert_eq!(hostcall["gate"]["denial_reason"], "cap-arg-generation");
    assert_eq!(hostcall["last_error"], "cap-arg-generation");
}

#[test]
fn substrate_event_view_v1_explains_unsupported_authority() {
    let view = substrate_event_view_v1(&SubstrateEventManifest {
        id: 21,
        epoch: 34,
        event_kind: "unsupported".to_owned(),
        authority: "DmaAuthority".to_owned(),
        operation: "dma_alloc".to_owned(),
        requester: Some("driver.fake_net".to_owned()),
        artifact: Some(9),
        store: Some(4),
        capability: None,
        explanation: "driver.fake_net observed DmaAuthority::dma_alloc as unsupported".to_owned(),
    });
    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "substrate-event");
    assert_eq!(view["id"], 21);
    assert_eq!(view["state"], "unsupported");
    assert_eq!(view["authority"], "DmaAuthority");
    assert_eq!(view["operation"], "dma_alloc");
    assert_eq!(view["requester"], "driver.fake_net");
    assert_eq!(view["references"]["artifact"], 9);
    assert_eq!(view["references"]["store"], 4);
    assert_eq!(view["references"]["event_epoch"], 34);
    assert_eq!(
        view["last_error"],
        "driver.fake_net observed DmaAuthority::dma_alloc as unsupported"
    );
}

#[test]
fn command_result_view_v1_exposes_status_events_and_violations() {
    let view = command_result_view_v1(&CommandResultManifest {
        id: 5,
        issuer: "target-executor-command-probe".to_owned(),
        command: "create-wait".to_owned(),
        status: "rejected".to_owned(),
        events: Vec::new(),
        effects: Vec::new(),
        violations: vec!["create-wait requires owner task or owner store".to_owned()],
    });
    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "command");
    assert_eq!(view["id"], 5);
    assert_eq!(view["state"], "rejected");
    assert_eq!(view["issuer"], "target-executor-command-probe");
    assert_eq!(view["command_name"], "create-wait");
    assert_eq!(view["last_transition"]["event_count"], 0);
    assert_eq!(view["last_error"], "create-wait requires owner task or owner store");
}

#[test]
fn interface_event_view_v1_explains_unsupported_interface() {
    let view = interface_event_view_v1(&InterfaceEventManifest {
        id: 8,
        epoch: 13,
        interface_kind: "standard-wasi".to_owned(),
        interface: "wasi:clocks/monotonic-clock".to_owned(),
        operation: "subscribe".to_owned(),
        requester: Some("target-executor-interface-probe".to_owned()),
        artifact: None,
        store: None,
        explanation:
            "target-executor-interface-probe observed standard-wasi wasi:clocks/monotonic-clock::subscribe as unsupported"
                .to_owned(),
    });
    assert_eq!(view["schema"], VIEW_SCHEMA_V1);
    assert_eq!(view["kind"], "interface-event");
    assert_eq!(view["state"], "unsupported");
    assert_eq!(view["interface_kind"], "standard-wasi");
    assert_eq!(view["interface"], "wasi:clocks/monotonic-clock");
    assert_eq!(view["operation"], "subscribe");
    assert_eq!(view["references"]["event_epoch"], 13);
    assert_eq!(
        view["last_error"],
        "target-executor-interface-probe observed standard-wasi wasi:clocks/monotonic-clock::subscribe as unsupported"
    );
}
