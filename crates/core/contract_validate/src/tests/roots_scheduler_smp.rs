use super::*;

#[test]
fn semantic_roots_reject_substrate_event_count_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.substrate_events.push(SubstrateEventManifest {
        id: 1,
        epoch: 7,
        event_kind: "unsupported".to_owned(),
        authority: "DmaAuthority".to_owned(),
        operation: "dma_alloc".to_owned(),
        requester: Some("test".to_owned()),
        artifact: None,
        store: None,
        capability: None,
        explanation: "unsupported probe".to_owned(),
    });
    package
        .semantic
        .roots
        .substrate_event_roots
        .push("substrate-event:unsupported:DmaAuthority:dma_alloc".to_owned());

    let err = validate_migration_package(&package).expect_err("count mismatch must fail");
    assert_eq!(err.to_string(), "substrate event root/count mismatch");
}

#[test]
fn semantic_roots_reject_runtime_scheduler_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.runtime_activation_count = 1;
    package.semantic.runtime_activation_records.push(RuntimeActivationRecordManifest {
        id: 11,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: None,
        owner_store_generation: None,
        code_object: None,
        generation: 1,
        state: "runnable".to_owned(),
        runnable_queue: Some(1),
        runnable_queue_generation: Some(1),
        last_event: Some(3),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "runtime activation root/count mismatch");
}

#[test]
fn semantic_roots_reject_activation_context_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.activation_context_count = 1;
    package.semantic.activation_contexts.push(artifact_manifest::ActivationContextManifest {
        id: 12,
        activation: 11,
        activation_generation: 2,
        owner_task: 7,
        owner_task_generation: 1,
        owner_store: None,
        owner_store_generation: None,
        generation: 1,
        state: "created".to_owned(),
        current_saved_context: None,
        current_saved_context_generation: None,
        vector_state: None,
        vector_status: "absent".to_owned(),
        vector_state_event: None,
        last_event: Some(4),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "activation context root/count mismatch");
}

#[test]
fn semantic_roots_reject_timer_interrupt_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.timer_interrupt_count = 1;
    package.semantic.timer_interrupts.push(artifact_manifest::TimerInterruptManifest {
        id: 3,
        timer_epoch: 1,
        hart: 1,
        hart_generation: Some(2),
        hardware_hart: Some(0),
        target_activation: Some(11),
        target_activation_generation: Some(2),
        target_task: Some(7),
        target_task_generation: Some(1),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 5,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "timer interrupt root/count mismatch");
}

#[test]
fn semantic_roots_reject_ipi_event_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.ipi_event_count = 1;
    package.semantic.ipi_events.push(artifact_manifest::IpiEventManifest {
        id: 4,
        source_hart: 1,
        source_hart_generation: 2,
        source_hardware_hart: 0,
        target_hart: 2,
        target_hart_generation: 2,
        target_hardware_hart: 1,
        kind: "scheduler-kick".to_owned(),
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 5,
        reason: "test".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "ipi event root/count mismatch");
}

#[test]
fn semantic_roots_reject_remote_preempt_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.remote_preempt_count = 1;
    package.semantic.remote_preempts.push(artifact_manifest::RemotePreemptManifest {
        id: 4,
        ipi: 3,
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
        state: "applied".to_owned(),
        preempted_at_event: 6,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "remote preempt root/count mismatch");
}

#[test]
fn semantic_roots_reject_remote_park_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.remote_park_count = 1;
    package.semantic.remote_parks.push(artifact_manifest::RemoteParkManifest {
        id: 5,
        ipi: 3,
        ipi_generation: 1,
        source_hart: 1,
        source_hart_generation: 2,
        target_hart: 2,
        target_hart_generation_before: 3,
        target_hart_generation_after: 4,
        generation: 1,
        state: "parked".to_owned(),
        parked_at_event: 6,
        reason: "test".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "remote park root/count mismatch");
}

#[test]
fn semantic_roots_reject_preemption_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.preemption_count = 1;
    package.semantic.preemptions.push(artifact_manifest::PreemptionManifest {
        id: 4,
        activation: 11,
        activation_generation_before: 3,
        activation_generation_after: 4,
        timer_interrupt: 3,
        timer_interrupt_generation: 1,
        queue: 1,
        queue_generation: 1,
        generation: 1,
        state: "applied".to_owned(),
        preempted_at_event: 6,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "preemption root/count mismatch");
}

#[test]
fn semantic_roots_reject_scheduler_decision_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.scheduler_decision_count = 1;
    package.semantic.scheduler_decisions.push(artifact_manifest::SchedulerDecisionManifest {
        id: 5,
        queue: 1,
        queue_generation: 1,
        selected_activation: 11,
        selected_activation_generation: 4,
        owner_task: 7,
        owner_task_generation: 1,
        generation: 1,
        state: "recorded".to_owned(),
        decided_at_event: 7,
        reason: "runnable-available".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "scheduler decision root/count mismatch");
}

#[test]
fn semantic_roots_reject_cross_hart_scheduler_decision_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.cross_hart_scheduler_decision_count = 1;
    package.semantic.cross_hart_scheduler_decisions.push(
        artifact_manifest::CrossHartSchedulerDecisionManifest {
            id: 6,
            scheduler_decision: 5,
            scheduler_decision_generation: 1,
            deciding_hart: 1,
            deciding_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 4,
            queue: 1,
            queue_generation: 2,
            queue_owner_hart_generation: 2,
            selected_activation: 11,
            selected_activation_generation: 4,
            generation: 1,
            state: "recorded".to_owned(),
            decided_at_event: 8,
            reason: "remote-runnable".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "cross-hart scheduler decision root/count mismatch");
}

#[test]
fn semantic_roots_reject_activation_migration_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.activation_migration_count = 1;
    package.semantic.activation_migrations.push(artifact_manifest::ActivationMigrationManifest {
        id: 7,
        activation: 11,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 7,
        owner_task_generation: 1,
        source_hart: 2,
        source_hart_generation: 4,
        target_hart: 1,
        target_hart_generation: 2,
        source_queue: 2,
        source_queue_generation: 2,
        source_queue_owner_hart_generation: 2,
        target_queue: 3,
        target_queue_generation: 2,
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
        migrated_at_event: 9,
        reason: "rebalance".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "activation migration root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_safe_point_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_safe_point_count = 1;
    package.semantic.smp_safe_points.push(artifact_manifest::SmpSafePointManifest {
        id: 8,
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
                hart_generation: 4,
                hardware_hart: 1,
                hart_state: "idle".to_owned(),
                current_activation: None,
                current_activation_generation: None,
            },
        ],
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 10,
        reason: "smp-safe-point".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp safe point root/count mismatch");
}

#[test]
fn semantic_roots_reject_stop_the_world_rendezvous_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.stop_the_world_rendezvous_count = 1;
    package.semantic.stop_the_world_rendezvous.push(
        artifact_manifest::StopTheWorldRendezvousManifest {
            id: 9,
            epoch: 1,
            safe_point: 8,
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
                    hart_generation: 4,
                    hardware_hart: 1,
                    hart_state: "idle".to_owned(),
                },
            ],
            stop_new_activations: true,
            generation: 1,
            state: "completed".to_owned(),
            completed_at_event: 11,
            reason: "stop-the-world".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "stop-the-world rendezvous root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_code_publish_barrier_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_code_publish_barrier_count = 1;
    package.semantic.smp_code_publish_barriers.push(
        artifact_manifest::SmpCodePublishBarrierManifest {
            id: 10,
            rendezvous: 9,
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
                    hart_generation: 4,
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
            validated_at_event: 12,
            reason: "smp-code-publish-barrier".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp code publish barrier root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_cleanup_quiescence_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_cleanup_quiescence_count = 1;
    package.semantic.smp_cleanup_quiescence.push(artifact_manifest::SmpCleanupQuiescenceManifest {
        id: 11,
        cleanup: 10,
        cleanup_generation: 1,
        store: 7,
        target_store_generation: 2,
        result_store_generation: 4,
        activation: 12,
        activation_generation_after: 5,
        rendezvous: 9,
        rendezvous_generation: 1,
        rendezvous_epoch: 2,
        participants: vec![
            artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                hart: 1,
                hart_generation: 4,
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
                hart_generation: 5,
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
        validated_at_event: 13,
        reason: "smp-cleanup-quiescence".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp cleanup quiescence root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_snapshot_barrier_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_snapshot_barrier_count = 1;
    package.semantic.smp_snapshot_barriers.push(artifact_manifest::SmpSnapshotBarrierManifest {
        id: 12,
        rendezvous: 9,
        rendezvous_generation: 1,
        rendezvous_epoch: 3,
        event_log_cursor: 42,
        participants: vec![
            artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                hart: 1,
                hart_generation: 4,
                hardware_hart: 0,
                hart_state: "idle".to_owned(),
                event_log_cursor_observed: 42,
                snapshot_safe: true,
            },
            artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                hart: 2,
                hart_generation: 5,
                hardware_hart: 1,
                hart_state: "parked".to_owned(),
                event_log_cursor_observed: 42,
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
        validated_at_event: 43,
        reason: "smp-snapshot-barrier".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp snapshot barrier root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_stress_run_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_stress_run_count = 1;
    package.semantic.smp_stress_runs.push(artifact_manifest::SmpStressRunManifest {
        id: 15,
        scenario: "smp-stress".to_owned(),
        iterations: 3,
        hart_count: 2,
        event_log_cursor: 50,
        observed_safe_point_count: 3,
        observed_rendezvous_count: 3,
        observed_code_publish_barrier_count: 1,
        observed_cleanup_quiescence_count: 1,
        observed_snapshot_barrier_count: 1,
        observed_activation_migration_count: 1,
        observed_remote_preempt_count: 1,
        observed_remote_park_count: 1,
        invariant_checks: 3,
        property_failures: 0,
        last_safe_point: 3,
        last_safe_point_generation: 1,
        last_rendezvous: 3,
        last_rendezvous_generation: 1,
        last_code_publish_barrier: 1,
        last_code_publish_barrier_generation: 1,
        last_cleanup_quiescence: 1,
        last_cleanup_quiescence_generation: 1,
        last_snapshot_barrier: 1,
        last_snapshot_barrier_generation: 1,
        last_activation_migration: 1,
        last_activation_migration_generation: 1,
        last_remote_preempt: 1,
        last_remote_preempt_generation: 1,
        last_remote_park: 1,
        last_remote_park_generation: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 51,
        reason: "smp-stress-property".to_owned(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp stress run root/count mismatch");
}

#[test]
fn semantic_roots_reject_smp_scaling_benchmark_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.smp_scaling_benchmark_count = 1;
    package.semantic.smp_scaling_benchmarks.push(artifact_manifest::SmpScalingBenchmarkManifest {
        id: 16,
        scenario: "smp-scaling".to_owned(),
        stress_run: 15,
        stress_run_generation: 1,
        hart_count: 2,
        workload_units: 6,
        baseline_single_hart_nanos: 120_000,
        measured_smp_nanos: 72_000,
        budget_nanos: 90_000,
        speedup_milli: 1_666,
        efficiency_milli: 833,
        event_log_cursor: 51,
        stress_safe_point_count: 3,
        stress_rendezvous_count: 3,
        stress_property_failures: 0,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 52,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "smp scaling benchmark root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_smp_preemption_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_smp_preemption_cleanup_count = 1;
    package.semantic.integrated_smp_preemption_cleanups.push(
        artifact_manifest::IntegratedSmpPreemptionCleanupManifest {
            id: 17,
            scenario: "x0-smp-preemption-cleanup".to_owned(),
            stress_run: 15,
            stress_run_generation: 1,
            preemption: 1,
            preemption_generation: 1,
            timer_interrupt: 1,
            timer_interrupt_generation: 1,
            saved_context: 1,
            saved_context_generation: 1,
            remote_preempt: 1,
            remote_preempt_generation: 1,
            activation_cleanup: 1,
            activation_cleanup_generation: 1,
            smp_cleanup_quiescence: 1,
            smp_cleanup_quiescence_generation: 1,
            cleanup_store: 1,
            target_store_generation: 2,
            result_store_generation: 4,
            cleanup_activation: 1,
            cleanup_activation_generation_after: 5,
            hart_count: 2,
            invariant_checks: 7,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 53,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated smp preemption cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_smp_network_fault_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_smp_network_fault_count = 1;
    package.semantic.integrated_smp_network_faults.push(
        artifact_manifest::IntegratedSmpNetworkFaultManifest {
            id: 18,
            scenario: "x1-smp-network-driver-fault".to_owned(),
            network_driver_cleanup: 46,
            network_driver_cleanup_generation: 1,
            smp_stress_run: 15,
            smp_stress_run_generation: 1,
            remote_preempt: 3,
            remote_preempt_generation: 1,
            smp_cleanup_quiescence: 4,
            smp_cleanup_quiescence_generation: 1,
            driver_store: 7,
            driver_store_generation: 3,
            packet_device: 10,
            packet_device_generation: 1,
            adapter: 11,
            adapter_generation: 1,
            backend: artifact_manifest::ContractObjectRefManifest {
                kind: "virtio-net-backend-object".to_owned(),
                id: 12,
                generation: 1,
            },
            io_cleanup: 47,
            io_cleanup_generation: 1,
            cancelled_socket_wait_count: 1,
            cancelled_wait_token_count: 1,
            revoked_packet_capability_count: 1,
            hart_count: 2,
            invariant_checks: 7,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 54,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated smp network fault root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_disk_preempt_fault_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_disk_preempt_fault_count = 1;
    package.semantic.integrated_disk_preempt_faults.push(
        artifact_manifest::IntegratedDiskPreemptFaultManifest {
            id: 19,
            scenario: "x2-disk-pending-io-fault-under-preemption".to_owned(),
            preemption: 6,
            preemption_generation: 1,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            block_pending_io_policy: 71,
            block_pending_io_policy_generation: 1,
            block_wait: 55,
            block_wait_generation: 1,
            wait: 8,
            wait_generation: 1,
            block_request: 53,
            block_request_generation: 1,
            retry_request: None,
            retry_request_generation: None,
            block_device: 51,
            block_device_generation: 1,
            block_range: 52,
            block_range_generation: 1,
            driver_store: Some(7),
            driver_store_generation: Some(2),
            action: "eio".to_owned(),
            errno: 5,
            preempted_activation: 9,
            preempted_activation_generation_after: 4,
            invariant_checks: 6,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 55,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated disk preempt fault root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_simd_migration_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_simd_migration_count = 1;
    package.semantic.integrated_simd_migrations.push(
        artifact_manifest::IntegratedSimdMigrationManifest {
            id: 20,
            scenario: "x3-simd-task-migration-across-harts".to_owned(),
            activation_migration: 9,
            activation_migration_generation: 1,
            target_feature_set: 75,
            target_feature_set_generation: 1,
            source_vector_state: artifact_manifest::ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 76,
                generation: 1,
            },
            migrated_vector_state: artifact_manifest::ContractObjectRefManifest {
                kind: "vector-state".to_owned(),
                id: 77,
                generation: 1,
            },
            activation: 8,
            activation_generation_before: 2,
            activation_generation_after: 3,
            context: 4,
            context_generation_after: 3,
            source_hart: 1,
            source_hart_generation: 1,
            target_hart: 2,
            target_hart_generation: 1,
            source_queue: 3,
            source_queue_generation: 2,
            target_queue: 4,
            target_queue_generation: 2,
            simd_abi: "riscv-v".to_owned(),
            vector_register_count: 32,
            vector_register_bits: 128,
            invariant_checks: 6,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 56,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated simd migration root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_network_disk_io_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_network_disk_io_count = 1;
    package.semantic.integrated_network_disk_ios.push(
        artifact_manifest::IntegratedNetworkDiskIoManifest {
            id: 26_401,
            scenario: "x4-network-disk-concurrent-io".to_owned(),
            network_benchmark: 10_067,
            network_benchmark_generation: 1,
            block_benchmark: 20_132,
            block_benchmark_generation: 1,
            network_owner_store: 9,
            network_owner_store_generation: 3,
            network_adapter: 10_025,
            network_adapter_generation: 1,
            packet_device: 10_002,
            packet_device_generation: 1,
            socket: 10_031,
            socket_generation: 1,
            block_backend: artifact_manifest::ContractObjectRefManifest {
                kind: "fake-block-backend-object".to_owned(),
                id: 20_026,
                generation: 1,
            },
            block_device: 20_002,
            block_device_generation: 1,
            block_request_queue: 20_053,
            block_request_queue_generation: 1,
            block_dma_buffer: 20_061,
            block_dma_buffer_generation: 1,
            network_sample_bytes: 6_000,
            block_sample_bytes: 8_192,
            network_sample_packets: 3,
            block_sample_requests: 2,
            concurrent_window_nanos: 120_000,
            combined_throughput_bytes_per_sec: 118_266_666,
            max_p99_latency_nanos: 48_000,
            invariant_checks: 6,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 574,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated network disk io root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_display_scheduler_load_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_display_scheduler_load_count = 1;
    package.semantic.integrated_display_scheduler_loads.push(
        artifact_manifest::IntegratedDisplaySchedulerLoadManifest {
            id: 26_501,
            scenario: "x5-display-update-during-scheduler-load".to_owned(),
            framebuffer_benchmark: 25_101,
            framebuffer_benchmark_generation: 1,
            scheduler_decision: 9_001,
            scheduler_decision_generation: 1,
            owner_store: 1,
            owner_store_generation: 2,
            owner_task: 7,
            owner_task_generation: 1,
            queue: 9_002,
            queue_generation: 2,
            selected_activation: 9_002,
            selected_activation_generation: 4,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            display_capability: 23_201,
            display_capability_generation: 1,
            framebuffer_write: 23_501,
            framebuffer_write_generation: 1,
            framebuffer_flush_region: 23_601,
            framebuffer_flush_region_generation: 1,
            display_event_log: 23_801,
            display_event_log_generation: 1,
            sample_frames: 1,
            sample_bytes: 3_200,
            scheduler_load_units: 1,
            display_measured_nanos: 100_000,
            scheduler_decided_at_event: 50,
            display_recorded_at_event: 571,
            invariant_checks: 6,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 575,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated display scheduler load root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_snapshot_io_lease_barrier_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_snapshot_io_lease_barrier_count = 1;
    package.semantic.integrated_snapshot_io_lease_barriers.push(
        artifact_manifest::IntegratedSnapshotIoLeaseBarrierManifest {
            id: 26_601,
            scenario: "x6-snapshot-barrier-blocks-active-io-leases".to_owned(),
            smp_snapshot_barrier: 9_401,
            smp_snapshot_barrier_generation: 1,
            io_cleanup: 9_967,
            io_cleanup_generation: 1,
            display_snapshot_barrier: 24_001,
            display_snapshot_barrier_generation: 1,
            driver_store: 2,
            driver_store_generation: 2,
            device: 9_701,
            device_generation: 1,
            display: 23_101,
            display_generation: 1,
            framebuffer: 23_001,
            framebuffer_generation: 1,
            active_dmw_lease_count: 0,
            in_flight_dma_count: 0,
            raw_dma_binding_count: 0,
            raw_mmio_binding_count: 0,
            active_framebuffer_window_lease_count: 0,
            active_framebuffer_mapping_count: 0,
            dirty_framebuffer_region_count: 0,
            released_dma_buffers: 1,
            released_mmio_regions: 1,
            released_irq_lines: 1,
            released_framebuffer_window_leases: 1,
            revoked_device_capabilities: 4,
            revoked_display_capabilities: 1,
            smp_barrier_event: 117,
            io_cleanup_completed_event: 152,
            display_barrier_event: 567,
            invariant_checks: 7,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 576,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "integrated snapshot io lease barrier root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_code_publish_smp_workload_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_code_publish_smp_workload_count = 1;
    package.semantic.integrated_code_publish_smp_workloads.push(
        artifact_manifest::IntegratedCodePublishSmpWorkloadManifest {
            id: 26_701,
            scenario: "x7-code-publish-while-smp-workload-active".to_owned(),
            smp_stress_run: 9_501,
            smp_stress_run_generation: 1,
            smp_code_publish_barrier: 9_201,
            smp_code_publish_barrier_generation: 1,
            publish_rendezvous: 9_101,
            publish_rendezvous_generation: 1,
            publish_safe_point: 9_001,
            publish_safe_point_generation: 1,
            hart_count: 2,
            workload_iterations: 3,
            observed_safe_point_count: 3,
            observed_rendezvous_count: 3,
            observed_code_publish_barrier_count: 1,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: true,
            code_publish_executed: false,
            participant_count: 2,
            stress_event_log_cursor: 117,
            barrier_event: 24,
            stress_recorded_at_event: 118,
            invariant_checks: 7,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 577,
            note: "x7 semantic code publish while smp workload is active".to_owned(),
        },
    );

    let err = validate_semantic_roots(&package).unwrap_err();
    assert_eq!(err.to_string(), "integrated code publish smp workload root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_display_panic_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_display_panic_count = 1;
    package.semantic.integrated_display_panics.push(
        artifact_manifest::IntegratedDisplayPanicManifest {
            id: 26_801,
            scenario: "x8-panic-ring-extraction-after-substrate-panic".to_owned(),
            substrate_panic_event: 577,
            substrate_panic_epoch: 1,
            substrate_panic_cpu: 0,
            substrate_panic_reason_code: 1,
            display_panic_last_frame: 25_001,
            display_panic_last_frame_generation: 1,
            panic_ring_bytes: 65_536,
            panic_record_max_bytes: 4_096,
            panic_ring_oldest_seq: 1,
            panic_ring_newest_seq: 3,
            panic_ring_record_count: 3,
            panic_ring_lost_count: 0,
            jsonl_frame_count: 5,
            contract_panic_summary_records: 1,
            last_frame_summary_records: 1,
            corrupt_record_count: 0,
            truncated_record_count: 0,
            summary_record_bytes: 512,
            raw_framebuffer_bytes_exported: false,
            panic_path_allocates: false,
            invariant_checks: 8,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 578,
            note: "x8 panic ring extraction after substrate panic".to_owned(),
        },
    );

    let err = validate_semantic_roots(&package).unwrap_err();
    assert_eq!(err.to_string(), "integrated display panic root/count mismatch");
}

#[test]
fn semantic_roots_reject_integrated_osctl_trace_replay_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.integrated_osctl_trace_replay_count = 1;
    package.semantic.integrated_osctl_trace_replays.push(
        artifact_manifest::IntegratedOsctlTraceReplayManifest {
            id: 26_901,
            scenario: "x9-full-osctl-trace-replay".to_owned(),
            integrated_smp_preemption_cleanup: 26_001,
            integrated_smp_preemption_cleanup_generation: 1,
            integrated_smp_network_fault: 26_101,
            integrated_smp_network_fault_generation: 1,
            integrated_disk_preempt_fault: 26_201,
            integrated_disk_preempt_fault_generation: 1,
            integrated_simd_migration: 26_301,
            integrated_simd_migration_generation: 1,
            integrated_network_disk_io: 26_401,
            integrated_network_disk_io_generation: 1,
            integrated_display_scheduler_load: 26_501,
            integrated_display_scheduler_load_generation: 1,
            integrated_snapshot_io_lease_barrier: 26_601,
            integrated_snapshot_io_lease_barrier_generation: 1,
            integrated_code_publish_smp_workload: 26_701,
            integrated_code_publish_smp_workload_generation: 1,
            integrated_display_panic: 26_801,
            integrated_display_panic_generation: 1,
            replay_event_cursor: 579,
            stable_view_count: 9,
            historical_edge_count: 9,
            replayed_root_count: 9,
            integrated_scenario_count: 9,
            replay_fixture_count: 9,
            contract_validation_ok: true,
            replay_validation_ok: true,
            graph_history_ok: true,
            roots_match_counts: true,
            invariant_checks: 9,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 580,
            note: "x9 full osctl trace replay".to_owned(),
        },
    );

    let err = validate_semantic_roots(&package).unwrap_err();
    assert_eq!(err.to_string(), "integrated osctl trace replay root/count mismatch");
}
