use super::*;

#[test]
pub(super) fn preemptive_runtime_p7_wait_blocks_and_cancel_does_not_auto_resume() {
    let mut graph = p7_resumed_activation();
    let blocker = ContractObjectRef::new(ContractObjectKind::TimerInterrupt, 5, 1);

    let blocked = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p7-test",
        SemanticCommand::BlockActivationOnWait {
            activation_wait: 16,
            activation: 11,
            activation_generation: 5,
            wait: 17,
            kind: SemanticWaitKind::Timer,
            blockers: {
                let mut blockers = Vec::new();
                blockers.push(blocker);
                blockers
            },
            deadline: Some(200),
            restart_policy: RestartPolicy::RestartIfAllowed,
            note: "block on timer wait".to_string(),
        },
    ));
    assert_eq!(blocked.status, CommandStatus::Applied);
    assert_eq!(graph.activation_waits().len(), 1);
    assert_eq!(graph.wait_records().len(), 1);
    assert_eq!(graph.pending_wait_count(), 1);
    assert_eq!(graph.wait_records()[0].owner_task_generation, Some(2));
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Pending);
    assert_eq!(graph.runtime_activations()[0].generation, 6);
    assert_eq!(graph.runtime_activations()[0].owner_task_generation, 2);
    assert_eq!(graph.tasks()[0].state, TaskState::Pending);
    assert_eq!(graph.tasks()[0].pending_wait, Some(17));
    assert!(graph.check_invariants().is_ok());

    let cancelled = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p7-test",
        SemanticCommand::CancelActivationWait {
            activation_wait: 16,
            activation_wait_generation: 1,
            wait_generation: 1,
            errno: 110,
            reason: WaitCancelReason::Timeout,
            note: "timer timeout".to_string(),
        },
    ));
    assert_eq!(cancelled.status, CommandStatus::Applied);
    assert_eq!(graph.pending_wait_count(), 0);
    assert_eq!(graph.wait_records()[0].state, WaitState::Cancelled);
    assert_eq!(graph.wait_records()[0].cancel_reason, Some(WaitCancelReason::Timeout));
    assert_eq!(graph.activation_waits()[0].state, ActivationWaitState::Cancelled);
    assert_eq!(graph.activation_waits()[0].activation_generation_after_cancel, Some(7));
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Blocked);
    assert_eq!(graph.runtime_activations()[0].generation, 7);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "RuntimeActivationWaitCancelled activation_wait=16 activation=11@6->7 wait=17@1 reason=timeout generation=1"
    );
}

#[test]
pub(super) fn preemptive_runtime_p7_rejects_preempt_or_resume_of_waiting_activation() {
    let mut graph = p7_resumed_activation();
    assert!(graph.block_activation_on_wait_with_id(
        16,
        11,
        5,
        17,
        SemanticWaitKind::Timer,
        {
            let mut blockers = Vec::new();
            blockers.push(ContractObjectRef::new(ContractObjectKind::TimerInterrupt, 5, 1));
            blockers
        },
        Some(200),
        RestartPolicy::RestartIfAllowed,
        "block"
    ));
    assert!(graph.record_timer_interrupt_with_id(18, 2, 1, 2, Some(11), Some(6), "timer"));

    let rejected_preempt = graph.apply_envelope(CommandEnvelope::new(
        3,
        "p7-test",
        SemanticCommand::PreemptActivation {
            preemption: 19,
            activation: 11,
            activation_generation: 6,
            timer_interrupt: 18,
            timer_interrupt_generation: 1,
            queue: 1,
            note: "preempt pending activation".to_string(),
        },
    ));
    assert_eq!(rejected_preempt.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption target activation generation is not running".to_string());
    assert_eq!(rejected_preempt.violations, expected);

    let rejected_enqueue = graph.apply_envelope(CommandEnvelope::new(
        4,
        "p7-test",
        SemanticCommand::EnqueueRunnable { queue: 1, activation: 11, activation_generation: 6 },
    ));
    assert_eq!(rejected_enqueue.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation is not enqueueable".to_string());
    assert_eq!(rejected_enqueue.violations, expected);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn preemptive_runtime_p7_invariants_reject_waiting_activation_runnable_leak() {
    let mut graph = p7_resumed_activation();
    assert!(graph.block_activation_on_wait_with_id(
        16,
        11,
        5,
        17,
        SemanticWaitKind::Timer,
        {
            let mut blockers = Vec::new();
            blockers.push(ContractObjectRef::new(ContractObjectKind::TimerInterrupt, 5, 1));
            blockers
        },
        Some(200),
        RestartPolicy::RestartIfAllowed,
        "block"
    ));
    graph.corrupt_runtime_activation_state_for_test(11, RuntimeActivationState::Runnable);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PendingTaskHasRunnableActivation { task: 7, activation: 11 })
    );
}

pub(super) fn p8_pending_store_activation() -> (SemanticGraph, StoreId, Generation) {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "driver-thread-7");
    let store = graph.register_store("driver.p8", "driver.fake-aot", "driver", "restartable");
    graph.set_store_state(store, StoreState::Running);
    let store_generation = graph.store_handle(store).unwrap().generation;
    assert!(graph.create_runnable_queue_with_id(1, "driver-rq"));
    assert!(graph.create_runtime_activation_with_id(
        11,
        7,
        1,
        Some(store),
        Some(store_generation),
        None
    ));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.block_activation_on_wait_with_id(
        16,
        11,
        3,
        17,
        SemanticWaitKind::DeviceIrq,
        {
            let mut blockers = Vec::new();
            blockers.push(ContractObjectRef::new(
                ContractObjectKind::Store,
                store,
                store_generation,
            ));
            blockers
        },
        None,
        RestartPolicy::InternalOnly,
        "driver waits for irq"
    ));
    (graph, store, store_generation)
}

#[test]
pub(super) fn preemptive_runtime_p8_cleanup_cancels_wait_and_kills_dead_store_activation() {
    let (mut graph, store, store_generation) = p8_pending_store_activation();

    let cleanup = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p8-test",
        SemanticCommand::CleanupActivationForStoreFault {
            cleanup: 20,
            store,
            store_generation,
            activation: 11,
            activation_generation: 4,
            wait: Some(17),
            wait_generation: Some(1),
            reason: "driver-store-fault".to_string(),
            note: "cleanup store-owned activation".to_string(),
        },
    ));
    assert_eq!(cleanup.status, CommandStatus::Applied);
    assert_eq!(graph.activation_cleanups().len(), 1);
    assert_eq!(graph.activation_cleanups()[0].state, ActivationCleanupState::Completed);
    assert_eq!(graph.activation_cleanups()[0].target_store_generation, store_generation);
    assert_eq!(graph.activation_cleanups()[0].activation_generation_after, 5);
    assert_eq!(graph.wait_records()[0].state, WaitState::Cancelled);
    assert_eq!(graph.wait_records()[0].cancel_reason, Some(WaitCancelReason::StoreFault));
    assert_eq!(graph.activation_waits()[0].state, ActivationWaitState::Cancelled);
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Dead);
    assert_eq!(graph.tasks()[0].state, TaskState::Faulted);
    assert_eq!(graph.tasks()[0].pending_wait, None);
    assert_eq!(graph.stores()[0].state, StoreState::Dead);
    assert!(
        graph
            .resources()
            .iter()
            .filter(|resource| resource.owner_store == Some(store))
            .all(|resource| !resource.live)
    );
    assert_eq!(
        graph.runtime_activations()[0].owner_store_generation,
        Some(graph.activation_cleanups()[0].result_store_generation)
    );
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "RuntimeActivationCleanupCompleted cleanup=20 store={store}@{store_generation}->{} activation=11@4->5 generation=1",
            graph.activation_cleanups()[0].result_store_generation
        )
    );
}

#[test]
pub(super) fn preemptive_runtime_p8_cleanup_rejects_stale_store_generation_and_no_resume_leak() {
    let (mut graph, store, store_generation) = p8_pending_store_activation();
    graph.set_store_state(store, StoreState::Suspended);
    graph.set_store_state(store, StoreState::Running);
    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p8-test",
        SemanticCommand::CleanupActivationForStoreFault {
            cleanup: 20,
            store,
            store_generation,
            activation: 11,
            activation_generation: 4,
            wait: Some(17),
            wait_generation: Some(1),
            reason: "stale cleanup".to_string(),
            note: "old store generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("cleanup target store generation is missing or dead".to_string());
    assert_eq!(stale.violations, expected);
    assert_ne!(graph.stores()[0].state, StoreState::Dead);

    let (mut graph, store, store_generation) = p8_pending_store_activation();
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        store_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    let enqueue = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p8-test",
        SemanticCommand::EnqueueRunnable { queue: 1, activation: 11, activation_generation: 5 },
    ));
    assert_eq!(enqueue.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation is not enqueueable".to_string());
    assert_eq!(enqueue.violations, expected);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn preemptive_runtime_p8_cleanup_history_survives_store_restart_generation() {
    let (mut graph, store, store_generation) = p8_pending_store_activation();
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        store_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    let cleanup_result_generation = graph.activation_cleanups()[0].result_store_generation;

    let rebind = graph.rebind_store_instance(store).expect("store rebind");
    assert!(rebind.generation > cleanup_result_generation);
    graph.set_store_state(store, StoreState::Running);

    assert!(graph.store_handle(store).unwrap().generation > cleanup_result_generation);
    assert_eq!(
        graph.runtime_activations()[0].owner_store_generation,
        Some(cleanup_result_generation)
    );
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Dead);
    assert_eq!(graph.check_invariants(), Ok(()));
}

#[test]
pub(super) fn preemptive_runtime_p8_invariants_reject_cleanup_generation_leak() {
    let (mut graph, store, store_generation) = p8_pending_store_activation();
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        store_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    graph.corrupt_activation_cleanup_after_generation_for_test(20, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationCleanupMissingActivation {
            cleanup: 20,
            activation: 11,
        })
    );
}

pub(super) fn s13_cleanup_quiescence_graph() -> (SemanticGraph, StoreId, Generation, Generation) {
    let (mut graph, store, target_generation) = p8_pending_store_activation();
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        target_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    let result_generation = graph.activation_cleanups()[0].result_store_generation;
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "s13 hart0"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "s13 hart1"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "cleanup-quiescence-boundary",
        "post-cleanup safe point"
    ));
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        1,
        71,
        1,
        true,
        "cleanup-quiescence-rendezvous",
        "all harts parked after cleanup",
    ));
    (graph, store, target_generation, result_generation)
}

#[test]
pub(super) fn smp_runtime_s13_cleanup_quiescence_validates_after_cleanup_rendezvous() {
    let (mut graph, store, target_generation, result_generation) = s13_cleanup_quiescence_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s13-test",
        SemanticCommand::ValidateSmpCleanupQuiescence {
            quiescence: 91,
            cleanup: 20,
            cleanup_generation: 1,
            rendezvous: 81,
            rendezvous_generation: 1,
            store,
            target_store_generation: target_generation,
            result_store_generation: result_generation,
            reason: "smp-cleanup-quiescence".to_string(),
            note: "dead store quiesced across harts".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_cleanup_quiescence().len(), 1);
    let quiescence = &graph.smp_cleanup_quiescence()[0];
    assert_eq!(quiescence.cleanup, 20);
    assert_eq!(quiescence.cleanup_generation, 1);
    assert_eq!(quiescence.store, store);
    assert_eq!(quiescence.target_store_generation, target_generation);
    assert_eq!(quiescence.result_store_generation, result_generation);
    assert_eq!(quiescence.rendezvous, 81);
    assert_eq!(quiescence.rendezvous_generation, 1);
    assert_eq!(quiescence.participants.len(), 2);
    assert!(quiescence.no_running_activation);
    assert!(quiescence.no_pending_wait);
    assert!(quiescence.no_live_capability);
    assert!(quiescence.no_live_resource);
    assert!(quiescence.participants.iter().all(|participant| participant.quiesced
        && participant.current_activation.is_none()
        && participant.current_store.is_none()));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == quiescence.validated_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "SmpCleanupQuiescenceHartObserved"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "SmpCleanupQuiescenceValidated quiescence=91 cleanup=20@1 store={store}@{target_generation}->{result_generation} rendezvous=81@1 participants=2 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s13_rejects_stale_or_premature_cleanup_quiescence() {
    let (mut stale_cleanup, store, target_generation, result_generation) =
        s13_cleanup_quiescence_graph();
    let stale = stale_cleanup.apply_envelope(CommandEnvelope::new(
        1,
        "s13-test",
        SemanticCommand::ValidateSmpCleanupQuiescence {
            quiescence: 91,
            cleanup: 20,
            cleanup_generation: 2,
            rendezvous: 81,
            rendezvous_generation: 1,
            store,
            target_store_generation: target_generation,
            result_store_generation: result_generation,
            reason: "stale-cleanup-generation".to_string(),
            note: "reject stale cleanup generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp cleanup quiescence cleanup is missing".to_string());
    assert_eq!(stale.violations, expected);

    let (mut premature, store, target_generation) = p8_pending_store_activation();
    assert!(premature.register_hart_with_id(1, 0, "boot-hart0", true, "s13 hart0"));
    assert!(premature.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(premature.register_hart_with_id(2, 1, "hart1", false, "s13 hart1"));
    assert!(premature.set_hart_state(2, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(premature.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "premature-quiescence-boundary",
        "safe point before cleanup"
    ));
    assert!(premature.complete_stop_the_world_rendezvous_with_id(
        81,
        1,
        71,
        1,
        true,
        "premature-quiescence-rendezvous",
        "rendezvous before cleanup",
    ));
    assert!(premature.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        target_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    let result_generation = premature.activation_cleanups()[0].result_store_generation;
    let premature_result = premature.apply_envelope(CommandEnvelope::new(
        2,
        "s13-test",
        SemanticCommand::ValidateSmpCleanupQuiescence {
            quiescence: 91,
            cleanup: 20,
            cleanup_generation: 1,
            rendezvous: 81,
            rendezvous_generation: 1,
            store,
            target_store_generation: target_generation,
            result_store_generation: result_generation,
            reason: "premature-rendezvous".to_string(),
            note: "rendezvous must follow cleanup".to_string(),
        },
    ));
    assert_eq!(premature_result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp cleanup quiescence rendezvous must follow cleanup".to_string());
    assert_eq!(premature_result.violations, expected);
}

#[test]
pub(super) fn smp_runtime_s13_rejects_live_store_generation_leak() {
    let (mut graph, store, target_generation) = p8_pending_store_activation();
    graph.ensure_task(8, FrontendKind::LinuxElf, "leaked-driver-thread");
    assert!(graph.create_runtime_activation_with_id(
        21,
        8,
        1,
        Some(store),
        Some(target_generation),
        None
    ));
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        target_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    let result_generation = graph.activation_cleanups()[0].result_store_generation;
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "s13 hart0"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "s13 hart1"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "cleanup-quiescence-boundary",
        "post-cleanup safe point"
    ));
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        1,
        71,
        1,
        true,
        "cleanup-quiescence-rendezvous",
        "all harts parked after cleanup",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s13-test",
        SemanticCommand::ValidateSmpCleanupQuiescence {
            quiescence: 91,
            cleanup: 20,
            cleanup_generation: 1,
            rendezvous: 81,
            rendezvous_generation: 1,
            store,
            target_store_generation: target_generation,
            result_store_generation: result_generation,
            reason: "live-activation-leak".to_string(),
            note: "reject live activation owned by cleanup store generation".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp cleanup quiescence found live activation for dead store".to_string());
    assert_eq!(result.violations, expected);
}

#[test]
pub(super) fn smp_runtime_s13_rejects_generationless_live_capability_leak() {
    let (mut graph, store, target_generation, result_generation) = s13_cleanup_quiescence_graph();
    let cap = graph.grant_capability("driver.p8", "packet-device.net0", &["tx"], "store");
    assert!(graph.corrupt_capability_owner_store_generation_for_test(cap, None));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s13-test",
        SemanticCommand::ValidateSmpCleanupQuiescence {
            quiescence: 91,
            cleanup: 20,
            cleanup_generation: 1,
            rendezvous: 81,
            rendezvous_generation: 1,
            store,
            target_store_generation: target_generation,
            result_store_generation: result_generation,
            reason: "generationless-capability-leak".to_string(),
            note: "reject live capability missing owner store generation".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp cleanup quiescence found live capability for dead store".to_string());
    assert_eq!(result.violations, expected);
}

#[test]
pub(super) fn smp_runtime_s13_history_survives_store_rebind_and_hart_transition() {
    let (mut graph, store, target_generation, result_generation) = s13_cleanup_quiescence_graph();
    assert!(graph.validate_smp_cleanup_quiescence_with_id(
        91,
        20,
        1,
        81,
        1,
        store,
        target_generation,
        result_generation,
        "smp-cleanup-quiescence",
        "dead store quiesced across harts",
    ));

    let rebind = graph.rebind_store_instance(store).expect("store rebind");
    assert!(rebind.generation > result_generation);
    graph.set_store_state(store, StoreState::Running);
    assert!(graph.set_hart_state(
        1,
        2,
        HartState::Booting,
        "advance after cleanup quiescence",
        "later"
    ));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_smp_cleanup_quiescence_event_for_test(91, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpCleanupQuiescenceMissingEvent { quiescence: 91 })
    );
}

pub(super) fn s14_snapshot_barrier_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "s14 hart0"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "s14 hart1"));
    assert!(graph.set_hart_state(2, 1, HartState::Parked, "scheduler-ready", "parked"));
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "snapshot-barrier-boundary",
        "snapshot safe point"
    ));
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        3,
        71,
        1,
        true,
        "snapshot-barrier-rendezvous",
        "all harts stopped for snapshot",
    ));
    graph
}

#[test]
pub(super) fn smp_runtime_s14_snapshot_barrier_validates_clean_rendezvous() {
    let mut graph = s14_snapshot_barrier_graph();
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s14-test",
        SemanticCommand::ValidateSmpSnapshotBarrier {
            barrier: 101,
            rendezvous: 81,
            rendezvous_generation: 1,
            snapshot_state: SnapshotBarrierValidationState::default(),
            reason: "smp-snapshot-barrier".to_string(),
            note: "snapshot barrier over stopped harts".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_snapshot_barriers().len(), 1);
    let barrier = &graph.smp_snapshot_barriers()[0];
    assert_eq!(barrier.id, 101);
    assert_eq!(barrier.rendezvous, 81);
    assert_eq!(barrier.rendezvous_generation, 1);
    assert_eq!(barrier.rendezvous_epoch, 3);
    assert_eq!(barrier.event_log_cursor, cursor_before);
    assert_eq!(barrier.participants.len(), 2);
    assert!(barrier.snapshot_validation_ok);
    assert!(barrier.participants.iter().all(|participant| {
        participant.snapshot_safe && participant.event_log_cursor_observed == cursor_before
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == barrier.validated_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "SmpSnapshotBarrierHartFrozen"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "SmpSnapshotBarrierValidated barrier=101 rendezvous=81@1 cursor={cursor_before} participants=2 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s14_rejects_dirty_boundary_or_pending_wait() {
    let mut dirty = s14_snapshot_barrier_graph();
    let rejected = dirty.apply_envelope(CommandEnvelope::new(
        1,
        "s14-test",
        SemanticCommand::ValidateSmpSnapshotBarrier {
            barrier: 101,
            rendezvous: 81,
            rendezvous_generation: 1,
            snapshot_state: SnapshotBarrierValidationState {
                active_dmw_lease_count: 1,
                ..SnapshotBarrierValidationState::default()
            },
            reason: "dirty-boundary".to_string(),
            note: "reject active dmw lease".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp snapshot barrier boundary state is not quiescent".to_string());
    assert_eq!(rejected.violations, expected);

    let (mut pending, _, _) = p8_pending_store_activation();
    assert!(pending.register_hart_with_id(1, 0, "boot-hart0", true, "s14 hart0"));
    assert!(pending.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(pending.register_hart_with_id(2, 1, "hart1", false, "s14 hart1"));
    assert!(pending.set_hart_state(2, 1, HartState::Parked, "scheduler-ready", "parked"));
    assert!(pending.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "snapshot-barrier-boundary",
        "snapshot safe point"
    ));
    assert!(pending.complete_stop_the_world_rendezvous_with_id(
        81,
        3,
        71,
        1,
        true,
        "snapshot-barrier-rendezvous",
        "all harts stopped for snapshot",
    ));
    let wait_rejected = pending.apply_envelope(CommandEnvelope::new(
        2,
        "s14-test",
        SemanticCommand::ValidateSmpSnapshotBarrier {
            barrier: 101,
            rendezvous: 81,
            rendezvous_generation: 1,
            snapshot_state: SnapshotBarrierValidationState::default(),
            reason: "pending-wait".to_string(),
            note: "reject pending wait".to_string(),
        },
    ));
    assert_eq!(wait_rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp snapshot barrier found pending wait".to_string());
    assert_eq!(wait_rejected.violations, expected);
}

#[test]
pub(super) fn smp_runtime_s14_rejects_stale_rendezvous_generation() {
    let mut graph = s14_snapshot_barrier_graph();
    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s14-test",
        SemanticCommand::ValidateSmpSnapshotBarrier {
            barrier: 101,
            rendezvous: 81,
            rendezvous_generation: 2,
            snapshot_state: SnapshotBarrierValidationState::default(),
            reason: "stale-rendezvous".to_string(),
            note: "reject stale rendezvous generation".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp snapshot barrier rendezvous is missing".to_string());
    assert_eq!(rejected.violations, expected);
}

#[test]
pub(super) fn smp_runtime_s14_history_survives_hart_transition() {
    let mut graph = s14_snapshot_barrier_graph();
    assert!(graph.validate_smp_snapshot_barrier_with_id(
        101,
        81,
        1,
        SnapshotBarrierValidationState::default(),
        "smp-snapshot-barrier",
        "snapshot barrier over stopped harts",
    ));
    let cursor = graph.smp_snapshot_barriers()[0].event_log_cursor;

    assert!(graph.set_hart_state(
        1,
        2,
        HartState::Booting,
        "advance after snapshot barrier",
        "later"
    ));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_smp_snapshot_barrier_event_for_test(101, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpSnapshotBarrierMissingEvent { barrier: 101 })
    );
    assert_eq!(cursor, graph.smp_snapshot_barriers()[0].event_log_cursor);
}

pub(super) fn s15_stress_graph(include_snapshot: bool) -> SemanticGraph {
    let mut graph = s12_smp_code_publish_barrier_graph();
    assert!(graph.validate_smp_code_publish_barrier_with_id(
        91,
        81,
        1,
        0,
        1,
        true,
        false,
        "semantic-code-publish-barrier",
        "validate remote icache sync evidence only",
    ));
    assert!(graph.record_ipi_event_with_id(
        171,
        1,
        2,
        2,
        4,
        IpiEventKind::SchedulerKick,
        "s15-remote-park",
        "park hart1 before stress barrier",
    ));
    assert!(graph.remote_park_hart_with_id(
        171,
        171,
        1,
        1,
        2,
        2,
        4,
        "s15-remote-maintenance",
        "remote park for stress property run",
    ));

    graph.ensure_task(70, FrontendKind::LinuxElf, "s15-driver-thread");
    let store = graph.register_store("driver.s15", "driver.fake-aot", "driver", "restartable");
    graph.set_store_state(store, StoreState::Running);
    let store_generation = graph.store_handle(store).unwrap().generation;
    assert!(graph.create_runnable_queue_with_id(70, "s15-cleanup-rq"));
    assert!(graph.bind_runnable_queue_owner(70, 1, 1, 2, "hart0 owns cleanup queue"));
    assert!(graph.create_runtime_activation_with_id(
        70,
        70,
        1,
        Some(store),
        Some(store_generation),
        None
    ));
    assert!(graph.enqueue_runnable_activation(70, 70, 1));
    assert!(graph.dequeue_runnable_activation(70, 70));
    assert!(graph.block_activation_on_wait_with_id(
        170,
        70,
        3,
        171,
        SemanticWaitKind::DeviceIrq,
        {
            let mut blockers = Vec::new();
            blockers.push(ContractObjectRef::new(
                ContractObjectKind::Store,
                store,
                store_generation,
            ));
            blockers
        },
        None,
        RestartPolicy::InternalOnly,
        "s15 driver waits for irq",
    ));
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        170,
        store,
        store_generation,
        70,
        4,
        Some(171),
        Some(1),
        "s15-driver-store-fault",
        "cleanup stress driver",
    ));
    let result_generation = graph.activation_cleanups()[0].result_store_generation;
    assert!(graph.record_smp_safe_point_with_id(
        171,
        1,
        2,
        vec![(1, 2), (2, 5)],
        "s15-cleanup-quiescence-boundary",
        "stress cleanup safe point",
    ));
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        171,
        2,
        171,
        1,
        true,
        "s15-cleanup-rendezvous",
        "stress cleanup rendezvous",
    ));
    assert!(graph.validate_smp_cleanup_quiescence_with_id(
        171,
        170,
        1,
        171,
        1,
        store,
        store_generation,
        result_generation,
        "s15-cleanup-quiescence",
        "stress cleanup quiescence evidence",
    ));
    if include_snapshot {
        assert!(graph.record_smp_safe_point_with_id(
            181,
            1,
            2,
            vec![(1, 2), (2, 5)],
            "s15-snapshot-boundary",
            "stress snapshot safe point",
        ));
        assert!(graph.complete_stop_the_world_rendezvous_with_id(
            181,
            3,
            181,
            1,
            true,
            "s15-snapshot-rendezvous",
            "stress snapshot rendezvous",
        ));
        assert!(graph.validate_smp_snapshot_barrier_with_id(
            181,
            181,
            1,
            SnapshotBarrierValidationState::default(),
            "s15-smp-snapshot-barrier",
            "stress snapshot barrier",
        ));
    }
    graph
}

#[test]
pub(super) fn smp_runtime_s15_stress_run_records_property_evidence() {
    let mut graph = s15_stress_graph(true);
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s15-test",
        SemanticCommand::RecordSmpStressRun {
            run: 191,
            scenario: "s15-smp-stress-property".to_string(),
            iterations: 3,
            invariant_checks: 6,
            reason: "smp-stress-property-tests".to_string(),
            note: "stress code publish cleanup snapshot properties".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_stress_runs().len(), 1);
    let run = &graph.smp_stress_runs()[0];
    assert_eq!(run.id, 191);
    assert_eq!(run.iterations, 3);
    assert_eq!(run.hart_count, 2);
    assert_eq!(run.event_log_cursor, cursor_before);
    assert_eq!(run.observed_safe_point_count, 3);
    assert_eq!(run.observed_rendezvous_count, 3);
    assert_eq!(run.observed_code_publish_barrier_count, 1);
    assert_eq!(run.observed_cleanup_quiescence_count, 1);
    assert_eq!(run.observed_snapshot_barrier_count, 1);
    assert_eq!(run.observed_activation_migration_count, 1);
    assert_eq!(run.observed_remote_preempt_count, 1);
    assert_eq!(run.observed_remote_park_count, 1);
    assert_eq!(run.property_failures, 0);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SmpStressRunRecorded run=191 scenario=s15-smp-stress-property iterations=3 harts=2 safe_points=3 rendezvous=3 property_failures=0 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s15_rejects_incomplete_or_dirty_property_run() {
    let mut missing_snapshot = s15_stress_graph(false);
    let rejected = missing_snapshot.apply_envelope(CommandEnvelope::new(
        1,
        "s15-test",
        SemanticCommand::RecordSmpStressRun {
            run: 191,
            scenario: "s15-smp-stress-property".to_string(),
            iterations: 3,
            invariant_checks: 3,
            reason: "missing-snapshot".to_string(),
            note: "must reject incomplete coverage".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp stress run safe point coverage is incomplete".to_string());
    assert_eq!(rejected.violations, expected);

    let mut graph = s15_stress_graph(true);
    assert!(graph.record_smp_stress_run_with_id(
        191,
        "s15-smp-stress-property",
        3,
        6,
        "smp-stress-property-tests",
        "stress run",
    ));
    graph.corrupt_smp_stress_run_failures_for_test(191, 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpStressRunInvalid { run: 191 })
    );

    let mut graph = s15_stress_graph(true);
    assert!(graph.record_smp_stress_run_with_id(
        191,
        "s15-smp-stress-property",
        3,
        6,
        "smp-stress-property-tests",
        "stress run",
    ));
    graph.corrupt_smp_stress_run_snapshot_count_for_test(191, 0);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpStressRunInvalid { run: 191 })
    );
}

#[test]
pub(super) fn smp_runtime_s16_scaling_benchmark_records_semantic_metrics() {
    let mut graph = s15_stress_graph(true);
    assert!(graph.record_smp_stress_run_with_id(
        191,
        "s15-smp-stress-property",
        3,
        6,
        "smp-stress-property-tests",
        "stress run",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s16-test",
        SemanticCommand::RecordSmpScalingBenchmark {
            benchmark: 201,
            scenario: "s16-smp-scaling-benchmark".to_string(),
            stress_run: 191,
            stress_run_generation: 1,
            workload_units: 6,
            baseline_single_hart_nanos: 120_000,
            measured_smp_nanos: 72_000,
            budget_nanos: 90_000,
            note: "semantic harness scaling benchmark".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_scaling_benchmarks().len(), 1);
    let benchmark = &graph.smp_scaling_benchmarks()[0];
    assert_eq!(benchmark.id, 201);
    assert_eq!(benchmark.stress_run, 191);
    assert_eq!(benchmark.stress_run_generation, 1);
    assert_eq!(benchmark.hart_count, 2);
    assert_eq!(benchmark.workload_units, 6);
    assert_eq!(benchmark.baseline_single_hart_nanos, 120_000);
    assert_eq!(benchmark.measured_smp_nanos, 72_000);
    assert_eq!(benchmark.budget_nanos, 90_000);
    assert_eq!(benchmark.speedup_milli, 1_666);
    assert_eq!(benchmark.efficiency_milli, 833);
    assert_eq!(benchmark.event_log_cursor, cursor_before);
    assert_eq!(benchmark.stress_safe_point_count, 3);
    assert_eq!(benchmark.stress_rendezvous_count, 3);
    assert_eq!(benchmark.stress_property_failures, 0);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SmpScalingBenchmarkRecorded benchmark=201 stress_run=191@1 harts=2 workload_units=6 measured_nanos=72000 budget_nanos=90000 speedup_milli=1666 efficiency_milli=833 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s16_rejects_unbacked_or_invalid_scaling_benchmark() {
    let mut graph = s15_stress_graph(true);
    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s16-test",
        SemanticCommand::RecordSmpScalingBenchmark {
            benchmark: 201,
            scenario: "s16-smp-scaling-benchmark".to_string(),
            stress_run: 191,
            stress_run_generation: 1,
            workload_units: 6,
            baseline_single_hart_nanos: 120_000,
            measured_smp_nanos: 72_000,
            budget_nanos: 90_000,
            note: "missing stress must reject".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["smp scaling benchmark missing stress run evidence".to_string()]
    );

    assert!(graph.record_smp_stress_run_with_id(
        191,
        "s15-smp-stress-property",
        3,
        6,
        "smp-stress-property-tests",
        "stress run",
    ));
    let budget_rejected = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s16-test",
        SemanticCommand::RecordSmpScalingBenchmark {
            benchmark: 202,
            scenario: "s16-smp-scaling-benchmark".to_string(),
            stress_run: 191,
            stress_run_generation: 1,
            workload_units: 6,
            baseline_single_hart_nanos: 120_000,
            measured_smp_nanos: 100_000,
            budget_nanos: 90_000,
            note: "budget overrun must reject".to_string(),
        },
    ));
    assert_eq!(budget_rejected.status, CommandStatus::Rejected);
    assert_eq!(
        budget_rejected.violations,
        vec!["smp scaling benchmark exceeds budget".to_string()]
    );

    assert!(graph.record_smp_scaling_benchmark_with_id(
        201,
        "s16-smp-scaling-benchmark",
        191,
        1,
        6,
        120_000,
        72_000,
        90_000,
        "semantic harness scaling benchmark",
    ));
    graph.corrupt_smp_scaling_benchmark_speedup_for_test(201, 1_999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpScalingBenchmarkInvalid { benchmark: 201 })
    );
}

pub(super) fn x0_integrated_smp_preemption_cleanup_graph() -> SemanticGraph {
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
pub(super) fn integrated_runtime_x0_records_smp_preemption_cleanup_closure() {
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
pub(super) fn integrated_runtime_x0_rejects_stale_or_incomplete_evidence() {
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
pub(super) fn integrated_runtime_x0_contract_graph_rejects_generation_drift() {
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

pub(super) fn x1_integrated_smp_network_fault_snapshot() -> ContractGraphSnapshot {
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
pub(super) fn integrated_runtime_x1_contract_graph_accepts_network_fault_under_smp() {
    let violations = validate_contract_graph(&x1_integrated_smp_network_fault_snapshot());
    assert_eq!(violations, Vec::new());
}

#[test]
pub(super) fn integrated_runtime_x1_rejects_stale_or_incomplete_evidence() {
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
pub(super) fn integrated_runtime_x1_contract_graph_rejects_generation_drift() {
    let mut snapshot = x1_integrated_smp_network_fault_snapshot();
    snapshot.integrated_smp_network_faults[0].remote_preempt_generation = 99;
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-smp-network-fault->remote-preempt"
            && violation.kind == ContractViolationKind::GenerationMismatch
    }));
}

pub(super) fn x2_integrated_disk_preempt_fault_graph() -> SemanticGraph {
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
pub(super) fn integrated_runtime_x2_records_disk_pending_io_fault_under_preemption() {
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
pub(super) fn integrated_runtime_x2_rejects_missing_or_non_fault_evidence() {
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
pub(super) fn integrated_runtime_x2_contract_graph_rejects_generation_drift() {
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

pub(super) fn x3_integrated_simd_migration_graph() -> SemanticGraph {
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
pub(super) fn integrated_runtime_x3_records_simd_task_migration_across_harts() {
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
pub(super) fn integrated_runtime_x3_rejects_missing_or_dirty_vector_migration() {
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
pub(super) fn integrated_runtime_x3_contract_graph_rejects_vector_generation_drift() {
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
pub(super) fn integrated_runtime_x3_contract_graph_rejects_context_binding_drift() {
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

pub(super) fn add_x4_block_benchmark_evidence(graph: &mut SemanticGraph) {
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

pub(super) fn x4_network_disk_concurrent_io_graph() -> SemanticGraph {
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
pub(super) fn integrated_runtime_x4_records_network_disk_concurrent_io() {
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
pub(super) fn integrated_runtime_x4_rejects_missing_or_stale_benchmark_refs() {
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
pub(super) fn integrated_runtime_x4_contract_graph_rejects_block_dma_generation_drift() {
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

pub(super) fn x5_display_scheduler_load_graph() -> SemanticGraph {
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
pub(super) fn integrated_runtime_x5_records_display_scheduler_load() {
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
pub(super) fn integrated_runtime_x5_rejects_missing_or_stale_evidence_refs() {
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
pub(super) fn integrated_runtime_x5_contract_graph_rejects_scheduler_generation_drift() {
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

pub(super) fn add_i10_io_cleanup_setup_to_graph(
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

pub(super) fn add_s14_snapshot_barrier_to_graph(graph: &mut SemanticGraph) {
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

pub(super) fn x6_snapshot_io_lease_barrier_graph() -> SemanticGraph {
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
pub(super) fn integrated_runtime_x6_records_snapshot_io_lease_barrier() {
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
pub(super) fn integrated_runtime_x6_rejects_missing_or_stale_barrier_refs() {
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
pub(super) fn integrated_runtime_x6_contract_graph_rejects_cleanup_count_drift() {
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

pub(super) fn x7_code_publish_smp_workload_graph() -> SemanticGraph {
    let mut graph = s15_stress_graph(true);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "x7-test",
        SemanticCommand::RecordSmpStressRun {
            run: 191,
            scenario: "s15-smp-stress-property".to_string(),
            iterations: 3,
            invariant_checks: 6,
            reason: "smp-stress-property-tests".to_string(),
            note: "stress code publish cleanup snapshot properties".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    graph
}

#[test]
pub(super) fn integrated_runtime_x7_records_code_publish_smp_workload() {
    let mut graph = x7_code_publish_smp_workload_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        22,
        "x7-test",
        SemanticCommand::RecordIntegratedCodePublishSmpWorkload {
            integrated: 902,
            scenario: "x7-code-publish-while-smp-workload-active".to_string(),
            smp_stress_run: 191,
            smp_stress_run_generation: 1,
            smp_code_publish_barrier: 91,
            smp_code_publish_barrier_generation: 1,
            invariant_checks: 7,
            note: "integrate code publish barrier with SMP workload evidence".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.integrated_code_publish_smp_workload_count(), 1);
    let record = &graph.integrated_code_publish_smp_workloads()[0];
    assert_eq!(record.id, 902);
    assert_eq!(record.smp_stress_run, 191);
    assert_eq!(record.smp_code_publish_barrier, 91);
    assert_eq!(record.publish_rendezvous, 81);
    assert_eq!(record.publish_safe_point, 71);
    assert_eq!(record.hart_count, 2);
    assert_eq!(record.workload_iterations, 3);
    assert_eq!(record.observed_code_publish_barrier_count, 1);
    assert_eq!(record.code_publish_epoch_before, 0);
    assert_eq!(record.code_publish_epoch_after, 1);
    assert!(record.remote_icache_sync_required);
    assert!(!record.code_publish_executed);
    assert_eq!(record.participant_count, 2);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IntegratedCodePublishSmpWorkloadRecorded integrated=902 scenario=x7-code-publish-while-smp-workload-active stress_run=191@1 code_publish_barrier=91@1 rendezvous=81@1 safe_point=71@1 code_publish_epoch=0->1 harts=2 iterations=3 invariant_checks=7 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn integrated_runtime_x7_rejects_missing_or_stale_publish_evidence() {
    let missing = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x7-test",
        SemanticCommand::RecordIntegratedCodePublishSmpWorkload {
            integrated: 902,
            scenario: "x7-code-publish-while-smp-workload-active".to_string(),
            smp_stress_run: 191,
            smp_stress_run_generation: 1,
            smp_code_publish_barrier: 91,
            smp_code_publish_barrier_generation: 1,
            invariant_checks: 7,
            note: "missing evidence rejects".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    assert_eq!(
        missing.violations,
        vec!["integrated code-publish/SMP workload missing stress evidence".to_string()]
    );

    let stale = x7_code_publish_smp_workload_graph().apply_envelope(CommandEnvelope::new(
        22,
        "x7-test",
        SemanticCommand::RecordIntegratedCodePublishSmpWorkload {
            integrated: 902,
            scenario: "x7-code-publish-while-smp-workload-active".to_string(),
            smp_stress_run: 191,
            smp_stress_run_generation: 1,
            smp_code_publish_barrier: 91,
            smp_code_publish_barrier_generation: 2,
            invariant_checks: 7,
            note: "stale publish barrier rejects".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["integrated code-publish/SMP workload missing code publish barrier".to_string()]
    );
}

#[test]
pub(super) fn integrated_runtime_x7_contract_graph_rejects_epoch_drift() {
    let mut graph = x7_code_publish_smp_workload_graph();
    assert!(graph.record_integrated_code_publish_smp_workload_with_id(
        902,
        "x7-code-publish-while-smp-workload-active",
        191,
        1,
        91,
        1,
        7,
        "integrated code publish smp workload",
    ));
    let mut integrated = graph.integrated_code_publish_smp_workloads().to_vec();
    integrated[0].code_publish_epoch_after = 2;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_code_publish_smp_workloads: integrated,
        smp_stress_runs: graph.smp_stress_runs().to_vec(),
        smp_code_publish_barriers: graph.smp_code_publish_barriers().to_vec(),
        stop_the_world_rendezvous: graph.stop_the_world_rendezvous().to_vec(),
        smp_safe_points: graph.smp_safe_points().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-code-publish-smp-workload->contract"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

pub(super) fn x8_integrated_display_panic_graph() -> SemanticGraph {
    let (mut graph, owner_store, owner_store_generation, payload_digest, summary_digest) =
        g11_display_panic_last_frame_graph();
    assert!(graph.record_display_panic_last_frame_with_id(
        25_001,
        owner_store,
        owner_store_generation,
        24_011,
        1,
        23_801,
        1,
        23_501,
        1,
        23_601,
        1,
        payload_digest,
        summary_digest,
        512,
        1,
        "contract-panic-summary-v1",
        false,
        "x8 panic last-frame evidence",
    ));
    graph.record_substrate_panic(
        "PanicRing",
        "extract-after-substrate-panic",
        Some("substrate.panic".to_string()),
        None,
        None,
        1,
        0,
        1,
    );
    graph
}

#[test]
pub(super) fn integrated_runtime_x8_records_panic_ring_extraction() {
    let mut graph = x8_integrated_display_panic_graph();
    let substrate_panic_event = graph.event_log_tail(1)[0].id;
    let result = graph.apply_envelope(CommandEnvelope::new(
        23,
        "x8-test",
        SemanticCommand::RecordIntegratedDisplayPanic {
            integrated: 903,
            scenario: "x8-panic-ring-extraction-after-substrate-panic".to_string(),
            substrate_panic_event,
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
            invariant_checks: 8,
            note: "integrate substrate panic ring extraction with display panic evidence"
                .to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.integrated_display_panic_count(), 1);
    let record = &graph.integrated_display_panics()[0];
    assert_eq!(record.id, 903);
    assert_eq!(record.substrate_panic_event, substrate_panic_event);
    assert_eq!(record.display_panic_last_frame, 25_001);
    assert_eq!(record.panic_ring_record_count, 3);
    assert_eq!(record.jsonl_frame_count, 5);
    assert_eq!(record.contract_panic_summary_records, 1);
    assert_eq!(record.corrupt_record_count, 0);
    assert!(!record.raw_framebuffer_bytes_exported);
    assert!(!record.panic_path_allocates);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "IntegratedDisplayPanicRecorded integrated=903 scenario=x8-panic-ring-extraction-after-substrate-panic substrate_panic_event={substrate_panic_event} display_panic_last_frame=25001@1 panic_ring_records=3 lost=0 jsonl_frames=5 contract_panic_summary_records=1 last_frame_summary_records=1 corrupt_records=0 truncated_records=0 invariant_checks=8 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn integrated_runtime_x8_rejects_missing_or_corrupt_panic_evidence() {
    let missing = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x8-test",
        SemanticCommand::RecordIntegratedDisplayPanic {
            integrated: 903,
            scenario: "x8-panic-ring-extraction-after-substrate-panic".to_string(),
            substrate_panic_event: 1,
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
            invariant_checks: 8,
            note: "missing display panic frame rejects".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    assert_eq!(
        missing.violations,
        vec!["integrated display panic missing last-frame evidence".to_string()]
    );

    let mut graph = x8_integrated_display_panic_graph();
    let substrate_panic_event = graph.event_log_tail(1)[0].id;
    let corrupt = graph.apply_envelope(CommandEnvelope::new(
        23,
        "x8-test",
        SemanticCommand::RecordIntegratedDisplayPanic {
            integrated: 903,
            scenario: "x8-panic-ring-extraction-after-substrate-panic".to_string(),
            substrate_panic_event,
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
            corrupt_record_count: 1,
            truncated_record_count: 0,
            invariant_checks: 8,
            note: "corrupt panic ring extraction rejects".to_string(),
        },
    ));
    assert_eq!(corrupt.status, CommandStatus::Rejected);
    assert_eq!(
        corrupt.violations,
        vec!["integrated display panic requires clean panic-ring extraction evidence".to_string()]
    );
}

#[test]
pub(super) fn integrated_runtime_x8_contract_graph_rejects_last_frame_drift() {
    let mut graph = x8_integrated_display_panic_graph();
    let substrate_panic_event = graph.event_log_tail(1)[0].id;
    assert!(graph.record_integrated_display_panic_with_id(
        903,
        "x8-panic-ring-extraction-after-substrate-panic",
        substrate_panic_event,
        25_001,
        1,
        65_536,
        4_096,
        1,
        3,
        3,
        0,
        5,
        1,
        1,
        0,
        0,
        8,
        "integrated display panic",
    ));
    let mut frames = graph.display_panic_last_frames().to_vec();
    frames[0].raw_framebuffer_bytes_exported = true;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        display_panic_last_frames: frames,
        integrated_display_panics: graph.integrated_display_panics().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "display-panic-last-frame->contract"
            || violation.edge == "integrated-display-panic->last-frame-binding"
    }));
}

#[test]
pub(super) fn integrated_runtime_x9_rejects_missing_or_incomplete_replay_evidence() {
    let missing_sources = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x9-test",
        SemanticCommand::RecordIntegratedOsctlTraceReplay {
            integrated: 904,
            scenario: "x9-full-osctl-trace-replay".to_string(),
            integrated_smp_preemption_cleanup: 301,
            integrated_smp_preemption_cleanup_generation: 1,
            integrated_smp_network_fault: 401,
            integrated_smp_network_fault_generation: 1,
            integrated_disk_preempt_fault: 501,
            integrated_disk_preempt_fault_generation: 1,
            integrated_simd_migration: 601,
            integrated_simd_migration_generation: 1,
            integrated_network_disk_io: 701,
            integrated_network_disk_io_generation: 1,
            integrated_display_scheduler_load: 801,
            integrated_display_scheduler_load_generation: 1,
            integrated_snapshot_io_lease_barrier: 901,
            integrated_snapshot_io_lease_barrier_generation: 1,
            integrated_code_publish_smp_workload: 902,
            integrated_code_publish_smp_workload_generation: 1,
            integrated_display_panic: 903,
            integrated_display_panic_generation: 1,
            replay_event_cursor: 1,
            stable_view_count: 9,
            historical_edge_count: 9,
            replayed_root_count: 9,
            integrated_scenario_count: 9,
            replay_fixture_count: 9,
            invariant_checks: 9,
            note: "missing integrated scenario evidence rejects".to_string(),
        },
    ));
    assert_eq!(missing_sources.status, CommandStatus::Rejected);
    assert_eq!(
        missing_sources.violations,
        vec!["integrated osctl trace replay missing integrated scenario evidence".to_string()]
    );

    let incomplete_evidence = SemanticGraph::new().apply_envelope(CommandEnvelope::new(
        1,
        "x9-test",
        SemanticCommand::RecordIntegratedOsctlTraceReplay {
            integrated: 904,
            scenario: "x9-full-osctl-trace-replay".to_string(),
            integrated_smp_preemption_cleanup: 301,
            integrated_smp_preemption_cleanup_generation: 1,
            integrated_smp_network_fault: 401,
            integrated_smp_network_fault_generation: 1,
            integrated_disk_preempt_fault: 501,
            integrated_disk_preempt_fault_generation: 1,
            integrated_simd_migration: 601,
            integrated_simd_migration_generation: 1,
            integrated_network_disk_io: 701,
            integrated_network_disk_io_generation: 1,
            integrated_display_scheduler_load: 801,
            integrated_display_scheduler_load_generation: 1,
            integrated_snapshot_io_lease_barrier: 901,
            integrated_snapshot_io_lease_barrier_generation: 1,
            integrated_code_publish_smp_workload: 902,
            integrated_code_publish_smp_workload_generation: 1,
            integrated_display_panic: 903,
            integrated_display_panic_generation: 1,
            replay_event_cursor: 1,
            stable_view_count: 8,
            historical_edge_count: 9,
            replayed_root_count: 9,
            integrated_scenario_count: 9,
            replay_fixture_count: 9,
            invariant_checks: 9,
            note: "incomplete stable view evidence rejects".to_string(),
        },
    ));
    assert_eq!(incomplete_evidence.status, CommandStatus::Rejected);
    assert_eq!(
        incomplete_evidence.violations,
        vec!["integrated osctl trace replay requires complete stable evidence".to_string()]
    );
}

#[test]
pub(super) fn integrated_runtime_x9_contract_graph_rejects_dangling_integrated_history() {
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        integrated_osctl_trace_replays: vec![IntegratedOsctlTraceReplayRecord {
            id: 904,
            scenario: "x9-full-osctl-trace-replay".to_string(),
            integrated_smp_preemption_cleanup: 301,
            integrated_smp_preemption_cleanup_generation: 1,
            integrated_smp_network_fault: 401,
            integrated_smp_network_fault_generation: 1,
            integrated_disk_preempt_fault: 501,
            integrated_disk_preempt_fault_generation: 1,
            integrated_simd_migration: 601,
            integrated_simd_migration_generation: 1,
            integrated_network_disk_io: 701,
            integrated_network_disk_io_generation: 1,
            integrated_display_scheduler_load: 801,
            integrated_display_scheduler_load_generation: 1,
            integrated_snapshot_io_lease_barrier: 901,
            integrated_snapshot_io_lease_barrier_generation: 1,
            integrated_code_publish_smp_workload: 902,
            integrated_code_publish_smp_workload_generation: 1,
            integrated_display_panic: 903,
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
            state: IntegratedOsctlTraceReplayState::Recorded,
            recorded_at_event: 580,
            note: "missing referenced integrated history rejects".to_string(),
        }],
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-osctl-trace-replay->x0-smp-preemption-cleanup"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
    assert!(violations.iter().any(|violation| {
        violation.edge == "integrated-osctl-trace-replay->x8-display-panic"
            && violation.kind == ContractViolationKind::DanglingEdge
    }));
}
