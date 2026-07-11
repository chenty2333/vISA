use super::*;

#[test]
pub(in crate::tests) fn preemptive_runtime_p7_wait_blocks_and_cancel_does_not_auto_resume() {
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
pub(in crate::tests) fn preemptive_runtime_p7_rejects_preempt_or_resume_of_waiting_activation() {
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
pub(in crate::tests) fn preemptive_runtime_p7_invariants_reject_waiting_activation_runnable_leak() {
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

pub(in crate::tests) fn p8_pending_store_activation() -> (SemanticGraph, StoreId, Generation) {
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
pub(in crate::tests) fn preemptive_runtime_p8_cleanup_cancels_wait_and_kills_dead_store_activation()
{
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
pub(in crate::tests) fn preemptive_runtime_p8_cleanup_rejects_stale_store_generation_and_no_resume_leak()
 {
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
pub(in crate::tests) fn preemptive_runtime_p8_cleanup_history_survives_store_restart_generation() {
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
pub(in crate::tests) fn preemptive_runtime_p8_invariants_reject_cleanup_generation_leak() {
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

pub(in crate::tests) fn s13_cleanup_quiescence_graph()
-> (SemanticGraph, StoreId, Generation, Generation) {
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
pub(in crate::tests) fn smp_runtime_s13_cleanup_quiescence_validates_after_cleanup_rendezvous() {
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
pub(in crate::tests) fn smp_runtime_s13_rejects_stale_or_premature_cleanup_quiescence() {
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
pub(in crate::tests) fn smp_runtime_s13_rejects_live_store_generation_leak() {
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
pub(in crate::tests) fn smp_runtime_s13_rejects_generationless_live_capability_leak() {
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
pub(in crate::tests) fn smp_runtime_s13_history_survives_store_rebind_and_hart_transition() {
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

pub(in crate::tests) fn s14_snapshot_barrier_graph() -> SemanticGraph {
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
pub(in crate::tests) fn smp_runtime_s14_snapshot_barrier_validates_clean_rendezvous() {
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
pub(in crate::tests) fn smp_runtime_s14_rejects_dirty_boundary_or_pending_wait() {
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
pub(in crate::tests) fn smp_runtime_s14_rejects_stale_rendezvous_generation() {
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
pub(in crate::tests) fn smp_runtime_s14_history_survives_hart_transition() {
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

pub(in crate::tests) fn s15_stress_graph(include_snapshot: bool) -> SemanticGraph {
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
pub(in crate::tests) fn smp_runtime_s15_stress_run_records_property_evidence() {
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
pub(in crate::tests) fn smp_runtime_s15_rejects_incomplete_or_dirty_property_run() {
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
pub(in crate::tests) fn smp_runtime_s16_scaling_benchmark_records_semantic_metrics() {
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
pub(in crate::tests) fn smp_runtime_s16_rejects_unbacked_or_invalid_scaling_benchmark() {
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
