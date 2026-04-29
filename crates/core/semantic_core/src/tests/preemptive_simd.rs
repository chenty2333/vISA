use super::*;

#[test]
pub(super) fn preemptive_runtime_p0_queue_commands_emit_events_and_pass_invariants() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");

    let queue = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p0-test",
        SemanticCommand::CreateRunnableQueue { queue: 1, label: "main-rq".to_string() },
    ));
    assert_eq!(queue.status, CommandStatus::Applied);

    let activation = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p0-test",
        SemanticCommand::CreateRuntimeActivation {
            activation: 11,
            owner_task: 7,
            owner_task_generation: 1,
            owner_store: None,
            owner_store_generation: None,
            code_object: Some(ContractObjectRef::new(ContractObjectKind::CodeObject, 3, 1)),
        },
    ));
    assert_eq!(activation.status, CommandStatus::Applied);
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Created);

    let enqueue = graph.apply_envelope(CommandEnvelope::new(
        3,
        "p0-test",
        SemanticCommand::EnqueueRunnable { queue: 1, activation: 11, activation_generation: 1 },
    ));
    assert_eq!(enqueue.status, CommandStatus::Applied);
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Runnable);
    assert_eq!(graph.runtime_activations()[0].generation, 2);
    assert_eq!(graph.runnable_queues()[0].entries[0].activation, 11);
    assert_eq!(graph.runnable_queues()[0].entries[0].activation_generation, 2);

    let dequeue = graph.apply_envelope(CommandEnvelope::new(
        4,
        "p0-test",
        SemanticCommand::DequeueRunnable { queue: 1, activation: 11 },
    ));
    assert_eq!(dequeue.status, CommandStatus::Applied);
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Running);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert_eq!(graph.check_invariants(), Ok(()));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "RuntimeActivationStateChanged activation=11 runnable->running generation=3"
    );
}

#[test]
pub(super) fn preemptive_runtime_p0_rejects_pending_task_and_stale_generation_enqueue() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p0-test",
        SemanticCommand::EnqueueRunnable { queue: 1, activation: 11, activation_generation: 99 },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation generation mismatch".to_string());
    assert_eq!(stale.violations, expected);
    assert!(graph.runnable_queues()[0].entries.is_empty());

    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    graph.record_wait_created_with_details(
        42,
        Some(7),
        None,
        None,
        SemanticWaitKind::Timer,
        1,
        Vec::new(),
        Some(10),
        RestartPolicy::RestartIfAllowed,
        None,
    );
    let task_generation = graph.tasks()[0].generation;
    assert!(graph.create_runtime_activation_with_id(11, 7, task_generation, None, None, None));
    let pending = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p0-test",
        SemanticCommand::EnqueueRunnable { queue: 1, activation: 11, activation_generation: 1 },
    ));
    assert_eq!(pending.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("pending wait task cannot be enqueued".to_string());
    assert_eq!(pending.violations, expected);
    assert!(graph.runnable_queues()[0].entries.is_empty());
}

#[test]
pub(super) fn preemptive_runtime_p0_rejects_duplicate_queue_and_generationless_store_owner() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    let store = graph.register_store("sched-store", "sched-artifact", "service", "restartable");
    assert!(!graph.create_runtime_activation_with_id(9, 7, 1, Some(store), None, None));

    let missing_generation = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p0-test",
        SemanticCommand::CreateRuntimeActivation {
            activation: 9,
            owner_task: 7,
            owner_task_generation: 1,
            owner_store: Some(store),
            owner_store_generation: None,
            code_object: None,
        },
    ));
    assert_eq!(missing_generation.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation owner store generation is required".to_string());
    assert_eq!(missing_generation.violations, expected);

    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runnable_queue_with_id(2, "backup-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p0-test",
        SemanticCommand::EnqueueRunnable { queue: 2, activation: 11, activation_generation: 2 },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation already queued".to_string());
    assert_eq!(duplicate.violations, expected);
    assert!(graph.runnable_queues()[1].entries.is_empty());
    assert_eq!(graph.check_invariants(), Ok(()));
}

#[test]
pub(super) fn preemptive_runtime_p0_invariants_reject_bad_queue_ownership() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    graph.clear_runtime_activation_queue_for_test(11);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RunnableQueueOwnershipMismatch { queue: 1, activation: 11 })
    );
}

#[test]
pub(super) fn preemptive_runtime_p1_context_commands_emit_events_and_pass_invariants() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));

    let context = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p1-test",
        SemanticCommand::CreateActivationContext {
            context: 12,
            activation: 11,
            activation_generation: 2,
        },
    ));
    assert_eq!(context.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].generation, 1);
    assert_eq!(graph.activation_contexts()[0].state, ActivationContextState::Created);

    let saved = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p1-test",
        SemanticCommand::CaptureSavedContext {
            saved_context: 13,
            context: 12,
            context_generation: 1,
            reason: SavedContextReason::Initial,
            pc: 0x1000,
            sp: 0x8000,
            flags: 0,
            note: "initial frame".to_string(),
        },
    ));
    assert_eq!(saved.status, CommandStatus::Applied, "{:?}", saved.violations);
    assert_eq!(graph.activation_contexts()[0].generation, 2);
    assert_eq!(graph.activation_contexts()[0].state, ActivationContextState::Saved);
    assert_eq!(graph.saved_contexts()[0].context_generation, 2);
    assert_eq!(graph.saved_contexts()[0].pc, 0x1000);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SavedContextCaptured saved_context=13 context=12@2 activation=11@2 reason=initial generation=1"
    );
}

#[test]
pub(super) fn preemptive_runtime_p1_rejects_stale_context_generation_and_empty_frame() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.create_activation_context_with_id(12, 11, 1));

    let empty_frame = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p1-test",
        SemanticCommand::CaptureSavedContext {
            saved_context: 13,
            context: 12,
            context_generation: 1,
            reason: SavedContextReason::Initial,
            pc: 0,
            sp: 0x8000,
            flags: 0,
            note: "bad frame".to_string(),
        },
    ));
    assert_eq!(empty_frame.status, CommandStatus::Rejected);
    assert!(graph.saved_contexts().is_empty());

    assert!(graph.capture_saved_context_with_id(
        13,
        12,
        1,
        SavedContextReason::Initial,
        0x1000,
        0x8000,
        0,
        "initial frame",
    ));
    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p1-test",
        SemanticCommand::CaptureSavedContext {
            saved_context: 14,
            context: 12,
            context_generation: 1,
            reason: SavedContextReason::CooperativeYield,
            pc: 0x1004,
            sp: 0x7ff0,
            flags: 0,
            note: "stale frame".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation context generation is missing or dropped".to_string());
    assert_eq!(stale.violations, expected);

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "p1-test",
        SemanticCommand::CaptureSavedContext {
            saved_context: 14,
            context: 12,
            context_generation: 2,
            reason: SavedContextReason::CooperativeYield,
            pc: 0x1004,
            sp: 0x7ff0,
            flags: 0,
            note: "duplicate frame".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation context already has saved context".to_string());
    assert_eq!(duplicate.violations, expected);
    assert_eq!(graph.saved_contexts().len(), 1);
}

#[test]
pub(super) fn preemptive_runtime_p1_invariants_reject_context_saved_generation_leak() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.create_activation_context_with_id(12, 11, 1));
    assert!(graph.capture_saved_context_with_id(
        13,
        12,
        1,
        SavedContextReason::Initial,
        0x1000,
        0x8000,
        0,
        "initial frame",
    ));
    graph.clear_activation_context_saved_ref_for_test(12);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationContextSavedGenerationMissing {
            context: 12,
            saved_context: 13,
        })
    );
}

pub(super) fn register_idle_test_hart(graph: &mut SemanticGraph) -> Generation {
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    2
}

#[test]
pub(super) fn preemptive_runtime_p2_timer_interrupt_records_event_and_passes_invariants() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));

    let timer = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p2-test",
        SemanticCommand::RecordTimerInterrupt {
            interrupt: 5,
            timer_epoch: 1,
            hart: 1,
            hart_generation,
            target_activation: Some(11),
            target_activation_generation: Some(3),
            note: "timer tick".to_string(),
        },
    ));
    assert_eq!(timer.status, CommandStatus::Applied);
    assert_eq!(graph.timer_interrupts()[0].timer_epoch, 1);
    assert_eq!(graph.timer_interrupts()[0].hart, 1);
    assert_eq!(graph.timer_interrupts()[0].hart_generation, 2);
    assert_eq!(graph.timer_interrupts()[0].hardware_hart, 0);
    assert_eq!(graph.hart_event_attributions().len(), 3);
    assert_eq!(graph.timer_epoch(), 1);
    assert_eq!(graph.timer_interrupts()[0].target_task, Some(7));
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "TimerInterruptRecorded interrupt=5 epoch=1 hart=1@2 hardware_id=0 target=11@3 generation=1"
    );
}

#[test]
pub(super) fn preemptive_runtime_p2_rejects_stale_target_and_non_monotonic_epoch() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p2-test",
        SemanticCommand::RecordTimerInterrupt {
            interrupt: 5,
            timer_epoch: 1,
            hart: 1,
            hart_generation,
            target_activation: Some(11),
            target_activation_generation: Some(99),
            note: "stale target".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert!(graph.timer_interrupts().is_empty());

    assert!(graph.record_timer_interrupt_with_id(
        5,
        1,
        1,
        hart_generation,
        Some(11),
        Some(1),
        "first tick"
    ));
    assert!(graph.record_timer_interrupt_with_id(
        6,
        3,
        1,
        hart_generation,
        Some(11),
        Some(1),
        "third tick"
    ));
    let non_monotonic = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p2-test",
        SemanticCommand::RecordTimerInterrupt {
            interrupt: 7,
            timer_epoch: 2,
            hart: 1,
            hart_generation,
            target_activation: Some(11),
            target_activation_generation: Some(1),
            note: "old epoch".to_string(),
        },
    ));
    assert_eq!(non_monotonic.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("timer interrupt epoch must be monotonic".to_string());
    assert_eq!(non_monotonic.violations, expected);
}

#[test]
pub(super) fn preemptive_runtime_p2_invariants_reject_timer_epoch_regression() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.record_timer_interrupt_with_id(
        5,
        1,
        1,
        hart_generation,
        Some(11),
        Some(1),
        "first tick"
    ));
    assert!(graph.record_timer_interrupt_with_id(
        6,
        2,
        1,
        hart_generation,
        Some(11),
        Some(1),
        "second tick"
    ));
    graph.corrupt_timer_interrupt_epoch_for_test(6, 1);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::TimerInterruptEpochNonMonotonic {
            interrupt: 6,
            timer_epoch: 1,
        })
    );
}

pub(super) fn p3_running_activation_with_timer() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
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
        "timer tick"
    ));
    graph
}

#[test]
pub(super) fn preemptive_runtime_p3_preempt_activation_requeues_running_activation() {
    let mut graph = p3_running_activation_with_timer();

    let preempt = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p3-test",
        SemanticCommand::PreemptActivation {
            preemption: 6,
            activation: 11,
            activation_generation: 3,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            queue: 1,
            note: "timer preempt".to_string(),
        },
    ));
    assert_eq!(preempt.status, CommandStatus::Applied);
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Runnable);
    assert_eq!(graph.runtime_activations()[0].generation, 4);
    assert_eq!(graph.runnable_queues()[0].entries[0].activation, 11);
    assert_eq!(graph.runnable_queues()[0].entries[0].activation_generation, 4);
    assert_eq!(graph.preemptions()[0].activation_generation_before, 3);
    assert_eq!(graph.preemptions()[0].activation_generation_after, 4);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(3)[0].kind.summary(),
        "RuntimeActivationPreempted preemption=6 activation=11@3->4 timer=5@1 queue=1@1 generation=1"
    );
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Running);
    assert_eq!(graph.runtime_activations()[0].generation, 5);
    assert!(
        graph.check_invariants().is_ok(),
        "preemption history must survive later activation generation advance"
    );
}

#[test]
pub(super) fn preemptive_runtime_p3_rejects_stale_or_mismatched_preemptions() {
    let mut graph = p3_running_activation_with_timer();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p3-test",
        SemanticCommand::PreemptActivation {
            preemption: 6,
            activation: 11,
            activation_generation: 2,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            queue: 1,
            note: "stale".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption timer target does not match activation generation".to_string());
    assert_eq!(stale.violations, expected);
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Running);

    let missing_timer = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p3-test",
        SemanticCommand::PreemptActivation {
            preemption: 7,
            activation: 11,
            activation_generation: 3,
            timer_interrupt: 99,
            timer_interrupt_generation: 1,
            queue: 1,
            note: "missing timer".to_string(),
        },
    ));
    assert_eq!(missing_timer.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption timer interrupt generation is missing".to_string());
    assert_eq!(missing_timer.violations, expected);
}

#[test]
pub(super) fn preemptive_runtime_p3_invariants_reject_preemption_timer_generation_leak() {
    let mut graph = p3_running_activation_with_timer();
    assert!(graph.preempt_running_activation_with_id(6, 11, 3, 5, 1, 1, "timer preempt"));
    graph.corrupt_preemption_timer_generation_for_test(6, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PreemptionMissingTimerInterrupt {
            preemption: 6,
            interrupt: 5,
        })
    );
}

pub(super) fn p4_preempted_activation() -> SemanticGraph {
    let mut graph = p3_running_activation_with_timer();
    assert!(graph.preempt_running_activation_with_id(6, 11, 3, 5, 1, 1, "timer preempt"));
    graph
}

#[test]
pub(super) fn preemptive_runtime_p4_save_preempted_context_captures_timer_frame() {
    let mut graph = p4_preempted_activation();

    let save = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p4-test",
        SemanticCommand::SavePreemptedContext {
            context: 12,
            saved_context: 13,
            preemption: 6,
            preemption_generation: 1,
            pc: 0x2000,
            sp: 0x9000,
            flags: 0,
            note: "timer frame".to_string(),
        },
    ));
    assert_eq!(save.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].activation, 11);
    assert_eq!(graph.activation_contexts()[0].activation_generation, 4);
    assert_eq!(graph.activation_contexts()[0].generation, 2);
    assert_eq!(graph.saved_contexts()[0].reason, SavedContextReason::TimerPreempt);
    assert_eq!(graph.saved_contexts()[0].pc, 0x2000);
    assert_eq!(graph.saved_contexts()[0].sp, 0x9000);
    assert_eq!(graph.saved_contexts()[0].source_preemption, Some(6));
    assert_eq!(graph.saved_contexts()[0].source_preemption_generation, Some(1));
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SavedContextCaptured saved_context=13 context=12@2 activation=11@4 reason=timer-preempt generation=1"
    );
}

#[test]
pub(super) fn preemptive_runtime_p4_rejects_missing_preemption_and_empty_frame() {
    let mut graph = p4_preempted_activation();
    let missing = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p4-test",
        SemanticCommand::SavePreemptedContext {
            context: 12,
            saved_context: 13,
            preemption: 99,
            preemption_generation: 1,
            pc: 0x2000,
            sp: 0x9000,
            flags: 0,
            note: "missing".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption generation is missing".to_string());
    assert_eq!(missing.violations, expected);
    assert!(graph.activation_contexts().is_empty());
    assert!(graph.saved_contexts().is_empty());

    let empty_frame = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p4-test",
        SemanticCommand::SavePreemptedContext {
            context: 12,
            saved_context: 13,
            preemption: 6,
            preemption_generation: 1,
            pc: 0,
            sp: 0x9000,
            flags: 0,
            note: "empty".to_string(),
        },
    ));
    assert_eq!(empty_frame.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preempted context requires nonzero pc and sp".to_string());
    assert_eq!(empty_frame.violations, expected);
}

#[test]
pub(super) fn preemptive_runtime_p4_invariants_reject_saved_context_preemption_generation_leak() {
    let mut graph = p4_preempted_activation();
    assert!(graph.save_preempted_context_with_ids(12, 13, 6, 1, 0x2000, 0x9000, 0, "timer"));
    graph.clear_saved_context_source_preemption_generation_for_test(13);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SavedContextMissingPreemptionGeneration { saved_context: 13 })
    );
}

pub(super) fn p5_preempted_activation_with_saved_context() -> SemanticGraph {
    let mut graph = p4_preempted_activation();
    assert!(graph.save_preempted_context_with_ids(12, 13, 6, 1, 0x2000, 0x9000, 0, "timer"));
    graph
}

#[test]
pub(super) fn preemptive_runtime_p5_scheduler_decision_records_runnable_choice() {
    let mut graph = p5_preempted_activation_with_saved_context();

    let decision = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p5-test",
        SemanticCommand::RecordSchedulerDecision {
            decision: 14,
            queue: 1,
            queue_generation: 1,
            selected_activation: 11,
            selected_activation_generation: 4,
            reason: "runnable-available".to_string(),
            note: "choose preempted activation".to_string(),
        },
    ));
    assert_eq!(decision.status, CommandStatus::Applied);
    assert_eq!(graph.scheduler_decisions().len(), 1);
    assert_eq!(graph.scheduler_decisions()[0].state, SchedulerDecisionState::Recorded);
    assert_eq!(graph.scheduler_decisions()[0].selected_activation, 11);
    assert_eq!(graph.scheduler_decisions()[0].selected_activation_generation, 4);
    assert_eq!(graph.scheduler_decisions()[0].owner_task, 7);
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Runnable);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SchedulerDecisionRecorded decision=14 queue=1@1 activation=11@4 generation=1"
    );
}

#[test]
pub(super) fn preemptive_runtime_p5_scheduler_decision_is_historical_after_dequeue() {
    let mut graph = p4_preempted_activation();
    assert!(graph.record_scheduler_decision_with_id(
        14,
        1,
        1,
        11,
        4,
        "runnable-available",
        "choose"
    ));
    assert!(graph.dequeue_runnable_activation(1, 11));

    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Running);
    assert_eq!(graph.runtime_activations()[0].generation, 5);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert_eq!(graph.check_invariants(), Ok(()));
}

#[test]
pub(super) fn preemptive_runtime_p5_rejects_unqueued_or_stale_decision() {
    let mut graph = p5_preempted_activation_with_saved_context();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p5-test",
        SemanticCommand::RecordSchedulerDecision {
            decision: 14,
            queue: 1,
            queue_generation: 1,
            selected_activation: 11,
            selected_activation_generation: 3,
            reason: "stale".to_string(),
            note: "stale activation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("scheduler decision activation is not queued".to_string());
    assert_eq!(stale.violations, expected);
    assert!(graph.scheduler_decisions().is_empty());

    let empty_reason = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p5-test",
        SemanticCommand::RecordSchedulerDecision {
            decision: 14,
            queue: 1,
            queue_generation: 1,
            selected_activation: 11,
            selected_activation_generation: 4,
            reason: "".to_string(),
            note: "empty reason".to_string(),
        },
    ));
    assert_eq!(empty_reason.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("scheduler decision reason is empty".to_string());
    assert_eq!(empty_reason.violations, expected);
}

#[test]
pub(super) fn preemptive_runtime_p5_invariants_reject_decision_generation_leak() {
    let mut graph = p5_preempted_activation_with_saved_context();
    assert!(graph.record_scheduler_decision_with_id(
        14,
        1,
        1,
        11,
        4,
        "runnable-available",
        "choose"
    ));
    graph.corrupt_scheduler_decision_activation_generation_for_test(14, 3);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SchedulerDecisionQueueEntryMismatch {
            decision: 14,
            activation: 11,
        })
    );
}

pub(super) fn p6_decided_preempted_activation() -> SemanticGraph {
    let mut graph = p5_preempted_activation_with_saved_context();
    assert!(graph.record_scheduler_decision_with_id(
        14,
        1,
        1,
        11,
        4,
        "runnable-available",
        "choose"
    ));
    graph
}

#[test]
pub(super) fn preemptive_runtime_p6_resume_activation_consumes_decision_and_restores_context() {
    let mut graph = p6_decided_preempted_activation();

    let resume = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p6-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "resume selected activation".to_string(),
        },
    ));

    assert_eq!(resume.status, CommandStatus::Applied);
    assert_eq!(graph.activation_resumes().len(), 1);
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Running);
    assert_eq!(graph.runtime_activations()[0].generation, 5);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert_eq!(graph.scheduler_decisions()[0].state, SchedulerDecisionState::Superseded);
    assert_eq!(graph.activation_contexts()[0].generation, 3);
    assert_eq!(graph.activation_contexts()[0].activation_generation, 5);
    assert_eq!(graph.activation_contexts()[0].state, ActivationContextState::Current);
    assert!(graph.activation_contexts()[0].current_saved_context.is_none());
    assert_eq!(graph.saved_contexts()[0].generation, 2);
    assert_eq!(graph.saved_contexts()[0].state, SavedContextState::Restored);
    assert_eq!(graph.saved_contexts()[0].activation_generation, 4);
    assert_eq!(graph.activation_resumes()[0].activation_generation_before, 4);
    assert_eq!(graph.activation_resumes()[0].activation_generation_after, 5);
    assert_eq!(graph.activation_resumes()[0].context, Some(12));
    assert_eq!(graph.activation_resumes()[0].context_generation_before, Some(2));
    assert_eq!(graph.activation_resumes()[0].context_generation_after, Some(3));
    assert_eq!(graph.activation_resumes()[0].saved_context, Some(13));
    assert_eq!(graph.activation_resumes()[0].saved_context_generation, Some(2));
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "RuntimeActivationResumed resume=15 decision=14@1 activation=11@4->5 queue=1@1 generation=1"
    );
}

#[test]
pub(super) fn preemptive_runtime_p6_rejects_stale_decision_and_dead_store_resume() {
    let mut graph = p6_decided_preempted_activation();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p6-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 2,
            activation: 11,
            activation_generation: 4,
            note: "stale decision".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("resume scheduler decision generation is missing or consumed".to_string());
    assert_eq!(stale.violations, expected);
    assert!(graph.activation_resumes().is_empty());
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Runnable);

    let mut dead_store_graph = SemanticGraph::new();
    dead_store_graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    let store = dead_store_graph.register_store("driver", "driver.cwasm", "driver", "restartable");
    assert!(dead_store_graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(dead_store_graph.create_runtime_activation_with_id(
        11,
        7,
        1,
        Some(store),
        Some(1),
        None
    ));
    assert!(dead_store_graph.enqueue_runnable_activation(1, 11, 1));
    assert!(dead_store_graph.record_scheduler_decision_with_id(
        14,
        1,
        1,
        11,
        2,
        "runnable-available",
        "choose"
    ));
    dead_store_graph.set_store_state(store, StoreState::Dead);
    let rejected = dead_store_graph.apply_envelope(CommandEnvelope::new(
        2,
        "p6-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 2,
            note: "dead store".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("resume owner store generation is missing or dead".to_string());
    assert_eq!(rejected.violations, expected);

    let mut faulted_task_graph = p6_decided_preempted_activation();
    faulted_task_graph.set_task_state(7, TaskState::Faulted);
    let rejected = faulted_task_graph.apply_envelope(CommandEnvelope::new(
        3,
        "p6-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "faulted task".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("resume owner task generation is missing or not runnable".to_string());
    assert_eq!(rejected.violations, expected);
}

#[test]
pub(super) fn preemptive_runtime_p6_invariants_reject_resume_generation_leak() {
    let mut graph = p6_decided_preempted_activation();
    assert!(graph.resume_activation_with_id(15, 14, 1, 11, 4, "resume"));
    graph.corrupt_activation_resume_after_generation_for_test(15, 7);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationResumeMissingActivation {
            resume: 15,
            activation: 11,
        })
    );
}

pub(super) fn p7_resumed_activation() -> SemanticGraph {
    let mut graph = p6_decided_preempted_activation();
    assert!(graph.resume_activation_with_id(15, 14, 1, 11, 4, "resume"));
    graph
}

#[test]
pub(super) fn preemptive_runtime_p9_latency_sample_records_measured_window() {
    let mut graph = p7_resumed_activation();

    let sample = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p9-test",
        SemanticCommand::RecordPreemptionLatencySample {
            sample: 18,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation_resume: 15,
            activation_resume_generation: 1,
            measured_nanos: 8_500,
            budget_nanos: 50_000,
            note: "host-validation measured window".to_string(),
        },
    ));

    assert_eq!(sample.status, CommandStatus::Applied);
    assert_eq!(graph.preemption_latency_samples().len(), 1);
    let sample = &graph.preemption_latency_samples()[0];
    assert_eq!(sample.state, PreemptionLatencySampleState::Recorded);
    assert_eq!(sample.activation, 11);
    assert_eq!(sample.activation_generation_before, 3);
    assert_eq!(sample.activation_generation_after, 5);
    assert_eq!(sample.measured_nanos, 8_500);
    assert!(sample.measured_nanos <= sample.budget_nanos);
    assert_eq!(
        sample.interrupt_to_resume_events,
        sample.resumed_at_event - sample.interrupt_recorded_at_event
    );
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "PreemptionLatencySampleRecorded sample=18 timer=5@1 preemption=6@1 decision=14@1 resume=15@1 measured_nanos=8500 budget_nanos=50000 generation=1"
    );
}

#[test]
pub(super) fn preemptive_runtime_p9_latency_sample_rejects_bad_measurement_and_chain() {
    let mut graph = p7_resumed_activation();

    let zero_measurement = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p9-test",
        SemanticCommand::RecordPreemptionLatencySample {
            sample: 18,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation_resume: 15,
            activation_resume_generation: 1,
            measured_nanos: 0,
            budget_nanos: 50_000,
            note: "invalid".to_string(),
        },
    ));
    assert_eq!(zero_measurement.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption latency measured nanos must be nonzero".to_string());
    assert_eq!(zero_measurement.violations, expected);

    let missing_resume = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p9-test",
        SemanticCommand::RecordPreemptionLatencySample {
            sample: 18,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation_resume: 99,
            activation_resume_generation: 1,
            measured_nanos: 8_500,
            budget_nanos: 50_000,
            note: "missing resume".to_string(),
        },
    ));
    assert_eq!(missing_resume.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption latency chain is invalid".to_string());
    assert_eq!(missing_resume.violations, expected);
    assert!(graph.preemption_latency_samples().is_empty());
}

#[test]
pub(super) fn preemptive_runtime_p9_invariants_reject_latency_delta_drift() {
    let mut graph = p7_resumed_activation();
    assert!(graph.record_preemption_latency_sample_with_id(
        18, 5, 1, 6, 1, 14, 1, 15, 1, 8_500, 50_000, "sample"
    ));
    graph.corrupt_preemption_latency_interrupt_to_resume_for_test(18, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PreemptionLatencyTimelineMismatch { sample: 18 })
    );
}

#[test]
pub(super) fn timer_wait_scheduler_convergence_keeps_generation_safe_cancel_chain() {
    let mut graph = p7_resumed_activation();

    let timer =
        graph.timer_interrupts().iter().find(|record| record.id == 5).expect("timer interrupt");
    assert_eq!(timer.target_activation, Some(11));
    assert_eq!(timer.target_activation_generation, Some(3));

    let decision = graph
        .scheduler_decisions()
        .iter()
        .find(|record| record.id == 14)
        .expect("scheduler decision");
    assert_eq!(decision.selected_activation, 11);
    assert_eq!(decision.selected_activation_generation, 4);
    assert_eq!(decision.state, SchedulerDecisionState::Superseded);

    let resume = graph
        .activation_resumes()
        .iter()
        .find(|record| record.id == 15)
        .expect("activation resume");
    assert_eq!(resume.scheduler_decision, 14);
    assert_eq!(resume.activation_generation_before, 4);
    assert_eq!(resume.activation_generation_after, 5);

    let timer_blocker = ContractObjectRef::new(ContractObjectKind::TimerInterrupt, 5, 1);
    assert!(graph.block_activation_on_wait_with_id(
        160,
        11,
        5,
        170,
        SemanticWaitKind::Timer,
        vec![timer_blocker],
        Some(400),
        RestartPolicy::RestartIfAllowed,
        "d2 timer wait convergence"
    ));

    let wait = graph.wait_records().iter().find(|record| record.id == 170).expect("d2 wait");
    assert_eq!(wait.kind, SemanticWaitKind::Timer);
    assert_eq!(wait.state, WaitState::Pending);
    assert_eq!(wait.owner_task, Some(7));
    assert_eq!(wait.owner_task_generation, Some(2));
    assert_eq!(wait.blockers, vec![timer_blocker]);
    assert_eq!(wait.deadline, Some(400));

    let activation_wait = graph
        .activation_waits()
        .iter()
        .find(|record| record.id == 160)
        .expect("d2 activation wait");
    assert_eq!(activation_wait.activation_generation_before, 5);
    assert_eq!(activation_wait.activation_generation_after_block, 6);
    assert_eq!(activation_wait.owner_task_generation, 2);
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Pending);
    assert_eq!(graph.runtime_activations()[0].generation, 6);

    let mut pending_graph = graph.clone();
    assert!(pending_graph.record_timer_interrupt_with_id(
        171,
        2,
        1,
        2,
        Some(11),
        Some(6),
        "pending tick"
    ));
    let rejected_preempt = pending_graph.apply_envelope(CommandEnvelope::new(
        2,
        "d2-test",
        SemanticCommand::PreemptActivation {
            preemption: 172,
            activation: 11,
            activation_generation: 6,
            timer_interrupt: 171,
            timer_interrupt_generation: 1,
            queue: 1,
            note: "pending activation is not running".to_string(),
        },
    ));
    assert_eq!(rejected_preempt.status, CommandStatus::Rejected);
    assert!(pending_graph.check_invariants().is_ok());

    assert!(graph.cancel_activation_wait(
        160,
        1,
        1,
        110,
        WaitCancelReason::Timeout,
        "d2 timer wait timeout"
    ));
    let wait =
        graph.wait_records().iter().find(|record| record.id == 170).expect("cancelled d2 wait");
    assert_eq!(wait.state, WaitState::Cancelled);
    assert_eq!(wait.cancel_reason, Some(WaitCancelReason::Timeout));

    let activation_wait = graph
        .activation_waits()
        .iter()
        .find(|record| record.id == 160)
        .expect("cancelled d2 activation wait");
    assert_eq!(activation_wait.state, ActivationWaitState::Cancelled);
    assert_eq!(activation_wait.activation_generation_after_cancel, Some(7));
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Blocked);
    assert_eq!(graph.runtime_activations()[0].generation, 7);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert!(!graph.cancel_activation_wait(
        160,
        1,
        1,
        110,
        WaitCancelReason::Timeout,
        "repeat cancel must not apply"
    ));
    assert!(!graph.record_scheduler_decision_with_id(
        173,
        1,
        1,
        11,
        7,
        "blocked-activation",
        "blocked activation is not schedulable"
    ));
    assert!(graph.check_invariants().is_ok());
    assert!(graph.event_log_tail(4).iter().any(|record| {
        record
            .kind
            .summary()
            .contains("RuntimeActivationWaitCancelled activation_wait=160 activation=11@6->7")
    }));
}

#[test]
pub(super) fn simd_runtime_v0_target_feature_set_records_default_discovery() {
    let mut graph = SemanticGraph::new();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v0-test",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set: 21_000,
            name: "riscv64-qemu-virt-research-target".to_string(),
            discovery_source: "target-runtime-default-profile".to_string(),
            target_profile: "riscv64-qemu-virt-research".to_string(),
            target_arch: "riscv64".to_string(),
            base_isa: "rv64imac".to_string(),
            simd_abi: "riscv-v".to_string(),
            simd_supported: false,
            vector_register_count: 0,
            vector_register_bits: 0,
            scalar_fallback: true,
            unsupported_reason: "default profile does not declare RVV/SIMD".to_string(),
            note: "v0 default SIMD discovery".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.target_feature_set_count(), 1);
    let feature = &graph.target_feature_sets()[0];
    assert_eq!(
        feature.object_ref(),
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_000, 1)
    );
    assert_eq!(feature.state, TargetFeatureSetState::Discovered);
    assert!(!feature.simd_supported);
    assert!(feature.scalar_fallback);
    assert_eq!(feature.vector_register_count, 0);
    assert_eq!(feature.vector_register_bits, 0);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "TargetFeatureSetDiscovered feature_set=21000 target_profile=riscv64-qemu-virt-research target_arch=riscv64 base_isa=rv64imac simd_abi=riscv-v simd_supported=false vector_register_count=0 vector_register_bits=0 scalar_fallback=true generation=1"
    );
}

#[test]
pub(super) fn simd_runtime_v0_rejects_inconsistent_target_feature_discovery() {
    let mut graph = SemanticGraph::new();

    let supported_without_shape = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v0-test",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set: 21_000,
            name: "bad-supported".to_string(),
            discovery_source: "unit-test".to_string(),
            target_profile: "test-profile".to_string(),
            target_arch: "riscv64".to_string(),
            base_isa: "rv64imac".to_string(),
            simd_abi: "riscv-v".to_string(),
            simd_supported: true,
            vector_register_count: 0,
            vector_register_bits: 0,
            scalar_fallback: true,
            unsupported_reason: "".to_string(),
            note: "bad".to_string(),
        },
    ));
    assert_eq!(supported_without_shape.status, CommandStatus::Rejected);
    assert_eq!(
        supported_without_shape.violations,
        vec!["supported SIMD discovery requires vector register shape".to_string()]
    );

    let unsupported_without_reason = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v0-test",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set: 21_001,
            name: "bad-unsupported".to_string(),
            discovery_source: "unit-test".to_string(),
            target_profile: "test-profile".to_string(),
            target_arch: "riscv64".to_string(),
            base_isa: "rv64imac".to_string(),
            simd_abi: "riscv-v".to_string(),
            simd_supported: false,
            vector_register_count: 0,
            vector_register_bits: 0,
            scalar_fallback: true,
            unsupported_reason: "".to_string(),
            note: "bad".to_string(),
        },
    ));
    assert_eq!(unsupported_without_reason.status, CommandStatus::Rejected);
    assert_eq!(
        unsupported_without_reason.violations,
        vec!["unsupported SIMD discovery requires a reason".to_string()]
    );
    assert!(graph.target_feature_sets().is_empty());
}

#[test]
pub(super) fn simd_runtime_v0_invariants_reject_vector_shape_drift() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-qemu-virt-research-target",
        "target-runtime-default-profile",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "default profile does not declare RVV/SIMD",
        "v0 default SIMD discovery",
    ));
    graph.corrupt_target_feature_set_vector_shape_for_test(21_000, 128);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::TargetFeatureSetInvalid { feature_set: 21_000 })
    );
}

#[test]
pub(super) fn simd_runtime_v4_vector_state_records_unavailable_context_object() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-qemu-virt-research-target",
        "target-runtime-default-profile",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "default profile does not declare RVV/SIMD",
        "v0 default SIMD discovery",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v4-test",
        SemanticCommand::RecordVectorState {
            vector_state: 22_000,
            owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 7, 3),
            owner_store: ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
            code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_000,
                1,
            ),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            register_bytes: 512,
            state: VectorStateState::Unavailable,
            note: "v4 unavailable vector state".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.vector_state_count(), 1);
    let vector_state = &graph.vector_states()[0];
    assert_eq!(
        vector_state.object_ref(),
        ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1)
    );
    assert_eq!(vector_state.state, VectorStateState::Unavailable);
    assert_eq!(vector_state.register_bytes, 512);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "VectorStateRecorded vector_state=22000 activation=activation:7@3 store=store:2@5 code_object=code-object:9@4 target_feature_set=target-feature-set:21000@1 simd_abi=riscv-v vector_register_count=32 vector_register_bits=128 register_bytes=512 state=unavailable generation=1"
    );
}

#[test]
pub(super) fn simd_runtime_v4_rejects_reserved_vector_state_without_target_support() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-qemu-virt-research-target",
        "target-runtime-default-profile",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "default profile does not declare RVV/SIMD",
        "v0 default SIMD discovery",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v4-test",
        SemanticCommand::RecordVectorState {
            vector_state: 22_000,
            owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 7, 3),
            owner_store: ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
            code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_000,
                1,
            ),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            register_bytes: 512,
            state: VectorStateState::Reserved,
            note: "bad reserved vector state".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Rejected);
    assert_eq!(
        result.violations,
        vec!["reserved vector state requires supported SIMD target feature set".to_string()]
    );
    assert!(graph.vector_states().is_empty());
}

#[test]
pub(super) fn simd_runtime_v4_invariants_reject_vector_state_event_drift() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-qemu-virt-research-target",
        "target-runtime-default-profile",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "default profile does not declare RVV/SIMD",
        "v0 default SIMD discovery",
    ));
    assert!(graph.record_vector_state_with_id(
        22_000,
        ContractObjectRef::new(ContractObjectKind::Activation, 7, 3),
        ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_000, 1),
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Unavailable,
        "v4 unavailable vector state",
    ));
    graph.corrupt_vector_state_owner_activation_generation_for_test(22_000, 4);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::VectorStateMissingEvent { vector_state: 22_000, event: 2 })
    );
}

pub(super) fn v5_activation_context_with_reserved_vector_state() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "simd-vector-task");
    let store =
        graph.register_store("v5.simd.store", "v5-simd-context.fake-aot", "service", "restartable");
    graph.set_store_state(store, StoreState::Running);
    let store_generation =
        graph.store_handle(store).map(|handle| handle.generation).expect("store generation");
    let code_object = ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4);
    assert!(graph.create_runtime_activation_with_id(
        11,
        7,
        1,
        Some(store),
        Some(store_generation),
        Some(code_object),
    ));
    assert!(graph.create_activation_context_with_id(12, 11, 1));
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-vector-test-target",
        "semantic-contract-v5-test",
        "riscv64-vector-test",
        "riscv64",
        "rv64gcv",
        "riscv-v",
        true,
        32,
        128,
        false,
        "",
        "v5 supported SIMD discovery",
    ));
    assert!(graph.record_vector_state_with_id(
        22_000,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 1),
        ContractObjectRef::new(ContractObjectKind::Store, store, store_generation),
        code_object,
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_000, 1),
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Reserved,
        "v5 reserved vector state",
    ));
    graph
}

#[test]
pub(super) fn simd_runtime_v5_activation_context_tracks_dirty_and_clean_vector_state() {
    let mut graph = v5_activation_context_with_reserved_vector_state();
    let vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1);

    let dirty = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v5-test",
        SemanticCommand::UpdateActivationContextVectorState {
            context: 12,
            context_generation: 1,
            vector_state: Some(vector_ref),
            vector_status: ActivationVectorState::Dirty,
            note: "guest touched vector registers".to_string(),
        },
    ));
    assert_eq!(dirty.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Dirty);
    assert_eq!(graph.activation_contexts()[0].vector_state, Some(vector_ref));
    assert_eq!(graph.activation_contexts()[0].generation, 2);

    let clean = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v5-test",
        SemanticCommand::UpdateActivationContextVectorState {
            context: 12,
            context_generation: 2,
            vector_state: Some(vector_ref),
            vector_status: ActivationVectorState::Clean,
            note: "vector state is synchronized with activation context".to_string(),
        },
    ));
    assert_eq!(clean.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Clean);
    assert_eq!(graph.activation_contexts()[0].generation, 3);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "ActivationContextVectorStateUpdated context=12@2->3 vector_state=vector-state:22000@1 vector_status=clean generation=1"
    );
}

#[test]
pub(super) fn simd_runtime_v5_rejects_missing_or_stale_vector_state_ref() {
    let mut graph = v5_activation_context_with_reserved_vector_state();

    let missing = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v5-test",
        SemanticCommand::UpdateActivationContextVectorState {
            context: 12,
            context_generation: 1,
            vector_state: None,
            vector_status: ActivationVectorState::Dirty,
            note: "missing vector ref".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    assert_eq!(
        missing.violations,
        vec!["clean or dirty vector context requires vector state".to_string()]
    );

    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v5-test",
        SemanticCommand::UpdateActivationContextVectorState {
            context: 12,
            context_generation: 1,
            vector_state: Some(ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 2)),
            vector_status: ActivationVectorState::Clean,
            note: "stale vector generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(stale.violations, vec!["activation context vector state is missing".to_string()]);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Absent);
}

#[test]
pub(super) fn simd_runtime_v5_invariants_reject_vector_context_generation_drift() {
    let mut graph = v5_activation_context_with_reserved_vector_state();
    assert!(graph.update_activation_context_vector_state(
        12,
        1,
        Some(ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1,)),
        ActivationVectorState::Dirty,
        "dirty vector state",
    ));
    graph.corrupt_activation_context_vector_state_generation_for_test(12, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationContextVectorStateMissing { context: 12 })
    );
}

#[test]
pub(super) fn simd_runtime_v6_lazy_enable_transitions_absent_context_to_dirty() {
    let mut graph = v5_activation_context_with_reserved_vector_state();
    let vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1);

    let enabled = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v6-test",
        SemanticCommand::EnableLazyVectorState {
            context: 12,
            context_generation: 1,
            vector_state: vector_ref,
            note: "first vector instruction enables vector state".to_string(),
        },
    ));

    assert_eq!(enabled.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Dirty);
    assert_eq!(graph.activation_contexts()[0].vector_state, Some(vector_ref));
    assert_eq!(graph.activation_contexts()[0].generation, 2);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "LazyVectorStateEnabled context=12@1->2 vector_state=vector-state:22000@1 vector_status=dirty generation=1"
    );
}

#[test]
pub(super) fn simd_runtime_v6_rejects_lazy_enable_when_context_already_has_vector_state() {
    let mut graph = v5_activation_context_with_reserved_vector_state();
    let vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1);
    assert!(graph.enable_lazy_vector_state(12, 1, vector_ref, "first vector use"));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v6-test",
        SemanticCommand::EnableLazyVectorState {
            context: 12,
            context_generation: 2,
            vector_state: vector_ref,
            note: "second lazy enable".to_string(),
        },
    ));

    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["lazy vector enable requires absent vector context".to_string()]
    );
}

#[test]
pub(super) fn simd_runtime_v6_rejects_lazy_enable_with_unavailable_vector_state() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "simd-unavailable-task");
    let code_object = ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4);
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, Some(code_object)));
    assert!(graph.create_activation_context_with_id(12, 11, 1));
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-qemu-virt-research-target",
        "target-runtime-default-profile",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "default profile does not declare RVV/SIMD",
        "v6 unavailable SIMD discovery",
    ));
    assert!(graph.record_vector_state_with_id(
        22_000,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 1),
        ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
        code_object,
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_000, 1),
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Unavailable,
        "v6 unavailable vector state",
    ));

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v6-test",
        SemanticCommand::EnableLazyVectorState {
            context: 12,
            context_generation: 1,
            vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1),
            note: "first vector instruction on unsupported target".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["activation context vector state must be live-owned".to_string()]
    );
}

pub(super) fn v7_preempted_dirty_vector_context() -> SemanticGraph {
    let mut graph = p4_preempted_activation();
    assert!(graph.save_preempted_context_with_ids(12, 13, 6, 1, 0x2000, 0x9000, 0, "timer"));
    assert!(graph.record_target_feature_set_with_id(
        21_002,
        "riscv64-vector-preempt-test-target",
        "semantic-contract-v7-test",
        "riscv64-vector-preempt-test",
        "riscv64",
        "rv64gcv",
        "riscv-v",
        true,
        32,
        128,
        false,
        "",
        "v7 supported SIMD preempt fixture",
    ));
    assert!(graph.record_vector_state_with_id(
        22_002,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 4),
        ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_002, 1),
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Reserved,
        "v7 reserved vector state",
    ));
    assert!(graph.update_activation_context_vector_state(
        12,
        2,
        Some(ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1,)),
        ActivationVectorState::Dirty,
        "dirty vector state before preempt save",
    ));
    graph
}

#[test]
pub(super) fn simd_runtime_v7_preempt_saves_dirty_vector_state_as_clean_context() {
    let mut graph = v7_preempted_dirty_vector_context();
    let vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1);

    let saved = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v7-test",
        SemanticCommand::SaveDirtyVectorStateOnPreempt {
            context: 12,
            context_generation: 3,
            saved_context: 13,
            saved_context_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            vector_state: vector_ref,
            note: "timer preempt saves dirty vector state".to_string(),
        },
    ));

    assert_eq!(saved.status, CommandStatus::Applied, "{:?}", saved.violations);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Clean);
    assert_eq!(graph.activation_contexts()[0].generation, 4);
    assert_eq!(graph.activation_contexts()[0].current_saved_context_generation, Some(2));
    assert_eq!(graph.saved_contexts()[0].generation, 2);
    assert_eq!(graph.saved_contexts()[0].context_generation, 4);
    assert_eq!(graph.saved_contexts()[0].vector_state, Some(vector_ref));
    assert_eq!(graph.saved_contexts()[0].vector_status, ActivationVectorState::Clean);
    assert!(graph.saved_contexts()[0].vector_saved_at_event.is_some());
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "DirtyVectorStateSavedOnPreempt saved_context=13@2 context=12@3->4 preemption=6@1 vector_state=vector-state:22002@1 vector_status=clean generation=1"
    );
}

#[test]
pub(super) fn simd_runtime_v7_rejects_preempt_vector_save_without_dirty_context() {
    let mut graph = p4_preempted_activation();
    assert!(graph.save_preempted_context_with_ids(12, 13, 6, 1, 0x2000, 0x9000, 0, "timer"));

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v7-test",
        SemanticCommand::SaveDirtyVectorStateOnPreempt {
            context: 12,
            context_generation: 2,
            saved_context: 13,
            saved_context_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
            note: "no dirty vector state".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["preempt vector save requires dirty activation vector state".to_string()]
    );
}

#[test]
pub(super) fn simd_runtime_v7_rejects_stale_saved_context_generation() {
    let mut graph = v7_preempted_dirty_vector_context();

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v7-test",
        SemanticCommand::SaveDirtyVectorStateOnPreempt {
            context: 12,
            context_generation: 3,
            saved_context: 13,
            saved_context_generation: 99,
            preemption: 6,
            preemption_generation: 1,
            vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
            note: "stale saved generation".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["saved activation context does not reference saved context generation".to_string()]
    );
}

pub(super) fn v8_saved_vector_context_with_decision() -> SemanticGraph {
    let mut graph = v7_preempted_dirty_vector_context();
    let vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1);
    let saved = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v8-test",
        SemanticCommand::SaveDirtyVectorStateOnPreempt {
            context: 12,
            context_generation: 3,
            saved_context: 13,
            saved_context_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            vector_state: vector_ref,
            note: "timer preempt saves dirty vector state".to_string(),
        },
    ));
    assert_eq!(saved.status, CommandStatus::Applied, "{saved:?}");
    let decision = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v8-test",
        SemanticCommand::RecordSchedulerDecision {
            decision: 14,
            queue: 1,
            queue_generation: 1,
            selected_activation: 11,
            selected_activation_generation: 4,
            reason: "resume-ready".to_string(),
            note: "choose vector-saved activation".to_string(),
        },
    ));
    assert_eq!(decision.status, CommandStatus::Applied, "{decision:?}");
    graph
}

#[test]
pub(super) fn simd_runtime_v8_resume_restores_vector_state_to_current_activation_generation() {
    let mut graph = v8_saved_vector_context_with_decision();
    let saved_vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1);
    let restored_vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_003, 1);

    let resumed = graph.apply_envelope(CommandEnvelope::new(
        3,
        "v8-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "resume restores vector state".to_string(),
        },
    ));

    assert_eq!(resumed.status, CommandStatus::Applied, "{resumed:?}");
    assert_eq!(graph.runtime_activations()[0].generation, 5);
    assert_eq!(graph.activation_contexts()[0].state, ActivationContextState::Current);
    assert_eq!(graph.activation_contexts()[0].generation, 5);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Clean);
    assert_eq!(graph.activation_contexts()[0].vector_state, Some(restored_vector_ref));
    assert_eq!(graph.saved_contexts()[0].state, SavedContextState::Restored);
    assert_eq!(graph.saved_contexts()[0].vector_state, Some(saved_vector_ref));
    let resume = &graph.activation_resumes()[0];
    assert_eq!(resume.saved_vector_state, Some(saved_vector_ref));
    assert_eq!(resume.restored_vector_state, Some(restored_vector_ref));
    assert_eq!(resume.vector_status, ActivationVectorState::Clean);
    assert!(resume.vector_restored_at_event.is_some());
    let restored_vector = graph
        .vector_states()
        .iter()
        .find(|record| record.object_ref() == restored_vector_ref)
        .unwrap();
    assert_eq!(
        restored_vector.owner_activation,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 5)
    );
    let saved_vector = graph
        .vector_states()
        .iter()
        .find(|record| record.object_ref() == saved_vector_ref)
        .unwrap();
    assert_eq!(saved_vector.state, VectorStateState::Dropped);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "VectorStateRestoredOnResume resume=15@1 context=12@5 saved_context=13@3 saved_vector_state=vector-state:22002@1 restored_vector_state=vector-state:22003@1 vector_status=clean generation=1"
    );
}

#[test]
pub(super) fn simd_runtime_v8_rejects_resume_when_dirty_vector_state_was_not_saved() {
    let mut graph = v7_preempted_dirty_vector_context();
    let decision = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v8-test",
        SemanticCommand::RecordSchedulerDecision {
            decision: 14,
            queue: 1,
            queue_generation: 1,
            selected_activation: 11,
            selected_activation_generation: 4,
            reason: "resume-ready".to_string(),
            note: "choose dirty vector activation".to_string(),
        },
    ));
    assert_eq!(decision.status, CommandStatus::Applied, "{decision:?}");

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v8-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "must reject dirty vector resume".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["resume vector state is present without saved vector state".to_string()]
    );
}

#[test]
pub(super) fn simd_runtime_v8_rejects_resume_vector_generation_mismatch() {
    let mut graph = v8_saved_vector_context_with_decision();
    graph.corrupt_activation_context_vector_state_generation_for_test(12, 99);

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        3,
        "v8-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "must reject stale vector generation".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["resume vector state does not match saved context".to_string()]
    );
}

pub(super) fn v9_cross_hart_clean_vector_migration_graph(
    vector_status: ActivationVectorState,
) -> SemanticGraph {
    let mut graph = s9_activation_migration_graph();
    assert!(graph.create_activation_context_with_id(12, 11, 4));
    assert!(graph.record_target_feature_set_with_id(
        21_003,
        "riscv64-vector-migration-test-target",
        "semantic-contract-v9-test",
        "riscv64-vector-migration-test",
        "riscv64",
        "rv64gcv",
        "riscv-v",
        true,
        32,
        128,
        false,
        "",
        "v9 supported SIMD migration fixture",
    ));
    assert!(graph.record_vector_state_with_id(
        22_004,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 4),
        ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_003, 1),
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Reserved,
        "v9 reserved vector state before cross-hart migration",
    ));
    assert!(graph.update_activation_context_vector_state(
        12,
        1,
        Some(ContractObjectRef::new(ContractObjectKind::VectorState, 22_004, 1,)),
        vector_status,
        "v9 context vector state before cross-hart migration",
    ));
    graph
}

#[test]
pub(super) fn simd_runtime_v9_cross_hart_migration_rehomes_clean_vector_state() {
    let mut graph = v9_cross_hart_clean_vector_migration_graph(ActivationVectorState::Clean);
    let source_vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_004, 1);
    let migrated_vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_005, 1);

    let migrated = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v9-test",
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
            note: "cross-hart migration rehomes clean vector state".to_string(),
        },
    ));

    assert_eq!(migrated.status, CommandStatus::Applied, "{migrated:?}");
    let migration = &graph.activation_migrations()[0];
    assert_eq!(migration.source_vector_state, Some(source_vector_ref));
    assert_eq!(migration.migrated_vector_state, Some(migrated_vector_ref));
    assert_eq!(migration.vector_status, ActivationVectorState::Clean);
    assert!(migration.vector_migrated_at_event.is_some());
    assert_eq!(migration.context, Some(12));
    assert_eq!(migration.context_generation_before, Some(2));
    assert_eq!(migration.context_generation_after, Some(3));
    let context = &graph.activation_contexts()[0];
    assert_eq!(context.activation_generation, 5);
    assert_eq!(context.vector_state, Some(migrated_vector_ref));
    assert_eq!(context.vector_status, ActivationVectorState::Clean);
    let source_vector = graph
        .vector_states()
        .iter()
        .find(|record| record.object_ref() == source_vector_ref)
        .unwrap();
    assert_eq!(source_vector.state, VectorStateState::Dropped);
    let migrated_vector = graph
        .vector_states()
        .iter()
        .find(|record| record.object_ref() == migrated_vector_ref)
        .unwrap();
    assert_eq!(
        migrated_vector.owner_activation,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 5)
    );
    assert_eq!(migrated_vector.state, VectorStateState::Reserved);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "VectorStateMigratedAcrossHart migration=71@1 context=12@3 source_vector_state=vector-state:22004@1 migrated_vector_state=vector-state:22005@1 vector_status=clean generation=1"
    );
}

#[test]
pub(super) fn simd_runtime_v9_history_survives_context_generation_advance() {
    let mut graph = v9_cross_hart_clean_vector_migration_graph(ActivationVectorState::Clean);
    let migrated_vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_005, 1);

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
        "cross-hart migration rehomes clean vector state",
    ));
    assert!(graph.update_activation_context_vector_state(
        12,
        3,
        Some(migrated_vector_ref),
        ActivationVectorState::Clean,
        "later context bookkeeping must not invalidate migration history",
    ));

    let migration = &graph.activation_migrations()[0];
    assert_eq!(migration.context_generation_after, Some(3));
    assert_eq!(graph.activation_contexts()[0].generation, 4);
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn simd_runtime_v9_rejects_dirty_vector_state_migration() {
    let mut graph = v9_cross_hart_clean_vector_migration_graph(ActivationVectorState::Dirty);

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v9-test",
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
            note: "must reject dirty vector migration".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["activation migration requires clean vector state".to_string()]
    );
    assert!(graph.activation_migrations().is_empty());
}

#[test]
pub(super) fn simd_runtime_v9_invariants_reject_migrated_vector_generation_drift() {
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
        "cross-hart migration rehomes clean vector state",
    ));
    graph.corrupt_vector_state_owner_activation_generation_for_test(22_005, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationContextVectorStateInvalid { context: 12 })
    );
}

#[test]
pub(super) fn simd_runtime_v10_fault_injection_records_exact_trap_attribution() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_010,
        "riscv64-qemu-virt-no-rvv",
        "semantic-contract-v10-test",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "RVV disabled for injected fault test",
        "v10 unsupported SIMD target fixture",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v10-test",
        SemanticCommand::RecordSimdFaultInjection {
            injection: 22_010,
            activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 4),
            code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            trap: ContractObjectRef::new(ContractObjectKind::Trap, 33, 1),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_010,
                1,
            ),
            vector_state: None,
            kind: SimdFaultInjectionKind::UnsupportedFeature,
            effect: SimdFaultInjectionEffect::ActivationTrapped,
            required_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            injected_faults: 1,
            note: "record unsupported SIMD injection".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.simd_fault_injection_count(), 1);
    let injection = &graph.simd_fault_injections()[0];
    assert_eq!(
        injection.object_ref(),
        ContractObjectRef::new(ContractObjectKind::SimdFaultInjection, 22_010, 1)
    );
    assert_eq!(injection.activation.generation, 4);
    assert_eq!(injection.code_object.generation, 4);
    assert_eq!(injection.trap.generation, 1);
    assert_eq!(
        injection.target_feature_set,
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_010, 1)
    );
    assert_eq!(injection.kind, SimdFaultInjectionKind::UnsupportedFeature);
    assert_eq!(injection.effect, SimdFaultInjectionEffect::ActivationTrapped);
    assert_eq!(injection.injected_faults, 1);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SimdFaultInjectionRecorded injection=22010 activation=activation:11@4 code_object=code-object:9@4 trap=trap:33@1 target_feature_set=target-feature-set:21010@1 vector_state=none kind=unsupported-feature effect=activation-trapped generation=1"
    );
}

#[test]
pub(super) fn simd_runtime_v10_rejects_unsupported_fault_with_live_vector_state() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_010,
        "riscv64-qemu-virt-no-rvv",
        "semantic-contract-v10-test",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "RVV disabled for injected fault test",
        "v10 unsupported SIMD target fixture",
    ));

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v10-test",
        SemanticCommand::RecordSimdFaultInjection {
            injection: 22_010,
            activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 4),
            code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            trap: ContractObjectRef::new(ContractObjectKind::Trap, 33, 1),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_010,
                1,
            ),
            vector_state: Some(ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1)),
            kind: SimdFaultInjectionKind::UnsupportedFeature,
            effect: SimdFaultInjectionEffect::ActivationTrapped,
            required_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            injected_faults: 1,
            note: "bad unsupported SIMD injection".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec![
            "unsupported SIMD fault injection must record a trap without live vector state"
                .to_string()
        ]
    );
    assert!(graph.simd_fault_injections().is_empty());
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn simd_runtime_v10_rejects_illegal_instruction_on_unsupported_target() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_010,
        "riscv64-qemu-virt-no-rvv",
        "semantic-contract-v10-test",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "RVV disabled for injected fault test",
        "v10 unsupported SIMD target fixture",
    ));

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v10-test",
        SemanticCommand::RecordSimdFaultInjection {
            injection: 22_010,
            activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 4),
            code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            trap: ContractObjectRef::new(ContractObjectKind::Trap, 33, 1),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_010,
                1,
            ),
            vector_state: None,
            kind: SimdFaultInjectionKind::IllegalInstruction,
            effect: SimdFaultInjectionEffect::ActivationTrapped,
            required_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            injected_faults: 1,
            note: "bad illegal SIMD injection".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["SIMD illegal instruction injection requires a supported feature set".to_string()]
    );
    assert!(graph.simd_fault_injections().is_empty());
}

pub(super) fn v11_supported_simd_benchmark_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_011,
        "riscv64-vector-benchmark-test-target",
        "semantic-contract-v11-test",
        "riscv64-vector-benchmark-test",
        "riscv64",
        "rv64gcv",
        "riscv-v",
        true,
        32,
        128,
        true,
        "",
        "v11 supported SIMD benchmark fixture",
    ));
    graph
}

#[test]
pub(super) fn simd_runtime_v11_benchmark_records_scalar_vs_vector_speedup() {
    let mut graph = v11_supported_simd_benchmark_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v11-test",
        SemanticCommand::RecordSimdBenchmark {
            benchmark: 22_011,
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_011,
                1,
            ),
            scalar_code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            vector_code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 10, 4),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            workload_units: 4096,
            scalar_nanos: 120_000,
            vector_nanos: 40_000,
            speedup_milli: 3000,
            context_overhead_nanos: 80_000,
            note: "record scalar/vector SIMD benchmark".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.simd_benchmark_count(), 1);
    let benchmark = &graph.simd_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::SimdBenchmark, 22_011, 1)
    );
    assert_eq!(benchmark.scalar_code_object.generation, 4);
    assert_eq!(benchmark.vector_code_object.generation, 4);
    assert_eq!(benchmark.speedup_milli, 3000);
    assert_eq!(benchmark.context_overhead_nanos, 80_000);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SimdBenchmarkRecorded benchmark=22011 target_feature_set=target-feature-set:21011@1 scalar_code_object=code-object:9@4 vector_code_object=code-object:10@4 simd_abi=riscv-v vector_register_count=32 vector_register_bits=128 workload_units=4096 scalar_nanos=120000 vector_nanos=40000 speedup_milli=3000 context_overhead_nanos=80000 generation=1"
    );
}

#[test]
pub(super) fn simd_runtime_v11_rejects_vector_slower_than_scalar() {
    let mut graph = v11_supported_simd_benchmark_graph();

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v11-test",
        SemanticCommand::RecordSimdBenchmark {
            benchmark: 22_011,
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_011,
                1,
            ),
            scalar_code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            vector_code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 10, 4),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            workload_units: 4096,
            scalar_nanos: 40_000,
            vector_nanos: 120_000,
            speedup_milli: 333,
            context_overhead_nanos: 0,
            note: "bad slower vector benchmark".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["SIMD benchmark vector path must be faster than scalar path".to_string()]
    );
    assert!(graph.simd_benchmarks().is_empty());
}

#[test]
pub(super) fn simd_runtime_v11_invariants_reject_metric_drift() {
    let mut graph = v11_supported_simd_benchmark_graph();
    assert!(graph.record_simd_benchmark_with_id(
        22_011,
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_011, 1),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 10, 4),
        "riscv-v",
        32,
        128,
        4096,
        120_000,
        40_000,
        3000,
        80_000,
        "v11 scalar/vector benchmark",
    ));
    graph.corrupt_simd_benchmark_speedup_for_test(22_011, 2999);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SimdBenchmarkInvalid { benchmark: 22_011 })
    );
}

pub(super) fn v12_resumed_vector_context() -> SemanticGraph {
    let mut graph = v8_saved_vector_context_with_decision();
    let resumed = graph.apply_envelope(CommandEnvelope::new(
        3,
        "v12-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "resume restores vector state before benchmark".to_string(),
        },
    ));
    assert_eq!(resumed.status, CommandStatus::Applied, "{resumed:?}");
    graph
}

#[test]
pub(super) fn simd_runtime_v12_context_switch_benchmark_records_vector_overhead() {
    let mut graph = v12_resumed_vector_context();

    let result = graph.apply_envelope(CommandEnvelope::new(
        4,
        "v12-test",
        SemanticCommand::RecordSimdContextSwitchBenchmark {
            benchmark: 22_012,
            preemption: ContractObjectRef::new(ContractObjectKind::Preemption, 6, 1),
            activation_resume: ContractObjectRef::new(ContractObjectKind::ActivationResume, 15, 1),
            saved_vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
            restored_vector_state: ContractObjectRef::new(
                ContractObjectKind::VectorState,
                22_003,
                1,
            ),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_002,
                1,
            ),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            sample_count: 64,
            scalar_context_switch_nanos: 30_000,
            vector_context_switch_nanos: 46_384,
            overhead_nanos: 16_384,
            budget_nanos: 50_000,
            note: "record SIMD context switch overhead".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.simd_context_switch_benchmark_count(), 1);
    let benchmark = &graph.simd_context_switch_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::SimdContextSwitchBenchmark, 22_012, 1)
    );
    assert_eq!(benchmark.preemption.generation, 1);
    assert_eq!(benchmark.activation_resume.generation, 1);
    assert_eq!(benchmark.saved_vector_state.id, 22_002);
    assert_eq!(benchmark.restored_vector_state.id, 22_003);
    assert_eq!(benchmark.overhead_nanos, 16_384);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SimdContextSwitchBenchmarkRecorded benchmark=22012 preemption=preemption:6@1 activation_resume=activation-resume:15@1 saved_vector_state=vector-state:22002@1 restored_vector_state=vector-state:22003@1 target_feature_set=target-feature-set:21002@1 simd_abi=riscv-v vector_register_count=32 vector_register_bits=128 sample_count=64 scalar_context_switch_nanos=30000 vector_context_switch_nanos=46384 overhead_nanos=16384 budget_nanos=50000 generation=1"
    );
}

#[test]
pub(super) fn simd_runtime_v12_rejects_overhead_budget_violation() {
    let mut graph = v12_resumed_vector_context();

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        4,
        "v12-test",
        SemanticCommand::RecordSimdContextSwitchBenchmark {
            benchmark: 22_012,
            preemption: ContractObjectRef::new(ContractObjectKind::Preemption, 6, 1),
            activation_resume: ContractObjectRef::new(ContractObjectKind::ActivationResume, 15, 1),
            saved_vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
            restored_vector_state: ContractObjectRef::new(
                ContractObjectKind::VectorState,
                22_003,
                1,
            ),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_002,
                1,
            ),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            sample_count: 64,
            scalar_context_switch_nanos: 30_000,
            vector_context_switch_nanos: 46_384,
            overhead_nanos: 16_384,
            budget_nanos: 10_000,
            note: "bad SIMD context switch budget".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["SIMD context switch benchmark overhead exceeds budget".to_string()]
    );
    assert!(graph.simd_context_switch_benchmarks().is_empty());
}

#[test]
pub(super) fn simd_runtime_v12_invariants_reject_overhead_drift() {
    let mut graph = v12_resumed_vector_context();
    assert!(graph.record_simd_context_switch_benchmark_with_id(
        22_012,
        ContractObjectRef::new(ContractObjectKind::Preemption, 6, 1),
        ContractObjectRef::new(ContractObjectKind::ActivationResume, 15, 1),
        ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
        ContractObjectRef::new(ContractObjectKind::VectorState, 22_003, 1),
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_002, 1),
        "riscv-v",
        32,
        128,
        64,
        30_000,
        46_384,
        16_384,
        50_000,
        "v12 context switch benchmark",
    ));
    graph.corrupt_simd_context_switch_overhead_for_test(22_012, 16_383);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SimdContextSwitchBenchmarkInvalid { benchmark: 22_012 })
    );
}
