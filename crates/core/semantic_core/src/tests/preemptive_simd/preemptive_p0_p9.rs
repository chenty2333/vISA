use super::*;

#[test]
pub(in crate::tests) fn preemptive_runtime_p0_queue_commands_emit_events_and_pass_invariants() {
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
pub(in crate::tests) fn preemptive_runtime_p0_rejects_pending_task_and_stale_generation_enqueue() {
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
pub(in crate::tests) fn preemptive_runtime_p0_rejects_duplicate_queue_and_generationless_store_owner()
 {
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
pub(in crate::tests) fn preemptive_runtime_p0_invariants_reject_bad_queue_ownership() {
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
pub(in crate::tests) fn preemptive_runtime_p1_context_commands_emit_events_and_pass_invariants() {
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
pub(in crate::tests) fn preemptive_runtime_p1_rejects_stale_context_generation_and_empty_frame() {
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
pub(in crate::tests) fn preemptive_runtime_p1_invariants_reject_context_saved_generation_leak() {
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

pub(in crate::tests) fn register_idle_test_hart(graph: &mut SemanticGraph) -> Generation {
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    2
}

#[test]
pub(in crate::tests) fn preemptive_runtime_p2_timer_interrupt_records_event_and_passes_invariants()
{
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
pub(in crate::tests) fn preemptive_runtime_p2_rejects_stale_target_and_non_monotonic_epoch() {
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
pub(in crate::tests) fn preemptive_runtime_p2_invariants_reject_timer_epoch_regression() {
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

pub(in crate::tests) fn p3_running_activation_with_timer() -> SemanticGraph {
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
pub(in crate::tests) fn preemptive_runtime_p3_preempt_activation_requeues_running_activation() {
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
pub(in crate::tests) fn preemptive_runtime_p3_rejects_stale_or_mismatched_preemptions() {
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
pub(in crate::tests) fn preemptive_runtime_p3_invariants_reject_preemption_timer_generation_leak() {
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

pub(in crate::tests) fn p4_preempted_activation() -> SemanticGraph {
    let mut graph = p3_running_activation_with_timer();
    assert!(graph.preempt_running_activation_with_id(6, 11, 3, 5, 1, 1, "timer preempt"));
    graph
}

#[test]
pub(in crate::tests) fn preemptive_runtime_p4_save_preempted_context_captures_timer_frame() {
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
pub(in crate::tests) fn preemptive_runtime_p4_rejects_missing_preemption_and_empty_frame() {
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
pub(in crate::tests) fn preemptive_runtime_p4_invariants_reject_saved_context_preemption_generation_leak()
 {
    let mut graph = p4_preempted_activation();
    assert!(graph.save_preempted_context_with_ids(12, 13, 6, 1, 0x2000, 0x9000, 0, "timer"));
    graph.clear_saved_context_source_preemption_generation_for_test(13);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SavedContextMissingPreemptionGeneration { saved_context: 13 })
    );
}

pub(in crate::tests) fn p5_preempted_activation_with_saved_context() -> SemanticGraph {
    let mut graph = p4_preempted_activation();
    assert!(graph.save_preempted_context_with_ids(12, 13, 6, 1, 0x2000, 0x9000, 0, "timer"));
    graph
}

#[test]
pub(in crate::tests) fn preemptive_runtime_p5_scheduler_decision_records_runnable_choice() {
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
pub(in crate::tests) fn preemptive_runtime_p5_scheduler_decision_is_historical_after_dequeue() {
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
pub(in crate::tests) fn preemptive_runtime_p5_rejects_unqueued_or_stale_decision() {
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
pub(in crate::tests) fn preemptive_runtime_p5_invariants_reject_decision_generation_leak() {
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

pub(in crate::tests) fn p6_decided_preempted_activation() -> SemanticGraph {
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
pub(in crate::tests) fn preemptive_runtime_p6_resume_activation_consumes_decision_and_restores_context()
 {
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
pub(in crate::tests) fn preemptive_runtime_p6_rejects_stale_decision_and_dead_store_resume() {
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
pub(in crate::tests) fn preemptive_runtime_p6_invariants_reject_resume_generation_leak() {
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

pub(in crate::tests) fn p7_resumed_activation() -> SemanticGraph {
    let mut graph = p6_decided_preempted_activation();
    assert!(graph.resume_activation_with_id(15, 14, 1, 11, 4, "resume"));
    graph
}

#[test]
pub(in crate::tests) fn preemptive_runtime_p9_latency_sample_records_measured_window() {
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
pub(in crate::tests) fn preemptive_runtime_p9_latency_sample_rejects_bad_measurement_and_chain() {
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
pub(in crate::tests) fn preemptive_runtime_p9_invariants_reject_latency_delta_drift() {
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
pub(in crate::tests) fn timer_wait_scheduler_convergence_keeps_generation_safe_cancel_chain() {
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
