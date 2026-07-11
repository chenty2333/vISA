use super::*;

#[test]
pub(super) fn smp_runtime_s2_timer_interrupt_uses_exact_hart_ref_and_event_attribution() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));

    let timer = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s2-test",
        SemanticCommand::RecordTimerInterrupt {
            interrupt: 5,
            timer_epoch: 1,
            hart: 1,
            hart_generation,
            target_activation: Some(11),
            target_activation_generation: Some(3),
            note: "timer attributed to hart0".to_string(),
        },
    ));

    assert_eq!(timer.status, CommandStatus::Applied);
    assert_eq!(graph.timer_interrupts()[0].hart, 1);
    assert_eq!(graph.timer_interrupts()[0].hart_generation, 2);
    assert_eq!(graph.timer_interrupts()[0].hardware_hart, 0);
    let attribution = graph.hart_event_attributions().last().unwrap();
    assert_eq!(attribution.event_kind, "TimerInterruptRecorded");
    assert_eq!(attribution.event_source, "timer");
    assert_eq!(attribution.hart, 1);
    assert_eq!(attribution.hart_generation, 2);
    assert_eq!(attribution.activation, Some(11));
    assert_eq!(attribution.activation_generation, Some(3));
    assert_eq!(attribution.task, Some(7));
    assert_eq!(attribution.task_generation, Some(1));
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s2_rejects_stale_or_missing_hart_ref() {
    let mut graph = SemanticGraph::new();
    register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));

    let stale_hart = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s2-test",
        SemanticCommand::RecordTimerInterrupt {
            interrupt: 5,
            timer_epoch: 1,
            hart: 1,
            hart_generation: 99,
            target_activation: Some(11),
            target_activation_generation: Some(1),
            note: "stale hart generation".to_string(),
        },
    ));
    assert_eq!(stale_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("timer interrupt hart generation is missing or inactive".to_string());
    assert_eq!(stale_hart.violations, expected);
    assert!(graph.timer_interrupts().is_empty());
}

#[test]
pub(super) fn smp_runtime_s2_invariants_reject_bad_hart_event_generation() {
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
        "timer"
    ));
    graph.corrupt_hart_event_attribution_hart_generation_for_test(1, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::HartEventAttributionHartGenerationMismatch {
            attribution: 1,
            hart: 1,
        })
    );
}

#[test]
pub(super) fn smp_runtime_s2_invariants_reject_timer_without_hart_event_attribution() {
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
        "timer"
    ));
    graph.clear_hart_event_attributions_for_test();

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::TimerInterruptMissingHartEventAttribution {
            interrupt: 5,
            event: graph.timer_interrupts()[0].recorded_at_event,
        })
    );
}

#[test]
pub(super) fn smp_runtime_s3_binds_runnable_queue_to_owner_hart_generation() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));

    let bound = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s3-test",
        SemanticCommand::BindRunnableQueueOwner {
            queue: 1,
            queue_generation: 1,
            hart: 1,
            hart_generation,
            note: "hart0 owns queue".to_string(),
        },
    ));

    assert_eq!(bound.status, CommandStatus::Applied);
    assert_eq!(graph.runnable_queues()[0].generation, 2);
    assert_eq!(graph.runnable_queues()[0].owner_hart, Some(1));
    assert_eq!(graph.runnable_queues()[0].owner_hart_generation, Some(hart_generation));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "RunnableQueueOwnerBound queue=1 hart=1@2 generation=2 note=hart0 owns queue"
    );
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert_eq!(graph.runtime_activations()[0].runnable_queue_generation, Some(2));
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s3_rejects_stale_hart_generation_and_live_rebinding() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));

    let stale_owner = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s3-test",
        SemanticCommand::BindRunnableQueueOwner {
            queue: 1,
            queue_generation: 1,
            hart: 1,
            hart_generation: 99,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale_owner.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("runnable queue owner hart generation is missing or unavailable".to_string());
    assert_eq!(stale_owner.violations, expected);
    assert_eq!(graph.runnable_queues()[0].generation, 1);

    let bound = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s3-test",
        SemanticCommand::BindRunnableQueueOwner {
            queue: 1,
            queue_generation: 1,
            hart: 1,
            hart_generation,
            note: "hart0 owns queue".to_string(),
        },
    ));
    assert_eq!(bound.status, CommandStatus::Applied);
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));

    let live_rebind = graph.apply_envelope(CommandEnvelope::new(
        3,
        "s3-test",
        SemanticCommand::BindRunnableQueueOwner {
            queue: 1,
            queue_generation: 2,
            hart: 2,
            hart_generation: 2,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(live_rebind.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("runnable queue owner cannot change while entries are live".to_string());
    assert_eq!(live_rebind.violations, expected);
    assert_eq!(graph.runnable_queues()[0].owner_hart, Some(1));
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s3_invariants_reject_bad_queue_owner_generation() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));
    assert!(graph.bind_runnable_queue_owner(1, 1, 1, hart_generation, "owner"));

    graph.corrupt_runnable_queue_owner_for_test(1, Some(1), Some(99));

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RunnableQueueOwnerHartGenerationMismatch {
            queue: 1,
            hart: 1,
            expected: 99,
            actual: 2,
        })
    );
}

#[test]
pub(super) fn smp_runtime_s3_invariants_reject_partial_queue_owner_ref() {
    let mut graph = SemanticGraph::new();
    register_idle_test_hart(&mut graph);
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));

    graph.corrupt_runnable_queue_owner_for_test(1, Some(1), None);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RunnableQueueOwnerFieldMismatch { queue: 1 })
    );
}

#[test]
pub(super) fn smp_runtime_s4_allows_distinct_current_activations_on_distinct_harts() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    graph.ensure_task(8, FrontendKind::LinuxElf, "linux-thread-8");
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));
    assert!(graph.create_runnable_queue_with_id(2, "hart1-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.create_runtime_activation_with_id(12, 8, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.enqueue_runnable_activation(2, 12, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.dequeue_runnable_activation(2, 12));

    let hart0 = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s4-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 1,
            hart_generation: 2,
            activation: 11,
            activation_generation: 3,
            note: "dispatch activation 11 on hart0".to_string(),
        },
    ));
    assert_eq!(hart0.status, CommandStatus::Applied);
    let hart1 = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s4-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 2,
            hart_generation: 2,
            activation: 12,
            activation_generation: 3,
            note: "dispatch activation 12 on hart1".to_string(),
        },
    ));
    assert_eq!(hart1.status, CommandStatus::Applied);
    assert_eq!(graph.harts()[0].current_activation, Some(11));
    assert_eq!(graph.harts()[1].current_activation, Some(12));
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s4_rejects_activation_current_on_another_hart() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.bind_hart_current_activation(1, 2, 11, 3, "dispatch hart0"));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s4-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 2,
            hart_generation: 2,
            activation: 11,
            activation_generation: 3,
            note: "must reject duplicate current activation".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation is already current on another hart".to_string());
    assert_eq!(duplicate.violations, expected);
    assert_eq!(graph.harts()[1].current_activation, None);
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s4_invariants_reject_duplicate_current_activation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.bind_hart_current_activation(1, 2, 11, 3, "dispatch hart0"));
    let mut duplicate = graph.harts()[0].clone();
    duplicate.id = 2;
    duplicate.hardware_id = 1;
    duplicate.label = "hart1-duplicate-current".to_string();
    duplicate.boot = false;
    graph.duplicate_hart_for_test(duplicate);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationCurrentOnMultipleHarts {
            activation: 11,
            first_hart: 1,
            second_hart: 2,
        })
    );
}

#[test]
pub(super) fn smp_runtime_s5_records_ipi_event_between_hart_generations() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));

    let ipi = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s5-test",
        SemanticCommand::RecordIpiEvent {
            ipi: 21,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 2,
            kind: IpiEventKind::SchedulerKick,
            reason: "scheduler kick".to_string(),
            note: "hart0 kicks hart1".to_string(),
        },
    ));

    assert_eq!(ipi.status, CommandStatus::Applied);
    assert_eq!(graph.ipi_events().len(), 1);
    assert_eq!(graph.ipi_events()[0].source_hardware_hart, 0);
    assert_eq!(graph.ipi_events()[0].target_hardware_hart, 1);
    assert_eq!(graph.hart_event_attributions().len(), 6);
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.ipi_events()[0].recorded_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "IpiEventSourceRecorded"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.ipi_events()[0].recorded_at_event
            && record.hart == 2
            && record.hart_generation == 2
            && record.event_kind == "IpiEventTargetRecorded"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IpiEventRecorded ipi=21 kind=scheduler-kick source_hart=1@2 target_hart=2@2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s5_rejects_stale_or_self_target_ipi_event() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s5-test",
        SemanticCommand::RecordIpiEvent {
            ipi: 21,
            source_hart: 1,
            source_hart_generation: 99,
            target_hart: 2,
            target_hart_generation: 2,
            kind: IpiEventKind::SchedulerKick,
            reason: "stale source".to_string(),
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("ipi source hart generation is missing or inactive".to_string());
    assert_eq!(stale.violations, expected);

    let self_target = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s5-test",
        SemanticCommand::RecordIpiEvent {
            ipi: 22,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 1,
            target_hart_generation: 2,
            kind: IpiEventKind::SchedulerKick,
            reason: "self target".to_string(),
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(self_target.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("ipi source and target harts must differ".to_string());
    assert_eq!(self_target.violations, expected);
    assert!(graph.ipi_events().is_empty());
}

#[test]
pub(super) fn smp_runtime_s5_invariants_reject_bad_ipi_target_generation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.record_ipi_event_with_id(
        21,
        1,
        2,
        2,
        2,
        IpiEventKind::SchedulerKick,
        "scheduler kick",
        "hart0 kicks hart1",
    ));

    graph.corrupt_ipi_event_target_generation_for_test(21, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IpiEventHartGenerationMismatch { ipi: 21, hart: 2 })
    );
}

#[test]
pub(super) fn smp_runtime_s5_ipi_history_survives_later_hart_offline() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.record_ipi_event_with_id(
        21,
        1,
        2,
        2,
        2,
        IpiEventKind::SchedulerKick,
        "scheduler kick",
        "hart0 kicks hart1",
    ));
    assert!(graph.set_hart_state(2, 2, HartState::Offline, "parked", "offline after event"));

    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s5_invariants_require_source_and_target_attribution() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.record_ipi_event_with_id(
        21,
        1,
        2,
        2,
        2,
        IpiEventKind::SchedulerKick,
        "scheduler kick",
        "hart0 kicks hart1",
    ));
    let event = graph.ipi_events()[0].recorded_at_event;
    graph.clear_hart_event_attributions_for_test();

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IpiEventMissingHartEventAttribution { ipi: 21, event })
    );
}

pub(super) fn s6_remote_preempt_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "remote-preempt-target");
    assert!(graph.create_runnable_queue_with_id(2, "hart1-rq"));
    assert!(graph.bind_runnable_queue_owner(2, 1, 2, 2, "hart1 owns queue"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(2, 11, 1));
    assert!(graph.dequeue_runnable_activation(2, 11));
    assert!(graph.bind_hart_current_activation(2, 2, 11, 3, "dispatch on hart1"));
    assert!(graph.record_ipi_event_with_id(
        21,
        1,
        2,
        2,
        3,
        IpiEventKind::SchedulerKick,
        "remote preempt",
        "hart0 requests hart1 preempt",
    ));
    graph
}

#[test]
pub(super) fn smp_runtime_s6_remote_preempt_requeues_target_hart_activation() {
    let mut graph = s6_remote_preempt_graph();

    let remote = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s6-test",
        SemanticCommand::RemotePreemptActivation {
            remote_preempt: 31,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 3,
            activation: 11,
            activation_generation: 3,
            queue: 2,
            note: "remote preempt activation".to_string(),
        },
    ));

    assert_eq!(remote.status, CommandStatus::Applied);
    assert_eq!(graph.remote_preempts().len(), 1);
    assert_eq!(graph.remote_preempts()[0].ipi, 21);
    assert_eq!(graph.remote_preempts()[0].target_hart_generation_before, 3);
    assert_eq!(graph.remote_preempts()[0].target_hart_generation_after, 4);
    assert_eq!(graph.remote_preempts()[0].activation_generation_after, 4);
    let hart = graph.harts().iter().find(|hart| hart.id == 2).expect("target hart");
    assert_eq!(hart.state, HartState::Idle);
    assert_eq!(hart.generation, 4);
    assert_eq!(hart.current_activation, None);
    let activation = graph
        .runtime_activations()
        .iter()
        .find(|activation| activation.id == 11)
        .expect("activation");
    assert_eq!(activation.state, RuntimeActivationState::Runnable);
    assert_eq!(activation.generation, 4);
    assert_eq!(activation.runnable_queue, Some(2));
    assert!(
        graph.runnable_queues()[0]
            .entries
            .iter()
            .any(|entry| entry.activation == 11 && entry.activation_generation == 4)
    );
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.remote_preempts()[0].preempted_at_event
            && record.hart == 1
            && record.event_kind == "RemotePreemptSourceRecorded"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.remote_preempts()[0].preempted_at_event
            && record.hart == 2
            && record.hart_generation == 4
            && record.event_kind == "RemotePreemptTargetRecorded"
    }));
    assert_eq!(
        graph.event_log_tail(3)[0].kind.summary(),
        "RemoteActivationPreempted remote_preempt=31 ipi=21@1 source_hart=1@2 target_hart=2@3->4 activation=11@3->4 queue=2@2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s6_rejects_stale_ipi_and_wrong_target_generation() {
    let mut graph = s6_remote_preempt_graph();

    let stale_ipi = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s6-test",
        SemanticCommand::RemotePreemptActivation {
            remote_preempt: 31,
            ipi: 21,
            ipi_generation: 99,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 3,
            activation: 11,
            activation_generation: 3,
            queue: 2,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale_ipi.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote preempt ipi generation is missing".to_string());
    assert_eq!(stale_ipi.violations, expected);

    let wrong_target = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s6-test",
        SemanticCommand::RemotePreemptActivation {
            remote_preempt: 32,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 2,
            activation: 11,
            activation_generation: 3,
            queue: 2,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(wrong_target.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote preempt target hart generation is missing".to_string());
    assert_eq!(wrong_target.violations, expected);
    assert!(graph.remote_preempts().is_empty());
}

#[test]
pub(super) fn smp_runtime_s6_rejects_queue_not_owned_by_target_hart() {
    let mut graph = s6_remote_preempt_graph();
    assert!(graph.create_runnable_queue_with_id(3, "wrong-rq"));
    assert!(graph.bind_runnable_queue_owner(3, 1, 1, 2, "hart0 owns wrong queue"));

    let remote = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s6-test",
        SemanticCommand::RemotePreemptActivation {
            remote_preempt: 31,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 3,
            activation: 11,
            activation_generation: 3,
            queue: 3,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(remote.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote preempt queue is not owned by target hart".to_string());
    assert_eq!(remote.violations, expected);
}

#[test]
pub(super) fn smp_runtime_s6_invariants_reject_remote_preempt_ipi_generation_leak() {
    let mut graph = s6_remote_preempt_graph();
    assert!(graph.remote_preempt_activation_with_id(
        31,
        21,
        1,
        1,
        2,
        2,
        3,
        11,
        3,
        2,
        "remote preempt activation",
    ));
    graph.corrupt_remote_preempt_ipi_generation_for_test(31, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RemotePreemptMissingIpi { remote_preempt: 31, ipi: 21 })
    );
}

#[test]
pub(super) fn smp_runtime_s6_history_still_requires_event_after_activation_advances() {
    let mut graph = s6_remote_preempt_graph();
    assert!(graph.remote_preempt_activation_with_id(
        31,
        21,
        1,
        1,
        2,
        2,
        3,
        11,
        3,
        2,
        "remote preempt activation",
    ));
    assert!(graph.dequeue_runnable_activation(2, 11));
    graph.corrupt_remote_preempt_event_for_test(31, 999);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RemotePreemptMissingEvent { remote_preempt: 31 })
    );
}

pub(super) fn s7_remote_park_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "hart0", true, "boot hart"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "hart0 idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "secondary hart"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "hart1 idle"));
    assert!(graph.record_ipi_event_with_id(
        21,
        1,
        2,
        2,
        2,
        IpiEventKind::SchedulerKick,
        "remote-park-request",
        "park target hart",
    ));
    graph
}

#[test]
pub(super) fn smp_runtime_s7_remote_park_parks_idle_target_hart() {
    let mut graph = s7_remote_park_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s7-test",
        SemanticCommand::RemoteParkHart {
            remote_park: 31,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 2,
            reason: "remote-maintenance".to_string(),
            note: "park secondary hart".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.remote_parks().len(), 1);
    assert_eq!(graph.remote_parks()[0].ipi, 21);
    assert_eq!(graph.remote_parks()[0].target_hart_generation_before, 2);
    assert_eq!(graph.remote_parks()[0].target_hart_generation_after, 3);
    let target = graph.harts().iter().find(|hart| hart.id == 2).unwrap();
    assert_eq!(target.state, HartState::Parked);
    assert_eq!(target.generation, 3);
    assert!(target.current_activation.is_none());
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.remote_parks()[0].parked_at_event
            && record.hart == 1
            && record.event_kind == "RemoteParkSourceRecorded"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.remote_parks()[0].parked_at_event
            && record.hart == 2
            && record.hart_generation == 3
            && record.event_kind == "RemoteParkTargetRecorded"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "RemoteHartParked remote_park=31 ipi=21@1 source_hart=1@2 target_hart=2@2->3 reason=remote-maintenance generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s7_rejects_stale_ipi_and_running_target_hart() {
    let mut graph = s7_remote_park_graph();
    let stale_ipi = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s7-test",
        SemanticCommand::RemoteParkHart {
            remote_park: 31,
            ipi: 21,
            ipi_generation: 99,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 2,
            reason: "remote-maintenance".to_string(),
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale_ipi.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote park ipi generation is missing".to_string());
    assert_eq!(stale_ipi.violations, expected);

    assert!(graph.set_hart_state(1, 2, HartState::Booting, "source bump", "advance source"));
    assert!(graph.set_hart_state(1, 3, HartState::Idle, "source ready", "source idle again"));
    let stale_source = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s7-test",
        SemanticCommand::RemoteParkHart {
            remote_park: 32,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 2,
            reason: "remote-maintenance".to_string(),
            note: "must reject stale source".to_string(),
        },
    ));
    assert_eq!(stale_source.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote park source hart generation is missing".to_string());
    assert_eq!(stale_source.violations, expected);

    let mut running = s6_remote_preempt_graph();
    let running_target = running.apply_envelope(CommandEnvelope::new(
        2,
        "s7-test",
        SemanticCommand::RemoteParkHart {
            remote_park: 31,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 3,
            reason: "remote-maintenance".to_string(),
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(running_target.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote park target hart is not idle".to_string());
    assert_eq!(running_target.violations, expected);
    assert!(graph.remote_parks().is_empty());
}

#[test]
pub(super) fn smp_runtime_s7_invariants_reject_remote_park_ipi_generation_leak() {
    let mut graph = s7_remote_park_graph();
    assert!(graph.remote_park_hart_with_id(
        31,
        21,
        1,
        1,
        2,
        2,
        2,
        "remote-maintenance",
        "park secondary hart",
    ));
    graph.corrupt_remote_park_ipi_generation_for_test(31, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RemoteParkMissingIpi { remote_park: 31, ipi: 21 })
    );
}

#[test]
pub(super) fn smp_runtime_s7_history_still_requires_event_after_hart_unparks() {
    let mut graph = s7_remote_park_graph();
    assert!(graph.remote_park_hart_with_id(
        31,
        21,
        1,
        1,
        2,
        2,
        2,
        "remote-maintenance",
        "park secondary hart",
    ));
    assert!(graph.set_hart_state(2, 3, HartState::Idle, "unpark", "later unpark"));
    graph.corrupt_remote_park_event_for_test(31, 999);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RemoteParkMissingEvent { remote_park: 31 })
    );
}

pub(super) fn s8_cross_hart_decision_graph() -> SemanticGraph {
    let mut graph = s6_remote_preempt_graph();
    assert!(graph.remote_preempt_activation_with_id(
        31,
        21,
        1,
        1,
        2,
        2,
        3,
        11,
        3,
        2,
        "remote preempt activation",
    ));
    assert!(graph.record_scheduler_decision_with_id(
        41,
        2,
        2,
        11,
        4,
        "remote-runnable",
        "cross-hart base scheduler decision",
    ));
    graph
}

#[test]
pub(super) fn smp_runtime_s8_cross_hart_scheduler_decision_records_remote_choice() {
    let mut graph = s8_cross_hart_decision_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s8-test",
        SemanticCommand::RecordCrossHartSchedulerDecision {
            cross_decision: 51,
            scheduler_decision: 41,
            scheduler_decision_generation: 1,
            deciding_hart: 1,
            deciding_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 4,
            reason: "remote-runnable-selected".to_string(),
            note: "hart0 selects hart1 queue".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.cross_hart_scheduler_decisions().len(), 1);
    let decision = &graph.cross_hart_scheduler_decisions()[0];
    assert_eq!(decision.scheduler_decision, 41);
    assert_eq!(decision.deciding_hart, 1);
    assert_eq!(decision.target_hart, 2);
    assert_eq!(decision.target_hart_generation, 4);
    assert_eq!(decision.queue, 2);
    assert_eq!(decision.queue_generation, 2);
    assert_eq!(decision.queue_owner_hart_generation, 2);
    assert_eq!(decision.selected_activation, 11);
    assert_eq!(decision.selected_activation_generation, 4);
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == decision.decided_at_event
            && record.hart == 1
            && record.event_kind == "CrossHartSchedulerDecisionSourceRecorded"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == decision.decided_at_event
            && record.hart == 2
            && record.hart_generation == 4
            && record.event_kind == "CrossHartSchedulerDecisionTargetRecorded"
            && record.activation == Some(11)
            && record.activation_generation == Some(4)
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "CrossHartSchedulerDecisionRecorded cross_decision=51 decision=41@1 deciding_hart=1@2 target_hart=2@4 queue=2@2 activation=11@4 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s8_rejects_stale_target_and_same_hart_decision() {
    let mut graph = s8_cross_hart_decision_graph();
    let stale_target = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s8-test",
        SemanticCommand::RecordCrossHartSchedulerDecision {
            cross_decision: 51,
            scheduler_decision: 41,
            scheduler_decision_generation: 1,
            deciding_hart: 1,
            deciding_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 3,
            reason: "remote-runnable-selected".to_string(),
            note: "must reject stale target".to_string(),
        },
    ));
    assert_eq!(stale_target.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("cross-hart scheduler decision target hart generation is missing".to_string());
    assert_eq!(stale_target.violations, expected);

    let same_hart = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s8-test",
        SemanticCommand::RecordCrossHartSchedulerDecision {
            cross_decision: 51,
            scheduler_decision: 41,
            scheduler_decision_generation: 1,
            deciding_hart: 2,
            deciding_hart_generation: 4,
            target_hart: 2,
            target_hart_generation: 4,
            reason: "remote-runnable-selected".to_string(),
            note: "must reject same hart".to_string(),
        },
    ));
    assert_eq!(same_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("cross-hart scheduler decision requires distinct harts".to_string());
    assert_eq!(same_hart.violations, expected);
    assert!(graph.cross_hart_scheduler_decisions().is_empty());
}

#[test]
pub(super) fn smp_runtime_s8_history_still_requires_event_after_target_hart_advances() {
    let mut graph = s8_cross_hart_decision_graph();
    assert!(graph.record_cross_hart_scheduler_decision_with_id(
        51,
        41,
        1,
        1,
        2,
        2,
        4,
        "remote-runnable-selected",
        "hart0 selects hart1 queue",
    ));
    assert!(graph.set_hart_state(2, 4, HartState::Parked, "park after decision", "later park"));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_cross_hart_scheduler_decision_event_for_test(51, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::CrossHartSchedulerDecisionMissingEvent { cross_decision: 51 })
    );
}

pub(super) fn s9_activation_migration_graph() -> SemanticGraph {
    let mut graph = s8_cross_hart_decision_graph();
    assert!(graph.create_runnable_queue_with_id(3, "hart0-migration-rq"));
    assert!(graph.bind_runnable_queue_owner(3, 1, 1, 2, "hart0 owns migration queue"));
    graph
}

#[test]
pub(super) fn smp_runtime_s9_activation_migration_moves_runnable_between_hart_queues() {
    let mut graph = s9_activation_migration_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s9-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 61,
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
            reason: "rebalance".to_string(),
            note: "move runnable to hart0".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.activation_migrations().len(), 1);
    let migration = &graph.activation_migrations()[0];
    assert_eq!(migration.activation, 11);
    assert_eq!(migration.activation_generation_before, 4);
    assert_eq!(migration.activation_generation_after, 5);
    assert_eq!(migration.source_queue, 2);
    assert_eq!(migration.target_queue, 3);
    let activation =
        graph.runtime_activations().iter().find(|activation| activation.id == 11).unwrap();
    assert_eq!(activation.generation, 5);
    assert_eq!(activation.runnable_queue, Some(3));
    let source_queue = graph
        .runnable_queues()
        .iter()
        .find(|queue| queue.id == 2 && queue.generation == 2)
        .unwrap();
    assert!(source_queue.entries.iter().all(|entry| entry.activation != 11));
    let target_queue = graph
        .runnable_queues()
        .iter()
        .find(|queue| queue.id == 3 && queue.generation == 2)
        .unwrap();
    assert!(
        target_queue
            .entries
            .iter()
            .any(|entry| entry.activation == 11 && entry.activation_generation == 5)
    );
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == migration.migrated_at_event
            && record.hart == 2
            && record.event_kind == "ActivationMigrationSourceRecorded"
            && record.activation_generation == Some(4)
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == migration.migrated_at_event
            && record.hart == 1
            && record.event_kind == "ActivationMigrationTargetRecorded"
            && record.activation_generation == Some(5)
    }));
    assert_eq!(
        graph.event_log_tail(3)[0].kind.summary(),
        "ActivationMigrated migration=61 activation=11@4->5 source_hart=2@4 target_hart=1@2 source_queue=2@2 target_queue=3@2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s9_rejects_stale_activation_and_wrong_target_queue_owner() {
    let mut graph = s9_activation_migration_graph();
    let stale_activation = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s9-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 61,
            activation: 11,
            activation_generation: 3,
            source_queue: 2,
            source_queue_generation: 2,
            target_queue: 3,
            target_queue_generation: 2,
            source_hart: 2,
            source_hart_generation: 4,
            target_hart: 1,
            target_hart_generation: 2,
            reason: "rebalance".to_string(),
            note: "must reject stale activation".to_string(),
        },
    ));
    assert_eq!(stale_activation.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation migration source queue entry is missing".to_string());
    assert_eq!(stale_activation.violations, expected);

    let same_hart = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s9-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 61,
            activation: 11,
            activation_generation: 4,
            source_queue: 2,
            source_queue_generation: 2,
            target_queue: 3,
            target_queue_generation: 2,
            source_hart: 2,
            source_hart_generation: 4,
            target_hart: 2,
            target_hart_generation: 4,
            reason: "rebalance".to_string(),
            note: "must reject wrong owner".to_string(),
        },
    ));
    assert_eq!(same_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation migration requires distinct harts".to_string());
    assert_eq!(same_hart.violations, expected);

    assert!(graph.create_runnable_queue_with_id(4, "wrong-target-owner-rq"));
    assert!(graph.bind_runnable_queue_owner(4, 1, 2, 4, "hart1 owns wrong target queue"));
    let wrong_owner = graph.apply_envelope(CommandEnvelope::new(
        3,
        "s9-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 62,
            activation: 11,
            activation_generation: 4,
            source_queue: 2,
            source_queue_generation: 2,
            target_queue: 4,
            target_queue_generation: 2,
            source_hart: 2,
            source_hart_generation: 4,
            target_hart: 1,
            target_hart_generation: 2,
            reason: "rebalance".to_string(),
            note: "must reject target queue owner mismatch".to_string(),
        },
    ));
    assert_eq!(wrong_owner.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation migration target queue owner mismatch".to_string());
    assert_eq!(wrong_owner.violations, expected);
    assert!(graph.activation_migrations().is_empty());
}

#[test]
pub(super) fn smp_runtime_s9_history_still_requires_event_after_target_hart_advances() {
    let mut graph = s9_activation_migration_graph();
    assert!(graph.migrate_runnable_activation_with_id(
        61,
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
        "rebalance",
        "move runnable to hart0",
    ));
    assert!(graph.set_hart_state(1, 2, HartState::Booting, "target advances", "later state"));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_activation_migration_event_for_test(61, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationMigrationMissingEvent { migration: 61 })
    );
}

pub(super) fn s10_smp_safe_point_graph() -> SemanticGraph {
    let mut graph = s9_activation_migration_graph();
    assert!(graph.migrate_runnable_activation_with_id(
        61,
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
        "rebalance",
        "move runnable to hart0",
    ));
    graph
}

#[test]
pub(super) fn smp_runtime_s10_safe_point_records_quiesced_harts() {
    let mut graph = s10_smp_safe_point_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s10-test",
        SemanticCommand::RecordSmpSafePoint {
            safe_point: 71,
            coordinator_hart: 1,
            coordinator_hart_generation: 2,
            participants: vec![(1, 2), (2, 4)],
            reason: "quiescent-boundary".to_string(),
            note: "record all harts quiesced".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_safe_points().len(), 1);
    let safe_point = &graph.smp_safe_points()[0];
    assert_eq!(safe_point.coordinator_hart, 1);
    assert_eq!(safe_point.coordinator_hart_generation, 2);
    assert_eq!(safe_point.participants.len(), 2);
    assert!(safe_point.participants.iter().all(|participant| matches!(
        participant.hart_state,
        HartState::Idle | HartState::Parked
    )
        && participant.current_activation.is_none()));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == safe_point.recorded_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "SmpSafePointCoordinatorRecorded"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == safe_point.recorded_at_event
            && record.hart == 2
            && record.hart_generation == 4
            && record.event_kind == "SmpSafePointParticipantRecorded"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SmpSafePointRecorded safe_point=71 coordinator_hart=1@2 participants=2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s10_rejects_stale_participant_and_running_hart() {
    let mut graph = s10_smp_safe_point_graph();
    let stale_participant = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s10-test",
        SemanticCommand::RecordSmpSafePoint {
            safe_point: 71,
            coordinator_hart: 1,
            coordinator_hart_generation: 2,
            participants: vec![(1, 2), (2, 3)],
            reason: "quiescent-boundary".to_string(),
            note: "must reject stale hart generation".to_string(),
        },
    ));
    assert_eq!(stale_participant.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp safe point participant hart generation is missing".to_string());
    assert_eq!(stale_participant.violations, expected);

    let mut running = s6_remote_preempt_graph();
    let running_participant = running.apply_envelope(CommandEnvelope::new(
        2,
        "s10-test",
        SemanticCommand::RecordSmpSafePoint {
            safe_point: 71,
            coordinator_hart: 1,
            coordinator_hart_generation: 2,
            participants: vec![(1, 2), (2, 3)],
            reason: "quiescent-boundary".to_string(),
            note: "must reject running hart".to_string(),
        },
    ));
    assert_eq!(running_participant.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp safe point participant is not quiesced".to_string());
    assert_eq!(running_participant.violations, expected);
    assert!(running.smp_safe_points().is_empty());

    let mut missing = s10_smp_safe_point_graph();
    assert!(missing.register_hart_with_id(3, 2, "hart2", false, "created"));
    assert!(missing.set_hart_state(3, 1, HartState::Idle, "ready", "idle"));
    let missing_active_hart = missing.apply_envelope(CommandEnvelope::new(
        3,
        "s10-test",
        SemanticCommand::RecordSmpSafePoint {
            safe_point: 71,
            coordinator_hart: 1,
            coordinator_hart_generation: 2,
            participants: vec![(1, 2), (2, 4)],
            reason: "quiescent-boundary".to_string(),
            note: "must reject partial safe point".to_string(),
        },
    ));
    assert_eq!(missing_active_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp safe point missing active hart".to_string());
    assert_eq!(missing_active_hart.violations, expected);
    assert!(missing.smp_safe_points().is_empty());
    assert!(graph.smp_safe_points().is_empty());
}

#[test]
pub(super) fn smp_runtime_s10_history_survives_later_hart_transition() {
    let mut graph = s10_smp_safe_point_graph();
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 4)],
        "quiescent-boundary",
        "record all harts quiesced",
    ));
    assert!(graph.set_hart_state(1, 2, HartState::Booting, "advance after safe point", "later"));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_smp_safe_point_event_for_test(71, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpSafePointMissingEvent { safe_point: 71 })
    );
}

pub(super) fn s11_stop_the_world_graph() -> SemanticGraph {
    let mut graph = s10_smp_safe_point_graph();
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 4)],
        "quiescent-boundary",
        "record all harts quiesced",
    ));
    graph
}

#[test]
pub(super) fn smp_runtime_s11_stop_the_world_rendezvous_completes_from_safe_point() {
    let mut graph = s11_stop_the_world_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s11-test",
        SemanticCommand::CompleteStopTheWorldRendezvous {
            rendezvous: 81,
            epoch: 1,
            safe_point: 71,
            safe_point_generation: 1,
            stop_new_activations: true,
            reason: "code-publish-boundary".to_string(),
            note: "all harts parked at activation boundary".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.stop_the_world_rendezvous().len(), 1);
    let rendezvous = &graph.stop_the_world_rendezvous()[0];
    assert_eq!(rendezvous.epoch, 1);
    assert_eq!(rendezvous.safe_point, 71);
    assert_eq!(rendezvous.safe_point_generation, 1);
    assert!(rendezvous.stop_new_activations);
    assert_eq!(rendezvous.coordinator_hart, 1);
    assert_eq!(rendezvous.coordinator_hart_generation, 2);
    assert_eq!(rendezvous.participants.len(), 2);
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == rendezvous.completed_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "StopTheWorldHartParked"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == rendezvous.completed_at_event
            && record.hart == 2
            && record.hart_generation == 4
            && record.event_kind == "StopTheWorldHartParked"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "StopTheWorldRendezvousCompleted rendezvous=81 epoch=1 safe_point=71@1 coordinator_hart=1@2 participants=2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s11_rejects_missing_stop_flag_stale_safe_point_and_hart() {
    let mut graph = s11_stop_the_world_graph();
    let missing_stop = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s11-test",
        SemanticCommand::CompleteStopTheWorldRendezvous {
            rendezvous: 81,
            epoch: 1,
            safe_point: 71,
            safe_point_generation: 1,
            stop_new_activations: false,
            reason: "code-publish-boundary".to_string(),
            note: "must stop new activations".to_string(),
        },
    ));
    assert_eq!(missing_stop.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("stop-the-world rendezvous must stop new activations".to_string());
    assert_eq!(missing_stop.violations, expected);
    assert!(graph.stop_the_world_rendezvous().is_empty());

    let stale_safe_point = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s11-test",
        SemanticCommand::CompleteStopTheWorldRendezvous {
            rendezvous: 81,
            epoch: 1,
            safe_point: 71,
            safe_point_generation: 2,
            stop_new_activations: true,
            reason: "code-publish-boundary".to_string(),
            note: "must reject stale safe point generation".to_string(),
        },
    ));
    assert_eq!(stale_safe_point.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("stop-the-world rendezvous safe point is missing".to_string());
    assert_eq!(stale_safe_point.violations, expected);
    assert!(graph.stop_the_world_rendezvous().is_empty());

    let mut stale_hart = s11_stop_the_world_graph();
    assert!(stale_hart.set_hart_state(
        1,
        2,
        HartState::Booting,
        "advance before rendezvous",
        "not parked"
    ));
    let stale_participant = stale_hart.apply_envelope(CommandEnvelope::new(
        3,
        "s11-test",
        SemanticCommand::CompleteStopTheWorldRendezvous {
            rendezvous: 81,
            epoch: 1,
            safe_point: 71,
            safe_point_generation: 1,
            stop_new_activations: true,
            reason: "code-publish-boundary".to_string(),
            note: "safe point no longer covers current hart".to_string(),
        },
    ));
    assert_eq!(stale_participant.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("stop-the-world rendezvous participant generation is stale".to_string());
    assert_eq!(stale_participant.violations, expected);
    assert!(stale_hart.stop_the_world_rendezvous().is_empty());
}

#[test]
pub(super) fn smp_runtime_s11_history_survives_later_hart_transition() {
    let mut graph = s11_stop_the_world_graph();
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        1,
        71,
        1,
        true,
        "code-publish-boundary",
        "all harts parked at activation boundary",
    ));
    assert!(graph.set_hart_state(2, 4, HartState::Booting, "advance after rendezvous", "later"));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_stop_the_world_event_for_test(81, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::StopTheWorldRendezvousMissingEvent { rendezvous: 81 })
    );
}

pub(super) fn s12_smp_code_publish_barrier_graph() -> SemanticGraph {
    let mut graph = s11_stop_the_world_graph();
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        1,
        71,
        1,
        true,
        "code-publish-boundary",
        "all harts parked at activation boundary",
    ));
    graph
}

#[test]
pub(super) fn smp_runtime_s12_code_publish_barrier_validates_from_rendezvous() {
    let mut graph = s12_smp_code_publish_barrier_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s12-test",
        SemanticCommand::ValidateSmpCodePublishBarrier {
            barrier: 91,
            rendezvous: 81,
            rendezvous_generation: 1,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: true,
            code_publish_executed: false,
            reason: "semantic-code-publish-barrier".to_string(),
            note: "validate remote icache sync evidence only".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_code_publish_barriers().len(), 1);
    let barrier = &graph.smp_code_publish_barriers()[0];
    assert_eq!(barrier.rendezvous, 81);
    assert_eq!(barrier.rendezvous_generation, 1);
    assert_eq!(barrier.rendezvous_epoch, 1);
    assert_eq!(barrier.code_publish_epoch_before, 0);
    assert_eq!(barrier.code_publish_epoch_after, 1);
    assert!(barrier.remote_icache_sync_required);
    assert!(!barrier.code_publish_executed);
    assert_eq!(barrier.participants.len(), 2);
    assert!(barrier.participants.iter().all(|participant| participant.semantic_icache_sync
        && participant.last_seen_code_epoch_before == 0
        && participant.last_seen_code_epoch_after == 1));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == barrier.validated_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "SmpCodePublishBarrierHartSynced"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == barrier.validated_at_event
            && record.hart == 2
            && record.hart_generation == 4
            && record.event_kind == "SmpCodePublishBarrierHartSynced"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SmpCodePublishBarrierValidated barrier=91 rendezvous=81@1 code_publish_epoch=0->1 participants=2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(super) fn smp_runtime_s12_rejects_bad_barrier_inputs() {
    let mut stale_rendezvous = s12_smp_code_publish_barrier_graph();
    let stale = stale_rendezvous.apply_envelope(CommandEnvelope::new(
        1,
        "s12-test",
        SemanticCommand::ValidateSmpCodePublishBarrier {
            barrier: 91,
            rendezvous: 81,
            rendezvous_generation: 2,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: true,
            code_publish_executed: false,
            reason: "semantic-code-publish-barrier".to_string(),
            note: "must reject stale rendezvous".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp code publish barrier rendezvous is missing".to_string());
    assert_eq!(stale.violations, expected);

    let mut missing_sync = s12_smp_code_publish_barrier_graph();
    let missing_sync_result = missing_sync.apply_envelope(CommandEnvelope::new(
        2,
        "s12-test",
        SemanticCommand::ValidateSmpCodePublishBarrier {
            barrier: 91,
            rendezvous: 81,
            rendezvous_generation: 1,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: false,
            code_publish_executed: false,
            reason: "semantic-code-publish-barrier".to_string(),
            note: "must require remote sync".to_string(),
        },
    ));
    assert_eq!(missing_sync_result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp code publish barrier requires remote icache sync".to_string());
    assert_eq!(missing_sync_result.violations, expected);

    let mut real_publish = s12_smp_code_publish_barrier_graph();
    let real_publish_result = real_publish.apply_envelope(CommandEnvelope::new(
        3,
        "s12-test",
        SemanticCommand::ValidateSmpCodePublishBarrier {
            barrier: 91,
            rendezvous: 81,
            rendezvous_generation: 1,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: true,
            code_publish_executed: true,
            reason: "semantic-code-publish-barrier".to_string(),
            note: "must not execute real publish in s12".to_string(),
        },
    ));
    assert_eq!(real_publish_result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp code publish barrier must not execute code publish".to_string());
    assert_eq!(real_publish_result.violations, expected);

    let mut stale_hart = s12_smp_code_publish_barrier_graph();
    assert!(stale_hart.set_hart_state(
        2,
        4,
        HartState::Booting,
        "advance before publish barrier",
        "not parked"
    ));
    let stale_hart_result = stale_hart.apply_envelope(CommandEnvelope::new(
        4,
        "s12-test",
        SemanticCommand::ValidateSmpCodePublishBarrier {
            barrier: 91,
            rendezvous: 81,
            rendezvous_generation: 1,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: true,
            code_publish_executed: false,
            reason: "semantic-code-publish-barrier".to_string(),
            note: "must reject stale participant generation".to_string(),
        },
    ));
    assert_eq!(stale_hart_result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp code publish barrier participant generation is stale".to_string());
    assert_eq!(stale_hart_result.violations, expected);
}

#[test]
pub(super) fn smp_runtime_s12_history_survives_later_hart_transition() {
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
    assert!(graph.set_hart_state(
        1,
        2,
        HartState::Booting,
        "advance after publish barrier",
        "later"
    ));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_smp_code_publish_barrier_event_for_test(91, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpCodePublishBarrierMissingEvent { barrier: 91 })
    );
}
