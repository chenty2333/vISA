use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticCommand {
    CreateRuntimeActivation {
        activation: ActivationId,
        owner_task: TaskId,
        owner_task_generation: Generation,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        code_object: Option<ContractObjectRef>,
    },
    CreateRunnableQueue {
        queue: RunnableQueueId,
        label: String,
    },
    EnqueueRunnable {
        queue: RunnableQueueId,
        activation: ActivationId,
        activation_generation: Generation,
    },
    DequeueRunnable {
        queue: RunnableQueueId,
        activation: ActivationId,
    },
    CreateActivationContext {
        context: ActivationContextId,
        activation: ActivationId,
        activation_generation: Generation,
    },
    CaptureSavedContext {
        saved_context: SavedContextId,
        context: ActivationContextId,
        context_generation: Generation,
        reason: SavedContextReason,
        pc: u64,
        sp: u64,
        flags: u64,
        note: String,
    },
    SavePreemptedContext {
        context: ActivationContextId,
        saved_context: SavedContextId,
        preemption: PreemptionId,
        preemption_generation: Generation,
        pc: u64,
        sp: u64,
        flags: u64,
        note: String,
    },
    RecordTimerInterrupt {
        interrupt: TimerInterruptId,
        timer_epoch: u64,
        hart: u32,
        target_activation: Option<ActivationId>,
        target_activation_generation: Option<Generation>,
        note: String,
    },
    PreemptActivation {
        preemption: PreemptionId,
        activation: ActivationId,
        activation_generation: Generation,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        queue: RunnableQueueId,
        note: String,
    },
    RecordSchedulerDecision {
        decision: SchedulerDecisionId,
        queue: RunnableQueueId,
        queue_generation: Generation,
        selected_activation: ActivationId,
        selected_activation_generation: Generation,
        reason: String,
        note: String,
    },
    ResumeActivation {
        resume: ActivationResumeId,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        note: String,
    },
    RecordPreemptionLatencySample {
        sample: PreemptionLatencySampleId,
        timer_interrupt: TimerInterruptId,
        timer_interrupt_generation: Generation,
        preemption: PreemptionId,
        preemption_generation: Generation,
        scheduler_decision: SchedulerDecisionId,
        scheduler_decision_generation: Generation,
        activation_resume: ActivationResumeId,
        activation_resume_generation: Generation,
        measured_nanos: u64,
        budget_nanos: u64,
        note: String,
    },
    BlockActivationOnWait {
        activation_wait: ActivationWaitId,
        activation: ActivationId,
        activation_generation: Generation,
        wait: WaitId,
        kind: SemanticWaitKind,
        blockers: Vec<ContractObjectRef>,
        deadline: Option<u64>,
        restart_policy: RestartPolicy,
        note: String,
    },
    CancelActivationWait {
        activation_wait: ActivationWaitId,
        activation_wait_generation: Generation,
        wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: String,
    },
    CleanupActivationForStoreFault {
        cleanup: ActivationCleanupId,
        store: StoreId,
        store_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        wait: Option<WaitId>,
        wait_generation: Option<Generation>,
        reason: String,
        note: String,
    },
    GrantCapability {
        subject: String,
        debug_object_label: String,
        object_ref: AuthorityObjectRef,
        operations: Vec<String>,
        lifetime: String,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        owner_task: Option<TaskId>,
        source: String,
        manifest_decl: bool,
    },
    RevokeCapability {
        cap: CapabilityId,
    },
    CreateWait {
        wait: WaitId,
        owner_task: Option<TaskId>,
        owner_store: Option<StoreId>,
        owner_store_generation: Option<Generation>,
        kind: SemanticWaitKind,
        generation: Generation,
        blockers: Vec<ContractObjectRef>,
        deadline: Option<u64>,
        restart_policy: RestartPolicy,
        saved_context: Option<String>,
    },
    ResolveWait {
        wait: WaitId,
        reason: String,
    },
    CancelWait {
        wait: WaitId,
        errno: i32,
        reason: WaitCancelReason,
    },
    RecordTrap {
        store: Option<StoreId>,
        task: Option<TaskId>,
        trap: TrapClass,
        detail: String,
    },
    BeginCleanup {
        cleanup: TransactionId,
        store: StoreId,
        generation: Generation,
        reason: String,
    },
    ApplyCleanupStep {
        cleanup: TransactionId,
        step: CleanupStep,
        target: ContractObjectRef,
        observed_generation: Generation,
    },
    CommitCleanup {
        cleanup: TransactionId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandEnvelope {
    pub command_id: CommandId,
    pub issuer: String,
    pub expected_epoch: Option<u64>,
    pub command: SemanticCommand,
}

impl CommandEnvelope {
    pub fn new(command_id: CommandId, issuer: &str, command: SemanticCommand) -> Self {
        Self {
            command_id,
            issuer: issuer.to_string(),
            expected_epoch: None,
            command,
        }
    }

    pub fn with_expected_epoch(mut self, expected_epoch: u64) -> Self {
        self.expected_epoch = Some(expected_epoch);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStatus {
    Applied,
    Noop,
    Rejected,
}

impl CommandStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Noop => "noop",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandEffect {
    pub kind: String,
    pub target: Option<ContractObjectRef>,
}

impl CommandEffect {
    pub fn new(kind: &str, target: Option<ContractObjectRef>) -> Self {
        Self {
            kind: kind.to_string(),
            target,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandResult {
    pub command_id: CommandId,
    pub issuer: String,
    pub command: &'static str,
    pub status: CommandStatus,
    pub events: Vec<EventId>,
    pub effects: Vec<CommandEffect>,
    pub violations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutcome {
    pub command: &'static str,
    pub event_count_before: usize,
    pub event_count_after: usize,
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandError {
    PreconditionFailed(String),
}

impl CommandError {
    pub fn precondition(detail: &str) -> Self {
        Self::PreconditionFailed(detail.to_string())
    }
}

impl SemanticCommand {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::CreateRuntimeActivation { .. } => "create-runtime-activation",
            Self::CreateRunnableQueue { .. } => "create-runnable-queue",
            Self::EnqueueRunnable { .. } => "enqueue-runnable",
            Self::DequeueRunnable { .. } => "dequeue-runnable",
            Self::CreateActivationContext { .. } => "create-activation-context",
            Self::CaptureSavedContext { .. } => "capture-saved-context",
            Self::SavePreemptedContext { .. } => "save-preempted-context",
            Self::RecordTimerInterrupt { .. } => "record-timer-interrupt",
            Self::PreemptActivation { .. } => "preempt-activation",
            Self::RecordSchedulerDecision { .. } => "record-scheduler-decision",
            Self::ResumeActivation { .. } => "resume-activation",
            Self::RecordPreemptionLatencySample { .. } => "record-preemption-latency-sample",
            Self::BlockActivationOnWait { .. } => "block-activation-on-wait",
            Self::CancelActivationWait { .. } => "cancel-activation-wait",
            Self::CleanupActivationForStoreFault { .. } => "cleanup-activation-for-store-fault",
            Self::GrantCapability { .. } => "grant-capability",
            Self::RevokeCapability { .. } => "revoke-capability",
            Self::CreateWait { .. } => "create-wait",
            Self::ResolveWait { .. } => "resolve-wait",
            Self::CancelWait { .. } => "cancel-wait",
            Self::RecordTrap { .. } => "record-trap",
            Self::BeginCleanup { .. } => "begin-cleanup",
            Self::ApplyCleanupStep { .. } => "apply-cleanup-step",
            Self::CommitCleanup { .. } => "commit-cleanup",
        }
    }
}

impl SemanticGraph {
    pub fn apply_envelope(&mut self, envelope: CommandEnvelope) -> CommandResult {
        let command_name = envelope.command.name();
        let result = if envelope.command_id == 0 {
            rejected_command_result(
                envelope.command_id,
                envelope.issuer,
                command_name,
                "command id=0 is invalid",
            )
        } else if let Some(expected_epoch) = envelope.expected_epoch {
            let actual_epoch = self.event_count() as u64;
            if expected_epoch != actual_epoch {
                rejected_command_result(
                    envelope.command_id,
                    envelope.issuer,
                    command_name,
                    "expected epoch mismatch",
                )
            } else {
                self.apply_envelope_prechecked(envelope, command_name)
            }
        } else {
            self.apply_envelope_prechecked(envelope, command_name)
        };
        self.command_results.push(result.clone());
        result
    }

    fn apply_envelope_prechecked(
        &mut self,
        envelope: CommandEnvelope,
        command_name: &'static str,
    ) -> CommandResult {
        match self.apply(envelope.command) {
            Ok(outcome) => CommandResult {
                command_id: envelope.command_id,
                issuer: envelope.issuer,
                command: outcome.command,
                status: if outcome.changed {
                    CommandStatus::Applied
                } else {
                    CommandStatus::Noop
                },
                events: event_refs_between(outcome.event_count_before, outcome.event_count_after),
                effects: command_effects(&outcome),
                violations: Vec::new(),
            },
            Err(CommandError::PreconditionFailed(detail)) => CommandResult {
                command_id: envelope.command_id,
                issuer: envelope.issuer,
                command: command_name,
                status: CommandStatus::Rejected,
                events: Vec::new(),
                effects: Vec::new(),
                violations: {
                    let mut violations = Vec::new();
                    violations.push(detail);
                    violations
                },
            },
        }
    }

    pub fn apply(&mut self, command: SemanticCommand) -> Result<CommandOutcome, CommandError> {
        self.preflight_command(&command)?;
        let event_count_before = self.event_count();
        let command_name = command.name();
        let changed = self.apply_prechecked_command(command);
        Ok(CommandOutcome {
            command: command_name,
            event_count_before,
            event_count_after: self.event_count(),
            changed,
        })
    }

    fn preflight_command(&self, command: &SemanticCommand) -> Result<(), CommandError> {
        match command {
            SemanticCommand::CreateRuntimeActivation {
                activation,
                owner_task,
                owner_task_generation,
                owner_store,
                owner_store_generation,
                code_object,
            } => {
                if *activation == 0 {
                    Err(CommandError::precondition("activation id=0 is invalid"))
                } else if self
                    .runtime_activations
                    .iter()
                    .any(|record| record.id == *activation)
                {
                    Err(CommandError::precondition("activation already exists"))
                } else if !self
                    .tasks
                    .iter()
                    .any(|task| task.id == *owner_task && task.generation == *owner_task_generation)
                {
                    Err(CommandError::precondition(
                        "activation owner task generation is missing",
                    ))
                } else if let Some(code) = code_object
                    && code.kind != ContractObjectKind::CodeObject
                {
                    Err(CommandError::precondition(
                        "activation code reference must be a code object",
                    ))
                } else if let Some(store) = owner_store {
                    if let Some(generation) = owner_store_generation {
                        if self.stores.iter().any(|record| {
                            record.id == *store
                                && record.generation == *generation
                                && record.state != StoreState::Dead
                        }) {
                            Ok(())
                        } else {
                            Err(CommandError::precondition(
                                "activation owner store generation is missing or dead",
                            ))
                        }
                    } else {
                        Err(CommandError::precondition(
                            "activation owner store generation is required",
                        ))
                    }
                } else {
                    Ok(())
                }
            }
            SemanticCommand::CreateRunnableQueue { queue, label } => {
                if *queue == 0 {
                    Err(CommandError::precondition("runnable queue id=0 is invalid"))
                } else if label.is_empty() {
                    Err(CommandError::precondition("runnable queue label is empty"))
                } else if self
                    .runnable_queues
                    .iter()
                    .any(|record| record.id == *queue)
                {
                    Err(CommandError::precondition("runnable queue already exists"))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::EnqueueRunnable {
                queue,
                activation,
                activation_generation,
            } => {
                let Some(queue_record) = self
                    .runnable_queues
                    .iter()
                    .find(|record| record.id == *queue)
                else {
                    return Err(CommandError::precondition("runnable queue is missing"));
                };
                if queue_record.state != RunnableQueueState::Active {
                    return Err(CommandError::precondition("runnable queue is not active"));
                }
                if self.runnable_queues.iter().any(|record| {
                    record
                        .entries
                        .iter()
                        .any(|entry| entry.activation == *activation)
                }) {
                    return Err(CommandError::precondition("activation already queued"));
                }
                let Some(activation_record) = self
                    .runtime_activations
                    .iter()
                    .find(|record| record.id == *activation)
                else {
                    return Err(CommandError::precondition("activation is missing"));
                };
                if activation_record.generation != *activation_generation {
                    return Err(CommandError::precondition("activation generation mismatch"));
                }
                if !matches!(
                    activation_record.state,
                    RuntimeActivationState::Created | RuntimeActivationState::Blocked
                ) {
                    return Err(CommandError::precondition("activation is not enqueueable"));
                }
                if activation_record.runnable_queue.is_some() {
                    return Err(CommandError::precondition("activation already queued"));
                }
                let Some(owner_task) = self.tasks.iter().find(|task| {
                    task.id == activation_record.owner_task
                        && task.generation == activation_record.owner_task_generation
                }) else {
                    return Err(CommandError::precondition(
                        "activation owner task generation is missing",
                    ));
                };
                if owner_task.state == TaskState::Pending {
                    return Err(CommandError::precondition(
                        "pending wait task cannot be enqueued",
                    ));
                }
                if let Some(store) = activation_record.owner_store {
                    let Some(generation) = activation_record.owner_store_generation else {
                        return Err(CommandError::precondition(
                            "activation owner store generation is required",
                        ));
                    };
                    if !self.stores.iter().any(|record| {
                        record.id == store
                            && record.generation == generation
                            && record.state != StoreState::Dead
                    }) {
                        return Err(CommandError::precondition(
                            "dead or missing store activation cannot be enqueued",
                        ));
                    }
                }
                Ok(())
            }
            SemanticCommand::DequeueRunnable { queue, activation } => {
                let Some(queue_record) = self
                    .runnable_queues
                    .iter()
                    .find(|record| record.id == *queue)
                else {
                    return Err(CommandError::precondition("runnable queue is missing"));
                };
                if queue_record.state != RunnableQueueState::Active {
                    return Err(CommandError::precondition("runnable queue is not active"));
                }
                if !queue_record
                    .entries
                    .iter()
                    .any(|entry| entry.activation == *activation)
                {
                    return Err(CommandError::precondition("activation is not queued"));
                }
                Ok(())
            }
            SemanticCommand::CreateActivationContext {
                context,
                activation,
                activation_generation,
            } => {
                if *context == 0 {
                    Err(CommandError::precondition(
                        "activation context id=0 is invalid",
                    ))
                } else if self
                    .activation_contexts
                    .iter()
                    .any(|record| record.id == *context)
                {
                    Err(CommandError::precondition(
                        "activation context already exists",
                    ))
                } else if self.activation_contexts.iter().any(|record| {
                    record.activation == *activation
                        && record.state != ActivationContextState::Dropped
                }) {
                    Err(CommandError::precondition(
                        "activation already has a live context",
                    ))
                } else if self.runtime_activations.iter().any(|record| {
                    record.id == *activation
                        && record.generation == *activation_generation
                        && !matches!(
                            record.state,
                            RuntimeActivationState::Dead | RuntimeActivationState::Exited
                        )
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "activation generation is missing or inactive",
                    ))
                }
            }
            SemanticCommand::CaptureSavedContext {
                saved_context,
                context,
                context_generation,
                pc,
                sp,
                ..
            } => {
                if *saved_context == 0 {
                    Err(CommandError::precondition("saved context id=0 is invalid"))
                } else if *pc == 0 || *sp == 0 {
                    Err(CommandError::precondition(
                        "saved context requires nonzero pc and sp",
                    ))
                } else if self
                    .saved_contexts
                    .iter()
                    .any(|record| record.id == *saved_context)
                {
                    Err(CommandError::precondition("saved context already exists"))
                } else {
                    let Some(context_record) = self.activation_contexts.iter().find(|record| {
                        record.id == *context
                            && record.generation == *context_generation
                            && record.state != ActivationContextState::Dropped
                    }) else {
                        return Err(CommandError::precondition(
                            "activation context generation is missing or dropped",
                        ));
                    };
                    if context_record.current_saved_context.is_some() {
                        Err(CommandError::precondition(
                            "activation context already has saved context",
                        ))
                    } else {
                        Ok(())
                    }
                }
            }
            SemanticCommand::SavePreemptedContext {
                context,
                saved_context,
                preemption,
                preemption_generation,
                pc,
                sp,
                ..
            } => {
                if *context == 0 || *saved_context == 0 {
                    Err(CommandError::precondition(
                        "preempted context requires nonzero context ids",
                    ))
                } else if *pc == 0 || *sp == 0 {
                    Err(CommandError::precondition(
                        "preempted context requires nonzero pc and sp",
                    ))
                } else if self
                    .activation_contexts
                    .iter()
                    .any(|record| record.id == *context)
                {
                    Err(CommandError::precondition(
                        "activation context already exists",
                    ))
                } else if self
                    .saved_contexts
                    .iter()
                    .any(|record| record.id == *saved_context)
                {
                    Err(CommandError::precondition("saved context already exists"))
                } else {
                    let Some(preemption_record) = self.preemptions.iter().find(|record| {
                        record.id == *preemption
                            && record.generation == *preemption_generation
                            && record.state == PreemptionState::Applied
                    }) else {
                        return Err(CommandError::precondition(
                            "preemption generation is missing",
                        ));
                    };
                    let Some(activation) = self.runtime_activations.iter().find(|record| {
                        record.id == preemption_record.activation
                            && record.generation == preemption_record.activation_generation_after
                            && !matches!(
                                record.state,
                                RuntimeActivationState::Dead | RuntimeActivationState::Exited
                            )
                    }) else {
                        return Err(CommandError::precondition(
                            "preempted activation generation is missing or dead",
                        ));
                    };
                    if self.activation_contexts.iter().any(|record| {
                        record.activation == activation.id
                            && record.state != ActivationContextState::Dropped
                    }) {
                        Err(CommandError::precondition(
                            "activation already has live context",
                        ))
                    } else if !self.tasks.iter().any(|task| {
                        task.id == activation.owner_task
                            && task.generation == activation.owner_task_generation
                    }) {
                        Err(CommandError::precondition(
                            "preempted activation owner task generation is missing",
                        ))
                    } else if let Some(store) = activation.owner_store {
                        if let Some(generation) = activation.owner_store_generation {
                            if self.stores.iter().any(|record| {
                                record.id == store
                                    && record.generation == generation
                                    && record.state != StoreState::Dead
                            }) {
                                Ok(())
                            } else {
                                Err(CommandError::precondition(
                                    "preempted activation owner store generation is missing or dead",
                                ))
                            }
                        } else {
                            Err(CommandError::precondition(
                                "preempted activation owner store generation is required",
                            ))
                        }
                    } else {
                        Ok(())
                    }
                }
            }
            SemanticCommand::RecordTimerInterrupt {
                interrupt,
                timer_epoch,
                target_activation,
                target_activation_generation,
                ..
            } => {
                if *interrupt == 0 {
                    Err(CommandError::precondition(
                        "timer interrupt id=0 is invalid",
                    ))
                } else if *timer_epoch == 0 {
                    Err(CommandError::precondition(
                        "timer interrupt epoch=0 is invalid",
                    ))
                } else if self
                    .timer_interrupts
                    .iter()
                    .any(|record| record.id == *interrupt || record.timer_epoch == *timer_epoch)
                {
                    Err(CommandError::precondition("timer interrupt already exists"))
                } else if let Some(previous) = self
                    .timer_interrupts
                    .iter()
                    .map(|record| record.timer_epoch)
                    .max()
                    && *timer_epoch <= previous
                {
                    Err(CommandError::precondition(
                        "timer interrupt epoch must be monotonic",
                    ))
                } else if let Some(activation) = target_activation {
                    let Some(generation) = target_activation_generation else {
                        return Err(CommandError::precondition(
                            "timer interrupt target activation generation is required",
                        ));
                    };
                    if self.runtime_activations.iter().any(|record| {
                        record.id == *activation
                            && record.generation == *generation
                            && !matches!(
                                record.state,
                                RuntimeActivationState::Dead | RuntimeActivationState::Exited
                            )
                    }) {
                        Ok(())
                    } else {
                        Err(CommandError::precondition(
                            "timer interrupt target activation generation is missing or inactive",
                        ))
                    }
                } else if target_activation_generation.is_some() {
                    Err(CommandError::precondition(
                        "timer interrupt target activation is required",
                    ))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::PreemptActivation {
                preemption,
                activation,
                activation_generation,
                timer_interrupt,
                timer_interrupt_generation,
                queue,
                ..
            } => {
                if *preemption == 0 {
                    Err(CommandError::precondition("preemption id=0 is invalid"))
                } else if self
                    .preemptions
                    .iter()
                    .any(|record| record.id == *preemption)
                {
                    Err(CommandError::precondition("preemption already exists"))
                } else if !self
                    .runnable_queues
                    .iter()
                    .any(|record| record.id == *queue && record.state == RunnableQueueState::Active)
                {
                    Err(CommandError::precondition(
                        "preemption queue is missing or inactive",
                    ))
                } else if self.runnable_queues.iter().any(|record| {
                    record
                        .entries
                        .iter()
                        .any(|entry| entry.activation == *activation)
                }) {
                    Err(CommandError::precondition("activation already queued"))
                } else {
                    let Some(timer) = self.timer_interrupts.iter().find(|record| {
                        record.id == *timer_interrupt
                            && record.generation == *timer_interrupt_generation
                    }) else {
                        return Err(CommandError::precondition(
                            "preemption timer interrupt generation is missing",
                        ));
                    };
                    if timer.target_activation != Some(*activation)
                        || timer.target_activation_generation != Some(*activation_generation)
                    {
                        return Err(CommandError::precondition(
                            "preemption timer target does not match activation generation",
                        ));
                    }
                    let Some(record) = self.runtime_activations.iter().find(|record| {
                        record.id == *activation
                            && record.generation == *activation_generation
                            && record.state == RuntimeActivationState::Running
                            && record.runnable_queue.is_none()
                            && record.runnable_queue_generation.is_none()
                    }) else {
                        return Err(CommandError::precondition(
                            "preemption target activation generation is not running",
                        ));
                    };
                    let Some(owner_task) = self.tasks.iter().find(|task| {
                        task.id == record.owner_task
                            && task.generation == record.owner_task_generation
                    }) else {
                        return Err(CommandError::precondition(
                            "preemption owner task generation is missing",
                        ));
                    };
                    if matches!(
                        owner_task.state,
                        TaskState::Pending
                            | TaskState::Cancelled
                            | TaskState::Faulted
                            | TaskState::Exited
                    ) {
                        return Err(CommandError::precondition(
                            "preemption owner task is not runnable",
                        ));
                    }
                    if let Some(store) = record.owner_store {
                        let Some(generation) = record.owner_store_generation else {
                            return Err(CommandError::precondition(
                                "preemption owner store generation is required",
                            ));
                        };
                        if !self.stores.iter().any(|store_record| {
                            store_record.id == store
                                && store_record.generation == generation
                                && store_record.state != StoreState::Dead
                        }) {
                            return Err(CommandError::precondition(
                                "preemption owner store generation is missing or dead",
                            ));
                        }
                    }
                    Ok(())
                }
            }
            SemanticCommand::RecordSchedulerDecision {
                decision,
                queue,
                queue_generation,
                selected_activation,
                selected_activation_generation,
                reason,
                ..
            } => {
                if *decision == 0 {
                    Err(CommandError::precondition(
                        "scheduler decision id=0 is invalid",
                    ))
                } else if reason.is_empty() {
                    Err(CommandError::precondition(
                        "scheduler decision reason is empty",
                    ))
                } else if self
                    .scheduler_decisions
                    .iter()
                    .any(|record| record.id == *decision)
                {
                    Err(CommandError::precondition(
                        "scheduler decision already exists",
                    ))
                } else {
                    let Some(queue_record) = self.runnable_queues.iter().find(|record| {
                        record.id == *queue
                            && record.generation == *queue_generation
                            && record.state == RunnableQueueState::Active
                    }) else {
                        return Err(CommandError::precondition(
                            "scheduler decision queue generation is missing or inactive",
                        ));
                    };
                    if !queue_record.entries.iter().any(|entry| {
                        entry.activation == *selected_activation
                            && entry.activation_generation == *selected_activation_generation
                    }) {
                        return Err(CommandError::precondition(
                            "scheduler decision activation is not queued",
                        ));
                    }
                    let Some(activation) = self.runtime_activations.iter().find(|record| {
                        record.id == *selected_activation
                            && record.generation == *selected_activation_generation
                            && record.state == RuntimeActivationState::Runnable
                            && record.runnable_queue == Some(*queue)
                            && record.runnable_queue_generation == Some(*queue_generation)
                    }) else {
                        return Err(CommandError::precondition(
                            "scheduler decision activation generation is not runnable",
                        ));
                    };
                    if self.tasks.iter().any(|task| {
                        task.id == activation.owner_task
                            && task.generation == activation.owner_task_generation
                    }) {
                        Ok(())
                    } else {
                        Err(CommandError::precondition(
                            "scheduler decision owner task generation is missing",
                        ))
                    }
                }
            }
            SemanticCommand::ResumeActivation {
                resume,
                scheduler_decision,
                scheduler_decision_generation,
                activation,
                activation_generation,
                ..
            } => {
                if *resume == 0 {
                    Err(CommandError::precondition(
                        "activation resume id=0 is invalid",
                    ))
                } else if self
                    .activation_resumes
                    .iter()
                    .any(|record| record.id == *resume)
                {
                    Err(CommandError::precondition(
                        "activation resume already exists",
                    ))
                } else {
                    let Some(decision) = self.scheduler_decisions.iter().find(|record| {
                        record.id == *scheduler_decision
                            && record.generation == *scheduler_decision_generation
                            && record.state == SchedulerDecisionState::Recorded
                            && record.selected_activation == *activation
                            && record.selected_activation_generation == *activation_generation
                    }) else {
                        return Err(CommandError::precondition(
                            "resume scheduler decision generation is missing or consumed",
                        ));
                    };
                    let Some(queue) = self.runnable_queues.iter().find(|record| {
                        record.id == decision.queue
                            && record.generation == decision.queue_generation
                            && record.state == RunnableQueueState::Active
                    }) else {
                        return Err(CommandError::precondition(
                            "resume queue generation is missing or inactive",
                        ));
                    };
                    if !queue.entries.iter().any(|entry| {
                        entry.activation == *activation
                            && entry.activation_generation == *activation_generation
                    }) {
                        return Err(CommandError::precondition(
                            "resume activation is not queued",
                        ));
                    }
                    let Some(record) = self.runtime_activations.iter().find(|record| {
                        record.id == *activation
                            && record.generation == *activation_generation
                            && record.state == RuntimeActivationState::Runnable
                            && record.runnable_queue == Some(decision.queue)
                            && record.runnable_queue_generation == Some(decision.queue_generation)
                    }) else {
                        return Err(CommandError::precondition(
                            "resume activation generation is not runnable",
                        ));
                    };
                    if !self.tasks.iter().any(|task| {
                        task.id == record.owner_task
                            && task.generation == record.owner_task_generation
                            && matches!(task.state, TaskState::Runnable | TaskState::Running)
                    }) {
                        return Err(CommandError::precondition(
                            "resume owner task generation is missing or not runnable",
                        ));
                    }
                    if let Some(store) = record.owner_store {
                        let Some(generation) = record.owner_store_generation else {
                            return Err(CommandError::precondition(
                                "resume owner store generation is required",
                            ));
                        };
                        if !self.stores.iter().any(|store_record| {
                            store_record.id == store
                                && store_record.generation == generation
                                && store_record.state != StoreState::Dead
                        }) {
                            return Err(CommandError::precondition(
                                "resume owner store generation is missing or dead",
                            ));
                        }
                    }
                    if let Some(code) = record.code_object
                        && (code.kind != ContractObjectKind::CodeObject || code.generation == 0)
                    {
                        return Err(CommandError::precondition(
                            "resume code object reference is invalid",
                        ));
                    }
                    if let Some(context) = self.activation_contexts.iter().find(|context| {
                        context.activation == *activation
                            && context.activation_generation == *activation_generation
                            && context.state != ActivationContextState::Dropped
                    }) {
                        if context.state != ActivationContextState::Saved {
                            return Err(CommandError::precondition(
                                "resume activation context is not saved",
                            ));
                        }
                        match (
                            context.current_saved_context,
                            context.current_saved_context_generation,
                        ) {
                            (Some(saved), Some(saved_generation)) => {
                                if !self.saved_contexts.iter().any(|saved_record| {
                                    saved_record.id == saved
                                        && saved_record.generation == saved_generation
                                        && saved_record.context == context.id
                                        && saved_record.context_generation == context.generation
                                        && saved_record.activation == *activation
                                        && saved_record.activation_generation
                                            == *activation_generation
                                        && saved_record.state == SavedContextState::Captured
                                }) {
                                    return Err(CommandError::precondition(
                                        "resume saved context generation is missing",
                                    ));
                                }
                            }
                            (None, None) => {}
                            _ => {
                                return Err(CommandError::precondition(
                                    "resume saved context generation is required",
                                ));
                            }
                        }
                    }
                    Ok(())
                }
            }
            SemanticCommand::RecordPreemptionLatencySample {
                sample,
                timer_interrupt,
                timer_interrupt_generation,
                preemption,
                preemption_generation,
                scheduler_decision,
                scheduler_decision_generation,
                activation_resume,
                activation_resume_generation,
                measured_nanos,
                budget_nanos,
                ..
            } => self
                .validate_preemption_latency_sample(
                    *sample,
                    *timer_interrupt,
                    *timer_interrupt_generation,
                    *preemption,
                    *preemption_generation,
                    *scheduler_decision,
                    *scheduler_decision_generation,
                    *activation_resume,
                    *activation_resume_generation,
                    *measured_nanos,
                    *budget_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::BlockActivationOnWait {
                activation_wait,
                activation,
                activation_generation,
                wait,
                blockers,
                deadline,
                ..
            } => {
                if *activation_wait == 0 {
                    Err(CommandError::precondition(
                        "activation wait id=0 is invalid",
                    ))
                } else if *wait == 0 {
                    Err(CommandError::precondition("wait id=0 is invalid"))
                } else if blockers.is_empty() && deadline.is_none() {
                    Err(CommandError::precondition(
                        "activation wait requires blocker or deadline",
                    ))
                } else if self
                    .activation_waits
                    .iter()
                    .any(|record| record.id == *activation_wait)
                {
                    Err(CommandError::precondition("activation wait already exists"))
                } else if self.waits.iter().any(|record| record.id == *wait) {
                    Err(CommandError::precondition("wait already exists"))
                } else {
                    let Some(record) = self.runtime_activations.iter().find(|record| {
                        record.id == *activation
                            && record.generation == *activation_generation
                            && record.state == RuntimeActivationState::Running
                            && record.runnable_queue.is_none()
                            && record.runnable_queue_generation.is_none()
                    }) else {
                        return Err(CommandError::precondition(
                            "activation wait target generation is not running",
                        ));
                    };
                    if !self.tasks.iter().any(|task| {
                        task.id == record.owner_task
                            && task.generation == record.owner_task_generation
                            && matches!(task.state, TaskState::Runnable | TaskState::Running)
                    }) {
                        return Err(CommandError::precondition(
                            "activation wait owner task generation is missing or not runnable",
                        ));
                    }
                    if let Some(store) = record.owner_store {
                        let Some(generation) = record.owner_store_generation else {
                            return Err(CommandError::precondition(
                                "activation wait owner store generation is required",
                            ));
                        };
                        if !self.stores.iter().any(|store_record| {
                            store_record.id == store
                                && store_record.generation == generation
                                && store_record.state != StoreState::Dead
                        }) {
                            return Err(CommandError::precondition(
                                "activation wait owner store generation is missing or dead",
                            ));
                        }
                    }
                    Ok(())
                }
            }
            SemanticCommand::CancelActivationWait {
                activation_wait,
                activation_wait_generation,
                wait_generation,
                ..
            } => {
                let Some(record) = self.activation_waits.iter().find(|record| {
                    record.id == *activation_wait
                        && record.generation == *activation_wait_generation
                        && record.wait_generation == *wait_generation
                        && record.state == ActivationWaitState::Pending
                }) else {
                    return Err(CommandError::precondition(
                        "activation wait generation is missing or not pending",
                    ));
                };
                if self.waits.iter().any(|wait| {
                    wait.id == record.wait
                        && wait.generation == *wait_generation
                        && wait.state == WaitState::Pending
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "activation wait token generation is missing or not pending",
                    ))
                }
            }
            SemanticCommand::CleanupActivationForStoreFault {
                cleanup,
                store,
                store_generation,
                activation,
                activation_generation,
                wait,
                wait_generation,
                reason,
                ..
            } => {
                if *cleanup == 0 {
                    return Err(CommandError::precondition(
                        "activation cleanup id=0 is invalid",
                    ));
                }
                if reason.is_empty() {
                    return Err(CommandError::precondition(
                        "activation cleanup reason is empty",
                    ));
                }
                if self
                    .activation_cleanups
                    .iter()
                    .any(|record| record.id == *cleanup)
                {
                    return Err(CommandError::precondition(
                        "activation cleanup already exists",
                    ));
                }
                if !self.stores.iter().any(|record| {
                    record.id == *store
                        && record.generation == *store_generation
                        && record.state != StoreState::Dead
                }) {
                    return Err(CommandError::precondition(
                        "cleanup target store generation is missing or dead",
                    ));
                }
                if !self.runtime_activations.iter().any(|record| {
                    record.id == *activation
                        && record.generation == *activation_generation
                        && record.owner_store == Some(*store)
                        && record.owner_store_generation == Some(*store_generation)
                        && !matches!(
                            record.state,
                            RuntimeActivationState::Dead | RuntimeActivationState::Exited
                        )
                }) {
                    return Err(CommandError::precondition(
                        "cleanup target activation generation is missing or not store-owned",
                    ));
                }
                match (*wait, *wait_generation) {
                    (Some(wait), Some(generation)) => {
                        if self.waits.iter().any(|record| {
                            record.id == wait
                                && record.generation == generation
                                && record.state == WaitState::Pending
                                && record.owner_store == Some(*store)
                                && record.owner_store_generation == Some(*store_generation)
                        }) {
                            Ok(())
                        } else {
                            Err(CommandError::precondition(
                                "cleanup wait generation is missing or not pending",
                            ))
                        }
                    }
                    (Some(_), None) | (None, Some(_)) => Err(CommandError::precondition(
                        "cleanup wait and wait generation must be paired",
                    )),
                    (None, None) => Ok(()),
                }
            }
            SemanticCommand::GrantCapability { operations, .. } if operations.is_empty() => Err(
                CommandError::precondition("grant-capability requires at least one operation"),
            ),
            SemanticCommand::GrantCapability {
                owner_store: Some(store),
                owner_store_generation,
                ..
            } => {
                if let Some(generation) = owner_store_generation {
                    if self
                        .stores
                        .iter()
                        .any(|record| record.id == *store && record.generation == *generation)
                    {
                        Ok(())
                    } else {
                        Err(CommandError::precondition(
                            "owner store generation is missing",
                        ))
                    }
                } else {
                    Err(CommandError::precondition(
                        "owner store generation is required",
                    ))
                }
            }
            SemanticCommand::RevokeCapability { cap } => {
                if self
                    .capabilities
                    .records()
                    .iter()
                    .any(|record| record.id == *cap)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("capability does not exist"))
                }
            }
            SemanticCommand::CreateWait {
                owner_task,
                owner_store,
                owner_store_generation,
                blockers,
                deadline,
                ..
            } => {
                if owner_task.is_none() && owner_store.is_none() {
                    Err(CommandError::precondition(
                        "create-wait requires owner task or owner store",
                    ))
                } else if blockers.is_empty() && deadline.is_none() {
                    Err(CommandError::precondition(
                        "create-wait requires blocker or deadline",
                    ))
                } else {
                    if let Some(task) = owner_task
                        && !self.tasks.iter().any(|record| record.id == *task)
                    {
                        return Err(CommandError::precondition("owner task is missing"));
                    }
                    if let Some(store) = owner_store {
                        if let Some(generation) = owner_store_generation {
                            if self.stores.iter().any(|record| {
                                record.id == *store && record.generation == *generation
                            }) {
                                Ok(())
                            } else {
                                Err(CommandError::precondition(
                                    "owner store generation is missing",
                                ))
                            }
                        } else {
                            Err(CommandError::precondition(
                                "owner store generation is required",
                            ))
                        }
                    } else {
                        Ok(())
                    }
                }
            }
            SemanticCommand::ResolveWait { wait, .. }
            | SemanticCommand::CancelWait { wait, .. } => {
                if self
                    .waits
                    .iter()
                    .any(|record| record.id == *wait && record.state == WaitState::Pending)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("wait is not pending"))
                }
            }
            SemanticCommand::BeginCleanup {
                cleanup,
                store,
                generation,
                ..
            } => {
                if self.transactions.iter().any(|record| record.id == *cleanup) {
                    Err(CommandError::precondition(
                        "cleanup transaction id already exists",
                    ))
                } else if self
                    .stores
                    .iter()
                    .any(|record| record.id == *store && record.generation == *generation)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "cleanup target store generation is missing",
                    ))
                }
            }
            SemanticCommand::ApplyCleanupStep { cleanup, .. }
            | SemanticCommand::CommitCleanup { cleanup } => {
                if self
                    .transactions
                    .iter()
                    .any(|record| record.id == *cleanup && record.state == TransactionState::Begun)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "cleanup transaction is not active",
                    ))
                }
            }
            SemanticCommand::GrantCapability { .. } | SemanticCommand::RecordTrap { .. } => Ok(()),
        }
    }

    fn apply_prechecked_command(&mut self, command: SemanticCommand) -> bool {
        match command {
            SemanticCommand::CreateRuntimeActivation {
                activation,
                owner_task,
                owner_task_generation,
                owner_store,
                owner_store_generation,
                code_object,
            } => self.create_runtime_activation_with_id(
                activation,
                owner_task,
                owner_task_generation,
                owner_store,
                owner_store_generation,
                code_object,
            ),
            SemanticCommand::CreateRunnableQueue { queue, label } => {
                self.create_runnable_queue_with_id(queue, &label)
            }
            SemanticCommand::EnqueueRunnable {
                queue,
                activation,
                activation_generation,
            } => self.enqueue_runnable_activation(queue, activation, activation_generation),
            SemanticCommand::DequeueRunnable { queue, activation } => {
                self.dequeue_runnable_activation(queue, activation)
            }
            SemanticCommand::CreateActivationContext {
                context,
                activation,
                activation_generation,
            } => self.create_activation_context_with_id(context, activation, activation_generation),
            SemanticCommand::CaptureSavedContext {
                saved_context,
                context,
                context_generation,
                reason,
                pc,
                sp,
                flags,
                note,
            } => self.capture_saved_context_with_id(
                saved_context,
                context,
                context_generation,
                reason,
                pc,
                sp,
                flags,
                &note,
            ),
            SemanticCommand::SavePreemptedContext {
                context,
                saved_context,
                preemption,
                preemption_generation,
                pc,
                sp,
                flags,
                note,
            } => self.save_preempted_context_with_ids(
                context,
                saved_context,
                preemption,
                preemption_generation,
                pc,
                sp,
                flags,
                &note,
            ),
            SemanticCommand::RecordTimerInterrupt {
                interrupt,
                timer_epoch,
                hart,
                target_activation,
                target_activation_generation,
                note,
            } => self.record_timer_interrupt_with_id(
                interrupt,
                timer_epoch,
                hart,
                target_activation,
                target_activation_generation,
                &note,
            ),
            SemanticCommand::PreemptActivation {
                preemption,
                activation,
                activation_generation,
                timer_interrupt,
                timer_interrupt_generation,
                queue,
                note,
            } => self.preempt_running_activation_with_id(
                preemption,
                activation,
                activation_generation,
                timer_interrupt,
                timer_interrupt_generation,
                queue,
                &note,
            ),
            SemanticCommand::RecordSchedulerDecision {
                decision,
                queue,
                queue_generation,
                selected_activation,
                selected_activation_generation,
                reason,
                note,
            } => self.record_scheduler_decision_with_id(
                decision,
                queue,
                queue_generation,
                selected_activation,
                selected_activation_generation,
                &reason,
                &note,
            ),
            SemanticCommand::ResumeActivation {
                resume,
                scheduler_decision,
                scheduler_decision_generation,
                activation,
                activation_generation,
                note,
            } => self.resume_activation_with_id(
                resume,
                scheduler_decision,
                scheduler_decision_generation,
                activation,
                activation_generation,
                &note,
            ),
            SemanticCommand::RecordPreemptionLatencySample {
                sample,
                timer_interrupt,
                timer_interrupt_generation,
                preemption,
                preemption_generation,
                scheduler_decision,
                scheduler_decision_generation,
                activation_resume,
                activation_resume_generation,
                measured_nanos,
                budget_nanos,
                note,
            } => self.record_preemption_latency_sample_with_id(
                sample,
                timer_interrupt,
                timer_interrupt_generation,
                preemption,
                preemption_generation,
                scheduler_decision,
                scheduler_decision_generation,
                activation_resume,
                activation_resume_generation,
                measured_nanos,
                budget_nanos,
                &note,
            ),
            SemanticCommand::BlockActivationOnWait {
                activation_wait,
                activation,
                activation_generation,
                wait,
                kind,
                blockers,
                deadline,
                restart_policy,
                note,
            } => self.block_activation_on_wait_with_id(
                activation_wait,
                activation,
                activation_generation,
                wait,
                kind,
                blockers,
                deadline,
                restart_policy,
                &note,
            ),
            SemanticCommand::CancelActivationWait {
                activation_wait,
                activation_wait_generation,
                wait_generation,
                errno,
                reason,
                note,
            } => self.cancel_activation_wait(
                activation_wait,
                activation_wait_generation,
                wait_generation,
                errno,
                reason,
                &note,
            ),
            SemanticCommand::CleanupActivationForStoreFault {
                cleanup,
                store,
                store_generation,
                activation,
                activation_generation,
                wait,
                wait_generation,
                reason,
                note,
            } => self.cleanup_activation_for_store_fault_with_id(
                cleanup,
                store,
                store_generation,
                activation,
                activation_generation,
                wait,
                wait_generation,
                &reason,
                &note,
            ),
            SemanticCommand::GrantCapability {
                subject,
                debug_object_label,
                object_ref,
                operations,
                lifetime,
                owner_store,
                owner_store_generation,
                owner_task,
                source,
                manifest_decl,
            } => {
                let operations = operations.iter().map(String::as_str).collect::<Vec<_>>();
                let cap = self.capabilities.grant_with_authority_ref(
                    &subject,
                    &debug_object_label,
                    object_ref,
                    &operations,
                    &lifetime,
                    owner_store,
                    owner_store_generation,
                    owner_task,
                    &source,
                    manifest_decl,
                );
                let Ok(cap) = cap else {
                    return false;
                };
                self.event_log
                    .push("command", EventKind::CapabilityGranted { cap });
                true
            }
            SemanticCommand::RevokeCapability { cap } => {
                let changed = self.capabilities.revoke(cap);
                if changed {
                    self.event_log
                        .push("command", EventKind::CapabilityRevoked { cap });
                }
                changed
            }
            SemanticCommand::CreateWait {
                wait,
                owner_task,
                owner_store,
                owner_store_generation,
                kind,
                generation,
                blockers,
                deadline,
                restart_policy,
                saved_context,
            } => {
                self.record_wait_created_with_details(
                    wait,
                    owner_task,
                    owner_store,
                    owner_store_generation,
                    kind,
                    generation,
                    blockers,
                    deadline,
                    restart_policy,
                    saved_context,
                );
                true
            }
            SemanticCommand::ResolveWait { wait, reason } => {
                self.record_wait_resolved(wait, &reason);
                true
            }
            SemanticCommand::CancelWait {
                wait,
                errno,
                reason,
            } => {
                self.record_wait_cancelled_with_reason(wait, errno, reason);
                true
            }
            SemanticCommand::RecordTrap {
                store,
                task,
                trap,
                detail,
            } => {
                self.event_log.push(
                    "command",
                    EventKind::FaultClassified {
                        trap,
                        class: trap.fault_class(),
                        store,
                        task,
                        detail,
                    },
                );
                true
            }
            SemanticCommand::BeginCleanup {
                cleanup,
                store,
                generation,
                reason,
            } => {
                self.next_transaction_id = self.next_transaction_id.max(cleanup + 1);
                self.transactions.push(SemanticTransactionRecord {
                    id: cleanup,
                    label: format!("cleanup:{reason}"),
                    store: Some(store),
                    task: None,
                    state: TransactionState::Begun,
                    generation,
                });
                self.event_log.push(
                    "command",
                    EventKind::TransactionBegan {
                        transaction: cleanup,
                        store: Some(store),
                        task: None,
                        label: format!("cleanup:{reason}"),
                    },
                );
                true
            }
            SemanticCommand::ApplyCleanupStep {
                cleanup,
                step,
                target,
                observed_generation,
            } => {
                self.event_log.push(
                    "command",
                    EventKind::CleanupStepApplied {
                        cleanup,
                        step: step.as_str().to_string(),
                        target: target.summary(),
                        observed_generation,
                    },
                );
                true
            }
            SemanticCommand::CommitCleanup { cleanup } => {
                let before = self.event_count();
                self.commit_transaction(cleanup);
                self.event_count() != before
            }
        }
    }
}

fn rejected_command_result(
    command_id: CommandId,
    issuer: String,
    command: &'static str,
    detail: &str,
) -> CommandResult {
    CommandResult {
        command_id,
        issuer,
        command,
        status: CommandStatus::Rejected,
        events: Vec::new(),
        effects: Vec::new(),
        violations: {
            let mut violations = Vec::new();
            violations.push(detail.to_string());
            violations
        },
    }
}

fn event_refs_between(before: usize, after: usize) -> Vec<EventId> {
    ((before + 1)..=after)
        .map(|event| event as EventId)
        .collect()
}

fn command_effects(outcome: &CommandOutcome) -> Vec<CommandEffect> {
    if !outcome.changed {
        return Vec::new();
    }
    let mut effects = Vec::new();
    effects.push(CommandEffect::new(outcome.command, None));
    effects
}
