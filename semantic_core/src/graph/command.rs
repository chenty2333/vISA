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
    RecordTimerInterrupt {
        interrupt: TimerInterruptId,
        timer_epoch: u64,
        hart: u32,
        target_activation: Option<ActivationId>,
        target_activation_generation: Option<Generation>,
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
            Self::RecordTimerInterrupt { .. } => "record-timer-interrupt",
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
                } else if let Some(store) = owner_store {
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
                } else {
                    Ok(())
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
