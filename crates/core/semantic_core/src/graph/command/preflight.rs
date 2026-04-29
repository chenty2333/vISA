use super::*;

impl SemanticGraph {
    pub(super) fn preflight_command(&self, command: &SemanticCommand) -> Result<(), CommandError> {
        match command {
            SemanticCommand::RegisterHart { hart, hardware_id, label, boot, .. } => {
                if *hart == 0 {
                    Err(CommandError::precondition("hart id=0 is invalid"))
                } else if label.is_empty() {
                    Err(CommandError::precondition("hart label is empty"))
                } else if self.harts.iter().any(|record| record.id == *hart) {
                    Err(CommandError::precondition("hart already exists"))
                } else if self.harts.iter().any(|record| record.hardware_id == *hardware_id) {
                    Err(CommandError::precondition("hardware hart already exists"))
                } else if *boot && self.harts.iter().any(|record| record.boot) {
                    Err(CommandError::precondition("boot hart already exists"))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::SetHartState { hart, hart_generation, reason, .. } => {
                if reason.is_empty() {
                    Err(CommandError::precondition("hart state reason is empty"))
                } else if self
                    .harts
                    .iter()
                    .any(|record| record.id == *hart && record.generation == *hart_generation)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("hart generation is missing"))
                }
            }
            SemanticCommand::BindHartCurrentActivation {
                hart,
                hart_generation,
                activation,
                activation_generation,
                ..
            } => {
                let Some(hart_record) = self
                    .harts
                    .iter()
                    .find(|record| record.id == *hart && record.generation == *hart_generation)
                else {
                    return Err(CommandError::precondition("hart generation is missing"));
                };
                if hart_record.state != HartState::Idle {
                    return Err(CommandError::precondition("hart is not idle"));
                }
                if hart_record.current_activation.is_some() {
                    return Err(CommandError::precondition("hart already has current activation"));
                }
                if self.harts.iter().any(|record| {
                    record.id != *hart
                        && record.current_activation == Some(*activation)
                        && record.current_activation_generation == Some(*activation_generation)
                }) {
                    return Err(CommandError::precondition(
                        "activation is already current on another hart",
                    ));
                }
                let Some(activation_record) = self.runtime_activations.iter().find(|record| {
                    record.id == *activation
                        && record.generation == *activation_generation
                        && record.state == RuntimeActivationState::Running
                }) else {
                    return Err(CommandError::precondition(
                        "current activation generation is missing or not running",
                    ));
                };
                if !self.tasks.iter().any(|task| {
                    task.id == activation_record.owner_task
                        && task.generation == activation_record.owner_task_generation
                }) {
                    return Err(CommandError::precondition(
                        "current activation owner task generation is missing",
                    ));
                }
                if let Some(store) = activation_record.owner_store {
                    let Some(generation) = activation_record.owner_store_generation else {
                        return Err(CommandError::precondition(
                            "current activation owner store generation is required",
                        ));
                    };
                    if !self.stores.iter().any(|store_record| {
                        store_record.id == store
                            && store_record.generation == generation
                            && store_record.state != StoreState::Dead
                    }) {
                        return Err(CommandError::precondition(
                            "current activation owner store generation is missing or dead",
                        ));
                    }
                }
                Ok(())
            }
            SemanticCommand::ClearHartCurrentActivation {
                hart,
                hart_generation,
                activation,
                activation_generation,
                reason,
                ..
            } => {
                if reason.is_empty() {
                    return Err(CommandError::precondition(
                        "clear hart current activation reason is empty",
                    ));
                }
                let Some(hart_record) = self
                    .harts
                    .iter()
                    .find(|record| record.id == *hart && record.generation == *hart_generation)
                else {
                    return Err(CommandError::precondition("hart generation is missing"));
                };
                if hart_record.current_activation == Some(*activation)
                    && hart_record.current_activation_generation == Some(*activation_generation)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("hart current activation generation mismatch"))
                }
            }
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
                } else if self.runtime_activations.iter().any(|record| record.id == *activation) {
                    Err(CommandError::precondition("activation already exists"))
                } else if !self
                    .tasks
                    .iter()
                    .any(|task| task.id == *owner_task && task.generation == *owner_task_generation)
                {
                    Err(CommandError::precondition("activation owner task generation is missing"))
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
                } else if self.runnable_queues.iter().any(|record| record.id == *queue) {
                    Err(CommandError::precondition("runnable queue already exists"))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::BindRunnableQueueOwner {
                queue,
                queue_generation,
                hart,
                hart_generation,
                ..
            } => {
                let Some(queue_record) = self.runnable_queues.iter().find(|record| {
                    record.id == *queue
                        && record.generation == *queue_generation
                        && record.state == RunnableQueueState::Active
                }) else {
                    return Err(CommandError::precondition(
                        "runnable queue generation is missing or inactive",
                    ));
                };
                if queue_record.owner_hart == Some(*hart)
                    && queue_record.owner_hart_generation == Some(*hart_generation)
                {
                    return Err(CommandError::precondition(
                        "runnable queue owner is already bound",
                    ));
                }
                if !queue_record.entries.is_empty() {
                    return Err(CommandError::precondition(
                        "runnable queue owner cannot change while entries are live",
                    ));
                }
                let Some(_hart_record) = self.harts.iter().find(|record| {
                    record.id == *hart
                        && record.generation == *hart_generation
                        && !matches!(record.state, HartState::Offline | HartState::Faulted)
                }) else {
                    return Err(CommandError::precondition(
                        "runnable queue owner hart generation is missing or unavailable",
                    ));
                };
                Ok(())
            }
            SemanticCommand::EnqueueRunnable { queue, activation, activation_generation } => {
                let Some(queue_record) =
                    self.runnable_queues.iter().find(|record| record.id == *queue)
                else {
                    return Err(CommandError::precondition("runnable queue is missing"));
                };
                if queue_record.state != RunnableQueueState::Active {
                    return Err(CommandError::precondition("runnable queue is not active"));
                }
                if self.runnable_queues.iter().any(|record| {
                    record.entries.iter().any(|entry| entry.activation == *activation)
                }) {
                    return Err(CommandError::precondition("activation already queued"));
                }
                let Some(activation_record) =
                    self.runtime_activations.iter().find(|record| record.id == *activation)
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
                    return Err(CommandError::precondition("pending wait task cannot be enqueued"));
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
                let Some(queue_record) =
                    self.runnable_queues.iter().find(|record| record.id == *queue)
                else {
                    return Err(CommandError::precondition("runnable queue is missing"));
                };
                if queue_record.state != RunnableQueueState::Active {
                    return Err(CommandError::precondition("runnable queue is not active"));
                }
                if !queue_record.entries.iter().any(|entry| entry.activation == *activation) {
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
                    Err(CommandError::precondition("activation context id=0 is invalid"))
                } else if self.activation_contexts.iter().any(|record| record.id == *context) {
                    Err(CommandError::precondition("activation context already exists"))
                } else if self.activation_contexts.iter().any(|record| {
                    record.activation == *activation
                        && record.state != ActivationContextState::Dropped
                }) {
                    Err(CommandError::precondition("activation already has a live context"))
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
                    Err(CommandError::precondition("activation generation is missing or inactive"))
                }
            }
            SemanticCommand::UpdateActivationContextVectorState {
                context,
                context_generation,
                vector_state,
                vector_status,
                ..
            } => self
                .validate_activation_context_vector_state(
                    *context,
                    *context_generation,
                    *vector_state,
                    *vector_status,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::EnableLazyVectorState {
                context,
                context_generation,
                vector_state,
                ..
            } => self
                .validate_lazy_vector_state_enable(*context, *context_generation, *vector_state)
                .map_err(CommandError::precondition),
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
                    Err(CommandError::precondition("saved context requires nonzero pc and sp"))
                } else if self.saved_contexts.iter().any(|record| record.id == *saved_context) {
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
                    Err(CommandError::precondition("preempted context requires nonzero pc and sp"))
                } else if self.activation_contexts.iter().any(|record| record.id == *context) {
                    Err(CommandError::precondition("activation context already exists"))
                } else if self.saved_contexts.iter().any(|record| record.id == *saved_context) {
                    Err(CommandError::precondition("saved context already exists"))
                } else {
                    let Some(preemption_record) = self.preemptions.iter().find(|record| {
                        record.id == *preemption
                            && record.generation == *preemption_generation
                            && record.state == PreemptionState::Applied
                    }) else {
                        return Err(CommandError::precondition("preemption generation is missing"));
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
                        Err(CommandError::precondition("activation already has live context"))
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
            SemanticCommand::SaveDirtyVectorStateOnPreempt {
                context,
                context_generation,
                saved_context,
                saved_context_generation,
                preemption,
                preemption_generation,
                vector_state,
                ..
            } => self
                .validate_dirty_vector_state_preempt_save(
                    *context,
                    *context_generation,
                    *saved_context,
                    *saved_context_generation,
                    *preemption,
                    *preemption_generation,
                    *vector_state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordTimerInterrupt {
                interrupt,
                timer_epoch,
                hart,
                hart_generation,
                target_activation,
                target_activation_generation,
                ..
            } => {
                if *interrupt == 0 {
                    Err(CommandError::precondition("timer interrupt id=0 is invalid"))
                } else if *timer_epoch == 0 {
                    Err(CommandError::precondition("timer interrupt epoch=0 is invalid"))
                } else if self
                    .timer_interrupts
                    .iter()
                    .any(|record| record.id == *interrupt || record.timer_epoch == *timer_epoch)
                {
                    Err(CommandError::precondition("timer interrupt already exists"))
                } else if let Some(previous) =
                    self.timer_interrupts.iter().map(|record| record.timer_epoch).max()
                    && *timer_epoch <= previous
                {
                    Err(CommandError::precondition("timer interrupt epoch must be monotonic"))
                } else if !self.harts.iter().any(|record| {
                    record.id == *hart
                        && record.generation == *hart_generation
                        && !matches!(record.state, HartState::Offline | HartState::Faulted)
                }) {
                    Err(CommandError::precondition(
                        "timer interrupt hart generation is missing or inactive",
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
                    Err(CommandError::precondition("timer interrupt target activation is required"))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::RecordIpiEvent {
                ipi,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                reason,
                ..
            } => {
                if *ipi == 0 {
                    Err(CommandError::precondition("ipi event id=0 is invalid"))
                } else if reason.is_empty() {
                    Err(CommandError::precondition("ipi event reason is empty"))
                } else if source_hart == target_hart {
                    Err(CommandError::precondition("ipi source and target harts must differ"))
                } else if self.ipi_events.iter().any(|record| record.id == *ipi) {
                    Err(CommandError::precondition("ipi event already exists"))
                } else if !self.harts.iter().any(|record| {
                    record.id == *source_hart
                        && record.generation == *source_hart_generation
                        && !matches!(record.state, HartState::Offline | HartState::Faulted)
                }) {
                    Err(CommandError::precondition(
                        "ipi source hart generation is missing or inactive",
                    ))
                } else if !self.harts.iter().any(|record| {
                    record.id == *target_hart
                        && record.generation == *target_hart_generation
                        && !matches!(record.state, HartState::Offline | HartState::Faulted)
                }) {
                    Err(CommandError::precondition(
                        "ipi target hart generation is missing or inactive",
                    ))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::RemotePreemptActivation {
                remote_preempt,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                activation,
                activation_generation,
                queue,
                ..
            } => self
                .validate_remote_preempt_activation(
                    *remote_preempt,
                    *ipi,
                    *ipi_generation,
                    *source_hart,
                    *source_hart_generation,
                    *target_hart,
                    *target_hart_generation,
                    *activation,
                    *activation_generation,
                    *queue,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RemoteParkHart {
                remote_park,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                ..
            } => self
                .validate_remote_park_hart(
                    *remote_park,
                    *ipi,
                    *ipi_generation,
                    *source_hart,
                    *source_hart_generation,
                    *target_hart,
                    *target_hart_generation,
                )
                .map_err(CommandError::precondition),
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
                } else if self.preemptions.iter().any(|record| record.id == *preemption) {
                    Err(CommandError::precondition("preemption already exists"))
                } else if !self
                    .runnable_queues
                    .iter()
                    .any(|record| record.id == *queue && record.state == RunnableQueueState::Active)
                {
                    Err(CommandError::precondition("preemption queue is missing or inactive"))
                } else if self.runnable_queues.iter().any(|record| {
                    record.entries.iter().any(|entry| entry.activation == *activation)
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
                    Err(CommandError::precondition("scheduler decision id=0 is invalid"))
                } else if reason.is_empty() {
                    Err(CommandError::precondition("scheduler decision reason is empty"))
                } else if self.scheduler_decisions.iter().any(|record| record.id == *decision) {
                    Err(CommandError::precondition("scheduler decision already exists"))
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
            SemanticCommand::RecordCrossHartSchedulerDecision {
                cross_decision,
                scheduler_decision,
                scheduler_decision_generation,
                deciding_hart,
                deciding_hart_generation,
                target_hart,
                target_hart_generation,
                reason,
                ..
            } => self
                .validate_cross_hart_scheduler_decision(
                    *cross_decision,
                    *scheduler_decision,
                    *scheduler_decision_generation,
                    *deciding_hart,
                    *deciding_hart_generation,
                    *target_hart,
                    *target_hart_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::MigrateRunnableActivation {
                migration,
                activation,
                activation_generation,
                source_queue,
                source_queue_generation,
                target_queue,
                target_queue_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                reason,
                ..
            } => self
                .validate_runnable_activation_migration(
                    *migration,
                    *activation,
                    *activation_generation,
                    *source_queue,
                    *source_queue_generation,
                    *target_queue,
                    *target_queue_generation,
                    *source_hart,
                    *source_hart_generation,
                    *target_hart,
                    *target_hart_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSmpSafePoint {
                safe_point,
                coordinator_hart,
                coordinator_hart_generation,
                participants,
                reason,
                ..
            } => self
                .validate_smp_safe_point(
                    *safe_point,
                    *coordinator_hart,
                    *coordinator_hart_generation,
                    participants,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::CompleteStopTheWorldRendezvous {
                rendezvous,
                epoch,
                safe_point,
                safe_point_generation,
                stop_new_activations,
                reason,
                ..
            } => self
                .validate_stop_the_world_rendezvous(
                    *rendezvous,
                    *epoch,
                    *safe_point,
                    *safe_point_generation,
                    *stop_new_activations,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ValidateSmpCodePublishBarrier {
                barrier,
                rendezvous,
                rendezvous_generation,
                code_publish_epoch_before,
                code_publish_epoch_after,
                remote_icache_sync_required,
                code_publish_executed,
                reason,
                ..
            } => self
                .validate_smp_code_publish_barrier(
                    *barrier,
                    *rendezvous,
                    *rendezvous_generation,
                    *code_publish_epoch_before,
                    *code_publish_epoch_after,
                    *remote_icache_sync_required,
                    *code_publish_executed,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ValidateSmpCleanupQuiescence {
                quiescence,
                cleanup,
                cleanup_generation,
                rendezvous,
                rendezvous_generation,
                store,
                target_store_generation,
                result_store_generation,
                reason,
                ..
            } => self
                .validate_smp_cleanup_quiescence(
                    *quiescence,
                    *cleanup,
                    *cleanup_generation,
                    *rendezvous,
                    *rendezvous_generation,
                    *store,
                    *target_store_generation,
                    *result_store_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ValidateSmpSnapshotBarrier {
                barrier,
                rendezvous,
                rendezvous_generation,
                snapshot_state,
                reason,
                ..
            } => self
                .validate_smp_snapshot_barrier(
                    *barrier,
                    *rendezvous,
                    *rendezvous_generation,
                    snapshot_state,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSmpStressRun {
                run,
                scenario,
                iterations,
                invariant_checks,
                reason,
                ..
            } => self
                .validate_smp_stress_run(*run, scenario, *iterations, *invariant_checks, reason)
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSmpScalingBenchmark {
                benchmark,
                scenario,
                stress_run,
                stress_run_generation,
                workload_units,
                baseline_single_hart_nanos,
                measured_smp_nanos,
                budget_nanos,
                ..
            } => self
                .validate_smp_scaling_benchmark(
                    *benchmark,
                    scenario,
                    *stress_run,
                    *stress_run_generation,
                    *workload_units,
                    *baseline_single_hart_nanos,
                    *measured_smp_nanos,
                    *budget_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIntegratedSmpPreemptionCleanup {
                integrated,
                scenario,
                stress_run,
                stress_run_generation,
                preemption,
                preemption_generation,
                timer_interrupt,
                timer_interrupt_generation,
                saved_context,
                saved_context_generation,
                remote_preempt,
                remote_preempt_generation,
                activation_cleanup,
                activation_cleanup_generation,
                smp_cleanup_quiescence,
                smp_cleanup_quiescence_generation,
                invariant_checks,
                ..
            } => self
                .validate_integrated_smp_preemption_cleanup(
                    *integrated,
                    scenario,
                    *stress_run,
                    *stress_run_generation,
                    *preemption,
                    *preemption_generation,
                    *timer_interrupt,
                    *timer_interrupt_generation,
                    *saved_context,
                    *saved_context_generation,
                    *remote_preempt,
                    *remote_preempt_generation,
                    *activation_cleanup,
                    *activation_cleanup_generation,
                    *smp_cleanup_quiescence,
                    *smp_cleanup_quiescence_generation,
                    *invariant_checks,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIntegratedSmpNetworkFault {
                integrated,
                scenario,
                network_driver_cleanup,
                network_driver_cleanup_generation,
                smp_stress_run,
                smp_stress_run_generation,
                remote_preempt,
                remote_preempt_generation,
                smp_cleanup_quiescence,
                smp_cleanup_quiescence_generation,
                invariant_checks,
                ..
            } => self
                .validate_integrated_smp_network_fault(
                    *integrated,
                    scenario,
                    *network_driver_cleanup,
                    *network_driver_cleanup_generation,
                    *smp_stress_run,
                    *smp_stress_run_generation,
                    *remote_preempt,
                    *remote_preempt_generation,
                    *smp_cleanup_quiescence,
                    *smp_cleanup_quiescence_generation,
                    *invariant_checks,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIntegratedDiskPreemptFault {
                integrated,
                scenario,
                preemption,
                preemption_generation,
                block_pending_io_policy,
                block_pending_io_policy_generation,
                invariant_checks,
                ..
            } => self
                .validate_integrated_disk_preempt_fault(
                    *integrated,
                    scenario,
                    *preemption,
                    *preemption_generation,
                    *block_pending_io_policy,
                    *block_pending_io_policy_generation,
                    *invariant_checks,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIntegratedSimdMigration {
                integrated,
                scenario,
                activation_migration,
                activation_migration_generation,
                invariant_checks,
                ..
            } => self
                .validate_integrated_simd_migration(
                    *integrated,
                    scenario,
                    *activation_migration,
                    *activation_migration_generation,
                    *invariant_checks,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIntegratedNetworkDiskIo {
                integrated,
                scenario,
                network_benchmark,
                network_benchmark_generation,
                block_benchmark,
                block_benchmark_generation,
                invariant_checks,
                ..
            } => self
                .validate_integrated_network_disk_io(
                    *integrated,
                    scenario,
                    *network_benchmark,
                    *network_benchmark_generation,
                    *block_benchmark,
                    *block_benchmark_generation,
                    *invariant_checks,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIntegratedDisplaySchedulerLoad {
                integrated,
                scenario,
                framebuffer_benchmark,
                framebuffer_benchmark_generation,
                scheduler_decision,
                scheduler_decision_generation,
                invariant_checks,
                ..
            } => self
                .validate_integrated_display_scheduler_load(
                    *integrated,
                    scenario,
                    *framebuffer_benchmark,
                    *framebuffer_benchmark_generation,
                    *scheduler_decision,
                    *scheduler_decision_generation,
                    *invariant_checks,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIntegratedSnapshotIoLeaseBarrier {
                integrated,
                scenario,
                smp_snapshot_barrier,
                smp_snapshot_barrier_generation,
                io_cleanup,
                io_cleanup_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                invariant_checks,
                ..
            } => self
                .validate_integrated_snapshot_io_lease_barrier(
                    *integrated,
                    scenario,
                    *smp_snapshot_barrier,
                    *smp_snapshot_barrier_generation,
                    *io_cleanup,
                    *io_cleanup_generation,
                    *display_snapshot_barrier,
                    *display_snapshot_barrier_generation,
                    *invariant_checks,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIntegratedCodePublishSmpWorkload {
                integrated,
                scenario,
                smp_stress_run,
                smp_stress_run_generation,
                smp_code_publish_barrier,
                smp_code_publish_barrier_generation,
                invariant_checks,
                ..
            } => self
                .validate_integrated_code_publish_smp_workload(
                    *integrated,
                    scenario,
                    *smp_stress_run,
                    *smp_stress_run_generation,
                    *smp_code_publish_barrier,
                    *smp_code_publish_barrier_generation,
                    *invariant_checks,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIntegratedDisplayPanic {
                integrated,
                scenario,
                substrate_panic_event,
                display_panic_last_frame,
                display_panic_last_frame_generation,
                panic_ring_bytes,
                panic_record_max_bytes,
                panic_ring_oldest_seq,
                panic_ring_newest_seq,
                panic_ring_record_count,
                panic_ring_lost_count,
                jsonl_frame_count,
                contract_panic_summary_records,
                last_frame_summary_records,
                corrupt_record_count,
                truncated_record_count,
                invariant_checks,
                ..
            } => self
                .validate_integrated_display_panic(
                    *integrated,
                    scenario,
                    *substrate_panic_event,
                    *display_panic_last_frame,
                    *display_panic_last_frame_generation,
                    *panic_ring_bytes,
                    *panic_record_max_bytes,
                    *panic_ring_oldest_seq,
                    *panic_ring_newest_seq,
                    *panic_ring_record_count,
                    *panic_ring_lost_count,
                    *jsonl_frame_count,
                    *contract_panic_summary_records,
                    *last_frame_summary_records,
                    *corrupt_record_count,
                    *truncated_record_count,
                    *invariant_checks,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIntegratedOsctlTraceReplay {
                integrated,
                scenario,
                integrated_smp_preemption_cleanup,
                integrated_smp_preemption_cleanup_generation,
                integrated_smp_network_fault,
                integrated_smp_network_fault_generation,
                integrated_disk_preempt_fault,
                integrated_disk_preempt_fault_generation,
                integrated_simd_migration,
                integrated_simd_migration_generation,
                integrated_network_disk_io,
                integrated_network_disk_io_generation,
                integrated_display_scheduler_load,
                integrated_display_scheduler_load_generation,
                integrated_snapshot_io_lease_barrier,
                integrated_snapshot_io_lease_barrier_generation,
                integrated_code_publish_smp_workload,
                integrated_code_publish_smp_workload_generation,
                integrated_display_panic,
                integrated_display_panic_generation,
                replay_event_cursor,
                stable_view_count,
                historical_edge_count,
                replayed_root_count,
                integrated_scenario_count,
                replay_fixture_count,
                invariant_checks,
                ..
            } => self
                .validate_integrated_osctl_trace_replay(
                    *integrated,
                    scenario,
                    *integrated_smp_preemption_cleanup,
                    *integrated_smp_preemption_cleanup_generation,
                    *integrated_smp_network_fault,
                    *integrated_smp_network_fault_generation,
                    *integrated_disk_preempt_fault,
                    *integrated_disk_preempt_fault_generation,
                    *integrated_simd_migration,
                    *integrated_simd_migration_generation,
                    *integrated_network_disk_io,
                    *integrated_network_disk_io_generation,
                    *integrated_display_scheduler_load,
                    *integrated_display_scheduler_load_generation,
                    *integrated_snapshot_io_lease_barrier,
                    *integrated_snapshot_io_lease_barrier_generation,
                    *integrated_code_publish_smp_workload,
                    *integrated_code_publish_smp_workload_generation,
                    *integrated_display_panic,
                    *integrated_display_panic_generation,
                    *replay_event_cursor,
                    *stable_view_count,
                    *historical_edge_count,
                    *replayed_root_count,
                    *integrated_scenario_count,
                    *replay_fixture_count,
                    *invariant_checks,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDeviceObject {
                device,
                name,
                class,
                resource,
                resource_generation,
                backend,
                ..
            } => self
                .validate_device_object(
                    *device,
                    name,
                    class,
                    *resource,
                    *resource_generation,
                    backend,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketDeviceObject {
                packet_device,
                name,
                device,
                device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                frame_format_version,
                max_payload_len,
                ..
            } => self
                .validate_packet_device_object(
                    *packet_device,
                    name,
                    *device,
                    *device_generation,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *frame_format_version,
                    *max_payload_len,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketBufferObject {
                packet_buffer,
                packet_device,
                packet_device_generation,
                direction,
                frame_format_version,
                capacity,
                payload_len,
                sequence,
                state,
                ..
            } => self
                .validate_packet_buffer_object(
                    *packet_buffer,
                    *packet_device,
                    *packet_device_generation,
                    *direction,
                    *frame_format_version,
                    *capacity,
                    *payload_len,
                    *sequence,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketQueueObject {
                packet_queue,
                name,
                packet_device,
                packet_device_generation,
                role,
                queue_index,
                depth,
                ..
            } => self
                .validate_packet_queue_object(
                    *packet_queue,
                    name,
                    *packet_device,
                    *packet_device_generation,
                    *role,
                    *queue_index,
                    *depth,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordPacketDescriptorObject {
                packet_descriptor,
                packet_queue,
                packet_queue_generation,
                packet_buffer,
                packet_buffer_generation,
                slot,
                length,
                ..
            } => self
                .validate_packet_descriptor_object(
                    *packet_descriptor,
                    *packet_queue,
                    *packet_queue_generation,
                    *packet_buffer,
                    *packet_buffer_generation,
                    *slot,
                    *length,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFakeNetBackendObject {
                fake_net_backend,
                name,
                packet_device,
                packet_device_generation,
                provider,
                profile,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                deterministic_seed,
                ..
            } => self
                .validate_fake_net_backend_object(
                    *fake_net_backend,
                    name,
                    *packet_device,
                    *packet_device_generation,
                    provider,
                    profile,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *mac,
                    *frame_format_version,
                    *max_payload_len,
                    *deterministic_seed,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFakeBlockBackendObject {
                fake_block_backend,
                name,
                block_device,
                block_device_generation,
                provider,
                profile,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                deterministic_seed,
                ..
            } => self
                .validate_fake_block_backend_object(
                    *fake_block_backend,
                    name,
                    *block_device,
                    *block_device_generation,
                    provider,
                    profile,
                    *sector_size,
                    *sector_count,
                    *read_only,
                    *max_transfer_sectors,
                    *deterministic_seed,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordVirtioBlkBackendObject {
                virtio_blk_backend,
                name,
                block_device,
                block_device_generation,
                driver_binding,
                driver_binding_generation,
                provider,
                profile,
                model,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                device_features,
                driver_features,
                negotiated_features,
                request_queue_index,
                queue_size,
                irq_vector,
                ..
            } => self
                .validate_virtio_blk_backend_object(
                    *virtio_blk_backend,
                    name,
                    *block_device,
                    *block_device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    provider,
                    profile,
                    model,
                    *sector_size,
                    *sector_count,
                    *read_only,
                    *max_transfer_sectors,
                    *device_features,
                    *driver_features,
                    *negotiated_features,
                    *request_queue_index,
                    *queue_size,
                    *irq_vector,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockReadPath {
                read_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                data_digest,
                ..
            } => self
                .validate_block_read_path(
                    *read_path,
                    *backend,
                    *block_request,
                    *block_request_generation,
                    *block_completion,
                    *block_completion_generation,
                    *data_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockWritePath {
                write_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                payload_digest,
                ..
            } => self
                .validate_block_write_path(
                    *write_path,
                    *backend,
                    *block_request,
                    *block_request_generation,
                    *block_completion,
                    *block_completion_generation,
                    *payload_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRequestQueue {
                queue,
                backend,
                block_device,
                block_device_generation,
                depth,
                entries,
                ..
            } => self
                .validate_block_request_queue(
                    *queue,
                    *backend,
                    *block_device,
                    *block_device_generation,
                    *depth,
                    entries,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockDmaBuffer {
                block_dma_buffer,
                backend,
                block_request,
                block_request_generation,
                dma_buffer,
                dma_buffer_generation,
                buffer_digest,
                ..
            } => self
                .validate_block_dma_buffer(
                    *block_dma_buffer,
                    *backend,
                    *block_request,
                    *block_request_generation,
                    *dma_buffer,
                    *dma_buffer_generation,
                    *buffer_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockPageObject {
                block_page_object,
                block_dma_buffer,
                block_dma_buffer_generation,
                block_completion,
                block_completion_generation,
                aspace,
                vma_region,
                page,
                page_dirty_generation,
                page_backing,
                cow_state,
                page_state,
                page_offset,
                byte_len,
                ..
            } => self
                .validate_block_page_object(
                    *block_page_object,
                    *block_dma_buffer,
                    *block_dma_buffer_generation,
                    *block_completion,
                    *block_completion_generation,
                    *aspace,
                    *vma_region,
                    *page,
                    *page_dirty_generation,
                    *page_backing,
                    *cow_state,
                    *page_state,
                    *page_offset,
                    *byte_len,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBufferCacheObject {
                buffer_cache_object,
                block_page_object,
                block_page_object_generation,
                page,
                page_dirty_generation,
                block_offset,
                byte_len,
                cache_state,
                coherency_epoch,
                ..
            } => self
                .validate_buffer_cache_object(
                    *buffer_cache_object,
                    *block_page_object,
                    *block_page_object_generation,
                    *page,
                    *page_dirty_generation,
                    *block_offset,
                    *byte_len,
                    *cache_state,
                    *coherency_epoch,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFileObject {
                file_object,
                buffer_cache_object,
                buffer_cache_object_generation,
                namespace,
                file_key,
                path,
                file_offset,
                byte_len,
                file_size,
                content_digest,
                state,
                ..
            } => self
                .validate_file_object(
                    *file_object,
                    *buffer_cache_object,
                    *buffer_cache_object_generation,
                    namespace,
                    file_key,
                    path,
                    *file_offset,
                    *byte_len,
                    *file_size,
                    *content_digest,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDirectoryObject {
                directory_object,
                file_object,
                file_object_generation,
                namespace,
                directory_key,
                directory_path,
                entry_name,
                child_file_key,
                child_path,
                entry_kind,
                file_size,
                content_digest,
                state,
                ..
            } => self
                .validate_directory_object(
                    *directory_object,
                    *file_object,
                    *file_object_generation,
                    namespace,
                    directory_key,
                    directory_path,
                    entry_name,
                    child_file_key,
                    child_path,
                    *entry_kind,
                    *file_size,
                    *content_digest,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFatAdapterObject {
                fat_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation,
                version,
                profile,
                volume_label,
                image_bytes,
                adapter_path,
                semantic_path,
                bytes_written,
                bytes_read,
                write_digest,
                read_digest,
                file_content_digest,
                state,
                ..
            } => self
                .validate_fat_adapter_object(
                    *fat_adapter_object,
                    *directory_object,
                    *directory_object_generation,
                    *file_object,
                    *file_object_generation,
                    *block_device,
                    *block_device_generation,
                    implementation,
                    version,
                    profile,
                    volume_label,
                    *image_bytes,
                    adapter_path,
                    semantic_path,
                    *bytes_written,
                    *bytes_read,
                    *write_digest,
                    *read_digest,
                    *file_content_digest,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordExt4AdapterObject {
                ext4_adapter_object,
                directory_object,
                directory_object_generation,
                file_object,
                file_object_generation,
                block_device,
                block_device_generation,
                implementation,
                version,
                profile,
                volume_label,
                image_bytes,
                adapter_path,
                semantic_path,
                bytes_read,
                read_digest,
                file_content_digest,
                directory_entries,
                read_only_enforced,
                state,
                ..
            } => self
                .validate_ext4_adapter_object(
                    *ext4_adapter_object,
                    *directory_object,
                    *directory_object_generation,
                    *file_object,
                    *file_object_generation,
                    *block_device,
                    *block_device_generation,
                    implementation,
                    version,
                    profile,
                    volume_label,
                    *image_bytes,
                    adapter_path,
                    semantic_path,
                    *bytes_read,
                    *read_digest,
                    *file_content_digest,
                    *directory_entries,
                    *read_only_enforced,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFileHandleCapability {
                file_handle_capability,
                owner_store,
                owner_store_generation,
                file_object,
                file_object_generation,
                directory_object,
                directory_object_generation,
                capability,
                capability_generation,
                handle,
                operation,
                file_offset,
                byte_len,
                content_digest,
                ..
            } => self
                .validate_file_handle_capability(
                    *file_handle_capability,
                    *owner_store,
                    *owner_store_generation,
                    *file_object,
                    *file_object_generation,
                    *directory_object,
                    *directory_object_generation,
                    *capability,
                    *capability_generation,
                    handle,
                    operation,
                    *file_offset,
                    *byte_len,
                    *content_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFsWait {
                fs_wait,
                wait,
                wait_generation,
                file_handle_capability,
                file_handle_capability_generation,
                operation,
                sequence,
                ..
            } => self
                .validate_fs_wait(
                    *fs_wait,
                    *wait,
                    *wait_generation,
                    *file_handle_capability,
                    *file_handle_capability_generation,
                    operation,
                    *sequence,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveFsWait { fs_wait, fs_wait_generation, .. } => {
                if self.fs_waits.iter().any(|record| {
                    record.id == *fs_wait
                        && record.generation == *fs_wait_generation
                        && record.state == FsWaitState::Pending
                        && self.domains.wait.waits.iter().any(|wait| {
                            wait.id == record.wait
                                && wait.generation == record.wait_generation
                                && wait.state == WaitState::Pending
                        })
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition("fs wait generation is missing or not pending"))
                }
            }
            SemanticCommand::CancelFsWait { fs_wait, fs_wait_generation, reason, .. } => {
                if !matches!(
                    reason,
                    WaitCancelReason::CloseFd
                        | WaitCancelReason::StoreFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    return Err(CommandError::precondition(
                        "fs wait cancellation reason is not a filesystem reason",
                    ));
                }
                if self.fs_waits.iter().any(|record| {
                    record.id == *fs_wait
                        && record.generation == *fs_wait_generation
                        && record.state == FsWaitState::Pending
                        && self.domains.wait.waits.iter().any(|wait| {
                            wait.id == record.wait
                                && wait.generation == record.wait_generation
                                && wait.state == WaitState::Pending
                        })
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition("fs wait generation is missing or not pending"))
                }
            }
            SemanticCommand::CleanupBlockDriver {
                cleanup,
                io_cleanup,
                block_device,
                block_device_generation,
                backend,
                reason,
                ..
            } => self
                .validate_block_driver_cleanup(
                    *cleanup,
                    *io_cleanup,
                    *block_device,
                    *block_device_generation,
                    *backend,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordVirtioNetBackendObject {
                virtio_net_backend,
                name,
                packet_device,
                packet_device_generation,
                driver_binding,
                driver_binding_generation,
                provider,
                profile,
                model,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                mac,
                frame_format_version,
                max_payload_len,
                device_features,
                driver_features,
                negotiated_features,
                rx_queue_index,
                tx_queue_index,
                queue_size,
                irq_vector,
                ..
            } => self
                .validate_virtio_net_backend_object(
                    *virtio_net_backend,
                    name,
                    *packet_device,
                    *packet_device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    provider,
                    profile,
                    model,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *mac,
                    *frame_format_version,
                    *max_payload_len,
                    *device_features,
                    *driver_features,
                    *negotiated_features,
                    *rx_queue_index,
                    *tx_queue_index,
                    *queue_size,
                    *irq_vector,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkRxInterrupt {
                rx_interrupt,
                virtio_net_backend,
                virtio_net_backend_generation,
                irq_event,
                irq_event_generation,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                ready_descriptors,
                sequence,
                ..
            } => self
                .validate_network_rx_interrupt(
                    *rx_interrupt,
                    *virtio_net_backend,
                    *virtio_net_backend_generation,
                    *irq_event,
                    *irq_event_generation,
                    *packet_device,
                    *packet_device_generation,
                    *rx_queue,
                    *rx_queue_generation,
                    *ready_descriptors,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveNetworkRxWait {
                resolution,
                io_wait,
                io_wait_generation,
                rx_interrupt,
                rx_interrupt_generation,
                ..
            } => self
                .validate_network_rx_wait_resolution(
                    *resolution,
                    *io_wait,
                    *io_wait_generation,
                    *rx_interrupt,
                    *rx_interrupt_generation,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkTxCapabilityGate {
                tx_gate,
                driver_store,
                driver_store_generation,
                packet_descriptor,
                packet_descriptor_generation,
                device_capability,
                device_capability_generation,
                handle,
                ..
            } => self
                .validate_network_tx_capability_gate(
                    *tx_gate,
                    *driver_store,
                    *driver_store_generation,
                    *packet_descriptor,
                    *packet_descriptor_generation,
                    *device_capability,
                    *device_capability_generation,
                    handle,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkTxCompletion {
                completion,
                tx_gate,
                tx_gate_generation,
                backend,
                completion_sequence,
                ..
            } => self
                .validate_network_tx_completion(
                    *completion,
                    *tx_gate,
                    *tx_gate_generation,
                    *backend,
                    *completion_sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkStackAdapter {
                adapter,
                backend,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                tx_queue,
                tx_queue_generation,
                implementation,
                implementation_version,
                profile,
                medium,
                mac,
                ipv4_addr,
                ipv4_prefix_len,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                max_payload_len,
                socket_capacity,
                ..
            } => self
                .validate_network_stack_adapter(
                    *adapter,
                    *backend,
                    *packet_device,
                    *packet_device_generation,
                    *rx_queue,
                    *rx_queue_generation,
                    *tx_queue,
                    *tx_queue_generation,
                    implementation,
                    implementation_version,
                    profile,
                    medium,
                    *mac,
                    *ipv4_addr,
                    *ipv4_prefix_len,
                    *mtu,
                    *rx_queue_depth,
                    *tx_queue_depth,
                    *max_payload_len,
                    *socket_capacity,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSocketObject {
                socket,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                domain,
                socket_type,
                protocol,
                ..
            } => self
                .validate_socket_object(
                    *socket,
                    *adapter,
                    *adapter_generation,
                    *owner_store,
                    *owner_store_generation,
                    *domain,
                    *socket_type,
                    *protocol,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordEndpointObject {
                endpoint,
                socket,
                socket_generation,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                ..
            } => self
                .validate_endpoint_object(
                    *endpoint,
                    *socket,
                    *socket_generation,
                    *local_addr,
                    *local_port,
                    *remote_addr,
                    *remote_port,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::BindSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                local_addr,
                local_port,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Bind,
                    *local_addr,
                    *local_port,
                    [0, 0, 0, 0],
                    0,
                    0,
                    0,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ListenSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                backlog,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Listen,
                    [0, 0, 0, 0],
                    0,
                    [0, 0, 0, 0],
                    0,
                    *backlog,
                    0,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ConnectSocketEndpoint {
                operation_id,
                endpoint,
                endpoint_generation,
                remote_addr,
                remote_port,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Connect,
                    [0, 0, 0, 0],
                    0,
                    *remote_addr,
                    *remote_port,
                    0,
                    0,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::SendSocket {
                operation_id,
                endpoint,
                endpoint_generation,
                byte_len,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Send,
                    [0, 0, 0, 0],
                    0,
                    [0, 0, 0, 0],
                    0,
                    0,
                    *byte_len,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecvSocket {
                operation_id,
                endpoint,
                endpoint_generation,
                byte_len,
                sequence,
                ..
            } => self
                .validate_socket_operation(
                    *operation_id,
                    *endpoint,
                    *endpoint_generation,
                    SocketOperationKind::Recv,
                    [0, 0, 0, 0],
                    0,
                    [0, 0, 0, 0],
                    0,
                    0,
                    *byte_len,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSocketWait {
                socket_wait,
                wait,
                wait_generation,
                endpoint,
                endpoint_generation,
                wait_kind,
                blocker,
                ..
            } => self
                .validate_socket_wait(
                    *socket_wait,
                    *wait,
                    *wait_generation,
                    *endpoint,
                    *endpoint_generation,
                    *wait_kind,
                    *blocker,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveSocketWait {
                socket_wait,
                socket_wait_generation,
                ready_sequence,
                byte_len,
                ..
            } => {
                if self.socket_waits.iter().any(|record| {
                    record.id == *socket_wait
                        && record.generation == *socket_wait_generation
                        && record.state == SocketWaitState::Pending
                        && *ready_sequence > 0
                        && (!matches!(record.wait_kind, SemanticWaitKind::SocketReadable)
                            || *byte_len > 0)
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "socket wait is not pending or readiness is empty",
                    ))
                }
            }
            SemanticCommand::CancelSocketWait {
                socket_wait,
                socket_wait_generation,
                reason,
                ..
            } => {
                if self.socket_waits.iter().any(|record| {
                    record.id == *socket_wait
                        && record.generation == *socket_wait_generation
                        && record.state == SocketWaitState::Pending
                }) && matches!(
                    reason,
                    WaitCancelReason::CloseFd
                        | WaitCancelReason::StoreFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::DeviceFault
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "socket wait is not pending or cancel reason is not socket-visible",
                    ))
                }
            }
            SemanticCommand::RecordNetworkBackpressure {
                backpressure,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                endpoint,
                endpoint_generation,
                direction,
                reason,
                action,
                queue_depth,
                queue_limit,
                dropped_packets,
                dropped_bytes,
                sequence,
                ..
            } => self
                .validate_network_backpressure(
                    *backpressure,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *packet_queue,
                    *packet_queue_generation,
                    *endpoint,
                    *endpoint_generation,
                    *direction,
                    *reason,
                    *action,
                    *queue_depth,
                    *queue_limit,
                    *dropped_packets,
                    *dropped_bytes,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::CleanupNetworkDriver {
                cleanup,
                io_cleanup,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                backend,
                reason,
                ..
            } => self
                .validate_network_driver_cleanup(
                    *cleanup,
                    *io_cleanup,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *backend,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkGenerationAudit {
                audit,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                dma_buffer,
                device_capability,
                rejected_packet_generation_probes,
                rejected_dma_generation_probes,
                ..
            } => self
                .validate_network_generation_audit(
                    *audit,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *packet_queue,
                    *packet_queue_generation,
                    *packet_descriptor,
                    *packet_descriptor_generation,
                    *packet_buffer,
                    *packet_buffer_generation,
                    *dma_buffer,
                    *device_capability,
                    *rejected_packet_generation_probes,
                    *rejected_dma_generation_probes,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkFaultInjection {
                injection,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                endpoint,
                endpoint_generation,
                direction,
                kind,
                effect,
                injected_packets,
                dropped_packets,
                error_packets,
                error_code,
                sequence,
                ..
            } => self
                .validate_network_fault_injection(
                    *injection,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *packet_queue,
                    *packet_queue_generation,
                    *packet_descriptor,
                    *packet_descriptor_generation,
                    *packet_buffer,
                    *packet_buffer_generation,
                    *endpoint,
                    *endpoint_generation,
                    *direction,
                    *kind,
                    *effect,
                    *injected_packets,
                    *dropped_packets,
                    *error_packets,
                    error_code,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkBenchmark {
                benchmark,
                scenario,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                rx_queue,
                rx_queue_generation,
                tx_completion,
                tx_completion_generation,
                rx_wait_resolution,
                rx_wait_resolution_generation,
                endpoint,
                endpoint_generation,
                backpressure,
                backpressure_generation,
                sample_packets,
                sample_bytes,
                tx_completed_packets,
                rx_resolved_packets,
                dropped_packets,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                ..
            } => self
                .validate_network_benchmark(
                    *benchmark,
                    scenario,
                    *adapter,
                    *adapter_generation,
                    *packet_device,
                    *packet_device_generation,
                    *tx_queue,
                    *tx_queue_generation,
                    *rx_queue,
                    *rx_queue_generation,
                    *tx_completion,
                    *tx_completion_generation,
                    *rx_wait_resolution,
                    *rx_wait_resolution_generation,
                    *endpoint,
                    *endpoint_generation,
                    *backpressure,
                    *backpressure_generation,
                    *sample_packets,
                    *sample_bytes,
                    *tx_completed_packets,
                    *rx_resolved_packets,
                    *dropped_packets,
                    *measured_nanos,
                    *budget_nanos,
                    *p50_latency_nanos,
                    *p99_latency_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordNetworkRecoveryBenchmark {
                benchmark,
                scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                fault_injection,
                fault_injection_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_socket_waits,
                revoked_packet_capabilities,
                recovery_nanos,
                budget_nanos,
                ..
            } => self
                .validate_network_recovery_benchmark(
                    *benchmark,
                    scenario,
                    *cleanup,
                    *cleanup_generation,
                    *io_cleanup,
                    *io_cleanup_generation,
                    *fault_injection,
                    *fault_injection_generation,
                    *recovery_start_event,
                    *recovery_complete_event,
                    *cancelled_socket_waits,
                    *revoked_packet_capabilities,
                    *recovery_nanos,
                    *budget_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockDeviceObject {
                block_device,
                name,
                device,
                device_generation,
                sector_size,
                sector_count,
                max_transfer_sectors,
                ..
            } => self
                .validate_block_device_object(
                    *block_device,
                    name,
                    *device,
                    *device_generation,
                    *sector_size,
                    *sector_count,
                    *max_transfer_sectors,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRangeObject {
                block_range,
                block_device,
                block_device_generation,
                start_sector,
                sector_count,
                ..
            } => self
                .validate_block_range_object(
                    *block_range,
                    *block_device,
                    *block_device_generation,
                    *start_sector,
                    *sector_count,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRequestObject {
                block_request,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                operation,
                sequence,
                ..
            } => self
                .validate_block_request_object(
                    *block_request,
                    *block_device,
                    *block_device_generation,
                    *block_range,
                    *block_range_generation,
                    *operation,
                    *sequence,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockCompletionObject {
                block_completion,
                block_request,
                block_request_generation,
                sequence,
                completed_bytes,
                status,
                ..
            } => self
                .validate_block_completion_object(
                    *block_completion,
                    *block_request,
                    *block_request_generation,
                    *sequence,
                    *completed_bytes,
                    *status,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockWait {
                block_wait,
                wait,
                wait_generation,
                block_request,
                block_request_generation,
                ..
            } => self
                .validate_block_wait(
                    *block_wait,
                    *wait,
                    *wait_generation,
                    *block_request,
                    *block_request_generation,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveBlockWait {
                block_wait,
                block_wait_generation,
                block_completion,
                block_completion_generation,
                ..
            } => {
                let Some(record) = self.block_waits.iter().find(|record| {
                    record.id == *block_wait
                        && record.generation == *block_wait_generation
                        && record.state == BlockWaitState::Pending
                }) else {
                    return Err(CommandError::precondition(
                        "block wait generation is missing or not pending",
                    ));
                };
                let Some(completion) = self.block_completion_objects.iter().find(|completion| {
                    completion.id == *block_completion
                        && completion.generation == *block_completion_generation
                        && completion.state == BlockCompletionObjectState::Recorded
                }) else {
                    return Err(CommandError::precondition(
                        "block wait completion generation is missing",
                    ));
                };
                if completion.block_request == record.block_request
                    && completion.block_request_generation == record.block_request_generation
                    && completion.block_device == record.block_device
                    && completion.block_device_generation == record.block_device_generation
                    && completion.block_range == record.block_range
                    && completion.block_range_generation == record.block_range_generation
                    && completion.sequence == record.sequence
                    && completion.status == BlockCompletionStatus::Success
                    && completion.completed_bytes == record.byte_len
                    && self.domains.wait.waits.iter().any(|wait| {
                        wait.id == record.wait
                            && wait.generation == record.wait_generation
                            && wait.state == WaitState::Pending
                    })
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("block wait completion attribution mismatch"))
                }
            }
            SemanticCommand::CancelBlockWait {
                block_wait, block_wait_generation, reason, ..
            } => {
                if !matches!(
                    reason,
                    WaitCancelReason::DeviceFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    return Err(CommandError::precondition(
                        "block wait cancellation reason is not a block io reason",
                    ));
                }
                if self.block_waits.iter().any(|record| {
                    record.id == *block_wait
                        && record.generation == *block_wait_generation
                        && record.state == BlockWaitState::Pending
                        && self.domains.wait.waits.iter().any(|wait| {
                            wait.id == record.wait
                                && wait.generation == record.wait_generation
                                && wait.state == WaitState::Pending
                        })
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition(
                        "block wait generation is missing or not pending",
                    ))
                }
            }
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy,
                block_wait,
                block_wait_generation,
                action,
                retry_request,
                retry_request_generation,
                errno,
                retry_attempt,
                max_retries,
                ..
            } => self
                .validate_block_pending_io_policy(
                    *policy,
                    *block_wait,
                    *block_wait_generation,
                    *action,
                    *retry_request,
                    *retry_request_generation,
                    *errno,
                    *retry_attempt,
                    *max_retries,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRequestGenerationAudit {
                audit,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                block_request,
                block_request_generation,
                backend,
                dma_buffer,
                rejected_completion_generation_probes,
                rejected_wait_generation_probes,
                rejected_dma_generation_probes,
                rejected_queue_generation_probes,
                ..
            } => self
                .validate_block_request_generation_audit(
                    *audit,
                    *block_device,
                    *block_device_generation,
                    *block_range,
                    *block_range_generation,
                    *block_request,
                    *block_request_generation,
                    *backend,
                    *dma_buffer,
                    *rejected_completion_generation_probes,
                    *rejected_wait_generation_probes,
                    *rejected_dma_generation_probes,
                    *rejected_queue_generation_probes,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockBenchmark {
                benchmark,
                scenario,
                backend,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                read_path,
                read_path_generation,
                write_path,
                write_path_generation,
                request_queue,
                request_queue_generation,
                block_dma_buffer,
                block_dma_buffer_generation,
                sample_requests,
                sample_bytes,
                read_completed_requests,
                write_completed_requests,
                queue_completed_requests,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                ..
            } => self
                .validate_block_benchmark(
                    *benchmark,
                    scenario,
                    *backend,
                    *block_device,
                    *block_device_generation,
                    *block_range,
                    *block_range_generation,
                    *read_path,
                    *read_path_generation,
                    *write_path,
                    *write_path_generation,
                    *request_queue,
                    *request_queue_generation,
                    *block_dma_buffer,
                    *block_dma_buffer_generation,
                    *sample_requests,
                    *sample_bytes,
                    *read_completed_requests,
                    *write_completed_requests,
                    *queue_completed_requests,
                    *measured_nanos,
                    *budget_nanos,
                    *p50_latency_nanos,
                    *p99_latency_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordBlockRecoveryBenchmark {
                benchmark,
                scenario,
                cleanup,
                cleanup_generation,
                io_cleanup,
                io_cleanup_generation,
                recovery_start_event,
                recovery_complete_event,
                cancelled_block_waits,
                cancelled_wait_tokens,
                released_dma_buffers,
                revoked_device_capabilities,
                recovery_nanos,
                budget_nanos,
                ..
            } => self
                .validate_block_recovery_benchmark(
                    *benchmark,
                    scenario,
                    *cleanup,
                    *cleanup_generation,
                    *io_cleanup,
                    *io_cleanup_generation,
                    *recovery_start_event,
                    *recovery_complete_event,
                    *cancelled_block_waits,
                    *cancelled_wait_tokens,
                    *released_dma_buffers,
                    *revoked_device_capabilities,
                    *recovery_nanos,
                    *budget_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordTargetFeatureSet {
                feature_set,
                name,
                discovery_source,
                target_profile,
                target_arch,
                base_isa,
                simd_abi,
                simd_supported,
                vector_register_count,
                vector_register_bits,
                scalar_fallback,
                unsupported_reason,
                ..
            } => self
                .validate_target_feature_set(
                    *feature_set,
                    name,
                    discovery_source,
                    target_profile,
                    target_arch,
                    base_isa,
                    simd_abi,
                    *simd_supported,
                    *vector_register_count,
                    *vector_register_bits,
                    *scalar_fallback,
                    unsupported_reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordVectorState {
                vector_state,
                owner_activation,
                owner_store,
                code_object,
                target_feature_set,
                simd_abi,
                vector_register_count,
                vector_register_bits,
                register_bytes,
                state,
                ..
            } => self
                .validate_vector_state(
                    *vector_state,
                    *owner_activation,
                    *owner_store,
                    *code_object,
                    *target_feature_set,
                    simd_abi,
                    *vector_register_count,
                    *vector_register_bits,
                    *register_bytes,
                    *state,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSimdFaultInjection {
                injection,
                activation,
                code_object,
                trap,
                target_feature_set,
                vector_state,
                kind,
                effect,
                required_abi,
                vector_register_count,
                vector_register_bits,
                injected_faults,
                ..
            } => self
                .validate_simd_fault_injection(
                    *injection,
                    *activation,
                    *code_object,
                    *trap,
                    *target_feature_set,
                    *vector_state,
                    *kind,
                    *effect,
                    required_abi,
                    *vector_register_count,
                    *vector_register_bits,
                    *injected_faults,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordSimdBenchmark {
                benchmark,
                target_feature_set,
                scalar_code_object,
                vector_code_object,
                simd_abi,
                vector_register_count,
                vector_register_bits,
                workload_units,
                scalar_nanos,
                vector_nanos,
                speedup_milli,
                context_overhead_nanos,
                ..
            } => {
                if self.simd_benchmarks.iter().any(|record| record.id == *benchmark) {
                    Err(CommandError::precondition("SIMD benchmark already exists"))
                } else {
                    self.validate_simd_benchmark(
                        *benchmark,
                        *target_feature_set,
                        *scalar_code_object,
                        *vector_code_object,
                        simd_abi,
                        *vector_register_count,
                        *vector_register_bits,
                        *workload_units,
                        *scalar_nanos,
                        *vector_nanos,
                        *speedup_milli,
                        *context_overhead_nanos,
                    )
                    .map_err(CommandError::precondition)
                }
            }
            SemanticCommand::RecordSimdContextSwitchBenchmark {
                benchmark,
                preemption,
                activation_resume,
                saved_vector_state,
                restored_vector_state,
                target_feature_set,
                simd_abi,
                vector_register_count,
                vector_register_bits,
                sample_count,
                scalar_context_switch_nanos,
                vector_context_switch_nanos,
                overhead_nanos,
                budget_nanos,
                ..
            } => {
                if self.simd_context_switch_benchmarks.iter().any(|record| record.id == *benchmark)
                {
                    Err(CommandError::precondition("SIMD context switch benchmark already exists"))
                } else {
                    self.validate_simd_context_switch_benchmark(
                        *benchmark,
                        *preemption,
                        *activation_resume,
                        *saved_vector_state,
                        *restored_vector_state,
                        *target_feature_set,
                        simd_abi,
                        *vector_register_count,
                        *vector_register_bits,
                        *sample_count,
                        *scalar_context_switch_nanos,
                        *vector_context_switch_nanos,
                        *overhead_nanos,
                        *budget_nanos,
                    )
                    .map_err(CommandError::precondition)
                }
            }
            SemanticCommand::RecordFramebufferObject {
                framebuffer,
                name,
                resource,
                resource_generation,
                width,
                height,
                stride_bytes,
                pixel_format,
                byte_len,
                ..
            } => self
                .validate_framebuffer_object(
                    *framebuffer,
                    name,
                    *resource,
                    *resource_generation,
                    *width,
                    *height,
                    *stride_bytes,
                    pixel_format,
                    *byte_len,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDisplayObject {
                display,
                name,
                framebuffer,
                framebuffer_generation,
                mode_name,
                width,
                height,
                refresh_millihz,
                ..
            } => self
                .validate_display_object(
                    *display,
                    name,
                    *framebuffer,
                    *framebuffer_generation,
                    mode_name,
                    *width,
                    *height,
                    *refresh_millihz,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDisplayCapability {
                display_capability,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                capability,
                capability_generation,
                handle,
                operations,
                ..
            } => self
                .validate_display_capability(
                    *display_capability,
                    *owner_store,
                    *owner_store_generation,
                    *display,
                    *display_generation,
                    *capability,
                    *capability_generation,
                    handle,
                    operations,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFramebufferWindowLease {
                framebuffer_window_lease,
                owner_store,
                owner_store_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                access,
                ..
            } => self
                .validate_framebuffer_window_lease(
                    *framebuffer_window_lease,
                    *owner_store,
                    *owner_store_generation,
                    *display_capability,
                    *display_capability_generation,
                    *display,
                    *display_generation,
                    *framebuffer,
                    *framebuffer_generation,
                    *x,
                    *y,
                    *width,
                    *height,
                    *byte_offset,
                    *byte_len,
                    access,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFramebufferMapping {
                framebuffer_mapping,
                owner_store,
                owner_store_generation,
                framebuffer_window_lease,
                framebuffer_window_lease_generation,
                map_handle_slot,
                map_handle_generation,
                map_handle_tag,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                access,
                mode,
                ..
            } => self
                .validate_framebuffer_mapping(
                    *framebuffer_mapping,
                    *owner_store,
                    *owner_store_generation,
                    *framebuffer_window_lease,
                    *framebuffer_window_lease_generation,
                    *map_handle_slot,
                    *map_handle_generation,
                    *map_handle_tag,
                    *x,
                    *y,
                    *width,
                    *height,
                    *byte_offset,
                    *byte_len,
                    access,
                    mode,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFramebufferWrite {
                framebuffer_write,
                owner_store,
                owner_store_generation,
                framebuffer_mapping,
                framebuffer_mapping_generation,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                payload_digest,
                ..
            } => self
                .validate_framebuffer_write(
                    *framebuffer_write,
                    *owner_store,
                    *owner_store_generation,
                    *framebuffer_mapping,
                    *framebuffer_mapping_generation,
                    *x,
                    *y,
                    *width,
                    *height,
                    *byte_offset,
                    *byte_len,
                    *payload_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFramebufferFlushRegion {
                framebuffer_flush_region,
                owner_store,
                owner_store_generation,
                framebuffer_write,
                framebuffer_write_generation,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                payload_digest,
                ..
            } => self
                .validate_framebuffer_flush_region(
                    *framebuffer_flush_region,
                    *owner_store,
                    *owner_store_generation,
                    *framebuffer_write,
                    *framebuffer_write_generation,
                    *x,
                    *y,
                    *width,
                    *height,
                    *byte_offset,
                    *byte_len,
                    *payload_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFramebufferDirtyRegion {
                framebuffer_dirty_region,
                owner_store,
                owner_store_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                state,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                payload_digest,
                ..
            } => self
                .validate_framebuffer_dirty_region(
                    *framebuffer_dirty_region,
                    *owner_store,
                    *owner_store_generation,
                    *framebuffer_write,
                    *framebuffer_write_generation,
                    *framebuffer_flush_region,
                    *framebuffer_flush_region_generation,
                    *state,
                    *x,
                    *y,
                    *width,
                    *height,
                    *byte_offset,
                    *byte_len,
                    *payload_digest,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDisplayEventLog {
                display_event_log,
                owner_store,
                owner_store_generation,
                framebuffer_dirty_region,
                framebuffer_dirty_region_generation,
                first_event,
                last_event,
                event_count,
                flush_count,
                dirty_region_count,
                ..
            } => self
                .validate_display_event_log(
                    *display_event_log,
                    *owner_store,
                    *owner_store_generation,
                    *framebuffer_dirty_region,
                    *framebuffer_dirty_region_generation,
                    *first_event,
                    *last_event,
                    *event_count,
                    *flush_count,
                    *dirty_region_count,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::CleanupDisplay {
                cleanup,
                owner_store,
                owner_store_generation,
                display_capability,
                display_capability_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                reason,
                ..
            } => self
                .validate_display_cleanup(
                    *cleanup,
                    *owner_store,
                    *owner_store_generation,
                    *display_capability,
                    *display_capability_generation,
                    *display,
                    *display_generation,
                    *framebuffer,
                    *framebuffer_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ValidateDisplaySnapshotBarrier {
                barrier,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                display_cleanup,
                display_cleanup_generation,
                reason,
                ..
            } => self
                .validate_display_snapshot_barrier(
                    *barrier,
                    *owner_store,
                    *owner_store_generation,
                    *display,
                    *display_generation,
                    *framebuffer,
                    *framebuffer_generation,
                    *display_cleanup,
                    *display_cleanup_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDisplayPanicLastFrame {
                panic_last_frame,
                owner_store,
                owner_store_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                display_event_log,
                display_event_log_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                payload_digest,
                summary_digest,
                summary_record_bytes,
                panic_epoch,
                panic_record_kind,
                raw_framebuffer_bytes_exported,
                ..
            } => self
                .validate_display_panic_last_frame(
                    *panic_last_frame,
                    *owner_store,
                    *owner_store_generation,
                    *display_snapshot_barrier,
                    *display_snapshot_barrier_generation,
                    *display_event_log,
                    *display_event_log_generation,
                    *framebuffer_write,
                    *framebuffer_write_generation,
                    *framebuffer_flush_region,
                    *framebuffer_flush_region_generation,
                    *payload_digest,
                    *summary_digest,
                    *summary_record_bytes,
                    *panic_epoch,
                    panic_record_kind,
                    *raw_framebuffer_bytes_exported,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordFramebufferBenchmark {
                benchmark,
                scenario,
                owner_store,
                owner_store_generation,
                display_capability,
                display_capability_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                display_event_log,
                display_event_log_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                sample_frames,
                sample_bytes,
                frame_area_pixels,
                write_nanos,
                flush_nanos,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
                ..
            } => self
                .validate_framebuffer_benchmark(
                    *benchmark,
                    scenario,
                    *owner_store,
                    *owner_store_generation,
                    *display_capability,
                    *display_capability_generation,
                    *framebuffer_write,
                    *framebuffer_write_generation,
                    *framebuffer_flush_region,
                    *framebuffer_flush_region_generation,
                    *display_event_log,
                    *display_event_log_generation,
                    *display_snapshot_barrier,
                    *display_snapshot_barrier_generation,
                    *sample_frames,
                    *sample_bytes,
                    *frame_area_pixels,
                    *write_nanos,
                    *flush_nanos,
                    *measured_nanos,
                    *budget_nanos,
                    *p50_latency_nanos,
                    *p99_latency_nanos,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordQueueObject {
                queue,
                name,
                role,
                queue_index,
                depth,
                device,
                device_generation,
                ..
            } => self
                .validate_queue_object(
                    *queue,
                    name,
                    *role,
                    *queue_index,
                    *depth,
                    *device,
                    *device_generation,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDescriptorObject {
                descriptor,
                queue,
                queue_generation,
                slot,
                access,
                length,
                ..
            } => self
                .validate_descriptor_object(
                    *descriptor,
                    *queue,
                    *queue_generation,
                    *slot,
                    *access,
                    *length,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDmaBufferObject {
                dma_buffer,
                descriptor,
                descriptor_generation,
                resource,
                resource_generation,
                access,
                length,
                ..
            } => self
                .validate_dma_buffer_object(
                    *dma_buffer,
                    *descriptor,
                    *descriptor_generation,
                    *resource,
                    *resource_generation,
                    *access,
                    *length,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordMmioRegionObject {
                mmio_region,
                device,
                device_generation,
                resource,
                resource_generation,
                region_index,
                offset,
                length,
                access,
                ..
            } => self
                .validate_mmio_region_object(
                    *mmio_region,
                    *device,
                    *device_generation,
                    *resource,
                    *resource_generation,
                    *region_index,
                    *offset,
                    *length,
                    *access,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIrqLineObject {
                irq_line,
                device,
                device_generation,
                resource,
                resource_generation,
                irq_number,
                trigger,
                polarity,
                ..
            } => self
                .validate_irq_line_object(
                    *irq_line,
                    *device,
                    *device_generation,
                    *resource,
                    *resource_generation,
                    *irq_number,
                    *trigger,
                    *polarity,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIrqEvent {
                irq_event,
                irq_line,
                irq_line_generation,
                device,
                device_generation,
                driver_store,
                driver_store_generation,
                sequence,
                ..
            } => self
                .validate_irq_event(
                    *irq_event,
                    *irq_line,
                    *irq_line_generation,
                    *device,
                    *device_generation,
                    *driver_store,
                    *driver_store_generation,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDeviceCapability {
                device_capability,
                driver_store,
                driver_store_generation,
                target,
                class,
                operation,
                handle,
                ..
            } => self
                .validate_device_capability(
                    *device_capability,
                    *driver_store,
                    *driver_store_generation,
                    *target,
                    *class,
                    operation,
                    handle,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::BindDriverStore {
                binding,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                device_capability,
                device_capability_generation,
                ..
            } => self
                .validate_driver_store_binding(
                    *binding,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *device_capability,
                    *device_capability_generation,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIoWait {
                io_wait,
                wait,
                wait_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                blocker,
                ..
            } => self
                .validate_io_wait(
                    *io_wait,
                    *wait,
                    *wait_generation,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    *blocker,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveIoWait {
                io_wait,
                io_wait_generation,
                irq_event,
                irq_event_generation,
                ..
            } => {
                let Some(record) = self.domains.io.io_waits.iter().find(|record| {
                    record.id == *io_wait
                        && record.generation == *io_wait_generation
                        && record.state == IoWaitState::Pending
                }) else {
                    return Err(CommandError::precondition(
                        "io wait generation is missing or not pending",
                    ));
                };
                let Some(irq_record) = self.irq_events.iter().find(|irq| {
                    irq.id == *irq_event
                        && irq.generation == *irq_event_generation
                        && irq.state == IrqEventState::Recorded
                }) else {
                    return Err(CommandError::precondition(
                        "io wait irq event generation is missing",
                    ));
                };
                if record.blocker.kind == ContractObjectKind::IrqLineObject
                    && (record.blocker.id != irq_record.irq_line
                        || record.blocker.generation != irq_record.irq_line_generation)
                {
                    return Err(CommandError::precondition(
                        "io wait irq line attribution mismatch",
                    ));
                }
                if !self.domains.wait.waits.iter().any(|wait| {
                    wait.id == record.wait
                        && wait.generation == record.wait_generation
                        && wait.state == WaitState::Pending
                }) {
                    return Err(CommandError::precondition(
                        "io wait token generation is missing or not pending",
                    ));
                }
                if irq_record.device == record.device
                    && irq_record.device_generation == record.device_generation
                    && irq_record.driver_store == record.driver_store
                    && irq_record.driver_store_generation == record.driver_store_generation
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("io wait irq event attribution mismatch"))
                }
            }
            SemanticCommand::CancelIoWait { io_wait, io_wait_generation, reason, .. } => {
                if !matches!(
                    reason,
                    WaitCancelReason::DeviceFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    return Err(CommandError::precondition(
                        "io wait cancellation reason is not an io reason",
                    ));
                }
                if self.domains.io.io_waits.iter().any(|record| {
                    record.id == *io_wait
                        && record.generation == *io_wait_generation
                        && record.state == IoWaitState::Pending
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition("io wait generation is missing or not pending"))
                }
            }
            SemanticCommand::CleanupIoDriver {
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                reason,
                ..
            } => self
                .validate_io_cleanup(
                    *cleanup,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::InjectIoFault {
                fault,
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                target,
                kind,
                ..
            } => self
                .validate_io_fault_injection(
                    *fault,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    *target,
                    *cleanup,
                    *kind,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ValidateIoRuntime { report, .. } => {
                self.validate_io_validation_report(*report).map_err(CommandError::precondition)
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
                    Err(CommandError::precondition("activation resume id=0 is invalid"))
                } else if self.activation_resumes.iter().any(|record| record.id == *resume) {
                    Err(CommandError::precondition("activation resume already exists"))
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
                        return Err(CommandError::precondition("resume activation is not queued"));
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
                        let saved_for_vector = match (
                            context.current_saved_context,
                            context.current_saved_context_generation,
                        ) {
                            (Some(saved), Some(saved_generation)) => {
                                let Some(saved_record) =
                                    self.saved_contexts.iter().find(|saved_record| {
                                        saved_record.id == saved
                                            && saved_record.generation == saved_generation
                                            && saved_record.context == context.id
                                            && saved_record.context_generation == context.generation
                                            && saved_record.activation == *activation
                                            && saved_record.activation_generation
                                                == *activation_generation
                                            && saved_record.state == SavedContextState::Captured
                                    })
                                else {
                                    return Err(CommandError::precondition(
                                        "resume saved context generation is missing",
                                    ));
                                };
                                Some(saved_record)
                            }
                            (None, None) => None,
                            _ => {
                                return Err(CommandError::precondition(
                                    "resume saved context generation is required",
                                ));
                            }
                        };
                        if let Err(message) = self.validate_resume_vector_restore_records(
                            Some(context),
                            saved_for_vector,
                            *activation,
                            *activation_generation,
                        ) {
                            return Err(CommandError::precondition(message));
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
                    Err(CommandError::precondition("activation wait id=0 is invalid"))
                } else if *wait == 0 {
                    Err(CommandError::precondition("wait id=0 is invalid"))
                } else if blockers.is_empty() && deadline.is_none() {
                    Err(CommandError::precondition("activation wait requires blocker or deadline"))
                } else if self.activation_waits.iter().any(|record| record.id == *activation_wait) {
                    Err(CommandError::precondition("activation wait already exists"))
                } else if self.domains.wait.waits.iter().any(|record| record.id == *wait) {
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
                if self.domains.wait.waits.iter().any(|wait| {
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
                    return Err(CommandError::precondition("activation cleanup id=0 is invalid"));
                }
                if reason.is_empty() {
                    return Err(CommandError::precondition("activation cleanup reason is empty"));
                }
                if self.activation_cleanups.iter().any(|record| record.id == *cleanup) {
                    return Err(CommandError::precondition("activation cleanup already exists"));
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
                        if self.domains.wait.waits.iter().any(|record| {
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
            SemanticCommand::GrantCapability { operations, .. } if operations.is_empty() => {
                Err(CommandError::precondition("grant-capability requires at least one operation"))
            }
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
                        Err(CommandError::precondition("owner store generation is missing"))
                    }
                } else {
                    Err(CommandError::precondition("owner store generation is required"))
                }
            }
            SemanticCommand::RevokeCapability { cap } => {
                if self
                    .domains
                    .capability
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
                    Err(CommandError::precondition("create-wait requires blocker or deadline"))
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
                                Err(CommandError::precondition("owner store generation is missing"))
                            }
                        } else {
                            Err(CommandError::precondition("owner store generation is required"))
                        }
                    } else {
                        Ok(())
                    }
                }
            }
            SemanticCommand::ResolveWait { wait, .. }
            | SemanticCommand::CancelWait { wait, .. } => {
                if self
                    .domains
                    .wait
                    .waits
                    .iter()
                    .any(|record| record.id == *wait && record.state == WaitState::Pending)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("wait is not pending"))
                }
            }
            SemanticCommand::BeginCleanup { cleanup, store, generation, .. } => {
                if self.transactions.iter().any(|record| record.id == *cleanup) {
                    Err(CommandError::precondition("cleanup transaction id already exists"))
                } else if self
                    .stores
                    .iter()
                    .any(|record| record.id == *store && record.generation == *generation)
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("cleanup target store generation is missing"))
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
                    Err(CommandError::precondition("cleanup transaction is not active"))
                }
            }
            SemanticCommand::GrantCapability { .. } | SemanticCommand::RecordTrap { .. } => Ok(()),
        }
    }
}
