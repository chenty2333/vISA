use super::*;

impl SemanticGraph {
    pub(super) fn preflight_scheduler_command(
        &self,
        command: &SemanticCommand,
    ) -> Result<(), CommandError> {
        match command {
            SemanticCommand::RegisterHart { hart, hardware_id, label, boot, .. } => {
                if *hart == 0 {
                    Err(CommandError::precondition("hart id=0 is invalid"))
                } else if label.is_empty() {
                    Err(CommandError::precondition("hart label is empty"))
                } else if self.domains.scheduler.harts.iter().any(|record| record.id == *hart) {
                    Err(CommandError::precondition("hart already exists"))
                } else if self
                    .domains
                    .scheduler
                    .harts
                    .iter()
                    .any(|record| record.hardware_id == *hardware_id)
                {
                    Err(CommandError::precondition("hardware hart already exists"))
                } else if *boot && self.domains.scheduler.harts.iter().any(|record| record.boot) {
                    Err(CommandError::precondition("boot hart already exists"))
                } else {
                    Ok(())
                }
            }
            SemanticCommand::SetHartState { hart, hart_generation, reason, .. } => {
                if reason.is_empty() {
                    Err(CommandError::precondition("hart state reason is empty"))
                } else if self
                    .domains
                    .scheduler
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
                    .domains
                    .scheduler
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
                if self.domains.scheduler.harts.iter().any(|record| {
                    record.id != *hart
                        && record.current_activation == Some(*activation)
                        && record.current_activation_generation == Some(*activation_generation)
                }) {
                    return Err(CommandError::precondition(
                        "activation is already current on another hart",
                    ));
                }
                let Some(activation_record) =
                    self.domains.scheduler.runtime_activations.iter().find(|record| {
                        record.id == *activation
                            && record.generation == *activation_generation
                            && record.state == RuntimeActivationState::Running
                    })
                else {
                    return Err(CommandError::precondition(
                        "current activation generation is missing or not running",
                    ));
                };
                if !self.domains.scheduler.tasks.iter().any(|task| {
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
                    if !self.domains.lifecycle.stores.iter().any(|store_record| {
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
                    .domains
                    .scheduler
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
                } else if self
                    .domains
                    .scheduler
                    .runtime_activations
                    .iter()
                    .any(|record| record.id == *activation)
                {
                    Err(CommandError::precondition("activation already exists"))
                } else if !self
                    .domains
                    .scheduler
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
                        if self.domains.lifecycle.stores.iter().any(|record| {
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
                    .domains
                    .scheduler
                    .runnable_queues
                    .iter()
                    .any(|record| record.id == *queue)
                {
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
                let Some(queue_record) =
                    self.domains.scheduler.runnable_queues.iter().find(|record| {
                        record.id == *queue
                            && record.generation == *queue_generation
                            && record.state == RunnableQueueState::Active
                    })
                else {
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
                let Some(_hart_record) = self.domains.scheduler.harts.iter().find(|record| {
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
                let Some(queue_record) = self
                    .domains
                    .scheduler
                    .runnable_queues
                    .iter()
                    .find(|record| record.id == *queue)
                else {
                    return Err(CommandError::precondition("runnable queue is missing"));
                };
                if queue_record.state != RunnableQueueState::Active {
                    return Err(CommandError::precondition("runnable queue is not active"));
                }
                if self.domains.scheduler.runnable_queues.iter().any(|record| {
                    record.entries.iter().any(|entry| entry.activation == *activation)
                }) {
                    return Err(CommandError::precondition("activation already queued"));
                }
                let Some(activation_record) = self
                    .domains
                    .scheduler
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
                let Some(owner_task) = self.domains.scheduler.tasks.iter().find(|task| {
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
                    if !self.domains.lifecycle.stores.iter().any(|record| {
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
                    .domains
                    .scheduler
                    .runnable_queues
                    .iter()
                    .find(|record| record.id == *queue)
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
                } else if self
                    .domains
                    .scheduler
                    .activation_contexts
                    .iter()
                    .any(|record| record.id == *context)
                {
                    Err(CommandError::precondition("activation context already exists"))
                } else if self.domains.scheduler.activation_contexts.iter().any(|record| {
                    record.activation == *activation
                        && record.state != ActivationContextState::Dropped
                }) {
                    Err(CommandError::precondition("activation already has a live context"))
                } else if self.domains.scheduler.runtime_activations.iter().any(|record| {
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
                } else if self
                    .domains
                    .scheduler
                    .saved_contexts
                    .iter()
                    .any(|record| record.id == *saved_context)
                {
                    Err(CommandError::precondition("saved context already exists"))
                } else {
                    let Some(context_record) =
                        self.domains.scheduler.activation_contexts.iter().find(|record| {
                            record.id == *context
                                && record.generation == *context_generation
                                && record.state != ActivationContextState::Dropped
                        })
                    else {
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
                } else if self
                    .domains
                    .scheduler
                    .activation_contexts
                    .iter()
                    .any(|record| record.id == *context)
                {
                    Err(CommandError::precondition("activation context already exists"))
                } else if self
                    .domains
                    .scheduler
                    .saved_contexts
                    .iter()
                    .any(|record| record.id == *saved_context)
                {
                    Err(CommandError::precondition("saved context already exists"))
                } else {
                    let Some(preemption_record) =
                        self.domains.scheduler.preemptions.iter().find(|record| {
                            record.id == *preemption
                                && record.generation == *preemption_generation
                                && record.state == PreemptionState::Applied
                        })
                    else {
                        return Err(CommandError::precondition("preemption generation is missing"));
                    };
                    let Some(activation) =
                        self.domains.scheduler.runtime_activations.iter().find(|record| {
                            record.id == preemption_record.activation
                                && record.generation
                                    == preemption_record.activation_generation_after
                                && !matches!(
                                    record.state,
                                    RuntimeActivationState::Dead | RuntimeActivationState::Exited
                                )
                        })
                    else {
                        return Err(CommandError::precondition(
                            "preempted activation generation is missing or dead",
                        ));
                    };
                    if self.domains.scheduler.activation_contexts.iter().any(|record| {
                        record.activation == activation.id
                            && record.state != ActivationContextState::Dropped
                    }) {
                        Err(CommandError::precondition("activation already has live context"))
                    } else if !self.domains.scheduler.tasks.iter().any(|task| {
                        task.id == activation.owner_task
                            && task.generation == activation.owner_task_generation
                    }) {
                        Err(CommandError::precondition(
                            "preempted activation owner task generation is missing",
                        ))
                    } else if let Some(store) = activation.owner_store {
                        if let Some(generation) = activation.owner_store_generation {
                            if self.domains.lifecycle.stores.iter().any(|record| {
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
                    .domains
                    .scheduler
                    .timer_interrupts
                    .iter()
                    .any(|record| record.id == *interrupt || record.timer_epoch == *timer_epoch)
                {
                    Err(CommandError::precondition("timer interrupt already exists"))
                } else if let Some(previous) = self
                    .domains
                    .scheduler
                    .timer_interrupts
                    .iter()
                    .map(|record| record.timer_epoch)
                    .max()
                    && *timer_epoch <= previous
                {
                    Err(CommandError::precondition("timer interrupt epoch must be monotonic"))
                } else if !self.domains.scheduler.harts.iter().any(|record| {
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
                    if self.domains.scheduler.runtime_activations.iter().any(|record| {
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
                } else if self.domains.scheduler.ipi_events.iter().any(|record| record.id == *ipi) {
                    Err(CommandError::precondition("ipi event already exists"))
                } else if !self.domains.scheduler.harts.iter().any(|record| {
                    record.id == *source_hart
                        && record.generation == *source_hart_generation
                        && !matches!(record.state, HartState::Offline | HartState::Faulted)
                }) {
                    Err(CommandError::precondition(
                        "ipi source hart generation is missing or inactive",
                    ))
                } else if !self.domains.scheduler.harts.iter().any(|record| {
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
                } else if self
                    .domains
                    .scheduler
                    .preemptions
                    .iter()
                    .any(|record| record.id == *preemption)
                {
                    Err(CommandError::precondition("preemption already exists"))
                } else if !self
                    .domains
                    .scheduler
                    .runnable_queues
                    .iter()
                    .any(|record| record.id == *queue && record.state == RunnableQueueState::Active)
                {
                    Err(CommandError::precondition("preemption queue is missing or inactive"))
                } else if self.domains.scheduler.runnable_queues.iter().any(|record| {
                    record.entries.iter().any(|entry| entry.activation == *activation)
                }) {
                    Err(CommandError::precondition("activation already queued"))
                } else {
                    let Some(timer) =
                        self.domains.scheduler.timer_interrupts.iter().find(|record| {
                            record.id == *timer_interrupt
                                && record.generation == *timer_interrupt_generation
                        })
                    else {
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
                    let Some(record) =
                        self.domains.scheduler.runtime_activations.iter().find(|record| {
                            record.id == *activation
                                && record.generation == *activation_generation
                                && record.state == RuntimeActivationState::Running
                                && record.runnable_queue.is_none()
                                && record.runnable_queue_generation.is_none()
                        })
                    else {
                        return Err(CommandError::precondition(
                            "preemption target activation generation is not running",
                        ));
                    };
                    let Some(owner_task) = self.domains.scheduler.tasks.iter().find(|task| {
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
                        if !self.domains.lifecycle.stores.iter().any(|store_record| {
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
                } else if self
                    .domains
                    .scheduler
                    .scheduler_decisions
                    .iter()
                    .any(|record| record.id == *decision)
                {
                    Err(CommandError::precondition("scheduler decision already exists"))
                } else {
                    let Some(queue_record) =
                        self.domains.scheduler.runnable_queues.iter().find(|record| {
                            record.id == *queue
                                && record.generation == *queue_generation
                                && record.state == RunnableQueueState::Active
                        })
                    else {
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
                    let Some(activation) =
                        self.domains.scheduler.runtime_activations.iter().find(|record| {
                            record.id == *selected_activation
                                && record.generation == *selected_activation_generation
                                && record.state == RuntimeActivationState::Runnable
                                && record.runnable_queue == Some(*queue)
                                && record.runnable_queue_generation == Some(*queue_generation)
                        })
                    else {
                        return Err(CommandError::precondition(
                            "scheduler decision activation generation is not runnable",
                        ));
                    };
                    if self.domains.scheduler.tasks.iter().any(|task| {
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
            _ => unreachable!("preflight handler called with wrong command domain"),
        }
    }
}
