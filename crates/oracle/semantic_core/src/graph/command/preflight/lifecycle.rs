use super::*;

impl SemanticGraph {
    pub(super) fn preflight_lifecycle_command(
        &self,
        command: &SemanticCommand,
    ) -> Result<(), CommandError> {
        match command {
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
                } else if self
                    .domains
                    .scheduler
                    .activation_resumes
                    .iter()
                    .any(|record| record.id == *resume)
                {
                    Err(CommandError::precondition("activation resume already exists"))
                } else {
                    let Some(decision) =
                        self.domains.scheduler.scheduler_decisions.iter().find(|record| {
                            record.id == *scheduler_decision
                                && record.generation == *scheduler_decision_generation
                                && record.state == SchedulerDecisionState::Recorded
                                && record.selected_activation == *activation
                                && record.selected_activation_generation == *activation_generation
                        })
                    else {
                        return Err(CommandError::precondition(
                            "resume scheduler decision generation is missing or consumed",
                        ));
                    };
                    let Some(queue) =
                        self.domains.scheduler.runnable_queues.iter().find(|record| {
                            record.id == decision.queue
                                && record.generation == decision.queue_generation
                                && record.state == RunnableQueueState::Active
                        })
                    else {
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
                    let Some(record) =
                        self.domains.scheduler.runtime_activations.iter().find(|record| {
                            record.id == *activation
                                && record.generation == *activation_generation
                                && record.state == RuntimeActivationState::Runnable
                                && record.runnable_queue == Some(decision.queue)
                                && record.runnable_queue_generation
                                    == Some(decision.queue_generation)
                        })
                    else {
                        return Err(CommandError::precondition(
                            "resume activation generation is not runnable",
                        ));
                    };
                    if !self.domains.scheduler.tasks.iter().any(|task| {
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
                        if !self.domains.lifecycle.stores.iter().any(|store_record| {
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
                    if let Some(context) =
                        self.domains.scheduler.activation_contexts.iter().find(|context| {
                            context.activation == *activation
                                && context.activation_generation == *activation_generation
                                && context.state != ActivationContextState::Dropped
                        })
                    {
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
                                    self.domains.scheduler.saved_contexts.iter().find(
                                        |saved_record| {
                                            saved_record.id == saved
                                                && saved_record.generation == saved_generation
                                                && saved_record.context == context.id
                                                && saved_record.context_generation
                                                    == context.generation
                                                && saved_record.activation == *activation
                                                && saved_record.activation_generation
                                                    == *activation_generation
                                                && saved_record.state == SavedContextState::Captured
                                        },
                                    )
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
                } else if self
                    .domains
                    .scheduler
                    .activation_waits
                    .iter()
                    .any(|record| record.id == *activation_wait)
                {
                    Err(CommandError::precondition("activation wait already exists"))
                } else if self.domains.wait.waits.iter().any(|record| record.id == *wait) {
                    Err(CommandError::precondition("wait already exists"))
                } else {
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
                            "activation wait target generation is not running",
                        ));
                    };
                    if !self.domains.scheduler.tasks.iter().any(|task| {
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
                        if !self.domains.lifecycle.stores.iter().any(|store_record| {
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
                let Some(record) = self.domains.scheduler.activation_waits.iter().find(|record| {
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
                if self
                    .domains
                    .scheduler
                    .activation_cleanups
                    .iter()
                    .any(|record| record.id == *cleanup)
                {
                    return Err(CommandError::precondition("activation cleanup already exists"));
                }
                if !self.domains.lifecycle.stores.iter().any(|record| {
                    record.id == *store
                        && record.generation == *store_generation
                        && record.state != StoreState::Dead
                }) {
                    return Err(CommandError::precondition(
                        "cleanup target store generation is missing or dead",
                    ));
                }
                if !self.domains.scheduler.runtime_activations.iter().any(|record| {
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
                        .domains
                        .lifecycle
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
                        && !self.domains.scheduler.tasks.iter().any(|record| record.id == *task)
                    {
                        return Err(CommandError::precondition("owner task is missing"));
                    }
                    if let Some(store) = owner_store {
                        if let Some(generation) = owner_store_generation {
                            if self.domains.lifecycle.stores.iter().any(|record| {
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
                if self.domains.lifecycle.transactions.iter().any(|record| record.id == *cleanup) {
                    Err(CommandError::precondition("cleanup transaction id already exists"))
                } else if self
                    .domains
                    .lifecycle
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
                    .domains
                    .lifecycle
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
            _ => unreachable!("preflight handler called with wrong command domain"),
        }
    }
}
