use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticCommand {
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
