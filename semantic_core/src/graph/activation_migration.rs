use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_runnable_activation_migration(
        &self,
        migration: ActivationMigrationId,
        activation: ActivationId,
        activation_generation: Generation,
        source_queue: RunnableQueueId,
        source_queue_generation: Generation,
        target_queue: RunnableQueueId,
        target_queue_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        reason: &str,
    ) -> Result<(), &'static str> {
        if migration == 0 {
            return Err("activation migration id=0 is invalid");
        }
        if reason.is_empty() {
            return Err("activation migration reason is empty");
        }
        if self
            .activation_migrations
            .iter()
            .any(|record| record.id == migration)
        {
            return Err("activation migration already exists");
        }
        if source_hart == target_hart {
            return Err("activation migration requires distinct harts");
        }
        if source_queue == target_queue {
            return Err("activation migration requires distinct queues");
        }
        let Some(source_hart_record) = self
            .harts
            .iter()
            .find(|record| record.id == source_hart && record.generation == source_hart_generation)
        else {
            return Err("activation migration source hart generation is missing");
        };
        if matches!(
            source_hart_record.state,
            HartState::Offline | HartState::Faulted | HartState::Parked
        ) {
            return Err("activation migration source hart is inactive");
        }
        let Some(target_hart_record) = self
            .harts
            .iter()
            .find(|record| record.id == target_hart && record.generation == target_hart_generation)
        else {
            return Err("activation migration target hart generation is missing");
        };
        if matches!(
            target_hart_record.state,
            HartState::Offline | HartState::Faulted | HartState::Parked
        ) {
            return Err("activation migration target hart is inactive");
        }
        let Some(source) = self.runnable_queues.iter().find(|record| {
            record.id == source_queue
                && record.generation == source_queue_generation
                && record.state == RunnableQueueState::Active
        }) else {
            return Err("activation migration source queue generation is missing");
        };
        if source.owner_hart != Some(source_hart)
            || source
                .owner_hart_generation
                .is_none_or(|generation| generation > source_hart_generation)
        {
            return Err("activation migration source queue owner mismatch");
        }
        if !source.entries.iter().any(|entry| {
            entry.activation == activation && entry.activation_generation == activation_generation
        }) {
            return Err("activation migration source queue entry is missing");
        }
        let Some(target) = self.runnable_queues.iter().find(|record| {
            record.id == target_queue
                && record.generation == target_queue_generation
                && record.state == RunnableQueueState::Active
        }) else {
            return Err("activation migration target queue generation is missing");
        };
        if target.owner_hart != Some(target_hart)
            || target
                .owner_hart_generation
                .is_none_or(|generation| generation > target_hart_generation)
        {
            return Err("activation migration target queue owner mismatch");
        }
        if target
            .entries
            .iter()
            .any(|entry| entry.activation == activation)
        {
            return Err("activation migration target queue already contains activation");
        }
        let Some(activation_record) = self.runtime_activations.iter().find(|record| {
            record.id == activation
                && record.generation == activation_generation
                && record.state == RuntimeActivationState::Runnable
                && record.runnable_queue == Some(source_queue)
                && record.runnable_queue_generation == Some(source_queue_generation)
        }) else {
            return Err(
                "activation migration activation generation is not runnable on source queue",
            );
        };
        if self.harts.iter().any(|hart| {
            hart.current_activation == Some(activation)
                && hart.current_activation_generation == Some(activation_generation)
        }) {
            return Err("activation migration activation is currently running");
        }
        if !self.tasks.iter().any(|task| {
            task.id == activation_record.owner_task
                && task.generation == activation_record.owner_task_generation
                && matches!(task.state, TaskState::Runnable | TaskState::Running)
        }) {
            return Err("activation migration owner task generation is missing or not runnable");
        }
        if let Some(store) = activation_record.owner_store {
            let Some(generation) = activation_record.owner_store_generation else {
                return Err("activation migration owner store generation is required");
            };
            if !self.stores.iter().any(|store_record| {
                store_record.id == store
                    && store_record.generation == generation
                    && store_record.state != StoreState::Dead
            }) {
                return Err("activation migration owner store generation is missing or dead");
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn migrate_runnable_activation_with_id(
        &mut self,
        migration: ActivationMigrationId,
        activation: ActivationId,
        activation_generation: Generation,
        source_queue: RunnableQueueId,
        source_queue_generation: Generation,
        target_queue: RunnableQueueId,
        target_queue_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_runnable_activation_migration(
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
            )
            .is_err()
        {
            return false;
        }
        let Some(source_index) = self.runnable_queues.iter().position(|record| {
            record.id == source_queue && record.generation == source_queue_generation
        }) else {
            return false;
        };
        let Some(source_entry_index) =
            self.runnable_queues[source_index]
                .entries
                .iter()
                .position(|entry| {
                    entry.activation == activation
                        && entry.activation_generation == activation_generation
                })
        else {
            return false;
        };
        let Some(target_index) = self.runnable_queues.iter().position(|record| {
            record.id == target_queue && record.generation == target_queue_generation
        }) else {
            return false;
        };
        let Some(activation_index) = self.runtime_activations.iter().position(|record| {
            record.id == activation && record.generation == activation_generation
        }) else {
            return false;
        };
        let Some(source_queue_owner_hart_generation) =
            self.runnable_queues[source_index].owner_hart_generation
        else {
            return false;
        };
        let Some(target_queue_owner_hart_generation) =
            self.runnable_queues[target_index].owner_hart_generation
        else {
            return false;
        };

        self.next_activation_migration_id = self.next_activation_migration_id.max(migration + 1);
        self.runnable_queues[source_index]
            .entries
            .remove(source_entry_index);
        let owner_task = self.runtime_activations[activation_index].owner_task;
        let owner_task_generation =
            self.runtime_activations[activation_index].owner_task_generation;
        self.runtime_activations[activation_index].generation += 1;
        let activation_generation_after = self.runtime_activations[activation_index].generation;
        self.runtime_activations[activation_index].runnable_queue = Some(target_queue);
        self.runtime_activations[activation_index].runnable_queue_generation =
            Some(target_queue_generation);

        let migration_event = self.event_log.push(
            "scheduler",
            EventKind::ActivationMigrated {
                migration,
                activation,
                from_generation: activation_generation,
                to_generation: activation_generation_after,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                source_queue,
                source_queue_generation,
                target_queue,
                target_queue_generation,
                generation: 1,
            },
        );
        let dequeued_event = self.event_log.push(
            "scheduler",
            EventKind::RunnableDequeued {
                queue: source_queue,
                activation,
                activation_generation,
            },
        );
        let queued_event = self.event_log.push(
            "scheduler",
            EventKind::RunnableQueued {
                queue: target_queue,
                activation,
                activation_generation: activation_generation_after,
            },
        );
        self.runtime_activations[activation_index].last_event =
            Some(migration_event.max(dequeued_event).max(queued_event));
        self.runnable_queues[target_index]
            .entries
            .push(RunnableQueueEntry {
                activation,
                activation_generation: activation_generation_after,
                enqueued_at: queued_event,
            });
        self.activation_migrations.push(ActivationMigrationRecord {
            id: migration,
            activation,
            activation_generation_before: activation_generation,
            activation_generation_after,
            owner_task,
            owner_task_generation,
            source_hart,
            source_hart_generation,
            target_hart,
            target_hart_generation,
            source_queue,
            source_queue_generation,
            source_queue_owner_hart_generation,
            target_queue,
            target_queue_generation,
            target_queue_owner_hart_generation,
            generation: 1,
            state: ActivationMigrationState::Applied,
            migrated_at_event: migration_event,
            reason: reason.to_string(),
            note: note.to_string(),
        });
        let _ = self.push_hart_event_attribution(
            source_hart,
            source_hart_generation,
            migration_event,
            "ActivationMigrationSourceRecorded",
            Some(activation),
            Some(activation_generation),
            note,
        );
        let _ = self.push_hart_event_attribution(
            target_hart,
            target_hart_generation,
            migration_event,
            "ActivationMigrationTargetRecorded",
            Some(activation),
            Some(activation_generation_after),
            note,
        );
        true
    }

    pub fn activation_migrations(&self) -> &[ActivationMigrationRecord] {
        &self.activation_migrations
    }

    pub fn activation_migration_count(&self) -> usize {
        self.activation_migrations.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_activation_migration_event_for_test(
        &mut self,
        migration: ActivationMigrationId,
        event: EventId,
    ) {
        if let Some(record) = self
            .activation_migrations
            .iter_mut()
            .find(|record| record.id == migration)
        {
            record.migrated_at_event = event;
        }
    }

    pub fn check_activation_migration_invariants(&self) -> Result<(), SemanticInvariantError> {
        for migration in &self.activation_migrations {
            if migration.id == 0
                || migration.generation == 0
                || migration.state != ActivationMigrationState::Applied
                || migration.activation == 0
                || migration.activation_generation_before == 0
                || migration.activation_generation_after <= migration.activation_generation_before
                || migration.owner_task == 0
                || migration.owner_task_generation == 0
                || migration.source_hart == 0
                || migration.target_hart == 0
                || migration.source_hart == migration.target_hart
                || migration.source_queue == 0
                || migration.target_queue == 0
                || migration.source_queue == migration.target_queue
            {
                return Err(SemanticInvariantError::ActivationMigrationInvalid {
                    migration: migration.id,
                });
            }
            self.check_activation_migration_hart_ref(
                migration.id,
                migration.source_hart,
                migration.source_hart_generation,
            )?;
            self.check_activation_migration_hart_ref(
                migration.id,
                migration.target_hart,
                migration.target_hart_generation,
            )?;
            self.check_activation_migration_queue_ref(
                migration.id,
                migration.source_queue,
                migration.source_queue_generation,
                migration.source_hart,
                migration.source_queue_owner_hart_generation,
            )?;
            self.check_activation_migration_queue_ref(
                migration.id,
                migration.target_queue,
                migration.target_queue_generation,
                migration.target_hart,
                migration.target_queue_owner_hart_generation,
            )?;
            let Some(activation) = self
                .runtime_activations
                .iter()
                .find(|record| record.id == migration.activation)
            else {
                return Err(
                    SemanticInvariantError::ActivationMigrationMissingActivation {
                        migration: migration.id,
                        activation: migration.activation,
                    },
                );
            };
            if activation.generation < migration.activation_generation_after {
                return Err(
                    SemanticInvariantError::ActivationMigrationMissingActivation {
                        migration: migration.id,
                        activation: migration.activation,
                    },
                );
            }
            if activation.generation == migration.activation_generation_after
                && (activation.state != RuntimeActivationState::Runnable
                    || activation.runnable_queue != Some(migration.target_queue)
                    || activation.runnable_queue_generation
                        != Some(migration.target_queue_generation))
            {
                return Err(
                    SemanticInvariantError::ActivationMigrationQueueEntryMismatch {
                        migration: migration.id,
                        activation: migration.activation,
                    },
                );
            }
            let Some(target_queue) = self
                .runnable_queues
                .iter()
                .find(|record| record.id == migration.target_queue)
            else {
                return Err(SemanticInvariantError::ActivationMigrationMissingQueue {
                    migration: migration.id,
                    queue: migration.target_queue,
                });
            };
            if target_queue.generation == migration.target_queue_generation
                && !target_queue.entries.iter().any(|entry| {
                    entry.activation == migration.activation
                        && entry.activation_generation == migration.activation_generation_after
                })
                && activation.generation == migration.activation_generation_after
            {
                return Err(
                    SemanticInvariantError::ActivationMigrationQueueEntryMismatch {
                        migration: migration.id,
                        activation: migration.activation,
                    },
                );
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == migration.migrated_at_event
                    && matches!(
                        &event.kind,
                        EventKind::ActivationMigrated {
                            migration: event_migration,
                            activation,
                            from_generation,
                            to_generation,
                            source_hart,
                            source_hart_generation,
                            target_hart,
                            target_hart_generation,
                            source_queue,
                            source_queue_generation,
                            target_queue,
                            target_queue_generation,
                            generation,
                        } if *event_migration == migration.id
                            && *activation == migration.activation
                            && *from_generation == migration.activation_generation_before
                            && *to_generation == migration.activation_generation_after
                            && *source_hart == migration.source_hart
                            && *source_hart_generation == migration.source_hart_generation
                            && *target_hart == migration.target_hart
                            && *target_hart_generation == migration.target_hart_generation
                            && *source_queue == migration.source_queue
                            && *source_queue_generation == migration.source_queue_generation
                            && *target_queue == migration.target_queue
                            && *target_queue_generation == migration.target_queue_generation
                            && *generation == migration.generation
                    )
            }) {
                return Err(SemanticInvariantError::ActivationMigrationMissingEvent {
                    migration: migration.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                matches!(
                    &event.kind,
                    EventKind::RunnableDequeued {
                        queue,
                        activation,
                        activation_generation,
                    } if *queue == migration.source_queue
                        && *activation == migration.activation
                        && *activation_generation == migration.activation_generation_before
                )
            }) || !self.event_log.events.iter().any(|event| {
                matches!(
                    &event.kind,
                    EventKind::RunnableQueued {
                        queue,
                        activation,
                        activation_generation,
                    } if *queue == migration.target_queue
                        && *activation == migration.activation
                        && *activation_generation == migration.activation_generation_after
                )
            }) {
                return Err(
                    SemanticInvariantError::ActivationMigrationQueueEntryMismatch {
                        migration: migration.id,
                        activation: migration.activation,
                    },
                );
            }
            if !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == migration.migrated_at_event
                    && attribution.hart == migration.source_hart
                    && attribution.hart_generation == migration.source_hart_generation
                    && attribution.event_kind == "ActivationMigrationSourceRecorded"
                    && attribution.activation == Some(migration.activation)
                    && attribution.activation_generation
                        == Some(migration.activation_generation_before)
            }) || !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == migration.migrated_at_event
                    && attribution.hart == migration.target_hart
                    && attribution.hart_generation == migration.target_hart_generation
                    && attribution.event_kind == "ActivationMigrationTargetRecorded"
                    && attribution.activation == Some(migration.activation)
                    && attribution.activation_generation
                        == Some(migration.activation_generation_after)
            }) {
                return Err(
                    SemanticInvariantError::ActivationMigrationMissingHartEventAttribution {
                        migration: migration.id,
                        event: migration.migrated_at_event,
                    },
                );
            }
        }
        Ok(())
    }

    fn check_activation_migration_hart_ref(
        &self,
        migration: ActivationMigrationId,
        hart: HartId,
        generation: Generation,
    ) -> Result<(), SemanticInvariantError> {
        let Some(record) = self.harts.iter().find(|record| record.id == hart) else {
            return Err(SemanticInvariantError::ActivationMigrationMissingHart { migration, hart });
        };
        if record.generation < generation {
            return Err(
                SemanticInvariantError::ActivationMigrationHartGenerationMismatch {
                    migration,
                    hart,
                },
            );
        }
        Ok(())
    }

    fn check_activation_migration_queue_ref(
        &self,
        migration: ActivationMigrationId,
        queue: RunnableQueueId,
        queue_generation: Generation,
        owner_hart: HartId,
        owner_hart_generation: Generation,
    ) -> Result<(), SemanticInvariantError> {
        let Some(record) = self
            .runnable_queues
            .iter()
            .find(|record| record.id == queue)
        else {
            return Err(SemanticInvariantError::ActivationMigrationMissingQueue {
                migration,
                queue,
            });
        };
        if record.generation < queue_generation
            || (record.generation == queue_generation
                && (record.owner_hart != Some(owner_hart)
                    || record.owner_hart_generation != Some(owner_hart_generation)))
        {
            return Err(
                SemanticInvariantError::ActivationMigrationQueueOwnerMismatch { migration, queue },
            );
        }
        Ok(())
    }
}
