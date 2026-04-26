use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_remote_preempt_activation(
        &self,
        remote_preempt: RemotePreemptId,
        ipi: IpiEventId,
        ipi_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        queue: RunnableQueueId,
    ) -> Result<(), &'static str> {
        if remote_preempt == 0 {
            return Err("remote preempt id=0 is invalid");
        }
        if self
            .remote_preempts
            .iter()
            .any(|record| record.id == remote_preempt)
        {
            return Err("remote preempt already exists");
        }
        if source_hart == target_hart {
            return Err("remote preempt source and target harts must differ");
        }
        let Some(ipi_record) = self
            .ipi_events
            .iter()
            .find(|record| record.id == ipi && record.generation == ipi_generation)
        else {
            return Err("remote preempt ipi generation is missing");
        };
        let Some(source) = self
            .harts
            .iter()
            .find(|record| record.id == source_hart && record.generation >= source_hart_generation)
        else {
            return Err("remote preempt source hart generation is missing");
        };
        if matches!(source.state, HartState::Offline | HartState::Faulted) {
            return Err("remote preempt source hart is inactive");
        }
        let Some(target) = self
            .harts
            .iter()
            .find(|record| record.id == target_hart && record.generation == target_hart_generation)
        else {
            return Err("remote preempt target hart generation is missing");
        };
        if target.state != HartState::Running
            || target.current_activation != Some(activation)
            || target.current_activation_generation != Some(activation_generation)
        {
            return Err("remote preempt target hart current activation mismatch");
        }
        if ipi_record.kind != IpiEventKind::SchedulerKick
            || ipi_record.source_hart != source_hart
            || ipi_record.target_hart != target_hart
            || source_hart_generation < ipi_record.source_hart_generation
            || target_hart_generation < ipi_record.target_hart_generation
        {
            return Err("remote preempt ipi source/target mismatch");
        }
        if self.runnable_queues.iter().any(|record| {
            record
                .entries
                .iter()
                .any(|entry| entry.activation == activation)
        }) {
            return Err("remote preempt activation already queued");
        }
        let Some(queue_record) = self
            .runnable_queues
            .iter()
            .find(|record| record.id == queue && record.state == RunnableQueueState::Active)
        else {
            return Err("remote preempt queue is missing or inactive");
        };
        if queue_record.owner_hart != Some(target_hart)
            || queue_record
                .owner_hart_generation
                .is_none_or(|generation| generation > target_hart_generation)
        {
            return Err("remote preempt queue is not owned by target hart");
        }
        let Some(activation_record) = self.runtime_activations.iter().find(|record| {
            record.id == activation
                && record.generation == activation_generation
                && record.state == RuntimeActivationState::Running
                && record.runnable_queue.is_none()
                && record.runnable_queue_generation.is_none()
        }) else {
            return Err("remote preempt activation generation is not running");
        };
        if !self.tasks.iter().any(|task| {
            task.id == activation_record.owner_task
                && task.generation == activation_record.owner_task_generation
                && matches!(task.state, TaskState::Runnable | TaskState::Running)
        }) {
            return Err("remote preempt owner task generation is missing or not runnable");
        }
        if let Some(store) = activation_record.owner_store {
            let Some(generation) = activation_record.owner_store_generation else {
                return Err("remote preempt owner store generation is required");
            };
            if !self.stores.iter().any(|store_record| {
                store_record.id == store
                    && store_record.generation == generation
                    && store_record.state != StoreState::Dead
            }) {
                return Err("remote preempt owner store generation is missing or dead");
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn remote_preempt_activation_with_id(
        &mut self,
        remote_preempt: RemotePreemptId,
        ipi: IpiEventId,
        ipi_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        activation: ActivationId,
        activation_generation: Generation,
        queue: RunnableQueueId,
        note: &str,
    ) -> bool {
        if self
            .validate_remote_preempt_activation(
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
            )
            .is_err()
        {
            return false;
        }

        let Some(target_hart_index) = self.harts.iter().position(|record| {
            record.id == target_hart && record.generation == target_hart_generation
        }) else {
            return false;
        };
        let Some(activation_index) = self.runtime_activations.iter().position(|record| {
            record.id == activation && record.generation == activation_generation
        }) else {
            return false;
        };
        let Some(queue_index) = self
            .runnable_queues
            .iter()
            .position(|record| record.id == queue && record.state == RunnableQueueState::Active)
        else {
            return false;
        };

        self.next_remote_preempt_id = self.next_remote_preempt_id.max(remote_preempt + 1);
        self.harts[target_hart_index].state = HartState::Idle;
        self.harts[target_hart_index].generation += 1;
        self.harts[target_hart_index].current_activation = None;
        self.harts[target_hart_index].current_activation_generation = None;
        self.harts[target_hart_index].current_task = None;
        self.harts[target_hart_index].current_task_generation = None;
        self.harts[target_hart_index].current_store = None;
        self.harts[target_hart_index].current_store_generation = None;
        if !note.is_empty() {
            self.harts[target_hart_index].note = note.to_string();
        }
        let target_hart_generation_after = self.harts[target_hart_index].generation;
        let clear_event = self.event_log.push(
            "scheduler",
            EventKind::HartCurrentActivationCleared {
                hart: target_hart,
                activation,
                activation_generation,
                reason: "remote-preempt".to_string(),
                generation: target_hart_generation_after,
            },
        );
        self.harts[target_hart_index].last_event = Some(clear_event);
        self.harts[target_hart_index].last_current_event = Some(clear_event);
        let _ = self.push_hart_event_attribution(
            target_hart,
            target_hart_generation_after,
            clear_event,
            "HartCurrentActivationCleared",
            Some(activation),
            Some(activation_generation),
            note,
        );

        let activation_from = self.runtime_activations[activation_index].state;
        self.runtime_activations[activation_index].state = RuntimeActivationState::Runnable;
        self.runtime_activations[activation_index].generation += 1;
        let activation_generation_after = self.runtime_activations[activation_index].generation;
        let queue_generation = self.runnable_queues[queue_index].generation;
        self.runtime_activations[activation_index].runnable_queue = Some(queue);
        self.runtime_activations[activation_index].runnable_queue_generation =
            Some(queue_generation);

        let remote_event = self.event_log.push(
            "scheduler",
            EventKind::RemoteActivationPreempted {
                remote_preempt,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation_before: target_hart_generation,
                target_hart_generation_after,
                activation,
                from_generation: activation_generation,
                to_generation: activation_generation_after,
                queue,
                queue_generation,
                generation: 1,
            },
        );
        let state_event = self.event_log.push(
            "scheduler",
            EventKind::RuntimeActivationStateChanged {
                activation,
                from: activation_from,
                to: RuntimeActivationState::Runnable,
                generation: activation_generation_after,
            },
        );
        let queued_event = self.event_log.push(
            "scheduler",
            EventKind::RunnableQueued {
                queue,
                activation,
                activation_generation: activation_generation_after,
            },
        );
        self.runtime_activations[activation_index].last_event =
            Some(remote_event.max(state_event).max(queued_event));
        self.runnable_queues[queue_index]
            .entries
            .push(RunnableQueueEntry {
                activation,
                activation_generation: activation_generation_after,
                enqueued_at: queued_event,
            });
        self.remote_preempts.push(RemotePreemptRecord {
            id: remote_preempt,
            ipi,
            ipi_generation,
            source_hart,
            source_hart_generation,
            target_hart,
            target_hart_generation_before: target_hart_generation,
            target_hart_generation_after,
            activation,
            activation_generation_before: activation_generation,
            activation_generation_after,
            queue,
            queue_generation,
            generation: 1,
            state: RemotePreemptState::Applied,
            preempted_at_event: remote_event,
            note: note.to_string(),
        });
        let _ = self.push_hart_event_attribution(
            source_hart,
            source_hart_generation,
            remote_event,
            "RemotePreemptSourceRecorded",
            None,
            None,
            note,
        );
        let _ = self.push_hart_event_attribution(
            target_hart,
            target_hart_generation_after,
            remote_event,
            "RemotePreemptTargetRecorded",
            Some(activation),
            Some(activation_generation_after),
            note,
        );
        true
    }

    pub fn remote_preempts(&self) -> &[RemotePreemptRecord] {
        &self.remote_preempts
    }

    pub fn remote_preempt_count(&self) -> usize {
        self.remote_preempts.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_remote_preempt_ipi_generation_for_test(
        &mut self,
        remote_preempt: RemotePreemptId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .remote_preempts
            .iter_mut()
            .find(|record| record.id == remote_preempt)
        {
            record.ipi_generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_remote_preempt_event_for_test(
        &mut self,
        remote_preempt: RemotePreemptId,
        event: EventId,
    ) {
        if let Some(record) = self
            .remote_preempts
            .iter_mut()
            .find(|record| record.id == remote_preempt)
        {
            record.preempted_at_event = event;
        }
    }

    pub fn check_remote_preempt_invariants(&self) -> Result<(), SemanticInvariantError> {
        for remote in &self.remote_preempts {
            if remote.id == 0
                || remote.generation == 0
                || remote.ipi == 0
                || remote.ipi_generation == 0
                || remote.source_hart == 0
                || remote.target_hart == 0
                || remote.source_hart == remote.target_hart
                || remote.activation == 0
                || remote.queue == 0
            {
                return Err(SemanticInvariantError::RemotePreemptInvalid {
                    remote_preempt: remote.id,
                });
            }
            let Some(ipi) = self.ipi_events.iter().find(|record| {
                record.id == remote.ipi && record.generation == remote.ipi_generation
            }) else {
                return Err(SemanticInvariantError::RemotePreemptMissingIpi {
                    remote_preempt: remote.id,
                    ipi: remote.ipi,
                });
            };
            if ipi.kind != IpiEventKind::SchedulerKick
                || ipi.source_hart != remote.source_hart
                || ipi.target_hart != remote.target_hart
                || remote.source_hart_generation < ipi.source_hart_generation
                || remote.target_hart_generation_before < ipi.target_hart_generation
            {
                return Err(SemanticInvariantError::RemotePreemptIpiMismatch {
                    remote_preempt: remote.id,
                    ipi: remote.ipi,
                });
            }
            let Some(source) = self
                .harts
                .iter()
                .find(|record| record.id == remote.source_hart)
            else {
                return Err(SemanticInvariantError::RemotePreemptMissingHart {
                    remote_preempt: remote.id,
                    hart: remote.source_hart,
                });
            };
            if source.generation < remote.source_hart_generation {
                return Err(
                    SemanticInvariantError::RemotePreemptHartGenerationMismatch {
                        remote_preempt: remote.id,
                        hart: remote.source_hart,
                    },
                );
            }
            let Some(target) = self
                .harts
                .iter()
                .find(|record| record.id == remote.target_hart)
            else {
                return Err(SemanticInvariantError::RemotePreemptMissingHart {
                    remote_preempt: remote.id,
                    hart: remote.target_hart,
                });
            };
            if target.generation < remote.target_hart_generation_after
                || (target.generation == remote.target_hart_generation_after
                    && (target.state != HartState::Idle
                        || target.current_activation.is_some()
                        || target.current_activation_generation.is_some()))
            {
                return Err(
                    SemanticInvariantError::RemotePreemptHartGenerationMismatch {
                        remote_preempt: remote.id,
                        hart: remote.target_hart,
                    },
                );
            }
            let queue = self.runnable_queues.iter().find(|record| {
                record.id == remote.queue && record.generation == remote.queue_generation
            });
            let queue_has_advanced = self.runnable_queues.iter().any(|record| {
                record.id == remote.queue && record.generation > remote.queue_generation
            });
            if queue.is_none() && !queue_has_advanced {
                return Err(SemanticInvariantError::RemotePreemptMissingQueue {
                    remote_preempt: remote.id,
                    queue: remote.queue,
                });
            }
            if let Some(queue) = queue {
                if queue.owner_hart != Some(remote.target_hart)
                    || queue
                        .owner_hart_generation
                        .is_none_or(|generation| generation > remote.target_hart_generation_before)
                {
                    return Err(SemanticInvariantError::RemotePreemptMissingQueue {
                        remote_preempt: remote.id,
                        queue: remote.queue,
                    });
                }
            }
            let activation = self.runtime_activations.iter().find(|record| {
                record.id == remote.activation
                    && record.generation == remote.activation_generation_after
            });
            let activation_has_advanced = self.runtime_activations.iter().any(|record| {
                record.id == remote.activation
                    && record.generation > remote.activation_generation_after
            });
            if activation.is_none() && !activation_has_advanced {
                return Err(SemanticInvariantError::RemotePreemptMissingActivation {
                    remote_preempt: remote.id,
                    activation: remote.activation,
                });
            }
            if let (Some(activation), Some(queue)) = (activation, queue) {
                if activation.state == RuntimeActivationState::Runnable
                    && !queue.entries.iter().any(|entry| {
                        entry.activation == remote.activation
                            && entry.activation_generation == remote.activation_generation_after
                    })
                {
                    return Err(SemanticInvariantError::RemotePreemptQueueEntryMismatch {
                        remote_preempt: remote.id,
                        activation: remote.activation,
                    });
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == remote.preempted_at_event
                    && matches!(
                        event.kind,
                        EventKind::RemoteActivationPreempted {
                            remote_preempt,
                            ipi,
                            ipi_generation,
                            source_hart,
                            source_hart_generation,
                            target_hart,
                            target_hart_generation_before,
                            target_hart_generation_after,
                            activation,
                            from_generation,
                            to_generation,
                            queue,
                            queue_generation,
                            generation,
                        } if remote_preempt == remote.id
                            && ipi == remote.ipi
                            && ipi_generation == remote.ipi_generation
                            && source_hart == remote.source_hart
                            && source_hart_generation == remote.source_hart_generation
                            && target_hart == remote.target_hart
                            && target_hart_generation_before == remote.target_hart_generation_before
                            && target_hart_generation_after == remote.target_hart_generation_after
                            && activation == remote.activation
                            && from_generation == remote.activation_generation_before
                            && to_generation == remote.activation_generation_after
                            && queue == remote.queue
                            && queue_generation == remote.queue_generation
                            && generation == remote.generation
                    )
            }) {
                return Err(SemanticInvariantError::RemotePreemptMissingEvent {
                    remote_preempt: remote.id,
                });
            }
            if !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == remote.preempted_at_event
                    && attribution.hart == remote.source_hart
                    && attribution.hart_generation == remote.source_hart_generation
                    && attribution.event_kind == "RemotePreemptSourceRecorded"
            }) || !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == remote.preempted_at_event
                    && attribution.hart == remote.target_hart
                    && attribution.hart_generation == remote.target_hart_generation_after
                    && attribution.event_kind == "RemotePreemptTargetRecorded"
            }) {
                return Err(
                    SemanticInvariantError::RemotePreemptMissingHartEventAttribution {
                        remote_preempt: remote.id,
                        event: remote.preempted_at_event,
                    },
                );
            }
        }
        Ok(())
    }
}
