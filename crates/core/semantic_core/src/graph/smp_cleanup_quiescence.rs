use alloc::{collections::BTreeSet, vec::Vec};

use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_smp_cleanup_quiescence(
        &self,
        quiescence: SmpCleanupQuiescenceId,
        cleanup: ActivationCleanupId,
        cleanup_generation: Generation,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        store: StoreId,
        target_store_generation: Generation,
        result_store_generation: Generation,
        reason: &str,
    ) -> Result<(), &'static str> {
        if quiescence == 0 {
            return Err("smp cleanup quiescence id=0 is invalid");
        }
        if cleanup == 0 || cleanup_generation == 0 {
            return Err("smp cleanup quiescence cleanup is invalid");
        }
        if rendezvous == 0 || rendezvous_generation == 0 {
            return Err("smp cleanup quiescence rendezvous is invalid");
        }
        if store == 0 || target_store_generation == 0 || result_store_generation == 0 {
            return Err("smp cleanup quiescence store generation is invalid");
        }
        if reason.is_empty() {
            return Err("smp cleanup quiescence reason is empty");
        }
        if self
            .domains
            .scheduler
            .smp_cleanup_quiescence
            .iter()
            .any(|record| record.id == quiescence)
        {
            return Err("smp cleanup quiescence already exists");
        }
        let Some(cleanup_record) = self
            .domains
            .scheduler
            .activation_cleanups
            .iter()
            .find(|record| record.id == cleanup && record.generation == cleanup_generation)
        else {
            return Err("smp cleanup quiescence cleanup is missing");
        };
        if cleanup_record.state != ActivationCleanupState::Completed
            || cleanup_record.store != store
            || cleanup_record.target_store_generation != target_store_generation
            || cleanup_record.result_store_generation != result_store_generation
        {
            return Err("smp cleanup quiescence cleanup does not match target store generation");
        }
        let Some(rendezvous_record) =
            self.domains.scheduler.stop_the_world_rendezvous.iter().find(|record| {
                record.id == rendezvous && record.generation == rendezvous_generation
            })
        else {
            return Err("smp cleanup quiescence rendezvous is missing");
        };
        if rendezvous_record.state != StopTheWorldRendezvousState::Completed
            || !rendezvous_record.stop_new_activations
            || rendezvous_record.participants.len() < 2
        {
            return Err("smp cleanup quiescence rendezvous is invalid");
        }
        if cleanup_record.completed_at_event >= rendezvous_record.completed_at_event {
            return Err("smp cleanup quiescence rendezvous must follow cleanup");
        }
        let Some(store_record) =
            self.domains.lifecycle.stores.iter().find(|record| record.id == store)
        else {
            return Err("smp cleanup quiescence store is missing");
        };
        if store_record.generation < result_store_generation {
            return Err("smp cleanup quiescence store generation is stale");
        }
        if store_record.generation == result_store_generation
            && store_record.state != StoreState::Dead
        {
            return Err("smp cleanup quiescence store is not dead");
        }
        if !self.store_generation_has_no_live_activation(
            store,
            target_store_generation,
            result_store_generation,
        ) {
            return Err("smp cleanup quiescence found live activation for dead store");
        }
        if !self.store_generation_has_no_pending_wait(
            store,
            target_store_generation,
            result_store_generation,
        ) {
            return Err("smp cleanup quiescence found pending wait for dead store");
        }
        if !self.store_generation_has_no_live_capability(
            store,
            target_store_generation,
            result_store_generation,
        ) {
            return Err("smp cleanup quiescence found live capability for dead store");
        }
        if store_record.generation == result_store_generation
            && self
                .domains
                .resource
                .resources
                .iter()
                .any(|record| record.owner_store == Some(store) && record.live)
        {
            return Err("smp cleanup quiescence found live resource for dead store");
        }
        let mut participant_harts = BTreeSet::new();
        for participant in &rendezvous_record.participants {
            if participant.hart == 0
                || participant.hart_generation == 0
                || !participant_harts.insert(participant.hart)
            {
                return Err("smp cleanup quiescence participant list is invalid");
            }
            let Some(hart) = self.domains.scheduler.harts.iter().find(|record| {
                record.id == participant.hart && record.generation == participant.hart_generation
            }) else {
                return Err("smp cleanup quiescence participant generation is stale");
            };
            if !Self::hart_is_cleanup_quiesced(hart) {
                return Err("smp cleanup quiescence participant is not quiesced");
            }
            if hart.current_store == Some(store)
                && hart.current_store_generation.is_some_and(|generation| {
                    Self::generation_in_cleanup_scope(
                        generation,
                        target_store_generation,
                        result_store_generation,
                    )
                })
            {
                return Err("smp cleanup quiescence hart still owns target store");
            }
        }
        for hart in self
            .domains
            .scheduler
            .harts
            .iter()
            .filter(|record| !matches!(record.state, HartState::Offline | HartState::Faulted))
        {
            if !rendezvous_record.participants.iter().any(|participant| {
                participant.hart == hart.id && participant.hart_generation == hart.generation
            }) {
                return Err("smp cleanup quiescence missing active hart");
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_smp_cleanup_quiescence_with_id(
        &mut self,
        quiescence: SmpCleanupQuiescenceId,
        cleanup: ActivationCleanupId,
        cleanup_generation: Generation,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        store: StoreId,
        target_store_generation: Generation,
        result_store_generation: Generation,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_smp_cleanup_quiescence(
                quiescence,
                cleanup,
                cleanup_generation,
                rendezvous,
                rendezvous_generation,
                store,
                target_store_generation,
                result_store_generation,
                reason,
            )
            .is_err()
        {
            return false;
        }
        let Some(cleanup_record) = self
            .domains
            .scheduler
            .activation_cleanups
            .iter()
            .find(|record| record.id == cleanup && record.generation == cleanup_generation)
            .cloned()
        else {
            return false;
        };
        let Some(rendezvous_record) = self
            .domains
            .scheduler
            .stop_the_world_rendezvous
            .iter()
            .find(|record| record.id == rendezvous && record.generation == rendezvous_generation)
            .cloned()
        else {
            return false;
        };
        let mut participants = Vec::new();
        for participant in &rendezvous_record.participants {
            let Some(hart) = self.domains.scheduler.harts.iter().find(|record| {
                record.id == participant.hart && record.generation == participant.hart_generation
            }) else {
                return false;
            };
            participants.push(SmpCleanupQuiescenceParticipantRecord {
                hart: participant.hart,
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                hart_state: participant.hart_state,
                current_activation: hart.current_activation,
                current_activation_generation: hart.current_activation_generation,
                current_store: hart.current_store,
                current_store_generation: hart.current_store_generation,
                quiesced: Self::hart_is_cleanup_quiesced(hart),
            });
        }

        self.domains.scheduler.next_smp_cleanup_quiescence_id =
            self.domains.scheduler.next_smp_cleanup_quiescence_id.max(quiescence + 1);
        let event = self.event_log.push(
            "scheduler",
            EventKind::SmpCleanupQuiescenceValidated {
                quiescence,
                cleanup,
                cleanup_generation,
                store,
                target_store_generation,
                result_store_generation,
                rendezvous,
                rendezvous_generation,
                participant_count: participants.len() as u32,
                generation: 1,
            },
        );
        self.domains.scheduler.smp_cleanup_quiescence.push(SmpCleanupQuiescenceRecord {
            id: quiescence,
            cleanup,
            cleanup_generation,
            store,
            target_store_generation,
            result_store_generation,
            activation: cleanup_record.activation,
            activation_generation_after: cleanup_record.activation_generation_after,
            rendezvous,
            rendezvous_generation,
            rendezvous_epoch: rendezvous_record.epoch,
            participants: participants.clone(),
            no_running_activation: true,
            no_pending_wait: true,
            no_live_capability: true,
            no_live_resource: true,
            generation: 1,
            state: SmpCleanupQuiescenceState::Validated,
            validated_at_event: event,
            reason: reason.to_string(),
            note: note.to_string(),
        });
        for participant in participants {
            let _ = self.push_hart_event_attribution(
                participant.hart,
                participant.hart_generation,
                event,
                "SmpCleanupQuiescenceHartObserved",
                None,
                None,
                note,
            );
        }
        true
    }

    pub fn smp_cleanup_quiescence(&self) -> &[SmpCleanupQuiescenceRecord] {
        &self.domains.scheduler.smp_cleanup_quiescence
    }

    pub fn smp_cleanup_quiescence_count(&self) -> usize {
        self.domains.scheduler.smp_cleanup_quiescence.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_smp_cleanup_quiescence_event_for_test(
        &mut self,
        quiescence: SmpCleanupQuiescenceId,
        event: EventId,
    ) {
        if let Some(record) = self
            .domains
            .scheduler
            .smp_cleanup_quiescence
            .iter_mut()
            .find(|record| record.id == quiescence)
        {
            record.validated_at_event = event;
        }
    }

    pub fn check_smp_cleanup_quiescence_invariants(&self) -> Result<(), SemanticInvariantError> {
        let mut ids = BTreeSet::new();
        for quiescence in &self.domains.scheduler.smp_cleanup_quiescence {
            if quiescence.id == 0
                || !ids.insert(quiescence.id)
                || quiescence.generation == 0
                || quiescence.cleanup == 0
                || quiescence.cleanup_generation == 0
                || quiescence.store == 0
                || quiescence.target_store_generation == 0
                || quiescence.result_store_generation == 0
                || quiescence.rendezvous == 0
                || quiescence.rendezvous_generation == 0
                || quiescence.participants.len() < 2
                || quiescence.state != SmpCleanupQuiescenceState::Validated
                || !quiescence.no_running_activation
                || !quiescence.no_pending_wait
                || !quiescence.no_live_capability
                || !quiescence.no_live_resource
            {
                return Err(SemanticInvariantError::SmpCleanupQuiescenceInvalid {
                    quiescence: quiescence.id,
                });
            }
            let Some(cleanup) = self.domains.scheduler.activation_cleanups.iter().find(|record| {
                record.id == quiescence.cleanup
                    && record.generation == quiescence.cleanup_generation
            }) else {
                return Err(SemanticInvariantError::SmpCleanupQuiescenceCleanupMissing {
                    quiescence: quiescence.id,
                    cleanup: quiescence.cleanup,
                });
            };
            if cleanup.state != ActivationCleanupState::Completed
                || cleanup.store != quiescence.store
                || cleanup.target_store_generation != quiescence.target_store_generation
                || cleanup.result_store_generation != quiescence.result_store_generation
                || cleanup.activation != quiescence.activation
                || cleanup.activation_generation_after != quiescence.activation_generation_after
            {
                return Err(SemanticInvariantError::SmpCleanupQuiescenceInvalid {
                    quiescence: quiescence.id,
                });
            }
            let Some(rendezvous) =
                self.domains.scheduler.stop_the_world_rendezvous.iter().find(|record| {
                    record.id == quiescence.rendezvous
                        && record.generation == quiescence.rendezvous_generation
                })
            else {
                return Err(SemanticInvariantError::SmpCleanupQuiescenceRendezvousMissing {
                    quiescence: quiescence.id,
                    rendezvous: quiescence.rendezvous,
                });
            };
            if rendezvous.state != StopTheWorldRendezvousState::Completed
                || !rendezvous.stop_new_activations
                || rendezvous.epoch != quiescence.rendezvous_epoch
                || rendezvous.participants.len() != quiescence.participants.len()
                || cleanup.completed_at_event >= rendezvous.completed_at_event
                || rendezvous.completed_at_event >= quiescence.validated_at_event
            {
                return Err(SemanticInvariantError::SmpCleanupQuiescenceInvalid {
                    quiescence: quiescence.id,
                });
            }
            let Some(store) =
                self.domains.lifecycle.stores.iter().find(|record| record.id == quiescence.store)
            else {
                return Err(SemanticInvariantError::SmpCleanupQuiescenceStoreLeak {
                    quiescence: quiescence.id,
                    store: quiescence.store,
                });
            };
            if store.generation < quiescence.result_store_generation
                || (store.generation == quiescence.result_store_generation
                    && store.state != StoreState::Dead)
            {
                return Err(SemanticInvariantError::SmpCleanupQuiescenceStoreLeak {
                    quiescence: quiescence.id,
                    store: quiescence.store,
                });
            }
            if store.generation == quiescence.result_store_generation {
                if !self.store_generation_has_no_live_activation(
                    quiescence.store,
                    quiescence.target_store_generation,
                    quiescence.result_store_generation,
                ) {
                    return Err(SemanticInvariantError::SmpCleanupQuiescenceStoreLeak {
                        quiescence: quiescence.id,
                        store: quiescence.store,
                    });
                }
                if !self.store_generation_has_no_pending_wait(
                    quiescence.store,
                    quiescence.target_store_generation,
                    quiescence.result_store_generation,
                ) {
                    return Err(SemanticInvariantError::SmpCleanupQuiescenceStoreLeak {
                        quiescence: quiescence.id,
                        store: quiescence.store,
                    });
                }
                if !self.store_generation_has_no_live_capability(
                    quiescence.store,
                    quiescence.target_store_generation,
                    quiescence.result_store_generation,
                ) {
                    return Err(SemanticInvariantError::SmpCleanupQuiescenceStoreLeak {
                        quiescence: quiescence.id,
                        store: quiescence.store,
                    });
                }
                if self
                    .domains
                    .resource
                    .resources
                    .iter()
                    .any(|record| record.owner_store == Some(quiescence.store) && record.live)
                {
                    return Err(SemanticInvariantError::SmpCleanupQuiescenceStoreLeak {
                        quiescence: quiescence.id,
                        store: quiescence.store,
                    });
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == quiescence.validated_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SmpCleanupQuiescenceValidated {
                            quiescence: event_quiescence,
                            cleanup,
                            cleanup_generation,
                            store,
                            target_store_generation,
                            result_store_generation,
                            rendezvous,
                            rendezvous_generation,
                            participant_count,
                            generation,
                        } if *event_quiescence == quiescence.id
                            && *cleanup == quiescence.cleanup
                            && *cleanup_generation == quiescence.cleanup_generation
                            && *store == quiescence.store
                            && *target_store_generation == quiescence.target_store_generation
                            && *result_store_generation == quiescence.result_store_generation
                            && *rendezvous == quiescence.rendezvous
                            && *rendezvous_generation == quiescence.rendezvous_generation
                            && *participant_count == quiescence.participants.len() as u32
                            && *generation == quiescence.generation
                    )
            }) {
                return Err(SemanticInvariantError::SmpCleanupQuiescenceMissingEvent {
                    quiescence: quiescence.id,
                });
            }

            let mut seen = BTreeSet::new();
            for participant in &quiescence.participants {
                if participant.hart == 0
                    || participant.hart_generation == 0
                    || !participant.quiesced
                    || participant.current_activation.is_some()
                    || participant.current_activation_generation.is_some()
                    || participant.current_store.is_some()
                    || participant.current_store_generation.is_some()
                    || !seen.insert(participant.hart)
                {
                    return Err(SemanticInvariantError::SmpCleanupQuiescenceParticipantMismatch {
                        quiescence: quiescence.id,
                        hart: participant.hart,
                    });
                }
                let Some(rendezvous_participant) = rendezvous.participants.iter().find(|record| {
                    record.hart == participant.hart
                        && record.hart_generation == participant.hart_generation
                }) else {
                    return Err(SemanticInvariantError::SmpCleanupQuiescenceParticipantMismatch {
                        quiescence: quiescence.id,
                        hart: participant.hart,
                    });
                };
                if rendezvous_participant.hardware_hart != participant.hardware_hart
                    || rendezvous_participant.hart_state != participant.hart_state
                {
                    return Err(SemanticInvariantError::SmpCleanupQuiescenceParticipantMismatch {
                        quiescence: quiescence.id,
                        hart: participant.hart,
                    });
                }
                let Some(current_hart) = self
                    .domains
                    .scheduler
                    .harts
                    .iter()
                    .find(|record| record.id == participant.hart)
                else {
                    return Err(SemanticInvariantError::SmpCleanupQuiescenceParticipantMismatch {
                        quiescence: quiescence.id,
                        hart: participant.hart,
                    });
                };
                if current_hart.generation < participant.hart_generation
                    || (current_hart.generation == participant.hart_generation
                        && !Self::hart_is_cleanup_quiesced(current_hart))
                {
                    return Err(SemanticInvariantError::SmpCleanupQuiescenceParticipantMismatch {
                        quiescence: quiescence.id,
                        hart: participant.hart,
                    });
                }
                if !self.domains.scheduler.hart_event_attributions.iter().any(|attribution| {
                    attribution.event == quiescence.validated_at_event
                        && attribution.hart == participant.hart
                        && attribution.hart_generation == participant.hart_generation
                        && attribution.event_kind == "SmpCleanupQuiescenceHartObserved"
                }) {
                    return Err(
                        SemanticInvariantError::SmpCleanupQuiescenceMissingHartEventAttribution {
                            quiescence: quiescence.id,
                            event: quiescence.validated_at_event,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn hart_is_cleanup_quiesced(hart: &HartRecord) -> bool {
        matches!(hart.state, HartState::Idle | HartState::Parked)
            && hart.current_activation.is_none()
            && hart.current_activation_generation.is_none()
            && hart.current_store.is_none()
            && hart.current_store_generation.is_none()
    }

    fn store_generation_has_no_live_activation(
        &self,
        store: StoreId,
        target_store_generation: Generation,
        result_store_generation: Generation,
    ) -> bool {
        self.domains.scheduler.runtime_activations.iter().all(|record| {
            record.owner_store != Some(store)
                || match record.owner_store_generation {
                    Some(generation) => {
                        !Self::generation_in_cleanup_scope(
                            generation,
                            target_store_generation,
                            result_store_generation,
                        ) || matches!(
                            record.state,
                            RuntimeActivationState::Dead | RuntimeActivationState::Exited
                        )
                    }
                    None => matches!(
                        record.state,
                        RuntimeActivationState::Dead | RuntimeActivationState::Exited
                    ),
                }
        })
    }

    fn store_generation_has_no_pending_wait(
        &self,
        store: StoreId,
        target_store_generation: Generation,
        result_store_generation: Generation,
    ) -> bool {
        self.domains.wait.waits.iter().all(|record| {
            record.owner_store != Some(store)
                || match record.owner_store_generation {
                    Some(generation) => {
                        !Self::generation_in_cleanup_scope(
                            generation,
                            target_store_generation,
                            result_store_generation,
                        ) || record.state != WaitState::Pending
                    }
                    None => record.state != WaitState::Pending,
                }
        })
    }

    fn store_generation_has_no_live_capability(
        &self,
        store: StoreId,
        target_store_generation: Generation,
        result_store_generation: Generation,
    ) -> bool {
        self.domains.capability.capabilities.records().iter().all(|record| {
            record.owner_store != Some(store)
                || match record.owner_store_generation {
                    Some(generation) => {
                        !Self::generation_in_cleanup_scope(
                            generation,
                            target_store_generation,
                            result_store_generation,
                        ) || record.revoked
                    }
                    None => record.revoked,
                }
        })
    }

    fn generation_in_cleanup_scope(
        generation: Generation,
        target_store_generation: Generation,
        result_store_generation: Generation,
    ) -> bool {
        generation >= target_store_generation && generation <= result_store_generation
    }
}
