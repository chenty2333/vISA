use alloc::{collections::BTreeSet, vec::Vec};

use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_smp_code_publish_barrier(
        &self,
        barrier: SmpCodePublishBarrierId,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        code_publish_epoch_before: u64,
        code_publish_epoch_after: u64,
        remote_icache_sync_required: bool,
        code_publish_executed: bool,
        reason: &str,
    ) -> Result<(), &'static str> {
        if barrier == 0 {
            return Err("smp code publish barrier id=0 is invalid");
        }
        if rendezvous == 0 || rendezvous_generation == 0 {
            return Err("smp code publish barrier rendezvous is invalid");
        }
        if reason.is_empty() {
            return Err("smp code publish barrier reason is empty");
        }
        if self.smp_code_publish_barriers.iter().any(|record| record.id == barrier) {
            return Err("smp code publish barrier already exists");
        }
        if code_publish_epoch_after != code_publish_epoch_before + 1 {
            return Err("smp code publish barrier epoch must advance by one");
        }
        if !remote_icache_sync_required {
            return Err("smp code publish barrier requires remote icache sync");
        }
        if code_publish_executed {
            return Err("smp code publish barrier must not execute code publish");
        }
        let Some(rendezvous_record) = self
            .stop_the_world_rendezvous
            .iter()
            .find(|record| record.id == rendezvous && record.generation == rendezvous_generation)
        else {
            return Err("smp code publish barrier rendezvous is missing");
        };
        if rendezvous_record.state != StopTheWorldRendezvousState::Completed
            || !rendezvous_record.stop_new_activations
            || rendezvous_record.participants.len() < 2
            || rendezvous_record.epoch != code_publish_epoch_after
        {
            return Err("smp code publish barrier rendezvous is invalid");
        }
        let mut seen = BTreeSet::new();
        for participant in &rendezvous_record.participants {
            if participant.hart == 0
                || participant.hart_generation == 0
                || !seen.insert(participant.hart)
            {
                return Err("smp code publish barrier participant list is invalid");
            }
            let Some(current) = self.harts.iter().find(|hart| {
                hart.id == participant.hart && hart.generation == participant.hart_generation
            }) else {
                return Err("smp code publish barrier participant generation is stale");
            };
            if !Self::hart_is_code_publish_barrier_quiesced(current) {
                return Err("smp code publish barrier participant is not quiesced");
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_smp_code_publish_barrier_with_id(
        &mut self,
        barrier: SmpCodePublishBarrierId,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        code_publish_epoch_before: u64,
        code_publish_epoch_after: u64,
        remote_icache_sync_required: bool,
        code_publish_executed: bool,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_smp_code_publish_barrier(
                barrier,
                rendezvous,
                rendezvous_generation,
                code_publish_epoch_before,
                code_publish_epoch_after,
                remote_icache_sync_required,
                code_publish_executed,
                reason,
            )
            .is_err()
        {
            return false;
        }
        let Some(rendezvous_record) = self
            .stop_the_world_rendezvous
            .iter()
            .find(|record| record.id == rendezvous && record.generation == rendezvous_generation)
            .cloned()
        else {
            return false;
        };

        let participants = rendezvous_record
            .participants
            .iter()
            .map(|participant| SmpCodePublishBarrierParticipantRecord {
                hart: participant.hart,
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                last_seen_code_epoch_before: code_publish_epoch_before,
                last_seen_code_epoch_after: code_publish_epoch_after,
                semantic_icache_sync: true,
            })
            .collect::<Vec<_>>();

        self.next_smp_code_publish_barrier_id =
            self.next_smp_code_publish_barrier_id.max(barrier + 1);
        let event = self.event_log.push(
            "scheduler",
            EventKind::SmpCodePublishBarrierValidated {
                barrier,
                rendezvous,
                rendezvous_generation,
                code_publish_epoch_before,
                code_publish_epoch_after,
                participant_count: participants.len() as u32,
                generation: 1,
            },
        );
        self.smp_code_publish_barriers.push(SmpCodePublishBarrierRecord {
            id: barrier,
            rendezvous,
            rendezvous_generation,
            rendezvous_epoch: rendezvous_record.epoch,
            code_publish_epoch_before,
            code_publish_epoch_after,
            participants: participants.clone(),
            remote_icache_sync_required,
            code_publish_executed,
            generation: 1,
            state: SmpCodePublishBarrierState::Validated,
            validated_at_event: event,
            reason: reason.to_string(),
            note: note.to_string(),
        });
        for participant in participants {
            let _ = self.push_hart_event_attribution(
                participant.hart,
                participant.hart_generation,
                event,
                "SmpCodePublishBarrierHartSynced",
                None,
                None,
                note,
            );
        }
        true
    }

    pub fn smp_code_publish_barriers(&self) -> &[SmpCodePublishBarrierRecord] {
        &self.smp_code_publish_barriers
    }

    pub fn smp_code_publish_barrier_count(&self) -> usize {
        self.smp_code_publish_barriers.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_smp_code_publish_barrier_event_for_test(
        &mut self,
        barrier: SmpCodePublishBarrierId,
        event: EventId,
    ) {
        if let Some(record) =
            self.smp_code_publish_barriers.iter_mut().find(|record| record.id == barrier)
        {
            record.validated_at_event = event;
        }
    }

    pub fn check_smp_code_publish_barrier_invariants(&self) -> Result<(), SemanticInvariantError> {
        let mut ids = BTreeSet::new();
        for barrier in &self.smp_code_publish_barriers {
            if barrier.id == 0
                || !ids.insert(barrier.id)
                || barrier.generation == 0
                || barrier.rendezvous == 0
                || barrier.rendezvous_generation == 0
                || barrier.state != SmpCodePublishBarrierState::Validated
                || barrier.participants.len() < 2
                || barrier.code_publish_epoch_after != barrier.code_publish_epoch_before + 1
                || barrier.rendezvous_epoch != barrier.code_publish_epoch_after
                || !barrier.remote_icache_sync_required
                || barrier.code_publish_executed
            {
                return Err(SemanticInvariantError::SmpCodePublishBarrierInvalid {
                    barrier: barrier.id,
                });
            }
            let Some(rendezvous) = self.stop_the_world_rendezvous.iter().find(|record| {
                record.id == barrier.rendezvous
                    && record.generation == barrier.rendezvous_generation
            }) else {
                return Err(SemanticInvariantError::SmpCodePublishBarrierRendezvousMissing {
                    barrier: barrier.id,
                    rendezvous: barrier.rendezvous,
                });
            };
            if rendezvous.state != StopTheWorldRendezvousState::Completed
                || !rendezvous.stop_new_activations
                || rendezvous.epoch != barrier.rendezvous_epoch
                || rendezvous.epoch != barrier.code_publish_epoch_after
                || rendezvous.participants.len() != barrier.participants.len()
                || rendezvous.completed_at_event >= barrier.validated_at_event
            {
                return Err(SemanticInvariantError::SmpCodePublishBarrierInvalid {
                    barrier: barrier.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == barrier.validated_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SmpCodePublishBarrierValidated {
                            barrier: event_barrier,
                            rendezvous,
                            rendezvous_generation,
                            code_publish_epoch_before,
                            code_publish_epoch_after,
                            participant_count,
                            generation,
                        } if *event_barrier == barrier.id
                            && *rendezvous == barrier.rendezvous
                            && *rendezvous_generation == barrier.rendezvous_generation
                            && *code_publish_epoch_before == barrier.code_publish_epoch_before
                            && *code_publish_epoch_after == barrier.code_publish_epoch_after
                            && *participant_count == barrier.participants.len() as u32
                            && *generation == barrier.generation
                    )
            }) {
                return Err(SemanticInvariantError::SmpCodePublishBarrierMissingEvent {
                    barrier: barrier.id,
                });
            }

            let mut seen = BTreeSet::new();
            for participant in &barrier.participants {
                if participant.hart == 0
                    || participant.hart_generation == 0
                    || participant.last_seen_code_epoch_before != barrier.code_publish_epoch_before
                    || participant.last_seen_code_epoch_after != barrier.code_publish_epoch_after
                    || !participant.semantic_icache_sync
                    || !seen.insert(participant.hart)
                {
                    return Err(SemanticInvariantError::SmpCodePublishBarrierParticipantMismatch {
                        barrier: barrier.id,
                        hart: participant.hart,
                    });
                }
                let Some(rendezvous_participant) = rendezvous.participants.iter().find(|record| {
                    record.hart == participant.hart
                        && record.hart_generation == participant.hart_generation
                }) else {
                    return Err(SemanticInvariantError::SmpCodePublishBarrierParticipantMismatch {
                        barrier: barrier.id,
                        hart: participant.hart,
                    });
                };
                if rendezvous_participant.hardware_hart != participant.hardware_hart
                    || !matches!(
                        rendezvous_participant.hart_state,
                        HartState::Idle | HartState::Parked
                    )
                {
                    return Err(SemanticInvariantError::SmpCodePublishBarrierParticipantMismatch {
                        barrier: barrier.id,
                        hart: participant.hart,
                    });
                }
                let Some(current_hart) =
                    self.harts.iter().find(|record| record.id == participant.hart)
                else {
                    return Err(SemanticInvariantError::SmpCodePublishBarrierParticipantMismatch {
                        barrier: barrier.id,
                        hart: participant.hart,
                    });
                };
                if current_hart.generation < participant.hart_generation
                    || (current_hart.generation == participant.hart_generation
                        && !Self::hart_is_code_publish_barrier_quiesced(current_hart))
                {
                    return Err(SemanticInvariantError::SmpCodePublishBarrierParticipantMismatch {
                        barrier: barrier.id,
                        hart: participant.hart,
                    });
                }
                if !self.hart_event_attributions.iter().any(|attribution| {
                    attribution.event == barrier.validated_at_event
                        && attribution.hart == participant.hart
                        && attribution.hart_generation == participant.hart_generation
                        && attribution.event_kind == "SmpCodePublishBarrierHartSynced"
                }) {
                    return Err(
                        SemanticInvariantError::SmpCodePublishBarrierMissingHartEventAttribution {
                            barrier: barrier.id,
                            event: barrier.validated_at_event,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn hart_is_code_publish_barrier_quiesced(hart: &HartRecord) -> bool {
        matches!(hart.state, HartState::Idle | HartState::Parked)
            && hart.current_activation.is_none()
            && hart.current_activation_generation.is_none()
    }
}
