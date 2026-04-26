use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::*;

impl SemanticGraph {
    pub(crate) fn validate_stop_the_world_rendezvous(
        &self,
        rendezvous: StopTheWorldRendezvousId,
        epoch: u64,
        safe_point: SmpSafePointId,
        safe_point_generation: Generation,
        stop_new_activations: bool,
        reason: &str,
    ) -> Result<(), &'static str> {
        if rendezvous == 0 {
            return Err("stop-the-world rendezvous id=0 is invalid");
        }
        if epoch == 0 {
            return Err("stop-the-world rendezvous epoch=0 is invalid");
        }
        if safe_point == 0 || safe_point_generation == 0 {
            return Err("stop-the-world rendezvous safe point is invalid");
        }
        if reason.is_empty() {
            return Err("stop-the-world rendezvous reason is empty");
        }
        if !stop_new_activations {
            return Err("stop-the-world rendezvous must stop new activations");
        }
        if self
            .stop_the_world_rendezvous
            .iter()
            .any(|record| record.id == rendezvous || record.epoch == epoch)
        {
            return Err("stop-the-world rendezvous already exists");
        }
        let Some(safe_point_record) = self
            .smp_safe_points
            .iter()
            .find(|record| record.id == safe_point && record.generation == safe_point_generation)
        else {
            return Err("stop-the-world rendezvous safe point is missing");
        };
        if safe_point_record.state != SmpSafePointState::Recorded
            || safe_point_record.participants.len() < 2
        {
            return Err("stop-the-world rendezvous safe point is invalid");
        }
        if safe_point_record.participants.iter().any(|participant| {
            !matches!(participant.hart_state, HartState::Idle | HartState::Parked)
                || participant.current_activation.is_some()
                || participant.current_activation_generation.is_some()
        }) {
            return Err("stop-the-world rendezvous safe point is not quiesced");
        }

        let mut participant_harts = BTreeSet::new();
        for participant in &safe_point_record.participants {
            if !participant_harts.insert(participant.hart) {
                return Err("stop-the-world rendezvous participant list is invalid");
            }
            let Some(current) = self.harts.iter().find(|hart| {
                hart.id == participant.hart && hart.generation == participant.hart_generation
            }) else {
                return Err("stop-the-world rendezvous participant generation is stale");
            };
            if !matches!(current.state, HartState::Idle | HartState::Parked)
                || current.current_activation.is_some()
                || current.current_activation_generation.is_some()
            {
                return Err("stop-the-world rendezvous participant is not parked");
            }
        }
        for hart in self
            .harts
            .iter()
            .filter(|record| !matches!(record.state, HartState::Offline | HartState::Faulted))
        {
            if !safe_point_record.participants.iter().any(|participant| {
                participant.hart == hart.id && participant.hart_generation == hart.generation
            }) {
                return Err("stop-the-world rendezvous missing active hart");
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_stop_the_world_rendezvous_with_id(
        &mut self,
        rendezvous: StopTheWorldRendezvousId,
        epoch: u64,
        safe_point: SmpSafePointId,
        safe_point_generation: Generation,
        stop_new_activations: bool,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_stop_the_world_rendezvous(
                rendezvous,
                epoch,
                safe_point,
                safe_point_generation,
                stop_new_activations,
                reason,
            )
            .is_err()
        {
            return false;
        }

        let Some(safe_point_record) = self
            .smp_safe_points
            .iter()
            .find(|record| record.id == safe_point && record.generation == safe_point_generation)
            .cloned()
        else {
            return false;
        };
        let participants = safe_point_record
            .participants
            .iter()
            .map(|participant| StopTheWorldRendezvousParticipantRecord {
                hart: participant.hart,
                hart_generation: participant.hart_generation,
                hardware_hart: participant.hardware_hart,
                hart_state: participant.hart_state,
            })
            .collect::<Vec<_>>();

        self.next_stop_the_world_rendezvous_id =
            self.next_stop_the_world_rendezvous_id.max(rendezvous + 1);
        let event = self.event_log.push(
            "scheduler",
            EventKind::StopTheWorldRendezvousCompleted {
                rendezvous,
                epoch,
                safe_point,
                safe_point_generation,
                coordinator_hart: safe_point_record.coordinator_hart,
                coordinator_hart_generation: safe_point_record.coordinator_hart_generation,
                participant_count: participants.len() as u32,
                generation: 1,
            },
        );
        self.stop_the_world_rendezvous
            .push(StopTheWorldRendezvousRecord {
                id: rendezvous,
                epoch,
                safe_point,
                safe_point_generation,
                coordinator_hart: safe_point_record.coordinator_hart,
                coordinator_hart_generation: safe_point_record.coordinator_hart_generation,
                participants: participants.clone(),
                stop_new_activations,
                generation: 1,
                state: StopTheWorldRendezvousState::Completed,
                completed_at_event: event,
                reason: reason.to_string(),
                note: note.to_string(),
            });
        for participant in participants {
            let _ = self.push_hart_event_attribution(
                participant.hart,
                participant.hart_generation,
                event,
                "StopTheWorldHartParked",
                None,
                None,
                note,
            );
        }
        true
    }

    pub fn stop_the_world_rendezvous(&self) -> &[StopTheWorldRendezvousRecord] {
        &self.stop_the_world_rendezvous
    }

    pub fn stop_the_world_rendezvous_count(&self) -> usize {
        self.stop_the_world_rendezvous.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_stop_the_world_event_for_test(
        &mut self,
        rendezvous: StopTheWorldRendezvousId,
        event: EventId,
    ) {
        if let Some(record) = self
            .stop_the_world_rendezvous
            .iter_mut()
            .find(|record| record.id == rendezvous)
        {
            record.completed_at_event = event;
        }
    }

    pub fn check_stop_the_world_invariants(&self) -> Result<(), SemanticInvariantError> {
        let mut epochs = BTreeSet::new();
        for rendezvous in &self.stop_the_world_rendezvous {
            if rendezvous.id == 0
                || rendezvous.epoch == 0
                || !epochs.insert(rendezvous.epoch)
                || rendezvous.generation == 0
                || rendezvous.state != StopTheWorldRendezvousState::Completed
                || !rendezvous.stop_new_activations
                || rendezvous.participants.len() < 2
            {
                return Err(SemanticInvariantError::StopTheWorldRendezvousInvalid {
                    rendezvous: rendezvous.id,
                });
            }
            let Some(safe_point) = self.smp_safe_points.iter().find(|record| {
                record.id == rendezvous.safe_point
                    && record.generation == rendezvous.safe_point_generation
            }) else {
                return Err(
                    SemanticInvariantError::StopTheWorldRendezvousSafePointMissing {
                        rendezvous: rendezvous.id,
                        safe_point: rendezvous.safe_point,
                    },
                );
            };
            if safe_point.recorded_at_event >= rendezvous.completed_at_event
                || safe_point.coordinator_hart != rendezvous.coordinator_hart
                || safe_point.coordinator_hart_generation != rendezvous.coordinator_hart_generation
                || safe_point.participants.len() != rendezvous.participants.len()
            {
                return Err(SemanticInvariantError::StopTheWorldRendezvousInvalid {
                    rendezvous: rendezvous.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == rendezvous.completed_at_event
                    && matches!(
                        &event.kind,
                        EventKind::StopTheWorldRendezvousCompleted {
                            rendezvous: event_rendezvous,
                            epoch,
                            safe_point,
                            safe_point_generation,
                            coordinator_hart,
                            coordinator_hart_generation,
                            participant_count,
                            generation,
                        } if *event_rendezvous == rendezvous.id
                            && *epoch == rendezvous.epoch
                            && *safe_point == rendezvous.safe_point
                            && *safe_point_generation == rendezvous.safe_point_generation
                            && *coordinator_hart == rendezvous.coordinator_hart
                            && *coordinator_hart_generation
                                == rendezvous.coordinator_hart_generation
                            && *participant_count == rendezvous.participants.len() as u32
                            && *generation == rendezvous.generation
                    )
            }) {
                return Err(SemanticInvariantError::StopTheWorldRendezvousMissingEvent {
                    rendezvous: rendezvous.id,
                });
            }
            for participant in &rendezvous.participants {
                let Some(safe_participant) = safe_point.participants.iter().find(|record| {
                    record.hart == participant.hart
                        && record.hart_generation == participant.hart_generation
                }) else {
                    return Err(
                        SemanticInvariantError::StopTheWorldRendezvousParticipantMismatch {
                            rendezvous: rendezvous.id,
                            hart: participant.hart,
                        },
                    );
                };
                if safe_participant.hardware_hart != participant.hardware_hart
                    || safe_participant.hart_state != participant.hart_state
                    || safe_participant.current_activation.is_some()
                    || safe_participant.current_activation_generation.is_some()
                {
                    return Err(
                        SemanticInvariantError::StopTheWorldRendezvousParticipantMismatch {
                            rendezvous: rendezvous.id,
                            hart: participant.hart,
                        },
                    );
                }
                let Some(current_hart) = self
                    .harts
                    .iter()
                    .find(|record| record.id == participant.hart)
                else {
                    return Err(
                        SemanticInvariantError::StopTheWorldRendezvousParticipantMismatch {
                            rendezvous: rendezvous.id,
                            hart: participant.hart,
                        },
                    );
                };
                if current_hart.generation < participant.hart_generation
                    || (current_hart.generation == participant.hart_generation
                        && (current_hart.state != participant.hart_state
                            || current_hart.current_activation.is_some()
                            || current_hart.current_activation_generation.is_some()))
                {
                    return Err(
                        SemanticInvariantError::StopTheWorldRendezvousParticipantMismatch {
                            rendezvous: rendezvous.id,
                            hart: participant.hart,
                        },
                    );
                }
                if !self.hart_event_attributions.iter().any(|attribution| {
                    attribution.event == rendezvous.completed_at_event
                        && attribution.hart == participant.hart
                        && attribution.hart_generation == participant.hart_generation
                        && attribution.event_kind == "StopTheWorldHartParked"
                }) {
                    return Err(
                        SemanticInvariantError::StopTheWorldRendezvousMissingHartEventAttribution {
                            rendezvous: rendezvous.id,
                            event: rendezvous.completed_at_event,
                        },
                    );
                }
            }
        }
        Ok(())
    }
}
