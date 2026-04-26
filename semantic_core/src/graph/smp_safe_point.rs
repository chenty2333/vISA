use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_smp_safe_point(
        &self,
        safe_point: SmpSafePointId,
        coordinator_hart: HartId,
        coordinator_hart_generation: Generation,
        participants: &[(HartId, Generation)],
        reason: &str,
    ) -> Result<(), &'static str> {
        if safe_point == 0 {
            return Err("smp safe point id=0 is invalid");
        }
        if reason.is_empty() {
            return Err("smp safe point reason is empty");
        }
        if participants.len() < 2 {
            return Err("smp safe point requires at least two harts");
        }
        if self
            .smp_safe_points
            .iter()
            .any(|record| record.id == safe_point)
        {
            return Err("smp safe point already exists");
        }
        let Some(coordinator) = self.harts.iter().find(|record| {
            record.id == coordinator_hart && record.generation == coordinator_hart_generation
        }) else {
            return Err("smp safe point coordinator hart generation is missing");
        };
        if !Self::hart_is_safe_point_quiesced(coordinator) {
            return Err("smp safe point coordinator is not quiesced");
        }

        let mut seen = BTreeSet::new();
        for (hart, generation) in participants {
            if *hart == 0 || *generation == 0 || !seen.insert(*hart) {
                return Err("smp safe point participant list is invalid");
            }
            let Some(record) = self
                .harts
                .iter()
                .find(|record| record.id == *hart && record.generation == *generation)
            else {
                return Err("smp safe point participant hart generation is missing");
            };
            if !Self::hart_is_safe_point_quiesced(record) {
                return Err("smp safe point participant is not quiesced");
            }
        }
        if !participants.iter().any(|(hart, generation)| {
            *hart == coordinator_hart && *generation == coordinator_hart_generation
        }) {
            return Err("smp safe point coordinator must be a participant");
        }
        for hart in self
            .harts
            .iter()
            .filter(|record| !matches!(record.state, HartState::Offline | HartState::Faulted))
        {
            if !participants.iter().any(|(participant, generation)| {
                *participant == hart.id && *generation == hart.generation
            }) {
                return Err("smp safe point missing active hart");
            }
        }
        Ok(())
    }

    pub fn record_smp_safe_point_with_id(
        &mut self,
        safe_point: SmpSafePointId,
        coordinator_hart: HartId,
        coordinator_hart_generation: Generation,
        participants: Vec<(HartId, Generation)>,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_smp_safe_point(
                safe_point,
                coordinator_hart,
                coordinator_hart_generation,
                &participants,
                reason,
            )
            .is_err()
        {
            return false;
        }

        let mut participant_records = Vec::new();
        for (hart, generation) in &participants {
            let Some(record) = self
                .harts
                .iter()
                .find(|record| record.id == *hart && record.generation == *generation)
            else {
                return false;
            };
            participant_records.push(SmpSafePointParticipantRecord {
                hart: record.id,
                hart_generation: record.generation,
                hardware_hart: record.hardware_id,
                hart_state: record.state,
                current_activation: record.current_activation,
                current_activation_generation: record.current_activation_generation,
            });
        }

        self.next_smp_safe_point_id = self.next_smp_safe_point_id.max(safe_point + 1);
        let event = self.event_log.push(
            "scheduler",
            EventKind::SmpSafePointRecorded {
                safe_point,
                coordinator_hart,
                coordinator_hart_generation,
                participant_count: participant_records.len() as u32,
                generation: 1,
            },
        );
        self.smp_safe_points.push(SmpSafePointRecord {
            id: safe_point,
            coordinator_hart,
            coordinator_hart_generation,
            participants: participant_records.clone(),
            generation: 1,
            state: SmpSafePointState::Recorded,
            recorded_at_event: event,
            reason: reason.to_string(),
            note: note.to_string(),
        });
        let _ = self.push_hart_event_attribution(
            coordinator_hart,
            coordinator_hart_generation,
            event,
            "SmpSafePointCoordinatorRecorded",
            None,
            None,
            note,
        );
        for participant in participant_records {
            if participant.hart == coordinator_hart
                && participant.hart_generation == coordinator_hart_generation
            {
                continue;
            }
            let _ = self.push_hart_event_attribution(
                participant.hart,
                participant.hart_generation,
                event,
                "SmpSafePointParticipantRecorded",
                participant.current_activation,
                participant.current_activation_generation,
                note,
            );
        }
        true
    }

    pub fn smp_safe_points(&self) -> &[SmpSafePointRecord] {
        &self.smp_safe_points
    }

    pub fn smp_safe_point_count(&self) -> usize {
        self.smp_safe_points.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_smp_safe_point_event_for_test(
        &mut self,
        safe_point: SmpSafePointId,
        event: EventId,
    ) {
        if let Some(record) = self
            .smp_safe_points
            .iter_mut()
            .find(|record| record.id == safe_point)
        {
            record.recorded_at_event = event;
        }
    }

    pub fn check_smp_safe_point_invariants(&self) -> Result<(), SemanticInvariantError> {
        for safe_point in &self.smp_safe_points {
            if safe_point.id == 0
                || safe_point.generation == 0
                || safe_point.state != SmpSafePointState::Recorded
                || safe_point.coordinator_hart == 0
                || safe_point.coordinator_hart_generation == 0
                || safe_point.participants.len() < 2
            {
                return Err(SemanticInvariantError::SmpSafePointInvalid {
                    safe_point: safe_point.id,
                });
            }
            if !safe_point.participants.iter().any(|participant| {
                participant.hart == safe_point.coordinator_hart
                    && participant.hart_generation == safe_point.coordinator_hart_generation
            }) {
                return Err(SemanticInvariantError::SmpSafePointInvalid {
                    safe_point: safe_point.id,
                });
            }
            let mut seen = BTreeSet::new();
            for participant in &safe_point.participants {
                if participant.hart == 0
                    || participant.hart_generation == 0
                    || !seen.insert(participant.hart)
                {
                    return Err(SemanticInvariantError::SmpSafePointInvalid {
                        safe_point: safe_point.id,
                    });
                }
                if !matches!(participant.hart_state, HartState::Idle | HartState::Parked)
                    || participant.current_activation.is_some()
                    || participant.current_activation_generation.is_some()
                {
                    return Err(SemanticInvariantError::SmpSafePointParticipantNotQuiesced {
                        safe_point: safe_point.id,
                        hart: participant.hart,
                    });
                }
                let Some(hart) = self
                    .harts
                    .iter()
                    .find(|record| record.id == participant.hart)
                else {
                    return Err(SemanticInvariantError::SmpSafePointMissingHart {
                        safe_point: safe_point.id,
                        hart: participant.hart,
                    });
                };
                if hart.generation < participant.hart_generation
                    || (hart.generation == participant.hart_generation
                        && (hart.state != participant.hart_state
                            || hart.current_activation != participant.current_activation
                            || hart.current_activation_generation
                                != participant.current_activation_generation))
                {
                    return Err(SemanticInvariantError::SmpSafePointHartGenerationMismatch {
                        safe_point: safe_point.id,
                        hart: participant.hart,
                    });
                }
            }
            let Some(coordinator) = self
                .harts
                .iter()
                .find(|record| record.id == safe_point.coordinator_hart)
            else {
                return Err(SemanticInvariantError::SmpSafePointMissingHart {
                    safe_point: safe_point.id,
                    hart: safe_point.coordinator_hart,
                });
            };
            if coordinator.generation < safe_point.coordinator_hart_generation {
                return Err(SemanticInvariantError::SmpSafePointHartGenerationMismatch {
                    safe_point: safe_point.id,
                    hart: safe_point.coordinator_hart,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == safe_point.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SmpSafePointRecorded {
                            safe_point: event_safe_point,
                            coordinator_hart,
                            coordinator_hart_generation,
                            participant_count,
                            generation,
                        } if *event_safe_point == safe_point.id
                            && *coordinator_hart == safe_point.coordinator_hart
                            && *coordinator_hart_generation
                                == safe_point.coordinator_hart_generation
                            && *participant_count == safe_point.participants.len() as u32
                            && *generation == safe_point.generation
                    )
            }) {
                return Err(SemanticInvariantError::SmpSafePointMissingEvent {
                    safe_point: safe_point.id,
                });
            }
            if !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == safe_point.recorded_at_event
                    && attribution.hart == safe_point.coordinator_hart
                    && attribution.hart_generation == safe_point.coordinator_hart_generation
                    && attribution.event_kind == "SmpSafePointCoordinatorRecorded"
            }) {
                return Err(
                    SemanticInvariantError::SmpSafePointMissingHartEventAttribution {
                        safe_point: safe_point.id,
                        event: safe_point.recorded_at_event,
                    },
                );
            }
            for participant in &safe_point.participants {
                let expected_event_kind = if participant.hart == safe_point.coordinator_hart
                    && participant.hart_generation == safe_point.coordinator_hart_generation
                {
                    "SmpSafePointCoordinatorRecorded"
                } else {
                    "SmpSafePointParticipantRecorded"
                };
                if !self.hart_event_attributions.iter().any(|attribution| {
                    attribution.event == safe_point.recorded_at_event
                        && attribution.hart == participant.hart
                        && attribution.hart_generation == participant.hart_generation
                        && attribution.event_kind == expected_event_kind
                        && attribution.activation == participant.current_activation
                        && attribution.activation_generation
                            == participant.current_activation_generation
                }) {
                    return Err(
                        SemanticInvariantError::SmpSafePointMissingHartEventAttribution {
                            safe_point: safe_point.id,
                            event: safe_point.recorded_at_event,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn hart_is_safe_point_quiesced(hart: &HartRecord) -> bool {
        matches!(hart.state, HartState::Idle | HartState::Parked)
            && hart.current_activation.is_none()
            && hart.current_activation_generation.is_none()
    }
}
