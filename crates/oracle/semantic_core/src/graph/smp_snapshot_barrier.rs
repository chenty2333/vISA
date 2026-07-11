use alloc::{collections::BTreeSet, vec::Vec};

use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_smp_snapshot_barrier(
        &self,
        barrier: SmpSnapshotBarrierId,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        snapshot_state: &SnapshotBarrierValidationState,
        reason: &str,
    ) -> Result<(), &'static str> {
        if barrier == 0 {
            return Err("smp snapshot barrier id=0 is invalid");
        }
        if rendezvous == 0 || rendezvous_generation == 0 {
            return Err("smp snapshot barrier rendezvous is invalid");
        }
        if reason.is_empty() {
            return Err("smp snapshot barrier reason is empty");
        }
        if self.domains.scheduler.smp_snapshot_barriers.iter().any(|record| record.id == barrier) {
            return Err("smp snapshot barrier already exists");
        }
        let Some(rendezvous_record) =
            self.domains.scheduler.stop_the_world_rendezvous.iter().find(|record| {
                record.id == rendezvous && record.generation == rendezvous_generation
            })
        else {
            return Err("smp snapshot barrier rendezvous is missing");
        };
        if rendezvous_record.state != StopTheWorldRendezvousState::Completed
            || !rendezvous_record.stop_new_activations
            || rendezvous_record.participants.len() < 2
        {
            return Err("smp snapshot barrier rendezvous is invalid");
        }
        if self.pending_wait_count() != 0 {
            return Err("smp snapshot barrier found pending wait");
        }
        if self.active_transaction_count() != 0 {
            return Err("smp snapshot barrier found active semantic transaction");
        }
        let report = SnapshotBarrierValidator::validate(snapshot_state);
        if !report.is_ok() {
            return Err("smp snapshot barrier boundary state is not quiescent");
        }

        let mut participant_harts = BTreeSet::new();
        for participant in &rendezvous_record.participants {
            if participant.hart == 0
                || participant.hart_generation == 0
                || !participant_harts.insert(participant.hart)
            {
                return Err("smp snapshot barrier participant list is invalid");
            }
            let Some(hart) = self.domains.scheduler.harts.iter().find(|record| {
                record.id == participant.hart && record.generation == participant.hart_generation
            }) else {
                return Err("smp snapshot barrier participant generation is stale");
            };
            if !Self::hart_is_snapshot_barrier_quiesced(hart) {
                return Err("smp snapshot barrier participant is not quiesced");
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
                return Err("smp snapshot barrier missing active hart");
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_smp_snapshot_barrier_with_id(
        &mut self,
        barrier: SmpSnapshotBarrierId,
        rendezvous: StopTheWorldRendezvousId,
        rendezvous_generation: Generation,
        snapshot_state: SnapshotBarrierValidationState,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_smp_snapshot_barrier(
                barrier,
                rendezvous,
                rendezvous_generation,
                &snapshot_state,
                reason,
            )
            .is_err()
        {
            return false;
        }
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
        let event_log_cursor = self.event_log.cursor();
        let participants = rendezvous_record
            .participants
            .iter()
            .filter_map(|participant| {
                let hart = self.domains.scheduler.harts.iter().find(|record| {
                    record.id == participant.hart
                        && record.generation == participant.hart_generation
                })?;
                Some(SmpSnapshotBarrierParticipantRecord {
                    hart: participant.hart,
                    hart_generation: participant.hart_generation,
                    hardware_hart: participant.hardware_hart,
                    hart_state: participant.hart_state,
                    event_log_cursor_observed: event_log_cursor,
                    snapshot_safe: Self::hart_is_snapshot_barrier_quiesced(hart),
                })
            })
            .collect::<Vec<_>>();
        if participants.len() != rendezvous_record.participants.len() {
            return false;
        }

        self.domains.scheduler.next_smp_snapshot_barrier_id =
            self.domains.scheduler.next_smp_snapshot_barrier_id.max(barrier + 1);
        let event = self.event_log.push(
            "snapshot",
            EventKind::SmpSnapshotBarrierValidated {
                barrier,
                rendezvous,
                rendezvous_generation,
                event_log_cursor,
                participant_count: participants.len() as u32,
                generation: 1,
            },
        );
        self.domains.scheduler.smp_snapshot_barriers.push(SmpSnapshotBarrierRecord {
            id: barrier,
            rendezvous,
            rendezvous_generation,
            rendezvous_epoch: rendezvous_record.epoch,
            event_log_cursor,
            participants: participants.clone(),
            pending_wait_count: self.pending_wait_count() as u32,
            active_transaction_count: self.active_transaction_count() as u32,
            active_dmw_lease_count: snapshot_state.active_dmw_lease_count,
            active_nonconvertible_activation_count: snapshot_state
                .active_nonconvertible_activation_count,
            in_flight_dma_count: snapshot_state.in_flight_dma_count,
            unsealed_event_log: snapshot_state.unsealed_event_log,
            unflushed_trap_record_count: snapshot_state.unflushed_trap_record_count,
            pending_cleanup_count: snapshot_state.pending_cleanup_count,
            native_activation_stack_live: snapshot_state.native_activation_stack_live,
            raw_dma_binding_count: snapshot_state.raw_dma_binding_count,
            raw_mmio_binding_count: snapshot_state.raw_mmio_binding_count,
            snapshot_validation_ok: true,
            generation: 1,
            state: SmpSnapshotBarrierState::Validated,
            validated_at_event: event,
            reason: reason.to_string(),
            note: note.to_string(),
        });
        for participant in participants {
            let _ = self.push_hart_event_attribution(
                participant.hart,
                participant.hart_generation,
                event,
                "SmpSnapshotBarrierHartFrozen",
                None,
                None,
                note,
            );
        }
        true
    }

    pub fn smp_snapshot_barriers(&self) -> &[SmpSnapshotBarrierRecord] {
        &self.domains.scheduler.smp_snapshot_barriers
    }

    pub fn smp_snapshot_barrier_count(&self) -> usize {
        self.domains.scheduler.smp_snapshot_barriers.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_smp_snapshot_barrier_event_for_test(
        &mut self,
        barrier: SmpSnapshotBarrierId,
        event: EventId,
    ) {
        if let Some(record) = self
            .domains
            .scheduler
            .smp_snapshot_barriers
            .iter_mut()
            .find(|record| record.id == barrier)
        {
            record.validated_at_event = event;
        }
    }

    pub fn check_smp_snapshot_barrier_invariants(&self) -> Result<(), SemanticInvariantError> {
        let mut ids = BTreeSet::new();
        for barrier in &self.domains.scheduler.smp_snapshot_barriers {
            if barrier.id == 0
                || !ids.insert(barrier.id)
                || barrier.generation == 0
                || barrier.rendezvous == 0
                || barrier.rendezvous_generation == 0
                || barrier.event_log_cursor == 0
                || barrier.participants.len() < 2
                || barrier.state != SmpSnapshotBarrierState::Validated
                || !barrier.snapshot_validation_ok
                || !Self::snapshot_barrier_counts_are_clean(barrier)
            {
                return Err(SemanticInvariantError::SmpSnapshotBarrierInvalid {
                    barrier: barrier.id,
                });
            }
            let Some(rendezvous) =
                self.domains.scheduler.stop_the_world_rendezvous.iter().find(|record| {
                    record.id == barrier.rendezvous
                        && record.generation == barrier.rendezvous_generation
                })
            else {
                return Err(SemanticInvariantError::SmpSnapshotBarrierRendezvousMissing {
                    barrier: barrier.id,
                    rendezvous: barrier.rendezvous,
                });
            };
            if rendezvous.state != StopTheWorldRendezvousState::Completed
                || !rendezvous.stop_new_activations
                || rendezvous.epoch != barrier.rendezvous_epoch
                || rendezvous.participants.len() != barrier.participants.len()
                || rendezvous.completed_at_event > barrier.event_log_cursor
                || barrier.event_log_cursor >= barrier.validated_at_event
            {
                return Err(SemanticInvariantError::SmpSnapshotBarrierInvalid {
                    barrier: barrier.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == barrier.validated_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SmpSnapshotBarrierValidated {
                            barrier: event_barrier,
                            rendezvous,
                            rendezvous_generation,
                            event_log_cursor,
                            participant_count,
                            generation,
                        } if *event_barrier == barrier.id
                            && *rendezvous == barrier.rendezvous
                            && *rendezvous_generation == barrier.rendezvous_generation
                            && *event_log_cursor == barrier.event_log_cursor
                            && *participant_count == barrier.participants.len() as u32
                            && *generation == barrier.generation
                    )
            }) {
                return Err(SemanticInvariantError::SmpSnapshotBarrierMissingEvent {
                    barrier: barrier.id,
                });
            }
            let mut seen = BTreeSet::new();
            for participant in &barrier.participants {
                if participant.hart == 0
                    || participant.hart_generation == 0
                    || participant.event_log_cursor_observed != barrier.event_log_cursor
                    || !participant.snapshot_safe
                    || !seen.insert(participant.hart)
                {
                    return Err(SemanticInvariantError::SmpSnapshotBarrierParticipantMismatch {
                        barrier: barrier.id,
                        hart: participant.hart,
                    });
                }
                let Some(rendezvous_participant) = rendezvous.participants.iter().find(|record| {
                    record.hart == participant.hart
                        && record.hart_generation == participant.hart_generation
                }) else {
                    return Err(SemanticInvariantError::SmpSnapshotBarrierParticipantMismatch {
                        barrier: barrier.id,
                        hart: participant.hart,
                    });
                };
                if rendezvous_participant.hardware_hart != participant.hardware_hart
                    || rendezvous_participant.hart_state != participant.hart_state
                {
                    return Err(SemanticInvariantError::SmpSnapshotBarrierParticipantMismatch {
                        barrier: barrier.id,
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
                    return Err(SemanticInvariantError::SmpSnapshotBarrierParticipantMismatch {
                        barrier: barrier.id,
                        hart: participant.hart,
                    });
                };
                if current_hart.generation < participant.hart_generation
                    || (current_hart.generation == participant.hart_generation
                        && !Self::hart_is_snapshot_barrier_quiesced(current_hart))
                {
                    return Err(SemanticInvariantError::SmpSnapshotBarrierParticipantMismatch {
                        barrier: barrier.id,
                        hart: participant.hart,
                    });
                }
                if !self.domains.scheduler.hart_event_attributions.iter().any(|attribution| {
                    attribution.event == barrier.validated_at_event
                        && attribution.hart == participant.hart
                        && attribution.hart_generation == participant.hart_generation
                        && attribution.event_kind == "SmpSnapshotBarrierHartFrozen"
                }) {
                    return Err(
                        SemanticInvariantError::SmpSnapshotBarrierMissingHartEventAttribution {
                            barrier: barrier.id,
                            event: barrier.validated_at_event,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    fn hart_is_snapshot_barrier_quiesced(hart: &HartRecord) -> bool {
        matches!(hart.state, HartState::Idle | HartState::Parked)
            && hart.current_activation.is_none()
            && hart.current_activation_generation.is_none()
            && hart.current_store.is_none()
            && hart.current_store_generation.is_none()
    }

    fn snapshot_barrier_counts_are_clean(barrier: &SmpSnapshotBarrierRecord) -> bool {
        barrier.pending_wait_count == 0
            && barrier.active_transaction_count == 0
            && barrier.active_dmw_lease_count == 0
            && barrier.active_nonconvertible_activation_count == 0
            && barrier.in_flight_dma_count == 0
            && !barrier.unsealed_event_log
            && barrier.unflushed_trap_record_count == 0
            && barrier.pending_cleanup_count == 0
            && !barrier.native_activation_stack_live
            && barrier.raw_dma_binding_count == 0
            && barrier.raw_mmio_binding_count == 0
    }
}
