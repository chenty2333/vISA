use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_remote_park_hart(
        &self,
        remote_park: RemoteParkId,
        ipi: IpiEventId,
        ipi_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
    ) -> Result<(), &'static str> {
        if remote_park == 0 {
            return Err("remote park id=0 is invalid");
        }
        if self
            .remote_parks
            .iter()
            .any(|record| record.id == remote_park)
        {
            return Err("remote park already exists");
        }
        if source_hart == target_hart {
            return Err("remote park source and target harts must differ");
        }
        let Some(ipi_record) = self
            .ipi_events
            .iter()
            .find(|record| record.id == ipi && record.generation == ipi_generation)
        else {
            return Err("remote park ipi generation is missing");
        };
        let Some(source) = self
            .harts
            .iter()
            .find(|record| record.id == source_hart && record.generation == source_hart_generation)
        else {
            return Err("remote park source hart generation is missing");
        };
        if matches!(
            source.state,
            HartState::Offline | HartState::Faulted | HartState::Parked
        ) {
            return Err("remote park source hart is inactive");
        }
        let Some(target) = self
            .harts
            .iter()
            .find(|record| record.id == target_hart && record.generation == target_hart_generation)
        else {
            return Err("remote park target hart generation is missing");
        };
        if target.state != HartState::Idle
            || target.current_activation.is_some()
            || target.current_activation_generation.is_some()
        {
            return Err("remote park target hart is not idle");
        }
        if ipi_record.kind != IpiEventKind::SchedulerKick
            || ipi_record.source_hart != source_hart
            || ipi_record.target_hart != target_hart
            || source_hart_generation < ipi_record.source_hart_generation
            || target_hart_generation < ipi_record.target_hart_generation
        {
            return Err("remote park ipi source/target mismatch");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn remote_park_hart_with_id(
        &mut self,
        remote_park: RemoteParkId,
        ipi: IpiEventId,
        ipi_generation: Generation,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_remote_park_hart(
                remote_park,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
            )
            .is_err()
        {
            return false;
        }

        let Some(target_index) = self.harts.iter().position(|record| {
            record.id == target_hart && record.generation == target_hart_generation
        }) else {
            return false;
        };

        self.next_remote_park_id = self.next_remote_park_id.max(remote_park + 1);
        self.harts[target_index].state = HartState::Parked;
        self.harts[target_index].generation += 1;
        self.harts[target_index].current_activation = None;
        self.harts[target_index].current_activation_generation = None;
        self.harts[target_index].current_task = None;
        self.harts[target_index].current_task_generation = None;
        self.harts[target_index].current_store = None;
        self.harts[target_index].current_store_generation = None;
        if !note.is_empty() {
            self.harts[target_index].note = note.to_string();
        }
        let target_hart_generation_after = self.harts[target_index].generation;
        let remote_event = self.event_log.push(
            "scheduler",
            EventKind::RemoteHartParked {
                remote_park,
                ipi,
                ipi_generation,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation_before: target_hart_generation,
                target_hart_generation_after,
                reason: reason.to_string(),
                generation: 1,
            },
        );
        self.harts[target_index].last_event = Some(remote_event);
        self.harts[target_index].last_current_event = Some(remote_event);
        self.remote_parks.push(RemoteParkRecord {
            id: remote_park,
            ipi,
            ipi_generation,
            source_hart,
            source_hart_generation,
            target_hart,
            target_hart_generation_before: target_hart_generation,
            target_hart_generation_after,
            generation: 1,
            state: RemoteParkState::Parked,
            parked_at_event: remote_event,
            reason: reason.to_string(),
            note: note.to_string(),
        });
        let _ = self.push_hart_event_attribution(
            source_hart,
            source_hart_generation,
            remote_event,
            "RemoteParkSourceRecorded",
            None,
            None,
            note,
        );
        let _ = self.push_hart_event_attribution(
            target_hart,
            target_hart_generation_after,
            remote_event,
            "RemoteParkTargetRecorded",
            None,
            None,
            note,
        );
        true
    }

    pub fn remote_parks(&self) -> &[RemoteParkRecord] {
        &self.remote_parks
    }

    pub fn remote_park_count(&self) -> usize {
        self.remote_parks.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_remote_park_ipi_generation_for_test(
        &mut self,
        remote_park: RemoteParkId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .remote_parks
            .iter_mut()
            .find(|record| record.id == remote_park)
        {
            record.ipi_generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_remote_park_event_for_test(
        &mut self,
        remote_park: RemoteParkId,
        event: EventId,
    ) {
        if let Some(record) = self
            .remote_parks
            .iter_mut()
            .find(|record| record.id == remote_park)
        {
            record.parked_at_event = event;
        }
    }

    pub fn check_remote_park_invariants(&self) -> Result<(), SemanticInvariantError> {
        for remote in &self.remote_parks {
            if remote.id == 0
                || remote.generation == 0
                || remote.ipi == 0
                || remote.ipi_generation == 0
                || remote.source_hart == 0
                || remote.target_hart == 0
                || remote.source_hart == remote.target_hart
            {
                return Err(SemanticInvariantError::RemoteParkInvalid {
                    remote_park: remote.id,
                });
            }
            let Some(ipi) = self.ipi_events.iter().find(|record| {
                record.id == remote.ipi && record.generation == remote.ipi_generation
            }) else {
                return Err(SemanticInvariantError::RemoteParkMissingIpi {
                    remote_park: remote.id,
                    ipi: remote.ipi,
                });
            };
            if ipi.kind != IpiEventKind::SchedulerKick
                || ipi.source_hart != remote.source_hart
                || ipi.target_hart != remote.target_hart
                || remote.source_hart_generation < ipi.source_hart_generation
                || remote.target_hart_generation_before < ipi.target_hart_generation
            {
                return Err(SemanticInvariantError::RemoteParkIpiMismatch {
                    remote_park: remote.id,
                    ipi: remote.ipi,
                });
            }
            let Some(source) = self
                .harts
                .iter()
                .find(|record| record.id == remote.source_hart)
            else {
                return Err(SemanticInvariantError::RemoteParkMissingHart {
                    remote_park: remote.id,
                    hart: remote.source_hart,
                });
            };
            if source.generation < remote.source_hart_generation {
                return Err(SemanticInvariantError::RemoteParkHartGenerationMismatch {
                    remote_park: remote.id,
                    hart: remote.source_hart,
                });
            }
            let Some(target) = self
                .harts
                .iter()
                .find(|record| record.id == remote.target_hart)
            else {
                return Err(SemanticInvariantError::RemoteParkMissingHart {
                    remote_park: remote.id,
                    hart: remote.target_hart,
                });
            };
            if target.generation < remote.target_hart_generation_after
                || (target.generation == remote.target_hart_generation_after
                    && (target.state != HartState::Parked
                        || target.current_activation.is_some()
                        || target.current_activation_generation.is_some()))
            {
                return Err(SemanticInvariantError::RemoteParkHartGenerationMismatch {
                    remote_park: remote.id,
                    hart: remote.target_hart,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == remote.parked_at_event
                    && matches!(
                        &event.kind,
                        EventKind::RemoteHartParked {
                            remote_park,
                            ipi,
                            ipi_generation,
                            source_hart,
                            source_hart_generation,
                            target_hart,
                            target_hart_generation_before,
                            target_hart_generation_after,
                            reason,
                            generation,
                        } if *remote_park == remote.id
                            && *ipi == remote.ipi
                            && *ipi_generation == remote.ipi_generation
                            && *source_hart == remote.source_hart
                            && *source_hart_generation == remote.source_hart_generation
                            && *target_hart == remote.target_hart
                            && *target_hart_generation_before == remote.target_hart_generation_before
                            && *target_hart_generation_after == remote.target_hart_generation_after
                            && reason == &remote.reason
                            && *generation == remote.generation
                    )
            }) {
                return Err(SemanticInvariantError::RemoteParkMissingEvent {
                    remote_park: remote.id,
                });
            }
            if !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == remote.parked_at_event
                    && attribution.hart == remote.source_hart
                    && attribution.hart_generation == remote.source_hart_generation
                    && attribution.event_kind == "RemoteParkSourceRecorded"
            }) || !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == remote.parked_at_event
                    && attribution.hart == remote.target_hart
                    && attribution.hart_generation == remote.target_hart_generation_after
                    && attribution.event_kind == "RemoteParkTargetRecorded"
            }) {
                return Err(
                    SemanticInvariantError::RemoteParkMissingHartEventAttribution {
                        remote_park: remote.id,
                        event: remote.parked_at_event,
                    },
                );
            }
        }
        Ok(())
    }
}
