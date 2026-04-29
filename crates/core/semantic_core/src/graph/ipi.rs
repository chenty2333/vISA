use super::*;

impl SemanticGraph {
    pub fn record_ipi_event_with_id(
        &mut self,
        ipi: IpiEventId,
        source_hart: HartId,
        source_hart_generation: Generation,
        target_hart: HartId,
        target_hart_generation: Generation,
        kind: IpiEventKind,
        reason: &str,
        note: &str,
    ) -> bool {
        if ipi == 0
            || source_hart == 0
            || source_hart_generation == 0
            || target_hart == 0
            || target_hart_generation == 0
            || source_hart == target_hart
            || reason.is_empty()
            || self.ipi_events.iter().any(|record| record.id == ipi)
        {
            return false;
        }
        let Some(source) = self.harts.iter().find(|record| {
            record.id == source_hart
                && record.generation == source_hart_generation
                && !matches!(record.state, HartState::Offline | HartState::Faulted)
        }) else {
            return false;
        };
        let source_hardware_hart = source.hardware_id;
        let Some(target) = self.harts.iter().find(|record| {
            record.id == target_hart
                && record.generation == target_hart_generation
                && !matches!(record.state, HartState::Offline | HartState::Faulted)
        }) else {
            return false;
        };
        let target_hardware_hart = target.hardware_id;
        self.next_ipi_event_id = self.next_ipi_event_id.max(ipi + 1);
        let generation = 1;
        let event = self.event_log.push(
            "ipi",
            EventKind::IpiEventRecorded {
                ipi,
                source_hart,
                source_hart_generation,
                target_hart,
                target_hart_generation,
                kind,
                generation,
            },
        );
        self.ipi_events.push(IpiEventRecord {
            id: ipi,
            source_hart,
            source_hart_generation,
            source_hardware_hart,
            target_hart,
            target_hart_generation,
            target_hardware_hart,
            kind,
            generation,
            state: IpiEventState::Recorded,
            recorded_at_event: event,
            reason: reason.to_string(),
            note: note.to_string(),
        });
        let _ = self.push_hart_event_attribution(
            source_hart,
            source_hart_generation,
            event,
            "IpiEventSourceRecorded",
            None,
            None,
            note,
        );
        let _ = self.push_hart_event_attribution(
            target_hart,
            target_hart_generation,
            event,
            "IpiEventTargetRecorded",
            None,
            None,
            note,
        );
        true
    }

    pub fn ipi_events(&self) -> &[IpiEventRecord] {
        &self.ipi_events
    }

    pub fn ipi_event_count(&self) -> usize {
        self.ipi_events.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_ipi_event_target_generation_for_test(
        &mut self,
        ipi: IpiEventId,
        generation: Generation,
    ) {
        if let Some(record) = self.ipi_events.iter_mut().find(|record| record.id == ipi) {
            record.target_hart_generation = generation;
        }
    }

    pub fn check_ipi_invariants(&self) -> Result<(), SemanticInvariantError> {
        for ipi in &self.ipi_events {
            if ipi.id == 0
                || ipi.generation == 0
                || ipi.source_hart == 0
                || ipi.target_hart == 0
                || ipi.source_hart == ipi.target_hart
                || ipi.reason.is_empty()
            {
                return Err(SemanticInvariantError::IpiEventInvalid { ipi: ipi.id });
            }
            let Some(source) = self.harts.iter().find(|record| record.id == ipi.source_hart) else {
                return Err(SemanticInvariantError::IpiEventMissingHart {
                    ipi: ipi.id,
                    hart: ipi.source_hart,
                });
            };
            if source.generation < ipi.source_hart_generation
                || source.hardware_id != ipi.source_hardware_hart
            {
                return Err(SemanticInvariantError::IpiEventHartGenerationMismatch {
                    ipi: ipi.id,
                    hart: ipi.source_hart,
                });
            }
            let Some(target) = self.harts.iter().find(|record| record.id == ipi.target_hart) else {
                return Err(SemanticInvariantError::IpiEventMissingHart {
                    ipi: ipi.id,
                    hart: ipi.target_hart,
                });
            };
            if target.generation < ipi.target_hart_generation
                || target.hardware_id != ipi.target_hardware_hart
            {
                return Err(SemanticInvariantError::IpiEventHartGenerationMismatch {
                    ipi: ipi.id,
                    hart: ipi.target_hart,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == ipi.recorded_at_event
                    && matches!(
                        event.kind,
                        EventKind::IpiEventRecorded {
                            ipi: event_ipi,
                            source_hart,
                            source_hart_generation,
                            target_hart,
                            target_hart_generation,
                            kind,
                            generation,
                        } if event_ipi == ipi.id
                            && source_hart == ipi.source_hart
                            && source_hart_generation == ipi.source_hart_generation
                            && target_hart == ipi.target_hart
                            && target_hart_generation == ipi.target_hart_generation
                            && kind == ipi.kind
                            && generation == ipi.generation
                    )
            }) {
                return Err(SemanticInvariantError::IpiEventMissingEvent { ipi: ipi.id });
            }
            if !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == ipi.recorded_at_event
                    && attribution.hart == ipi.source_hart
                    && attribution.hart_generation == ipi.source_hart_generation
                    && attribution.event_kind == "IpiEventSourceRecorded"
            }) || !self.hart_event_attributions.iter().any(|attribution| {
                attribution.event == ipi.recorded_at_event
                    && attribution.hart == ipi.target_hart
                    && attribution.hart_generation == ipi.target_hart_generation
                    && attribution.event_kind == "IpiEventTargetRecorded"
            }) {
                return Err(SemanticInvariantError::IpiEventMissingHartEventAttribution {
                    ipi: ipi.id,
                    event: ipi.recorded_at_event,
                });
            }
        }
        Ok(())
    }
}
