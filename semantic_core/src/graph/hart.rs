use super::*;

impl SemanticGraph {
    pub fn register_hart_with_id(
        &mut self,
        hart: HartId,
        hardware_id: u32,
        label: &str,
        boot: bool,
        note: &str,
    ) -> bool {
        if hart == 0
            || label.is_empty()
            || self
                .harts
                .iter()
                .any(|record| record.id == hart || record.hardware_id == hardware_id)
            || (boot && self.harts.iter().any(|record| record.boot))
        {
            return false;
        }
        let generation = 1;
        let event = self.event_log.push(
            "scheduler",
            EventKind::HartRegistered {
                hart,
                hardware_id,
                label: label.to_string(),
                boot,
                generation,
            },
        );
        self.harts.push(HartRecord {
            id: hart,
            hardware_id,
            label: label.to_string(),
            state: HartState::Created,
            generation,
            boot,
            last_event: Some(event),
            note: note.to_string(),
        });
        true
    }

    pub fn set_hart_state(
        &mut self,
        hart: HartId,
        hart_generation: Generation,
        state: HartState,
        reason: &str,
        note: &str,
    ) -> bool {
        if reason.is_empty() {
            return false;
        }
        let Some(index) = self
            .harts
            .iter()
            .position(|record| record.id == hart && record.generation == hart_generation)
        else {
            return false;
        };
        let from = self.harts[index].state;
        if from == state {
            return false;
        }
        self.harts[index].state = state;
        self.harts[index].generation += 1;
        if !note.is_empty() {
            self.harts[index].note = note.to_string();
        }
        let generation = self.harts[index].generation;
        let event = self.event_log.push(
            "scheduler",
            EventKind::HartStateChanged {
                hart,
                from,
                to: state,
                reason: reason.to_string(),
                generation,
            },
        );
        self.harts[index].last_event = Some(event);
        true
    }

    pub fn harts(&self) -> &[HartRecord] {
        &self.harts
    }

    pub fn hart_count(&self) -> usize {
        self.harts.len()
    }

    #[cfg(test)]
    pub(crate) fn corrupt_hart_generation_for_test(
        &mut self,
        hart: HartId,
        generation: Generation,
    ) {
        if let Some(record) = self.harts.iter_mut().find(|record| record.id == hart) {
            record.generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn duplicate_hart_for_test(&mut self, hart: HartRecord) {
        self.harts.push(hart);
    }

    pub fn check_hart_invariants(&self) -> Result<(), SemanticInvariantError> {
        let mut boot_harts = 0;
        for (index, hart) in self.harts.iter().enumerate() {
            if hart.id == 0 || hart.generation == 0 || hart.label.is_empty() {
                return Err(SemanticInvariantError::HartInvalidObjectIdentity { hart: hart.id });
            }
            if hart.boot {
                boot_harts += 1;
            }
            if self.harts[index + 1..]
                .iter()
                .any(|other| other.id == hart.id)
            {
                return Err(SemanticInvariantError::DuplicateHart { hart: hart.id });
            }
            if self.harts[index + 1..]
                .iter()
                .any(|other| other.hardware_id == hart.hardware_id)
            {
                return Err(SemanticInvariantError::DuplicateHardwareHart {
                    hardware_id: hart.hardware_id,
                });
            }
        }
        if boot_harts > 1 {
            return Err(SemanticInvariantError::MultipleBootHarts);
        }
        Ok(())
    }
}
