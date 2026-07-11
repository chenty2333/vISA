use super::*;

impl SemanticGraph {
    pub(crate) fn validate_irq_event(
        &self,
        irq_event: IrqEventId,
        irq_line: IrqLineObjectId,
        irq_line_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_store: StoreId,
        driver_store_generation: Generation,
        sequence: u64,
    ) -> Result<(), &'static str> {
        if irq_event == 0 {
            return Err("irq event id=0 is invalid");
        }
        if self.domains.device.irq_events.iter().any(|record| record.id == irq_event) {
            return Err("irq event already exists");
        }
        if sequence == 0 {
            return Err("irq event sequence is zero");
        }
        let Some(line_record) = self.domains.device.irq_line_objects.iter().find(|record| {
            record.id == irq_line
                && record.generation == irq_line_generation
                && record.state == IrqLineObjectState::Registered
        }) else {
            return Err("irq event line generation is missing or inactive");
        };
        if line_record.device != device || line_record.device_generation != device_generation {
            return Err("irq event device does not match irq line");
        }
        let Some(device_record) = self.domains.device.device_objects.iter().find(|record| {
            record.id == device
                && record.generation == device_generation
                && record.state == DeviceObjectState::Registered
        }) else {
            return Err("irq event device generation is missing or inactive");
        };
        let Some(store_record) =
            self.domains.lifecycle.stores.iter().find(|record| record.id == driver_store)
        else {
            return Err("irq event driver store is missing");
        };
        if store_record.generation != driver_store_generation {
            return Err("irq event driver store generation mismatch");
        }
        if store_record.state == StoreState::Dead {
            return Err("irq event driver store is dead");
        }
        if store_record.role != "driver" {
            return Err("irq event driver store role is not driver");
        }
        if self.domains.device.irq_events.iter().any(|record| {
            record.irq_line == line_record.id
                && record.irq_line_generation == irq_line_generation
                && record.sequence == sequence
                && record.state == IrqEventState::Recorded
        }) {
            return Err("irq event sequence already exists for irq line generation");
        }
        if device_record.id != line_record.device {
            return Err("irq event device does not match irq line");
        }
        if self.check_invariants().is_err() {
            return Err("irq event requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_irq_event_with_id(
        &mut self,
        irq_event: IrqEventId,
        irq_line: IrqLineObjectId,
        irq_line_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_store: StoreId,
        driver_store_generation: Generation,
        sequence: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_irq_event(
                irq_event,
                irq_line,
                irq_line_generation,
                device,
                device_generation,
                driver_store,
                driver_store_generation,
                sequence,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        let Some(irq_number) = self
            .domains
            .device
            .irq_line_objects
            .iter()
            .find(|record| record.id == irq_line && record.generation == irq_line_generation)
            .map(|record| record.irq_number)
        else {
            return false;
        };
        self.domains.device.next_irq_event_id =
            self.domains.device.next_irq_event_id.max(irq_event + 1);
        let recorded_at_event = self.event_log.push(
            "io",
            EventKind::IrqEventRecorded {
                irq_event,
                irq_line,
                irq_line_generation,
                device,
                device_generation,
                driver_store,
                driver_store_generation,
                irq_number,
                sequence,
                generation,
            },
        );
        self.domains.device.irq_events.push(IrqEventRecord {
            id: irq_event,
            irq_line,
            irq_line_generation,
            device,
            device_generation,
            driver_store,
            driver_store_generation,
            irq_number,
            sequence,
            generation,
            state: IrqEventState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn irq_events(&self) -> &[IrqEventRecord] {
        &self.domains.device.irq_events
    }

    pub fn irq_event_count(&self) -> usize {
        self.domains.device.irq_events.len()
    }

    pub fn check_irq_event_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.device.irq_events {
            let Some(line_record) = self.domains.device.irq_line_objects.iter().find(|line| {
                line.id == record.irq_line && line.generation == record.irq_line_generation
            }) else {
                return Err(SemanticInvariantError::IrqEventMissingLine {
                    irq_event: record.id,
                    irq_line: record.irq_line,
                });
            };
            let Some(device_record) = self.domains.device.device_objects.iter().find(|device| {
                device.id == record.device && device.generation == record.device_generation
            }) else {
                return Err(SemanticInvariantError::IrqEventMissingDevice {
                    irq_event: record.id,
                    device: record.device,
                });
            };
            let Some(store_record) = self.domains.lifecycle.stores.iter().find(|store| {
                store.id == record.driver_store
                    && store.generation == record.driver_store_generation
            }) else {
                return Err(SemanticInvariantError::IrqEventMissingDriverStore {
                    irq_event: record.id,
                    store: record.driver_store,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.irq_line_generation == 0
                || record.device_generation == 0
                || record.driver_store_generation == 0
                || record.sequence == 0
                || !matches!(
                    line_record.state,
                    IrqLineObjectState::Registered | IrqLineObjectState::Released
                )
                || line_record.device != record.device
                || line_record.device_generation != record.device_generation
                || line_record.irq_number != record.irq_number
                || device_record.state != DeviceObjectState::Registered
                || store_record.state == StoreState::Dead
                || store_record.role != "driver"
                || record.state != IrqEventState::Recorded
            {
                return Err(SemanticInvariantError::IrqEventInvalid { irq_event: record.id });
            }
            if let Some(duplicate) = self.domains.device.irq_events.iter().find(|other| {
                other.id != record.id
                    && other.irq_line == record.irq_line
                    && other.irq_line_generation == record.irq_line_generation
                    && other.sequence == record.sequence
                    && other.state == IrqEventState::Recorded
            }) {
                return Err(SemanticInvariantError::IrqEventDuplicateSequence {
                    irq_event: duplicate.id,
                    irq_line: record.irq_line,
                    sequence: record.sequence,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IrqEventRecorded {
                            irq_event,
                            irq_line,
                            irq_line_generation,
                            device,
                            device_generation,
                            driver_store,
                            driver_store_generation,
                            irq_number,
                            sequence,
                            generation,
                        } if *irq_event == record.id
                            && *irq_line == record.irq_line
                            && *irq_line_generation == record.irq_line_generation
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *driver_store == record.driver_store
                            && *driver_store_generation == record.driver_store_generation
                            && *irq_number == record.irq_number
                            && *sequence == record.sequence
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::IrqEventMissingEvent { irq_event: record.id });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_irq_event_driver_store_generation_for_test(
        &mut self,
        irq_event: IrqEventId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.domains.device.irq_events.iter_mut().find(|record| record.id == irq_event)
        {
            record.driver_store_generation = generation;
        }
    }
}
