use super::*;

impl SemanticGraph {
    pub(crate) fn validate_irq_line_object(
        &self,
        irq_line: IrqLineObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        irq_number: u32,
        trigger: IrqLineTrigger,
        polarity: IrqLinePolarity,
    ) -> Result<(), &'static str> {
        if irq_line == 0 {
            return Err("irq line object id=0 is invalid");
        }
        if self
            .irq_line_objects
            .iter()
            .any(|record| record.id == irq_line)
        {
            return Err("irq line object already exists");
        }
        if !Self::irq_line_trigger_is_supported(trigger) {
            return Err("irq line object trigger is unsupported");
        }
        if !Self::irq_line_polarity_is_supported(polarity) {
            return Err("irq line object polarity is unsupported");
        }
        let Some(device_record) = self.device_objects.iter().find(|record| {
            record.id == device
                && record.generation == device_generation
                && record.state == DeviceObjectState::Registered
        }) else {
            return Err("irq line object device generation is missing or inactive");
        };
        let Some(resource_record) = self.resources.iter().find(|record| record.id == resource)
        else {
            return Err("irq line object resource is missing");
        };
        if resource_record.generation != resource_generation {
            return Err("irq line object resource generation mismatch");
        }
        if !resource_record.live {
            return Err("irq line object resource is dead");
        }
        if resource_record.kind != ResourceKind::IrqLine {
            return Err("irq line object resource kind is not irq-line");
        }
        if self.irq_line_objects.iter().any(|record| {
            record.device == device_record.id
                && record.device_generation == device_generation
                && record.irq_number == irq_number
                && record.state == IrqLineObjectState::Registered
        }) {
            return Err("irq line object number already exists for device generation");
        }
        if self.check_invariants().is_err() {
            return Err("irq line object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_irq_line_object_with_id(
        &mut self,
        irq_line: IrqLineObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        irq_number: u32,
        trigger: IrqLineTrigger,
        polarity: IrqLinePolarity,
        note: &str,
    ) -> bool {
        if self
            .validate_irq_line_object(
                irq_line,
                device,
                device_generation,
                resource,
                resource_generation,
                irq_number,
                trigger,
                polarity,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_irq_line_object_id = self.next_irq_line_object_id.max(irq_line + 1);
        let recorded_at_event = self.event_log.push(
            "io",
            EventKind::IrqLineObjectRecorded {
                irq_line,
                device,
                device_generation,
                resource,
                resource_generation,
                irq_number,
                trigger,
                polarity,
                generation,
            },
        );
        self.irq_line_objects.push(IrqLineObjectRecord {
            id: irq_line,
            device,
            device_generation,
            resource,
            resource_generation,
            irq_number,
            trigger,
            polarity,
            generation,
            state: IrqLineObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn irq_line_objects(&self) -> &[IrqLineObjectRecord] {
        &self.irq_line_objects
    }

    pub fn irq_line_object_count(&self) -> usize {
        self.irq_line_objects.len()
    }

    pub fn check_irq_line_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.irq_line_objects {
            let Some(device_record) = self.device_objects.iter().find(|device| {
                device.id == record.device && device.generation == record.device_generation
            }) else {
                return Err(SemanticInvariantError::IrqLineObjectMissingDevice {
                    irq_line: record.id,
                    device: record.device,
                });
            };
            let Some(resource_record) = self.resources.iter().find(|resource| {
                resource.id == record.resource && resource.generation == record.resource_generation
            }) else {
                return Err(SemanticInvariantError::IrqLineObjectMissingResource {
                    irq_line: record.id,
                    resource: record.resource,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.device_generation == 0
                || record.resource_generation == 0
                || resource_record.kind != ResourceKind::IrqLine
                || !matches!(
                    record.state,
                    IrqLineObjectState::Registered | IrqLineObjectState::Released
                )
                || (record.state == IrqLineObjectState::Registered
                    && (device_record.state != DeviceObjectState::Registered
                        || !resource_record.live))
                || !Self::irq_line_trigger_is_supported(record.trigger)
                || !Self::irq_line_polarity_is_supported(record.polarity)
            {
                return Err(SemanticInvariantError::IrqLineObjectInvalid {
                    irq_line: record.id,
                });
            }
            if let Some(duplicate) = self.irq_line_objects.iter().find(|other| {
                other.id != record.id
                    && other.device == record.device
                    && other.device_generation == record.device_generation
                    && other.irq_number == record.irq_number
                    && other.state == IrqLineObjectState::Registered
            }) {
                return Err(SemanticInvariantError::IrqLineObjectDuplicateNumber {
                    irq_line: duplicate.id,
                    device: record.device,
                    irq_number: record.irq_number,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IrqLineObjectRecorded {
                            irq_line,
                            device,
                            device_generation,
                            resource,
                            resource_generation,
                            irq_number,
                            trigger,
                            polarity,
                            generation,
                        } if *irq_line == record.id
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *resource == record.resource
                            && *resource_generation == record.resource_generation
                            && *irq_number == record.irq_number
                            && *trigger == record.trigger
                            && *polarity == record.polarity
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::IrqLineObjectMissingEvent {
                    irq_line: record.id,
                });
            }
        }
        Ok(())
    }

    const fn irq_line_trigger_is_supported(trigger: IrqLineTrigger) -> bool {
        matches!(trigger, IrqLineTrigger::Edge | IrqLineTrigger::Level)
    }

    const fn irq_line_polarity_is_supported(polarity: IrqLinePolarity) -> bool {
        matches!(
            polarity,
            IrqLinePolarity::ActiveHigh | IrqLinePolarity::ActiveLow
        )
    }

    #[cfg(test)]
    pub(crate) fn corrupt_irq_line_object_device_generation_for_test(
        &mut self,
        irq_line: IrqLineObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .irq_line_objects
            .iter_mut()
            .find(|record| record.id == irq_line)
        {
            record.device_generation = generation;
        }
    }
}
