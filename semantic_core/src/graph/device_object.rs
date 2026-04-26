use super::*;

impl SemanticGraph {
    pub(crate) fn validate_device_object(
        &self,
        device: DeviceObjectId,
        name: &str,
        class: &str,
        resource: ResourceId,
        resource_generation: Generation,
        backend: &str,
    ) -> Result<(), &'static str> {
        if device == 0 {
            return Err("device object id=0 is invalid");
        }
        if self.device_objects.iter().any(|record| record.id == device) {
            return Err("device object already exists");
        }
        if name.is_empty() {
            return Err("device object name is empty");
        }
        if class.is_empty() {
            return Err("device object class is empty");
        }
        if backend.is_empty() {
            return Err("device object backend is empty");
        }
        let Some(resource_record) = self.resources.iter().find(|record| record.id == resource)
        else {
            return Err("device object resource is missing");
        };
        if resource_record.generation != resource_generation {
            return Err("device object resource generation mismatch");
        }
        if !resource_record.live {
            return Err("device object resource is dead");
        }
        if !Self::resource_kind_can_back_device(resource_record.kind) {
            return Err("device object resource kind is not device-capable");
        }
        if self.check_invariants().is_err() {
            return Err("device object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_device_object_with_id(
        &mut self,
        device: DeviceObjectId,
        name: &str,
        class: &str,
        resource: ResourceId,
        resource_generation: Generation,
        backend: &str,
        bus: &str,
        vendor: &str,
        model: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_device_object(device, name, class, resource, resource_generation, backend)
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_device_object_id = self.next_device_object_id.max(device + 1);
        let recorded_at_event = self.event_log.push(
            "io",
            EventKind::DeviceObjectRecorded {
                device,
                resource,
                resource_generation,
                class: class.to_string(),
                backend: backend.to_string(),
                generation,
            },
        );
        self.device_objects.push(DeviceObjectRecord {
            id: device,
            name: name.to_string(),
            class: class.to_string(),
            resource,
            resource_generation,
            backend: backend.to_string(),
            bus: bus.to_string(),
            vendor: vendor.to_string(),
            model: model.to_string(),
            generation,
            state: DeviceObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn device_objects(&self) -> &[DeviceObjectRecord] {
        &self.device_objects
    }

    pub fn device_object_count(&self) -> usize {
        self.device_objects.len()
    }

    pub fn check_device_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.device_objects {
            let Some(resource_record) = self.resources.iter().find(|resource| {
                resource.id == record.resource && resource.generation == record.resource_generation
            }) else {
                return Err(SemanticInvariantError::DeviceObjectMissingResource {
                    device: record.id,
                    resource: record.resource,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.class.is_empty()
                || record.backend.is_empty()
                || record.resource_generation == 0
                || !resource_record.live
                || !Self::resource_kind_can_back_device(resource_record.kind)
                || record.state != DeviceObjectState::Registered
            {
                return Err(SemanticInvariantError::DeviceObjectInvalid { device: record.id });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DeviceObjectRecorded {
                            device,
                            resource,
                            resource_generation,
                            class,
                            backend,
                            generation,
                        } if *device == record.id
                            && *resource == record.resource
                            && *resource_generation == record.resource_generation
                            && class == &record.class
                            && backend == &record.backend
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::DeviceObjectMissingEvent { device: record.id });
            }
        }
        Ok(())
    }

    fn resource_kind_can_back_device(kind: ResourceKind) -> bool {
        matches!(
            kind,
            ResourceKind::Device | ResourceKind::PacketDevice | ResourceKind::PciDevice
        )
    }

    #[cfg(test)]
    pub(crate) fn corrupt_device_object_resource_generation_for_test(
        &mut self,
        device: DeviceObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .device_objects
            .iter_mut()
            .find(|record| record.id == device)
        {
            record.resource_generation = generation;
        }
    }
}
