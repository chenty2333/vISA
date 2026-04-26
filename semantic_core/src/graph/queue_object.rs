use super::*;

impl SemanticGraph {
    pub(crate) fn validate_queue_object(
        &self,
        queue: QueueObjectId,
        name: &str,
        role: QueueObjectRole,
        queue_index: u16,
        depth: u32,
        device: DeviceObjectId,
        device_generation: Generation,
    ) -> Result<(), &'static str> {
        if queue == 0 {
            return Err("queue object id=0 is invalid");
        }
        if self.queue_objects.iter().any(|record| record.id == queue) {
            return Err("queue object already exists");
        }
        if name.is_empty() {
            return Err("queue object name is empty");
        }
        if depth == 0 {
            return Err("queue object depth is zero");
        }
        if !Self::queue_role_is_supported(role) {
            return Err("queue object role is unsupported");
        }
        let Some(device_record) = self.device_objects.iter().find(|record| {
            record.id == device
                && record.generation == device_generation
                && record.state == DeviceObjectState::Registered
        }) else {
            return Err("queue object device generation is missing or inactive");
        };
        if self.queue_objects.iter().any(|record| {
            record.device == device_record.id
                && record.device_generation == device_generation
                && record.queue_index == queue_index
                && record.state == QueueObjectState::Registered
        }) {
            return Err("queue object index already exists for device generation");
        }
        if self.check_invariants().is_err() {
            return Err("queue object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_queue_object_with_id(
        &mut self,
        queue: QueueObjectId,
        name: &str,
        role: QueueObjectRole,
        queue_index: u16,
        depth: u32,
        device: DeviceObjectId,
        device_generation: Generation,
        note: &str,
    ) -> bool {
        if self
            .validate_queue_object(
                queue,
                name,
                role,
                queue_index,
                depth,
                device,
                device_generation,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_queue_object_id = self.next_queue_object_id.max(queue + 1);
        let recorded_at_event = self.event_log.push(
            "io",
            EventKind::QueueObjectRecorded {
                queue,
                device,
                device_generation,
                role,
                queue_index,
                depth,
                generation,
            },
        );
        self.queue_objects.push(QueueObjectRecord {
            id: queue,
            name: name.to_string(),
            role,
            queue_index,
            depth,
            device,
            device_generation,
            generation,
            state: QueueObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn queue_objects(&self) -> &[QueueObjectRecord] {
        &self.queue_objects
    }

    pub fn queue_object_count(&self) -> usize {
        self.queue_objects.len()
    }

    pub fn check_queue_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.queue_objects {
            let Some(device_record) = self.device_objects.iter().find(|device| {
                device.id == record.device && device.generation == record.device_generation
            }) else {
                return Err(SemanticInvariantError::QueueObjectMissingDevice {
                    queue: record.id,
                    device: record.device,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.depth == 0
                || record.device_generation == 0
                || device_record.state != DeviceObjectState::Registered
                || record.state != QueueObjectState::Registered
            {
                return Err(SemanticInvariantError::QueueObjectInvalid { queue: record.id });
            }
            if let Some(duplicate) = self.queue_objects.iter().find(|other| {
                other.id != record.id
                    && other.device == record.device
                    && other.device_generation == record.device_generation
                    && other.queue_index == record.queue_index
                    && other.state == QueueObjectState::Registered
            }) {
                return Err(SemanticInvariantError::QueueObjectDuplicateIndex {
                    queue: duplicate.id,
                    device: record.device,
                    queue_index: record.queue_index,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::QueueObjectRecorded {
                            queue,
                            device,
                            device_generation,
                            role,
                            queue_index,
                            depth,
                            generation,
                        } if *queue == record.id
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *role == record.role
                            && *queue_index == record.queue_index
                            && *depth == record.depth
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::QueueObjectMissingEvent { queue: record.id });
            }
        }
        Ok(())
    }

    const fn queue_role_is_supported(role: QueueObjectRole) -> bool {
        matches!(
            role,
            QueueObjectRole::Rx
                | QueueObjectRole::Tx
                | QueueObjectRole::Control
                | QueueObjectRole::Submission
                | QueueObjectRole::Completion
        )
    }

    #[cfg(test)]
    pub(crate) fn corrupt_queue_object_device_generation_for_test(
        &mut self,
        queue: QueueObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .queue_objects
            .iter_mut()
            .find(|record| record.id == queue)
        {
            record.device_generation = generation;
        }
    }
}
