use super::*;

impl SemanticGraph {
    pub(crate) fn validate_descriptor_object(
        &self,
        descriptor: DescriptorObjectId,
        queue: QueueObjectId,
        queue_generation: Generation,
        slot: u16,
        access: DescriptorObjectAccess,
        length: u32,
    ) -> Result<(), &'static str> {
        if descriptor == 0 {
            return Err("descriptor object id=0 is invalid");
        }
        if self.descriptor_objects.iter().any(|record| record.id == descriptor) {
            return Err("descriptor object already exists");
        }
        if length == 0 {
            return Err("descriptor object length is zero");
        }
        if !Self::descriptor_access_is_supported(access) {
            return Err("descriptor object access is unsupported");
        }
        let Some(queue_record) = self.queue_objects.iter().find(|record| {
            record.id == queue
                && record.generation == queue_generation
                && record.state == QueueObjectState::Registered
        }) else {
            return Err("descriptor object queue generation is missing or inactive");
        };
        if u32::from(slot) >= queue_record.depth {
            return Err("descriptor object slot is outside queue depth");
        }
        if self.descriptor_objects.iter().any(|record| {
            record.queue == queue_record.id
                && record.queue_generation == queue_generation
                && record.slot == slot
                && record.state == DescriptorObjectState::Registered
        }) {
            return Err("descriptor object slot already exists for queue generation");
        }
        if self.check_invariants().is_err() {
            return Err("descriptor object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_descriptor_object_with_id(
        &mut self,
        descriptor: DescriptorObjectId,
        queue: QueueObjectId,
        queue_generation: Generation,
        slot: u16,
        access: DescriptorObjectAccess,
        length: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_descriptor_object(descriptor, queue, queue_generation, slot, access, length)
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_descriptor_object_id = self.next_descriptor_object_id.max(descriptor + 1);
        let recorded_at_event = self.event_log.push(
            "io",
            EventKind::DescriptorObjectRecorded {
                descriptor,
                queue,
                queue_generation,
                slot,
                access,
                length,
                generation,
            },
        );
        self.descriptor_objects.push(DescriptorObjectRecord {
            id: descriptor,
            queue,
            queue_generation,
            slot,
            access,
            length,
            generation,
            state: DescriptorObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn descriptor_objects(&self) -> &[DescriptorObjectRecord] {
        &self.descriptor_objects
    }

    pub fn descriptor_object_count(&self) -> usize {
        self.descriptor_objects.len()
    }

    pub fn check_descriptor_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.descriptor_objects {
            let Some(queue_record) = self.queue_objects.iter().find(|queue| {
                queue.id == record.queue && queue.generation == record.queue_generation
            }) else {
                return Err(SemanticInvariantError::DescriptorObjectMissingQueue {
                    descriptor: record.id,
                    queue: record.queue,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.length == 0
                || record.queue_generation == 0
                || u32::from(record.slot) >= queue_record.depth
                || queue_record.state != QueueObjectState::Registered
                || record.state != DescriptorObjectState::Registered
                || !Self::descriptor_access_is_supported(record.access)
            {
                return Err(SemanticInvariantError::DescriptorObjectInvalid {
                    descriptor: record.id,
                });
            }
            if let Some(duplicate) = self.descriptor_objects.iter().find(|other| {
                other.id != record.id
                    && other.queue == record.queue
                    && other.queue_generation == record.queue_generation
                    && other.slot == record.slot
                    && other.state == DescriptorObjectState::Registered
            }) {
                return Err(SemanticInvariantError::DescriptorObjectDuplicateSlot {
                    descriptor: duplicate.id,
                    queue: record.queue,
                    slot: record.slot,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DescriptorObjectRecorded {
                            descriptor,
                            queue,
                            queue_generation,
                            slot,
                            access,
                            length,
                            generation,
                        } if *descriptor == record.id
                            && *queue == record.queue
                            && *queue_generation == record.queue_generation
                            && *slot == record.slot
                            && *access == record.access
                            && *length == record.length
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::DescriptorObjectMissingEvent {
                    descriptor: record.id,
                });
            }
        }
        Ok(())
    }

    const fn descriptor_access_is_supported(access: DescriptorObjectAccess) -> bool {
        matches!(
            access,
            DescriptorObjectAccess::ReadOnly
                | DescriptorObjectAccess::WriteOnly
                | DescriptorObjectAccess::ReadWrite
        )
    }

    #[cfg(test)]
    pub(crate) fn corrupt_descriptor_object_queue_generation_for_test(
        &mut self,
        descriptor: DescriptorObjectId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.descriptor_objects.iter_mut().find(|record| record.id == descriptor)
        {
            record.queue_generation = generation;
        }
    }
}
