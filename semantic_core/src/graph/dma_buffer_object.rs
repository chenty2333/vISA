use super::*;

impl SemanticGraph {
    pub(crate) fn validate_dma_buffer_object(
        &self,
        dma_buffer: DmaBufferObjectId,
        descriptor: DescriptorObjectId,
        descriptor_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        access: DmaBufferObjectAccess,
        length: u32,
    ) -> Result<(), &'static str> {
        if dma_buffer == 0 {
            return Err("dma buffer object id=0 is invalid");
        }
        if self
            .dma_buffer_objects
            .iter()
            .any(|record| record.id == dma_buffer)
        {
            return Err("dma buffer object already exists");
        }
        if length == 0 {
            return Err("dma buffer object length is zero");
        }
        if !Self::dma_buffer_access_is_supported(access) {
            return Err("dma buffer object access is unsupported");
        }
        let Some(descriptor_record) = self.descriptor_objects.iter().find(|record| {
            record.id == descriptor
                && record.generation == descriptor_generation
                && record.state == DescriptorObjectState::Registered
        }) else {
            return Err("dma buffer object descriptor generation is missing or inactive");
        };
        if length > descriptor_record.length {
            return Err("dma buffer object length exceeds descriptor length");
        }
        if !Self::dma_buffer_access_matches_descriptor(access, descriptor_record.access) {
            return Err("dma buffer object access exceeds descriptor access");
        }
        let Some(resource_record) = self.resources.iter().find(|record| record.id == resource)
        else {
            return Err("dma buffer object resource is missing");
        };
        if resource_record.generation != resource_generation {
            return Err("dma buffer object resource generation mismatch");
        }
        if !resource_record.live {
            return Err("dma buffer object resource is dead");
        }
        if resource_record.kind != ResourceKind::DmaBuffer {
            return Err("dma buffer object resource kind is not dma-buffer");
        }
        if self.dma_buffer_objects.iter().any(|record| {
            record.descriptor == descriptor_record.id
                && record.descriptor_generation == descriptor_generation
                && record.state == DmaBufferObjectState::Registered
        }) {
            return Err("dma buffer object descriptor already has a buffer");
        }
        if self.check_invariants().is_err() {
            return Err("dma buffer object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_dma_buffer_object_with_id(
        &mut self,
        dma_buffer: DmaBufferObjectId,
        descriptor: DescriptorObjectId,
        descriptor_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        access: DmaBufferObjectAccess,
        length: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_dma_buffer_object(
                dma_buffer,
                descriptor,
                descriptor_generation,
                resource,
                resource_generation,
                access,
                length,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_dma_buffer_object_id = self.next_dma_buffer_object_id.max(dma_buffer + 1);
        let recorded_at_event = self.event_log.push(
            "io",
            EventKind::DmaBufferObjectRecorded {
                dma_buffer,
                descriptor,
                descriptor_generation,
                resource,
                resource_generation,
                access,
                length,
                generation,
            },
        );
        self.dma_buffer_objects.push(DmaBufferObjectRecord {
            id: dma_buffer,
            descriptor,
            descriptor_generation,
            resource,
            resource_generation,
            access,
            length,
            generation,
            state: DmaBufferObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn dma_buffer_objects(&self) -> &[DmaBufferObjectRecord] {
        &self.dma_buffer_objects
    }

    pub fn dma_buffer_object_count(&self) -> usize {
        self.dma_buffer_objects.len()
    }

    pub fn check_dma_buffer_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.dma_buffer_objects {
            let Some(descriptor_record) = self.descriptor_objects.iter().find(|descriptor| {
                descriptor.id == record.descriptor
                    && descriptor.generation == record.descriptor_generation
            }) else {
                return Err(SemanticInvariantError::DmaBufferObjectMissingDescriptor {
                    dma_buffer: record.id,
                    descriptor: record.descriptor,
                });
            };
            let Some(resource_record) = self.resources.iter().find(|resource| {
                resource.id == record.resource && resource.generation == record.resource_generation
            }) else {
                return Err(SemanticInvariantError::DmaBufferObjectMissingResource {
                    dma_buffer: record.id,
                    resource: record.resource,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.length == 0
                || record.length > descriptor_record.length
                || record.descriptor_generation == 0
                || record.resource_generation == 0
                || descriptor_record.state != DescriptorObjectState::Registered
                || resource_record.kind != ResourceKind::DmaBuffer
                || !resource_record.live
                || record.state != DmaBufferObjectState::Registered
                || !Self::dma_buffer_access_is_supported(record.access)
                || !Self::dma_buffer_access_matches_descriptor(
                    record.access,
                    descriptor_record.access,
                )
            {
                return Err(SemanticInvariantError::DmaBufferObjectInvalid {
                    dma_buffer: record.id,
                });
            }
            if let Some(duplicate) = self.dma_buffer_objects.iter().find(|other| {
                other.id != record.id
                    && other.descriptor == record.descriptor
                    && other.descriptor_generation == record.descriptor_generation
                    && other.state == DmaBufferObjectState::Registered
            }) {
                return Err(SemanticInvariantError::DmaBufferObjectDuplicateDescriptor {
                    dma_buffer: duplicate.id,
                    descriptor: record.descriptor,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DmaBufferObjectRecorded {
                            dma_buffer,
                            descriptor,
                            descriptor_generation,
                            resource,
                            resource_generation,
                            access,
                            length,
                            generation,
                        } if *dma_buffer == record.id
                            && *descriptor == record.descriptor
                            && *descriptor_generation == record.descriptor_generation
                            && *resource == record.resource
                            && *resource_generation == record.resource_generation
                            && *access == record.access
                            && *length == record.length
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::DmaBufferObjectMissingEvent {
                    dma_buffer: record.id,
                });
            }
        }
        Ok(())
    }

    const fn dma_buffer_access_is_supported(access: DmaBufferObjectAccess) -> bool {
        matches!(
            access,
            DmaBufferObjectAccess::ReadOnly
                | DmaBufferObjectAccess::WriteOnly
                | DmaBufferObjectAccess::ReadWrite
        )
    }

    const fn dma_buffer_access_matches_descriptor(
        buffer: DmaBufferObjectAccess,
        descriptor: DescriptorObjectAccess,
    ) -> bool {
        matches!(
            (buffer, descriptor),
            (_, DescriptorObjectAccess::ReadWrite)
                | (
                    DmaBufferObjectAccess::ReadOnly,
                    DescriptorObjectAccess::ReadOnly
                )
                | (
                    DmaBufferObjectAccess::WriteOnly,
                    DescriptorObjectAccess::WriteOnly
                )
        )
    }

    #[cfg(test)]
    pub(crate) fn corrupt_dma_buffer_object_resource_generation_for_test(
        &mut self,
        dma_buffer: DmaBufferObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .dma_buffer_objects
            .iter_mut()
            .find(|record| record.id == dma_buffer)
        {
            record.resource_generation = generation;
        }
    }
}
