use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_framebuffer_object(
        &self,
        framebuffer: FramebufferObjectId,
        name: &str,
        resource: ResourceId,
        resource_generation: Generation,
        width: u32,
        height: u32,
        stride_bytes: u32,
        pixel_format: &str,
        byte_len: u64,
    ) -> Result<(), &'static str> {
        if framebuffer == 0 {
            return Err("framebuffer object id=0 is invalid");
        }
        if self.framebuffer_objects.iter().any(|record| record.id == framebuffer) {
            return Err("framebuffer object already exists");
        }
        if name.is_empty() {
            return Err("framebuffer object name is empty");
        }
        if width == 0 || height == 0 || stride_bytes == 0 || byte_len == 0 {
            return Err("framebuffer object dimensions must be nonzero");
        }
        if pixel_format.is_empty() {
            return Err("framebuffer object pixel format is empty");
        }
        let bytes_per_pixel = match pixel_format {
            "xrgb8888" | "argb8888" | "rgba8888" | "bgra8888" => 4,
            "rgb565" => 2,
            _ => return Err("framebuffer object pixel format is unsupported"),
        };
        let min_stride = width.saturating_mul(bytes_per_pixel);
        if stride_bytes < min_stride {
            return Err("framebuffer object stride is smaller than visible row bytes");
        }
        let required_len = u64::from(stride_bytes).saturating_mul(u64::from(height));
        if byte_len < required_len {
            return Err("framebuffer object byte length is smaller than stride*height");
        }
        let Some(resource_record) = self
            .resources
            .iter()
            .find(|record| record.id == resource && record.generation == resource_generation)
        else {
            return Err("framebuffer object backing resource generation is missing");
        };
        if resource_record.kind != ResourceKind::Framebuffer || !resource_record.live {
            return Err("framebuffer object must be backed by live framebuffer resource");
        }
        if self.check_invariants().is_err() {
            return Err("framebuffer object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_framebuffer_object_with_id(
        &mut self,
        framebuffer: FramebufferObjectId,
        name: &str,
        resource: ResourceId,
        resource_generation: Generation,
        width: u32,
        height: u32,
        stride_bytes: u32,
        pixel_format: &str,
        byte_len: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_framebuffer_object(
                framebuffer,
                name,
                resource,
                resource_generation,
                width,
                height,
                stride_bytes,
                pixel_format,
                byte_len,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_framebuffer_object_id =
            self.next_framebuffer_object_id.max(framebuffer.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::FramebufferObjectRecorded {
                framebuffer,
                resource,
                resource_generation,
                width,
                height,
                stride_bytes,
                pixel_format: pixel_format.to_string(),
                byte_len,
                generation,
            },
        );
        self.framebuffer_objects.push(FramebufferObjectRecord {
            id: framebuffer,
            name: name.to_string(),
            resource,
            resource_generation,
            width,
            height,
            stride_bytes,
            pixel_format: pixel_format.to_string(),
            byte_len,
            generation,
            state: FramebufferObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn framebuffer_objects(&self) -> &[FramebufferObjectRecord] {
        &self.framebuffer_objects
    }

    pub fn framebuffer_object_count(&self) -> usize {
        self.framebuffer_objects.len()
    }

    pub fn check_framebuffer_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.framebuffer_objects {
            let Some(resource_record) = self.resources.iter().find(|resource| {
                resource.id == record.resource && resource.generation == record.resource_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferObjectMissingResource {
                    framebuffer: record.id,
                    resource: record.resource,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.width == 0
                || record.height == 0
                || record.stride_bytes == 0
                || record.pixel_format.is_empty()
                || record.byte_len
                    < u64::from(record.stride_bytes).saturating_mul(u64::from(record.height))
                || record.state != FramebufferObjectState::Registered
                || resource_record.kind != ResourceKind::Framebuffer
                || !resource_record.live
            {
                return Err(SemanticInvariantError::FramebufferObjectInvalid {
                    framebuffer: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FramebufferObjectRecorded {
                            framebuffer,
                            resource,
                            resource_generation,
                            width,
                            height,
                            stride_bytes,
                            pixel_format,
                            byte_len,
                            generation,
                        } if *framebuffer == record.id
                            && *resource == record.resource
                            && *resource_generation == record.resource_generation
                            && *width == record.width
                            && *height == record.height
                            && *stride_bytes == record.stride_bytes
                            && pixel_format == &record.pixel_format
                            && *byte_len == record.byte_len
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::FramebufferObjectMissingEvent {
                    framebuffer: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_framebuffer_object_resource_generation_for_test(
        &mut self,
        framebuffer: FramebufferObjectId,
        resource_generation: Generation,
    ) {
        if let Some(record) =
            self.framebuffer_objects.iter_mut().find(|record| record.id == framebuffer)
        {
            record.resource_generation = resource_generation;
        }
    }
}
