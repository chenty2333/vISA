use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_display_object(
        &self,
        display: DisplayObjectId,
        name: &str,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
        mode_name: &str,
        width: u32,
        height: u32,
        refresh_millihz: u32,
    ) -> Result<(), &'static str> {
        if display == 0 {
            return Err("display object id=0 is invalid");
        }
        if self
            .display_objects
            .iter()
            .any(|record| record.id == display)
        {
            return Err("display object already exists");
        }
        if name.is_empty() || mode_name.is_empty() {
            return Err("display object name/mode is empty");
        }
        if width == 0 || height == 0 || refresh_millihz == 0 {
            return Err("display object mode must be nonzero");
        }
        let Some(framebuffer_record) = self
            .framebuffer_objects
            .iter()
            .find(|record| record.id == framebuffer && record.generation == framebuffer_generation)
        else {
            return Err("display object framebuffer generation is missing");
        };
        if framebuffer_record.state != FramebufferObjectState::Registered {
            return Err("display object framebuffer must be registered");
        }
        if width > framebuffer_record.width || height > framebuffer_record.height {
            return Err("display object mode exceeds framebuffer geometry");
        }
        if self.check_invariants().is_err() {
            return Err("display object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_display_object_with_id(
        &mut self,
        display: DisplayObjectId,
        name: &str,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
        mode_name: &str,
        width: u32,
        height: u32,
        refresh_millihz: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_display_object(
                display,
                name,
                framebuffer,
                framebuffer_generation,
                mode_name,
                width,
                height,
                refresh_millihz,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_display_object_id = self.next_display_object_id.max(display.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::DisplayObjectRecorded {
                display,
                framebuffer,
                framebuffer_generation,
                mode_name: mode_name.to_string(),
                width,
                height,
                refresh_millihz,
                generation,
            },
        );
        self.display_objects.push(DisplayObjectRecord {
            id: display,
            name: name.to_string(),
            framebuffer,
            framebuffer_generation,
            mode_name: mode_name.to_string(),
            width,
            height,
            refresh_millihz,
            generation,
            state: DisplayObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn display_objects(&self) -> &[DisplayObjectRecord] {
        &self.display_objects
    }

    pub fn display_object_count(&self) -> usize {
        self.display_objects.len()
    }

    pub fn check_display_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.display_objects {
            let Some(framebuffer_record) = self.framebuffer_objects.iter().find(|framebuffer| {
                framebuffer.id == record.framebuffer
                    && framebuffer.generation == record.framebuffer_generation
            }) else {
                return Err(SemanticInvariantError::DisplayObjectMissingFramebuffer {
                    display: record.id,
                    framebuffer: record.framebuffer,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.mode_name.is_empty()
                || record.width == 0
                || record.height == 0
                || record.refresh_millihz == 0
                || record.width > framebuffer_record.width
                || record.height > framebuffer_record.height
                || record.state != DisplayObjectState::Registered
                || framebuffer_record.state != FramebufferObjectState::Registered
            {
                return Err(SemanticInvariantError::DisplayObjectInvalid { display: record.id });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DisplayObjectRecorded {
                            display,
                            framebuffer,
                            framebuffer_generation,
                            mode_name,
                            width,
                            height,
                            refresh_millihz,
                            generation,
                        } if *display == record.id
                            && *framebuffer == record.framebuffer
                            && *framebuffer_generation == record.framebuffer_generation
                            && mode_name == &record.mode_name
                            && *width == record.width
                            && *height == record.height
                            && *refresh_millihz == record.refresh_millihz
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::DisplayObjectMissingEvent {
                    display: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_display_object_framebuffer_generation_for_test(
        &mut self,
        display: DisplayObjectId,
        framebuffer_generation: Generation,
    ) {
        if let Some(record) = self
            .display_objects
            .iter_mut()
            .find(|record| record.id == display)
        {
            record.framebuffer_generation = framebuffer_generation;
        }
    }
}
