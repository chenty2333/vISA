use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_framebuffer_flush_region(
        &self,
        framebuffer_flush_region: FramebufferFlushRegionId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        framebuffer_write: FramebufferWriteId,
        framebuffer_write_generation: Generation,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        byte_offset: u64,
        byte_len: u64,
        payload_digest: u64,
    ) -> Result<(), &'static str> {
        if framebuffer_flush_region == 0 {
            return Err("framebuffer flush region id=0 is invalid");
        }
        if self
            .framebuffer_flush_regions
            .iter()
            .any(|record| record.id == framebuffer_flush_region)
        {
            return Err("framebuffer flush region already exists");
        }
        if owner_store_generation == 0
            || framebuffer_write_generation == 0
            || width == 0
            || height == 0
            || byte_len == 0
            || payload_digest == 0
        {
            return Err("framebuffer flush region identity and region values must be nonzero");
        }
        let Some(store_record) = self
            .stores
            .iter()
            .find(|store| store.id == owner_store && store.generation == owner_store_generation)
        else {
            return Err("framebuffer flush region owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("framebuffer flush region owner store is dead");
        }
        let Some(write_record) = self.framebuffer_writes.iter().find(|write| {
            write.id == framebuffer_write
                && write.generation == framebuffer_write_generation
                && write.state == FramebufferWriteState::Applied
        }) else {
            return Err("framebuffer flush region write generation is missing");
        };
        if write_record.owner_store != owner_store
            || write_record.owner_store_generation != owner_store_generation
            || write_record.x != x
            || write_record.y != y
            || write_record.width != width
            || write_record.height != height
            || write_record.byte_offset != byte_offset
            || write_record.byte_len != byte_len
            || write_record.payload_digest != payload_digest
        {
            return Err("framebuffer flush region write binding mismatch");
        }
        let Some(display_capability_record) = self.display_capabilities.iter().find(|capability| {
            capability.id == write_record.display_capability
                && capability.generation == write_record.display_capability_generation
                && capability.state == DisplayCapabilityState::Active
        }) else {
            return Err("framebuffer flush region display capability generation is missing");
        };
        if display_capability_record.owner_store != owner_store
            || display_capability_record.owner_store_generation != owner_store_generation
            || display_capability_record.display != write_record.display
            || display_capability_record.display_generation != write_record.display_generation
            || display_capability_record.framebuffer != write_record.framebuffer
            || display_capability_record.framebuffer_generation
                != write_record.framebuffer_generation
            || !display_capability_record
                .operations
                .iter()
                .any(|operation| operation == "flush")
        {
            return Err("framebuffer flush region display capability binding mismatch");
        }
        if self.framebuffer_flush_regions.iter().any(|record| {
            record.framebuffer_write == framebuffer_write
                && record.framebuffer_write_generation == framebuffer_write_generation
                && record.state == FramebufferFlushRegionState::Applied
        }) {
            return Err("framebuffer flush region already exists for write generation");
        }
        if self.check_invariants().is_err() {
            return Err("framebuffer flush region requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_framebuffer_flush_region_with_id(
        &mut self,
        framebuffer_flush_region: FramebufferFlushRegionId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        framebuffer_write: FramebufferWriteId,
        framebuffer_write_generation: Generation,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        byte_offset: u64,
        byte_len: u64,
        payload_digest: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_framebuffer_flush_region(
                framebuffer_flush_region,
                owner_store,
                owner_store_generation,
                framebuffer_write,
                framebuffer_write_generation,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                payload_digest,
            )
            .is_err()
        {
            return false;
        }
        let write_record = self
            .framebuffer_writes
            .iter()
            .find(|write| {
                write.id == framebuffer_write && write.generation == framebuffer_write_generation
            })
            .expect("validated framebuffer flush region write exists")
            .clone();
        let generation = 1;
        self.next_framebuffer_flush_region_id = self
            .next_framebuffer_flush_region_id
            .max(framebuffer_flush_region.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::FramebufferFlushRegionRecorded {
                framebuffer_flush_region,
                owner_store,
                owner_store_generation,
                framebuffer_write,
                framebuffer_write_generation,
                display_capability: write_record.display_capability,
                display_capability_generation: write_record.display_capability_generation,
                display: write_record.display,
                display_generation: write_record.display_generation,
                framebuffer: write_record.framebuffer,
                framebuffer_generation: write_record.framebuffer_generation,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                pixel_format: write_record.pixel_format.clone(),
                payload_digest,
                state: FramebufferFlushRegionState::Applied,
                generation,
            },
        );
        self.framebuffer_flush_regions
            .push(FramebufferFlushRegionRecord {
                id: framebuffer_flush_region,
                owner_store,
                owner_store_generation,
                framebuffer_write,
                framebuffer_write_generation,
                display_capability: write_record.display_capability,
                display_capability_generation: write_record.display_capability_generation,
                display: write_record.display,
                display_generation: write_record.display_generation,
                framebuffer: write_record.framebuffer,
                framebuffer_generation: write_record.framebuffer_generation,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                pixel_format: write_record.pixel_format,
                payload_digest,
                generation,
                state: FramebufferFlushRegionState::Applied,
                recorded_at_event,
                note: note.to_string(),
            });
        true
    }

    pub fn framebuffer_flush_regions(&self) -> &[FramebufferFlushRegionRecord] {
        &self.framebuffer_flush_regions
    }

    pub fn framebuffer_flush_region_count(&self) -> usize {
        self.framebuffer_flush_regions.len()
    }

    pub fn check_framebuffer_flush_region_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.framebuffer_flush_regions {
            let Some(store_record) = self.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferFlushRegionMissingStore {
                    framebuffer_flush_region: record.id,
                    store: record.owner_store,
                });
            };
            let Some(write_record) = self.framebuffer_writes.iter().find(|write| {
                write.id == record.framebuffer_write
                    && write.generation == record.framebuffer_write_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferFlushRegionMissingWrite {
                    framebuffer_flush_region: record.id,
                    framebuffer_write: record.framebuffer_write,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.owner_store_generation == 0
                || record.framebuffer_write_generation == 0
                || record.width == 0
                || record.height == 0
                || record.byte_len == 0
                || record.pixel_format.is_empty()
                || record.payload_digest == 0
                || record.state != FramebufferFlushRegionState::Applied
                || store_record.state == StoreState::Dead
                || write_record.state != FramebufferWriteState::Applied
                || write_record.owner_store != record.owner_store
                || write_record.owner_store_generation != record.owner_store_generation
                || write_record.display_capability != record.display_capability
                || write_record.display_capability_generation
                    != record.display_capability_generation
                || write_record.display != record.display
                || write_record.display_generation != record.display_generation
                || write_record.framebuffer != record.framebuffer
                || write_record.framebuffer_generation != record.framebuffer_generation
                || write_record.x != record.x
                || write_record.y != record.y
                || write_record.width != record.width
                || write_record.height != record.height
                || write_record.byte_offset != record.byte_offset
                || write_record.byte_len != record.byte_len
                || write_record.pixel_format != record.pixel_format
                || write_record.payload_digest != record.payload_digest
            {
                return Err(SemanticInvariantError::FramebufferFlushRegionInvalid {
                    framebuffer_flush_region: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FramebufferFlushRegionRecorded {
                            framebuffer_flush_region,
                            owner_store,
                            owner_store_generation,
                            framebuffer_write,
                            framebuffer_write_generation,
                            display_capability,
                            display_capability_generation,
                            display,
                            display_generation,
                            framebuffer,
                            framebuffer_generation,
                            x,
                            y,
                            width,
                            height,
                            byte_offset,
                            byte_len,
                            pixel_format,
                            payload_digest,
                            state,
                            generation,
                        } if *framebuffer_flush_region == record.id
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *framebuffer_write == record.framebuffer_write
                            && *framebuffer_write_generation == record.framebuffer_write_generation
                            && *display_capability == record.display_capability
                            && *display_capability_generation == record.display_capability_generation
                            && *display == record.display
                            && *display_generation == record.display_generation
                            && *framebuffer == record.framebuffer
                            && *framebuffer_generation == record.framebuffer_generation
                            && *x == record.x
                            && *y == record.y
                            && *width == record.width
                            && *height == record.height
                            && *byte_offset == record.byte_offset
                            && *byte_len == record.byte_len
                            && pixel_format == &record.pixel_format
                            && *payload_digest == record.payload_digest
                            && *state == record.state
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::FramebufferFlushRegionMissingEvent {
                    framebuffer_flush_region: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_framebuffer_flush_region_write_generation_for_test(
        &mut self,
        framebuffer_flush_region: FramebufferFlushRegionId,
        framebuffer_write_generation: Generation,
    ) {
        if let Some(record) = self
            .framebuffer_flush_regions
            .iter_mut()
            .find(|record| record.id == framebuffer_flush_region)
        {
            record.framebuffer_write_generation = framebuffer_write_generation;
        }
    }
}
