use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_framebuffer_dirty_region(
        &self,
        framebuffer_dirty_region: FramebufferDirtyRegionId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        framebuffer_write: FramebufferWriteId,
        framebuffer_write_generation: Generation,
        framebuffer_flush_region: Option<FramebufferFlushRegionId>,
        framebuffer_flush_region_generation: Option<Generation>,
        state: FramebufferDirtyRegionState,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        byte_offset: u64,
        byte_len: u64,
        payload_digest: u64,
    ) -> Result<(), &'static str> {
        if framebuffer_dirty_region == 0 {
            return Err("framebuffer dirty region id=0 is invalid");
        }
        if self
            .domains
            .display
            .framebuffer_dirty_regions
            .iter()
            .any(|record| record.id == framebuffer_dirty_region)
        {
            return Err("framebuffer dirty region already exists");
        }
        if owner_store_generation == 0
            || framebuffer_write_generation == 0
            || width == 0
            || height == 0
            || byte_len == 0
            || payload_digest == 0
        {
            return Err("framebuffer dirty region identity and region values must be nonzero");
        }
        match state {
            FramebufferDirtyRegionState::Dirty => {
                if framebuffer_flush_region.is_some()
                    || framebuffer_flush_region_generation.is_some()
                {
                    return Err("dirty framebuffer region cannot carry a flush ref");
                }
            }
            FramebufferDirtyRegionState::Clean => {
                if framebuffer_flush_region.unwrap_or(0) == 0
                    || framebuffer_flush_region_generation.unwrap_or(0) == 0
                {
                    return Err("clean framebuffer dirty region requires exact flush ref");
                }
            }
        }
        let Some(store_record) =
            self.domains.lifecycle.stores.iter().find(|store| {
                store.id == owner_store && store.generation == owner_store_generation
            })
        else {
            return Err("framebuffer dirty region owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("framebuffer dirty region owner store is dead");
        }
        let Some(write_record) = self.domains.display.framebuffer_writes.iter().find(|write| {
            write.id == framebuffer_write
                && write.generation == framebuffer_write_generation
                && write.state == FramebufferWriteState::Applied
        }) else {
            return Err("framebuffer dirty region write generation is missing");
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
            return Err("framebuffer dirty region write binding mismatch");
        }
        if let FramebufferDirtyRegionState::Clean = state {
            let Some(flush_record) =
                self.domains.display.framebuffer_flush_regions.iter().find(|flush| {
                    Some(flush.id) == framebuffer_flush_region
                        && Some(flush.generation) == framebuffer_flush_region_generation
                        && flush.state == FramebufferFlushRegionState::Applied
                })
            else {
                return Err("framebuffer dirty region flush generation is missing");
            };
            if flush_record.owner_store != owner_store
                || flush_record.owner_store_generation != owner_store_generation
                || flush_record.framebuffer_write != framebuffer_write
                || flush_record.framebuffer_write_generation != framebuffer_write_generation
                || flush_record.display_capability != write_record.display_capability
                || flush_record.display_capability_generation
                    != write_record.display_capability_generation
                || flush_record.display != write_record.display
                || flush_record.display_generation != write_record.display_generation
                || flush_record.framebuffer != write_record.framebuffer
                || flush_record.framebuffer_generation != write_record.framebuffer_generation
                || flush_record.x != x
                || flush_record.y != y
                || flush_record.width != width
                || flush_record.height != height
                || flush_record.byte_offset != byte_offset
                || flush_record.byte_len != byte_len
                || flush_record.payload_digest != payload_digest
            {
                return Err("framebuffer dirty region flush binding mismatch");
            }
            if flush_record.recorded_at_event <= write_record.recorded_at_event {
                return Err("framebuffer dirty region flush must follow write event");
            }
        }
        if self.domains.display.framebuffer_dirty_regions.iter().any(|record| {
            record.framebuffer_write == framebuffer_write
                && record.framebuffer_write_generation == framebuffer_write_generation
                && record.state == FramebufferDirtyRegionState::Dirty
                && state == FramebufferDirtyRegionState::Dirty
        }) {
            return Err("dirty framebuffer region already tracked for write generation");
        }
        if self.check_invariants().is_err() {
            return Err("framebuffer dirty region requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_framebuffer_dirty_region_with_id(
        &mut self,
        framebuffer_dirty_region: FramebufferDirtyRegionId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        framebuffer_write: FramebufferWriteId,
        framebuffer_write_generation: Generation,
        framebuffer_flush_region: Option<FramebufferFlushRegionId>,
        framebuffer_flush_region_generation: Option<Generation>,
        state: FramebufferDirtyRegionState,
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
            .validate_framebuffer_dirty_region(
                framebuffer_dirty_region,
                owner_store,
                owner_store_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                state,
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
            .domains
            .display
            .framebuffer_writes
            .iter()
            .find(|write| {
                write.id == framebuffer_write && write.generation == framebuffer_write_generation
            })
            .expect("validated framebuffer dirty region write exists")
            .clone();
        let cleaned_at_event = framebuffer_flush_region.and_then(|flush_id| {
            self.domains
                .display
                .framebuffer_flush_regions
                .iter()
                .find(|flush| {
                    flush.id == flush_id
                        && Some(flush.generation) == framebuffer_flush_region_generation
                })
                .map(|flush| flush.recorded_at_event)
        });
        let generation = 1;
        self.domains.display.next_framebuffer_dirty_region_id = self
            .domains
            .display
            .next_framebuffer_dirty_region_id
            .max(framebuffer_dirty_region.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::FramebufferDirtyRegionTracked {
                framebuffer_dirty_region,
                owner_store,
                owner_store_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
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
                state,
                generation,
            },
        );
        self.domains.display.framebuffer_dirty_regions.push(FramebufferDirtyRegionRecord {
            id: framebuffer_dirty_region,
            owner_store,
            owner_store_generation,
            framebuffer_write,
            framebuffer_write_generation,
            framebuffer_flush_region,
            framebuffer_flush_region_generation,
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
            state,
            dirty_at_event: write_record.recorded_at_event,
            cleaned_at_event,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn framebuffer_dirty_regions(&self) -> &[FramebufferDirtyRegionRecord] {
        &self.domains.display.framebuffer_dirty_regions
    }

    pub fn framebuffer_dirty_region_count(&self) -> usize {
        self.domains.display.framebuffer_dirty_regions.len()
    }

    pub fn check_framebuffer_dirty_region_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.display.framebuffer_dirty_regions {
            let Some(store_record) = self.domains.lifecycle.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferDirtyRegionMissingStore {
                    framebuffer_dirty_region: record.id,
                    store: record.owner_store,
                });
            };
            let Some(write_record) = self.domains.display.framebuffer_writes.iter().find(|write| {
                write.id == record.framebuffer_write
                    && write.generation == record.framebuffer_write_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferDirtyRegionMissingWrite {
                    framebuffer_dirty_region: record.id,
                    framebuffer_write: record.framebuffer_write,
                });
            };
            let flush_record = match (
                record.state,
                record.framebuffer_flush_region,
                record.framebuffer_flush_region_generation,
            ) {
                (FramebufferDirtyRegionState::Clean, Some(flush), Some(generation)) => Some(
                    self.domains
                        .display
                        .framebuffer_flush_regions
                        .iter()
                        .find(|entry| entry.id == flush && entry.generation == generation)
                        .ok_or(SemanticInvariantError::FramebufferDirtyRegionMissingFlush {
                            framebuffer_dirty_region: record.id,
                            framebuffer_flush_region: flush,
                        })?,
                ),
                (FramebufferDirtyRegionState::Dirty, None, None) => None,
                _ => {
                    return Err(SemanticInvariantError::FramebufferDirtyRegionInvalid {
                        framebuffer_dirty_region: record.id,
                    });
                }
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
                || write_record.recorded_at_event != record.dirty_at_event
            {
                return Err(SemanticInvariantError::FramebufferDirtyRegionInvalid {
                    framebuffer_dirty_region: record.id,
                });
            }
            if let Some(flush_record) = flush_record
                && (flush_record.state != FramebufferFlushRegionState::Applied
                    || flush_record.owner_store != record.owner_store
                    || flush_record.owner_store_generation != record.owner_store_generation
                    || flush_record.framebuffer_write != record.framebuffer_write
                    || flush_record.framebuffer_write_generation
                        != record.framebuffer_write_generation
                    || flush_record.display_capability != record.display_capability
                    || flush_record.display_capability_generation
                        != record.display_capability_generation
                    || flush_record.display != record.display
                    || flush_record.display_generation != record.display_generation
                    || flush_record.framebuffer != record.framebuffer
                    || flush_record.framebuffer_generation != record.framebuffer_generation
                    || flush_record.x != record.x
                    || flush_record.y != record.y
                    || flush_record.width != record.width
                    || flush_record.height != record.height
                    || flush_record.byte_offset != record.byte_offset
                    || flush_record.byte_len != record.byte_len
                    || flush_record.pixel_format != record.pixel_format
                    || flush_record.payload_digest != record.payload_digest
                    || Some(flush_record.recorded_at_event) != record.cleaned_at_event
                    || flush_record.recorded_at_event <= record.dirty_at_event)
            {
                return Err(SemanticInvariantError::FramebufferDirtyRegionInvalid {
                    framebuffer_dirty_region: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FramebufferDirtyRegionTracked {
                            framebuffer_dirty_region,
                            owner_store,
                            owner_store_generation,
                            framebuffer_write,
                            framebuffer_write_generation,
                            framebuffer_flush_region,
                            framebuffer_flush_region_generation,
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
                        } if *framebuffer_dirty_region == record.id
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *framebuffer_write == record.framebuffer_write
                            && *framebuffer_write_generation == record.framebuffer_write_generation
                            && *framebuffer_flush_region == record.framebuffer_flush_region
                            && *framebuffer_flush_region_generation
                                == record.framebuffer_flush_region_generation
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
                return Err(SemanticInvariantError::FramebufferDirtyRegionMissingEvent {
                    framebuffer_dirty_region: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_framebuffer_dirty_region_flush_generation_for_test(
        &mut self,
        framebuffer_dirty_region: FramebufferDirtyRegionId,
        framebuffer_flush_region_generation: Option<Generation>,
    ) {
        if let Some(record) = self
            .domains
            .display
            .framebuffer_dirty_regions
            .iter_mut()
            .find(|record| record.id == framebuffer_dirty_region)
        {
            record.framebuffer_flush_region_generation = framebuffer_flush_region_generation;
        }
    }
}
