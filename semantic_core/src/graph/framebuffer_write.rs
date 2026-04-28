use super::*;

const FRAMEBUFFER_WRITE_DIGEST_OFFSET_V1: u64 = 0x9fb2_1c7d_52aa_35ef;
const FRAMEBUFFER_WRITE_DIGEST_PRIME_V1: u64 = 0x0000_0100_0000_01b3;

fn mix_digest(mut digest: u64, value: u64) -> u64 {
    digest ^= value;
    digest.wrapping_mul(FRAMEBUFFER_WRITE_DIGEST_PRIME_V1)
}

fn bytes_per_pixel(pixel_format: &str) -> Option<u64> {
    match pixel_format {
        "xrgb8888" | "argb8888" | "rgba8888" | "bgra8888" => Some(4),
        "rgb565" => Some(2),
        _ => None,
    }
}

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub fn expected_framebuffer_write_payload_digest_v1(
        framebuffer_mapping: FramebufferMappingId,
        framebuffer_mapping_generation: Generation,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        byte_offset: u64,
        byte_len: u64,
    ) -> u64 {
        let mut digest = FRAMEBUFFER_WRITE_DIGEST_OFFSET_V1;
        digest = mix_digest(digest, framebuffer_mapping);
        digest = mix_digest(digest, framebuffer_mapping_generation);
        digest = mix_digest(digest, framebuffer);
        digest = mix_digest(digest, framebuffer_generation);
        digest = mix_digest(digest, u64::from(x));
        digest = mix_digest(digest, u64::from(y));
        digest = mix_digest(digest, u64::from(width));
        digest = mix_digest(digest, u64::from(height));
        digest = mix_digest(digest, byte_offset);
        digest = mix_digest(digest, byte_len);
        if digest == 0 { 1 } else { digest }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_framebuffer_write(
        &self,
        framebuffer_write: FramebufferWriteId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        framebuffer_mapping: FramebufferMappingId,
        framebuffer_mapping_generation: Generation,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        byte_offset: u64,
        byte_len: u64,
        payload_digest: u64,
    ) -> Result<(), &'static str> {
        if framebuffer_write == 0 {
            return Err("framebuffer write id=0 is invalid");
        }
        if self
            .framebuffer_writes
            .iter()
            .any(|record| record.id == framebuffer_write)
        {
            return Err("framebuffer write already exists");
        }
        if owner_store_generation == 0
            || framebuffer_mapping_generation == 0
            || width == 0
            || height == 0
            || byte_len == 0
            || payload_digest == 0
        {
            return Err("framebuffer write identity and region values must be nonzero");
        }
        let Some(store_record) = self
            .stores
            .iter()
            .find(|store| store.id == owner_store && store.generation == owner_store_generation)
        else {
            return Err("framebuffer write owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("framebuffer write owner store is dead");
        }
        let Some(mapping_record) = self.framebuffer_mappings.iter().find(|mapping| {
            mapping.id == framebuffer_mapping
                && mapping.generation == framebuffer_mapping_generation
                && mapping.state == FramebufferMappingState::Active
        }) else {
            return Err("framebuffer write active mapping generation is missing");
        };
        if mapping_record.owner_store != owner_store
            || mapping_record.owner_store_generation != owner_store_generation
            || mapping_record.access != "write"
            || mapping_record.mode != "handle-mode"
        {
            return Err("framebuffer write mapping binding mismatch");
        }
        let Some(framebuffer_record) = self.framebuffer_objects.iter().find(|framebuffer| {
            framebuffer.id == mapping_record.framebuffer
                && framebuffer.generation == mapping_record.framebuffer_generation
                && framebuffer.state == FramebufferObjectState::Registered
        }) else {
            return Err("framebuffer write framebuffer generation is missing");
        };
        let Some(bytes_per_pixel) = bytes_per_pixel(&framebuffer_record.pixel_format) else {
            return Err("framebuffer write pixel format is unsupported");
        };
        let Some(mapping_right) = mapping_record.x.checked_add(mapping_record.width) else {
            return Err("framebuffer write mapping geometry overflows");
        };
        let Some(mapping_bottom) = mapping_record.y.checked_add(mapping_record.height) else {
            return Err("framebuffer write mapping geometry overflows");
        };
        if x < mapping_record.x
            || y < mapping_record.y
            || x.checked_add(width)
                .is_none_or(|right| right > mapping_right)
            || y.checked_add(height)
                .is_none_or(|bottom| bottom > mapping_bottom)
        {
            return Err("framebuffer write region exceeds mapping window");
        }
        let Some(row_bytes) = u64::from(width).checked_mul(bytes_per_pixel) else {
            return Err("framebuffer write byte geometry overflows");
        };
        let Some(expected_byte_offset) = u64::from(y)
            .checked_mul(u64::from(framebuffer_record.stride_bytes))
            .and_then(|base| {
                u64::from(x)
                    .checked_mul(bytes_per_pixel)
                    .and_then(|x_bytes| base.checked_add(x_bytes))
            })
        else {
            return Err("framebuffer write byte geometry overflows");
        };
        let Some(min_write_bytes) = u64::from(height.saturating_sub(1))
            .checked_mul(u64::from(framebuffer_record.stride_bytes))
            .and_then(|rows| rows.checked_add(row_bytes))
        else {
            return Err("framebuffer write byte geometry overflows");
        };
        if byte_offset != expected_byte_offset || byte_len < min_write_bytes {
            return Err("framebuffer write byte range does not match region geometry");
        }
        let Some(mapping_byte_end) = mapping_record
            .byte_offset
            .checked_add(mapping_record.byte_len)
        else {
            return Err("framebuffer write mapping byte range overflows");
        };
        if byte_offset < mapping_record.byte_offset
            || byte_offset
                .checked_add(byte_len)
                .is_none_or(|end| end > mapping_byte_end)
        {
            return Err("framebuffer write byte range exceeds mapping lease");
        }
        let expected_digest = Self::expected_framebuffer_write_payload_digest_v1(
            framebuffer_mapping,
            framebuffer_mapping_generation,
            framebuffer_record.id,
            framebuffer_record.generation,
            x,
            y,
            width,
            height,
            byte_offset,
            byte_len,
        );
        if payload_digest != expected_digest {
            return Err("framebuffer write payload digest mismatch");
        }
        if self.check_invariants().is_err() {
            return Err("framebuffer write requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_framebuffer_write_with_id(
        &mut self,
        framebuffer_write: FramebufferWriteId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        framebuffer_mapping: FramebufferMappingId,
        framebuffer_mapping_generation: Generation,
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
            .validate_framebuffer_write(
                framebuffer_write,
                owner_store,
                owner_store_generation,
                framebuffer_mapping,
                framebuffer_mapping_generation,
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
        let mapping_record = self
            .framebuffer_mappings
            .iter()
            .find(|mapping| {
                mapping.id == framebuffer_mapping
                    && mapping.generation == framebuffer_mapping_generation
            })
            .expect("validated framebuffer write mapping exists")
            .clone();
        let framebuffer_record = self
            .framebuffer_objects
            .iter()
            .find(|framebuffer| {
                framebuffer.id == mapping_record.framebuffer
                    && framebuffer.generation == mapping_record.framebuffer_generation
            })
            .expect("validated framebuffer write framebuffer exists")
            .clone();
        let generation = 1;
        self.next_framebuffer_write_id = self
            .next_framebuffer_write_id
            .max(framebuffer_write.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::FramebufferWriteRecorded {
                framebuffer_write,
                owner_store,
                owner_store_generation,
                framebuffer_mapping,
                framebuffer_mapping_generation,
                framebuffer_window_lease: mapping_record.framebuffer_window_lease,
                framebuffer_window_lease_generation: mapping_record
                    .framebuffer_window_lease_generation,
                display_capability: mapping_record.display_capability,
                display_capability_generation: mapping_record.display_capability_generation,
                display: mapping_record.display,
                display_generation: mapping_record.display_generation,
                framebuffer: mapping_record.framebuffer,
                framebuffer_generation: mapping_record.framebuffer_generation,
                map_handle_slot: mapping_record.map_handle_slot,
                map_handle_generation: mapping_record.map_handle_generation,
                map_handle_tag: mapping_record.map_handle_tag,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                pixel_format: framebuffer_record.pixel_format.clone(),
                payload_digest,
                state: FramebufferWriteState::Applied,
                generation,
            },
        );
        self.framebuffer_writes.push(FramebufferWriteRecord {
            id: framebuffer_write,
            owner_store,
            owner_store_generation,
            framebuffer_mapping,
            framebuffer_mapping_generation,
            framebuffer_window_lease: mapping_record.framebuffer_window_lease,
            framebuffer_window_lease_generation: mapping_record.framebuffer_window_lease_generation,
            display_capability: mapping_record.display_capability,
            display_capability_generation: mapping_record.display_capability_generation,
            display: mapping_record.display,
            display_generation: mapping_record.display_generation,
            framebuffer: mapping_record.framebuffer,
            framebuffer_generation: mapping_record.framebuffer_generation,
            map_handle_slot: mapping_record.map_handle_slot,
            map_handle_generation: mapping_record.map_handle_generation,
            map_handle_tag: mapping_record.map_handle_tag,
            x,
            y,
            width,
            height,
            byte_offset,
            byte_len,
            pixel_format: framebuffer_record.pixel_format,
            payload_digest,
            generation,
            state: FramebufferWriteState::Applied,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn framebuffer_writes(&self) -> &[FramebufferWriteRecord] {
        &self.framebuffer_writes
    }

    pub fn framebuffer_write_count(&self) -> usize {
        self.framebuffer_writes.len()
    }

    pub fn check_framebuffer_write_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.framebuffer_writes {
            let Some(store_record) = self.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferWriteMissingStore {
                    framebuffer_write: record.id,
                    store: record.owner_store,
                });
            };
            let Some(mapping_record) = self.framebuffer_mappings.iter().find(|mapping| {
                mapping.id == record.framebuffer_mapping
                    && mapping.generation == record.framebuffer_mapping_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferWriteMissingMapping {
                    framebuffer_write: record.id,
                    framebuffer_mapping: record.framebuffer_mapping,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.owner_store_generation == 0
                || record.framebuffer_mapping_generation == 0
                || record.width == 0
                || record.height == 0
                || record.byte_len == 0
                || record.pixel_format.is_empty()
                || record.payload_digest == 0
                || record.state != FramebufferWriteState::Applied
                || store_record.state == StoreState::Dead
                || mapping_record.state != FramebufferMappingState::Active
                || mapping_record.access != "write"
                || mapping_record.mode != "handle-mode"
                || mapping_record.owner_store != record.owner_store
                || mapping_record.owner_store_generation != record.owner_store_generation
                || mapping_record.framebuffer_window_lease != record.framebuffer_window_lease
                || mapping_record.framebuffer_window_lease_generation
                    != record.framebuffer_window_lease_generation
                || mapping_record.display_capability != record.display_capability
                || mapping_record.display_capability_generation
                    != record.display_capability_generation
                || mapping_record.display != record.display
                || mapping_record.display_generation != record.display_generation
                || mapping_record.framebuffer != record.framebuffer
                || mapping_record.framebuffer_generation != record.framebuffer_generation
                || mapping_record.map_handle_slot != record.map_handle_slot
                || mapping_record.map_handle_generation != record.map_handle_generation
                || mapping_record.map_handle_tag != record.map_handle_tag
            {
                return Err(SemanticInvariantError::FramebufferWriteInvalid {
                    framebuffer_write: record.id,
                });
            }
            let expected_digest = Self::expected_framebuffer_write_payload_digest_v1(
                record.framebuffer_mapping,
                record.framebuffer_mapping_generation,
                record.framebuffer,
                record.framebuffer_generation,
                record.x,
                record.y,
                record.width,
                record.height,
                record.byte_offset,
                record.byte_len,
            );
            if expected_digest != record.payload_digest {
                return Err(SemanticInvariantError::FramebufferWriteInvalid {
                    framebuffer_write: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FramebufferWriteRecorded {
                            framebuffer_write,
                            owner_store,
                            owner_store_generation,
                            framebuffer_mapping,
                            framebuffer_mapping_generation,
                            framebuffer_window_lease,
                            framebuffer_window_lease_generation,
                            display_capability,
                            display_capability_generation,
                            display,
                            display_generation,
                            framebuffer,
                            framebuffer_generation,
                            map_handle_slot,
                            map_handle_generation,
                            map_handle_tag,
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
                        } if *framebuffer_write == record.id
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *framebuffer_mapping == record.framebuffer_mapping
                            && *framebuffer_mapping_generation == record.framebuffer_mapping_generation
                            && *framebuffer_window_lease == record.framebuffer_window_lease
                            && *framebuffer_window_lease_generation
                                == record.framebuffer_window_lease_generation
                            && *display_capability == record.display_capability
                            && *display_capability_generation == record.display_capability_generation
                            && *display == record.display
                            && *display_generation == record.display_generation
                            && *framebuffer == record.framebuffer
                            && *framebuffer_generation == record.framebuffer_generation
                            && *map_handle_slot == record.map_handle_slot
                            && *map_handle_generation == record.map_handle_generation
                            && *map_handle_tag == record.map_handle_tag
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
                return Err(SemanticInvariantError::FramebufferWriteMissingEvent {
                    framebuffer_write: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_framebuffer_write_mapping_generation_for_test(
        &mut self,
        framebuffer_write: FramebufferWriteId,
        framebuffer_mapping_generation: Generation,
    ) {
        if let Some(record) = self
            .framebuffer_writes
            .iter_mut()
            .find(|record| record.id == framebuffer_write)
        {
            record.framebuffer_mapping_generation = framebuffer_mapping_generation;
        }
    }
}
