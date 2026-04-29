use super::*;

fn framebuffer_bytes_per_pixel(pixel_format: &str) -> Option<u64> {
    match pixel_format {
        "xrgb8888" | "argb8888" | "rgba8888" | "bgra8888" => Some(4),
        "rgb565" => Some(2),
        _ => None,
    }
}

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_framebuffer_window_lease(
        &self,
        framebuffer_window_lease: FramebufferWindowLeaseId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display_capability: DisplayCapabilityId,
        display_capability_generation: Generation,
        display: DisplayObjectId,
        display_generation: Generation,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        byte_offset: u64,
        byte_len: u64,
        access: &str,
    ) -> Result<(), &'static str> {
        if framebuffer_window_lease == 0 {
            return Err("framebuffer window lease id=0 is invalid");
        }
        if self
            .domains
            .display
            .framebuffer_window_leases
            .iter()
            .any(|record| record.id == framebuffer_window_lease)
        {
            return Err("framebuffer window lease already exists");
        }
        if owner_store_generation == 0
            || display_capability_generation == 0
            || display_generation == 0
            || framebuffer_generation == 0
            || width == 0
            || height == 0
            || byte_len == 0
            || access.is_empty()
        {
            return Err("framebuffer window lease identity and window values must be nonzero");
        }
        if access != "write" && access != "read" {
            return Err("framebuffer window lease access is unsupported");
        }
        let Some(store_record) =
            self.domains.lifecycle.stores.iter().find(|store| {
                store.id == owner_store && store.generation == owner_store_generation
            })
        else {
            return Err("framebuffer window lease owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("framebuffer window lease owner store is dead");
        }
        let Some(display_capability_record) =
            self.domains.display.display_capabilities.iter().find(|record| {
                record.id == display_capability
                    && record.generation == display_capability_generation
                    && record.state == DisplayCapabilityState::Active
            })
        else {
            return Err("framebuffer window lease display capability generation is missing");
        };
        if display_capability_record.owner_store != owner_store
            || display_capability_record.owner_store_generation != owner_store_generation
            || display_capability_record.display != display
            || display_capability_record.display_generation != display_generation
            || display_capability_record.framebuffer != framebuffer
            || display_capability_record.framebuffer_generation != framebuffer_generation
            || !display_capability_record.operations.iter().any(|operation| operation == "lease")
        {
            return Err("framebuffer window lease display capability binding mismatch");
        }
        let Some(display_record) = self.domains.display.display_objects.iter().find(|record| {
            record.id == display
                && record.generation == display_generation
                && record.state == DisplayObjectState::Registered
        }) else {
            return Err("framebuffer window lease display generation is missing");
        };
        let Some(framebuffer_record) =
            self.domains.display.framebuffer_objects.iter().find(|record| {
                record.id == framebuffer
                    && record.generation == framebuffer_generation
                    && record.state == FramebufferObjectState::Registered
            })
        else {
            return Err("framebuffer window lease framebuffer generation is missing");
        };
        if display_record.framebuffer != framebuffer
            || display_record.framebuffer_generation != framebuffer_generation
        {
            return Err("framebuffer window lease display framebuffer mismatch");
        }
        if x.checked_add(width).is_none_or(|right| right > display_record.width)
            || y.checked_add(height).is_none_or(|bottom| bottom > display_record.height)
        {
            return Err("framebuffer window lease window exceeds display mode");
        }
        let Some(bytes_per_pixel) = framebuffer_bytes_per_pixel(&framebuffer_record.pixel_format)
        else {
            return Err("framebuffer window lease pixel format is unsupported");
        };
        let Some(row_bytes) = u64::from(width).checked_mul(bytes_per_pixel) else {
            return Err("framebuffer window lease byte geometry overflows");
        };
        let Some(expected_byte_offset) =
            u64::from(y).checked_mul(u64::from(framebuffer_record.stride_bytes)).and_then(|base| {
                u64::from(x)
                    .checked_mul(bytes_per_pixel)
                    .and_then(|x_bytes| base.checked_add(x_bytes))
            })
        else {
            return Err("framebuffer window lease byte geometry overflows");
        };
        let Some(min_window_bytes) = u64::from(height.saturating_sub(1))
            .checked_mul(u64::from(framebuffer_record.stride_bytes))
            .and_then(|rows| rows.checked_add(row_bytes))
        else {
            return Err("framebuffer window lease byte geometry overflows");
        };
        if byte_offset != expected_byte_offset {
            return Err("framebuffer window lease byte offset does not match window geometry");
        }
        if byte_len < min_window_bytes
            || byte_offset.checked_add(byte_len).is_none_or(|end| end > framebuffer_record.byte_len)
        {
            return Err("framebuffer window lease byte range exceeds framebuffer");
        }
        if self.domains.display.framebuffer_window_leases.iter().any(|record| {
            record.owner_store == owner_store
                && record.owner_store_generation == owner_store_generation
                && record.framebuffer == framebuffer
                && record.framebuffer_generation == framebuffer_generation
                && record.state == FramebufferWindowLeaseState::Active
        }) {
            return Err("framebuffer window lease already active for framebuffer generation");
        }
        if self.check_invariants().is_err() {
            return Err("framebuffer window lease requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_framebuffer_window_lease_with_id(
        &mut self,
        framebuffer_window_lease: FramebufferWindowLeaseId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display_capability: DisplayCapabilityId,
        display_capability_generation: Generation,
        display: DisplayObjectId,
        display_generation: Generation,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        byte_offset: u64,
        byte_len: u64,
        access: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_framebuffer_window_lease(
                framebuffer_window_lease,
                owner_store,
                owner_store_generation,
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
                access,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.domains.display.next_framebuffer_window_lease_id = self
            .domains
            .display
            .next_framebuffer_window_lease_id
            .max(framebuffer_window_lease.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::FramebufferWindowLeaseRecorded {
                framebuffer_window_lease,
                owner_store,
                owner_store_generation,
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
                access: access.to_string(),
                state: FramebufferWindowLeaseState::Active,
                generation,
            },
        );
        self.domains.display.framebuffer_window_leases.push(FramebufferWindowLeaseRecord {
            id: framebuffer_window_lease,
            owner_store,
            owner_store_generation,
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
            access: access.to_string(),
            generation,
            state: FramebufferWindowLeaseState::Active,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn framebuffer_window_leases(&self) -> &[FramebufferWindowLeaseRecord] {
        &self.domains.display.framebuffer_window_leases
    }

    pub fn framebuffer_window_lease_count(&self) -> usize {
        self.domains.display.framebuffer_window_leases.len()
    }

    pub fn active_framebuffer_window_lease_count(&self) -> usize {
        self.domains
            .display
            .framebuffer_window_leases
            .iter()
            .filter(|lease| lease.state == FramebufferWindowLeaseState::Active)
            .count()
    }

    pub fn check_framebuffer_window_lease_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.display.framebuffer_window_leases {
            let Some(store_record) = self.domains.lifecycle.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferWindowLeaseMissingStore {
                    framebuffer_window_lease: record.id,
                    store: record.owner_store,
                });
            };
            let Some(display_capability_record) =
                self.domains.display.display_capabilities.iter().find(|capability| {
                    capability.id == record.display_capability
                        && capability.generation == record.display_capability_generation
                })
            else {
                return Err(
                    SemanticInvariantError::FramebufferWindowLeaseMissingDisplayCapability {
                        framebuffer_window_lease: record.id,
                        display_capability: record.display_capability,
                    },
                );
            };
            let Some(display_record) =
                self.domains.display.display_objects.iter().find(|display| {
                    display.id == record.display && display.generation == record.display_generation
                })
            else {
                return Err(SemanticInvariantError::FramebufferWindowLeaseMissingDisplay {
                    framebuffer_window_lease: record.id,
                    display: record.display,
                });
            };
            let Some(framebuffer_record) =
                self.domains.display.framebuffer_objects.iter().find(|framebuffer| {
                    framebuffer.id == record.framebuffer
                        && framebuffer.generation == record.framebuffer_generation
                })
            else {
                return Err(SemanticInvariantError::FramebufferWindowLeaseMissingFramebuffer {
                    framebuffer_window_lease: record.id,
                    framebuffer: record.framebuffer,
                });
            };
            let active = record.state == FramebufferWindowLeaseState::Active;
            let released = record.state == FramebufferWindowLeaseState::Released;
            let Some(bytes_per_pixel) =
                framebuffer_bytes_per_pixel(&framebuffer_record.pixel_format)
            else {
                return Err(SemanticInvariantError::FramebufferWindowLeaseInvalid {
                    framebuffer_window_lease: record.id,
                });
            };
            let Some(row_bytes) = u64::from(record.width).checked_mul(bytes_per_pixel) else {
                return Err(SemanticInvariantError::FramebufferWindowLeaseInvalid {
                    framebuffer_window_lease: record.id,
                });
            };
            let Some(expected_byte_offset) = u64::from(record.y)
                .checked_mul(u64::from(framebuffer_record.stride_bytes))
                .and_then(|base| {
                    u64::from(record.x)
                        .checked_mul(bytes_per_pixel)
                        .and_then(|x_bytes| base.checked_add(x_bytes))
                })
            else {
                return Err(SemanticInvariantError::FramebufferWindowLeaseInvalid {
                    framebuffer_window_lease: record.id,
                });
            };
            let Some(min_window_bytes) = u64::from(record.height.saturating_sub(1))
                .checked_mul(u64::from(framebuffer_record.stride_bytes))
                .and_then(|rows| rows.checked_add(row_bytes))
            else {
                return Err(SemanticInvariantError::FramebufferWindowLeaseInvalid {
                    framebuffer_window_lease: record.id,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.owner_store_generation == 0
                || record.display_capability_generation == 0
                || record.display_generation == 0
                || record.framebuffer_generation == 0
                || record.width == 0
                || record.height == 0
                || record.byte_len == 0
                || record.access.is_empty()
                || (record.access != "write" && record.access != "read")
                || (!active && !released)
                || (active && store_record.state == StoreState::Dead)
                || (active && display_capability_record.state != DisplayCapabilityState::Active)
                || display_capability_record.owner_store != record.owner_store
                || display_capability_record.owner_store_generation != record.owner_store_generation
                || display_capability_record.display != record.display
                || display_capability_record.display_generation != record.display_generation
                || display_capability_record.framebuffer != record.framebuffer
                || display_capability_record.framebuffer_generation != record.framebuffer_generation
                || !display_capability_record
                    .operations
                    .iter()
                    .any(|operation| operation == "lease")
                || display_record.state != DisplayObjectState::Registered
                || display_record.framebuffer != record.framebuffer
                || display_record.framebuffer_generation != record.framebuffer_generation
                || framebuffer_record.state != FramebufferObjectState::Registered
                || record
                    .x
                    .checked_add(record.width)
                    .is_none_or(|right| right > display_record.width)
                || record
                    .y
                    .checked_add(record.height)
                    .is_none_or(|bottom| bottom > display_record.height)
                || record.byte_offset != expected_byte_offset
                || record.byte_len < min_window_bytes
                || record
                    .byte_offset
                    .checked_add(record.byte_len)
                    .is_none_or(|end| end > framebuffer_record.byte_len)
            {
                return Err(SemanticInvariantError::FramebufferWindowLeaseInvalid {
                    framebuffer_window_lease: record.id,
                });
            }
            if let Some(duplicate) =
                self.domains.display.framebuffer_window_leases.iter().find(|other| {
                    other.id != record.id
                        && other.owner_store == record.owner_store
                        && other.owner_store_generation == record.owner_store_generation
                        && other.framebuffer == record.framebuffer
                        && other.framebuffer_generation == record.framebuffer_generation
                        && other.state == FramebufferWindowLeaseState::Active
                        && record.state == FramebufferWindowLeaseState::Active
                })
            {
                return Err(SemanticInvariantError::FramebufferWindowLeaseDuplicateActive {
                    framebuffer_window_lease: duplicate.id,
                    framebuffer: record.framebuffer,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FramebufferWindowLeaseRecorded {
                            framebuffer_window_lease,
                            owner_store,
                            owner_store_generation,
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
                            access,
                            state,
                            generation,
                        } if *framebuffer_window_lease == record.id
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
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
                            && access == &record.access
                            && *state == FramebufferWindowLeaseState::Active
                            && *generation == record.generation
                    )
            }) {
                return Err(
                    SemanticInvariantError::FramebufferWindowLeaseMissingEvent {
                        framebuffer_window_lease: record.id,
                    },
                );
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_framebuffer_window_lease_display_capability_generation_for_test(
        &mut self,
        framebuffer_window_lease: FramebufferWindowLeaseId,
        display_capability_generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .display
            .framebuffer_window_leases
            .iter_mut()
            .find(|record| record.id == framebuffer_window_lease)
        {
            record.display_capability_generation = display_capability_generation;
        }
    }
}
