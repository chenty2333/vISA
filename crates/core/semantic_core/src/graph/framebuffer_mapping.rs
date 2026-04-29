use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_framebuffer_mapping(
        &self,
        framebuffer_mapping: FramebufferMappingId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        framebuffer_window_lease: FramebufferWindowLeaseId,
        framebuffer_window_lease_generation: Generation,
        map_handle_slot: u32,
        map_handle_generation: u32,
        map_handle_tag: u64,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        byte_offset: u64,
        byte_len: u64,
        access: &str,
        mode: &str,
    ) -> Result<(), &'static str> {
        if framebuffer_mapping == 0 {
            return Err("framebuffer mapping id=0 is invalid");
        }
        if self.framebuffer_mappings.iter().any(|record| record.id == framebuffer_mapping) {
            return Err("framebuffer mapping already exists");
        }
        if owner_store_generation == 0
            || framebuffer_window_lease_generation == 0
            || map_handle_slot == 0
            || map_handle_generation == 0
            || map_handle_tag == 0
            || width == 0
            || height == 0
            || byte_len == 0
            || access.is_empty()
            || mode.is_empty()
        {
            return Err("framebuffer mapping identity, handle, and window values must be nonzero");
        }
        if mode != "handle-mode" {
            return Err("framebuffer mapping mode is unsupported");
        }
        if access != "write" && access != "read" {
            return Err("framebuffer mapping access is unsupported");
        }
        let Some(store_record) = self
            .stores
            .iter()
            .find(|store| store.id == owner_store && store.generation == owner_store_generation)
        else {
            return Err("framebuffer mapping owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("framebuffer mapping owner store is dead");
        }
        let Some(lease_record) = self.framebuffer_window_leases.iter().find(|lease| {
            lease.id == framebuffer_window_lease
                && lease.generation == framebuffer_window_lease_generation
                && lease.state == FramebufferWindowLeaseState::Active
        }) else {
            return Err("framebuffer mapping active lease generation is missing");
        };
        if lease_record.owner_store != owner_store
            || lease_record.owner_store_generation != owner_store_generation
            || lease_record.x != x
            || lease_record.y != y
            || lease_record.width != width
            || lease_record.height != height
            || lease_record.byte_offset != byte_offset
            || lease_record.byte_len != byte_len
            || lease_record.access != access
        {
            return Err("framebuffer mapping lease binding mismatch");
        }
        if self.framebuffer_mappings.iter().any(|record| {
            record.framebuffer_window_lease == framebuffer_window_lease
                && record.framebuffer_window_lease_generation == framebuffer_window_lease_generation
                && record.state == FramebufferMappingState::Active
        }) {
            return Err("framebuffer mapping already active for lease generation");
        }
        if self.check_invariants().is_err() {
            return Err("framebuffer mapping requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_framebuffer_mapping_with_id(
        &mut self,
        framebuffer_mapping: FramebufferMappingId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        framebuffer_window_lease: FramebufferWindowLeaseId,
        framebuffer_window_lease_generation: Generation,
        map_handle_slot: u32,
        map_handle_generation: u32,
        map_handle_tag: u64,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        byte_offset: u64,
        byte_len: u64,
        access: &str,
        mode: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_framebuffer_mapping(
                framebuffer_mapping,
                owner_store,
                owner_store_generation,
                framebuffer_window_lease,
                framebuffer_window_lease_generation,
                map_handle_slot,
                map_handle_generation,
                map_handle_tag,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                access,
                mode,
            )
            .is_err()
        {
            return false;
        }
        let lease_record = self
            .framebuffer_window_leases
            .iter()
            .find(|lease| {
                lease.id == framebuffer_window_lease
                    && lease.generation == framebuffer_window_lease_generation
            })
            .expect("validated framebuffer mapping lease exists")
            .clone();
        let generation = 1;
        self.next_framebuffer_mapping_id =
            self.next_framebuffer_mapping_id.max(framebuffer_mapping.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::FramebufferMappingRecorded {
                framebuffer_mapping,
                owner_store,
                owner_store_generation,
                framebuffer_window_lease,
                framebuffer_window_lease_generation,
                display_capability: lease_record.display_capability,
                display_capability_generation: lease_record.display_capability_generation,
                display: lease_record.display,
                display_generation: lease_record.display_generation,
                framebuffer: lease_record.framebuffer,
                framebuffer_generation: lease_record.framebuffer_generation,
                map_handle_slot,
                map_handle_generation,
                map_handle_tag,
                x,
                y,
                width,
                height,
                byte_offset,
                byte_len,
                access: access.to_string(),
                mode: mode.to_string(),
                state: FramebufferMappingState::Active,
                generation,
            },
        );
        self.framebuffer_mappings.push(FramebufferMappingRecord {
            id: framebuffer_mapping,
            owner_store,
            owner_store_generation,
            framebuffer_window_lease,
            framebuffer_window_lease_generation,
            display_capability: lease_record.display_capability,
            display_capability_generation: lease_record.display_capability_generation,
            display: lease_record.display,
            display_generation: lease_record.display_generation,
            framebuffer: lease_record.framebuffer,
            framebuffer_generation: lease_record.framebuffer_generation,
            map_handle_slot,
            map_handle_generation,
            map_handle_tag,
            x,
            y,
            width,
            height,
            byte_offset,
            byte_len,
            access: access.to_string(),
            mode: mode.to_string(),
            generation,
            state: FramebufferMappingState::Active,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn framebuffer_mappings(&self) -> &[FramebufferMappingRecord] {
        &self.framebuffer_mappings
    }

    pub fn framebuffer_mapping_count(&self) -> usize {
        self.framebuffer_mappings.len()
    }

    pub fn active_framebuffer_mapping_count(&self) -> usize {
        self.framebuffer_mappings
            .iter()
            .filter(|mapping| mapping.state == FramebufferMappingState::Active)
            .count()
    }

    pub fn check_framebuffer_mapping_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.framebuffer_mappings {
            let Some(store_record) = self.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferMappingMissingStore {
                    framebuffer_mapping: record.id,
                    store: record.owner_store,
                });
            };
            let Some(lease_record) = self.framebuffer_window_leases.iter().find(|lease| {
                lease.id == record.framebuffer_window_lease
                    && lease.generation == record.framebuffer_window_lease_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferMappingMissingLease {
                    framebuffer_mapping: record.id,
                    framebuffer_window_lease: record.framebuffer_window_lease,
                });
            };
            let active = record.state == FramebufferMappingState::Active;
            let unmapped = record.state == FramebufferMappingState::Unmapped;
            if record.id == 0
                || record.generation == 0
                || record.owner_store_generation == 0
                || record.framebuffer_window_lease_generation == 0
                || record.map_handle_slot == 0
                || record.map_handle_generation == 0
                || record.map_handle_tag == 0
                || record.width == 0
                || record.height == 0
                || record.byte_len == 0
                || record.access.is_empty()
                || record.mode != "handle-mode"
                || (record.access != "write" && record.access != "read")
                || (!active && !unmapped)
                || (active && store_record.state == StoreState::Dead)
                || (active && lease_record.state != FramebufferWindowLeaseState::Active)
                || lease_record.owner_store != record.owner_store
                || lease_record.owner_store_generation != record.owner_store_generation
                || lease_record.display_capability != record.display_capability
                || lease_record.display_capability_generation
                    != record.display_capability_generation
                || lease_record.display != record.display
                || lease_record.display_generation != record.display_generation
                || lease_record.framebuffer != record.framebuffer
                || lease_record.framebuffer_generation != record.framebuffer_generation
                || lease_record.x != record.x
                || lease_record.y != record.y
                || lease_record.width != record.width
                || lease_record.height != record.height
                || lease_record.byte_offset != record.byte_offset
                || lease_record.byte_len != record.byte_len
                || lease_record.access != record.access
            {
                return Err(SemanticInvariantError::FramebufferMappingInvalid {
                    framebuffer_mapping: record.id,
                });
            }
            if let Some(duplicate) = self.framebuffer_mappings.iter().find(|other| {
                other.id != record.id
                    && other.framebuffer_window_lease == record.framebuffer_window_lease
                    && other.framebuffer_window_lease_generation
                        == record.framebuffer_window_lease_generation
                    && other.state == FramebufferMappingState::Active
                    && record.state == FramebufferMappingState::Active
            }) {
                return Err(SemanticInvariantError::FramebufferMappingDuplicateActive {
                    framebuffer_mapping: duplicate.id,
                    framebuffer_window_lease: record.framebuffer_window_lease,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FramebufferMappingRecorded {
                            framebuffer_mapping,
                            owner_store,
                            owner_store_generation,
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
                            access,
                            mode,
                            state,
                            generation,
                        } if *framebuffer_mapping == record.id
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
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
                            && access == &record.access
                            && mode == &record.mode
                            && *state == FramebufferMappingState::Active
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::FramebufferMappingMissingEvent {
                    framebuffer_mapping: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_framebuffer_mapping_lease_generation_for_test(
        &mut self,
        framebuffer_mapping: FramebufferMappingId,
        framebuffer_window_lease_generation: Generation,
    ) {
        if let Some(record) =
            self.framebuffer_mappings.iter_mut().find(|record| record.id == framebuffer_mapping)
        {
            record.framebuffer_window_lease_generation = framebuffer_window_lease_generation;
        }
    }
}
