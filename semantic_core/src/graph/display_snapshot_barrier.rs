use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_display_snapshot_barrier(
        &self,
        barrier: DisplaySnapshotBarrierId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display: DisplayObjectId,
        display_generation: Generation,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
        display_cleanup: Option<DisplayCleanupId>,
        display_cleanup_generation: Option<Generation>,
        reason: &str,
    ) -> Result<(), &'static str> {
        if barrier == 0 {
            return Err("display snapshot barrier id=0 is invalid");
        }
        if owner_store_generation == 0
            || display_generation == 0
            || framebuffer_generation == 0
            || reason.is_empty()
        {
            return Err("display snapshot barrier requires exact refs and reason");
        }
        if self
            .display_snapshot_barriers
            .iter()
            .any(|record| record.id == barrier)
        {
            return Err("display snapshot barrier already exists");
        }
        let Some(store_record) = self
            .stores
            .iter()
            .find(|store| store.id == owner_store && store.generation == owner_store_generation)
        else {
            return Err("display snapshot barrier owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("display snapshot barrier owner store is dead");
        }
        let Some(display_record) = self.display_objects.iter().find(|record| {
            record.id == display
                && record.generation == display_generation
                && record.framebuffer == framebuffer
                && record.framebuffer_generation == framebuffer_generation
                && record.state == DisplayObjectState::Registered
        }) else {
            return Err("display snapshot barrier display generation is missing");
        };
        if !self.framebuffer_objects.iter().any(|record| {
            record.id == display_record.framebuffer
                && record.generation == display_record.framebuffer_generation
                && record.state == FramebufferObjectState::Registered
        }) {
            return Err("display snapshot barrier framebuffer generation is missing");
        }
        match (display_cleanup, display_cleanup_generation) {
            (Some(cleanup), Some(generation)) if cleanup != 0 && generation != 0 => {
                let Some(cleanup_record) = self.display_cleanups.iter().find(|record| {
                    record.id == cleanup
                        && record.generation == generation
                        && record.state == DisplayCleanupState::Completed
                }) else {
                    return Err("display snapshot barrier cleanup generation is missing");
                };
                if cleanup_record.owner_store != owner_store
                    || cleanup_record.owner_store_generation != owner_store_generation
                    || cleanup_record.display != display
                    || cleanup_record.display_generation != display_generation
                    || cleanup_record.framebuffer != framebuffer
                    || cleanup_record.framebuffer_generation != framebuffer_generation
                {
                    return Err("display snapshot barrier cleanup binding mismatch");
                }
            }
            (None, None) => {}
            _ => return Err("display snapshot barrier cleanup ref must be exact or absent"),
        }
        let snapshot_state = self.display_snapshot_barrier_validation_state(
            owner_store,
            owner_store_generation,
            display,
            display_generation,
            framebuffer,
            framebuffer_generation,
        );
        if !SnapshotBarrierValidator::validate(&snapshot_state).is_ok() {
            return Err("display snapshot barrier display state is not quiescent");
        }
        if self.check_invariants().is_err() {
            return Err("display snapshot barrier requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_display_snapshot_barrier_with_id(
        &mut self,
        barrier: DisplaySnapshotBarrierId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display: DisplayObjectId,
        display_generation: Generation,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
        display_cleanup: Option<DisplayCleanupId>,
        display_cleanup_generation: Option<Generation>,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_display_snapshot_barrier(
                barrier,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                display_cleanup,
                display_cleanup_generation,
                reason,
            )
            .is_err()
        {
            return false;
        }
        let snapshot_state = self.display_snapshot_barrier_validation_state(
            owner_store,
            owner_store_generation,
            display,
            display_generation,
            framebuffer,
            framebuffer_generation,
        );
        let generation = 1;
        self.next_display_snapshot_barrier_id = self
            .next_display_snapshot_barrier_id
            .max(barrier.saturating_add(1));
        let validated_at_event = self.event_log.push(
            "display",
            EventKind::DisplaySnapshotBarrierValidated {
                barrier,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                display_cleanup,
                display_cleanup_generation,
                active_framebuffer_window_lease_count: snapshot_state
                    .active_framebuffer_window_lease_count,
                active_framebuffer_mapping_count: snapshot_state.active_framebuffer_mapping_count,
                dirty_framebuffer_region_count: snapshot_state.dirty_framebuffer_region_count,
                generation,
            },
        );
        self.display_snapshot_barriers
            .push(DisplaySnapshotBarrierRecord {
                id: barrier,
                owner_store,
                owner_store_generation,
                display,
                display_generation,
                framebuffer,
                framebuffer_generation,
                display_cleanup,
                display_cleanup_generation,
                active_framebuffer_window_lease_count: snapshot_state
                    .active_framebuffer_window_lease_count,
                active_framebuffer_mapping_count: snapshot_state.active_framebuffer_mapping_count,
                dirty_framebuffer_region_count: snapshot_state.dirty_framebuffer_region_count,
                snapshot_validation_ok: true,
                generation,
                state: DisplaySnapshotBarrierState::Validated,
                validated_at_event,
                reason: reason.to_string(),
                note: note.to_string(),
            });
        self.check_invariants().is_ok()
    }

    pub fn display_snapshot_barriers(&self) -> &[DisplaySnapshotBarrierRecord] {
        &self.display_snapshot_barriers
    }

    pub fn display_snapshot_barrier_count(&self) -> usize {
        self.display_snapshot_barriers.len()
    }

    #[allow(clippy::too_many_arguments)]
    fn display_snapshot_barrier_validation_state(
        &self,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display: DisplayObjectId,
        display_generation: Generation,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
    ) -> SnapshotBarrierValidationState {
        SnapshotBarrierValidationState {
            active_framebuffer_window_lease_count: self
                .framebuffer_window_leases
                .iter()
                .filter(|record| {
                    record.owner_store == owner_store
                        && record.owner_store_generation == owner_store_generation
                        && record.display == display
                        && record.display_generation == display_generation
                        && record.framebuffer == framebuffer
                        && record.framebuffer_generation == framebuffer_generation
                        && record.state == FramebufferWindowLeaseState::Active
                })
                .count() as u32,
            active_framebuffer_mapping_count: self
                .framebuffer_mappings
                .iter()
                .filter(|record| {
                    record.owner_store == owner_store
                        && record.owner_store_generation == owner_store_generation
                        && record.display == display
                        && record.display_generation == display_generation
                        && record.framebuffer == framebuffer
                        && record.framebuffer_generation == framebuffer_generation
                        && record.state == FramebufferMappingState::Active
                })
                .count() as u32,
            dirty_framebuffer_region_count: self
                .framebuffer_dirty_regions
                .iter()
                .filter(|record| {
                    record.owner_store == owner_store
                        && record.owner_store_generation == owner_store_generation
                        && record.display == display
                        && record.display_generation == display_generation
                        && record.framebuffer == framebuffer
                        && record.framebuffer_generation == framebuffer_generation
                        && record.state == FramebufferDirtyRegionState::Dirty
                })
                .count() as u32,
            ..SnapshotBarrierValidationState::default()
        }
    }

    pub fn check_display_snapshot_barrier_invariants(&self) -> Result<(), SemanticInvariantError> {
        for barrier in &self.display_snapshot_barriers {
            if barrier.id == 0
                || barrier.generation == 0
                || barrier.owner_store_generation == 0
                || barrier.display_generation == 0
                || barrier.framebuffer_generation == 0
                || barrier.reason.is_empty()
                || !barrier.snapshot_validation_ok
                || barrier.state != DisplaySnapshotBarrierState::Validated
                || barrier.active_framebuffer_window_lease_count != 0
                || barrier.active_framebuffer_mapping_count != 0
                || barrier.dirty_framebuffer_region_count != 0
            {
                return Err(SemanticInvariantError::DisplaySnapshotBarrierInvalid {
                    barrier: barrier.id,
                });
            }
            if !self.stores.iter().any(|store| {
                store.id == barrier.owner_store
                    && store.generation == barrier.owner_store_generation
            }) {
                return Err(SemanticInvariantError::DisplaySnapshotBarrierMissingStore {
                    barrier: barrier.id,
                    store: barrier.owner_store,
                });
            }
            if !self.display_objects.iter().any(|display| {
                display.id == barrier.display
                    && display.generation == barrier.display_generation
                    && display.framebuffer == barrier.framebuffer
                    && display.framebuffer_generation == barrier.framebuffer_generation
            }) {
                return Err(
                    SemanticInvariantError::DisplaySnapshotBarrierMissingDisplay {
                        barrier: barrier.id,
                        display: barrier.display,
                    },
                );
            }
            if !self.framebuffer_objects.iter().any(|framebuffer| {
                framebuffer.id == barrier.framebuffer
                    && framebuffer.generation == barrier.framebuffer_generation
            }) {
                return Err(
                    SemanticInvariantError::DisplaySnapshotBarrierMissingFramebuffer {
                        barrier: barrier.id,
                        framebuffer: barrier.framebuffer,
                    },
                );
            }
            match (barrier.display_cleanup, barrier.display_cleanup_generation) {
                (Some(cleanup), Some(generation)) => {
                    let Some(cleanup_record) = self
                        .display_cleanups
                        .iter()
                        .find(|record| record.id == cleanup && record.generation == generation)
                    else {
                        return Err(
                            SemanticInvariantError::DisplaySnapshotBarrierMissingCleanup {
                                barrier: barrier.id,
                                cleanup,
                            },
                        );
                    };
                    if cleanup_record.owner_store != barrier.owner_store
                        || cleanup_record.owner_store_generation != barrier.owner_store_generation
                        || cleanup_record.display != barrier.display
                        || cleanup_record.display_generation != barrier.display_generation
                        || cleanup_record.framebuffer != barrier.framebuffer
                        || cleanup_record.framebuffer_generation != barrier.framebuffer_generation
                        || cleanup_record.state != DisplayCleanupState::Completed
                    {
                        return Err(SemanticInvariantError::DisplaySnapshotBarrierInvalid {
                            barrier: barrier.id,
                        });
                    }
                }
                (None, None) => {}
                _ => {
                    return Err(SemanticInvariantError::DisplaySnapshotBarrierInvalid {
                        barrier: barrier.id,
                    });
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == barrier.validated_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DisplaySnapshotBarrierValidated {
                            barrier: event_barrier,
                            owner_store,
                            owner_store_generation,
                            display,
                            display_generation,
                            framebuffer,
                            framebuffer_generation,
                            display_cleanup,
                            display_cleanup_generation,
                            active_framebuffer_window_lease_count,
                            active_framebuffer_mapping_count,
                            dirty_framebuffer_region_count,
                            generation,
                        } if *event_barrier == barrier.id
                            && *owner_store == barrier.owner_store
                            && *owner_store_generation == barrier.owner_store_generation
                            && *display == barrier.display
                            && *display_generation == barrier.display_generation
                            && *framebuffer == barrier.framebuffer
                            && *framebuffer_generation == barrier.framebuffer_generation
                            && *display_cleanup == barrier.display_cleanup
                            && *display_cleanup_generation == barrier.display_cleanup_generation
                            && *active_framebuffer_window_lease_count
                                == barrier.active_framebuffer_window_lease_count
                            && *active_framebuffer_mapping_count
                                == barrier.active_framebuffer_mapping_count
                            && *dirty_framebuffer_region_count
                                == barrier.dirty_framebuffer_region_count
                            && *generation == barrier.generation
                    )
            }) {
                return Err(SemanticInvariantError::DisplaySnapshotBarrierMissingEvent {
                    barrier: barrier.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_display_snapshot_barrier_dirty_count_for_test(
        &mut self,
        barrier: DisplaySnapshotBarrierId,
        dirty_count: u32,
    ) {
        if let Some(record) = self
            .display_snapshot_barriers
            .iter_mut()
            .find(|record| record.id == barrier)
        {
            record.dirty_framebuffer_region_count = dirty_count;
        }
    }
}
