use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_display_event_log(
        &self,
        display_event_log: DisplayEventLogId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        framebuffer_dirty_region: FramebufferDirtyRegionId,
        framebuffer_dirty_region_generation: Generation,
        first_event: EventId,
        last_event: EventId,
        event_count: u64,
        flush_count: u64,
        dirty_region_count: u64,
    ) -> Result<(), &'static str> {
        if display_event_log == 0 {
            return Err("display event log id=0 is invalid");
        }
        if self
            .domains
            .display
            .display_event_logs
            .iter()
            .any(|record| record.id == display_event_log)
        {
            return Err("display event log already exists");
        }
        if owner_store_generation == 0
            || framebuffer_dirty_region_generation == 0
            || first_event == 0
            || last_event < first_event
            || event_count == 0
        {
            return Err("display event log requires exact refs and nonempty event window");
        }
        let Some(store_record) =
            self.domains.lifecycle.stores.iter().find(|store| {
                store.id == owner_store && store.generation == owner_store_generation
            })
        else {
            return Err("display event log owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("display event log owner store is dead");
        }
        let Some(dirty_record) =
            self.domains.display.framebuffer_dirty_regions.iter().find(|dirty| {
                dirty.id == framebuffer_dirty_region
                    && dirty.generation == framebuffer_dirty_region_generation
            })
        else {
            return Err("display event log dirty region generation is missing");
        };
        if dirty_record.owner_store != owner_store
            || dirty_record.owner_store_generation != owner_store_generation
            || dirty_record.state != FramebufferDirtyRegionState::Clean
        {
            return Err("display event log dirty region binding mismatch");
        }
        if dirty_record.recorded_at_event > last_event || dirty_record.dirty_at_event < first_event
        {
            return Err("display event log window does not cover dirty region lifecycle");
        }
        let display_events = self
            .event_log
            .events
            .iter()
            .filter(|event| {
                event.source == "display" && event.id >= first_event && event.id <= last_event
            })
            .collect::<Vec<_>>();
        if display_events.len() as u64 != event_count {
            return Err("display event log event count mismatch");
        }
        let observed_flush_count = display_events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::FramebufferFlushRegionRecorded { .. }))
            .count() as u64;
        let observed_dirty_region_count = display_events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::FramebufferDirtyRegionTracked { .. }))
            .count() as u64;
        if observed_flush_count != flush_count || observed_dirty_region_count != dirty_region_count
        {
            return Err("display event log classified count mismatch");
        }
        if self.check_invariants().is_err() {
            return Err("display event log requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_display_event_log_with_id(
        &mut self,
        display_event_log: DisplayEventLogId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        framebuffer_dirty_region: FramebufferDirtyRegionId,
        framebuffer_dirty_region_generation: Generation,
        first_event: EventId,
        last_event: EventId,
        event_count: u64,
        flush_count: u64,
        dirty_region_count: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_display_event_log(
                display_event_log,
                owner_store,
                owner_store_generation,
                framebuffer_dirty_region,
                framebuffer_dirty_region_generation,
                first_event,
                last_event,
                event_count,
                flush_count,
                dirty_region_count,
            )
            .is_err()
        {
            return false;
        }
        let dirty_record = self
            .domains
            .display
            .framebuffer_dirty_regions
            .iter()
            .find(|dirty| {
                dirty.id == framebuffer_dirty_region
                    && dirty.generation == framebuffer_dirty_region_generation
            })
            .expect("validated display event log dirty region exists")
            .clone();
        let generation = 1;
        self.domains.display.next_display_event_log_id =
            self.domains.display.next_display_event_log_id.max(display_event_log.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::DisplayEventLogRecorded {
                display_event_log,
                owner_store,
                owner_store_generation,
                display_capability: dirty_record.display_capability,
                display_capability_generation: dirty_record.display_capability_generation,
                display: dirty_record.display,
                display_generation: dirty_record.display_generation,
                framebuffer: dirty_record.framebuffer,
                framebuffer_generation: dirty_record.framebuffer_generation,
                framebuffer_dirty_region,
                framebuffer_dirty_region_generation,
                first_event,
                last_event,
                event_count,
                flush_count,
                dirty_region_count,
                state: DisplayEventLogState::Recorded,
                generation,
            },
        );
        self.domains.display.display_event_logs.push(DisplayEventLogRecord {
            id: display_event_log,
            owner_store,
            owner_store_generation,
            display_capability: dirty_record.display_capability,
            display_capability_generation: dirty_record.display_capability_generation,
            display: dirty_record.display,
            display_generation: dirty_record.display_generation,
            framebuffer: dirty_record.framebuffer,
            framebuffer_generation: dirty_record.framebuffer_generation,
            framebuffer_dirty_region,
            framebuffer_dirty_region_generation,
            first_event,
            last_event,
            event_count,
            flush_count,
            dirty_region_count,
            generation,
            state: DisplayEventLogState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn display_event_logs(&self) -> &[DisplayEventLogRecord] {
        &self.domains.display.display_event_logs
    }

    pub fn display_event_log_count(&self) -> usize {
        self.domains.display.display_event_logs.len()
    }

    pub fn check_display_event_log_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.display.display_event_logs {
            let Some(store_record) = self.domains.lifecycle.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::DisplayEventLogMissingStore {
                    display_event_log: record.id,
                    store: record.owner_store,
                });
            };
            let Some(dirty_record) =
                self.domains.display.framebuffer_dirty_regions.iter().find(|dirty| {
                    dirty.id == record.framebuffer_dirty_region
                        && dirty.generation == record.framebuffer_dirty_region_generation
                })
            else {
                return Err(SemanticInvariantError::DisplayEventLogMissingDirtyRegion {
                    display_event_log: record.id,
                    framebuffer_dirty_region: record.framebuffer_dirty_region,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.owner_store_generation == 0
                || record.framebuffer_dirty_region_generation == 0
                || record.first_event == 0
                || record.last_event < record.first_event
                || record.event_count == 0
                || record.state != DisplayEventLogState::Recorded
                || store_record.state == StoreState::Dead
                || dirty_record.owner_store != record.owner_store
                || dirty_record.owner_store_generation != record.owner_store_generation
                || dirty_record.display_capability != record.display_capability
                || dirty_record.display_capability_generation
                    != record.display_capability_generation
                || dirty_record.display != record.display
                || dirty_record.display_generation != record.display_generation
                || dirty_record.framebuffer != record.framebuffer
                || dirty_record.framebuffer_generation != record.framebuffer_generation
                || dirty_record.state != FramebufferDirtyRegionState::Clean
                || dirty_record.dirty_at_event < record.first_event
                || dirty_record.recorded_at_event > record.last_event
            {
                return Err(SemanticInvariantError::DisplayEventLogInvalid {
                    display_event_log: record.id,
                });
            }
            let display_events = self
                .event_log
                .events
                .iter()
                .filter(|event| {
                    event.source == "display"
                        && event.id >= record.first_event
                        && event.id <= record.last_event
                })
                .collect::<Vec<_>>();
            let observed_flush_count = display_events
                .iter()
                .filter(|event| {
                    matches!(event.kind, EventKind::FramebufferFlushRegionRecorded { .. })
                })
                .count() as u64;
            let observed_dirty_region_count = display_events
                .iter()
                .filter(|event| {
                    matches!(event.kind, EventKind::FramebufferDirtyRegionTracked { .. })
                })
                .count() as u64;
            if display_events.len() as u64 != record.event_count
                || observed_flush_count != record.flush_count
                || observed_dirty_region_count != record.dirty_region_count
            {
                return Err(SemanticInvariantError::DisplayEventLogInvalid {
                    display_event_log: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DisplayEventLogRecorded {
                            display_event_log,
                            owner_store,
                            owner_store_generation,
                            display_capability,
                            display_capability_generation,
                            display,
                            display_generation,
                            framebuffer,
                            framebuffer_generation,
                            framebuffer_dirty_region,
                            framebuffer_dirty_region_generation,
                            first_event,
                            last_event,
                            event_count,
                            flush_count,
                            dirty_region_count,
                            state,
                            generation,
                        } if *display_event_log == record.id
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *display_capability == record.display_capability
                            && *display_capability_generation == record.display_capability_generation
                            && *display == record.display
                            && *display_generation == record.display_generation
                            && *framebuffer == record.framebuffer
                            && *framebuffer_generation == record.framebuffer_generation
                            && *framebuffer_dirty_region == record.framebuffer_dirty_region
                            && *framebuffer_dirty_region_generation
                                == record.framebuffer_dirty_region_generation
                            && *first_event == record.first_event
                            && *last_event == record.last_event
                            && *event_count == record.event_count
                            && *flush_count == record.flush_count
                            && *dirty_region_count == record.dirty_region_count
                            && *state == record.state
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::DisplayEventLogMissingEvent {
                    display_event_log: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_display_event_log_event_count_for_test(
        &mut self,
        display_event_log: DisplayEventLogId,
        event_count: u64,
    ) {
        if let Some(record) = self
            .domains
            .display
            .display_event_logs
            .iter_mut()
            .find(|record| record.id == display_event_log)
        {
            record.event_count = event_count;
        }
    }
}
