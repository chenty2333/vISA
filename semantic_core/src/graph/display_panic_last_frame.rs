use super::*;

const DISPLAY_PANIC_LAST_FRAME_DIGEST_OFFSET_V1: u64 = 0xd1f7_5a31_b9c4_620d;
const DISPLAY_PANIC_LAST_FRAME_DIGEST_PRIME_V1: u64 = 0x0000_0100_0000_01b3;
const DISPLAY_PANIC_LAST_FRAME_MAX_RECORD_BYTES_V1: u32 = 4096;
const DISPLAY_PANIC_LAST_FRAME_RECORD_KIND_V1: &str = "contract-panic-summary-v1";

fn mix_digest(mut digest: u64, value: u64) -> u64 {
    digest ^= value;
    digest.wrapping_mul(DISPLAY_PANIC_LAST_FRAME_DIGEST_PRIME_V1)
}

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub fn expected_display_panic_last_frame_summary_digest_v1(
        owner_store: StoreId,
        owner_store_generation: Generation,
        display: DisplayObjectId,
        display_generation: Generation,
        framebuffer: FramebufferObjectId,
        framebuffer_generation: Generation,
        display_snapshot_barrier: DisplaySnapshotBarrierId,
        display_snapshot_barrier_generation: Generation,
        display_event_log: DisplayEventLogId,
        display_event_log_generation: Generation,
        framebuffer_write: FramebufferWriteId,
        framebuffer_write_generation: Generation,
        framebuffer_flush_region: FramebufferFlushRegionId,
        framebuffer_flush_region_generation: Generation,
        payload_digest: u64,
        panic_epoch: u64,
        panic_cpu: u32,
        panic_reason_code: u32,
    ) -> u64 {
        let mut digest = DISPLAY_PANIC_LAST_FRAME_DIGEST_OFFSET_V1;
        for value in [
            owner_store,
            owner_store_generation,
            display,
            display_generation,
            framebuffer,
            framebuffer_generation,
            display_snapshot_barrier,
            display_snapshot_barrier_generation,
            display_event_log,
            display_event_log_generation,
            framebuffer_write,
            framebuffer_write_generation,
            framebuffer_flush_region,
            framebuffer_flush_region_generation,
            payload_digest,
            panic_epoch,
            u64::from(panic_cpu),
            u64::from(panic_reason_code),
        ] {
            digest = mix_digest(digest, value);
        }
        if digest == 0 { 1 } else { digest }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_display_panic_last_frame(
        &self,
        panic_last_frame: DisplayPanicLastFrameId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display_snapshot_barrier: DisplaySnapshotBarrierId,
        display_snapshot_barrier_generation: Generation,
        display_event_log: DisplayEventLogId,
        display_event_log_generation: Generation,
        framebuffer_write: FramebufferWriteId,
        framebuffer_write_generation: Generation,
        framebuffer_flush_region: FramebufferFlushRegionId,
        framebuffer_flush_region_generation: Generation,
        payload_digest: u64,
        summary_digest: u64,
        summary_record_bytes: u32,
        panic_epoch: u64,
        panic_record_kind: &str,
        raw_framebuffer_bytes_exported: bool,
    ) -> Result<(), &'static str> {
        if panic_last_frame == 0 {
            return Err("display panic last-frame id=0 is invalid");
        }
        if self
            .display_panic_last_frames
            .iter()
            .any(|record| record.id == panic_last_frame)
        {
            return Err("display panic last-frame already exists");
        }
        if owner_store_generation == 0
            || display_snapshot_barrier_generation == 0
            || display_event_log_generation == 0
            || framebuffer_write_generation == 0
            || framebuffer_flush_region_generation == 0
            || payload_digest == 0
            || summary_digest == 0
            || summary_record_bytes == 0
            || summary_record_bytes > DISPLAY_PANIC_LAST_FRAME_MAX_RECORD_BYTES_V1
            || panic_epoch == 0
        {
            return Err("display panic last-frame requires exact refs and bounded summary");
        }
        if panic_record_kind != DISPLAY_PANIC_LAST_FRAME_RECORD_KIND_V1 {
            return Err("display panic last-frame record kind is unsupported");
        }
        if raw_framebuffer_bytes_exported {
            return Err("display panic last-frame cannot export raw framebuffer bytes");
        }
        let Some(store_record) = self
            .stores
            .iter()
            .find(|store| store.id == owner_store && store.generation == owner_store_generation)
        else {
            return Err("display panic last-frame owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("display panic last-frame owner store is dead");
        }
        let Some(barrier) = self.display_snapshot_barriers.iter().find(|barrier| {
            barrier.id == display_snapshot_barrier
                && barrier.generation == display_snapshot_barrier_generation
                && barrier.owner_store == owner_store
                && barrier.owner_store_generation == owner_store_generation
                && barrier.state == DisplaySnapshotBarrierState::Validated
        }) else {
            return Err("display panic last-frame snapshot barrier generation is missing");
        };
        let Some(display_record) = self.display_objects.iter().find(|display_record| {
            display_record.id == barrier.display
                && display_record.generation == barrier.display_generation
                && display_record.framebuffer == barrier.framebuffer
                && display_record.framebuffer_generation == barrier.framebuffer_generation
                && display_record.state == DisplayObjectState::Registered
        }) else {
            return Err("display panic last-frame display generation is missing");
        };
        let Some(framebuffer_record) = self.framebuffer_objects.iter().find(|framebuffer| {
            framebuffer.id == barrier.framebuffer
                && framebuffer.generation == barrier.framebuffer_generation
                && framebuffer.state == FramebufferObjectState::Registered
        }) else {
            return Err("display panic last-frame framebuffer generation is missing");
        };
        let Some(event_log) = self.display_event_logs.iter().find(|event_log| {
            event_log.id == display_event_log
                && event_log.generation == display_event_log_generation
                && event_log.owner_store == owner_store
                && event_log.owner_store_generation == owner_store_generation
                && event_log.display == barrier.display
                && event_log.display_generation == barrier.display_generation
                && event_log.framebuffer == barrier.framebuffer
                && event_log.framebuffer_generation == barrier.framebuffer_generation
                && event_log.state == DisplayEventLogState::Recorded
        }) else {
            return Err("display panic last-frame event-log generation is missing");
        };
        if event_log.flush_count == 0 {
            return Err("display panic last-frame requires a flushed frame");
        }
        let Some(write) = self.framebuffer_writes.iter().find(|write| {
            write.id == framebuffer_write
                && write.generation == framebuffer_write_generation
                && write.owner_store == owner_store
                && write.owner_store_generation == owner_store_generation
                && write.display == barrier.display
                && write.display_generation == barrier.display_generation
                && write.framebuffer == barrier.framebuffer
                && write.framebuffer_generation == barrier.framebuffer_generation
                && write.payload_digest == payload_digest
                && write.state == FramebufferWriteState::Applied
        }) else {
            return Err("display panic last-frame write generation is missing");
        };
        let Some(flush) = self.framebuffer_flush_regions.iter().find(|flush| {
            flush.id == framebuffer_flush_region
                && flush.generation == framebuffer_flush_region_generation
                && flush.owner_store == owner_store
                && flush.owner_store_generation == owner_store_generation
                && flush.framebuffer_write == framebuffer_write
                && flush.framebuffer_write_generation == framebuffer_write_generation
                && flush.display == barrier.display
                && flush.display_generation == barrier.display_generation
                && flush.framebuffer == barrier.framebuffer
                && flush.framebuffer_generation == barrier.framebuffer_generation
                && flush.payload_digest == payload_digest
                && flush.state == FramebufferFlushRegionState::Applied
        }) else {
            return Err("display panic last-frame flush generation is missing");
        };
        if flush.recorded_at_event < write.recorded_at_event
            || flush.recorded_at_event > event_log.last_event
            || write.recorded_at_event < event_log.first_event
            || write.x != flush.x
            || write.y != flush.y
            || write.width != flush.width
            || write.height != flush.height
            || write.byte_offset != flush.byte_offset
            || write.byte_len != flush.byte_len
            || write.pixel_format != flush.pixel_format
        {
            return Err("display panic last-frame write/flush binding mismatch");
        }
        let expected_digest = Self::expected_display_panic_last_frame_summary_digest_v1(
            owner_store,
            owner_store_generation,
            display_record.id,
            display_record.generation,
            framebuffer_record.id,
            framebuffer_record.generation,
            display_snapshot_barrier,
            display_snapshot_barrier_generation,
            display_event_log,
            display_event_log_generation,
            framebuffer_write,
            framebuffer_write_generation,
            framebuffer_flush_region,
            framebuffer_flush_region_generation,
            payload_digest,
            panic_epoch,
            0,
            1,
        );
        if summary_digest != expected_digest {
            return Err("display panic last-frame summary digest mismatch");
        }
        if self.check_invariants().is_err() {
            return Err("display panic last-frame requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_display_panic_last_frame_with_id(
        &mut self,
        panic_last_frame: DisplayPanicLastFrameId,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display_snapshot_barrier: DisplaySnapshotBarrierId,
        display_snapshot_barrier_generation: Generation,
        display_event_log: DisplayEventLogId,
        display_event_log_generation: Generation,
        framebuffer_write: FramebufferWriteId,
        framebuffer_write_generation: Generation,
        framebuffer_flush_region: FramebufferFlushRegionId,
        framebuffer_flush_region_generation: Generation,
        payload_digest: u64,
        summary_digest: u64,
        summary_record_bytes: u32,
        panic_epoch: u64,
        panic_record_kind: &str,
        raw_framebuffer_bytes_exported: bool,
        note: &str,
    ) -> bool {
        if self
            .validate_display_panic_last_frame(
                panic_last_frame,
                owner_store,
                owner_store_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                display_event_log,
                display_event_log_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                payload_digest,
                summary_digest,
                summary_record_bytes,
                panic_epoch,
                panic_record_kind,
                raw_framebuffer_bytes_exported,
            )
            .is_err()
        {
            return false;
        }
        let barrier = self
            .display_snapshot_barriers
            .iter()
            .find(|barrier| {
                barrier.id == display_snapshot_barrier
                    && barrier.generation == display_snapshot_barrier_generation
            })
            .expect("validated display panic last-frame barrier exists")
            .clone();
        let flush = self
            .framebuffer_flush_regions
            .iter()
            .find(|flush| {
                flush.id == framebuffer_flush_region
                    && flush.generation == framebuffer_flush_region_generation
            })
            .expect("validated display panic last-frame flush exists")
            .clone();
        let generation = 1;
        let panic_cpu = 0;
        let panic_reason_code = 1;
        self.next_display_panic_last_frame_id = self
            .next_display_panic_last_frame_id
            .max(panic_last_frame.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::DisplayPanicLastFrameRecorded {
                panic_last_frame,
                owner_store,
                owner_store_generation,
                display: barrier.display,
                display_generation: barrier.display_generation,
                framebuffer: barrier.framebuffer,
                framebuffer_generation: barrier.framebuffer_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                display_event_log,
                display_event_log_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                payload_digest,
                summary_digest,
                summary_record_bytes,
                panic_epoch,
                panic_cpu,
                panic_reason_code,
                raw_framebuffer_bytes_exported,
                generation,
            },
        );
        self.display_panic_last_frames
            .push(DisplayPanicLastFrameRecord {
                id: panic_last_frame,
                owner_store,
                owner_store_generation,
                display: barrier.display,
                display_generation: barrier.display_generation,
                framebuffer: barrier.framebuffer,
                framebuffer_generation: barrier.framebuffer_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                display_event_log,
                display_event_log_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                x: flush.x,
                y: flush.y,
                width: flush.width,
                height: flush.height,
                byte_offset: flush.byte_offset,
                byte_len: flush.byte_len,
                pixel_format: flush.pixel_format,
                payload_digest,
                summary_digest,
                summary_record_bytes,
                panic_epoch,
                panic_cpu,
                panic_reason_code,
                panic_record_kind: panic_record_kind.to_string(),
                raw_framebuffer_bytes_exported,
                generation,
                state: DisplayPanicLastFrameState::Recorded,
                recorded_at_event,
                note: note.to_string(),
            });
        self.check_invariants().is_ok()
    }

    pub fn display_panic_last_frames(&self) -> &[DisplayPanicLastFrameRecord] {
        &self.display_panic_last_frames
    }

    pub fn display_panic_last_frame_count(&self) -> usize {
        self.display_panic_last_frames.len()
    }

    pub fn check_display_panic_last_frame_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.display_panic_last_frames {
            if record.id == 0
                || record.generation == 0
                || record.owner_store_generation == 0
                || record.display_generation == 0
                || record.framebuffer_generation == 0
                || record.display_snapshot_barrier_generation == 0
                || record.display_event_log_generation == 0
                || record.framebuffer_write_generation == 0
                || record.framebuffer_flush_region_generation == 0
                || record.payload_digest == 0
                || record.summary_digest == 0
                || record.summary_record_bytes == 0
                || record.summary_record_bytes > DISPLAY_PANIC_LAST_FRAME_MAX_RECORD_BYTES_V1
                || record.panic_epoch == 0
                || record.panic_record_kind != DISPLAY_PANIC_LAST_FRAME_RECORD_KIND_V1
                || record.raw_framebuffer_bytes_exported
                || record.state != DisplayPanicLastFrameState::Recorded
            {
                return Err(SemanticInvariantError::DisplayPanicLastFrameInvalid {
                    panic_last_frame: record.id,
                });
            }
            let Some(store_record) = self.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::DisplayPanicLastFrameMissingStore {
                    panic_last_frame: record.id,
                    store: record.owner_store,
                });
            };
            if store_record.state == StoreState::Dead {
                return Err(SemanticInvariantError::DisplayPanicLastFrameInvalid {
                    panic_last_frame: record.id,
                });
            }
            if !self.display_objects.iter().any(|display| {
                display.id == record.display
                    && display.generation == record.display_generation
                    && display.framebuffer == record.framebuffer
                    && display.framebuffer_generation == record.framebuffer_generation
            }) {
                return Err(
                    SemanticInvariantError::DisplayPanicLastFrameMissingDisplay {
                        panic_last_frame: record.id,
                        display: record.display,
                    },
                );
            }
            if !self.framebuffer_objects.iter().any(|framebuffer| {
                framebuffer.id == record.framebuffer
                    && framebuffer.generation == record.framebuffer_generation
            }) {
                return Err(
                    SemanticInvariantError::DisplayPanicLastFrameMissingFramebuffer {
                        panic_last_frame: record.id,
                        framebuffer: record.framebuffer,
                    },
                );
            }
            let Some(barrier) = self.display_snapshot_barriers.iter().find(|barrier| {
                barrier.id == record.display_snapshot_barrier
                    && barrier.generation == record.display_snapshot_barrier_generation
            }) else {
                return Err(
                    SemanticInvariantError::DisplayPanicLastFrameMissingBarrier {
                        panic_last_frame: record.id,
                        barrier: record.display_snapshot_barrier,
                    },
                );
            };
            let Some(event_log) = self.display_event_logs.iter().find(|event_log| {
                event_log.id == record.display_event_log
                    && event_log.generation == record.display_event_log_generation
            }) else {
                return Err(
                    SemanticInvariantError::DisplayPanicLastFrameMissingEventLog {
                        panic_last_frame: record.id,
                        display_event_log: record.display_event_log,
                    },
                );
            };
            let Some(write) = self.framebuffer_writes.iter().find(|write| {
                write.id == record.framebuffer_write
                    && write.generation == record.framebuffer_write_generation
            }) else {
                return Err(SemanticInvariantError::DisplayPanicLastFrameMissingWrite {
                    panic_last_frame: record.id,
                    framebuffer_write: record.framebuffer_write,
                });
            };
            let Some(flush) = self.framebuffer_flush_regions.iter().find(|flush| {
                flush.id == record.framebuffer_flush_region
                    && flush.generation == record.framebuffer_flush_region_generation
            }) else {
                return Err(SemanticInvariantError::DisplayPanicLastFrameMissingFlush {
                    panic_last_frame: record.id,
                    framebuffer_flush_region: record.framebuffer_flush_region,
                });
            };
            let expected_digest = Self::expected_display_panic_last_frame_summary_digest_v1(
                record.owner_store,
                record.owner_store_generation,
                record.display,
                record.display_generation,
                record.framebuffer,
                record.framebuffer_generation,
                record.display_snapshot_barrier,
                record.display_snapshot_barrier_generation,
                record.display_event_log,
                record.display_event_log_generation,
                record.framebuffer_write,
                record.framebuffer_write_generation,
                record.framebuffer_flush_region,
                record.framebuffer_flush_region_generation,
                record.payload_digest,
                record.panic_epoch,
                record.panic_cpu,
                record.panic_reason_code,
            );
            if barrier.owner_store != record.owner_store
                || barrier.owner_store_generation != record.owner_store_generation
                || barrier.display != record.display
                || barrier.display_generation != record.display_generation
                || barrier.framebuffer != record.framebuffer
                || barrier.framebuffer_generation != record.framebuffer_generation
                || barrier.state != DisplaySnapshotBarrierState::Validated
                || event_log.owner_store != record.owner_store
                || event_log.owner_store_generation != record.owner_store_generation
                || event_log.display != record.display
                || event_log.display_generation != record.display_generation
                || event_log.framebuffer != record.framebuffer
                || event_log.framebuffer_generation != record.framebuffer_generation
                || event_log.flush_count == 0
                || write.owner_store != record.owner_store
                || write.owner_store_generation != record.owner_store_generation
                || write.display != record.display
                || write.display_generation != record.display_generation
                || write.framebuffer != record.framebuffer
                || write.framebuffer_generation != record.framebuffer_generation
                || write.payload_digest != record.payload_digest
                || flush.owner_store != record.owner_store
                || flush.owner_store_generation != record.owner_store_generation
                || flush.framebuffer_write != record.framebuffer_write
                || flush.framebuffer_write_generation != record.framebuffer_write_generation
                || flush.display != record.display
                || flush.display_generation != record.display_generation
                || flush.framebuffer != record.framebuffer
                || flush.framebuffer_generation != record.framebuffer_generation
                || flush.payload_digest != record.payload_digest
                || flush.x != record.x
                || flush.y != record.y
                || flush.width != record.width
                || flush.height != record.height
                || flush.byte_offset != record.byte_offset
                || flush.byte_len != record.byte_len
                || flush.pixel_format != record.pixel_format
                || record.summary_digest != expected_digest
            {
                return Err(SemanticInvariantError::DisplayPanicLastFrameInvalid {
                    panic_last_frame: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DisplayPanicLastFrameRecorded {
                            panic_last_frame,
                            owner_store,
                            owner_store_generation,
                            display,
                            display_generation,
                            framebuffer,
                            framebuffer_generation,
                            display_snapshot_barrier,
                            display_snapshot_barrier_generation,
                            display_event_log,
                            display_event_log_generation,
                            framebuffer_write,
                            framebuffer_write_generation,
                            framebuffer_flush_region,
                            framebuffer_flush_region_generation,
                            payload_digest,
                            summary_digest,
                            summary_record_bytes,
                            panic_epoch,
                            panic_cpu,
                            panic_reason_code,
                            raw_framebuffer_bytes_exported,
                            generation,
                        } if *panic_last_frame == record.id
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *display == record.display
                            && *display_generation == record.display_generation
                            && *framebuffer == record.framebuffer
                            && *framebuffer_generation == record.framebuffer_generation
                            && *display_snapshot_barrier == record.display_snapshot_barrier
                            && *display_snapshot_barrier_generation
                                == record.display_snapshot_barrier_generation
                            && *display_event_log == record.display_event_log
                            && *display_event_log_generation
                                == record.display_event_log_generation
                            && *framebuffer_write == record.framebuffer_write
                            && *framebuffer_write_generation
                                == record.framebuffer_write_generation
                            && *framebuffer_flush_region == record.framebuffer_flush_region
                            && *framebuffer_flush_region_generation
                                == record.framebuffer_flush_region_generation
                            && *payload_digest == record.payload_digest
                            && *summary_digest == record.summary_digest
                            && *summary_record_bytes == record.summary_record_bytes
                            && *panic_epoch == record.panic_epoch
                            && *panic_cpu == record.panic_cpu
                            && *panic_reason_code == record.panic_reason_code
                            && *raw_framebuffer_bytes_exported
                                == record.raw_framebuffer_bytes_exported
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::DisplayPanicLastFrameMissingEvent {
                    panic_last_frame: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_display_panic_last_frame_summary_digest_for_test(
        &mut self,
        panic_last_frame: DisplayPanicLastFrameId,
        summary_digest: u64,
    ) {
        if let Some(record) = self
            .display_panic_last_frames
            .iter_mut()
            .find(|record| record.id == panic_last_frame)
        {
            record.summary_digest = summary_digest;
        }
    }
}
