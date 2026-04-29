use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_framebuffer_benchmark(
        &self,
        benchmark: FramebufferBenchmarkId,
        scenario: &str,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display_capability: DisplayCapabilityId,
        display_capability_generation: Generation,
        framebuffer_write: FramebufferWriteId,
        framebuffer_write_generation: Generation,
        framebuffer_flush_region: FramebufferFlushRegionId,
        framebuffer_flush_region_generation: Generation,
        display_event_log: DisplayEventLogId,
        display_event_log_generation: Generation,
        display_snapshot_barrier: DisplaySnapshotBarrierId,
        display_snapshot_barrier_generation: Generation,
        sample_frames: u32,
        sample_bytes: u64,
        frame_area_pixels: u64,
        write_nanos: u64,
        flush_nanos: u64,
        measured_nanos: u64,
        budget_nanos: u64,
        p50_latency_nanos: u64,
        p99_latency_nanos: u64,
    ) -> Result<(), &'static str> {
        if benchmark == 0 {
            return Err("framebuffer benchmark id=0 is invalid");
        }
        if benchmark == u64::MAX {
            return Err("framebuffer benchmark id cannot advance generation cursor");
        }
        if self.framebuffer_benchmarks.iter().any(|record| record.id == benchmark) {
            return Err("framebuffer benchmark already exists");
        }
        if scenario.is_empty() {
            return Err("framebuffer benchmark scenario is empty");
        }
        if owner_store_generation == 0
            || display_capability_generation == 0
            || framebuffer_write_generation == 0
            || framebuffer_flush_region_generation == 0
            || display_event_log_generation == 0
            || display_snapshot_barrier_generation == 0
        {
            return Err("framebuffer benchmark identity values must be nonzero");
        }
        if sample_frames == 0
            || sample_bytes == 0
            || frame_area_pixels == 0
            || write_nanos == 0
            || flush_nanos == 0
            || measured_nanos == 0
            || budget_nanos == 0
            || p50_latency_nanos == 0
            || p99_latency_nanos == 0
        {
            return Err("framebuffer benchmark metrics require nonzero samples and timing");
        }
        if write_nanos.checked_add(flush_nanos) != Some(measured_nanos) {
            return Err("framebuffer benchmark measured time is not closed");
        }
        if measured_nanos > budget_nanos {
            return Err("framebuffer benchmark exceeds latency budget");
        }
        if p99_latency_nanos < p50_latency_nanos || p99_latency_nanos > measured_nanos {
            return Err("framebuffer benchmark latency distribution is invalid");
        }
        if Self::derive_framebuffer_throughput_bytes_per_sec(sample_bytes, measured_nanos).is_none()
            || Self::derive_framebuffer_flushes_per_sec_milli(sample_frames, measured_nanos)
                .is_none()
        {
            return Err("framebuffer benchmark metric overflow");
        }

        let Some(store) = self
            .stores
            .iter()
            .find(|store| store.id == owner_store && store.generation == owner_store_generation)
        else {
            return Err("framebuffer benchmark owner store generation is missing");
        };
        if store.state == StoreState::Dead {
            return Err("framebuffer benchmark owner store is dead");
        }
        let Some(capability) = self.display_capabilities.iter().find(|capability| {
            capability.id == display_capability
                && capability.generation == display_capability_generation
        }) else {
            return Err("framebuffer benchmark display capability generation is missing");
        };
        if capability.owner_store != owner_store
            || capability.owner_store_generation != owner_store_generation
            || !matches!(
                capability.state,
                DisplayCapabilityState::Active | DisplayCapabilityState::Revoked
            )
            || !capability.operations.iter().any(|operation| operation == "lease")
            || !capability.operations.iter().any(|operation| operation == "flush")
        {
            return Err("framebuffer benchmark display capability binding mismatch");
        }

        let Some(display) = self.display_objects.iter().find(|display| {
            display.id == capability.display
                && display.generation == capability.display_generation
                && display.state == DisplayObjectState::Registered
        }) else {
            return Err("framebuffer benchmark display generation is missing");
        };
        let Some(framebuffer) = self.framebuffer_objects.iter().find(|framebuffer| {
            framebuffer.id == capability.framebuffer
                && framebuffer.generation == capability.framebuffer_generation
                && framebuffer.state == FramebufferObjectState::Registered
        }) else {
            return Err("framebuffer benchmark framebuffer generation is missing");
        };
        if display.framebuffer != framebuffer.id
            || display.framebuffer_generation != framebuffer.generation
        {
            return Err("framebuffer benchmark display/framebuffer binding mismatch");
        }

        let Some(write) = self.framebuffer_writes.iter().find(|write| {
            write.id == framebuffer_write
                && write.generation == framebuffer_write_generation
                && write.state == FramebufferWriteState::Applied
        }) else {
            return Err("framebuffer benchmark write generation is missing");
        };
        let Some(flush) = self.framebuffer_flush_regions.iter().find(|flush| {
            flush.id == framebuffer_flush_region
                && flush.generation == framebuffer_flush_region_generation
                && flush.state == FramebufferFlushRegionState::Applied
        }) else {
            return Err("framebuffer benchmark flush generation is missing");
        };
        if write.owner_store != owner_store
            || write.owner_store_generation != owner_store_generation
            || write.display_capability != display_capability
            || write.display_capability_generation != display_capability_generation
            || write.display != display.id
            || write.display_generation != display.generation
            || write.framebuffer != framebuffer.id
            || write.framebuffer_generation != framebuffer.generation
            || flush.owner_store != owner_store
            || flush.owner_store_generation != owner_store_generation
            || flush.framebuffer_write != write.id
            || flush.framebuffer_write_generation != write.generation
            || flush.display_capability != display_capability
            || flush.display_capability_generation != display_capability_generation
            || flush.display != display.id
            || flush.display_generation != display.generation
            || flush.framebuffer != framebuffer.id
            || flush.framebuffer_generation != framebuffer.generation
            || flush.x != write.x
            || flush.y != write.y
            || flush.width != write.width
            || flush.height != write.height
            || flush.byte_offset != write.byte_offset
            || flush.byte_len != write.byte_len
            || flush.pixel_format != write.pixel_format
            || flush.payload_digest != write.payload_digest
        {
            return Err("framebuffer benchmark write/flush binding mismatch");
        }
        if sample_bytes
            != flush
                .byte_len
                .checked_mul(u64::from(sample_frames))
                .ok_or("framebuffer benchmark byte accounting overflow")?
        {
            return Err("framebuffer benchmark byte accounting is not closed");
        }
        if frame_area_pixels
            != u64::from(flush.width)
                .checked_mul(u64::from(flush.height))
                .ok_or("framebuffer benchmark pixel accounting overflow")?
        {
            return Err("framebuffer benchmark pixel accounting is not closed");
        }

        let Some(event_log) = self.display_event_logs.iter().find(|event_log| {
            event_log.id == display_event_log
                && event_log.generation == display_event_log_generation
                && event_log.state == DisplayEventLogState::Recorded
        }) else {
            return Err("framebuffer benchmark display event log generation is missing");
        };
        if event_log.owner_store != owner_store
            || event_log.owner_store_generation != owner_store_generation
            || event_log.display_capability != display_capability
            || event_log.display_capability_generation != display_capability_generation
            || event_log.display != display.id
            || event_log.display_generation != display.generation
            || event_log.framebuffer != framebuffer.id
            || event_log.framebuffer_generation != framebuffer.generation
            || event_log.flush_count < u64::from(sample_frames)
            || write.recorded_at_event < event_log.first_event
            || flush.recorded_at_event > event_log.last_event
        {
            return Err("framebuffer benchmark event-log binding mismatch");
        }

        let Some(barrier) = self.display_snapshot_barriers.iter().find(|barrier| {
            barrier.id == display_snapshot_barrier
                && barrier.generation == display_snapshot_barrier_generation
                && barrier.state == DisplaySnapshotBarrierState::Validated
        }) else {
            return Err("framebuffer benchmark snapshot barrier generation is missing");
        };
        if barrier.owner_store != owner_store
            || barrier.owner_store_generation != owner_store_generation
            || barrier.display != display.id
            || barrier.display_generation != display.generation
            || barrier.framebuffer != framebuffer.id
            || barrier.framebuffer_generation != framebuffer.generation
            || barrier.active_framebuffer_window_lease_count != 0
            || barrier.active_framebuffer_mapping_count != 0
            || barrier.dirty_framebuffer_region_count != 0
        {
            return Err("framebuffer benchmark snapshot barrier is not quiescent");
        }

        if self.check_invariants().is_err() {
            return Err("framebuffer benchmark requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_framebuffer_benchmark_with_id(
        &mut self,
        benchmark: FramebufferBenchmarkId,
        scenario: &str,
        owner_store: StoreId,
        owner_store_generation: Generation,
        display_capability: DisplayCapabilityId,
        display_capability_generation: Generation,
        framebuffer_write: FramebufferWriteId,
        framebuffer_write_generation: Generation,
        framebuffer_flush_region: FramebufferFlushRegionId,
        framebuffer_flush_region_generation: Generation,
        display_event_log: DisplayEventLogId,
        display_event_log_generation: Generation,
        display_snapshot_barrier: DisplaySnapshotBarrierId,
        display_snapshot_barrier_generation: Generation,
        sample_frames: u32,
        sample_bytes: u64,
        frame_area_pixels: u64,
        write_nanos: u64,
        flush_nanos: u64,
        measured_nanos: u64,
        budget_nanos: u64,
        p50_latency_nanos: u64,
        p99_latency_nanos: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_framebuffer_benchmark(
                benchmark,
                scenario,
                owner_store,
                owner_store_generation,
                display_capability,
                display_capability_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                display_event_log,
                display_event_log_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                sample_frames,
                sample_bytes,
                frame_area_pixels,
                write_nanos,
                flush_nanos,
                measured_nanos,
                budget_nanos,
                p50_latency_nanos,
                p99_latency_nanos,
            )
            .is_err()
        {
            return false;
        }
        let Some(throughput_bytes_per_sec) =
            Self::derive_framebuffer_throughput_bytes_per_sec(sample_bytes, measured_nanos)
        else {
            return false;
        };
        let Some(flushes_per_sec_milli) =
            Self::derive_framebuffer_flushes_per_sec_milli(sample_frames, measured_nanos)
        else {
            return false;
        };
        let Some(capability) = self
            .display_capabilities
            .iter()
            .find(|capability| {
                capability.id == display_capability
                    && capability.generation == display_capability_generation
            })
            .cloned()
        else {
            return false;
        };
        let generation = 1;
        self.next_framebuffer_benchmark_id =
            self.next_framebuffer_benchmark_id.max(benchmark.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "display",
            EventKind::FramebufferBenchmarkRecorded {
                benchmark,
                owner_store,
                owner_store_generation,
                display: capability.display,
                display_generation: capability.display_generation,
                framebuffer: capability.framebuffer,
                framebuffer_generation: capability.framebuffer_generation,
                display_capability,
                display_capability_generation,
                framebuffer_write,
                framebuffer_write_generation,
                framebuffer_flush_region,
                framebuffer_flush_region_generation,
                display_event_log,
                display_event_log_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                sample_frames,
                sample_bytes,
                frame_area_pixels,
                write_nanos,
                flush_nanos,
                measured_nanos,
                budget_nanos,
                throughput_bytes_per_sec,
                flushes_per_sec_milli,
                p50_latency_nanos,
                p99_latency_nanos,
                generation,
            },
        );
        self.framebuffer_benchmarks.push(FramebufferBenchmarkRecord {
            id: benchmark,
            scenario: scenario.to_string(),
            owner_store,
            owner_store_generation,
            display: capability.display,
            display_generation: capability.display_generation,
            framebuffer: capability.framebuffer,
            framebuffer_generation: capability.framebuffer_generation,
            display_capability,
            display_capability_generation,
            framebuffer_write,
            framebuffer_write_generation,
            framebuffer_flush_region,
            framebuffer_flush_region_generation,
            display_event_log,
            display_event_log_generation,
            display_snapshot_barrier,
            display_snapshot_barrier_generation,
            sample_frames,
            sample_bytes,
            frame_area_pixels,
            write_nanos,
            flush_nanos,
            measured_nanos,
            budget_nanos,
            throughput_bytes_per_sec,
            flushes_per_sec_milli,
            p50_latency_nanos,
            p99_latency_nanos,
            generation,
            state: FramebufferBenchmarkState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn framebuffer_benchmarks(&self) -> &[FramebufferBenchmarkRecord] {
        &self.framebuffer_benchmarks
    }

    pub fn framebuffer_benchmark_count(&self) -> usize {
        self.framebuffer_benchmarks.len()
    }

    pub fn derive_framebuffer_throughput_bytes_per_sec(
        sample_bytes: u64,
        measured_nanos: u64,
    ) -> Option<u64> {
        sample_bytes.checked_mul(1_000_000_000)?.checked_div(measured_nanos)
    }

    pub fn derive_framebuffer_flushes_per_sec_milli(
        sample_frames: u32,
        measured_nanos: u64,
    ) -> Option<u64> {
        u64::from(sample_frames).checked_mul(1_000_000_000_000)?.checked_div(measured_nanos)
    }

    pub fn check_framebuffer_benchmark_invariants(&self) -> Result<(), SemanticInvariantError> {
        for benchmark in &self.framebuffer_benchmarks {
            let expected_throughput = Self::derive_framebuffer_throughput_bytes_per_sec(
                benchmark.sample_bytes,
                benchmark.measured_nanos,
            );
            let expected_flushes = Self::derive_framebuffer_flushes_per_sec_milli(
                benchmark.sample_frames,
                benchmark.measured_nanos,
            );
            if benchmark.id == 0
                || benchmark.generation == 0
                || benchmark.scenario.is_empty()
                || benchmark.owner_store_generation == 0
                || benchmark.display_generation == 0
                || benchmark.framebuffer_generation == 0
                || benchmark.display_capability_generation == 0
                || benchmark.framebuffer_write_generation == 0
                || benchmark.framebuffer_flush_region_generation == 0
                || benchmark.display_event_log_generation == 0
                || benchmark.display_snapshot_barrier_generation == 0
                || benchmark.sample_frames == 0
                || benchmark.sample_bytes == 0
                || benchmark.frame_area_pixels == 0
                || benchmark.write_nanos == 0
                || benchmark.flush_nanos == 0
                || benchmark.write_nanos.checked_add(benchmark.flush_nanos)
                    != Some(benchmark.measured_nanos)
                || benchmark.measured_nanos == 0
                || benchmark.budget_nanos == 0
                || benchmark.measured_nanos > benchmark.budget_nanos
                || expected_throughput != Some(benchmark.throughput_bytes_per_sec)
                || expected_flushes != Some(benchmark.flushes_per_sec_milli)
                || benchmark.p50_latency_nanos == 0
                || benchmark.p99_latency_nanos < benchmark.p50_latency_nanos
                || benchmark.p99_latency_nanos > benchmark.measured_nanos
                || benchmark.state != FramebufferBenchmarkState::Recorded
            {
                return Err(SemanticInvariantError::FramebufferBenchmarkInvalid {
                    benchmark: benchmark.id,
                });
            }
            let required_refs = [
                ContractObjectRef::new(
                    ContractObjectKind::Store,
                    benchmark.owner_store,
                    benchmark.owner_store_generation,
                ),
                ContractObjectRef::new(
                    ContractObjectKind::DisplayObject,
                    benchmark.display,
                    benchmark.display_generation,
                ),
                ContractObjectRef::new(
                    ContractObjectKind::FramebufferObject,
                    benchmark.framebuffer,
                    benchmark.framebuffer_generation,
                ),
                ContractObjectRef::new(
                    ContractObjectKind::DisplayCapability,
                    benchmark.display_capability,
                    benchmark.display_capability_generation,
                ),
                ContractObjectRef::new(
                    ContractObjectKind::FramebufferWrite,
                    benchmark.framebuffer_write,
                    benchmark.framebuffer_write_generation,
                ),
                ContractObjectRef::new(
                    ContractObjectKind::FramebufferFlushRegion,
                    benchmark.framebuffer_flush_region,
                    benchmark.framebuffer_flush_region_generation,
                ),
                ContractObjectRef::new(
                    ContractObjectKind::DisplayEventLog,
                    benchmark.display_event_log,
                    benchmark.display_event_log_generation,
                ),
                ContractObjectRef::new(
                    ContractObjectKind::DisplaySnapshotBarrier,
                    benchmark.display_snapshot_barrier,
                    benchmark.display_snapshot_barrier_generation,
                ),
            ];
            for target in required_refs {
                if self.object_ref_exists(target).is_none() {
                    return Err(SemanticInvariantError::FramebufferBenchmarkMissingTarget {
                        benchmark: benchmark.id,
                        target,
                    });
                }
            }
            let Some(write) = self.framebuffer_writes.iter().find(|write| {
                write.id == benchmark.framebuffer_write
                    && write.generation == benchmark.framebuffer_write_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::FramebufferWrite,
                        benchmark.framebuffer_write,
                        benchmark.framebuffer_write_generation,
                    ),
                });
            };
            let Some(flush) = self.framebuffer_flush_regions.iter().find(|flush| {
                flush.id == benchmark.framebuffer_flush_region
                    && flush.generation == benchmark.framebuffer_flush_region_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::FramebufferFlushRegion,
                        benchmark.framebuffer_flush_region,
                        benchmark.framebuffer_flush_region_generation,
                    ),
                });
            };
            let Some(event_log) = self.display_event_logs.iter().find(|event_log| {
                event_log.id == benchmark.display_event_log
                    && event_log.generation == benchmark.display_event_log_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::DisplayEventLog,
                        benchmark.display_event_log,
                        benchmark.display_event_log_generation,
                    ),
                });
            };
            let Some(barrier) = self.display_snapshot_barriers.iter().find(|barrier| {
                barrier.id == benchmark.display_snapshot_barrier
                    && barrier.generation == benchmark.display_snapshot_barrier_generation
            }) else {
                return Err(SemanticInvariantError::FramebufferBenchmarkMissingTarget {
                    benchmark: benchmark.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::DisplaySnapshotBarrier,
                        benchmark.display_snapshot_barrier,
                        benchmark.display_snapshot_barrier_generation,
                    ),
                });
            };
            if write.state != FramebufferWriteState::Applied
                || flush.state != FramebufferFlushRegionState::Applied
                || event_log.state != DisplayEventLogState::Recorded
                || barrier.state != DisplaySnapshotBarrierState::Validated
                || write.display_capability != benchmark.display_capability
                || write.display_capability_generation != benchmark.display_capability_generation
                || flush.framebuffer_write != write.id
                || flush.framebuffer_write_generation != write.generation
                || flush.payload_digest != write.payload_digest
                || flush.byte_len.checked_mul(u64::from(benchmark.sample_frames))
                    != Some(benchmark.sample_bytes)
                || u64::from(flush.width).checked_mul(u64::from(flush.height))
                    != Some(benchmark.frame_area_pixels)
                || event_log.flush_count < u64::from(benchmark.sample_frames)
                || barrier.active_framebuffer_window_lease_count != 0
                || barrier.active_framebuffer_mapping_count != 0
                || barrier.dirty_framebuffer_region_count != 0
            {
                return Err(SemanticInvariantError::FramebufferBenchmarkMetricMismatch {
                    benchmark: benchmark.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == benchmark.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FramebufferBenchmarkRecorded {
                            benchmark: id,
                            owner_store,
                            owner_store_generation,
                            display,
                            display_generation,
                            framebuffer,
                            framebuffer_generation,
                            display_capability,
                            display_capability_generation,
                            framebuffer_write,
                            framebuffer_write_generation,
                            framebuffer_flush_region,
                            framebuffer_flush_region_generation,
                            display_event_log,
                            display_event_log_generation,
                            display_snapshot_barrier,
                            display_snapshot_barrier_generation,
                            sample_frames,
                            sample_bytes,
                            frame_area_pixels,
                            write_nanos,
                            flush_nanos,
                            measured_nanos,
                            budget_nanos,
                            throughput_bytes_per_sec,
                            flushes_per_sec_milli,
                            p50_latency_nanos,
                            p99_latency_nanos,
                            generation,
                        } if *id == benchmark.id
                            && *owner_store == benchmark.owner_store
                            && *owner_store_generation == benchmark.owner_store_generation
                            && *display == benchmark.display
                            && *display_generation == benchmark.display_generation
                            && *framebuffer == benchmark.framebuffer
                            && *framebuffer_generation == benchmark.framebuffer_generation
                            && *display_capability == benchmark.display_capability
                            && *display_capability_generation == benchmark.display_capability_generation
                            && *framebuffer_write == benchmark.framebuffer_write
                            && *framebuffer_write_generation == benchmark.framebuffer_write_generation
                            && *framebuffer_flush_region == benchmark.framebuffer_flush_region
                            && *framebuffer_flush_region_generation == benchmark.framebuffer_flush_region_generation
                            && *display_event_log == benchmark.display_event_log
                            && *display_event_log_generation == benchmark.display_event_log_generation
                            && *display_snapshot_barrier == benchmark.display_snapshot_barrier
                            && *display_snapshot_barrier_generation == benchmark.display_snapshot_barrier_generation
                            && *sample_frames == benchmark.sample_frames
                            && *sample_bytes == benchmark.sample_bytes
                            && *frame_area_pixels == benchmark.frame_area_pixels
                            && *write_nanos == benchmark.write_nanos
                            && *flush_nanos == benchmark.flush_nanos
                            && *measured_nanos == benchmark.measured_nanos
                            && *budget_nanos == benchmark.budget_nanos
                            && *throughput_bytes_per_sec == benchmark.throughput_bytes_per_sec
                            && *flushes_per_sec_milli == benchmark.flushes_per_sec_milli
                            && *p50_latency_nanos == benchmark.p50_latency_nanos
                            && *p99_latency_nanos == benchmark.p99_latency_nanos
                            && *generation == benchmark.generation
                    )
            }) {
                return Err(SemanticInvariantError::FramebufferBenchmarkMissingEvent {
                    benchmark: benchmark.id,
                    event: benchmark.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    fn object_ref_exists(&self, target: ContractObjectRef) -> Option<ContractObjectRef> {
        match target.kind {
            ContractObjectKind::Store => self
                .stores
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .map(StoreRecord::object_ref),
            ContractObjectKind::DisplayObject => self
                .display_objects
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .map(DisplayObjectRecord::object_ref),
            ContractObjectKind::FramebufferObject => self
                .framebuffer_objects
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .map(FramebufferObjectRecord::object_ref),
            ContractObjectKind::DisplayCapability => self
                .display_capabilities
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .map(DisplayCapabilityRecord::object_ref),
            ContractObjectKind::FramebufferWrite => self
                .framebuffer_writes
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .map(FramebufferWriteRecord::object_ref),
            ContractObjectKind::FramebufferFlushRegion => self
                .framebuffer_flush_regions
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .map(FramebufferFlushRegionRecord::object_ref),
            ContractObjectKind::DisplayEventLog => self
                .display_event_logs
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .map(DisplayEventLogRecord::object_ref),
            ContractObjectKind::DisplaySnapshotBarrier => self
                .display_snapshot_barriers
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .map(DisplaySnapshotBarrierRecord::object_ref),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_framebuffer_benchmark_throughput_for_test(
        &mut self,
        benchmark: FramebufferBenchmarkId,
        throughput: u64,
    ) {
        if let Some(record) =
            self.framebuffer_benchmarks.iter_mut().find(|record| record.id == benchmark)
        {
            record.throughput_bytes_per_sec = throughput;
        }
    }
}
