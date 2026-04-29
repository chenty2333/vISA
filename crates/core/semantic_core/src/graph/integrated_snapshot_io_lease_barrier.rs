use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_integrated_snapshot_io_lease_barrier(
        &self,
        integrated: IntegratedSnapshotIoLeaseBarrierId,
        scenario: &str,
        smp_snapshot_barrier: SmpSnapshotBarrierId,
        smp_snapshot_barrier_generation: Generation,
        io_cleanup: IoCleanupId,
        io_cleanup_generation: Generation,
        display_snapshot_barrier: DisplaySnapshotBarrierId,
        display_snapshot_barrier_generation: Generation,
        invariant_checks: u32,
    ) -> Result<(), &'static str> {
        if integrated == 0 {
            return Err("integrated snapshot/io lease barrier id=0 is invalid");
        }
        if self.integrated_snapshot_io_lease_barriers.iter().any(|record| record.id == integrated) {
            return Err("integrated snapshot/io lease barrier evidence already exists");
        }
        if scenario.is_empty() {
            return Err("integrated snapshot/io lease barrier scenario is empty");
        }
        if smp_snapshot_barrier_generation == 0
            || io_cleanup_generation == 0
            || display_snapshot_barrier_generation == 0
            || invariant_checks == 0
        {
            return Err("integrated snapshot/io lease barrier refs must carry generations");
        }

        let Some(smp_barrier) =
            self.domains.scheduler.smp_snapshot_barriers.iter().find(|record| {
                record.id == smp_snapshot_barrier
                    && record.generation == smp_snapshot_barrier_generation
            })
        else {
            return Err(
                "integrated snapshot/io lease barrier missing smp snapshot barrier evidence",
            );
        };
        let Some(cleanup) =
            self.domains.io.io_cleanups.iter().find(|record| {
                record.id == io_cleanup && record.generation == io_cleanup_generation
            })
        else {
            return Err("integrated snapshot/io lease barrier missing io cleanup evidence");
        };
        let Some(display_barrier) =
            self.domains.display.display_snapshot_barriers.iter().find(|record| {
                record.id == display_snapshot_barrier
                    && record.generation == display_snapshot_barrier_generation
            })
        else {
            return Err(
                "integrated snapshot/io lease barrier missing display snapshot barrier evidence",
            );
        };

        if smp_barrier.state != SmpSnapshotBarrierState::Validated
            || !smp_barrier.snapshot_validation_ok
            || smp_barrier.active_dmw_lease_count != 0
            || smp_barrier.in_flight_dma_count != 0
            || smp_barrier.raw_dma_binding_count != 0
            || smp_barrier.raw_mmio_binding_count != 0
            || smp_barrier.pending_cleanup_count != 0
        {
            return Err("integrated snapshot/io lease barrier requires clean smp snapshot barrier");
        }
        if cleanup.state != IoCleanupState::Completed
            || cleanup.completed_at_event == 0
            || cleanup.driver_store_generation == 0
            || cleanup.device_generation == 0
            || cleanup.released_dma_buffers.is_empty()
            || cleanup.released_mmio_regions.is_empty()
            || cleanup.released_irq_lines.is_empty()
            || cleanup.revoked_device_capabilities.is_empty()
        {
            return Err("integrated snapshot/io lease barrier requires completed io cleanup");
        }
        if display_barrier.state != DisplaySnapshotBarrierState::Validated
            || !display_barrier.snapshot_validation_ok
            || display_barrier.active_framebuffer_window_lease_count != 0
            || display_barrier.active_framebuffer_mapping_count != 0
            || display_barrier.dirty_framebuffer_region_count != 0
        {
            return Err(
                "integrated snapshot/io lease barrier requires clean display snapshot barrier",
            );
        }
        let Some(display_cleanup) =
            (match (display_barrier.display_cleanup, display_barrier.display_cleanup_generation) {
                (Some(cleanup_id), Some(generation)) => {
                    self.domains.display.display_cleanups.iter().find(|record| {
                        record.id == cleanup_id
                            && record.generation == generation
                            && record.state == DisplayCleanupState::Completed
                    })
                }
                _ => None,
            })
        else {
            return Err("integrated snapshot/io lease barrier requires display cleanup evidence");
        };
        if display_cleanup.released_framebuffer_window_leases.is_empty()
            || display_cleanup.revoked_display_capabilities.is_empty()
            || display_cleanup.owner_store != display_barrier.owner_store
            || display_cleanup.owner_store_generation != display_barrier.owner_store_generation
            || display_cleanup.display != display_barrier.display
            || display_cleanup.display_generation != display_barrier.display_generation
            || display_cleanup.framebuffer != display_barrier.framebuffer
            || display_cleanup.framebuffer_generation != display_barrier.framebuffer_generation
        {
            return Err("integrated snapshot/io lease barrier display cleanup binding mismatch");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_integrated_snapshot_io_lease_barrier_with_id(
        &mut self,
        integrated: IntegratedSnapshotIoLeaseBarrierId,
        scenario: &str,
        smp_snapshot_barrier: SmpSnapshotBarrierId,
        smp_snapshot_barrier_generation: Generation,
        io_cleanup: IoCleanupId,
        io_cleanup_generation: Generation,
        display_snapshot_barrier: DisplaySnapshotBarrierId,
        display_snapshot_barrier_generation: Generation,
        invariant_checks: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_integrated_snapshot_io_lease_barrier(
                integrated,
                scenario,
                smp_snapshot_barrier,
                smp_snapshot_barrier_generation,
                io_cleanup,
                io_cleanup_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                invariant_checks,
            )
            .is_err()
        {
            return false;
        }

        let Some(smp_barrier) =
            self.domains.scheduler.smp_snapshot_barriers.iter().find(|record| {
                record.id == smp_snapshot_barrier
                    && record.generation == smp_snapshot_barrier_generation
            })
        else {
            return false;
        };
        let Some(cleanup) =
            self.domains.io.io_cleanups.iter().find(|record| {
                record.id == io_cleanup && record.generation == io_cleanup_generation
            })
        else {
            return false;
        };
        let Some(display_barrier) =
            self.domains.display.display_snapshot_barriers.iter().find(|record| {
                record.id == display_snapshot_barrier
                    && record.generation == display_snapshot_barrier_generation
            })
        else {
            return false;
        };
        let Some(display_cleanup) =
            (match (display_barrier.display_cleanup, display_barrier.display_cleanup_generation) {
                (Some(cleanup_id), Some(generation)) => self
                    .domains
                    .display
                    .display_cleanups
                    .iter()
                    .find(|record| record.id == cleanup_id && record.generation == generation),
                _ => None,
            })
        else {
            return false;
        };

        let generation = 1;
        self.next_integrated_snapshot_io_lease_barrier_id =
            self.next_integrated_snapshot_io_lease_barrier_id.max(integrated.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "integrated-runtime",
            EventKind::IntegratedSnapshotIoLeaseBarrierRecorded {
                scenario: scenario.to_string(),
                integrated,
                smp_snapshot_barrier,
                smp_snapshot_barrier_generation,
                io_cleanup,
                io_cleanup_generation,
                display_snapshot_barrier,
                display_snapshot_barrier_generation,
                released_dma_buffers: cleanup.released_dma_buffers.len() as u32,
                released_mmio_regions: cleanup.released_mmio_regions.len() as u32,
                released_irq_lines: cleanup.released_irq_lines.len() as u32,
                released_framebuffer_window_leases: display_cleanup
                    .released_framebuffer_window_leases
                    .len() as u32,
                active_dmw_lease_count: smp_barrier.active_dmw_lease_count,
                in_flight_dma_count: smp_barrier.in_flight_dma_count,
                active_framebuffer_window_lease_count: display_barrier
                    .active_framebuffer_window_lease_count,
                invariant_checks,
                generation,
            },
        );
        self.integrated_snapshot_io_lease_barriers.push(IntegratedSnapshotIoLeaseBarrierRecord {
            id: integrated,
            scenario: scenario.to_string(),
            smp_snapshot_barrier,
            smp_snapshot_barrier_generation,
            io_cleanup,
            io_cleanup_generation,
            display_snapshot_barrier,
            display_snapshot_barrier_generation,
            driver_store: cleanup.driver_store,
            driver_store_generation: cleanup.driver_store_generation,
            device: cleanup.device,
            device_generation: cleanup.device_generation,
            display: display_barrier.display,
            display_generation: display_barrier.display_generation,
            framebuffer: display_barrier.framebuffer,
            framebuffer_generation: display_barrier.framebuffer_generation,
            active_dmw_lease_count: smp_barrier.active_dmw_lease_count,
            in_flight_dma_count: smp_barrier.in_flight_dma_count,
            raw_dma_binding_count: smp_barrier.raw_dma_binding_count,
            raw_mmio_binding_count: smp_barrier.raw_mmio_binding_count,
            active_framebuffer_window_lease_count: display_barrier
                .active_framebuffer_window_lease_count,
            active_framebuffer_mapping_count: display_barrier.active_framebuffer_mapping_count,
            dirty_framebuffer_region_count: display_barrier.dirty_framebuffer_region_count,
            released_dma_buffers: cleanup.released_dma_buffers.len() as u32,
            released_mmio_regions: cleanup.released_mmio_regions.len() as u32,
            released_irq_lines: cleanup.released_irq_lines.len() as u32,
            released_framebuffer_window_leases: display_cleanup
                .released_framebuffer_window_leases
                .len() as u32,
            revoked_device_capabilities: cleanup.revoked_device_capabilities.len() as u32,
            revoked_display_capabilities: display_cleanup.revoked_display_capabilities.len() as u32,
            smp_barrier_event: smp_barrier.validated_at_event,
            io_cleanup_completed_event: cleanup.completed_at_event,
            display_barrier_event: display_barrier.validated_at_event,
            invariant_checks,
            generation,
            state: IntegratedSnapshotIoLeaseBarrierState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn integrated_snapshot_io_lease_barriers(
        &self,
    ) -> &[IntegratedSnapshotIoLeaseBarrierRecord] {
        &self.integrated_snapshot_io_lease_barriers
    }

    pub fn integrated_snapshot_io_lease_barrier_count(&self) -> usize {
        self.integrated_snapshot_io_lease_barriers.len()
    }

    pub fn check_integrated_snapshot_io_lease_barrier_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.integrated_snapshot_io_lease_barriers {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSnapshotIoLeaseBarrierState::Recorded
                || record.smp_snapshot_barrier_generation == 0
                || record.io_cleanup_generation == 0
                || record.display_snapshot_barrier_generation == 0
                || record.driver_store_generation == 0
                || record.device_generation == 0
                || record.display_generation == 0
                || record.framebuffer_generation == 0
                || record.active_dmw_lease_count != 0
                || record.in_flight_dma_count != 0
                || record.raw_dma_binding_count != 0
                || record.raw_mmio_binding_count != 0
                || record.active_framebuffer_window_lease_count != 0
                || record.active_framebuffer_mapping_count != 0
                || record.dirty_framebuffer_region_count != 0
                || record.released_dma_buffers == 0
                || record.released_mmio_regions == 0
                || record.released_irq_lines == 0
                || record.released_framebuffer_window_leases == 0
                || record.revoked_device_capabilities == 0
                || record.revoked_display_capabilities == 0
                || record.smp_barrier_event == 0
                || record.io_cleanup_completed_event == 0
                || record.display_barrier_event == 0
                || record.invariant_checks == 0
            {
                return Err(SemanticInvariantError::IntegratedSnapshotIoLeaseBarrierInvalid {
                    integrated: record.id,
                });
            }
            for (label, id, generation, refs) in [
                (
                    "smp-snapshot-barrier",
                    record.smp_snapshot_barrier,
                    record.smp_snapshot_barrier_generation,
                    self.domains
                        .scheduler
                        .smp_snapshot_barriers
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "io-cleanup",
                    record.io_cleanup,
                    record.io_cleanup_generation,
                    self.domains
                        .io
                        .io_cleanups
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "display-snapshot-barrier",
                    record.display_snapshot_barrier,
                    record.display_snapshot_barrier_generation,
                    self.domains
                        .display
                        .display_snapshot_barriers
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
            ] {
                if id == 0
                    || generation == 0
                    || !refs.into_iter().any(|item| item == (id, generation))
                {
                    return Err(
                        SemanticInvariantError::IntegratedSnapshotIoLeaseBarrierMissingEvidence {
                            integrated: record.id,
                            evidence: label,
                        },
                    );
                }
            }
            if self
                .validate_integrated_snapshot_io_lease_barrier(
                    u64::MAX,
                    &record.scenario,
                    record.smp_snapshot_barrier,
                    record.smp_snapshot_barrier_generation,
                    record.io_cleanup,
                    record.io_cleanup_generation,
                    record.display_snapshot_barrier,
                    record.display_snapshot_barrier_generation,
                    record.invariant_checks,
                )
                .is_err()
            {
                return Err(SemanticInvariantError::IntegratedSnapshotIoLeaseBarrierInvalid {
                    integrated: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IntegratedSnapshotIoLeaseBarrierRecorded {
                            scenario,
                            integrated,
                            smp_snapshot_barrier,
                            smp_snapshot_barrier_generation,
                            io_cleanup,
                            io_cleanup_generation,
                            display_snapshot_barrier,
                            display_snapshot_barrier_generation,
                            released_dma_buffers,
                            released_mmio_regions,
                            released_irq_lines,
                            released_framebuffer_window_leases,
                            active_dmw_lease_count,
                            in_flight_dma_count,
                            active_framebuffer_window_lease_count,
                            invariant_checks,
                            generation,
                        } if scenario == &record.scenario
                            && *integrated == record.id
                            && *smp_snapshot_barrier == record.smp_snapshot_barrier
                            && *smp_snapshot_barrier_generation
                                == record.smp_snapshot_barrier_generation
                            && *io_cleanup == record.io_cleanup
                            && *io_cleanup_generation == record.io_cleanup_generation
                            && *display_snapshot_barrier == record.display_snapshot_barrier
                            && *display_snapshot_barrier_generation
                                == record.display_snapshot_barrier_generation
                            && *released_dma_buffers == record.released_dma_buffers
                            && *released_mmio_regions == record.released_mmio_regions
                            && *released_irq_lines == record.released_irq_lines
                            && *released_framebuffer_window_leases
                                == record.released_framebuffer_window_leases
                            && *active_dmw_lease_count == record.active_dmw_lease_count
                            && *in_flight_dma_count == record.in_flight_dma_count
                            && *active_framebuffer_window_lease_count
                                == record.active_framebuffer_window_lease_count
                            && *invariant_checks == record.invariant_checks
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::IntegratedSnapshotIoLeaseBarrierMissingEvent {
                    integrated: record.id,
                });
            }
        }
        Ok(())
    }
}
