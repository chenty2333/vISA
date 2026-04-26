use super::*;

impl SemanticGraph {
    pub(crate) fn validate_io_cleanup(
        &self,
        cleanup: IoCleanupId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        reason: &str,
    ) -> Result<(), &'static str> {
        if cleanup == 0 {
            return Err("io cleanup id=0 is invalid");
        }
        if reason.is_empty() {
            return Err("io cleanup reason is empty");
        }
        if self.io_cleanups.iter().any(|record| {
            record.id == cleanup
                && (record.driver_store != driver_store
                    || record.driver_store_generation != driver_store_generation
                    || record.device != device
                    || record.device_generation != device_generation
                    || record.driver_binding != driver_binding
                    || record.driver_binding_generation != driver_binding_generation)
        }) {
            return Err("io cleanup id is already used for a different target");
        }
        if self.io_cleanups.iter().any(|record| {
            record.driver_store == driver_store
                && record.driver_store_generation == driver_store_generation
                && record.device == device
                && record.device_generation == device_generation
                && record.driver_binding == driver_binding
                && record.driver_binding_generation == driver_binding_generation
                && record.state == IoCleanupState::Completed
        }) {
            return Ok(());
        }
        let Some(store) = self.stores.iter().find(|record| {
            record.id == driver_store && record.generation == driver_store_generation
        }) else {
            return Err("io cleanup driver store generation is missing");
        };
        if store.role != "driver" {
            return Err("io cleanup store role is not driver");
        }
        if !self.device_objects.iter().any(|record| {
            record.id == device
                && record.generation == device_generation
                && record.state == DeviceObjectState::Registered
        }) {
            return Err("io cleanup device generation is missing or inactive");
        }
        let Some(binding) = self.driver_store_bindings.iter().find(|record| {
            record.id == driver_binding && record.generation == driver_binding_generation
        }) else {
            return Err("io cleanup driver binding generation is missing");
        };
        if binding.state != DriverStoreBindingState::Bound
            || binding.driver_store != driver_store
            || binding.driver_store_generation != driver_store_generation
            || binding.device != device
            || binding.device_generation != device_generation
        {
            return Err("io cleanup driver binding is not bound to target");
        }
        if self.check_invariants().is_err() {
            return Err("io cleanup requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn cleanup_io_driver_for_device_fault_with_id(
        &mut self,
        cleanup: IoCleanupId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_io_cleanup(
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                reason,
            )
            .is_err()
        {
            return false;
        }
        if self.io_cleanups.iter().any(|record| {
            record.id == cleanup
                && record.driver_store == driver_store
                && record.driver_store_generation == driver_store_generation
                && record.device == device
                && record.device_generation == device_generation
                && record.driver_binding == driver_binding
                && record.driver_binding_generation == driver_binding_generation
                && record.state == IoCleanupState::Completed
        }) {
            return true;
        }

        let generation = 1;
        self.next_io_cleanup_id = self.next_io_cleanup_id.max(cleanup + 1);
        let started_at_event = self.event_log.push(
            "io",
            EventKind::IoCleanupStarted {
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                generation,
            },
        );

        let store_ref = ContractObjectRef::new(
            ContractObjectKind::Store,
            driver_store,
            driver_store_generation,
        );
        let device_ref =
            ContractObjectRef::new(ContractObjectKind::DeviceObject, device, device_generation);
        let binding_ref = ContractObjectRef::new(
            ContractObjectKind::DriverStoreBinding,
            driver_binding,
            driver_binding_generation,
        );

        let pending_io_waits = self
            .io_waits
            .iter()
            .filter(|record| {
                record.driver_store == driver_store
                    && record.driver_store_generation == driver_store_generation
                    && record.device == device
                    && record.device_generation == device_generation
                    && record.driver_binding == driver_binding
                    && record.driver_binding_generation == driver_binding_generation
                    && record.state == IoWaitState::Pending
            })
            .map(|record| (record.id, record.generation, record.object_ref()))
            .collect::<Vec<_>>();
        let mut cancelled_io_waits = Vec::new();
        for (io_wait, io_wait_generation, io_wait_ref) in pending_io_waits {
            if self.cancel_io_wait(
                io_wait,
                io_wait_generation,
                5,
                WaitCancelReason::DeviceFault,
                "io cleanup cancelled pending wait",
            ) {
                cancelled_io_waits.push(io_wait_ref);
            }
        }
        let cancel_event = self.event_log.cursor();
        let mut steps = Vec::new();
        steps.push(IoCleanupStepRecord {
            kind: IoCleanupStepKind::CancelIoWaits,
            target: store_ref,
            observed_generation: driver_store_generation,
            status: if cancelled_io_waits.is_empty() {
                IoCleanupStepStatus::SkippedNotPresent
            } else {
                IoCleanupStepStatus::Done
            },
            event: Some(cancel_event),
        });

        let capability_targets = self
            .device_capabilities
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                record.driver_store == driver_store
                    && record.driver_store_generation == driver_store_generation
                    && record.state == DeviceCapabilityState::Active
                    && self.io_cleanup_device_capability_belongs_to_device(
                        record,
                        device,
                        device_generation,
                    )
            })
            .map(|(index, record)| {
                (
                    index,
                    record.id,
                    record.generation,
                    record.capability,
                    record.capability_generation,
                )
            })
            .collect::<Vec<_>>();
        let mut revoked_device_capabilities = Vec::new();
        let mut revoked_capabilities = Vec::new();
        for (index, device_capability, device_capability_generation, cap, cap_generation) in
            capability_targets
        {
            if self.capabilities.revoke_generation(cap, cap_generation) {
                self.event_log
                    .push("capability", EventKind::CapabilityRevoked { cap });
                self.device_capabilities[index].state = DeviceCapabilityState::Revoked;
                revoked_device_capabilities.push(ContractObjectRef::new(
                    ContractObjectKind::DeviceCapability,
                    device_capability,
                    device_capability_generation,
                ));
                revoked_capabilities.push(ContractObjectRef::new(
                    ContractObjectKind::Capability,
                    cap,
                    cap_generation,
                ));
            }
        }
        let revoke_event = self.event_log.cursor();
        steps.push(IoCleanupStepRecord {
            kind: IoCleanupStepKind::RevokeDeviceCapabilities,
            target: store_ref,
            observed_generation: driver_store_generation,
            status: if revoked_device_capabilities.is_empty() {
                IoCleanupStepStatus::SkippedNotPresent
            } else {
                IoCleanupStepStatus::Done
            },
            event: Some(revoke_event),
        });

        let released_binding = if let Some(record) =
            self.driver_store_bindings.iter_mut().find(|record| {
                record.id == driver_binding
                    && record.generation == driver_binding_generation
                    && record.state == DriverStoreBindingState::Bound
            }) {
            record.state = DriverStoreBindingState::Released;
            true
        } else {
            false
        };
        steps.push(IoCleanupStepRecord {
            kind: IoCleanupStepKind::ReleaseDriverBinding,
            target: binding_ref,
            observed_generation: driver_binding_generation,
            status: if released_binding {
                IoCleanupStepStatus::Done
            } else {
                IoCleanupStepStatus::SkippedStaleGeneration
            },
            event: Some(self.event_log.cursor()),
        });

        let mut released_dma_buffers = Vec::new();
        for index in 0..self.dma_buffer_objects.len() {
            let dma_ref = self.dma_buffer_objects[index].object_ref();
            if self.dma_buffer_objects[index].state == DmaBufferObjectState::Registered
                && self.io_cleanup_dma_buffer_belongs_to_device(
                    self.dma_buffer_objects[index].id,
                    self.dma_buffer_objects[index].generation,
                    device,
                    device_generation,
                )
            {
                self.dma_buffer_objects[index].state = DmaBufferObjectState::Released;
                released_dma_buffers.push(dma_ref);
            }
        }
        steps.push(IoCleanupStepRecord {
            kind: IoCleanupStepKind::ReleaseDmaBuffers,
            target: device_ref,
            observed_generation: device_generation,
            status: if released_dma_buffers.is_empty() {
                IoCleanupStepStatus::SkippedNotPresent
            } else {
                IoCleanupStepStatus::Done
            },
            event: Some(self.event_log.cursor()),
        });

        let mut released_mmio_regions = Vec::new();
        for record in &mut self.mmio_region_objects {
            if record.device == device
                && record.device_generation == device_generation
                && record.state == MmioRegionObjectState::Registered
            {
                released_mmio_regions.push(record.object_ref());
                record.state = MmioRegionObjectState::Released;
            }
        }
        steps.push(IoCleanupStepRecord {
            kind: IoCleanupStepKind::ReleaseMmioRegions,
            target: device_ref,
            observed_generation: device_generation,
            status: if released_mmio_regions.is_empty() {
                IoCleanupStepStatus::SkippedNotPresent
            } else {
                IoCleanupStepStatus::Done
            },
            event: Some(self.event_log.cursor()),
        });

        let mut released_irq_lines = Vec::new();
        for record in &mut self.irq_line_objects {
            if record.device == device
                && record.device_generation == device_generation
                && record.state == IrqLineObjectState::Registered
            {
                released_irq_lines.push(record.object_ref());
                record.state = IrqLineObjectState::Released;
            }
        }
        steps.push(IoCleanupStepRecord {
            kind: IoCleanupStepKind::ReleaseIrqLines,
            target: device_ref,
            observed_generation: device_generation,
            status: if released_irq_lines.is_empty() {
                IoCleanupStepStatus::SkippedNotPresent
            } else {
                IoCleanupStepStatus::Done
            },
            event: Some(self.event_log.cursor()),
        });

        let completed_at_event = self.event_log.push(
            "io",
            EventKind::IoCleanupCompleted {
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                cancelled_io_waits: cancelled_io_waits.len(),
                revoked_device_capabilities: revoked_device_capabilities.len(),
                released_dma_buffers: released_dma_buffers.len(),
                released_mmio_regions: released_mmio_regions.len(),
                released_irq_lines: released_irq_lines.len(),
                generation,
            },
        );

        self.io_cleanups.push(IoCleanupRecord {
            id: cleanup,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            driver_binding,
            driver_binding_generation,
            generation,
            state: IoCleanupState::Completed,
            reason: reason.to_string(),
            started_at_event,
            completed_at_event,
            cancelled_io_waits,
            revoked_device_capabilities,
            revoked_capabilities,
            released_dma_buffers,
            released_mmio_regions,
            released_irq_lines,
            steps,
            note: note.to_string(),
        });
        self.check_invariants().is_ok()
    }

    pub fn io_cleanups(&self) -> &[IoCleanupRecord] {
        &self.io_cleanups
    }

    pub fn io_cleanup_count(&self) -> usize {
        self.io_cleanups.len()
    }

    pub(crate) fn io_cleanup_device_capability_belongs_to_device(
        &self,
        capability: &DeviceCapabilityRecord,
        device: DeviceObjectId,
        device_generation: Generation,
    ) -> bool {
        match capability.target.kind {
            ContractObjectKind::DeviceObject => {
                capability.target.id == device && capability.target.generation == device_generation
            }
            ContractObjectKind::MmioRegionObject => self.mmio_region_objects.iter().any(|record| {
                record.object_ref() == capability.target
                    && record.device == device
                    && record.device_generation == device_generation
            }),
            ContractObjectKind::IrqLineObject => self.irq_line_objects.iter().any(|record| {
                record.object_ref() == capability.target
                    && record.device == device
                    && record.device_generation == device_generation
            }),
            ContractObjectKind::DmaBufferObject => self.io_cleanup_dma_buffer_belongs_to_device(
                capability.target.id,
                capability.target.generation,
                device,
                device_generation,
            ),
            _ => false,
        }
    }

    pub(crate) fn io_cleanup_dma_buffer_belongs_to_device(
        &self,
        dma_buffer: DmaBufferObjectId,
        dma_buffer_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
    ) -> bool {
        let Some(dma_buffer) = self
            .dma_buffer_objects
            .iter()
            .find(|record| record.id == dma_buffer && record.generation == dma_buffer_generation)
        else {
            return false;
        };
        let Some(descriptor) = self.descriptor_objects.iter().find(|descriptor| {
            descriptor.id == dma_buffer.descriptor
                && descriptor.generation == dma_buffer.descriptor_generation
        }) else {
            return false;
        };
        self.queue_objects.iter().any(|queue| {
            queue.id == descriptor.queue
                && queue.generation == descriptor.queue_generation
                && queue.device == device
                && queue.device_generation == device_generation
        })
    }

    pub fn check_io_cleanup_invariants(&self) -> Result<(), SemanticInvariantError> {
        for cleanup in &self.io_cleanups {
            if cleanup.id == 0
                || cleanup.generation == 0
                || cleanup.driver_store_generation == 0
                || cleanup.device_generation == 0
                || cleanup.driver_binding_generation == 0
                || cleanup.reason.is_empty()
                || cleanup.state != IoCleanupState::Completed
            {
                return Err(SemanticInvariantError::IoCleanupInvalid {
                    cleanup: cleanup.id,
                });
            }
            if !self.stores.iter().any(|store| {
                store.id == cleanup.driver_store
                    && store.generation == cleanup.driver_store_generation
                    && store.role == "driver"
            }) {
                return Err(SemanticInvariantError::IoCleanupMissingStore {
                    cleanup: cleanup.id,
                    store: cleanup.driver_store,
                });
            }
            if !self.device_objects.iter().any(|device| {
                device.id == cleanup.device && device.generation == cleanup.device_generation
            }) {
                return Err(SemanticInvariantError::IoCleanupMissingDevice {
                    cleanup: cleanup.id,
                    device: cleanup.device,
                });
            }
            let Some(binding) = self.driver_store_bindings.iter().find(|binding| {
                binding.id == cleanup.driver_binding
                    && binding.generation == cleanup.driver_binding_generation
            }) else {
                return Err(SemanticInvariantError::IoCleanupMissingDriverBinding {
                    cleanup: cleanup.id,
                    binding: cleanup.driver_binding,
                });
            };
            if binding.state != DriverStoreBindingState::Released
                || binding.driver_store != cleanup.driver_store
                || binding.driver_store_generation != cleanup.driver_store_generation
                || binding.device != cleanup.device
                || binding.device_generation != cleanup.device_generation
            {
                return Err(SemanticInvariantError::IoCleanupInvalid {
                    cleanup: cleanup.id,
                });
            }
            for io_wait in &cleanup.cancelled_io_waits {
                let Some(record) = self.io_waits.iter().find(|record| {
                    record.id == io_wait.id && record.generation == io_wait.generation
                }) else {
                    return Err(SemanticInvariantError::IoCleanupMissingEffectTarget {
                        cleanup: cleanup.id,
                        target: *io_wait,
                    });
                };
                if record.state != IoWaitState::Cancelled
                    || record.cancel_reason != Some(WaitCancelReason::DeviceFault)
                {
                    return Err(SemanticInvariantError::IoCleanupInvalid {
                        cleanup: cleanup.id,
                    });
                }
            }
            for device_capability in &cleanup.revoked_device_capabilities {
                let Some(record) = self.device_capabilities.iter().find(|record| {
                    record.id == device_capability.id
                        && record.generation == device_capability.generation
                }) else {
                    return Err(SemanticInvariantError::IoCleanupMissingEffectTarget {
                        cleanup: cleanup.id,
                        target: *device_capability,
                    });
                };
                if record.state != DeviceCapabilityState::Revoked {
                    return Err(SemanticInvariantError::IoCleanupInvalid {
                        cleanup: cleanup.id,
                    });
                }
            }
            for capability in &cleanup.revoked_capabilities {
                let Some(record) = self.capabilities.record(capability.id) else {
                    return Err(SemanticInvariantError::IoCleanupMissingEffectTarget {
                        cleanup: cleanup.id,
                        target: *capability,
                    });
                };
                if !record.revoked || record.generation <= capability.generation {
                    return Err(SemanticInvariantError::IoCleanupInvalid {
                        cleanup: cleanup.id,
                    });
                }
            }
            for dma_buffer in &cleanup.released_dma_buffers {
                if !self.dma_buffer_objects.iter().any(|record| {
                    record.id == dma_buffer.id
                        && record.generation == dma_buffer.generation
                        && record.state == DmaBufferObjectState::Released
                }) {
                    return Err(SemanticInvariantError::IoCleanupMissingEffectTarget {
                        cleanup: cleanup.id,
                        target: *dma_buffer,
                    });
                }
            }
            for mmio_region in &cleanup.released_mmio_regions {
                if !self.mmio_region_objects.iter().any(|record| {
                    record.id == mmio_region.id
                        && record.generation == mmio_region.generation
                        && record.state == MmioRegionObjectState::Released
                }) {
                    return Err(SemanticInvariantError::IoCleanupMissingEffectTarget {
                        cleanup: cleanup.id,
                        target: *mmio_region,
                    });
                }
            }
            for irq_line in &cleanup.released_irq_lines {
                if !self.irq_line_objects.iter().any(|record| {
                    record.id == irq_line.id
                        && record.generation == irq_line.generation
                        && record.state == IrqLineObjectState::Released
                }) {
                    return Err(SemanticInvariantError::IoCleanupMissingEffectTarget {
                        cleanup: cleanup.id,
                        target: *irq_line,
                    });
                }
            }
            let expected_steps = [
                (
                    IoCleanupStepKind::CancelIoWaits,
                    ContractObjectKind::Store,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                ),
                (
                    IoCleanupStepKind::RevokeDeviceCapabilities,
                    ContractObjectKind::Store,
                    cleanup.driver_store,
                    cleanup.driver_store_generation,
                ),
                (
                    IoCleanupStepKind::ReleaseDriverBinding,
                    ContractObjectKind::DriverStoreBinding,
                    cleanup.driver_binding,
                    cleanup.driver_binding_generation,
                ),
                (
                    IoCleanupStepKind::ReleaseDmaBuffers,
                    ContractObjectKind::DeviceObject,
                    cleanup.device,
                    cleanup.device_generation,
                ),
                (
                    IoCleanupStepKind::ReleaseMmioRegions,
                    ContractObjectKind::DeviceObject,
                    cleanup.device,
                    cleanup.device_generation,
                ),
                (
                    IoCleanupStepKind::ReleaseIrqLines,
                    ContractObjectKind::DeviceObject,
                    cleanup.device,
                    cleanup.device_generation,
                ),
            ];
            if cleanup.steps.len() != expected_steps.len() {
                return Err(SemanticInvariantError::IoCleanupInvalid {
                    cleanup: cleanup.id,
                });
            }
            for (step, (expected_kind, expected_target_kind, expected_id, expected_generation)) in
                cleanup.steps.iter().zip(expected_steps)
            {
                if step.kind != expected_kind
                    || step.target.kind != expected_target_kind
                    || step.target.id != expected_id
                    || step.observed_generation != expected_generation
                    || step.target.generation != expected_generation
                    || step.event.is_none()
                {
                    return Err(SemanticInvariantError::IoCleanupInvalid {
                        cleanup: cleanup.id,
                    });
                }
            }
            if self.io_waits.iter().any(|record| {
                record.driver_store == cleanup.driver_store
                    && record.driver_store_generation == cleanup.driver_store_generation
                    && record.device == cleanup.device
                    && record.device_generation == cleanup.device_generation
                    && record.driver_binding == cleanup.driver_binding
                    && record.driver_binding_generation == cleanup.driver_binding_generation
                    && record.state == IoWaitState::Pending
            }) || self.device_capabilities.iter().any(|record| {
                record.driver_store == cleanup.driver_store
                    && record.driver_store_generation == cleanup.driver_store_generation
                    && record.state == DeviceCapabilityState::Active
                    && self.io_cleanup_device_capability_belongs_to_device(
                        record,
                        cleanup.device,
                        cleanup.device_generation,
                    )
            }) || self.driver_store_bindings.iter().any(|record| {
                record.id == cleanup.driver_binding
                    && record.generation == cleanup.driver_binding_generation
                    && record.state == DriverStoreBindingState::Bound
            }) || self.dma_buffer_objects.iter().any(|record| {
                record.state == DmaBufferObjectState::Registered
                    && self.io_cleanup_dma_buffer_belongs_to_device(
                        record.id,
                        record.generation,
                        cleanup.device,
                        cleanup.device_generation,
                    )
            }) || self.mmio_region_objects.iter().any(|record| {
                record.device == cleanup.device
                    && record.device_generation == cleanup.device_generation
                    && record.state == MmioRegionObjectState::Registered
            }) || self.irq_line_objects.iter().any(|record| {
                record.device == cleanup.device
                    && record.device_generation == cleanup.device_generation
                    && record.state == IrqLineObjectState::Registered
            }) {
                return Err(SemanticInvariantError::IoCleanupLiveLeak {
                    cleanup: cleanup.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == cleanup.started_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IoCleanupStarted {
                            cleanup: id,
                            driver_store,
                            driver_store_generation,
                            device,
                            device_generation,
                            driver_binding,
                            driver_binding_generation,
                            generation,
                        } if *id == cleanup.id
                            && *driver_store == cleanup.driver_store
                            && *driver_store_generation == cleanup.driver_store_generation
                            && *device == cleanup.device
                            && *device_generation == cleanup.device_generation
                            && *driver_binding == cleanup.driver_binding
                            && *driver_binding_generation == cleanup.driver_binding_generation
                            && *generation == cleanup.generation
                    )
            }) || !self.event_log.events.iter().any(|event| {
                event.id == cleanup.completed_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IoCleanupCompleted {
                            cleanup: id,
                            driver_store,
                            driver_store_generation,
                            device,
                            device_generation,
                            driver_binding,
                            driver_binding_generation,
                            cancelled_io_waits,
                            revoked_device_capabilities,
                            released_dma_buffers,
                            released_mmio_regions,
                            released_irq_lines,
                            generation,
                        } if *id == cleanup.id
                            && *driver_store == cleanup.driver_store
                            && *driver_store_generation == cleanup.driver_store_generation
                            && *device == cleanup.device
                            && *device_generation == cleanup.device_generation
                            && *driver_binding == cleanup.driver_binding
                            && *driver_binding_generation == cleanup.driver_binding_generation
                            && *cancelled_io_waits == cleanup.cancelled_io_waits.len()
                            && *revoked_device_capabilities == cleanup.revoked_device_capabilities.len()
                            && *released_dma_buffers == cleanup.released_dma_buffers.len()
                            && *released_mmio_regions == cleanup.released_mmio_regions.len()
                            && *released_irq_lines == cleanup.released_irq_lines.len()
                            && *generation == cleanup.generation
                    )
            }) {
                return Err(SemanticInvariantError::IoCleanupMissingEvent {
                    cleanup: cleanup.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_io_cleanup_cancelled_wait_for_test(
        &mut self,
        cleanup: IoCleanupId,
        io_wait: IoWaitId,
    ) {
        if let Some(record) = self.io_waits.iter_mut().find(|record| record.id == io_wait) {
            record.state = IoWaitState::Pending;
            record.cancel_reason = None;
        }
        if let Some(cleanup) = self
            .io_cleanups
            .iter_mut()
            .find(|record| record.id == cleanup)
        {
            cleanup.state = IoCleanupState::Completed;
        }
    }
}
