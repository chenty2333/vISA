use super::*;

impl SemanticGraph {
    pub(crate) fn validate_io_wait(
        &self,
        io_wait: IoWaitId,
        wait: WaitId,
        wait_generation: Generation,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        blocker: ContractObjectRef,
    ) -> Result<(), &'static str> {
        if io_wait == 0 {
            return Err("io wait id=0 is invalid");
        }
        if self.domains.io.io_waits.iter().any(|record| record.id == io_wait) {
            return Err("io wait already exists");
        }
        let Some(wait_record) = self.domains.wait.waits.iter().find(|record| {
            record.id == wait
                && record.generation == wait_generation
                && record.state == WaitState::Pending
        }) else {
            return Err("io wait token generation is missing or not pending");
        };
        if !matches!(
            wait_record.kind,
            SemanticWaitKind::DeviceIrq | SemanticWaitKind::DriverCompletion
        ) {
            return Err("io wait kind is not an io wait kind");
        }
        if wait_record.owner_store != Some(driver_store)
            || wait_record.owner_store_generation != Some(driver_store_generation)
            || !wait_record.blockers.contains(&blocker)
        {
            return Err("io wait token does not reference the requested io blocker");
        }
        let Some(store_record) = self.domains.lifecycle.stores.iter().find(|record| {
            record.id == driver_store && record.generation == driver_store_generation
        }) else {
            return Err("io wait driver store generation is missing");
        };
        if store_record.state == StoreState::Dead || store_record.role != "driver" {
            return Err("io wait driver store is not a live driver store");
        }
        if !self.device_objects.iter().any(|record| {
            record.id == device
                && record.generation == device_generation
                && record.state == DeviceObjectState::Registered
        }) {
            return Err("io wait device generation is missing or inactive");
        }
        let Some(binding_record) = self.driver_store_bindings.iter().find(|record| {
            record.id == driver_binding
                && record.generation == driver_binding_generation
                && record.state == DriverStoreBindingState::Bound
        }) else {
            return Err("io wait driver binding generation is missing or inactive");
        };
        if binding_record.driver_store != driver_store
            || binding_record.driver_store_generation != driver_store_generation
            || binding_record.device != device
            || binding_record.device_generation != device_generation
        {
            return Err("io wait driver binding does not match wait owner/device");
        }
        if !self.io_wait_blocker_exists(blocker, device, device_generation) {
            return Err("io wait blocker generation is missing or inactive");
        }
        if self
            .domains
            .io
            .io_waits
            .iter()
            .any(|record| record.wait == wait && record.state == IoWaitState::Pending)
        {
            return Err("io wait token already has a pending io wait");
        }
        if self.check_invariants().is_err() {
            return Err("io wait requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_io_wait_with_id(
        &mut self,
        io_wait: IoWaitId,
        wait: WaitId,
        wait_generation: Generation,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        blocker: ContractObjectRef,
        note: &str,
    ) -> bool {
        if self
            .validate_io_wait(
                io_wait,
                wait,
                wait_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                blocker,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.domains.io.next_io_wait_id = self.domains.io.next_io_wait_id.max(io_wait + 1);
        let created_at_event = self.event_log.push(
            "io",
            EventKind::IoWaitCreated {
                io_wait,
                wait,
                wait_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                blocker,
                generation,
            },
        );
        self.domains.io.io_waits.push(IoWaitRecord {
            id: io_wait,
            wait,
            wait_generation,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            driver_binding,
            driver_binding_generation,
            blocker,
            generation,
            state: IoWaitState::Pending,
            created_at_event,
            completed_at_event: None,
            completion_irq_event: None,
            completion_irq_event_generation: None,
            cancel_reason: None,
            note: note.to_string(),
        });
        true
    }

    pub fn resolve_io_wait_with_irq_event(
        &mut self,
        io_wait: IoWaitId,
        io_wait_generation: Generation,
        irq_event: IrqEventId,
        irq_event_generation: Generation,
        note: &str,
    ) -> bool {
        let Some(index) = self.domains.io.io_waits.iter().position(|record| {
            record.id == io_wait
                && record.generation == io_wait_generation
                && record.state == IoWaitState::Pending
        }) else {
            return false;
        };
        let record = self.domains.io.io_waits[index].clone();
        let Some(irq_record) = self.irq_events.iter().find(|irq| {
            irq.id == irq_event
                && irq.generation == irq_event_generation
                && irq.state == IrqEventState::Recorded
        }) else {
            return false;
        };
        if irq_record.device != record.device
            || irq_record.device_generation != record.device_generation
            || irq_record.driver_store != record.driver_store
            || irq_record.driver_store_generation != record.driver_store_generation
        {
            return false;
        }
        if record.blocker.kind == ContractObjectKind::IrqLineObject
            && (record.blocker.id != irq_record.irq_line
                || record.blocker.generation != irq_record.irq_line_generation)
        {
            return false;
        }
        if !self.domains.wait.waits.iter().any(|wait| {
            wait.id == record.wait
                && wait.generation == record.wait_generation
                && wait.state == WaitState::Pending
        }) {
            return false;
        }
        self.record_wait_resolved(record.wait, "io-irq-event");
        let completed_at_event = self.event_log.push(
            "io",
            EventKind::IoWaitResolved {
                io_wait,
                wait: record.wait,
                wait_generation: record.wait_generation,
                irq_event,
                irq_event_generation,
                generation: io_wait_generation,
            },
        );
        self.domains.io.io_waits[index].state = IoWaitState::Resolved;
        self.domains.io.io_waits[index].completed_at_event = Some(completed_at_event);
        self.domains.io.io_waits[index].completion_irq_event = Some(irq_event);
        self.domains.io.io_waits[index].completion_irq_event_generation =
            Some(irq_event_generation);
        self.domains.io.io_waits[index].note = note.to_string();
        true
    }

    pub fn cancel_io_wait(
        &mut self,
        io_wait: IoWaitId,
        io_wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: &str,
    ) -> bool {
        if !matches!(
            reason,
            WaitCancelReason::DeviceFault
                | WaitCancelReason::CapabilityRevoked
                | WaitCancelReason::ResourceDropped
                | WaitCancelReason::GenerationMismatch
        ) {
            return false;
        }
        let Some(index) = self.domains.io.io_waits.iter().position(|record| {
            record.id == io_wait
                && record.generation == io_wait_generation
                && record.state == IoWaitState::Pending
        }) else {
            return false;
        };
        let record = self.domains.io.io_waits[index].clone();
        if !self.domains.wait.waits.iter().any(|wait| {
            wait.id == record.wait
                && wait.generation == record.wait_generation
                && wait.state == WaitState::Pending
        }) {
            return false;
        }
        self.record_wait_cancelled_with_reason(record.wait, errno, reason);
        let completed_at_event = self.event_log.push(
            "io",
            EventKind::IoWaitCancelled {
                io_wait,
                wait: record.wait,
                wait_generation: record.wait_generation,
                reason,
                generation: io_wait_generation,
            },
        );
        self.domains.io.io_waits[index].state = IoWaitState::Cancelled;
        self.domains.io.io_waits[index].completed_at_event = Some(completed_at_event);
        self.domains.io.io_waits[index].cancel_reason = Some(reason);
        self.domains.io.io_waits[index].note = note.to_string();
        true
    }

    pub fn io_waits(&self) -> &[IoWaitRecord] {
        &self.domains.io.io_waits
    }

    pub fn io_wait_count(&self) -> usize {
        self.domains.io.io_waits.len()
    }

    pub fn check_io_wait_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.io.io_waits {
            let Some(wait_record) =
                self.domains.wait.waits.iter().find(|wait| {
                    wait.id == record.wait && wait.generation == record.wait_generation
                })
            else {
                return Err(SemanticInvariantError::IoWaitMissingWait {
                    io_wait: record.id,
                    wait: record.wait,
                });
            };
            let Some(store_record) = self.domains.lifecycle.stores.iter().find(|store| {
                store.id == record.driver_store
                    && store.generation == record.driver_store_generation
            }) else {
                return Err(SemanticInvariantError::IoWaitMissingStore {
                    io_wait: record.id,
                    store: record.driver_store,
                });
            };
            let Some(device_record) = self.device_objects.iter().find(|device| {
                device.id == record.device && device.generation == record.device_generation
            }) else {
                return Err(SemanticInvariantError::IoWaitMissingDevice {
                    io_wait: record.id,
                    device: record.device,
                });
            };
            let Some(binding_record) = self.driver_store_bindings.iter().find(|binding| {
                binding.id == record.driver_binding
                    && binding.generation == record.driver_binding_generation
            }) else {
                return Err(SemanticInvariantError::IoWaitMissingDriverBinding {
                    io_wait: record.id,
                    binding: record.driver_binding,
                });
            };
            let pending = record.state == IoWaitState::Pending;
            let blocker_exists = if pending {
                self.io_wait_blocker_exists(record.blocker, record.device, record.device_generation)
            } else {
                self.io_wait_blocker_generation_exists(
                    record.blocker,
                    record.device,
                    record.device_generation,
                )
            };
            if !blocker_exists {
                return Err(SemanticInvariantError::IoWaitMissingBlocker {
                    io_wait: record.id,
                    blocker: record.blocker,
                });
            }
            if record.id == 0
                || record.generation == 0
                || record.wait_generation == 0
                || record.driver_store_generation == 0
                || record.device_generation == 0
                || record.driver_binding_generation == 0
                || store_record.role != "driver"
                || (pending && store_record.state == StoreState::Dead)
                || (pending && device_record.state != DeviceObjectState::Registered)
                || (pending && binding_record.state != DriverStoreBindingState::Bound)
                || (!pending
                    && !matches!(
                        binding_record.state,
                        DriverStoreBindingState::Bound | DriverStoreBindingState::Released
                    ))
                || binding_record.driver_store != record.driver_store
                || binding_record.driver_store_generation != record.driver_store_generation
                || binding_record.device != record.device
                || binding_record.device_generation != record.device_generation
                || wait_record.owner_store != Some(record.driver_store)
                || wait_record.owner_store_generation != Some(record.driver_store_generation)
                || !wait_record.blockers.contains(&record.blocker)
            {
                return Err(SemanticInvariantError::IoWaitInvalid { io_wait: record.id });
            }
            match record.state {
                IoWaitState::Pending => {
                    if wait_record.state != WaitState::Pending
                        || self.domains.io.io_waits.iter().any(|other| {
                            other.id != record.id
                                && other.wait == record.wait
                                && other.state == IoWaitState::Pending
                        })
                    {
                        return Err(SemanticInvariantError::IoWaitDuplicateWait {
                            io_wait: record.id,
                            wait: record.wait,
                        });
                    }
                }
                IoWaitState::Resolved => {
                    if !matches!(wait_record.state, WaitState::Resolved | WaitState::Consumed)
                        || record.completion_irq_event.is_none()
                        || record.completion_irq_event_generation.is_none()
                    {
                        return Err(SemanticInvariantError::IoWaitInvalid { io_wait: record.id });
                    }
                }
                IoWaitState::Cancelled => {
                    if wait_record.state != WaitState::Cancelled
                        || wait_record.cancel_reason != record.cancel_reason
                        || record.cancel_reason.is_none()
                    {
                        return Err(SemanticInvariantError::IoWaitInvalid { io_wait: record.id });
                    }
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.created_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IoWaitCreated {
                            io_wait,
                            wait,
                            wait_generation,
                            driver_store,
                            driver_store_generation,
                            device,
                            device_generation,
                            driver_binding,
                            driver_binding_generation,
                            blocker,
                            generation,
                        } if *io_wait == record.id
                            && *wait == record.wait
                            && *wait_generation == record.wait_generation
                            && *driver_store == record.driver_store
                            && *driver_store_generation == record.driver_store_generation
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *driver_binding == record.driver_binding
                            && *driver_binding_generation == record.driver_binding_generation
                            && *blocker == record.blocker
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::IoWaitMissingEvent {
                    io_wait: record.id,
                    event: record.created_at_event,
                });
            }
            if let Some(completed_at_event) = record.completed_at_event {
                let completion_found = self.event_log.events.iter().any(|event| {
                    event.id == completed_at_event
                        && match (&record.state, &event.kind) {
                            (
                                IoWaitState::Resolved,
                                EventKind::IoWaitResolved {
                                    io_wait,
                                    wait,
                                    wait_generation,
                                    irq_event,
                                    irq_event_generation,
                                    generation,
                                },
                            ) => {
                                Some(*io_wait) == Some(record.id)
                                    && *wait == record.wait
                                    && *wait_generation == record.wait_generation
                                    && Some(*irq_event) == record.completion_irq_event
                                    && Some(*irq_event_generation)
                                        == record.completion_irq_event_generation
                                    && *generation == record.generation
                            }
                            (
                                IoWaitState::Cancelled,
                                EventKind::IoWaitCancelled {
                                    io_wait,
                                    wait,
                                    wait_generation,
                                    reason,
                                    generation,
                                },
                            ) => {
                                Some(*io_wait) == Some(record.id)
                                    && *wait == record.wait
                                    && *wait_generation == record.wait_generation
                                    && Some(*reason) == record.cancel_reason
                                    && *generation == record.generation
                            }
                            _ => false,
                        }
                });
                if !completion_found {
                    return Err(SemanticInvariantError::IoWaitMissingEvent {
                        io_wait: record.id,
                        event: completed_at_event,
                    });
                }
            }
        }
        Ok(())
    }

    fn io_wait_blocker_exists(
        &self,
        blocker: ContractObjectRef,
        device: DeviceObjectId,
        device_generation: Generation,
    ) -> bool {
        match blocker.kind {
            ContractObjectKind::DeviceObject => self.device_objects.iter().any(|record| {
                record.id == blocker.id
                    && record.generation == blocker.generation
                    && record.id == device
                    && record.generation == device_generation
                    && record.state == DeviceObjectState::Registered
            }),
            ContractObjectKind::QueueObject => self.queue_objects.iter().any(|record| {
                record.id == blocker.id
                    && record.generation == blocker.generation
                    && record.device == device
                    && record.device_generation == device_generation
                    && record.state == QueueObjectState::Registered
            }),
            ContractObjectKind::IrqLineObject => self.irq_line_objects.iter().any(|record| {
                record.id == blocker.id
                    && record.generation == blocker.generation
                    && record.device == device
                    && record.device_generation == device_generation
                    && record.state == IrqLineObjectState::Registered
            }),
            ContractObjectKind::DmaBufferObject => self.dma_buffer_objects.iter().any(|record| {
                if record.id != blocker.id
                    || record.generation != blocker.generation
                    || record.state != DmaBufferObjectState::Registered
                {
                    return false;
                }
                let Some(descriptor) = self.descriptor_objects.iter().find(|descriptor| {
                    descriptor.id == record.descriptor
                        && descriptor.generation == record.descriptor_generation
                        && descriptor.state == DescriptorObjectState::Registered
                }) else {
                    return false;
                };
                self.queue_objects.iter().any(|queue| {
                    queue.id == descriptor.queue
                        && queue.generation == descriptor.queue_generation
                        && queue.device == device
                        && queue.device_generation == device_generation
                        && queue.state == QueueObjectState::Registered
                })
            }),
            ContractObjectKind::MmioRegionObject => self.mmio_region_objects.iter().any(|record| {
                record.id == blocker.id
                    && record.generation == blocker.generation
                    && record.device == device
                    && record.device_generation == device_generation
                    && record.state == MmioRegionObjectState::Registered
            }),
            ContractObjectKind::PacketQueueObject => {
                self.packet_queue_objects.iter().any(|record| {
                    if record.id != blocker.id
                        || record.generation != blocker.generation
                        || record.state != PacketQueueObjectState::Registered
                    {
                        return false;
                    }
                    self.packet_device_objects.iter().any(|packet_device| {
                        packet_device.id == record.packet_device
                            && packet_device.generation == record.packet_device_generation
                            && packet_device.device == device
                            && packet_device.device_generation == device_generation
                            && packet_device.state == PacketDeviceObjectState::Registered
                    })
                })
            }
            _ => false,
        }
    }

    fn io_wait_blocker_generation_exists(
        &self,
        blocker: ContractObjectRef,
        device: DeviceObjectId,
        device_generation: Generation,
    ) -> bool {
        match blocker.kind {
            ContractObjectKind::DeviceObject => self.device_objects.iter().any(|record| {
                record.id == blocker.id
                    && record.generation == blocker.generation
                    && record.id == device
                    && record.generation == device_generation
            }),
            ContractObjectKind::QueueObject => self.queue_objects.iter().any(|record| {
                record.id == blocker.id
                    && record.generation == blocker.generation
                    && record.device == device
                    && record.device_generation == device_generation
            }),
            ContractObjectKind::IrqLineObject => self.irq_line_objects.iter().any(|record| {
                record.id == blocker.id
                    && record.generation == blocker.generation
                    && record.device == device
                    && record.device_generation == device_generation
            }),
            ContractObjectKind::DmaBufferObject => self.io_cleanup_dma_buffer_belongs_to_device(
                blocker.id,
                blocker.generation,
                device,
                device_generation,
            ),
            ContractObjectKind::MmioRegionObject => self.mmio_region_objects.iter().any(|record| {
                record.id == blocker.id
                    && record.generation == blocker.generation
                    && record.device == device
                    && record.device_generation == device_generation
            }),
            ContractObjectKind::PacketQueueObject => {
                self.packet_queue_objects.iter().any(|record| {
                    if record.id != blocker.id || record.generation != blocker.generation {
                        return false;
                    }
                    self.packet_device_objects.iter().any(|packet_device| {
                        packet_device.id == record.packet_device
                            && packet_device.generation == record.packet_device_generation
                            && packet_device.device == device
                            && packet_device.device_generation == device_generation
                    })
                })
            }
            _ => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_io_wait_blocker_generation_for_test(
        &mut self,
        io_wait: IoWaitId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.domains.io.io_waits.iter_mut().find(|record| record.id == io_wait)
        {
            record.blocker.generation = generation;
        }
    }
}
