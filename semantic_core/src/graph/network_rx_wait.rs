use super::*;

impl SemanticGraph {
    pub(crate) fn validate_network_rx_wait_resolution(
        &self,
        resolution: NetworkRxWaitResolutionId,
        io_wait: IoWaitId,
        io_wait_generation: Generation,
        rx_interrupt: NetworkRxInterruptId,
        rx_interrupt_generation: Generation,
    ) -> Result<(), &'static str> {
        if resolution == 0 {
            return Err("network rx wait resolution id=0 is invalid");
        }
        if self
            .network_rx_wait_resolutions
            .iter()
            .any(|record| record.id == resolution)
        {
            return Err("network rx wait resolution already exists");
        }
        let Some(rx_record) = self.network_rx_interrupts.iter().find(|record| {
            record.id == rx_interrupt
                && record.generation == rx_interrupt_generation
                && record.state == NetworkRxInterruptState::Recorded
        }) else {
            return Err("network rx wait interrupt generation is missing or inactive");
        };
        let Some(io_wait_record) = self.io_waits.iter().find(|record| {
            record.id == io_wait
                && record.generation == io_wait_generation
                && record.state == IoWaitState::Pending
        }) else {
            return Err("network rx wait io wait generation is missing or not pending");
        };
        let Some(wait_record) = self.waits.iter().find(|record| {
            record.id == io_wait_record.wait
                && record.generation == io_wait_record.wait_generation
                && record.state == WaitState::Pending
        }) else {
            return Err("network rx wait token generation is missing or not pending");
        };
        let Some(backend_record) = self.virtio_net_backends.iter().find(|record| {
            record.id == rx_record.virtio_net_backend
                && record.generation == rx_record.virtio_net_backend_generation
                && record.state == VirtioNetBackendObjectState::SkeletonReady
        }) else {
            return Err("network rx wait backend generation is missing or inactive");
        };
        let Some(binding_record) = self.driver_store_bindings.iter().find(|record| {
            record.id == backend_record.driver_binding
                && record.generation == backend_record.driver_binding_generation
                && record.state == DriverStoreBindingState::Bound
        }) else {
            return Err("network rx wait backend driver binding is missing or inactive");
        };
        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == rx_record.packet_device
                && record.generation == rx_record.packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err("network rx wait packet device generation is missing or inactive");
        };
        let Some(rx_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == rx_record.rx_queue
                && record.generation == rx_record.rx_queue_generation
                && record.state == PacketQueueObjectState::Registered
                && record.role == PacketQueueRole::Rx
        }) else {
            return Err("network rx wait rx queue generation is missing or inactive");
        };
        let Some(irq_record) = self.irq_events.iter().find(|record| {
            record.id == rx_record.irq_event
                && record.generation == rx_record.irq_event_generation
                && record.state == IrqEventState::Recorded
        }) else {
            return Err("network rx wait irq event generation is missing or inactive");
        };
        let rx_queue_ref = ContractObjectRef::new(
            ContractObjectKind::PacketQueueObject,
            rx_queue_record.id,
            rx_queue_record.generation,
        );
        if io_wait_record.blocker != rx_queue_ref || !wait_record.blockers.contains(&rx_queue_ref) {
            return Err("network rx wait blocker must be the rx packet queue");
        }
        if packet_device_record.device != io_wait_record.device
            || packet_device_record.device_generation != io_wait_record.device_generation
            || binding_record.driver_store != io_wait_record.driver_store
            || binding_record.driver_store_generation != io_wait_record.driver_store_generation
            || binding_record.device != io_wait_record.device
            || binding_record.device_generation != io_wait_record.device_generation
            || irq_record.device != io_wait_record.device
            || irq_record.device_generation != io_wait_record.device_generation
            || irq_record.driver_store != io_wait_record.driver_store
            || irq_record.driver_store_generation != io_wait_record.driver_store_generation
            || rx_queue_record.packet_device != packet_device_record.id
            || rx_queue_record.packet_device_generation != packet_device_record.generation
        {
            return Err("network rx wait interrupt attribution mismatch");
        }
        if self.network_rx_wait_resolutions.iter().any(|record| {
            record.io_wait == io_wait_record.id
                && record.io_wait_generation == io_wait_record.generation
                && record.state == NetworkRxWaitResolutionState::Resolved
        }) {
            return Err("network rx wait io wait already has a resolution");
        }
        if self.check_invariants().is_err() {
            return Err("network rx wait requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn resolve_network_rx_wait_with_id(
        &mut self,
        resolution: NetworkRxWaitResolutionId,
        io_wait: IoWaitId,
        io_wait_generation: Generation,
        rx_interrupt: NetworkRxInterruptId,
        rx_interrupt_generation: Generation,
        note: &str,
    ) -> bool {
        if self
            .validate_network_rx_wait_resolution(
                resolution,
                io_wait,
                io_wait_generation,
                rx_interrupt,
                rx_interrupt_generation,
            )
            .is_err()
        {
            return false;
        }
        let Some(rx_record) = self
            .network_rx_interrupts
            .iter()
            .find(|record| {
                record.id == rx_interrupt && record.generation == rx_interrupt_generation
            })
            .cloned()
        else {
            return false;
        };
        let Some(io_wait_record) = self
            .io_waits
            .iter()
            .find(|record| record.id == io_wait && record.generation == io_wait_generation)
            .cloned()
        else {
            return false;
        };
        if !self.resolve_io_wait_with_irq_event(
            io_wait,
            io_wait_generation,
            rx_record.irq_event,
            rx_record.irq_event_generation,
            note,
        ) {
            return false;
        }
        let generation = 1;
        self.next_network_rx_wait_resolution_id =
            self.next_network_rx_wait_resolution_id.max(resolution + 1);
        let resolved_at_event = self.event_log.push(
            "network",
            EventKind::NetworkRxWaitResolved {
                resolution,
                io_wait,
                io_wait_generation,
                wait: io_wait_record.wait,
                wait_generation: io_wait_record.wait_generation,
                rx_interrupt,
                rx_interrupt_generation,
                rx_queue: rx_record.rx_queue,
                rx_queue_generation: rx_record.rx_queue_generation,
                ready_descriptors: rx_record.ready_descriptors,
                generation,
            },
        );
        self.network_rx_wait_resolutions
            .push(NetworkRxWaitResolutionRecord {
                id: resolution,
                io_wait,
                io_wait_generation,
                wait: io_wait_record.wait,
                wait_generation: io_wait_record.wait_generation,
                rx_interrupt,
                rx_interrupt_generation,
                irq_event: rx_record.irq_event,
                irq_event_generation: rx_record.irq_event_generation,
                packet_device: rx_record.packet_device,
                packet_device_generation: rx_record.packet_device_generation,
                rx_queue: rx_record.rx_queue,
                rx_queue_generation: rx_record.rx_queue_generation,
                ready_descriptors: rx_record.ready_descriptors,
                sequence: rx_record.sequence,
                generation,
                state: NetworkRxWaitResolutionState::Resolved,
                resolved_at_event,
                note: note.to_string(),
            });
        true
    }

    pub fn network_rx_wait_resolutions(&self) -> &[NetworkRxWaitResolutionRecord] {
        &self.network_rx_wait_resolutions
    }

    pub fn network_rx_wait_resolution_count(&self) -> usize {
        self.network_rx_wait_resolutions.len()
    }

    pub fn check_network_rx_wait_resolution_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.network_rx_wait_resolutions {
            let Some(io_wait_record) = self.io_waits.iter().find(|io_wait| {
                io_wait.id == record.io_wait && io_wait.generation == record.io_wait_generation
            }) else {
                return Err(
                    SemanticInvariantError::NetworkRxWaitResolutionMissingIoWait {
                        resolution: record.id,
                        io_wait: record.io_wait,
                    },
                );
            };
            let Some(wait_record) = self
                .waits
                .iter()
                .find(|wait| wait.id == record.wait && wait.generation == record.wait_generation)
            else {
                return Err(SemanticInvariantError::NetworkRxWaitResolutionInvalid {
                    resolution: record.id,
                });
            };
            let Some(rx_record) = self.network_rx_interrupts.iter().find(|rx_interrupt| {
                rx_interrupt.id == record.rx_interrupt
                    && rx_interrupt.generation == record.rx_interrupt_generation
            }) else {
                return Err(
                    SemanticInvariantError::NetworkRxWaitResolutionMissingInterrupt {
                        resolution: record.id,
                        rx_interrupt: record.rx_interrupt,
                    },
                );
            };
            let Some(rx_queue_record) = self.packet_queue_objects.iter().find(|rx_queue| {
                rx_queue.id == record.rx_queue && rx_queue.generation == record.rx_queue_generation
            }) else {
                return Err(
                    SemanticInvariantError::NetworkRxWaitResolutionMissingRxQueue {
                        resolution: record.id,
                        rx_queue: record.rx_queue,
                    },
                );
            };
            let rx_queue_ref = ContractObjectRef::new(
                ContractObjectKind::PacketQueueObject,
                record.rx_queue,
                record.rx_queue_generation,
            );
            if record.id == 0
                || record.generation == 0
                || record.io_wait_generation == 0
                || record.wait_generation == 0
                || record.rx_interrupt_generation == 0
                || record.irq_event_generation == 0
                || record.packet_device_generation == 0
                || record.rx_queue_generation == 0
                || record.ready_descriptors == 0
                || record.sequence == 0
                || record.state != NetworkRxWaitResolutionState::Resolved
                || io_wait_record.state != IoWaitState::Resolved
                || io_wait_record.wait != record.wait
                || io_wait_record.wait_generation != record.wait_generation
                || io_wait_record.blocker != rx_queue_ref
                || io_wait_record.completion_irq_event != Some(record.irq_event)
                || io_wait_record.completion_irq_event_generation
                    != Some(record.irq_event_generation)
                || !matches!(wait_record.state, WaitState::Resolved | WaitState::Consumed)
                || rx_record.state != NetworkRxInterruptState::Recorded
                || rx_record.irq_event != record.irq_event
                || rx_record.irq_event_generation != record.irq_event_generation
                || rx_record.packet_device != record.packet_device
                || rx_record.packet_device_generation != record.packet_device_generation
                || rx_record.rx_queue != record.rx_queue
                || rx_record.rx_queue_generation != record.rx_queue_generation
                || rx_record.ready_descriptors != record.ready_descriptors
                || rx_record.sequence != record.sequence
                || rx_queue_record.role != PacketQueueRole::Rx
                || rx_queue_record.state != PacketQueueObjectState::Registered
            {
                return Err(SemanticInvariantError::NetworkRxWaitResolutionInvalid {
                    resolution: record.id,
                });
            }
            if let Some(duplicate) = self.network_rx_wait_resolutions.iter().find(|other| {
                other.id != record.id
                    && other.io_wait == record.io_wait
                    && other.io_wait_generation == record.io_wait_generation
                    && other.state == NetworkRxWaitResolutionState::Resolved
            }) {
                return Err(
                    SemanticInvariantError::NetworkRxWaitResolutionDuplicateIoWait {
                        resolution: duplicate.id,
                        io_wait: record.io_wait,
                    },
                );
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.resolved_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkRxWaitResolved {
                            resolution,
                            io_wait,
                            io_wait_generation,
                            wait,
                            wait_generation,
                            rx_interrupt,
                            rx_interrupt_generation,
                            rx_queue,
                            rx_queue_generation,
                            ready_descriptors,
                            generation,
                        } if *resolution == record.id
                            && *io_wait == record.io_wait
                            && *io_wait_generation == record.io_wait_generation
                            && *wait == record.wait
                            && *wait_generation == record.wait_generation
                            && *rx_interrupt == record.rx_interrupt
                            && *rx_interrupt_generation == record.rx_interrupt_generation
                            && *rx_queue == record.rx_queue
                            && *rx_queue_generation == record.rx_queue_generation
                            && *ready_descriptors == record.ready_descriptors
                            && *generation == record.generation
                    )
            }) {
                return Err(
                    SemanticInvariantError::NetworkRxWaitResolutionMissingEvent {
                        resolution: record.id,
                    },
                );
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_rx_wait_resolution_queue_generation_for_test(
        &mut self,
        resolution: NetworkRxWaitResolutionId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .network_rx_wait_resolutions
            .iter_mut()
            .find(|record| record.id == resolution)
        {
            record.rx_queue_generation = generation;
        }
    }
}
