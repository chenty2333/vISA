use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_network_rx_interrupt(
        &self,
        rx_interrupt: NetworkRxInterruptId,
        virtio_net_backend: VirtioNetBackendObjectId,
        virtio_net_backend_generation: Generation,
        irq_event: IrqEventId,
        irq_event_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        ready_descriptors: u16,
        sequence: u64,
    ) -> Result<(), &'static str> {
        if rx_interrupt == 0 {
            return Err("network rx interrupt id=0 is invalid");
        }
        if self
            .network_rx_interrupts
            .iter()
            .any(|record| record.id == rx_interrupt)
        {
            return Err("network rx interrupt already exists");
        }
        if ready_descriptors == 0 || sequence == 0 {
            return Err("network rx interrupt readiness values are invalid");
        }
        let Some(backend_record) = self.virtio_net_backends.iter().find(|record| {
            record.id == virtio_net_backend
                && record.generation == virtio_net_backend_generation
                && record.state == VirtioNetBackendObjectState::SkeletonReady
        }) else {
            return Err("network rx interrupt backend generation is missing or inactive");
        };
        let Some(irq_record) = self.irq_events.iter().find(|record| {
            record.id == irq_event
                && record.generation == irq_event_generation
                && record.state == IrqEventState::Recorded
        }) else {
            return Err("network rx interrupt irq event generation is missing or inactive");
        };
        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == packet_device
                && record.generation == packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err("network rx interrupt packet device generation is missing or inactive");
        };
        let Some(rx_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == rx_queue
                && record.generation == rx_queue_generation
                && record.state == PacketQueueObjectState::Registered
        }) else {
            return Err("network rx interrupt rx queue generation is missing or inactive");
        };
        let Some(binding_record) = self.driver_store_bindings.iter().find(|record| {
            record.id == backend_record.driver_binding
                && record.generation == backend_record.driver_binding_generation
                && record.state == DriverStoreBindingState::Bound
        }) else {
            return Err("network rx interrupt backend driver binding is missing or inactive");
        };
        let irq_capability_target = ContractObjectRef::new(
            ContractObjectKind::IrqLineObject,
            irq_record.irq_line,
            irq_record.irq_line_generation,
        );
        let irq_capability_active = self.device_capabilities.iter().any(|record| {
            record.driver_store == binding_record.driver_store
                && record.driver_store_generation == binding_record.driver_store_generation
                && record.target == irq_capability_target
                && record.class == CapabilityClass::IrqLine
                && record.operation == "ack"
                && record.state == DeviceCapabilityState::Active
        });
        if !irq_capability_active {
            return Err("network rx interrupt irq ack capability is missing");
        }
        if backend_record.packet_device != packet_device_record.id
            || backend_record.packet_device_generation != packet_device_record.generation
            || rx_queue_record.packet_device != packet_device_record.id
            || rx_queue_record.packet_device_generation != packet_device_record.generation
            || rx_queue_record.role != PacketQueueRole::Rx
        {
            return Err("network rx interrupt rx queue does not match backend packet device");
        }
        if irq_record.device != backend_record.device
            || irq_record.device_generation != backend_record.device_generation
            || irq_record.driver_store != binding_record.driver_store
            || irq_record.driver_store_generation != binding_record.driver_store_generation
        {
            return Err("network rx interrupt irq event does not match backend driver binding");
        }
        if ready_descriptors as u32 > rx_queue_record.depth {
            return Err("network rx interrupt ready descriptors exceed rx queue depth");
        }
        if self.network_rx_interrupts.iter().any(|record| {
            record.irq_event == irq_event
                && record.irq_event_generation == irq_event_generation
                && record.state == NetworkRxInterruptState::Recorded
        }) {
            return Err("network rx interrupt already recorded for irq event generation");
        }
        if self.check_invariants().is_err() {
            return Err("network rx interrupt requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_network_rx_interrupt_with_id(
        &mut self,
        rx_interrupt: NetworkRxInterruptId,
        virtio_net_backend: VirtioNetBackendObjectId,
        virtio_net_backend_generation: Generation,
        irq_event: IrqEventId,
        irq_event_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        rx_queue: PacketQueueObjectId,
        rx_queue_generation: Generation,
        ready_descriptors: u16,
        sequence: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_network_rx_interrupt(
                rx_interrupt,
                virtio_net_backend,
                virtio_net_backend_generation,
                irq_event,
                irq_event_generation,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                ready_descriptors,
                sequence,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_network_rx_interrupt_id = self.next_network_rx_interrupt_id.max(rx_interrupt + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::NetworkRxInterruptRecorded {
                rx_interrupt,
                virtio_net_backend,
                virtio_net_backend_generation,
                irq_event,
                irq_event_generation,
                packet_device,
                packet_device_generation,
                rx_queue,
                rx_queue_generation,
                ready_descriptors,
                sequence,
                generation,
            },
        );
        self.network_rx_interrupts.push(NetworkRxInterruptRecord {
            id: rx_interrupt,
            virtio_net_backend,
            virtio_net_backend_generation,
            irq_event,
            irq_event_generation,
            packet_device,
            packet_device_generation,
            rx_queue,
            rx_queue_generation,
            ready_descriptors,
            sequence,
            generation,
            state: NetworkRxInterruptState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn network_rx_interrupts(&self) -> &[NetworkRxInterruptRecord] {
        &self.network_rx_interrupts
    }

    pub fn network_rx_interrupt_count(&self) -> usize {
        self.network_rx_interrupts.len()
    }

    pub fn check_network_rx_interrupt_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.network_rx_interrupts {
            let Some(backend_record) = self.virtio_net_backends.iter().find(|backend| {
                backend.id == record.virtio_net_backend
                    && backend.generation == record.virtio_net_backend_generation
            }) else {
                return Err(SemanticInvariantError::NetworkRxInterruptMissingBackend {
                    rx_interrupt: record.id,
                    virtio_net_backend: record.virtio_net_backend,
                });
            };
            let Some(irq_record) = self.irq_events.iter().find(|irq| {
                irq.id == record.irq_event && irq.generation == record.irq_event_generation
            }) else {
                return Err(SemanticInvariantError::NetworkRxInterruptMissingIrqEvent {
                    rx_interrupt: record.id,
                    irq_event: record.irq_event,
                });
            };
            let Some(packet_device_record) =
                self.packet_device_objects.iter().find(|packet_device| {
                    packet_device.id == record.packet_device
                        && packet_device.generation == record.packet_device_generation
                })
            else {
                return Err(
                    SemanticInvariantError::NetworkRxInterruptMissingPacketDevice {
                        rx_interrupt: record.id,
                        packet_device: record.packet_device,
                    },
                );
            };
            let Some(rx_queue_record) = self.packet_queue_objects.iter().find(|queue| {
                queue.id == record.rx_queue && queue.generation == record.rx_queue_generation
            }) else {
                return Err(SemanticInvariantError::NetworkRxInterruptMissingRxQueue {
                    rx_interrupt: record.id,
                    rx_queue: record.rx_queue,
                });
            };
            let Some(binding_record) = self.driver_store_bindings.iter().find(|binding| {
                binding.id == backend_record.driver_binding
                    && binding.generation == backend_record.driver_binding_generation
            }) else {
                return Err(SemanticInvariantError::NetworkRxInterruptInvalid {
                    rx_interrupt: record.id,
                });
            };
            let cleanup_covers_binding = self.network_driver_cleanup_covers_binding(
                backend_record.driver_binding,
                backend_record.driver_binding_generation,
            );
            let binding_available = binding_record.state == DriverStoreBindingState::Bound
                || (binding_record.state == DriverStoreBindingState::Released
                    && cleanup_covers_binding);
            let irq_capability_target = ContractObjectRef::new(
                ContractObjectKind::IrqLineObject,
                irq_record.irq_line,
                irq_record.irq_line_generation,
            );
            let irq_capability_active = self.device_capabilities.iter().any(|capability| {
                capability.driver_store == binding_record.driver_store
                    && capability.driver_store_generation == binding_record.driver_store_generation
                    && capability.target == irq_capability_target
                    && capability.class == CapabilityClass::IrqLine
                    && capability.operation == "ack"
                    && capability.state == DeviceCapabilityState::Active
            });
            if !irq_capability_active && !cleanup_covers_binding {
                return Err(
                    SemanticInvariantError::NetworkRxInterruptMissingIrqCapability {
                        rx_interrupt: record.id,
                        irq_line: irq_record.irq_line,
                    },
                );
            }
            if record.id == 0
                || record.generation == 0
                || record.virtio_net_backend_generation == 0
                || record.irq_event_generation == 0
                || record.packet_device_generation == 0
                || record.rx_queue_generation == 0
                || record.ready_descriptors == 0
                || record.sequence == 0
                || record.state != NetworkRxInterruptState::Recorded
                || backend_record.state != VirtioNetBackendObjectState::SkeletonReady
                || irq_record.state != IrqEventState::Recorded
                || packet_device_record.state != PacketDeviceObjectState::Registered
                || rx_queue_record.state != PacketQueueObjectState::Registered
                || rx_queue_record.role != PacketQueueRole::Rx
                || !binding_available
                || backend_record.packet_device != packet_device_record.id
                || backend_record.packet_device_generation != packet_device_record.generation
                || rx_queue_record.packet_device != packet_device_record.id
                || rx_queue_record.packet_device_generation != packet_device_record.generation
                || irq_record.device != backend_record.device
                || irq_record.device_generation != backend_record.device_generation
                || irq_record.driver_store != binding_record.driver_store
                || irq_record.driver_store_generation != binding_record.driver_store_generation
                || record.ready_descriptors as u32 > rx_queue_record.depth
            {
                return Err(SemanticInvariantError::NetworkRxInterruptInvalid {
                    rx_interrupt: record.id,
                });
            }
            if let Some(duplicate) = self.network_rx_interrupts.iter().find(|other| {
                other.id != record.id
                    && other.irq_event == record.irq_event
                    && other.irq_event_generation == record.irq_event_generation
                    && other.state == NetworkRxInterruptState::Recorded
            }) {
                return Err(
                    SemanticInvariantError::NetworkRxInterruptDuplicateIrqEvent {
                        rx_interrupt: duplicate.id,
                        irq_event: record.irq_event,
                    },
                );
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkRxInterruptRecorded {
                            rx_interrupt,
                            virtio_net_backend,
                            virtio_net_backend_generation,
                            irq_event,
                            irq_event_generation,
                            packet_device,
                            packet_device_generation,
                            rx_queue,
                            rx_queue_generation,
                            ready_descriptors,
                            sequence,
                            generation,
                        } if *rx_interrupt == record.id
                            && *virtio_net_backend == record.virtio_net_backend
                            && *virtio_net_backend_generation == record.virtio_net_backend_generation
                            && *irq_event == record.irq_event
                            && *irq_event_generation == record.irq_event_generation
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *rx_queue == record.rx_queue
                            && *rx_queue_generation == record.rx_queue_generation
                            && *ready_descriptors == record.ready_descriptors
                            && *sequence == record.sequence
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::NetworkRxInterruptMissingEvent {
                    rx_interrupt: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_rx_interrupt_queue_generation_for_test(
        &mut self,
        rx_interrupt: NetworkRxInterruptId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .network_rx_interrupts
            .iter_mut()
            .find(|record| record.id == rx_interrupt)
        {
            record.rx_queue_generation = generation;
        }
    }
}
