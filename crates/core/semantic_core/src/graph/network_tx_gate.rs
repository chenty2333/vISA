use super::*;

impl SemanticGraph {
    pub(crate) fn validate_network_tx_capability_gate(
        &self,
        tx_gate: NetworkTxCapabilityGateId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        packet_descriptor: PacketDescriptorObjectId,
        packet_descriptor_generation: Generation,
        device_capability: DeviceCapabilityId,
        device_capability_generation: Generation,
        handle: &CapabilityHandle,
    ) -> Result<CapabilityId, &'static str> {
        if tx_gate == 0 {
            return Err("network tx capability gate id=0 is invalid");
        }
        if self.network_tx_capability_gates.iter().any(|record| record.id == tx_gate) {
            return Err("network tx capability gate already exists");
        }
        let Some(store_record) = self.stores.iter().find(|record| {
            record.id == driver_store && record.generation == driver_store_generation
        }) else {
            return Err("network tx capability gate driver store generation is missing");
        };
        if store_record.role != "driver" || store_record.state == StoreState::Dead {
            return Err("network tx capability gate driver store is not live driver");
        }
        let Some(descriptor_record) = self.packet_descriptors.iter().find(|record| {
            record.id == packet_descriptor
                && record.generation == packet_descriptor_generation
                && record.state == PacketDescriptorObjectState::Registered
        }) else {
            return Err("network tx capability gate descriptor generation is missing or inactive");
        };
        let Some(tx_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == descriptor_record.packet_queue
                && record.generation == descriptor_record.packet_queue_generation
                && record.state == PacketQueueObjectState::Registered
        }) else {
            return Err("network tx capability gate queue generation is missing or inactive");
        };
        if tx_queue_record.role != PacketQueueRole::Tx {
            return Err("network tx capability gate requires tx packet queue");
        }
        let Some(buffer_record) = self.packet_buffer_objects.iter().find(|record| {
            record.id == descriptor_record.packet_buffer
                && record.generation == descriptor_record.packet_buffer_generation
                && record.state == PacketBufferObjectState::Filled
        }) else {
            return Err("network tx capability gate buffer generation is missing or not filled");
        };
        if buffer_record.direction != PacketBufferDirection::Tx
            || descriptor_record.length > buffer_record.payload_len
        {
            return Err(
                "network tx capability gate descriptor does not reference a valid tx buffer",
            );
        }
        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == tx_queue_record.packet_device
                && record.generation == tx_queue_record.packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err(
                "network tx capability gate packet device generation is missing or inactive",
            );
        };
        if buffer_record.packet_device != packet_device_record.id
            || buffer_record.packet_device_generation != packet_device_record.generation
        {
            return Err("network tx capability gate queue and buffer packet device mismatch");
        }
        let packet_device_ref = packet_device_record.object_ref();
        let Some(device_capability_record) = self.device_capabilities.iter().find(|record| {
            record.id == device_capability
                && record.generation == device_capability_generation
                && record.state == DeviceCapabilityState::Active
        }) else {
            return Err("network tx capability gate device capability generation is missing");
        };
        if device_capability_record.driver_store != driver_store
            || device_capability_record.driver_store_generation != driver_store_generation
            || device_capability_record.target != packet_device_ref
            || device_capability_record.class != CapabilityClass::PacketDevice
            || device_capability_record.operation != "tx"
        {
            return Err("network tx capability gate device capability target mismatch");
        }
        if handle.owner_store != driver_store
            || handle.owner_store_generation != driver_store_generation
            || handle.slot != device_capability_record.handle_slot
            || handle.generation != device_capability_record.handle_generation
            || handle.tag != device_capability_record.handle_tag
            || handle.class_hint != CapabilityClass::PacketDevice
            || !handle.rights_hint.contains("tx")
        {
            return Err("network tx capability gate handle mismatch");
        }
        let authority =
            AuthorityObjectRef::internal(CapabilityClass::PacketDevice, packet_device_ref);
        let capability_record = self
            .domains
            .capability
            .capabilities
            .check_authority(&store_record.package, authority, "tx", Some(handle))
            .map_err(|_| "network tx capability gate handle is not authorized")?;
        if capability_record.id != device_capability_record.capability
            || capability_record.generation != device_capability_record.capability_generation
        {
            return Err("network tx capability gate capability attribution mismatch");
        }
        if self.network_tx_capability_gates.iter().any(|record| {
            record.packet_descriptor == descriptor_record.id
                && record.packet_descriptor_generation == descriptor_record.generation
                && record.state == NetworkTxCapabilityGateState::Allowed
        }) {
            return Err("network tx capability gate descriptor already has an allowed gate");
        }
        if self.check_invariants().is_err() {
            return Err("network tx capability gate requires invariant-clean graph");
        }
        Ok(capability_record.id)
    }

    pub fn record_network_tx_capability_gate_with_id(
        &mut self,
        tx_gate: NetworkTxCapabilityGateId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        packet_descriptor: PacketDescriptorObjectId,
        packet_descriptor_generation: Generation,
        device_capability: DeviceCapabilityId,
        device_capability_generation: Generation,
        handle: CapabilityHandle,
        note: &str,
    ) -> bool {
        let Ok(capability) = self.validate_network_tx_capability_gate(
            tx_gate,
            driver_store,
            driver_store_generation,
            packet_descriptor,
            packet_descriptor_generation,
            device_capability,
            device_capability_generation,
            &handle,
        ) else {
            return false;
        };
        let Some(descriptor_record) = self.packet_descriptors.iter().find(|record| {
            record.id == packet_descriptor && record.generation == packet_descriptor_generation
        }) else {
            return false;
        };
        let Some(tx_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == descriptor_record.packet_queue
                && record.generation == descriptor_record.packet_queue_generation
        }) else {
            return false;
        };
        let Some(buffer_record) = self.packet_buffer_objects.iter().find(|record| {
            record.id == descriptor_record.packet_buffer
                && record.generation == descriptor_record.packet_buffer_generation
        }) else {
            return false;
        };
        let Some(device_capability_record) = self.device_capabilities.iter().find(|record| {
            record.id == device_capability && record.generation == device_capability_generation
        }) else {
            return false;
        };
        let Some(capability_record) = self.domains.capability.capabilities.record(capability)
        else {
            return false;
        };
        let packet_device = tx_queue_record.packet_device;
        let packet_device_generation = tx_queue_record.packet_device_generation;
        let tx_queue = tx_queue_record.id;
        let tx_queue_generation = tx_queue_record.generation;
        let packet_buffer = buffer_record.id;
        let packet_buffer_generation = buffer_record.generation;
        let byte_len = descriptor_record.length;
        let sequence = buffer_record.sequence;
        let capability_generation = capability_record.generation;
        let operation = device_capability_record.operation.clone();
        let generation = 1;
        self.next_network_tx_capability_gate_id =
            self.next_network_tx_capability_gate_id.max(tx_gate + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::NetworkTxCapabilityGateRecorded {
                tx_gate,
                driver_store,
                driver_store_generation,
                packet_device,
                packet_device_generation,
                tx_queue,
                tx_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                device_capability,
                device_capability_generation,
                capability,
                capability_generation,
                handle_slot: handle.slot,
                handle_generation: handle.generation,
                handle_tag: handle.tag,
                byte_len,
                sequence,
                generation,
            },
        );
        self.network_tx_capability_gates.push(NetworkTxCapabilityGateRecord {
            id: tx_gate,
            driver_store,
            driver_store_generation,
            packet_device,
            packet_device_generation,
            tx_queue,
            tx_queue_generation,
            packet_descriptor,
            packet_descriptor_generation,
            packet_buffer,
            packet_buffer_generation,
            device_capability,
            device_capability_generation,
            capability,
            capability_generation,
            handle_slot: handle.slot,
            handle_generation: handle.generation,
            handle_tag: handle.tag,
            operation,
            byte_len,
            sequence,
            generation,
            state: NetworkTxCapabilityGateState::Allowed,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn network_tx_capability_gates(&self) -> &[NetworkTxCapabilityGateRecord] {
        &self.network_tx_capability_gates
    }

    pub fn network_tx_capability_gate_count(&self) -> usize {
        self.network_tx_capability_gates.len()
    }

    pub fn check_network_tx_capability_gate_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.network_tx_capability_gates {
            let Some(descriptor_record) =
                self.packet_descriptors.iter().find(|packet_descriptor| {
                    packet_descriptor.id == record.packet_descriptor
                        && packet_descriptor.generation == record.packet_descriptor_generation
                })
            else {
                return Err(SemanticInvariantError::NetworkTxCapabilityGateMissingDescriptor {
                    tx_gate: record.id,
                    packet_descriptor: record.packet_descriptor,
                });
            };
            let Some(tx_queue_record) = self.packet_queue_objects.iter().find(|tx_queue| {
                tx_queue.id == record.tx_queue && tx_queue.generation == record.tx_queue_generation
            }) else {
                return Err(SemanticInvariantError::NetworkTxCapabilityGateInvalid {
                    tx_gate: record.id,
                });
            };
            let Some(buffer_record) = self.packet_buffer_objects.iter().find(|packet_buffer| {
                packet_buffer.id == record.packet_buffer
                    && packet_buffer.generation == record.packet_buffer_generation
            }) else {
                return Err(SemanticInvariantError::NetworkTxCapabilityGateInvalid {
                    tx_gate: record.id,
                });
            };
            let Some(packet_device_record) =
                self.packet_device_objects.iter().find(|packet_device| {
                    packet_device.id == record.packet_device
                        && packet_device.generation == record.packet_device_generation
                })
            else {
                return Err(SemanticInvariantError::NetworkTxCapabilityGateInvalid {
                    tx_gate: record.id,
                });
            };
            let Some(device_capability_record) =
                self.device_capabilities.iter().find(|device_capability| {
                    device_capability.id == record.device_capability
                        && device_capability.generation == record.device_capability_generation
                })
            else {
                return Err(SemanticInvariantError::NetworkTxCapabilityGateMissingCapability {
                    tx_gate: record.id,
                    device_capability: record.device_capability,
                });
            };
            let Some(capability_record) =
                self.domains.capability.capabilities.record(record.capability)
            else {
                return Err(SemanticInvariantError::NetworkTxCapabilityGateMissingCapability {
                    tx_gate: record.id,
                    device_capability: record.device_capability,
                });
            };
            let Some(store_record) = self.stores.iter().find(|store| {
                store.id == record.driver_store
                    && store.generation == record.driver_store_generation
            }) else {
                return Err(SemanticInvariantError::NetworkTxCapabilityGateInvalid {
                    tx_gate: record.id,
                });
            };
            let packet_device_ref = packet_device_record.object_ref();
            let cleanup_covers_packet_device = self
                .network_driver_cleanup_covers_packet_device_for_store(
                    record.driver_store,
                    record.driver_store_generation,
                    record.packet_device,
                    record.packet_device_generation,
                );
            let device_capability_available = device_capability_record.state
                == DeviceCapabilityState::Active
                || (device_capability_record.state == DeviceCapabilityState::Revoked
                    && cleanup_covers_packet_device);
            let capability_generation_ok = if cleanup_covers_packet_device {
                capability_record.generation >= record.capability_generation
            } else {
                capability_record.generation == record.capability_generation
            };
            let capability_revocation_ok =
                !capability_record.revoked || cleanup_covers_packet_device;
            if record.id == 0
                || record.generation == 0
                || record.driver_store_generation == 0
                || record.packet_device_generation == 0
                || record.tx_queue_generation == 0
                || record.packet_descriptor_generation == 0
                || record.packet_buffer_generation == 0
                || record.device_capability_generation == 0
                || record.capability_generation == 0
                || record.operation != "tx"
                || record.byte_len == 0
                || record.sequence == 0
                || record.state != NetworkTxCapabilityGateState::Allowed
                || store_record.role != "driver"
                || store_record.state == StoreState::Dead
                || packet_device_record.state != PacketDeviceObjectState::Registered
                || tx_queue_record.state != PacketQueueObjectState::Registered
                || tx_queue_record.role != PacketQueueRole::Tx
                || tx_queue_record.packet_device != record.packet_device
                || tx_queue_record.packet_device_generation != record.packet_device_generation
                || descriptor_record.state != PacketDescriptorObjectState::Registered
                || descriptor_record.packet_queue != record.tx_queue
                || descriptor_record.packet_queue_generation != record.tx_queue_generation
                || descriptor_record.packet_buffer != record.packet_buffer
                || descriptor_record.packet_buffer_generation != record.packet_buffer_generation
                || descriptor_record.length != record.byte_len
                || buffer_record.state != PacketBufferObjectState::Filled
                || buffer_record.direction != PacketBufferDirection::Tx
                || buffer_record.packet_device != record.packet_device
                || buffer_record.packet_device_generation != record.packet_device_generation
                || buffer_record.sequence != record.sequence
                || !device_capability_available
                || device_capability_record.driver_store != record.driver_store
                || device_capability_record.driver_store_generation
                    != record.driver_store_generation
                || device_capability_record.target != packet_device_ref
                || device_capability_record.class != CapabilityClass::PacketDevice
                || device_capability_record.operation != record.operation
                || device_capability_record.capability != record.capability
                || device_capability_record.capability_generation != record.capability_generation
                || device_capability_record.handle_slot != record.handle_slot
                || device_capability_record.handle_generation != record.handle_generation
                || device_capability_record.handle_tag != record.handle_tag
                || !capability_generation_ok
                || !capability_revocation_ok
                || capability_record.subject != store_record.package
                || capability_record.object_ref
                    != Some(AuthorityObjectRef::internal(
                        CapabilityClass::PacketDevice,
                        packet_device_ref,
                    ))
                || !capability_record.operations.contains("tx")
                || descriptor_record.length > buffer_record.payload_len
            {
                return Err(SemanticInvariantError::NetworkTxCapabilityGateInvalid {
                    tx_gate: record.id,
                });
            }
            if let Some(duplicate) = self.network_tx_capability_gates.iter().find(|other| {
                other.id != record.id
                    && other.packet_descriptor == record.packet_descriptor
                    && other.packet_descriptor_generation == record.packet_descriptor_generation
                    && other.state == NetworkTxCapabilityGateState::Allowed
            }) {
                return Err(SemanticInvariantError::NetworkTxCapabilityGateDuplicateDescriptor {
                    tx_gate: duplicate.id,
                    packet_descriptor: record.packet_descriptor,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkTxCapabilityGateRecorded {
                            tx_gate,
                            driver_store,
                            driver_store_generation,
                            packet_device,
                            packet_device_generation,
                            tx_queue,
                            tx_queue_generation,
                            packet_descriptor,
                            packet_descriptor_generation,
                            packet_buffer,
                            packet_buffer_generation,
                            device_capability,
                            device_capability_generation,
                            capability,
                            capability_generation,
                            handle_slot,
                            handle_generation,
                            handle_tag,
                            byte_len,
                            sequence,
                            generation,
                        } if *tx_gate == record.id
                            && *driver_store == record.driver_store
                            && *driver_store_generation == record.driver_store_generation
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *tx_queue == record.tx_queue
                            && *tx_queue_generation == record.tx_queue_generation
                            && *packet_descriptor == record.packet_descriptor
                            && *packet_descriptor_generation == record.packet_descriptor_generation
                            && *packet_buffer == record.packet_buffer
                            && *packet_buffer_generation == record.packet_buffer_generation
                            && *device_capability == record.device_capability
                            && *device_capability_generation == record.device_capability_generation
                            && *capability == record.capability
                            && *capability_generation == record.capability_generation
                            && *handle_slot == record.handle_slot
                            && *handle_generation == record.handle_generation
                            && *handle_tag == record.handle_tag
                            && *byte_len == record.byte_len
                            && *sequence == record.sequence
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::NetworkTxCapabilityGateMissingEvent {
                    tx_gate: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_tx_gate_capability_generation_for_test(
        &mut self,
        tx_gate: NetworkTxCapabilityGateId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.network_tx_capability_gates.iter_mut().find(|record| record.id == tx_gate)
        {
            record.capability_generation = generation;
        }
    }
}
