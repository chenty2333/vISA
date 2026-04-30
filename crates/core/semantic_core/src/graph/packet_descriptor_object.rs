use super::*;

impl SemanticGraph {
    pub(crate) fn validate_packet_descriptor_object(
        &self,
        packet_descriptor: PacketDescriptorObjectId,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        packet_buffer: PacketBufferObjectId,
        packet_buffer_generation: Generation,
        slot: u16,
        length: u32,
    ) -> Result<(), &'static str> {
        if packet_descriptor == 0 {
            return Err("packet descriptor object id=0 is invalid");
        }
        if self
            .domains
            .network
            .packet_descriptors
            .iter()
            .any(|record| record.id == packet_descriptor)
        {
            return Err("packet descriptor object already exists");
        }
        if length == 0 {
            return Err("packet descriptor object length is zero");
        }
        let Some(queue_record) = self.domains.network.packet_queue_objects.iter().find(|record| {
            record.id == packet_queue
                && record.generation == packet_queue_generation
                && record.state == PacketQueueObjectState::Registered
        }) else {
            return Err("packet descriptor object queue generation is missing or inactive");
        };
        if u32::from(slot) >= queue_record.depth {
            return Err("packet descriptor object slot is outside queue depth");
        }
        let Some(buffer_record) =
            self.domains.network.packet_buffer_objects.iter().find(|record| {
                record.id == packet_buffer
                    && record.generation == packet_buffer_generation
                    && matches!(
                        record.state,
                        PacketBufferObjectState::Allocated | PacketBufferObjectState::Filled
                    )
            })
        else {
            return Err("packet descriptor object buffer generation is missing or inactive");
        };
        if queue_record.packet_device != buffer_record.packet_device
            || queue_record.packet_device_generation != buffer_record.packet_device_generation
        {
            return Err("packet descriptor object queue and buffer packet device mismatch");
        }
        if !Self::packet_descriptor_role_matches_buffer(queue_record.role, buffer_record.direction)
        {
            return Err("packet descriptor object queue role and buffer direction mismatch");
        }
        match queue_record.role {
            PacketQueueRole::Rx => {
                if length > buffer_record.capacity {
                    return Err("packet descriptor object length exceeds packet buffer capacity");
                }
            }
            PacketQueueRole::Tx => {
                if buffer_record.state != PacketBufferObjectState::Filled {
                    return Err("tx packet descriptor requires filled packet buffer");
                }
                if length > buffer_record.payload_len {
                    return Err("tx packet descriptor length exceeds packet payload");
                }
            }
        }
        if self.domains.network.packet_descriptors.iter().any(|record| {
            record.packet_queue == queue_record.id
                && record.packet_queue_generation == packet_queue_generation
                && record.slot == slot
                && record.state == PacketDescriptorObjectState::Registered
        }) {
            return Err("packet descriptor object slot already exists for packet queue generation");
        }
        if self.domains.network.packet_descriptors.iter().any(|record| {
            record.packet_buffer == buffer_record.id
                && record.packet_buffer_generation == packet_buffer_generation
                && record.state == PacketDescriptorObjectState::Registered
        }) {
            return Err("packet descriptor object packet buffer already has a descriptor");
        }
        if self.check_invariants().is_err() {
            return Err("packet descriptor object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_packet_descriptor_object_with_id(
        &mut self,
        packet_descriptor: PacketDescriptorObjectId,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        packet_buffer: PacketBufferObjectId,
        packet_buffer_generation: Generation,
        slot: u16,
        length: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_packet_descriptor_object(
                packet_descriptor,
                packet_queue,
                packet_queue_generation,
                packet_buffer,
                packet_buffer_generation,
                slot,
                length,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.domains.network.next_packet_descriptor_object_id =
            self.domains.network.next_packet_descriptor_object_id.max(packet_descriptor + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::PacketDescriptorObjectRecorded {
                packet_descriptor,
                packet_queue,
                packet_queue_generation,
                packet_buffer,
                packet_buffer_generation,
                slot,
                length,
                generation,
            },
        );
        self.domains.network.packet_descriptors.push(PacketDescriptorObjectRecord {
            id: packet_descriptor,
            packet_queue,
            packet_queue_generation,
            packet_buffer,
            packet_buffer_generation,
            slot,
            length,
            generation,
            state: PacketDescriptorObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn packet_descriptors(&self) -> &[PacketDescriptorObjectRecord] {
        &self.domains.network.packet_descriptors
    }

    pub fn packet_descriptor_object_count(&self) -> usize {
        self.domains.network.packet_descriptors.len()
    }

    pub fn check_packet_descriptor_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.network.packet_descriptors {
            let Some(queue_record) =
                self.domains.network.packet_queue_objects.iter().find(|packet_queue| {
                    packet_queue.id == record.packet_queue
                        && packet_queue.generation == record.packet_queue_generation
                })
            else {
                return Err(SemanticInvariantError::PacketDescriptorObjectMissingQueue {
                    packet_descriptor: record.id,
                    packet_queue: record.packet_queue,
                });
            };
            let Some(buffer_record) =
                self.domains.network.packet_buffer_objects.iter().find(|packet_buffer| {
                    packet_buffer.id == record.packet_buffer
                        && packet_buffer.generation == record.packet_buffer_generation
                })
            else {
                return Err(SemanticInvariantError::PacketDescriptorObjectMissingBuffer {
                    packet_descriptor: record.id,
                    packet_buffer: record.packet_buffer,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.packet_queue_generation == 0
                || record.packet_buffer_generation == 0
                || record.length == 0
                || u32::from(record.slot) >= queue_record.depth
                || queue_record.state != PacketQueueObjectState::Registered
                || record.state != PacketDescriptorObjectState::Registered
                || queue_record.packet_device != buffer_record.packet_device
                || queue_record.packet_device_generation != buffer_record.packet_device_generation
                || !Self::packet_descriptor_role_matches_buffer(
                    queue_record.role,
                    buffer_record.direction,
                )
                || !matches!(
                    buffer_record.state,
                    PacketBufferObjectState::Allocated | PacketBufferObjectState::Filled
                )
                || (queue_record.role == PacketQueueRole::Rx
                    && record.length > buffer_record.capacity)
                || (queue_record.role == PacketQueueRole::Tx
                    && (buffer_record.state != PacketBufferObjectState::Filled
                        || record.length > buffer_record.payload_len))
            {
                return Err(SemanticInvariantError::PacketDescriptorObjectInvalid {
                    packet_descriptor: record.id,
                });
            }
            if let Some(duplicate) = self.domains.network.packet_descriptors.iter().find(|other| {
                other.id != record.id
                    && other.packet_queue == record.packet_queue
                    && other.packet_queue_generation == record.packet_queue_generation
                    && other.slot == record.slot
                    && other.state == PacketDescriptorObjectState::Registered
            }) {
                return Err(SemanticInvariantError::PacketDescriptorObjectDuplicateSlot {
                    packet_descriptor: duplicate.id,
                    packet_queue: record.packet_queue,
                    slot: record.slot,
                });
            }
            if let Some(duplicate) = self.domains.network.packet_descriptors.iter().find(|other| {
                other.id != record.id
                    && other.packet_buffer == record.packet_buffer
                    && other.packet_buffer_generation == record.packet_buffer_generation
                    && other.state == PacketDescriptorObjectState::Registered
            }) {
                return Err(SemanticInvariantError::PacketDescriptorObjectDuplicateBuffer {
                    packet_descriptor: duplicate.id,
                    packet_buffer: record.packet_buffer,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::PacketDescriptorObjectRecorded {
                            packet_descriptor,
                            packet_queue,
                            packet_queue_generation,
                            packet_buffer,
                            packet_buffer_generation,
                            slot,
                            length,
                            generation,
                        } if *packet_descriptor == record.id
                            && *packet_queue == record.packet_queue
                            && *packet_queue_generation == record.packet_queue_generation
                            && *packet_buffer == record.packet_buffer
                            && *packet_buffer_generation == record.packet_buffer_generation
                            && *slot == record.slot
                            && *length == record.length
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::PacketDescriptorObjectMissingEvent {
                    packet_descriptor: record.id,
                });
            }
        }
        Ok(())
    }

    const fn packet_descriptor_role_matches_buffer(
        role: PacketQueueRole,
        direction: PacketBufferDirection,
    ) -> bool {
        matches!(
            (role, direction),
            (PacketQueueRole::Rx, PacketBufferDirection::Rx)
                | (PacketQueueRole::Tx, PacketBufferDirection::Tx)
        )
    }

    #[cfg(test)]
    pub(crate) fn corrupt_packet_descriptor_queue_generation_for_test(
        &mut self,
        packet_descriptor: PacketDescriptorObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .network
            .packet_descriptors
            .iter_mut()
            .find(|record| record.id == packet_descriptor)
        {
            record.packet_queue_generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_packet_descriptor_buffer_generation_for_test(
        &mut self,
        packet_descriptor: PacketDescriptorObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .network
            .packet_descriptors
            .iter_mut()
            .find(|record| record.id == packet_descriptor)
        {
            record.packet_buffer_generation = generation;
        }
    }
}
