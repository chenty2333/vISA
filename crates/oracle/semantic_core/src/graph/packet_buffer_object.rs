use super::*;

impl SemanticGraph {
    pub(crate) fn validate_packet_buffer_object(
        &self,
        packet_buffer: PacketBufferObjectId,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        direction: PacketBufferDirection,
        frame_format_version: u32,
        capacity: u32,
        payload_len: u32,
        sequence: u64,
        state: PacketBufferObjectState,
    ) -> Result<(), &'static str> {
        if packet_buffer == 0 {
            return Err("packet buffer object id=0 is invalid");
        }
        if self
            .domains
            .network
            .packet_buffer_objects
            .iter()
            .any(|record| record.id == packet_buffer)
        {
            return Err("packet buffer object already exists");
        }
        if frame_format_version == 0 || capacity == 0 || sequence == 0 {
            return Err("packet buffer object identity values must be nonzero");
        }
        if payload_len > capacity {
            return Err("packet buffer object payload exceeds capacity");
        }
        if !Self::packet_buffer_direction_is_supported(direction) {
            return Err("packet buffer object direction is unsupported");
        }
        if !Self::packet_buffer_state_is_recordable(state) {
            return Err("packet buffer object state is not recordable");
        }
        if state == PacketBufferObjectState::Filled && payload_len == 0 {
            return Err("filled packet buffer object must carry payload");
        }
        let Some(packet_device_record) =
            self.domains.network.packet_device_objects.iter().find(|record| {
                record.id == packet_device
                    && record.generation == packet_device_generation
                    && record.state == PacketDeviceObjectState::Registered
            })
        else {
            return Err("packet buffer object packet device generation is missing or inactive");
        };
        if frame_format_version != packet_device_record.frame_format_version {
            return Err("packet buffer object frame format does not match packet device");
        }
        if capacity > packet_device_record.max_payload_len {
            return Err("packet buffer object capacity exceeds packet device payload limit");
        }
        if self.check_invariants().is_err() {
            return Err("packet buffer object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_packet_buffer_object_with_id(
        &mut self,
        packet_buffer: PacketBufferObjectId,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        direction: PacketBufferDirection,
        frame_format_version: u32,
        capacity: u32,
        payload_len: u32,
        sequence: u64,
        state: PacketBufferObjectState,
        note: &str,
    ) -> bool {
        if self
            .validate_packet_buffer_object(
                packet_buffer,
                packet_device,
                packet_device_generation,
                direction,
                frame_format_version,
                capacity,
                payload_len,
                sequence,
                state,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.domains.network.next_packet_buffer_object_id =
            self.domains.network.next_packet_buffer_object_id.max(packet_buffer + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::PacketBufferObjectRecorded {
                packet_buffer,
                packet_device,
                packet_device_generation,
                direction,
                frame_format_version,
                capacity,
                payload_len,
                sequence,
                state,
                generation,
            },
        );
        self.domains.network.packet_buffer_objects.push(PacketBufferObjectRecord {
            id: packet_buffer,
            packet_device,
            packet_device_generation,
            direction,
            frame_format_version,
            capacity,
            payload_len,
            sequence,
            generation,
            state,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn packet_buffer_objects(&self) -> &[PacketBufferObjectRecord] {
        &self.domains.network.packet_buffer_objects
    }

    pub fn packet_buffer_object_count(&self) -> usize {
        self.domains.network.packet_buffer_objects.len()
    }

    pub fn check_packet_buffer_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.network.packet_buffer_objects {
            let Some(packet_device_record) =
                self.domains.network.packet_device_objects.iter().find(|packet_device| {
                    packet_device.id == record.packet_device
                        && packet_device.generation == record.packet_device_generation
                })
            else {
                return Err(SemanticInvariantError::PacketBufferObjectMissingDevice {
                    packet_buffer: record.id,
                    packet_device: record.packet_device,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.packet_device_generation == 0
                || record.frame_format_version == 0
                || record.capacity == 0
                || record.capacity > packet_device_record.max_payload_len
                || record.payload_len > record.capacity
                || record.sequence == 0
                || record.frame_format_version != packet_device_record.frame_format_version
                || !Self::packet_buffer_direction_is_supported(record.direction)
                || !Self::packet_buffer_state_is_recordable(record.state)
                || (record.state == PacketBufferObjectState::Filled && record.payload_len == 0)
                || packet_device_record.state != PacketDeviceObjectState::Registered
            {
                return Err(SemanticInvariantError::PacketBufferObjectInvalid {
                    packet_buffer: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::PacketBufferObjectRecorded {
                            packet_buffer,
                            packet_device,
                            packet_device_generation,
                            direction,
                            frame_format_version,
                            capacity,
                            payload_len,
                            sequence,
                            state,
                            generation,
                        } if *packet_buffer == record.id
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *direction == record.direction
                            && *frame_format_version == record.frame_format_version
                            && *capacity == record.capacity
                            && *payload_len == record.payload_len
                            && *sequence == record.sequence
                            && *state == record.state
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::PacketBufferObjectMissingEvent {
                    packet_buffer: record.id,
                });
            }
        }
        Ok(())
    }

    const fn packet_buffer_direction_is_supported(direction: PacketBufferDirection) -> bool {
        matches!(direction, PacketBufferDirection::Rx | PacketBufferDirection::Tx)
    }

    const fn packet_buffer_state_is_recordable(state: PacketBufferObjectState) -> bool {
        matches!(state, PacketBufferObjectState::Allocated | PacketBufferObjectState::Filled)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_packet_buffer_packet_device_generation_for_test(
        &mut self,
        packet_buffer: PacketBufferObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .network
            .packet_buffer_objects
            .iter_mut()
            .find(|record| record.id == packet_buffer)
        {
            record.packet_device_generation = generation;
        }
    }
}
