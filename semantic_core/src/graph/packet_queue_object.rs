use super::*;

impl SemanticGraph {
    pub(crate) fn validate_packet_queue_object(
        &self,
        packet_queue: PacketQueueObjectId,
        name: &str,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        role: PacketQueueRole,
        queue_index: u16,
        depth: u32,
    ) -> Result<(), &'static str> {
        if packet_queue == 0 {
            return Err("packet queue object id=0 is invalid");
        }
        if self.packet_queue_objects.iter().any(|record| record.id == packet_queue) {
            return Err("packet queue object already exists");
        }
        if name.is_empty() {
            return Err("packet queue object name is empty");
        }
        if depth == 0 {
            return Err("packet queue object depth is zero");
        }
        if !Self::packet_queue_role_is_supported(role) {
            return Err("packet queue object role is unsupported");
        }
        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == packet_device
                && record.generation == packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err("packet queue object packet device generation is missing or inactive");
        };
        let max_depth = match role {
            PacketQueueRole::Rx => packet_device_record.rx_queue_depth,
            PacketQueueRole::Tx => packet_device_record.tx_queue_depth,
        };
        if depth > max_depth {
            return Err("packet queue object depth exceeds packet device queue contract");
        }
        if self.packet_queue_objects.iter().any(|record| {
            record.packet_device == packet_device_record.id
                && record.packet_device_generation == packet_device_generation
                && record.role == role
                && record.queue_index == queue_index
                && record.state == PacketQueueObjectState::Registered
        }) {
            return Err("packet queue object index already exists for packet device generation");
        }
        if self.check_invariants().is_err() {
            return Err("packet queue object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_packet_queue_object_with_id(
        &mut self,
        packet_queue: PacketQueueObjectId,
        name: &str,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        role: PacketQueueRole,
        queue_index: u16,
        depth: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_packet_queue_object(
                packet_queue,
                name,
                packet_device,
                packet_device_generation,
                role,
                queue_index,
                depth,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_packet_queue_object_id = self.next_packet_queue_object_id.max(packet_queue + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::PacketQueueObjectRecorded {
                packet_queue,
                packet_device,
                packet_device_generation,
                role,
                queue_index,
                depth,
                generation,
            },
        );
        self.packet_queue_objects.push(PacketQueueObjectRecord {
            id: packet_queue,
            name: name.to_string(),
            packet_device,
            packet_device_generation,
            role,
            queue_index,
            depth,
            generation,
            state: PacketQueueObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn packet_queue_objects(&self) -> &[PacketQueueObjectRecord] {
        &self.packet_queue_objects
    }

    pub fn packet_queue_object_count(&self) -> usize {
        self.packet_queue_objects.len()
    }

    pub fn check_packet_queue_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.packet_queue_objects {
            let Some(packet_device_record) =
                self.packet_device_objects.iter().find(|packet_device| {
                    packet_device.id == record.packet_device
                        && packet_device.generation == record.packet_device_generation
                })
            else {
                return Err(SemanticInvariantError::PacketQueueObjectMissingDevice {
                    packet_queue: record.id,
                    packet_device: record.packet_device,
                });
            };
            let max_depth = match record.role {
                PacketQueueRole::Rx => packet_device_record.rx_queue_depth,
                PacketQueueRole::Tx => packet_device_record.tx_queue_depth,
            };
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.packet_device_generation == 0
                || record.depth == 0
                || record.depth > max_depth
                || !Self::packet_queue_role_is_supported(record.role)
                || record.state != PacketQueueObjectState::Registered
                || packet_device_record.state != PacketDeviceObjectState::Registered
            {
                return Err(SemanticInvariantError::PacketQueueObjectInvalid {
                    packet_queue: record.id,
                });
            }
            if let Some(duplicate) = self.packet_queue_objects.iter().find(|other| {
                other.id != record.id
                    && other.packet_device == record.packet_device
                    && other.packet_device_generation == record.packet_device_generation
                    && other.role == record.role
                    && other.queue_index == record.queue_index
                    && other.state == PacketQueueObjectState::Registered
            }) {
                return Err(SemanticInvariantError::PacketQueueObjectDuplicateIndex {
                    packet_queue: duplicate.id,
                    packet_device: record.packet_device,
                    role: record.role,
                    queue_index: record.queue_index,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::PacketQueueObjectRecorded {
                            packet_queue,
                            packet_device,
                            packet_device_generation,
                            role,
                            queue_index,
                            depth,
                            generation,
                        } if *packet_queue == record.id
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *role == record.role
                            && *queue_index == record.queue_index
                            && *depth == record.depth
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::PacketQueueObjectMissingEvent {
                    packet_queue: record.id,
                });
            }
        }
        Ok(())
    }

    const fn packet_queue_role_is_supported(role: PacketQueueRole) -> bool {
        matches!(role, PacketQueueRole::Rx | PacketQueueRole::Tx)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_packet_queue_packet_device_generation_for_test(
        &mut self,
        packet_queue: PacketQueueObjectId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.packet_queue_objects.iter_mut().find(|record| record.id == packet_queue)
        {
            record.packet_device_generation = generation;
        }
    }
}
