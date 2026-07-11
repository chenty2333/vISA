use super::*;

impl SemanticGraph {
    pub(crate) fn validate_packet_device_object(
        &self,
        packet_device: PacketDeviceObjectId,
        name: &str,
        device: DeviceObjectId,
        device_generation: Generation,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        frame_format_version: u32,
        max_payload_len: u32,
    ) -> Result<(), &'static str> {
        if packet_device == 0 {
            return Err("packet device object id=0 is invalid");
        }
        if self
            .domains
            .network
            .packet_device_objects
            .iter()
            .any(|record| record.id == packet_device)
        {
            return Err("packet device object already exists");
        }
        if name.is_empty() {
            return Err("packet device object name is empty");
        }
        if mtu == 0
            || rx_queue_depth == 0
            || tx_queue_depth == 0
            || frame_format_version == 0
            || max_payload_len == 0
        {
            return Err("packet device object contract values must be nonzero");
        }
        let Some(device_record) = self
            .domains
            .device
            .device_objects
            .iter()
            .find(|record| record.id == device && record.generation == device_generation)
        else {
            return Err("packet device object device generation is missing");
        };
        if device_record.state != DeviceObjectState::Registered {
            return Err("packet device object device is not registered");
        }
        if device_record.class != "packet-device" {
            return Err("packet device object device class is not packet-device");
        }
        if !self.domains.resource.resources.iter().any(|resource| {
            resource.id == device_record.resource
                && resource.generation == device_record.resource_generation
                && resource.kind == ResourceKind::PacketDevice
                && resource.live
        }) {
            return Err("packet device object must be backed by live packet device resource");
        }
        if self.check_invariants().is_err() {
            return Err("packet device object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_packet_device_object_with_id(
        &mut self,
        packet_device: PacketDeviceObjectId,
        name: &str,
        device: DeviceObjectId,
        device_generation: Generation,
        mtu: u32,
        rx_queue_depth: u32,
        tx_queue_depth: u32,
        mac: [u8; 6],
        frame_format_version: u32,
        max_payload_len: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_packet_device_object(
                packet_device,
                name,
                device,
                device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                frame_format_version,
                max_payload_len,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.domains.network.next_packet_device_object_id =
            self.domains.network.next_packet_device_object_id.max(packet_device + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::PacketDeviceObjectRecorded {
                packet_device,
                device,
                device_generation,
                mtu,
                rx_queue_depth,
                tx_queue_depth,
                frame_format_version,
                max_payload_len,
                generation,
            },
        );
        self.domains.network.packet_device_objects.push(PacketDeviceObjectRecord {
            id: packet_device,
            name: name.to_string(),
            device,
            device_generation,
            mtu,
            rx_queue_depth,
            tx_queue_depth,
            mac,
            frame_format_version,
            max_payload_len,
            generation,
            state: PacketDeviceObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn packet_device_objects(&self) -> &[PacketDeviceObjectRecord] {
        &self.domains.network.packet_device_objects
    }

    pub fn packet_device_object_count(&self) -> usize {
        self.domains.network.packet_device_objects.len()
    }

    pub fn check_packet_device_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.network.packet_device_objects {
            let Some(device_record) = self.domains.device.device_objects.iter().find(|device| {
                device.id == record.device && device.generation == record.device_generation
            }) else {
                return Err(SemanticInvariantError::PacketDeviceObjectMissingDevice {
                    packet_device: record.id,
                    device: record.device,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.mtu == 0
                || record.rx_queue_depth == 0
                || record.tx_queue_depth == 0
                || record.frame_format_version == 0
                || record.max_payload_len == 0
                || record.state != PacketDeviceObjectState::Registered
                || device_record.state != DeviceObjectState::Registered
                || device_record.class != "packet-device"
                || !self.domains.resource.resources.iter().any(|resource| {
                    resource.id == device_record.resource
                        && resource.generation == device_record.resource_generation
                        && resource.kind == ResourceKind::PacketDevice
                        && resource.live
                })
            {
                return Err(SemanticInvariantError::PacketDeviceObjectInvalid {
                    packet_device: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::PacketDeviceObjectRecorded {
                            packet_device,
                            device,
                            device_generation,
                            mtu,
                            rx_queue_depth,
                            tx_queue_depth,
                            frame_format_version,
                            max_payload_len,
                            generation,
                        } if *packet_device == record.id
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *mtu == record.mtu
                            && *rx_queue_depth == record.rx_queue_depth
                            && *tx_queue_depth == record.tx_queue_depth
                            && *frame_format_version == record.frame_format_version
                            && *max_payload_len == record.max_payload_len
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::PacketDeviceObjectMissingEvent {
                    packet_device: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_packet_device_object_device_generation_for_test(
        &mut self,
        packet_device: PacketDeviceObjectId,
        device_generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .network
            .packet_device_objects
            .iter_mut()
            .find(|record| record.id == packet_device)
        {
            record.device_generation = device_generation;
        }
    }
}
