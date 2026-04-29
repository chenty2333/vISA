use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_block_device_object(
        &self,
        block_device: BlockDeviceObjectId,
        name: &str,
        device: DeviceObjectId,
        device_generation: Generation,
        sector_size: u32,
        sector_count: u64,
        max_transfer_sectors: u32,
    ) -> Result<(), &'static str> {
        if block_device == 0 {
            return Err("block device object id=0 is invalid");
        }
        if self.block_device_objects.iter().any(|record| record.id == block_device) {
            return Err("block device object already exists");
        }
        if name.is_empty() {
            return Err("block device object name is empty");
        }
        if sector_size == 0 || sector_count == 0 || max_transfer_sectors == 0 {
            return Err("block device object contract values must be nonzero");
        }
        if !sector_size.is_power_of_two() || sector_size < 512 {
            return Err("block device object sector size is unsupported");
        }
        let Some(device_record) = self
            .device_objects
            .iter()
            .find(|record| record.id == device && record.generation == device_generation)
        else {
            return Err("block device object device generation is missing");
        };
        if device_record.state != DeviceObjectState::Registered {
            return Err("block device object device is not registered");
        }
        if device_record.class != "block-device" {
            return Err("block device object device class is not block-device");
        }
        if !self.resources.iter().any(|resource| {
            resource.id == device_record.resource
                && resource.generation == device_record.resource_generation
                && resource.kind == ResourceKind::BlockDevice
                && resource.live
        }) {
            return Err("block device object must be backed by live block device resource");
        }
        if self.check_invariants().is_err() {
            return Err("block device object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_block_device_object_with_id(
        &mut self,
        block_device: BlockDeviceObjectId,
        name: &str,
        device: DeviceObjectId,
        device_generation: Generation,
        sector_size: u32,
        sector_count: u64,
        read_only: bool,
        max_transfer_sectors: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_block_device_object(
                block_device,
                name,
                device,
                device_generation,
                sector_size,
                sector_count,
                max_transfer_sectors,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_block_device_object_id =
            self.next_block_device_object_id.max(block_device.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockDeviceObjectRecorded {
                block_device,
                device,
                device_generation,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                generation,
            },
        );
        self.block_device_objects.push(BlockDeviceObjectRecord {
            id: block_device,
            name: name.to_string(),
            device,
            device_generation,
            sector_size,
            sector_count,
            read_only,
            max_transfer_sectors,
            generation,
            state: BlockDeviceObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn block_device_objects(&self) -> &[BlockDeviceObjectRecord] {
        &self.block_device_objects
    }

    pub fn block_device_object_count(&self) -> usize {
        self.block_device_objects.len()
    }

    pub fn check_block_device_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.block_device_objects {
            let Some(device_record) = self.device_objects.iter().find(|device| {
                device.id == record.device && device.generation == record.device_generation
            }) else {
                return Err(SemanticInvariantError::BlockDeviceObjectMissingDevice {
                    block_device: record.id,
                    device: record.device,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.sector_size == 0
                || !record.sector_size.is_power_of_two()
                || record.sector_size < 512
                || record.sector_count == 0
                || record.max_transfer_sectors == 0
                || record.state != BlockDeviceObjectState::Registered
                || device_record.state != DeviceObjectState::Registered
                || device_record.class != "block-device"
                || !self.resources.iter().any(|resource| {
                    resource.id == device_record.resource
                        && resource.generation == device_record.resource_generation
                        && resource.kind == ResourceKind::BlockDevice
                        && resource.live
                })
            {
                return Err(SemanticInvariantError::BlockDeviceObjectInvalid {
                    block_device: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockDeviceObjectRecorded {
                            block_device,
                            device,
                            device_generation,
                            sector_size,
                            sector_count,
                            read_only,
                            max_transfer_sectors,
                            generation,
                        } if *block_device == record.id
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *sector_size == record.sector_size
                            && *sector_count == record.sector_count
                            && *read_only == record.read_only
                            && *max_transfer_sectors == record.max_transfer_sectors
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockDeviceObjectMissingEvent {
                    block_device: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_device_object_device_generation_for_test(
        &mut self,
        block_device: BlockDeviceObjectId,
        device_generation: Generation,
    ) {
        if let Some(record) =
            self.block_device_objects.iter_mut().find(|record| record.id == block_device)
        {
            record.device_generation = device_generation;
        }
    }
}
