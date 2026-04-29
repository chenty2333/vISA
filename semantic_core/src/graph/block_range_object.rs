use super::*;

impl SemanticGraph {
    pub(crate) fn validate_block_range_object(
        &self,
        block_range: BlockRangeObjectId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        start_sector: u64,
        sector_count: u64,
    ) -> Result<(u64, u64), &'static str> {
        if block_range == 0 {
            return Err("block range object id=0 is invalid");
        }
        if self.block_range_objects.iter().any(|record| record.id == block_range) {
            return Err("block range object already exists");
        }
        if block_device_generation == 0 || sector_count == 0 {
            return Err("block range object identity values must be nonzero");
        }
        let Some(block_device_record) = self.block_device_objects.iter().find(|record| {
            record.id == block_device
                && record.generation == block_device_generation
                && record.state == BlockDeviceObjectState::Registered
        }) else {
            return Err("block range object block device generation is missing or inactive");
        };
        if start_sector >= block_device_record.sector_count {
            return Err("block range object starts outside block device");
        }
        if sector_count > block_device_record.sector_count.saturating_sub(start_sector) {
            return Err("block range object extends beyond block device");
        }
        if sector_count > u64::from(block_device_record.max_transfer_sectors) {
            return Err("block range object exceeds max transfer sectors");
        }
        let byte_offset = start_sector
            .checked_mul(u64::from(block_device_record.sector_size))
            .ok_or("block range object byte offset overflow")?;
        let byte_len = sector_count
            .checked_mul(u64::from(block_device_record.sector_size))
            .ok_or("block range object byte length overflow")?;
        if self.check_invariants().is_err() {
            return Err("block range object requires invariant-clean graph");
        }
        Ok((byte_offset, byte_len))
    }

    pub fn record_block_range_object_with_id(
        &mut self,
        block_range: BlockRangeObjectId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        start_sector: u64,
        sector_count: u64,
        note: &str,
    ) -> bool {
        let Ok((byte_offset, byte_len)) = self.validate_block_range_object(
            block_range,
            block_device,
            block_device_generation,
            start_sector,
            sector_count,
        ) else {
            return false;
        };
        let generation = 1;
        self.next_block_range_object_id =
            self.next_block_range_object_id.max(block_range.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockRangeObjectRecorded {
                block_range,
                block_device,
                block_device_generation,
                start_sector,
                sector_count,
                byte_offset,
                byte_len,
                generation,
            },
        );
        self.block_range_objects.push(BlockRangeObjectRecord {
            id: block_range,
            block_device,
            block_device_generation,
            start_sector,
            sector_count,
            byte_offset,
            byte_len,
            generation,
            state: BlockRangeObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn block_range_objects(&self) -> &[BlockRangeObjectRecord] {
        &self.block_range_objects
    }

    pub fn block_range_object_count(&self) -> usize {
        self.block_range_objects.len()
    }

    pub fn check_block_range_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.block_range_objects {
            let Some(block_device_record) = self.block_device_objects.iter().find(|block_device| {
                block_device.id == record.block_device
                    && block_device.generation == record.block_device_generation
            }) else {
                return Err(SemanticInvariantError::BlockRangeObjectMissingDevice {
                    block_range: record.id,
                    block_device: record.block_device,
                });
            };
            let expected_byte_offset =
                record.start_sector.checked_mul(u64::from(block_device_record.sector_size));
            let expected_byte_len =
                record.sector_count.checked_mul(u64::from(block_device_record.sector_size));
            if record.id == 0
                || record.generation == 0
                || record.block_device_generation == 0
                || record.sector_count == 0
                || record.start_sector >= block_device_record.sector_count
                || record.sector_count
                    > block_device_record.sector_count.saturating_sub(record.start_sector)
                || record.sector_count > u64::from(block_device_record.max_transfer_sectors)
                || expected_byte_offset != Some(record.byte_offset)
                || expected_byte_len != Some(record.byte_len)
                || record.state != BlockRangeObjectState::Registered
                || block_device_record.state != BlockDeviceObjectState::Registered
            {
                return Err(SemanticInvariantError::BlockRangeObjectInvalid {
                    block_range: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockRangeObjectRecorded {
                            block_range,
                            block_device,
                            block_device_generation,
                            start_sector,
                            sector_count,
                            byte_offset,
                            byte_len,
                            generation,
                        } if *block_range == record.id
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *start_sector == record.start_sector
                            && *sector_count == record.sector_count
                            && *byte_offset == record.byte_offset
                            && *byte_len == record.byte_len
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockRangeObjectMissingEvent {
                    block_range: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_range_object_device_generation_for_test(
        &mut self,
        block_range: BlockRangeObjectId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.block_range_objects.iter_mut().find(|record| record.id == block_range)
        {
            record.block_device_generation = generation;
        }
    }
}
