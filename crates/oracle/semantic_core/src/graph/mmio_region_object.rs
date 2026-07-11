use super::*;

impl SemanticGraph {
    pub(crate) fn validate_mmio_region_object(
        &self,
        mmio_region: MmioRegionObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        region_index: u16,
        offset: u64,
        length: u64,
        access: MmioRegionObjectAccess,
    ) -> Result<(), &'static str> {
        if mmio_region == 0 {
            return Err("mmio region object id=0 is invalid");
        }
        if self.domains.device.mmio_region_objects.iter().any(|record| record.id == mmio_region) {
            return Err("mmio region object already exists");
        }
        if length == 0 {
            return Err("mmio region object length is zero");
        }
        if offset.checked_add(length).is_none() {
            return Err("mmio region object range overflows");
        }
        if !Self::mmio_region_access_is_supported(access) {
            return Err("mmio region object access is unsupported");
        }
        let Some(device_record) = self.domains.device.device_objects.iter().find(|record| {
            record.id == device
                && record.generation == device_generation
                && record.state == DeviceObjectState::Registered
        }) else {
            return Err("mmio region object device generation is missing or inactive");
        };
        let Some(resource_record) =
            self.domains.resource.resources.iter().find(|record| record.id == resource)
        else {
            return Err("mmio region object resource is missing");
        };
        if resource_record.generation != resource_generation {
            return Err("mmio region object resource generation mismatch");
        }
        if !resource_record.live {
            return Err("mmio region object resource is dead");
        }
        if resource_record.kind != ResourceKind::MmioRegion {
            return Err("mmio region object resource kind is not mmio-region");
        }
        if self.domains.device.mmio_region_objects.iter().any(|record| {
            record.device == device_record.id
                && record.device_generation == device_generation
                && record.region_index == region_index
                && record.state == MmioRegionObjectState::Registered
        }) {
            return Err("mmio region object index already exists for device generation");
        }
        if self.check_invariants().is_err() {
            return Err("mmio region object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_mmio_region_object_with_id(
        &mut self,
        mmio_region: MmioRegionObjectId,
        device: DeviceObjectId,
        device_generation: Generation,
        resource: ResourceId,
        resource_generation: Generation,
        region_index: u16,
        offset: u64,
        length: u64,
        access: MmioRegionObjectAccess,
        note: &str,
    ) -> bool {
        if self
            .validate_mmio_region_object(
                mmio_region,
                device,
                device_generation,
                resource,
                resource_generation,
                region_index,
                offset,
                length,
                access,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.domains.device.next_mmio_region_object_id =
            self.domains.device.next_mmio_region_object_id.max(mmio_region + 1);
        let recorded_at_event = self.event_log.push(
            "io",
            EventKind::MmioRegionObjectRecorded {
                mmio_region,
                device,
                device_generation,
                resource,
                resource_generation,
                region_index,
                offset,
                length,
                access,
                generation,
            },
        );
        self.domains.device.mmio_region_objects.push(MmioRegionObjectRecord {
            id: mmio_region,
            device,
            device_generation,
            resource,
            resource_generation,
            region_index,
            offset,
            length,
            access,
            generation,
            state: MmioRegionObjectState::Registered,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn mmio_region_objects(&self) -> &[MmioRegionObjectRecord] {
        &self.domains.device.mmio_region_objects
    }

    pub fn mmio_region_object_count(&self) -> usize {
        self.domains.device.mmio_region_objects.len()
    }

    pub fn check_mmio_region_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.device.mmio_region_objects {
            let Some(device_record) = self.domains.device.device_objects.iter().find(|device| {
                device.id == record.device && device.generation == record.device_generation
            }) else {
                return Err(SemanticInvariantError::MmioRegionObjectMissingDevice {
                    mmio_region: record.id,
                    device: record.device,
                });
            };
            let Some(resource_record) = self.domains.resource.resources.iter().find(|resource| {
                resource.id == record.resource && resource.generation == record.resource_generation
            }) else {
                return Err(SemanticInvariantError::MmioRegionObjectMissingResource {
                    mmio_region: record.id,
                    resource: record.resource,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.length == 0
                || record.offset.checked_add(record.length).is_none()
                || record.device_generation == 0
                || record.resource_generation == 0
                || resource_record.kind != ResourceKind::MmioRegion
                || !matches!(
                    record.state,
                    MmioRegionObjectState::Registered | MmioRegionObjectState::Released
                )
                || (record.state == MmioRegionObjectState::Registered
                    && (device_record.state != DeviceObjectState::Registered
                        || !resource_record.live))
                || !Self::mmio_region_access_is_supported(record.access)
            {
                return Err(SemanticInvariantError::MmioRegionObjectInvalid {
                    mmio_region: record.id,
                });
            }
            if let Some(duplicate) = self.domains.device.mmio_region_objects.iter().find(|other| {
                other.id != record.id
                    && other.device == record.device
                    && other.device_generation == record.device_generation
                    && other.region_index == record.region_index
                    && other.state == MmioRegionObjectState::Registered
            }) {
                return Err(SemanticInvariantError::MmioRegionObjectDuplicateIndex {
                    mmio_region: duplicate.id,
                    device: record.device,
                    region_index: record.region_index,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::MmioRegionObjectRecorded {
                            mmio_region,
                            device,
                            device_generation,
                            resource,
                            resource_generation,
                            region_index,
                            offset,
                            length,
                            access,
                            generation,
                        } if *mmio_region == record.id
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *resource == record.resource
                            && *resource_generation == record.resource_generation
                            && *region_index == record.region_index
                            && *offset == record.offset
                            && *length == record.length
                            && *access == record.access
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::MmioRegionObjectMissingEvent {
                    mmio_region: record.id,
                });
            }
        }
        Ok(())
    }

    const fn mmio_region_access_is_supported(access: MmioRegionObjectAccess) -> bool {
        matches!(
            access,
            MmioRegionObjectAccess::ReadOnly
                | MmioRegionObjectAccess::WriteOnly
                | MmioRegionObjectAccess::ReadWrite
        )
    }

    #[cfg(test)]
    pub(crate) fn corrupt_mmio_region_object_device_generation_for_test(
        &mut self,
        mmio_region: MmioRegionObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .domains
            .device
            .mmio_region_objects
            .iter_mut()
            .find(|record| record.id == mmio_region)
        {
            record.device_generation = generation;
        }
    }
}
