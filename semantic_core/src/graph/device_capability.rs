use super::*;

impl SemanticGraph {
    pub(crate) fn validate_device_capability(
        &self,
        device_capability: DeviceCapabilityId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        target: ContractObjectRef,
        class: CapabilityClass,
        operation: &str,
        handle: &CapabilityHandle,
    ) -> Result<CapabilityId, &'static str> {
        if device_capability == 0 {
            return Err("device capability id=0 is invalid");
        }
        if self
            .device_capabilities
            .iter()
            .any(|record| record.id == device_capability)
        {
            return Err("device capability already exists");
        }
        if operation.is_empty() {
            return Err("device capability operation is empty");
        }
        let Some(store_record) = self
            .stores
            .iter()
            .find(|store| store.id == driver_store && store.generation == driver_store_generation)
        else {
            return Err("device capability driver store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("device capability driver store is dead");
        }
        if store_record.role != "driver" {
            return Err("device capability driver store role is not driver");
        }
        if !self.device_capability_target_exists(target, class) {
            return Err("device capability target generation is missing or inactive");
        }
        let authority = AuthorityObjectRef::internal(class, target);
        let record = self
            .capabilities
            .check_authority(&store_record.package, authority, operation, Some(handle))
            .map_err(|_| "device capability handle is not authorized")?;
        if record.owner_store != Some(driver_store)
            || record.owner_store_generation != Some(driver_store_generation)
        {
            return Err("device capability owner store generation mismatch");
        }
        if self.device_capabilities.iter().any(|record| {
            record.driver_store == driver_store
                && record.driver_store_generation == driver_store_generation
                && record.target == target
                && record.operation == operation
                && record.state == DeviceCapabilityState::Active
        }) {
            return Err("device capability target operation already has an active grant");
        }
        if self.check_invariants().is_err() {
            return Err("device capability requires invariant-clean graph");
        }
        Ok(record.id)
    }

    pub fn record_device_capability_with_id(
        &mut self,
        device_capability: DeviceCapabilityId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        target: ContractObjectRef,
        class: CapabilityClass,
        operation: &str,
        handle: CapabilityHandle,
        note: &str,
    ) -> bool {
        let Ok(capability) = self.validate_device_capability(
            device_capability,
            driver_store,
            driver_store_generation,
            target,
            class,
            operation,
            &handle,
        ) else {
            return false;
        };
        let Some(capability_record) = self.capabilities.record(capability) else {
            return false;
        };
        let generation = 1;
        self.next_device_capability_id = self.next_device_capability_id.max(device_capability + 1);
        let recorded_at_event = self.event_log.push(
            "io",
            EventKind::DeviceCapabilityRecorded {
                device_capability,
                driver_store,
                driver_store_generation,
                target,
                class,
                operation: operation.to_string(),
                capability,
                capability_generation: capability_record.generation,
                handle_slot: handle.slot,
                handle_generation: handle.generation,
                generation,
            },
        );
        self.device_capabilities.push(DeviceCapabilityRecord {
            id: device_capability,
            driver_store,
            driver_store_generation,
            target,
            class,
            operation: operation.to_string(),
            capability,
            capability_generation: capability_record.generation,
            handle_slot: handle.slot,
            handle_generation: handle.generation,
            handle_tag: handle.tag,
            generation,
            state: DeviceCapabilityState::Active,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn device_capabilities(&self) -> &[DeviceCapabilityRecord] {
        &self.device_capabilities
    }

    pub fn device_capability_count(&self) -> usize {
        self.device_capabilities.len()
    }

    pub fn check_device_capability_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.device_capabilities {
            let Some(store_record) = self.stores.iter().find(|store| {
                store.id == record.driver_store
                    && store.generation == record.driver_store_generation
            }) else {
                return Err(SemanticInvariantError::DeviceCapabilityMissingStore {
                    device_capability: record.id,
                    store: record.driver_store,
                });
            };
            if !self.device_capability_target_exists(record.target, record.class) {
                return Err(SemanticInvariantError::DeviceCapabilityMissingTarget {
                    device_capability: record.id,
                    target: record.target,
                });
            }
            let Some(capability_record) = self.capabilities.record(record.capability) else {
                return Err(SemanticInvariantError::DeviceCapabilityMissingCapability {
                    device_capability: record.id,
                    capability: record.capability,
                });
            };
            let authority = AuthorityObjectRef::internal(record.class, record.target);
            if record.id == 0
                || record.generation == 0
                || record.driver_store_generation == 0
                || record.target.generation == 0
                || record.operation.is_empty()
                || record.capability_generation == 0
                || store_record.state == StoreState::Dead
                || store_record.role != "driver"
                || record.state != DeviceCapabilityState::Active
                || capability_record.generation != record.capability_generation
                || capability_record.revoked
                || capability_record.subject != store_record.package
                || capability_record.object_ref != Some(authority)
                || capability_record.owner_store != Some(record.driver_store)
                || capability_record.owner_store_generation != Some(record.driver_store_generation)
                || capability_record.handle_slot != record.handle_slot
                || capability_record.handle_generation != record.handle_generation
                || capability_record.handle_tag != record.handle_tag
                || !capability_record.operations.contains(&record.operation)
                || (capability_record.class.requires_manifest_declaration()
                    && !capability_record.manifest_decl)
            {
                return Err(SemanticInvariantError::DeviceCapabilityInvalid {
                    device_capability: record.id,
                });
            }
            if let Some(duplicate) = self.device_capabilities.iter().find(|other| {
                other.id != record.id
                    && other.driver_store == record.driver_store
                    && other.driver_store_generation == record.driver_store_generation
                    && other.target == record.target
                    && other.operation == record.operation
                    && other.state == DeviceCapabilityState::Active
            }) {
                return Err(SemanticInvariantError::DeviceCapabilityDuplicateTarget {
                    device_capability: duplicate.id,
                    target: record.target,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DeviceCapabilityRecorded {
                            device_capability,
                            driver_store,
                            driver_store_generation,
                            target,
                            class,
                            operation,
                            capability,
                            capability_generation,
                            handle_slot,
                            handle_generation,
                            generation,
                        } if *device_capability == record.id
                            && *driver_store == record.driver_store
                            && *driver_store_generation == record.driver_store_generation
                            && *target == record.target
                            && *class == record.class
                            && operation == &record.operation
                            && *capability == record.capability
                            && *capability_generation == record.capability_generation
                            && *handle_slot == record.handle_slot
                            && *handle_generation == record.handle_generation
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::DeviceCapabilityMissingEvent {
                    device_capability: record.id,
                });
            }
        }
        Ok(())
    }

    fn device_capability_target_exists(
        &self,
        target: ContractObjectRef,
        class: CapabilityClass,
    ) -> bool {
        match (class, target.kind) {
            (CapabilityClass::Device, ContractObjectKind::DeviceObject) => {
                self.device_objects.iter().any(|record| {
                    record.object_ref() == target && record.state == DeviceObjectState::Registered
                })
            }
            (CapabilityClass::DmaBuffer, ContractObjectKind::DmaBufferObject) => {
                self.dma_buffer_objects.iter().any(|record| {
                    record.object_ref() == target
                        && record.state == DmaBufferObjectState::Registered
                })
            }
            (CapabilityClass::MmioRegion, ContractObjectKind::MmioRegionObject) => {
                self.mmio_region_objects.iter().any(|record| {
                    record.object_ref() == target
                        && record.state == MmioRegionObjectState::Registered
                })
            }
            (CapabilityClass::IrqLine, ContractObjectKind::IrqLineObject) => {
                self.irq_line_objects.iter().any(|record| {
                    record.object_ref() == target && record.state == IrqLineObjectState::Registered
                })
            }
            _ => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_device_capability_target_generation_for_test(
        &mut self,
        device_capability: DeviceCapabilityId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .device_capabilities
            .iter_mut()
            .find(|record| record.id == device_capability)
        {
            record.target.generation = generation;
        }
    }
}
