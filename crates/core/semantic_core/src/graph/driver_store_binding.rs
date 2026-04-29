use super::*;

impl SemanticGraph {
    pub(crate) fn validate_driver_store_binding(
        &self,
        binding: DriverStoreBindingId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        device_capability: DeviceCapabilityId,
        device_capability_generation: Generation,
    ) -> Result<(), &'static str> {
        if binding == 0 {
            return Err("driver store binding id=0 is invalid");
        }
        if self.driver_store_bindings.iter().any(|record| record.id == binding) {
            return Err("driver store binding already exists");
        }
        let Some(store_record) = self.stores.iter().find(|record| {
            record.id == driver_store && record.generation == driver_store_generation
        }) else {
            return Err("driver store binding store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("driver store binding store is dead");
        }
        if store_record.role != "driver" {
            return Err("driver store binding store role is not driver");
        }
        let device_ref =
            ContractObjectRef::new(ContractObjectKind::DeviceObject, device, device_generation);
        if !self.device_objects.iter().any(|record| {
            record.object_ref() == device_ref && record.state == DeviceObjectState::Registered
        }) {
            return Err("driver store binding device generation is missing or inactive");
        }
        let Some(capability_evidence) = self.device_capabilities.iter().find(|record| {
            record.id == device_capability
                && record.generation == device_capability_generation
                && record.state == DeviceCapabilityState::Active
        }) else {
            return Err("driver store binding device capability generation is missing or inactive");
        };
        if capability_evidence.driver_store != driver_store
            || capability_evidence.driver_store_generation != driver_store_generation
            || capability_evidence.target != device_ref
            || capability_evidence.class != CapabilityClass::Device
            || !is_driver_binding_operation(&capability_evidence.operation)
        {
            return Err("driver store binding device capability does not authorize binding");
        }
        let Some(capability_record) =
            self.domains.capability.capabilities.record(capability_evidence.capability)
        else {
            return Err("driver store binding capability record is missing");
        };
        let authority = AuthorityObjectRef::internal(CapabilityClass::Device, device_ref);
        if capability_record.generation != capability_evidence.capability_generation
            || capability_record.revoked
            || capability_record.subject != store_record.package
            || capability_record.object_ref != Some(authority)
            || capability_record.owner_store != Some(driver_store)
            || capability_record.owner_store_generation != Some(driver_store_generation)
            || !capability_record.operations.contains(&capability_evidence.operation)
        {
            return Err("driver store binding capability record is not active for device");
        }
        if self.driver_store_bindings.iter().any(|record| {
            record.device == device
                && record.device_generation == device_generation
                && record.state == DriverStoreBindingState::Bound
        }) {
            return Err("driver store binding device already has an active driver");
        }
        if self.check_invariants().is_err() {
            return Err("driver store binding requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_driver_store_binding_with_id(
        &mut self,
        binding: DriverStoreBindingId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        device_capability: DeviceCapabilityId,
        device_capability_generation: Generation,
        note: &str,
    ) -> bool {
        if self
            .validate_driver_store_binding(
                binding,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                device_capability,
                device_capability_generation,
            )
            .is_err()
        {
            return false;
        }
        let Some(capability_evidence) = self.device_capabilities.iter().find(|record| {
            record.id == device_capability && record.generation == device_capability_generation
        }) else {
            return false;
        };
        let generation = 1;
        self.next_driver_store_binding_id = self.next_driver_store_binding_id.max(binding + 1);
        let recorded_at_event = self.event_log.push(
            "io",
            EventKind::DriverStoreBound {
                binding,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                device_capability,
                device_capability_generation,
                capability: capability_evidence.capability,
                capability_generation: capability_evidence.capability_generation,
                generation,
            },
        );
        self.driver_store_bindings.push(DriverStoreBindingRecord {
            id: binding,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            device_capability,
            device_capability_generation,
            capability: capability_evidence.capability,
            capability_generation: capability_evidence.capability_generation,
            generation,
            state: DriverStoreBindingState::Bound,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn driver_store_bindings(&self) -> &[DriverStoreBindingRecord] {
        &self.driver_store_bindings
    }

    pub fn driver_store_binding_count(&self) -> usize {
        self.driver_store_bindings.len()
    }

    pub fn check_driver_store_binding_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.driver_store_bindings {
            let Some(store_record) = self.stores.iter().find(|store| {
                store.id == record.driver_store
                    && store.generation == record.driver_store_generation
            }) else {
                return Err(SemanticInvariantError::DriverStoreBindingMissingStore {
                    binding: record.id,
                    store: record.driver_store,
                });
            };
            let device_ref = ContractObjectRef::new(
                ContractObjectKind::DeviceObject,
                record.device,
                record.device_generation,
            );
            let Some(device_record) =
                self.device_objects.iter().find(|device| device.object_ref() == device_ref)
            else {
                return Err(SemanticInvariantError::DriverStoreBindingMissingDevice {
                    binding: record.id,
                    device: record.device,
                });
            };
            let Some(device_capability) = self.device_capabilities.iter().find(|capability| {
                capability.id == record.device_capability
                    && capability.generation == record.device_capability_generation
            }) else {
                return Err(SemanticInvariantError::DriverStoreBindingMissingCapabilityEvidence {
                    binding: record.id,
                    device_capability: record.device_capability,
                });
            };
            let bound = record.state == DriverStoreBindingState::Bound;
            let released = record.state == DriverStoreBindingState::Released;
            if record.id == 0
                || record.generation == 0
                || record.driver_store_generation == 0
                || record.device_generation == 0
                || record.device_capability_generation == 0
                || record.capability_generation == 0
                || store_record.role != "driver"
                || device_record.state != DeviceObjectState::Registered
                || (!bound && !released)
                || (bound && store_record.state == StoreState::Dead)
                || (bound && device_capability.state != DeviceCapabilityState::Active)
                || (released && device_capability.state != DeviceCapabilityState::Revoked)
                || device_capability.driver_store != record.driver_store
                || device_capability.driver_store_generation != record.driver_store_generation
                || device_capability.target != device_ref
                || device_capability.class != CapabilityClass::Device
                || !is_driver_binding_operation(&device_capability.operation)
                || device_capability.capability != record.capability
                || device_capability.capability_generation != record.capability_generation
            {
                return Err(SemanticInvariantError::DriverStoreBindingInvalid {
                    binding: record.id,
                });
            }
            if let Some(duplicate) = self.driver_store_bindings.iter().find(|other| {
                other.id != record.id
                    && other.device == record.device
                    && other.device_generation == record.device_generation
                    && other.state == DriverStoreBindingState::Bound
            }) {
                return Err(SemanticInvariantError::DriverStoreBindingDuplicateDevice {
                    binding: duplicate.id,
                    device: record.device,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::DriverStoreBound {
                            binding,
                            driver_store,
                            driver_store_generation,
                            device,
                            device_generation,
                            device_capability,
                            device_capability_generation,
                            capability,
                            capability_generation,
                            generation,
                        } if *binding == record.id
                            && *driver_store == record.driver_store
                            && *driver_store_generation == record.driver_store_generation
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *device_capability == record.device_capability
                            && *device_capability_generation == record.device_capability_generation
                            && *capability == record.capability
                            && *capability_generation == record.capability_generation
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::DriverStoreBindingMissingEvent {
                    binding: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_driver_store_binding_device_generation_for_test(
        &mut self,
        binding: DriverStoreBindingId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.driver_store_bindings.iter_mut().find(|record| record.id == binding)
        {
            record.device_generation = generation;
        }
    }
}

fn is_driver_binding_operation(operation: &str) -> bool {
    matches!(operation, "probe" | "bind-driver")
}
