use super::*;

impl SemanticGraph {
    pub(crate) fn validate_io_fault_injection(
        &self,
        fault: IoFaultInjectionId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        target: ContractObjectRef,
        cleanup: IoCleanupId,
        kind: IoFaultInjectionKind,
    ) -> Result<(), &'static str> {
        if fault == 0 {
            return Err("io fault injection id=0 is invalid");
        }
        if cleanup == 0 {
            return Err("io fault injection cleanup id=0 is invalid");
        }
        if self.domains.io.io_fault_injections.iter().any(|record| {
            record.id == fault
                && (record.driver_store != driver_store
                    || record.driver_store_generation != driver_store_generation
                    || record.device != device
                    || record.device_generation != device_generation
                    || record.driver_binding != driver_binding
                    || record.driver_binding_generation != driver_binding_generation
                    || record.target != target
                    || record.cleanup != cleanup
                    || record.kind != kind)
        }) {
            return Err("io fault injection id is already used for a different target");
        }
        if self.domains.io.io_fault_injections.iter().any(|record| {
            record.id == fault
                && record.driver_store == driver_store
                && record.driver_store_generation == driver_store_generation
                && record.device == device
                && record.device_generation == device_generation
                && record.driver_binding == driver_binding
                && record.driver_binding_generation == driver_binding_generation
                && record.target == target
                && record.cleanup == cleanup
                && record.kind == kind
                && record.state == IoFaultInjectionState::Completed
        }) {
            return Ok(());
        }
        let Some(store) = self.domains.lifecycle.stores.iter().find(|record| {
            record.id == driver_store && record.generation == driver_store_generation
        }) else {
            return Err("io fault injection driver store generation is missing");
        };
        if store.role != "driver" || store.state == StoreState::Dead {
            return Err("io fault injection store is not a live driver");
        }
        if !self.domains.device.device_objects.iter().any(|record| {
            record.id == device
                && record.generation == device_generation
                && record.state == DeviceObjectState::Registered
        }) {
            return Err("io fault injection device generation is missing or inactive");
        }
        let Some(binding) = self.domains.device.driver_store_bindings.iter().find(|record| {
            record.id == driver_binding && record.generation == driver_binding_generation
        }) else {
            return Err("io fault injection driver binding generation is missing");
        };
        if binding.state != DriverStoreBindingState::Bound
            || binding.driver_store != driver_store
            || binding.driver_store_generation != driver_store_generation
            || binding.device != device
            || binding.device_generation != device_generation
        {
            return Err("io fault injection driver binding is not bound to target");
        }
        if !self.io_fault_target_is_active_for_device(target, device, device_generation) {
            return Err("io fault injection target generation is missing or inactive");
        }
        if kind != IoFaultInjectionKind::DeviceFault {
            return Err("io fault injection kind is unsupported");
        }
        if self.check_invariants().is_err() {
            return Err("io fault injection requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn inject_io_fault_with_id(
        &mut self,
        fault: IoFaultInjectionId,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        target: ContractObjectRef,
        cleanup: IoCleanupId,
        kind: IoFaultInjectionKind,
        note: &str,
    ) -> bool {
        if self
            .validate_io_fault_injection(
                fault,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                target,
                cleanup,
                kind,
            )
            .is_err()
        {
            return false;
        }
        if self.domains.io.io_fault_injections.iter().any(|record| {
            record.id == fault
                && record.driver_store == driver_store
                && record.driver_store_generation == driver_store_generation
                && record.device == device
                && record.device_generation == device_generation
                && record.driver_binding == driver_binding
                && record.driver_binding_generation == driver_binding_generation
                && record.target == target
                && record.cleanup == cleanup
                && record.kind == kind
                && record.state == IoFaultInjectionState::Completed
        }) {
            return true;
        }
        if !self.cleanup_io_driver_for_device_fault_with_id(
            cleanup,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            driver_binding,
            driver_binding_generation,
            kind.as_str(),
            note,
        ) {
            return false;
        }
        let Some(cleanup_generation) = self
            .domains
            .io
            .io_cleanups
            .iter()
            .find(|record| record.id == cleanup)
            .map(|record| record.generation)
        else {
            return false;
        };
        let generation = 1;
        self.domains.io.next_io_fault_injection_id =
            self.domains.io.next_io_fault_injection_id.max(fault + 1);
        let injected_at_event = self.event_log.push(
            "io",
            EventKind::IoFaultInjected {
                fault,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                target,
                cleanup,
                cleanup_generation,
                kind,
                generation,
            },
        );
        self.domains.io.io_fault_injections.push(IoFaultInjectionRecord {
            id: fault,
            driver_store,
            driver_store_generation,
            device,
            device_generation,
            driver_binding,
            driver_binding_generation,
            target,
            cleanup,
            cleanup_generation,
            generation,
            kind,
            state: IoFaultInjectionState::Completed,
            injected_at_event,
            note: note.to_string(),
        });
        self.check_invariants().is_ok()
    }

    pub fn io_fault_injections(&self) -> &[IoFaultInjectionRecord] {
        &self.domains.io.io_fault_injections
    }

    pub fn io_fault_injection_count(&self) -> usize {
        self.domains.io.io_fault_injections.len()
    }

    fn io_fault_target_is_active_for_device(
        &self,
        target: ContractObjectRef,
        device: DeviceObjectId,
        device_generation: Generation,
    ) -> bool {
        match target.kind {
            ContractObjectKind::DeviceObject => {
                self.domains.device.device_objects.iter().any(|record| {
                    record.id == target.id
                        && record.generation == target.generation
                        && record.id == device
                        && record.generation == device_generation
                        && record.state == DeviceObjectState::Registered
                })
            }
            ContractObjectKind::DmaBufferObject => {
                self.domains.device.dma_buffer_objects.iter().any(|record| {
                    record.id == target.id
                        && record.generation == target.generation
                        && record.state == DmaBufferObjectState::Registered
                }) && self.io_cleanup_dma_buffer_belongs_to_device(
                    target.id,
                    target.generation,
                    device,
                    device_generation,
                )
            }
            ContractObjectKind::MmioRegionObject => {
                self.domains.device.mmio_region_objects.iter().any(|record| {
                    record.id == target.id
                        && record.generation == target.generation
                        && record.device == device
                        && record.device_generation == device_generation
                        && record.state == MmioRegionObjectState::Registered
                })
            }
            ContractObjectKind::IrqLineObject => {
                self.domains.device.irq_line_objects.iter().any(|record| {
                    record.id == target.id
                        && record.generation == target.generation
                        && record.device == device
                        && record.device_generation == device_generation
                        && record.state == IrqLineObjectState::Registered
                })
            }
            _ => false,
        }
    }

    fn io_fault_target_generation_belongs_to_device(
        &self,
        target: ContractObjectRef,
        device: DeviceObjectId,
        device_generation: Generation,
    ) -> bool {
        match target.kind {
            ContractObjectKind::DeviceObject => {
                self.domains.device.device_objects.iter().any(|record| {
                    record.id == target.id
                        && record.generation == target.generation
                        && record.id == device
                        && record.generation == device_generation
                })
            }
            ContractObjectKind::DmaBufferObject => self.io_cleanup_dma_buffer_belongs_to_device(
                target.id,
                target.generation,
                device,
                device_generation,
            ),
            ContractObjectKind::MmioRegionObject => {
                self.domains.device.mmio_region_objects.iter().any(|record| {
                    record.id == target.id
                        && record.generation == target.generation
                        && record.device == device
                        && record.device_generation == device_generation
                })
            }
            ContractObjectKind::IrqLineObject => {
                self.domains.device.irq_line_objects.iter().any(|record| {
                    record.id == target.id
                        && record.generation == target.generation
                        && record.device == device
                        && record.device_generation == device_generation
                })
            }
            _ => false,
        }
    }

    pub fn check_io_fault_injection_invariants(&self) -> Result<(), SemanticInvariantError> {
        for fault in &self.domains.io.io_fault_injections {
            if fault.id == 0
                || fault.generation == 0
                || fault.driver_store_generation == 0
                || fault.device_generation == 0
                || fault.driver_binding_generation == 0
                || fault.cleanup_generation == 0
                || fault.state != IoFaultInjectionState::Completed
                || fault.kind != IoFaultInjectionKind::DeviceFault
            {
                return Err(SemanticInvariantError::IoFaultInjectionInvalid { fault: fault.id });
            }
            if !self.domains.lifecycle.stores.iter().any(|store| {
                store.id == fault.driver_store
                    && store.generation == fault.driver_store_generation
                    && store.role == "driver"
            }) {
                return Err(SemanticInvariantError::IoFaultInjectionMissingStore {
                    fault: fault.id,
                    store: fault.driver_store,
                });
            }
            if !self.domains.device.device_objects.iter().any(|device| {
                device.id == fault.device && device.generation == fault.device_generation
            }) {
                return Err(SemanticInvariantError::IoFaultInjectionMissingDevice {
                    fault: fault.id,
                    device: fault.device,
                });
            }
            let Some(binding) = self.domains.device.driver_store_bindings.iter().find(|binding| {
                binding.id == fault.driver_binding
                    && binding.generation == fault.driver_binding_generation
            }) else {
                return Err(SemanticInvariantError::IoFaultInjectionMissingDriverBinding {
                    fault: fault.id,
                    binding: fault.driver_binding,
                });
            };
            if binding.driver_store != fault.driver_store
                || binding.driver_store_generation != fault.driver_store_generation
                || binding.device != fault.device
                || binding.device_generation != fault.device_generation
            {
                return Err(SemanticInvariantError::IoFaultInjectionInvalid { fault: fault.id });
            }
            if !self.io_fault_target_generation_belongs_to_device(
                fault.target,
                fault.device,
                fault.device_generation,
            ) {
                return Err(SemanticInvariantError::IoFaultInjectionMissingTarget {
                    fault: fault.id,
                    target: fault.target,
                });
            }
            let Some(cleanup) = self.domains.io.io_cleanups.iter().find(|cleanup| {
                cleanup.id == fault.cleanup && cleanup.generation == fault.cleanup_generation
            }) else {
                return Err(SemanticInvariantError::IoFaultInjectionMissingCleanup {
                    fault: fault.id,
                    cleanup: fault.cleanup,
                });
            };
            if cleanup.state != IoCleanupState::Completed
                || cleanup.driver_store != fault.driver_store
                || cleanup.driver_store_generation != fault.driver_store_generation
                || cleanup.device != fault.device
                || cleanup.device_generation != fault.device_generation
                || cleanup.driver_binding != fault.driver_binding
                || cleanup.driver_binding_generation != fault.driver_binding_generation
            {
                return Err(SemanticInvariantError::IoFaultInjectionInvalid { fault: fault.id });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == fault.injected_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IoFaultInjected {
                            fault: id,
                            driver_store,
                            driver_store_generation,
                            device,
                            device_generation,
                            driver_binding,
                            driver_binding_generation,
                            target,
                            cleanup,
                            cleanup_generation,
                            kind,
                            generation,
                        } if *id == fault.id
                            && *driver_store == fault.driver_store
                            && *driver_store_generation == fault.driver_store_generation
                            && *device == fault.device
                            && *device_generation == fault.device_generation
                            && *driver_binding == fault.driver_binding
                            && *driver_binding_generation == fault.driver_binding_generation
                            && *target == fault.target
                            && *cleanup == fault.cleanup
                            && *cleanup_generation == fault.cleanup_generation
                            && *kind == fault.kind
                            && *generation == fault.generation
                    )
            }) {
                return Err(SemanticInvariantError::IoFaultInjectionMissingEvent {
                    fault: fault.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_io_fault_cleanup_ref_for_test(
        &mut self,
        fault: IoFaultInjectionId,
        cleanup_generation: Generation,
    ) {
        if let Some(record) =
            self.domains.io.io_fault_injections.iter_mut().find(|record| record.id == fault)
        {
            record.cleanup_generation = cleanup_generation;
        }
    }
}
