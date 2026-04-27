use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_block_driver_cleanup(
        &self,
        cleanup: BlockDriverCleanupId,
        io_cleanup: IoCleanupId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        backend: ContractObjectRef,
        reason: &str,
    ) -> Result<(), &'static str> {
        if cleanup == 0 {
            return Err("block driver cleanup id=0 is invalid");
        }
        if io_cleanup == 0 {
            return Err("block driver cleanup io cleanup id=0 is invalid");
        }
        if reason.is_empty() {
            return Err("block driver cleanup reason is empty");
        }
        if self
            .block_driver_cleanups
            .iter()
            .any(|record| record.id == cleanup)
        {
            return Err("block driver cleanup already exists");
        }
        if backend.kind != ContractObjectKind::VirtioBlkBackendObject {
            return Err("block driver cleanup backend kind is unsupported");
        }
        let Some(block_device_record) = self.block_device_objects.iter().find(|record| {
            record.id == block_device
                && record.generation == block_device_generation
                && record.state == BlockDeviceObjectState::Registered
        }) else {
            return Err("block driver cleanup block device generation is missing or inactive");
        };
        let Some(backend_record) = self.virtio_blk_backends.iter().find(|record| {
            record.id == backend.id
                && record.generation == backend.generation
                && record.state == VirtioBlkBackendObjectState::SkeletonReady
        }) else {
            return Err("block driver cleanup backend generation is missing or inactive");
        };
        if backend_record.block_device != block_device_record.id
            || backend_record.block_device_generation != block_device_record.generation
            || backend_record.device != block_device_record.device
            || backend_record.device_generation != block_device_record.device_generation
        {
            return Err("block driver cleanup backend does not match block device");
        }
        let Some(binding_record) = self.driver_store_bindings.iter().find(|record| {
            record.id == backend_record.driver_binding
                && record.generation == backend_record.driver_binding_generation
                && record.state == DriverStoreBindingState::Bound
        }) else {
            return Err("block driver cleanup backend driver binding is missing or inactive");
        };
        if binding_record.device != block_device_record.device
            || binding_record.device_generation != block_device_record.device_generation
        {
            return Err("block driver cleanup driver binding does not target block device");
        }
        if self.io_cleanups.iter().any(|record| {
            record.id == io_cleanup
                || (record.driver_store == binding_record.driver_store
                    && record.driver_store_generation == binding_record.driver_store_generation
                    && record.device == binding_record.device
                    && record.device_generation == binding_record.device_generation
                    && record.driver_binding == binding_record.id
                    && record.driver_binding_generation == binding_record.generation
                    && record.state == IoCleanupState::Completed)
        }) {
            return Err("block driver cleanup io cleanup target already exists");
        }
        if self.block_driver_cleanups.iter().any(|record| {
            record.driver_binding == binding_record.id
                && record.driver_binding_generation == binding_record.generation
                && record.state != BlockDriverCleanupState::Retired
        }) {
            return Err("block driver cleanup target already exists");
        }
        if self.check_invariants().is_err() {
            return Err("block driver cleanup requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cleanup_block_driver_with_id(
        &mut self,
        cleanup: BlockDriverCleanupId,
        io_cleanup: IoCleanupId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        backend: ContractObjectRef,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_block_driver_cleanup(
                cleanup,
                io_cleanup,
                block_device,
                block_device_generation,
                backend,
                reason,
            )
            .is_err()
        {
            return false;
        }

        let Some(backend_record) = self
            .virtio_blk_backends
            .iter()
            .find(|record| record.id == backend.id && record.generation == backend.generation)
            .cloned()
        else {
            return false;
        };
        let Some(binding_record) = self
            .driver_store_bindings
            .iter()
            .find(|record| {
                record.id == backend_record.driver_binding
                    && record.generation == backend_record.driver_binding_generation
            })
            .cloned()
        else {
            return false;
        };

        let generation = 1;
        self.next_block_driver_cleanup_id = self
            .next_block_driver_cleanup_id
            .max(cleanup.saturating_add(1));
        let started_at_event = self.event_log.push(
            "block",
            EventKind::BlockDriverCleanupStarted {
                cleanup,
                io_cleanup,
                driver_store: binding_record.driver_store,
                driver_store_generation: binding_record.driver_store_generation,
                device: binding_record.device,
                device_generation: binding_record.device_generation,
                driver_binding: binding_record.id,
                driver_binding_generation: binding_record.generation,
                block_device,
                block_device_generation,
                backend,
                generation,
            },
        );
        self.block_driver_cleanups.push(BlockDriverCleanupRecord {
            id: cleanup,
            io_cleanup,
            io_cleanup_generation: generation,
            driver_store: binding_record.driver_store,
            driver_store_generation: binding_record.driver_store_generation,
            device: binding_record.device,
            device_generation: binding_record.device_generation,
            driver_binding: binding_record.id,
            driver_binding_generation: binding_record.generation,
            block_device,
            block_device_generation,
            backend,
            cancelled_block_waits: Vec::new(),
            cancelled_wait_tokens: Vec::new(),
            revoked_device_capabilities: Vec::new(),
            released_dma_buffers: Vec::new(),
            generation,
            state: BlockDriverCleanupState::Started,
            started_at_event,
            completed_at_event: None,
            reason: reason.to_string(),
            note: note.to_string(),
        });

        if !self.cleanup_io_driver_for_device_fault_with_id(
            io_cleanup,
            binding_record.driver_store,
            binding_record.driver_store_generation,
            binding_record.device,
            binding_record.device_generation,
            binding_record.id,
            binding_record.generation,
            reason,
            note,
        ) {
            return false;
        }

        let pending_block_waits = self
            .block_waits
            .iter()
            .filter(|record| {
                record.block_device == block_device
                    && record.block_device_generation == block_device_generation
                    && record.state == BlockWaitState::Pending
            })
            .map(|record| {
                (
                    record.id,
                    record.generation,
                    record.wait,
                    record.wait_generation,
                )
            })
            .collect::<Vec<_>>();
        let mut cancelled_block_waits = Vec::new();
        let mut cancelled_wait_tokens = Vec::new();
        for (block_wait, block_wait_generation, wait, wait_generation) in pending_block_waits {
            if self.cancel_block_wait(
                block_wait,
                block_wait_generation,
                5,
                WaitCancelReason::DeviceFault,
                "block driver cleanup cancelled pending block wait",
            ) {
                cancelled_block_waits.push(ContractObjectRef::new(
                    ContractObjectKind::BlockWait,
                    block_wait,
                    block_wait_generation,
                ));
                cancelled_wait_tokens.push(ContractObjectRef::new(
                    ContractObjectKind::WaitToken,
                    wait,
                    wait_generation,
                ));
            }
        }

        let (revoked_device_capabilities, released_dma_buffers) = self
            .io_cleanups
            .iter()
            .find(|record| record.id == io_cleanup && record.generation == generation)
            .map(|record| {
                (
                    record.revoked_device_capabilities.clone(),
                    record.released_dma_buffers.clone(),
                )
            })
            .unwrap_or_default();

        if let Some(backend_record) = self
            .virtio_blk_backends
            .iter_mut()
            .find(|record| record.id == backend.id && record.generation == backend.generation)
        {
            backend_record.state = VirtioBlkBackendObjectState::Retired;
        }

        let completed_at_event = self.event_log.push(
            "block",
            EventKind::BlockDriverCleanupCompleted {
                cleanup,
                io_cleanup,
                io_cleanup_generation: generation,
                cancelled_block_waits: cancelled_block_waits.len(),
                released_dma_buffers: released_dma_buffers.len(),
                revoked_device_capabilities: revoked_device_capabilities.len(),
                generation,
            },
        );
        if let Some(record) = self
            .block_driver_cleanups
            .iter_mut()
            .find(|record| record.id == cleanup && record.generation == generation)
        {
            record.cancelled_block_waits = cancelled_block_waits;
            record.cancelled_wait_tokens = cancelled_wait_tokens;
            record.revoked_device_capabilities = revoked_device_capabilities;
            record.released_dma_buffers = released_dma_buffers;
            record.state = BlockDriverCleanupState::Completed;
            record.completed_at_event = Some(completed_at_event);
        }
        self.check_invariants().is_ok()
    }

    pub fn block_driver_cleanups(&self) -> &[BlockDriverCleanupRecord] {
        &self.block_driver_cleanups
    }

    pub fn block_driver_cleanup_count(&self) -> usize {
        self.block_driver_cleanups.len()
    }

    pub fn check_block_driver_cleanup_invariants(&self) -> Result<(), SemanticInvariantError> {
        for cleanup in &self.block_driver_cleanups {
            if cleanup.id == 0
                || cleanup.generation == 0
                || cleanup.io_cleanup == 0
                || cleanup.io_cleanup_generation == 0
                || cleanup.driver_store_generation == 0
                || cleanup.device_generation == 0
                || cleanup.driver_binding_generation == 0
                || cleanup.block_device_generation == 0
                || cleanup.reason.is_empty()
                || cleanup.backend.kind != ContractObjectKind::VirtioBlkBackendObject
            {
                return Err(SemanticInvariantError::BlockDriverCleanupInvalid {
                    cleanup: cleanup.id,
                });
            }
            let Some(io_cleanup) = self.io_cleanups.iter().find(|record| {
                record.id == cleanup.io_cleanup
                    && record.generation == cleanup.io_cleanup_generation
                    && record.state == IoCleanupState::Completed
            }) else {
                if cleanup.state != BlockDriverCleanupState::Started {
                    return Err(SemanticInvariantError::BlockDriverCleanupMissingIoCleanup {
                        cleanup: cleanup.id,
                        io_cleanup: cleanup.io_cleanup,
                    });
                }
                continue;
            };
            if io_cleanup.driver_store != cleanup.driver_store
                || io_cleanup.driver_store_generation != cleanup.driver_store_generation
                || io_cleanup.device != cleanup.device
                || io_cleanup.device_generation != cleanup.device_generation
                || io_cleanup.driver_binding != cleanup.driver_binding
                || io_cleanup.driver_binding_generation != cleanup.driver_binding_generation
            {
                return Err(SemanticInvariantError::BlockDriverCleanupInvalid {
                    cleanup: cleanup.id,
                });
            }
            let Some(block_device) = self.block_device_objects.iter().find(|record| {
                record.id == cleanup.block_device
                    && record.generation == cleanup.block_device_generation
            }) else {
                return Err(
                    SemanticInvariantError::BlockDriverCleanupMissingBlockDevice {
                        cleanup: cleanup.id,
                        block_device: cleanup.block_device,
                    },
                );
            };
            let Some(backend) = self.virtio_blk_backends.iter().find(|record| {
                record.id == cleanup.backend.id && record.generation == cleanup.backend.generation
            }) else {
                return Err(SemanticInvariantError::BlockDriverCleanupMissingBackend {
                    cleanup: cleanup.id,
                    backend: cleanup.backend,
                });
            };
            if block_device.device != cleanup.device
                || block_device.device_generation != cleanup.device_generation
                || backend.block_device != cleanup.block_device
                || backend.block_device_generation != cleanup.block_device_generation
                || backend.driver_binding != cleanup.driver_binding
                || backend.driver_binding_generation != cleanup.driver_binding_generation
                || backend.device != cleanup.device
                || backend.device_generation != cleanup.device_generation
            {
                return Err(SemanticInvariantError::BlockDriverCleanupInvalid {
                    cleanup: cleanup.id,
                });
            }
            for target in cleanup
                .cancelled_block_waits
                .iter()
                .chain(cleanup.cancelled_wait_tokens.iter())
                .chain(cleanup.revoked_device_capabilities.iter())
                .chain(cleanup.released_dma_buffers.iter())
            {
                if !self.io_validation_historical_object_exists(*target) {
                    return Err(
                        SemanticInvariantError::BlockDriverCleanupMissingEffectTarget {
                            cleanup: cleanup.id,
                            target: *target,
                        },
                    );
                }
            }
            if cleanup.state == BlockDriverCleanupState::Completed {
                let Some(completed_at_event) = cleanup.completed_at_event else {
                    return Err(SemanticInvariantError::BlockDriverCleanupMissingEvent {
                        cleanup: cleanup.id,
                        event: 0,
                    });
                };
                if backend.state != VirtioBlkBackendObjectState::Retired
                    || self.block_waits.iter().any(|record| {
                        record.block_device == cleanup.block_device
                            && record.block_device_generation == cleanup.block_device_generation
                            && record.state == BlockWaitState::Pending
                    })
                    || self.device_capabilities.iter().any(|record| {
                        record.driver_store == cleanup.driver_store
                            && record.driver_store_generation == cleanup.driver_store_generation
                            && self.io_cleanup_device_capability_belongs_to_device(
                                record,
                                cleanup.device,
                                cleanup.device_generation,
                            )
                            && record.state == DeviceCapabilityState::Active
                    })
                {
                    return Err(SemanticInvariantError::BlockDriverCleanupLiveLeak {
                        cleanup: cleanup.id,
                    });
                }
                if !self.event_log.events.iter().any(|event| {
                    event.id == completed_at_event
                        && matches!(
                            &event.kind,
                            EventKind::BlockDriverCleanupCompleted {
                                cleanup: id,
                                io_cleanup,
                                io_cleanup_generation,
                                cancelled_block_waits,
                                released_dma_buffers,
                                revoked_device_capabilities,
                                generation,
                            } if *id == cleanup.id
                                && *io_cleanup == cleanup.io_cleanup
                                && *io_cleanup_generation == cleanup.io_cleanup_generation
                                && *cancelled_block_waits == cleanup.cancelled_block_waits.len()
                                && *released_dma_buffers == cleanup.released_dma_buffers.len()
                                && *revoked_device_capabilities
                                    == cleanup.revoked_device_capabilities.len()
                                && *generation == cleanup.generation
                        )
                }) {
                    return Err(SemanticInvariantError::BlockDriverCleanupMissingEvent {
                        cleanup: cleanup.id,
                        event: completed_at_event,
                    });
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == cleanup.started_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockDriverCleanupStarted {
                            cleanup: id,
                            io_cleanup,
                            driver_store,
                            driver_store_generation,
                            device,
                            device_generation,
                            driver_binding,
                            driver_binding_generation,
                            block_device,
                            block_device_generation,
                            backend,
                            generation,
                        } if *id == cleanup.id
                            && *io_cleanup == cleanup.io_cleanup
                            && *driver_store == cleanup.driver_store
                            && *driver_store_generation == cleanup.driver_store_generation
                            && *device == cleanup.device
                            && *device_generation == cleanup.device_generation
                            && *driver_binding == cleanup.driver_binding
                            && *driver_binding_generation == cleanup.driver_binding_generation
                            && *block_device == cleanup.block_device
                            && *block_device_generation == cleanup.block_device_generation
                            && *backend == cleanup.backend
                            && *generation == cleanup.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockDriverCleanupMissingEvent {
                    cleanup: cleanup.id,
                    event: cleanup.started_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_driver_cleanup_wait_generation_for_test(
        &mut self,
        cleanup: BlockDriverCleanupId,
        generation: Generation,
    ) {
        if let Some(target) = self
            .block_driver_cleanups
            .iter_mut()
            .find(|record| record.id == cleanup)
            .and_then(|record| record.cancelled_block_waits.first_mut())
        {
            target.generation = generation;
        }
    }
}
