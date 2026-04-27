use super::*;

impl SemanticGraph {
    pub(crate) fn validate_network_driver_cleanup(
        &self,
        cleanup: NetworkDriverCleanupId,
        io_cleanup: IoCleanupId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        backend: ContractObjectRef,
        reason: &str,
    ) -> Result<(), &'static str> {
        if cleanup == 0 {
            return Err("network driver cleanup id=0 is invalid");
        }
        if io_cleanup == 0 {
            return Err("network driver cleanup io cleanup id=0 is invalid");
        }
        if reason.is_empty() {
            return Err("network driver cleanup reason is empty");
        }
        if self
            .network_driver_cleanups
            .iter()
            .any(|record| record.id == cleanup)
        {
            return Err("network driver cleanup already exists");
        }
        let Some(adapter_record) = self.network_stack_adapters.iter().find(|record| {
            record.id == adapter
                && record.generation == adapter_generation
                && record.state == NetworkStackAdapterState::Bound
        }) else {
            return Err("network driver cleanup adapter generation is missing or inactive");
        };
        if adapter_record.packet_device != packet_device
            || adapter_record.packet_device_generation != packet_device_generation
            || adapter_record.backend != backend
        {
            return Err("network driver cleanup adapter does not match packet device/backend");
        }
        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == packet_device
                && record.generation == packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err("network driver cleanup packet device generation is missing or inactive");
        };
        let Some(backend_record) = self.virtio_net_backends.iter().find(|record| {
            backend.kind == ContractObjectKind::VirtioNetBackendObject
                && record.id == backend.id
                && record.generation == backend.generation
                && record.state == VirtioNetBackendObjectState::SkeletonReady
        }) else {
            return Err("network driver cleanup backend generation is missing or inactive");
        };
        if backend_record.packet_device != packet_device_record.id
            || backend_record.packet_device_generation != packet_device_record.generation
            || backend_record.device != packet_device_record.device
            || backend_record.device_generation != packet_device_record.device_generation
        {
            return Err("network driver cleanup backend does not match packet device");
        }
        let Some(binding_record) = self.driver_store_bindings.iter().find(|record| {
            record.id == backend_record.driver_binding
                && record.generation == backend_record.driver_binding_generation
                && record.state == DriverStoreBindingState::Bound
        }) else {
            return Err("network driver cleanup backend driver binding is missing or inactive");
        };
        if binding_record.device != packet_device_record.device
            || binding_record.device_generation != packet_device_record.device_generation
        {
            return Err("network driver cleanup driver binding does not target packet device");
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
            return Err("network driver cleanup io cleanup target already exists");
        }
        if self.network_driver_cleanups.iter().any(|record| {
            record.driver_binding == binding_record.id
                && record.driver_binding_generation == binding_record.generation
                && record.state != NetworkDriverCleanupState::Retired
        }) {
            return Err("network driver cleanup target already exists");
        }
        if self.check_invariants().is_err() {
            return Err("network driver cleanup requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cleanup_network_driver_with_id(
        &mut self,
        cleanup: NetworkDriverCleanupId,
        io_cleanup: IoCleanupId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        backend: ContractObjectRef,
        reason: &str,
        note: &str,
    ) -> bool {
        if self
            .validate_network_driver_cleanup(
                cleanup,
                io_cleanup,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                backend,
                reason,
            )
            .is_err()
        {
            return false;
        }

        let Some(backend_record) = self
            .virtio_net_backends
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
        self.next_network_driver_cleanup_id = self.next_network_driver_cleanup_id.max(cleanup + 1);
        let started_at_event = self.event_log.push(
            "network",
            EventKind::NetworkDriverCleanupStarted {
                cleanup,
                io_cleanup,
                driver_store: binding_record.driver_store,
                driver_store_generation: binding_record.driver_store_generation,
                device: binding_record.device,
                device_generation: binding_record.device_generation,
                driver_binding: binding_record.id,
                driver_binding_generation: binding_record.generation,
                packet_device,
                packet_device_generation,
                adapter,
                adapter_generation,
                backend,
                generation,
            },
        );
        self.network_driver_cleanups
            .push(NetworkDriverCleanupRecord {
                id: cleanup,
                io_cleanup,
                io_cleanup_generation: generation,
                driver_store: binding_record.driver_store,
                driver_store_generation: binding_record.driver_store_generation,
                device: binding_record.device,
                device_generation: binding_record.device_generation,
                driver_binding: binding_record.id,
                driver_binding_generation: binding_record.generation,
                packet_device,
                packet_device_generation,
                adapter,
                adapter_generation,
                backend,
                cancelled_socket_waits: Vec::new(),
                cancelled_wait_tokens: Vec::new(),
                revoked_packet_capabilities: Vec::new(),
                generation,
                state: NetworkDriverCleanupState::Started,
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

        let pending_socket_waits = self
            .socket_waits
            .iter()
            .filter(|record| {
                record.adapter == adapter
                    && record.adapter_generation == adapter_generation
                    && record.state == SocketWaitState::Pending
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
        let mut cancelled_socket_waits = Vec::new();
        let mut cancelled_wait_tokens = Vec::new();
        for (socket_wait, socket_wait_generation, wait, wait_generation) in pending_socket_waits {
            if self.cancel_socket_wait(
                socket_wait,
                socket_wait_generation,
                5,
                WaitCancelReason::DeviceFault,
                "network driver cleanup cancelled pending socket wait",
            ) {
                cancelled_socket_waits.push(ContractObjectRef::new(
                    ContractObjectKind::SocketWait,
                    socket_wait,
                    socket_wait_generation,
                ));
                cancelled_wait_tokens.push(ContractObjectRef::new(
                    ContractObjectKind::WaitToken,
                    wait,
                    wait_generation,
                ));
            }
        }

        let revoked_packet_capabilities = self
            .io_cleanups
            .iter()
            .find(|record| record.id == io_cleanup && record.generation == generation)
            .map(|record| {
                record
                    .revoked_device_capabilities
                    .iter()
                    .filter(|target| {
                        self.device_capabilities.iter().any(|capability| {
                            capability.id == target.id
                                && capability.generation == target.generation
                                && capability.target
                                    == ContractObjectRef::new(
                                        ContractObjectKind::PacketDeviceObject,
                                        packet_device,
                                        packet_device_generation,
                                    )
                                && capability.state == DeviceCapabilityState::Revoked
                        })
                    })
                    .copied()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let completed_at_event = self.event_log.push(
            "network",
            EventKind::NetworkDriverCleanupCompleted {
                cleanup,
                io_cleanup,
                io_cleanup_generation: generation,
                cancelled_socket_waits: cancelled_socket_waits.len(),
                revoked_packet_capabilities: revoked_packet_capabilities.len(),
                generation,
            },
        );
        if let Some(record) = self
            .network_driver_cleanups
            .iter_mut()
            .find(|record| record.id == cleanup && record.generation == generation)
        {
            record.cancelled_socket_waits = cancelled_socket_waits;
            record.cancelled_wait_tokens = cancelled_wait_tokens;
            record.revoked_packet_capabilities = revoked_packet_capabilities;
            record.state = NetworkDriverCleanupState::Completed;
            record.completed_at_event = Some(completed_at_event);
        }
        self.check_invariants().is_ok()
    }

    pub fn network_driver_cleanups(&self) -> &[NetworkDriverCleanupRecord] {
        &self.network_driver_cleanups
    }

    pub fn network_driver_cleanup_count(&self) -> usize {
        self.network_driver_cleanups.len()
    }

    pub(crate) fn network_driver_cleanup_covers_binding(
        &self,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
    ) -> bool {
        self.network_driver_cleanups.iter().any(|record| {
            record.driver_binding == driver_binding
                && record.driver_binding_generation == driver_binding_generation
                && record.state != NetworkDriverCleanupState::Retired
        })
    }

    pub(crate) fn network_driver_cleanup_covers_packet_device_for_store(
        &self,
        driver_store: StoreId,
        driver_store_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
    ) -> bool {
        self.network_driver_cleanups.iter().any(|record| {
            record.driver_store == driver_store
                && record.driver_store_generation == driver_store_generation
                && record.packet_device == packet_device
                && record.packet_device_generation == packet_device_generation
                && record.state != NetworkDriverCleanupState::Retired
        })
    }

    pub fn check_network_driver_cleanup_invariants(&self) -> Result<(), SemanticInvariantError> {
        for cleanup in &self.network_driver_cleanups {
            if cleanup.id == 0
                || cleanup.generation == 0
                || cleanup.io_cleanup == 0
                || cleanup.io_cleanup_generation == 0
                || cleanup.driver_store_generation == 0
                || cleanup.device_generation == 0
                || cleanup.driver_binding_generation == 0
                || cleanup.packet_device_generation == 0
                || cleanup.adapter_generation == 0
                || cleanup.reason.is_empty()
                || cleanup.backend.kind != ContractObjectKind::VirtioNetBackendObject
            {
                return Err(SemanticInvariantError::NetworkDriverCleanupInvalid {
                    cleanup: cleanup.id,
                });
            }
            let io_cleanup = self.io_cleanups.iter().find(|record| {
                record.id == cleanup.io_cleanup
                    && record.generation == cleanup.io_cleanup_generation
                    && record.state == IoCleanupState::Completed
            });
            if let Some(io_cleanup) = io_cleanup {
                if io_cleanup.driver_store != cleanup.driver_store
                    || io_cleanup.driver_store_generation != cleanup.driver_store_generation
                    || io_cleanup.device != cleanup.device
                    || io_cleanup.device_generation != cleanup.device_generation
                    || io_cleanup.driver_binding != cleanup.driver_binding
                    || io_cleanup.driver_binding_generation != cleanup.driver_binding_generation
                {
                    return Err(SemanticInvariantError::NetworkDriverCleanupInvalid {
                        cleanup: cleanup.id,
                    });
                }
            } else if cleanup.state != NetworkDriverCleanupState::Started {
                return Err(
                    SemanticInvariantError::NetworkDriverCleanupMissingIoCleanup {
                        cleanup: cleanup.id,
                        io_cleanup: cleanup.io_cleanup,
                    },
                );
            }
            let Some(adapter) = self.network_stack_adapters.iter().find(|record| {
                record.id == cleanup.adapter && record.generation == cleanup.adapter_generation
            }) else {
                return Err(SemanticInvariantError::NetworkDriverCleanupMissingAdapter {
                    cleanup: cleanup.id,
                    adapter: cleanup.adapter,
                });
            };
            let Some(packet_device) = self.packet_device_objects.iter().find(|record| {
                record.id == cleanup.packet_device
                    && record.generation == cleanup.packet_device_generation
            }) else {
                return Err(
                    SemanticInvariantError::NetworkDriverCleanupMissingPacketDevice {
                        cleanup: cleanup.id,
                        packet_device: cleanup.packet_device,
                    },
                );
            };
            let Some(backend) = self.virtio_net_backends.iter().find(|record| {
                record.id == cleanup.backend.id && record.generation == cleanup.backend.generation
            }) else {
                return Err(SemanticInvariantError::NetworkDriverCleanupMissingBackend {
                    cleanup: cleanup.id,
                    backend: cleanup.backend,
                });
            };
            if adapter.packet_device != cleanup.packet_device
                || adapter.packet_device_generation != cleanup.packet_device_generation
                || adapter.backend != cleanup.backend
                || packet_device.device != cleanup.device
                || packet_device.device_generation != cleanup.device_generation
                || backend.packet_device != cleanup.packet_device
                || backend.packet_device_generation != cleanup.packet_device_generation
                || backend.driver_binding != cleanup.driver_binding
                || backend.driver_binding_generation != cleanup.driver_binding_generation
            {
                return Err(SemanticInvariantError::NetworkDriverCleanupInvalid {
                    cleanup: cleanup.id,
                });
            }
            for target in cleanup
                .cancelled_socket_waits
                .iter()
                .chain(cleanup.cancelled_wait_tokens.iter())
                .chain(cleanup.revoked_packet_capabilities.iter())
            {
                if !self.io_validation_historical_object_exists(*target) {
                    return Err(
                        SemanticInvariantError::NetworkDriverCleanupMissingEffectTarget {
                            cleanup: cleanup.id,
                            target: *target,
                        },
                    );
                }
            }
            if cleanup.state == NetworkDriverCleanupState::Completed {
                let Some(completed_at_event) = cleanup.completed_at_event else {
                    return Err(SemanticInvariantError::NetworkDriverCleanupMissingEvent {
                        cleanup: cleanup.id,
                        event: 0,
                    });
                };
                if self.socket_waits.iter().any(|record| {
                    record.adapter == cleanup.adapter
                        && record.adapter_generation == cleanup.adapter_generation
                        && record.state == SocketWaitState::Pending
                }) || self.device_capabilities.iter().any(|record| {
                    record.driver_store == cleanup.driver_store
                        && record.driver_store_generation == cleanup.driver_store_generation
                        && record.target
                            == ContractObjectRef::new(
                                ContractObjectKind::PacketDeviceObject,
                                cleanup.packet_device,
                                cleanup.packet_device_generation,
                            )
                        && record.state == DeviceCapabilityState::Active
                }) {
                    return Err(SemanticInvariantError::NetworkDriverCleanupLiveLeak {
                        cleanup: cleanup.id,
                    });
                }
                if !self.event_log.events.iter().any(|event| {
                    event.id == completed_at_event
                        && matches!(
                            &event.kind,
                            EventKind::NetworkDriverCleanupCompleted {
                                cleanup: id,
                                io_cleanup,
                                io_cleanup_generation,
                                cancelled_socket_waits,
                                revoked_packet_capabilities,
                                generation,
                            } if *id == cleanup.id
                                && *io_cleanup == cleanup.io_cleanup
                                && *io_cleanup_generation == cleanup.io_cleanup_generation
                                && *cancelled_socket_waits == cleanup.cancelled_socket_waits.len()
                                && *revoked_packet_capabilities
                                    == cleanup.revoked_packet_capabilities.len()
                                && *generation == cleanup.generation
                        )
                }) {
                    return Err(SemanticInvariantError::NetworkDriverCleanupMissingEvent {
                        cleanup: cleanup.id,
                        event: completed_at_event,
                    });
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == cleanup.started_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkDriverCleanupStarted {
                            cleanup: id,
                            io_cleanup,
                            driver_store,
                            driver_store_generation,
                            device,
                            device_generation,
                            driver_binding,
                            driver_binding_generation,
                            packet_device,
                            packet_device_generation,
                            adapter,
                            adapter_generation,
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
                            && *packet_device == cleanup.packet_device
                            && *packet_device_generation == cleanup.packet_device_generation
                            && *adapter == cleanup.adapter
                            && *adapter_generation == cleanup.adapter_generation
                            && *backend == cleanup.backend
                            && *generation == cleanup.generation
                    )
            }) {
                return Err(SemanticInvariantError::NetworkDriverCleanupMissingEvent {
                    cleanup: cleanup.id,
                    event: cleanup.started_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_driver_cleanup_revoked_capability_generation_for_test(
        &mut self,
        cleanup: NetworkDriverCleanupId,
        generation: Generation,
    ) {
        if let Some(target) = self
            .network_driver_cleanups
            .iter_mut()
            .find(|record| record.id == cleanup)
            .and_then(|record| record.revoked_packet_capabilities.first_mut())
        {
            target.generation = generation;
        }
    }
}
