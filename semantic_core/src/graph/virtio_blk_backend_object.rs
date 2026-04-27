use super::*;

pub const VIRTIO_BLK_BACKEND_PROVIDER_V1: &str = "substrate_virtio";
pub const VIRTIO_BLK_BACKEND_PROFILE_V1: &str = "virtio-blk-backend-skeleton-v1";
pub const VIRTIO_BLK_BACKEND_MODEL_V1: &str = "virtio-blk";

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_virtio_blk_backend_object(
        &self,
        virtio_blk_backend: VirtioBlkBackendObjectId,
        name: &str,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        provider: &str,
        profile: &str,
        model: &str,
        sector_size: u32,
        sector_count: u64,
        read_only: bool,
        max_transfer_sectors: u32,
        device_features: u64,
        driver_features: u64,
        negotiated_features: u64,
        _request_queue_index: u16,
        queue_size: u16,
        irq_vector: u16,
    ) -> Result<(), &'static str> {
        if virtio_blk_backend == 0 {
            return Err("virtio block backend object id=0 is invalid");
        }
        if self
            .virtio_blk_backends
            .iter()
            .any(|record| record.id == virtio_blk_backend)
        {
            return Err("virtio block backend object already exists");
        }
        if name.is_empty() || provider.is_empty() || profile.is_empty() || model.is_empty() {
            return Err("virtio block backend object identity fields are empty");
        }
        if provider != VIRTIO_BLK_BACKEND_PROVIDER_V1 {
            return Err("virtio block backend object provider is unsupported");
        }
        if profile != VIRTIO_BLK_BACKEND_PROFILE_V1 {
            return Err("virtio block backend object profile is unsupported");
        }
        if model != VIRTIO_BLK_BACKEND_MODEL_V1 {
            return Err("virtio block backend object model is unsupported");
        }
        if sector_size < 512
            || !sector_size.is_power_of_two()
            || sector_count == 0
            || max_transfer_sectors == 0
            || queue_size == 0
            || irq_vector == 0
        {
            return Err("virtio block backend object contract values are invalid");
        }
        if negotiated_features & !device_features != 0 {
            return Err("virtio block backend negotiated features exceed device features");
        }
        if negotiated_features & !driver_features != 0 {
            return Err("virtio block backend negotiated features exceed driver features");
        }
        let Some(block_device_record) = self.block_device_objects.iter().find(|record| {
            record.id == block_device
                && record.generation == block_device_generation
                && record.state == BlockDeviceObjectState::Registered
        }) else {
            return Err(
                "virtio block backend object block device generation is missing or inactive",
            );
        };
        if sector_size != block_device_record.sector_size
            || sector_count != block_device_record.sector_count
            || read_only != block_device_record.read_only
            || max_transfer_sectors != block_device_record.max_transfer_sectors
        {
            return Err("virtio block backend object contract does not match block device");
        }
        let Some(binding_record) = self.driver_store_bindings.iter().find(|record| {
            record.id == driver_binding
                && record.generation == driver_binding_generation
                && record.state == DriverStoreBindingState::Bound
        }) else {
            return Err(
                "virtio block backend object driver binding generation is missing or inactive",
            );
        };
        if binding_record.device != block_device_record.device
            || binding_record.device_generation != block_device_record.device_generation
        {
            return Err("virtio block backend object driver binding does not target block device");
        }
        if self.virtio_blk_backends.iter().any(|record| {
            record.block_device == block_device_record.id
                && record.block_device_generation == block_device_generation
                && record.state == VirtioBlkBackendObjectState::SkeletonReady
        }) {
            return Err("virtio block backend object already bound to block device generation");
        }
        if self.virtio_blk_backends.iter().any(|record| {
            record.driver_binding == binding_record.id
                && record.driver_binding_generation == driver_binding_generation
                && record.state == VirtioBlkBackendObjectState::SkeletonReady
        }) {
            return Err("virtio block backend object already bound to driver binding generation");
        }
        if self.check_invariants().is_err() {
            return Err("virtio block backend object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_virtio_blk_backend_object_with_id(
        &mut self,
        virtio_blk_backend: VirtioBlkBackendObjectId,
        name: &str,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
        provider: &str,
        profile: &str,
        model: &str,
        sector_size: u32,
        sector_count: u64,
        read_only: bool,
        max_transfer_sectors: u32,
        device_features: u64,
        driver_features: u64,
        negotiated_features: u64,
        request_queue_index: u16,
        queue_size: u16,
        irq_vector: u16,
        note: &str,
    ) -> bool {
        if self
            .validate_virtio_blk_backend_object(
                virtio_blk_backend,
                name,
                block_device,
                block_device_generation,
                driver_binding,
                driver_binding_generation,
                provider,
                profile,
                model,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                device_features,
                driver_features,
                negotiated_features,
                request_queue_index,
                queue_size,
                irq_vector,
            )
            .is_err()
        {
            return false;
        }
        let Some(block_device_record) = self.block_device_objects.iter().find(|record| {
            record.id == block_device && record.generation == block_device_generation
        }) else {
            return false;
        };
        let generation = 1;
        self.next_virtio_blk_backend_object_id = self
            .next_virtio_blk_backend_object_id
            .max(virtio_blk_backend + 1);
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::VirtioBlkBackendSkeletonBound {
                virtio_blk_backend,
                block_device,
                block_device_generation,
                driver_binding,
                driver_binding_generation,
                device: block_device_record.device,
                device_generation: block_device_record.device_generation,
                queue_size,
                request_queue_index,
                negotiated_features,
                generation,
            },
        );
        self.virtio_blk_backends.push(VirtioBlkBackendObjectRecord {
            id: virtio_blk_backend,
            name: name.to_string(),
            block_device,
            block_device_generation,
            driver_binding,
            driver_binding_generation,
            device: block_device_record.device,
            device_generation: block_device_record.device_generation,
            provider: provider.to_string(),
            profile: profile.to_string(),
            model: model.to_string(),
            sector_size,
            sector_count,
            read_only,
            max_transfer_sectors,
            device_features,
            driver_features,
            negotiated_features,
            request_queue_index,
            queue_size,
            irq_vector,
            generation,
            state: VirtioBlkBackendObjectState::SkeletonReady,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn virtio_blk_backends(&self) -> &[VirtioBlkBackendObjectRecord] {
        &self.virtio_blk_backends
    }

    pub fn virtio_blk_backend_object_count(&self) -> usize {
        self.virtio_blk_backends.len()
    }

    pub fn check_virtio_blk_backend_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.virtio_blk_backends {
            let Some(block_device_record) = self.block_device_objects.iter().find(|block_device| {
                block_device.id == record.block_device
                    && block_device.generation == record.block_device_generation
            }) else {
                return Err(
                    SemanticInvariantError::VirtioBlkBackendObjectMissingBlockDevice {
                        virtio_blk_backend: record.id,
                        block_device: record.block_device,
                    },
                );
            };
            let Some(binding_record) = self.driver_store_bindings.iter().find(|driver_binding| {
                driver_binding.id == record.driver_binding
                    && driver_binding.generation == record.driver_binding_generation
            }) else {
                return Err(
                    SemanticInvariantError::VirtioBlkBackendObjectMissingDriverBinding {
                        virtio_blk_backend: record.id,
                        driver_binding: record.driver_binding,
                    },
                );
            };
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.provider != VIRTIO_BLK_BACKEND_PROVIDER_V1
                || record.profile != VIRTIO_BLK_BACKEND_PROFILE_V1
                || record.model != VIRTIO_BLK_BACKEND_MODEL_V1
                || record.block_device_generation == 0
                || record.driver_binding_generation == 0
                || record.device_generation == 0
                || record.sector_size < 512
                || !record.sector_size.is_power_of_two()
                || record.sector_count == 0
                || record.max_transfer_sectors == 0
                || record.queue_size == 0
                || record.irq_vector == 0
                || (record.negotiated_features & !record.device_features) != 0
                || (record.negotiated_features & !record.driver_features) != 0
                || record.state != VirtioBlkBackendObjectState::SkeletonReady
                || block_device_record.state != BlockDeviceObjectState::Registered
                || binding_record.state != DriverStoreBindingState::Bound
                || binding_record.device != block_device_record.device
                || binding_record.device_generation != block_device_record.device_generation
                || record.device != block_device_record.device
                || record.device_generation != block_device_record.device_generation
                || record.sector_size != block_device_record.sector_size
                || record.sector_count != block_device_record.sector_count
                || record.read_only != block_device_record.read_only
                || record.max_transfer_sectors != block_device_record.max_transfer_sectors
            {
                return Err(SemanticInvariantError::VirtioBlkBackendObjectInvalid {
                    virtio_blk_backend: record.id,
                });
            }
            if let Some(duplicate) = self.virtio_blk_backends.iter().find(|other| {
                other.id != record.id
                    && other.block_device == record.block_device
                    && other.block_device_generation == record.block_device_generation
                    && other.state == VirtioBlkBackendObjectState::SkeletonReady
            }) {
                return Err(
                    SemanticInvariantError::VirtioBlkBackendObjectDuplicateBinding {
                        virtio_blk_backend: duplicate.id,
                        block_device: record.block_device,
                    },
                );
            }
            if let Some(duplicate) = self.virtio_blk_backends.iter().find(|other| {
                other.id != record.id
                    && other.driver_binding == record.driver_binding
                    && other.driver_binding_generation == record.driver_binding_generation
                    && other.state == VirtioBlkBackendObjectState::SkeletonReady
            }) {
                return Err(
                    SemanticInvariantError::VirtioBlkBackendObjectDuplicateDriverBinding {
                        virtio_blk_backend: duplicate.id,
                        driver_binding: record.driver_binding,
                    },
                );
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::VirtioBlkBackendSkeletonBound {
                            virtio_blk_backend,
                            block_device,
                            block_device_generation,
                            driver_binding,
                            driver_binding_generation,
                            device,
                            device_generation,
                            queue_size,
                            request_queue_index,
                            negotiated_features,
                            generation,
                        } if *virtio_blk_backend == record.id
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *driver_binding == record.driver_binding
                            && *driver_binding_generation == record.driver_binding_generation
                            && *device == record.device
                            && *device_generation == record.device_generation
                            && *queue_size == record.queue_size
                            && *request_queue_index == record.request_queue_index
                            && *negotiated_features == record.negotiated_features
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::VirtioBlkBackendObjectMissingEvent {
                    virtio_blk_backend: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_virtio_blk_backend_driver_binding_generation_for_test(
        &mut self,
        virtio_blk_backend: VirtioBlkBackendObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .virtio_blk_backends
            .iter_mut()
            .find(|record| record.id == virtio_blk_backend)
        {
            record.driver_binding_generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_virtio_blk_backend_irq_vector_for_test(
        &mut self,
        virtio_blk_backend: VirtioBlkBackendObjectId,
        irq_vector: u16,
    ) {
        if let Some(record) = self
            .virtio_blk_backends
            .iter_mut()
            .find(|record| record.id == virtio_blk_backend)
        {
            record.irq_vector = irq_vector;
        }
    }
}
