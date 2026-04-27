use super::*;

pub const FAKE_BLOCK_BACKEND_PROFILE_V1: &str = "fake-block-v1";
pub const FAKE_BLOCK_BACKEND_PROVIDER_V1: &str = "service_core";

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_fake_block_backend_object(
        &self,
        fake_block_backend: FakeBlockBackendObjectId,
        name: &str,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        provider: &str,
        profile: &str,
        sector_size: u32,
        sector_count: u64,
        read_only: bool,
        max_transfer_sectors: u32,
        deterministic_seed: u64,
    ) -> Result<(), &'static str> {
        if fake_block_backend == 0 {
            return Err("fake block backend object id=0 is invalid");
        }
        if self
            .fake_block_backends
            .iter()
            .any(|record| record.id == fake_block_backend)
        {
            return Err("fake block backend object already exists");
        }
        if name.is_empty() || provider.is_empty() || profile.is_empty() {
            return Err("fake block backend object identity fields are empty");
        }
        if provider != FAKE_BLOCK_BACKEND_PROVIDER_V1 {
            return Err("fake block backend object provider is unsupported");
        }
        if profile != FAKE_BLOCK_BACKEND_PROFILE_V1 {
            return Err("fake block backend object profile is unsupported");
        }
        if sector_size == 0
            || sector_count == 0
            || max_transfer_sectors == 0
            || deterministic_seed == 0
        {
            return Err("fake block backend object contract values must be nonzero");
        }
        let Some(block_device_record) = self.block_device_objects.iter().find(|record| {
            record.id == block_device
                && record.generation == block_device_generation
                && record.state == BlockDeviceObjectState::Registered
        }) else {
            return Err("fake block backend object block device generation is missing or inactive");
        };
        if sector_size != block_device_record.sector_size
            || sector_count != block_device_record.sector_count
            || read_only != block_device_record.read_only
            || max_transfer_sectors != block_device_record.max_transfer_sectors
        {
            return Err("fake block backend object contract does not match block device");
        }
        if self.fake_block_backends.iter().any(|record| {
            record.block_device == block_device_record.id
                && record.block_device_generation == block_device_generation
                && record.state == FakeBlockBackendObjectState::Bound
        }) {
            return Err("fake block backend object already bound to block device generation");
        }
        if self.check_invariants().is_err() {
            return Err("fake block backend object requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_fake_block_backend_object_with_id(
        &mut self,
        fake_block_backend: FakeBlockBackendObjectId,
        name: &str,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        provider: &str,
        profile: &str,
        sector_size: u32,
        sector_count: u64,
        read_only: bool,
        max_transfer_sectors: u32,
        deterministic_seed: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_fake_block_backend_object(
                fake_block_backend,
                name,
                block_device,
                block_device_generation,
                provider,
                profile,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                deterministic_seed,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.next_fake_block_backend_object_id = self
            .next_fake_block_backend_object_id
            .max(fake_block_backend.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::FakeBlockBackendObjectBound {
                fake_block_backend,
                block_device,
                block_device_generation,
                sector_size,
                sector_count,
                read_only,
                max_transfer_sectors,
                deterministic_seed,
                generation,
            },
        );
        self.fake_block_backends.push(FakeBlockBackendObjectRecord {
            id: fake_block_backend,
            name: name.to_string(),
            block_device,
            block_device_generation,
            provider: provider.to_string(),
            profile: profile.to_string(),
            sector_size,
            sector_count,
            read_only,
            max_transfer_sectors,
            deterministic_seed,
            generation,
            state: FakeBlockBackendObjectState::Bound,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn fake_block_backends(&self) -> &[FakeBlockBackendObjectRecord] {
        &self.fake_block_backends
    }

    pub fn fake_block_backend_object_count(&self) -> usize {
        self.fake_block_backends.len()
    }

    pub fn check_fake_block_backend_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.fake_block_backends {
            let Some(block_device_record) = self.block_device_objects.iter().find(|block_device| {
                block_device.id == record.block_device
                    && block_device.generation == record.block_device_generation
            }) else {
                return Err(
                    SemanticInvariantError::FakeBlockBackendObjectMissingBlockDevice {
                        fake_block_backend: record.id,
                        block_device: record.block_device,
                    },
                );
            };
            if record.id == 0
                || record.generation == 0
                || record.name.is_empty()
                || record.provider != FAKE_BLOCK_BACKEND_PROVIDER_V1
                || record.profile != FAKE_BLOCK_BACKEND_PROFILE_V1
                || record.block_device_generation == 0
                || record.sector_size == 0
                || record.sector_count == 0
                || record.max_transfer_sectors == 0
                || record.deterministic_seed == 0
                || record.state != FakeBlockBackendObjectState::Bound
                || block_device_record.state != BlockDeviceObjectState::Registered
                || record.sector_size != block_device_record.sector_size
                || record.sector_count != block_device_record.sector_count
                || record.read_only != block_device_record.read_only
                || record.max_transfer_sectors != block_device_record.max_transfer_sectors
            {
                return Err(SemanticInvariantError::FakeBlockBackendObjectInvalid {
                    fake_block_backend: record.id,
                });
            }
            if let Some(duplicate) = self.fake_block_backends.iter().find(|other| {
                other.id != record.id
                    && other.block_device == record.block_device
                    && other.block_device_generation == record.block_device_generation
                    && other.state == FakeBlockBackendObjectState::Bound
            }) {
                return Err(
                    SemanticInvariantError::FakeBlockBackendObjectDuplicateBinding {
                        fake_block_backend: duplicate.id,
                        block_device: record.block_device,
                    },
                );
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::FakeBlockBackendObjectBound {
                            fake_block_backend,
                            block_device,
                            block_device_generation,
                            sector_size,
                            sector_count,
                            read_only,
                            max_transfer_sectors,
                            deterministic_seed,
                            generation,
                        } if *fake_block_backend == record.id
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *sector_size == record.sector_size
                            && *sector_count == record.sector_count
                            && *read_only == record.read_only
                            && *max_transfer_sectors == record.max_transfer_sectors
                            && *deterministic_seed == record.deterministic_seed
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::FakeBlockBackendObjectMissingEvent {
                    fake_block_backend: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_fake_block_backend_block_device_generation_for_test(
        &mut self,
        fake_block_backend: FakeBlockBackendObjectId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .fake_block_backends
            .iter_mut()
            .find(|record| record.id == fake_block_backend)
        {
            record.block_device_generation = generation;
        }
    }
}
