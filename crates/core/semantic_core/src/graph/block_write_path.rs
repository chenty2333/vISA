use super::*;

const BLOCK_WRITE_DIGEST_OFFSET_V1: u64 = 0x8422_2325_cbf2_9ce4;
const BLOCK_WRITE_DIGEST_PRIME_V1: u64 = 0x0000_0100_0000_01b3;

fn mix_digest(mut digest: u64, value: u64) -> u64 {
    digest ^= value;
    digest.wrapping_mul(BLOCK_WRITE_DIGEST_PRIME_V1)
}

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub fn expected_block_write_payload_digest_v1(
        deterministic_seed: u64,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        start_sector: u64,
        sector_count: u64,
        sequence: u64,
        completed_bytes: u64,
    ) -> u64 {
        let mut digest = BLOCK_WRITE_DIGEST_OFFSET_V1 ^ deterministic_seed;
        digest = mix_digest(digest, block_device);
        digest = mix_digest(digest, block_device_generation);
        digest = mix_digest(digest, block_range);
        digest = mix_digest(digest, block_range_generation);
        digest = mix_digest(digest, start_sector);
        digest = mix_digest(digest, sector_count);
        digest = mix_digest(digest, sequence);
        digest = mix_digest(digest, completed_bytes);
        if digest == 0 { 1 } else { digest }
    }

    pub(crate) fn validate_block_write_path(
        &self,
        write_path: BlockWritePathId,
        backend: ContractObjectRef,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        payload_digest: u64,
    ) -> Result<(), &'static str> {
        if write_path == 0 {
            return Err("block write path id=0 is invalid");
        }
        if self.block_write_paths.iter().any(|record| record.id == write_path) {
            return Err("block write path already exists");
        }
        if backend.generation == 0
            || block_request_generation == 0
            || block_completion_generation == 0
            || payload_digest == 0
        {
            return Err("block write path identity values must be nonzero");
        }
        if backend.kind != ContractObjectKind::FakeBlockBackendObject {
            return Err("block write path backend kind is unsupported for B8");
        }
        let Some(backend_record) = self.fake_block_backends.iter().find(|record| {
            record.id == backend.id
                && record.generation == backend.generation
                && record.state == FakeBlockBackendObjectState::Bound
        }) else {
            return Err("block write path backend generation is missing or inactive");
        };
        if backend_record.read_only {
            return Err("block write path backend is read-only");
        }
        let Some(request_record) = self.block_request_objects.iter().find(|record| {
            record.id == block_request && record.generation == block_request_generation
        }) else {
            return Err("block write path request generation is missing");
        };
        if request_record.operation != BlockRequestOperation::Write {
            return Err("block write path request operation is not write");
        }
        if request_record.state != BlockRequestObjectState::Completed {
            return Err("block write path request is not completed");
        }
        let Some(completion_record) = self.block_completion_objects.iter().find(|record| {
            record.id == block_completion && record.generation == block_completion_generation
        }) else {
            return Err("block write path completion generation is missing");
        };
        if completion_record.block_request != request_record.id
            || completion_record.block_request_generation != request_record.generation
            || completion_record.state != BlockCompletionObjectState::Recorded
            || completion_record.status != BlockCompletionStatus::Success
            || completion_record.completed_bytes != request_record.byte_len
            || completion_record.sequence != request_record.sequence
            || completion_record.block_device != request_record.block_device
            || completion_record.block_device_generation != request_record.block_device_generation
            || completion_record.block_range != request_record.block_range
            || completion_record.block_range_generation != request_record.block_range_generation
        {
            return Err("block write path completion does not match write request");
        }
        if backend_record.block_device != request_record.block_device
            || backend_record.block_device_generation != request_record.block_device_generation
        {
            return Err("block write path backend does not target request block device");
        }
        let Some(range_record) = self.block_range_objects.iter().find(|range| {
            range.id == request_record.block_range
                && range.generation == request_record.block_range_generation
        }) else {
            return Err("block write path range generation is missing");
        };
        let expected_digest = Self::expected_block_write_payload_digest_v1(
            backend_record.deterministic_seed,
            request_record.block_device,
            request_record.block_device_generation,
            request_record.block_range,
            request_record.block_range_generation,
            range_record.start_sector,
            range_record.sector_count,
            request_record.sequence,
            completion_record.completed_bytes,
        );
        if payload_digest != expected_digest {
            return Err("block write path payload digest mismatch");
        }
        if self.block_write_paths.iter().any(|record| {
            record.block_request == request_record.id
                && record.block_request_generation == request_record.generation
                && record.state == BlockWritePathState::Completed
        }) {
            return Err("block write path already exists for request generation");
        }
        if self.check_invariants().is_err() {
            return Err("block write path requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_block_write_path_with_id(
        &mut self,
        write_path: BlockWritePathId,
        backend: ContractObjectRef,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        block_completion: BlockCompletionObjectId,
        block_completion_generation: Generation,
        payload_digest: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_block_write_path(
                write_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                payload_digest,
            )
            .is_err()
        {
            return false;
        }
        let Some(completion_record) = self.block_completion_objects.iter().find(|completion| {
            completion.id == block_completion
                && completion.generation == block_completion_generation
        }) else {
            return false;
        };
        let generation = 1;
        self.next_block_write_path_id =
            self.next_block_write_path_id.max(write_path.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockWritePathRecorded {
                write_path,
                backend,
                block_request,
                block_request_generation,
                block_completion,
                block_completion_generation,
                block_device: completion_record.block_device,
                block_device_generation: completion_record.block_device_generation,
                block_range: completion_record.block_range,
                block_range_generation: completion_record.block_range_generation,
                sequence: completion_record.sequence,
                completed_bytes: completion_record.completed_bytes,
                payload_digest,
                generation,
            },
        );
        self.block_write_paths.push(BlockWritePathRecord {
            id: write_path,
            backend,
            block_request,
            block_request_generation,
            block_completion,
            block_completion_generation,
            block_device: completion_record.block_device,
            block_device_generation: completion_record.block_device_generation,
            block_range: completion_record.block_range,
            block_range_generation: completion_record.block_range_generation,
            sequence: completion_record.sequence,
            completed_bytes: completion_record.completed_bytes,
            payload_digest,
            generation,
            state: BlockWritePathState::Completed,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn block_write_paths(&self) -> &[BlockWritePathRecord] {
        &self.block_write_paths
    }

    pub fn block_write_path_count(&self) -> usize {
        self.block_write_paths.len()
    }

    pub fn check_block_write_path_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.block_write_paths {
            let Some(backend_record) = self.fake_block_backends.iter().find(|backend| {
                record.backend.kind == ContractObjectKind::FakeBlockBackendObject
                    && backend.id == record.backend.id
                    && backend.generation == record.backend.generation
            }) else {
                return Err(SemanticInvariantError::BlockWritePathMissingBackend {
                    write_path: record.id,
                    backend: record.backend,
                });
            };
            let Some(request_record) = self.block_request_objects.iter().find(|request| {
                request.id == record.block_request
                    && request.generation == record.block_request_generation
            }) else {
                return Err(SemanticInvariantError::BlockWritePathMissingRequest {
                    write_path: record.id,
                    block_request: record.block_request,
                });
            };
            let Some(completion_record) = self.block_completion_objects.iter().find(|completion| {
                completion.id == record.block_completion
                    && completion.generation == record.block_completion_generation
            }) else {
                return Err(SemanticInvariantError::BlockWritePathMissingCompletion {
                    write_path: record.id,
                    block_completion: record.block_completion,
                });
            };
            let Some(range_record) = self.block_range_objects.iter().find(|range| {
                range.id == record.block_range && range.generation == record.block_range_generation
            }) else {
                return Err(SemanticInvariantError::BlockWritePathInvalid {
                    write_path: record.id,
                });
            };
            let expected_digest = Self::expected_block_write_payload_digest_v1(
                backend_record.deterministic_seed,
                record.block_device,
                record.block_device_generation,
                record.block_range,
                record.block_range_generation,
                range_record.start_sector,
                range_record.sector_count,
                record.sequence,
                record.completed_bytes,
            );
            if record.id == 0
                || record.generation == 0
                || record.backend.generation == 0
                || record.block_request_generation == 0
                || record.block_completion_generation == 0
                || record.block_device_generation == 0
                || record.block_range_generation == 0
                || record.sequence == 0
                || record.completed_bytes == 0
                || record.payload_digest == 0
                || record.state != BlockWritePathState::Completed
                || record.backend.kind != ContractObjectKind::FakeBlockBackendObject
                || backend_record.state != FakeBlockBackendObjectState::Bound
                || backend_record.read_only
                || backend_record.block_device != record.block_device
                || backend_record.block_device_generation != record.block_device_generation
                || request_record.operation != BlockRequestOperation::Write
                || request_record.state != BlockRequestObjectState::Completed
                || request_record.block_device != record.block_device
                || request_record.block_device_generation != record.block_device_generation
                || request_record.block_range != record.block_range
                || request_record.block_range_generation != record.block_range_generation
                || request_record.sequence != record.sequence
                || completion_record.state != BlockCompletionObjectState::Recorded
                || completion_record.status != BlockCompletionStatus::Success
                || completion_record.block_request != record.block_request
                || completion_record.block_request_generation != record.block_request_generation
                || completion_record.block_device != record.block_device
                || completion_record.block_device_generation != record.block_device_generation
                || completion_record.block_range != record.block_range
                || completion_record.block_range_generation != record.block_range_generation
                || completion_record.sequence != record.sequence
                || completion_record.completed_bytes != record.completed_bytes
                || completion_record.completed_bytes != request_record.byte_len
                || record.payload_digest != expected_digest
            {
                return Err(SemanticInvariantError::BlockWritePathInvalid {
                    write_path: record.id,
                });
            }
            if let Some(duplicate) = self.block_write_paths.iter().find(|other| {
                other.id != record.id
                    && other.block_request == record.block_request
                    && other.block_request_generation == record.block_request_generation
                    && other.state == BlockWritePathState::Completed
            }) {
                return Err(SemanticInvariantError::BlockWritePathDuplicateRequest {
                    write_path: duplicate.id,
                    block_request: record.block_request,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockWritePathRecorded {
                            write_path,
                            backend,
                            block_request,
                            block_request_generation,
                            block_completion,
                            block_completion_generation,
                            block_device,
                            block_device_generation,
                            block_range,
                            block_range_generation,
                            sequence,
                            completed_bytes,
                            payload_digest,
                            generation,
                        } if *write_path == record.id
                            && *backend == record.backend
                            && *block_request == record.block_request
                            && *block_request_generation == record.block_request_generation
                            && *block_completion == record.block_completion
                            && *block_completion_generation == record.block_completion_generation
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *block_range == record.block_range
                            && *block_range_generation == record.block_range_generation
                            && *sequence == record.sequence
                            && *completed_bytes == record.completed_bytes
                            && *payload_digest == record.payload_digest
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockWritePathMissingEvent {
                    write_path: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_write_path_backend_generation_for_test(
        &mut self,
        write_path: BlockWritePathId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.block_write_paths.iter_mut().find(|record| record.id == write_path)
        {
            record.backend.generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_write_path_payload_digest_for_test(
        &mut self,
        write_path: BlockWritePathId,
        payload_digest: u64,
    ) {
        if let Some(record) =
            self.block_write_paths.iter_mut().find(|record| record.id == write_path)
        {
            record.payload_digest = payload_digest;
        }
    }
}
