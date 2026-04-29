use super::*;

const BLOCK_DMA_BUFFER_DIGEST_OFFSET_V1: u64 = 0x6d64_626c_6f63_6b31;
const BLOCK_DMA_BUFFER_DIGEST_PRIME_V1: u64 = 0x0000_0100_0000_01b3;

fn mix_digest(mut digest: u64, value: u64) -> u64 {
    digest ^= value;
    digest.wrapping_mul(BLOCK_DMA_BUFFER_DIGEST_PRIME_V1)
}

const fn operation_digest_tag(operation: BlockRequestOperation) -> u64 {
    match operation {
        BlockRequestOperation::Read => 1,
        BlockRequestOperation::Write => 2,
    }
}

const fn access_digest_tag(access: DmaBufferObjectAccess) -> u64 {
    match access {
        DmaBufferObjectAccess::ReadOnly => 1,
        DmaBufferObjectAccess::WriteOnly => 2,
        DmaBufferObjectAccess::ReadWrite => 3,
    }
}

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub fn expected_block_dma_buffer_digest_v1(
        deterministic_seed: u64,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        dma_buffer: DmaBufferObjectId,
        dma_buffer_generation: Generation,
        descriptor: DescriptorObjectId,
        descriptor_generation: Generation,
        queue: QueueObjectId,
        queue_generation: Generation,
        operation: BlockRequestOperation,
        access: DmaBufferObjectAccess,
        sequence: u64,
        byte_len: u64,
        buffer_len: u32,
    ) -> u64 {
        let mut digest = BLOCK_DMA_BUFFER_DIGEST_OFFSET_V1 ^ deterministic_seed;
        digest = mix_digest(digest, block_device);
        digest = mix_digest(digest, block_device_generation);
        digest = mix_digest(digest, block_range);
        digest = mix_digest(digest, block_range_generation);
        digest = mix_digest(digest, block_request);
        digest = mix_digest(digest, block_request_generation);
        digest = mix_digest(digest, dma_buffer);
        digest = mix_digest(digest, dma_buffer_generation);
        digest = mix_digest(digest, descriptor);
        digest = mix_digest(digest, descriptor_generation);
        digest = mix_digest(digest, queue);
        digest = mix_digest(digest, queue_generation);
        digest = mix_digest(digest, operation_digest_tag(operation));
        digest = mix_digest(digest, access_digest_tag(access));
        digest = mix_digest(digest, sequence);
        digest = mix_digest(digest, byte_len);
        digest = mix_digest(digest, u64::from(buffer_len));
        if digest == 0 { 1 } else { digest }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_block_dma_buffer(
        &self,
        block_dma_buffer: BlockDmaBufferId,
        backend: ContractObjectRef,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        dma_buffer: DmaBufferObjectId,
        dma_buffer_generation: Generation,
        buffer_digest: u64,
    ) -> Result<(), &'static str> {
        if block_dma_buffer == 0 {
            return Err("block dma buffer id=0 is invalid");
        }
        if self.block_dma_buffers.iter().any(|record| record.id == block_dma_buffer) {
            return Err("block dma buffer already exists");
        }
        if backend.generation == 0
            || block_request_generation == 0
            || dma_buffer_generation == 0
            || buffer_digest == 0
        {
            return Err("block dma buffer identity values must be nonzero");
        }
        if backend.kind != ContractObjectKind::FakeBlockBackendObject {
            return Err("block dma buffer backend kind is unsupported for B10");
        }
        let Some(backend_record) = self.fake_block_backends.iter().find(|record| {
            record.id == backend.id
                && record.generation == backend.generation
                && record.state == FakeBlockBackendObjectState::Bound
        }) else {
            return Err("block dma buffer backend generation is missing or inactive");
        };
        let Some(request_record) = self.block_request_objects.iter().find(|record| {
            record.id == block_request && record.generation == block_request_generation
        }) else {
            return Err("block dma buffer request generation is missing");
        };
        if request_record.state == BlockRequestObjectState::Cancelled {
            return Err("block dma buffer request is cancelled");
        }
        let Some(block_device_record) = self.block_device_objects.iter().find(|record| {
            record.id == request_record.block_device
                && record.generation == request_record.block_device_generation
                && record.state == BlockDeviceObjectState::Registered
        }) else {
            return Err("block dma buffer block device generation is missing or inactive");
        };
        if backend_record.block_device != request_record.block_device
            || backend_record.block_device_generation != request_record.block_device_generation
        {
            return Err("block dma buffer backend does not target request block device");
        }
        let Some(dma_record) = self.dma_buffer_objects.iter().find(|record| {
            record.id == dma_buffer
                && record.generation == dma_buffer_generation
                && record.state == DmaBufferObjectState::Registered
        }) else {
            return Err("block dma buffer dma generation is missing or inactive");
        };
        if u64::from(dma_record.length) < request_record.byte_len {
            return Err("block dma buffer length is smaller than request");
        }
        if !Self::block_dma_access_matches_request(request_record.operation, dma_record.access) {
            return Err("block dma buffer access does not match request operation");
        }
        let Some(descriptor_record) = self.descriptor_objects.iter().find(|descriptor| {
            descriptor.id == dma_record.descriptor
                && descriptor.generation == dma_record.descriptor_generation
                && descriptor.state == DescriptorObjectState::Registered
        }) else {
            return Err("block dma buffer descriptor generation is missing or inactive");
        };
        let Some(queue_record) = self.queue_objects.iter().find(|queue| {
            queue.id == descriptor_record.queue
                && queue.generation == descriptor_record.queue_generation
                && queue.state == QueueObjectState::Registered
        }) else {
            return Err("block dma buffer queue generation is missing or inactive");
        };
        if queue_record.device != block_device_record.device
            || queue_record.device_generation != block_device_record.device_generation
        {
            return Err("block dma buffer queue does not belong to block device");
        }
        if !matches!(
            queue_record.role,
            QueueObjectRole::Submission | QueueObjectRole::Completion | QueueObjectRole::Control
        ) {
            return Err("block dma buffer queue role is not a block io role");
        }
        let expected_digest = Self::expected_block_dma_buffer_digest_v1(
            backend_record.deterministic_seed,
            request_record.block_device,
            request_record.block_device_generation,
            request_record.block_range,
            request_record.block_range_generation,
            request_record.id,
            request_record.generation,
            dma_record.id,
            dma_record.generation,
            descriptor_record.id,
            descriptor_record.generation,
            queue_record.id,
            queue_record.generation,
            request_record.operation,
            dma_record.access,
            request_record.sequence,
            request_record.byte_len,
            dma_record.length,
        );
        if buffer_digest != expected_digest {
            return Err("block dma buffer digest mismatch");
        }
        if self.block_dma_buffers.iter().any(|record| {
            record.state == BlockDmaBufferState::Bound
                && record.block_request == request_record.id
                && record.block_request_generation == request_record.generation
        }) {
            return Err("block dma buffer request already has a bound dma buffer");
        }
        if self.block_dma_buffers.iter().any(|record| {
            record.state == BlockDmaBufferState::Bound
                && record.dma_buffer == dma_record.id
                && record.dma_buffer_generation == dma_record.generation
        }) {
            return Err("block dma buffer dma object is already bound");
        }
        if self.check_invariants().is_err() {
            return Err("block dma buffer requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_block_dma_buffer_with_id(
        &mut self,
        block_dma_buffer: BlockDmaBufferId,
        backend: ContractObjectRef,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        dma_buffer: DmaBufferObjectId,
        dma_buffer_generation: Generation,
        buffer_digest: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_block_dma_buffer(
                block_dma_buffer,
                backend,
                block_request,
                block_request_generation,
                dma_buffer,
                dma_buffer_generation,
                buffer_digest,
            )
            .is_err()
        {
            return false;
        }
        let Some(request_record) = self.block_request_objects.iter().find(|request| {
            request.id == block_request && request.generation == block_request_generation
        }) else {
            return false;
        };
        let Some(dma_record) = self
            .dma_buffer_objects
            .iter()
            .find(|dma| dma.id == dma_buffer && dma.generation == dma_buffer_generation)
        else {
            return false;
        };
        let Some(descriptor_record) = self.descriptor_objects.iter().find(|descriptor| {
            descriptor.id == dma_record.descriptor
                && descriptor.generation == dma_record.descriptor_generation
        }) else {
            return false;
        };
        let Some(queue_record) = self.queue_objects.iter().find(|queue| {
            queue.id == descriptor_record.queue
                && queue.generation == descriptor_record.queue_generation
        }) else {
            return false;
        };
        let generation = 1;
        self.next_block_dma_buffer_id =
            self.next_block_dma_buffer_id.max(block_dma_buffer.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockDmaBufferBound {
                block_dma_buffer,
                backend,
                block_request,
                block_request_generation,
                dma_buffer,
                dma_buffer_generation,
                block_device: request_record.block_device,
                block_device_generation: request_record.block_device_generation,
                block_range: request_record.block_range,
                block_range_generation: request_record.block_range_generation,
                descriptor: descriptor_record.id,
                descriptor_generation: descriptor_record.generation,
                queue: queue_record.id,
                queue_generation: queue_record.generation,
                operation: request_record.operation,
                access: dma_record.access,
                byte_len: request_record.byte_len,
                buffer_len: dma_record.length,
                buffer_digest,
                generation,
            },
        );
        self.block_dma_buffers.push(BlockDmaBufferRecord {
            id: block_dma_buffer,
            backend,
            block_request,
            block_request_generation,
            dma_buffer,
            dma_buffer_generation,
            block_device: request_record.block_device,
            block_device_generation: request_record.block_device_generation,
            block_range: request_record.block_range,
            block_range_generation: request_record.block_range_generation,
            descriptor: descriptor_record.id,
            descriptor_generation: descriptor_record.generation,
            queue: queue_record.id,
            queue_generation: queue_record.generation,
            operation: request_record.operation,
            access: dma_record.access,
            byte_len: request_record.byte_len,
            buffer_len: dma_record.length,
            buffer_digest,
            generation,
            state: BlockDmaBufferState::Bound,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn block_dma_buffers(&self) -> &[BlockDmaBufferRecord] {
        &self.block_dma_buffers
    }

    pub fn block_dma_buffer_count(&self) -> usize {
        self.block_dma_buffers.len()
    }

    pub fn check_block_dma_buffer_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.block_dma_buffers {
            let Some(backend_record) = self.fake_block_backends.iter().find(|backend| {
                record.backend.kind == ContractObjectKind::FakeBlockBackendObject
                    && backend.id == record.backend.id
                    && backend.generation == record.backend.generation
            }) else {
                return Err(SemanticInvariantError::BlockDmaBufferMissingBackend {
                    block_dma_buffer: record.id,
                    backend: record.backend,
                });
            };
            let Some(request_record) = self.block_request_objects.iter().find(|request| {
                request.id == record.block_request
                    && request.generation == record.block_request_generation
            }) else {
                return Err(SemanticInvariantError::BlockDmaBufferMissingRequest {
                    block_dma_buffer: record.id,
                    block_request: record.block_request,
                });
            };
            let Some(dma_record) = self.dma_buffer_objects.iter().find(|dma| {
                dma.id == record.dma_buffer && dma.generation == record.dma_buffer_generation
            }) else {
                return Err(SemanticInvariantError::BlockDmaBufferMissingDmaBuffer {
                    block_dma_buffer: record.id,
                    dma_buffer: record.dma_buffer,
                });
            };
            let Some(descriptor_record) = self.descriptor_objects.iter().find(|descriptor| {
                descriptor.id == record.descriptor
                    && descriptor.generation == record.descriptor_generation
            }) else {
                return Err(SemanticInvariantError::BlockDmaBufferInvalid {
                    block_dma_buffer: record.id,
                });
            };
            let Some(queue_record) = self.queue_objects.iter().find(|queue| {
                queue.id == record.queue && queue.generation == record.queue_generation
            }) else {
                return Err(SemanticInvariantError::BlockDmaBufferInvalid {
                    block_dma_buffer: record.id,
                });
            };
            let Some(block_device_record) = self.block_device_objects.iter().find(|block_device| {
                block_device.id == record.block_device
                    && block_device.generation == record.block_device_generation
            }) else {
                return Err(SemanticInvariantError::BlockDmaBufferInvalid {
                    block_dma_buffer: record.id,
                });
            };
            let expected_digest = Self::expected_block_dma_buffer_digest_v1(
                backend_record.deterministic_seed,
                record.block_device,
                record.block_device_generation,
                record.block_range,
                record.block_range_generation,
                record.block_request,
                record.block_request_generation,
                record.dma_buffer,
                record.dma_buffer_generation,
                record.descriptor,
                record.descriptor_generation,
                record.queue,
                record.queue_generation,
                record.operation,
                record.access,
                request_record.sequence,
                record.byte_len,
                record.buffer_len,
            );
            if record.id == 0
                || record.generation == 0
                || record.backend.generation == 0
                || record.block_request_generation == 0
                || record.dma_buffer_generation == 0
                || record.block_device_generation == 0
                || record.block_range_generation == 0
                || record.descriptor_generation == 0
                || record.queue_generation == 0
                || record.byte_len == 0
                || record.buffer_len == 0
                || record.buffer_digest == 0
                || record.buffer_digest != expected_digest
                || record.state != BlockDmaBufferState::Bound
                || record.backend.kind != ContractObjectKind::FakeBlockBackendObject
                || backend_record.state != FakeBlockBackendObjectState::Bound
                || dma_record.state != DmaBufferObjectState::Registered
                || descriptor_record.state != DescriptorObjectState::Registered
                || queue_record.state != QueueObjectState::Registered
                || block_device_record.state != BlockDeviceObjectState::Registered
                || request_record.state == BlockRequestObjectState::Cancelled
                || record.block_device != request_record.block_device
                || record.block_device_generation != request_record.block_device_generation
                || record.block_range != request_record.block_range
                || record.block_range_generation != request_record.block_range_generation
                || record.operation != request_record.operation
                || record.dma_buffer != dma_record.id
                || record.descriptor != dma_record.descriptor
                || record.descriptor_generation != dma_record.descriptor_generation
                || record.queue != descriptor_record.queue
                || record.queue_generation != descriptor_record.queue_generation
                || queue_record.device != block_device_record.device
                || queue_record.device_generation != block_device_record.device_generation
                || backend_record.block_device != record.block_device
                || backend_record.block_device_generation != record.block_device_generation
                || u64::from(dma_record.length) < record.byte_len
                || dma_record.length != record.buffer_len
                || dma_record.access != record.access
                || !Self::block_dma_access_matches_request(record.operation, record.access)
            {
                return Err(SemanticInvariantError::BlockDmaBufferInvalid {
                    block_dma_buffer: record.id,
                });
            }
            if let Some(duplicate) = self.block_dma_buffers.iter().find(|other| {
                other.id != record.id
                    && other.state == BlockDmaBufferState::Bound
                    && other.block_request == record.block_request
                    && other.block_request_generation == record.block_request_generation
            }) {
                return Err(SemanticInvariantError::BlockDmaBufferDuplicateRequest {
                    block_dma_buffer: duplicate.id,
                    block_request: record.block_request,
                });
            }
            if let Some(duplicate) = self.block_dma_buffers.iter().find(|other| {
                other.id != record.id
                    && other.state == BlockDmaBufferState::Bound
                    && other.dma_buffer == record.dma_buffer
                    && other.dma_buffer_generation == record.dma_buffer_generation
            }) {
                return Err(SemanticInvariantError::BlockDmaBufferDuplicateDmaBuffer {
                    block_dma_buffer: duplicate.id,
                    dma_buffer: record.dma_buffer,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockDmaBufferBound {
                            block_dma_buffer,
                            backend,
                            block_request,
                            block_request_generation,
                            dma_buffer,
                            dma_buffer_generation,
                            block_device,
                            block_device_generation,
                            block_range,
                            block_range_generation,
                            descriptor,
                            descriptor_generation,
                            queue,
                            queue_generation,
                            operation,
                            access,
                            byte_len,
                            buffer_len,
                            buffer_digest,
                            generation,
                        } if *block_dma_buffer == record.id
                            && *backend == record.backend
                            && *block_request == record.block_request
                            && *block_request_generation == record.block_request_generation
                            && *dma_buffer == record.dma_buffer
                            && *dma_buffer_generation == record.dma_buffer_generation
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *block_range == record.block_range
                            && *block_range_generation == record.block_range_generation
                            && *descriptor == record.descriptor
                            && *descriptor_generation == record.descriptor_generation
                            && *queue == record.queue
                            && *queue_generation == record.queue_generation
                            && *operation == record.operation
                            && *access == record.access
                            && *byte_len == record.byte_len
                            && *buffer_len == record.buffer_len
                            && *buffer_digest == record.buffer_digest
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::BlockDmaBufferMissingEvent {
                    block_dma_buffer: record.id,
                });
            }
        }
        Ok(())
    }

    const fn block_dma_access_matches_request(
        operation: BlockRequestOperation,
        access: DmaBufferObjectAccess,
    ) -> bool {
        matches!(
            (operation, access),
            (BlockRequestOperation::Read, DmaBufferObjectAccess::WriteOnly)
                | (BlockRequestOperation::Read, DmaBufferObjectAccess::ReadWrite)
                | (BlockRequestOperation::Write, DmaBufferObjectAccess::ReadOnly)
                | (BlockRequestOperation::Write, DmaBufferObjectAccess::ReadWrite)
        )
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_dma_buffer_dma_generation_for_test(
        &mut self,
        block_dma_buffer: BlockDmaBufferId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.block_dma_buffers.iter_mut().find(|record| record.id == block_dma_buffer)
        {
            record.dma_buffer_generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_dma_buffer_digest_for_test(
        &mut self,
        block_dma_buffer: BlockDmaBufferId,
        digest: u64,
    ) {
        if let Some(record) =
            self.block_dma_buffers.iter_mut().find(|record| record.id == block_dma_buffer)
        {
            record.buffer_digest = digest;
        }
    }
}
