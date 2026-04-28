use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_block_request_generation_audit(
        &self,
        audit: BlockRequestGenerationAuditId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        backend: ContractObjectRef,
        dma_buffer: ContractObjectRef,
        rejected_completion_generation_probes: u32,
        rejected_wait_generation_probes: u32,
        rejected_dma_generation_probes: u32,
        rejected_queue_generation_probes: u32,
    ) -> Result<(), &'static str> {
        if audit == 0 {
            return Err("block request generation audit id=0 is invalid");
        }
        if self
            .block_request_generation_audits
            .iter()
            .any(|record| record.id == audit)
        {
            return Err("block request generation audit already exists");
        }
        if block_device_generation == 0
            || block_range_generation == 0
            || block_request_generation == 0
        {
            return Err("block request generation audit target generations must be nonzero");
        }
        if rejected_completion_generation_probes == 0
            || rejected_wait_generation_probes == 0
            || rejected_dma_generation_probes == 0
            || rejected_queue_generation_probes == 0
        {
            return Err("block request generation audit requires rejected probes for all paths");
        }
        if backend.kind != ContractObjectKind::FakeBlockBackendObject {
            return Err("block request generation audit backend is not fake block backend");
        }
        if dma_buffer.kind != ContractObjectKind::DmaBufferObject {
            return Err("block request generation audit dma target is not a dma buffer");
        }

        let Some(backend_record) = self.fake_block_backends.iter().find(|record| {
            record.id == backend.id
                && record.generation == backend.generation
                && record.state == FakeBlockBackendObjectState::Bound
        }) else {
            return Err("block request generation audit backend generation is missing or inactive");
        };
        if backend_record.block_device != block_device
            || backend_record.block_device_generation != block_device_generation
        {
            return Err("block request generation audit backend does not match block device");
        }

        let Some(block_device_record) = self.block_device_objects.iter().find(|record| {
            record.id == block_device
                && record.generation == block_device_generation
                && record.state == BlockDeviceObjectState::Registered
        }) else {
            return Err(
                "block request generation audit block device generation is missing or inactive",
            );
        };
        let Some(block_range_record) = self.block_range_objects.iter().find(|record| {
            record.id == block_range
                && record.generation == block_range_generation
                && record.state == BlockRangeObjectState::Registered
        }) else {
            return Err(
                "block request generation audit block range generation is missing or inactive",
            );
        };
        if block_range_record.block_device != block_device_record.id
            || block_range_record.block_device_generation != block_device_record.generation
        {
            return Err("block request generation audit range does not match block device");
        }

        let Some(request_record) = self.block_request_objects.iter().find(|record| {
            record.id == block_request
                && record.generation == block_request_generation
                && record.state == BlockRequestObjectState::Submitted
        }) else {
            return Err("block request generation audit request generation is missing or inactive");
        };
        if request_record.block_device != block_device_record.id
            || request_record.block_device_generation != block_device_record.generation
            || request_record.block_range != block_range_record.id
            || request_record.block_range_generation != block_range_record.generation
        {
            return Err("block request generation audit request does not match block device/range");
        }
        if !self.io_validation_historical_object_exists(dma_buffer) {
            return Err("block request generation audit dma buffer generation is missing");
        }
        if self.check_invariants().is_err() {
            return Err("block request generation audit requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_block_request_generation_audit_with_id(
        &mut self,
        audit: BlockRequestGenerationAuditId,
        block_device: BlockDeviceObjectId,
        block_device_generation: Generation,
        block_range: BlockRangeObjectId,
        block_range_generation: Generation,
        block_request: BlockRequestObjectId,
        block_request_generation: Generation,
        backend: ContractObjectRef,
        dma_buffer: ContractObjectRef,
        rejected_completion_generation_probes: u32,
        rejected_wait_generation_probes: u32,
        rejected_dma_generation_probes: u32,
        rejected_queue_generation_probes: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_block_request_generation_audit(
                audit,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                block_request,
                block_request_generation,
                backend,
                dma_buffer,
                rejected_completion_generation_probes,
                rejected_wait_generation_probes,
                rejected_dma_generation_probes,
                rejected_queue_generation_probes,
            )
            .is_err()
        {
            return false;
        }

        let generation = 1;
        self.next_block_request_generation_audit_id = self
            .next_block_request_generation_audit_id
            .max(audit.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "block",
            EventKind::BlockRequestGenerationAuditRecorded {
                audit,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                block_request,
                block_request_generation,
                backend,
                dma_buffer,
                rejected_completion_generation_probes,
                rejected_wait_generation_probes,
                rejected_dma_generation_probes,
                rejected_queue_generation_probes,
                generation,
            },
        );
        self.block_request_generation_audits
            .push(BlockRequestGenerationAuditRecord {
                id: audit,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                block_request,
                block_request_generation,
                backend,
                dma_buffer,
                rejected_completion_generation_probes,
                rejected_wait_generation_probes,
                rejected_dma_generation_probes,
                rejected_queue_generation_probes,
                generation,
                state: BlockRequestGenerationAuditState::Recorded,
                recorded_at_event,
                note: note.to_string(),
            });
        true
    }

    pub fn block_request_generation_audits(&self) -> &[BlockRequestGenerationAuditRecord] {
        &self.block_request_generation_audits
    }

    pub fn block_request_generation_audit_count(&self) -> usize {
        self.block_request_generation_audits.len()
    }

    pub fn check_block_request_generation_audit_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for audit in &self.block_request_generation_audits {
            if audit.id == 0
                || audit.generation == 0
                || audit.block_device_generation == 0
                || audit.block_range_generation == 0
                || audit.block_request_generation == 0
                || audit.backend.generation == 0
                || audit.dma_buffer.generation == 0
                || audit.rejected_completion_generation_probes == 0
                || audit.rejected_wait_generation_probes == 0
                || audit.rejected_dma_generation_probes == 0
                || audit.rejected_queue_generation_probes == 0
                || audit.state != BlockRequestGenerationAuditState::Recorded
            {
                return Err(SemanticInvariantError::BlockRequestGenerationAuditInvalid {
                    audit: audit.id,
                });
            }

            let Some(backend) = self.fake_block_backends.iter().find(|record| {
                record.id == audit.backend.id && record.generation == audit.backend.generation
            }) else {
                return Err(
                    SemanticInvariantError::BlockRequestGenerationAuditMissingTarget {
                        audit: audit.id,
                        target: audit.backend,
                    },
                );
            };
            let Some(block_device) = self.block_device_objects.iter().find(|record| {
                record.id == audit.block_device
                    && record.generation == audit.block_device_generation
            }) else {
                return Err(
                    SemanticInvariantError::BlockRequestGenerationAuditMissingTarget {
                        audit: audit.id,
                        target: ContractObjectRef::new(
                            ContractObjectKind::BlockDeviceObject,
                            audit.block_device,
                            audit.block_device_generation,
                        ),
                    },
                );
            };
            let Some(block_range) = self.block_range_objects.iter().find(|record| {
                record.id == audit.block_range && record.generation == audit.block_range_generation
            }) else {
                return Err(
                    SemanticInvariantError::BlockRequestGenerationAuditMissingTarget {
                        audit: audit.id,
                        target: ContractObjectRef::new(
                            ContractObjectKind::BlockRangeObject,
                            audit.block_range,
                            audit.block_range_generation,
                        ),
                    },
                );
            };
            let Some(block_request) = self.block_request_objects.iter().find(|record| {
                record.id == audit.block_request
                    && record.generation == audit.block_request_generation
            }) else {
                return Err(
                    SemanticInvariantError::BlockRequestGenerationAuditMissingTarget {
                        audit: audit.id,
                        target: ContractObjectRef::new(
                            ContractObjectKind::BlockRequestObject,
                            audit.block_request,
                            audit.block_request_generation,
                        ),
                    },
                );
            };
            if backend.state != FakeBlockBackendObjectState::Bound
                || block_device.state != BlockDeviceObjectState::Registered
                || block_range.state != BlockRangeObjectState::Registered
                || block_request.state != BlockRequestObjectState::Submitted
                || audit.backend.kind != ContractObjectKind::FakeBlockBackendObject
                || audit.dma_buffer.kind != ContractObjectKind::DmaBufferObject
                || backend.block_device != audit.block_device
                || backend.block_device_generation != audit.block_device_generation
                || block_range.block_device != audit.block_device
                || block_range.block_device_generation != audit.block_device_generation
                || block_request.block_device != audit.block_device
                || block_request.block_device_generation != audit.block_device_generation
                || block_request.block_range != audit.block_range
                || block_request.block_range_generation != audit.block_range_generation
            {
                return Err(SemanticInvariantError::BlockRequestGenerationAuditInvalid {
                    audit: audit.id,
                });
            }
            if !self.io_validation_historical_object_exists(audit.dma_buffer) {
                return Err(
                    SemanticInvariantError::BlockRequestGenerationAuditMissingTarget {
                        audit: audit.id,
                        target: audit.dma_buffer,
                    },
                );
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == audit.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::BlockRequestGenerationAuditRecorded {
                            audit: id,
                            block_device,
                            block_device_generation,
                            block_range,
                            block_range_generation,
                            block_request,
                            block_request_generation,
                            backend,
                            dma_buffer,
                            rejected_completion_generation_probes,
                            rejected_wait_generation_probes,
                            rejected_dma_generation_probes,
                            rejected_queue_generation_probes,
                            generation,
                        } if *id == audit.id
                            && *block_device == audit.block_device
                            && *block_device_generation == audit.block_device_generation
                            && *block_range == audit.block_range
                            && *block_range_generation == audit.block_range_generation
                            && *block_request == audit.block_request
                            && *block_request_generation == audit.block_request_generation
                            && *backend == audit.backend
                            && *dma_buffer == audit.dma_buffer
                            && *rejected_completion_generation_probes
                                == audit.rejected_completion_generation_probes
                            && *rejected_wait_generation_probes
                                == audit.rejected_wait_generation_probes
                            && *rejected_dma_generation_probes
                                == audit.rejected_dma_generation_probes
                            && *rejected_queue_generation_probes
                                == audit.rejected_queue_generation_probes
                            && *generation == audit.generation
                    )
            }) {
                return Err(
                    SemanticInvariantError::BlockRequestGenerationAuditMissingEvent {
                        audit: audit.id,
                        event: audit.recorded_at_event,
                    },
                );
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_block_request_generation_audit_request_generation_for_test(
        &mut self,
        audit: BlockRequestGenerationAuditId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .block_request_generation_audits
            .iter_mut()
            .find(|record| record.id == audit)
        {
            record.block_request_generation = generation;
        }
    }
}
