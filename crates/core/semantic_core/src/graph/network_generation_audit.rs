use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_network_generation_audit(
        &self,
        audit: NetworkGenerationAuditId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        packet_descriptor: PacketDescriptorObjectId,
        packet_descriptor_generation: Generation,
        packet_buffer: PacketBufferObjectId,
        packet_buffer_generation: Generation,
        dma_buffer: ContractObjectRef,
        device_capability: ContractObjectRef,
        rejected_packet_generation_probes: u32,
        rejected_dma_generation_probes: u32,
    ) -> Result<(), &'static str> {
        if audit == 0 {
            return Err("network generation audit id=0 is invalid");
        }
        if self.network_generation_audits.iter().any(|record| record.id == audit) {
            return Err("network generation audit already exists");
        }
        if rejected_packet_generation_probes == 0 || rejected_dma_generation_probes == 0 {
            return Err("network generation audit requires rejected packet and dma probes");
        }
        if dma_buffer.kind != ContractObjectKind::DmaBufferObject {
            return Err("network generation audit dma target is not a dma buffer");
        }
        if device_capability.kind != ContractObjectKind::DeviceCapability {
            return Err("network generation audit capability target is not a device capability");
        }

        let Some(adapter_record) = self.network_stack_adapters.iter().find(|record| {
            record.id == adapter
                && record.generation == adapter_generation
                && record.state == NetworkStackAdapterState::Bound
        }) else {
            return Err("network generation audit adapter generation is missing or inactive");
        };
        if adapter_record.packet_device != packet_device
            || adapter_record.packet_device_generation != packet_device_generation
        {
            return Err("network generation audit adapter does not match packet device");
        }

        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == packet_device
                && record.generation == packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err("network generation audit packet device generation is missing or inactive");
        };
        let Some(packet_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == packet_queue
                && record.generation == packet_queue_generation
                && record.state == PacketQueueObjectState::Registered
        }) else {
            return Err("network generation audit packet queue generation is missing or inactive");
        };
        if packet_queue_record.packet_device != packet_device_record.id
            || packet_queue_record.packet_device_generation != packet_device_record.generation
            || !((adapter_record.rx_queue == packet_queue_record.id
                && adapter_record.rx_queue_generation == packet_queue_record.generation)
                || (adapter_record.tx_queue == packet_queue_record.id
                    && adapter_record.tx_queue_generation == packet_queue_record.generation))
        {
            return Err("network generation audit queue does not match adapter packet device");
        }

        let Some(packet_buffer_record) = self.packet_buffer_objects.iter().find(|record| {
            record.id == packet_buffer
                && record.generation == packet_buffer_generation
                && record.state == PacketBufferObjectState::Filled
        }) else {
            return Err("network generation audit packet buffer generation is missing or inactive");
        };
        if packet_buffer_record.packet_device != packet_device_record.id
            || packet_buffer_record.packet_device_generation != packet_device_record.generation
        {
            return Err("network generation audit packet buffer does not match packet device");
        }

        let Some(packet_descriptor_record) = self.packet_descriptors.iter().find(|record| {
            record.id == packet_descriptor
                && record.generation == packet_descriptor_generation
                && record.state == PacketDescriptorObjectState::Registered
        }) else {
            return Err(
                "network generation audit packet descriptor generation is missing or inactive",
            );
        };
        if packet_descriptor_record.packet_queue != packet_queue_record.id
            || packet_descriptor_record.packet_queue_generation != packet_queue_record.generation
            || packet_descriptor_record.packet_buffer != packet_buffer_record.id
            || packet_descriptor_record.packet_buffer_generation != packet_buffer_record.generation
        {
            return Err("network generation audit descriptor does not match queue/buffer");
        }

        if !self.io_validation_historical_object_exists(dma_buffer) {
            return Err("network generation audit dma buffer generation is missing");
        }
        if !self.io_validation_historical_object_exists(device_capability) {
            return Err("network generation audit device capability generation is missing");
        }
        if self.check_invariants().is_err() {
            return Err("network generation audit requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_network_generation_audit_with_id(
        &mut self,
        audit: NetworkGenerationAuditId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        packet_descriptor: PacketDescriptorObjectId,
        packet_descriptor_generation: Generation,
        packet_buffer: PacketBufferObjectId,
        packet_buffer_generation: Generation,
        dma_buffer: ContractObjectRef,
        device_capability: ContractObjectRef,
        rejected_packet_generation_probes: u32,
        rejected_dma_generation_probes: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_network_generation_audit(
                audit,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                dma_buffer,
                device_capability,
                rejected_packet_generation_probes,
                rejected_dma_generation_probes,
            )
            .is_err()
        {
            return false;
        }

        let generation = 1;
        self.next_network_generation_audit_id =
            self.next_network_generation_audit_id.max(audit + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::NetworkGenerationAuditRecorded {
                audit,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                packet_descriptor,
                packet_descriptor_generation,
                packet_buffer,
                packet_buffer_generation,
                dma_buffer,
                device_capability,
                rejected_packet_generation_probes,
                rejected_dma_generation_probes,
                generation,
            },
        );
        self.network_generation_audits.push(NetworkGenerationAuditRecord {
            id: audit,
            adapter,
            adapter_generation,
            packet_device,
            packet_device_generation,
            packet_queue,
            packet_queue_generation,
            packet_descriptor,
            packet_descriptor_generation,
            packet_buffer,
            packet_buffer_generation,
            dma_buffer,
            device_capability,
            rejected_packet_generation_probes,
            rejected_dma_generation_probes,
            generation,
            state: NetworkGenerationAuditState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn network_generation_audits(&self) -> &[NetworkGenerationAuditRecord] {
        &self.network_generation_audits
    }

    pub fn network_generation_audit_count(&self) -> usize {
        self.network_generation_audits.len()
    }

    pub fn check_network_generation_audit_invariants(&self) -> Result<(), SemanticInvariantError> {
        for audit in &self.network_generation_audits {
            if audit.id == 0
                || audit.generation == 0
                || audit.adapter_generation == 0
                || audit.packet_device_generation == 0
                || audit.packet_queue_generation == 0
                || audit.packet_descriptor_generation == 0
                || audit.packet_buffer_generation == 0
                || audit.dma_buffer.generation == 0
                || audit.device_capability.generation == 0
                || audit.rejected_packet_generation_probes == 0
                || audit.rejected_dma_generation_probes == 0
                || audit.state != NetworkGenerationAuditState::Recorded
            {
                return Err(SemanticInvariantError::NetworkGenerationAuditInvalid {
                    audit: audit.id,
                });
            }

            let Some(adapter) = self.network_stack_adapters.iter().find(|record| {
                record.id == audit.adapter && record.generation == audit.adapter_generation
            }) else {
                return Err(SemanticInvariantError::NetworkGenerationAuditMissingTarget {
                    audit: audit.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::NetworkStackAdapter,
                        audit.adapter,
                        audit.adapter_generation,
                    ),
                });
            };
            let Some(packet_device) = self.packet_device_objects.iter().find(|record| {
                record.id == audit.packet_device
                    && record.generation == audit.packet_device_generation
            }) else {
                return Err(SemanticInvariantError::NetworkGenerationAuditMissingTarget {
                    audit: audit.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::PacketDeviceObject,
                        audit.packet_device,
                        audit.packet_device_generation,
                    ),
                });
            };
            let Some(packet_queue) = self.packet_queue_objects.iter().find(|record| {
                record.id == audit.packet_queue
                    && record.generation == audit.packet_queue_generation
            }) else {
                return Err(SemanticInvariantError::NetworkGenerationAuditMissingTarget {
                    audit: audit.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::PacketQueueObject,
                        audit.packet_queue,
                        audit.packet_queue_generation,
                    ),
                });
            };
            let Some(packet_descriptor) = self.packet_descriptors.iter().find(|record| {
                record.id == audit.packet_descriptor
                    && record.generation == audit.packet_descriptor_generation
            }) else {
                return Err(SemanticInvariantError::NetworkGenerationAuditMissingTarget {
                    audit: audit.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::PacketDescriptorObject,
                        audit.packet_descriptor,
                        audit.packet_descriptor_generation,
                    ),
                });
            };
            let Some(packet_buffer) = self.packet_buffer_objects.iter().find(|record| {
                record.id == audit.packet_buffer
                    && record.generation == audit.packet_buffer_generation
            }) else {
                return Err(SemanticInvariantError::NetworkGenerationAuditMissingTarget {
                    audit: audit.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::PacketBufferObject,
                        audit.packet_buffer,
                        audit.packet_buffer_generation,
                    ),
                });
            };

            if adapter.state != NetworkStackAdapterState::Bound
                || packet_device.state != PacketDeviceObjectState::Registered
                || packet_queue.state != PacketQueueObjectState::Registered
                || packet_descriptor.state != PacketDescriptorObjectState::Registered
                || packet_buffer.state != PacketBufferObjectState::Filled
                || adapter.packet_device != audit.packet_device
                || adapter.packet_device_generation != audit.packet_device_generation
                || packet_queue.packet_device != audit.packet_device
                || packet_queue.packet_device_generation != audit.packet_device_generation
                || packet_buffer.packet_device != audit.packet_device
                || packet_buffer.packet_device_generation != audit.packet_device_generation
                || packet_descriptor.packet_queue != audit.packet_queue
                || packet_descriptor.packet_queue_generation != audit.packet_queue_generation
                || packet_descriptor.packet_buffer != audit.packet_buffer
                || packet_descriptor.packet_buffer_generation != audit.packet_buffer_generation
                || !((adapter.rx_queue == audit.packet_queue
                    && adapter.rx_queue_generation == audit.packet_queue_generation)
                    || (adapter.tx_queue == audit.packet_queue
                        && adapter.tx_queue_generation == audit.packet_queue_generation))
            {
                return Err(SemanticInvariantError::NetworkGenerationAuditInvalid {
                    audit: audit.id,
                });
            }

            for target in [audit.dma_buffer, audit.device_capability] {
                if !self.io_validation_historical_object_exists(target) {
                    return Err(SemanticInvariantError::NetworkGenerationAuditMissingTarget {
                        audit: audit.id,
                        target,
                    });
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == audit.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkGenerationAuditRecorded {
                            audit: id,
                            adapter,
                            adapter_generation,
                            packet_device,
                            packet_device_generation,
                            packet_queue,
                            packet_queue_generation,
                            packet_descriptor,
                            packet_descriptor_generation,
                            packet_buffer,
                            packet_buffer_generation,
                            dma_buffer,
                            device_capability,
                            rejected_packet_generation_probes,
                            rejected_dma_generation_probes,
                            generation,
                        } if *id == audit.id
                            && *adapter == audit.adapter
                            && *adapter_generation == audit.adapter_generation
                            && *packet_device == audit.packet_device
                            && *packet_device_generation == audit.packet_device_generation
                            && *packet_queue == audit.packet_queue
                            && *packet_queue_generation == audit.packet_queue_generation
                            && *packet_descriptor == audit.packet_descriptor
                            && *packet_descriptor_generation == audit.packet_descriptor_generation
                            && *packet_buffer == audit.packet_buffer
                            && *packet_buffer_generation == audit.packet_buffer_generation
                            && *dma_buffer == audit.dma_buffer
                            && *device_capability == audit.device_capability
                            && *rejected_packet_generation_probes
                                == audit.rejected_packet_generation_probes
                            && *rejected_dma_generation_probes
                                == audit.rejected_dma_generation_probes
                            && *generation == audit.generation
                    )
            }) {
                return Err(SemanticInvariantError::NetworkGenerationAuditMissingEvent {
                    audit: audit.id,
                    event: audit.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_generation_audit_descriptor_generation_for_test(
        &mut self,
        audit: NetworkGenerationAuditId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.network_generation_audits.iter_mut().find(|record| record.id == audit)
        {
            record.packet_descriptor_generation = generation;
        }
    }
}
