use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_network_fault_injection(
        &self,
        injection: NetworkFaultInjectionId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        packet_descriptor: Option<PacketDescriptorObjectId>,
        packet_descriptor_generation: Option<Generation>,
        packet_buffer: Option<PacketBufferObjectId>,
        packet_buffer_generation: Option<Generation>,
        endpoint: Option<EndpointObjectId>,
        endpoint_generation: Option<Generation>,
        direction: PacketBufferDirection,
        kind: NetworkFaultInjectionKind,
        effect: NetworkFaultInjectionEffect,
        injected_packets: u32,
        dropped_packets: u32,
        error_packets: u32,
        error_code: &str,
        sequence: u64,
    ) -> Result<(), &'static str> {
        if injection == 0 {
            return Err("network fault injection id=0 is invalid");
        }
        if self.network_fault_injections.iter().any(|record| record.id == injection) {
            return Err("network fault injection already exists");
        }
        if sequence == 0 || injected_packets == 0 {
            return Err("network fault injection requires nonzero sequence and packet count");
        }
        if packet_descriptor.is_some() != packet_descriptor_generation.is_some()
            || packet_buffer.is_some() != packet_buffer_generation.is_some()
            || endpoint.is_some() != endpoint_generation.is_some()
        {
            return Err("network fault injection reference generation is incomplete");
        }
        if packet_descriptor.is_some() && packet_buffer.is_none() {
            return Err("network fault injection descriptor requires packet buffer attribution");
        }

        match kind {
            NetworkFaultInjectionKind::PacketLoss => {
                if effect != NetworkFaultInjectionEffect::DropPacket
                    || dropped_packets != injected_packets
                    || error_packets != 0
                    || !error_code.is_empty()
                {
                    return Err(
                        "network packet loss injection must drop exactly the injected packets",
                    );
                }
            }
            NetworkFaultInjectionKind::PacketError => {
                if effect != NetworkFaultInjectionEffect::ReportError
                    || error_packets != injected_packets
                    || dropped_packets != 0
                    || error_code.is_empty()
                    || endpoint.is_none()
                    || packet_descriptor.is_none()
                    || packet_buffer.is_none()
                {
                    return Err(
                        "network packet error injection requires endpoint, descriptor, buffer, and error code",
                    );
                }
            }
        }

        let Some(adapter_record) = self.network_stack_adapters.iter().find(|record| {
            record.id == adapter
                && record.generation == adapter_generation
                && record.state == NetworkStackAdapterState::Bound
        }) else {
            return Err("network fault injection adapter generation is missing or inactive");
        };
        if adapter_record.packet_device != packet_device
            || adapter_record.packet_device_generation != packet_device_generation
        {
            return Err("network fault injection packet device does not match adapter");
        }

        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == packet_device
                && record.generation == packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err("network fault injection packet device generation is missing or inactive");
        };
        let Some(packet_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == packet_queue
                && record.generation == packet_queue_generation
                && record.state == PacketQueueObjectState::Registered
        }) else {
            return Err("network fault injection packet queue generation is missing or inactive");
        };
        let (expected_queue, expected_queue_generation, expected_role) = match direction {
            PacketBufferDirection::Rx => {
                (adapter_record.rx_queue, adapter_record.rx_queue_generation, PacketQueueRole::Rx)
            }
            PacketBufferDirection::Tx => {
                (adapter_record.tx_queue, adapter_record.tx_queue_generation, PacketQueueRole::Tx)
            }
        };
        if packet_queue_record.id != expected_queue
            || packet_queue_record.generation != expected_queue_generation
            || packet_queue_record.role != expected_role
            || packet_queue_record.packet_device != packet_device_record.id
            || packet_queue_record.packet_device_generation != packet_device_record.generation
        {
            return Err("network fault injection queue does not match adapter direction contract");
        }

        if let (Some(packet_buffer), Some(packet_buffer_generation)) =
            (packet_buffer, packet_buffer_generation)
        {
            let Some(packet_buffer_record) = self.packet_buffer_objects.iter().find(|record| {
                record.id == packet_buffer
                    && record.generation == packet_buffer_generation
                    && record.state == PacketBufferObjectState::Filled
            }) else {
                return Err(
                    "network fault injection packet buffer generation is missing or inactive",
                );
            };
            if packet_buffer_record.packet_device != packet_device_record.id
                || packet_buffer_record.packet_device_generation != packet_device_record.generation
                || packet_buffer_record.direction != direction
            {
                return Err("network fault injection packet buffer does not match target queue");
            }
        }

        if let (Some(packet_descriptor), Some(packet_descriptor_generation)) =
            (packet_descriptor, packet_descriptor_generation)
        {
            let Some(expected_buffer) = packet_buffer else {
                return Err(
                    "network fault injection descriptor requires packet buffer attribution",
                );
            };
            let Some(expected_buffer_generation) = packet_buffer_generation else {
                return Err(
                    "network fault injection descriptor requires packet buffer attribution",
                );
            };
            let Some(packet_descriptor_record) = self.packet_descriptors.iter().find(|record| {
                record.id == packet_descriptor
                    && record.generation == packet_descriptor_generation
                    && record.state == PacketDescriptorObjectState::Registered
            }) else {
                return Err(
                    "network fault injection packet descriptor generation is missing or inactive",
                );
            };
            if packet_descriptor_record.packet_queue != packet_queue_record.id
                || packet_descriptor_record.packet_queue_generation
                    != packet_queue_record.generation
                || packet_descriptor_record.packet_buffer != expected_buffer
                || packet_descriptor_record.packet_buffer_generation != expected_buffer_generation
            {
                return Err("network fault injection descriptor does not match queue/buffer");
            }
        }

        if let (Some(endpoint), Some(endpoint_generation)) = (endpoint, endpoint_generation) {
            let Some(endpoint_record) = self.endpoint_objects.iter().find(|record| {
                record.id == endpoint
                    && record.generation == endpoint_generation
                    && record.state == EndpointObjectState::Allocated
            }) else {
                return Err("network fault injection endpoint generation is missing or inactive");
            };
            if endpoint_record.adapter != adapter_record.id
                || endpoint_record.adapter_generation != adapter_record.generation
            {
                return Err("network fault injection endpoint adapter does not match");
            }
            if !self.socket_objects.iter().any(|record| {
                record.id == endpoint_record.socket
                    && record.generation == endpoint_record.socket_generation
                    && record.state == SocketObjectState::Created
            }) {
                return Err("network fault injection socket generation is missing or inactive");
            }
            let Some(store_record) = self.domains.lifecycle.stores.iter().find(|record| {
                record.id == endpoint_record.owner_store
                    && record.generation == endpoint_record.owner_store_generation
            }) else {
                return Err("network fault injection owner store generation is missing");
            };
            if store_record.state == StoreState::Dead {
                return Err("network fault injection owner store is dead");
            }
        }

        if self.network_fault_injections.iter().any(|record| {
            record.packet_queue == packet_queue
                && record.packet_queue_generation == packet_queue_generation
                && record.direction == direction
                && record.sequence == sequence
                && record.state == NetworkFaultInjectionState::Recorded
        }) {
            return Err("network fault injection sequence already exists for queue direction");
        }
        if self.check_invariants().is_err() {
            return Err("network fault injection requires invariant-clean graph");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_network_fault_injection_with_id(
        &mut self,
        injection: NetworkFaultInjectionId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        packet_descriptor: Option<PacketDescriptorObjectId>,
        packet_descriptor_generation: Option<Generation>,
        packet_buffer: Option<PacketBufferObjectId>,
        packet_buffer_generation: Option<Generation>,
        endpoint: Option<EndpointObjectId>,
        endpoint_generation: Option<Generation>,
        direction: PacketBufferDirection,
        kind: NetworkFaultInjectionKind,
        effect: NetworkFaultInjectionEffect,
        injected_packets: u32,
        dropped_packets: u32,
        error_packets: u32,
        error_code: &str,
        sequence: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_network_fault_injection(
                injection,
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
                endpoint,
                endpoint_generation,
                direction,
                kind,
                effect,
                injected_packets,
                dropped_packets,
                error_packets,
                error_code,
                sequence,
            )
            .is_err()
        {
            return false;
        }

        let (socket, socket_generation, owner_store, owner_store_generation) =
            if let (Some(endpoint), Some(endpoint_generation)) = (endpoint, endpoint_generation) {
                let Some(endpoint_record) = self.endpoint_objects.iter().find(|record| {
                    record.id == endpoint && record.generation == endpoint_generation
                }) else {
                    return false;
                };
                (
                    Some(endpoint_record.socket),
                    Some(endpoint_record.socket_generation),
                    Some(endpoint_record.owner_store),
                    Some(endpoint_record.owner_store_generation),
                )
            } else {
                (None, None, None, None)
            };

        let generation = 1;
        self.next_network_fault_injection_id =
            self.next_network_fault_injection_id.max(injection + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::NetworkFaultInjectionRecorded {
                injection,
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
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                owner_store,
                owner_store_generation,
                direction,
                kind,
                effect,
                injected_packets,
                dropped_packets,
                error_packets,
                error_code: error_code.to_string(),
                sequence,
                generation,
            },
        );
        self.network_fault_injections.push(NetworkFaultInjectionRecord {
            id: injection,
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
            endpoint,
            endpoint_generation,
            socket,
            socket_generation,
            owner_store,
            owner_store_generation,
            direction,
            kind,
            effect,
            injected_packets,
            dropped_packets,
            error_packets,
            error_code: error_code.to_string(),
            sequence,
            generation,
            state: NetworkFaultInjectionState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn network_fault_injections(&self) -> &[NetworkFaultInjectionRecord] {
        &self.network_fault_injections
    }

    pub fn network_fault_injection_count(&self) -> usize {
        self.network_fault_injections.len()
    }

    pub fn check_network_fault_injection_invariants(&self) -> Result<(), SemanticInvariantError> {
        for injection in &self.network_fault_injections {
            if injection.id == 0
                || injection.generation == 0
                || injection.adapter_generation == 0
                || injection.packet_device_generation == 0
                || injection.packet_queue_generation == 0
                || injection.sequence == 0
                || injection.injected_packets == 0
                || injection.state != NetworkFaultInjectionState::Recorded
                || injection.packet_descriptor.is_some()
                    != injection.packet_descriptor_generation.is_some()
                || injection.packet_buffer.is_some() != injection.packet_buffer_generation.is_some()
                || injection.endpoint.is_some() != injection.endpoint_generation.is_some()
            {
                return Err(SemanticInvariantError::NetworkFaultInjectionInvalid {
                    injection: injection.id,
                });
            }

            let Some(adapter) = self.network_stack_adapters.iter().find(|record| {
                record.id == injection.adapter && record.generation == injection.adapter_generation
            }) else {
                return Err(SemanticInvariantError::NetworkFaultInjectionMissingTarget {
                    injection: injection.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::NetworkStackAdapter,
                        injection.adapter,
                        injection.adapter_generation,
                    ),
                });
            };
            let Some(packet_device) = self.packet_device_objects.iter().find(|record| {
                record.id == injection.packet_device
                    && record.generation == injection.packet_device_generation
            }) else {
                return Err(SemanticInvariantError::NetworkFaultInjectionMissingTarget {
                    injection: injection.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::PacketDeviceObject,
                        injection.packet_device,
                        injection.packet_device_generation,
                    ),
                });
            };
            let Some(packet_queue) = self.packet_queue_objects.iter().find(|record| {
                record.id == injection.packet_queue
                    && record.generation == injection.packet_queue_generation
            }) else {
                return Err(SemanticInvariantError::NetworkFaultInjectionMissingTarget {
                    injection: injection.id,
                    target: ContractObjectRef::new(
                        ContractObjectKind::PacketQueueObject,
                        injection.packet_queue,
                        injection.packet_queue_generation,
                    ),
                });
            };
            let (expected_queue, expected_queue_generation, expected_role) =
                match injection.direction {
                    PacketBufferDirection::Rx => {
                        (adapter.rx_queue, adapter.rx_queue_generation, PacketQueueRole::Rx)
                    }
                    PacketBufferDirection::Tx => {
                        (adapter.tx_queue, adapter.tx_queue_generation, PacketQueueRole::Tx)
                    }
                };
            if adapter.state != NetworkStackAdapterState::Bound
                || packet_device.state != PacketDeviceObjectState::Registered
                || packet_queue.state != PacketQueueObjectState::Registered
                || adapter.packet_device != injection.packet_device
                || adapter.packet_device_generation != injection.packet_device_generation
                || packet_queue.id != expected_queue
                || packet_queue.generation != expected_queue_generation
                || packet_queue.role != expected_role
                || packet_queue.packet_device != injection.packet_device
                || packet_queue.packet_device_generation != injection.packet_device_generation
            {
                return Err(SemanticInvariantError::NetworkFaultInjectionInvalid {
                    injection: injection.id,
                });
            }

            if let (Some(packet_buffer), Some(packet_buffer_generation)) =
                (injection.packet_buffer, injection.packet_buffer_generation)
            {
                let Some(buffer) = self.packet_buffer_objects.iter().find(|record| {
                    record.id == packet_buffer && record.generation == packet_buffer_generation
                }) else {
                    return Err(SemanticInvariantError::NetworkFaultInjectionMissingTarget {
                        injection: injection.id,
                        target: ContractObjectRef::new(
                            ContractObjectKind::PacketBufferObject,
                            packet_buffer,
                            packet_buffer_generation,
                        ),
                    });
                };
                if buffer.state != PacketBufferObjectState::Filled
                    || buffer.packet_device != injection.packet_device
                    || buffer.packet_device_generation != injection.packet_device_generation
                    || buffer.direction != injection.direction
                {
                    return Err(SemanticInvariantError::NetworkFaultInjectionInvalid {
                        injection: injection.id,
                    });
                }
            }
            if let (Some(packet_descriptor), Some(packet_descriptor_generation)) =
                (injection.packet_descriptor, injection.packet_descriptor_generation)
            {
                let Some(expected_buffer) = injection.packet_buffer else {
                    return Err(SemanticInvariantError::NetworkFaultInjectionInvalid {
                        injection: injection.id,
                    });
                };
                let Some(expected_buffer_generation) = injection.packet_buffer_generation else {
                    return Err(SemanticInvariantError::NetworkFaultInjectionInvalid {
                        injection: injection.id,
                    });
                };
                let Some(descriptor) = self.packet_descriptors.iter().find(|record| {
                    record.id == packet_descriptor
                        && record.generation == packet_descriptor_generation
                }) else {
                    return Err(SemanticInvariantError::NetworkFaultInjectionMissingTarget {
                        injection: injection.id,
                        target: ContractObjectRef::new(
                            ContractObjectKind::PacketDescriptorObject,
                            packet_descriptor,
                            packet_descriptor_generation,
                        ),
                    });
                };
                if descriptor.state != PacketDescriptorObjectState::Registered
                    || descriptor.packet_queue != injection.packet_queue
                    || descriptor.packet_queue_generation != injection.packet_queue_generation
                    || descriptor.packet_buffer != expected_buffer
                    || descriptor.packet_buffer_generation != expected_buffer_generation
                {
                    return Err(SemanticInvariantError::NetworkFaultInjectionInvalid {
                        injection: injection.id,
                    });
                }
            }
            if let (Some(endpoint), Some(endpoint_generation)) =
                (injection.endpoint, injection.endpoint_generation)
            {
                let Some(endpoint_record) = self.endpoint_objects.iter().find(|record| {
                    record.id == endpoint && record.generation == endpoint_generation
                }) else {
                    return Err(SemanticInvariantError::NetworkFaultInjectionMissingTarget {
                        injection: injection.id,
                        target: ContractObjectRef::new(
                            ContractObjectKind::EndpointObject,
                            endpoint,
                            endpoint_generation,
                        ),
                    });
                };
                if endpoint_record.state != EndpointObjectState::Allocated
                    || endpoint_record.adapter != injection.adapter
                    || endpoint_record.adapter_generation != injection.adapter_generation
                    || injection.socket != Some(endpoint_record.socket)
                    || injection.socket_generation != Some(endpoint_record.socket_generation)
                    || injection.owner_store != Some(endpoint_record.owner_store)
                    || injection.owner_store_generation
                        != Some(endpoint_record.owner_store_generation)
                {
                    return Err(SemanticInvariantError::NetworkFaultInjectionInvalid {
                        injection: injection.id,
                    });
                }
                if !self.socket_objects.iter().any(|socket| {
                    socket.id == endpoint_record.socket
                        && socket.generation == endpoint_record.socket_generation
                        && socket.state == SocketObjectState::Created
                }) {
                    return Err(SemanticInvariantError::NetworkFaultInjectionMissingTarget {
                        injection: injection.id,
                        target: ContractObjectRef::new(
                            ContractObjectKind::SocketObject,
                            endpoint_record.socket,
                            endpoint_record.socket_generation,
                        ),
                    });
                }
            } else if injection.socket.is_some()
                || injection.socket_generation.is_some()
                || injection.owner_store.is_some()
                || injection.owner_store_generation.is_some()
            {
                return Err(SemanticInvariantError::NetworkFaultInjectionInvalid {
                    injection: injection.id,
                });
            }

            if (injection.kind == NetworkFaultInjectionKind::PacketLoss
                && (injection.effect != NetworkFaultInjectionEffect::DropPacket
                    || injection.dropped_packets != injection.injected_packets
                    || injection.error_packets != 0
                    || !injection.error_code.is_empty()))
                || (injection.kind == NetworkFaultInjectionKind::PacketError
                    && (injection.effect != NetworkFaultInjectionEffect::ReportError
                        || injection.error_packets != injection.injected_packets
                        || injection.dropped_packets != 0
                        || injection.error_code.is_empty()
                        || injection.endpoint.is_none()
                        || injection.packet_descriptor.is_none()
                        || injection.packet_buffer.is_none()))
            {
                return Err(SemanticInvariantError::NetworkFaultInjectionInvalid {
                    injection: injection.id,
                });
            }

            if let Some(duplicate) = self.network_fault_injections.iter().find(|other| {
                other.id != injection.id
                    && other.packet_queue == injection.packet_queue
                    && other.packet_queue_generation == injection.packet_queue_generation
                    && other.direction == injection.direction
                    && other.sequence == injection.sequence
                    && other.state == NetworkFaultInjectionState::Recorded
                    && injection.state == NetworkFaultInjectionState::Recorded
            }) {
                return Err(SemanticInvariantError::NetworkFaultInjectionDuplicateSequence {
                    injection: duplicate.id,
                    packet_queue: injection.packet_queue,
                    sequence: injection.sequence,
                });
            }

            if !self.event_log.events.iter().any(|event| {
                event.id == injection.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkFaultInjectionRecorded {
                            injection: id,
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
                            endpoint,
                            endpoint_generation,
                            socket,
                            socket_generation,
                            owner_store,
                            owner_store_generation,
                            direction,
                            kind,
                            effect,
                            injected_packets,
                            dropped_packets,
                            error_packets,
                            error_code,
                            sequence,
                            generation,
                        } if *id == injection.id
                            && *adapter == injection.adapter
                            && *adapter_generation == injection.adapter_generation
                            && *packet_device == injection.packet_device
                            && *packet_device_generation == injection.packet_device_generation
                            && *packet_queue == injection.packet_queue
                            && *packet_queue_generation == injection.packet_queue_generation
                            && *packet_descriptor == injection.packet_descriptor
                            && *packet_descriptor_generation
                                == injection.packet_descriptor_generation
                            && *packet_buffer == injection.packet_buffer
                            && *packet_buffer_generation == injection.packet_buffer_generation
                            && *endpoint == injection.endpoint
                            && *endpoint_generation == injection.endpoint_generation
                            && *socket == injection.socket
                            && *socket_generation == injection.socket_generation
                            && *owner_store == injection.owner_store
                            && *owner_store_generation == injection.owner_store_generation
                            && *direction == injection.direction
                            && *kind == injection.kind
                            && *effect == injection.effect
                            && *injected_packets == injection.injected_packets
                            && *dropped_packets == injection.dropped_packets
                            && *error_packets == injection.error_packets
                            && *error_code == injection.error_code
                            && *sequence == injection.sequence
                            && *generation == injection.generation
                    )
            }) {
                return Err(SemanticInvariantError::NetworkFaultInjectionMissingEvent {
                    injection: injection.id,
                    event: injection.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_fault_injection_queue_generation_for_test(
        &mut self,
        injection: NetworkFaultInjectionId,
        generation: Generation,
    ) {
        if let Some(record) =
            self.network_fault_injections.iter_mut().find(|record| record.id == injection)
        {
            record.packet_queue_generation = generation;
        }
    }
}
