use super::*;

impl SemanticGraph {
    pub(crate) fn validate_network_backpressure(
        &self,
        backpressure: NetworkBackpressureId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        endpoint: Option<EndpointObjectId>,
        endpoint_generation: Option<Generation>,
        direction: PacketBufferDirection,
        reason: NetworkBackpressureReason,
        action: NetworkBackpressureAction,
        queue_depth: u32,
        queue_limit: u32,
        dropped_packets: u32,
        dropped_bytes: u32,
        sequence: u64,
    ) -> Result<(), &'static str> {
        if backpressure == 0 {
            return Err("network backpressure id=0 is invalid");
        }
        if self
            .network_backpressures
            .iter()
            .any(|record| record.id == backpressure)
        {
            return Err("network backpressure already exists");
        }
        if sequence == 0 {
            return Err("network backpressure sequence is zero");
        }
        if queue_limit == 0 || queue_depth < queue_limit {
            return Err("network backpressure requires queue depth at or above limit");
        }
        if endpoint.is_some() != endpoint_generation.is_some() {
            return Err("network backpressure endpoint generation is incomplete");
        }
        let drop_action = matches!(
            action,
            NetworkBackpressureAction::DropNewest | NetworkBackpressureAction::DropOldest
        );
        if drop_action {
            if dropped_packets == 0 || dropped_bytes == 0 {
                return Err("network backpressure drop action requires dropped packet evidence");
            }
        } else if dropped_packets != 0 || dropped_bytes != 0 {
            return Err("network backpressure non-drop action cannot report dropped packets");
        }
        if matches!(
            reason,
            NetworkBackpressureReason::SocketCapacity | NetworkBackpressureReason::OversizePacket
        ) && endpoint.is_none()
        {
            return Err("network backpressure reason requires endpoint attribution");
        }
        if matches!(action, NetworkBackpressureAction::RejectSend) && endpoint.is_none() {
            return Err("network backpressure reject-send requires endpoint attribution");
        }
        if reason == NetworkBackpressureReason::OversizePacket && !drop_action {
            return Err("network backpressure oversize packet must drop a packet");
        }
        let Some(adapter_record) = self.network_stack_adapters.iter().find(|record| {
            record.id == adapter
                && record.generation == adapter_generation
                && record.state == NetworkStackAdapterState::Bound
        }) else {
            return Err("network backpressure adapter generation is missing or inactive");
        };
        if adapter_record.packet_device != packet_device
            || adapter_record.packet_device_generation != packet_device_generation
        {
            return Err("network backpressure packet device does not match adapter");
        }
        let Some(packet_device_record) = self.packet_device_objects.iter().find(|record| {
            record.id == packet_device
                && record.generation == packet_device_generation
                && record.state == PacketDeviceObjectState::Registered
        }) else {
            return Err("network backpressure packet device generation is missing or inactive");
        };
        let Some(packet_queue_record) = self.packet_queue_objects.iter().find(|record| {
            record.id == packet_queue
                && record.generation == packet_queue_generation
                && record.state == PacketQueueObjectState::Registered
        }) else {
            return Err("network backpressure packet queue generation is missing or inactive");
        };
        let (expected_queue, expected_queue_generation, expected_role, expected_depth) =
            match direction {
                PacketBufferDirection::Rx => (
                    adapter_record.rx_queue,
                    adapter_record.rx_queue_generation,
                    PacketQueueRole::Rx,
                    adapter_record.rx_queue_depth,
                ),
                PacketBufferDirection::Tx => (
                    adapter_record.tx_queue,
                    adapter_record.tx_queue_generation,
                    PacketQueueRole::Tx,
                    adapter_record.tx_queue_depth,
                ),
            };
        if packet_queue_record.id != expected_queue
            || packet_queue_record.generation != expected_queue_generation
            || packet_queue_record.role != expected_role
            || packet_queue_record.packet_device != packet_device_record.id
            || packet_queue_record.packet_device_generation != packet_device_record.generation
            || packet_queue_record.depth != expected_depth
            || queue_limit > packet_queue_record.depth
        {
            return Err("network backpressure queue does not match adapter direction contract");
        }
        if let (Some(endpoint), Some(endpoint_generation)) = (endpoint, endpoint_generation) {
            let Some(endpoint_record) = self.endpoint_objects.iter().find(|record| {
                record.id == endpoint
                    && record.generation == endpoint_generation
                    && record.state == EndpointObjectState::Allocated
            }) else {
                return Err("network backpressure endpoint generation is missing or inactive");
            };
            if endpoint_record.adapter != adapter_record.id
                || endpoint_record.adapter_generation != adapter_record.generation
            {
                return Err("network backpressure endpoint adapter does not match");
            }
            if !self.socket_objects.iter().any(|record| {
                record.id == endpoint_record.socket
                    && record.generation == endpoint_record.socket_generation
                    && record.state == SocketObjectState::Created
            }) {
                return Err("network backpressure socket generation is missing or inactive");
            }
            let Some(store_record) = self.stores.iter().find(|record| {
                record.id == endpoint_record.owner_store
                    && record.generation == endpoint_record.owner_store_generation
            }) else {
                return Err("network backpressure owner store generation is missing");
            };
            if store_record.state == StoreState::Dead {
                return Err("network backpressure owner store is dead");
            }
        }
        if self.network_backpressures.iter().any(|record| {
            record.packet_queue == packet_queue
                && record.packet_queue_generation == packet_queue_generation
                && record.direction == direction
                && record.sequence == sequence
                && record.state == NetworkBackpressureState::Recorded
        }) {
            return Err("network backpressure sequence already exists for queue direction");
        }
        if self.check_invariants().is_err() {
            return Err("network backpressure requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_network_backpressure_with_id(
        &mut self,
        backpressure: NetworkBackpressureId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        packet_device: PacketDeviceObjectId,
        packet_device_generation: Generation,
        packet_queue: PacketQueueObjectId,
        packet_queue_generation: Generation,
        endpoint: Option<EndpointObjectId>,
        endpoint_generation: Option<Generation>,
        direction: PacketBufferDirection,
        reason: NetworkBackpressureReason,
        action: NetworkBackpressureAction,
        queue_depth: u32,
        queue_limit: u32,
        dropped_packets: u32,
        dropped_bytes: u32,
        sequence: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_network_backpressure(
                backpressure,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                endpoint,
                endpoint_generation,
                direction,
                reason,
                action,
                queue_depth,
                queue_limit,
                dropped_packets,
                dropped_bytes,
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
        self.next_network_backpressure_id = self.next_network_backpressure_id.max(backpressure + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::NetworkBackpressureRecorded {
                backpressure,
                adapter,
                adapter_generation,
                packet_device,
                packet_device_generation,
                packet_queue,
                packet_queue_generation,
                endpoint,
                endpoint_generation,
                socket,
                socket_generation,
                owner_store,
                owner_store_generation,
                direction,
                reason,
                action,
                queue_depth,
                queue_limit,
                dropped_packets,
                dropped_bytes,
                sequence,
                generation,
            },
        );
        self.network_backpressures.push(NetworkBackpressureRecord {
            id: backpressure,
            adapter,
            adapter_generation,
            packet_device,
            packet_device_generation,
            packet_queue,
            packet_queue_generation,
            endpoint,
            endpoint_generation,
            socket,
            socket_generation,
            owner_store,
            owner_store_generation,
            direction,
            reason,
            action,
            queue_depth,
            queue_limit,
            dropped_packets,
            dropped_bytes,
            sequence,
            generation,
            state: NetworkBackpressureState::Recorded,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn network_backpressures(&self) -> &[NetworkBackpressureRecord] {
        &self.network_backpressures
    }

    pub fn network_backpressure_count(&self) -> usize {
        self.network_backpressures.len()
    }

    pub fn check_network_backpressure_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.network_backpressures {
            if record.id == 0
                || record.generation == 0
                || record.adapter_generation == 0
                || record.packet_device_generation == 0
                || record.packet_queue_generation == 0
                || record.sequence == 0
                || record.queue_limit == 0
                || record.queue_depth < record.queue_limit
            {
                return Err(SemanticInvariantError::NetworkBackpressureInvalid {
                    backpressure: record.id,
                });
            }

            let Some(adapter_record) = self.network_stack_adapters.iter().find(|adapter| {
                adapter.id == record.adapter && adapter.generation == record.adapter_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBackpressureMissingAdapter {
                    backpressure: record.id,
                    adapter: record.adapter,
                });
            };
            let Some(packet_device_record) =
                self.packet_device_objects.iter().find(|packet_device| {
                    packet_device.id == record.packet_device
                        && packet_device.generation == record.packet_device_generation
                })
            else {
                return Err(
                    SemanticInvariantError::NetworkBackpressureMissingPacketDevice {
                        backpressure: record.id,
                        packet_device: record.packet_device,
                    },
                );
            };
            let Some(packet_queue_record) = self.packet_queue_objects.iter().find(|queue| {
                queue.id == record.packet_queue
                    && queue.generation == record.packet_queue_generation
            }) else {
                return Err(SemanticInvariantError::NetworkBackpressureMissingQueue {
                    backpressure: record.id,
                    packet_queue: record.packet_queue,
                });
            };
            let (expected_queue, expected_queue_generation, expected_role, expected_depth) =
                match record.direction {
                    PacketBufferDirection::Rx => (
                        adapter_record.rx_queue,
                        adapter_record.rx_queue_generation,
                        PacketQueueRole::Rx,
                        adapter_record.rx_queue_depth,
                    ),
                    PacketBufferDirection::Tx => (
                        adapter_record.tx_queue,
                        adapter_record.tx_queue_generation,
                        PacketQueueRole::Tx,
                        adapter_record.tx_queue_depth,
                    ),
                };
            if adapter_record.state != NetworkStackAdapterState::Bound
                || packet_device_record.state != PacketDeviceObjectState::Registered
                || packet_queue_record.state != PacketQueueObjectState::Registered
                || adapter_record.packet_device != record.packet_device
                || adapter_record.packet_device_generation != record.packet_device_generation
                || packet_queue_record.id != expected_queue
                || packet_queue_record.generation != expected_queue_generation
                || packet_queue_record.role != expected_role
                || packet_queue_record.packet_device != record.packet_device
                || packet_queue_record.packet_device_generation != record.packet_device_generation
                || packet_queue_record.depth != expected_depth
                || record.queue_limit > packet_queue_record.depth
            {
                return Err(SemanticInvariantError::NetworkBackpressureInvalid {
                    backpressure: record.id,
                });
            }

            if let (Some(endpoint), Some(endpoint_generation)) =
                (record.endpoint, record.endpoint_generation)
            {
                let Some(endpoint_record) = self.endpoint_objects.iter().find(|candidate| {
                    candidate.id == endpoint && candidate.generation == endpoint_generation
                }) else {
                    return Err(SemanticInvariantError::NetworkBackpressureMissingEndpoint {
                        backpressure: record.id,
                        endpoint,
                    });
                };
                if endpoint_record.state != EndpointObjectState::Allocated
                    || endpoint_record.adapter != record.adapter
                    || endpoint_record.adapter_generation != record.adapter_generation
                    || record.socket != Some(endpoint_record.socket)
                    || record.socket_generation != Some(endpoint_record.socket_generation)
                    || record.owner_store != Some(endpoint_record.owner_store)
                    || record.owner_store_generation != Some(endpoint_record.owner_store_generation)
                {
                    return Err(SemanticInvariantError::NetworkBackpressureInvalid {
                        backpressure: record.id,
                    });
                }
                if !self.socket_objects.iter().any(|socket| {
                    socket.id == endpoint_record.socket
                        && socket.generation == endpoint_record.socket_generation
                        && socket.state == SocketObjectState::Created
                }) {
                    return Err(SemanticInvariantError::NetworkBackpressureMissingSocket {
                        backpressure: record.id,
                        socket: endpoint_record.socket,
                    });
                }
                let Some(store) = self.stores.iter().find(|store| {
                    store.id == endpoint_record.owner_store
                        && store.generation == endpoint_record.owner_store_generation
                }) else {
                    return Err(
                        SemanticInvariantError::NetworkBackpressureMissingOwnerStore {
                            backpressure: record.id,
                            store: endpoint_record.owner_store,
                        },
                    );
                };
                if store.state == StoreState::Dead {
                    return Err(SemanticInvariantError::NetworkBackpressureInvalid {
                        backpressure: record.id,
                    });
                }
            } else if record.endpoint.is_some()
                || record.endpoint_generation.is_some()
                || record.socket.is_some()
                || record.socket_generation.is_some()
                || record.owner_store.is_some()
                || record.owner_store_generation.is_some()
            {
                return Err(SemanticInvariantError::NetworkBackpressureInvalid {
                    backpressure: record.id,
                });
            }

            let drop_action = matches!(
                record.action,
                NetworkBackpressureAction::DropNewest | NetworkBackpressureAction::DropOldest
            );
            if (drop_action && (record.dropped_packets == 0 || record.dropped_bytes == 0))
                || (!drop_action && (record.dropped_packets != 0 || record.dropped_bytes != 0))
                || (matches!(
                    record.reason,
                    NetworkBackpressureReason::SocketCapacity
                        | NetworkBackpressureReason::OversizePacket
                ) && record.endpoint.is_none())
                || (record.action == NetworkBackpressureAction::RejectSend
                    && record.endpoint.is_none())
                || (record.reason == NetworkBackpressureReason::OversizePacket && !drop_action)
            {
                return Err(SemanticInvariantError::NetworkBackpressureInvalid {
                    backpressure: record.id,
                });
            }

            if let Some(duplicate) = self.network_backpressures.iter().find(|other| {
                other.id != record.id
                    && other.packet_queue == record.packet_queue
                    && other.packet_queue_generation == record.packet_queue_generation
                    && other.direction == record.direction
                    && other.sequence == record.sequence
                    && other.state == NetworkBackpressureState::Recorded
                    && record.state == NetworkBackpressureState::Recorded
            }) {
                return Err(
                    SemanticInvariantError::NetworkBackpressureDuplicateSequence {
                        backpressure: duplicate.id,
                        packet_queue: record.packet_queue,
                        sequence: record.sequence,
                    },
                );
            }

            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkBackpressureRecorded {
                            backpressure,
                            adapter,
                            adapter_generation,
                            packet_device,
                            packet_device_generation,
                            packet_queue,
                            packet_queue_generation,
                            endpoint,
                            endpoint_generation,
                            socket,
                            socket_generation,
                            owner_store,
                            owner_store_generation,
                            direction,
                            reason,
                            action,
                            queue_depth,
                            queue_limit,
                            dropped_packets,
                            dropped_bytes,
                            sequence,
                            generation,
                        } if *backpressure == record.id
                            && *adapter == record.adapter
                            && *adapter_generation == record.adapter_generation
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *packet_queue == record.packet_queue
                            && *packet_queue_generation == record.packet_queue_generation
                            && *endpoint == record.endpoint
                            && *endpoint_generation == record.endpoint_generation
                            && *socket == record.socket
                            && *socket_generation == record.socket_generation
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *direction == record.direction
                            && *reason == record.reason
                            && *action == record.action
                            && *queue_depth == record.queue_depth
                            && *queue_limit == record.queue_limit
                            && *dropped_packets == record.dropped_packets
                            && *dropped_bytes == record.dropped_bytes
                            && *sequence == record.sequence
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::NetworkBackpressureMissingEvent {
                    backpressure: record.id,
                    event: record.recorded_at_event,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_backpressure_queue_generation_for_test(
        &mut self,
        backpressure: NetworkBackpressureId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .network_backpressures
            .iter_mut()
            .find(|record| record.id == backpressure)
        {
            record.packet_queue_generation = generation;
        }
    }
}
