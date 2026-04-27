use super::*;

impl SemanticGraph {
    pub(crate) fn validate_network_tx_completion(
        &self,
        completion: NetworkTxCompletionId,
        tx_gate: NetworkTxCapabilityGateId,
        tx_gate_generation: Generation,
        backend: ContractObjectRef,
        completion_sequence: u64,
    ) -> Result<(), &'static str> {
        if completion == 0 {
            return Err("network tx completion id=0 is invalid");
        }
        if completion_sequence == 0 {
            return Err("network tx completion sequence is zero");
        }
        if backend.id == 0 || backend.generation == 0 {
            return Err("network tx completion backend ref is invalid");
        }
        if self
            .network_tx_completions
            .iter()
            .any(|record| record.id == completion)
        {
            return Err("network tx completion already exists");
        }
        let Some(gate_record) = self.network_tx_capability_gates.iter().find(|record| {
            record.id == tx_gate
                && record.generation == tx_gate_generation
                && record.state == NetworkTxCapabilityGateState::Allowed
        }) else {
            return Err("network tx completion gate generation is missing or inactive");
        };
        if self.network_tx_completions.iter().any(|record| {
            record.tx_gate == gate_record.id
                && record.tx_gate_generation == gate_record.generation
                && record.state == NetworkTxCompletionState::Completed
        }) {
            return Err("network tx completion gate already completed");
        }
        if self.network_tx_completions.iter().any(|record| {
            record.tx_queue == gate_record.tx_queue
                && record.tx_queue_generation == gate_record.tx_queue_generation
                && record.completion_sequence == completion_sequence
                && record.state == NetworkTxCompletionState::Completed
        }) {
            return Err("network tx completion sequence already exists for tx queue generation");
        }
        let Some((backend_packet_device, backend_packet_device_generation)) =
            self.live_network_backend_packet_device(backend)
        else {
            return Err("network tx completion backend generation is missing or inactive");
        };
        if backend_packet_device != gate_record.packet_device
            || backend_packet_device_generation != gate_record.packet_device_generation
        {
            return Err("network tx completion backend packet device mismatch");
        }
        if backend.kind == ContractObjectKind::VirtioNetBackendObject {
            let Some(backend_record) = self
                .virtio_net_backends
                .iter()
                .find(|record| record.id == backend.id && record.generation == backend.generation)
            else {
                return Err("network tx completion backend generation is missing or inactive");
            };
            let Some(binding_record) = self.driver_store_bindings.iter().find(|record| {
                record.id == backend_record.driver_binding
                    && record.generation == backend_record.driver_binding_generation
            }) else {
                return Err("network tx completion driver binding generation is missing");
            };
            if binding_record.driver_store != gate_record.driver_store
                || binding_record.driver_store_generation != gate_record.driver_store_generation
            {
                return Err("network tx completion driver store mismatch");
            }
        }
        if self.check_invariants().is_err() {
            return Err("network tx completion requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_network_tx_completion_with_id(
        &mut self,
        completion: NetworkTxCompletionId,
        tx_gate: NetworkTxCapabilityGateId,
        tx_gate_generation: Generation,
        backend: ContractObjectRef,
        completion_sequence: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_network_tx_completion(
                completion,
                tx_gate,
                tx_gate_generation,
                backend,
                completion_sequence,
            )
            .is_err()
        {
            return false;
        }
        let Some(gate_record) = self
            .network_tx_capability_gates
            .iter()
            .find(|record| record.id == tx_gate && record.generation == tx_gate_generation)
            .cloned()
        else {
            return false;
        };
        let generation = 1;
        self.next_network_tx_completion_id = self.next_network_tx_completion_id.max(completion + 1);
        let completed_at_event = self.event_log.push(
            "network",
            EventKind::NetworkTxCompleted {
                completion,
                tx_gate,
                tx_gate_generation,
                backend,
                driver_store: gate_record.driver_store,
                driver_store_generation: gate_record.driver_store_generation,
                packet_device: gate_record.packet_device,
                packet_device_generation: gate_record.packet_device_generation,
                tx_queue: gate_record.tx_queue,
                tx_queue_generation: gate_record.tx_queue_generation,
                packet_descriptor: gate_record.packet_descriptor,
                packet_descriptor_generation: gate_record.packet_descriptor_generation,
                packet_buffer: gate_record.packet_buffer,
                packet_buffer_generation: gate_record.packet_buffer_generation,
                byte_len: gate_record.byte_len,
                sequence: gate_record.sequence,
                completion_sequence,
                generation,
            },
        );
        self.network_tx_completions.push(NetworkTxCompletionRecord {
            id: completion,
            tx_gate,
            tx_gate_generation,
            backend,
            driver_store: gate_record.driver_store,
            driver_store_generation: gate_record.driver_store_generation,
            packet_device: gate_record.packet_device,
            packet_device_generation: gate_record.packet_device_generation,
            tx_queue: gate_record.tx_queue,
            tx_queue_generation: gate_record.tx_queue_generation,
            packet_descriptor: gate_record.packet_descriptor,
            packet_descriptor_generation: gate_record.packet_descriptor_generation,
            packet_buffer: gate_record.packet_buffer,
            packet_buffer_generation: gate_record.packet_buffer_generation,
            byte_len: gate_record.byte_len,
            sequence: gate_record.sequence,
            completion_sequence,
            generation,
            state: NetworkTxCompletionState::Completed,
            completed_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn network_tx_completions(&self) -> &[NetworkTxCompletionRecord] {
        &self.network_tx_completions
    }

    pub fn network_tx_completion_count(&self) -> usize {
        self.network_tx_completions.len()
    }

    pub fn check_network_tx_completion_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.network_tx_completions {
            let Some(gate_record) = self.network_tx_capability_gates.iter().find(|gate| {
                gate.id == record.tx_gate && gate.generation == record.tx_gate_generation
            }) else {
                return Err(SemanticInvariantError::NetworkTxCompletionMissingGate {
                    completion: record.id,
                    tx_gate: record.tx_gate,
                });
            };
            let Some((backend_packet_device, backend_packet_device_generation)) =
                self.network_backend_packet_device(record.backend)
            else {
                return Err(SemanticInvariantError::NetworkTxCompletionMissingBackend {
                    completion: record.id,
                    backend: record.backend,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.tx_gate_generation == 0
                || record.driver_store_generation == 0
                || record.packet_device_generation == 0
                || record.tx_queue_generation == 0
                || record.packet_descriptor_generation == 0
                || record.packet_buffer_generation == 0
                || record.byte_len == 0
                || record.sequence == 0
                || record.completion_sequence == 0
                || record.state != NetworkTxCompletionState::Completed
                || gate_record.state != NetworkTxCapabilityGateState::Allowed
                || record.driver_store != gate_record.driver_store
                || record.driver_store_generation != gate_record.driver_store_generation
                || record.packet_device != gate_record.packet_device
                || record.packet_device_generation != gate_record.packet_device_generation
                || record.tx_queue != gate_record.tx_queue
                || record.tx_queue_generation != gate_record.tx_queue_generation
                || record.packet_descriptor != gate_record.packet_descriptor
                || record.packet_descriptor_generation != gate_record.packet_descriptor_generation
                || record.packet_buffer != gate_record.packet_buffer
                || record.packet_buffer_generation != gate_record.packet_buffer_generation
                || record.byte_len != gate_record.byte_len
                || record.sequence != gate_record.sequence
                || backend_packet_device != record.packet_device
                || backend_packet_device_generation != record.packet_device_generation
            {
                return Err(SemanticInvariantError::NetworkTxCompletionInvalid {
                    completion: record.id,
                });
            }
            if let Some(duplicate) = self.network_tx_completions.iter().find(|other| {
                other.id != record.id
                    && other.tx_gate == record.tx_gate
                    && other.tx_gate_generation == record.tx_gate_generation
                    && other.state == NetworkTxCompletionState::Completed
            }) {
                return Err(SemanticInvariantError::NetworkTxCompletionDuplicateGate {
                    completion: duplicate.id,
                    tx_gate: record.tx_gate,
                });
            }
            if let Some(duplicate) = self.network_tx_completions.iter().find(|other| {
                other.id != record.id
                    && other.tx_queue == record.tx_queue
                    && other.tx_queue_generation == record.tx_queue_generation
                    && other.completion_sequence == record.completion_sequence
                    && other.state == NetworkTxCompletionState::Completed
            }) {
                return Err(
                    SemanticInvariantError::NetworkTxCompletionDuplicateSequence {
                        completion: duplicate.id,
                        tx_queue: record.tx_queue,
                        completion_sequence: record.completion_sequence,
                    },
                );
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.completed_at_event
                    && matches!(
                        &event.kind,
                        EventKind::NetworkTxCompleted {
                            completion,
                            tx_gate,
                            tx_gate_generation,
                            backend,
                            driver_store,
                            driver_store_generation,
                            packet_device,
                            packet_device_generation,
                            tx_queue,
                            tx_queue_generation,
                            packet_descriptor,
                            packet_descriptor_generation,
                            packet_buffer,
                            packet_buffer_generation,
                            byte_len,
                            sequence,
                            completion_sequence,
                            generation,
                        } if *completion == record.id
                            && *tx_gate == record.tx_gate
                            && *tx_gate_generation == record.tx_gate_generation
                            && *backend == record.backend
                            && *driver_store == record.driver_store
                            && *driver_store_generation == record.driver_store_generation
                            && *packet_device == record.packet_device
                            && *packet_device_generation == record.packet_device_generation
                            && *tx_queue == record.tx_queue
                            && *tx_queue_generation == record.tx_queue_generation
                            && *packet_descriptor == record.packet_descriptor
                            && *packet_descriptor_generation == record.packet_descriptor_generation
                            && *packet_buffer == record.packet_buffer
                            && *packet_buffer_generation == record.packet_buffer_generation
                            && *byte_len == record.byte_len
                            && *sequence == record.sequence
                            && *completion_sequence == record.completion_sequence
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::NetworkTxCompletionMissingEvent {
                    completion: record.id,
                });
            }
        }
        Ok(())
    }

    fn network_backend_packet_device(
        &self,
        backend: ContractObjectRef,
    ) -> Option<(PacketDeviceObjectId, Generation)> {
        match backend.kind {
            ContractObjectKind::FakeNetBackendObject => self
                .fake_net_backends
                .iter()
                .find(|record| record.id == backend.id && record.generation == backend.generation)
                .map(|record| (record.packet_device, record.packet_device_generation)),
            ContractObjectKind::VirtioNetBackendObject => self
                .virtio_net_backends
                .iter()
                .find(|record| record.id == backend.id && record.generation == backend.generation)
                .map(|record| (record.packet_device, record.packet_device_generation)),
            _ => None,
        }
    }

    fn live_network_backend_packet_device(
        &self,
        backend: ContractObjectRef,
    ) -> Option<(PacketDeviceObjectId, Generation)> {
        match backend.kind {
            ContractObjectKind::FakeNetBackendObject => self
                .fake_net_backends
                .iter()
                .find(|record| {
                    record.id == backend.id
                        && record.generation == backend.generation
                        && record.state == FakeNetBackendObjectState::Bound
                })
                .map(|record| (record.packet_device, record.packet_device_generation)),
            ContractObjectKind::VirtioNetBackendObject => self
                .virtio_net_backends
                .iter()
                .find(|record| {
                    record.id == backend.id
                        && record.generation == backend.generation
                        && record.state == VirtioNetBackendObjectState::SkeletonReady
                })
                .map(|record| (record.packet_device, record.packet_device_generation)),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_tx_completion_gate_generation_for_test(
        &mut self,
        completion: NetworkTxCompletionId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .network_tx_completions
            .iter_mut()
            .find(|record| record.id == completion)
        {
            record.tx_gate_generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_network_tx_completion_sequence_for_test(
        &mut self,
        completion: NetworkTxCompletionId,
        completion_sequence: u64,
    ) {
        if let Some(record) = self
            .network_tx_completions
            .iter_mut()
            .find(|record| record.id == completion)
        {
            record.completion_sequence = completion_sequence;
        }
    }
}
