use super::*;

impl SemanticGraph {
    pub(crate) fn validate_socket_wait(
        &self,
        socket_wait: SocketWaitId,
        wait: WaitId,
        wait_generation: Generation,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        wait_kind: SemanticWaitKind,
        blocker: ContractObjectRef,
    ) -> Result<(), &'static str> {
        if socket_wait == 0 {
            return Err("socket wait id=0 is invalid");
        }
        if self.socket_waits.iter().any(|record| record.id == socket_wait) {
            return Err("socket wait already exists");
        }
        if !matches!(
            wait_kind,
            SemanticWaitKind::SocketReadable
                | SemanticWaitKind::SocketWritable
                | SemanticWaitKind::SocketAccept
        ) {
            return Err("socket wait kind is not a socket wait kind");
        }
        let expected_blocker = ContractObjectRef::new(
            ContractObjectKind::EndpointObject,
            endpoint,
            endpoint_generation,
        );
        if blocker != expected_blocker {
            return Err("socket wait blocker must be the endpoint generation");
        }
        let Some(wait_record) = self.domains.wait.waits.iter().find(|record| {
            record.id == wait
                && record.generation == wait_generation
                && record.state == WaitState::Pending
        }) else {
            return Err("socket wait token generation is missing or not pending");
        };
        if wait_record.kind != wait_kind || !wait_record.blockers.contains(&blocker) {
            return Err("socket wait token does not reference the requested endpoint blocker");
        }
        let Some(endpoint_record) = self.endpoint_objects.iter().find(|record| {
            record.id == endpoint
                && record.generation == endpoint_generation
                && record.state == EndpointObjectState::Allocated
        }) else {
            return Err("socket wait endpoint generation is missing or inactive");
        };
        if wait_record.owner_store != Some(endpoint_record.owner_store)
            || wait_record.owner_store_generation != Some(endpoint_record.owner_store_generation)
        {
            return Err("socket wait owner store does not match endpoint owner");
        }
        let Some(store_record) = self.stores.iter().find(|record| {
            record.id == endpoint_record.owner_store
                && record.generation == endpoint_record.owner_store_generation
        }) else {
            return Err("socket wait owner store generation is missing");
        };
        if store_record.state == StoreState::Dead {
            return Err("socket wait owner store is dead");
        }
        if !self.socket_objects.iter().any(|record| {
            record.id == endpoint_record.socket
                && record.generation == endpoint_record.socket_generation
                && record.state == SocketObjectState::Created
        }) {
            return Err("socket wait socket generation is missing or inactive");
        }
        let connected = self.socket_wait_operation_before(
            endpoint_record.id,
            endpoint_record.generation,
            SocketOperationKind::Connect,
        );
        let listening = self.socket_wait_operation_before(
            endpoint_record.id,
            endpoint_record.generation,
            SocketOperationKind::Listen,
        );
        match wait_kind {
            SemanticWaitKind::SocketAccept => {
                if !listening {
                    return Err("socket accept wait requires listening endpoint");
                }
            }
            SemanticWaitKind::SocketReadable | SemanticWaitKind::SocketWritable => {
                if !connected || listening {
                    return Err("socket data wait requires connected endpoint");
                }
            }
            _ => unreachable!(),
        }
        if self
            .socket_waits
            .iter()
            .any(|record| record.wait == wait && record.state == SocketWaitState::Pending)
        {
            return Err("socket wait token already has a pending socket wait");
        }
        if self.check_invariants().is_err() {
            return Err("socket wait requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_socket_wait_with_id(
        &mut self,
        socket_wait: SocketWaitId,
        wait: WaitId,
        wait_generation: Generation,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        wait_kind: SemanticWaitKind,
        blocker: ContractObjectRef,
        note: &str,
    ) -> bool {
        if self
            .validate_socket_wait(
                socket_wait,
                wait,
                wait_generation,
                endpoint,
                endpoint_generation,
                wait_kind,
                blocker,
            )
            .is_err()
        {
            return false;
        }
        let Some(endpoint_record) = self
            .endpoint_objects
            .iter()
            .find(|record| record.id == endpoint && record.generation == endpoint_generation)
            .cloned()
        else {
            return false;
        };
        let generation = 1;
        self.next_socket_wait_id = self.next_socket_wait_id.max(socket_wait + 1);
        let created_at_event = self.event_log.push(
            "network",
            EventKind::SocketWaitCreated {
                socket_wait,
                wait,
                wait_generation,
                endpoint,
                endpoint_generation,
                socket: endpoint_record.socket,
                socket_generation: endpoint_record.socket_generation,
                adapter: endpoint_record.adapter,
                adapter_generation: endpoint_record.adapter_generation,
                owner_store: endpoint_record.owner_store,
                owner_store_generation: endpoint_record.owner_store_generation,
                wait_kind,
                blocker,
                generation,
            },
        );
        self.socket_waits.push(SocketWaitRecord {
            id: socket_wait,
            wait,
            wait_generation,
            endpoint,
            endpoint_generation,
            socket: endpoint_record.socket,
            socket_generation: endpoint_record.socket_generation,
            adapter: endpoint_record.adapter,
            adapter_generation: endpoint_record.adapter_generation,
            owner_store: endpoint_record.owner_store,
            owner_store_generation: endpoint_record.owner_store_generation,
            wait_kind,
            blocker,
            generation,
            state: SocketWaitState::Pending,
            created_at_event,
            completed_at_event: None,
            cancel_reason: None,
            ready_sequence: None,
            byte_len: None,
            note: note.to_string(),
        });
        true
    }

    pub fn resolve_socket_wait(
        &mut self,
        socket_wait: SocketWaitId,
        socket_wait_generation: Generation,
        ready_sequence: u64,
        byte_len: u32,
        note: &str,
    ) -> bool {
        if ready_sequence == 0 {
            return false;
        }
        let Some(index) = self.socket_waits.iter().position(|record| {
            record.id == socket_wait
                && record.generation == socket_wait_generation
                && record.state == SocketWaitState::Pending
        }) else {
            return false;
        };
        let record = self.socket_waits[index].clone();
        if matches!(record.wait_kind, SemanticWaitKind::SocketReadable) && byte_len == 0 {
            return false;
        }
        if !self.domains.wait.waits.iter().any(|wait| {
            wait.id == record.wait
                && wait.generation == record.wait_generation
                && wait.state == WaitState::Pending
        }) {
            return false;
        }
        self.record_wait_resolved(record.wait, "socket-ready");
        let completed_at_event = self.event_log.push(
            "network",
            EventKind::SocketWaitResolved {
                socket_wait,
                wait: record.wait,
                wait_generation: record.wait_generation,
                ready_sequence,
                byte_len,
                generation: socket_wait_generation,
            },
        );
        self.socket_waits[index].state = SocketWaitState::Resolved;
        self.socket_waits[index].completed_at_event = Some(completed_at_event);
        self.socket_waits[index].ready_sequence = Some(ready_sequence);
        self.socket_waits[index].byte_len = Some(byte_len);
        self.socket_waits[index].note = note.to_string();
        true
    }

    pub fn cancel_socket_wait(
        &mut self,
        socket_wait: SocketWaitId,
        socket_wait_generation: Generation,
        errno: i32,
        reason: WaitCancelReason,
        note: &str,
    ) -> bool {
        if !matches!(
            reason,
            WaitCancelReason::CloseFd
                | WaitCancelReason::StoreFault
                | WaitCancelReason::CapabilityRevoked
                | WaitCancelReason::DeviceFault
                | WaitCancelReason::ResourceDropped
                | WaitCancelReason::GenerationMismatch
        ) {
            return false;
        }
        let Some(index) = self.socket_waits.iter().position(|record| {
            record.id == socket_wait
                && record.generation == socket_wait_generation
                && record.state == SocketWaitState::Pending
        }) else {
            return false;
        };
        let record = self.socket_waits[index].clone();
        if !self.domains.wait.waits.iter().any(|wait| {
            wait.id == record.wait
                && wait.generation == record.wait_generation
                && wait.state == WaitState::Pending
        }) {
            return false;
        }
        self.record_wait_cancelled_with_reason(record.wait, errno, reason);
        let completed_at_event = self.event_log.push(
            "network",
            EventKind::SocketWaitCancelled {
                socket_wait,
                wait: record.wait,
                wait_generation: record.wait_generation,
                reason,
                generation: socket_wait_generation,
            },
        );
        self.socket_waits[index].state = SocketWaitState::Cancelled;
        self.socket_waits[index].completed_at_event = Some(completed_at_event);
        self.socket_waits[index].cancel_reason = Some(reason);
        self.socket_waits[index].note = note.to_string();
        true
    }

    pub fn socket_waits(&self) -> &[SocketWaitRecord] {
        &self.socket_waits
    }

    pub fn socket_wait_count(&self) -> usize {
        self.socket_waits.len()
    }

    pub fn check_socket_wait_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.socket_waits {
            let Some(wait_record) =
                self.domains.wait.waits.iter().find(|wait| {
                    wait.id == record.wait && wait.generation == record.wait_generation
                })
            else {
                return Err(SemanticInvariantError::SocketWaitMissingWait {
                    socket_wait: record.id,
                    wait: record.wait,
                });
            };
            let Some(endpoint) = self.endpoint_objects.iter().find(|endpoint| {
                endpoint.id == record.endpoint && endpoint.generation == record.endpoint_generation
            }) else {
                return Err(SemanticInvariantError::SocketWaitMissingEndpoint {
                    socket_wait: record.id,
                    endpoint: record.endpoint,
                });
            };
            if !self.socket_objects.iter().any(|socket| {
                socket.id == record.socket && socket.generation == record.socket_generation
            }) {
                return Err(SemanticInvariantError::SocketWaitMissingSocket {
                    socket_wait: record.id,
                    socket: record.socket,
                });
            }
            if !self.network_stack_adapters.iter().any(|adapter| {
                adapter.id == record.adapter && adapter.generation == record.adapter_generation
            }) {
                return Err(SemanticInvariantError::SocketWaitMissingAdapter {
                    socket_wait: record.id,
                    adapter: record.adapter,
                });
            }
            let Some(store) = self.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::SocketWaitMissingOwnerStore {
                    socket_wait: record.id,
                    store: record.owner_store,
                });
            };
            let endpoint_ref = ContractObjectRef::new(
                ContractObjectKind::EndpointObject,
                record.endpoint,
                record.endpoint_generation,
            );
            if record.id == 0
                || record.generation == 0
                || record.wait_generation == 0
                || record.endpoint_generation == 0
                || record.socket_generation == 0
                || record.adapter_generation == 0
                || record.owner_store_generation == 0
                || record.blocker != endpoint_ref
                || !wait_record.blockers.contains(&record.blocker)
                || wait_record.owner_store != Some(record.owner_store)
                || wait_record.owner_store_generation != Some(record.owner_store_generation)
                || wait_record.kind != record.wait_kind
                || endpoint.socket != record.socket
                || endpoint.socket_generation != record.socket_generation
                || endpoint.adapter != record.adapter
                || endpoint.adapter_generation != record.adapter_generation
                || endpoint.owner_store != record.owner_store
                || endpoint.owner_store_generation != record.owner_store_generation
                || (record.state == SocketWaitState::Pending && store.state == StoreState::Dead)
            {
                return Err(SemanticInvariantError::SocketWaitInvalid { socket_wait: record.id });
            }
            if record.state == SocketWaitState::Pending
                && self.socket_waits.iter().any(|other| {
                    other.id != record.id
                        && other.wait == record.wait
                        && other.state == SocketWaitState::Pending
                })
            {
                return Err(SemanticInvariantError::SocketWaitDuplicateWait {
                    socket_wait: record.id,
                    wait: record.wait,
                });
            }
            match record.state {
                SocketWaitState::Pending => {
                    if wait_record.state != WaitState::Pending {
                        return Err(SemanticInvariantError::SocketWaitInvalid {
                            socket_wait: record.id,
                        });
                    }
                }
                SocketWaitState::Resolved => {
                    if !matches!(wait_record.state, WaitState::Resolved | WaitState::Consumed)
                        || record.ready_sequence.is_none()
                    {
                        return Err(SemanticInvariantError::SocketWaitInvalid {
                            socket_wait: record.id,
                        });
                    }
                }
                SocketWaitState::Cancelled => {
                    if wait_record.state != WaitState::Cancelled
                        || wait_record.cancel_reason != record.cancel_reason
                        || record.cancel_reason.is_none()
                    {
                        return Err(SemanticInvariantError::SocketWaitInvalid {
                            socket_wait: record.id,
                        });
                    }
                }
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.created_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SocketWaitCreated {
                            socket_wait,
                            wait,
                            wait_generation,
                            endpoint,
                            endpoint_generation,
                            socket,
                            socket_generation,
                            adapter,
                            adapter_generation,
                            owner_store,
                            owner_store_generation,
                            wait_kind,
                            blocker,
                            generation,
                        } if *socket_wait == record.id
                            && *wait == record.wait
                            && *wait_generation == record.wait_generation
                            && *endpoint == record.endpoint
                            && *endpoint_generation == record.endpoint_generation
                            && *socket == record.socket
                            && *socket_generation == record.socket_generation
                            && *adapter == record.adapter
                            && *adapter_generation == record.adapter_generation
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *wait_kind == record.wait_kind
                            && *blocker == record.blocker
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::SocketWaitMissingEvent {
                    socket_wait: record.id,
                    event: record.created_at_event,
                });
            }
            if let Some(completed_at_event) = record.completed_at_event {
                let found = self.event_log.events.iter().any(|event| {
                    event.id == completed_at_event
                        && match (&record.state, &event.kind) {
                            (
                                SocketWaitState::Resolved,
                                EventKind::SocketWaitResolved {
                                    socket_wait,
                                    wait,
                                    wait_generation,
                                    ready_sequence,
                                    byte_len,
                                    generation,
                                },
                            ) => {
                                *socket_wait == record.id
                                    && *wait == record.wait
                                    && *wait_generation == record.wait_generation
                                    && Some(*ready_sequence) == record.ready_sequence
                                    && Some(*byte_len) == record.byte_len
                                    && *generation == record.generation
                            }
                            (
                                SocketWaitState::Cancelled,
                                EventKind::SocketWaitCancelled {
                                    socket_wait,
                                    wait,
                                    wait_generation,
                                    reason,
                                    generation,
                                },
                            ) => {
                                *socket_wait == record.id
                                    && *wait == record.wait
                                    && *wait_generation == record.wait_generation
                                    && Some(*reason) == record.cancel_reason
                                    && *generation == record.generation
                            }
                            _ => false,
                        }
                });
                if !found {
                    return Err(SemanticInvariantError::SocketWaitMissingEvent {
                        socket_wait: record.id,
                        event: completed_at_event,
                    });
                }
            }
        }
        Ok(())
    }

    fn socket_wait_operation_before(
        &self,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        operation: SocketOperationKind,
    ) -> bool {
        self.socket_operations.iter().any(|record| {
            record.endpoint == endpoint
                && record.endpoint_generation == endpoint_generation
                && record.operation == operation
                && record.state == SocketOperationState::Applied
        })
    }

    #[cfg(test)]
    pub(crate) fn corrupt_socket_wait_endpoint_generation_for_test(
        &mut self,
        socket_wait: SocketWaitId,
        generation: Generation,
    ) {
        if let Some(record) = self.socket_waits.iter_mut().find(|record| record.id == socket_wait) {
            record.endpoint_generation = generation;
        }
    }
}
