use super::*;

pub const SOCKET_OPERATION_UNSPECIFIED_IPV4: [u8; 4] = [0, 0, 0, 0];
pub const SOCKET_OPERATION_UNSPECIFIED_PORT: u16 = 0;

impl SemanticGraph {
    pub(crate) fn validate_socket_operation(
        &self,
        operation_id: SocketOperationId,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        operation: SocketOperationKind,
        local_addr: [u8; 4],
        local_port: u16,
        remote_addr: [u8; 4],
        remote_port: u16,
        backlog: u16,
        byte_len: u32,
        sequence: u64,
    ) -> Result<(), &'static str> {
        if operation_id == 0 {
            return Err("socket operation id=0 is invalid");
        }
        if sequence == 0 {
            return Err("socket operation sequence is zero");
        }
        if self.domains.network.socket_operations.iter().any(|record| record.id == operation_id) {
            return Err("socket operation already exists");
        }
        let Some(endpoint_record) = self.live_endpoint_record(endpoint, endpoint_generation) else {
            return Err("socket operation endpoint generation is missing or inactive");
        };
        if self.domains.network.socket_operations.iter().any(|record| {
            record.endpoint == endpoint_record.id
                && record.endpoint_generation == endpoint_record.generation
                && record.sequence == sequence
                && record.state == SocketOperationState::Applied
        }) {
            return Err("socket operation sequence already exists for endpoint generation");
        }
        if self.max_socket_operation_sequence(endpoint_record.id, endpoint_record.generation)
            >= sequence
        {
            return Err("socket operation sequence must advance");
        }
        if self.check_invariants().is_err() {
            return Err("socket operation requires invariant-clean graph");
        }

        match operation {
            SocketOperationKind::Bind => {
                if local_port == SOCKET_OPERATION_UNSPECIFIED_PORT
                    || remote_addr != SOCKET_OPERATION_UNSPECIFIED_IPV4
                    || remote_port != SOCKET_OPERATION_UNSPECIFIED_PORT
                    || backlog != 0
                    || byte_len != 0
                    || self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Bind,
                    )
                    || self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Connect,
                    )
                    || self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Listen,
                    )
                {
                    return Err("socket bind operation is invalid");
                }
            }
            SocketOperationKind::Listen => {
                if local_addr != SOCKET_OPERATION_UNSPECIFIED_IPV4
                    || local_port != SOCKET_OPERATION_UNSPECIFIED_PORT
                    || remote_addr != SOCKET_OPERATION_UNSPECIFIED_IPV4
                    || remote_port != SOCKET_OPERATION_UNSPECIFIED_PORT
                    || backlog == 0
                    || byte_len != 0
                    || !self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Bind,
                    )
                    || self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Listen,
                    )
                    || self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Connect,
                    )
                {
                    return Err("socket listen operation requires bound endpoint");
                }
            }
            SocketOperationKind::Connect => {
                if local_addr != SOCKET_OPERATION_UNSPECIFIED_IPV4
                    || local_port != SOCKET_OPERATION_UNSPECIFIED_PORT
                    || remote_addr == SOCKET_OPERATION_UNSPECIFIED_IPV4
                    || remote_port == SOCKET_OPERATION_UNSPECIFIED_PORT
                    || backlog != 0
                    || byte_len != 0
                    || !self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Bind,
                    )
                    || self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Listen,
                    )
                    || self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Connect,
                    )
                {
                    return Err("socket connect operation requires bound non-listening endpoint");
                }
            }
            SocketOperationKind::Send | SocketOperationKind::Recv => {
                if local_addr != SOCKET_OPERATION_UNSPECIFIED_IPV4
                    || local_port != SOCKET_OPERATION_UNSPECIFIED_PORT
                    || remote_addr != SOCKET_OPERATION_UNSPECIFIED_IPV4
                    || remote_port != SOCKET_OPERATION_UNSPECIFIED_PORT
                    || backlog != 0
                    || byte_len == 0
                    || !self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Connect,
                    )
                    || self.socket_operation_exists(
                        endpoint_record.id,
                        endpoint_record.generation,
                        SocketOperationKind::Listen,
                    )
                {
                    return Err("socket data operation requires connected endpoint");
                }
            }
        }
        Ok(())
    }

    pub fn record_socket_operation_with_id(
        &mut self,
        operation_id: SocketOperationId,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        operation: SocketOperationKind,
        local_addr: [u8; 4],
        local_port: u16,
        remote_addr: [u8; 4],
        remote_port: u16,
        backlog: u16,
        byte_len: u32,
        sequence: u64,
        note: &str,
    ) -> bool {
        if self
            .validate_socket_operation(
                operation_id,
                endpoint,
                endpoint_generation,
                operation,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                backlog,
                byte_len,
                sequence,
            )
            .is_err()
        {
            return false;
        }
        let Some(endpoint_record) =
            self.live_endpoint_record(endpoint, endpoint_generation).cloned()
        else {
            return false;
        };
        let (record_local_addr, record_local_port, record_remote_addr, record_remote_port) = self
            .socket_operation_endpoint_tuple(
                endpoint_record.id,
                endpoint_record.generation,
                operation,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
            );
        let generation = 1;
        self.domains.network.next_socket_operation_id =
            self.domains.network.next_socket_operation_id.max(operation_id + 1);
        let recorded_at_event = self.event_log.push(
            "network",
            EventKind::SocketOperationRecorded {
                operation_id,
                endpoint,
                endpoint_generation,
                socket: endpoint_record.socket,
                socket_generation: endpoint_record.socket_generation,
                adapter: endpoint_record.adapter,
                adapter_generation: endpoint_record.adapter_generation,
                owner_store: endpoint_record.owner_store,
                owner_store_generation: endpoint_record.owner_store_generation,
                operation,
                local_addr: record_local_addr,
                local_port: record_local_port,
                remote_addr: record_remote_addr,
                remote_port: record_remote_port,
                backlog,
                byte_len,
                sequence,
                generation,
            },
        );
        self.domains.network.socket_operations.push(SocketOperationRecord {
            id: operation_id,
            endpoint,
            endpoint_generation,
            socket: endpoint_record.socket,
            socket_generation: endpoint_record.socket_generation,
            adapter: endpoint_record.adapter,
            adapter_generation: endpoint_record.adapter_generation,
            owner_store: endpoint_record.owner_store,
            owner_store_generation: endpoint_record.owner_store_generation,
            operation,
            local_addr: record_local_addr,
            local_port: record_local_port,
            remote_addr: record_remote_addr,
            remote_port: record_remote_port,
            backlog,
            byte_len,
            sequence,
            generation,
            state: SocketOperationState::Applied,
            recorded_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn socket_operations(&self) -> &[SocketOperationRecord] {
        &self.domains.network.socket_operations
    }

    pub fn socket_operation_count(&self) -> usize {
        self.domains.network.socket_operations.len()
    }

    pub fn check_socket_operation_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.network.socket_operations {
            let Some(endpoint) =
                self.live_endpoint_record(record.endpoint, record.endpoint_generation)
            else {
                return Err(SemanticInvariantError::SocketOperationMissingEndpoint {
                    operation: record.id,
                    endpoint: record.endpoint,
                });
            };
            let Some(socket) = self.domains.network.socket_objects.iter().find(|socket| {
                socket.id == record.socket && socket.generation == record.socket_generation
            }) else {
                return Err(SemanticInvariantError::SocketOperationMissingSocket {
                    operation: record.id,
                    socket: record.socket,
                });
            };
            let Some(adapter) =
                self.domains.network.network_stack_adapters.iter().find(|adapter| {
                    adapter.id == record.adapter && adapter.generation == record.adapter_generation
                })
            else {
                return Err(SemanticInvariantError::SocketOperationMissingAdapter {
                    operation: record.id,
                    adapter: record.adapter,
                });
            };
            let Some(store) = self.domains.lifecycle.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::SocketOperationMissingOwnerStore {
                    operation: record.id,
                    store: record.owner_store,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.endpoint_generation == 0
                || record.socket_generation == 0
                || record.adapter_generation == 0
                || record.owner_store_generation == 0
                || record.sequence == 0
                || record.state != SocketOperationState::Applied
                || endpoint.socket != record.socket
                || endpoint.socket_generation != record.socket_generation
                || endpoint.adapter != record.adapter
                || endpoint.adapter_generation != record.adapter_generation
                || endpoint.owner_store != record.owner_store
                || endpoint.owner_store_generation != record.owner_store_generation
                || socket.state != SocketObjectState::Created
                || adapter.state != NetworkStackAdapterState::Bound
                || matches!(
                    store.state,
                    StoreState::Dead | StoreState::Faulted | StoreState::Cleaning
                )
            {
                return Err(SemanticInvariantError::SocketOperationInvalid {
                    operation: record.id,
                });
            }
            if self
                .domains
                .network
                .socket_operations
                .iter()
                .filter(|other| other.id == record.id)
                .count()
                > 1
            {
                return Err(SemanticInvariantError::SocketOperationDuplicate {
                    operation: record.id,
                });
            }
            if let Some(duplicate) = self
                .domains
                .network
                .socket_operations
                .iter()
                .filter(|other| {
                    other.id != record.id
                        && other.endpoint == record.endpoint
                        && other.endpoint_generation == record.endpoint_generation
                        && other.sequence == record.sequence
                        && other.state == SocketOperationState::Applied
                })
                .max_by_key(|other| other.id)
            {
                return Err(SemanticInvariantError::SocketOperationOrderingInvalid {
                    operation: duplicate.id.max(record.id),
                });
            }
            if !self.socket_operation_record_is_ordered(record) {
                return Err(SemanticInvariantError::SocketOperationOrderingInvalid {
                    operation: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SocketOperationRecorded {
                            operation_id,
                            endpoint,
                            endpoint_generation,
                            socket,
                            socket_generation,
                            adapter,
                            adapter_generation,
                            owner_store,
                            owner_store_generation,
                            operation,
                            local_addr,
                            local_port,
                            remote_addr,
                            remote_port,
                            backlog,
                            byte_len,
                            sequence,
                            generation,
                        } if *operation_id == record.id
                            && *endpoint == record.endpoint
                            && *endpoint_generation == record.endpoint_generation
                            && *socket == record.socket
                            && *socket_generation == record.socket_generation
                            && *adapter == record.adapter
                            && *adapter_generation == record.adapter_generation
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *operation == record.operation
                            && *local_addr == record.local_addr
                            && *local_port == record.local_port
                            && *remote_addr == record.remote_addr
                            && *remote_port == record.remote_port
                            && *backlog == record.backlog
                            && *byte_len == record.byte_len
                            && *sequence == record.sequence
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::SocketOperationMissingEvent {
                    operation: record.id,
                });
            }
        }
        Ok(())
    }

    fn live_endpoint_record(
        &self,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
    ) -> Option<&EndpointObjectRecord> {
        self.domains.network.endpoint_objects.iter().find(|record| {
            record.id == endpoint
                && record.generation == endpoint_generation
                && record.state == EndpointObjectState::Allocated
        })
    }

    fn socket_operation_exists(
        &self,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        operation: SocketOperationKind,
    ) -> bool {
        self.domains.network.socket_operations.iter().any(|record| {
            record.endpoint == endpoint
                && record.endpoint_generation == endpoint_generation
                && record.operation == operation
                && record.state == SocketOperationState::Applied
        })
    }

    fn max_socket_operation_sequence(
        &self,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
    ) -> u64 {
        self.domains
            .network
            .socket_operations
            .iter()
            .filter(|record| {
                record.endpoint == endpoint
                    && record.endpoint_generation == endpoint_generation
                    && record.state == SocketOperationState::Applied
            })
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0)
    }

    fn socket_operation_record_is_ordered(&self, record: &SocketOperationRecord) -> bool {
        match record.operation {
            SocketOperationKind::Bind => {
                record.local_port != SOCKET_OPERATION_UNSPECIFIED_PORT
                    && record.remote_addr == SOCKET_OPERATION_UNSPECIFIED_IPV4
                    && record.remote_port == SOCKET_OPERATION_UNSPECIFIED_PORT
                    && record.backlog == 0
                    && record.byte_len == 0
                    && self
                        .domains
                        .network
                        .socket_operations
                        .iter()
                        .filter(|other| {
                            other.endpoint == record.endpoint
                                && other.endpoint_generation == record.endpoint_generation
                                && other.sequence < record.sequence
                                && other.state == SocketOperationState::Applied
                        })
                        .count()
                        == 0
            }
            SocketOperationKind::Listen => {
                record.backlog > 0
                    && record.byte_len == 0
                    && self.socket_operation_kind_before(record, SocketOperationKind::Bind)
                    && !self.socket_operation_kind_before(record, SocketOperationKind::Connect)
                    && !self.socket_operation_kind_before(record, SocketOperationKind::Listen)
            }
            SocketOperationKind::Connect => {
                record.remote_addr != SOCKET_OPERATION_UNSPECIFIED_IPV4
                    && record.remote_port != SOCKET_OPERATION_UNSPECIFIED_PORT
                    && record.backlog == 0
                    && record.byte_len == 0
                    && self.socket_operation_kind_before(record, SocketOperationKind::Bind)
                    && !self.socket_operation_kind_before(record, SocketOperationKind::Listen)
                    && !self.socket_operation_kind_before(record, SocketOperationKind::Connect)
            }
            SocketOperationKind::Send | SocketOperationKind::Recv => {
                record.byte_len > 0
                    && record.backlog == 0
                    && self.socket_operation_kind_before(record, SocketOperationKind::Connect)
                    && !self.socket_operation_kind_before(record, SocketOperationKind::Listen)
            }
        }
    }

    fn socket_operation_kind_before(
        &self,
        record: &SocketOperationRecord,
        operation: SocketOperationKind,
    ) -> bool {
        self.domains.network.socket_operations.iter().any(|other| {
            other.endpoint == record.endpoint
                && other.endpoint_generation == record.endpoint_generation
                && other.operation == operation
                && other.sequence < record.sequence
                && other.state == SocketOperationState::Applied
        })
    }

    fn socket_operation_endpoint_tuple(
        &self,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        operation: SocketOperationKind,
        local_addr: [u8; 4],
        local_port: u16,
        remote_addr: [u8; 4],
        remote_port: u16,
    ) -> ([u8; 4], u16, [u8; 4], u16) {
        match operation {
            SocketOperationKind::Bind => (
                local_addr,
                local_port,
                SOCKET_OPERATION_UNSPECIFIED_IPV4,
                SOCKET_OPERATION_UNSPECIFIED_PORT,
            ),
            SocketOperationKind::Listen => {
                let bind = self.socket_operation_last(
                    endpoint,
                    endpoint_generation,
                    SocketOperationKind::Bind,
                );
                bind.map(|record| {
                    (
                        record.local_addr,
                        record.local_port,
                        SOCKET_OPERATION_UNSPECIFIED_IPV4,
                        SOCKET_OPERATION_UNSPECIFIED_PORT,
                    )
                })
                .unwrap_or((
                    SOCKET_OPERATION_UNSPECIFIED_IPV4,
                    SOCKET_OPERATION_UNSPECIFIED_PORT,
                    SOCKET_OPERATION_UNSPECIFIED_IPV4,
                    SOCKET_OPERATION_UNSPECIFIED_PORT,
                ))
            }
            SocketOperationKind::Connect => {
                let bind = self.socket_operation_last(
                    endpoint,
                    endpoint_generation,
                    SocketOperationKind::Bind,
                );
                bind.map(|record| (record.local_addr, record.local_port, remote_addr, remote_port))
                    .unwrap_or((
                        SOCKET_OPERATION_UNSPECIFIED_IPV4,
                        SOCKET_OPERATION_UNSPECIFIED_PORT,
                        remote_addr,
                        remote_port,
                    ))
            }
            SocketOperationKind::Send | SocketOperationKind::Recv => {
                let connect = self.socket_operation_last(
                    endpoint,
                    endpoint_generation,
                    SocketOperationKind::Connect,
                );
                connect
                    .map(|record| {
                        (
                            record.local_addr,
                            record.local_port,
                            record.remote_addr,
                            record.remote_port,
                        )
                    })
                    .unwrap_or((
                        SOCKET_OPERATION_UNSPECIFIED_IPV4,
                        SOCKET_OPERATION_UNSPECIFIED_PORT,
                        SOCKET_OPERATION_UNSPECIFIED_IPV4,
                        SOCKET_OPERATION_UNSPECIFIED_PORT,
                    ))
            }
        }
    }

    fn socket_operation_last(
        &self,
        endpoint: EndpointObjectId,
        endpoint_generation: Generation,
        operation: SocketOperationKind,
    ) -> Option<&SocketOperationRecord> {
        self.domains
            .network
            .socket_operations
            .iter()
            .filter(|record| {
                record.endpoint == endpoint
                    && record.endpoint_generation == endpoint_generation
                    && record.operation == operation
                    && record.state == SocketOperationState::Applied
            })
            .max_by_key(|record| record.sequence)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_socket_operation_sequence_for_test(
        &mut self,
        operation_id: SocketOperationId,
        sequence: u64,
    ) {
        if let Some(record) = self
            .domains
            .network
            .socket_operations
            .iter_mut()
            .find(|record| record.id == operation_id)
        {
            record.sequence = sequence;
        }
    }
}
