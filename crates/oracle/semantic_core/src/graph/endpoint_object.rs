use super::*;

pub const ENDPOINT_OBJECT_UNSPECIFIED_IPV4: [u8; 4] = [0, 0, 0, 0];
pub const ENDPOINT_OBJECT_UNSPECIFIED_PORT: u16 = 0;

impl SemanticGraph {
    pub(crate) fn validate_endpoint_object(
        &self,
        endpoint: EndpointObjectId,
        socket: SocketObjectId,
        socket_generation: Generation,
        local_addr: [u8; 4],
        local_port: u16,
        remote_addr: [u8; 4],
        remote_port: u16,
    ) -> Result<(), &'static str> {
        if endpoint == 0 {
            return Err("endpoint object id=0 is invalid");
        }
        if self.domains.network.endpoint_objects.iter().any(|record| record.id == endpoint) {
            return Err("endpoint object already exists");
        }
        let Some(socket_record) = self.domains.network.socket_objects.iter().find(|record| {
            record.id == socket
                && record.generation == socket_generation
                && record.state == SocketObjectState::Created
        }) else {
            return Err("endpoint object socket generation is missing or inactive");
        };
        if self.domains.network.network_stack_adapters.iter().all(|record| {
            record.id != socket_record.adapter
                || record.generation != socket_record.adapter_generation
                || record.state != NetworkStackAdapterState::Bound
        }) {
            return Err("endpoint object adapter generation is missing or inactive");
        }
        let Some(store) = self.domains.lifecycle.stores.iter().find(|record| {
            record.id == socket_record.owner_store
                && record.generation == socket_record.owner_store_generation
        }) else {
            return Err("endpoint object owner store generation is missing");
        };
        if matches!(store.state, StoreState::Dead | StoreState::Faulted | StoreState::Cleaning) {
            return Err("endpoint object owner store is not live");
        }
        if local_addr != ENDPOINT_OBJECT_UNSPECIFIED_IPV4
            || remote_addr != ENDPOINT_OBJECT_UNSPECIFIED_IPV4
            || local_port != ENDPOINT_OBJECT_UNSPECIFIED_PORT
            || remote_port != ENDPOINT_OBJECT_UNSPECIFIED_PORT
        {
            return Err("endpoint object must remain unbound before N13");
        }
        if self.domains.network.endpoint_objects.iter().any(|record| {
            record.socket == socket_record.id
                && record.socket_generation == socket_record.generation
                && record.state == EndpointObjectState::Allocated
        }) {
            return Err("endpoint object socket generation already has endpoint");
        }
        if self.check_invariants().is_err() {
            return Err("endpoint object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_endpoint_object_with_id(
        &mut self,
        endpoint: EndpointObjectId,
        socket: SocketObjectId,
        socket_generation: Generation,
        local_addr: [u8; 4],
        local_port: u16,
        remote_addr: [u8; 4],
        remote_port: u16,
        note: &str,
    ) -> bool {
        if self
            .validate_endpoint_object(
                endpoint,
                socket,
                socket_generation,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
            )
            .is_err()
        {
            return false;
        }
        let Some(socket_record) = self
            .domains
            .network
            .socket_objects
            .iter()
            .find(|record| record.id == socket && record.generation == socket_generation)
            .cloned()
        else {
            return false;
        };
        let generation = 1;
        self.domains.network.next_endpoint_object_id =
            self.domains.network.next_endpoint_object_id.max(endpoint + 1);
        let created_at_event = self.event_log.push(
            "network",
            EventKind::EndpointObjectCreated {
                endpoint,
                socket,
                socket_generation,
                adapter: socket_record.adapter,
                adapter_generation: socket_record.adapter_generation,
                owner_store: socket_record.owner_store,
                owner_store_generation: socket_record.owner_store_generation,
                family: socket_record.family.clone(),
                transport: socket_record.transport.clone(),
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                generation,
            },
        );
        self.domains.network.endpoint_objects.push(EndpointObjectRecord {
            id: endpoint,
            socket,
            socket_generation,
            adapter: socket_record.adapter,
            adapter_generation: socket_record.adapter_generation,
            owner_store: socket_record.owner_store,
            owner_store_generation: socket_record.owner_store_generation,
            family: socket_record.family,
            transport: socket_record.transport,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            generation,
            state: EndpointObjectState::Allocated,
            created_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn endpoint_objects(&self) -> &[EndpointObjectRecord] {
        &self.domains.network.endpoint_objects
    }

    pub fn endpoint_object_count(&self) -> usize {
        self.domains.network.endpoint_objects.len()
    }

    pub fn check_endpoint_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.network.endpoint_objects {
            let Some(socket_record) = self.domains.network.socket_objects.iter().find(|socket| {
                socket.id == record.socket && socket.generation == record.socket_generation
            }) else {
                return Err(SemanticInvariantError::EndpointObjectMissingSocket {
                    endpoint: record.id,
                    socket: record.socket,
                });
            };
            let Some(adapter) =
                self.domains.network.network_stack_adapters.iter().find(|adapter| {
                    adapter.id == record.adapter && adapter.generation == record.adapter_generation
                })
            else {
                return Err(SemanticInvariantError::EndpointObjectMissingAdapter {
                    endpoint: record.id,
                    adapter: record.adapter,
                });
            };
            let Some(store) = self.domains.lifecycle.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::EndpointObjectMissingOwnerStore {
                    endpoint: record.id,
                    store: record.owner_store,
                });
            };
            if record.id == 0
                || record.generation == 0
                || record.socket_generation == 0
                || record.adapter_generation == 0
                || record.owner_store_generation == 0
                || socket_record.state != SocketObjectState::Created
                || adapter.state != NetworkStackAdapterState::Bound
                || matches!(
                    store.state,
                    StoreState::Dead | StoreState::Faulted | StoreState::Cleaning
                )
                || record.adapter != socket_record.adapter
                || record.adapter_generation != socket_record.adapter_generation
                || record.owner_store != socket_record.owner_store
                || record.owner_store_generation != socket_record.owner_store_generation
                || record.family != socket_record.family
                || record.transport != socket_record.transport
                || record.local_addr != ENDPOINT_OBJECT_UNSPECIFIED_IPV4
                || record.remote_addr != ENDPOINT_OBJECT_UNSPECIFIED_IPV4
                || record.local_port != ENDPOINT_OBJECT_UNSPECIFIED_PORT
                || record.remote_port != ENDPOINT_OBJECT_UNSPECIFIED_PORT
                || record.state != EndpointObjectState::Allocated
            {
                return Err(SemanticInvariantError::EndpointObjectInvalid { endpoint: record.id });
            }
            if self
                .domains
                .network
                .endpoint_objects
                .iter()
                .filter(|other| other.id == record.id)
                .count()
                > 1
            {
                return Err(SemanticInvariantError::EndpointObjectDuplicate {
                    endpoint: record.id,
                });
            }
            if let Some(duplicate) = self.domains.network.endpoint_objects.iter().find(|other| {
                other.id != record.id
                    && other.socket == record.socket
                    && other.socket_generation == record.socket_generation
                    && other.state == EndpointObjectState::Allocated
            }) {
                return Err(SemanticInvariantError::EndpointObjectDuplicateSocket {
                    endpoint: duplicate.id,
                    socket: record.socket,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.created_at_event
                    && matches!(
                        &event.kind,
                        EventKind::EndpointObjectCreated {
                            endpoint,
                            socket,
                            socket_generation,
                            adapter,
                            adapter_generation,
                            owner_store,
                            owner_store_generation,
                            family,
                            transport,
                            local_addr,
                            local_port,
                            remote_addr,
                            remote_port,
                            generation,
                        } if *endpoint == record.id
                            && *socket == record.socket
                            && *socket_generation == record.socket_generation
                            && *adapter == record.adapter
                            && *adapter_generation == record.adapter_generation
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && family == &record.family
                            && transport == &record.transport
                            && *local_addr == record.local_addr
                            && *local_port == record.local_port
                            && *remote_addr == record.remote_addr
                            && *remote_port == record.remote_port
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::EndpointObjectMissingEvent {
                    endpoint: record.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_endpoint_object_socket_generation_for_test(
        &mut self,
        endpoint: EndpointObjectId,
        socket_generation: Generation,
    ) {
        if let Some(record) =
            self.domains.network.endpoint_objects.iter_mut().find(|record| record.id == endpoint)
        {
            record.socket_generation = socket_generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn duplicate_endpoint_object_id_for_test(
        &mut self,
        endpoint: EndpointObjectId,
        socket_generation: Generation,
    ) {
        if let Some(mut duplicate) = self
            .domains
            .network
            .endpoint_objects
            .iter()
            .find(|record| record.id == endpoint)
            .cloned()
        {
            duplicate.socket_generation = socket_generation;
            self.domains.network.endpoint_objects.push(duplicate);
        }
    }
}
