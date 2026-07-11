use super::*;

pub const SOCKET_OBJECT_FAMILY_INET: &str = "inet";
pub const SOCKET_OBJECT_TRANSPORT_TCP: &str = "tcp";
pub const SOCKET_OBJECT_DOMAIN_INET: u32 = 2;
pub const SOCKET_OBJECT_TYPE_STREAM: u32 = 1;
pub const SOCKET_OBJECT_PROTOCOL_UNSPECIFIED: u32 = 0;
pub const SOCKET_OBJECT_PROTOCOL_TCP: u16 = 6;

impl SemanticGraph {
    pub(crate) fn validate_socket_object(
        &self,
        socket: SocketObjectId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        owner_store: StoreId,
        owner_store_generation: Generation,
        domain: u32,
        socket_type: u32,
        protocol: u32,
    ) -> Result<(), &'static str> {
        if socket == 0 {
            return Err("socket object id=0 is invalid");
        }
        if self.domains.network.socket_objects.iter().any(|record| record.id == socket) {
            return Err("socket object already exists");
        }
        if self.domains.network.network_stack_adapters.iter().all(|record| {
            record.id != adapter
                || record.generation != adapter_generation
                || record.state != NetworkStackAdapterState::Bound
        }) {
            return Err("socket object adapter generation is missing or inactive");
        }
        let Some(store) =
            self.domains.lifecycle.stores.iter().find(|record| {
                record.id == owner_store && record.generation == owner_store_generation
            })
        else {
            return Err("socket object owner store generation is missing");
        };
        if matches!(store.state, StoreState::Dead | StoreState::Faulted | StoreState::Cleaning) {
            return Err("socket object owner store is not live");
        }
        if canonical_socket_protocol(domain, socket_type, protocol).is_none() {
            return Err("socket object contract is unsupported");
        }
        if self.check_invariants().is_err() {
            return Err("socket object requires invariant-clean graph");
        }
        Ok(())
    }

    pub fn record_socket_object_with_id(
        &mut self,
        socket: SocketObjectId,
        adapter: NetworkStackAdapterId,
        adapter_generation: Generation,
        owner_store: StoreId,
        owner_store_generation: Generation,
        domain: u32,
        socket_type: u32,
        protocol: u32,
        note: &str,
    ) -> bool {
        let Some((canonical_protocol, family, transport)) =
            canonical_socket_protocol(domain, socket_type, protocol)
        else {
            return false;
        };
        if self
            .validate_socket_object(
                socket,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                domain,
                socket_type,
                protocol,
            )
            .is_err()
        {
            return false;
        }
        let generation = 1;
        self.domains.network.next_socket_object_id =
            self.domains.network.next_socket_object_id.max(socket + 1);
        let created_at_event = self.event_log.push(
            "network",
            EventKind::SocketObjectCreated {
                socket,
                adapter,
                adapter_generation,
                owner_store,
                owner_store_generation,
                domain,
                socket_type,
                protocol,
                canonical_protocol,
                family: family.to_string(),
                transport: transport.to_string(),
                generation,
            },
        );
        self.domains.network.socket_objects.push(SocketObjectRecord {
            id: socket,
            adapter,
            adapter_generation,
            owner_store,
            owner_store_generation,
            domain,
            socket_type,
            protocol,
            canonical_protocol,
            family: family.to_string(),
            transport: transport.to_string(),
            generation,
            state: SocketObjectState::Created,
            created_at_event,
            note: note.to_string(),
        });
        true
    }

    pub fn socket_objects(&self) -> &[SocketObjectRecord] {
        &self.domains.network.socket_objects
    }

    pub fn socket_object_count(&self) -> usize {
        self.domains.network.socket_objects.len()
    }

    pub fn check_socket_object_invariants(&self) -> Result<(), SemanticInvariantError> {
        for record in &self.domains.network.socket_objects {
            let Some(adapter) =
                self.domains.network.network_stack_adapters.iter().find(|adapter| {
                    adapter.id == record.adapter && adapter.generation == record.adapter_generation
                })
            else {
                return Err(SemanticInvariantError::SocketObjectMissingAdapter {
                    socket: record.id,
                    adapter: record.adapter,
                });
            };
            let Some(store) = self.domains.lifecycle.stores.iter().find(|store| {
                store.id == record.owner_store && store.generation == record.owner_store_generation
            }) else {
                return Err(SemanticInvariantError::SocketObjectMissingOwnerStore {
                    socket: record.id,
                    store: record.owner_store,
                });
            };
            if record.id == 0
                || record.generation == 0
                || adapter.state != NetworkStackAdapterState::Bound
                || matches!(
                    store.state,
                    StoreState::Dead | StoreState::Faulted | StoreState::Cleaning
                )
                || record.state != SocketObjectState::Created
                || canonical_socket_protocol(record.domain, record.socket_type, record.protocol)
                    != Some((
                        record.canonical_protocol,
                        record.family.as_str(),
                        record.transport.as_str(),
                    ))
            {
                return Err(SemanticInvariantError::SocketObjectInvalid { socket: record.id });
            }
            if self
                .domains
                .network
                .socket_objects
                .iter()
                .filter(|other| other.id == record.id)
                .count()
                > 1
            {
                return Err(SemanticInvariantError::SocketObjectDuplicate { socket: record.id });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.created_at_event
                    && matches!(
                        &event.kind,
                        EventKind::SocketObjectCreated {
                            socket,
                            adapter,
                            adapter_generation,
                            owner_store,
                            owner_store_generation,
                            domain,
                            socket_type,
                            protocol,
                            canonical_protocol,
                            family,
                            transport,
                            generation,
                        } if *socket == record.id
                            && *adapter == record.adapter
                            && *adapter_generation == record.adapter_generation
                            && *owner_store == record.owner_store
                            && *owner_store_generation == record.owner_store_generation
                            && *domain == record.domain
                            && *socket_type == record.socket_type
                            && *protocol == record.protocol
                            && *canonical_protocol == record.canonical_protocol
                            && family == &record.family
                            && transport == &record.transport
                            && *generation == record.generation
                    )
            }) {
                return Err(SemanticInvariantError::SocketObjectMissingEvent { socket: record.id });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_socket_object_adapter_generation_for_test(
        &mut self,
        socket: SocketObjectId,
        adapter_generation: Generation,
    ) {
        if let Some(record) =
            self.domains.network.socket_objects.iter_mut().find(|record| record.id == socket)
        {
            record.adapter_generation = adapter_generation;
        }
    }
}

fn canonical_socket_protocol(
    domain: u32,
    socket_type: u32,
    protocol: u32,
) -> Option<(u16, &'static str, &'static str)> {
    if domain == SOCKET_OBJECT_DOMAIN_INET
        && socket_type == SOCKET_OBJECT_TYPE_STREAM
        && (protocol == SOCKET_OBJECT_PROTOCOL_UNSPECIFIED
            || protocol == SOCKET_OBJECT_PROTOCOL_TCP as u32)
    {
        Some((SOCKET_OBJECT_PROTOCOL_TCP, SOCKET_OBJECT_FAMILY_INET, SOCKET_OBJECT_TRANSPORT_TCP))
    } else {
        None
    }
}
