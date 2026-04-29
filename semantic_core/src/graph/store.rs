use super::*;

impl SemanticGraph {
    pub fn register_fault_domain(&mut self, name: &str, role: &str) -> FaultDomainId {
        if let Some(domain) = self.fault_domains.iter().find(|domain| domain.name == name) {
            return domain.id;
        }

        let id = self.next_fault_domain_id;
        self.next_fault_domain_id += 1;
        self.fault_domains.push(FaultDomainRecord {
            id,
            name: name.to_string(),
            role: role.to_string(),
            state: FaultDomainState::Created,
            generation: 1,
        });
        self.event_log.push("fault-domain", EventKind::FaultDomainRegistered { domain: id });
        id
    }
    pub fn fault_domain_id(&self, name: &str) -> Option<FaultDomainId> {
        self.fault_domains.iter().find(|domain| domain.name == name).map(|domain| domain.id)
    }
    pub fn set_fault_domain_state(&mut self, id: FaultDomainId, state: FaultDomainState) {
        let Some(domain) = self.fault_domains.iter_mut().find(|domain| domain.id == id) else {
            return;
        };
        let from = domain.state;
        if domain.state == state {
            return;
        }
        domain.state = state;
        domain.generation += 1;
        let generation = domain.generation;
        self.event_log.push(
            "fault-domain",
            EventKind::FaultDomainStateChanged { domain: id, from, to: state, generation },
        );
    }
    pub fn register_store(
        &mut self,
        package: &str,
        artifact: &str,
        role: &str,
        fault_policy: &str,
    ) -> StoreId {
        if let Some(store) = self.stores.iter().find(|store| store.package == package) {
            return store.id;
        }

        let id = self.next_store_id;
        self.next_store_id += 1;
        let fault_domain = self.register_fault_domain(package, role);
        let resource = self.register_resource_for_store(
            ResourceKind::ServiceStore,
            None,
            Some(id),
            &format!("store:{package}:{artifact}"),
        );
        self.stores.push(StoreRecord {
            id,
            package: package.to_string(),
            artifact: artifact.to_string(),
            role: role.to_string(),
            fault_policy: fault_policy.to_string(),
            fault_domain,
            resource: Some(resource),
            state: StoreState::Created,
            generation: 1,
            restart_count: 0,
        });
        self.event_log.push(
            "store",
            EventKind::StoreRegistered { store: id, domain: fault_domain, resource, generation: 1 },
        );
        id
    }
    pub fn store_id(&self, package: &str) -> Option<StoreId> {
        self.stores.iter().find(|store| store.package == package).map(|store| store.id)
    }
    pub fn store_handle(&self, id: StoreId) -> Option<StoreHandle> {
        self.stores
            .iter()
            .find(|store| store.id == id)
            .map(|store| StoreHandle::new(store.id, store.generation))
    }
    pub fn store_resource(&self, id: StoreId) -> Option<ResourceId> {
        self.stores.iter().find(|store| store.id == id).and_then(|store| store.resource)
    }
    pub fn validate_store_handle(
        &mut self,
        handle: StoreHandle,
    ) -> Result<(), GenerationCheckError> {
        let store = self.stores.iter().find(|store| store.id == handle.id);
        let actual = store.map(|store| store.generation);
        match store {
            None => Err(GenerationCheckError::Missing),
            Some(store) if store.generation != handle.generation => {
                Err(GenerationCheckError::GenerationMismatch {
                    expected: handle.generation,
                    actual,
                })
            }
            Some(store) if store.state == StoreState::Dead => {
                Err(GenerationCheckError::Dead { actual: store.generation })
            }
            Some(_) => Ok(()),
        }
    }
    pub fn set_store_state(&mut self, id: StoreId, state: StoreState) {
        let Some(index) = self.stores.iter().position(|store| store.id == id) else {
            return;
        };
        let from = self.stores[index].state;
        if from == state {
            return;
        }
        self.stores[index].state = state;
        self.stores[index].generation += 1;
        if state == StoreState::Restarting {
            self.stores[index].restart_count += 1;
        }
        let generation = self.stores[index].generation;
        let fault_domain = self.stores[index].fault_domain;
        self.event_log
            .push("store", EventKind::StoreStateChanged { store: id, from, to: state, generation });
        self.set_fault_domain_state(fault_domain, state.fault_domain_state());
        if state == StoreState::Running && self.stores[index].restart_count > 0 {
            self.event_log
                .push("fault-domain", EventKind::FaultDomainRestarted { domain: fault_domain });
        }
    }
    pub fn record_store_executor_transition(
        &mut self,
        id: StoreId,
        from: &str,
        to: &str,
        blocked_by: Option<&str>,
        hostcall_table: &str,
        trap_surface: &str,
    ) {
        if !self.stores.iter().any(|store| store.id == id) {
            return;
        }
        self.event_log.push(
            "executor",
            EventKind::StoreExecutorTransition {
                store: id,
                from: from.to_string(),
                to: to.to_string(),
                blocked_by: blocked_by.map(|value| value.to_string()),
                hostcall_table: hostcall_table.to_string(),
                trap_surface: trap_surface.to_string(),
            },
        );
    }
    pub fn record_store_trap(&mut self, id: StoreId, trap: &str) {
        self.record_store_trap_class(id, TrapClass::ServiceTrap, trap);
    }
    pub fn record_store_trap_class(&mut self, id: StoreId, trap: TrapClass, detail: &str) {
        let domain =
            self.stores.iter().find(|store| store.id == id).map(|store| store.fault_domain);
        self.event_log.push(
            "fault",
            EventKind::FaultClassified {
                trap,
                class: trap.fault_class(),
                store: Some(id),
                task: None,
                detail: detail.to_string(),
            },
        );
        self.event_log
            .push("store", EventKind::StoreTrap { store: id, trap, detail: detail.to_string() });
        self.record_driver_trap_class(domain, trap, detail);
        self.set_store_state(id, StoreState::Degraded);
    }
    pub fn drop_store_instance(&mut self, id: StoreId) -> Option<StoreDropReport> {
        let index = self.stores.iter().position(|store| store.id == id)?;
        let resource = self.stores[index].resource.take();
        let cleanup = self.cleanup_resources_owned_by_store(id);
        self.set_store_state(id, StoreState::Dead);
        let generation = self.stores[index].generation;
        self.event_log.push("store", EventKind::StoreDropped { store: id, generation, resource });
        Some(StoreDropReport {
            store: id,
            generation,
            previous_resource: resource,
            closed_resources: cleanup.closed_resources,
            revoked_authorities: cleanup.revoked_authorities,
        })
    }
    pub fn rebind_store_instance(&mut self, id: StoreId) -> Option<StoreRebindReport> {
        let index = self.stores.iter().position(|store| store.id == id)?;
        let package = self.stores[index].package.clone();
        let artifact = self.stores[index].artifact.clone();
        let resource = self.register_resource_for_store(
            ResourceKind::ServiceStore,
            None,
            Some(id),
            &format!("store:{package}:{artifact}"),
        );
        self.stores[index].resource = Some(resource);
        self.stores[index].generation += 1;
        self.stores[index].state = StoreState::Rebinding;
        let generation = self.stores[index].generation;
        self.event_log.push("store", EventKind::StoreRebound { store: id, generation, resource });
        self.set_fault_domain_state(
            self.stores[index].fault_domain,
            StoreState::Rebinding.fault_domain_state(),
        );
        Some(StoreRebindReport { store: id, generation, resource })
    }
    pub fn record_driver_trap(&mut self, domain: Option<FaultDomainId>, trap: &str) {
        self.record_driver_trap_class(domain, TrapClass::DriverTrap, trap);
    }
    pub fn record_driver_trap_class(
        &mut self,
        domain: Option<FaultDomainId>,
        trap: TrapClass,
        detail: &str,
    ) {
        self.event_log
            .push("trap", EventKind::DriverTrap { domain, trap, detail: detail.to_string() });
    }
    pub fn fault_domain_count(&self) -> usize {
        self.fault_domains.len()
    }
    pub fn store_count(&self) -> usize {
        self.stores.len()
    }
    pub fn store_executor_transition_count(&self) -> usize {
        self.event_log
            .events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::StoreExecutorTransition { .. }))
            .count()
    }
    pub fn store_executor_transition_tail(&self, count: usize) -> Vec<String> {
        let mut lines = Vec::new();
        for event in self.event_log.events.iter().rev() {
            if matches!(event.kind, EventKind::StoreExecutorTransition { .. }) {
                lines.push(event.summary());
                if lines.len() == count {
                    break;
                }
            }
        }
        lines.reverse();
        lines
    }
    pub fn stores(&self) -> &[StoreRecord] {
        &self.stores
    }
}
