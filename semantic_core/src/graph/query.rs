use super::*;

impl SemanticGraph {
    pub fn event_count(&self) -> usize {
        self.event_log.len()
    }
    pub fn event_log(&self) -> &EventLog {
        &self.event_log
    }
    pub fn event_log_tail(&self, count: usize) -> &[EventRecord] {
        self.event_log.tail(count)
    }
    pub fn check_invariants(&self) -> Result<(), SemanticInvariantError> {
        for task in &self.tasks {
            for resource in &task.resources {
                if !self.resources.iter().any(|entry| entry.id == *resource) {
                    return Err(SemanticInvariantError::TaskReferencesMissingResource {
                        task: task.id,
                        resource: *resource,
                    });
                }
            }
        }

        for resource in &self.resources {
            if let Some(task) = resource.owner_task
                && !self.tasks.iter().any(|entry| entry.id == task)
            {
                return Err(SemanticInvariantError::ResourceReferencesMissingTask {
                    resource: resource.id,
                    task,
                });
            }
            if let Some(store) = resource.owner_store
                && !self.stores.iter().any(|entry| entry.id == store)
            {
                return Err(SemanticInvariantError::ResourceReferencesMissingStore {
                    resource: resource.id,
                    store,
                });
            }
        }

        for wait in &self.waits {
            if !self.tasks.iter().any(|entry| entry.id == wait.owner_task) {
                return Err(SemanticInvariantError::WaitReferencesMissingTask {
                    wait: wait.id,
                    task: wait.owner_task,
                });
            }
        }

        for store in &self.stores {
            if !self
                .fault_domains
                .iter()
                .any(|entry| entry.id == store.fault_domain)
            {
                return Err(SemanticInvariantError::StoreReferencesMissingFaultDomain {
                    store: store.id,
                    fault_domain: store.fault_domain,
                });
            }
            if store.state != StoreState::Dead {
                let Some(resource) = store.resource else {
                    return Err(SemanticInvariantError::LiveStoreMissingResource {
                        store: store.id,
                    });
                };
                if !self.resources.iter().any(|entry| {
                    entry.id == resource && entry.owner_store == Some(store.id) && entry.live
                }) {
                    return Err(SemanticInvariantError::StoreReferencesDeadResource {
                        store: store.id,
                        resource,
                    });
                }
            }
        }

        for authority in &self.authority_bindings {
            if authority.state != AuthorityState::Bound {
                continue;
            }
            let Some(resource) = self
                .resources
                .iter()
                .find(|entry| entry.id == authority.resource)
            else {
                return Err(SemanticInvariantError::AuthorityReferencesMissingResource {
                    authority: authority.id,
                    resource: authority.resource,
                });
            };
            if !resource.live {
                return Err(SemanticInvariantError::AuthorityReferencesDeadResource {
                    authority: authority.id,
                    resource: authority.resource,
                });
            }
            for operation in authority.operations.as_slice() {
                if self
                    .capabilities
                    .check(&authority.subject, &authority.object, operation)
                    .is_err()
                {
                    return Err(SemanticInvariantError::AuthorityCapabilityMissing {
                        authority: authority.id,
                    });
                }
            }
        }

        Ok(())
    }
}
