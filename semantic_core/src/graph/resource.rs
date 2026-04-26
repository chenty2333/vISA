use super::*;

impl SemanticGraph {
    pub fn register_resource(
        &mut self,
        kind: ResourceKind,
        owner_task: Option<TaskId>,
        label: &str,
    ) -> ResourceId {
        self.register_resource_for_store(kind, owner_task, None, label)
    }
    pub fn register_resource_for_store(
        &mut self,
        kind: ResourceKind,
        owner_task: Option<TaskId>,
        owner_store: Option<StoreId>,
        label: &str,
    ) -> ResourceId {
        let id = self.next_resource_id;
        self.next_resource_id += 1;
        self.resources.push(ResourceRecord {
            id,
            label: label.to_string(),
            kind,
            owner_task,
            owner_store,
            generation: 1,
            live: true,
        });
        if let Some(owner_task) = owner_task
            && let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task)
        {
            task.resources.push(id);
        }
        self.event_log.push(
            "resource",
            EventKind::ResourceCreated {
                resource: id,
                kind,
                generation: 1,
            },
        );
        id
    }
    pub fn close_resource(&mut self, id: ResourceId) {
        let Some(resource) = self.resources.iter_mut().find(|resource| resource.id == id) else {
            return;
        };
        if !resource.live {
            return;
        }
        resource.live = false;
        resource.generation += 1;
        self.event_log.push(
            "resource",
            EventKind::ResourceClosed {
                resource: id,
                generation: resource.generation,
            },
        );
    }
    pub fn mark_resource_dead(&mut self, id: ResourceId) {
        self.close_resource(id);
        self.record_failure_effect(FailureEffect::MarkResourceDead(id));
    }
    pub fn close_resources_owned_by_store(&mut self, store: StoreId) -> usize {
        self.cleanup_resources_owned_by_store(store)
            .closed_resources
    }
    pub fn cleanup_resources_owned_by_store(
        &mut self,
        store: StoreId,
    ) -> StoreResourceCleanupReport {
        let resources = self
            .resources
            .iter()
            .filter(|resource| resource.owner_store == Some(store) && resource.live)
            .map(|resource| resource.id)
            .collect::<Vec<_>>();
        let count = resources.len();
        let mut revoked_authorities = 0usize;
        for resource in resources {
            revoked_authorities +=
                self.revoke_authority_for_resource(resource, "owner store dropped");
            if self
                .resources
                .iter()
                .any(|entry| entry.id == resource && entry.live)
            {
                self.mark_resource_dead(resource);
            }
        }
        StoreResourceCleanupReport {
            store,
            closed_resources: count,
            revoked_authorities,
        }
    }
    pub fn resource_handle(&self, id: ResourceId) -> Option<ResourceHandle> {
        self.resources
            .iter()
            .find(|resource| resource.id == id)
            .map(|resource| ResourceHandle::new(resource.id, resource.generation))
    }
    pub fn validate_resource_handle(
        &mut self,
        handle: ResourceHandle,
    ) -> Result<(), GenerationCheckError> {
        let resource = self
            .resources
            .iter()
            .find(|resource| resource.id == handle.id);
        let actual = resource.map(|resource| resource.generation);
        let result = match resource {
            None => Err(GenerationCheckError::Missing),
            Some(resource) if resource.generation != handle.generation => {
                Err(GenerationCheckError::GenerationMismatch {
                    expected: handle.generation,
                    actual,
                })
            }
            Some(resource) if !resource.live => Err(GenerationCheckError::Dead {
                actual: resource.generation,
            }),
            Some(_) => Ok(()),
        };

        match result {
            Ok(()) => {
                self.event_log.push(
                    "resource",
                    EventKind::ResourceHandleValidated {
                        resource: handle.id,
                        generation: handle.generation,
                    },
                );
                Ok(())
            }
            Err(reason) => {
                self.event_log.push(
                    "resource",
                    EventKind::ResourceHandleRejected {
                        resource: handle.id,
                        expected: handle.generation,
                        actual,
                        reason,
                    },
                );
                Err(reason)
            }
        }
    }
    pub fn record_window_lease_created(
        &mut self,
        owner_task: Option<TaskId>,
        label: &str,
        generation: Generation,
    ) -> ResourceId {
        let lease = self.register_resource(ResourceKind::WindowLease, owner_task, label);
        self.event_log
            .push("dmw", EventKind::WindowLeaseCreated { lease, generation });
        lease
    }
    pub fn record_window_lease_destroyed(&mut self, lease: ResourceId, generation: Generation) {
        self.close_resource(lease);
        self.event_log
            .push("dmw", EventKind::WindowLeaseDestroyed { lease, generation });
    }
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }
    pub fn resources(&self) -> &[ResourceRecord] {
        &self.resources
    }
    pub fn live_resource_count(&self) -> usize {
        self.resources
            .iter()
            .filter(|resource| resource.live)
            .count()
    }
}
