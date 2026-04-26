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
    pub fn command_results(&self) -> &[CommandResult] {
        &self.command_results
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

        self.check_hart_invariants()?;
        self.check_scheduler_invariants()?;
        self.check_context_invariants()?;
        self.check_timer_invariants()?;
        self.check_ipi_invariants()?;
        self.check_remote_preempt_invariants()?;
        self.check_remote_park_invariants()?;
        self.check_cross_hart_scheduler_invariants()?;
        self.check_activation_migration_invariants()?;
        self.check_smp_safe_point_invariants()?;
        self.check_stop_the_world_invariants()?;
        self.check_smp_code_publish_barrier_invariants()?;
        self.check_smp_cleanup_quiescence_invariants()?;
        self.check_smp_snapshot_barrier_invariants()?;
        self.check_smp_stress_run_invariants()?;
        self.check_smp_scaling_benchmark_invariants()?;
        self.check_device_object_invariants()?;
        self.check_queue_object_invariants()?;
        self.check_descriptor_object_invariants()?;
        self.check_dma_buffer_object_invariants()?;
        self.check_mmio_region_object_invariants()?;
        self.check_irq_line_object_invariants()?;
        self.check_irq_event_invariants()?;
        self.check_hart_event_attribution_invariants()?;
        self.check_wait_invariants()?;
        self.check_cleanup_invariants()?;
        self.check_preemption_latency_invariants()?;

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
            if authority.object_ref.object()
                != ContractObjectRef::new(
                    ContractObjectKind::Resource,
                    resource.id,
                    resource.generation,
                )
            {
                return Err(SemanticInvariantError::AuthorityCapabilityMissing {
                    authority: authority.id,
                });
            }
            let Some(capability) = self.capabilities.active(authority.capability) else {
                return Err(SemanticInvariantError::AuthorityCapabilityMissing {
                    authority: authority.id,
                });
            };
            if capability.generation != authority.capability_generation
                || capability.subject != authority.subject
                || capability.object_ref != Some(authority.object_ref)
            {
                return Err(SemanticInvariantError::AuthorityCapabilityMissing {
                    authority: authority.id,
                });
            }
            for operation in authority.operations.as_slice() {
                if !capability.operations.contains(operation) {
                    return Err(SemanticInvariantError::AuthorityCapabilityMissing {
                        authority: authority.id,
                    });
                }
            }
        }

        Ok(())
    }
}
