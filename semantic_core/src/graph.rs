use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

#[derive(Clone, Debug)]
pub struct SemanticGraph {
    tasks: Vec<TaskRecord>,
    resources: Vec<ResourceRecord>,
    authority_bindings: Vec<AuthorityBindingRecord>,
    waits: Vec<WaitRecord>,
    fault_domains: Vec<FaultDomainRecord>,
    stores: Vec<StoreRecord>,
    transactions: Vec<SemanticTransactionRecord>,
    fast_path_plans: Vec<FastPathPlanRecord>,
    boundaries: Vec<BoundaryRecord>,
    artifact_verifications: Vec<ArtifactVerificationRecord>,
    store_activations: Vec<StoreActivationRecord>,
    capabilities: CapabilityLedger,
    event_log: EventLog,
    next_resource_id: ResourceId,
    next_authority_id: AuthorityId,
    next_fault_domain_id: FaultDomainId,
    next_store_id: StoreId,
    next_transaction_id: TransactionId,
    next_plan_id: PlanId,
    next_boundary_id: BoundaryId,
    next_artifact_id: ArtifactId,
    next_activation_id: StoreActivationId,
}

impl SemanticGraph {
    pub fn new() -> Self {
        Self::with_runtime_mode(RuntimeMode::Research)
    }

    pub fn with_runtime_mode(runtime_mode: RuntimeMode) -> Self {
        Self {
            tasks: Vec::new(),
            resources: Vec::new(),
            authority_bindings: Vec::new(),
            waits: Vec::new(),
            fault_domains: Vec::new(),
            stores: Vec::new(),
            transactions: Vec::new(),
            fast_path_plans: Vec::new(),
            boundaries: Vec::new(),
            artifact_verifications: Vec::new(),
            store_activations: Vec::new(),
            capabilities: CapabilityLedger::new(),
            event_log: EventLog::with_runtime_mode(runtime_mode),
            next_resource_id: 1,
            next_authority_id: 1,
            next_fault_domain_id: 1,
            next_store_id: 1,
            next_transaction_id: 1,
            next_plan_id: 1,
            next_boundary_id: 1,
            next_artifact_id: 1,
            next_activation_id: 1,
        }
    }

    pub fn runtime_mode(&self) -> RuntimeMode {
        self.event_log.runtime_mode()
    }

    pub fn publish_boundary(
        &mut self,
        name: &str,
        kind: BoundaryKind,
        status: BoundaryStatus,
        backend: &str,
        blocked_by: Option<&str>,
    ) -> BoundaryId {
        if let Some(index) = self
            .boundaries
            .iter()
            .position(|boundary| boundary.name == name)
        {
            self.boundaries[index].kind = kind;
            self.boundaries[index].status = status;
            self.boundaries[index].backend = backend.to_string();
            self.boundaries[index].blocked_by = blocked_by.map(|value| value.to_string());
            self.boundaries[index].generation += 1;
            let id = self.boundaries[index].id;
            let name = self.boundaries[index].name.clone();
            let backend = self.boundaries[index].backend.clone();
            let blocked_by = self.boundaries[index].blocked_by.clone();
            let generation = self.boundaries[index].generation;
            self.event_log.push(
                "boundary",
                EventKind::BoundaryPublished {
                    boundary: id,
                    name,
                    kind,
                    status,
                    backend,
                    blocked_by,
                    generation,
                },
            );
            return id;
        }

        let id = self.next_boundary_id;
        self.next_boundary_id += 1;
        let boundary = BoundaryRecord {
            id,
            name: name.to_string(),
            kind,
            status,
            backend: backend.to_string(),
            blocked_by: blocked_by.map(|value| value.to_string()),
            generation: 1,
        };
        self.event_log.push(
            "boundary",
            EventKind::BoundaryPublished {
                boundary: id,
                name: boundary.name.clone(),
                kind,
                status,
                backend: boundary.backend.clone(),
                blocked_by: boundary.blocked_by.clone(),
                generation: boundary.generation,
            },
        );
        self.boundaries.push(boundary);
        id
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_artifact_verification(
        &mut self,
        package: &str,
        artifact_name: &str,
        manifest_binding_hash: &str,
        cwasm_sha256: &str,
        abi_fingerprint: &str,
        signature_profile: &str,
        signer: &str,
        state: ArtifactVerificationState,
        blocked_by: Option<&str>,
    ) -> ArtifactId {
        if let Some(index) = self
            .artifact_verifications
            .iter()
            .position(|record| record.package == package)
        {
            self.artifact_verifications[index].artifact_name = artifact_name.to_string();
            self.artifact_verifications[index].manifest_binding_hash =
                manifest_binding_hash.to_string();
            self.artifact_verifications[index].cwasm_sha256 = cwasm_sha256.to_string();
            self.artifact_verifications[index].abi_fingerprint = abi_fingerprint.to_string();
            self.artifact_verifications[index].signature_profile = signature_profile.to_string();
            self.artifact_verifications[index].signer = signer.to_string();
            self.artifact_verifications[index].state = state;
            self.artifact_verifications[index].blocked_by =
                blocked_by.map(|value| value.to_string());
            self.artifact_verifications[index].generation += 1;
            let record = &self.artifact_verifications[index];
            self.event_log.push(
                "artifact",
                EventKind::ArtifactVerificationRecorded {
                    artifact: record.id,
                    package: record.package.clone(),
                    artifact_name: record.artifact_name.clone(),
                    state,
                    manifest_binding_hash: record.manifest_binding_hash.clone(),
                    blocked_by: record.blocked_by.clone(),
                    generation: record.generation,
                },
            );
            return record.id;
        }

        let id = self.next_artifact_id;
        self.next_artifact_id += 1;
        let record = ArtifactVerificationRecord {
            id,
            package: package.to_string(),
            artifact_name: artifact_name.to_string(),
            manifest_binding_hash: manifest_binding_hash.to_string(),
            cwasm_sha256: cwasm_sha256.to_string(),
            abi_fingerprint: abi_fingerprint.to_string(),
            signature_profile: signature_profile.to_string(),
            signer: signer.to_string(),
            state,
            blocked_by: blocked_by.map(|value| value.to_string()),
            generation: 1,
        };
        self.event_log.push(
            "artifact",
            EventKind::ArtifactVerificationRecorded {
                artifact: id,
                package: record.package.clone(),
                artifact_name: record.artifact_name.clone(),
                state,
                manifest_binding_hash: record.manifest_binding_hash.clone(),
                blocked_by: record.blocked_by.clone(),
                generation: record.generation,
            },
        );
        self.artifact_verifications.push(record);
        id
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_store_activation(
        &mut self,
        store: StoreId,
        package: &str,
        manifest_binding_hash: &str,
        cwasm_sha256: &str,
        code_publish_state: CodePublishState,
        memory_layout_state: MemoryLayoutState,
        hostcall_table_state: HostcallLinkState,
        trap_surface_state: TrapSurfaceState,
        entrypoint_state: EntrypointState,
        blocked_by: Option<&str>,
    ) -> StoreActivationId {
        if let Some(index) = self
            .store_activations
            .iter()
            .position(|record| record.store == store)
        {
            self.store_activations[index].package = package.to_string();
            self.store_activations[index].manifest_binding_hash = manifest_binding_hash.to_string();
            self.store_activations[index].cwasm_sha256 = cwasm_sha256.to_string();
            self.store_activations[index].code_publish_state = code_publish_state;
            self.store_activations[index].memory_layout_state = memory_layout_state;
            self.store_activations[index].hostcall_table_state = hostcall_table_state;
            self.store_activations[index].trap_surface_state = trap_surface_state;
            self.store_activations[index].entrypoint_state = entrypoint_state;
            self.store_activations[index].blocked_by = blocked_by.map(|value| value.to_string());
            self.store_activations[index].generation += 1;
            let record = &self.store_activations[index];
            self.event_log.push(
                "activation",
                EventKind::StoreActivationRecorded {
                    activation: record.id,
                    store,
                    package: record.package.clone(),
                    code_publish_state,
                    memory_layout_state,
                    hostcall_table_state,
                    trap_surface_state,
                    entrypoint_state,
                    blocked_by: record.blocked_by.clone(),
                    generation: record.generation,
                },
            );
            return record.id;
        }

        let id = self.next_activation_id;
        self.next_activation_id += 1;
        let record = StoreActivationRecord::new(
            id,
            store,
            package,
            manifest_binding_hash,
            cwasm_sha256,
            code_publish_state,
            memory_layout_state,
            hostcall_table_state,
            trap_surface_state,
            entrypoint_state,
            blocked_by,
        );
        self.event_log.push(
            "activation",
            EventKind::StoreActivationRecorded {
                activation: id,
                store,
                package: record.package.clone(),
                code_publish_state,
                memory_layout_state,
                hostcall_table_state,
                trap_surface_state,
                entrypoint_state,
                blocked_by: record.blocked_by.clone(),
                generation: record.generation,
            },
        );
        self.store_activations.push(record);
        id
    }

    pub fn ensure_task(&mut self, id: TaskId, frontend: FrontendKind, label: &str) {
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
            task.frontend = frontend;
            task.label = label.to_string();
            return;
        }

        self.tasks.push(TaskRecord {
            id,
            label: label.to_string(),
            frontend,
            state: TaskState::Runnable,
            fault_domain: None,
            pending_wait: None,
            generation: 1,
            resources: Vec::new(),
        });
        self.event_log
            .push("semantic", EventKind::TaskCreated { task: id, frontend });
    }

    pub fn set_task_state(&mut self, id: TaskId, state: TaskState) {
        let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) else {
            return;
        };
        let from = task.state;
        if from == state {
            return;
        }
        task.state = state;
        task.generation += 1;
        if state != TaskState::Pending {
            task.pending_wait = None;
        }
        self.event_log.push(
            "scheduler",
            EventKind::TaskStateChanged {
                task: id,
                from,
                to: state,
            },
        );
    }

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

    pub fn bind_authority_resource(
        &mut self,
        resource: ResourceId,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> Option<AuthorityId> {
        let kind = {
            let resource = self
                .resources
                .iter()
                .find(|candidate| candidate.id == resource && candidate.live)?;
            AuthorityKind::from_resource_kind(resource.kind)?
        };
        let id = self.next_authority_id;
        self.next_authority_id += 1;
        self.authority_bindings.push(AuthorityBindingRecord {
            id,
            resource,
            kind,
            subject: subject.to_string(),
            object: object.to_string(),
            operations: OperationSet::from_static(operations),
            lifetime: lifetime.to_string(),
            generation: 1,
            state: AuthorityState::Bound,
        });
        self.grant_capability_with_source(
            subject,
            object,
            operations,
            lifetime,
            CapabilityClass::from_object(object),
            "authority-binding",
        );
        self.event_log.push(
            "authority",
            EventKind::AuthorityBound {
                authority: id,
                resource,
                kind,
                subject: subject.to_string(),
                object: object.to_string(),
                generation: 1,
            },
        );
        Some(id)
    }

    pub fn release_authority_binding(&mut self, id: AuthorityId, reason: &str) -> bool {
        let Some(index) = self
            .authority_bindings
            .iter()
            .position(|authority| authority.id == id)
        else {
            return false;
        };
        if self.authority_bindings[index].state != AuthorityState::Bound {
            return false;
        }
        self.authority_bindings[index].state = AuthorityState::Released;
        self.authority_bindings[index].generation += 1;
        let resource = self.authority_bindings[index].resource;
        let generation = self.authority_bindings[index].generation;
        let subject = self.authority_bindings[index].subject.clone();
        let object = self.authority_bindings[index].object.clone();
        self.capabilities
            .revoke_by_subject_object(&subject, &object);
        self.event_log.push(
            "authority",
            EventKind::AuthorityReleased {
                authority: id,
                resource,
                generation,
                reason: reason.to_string(),
            },
        );
        self.close_resource(resource);
        true
    }

    pub fn revoke_authority_for_resource(&mut self, resource: ResourceId, reason: &str) -> usize {
        let authorities = self
            .authority_bindings
            .iter()
            .filter(|authority| {
                authority.resource == resource && authority.state == AuthorityState::Bound
            })
            .map(|authority| authority.id)
            .collect::<Vec<_>>();
        let count = authorities.len();
        for authority in authorities {
            self.revoke_authority_binding(authority, reason);
        }
        count
    }

    pub fn revoke_authority_binding(&mut self, id: AuthorityId, reason: &str) -> bool {
        let Some(index) = self
            .authority_bindings
            .iter()
            .position(|authority| authority.id == id)
        else {
            return false;
        };
        if self.authority_bindings[index].state != AuthorityState::Bound {
            return false;
        }
        self.authority_bindings[index].state = AuthorityState::Revoked;
        self.authority_bindings[index].generation += 1;
        let resource = self.authority_bindings[index].resource;
        let generation = self.authority_bindings[index].generation;
        let subject = self.authority_bindings[index].subject.clone();
        let object = self.authority_bindings[index].object.clone();
        self.capabilities
            .revoke_by_subject_object(&subject, &object);
        self.event_log.push(
            "authority",
            EventKind::AuthorityRevoked {
                authority: id,
                resource,
                generation,
                reason: reason.to_string(),
            },
        );
        self.mark_resource_dead(resource);
        true
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
        self.event_log.push(
            "fault-domain",
            EventKind::FaultDomainRegistered { domain: id },
        );
        id
    }

    pub fn fault_domain_id(&self, name: &str) -> Option<FaultDomainId> {
        self.fault_domains
            .iter()
            .find(|domain| domain.name == name)
            .map(|domain| domain.id)
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
            EventKind::FaultDomainStateChanged {
                domain: id,
                from,
                to: state,
                generation,
            },
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
            EventKind::StoreRegistered {
                store: id,
                domain: fault_domain,
                resource,
                generation: 1,
            },
        );
        id
    }

    pub fn store_id(&self, package: &str) -> Option<StoreId> {
        self.stores
            .iter()
            .find(|store| store.package == package)
            .map(|store| store.id)
    }

    pub fn store_handle(&self, id: StoreId) -> Option<StoreHandle> {
        self.stores
            .iter()
            .find(|store| store.id == id)
            .map(|store| StoreHandle::new(store.id, store.generation))
    }

    pub fn store_resource(&self, id: StoreId) -> Option<ResourceId> {
        self.stores
            .iter()
            .find(|store| store.id == id)
            .and_then(|store| store.resource)
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
            Some(store) if store.state == StoreState::Dead => Err(GenerationCheckError::Dead {
                actual: store.generation,
            }),
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
        self.event_log.push(
            "store",
            EventKind::StoreStateChanged {
                store: id,
                from,
                to: state,
                generation,
            },
        );
        self.set_fault_domain_state(fault_domain, state.fault_domain_state());
        if state == StoreState::Running && self.stores[index].restart_count > 0 {
            self.event_log.push(
                "fault-domain",
                EventKind::FaultDomainRestarted {
                    domain: fault_domain,
                },
            );
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
        let domain = self
            .stores
            .iter()
            .find(|store| store.id == id)
            .map(|store| store.fault_domain);
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
        self.event_log.push(
            "store",
            EventKind::StoreTrap {
                store: id,
                trap,
                detail: detail.to_string(),
            },
        );
        self.record_driver_trap_class(domain, trap, detail);
        self.set_store_state(id, StoreState::Degraded);
    }

    pub fn drop_store_instance(&mut self, id: StoreId) -> Option<StoreDropReport> {
        let index = self.stores.iter().position(|store| store.id == id)?;
        let resource = self.stores[index].resource.take();
        let cleanup = self.cleanup_resources_owned_by_store(id);
        self.set_store_state(id, StoreState::Dead);
        let generation = self.stores[index].generation;
        self.event_log.push(
            "store",
            EventKind::StoreDropped {
                store: id,
                generation,
                resource,
            },
        );
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
        self.event_log.push(
            "store",
            EventKind::StoreRebound {
                store: id,
                generation,
                resource,
            },
        );
        self.set_fault_domain_state(
            self.stores[index].fault_domain,
            StoreState::Rebinding.fault_domain_state(),
        );
        Some(StoreRebindReport {
            store: id,
            generation,
            resource,
        })
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
        self.event_log.push(
            "trap",
            EventKind::DriverTrap {
                domain,
                trap,
                detail: detail.to_string(),
            },
        );
    }

    pub fn record_packet_received(
        &mut self,
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    ) {
        self.event_log.push(
            "net",
            EventKind::PacketReceived {
                interface,
                socket,
                ready_key,
                len,
            },
        );
    }

    pub fn record_packet_transmitted(
        &mut self,
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    ) {
        self.event_log.push(
            "net",
            EventKind::PacketTransmitted {
                interface,
                socket,
                ready_key,
                len,
            },
        );
    }

    pub fn record_net_interface_state_changed(&mut self, interface: ResourceId, up: bool) {
        self.event_log
            .push("net", EventKind::NetInterfaceStateChanged { interface, up });
    }

    pub fn record_socket_state_changed(&mut self, socket: ResourceId, state: &str) {
        self.event_log.push(
            "net",
            EventKind::SocketStateChanged {
                socket,
                state: state.to_string(),
            },
        );
    }

    pub fn record_device_irq_delivered(
        &mut self,
        irq: ResourceId,
        device: ResourceId,
        cause: &str,
    ) {
        self.event_log.push(
            "device",
            EventKind::DeviceIrqDelivered {
                irq,
                device,
                cause: cause.to_string(),
            },
        );
    }

    pub fn record_driver_completion(&mut self, device: ResourceId, operation: &str) {
        self.event_log.push(
            "driver",
            EventKind::DriverCompletion {
                device,
                operation: operation.to_string(),
            },
        );
    }

    pub fn record_dma_submitted(&mut self, buffer: ResourceId, device: ResourceId, len: usize) {
        self.event_log.push(
            "dma",
            EventKind::DmaSubmitted {
                buffer,
                device,
                len,
            },
        );
    }

    pub fn record_dma_completed(&mut self, buffer: ResourceId, device: ResourceId, len: usize) {
        self.event_log.push(
            "dma",
            EventKind::DmaCompleted {
                buffer,
                device,
                len,
            },
        );
    }

    pub fn grant_capability(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> CapabilityId {
        self.grant_capability_with_source(
            subject,
            object,
            operations,
            lifetime,
            CapabilityClass::from_object(object),
            "runtime-grant",
        )
    }

    pub fn grant_manifest_capability(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> CapabilityId {
        self.grant_capability_with_source(
            subject,
            object,
            operations,
            lifetime,
            CapabilityClass::from_object(object),
            "artifact-manifest",
        )
    }

    pub fn grant_capability_with_source(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
        class: CapabilityClass,
        source: &str,
    ) -> CapabilityId {
        let owner_store = self.store_id(subject);
        let cap = self.capabilities.grant_with_metadata(
            subject,
            object,
            operations,
            lifetime,
            class,
            owner_store,
            None,
            source,
        );
        self.event_log
            .push("capability", EventKind::CapabilityGranted { cap });
        cap
    }

    pub fn revoke_capability(&mut self, cap: CapabilityId) -> bool {
        if !self.capabilities.revoke(cap) {
            return false;
        }
        self.event_log
            .push("capability", EventKind::CapabilityRevoked { cap });
        true
    }

    pub fn revoke_capability_by_subject_object(
        &mut self,
        subject: &str,
        object: &str,
    ) -> Option<CapabilityId> {
        let cap = self
            .capabilities
            .revoke_by_subject_object(subject, object)?;
        self.event_log
            .push("capability", EventKind::CapabilityRevoked { cap });
        Some(cap)
    }

    pub fn revoke_capabilities_for_subject(&mut self, subject: &str) -> CapabilityRevocationReport {
        let report = self.capabilities.revoke_subject_report(subject);
        for cap in &report.revoked {
            self.event_log
                .push("capability", EventKind::CapabilityRevoked { cap: *cap });
        }
        report
    }

    pub fn check_capability(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> Result<CapabilityId, CapabilityDenyReason> {
        match self.capabilities.check(subject, object, operation) {
            Ok(record) => {
                let cap = record.id;
                let generation = record.generation;
                self.event_log.push(
                    "capability",
                    EventKind::CapabilityUsed {
                        cap,
                        subject: subject.to_string(),
                        object: object.to_string(),
                        operation: operation.to_string(),
                        generation,
                    },
                );
                Ok(cap)
            }
            Err(reason) => {
                self.event_log.push(
                    "capability",
                    EventKind::CapabilityDenied {
                        subject: subject.to_string(),
                        object: object.to_string(),
                        operation: operation.to_string(),
                        reason,
                    },
                );
                Err(reason)
            }
        }
    }

    pub fn check_capability_generation(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
        expected_generation: Generation,
    ) -> Result<CapabilityId, CapabilityDenyReason> {
        let actual_generation = self.capabilities.generation_of(subject, object);
        let record = match self.capabilities.check(subject, object, operation) {
            Ok(record) => record,
            Err(reason) => {
                self.event_log.push(
                    "capability",
                    EventKind::CapabilityDenied {
                        subject: subject.to_string(),
                        object: object.to_string(),
                        operation: operation.to_string(),
                        reason,
                    },
                );
                return Err(reason);
            }
        };
        if record.generation != expected_generation {
            self.event_log.push(
                "capability",
                EventKind::CapabilityGenerationMismatch {
                    subject: subject.to_string(),
                    object: object.to_string(),
                    operation: operation.to_string(),
                    expected: expected_generation,
                    actual: actual_generation,
                },
            );
            return Err(CapabilityDenyReason::GenerationMismatch);
        }
        let cap = record.id;
        let generation = record.generation;
        self.event_log.push(
            "capability",
            EventKind::CapabilityUsed {
                cap,
                subject: subject.to_string(),
                object: object.to_string(),
                operation: operation.to_string(),
                generation,
            },
        );
        Ok(cap)
    }

    pub fn capability_generation(&self, subject: &str, object: &str) -> Option<Generation> {
        self.capabilities.generation_of(subject, object)
    }

    pub fn capability_owner_summary(&self, subject: &str) -> CapabilityOwnerSummary {
        self.capabilities.owner_summary(subject)
    }

    pub fn record_hostcall(
        &mut self,
        label: &str,
        class: HostcallClass,
        subject: &str,
        object: &str,
        operation: &str,
    ) {
        self.event_log.push(
            "hostcall",
            EventKind::HostcallEntered {
                label: label.to_string(),
                class,
                subject: subject.to_string(),
                object: object.to_string(),
                operation: operation.to_string(),
            },
        );
    }

    pub fn record_wait_created(
        &mut self,
        wait: WaitId,
        owner_task: TaskId,
        kind: SemanticWaitKind,
        generation: Generation,
    ) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Pending;
            record.generation = generation;
        } else {
            self.waits.push(WaitRecord {
                id: wait,
                owner_task,
                kind,
                generation,
                state: WaitState::Pending,
            });
        }
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task) {
            task.pending_wait = Some(wait);
        }
        self.set_task_state(owner_task, TaskState::Pending);
        self.event_log.push(
            "wait",
            EventKind::WaitCreated {
                wait,
                task: owner_task,
                kind,
                generation,
            },
        );
    }

    pub fn record_wait_resolved(&mut self, wait: WaitId, reason: &str) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Ready;
        }
        self.event_log.push(
            "wait",
            EventKind::WaitResolved {
                wait,
                reason: reason.to_string(),
            },
        );
    }

    pub fn record_wait_cancelled(&mut self, wait: WaitId, errno: i32) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Cancelled;
        }
        self.event_log
            .push("wait", EventKind::WaitCancelled { wait, errno });
    }

    pub fn record_wait_restarted(&mut self, wait: WaitId, class: &str) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Restarted;
        }
        self.event_log.push(
            "wait",
            EventKind::WaitRestarted {
                wait,
                class: class.to_string(),
            },
        );
    }

    pub fn wait_handle(&self, id: WaitId) -> Option<WaitHandle> {
        self.waits
            .iter()
            .find(|wait| wait.id == id)
            .map(|wait| WaitHandle::new(wait.id, wait.generation))
    }

    pub fn validate_wait_handle(&mut self, handle: WaitHandle) -> Result<(), GenerationCheckError> {
        let wait = self.waits.iter().find(|wait| wait.id == handle.id);
        let actual = wait.map(|wait| wait.generation);
        let result = match wait {
            None => Err(GenerationCheckError::Missing),
            Some(wait) if wait.generation != handle.generation => {
                Err(GenerationCheckError::GenerationMismatch {
                    expected: handle.generation,
                    actual,
                })
            }
            Some(_) => Ok(()),
        };

        match result {
            Ok(()) => {
                self.event_log.push(
                    "wait",
                    EventKind::WaitTokenValidated {
                        wait: handle.id,
                        generation: handle.generation,
                    },
                );
                Ok(())
            }
            Err(reason) => {
                self.event_log.push(
                    "wait",
                    EventKind::WaitTokenRejected {
                        wait: handle.id,
                        expected: handle.generation,
                        actual,
                        reason,
                    },
                );
                Err(reason)
            }
        }
    }

    pub fn begin_transaction(
        &mut self,
        label: &str,
        store: Option<StoreId>,
        task: Option<TaskId>,
    ) -> TransactionId {
        let id = self.next_transaction_id;
        self.next_transaction_id += 1;
        self.transactions.push(SemanticTransactionRecord {
            id,
            label: label.to_string(),
            store,
            task,
            state: TransactionState::Begun,
            generation: 1,
        });
        self.event_log.push(
            "transaction",
            EventKind::TransactionBegan {
                transaction: id,
                store,
                task,
                label: label.to_string(),
            },
        );
        id
    }

    pub fn commit_transaction(&mut self, id: TransactionId) {
        let Some(transaction) = self
            .transactions
            .iter_mut()
            .find(|transaction| transaction.id == id)
        else {
            return;
        };
        if transaction.state != TransactionState::Begun {
            return;
        }
        transaction.state = TransactionState::Committed;
        transaction.generation += 1;
        self.event_log.push(
            "transaction",
            EventKind::TransactionCommitted {
                transaction: id,
                generation: transaction.generation,
            },
        );
    }

    pub fn rollback_transaction(&mut self, id: TransactionId, reason: &str) {
        let Some(transaction) = self
            .transactions
            .iter_mut()
            .find(|transaction| transaction.id == id)
        else {
            return;
        };
        if transaction.state != TransactionState::Begun {
            return;
        }
        transaction.state = TransactionState::RolledBack;
        transaction.generation += 1;
        self.event_log.push(
            "transaction",
            EventKind::TransactionRolledBack {
                transaction: id,
                reason: reason.to_string(),
                generation: transaction.generation,
            },
        );
    }

    pub fn install_fast_path_plan(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> PlanId {
        let id = self.next_plan_id;
        self.next_plan_id += 1;
        self.fast_path_plans.push(FastPathPlanRecord {
            id,
            subject: subject.to_string(),
            object: object.to_string(),
            operation: operation.to_string(),
            generation: 1,
            valid: true,
        });
        self.event_log
            .push("fastpath", EventKind::FastPathPlanInstalled { plan: id });
        id
    }

    pub fn invalidate_fast_path_plan(&mut self, id: PlanId) {
        let Some(plan) = self.fast_path_plans.iter_mut().find(|plan| plan.id == id) else {
            return;
        };
        if !plan.valid {
            return;
        }
        plan.valid = false;
        plan.generation += 1;
        self.event_log
            .push("fastpath", EventKind::FastPathPlanInvalidated { plan: id });
    }

    pub fn record_failure_effect(&mut self, effect: FailureEffect) {
        self.event_log
            .push("failure", EventKind::FailureEffect { effect });
    }

    pub fn record_snapshot_barrier_enter(&mut self, barrier: SnapshotBarrierId) {
        self.event_log
            .push("snapshot", EventKind::SnapshotBarrierEnter { barrier });
    }

    pub fn record_snapshot_barrier_exit(&mut self, barrier: SnapshotBarrierId) {
        self.event_log
            .push("snapshot", EventKind::SnapshotBarrierExit { barrier });
    }

    pub fn migration_package(
        &self,
        package_id: &str,
        source_host_arch: &str,
        target_host_arch_hint: &str,
        required_artifact_profile: ArtifactProfile,
        guest: GuestStateSnapshot,
        substrate_boundary: SubstrateBoundarySnapshot,
        barrier_id: SnapshotBarrierId,
        dmw_quiescent: bool,
    ) -> MigrationPackage {
        MigrationPackage {
            schema_version: 1,
            package_id: package_id.to_string(),
            source_host_arch: source_host_arch.to_string(),
            target_host_arch_hint: target_host_arch_hint.to_string(),
            required_artifact_profile,
            guest,
            substrate_boundary: substrate_boundary.clone(),
            semantic: SemanticSnapshot {
                barrier: SnapshotBarrierSnapshot {
                    id: barrier_id,
                    event_log_cursor: self.event_log.cursor(),
                    pending_wait_count: self.pending_wait_count(),
                    live_resource_count: self.live_resource_count(),
                    active_transaction_count: self.active_transaction_count(),
                    active_dmw_lease_count: substrate_boundary.active_dmw_lease_count,
                    dmw_quiescent,
                },
                tasks: self.tasks.clone(),
                resources: self.resources.clone(),
                authority_bindings: self.authority_bindings.clone(),
                waits: self.waits.clone(),
                fault_domains: self.fault_domains.clone(),
                stores: self.stores.clone(),
                transactions: self.transactions.clone(),
                fast_path_plans: self.fast_path_plans.clone(),
                boundaries: self.boundaries.clone(),
                artifact_verifications: self.artifact_verifications.clone(),
                store_activations: self.store_activations.clone(),
                capabilities: self.capabilities.records().to_vec(),
            },
        }
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    pub fn wait_count(&self) -> usize {
        self.waits.len()
    }

    pub fn fault_domain_count(&self) -> usize {
        self.fault_domains.len()
    }

    pub fn store_count(&self) -> usize {
        self.stores.len()
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    pub fn fast_path_plan_count(&self) -> usize {
        self.fast_path_plans.len()
    }

    pub fn boundary_count(&self) -> usize {
        self.boundaries.len()
    }

    pub fn artifact_verification_count(&self) -> usize {
        self.artifact_verifications.len()
    }

    pub fn store_activation_count(&self) -> usize {
        self.store_activations.len()
    }

    pub fn active_fast_path_plan_count(&self) -> usize {
        self.fast_path_plans
            .iter()
            .filter(|plan| plan.valid)
            .count()
    }

    pub fn active_transaction_count(&self) -> usize {
        self.transactions
            .iter()
            .filter(|transaction| transaction.state == TransactionState::Begun)
            .count()
    }

    pub fn capability_count(&self) -> usize {
        self.capabilities.active_count()
    }

    pub fn event_count(&self) -> usize {
        self.event_log.len()
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

    pub fn pending_wait_count(&self) -> usize {
        self.waits
            .iter()
            .filter(|wait| wait.state == WaitState::Pending)
            .count()
    }

    pub fn live_resource_count(&self) -> usize {
        self.resources
            .iter()
            .filter(|resource| resource.live)
            .count()
    }

    pub fn authority_count(&self) -> usize {
        self.authority_bindings.len()
    }

    pub fn active_authority_count(&self) -> usize {
        self.authority_bindings
            .iter()
            .filter(|authority| authority.state == AuthorityState::Bound)
            .count()
    }

    pub fn capabilities(&self) -> &CapabilityLedger {
        &self.capabilities
    }

    pub fn authority_bindings(&self) -> &[AuthorityBindingRecord] {
        &self.authority_bindings
    }

    pub fn event_log(&self) -> &EventLog {
        &self.event_log
    }

    pub fn stores(&self) -> &[StoreRecord] {
        &self.stores
    }

    pub fn transactions(&self) -> &[SemanticTransactionRecord] {
        &self.transactions
    }

    pub fn fast_path_plans(&self) -> &[FastPathPlanRecord] {
        &self.fast_path_plans
    }

    pub fn boundaries(&self) -> &[BoundaryRecord] {
        &self.boundaries
    }

    pub fn artifact_verifications(&self) -> &[ArtifactVerificationRecord] {
        &self.artifact_verifications
    }

    pub fn artifact_verification_for_package(
        &self,
        package: &str,
    ) -> Option<&ArtifactVerificationRecord> {
        self.artifact_verifications
            .iter()
            .find(|record| record.package == package)
    }

    pub fn store_activations(&self) -> &[StoreActivationRecord] {
        &self.store_activations
    }

    pub fn store_activation_handle(&self, store: StoreId) -> Option<StoreActivationHandle> {
        self.store_activations
            .iter()
            .find(|record| record.store == store)
            .map(|record| StoreActivationHandle::new(record.store, record.generation))
    }

    pub fn validate_store_activation_handle(
        &mut self,
        handle: StoreActivationHandle,
    ) -> Result<(), GenerationCheckError> {
        let activation = self
            .store_activations
            .iter()
            .find(|record| record.store == handle.store);
        let actual = activation.map(|record| record.generation);
        let result = match activation {
            None => Err(GenerationCheckError::Missing),
            Some(record) if record.generation != handle.generation => {
                Err(GenerationCheckError::GenerationMismatch {
                    expected: handle.generation,
                    actual,
                })
            }
            Some(_) => Ok(()),
        };

        match result {
            Ok(()) => {
                self.event_log.push(
                    "activation",
                    EventKind::StoreActivationHandleValidated {
                        store: handle.store,
                        generation: handle.generation,
                    },
                );
                Ok(())
            }
            Err(reason) => {
                self.event_log.push(
                    "activation",
                    EventKind::StoreActivationHandleRejected {
                        store: handle.store,
                        expected: handle.generation,
                        actual,
                        reason,
                    },
                );
                Err(reason)
            }
        }
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

impl Default for SemanticGraph {
    fn default() -> Self {
        Self::new()
    }
}
