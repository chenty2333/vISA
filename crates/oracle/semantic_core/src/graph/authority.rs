use super::*;

impl SemanticGraph {
    pub fn bind_authority_resource(
        &mut self,
        resource: ResourceId,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> Option<AuthorityId> {
        let (kind, resource_generation) = {
            let resource = self
                .domains
                .resource
                .resources
                .iter()
                .find(|candidate| candidate.id == resource && candidate.live)?;
            (AuthorityKind::from_resource_kind(resource.kind)?, resource.generation)
        };
        let id = self.domains.resource.next_authority_id;
        self.domains.resource.next_authority_id += 1;
        let class = CapabilityClass::from_object(object);
        let authority_object_ref = AuthorityObjectRef::internal(
            class,
            ContractObjectRef::new(ContractObjectKind::Resource, resource, resource_generation),
        );
        let capability = self.grant_capability_with_authority_ref(
            subject,
            object,
            authority_object_ref,
            operations,
            lifetime,
            "authority-binding",
            true,
        );
        let capability_generation = self
            .domains
            .capability
            .capabilities
            .record(capability)
            .map(|record| record.generation)
            .unwrap_or(0);
        self.domains.resource.authority_bindings.push(AuthorityBindingRecord {
            id,
            resource,
            kind,
            subject: subject.to_string(),
            object: object.to_string(),
            object_ref: authority_object_ref,
            capability,
            capability_generation,
            operations: OperationSet::from_static(operations),
            lifetime: lifetime.to_string(),
            generation: 1,
            state: AuthorityState::Bound,
        });
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
            .domains
            .resource
            .authority_bindings
            .iter()
            .position(|authority| authority.id == id)
        else {
            return false;
        };
        if self.domains.resource.authority_bindings[index].state != AuthorityState::Bound {
            return false;
        }
        self.domains.resource.authority_bindings[index].state = AuthorityState::Released;
        self.domains.resource.authority_bindings[index].generation += 1;
        let resource = self.domains.resource.authority_bindings[index].resource;
        let generation = self.domains.resource.authority_bindings[index].generation;
        let capability = self.domains.resource.authority_bindings[index].capability;
        let capability_generation =
            self.domains.resource.authority_bindings[index].capability_generation;
        self.domains.capability.capabilities.revoke_generation(capability, capability_generation);
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
            .domains
            .resource
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
            .domains
            .resource
            .authority_bindings
            .iter()
            .position(|authority| authority.id == id)
        else {
            return false;
        };
        if self.domains.resource.authority_bindings[index].state != AuthorityState::Bound {
            return false;
        }
        self.domains.resource.authority_bindings[index].state = AuthorityState::Revoked;
        self.domains.resource.authority_bindings[index].generation += 1;
        let resource = self.domains.resource.authority_bindings[index].resource;
        let generation = self.domains.resource.authority_bindings[index].generation;
        let capability = self.domains.resource.authority_bindings[index].capability;
        let capability_generation =
            self.domains.resource.authority_bindings[index].capability_generation;
        self.domains.capability.capabilities.revoke_generation(capability, capability_generation);
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
    pub fn authority_bindings(&self) -> &[AuthorityBindingRecord] {
        &self.domains.resource.authority_bindings
    }
    pub fn authority_count(&self) -> usize {
        self.domains.resource.authority_bindings.len()
    }
    pub fn active_authority_count(&self) -> usize {
        self.domains
            .resource
            .authority_bindings
            .iter()
            .filter(|authority| authority.state == AuthorityState::Bound)
            .count()
    }
}
