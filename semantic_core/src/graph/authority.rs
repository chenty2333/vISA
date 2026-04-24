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
    pub fn authority_bindings(&self) -> &[AuthorityBindingRecord] {
        &self.authority_bindings
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
}
