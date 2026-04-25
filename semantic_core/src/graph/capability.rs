use super::*;

impl SemanticGraph {
    pub fn grant_capability(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> CapabilityId {
        self.grant_manifest_capability_with_source(
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
        self.grant_manifest_capability_with_source(
            subject,
            object,
            operations,
            lifetime,
            CapabilityClass::from_object(object),
            "artifact-manifest",
        )
    }
    pub fn grant_manifest_capability_with_source(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
        class: CapabilityClass,
        source: &str,
    ) -> CapabilityId {
        let owner_store = self.store_id(subject);
        let owner_store_generation = owner_store.and_then(|store_id| {
            self.stores
                .iter()
                .find(|store| store.id == store_id)
                .map(|store| store.generation)
        });
        let cap = self.capabilities.grant_manifest_binding(
            subject,
            object,
            operations,
            lifetime,
            class,
            owner_store,
            owner_store_generation,
            None,
            source,
        );
        self.event_log
            .push("capability", EventKind::CapabilityGranted { cap });
        cap
    }
    pub fn grant_capability_with_authority_ref(
        &mut self,
        subject: &str,
        debug_object_label: &str,
        object_ref: AuthorityObjectRef,
        operations: &[&str],
        lifetime: &str,
        source: &str,
        manifest_decl: bool,
    ) -> CapabilityId {
        let owner_store = self.store_id(subject);
        let owner_store_generation = owner_store.and_then(|store_id| {
            self.stores
                .iter()
                .find(|store| store.id == store_id)
                .map(|store| store.generation)
        });
        let cap = self.capabilities.grant_with_authority_ref(
            subject,
            debug_object_label,
            object_ref,
            operations,
            lifetime,
            owner_store,
            owner_store_generation,
            None,
            source,
            manifest_decl,
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
    pub fn capability_count(&self) -> usize {
        self.capabilities.active_count()
    }
    pub fn capabilities(&self) -> &CapabilityLedger {
        &self.capabilities
    }
}
