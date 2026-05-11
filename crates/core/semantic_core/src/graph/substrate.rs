use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub fn record_substrate_authority_extracted(
        &mut self,
        authority: impl Into<String>,
        operation: impl Into<String>,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
        capability: Option<CapabilityId>,
        capability_generation: Option<Generation>,
    ) -> EventId {
        self.event_log.push(
            "substrate",
            EventKind::SubstrateAuthorityExtracted {
                authority: authority.into(),
                operation: operation.into(),
                requester,
                artifact,
                store,
                capability,
                capability_generation,
            },
        )
    }

    pub fn record_substrate_unsupported(
        &mut self,
        authority: impl Into<String>,
        operation: impl Into<String>,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
    ) -> EventId {
        self.event_log.push(
            "substrate",
            EventKind::SubstrateUnsupported {
                authority: authority.into(),
                operation: operation.into(),
                requester,
                artifact,
                store,
            },
        )
    }

    pub fn record_substrate_capability_denied(
        &mut self,
        authority: impl Into<String>,
        operation: impl Into<String>,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
        capability: Option<CapabilityId>,
        capability_generation: Option<Generation>,
    ) -> EventId {
        self.event_log.push(
            "substrate",
            EventKind::SubstrateCapabilityDenied {
                authority: authority.into(),
                operation: operation.into(),
                requester,
                artifact,
                store,
                capability,
                capability_generation,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_substrate_panic(
        &mut self,
        authority: impl Into<String>,
        operation: impl Into<String>,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
        panic_epoch: u64,
        panic_cpu: u32,
        panic_reason_code: u32,
    ) -> EventId {
        self.event_log.push(
            "substrate",
            EventKind::SubstratePanic {
                authority: authority.into(),
                operation: operation.into(),
                requester,
                artifact,
                store,
                panic_epoch,
                panic_cpu,
                panic_reason_code,
            },
        )
    }
}
