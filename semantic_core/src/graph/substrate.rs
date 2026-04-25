use super::*;

impl SemanticGraph {
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
}
