use super::*;

impl SemanticGraph {
    pub fn record_interface_unsupported(
        &mut self,
        interface_kind: impl Into<String>,
        interface: impl Into<String>,
        operation: impl Into<String>,
        requester: Option<String>,
        artifact: Option<ArtifactId>,
        store: Option<StoreId>,
    ) -> EventId {
        self.event_log.push(
            "interface",
            EventKind::InterfaceUnsupported {
                interface_kind: interface_kind.into(),
                interface: interface.into(),
                operation: operation.into(),
                requester,
                artifact,
                store,
            },
        )
    }
}
