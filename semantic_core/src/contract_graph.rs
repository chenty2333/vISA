use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractViolationKind {
    DanglingEdge,
    GenerationMismatch,
    LiveObjectReferencesDeadObject,
    TombstoneReferencedByLiveEdge,
}

impl ContractViolationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DanglingEdge => "dangling-edge",
            Self::GenerationMismatch => "generation-mismatch",
            Self::LiveObjectReferencesDeadObject => "live-object-references-dead-object",
            Self::TombstoneReferencedByLiveEdge => "tombstone-referenced-by-live-edge",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractViolation {
    pub kind: ContractViolationKind,
    pub edge: String,
    pub from: ContractObjectRef,
    pub to: Option<ContractObjectRef>,
    pub detail: String,
}

impl ContractViolation {
    pub fn new(
        kind: ContractViolationKind,
        edge: &str,
        from: ContractObjectRef,
        to: Option<ContractObjectRef>,
        detail: &str,
    ) -> Self {
        Self {
            kind,
            edge: edge.to_string(),
            from,
            to,
            detail: detail.to_string(),
        }
    }

    pub fn summary(&self) -> String {
        let to = self
            .to
            .map(ContractObjectRef::summary)
            .unwrap_or_else(|| "none".to_string());
        format!(
            "contract-violation kind={} edge={} from={} to={} detail={}",
            self.kind.as_str(),
            self.edge,
            self.from.summary(),
            to,
            self.detail
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct ContractGraphSnapshot {
    pub artifacts: Vec<VerifiedArtifact>,
    pub code_objects: Vec<CodeObject>,
    pub stores: Vec<StoreRecord>,
    pub activations: Vec<ActivationRecord>,
    pub traps: Vec<TargetTrapRecord>,
    pub hostcalls: Vec<HostcallTraceRecord>,
    pub capabilities: Vec<CapabilityRecord>,
    pub waits: Vec<WaitRecord>,
    pub tombstones: Vec<TombstoneRecord>,
}

pub fn validate_contract_graph(snapshot: &ContractGraphSnapshot) -> Vec<ContractViolation> {
    ContractGraphValidator::validate(snapshot)
}

pub struct ContractGraphValidator;

impl ContractGraphValidator {
    pub fn validate(snapshot: &ContractGraphSnapshot) -> Vec<ContractViolation> {
        let mut violations = Vec::new();
        Self::validate_code_objects(snapshot, &mut violations);
        Self::validate_activations(snapshot, &mut violations);
        Self::validate_traps(snapshot, &mut violations);
        Self::validate_hostcalls(snapshot, &mut violations);
        Self::validate_capabilities(snapshot, &mut violations);
        Self::validate_waits(snapshot, &mut violations);
        violations
    }

    fn validate_code_objects(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for code in &snapshot.code_objects {
            let from = code.object_ref();
            if snapshot
                .artifacts
                .iter()
                .all(|artifact| artifact.artifact_id != code.artifact_id)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "code->artifact",
                    from,
                    Some(ContractObjectRef::new(
                        ContractObjectKind::Artifact,
                        code.artifact_id,
                        0,
                    )),
                    "code object references missing artifact",
                ));
            }
            if let Some(store_id) = code.bound_store {
                match snapshot.stores.iter().find(|store| store.id == store_id) {
                    Some(store) if store.state == StoreState::Dead => {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "code->store",
                            from,
                            Some(store.object_ref()),
                            "bound code object references a dead store",
                        ));
                    }
                    Some(_) => {}
                    None => violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        "code->store",
                        from,
                        Some(ContractObjectRef::new(
                            ContractObjectKind::Store,
                            store_id,
                            0,
                        )),
                        "bound code object references missing store",
                    )),
                }
            }
        }
    }

    fn validate_activations(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for activation in &snapshot.activations {
            let from = activation.object_ref();
            match snapshot
                .stores
                .iter()
                .find(|store| store.id == activation.store)
            {
                Some(store) => {
                    if store.generation != activation.store_generation {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "activation->store",
                            from,
                            Some(store.object_ref()),
                            "activation store generation is stale",
                        ));
                    }
                    if Self::is_live_activation(activation) && store.state == StoreState::Dead {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "activation->store",
                            from,
                            Some(store.object_ref()),
                            "live activation references a dead store",
                        ));
                    }
                    Self::check_tombstone_live_edge(
                        snapshot,
                        violations,
                        from,
                        "activation->store",
                        store.object_ref(),
                        Self::is_live_activation(activation),
                    );
                }
                None => violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "activation->store",
                    from,
                    Some(ContractObjectRef::new(
                        ContractObjectKind::Store,
                        activation.store,
                        activation.store_generation,
                    )),
                    "activation references missing store",
                )),
            }
            match snapshot
                .code_objects
                .iter()
                .find(|code| code.id == activation.code_object)
            {
                Some(code) => {
                    if code.generation != activation.code_generation {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "activation->code",
                            from,
                            Some(code.object_ref()),
                            "activation code generation is stale",
                        ));
                    }
                    if Self::is_live_activation(activation)
                        && matches!(
                            code.state,
                            CodeObjectState::Faulted
                                | CodeObjectState::Retired
                                | CodeObjectState::Unpublished
                        )
                    {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "activation->code",
                            from,
                            Some(code.object_ref()),
                            "live activation references non-runnable code",
                        ));
                    }
                    Self::check_tombstone_live_edge(
                        snapshot,
                        violations,
                        from,
                        "activation->code",
                        code.object_ref(),
                        Self::is_live_activation(activation),
                    );
                }
                None => violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "activation->code",
                    from,
                    Some(ContractObjectRef::new(
                        ContractObjectKind::CodeObject,
                        activation.code_object,
                        activation.code_generation,
                    )),
                    "activation references missing code object",
                )),
            }
        }
    }

    fn validate_traps(snapshot: &ContractGraphSnapshot, violations: &mut Vec<ContractViolation>) {
        for trap in &snapshot.traps {
            let from = trap.object_ref();
            if let Some(activation_id) = trap.activation {
                if snapshot
                    .activations
                    .iter()
                    .all(|activation| activation.id != activation_id)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        "trap->activation",
                        from,
                        Some(ContractObjectRef::new(
                            ContractObjectKind::Activation,
                            activation_id,
                            0,
                        )),
                        "trap references missing activation",
                    ));
                }
            }
            if let Some(code_id) = trap.code_object {
                if snapshot.code_objects.iter().all(|code| code.id != code_id)
                    && !snapshot.tombstones.iter().any(|tombstone| {
                        tombstone.kind == ContractObjectKind::CodeObject && tombstone.id == code_id
                    })
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        "trap->code",
                        from,
                        Some(ContractObjectRef::new(
                            ContractObjectKind::CodeObject,
                            code_id,
                            0,
                        )),
                        "trap references missing code object",
                    ));
                }
            }
        }
    }

    fn validate_hostcalls(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for hostcall in &snapshot.hostcalls {
            let from = hostcall.object_ref();
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "hostcall->activation",
                ContractObjectKind::Activation,
                hostcall.activation,
                hostcall.activation_generation,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "hostcall->store",
                ContractObjectKind::Store,
                hostcall.store,
                hostcall.store_generation,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "hostcall->code",
                ContractObjectKind::CodeObject,
                hostcall.code_object,
                hostcall.code_generation,
            );
        }
    }

    fn validate_capabilities(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for capability in &snapshot.capabilities {
            if let Some(store_id) = capability.owner_store {
                let from = capability.object_ref();
                match snapshot.stores.iter().find(|store| store.id == store_id) {
                    Some(store) if store.state == StoreState::Dead && !capability.revoked => {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "capability->owner-store",
                            from,
                            Some(store.object_ref()),
                            "active capability is owned by a dead store",
                        ));
                    }
                    Some(_) => {}
                    None => violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        "capability->owner-store",
                        from,
                        Some(ContractObjectRef::new(
                            ContractObjectKind::Store,
                            store_id,
                            0,
                        )),
                        "capability references missing owner store",
                    )),
                }
            }
        }
    }

    fn validate_waits(snapshot: &ContractGraphSnapshot, violations: &mut Vec<ContractViolation>) {
        for wait in &snapshot.waits {
            if snapshot.stores.iter().any(|store| {
                store.id == u64::from(wait.owner_task) && store.state == StoreState::Dead
            }) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::LiveObjectReferencesDeadObject,
                    "wait->owner-task",
                    wait.object_ref(),
                    None,
                    "wait token owner task maps to a dead store id in this harness",
                ));
            }
        }
    }

    fn check_generation_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        from: ContractObjectRef,
        edge: &str,
        kind: ContractObjectKind,
        id: u64,
        generation: Generation,
    ) {
        let target = match kind {
            ContractObjectKind::Activation => snapshot
                .activations
                .iter()
                .find(|activation| activation.id == id)
                .map(ActivationRecord::object_ref),
            ContractObjectKind::Store => snapshot
                .stores
                .iter()
                .find(|store| store.id == id)
                .map(StoreRecord::object_ref),
            ContractObjectKind::CodeObject => snapshot
                .code_objects
                .iter()
                .find(|code| code.id == id)
                .map(CodeObject::object_ref),
            _ => None,
        };
        match target {
            Some(target) if target.generation != generation => {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    edge,
                    from,
                    Some(target),
                    "edge generation does not match target object",
                ))
            }
            Some(target) => {
                Self::check_tombstone_live_edge(snapshot, violations, from, edge, target, true)
            }
            None => violations.push(ContractViolation::new(
                ContractViolationKind::DanglingEdge,
                edge,
                from,
                Some(ContractObjectRef::new(kind, id, generation)),
                "edge references missing target",
            )),
        }
    }

    fn check_tombstone_live_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        from: ContractObjectRef,
        edge: &str,
        to: ContractObjectRef,
        live_edge: bool,
    ) {
        if !live_edge {
            return;
        }
        if snapshot
            .tombstones
            .iter()
            .any(|tombstone| tombstone.object_ref() == to)
        {
            violations.push(ContractViolation::new(
                ContractViolationKind::TombstoneReferencedByLiveEdge,
                edge,
                from,
                Some(to),
                "live edge references a tombstoned generation",
            ));
        }
    }

    fn is_live_activation(activation: &ActivationRecord) -> bool {
        matches!(
            activation.state,
            ActivationState::Running | ActivationState::Pending
        )
    }
}

impl VerifiedArtifact {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::Artifact,
            self.artifact_id,
            self.generation,
        )
    }
}

impl CodeObject {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::CodeObject, self.id, self.generation)
    }
}

impl StoreRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Store, self.id, self.generation)
    }
}

impl ActivationRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Activation, self.id, self.generation)
    }
}

impl TargetTrapRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Trap, self.id, self.generation)
    }
}

impl HostcallTraceRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Hostcall, self.id, self.generation)
    }
}

impl CapabilityRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Capability, self.id, self.generation)
    }
}

impl WaitRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::WaitToken, self.id, self.generation)
    }
}
