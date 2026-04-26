use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractViolationKind {
    DanglingEdge,
    GenerationMismatch,
    LiveObjectReferencesDeadObject,
    LiveEdgeReferencesInactiveObject,
    TombstoneReferencedByLiveEdge,
    HistoricalEdgeMissingGeneration,
    CleanupEffectCreatesLiveOwnership,
    ExternalEdgeMissingDeclaration,
    ExternalEdgeMetadataMismatch,
}

impl ContractViolationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DanglingEdge => "dangling-edge",
            Self::GenerationMismatch => "generation-mismatch",
            Self::LiveObjectReferencesDeadObject => "live-object-references-dead-object",
            Self::LiveEdgeReferencesInactiveObject => "live-edge-references-inactive-object",
            Self::TombstoneReferencedByLiveEdge => "tombstone-referenced-by-live-edge",
            Self::HistoricalEdgeMissingGeneration => "historical-edge-missing-generation",
            Self::CleanupEffectCreatesLiveOwnership => "cleanup-effect-creates-live-ownership",
            Self::ExternalEdgeMissingDeclaration => "external-edge-missing-declaration",
            Self::ExternalEdgeMetadataMismatch => "external-edge-metadata-mismatch",
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
    pub cleanup_transactions: Vec<FaultCleanupTransaction>,
    pub tombstones: Vec<TombstoneRecord>,
    pub external_objects: Vec<ExternalObjectDeclaration>,
    pub explicit_edges: Vec<ContractEdgeRecord>,
}

pub fn validate_contract_graph(snapshot: &ContractGraphSnapshot) -> Vec<ContractViolation> {
    ContractGraphValidator::validate(snapshot)
}

pub struct ContractGraphValidator;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractEdgeMode {
    Live,
    Historical,
    CleanupEffect,
    External,
}

impl ContractEdgeMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Historical => "historical",
            Self::CleanupEffect => "cleanup-effect",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalObjectDeclaration {
    pub object: ContractObjectRef,
    pub provider: String,
    pub class: String,
    pub debug_label: String,
}

impl ExternalObjectDeclaration {
    pub fn new(object: ContractObjectRef, provider: &str, class: &str, debug_label: &str) -> Self {
        Self {
            object,
            provider: provider.to_string(),
            class: class.to_string(),
            debug_label: debug_label.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractEdgeRecord {
    pub from: ContractObjectRef,
    pub to: ContractObjectRef,
    pub mode: ContractEdgeMode,
    pub label: String,
    pub epoch: EventId,
    pub provider: Option<String>,
    pub class: Option<String>,
}

impl ContractEdgeRecord {
    pub fn new(
        from: ContractObjectRef,
        to: ContractObjectRef,
        mode: ContractEdgeMode,
        label: &str,
        epoch: EventId,
    ) -> Self {
        Self {
            from,
            to,
            mode,
            label: label.to_string(),
            epoch,
            provider: None,
            class: None,
        }
    }

    pub fn with_external_metadata(mut self, provider: &str, class: &str) -> Self {
        self.provider = Some(provider.to_string());
        self.class = Some(class.to_string());
        self
    }
}

impl ContractGraphValidator {
    pub fn validate(snapshot: &ContractGraphSnapshot) -> Vec<ContractViolation> {
        let mut violations = Vec::new();
        Self::validate_code_objects(snapshot, &mut violations);
        Self::validate_activations(snapshot, &mut violations);
        Self::validate_traps(snapshot, &mut violations);
        Self::validate_hostcalls(snapshot, &mut violations);
        Self::validate_capabilities(snapshot, &mut violations);
        Self::validate_waits(snapshot, &mut violations);
        Self::validate_cleanups(snapshot, &mut violations);
        Self::validate_explicit_edges(snapshot, &mut violations);
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
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "code->store",
                    ContractObjectKind::Store,
                    store_id,
                    code.bound_store_generation.unwrap_or(0),
                    ContractEdgeMode::Live,
                );
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
                    if store.state == StoreState::Dead && activation.active_dmw_leases != 0 {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "activation->dmw-lease",
                            from,
                            Some(store.object_ref()),
                            "dead store still has active DMW lease through activation",
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
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "trap->activation",
                    ContractObjectKind::Activation,
                    activation_id,
                    trap.activation_generation.unwrap_or(0),
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(store_id) = trap.store {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "trap->store",
                    ContractObjectKind::Store,
                    store_id,
                    trap.store_generation.unwrap_or(0),
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(code_id) = trap.code_object {
                match snapshot.code_objects.iter().find(|code| code.id == code_id) {
                    Some(code) => {
                        if let Some(generation) = trap.code_generation {
                            if code.generation != generation {
                                violations.push(ContractViolation::new(
                                    ContractViolationKind::GenerationMismatch,
                                    "trap->code",
                                    from,
                                    Some(code.object_ref()),
                                    "trap code generation is stale",
                                ));
                            }
                        }
                        if let Some(artifact) = trap.artifact {
                            if code.artifact_id != artifact {
                                violations.push(ContractViolation::new(
                                    ContractViolationKind::GenerationMismatch,
                                    "trap->artifact",
                                    from,
                                    Some(ContractObjectRef::new(
                                        ContractObjectKind::Artifact,
                                        artifact,
                                        trap.artifact_generation.unwrap_or(0),
                                    )),
                                    "trap artifact does not match code artifact",
                                ));
                            }
                        }
                    }
                    None => {
                        let generation = trap.code_generation.unwrap_or(0);
                        if !snapshot.tombstones.iter().any(|tombstone| {
                            tombstone.kind == ContractObjectKind::CodeObject
                                && tombstone.id == code_id
                                && (generation == 0 || tombstone.generation == generation)
                        }) {
                            violations.push(ContractViolation::new(
                                ContractViolationKind::DanglingEdge,
                                "trap->code",
                                from,
                                Some(ContractObjectRef::new(
                                    ContractObjectKind::CodeObject,
                                    code_id,
                                    generation,
                                )),
                                "trap references missing code object",
                            ));
                        }
                    }
                }
            }
            if let Some(artifact_id) = trap.artifact {
                match snapshot
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.artifact_id == artifact_id)
                {
                    Some(artifact) => {
                        if let Some(generation) = trap.artifact_generation {
                            if artifact.generation != generation {
                                violations.push(ContractViolation::new(
                                    ContractViolationKind::GenerationMismatch,
                                    "trap->artifact",
                                    from,
                                    Some(artifact.object_ref()),
                                    "trap artifact generation is stale",
                                ));
                            }
                        }
                    }
                    None => violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        "trap->artifact",
                        from,
                        Some(ContractObjectRef::new(
                            ContractObjectKind::Artifact,
                            artifact_id,
                            trap.artifact_generation.unwrap_or(0),
                        )),
                        "trap references missing artifact",
                    )),
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
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "hostcall->store",
                ContractObjectKind::Store,
                hostcall.store,
                hostcall.store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "hostcall->code",
                ContractObjectKind::CodeObject,
                hostcall.code_object,
                hostcall.code_generation,
                ContractEdgeMode::Historical,
            );
        }
    }

    fn validate_capabilities(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for capability in &snapshot.capabilities {
            let from = capability.object_ref();
            if let Some(store_id) = capability.owner_store {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "capability->owner-store",
                    ContractObjectKind::Store,
                    store_id,
                    capability.owner_store_generation.unwrap_or(0),
                    if capability.revoked {
                        ContractEdgeMode::Historical
                    } else {
                        ContractEdgeMode::Live
                    },
                );
            }
            match capability.object_ref {
                Some(object_ref) => Self::check_authority_object_edge(
                    snapshot,
                    violations,
                    from,
                    "capability->object",
                    object_ref,
                    if capability.revoked {
                        ContractEdgeMode::Historical
                    } else {
                        ContractEdgeMode::Live
                    },
                ),
                None if !capability.revoked => violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "capability->object",
                    from,
                    None,
                    "active capability is missing authority object ref",
                )),
                None => {}
            }
        }
    }

    fn validate_waits(snapshot: &ContractGraphSnapshot, violations: &mut Vec<ContractViolation>) {
        for wait in &snapshot.waits {
            let from = wait.object_ref();
            if wait.state == WaitState::Pending
                && wait.owner_task.is_none()
                && wait.owner_store.is_none()
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "wait->owner",
                    from,
                    None,
                    "pending wait has no owner task or owner store",
                ));
            }
            if wait.state == WaitState::Pending
                && wait.blockers.is_empty()
                && wait.deadline.is_none()
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "wait->blocker",
                    from,
                    None,
                    "pending wait has no blocker or deadline",
                ));
            }
            if wait.state == WaitState::Pending {
                if wait.owner_task.is_some() && wait.owner_task_generation.is_none() {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::HistoricalEdgeMissingGeneration,
                        "wait->owner-task",
                        from,
                        None,
                        "pending wait owner task is missing generation",
                    ));
                }
                if let Some(owner_store) = wait.owner_store {
                    Self::check_generation_edge(
                        snapshot,
                        violations,
                        from,
                        "wait->owner-store",
                        ContractObjectKind::Store,
                        owner_store,
                        wait.owner_store_generation.unwrap_or(0),
                        ContractEdgeMode::Live,
                    );
                }
                for blocker in &wait.blockers {
                    Self::check_contract_ref_edge(
                        snapshot,
                        violations,
                        from,
                        "wait->blocker",
                        *blocker,
                        ContractEdgeMode::Live,
                        None,
                    );
                }
            }
        }
    }

    fn validate_cleanups(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for cleanup in &snapshot.cleanup_transactions {
            let from = cleanup.object_ref();
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "cleanup->store",
                ContractObjectKind::Store,
                cleanup.store,
                cleanup.store_generation,
                ContractEdgeMode::Historical,
            );
            let current_store = snapshot
                .stores
                .iter()
                .find(|store| store.id == cleanup.store);
            if cleanup.state == CleanupTransactionState::Completed {
                match cleanup.result_store_generation {
                    Some(generation) => {
                        let result_ref = ContractObjectRef::new(
                            ContractObjectKind::Store,
                            cleanup.store,
                            generation,
                        );
                        match current_store {
                            Some(store) if generation == store.generation => {
                                if store.state != StoreState::Dead {
                                    violations.push(ContractViolation::new(
                                        ContractViolationKind::LiveObjectReferencesDeadObject,
                                        "cleanup->result-store",
                                        from,
                                        Some(store.object_ref()),
                                        "completed cleanup result points to a live current store",
                                    ));
                                }
                            }
                            _ if Self::has_tombstone(snapshot, result_ref) => {}
                            Some(store) => violations.push(ContractViolation::new(
                                ContractViolationKind::GenerationMismatch,
                                "cleanup->result-store",
                                from,
                                Some(store.object_ref()),
                                "completed cleanup result store generation is neither current nor tombstoned",
                            )),
                            None => violations.push(ContractViolation::new(
                                ContractViolationKind::DanglingEdge,
                                "cleanup->result-store",
                                from,
                                Some(result_ref),
                                "completed cleanup result store generation has no current object or tombstone",
                            )),
                        }
                    }
                    None => violations.push(ContractViolation::new(
                        ContractViolationKind::HistoricalEdgeMissingGeneration,
                        "cleanup->result-store",
                        from,
                        current_store.map(StoreRecord::object_ref),
                        "completed cleanup is missing result store generation",
                    )),
                }
            }
            if let Some(activation_id) = cleanup.activation {
                match cleanup.activation_generation {
                    Some(generation) => Self::check_generation_edge(
                        snapshot,
                        violations,
                        from,
                        "cleanup->activation",
                        ContractObjectKind::Activation,
                        activation_id,
                        generation,
                        ContractEdgeMode::Historical,
                    ),
                    None => {
                        if snapshot
                            .activations
                            .iter()
                            .all(|activation| activation.id != activation_id)
                        {
                            violations.push(ContractViolation::new(
                                ContractViolationKind::DanglingEdge,
                                "cleanup->activation",
                                from,
                                Some(ContractObjectRef::new(
                                    ContractObjectKind::Activation,
                                    activation_id,
                                    0,
                                )),
                                "cleanup references missing activation",
                            ));
                        }
                    }
                }
            }
            if let Some(code_id) = cleanup.code_object {
                if let Some(generation) = cleanup.code_generation {
                    Self::check_generation_edge(
                        snapshot,
                        violations,
                        from,
                        "cleanup->code",
                        ContractObjectKind::CodeObject,
                        code_id,
                        generation,
                        ContractEdgeMode::Historical,
                    );
                }
                match snapshot.code_objects.iter().find(|code| code.id == code_id) {
                    Some(code) => {
                        if cleanup.state == CleanupTransactionState::Completed {
                            if code.bound_store == Some(cleanup.store)
                                && code.bound_store_generation == Some(cleanup.store_generation)
                            {
                                violations.push(ContractViolation::new(
                                    ContractViolationKind::LiveObjectReferencesDeadObject,
                                    "cleanup->code",
                                    from,
                                    Some(code.object_ref()),
                                    "completed cleanup left code object bound to store",
                                ));
                            }
                            if cleanup.unbound_code_object
                                && !matches!(
                                    code.state,
                                    CodeObjectState::Retired
                                        | CodeObjectState::Unpublished
                                        | CodeObjectState::Faulted
                                )
                            {
                                violations.push(ContractViolation::new(
                                    ContractViolationKind::LiveObjectReferencesDeadObject,
                                    "cleanup->code",
                                    from,
                                    Some(code.object_ref()),
                                    "completed cleanup did not retire or unpublish code object",
                                ));
                            }
                        }
                    }
                    None => violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        "cleanup->code",
                        from,
                        Some(ContractObjectRef::new(
                            ContractObjectKind::CodeObject,
                            code_id,
                            0,
                        )),
                        "cleanup references missing code object",
                    )),
                }
            }
            for capability_ref in &cleanup.revoked_capability_refs {
                match snapshot
                    .capabilities
                    .iter()
                    .find(|capability| capability.id == capability_ref.id)
                {
                    Some(capability) if capability.generation != capability_ref.generation => {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "cleanup->capability",
                            from,
                            Some(capability.object_ref()),
                            "cleanup capability generation is stale",
                        ));
                    }
                    Some(capability) => {
                        if cleanup.state == CleanupTransactionState::Completed
                            && !capability.revoked
                        {
                            violations.push(ContractViolation::new(
                                ContractViolationKind::LiveObjectReferencesDeadObject,
                                "cleanup->capability",
                                from,
                                Some(capability.object_ref()),
                                "completed cleanup listed an active capability as revoked",
                            ));
                        }
                    }
                    None => violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        "cleanup->capability",
                        from,
                        Some(*capability_ref),
                        "cleanup references missing capability",
                    )),
                }
            }
            if cleanup.revoked_capability_refs.is_empty() {
                for capability_id in &cleanup.revoked_capabilities {
                    match snapshot
                        .capabilities
                        .iter()
                        .find(|capability| capability.id == *capability_id)
                    {
                        Some(capability) if cleanup.state == CleanupTransactionState::Completed => {
                            if !capability.revoked {
                                violations.push(ContractViolation::new(
                                    ContractViolationKind::LiveObjectReferencesDeadObject,
                                    "cleanup->capability",
                                    from,
                                    Some(capability.object_ref()),
                                    "completed cleanup listed an active capability as revoked",
                                ));
                            }
                        }
                        Some(_) => {}
                        None => violations.push(ContractViolation::new(
                            ContractViolationKind::DanglingEdge,
                            "cleanup->capability",
                            from,
                            Some(ContractObjectRef::new(
                                ContractObjectKind::Capability,
                                *capability_id,
                                0,
                            )),
                            "cleanup references missing capability",
                        )),
                    }
                }
            }
            Self::validate_cleanup_effects(snapshot, violations, cleanup);
        }
    }

    fn validate_cleanup_effects(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        cleanup: &FaultCleanupTransaction,
    ) {
        let from = cleanup.object_ref();
        for effect in &cleanup.effects {
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "cleanup->effect-target",
                effect.target.kind,
                effect.target.id,
                effect.expected_generation,
                ContractEdgeMode::CleanupEffect,
            );
            if effect.status != CleanupEffectStatus::Applied {
                continue;
            }
            match effect.kind {
                CleanupEffectKind::MarkStoreDead => {
                    match snapshot.stores.iter().find(|store| {
                        store.id == effect.target.id
                            && store.generation == effect.expected_generation
                    }) {
                        Some(store) if store.state == StoreState::Dead => {}
                        Some(store) => violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "cleanup->effect-target",
                            from,
                            Some(store.object_ref()),
                            "mark-store-dead effect target is not dead",
                        )),
                        None => {}
                    }
                }
                CleanupEffectKind::RevokeCapability => {
                    match snapshot.capabilities.iter().find(|capability| {
                        capability.id == effect.target.id
                            && capability.generation == effect.expected_generation
                    }) {
                        Some(capability) if capability.revoked => {}
                        Some(capability) => violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "cleanup->effect-target",
                            from,
                            Some(capability.object_ref()),
                            "revoke-capability effect target is still active",
                        )),
                        None => {}
                    }
                }
                CleanupEffectKind::UnbindCode => {
                    match snapshot.code_objects.iter().find(|code| {
                        code.id == effect.target.id && code.generation == effect.expected_generation
                    }) {
                        Some(code)
                            if (code.bound_store != Some(cleanup.store)
                                || code.bound_store_generation
                                    != Some(cleanup.store_generation))
                                && matches!(
                                    code.state,
                                    CodeObjectState::Faulted
                                        | CodeObjectState::Retired
                                        | CodeObjectState::Unpublished
                                ) => {}
                        Some(code) => violations.push(ContractViolation::new(
                            ContractViolationKind::LiveObjectReferencesDeadObject,
                            "cleanup->effect-target",
                            from,
                            Some(code.object_ref()),
                            "unbind-code effect left code live or bound",
                        )),
                        None => {}
                    }
                }
                CleanupEffectKind::EmitTombstone => {
                    if !Self::has_tombstone(snapshot, effect.target) {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::DanglingEdge,
                            "cleanup->effect-target",
                            from,
                            Some(effect.target),
                            "emit-tombstone effect has no matching tombstone",
                        ));
                    }
                }
                CleanupEffectKind::StopNewActivation
                | CleanupEffectKind::SealActivation
                | CleanupEffectKind::ReleaseLeases
                | CleanupEffectKind::CancelWaits
                | CleanupEffectKind::DropResources
                | CleanupEffectKind::RecordFailureEffect => {}
            }
        }
    }

    fn validate_explicit_edges(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for edge in &snapshot.explicit_edges {
            if edge.mode == ContractEdgeMode::External {
                Self::validate_external_edge(snapshot, violations, edge);
                continue;
            }

            if let Some(source) = Self::current_object_ref(snapshot, edge.from.kind, edge.from.id) {
                if source.generation != edge.from.generation {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        &edge.label,
                        edge.from,
                        Some(source),
                        "edge source generation does not match source object",
                    ));
                }
                if edge.mode == ContractEdgeMode::Live {
                    if let Some(reason) = Self::inactive_reason(snapshot, edge.from) {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::LiveEdgeReferencesInactiveObject,
                            &edge.label,
                            edge.from,
                            Some(source),
                            reason,
                        ));
                    }
                }
            } else if !Self::has_tombstone(snapshot, edge.from) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    &edge.label,
                    edge.from,
                    None,
                    "edge source is missing",
                ));
            }

            if edge.mode == ContractEdgeMode::CleanupEffect
                && Self::cleanup_effect_label_creates_live_ownership(&edge.label)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::CleanupEffectCreatesLiveOwnership,
                    &edge.label,
                    edge.from,
                    Some(edge.to),
                    "cleanup effect edge uses a live-ownership relation",
                ));
            }

            Self::check_generation_edge(
                snapshot,
                violations,
                edge.from,
                &edge.label,
                edge.to.kind,
                edge.to.id,
                edge.to.generation,
                edge.mode,
            );
        }
    }

    fn validate_external_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        edge: &ContractEdgeRecord,
    ) {
        if edge.to.kind != ContractObjectKind::ExternalObject {
            violations.push(ContractViolation::new(
                ContractViolationKind::DanglingEdge,
                &edge.label,
                edge.from,
                Some(edge.to),
                "external edge target is not an external object",
            ));
            return;
        }

        let declaration = snapshot
            .external_objects
            .iter()
            .find(|declaration| declaration.object == edge.to);
        let Some(declaration) = declaration else {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMissingDeclaration,
                &edge.label,
                edge.from,
                Some(edge.to),
                "external edge target has no declaration",
            ));
            return;
        };

        match (&edge.provider, &edge.class) {
            (Some(provider), Some(class))
                if *provider == declaration.provider && *class == declaration.class => {}
            (Some(_), Some(_)) => violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                &edge.label,
                edge.from,
                Some(edge.to),
                "external edge provider/class metadata does not match declaration",
            )),
            _ => violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                &edge.label,
                edge.from,
                Some(edge.to),
                "external edge is missing provider/class metadata",
            )),
        }
    }

    fn check_authority_object_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        from: ContractObjectRef,
        edge: &str,
        authority: AuthorityObjectRef,
        semantics: ContractEdgeMode,
    ) {
        let object = authority.object();
        let class = authority.class().as_str();
        if matches!(authority, AuthorityObjectRef::External { .. }) {
            if Self::has_declared_object(snapshot, object, Some(class)) {
                return;
            }
            if Self::has_declared_object(snapshot, object, None) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    edge,
                    from,
                    Some(object),
                    "external authority object declaration has mismatched class metadata",
                ));
            } else {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMissingDeclaration,
                    edge,
                    from,
                    Some(object),
                    "external authority object is missing a matching declaration",
                ));
            }
            return;
        }
        Self::check_contract_ref_edge(
            snapshot,
            violations,
            from,
            edge,
            object,
            semantics,
            Some(class),
        );
    }

    fn check_contract_ref_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        from: ContractObjectRef,
        edge: &str,
        target: ContractObjectRef,
        semantics: ContractEdgeMode,
        class: Option<&str>,
    ) {
        if Self::is_graph_modeled_kind(target.kind) {
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                edge,
                target.kind,
                target.id,
                target.generation,
                semantics,
            );
            return;
        }

        if Self::has_declared_object(snapshot, target, class) {
            return;
        }
        if class.is_some() && Self::has_declared_object(snapshot, target, None) {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                edge,
                from,
                Some(target),
                "declared authority/wait target has mismatched class metadata",
            ));
            return;
        }

        violations.push(ContractViolation::new(
            ContractViolationKind::ExternalEdgeMissingDeclaration,
            edge,
            from,
            Some(target),
            "authority/wait target is not represented by a declared contract object",
        ));
    }

    fn check_generation_edge(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        from: ContractObjectRef,
        edge: &str,
        kind: ContractObjectKind,
        id: u64,
        generation: Generation,
        semantics: ContractEdgeMode,
    ) {
        if semantics != ContractEdgeMode::Live
            && kind != ContractObjectKind::ExternalObject
            && generation == 0
        {
            violations.push(ContractViolation::new(
                ContractViolationKind::HistoricalEdgeMissingGeneration,
                edge,
                from,
                Some(ContractObjectRef::new(kind, id, generation)),
                "historical/cleanup edge is missing exact target generation",
            ));
            return;
        }
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
            ContractObjectKind::Artifact => snapshot
                .artifacts
                .iter()
                .find(|artifact| artifact.artifact_id == id)
                .map(VerifiedArtifact::object_ref),
            ContractObjectKind::Trap => snapshot
                .traps
                .iter()
                .find(|trap| trap.id == id)
                .map(TargetTrapRecord::object_ref),
            ContractObjectKind::Hostcall => snapshot
                .hostcalls
                .iter()
                .find(|hostcall| hostcall.id == id)
                .map(HostcallTraceRecord::object_ref),
            ContractObjectKind::Capability => snapshot
                .capabilities
                .iter()
                .find(|capability| capability.id == id)
                .map(CapabilityRecord::object_ref),
            ContractObjectKind::WaitToken => snapshot
                .waits
                .iter()
                .find(|wait| wait.id == id)
                .map(WaitRecord::object_ref),
            ContractObjectKind::CleanupTransaction => snapshot
                .cleanup_transactions
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(FaultCleanupTransaction::object_ref),
            ContractObjectKind::ExternalObject => snapshot
                .external_objects
                .iter()
                .find(|external| external.object.id == id)
                .map(|external| external.object),
            _ => None,
        };
        match target {
            Some(target) if target.generation != generation => {
                let has_exact_tombstone =
                    Self::has_tombstone(snapshot, ContractObjectRef::new(kind, id, generation));
                if semantics == ContractEdgeMode::Live && has_exact_tombstone {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::TombstoneReferencedByLiveEdge,
                        edge,
                        from,
                        Some(ContractObjectRef::new(kind, id, generation)),
                        "live edge references a tombstoned generation",
                    ));
                } else if !has_exact_tombstone
                    || !matches!(
                        semantics,
                        ContractEdgeMode::Historical | ContractEdgeMode::CleanupEffect
                    )
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        edge,
                        from,
                        Some(target),
                        "edge generation does not match target object",
                    ));
                }
            }
            Some(target) => {
                Self::check_tombstone_live_edge(
                    snapshot,
                    violations,
                    from,
                    edge,
                    target,
                    semantics == ContractEdgeMode::Live,
                );
                if semantics == ContractEdgeMode::Live
                    && let Some(reason) = Self::inactive_reason(snapshot, target)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::LiveEdgeReferencesInactiveObject,
                        edge,
                        from,
                        Some(target),
                        reason,
                    ));
                }
            }
            None => {
                let target_ref = ContractObjectRef::new(kind, id, generation);
                let has_exact_tombstone = Self::has_tombstone(snapshot, target_ref);
                if semantics == ContractEdgeMode::Live && has_exact_tombstone {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::TombstoneReferencedByLiveEdge,
                        edge,
                        from,
                        Some(target_ref),
                        "live edge references a tombstoned generation",
                    ));
                } else if !has_exact_tombstone
                    || !matches!(
                        semantics,
                        ContractEdgeMode::Historical | ContractEdgeMode::CleanupEffect
                    )
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::DanglingEdge,
                        edge,
                        from,
                        Some(target_ref),
                        "edge references missing target",
                    ));
                }
            }
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

    fn current_object_ref(
        snapshot: &ContractGraphSnapshot,
        kind: ContractObjectKind,
        id: u64,
    ) -> Option<ContractObjectRef> {
        match kind {
            ContractObjectKind::Artifact => snapshot
                .artifacts
                .iter()
                .find(|artifact| artifact.artifact_id == id)
                .map(VerifiedArtifact::object_ref),
            ContractObjectKind::CodeObject => snapshot
                .code_objects
                .iter()
                .find(|code| code.id == id)
                .map(CodeObject::object_ref),
            ContractObjectKind::Store => snapshot
                .stores
                .iter()
                .find(|store| store.id == id)
                .map(StoreRecord::object_ref),
            ContractObjectKind::Activation => snapshot
                .activations
                .iter()
                .find(|activation| activation.id == id)
                .map(ActivationRecord::object_ref),
            ContractObjectKind::Trap => snapshot
                .traps
                .iter()
                .find(|trap| trap.id == id)
                .map(TargetTrapRecord::object_ref),
            ContractObjectKind::Hostcall => snapshot
                .hostcalls
                .iter()
                .find(|hostcall| hostcall.id == id)
                .map(HostcallTraceRecord::object_ref),
            ContractObjectKind::Capability => snapshot
                .capabilities
                .iter()
                .find(|capability| capability.id == id)
                .map(CapabilityRecord::object_ref),
            ContractObjectKind::WaitToken => snapshot
                .waits
                .iter()
                .find(|wait| wait.id == id)
                .map(WaitRecord::object_ref),
            ContractObjectKind::CleanupTransaction => snapshot
                .cleanup_transactions
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(FaultCleanupTransaction::object_ref),
            ContractObjectKind::ExternalObject => snapshot
                .external_objects
                .iter()
                .find(|external| external.object.id == id)
                .map(|external| external.object),
            ContractObjectKind::Hart
            | ContractObjectKind::Task
            | ContractObjectKind::RunnableQueue
            | ContractObjectKind::ActivationContext
            | ContractObjectKind::SavedContext
            | ContractObjectKind::TimerInterrupt
            | ContractObjectKind::IpiEvent
            | ContractObjectKind::RemotePreempt
            | ContractObjectKind::RemotePark
            | ContractObjectKind::Preemption
            | ContractObjectKind::SchedulerDecision
            | ContractObjectKind::CrossHartSchedulerDecision
            | ContractObjectKind::ActivationMigration
            | ContractObjectKind::SmpSafePoint
            | ContractObjectKind::StopTheWorldRendezvous
            | ContractObjectKind::SmpCodePublishBarrier
            | ContractObjectKind::SmpCleanupQuiescence
            | ContractObjectKind::SmpSnapshotBarrier
            | ContractObjectKind::SmpStressRun
            | ContractObjectKind::ActivationResume
            | ContractObjectKind::ActivationWait
            | ContractObjectKind::ActivationCleanup
            | ContractObjectKind::PreemptionLatencySample
            | ContractObjectKind::HartEventAttribution
            | ContractObjectKind::Resource
            | ContractObjectKind::FaultDomain
            | ContractObjectKind::MemoryObject
            | ContractObjectKind::GuestAddressSpace
            | ContractObjectKind::VmaRegion
            | ContractObjectKind::PageObject
            | ContractObjectKind::EventLog
            | ContractObjectKind::Tombstone => None,
        }
    }

    fn is_graph_modeled_kind(kind: ContractObjectKind) -> bool {
        matches!(
            kind,
            ContractObjectKind::Artifact
                | ContractObjectKind::CodeObject
                | ContractObjectKind::Store
                | ContractObjectKind::Activation
                | ContractObjectKind::Trap
                | ContractObjectKind::Hostcall
                | ContractObjectKind::Capability
                | ContractObjectKind::WaitToken
                | ContractObjectKind::CleanupTransaction
                | ContractObjectKind::ExternalObject
        )
    }

    fn has_declared_object(
        snapshot: &ContractGraphSnapshot,
        object: ContractObjectRef,
        class: Option<&str>,
    ) -> bool {
        snapshot.external_objects.iter().any(|declaration| {
            declaration.object == object && class.is_none_or(|class| declaration.class == class)
        })
    }

    fn has_tombstone(snapshot: &ContractGraphSnapshot, object: ContractObjectRef) -> bool {
        snapshot
            .tombstones
            .iter()
            .any(|tombstone| tombstone.object_ref() == object)
    }

    fn inactive_reason(
        snapshot: &ContractGraphSnapshot,
        object: ContractObjectRef,
    ) -> Option<&'static str> {
        match object.kind {
            ContractObjectKind::Store => snapshot
                .stores
                .iter()
                .find(|store| store.id == object.id && store.generation == object.generation)
                .and_then(|store| {
                    (store.state == StoreState::Dead).then_some("live edge references dead store")
                }),
            ContractObjectKind::CodeObject => snapshot
                .code_objects
                .iter()
                .find(|code| code.id == object.id && code.generation == object.generation)
                .and_then(|code| {
                    matches!(
                        code.state,
                        CodeObjectState::Faulted
                            | CodeObjectState::Retired
                            | CodeObjectState::Unpublished
                    )
                    .then_some("live edge references inactive code object")
                }),
            ContractObjectKind::Activation => snapshot
                .activations
                .iter()
                .find(|activation| {
                    activation.id == object.id && activation.generation == object.generation
                })
                .and_then(|activation| {
                    (!Self::is_live_activation(activation))
                        .then_some("live edge references inactive activation")
                }),
            ContractObjectKind::Capability => snapshot
                .capabilities
                .iter()
                .find(|capability| {
                    capability.id == object.id && capability.generation == object.generation
                })
                .and_then(|capability| {
                    capability
                        .revoked
                        .then_some("live edge references revoked capability")
                }),
            ContractObjectKind::WaitToken => snapshot
                .waits
                .iter()
                .find(|wait| wait.id == object.id && wait.generation == object.generation)
                .and_then(|wait| {
                    (wait.state != WaitState::Pending)
                        .then_some("live edge references inactive wait token")
                }),
            _ => None,
        }
    }

    fn cleanup_effect_label_creates_live_ownership(label: &str) -> bool {
        matches!(
            label,
            "owns"
                | "owner"
                | "owner-store"
                | "bound-to"
                | "blocks-on"
                | "authorizes"
                | "live"
                | "live-owner"
        ) || label.starts_with("live:")
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

impl FaultCleanupTransaction {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(
            ContractObjectKind::CleanupTransaction,
            self.id,
            self.generation,
        )
    }
}
