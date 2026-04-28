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
    pub target_feature_sets: Vec<TargetFeatureSetRecord>,
    pub vector_states: Vec<VectorStateRecord>,
    pub simd_fault_injections: Vec<SimdFaultInjectionRecord>,
    pub simd_benchmarks: Vec<SimdBenchmarkRecord>,
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
        Self::validate_vector_states(snapshot, &mut violations);
        Self::validate_simd_fault_injections(snapshot, &mut violations);
        Self::validate_simd_benchmarks(snapshot, &mut violations);
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
            if !code.simd_requirement.is_valid() {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "code->simd-requirement",
                    from,
                    code.simd_requirement.target_feature_set,
                    "code object SIMD requirement is malformed or missing",
                ));
            }
            if let Some(feature_set) = code.simd_requirement.target_feature_set {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "code->target-feature-set",
                    ContractObjectKind::TargetFeatureSet,
                    feature_set.id,
                    feature_set.generation,
                    ContractEdgeMode::Live,
                );
            }
        }
    }

    fn validate_vector_states(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for vector_state in &snapshot.vector_states {
            let from = vector_state.object_ref();
            let edge_mode = if vector_state.state.is_live_owned() {
                ContractEdgeMode::Live
            } else {
                ContractEdgeMode::Historical
            };
            Self::check_contract_ref_edge(
                snapshot,
                violations,
                from,
                "vector-state->activation",
                vector_state.owner_activation,
                edge_mode,
                None,
            );
            Self::check_contract_ref_edge(
                snapshot,
                violations,
                from,
                "vector-state->store",
                vector_state.owner_store,
                edge_mode,
                None,
            );
            Self::check_contract_ref_edge(
                snapshot,
                violations,
                from,
                "vector-state->code-object",
                vector_state.code_object,
                edge_mode,
                None,
            );
            Self::check_contract_ref_edge(
                snapshot,
                violations,
                from,
                "vector-state->target-feature-set",
                vector_state.target_feature_set,
                edge_mode,
                None,
            );
            if vector_state.state == VectorStateState::Reserved {
                let Some(feature) = snapshot.target_feature_sets.iter().find(|feature| {
                    feature.id == vector_state.target_feature_set.id
                        && feature.generation == vector_state.target_feature_set.generation
                }) else {
                    continue;
                };
                if !feature.simd_supported
                    || feature.simd_abi != vector_state.simd_abi
                    || feature.vector_register_count < vector_state.vector_register_count
                    || feature.vector_register_bits < vector_state.vector_register_bits
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "vector-state->target-feature-set",
                        from,
                        Some(vector_state.target_feature_set),
                        "reserved vector state is incompatible with target SIMD feature set",
                    ));
                }
            }
            if vector_state.state == VectorStateState::Unavailable {
                let Some(feature) = snapshot.target_feature_sets.iter().find(|feature| {
                    feature.id == vector_state.target_feature_set.id
                        && feature.generation == vector_state.target_feature_set.generation
                }) else {
                    continue;
                };
                if feature.simd_supported {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "vector-state->target-feature-set",
                        from,
                        Some(vector_state.target_feature_set),
                        "unavailable vector state cannot point at a supported SIMD feature set",
                    ));
                }
            }
        }
    }

    fn validate_simd_fault_injections(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for injection in &snapshot.simd_fault_injections {
            let from = injection.object_ref();
            for (label, target, expected_kind) in [
                (
                    "simd-fault-injection->activation",
                    injection.activation,
                    ContractObjectKind::Activation,
                ),
                (
                    "simd-fault-injection->code",
                    injection.code_object,
                    ContractObjectKind::CodeObject,
                ),
                (
                    "simd-fault-injection->trap",
                    injection.trap,
                    ContractObjectKind::Trap,
                ),
                (
                    "simd-fault-injection->target-feature-set",
                    injection.target_feature_set,
                    ContractObjectKind::TargetFeatureSet,
                ),
            ] {
                if target.kind != expected_kind {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        label,
                        from,
                        Some(target),
                        "SIMD fault injection edge uses the wrong object kind",
                    ));
                    continue;
                }
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    expected_kind,
                    target.id,
                    target.generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(vector_state) = injection.vector_state {
                if vector_state.kind != ContractObjectKind::VectorState {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "simd-fault-injection->vector-state",
                        from,
                        Some(vector_state),
                        "SIMD fault injection vector state edge uses the wrong object kind",
                    ));
                    continue;
                }
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "simd-fault-injection->vector-state",
                    ContractObjectKind::VectorState,
                    vector_state.id,
                    vector_state.generation,
                    ContractEdgeMode::Historical,
                );
            }
            let Some(trap) = snapshot
                .traps
                .iter()
                .find(|trap| trap.id == injection.trap.id)
            else {
                continue;
            };
            if trap.generation != injection.trap.generation {
                continue;
            }
            if trap.trap_kind.as_deref() != Some(injection.kind.trap_kind()) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "simd-fault-injection->trap",
                    from,
                    Some(trap.object_ref()),
                    "SIMD fault injection kind does not match the classified trap kind",
                ));
            }
            let Some(simd) = &trap.simd_attribution else {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "simd-fault-injection->trap",
                    from,
                    Some(trap.object_ref()),
                    "SIMD fault injection trap is missing SIMD attribution",
                ));
                continue;
            };
            if simd.required_abi != injection.required_abi
                || simd.min_vector_register_count != injection.vector_register_count
                || simd.min_vector_register_bits != injection.vector_register_bits
                || simd.target_feature_set != Some(injection.target_feature_set)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "simd-fault-injection->trap",
                    from,
                    Some(trap.object_ref()),
                    "SIMD fault injection metadata does not match trap SIMD attribution",
                ));
            }
            if let Some(feature_set) = snapshot
                .target_feature_sets
                .iter()
                .find(|feature_set| feature_set.object_ref() == injection.target_feature_set)
            {
                if feature_set.simd_abi != injection.required_abi
                    || (injection.kind == SimdFaultInjectionKind::UnsupportedFeature
                        && feature_set.simd_supported)
                    || (injection.kind == SimdFaultInjectionKind::IllegalInstruction
                        && !feature_set.simd_supported)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "simd-fault-injection->target-feature-set",
                        from,
                        Some(feature_set.object_ref()),
                        "SIMD fault injection target feature set does not match injected fault class",
                    ));
                }
            }
            if trap.code_object != Some(injection.code_object.id)
                || trap.code_generation != Some(injection.code_object.generation)
                || trap.activation != Some(injection.activation.id)
                || trap.activation_generation != Some(injection.activation.generation)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "simd-fault-injection->trap",
                    from,
                    Some(trap.object_ref()),
                    "SIMD fault injection trap attribution does not match exact activation/code refs",
                ));
            }
        }
    }

    fn validate_simd_benchmarks(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for benchmark in &snapshot.simd_benchmarks {
            let from = benchmark.object_ref();
            for (label, target, expected_kind) in [
                (
                    "simd-benchmark->target-feature-set",
                    benchmark.target_feature_set,
                    ContractObjectKind::TargetFeatureSet,
                ),
                (
                    "simd-benchmark->scalar-code",
                    benchmark.scalar_code_object,
                    ContractObjectKind::CodeObject,
                ),
                (
                    "simd-benchmark->vector-code",
                    benchmark.vector_code_object,
                    ContractObjectKind::CodeObject,
                ),
            ] {
                if target.kind != expected_kind {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        label,
                        from,
                        Some(target),
                        "SIMD benchmark edge uses the wrong object kind",
                    ));
                    continue;
                }
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    expected_kind,
                    target.id,
                    target.generation,
                    ContractEdgeMode::Historical,
                );
            }

            if benchmark.scalar_code_object == benchmark.vector_code_object {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "simd-benchmark->code-pair",
                    from,
                    Some(benchmark.scalar_code_object),
                    "SIMD benchmark requires distinct scalar and vector code objects",
                ));
            }
            if benchmark.vector_nanos >= benchmark.scalar_nanos
                || benchmark.scalar_nanos == 0
                || benchmark.vector_nanos == 0
                || benchmark.workload_units == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "simd-benchmark->metrics",
                    from,
                    None,
                    "SIMD benchmark requires nonzero workload and faster vector path",
                ));
            } else {
                let expected_speedup = ((benchmark.scalar_nanos as u128) * 1000u128
                    / benchmark.vector_nanos as u128) as u64;
                let expected_overhead = benchmark.scalar_nanos - benchmark.vector_nanos;
                if benchmark.speedup_milli != expected_speedup
                    || benchmark.context_overhead_nanos != expected_overhead
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "simd-benchmark->metrics",
                        from,
                        None,
                        "SIMD benchmark derived metrics do not match scalar/vector measurements",
                    ));
                }
            }

            let feature = snapshot
                .target_feature_sets
                .iter()
                .find(|feature| feature.object_ref() == benchmark.target_feature_set);
            if let Some(feature) = feature {
                if !feature.simd_supported
                    || feature.simd_abi != benchmark.simd_abi
                    || feature.vector_register_count < benchmark.vector_register_count
                    || feature.vector_register_bits < benchmark.vector_register_bits
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "simd-benchmark->target-feature-set",
                        from,
                        Some(feature.object_ref()),
                        "SIMD benchmark target feature set does not support benchmark vector shape",
                    ));
                }
            }

            let scalar_code = snapshot
                .code_objects
                .iter()
                .find(|code| code.object_ref() == benchmark.scalar_code_object);
            if let Some(code) = scalar_code
                && code.simd_requirement.uses_simd
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "simd-benchmark->scalar-code",
                    from,
                    Some(code.object_ref()),
                    "SIMD benchmark scalar code object must not declare SIMD usage",
                ));
            }

            let vector_code = snapshot
                .code_objects
                .iter()
                .find(|code| code.object_ref() == benchmark.vector_code_object);
            if let Some(code) = vector_code {
                if !code.simd_requirement.uses_simd
                    || code.simd_requirement.status != CodeObjectSimdRequirementStatus::Declared
                    || code.simd_requirement.required_abi != benchmark.simd_abi
                    || code.simd_requirement.min_vector_register_count
                        != benchmark.vector_register_count
                    || code.simd_requirement.min_vector_register_bits
                        != benchmark.vector_register_bits
                    || code.simd_requirement.target_feature_set
                        != Some(benchmark.target_feature_set)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "simd-benchmark->vector-code",
                        from,
                        Some(code.object_ref()),
                        "SIMD benchmark vector code object does not declare matching SIMD requirement",
                    ));
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
            Self::validate_simd_trap(snapshot, violations, trap);
        }
    }

    fn validate_simd_trap(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        trap: &TargetTrapRecord,
    ) {
        let is_simd_trap = trap
            .trap_kind
            .as_deref()
            .is_some_and(|kind| kind.starts_with("simd-"));
        if !is_simd_trap && trap.simd_attribution.is_none() {
            return;
        }
        let from = trap.object_ref();
        let Some(attribution) = &trap.simd_attribution else {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                "trap->simd-requirement",
                from,
                None,
                "SIMD trap is missing SIMD attribution",
            ));
            return;
        };
        if attribution.classification == SimdTrapClassification::RequirementMissing {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                "trap->simd-requirement",
                from,
                None,
                "SIMD trap was attributed to code without a declared SIMD requirement",
            ));
        }
        if let Some(feature) = attribution.target_feature_set {
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "trap->target-feature-set",
                ContractObjectKind::TargetFeatureSet,
                feature.id,
                feature.generation,
                ContractEdgeMode::Historical,
            );
        }
        let Some(code_id) = trap.code_object else {
            violations.push(ContractViolation::new(
                ContractViolationKind::DanglingEdge,
                "trap->simd-code",
                from,
                None,
                "SIMD trap is missing code object attribution",
            ));
            return;
        };
        let Some(code) = snapshot.code_objects.iter().find(|code| code.id == code_id) else {
            return;
        };
        if trap.code_generation != Some(code.generation) {
            return;
        }
        if !code.simd_requirement.uses_simd
            || !code.simd_requirement.declared
            || code.simd_requirement.status != CodeObjectSimdRequirementStatus::Declared
        {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                "trap->simd-requirement",
                from,
                Some(code.object_ref()),
                "SIMD trap code object does not declare a valid SIMD requirement",
            ));
            return;
        }
        if attribution.required_abi != code.simd_requirement.required_abi
            || attribution.min_vector_register_count
                != code.simd_requirement.min_vector_register_count
            || attribution.min_vector_register_bits
                != code.simd_requirement.min_vector_register_bits
            || attribution.target_feature_set != code.simd_requirement.target_feature_set
            || attribution.code_requirement_status != code.simd_requirement.status
        {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                "trap->simd-requirement",
                from,
                Some(code.object_ref()),
                "SIMD trap attribution does not match CodeObject SIMD requirement",
            ));
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
            ContractObjectKind::TargetFeatureSet => snapshot
                .target_feature_sets
                .iter()
                .find(|feature| feature.id == id)
                .map(TargetFeatureSetRecord::object_ref),
            ContractObjectKind::VectorState => snapshot
                .vector_states
                .iter()
                .find(|vector_state| vector_state.id == id)
                .map(VectorStateRecord::object_ref),
            ContractObjectKind::SimdFaultInjection => snapshot
                .simd_fault_injections
                .iter()
                .find(|injection| injection.id == id)
                .map(SimdFaultInjectionRecord::object_ref),
            ContractObjectKind::SimdBenchmark => snapshot
                .simd_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(SimdBenchmarkRecord::object_ref),
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
            ContractObjectKind::TargetFeatureSet => snapshot
                .target_feature_sets
                .iter()
                .find(|feature| feature.id == id)
                .map(TargetFeatureSetRecord::object_ref),
            ContractObjectKind::VectorState => snapshot
                .vector_states
                .iter()
                .find(|vector_state| vector_state.id == id)
                .map(VectorStateRecord::object_ref),
            ContractObjectKind::SimdFaultInjection => snapshot
                .simd_fault_injections
                .iter()
                .find(|injection| injection.id == id)
                .map(SimdFaultInjectionRecord::object_ref),
            ContractObjectKind::SimdBenchmark => snapshot
                .simd_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(SimdBenchmarkRecord::object_ref),
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
            | ContractObjectKind::SmpScalingBenchmark
            | ContractObjectKind::DeviceObject
            | ContractObjectKind::QueueObject
            | ContractObjectKind::DescriptorObject
            | ContractObjectKind::DmaBufferObject
            | ContractObjectKind::MmioRegionObject
            | ContractObjectKind::IrqLineObject
            | ContractObjectKind::IrqEvent
            | ContractObjectKind::DeviceCapability
            | ContractObjectKind::DriverStoreBinding
            | ContractObjectKind::IoWait
            | ContractObjectKind::IoCleanup
            | ContractObjectKind::IoFaultInjection
            | ContractObjectKind::IoValidationReport
            | ContractObjectKind::PacketDeviceObject
            | ContractObjectKind::PacketBufferObject
            | ContractObjectKind::PacketQueueObject
            | ContractObjectKind::PacketDescriptorObject
            | ContractObjectKind::FakeNetBackendObject
            | ContractObjectKind::FakeBlockBackendObject
            | ContractObjectKind::VirtioBlkBackendObject
            | ContractObjectKind::VirtioNetBackendObject
            | ContractObjectKind::NetworkRxInterrupt
            | ContractObjectKind::NetworkRxWaitResolution
            | ContractObjectKind::NetworkTxCapabilityGate
            | ContractObjectKind::NetworkTxCompletion
            | ContractObjectKind::NetworkStackAdapter
            | ContractObjectKind::SocketObject
            | ContractObjectKind::EndpointObject
            | ContractObjectKind::SocketOperation
            | ContractObjectKind::SocketWait
            | ContractObjectKind::NetworkBackpressure
            | ContractObjectKind::NetworkDriverCleanup
            | ContractObjectKind::NetworkGenerationAudit
            | ContractObjectKind::NetworkFaultInjection
            | ContractObjectKind::NetworkBenchmark
            | ContractObjectKind::NetworkRecoveryBenchmark
            | ContractObjectKind::BlockDeviceObject
            | ContractObjectKind::BlockRangeObject
            | ContractObjectKind::BlockRequestObject
            | ContractObjectKind::BlockCompletionObject
            | ContractObjectKind::BlockWait
            | ContractObjectKind::BlockReadPath
            | ContractObjectKind::BlockWritePath
            | ContractObjectKind::BlockRequestQueue
            | ContractObjectKind::BlockDmaBuffer
            | ContractObjectKind::BlockPageObject
            | ContractObjectKind::BufferCacheObject
            | ContractObjectKind::FileObject
            | ContractObjectKind::DirectoryObject
            | ContractObjectKind::FatAdapterObject
            | ContractObjectKind::Ext4AdapterObject
            | ContractObjectKind::FileHandleCapability
            | ContractObjectKind::FsWait
            | ContractObjectKind::BlockDriverCleanup
            | ContractObjectKind::BlockPendingIoPolicy
            | ContractObjectKind::BlockRequestGenerationAudit
            | ContractObjectKind::BlockBenchmark
            | ContractObjectKind::BlockRecoveryBenchmark
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
                | ContractObjectKind::TargetFeatureSet
                | ContractObjectKind::VectorState
                | ContractObjectKind::SimdFaultInjection
                | ContractObjectKind::SimdBenchmark
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
            ContractObjectKind::VectorState => snapshot
                .vector_states
                .iter()
                .find(|vector_state| {
                    vector_state.id == object.id && vector_state.generation == object.generation
                })
                .and_then(|vector_state| {
                    (!vector_state.state.is_live_owned())
                        .then_some("live edge references inactive vector state")
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
