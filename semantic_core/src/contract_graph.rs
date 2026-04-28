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
    pub simd_context_switch_benchmarks: Vec<SimdContextSwitchBenchmarkRecord>,
    pub framebuffer_objects: Vec<FramebufferObjectRecord>,
    pub display_objects: Vec<DisplayObjectRecord>,
    pub display_capabilities: Vec<DisplayCapabilityRecord>,
    pub framebuffer_window_leases: Vec<FramebufferWindowLeaseRecord>,
    pub framebuffer_mappings: Vec<FramebufferMappingRecord>,
    pub framebuffer_writes: Vec<FramebufferWriteRecord>,
    pub preemptions: Vec<PreemptionRecord>,
    pub activation_resumes: Vec<ActivationResumeRecord>,
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
        Self::validate_simd_context_switch_benchmarks(snapshot, &mut violations);
        Self::validate_framebuffer_objects(snapshot, &mut violations);
        Self::validate_display_objects(snapshot, &mut violations);
        Self::validate_display_capabilities(snapshot, &mut violations);
        Self::validate_framebuffer_window_leases(snapshot, &mut violations);
        Self::validate_framebuffer_mappings(snapshot, &mut violations);
        Self::validate_framebuffer_writes(snapshot, &mut violations);
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

    fn validate_simd_context_switch_benchmarks(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for benchmark in &snapshot.simd_context_switch_benchmarks {
            let from = benchmark.object_ref();
            for (label, target, expected_kind) in [
                (
                    "simd-context-switch-benchmark->preemption",
                    benchmark.preemption,
                    ContractObjectKind::Preemption,
                ),
                (
                    "simd-context-switch-benchmark->activation-resume",
                    benchmark.activation_resume,
                    ContractObjectKind::ActivationResume,
                ),
                (
                    "simd-context-switch-benchmark->saved-vector-state",
                    benchmark.saved_vector_state,
                    ContractObjectKind::VectorState,
                ),
                (
                    "simd-context-switch-benchmark->restored-vector-state",
                    benchmark.restored_vector_state,
                    ContractObjectKind::VectorState,
                ),
                (
                    "simd-context-switch-benchmark->target-feature-set",
                    benchmark.target_feature_set,
                    ContractObjectKind::TargetFeatureSet,
                ),
            ] {
                if target.kind != expected_kind {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        label,
                        from,
                        Some(target),
                        "SIMD context switch benchmark edge uses the wrong object kind",
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

            if benchmark.saved_vector_state == benchmark.restored_vector_state {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "simd-context-switch-benchmark->vector-state-pair",
                    from,
                    Some(benchmark.saved_vector_state),
                    "SIMD context switch benchmark requires distinct saved/restored vector states",
                ));
            }
            if benchmark.sample_count == 0
                || benchmark.scalar_context_switch_nanos == 0
                || benchmark.vector_context_switch_nanos <= benchmark.scalar_context_switch_nanos
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "simd-context-switch-benchmark->metrics",
                    from,
                    None,
                    "SIMD context switch benchmark requires nonzero samples and higher vector context cost",
                ));
            } else {
                let expected_overhead =
                    benchmark.vector_context_switch_nanos - benchmark.scalar_context_switch_nanos;
                if benchmark.overhead_nanos != expected_overhead
                    || benchmark.overhead_nanos > benchmark.budget_nanos
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "simd-context-switch-benchmark->metrics",
                        from,
                        None,
                        "SIMD context switch benchmark overhead is inconsistent or over budget",
                    ));
                }
            }

            let preemption = snapshot
                .preemptions
                .iter()
                .find(|preemption| preemption.object_ref() == benchmark.preemption);
            let resume = snapshot
                .activation_resumes
                .iter()
                .find(|resume| resume.object_ref() == benchmark.activation_resume);
            if let (Some(preemption), Some(resume)) = (preemption, resume) {
                if preemption.activation != resume.activation
                    || preemption.activation_generation_after != resume.activation_generation_before
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "simd-context-switch-benchmark->activation-flow",
                        from,
                        Some(resume.object_ref()),
                        "SIMD context switch benchmark preempt/resume activation generations do not form a handoff",
                    ));
                }
            }

            if let Some(resume) = resume {
                if resume.saved_vector_state != Some(benchmark.saved_vector_state)
                    || resume.restored_vector_state != Some(benchmark.restored_vector_state)
                    || resume.vector_status != ActivationVectorState::Clean
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "simd-context-switch-benchmark->activation-resume",
                        from,
                        Some(resume.object_ref()),
                        "SIMD context switch benchmark resume does not record the benchmark vector restore pair",
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
                        "simd-context-switch-benchmark->target-feature-set",
                        from,
                        Some(feature.object_ref()),
                        "SIMD context switch benchmark target feature set does not support measured vector shape",
                    ));
                }
            }

            for (label, vector_ref) in [
                (
                    "simd-context-switch-benchmark->saved-vector-state",
                    benchmark.saved_vector_state,
                ),
                (
                    "simd-context-switch-benchmark->restored-vector-state",
                    benchmark.restored_vector_state,
                ),
            ] {
                let Some(vector) = snapshot
                    .vector_states
                    .iter()
                    .find(|vector| vector.object_ref() == vector_ref)
                else {
                    continue;
                };
                if vector.target_feature_set != benchmark.target_feature_set
                    || vector.simd_abi != benchmark.simd_abi
                    || vector.vector_register_count != benchmark.vector_register_count
                    || vector.vector_register_bits != benchmark.vector_register_bits
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        label,
                        from,
                        Some(vector.object_ref()),
                        "SIMD context switch benchmark vector state shape does not match benchmark target",
                    ));
                }
            }
        }
    }

    fn validate_framebuffer_objects(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for framebuffer in &snapshot.framebuffer_objects {
            let from = framebuffer.object_ref();
            if framebuffer.id == 0
                || framebuffer.generation == 0
                || framebuffer.resource == 0
                || framebuffer.resource_generation == 0
                || framebuffer.name.is_empty()
                || framebuffer.width == 0
                || framebuffer.height == 0
                || framebuffer.stride_bytes == 0
                || framebuffer.pixel_format.is_empty()
                || framebuffer.byte_len == 0
                || framebuffer.state != FramebufferObjectState::Registered
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-object->contract",
                    from,
                    None,
                    "framebuffer object requires nonzero identity, backing resource, geometry, pixel format, and registered state",
                ));
                continue;
            }

            let bytes_per_pixel = match framebuffer.pixel_format.as_str() {
                "xrgb8888" | "argb8888" | "rgba8888" | "bgra8888" => 4,
                "rgb565" => 2,
                _ => {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "framebuffer-object->pixel-format",
                        from,
                        None,
                        "framebuffer object uses an unsupported pixel format",
                    ));
                    continue;
                }
            };
            if framebuffer.stride_bytes < framebuffer.width.saturating_mul(bytes_per_pixel)
                || framebuffer.byte_len
                    < u64::from(framebuffer.stride_bytes)
                        .saturating_mul(u64::from(framebuffer.height))
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-object->geometry",
                    from,
                    None,
                    "framebuffer object stride/byte length do not cover visible geometry",
                ));
            }
        }
    }

    fn validate_display_objects(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for display in &snapshot.display_objects {
            let from = display.object_ref();
            if display.id == 0
                || display.generation == 0
                || display.framebuffer == 0
                || display.framebuffer_generation == 0
                || display.name.is_empty()
                || display.mode_name.is_empty()
                || display.width == 0
                || display.height == 0
                || display.refresh_millihz == 0
                || display.state != DisplayObjectState::Registered
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-object->contract",
                    from,
                    None,
                    "display object requires nonzero identity, framebuffer generation, mode, refresh, and registered state",
                ));
                continue;
            }

            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-object->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                display.framebuffer,
                display.framebuffer_generation,
                ContractEdgeMode::Live,
            );

            if let Some(framebuffer) = snapshot.framebuffer_objects.iter().find(|framebuffer| {
                framebuffer.id == display.framebuffer
                    && framebuffer.generation == display.framebuffer_generation
            }) {
                if framebuffer.state != FramebufferObjectState::Registered
                    || display.width > framebuffer.width
                    || display.height > framebuffer.height
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "display-object->framebuffer-geometry",
                        from,
                        Some(framebuffer.object_ref()),
                        "display object mode must fit its registered framebuffer generation",
                    ));
                }
            }
        }
    }

    fn validate_display_capabilities(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for capability in &snapshot.display_capabilities {
            let from = capability.object_ref();
            if capability.id == 0
                || capability.generation == 0
                || capability.owner_store_generation == 0
                || capability.display_generation == 0
                || capability.framebuffer_generation == 0
                || capability.capability_generation == 0
                || capability.operations.is_empty()
                || capability
                    .operations
                    .iter()
                    .any(|operation| operation.is_empty())
                || capability.state != DisplayCapabilityState::Active
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-capability->contract",
                    from,
                    None,
                    "display capability requires nonzero owner, display, framebuffer, capability, operations, and active state",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-capability->owner-store",
                ContractObjectKind::Store,
                capability.owner_store,
                capability.owner_store_generation,
                ContractEdgeMode::Live,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-capability->display-object",
                ContractObjectKind::DisplayObject,
                capability.display,
                capability.display_generation,
                ContractEdgeMode::Live,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-capability->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                capability.framebuffer,
                capability.framebuffer_generation,
                ContractEdgeMode::Live,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-capability->capability",
                ContractObjectKind::Capability,
                capability.capability,
                capability.capability_generation,
                ContractEdgeMode::Live,
            );

            if let Some(display) = snapshot.display_objects.iter().find(|display| {
                display.id == capability.display
                    && display.generation == capability.display_generation
            }) {
                if display.framebuffer != capability.framebuffer
                    || display.framebuffer_generation != capability.framebuffer_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-capability->display-framebuffer",
                        from,
                        Some(display.object_ref()),
                        "display capability framebuffer edge does not match display object generation",
                    ));
                }
            }
        }
    }

    fn validate_framebuffer_window_leases(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for lease in &snapshot.framebuffer_window_leases {
            let from = lease.object_ref();
            if lease.id == 0
                || lease.generation == 0
                || lease.owner_store_generation == 0
                || lease.display_capability_generation == 0
                || lease.display_generation == 0
                || lease.framebuffer_generation == 0
                || lease.width == 0
                || lease.height == 0
                || lease.byte_len == 0
                || lease.access.is_empty()
                || lease.state != FramebufferWindowLeaseState::Active
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-window-lease->contract",
                    from,
                    None,
                    "framebuffer window lease requires nonzero exact refs, window, byte range, access, and active state",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->owner-store",
                ContractObjectKind::Store,
                lease.owner_store,
                lease.owner_store_generation,
                ContractEdgeMode::Live,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->display-capability",
                ContractObjectKind::DisplayCapability,
                lease.display_capability,
                lease.display_capability_generation,
                ContractEdgeMode::Live,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->display-object",
                ContractObjectKind::DisplayObject,
                lease.display,
                lease.display_generation,
                ContractEdgeMode::Live,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                lease.framebuffer,
                lease.framebuffer_generation,
                ContractEdgeMode::Live,
            );

            let display_capability = snapshot.display_capabilities.iter().find(|capability| {
                capability.id == lease.display_capability
                    && capability.generation == lease.display_capability_generation
            });
            if let Some(capability) = display_capability {
                if capability.owner_store != lease.owner_store
                    || capability.owner_store_generation != lease.owner_store_generation
                    || capability.display != lease.display
                    || capability.display_generation != lease.display_generation
                    || capability.framebuffer != lease.framebuffer
                    || capability.framebuffer_generation != lease.framebuffer_generation
                    || !capability
                        .operations
                        .iter()
                        .any(|operation| operation == "lease")
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-window-lease->display-capability-binding",
                        from,
                        Some(capability.object_ref()),
                        "framebuffer window lease does not match display capability authority binding",
                    ));
                }
            }
            if let Some(display) = snapshot.display_objects.iter().find(|display| {
                display.id == lease.display && display.generation == lease.display_generation
            }) {
                if display.framebuffer != lease.framebuffer
                    || display.framebuffer_generation != lease.framebuffer_generation
                    || lease
                        .x
                        .checked_add(lease.width)
                        .is_none_or(|right| right > display.width)
                    || lease
                        .y
                        .checked_add(lease.height)
                        .is_none_or(|bottom| bottom > display.height)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "framebuffer-window-lease->display-window",
                        from,
                        Some(display.object_ref()),
                        "framebuffer window lease window is outside display mode or framebuffer binding",
                    ));
                }
            }
            if let Some(framebuffer) = snapshot.framebuffer_objects.iter().find(|framebuffer| {
                framebuffer.id == lease.framebuffer
                    && framebuffer.generation == lease.framebuffer_generation
            }) {
                let bytes_per_pixel = match framebuffer.pixel_format.as_str() {
                    "xrgb8888" | "argb8888" | "rgba8888" | "bgra8888" => Some(4_u64),
                    "rgb565" => Some(2_u64),
                    _ => None,
                };
                let byte_window = bytes_per_pixel.and_then(|bytes_per_pixel| {
                    let row_bytes = u64::from(lease.width).checked_mul(bytes_per_pixel)?;
                    let expected_byte_offset = u64::from(lease.y)
                        .checked_mul(u64::from(framebuffer.stride_bytes))
                        .and_then(|base| {
                            u64::from(lease.x)
                                .checked_mul(bytes_per_pixel)
                                .and_then(|x_bytes| base.checked_add(x_bytes))
                        })?;
                    let min_window_bytes = u64::from(lease.height.saturating_sub(1))
                        .checked_mul(u64::from(framebuffer.stride_bytes))
                        .and_then(|rows| rows.checked_add(row_bytes))?;
                    Some((expected_byte_offset, min_window_bytes))
                });
                if byte_window.is_none_or(|(expected_byte_offset, min_window_bytes)| {
                    lease.byte_offset != expected_byte_offset || lease.byte_len < min_window_bytes
                }) || lease
                    .byte_offset
                    .checked_add(lease.byte_len)
                    .is_none_or(|end| end > framebuffer.byte_len)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::ExternalEdgeMetadataMismatch,
                        "framebuffer-window-lease->byte-window",
                        from,
                        Some(framebuffer.object_ref()),
                        "framebuffer window lease byte window does not match framebuffer geometry or exceeds framebuffer object",
                    ));
                }
            }
        }
    }

    fn validate_framebuffer_mappings(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for mapping in &snapshot.framebuffer_mappings {
            let from = mapping.object_ref();
            if mapping.id == 0
                || mapping.generation == 0
                || mapping.owner_store_generation == 0
                || mapping.framebuffer_window_lease_generation == 0
                || mapping.map_handle_slot == 0
                || mapping.map_handle_generation == 0
                || mapping.map_handle_tag == 0
                || mapping.width == 0
                || mapping.height == 0
                || mapping.byte_len == 0
                || mapping.mode != "handle-mode"
                || (mapping.access != "write" && mapping.access != "read")
                || mapping.state != FramebufferMappingState::Active
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-mapping->contract",
                    from,
                    None,
                    "framebuffer mapping requires exact refs, active handle-mode state, handle identity, and byte window",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->owner-store",
                ContractObjectKind::Store,
                mapping.owner_store,
                mapping.owner_store_generation,
                ContractEdgeMode::Live,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->framebuffer-window-lease",
                ContractObjectKind::FramebufferWindowLease,
                mapping.framebuffer_window_lease,
                mapping.framebuffer_window_lease_generation,
                ContractEdgeMode::Live,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->display-capability",
                ContractObjectKind::DisplayCapability,
                mapping.display_capability,
                mapping.display_capability_generation,
                ContractEdgeMode::Live,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->display-object",
                ContractObjectKind::DisplayObject,
                mapping.display,
                mapping.display_generation,
                ContractEdgeMode::Live,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                mapping.framebuffer,
                mapping.framebuffer_generation,
                ContractEdgeMode::Live,
            );
            if let Some(lease) = snapshot.framebuffer_window_leases.iter().find(|lease| {
                lease.id == mapping.framebuffer_window_lease
                    && lease.generation == mapping.framebuffer_window_lease_generation
            }) {
                if lease.owner_store != mapping.owner_store
                    || lease.owner_store_generation != mapping.owner_store_generation
                    || lease.display_capability != mapping.display_capability
                    || lease.display_capability_generation != mapping.display_capability_generation
                    || lease.display != mapping.display
                    || lease.display_generation != mapping.display_generation
                    || lease.framebuffer != mapping.framebuffer
                    || lease.framebuffer_generation != mapping.framebuffer_generation
                    || lease.x != mapping.x
                    || lease.y != mapping.y
                    || lease.width != mapping.width
                    || lease.height != mapping.height
                    || lease.byte_offset != mapping.byte_offset
                    || lease.byte_len != mapping.byte_len
                    || lease.access != mapping.access
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-mapping->lease-binding",
                        from,
                        Some(lease.object_ref()),
                        "framebuffer mapping does not match the active framebuffer window lease",
                    ));
                }
            }
        }
    }

    fn validate_framebuffer_writes(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for write in &snapshot.framebuffer_writes {
            let from = write.object_ref();
            if write.id == 0
                || write.generation == 0
                || write.owner_store_generation == 0
                || write.framebuffer_mapping_generation == 0
                || write.map_handle_slot == 0
                || write.map_handle_generation == 0
                || write.map_handle_tag == 0
                || write.width == 0
                || write.height == 0
                || write.byte_len == 0
                || write.pixel_format.is_empty()
                || write.payload_digest == 0
                || write.state != FramebufferWriteState::Applied
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-write->contract",
                    from,
                    None,
                    "framebuffer write requires exact refs, applied state, handle identity, payload digest, and byte window",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->owner-store",
                ContractObjectKind::Store,
                write.owner_store,
                write.owner_store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->framebuffer-mapping",
                ContractObjectKind::FramebufferMapping,
                write.framebuffer_mapping,
                write.framebuffer_mapping_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->framebuffer-window-lease",
                ContractObjectKind::FramebufferWindowLease,
                write.framebuffer_window_lease,
                write.framebuffer_window_lease_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->display-capability",
                ContractObjectKind::DisplayCapability,
                write.display_capability,
                write.display_capability_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->display-object",
                ContractObjectKind::DisplayObject,
                write.display,
                write.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-write->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                write.framebuffer,
                write.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            if let Some(mapping) = snapshot.framebuffer_mappings.iter().find(|mapping| {
                mapping.id == write.framebuffer_mapping
                    && mapping.generation == write.framebuffer_mapping_generation
            }) {
                let region_mismatch = write.x < mapping.x
                    || write.y < mapping.y
                    || write
                        .x
                        .checked_add(write.width)
                        .zip(mapping.x.checked_add(mapping.width))
                        .is_none_or(|(write_right, mapping_right)| write_right > mapping_right)
                    || write
                        .y
                        .checked_add(write.height)
                        .zip(mapping.y.checked_add(mapping.height))
                        .is_none_or(|(write_bottom, mapping_bottom)| write_bottom > mapping_bottom);
                let byte_mismatch = write.byte_offset < mapping.byte_offset
                    || write
                        .byte_offset
                        .checked_add(write.byte_len)
                        .zip(mapping.byte_offset.checked_add(mapping.byte_len))
                        .is_none_or(|(write_end, mapping_end)| write_end > mapping_end);
                if mapping.owner_store != write.owner_store
                    || mapping.owner_store_generation != write.owner_store_generation
                    || mapping.framebuffer_window_lease != write.framebuffer_window_lease
                    || mapping.framebuffer_window_lease_generation
                        != write.framebuffer_window_lease_generation
                    || mapping.display_capability != write.display_capability
                    || mapping.display_capability_generation != write.display_capability_generation
                    || mapping.display != write.display
                    || mapping.display_generation != write.display_generation
                    || mapping.framebuffer != write.framebuffer
                    || mapping.framebuffer_generation != write.framebuffer_generation
                    || mapping.map_handle_slot != write.map_handle_slot
                    || mapping.map_handle_generation != write.map_handle_generation
                    || mapping.map_handle_tag != write.map_handle_tag
                    || mapping.access != "write"
                    || mapping.mode != "handle-mode"
                    || region_mismatch
                    || byte_mismatch
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-write->mapping-binding",
                        from,
                        Some(mapping.object_ref()),
                        "framebuffer write does not match the mapped framebuffer lease authority",
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

            if let Some(source) = Self::object_ref_by_id_generation(
                snapshot,
                edge.from.kind,
                edge.from.id,
                edge.from.generation,
            )
            .or_else(|| Self::current_object_ref(snapshot, edge.from.kind, edge.from.id))
            {
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
        let target = Self::object_ref_by_id_generation(snapshot, kind, id, generation)
            .or_else(|| Self::current_object_ref(snapshot, kind, id));
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

    fn object_ref_by_id_generation(
        snapshot: &ContractGraphSnapshot,
        kind: ContractObjectKind,
        id: u64,
        generation: Generation,
    ) -> Option<ContractObjectRef> {
        match kind {
            ContractObjectKind::Activation => snapshot
                .activations
                .iter()
                .find(|activation| activation.id == id && activation.generation == generation)
                .map(ActivationRecord::object_ref),
            ContractObjectKind::Store => snapshot
                .stores
                .iter()
                .find(|store| store.id == id && store.generation == generation)
                .map(StoreRecord::object_ref),
            ContractObjectKind::CodeObject => snapshot
                .code_objects
                .iter()
                .find(|code| code.id == id && code.generation == generation)
                .map(CodeObject::object_ref),
            ContractObjectKind::TargetFeatureSet => snapshot
                .target_feature_sets
                .iter()
                .find(|feature| feature.id == id && feature.generation == generation)
                .map(TargetFeatureSetRecord::object_ref),
            ContractObjectKind::VectorState => snapshot
                .vector_states
                .iter()
                .find(|vector_state| vector_state.id == id && vector_state.generation == generation)
                .map(VectorStateRecord::object_ref),
            ContractObjectKind::SimdFaultInjection => snapshot
                .simd_fault_injections
                .iter()
                .find(|injection| injection.id == id && injection.generation == generation)
                .map(SimdFaultInjectionRecord::object_ref),
            ContractObjectKind::SimdBenchmark => snapshot
                .simd_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id && benchmark.generation == generation)
                .map(SimdBenchmarkRecord::object_ref),
            ContractObjectKind::SimdContextSwitchBenchmark => snapshot
                .simd_context_switch_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id && benchmark.generation == generation)
                .map(SimdContextSwitchBenchmarkRecord::object_ref),
            ContractObjectKind::FramebufferObject => snapshot
                .framebuffer_objects
                .iter()
                .find(|framebuffer| framebuffer.id == id && framebuffer.generation == generation)
                .map(FramebufferObjectRecord::object_ref),
            ContractObjectKind::DisplayObject => snapshot
                .display_objects
                .iter()
                .find(|display| display.id == id && display.generation == generation)
                .map(DisplayObjectRecord::object_ref),
            ContractObjectKind::DisplayCapability => snapshot
                .display_capabilities
                .iter()
                .find(|capability| capability.id == id && capability.generation == generation)
                .map(DisplayCapabilityRecord::object_ref),
            ContractObjectKind::FramebufferWindowLease => snapshot
                .framebuffer_window_leases
                .iter()
                .find(|lease| lease.id == id && lease.generation == generation)
                .map(FramebufferWindowLeaseRecord::object_ref),
            ContractObjectKind::FramebufferMapping => snapshot
                .framebuffer_mappings
                .iter()
                .find(|mapping| mapping.id == id && mapping.generation == generation)
                .map(FramebufferMappingRecord::object_ref),
            ContractObjectKind::FramebufferWrite => snapshot
                .framebuffer_writes
                .iter()
                .find(|write| write.id == id && write.generation == generation)
                .map(FramebufferWriteRecord::object_ref),
            ContractObjectKind::Preemption => snapshot
                .preemptions
                .iter()
                .find(|preemption| preemption.id == id && preemption.generation == generation)
                .map(PreemptionRecord::object_ref),
            ContractObjectKind::ActivationResume => snapshot
                .activation_resumes
                .iter()
                .find(|resume| resume.id == id && resume.generation == generation)
                .map(ActivationResumeRecord::object_ref),
            ContractObjectKind::Artifact => snapshot
                .artifacts
                .iter()
                .find(|artifact| artifact.artifact_id == id && artifact.generation == generation)
                .map(VerifiedArtifact::object_ref),
            ContractObjectKind::Trap => snapshot
                .traps
                .iter()
                .find(|trap| trap.id == id && trap.generation == generation)
                .map(TargetTrapRecord::object_ref),
            ContractObjectKind::Hostcall => snapshot
                .hostcalls
                .iter()
                .find(|hostcall| hostcall.id == id && hostcall.generation == generation)
                .map(HostcallTraceRecord::object_ref),
            ContractObjectKind::Capability => snapshot
                .capabilities
                .iter()
                .find(|capability| capability.id == id && capability.generation == generation)
                .map(CapabilityRecord::object_ref),
            ContractObjectKind::WaitToken => snapshot
                .waits
                .iter()
                .find(|wait| wait.id == id && wait.generation == generation)
                .map(WaitRecord::object_ref),
            ContractObjectKind::CleanupTransaction => snapshot
                .cleanup_transactions
                .iter()
                .find(|cleanup| cleanup.id == id && cleanup.generation == generation)
                .map(FaultCleanupTransaction::object_ref),
            ContractObjectKind::ExternalObject => snapshot
                .external_objects
                .iter()
                .find(|external| {
                    external.object.id == id && external.object.generation == generation
                })
                .map(|external| external.object),
            _ => None,
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
            ContractObjectKind::SimdContextSwitchBenchmark => snapshot
                .simd_context_switch_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(SimdContextSwitchBenchmarkRecord::object_ref),
            ContractObjectKind::FramebufferObject => snapshot
                .framebuffer_objects
                .iter()
                .find(|framebuffer| framebuffer.id == id)
                .map(FramebufferObjectRecord::object_ref),
            ContractObjectKind::DisplayObject => snapshot
                .display_objects
                .iter()
                .find(|display| display.id == id)
                .map(DisplayObjectRecord::object_ref),
            ContractObjectKind::DisplayCapability => snapshot
                .display_capabilities
                .iter()
                .find(|capability| capability.id == id)
                .map(DisplayCapabilityRecord::object_ref),
            ContractObjectKind::FramebufferWindowLease => snapshot
                .framebuffer_window_leases
                .iter()
                .find(|lease| lease.id == id)
                .map(FramebufferWindowLeaseRecord::object_ref),
            ContractObjectKind::FramebufferMapping => snapshot
                .framebuffer_mappings
                .iter()
                .find(|mapping| mapping.id == id)
                .map(FramebufferMappingRecord::object_ref),
            ContractObjectKind::FramebufferWrite => snapshot
                .framebuffer_writes
                .iter()
                .find(|write| write.id == id)
                .map(FramebufferWriteRecord::object_ref),
            ContractObjectKind::Preemption => snapshot
                .preemptions
                .iter()
                .find(|preemption| preemption.id == id)
                .map(PreemptionRecord::object_ref),
            ContractObjectKind::ActivationResume => snapshot
                .activation_resumes
                .iter()
                .find(|resume| resume.id == id)
                .map(ActivationResumeRecord::object_ref),
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
                | ContractObjectKind::SimdContextSwitchBenchmark
                | ContractObjectKind::FramebufferObject
                | ContractObjectKind::DisplayObject
                | ContractObjectKind::DisplayCapability
                | ContractObjectKind::FramebufferWindowLease
                | ContractObjectKind::FramebufferMapping
                | ContractObjectKind::FramebufferWrite
                | ContractObjectKind::Preemption
                | ContractObjectKind::ActivationResume
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
            ContractObjectKind::FramebufferObject => snapshot
                .framebuffer_objects
                .iter()
                .find(|framebuffer| {
                    framebuffer.id == object.id && framebuffer.generation == object.generation
                })
                .and_then(|framebuffer| {
                    (framebuffer.state != FramebufferObjectState::Registered)
                        .then_some("live edge references inactive framebuffer object")
                }),
            ContractObjectKind::DisplayObject => snapshot
                .display_objects
                .iter()
                .find(|display| display.id == object.id && display.generation == object.generation)
                .and_then(|display| {
                    (display.state != DisplayObjectState::Registered)
                        .then_some("live edge references inactive display object")
                }),
            ContractObjectKind::DisplayCapability => snapshot
                .display_capabilities
                .iter()
                .find(|capability| {
                    capability.id == object.id && capability.generation == object.generation
                })
                .and_then(|capability| {
                    (capability.state != DisplayCapabilityState::Active)
                        .then_some("live edge references inactive display capability")
                }),
            ContractObjectKind::FramebufferWindowLease => snapshot
                .framebuffer_window_leases
                .iter()
                .find(|lease| lease.id == object.id && lease.generation == object.generation)
                .and_then(|lease| {
                    (lease.state != FramebufferWindowLeaseState::Active)
                        .then_some("live edge references inactive framebuffer window lease")
                }),
            ContractObjectKind::FramebufferMapping => snapshot
                .framebuffer_mappings
                .iter()
                .find(|mapping| mapping.id == object.id && mapping.generation == object.generation)
                .and_then(|mapping| {
                    (mapping.state != FramebufferMappingState::Active)
                        .then_some("live edge references inactive framebuffer mapping")
                }),
            ContractObjectKind::FramebufferWrite => snapshot
                .framebuffer_writes
                .iter()
                .find(|write| write.id == object.id && write.generation == object.generation)
                .and_then(|write| {
                    (write.state != FramebufferWriteState::Applied)
                        .then_some("live edge references unapplied framebuffer write")
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
