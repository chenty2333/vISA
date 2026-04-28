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
    pub framebuffer_flush_regions: Vec<FramebufferFlushRegionRecord>,
    pub framebuffer_dirty_regions: Vec<FramebufferDirtyRegionRecord>,
    pub display_event_logs: Vec<DisplayEventLogRecord>,
    pub display_cleanups: Vec<DisplayCleanupRecord>,
    pub display_snapshot_barriers: Vec<DisplaySnapshotBarrierRecord>,
    pub display_panic_last_frames: Vec<DisplayPanicLastFrameRecord>,
    pub framebuffer_benchmarks: Vec<FramebufferBenchmarkRecord>,
    pub integrated_display_scheduler_loads: Vec<IntegratedDisplaySchedulerLoadRecord>,
    pub integrated_snapshot_io_lease_barriers: Vec<IntegratedSnapshotIoLeaseBarrierRecord>,
    pub integrated_code_publish_smp_workloads: Vec<IntegratedCodePublishSmpWorkloadRecord>,
    pub integrated_display_panics: Vec<IntegratedDisplayPanicRecord>,
    pub integrated_smp_preemption_cleanups: Vec<IntegratedSmpPreemptionCleanupRecord>,
    pub integrated_smp_network_faults: Vec<IntegratedSmpNetworkFaultRecord>,
    pub integrated_disk_preempt_faults: Vec<IntegratedDiskPreemptFaultRecord>,
    pub integrated_simd_migrations: Vec<IntegratedSimdMigrationRecord>,
    pub integrated_network_disk_ios: Vec<IntegratedNetworkDiskIoRecord>,
    pub network_benchmarks: Vec<NetworkBenchmarkRecord>,
    pub block_benchmarks: Vec<BlockBenchmarkRecord>,
    pub fake_block_backends: Vec<FakeBlockBackendObjectRecord>,
    pub network_driver_cleanups: Vec<NetworkDriverCleanupRecord>,
    pub device_objects: Vec<DeviceObjectRecord>,
    pub packet_device_objects: Vec<PacketDeviceObjectRecord>,
    pub network_stack_adapters: Vec<NetworkStackAdapterRecord>,
    pub socket_objects: Vec<SocketObjectRecord>,
    pub virtio_net_backends: Vec<VirtioNetBackendObjectRecord>,
    pub io_cleanups: Vec<IoCleanupRecord>,
    pub block_pending_io_policies: Vec<BlockPendingIoPolicyRecord>,
    pub block_waits: Vec<BlockWaitRecord>,
    pub block_request_objects: Vec<BlockRequestObjectRecord>,
    pub block_device_objects: Vec<BlockDeviceObjectRecord>,
    pub block_range_objects: Vec<BlockRangeObjectRecord>,
    pub block_request_queues: Vec<BlockRequestQueueRecord>,
    pub block_dma_buffers: Vec<BlockDmaBufferRecord>,
    pub harts: Vec<HartRecord>,
    pub tasks: Vec<TaskRecord>,
    pub runtime_activations: Vec<RuntimeActivationRecord>,
    pub runnable_queues: Vec<RunnableQueueRecord>,
    pub scheduler_decisions: Vec<SchedulerDecisionRecord>,
    pub activation_contexts: Vec<ActivationContextRecord>,
    pub activation_migrations: Vec<ActivationMigrationRecord>,
    pub smp_safe_points: Vec<SmpSafePointRecord>,
    pub stop_the_world_rendezvous: Vec<StopTheWorldRendezvousRecord>,
    pub smp_code_publish_barriers: Vec<SmpCodePublishBarrierRecord>,
    pub saved_contexts: Vec<SavedContextRecord>,
    pub timer_interrupts: Vec<TimerInterruptRecord>,
    pub remote_preempts: Vec<RemotePreemptRecord>,
    pub activation_cleanups: Vec<ActivationCleanupRecord>,
    pub smp_cleanup_quiescence: Vec<SmpCleanupQuiescenceRecord>,
    pub smp_snapshot_barriers: Vec<SmpSnapshotBarrierRecord>,
    pub smp_stress_runs: Vec<SmpStressRunRecord>,
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
        Self::validate_framebuffer_flush_regions(snapshot, &mut violations);
        Self::validate_framebuffer_dirty_regions(snapshot, &mut violations);
        Self::validate_display_event_logs(snapshot, &mut violations);
        Self::validate_display_cleanups(snapshot, &mut violations);
        Self::validate_display_snapshot_barriers(snapshot, &mut violations);
        Self::validate_display_panic_last_frames(snapshot, &mut violations);
        Self::validate_framebuffer_benchmarks(snapshot, &mut violations);
        Self::validate_integrated_display_scheduler_loads(snapshot, &mut violations);
        Self::validate_integrated_snapshot_io_lease_barriers(snapshot, &mut violations);
        Self::validate_integrated_code_publish_smp_workloads(snapshot, &mut violations);
        Self::validate_integrated_display_panics(snapshot, &mut violations);
        Self::validate_integrated_smp_preemption_cleanups(snapshot, &mut violations);
        Self::validate_integrated_smp_network_faults(snapshot, &mut violations);
        Self::validate_integrated_disk_preempt_faults(snapshot, &mut violations);
        Self::validate_integrated_simd_migrations(snapshot, &mut violations);
        Self::validate_integrated_network_disk_ios(snapshot, &mut violations);
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
                || (capability.state != DisplayCapabilityState::Active
                    && capability.state != DisplayCapabilityState::Revoked)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-capability->contract",
                    from,
                    None,
                    "display capability requires nonzero owner, display, framebuffer, capability, operations, and known state",
                ));
                continue;
            }
            let active = capability.state == DisplayCapabilityState::Active;
            let edge_mode = if active {
                ContractEdgeMode::Live
            } else {
                ContractEdgeMode::Historical
            };
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-capability->owner-store",
                ContractObjectKind::Store,
                capability.owner_store,
                capability.owner_store_generation,
                edge_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-capability->display-object",
                ContractObjectKind::DisplayObject,
                capability.display,
                capability.display_generation,
                edge_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-capability->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                capability.framebuffer,
                capability.framebuffer_generation,
                edge_mode,
            );
            if active {
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
            } else if !snapshot.capabilities.iter().any(|record| {
                record.id == capability.capability
                    && record.revoked
                    && record.generation > capability.capability_generation
            }) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "display-capability->revoked-capability",
                    from,
                    None,
                    "revoked display capability must point to an advanced revoked capability generation",
                ));
            }

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
                || (lease.state != FramebufferWindowLeaseState::Active
                    && lease.state != FramebufferWindowLeaseState::Released)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-window-lease->contract",
                    from,
                    None,
                    "framebuffer window lease requires nonzero exact refs, window, byte range, access, and known state",
                ));
                continue;
            }
            let active = lease.state == FramebufferWindowLeaseState::Active;
            let owner_mode = if active {
                ContractEdgeMode::Live
            } else {
                ContractEdgeMode::Historical
            };
            let capability_mode = if active {
                ContractEdgeMode::Live
            } else {
                ContractEdgeMode::CleanupEffect
            };
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->owner-store",
                ContractObjectKind::Store,
                lease.owner_store,
                lease.owner_store_generation,
                owner_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->display-capability",
                ContractObjectKind::DisplayCapability,
                lease.display_capability,
                lease.display_capability_generation,
                capability_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->display-object",
                ContractObjectKind::DisplayObject,
                lease.display,
                lease.display_generation,
                owner_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-window-lease->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                lease.framebuffer,
                lease.framebuffer_generation,
                owner_mode,
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
                || (mapping.state != FramebufferMappingState::Active
                    && mapping.state != FramebufferMappingState::Unmapped)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-mapping->contract",
                    from,
                    None,
                    "framebuffer mapping requires exact refs, handle-mode state, handle identity, and byte window",
                ));
                continue;
            }
            let active = mapping.state == FramebufferMappingState::Active;
            let owner_mode = if active {
                ContractEdgeMode::Live
            } else {
                ContractEdgeMode::Historical
            };
            let cleanup_mode = if active {
                ContractEdgeMode::Live
            } else {
                ContractEdgeMode::CleanupEffect
            };
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->owner-store",
                ContractObjectKind::Store,
                mapping.owner_store,
                mapping.owner_store_generation,
                owner_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->framebuffer-window-lease",
                ContractObjectKind::FramebufferWindowLease,
                mapping.framebuffer_window_lease,
                mapping.framebuffer_window_lease_generation,
                cleanup_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->display-capability",
                ContractObjectKind::DisplayCapability,
                mapping.display_capability,
                mapping.display_capability_generation,
                cleanup_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->display-object",
                ContractObjectKind::DisplayObject,
                mapping.display,
                mapping.display_generation,
                owner_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-mapping->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                mapping.framebuffer,
                mapping.framebuffer_generation,
                owner_mode,
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

    fn validate_framebuffer_flush_regions(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for flush in &snapshot.framebuffer_flush_regions {
            let from = flush.object_ref();
            if flush.id == 0
                || flush.generation == 0
                || flush.owner_store_generation == 0
                || flush.framebuffer_write_generation == 0
                || flush.width == 0
                || flush.height == 0
                || flush.byte_len == 0
                || flush.pixel_format.is_empty()
                || flush.payload_digest == 0
                || flush.state != FramebufferFlushRegionState::Applied
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-flush-region->contract",
                    from,
                    None,
                    "framebuffer flush region requires exact refs, applied state, payload digest, and byte window",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-flush-region->owner-store",
                ContractObjectKind::Store,
                flush.owner_store,
                flush.owner_store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-flush-region->framebuffer-write",
                ContractObjectKind::FramebufferWrite,
                flush.framebuffer_write,
                flush.framebuffer_write_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-flush-region->display-capability",
                ContractObjectKind::DisplayCapability,
                flush.display_capability,
                flush.display_capability_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-flush-region->display-object",
                ContractObjectKind::DisplayObject,
                flush.display,
                flush.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-flush-region->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                flush.framebuffer,
                flush.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            if let Some(write) = snapshot.framebuffer_writes.iter().find(|write| {
                write.id == flush.framebuffer_write
                    && write.generation == flush.framebuffer_write_generation
            }) {
                if write.owner_store != flush.owner_store
                    || write.owner_store_generation != flush.owner_store_generation
                    || write.display_capability != flush.display_capability
                    || write.display_capability_generation != flush.display_capability_generation
                    || write.display != flush.display
                    || write.display_generation != flush.display_generation
                    || write.framebuffer != flush.framebuffer
                    || write.framebuffer_generation != flush.framebuffer_generation
                    || write.x != flush.x
                    || write.y != flush.y
                    || write.width != flush.width
                    || write.height != flush.height
                    || write.byte_offset != flush.byte_offset
                    || write.byte_len != flush.byte_len
                    || write.pixel_format != flush.pixel_format
                    || write.payload_digest != flush.payload_digest
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-flush-region->write-binding",
                        from,
                        Some(write.object_ref()),
                        "framebuffer flush region does not match the written framebuffer region",
                    ));
                }
            }
        }
    }

    fn validate_framebuffer_dirty_regions(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for dirty in &snapshot.framebuffer_dirty_regions {
            let from = dirty.object_ref();
            let state_valid = matches!(
                dirty.state,
                FramebufferDirtyRegionState::Dirty | FramebufferDirtyRegionState::Clean
            );
            let clean_has_flush = dirty.framebuffer_flush_region.is_some()
                && dirty.framebuffer_flush_region_generation.unwrap_or(0) != 0
                && dirty.cleaned_at_event.unwrap_or(0) != 0;
            let dirty_has_no_flush = dirty.framebuffer_flush_region.is_none()
                && dirty.framebuffer_flush_region_generation.is_none()
                && dirty.cleaned_at_event.is_none();
            if dirty.id == 0
                || dirty.generation == 0
                || dirty.owner_store_generation == 0
                || dirty.framebuffer_write_generation == 0
                || dirty.width == 0
                || dirty.height == 0
                || dirty.byte_len == 0
                || dirty.pixel_format.is_empty()
                || dirty.payload_digest == 0
                || !state_valid
                || (dirty.state == FramebufferDirtyRegionState::Clean && !clean_has_flush)
                || (dirty.state == FramebufferDirtyRegionState::Dirty && !dirty_has_no_flush)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-dirty-region->contract",
                    from,
                    None,
                    "framebuffer dirty region requires exact refs, state-consistent flush refs, payload digest, and byte window",
                ));
                continue;
            }
            let owner_edge_mode = if dirty.state == FramebufferDirtyRegionState::Dirty {
                ContractEdgeMode::Live
            } else {
                ContractEdgeMode::Historical
            };
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-dirty-region->owner-store",
                ContractObjectKind::Store,
                dirty.owner_store,
                dirty.owner_store_generation,
                owner_edge_mode,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-dirty-region->framebuffer-write",
                ContractObjectKind::FramebufferWrite,
                dirty.framebuffer_write,
                dirty.framebuffer_write_generation,
                ContractEdgeMode::Historical,
            );
            if let (Some(flush), Some(generation)) = (
                dirty.framebuffer_flush_region,
                dirty.framebuffer_flush_region_generation,
            ) {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "framebuffer-dirty-region->framebuffer-flush-region",
                    ContractObjectKind::FramebufferFlushRegion,
                    flush,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-dirty-region->display-capability",
                ContractObjectKind::DisplayCapability,
                dirty.display_capability,
                dirty.display_capability_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-dirty-region->display-object",
                ContractObjectKind::DisplayObject,
                dirty.display,
                dirty.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "framebuffer-dirty-region->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                dirty.framebuffer,
                dirty.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            if let Some(write) = snapshot.framebuffer_writes.iter().find(|write| {
                write.id == dirty.framebuffer_write
                    && write.generation == dirty.framebuffer_write_generation
            }) {
                if write.owner_store != dirty.owner_store
                    || write.owner_store_generation != dirty.owner_store_generation
                    || write.display_capability != dirty.display_capability
                    || write.display_capability_generation != dirty.display_capability_generation
                    || write.display != dirty.display
                    || write.display_generation != dirty.display_generation
                    || write.framebuffer != dirty.framebuffer
                    || write.framebuffer_generation != dirty.framebuffer_generation
                    || write.x != dirty.x
                    || write.y != dirty.y
                    || write.width != dirty.width
                    || write.height != dirty.height
                    || write.byte_offset != dirty.byte_offset
                    || write.byte_len != dirty.byte_len
                    || write.pixel_format != dirty.pixel_format
                    || write.payload_digest != dirty.payload_digest
                    || write.recorded_at_event != dirty.dirty_at_event
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-dirty-region->write-binding",
                        from,
                        Some(write.object_ref()),
                        "framebuffer dirty region does not match the written framebuffer region",
                    ));
                }
            }
            if let (Some(flush_id), Some(flush_generation)) = (
                dirty.framebuffer_flush_region,
                dirty.framebuffer_flush_region_generation,
            ) && let Some(flush) = snapshot
                .framebuffer_flush_regions
                .iter()
                .find(|flush| flush.id == flush_id && flush.generation == flush_generation)
                && (flush.owner_store != dirty.owner_store
                    || flush.owner_store_generation != dirty.owner_store_generation
                    || flush.framebuffer_write != dirty.framebuffer_write
                    || flush.framebuffer_write_generation != dirty.framebuffer_write_generation
                    || flush.display_capability != dirty.display_capability
                    || flush.display_capability_generation != dirty.display_capability_generation
                    || flush.display != dirty.display
                    || flush.display_generation != dirty.display_generation
                    || flush.framebuffer != dirty.framebuffer
                    || flush.framebuffer_generation != dirty.framebuffer_generation
                    || flush.x != dirty.x
                    || flush.y != dirty.y
                    || flush.width != dirty.width
                    || flush.height != dirty.height
                    || flush.byte_offset != dirty.byte_offset
                    || flush.byte_len != dirty.byte_len
                    || flush.pixel_format != dirty.pixel_format
                    || flush.payload_digest != dirty.payload_digest
                    || Some(flush.recorded_at_event) != dirty.cleaned_at_event)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "framebuffer-dirty-region->flush-binding",
                    from,
                    Some(flush.object_ref()),
                    "clean framebuffer dirty region does not match the clearing flush region",
                ));
            }
        }
    }

    fn validate_display_event_logs(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for log in &snapshot.display_event_logs {
            let from = log.object_ref();
            if log.id == 0
                || log.generation == 0
                || log.owner_store_generation == 0
                || log.framebuffer_dirty_region_generation == 0
                || log.first_event == 0
                || log.last_event < log.first_event
                || log.event_count == 0
                || log.state != DisplayEventLogState::Recorded
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-event-log->contract",
                    from,
                    None,
                    "display event log requires exact refs, recorded state, and nonempty event window",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-event-log->owner-store",
                ContractObjectKind::Store,
                log.owner_store,
                log.owner_store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-event-log->framebuffer-dirty-region",
                ContractObjectKind::FramebufferDirtyRegion,
                log.framebuffer_dirty_region,
                log.framebuffer_dirty_region_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-event-log->display-capability",
                ContractObjectKind::DisplayCapability,
                log.display_capability,
                log.display_capability_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-event-log->display-object",
                ContractObjectKind::DisplayObject,
                log.display,
                log.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-event-log->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                log.framebuffer,
                log.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            if let Some(dirty) = snapshot.framebuffer_dirty_regions.iter().find(|dirty| {
                dirty.id == log.framebuffer_dirty_region
                    && dirty.generation == log.framebuffer_dirty_region_generation
            }) {
                if dirty.owner_store != log.owner_store
                    || dirty.owner_store_generation != log.owner_store_generation
                    || dirty.display_capability != log.display_capability
                    || dirty.display_capability_generation != log.display_capability_generation
                    || dirty.display != log.display
                    || dirty.display_generation != log.display_generation
                    || dirty.framebuffer != log.framebuffer
                    || dirty.framebuffer_generation != log.framebuffer_generation
                    || dirty.dirty_at_event < log.first_event
                    || dirty.recorded_at_event > log.last_event
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-event-log->dirty-region-binding",
                        from,
                        Some(dirty.object_ref()),
                        "display event log window or refs do not match the dirty region lifecycle",
                    ));
                }
            }
        }
    }

    fn validate_display_cleanups(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for cleanup in &snapshot.display_cleanups {
            let from = cleanup.object_ref();
            if cleanup.id == 0
                || cleanup.generation == 0
                || cleanup.owner_store_generation == 0
                || cleanup.display_capability_generation == 0
                || cleanup.display_generation == 0
                || cleanup.framebuffer_generation == 0
                || cleanup.reason.is_empty()
                || cleanup.state != DisplayCleanupState::Completed
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-cleanup->contract",
                    from,
                    None,
                    "display cleanup requires exact refs, completed state, and reason",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-cleanup->owner-store",
                ContractObjectKind::Store,
                cleanup.owner_store,
                cleanup.owner_store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-cleanup->display-capability",
                ContractObjectKind::DisplayCapability,
                cleanup.display_capability,
                cleanup.display_capability_generation,
                ContractEdgeMode::CleanupEffect,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-cleanup->display-object",
                ContractObjectKind::DisplayObject,
                cleanup.display,
                cleanup.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-cleanup->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                cleanup.framebuffer,
                cleanup.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            for mapping in &cleanup.unmapped_framebuffer_mappings {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "display-cleanup->unmapped-framebuffer-mapping",
                    ContractObjectKind::FramebufferMapping,
                    mapping.id,
                    mapping.generation,
                    ContractEdgeMode::CleanupEffect,
                );
                if let Some(record) = snapshot.framebuffer_mappings.iter().find(|record| {
                    record.id == mapping.id && record.generation == mapping.generation
                }) {
                    if record.state != FramebufferMappingState::Unmapped
                        || record.owner_store != cleanup.owner_store
                        || record.owner_store_generation != cleanup.owner_store_generation
                        || record.display_capability != cleanup.display_capability
                        || record.display_capability_generation
                            != cleanup.display_capability_generation
                    {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "display-cleanup->mapping-effect",
                            from,
                            Some(record.object_ref()),
                            "display cleanup mapping effect does not match the cleanup target",
                        ));
                    }
                }
            }
            for lease in &cleanup.released_framebuffer_window_leases {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "display-cleanup->released-framebuffer-window-lease",
                    ContractObjectKind::FramebufferWindowLease,
                    lease.id,
                    lease.generation,
                    ContractEdgeMode::CleanupEffect,
                );
                if let Some(record) = snapshot
                    .framebuffer_window_leases
                    .iter()
                    .find(|record| record.id == lease.id && record.generation == lease.generation)
                {
                    if record.state != FramebufferWindowLeaseState::Released
                        || record.owner_store != cleanup.owner_store
                        || record.owner_store_generation != cleanup.owner_store_generation
                        || record.display_capability != cleanup.display_capability
                        || record.display_capability_generation
                            != cleanup.display_capability_generation
                    {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "display-cleanup->lease-effect",
                            from,
                            Some(record.object_ref()),
                            "display cleanup lease effect does not match the cleanup target",
                        ));
                    }
                }
            }
            for display_capability in &cleanup.revoked_display_capabilities {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "display-cleanup->revoked-display-capability",
                    ContractObjectKind::DisplayCapability,
                    display_capability.id,
                    display_capability.generation,
                    ContractEdgeMode::CleanupEffect,
                );
                if let Some(record) = snapshot.display_capabilities.iter().find(|record| {
                    record.id == display_capability.id
                        && record.generation == display_capability.generation
                }) {
                    if record.state != DisplayCapabilityState::Revoked
                        || record.owner_store != cleanup.owner_store
                        || record.owner_store_generation != cleanup.owner_store_generation
                    {
                        violations.push(ContractViolation::new(
                            ContractViolationKind::GenerationMismatch,
                            "display-cleanup->display-capability-effect",
                            from,
                            Some(record.object_ref()),
                            "display cleanup display-capability effect does not match the cleanup target",
                        ));
                    }
                }
            }
            for capability in &cleanup.revoked_capabilities {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "display-cleanup->revoked-capability",
                    ContractObjectKind::Capability,
                    capability.id,
                    capability.generation,
                    ContractEdgeMode::CleanupEffect,
                );
            }
        }
    }

    fn validate_display_snapshot_barriers(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for barrier in &snapshot.display_snapshot_barriers {
            let from = barrier.object_ref();
            if barrier.id == 0
                || barrier.generation == 0
                || barrier.owner_store_generation == 0
                || barrier.display_generation == 0
                || barrier.framebuffer_generation == 0
                || barrier.reason.is_empty()
                || !barrier.snapshot_validation_ok
                || barrier.state != DisplaySnapshotBarrierState::Validated
                || barrier.active_framebuffer_window_lease_count != 0
                || barrier.active_framebuffer_mapping_count != 0
                || barrier.dirty_framebuffer_region_count != 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-snapshot-barrier->contract",
                    from,
                    None,
                    "display snapshot barrier requires exact refs and quiescent display state",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-snapshot-barrier->owner-store",
                ContractObjectKind::Store,
                barrier.owner_store,
                barrier.owner_store_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-snapshot-barrier->display-object",
                ContractObjectKind::DisplayObject,
                barrier.display,
                barrier.display_generation,
                ContractEdgeMode::Historical,
            );
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "display-snapshot-barrier->framebuffer-object",
                ContractObjectKind::FramebufferObject,
                barrier.framebuffer,
                barrier.framebuffer_generation,
                ContractEdgeMode::Historical,
            );
            match (barrier.display_cleanup, barrier.display_cleanup_generation) {
                (Some(cleanup), Some(generation)) => {
                    Self::check_generation_edge(
                        snapshot,
                        violations,
                        from,
                        "display-snapshot-barrier->display-cleanup",
                        ContractObjectKind::DisplayCleanup,
                        cleanup,
                        generation,
                        ContractEdgeMode::Historical,
                    );
                    if let Some(cleanup_record) = snapshot
                        .display_cleanups
                        .iter()
                        .find(|record| record.id == cleanup && record.generation == generation)
                    {
                        if cleanup_record.owner_store != barrier.owner_store
                            || cleanup_record.owner_store_generation
                                != barrier.owner_store_generation
                            || cleanup_record.display != barrier.display
                            || cleanup_record.display_generation != barrier.display_generation
                            || cleanup_record.framebuffer != barrier.framebuffer
                            || cleanup_record.framebuffer_generation
                                != barrier.framebuffer_generation
                            || cleanup_record.state != DisplayCleanupState::Completed
                        {
                            violations.push(ContractViolation::new(
                                ContractViolationKind::GenerationMismatch,
                                "display-snapshot-barrier->cleanup-binding",
                                from,
                                Some(cleanup_record.object_ref()),
                                "display snapshot barrier cleanup does not match the barrier target",
                            ));
                        }
                    }
                }
                (None, None) => {}
                _ => violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "display-snapshot-barrier->cleanup-ref",
                    from,
                    None,
                    "display snapshot barrier cleanup ref must be exact or absent",
                )),
            }
        }
    }

    fn validate_display_panic_last_frames(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for frame in &snapshot.display_panic_last_frames {
            let from = frame.object_ref();
            if frame.id == 0
                || frame.generation == 0
                || frame.owner_store_generation == 0
                || frame.display_generation == 0
                || frame.framebuffer_generation == 0
                || frame.display_snapshot_barrier_generation == 0
                || frame.display_event_log_generation == 0
                || frame.framebuffer_write_generation == 0
                || frame.framebuffer_flush_region_generation == 0
                || frame.payload_digest == 0
                || frame.summary_digest == 0
                || frame.summary_record_bytes == 0
                || frame.summary_record_bytes > 4096
                || frame.panic_epoch == 0
                || frame.panic_record_kind != "contract-panic-summary-v1"
                || frame.raw_framebuffer_bytes_exported
                || frame.state != DisplayPanicLastFrameState::Recorded
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "display-panic-last-frame->contract",
                    from,
                    None,
                    "display panic last-frame summary requires exact refs and no raw framebuffer bytes",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "display-panic-last-frame->owner-store",
                    ContractObjectKind::Store,
                    frame.owner_store,
                    frame.owner_store_generation,
                ),
                (
                    "display-panic-last-frame->display-object",
                    ContractObjectKind::DisplayObject,
                    frame.display,
                    frame.display_generation,
                ),
                (
                    "display-panic-last-frame->framebuffer-object",
                    ContractObjectKind::FramebufferObject,
                    frame.framebuffer,
                    frame.framebuffer_generation,
                ),
                (
                    "display-panic-last-frame->snapshot-barrier",
                    ContractObjectKind::DisplaySnapshotBarrier,
                    frame.display_snapshot_barrier,
                    frame.display_snapshot_barrier_generation,
                ),
                (
                    "display-panic-last-frame->display-event-log",
                    ContractObjectKind::DisplayEventLog,
                    frame.display_event_log,
                    frame.display_event_log_generation,
                ),
                (
                    "display-panic-last-frame->framebuffer-write",
                    ContractObjectKind::FramebufferWrite,
                    frame.framebuffer_write,
                    frame.framebuffer_write_generation,
                ),
                (
                    "display-panic-last-frame->framebuffer-flush-region",
                    ContractObjectKind::FramebufferFlushRegion,
                    frame.framebuffer_flush_region,
                    frame.framebuffer_flush_region_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(barrier) = snapshot.display_snapshot_barriers.iter().find(|barrier| {
                barrier.id == frame.display_snapshot_barrier
                    && barrier.generation == frame.display_snapshot_barrier_generation
            }) {
                if barrier.owner_store != frame.owner_store
                    || barrier.owner_store_generation != frame.owner_store_generation
                    || barrier.display != frame.display
                    || barrier.display_generation != frame.display_generation
                    || barrier.framebuffer != frame.framebuffer
                    || barrier.framebuffer_generation != frame.framebuffer_generation
                    || barrier.state != DisplaySnapshotBarrierState::Validated
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-panic-last-frame->snapshot-barrier-binding",
                        from,
                        Some(barrier.object_ref()),
                        "display panic last-frame barrier does not match frame target",
                    ));
                }
            }
            if let Some(event_log) = snapshot.display_event_logs.iter().find(|event_log| {
                event_log.id == frame.display_event_log
                    && event_log.generation == frame.display_event_log_generation
            }) {
                if event_log.owner_store != frame.owner_store
                    || event_log.owner_store_generation != frame.owner_store_generation
                    || event_log.display != frame.display
                    || event_log.display_generation != frame.display_generation
                    || event_log.framebuffer != frame.framebuffer
                    || event_log.framebuffer_generation != frame.framebuffer_generation
                    || event_log.flush_count == 0
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-panic-last-frame->event-log-binding",
                        from,
                        Some(event_log.object_ref()),
                        "display panic last-frame event log does not match frame target",
                    ));
                }
            }
            if let Some(write) = snapshot.framebuffer_writes.iter().find(|write| {
                write.id == frame.framebuffer_write
                    && write.generation == frame.framebuffer_write_generation
            }) {
                if write.owner_store != frame.owner_store
                    || write.owner_store_generation != frame.owner_store_generation
                    || write.display != frame.display
                    || write.display_generation != frame.display_generation
                    || write.framebuffer != frame.framebuffer
                    || write.framebuffer_generation != frame.framebuffer_generation
                    || write.x != frame.x
                    || write.y != frame.y
                    || write.width != frame.width
                    || write.height != frame.height
                    || write.byte_offset != frame.byte_offset
                    || write.byte_len != frame.byte_len
                    || write.pixel_format != frame.pixel_format
                    || write.payload_digest != frame.payload_digest
                    || write.state != FramebufferWriteState::Applied
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-panic-last-frame->write-binding",
                        from,
                        Some(write.object_ref()),
                        "display panic last-frame write does not match frame target",
                    ));
                }
            }
            if let Some(flush) = snapshot.framebuffer_flush_regions.iter().find(|flush| {
                flush.id == frame.framebuffer_flush_region
                    && flush.generation == frame.framebuffer_flush_region_generation
            }) {
                if flush.owner_store != frame.owner_store
                    || flush.owner_store_generation != frame.owner_store_generation
                    || flush.framebuffer_write != frame.framebuffer_write
                    || flush.framebuffer_write_generation != frame.framebuffer_write_generation
                    || flush.display != frame.display
                    || flush.display_generation != frame.display_generation
                    || flush.framebuffer != frame.framebuffer
                    || flush.framebuffer_generation != frame.framebuffer_generation
                    || flush.x != frame.x
                    || flush.y != frame.y
                    || flush.width != frame.width
                    || flush.height != frame.height
                    || flush.byte_offset != frame.byte_offset
                    || flush.byte_len != frame.byte_len
                    || flush.pixel_format != frame.pixel_format
                    || flush.payload_digest != frame.payload_digest
                    || flush.state != FramebufferFlushRegionState::Applied
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "display-panic-last-frame->flush-binding",
                        from,
                        Some(flush.object_ref()),
                        "display panic last-frame flush does not match frame target",
                    ));
                }
            }
        }
    }

    fn validate_framebuffer_benchmarks(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for benchmark in &snapshot.framebuffer_benchmarks {
            let from = benchmark.object_ref();
            if benchmark.id == 0
                || benchmark.generation == 0
                || benchmark.scenario.is_empty()
                || benchmark.owner_store_generation == 0
                || benchmark.display_generation == 0
                || benchmark.framebuffer_generation == 0
                || benchmark.display_capability_generation == 0
                || benchmark.framebuffer_write_generation == 0
                || benchmark.framebuffer_flush_region_generation == 0
                || benchmark.display_event_log_generation == 0
                || benchmark.display_snapshot_barrier_generation == 0
                || benchmark.sample_frames == 0
                || benchmark.sample_bytes == 0
                || benchmark.frame_area_pixels == 0
                || benchmark.write_nanos == 0
                || benchmark.flush_nanos == 0
                || benchmark.write_nanos.checked_add(benchmark.flush_nanos)
                    != Some(benchmark.measured_nanos)
                || benchmark.measured_nanos == 0
                || benchmark.budget_nanos == 0
                || benchmark.measured_nanos > benchmark.budget_nanos
                || benchmark.p50_latency_nanos == 0
                || benchmark.p99_latency_nanos < benchmark.p50_latency_nanos
                || benchmark.p99_latency_nanos > benchmark.measured_nanos
                || benchmark.state != FramebufferBenchmarkState::Recorded
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-benchmark->contract",
                    from,
                    None,
                    "framebuffer benchmark requires exact refs, bounded timing, and recorded state",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "framebuffer-benchmark->owner-store",
                    ContractObjectKind::Store,
                    benchmark.owner_store,
                    benchmark.owner_store_generation,
                ),
                (
                    "framebuffer-benchmark->display-object",
                    ContractObjectKind::DisplayObject,
                    benchmark.display,
                    benchmark.display_generation,
                ),
                (
                    "framebuffer-benchmark->framebuffer-object",
                    ContractObjectKind::FramebufferObject,
                    benchmark.framebuffer,
                    benchmark.framebuffer_generation,
                ),
                (
                    "framebuffer-benchmark->display-capability",
                    ContractObjectKind::DisplayCapability,
                    benchmark.display_capability,
                    benchmark.display_capability_generation,
                ),
                (
                    "framebuffer-benchmark->framebuffer-write",
                    ContractObjectKind::FramebufferWrite,
                    benchmark.framebuffer_write,
                    benchmark.framebuffer_write_generation,
                ),
                (
                    "framebuffer-benchmark->framebuffer-flush-region",
                    ContractObjectKind::FramebufferFlushRegion,
                    benchmark.framebuffer_flush_region,
                    benchmark.framebuffer_flush_region_generation,
                ),
                (
                    "framebuffer-benchmark->display-event-log",
                    ContractObjectKind::DisplayEventLog,
                    benchmark.display_event_log,
                    benchmark.display_event_log_generation,
                ),
                (
                    "framebuffer-benchmark->display-snapshot-barrier",
                    ContractObjectKind::DisplaySnapshotBarrier,
                    benchmark.display_snapshot_barrier,
                    benchmark.display_snapshot_barrier_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            let expected_throughput = SemanticGraph::derive_framebuffer_throughput_bytes_per_sec(
                benchmark.sample_bytes,
                benchmark.measured_nanos,
            );
            let expected_flushes = SemanticGraph::derive_framebuffer_flushes_per_sec_milli(
                benchmark.sample_frames,
                benchmark.measured_nanos,
            );
            if expected_throughput != Some(benchmark.throughput_bytes_per_sec)
                || expected_flushes != Some(benchmark.flushes_per_sec_milli)
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "framebuffer-benchmark->metrics",
                    from,
                    None,
                    "framebuffer benchmark derived metrics do not match samples and timing",
                ));
            }
            if let Some(write) = snapshot.framebuffer_writes.iter().find(|write| {
                write.id == benchmark.framebuffer_write
                    && write.generation == benchmark.framebuffer_write_generation
            }) {
                if write.owner_store != benchmark.owner_store
                    || write.owner_store_generation != benchmark.owner_store_generation
                    || write.display_capability != benchmark.display_capability
                    || write.display_capability_generation
                        != benchmark.display_capability_generation
                    || write.display != benchmark.display
                    || write.display_generation != benchmark.display_generation
                    || write.framebuffer != benchmark.framebuffer
                    || write.framebuffer_generation != benchmark.framebuffer_generation
                    || write.state != FramebufferWriteState::Applied
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-benchmark->write-binding",
                        from,
                        Some(write.object_ref()),
                        "framebuffer benchmark write does not match display target",
                    ));
                }
            }
            if let Some(flush) = snapshot.framebuffer_flush_regions.iter().find(|flush| {
                flush.id == benchmark.framebuffer_flush_region
                    && flush.generation == benchmark.framebuffer_flush_region_generation
            }) {
                if flush.owner_store != benchmark.owner_store
                    || flush.owner_store_generation != benchmark.owner_store_generation
                    || flush.framebuffer_write != benchmark.framebuffer_write
                    || flush.framebuffer_write_generation != benchmark.framebuffer_write_generation
                    || flush.display_capability != benchmark.display_capability
                    || flush.display_capability_generation
                        != benchmark.display_capability_generation
                    || flush.display != benchmark.display
                    || flush.display_generation != benchmark.display_generation
                    || flush.framebuffer != benchmark.framebuffer
                    || flush.framebuffer_generation != benchmark.framebuffer_generation
                    || flush
                        .byte_len
                        .checked_mul(u64::from(benchmark.sample_frames))
                        != Some(benchmark.sample_bytes)
                    || u64::from(flush.width).checked_mul(u64::from(flush.height))
                        != Some(benchmark.frame_area_pixels)
                    || flush.state != FramebufferFlushRegionState::Applied
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-benchmark->flush-binding",
                        from,
                        Some(flush.object_ref()),
                        "framebuffer benchmark flush does not match sampled frame",
                    ));
                }
            }
            if let Some(event_log) = snapshot.display_event_logs.iter().find(|event_log| {
                event_log.id == benchmark.display_event_log
                    && event_log.generation == benchmark.display_event_log_generation
            }) {
                if event_log.owner_store != benchmark.owner_store
                    || event_log.owner_store_generation != benchmark.owner_store_generation
                    || event_log.display_capability != benchmark.display_capability
                    || event_log.display_capability_generation
                        != benchmark.display_capability_generation
                    || event_log.display != benchmark.display
                    || event_log.display_generation != benchmark.display_generation
                    || event_log.framebuffer != benchmark.framebuffer
                    || event_log.framebuffer_generation != benchmark.framebuffer_generation
                    || event_log.flush_count < u64::from(benchmark.sample_frames)
                    || event_log.state != DisplayEventLogState::Recorded
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-benchmark->event-log-binding",
                        from,
                        Some(event_log.object_ref()),
                        "framebuffer benchmark event log does not cover the sampled flush",
                    ));
                }
            }
            if let Some(barrier) = snapshot.display_snapshot_barriers.iter().find(|barrier| {
                barrier.id == benchmark.display_snapshot_barrier
                    && barrier.generation == benchmark.display_snapshot_barrier_generation
            }) {
                if barrier.owner_store != benchmark.owner_store
                    || barrier.owner_store_generation != benchmark.owner_store_generation
                    || barrier.display != benchmark.display
                    || barrier.display_generation != benchmark.display_generation
                    || barrier.framebuffer != benchmark.framebuffer
                    || barrier.framebuffer_generation != benchmark.framebuffer_generation
                    || barrier.active_framebuffer_window_lease_count != 0
                    || barrier.active_framebuffer_mapping_count != 0
                    || barrier.dirty_framebuffer_region_count != 0
                    || barrier.state != DisplaySnapshotBarrierState::Validated
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "framebuffer-benchmark->snapshot-barrier-binding",
                        from,
                        Some(barrier.object_ref()),
                        "framebuffer benchmark snapshot barrier is not quiescent for the display target",
                    ));
                }
            }
        }
    }

    fn validate_integrated_smp_preemption_cleanups(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_smp_preemption_cleanups {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSmpPreemptionCleanupState::Recorded
                || record.stress_run_generation == 0
                || record.preemption_generation == 0
                || record.timer_interrupt_generation == 0
                || record.saved_context_generation == 0
                || record.remote_preempt_generation == 0
                || record.activation_cleanup_generation == 0
                || record.smp_cleanup_quiescence_generation == 0
                || record.target_store_generation == 0
                || record.result_store_generation <= record.target_store_generation
                || record.cleanup_activation_generation_after == 0
                || record.hart_count < 2
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-smp-preemption-cleanup->contract",
                    from,
                    None,
                    "integrated SMP/preemption/cleanup evidence requires exact refs, 2+ harts, completed cleanup, and recorded state",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-smp-preemption-cleanup->smp-stress-run",
                    ContractObjectKind::SmpStressRun,
                    record.stress_run,
                    record.stress_run_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->preemption",
                    ContractObjectKind::Preemption,
                    record.preemption,
                    record.preemption_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->timer-interrupt",
                    ContractObjectKind::TimerInterrupt,
                    record.timer_interrupt,
                    record.timer_interrupt_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->saved-context",
                    ContractObjectKind::SavedContext,
                    record.saved_context,
                    record.saved_context_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->remote-preempt",
                    ContractObjectKind::RemotePreempt,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->activation-cleanup",
                    ContractObjectKind::ActivationCleanup,
                    record.activation_cleanup,
                    record.activation_cleanup_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->smp-cleanup-quiescence",
                    ContractObjectKind::SmpCleanupQuiescence,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->cleanup-store",
                    ContractObjectKind::Store,
                    record.cleanup_store,
                    record.target_store_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(preemption) = snapshot.preemptions.iter().find(|preemption| {
                preemption.id == record.preemption
                    && preemption.generation == record.preemption_generation
            }) {
                if preemption.state != PreemptionState::Applied
                    || preemption.timer_interrupt != record.timer_interrupt
                    || preemption.timer_interrupt_generation != record.timer_interrupt_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-preemption-cleanup->preemption-binding",
                        from,
                        Some(preemption.object_ref()),
                        "integrated evidence preemption does not match timer attribution",
                    ));
                }
            }
            if let Some(saved) = snapshot.saved_contexts.iter().find(|saved| {
                saved.id == record.saved_context
                    && saved.generation == record.saved_context_generation
            }) {
                if saved.state == SavedContextState::Dropped
                    || saved.source_preemption != Some(record.preemption)
                    || saved.source_preemption_generation != Some(record.preemption_generation)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-preemption-cleanup->saved-context-binding",
                        from,
                        Some(saved.object_ref()),
                        "integrated evidence saved context is not attributed to the preemption",
                    ));
                }
            }
            if let Some(remote) = snapshot.remote_preempts.iter().find(|remote| {
                remote.id == record.remote_preempt
                    && remote.generation == record.remote_preempt_generation
            }) {
                if remote.state != RemotePreemptState::Applied
                    || remote.source_hart == remote.target_hart
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-preemption-cleanup->remote-preempt-binding",
                        from,
                        Some(remote.object_ref()),
                        "integrated evidence remote preempt is not cross-hart applied evidence",
                    ));
                }
            }
            if let Some(cleanup) = snapshot.activation_cleanups.iter().find(|cleanup| {
                cleanup.id == record.activation_cleanup
                    && cleanup.generation == record.activation_cleanup_generation
            }) {
                if cleanup.state != ActivationCleanupState::Completed
                    || cleanup.store != record.cleanup_store
                    || cleanup.target_store_generation != record.target_store_generation
                    || cleanup.result_store_generation != record.result_store_generation
                    || cleanup.activation != record.cleanup_activation
                    || cleanup.activation_generation_after
                        != record.cleanup_activation_generation_after
                    || cleanup.wait.is_none()
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-preemption-cleanup->cleanup-binding",
                        from,
                        Some(cleanup.object_ref()),
                        "integrated evidence cleanup does not prove completed wait-cancelling store cleanup",
                    ));
                }
            }
            if let Some(quiescence) = snapshot.smp_cleanup_quiescence.iter().find(|quiescence| {
                quiescence.id == record.smp_cleanup_quiescence
                    && quiescence.generation == record.smp_cleanup_quiescence_generation
            }) {
                if quiescence.state != SmpCleanupQuiescenceState::Validated
                    || quiescence.cleanup != record.activation_cleanup
                    || quiescence.cleanup_generation != record.activation_cleanup_generation
                    || quiescence.store != record.cleanup_store
                    || quiescence.target_store_generation != record.target_store_generation
                    || quiescence.result_store_generation != record.result_store_generation
                    || quiescence.participants.len() < 2
                    || !quiescence.no_running_activation
                    || !quiescence.no_pending_wait
                    || !quiescence.no_live_capability
                    || !quiescence.no_live_resource
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-preemption-cleanup->quiescence-binding",
                        from,
                        Some(quiescence.object_ref()),
                        "integrated evidence quiescence does not close the cleanup boundary",
                    ));
                }
            }
        }
    }

    fn validate_integrated_smp_network_faults(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_smp_network_faults {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSmpNetworkFaultState::Recorded
                || record.network_driver_cleanup_generation == 0
                || record.smp_stress_run_generation == 0
                || record.remote_preempt_generation == 0
                || record.smp_cleanup_quiescence_generation == 0
                || record.driver_store_generation == 0
                || record.packet_device_generation == 0
                || record.adapter_generation == 0
                || record.backend.generation == 0
                || record.io_cleanup_generation == 0
                || record.cancelled_socket_wait_count == 0
                || record.cancelled_wait_token_count == 0
                || record.revoked_packet_capability_count == 0
                || record.hart_count < 2
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-smp-network-fault->contract",
                    from,
                    None,
                    "integrated SMP/network-fault evidence requires exact refs, completed network cleanup effects, 2+ harts, and recorded state",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-smp-network-fault->network-driver-cleanup",
                    ContractObjectKind::NetworkDriverCleanup,
                    record.network_driver_cleanup,
                    record.network_driver_cleanup_generation,
                ),
                (
                    "integrated-smp-network-fault->smp-stress-run",
                    ContractObjectKind::SmpStressRun,
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                ),
                (
                    "integrated-smp-network-fault->remote-preempt",
                    ContractObjectKind::RemotePreempt,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                ),
                (
                    "integrated-smp-network-fault->smp-cleanup-quiescence",
                    ContractObjectKind::SmpCleanupQuiescence,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                ),
                (
                    "integrated-smp-network-fault->packet-device",
                    ContractObjectKind::PacketDeviceObject,
                    record.packet_device,
                    record.packet_device_generation,
                ),
                (
                    "integrated-smp-network-fault->network-stack-adapter",
                    ContractObjectKind::NetworkStackAdapter,
                    record.adapter,
                    record.adapter_generation,
                ),
                (
                    "integrated-smp-network-fault->io-cleanup",
                    ContractObjectKind::IoCleanup,
                    record.io_cleanup,
                    record.io_cleanup_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "integrated-smp-network-fault->backend",
                record.backend.kind,
                record.backend.id,
                record.backend.generation,
                ContractEdgeMode::Historical,
            );
            if let Some(cleanup) = snapshot.network_driver_cleanups.iter().find(|cleanup| {
                cleanup.id == record.network_driver_cleanup
                    && cleanup.generation == record.network_driver_cleanup_generation
            }) {
                if cleanup.state != NetworkDriverCleanupState::Completed
                    || cleanup.driver_store != record.driver_store
                    || cleanup.driver_store_generation != record.driver_store_generation
                    || cleanup.packet_device != record.packet_device
                    || cleanup.packet_device_generation != record.packet_device_generation
                    || cleanup.adapter != record.adapter
                    || cleanup.adapter_generation != record.adapter_generation
                    || cleanup.backend != record.backend
                    || cleanup.io_cleanup != record.io_cleanup
                    || cleanup.io_cleanup_generation != record.io_cleanup_generation
                    || cleanup.cancelled_socket_waits.len() as u32
                        != record.cancelled_socket_wait_count
                    || cleanup.cancelled_wait_tokens.len() as u32
                        != record.cancelled_wait_token_count
                    || cleanup.revoked_packet_capabilities.len() as u32
                        != record.revoked_packet_capability_count
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-network-fault->network-cleanup-binding",
                        from,
                        Some(cleanup.object_ref()),
                        "integrated evidence network cleanup does not match recorded closure effects",
                    ));
                }
            }
            if let Some(stress) = snapshot.smp_stress_runs.iter().find(|run| {
                run.id == record.smp_stress_run
                    && run.generation == record.smp_stress_run_generation
            }) {
                if stress.state != SmpStressRunState::Recorded
                    || stress.property_failures != 0
                    || stress.hart_count != record.hart_count
                    || stress.hart_count < 2
                    || stress.observed_remote_preempt_count == 0
                    || stress.observed_cleanup_quiescence_count == 0
                    || stress.last_remote_preempt != record.remote_preempt
                    || stress.last_remote_preempt_generation != record.remote_preempt_generation
                    || stress.last_cleanup_quiescence != record.smp_cleanup_quiescence
                    || stress.last_cleanup_quiescence_generation
                        != record.smp_cleanup_quiescence_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-network-fault->smp-stress-binding",
                        from,
                        Some(stress.object_ref()),
                        "integrated evidence stress run does not prove cross-hart cleanup context",
                    ));
                }
            }
            if let Some(remote) = snapshot.remote_preempts.iter().find(|remote| {
                remote.id == record.remote_preempt
                    && remote.generation == record.remote_preempt_generation
            }) {
                if remote.state != RemotePreemptState::Applied
                    || remote.source_hart == remote.target_hart
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-network-fault->remote-preempt-binding",
                        from,
                        Some(remote.object_ref()),
                        "integrated evidence remote preempt is not cross-hart applied evidence",
                    ));
                }
            }
            if let Some(quiescence) = snapshot.smp_cleanup_quiescence.iter().find(|quiescence| {
                quiescence.id == record.smp_cleanup_quiescence
                    && quiescence.generation == record.smp_cleanup_quiescence_generation
            }) {
                if quiescence.state != SmpCleanupQuiescenceState::Validated
                    || quiescence.participants.len() < 2
                    || quiescence
                        .participants
                        .iter()
                        .any(|participant| !participant.quiesced)
                    || !quiescence.no_running_activation
                    || !quiescence.no_pending_wait
                    || !quiescence.no_live_capability
                    || !quiescence.no_live_resource
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-network-fault->quiescence-binding",
                        from,
                        Some(quiescence.object_ref()),
                        "integrated evidence quiescence does not prove an SMP-safe fault context",
                    ));
                }
            }
        }
    }

    fn validate_integrated_disk_preempt_faults(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_disk_preempt_faults {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedDiskPreemptFaultState::Recorded
                || record.preemption_generation == 0
                || record.timer_interrupt_generation == 0
                || record.block_pending_io_policy_generation == 0
                || record.block_wait_generation == 0
                || record.wait_generation == 0
                || record.block_request_generation == 0
                || record.block_device_generation == 0
                || record.block_range_generation == 0
                || record.preempted_activation_generation_after == 0
                || record.invariant_checks == 0
                || record.errno <= 0
                || record.action == BlockPendingIoAction::Cancel
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-disk-preempt-fault->contract",
                    from,
                    None,
                    "integrated disk/preempt fault evidence requires exact refs, applied preemption, cancelled block wait, and retry/EIO policy",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-disk-preempt-fault->preemption",
                    ContractObjectKind::Preemption,
                    record.preemption,
                    record.preemption_generation,
                ),
                (
                    "integrated-disk-preempt-fault->timer-interrupt",
                    ContractObjectKind::TimerInterrupt,
                    record.timer_interrupt,
                    record.timer_interrupt_generation,
                ),
                (
                    "integrated-disk-preempt-fault->block-pending-io-policy",
                    ContractObjectKind::BlockPendingIoPolicy,
                    record.block_pending_io_policy,
                    record.block_pending_io_policy_generation,
                ),
                (
                    "integrated-disk-preempt-fault->block-wait",
                    ContractObjectKind::BlockWait,
                    record.block_wait,
                    record.block_wait_generation,
                ),
                (
                    "integrated-disk-preempt-fault->wait",
                    ContractObjectKind::WaitToken,
                    record.wait,
                    record.wait_generation,
                ),
                (
                    "integrated-disk-preempt-fault->block-request",
                    ContractObjectKind::BlockRequestObject,
                    record.block_request,
                    record.block_request_generation,
                ),
                (
                    "integrated-disk-preempt-fault->block-device",
                    ContractObjectKind::BlockDeviceObject,
                    record.block_device,
                    record.block_device_generation,
                ),
                (
                    "integrated-disk-preempt-fault->block-range",
                    ContractObjectKind::BlockRangeObject,
                    record.block_range,
                    record.block_range_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let (Some(retry_request), Some(retry_generation)) =
                (record.retry_request, record.retry_request_generation)
            {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "integrated-disk-preempt-fault->retry-request",
                    ContractObjectKind::BlockRequestObject,
                    retry_request,
                    retry_generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(preemption) = snapshot.preemptions.iter().find(|preemption| {
                preemption.id == record.preemption
                    && preemption.generation == record.preemption_generation
            }) {
                if preemption.state != PreemptionState::Applied
                    || preemption.timer_interrupt != record.timer_interrupt
                    || preemption.timer_interrupt_generation != record.timer_interrupt_generation
                    || preemption.activation != record.preempted_activation
                    || preemption.activation_generation_after
                        != record.preempted_activation_generation_after
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->preemption-binding",
                        from,
                        Some(preemption.object_ref()),
                        "integrated disk/preempt fault preemption attribution does not match the recorded preempted activation",
                    ));
                }
            }
            if let Some(timer) = snapshot.timer_interrupts.iter().find(|timer| {
                timer.id == record.timer_interrupt
                    && timer.generation == record.timer_interrupt_generation
            }) {
                if timer.state != TimerInterruptState::Recorded
                    || timer.target_activation != Some(record.preempted_activation)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->timer-binding",
                        from,
                        Some(timer.object_ref()),
                        "integrated disk/preempt fault timer interrupt does not target the preempted activation",
                    ));
                }
            }
            if let Some(policy) = snapshot.block_pending_io_policies.iter().find(|policy| {
                policy.id == record.block_pending_io_policy
                    && policy.generation == record.block_pending_io_policy_generation
            }) {
                let expected_state = match record.action {
                    BlockPendingIoAction::Retry => BlockPendingIoPolicyState::RetryScheduled,
                    BlockPendingIoAction::Eio => BlockPendingIoPolicyState::EioReturned,
                    BlockPendingIoAction::Cancel => BlockPendingIoPolicyState::Cancelled,
                };
                if policy.state != expected_state
                    || policy.action != record.action
                    || policy.errno != record.errno
                    || policy.block_wait != record.block_wait
                    || policy.block_wait_generation != record.block_wait_generation
                    || policy.wait != record.wait
                    || policy.wait_generation != record.wait_generation
                    || policy.block_request != record.block_request
                    || policy.block_request_generation != record.block_request_generation
                    || policy.retry_request != record.retry_request
                    || policy.retry_request_generation != record.retry_request_generation
                    || policy.block_device != record.block_device
                    || policy.block_device_generation != record.block_device_generation
                    || policy.block_range != record.block_range
                    || policy.block_range_generation != record.block_range_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->policy-binding",
                        from,
                        Some(policy.object_ref()),
                        "integrated disk/preempt fault policy binding does not match recorded pending IO fault evidence",
                    ));
                }
            }
            if let Some(block_wait) = snapshot.block_waits.iter().find(|wait| {
                wait.id == record.block_wait && wait.generation == record.block_wait_generation
            }) {
                if block_wait.state != BlockWaitState::Cancelled
                    || block_wait.cancel_reason != Some(WaitCancelReason::DeviceFault)
                    || block_wait.wait != record.wait
                    || block_wait.wait_generation != record.wait_generation
                    || block_wait.block_request != record.block_request
                    || block_wait.block_request_generation != record.block_request_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->block-wait-binding",
                        from,
                        Some(block_wait.object_ref()),
                        "integrated disk/preempt fault block wait is not the cancelled device-fault wait",
                    ));
                }
            }
            if let Some(wait) = snapshot
                .waits
                .iter()
                .find(|wait| wait.id == record.wait && wait.generation == record.wait_generation)
            {
                if wait.state != WaitState::Cancelled
                    || wait.cancel_reason != Some(WaitCancelReason::DeviceFault)
                    || wait.owner_store != record.driver_store
                    || wait.owner_store_generation != record.driver_store_generation
                    || !wait.blockers.iter().any(|blocker| {
                        *blocker
                            == ContractObjectRef::new(
                                ContractObjectKind::BlockRequestObject,
                                record.block_request,
                                record.block_request_generation,
                            )
                    })
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->wait-binding",
                        from,
                        Some(wait.object_ref()),
                        "integrated disk/preempt fault wait token does not carry the cancelled block request blocker",
                    ));
                }
            }
            if let Some(request) = snapshot.block_request_objects.iter().find(|request| {
                request.id == record.block_request
                    && request.generation == record.block_request_generation
            }) {
                if request.block_device != record.block_device
                    || request.block_device_generation != record.block_device_generation
                    || request.block_range != record.block_range
                    || request.block_range_generation != record.block_range_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->request-binding",
                        from,
                        Some(request.object_ref()),
                        "integrated disk/preempt fault request does not match block device/range refs",
                    ));
                }
            }
            if snapshot.block_waits.iter().any(|wait| {
                wait.block_request == record.block_request
                    && wait.block_request_generation == record.block_request_generation
                    && wait.state == BlockWaitState::Pending
            }) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::LiveObjectReferencesDeadObject,
                    "integrated-disk-preempt-fault->pending-wait-leak",
                    from,
                    Some(ContractObjectRef::new(
                        ContractObjectKind::BlockRequestObject,
                        record.block_request,
                        record.block_request_generation,
                    )),
                    "integrated disk/preempt fault cannot leave the faulted block request pending",
                ));
            }
        }
    }

    fn validate_integrated_simd_migrations(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_simd_migrations {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSimdMigrationState::Recorded
                || record.activation_migration_generation == 0
                || record.target_feature_set_generation == 0
                || record.source_vector_state.generation == 0
                || record.migrated_vector_state.generation == 0
                || record.activation_generation_before == 0
                || record.activation_generation_after <= record.activation_generation_before
                || record.context_generation_after == 0
                || record.source_hart_generation == 0
                || record.target_hart_generation == 0
                || record.source_hart == record.target_hart
                || record.source_queue_generation == 0
                || record.target_queue_generation == 0
                || record.simd_abi.is_empty()
                || record.vector_register_count == 0
                || record.vector_register_bits == 0
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-simd-migration->contract",
                    from,
                    None,
                    "integrated SIMD migration requires exact refs and clean cross-hart vector migration evidence",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-simd-migration->activation-migration",
                    ContractObjectKind::ActivationMigration,
                    record.activation_migration,
                    record.activation_migration_generation,
                ),
                (
                    "integrated-simd-migration->target-feature-set",
                    ContractObjectKind::TargetFeatureSet,
                    record.target_feature_set,
                    record.target_feature_set_generation,
                ),
                (
                    "integrated-simd-migration->activation-before",
                    ContractObjectKind::Activation,
                    record.activation,
                    record.activation_generation_before,
                ),
                (
                    "integrated-simd-migration->activation-after",
                    ContractObjectKind::Activation,
                    record.activation,
                    record.activation_generation_after,
                ),
                (
                    "integrated-simd-migration->source-hart",
                    ContractObjectKind::Hart,
                    u64::from(record.source_hart),
                    record.source_hart_generation,
                ),
                (
                    "integrated-simd-migration->target-hart",
                    ContractObjectKind::Hart,
                    u64::from(record.target_hart),
                    record.target_hart_generation,
                ),
                (
                    "integrated-simd-migration->source-queue",
                    ContractObjectKind::RunnableQueue,
                    record.source_queue,
                    record.source_queue_generation,
                ),
                (
                    "integrated-simd-migration->target-queue",
                    ContractObjectKind::RunnableQueue,
                    record.target_queue,
                    record.target_queue_generation,
                ),
                (
                    "integrated-simd-migration->context",
                    ContractObjectKind::ActivationContext,
                    record.context,
                    record.context_generation_after,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            for (label, object) in [
                (
                    "integrated-simd-migration->source-vector-state",
                    record.source_vector_state,
                ),
                (
                    "integrated-simd-migration->migrated-vector-state",
                    record.migrated_vector_state,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    object.kind,
                    object.id,
                    object.generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(migration) = snapshot.activation_migrations.iter().find(|migration| {
                migration.id == record.activation_migration
                    && migration.generation == record.activation_migration_generation
            }) {
                if migration.state != ActivationMigrationState::Applied
                    || migration.source_hart == migration.target_hart
                    || migration.activation != record.activation
                    || migration.activation_generation_before != record.activation_generation_before
                    || migration.activation_generation_after != record.activation_generation_after
                    || migration.source_hart != record.source_hart
                    || migration.source_hart_generation != record.source_hart_generation
                    || migration.target_hart != record.target_hart
                    || migration.target_hart_generation != record.target_hart_generation
                    || migration.source_queue != record.source_queue
                    || migration.source_queue_generation != record.source_queue_generation
                    || migration.target_queue != record.target_queue
                    || migration.target_queue_generation != record.target_queue_generation
                    || migration.context != Some(record.context)
                    || migration.context_generation_after != Some(record.context_generation_after)
                    || migration.source_vector_state != Some(record.source_vector_state)
                    || migration.migrated_vector_state != Some(record.migrated_vector_state)
                    || migration.vector_status != ActivationVectorState::Clean
                    || migration.vector_migrated_at_event.is_none()
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-simd-migration->activation-migration-binding",
                        from,
                        Some(migration.object_ref()),
                        "integrated SIMD migration activation migration binding does not match clean cross-hart vector evidence",
                    ));
                }
            }
            if let Some(feature) = snapshot.target_feature_sets.iter().find(|feature| {
                feature.id == record.target_feature_set
                    && feature.generation == record.target_feature_set_generation
            }) {
                if feature.state != TargetFeatureSetState::Discovered
                    || !feature.simd_supported
                    || feature.simd_abi != record.simd_abi
                    || feature.vector_register_count != record.vector_register_count
                    || feature.vector_register_bits != record.vector_register_bits
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-simd-migration->target-feature-binding",
                        from,
                        Some(feature.object_ref()),
                        "integrated SIMD migration target feature set does not support the recorded vector shape",
                    ));
                }
            }
            let source = snapshot.vector_states.iter().find(|vector| {
                vector.id == record.source_vector_state.id
                    && vector.generation == record.source_vector_state.generation
            });
            let migrated = snapshot.vector_states.iter().find(|vector| {
                vector.id == record.migrated_vector_state.id
                    && vector.generation == record.migrated_vector_state.generation
            });
            if let (Some(source), Some(migrated)) = (source, migrated) {
                if source.state != VectorStateState::Dropped
                    || migrated.state != VectorStateState::Reserved
                    || source.owner_activation
                        != ContractObjectRef::new(
                            ContractObjectKind::Activation,
                            record.activation,
                            record.activation_generation_before,
                        )
                    || migrated.owner_activation
                        != ContractObjectRef::new(
                            ContractObjectKind::Activation,
                            record.activation,
                            record.activation_generation_after,
                        )
                    || source.target_feature_set
                        != ContractObjectRef::new(
                            ContractObjectKind::TargetFeatureSet,
                            record.target_feature_set,
                            record.target_feature_set_generation,
                        )
                    || migrated.target_feature_set != source.target_feature_set
                    || source.simd_abi != record.simd_abi
                    || migrated.simd_abi != record.simd_abi
                    || source.vector_register_count != record.vector_register_count
                    || migrated.vector_register_count != record.vector_register_count
                    || source.vector_register_bits != record.vector_register_bits
                    || migrated.vector_register_bits != record.vector_register_bits
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-simd-migration->vector-binding",
                        from,
                        Some(migrated.object_ref()),
                        "integrated SIMD migration source/migrated vector state refs do not prove clean rehome semantics",
                    ));
                }
            }
            if let Some(context) = snapshot.activation_contexts.iter().find(|context| {
                context.id == record.context
                    && context.generation == record.context_generation_after
            }) {
                if context.activation != record.activation
                    || context.activation_generation != record.activation_generation_after
                    || context.vector_state != Some(record.migrated_vector_state)
                    || context.vector_status != ActivationVectorState::Clean
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-simd-migration->context-binding",
                        from,
                        Some(context.object_ref()),
                        "integrated SIMD migration context must point at the clean migrated vector state",
                    ));
                }
            }
            if snapshot.vector_states.iter().any(|vector| {
                vector.owner_activation
                    == ContractObjectRef::new(
                        ContractObjectKind::Activation,
                        record.activation,
                        record.activation_generation_before,
                    )
                    && vector.state == VectorStateState::Reserved
            }) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::LiveObjectReferencesDeadObject,
                    "integrated-simd-migration->old-vector-live-leak",
                    from,
                    Some(ContractObjectRef::new(
                        ContractObjectKind::Activation,
                        record.activation,
                        record.activation_generation_before,
                    )),
                    "integrated SIMD migration cannot leave reserved vector state on the old activation generation",
                ));
            }
        }
    }

    fn validate_integrated_network_disk_ios(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_network_disk_ios {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedNetworkDiskIoState::Recorded
                || record.network_benchmark_generation == 0
                || record.block_benchmark_generation == 0
                || record.network_owner_store_generation == 0
                || record.network_adapter_generation == 0
                || record.packet_device_generation == 0
                || record.socket_generation == 0
                || record.block_backend.generation == 0
                || record.block_device_generation == 0
                || record.block_request_queue_generation == 0
                || record.block_dma_buffer_generation == 0
                || record.network_sample_bytes == 0
                || record.block_sample_bytes == 0
                || record.network_sample_packets == 0
                || record.block_sample_requests == 0
                || record.concurrent_window_nanos == 0
                || record.combined_throughput_bytes_per_sec == 0
                || record.max_p99_latency_nanos == 0
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-network-disk-io->contract",
                    from,
                    None,
                    "integrated network/disk IO requires exact benchmark refs and measured window evidence",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-network-disk-io->network-benchmark",
                    ContractObjectKind::NetworkBenchmark,
                    record.network_benchmark,
                    record.network_benchmark_generation,
                ),
                (
                    "integrated-network-disk-io->block-benchmark",
                    ContractObjectKind::BlockBenchmark,
                    record.block_benchmark,
                    record.block_benchmark_generation,
                ),
                (
                    "integrated-network-disk-io->network-owner-store",
                    ContractObjectKind::Store,
                    record.network_owner_store,
                    record.network_owner_store_generation,
                ),
                (
                    "integrated-network-disk-io->network-adapter",
                    ContractObjectKind::NetworkStackAdapter,
                    record.network_adapter,
                    record.network_adapter_generation,
                ),
                (
                    "integrated-network-disk-io->packet-device",
                    ContractObjectKind::PacketDeviceObject,
                    record.packet_device,
                    record.packet_device_generation,
                ),
                (
                    "integrated-network-disk-io->socket",
                    ContractObjectKind::SocketObject,
                    record.socket,
                    record.socket_generation,
                ),
                (
                    "integrated-network-disk-io->block-device",
                    ContractObjectKind::BlockDeviceObject,
                    record.block_device,
                    record.block_device_generation,
                ),
                (
                    "integrated-network-disk-io->block-request-queue",
                    ContractObjectKind::BlockRequestQueue,
                    record.block_request_queue,
                    record.block_request_queue_generation,
                ),
                (
                    "integrated-network-disk-io->block-dma-buffer",
                    ContractObjectKind::BlockDmaBuffer,
                    record.block_dma_buffer,
                    record.block_dma_buffer_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "integrated-network-disk-io->block-backend",
                record.block_backend.kind,
                record.block_backend.id,
                record.block_backend.generation,
                ContractEdgeMode::Historical,
            );
            let network = snapshot.network_benchmarks.iter().find(|benchmark| {
                benchmark.id == record.network_benchmark
                    && benchmark.generation == record.network_benchmark_generation
            });
            let block = snapshot.block_benchmarks.iter().find(|benchmark| {
                benchmark.id == record.block_benchmark
                    && benchmark.generation == record.block_benchmark_generation
            });
            if let (Some(network), Some(block)) = (network, block) {
                let total_bytes = network
                    .sample_bytes
                    .checked_add(block.sample_bytes)
                    .unwrap_or_default();
                let expected_window = network.measured_nanos.max(block.measured_nanos);
                let expected_throughput = if expected_window == 0 {
                    0
                } else {
                    total_bytes
                        .checked_mul(1_000_000_000)
                        .map(|scaled| scaled / expected_window)
                        .unwrap_or_default()
                };
                if network.state != NetworkBenchmarkState::Recorded
                    || block.state != BlockBenchmarkState::Recorded
                    || network.owner_store != record.network_owner_store
                    || network.owner_store_generation != record.network_owner_store_generation
                    || network.adapter != record.network_adapter
                    || network.adapter_generation != record.network_adapter_generation
                    || network.packet_device != record.packet_device
                    || network.packet_device_generation != record.packet_device_generation
                    || network.socket != record.socket
                    || network.socket_generation != record.socket_generation
                    || block.backend != record.block_backend
                    || block.block_device != record.block_device
                    || block.block_device_generation != record.block_device_generation
                    || block.request_queue != record.block_request_queue
                    || block.request_queue_generation != record.block_request_queue_generation
                    || block.block_dma_buffer != record.block_dma_buffer
                    || block.block_dma_buffer_generation != record.block_dma_buffer_generation
                    || network.sample_bytes != record.network_sample_bytes
                    || block.sample_bytes != record.block_sample_bytes
                    || network.sample_packets != record.network_sample_packets
                    || block.sample_requests != record.block_sample_requests
                    || record.concurrent_window_nanos != expected_window
                    || record.combined_throughput_bytes_per_sec != expected_throughput
                    || record.max_p99_latency_nanos
                        != network.p99_latency_nanos.max(block.p99_latency_nanos)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-network-disk-io->benchmark-binding",
                        from,
                        Some(network.object_ref()),
                        "integrated network/disk IO record does not match benchmark evidence",
                    ));
                }
            }
        }
    }

    fn validate_integrated_display_scheduler_loads(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_display_scheduler_loads {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedDisplaySchedulerLoadState::Recorded
                || record.framebuffer_benchmark_generation == 0
                || record.scheduler_decision_generation == 0
                || record.owner_store_generation == 0
                || record.owner_task_generation == 0
                || record.queue_generation == 0
                || record.selected_activation_generation == 0
                || record.display_generation == 0
                || record.framebuffer_generation == 0
                || record.display_capability_generation == 0
                || record.framebuffer_write_generation == 0
                || record.framebuffer_flush_region_generation == 0
                || record.display_event_log_generation == 0
                || record.sample_frames == 0
                || record.sample_bytes == 0
                || record.scheduler_load_units == 0
                || record.display_measured_nanos == 0
                || record.scheduler_decided_at_event == 0
                || record.display_recorded_at_event == 0
                || record.scheduler_decided_at_event > record.display_recorded_at_event
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-display-scheduler-load->contract",
                    from,
                    None,
                    "integrated display/scheduler load requires exact display benchmark and scheduler evidence",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-display-scheduler-load->framebuffer-benchmark",
                    ContractObjectKind::FramebufferBenchmark,
                    record.framebuffer_benchmark,
                    record.framebuffer_benchmark_generation,
                ),
                (
                    "integrated-display-scheduler-load->scheduler-decision",
                    ContractObjectKind::SchedulerDecision,
                    record.scheduler_decision,
                    record.scheduler_decision_generation,
                ),
                (
                    "integrated-display-scheduler-load->owner-store",
                    ContractObjectKind::Store,
                    record.owner_store,
                    record.owner_store_generation,
                ),
                (
                    "integrated-display-scheduler-load->runnable-queue",
                    ContractObjectKind::RunnableQueue,
                    record.queue,
                    record.queue_generation,
                ),
                (
                    "integrated-display-scheduler-load->display",
                    ContractObjectKind::DisplayObject,
                    record.display,
                    record.display_generation,
                ),
                (
                    "integrated-display-scheduler-load->framebuffer",
                    ContractObjectKind::FramebufferObject,
                    record.framebuffer,
                    record.framebuffer_generation,
                ),
                (
                    "integrated-display-scheduler-load->display-capability",
                    ContractObjectKind::DisplayCapability,
                    record.display_capability,
                    record.display_capability_generation,
                ),
                (
                    "integrated-display-scheduler-load->framebuffer-write",
                    ContractObjectKind::FramebufferWrite,
                    record.framebuffer_write,
                    record.framebuffer_write_generation,
                ),
                (
                    "integrated-display-scheduler-load->framebuffer-flush-region",
                    ContractObjectKind::FramebufferFlushRegion,
                    record.framebuffer_flush_region,
                    record.framebuffer_flush_region_generation,
                ),
                (
                    "integrated-display-scheduler-load->display-event-log",
                    ContractObjectKind::DisplayEventLog,
                    record.display_event_log,
                    record.display_event_log_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            let benchmark = snapshot.framebuffer_benchmarks.iter().find(|benchmark| {
                benchmark.id == record.framebuffer_benchmark
                    && benchmark.generation == record.framebuffer_benchmark_generation
            });
            let decision = snapshot.scheduler_decisions.iter().find(|decision| {
                decision.id == record.scheduler_decision
                    && decision.generation == record.scheduler_decision_generation
            });
            if let (Some(benchmark), Some(decision)) = (benchmark, decision) {
                if benchmark.state != FramebufferBenchmarkState::Recorded
                    || decision.state == SchedulerDecisionState::Dropped
                    || benchmark.owner_store != record.owner_store
                    || benchmark.owner_store_generation != record.owner_store_generation
                    || decision.owner_task != record.owner_task
                    || decision.owner_task_generation != record.owner_task_generation
                    || decision.queue != record.queue
                    || decision.queue_generation != record.queue_generation
                    || decision.selected_activation != record.selected_activation
                    || decision.selected_activation_generation
                        != record.selected_activation_generation
                    || benchmark.display != record.display
                    || benchmark.display_generation != record.display_generation
                    || benchmark.framebuffer != record.framebuffer
                    || benchmark.framebuffer_generation != record.framebuffer_generation
                    || benchmark.display_capability != record.display_capability
                    || benchmark.display_capability_generation
                        != record.display_capability_generation
                    || benchmark.framebuffer_write != record.framebuffer_write
                    || benchmark.framebuffer_write_generation != record.framebuffer_write_generation
                    || benchmark.framebuffer_flush_region != record.framebuffer_flush_region
                    || benchmark.framebuffer_flush_region_generation
                        != record.framebuffer_flush_region_generation
                    || benchmark.display_event_log != record.display_event_log
                    || benchmark.display_event_log_generation != record.display_event_log_generation
                    || benchmark.sample_frames != record.sample_frames
                    || benchmark.sample_bytes != record.sample_bytes
                    || benchmark.measured_nanos != record.display_measured_nanos
                    || decision.decided_at_event != record.scheduler_decided_at_event
                    || benchmark.recorded_at_event != record.display_recorded_at_event
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-display-scheduler-load->evidence-binding",
                        from,
                        Some(benchmark.object_ref()),
                        "integrated display/scheduler load record does not match source evidence",
                    ));
                }
            }
        }
    }

    fn validate_integrated_snapshot_io_lease_barriers(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_snapshot_io_lease_barriers {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSnapshotIoLeaseBarrierState::Recorded
                || record.smp_snapshot_barrier_generation == 0
                || record.io_cleanup_generation == 0
                || record.display_snapshot_barrier_generation == 0
                || record.driver_store_generation == 0
                || record.device_generation == 0
                || record.display_generation == 0
                || record.framebuffer_generation == 0
                || record.active_dmw_lease_count != 0
                || record.in_flight_dma_count != 0
                || record.raw_dma_binding_count != 0
                || record.raw_mmio_binding_count != 0
                || record.active_framebuffer_window_lease_count != 0
                || record.active_framebuffer_mapping_count != 0
                || record.dirty_framebuffer_region_count != 0
                || record.released_dma_buffers == 0
                || record.released_mmio_regions == 0
                || record.released_irq_lines == 0
                || record.released_framebuffer_window_leases == 0
                || record.revoked_device_capabilities == 0
                || record.revoked_display_capabilities == 0
                || record.smp_barrier_event == 0
                || record.io_cleanup_completed_event == 0
                || record.display_barrier_event == 0
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-snapshot-io-lease-barrier->contract",
                    from,
                    None,
                    "integrated snapshot/io lease barrier requires clean snapshot barriers and cleanup evidence",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-snapshot-io-lease-barrier->smp-snapshot-barrier",
                    ContractObjectKind::SmpSnapshotBarrier,
                    record.smp_snapshot_barrier,
                    record.smp_snapshot_barrier_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->io-cleanup",
                    ContractObjectKind::IoCleanup,
                    record.io_cleanup,
                    record.io_cleanup_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->display-snapshot-barrier",
                    ContractObjectKind::DisplaySnapshotBarrier,
                    record.display_snapshot_barrier,
                    record.display_snapshot_barrier_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->driver-store",
                    ContractObjectKind::Store,
                    record.driver_store,
                    record.driver_store_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->device",
                    ContractObjectKind::DeviceObject,
                    record.device,
                    record.device_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->display",
                    ContractObjectKind::DisplayObject,
                    record.display,
                    record.display_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->framebuffer",
                    ContractObjectKind::FramebufferObject,
                    record.framebuffer,
                    record.framebuffer_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }

            let smp_barrier = snapshot.smp_snapshot_barriers.iter().find(|barrier| {
                barrier.id == record.smp_snapshot_barrier
                    && barrier.generation == record.smp_snapshot_barrier_generation
            });
            let cleanup = snapshot.io_cleanups.iter().find(|cleanup| {
                cleanup.id == record.io_cleanup
                    && cleanup.generation == record.io_cleanup_generation
            });
            let display_barrier = snapshot.display_snapshot_barriers.iter().find(|barrier| {
                barrier.id == record.display_snapshot_barrier
                    && barrier.generation == record.display_snapshot_barrier_generation
            });
            if let (Some(smp_barrier), Some(cleanup), Some(display_barrier)) =
                (smp_barrier, cleanup, display_barrier)
            {
                let display_cleanup = display_barrier
                    .display_cleanup
                    .zip(display_barrier.display_cleanup_generation)
                    .and_then(|(cleanup_id, generation)| {
                        snapshot.display_cleanups.iter().find(|cleanup| {
                            cleanup.id == cleanup_id && cleanup.generation == generation
                        })
                    });
                if smp_barrier.state != SmpSnapshotBarrierState::Validated
                    || !smp_barrier.snapshot_validation_ok
                    || smp_barrier.active_dmw_lease_count != record.active_dmw_lease_count
                    || smp_barrier.in_flight_dma_count != record.in_flight_dma_count
                    || smp_barrier.raw_dma_binding_count != record.raw_dma_binding_count
                    || smp_barrier.raw_mmio_binding_count != record.raw_mmio_binding_count
                    || cleanup.state != IoCleanupState::Completed
                    || cleanup.driver_store != record.driver_store
                    || cleanup.driver_store_generation != record.driver_store_generation
                    || cleanup.device != record.device
                    || cleanup.device_generation != record.device_generation
                    || cleanup.released_dma_buffers.len() as u32 != record.released_dma_buffers
                    || cleanup.released_mmio_regions.len() as u32 != record.released_mmio_regions
                    || cleanup.released_irq_lines.len() as u32 != record.released_irq_lines
                    || cleanup.revoked_device_capabilities.len() as u32
                        != record.revoked_device_capabilities
                    || display_barrier.state != DisplaySnapshotBarrierState::Validated
                    || !display_barrier.snapshot_validation_ok
                    || display_barrier.display != record.display
                    || display_barrier.display_generation != record.display_generation
                    || display_barrier.framebuffer != record.framebuffer
                    || display_barrier.framebuffer_generation != record.framebuffer_generation
                    || display_barrier.active_framebuffer_window_lease_count
                        != record.active_framebuffer_window_lease_count
                    || display_barrier.active_framebuffer_mapping_count
                        != record.active_framebuffer_mapping_count
                    || display_barrier.dirty_framebuffer_region_count
                        != record.dirty_framebuffer_region_count
                    || smp_barrier.validated_at_event != record.smp_barrier_event
                    || cleanup.completed_at_event != record.io_cleanup_completed_event
                    || display_barrier.validated_at_event != record.display_barrier_event
                    || display_cleanup.is_none_or(|cleanup| {
                        cleanup.released_framebuffer_window_leases.len() as u32
                            != record.released_framebuffer_window_leases
                            || cleanup.revoked_display_capabilities.len() as u32
                                != record.revoked_display_capabilities
                    })
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-snapshot-io-lease-barrier->evidence-binding",
                        from,
                        Some(smp_barrier.object_ref()),
                        "integrated snapshot/io lease barrier record does not match source cleanup and barrier evidence",
                    ));
                }
            }
        }
    }

    fn validate_integrated_code_publish_smp_workloads(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_code_publish_smp_workloads {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedCodePublishSmpWorkloadState::Recorded
                || record.smp_stress_run_generation == 0
                || record.smp_code_publish_barrier_generation == 0
                || record.publish_rendezvous_generation == 0
                || record.publish_safe_point_generation == 0
                || record.hart_count < 2
                || record.workload_iterations < 3
                || record.observed_safe_point_count == 0
                || record.observed_rendezvous_count == 0
                || record.observed_code_publish_barrier_count == 0
                || record.code_publish_epoch_after != record.code_publish_epoch_before + 1
                || !record.remote_icache_sync_required
                || record.code_publish_executed
                || record.participant_count < 2
                || record.stress_event_log_cursor < record.barrier_event
                || record.stress_recorded_at_event <= record.barrier_event
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-code-publish-smp-workload->contract",
                    from,
                    None,
                    "integrated code publish/SMP workload requires clean stress and semantic publish barrier evidence",
                ));
                continue;
            }

            for (label, kind, id, generation) in [
                (
                    "integrated-code-publish-smp-workload->smp-stress-run",
                    ContractObjectKind::SmpStressRun,
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                ),
                (
                    "integrated-code-publish-smp-workload->smp-code-publish-barrier",
                    ContractObjectKind::SmpCodePublishBarrier,
                    record.smp_code_publish_barrier,
                    record.smp_code_publish_barrier_generation,
                ),
                (
                    "integrated-code-publish-smp-workload->stop-the-world-rendezvous",
                    ContractObjectKind::StopTheWorldRendezvous,
                    record.publish_rendezvous,
                    record.publish_rendezvous_generation,
                ),
                (
                    "integrated-code-publish-smp-workload->smp-safe-point",
                    ContractObjectKind::SmpSafePoint,
                    record.publish_safe_point,
                    record.publish_safe_point_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }

            let stress = snapshot.smp_stress_runs.iter().find(|stress| {
                stress.id == record.smp_stress_run
                    && stress.generation == record.smp_stress_run_generation
            });
            let barrier = snapshot.smp_code_publish_barriers.iter().find(|barrier| {
                barrier.id == record.smp_code_publish_barrier
                    && barrier.generation == record.smp_code_publish_barrier_generation
            });
            let rendezvous = snapshot
                .stop_the_world_rendezvous
                .iter()
                .find(|rendezvous| {
                    rendezvous.id == record.publish_rendezvous
                        && rendezvous.generation == record.publish_rendezvous_generation
                });
            if let (Some(stress), Some(barrier), Some(rendezvous)) = (stress, barrier, rendezvous) {
                if stress.state != SmpStressRunState::Recorded
                    || stress.property_failures != 0
                    || stress.hart_count != record.hart_count
                    || stress.iterations != record.workload_iterations
                    || stress.observed_safe_point_count != record.observed_safe_point_count
                    || stress.observed_rendezvous_count != record.observed_rendezvous_count
                    || stress.observed_code_publish_barrier_count
                        != record.observed_code_publish_barrier_count
                    || stress.last_code_publish_barrier != barrier.id
                    || stress.last_code_publish_barrier_generation != barrier.generation
                    || stress.event_log_cursor != record.stress_event_log_cursor
                    || stress.recorded_at_event != record.stress_recorded_at_event
                    || barrier.state != SmpCodePublishBarrierState::Validated
                    || barrier.rendezvous != record.publish_rendezvous
                    || barrier.rendezvous_generation != record.publish_rendezvous_generation
                    || barrier.code_publish_epoch_before != record.code_publish_epoch_before
                    || barrier.code_publish_epoch_after != record.code_publish_epoch_after
                    || barrier.remote_icache_sync_required != record.remote_icache_sync_required
                    || barrier.code_publish_executed != record.code_publish_executed
                    || barrier.participants.len() as u32 != record.participant_count
                    || barrier.validated_at_event != record.barrier_event
                    || rendezvous.safe_point != record.publish_safe_point
                    || rendezvous.safe_point_generation != record.publish_safe_point_generation
                    || rendezvous.state != StopTheWorldRendezvousState::Completed
                    || !rendezvous.stop_new_activations
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-code-publish-smp-workload->evidence-binding",
                        from,
                        Some(barrier.object_ref()),
                        "integrated code publish/SMP workload record does not match stress and publish barrier evidence",
                    ));
                }
            }
        }
    }

    fn validate_integrated_display_panics(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_display_panics {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedDisplayPanicState::Recorded
                || record.substrate_panic_event == 0
                || record.display_panic_last_frame_generation == 0
                || record.panic_ring_bytes != 65_536
                || record.panic_record_max_bytes != 4_096
                || record.panic_ring_oldest_seq == 0
                || record.panic_ring_newest_seq < record.panic_ring_oldest_seq
                || record.panic_ring_record_count < 2
                || record
                    .panic_ring_newest_seq
                    .saturating_sub(record.panic_ring_oldest_seq)
                    .saturating_add(1)
                    < u64::from(record.panic_ring_record_count)
                || record.panic_ring_lost_count != 0
                || record.jsonl_frame_count < record.panic_ring_record_count.saturating_add(2)
                || record.contract_panic_summary_records == 0
                || record.last_frame_summary_records == 0
                || record.corrupt_record_count != 0
                || record.truncated_record_count != 0
                || record.summary_record_bytes == 0
                || record.summary_record_bytes > record.panic_record_max_bytes
                || record.raw_framebuffer_bytes_exported
                || record.panic_path_allocates
                || record.invariant_checks == 0
                || record.recorded_at_event == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-display-panic->contract",
                    from,
                    None,
                    "integrated display panic requires clean panic-ring extraction and bounded last-frame summary",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "integrated-display-panic->display-panic-last-frame",
                ContractObjectKind::DisplayPanicLastFrame,
                record.display_panic_last_frame,
                record.display_panic_last_frame_generation,
                ContractEdgeMode::Historical,
            );
            if let Some(frame) = snapshot.display_panic_last_frames.iter().find(|frame| {
                frame.id == record.display_panic_last_frame
                    && frame.generation == record.display_panic_last_frame_generation
            }) {
                if frame.state != DisplayPanicLastFrameState::Recorded
                    || frame.raw_framebuffer_bytes_exported
                    || frame.summary_record_bytes != record.summary_record_bytes
                    || frame.panic_epoch != record.substrate_panic_epoch
                    || frame.panic_cpu != record.substrate_panic_cpu
                    || frame.panic_reason_code != record.substrate_panic_reason_code
                    || frame.panic_record_kind != "contract-panic-summary-v1"
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-display-panic->last-frame-binding",
                        from,
                        Some(frame.object_ref()),
                        "integrated display panic does not match last-frame panic summary evidence",
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
            ContractObjectKind::Task => snapshot
                .tasks
                .iter()
                .find(|task| u64::from(task.id) == id && task.generation == generation)
                .map(TaskRecord::object_ref),
            ContractObjectKind::Activation => snapshot
                .runtime_activations
                .iter()
                .find(|activation| activation.id == id && activation.generation == generation)
                .map(RuntimeActivationRecord::object_ref)
                .or_else(|| {
                    snapshot
                        .activations
                        .iter()
                        .find(|activation| {
                            activation.id == id && activation.generation == generation
                        })
                        .map(ActivationRecord::object_ref)
                }),
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
            ContractObjectKind::SmpStressRun => snapshot
                .smp_stress_runs
                .iter()
                .find(|run| run.id == id && run.generation == generation)
                .map(SmpStressRunRecord::object_ref),
            ContractObjectKind::SchedulerDecision => snapshot
                .scheduler_decisions
                .iter()
                .find(|decision| decision.id == id && decision.generation == generation)
                .map(SchedulerDecisionRecord::object_ref),
            ContractObjectKind::SmpSnapshotBarrier => snapshot
                .smp_snapshot_barriers
                .iter()
                .find(|barrier| barrier.id == id && barrier.generation == generation)
                .map(SmpSnapshotBarrierRecord::object_ref),
            ContractObjectKind::RemotePreempt => snapshot
                .remote_preempts
                .iter()
                .find(|remote| remote.id == id && remote.generation == generation)
                .map(RemotePreemptRecord::object_ref),
            ContractObjectKind::SavedContext => snapshot
                .saved_contexts
                .iter()
                .find(|context| context.id == id && context.generation == generation)
                .map(SavedContextRecord::object_ref),
            ContractObjectKind::TimerInterrupt => snapshot
                .timer_interrupts
                .iter()
                .find(|timer| timer.id == id && timer.generation == generation)
                .map(TimerInterruptRecord::object_ref),
            ContractObjectKind::ActivationCleanup => snapshot
                .activation_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id && cleanup.generation == generation)
                .map(ActivationCleanupRecord::object_ref),
            ContractObjectKind::SmpCleanupQuiescence => snapshot
                .smp_cleanup_quiescence
                .iter()
                .find(|quiescence| quiescence.id == id && quiescence.generation == generation)
                .map(SmpCleanupQuiescenceRecord::object_ref),
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
            ContractObjectKind::FramebufferFlushRegion => snapshot
                .framebuffer_flush_regions
                .iter()
                .find(|flush| flush.id == id && flush.generation == generation)
                .map(FramebufferFlushRegionRecord::object_ref),
            ContractObjectKind::FramebufferDirtyRegion => snapshot
                .framebuffer_dirty_regions
                .iter()
                .find(|dirty| dirty.id == id && dirty.generation == generation)
                .map(FramebufferDirtyRegionRecord::object_ref),
            ContractObjectKind::DisplayEventLog => snapshot
                .display_event_logs
                .iter()
                .find(|log| log.id == id && log.generation == generation)
                .map(DisplayEventLogRecord::object_ref),
            ContractObjectKind::DisplayCleanup => snapshot
                .display_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id && cleanup.generation == generation)
                .map(DisplayCleanupRecord::object_ref),
            ContractObjectKind::DisplaySnapshotBarrier => snapshot
                .display_snapshot_barriers
                .iter()
                .find(|barrier| barrier.id == id && barrier.generation == generation)
                .map(DisplaySnapshotBarrierRecord::object_ref),
            ContractObjectKind::DisplayPanicLastFrame => snapshot
                .display_panic_last_frames
                .iter()
                .find(|frame| frame.id == id && frame.generation == generation)
                .map(DisplayPanicLastFrameRecord::object_ref),
            ContractObjectKind::FramebufferBenchmark => snapshot
                .framebuffer_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id && benchmark.generation == generation)
                .map(FramebufferBenchmarkRecord::object_ref),
            ContractObjectKind::IntegratedSmpPreemptionCleanup => snapshot
                .integrated_smp_preemption_cleanups
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedSmpPreemptionCleanupRecord::object_ref),
            ContractObjectKind::IntegratedSmpNetworkFault => snapshot
                .integrated_smp_network_faults
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedSmpNetworkFaultRecord::object_ref),
            ContractObjectKind::IntegratedDiskPreemptFault => snapshot
                .integrated_disk_preempt_faults
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedDiskPreemptFaultRecord::object_ref),
            ContractObjectKind::IntegratedSimdMigration => snapshot
                .integrated_simd_migrations
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedSimdMigrationRecord::object_ref),
            ContractObjectKind::IntegratedNetworkDiskIo => snapshot
                .integrated_network_disk_ios
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedNetworkDiskIoRecord::object_ref),
            ContractObjectKind::IntegratedDisplaySchedulerLoad => snapshot
                .integrated_display_scheduler_loads
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedDisplaySchedulerLoadRecord::object_ref),
            ContractObjectKind::IntegratedSnapshotIoLeaseBarrier => snapshot
                .integrated_snapshot_io_lease_barriers
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedSnapshotIoLeaseBarrierRecord::object_ref),
            ContractObjectKind::IntegratedCodePublishSmpWorkload => snapshot
                .integrated_code_publish_smp_workloads
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedCodePublishSmpWorkloadRecord::object_ref),
            ContractObjectKind::IntegratedDisplayPanic => snapshot
                .integrated_display_panics
                .iter()
                .find(|record| record.id == id && record.generation == generation)
                .map(IntegratedDisplayPanicRecord::object_ref),
            ContractObjectKind::SmpSafePoint => snapshot
                .smp_safe_points
                .iter()
                .find(|safe_point| safe_point.id == id && safe_point.generation == generation)
                .map(SmpSafePointRecord::object_ref),
            ContractObjectKind::StopTheWorldRendezvous => snapshot
                .stop_the_world_rendezvous
                .iter()
                .find(|rendezvous| rendezvous.id == id && rendezvous.generation == generation)
                .map(StopTheWorldRendezvousRecord::object_ref),
            ContractObjectKind::DeviceObject => snapshot
                .device_objects
                .iter()
                .find(|device| device.id == id && device.generation == generation)
                .map(DeviceObjectRecord::object_ref),
            ContractObjectKind::SmpCodePublishBarrier => snapshot
                .smp_code_publish_barriers
                .iter()
                .find(|barrier| barrier.id == id && barrier.generation == generation)
                .map(SmpCodePublishBarrierRecord::object_ref),
            ContractObjectKind::NetworkDriverCleanup => snapshot
                .network_driver_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id && cleanup.generation == generation)
                .map(NetworkDriverCleanupRecord::object_ref),
            ContractObjectKind::PacketDeviceObject => snapshot
                .packet_device_objects
                .iter()
                .find(|packet_device| {
                    packet_device.id == id && packet_device.generation == generation
                })
                .map(PacketDeviceObjectRecord::object_ref),
            ContractObjectKind::NetworkStackAdapter => snapshot
                .network_stack_adapters
                .iter()
                .find(|adapter| adapter.id == id && adapter.generation == generation)
                .map(NetworkStackAdapterRecord::object_ref),
            ContractObjectKind::SocketObject => snapshot
                .socket_objects
                .iter()
                .find(|socket| socket.id == id && socket.generation == generation)
                .map(SocketObjectRecord::object_ref),
            ContractObjectKind::VirtioNetBackendObject => snapshot
                .virtio_net_backends
                .iter()
                .find(|backend| backend.id == id && backend.generation == generation)
                .map(VirtioNetBackendObjectRecord::object_ref),
            ContractObjectKind::IoCleanup => snapshot
                .io_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id && cleanup.generation == generation)
                .map(IoCleanupRecord::object_ref),
            ContractObjectKind::BlockPendingIoPolicy => snapshot
                .block_pending_io_policies
                .iter()
                .find(|policy| policy.id == id && policy.generation == generation)
                .map(BlockPendingIoPolicyRecord::object_ref),
            ContractObjectKind::BlockWait => snapshot
                .block_waits
                .iter()
                .find(|wait| wait.id == id && wait.generation == generation)
                .map(BlockWaitRecord::object_ref),
            ContractObjectKind::BlockRequestObject => snapshot
                .block_request_objects
                .iter()
                .find(|request| request.id == id && request.generation == generation)
                .map(BlockRequestObjectRecord::object_ref),
            ContractObjectKind::BlockDeviceObject => snapshot
                .block_device_objects
                .iter()
                .find(|device| device.id == id && device.generation == generation)
                .map(BlockDeviceObjectRecord::object_ref),
            ContractObjectKind::BlockRangeObject => snapshot
                .block_range_objects
                .iter()
                .find(|range| range.id == id && range.generation == generation)
                .map(BlockRangeObjectRecord::object_ref),
            ContractObjectKind::BlockRequestQueue => snapshot
                .block_request_queues
                .iter()
                .find(|queue| queue.id == id && queue.generation == generation)
                .map(BlockRequestQueueRecord::object_ref),
            ContractObjectKind::BlockDmaBuffer => snapshot
                .block_dma_buffers
                .iter()
                .find(|buffer| buffer.id == id && buffer.generation == generation)
                .map(BlockDmaBufferRecord::object_ref),
            ContractObjectKind::FakeBlockBackendObject => snapshot
                .fake_block_backends
                .iter()
                .find(|backend| backend.id == id && backend.generation == generation)
                .map(FakeBlockBackendObjectRecord::object_ref),
            ContractObjectKind::NetworkBenchmark => snapshot
                .network_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id && benchmark.generation == generation)
                .map(NetworkBenchmarkRecord::object_ref),
            ContractObjectKind::BlockBenchmark => snapshot
                .block_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id && benchmark.generation == generation)
                .map(BlockBenchmarkRecord::object_ref),
            ContractObjectKind::Hart => snapshot
                .harts
                .iter()
                .find(|hart| u64::from(hart.id) == id && hart.generation == generation)
                .map(HartRecord::object_ref),
            ContractObjectKind::RunnableQueue => snapshot
                .runnable_queues
                .iter()
                .find(|queue| queue.id == id && queue.generation == generation)
                .map(RunnableQueueRecord::object_ref),
            ContractObjectKind::ActivationContext => snapshot
                .activation_contexts
                .iter()
                .find(|context| context.id == id && context.generation == generation)
                .map(ActivationContextRecord::object_ref),
            ContractObjectKind::ActivationMigration => snapshot
                .activation_migrations
                .iter()
                .find(|migration| migration.id == id && migration.generation == generation)
                .map(ActivationMigrationRecord::object_ref),
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
            ContractObjectKind::SmpStressRun => snapshot
                .smp_stress_runs
                .iter()
                .find(|run| run.id == id)
                .map(SmpStressRunRecord::object_ref),
            ContractObjectKind::Task => snapshot
                .tasks
                .iter()
                .find(|task| u64::from(task.id) == id)
                .map(TaskRecord::object_ref),
            ContractObjectKind::SchedulerDecision => snapshot
                .scheduler_decisions
                .iter()
                .find(|decision| decision.id == id)
                .map(SchedulerDecisionRecord::object_ref),
            ContractObjectKind::SmpSnapshotBarrier => snapshot
                .smp_snapshot_barriers
                .iter()
                .find(|barrier| barrier.id == id)
                .map(SmpSnapshotBarrierRecord::object_ref),
            ContractObjectKind::RemotePreempt => snapshot
                .remote_preempts
                .iter()
                .find(|remote| remote.id == id)
                .map(RemotePreemptRecord::object_ref),
            ContractObjectKind::SavedContext => snapshot
                .saved_contexts
                .iter()
                .find(|context| context.id == id)
                .map(SavedContextRecord::object_ref),
            ContractObjectKind::TimerInterrupt => snapshot
                .timer_interrupts
                .iter()
                .find(|timer| timer.id == id)
                .map(TimerInterruptRecord::object_ref),
            ContractObjectKind::ActivationCleanup => snapshot
                .activation_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(ActivationCleanupRecord::object_ref),
            ContractObjectKind::SmpCleanupQuiescence => snapshot
                .smp_cleanup_quiescence
                .iter()
                .find(|quiescence| quiescence.id == id)
                .map(SmpCleanupQuiescenceRecord::object_ref),
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
            ContractObjectKind::FramebufferFlushRegion => snapshot
                .framebuffer_flush_regions
                .iter()
                .find(|flush| flush.id == id)
                .map(FramebufferFlushRegionRecord::object_ref),
            ContractObjectKind::FramebufferDirtyRegion => snapshot
                .framebuffer_dirty_regions
                .iter()
                .find(|dirty| dirty.id == id)
                .map(FramebufferDirtyRegionRecord::object_ref),
            ContractObjectKind::DisplayEventLog => snapshot
                .display_event_logs
                .iter()
                .find(|log| log.id == id)
                .map(DisplayEventLogRecord::object_ref),
            ContractObjectKind::DisplayCleanup => snapshot
                .display_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(DisplayCleanupRecord::object_ref),
            ContractObjectKind::DisplaySnapshotBarrier => snapshot
                .display_snapshot_barriers
                .iter()
                .find(|barrier| barrier.id == id)
                .map(DisplaySnapshotBarrierRecord::object_ref),
            ContractObjectKind::DisplayPanicLastFrame => snapshot
                .display_panic_last_frames
                .iter()
                .find(|frame| frame.id == id)
                .map(DisplayPanicLastFrameRecord::object_ref),
            ContractObjectKind::FramebufferBenchmark => snapshot
                .framebuffer_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(FramebufferBenchmarkRecord::object_ref),
            ContractObjectKind::IntegratedSmpPreemptionCleanup => snapshot
                .integrated_smp_preemption_cleanups
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedSmpPreemptionCleanupRecord::object_ref),
            ContractObjectKind::IntegratedSmpNetworkFault => snapshot
                .integrated_smp_network_faults
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedSmpNetworkFaultRecord::object_ref),
            ContractObjectKind::IntegratedDiskPreemptFault => snapshot
                .integrated_disk_preempt_faults
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedDiskPreemptFaultRecord::object_ref),
            ContractObjectKind::IntegratedSimdMigration => snapshot
                .integrated_simd_migrations
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedSimdMigrationRecord::object_ref),
            ContractObjectKind::IntegratedNetworkDiskIo => snapshot
                .integrated_network_disk_ios
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedNetworkDiskIoRecord::object_ref),
            ContractObjectKind::IntegratedDisplaySchedulerLoad => snapshot
                .integrated_display_scheduler_loads
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedDisplaySchedulerLoadRecord::object_ref),
            ContractObjectKind::IntegratedSnapshotIoLeaseBarrier => snapshot
                .integrated_snapshot_io_lease_barriers
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedSnapshotIoLeaseBarrierRecord::object_ref),
            ContractObjectKind::IntegratedCodePublishSmpWorkload => snapshot
                .integrated_code_publish_smp_workloads
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedCodePublishSmpWorkloadRecord::object_ref),
            ContractObjectKind::IntegratedDisplayPanic => snapshot
                .integrated_display_panics
                .iter()
                .find(|record| record.id == id)
                .map(IntegratedDisplayPanicRecord::object_ref),
            ContractObjectKind::SmpSafePoint => snapshot
                .smp_safe_points
                .iter()
                .find(|safe_point| safe_point.id == id)
                .map(SmpSafePointRecord::object_ref),
            ContractObjectKind::StopTheWorldRendezvous => snapshot
                .stop_the_world_rendezvous
                .iter()
                .find(|rendezvous| rendezvous.id == id)
                .map(StopTheWorldRendezvousRecord::object_ref),
            ContractObjectKind::DeviceObject => snapshot
                .device_objects
                .iter()
                .find(|device| device.id == id)
                .map(DeviceObjectRecord::object_ref),
            ContractObjectKind::SmpCodePublishBarrier => snapshot
                .smp_code_publish_barriers
                .iter()
                .find(|barrier| barrier.id == id)
                .map(SmpCodePublishBarrierRecord::object_ref),
            ContractObjectKind::NetworkDriverCleanup => snapshot
                .network_driver_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(NetworkDriverCleanupRecord::object_ref),
            ContractObjectKind::PacketDeviceObject => snapshot
                .packet_device_objects
                .iter()
                .find(|packet_device| packet_device.id == id)
                .map(PacketDeviceObjectRecord::object_ref),
            ContractObjectKind::NetworkStackAdapter => snapshot
                .network_stack_adapters
                .iter()
                .find(|adapter| adapter.id == id)
                .map(NetworkStackAdapterRecord::object_ref),
            ContractObjectKind::SocketObject => snapshot
                .socket_objects
                .iter()
                .find(|socket| socket.id == id)
                .map(SocketObjectRecord::object_ref),
            ContractObjectKind::VirtioNetBackendObject => snapshot
                .virtio_net_backends
                .iter()
                .find(|backend| backend.id == id)
                .map(VirtioNetBackendObjectRecord::object_ref),
            ContractObjectKind::IoCleanup => snapshot
                .io_cleanups
                .iter()
                .find(|cleanup| cleanup.id == id)
                .map(IoCleanupRecord::object_ref),
            ContractObjectKind::BlockPendingIoPolicy => snapshot
                .block_pending_io_policies
                .iter()
                .find(|policy| policy.id == id)
                .map(BlockPendingIoPolicyRecord::object_ref),
            ContractObjectKind::BlockWait => snapshot
                .block_waits
                .iter()
                .find(|wait| wait.id == id)
                .map(BlockWaitRecord::object_ref),
            ContractObjectKind::BlockRequestObject => snapshot
                .block_request_objects
                .iter()
                .find(|request| request.id == id)
                .map(BlockRequestObjectRecord::object_ref),
            ContractObjectKind::BlockDeviceObject => snapshot
                .block_device_objects
                .iter()
                .find(|device| device.id == id)
                .map(BlockDeviceObjectRecord::object_ref),
            ContractObjectKind::BlockRangeObject => snapshot
                .block_range_objects
                .iter()
                .find(|range| range.id == id)
                .map(BlockRangeObjectRecord::object_ref),
            ContractObjectKind::BlockRequestQueue => snapshot
                .block_request_queues
                .iter()
                .find(|queue| queue.id == id)
                .map(BlockRequestQueueRecord::object_ref),
            ContractObjectKind::BlockDmaBuffer => snapshot
                .block_dma_buffers
                .iter()
                .find(|buffer| buffer.id == id)
                .map(BlockDmaBufferRecord::object_ref),
            ContractObjectKind::FakeBlockBackendObject => snapshot
                .fake_block_backends
                .iter()
                .find(|backend| backend.id == id)
                .map(FakeBlockBackendObjectRecord::object_ref),
            ContractObjectKind::NetworkBenchmark => snapshot
                .network_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(NetworkBenchmarkRecord::object_ref),
            ContractObjectKind::BlockBenchmark => snapshot
                .block_benchmarks
                .iter()
                .find(|benchmark| benchmark.id == id)
                .map(BlockBenchmarkRecord::object_ref),
            ContractObjectKind::Hart => snapshot
                .harts
                .iter()
                .find(|hart| u64::from(hart.id) == id)
                .map(HartRecord::object_ref),
            ContractObjectKind::RunnableQueue => snapshot
                .runnable_queues
                .iter()
                .find(|queue| queue.id == id)
                .map(RunnableQueueRecord::object_ref),
            ContractObjectKind::ActivationContext => snapshot
                .activation_contexts
                .iter()
                .find(|context| context.id == id)
                .map(ActivationContextRecord::object_ref),
            ContractObjectKind::ActivationMigration => snapshot
                .activation_migrations
                .iter()
                .find(|migration| migration.id == id)
                .map(ActivationMigrationRecord::object_ref),
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
                .runtime_activations
                .iter()
                .find(|activation| activation.id == id)
                .map(RuntimeActivationRecord::object_ref)
                .or_else(|| {
                    snapshot
                        .activations
                        .iter()
                        .find(|activation| activation.id == id)
                        .map(ActivationRecord::object_ref)
                }),
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
            ContractObjectKind::IpiEvent
            | ContractObjectKind::RemotePark
            | ContractObjectKind::CrossHartSchedulerDecision
            | ContractObjectKind::SmpScalingBenchmark
            | ContractObjectKind::QueueObject
            | ContractObjectKind::DescriptorObject
            | ContractObjectKind::DmaBufferObject
            | ContractObjectKind::MmioRegionObject
            | ContractObjectKind::IrqLineObject
            | ContractObjectKind::IrqEvent
            | ContractObjectKind::DeviceCapability
            | ContractObjectKind::DriverStoreBinding
            | ContractObjectKind::IoWait
            | ContractObjectKind::IoFaultInjection
            | ContractObjectKind::IoValidationReport
            | ContractObjectKind::PacketBufferObject
            | ContractObjectKind::PacketQueueObject
            | ContractObjectKind::PacketDescriptorObject
            | ContractObjectKind::FakeNetBackendObject
            | ContractObjectKind::VirtioBlkBackendObject
            | ContractObjectKind::NetworkRxInterrupt
            | ContractObjectKind::NetworkRxWaitResolution
            | ContractObjectKind::NetworkTxCapabilityGate
            | ContractObjectKind::NetworkTxCompletion
            | ContractObjectKind::EndpointObject
            | ContractObjectKind::SocketOperation
            | ContractObjectKind::SocketWait
            | ContractObjectKind::NetworkBackpressure
            | ContractObjectKind::NetworkGenerationAudit
            | ContractObjectKind::NetworkFaultInjection
            | ContractObjectKind::NetworkRecoveryBenchmark
            | ContractObjectKind::BlockCompletionObject
            | ContractObjectKind::BlockReadPath
            | ContractObjectKind::BlockWritePath
            | ContractObjectKind::BlockPageObject
            | ContractObjectKind::BufferCacheObject
            | ContractObjectKind::FileObject
            | ContractObjectKind::DirectoryObject
            | ContractObjectKind::FatAdapterObject
            | ContractObjectKind::Ext4AdapterObject
            | ContractObjectKind::FileHandleCapability
            | ContractObjectKind::FsWait
            | ContractObjectKind::BlockDriverCleanup
            | ContractObjectKind::BlockRequestGenerationAudit
            | ContractObjectKind::BlockRecoveryBenchmark
            | ContractObjectKind::ActivationWait
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
                | ContractObjectKind::FramebufferFlushRegion
                | ContractObjectKind::FramebufferDirtyRegion
                | ContractObjectKind::DisplayEventLog
                | ContractObjectKind::DisplayCleanup
                | ContractObjectKind::DisplaySnapshotBarrier
                | ContractObjectKind::DisplayPanicLastFrame
                | ContractObjectKind::FramebufferBenchmark
                | ContractObjectKind::IntegratedDisplaySchedulerLoad
                | ContractObjectKind::IntegratedSnapshotIoLeaseBarrier
                | ContractObjectKind::IntegratedSmpPreemptionCleanup
                | ContractObjectKind::IntegratedSmpNetworkFault
                | ContractObjectKind::IntegratedDiskPreemptFault
                | ContractObjectKind::IntegratedSimdMigration
                | ContractObjectKind::IntegratedNetworkDiskIo
                | ContractObjectKind::BlockPendingIoPolicy
                | ContractObjectKind::BlockWait
                | ContractObjectKind::BlockRequestObject
                | ContractObjectKind::BlockDeviceObject
                | ContractObjectKind::BlockRangeObject
                | ContractObjectKind::SmpSnapshotBarrier
                | ContractObjectKind::DeviceObject
                | ContractObjectKind::Task
                | ContractObjectKind::SchedulerDecision
                | ContractObjectKind::RunnableQueue
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
            ContractObjectKind::FramebufferFlushRegion => snapshot
                .framebuffer_flush_regions
                .iter()
                .find(|flush| flush.id == object.id && flush.generation == object.generation)
                .and_then(|flush| {
                    (flush.state != FramebufferFlushRegionState::Applied)
                        .then_some("live edge references unapplied framebuffer flush region")
                }),
            ContractObjectKind::FramebufferDirtyRegion => snapshot
                .framebuffer_dirty_regions
                .iter()
                .find(|dirty| dirty.id == object.id && dirty.generation == object.generation)
                .and_then(|dirty| {
                    (dirty.state != FramebufferDirtyRegionState::Dirty)
                        .then_some("live edge references clean framebuffer dirty region")
                }),
            ContractObjectKind::DisplayEventLog => snapshot
                .display_event_logs
                .iter()
                .find(|log| log.id == object.id && log.generation == object.generation)
                .and_then(|log| {
                    (log.state != DisplayEventLogState::Recorded)
                        .then_some("live edge references unrecorded display event log")
                }),
            ContractObjectKind::DisplayCleanup => snapshot
                .display_cleanups
                .iter()
                .find(|cleanup| cleanup.id == object.id && cleanup.generation == object.generation)
                .and_then(|cleanup| {
                    (cleanup.state != DisplayCleanupState::Completed)
                        .then_some("live edge references incomplete display cleanup")
                }),
            ContractObjectKind::DisplaySnapshotBarrier => snapshot
                .display_snapshot_barriers
                .iter()
                .find(|barrier| barrier.id == object.id && barrier.generation == object.generation)
                .and_then(|barrier| {
                    (barrier.state != DisplaySnapshotBarrierState::Validated)
                        .then_some("live edge references unvalidated display snapshot barrier")
                }),
            ContractObjectKind::DisplayPanicLastFrame => snapshot
                .display_panic_last_frames
                .iter()
                .find(|frame| frame.id == object.id && frame.generation == object.generation)
                .and_then(|frame| {
                    (frame.state != DisplayPanicLastFrameState::Recorded)
                        .then_some("live edge references unrecorded display panic last-frame")
                }),
            ContractObjectKind::FramebufferBenchmark => snapshot
                .framebuffer_benchmarks
                .iter()
                .find(|benchmark| {
                    benchmark.id == object.id && benchmark.generation == object.generation
                })
                .and_then(|benchmark| {
                    (benchmark.state != FramebufferBenchmarkState::Recorded)
                        .then_some("live edge references unrecorded framebuffer benchmark")
                }),
            ContractObjectKind::IntegratedSmpPreemptionCleanup => snapshot
                .integrated_smp_preemption_cleanups
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedSmpPreemptionCleanupState::Recorded).then_some(
                        "live edge references unrecorded integrated SMP/preemption/cleanup evidence",
                    )
                }),
            ContractObjectKind::IntegratedSmpNetworkFault => snapshot
                .integrated_smp_network_faults
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedSmpNetworkFaultState::Recorded).then_some(
                        "live edge references unrecorded integrated SMP/network-fault evidence",
                    )
                }),
            ContractObjectKind::IntegratedDiskPreemptFault => snapshot
                .integrated_disk_preempt_faults
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedDiskPreemptFaultState::Recorded).then_some(
                        "live edge references unrecorded integrated disk/preempt fault evidence",
                    )
                }),
            ContractObjectKind::IntegratedSimdMigration => snapshot
                .integrated_simd_migrations
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedSimdMigrationState::Recorded)
                        .then_some("live edge references unrecorded integrated SIMD migration evidence")
                }),
            ContractObjectKind::IntegratedNetworkDiskIo => snapshot
                .integrated_network_disk_ios
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedNetworkDiskIoState::Recorded)
                        .then_some("live edge references unrecorded integrated network/disk IO evidence")
                }),
            ContractObjectKind::IntegratedDisplaySchedulerLoad => snapshot
                .integrated_display_scheduler_loads
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedDisplaySchedulerLoadState::Recorded).then_some(
                        "live edge references unrecorded integrated display/scheduler load evidence",
                    )
                }),
            ContractObjectKind::IntegratedSnapshotIoLeaseBarrier => snapshot
                .integrated_snapshot_io_lease_barriers
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedSnapshotIoLeaseBarrierState::Recorded).then_some(
                        "live edge references unrecorded integrated snapshot/io lease barrier evidence",
                    )
                }),
            ContractObjectKind::IntegratedCodePublishSmpWorkload => snapshot
                .integrated_code_publish_smp_workloads
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedCodePublishSmpWorkloadState::Recorded).then_some(
                        "live edge references unrecorded integrated code publish/SMP workload evidence",
                    )
                }),
            ContractObjectKind::IntegratedDisplayPanic => snapshot
                .integrated_display_panics
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != IntegratedDisplayPanicState::Recorded)
                        .then_some("live edge references unrecorded integrated display panic evidence")
                }),
            ContractObjectKind::SmpCodePublishBarrier => snapshot
                .smp_code_publish_barriers
                .iter()
                .find(|barrier| barrier.id == object.id && barrier.generation == object.generation)
                .and_then(|barrier| {
                    (barrier.state != SmpCodePublishBarrierState::Validated)
                        .then_some("live edge references invalid SMP code publish barrier")
                }),
            ContractObjectKind::Task => snapshot
                .tasks
                .iter()
                .find(|task| {
                    u64::from(task.id) == object.id && task.generation == object.generation
                })
                .and_then(|task| {
                    matches!(
                        task.state,
                        TaskState::Cancelled | TaskState::Faulted | TaskState::Exited
                    )
                    .then_some("live edge references inactive task")
                }),
            ContractObjectKind::SchedulerDecision => snapshot
                .scheduler_decisions
                .iter()
                .find(|decision| {
                    decision.id == object.id && decision.generation == object.generation
                })
                .and_then(|decision| {
                    (decision.state == SchedulerDecisionState::Dropped)
                        .then_some("live edge references dropped scheduler decision")
                }),
            ContractObjectKind::SocketObject => snapshot
                .socket_objects
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != SocketObjectState::Created)
                        .then_some("live edge references inactive socket object")
                }),
            ContractObjectKind::BlockRequestQueue => snapshot
                .block_request_queues
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != BlockRequestQueueState::Active)
                        .then_some("live edge references inactive block request queue")
                }),
            ContractObjectKind::BlockDmaBuffer => snapshot
                .block_dma_buffers
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != BlockDmaBufferState::Bound)
                        .then_some("live edge references inactive block DMA buffer")
                }),
            ContractObjectKind::NetworkBenchmark => snapshot
                .network_benchmarks
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != NetworkBenchmarkState::Recorded)
                        .then_some("live edge references unrecorded network benchmark evidence")
                }),
            ContractObjectKind::BlockBenchmark => snapshot
                .block_benchmarks
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != BlockBenchmarkState::Recorded)
                        .then_some("live edge references unrecorded block benchmark evidence")
                }),
            ContractObjectKind::FakeBlockBackendObject => snapshot
                .fake_block_backends
                .iter()
                .find(|record| record.id == object.id && record.generation == object.generation)
                .and_then(|record| {
                    (record.state != FakeBlockBackendObjectState::Bound)
                        .then_some("live edge references inactive fake block backend evidence")
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
