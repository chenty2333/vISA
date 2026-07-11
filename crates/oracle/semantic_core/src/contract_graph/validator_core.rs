use alloc::vec::Vec;

use super::*;

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
        Self::validate_integrated_osctl_trace_replays(snapshot, &mut violations);
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
        Self::validate_guest_memory(snapshot, &mut violations);
        Self::validate_evidence_boundary_claims(snapshot, &mut violations);
        Self::validate_explicit_edges(snapshot, &mut violations);
        violations
    }

    pub(super) fn validate_guest_memory(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for aspace in &snapshot.guest_address_spaces {
            let from = aspace.object_ref();
            if aspace.aspace.generation() != aspace.generation || aspace.generation == 0 {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "guest-address-space->self",
                    from,
                    Some(aspace.aspace.object_ref()),
                    "guest address space generation does not match its object ref",
                ));
            }
            if let Some(root) = aspace.root_region {
                Self::check_contract_ref_edge(
                    snapshot,
                    violations,
                    from,
                    "guest-address-space->root-vma",
                    root.object_ref(),
                    ContractEdgeMode::Live,
                    None,
                );
            }
        }

        for region in &snapshot.vma_regions {
            let from = region.object_ref();
            if region.region.generation() != region.generation || region.generation == 0 {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "vma-region->self",
                    from,
                    Some(region.region.object_ref()),
                    "VMA generation does not match its object ref",
                ));
            }
            let edge_mode = if region.state == VmaState::Mapped {
                ContractEdgeMode::Live
            } else {
                ContractEdgeMode::Historical
            };
            Self::check_contract_ref_edge(
                snapshot,
                violations,
                from,
                "vma-region->aspace",
                region.aspace.object_ref(),
                edge_mode,
                None,
            );
            Self::check_contract_ref_edge(
                snapshot,
                violations,
                from,
                "vma-region->page",
                region.backing.object_ref(),
                edge_mode,
                None,
            );
        }

        for page in &snapshot.page_objects {
            let from = page.object_ref();
            if page.page.generation() != page.generation || page.generation == 0 {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "page-object->self",
                    from,
                    Some(page.page.object_ref()),
                    "page object generation does not match its object ref",
                ));
            }
            if page.dirty_generation == 0 {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "page-object->dirty-generation",
                    from,
                    None,
                    "page object dirty generation must be nonzero",
                ));
            }
        }

        for fault in &snapshot.guest_memory_faults {
            let from = fault.object_ref();
            Self::check_contract_ref_edge(
                snapshot,
                violations,
                from,
                "page-fault-event->page",
                fault.page.object_ref(),
                ContractEdgeMode::Historical,
                None,
            );
            if fault.reason.is_empty() {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "page-fault-event->reason",
                    from,
                    None,
                    "page fault event reason must be nonempty",
                ));
            }
        }

        for operation in &snapshot.guest_memory_operations {
            let from = operation.object_ref();
            if operation.operation_ref.generation() != operation.generation
                || operation.generation == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::GenerationMismatch,
                    "guest-memory-operation->self",
                    from,
                    Some(operation.operation_ref.object_ref()),
                    "guest memory operation generation does not match its object ref",
                ));
            }
            Self::check_contract_ref_edge(
                snapshot,
                violations,
                from,
                "guest-memory-operation->aspace",
                operation.aspace.object_ref(),
                ContractEdgeMode::Historical,
                None,
            );
            Self::check_guest_memory_historical_ref(
                snapshot,
                violations,
                from,
                "guest-memory-operation->region-before",
                operation.region_before.map(VmaRegionRef::object_ref),
            );
            Self::check_guest_memory_historical_ref(
                snapshot,
                violations,
                from,
                "guest-memory-operation->page-before",
                operation.page_before.map(PageObjectRef::object_ref),
            );
            if let Some(region) = operation.region_after {
                Self::check_contract_ref_edge(
                    snapshot,
                    violations,
                    from,
                    "guest-memory-operation->region-after",
                    region.object_ref(),
                    ContractEdgeMode::Historical,
                    None,
                );
            }
            if let Some(page) = operation.page_after {
                Self::check_contract_ref_edge(
                    snapshot,
                    violations,
                    from,
                    "guest-memory-operation->page-after",
                    page.object_ref(),
                    ContractEdgeMode::Historical,
                    None,
                );
            }
            if operation.reason.is_empty() {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "guest-memory-operation->reason",
                    from,
                    None,
                    "guest memory operation reason must be nonempty",
                ));
            }
            Self::validate_guest_memory_operation_shape(operation, violations);
        }
    }

    fn check_guest_memory_historical_ref(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
        from: ContractObjectRef,
        edge: &str,
        target: Option<ContractObjectRef>,
    ) {
        let Some(target) = target else {
            return;
        };
        if target.generation == 0 {
            violations.push(ContractViolation::new(
                ContractViolationKind::HistoricalEdgeMissingGeneration,
                edge,
                from,
                Some(target),
                "guest memory operation historical edge is missing exact generation",
            ));
            return;
        }
        if Self::object_ref_by_id_generation(snapshot, target.kind, target.id, target.generation)
            .is_some()
            || Self::current_object_ref(snapshot, target.kind, target.id).is_some()
            || Self::has_tombstone(snapshot, target)
        {
            return;
        }
        violations.push(ContractViolation::new(
            ContractViolationKind::DanglingEdge,
            edge,
            from,
            Some(target),
            "guest memory operation historical edge references an unknown object id",
        ));
    }

    fn validate_guest_memory_operation_shape(
        operation: &GuestMemoryOperationRecord,
        violations: &mut Vec<ContractViolation>,
    ) {
        let from = operation.object_ref();
        let valid = match operation.operation {
            GuestMemoryOperationKind::Mmap => {
                operation.range.len != 0
                    && operation.region_before.is_none()
                    && operation.region_after.is_some()
                    && operation.page_after.is_some()
                    && operation.perms_before.is_none()
                    && operation.perms_after.is_some()
                    && operation.brk_before.is_none()
                    && operation.brk_after.is_none()
            }
            GuestMemoryOperationKind::Munmap => {
                operation.range.len != 0
                    && operation.region_before.is_some()
                    && operation.region_after.is_some()
                    && operation.page_before.is_some()
                    && operation.page_after.is_some()
                    && operation.perms_before.is_some()
                    && operation.perms_after.is_none()
                    && operation.brk_before.is_none()
                    && operation.brk_after.is_none()
            }
            GuestMemoryOperationKind::Mprotect => {
                operation.range.len != 0
                    && operation.region_before.is_some()
                    && operation.region_after.is_some()
                    && operation.page_before.is_some()
                    && operation.page_after.is_some()
                    && operation.perms_before.is_some()
                    && operation.perms_after.is_some()
                    && operation.brk_before.is_none()
                    && operation.brk_after.is_none()
            }
            GuestMemoryOperationKind::Brk => {
                operation.region_before.is_none()
                    && operation.region_after.is_none()
                    && operation.page_before.is_none()
                    && operation.page_after.is_none()
                    && operation.perms_before.is_none()
                    && operation.perms_after.is_none()
                    && operation.brk_after.is_some()
            }
        };
        if !valid {
            violations.push(ContractViolation::new(
                ContractViolationKind::ExternalEdgeMetadataMismatch,
                "guest-memory-operation->shape",
                from,
                None,
                "guest memory operation record is missing required operation-specific fields",
            ));
        }
    }

    pub(super) fn validate_evidence_boundary_claims(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for edge in &snapshot.explicit_edges {
            if !edge.evidence_level.can_claim(snapshot.claimed_evidence_level) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::EvidenceBoundaryOverclaim,
                    &edge.label,
                    edge.from,
                    Some(edge.to),
                    "edge evidence boundary is weaker than the snapshot claim",
                ));
            }
        }
    }

    pub(super) fn validate_code_objects(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for code in &snapshot.code_objects {
            let from = code.object_ref();
            if snapshot.artifacts.iter().all(|artifact| artifact.artifact_id != code.artifact_id) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::DanglingEdge,
                    "code->artifact",
                    from,
                    Some(ContractObjectRef::new(ContractObjectKind::Artifact, code.artifact_id, 0)),
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

    pub(super) fn validate_vector_states(
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

    pub(super) fn validate_simd_fault_injections(
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
                ("simd-fault-injection->trap", injection.trap, ContractObjectKind::Trap),
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
            let Some(trap) = snapshot.traps.iter().find(|trap| trap.id == injection.trap.id) else {
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

    pub(super) fn validate_simd_benchmarks(
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

    pub(super) fn validate_simd_context_switch_benchmarks(
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
                ("simd-context-switch-benchmark->saved-vector-state", benchmark.saved_vector_state),
                (
                    "simd-context-switch-benchmark->restored-vector-state",
                    benchmark.restored_vector_state,
                ),
            ] {
                let Some(vector) =
                    snapshot.vector_states.iter().find(|vector| vector.object_ref() == vector_ref)
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
}
