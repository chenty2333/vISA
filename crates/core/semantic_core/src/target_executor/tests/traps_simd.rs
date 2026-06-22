use super::*;

#[test]
fn dmw_handle_mode_lease_cannot_cross_pending_or_snapshot_barrier() {
    let (_artifact, store, code, capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let lease = executor.acquire_dmw_lease(activation, "dmw.handle.1").unwrap();
    assert_eq!(executor.snapshot_barrier(), Err(TargetExecutorError::DmwLeaseActive));
    assert_eq!(
        executor.invoke_hostcall(
            &code,
            HostcallFrame::new_bound(activation, &store.store, &code, 9, "wait.timer", "park", 1,)
                .to_wire_frame(),
            &capabilities,
        ),
        Err(TargetExecutorError::DmwLeaseActive)
    );
    assert_eq!(executor.traps()[0].class, TargetTrapClass::WindowTrap);
    assert!(!executor.dmw_leases()[0].active);
    executor.release_dmw_lease(lease).unwrap();
    assert_eq!(executor.snapshot_barrier(), Ok(()));
}

#[test]
fn typed_trap_surface_and_migration_classification_are_queryable() {
    let (_artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    for class in [
        TargetTrapClass::GuestTrap,
        TargetTrapClass::SupervisorStoreTrap,
        TargetTrapClass::CapabilityTrap,
        TargetTrapClass::WindowTrap,
        TargetTrapClass::HostcallTrap,
        TargetTrapClass::CodeObjectTrap,
        TargetTrapClass::SubstrateFault,
    ] {
        executor.synthetic_trap(
            class,
            store.store.id,
            Some(activation),
            Some(&code),
            None,
            "typed trap harness",
        );
    }
    assert_eq!(executor.traps().len(), 7);
    assert!(executor.traps().iter().any(|trap| trap.class == TargetTrapClass::CodeObjectTrap
        && trap.code_object == Some(code.id)
        && trap.artifact == Some(code.artifact_id)));
    let migration = executor.classify_migration_objects(core::slice::from_ref(&code));
    assert!(migration.iter().any(|record| record.class == MigrationObjectClass::Migrated));
    assert!(migration.iter().any(|record| record.class == MigrationObjectClass::Rebuilt));
    assert!(migration.iter().any(|record| record.class == MigrationObjectClass::NeverMigrated));
}

#[test]
fn trap_record_uses_historical_refs() {
    let (_artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("entry_trap_ebreak".to_string()),
        )
        .unwrap();
    let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::WasmUnreachable,
        1,
        0x20,
        7,
    )];

    let trap_id =
        executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == trap_id).unwrap();

    assert_eq!(trap.store, Some(store.store.id));
    assert_eq!(trap.store_generation, Some(store.store.generation));
    assert_eq!(trap.activation, Some(activation));
    assert!(trap.activation_generation.is_some());
    assert_eq!(trap.code_object, Some(code.id));
    assert_eq!(trap.code_generation, Some(code.generation));
    assert_eq!(trap.artifact, Some(code.artifact_id));
    assert_eq!(trap.artifact_generation, Some(TARGET_ARTIFACT_GENERATION_V1));
    assert_eq!(trap.offset, Some(offset));
    assert_eq!(trap.trap_kind.as_deref(), Some("wasm-unreachable"));
    assert_eq!(trap.attribution_status, "trap-map-attributed");
    assert_eq!(trap.classification_status.as_deref(), Some("wasm-unreachable"));
}

#[test]
fn trap_map_records_success_and_failure_attribution_statuses() {
    let (_artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::WasmUnreachable,
        1,
        0x20,
        7,
    )];

    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("trap_success".to_string()))
        .unwrap();
    let success =
        executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();
    assert_eq!(
        executor.traps().iter().find(|trap| trap.id == success).unwrap().attribution_status,
        "trap-map-attributed"
    );

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("trap_unknown_pc".to_string()),
        )
        .unwrap();
    let unknown_pc =
        executor.trap_exit_by_pc(activation, &code, code.text.end() + 0x1000, &trap_map).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == unknown_pc).unwrap();
    assert_eq!(trap.attribution_status, "trap-map-unknown-pc");
    assert_eq!(trap.trap_kind.as_deref(), Some("unknown-code-fault"));
    assert_eq!(trap.code_object, None);

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("trap_missing_entry".to_string()),
        )
        .unwrap();
    let missing_entry =
        executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &[]).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == missing_entry).unwrap();
    assert_eq!(trap.attribution_status, "trap-map-missing-entry");
    assert_eq!(trap.trap_kind.as_deref(), Some("unknown-code-trap"));
    assert_eq!(trap.code_object, Some(code.id));

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("trap_stale_code".to_string()),
        )
        .unwrap();
    let mut retired_code = code.clone();
    retired_code.state = CodeObjectState::Retired;
    let stale = executor
        .trap_exit_by_pc(activation, &retired_code, retired_code.text.start + offset, &trap_map)
        .unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == stale).unwrap();
    assert_eq!(trap.attribution_status, "trap-map-stale-code");
    assert_eq!(trap.trap_kind.as_deref(), Some("stale-code-execution-fault"));
}

#[test]
fn simd_runtime_v3_trap_records_requirement_attribution() {
    let (artifact, store, mut code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v3 simd trap attribution",
    );
    code.generation += 1;
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("simd_fault".to_string()))
        .unwrap();
    let offset = 0x40;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::SimdUnsupported,
        7,
        0x80,
        13,
    )];

    let trap_id =
        executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == trap_id).unwrap();
    let simd = trap.simd_attribution.as_ref().expect("SIMD trap attribution");

    assert_eq!(trap.class, TargetTrapClass::CodeObjectTrap);
    assert_eq!(trap.trap_kind.as_deref(), Some("simd-unsupported"));
    assert_eq!(simd.classification, SimdTrapClassification::UnsupportedTargetProfile);
    assert_eq!(simd.required_abi, "riscv-v");
    assert_eq!(simd.target_feature_set, Some(feature_set.object_ref()));

    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        activations: executor.activations().to_vec(),
        traps: executor.traps().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v3_rejects_simd_trap_without_requirement() {
    let (artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("unexpected_simd_fault".to_string()),
        )
        .unwrap();
    let offset = 0x44;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::SimdIllegalInstruction,
        8,
        0x84,
        14,
    )];
    executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();

    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        stores: Vec::from([store.store]),
        activations: executor.activations().to_vec(),
        traps: executor.traps().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.iter().any(|violation| {
        violation.edge == "trap->simd-requirement"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn simd_runtime_v10_fault_injection_validates_exact_trap_attribution() {
    let (artifact, store, mut code, _capabilities) = running_store_and_code();
    let mut feature_set = target_feature_set_record();
    feature_set.simd_supported = false;
    feature_set.vector_register_count = 0;
    feature_set.vector_register_bits = 0;
    feature_set.unsupported_reason = "RVV disabled for fault injection".to_string();
    code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v10 simd fault injection attribution",
    );
    code.generation += 1;
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("simd_fault_injection".to_string()),
        )
        .unwrap();
    let offset = 0x48;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::SimdUnsupported,
        9,
        0x88,
        15,
    )];
    let trap_id =
        executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == trap_id).unwrap();
    let injection = SimdFaultInjectionRecord {
        id: 22_010,
        activation: ContractObjectRef::new(
            ContractObjectKind::Activation,
            activation,
            trap.activation_generation.unwrap(),
        ),
        code_object: code.object_ref(),
        trap: trap.object_ref(),
        target_feature_set: feature_set.object_ref(),
        vector_state: None,
        kind: SimdFaultInjectionKind::UnsupportedFeature,
        effect: SimdFaultInjectionEffect::ActivationTrapped,
        required_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        injected_faults: 1,
        generation: 1,
        state: SimdFaultInjectionState::Recorded,
        recorded_at_event: 99,
        note: "v10 SIMD fault injection".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        activations: executor.activations().to_vec(),
        traps: executor.traps().to_vec(),
        simd_fault_injections: Vec::from([injection]),
        ..ContractGraphSnapshot::default()
    };

    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v10_rejects_fault_injection_trap_kind_mismatch() {
    let (artifact, store, mut code, _capabilities) = running_store_and_code();
    let mut feature_set = target_feature_set_record();
    feature_set.simd_supported = false;
    feature_set.vector_register_count = 0;
    feature_set.vector_register_bits = 0;
    feature_set.unsupported_reason = "RVV disabled for fault injection".to_string();
    code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v10 simd fault injection attribution",
    );
    code.generation += 1;
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("simd_fault_injection".to_string()),
        )
        .unwrap();
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        0x48,
        0x4c,
        TrapKindV1::SimdUnsupported,
        9,
        0x88,
        15,
    )];
    let trap_id =
        executor.trap_exit_by_pc(activation, &code, code.text.start + 0x48, &trap_map).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == trap_id).unwrap();
    let injection = SimdFaultInjectionRecord {
        id: 22_010,
        activation: ContractObjectRef::new(
            ContractObjectKind::Activation,
            activation,
            trap.activation_generation.unwrap(),
        ),
        code_object: code.object_ref(),
        trap: trap.object_ref(),
        target_feature_set: feature_set.object_ref(),
        vector_state: None,
        kind: SimdFaultInjectionKind::IllegalInstruction,
        effect: SimdFaultInjectionEffect::ActivationTrapped,
        required_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        injected_faults: 1,
        generation: 1,
        state: SimdFaultInjectionState::Recorded,
        recorded_at_event: 99,
        note: "bad V10 SIMD fault injection".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        activations: executor.activations().to_vec(),
        traps: executor.traps().to_vec(),
        simd_fault_injections: Vec::from([injection]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "simd-fault-injection->trap"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
    assert!(violations.iter().any(|violation| {
        violation.edge == "simd-fault-injection->target-feature-set"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn simd_runtime_v10_rejects_fault_injection_wrong_ref_kind() {
    let (artifact, store, code, _capabilities) = running_store_and_code();
    let mut feature_set = target_feature_set_record();
    feature_set.simd_supported = false;
    feature_set.vector_register_count = 0;
    feature_set.vector_register_bits = 0;
    feature_set.unsupported_reason = "RVV disabled for fault injection".to_string();
    let injection = SimdFaultInjectionRecord {
        id: 22_010,
        activation: store.store.object_ref(),
        code_object: code.object_ref(),
        trap: ContractObjectRef::new(ContractObjectKind::Trap, 33, 1),
        target_feature_set: feature_set.object_ref(),
        vector_state: None,
        kind: SimdFaultInjectionKind::UnsupportedFeature,
        effect: SimdFaultInjectionEffect::ActivationTrapped,
        required_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        injected_faults: 1,
        generation: 1,
        state: SimdFaultInjectionState::Recorded,
        recorded_at_event: 99,
        note: "bad V10 SIMD fault injection ref kind".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        simd_fault_injections: Vec::from([injection]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "simd-fault-injection->activation"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn simd_runtime_v11_benchmark_validates_scalar_and_vector_code_requirements() {
    let (artifact, store, scalar_code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    let mut vector_code = scalar_code.clone();
    vector_code.id += 1;
    vector_code.generation += 1;
    vector_code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v11 vector benchmark code",
    );
    let benchmark = SimdBenchmarkRecord {
        id: 22_011,
        target_feature_set: feature_set.object_ref(),
        scalar_code_object: scalar_code.object_ref(),
        vector_code_object: vector_code.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        workload_units: 4096,
        scalar_nanos: 120_000,
        vector_nanos: 40_000,
        speedup_milli: 3000,
        context_overhead_nanos: 80_000,
        generation: 1,
        state: SimdBenchmarkState::Recorded,
        recorded_at_event: 99,
        note: "v11 scalar/vector benchmark".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([scalar_code, vector_code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        simd_benchmarks: Vec::from([benchmark]),
        ..ContractGraphSnapshot::default()
    };

    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v11_rejects_benchmark_scalar_code_that_declares_simd() {
    let (artifact, store, mut scalar_code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    scalar_code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "bad v11 scalar benchmark code",
    );
    scalar_code.generation += 1;
    let mut vector_code = scalar_code.clone();
    vector_code.id += 1;
    vector_code.generation += 1;
    let benchmark = SimdBenchmarkRecord {
        id: 22_011,
        target_feature_set: feature_set.object_ref(),
        scalar_code_object: scalar_code.object_ref(),
        vector_code_object: vector_code.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        workload_units: 4096,
        scalar_nanos: 120_000,
        vector_nanos: 40_000,
        speedup_milli: 3000,
        context_overhead_nanos: 80_000,
        generation: 1,
        state: SimdBenchmarkState::Recorded,
        recorded_at_event: 99,
        note: "bad v11 scalar/vector benchmark".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([scalar_code, vector_code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        simd_benchmarks: Vec::from([benchmark]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "simd-benchmark->scalar-code"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn simd_runtime_v12_context_switch_benchmark_validates_preempt_resume_vector_refs() {
    let (artifact, store, code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    let activation = ActivationRecord {
        id: 11,
        store: store.store.id,
        store_generation: store.store.generation,
        code_object: code.id,
        code_generation: code.generation,
        artifact: artifact.artifact_id,
        profile: code.owner_profile.clone(),
        entry: ActivationEntry::Symbol("v12_vector_context_switch".to_string()),
        generation: 5,
        state: ActivationState::Running,
        start_event: 1,
        exit_event: None,
        active_dmw_leases: 0,
        blocked_wait: None,
        trap: None,
        return_tag: None,
    };
    let preemption = PreemptionRecord {
        id: 9_070,
        activation: activation.id,
        activation_generation_before: 3,
        activation_generation_after: 4,
        timer_interrupt: 9_070,
        timer_interrupt_generation: 1,
        queue: 9_070,
        queue_generation: 2,
        generation: 1,
        state: PreemptionState::Applied,
        preempted_at_event: 10,
        note: "v12 preempt benchmark fixture".to_string(),
    };
    let saved_vector_state = VectorStateRecord {
        id: 22_002,
        owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 5),
        owner_store: ContractObjectRef::new(
            ContractObjectKind::Store,
            store.store.id,
            store.store.generation,
        ),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Dropped,
        recorded_at_event: 11,
        note: "v12 saved vector state".to_string(),
    };
    let restored_vector_state = VectorStateRecord {
        id: 22_003,
        owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 5),
        owner_store: ContractObjectRef::new(
            ContractObjectKind::Store,
            store.store.id,
            store.store.generation,
        ),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Reserved,
        recorded_at_event: 12,
        note: "v12 restored vector state".to_string(),
    };
    let resume = ActivationResumeRecord {
        id: 9_071,
        scheduler_decision: 9_071,
        scheduler_decision_generation: 1,
        activation: activation.id,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 9_070,
        owner_task_generation: 1,
        queue: 9_070,
        queue_generation: 2,
        context: Some(9_070),
        context_generation_before: Some(4),
        context_generation_after: Some(5),
        saved_context: Some(9_070),
        saved_context_generation: Some(2),
        saved_vector_state: Some(saved_vector_state.object_ref()),
        restored_vector_state: Some(restored_vector_state.object_ref()),
        vector_status: ActivationVectorState::Clean,
        vector_restored_at_event: Some(13),
        generation: 1,
        state: ActivationResumeState::Applied,
        resumed_at_event: 13,
        note: "v12 resume benchmark fixture".to_string(),
    };
    let benchmark = SimdContextSwitchBenchmarkRecord {
        id: 22_012,
        preemption: preemption.object_ref(),
        activation_resume: resume.object_ref(),
        saved_vector_state: saved_vector_state.object_ref(),
        restored_vector_state: restored_vector_state.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        sample_count: 64,
        scalar_context_switch_nanos: 30_000,
        vector_context_switch_nanos: 46_384,
        overhead_nanos: 16_384,
        budget_nanos: 50_000,
        generation: 1,
        state: SimdContextSwitchBenchmarkState::Recorded,
        recorded_at_event: 99,
        note: "v12 context switch benchmark".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        vector_states: Vec::from([saved_vector_state, restored_vector_state]),
        simd_context_switch_benchmarks: Vec::from([benchmark]),
        preemptions: Vec::from([preemption]),
        activation_resumes: Vec::from([resume]),
        stores: Vec::from([store.store]),
        activations: Vec::from([activation]),
        ..ContractGraphSnapshot::default()
    };

    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v12_rejects_benchmark_resume_vector_mismatch() {
    let (artifact, store, code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    let activation = ActivationRecord {
        id: 11,
        store: store.store.id,
        store_generation: store.store.generation,
        code_object: code.id,
        code_generation: code.generation,
        artifact: artifact.artifact_id,
        profile: code.owner_profile.clone(),
        entry: ActivationEntry::Symbol("v12_vector_context_switch".to_string()),
        generation: 5,
        state: ActivationState::Running,
        start_event: 1,
        exit_event: None,
        active_dmw_leases: 0,
        blocked_wait: None,
        trap: None,
        return_tag: None,
    };
    let preemption = PreemptionRecord {
        id: 9_070,
        activation: activation.id,
        activation_generation_before: 3,
        activation_generation_after: 4,
        timer_interrupt: 9_070,
        timer_interrupt_generation: 1,
        queue: 9_070,
        queue_generation: 2,
        generation: 1,
        state: PreemptionState::Applied,
        preempted_at_event: 10,
        note: "v12 preempt benchmark fixture".to_string(),
    };
    let saved_vector_state = VectorStateRecord {
        id: 22_002,
        owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 5),
        owner_store: ContractObjectRef::new(
            ContractObjectKind::Store,
            store.store.id,
            store.store.generation,
        ),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Dropped,
        recorded_at_event: 11,
        note: "v12 saved vector state".to_string(),
    };
    let restored_vector_state = VectorStateRecord {
        id: 22_003,
        owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 5),
        owner_store: ContractObjectRef::new(
            ContractObjectKind::Store,
            store.store.id,
            store.store.generation,
        ),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Reserved,
        recorded_at_event: 12,
        note: "v12 restored vector state".to_string(),
    };
    let resume = ActivationResumeRecord {
        id: 9_071,
        scheduler_decision: 9_071,
        scheduler_decision_generation: 1,
        activation: activation.id,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 9_070,
        owner_task_generation: 1,
        queue: 9_070,
        queue_generation: 2,
        context: Some(9_070),
        context_generation_before: Some(4),
        context_generation_after: Some(5),
        saved_context: Some(9_070),
        saved_context_generation: Some(2),
        saved_vector_state: Some(saved_vector_state.object_ref()),
        restored_vector_state: None,
        vector_status: ActivationVectorState::Clean,
        vector_restored_at_event: Some(13),
        generation: 1,
        state: ActivationResumeState::Applied,
        resumed_at_event: 13,
        note: "bad v12 resume benchmark fixture".to_string(),
    };
    let benchmark = SimdContextSwitchBenchmarkRecord {
        id: 22_012,
        preemption: preemption.object_ref(),
        activation_resume: resume.object_ref(),
        saved_vector_state: saved_vector_state.object_ref(),
        restored_vector_state: restored_vector_state.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        sample_count: 64,
        scalar_context_switch_nanos: 30_000,
        vector_context_switch_nanos: 46_384,
        overhead_nanos: 16_384,
        budget_nanos: 50_000,
        generation: 1,
        state: SimdContextSwitchBenchmarkState::Recorded,
        recorded_at_event: 99,
        note: "bad v12 context switch benchmark".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        vector_states: Vec::from([saved_vector_state, restored_vector_state]),
        simd_context_switch_benchmarks: Vec::from([benchmark]),
        preemptions: Vec::from([preemption]),
        activation_resumes: Vec::from([resume]),
        stores: Vec::from([store.store]),
        activations: Vec::from([activation]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "simd-context-switch-benchmark->activation-resume"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn simd_runtime_v4_vector_state_edges_validate_exact_generations() {
    let (artifact, store, mut code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v4 vector state object",
    );
    code.generation += 1;
    let mut executor = TargetExecutor::new();
    executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("simd_vector_state".to_string()),
        )
        .unwrap();
    let activation = executor.activations()[0].clone();
    let vector_state = VectorStateRecord {
        id: 22_000,
        owner_activation: activation.object_ref(),
        owner_store: store.store.object_ref(),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Reserved,
        recorded_at_event: 1,
        note: "v4 vector state object".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        vector_states: Vec::from([vector_state]),
        stores: Vec::from([store.store]),
        activations: executor.activations().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v4_rejects_live_vector_state_owned_by_dead_activation() {
    let (artifact, store, mut code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v4 vector state object",
    );
    code.generation += 1;
    let mut executor = TargetExecutor::new();
    executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("simd_vector_state".to_string()),
        )
        .unwrap();
    let mut activation = executor.activations()[0].clone();
    activation.state = ActivationState::Dropped;
    let vector_state = VectorStateRecord {
        id: 22_000,
        owner_activation: activation.object_ref(),
        owner_store: store.store.object_ref(),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Reserved,
        recorded_at_event: 1,
        note: "v4 vector state object".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        vector_states: Vec::from([vector_state]),
        stores: Vec::from([store.store]),
        activations: Vec::from([activation]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.iter().any(|violation| {
        violation.edge == "vector-state->activation"
            && violation.kind == ContractViolationKind::LiveEdgeReferencesInactiveObject
    }));
}

#[test]
fn cleanup_targets_exact_store_generation() {
    let (_artifact, mut store, mut code, mut capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("entry_trap_ebreak".to_string()),
        )
        .unwrap();
    let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::WasmUnreachable,
        1,
        0x20,
        7,
    )];
    executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();
    let fault_generation = store.store.generation;

    let cleanup_id = executor
        .run_fault_cleanup(
            &mut store.store,
            Some(activation),
            Some(&mut code),
            &mut capabilities,
            "trap-cleanup",
        )
        .unwrap();
    let cleanup =
        executor.cleanup_transactions().iter().find(|cleanup| cleanup.id == cleanup_id).unwrap();

    assert_eq!(cleanup.store_generation, fault_generation);
    assert_eq!(cleanup.result_store_generation, Some(fault_generation + 1));
}

#[test]
fn trap_exit_rejects_code_object_attribution_mismatch() {
    let (_artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("entry_trap_ebreak".to_string()),
        )
        .unwrap();
    let mut wrong_code = code.clone();
    wrong_code.id += 1;
    let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, wrong_code.id, wrong_code.generation),
        offset,
        offset + 4,
        TrapKindV1::WasmUnreachable,
        1,
        0x20,
        7,
    )];

    let result = executor.trap_exit_by_pc(
        activation,
        &wrong_code,
        wrong_code.text.start + offset,
        &trap_map,
    );

    assert_eq!(result, Err(TargetExecutorError::CodeObjectMismatch));
    let trap = executor.traps().last().expect("mismatch trap is visible");
    assert_eq!(trap.class, TargetTrapClass::CodeObjectTrap);
    assert_eq!(trap.fault_policy, "trap-attribution-failure");
    assert_eq!(trap.activation, Some(activation));
    assert!(trap.activation_generation.is_some());
}
