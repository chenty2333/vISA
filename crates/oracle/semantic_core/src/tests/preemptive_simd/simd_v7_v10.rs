use super::*;

pub(in crate::tests) fn v7_preempted_dirty_vector_context() -> SemanticGraph {
    let mut graph = p4_preempted_activation();
    assert!(graph.save_preempted_context_with_ids(12, 13, 6, 1, 0x2000, 0x9000, 0, "timer"));
    assert!(graph.record_target_feature_set_with_id(
        21_002,
        "riscv64-vector-preempt-test-target",
        "semantic-contract-v7-test",
        "riscv64-vector-preempt-test",
        "riscv64",
        "rv64gcv",
        "riscv-v",
        true,
        32,
        128,
        false,
        "",
        "v7 supported SIMD preempt fixture",
    ));
    assert!(graph.record_vector_state_with_id(
        22_002,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 4),
        ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_002, 1),
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Reserved,
        "v7 reserved vector state",
    ));
    assert!(graph.update_activation_context_vector_state(
        12,
        2,
        Some(ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1,)),
        ActivationVectorState::Dirty,
        "dirty vector state before preempt save",
    ));
    graph
}

#[test]
pub(in crate::tests) fn simd_runtime_v7_preempt_saves_dirty_vector_state_as_clean_context() {
    let mut graph = v7_preempted_dirty_vector_context();
    let vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1);

    let saved = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v7-test",
        SemanticCommand::SaveDirtyVectorStateOnPreempt {
            context: 12,
            context_generation: 3,
            saved_context: 13,
            saved_context_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            vector_state: vector_ref,
            note: "timer preempt saves dirty vector state".to_string(),
        },
    ));

    assert_eq!(saved.status, CommandStatus::Applied, "{:?}", saved.violations);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Clean);
    assert_eq!(graph.activation_contexts()[0].generation, 4);
    assert_eq!(graph.activation_contexts()[0].current_saved_context_generation, Some(2));
    assert_eq!(graph.saved_contexts()[0].generation, 2);
    assert_eq!(graph.saved_contexts()[0].context_generation, 4);
    assert_eq!(graph.saved_contexts()[0].vector_state, Some(vector_ref));
    assert_eq!(graph.saved_contexts()[0].vector_status, ActivationVectorState::Clean);
    assert!(graph.saved_contexts()[0].vector_saved_at_event.is_some());
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "DirtyVectorStateSavedOnPreempt saved_context=13@2 context=12@3->4 preemption=6@1 vector_state=vector-state:22002@1 vector_status=clean generation=1"
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v7_rejects_preempt_vector_save_without_dirty_context() {
    let mut graph = p4_preempted_activation();
    assert!(graph.save_preempted_context_with_ids(12, 13, 6, 1, 0x2000, 0x9000, 0, "timer"));

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v7-test",
        SemanticCommand::SaveDirtyVectorStateOnPreempt {
            context: 12,
            context_generation: 2,
            saved_context: 13,
            saved_context_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
            note: "no dirty vector state".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["preempt vector save requires dirty activation vector state".to_string()]
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v7_rejects_stale_saved_context_generation() {
    let mut graph = v7_preempted_dirty_vector_context();

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v7-test",
        SemanticCommand::SaveDirtyVectorStateOnPreempt {
            context: 12,
            context_generation: 3,
            saved_context: 13,
            saved_context_generation: 99,
            preemption: 6,
            preemption_generation: 1,
            vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
            note: "stale saved generation".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["saved activation context does not reference saved context generation".to_string()]
    );
}

pub(in crate::tests) fn v8_saved_vector_context_with_decision() -> SemanticGraph {
    let mut graph = v7_preempted_dirty_vector_context();
    let vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1);
    let saved = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v8-test",
        SemanticCommand::SaveDirtyVectorStateOnPreempt {
            context: 12,
            context_generation: 3,
            saved_context: 13,
            saved_context_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            vector_state: vector_ref,
            note: "timer preempt saves dirty vector state".to_string(),
        },
    ));
    assert_eq!(saved.status, CommandStatus::Applied, "{saved:?}");
    let decision = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v8-test",
        SemanticCommand::RecordSchedulerDecision {
            decision: 14,
            queue: 1,
            queue_generation: 1,
            selected_activation: 11,
            selected_activation_generation: 4,
            reason: "resume-ready".to_string(),
            note: "choose vector-saved activation".to_string(),
        },
    ));
    assert_eq!(decision.status, CommandStatus::Applied, "{decision:?}");
    graph
}

#[test]
pub(in crate::tests) fn simd_runtime_v8_resume_restores_vector_state_to_current_activation_generation()
 {
    let mut graph = v8_saved_vector_context_with_decision();
    let saved_vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1);
    let restored_vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_003, 1);

    let resumed = graph.apply_envelope(CommandEnvelope::new(
        3,
        "v8-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "resume restores vector state".to_string(),
        },
    ));

    assert_eq!(resumed.status, CommandStatus::Applied, "{resumed:?}");
    assert_eq!(graph.runtime_activations()[0].generation, 5);
    assert_eq!(graph.activation_contexts()[0].state, ActivationContextState::Current);
    assert_eq!(graph.activation_contexts()[0].generation, 5);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Clean);
    assert_eq!(graph.activation_contexts()[0].vector_state, Some(restored_vector_ref));
    assert_eq!(graph.saved_contexts()[0].state, SavedContextState::Restored);
    assert_eq!(graph.saved_contexts()[0].vector_state, Some(saved_vector_ref));
    let resume = &graph.activation_resumes()[0];
    assert_eq!(resume.saved_vector_state, Some(saved_vector_ref));
    assert_eq!(resume.restored_vector_state, Some(restored_vector_ref));
    assert_eq!(resume.vector_status, ActivationVectorState::Clean);
    assert!(resume.vector_restored_at_event.is_some());
    let restored_vector = graph
        .vector_states()
        .iter()
        .find(|record| record.object_ref() == restored_vector_ref)
        .unwrap();
    assert_eq!(
        restored_vector.owner_activation,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 5)
    );
    let saved_vector = graph
        .vector_states()
        .iter()
        .find(|record| record.object_ref() == saved_vector_ref)
        .unwrap();
    assert_eq!(saved_vector.state, VectorStateState::Dropped);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "VectorStateRestoredOnResume resume=15@1 context=12@5 saved_context=13@3 saved_vector_state=vector-state:22002@1 restored_vector_state=vector-state:22003@1 vector_status=clean generation=1"
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v8_rejects_resume_when_dirty_vector_state_was_not_saved() {
    let mut graph = v7_preempted_dirty_vector_context();
    let decision = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v8-test",
        SemanticCommand::RecordSchedulerDecision {
            decision: 14,
            queue: 1,
            queue_generation: 1,
            selected_activation: 11,
            selected_activation_generation: 4,
            reason: "resume-ready".to_string(),
            note: "choose dirty vector activation".to_string(),
        },
    ));
    assert_eq!(decision.status, CommandStatus::Applied, "{decision:?}");

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v8-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "must reject dirty vector resume".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["resume vector state is present without saved vector state".to_string()]
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v8_rejects_resume_vector_generation_mismatch() {
    let mut graph = v8_saved_vector_context_with_decision();
    graph.corrupt_activation_context_vector_state_generation_for_test(12, 99);

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        3,
        "v8-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "must reject stale vector generation".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["resume vector state does not match saved context".to_string()]
    );
}

pub(in crate::tests) fn v9_cross_hart_clean_vector_migration_graph(
    vector_status: ActivationVectorState,
) -> SemanticGraph {
    let mut graph = s9_activation_migration_graph();
    assert!(graph.create_activation_context_with_id(12, 11, 4));
    assert!(graph.record_target_feature_set_with_id(
        21_003,
        "riscv64-vector-migration-test-target",
        "semantic-contract-v9-test",
        "riscv64-vector-migration-test",
        "riscv64",
        "rv64gcv",
        "riscv-v",
        true,
        32,
        128,
        false,
        "",
        "v9 supported SIMD migration fixture",
    ));
    assert!(graph.record_vector_state_with_id(
        22_004,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 4),
        ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_003, 1),
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Reserved,
        "v9 reserved vector state before cross-hart migration",
    ));
    assert!(graph.update_activation_context_vector_state(
        12,
        1,
        Some(ContractObjectRef::new(ContractObjectKind::VectorState, 22_004, 1,)),
        vector_status,
        "v9 context vector state before cross-hart migration",
    ));
    graph
}

#[test]
pub(in crate::tests) fn simd_runtime_v9_cross_hart_migration_rehomes_clean_vector_state() {
    let mut graph = v9_cross_hart_clean_vector_migration_graph(ActivationVectorState::Clean);
    let source_vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_004, 1);
    let migrated_vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_005, 1);

    let migrated = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v9-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 71,
            activation: 11,
            activation_generation: 4,
            source_queue: 2,
            source_queue_generation: 2,
            target_queue: 3,
            target_queue_generation: 2,
            source_hart: 2,
            source_hart_generation: 4,
            target_hart: 1,
            target_hart_generation: 2,
            reason: "vector-rebalance".to_string(),
            note: "cross-hart migration rehomes clean vector state".to_string(),
        },
    ));

    assert_eq!(migrated.status, CommandStatus::Applied, "{migrated:?}");
    let migration = &graph.activation_migrations()[0];
    assert_eq!(migration.source_vector_state, Some(source_vector_ref));
    assert_eq!(migration.migrated_vector_state, Some(migrated_vector_ref));
    assert_eq!(migration.vector_status, ActivationVectorState::Clean);
    assert!(migration.vector_migrated_at_event.is_some());
    assert_eq!(migration.context, Some(12));
    assert_eq!(migration.context_generation_before, Some(2));
    assert_eq!(migration.context_generation_after, Some(3));
    let context = &graph.activation_contexts()[0];
    assert_eq!(context.activation_generation, 5);
    assert_eq!(context.vector_state, Some(migrated_vector_ref));
    assert_eq!(context.vector_status, ActivationVectorState::Clean);
    let source_vector = graph
        .vector_states()
        .iter()
        .find(|record| record.object_ref() == source_vector_ref)
        .unwrap();
    assert_eq!(source_vector.state, VectorStateState::Dropped);
    let migrated_vector = graph
        .vector_states()
        .iter()
        .find(|record| record.object_ref() == migrated_vector_ref)
        .unwrap();
    assert_eq!(
        migrated_vector.owner_activation,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 5)
    );
    assert_eq!(migrated_vector.state, VectorStateState::Reserved);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "VectorStateMigratedAcrossHart migration=71@1 context=12@3 source_vector_state=vector-state:22004@1 migrated_vector_state=vector-state:22005@1 vector_status=clean generation=1"
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v9_history_survives_context_generation_advance() {
    let mut graph = v9_cross_hart_clean_vector_migration_graph(ActivationVectorState::Clean);
    let migrated_vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_005, 1);

    assert!(graph.migrate_runnable_activation_with_id(
        71,
        11,
        4,
        2,
        2,
        3,
        2,
        2,
        4,
        1,
        2,
        "vector-rebalance",
        "cross-hart migration rehomes clean vector state",
    ));
    assert!(graph.update_activation_context_vector_state(
        12,
        3,
        Some(migrated_vector_ref),
        ActivationVectorState::Clean,
        "later context bookkeeping must not invalidate migration history",
    ));

    let migration = &graph.activation_migrations()[0];
    assert_eq!(migration.context_generation_after, Some(3));
    assert_eq!(graph.activation_contexts()[0].generation, 4);
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn simd_runtime_v9_rejects_dirty_vector_state_migration() {
    let mut graph = v9_cross_hart_clean_vector_migration_graph(ActivationVectorState::Dirty);

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v9-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 71,
            activation: 11,
            activation_generation: 4,
            source_queue: 2,
            source_queue_generation: 2,
            target_queue: 3,
            target_queue_generation: 2,
            source_hart: 2,
            source_hart_generation: 4,
            target_hart: 1,
            target_hart_generation: 2,
            reason: "vector-rebalance".to_string(),
            note: "must reject dirty vector migration".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["activation migration requires clean vector state".to_string()]
    );
    assert!(graph.activation_migrations().is_empty());
}

#[test]
pub(in crate::tests) fn simd_runtime_v9_invariants_reject_migrated_vector_generation_drift() {
    let mut graph = v9_cross_hart_clean_vector_migration_graph(ActivationVectorState::Clean);
    assert!(graph.migrate_runnable_activation_with_id(
        71,
        11,
        4,
        2,
        2,
        3,
        2,
        2,
        4,
        1,
        2,
        "vector-rebalance",
        "cross-hart migration rehomes clean vector state",
    ));
    graph.corrupt_vector_state_owner_activation_generation_for_test(22_005, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationContextVectorStateInvalid { context: 12 })
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v10_fault_injection_records_exact_trap_attribution() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_010,
        "riscv64-qemu-virt-no-rvv",
        "semantic-contract-v10-test",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "RVV disabled for injected fault test",
        "v10 unsupported SIMD target fixture",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v10-test",
        SemanticCommand::RecordSimdFaultInjection {
            injection: 22_010,
            activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 4),
            code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            trap: ContractObjectRef::new(ContractObjectKind::Trap, 33, 1),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_010,
                1,
            ),
            vector_state: None,
            kind: SimdFaultInjectionKind::UnsupportedFeature,
            effect: SimdFaultInjectionEffect::ActivationTrapped,
            required_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            injected_faults: 1,
            note: "record unsupported SIMD injection".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.simd_fault_injection_count(), 1);
    let injection = &graph.simd_fault_injections()[0];
    assert_eq!(
        injection.object_ref(),
        ContractObjectRef::new(ContractObjectKind::SimdFaultInjection, 22_010, 1)
    );
    assert_eq!(injection.activation.generation, 4);
    assert_eq!(injection.code_object.generation, 4);
    assert_eq!(injection.trap.generation, 1);
    assert_eq!(
        injection.target_feature_set,
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_010, 1)
    );
    assert_eq!(injection.kind, SimdFaultInjectionKind::UnsupportedFeature);
    assert_eq!(injection.effect, SimdFaultInjectionEffect::ActivationTrapped);
    assert_eq!(injection.injected_faults, 1);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SimdFaultInjectionRecorded injection=22010 activation=activation:11@4 code_object=code-object:9@4 trap=trap:33@1 target_feature_set=target-feature-set:21010@1 vector_state=none kind=unsupported-feature effect=activation-trapped generation=1"
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v10_rejects_unsupported_fault_with_live_vector_state() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_010,
        "riscv64-qemu-virt-no-rvv",
        "semantic-contract-v10-test",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "RVV disabled for injected fault test",
        "v10 unsupported SIMD target fixture",
    ));

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v10-test",
        SemanticCommand::RecordSimdFaultInjection {
            injection: 22_010,
            activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 4),
            code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            trap: ContractObjectRef::new(ContractObjectKind::Trap, 33, 1),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_010,
                1,
            ),
            vector_state: Some(ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1)),
            kind: SimdFaultInjectionKind::UnsupportedFeature,
            effect: SimdFaultInjectionEffect::ActivationTrapped,
            required_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            injected_faults: 1,
            note: "bad unsupported SIMD injection".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec![
            "unsupported SIMD fault injection must record a trap without live vector state"
                .to_string()
        ]
    );
    assert!(graph.simd_fault_injections().is_empty());
    assert!(graph.check_invariants().is_ok());
}

#[test]
pub(in crate::tests) fn simd_runtime_v10_rejects_illegal_instruction_on_unsupported_target() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_010,
        "riscv64-qemu-virt-no-rvv",
        "semantic-contract-v10-test",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "RVV disabled for injected fault test",
        "v10 unsupported SIMD target fixture",
    ));

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v10-test",
        SemanticCommand::RecordSimdFaultInjection {
            injection: 22_010,
            activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 4),
            code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            trap: ContractObjectRef::new(ContractObjectKind::Trap, 33, 1),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_010,
                1,
            ),
            vector_state: None,
            kind: SimdFaultInjectionKind::IllegalInstruction,
            effect: SimdFaultInjectionEffect::ActivationTrapped,
            required_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            injected_faults: 1,
            note: "bad illegal SIMD injection".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["SIMD illegal instruction injection requires a supported feature set".to_string()]
    );
    assert!(graph.simd_fault_injections().is_empty());
}
