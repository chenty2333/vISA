use super::*;

#[test]
pub(in crate::tests) fn simd_runtime_v0_target_feature_set_records_default_discovery() {
    let mut graph = SemanticGraph::new();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v0-test",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set: 21_000,
            name: "riscv64-qemu-virt-research-target".to_string(),
            discovery_source: "target-runtime-default-profile".to_string(),
            target_profile: "riscv64-qemu-virt-research".to_string(),
            target_arch: "riscv64".to_string(),
            base_isa: "rv64imac".to_string(),
            simd_abi: "riscv-v".to_string(),
            simd_supported: false,
            vector_register_count: 0,
            vector_register_bits: 0,
            scalar_fallback: true,
            unsupported_reason: "default profile does not declare RVV/SIMD".to_string(),
            note: "v0 default SIMD discovery".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.target_feature_set_count(), 1);
    let feature = &graph.target_feature_sets()[0];
    assert_eq!(
        feature.object_ref(),
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_000, 1)
    );
    assert_eq!(feature.state, TargetFeatureSetState::Discovered);
    assert!(!feature.simd_supported);
    assert!(feature.scalar_fallback);
    assert_eq!(feature.vector_register_count, 0);
    assert_eq!(feature.vector_register_bits, 0);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "TargetFeatureSetDiscovered feature_set=21000 target_profile=riscv64-qemu-virt-research target_arch=riscv64 base_isa=rv64imac simd_abi=riscv-v simd_supported=false vector_register_count=0 vector_register_bits=0 scalar_fallback=true generation=1"
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v0_rejects_inconsistent_target_feature_discovery() {
    let mut graph = SemanticGraph::new();

    let supported_without_shape = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v0-test",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set: 21_000,
            name: "bad-supported".to_string(),
            discovery_source: "unit-test".to_string(),
            target_profile: "test-profile".to_string(),
            target_arch: "riscv64".to_string(),
            base_isa: "rv64imac".to_string(),
            simd_abi: "riscv-v".to_string(),
            simd_supported: true,
            vector_register_count: 0,
            vector_register_bits: 0,
            scalar_fallback: true,
            unsupported_reason: "".to_string(),
            note: "bad".to_string(),
        },
    ));
    assert_eq!(supported_without_shape.status, CommandStatus::Rejected);
    assert_eq!(
        supported_without_shape.violations,
        vec!["supported SIMD discovery requires vector register shape".to_string()]
    );

    let unsupported_without_reason = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v0-test",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set: 21_001,
            name: "bad-unsupported".to_string(),
            discovery_source: "unit-test".to_string(),
            target_profile: "test-profile".to_string(),
            target_arch: "riscv64".to_string(),
            base_isa: "rv64imac".to_string(),
            simd_abi: "riscv-v".to_string(),
            simd_supported: false,
            vector_register_count: 0,
            vector_register_bits: 0,
            scalar_fallback: true,
            unsupported_reason: "".to_string(),
            note: "bad".to_string(),
        },
    ));
    assert_eq!(unsupported_without_reason.status, CommandStatus::Rejected);
    assert_eq!(
        unsupported_without_reason.violations,
        vec!["unsupported SIMD discovery requires a reason".to_string()]
    );
    assert!(graph.target_feature_sets().is_empty());
}

#[test]
pub(in crate::tests) fn simd_runtime_v0_invariants_reject_vector_shape_drift() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-qemu-virt-research-target",
        "target-runtime-default-profile",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "default profile does not declare RVV/SIMD",
        "v0 default SIMD discovery",
    ));
    graph.corrupt_target_feature_set_vector_shape_for_test(21_000, 128);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::TargetFeatureSetInvalid { feature_set: 21_000 })
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v4_vector_state_records_unavailable_context_object() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-qemu-virt-research-target",
        "target-runtime-default-profile",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "default profile does not declare RVV/SIMD",
        "v0 default SIMD discovery",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v4-test",
        SemanticCommand::RecordVectorState {
            vector_state: 22_000,
            owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 7, 3),
            owner_store: ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
            code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_000,
                1,
            ),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            register_bytes: 512,
            state: VectorStateState::Unavailable,
            note: "v4 unavailable vector state".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.vector_state_count(), 1);
    let vector_state = &graph.vector_states()[0];
    assert_eq!(
        vector_state.object_ref(),
        ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1)
    );
    assert_eq!(vector_state.state, VectorStateState::Unavailable);
    assert_eq!(vector_state.register_bytes, 512);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "VectorStateRecorded vector_state=22000 activation=activation:7@3 store=store:2@5 code_object=code-object:9@4 target_feature_set=target-feature-set:21000@1 simd_abi=riscv-v vector_register_count=32 vector_register_bits=128 register_bytes=512 state=unavailable generation=1"
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v4_rejects_reserved_vector_state_without_target_support() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-qemu-virt-research-target",
        "target-runtime-default-profile",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "default profile does not declare RVV/SIMD",
        "v0 default SIMD discovery",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v4-test",
        SemanticCommand::RecordVectorState {
            vector_state: 22_000,
            owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 7, 3),
            owner_store: ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
            code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_000,
                1,
            ),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            register_bytes: 512,
            state: VectorStateState::Reserved,
            note: "bad reserved vector state".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Rejected);
    assert_eq!(
        result.violations,
        vec!["reserved vector state requires supported SIMD target feature set".to_string()]
    );
    assert!(graph.vector_states().is_empty());
}

#[test]
pub(in crate::tests) fn simd_runtime_v4_invariants_reject_vector_state_event_drift() {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-qemu-virt-research-target",
        "target-runtime-default-profile",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "default profile does not declare RVV/SIMD",
        "v0 default SIMD discovery",
    ));
    assert!(graph.record_vector_state_with_id(
        22_000,
        ContractObjectRef::new(ContractObjectKind::Activation, 7, 3),
        ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_000, 1),
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Unavailable,
        "v4 unavailable vector state",
    ));
    graph.corrupt_vector_state_owner_activation_generation_for_test(22_000, 4);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::VectorStateMissingEvent { vector_state: 22_000, event: 2 })
    );
}

pub(in crate::tests) fn v5_activation_context_with_reserved_vector_state() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "simd-vector-task");
    let store =
        graph.register_store("v5.simd.store", "v5-simd-context.fake-aot", "service", "restartable");
    graph.set_store_state(store, StoreState::Running);
    let store_generation =
        graph.store_handle(store).map(|handle| handle.generation).expect("store generation");
    let code_object = ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4);
    assert!(graph.create_runtime_activation_with_id(
        11,
        7,
        1,
        Some(store),
        Some(store_generation),
        Some(code_object),
    ));
    assert!(graph.create_activation_context_with_id(12, 11, 1));
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-vector-test-target",
        "semantic-contract-v5-test",
        "riscv64-vector-test",
        "riscv64",
        "rv64gcv",
        "riscv-v",
        true,
        32,
        128,
        false,
        "",
        "v5 supported SIMD discovery",
    ));
    assert!(graph.record_vector_state_with_id(
        22_000,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 1),
        ContractObjectRef::new(ContractObjectKind::Store, store, store_generation),
        code_object,
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_000, 1),
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Reserved,
        "v5 reserved vector state",
    ));
    graph
}

#[test]
pub(in crate::tests) fn simd_runtime_v5_activation_context_tracks_dirty_and_clean_vector_state() {
    let mut graph = v5_activation_context_with_reserved_vector_state();
    let vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1);

    let dirty = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v5-test",
        SemanticCommand::UpdateActivationContextVectorState {
            context: 12,
            context_generation: 1,
            vector_state: Some(vector_ref),
            vector_status: ActivationVectorState::Dirty,
            note: "guest touched vector registers".to_string(),
        },
    ));
    assert_eq!(dirty.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Dirty);
    assert_eq!(graph.activation_contexts()[0].vector_state, Some(vector_ref));
    assert_eq!(graph.activation_contexts()[0].generation, 2);

    let clean = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v5-test",
        SemanticCommand::UpdateActivationContextVectorState {
            context: 12,
            context_generation: 2,
            vector_state: Some(vector_ref),
            vector_status: ActivationVectorState::Clean,
            note: "vector state is synchronized with activation context".to_string(),
        },
    ));
    assert_eq!(clean.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Clean);
    assert_eq!(graph.activation_contexts()[0].generation, 3);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "ActivationContextVectorStateUpdated context=12@2->3 vector_state=vector-state:22000@1 vector_status=clean generation=1"
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v5_rejects_missing_or_stale_vector_state_ref() {
    let mut graph = v5_activation_context_with_reserved_vector_state();

    let missing = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v5-test",
        SemanticCommand::UpdateActivationContextVectorState {
            context: 12,
            context_generation: 1,
            vector_state: None,
            vector_status: ActivationVectorState::Dirty,
            note: "missing vector ref".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    assert_eq!(
        missing.violations,
        vec!["clean or dirty vector context requires vector state".to_string()]
    );

    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v5-test",
        SemanticCommand::UpdateActivationContextVectorState {
            context: 12,
            context_generation: 1,
            vector_state: Some(ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 2)),
            vector_status: ActivationVectorState::Clean,
            note: "stale vector generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(stale.violations, vec!["activation context vector state is missing".to_string()]);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Absent);
}

#[test]
pub(in crate::tests) fn simd_runtime_v5_invariants_reject_vector_context_generation_drift() {
    let mut graph = v5_activation_context_with_reserved_vector_state();
    assert!(graph.update_activation_context_vector_state(
        12,
        1,
        Some(ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1,)),
        ActivationVectorState::Dirty,
        "dirty vector state",
    ));
    graph.corrupt_activation_context_vector_state_generation_for_test(12, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationContextVectorStateMissing { context: 12 })
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v6_lazy_enable_transitions_absent_context_to_dirty() {
    let mut graph = v5_activation_context_with_reserved_vector_state();
    let vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1);

    let enabled = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v6-test",
        SemanticCommand::EnableLazyVectorState {
            context: 12,
            context_generation: 1,
            vector_state: vector_ref,
            note: "first vector instruction enables vector state".to_string(),
        },
    ));

    assert_eq!(enabled.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].vector_status, ActivationVectorState::Dirty);
    assert_eq!(graph.activation_contexts()[0].vector_state, Some(vector_ref));
    assert_eq!(graph.activation_contexts()[0].generation, 2);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "LazyVectorStateEnabled context=12@1->2 vector_state=vector-state:22000@1 vector_status=dirty generation=1"
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v6_rejects_lazy_enable_when_context_already_has_vector_state()
{
    let mut graph = v5_activation_context_with_reserved_vector_state();
    let vector_ref = ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1);
    assert!(graph.enable_lazy_vector_state(12, 1, vector_ref, "first vector use"));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "v6-test",
        SemanticCommand::EnableLazyVectorState {
            context: 12,
            context_generation: 2,
            vector_state: vector_ref,
            note: "second lazy enable".to_string(),
        },
    ));

    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["lazy vector enable requires absent vector context".to_string()]
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v6_rejects_lazy_enable_with_unavailable_vector_state() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "simd-unavailable-task");
    let code_object = ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4);
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, Some(code_object)));
    assert!(graph.create_activation_context_with_id(12, 11, 1));
    assert!(graph.record_target_feature_set_with_id(
        21_000,
        "riscv64-qemu-virt-research-target",
        "target-runtime-default-profile",
        "riscv64-qemu-virt-research",
        "riscv64",
        "rv64imac",
        "riscv-v",
        false,
        0,
        0,
        true,
        "default profile does not declare RVV/SIMD",
        "v6 unavailable SIMD discovery",
    ));
    assert!(graph.record_vector_state_with_id(
        22_000,
        ContractObjectRef::new(ContractObjectKind::Activation, 11, 1),
        ContractObjectRef::new(ContractObjectKind::Store, 2, 5),
        code_object,
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_000, 1),
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Unavailable,
        "v6 unavailable vector state",
    ));

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v6-test",
        SemanticCommand::EnableLazyVectorState {
            context: 12,
            context_generation: 1,
            vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_000, 1),
            note: "first vector instruction on unsupported target".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["activation context vector state must be live-owned".to_string()]
    );
}
