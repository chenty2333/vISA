use contract_core::CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION;

use super::*;

const CORE_CONTRACT_KINDS: [ContractObjectKind; 11] = [
    ContractObjectKind::Artifact,
    ContractObjectKind::CodeObject,
    ContractObjectKind::Store,
    ContractObjectKind::Activation,
    ContractObjectKind::Trap,
    ContractObjectKind::Hostcall,
    ContractObjectKind::Capability,
    ContractObjectKind::WaitToken,
    ContractObjectKind::CleanupTransaction,
    ContractObjectKind::Tombstone,
    ContractObjectKind::ExternalObject,
];

pub(super) fn b3_store_record(
    id: StoreId,
    generation: Generation,
    state: StoreState,
) -> StoreRecord {
    StoreRecord {
        id,
        package: "driver".to_string(),
        artifact: "driver.cwasm".to_string(),
        role: "driver".to_string(),
        fault_policy: "restartable".to_string(),
        fault_domain: 1,
        resource: Some(id),
        state,
        generation,
        restart_count: generation.saturating_sub(1),
    }
}

pub(super) fn b3_capability_record(
    id: CapabilityId,
    owner_store: StoreId,
    owner_store_generation: Generation,
    object: ContractObjectRef,
    source: &str,
    manifest_decl: bool,
) -> CapabilityRecord {
    let mut ledger = CapabilityLedger::new();
    let capability = ledger
        .grant_with_authority_ref(
            "driver",
            "packet-device.net0",
            AuthorityObjectRef::internal(CapabilityClass::PacketDevice, object),
            &["rx"],
            "store",
            Some(owner_store),
            Some(owner_store_generation),
            None,
            source,
            manifest_decl,
        )
        .expect("b3 capability grant");
    let mut record = ledger
        .records()
        .iter()
        .find(|record| record.id == capability)
        .expect("b3 capability record")
        .clone();
    record.id = id;
    record
}

pub(super) fn assert_contract_violation(
    violations: &[ContractViolation],
    kind: ContractViolationKind,
    edge: &str,
) {
    assert!(
        violations.iter().any(|violation| violation.kind == kind && violation.edge == edge),
        "missing violation kind={} edge={} in {:?}",
        kind.as_str(),
        edge,
        violations.iter().map(ContractViolation::summary).collect::<Vec<_>>()
    );
}

fn core_artifact(id: TargetArtifactId, generation: Generation) -> VerifiedArtifact {
    VerifiedArtifact {
        artifact_id: id,
        package: "core".to_string(),
        artifact_name: "core.cwasm".to_string(),
        role: "runtime".to_string(),
        target_profile: "semantic-harness".to_string(),
        artifact_hash: "artifact-hash".to_string(),
        hash_status: "verified".to_string(),
        abi_fingerprint: "abi".to_string(),
        manifest_binding_hash: "manifest-binding".to_string(),
        code_hash: "code-hash".to_string(),
        signature_scheme: "none".to_string(),
        signature_status: "not-signed".to_string(),
        signature_verified: false,
        signer: "test".to_string(),
        imports: Vec::new(),
        exports: Vec::new(),
        memory_plan: TargetMemoryPlan::new(1, 1, 1),
        trap_metadata: Vec::new(),
        address_map: Vec::new(),
        capabilities: Vec::new(),
        hostcalls: Vec::new(),
        payload_len: 0,
        generation,
    }
}

fn core_code(
    id: CodeObjectId,
    artifact: TargetArtifactId,
    generation: Generation,
    state: CodeObjectState,
) -> CodeObject {
    CodeObject {
        id,
        artifact_id: artifact,
        package: "core".to_string(),
        owner_profile: "semantic-harness".to_string(),
        generation,
        text: TargetAddressRange::new(0x1000, 0x100, CodeRangePermission::ReadExecute),
        rodata: TargetAddressRange::new(0x2000, 0x100, CodeRangePermission::ReadOnly),
        trap_metadata: Vec::new(),
        address_map: Vec::new(),
        hostcall_table: None,
        hostcalls: Vec::new(),
        state,
        bound_store: None,
        bound_store_generation: None,
        code_hash: "code-hash".to_string(),
        simd_requirement: CodeObjectSimdRequirement::scalar_only("core identity contract fixture"),
    }
}

fn core_trap(id: TargetTrapId) -> TargetTrapRecord {
    TargetTrapRecord {
        id,
        generation: 1,
        class: TargetTrapClass::HostcallTrap,
        store: None,
        store_generation: None,
        activation: None,
        activation_generation: None,
        code_object: None,
        code_generation: None,
        artifact: None,
        artifact_generation: None,
        offset: Some(0),
        target_pc: None,
        trap_kind: None,
        function_index: None,
        wasm_offset: None,
        debug_symbol: None,
        classification_status: None,
        attribution_status: "semantic-contract-test".to_string(),
        simd_attribution: None,
        hostcall: None,
        fault_policy: "test".to_string(),
        effect: FailureEffect::CompleteWithErrno(5),
        detail: "identity contract fixture".to_string(),
    }
}

fn core_hostcall(id: HostcallTraceId, generation: Generation) -> HostcallTraceRecord {
    HostcallTraceRecord {
        id,
        generation,
        abi_version: "hostcall-frame-v1".to_string(),
        frame_size: 64,
        flags: 0,
        activation: 14,
        activation_generation: 6,
        store: 13,
        store_generation: 5,
        code_object: 12,
        code_generation: 4,
        artifact: 11,
        artifact_generation: 3,
        hostcall_number: 1,
        hostcall_seq: 1,
        caller_offset: 0,
        name: "test.hostcall".to_string(),
        category: HostcallCategory::Service,
        subject: "core".to_string(),
        subject_source: HostcallTraceRecord::SUBJECT_SOURCE_ACTIVE_STATE.to_string(),
        object: "test".to_string(),
        operation: "call".to_string(),
        args: [0; 6],
        cap_args: Vec::new(),
        record_mode: RecordMode::Deterministic,
        allowed: true,
        gate_status: "allowed".to_string(),
        result: "ok".to_string(),
        denial_reason: None,
        ret_tag: HostcallReturnTag::Ok,
        ret0: 0,
        ret1: 0,
        trap_out: None,
        trap_generation_out: None,
        wait_token_out: None,
        wait_token_generation_out: None,
    }
}

fn core_cleanup(id: CleanupTransactionId, generation: Generation) -> FaultCleanupTransaction {
    FaultCleanupTransaction {
        id,
        store: 13,
        store_generation: 5,
        result_store_generation: Some(5),
        activation: Some(14),
        activation_generation: Some(6),
        code_object: Some(12),
        code_generation: Some(4),
        generation,
        started_at: 1,
        finished_at: Some(2),
        state: CleanupTransactionState::Completed,
        reason: "identity-contract".to_string(),
        steps: Vec::new(),
        effects: Vec::new(),
        released_dmw_leases: 0,
        cancelled_waits: 0,
        revoked_capabilities: Vec::new(),
        revoked_capability_refs: Vec::new(),
        dropped_resources: 0,
        unbound_code_object: false,
        state_digest: "digest".to_string(),
        effect: FailureEffect::CompleteWithErrno(0),
    }
}

#[test]
pub(super) fn contract_graph_core_identity_contract_has_stable_names_and_refs() {
    let names = CORE_CONTRACT_KINDS.map(ContractObjectKind::as_str);
    assert_eq!(
        names,
        [
            "artifact",
            "code-object",
            "store",
            "activation",
            "trap",
            "hostcall",
            "capability",
            "wait-token",
            "cleanup-transaction",
            "tombstone",
            "external-object",
        ]
    );
    for (index, left) in names.iter().enumerate() {
        assert!(!names[..index].contains(left), "duplicate core contract object kind name: {left}");
    }

    assert_eq!(
        core_artifact(11, 3).object_ref(),
        ContractObjectRef::new(ContractObjectKind::Artifact, 11, 3)
    );
    assert_eq!(
        core_code(12, 11, 4, CodeObjectState::PublishedRx).object_ref(),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 12, 4)
    );
    assert_eq!(
        b3_store_record(13, 5, StoreState::Running).object_ref(),
        ContractObjectRef::new(ContractObjectKind::Store, 13, 5)
    );
    let activation = ActivationRecord {
        id: 14,
        store: 13,
        store_generation: 5,
        code_object: 12,
        code_generation: 4,
        artifact: 11,
        entry: ActivationEntry::Symbol("_start".to_string()),
        generation: 6,
        state: ActivationState::Running,
        start_event: 1,
        exit_event: None,
        active_dmw_leases: 0,
        blocked_wait: None,
        trap: None,
        return_tag: None,
    };
    assert_eq!(
        activation.object_ref(),
        ContractObjectRef::new(ContractObjectKind::Activation, 14, 6)
    );
    assert_eq!(core_trap(15).object_ref(), ContractObjectRef::new(ContractObjectKind::Trap, 15, 1));
    assert_eq!(
        core_hostcall(16, 7).object_ref(),
        ContractObjectRef::new(ContractObjectKind::Hostcall, 16, 7)
    );
    let capability = b3_capability_record(
        17,
        13,
        5,
        ContractObjectRef::new(ContractObjectKind::Resource, 18, 1),
        "manifest",
        true,
    );
    assert_eq!(
        capability.object_ref(),
        ContractObjectRef::new(ContractObjectKind::Capability, 17, 1)
    );
    let wait = WaitRecord {
        id: 18,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(13),
        owner_store_generation: Some(5),
        kind: SemanticWaitKind::Timer,
        generation: 7,
        state: WaitState::Pending,
        blockers: vec![ContractObjectRef::new(ContractObjectKind::Store, 13, 5)],
        deadline: Some(10),
        cancel_reason: None,
        restart_policy: RestartPolicy::RestartIfAllowed,
        saved_context: None,
    };
    assert_eq!(wait.object_ref(), ContractObjectRef::new(ContractObjectKind::WaitToken, 18, 7));
    assert_eq!(
        core_cleanup(19, 8).object_ref(),
        ContractObjectRef::new(ContractObjectKind::CleanupTransaction, 19, 8)
    );
    let tombstone = TombstoneRecord::new(ContractObjectKind::Store, 13, 5, 99, "store-retired");
    assert_eq!(tombstone.object_ref(), ContractObjectRef::new(ContractObjectKind::Store, 13, 5));
}

#[test]
pub(super) fn contract_graph_identity_edges_distinguish_live_and_historical_generations() {
    let live_store = b3_store_record(1, 2, StoreState::Running);
    let dead_store = b3_store_record(2, 1, StoreState::Dead);
    let source = ContractObjectRef::new(ContractObjectKind::Trap, 10, 1);
    let tombstoned_store = ContractObjectRef::new(ContractObjectKind::Store, live_store.id, 1);
    let valid_history = ContractEdgeRecord::new(
        source,
        tombstoned_store,
        ContractEdgeMode::Historical,
        "trap->retired-store-history",
        1,
    );
    let invalid_live = ContractEdgeRecord::new(
        source,
        tombstoned_store,
        ContractEdgeMode::Live,
        "trap->retired-store-live",
        1,
    );
    let missing_generation = ContractEdgeRecord::new(
        source,
        ContractObjectRef::new(ContractObjectKind::Store, live_store.id, 0),
        ContractEdgeMode::Historical,
        "trap->store-history-without-generation",
        1,
    );
    let dead_live = ContractEdgeRecord::new(
        source,
        dead_store.object_ref(),
        ContractEdgeMode::Live,
        "trap->dead-store-live",
        1,
    );
    let dangling = ContractEdgeRecord::new(
        source,
        ContractObjectRef::new(ContractObjectKind::Store, 999, 1),
        ContractEdgeMode::Historical,
        "trap->missing-store-history",
        1,
    );
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        stores: vec![live_store.clone(), dead_store],
        traps: vec![core_trap(source.id)],
        tombstones: vec![TombstoneRecord::new(
            ContractObjectKind::Store,
            live_store.id,
            1,
            2,
            "retired-generation",
        )],
        explicit_edges: vec![valid_history, invalid_live, missing_generation, dead_live, dangling],
        ..ContractGraphSnapshot::default()
    };

    let violations = validate_contract_graph(&snapshot);
    assert!(
        !violations.iter().any(|violation| violation.edge == "trap->retired-store-history"),
        "valid historical edge to tombstoned generation should not violate: {:?}",
        violations.iter().map(ContractViolation::summary).collect::<Vec<_>>()
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::TombstoneReferencedByLiveEdge,
        "trap->retired-store-live",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::HistoricalEdgeMissingGeneration,
        "trap->store-history-without-generation",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::LiveEdgeReferencesInactiveObject,
        "trap->dead-store-live",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::DanglingEdge,
        "trap->missing-store-history",
    );
}

#[test]
pub(super) fn contract_graph_trap_history_accepts_retired_code_generation_only_with_tombstone() {
    let artifact = core_artifact(1, 1);
    let current_code = core_code(20, artifact.artifact_id, 2, CodeObjectState::PublishedRx);
    let retired_generation = 1;
    let mut trap = core_trap(30);
    trap.code_object = Some(current_code.id);
    trap.code_generation = Some(retired_generation);
    trap.artifact = Some(artifact.artifact_id);
    trap.artifact_generation = Some(artifact.generation);
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: vec![artifact],
        code_objects: vec![current_code.clone()],
        traps: vec![trap],
        tombstones: vec![TombstoneRecord::new(
            ContractObjectKind::CodeObject,
            current_code.id,
            retired_generation,
            7,
            "code-generation-retired",
        )],
        ..ContractGraphSnapshot::default()
    };

    assert_eq!(validate_contract_graph(&snapshot), Vec::new());

    let mut missing_generation_trap = core_trap(31);
    missing_generation_trap.code_object = Some(current_code.id);
    missing_generation_trap.artifact = Some(current_code.artifact_id);
    missing_generation_trap.artifact_generation = Some(1);
    let missing_generation_snapshot = ContractGraphSnapshot {
        artifacts: snapshot.artifacts,
        code_objects: vec![current_code],
        traps: vec![missing_generation_trap],
        tombstones: snapshot.tombstones,
        ..ContractGraphSnapshot::default()
    };
    assert_contract_violation(
        &validate_contract_graph(&missing_generation_snapshot),
        ContractViolationKind::HistoricalEdgeMissingGeneration,
        "trap->code",
    );
}

#[test]
pub(super) fn contract_graph_snapshot_schema_version_is_explicit_contract() {
    assert_eq!(CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION, "contract-graph-snapshot-v0.1");
}

#[test]
pub(super) fn contract_graph_b3_accepts_valid_validator_boundary_snapshot() {
    let store = b3_store_record(1, 1, StoreState::Running);
    let authority_object = ContractObjectRef::new(ContractObjectKind::Resource, 77, 1);
    let capability =
        b3_capability_record(10, store.id, store.generation, authority_object, "manifest", true);
    let wait = WaitRecord {
        id: 20,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(store.id),
        owner_store_generation: Some(store.generation),
        kind: SemanticWaitKind::DeviceIrq,
        generation: 1,
        state: WaitState::Pending,
        blockers: vec![capability.object_ref()],
        deadline: None,
        cancel_reason: None,
        restart_policy: RestartPolicy::RestartIfAllowed,
        saved_context: None,
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        stores: vec![store.clone()],
        capabilities: vec![capability.clone()],
        waits: vec![wait],
        external_objects: vec![ExternalObjectDeclaration::new(
            authority_object,
            "manifest",
            CapabilityClass::PacketDevice.as_str(),
            "packet-device.net0",
        )],
        explicit_edges: vec![ContractEdgeRecord::new(
            store.object_ref(),
            capability.object_ref(),
            ContractEdgeMode::Live,
            "store->capability-live",
            1,
        )],
        ..ContractGraphSnapshot::default()
    };

    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
pub(super) fn contract_graph_rejects_evidence_boundary_overclaim() {
    let store = b3_store_record(1, 1, StoreState::Running);
    let task = TaskRecord {
        id: 2,
        label: "worker".to_string(),
        frontend: FrontendKind::WasmApp,
        state: TaskState::Runnable,
        fault_domain: None,
        pending_wait: None,
        generation: 1,
        resources: Vec::new(),
    };
    let weak_edge = ContractEdgeRecord::new(
        store.object_ref(),
        task.object_ref(),
        ContractEdgeMode::Live,
        "store->task-evidence",
        1,
    )
    .with_evidence_level(EvidenceBoundaryLevel::ReferenceService);
    let strong_edge =
        weak_edge.clone().with_evidence_level(EvidenceBoundaryLevel::PortableArtifactExecution);

    let overclaimed = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::PortableArtifactExecution,
        stores: vec![store.clone()],
        tasks: vec![task.clone()],
        explicit_edges: vec![weak_edge],
        ..ContractGraphSnapshot::default()
    };
    assert_contract_violation(
        &validate_contract_graph(&overclaimed),
        ContractViolationKind::EvidenceBoundaryOverclaim,
        "store->task-evidence",
    );

    let matched_claim = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::PortableArtifactExecution,
        stores: vec![store],
        tasks: vec![task],
        explicit_edges: vec![strong_edge],
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&matched_claim), Vec::new());
}

#[test]
pub(super) fn contract_graph_b3_reports_validator_completeness_matrix() {
    let running_store = b3_store_record(1, 2, StoreState::Running);
    let dead_store = b3_store_record(2, 1, StoreState::Dead);
    let authority_object = ContractObjectRef::new(ContractObjectKind::Resource, 77, 1);
    let external_object = ContractObjectRef::new(ContractObjectKind::ExternalObject, 900, 1);

    let mut stale_handle_capability = b3_capability_record(
        10,
        running_store.id,
        running_store.generation,
        authority_object,
        "manifest",
        true,
    );
    stale_handle_capability.handle_generation = 0;

    let overclaimed_provenance_capability = b3_capability_record(
        11,
        running_store.id,
        running_store.generation,
        authority_object,
        "debug-label-only",
        false,
    );

    let dead_owner_wait = WaitRecord {
        id: 20,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(dead_store.id),
        owner_store_generation: Some(dead_store.generation),
        kind: SemanticWaitKind::DeviceIrq,
        generation: 1,
        state: WaitState::Pending,
        blockers: vec![stale_handle_capability.object_ref()],
        deadline: None,
        cancel_reason: None,
        restart_policy: RestartPolicy::RestartIfAllowed,
        saved_context: None,
    };

    let active_lease_activation = ActivationRecord {
        id: 30,
        store: dead_store.id,
        store_generation: dead_store.generation,
        code_object: 40,
        code_generation: 1,
        artifact: 1,
        entry: ActivationEntry::Symbol("_start".to_string()),
        generation: 1,
        state: ActivationState::Running,
        start_event: 1,
        exit_event: None,
        active_dmw_leases: 1,
        blocked_wait: None,
        trap: None,
        return_tag: None,
    };

    let cleanup_source = ContractObjectRef::new(ContractObjectKind::CleanupTransaction, 42, 1);
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        stores: vec![running_store.clone(), dead_store],
        activations: vec![active_lease_activation],
        capabilities: vec![stale_handle_capability.clone(), overclaimed_provenance_capability],
        waits: vec![dead_owner_wait],
        tombstones: vec![TombstoneRecord::new(
            ContractObjectKind::Store,
            running_store.id,
            1,
            1,
            "old-generation",
        )],
        external_objects: vec![
            ExternalObjectDeclaration::new(
                authority_object,
                "manifest",
                CapabilityClass::PacketDevice.as_str(),
                "packet-device.net0",
            ),
            ExternalObjectDeclaration::new(
                external_object,
                "real-provider",
                CapabilityClass::PacketDevice.as_str(),
                "external.packet-device",
            ),
        ],
        explicit_edges: vec![
            ContractEdgeRecord::new(
                running_store.object_ref(),
                ContractObjectRef::new(ContractObjectKind::Task, 999, 1),
                ContractEdgeMode::Live,
                "store->missing-task",
                1,
            ),
            ContractEdgeRecord::new(
                running_store.object_ref(),
                ContractObjectRef::new(ContractObjectKind::Store, running_store.id, 3),
                ContractEdgeMode::Live,
                "store->future-generation",
                1,
            ),
            ContractEdgeRecord::new(
                running_store.object_ref(),
                ContractObjectRef::new(ContractObjectKind::Store, running_store.id, 1),
                ContractEdgeMode::Live,
                "store->old-generation-live",
                1,
            ),
            ContractEdgeRecord::new(
                cleanup_source,
                stale_handle_capability.object_ref(),
                ContractEdgeMode::CleanupEffect,
                "authorizes",
                1,
            ),
            ContractEdgeRecord::new(
                running_store.object_ref(),
                external_object,
                ContractEdgeMode::External,
                "store->claimed-external",
                1,
            )
            .with_external_metadata("wrong-provider", CapabilityClass::PacketDevice.as_str()),
        ],
        ..ContractGraphSnapshot::default()
    };

    let violations = validate_contract_graph(&snapshot);
    assert_contract_violation(
        &violations,
        ContractViolationKind::DanglingEdge,
        "store->missing-task",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::GenerationMismatch,
        "store->future-generation",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::TombstoneReferencedByLiveEdge,
        "store->old-generation-live",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::CleanupEffectCreatesLiveOwnership,
        "authorizes",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::ExternalEdgeMetadataMismatch,
        "store->claimed-external",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::GenerationMismatch,
        "capability->handle",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::ExternalEdgeMetadataMismatch,
        "capability->provenance",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::LiveEdgeReferencesInactiveObject,
        "wait->owner-store",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::LiveObjectReferencesDeadObject,
        "activation->dmw-lease",
    );
}
