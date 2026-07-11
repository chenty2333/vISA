use contract_core as cc;

use super::{
    contract_graph::{assert_contract_violation, b3_capability_record, b3_store_record},
    *,
};

#[test]
fn phase2_identity_generation_and_graph_edges_cover_positive_and_negative_cases() {
    let live_store = b3_store_record(1, 2, StoreState::Running);
    let from = live_store.object_ref();
    let valid_live = ContractEdgeRecord::new(
        from,
        live_store.object_ref(),
        ContractEdgeMode::Live,
        "store->store-live",
        1,
    );
    let future_generation = ContractEdgeRecord::new(
        from,
        ContractObjectRef::new(ContractObjectKind::Store, live_store.id, live_store.generation + 1),
        ContractEdgeMode::Live,
        "store->future-generation",
        1,
    );
    let missing_store = ContractEdgeRecord::new(
        from,
        ContractObjectRef::new(ContractObjectKind::Store, 999, 1),
        ContractEdgeMode::Live,
        "store->missing-store",
        1,
    );
    let tombstoned_live = ContractEdgeRecord::new(
        from,
        ContractObjectRef::new(ContractObjectKind::Store, live_store.id, 1),
        ContractEdgeMode::Live,
        "store->old-generation-live",
        1,
    );
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        stores: vec![live_store.clone()],
        tombstones: vec![TombstoneRecord::new(
            ContractObjectKind::Store,
            live_store.id,
            1,
            1,
            "retired-generation",
        )],
        explicit_edges: vec![valid_live, future_generation, missing_store, tombstoned_live],
        ..ContractGraphSnapshot::default()
    };

    let violations = validate_contract_graph(&snapshot);
    assert!(
        !violations.iter().any(|violation| violation.edge == "store->store-live"),
        "valid live edge should not violate: {:?}",
        violations.iter().map(ContractViolation::summary).collect::<Vec<_>>()
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::GenerationMismatch,
        "store->future-generation",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::DanglingEdge,
        "store->missing-store",
    );
    assert_contract_violation(
        &violations,
        ContractViolationKind::TombstoneReferencedByLiveEdge,
        "store->old-generation-live",
    );
}

#[test]
fn phase2_rejected_command_transactions_do_not_mutate_semantic_state() {
    let subject = cc::ObjectRef::new(cc::ObjectKind::Store, 7, 3).expect("valid store ref");
    let violation = cc::ValidationViolation::new(
        "precondition-failed",
        subject,
        "store-generation",
        "3",
        "2",
        "command observed a stale store generation",
    );
    let transaction = cc::CommandTransaction::new("cmd-1", "semantic-core", "capability-revoke")
        .with_effect(cc::ContractFactEffect::semantic(subject, "revokes", "capability=9"))
        .with_event(cc::EventEvidence::semantic(1, "capability-revoke", subject, 1))
        .rejected(violation);

    assert!(transaction.is_rejected());
    assert!(transaction.effects.is_empty());
    assert!(transaction.events.is_empty());
    transaction
        .validates_no_mutation_on_reject()
        .expect("rejected command must not mutate semantic state");
}

#[test]
fn phase2_capability_authority_and_wait_state_validate_owner_generation() {
    let running_store = b3_store_record(1, 1, StoreState::Running);
    let dead_store = b3_store_record(2, 1, StoreState::Dead);
    let authority_object = ContractObjectRef::new(ContractObjectKind::Resource, 77, 1);
    let capability = b3_capability_record(
        10,
        running_store.id,
        running_store.generation,
        authority_object,
        "manifest",
        true,
    );
    let valid_wait = WaitRecord {
        id: 20,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(running_store.id),
        owner_store_generation: Some(running_store.generation),
        kind: SemanticWaitKind::DeviceIrq,
        generation: 1,
        state: WaitState::Pending,
        blockers: vec![capability.object_ref()],
        deadline: None,
        cancel_reason: None,
        restart_policy: RestartPolicy::RestartIfAllowed,
        saved_context: None,
    };
    let invalid_wait = WaitRecord {
        id: 21,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(dead_store.id),
        owner_store_generation: Some(dead_store.generation),
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
        stores: vec![running_store, dead_store],
        capabilities: vec![capability],
        waits: vec![valid_wait, invalid_wait],
        external_objects: vec![ExternalObjectDeclaration::new(
            authority_object,
            "manifest",
            CapabilityClass::PacketDevice.as_str(),
            "packet-device.net0",
        )],
        ..ContractGraphSnapshot::default()
    };

    assert_contract_violation(
        &validate_contract_graph(&snapshot),
        ContractViolationKind::LiveEdgeReferencesInactiveObject,
        "wait->owner-store",
    );
}

#[test]
fn phase2_event_trap_cleanup_and_stable_view_records_stay_semantic() {
    let cleanup = ContractObjectRef::new(ContractObjectKind::CleanupTransaction, 42, 1);
    let capability = ContractObjectRef::new(ContractObjectKind::Capability, 9, 1);
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        explicit_edges: vec![ContractEdgeRecord::new(
            cleanup,
            capability,
            ContractEdgeMode::CleanupEffect,
            "authorizes",
            1,
        )],
        ..ContractGraphSnapshot::default()
    };
    assert_contract_violation(
        &validate_contract_graph(&snapshot),
        ContractViolationKind::CleanupEffectCreatesLiveOwnership,
        "authorizes",
    );

    let subject = cc::ObjectRef::new(cc::ObjectKind::Trap, 10, 1).expect("valid trap ref");
    let evidence = cc::EventEvidence::semantic(1, "trap-attribution", subject, 1);
    let view = cc::StableViewRecord::semantic(
        cc::Phase2SemanticFamily::TrapAttribution,
        subject,
        "attributed",
    );
    assert_eq!(evidence.claim_limit, cc::EvidenceBoundaryLevel::SemanticModel);
    assert_eq!(view.evidence_level, cc::EvidenceBoundaryLevel::SemanticModel);
}

#[test]
fn phase2_guest_memory_facts_separate_semantic_truth_from_substrate_truth() {
    assert_eq!(
        cc::object_kind_evidence_level(cc::ObjectKind::GuestMemoryOperation),
        cc::EvidenceBoundaryLevel::SemanticModel
    );
    assert_eq!(
        cc::object_kind_evidence_level(cc::ObjectKind::PageAllocSubstrateEvent),
        cc::EvidenceBoundaryLevel::RealTargetSubstrate
    );

    let subject = cc::ObjectRef::new(cc::ObjectKind::GuestMemoryOperation, 33, 1)
        .expect("valid guest memory op");
    let semantic_fact =
        cc::ContractFactEffect::semantic(subject, "guest-address", "gva=0x1000 len=4096");
    assert_eq!(semantic_fact.evidence_level, cc::EvidenceBoundaryLevel::SemanticModel);
}
