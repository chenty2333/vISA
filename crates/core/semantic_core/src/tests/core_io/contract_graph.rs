use super::*;

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
