use super::*;
use alloc::string::ToString;
use alloc::vec::Vec;

fn handle_for(record: &CapabilityRecord, rights: &[&str]) -> CapabilityHandle {
    record
        .store_local_handle(rights.iter().map(|right| (*right).to_string()).collect())
        .expect("capability record has store-local handle")
}

#[test]
fn capability_attenuation_cannot_expand_rights() {
    let mut ledger = CapabilityLedger::new();
    let parent = ledger
        .grant("driver", "mmio-bar0", &["read"], "store")
        .expect("test grant");

    assert!(
        ledger
            .attenuate(parent, "helper", &["read"], "activation")
            .is_some()
    );
    let helper = ledger
        .check("helper", "mmio-bar0", "read")
        .expect("attenuated capability");
    assert_eq!(helper.source, "attenuated");
    assert!(
        ledger
            .attenuate(parent, "helper", &["write"], "activation")
            .is_none()
    );
}

#[test]
fn capability_authority_uses_object_ref_not_debug_label() {
    let mut ledger = CapabilityLedger::new();
    let cap = ledger
        .grant_manifest_binding(
            "driver",
            "mmio.virtio-net",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(1),
            Some(1),
            None,
            "manifest",
        )
        .expect("test grant");
    let record = ledger
        .records()
        .iter()
        .find(|record| record.id == cap)
        .expect("capability record");
    let object_ref = record.object_ref.expect("authority object ref");
    let handle = handle_for(record, &["map"]);
    assert!(
        ledger
            .check_authority("driver", object_ref, "map", Some(&handle))
            .is_ok()
    );

    let mut debug_only = CapabilityLedger::new();
    debug_only.grant_debug_label_only_for_test("driver", "mmio.virtio-net", &["map"], "store");
    assert_eq!(
        debug_only.check("driver", "mmio.virtio-net", "map"),
        Err(CapabilityDenyReason::Missing)
    );

    let mut wrong_object = CapabilityLedger::new();
    let different_ref = AuthorityObjectRef::internal(
        CapabilityClass::MmioRegion,
        ContractObjectRef::new(ContractObjectKind::Resource, 999, 1),
    );
    let wrong_cap = wrong_object
        .grant_with_authority_ref(
            "driver",
            "mmio.virtio-net",
            different_ref,
            &["map"],
            "store",
            Some(1),
            Some(1),
            None,
            "manifest",
            true,
        )
        .expect("test grant");
    let wrong_record = wrong_object
        .records()
        .iter()
        .find(|record| record.id == wrong_cap)
        .expect("wrong capability record");
    let wrong_handle = handle_for(wrong_record, &["map"]);
    assert_eq!(
        wrong_object.check_authority("driver", object_ref, "map", Some(&wrong_handle)),
        Err(CapabilityDenyReason::ObjectMismatch)
    );
    assert_eq!(
        wrong_object.check_authority("driver", object_ref, "map", None),
        Err(CapabilityDenyReason::Missing)
    );
}

#[test]
fn manifest_binding_does_not_overwrite_explicit_authority_ref_by_label() {
    let mut ledger = CapabilityLedger::new();
    let explicit_ref = AuthorityObjectRef::internal(
        CapabilityClass::MmioRegion,
        ContractObjectRef::new(ContractObjectKind::Resource, 999, 1),
    );
    let explicit_cap = ledger
        .grant_with_authority_ref(
            "driver",
            "mmio.virtio-net",
            explicit_ref,
            &["map"],
            "store",
            Some(1),
            Some(1),
            None,
            "explicit",
            true,
        )
        .expect("test grant");
    let manifest_cap = ledger
        .grant_manifest_binding(
            "driver",
            "mmio.virtio-net",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(1),
            Some(1),
            None,
            "manifest",
        )
        .expect("test grant");

    assert_ne!(explicit_cap, manifest_cap);
    let explicit_record = ledger
        .records()
        .iter()
        .find(|record| record.id == explicit_cap)
        .expect("explicit capability");
    assert_eq!(explicit_record.object_ref, Some(explicit_ref));
    assert_eq!(explicit_record.source, "explicit");
}

#[test]
fn authority_binding_release_revokes_exact_granted_capability_not_same_label() {
    let mut graph = SemanticGraph::new();
    let manifest_ref = AuthorityObjectRef::internal(
        CapabilityClass::MmioRegion,
        ContractObjectRef::new(ContractObjectKind::Resource, 999, 1),
    );
    let manifest_cap = graph.grant_capability_with_authority_ref(
        "driver_virtio_net",
        "mmio.virtio-net0",
        manifest_ref,
        &["read"],
        "store",
        "manifest-test",
        true,
    );
    let mmio = graph.register_resource(ResourceKind::MmioRegion, None, "mmio:virtio-net0");
    let authority = graph
        .bind_authority_resource(
            mmio,
            "driver_virtio_net",
            "mmio.virtio-net0",
            &["read"],
            "store",
        )
        .expect("authority binding");
    let binding_cap = graph.authority_bindings()[0].capability;
    assert_ne!(manifest_cap, binding_cap);

    assert!(graph.release_authority_binding(authority, "test release"));

    let manifest_record = graph
        .capabilities()
        .record(manifest_cap)
        .expect("manifest cap");
    let binding_record = graph
        .capabilities()
        .record(binding_cap)
        .expect("binding cap");
    assert!(!manifest_record.revoked);
    assert!(binding_record.revoked);
}

#[test]
fn capability_grant_rejects_owner_store_without_generation() {
    let mut ledger = CapabilityLedger::new();
    assert_eq!(
        ledger.grant_manifest_binding(
            "driver",
            "mmio.virtio-net",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(1),
            None,
            None,
            "bad-test",
        ),
        Err(CapabilityGrantError::OwnerStoreGenerationRequired { owner_store: 1 })
    );
}

#[test]
fn revoke_owner_store_matches_exact_generation_only() {
    let mut ledger = CapabilityLedger::new();
    let cap_gen_1 = ledger
        .grant_manifest_binding(
            "driver",
            "mmio.gen1",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(1),
            Some(1),
            None,
            "test",
        )
        .expect("test grant");
    let cap_gen_2 = ledger
        .grant_manifest_binding(
            "driver",
            "mmio.gen2",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(1),
            Some(2),
            None,
            "test",
        )
        .expect("test grant");

    assert_eq!(ledger.revoke_owner_store(1, 1), {
        let mut revoked = Vec::new();
        revoked.push(cap_gen_1);
        revoked
    });
    assert!(ledger.record(cap_gen_1).expect("gen1").revoked);
    assert!(!ledger.record(cap_gen_2).expect("gen2").revoked);
}

#[test]
fn capability_authority_rejects_stale_revoked_wrong_subject_and_undeclared_external() {
    let mut ledger = CapabilityLedger::new();
    let cap = ledger
        .grant_manifest_binding(
            "driver",
            "packet-device.net0",
            &["rx", "tx"],
            "store",
            CapabilityClass::PacketDevice,
            Some(1),
            Some(1),
            None,
            "manifest",
        )
        .expect("test grant");
    let record = ledger
        .records()
        .iter()
        .find(|record| record.id == cap)
        .expect("capability record")
        .clone();
    let object_ref = record.object_ref.expect("authority object ref");
    let mut stale_handle = handle_for(&record, &["rx"]);
    stale_handle.generation += 1;
    assert_eq!(
        ledger.check_authority("driver", object_ref, "rx", Some(&stale_handle)),
        Err(CapabilityDenyReason::GenerationMismatch)
    );
    let wrong_subject_handle = handle_for(&record, &["rx"]);
    assert_eq!(
        ledger.check_authority(
            "other-driver",
            object_ref,
            "rx",
            Some(&wrong_subject_handle)
        ),
        Err(CapabilityDenyReason::SubjectMismatch)
    );
    assert!(ledger.revoke(cap));
    assert_eq!(
        ledger.check_authority("driver", object_ref, "rx", None),
        Err(CapabilityDenyReason::Revoked)
    );

    let mut external = CapabilityLedger::new();
    let external_ref = AuthorityObjectRef::external(
        CapabilityClass::Device,
        ContractObjectRef::new(ContractObjectKind::ExternalObject, 7, 0),
    );
    external
        .grant_with_authority_ref(
            "driver",
            "device.pci0",
            external_ref,
            &["probe"],
            "store",
            Some(1),
            Some(1),
            None,
            "test",
            false,
        )
        .expect("test grant");
    assert_eq!(
        external.check_authority("driver", external_ref, "probe", None),
        Err(CapabilityDenyReason::ManifestDeclarationMissing)
    );
}

#[test]
fn runtime_modes_publish_contract_policies() {
    let graph = SemanticGraph::with_runtime_mode(RuntimeMode::Replay);

    assert_eq!(graph.runtime_mode(), RuntimeMode::Replay);
    assert_eq!(graph.runtime_mode().event_log_policy(), "deterministic");
    assert!(graph.runtime_mode().deterministic_boundary());
    assert!(!graph.runtime_mode().fast_path_enabled());
}

#[test]
fn boundary_status_is_queryable_and_versioned() {
    let mut graph = SemanticGraph::new();
    let boundary = graph.publish_boundary(
        "target-cwasm",
        BoundaryKind::RuntimeExecutor,
        BoundaryStatus::NotLinked,
        "runtime-only-executor-v1",
        Some("code-publish"),
    );

    assert_eq!(graph.boundary_count(), 1);
    assert_eq!(graph.boundaries()[0].id, boundary);
    assert_eq!(graph.boundaries()[0].status, BoundaryStatus::NotLinked);

    let same_boundary = graph.publish_boundary(
        "target-cwasm",
        BoundaryKind::RuntimeExecutor,
        BoundaryStatus::RuntimeContract,
        "runtime-only-executor-v1",
        Some("hostcall-trampoline"),
    );

    assert_eq!(same_boundary, boundary);
    assert_eq!(graph.boundary_count(), 1);
    assert_eq!(graph.boundaries()[0].generation, 2);
    assert_eq!(
        graph.boundaries()[0].summary(),
        "boundary target-cwasm kind=runtime-executor status=runtime-contract backend=runtime-only-executor-v1 blocked=hostcall-trampoline generation=2"
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BoundaryPublished boundary=1 name=target-cwasm kind=runtime-executor status=runtime-contract backend=runtime-only-executor-v1 blocked=hostcall-trampoline generation=2"
    );
}

#[test]
fn artifact_verification_is_queryable_and_versioned() {
    let mut graph = SemanticGraph::new();
    let artifact = graph.record_artifact_verification(
        "vfs_service",
        "vfs",
        "binding-a",
        "cwasm-a",
        "abi-a",
        "prototype-self-signed-sha256",
        "target_executor",
        ArtifactVerificationState::ManifestVerified,
        Some("target-cwasm-loader-not-linked"),
    );
    let same_artifact = graph.record_artifact_verification(
        "vfs_service",
        "vfs",
        "binding-a",
        "cwasm-a",
        "abi-a",
        "prototype-self-signed-sha256",
        "target_executor",
        ArtifactVerificationState::HostValidated,
        Some("target-runtime-only-loader"),
    );

    assert_eq!(same_artifact, artifact);
    assert_eq!(graph.artifact_verification_count(), 1);
    assert_eq!(graph.artifact_verifications()[0].generation, 2);
    assert_eq!(
        graph.artifact_verifications()[0].summary(),
        "artifact vfs_service name=vfs state=host-validated binding=binding-a cwasm=cwasm-a abi=abi-a signature=prototype-self-signed-sha256 signer=target_executor blocked=target-runtime-only-loader generation=2"
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "ArtifactVerificationRecorded artifact=1 package=vfs_service name=vfs state=host-validated binding=binding-a blocked=target-runtime-only-loader generation=2"
    );
}

#[test]
fn store_activation_roots_and_handles_are_generation_checked() {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("vfs_service", "vfs", "service", "restartable");
    graph.record_store_activation(
        store,
        "vfs_service",
        "binding-a",
        "cwasm-a",
        CodePublishState::NotPublished,
        MemoryLayoutState::Verified,
        HostcallLinkState::NotLinked,
        TrapSurfaceState::ContractDeclared,
        EntrypointState::NotRunnable,
        Some("code-publish-not-linked"),
    );
    let handle = graph
        .store_activation_handle(store)
        .expect("activation handle");
    assert_eq!(graph.validate_store_activation_handle(handle), Ok(()));

    graph.record_store_activation(
        store,
        "vfs_service",
        "binding-a",
        "cwasm-a",
        CodePublishState::Published,
        MemoryLayoutState::Verified,
        HostcallLinkState::NotLinked,
        TrapSurfaceState::ContractDeclared,
        EntrypointState::NotRunnable,
        Some("hostcall-table-not-linked"),
    );

    assert_eq!(graph.store_activation_count(), 1);
    assert_eq!(
        graph.validate_store_activation_handle(handle),
        Err(GenerationCheckError::GenerationMismatch {
            expected: 1,
            actual: Some(2)
        })
    );
    assert_eq!(
        graph.store_activations()[0].summary(),
        "store-activation store=1 package=vfs_service binding=binding-a cwasm=cwasm-a code=published memory=verified hostcalls=not-linked traps=contract-declared entry=not-runnable blocked=hostcall-table-not-linked generation=2"
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "StoreActivationHandleRejected store=1 expected=1 actual=2 reason=generation-mismatch"
    );
}

#[test]
fn capability_ledger_reports_owner_recovery_state() {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("driver", "driver", "driver", "restartable");
    graph.grant_manifest_capability("driver", "mmio.bar0", &["read", "write"], "store");
    graph.grant_capability("driver", "irq11", &["ack"], "store");
    let mmio = graph
        .capabilities()
        .check("driver", "mmio.bar0", "read")
        .expect("manifest capability");
    assert_eq!(mmio.class, CapabilityClass::MmioRegion);
    assert_eq!(mmio.source, "artifact-manifest");
    assert_eq!(mmio.owner_store, Some(store));

    let report = graph.revoke_capabilities_for_subject("driver");
    let summary = graph.capability_owner_summary("driver");

    assert_eq!(report.count(), 2);
    assert_eq!(summary.active, 0);
    assert_eq!(summary.revoked, 2);
    assert_eq!(
        graph.check_capability("driver", "mmio.bar0", "read"),
        Err(CapabilityDenyReason::Revoked)
    );
}

#[test]
fn capability_check_records_denial_and_generation_mismatch() {
    let mut graph = SemanticGraph::new();
    let generation = {
        graph.grant_capability("linux_syscall", "timer.sleep", &["arm"], "wait-token");
        graph
            .capability_generation("linux_syscall", "timer.sleep")
            .expect("capability generation")
    };

    assert!(
        graph
            .check_capability("linux_syscall", "timer.sleep", "arm")
            .is_ok()
    );
    graph.revoke_current_capability("linux_syscall", "timer.sleep");
    assert_eq!(
        graph.check_capability("linux_syscall", "timer.sleep", "arm"),
        Err(CapabilityDenyReason::Revoked)
    );
    graph.grant_capability("linux_syscall", "timer.sleep", &["arm"], "wait-token");
    assert_eq!(
        graph.check_capability_generation("linux_syscall", "timer.sleep", "arm", generation),
        Err(CapabilityDenyReason::GenerationMismatch)
    );
}

#[test]
fn wait_flow_is_recorded_in_event_log() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
    graph.set_task_state(7, TaskState::Running);

    graph.record_wait_created(11, 7, SemanticWaitKind::Futex, 1);
    graph.record_wait_resolved(11, "ready");

    assert_eq!(graph.wait_count(), 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "WaitResolved wait=11 reason=ready"
    );
}

#[test]
fn wait_token_event_bridge_indexes_resolves_cancels_and_restarts() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
    let blocker = ContractObjectRef::new(ContractObjectKind::Capability, 5, 1);
    graph.record_wait_created_with_details(
        21,
        Some(7),
        Some(3),
        Some(1),
        SemanticWaitKind::Timer,
        1,
        {
            let mut blockers = Vec::new();
            blockers.push(blocker);
            blockers
        },
        Some(100),
        RestartPolicy::RestartWithAdjustedTimeout,
        Some("timer-context".to_string()),
    );
    let index = graph.wait_index();
    assert_eq!(index.by_task, {
        let mut expected = Vec::new();
        expected.push((7, 21));
        expected
    });
    assert_eq!(index.by_store, {
        let mut expected = Vec::new();
        expected.push((3, 1, 21));
        expected
    });
    assert!(graph.fake_timer_event_resolve_wait(21, 100));
    assert_eq!(graph.wait_records()[0].state, WaitState::Resolved);
    graph.record_wait_consumed(21);
    assert_eq!(graph.wait_records()[0].state, WaitState::Consumed);

    graph.record_wait_created_with_details(
        22,
        Some(7),
        Some(3),
        Some(1),
        SemanticWaitKind::DeviceIrq,
        1,
        {
            let mut blockers = Vec::new();
            blockers.push(blocker);
            blockers
        },
        None,
        RestartPolicy::RestartIfAllowed,
        Some("irq-context".to_string()),
    );
    assert_eq!(graph.fake_capability_revoke_cancel_wait(5), 1);
    let cancelled = graph
        .wait_records()
        .iter()
        .find(|wait| wait.id == 22)
        .expect("cancelled wait");
    assert_eq!(cancelled.state, WaitState::Cancelled);
    assert_eq!(
        cancelled.cancel_reason,
        Some(WaitCancelReason::CapabilityRevoked)
    );

    graph.record_wait_created(23, 7, SemanticWaitKind::Futex, 1);
    let old_handle = graph.wait_handle(23).expect("wait handle");
    graph.record_wait_interrupted(23, WaitCancelReason::Signal);
    graph.record_wait_restarted(23, "restart-if-allowed");
    assert_eq!(
        graph.validate_wait_handle(old_handle),
        Err(GenerationCheckError::GenerationMismatch {
            expected: 1,
            actual: Some(2),
        })
    );
}

#[test]
fn wait_contract_graph_rejects_hidden_or_stale_live_waits() {
    let running_store = StoreRecord {
        id: 6,
        package: "svc".to_string(),
        artifact: "svc.cwasm".to_string(),
        role: "service".to_string(),
        fault_policy: "restartable".to_string(),
        fault_domain: 1,
        resource: Some(1),
        state: StoreState::Running,
        generation: 1,
        restart_count: 0,
    };
    let mut dead_store = running_store.clone();
    dead_store.id = 5;
    dead_store.state = StoreState::Dead;
    let blocker = ContractObjectRef::new(ContractObjectKind::Resource, 9, 1);
    let missing_owner = WaitRecord {
        id: 31,
        owner_task: None,
        owner_store: None,
        owner_store_generation: None,
        kind: SemanticWaitKind::Futex,
        generation: 1,
        state: WaitState::Pending,
        blockers: Vec::new(),
        deadline: None,
        cancel_reason: None,
        restart_policy: RestartPolicy::Never,
        saved_context: None,
    };
    let dead_store_wait = WaitRecord {
        id: 32,
        owner_task: None,
        owner_store: Some(dead_store.id),
        owner_store_generation: Some(dead_store.generation),
        kind: SemanticWaitKind::DeviceIrq,
        generation: 1,
        state: WaitState::Pending,
        blockers: {
            let mut blockers = Vec::new();
            blockers.push(blocker);
            blockers
        },
        deadline: None,
        cancel_reason: None,
        restart_policy: RestartPolicy::InternalOnly,
        saved_context: None,
    };
    let resolved_wait = WaitRecord {
        id: 33,
        owner_task: None,
        owner_store: Some(running_store.id),
        owner_store_generation: Some(running_store.generation),
        kind: SemanticWaitKind::Timer,
        generation: 1,
        state: WaitState::Resolved,
        blockers: {
            let mut blockers = Vec::new();
            blockers.push(blocker);
            blockers
        },
        deadline: Some(200),
        cancel_reason: None,
        restart_policy: RestartPolicy::Never,
        saved_context: None,
    };
    let snapshot = ContractGraphSnapshot {
        stores: {
            let mut stores = Vec::new();
            stores.push(dead_store.clone());
            stores.push(running_store.clone());
            stores
        },
        waits: {
            let mut waits = Vec::new();
            waits.push(missing_owner);
            waits.push(dead_store_wait);
            waits.push(resolved_wait.clone());
            waits
        },
        explicit_edges: {
            let mut edges = Vec::new();
            edges.push(ContractEdgeRecord::new(
                running_store.object_ref(),
                resolved_wait.object_ref(),
                ContractEdgeMode::Live,
                "store->wait-live",
                1,
            ));
            edges
        },
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::DanglingEdge && violation.edge == "wait->owner"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::DanglingEdge && violation.edge == "wait->blocker"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::LiveEdgeReferencesInactiveObject
            && violation.edge == "wait->owner-store"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::LiveEdgeReferencesInactiveObject
            && violation.edge == "store->wait-live"
    }));
}

#[test]
fn contract_graph_rejects_active_capability_and_wait_owned_by_old_store_generation() {
    let mut store = StoreRecord {
        id: 9,
        package: "driver".to_string(),
        artifact: "driver.cwasm".to_string(),
        role: "driver".to_string(),
        fault_policy: "restartable".to_string(),
        fault_domain: 1,
        resource: Some(1),
        state: StoreState::Running,
        generation: 2,
        restart_count: 1,
    };
    let old_store = ContractObjectRef::new(ContractObjectKind::Store, store.id, 1);
    let object = ContractObjectRef::new(ContractObjectKind::Resource, 77, 1);
    let capability = CapabilityRecord {
        id: 4,
        subject: "driver".to_string(),
        object: "packet-device.net0".to_string(),
        object_ref: Some(AuthorityObjectRef::internal(
            CapabilityClass::PacketDevice,
            object,
        )),
        operations: OperationSet::from_static(&["rx"]),
        lifetime: "store".to_string(),
        class: CapabilityClass::PacketDevice,
        owner_store: Some(store.id),
        owner_store_generation: Some(1),
        owner_task: None,
        source: "test".to_string(),
        generation: 1,
        handle_slot: 1,
        handle_generation: 1,
        handle_tag: 1,
        parent: None,
        manifest_decl: true,
        debug_object_label: "packet-device.net0".to_string(),
        revoked: false,
    };
    let wait = WaitRecord {
        id: 8,
        owner_task: None,
        owner_store: Some(store.id),
        owner_store_generation: Some(1),
        kind: SemanticWaitKind::DeviceIrq,
        generation: 1,
        state: WaitState::Pending,
        blockers: {
            let mut blockers = Vec::new();
            blockers.push(capability.object_ref());
            blockers
        },
        deadline: None,
        cancel_reason: None,
        restart_policy: RestartPolicy::RestartIfAllowed,
        saved_context: None,
    };
    store.state = StoreState::Running;
    let snapshot = ContractGraphSnapshot {
        stores: {
            let mut stores = Vec::new();
            stores.push(store);
            stores
        },
        capabilities: {
            let mut capabilities = Vec::new();
            capabilities.push(capability);
            capabilities
        },
        waits: {
            let mut waits = Vec::new();
            waits.push(wait);
            waits
        },
        tombstones: {
            let mut tombstones = Vec::new();
            tombstones.push(TombstoneRecord::new(
                ContractObjectKind::Store,
                old_store.id,
                old_store.generation,
                1,
                "store-rebound",
            ));
            tombstones
        },
        external_objects: {
            let mut declarations = Vec::new();
            declarations.push(ExternalObjectDeclaration::new(
                object,
                "test",
                CapabilityClass::PacketDevice.as_str(),
                "packet-device.net0",
            ));
            declarations
        },
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::TombstoneReferencedByLiveEdge
            && violation.edge == "capability->owner-store"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::TombstoneReferencedByLiveEdge
            && violation.edge == "wait->owner-store"
    }));
}

#[test]
fn command_surface_grants_capability_and_precondition_failures_are_atomic() {
    let mut graph = SemanticGraph::new();
    let before = graph.event_count();
    let object_ref =
        AuthorityObjectRef::from_label(CapabilityClass::PacketDevice, "packet-device.net0");
    let outcome = graph
        .apply(SemanticCommand::GrantCapability {
            subject: "driver".to_string(),
            debug_object_label: "packet-device.net0".to_string(),
            object_ref,
            operations: {
                let mut operations = Vec::new();
                operations.push("rx".to_string());
                operations
            },
            lifetime: "store".to_string(),
            owner_store: None,
            owner_store_generation: None,
            owner_task: None,
            source: "command-test".to_string(),
            manifest_decl: true,
        })
        .expect("grant command");
    assert!(outcome.changed);
    assert!(outcome.event_count_after > before);
    assert!(
        graph
            .check_capability("driver", "packet-device.net0", "rx")
            .is_ok()
    );

    let wait_count = graph.wait_count();
    let events = graph.event_count();
    assert_eq!(
        graph.apply(SemanticCommand::CreateWait {
            wait: 99,
            owner_task: None,
            owner_store: None,
            owner_store_generation: None,
            kind: SemanticWaitKind::Futex,
            generation: 1,
            blockers: Vec::new(),
            deadline: None,
            restart_policy: RestartPolicy::Never,
            saved_context: None,
        }),
        Err(CommandError::PreconditionFailed(
            "create-wait requires owner task or owner store".to_string()
        ))
    );
    assert_eq!(graph.wait_count(), wait_count);
    assert_eq!(graph.event_count(), events);
}

#[test]
fn command_envelope_records_events_and_rejects_without_partial_mutation() {
    let mut graph = SemanticGraph::new();
    let object_ref =
        AuthorityObjectRef::from_label(CapabilityClass::PacketDevice, "packet-device.net0");
    let grant = CommandEnvelope::new(
        1,
        "test-harness",
        SemanticCommand::GrantCapability {
            subject: "driver".to_string(),
            debug_object_label: "packet-device.net0".to_string(),
            object_ref,
            operations: {
                let mut operations = Vec::new();
                operations.push("rx".to_string());
                operations
            },
            lifetime: "store".to_string(),
            owner_store: None,
            owner_store_generation: None,
            owner_task: None,
            source: "command-envelope-test".to_string(),
            manifest_decl: true,
        },
    )
    .with_expected_epoch(0);
    let result = graph.apply_envelope(grant);

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(result.command, "grant-capability");
    assert_eq!(result.issuer, "test-harness");
    assert_eq!(result.events, {
        let mut events = Vec::new();
        events.push(1);
        events
    });
    assert_eq!(result.effects[0].kind, "grant-capability");
    assert!(result.violations.is_empty());
    assert_eq!(graph.command_results().len(), 1);
    assert_eq!(graph.command_results()[0], result);

    let wait_count = graph.wait_count();
    let event_count = graph.event_count();
    let bad_wait = CommandEnvelope::new(
        2,
        "test-harness",
        SemanticCommand::CreateWait {
            wait: 99,
            owner_task: None,
            owner_store: None,
            owner_store_generation: None,
            kind: SemanticWaitKind::Futex,
            generation: 1,
            blockers: Vec::new(),
            deadline: None,
            restart_policy: RestartPolicy::Never,
            saved_context: None,
        },
    );
    let rejected = graph.apply_envelope(bad_wait);

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(rejected.violations, {
        let mut violations = Vec::new();
        violations.push("create-wait requires owner task or owner store".to_string());
        violations
    });
    assert_eq!(graph.wait_count(), wait_count);
    assert_eq!(graph.event_count(), event_count);
    assert_eq!(graph.command_results().len(), 2);
    assert_eq!(graph.command_results()[1], rejected);
}

#[test]
fn command_envelope_epoch_mismatch_is_atomic() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
    let before = graph.event_count();
    let result = graph.apply_envelope(
        CommandEnvelope::new(
            3,
            "test-harness",
            SemanticCommand::RecordTrap {
                store: None,
                task: Some(1),
                trap: TrapClass::GuestSegfault,
                detail: "synthetic".to_string(),
            },
        )
        .with_expected_epoch(0),
    );

    assert_eq!(result.status, CommandStatus::Rejected);
    assert_eq!(result.violations, {
        let mut violations = Vec::new();
        violations.push("expected epoch mismatch".to_string());
        violations
    });
    assert_eq!(graph.event_count(), before);
    assert_eq!(graph.command_results().len(), 1);
    assert_eq!(graph.command_results()[0], result);
}

#[test]
fn command_surface_wait_and_cleanup_transactions_are_canonical_and_idempotent() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
    graph
        .apply(SemanticCommand::CreateWait {
            wait: 41,
            owner_task: Some(7),
            owner_store: None,
            owner_store_generation: None,
            kind: SemanticWaitKind::Timer,
            generation: 1,
            blockers: Vec::new(),
            deadline: Some(10),
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("ctx".to_string()),
        })
        .expect("create wait");
    graph
        .apply(SemanticCommand::ResolveWait {
            wait: 41,
            reason: "timer".to_string(),
        })
        .expect("resolve wait");
    assert_eq!(graph.wait_records()[0].state, WaitState::Resolved);
    assert_eq!(
        graph.apply(SemanticCommand::CancelWait {
            wait: 41,
            errno: 125,
            reason: WaitCancelReason::Signal,
        }),
        Err(CommandError::PreconditionFailed(
            "wait is not pending".to_string()
        ))
    );

    let store = graph.register_store(
        "driver_virtio_net",
        "driver_virtio_net.cwasm",
        "driver",
        "restartable",
    );
    graph
        .apply(SemanticCommand::BeginCleanup {
            cleanup: 77,
            store,
            generation: 1,
            reason: "driver-fault".to_string(),
        })
        .expect("begin cleanup");
    assert_eq!(graph.active_transaction_count(), 1);
    graph
        .apply(SemanticCommand::ApplyCleanupStep {
            cleanup: 77,
            step: CleanupStep::ReleaseDmwLeases,
            target: ContractObjectRef::new(ContractObjectKind::Store, store, 1),
            observed_generation: 1,
        })
        .expect("apply cleanup step");
    let first_commit = graph
        .apply(SemanticCommand::CommitCleanup { cleanup: 77 })
        .expect("commit cleanup");
    assert!(first_commit.changed);
    assert_eq!(graph.active_transaction_count(), 0);
    assert_eq!(
        graph.apply(SemanticCommand::CommitCleanup { cleanup: 77 }),
        Err(CommandError::PreconditionFailed(
            "cleanup transaction is not active".to_string()
        ))
    );
}

#[test]
fn stale_resource_handles_are_rejected() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Fd, None, "fd:/sandbox/hello.txt");
    let handle = graph.resource_handle(resource).expect("resource handle");

    assert_eq!(graph.validate_resource_handle(handle), Ok(()));
    graph.close_resource(resource);
    assert_eq!(
        graph.validate_resource_handle(handle),
        Err(GenerationCheckError::GenerationMismatch {
            expected: 1,
            actual: Some(2),
        })
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "ResourceHandleRejected resource=1 expected=1 actual=2 reason=generation-mismatch"
    );
}

#[test]
fn stale_wait_tokens_are_rejected() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
    graph.record_wait_created(11, 7, SemanticWaitKind::Timer, 3);
    let handle = graph.wait_handle(11).expect("wait handle");

    assert_eq!(graph.validate_wait_handle(handle), Ok(()));
    assert_eq!(
        graph.validate_wait_handle(WaitHandle::new(11, 2)),
        Err(GenerationCheckError::GenerationMismatch {
            expected: 2,
            actual: Some(3),
        })
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "WaitTokenRejected wait=11 expected=2 actual=3 reason=generation-mismatch"
    );
}

#[test]
fn store_lifecycle_rebinds_instance_resource() {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("procfs_service", "procfs", "service", "restartable");

    graph.set_store_state(store, StoreState::Instantiating);
    graph.set_store_state(store, StoreState::Running);
    let first_resource = graph.store_resource(store).expect("initial store resource");

    graph.record_store_trap(store, "injected procfs read fault");
    graph.set_store_state(store, StoreState::Draining);
    graph.set_store_state(store, StoreState::Restarting);
    let drop_report = graph
        .drop_store_instance(store)
        .expect("dropped store instance");
    assert_eq!(drop_report.previous_resource, Some(first_resource));
    assert_eq!(drop_report.closed_resources, 1);
    assert_eq!(
        graph.validate_resource_handle(ResourceHandle::new(first_resource, 1)),
        Err(GenerationCheckError::GenerationMismatch {
            expected: 1,
            actual: Some(2),
        })
    );

    let rebind_report = graph
        .rebind_store_instance(store)
        .expect("rebound store resource");
    let second_resource = rebind_report.resource;
    graph.set_store_state(store, StoreState::Running);

    assert_ne!(first_resource, second_resource);
    assert_eq!(graph.store_count(), 1);
    assert_eq!(graph.live_resource_count(), 1);
    assert_eq!(graph.stores()[0].restart_count, 1);
    assert_eq!(graph.stores()[0].state, StoreState::Running);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FaultDomainRestarted domain=1"
    );
}

#[test]
fn store_executor_transitions_are_recorded_in_event_log() {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("vfs_service", "vfs", "service", "restartable");

    graph.record_store_executor_transition(
        store,
        "artifact-verified",
        "draining",
        Some("store-draining"),
        "not-linked",
        "contract-declared",
    );

    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "StoreExecutorTransition store=1 artifact-verified->draining blocked=store-draining hostcalls=not-linked traps=contract-declared"
    );
    assert_eq!(graph.store_executor_transition_count(), 1);
    assert!(
        graph.store_executor_transition_tail(1)[0].contains(
            "source=executor StoreExecutorTransition store=1 artifact-verified->draining blocked=store-draining hostcalls=not-linked traps=contract-declared"
        )
    );
}

#[test]
fn transaction_rollback_and_store_owned_resource_cleanup_are_recorded() {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("devfs_service", "devfs", "service", "restartable");
    graph.set_store_state(store, StoreState::Running);
    let scratch = graph.register_resource_for_store(
        ResourceKind::Device,
        None,
        Some(store),
        "device:pulse-shadow",
    );
    let authority = graph
        .bind_authority_resource(
            scratch,
            "devfs_service",
            "device.pulse-shadow",
            &["read"],
            "store",
        )
        .expect("store-owned device authority");
    let transaction = graph.begin_transaction("devfs.read_device", Some(store), Some(9));

    graph.rollback_transaction(transaction, "devfs_service trapped");
    graph.record_store_trap_class(store, TrapClass::ServiceTrap, "devfs_service trapped");
    let cleanup = graph.cleanup_resources_owned_by_store(store);
    assert_eq!(cleanup.closed_resources, 2);
    assert_eq!(cleanup.revoked_authorities, 1);
    assert_eq!(
        graph
            .authority_bindings()
            .iter()
            .find(|binding| binding.id == authority)
            .expect("authority binding")
            .state,
        AuthorityState::Revoked
    );

    assert_eq!(
        graph.validate_resource_handle(ResourceHandle::new(scratch, 1)),
        Err(GenerationCheckError::GenerationMismatch {
            expected: 1,
            actual: Some(2),
        })
    );
    assert_eq!(graph.transactions()[0].state, TransactionState::RolledBack);
    assert!(graph.event_log_tail(32).iter().any(|event| matches!(
        event.kind,
        EventKind::FaultClassified {
            trap: TrapClass::ServiceTrap,
            class: FaultClass::Service,
            ..
        }
    )));
}

#[test]
fn network_events_are_recorded_as_semantic_state() {
    let mut graph = SemanticGraph::new();
    let device = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let interface = graph.register_resource(ResourceKind::NetInterface, None, "net-interface:net0");
    let socket = graph.register_resource(ResourceKind::NetSocket, Some(7), "socket:tcp:1");
    let irq = graph.register_resource(ResourceKind::IrqLine, None, "irq:net0");
    let dma = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:net0-rx");

    graph.record_net_interface_state_changed(interface, true);
    graph.record_device_irq_delivered(irq, device, "rx");
    graph.record_dma_submitted(dma, device, 64);
    graph.record_dma_completed(dma, device, 64);
    graph.record_packet_received(interface, Some(socket), 0x6e6574307278, 64);

    assert!(graph.event_log_tail(8).iter().any(|event| matches!(
        event.kind,
        EventKind::PacketReceived {
            interface: recorded_interface,
            socket: Some(recorded_socket),
            len: 64,
            ..
        } if recorded_interface == interface && recorded_socket == socket
    )));
}

#[test]
fn authority_bindings_drive_resource_and_capability_lifecycle() {
    let mut graph = SemanticGraph::new();
    let mmio = graph.register_resource(ResourceKind::MmioRegion, None, "mmio:virtio-net0");
    let authority = graph
        .bind_authority_resource(
            mmio,
            "driver_virtio_net",
            "mmio.virtio-net0",
            &["read", "write"],
            "store",
        )
        .expect("authority binding");

    assert_eq!(graph.authority_count(), 1);
    assert_eq!(graph.active_authority_count(), 1);
    let cap_object_ref = graph.capabilities().records()[0]
        .object_ref
        .expect("authority binding capability carries object ref");
    assert!(
        graph
            .capabilities()
            .check_authority("driver_virtio_net", cap_object_ref, "write", None)
            .is_ok()
    );
    let old_generation = graph
        .capability_generation("driver_virtio_net", "mmio.virtio-net0")
        .expect("authority generation");
    assert_eq!(graph.check_invariants(), Ok(()));

    assert!(graph.release_authority_binding(authority, "driver micro-reboot"));
    assert_eq!(graph.active_authority_count(), 0);
    assert_eq!(
        graph
            .capabilities()
            .check_authority("driver_virtio_net", cap_object_ref, "write", None),
        Err(CapabilityDenyReason::Revoked)
    );
    assert_eq!(
        graph.validate_resource_handle(ResourceHandle::new(mmio, 1)),
        Err(GenerationCheckError::GenerationMismatch {
            expected: 1,
            actual: Some(2),
        })
    );
    assert!(graph.event_log_tail(8).iter().any(|event| matches!(
        event.kind,
        EventKind::AuthorityReleased {
            authority: recorded,
            resource: recorded_resource,
            ..
        } if recorded == authority && recorded_resource == mmio
    )));

    let rebound_mmio = graph.register_resource(ResourceKind::MmioRegion, None, "mmio:virtio-net0");
    graph
        .bind_authority_resource(
            rebound_mmio,
            "driver_virtio_net",
            "mmio.virtio-net0",
            &["read", "write"],
            "store",
        )
        .expect("rebound authority");
    let rebound_generation = graph
        .capability_generation("driver_virtio_net", "mmio.virtio-net0")
        .expect("rebound authority generation");
    assert!(rebound_generation > old_generation);
    assert_eq!(
        graph.check_capability_generation(
            "driver_virtio_net",
            "mmio.virtio-net0",
            "write",
            old_generation,
        ),
        Err(CapabilityDenyReason::GenerationMismatch)
    );
    assert!(
        graph
            .check_capability("driver_virtio_net", "mmio.virtio-net0", "write")
            .is_ok()
    );
    assert_eq!(graph.check_invariants(), Ok(()));
}

#[test]
fn packet_device_authority_is_part_of_the_hardware_ledger() {
    let mut graph = SemanticGraph::new();
    let device = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let authority = graph
        .bind_authority_resource(
            device,
            "driver_virtio_net",
            "packet-device.net0",
            &["rx", "tx", "poll"],
            "store",
        )
        .expect("packet device authority binding");

    assert_eq!(
        graph.authority_bindings()[0].kind,
        AuthorityKind::PacketDevice
    );
    let cap_object_ref = graph.capabilities().records()[0]
        .object_ref
        .expect("packet authority capability carries object ref");
    assert!(
        graph
            .capabilities()
            .check_authority("driver_virtio_net", cap_object_ref, "rx", None)
            .is_ok()
    );
    assert!(graph.revoke_authority_binding(authority, "driver restart"));
    assert_eq!(
        graph
            .capabilities()
            .check_authority("driver_virtio_net", cap_object_ref, "rx", None),
        Err(CapabilityDenyReason::Revoked)
    );
}

#[test]
fn invariants_reject_bound_authority_without_capability() {
    let mut graph = SemanticGraph::new();
    let irq = graph.register_resource(ResourceKind::IrqLine, None, "irq:net0");
    let authority = graph
        .bind_authority_resource(irq, "driver_virtio_net", "irq.net0", &["ack"], "store")
        .expect("authority binding");

    let (capability, capability_generation) = graph
        .authority_bindings()
        .iter()
        .find(|binding| binding.id == authority)
        .map(|binding| (binding.capability, binding.capability_generation))
        .expect("authority binding");
    assert!(graph.revoke_capability_generation(capability, capability_generation));

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::AuthorityCapabilityMissing { authority })
    );
}

#[test]
fn migration_package_rejects_active_dmw_leases() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
    graph.record_snapshot_barrier_enter(1);
    graph.record_snapshot_barrier_exit(1);

    let package = graph.migration_package(
        "test",
        "x86_64",
        "aarch64",
        test_artifact_profile(),
        GuestStateSnapshot::riscv64_placeholder(),
        SubstrateBoundarySnapshot {
            timer_epoch: 0,
            pending_irq_causes: 0,
            pending_dma_completions: 0,
            active_dmw_lease_count: 1,
            active_mmio_authority_count: 0,
            active_dma_authority_count: 0,
            active_irq_authority_count: 0,
            active_packet_device_authority_count: 0,
            active_virtio_queue_authority_count: 0,
            pending_network_inputs: 0,
            random_epoch: 0,
            scheduler_decision_cursor: 0,
            cow_epoch: 0,
            background_copy_pages: 0,
            native_state_policy: "rebuild".to_string(),
        },
        1,
        false,
    );

    assert_eq!(
        package.validate_portability(),
        Err(MigrationValidationError::ActiveDmwLease)
    );
}

#[test]
fn migration_package_rejects_active_semantic_transactions() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
    graph.begin_transaction("net.recvmsg", None, Some(1));

    let package = graph.migration_package(
        "test",
        "x86_64",
        "aarch64",
        test_artifact_profile(),
        GuestStateSnapshot::riscv64_placeholder(),
        SubstrateBoundarySnapshot {
            timer_epoch: 0,
            pending_irq_causes: 0,
            pending_dma_completions: 0,
            active_dmw_lease_count: 0,
            active_mmio_authority_count: 0,
            active_dma_authority_count: 0,
            active_irq_authority_count: 0,
            active_packet_device_authority_count: 0,
            active_virtio_queue_authority_count: 0,
            pending_network_inputs: 0,
            random_epoch: 0,
            scheduler_decision_cursor: 0,
            cow_epoch: 0,
            background_copy_pages: 0,
            native_state_policy: "rebuild".to_string(),
        },
        1,
        true,
    );

    assert_eq!(
        package.validate_portability(),
        Err(MigrationValidationError::ActiveSemanticTransaction)
    );
}

#[test]
fn migration_package_rejects_active_substrate_authorities() {
    let cases: [(fn(&mut SubstrateBoundarySnapshot), MigrationValidationError); 5] = [
        (
            |boundary| boundary.active_mmio_authority_count = 1,
            MigrationValidationError::ActiveMmioAuthority,
        ),
        (
            |boundary| boundary.active_dma_authority_count = 1,
            MigrationValidationError::ActiveDmaAuthority,
        ),
        (
            |boundary| boundary.active_irq_authority_count = 1,
            MigrationValidationError::ActiveIrqAuthority,
        ),
        (
            |boundary| boundary.active_packet_device_authority_count = 1,
            MigrationValidationError::ActivePacketDeviceAuthority,
        ),
        (
            |boundary| boundary.active_virtio_queue_authority_count = 1,
            MigrationValidationError::ActiveVirtioQueueAuthority,
        ),
    ];

    for (set_active, expected) in cases {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
        graph.record_snapshot_barrier_enter(1);
        graph.record_snapshot_barrier_exit(1);
        let mut boundary = test_substrate_boundary();
        set_active(&mut boundary);
        let package = graph.migration_package(
            "test",
            "x86_64",
            "aarch64",
            test_artifact_profile(),
            GuestStateSnapshot::riscv64_placeholder(),
            boundary,
            1,
            true,
        );

        assert_eq!(package.validate_portability(), Err(expected));
    }
}

#[test]
fn substrate_unsupported_is_event_log_visible() {
    let mut graph = SemanticGraph::new();

    let event = graph.record_substrate_unsupported(
        "DmaAuthority",
        "dma_alloc",
        Some("driver.fake_net".to_string()),
        Some(9),
        Some(4),
    );

    let record = graph.event_log_tail(1).first().expect("event was recorded");
    assert_eq!(record.id, event);
    assert_eq!(
        record.kind.summary(),
        "SubstrateUnsupported authority=DmaAuthority op=dma_alloc requester=driver.fake_net artifact=9 store=4"
    );
}

#[test]
fn substrate_capability_denied_is_event_log_visible() {
    let mut graph = SemanticGraph::new();

    let event = graph.record_substrate_capability_denied(
        "DmaAuthority",
        "dma_alloc",
        Some("driver.fake_net".to_string()),
        Some(9),
        Some(4),
        Some(7),
        Some(2),
    );

    let record = graph.event_log_tail(1).first().expect("event was recorded");
    assert_eq!(record.id, event);
    assert_eq!(
        record.kind.summary(),
        "SubstrateCapabilityDenied authority=DmaAuthority op=dma_alloc requester=driver.fake_net artifact=9 store=4 capability=7 generation=2"
    );
}

#[test]
fn interface_unsupported_is_event_log_visible() {
    let mut graph = SemanticGraph::new();

    let event = graph.record_interface_unsupported(
        "custom-wit",
        "semantic:machine/mmio",
        "read32",
        Some("driver.fake_net".to_string()),
        Some(9),
        Some(4),
    );

    let record = graph.event_log_tail(1).first().expect("event was recorded");
    assert_eq!(record.id, event);
    assert_eq!(
        record.kind.summary(),
        "InterfaceUnsupported kind=custom-wit interface=semantic:machine/mmio op=read32 requester=driver.fake_net artifact=9 store=4"
    );
}

fn test_substrate_boundary() -> SubstrateBoundarySnapshot {
    SubstrateBoundarySnapshot {
        timer_epoch: 0,
        pending_irq_causes: 0,
        pending_dma_completions: 0,
        active_dmw_lease_count: 0,
        active_mmio_authority_count: 0,
        active_dma_authority_count: 0,
        active_irq_authority_count: 0,
        active_packet_device_authority_count: 0,
        active_virtio_queue_authority_count: 0,
        pending_network_inputs: 0,
        random_epoch: 0,
        scheduler_decision_cursor: 0,
        cow_epoch: 0,
        background_copy_pages: 0,
        native_state_policy: "rebuild".to_string(),
    }
}

fn test_artifact_profile() -> ArtifactProfile {
    ArtifactProfile {
        artifact_profile: "test".to_string(),
        target_arch: "target-native".to_string(),
        machine_abi_version: "machine".to_string(),
        supervisor_abi_version: "supervisor".to_string(),
        wasm_feature_profile: "wasm32".to_string(),
        memory64: false,
        multi_memory: false,
        dmw_layout: "dmw".to_string(),
        network_contract_version: "network".to_string(),
        compiler_engine: "wasmtime".to_string(),
        compiler_execution_mode: "precompiled-core-module".to_string(),
        artifact_format: "cwasm".to_string(),
        runtime_executor_abi: "vmos-runtime-only-executor-v0".to_string(),
    }
}
