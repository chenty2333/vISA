use super::*;
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
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
        "artifact vfs_service name=vfs state=host-validated binding=binding-a artifact_hash=cwasm-a abi=abi-a signature=prototype-self-signed-sha256 signer=target_executor blocked=target-runtime-only-loader generation=2"
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
        "store-activation store=1 package=vfs_service binding=binding-a code_hash=cwasm-a code=published memory=verified hostcalls=not-linked traps=contract-declared entry=not-runnable blocked=hostcall-table-not-linked generation=2"
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
        expected.push((7, 2, 21));
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
        owner_task_generation: None,
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
        owner_task_generation: None,
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
        owner_task_generation: None,
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
        owner_task_generation: None,
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
fn io_runtime_i0_device_object_records_resource_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let generation = graph.resource_handle(resource).unwrap().generation;
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i0-test",
        SemanticCommand::RecordDeviceObject {
            device: 301,
            name: "fake-io0".to_string(),
            class: "fake-device".to_string(),
            resource,
            resource_generation: generation,
            backend: "fake-io-backend".to_string(),
            bus: "semantic-harness".to_string(),
            vendor: "vmos".to_string(),
            model: "fake-io-v1".to_string(),
            note: "device object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.device_objects().len(), 1);
    let device = &graph.device_objects()[0];
    assert_eq!(device.id, 301);
    assert_eq!(device.resource, resource);
    assert_eq!(device.resource_generation, generation);
    assert_eq!(device.class, "fake-device");
    assert_eq!(device.backend, "fake-io-backend");
    assert_eq!(device.state, DeviceObjectState::Registered);
    assert!(device.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DeviceObjectRecorded device=301 resource={resource}@{generation} class=fake-device backend=fake-io-backend generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i0_rejects_stale_or_non_device_resource() {
    let mut graph = SemanticGraph::new();
    let fd = graph.register_resource(ResourceKind::Fd, None, "fd:/not-a-device");
    let fd_generation = graph.resource_handle(fd).unwrap().generation;
    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i0-test",
        SemanticCommand::RecordDeviceObject {
            device: 301,
            name: "fake-io0".to_string(),
            class: "fake-device".to_string(),
            resource: fd,
            resource_generation: fd_generation,
            backend: "fake-io-backend".to_string(),
            bus: "semantic-harness".to_string(),
            vendor: "vmos".to_string(),
            model: "fake-io-v1".to_string(),
            note: "fd resource must reject".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["device object resource kind is not device-capable".to_string()]
    );

    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i0-test",
        SemanticCommand::RecordDeviceObject {
            device: 302,
            name: "net0".to_string(),
            class: "packet-device".to_string(),
            resource,
            resource_generation: 2,
            backend: "fake-net-backend".to_string(),
            bus: "semantic-harness".to_string(),
            vendor: "vmos".to_string(),
            model: "fake-net-v1".to_string(),
            note: "stale resource generation must reject".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["device object resource generation mismatch".to_string()]
    );

    let generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        302,
        "net0",
        "packet-device",
        resource,
        generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "device object harness",
    ));
    graph.corrupt_device_object_resource_generation_for_test(302, generation + 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DeviceObjectMissingResource {
            device: 302,
            resource
        })
    );
}

#[test]
fn io_runtime_i1_queue_object_records_device_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i1-test",
        SemanticCommand::RecordQueueObject {
            queue: 501,
            name: "fake-io0-rx".to_string(),
            role: QueueObjectRole::Rx,
            queue_index: 0,
            depth: 64,
            device: 401,
            device_generation: 1,
            note: "queue object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.queue_objects().len(), 1);
    let queue = &graph.queue_objects()[0];
    assert_eq!(queue.id, 501);
    assert_eq!(queue.device, 401);
    assert_eq!(queue.device_generation, 1);
    assert_eq!(queue.role, QueueObjectRole::Rx);
    assert_eq!(queue.queue_index, 0);
    assert_eq!(queue.depth, 64);
    assert_eq!(queue.state, QueueObjectState::Registered);
    assert!(queue.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "QueueObjectRecorded queue=501 device=401@1 role=rx index=0 depth=64 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i1_rejects_stale_or_duplicate_queue() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i1-test",
        SemanticCommand::RecordQueueObject {
            queue: 501,
            name: "fake-io0-rx".to_string(),
            role: QueueObjectRole::Rx,
            queue_index: 0,
            depth: 64,
            device: 401,
            device_generation: 2,
            note: "stale device generation must reject".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["queue object device generation is missing or inactive".to_string()]
    );

    let zero_depth = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i1-test",
        SemanticCommand::RecordQueueObject {
            queue: 501,
            name: "fake-io0-rx".to_string(),
            role: QueueObjectRole::Rx,
            queue_index: 0,
            depth: 0,
            device: 401,
            device_generation: 1,
            note: "zero depth must reject".to_string(),
        },
    ));
    assert_eq!(zero_depth.status, CommandStatus::Rejected);
    assert_eq!(
        zero_depth.violations,
        vec!["queue object depth is zero".to_string()]
    );

    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "queue object harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i1-test",
        SemanticCommand::RecordQueueObject {
            queue: 502,
            name: "fake-io0-tx".to_string(),
            role: QueueObjectRole::Tx,
            queue_index: 0,
            depth: 64,
            device: 401,
            device_generation: 1,
            note: "duplicate index must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["queue object index already exists for device generation".to_string()]
    );

    graph.corrupt_queue_object_device_generation_for_test(501, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::QueueObjectMissingDevice {
            queue: 501,
            device: 401
        })
    );
}

#[test]
fn io_runtime_i2_descriptor_object_records_queue_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "queue object harness",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i2-test",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 601,
            queue: 501,
            queue_generation: 1,
            slot: 0,
            access: DescriptorObjectAccess::ReadWrite,
            length: 2048,
            note: "descriptor object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.descriptor_objects().len(), 1);
    let descriptor = &graph.descriptor_objects()[0];
    assert_eq!(descriptor.id, 601);
    assert_eq!(descriptor.queue, 501);
    assert_eq!(descriptor.queue_generation, 1);
    assert_eq!(descriptor.slot, 0);
    assert_eq!(descriptor.access, DescriptorObjectAccess::ReadWrite);
    assert_eq!(descriptor.length, 2048);
    assert_eq!(descriptor.state, DescriptorObjectState::Registered);
    assert!(descriptor.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "DescriptorObjectRecorded descriptor=601 queue=501@1 slot=0 access=read-write length=2048 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i2_rejects_stale_out_of_bounds_or_duplicate_descriptor() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        2,
        401,
        1,
        "queue object harness",
    ));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i2-test",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 601,
            queue: 501,
            queue_generation: 2,
            slot: 0,
            access: DescriptorObjectAccess::ReadWrite,
            length: 2048,
            note: "stale queue generation must reject".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["descriptor object queue generation is missing or inactive".to_string()]
    );

    let zero_length = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i2-test",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 601,
            queue: 501,
            queue_generation: 1,
            slot: 0,
            access: DescriptorObjectAccess::ReadWrite,
            length: 0,
            note: "zero length must reject".to_string(),
        },
    ));
    assert_eq!(zero_length.status, CommandStatus::Rejected);
    assert_eq!(
        zero_length.violations,
        vec!["descriptor object length is zero".to_string()]
    );

    let out_of_bounds = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i2-test",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 601,
            queue: 501,
            queue_generation: 1,
            slot: 2,
            access: DescriptorObjectAccess::ReadWrite,
            length: 2048,
            note: "slot outside queue depth must reject".to_string(),
        },
    ));
    assert_eq!(out_of_bounds.status, CommandStatus::Rejected);
    assert_eq!(
        out_of_bounds.violations,
        vec!["descriptor object slot is outside queue depth".to_string()]
    );

    assert!(graph.record_descriptor_object_with_id(
        601,
        501,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "descriptor object harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i2-test",
        SemanticCommand::RecordDescriptorObject {
            descriptor: 602,
            queue: 501,
            queue_generation: 1,
            slot: 0,
            access: DescriptorObjectAccess::ReadOnly,
            length: 128,
            note: "duplicate slot must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["descriptor object slot already exists for queue generation".to_string()]
    );

    graph.corrupt_descriptor_object_queue_generation_for_test(601, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DescriptorObjectMissingQueue {
            descriptor: 601,
            queue: 501
        })
    );
}

#[test]
fn io_runtime_i3_dma_buffer_object_records_descriptor_and_resource_identity() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:fake-io0-rx0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "queue object harness",
    ));
    assert!(graph.record_descriptor_object_with_id(
        601,
        501,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "descriptor object harness",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 701,
            descriptor: 601,
            descriptor_generation: 1,
            resource: dma_resource,
            resource_generation: dma_resource_generation,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 2048,
            note: "dma buffer object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.dma_buffer_objects().len(), 1);
    let dma_buffer = &graph.dma_buffer_objects()[0];
    assert_eq!(dma_buffer.id, 701);
    assert_eq!(dma_buffer.descriptor, 601);
    assert_eq!(dma_buffer.descriptor_generation, 1);
    assert_eq!(dma_buffer.resource, dma_resource);
    assert_eq!(dma_buffer.resource_generation, dma_resource_generation);
    assert_eq!(dma_buffer.access, DmaBufferObjectAccess::ReadWrite);
    assert_eq!(dma_buffer.length, 2048);
    assert_eq!(dma_buffer.state, DmaBufferObjectState::Registered);
    assert!(dma_buffer.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DmaBufferObjectRecorded dma_buffer=701 descriptor=601@1 resource={dma_resource}@{dma_resource_generation} access=read-write length=2048 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i3_rejects_stale_wrong_resource_or_duplicate_dma_buffer() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:fake-io0-rx0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "queue object harness",
    ));
    assert!(graph.record_descriptor_object_with_id(
        601,
        501,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "descriptor object harness",
    ));

    let stale_descriptor = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 701,
            descriptor: 601,
            descriptor_generation: 2,
            resource: dma_resource,
            resource_generation: dma_resource_generation,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 2048,
            note: "stale descriptor generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_descriptor.status, CommandStatus::Rejected);
    assert_eq!(
        stale_descriptor.violations,
        vec!["dma buffer object descriptor generation is missing or inactive".to_string()]
    );

    let wrong_resource = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 701,
            descriptor: 601,
            descriptor_generation: 1,
            resource: device_resource,
            resource_generation: device_resource_generation,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 2048,
            note: "non-dma resource must reject".to_string(),
        },
    ));
    assert_eq!(wrong_resource.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_resource.violations,
        vec!["dma buffer object resource kind is not dma-buffer".to_string()]
    );

    let stale_resource = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 701,
            descriptor: 601,
            descriptor_generation: 1,
            resource: dma_resource,
            resource_generation: dma_resource_generation + 1,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 2048,
            note: "stale resource generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_resource.status, CommandStatus::Rejected);
    assert_eq!(
        stale_resource.violations,
        vec!["dma buffer object resource generation mismatch".to_string()]
    );

    let length_exceeds = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 701,
            descriptor: 601,
            descriptor_generation: 1,
            resource: dma_resource,
            resource_generation: dma_resource_generation,
            access: DmaBufferObjectAccess::ReadWrite,
            length: 4096,
            note: "length exceeds descriptor must reject".to_string(),
        },
    ));
    assert_eq!(length_exceeds.status, CommandStatus::Rejected);
    assert_eq!(
        length_exceeds.violations,
        vec!["dma buffer object length exceeds descriptor length".to_string()]
    );

    assert!(graph.record_dma_buffer_object_with_id(
        701,
        601,
        1,
        dma_resource,
        dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        2048,
        "dma buffer object harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "i3-test",
        SemanticCommand::RecordDmaBufferObject {
            dma_buffer: 702,
            descriptor: 601,
            descriptor_generation: 1,
            resource: dma_resource,
            resource_generation: dma_resource_generation,
            access: DmaBufferObjectAccess::ReadOnly,
            length: 128,
            note: "duplicate descriptor buffer must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["dma buffer object descriptor already has a buffer".to_string()]
    );

    graph.corrupt_dma_buffer_object_resource_generation_for_test(701, dma_resource_generation + 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DmaBufferObjectMissingResource {
            dma_buffer: 701,
            resource: dma_resource,
        })
    );
}

#[test]
fn io_runtime_i4_mmio_region_object_records_device_and_resource_identity() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let mmio_resource =
        graph.register_resource(ResourceKind::MmioRegion, None, "mmio:fake-io0-regs");
    let mmio_resource_generation = graph.resource_handle(mmio_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 801,
            device: 401,
            device_generation: 1,
            resource: mmio_resource,
            resource_generation: mmio_resource_generation,
            region_index: 0,
            offset: 0x1000,
            length: 0x100,
            access: MmioRegionObjectAccess::ReadWrite,
            note: "mmio region object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.mmio_region_objects().len(), 1);
    let mmio_region = &graph.mmio_region_objects()[0];
    assert_eq!(mmio_region.id, 801);
    assert_eq!(mmio_region.device, 401);
    assert_eq!(mmio_region.device_generation, 1);
    assert_eq!(mmio_region.resource, mmio_resource);
    assert_eq!(mmio_region.resource_generation, mmio_resource_generation);
    assert_eq!(mmio_region.region_index, 0);
    assert_eq!(mmio_region.offset, 0x1000);
    assert_eq!(mmio_region.length, 0x100);
    assert_eq!(mmio_region.access, MmioRegionObjectAccess::ReadWrite);
    assert_eq!(mmio_region.state, MmioRegionObjectState::Registered);
    assert!(mmio_region.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "MmioRegionObjectRecorded mmio_region=801 device=401@1 resource={mmio_resource}@{mmio_resource_generation} index=0 offset=4096 length=256 access=read-write generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i4_rejects_stale_wrong_resource_or_duplicate_mmio_region() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let mmio_resource =
        graph.register_resource(ResourceKind::MmioRegion, None, "mmio:fake-io0-regs");
    let mmio_resource_generation = graph.resource_handle(mmio_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));

    let stale_device = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 801,
            device: 401,
            device_generation: 2,
            resource: mmio_resource,
            resource_generation: mmio_resource_generation,
            region_index: 0,
            offset: 0x1000,
            length: 0x100,
            access: MmioRegionObjectAccess::ReadWrite,
            note: "stale device generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device.violations,
        vec!["mmio region object device generation is missing or inactive".to_string()]
    );

    let wrong_resource = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 801,
            device: 401,
            device_generation: 1,
            resource: device_resource,
            resource_generation: device_resource_generation,
            region_index: 0,
            offset: 0x1000,
            length: 0x100,
            access: MmioRegionObjectAccess::ReadWrite,
            note: "non-mmio resource must reject".to_string(),
        },
    ));
    assert_eq!(wrong_resource.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_resource.violations,
        vec!["mmio region object resource kind is not mmio-region".to_string()]
    );

    let stale_resource = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 801,
            device: 401,
            device_generation: 1,
            resource: mmio_resource,
            resource_generation: mmio_resource_generation + 1,
            region_index: 0,
            offset: 0x1000,
            length: 0x100,
            access: MmioRegionObjectAccess::ReadWrite,
            note: "stale resource generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_resource.status, CommandStatus::Rejected);
    assert_eq!(
        stale_resource.violations,
        vec!["mmio region object resource generation mismatch".to_string()]
    );

    let range_overflows = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 801,
            device: 401,
            device_generation: 1,
            resource: mmio_resource,
            resource_generation: mmio_resource_generation,
            region_index: 0,
            offset: u64::MAX,
            length: 1,
            access: MmioRegionObjectAccess::ReadWrite,
            note: "overflowing range must reject".to_string(),
        },
    ));
    assert_eq!(range_overflows.status, CommandStatus::Rejected);
    assert_eq!(
        range_overflows.violations,
        vec!["mmio region object range overflows".to_string()]
    );

    assert!(graph.record_mmio_region_object_with_id(
        801,
        401,
        1,
        mmio_resource,
        mmio_resource_generation,
        0,
        0x1000,
        0x100,
        MmioRegionObjectAccess::ReadWrite,
        "mmio region object harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "i4-test",
        SemanticCommand::RecordMmioRegionObject {
            mmio_region: 802,
            device: 401,
            device_generation: 1,
            resource: mmio_resource,
            resource_generation: mmio_resource_generation,
            region_index: 0,
            offset: 0x2000,
            length: 0x100,
            access: MmioRegionObjectAccess::ReadOnly,
            note: "duplicate region index must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["mmio region object index already exists for device generation".to_string()]
    );

    graph.corrupt_mmio_region_object_device_generation_for_test(801, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::MmioRegionObjectMissingDevice {
            mmio_region: 801,
            device: 401,
        })
    );
}

#[test]
fn io_runtime_i5_irq_line_object_records_device_and_resource_identity() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i5-test",
        SemanticCommand::RecordIrqLineObject {
            irq_line: 901,
            device: 401,
            device_generation: 1,
            resource: irq_resource,
            resource_generation: irq_resource_generation,
            irq_number: 5,
            trigger: IrqLineTrigger::Level,
            polarity: IrqLinePolarity::ActiveHigh,
            note: "irq line object harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.irq_line_objects().len(), 1);
    let irq_line = &graph.irq_line_objects()[0];
    assert_eq!(irq_line.id, 901);
    assert_eq!(irq_line.device, 401);
    assert_eq!(irq_line.device_generation, 1);
    assert_eq!(irq_line.resource, irq_resource);
    assert_eq!(irq_line.resource_generation, irq_resource_generation);
    assert_eq!(irq_line.irq_number, 5);
    assert_eq!(irq_line.trigger, IrqLineTrigger::Level);
    assert_eq!(irq_line.polarity, IrqLinePolarity::ActiveHigh);
    assert_eq!(irq_line.state, IrqLineObjectState::Registered);
    assert!(irq_line.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "IrqLineObjectRecorded irq_line=901 device=401@1 resource={irq_resource}@{irq_resource_generation} irq_number=5 trigger=level polarity=active-high generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i5_rejects_stale_wrong_resource_or_duplicate_irq_line() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));

    let stale_device = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i5-test",
        SemanticCommand::RecordIrqLineObject {
            irq_line: 901,
            device: 401,
            device_generation: 2,
            resource: irq_resource,
            resource_generation: irq_resource_generation,
            irq_number: 5,
            trigger: IrqLineTrigger::Level,
            polarity: IrqLinePolarity::ActiveHigh,
            note: "stale device generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device.violations,
        vec!["irq line object device generation is missing or inactive".to_string()]
    );

    let wrong_resource = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i5-test",
        SemanticCommand::RecordIrqLineObject {
            irq_line: 901,
            device: 401,
            device_generation: 1,
            resource: device_resource,
            resource_generation: device_resource_generation,
            irq_number: 5,
            trigger: IrqLineTrigger::Level,
            polarity: IrqLinePolarity::ActiveHigh,
            note: "non-irq resource must reject".to_string(),
        },
    ));
    assert_eq!(wrong_resource.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_resource.violations,
        vec!["irq line object resource kind is not irq-line".to_string()]
    );

    let stale_resource = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i5-test",
        SemanticCommand::RecordIrqLineObject {
            irq_line: 901,
            device: 401,
            device_generation: 1,
            resource: irq_resource,
            resource_generation: irq_resource_generation + 1,
            irq_number: 5,
            trigger: IrqLineTrigger::Level,
            polarity: IrqLinePolarity::ActiveHigh,
            note: "stale resource generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_resource.status, CommandStatus::Rejected);
    assert_eq!(
        stale_resource.violations,
        vec!["irq line object resource generation mismatch".to_string()]
    );

    assert!(graph.record_irq_line_object_with_id(
        901,
        401,
        1,
        irq_resource,
        irq_resource_generation,
        5,
        IrqLineTrigger::Level,
        IrqLinePolarity::ActiveHigh,
        "irq line object harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i5-test",
        SemanticCommand::RecordIrqLineObject {
            irq_line: 902,
            device: 401,
            device_generation: 1,
            resource: irq_resource,
            resource_generation: irq_resource_generation,
            irq_number: 5,
            trigger: IrqLineTrigger::Edge,
            polarity: IrqLinePolarity::ActiveLow,
            note: "duplicate irq number must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["irq line object number already exists for device generation".to_string()]
    );

    graph.corrupt_irq_line_object_device_generation_for_test(901, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IrqLineObjectMissingDevice {
            irq_line: 901,
            device: 401,
        })
    );
}

#[test]
fn io_runtime_i6_irq_event_records_line_device_and_driver_store_identity() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_irq_line_object_with_id(
        901,
        401,
        1,
        irq_resource,
        irq_resource_generation,
        5,
        IrqLineTrigger::Level,
        IrqLinePolarity::ActiveHigh,
        "irq line object harness",
    ));
    let driver_store = graph.register_store(
        "driver.fake-io0",
        "driver.fake-io0.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 1,
            device: 401,
            device_generation: 1,
            driver_store,
            driver_store_generation,
            sequence: 1,
            note: "irq event harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.irq_events().len(), 1);
    let irq_event = &graph.irq_events()[0];
    assert_eq!(irq_event.id, 1001);
    assert_eq!(irq_event.irq_line, 901);
    assert_eq!(irq_event.irq_line_generation, 1);
    assert_eq!(irq_event.device, 401);
    assert_eq!(irq_event.device_generation, 1);
    assert_eq!(irq_event.driver_store, driver_store);
    assert_eq!(irq_event.driver_store_generation, driver_store_generation);
    assert_eq!(irq_event.irq_number, 5);
    assert_eq!(irq_event.sequence, 1);
    assert_eq!(irq_event.state, IrqEventState::Recorded);
    assert!(irq_event.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "IrqEventRecorded irq_event=1001 irq_line=901@1 device=401@1 driver_store={driver_store}@{driver_store_generation} irq_number=5 sequence=1 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i6_rejects_stale_wrong_store_or_duplicate_irq_event() {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_irq_line_object_with_id(
        901,
        401,
        1,
        irq_resource,
        irq_resource_generation,
        5,
        IrqLineTrigger::Level,
        IrqLinePolarity::ActiveHigh,
        "irq line object harness",
    ));
    let driver_store = graph.register_store(
        "driver.fake-io0",
        "driver.fake-io0.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let service_store = graph.register_store(
        "service.fake-io0",
        "service.fake-io0.fake-aot",
        "service",
        "restartable",
    );
    graph.set_store_state(service_store, StoreState::Running);
    let service_store_generation = graph.store_handle(service_store).unwrap().generation;

    let stale_line = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 2,
            device: 401,
            device_generation: 1,
            driver_store,
            driver_store_generation,
            sequence: 1,
            note: "stale line generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_line.status, CommandStatus::Rejected);
    assert_eq!(
        stale_line.violations,
        vec!["irq event line generation is missing or inactive".to_string()]
    );

    let wrong_device = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 1,
            device: 402,
            device_generation: 1,
            driver_store,
            driver_store_generation,
            sequence: 1,
            note: "wrong device must reject".to_string(),
        },
    ));
    assert_eq!(wrong_device.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_device.violations,
        vec!["irq event device does not match irq line".to_string()]
    );

    let stale_store = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 1,
            device: 401,
            device_generation: 1,
            driver_store,
            driver_store_generation: driver_store_generation + 1,
            sequence: 1,
            note: "stale driver store generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_store.status, CommandStatus::Rejected);
    assert_eq!(
        stale_store.violations,
        vec!["irq event driver store generation mismatch".to_string()]
    );

    let non_driver_store = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 1,
            device: 401,
            device_generation: 1,
            driver_store: service_store,
            driver_store_generation: service_store_generation,
            sequence: 1,
            note: "non-driver store must reject".to_string(),
        },
    ));
    assert_eq!(non_driver_store.status, CommandStatus::Rejected);
    assert_eq!(
        non_driver_store.violations,
        vec!["irq event driver store role is not driver".to_string()]
    );

    let zero_sequence = graph.apply_envelope(CommandEnvelope::new(
        5,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1001,
            irq_line: 901,
            irq_line_generation: 1,
            device: 401,
            device_generation: 1,
            driver_store,
            driver_store_generation,
            sequence: 0,
            note: "zero sequence must reject".to_string(),
        },
    ));
    assert_eq!(zero_sequence.status, CommandStatus::Rejected);
    assert_eq!(
        zero_sequence.violations,
        vec!["irq event sequence is zero".to_string()]
    );

    assert!(graph.record_irq_event_with_id(
        1001,
        901,
        1,
        401,
        1,
        driver_store,
        driver_store_generation,
        1,
        "irq event harness",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        6,
        "i6-test",
        SemanticCommand::RecordIrqEvent {
            irq_event: 1002,
            irq_line: 901,
            irq_line_generation: 1,
            device: 401,
            device_generation: 1,
            driver_store,
            driver_store_generation,
            sequence: 1,
            note: "duplicate sequence must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["irq event sequence already exists for irq line generation".to_string()]
    );

    graph.corrupt_irq_event_driver_store_generation_for_test(1001, driver_store_generation + 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IrqEventMissingDriverStore {
            irq_event: 1001,
            store: driver_store,
        })
    );
}

fn setup_i7_device_capability_graph() -> (
    SemanticGraph,
    StoreId,
    Generation,
    ContractObjectRef,
    ContractObjectRef,
    ContractObjectRef,
    ContractObjectRef,
) {
    let mut graph = SemanticGraph::new();
    let device_resource = graph.register_resource(ResourceKind::Device, None, "device:fake-io0");
    let device_resource_generation = graph.resource_handle(device_resource).unwrap().generation;
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:fake-io0-rx0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    let mmio_resource = graph.register_resource(ResourceKind::MmioRegion, None, "mmio:fake-io0");
    let mmio_resource_generation = graph.resource_handle(mmio_resource).unwrap().generation;
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:fake-io0-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        401,
        "fake-io0",
        "fake-device",
        device_resource,
        device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "device object harness",
    ));
    assert!(graph.record_queue_object_with_id(
        501,
        "fake-io0-rx",
        QueueObjectRole::Rx,
        0,
        64,
        401,
        1,
        "queue object harness",
    ));
    assert!(graph.record_descriptor_object_with_id(
        601,
        501,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "descriptor object harness",
    ));
    assert!(graph.record_dma_buffer_object_with_id(
        701,
        601,
        1,
        dma_resource,
        dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        2048,
        "dma buffer object harness",
    ));
    assert!(graph.record_mmio_region_object_with_id(
        801,
        401,
        1,
        mmio_resource,
        mmio_resource_generation,
        0,
        0x1000,
        0x100,
        MmioRegionObjectAccess::ReadWrite,
        "mmio region object harness",
    ));
    assert!(graph.record_irq_line_object_with_id(
        901,
        401,
        1,
        irq_resource,
        irq_resource_generation,
        5,
        IrqLineTrigger::Level,
        IrqLinePolarity::ActiveHigh,
        "irq line object harness",
    ));
    let driver_store = graph.register_store(
        "driver.fake-io0",
        "driver.fake-io0.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    (
        graph,
        driver_store,
        driver_store_generation,
        ContractObjectRef::new(ContractObjectKind::DeviceObject, 401, 1),
        ContractObjectRef::new(ContractObjectKind::MmioRegionObject, 801, 1),
        ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 701, 1),
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
    )
}

#[test]
fn io_runtime_i7_device_capability_records_store_local_authority() {
    let (mut graph, driver_store, driver_store_generation, _device, mmio, dma, irq) =
        setup_i7_device_capability_graph();
    let mmio_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "i7-test",
        true,
    );
    let dma_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "dma.fake-io0.rx0",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma),
        &["sync-for-device"],
        "store",
        "i7-test",
        true,
    );
    let irq_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "irq.fake-io0.rx",
        AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq),
        &["ack"],
        "store",
        "i7-test",
        true,
    );
    let mmio_handle = graph
        .capabilities()
        .record(mmio_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    let dma_handle = graph
        .capabilities()
        .record(dma_cap)
        .and_then(|record| record.store_local_handle(vec!["sync-for-device".to_string()]))
        .unwrap();
    let irq_handle = graph
        .capabilities()
        .record(irq_cap)
        .and_then(|record| record.store_local_handle(vec!["ack".to_string()]))
        .unwrap();
    let cursor_before = graph.event_log().cursor();

    let mmio_result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1101,
            driver_store,
            driver_store_generation,
            target: mmio,
            class: CapabilityClass::MmioRegion,
            operation: "write32".to_string(),
            handle: mmio_handle.clone(),
            note: "mmio capability harness".to_string(),
        },
    ));
    let dma_result = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1102,
            driver_store,
            driver_store_generation,
            target: dma,
            class: CapabilityClass::DmaBuffer,
            operation: "sync-for-device".to_string(),
            handle: dma_handle,
            note: "dma capability harness".to_string(),
        },
    ));
    let irq_result = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1103,
            driver_store,
            driver_store_generation,
            target: irq,
            class: CapabilityClass::IrqLine,
            operation: "ack".to_string(),
            handle: irq_handle,
            note: "irq capability harness".to_string(),
        },
    ));

    assert_eq!(mmio_result.status, CommandStatus::Applied);
    assert_eq!(dma_result.status, CommandStatus::Applied);
    assert_eq!(irq_result.status, CommandStatus::Applied);
    assert_eq!(graph.device_capabilities().len(), 3);
    let record = &graph.device_capabilities()[0];
    assert_eq!(record.id, 1101);
    assert_eq!(record.driver_store, driver_store);
    assert_eq!(record.driver_store_generation, driver_store_generation);
    assert_eq!(record.target, mmio);
    assert_eq!(record.class, CapabilityClass::MmioRegion);
    assert_eq!(record.operation, "write32");
    assert_eq!(record.capability, mmio_cap);
    assert_eq!(record.handle_slot, mmio_handle.slot);
    assert_eq!(record.handle_generation, mmio_handle.generation);
    assert_eq!(record.handle_tag, mmio_handle.tag);
    assert_eq!(record.state, DeviceCapabilityState::Active);
    assert!(record.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DeviceCapabilityRecorded device_capability=1103 driver_store={driver_store}@{driver_store_generation} target={} class=irq-line operation=ack capability={irq_cap}@1 handle_slot=3 handle_generation=1 generation=1",
            irq.summary()
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i7_rejects_label_only_stale_revoked_or_duplicate_capability() {
    let (mut graph, driver_store, driver_store_generation, _device, mmio, _dma, _irq) =
        setup_i7_device_capability_graph();
    let label_cap = graph.grant_capability(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        &["write32"],
        "store",
    );
    let label_handle = graph
        .capabilities()
        .record(label_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    let label_only = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1101,
            driver_store,
            driver_store_generation,
            target: mmio,
            class: CapabilityClass::MmioRegion,
            operation: "write32".to_string(),
            handle: label_handle,
            note: "debug label object ref must not authorize".to_string(),
        },
    ));
    assert_eq!(label_only.status, CommandStatus::Rejected);
    assert_eq!(
        label_only.violations,
        vec!["device capability handle is not authorized".to_string()]
    );

    let exact_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "i7-test",
        true,
    );
    let exact_handle = graph
        .capabilities()
        .record(exact_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    let exact_generation = graph.capabilities().record(exact_cap).unwrap().generation;
    let stale_target = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1101,
            driver_store,
            driver_store_generation,
            target: ContractObjectRef::new(ContractObjectKind::MmioRegionObject, 801, 2),
            class: CapabilityClass::MmioRegion,
            operation: "write32".to_string(),
            handle: exact_handle.clone(),
            note: "stale target generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_target.status, CommandStatus::Rejected);
    assert_eq!(
        stale_target.violations,
        vec!["device capability target generation is missing or inactive".to_string()]
    );

    assert!(graph.revoke_capability_generation(exact_cap, exact_generation));
    let revoked = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1101,
            driver_store,
            driver_store_generation,
            target: mmio,
            class: CapabilityClass::MmioRegion,
            operation: "write32".to_string(),
            handle: exact_handle,
            note: "revoked capability must reject".to_string(),
        },
    ));
    assert_eq!(revoked.status, CommandStatus::Rejected);
    assert_eq!(
        revoked.violations,
        vec!["device capability handle is not authorized".to_string()]
    );

    let fresh_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "i7-test",
        true,
    );
    let fresh_handle = graph
        .capabilities()
        .record(fresh_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1101,
        driver_store,
        driver_store_generation,
        mmio,
        CapabilityClass::MmioRegion,
        "write32",
        fresh_handle.clone(),
        "first device capability",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i7-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1102,
            driver_store,
            driver_store_generation,
            target: mmio,
            class: CapabilityClass::MmioRegion,
            operation: "write32".to_string(),
            handle: fresh_handle,
            note: "duplicate target operation must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["device capability target operation already has an active grant".to_string()]
    );

    graph.corrupt_device_capability_target_generation_for_test(1101, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DeviceCapabilityMissingTarget {
            device_capability: 1101,
            target: ContractObjectRef::new(ContractObjectKind::MmioRegionObject, 801, 2),
        })
    );
}

fn record_i8_device_probe_capability(
    graph: &mut SemanticGraph,
    driver_store: StoreId,
    driver_store_generation: Generation,
    device: ContractObjectRef,
    id: DeviceCapabilityId,
) -> DeviceCapabilityId {
    let cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "device.fake-io0",
        AuthorityObjectRef::internal(CapabilityClass::Device, device),
        &["probe"],
        "store",
        "i8-test",
        true,
    );
    let handle = graph
        .capabilities()
        .record(cap)
        .and_then(|record| record.store_local_handle(vec!["probe".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        id,
        driver_store,
        driver_store_generation,
        device,
        CapabilityClass::Device,
        "probe",
        handle,
        "device probe capability",
    ));
    id
}

#[test]
fn io_runtime_i8_driver_store_binding_records_exact_driver_and_device_identity() {
    let (mut graph, driver_store, driver_store_generation, device, _mmio, _dma, _irq) =
        setup_i7_device_capability_graph();
    let device_capability = record_i8_device_probe_capability(
        &mut graph,
        driver_store,
        driver_store_generation,
        device,
        1201,
    );
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i8-test",
        SemanticCommand::BindDriverStore {
            binding: 1202,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            device_capability,
            device_capability_generation: 1,
            note: "driver store binding harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.driver_store_bindings().len(), 1);
    let binding = &graph.driver_store_bindings()[0];
    assert_eq!(binding.id, 1202);
    assert_eq!(binding.driver_store, driver_store);
    assert_eq!(binding.driver_store_generation, driver_store_generation);
    assert_eq!(binding.device, 401);
    assert_eq!(binding.device_generation, 1);
    assert_eq!(binding.device_capability, device_capability);
    assert_eq!(binding.device_capability_generation, 1);
    assert_eq!(binding.state, DriverStoreBindingState::Bound);
    assert!(binding.recorded_at_event > cursor_before);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "DriverStoreBound binding=1202 driver_store={driver_store}@{driver_store_generation} device=401@1 device_capability=1201@1 capability={}@1 generation=1",
            binding.capability
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i8_rejects_stale_wrong_or_duplicate_driver_store_binding() {
    let (mut graph, driver_store, driver_store_generation, device, mmio, _dma, _irq) =
        setup_i7_device_capability_graph();
    let device_capability = record_i8_device_probe_capability(
        &mut graph,
        driver_store,
        driver_store_generation,
        device,
        1201,
    );

    let stale_device_capability = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i8-test",
        SemanticCommand::BindDriverStore {
            binding: 1202,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            device_capability,
            device_capability_generation: 2,
            note: "stale device capability generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_device_capability.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device_capability.violations,
        vec![
            "driver store binding device capability generation is missing or inactive".to_string()
        ]
    );

    let stale_device = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i8-test",
        SemanticCommand::BindDriverStore {
            binding: 1202,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 2,
            device_capability,
            device_capability_generation: 1,
            note: "stale device generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device.violations,
        vec!["driver store binding device generation is missing or inactive".to_string()]
    );

    let wrong_class_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "i8-test",
        true,
    );
    let wrong_class_handle = graph
        .capabilities()
        .record(wrong_class_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1203,
        driver_store,
        driver_store_generation,
        mmio,
        CapabilityClass::MmioRegion,
        "write32",
        wrong_class_handle,
        "wrong-class capability",
    ));
    let wrong_class = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i8-test",
        SemanticCommand::BindDriverStore {
            binding: 1202,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            device_capability: 1203,
            device_capability_generation: 1,
            note: "wrong target/class capability must reject".to_string(),
        },
    ));
    assert_eq!(wrong_class.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_class.violations,
        vec!["driver store binding device capability does not authorize binding".to_string()]
    );

    assert!(graph.record_driver_store_binding_with_id(
        1202,
        driver_store,
        driver_store_generation,
        401,
        1,
        device_capability,
        1,
        "first binding",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i8-test",
        SemanticCommand::BindDriverStore {
            binding: 1204,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            device_capability,
            device_capability_generation: 1,
            note: "duplicate active binding must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["driver store binding device already has an active driver".to_string()]
    );

    graph.corrupt_driver_store_binding_device_generation_for_test(1202, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DriverStoreBindingMissingDevice {
            binding: 1202,
            device: 401,
        })
    );
}

fn setup_i9_io_wait_graph() -> (
    SemanticGraph,
    StoreId,
    Generation,
    ContractObjectRef,
    ContractObjectRef,
    DriverStoreBindingId,
) {
    let (mut graph, driver_store, driver_store_generation, device, _mmio, _dma, irq) =
        setup_i7_device_capability_graph();
    let device_capability = record_i8_device_probe_capability(
        &mut graph,
        driver_store,
        driver_store_generation,
        device,
        1301,
    );
    assert!(graph.record_driver_store_binding_with_id(
        1302,
        driver_store,
        driver_store_generation,
        401,
        1,
        device_capability,
        1,
        "i9 binding harness",
    ));
    (
        graph,
        driver_store,
        driver_store_generation,
        device,
        irq,
        1302,
    )
}

#[test]
fn io_runtime_i9_io_wait_resolves_from_irq_event_with_exact_generations() {
    let (mut graph, driver_store, driver_store_generation, _device, irq, binding) =
        setup_i9_io_wait_graph();

    let create_wait = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i9-test",
        SemanticCommand::CreateWait {
            wait: 1303,
            owner_task: None,
            owner_store: Some(driver_store),
            owner_store_generation: Some(driver_store_generation),
            kind: SemanticWaitKind::DeviceIrq,
            generation: 1,
            blockers: vec![irq],
            deadline: None,
            restart_policy: RestartPolicy::InternalOnly,
            saved_context: Some("driver.fake-io0:rx-irq".to_string()),
        },
    ));
    assert_eq!(create_wait.status, CommandStatus::Applied);

    let record_io_wait = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i9-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1304,
            wait: 1303,
            wait_generation: 1,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: irq,
            note: "io wait blocks on fake irq line".to_string(),
        },
    ));
    assert_eq!(record_io_wait.status, CommandStatus::Applied);
    let index = graph.wait_index();
    assert!(index.by_resource.contains(&(irq, 1303)));
    assert!(
        index
            .by_store
            .contains(&(driver_store, driver_store_generation, 1303))
    );

    assert_eq!(graph.io_waits().len(), 1);
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Pending);
    assert!(graph.record_irq_event_with_id(
        1305,
        901,
        1,
        401,
        1,
        driver_store,
        driver_store_generation,
        2,
        "fake irq resolves io wait",
    ));
    let resolve = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i9-test",
        SemanticCommand::ResolveIoWait {
            io_wait: 1304,
            io_wait_generation: 1,
            irq_event: 1305,
            irq_event_generation: 1,
            note: "fake irq event resolves wait".to_string(),
        },
    ));
    assert_eq!(resolve.status, CommandStatus::Applied);
    let wait = graph
        .wait_records()
        .iter()
        .find(|wait| wait.id == 1303)
        .unwrap();
    assert_eq!(wait.state, WaitState::Resolved);
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Resolved);
    assert_eq!(graph.io_waits()[0].completion_irq_event, Some(1305));
    assert_eq!(graph.io_waits()[0].completion_irq_event_generation, Some(1));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IoWaitResolved io_wait=1304 wait=1303@1 irq_event=1305@1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i9_rejects_stale_waits_and_cancels_device_faults() {
    let (mut graph, driver_store, driver_store_generation, _device, irq, binding) =
        setup_i9_io_wait_graph();
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1310,
                owner_task: None,
                owner_store: Some(driver_store),
                owner_store_generation: Some(driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![irq],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: None,
            })
            .is_ok()
    );

    let stale_wait_generation = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i9-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1311,
            wait: 1310,
            wait_generation: 2,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: irq,
            note: "stale wait generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_wait_generation.status, CommandStatus::Rejected);
    assert_eq!(
        stale_wait_generation.violations,
        vec!["io wait token generation is missing or not pending".to_string()]
    );

    let stale_device_generation = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i9-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1311,
            wait: 1310,
            wait_generation: 1,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 2,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: irq,
            note: "stale device generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_device_generation.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device_generation.violations,
        vec!["io wait device generation is missing or inactive".to_string()]
    );

    let other_device_resource = graph.register_resource(ResourceKind::Device, None, "device:other");
    let other_device_resource_generation = graph
        .resource_handle(other_device_resource)
        .unwrap()
        .generation;
    let other_dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:other");
    let other_dma_resource_generation = graph
        .resource_handle(other_dma_resource)
        .unwrap()
        .generation;
    assert!(graph.record_device_object_with_id(
        402,
        "other-io",
        "fake-device",
        other_device_resource,
        other_device_resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "other-io-v1",
        "other device object",
    ));
    assert!(graph.record_queue_object_with_id(
        502,
        "other-io-rx",
        QueueObjectRole::Rx,
        0,
        64,
        402,
        1,
        "other queue object",
    ));
    assert!(graph.record_descriptor_object_with_id(
        602,
        502,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "other descriptor object",
    ));
    assert!(graph.record_dma_buffer_object_with_id(
        702,
        602,
        1,
        other_dma_resource,
        other_dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        2048,
        "other dma buffer object",
    ));
    let wrong_device_dma = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 702, 1);
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1313,
                owner_task: None,
                owner_store: Some(driver_store),
                owner_store_generation: Some(driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![wrong_device_dma],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: None,
            })
            .is_ok()
    );
    let wrong_dma_device = graph.apply_envelope(CommandEnvelope::new(
        3,
        "i9-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1311,
            wait: 1313,
            wait_generation: 1,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: wrong_device_dma,
            note: "dma blocker from another device must reject".to_string(),
        },
    ));
    assert_eq!(wrong_dma_device.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_dma_device.violations,
        vec!["io wait blocker generation is missing or inactive".to_string()]
    );

    assert!(graph.record_io_wait_with_id(
        1311,
        1310,
        1,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        irq,
        "pending io wait",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "i9-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1312,
            wait: 1310,
            wait_generation: 1,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: irq,
            note: "duplicate pending io wait must reject".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["io wait token already has a pending io wait".to_string()]
    );

    let wrong_reason = graph.apply_envelope(CommandEnvelope::new(
        5,
        "i9-test",
        SemanticCommand::CancelIoWait {
            io_wait: 1311,
            io_wait_generation: 1,
            errno: 110,
            reason: WaitCancelReason::Timeout,
            note: "timeout is not an io fault reason".to_string(),
        },
    ));
    assert_eq!(wrong_reason.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_reason.violations,
        vec!["io wait cancellation reason is not an io reason".to_string()]
    );

    let cancel = graph.apply_envelope(CommandEnvelope::new(
        6,
        "i9-test",
        SemanticCommand::CancelIoWait {
            io_wait: 1311,
            io_wait_generation: 1,
            errno: 5,
            reason: WaitCancelReason::DeviceFault,
            note: "fake device fault cancels io wait".to_string(),
        },
    ));
    assert_eq!(cancel.status, CommandStatus::Applied);
    let wait = graph
        .wait_records()
        .iter()
        .find(|wait| wait.id == 1310)
        .unwrap();
    assert_eq!(wait.state, WaitState::Cancelled);
    assert_eq!(wait.cancel_reason, Some(WaitCancelReason::DeviceFault));
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Cancelled);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IoWaitCancelled io_wait=1311 wait=1310@1 reason=device-fault generation=1"
    );
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_io_wait_blocker_generation_for_test(1311, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IoWaitMissingBlocker {
            io_wait: 1311,
            blocker: ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 2),
        })
    );
}

fn setup_i10_io_cleanup_graph() -> (
    SemanticGraph,
    StoreId,
    Generation,
    DriverStoreBindingId,
    IoWaitId,
) {
    let (mut graph, driver_store, driver_store_generation, device, mmio, dma, irq) =
        setup_i7_device_capability_graph();
    let device_capability = record_i8_device_probe_capability(
        &mut graph,
        driver_store,
        driver_store_generation,
        device,
        1401,
    );
    assert!(graph.record_driver_store_binding_with_id(
        1402,
        driver_store,
        driver_store_generation,
        401,
        1,
        device_capability,
        1,
        "i10 binding harness",
    ));

    let mmio_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "mmio.fake-io0.regs",
        AuthorityObjectRef::internal(CapabilityClass::MmioRegion, mmio),
        &["write32"],
        "store",
        "i10-test",
        true,
    );
    let dma_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "dma.fake-io0.rx0",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma),
        &["sync-for-device"],
        "store",
        "i10-test",
        true,
    );
    let irq_cap = graph.grant_capability_with_authority_ref(
        "driver.fake-io0",
        "irq.fake-io0.rx",
        AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq),
        &["ack"],
        "store",
        "i10-test",
        true,
    );
    let mmio_handle = graph
        .capabilities()
        .record(mmio_cap)
        .and_then(|record| record.store_local_handle(vec!["write32".to_string()]))
        .unwrap();
    let dma_handle = graph
        .capabilities()
        .record(dma_cap)
        .and_then(|record| record.store_local_handle(vec!["sync-for-device".to_string()]))
        .unwrap();
    let irq_handle = graph
        .capabilities()
        .record(irq_cap)
        .and_then(|record| record.store_local_handle(vec!["ack".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1403,
        driver_store,
        driver_store_generation,
        mmio,
        CapabilityClass::MmioRegion,
        "write32",
        mmio_handle,
        "i10 mmio capability",
    ));
    assert!(graph.record_device_capability_with_id(
        1404,
        driver_store,
        driver_store_generation,
        dma,
        CapabilityClass::DmaBuffer,
        "sync-for-device",
        dma_handle,
        "i10 dma capability",
    ));
    assert!(graph.record_device_capability_with_id(
        1405,
        driver_store,
        driver_store_generation,
        irq,
        CapabilityClass::IrqLine,
        "ack",
        irq_handle,
        "i10 irq capability",
    ));
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1406,
                owner_task: None,
                owner_store: Some(driver_store),
                owner_store_generation: Some(driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![irq],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("driver.fake-io0:cleanup-rx".to_string()),
            })
            .is_ok()
    );
    assert!(graph.record_io_wait_with_id(
        1407,
        1406,
        1,
        driver_store,
        driver_store_generation,
        401,
        1,
        1402,
        1,
        irq,
        "i10 pending io wait",
    ));
    assert!(graph.record_irq_event_with_id(
        1409,
        901,
        1,
        401,
        1,
        driver_store,
        driver_store_generation,
        1,
        "i10 historical irq event before cleanup",
    ));
    (graph, driver_store, driver_store_generation, 1402, 1407)
}

#[test]
fn io_runtime_i10_cleanup_cancels_waits_revokes_caps_and_releases_io_objects() {
    let (mut graph, driver_store, driver_store_generation, binding, io_wait) =
        setup_i10_io_cleanup_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i10-test",
        SemanticCommand::CleanupIoDriver {
            cleanup: 1408,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            reason: "device-fault".to_string(),
            note: "i10 io cleanup harness".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.io_cleanup_count(), 1);
    let cleanup = &graph.io_cleanups()[0];
    assert_eq!(cleanup.state, IoCleanupState::Completed);
    assert_eq!(cleanup.cancelled_io_waits.len(), 1);
    assert_eq!(cleanup.cancelled_io_waits[0].id, io_wait);
    assert_eq!(cleanup.revoked_device_capabilities.len(), 4);
    assert_eq!(cleanup.revoked_capabilities.len(), 4);
    assert_eq!(cleanup.released_dma_buffers.len(), 1);
    assert_eq!(cleanup.released_mmio_regions.len(), 1);
    assert_eq!(cleanup.released_irq_lines.len(), 1);
    assert!(
        cleanup
            .steps
            .iter()
            .any(|step| step.kind == IoCleanupStepKind::CancelIoWaits
                && step.status == IoCleanupStepStatus::Done)
    );

    let wait = graph
        .wait_records()
        .iter()
        .find(|record| record.id == 1406)
        .unwrap();
    assert_eq!(wait.state, WaitState::Cancelled);
    assert_eq!(wait.cancel_reason, Some(WaitCancelReason::DeviceFault));
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Cancelled);
    assert!(
        graph
            .device_capabilities()
            .iter()
            .filter(|record| record.driver_store == driver_store
                && record.driver_store_generation == driver_store_generation)
            .all(|record| record.state == DeviceCapabilityState::Revoked)
    );
    assert_eq!(
        graph.driver_store_bindings()[0].state,
        DriverStoreBindingState::Released
    );
    assert_eq!(
        graph.dma_buffer_objects()[0].state,
        DmaBufferObjectState::Released
    );
    assert_eq!(
        graph.mmio_region_objects()[0].state,
        MmioRegionObjectState::Released
    );
    assert_eq!(
        graph.irq_line_objects()[0].state,
        IrqLineObjectState::Released
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IoCleanupCompleted cleanup=1408 driver_store=1@2 device=401@1 driver_binding=1402@1 cancelled_io_waits=1 revoked_device_capabilities=4 released_dma_buffers=1 released_mmio_regions=1 released_irq_lines=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());

    let cleanup_count = graph.io_cleanup_count();
    let replay = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i10-test",
        SemanticCommand::CleanupIoDriver {
            cleanup: 1408,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            reason: "device-fault".to_string(),
            note: "i10 idempotent replay".to_string(),
        },
    ));
    assert_eq!(replay.status, CommandStatus::Applied);
    assert_eq!(graph.io_cleanup_count(), cleanup_count);
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i10_rejects_stale_cleanup_and_blocks_post_cleanup_wait_reuse() {
    let (mut graph, driver_store, driver_store_generation, binding, _io_wait) =
        setup_i10_io_cleanup_graph();
    let stale_device = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i10-test",
        SemanticCommand::CleanupIoDriver {
            cleanup: 1410,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 2,
            driver_binding: binding,
            driver_binding_generation: 1,
            reason: "device-fault".to_string(),
            note: "stale device cleanup must reject".to_string(),
        },
    ));
    assert_eq!(stale_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_device.violations,
        vec!["io cleanup device generation is missing or inactive".to_string()]
    );

    assert!(graph.cleanup_io_driver_for_device_fault_with_id(
        1410,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        "device-fault",
        "cleanup before wait reuse",
    ));
    let irq = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1);
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1411,
                owner_task: None,
                owner_store: Some(driver_store),
                owner_store_generation: Some(driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![irq],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: None,
            })
            .is_ok()
    );
    let post_cleanup_wait = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i10-test",
        SemanticCommand::RecordIoWait {
            io_wait: 1412,
            wait: 1411,
            wait_generation: 1,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            blocker: irq,
            note: "released binding must reject new io wait".to_string(),
        },
    ));
    assert_eq!(post_cleanup_wait.status, CommandStatus::Rejected);
    assert_eq!(
        post_cleanup_wait.violations,
        vec!["io wait driver binding generation is missing or inactive".to_string()]
    );

    graph.corrupt_io_cleanup_cancelled_wait_for_test(1410, 1407);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IoWaitMissingBlocker {
            io_wait: 1407,
            blocker: irq,
        })
    );
}

#[test]
fn io_runtime_i11_fault_injection_triggers_cleanup_with_exact_generations() {
    let (mut graph, driver_store, driver_store_generation, binding, io_wait) =
        setup_i10_io_cleanup_graph();
    let target = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i11-test",
        SemanticCommand::InjectIoFault {
            fault: 1411,
            cleanup: 1412,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            target,
            kind: IoFaultInjectionKind::DeviceFault,
            note: "i11 injected irq fault".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.io_fault_injection_count(), 1);
    assert_eq!(graph.io_cleanup_count(), 1);
    let fault = &graph.io_fault_injections()[0];
    assert_eq!(fault.state, IoFaultInjectionState::Completed);
    assert_eq!(fault.kind, IoFaultInjectionKind::DeviceFault);
    assert_eq!(fault.target, target);
    assert_eq!(fault.cleanup, 1412);
    assert_eq!(fault.cleanup_generation, 1);
    assert_eq!(graph.io_cleanups()[0].cancelled_io_waits[0].id, io_wait);
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Cancelled);
    assert_eq!(
        graph.irq_line_objects()[0].state,
        IrqLineObjectState::Released
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IoFaultInjected fault=1411 kind=device-fault driver_store=1@2 device=401@1 driver_binding=1402@1 target=irq-line-object:901@1 cleanup=1412@1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());

    let replay = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i11-test",
        SemanticCommand::InjectIoFault {
            fault: 1411,
            cleanup: 1412,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            target,
            kind: IoFaultInjectionKind::DeviceFault,
            note: "i11 idempotent replay".to_string(),
        },
    ));
    assert_eq!(replay.status, CommandStatus::Applied);
    assert_eq!(graph.io_fault_injection_count(), 1);
    assert_eq!(graph.io_cleanup_count(), 1);
}

#[test]
fn io_runtime_i11_rejects_stale_or_post_cleanup_fault_injection() {
    let (mut graph, driver_store, driver_store_generation, binding, _io_wait) =
        setup_i10_io_cleanup_graph();
    let stale_target = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i11-test",
        SemanticCommand::InjectIoFault {
            fault: 1413,
            cleanup: 1414,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            target: ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 2),
            kind: IoFaultInjectionKind::DeviceFault,
            note: "stale irq generation must reject".to_string(),
        },
    ));
    assert_eq!(stale_target.status, CommandStatus::Rejected);
    assert_eq!(
        stale_target.violations,
        vec!["io fault injection target generation is missing or inactive".to_string()]
    );

    assert!(graph.inject_io_fault_with_id(
        1413,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
        1414,
        IoFaultInjectionKind::DeviceFault,
        "cleanup before second fault",
    ));
    let post_cleanup = graph.apply_envelope(CommandEnvelope::new(
        2,
        "i11-test",
        SemanticCommand::InjectIoFault {
            fault: 1415,
            cleanup: 1416,
            driver_store,
            driver_store_generation,
            device: 401,
            device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            target: ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
            kind: IoFaultInjectionKind::DeviceFault,
            note: "released binding must reject second fault".to_string(),
        },
    ));
    assert_eq!(post_cleanup.status, CommandStatus::Rejected);
    assert_eq!(
        post_cleanup.violations,
        vec!["io fault injection driver binding is not bound to target".to_string()]
    );

    graph.corrupt_io_fault_cleanup_ref_for_test(1413, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IoFaultInjectionMissingCleanup {
            fault: 1413,
            cleanup: 1414,
        })
    );
}

#[test]
fn io_runtime_i12_validator_reports_clean_io_subgraph() {
    let (mut graph, driver_store, driver_store_generation, binding, _io_wait) =
        setup_i10_io_cleanup_graph();
    assert!(graph.inject_io_fault_with_id(
        1417,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
        1418,
        IoFaultInjectionKind::DeviceFault,
        "i12 cleanup before validation",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i12-test",
        SemanticCommand::ValidateIoRuntime {
            report: 1419,
            note: "i12 clean validator".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.io_validation_report_count(), 1);
    let report = &graph.io_validation_reports()[0];
    assert_eq!(report.state, IoValidationReportState::Passed);
    assert!(report.violations.is_empty());
    assert_eq!(report.observed_device_count, 1);
    assert_eq!(report.observed_io_cleanup_count, 1);
    assert_eq!(report.observed_io_fault_injection_count, 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IoValidationReportRecorded report=1419 ok=true violations=0 devices=1 dma_buffers=1 irq_events=1 cleanups=1 fault_injections=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn io_runtime_i12_validator_records_generation_violations_without_hiding_them() {
    let (mut graph, driver_store, driver_store_generation, binding, io_wait) =
        setup_i10_io_cleanup_graph();
    assert!(graph.inject_io_fault_with_id(
        1420,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
        1421,
        IoFaultInjectionKind::DeviceFault,
        "i12 cleanup before negative validation",
    ));
    graph.corrupt_io_wait_driver_binding_generation_for_test(io_wait, 2);

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i12-test",
        SemanticCommand::ValidateIoRuntime {
            report: 1422,
            note: "i12 bad validator".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    let report = &graph.io_validation_reports()[0];
    assert_eq!(report.state, IoValidationReportState::Failed);
    assert!(report.violations.iter().any(|violation| {
        violation.code == IoValidationViolationCode::StaleGeneration
            && violation.subject.kind == ContractObjectKind::IoWait
            && violation.subject.id == io_wait
            && violation.relation == "io-wait->driver-binding"
    }));
}

#[test]
fn io_runtime_i12_validator_rejects_future_cleanup_capability_generation() {
    let (mut graph, driver_store, driver_store_generation, binding, _io_wait) =
        setup_i10_io_cleanup_graph();
    assert!(graph.inject_io_fault_with_id(
        1423,
        driver_store,
        driver_store_generation,
        401,
        1,
        binding,
        1,
        ContractObjectRef::new(ContractObjectKind::IrqLineObject, 901, 1),
        1424,
        IoFaultInjectionKind::DeviceFault,
        "i12 cleanup before capability-generation validation",
    ));
    graph.corrupt_io_cleanup_revoked_capability_generation_for_test(1424, 999);

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "i12-test",
        SemanticCommand::ValidateIoRuntime {
            report: 1425,
            note: "i12 future capability generation validator".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    let report = &graph.io_validation_reports()[0];
    assert_eq!(report.state, IoValidationReportState::Failed);
    assert!(report.violations.iter().any(|violation| {
        violation.code == IoValidationViolationCode::StaleGeneration
            && violation.subject.kind == ContractObjectKind::IoCleanup
            && violation.subject.id == 1424
            && violation.relation == "io-cleanup->effect"
    }));
}

#[test]
fn network_runtime_n0_packet_device_object_records_contract_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1501,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n0 backing device",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n0-test",
        SemanticCommand::RecordPacketDeviceObject {
            packet_device: 1502,
            name: "net0".to_string(),
            device: 1501,
            device_generation: 1,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
            frame_format_version: 2,
            max_payload_len: 512,
            note: "n0 packet device object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.packet_device_object_count(), 1);
    let packet_device = &graph.packet_device_objects()[0];
    assert_eq!(
        packet_device.object_ref(),
        ContractObjectRef::new(ContractObjectKind::PacketDeviceObject, 1502, 1)
    );
    assert_eq!(packet_device.device, 1501);
    assert_eq!(packet_device.device_generation, 1);
    assert_eq!(packet_device.mtu, 1500);
    assert_eq!(packet_device.rx_queue_depth, 4);
    assert_eq!(packet_device.tx_queue_depth, 4);
    assert_eq!(packet_device.max_payload_len, 512);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "PacketDeviceObjectRecorded packet_device=1502 device=1501@1 mtu=1500 rx_queue_depth=4 tx_queue_depth=4 frame_format_version=2 max_payload_len=512 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n0_rejects_stale_or_non_packet_device() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:not-packet");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1503,
        "not-net0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "n0 wrong backing device",
    ));

    let wrong_class = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n0-test",
        SemanticCommand::RecordPacketDeviceObject {
            packet_device: 1504,
            name: "net0".to_string(),
            device: 1503,
            device_generation: 1,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
            frame_format_version: 2,
            max_payload_len: 512,
            note: "n0 wrong class".to_string(),
        },
    ));
    assert_eq!(wrong_class.status, CommandStatus::Rejected);

    let packet_resource =
        graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net1");
    let packet_resource_generation = graph.resource_handle(packet_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1505,
        "virtio-net1",
        "packet-device",
        packet_resource,
        packet_resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n0 stale backing device",
    ));
    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n0-test",
        SemanticCommand::RecordPacketDeviceObject {
            packet_device: 1506,
            name: "net1".to_string(),
            device: 1505,
            device_generation: 2,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x02],
            frame_format_version: 2,
            max_payload_len: 512,
            note: "n0 stale generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let bad_contract = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n0-test",
        SemanticCommand::RecordPacketDeviceObject {
            packet_device: 1509,
            name: "net1".to_string(),
            device: 1505,
            device_generation: 1,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x02],
            frame_format_version: 0,
            max_payload_len: 512,
            note: "n0 bad frame format".to_string(),
        },
    ));
    assert_eq!(bad_contract.status, CommandStatus::Rejected);
}

#[test]
fn network_runtime_n0_invariants_reject_packet_device_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1507,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n0 invariant backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1508,
        "net0",
        1507,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        2,
        512,
        "n0 invariant packet device",
    ));
    graph.corrupt_packet_device_object_device_generation_for_test(1508, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PacketDeviceObjectMissingDevice {
            packet_device: 1508,
            device: 1507,
        })
    );
}

#[test]
fn network_runtime_n1_packet_buffer_object_records_generation_safe_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1510,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n1 backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1511,
        "net0",
        1510,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        2,
        512,
        "n1 packet device",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n1-test",
        SemanticCommand::RecordPacketBufferObject {
            packet_buffer: 1512,
            packet_device: 1511,
            packet_device_generation: 1,
            direction: PacketBufferDirection::Rx,
            frame_format_version: 2,
            capacity: 512,
            payload_len: 64,
            sequence: 7,
            state: PacketBufferObjectState::Filled,
            note: "n1 packet buffer object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.packet_buffer_object_count(), 1);
    let packet_buffer = &graph.packet_buffer_objects()[0];
    assert_eq!(
        packet_buffer.object_ref(),
        ContractObjectRef::new(ContractObjectKind::PacketBufferObject, 1512, 1)
    );
    assert_eq!(packet_buffer.packet_device, 1511);
    assert_eq!(packet_buffer.packet_device_generation, 1);
    assert_eq!(packet_buffer.direction, PacketBufferDirection::Rx);
    assert_eq!(packet_buffer.frame_format_version, 2);
    assert_eq!(packet_buffer.capacity, 512);
    assert_eq!(packet_buffer.payload_len, 64);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "PacketBufferObjectRecorded packet_buffer=1512 packet_device=1511@1 direction=rx frame_format_version=2 capacity=512 payload_len=64 sequence=7 state=filled generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n1_rejects_stale_format_and_oversized_buffer() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net1");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1513,
        "virtio-net1",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n1 backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1514,
        "net1",
        1513,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x02],
        2,
        512,
        "n1 packet device",
    ));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n1-test",
        SemanticCommand::RecordPacketBufferObject {
            packet_buffer: 1515,
            packet_device: 1514,
            packet_device_generation: 2,
            direction: PacketBufferDirection::Rx,
            frame_format_version: 2,
            capacity: 512,
            payload_len: 64,
            sequence: 1,
            state: PacketBufferObjectState::Filled,
            note: "n1 stale packet device".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let bad_format = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n1-test",
        SemanticCommand::RecordPacketBufferObject {
            packet_buffer: 1516,
            packet_device: 1514,
            packet_device_generation: 1,
            direction: PacketBufferDirection::Rx,
            frame_format_version: 3,
            capacity: 512,
            payload_len: 64,
            sequence: 2,
            state: PacketBufferObjectState::Filled,
            note: "n1 bad frame format".to_string(),
        },
    ));
    assert_eq!(bad_format.status, CommandStatus::Rejected);

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n1-test",
        SemanticCommand::RecordPacketBufferObject {
            packet_buffer: 1517,
            packet_device: 1514,
            packet_device_generation: 1,
            direction: PacketBufferDirection::Tx,
            frame_format_version: 2,
            capacity: 513,
            payload_len: 64,
            sequence: 3,
            state: PacketBufferObjectState::Filled,
            note: "n1 oversized capacity".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);

    let empty_filled = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n1-test",
        SemanticCommand::RecordPacketBufferObject {
            packet_buffer: 1518,
            packet_device: 1514,
            packet_device_generation: 1,
            direction: PacketBufferDirection::Tx,
            frame_format_version: 2,
            capacity: 512,
            payload_len: 0,
            sequence: 4,
            state: PacketBufferObjectState::Filled,
            note: "n1 empty filled buffer".to_string(),
        },
    ));
    assert_eq!(empty_filled.status, CommandStatus::Rejected);
}

#[test]
fn network_runtime_n1_invariants_reject_packet_buffer_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1519,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n1 invariant backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1520,
        "net0",
        1519,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        2,
        512,
        "n1 invariant packet device",
    ));
    assert!(graph.record_packet_buffer_object_with_id(
        1521,
        1520,
        1,
        PacketBufferDirection::Rx,
        2,
        512,
        64,
        1,
        PacketBufferObjectState::Filled,
        "n1 invariant packet buffer",
    ));
    graph.corrupt_packet_buffer_packet_device_generation_for_test(1521, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PacketBufferObjectMissingDevice {
            packet_buffer: 1521,
            packet_device: 1520,
        })
    );
}

#[test]
fn network_runtime_n2_packet_queues_record_rx_and_tx_contract_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1522,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n2 backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1523,
        "net0",
        1522,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        2,
        512,
        "n2 packet device",
    ));

    let rx = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n2-test",
        SemanticCommand::RecordPacketQueueObject {
            packet_queue: 1524,
            name: "net0-rx0".to_string(),
            packet_device: 1523,
            packet_device_generation: 1,
            role: PacketQueueRole::Rx,
            queue_index: 0,
            depth: 4,
            note: "n2 rx packet queue".to_string(),
        },
    ));
    let tx = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n2-test",
        SemanticCommand::RecordPacketQueueObject {
            packet_queue: 1525,
            name: "net0-tx0".to_string(),
            packet_device: 1523,
            packet_device_generation: 1,
            role: PacketQueueRole::Tx,
            queue_index: 0,
            depth: 4,
            note: "n2 tx packet queue".to_string(),
        },
    ));

    assert_eq!(rx.status, CommandStatus::Applied);
    assert_eq!(tx.status, CommandStatus::Applied);
    assert_eq!(graph.packet_queue_object_count(), 2);
    let rx_queue = &graph.packet_queue_objects()[0];
    assert_eq!(
        rx_queue.object_ref(),
        ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1524, 1)
    );
    assert_eq!(rx_queue.packet_device, 1523);
    assert_eq!(rx_queue.packet_device_generation, 1);
    assert_eq!(rx_queue.role, PacketQueueRole::Rx);
    assert_eq!(rx_queue.depth, 4);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "PacketQueueObjectRecorded packet_queue=1525 packet_device=1523@1 role=tx queue_index=0 depth=4 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n2_rejects_stale_duplicate_and_overdepth_queue() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net1");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1526,
        "virtio-net1",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n2 backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1527,
        "net1",
        1526,
        1,
        1500,
        2,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x02],
        2,
        512,
        "n2 packet device",
    ));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n2-test",
        SemanticCommand::RecordPacketQueueObject {
            packet_queue: 1528,
            name: "net1-rx0".to_string(),
            packet_device: 1527,
            packet_device_generation: 2,
            role: PacketQueueRole::Rx,
            queue_index: 0,
            depth: 2,
            note: "n2 stale queue".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    assert!(graph.record_packet_queue_object_with_id(
        1529,
        "net1-rx0",
        1527,
        1,
        PacketQueueRole::Rx,
        0,
        2,
        "n2 first rx queue",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n2-test",
        SemanticCommand::RecordPacketQueueObject {
            packet_queue: 1530,
            name: "net1-rx0-dup".to_string(),
            packet_device: 1527,
            packet_device_generation: 1,
            role: PacketQueueRole::Rx,
            queue_index: 0,
            depth: 2,
            note: "n2 duplicate rx queue".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);

    let overdepth = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n2-test",
        SemanticCommand::RecordPacketQueueObject {
            packet_queue: 1531,
            name: "net1-rx1".to_string(),
            packet_device: 1527,
            packet_device_generation: 1,
            role: PacketQueueRole::Rx,
            queue_index: 1,
            depth: 3,
            note: "n2 overdepth rx queue".to_string(),
        },
    ));
    assert_eq!(overdepth.status, CommandStatus::Rejected);
}

#[test]
fn network_runtime_n2_invariants_reject_packet_queue_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1532,
        "virtio-net0",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n2 invariant backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1533,
        "net0",
        1532,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x01],
        2,
        512,
        "n2 invariant packet device",
    ));
    assert!(graph.record_packet_queue_object_with_id(
        1534,
        "net0-rx0",
        1533,
        1,
        PacketQueueRole::Rx,
        0,
        4,
        "n2 invariant packet queue",
    ));
    graph.corrupt_packet_queue_packet_device_generation_for_test(1534, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PacketQueueObjectMissingDevice {
            packet_queue: 1534,
            packet_device: 1533,
        })
    );
}

fn setup_n3_packet_descriptor_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net2");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1540,
        "virtio-net2",
        "packet-device",
        resource,
        resource_generation,
        "fake-net-backend",
        "semantic-harness",
        "vmos",
        "fake-net-v1",
        "n3 backing device",
    ));
    assert!(graph.record_packet_device_object_with_id(
        1541,
        "net2",
        1540,
        1,
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        "n3 packet device",
    ));
    assert!(graph.record_packet_buffer_object_with_id(
        1542,
        1541,
        1,
        PacketBufferDirection::Rx,
        2,
        512,
        0,
        1,
        PacketBufferObjectState::Allocated,
        "n3 rx packet buffer",
    ));
    assert!(graph.record_packet_buffer_object_with_id(
        1543,
        1541,
        1,
        PacketBufferDirection::Tx,
        2,
        512,
        64,
        2,
        PacketBufferObjectState::Filled,
        "n3 tx packet buffer",
    ));
    assert!(graph.record_packet_queue_object_with_id(
        1544,
        "net2-rx0",
        1541,
        1,
        PacketQueueRole::Rx,
        0,
        4,
        "n3 rx queue",
    ));
    assert!(graph.record_packet_queue_object_with_id(
        1545,
        "net2-tx0",
        1541,
        1,
        PacketQueueRole::Tx,
        0,
        4,
        "n3 tx queue",
    ));
    graph
}

#[test]
fn network_runtime_n3_packet_descriptors_record_queue_and_buffer_identity() {
    let mut graph = setup_n3_packet_descriptor_graph();
    let rx = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1546,
            packet_queue: 1544,
            packet_queue_generation: 1,
            packet_buffer: 1542,
            packet_buffer_generation: 1,
            slot: 0,
            length: 512,
            note: "n3 rx packet descriptor".to_string(),
        },
    ));
    let tx = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1547,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            slot: 0,
            length: 64,
            note: "n3 tx packet descriptor".to_string(),
        },
    ));

    assert_eq!(rx.status, CommandStatus::Applied);
    assert_eq!(tx.status, CommandStatus::Applied);
    assert_eq!(graph.packet_descriptor_object_count(), 2);
    let rx_descriptor = &graph.packet_descriptors()[0];
    assert_eq!(
        rx_descriptor.object_ref(),
        ContractObjectRef::new(ContractObjectKind::PacketDescriptorObject, 1546, 1)
    );
    assert_eq!(rx_descriptor.packet_queue, 1544);
    assert_eq!(rx_descriptor.packet_queue_generation, 1);
    assert_eq!(rx_descriptor.packet_buffer, 1542);
    assert_eq!(rx_descriptor.packet_buffer_generation, 1);
    assert_eq!(rx_descriptor.slot, 0);
    assert_eq!(rx_descriptor.length, 512);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "PacketDescriptorObjectRecorded packet_descriptor=1547 packet_queue=1545@1 packet_buffer=1543@1 slot=0 length=64 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n3_rejects_stale_duplicate_mismatch_and_overlength_descriptor() {
    let mut graph = setup_n3_packet_descriptor_graph();

    let stale_queue = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1546,
            packet_queue: 1544,
            packet_queue_generation: 2,
            packet_buffer: 1542,
            packet_buffer_generation: 1,
            slot: 0,
            length: 512,
            note: "n3 stale queue".to_string(),
        },
    ));
    assert_eq!(stale_queue.status, CommandStatus::Rejected);
    assert_eq!(
        stale_queue.violations,
        vec!["packet descriptor object queue generation is missing or inactive".to_string()]
    );

    let role_mismatch = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1546,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_buffer: 1542,
            packet_buffer_generation: 1,
            slot: 0,
            length: 512,
            note: "n3 role mismatch".to_string(),
        },
    ));
    assert_eq!(role_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        role_mismatch.violations,
        vec!["packet descriptor object queue role and buffer direction mismatch".to_string()]
    );

    let tx_overlength = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1546,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            slot: 0,
            length: 65,
            note: "n3 tx overlength".to_string(),
        },
    ));
    assert_eq!(tx_overlength.status, CommandStatus::Rejected);
    assert_eq!(
        tx_overlength.violations,
        vec!["tx packet descriptor length exceeds packet payload".to_string()]
    );

    assert!(graph.record_packet_descriptor_object_with_id(
        1546,
        1544,
        1,
        1542,
        1,
        0,
        512,
        "n3 first rx descriptor",
    ));
    assert!(graph.record_packet_buffer_object_with_id(
        1548,
        1541,
        1,
        PacketBufferDirection::Rx,
        2,
        512,
        0,
        3,
        PacketBufferObjectState::Allocated,
        "n3 second rx packet buffer",
    ));

    let duplicate_slot = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1549,
            packet_queue: 1544,
            packet_queue_generation: 1,
            packet_buffer: 1548,
            packet_buffer_generation: 1,
            slot: 0,
            length: 512,
            note: "n3 duplicate slot".to_string(),
        },
    ));
    assert_eq!(duplicate_slot.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate_slot.violations,
        vec![
            "packet descriptor object slot already exists for packet queue generation".to_string()
        ]
    );

    let duplicate_buffer = graph.apply_envelope(CommandEnvelope::new(
        5,
        "n3-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1550,
            packet_queue: 1544,
            packet_queue_generation: 1,
            packet_buffer: 1542,
            packet_buffer_generation: 1,
            slot: 1,
            length: 512,
            note: "n3 duplicate buffer".to_string(),
        },
    ));
    assert_eq!(duplicate_buffer.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate_buffer.violations,
        vec!["packet descriptor object packet buffer already has a descriptor".to_string()]
    );
}

#[test]
fn network_runtime_n3_invariants_reject_packet_descriptor_generation_leaks() {
    let mut graph = setup_n3_packet_descriptor_graph();
    assert!(graph.record_packet_descriptor_object_with_id(
        1546,
        1544,
        1,
        1542,
        1,
        0,
        512,
        "n3 invariant packet descriptor",
    ));
    graph.corrupt_packet_descriptor_queue_generation_for_test(1546, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PacketDescriptorObjectMissingQueue {
            packet_descriptor: 1546,
            packet_queue: 1544,
        })
    );

    let mut graph = setup_n3_packet_descriptor_graph();
    assert!(graph.record_packet_descriptor_object_with_id(
        1546,
        1544,
        1,
        1542,
        1,
        0,
        512,
        "n3 invariant packet descriptor",
    ));
    graph.corrupt_packet_descriptor_buffer_generation_for_test(1546, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::PacketDescriptorObjectMissingBuffer {
                packet_descriptor: 1546,
                packet_buffer: 1542,
            }
        )
    );
}

#[test]
fn network_runtime_n4_fake_net_backend_binds_exact_packet_device_contract() {
    let mut graph = setup_n3_packet_descriptor_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1551,
            name: "fake-net2".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-net-v1".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 0x1234,
            note: "n4 fake backend binding".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.fake_net_backend_object_count(), 1);
    let backend = &graph.fake_net_backends()[0];
    assert_eq!(
        backend.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FakeNetBackendObject, 1551, 1)
    );
    assert_eq!(backend.packet_device, 1541);
    assert_eq!(backend.packet_device_generation, 1);
    assert_eq!(backend.provider, "service_core");
    assert_eq!(backend.profile, "fake-net-v1");
    assert_eq!(backend.deterministic_seed, 0x1234);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FakeNetBackendObjectBound fake_net_backend=1551 packet_device=1541@1 mtu=1500 rx_queue_depth=4 tx_queue_depth=4 frame_format_version=2 max_payload_len=512 deterministic_seed=4660 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n4_rejects_stale_mismatched_unsupported_and_duplicate_backend() {
    let mut graph = setup_n3_packet_descriptor_graph();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1551,
            name: "fake-net2".to_string(),
            packet_device: 1541,
            packet_device_generation: 2,
            provider: "service_core".to_string(),
            profile: "fake-net-v1".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 1,
            note: "n4 stale packet device".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["fake net backend object packet device generation is missing or inactive".to_string()]
    );

    let mismatch = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1551,
            name: "fake-net2".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-net-v1".to_string(),
            mtu: 1400,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 1,
            note: "n4 mismatch".to_string(),
        },
    ));
    assert_eq!(mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        mismatch.violations,
        vec!["fake net backend object contract does not match packet device".to_string()]
    );

    let unsupported = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1551,
            name: "virtio-net2".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "virtio-net-v1".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 1,
            note: "n4 unsupported profile".to_string(),
        },
    ));
    assert_eq!(unsupported.status, CommandStatus::Rejected);
    assert_eq!(
        unsupported.violations,
        vec!["fake net backend object profile is unsupported".to_string()]
    );

    let unsupported_provider = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1551,
            name: "fake-net2".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            provider: "debug-harness".to_string(),
            profile: "fake-net-v1".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 1,
            note: "n4 unsupported provider".to_string(),
        },
    ));
    assert_eq!(unsupported_provider.status, CommandStatus::Rejected);
    assert_eq!(
        unsupported_provider.violations,
        vec!["fake net backend object provider is unsupported".to_string()]
    );

    assert!(graph.record_fake_net_backend_object_with_id(
        1551,
        "fake-net2",
        1541,
        1,
        "service_core",
        "fake-net-v1",
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        1,
        "n4 first binding",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "n4-test",
        SemanticCommand::RecordFakeNetBackendObject {
            fake_net_backend: 1552,
            name: "fake-net2-second".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-net-v1".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            deterministic_seed: 2,
            note: "n4 duplicate binding".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["fake net backend object already bound to packet device generation".to_string()]
    );
}

#[test]
fn network_runtime_n4_invariants_reject_fake_net_backend_generation_leak() {
    let mut graph = setup_n3_packet_descriptor_graph();
    assert!(graph.record_fake_net_backend_object_with_id(
        1551,
        "fake-net2",
        1541,
        1,
        "service_core",
        "fake-net-v1",
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        1,
        "n4 fake backend binding",
    ));
    graph.corrupt_fake_net_backend_packet_device_generation_for_test(1551, 2);
    assert!(matches!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::FakeNetBackendObjectMissingPacketDevice {
                fake_net_backend: 1551,
                packet_device: 1541,
            }
        )
    ));
}

fn setup_n5_virtio_net_backend_graph() -> (SemanticGraph, DriverStoreBindingId) {
    let mut graph = setup_n3_packet_descriptor_graph();
    let driver_store = graph.register_store(
        "driver.virtio-net2",
        "driver_virtio_net.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let device_ref = ContractObjectRef::new(ContractObjectKind::DeviceObject, 1540, 1);
    let cap = graph.grant_capability_with_authority_ref(
        "driver.virtio-net2",
        "device.virtio-net2",
        AuthorityObjectRef::internal(CapabilityClass::Device, device_ref),
        &["probe"],
        "store",
        "n5-test",
        true,
    );
    let handle = graph
        .capabilities()
        .record(cap)
        .and_then(|record| record.store_local_handle(vec!["probe".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1551,
        driver_store,
        driver_store_generation,
        device_ref,
        CapabilityClass::Device,
        "probe",
        handle,
        "n5 device probe capability",
    ));
    assert!(graph.record_driver_store_binding_with_id(
        1552,
        driver_store,
        driver_store_generation,
        1540,
        1,
        1551,
        1,
        "n5 virtio net driver binding",
    ));
    (graph, 1552)
}

#[test]
fn network_runtime_n5_virtio_net_backend_skeleton_binds_driver_and_packet_device() {
    let (mut graph, binding) = setup_n5_virtio_net_backend_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 virtio backend skeleton".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.virtio_net_backend_object_count(), 1);
    let backend = &graph.virtio_net_backends()[0];
    assert_eq!(
        backend.object_ref(),
        ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1)
    );
    assert_eq!(backend.packet_device, 1541);
    assert_eq!(backend.packet_device_generation, 1);
    assert_eq!(backend.driver_binding, binding);
    assert_eq!(backend.driver_binding_generation, 1);
    assert_eq!(backend.device, 1540);
    assert_eq!(backend.device_generation, 1);
    assert_eq!(backend.provider, "substrate_virtio");
    assert_eq!(backend.profile, "virtio-net-backend-skeleton-v1");
    assert_eq!(backend.model, "virtio-net");
    assert_eq!(backend.negotiated_features, 32);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "VirtioNetBackendSkeletonBound virtio_net_backend=1553 packet_device=1541@1 driver_binding=1552@1 device=1540@1 queue_size=4 rx_queue_index=0 tx_queue_index=1 negotiated_features=32 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n5_rejects_stale_mismatched_or_unsupported_backend() {
    let (mut graph, binding) = setup_n5_virtio_net_backend_graph();
    let stale_packet_device = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 2,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 stale packet device".to_string(),
        },
    ));
    assert_eq!(stale_packet_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_packet_device.violations,
        vec![
            "virtio net backend object packet device generation is missing or inactive".to_string()
        ]
    );

    let stale_binding = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 2,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 stale driver binding".to_string(),
        },
    ));
    assert_eq!(stale_binding.status, CommandStatus::Rejected);
    assert_eq!(
        stale_binding.violations,
        vec![
            "virtio net backend object driver binding generation is missing or inactive"
                .to_string()
        ]
    );

    let bad_provider = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "service_core".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 bad provider".to_string(),
        },
    ));
    assert_eq!(bad_provider.status, CommandStatus::Rejected);
    assert_eq!(
        bad_provider.violations,
        vec!["virtio net backend object provider is unsupported".to_string()]
    );

    let feature_mismatch = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 64,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 bad feature negotiation".to_string(),
        },
    ));
    assert_eq!(feature_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        feature_mismatch.violations,
        vec!["virtio net backend negotiated features exceed device features".to_string()]
    );

    let contract_mismatch = graph.apply_envelope(CommandEnvelope::new(
        5,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1400,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 contract mismatch".to_string(),
        },
    ));
    assert_eq!(contract_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        contract_mismatch.violations,
        vec!["virtio net backend object contract does not match packet device".to_string()]
    );

    let invalid_irq = graph.apply_envelope(CommandEnvelope::new(
        6,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1553,
            name: "virtio-net2-backend".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 0,
            note: "n5 invalid irq vector".to_string(),
        },
    ));
    assert_eq!(invalid_irq.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_irq.violations,
        vec!["virtio net backend object contract values are invalid".to_string()]
    );

    assert!(graph.record_virtio_net_backend_object_with_id(
        1553,
        "virtio-net2-backend",
        1541,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-net-backend-skeleton-v1",
        "virtio-net",
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        32,
        32,
        32,
        0,
        1,
        4,
        5,
        "n5 first backend",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        7,
        "n5-test",
        SemanticCommand::RecordVirtioNetBackendObject {
            virtio_net_backend: 1554,
            name: "virtio-net2-backend-dup".to_string(),
            packet_device: 1541,
            packet_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-net-backend-skeleton-v1".to_string(),
            model: "virtio-net".to_string(),
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            frame_format_version: 2,
            max_payload_len: 512,
            device_features: 32,
            driver_features: 32,
            negotiated_features: 32,
            rx_queue_index: 0,
            tx_queue_index: 1,
            queue_size: 4,
            irq_vector: 5,
            note: "n5 duplicate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["virtio net backend object already bound to packet device generation".to_string()]
    );
}

#[test]
fn network_runtime_n5_invariants_reject_virtio_backend_generation_leak() {
    let (mut graph, binding) = setup_n5_virtio_net_backend_graph();
    assert!(graph.record_virtio_net_backend_object_with_id(
        1553,
        "virtio-net2-backend",
        1541,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-net-backend-skeleton-v1",
        "virtio-net",
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        32,
        32,
        32,
        0,
        1,
        4,
        5,
        "n5 invariant backend",
    ));
    graph.corrupt_virtio_net_backend_driver_binding_generation_for_test(1553, 2);
    assert!(matches!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::VirtioNetBackendObjectMissingDriverBinding {
                virtio_net_backend: 1553,
                driver_binding: 1552,
            }
        )
    ));
}

#[test]
fn network_runtime_n5_invariants_reject_invalid_virtio_irq_vector() {
    let (mut graph, binding) = setup_n5_virtio_net_backend_graph();
    assert!(graph.record_virtio_net_backend_object_with_id(
        1553,
        "virtio-net2-backend",
        1541,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-net-backend-skeleton-v1",
        "virtio-net",
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        32,
        32,
        32,
        0,
        1,
        4,
        5,
        "n5 invariant backend",
    ));
    graph.corrupt_virtio_net_backend_irq_vector_for_test(1553, 0);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::VirtioNetBackendObjectInvalid {
            virtio_net_backend: 1553,
        })
    ));
}

fn setup_n6_network_rx_interrupt_graph() -> SemanticGraph {
    setup_n6_network_rx_interrupt_graph_with_irq_capability(true)
}

fn setup_n6_network_rx_interrupt_graph_with_irq_capability(
    grant_irq_capability: bool,
) -> SemanticGraph {
    let (mut graph, binding) = setup_n5_virtio_net_backend_graph();
    assert!(graph.record_virtio_net_backend_object_with_id(
        1553,
        "virtio-net2-backend",
        1541,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-net-backend-skeleton-v1",
        "virtio-net",
        1500,
        4,
        4,
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        2,
        512,
        32,
        32,
        32,
        0,
        1,
        4,
        5,
        "n6 backend",
    ));
    let irq_resource = graph.register_resource(ResourceKind::IrqLine, None, "irq:virtio-net2-rx");
    let irq_resource_generation = graph.resource_handle(irq_resource).unwrap().generation;
    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == binding)
        .cloned()
        .unwrap();
    assert!(graph.record_irq_line_object_with_id(
        1554,
        1540,
        1,
        irq_resource,
        irq_resource_generation,
        5,
        IrqLineTrigger::Level,
        IrqLinePolarity::ActiveHigh,
        "n6 rx irq line",
    ));
    let irq_ref = ContractObjectRef::new(ContractObjectKind::IrqLineObject, 1554, 1);
    if grant_irq_capability {
        let irq_cap = graph.grant_capability_with_authority_ref(
            "driver.virtio-net2",
            "irq.virtio-net2.rx",
            AuthorityObjectRef::internal(CapabilityClass::IrqLine, irq_ref),
            &["ack"],
            "store",
            "n6-test",
            true,
        );
        let irq_handle = graph
            .capabilities()
            .record(irq_cap)
            .and_then(|record| record.store_local_handle(vec!["ack".to_string()]))
            .unwrap();
        assert!(graph.record_device_capability_with_id(
            1560,
            binding_record.driver_store,
            binding_record.driver_store_generation,
            irq_ref,
            CapabilityClass::IrqLine,
            "ack",
            irq_handle,
            "n6 irq ack capability",
        ));
    }
    assert!(graph.record_irq_event_with_id(
        1555,
        1554,
        1,
        1540,
        1,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1,
        "n6 rx irq event",
    ));
    graph
}

#[test]
fn network_runtime_n6_rx_interrupt_records_irq_to_rx_queue_path() {
    let mut graph = setup_n6_network_rx_interrupt_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1556,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 1,
            note: "n6 rx interrupt path".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.network_rx_interrupt_count(), 1);
    let rx_interrupt = &graph.network_rx_interrupts()[0];
    assert_eq!(
        rx_interrupt.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkRxInterrupt, 1556, 1)
    );
    assert_eq!(rx_interrupt.virtio_net_backend, 1553);
    assert_eq!(rx_interrupt.irq_event, 1555);
    assert_eq!(rx_interrupt.packet_device, 1541);
    assert_eq!(rx_interrupt.rx_queue, 1544);
    assert_eq!(rx_interrupt.ready_descriptors, 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "NetworkRxInterruptRecorded rx_interrupt=1556 virtio_net_backend=1553@1 irq_event=1555@1 packet_device=1541@1 rx_queue=1544@1 ready_descriptors=1 sequence=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n6_rejects_stale_wrong_queue_overdepth_and_duplicate_irq() {
    let mut graph = setup_n6_network_rx_interrupt_graph();
    let stale_irq = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1556,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 2,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 1,
            note: "n6 stale irq".to_string(),
        },
    ));
    assert_eq!(stale_irq.status, CommandStatus::Rejected);
    assert_eq!(
        stale_irq.violations,
        vec!["network rx interrupt irq event generation is missing or inactive".to_string()]
    );

    let tx_queue = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1556,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1545,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 1,
            note: "n6 tx queue is not rx".to_string(),
        },
    ));
    assert_eq!(tx_queue.status, CommandStatus::Rejected);
    assert_eq!(
        tx_queue.violations,
        vec!["network rx interrupt rx queue does not match backend packet device".to_string()]
    );

    let overdepth = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1556,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            ready_descriptors: 5,
            sequence: 1,
            note: "n6 overdepth".to_string(),
        },
    ));
    assert_eq!(overdepth.status, CommandStatus::Rejected);
    assert_eq!(
        overdepth.violations,
        vec!["network rx interrupt ready descriptors exceed rx queue depth".to_string()]
    );

    assert!(graph.record_network_rx_interrupt_with_id(
        1556,
        1553,
        1,
        1555,
        1,
        1541,
        1,
        1544,
        1,
        1,
        1,
        "n6 first rx interrupt",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1557,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 2,
            note: "n6 duplicate irq event".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["network rx interrupt already recorded for irq event generation".to_string()]
    );
}

#[test]
fn network_runtime_n6_rejects_missing_irq_ack_capability() {
    let mut graph = setup_n6_network_rx_interrupt_graph_with_irq_capability(false);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n6-test",
        SemanticCommand::RecordNetworkRxInterrupt {
            rx_interrupt: 1556,
            virtio_net_backend: 1553,
            virtio_net_backend_generation: 1,
            irq_event: 1555,
            irq_event_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            ready_descriptors: 1,
            sequence: 1,
            note: "n6 missing irq ack capability".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Rejected);
    assert_eq!(
        result.violations,
        vec!["network rx interrupt irq ack capability is missing".to_string()]
    );
    assert_eq!(graph.network_rx_interrupt_count(), 0);
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n6_invariants_reject_rx_queue_generation_leak() {
    let mut graph = setup_n6_network_rx_interrupt_graph();
    assert!(graph.record_network_rx_interrupt_with_id(
        1556,
        1553,
        1,
        1555,
        1,
        1541,
        1,
        1544,
        1,
        1,
        1,
        "n6 invariant rx interrupt",
    ));
    graph.corrupt_network_rx_interrupt_queue_generation_for_test(1556, 2);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkRxInterruptMissingRxQueue {
            rx_interrupt: 1556,
            rx_queue: 1544,
        })
    ));
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
    assert!(graph.check_invariants().is_ok());

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
    assert!(graph.check_invariants().is_ok());
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

#[test]
fn smp_runtime_s0_registers_hart_and_changes_state() {
    let mut graph = SemanticGraph::new();

    let registered = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s0-test",
        SemanticCommand::RegisterHart {
            hart: 1,
            hardware_id: 0,
            label: "boot-hart0".to_string(),
            boot: true,
            note: "s0 hart object".to_string(),
        },
    ));
    assert_eq!(registered.status, CommandStatus::Applied);
    assert_eq!(graph.hart_count(), 1);
    assert_eq!(graph.harts()[0].object_ref().summary(), "hart:1@1");

    let state = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s0-test",
        SemanticCommand::SetHartState {
            hart: 1,
            hart_generation: 1,
            state: HartState::Idle,
            reason: "scheduler-ready".to_string(),
            note: "hart ready for S1 current activation".to_string(),
        },
    ));
    assert_eq!(state.status, CommandStatus::Applied);
    assert_eq!(graph.harts()[0].state, HartState::Idle);
    assert_eq!(graph.harts()[0].generation, 2);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "HartStateChanged hart=1 from=created to=idle reason=scheduler-ready generation=2"
    );
}

#[test]
fn smp_runtime_s0_rejects_duplicate_hart_and_stale_state_generation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));

    let duplicate_object = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s0-test",
        SemanticCommand::RegisterHart {
            hart: 1,
            hardware_id: 1,
            label: "duplicate-hart-object".to_string(),
            boot: false,
            note: "duplicate object".to_string(),
        },
    ));
    assert_eq!(duplicate_object.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("hart already exists".to_string());
    assert_eq!(duplicate_object.violations, expected);

    let duplicate_hardware = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s0-test",
        SemanticCommand::RegisterHart {
            hart: 2,
            hardware_id: 0,
            label: "duplicate-hardware-hart0".to_string(),
            boot: false,
            note: "duplicate hardware".to_string(),
        },
    ));
    assert_eq!(duplicate_hardware.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("hardware hart already exists".to_string());
    assert_eq!(duplicate_hardware.violations, expected);

    let stale_state = graph.apply_envelope(CommandEnvelope::new(
        3,
        "s0-test",
        SemanticCommand::SetHartState {
            hart: 1,
            hart_generation: 99,
            state: HartState::Running,
            reason: "stale-generation".to_string(),
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale_state.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("hart generation is missing".to_string());
    assert_eq!(stale_state.violations, expected);
    assert_eq!(graph.harts()[0].state, HartState::Created);
}

#[test]
fn smp_runtime_s0_invariants_reject_invalid_hart_identity() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    graph.corrupt_hart_generation_for_test(1, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::HartInvalidObjectIdentity { hart: 1 })
    );
}

#[test]
fn smp_runtime_s0_invariants_reject_duplicate_hardware_hart() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    let mut duplicate = graph.harts()[0].clone();
    duplicate.id = 2;
    graph.duplicate_hart_for_test(duplicate);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DuplicateHardwareHart { hardware_id: 0 })
    );
}

#[test]
fn smp_runtime_s1_binds_and_clears_hart_local_current_activation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));

    let bound = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s1-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 1,
            hart_generation: 2,
            activation: 11,
            activation_generation: 3,
            note: "dispatch on hart0".to_string(),
        },
    ));
    assert_eq!(bound.status, CommandStatus::Applied);
    assert_eq!(graph.harts()[0].state, HartState::Running);
    assert_eq!(graph.harts()[0].generation, 3);
    assert_eq!(graph.harts()[0].current_activation, Some(11));
    assert_eq!(graph.harts()[0].current_activation_generation, Some(3));
    assert_eq!(graph.harts()[0].current_task, Some(7));
    assert_eq!(graph.harts()[0].current_task_generation, Some(1));
    assert!(graph.check_invariants().is_ok());

    let cleared = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s1-test",
        SemanticCommand::ClearHartCurrentActivation {
            hart: 1,
            hart_generation: 3,
            activation: 11,
            activation_generation: 3,
            reason: "timer-preempt".to_string(),
            note: "hart local slot cleared".to_string(),
        },
    ));
    assert_eq!(cleared.status, CommandStatus::Applied);
    assert_eq!(graph.harts()[0].state, HartState::Idle);
    assert_eq!(graph.harts()[0].generation, 4);
    assert_eq!(graph.harts()[0].current_activation, None);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "HartCurrentActivationCleared hart=1 activation=11@3 reason=timer-preempt generation=4"
    );
}

#[test]
fn smp_runtime_s1_rejects_stale_hart_and_non_running_activation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));

    let non_running = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s1-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 1,
            hart_generation: 2,
            activation: 11,
            activation_generation: 1,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(non_running.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("current activation generation is missing or not running".to_string());
    assert_eq!(non_running.violations, expected);

    let stale_hart = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s1-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 1,
            hart_generation: 99,
            activation: 11,
            activation_generation: 1,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("hart generation is missing".to_string());
    assert_eq!(stale_hart.violations, expected);

    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    let non_idle_hart = graph.apply_envelope(CommandEnvelope::new(
        3,
        "s1-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 2,
            hart_generation: 1,
            activation: 11,
            activation_generation: 3,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(non_idle_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("hart is not idle".to_string());
    assert_eq!(non_idle_hart.violations, expected);
}

#[test]
fn smp_runtime_s1_invariants_reject_stale_current_activation_generation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.bind_hart_current_activation(1, 2, 11, 3, "dispatch"));
    graph.corrupt_hart_current_activation_generation_for_test(1, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::HartCurrentActivationMissing {
            hart: 1,
            activation: 11,
        })
    );
}

#[test]
fn smp_runtime_s2_timer_interrupt_uses_exact_hart_ref_and_event_attribution() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));

    let timer = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s2-test",
        SemanticCommand::RecordTimerInterrupt {
            interrupt: 5,
            timer_epoch: 1,
            hart: 1,
            hart_generation,
            target_activation: Some(11),
            target_activation_generation: Some(3),
            note: "timer attributed to hart0".to_string(),
        },
    ));

    assert_eq!(timer.status, CommandStatus::Applied);
    assert_eq!(graph.timer_interrupts()[0].hart, 1);
    assert_eq!(graph.timer_interrupts()[0].hart_generation, 2);
    assert_eq!(graph.timer_interrupts()[0].hardware_hart, 0);
    let attribution = graph.hart_event_attributions().last().unwrap();
    assert_eq!(attribution.event_kind, "TimerInterruptRecorded");
    assert_eq!(attribution.event_source, "timer");
    assert_eq!(attribution.hart, 1);
    assert_eq!(attribution.hart_generation, 2);
    assert_eq!(attribution.activation, Some(11));
    assert_eq!(attribution.activation_generation, Some(3));
    assert_eq!(attribution.task, Some(7));
    assert_eq!(attribution.task_generation, Some(1));
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s2_rejects_stale_or_missing_hart_ref() {
    let mut graph = SemanticGraph::new();
    register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));

    let stale_hart = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s2-test",
        SemanticCommand::RecordTimerInterrupt {
            interrupt: 5,
            timer_epoch: 1,
            hart: 1,
            hart_generation: 99,
            target_activation: Some(11),
            target_activation_generation: Some(1),
            note: "stale hart generation".to_string(),
        },
    ));
    assert_eq!(stale_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("timer interrupt hart generation is missing or inactive".to_string());
    assert_eq!(stale_hart.violations, expected);
    assert!(graph.timer_interrupts().is_empty());
}

#[test]
fn smp_runtime_s2_invariants_reject_bad_hart_event_generation() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.record_timer_interrupt_with_id(
        5,
        1,
        1,
        hart_generation,
        Some(11),
        Some(1),
        "timer"
    ));
    graph.corrupt_hart_event_attribution_hart_generation_for_test(1, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::HartEventAttributionHartGenerationMismatch {
                attribution: 1,
                hart: 1,
            }
        )
    );
}

#[test]
fn smp_runtime_s2_invariants_reject_timer_without_hart_event_attribution() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.record_timer_interrupt_with_id(
        5,
        1,
        1,
        hart_generation,
        Some(11),
        Some(1),
        "timer"
    ));
    graph.clear_hart_event_attributions_for_test();

    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::TimerInterruptMissingHartEventAttribution {
                interrupt: 5,
                event: graph.timer_interrupts()[0].recorded_at_event,
            }
        )
    );
}

#[test]
fn smp_runtime_s3_binds_runnable_queue_to_owner_hart_generation() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));

    let bound = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s3-test",
        SemanticCommand::BindRunnableQueueOwner {
            queue: 1,
            queue_generation: 1,
            hart: 1,
            hart_generation,
            note: "hart0 owns queue".to_string(),
        },
    ));

    assert_eq!(bound.status, CommandStatus::Applied);
    assert_eq!(graph.runnable_queues()[0].generation, 2);
    assert_eq!(graph.runnable_queues()[0].owner_hart, Some(1));
    assert_eq!(
        graph.runnable_queues()[0].owner_hart_generation,
        Some(hart_generation)
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "RunnableQueueOwnerBound queue=1 hart=1@2 generation=2 note=hart0 owns queue"
    );
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert_eq!(
        graph.runtime_activations()[0].runnable_queue_generation,
        Some(2)
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s3_rejects_stale_hart_generation_and_live_rebinding() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));

    let stale_owner = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s3-test",
        SemanticCommand::BindRunnableQueueOwner {
            queue: 1,
            queue_generation: 1,
            hart: 1,
            hart_generation: 99,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale_owner.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("runnable queue owner hart generation is missing or unavailable".to_string());
    assert_eq!(stale_owner.violations, expected);
    assert_eq!(graph.runnable_queues()[0].generation, 1);

    let bound = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s3-test",
        SemanticCommand::BindRunnableQueueOwner {
            queue: 1,
            queue_generation: 1,
            hart: 1,
            hart_generation,
            note: "hart0 owns queue".to_string(),
        },
    ));
    assert_eq!(bound.status, CommandStatus::Applied);
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));

    let live_rebind = graph.apply_envelope(CommandEnvelope::new(
        3,
        "s3-test",
        SemanticCommand::BindRunnableQueueOwner {
            queue: 1,
            queue_generation: 2,
            hart: 2,
            hart_generation: 2,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(live_rebind.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("runnable queue owner cannot change while entries are live".to_string());
    assert_eq!(live_rebind.violations, expected);
    assert_eq!(graph.runnable_queues()[0].owner_hart, Some(1));
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s3_invariants_reject_bad_queue_owner_generation() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));
    assert!(graph.bind_runnable_queue_owner(1, 1, 1, hart_generation, "owner"));

    graph.corrupt_runnable_queue_owner_for_test(1, Some(1), Some(99));

    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::RunnableQueueOwnerHartGenerationMismatch {
                queue: 1,
                hart: 1,
                expected: 99,
                actual: 2,
            }
        )
    );
}

#[test]
fn smp_runtime_s3_invariants_reject_partial_queue_owner_ref() {
    let mut graph = SemanticGraph::new();
    register_idle_test_hart(&mut graph);
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));

    graph.corrupt_runnable_queue_owner_for_test(1, Some(1), None);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RunnableQueueOwnerFieldMismatch { queue: 1 })
    );
}

#[test]
fn smp_runtime_s4_allows_distinct_current_activations_on_distinct_harts() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    graph.ensure_task(8, FrontendKind::LinuxElf, "linux-thread-8");
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));
    assert!(graph.create_runnable_queue_with_id(2, "hart1-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.create_runtime_activation_with_id(12, 8, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.enqueue_runnable_activation(2, 12, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.dequeue_runnable_activation(2, 12));

    let hart0 = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s4-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 1,
            hart_generation: 2,
            activation: 11,
            activation_generation: 3,
            note: "dispatch activation 11 on hart0".to_string(),
        },
    ));
    assert_eq!(hart0.status, CommandStatus::Applied);
    let hart1 = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s4-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 2,
            hart_generation: 2,
            activation: 12,
            activation_generation: 3,
            note: "dispatch activation 12 on hart1".to_string(),
        },
    ));
    assert_eq!(hart1.status, CommandStatus::Applied);
    assert_eq!(graph.harts()[0].current_activation, Some(11));
    assert_eq!(graph.harts()[1].current_activation, Some(12));
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s4_rejects_activation_current_on_another_hart() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.bind_hart_current_activation(1, 2, 11, 3, "dispatch hart0"));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s4-test",
        SemanticCommand::BindHartCurrentActivation {
            hart: 2,
            hart_generation: 2,
            activation: 11,
            activation_generation: 3,
            note: "must reject duplicate current activation".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation is already current on another hart".to_string());
    assert_eq!(duplicate.violations, expected);
    assert_eq!(graph.harts()[1].current_activation, None);
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s4_invariants_reject_duplicate_current_activation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "hart0-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.bind_hart_current_activation(1, 2, 11, 3, "dispatch hart0"));
    let mut duplicate = graph.harts()[0].clone();
    duplicate.id = 2;
    duplicate.hardware_id = 1;
    duplicate.label = "hart1-duplicate-current".to_string();
    duplicate.boot = false;
    graph.duplicate_hart_for_test(duplicate);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationCurrentOnMultipleHarts {
            activation: 11,
            first_hart: 1,
            second_hart: 2,
        })
    );
}

#[test]
fn smp_runtime_s5_records_ipi_event_between_hart_generations() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));

    let ipi = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s5-test",
        SemanticCommand::RecordIpiEvent {
            ipi: 21,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 2,
            kind: IpiEventKind::SchedulerKick,
            reason: "scheduler kick".to_string(),
            note: "hart0 kicks hart1".to_string(),
        },
    ));

    assert_eq!(ipi.status, CommandStatus::Applied);
    assert_eq!(graph.ipi_events().len(), 1);
    assert_eq!(graph.ipi_events()[0].source_hardware_hart, 0);
    assert_eq!(graph.ipi_events()[0].target_hardware_hart, 1);
    assert_eq!(graph.hart_event_attributions().len(), 6);
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.ipi_events()[0].recorded_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "IpiEventSourceRecorded"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.ipi_events()[0].recorded_at_event
            && record.hart == 2
            && record.hart_generation == 2
            && record.event_kind == "IpiEventTargetRecorded"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "IpiEventRecorded ipi=21 kind=scheduler-kick source_hart=1@2 target_hart=2@2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s5_rejects_stale_or_self_target_ipi_event() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s5-test",
        SemanticCommand::RecordIpiEvent {
            ipi: 21,
            source_hart: 1,
            source_hart_generation: 99,
            target_hart: 2,
            target_hart_generation: 2,
            kind: IpiEventKind::SchedulerKick,
            reason: "stale source".to_string(),
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("ipi source hart generation is missing or inactive".to_string());
    assert_eq!(stale.violations, expected);

    let self_target = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s5-test",
        SemanticCommand::RecordIpiEvent {
            ipi: 22,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 1,
            target_hart_generation: 2,
            kind: IpiEventKind::SchedulerKick,
            reason: "self target".to_string(),
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(self_target.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("ipi source and target harts must differ".to_string());
    assert_eq!(self_target.violations, expected);
    assert!(graph.ipi_events().is_empty());
}

#[test]
fn smp_runtime_s5_invariants_reject_bad_ipi_target_generation() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.record_ipi_event_with_id(
        21,
        1,
        2,
        2,
        2,
        IpiEventKind::SchedulerKick,
        "scheduler kick",
        "hart0 kicks hart1",
    ));

    graph.corrupt_ipi_event_target_generation_for_test(21, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IpiEventHartGenerationMismatch { ipi: 21, hart: 2 })
    );
}

#[test]
fn smp_runtime_s5_ipi_history_survives_later_hart_offline() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.record_ipi_event_with_id(
        21,
        1,
        2,
        2,
        2,
        IpiEventKind::SchedulerKick,
        "scheduler kick",
        "hart0 kicks hart1",
    ));
    assert!(graph.set_hart_state(2, 2, HartState::Offline, "parked", "offline after event"));

    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s5_invariants_require_source_and_target_attribution() {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.record_ipi_event_with_id(
        21,
        1,
        2,
        2,
        2,
        IpiEventKind::SchedulerKick,
        "scheduler kick",
        "hart0 kicks hart1",
    ));
    let event = graph.ipi_events()[0].recorded_at_event;
    graph.clear_hart_event_attributions_for_test();

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::IpiEventMissingHartEventAttribution { ipi: 21, event })
    );
}

fn s6_remote_preempt_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "created"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "idle"));
    graph.ensure_task(7, FrontendKind::LinuxElf, "remote-preempt-target");
    assert!(graph.create_runnable_queue_with_id(2, "hart1-rq"));
    assert!(graph.bind_runnable_queue_owner(2, 1, 2, 2, "hart1 owns queue"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(2, 11, 1));
    assert!(graph.dequeue_runnable_activation(2, 11));
    assert!(graph.bind_hart_current_activation(2, 2, 11, 3, "dispatch on hart1"));
    assert!(graph.record_ipi_event_with_id(
        21,
        1,
        2,
        2,
        3,
        IpiEventKind::SchedulerKick,
        "remote preempt",
        "hart0 requests hart1 preempt",
    ));
    graph
}

#[test]
fn smp_runtime_s6_remote_preempt_requeues_target_hart_activation() {
    let mut graph = s6_remote_preempt_graph();

    let remote = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s6-test",
        SemanticCommand::RemotePreemptActivation {
            remote_preempt: 31,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 3,
            activation: 11,
            activation_generation: 3,
            queue: 2,
            note: "remote preempt activation".to_string(),
        },
    ));

    assert_eq!(remote.status, CommandStatus::Applied);
    assert_eq!(graph.remote_preempts().len(), 1);
    assert_eq!(graph.remote_preempts()[0].ipi, 21);
    assert_eq!(graph.remote_preempts()[0].target_hart_generation_before, 3);
    assert_eq!(graph.remote_preempts()[0].target_hart_generation_after, 4);
    assert_eq!(graph.remote_preempts()[0].activation_generation_after, 4);
    let hart = graph
        .harts()
        .iter()
        .find(|hart| hart.id == 2)
        .expect("target hart");
    assert_eq!(hart.state, HartState::Idle);
    assert_eq!(hart.generation, 4);
    assert_eq!(hart.current_activation, None);
    let activation = graph
        .runtime_activations()
        .iter()
        .find(|activation| activation.id == 11)
        .expect("activation");
    assert_eq!(activation.state, RuntimeActivationState::Runnable);
    assert_eq!(activation.generation, 4);
    assert_eq!(activation.runnable_queue, Some(2));
    assert!(
        graph.runnable_queues()[0]
            .entries
            .iter()
            .any(|entry| entry.activation == 11 && entry.activation_generation == 4)
    );
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.remote_preempts()[0].preempted_at_event
            && record.hart == 1
            && record.event_kind == "RemotePreemptSourceRecorded"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.remote_preempts()[0].preempted_at_event
            && record.hart == 2
            && record.hart_generation == 4
            && record.event_kind == "RemotePreemptTargetRecorded"
    }));
    assert_eq!(
        graph.event_log_tail(3)[0].kind.summary(),
        "RemoteActivationPreempted remote_preempt=31 ipi=21@1 source_hart=1@2 target_hart=2@3->4 activation=11@3->4 queue=2@2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s6_rejects_stale_ipi_and_wrong_target_generation() {
    let mut graph = s6_remote_preempt_graph();

    let stale_ipi = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s6-test",
        SemanticCommand::RemotePreemptActivation {
            remote_preempt: 31,
            ipi: 21,
            ipi_generation: 99,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 3,
            activation: 11,
            activation_generation: 3,
            queue: 2,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale_ipi.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote preempt ipi generation is missing".to_string());
    assert_eq!(stale_ipi.violations, expected);

    let wrong_target = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s6-test",
        SemanticCommand::RemotePreemptActivation {
            remote_preempt: 32,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 2,
            activation: 11,
            activation_generation: 3,
            queue: 2,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(wrong_target.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote preempt target hart generation is missing".to_string());
    assert_eq!(wrong_target.violations, expected);
    assert!(graph.remote_preempts().is_empty());
}

#[test]
fn smp_runtime_s6_rejects_queue_not_owned_by_target_hart() {
    let mut graph = s6_remote_preempt_graph();
    assert!(graph.create_runnable_queue_with_id(3, "wrong-rq"));
    assert!(graph.bind_runnable_queue_owner(3, 1, 1, 2, "hart0 owns wrong queue"));

    let remote = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s6-test",
        SemanticCommand::RemotePreemptActivation {
            remote_preempt: 31,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 3,
            activation: 11,
            activation_generation: 3,
            queue: 3,
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(remote.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote preempt queue is not owned by target hart".to_string());
    assert_eq!(remote.violations, expected);
}

#[test]
fn smp_runtime_s6_invariants_reject_remote_preempt_ipi_generation_leak() {
    let mut graph = s6_remote_preempt_graph();
    assert!(graph.remote_preempt_activation_with_id(
        31,
        21,
        1,
        1,
        2,
        2,
        3,
        11,
        3,
        2,
        "remote preempt activation",
    ));
    graph.corrupt_remote_preempt_ipi_generation_for_test(31, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RemotePreemptMissingIpi {
            remote_preempt: 31,
            ipi: 21,
        })
    );
}

#[test]
fn smp_runtime_s6_history_still_requires_event_after_activation_advances() {
    let mut graph = s6_remote_preempt_graph();
    assert!(graph.remote_preempt_activation_with_id(
        31,
        21,
        1,
        1,
        2,
        2,
        3,
        11,
        3,
        2,
        "remote preempt activation",
    ));
    assert!(graph.dequeue_runnable_activation(2, 11));
    graph.corrupt_remote_preempt_event_for_test(31, 999);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RemotePreemptMissingEvent { remote_preempt: 31 })
    );
}

fn s7_remote_park_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "hart0", true, "boot hart"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "hart0 idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "secondary hart"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "ready", "hart1 idle"));
    assert!(graph.record_ipi_event_with_id(
        21,
        1,
        2,
        2,
        2,
        IpiEventKind::SchedulerKick,
        "remote-park-request",
        "park target hart",
    ));
    graph
}

#[test]
fn smp_runtime_s7_remote_park_parks_idle_target_hart() {
    let mut graph = s7_remote_park_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s7-test",
        SemanticCommand::RemoteParkHart {
            remote_park: 31,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 2,
            reason: "remote-maintenance".to_string(),
            note: "park secondary hart".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.remote_parks().len(), 1);
    assert_eq!(graph.remote_parks()[0].ipi, 21);
    assert_eq!(graph.remote_parks()[0].target_hart_generation_before, 2);
    assert_eq!(graph.remote_parks()[0].target_hart_generation_after, 3);
    let target = graph.harts().iter().find(|hart| hart.id == 2).unwrap();
    assert_eq!(target.state, HartState::Parked);
    assert_eq!(target.generation, 3);
    assert!(target.current_activation.is_none());
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.remote_parks()[0].parked_at_event
            && record.hart == 1
            && record.event_kind == "RemoteParkSourceRecorded"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == graph.remote_parks()[0].parked_at_event
            && record.hart == 2
            && record.hart_generation == 3
            && record.event_kind == "RemoteParkTargetRecorded"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "RemoteHartParked remote_park=31 ipi=21@1 source_hart=1@2 target_hart=2@2->3 reason=remote-maintenance generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s7_rejects_stale_ipi_and_running_target_hart() {
    let mut graph = s7_remote_park_graph();
    let stale_ipi = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s7-test",
        SemanticCommand::RemoteParkHart {
            remote_park: 31,
            ipi: 21,
            ipi_generation: 99,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 2,
            reason: "remote-maintenance".to_string(),
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(stale_ipi.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote park ipi generation is missing".to_string());
    assert_eq!(stale_ipi.violations, expected);

    assert!(graph.set_hart_state(1, 2, HartState::Booting, "source bump", "advance source"));
    assert!(graph.set_hart_state(1, 3, HartState::Idle, "source ready", "source idle again"));
    let stale_source = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s7-test",
        SemanticCommand::RemoteParkHart {
            remote_park: 32,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 2,
            reason: "remote-maintenance".to_string(),
            note: "must reject stale source".to_string(),
        },
    ));
    assert_eq!(stale_source.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote park source hart generation is missing".to_string());
    assert_eq!(stale_source.violations, expected);

    let mut running = s6_remote_preempt_graph();
    let running_target = running.apply_envelope(CommandEnvelope::new(
        2,
        "s7-test",
        SemanticCommand::RemoteParkHart {
            remote_park: 31,
            ipi: 21,
            ipi_generation: 1,
            source_hart: 1,
            source_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 3,
            reason: "remote-maintenance".to_string(),
            note: "must reject".to_string(),
        },
    ));
    assert_eq!(running_target.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("remote park target hart is not idle".to_string());
    assert_eq!(running_target.violations, expected);
    assert!(graph.remote_parks().is_empty());
}

#[test]
fn smp_runtime_s7_invariants_reject_remote_park_ipi_generation_leak() {
    let mut graph = s7_remote_park_graph();
    assert!(graph.remote_park_hart_with_id(
        31,
        21,
        1,
        1,
        2,
        2,
        2,
        "remote-maintenance",
        "park secondary hart",
    ));
    graph.corrupt_remote_park_ipi_generation_for_test(31, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RemoteParkMissingIpi {
            remote_park: 31,
            ipi: 21,
        })
    );
}

#[test]
fn smp_runtime_s7_history_still_requires_event_after_hart_unparks() {
    let mut graph = s7_remote_park_graph();
    assert!(graph.remote_park_hart_with_id(
        31,
        21,
        1,
        1,
        2,
        2,
        2,
        "remote-maintenance",
        "park secondary hart",
    ));
    assert!(graph.set_hart_state(2, 3, HartState::Idle, "unpark", "later unpark"));
    graph.corrupt_remote_park_event_for_test(31, 999);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RemoteParkMissingEvent { remote_park: 31 })
    );
}

fn s8_cross_hart_decision_graph() -> SemanticGraph {
    let mut graph = s6_remote_preempt_graph();
    assert!(graph.remote_preempt_activation_with_id(
        31,
        21,
        1,
        1,
        2,
        2,
        3,
        11,
        3,
        2,
        "remote preempt activation",
    ));
    assert!(graph.record_scheduler_decision_with_id(
        41,
        2,
        2,
        11,
        4,
        "remote-runnable",
        "cross-hart base scheduler decision",
    ));
    graph
}

#[test]
fn smp_runtime_s8_cross_hart_scheduler_decision_records_remote_choice() {
    let mut graph = s8_cross_hart_decision_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s8-test",
        SemanticCommand::RecordCrossHartSchedulerDecision {
            cross_decision: 51,
            scheduler_decision: 41,
            scheduler_decision_generation: 1,
            deciding_hart: 1,
            deciding_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 4,
            reason: "remote-runnable-selected".to_string(),
            note: "hart0 selects hart1 queue".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.cross_hart_scheduler_decisions().len(), 1);
    let decision = &graph.cross_hart_scheduler_decisions()[0];
    assert_eq!(decision.scheduler_decision, 41);
    assert_eq!(decision.deciding_hart, 1);
    assert_eq!(decision.target_hart, 2);
    assert_eq!(decision.target_hart_generation, 4);
    assert_eq!(decision.queue, 2);
    assert_eq!(decision.queue_generation, 2);
    assert_eq!(decision.queue_owner_hart_generation, 2);
    assert_eq!(decision.selected_activation, 11);
    assert_eq!(decision.selected_activation_generation, 4);
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == decision.decided_at_event
            && record.hart == 1
            && record.event_kind == "CrossHartSchedulerDecisionSourceRecorded"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == decision.decided_at_event
            && record.hart == 2
            && record.hart_generation == 4
            && record.event_kind == "CrossHartSchedulerDecisionTargetRecorded"
            && record.activation == Some(11)
            && record.activation_generation == Some(4)
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "CrossHartSchedulerDecisionRecorded cross_decision=51 decision=41@1 deciding_hart=1@2 target_hart=2@4 queue=2@2 activation=11@4 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s8_rejects_stale_target_and_same_hart_decision() {
    let mut graph = s8_cross_hart_decision_graph();
    let stale_target = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s8-test",
        SemanticCommand::RecordCrossHartSchedulerDecision {
            cross_decision: 51,
            scheduler_decision: 41,
            scheduler_decision_generation: 1,
            deciding_hart: 1,
            deciding_hart_generation: 2,
            target_hart: 2,
            target_hart_generation: 3,
            reason: "remote-runnable-selected".to_string(),
            note: "must reject stale target".to_string(),
        },
    ));
    assert_eq!(stale_target.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("cross-hart scheduler decision target hart generation is missing".to_string());
    assert_eq!(stale_target.violations, expected);

    let same_hart = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s8-test",
        SemanticCommand::RecordCrossHartSchedulerDecision {
            cross_decision: 51,
            scheduler_decision: 41,
            scheduler_decision_generation: 1,
            deciding_hart: 2,
            deciding_hart_generation: 4,
            target_hart: 2,
            target_hart_generation: 4,
            reason: "remote-runnable-selected".to_string(),
            note: "must reject same hart".to_string(),
        },
    ));
    assert_eq!(same_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("cross-hart scheduler decision requires distinct harts".to_string());
    assert_eq!(same_hart.violations, expected);
    assert!(graph.cross_hart_scheduler_decisions().is_empty());
}

#[test]
fn smp_runtime_s8_history_still_requires_event_after_target_hart_advances() {
    let mut graph = s8_cross_hart_decision_graph();
    assert!(graph.record_cross_hart_scheduler_decision_with_id(
        51,
        41,
        1,
        1,
        2,
        2,
        4,
        "remote-runnable-selected",
        "hart0 selects hart1 queue",
    ));
    assert!(graph.set_hart_state(2, 4, HartState::Parked, "park after decision", "later park"));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_cross_hart_scheduler_decision_event_for_test(51, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::CrossHartSchedulerDecisionMissingEvent { cross_decision: 51 })
    );
}

fn s9_activation_migration_graph() -> SemanticGraph {
    let mut graph = s8_cross_hart_decision_graph();
    assert!(graph.create_runnable_queue_with_id(3, "hart0-migration-rq"));
    assert!(graph.bind_runnable_queue_owner(3, 1, 1, 2, "hart0 owns migration queue"));
    graph
}

#[test]
fn smp_runtime_s9_activation_migration_moves_runnable_between_hart_queues() {
    let mut graph = s9_activation_migration_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s9-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 61,
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
            reason: "rebalance".to_string(),
            note: "move runnable to hart0".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.activation_migrations().len(), 1);
    let migration = &graph.activation_migrations()[0];
    assert_eq!(migration.activation, 11);
    assert_eq!(migration.activation_generation_before, 4);
    assert_eq!(migration.activation_generation_after, 5);
    assert_eq!(migration.source_queue, 2);
    assert_eq!(migration.target_queue, 3);
    let activation = graph
        .runtime_activations()
        .iter()
        .find(|activation| activation.id == 11)
        .unwrap();
    assert_eq!(activation.generation, 5);
    assert_eq!(activation.runnable_queue, Some(3));
    let source_queue = graph
        .runnable_queues()
        .iter()
        .find(|queue| queue.id == 2 && queue.generation == 2)
        .unwrap();
    assert!(
        source_queue
            .entries
            .iter()
            .all(|entry| entry.activation != 11)
    );
    let target_queue = graph
        .runnable_queues()
        .iter()
        .find(|queue| queue.id == 3 && queue.generation == 2)
        .unwrap();
    assert!(
        target_queue
            .entries
            .iter()
            .any(|entry| entry.activation == 11 && entry.activation_generation == 5)
    );
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == migration.migrated_at_event
            && record.hart == 2
            && record.event_kind == "ActivationMigrationSourceRecorded"
            && record.activation_generation == Some(4)
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == migration.migrated_at_event
            && record.hart == 1
            && record.event_kind == "ActivationMigrationTargetRecorded"
            && record.activation_generation == Some(5)
    }));
    assert_eq!(
        graph.event_log_tail(3)[0].kind.summary(),
        "ActivationMigrated migration=61 activation=11@4->5 source_hart=2@4 target_hart=1@2 source_queue=2@2 target_queue=3@2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s9_rejects_stale_activation_and_wrong_target_queue_owner() {
    let mut graph = s9_activation_migration_graph();
    let stale_activation = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s9-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 61,
            activation: 11,
            activation_generation: 3,
            source_queue: 2,
            source_queue_generation: 2,
            target_queue: 3,
            target_queue_generation: 2,
            source_hart: 2,
            source_hart_generation: 4,
            target_hart: 1,
            target_hart_generation: 2,
            reason: "rebalance".to_string(),
            note: "must reject stale activation".to_string(),
        },
    ));
    assert_eq!(stale_activation.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation migration source queue entry is missing".to_string());
    assert_eq!(stale_activation.violations, expected);

    let same_hart = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s9-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 61,
            activation: 11,
            activation_generation: 4,
            source_queue: 2,
            source_queue_generation: 2,
            target_queue: 3,
            target_queue_generation: 2,
            source_hart: 2,
            source_hart_generation: 4,
            target_hart: 2,
            target_hart_generation: 4,
            reason: "rebalance".to_string(),
            note: "must reject wrong owner".to_string(),
        },
    ));
    assert_eq!(same_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation migration requires distinct harts".to_string());
    assert_eq!(same_hart.violations, expected);

    assert!(graph.create_runnable_queue_with_id(4, "wrong-target-owner-rq"));
    assert!(graph.bind_runnable_queue_owner(4, 1, 2, 4, "hart1 owns wrong target queue"));
    let wrong_owner = graph.apply_envelope(CommandEnvelope::new(
        3,
        "s9-test",
        SemanticCommand::MigrateRunnableActivation {
            migration: 62,
            activation: 11,
            activation_generation: 4,
            source_queue: 2,
            source_queue_generation: 2,
            target_queue: 4,
            target_queue_generation: 2,
            source_hart: 2,
            source_hart_generation: 4,
            target_hart: 1,
            target_hart_generation: 2,
            reason: "rebalance".to_string(),
            note: "must reject target queue owner mismatch".to_string(),
        },
    ));
    assert_eq!(wrong_owner.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation migration target queue owner mismatch".to_string());
    assert_eq!(wrong_owner.violations, expected);
    assert!(graph.activation_migrations().is_empty());
}

#[test]
fn smp_runtime_s9_history_still_requires_event_after_target_hart_advances() {
    let mut graph = s9_activation_migration_graph();
    assert!(graph.migrate_runnable_activation_with_id(
        61,
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
        "rebalance",
        "move runnable to hart0",
    ));
    assert!(graph.set_hart_state(1, 2, HartState::Booting, "target advances", "later state"));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_activation_migration_event_for_test(61, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationMigrationMissingEvent { migration: 61 })
    );
}

fn s10_smp_safe_point_graph() -> SemanticGraph {
    let mut graph = s9_activation_migration_graph();
    assert!(graph.migrate_runnable_activation_with_id(
        61,
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
        "rebalance",
        "move runnable to hart0",
    ));
    graph
}

#[test]
fn smp_runtime_s10_safe_point_records_quiesced_harts() {
    let mut graph = s10_smp_safe_point_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s10-test",
        SemanticCommand::RecordSmpSafePoint {
            safe_point: 71,
            coordinator_hart: 1,
            coordinator_hart_generation: 2,
            participants: vec![(1, 2), (2, 4)],
            reason: "quiescent-boundary".to_string(),
            note: "record all harts quiesced".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_safe_points().len(), 1);
    let safe_point = &graph.smp_safe_points()[0];
    assert_eq!(safe_point.coordinator_hart, 1);
    assert_eq!(safe_point.coordinator_hart_generation, 2);
    assert_eq!(safe_point.participants.len(), 2);
    assert!(safe_point.participants.iter().all(|participant| matches!(
        participant.hart_state,
        HartState::Idle | HartState::Parked
    )
        && participant.current_activation.is_none()));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == safe_point.recorded_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "SmpSafePointCoordinatorRecorded"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == safe_point.recorded_at_event
            && record.hart == 2
            && record.hart_generation == 4
            && record.event_kind == "SmpSafePointParticipantRecorded"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SmpSafePointRecorded safe_point=71 coordinator_hart=1@2 participants=2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s10_rejects_stale_participant_and_running_hart() {
    let mut graph = s10_smp_safe_point_graph();
    let stale_participant = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s10-test",
        SemanticCommand::RecordSmpSafePoint {
            safe_point: 71,
            coordinator_hart: 1,
            coordinator_hart_generation: 2,
            participants: vec![(1, 2), (2, 3)],
            reason: "quiescent-boundary".to_string(),
            note: "must reject stale hart generation".to_string(),
        },
    ));
    assert_eq!(stale_participant.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp safe point participant hart generation is missing".to_string());
    assert_eq!(stale_participant.violations, expected);

    let mut running = s6_remote_preempt_graph();
    let running_participant = running.apply_envelope(CommandEnvelope::new(
        2,
        "s10-test",
        SemanticCommand::RecordSmpSafePoint {
            safe_point: 71,
            coordinator_hart: 1,
            coordinator_hart_generation: 2,
            participants: vec![(1, 2), (2, 3)],
            reason: "quiescent-boundary".to_string(),
            note: "must reject running hart".to_string(),
        },
    ));
    assert_eq!(running_participant.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp safe point participant is not quiesced".to_string());
    assert_eq!(running_participant.violations, expected);
    assert!(running.smp_safe_points().is_empty());

    let mut missing = s10_smp_safe_point_graph();
    assert!(missing.register_hart_with_id(3, 2, "hart2", false, "created"));
    assert!(missing.set_hart_state(3, 1, HartState::Idle, "ready", "idle"));
    let missing_active_hart = missing.apply_envelope(CommandEnvelope::new(
        3,
        "s10-test",
        SemanticCommand::RecordSmpSafePoint {
            safe_point: 71,
            coordinator_hart: 1,
            coordinator_hart_generation: 2,
            participants: vec![(1, 2), (2, 4)],
            reason: "quiescent-boundary".to_string(),
            note: "must reject partial safe point".to_string(),
        },
    ));
    assert_eq!(missing_active_hart.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp safe point missing active hart".to_string());
    assert_eq!(missing_active_hart.violations, expected);
    assert!(missing.smp_safe_points().is_empty());
    assert!(graph.smp_safe_points().is_empty());
}

#[test]
fn smp_runtime_s10_history_survives_later_hart_transition() {
    let mut graph = s10_smp_safe_point_graph();
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 4)],
        "quiescent-boundary",
        "record all harts quiesced",
    ));
    assert!(graph.set_hart_state(
        1,
        2,
        HartState::Booting,
        "advance after safe point",
        "later"
    ));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_smp_safe_point_event_for_test(71, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpSafePointMissingEvent { safe_point: 71 })
    );
}

fn s11_stop_the_world_graph() -> SemanticGraph {
    let mut graph = s10_smp_safe_point_graph();
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 4)],
        "quiescent-boundary",
        "record all harts quiesced",
    ));
    graph
}

#[test]
fn smp_runtime_s11_stop_the_world_rendezvous_completes_from_safe_point() {
    let mut graph = s11_stop_the_world_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s11-test",
        SemanticCommand::CompleteStopTheWorldRendezvous {
            rendezvous: 81,
            epoch: 1,
            safe_point: 71,
            safe_point_generation: 1,
            stop_new_activations: true,
            reason: "code-publish-boundary".to_string(),
            note: "all harts parked at activation boundary".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.stop_the_world_rendezvous().len(), 1);
    let rendezvous = &graph.stop_the_world_rendezvous()[0];
    assert_eq!(rendezvous.epoch, 1);
    assert_eq!(rendezvous.safe_point, 71);
    assert_eq!(rendezvous.safe_point_generation, 1);
    assert!(rendezvous.stop_new_activations);
    assert_eq!(rendezvous.coordinator_hart, 1);
    assert_eq!(rendezvous.coordinator_hart_generation, 2);
    assert_eq!(rendezvous.participants.len(), 2);
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == rendezvous.completed_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "StopTheWorldHartParked"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == rendezvous.completed_at_event
            && record.hart == 2
            && record.hart_generation == 4
            && record.event_kind == "StopTheWorldHartParked"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "StopTheWorldRendezvousCompleted rendezvous=81 epoch=1 safe_point=71@1 coordinator_hart=1@2 participants=2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s11_rejects_missing_stop_flag_stale_safe_point_and_hart() {
    let mut graph = s11_stop_the_world_graph();
    let missing_stop = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s11-test",
        SemanticCommand::CompleteStopTheWorldRendezvous {
            rendezvous: 81,
            epoch: 1,
            safe_point: 71,
            safe_point_generation: 1,
            stop_new_activations: false,
            reason: "code-publish-boundary".to_string(),
            note: "must stop new activations".to_string(),
        },
    ));
    assert_eq!(missing_stop.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("stop-the-world rendezvous must stop new activations".to_string());
    assert_eq!(missing_stop.violations, expected);
    assert!(graph.stop_the_world_rendezvous().is_empty());

    let stale_safe_point = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s11-test",
        SemanticCommand::CompleteStopTheWorldRendezvous {
            rendezvous: 81,
            epoch: 1,
            safe_point: 71,
            safe_point_generation: 2,
            stop_new_activations: true,
            reason: "code-publish-boundary".to_string(),
            note: "must reject stale safe point generation".to_string(),
        },
    ));
    assert_eq!(stale_safe_point.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("stop-the-world rendezvous safe point is missing".to_string());
    assert_eq!(stale_safe_point.violations, expected);
    assert!(graph.stop_the_world_rendezvous().is_empty());

    let mut stale_hart = s11_stop_the_world_graph();
    assert!(stale_hart.set_hart_state(
        1,
        2,
        HartState::Booting,
        "advance before rendezvous",
        "not parked"
    ));
    let stale_participant = stale_hart.apply_envelope(CommandEnvelope::new(
        3,
        "s11-test",
        SemanticCommand::CompleteStopTheWorldRendezvous {
            rendezvous: 81,
            epoch: 1,
            safe_point: 71,
            safe_point_generation: 1,
            stop_new_activations: true,
            reason: "code-publish-boundary".to_string(),
            note: "safe point no longer covers current hart".to_string(),
        },
    ));
    assert_eq!(stale_participant.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("stop-the-world rendezvous participant generation is stale".to_string());
    assert_eq!(stale_participant.violations, expected);
    assert!(stale_hart.stop_the_world_rendezvous().is_empty());
}

#[test]
fn smp_runtime_s11_history_survives_later_hart_transition() {
    let mut graph = s11_stop_the_world_graph();
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        1,
        71,
        1,
        true,
        "code-publish-boundary",
        "all harts parked at activation boundary",
    ));
    assert!(graph.set_hart_state(
        2,
        4,
        HartState::Booting,
        "advance after rendezvous",
        "later"
    ));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_stop_the_world_event_for_test(81, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::StopTheWorldRendezvousMissingEvent { rendezvous: 81 })
    );
}

fn s12_smp_code_publish_barrier_graph() -> SemanticGraph {
    let mut graph = s11_stop_the_world_graph();
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        1,
        71,
        1,
        true,
        "code-publish-boundary",
        "all harts parked at activation boundary",
    ));
    graph
}

#[test]
fn smp_runtime_s12_code_publish_barrier_validates_from_rendezvous() {
    let mut graph = s12_smp_code_publish_barrier_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s12-test",
        SemanticCommand::ValidateSmpCodePublishBarrier {
            barrier: 91,
            rendezvous: 81,
            rendezvous_generation: 1,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: true,
            code_publish_executed: false,
            reason: "semantic-code-publish-barrier".to_string(),
            note: "validate remote icache sync evidence only".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_code_publish_barriers().len(), 1);
    let barrier = &graph.smp_code_publish_barriers()[0];
    assert_eq!(barrier.rendezvous, 81);
    assert_eq!(barrier.rendezvous_generation, 1);
    assert_eq!(barrier.rendezvous_epoch, 1);
    assert_eq!(barrier.code_publish_epoch_before, 0);
    assert_eq!(barrier.code_publish_epoch_after, 1);
    assert!(barrier.remote_icache_sync_required);
    assert!(!barrier.code_publish_executed);
    assert_eq!(barrier.participants.len(), 2);
    assert!(
        barrier
            .participants
            .iter()
            .all(|participant| participant.semantic_icache_sync
                && participant.last_seen_code_epoch_before == 0
                && participant.last_seen_code_epoch_after == 1)
    );
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == barrier.validated_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "SmpCodePublishBarrierHartSynced"
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == barrier.validated_at_event
            && record.hart == 2
            && record.hart_generation == 4
            && record.event_kind == "SmpCodePublishBarrierHartSynced"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SmpCodePublishBarrierValidated barrier=91 rendezvous=81@1 code_publish_epoch=0->1 participants=2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s12_rejects_bad_barrier_inputs() {
    let mut stale_rendezvous = s12_smp_code_publish_barrier_graph();
    let stale = stale_rendezvous.apply_envelope(CommandEnvelope::new(
        1,
        "s12-test",
        SemanticCommand::ValidateSmpCodePublishBarrier {
            barrier: 91,
            rendezvous: 81,
            rendezvous_generation: 2,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: true,
            code_publish_executed: false,
            reason: "semantic-code-publish-barrier".to_string(),
            note: "must reject stale rendezvous".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp code publish barrier rendezvous is missing".to_string());
    assert_eq!(stale.violations, expected);

    let mut missing_sync = s12_smp_code_publish_barrier_graph();
    let missing_sync_result = missing_sync.apply_envelope(CommandEnvelope::new(
        2,
        "s12-test",
        SemanticCommand::ValidateSmpCodePublishBarrier {
            barrier: 91,
            rendezvous: 81,
            rendezvous_generation: 1,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: false,
            code_publish_executed: false,
            reason: "semantic-code-publish-barrier".to_string(),
            note: "must require remote sync".to_string(),
        },
    ));
    assert_eq!(missing_sync_result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp code publish barrier requires remote icache sync".to_string());
    assert_eq!(missing_sync_result.violations, expected);

    let mut real_publish = s12_smp_code_publish_barrier_graph();
    let real_publish_result = real_publish.apply_envelope(CommandEnvelope::new(
        3,
        "s12-test",
        SemanticCommand::ValidateSmpCodePublishBarrier {
            barrier: 91,
            rendezvous: 81,
            rendezvous_generation: 1,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: true,
            code_publish_executed: true,
            reason: "semantic-code-publish-barrier".to_string(),
            note: "must not execute real publish in s12".to_string(),
        },
    ));
    assert_eq!(real_publish_result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp code publish barrier must not execute code publish".to_string());
    assert_eq!(real_publish_result.violations, expected);

    let mut stale_hart = s12_smp_code_publish_barrier_graph();
    assert!(stale_hart.set_hart_state(
        2,
        4,
        HartState::Booting,
        "advance before publish barrier",
        "not parked"
    ));
    let stale_hart_result = stale_hart.apply_envelope(CommandEnvelope::new(
        4,
        "s12-test",
        SemanticCommand::ValidateSmpCodePublishBarrier {
            barrier: 91,
            rendezvous: 81,
            rendezvous_generation: 1,
            code_publish_epoch_before: 0,
            code_publish_epoch_after: 1,
            remote_icache_sync_required: true,
            code_publish_executed: false,
            reason: "semantic-code-publish-barrier".to_string(),
            note: "must reject stale participant generation".to_string(),
        },
    ));
    assert_eq!(stale_hart_result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp code publish barrier participant generation is stale".to_string());
    assert_eq!(stale_hart_result.violations, expected);
}

#[test]
fn smp_runtime_s12_history_survives_later_hart_transition() {
    let mut graph = s12_smp_code_publish_barrier_graph();
    assert!(graph.validate_smp_code_publish_barrier_with_id(
        91,
        81,
        1,
        0,
        1,
        true,
        false,
        "semantic-code-publish-barrier",
        "validate remote icache sync evidence only",
    ));
    assert!(graph.set_hart_state(
        1,
        2,
        HartState::Booting,
        "advance after publish barrier",
        "later"
    ));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_smp_code_publish_barrier_event_for_test(91, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpCodePublishBarrierMissingEvent { barrier: 91 })
    );
}

#[test]
fn preemptive_runtime_p0_queue_commands_emit_events_and_pass_invariants() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");

    let queue = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p0-test",
        SemanticCommand::CreateRunnableQueue {
            queue: 1,
            label: "main-rq".to_string(),
        },
    ));
    assert_eq!(queue.status, CommandStatus::Applied);

    let activation = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p0-test",
        SemanticCommand::CreateRuntimeActivation {
            activation: 11,
            owner_task: 7,
            owner_task_generation: 1,
            owner_store: None,
            owner_store_generation: None,
            code_object: Some(ContractObjectRef::new(ContractObjectKind::CodeObject, 3, 1)),
        },
    ));
    assert_eq!(activation.status, CommandStatus::Applied);
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Created
    );

    let enqueue = graph.apply_envelope(CommandEnvelope::new(
        3,
        "p0-test",
        SemanticCommand::EnqueueRunnable {
            queue: 1,
            activation: 11,
            activation_generation: 1,
        },
    ));
    assert_eq!(enqueue.status, CommandStatus::Applied);
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Runnable
    );
    assert_eq!(graph.runtime_activations()[0].generation, 2);
    assert_eq!(graph.runnable_queues()[0].entries[0].activation, 11);
    assert_eq!(
        graph.runnable_queues()[0].entries[0].activation_generation,
        2
    );

    let dequeue = graph.apply_envelope(CommandEnvelope::new(
        4,
        "p0-test",
        SemanticCommand::DequeueRunnable {
            queue: 1,
            activation: 11,
        },
    ));
    assert_eq!(dequeue.status, CommandStatus::Applied);
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Running
    );
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert_eq!(graph.check_invariants(), Ok(()));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "RuntimeActivationStateChanged activation=11 runnable->running generation=3"
    );
}

#[test]
fn preemptive_runtime_p0_rejects_pending_task_and_stale_generation_enqueue() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p0-test",
        SemanticCommand::EnqueueRunnable {
            queue: 1,
            activation: 11,
            activation_generation: 99,
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation generation mismatch".to_string());
    assert_eq!(stale.violations, expected);
    assert!(graph.runnable_queues()[0].entries.is_empty());

    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    graph.record_wait_created_with_details(
        42,
        Some(7),
        None,
        None,
        SemanticWaitKind::Timer,
        1,
        Vec::new(),
        Some(10),
        RestartPolicy::RestartIfAllowed,
        None,
    );
    let task_generation = graph.tasks()[0].generation;
    assert!(graph.create_runtime_activation_with_id(11, 7, task_generation, None, None, None));
    let pending = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p0-test",
        SemanticCommand::EnqueueRunnable {
            queue: 1,
            activation: 11,
            activation_generation: 1,
        },
    ));
    assert_eq!(pending.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("pending wait task cannot be enqueued".to_string());
    assert_eq!(pending.violations, expected);
    assert!(graph.runnable_queues()[0].entries.is_empty());
}

#[test]
fn preemptive_runtime_p0_rejects_duplicate_queue_and_generationless_store_owner() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    let store = graph.register_store("sched-store", "sched-artifact", "service", "restartable");
    assert!(!graph.create_runtime_activation_with_id(9, 7, 1, Some(store), None, None));

    let missing_generation = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p0-test",
        SemanticCommand::CreateRuntimeActivation {
            activation: 9,
            owner_task: 7,
            owner_task_generation: 1,
            owner_store: Some(store),
            owner_store_generation: None,
            code_object: None,
        },
    ));
    assert_eq!(missing_generation.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation owner store generation is required".to_string());
    assert_eq!(missing_generation.violations, expected);

    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runnable_queue_with_id(2, "backup-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p0-test",
        SemanticCommand::EnqueueRunnable {
            queue: 2,
            activation: 11,
            activation_generation: 2,
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation already queued".to_string());
    assert_eq!(duplicate.violations, expected);
    assert!(graph.runnable_queues()[1].entries.is_empty());
    assert_eq!(graph.check_invariants(), Ok(()));
}

#[test]
fn preemptive_runtime_p0_invariants_reject_bad_queue_ownership() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    graph.clear_runtime_activation_queue_for_test(11);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::RunnableQueueOwnershipMismatch {
            queue: 1,
            activation: 11,
        })
    );
}

#[test]
fn preemptive_runtime_p1_context_commands_emit_events_and_pass_invariants() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));

    let context = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p1-test",
        SemanticCommand::CreateActivationContext {
            context: 12,
            activation: 11,
            activation_generation: 2,
        },
    ));
    assert_eq!(context.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].generation, 1);
    assert_eq!(
        graph.activation_contexts()[0].state,
        ActivationContextState::Created
    );

    let saved = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p1-test",
        SemanticCommand::CaptureSavedContext {
            saved_context: 13,
            context: 12,
            context_generation: 1,
            reason: SavedContextReason::Initial,
            pc: 0x1000,
            sp: 0x8000,
            flags: 0,
            note: "initial frame".to_string(),
        },
    ));
    assert_eq!(saved.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].generation, 2);
    assert_eq!(
        graph.activation_contexts()[0].state,
        ActivationContextState::Saved
    );
    assert_eq!(graph.saved_contexts()[0].context_generation, 2);
    assert_eq!(graph.saved_contexts()[0].pc, 0x1000);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SavedContextCaptured saved_context=13 context=12@2 activation=11@2 reason=initial generation=1"
    );
}

#[test]
fn preemptive_runtime_p1_rejects_stale_context_generation_and_empty_frame() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.create_activation_context_with_id(12, 11, 1));

    let empty_frame = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p1-test",
        SemanticCommand::CaptureSavedContext {
            saved_context: 13,
            context: 12,
            context_generation: 1,
            reason: SavedContextReason::Initial,
            pc: 0,
            sp: 0x8000,
            flags: 0,
            note: "bad frame".to_string(),
        },
    ));
    assert_eq!(empty_frame.status, CommandStatus::Rejected);
    assert!(graph.saved_contexts().is_empty());

    assert!(graph.capture_saved_context_with_id(
        13,
        12,
        1,
        SavedContextReason::Initial,
        0x1000,
        0x8000,
        0,
        "initial frame",
    ));
    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p1-test",
        SemanticCommand::CaptureSavedContext {
            saved_context: 14,
            context: 12,
            context_generation: 1,
            reason: SavedContextReason::CooperativeYield,
            pc: 0x1004,
            sp: 0x7ff0,
            flags: 0,
            note: "stale frame".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation context generation is missing or dropped".to_string());
    assert_eq!(stale.violations, expected);

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "p1-test",
        SemanticCommand::CaptureSavedContext {
            saved_context: 14,
            context: 12,
            context_generation: 2,
            reason: SavedContextReason::CooperativeYield,
            pc: 0x1004,
            sp: 0x7ff0,
            flags: 0,
            note: "duplicate frame".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation context already has saved context".to_string());
    assert_eq!(duplicate.violations, expected);
    assert_eq!(graph.saved_contexts().len(), 1);
}

#[test]
fn preemptive_runtime_p1_invariants_reject_context_saved_generation_leak() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.create_activation_context_with_id(12, 11, 1));
    assert!(graph.capture_saved_context_with_id(
        13,
        12,
        1,
        SavedContextReason::Initial,
        0x1000,
        0x8000,
        0,
        "initial frame",
    ));
    graph.clear_activation_context_saved_ref_for_test(12);

    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::ActivationContextSavedGenerationMissing {
                context: 12,
                saved_context: 13,
            }
        )
    );
}

fn register_idle_test_hart(graph: &mut SemanticGraph) -> Generation {
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "boot"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "ready", "idle"));
    2
}

#[test]
fn preemptive_runtime_p2_timer_interrupt_records_event_and_passes_invariants() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));

    let timer = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p2-test",
        SemanticCommand::RecordTimerInterrupt {
            interrupt: 5,
            timer_epoch: 1,
            hart: 1,
            hart_generation,
            target_activation: Some(11),
            target_activation_generation: Some(3),
            note: "timer tick".to_string(),
        },
    ));
    assert_eq!(timer.status, CommandStatus::Applied);
    assert_eq!(graph.timer_interrupts()[0].timer_epoch, 1);
    assert_eq!(graph.timer_interrupts()[0].hart, 1);
    assert_eq!(graph.timer_interrupts()[0].hart_generation, 2);
    assert_eq!(graph.timer_interrupts()[0].hardware_hart, 0);
    assert_eq!(graph.hart_event_attributions().len(), 3);
    assert_eq!(graph.timer_epoch(), 1);
    assert_eq!(graph.timer_interrupts()[0].target_task, Some(7));
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "TimerInterruptRecorded interrupt=5 epoch=1 hart=1@2 hardware_id=0 target=11@3 generation=1"
    );
}

#[test]
fn preemptive_runtime_p2_rejects_stale_target_and_non_monotonic_epoch() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p2-test",
        SemanticCommand::RecordTimerInterrupt {
            interrupt: 5,
            timer_epoch: 1,
            hart: 1,
            hart_generation,
            target_activation: Some(11),
            target_activation_generation: Some(99),
            note: "stale target".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert!(graph.timer_interrupts().is_empty());

    assert!(graph.record_timer_interrupt_with_id(
        5,
        1,
        1,
        hart_generation,
        Some(11),
        Some(1),
        "first tick"
    ));
    assert!(graph.record_timer_interrupt_with_id(
        6,
        3,
        1,
        hart_generation,
        Some(11),
        Some(1),
        "third tick"
    ));
    let non_monotonic = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p2-test",
        SemanticCommand::RecordTimerInterrupt {
            interrupt: 7,
            timer_epoch: 2,
            hart: 1,
            hart_generation,
            target_activation: Some(11),
            target_activation_generation: Some(1),
            note: "old epoch".to_string(),
        },
    ));
    assert_eq!(non_monotonic.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("timer interrupt epoch must be monotonic".to_string());
    assert_eq!(non_monotonic.violations, expected);
}

#[test]
fn preemptive_runtime_p2_invariants_reject_timer_epoch_regression() {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.record_timer_interrupt_with_id(
        5,
        1,
        1,
        hart_generation,
        Some(11),
        Some(1),
        "first tick"
    ));
    assert!(graph.record_timer_interrupt_with_id(
        6,
        2,
        1,
        hart_generation,
        Some(11),
        Some(1),
        "second tick"
    ));
    graph.corrupt_timer_interrupt_epoch_for_test(6, 1);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::TimerInterruptEpochNonMonotonic {
            interrupt: 6,
            timer_epoch: 1,
        })
    );
}

fn p3_running_activation_with_timer() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    let hart_generation = register_idle_test_hart(&mut graph);
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.record_timer_interrupt_with_id(
        5,
        1,
        1,
        hart_generation,
        Some(11),
        Some(3),
        "timer tick"
    ));
    graph
}

#[test]
fn preemptive_runtime_p3_preempt_activation_requeues_running_activation() {
    let mut graph = p3_running_activation_with_timer();

    let preempt = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p3-test",
        SemanticCommand::PreemptActivation {
            preemption: 6,
            activation: 11,
            activation_generation: 3,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            queue: 1,
            note: "timer preempt".to_string(),
        },
    ));
    assert_eq!(preempt.status, CommandStatus::Applied);
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Runnable
    );
    assert_eq!(graph.runtime_activations()[0].generation, 4);
    assert_eq!(graph.runnable_queues()[0].entries[0].activation, 11);
    assert_eq!(
        graph.runnable_queues()[0].entries[0].activation_generation,
        4
    );
    assert_eq!(graph.preemptions()[0].activation_generation_before, 3);
    assert_eq!(graph.preemptions()[0].activation_generation_after, 4);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(3)[0].kind.summary(),
        "RuntimeActivationPreempted preemption=6 activation=11@3->4 timer=5@1 queue=1@1 generation=1"
    );
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Running
    );
    assert_eq!(graph.runtime_activations()[0].generation, 5);
    assert!(
        graph.check_invariants().is_ok(),
        "preemption history must survive later activation generation advance"
    );
}

#[test]
fn preemptive_runtime_p3_rejects_stale_or_mismatched_preemptions() {
    let mut graph = p3_running_activation_with_timer();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p3-test",
        SemanticCommand::PreemptActivation {
            preemption: 6,
            activation: 11,
            activation_generation: 2,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            queue: 1,
            note: "stale".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption timer target does not match activation generation".to_string());
    assert_eq!(stale.violations, expected);
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Running
    );

    let missing_timer = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p3-test",
        SemanticCommand::PreemptActivation {
            preemption: 7,
            activation: 11,
            activation_generation: 3,
            timer_interrupt: 99,
            timer_interrupt_generation: 1,
            queue: 1,
            note: "missing timer".to_string(),
        },
    ));
    assert_eq!(missing_timer.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption timer interrupt generation is missing".to_string());
    assert_eq!(missing_timer.violations, expected);
}

#[test]
fn preemptive_runtime_p3_invariants_reject_preemption_timer_generation_leak() {
    let mut graph = p3_running_activation_with_timer();
    assert!(graph.preempt_running_activation_with_id(6, 11, 3, 5, 1, 1, "timer preempt"));
    graph.corrupt_preemption_timer_generation_for_test(6, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PreemptionMissingTimerInterrupt {
            preemption: 6,
            interrupt: 5,
        })
    );
}

fn p4_preempted_activation() -> SemanticGraph {
    let mut graph = p3_running_activation_with_timer();
    assert!(graph.preempt_running_activation_with_id(6, 11, 3, 5, 1, 1, "timer preempt"));
    graph
}

#[test]
fn preemptive_runtime_p4_save_preempted_context_captures_timer_frame() {
    let mut graph = p4_preempted_activation();

    let save = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p4-test",
        SemanticCommand::SavePreemptedContext {
            context: 12,
            saved_context: 13,
            preemption: 6,
            preemption_generation: 1,
            pc: 0x2000,
            sp: 0x9000,
            flags: 0,
            note: "timer frame".to_string(),
        },
    ));
    assert_eq!(save.status, CommandStatus::Applied);
    assert_eq!(graph.activation_contexts()[0].activation, 11);
    assert_eq!(graph.activation_contexts()[0].activation_generation, 4);
    assert_eq!(graph.activation_contexts()[0].generation, 2);
    assert_eq!(
        graph.saved_contexts()[0].reason,
        SavedContextReason::TimerPreempt
    );
    assert_eq!(graph.saved_contexts()[0].pc, 0x2000);
    assert_eq!(graph.saved_contexts()[0].sp, 0x9000);
    assert_eq!(graph.saved_contexts()[0].source_preemption, Some(6));
    assert_eq!(
        graph.saved_contexts()[0].source_preemption_generation,
        Some(1)
    );
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SavedContextCaptured saved_context=13 context=12@2 activation=11@4 reason=timer-preempt generation=1"
    );
}

#[test]
fn preemptive_runtime_p4_rejects_missing_preemption_and_empty_frame() {
    let mut graph = p4_preempted_activation();
    let missing = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p4-test",
        SemanticCommand::SavePreemptedContext {
            context: 12,
            saved_context: 13,
            preemption: 99,
            preemption_generation: 1,
            pc: 0x2000,
            sp: 0x9000,
            flags: 0,
            note: "missing".to_string(),
        },
    ));
    assert_eq!(missing.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption generation is missing".to_string());
    assert_eq!(missing.violations, expected);
    assert!(graph.activation_contexts().is_empty());
    assert!(graph.saved_contexts().is_empty());

    let empty_frame = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p4-test",
        SemanticCommand::SavePreemptedContext {
            context: 12,
            saved_context: 13,
            preemption: 6,
            preemption_generation: 1,
            pc: 0,
            sp: 0x9000,
            flags: 0,
            note: "empty".to_string(),
        },
    ));
    assert_eq!(empty_frame.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preempted context requires nonzero pc and sp".to_string());
    assert_eq!(empty_frame.violations, expected);
}

#[test]
fn preemptive_runtime_p4_invariants_reject_saved_context_preemption_generation_leak() {
    let mut graph = p4_preempted_activation();
    assert!(graph.save_preempted_context_with_ids(12, 13, 6, 1, 0x2000, 0x9000, 0, "timer"));
    graph.clear_saved_context_source_preemption_generation_for_test(13);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SavedContextMissingPreemptionGeneration { saved_context: 13 })
    );
}

fn p5_preempted_activation_with_saved_context() -> SemanticGraph {
    let mut graph = p4_preempted_activation();
    assert!(graph.save_preempted_context_with_ids(12, 13, 6, 1, 0x2000, 0x9000, 0, "timer"));
    graph
}

#[test]
fn preemptive_runtime_p5_scheduler_decision_records_runnable_choice() {
    let mut graph = p5_preempted_activation_with_saved_context();

    let decision = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p5-test",
        SemanticCommand::RecordSchedulerDecision {
            decision: 14,
            queue: 1,
            queue_generation: 1,
            selected_activation: 11,
            selected_activation_generation: 4,
            reason: "runnable-available".to_string(),
            note: "choose preempted activation".to_string(),
        },
    ));
    assert_eq!(decision.status, CommandStatus::Applied);
    assert_eq!(graph.scheduler_decisions().len(), 1);
    assert_eq!(
        graph.scheduler_decisions()[0].state,
        SchedulerDecisionState::Recorded
    );
    assert_eq!(graph.scheduler_decisions()[0].selected_activation, 11);
    assert_eq!(
        graph.scheduler_decisions()[0].selected_activation_generation,
        4
    );
    assert_eq!(graph.scheduler_decisions()[0].owner_task, 7);
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Runnable
    );
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SchedulerDecisionRecorded decision=14 queue=1@1 activation=11@4 generation=1"
    );
}

#[test]
fn preemptive_runtime_p5_scheduler_decision_is_historical_after_dequeue() {
    let mut graph = p4_preempted_activation();
    assert!(graph.record_scheduler_decision_with_id(
        14,
        1,
        1,
        11,
        4,
        "runnable-available",
        "choose"
    ));
    assert!(graph.dequeue_runnable_activation(1, 11));

    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Running
    );
    assert_eq!(graph.runtime_activations()[0].generation, 5);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert_eq!(graph.check_invariants(), Ok(()));
}

#[test]
fn preemptive_runtime_p5_rejects_unqueued_or_stale_decision() {
    let mut graph = p5_preempted_activation_with_saved_context();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p5-test",
        SemanticCommand::RecordSchedulerDecision {
            decision: 14,
            queue: 1,
            queue_generation: 1,
            selected_activation: 11,
            selected_activation_generation: 3,
            reason: "stale".to_string(),
            note: "stale activation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("scheduler decision activation is not queued".to_string());
    assert_eq!(stale.violations, expected);
    assert!(graph.scheduler_decisions().is_empty());

    let empty_reason = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p5-test",
        SemanticCommand::RecordSchedulerDecision {
            decision: 14,
            queue: 1,
            queue_generation: 1,
            selected_activation: 11,
            selected_activation_generation: 4,
            reason: "".to_string(),
            note: "empty reason".to_string(),
        },
    ));
    assert_eq!(empty_reason.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("scheduler decision reason is empty".to_string());
    assert_eq!(empty_reason.violations, expected);
}

#[test]
fn preemptive_runtime_p5_invariants_reject_decision_generation_leak() {
    let mut graph = p5_preempted_activation_with_saved_context();
    assert!(graph.record_scheduler_decision_with_id(
        14,
        1,
        1,
        11,
        4,
        "runnable-available",
        "choose"
    ));
    graph.corrupt_scheduler_decision_activation_generation_for_test(14, 3);

    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::SchedulerDecisionQueueEntryMismatch {
                decision: 14,
                activation: 11,
            }
        )
    );
}

fn p6_decided_preempted_activation() -> SemanticGraph {
    let mut graph = p5_preempted_activation_with_saved_context();
    assert!(graph.record_scheduler_decision_with_id(
        14,
        1,
        1,
        11,
        4,
        "runnable-available",
        "choose"
    ));
    graph
}

#[test]
fn preemptive_runtime_p6_resume_activation_consumes_decision_and_restores_context() {
    let mut graph = p6_decided_preempted_activation();

    let resume = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p6-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "resume selected activation".to_string(),
        },
    ));

    assert_eq!(resume.status, CommandStatus::Applied);
    assert_eq!(graph.activation_resumes().len(), 1);
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Running
    );
    assert_eq!(graph.runtime_activations()[0].generation, 5);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert_eq!(
        graph.scheduler_decisions()[0].state,
        SchedulerDecisionState::Superseded
    );
    assert_eq!(graph.activation_contexts()[0].generation, 3);
    assert_eq!(graph.activation_contexts()[0].activation_generation, 5);
    assert_eq!(
        graph.activation_contexts()[0].state,
        ActivationContextState::Current
    );
    assert!(
        graph.activation_contexts()[0]
            .current_saved_context
            .is_none()
    );
    assert_eq!(graph.saved_contexts()[0].generation, 2);
    assert_eq!(graph.saved_contexts()[0].state, SavedContextState::Restored);
    assert_eq!(graph.saved_contexts()[0].activation_generation, 4);
    assert_eq!(
        graph.activation_resumes()[0].activation_generation_before,
        4
    );
    assert_eq!(graph.activation_resumes()[0].activation_generation_after, 5);
    assert_eq!(graph.activation_resumes()[0].context, Some(12));
    assert_eq!(
        graph.activation_resumes()[0].context_generation_before,
        Some(2)
    );
    assert_eq!(
        graph.activation_resumes()[0].context_generation_after,
        Some(3)
    );
    assert_eq!(graph.activation_resumes()[0].saved_context, Some(13));
    assert_eq!(
        graph.activation_resumes()[0].saved_context_generation,
        Some(2)
    );
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "RuntimeActivationResumed resume=15 decision=14@1 activation=11@4->5 queue=1@1 generation=1"
    );
}

#[test]
fn preemptive_runtime_p6_rejects_stale_decision_and_dead_store_resume() {
    let mut graph = p6_decided_preempted_activation();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p6-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 2,
            activation: 11,
            activation_generation: 4,
            note: "stale decision".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("resume scheduler decision generation is missing or consumed".to_string());
    assert_eq!(stale.violations, expected);
    assert!(graph.activation_resumes().is_empty());
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Runnable
    );

    let mut dead_store_graph = SemanticGraph::new();
    dead_store_graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    let store = dead_store_graph.register_store("driver", "driver.cwasm", "driver", "restartable");
    assert!(dead_store_graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(dead_store_graph.create_runtime_activation_with_id(
        11,
        7,
        1,
        Some(store),
        Some(1),
        None
    ));
    assert!(dead_store_graph.enqueue_runnable_activation(1, 11, 1));
    assert!(dead_store_graph.record_scheduler_decision_with_id(
        14,
        1,
        1,
        11,
        2,
        "runnable-available",
        "choose"
    ));
    dead_store_graph.set_store_state(store, StoreState::Dead);
    let rejected = dead_store_graph.apply_envelope(CommandEnvelope::new(
        2,
        "p6-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 2,
            note: "dead store".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("resume owner store generation is missing or dead".to_string());
    assert_eq!(rejected.violations, expected);

    let mut faulted_task_graph = p6_decided_preempted_activation();
    faulted_task_graph.set_task_state(7, TaskState::Faulted);
    let rejected = faulted_task_graph.apply_envelope(CommandEnvelope::new(
        3,
        "p6-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "faulted task".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("resume owner task generation is missing or not runnable".to_string());
    assert_eq!(rejected.violations, expected);
}

#[test]
fn preemptive_runtime_p6_invariants_reject_resume_generation_leak() {
    let mut graph = p6_decided_preempted_activation();
    assert!(graph.resume_activation_with_id(15, 14, 1, 11, 4, "resume"));
    graph.corrupt_activation_resume_after_generation_for_test(15, 7);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationResumeMissingActivation {
            resume: 15,
            activation: 11,
        })
    );
}

fn p7_resumed_activation() -> SemanticGraph {
    let mut graph = p6_decided_preempted_activation();
    assert!(graph.resume_activation_with_id(15, 14, 1, 11, 4, "resume"));
    graph
}

#[test]
fn preemptive_runtime_p9_latency_sample_records_measured_window() {
    let mut graph = p7_resumed_activation();

    let sample = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p9-test",
        SemanticCommand::RecordPreemptionLatencySample {
            sample: 18,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation_resume: 15,
            activation_resume_generation: 1,
            measured_nanos: 8_500,
            budget_nanos: 50_000,
            note: "host-validation measured window".to_string(),
        },
    ));

    assert_eq!(sample.status, CommandStatus::Applied);
    assert_eq!(graph.preemption_latency_samples().len(), 1);
    let sample = &graph.preemption_latency_samples()[0];
    assert_eq!(sample.state, PreemptionLatencySampleState::Recorded);
    assert_eq!(sample.activation, 11);
    assert_eq!(sample.activation_generation_before, 3);
    assert_eq!(sample.activation_generation_after, 5);
    assert_eq!(sample.measured_nanos, 8_500);
    assert!(sample.measured_nanos <= sample.budget_nanos);
    assert_eq!(
        sample.interrupt_to_resume_events,
        sample.resumed_at_event - sample.interrupt_recorded_at_event
    );
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "PreemptionLatencySampleRecorded sample=18 timer=5@1 preemption=6@1 decision=14@1 resume=15@1 measured_nanos=8500 budget_nanos=50000 generation=1"
    );
}

#[test]
fn preemptive_runtime_p9_latency_sample_rejects_bad_measurement_and_chain() {
    let mut graph = p7_resumed_activation();

    let zero_measurement = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p9-test",
        SemanticCommand::RecordPreemptionLatencySample {
            sample: 18,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation_resume: 15,
            activation_resume_generation: 1,
            measured_nanos: 0,
            budget_nanos: 50_000,
            note: "invalid".to_string(),
        },
    ));
    assert_eq!(zero_measurement.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption latency measured nanos must be nonzero".to_string());
    assert_eq!(zero_measurement.violations, expected);

    let missing_resume = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p9-test",
        SemanticCommand::RecordPreemptionLatencySample {
            sample: 18,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation_resume: 99,
            activation_resume_generation: 1,
            measured_nanos: 8_500,
            budget_nanos: 50_000,
            note: "missing resume".to_string(),
        },
    ));
    assert_eq!(missing_resume.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption latency chain is invalid".to_string());
    assert_eq!(missing_resume.violations, expected);
    assert!(graph.preemption_latency_samples().is_empty());
}

#[test]
fn preemptive_runtime_p9_invariants_reject_latency_delta_drift() {
    let mut graph = p7_resumed_activation();
    assert!(graph.record_preemption_latency_sample_with_id(
        18, 5, 1, 6, 1, 14, 1, 15, 1, 8_500, 50_000, "sample"
    ));
    graph.corrupt_preemption_latency_interrupt_to_resume_for_test(18, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PreemptionLatencyTimelineMismatch { sample: 18 })
    );
}

#[test]
fn preemptive_runtime_p7_wait_blocks_and_cancel_does_not_auto_resume() {
    let mut graph = p7_resumed_activation();
    let blocker = ContractObjectRef::new(ContractObjectKind::TimerInterrupt, 5, 1);

    let blocked = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p7-test",
        SemanticCommand::BlockActivationOnWait {
            activation_wait: 16,
            activation: 11,
            activation_generation: 5,
            wait: 17,
            kind: SemanticWaitKind::Timer,
            blockers: {
                let mut blockers = Vec::new();
                blockers.push(blocker);
                blockers
            },
            deadline: Some(200),
            restart_policy: RestartPolicy::RestartIfAllowed,
            note: "block on timer wait".to_string(),
        },
    ));
    assert_eq!(blocked.status, CommandStatus::Applied);
    assert_eq!(graph.activation_waits().len(), 1);
    assert_eq!(graph.wait_records().len(), 1);
    assert_eq!(graph.pending_wait_count(), 1);
    assert_eq!(graph.wait_records()[0].owner_task_generation, Some(2));
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Pending
    );
    assert_eq!(graph.runtime_activations()[0].generation, 6);
    assert_eq!(graph.runtime_activations()[0].owner_task_generation, 2);
    assert_eq!(graph.tasks()[0].state, TaskState::Pending);
    assert_eq!(graph.tasks()[0].pending_wait, Some(17));
    assert!(graph.check_invariants().is_ok());

    let cancelled = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p7-test",
        SemanticCommand::CancelActivationWait {
            activation_wait: 16,
            activation_wait_generation: 1,
            wait_generation: 1,
            errno: 110,
            reason: WaitCancelReason::Timeout,
            note: "timer timeout".to_string(),
        },
    ));
    assert_eq!(cancelled.status, CommandStatus::Applied);
    assert_eq!(graph.pending_wait_count(), 0);
    assert_eq!(graph.wait_records()[0].state, WaitState::Cancelled);
    assert_eq!(
        graph.wait_records()[0].cancel_reason,
        Some(WaitCancelReason::Timeout)
    );
    assert_eq!(
        graph.activation_waits()[0].state,
        ActivationWaitState::Cancelled
    );
    assert_eq!(
        graph.activation_waits()[0].activation_generation_after_cancel,
        Some(7)
    );
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Blocked
    );
    assert_eq!(graph.runtime_activations()[0].generation, 7);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "RuntimeActivationWaitCancelled activation_wait=16 activation=11@6->7 wait=17@1 reason=timeout generation=1"
    );
}

#[test]
fn preemptive_runtime_p7_rejects_preempt_or_resume_of_waiting_activation() {
    let mut graph = p7_resumed_activation();
    assert!(graph.block_activation_on_wait_with_id(
        16,
        11,
        5,
        17,
        SemanticWaitKind::Timer,
        {
            let mut blockers = Vec::new();
            blockers.push(ContractObjectRef::new(
                ContractObjectKind::TimerInterrupt,
                5,
                1,
            ));
            blockers
        },
        Some(200),
        RestartPolicy::RestartIfAllowed,
        "block"
    ));
    assert!(graph.record_timer_interrupt_with_id(18, 2, 1, 2, Some(11), Some(6), "timer"));

    let rejected_preempt = graph.apply_envelope(CommandEnvelope::new(
        3,
        "p7-test",
        SemanticCommand::PreemptActivation {
            preemption: 19,
            activation: 11,
            activation_generation: 6,
            timer_interrupt: 18,
            timer_interrupt_generation: 1,
            queue: 1,
            note: "preempt pending activation".to_string(),
        },
    ));
    assert_eq!(rejected_preempt.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("preemption target activation generation is not running".to_string());
    assert_eq!(rejected_preempt.violations, expected);

    let rejected_enqueue = graph.apply_envelope(CommandEnvelope::new(
        4,
        "p7-test",
        SemanticCommand::EnqueueRunnable {
            queue: 1,
            activation: 11,
            activation_generation: 6,
        },
    ));
    assert_eq!(rejected_enqueue.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation is not enqueueable".to_string());
    assert_eq!(rejected_enqueue.violations, expected);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn preemptive_runtime_p7_invariants_reject_waiting_activation_runnable_leak() {
    let mut graph = p7_resumed_activation();
    assert!(graph.block_activation_on_wait_with_id(
        16,
        11,
        5,
        17,
        SemanticWaitKind::Timer,
        {
            let mut blockers = Vec::new();
            blockers.push(ContractObjectRef::new(
                ContractObjectKind::TimerInterrupt,
                5,
                1,
            ));
            blockers
        },
        Some(200),
        RestartPolicy::RestartIfAllowed,
        "block"
    ));
    graph.corrupt_runtime_activation_state_for_test(11, RuntimeActivationState::Runnable);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::PendingTaskHasRunnableActivation {
            task: 7,
            activation: 11,
        })
    );
}

fn p8_pending_store_activation() -> (SemanticGraph, StoreId, Generation) {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "driver-thread-7");
    let store = graph.register_store("driver.p8", "driver.fake-aot", "driver", "restartable");
    graph.set_store_state(store, StoreState::Running);
    let store_generation = graph.store_handle(store).unwrap().generation;
    assert!(graph.create_runnable_queue_with_id(1, "driver-rq"));
    assert!(graph.create_runtime_activation_with_id(
        11,
        7,
        1,
        Some(store),
        Some(store_generation),
        None
    ));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert!(graph.block_activation_on_wait_with_id(
        16,
        11,
        3,
        17,
        SemanticWaitKind::DeviceIrq,
        {
            let mut blockers = Vec::new();
            blockers.push(ContractObjectRef::new(
                ContractObjectKind::Store,
                store,
                store_generation,
            ));
            blockers
        },
        None,
        RestartPolicy::InternalOnly,
        "driver waits for irq"
    ));
    (graph, store, store_generation)
}

#[test]
fn preemptive_runtime_p8_cleanup_cancels_wait_and_kills_dead_store_activation() {
    let (mut graph, store, store_generation) = p8_pending_store_activation();

    let cleanup = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p8-test",
        SemanticCommand::CleanupActivationForStoreFault {
            cleanup: 20,
            store,
            store_generation,
            activation: 11,
            activation_generation: 4,
            wait: Some(17),
            wait_generation: Some(1),
            reason: "driver-store-fault".to_string(),
            note: "cleanup store-owned activation".to_string(),
        },
    ));
    assert_eq!(cleanup.status, CommandStatus::Applied);
    assert_eq!(graph.activation_cleanups().len(), 1);
    assert_eq!(
        graph.activation_cleanups()[0].state,
        ActivationCleanupState::Completed
    );
    assert_eq!(
        graph.activation_cleanups()[0].target_store_generation,
        store_generation
    );
    assert_eq!(
        graph.activation_cleanups()[0].activation_generation_after,
        5
    );
    assert_eq!(graph.wait_records()[0].state, WaitState::Cancelled);
    assert_eq!(
        graph.wait_records()[0].cancel_reason,
        Some(WaitCancelReason::StoreFault)
    );
    assert_eq!(
        graph.activation_waits()[0].state,
        ActivationWaitState::Cancelled
    );
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Dead
    );
    assert_eq!(graph.tasks()[0].state, TaskState::Faulted);
    assert_eq!(graph.tasks()[0].pending_wait, None);
    assert_eq!(graph.stores()[0].state, StoreState::Dead);
    assert!(
        graph
            .resources()
            .iter()
            .filter(|resource| resource.owner_store == Some(store))
            .all(|resource| !resource.live)
    );
    assert_eq!(
        graph.runtime_activations()[0].owner_store_generation,
        Some(graph.activation_cleanups()[0].result_store_generation)
    );
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "RuntimeActivationCleanupCompleted cleanup=20 store={store}@{store_generation}->{} activation=11@4->5 generation=1",
            graph.activation_cleanups()[0].result_store_generation
        )
    );
}

#[test]
fn preemptive_runtime_p8_cleanup_rejects_stale_store_generation_and_no_resume_leak() {
    let (mut graph, store, store_generation) = p8_pending_store_activation();
    graph.set_store_state(store, StoreState::Suspended);
    graph.set_store_state(store, StoreState::Running);
    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "p8-test",
        SemanticCommand::CleanupActivationForStoreFault {
            cleanup: 20,
            store,
            store_generation,
            activation: 11,
            activation_generation: 4,
            wait: Some(17),
            wait_generation: Some(1),
            reason: "stale cleanup".to_string(),
            note: "old store generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("cleanup target store generation is missing or dead".to_string());
    assert_eq!(stale.violations, expected);
    assert_ne!(graph.stores()[0].state, StoreState::Dead);

    let (mut graph, store, store_generation) = p8_pending_store_activation();
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        store_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    let enqueue = graph.apply_envelope(CommandEnvelope::new(
        2,
        "p8-test",
        SemanticCommand::EnqueueRunnable {
            queue: 1,
            activation: 11,
            activation_generation: 5,
        },
    ));
    assert_eq!(enqueue.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("activation is not enqueueable".to_string());
    assert_eq!(enqueue.violations, expected);
    assert!(graph.runnable_queues()[0].entries.is_empty());
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn preemptive_runtime_p8_cleanup_history_survives_store_restart_generation() {
    let (mut graph, store, store_generation) = p8_pending_store_activation();
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        store_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    let cleanup_result_generation = graph.activation_cleanups()[0].result_store_generation;

    let rebind = graph.rebind_store_instance(store).expect("store rebind");
    assert!(rebind.generation > cleanup_result_generation);
    graph.set_store_state(store, StoreState::Running);

    assert!(graph.store_handle(store).unwrap().generation > cleanup_result_generation);
    assert_eq!(
        graph.runtime_activations()[0].owner_store_generation,
        Some(cleanup_result_generation)
    );
    assert_eq!(
        graph.runtime_activations()[0].state,
        RuntimeActivationState::Dead
    );
    assert_eq!(graph.check_invariants(), Ok(()));
}

#[test]
fn preemptive_runtime_p8_invariants_reject_cleanup_generation_leak() {
    let (mut graph, store, store_generation) = p8_pending_store_activation();
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        store_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    graph.corrupt_activation_cleanup_after_generation_for_test(20, 99);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::ActivationCleanupMissingActivation {
            cleanup: 20,
            activation: 11,
        })
    );
}

fn s13_cleanup_quiescence_graph() -> (SemanticGraph, StoreId, Generation, Generation) {
    let (mut graph, store, target_generation) = p8_pending_store_activation();
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        target_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    let result_generation = graph.activation_cleanups()[0].result_store_generation;
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "s13 hart0"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "s13 hart1"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "cleanup-quiescence-boundary",
        "post-cleanup safe point"
    ));
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        1,
        71,
        1,
        true,
        "cleanup-quiescence-rendezvous",
        "all harts parked after cleanup",
    ));
    (graph, store, target_generation, result_generation)
}

#[test]
fn smp_runtime_s13_cleanup_quiescence_validates_after_cleanup_rendezvous() {
    let (mut graph, store, target_generation, result_generation) = s13_cleanup_quiescence_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s13-test",
        SemanticCommand::ValidateSmpCleanupQuiescence {
            quiescence: 91,
            cleanup: 20,
            cleanup_generation: 1,
            rendezvous: 81,
            rendezvous_generation: 1,
            store,
            target_store_generation: target_generation,
            result_store_generation: result_generation,
            reason: "smp-cleanup-quiescence".to_string(),
            note: "dead store quiesced across harts".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_cleanup_quiescence().len(), 1);
    let quiescence = &graph.smp_cleanup_quiescence()[0];
    assert_eq!(quiescence.cleanup, 20);
    assert_eq!(quiescence.cleanup_generation, 1);
    assert_eq!(quiescence.store, store);
    assert_eq!(quiescence.target_store_generation, target_generation);
    assert_eq!(quiescence.result_store_generation, result_generation);
    assert_eq!(quiescence.rendezvous, 81);
    assert_eq!(quiescence.rendezvous_generation, 1);
    assert_eq!(quiescence.participants.len(), 2);
    assert!(quiescence.no_running_activation);
    assert!(quiescence.no_pending_wait);
    assert!(quiescence.no_live_capability);
    assert!(quiescence.no_live_resource);
    assert!(
        quiescence
            .participants
            .iter()
            .all(|participant| participant.quiesced
                && participant.current_activation.is_none()
                && participant.current_store.is_none())
    );
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == quiescence.validated_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "SmpCleanupQuiescenceHartObserved"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "SmpCleanupQuiescenceValidated quiescence=91 cleanup=20@1 store={store}@{target_generation}->{result_generation} rendezvous=81@1 participants=2 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s13_rejects_stale_or_premature_cleanup_quiescence() {
    let (mut stale_cleanup, store, target_generation, result_generation) =
        s13_cleanup_quiescence_graph();
    let stale = stale_cleanup.apply_envelope(CommandEnvelope::new(
        1,
        "s13-test",
        SemanticCommand::ValidateSmpCleanupQuiescence {
            quiescence: 91,
            cleanup: 20,
            cleanup_generation: 2,
            rendezvous: 81,
            rendezvous_generation: 1,
            store,
            target_store_generation: target_generation,
            result_store_generation: result_generation,
            reason: "stale-cleanup-generation".to_string(),
            note: "reject stale cleanup generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp cleanup quiescence cleanup is missing".to_string());
    assert_eq!(stale.violations, expected);

    let (mut premature, store, target_generation) = p8_pending_store_activation();
    assert!(premature.register_hart_with_id(1, 0, "boot-hart0", true, "s13 hart0"));
    assert!(premature.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(premature.register_hart_with_id(2, 1, "hart1", false, "s13 hart1"));
    assert!(premature.set_hart_state(2, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(premature.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "premature-quiescence-boundary",
        "safe point before cleanup"
    ));
    assert!(premature.complete_stop_the_world_rendezvous_with_id(
        81,
        1,
        71,
        1,
        true,
        "premature-quiescence-rendezvous",
        "rendezvous before cleanup",
    ));
    assert!(premature.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        target_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    let result_generation = premature.activation_cleanups()[0].result_store_generation;
    let premature_result = premature.apply_envelope(CommandEnvelope::new(
        2,
        "s13-test",
        SemanticCommand::ValidateSmpCleanupQuiescence {
            quiescence: 91,
            cleanup: 20,
            cleanup_generation: 1,
            rendezvous: 81,
            rendezvous_generation: 1,
            store,
            target_store_generation: target_generation,
            result_store_generation: result_generation,
            reason: "premature-rendezvous".to_string(),
            note: "rendezvous must follow cleanup".to_string(),
        },
    ));
    assert_eq!(premature_result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp cleanup quiescence rendezvous must follow cleanup".to_string());
    assert_eq!(premature_result.violations, expected);
}

#[test]
fn smp_runtime_s13_rejects_live_store_generation_leak() {
    let (mut graph, store, target_generation) = p8_pending_store_activation();
    graph.ensure_task(8, FrontendKind::LinuxElf, "leaked-driver-thread");
    assert!(graph.create_runtime_activation_with_id(
        21,
        8,
        1,
        Some(store),
        Some(target_generation),
        None
    ));
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        20,
        store,
        target_generation,
        11,
        4,
        Some(17),
        Some(1),
        "driver-store-fault",
        "cleanup"
    ));
    let result_generation = graph.activation_cleanups()[0].result_store_generation;
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "s13 hart0"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "s13 hart1"));
    assert!(graph.set_hart_state(2, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "cleanup-quiescence-boundary",
        "post-cleanup safe point"
    ));
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        1,
        71,
        1,
        true,
        "cleanup-quiescence-rendezvous",
        "all harts parked after cleanup",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s13-test",
        SemanticCommand::ValidateSmpCleanupQuiescence {
            quiescence: 91,
            cleanup: 20,
            cleanup_generation: 1,
            rendezvous: 81,
            rendezvous_generation: 1,
            store,
            target_store_generation: target_generation,
            result_store_generation: result_generation,
            reason: "live-activation-leak".to_string(),
            note: "reject live activation owned by cleanup store generation".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp cleanup quiescence found live activation for dead store".to_string());
    assert_eq!(result.violations, expected);
}

#[test]
fn smp_runtime_s13_rejects_generationless_live_capability_leak() {
    let (mut graph, store, target_generation, result_generation) = s13_cleanup_quiescence_graph();
    let cap = graph.grant_capability("driver.p8", "packet-device.net0", &["tx"], "store");
    assert!(graph.corrupt_capability_owner_store_generation_for_test(cap, None));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s13-test",
        SemanticCommand::ValidateSmpCleanupQuiescence {
            quiescence: 91,
            cleanup: 20,
            cleanup_generation: 1,
            rendezvous: 81,
            rendezvous_generation: 1,
            store,
            target_store_generation: target_generation,
            result_store_generation: result_generation,
            reason: "generationless-capability-leak".to_string(),
            note: "reject live capability missing owner store generation".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp cleanup quiescence found live capability for dead store".to_string());
    assert_eq!(result.violations, expected);
}

#[test]
fn smp_runtime_s13_history_survives_store_rebind_and_hart_transition() {
    let (mut graph, store, target_generation, result_generation) = s13_cleanup_quiescence_graph();
    assert!(graph.validate_smp_cleanup_quiescence_with_id(
        91,
        20,
        1,
        81,
        1,
        store,
        target_generation,
        result_generation,
        "smp-cleanup-quiescence",
        "dead store quiesced across harts",
    ));

    let rebind = graph.rebind_store_instance(store).expect("store rebind");
    assert!(rebind.generation > result_generation);
    graph.set_store_state(store, StoreState::Running);
    assert!(graph.set_hart_state(
        1,
        2,
        HartState::Booting,
        "advance after cleanup quiescence",
        "later"
    ));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_smp_cleanup_quiescence_event_for_test(91, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpCleanupQuiescenceMissingEvent { quiescence: 91 })
    );
}

fn s14_snapshot_barrier_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    assert!(graph.register_hart_with_id(1, 0, "boot-hart0", true, "s14 hart0"));
    assert!(graph.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "s14 hart1"));
    assert!(graph.set_hart_state(2, 1, HartState::Parked, "scheduler-ready", "parked"));
    assert!(graph.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "snapshot-barrier-boundary",
        "snapshot safe point"
    ));
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        81,
        3,
        71,
        1,
        true,
        "snapshot-barrier-rendezvous",
        "all harts stopped for snapshot",
    ));
    graph
}

#[test]
fn smp_runtime_s14_snapshot_barrier_validates_clean_rendezvous() {
    let mut graph = s14_snapshot_barrier_graph();
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s14-test",
        SemanticCommand::ValidateSmpSnapshotBarrier {
            barrier: 101,
            rendezvous: 81,
            rendezvous_generation: 1,
            snapshot_state: SnapshotBarrierValidationState::default(),
            reason: "smp-snapshot-barrier".to_string(),
            note: "snapshot barrier over stopped harts".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_snapshot_barriers().len(), 1);
    let barrier = &graph.smp_snapshot_barriers()[0];
    assert_eq!(barrier.id, 101);
    assert_eq!(barrier.rendezvous, 81);
    assert_eq!(barrier.rendezvous_generation, 1);
    assert_eq!(barrier.rendezvous_epoch, 3);
    assert_eq!(barrier.event_log_cursor, cursor_before);
    assert_eq!(barrier.participants.len(), 2);
    assert!(barrier.snapshot_validation_ok);
    assert!(barrier.participants.iter().all(|participant| {
        participant.snapshot_safe && participant.event_log_cursor_observed == cursor_before
    }));
    assert!(graph.hart_event_attributions().iter().any(|record| {
        record.event == barrier.validated_at_event
            && record.hart == 1
            && record.hart_generation == 2
            && record.event_kind == "SmpSnapshotBarrierHartFrozen"
    }));
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "SmpSnapshotBarrierValidated barrier=101 rendezvous=81@1 cursor={cursor_before} participants=2 generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s14_rejects_dirty_boundary_or_pending_wait() {
    let mut dirty = s14_snapshot_barrier_graph();
    let rejected = dirty.apply_envelope(CommandEnvelope::new(
        1,
        "s14-test",
        SemanticCommand::ValidateSmpSnapshotBarrier {
            barrier: 101,
            rendezvous: 81,
            rendezvous_generation: 1,
            snapshot_state: SnapshotBarrierValidationState {
                active_dmw_lease_count: 1,
                ..SnapshotBarrierValidationState::default()
            },
            reason: "dirty-boundary".to_string(),
            note: "reject active dmw lease".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp snapshot barrier boundary state is not quiescent".to_string());
    assert_eq!(rejected.violations, expected);

    let (mut pending, _, _) = p8_pending_store_activation();
    assert!(pending.register_hart_with_id(1, 0, "boot-hart0", true, "s14 hart0"));
    assert!(pending.set_hart_state(1, 1, HartState::Idle, "scheduler-ready", "idle"));
    assert!(pending.register_hart_with_id(2, 1, "hart1", false, "s14 hart1"));
    assert!(pending.set_hart_state(2, 1, HartState::Parked, "scheduler-ready", "parked"));
    assert!(pending.record_smp_safe_point_with_id(
        71,
        1,
        2,
        vec![(1, 2), (2, 2)],
        "snapshot-barrier-boundary",
        "snapshot safe point"
    ));
    assert!(pending.complete_stop_the_world_rendezvous_with_id(
        81,
        3,
        71,
        1,
        true,
        "snapshot-barrier-rendezvous",
        "all harts stopped for snapshot",
    ));
    let wait_rejected = pending.apply_envelope(CommandEnvelope::new(
        2,
        "s14-test",
        SemanticCommand::ValidateSmpSnapshotBarrier {
            barrier: 101,
            rendezvous: 81,
            rendezvous_generation: 1,
            snapshot_state: SnapshotBarrierValidationState::default(),
            reason: "pending-wait".to_string(),
            note: "reject pending wait".to_string(),
        },
    ));
    assert_eq!(wait_rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp snapshot barrier found pending wait".to_string());
    assert_eq!(wait_rejected.violations, expected);
}

#[test]
fn smp_runtime_s14_rejects_stale_rendezvous_generation() {
    let mut graph = s14_snapshot_barrier_graph();
    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s14-test",
        SemanticCommand::ValidateSmpSnapshotBarrier {
            barrier: 101,
            rendezvous: 81,
            rendezvous_generation: 2,
            snapshot_state: SnapshotBarrierValidationState::default(),
            reason: "stale-rendezvous".to_string(),
            note: "reject stale rendezvous generation".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp snapshot barrier rendezvous is missing".to_string());
    assert_eq!(rejected.violations, expected);
}

#[test]
fn smp_runtime_s14_history_survives_hart_transition() {
    let mut graph = s14_snapshot_barrier_graph();
    assert!(graph.validate_smp_snapshot_barrier_with_id(
        101,
        81,
        1,
        SnapshotBarrierValidationState::default(),
        "smp-snapshot-barrier",
        "snapshot barrier over stopped harts",
    ));
    let cursor = graph.smp_snapshot_barriers()[0].event_log_cursor;

    assert!(graph.set_hart_state(
        1,
        2,
        HartState::Booting,
        "advance after snapshot barrier",
        "later"
    ));
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_smp_snapshot_barrier_event_for_test(101, 999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpSnapshotBarrierMissingEvent { barrier: 101 })
    );
    assert_eq!(cursor, graph.smp_snapshot_barriers()[0].event_log_cursor);
}

fn s15_stress_graph(include_snapshot: bool) -> SemanticGraph {
    let mut graph = s12_smp_code_publish_barrier_graph();
    assert!(graph.validate_smp_code_publish_barrier_with_id(
        91,
        81,
        1,
        0,
        1,
        true,
        false,
        "semantic-code-publish-barrier",
        "validate remote icache sync evidence only",
    ));
    assert!(graph.record_ipi_event_with_id(
        171,
        1,
        2,
        2,
        4,
        IpiEventKind::SchedulerKick,
        "s15-remote-park",
        "park hart1 before stress barrier",
    ));
    assert!(graph.remote_park_hart_with_id(
        171,
        171,
        1,
        1,
        2,
        2,
        4,
        "s15-remote-maintenance",
        "remote park for stress property run",
    ));

    graph.ensure_task(70, FrontendKind::LinuxElf, "s15-driver-thread");
    let store = graph.register_store("driver.s15", "driver.fake-aot", "driver", "restartable");
    graph.set_store_state(store, StoreState::Running);
    let store_generation = graph.store_handle(store).unwrap().generation;
    assert!(graph.create_runnable_queue_with_id(70, "s15-cleanup-rq"));
    assert!(graph.bind_runnable_queue_owner(70, 1, 1, 2, "hart0 owns cleanup queue"));
    assert!(graph.create_runtime_activation_with_id(
        70,
        70,
        1,
        Some(store),
        Some(store_generation),
        None
    ));
    assert!(graph.enqueue_runnable_activation(70, 70, 1));
    assert!(graph.dequeue_runnable_activation(70, 70));
    assert!(graph.block_activation_on_wait_with_id(
        170,
        70,
        3,
        171,
        SemanticWaitKind::DeviceIrq,
        {
            let mut blockers = Vec::new();
            blockers.push(ContractObjectRef::new(
                ContractObjectKind::Store,
                store,
                store_generation,
            ));
            blockers
        },
        None,
        RestartPolicy::InternalOnly,
        "s15 driver waits for irq",
    ));
    assert!(graph.cleanup_activation_for_store_fault_with_id(
        170,
        store,
        store_generation,
        70,
        4,
        Some(171),
        Some(1),
        "s15-driver-store-fault",
        "cleanup stress driver",
    ));
    let result_generation = graph.activation_cleanups()[0].result_store_generation;
    assert!(graph.record_smp_safe_point_with_id(
        171,
        1,
        2,
        vec![(1, 2), (2, 5)],
        "s15-cleanup-quiescence-boundary",
        "stress cleanup safe point",
    ));
    assert!(graph.complete_stop_the_world_rendezvous_with_id(
        171,
        2,
        171,
        1,
        true,
        "s15-cleanup-rendezvous",
        "stress cleanup rendezvous",
    ));
    assert!(graph.validate_smp_cleanup_quiescence_with_id(
        171,
        170,
        1,
        171,
        1,
        store,
        store_generation,
        result_generation,
        "s15-cleanup-quiescence",
        "stress cleanup quiescence evidence",
    ));
    if include_snapshot {
        assert!(graph.record_smp_safe_point_with_id(
            181,
            1,
            2,
            vec![(1, 2), (2, 5)],
            "s15-snapshot-boundary",
            "stress snapshot safe point",
        ));
        assert!(graph.complete_stop_the_world_rendezvous_with_id(
            181,
            3,
            181,
            1,
            true,
            "s15-snapshot-rendezvous",
            "stress snapshot rendezvous",
        ));
        assert!(graph.validate_smp_snapshot_barrier_with_id(
            181,
            181,
            1,
            SnapshotBarrierValidationState::default(),
            "s15-smp-snapshot-barrier",
            "stress snapshot barrier",
        ));
    }
    graph
}

#[test]
fn smp_runtime_s15_stress_run_records_property_evidence() {
    let mut graph = s15_stress_graph(true);
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s15-test",
        SemanticCommand::RecordSmpStressRun {
            run: 191,
            scenario: "s15-smp-stress-property".to_string(),
            iterations: 3,
            invariant_checks: 6,
            reason: "smp-stress-property-tests".to_string(),
            note: "stress code publish cleanup snapshot properties".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_stress_runs().len(), 1);
    let run = &graph.smp_stress_runs()[0];
    assert_eq!(run.id, 191);
    assert_eq!(run.iterations, 3);
    assert_eq!(run.hart_count, 2);
    assert_eq!(run.event_log_cursor, cursor_before);
    assert_eq!(run.observed_safe_point_count, 3);
    assert_eq!(run.observed_rendezvous_count, 3);
    assert_eq!(run.observed_code_publish_barrier_count, 1);
    assert_eq!(run.observed_cleanup_quiescence_count, 1);
    assert_eq!(run.observed_snapshot_barrier_count, 1);
    assert_eq!(run.observed_activation_migration_count, 1);
    assert_eq!(run.observed_remote_preempt_count, 1);
    assert_eq!(run.observed_remote_park_count, 1);
    assert_eq!(run.property_failures, 0);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SmpStressRunRecorded run=191 scenario=s15-smp-stress-property iterations=3 harts=2 safe_points=3 rendezvous=3 property_failures=0 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s15_rejects_incomplete_or_dirty_property_run() {
    let mut missing_snapshot = s15_stress_graph(false);
    let rejected = missing_snapshot.apply_envelope(CommandEnvelope::new(
        1,
        "s15-test",
        SemanticCommand::RecordSmpStressRun {
            run: 191,
            scenario: "s15-smp-stress-property".to_string(),
            iterations: 3,
            invariant_checks: 3,
            reason: "missing-snapshot".to_string(),
            note: "must reject incomplete coverage".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    let mut expected = Vec::new();
    expected.push("smp stress run safe point coverage is incomplete".to_string());
    assert_eq!(rejected.violations, expected);

    let mut graph = s15_stress_graph(true);
    assert!(graph.record_smp_stress_run_with_id(
        191,
        "s15-smp-stress-property",
        3,
        6,
        "smp-stress-property-tests",
        "stress run",
    ));
    graph.corrupt_smp_stress_run_failures_for_test(191, 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpStressRunInvalid { run: 191 })
    );

    let mut graph = s15_stress_graph(true);
    assert!(graph.record_smp_stress_run_with_id(
        191,
        "s15-smp-stress-property",
        3,
        6,
        "smp-stress-property-tests",
        "stress run",
    ));
    graph.corrupt_smp_stress_run_snapshot_count_for_test(191, 0);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpStressRunInvalid { run: 191 })
    );
}

#[test]
fn smp_runtime_s16_scaling_benchmark_records_semantic_metrics() {
    let mut graph = s15_stress_graph(true);
    assert!(graph.record_smp_stress_run_with_id(
        191,
        "s15-smp-stress-property",
        3,
        6,
        "smp-stress-property-tests",
        "stress run",
    ));
    let cursor_before = graph.event_log().cursor();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s16-test",
        SemanticCommand::RecordSmpScalingBenchmark {
            benchmark: 201,
            scenario: "s16-smp-scaling-benchmark".to_string(),
            stress_run: 191,
            stress_run_generation: 1,
            workload_units: 6,
            baseline_single_hart_nanos: 120_000,
            measured_smp_nanos: 72_000,
            budget_nanos: 90_000,
            note: "semantic harness scaling benchmark".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.smp_scaling_benchmarks().len(), 1);
    let benchmark = &graph.smp_scaling_benchmarks()[0];
    assert_eq!(benchmark.id, 201);
    assert_eq!(benchmark.stress_run, 191);
    assert_eq!(benchmark.stress_run_generation, 1);
    assert_eq!(benchmark.hart_count, 2);
    assert_eq!(benchmark.workload_units, 6);
    assert_eq!(benchmark.baseline_single_hart_nanos, 120_000);
    assert_eq!(benchmark.measured_smp_nanos, 72_000);
    assert_eq!(benchmark.budget_nanos, 90_000);
    assert_eq!(benchmark.speedup_milli, 1_666);
    assert_eq!(benchmark.efficiency_milli, 833);
    assert_eq!(benchmark.event_log_cursor, cursor_before);
    assert_eq!(benchmark.stress_safe_point_count, 3);
    assert_eq!(benchmark.stress_rendezvous_count, 3);
    assert_eq!(benchmark.stress_property_failures, 0);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SmpScalingBenchmarkRecorded benchmark=201 stress_run=191@1 harts=2 workload_units=6 measured_nanos=72000 budget_nanos=90000 speedup_milli=1666 efficiency_milli=833 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn smp_runtime_s16_rejects_unbacked_or_invalid_scaling_benchmark() {
    let mut graph = s15_stress_graph(true);
    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "s16-test",
        SemanticCommand::RecordSmpScalingBenchmark {
            benchmark: 201,
            scenario: "s16-smp-scaling-benchmark".to_string(),
            stress_run: 191,
            stress_run_generation: 1,
            workload_units: 6,
            baseline_single_hart_nanos: 120_000,
            measured_smp_nanos: 72_000,
            budget_nanos: 90_000,
            note: "missing stress must reject".to_string(),
        },
    ));
    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["smp scaling benchmark missing stress run evidence".to_string()]
    );

    assert!(graph.record_smp_stress_run_with_id(
        191,
        "s15-smp-stress-property",
        3,
        6,
        "smp-stress-property-tests",
        "stress run",
    ));
    let budget_rejected = graph.apply_envelope(CommandEnvelope::new(
        2,
        "s16-test",
        SemanticCommand::RecordSmpScalingBenchmark {
            benchmark: 202,
            scenario: "s16-smp-scaling-benchmark".to_string(),
            stress_run: 191,
            stress_run_generation: 1,
            workload_units: 6,
            baseline_single_hart_nanos: 120_000,
            measured_smp_nanos: 100_000,
            budget_nanos: 90_000,
            note: "budget overrun must reject".to_string(),
        },
    ));
    assert_eq!(budget_rejected.status, CommandStatus::Rejected);
    assert_eq!(
        budget_rejected.violations,
        vec!["smp scaling benchmark exceeds budget".to_string()]
    );

    assert!(graph.record_smp_scaling_benchmark_with_id(
        201,
        "s16-smp-scaling-benchmark",
        191,
        1,
        6,
        120_000,
        72_000,
        90_000,
        "semantic harness scaling benchmark",
    ));
    graph.corrupt_smp_scaling_benchmark_speedup_for_test(201, 1_999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SmpScalingBenchmarkInvalid { benchmark: 201 })
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
        artifact_format: "target-artifact-image-v1".to_string(),
        runtime_executor_abi: "vmos-runtime-only-executor-v0".to_string(),
    }
}
