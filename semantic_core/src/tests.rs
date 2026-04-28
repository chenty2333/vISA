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

fn setup_n7_network_rx_wait_graph() -> SemanticGraph {
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
        "n7 rx interrupt",
    ));
    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == 1552)
        .cloned()
        .unwrap();
    let rx_queue_ref = ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1544, 1);
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1561,
                owner_task: None,
                owner_store: Some(binding_record.driver_store),
                owner_store_generation: Some(binding_record.driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![rx_queue_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("driver.virtio-net2:rx-queue".to_string()),
            })
            .is_ok()
    );
    assert!(graph.record_io_wait_with_id(
        1562,
        1561,
        1,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1540,
        1,
        1552,
        1,
        rx_queue_ref,
        "n7 pending rx queue io wait",
    ));
    graph
}

#[test]
fn network_runtime_n7_rx_interrupt_resolves_rx_queue_wait() {
    let mut graph = setup_n7_network_rx_wait_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n7-test",
        SemanticCommand::ResolveNetworkRxWait {
            resolution: 1563,
            io_wait: 1562,
            io_wait_generation: 1,
            rx_interrupt: 1556,
            rx_interrupt_generation: 1,
            note: "n7 rx wait resolves from interrupt".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.network_rx_wait_resolution_count(), 1);
    assert_eq!(graph.io_waits()[0].state, IoWaitState::Resolved);
    assert_eq!(graph.io_waits()[0].completion_irq_event, Some(1555));
    let wait = graph
        .wait_records()
        .iter()
        .find(|record| record.id == 1561)
        .unwrap();
    assert_eq!(wait.state, WaitState::Resolved);
    let resolution = &graph.network_rx_wait_resolutions()[0];
    assert_eq!(
        resolution.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkRxWaitResolution, 1563, 1)
    );
    assert_eq!(resolution.rx_interrupt, 1556);
    assert_eq!(resolution.rx_queue, 1544);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "NetworkRxWaitResolved resolution=1563 io_wait=1562@1 wait=1561@1 rx_interrupt=1556@1 rx_queue=1544@1 ready_descriptors=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n7_rejects_stale_interrupt_and_wrong_wait_blocker() {
    let mut graph = setup_n7_network_rx_wait_graph();
    let stale_interrupt = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n7-test",
        SemanticCommand::ResolveNetworkRxWait {
            resolution: 1563,
            io_wait: 1562,
            io_wait_generation: 1,
            rx_interrupt: 1556,
            rx_interrupt_generation: 2,
            note: "n7 stale interrupt".to_string(),
        },
    ));
    assert_eq!(stale_interrupt.status, CommandStatus::Rejected);
    assert_eq!(
        stale_interrupt.violations,
        vec!["network rx wait interrupt generation is missing or inactive".to_string()]
    );

    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == 1552)
        .cloned()
        .unwrap();
    let tx_queue_ref = ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1545, 1);
    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1564,
                owner_task: None,
                owner_store: Some(binding_record.driver_store),
                owner_store_generation: Some(binding_record.driver_store_generation),
                kind: SemanticWaitKind::DeviceIrq,
                generation: 1,
                blockers: vec![tx_queue_ref],
                deadline: None,
                restart_policy: RestartPolicy::InternalOnly,
                saved_context: Some("driver.virtio-net2:tx-queue".to_string()),
            })
            .is_ok()
    );
    assert!(graph.record_io_wait_with_id(
        1565,
        1564,
        1,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1540,
        1,
        1552,
        1,
        tx_queue_ref,
        "n7 wrong tx queue io wait",
    ));
    let wrong_blocker = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n7-test",
        SemanticCommand::ResolveNetworkRxWait {
            resolution: 1563,
            io_wait: 1565,
            io_wait_generation: 1,
            rx_interrupt: 1556,
            rx_interrupt_generation: 1,
            note: "n7 tx queue must not resolve rx wait".to_string(),
        },
    ));
    assert_eq!(wrong_blocker.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_blocker.violations,
        vec!["network rx wait blocker must be the rx packet queue".to_string()]
    );
}

#[test]
fn network_runtime_n7_invariants_reject_resolution_queue_generation_leak() {
    let mut graph = setup_n7_network_rx_wait_graph();
    assert!(graph.resolve_network_rx_wait_with_id(1563, 1562, 1, 1556, 1, "n7 resolved rx wait",));
    graph.corrupt_network_rx_wait_resolution_queue_generation_for_test(1563, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::NetworkRxWaitResolutionMissingRxQueue {
                resolution: 1563,
                rx_queue: 1544,
            }
        )
    );
}

fn setup_n8_network_tx_gate_graph() -> (SemanticGraph, CapabilityHandle) {
    let mut graph = setup_n6_network_rx_interrupt_graph();
    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == 1552)
        .cloned()
        .unwrap();
    assert!(graph.record_packet_descriptor_object_with_id(
        1547,
        1545,
        1,
        1543,
        1,
        0,
        64,
        "n8 tx packet descriptor",
    ));
    let packet_device_ref = ContractObjectRef::new(ContractObjectKind::PacketDeviceObject, 1541, 1);
    let cap = graph.grant_capability_with_authority_ref(
        "driver.virtio-net2",
        "packet-device.net2",
        AuthorityObjectRef::internal(CapabilityClass::PacketDevice, packet_device_ref),
        &["tx"],
        "store",
        "n8-test",
        true,
    );
    let handle = graph
        .capabilities()
        .record(cap)
        .and_then(|record| record.store_local_handle(vec!["tx".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1570,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        packet_device_ref,
        CapabilityClass::PacketDevice,
        "tx",
        handle.clone(),
        "n8 packet tx capability",
    ));
    (graph, handle)
}

#[test]
fn network_runtime_n8_tx_descriptor_requires_packet_device_capability() {
    let (mut graph, handle) = setup_n8_network_tx_gate_graph();
    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == 1552)
        .cloned()
        .unwrap();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n8-test",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 1571,
            driver_store: binding_record.driver_store,
            driver_store_generation: binding_record.driver_store_generation,
            packet_descriptor: 1547,
            packet_descriptor_generation: 1,
            device_capability: 1570,
            device_capability_generation: 1,
            handle,
            note: "n8 tx gate allowed".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.network_tx_capability_gate_count(), 1);
    let gate = &graph.network_tx_capability_gates()[0];
    assert_eq!(
        gate.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkTxCapabilityGate, 1571, 1)
    );
    assert_eq!(gate.packet_device, 1541);
    assert_eq!(gate.tx_queue, 1545);
    assert_eq!(gate.packet_descriptor, 1547);
    assert_eq!(gate.operation, "tx");
    assert_eq!(gate.byte_len, 64);
    assert_eq!(gate.sequence, 2);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkTxCapabilityGateRecorded tx_gate=1571")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n8_rejects_forged_handle_and_rx_descriptor() {
    let (mut graph, mut forged_handle) = setup_n8_network_tx_gate_graph();
    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == 1552)
        .cloned()
        .unwrap();
    forged_handle.generation += 1;
    let forged = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n8-test",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 1571,
            driver_store: binding_record.driver_store,
            driver_store_generation: binding_record.driver_store_generation,
            packet_descriptor: 1547,
            packet_descriptor_generation: 1,
            device_capability: 1570,
            device_capability_generation: 1,
            handle: forged_handle,
            note: "n8 forged tx handle".to_string(),
        },
    ));
    assert_eq!(forged.status, CommandStatus::Rejected);
    assert_eq!(
        forged.violations,
        vec!["network tx capability gate handle mismatch".to_string()]
    );
    assert_eq!(graph.network_tx_capability_gate_count(), 0);

    assert!(graph.record_packet_descriptor_object_with_id(
        1546,
        1544,
        1,
        1542,
        1,
        0,
        512,
        "n8 rx descriptor must not tx",
    ));
    let valid_handle = graph
        .capabilities()
        .record(
            graph
                .device_capabilities()
                .iter()
                .find(|record| record.id == 1570)
                .unwrap()
                .capability,
        )
        .and_then(|record| record.store_local_handle(vec!["tx".to_string()]))
        .unwrap();
    let wrong_descriptor = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n8-test",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 1572,
            driver_store: binding_record.driver_store,
            driver_store_generation: binding_record.driver_store_generation,
            packet_descriptor: 1546,
            packet_descriptor_generation: 1,
            device_capability: 1570,
            device_capability_generation: 1,
            handle: valid_handle,
            note: "n8 rx descriptor rejected by tx gate".to_string(),
        },
    ));
    assert_eq!(wrong_descriptor.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_descriptor.violations,
        vec!["network tx capability gate requires tx packet queue".to_string()]
    );
}

#[test]
fn network_runtime_n8_invariants_reject_capability_generation_leak() {
    let (mut graph, handle) = setup_n8_network_tx_gate_graph();
    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == 1552)
        .cloned()
        .unwrap();
    assert!(graph.record_network_tx_capability_gate_with_id(
        1571,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1547,
        1,
        1570,
        1,
        handle,
        "n8 tx gate allowed",
    ));
    graph.corrupt_network_tx_gate_capability_generation_for_test(1571, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkTxCapabilityGateInvalid { tx_gate: 1571 })
    );
}

fn setup_n9_network_tx_completion_graph() -> SemanticGraph {
    let (mut graph, handle) = setup_n8_network_tx_gate_graph();
    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == 1552)
        .cloned()
        .unwrap();
    assert!(graph.record_network_tx_capability_gate_with_id(
        1571,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1547,
        1,
        1570,
        1,
        handle,
        "n9 tx gate allowed",
    ));
    graph
}

#[test]
fn network_runtime_n9_tx_completion_follows_allowed_gate() {
    let mut graph = setup_n9_network_tx_completion_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n9-test",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 1572,
            tx_gate: 1571,
            tx_gate_generation: 1,
            backend,
            completion_sequence: 1,
            note: "n9 tx completion path".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.network_tx_completion_count(), 1);
    let completion = &graph.network_tx_completions()[0];
    assert_eq!(
        completion.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkTxCompletion, 1572, 1)
    );
    assert_eq!(completion.tx_gate, 1571);
    assert_eq!(completion.backend, backend);
    assert_eq!(completion.packet_device, 1541);
    assert_eq!(completion.tx_queue, 1545);
    assert_eq!(completion.packet_descriptor, 1547);
    assert_eq!(completion.packet_buffer, 1543);
    assert_eq!(completion.byte_len, 64);
    assert_eq!(completion.sequence, 2);
    assert_eq!(completion.completion_sequence, 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "NetworkTxCompleted completion=1572 tx_gate=1571@1 backend=virtio-net-backend-object:1553@1 driver_store={}@{} packet_device=1541@1 tx_queue=1545@1 packet_descriptor=1547@1 packet_buffer=1543@1 byte_len=64 sequence=2 completion_sequence=1 generation=1",
            completion.driver_store, completion.driver_store_generation
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n9_rejects_stale_gate_wrong_backend_and_duplicate_completion() {
    let mut graph = setup_n9_network_tx_completion_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let stale_gate = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n9-test",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 1572,
            tx_gate: 1571,
            tx_gate_generation: 2,
            backend,
            completion_sequence: 1,
            note: "n9 stale gate".to_string(),
        },
    ));
    assert_eq!(stale_gate.status, CommandStatus::Rejected);
    assert_eq!(
        stale_gate.violations,
        vec!["network tx completion gate generation is missing or inactive".to_string()]
    );

    let wrong_backend = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n9-test",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 1572,
            tx_gate: 1571,
            tx_gate_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::PacketDeviceObject, 1541, 1),
            completion_sequence: 1,
            note: "n9 wrong backend".to_string(),
        },
    ));
    assert_eq!(wrong_backend.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_backend.violations,
        vec!["network tx completion backend generation is missing or inactive".to_string()]
    );

    assert!(graph.record_network_tx_completion_with_id(
        1572,
        1571,
        1,
        backend,
        1,
        "n9 tx completion",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n9-test",
        SemanticCommand::RecordNetworkTxCompletion {
            completion: 1573,
            tx_gate: 1571,
            tx_gate_generation: 1,
            backend,
            completion_sequence: 2,
            note: "n9 duplicate gate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["network tx completion gate already completed".to_string()]
    );
}

#[test]
fn network_runtime_n9_invariants_reject_completion_generation_leak() {
    let mut graph = setup_n9_network_tx_completion_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    assert!(graph.record_network_tx_completion_with_id(
        1572,
        1571,
        1,
        backend,
        1,
        "n9 tx completion",
    ));
    graph.corrupt_network_tx_completion_gate_generation_for_test(1572, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkTxCompletionMissingGate {
            completion: 1572,
            tx_gate: 1571,
        })
    );
}

#[test]
fn network_runtime_n9_invariants_reject_duplicate_completion_sequence() {
    let mut graph = setup_n9_network_tx_completion_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == 1552)
        .cloned()
        .unwrap();
    let handle = graph
        .device_capabilities()
        .iter()
        .find(|record| record.id == 1570)
        .and_then(|record| graph.capabilities().record(record.capability))
        .and_then(|record| record.store_local_handle(vec!["tx".to_string()]))
        .unwrap();
    assert!(graph.record_packet_buffer_object_with_id(
        1548,
        1541,
        1,
        PacketBufferDirection::Tx,
        2,
        512,
        32,
        3,
        PacketBufferObjectState::Filled,
        "n9 second tx packet buffer",
    ));
    assert!(graph.record_packet_descriptor_object_with_id(
        1549,
        1545,
        1,
        1548,
        1,
        1,
        32,
        "n9 second tx packet descriptor",
    ));
    assert!(graph.record_network_tx_capability_gate_with_id(
        1573,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1549,
        1,
        1570,
        1,
        handle,
        "n9 second tx gate allowed",
    ));
    assert!(graph.record_network_tx_completion_with_id(
        1572,
        1571,
        1,
        backend,
        1,
        "n9 first tx completion",
    ));
    assert!(graph.record_network_tx_completion_with_id(
        1574,
        1573,
        1,
        backend,
        2,
        "n9 second tx completion",
    ));
    graph.corrupt_network_tx_completion_sequence_for_test(1574, 1);
    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::NetworkTxCompletionDuplicateSequence {
                completion: 1574,
                tx_queue: 1545,
                completion_sequence: 1,
            }
        )
    );
}

fn setup_n10_network_stack_adapter_graph() -> SemanticGraph {
    setup_n9_network_tx_completion_graph()
}

#[test]
fn network_runtime_n10_smoltcp_adapter_binds_packet_device_contract() {
    let mut graph = setup_n10_network_stack_adapter_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n10-test",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 1575,
            backend,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            implementation: "smoltcp".to_string(),
            implementation_version: "0.13.0".to_string(),
            profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_string(),
            medium: "ethernet".to_string(),
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            ipv4_addr: [10, 0, 2, 15],
            ipv4_prefix_len: 24,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            max_payload_len: 512,
            socket_capacity: 0,
            note: "n10 smoltcp adapter binds packet device".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.network_stack_adapter_count(), 1);
    let adapter = &graph.network_stack_adapters()[0];
    assert_eq!(
        adapter.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkStackAdapter, 1575, 1)
    );
    assert_eq!(adapter.backend, backend);
    assert_eq!(adapter.packet_device, 1541);
    assert_eq!(adapter.rx_queue, 1544);
    assert_eq!(adapter.tx_queue, 1545);
    assert_eq!(adapter.profile, "smoltcp-0.13.0-ethernet-ipv4-tcp-v1");
    assert_eq!(adapter.socket_capacity, 0);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkStackAdapterBound adapter=1575 implementation=smoltcp")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n10_rejects_stale_profile_queue_and_duplicate_adapter() {
    let mut graph = setup_n10_network_stack_adapter_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    let unsupported_profile = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n10-test",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 1575,
            backend,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            implementation: "smoltcp".to_string(),
            implementation_version: "0.13.0".to_string(),
            profile: "smoltcp-unknown".to_string(),
            medium: "ethernet".to_string(),
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            ipv4_addr: [10, 0, 2, 15],
            ipv4_prefix_len: 24,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            max_payload_len: 512,
            socket_capacity: 0,
            note: "n10 unsupported profile".to_string(),
        },
    ));
    assert_eq!(unsupported_profile.status, CommandStatus::Rejected);
    assert_eq!(
        unsupported_profile.violations,
        vec!["network stack adapter profile is unsupported".to_string()]
    );

    let stale_queue = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n10-test",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 1575,
            backend,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 2,
            tx_queue: 1545,
            tx_queue_generation: 1,
            implementation: "smoltcp".to_string(),
            implementation_version: "0.13.0".to_string(),
            profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_string(),
            medium: "ethernet".to_string(),
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            ipv4_addr: [10, 0, 2, 15],
            ipv4_prefix_len: 24,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            max_payload_len: 512,
            socket_capacity: 0,
            note: "n10 stale rx queue".to_string(),
        },
    ));
    assert_eq!(stale_queue.status, CommandStatus::Rejected);
    assert_eq!(
        stale_queue.violations,
        vec!["network stack adapter rx queue generation is missing or inactive".to_string()]
    );

    assert!(graph.record_network_stack_adapter_with_id(
        1575,
        backend,
        1541,
        1,
        1544,
        1,
        1545,
        1,
        "smoltcp",
        "0.13.0",
        "smoltcp-0.13.0-ethernet-ipv4-tcp-v1",
        "ethernet",
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        [10, 0, 2, 15],
        24,
        1500,
        4,
        4,
        512,
        0,
        "n10 smoltcp adapter",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n10-test",
        SemanticCommand::RecordNetworkStackAdapter {
            adapter: 1576,
            backend,
            packet_device: 1541,
            packet_device_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            implementation: "smoltcp".to_string(),
            implementation_version: "0.13.0".to_string(),
            profile: "smoltcp-0.13.0-ethernet-ipv4-tcp-v1".to_string(),
            medium: "ethernet".to_string(),
            mac: [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
            ipv4_addr: [10, 0, 2, 15],
            ipv4_prefix_len: 24,
            mtu: 1500,
            rx_queue_depth: 4,
            tx_queue_depth: 4,
            max_payload_len: 512,
            socket_capacity: 0,
            note: "n10 duplicate adapter".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["network stack adapter packet device already bound".to_string()]
    );
}

#[test]
fn network_runtime_n10_invariants_reject_adapter_profile_drift() {
    let mut graph = setup_n10_network_stack_adapter_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    assert!(graph.record_network_stack_adapter_with_id(
        1575,
        backend,
        1541,
        1,
        1544,
        1,
        1545,
        1,
        "smoltcp",
        "0.13.0",
        "smoltcp-0.13.0-ethernet-ipv4-tcp-v1",
        "ethernet",
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        [10, 0, 2, 15],
        24,
        1500,
        4,
        4,
        512,
        0,
        "n10 smoltcp adapter",
    ));
    graph.corrupt_network_stack_adapter_profile_for_test(1575, "smoltcp-drift");
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkStackAdapterInvalid { adapter: 1575 })
    );
}

fn setup_n11_socket_object_graph() -> (SemanticGraph, StoreId, Generation) {
    let mut graph = setup_n10_network_stack_adapter_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1);
    assert!(graph.record_network_stack_adapter_with_id(
        1575,
        backend,
        1541,
        1,
        1544,
        1,
        1545,
        1,
        "smoltcp",
        "0.13.0",
        "smoltcp-0.13.0-ethernet-ipv4-tcp-v1",
        "ethernet",
        [0x02, 0x76, 0x6d, 0x6f, 0x73, 0x03],
        [10, 0, 2, 15],
        24,
        1500,
        4,
        4,
        512,
        0,
        "n10 smoltcp adapter",
    ));
    let owner_store = graph.register_store(
        "linux_socket_service",
        "linux-socket-service.fake-aot",
        "service",
        "restartable",
    );
    graph.set_store_state(owner_store, StoreState::Running);
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    (graph, owner_store, owner_store_generation)
}

#[test]
fn network_runtime_n11_socket_object_records_adapter_and_store_identity() {
    let (mut graph, owner_store, owner_store_generation) = setup_n11_socket_object_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n11-test",
        SemanticCommand::RecordSocketObject {
            socket: 1576,
            adapter: 1575,
            adapter_generation: 1,
            owner_store,
            owner_store_generation,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            note: "n11 socket object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.socket_object_count(), 1);
    let socket = &graph.socket_objects()[0];
    assert_eq!(
        socket.object_ref(),
        ContractObjectRef::new(ContractObjectKind::SocketObject, 1576, 1)
    );
    assert_eq!(socket.adapter, 1575);
    assert_eq!(socket.adapter_generation, 1);
    assert_eq!(socket.owner_store, owner_store);
    assert_eq!(socket.owner_store_generation, owner_store_generation);
    assert_eq!(socket.domain, 2);
    assert_eq!(socket.socket_type, 1);
    assert_eq!(socket.protocol, 0);
    assert_eq!(socket.canonical_protocol, 6);
    assert_eq!(socket.family, "inet");
    assert_eq!(socket.transport, "tcp");
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("SocketObjectCreated socket=1576 adapter=1575@1")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n11_rejects_stale_adapter_dead_store_and_unsupported_socket() {
    let (mut graph, owner_store, owner_store_generation) = setup_n11_socket_object_graph();
    let stale_adapter = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n11-test",
        SemanticCommand::RecordSocketObject {
            socket: 1576,
            adapter: 1575,
            adapter_generation: 2,
            owner_store,
            owner_store_generation,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            note: "n11 stale adapter".to_string(),
        },
    ));
    assert_eq!(stale_adapter.status, CommandStatus::Rejected);
    assert_eq!(
        stale_adapter.violations,
        vec!["socket object adapter generation is missing or inactive".to_string()]
    );

    let unsupported = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n11-test",
        SemanticCommand::RecordSocketObject {
            socket: 1576,
            adapter: 1575,
            adapter_generation: 1,
            owner_store,
            owner_store_generation,
            domain: 2,
            socket_type: 2,
            protocol: 0,
            note: "n11 unsupported datagram socket".to_string(),
        },
    ));
    assert_eq!(unsupported.status, CommandStatus::Rejected);
    assert_eq!(
        unsupported.violations,
        vec!["socket object contract is unsupported".to_string()]
    );

    graph.set_store_state(owner_store, StoreState::Dead);
    let dead_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let dead_store = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n11-test",
        SemanticCommand::RecordSocketObject {
            socket: 1576,
            adapter: 1575,
            adapter_generation: 1,
            owner_store,
            owner_store_generation: dead_store_generation,
            domain: 2,
            socket_type: 1,
            protocol: 0,
            note: "n11 dead owner store".to_string(),
        },
    ));
    assert_eq!(dead_store.status, CommandStatus::Rejected);
    assert_eq!(
        dead_store.violations,
        vec!["socket object owner store is not live".to_string()]
    );
}

#[test]
fn network_runtime_n11_invariants_reject_socket_adapter_generation_leak() {
    let (mut graph, owner_store, owner_store_generation) = setup_n11_socket_object_graph();
    assert!(graph.record_socket_object_with_id(
        1576,
        1575,
        1,
        owner_store,
        owner_store_generation,
        2,
        1,
        0,
        "n11 socket object",
    ));
    graph.corrupt_socket_object_adapter_generation_for_test(1576, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SocketObjectMissingAdapter {
            socket: 1576,
            adapter: 1575,
        })
    );
}

fn setup_n12_endpoint_object_graph() -> SemanticGraph {
    let (mut graph, owner_store, owner_store_generation) = setup_n11_socket_object_graph();
    assert!(graph.record_socket_object_with_id(
        1576,
        1575,
        1,
        owner_store,
        owner_store_generation,
        2,
        1,
        0,
        "n11 socket object",
    ));
    graph
}

#[test]
fn network_runtime_n12_endpoint_object_records_socket_adapter_and_store_identity() {
    let mut graph = setup_n12_endpoint_object_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n12-test",
        SemanticCommand::RecordEndpointObject {
            endpoint: 1577,
            socket: 1576,
            socket_generation: 1,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12 endpoint object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.endpoint_object_count(), 1);
    let endpoint = &graph.endpoint_objects()[0];
    assert_eq!(
        endpoint.object_ref(),
        ContractObjectRef::new(ContractObjectKind::EndpointObject, 1577, 1)
    );
    assert_eq!(endpoint.socket, 1576);
    assert_eq!(endpoint.socket_generation, 1);
    assert_eq!(endpoint.adapter, 1575);
    assert_eq!(endpoint.adapter_generation, 1);
    assert_eq!(endpoint.family, "inet");
    assert_eq!(endpoint.transport, "tcp");
    assert_eq!(endpoint.local_addr, [0, 0, 0, 0]);
    assert_eq!(endpoint.local_port, 0);
    assert_eq!(endpoint.remote_addr, [0, 0, 0, 0]);
    assert_eq!(endpoint.remote_port, 0);
    assert_eq!(endpoint.state, EndpointObjectState::Allocated);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("EndpointObjectCreated endpoint=1577 socket=1576@1")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n12_rejects_stale_duplicate_and_pre_n13_bound_endpoint() {
    let mut graph = setup_n12_endpoint_object_graph();
    let stale_socket = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n12-test",
        SemanticCommand::RecordEndpointObject {
            endpoint: 1577,
            socket: 1576,
            socket_generation: 2,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12 stale socket".to_string(),
        },
    ));
    assert_eq!(stale_socket.status, CommandStatus::Rejected);
    assert_eq!(
        stale_socket.violations,
        vec!["endpoint object socket generation is missing or inactive".to_string()]
    );

    let pre_bound = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n12-test",
        SemanticCommand::RecordEndpointObject {
            endpoint: 1577,
            socket: 1576,
            socket_generation: 1,
            local_addr: [10, 0, 2, 15],
            local_port: 8080,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12 pre-bound endpoint".to_string(),
        },
    ));
    assert_eq!(pre_bound.status, CommandStatus::Rejected);
    assert_eq!(
        pre_bound.violations,
        vec!["endpoint object must remain unbound before N13".to_string()]
    );

    assert!(graph.record_endpoint_object_with_id(
        1577,
        1576,
        1,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        "n12 endpoint object",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n12-test",
        SemanticCommand::RecordEndpointObject {
            endpoint: 1578,
            socket: 1576,
            socket_generation: 1,
            local_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            note: "n12 duplicate endpoint".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["endpoint object socket generation already has endpoint".to_string()]
    );
}

#[test]
fn network_runtime_n12_invariants_reject_endpoint_socket_generation_leak() {
    let mut graph = setup_n12_endpoint_object_graph();
    assert!(graph.record_endpoint_object_with_id(
        1577,
        1576,
        1,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        "n12 endpoint object",
    ));
    graph.corrupt_endpoint_object_socket_generation_for_test(1577, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::EndpointObjectMissingSocket {
            endpoint: 1577,
            socket: 1576,
        })
    );
}

#[test]
fn network_runtime_n12_invariants_reject_duplicate_endpoint_identity() {
    let mut graph = setup_n12_endpoint_object_graph();
    assert!(graph.record_endpoint_object_with_id(
        1577,
        1576,
        1,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        "n12 endpoint object",
    ));
    graph.duplicate_endpoint_object_id_for_test(1577, 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::EndpointObjectDuplicate { endpoint: 1577 })
    );
}

fn setup_n13_socket_operation_graph() -> (SemanticGraph, EndpointObjectId, EndpointObjectId) {
    let mut graph = setup_n12_endpoint_object_graph();
    assert!(graph.record_endpoint_object_with_id(
        1577,
        1576,
        1,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        "n12 listen endpoint",
    ));
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    assert!(graph.record_socket_object_with_id(
        1580,
        1575,
        1,
        owner_store,
        owner_store_generation,
        2,
        1,
        0,
        "n13 connected socket object",
    ));
    assert!(graph.record_endpoint_object_with_id(
        1581,
        1580,
        1,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        "n13 connected endpoint",
    ));
    (graph, 1577, 1581)
}

#[test]
fn network_runtime_n13_socket_operations_record_listen_and_connected_flows() {
    let (mut graph, listen_endpoint, connected_endpoint) = setup_n13_socket_operation_graph();
    for (offset, command) in [
        SemanticCommand::BindSocketEndpoint {
            operation_id: 1582,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            local_addr: [10, 0, 2, 15],
            local_port: 8080,
            sequence: 1,
            note: "n13 bind listening endpoint".to_string(),
        },
        SemanticCommand::ListenSocketEndpoint {
            operation_id: 1583,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            backlog: 16,
            sequence: 2,
            note: "n13 listen endpoint".to_string(),
        },
        SemanticCommand::BindSocketEndpoint {
            operation_id: 1584,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            local_addr: [10, 0, 2, 15],
            local_port: 40000,
            sequence: 1,
            note: "n13 bind connected endpoint".to_string(),
        },
        SemanticCommand::ConnectSocketEndpoint {
            operation_id: 1585,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            remote_addr: [10, 0, 2, 2],
            remote_port: 80,
            sequence: 2,
            note: "n13 connect endpoint".to_string(),
        },
        SemanticCommand::SendSocket {
            operation_id: 1586,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            byte_len: 18,
            sequence: 3,
            note: "n13 send socket".to_string(),
        },
        SemanticCommand::RecvSocket {
            operation_id: 1587,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            byte_len: 19,
            sequence: 4,
            note: "n13 recv socket".to_string(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let result =
            graph.apply_envelope(CommandEnvelope::new(1 + offset as u64, "n13-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }

    assert_eq!(graph.socket_operation_count(), 6);
    let listen = graph
        .socket_operations()
        .iter()
        .find(|operation| operation.id == 1583)
        .unwrap();
    assert_eq!(listen.operation, SocketOperationKind::Listen);
    assert_eq!(listen.local_addr, [10, 0, 2, 15]);
    assert_eq!(listen.local_port, 8080);
    assert_eq!(listen.backlog, 16);
    let send = graph
        .socket_operations()
        .iter()
        .find(|operation| operation.id == 1586)
        .unwrap();
    assert_eq!(send.operation, SocketOperationKind::Send);
    assert_eq!(send.remote_addr, [10, 0, 2, 2]);
    assert_eq!(send.remote_port, 80);
    assert_eq!(send.byte_len, 18);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("SocketOperationRecorded operation_id=1587 operation=recv")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n13_rejects_invalid_operation_ordering_and_generations() {
    let (mut graph, listen_endpoint, connected_endpoint) = setup_n13_socket_operation_graph();
    let listen_before_bind = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n13-test",
        SemanticCommand::ListenSocketEndpoint {
            operation_id: 1582,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            backlog: 16,
            sequence: 1,
            note: "n13 listen before bind".to_string(),
        },
    ));
    assert_eq!(listen_before_bind.status, CommandStatus::Rejected);
    assert_eq!(
        listen_before_bind.violations,
        vec!["socket listen operation requires bound endpoint".to_string()]
    );

    let stale_endpoint = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n13-test",
        SemanticCommand::BindSocketEndpoint {
            operation_id: 1582,
            endpoint: listen_endpoint,
            endpoint_generation: 2,
            local_addr: [10, 0, 2, 15],
            local_port: 8080,
            sequence: 1,
            note: "n13 stale endpoint".to_string(),
        },
    ));
    assert_eq!(stale_endpoint.status, CommandStatus::Rejected);
    assert_eq!(
        stale_endpoint.violations,
        vec!["socket operation endpoint generation is missing or inactive".to_string()]
    );

    assert!(graph.record_socket_operation_with_id(
        1582,
        listen_endpoint,
        1,
        SocketOperationKind::Bind,
        [10, 0, 2, 15],
        8080,
        [0, 0, 0, 0],
        0,
        0,
        0,
        1,
        "n13 bind listening endpoint",
    ));
    assert!(graph.record_socket_operation_with_id(
        1583,
        listen_endpoint,
        1,
        SocketOperationKind::Listen,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        16,
        0,
        2,
        "n13 listen endpoint",
    ));
    let connect_listening = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n13-test",
        SemanticCommand::ConnectSocketEndpoint {
            operation_id: 1584,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            remote_addr: [10, 0, 2, 2],
            remote_port: 80,
            sequence: 3,
            note: "n13 connect listening endpoint".to_string(),
        },
    ));
    assert_eq!(connect_listening.status, CommandStatus::Rejected);
    assert_eq!(
        connect_listening.violations,
        vec!["socket connect operation requires bound non-listening endpoint".to_string()]
    );

    let send_before_connect = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n13-test",
        SemanticCommand::SendSocket {
            operation_id: 1584,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            byte_len: 18,
            sequence: 1,
            note: "n13 send before connect".to_string(),
        },
    ));
    assert_eq!(send_before_connect.status, CommandStatus::Rejected);
    assert_eq!(
        send_before_connect.violations,
        vec!["socket data operation requires connected endpoint".to_string()]
    );
}

#[test]
fn network_runtime_n13_invariants_reject_socket_operation_sequence_leak() {
    let (mut graph, _, connected_endpoint) = setup_n13_socket_operation_graph();
    assert!(graph.record_socket_operation_with_id(
        1584,
        connected_endpoint,
        1,
        SocketOperationKind::Bind,
        [10, 0, 2, 15],
        40000,
        [0, 0, 0, 0],
        0,
        0,
        0,
        1,
        "n13 bind connected endpoint",
    ));
    assert!(graph.record_socket_operation_with_id(
        1585,
        connected_endpoint,
        1,
        SocketOperationKind::Connect,
        [0, 0, 0, 0],
        0,
        [10, 0, 2, 2],
        80,
        0,
        0,
        2,
        "n13 connect endpoint",
    ));
    graph.corrupt_socket_operation_sequence_for_test(1585, 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SocketOperationOrderingInvalid { operation: 1585 })
    );
}

fn setup_n14_socket_wait_graph() -> (SemanticGraph, EndpointObjectId, EndpointObjectId) {
    let (mut graph, listen_endpoint, connected_endpoint) = setup_n13_socket_operation_graph();
    assert!(graph.record_socket_operation_with_id(
        1582,
        listen_endpoint,
        1,
        SocketOperationKind::Bind,
        [10, 0, 2, 15],
        8080,
        [0, 0, 0, 0],
        0,
        0,
        0,
        1,
        "n14 bind listening endpoint",
    ));
    assert!(graph.record_socket_operation_with_id(
        1583,
        listen_endpoint,
        1,
        SocketOperationKind::Listen,
        [0, 0, 0, 0],
        0,
        [0, 0, 0, 0],
        0,
        16,
        0,
        2,
        "n14 listen endpoint",
    ));
    assert!(graph.record_socket_operation_with_id(
        1584,
        connected_endpoint,
        1,
        SocketOperationKind::Bind,
        [10, 0, 2, 15],
        40000,
        [0, 0, 0, 0],
        0,
        0,
        0,
        1,
        "n14 bind connected endpoint",
    ));
    assert!(graph.record_socket_operation_with_id(
        1585,
        connected_endpoint,
        1,
        SocketOperationKind::Connect,
        [0, 0, 0, 0],
        0,
        [10, 0, 2, 2],
        80,
        0,
        0,
        2,
        "n14 connect endpoint",
    ));
    (graph, listen_endpoint, connected_endpoint)
}

#[test]
fn network_runtime_n14_socket_wait_resolves_and_cancels_wait_tokens() {
    let (mut graph, listen_endpoint, connected_endpoint) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let readable_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);
    let accept_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, listen_endpoint, 1);

    for (offset, command) in [
        SemanticCommand::CreateWait {
            wait: 1588,
            owner_task: None,
            owner_store: Some(owner_store),
            owner_store_generation: Some(owner_store_generation),
            kind: SemanticWaitKind::SocketReadable,
            generation: 1,
            blockers: vec![readable_blocker],
            deadline: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("recv-would-block".to_string()),
        },
        SemanticCommand::RecordSocketWait {
            socket_wait: 1589,
            wait: 1588,
            wait_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            wait_kind: SemanticWaitKind::SocketReadable,
            blocker: readable_blocker,
            note: "n14 readable wait".to_string(),
        },
        SemanticCommand::ResolveSocketWait {
            socket_wait: 1589,
            socket_wait_generation: 1,
            ready_sequence: 1,
            byte_len: 19,
            note: "n14 readable ready".to_string(),
        },
        SemanticCommand::CreateWait {
            wait: 1590,
            owner_task: None,
            owner_store: Some(owner_store),
            owner_store_generation: Some(owner_store_generation),
            kind: SemanticWaitKind::SocketAccept,
            generation: 1,
            blockers: vec![accept_blocker],
            deadline: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("accept-would-block".to_string()),
        },
        SemanticCommand::RecordSocketWait {
            socket_wait: 1591,
            wait: 1590,
            wait_generation: 1,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            wait_kind: SemanticWaitKind::SocketAccept,
            blocker: accept_blocker,
            note: "n14 accept wait".to_string(),
        },
        SemanticCommand::CancelSocketWait {
            socket_wait: 1591,
            socket_wait_generation: 1,
            errno: 9,
            reason: WaitCancelReason::CloseFd,
            note: "n14 close listening socket".to_string(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let result =
            graph.apply_envelope(CommandEnvelope::new(1 + offset as u64, "n14-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }

    assert_eq!(graph.socket_wait_count(), 2);
    assert_eq!(graph.wait_records()[0].state, WaitState::Resolved);
    assert_eq!(graph.wait_records()[1].state, WaitState::Cancelled);
    assert_eq!(graph.socket_waits()[0].state, SocketWaitState::Resolved);
    assert_eq!(graph.socket_waits()[0].ready_sequence, Some(1));
    assert_eq!(graph.socket_waits()[0].byte_len, Some(19));
    assert_eq!(graph.socket_waits()[1].state, SocketWaitState::Cancelled);
    assert_eq!(
        graph.socket_waits()[1].cancel_reason,
        Some(WaitCancelReason::CloseFd)
    );
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("SocketWaitCancelled socket_wait=1591")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n14_accept_wait_can_resolve_without_payload_bytes() {
    let (mut graph, listen_endpoint, _) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let accept_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, listen_endpoint, 1);

    assert!(
        graph
            .apply(SemanticCommand::CreateWait {
                wait: 1592,
                owner_task: None,
                owner_store: Some(owner_store),
                owner_store_generation: Some(owner_store_generation),
                kind: SemanticWaitKind::SocketAccept,
                generation: 1,
                blockers: vec![accept_blocker],
                deadline: None,
                restart_policy: RestartPolicy::RestartIfAllowed,
                saved_context: Some("accept-ready".to_string()),
            })
            .is_ok()
    );
    assert!(
        graph
            .apply(SemanticCommand::RecordSocketWait {
                socket_wait: 1593,
                wait: 1592,
                wait_generation: 1,
                endpoint: listen_endpoint,
                endpoint_generation: 1,
                wait_kind: SemanticWaitKind::SocketAccept,
                blocker: accept_blocker,
                note: "socket accept wait".to_string(),
            })
            .is_ok()
    );
    assert!(
        graph
            .apply(SemanticCommand::ResolveSocketWait {
                socket_wait: 1593,
                socket_wait_generation: 1,
                ready_sequence: 1,
                byte_len: 0,
                note: "accept ready without payload".to_string(),
            })
            .is_ok()
    );

    let socket_wait = graph
        .socket_waits()
        .iter()
        .find(|record| record.id == 1593)
        .unwrap();
    assert_eq!(socket_wait.state, SocketWaitState::Resolved);
    assert_eq!(socket_wait.byte_len, Some(0));
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n14_rejects_wrong_socket_wait_state_and_generation() {
    let (mut graph, listen_endpoint, connected_endpoint) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let listen_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, listen_endpoint, 1);
    let connected_blocker =
        ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);

    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "n14-test",
                SemanticCommand::CreateWait {
                    wait: 1588,
                    owner_task: None,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    kind: SemanticWaitKind::SocketReadable,
                    generation: 1,
                    blockers: vec![listen_blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: None,
                },
            ))
            .status,
        CommandStatus::Applied
    );
    let wrong_endpoint = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n14-test",
        SemanticCommand::RecordSocketWait {
            socket_wait: 1589,
            wait: 1588,
            wait_generation: 1,
            endpoint: listen_endpoint,
            endpoint_generation: 1,
            wait_kind: SemanticWaitKind::SocketReadable,
            blocker: listen_blocker,
            note: "n14 readable wait on listening endpoint".to_string(),
        },
    ));
    assert_eq!(wrong_endpoint.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_endpoint.violations,
        vec!["socket data wait requires connected endpoint".to_string()]
    );

    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                3,
                "n14-test",
                SemanticCommand::CreateWait {
                    wait: 1590,
                    owner_task: None,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    kind: SemanticWaitKind::SocketReadable,
                    generation: 1,
                    blockers: vec![connected_blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: None,
                },
            ))
            .status,
        CommandStatus::Applied
    );
    let stale_endpoint = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n14-test",
        SemanticCommand::RecordSocketWait {
            socket_wait: 1591,
            wait: 1590,
            wait_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 2,
            wait_kind: SemanticWaitKind::SocketReadable,
            blocker: ContractObjectRef::new(
                ContractObjectKind::EndpointObject,
                connected_endpoint,
                2,
            ),
            note: "n14 stale endpoint wait".to_string(),
        },
    ));
    assert_eq!(stale_endpoint.status, CommandStatus::Rejected);
    assert_eq!(
        stale_endpoint.violations,
        vec!["socket wait token does not reference the requested endpoint blocker".to_string()]
    );
}

#[test]
fn network_runtime_n14_invariants_reject_socket_wait_endpoint_generation_leak() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "n14-test",
                SemanticCommand::CreateWait {
                    wait: 1588,
                    owner_task: None,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    kind: SemanticWaitKind::SocketReadable,
                    generation: 1,
                    blockers: vec![blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: None,
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert!(graph.record_socket_wait_with_id(
        1589,
        1588,
        1,
        connected_endpoint,
        1,
        SemanticWaitKind::SocketReadable,
        blocker,
        "n14 readable wait",
    ));
    graph.corrupt_socket_wait_endpoint_generation_for_test(1589, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SocketWaitMissingEndpoint {
            socket_wait: 1589,
            endpoint: connected_endpoint,
        })
    );
}

#[test]
fn network_runtime_n15_backpressure_records_throttle_reject_and_drop_policy() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();

    for (offset, command) in [
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1594,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1544,
            packet_queue_generation: 1,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Rx,
            reason: NetworkBackpressureReason::QueueHighWatermark,
            action: NetworkBackpressureAction::ThrottleProducer,
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 1,
            note: "n15 rx high watermark throttle".to_string(),
        },
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1595,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            endpoint: Some(connected_endpoint),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::RejectSend,
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 2,
            note: "n15 tx reject send at queue limit".to_string(),
        },
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1596,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1544,
            packet_queue_generation: 1,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Rx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::DropNewest,
            queue_depth: 5,
            queue_limit: 4,
            dropped_packets: 1,
            dropped_bytes: 1514,
            sequence: 3,
            note: "n15 rx drop newest when full".to_string(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let result =
            graph.apply_envelope(CommandEnvelope::new(1 + offset as u64, "n15-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }

    assert_eq!(graph.network_backpressure_count(), 3);
    let reject = graph
        .network_backpressures()
        .iter()
        .find(|record| record.id == 1595)
        .unwrap();
    assert_eq!(
        reject.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkBackpressure, 1595, 1)
    );
    assert_eq!(reject.endpoint, Some(connected_endpoint));
    assert_eq!(reject.socket, Some(1580));
    assert_eq!(reject.owner_store, graph.store_id("linux_socket_service"));
    assert_eq!(reject.action, NetworkBackpressureAction::RejectSend);
    assert_eq!(reject.dropped_packets, 0);
    let drop_record = graph
        .network_backpressures()
        .iter()
        .find(|record| record.id == 1596)
        .unwrap();
    assert_eq!(drop_record.action, NetworkBackpressureAction::DropNewest);
    assert_eq!(drop_record.dropped_bytes, 1514);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkBackpressureRecorded backpressure=1596")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n15_rejects_stale_queue_missing_endpoint_and_bad_drop_evidence() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let stale_queue = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n15-test",
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1594,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1544,
            packet_queue_generation: 2,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Rx,
            reason: NetworkBackpressureReason::QueueHighWatermark,
            action: NetworkBackpressureAction::ThrottleProducer,
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 1,
            note: "n15 stale rx queue".to_string(),
        },
    ));
    assert_eq!(stale_queue.status, CommandStatus::Rejected);
    assert_eq!(
        stale_queue.violations,
        vec!["network backpressure packet queue generation is missing or inactive".to_string()]
    );

    let missing_endpoint = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n15-test",
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1594,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Tx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::RejectSend,
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 1,
            note: "n15 reject without endpoint".to_string(),
        },
    ));
    assert_eq!(missing_endpoint.status, CommandStatus::Rejected);
    assert_eq!(
        missing_endpoint.violations,
        vec!["network backpressure reject-send requires endpoint attribution".to_string()]
    );

    let bad_drop = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n15-test",
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1594,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1544,
            packet_queue_generation: 1,
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Rx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::DropNewest,
            queue_depth: 5,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 1514,
            sequence: 1,
            note: "n15 bad drop counters".to_string(),
        },
    ));
    assert_eq!(bad_drop.status, CommandStatus::Rejected);
    assert_eq!(
        bad_drop.violations,
        vec!["network backpressure drop action requires dropped packet evidence".to_string()]
    );

    assert!(graph.record_network_backpressure_with_id(
        1594,
        1575,
        1,
        1541,
        1,
        1545,
        1,
        Some(connected_endpoint),
        Some(1),
        PacketBufferDirection::Tx,
        NetworkBackpressureReason::QueueFull,
        NetworkBackpressureAction::RejectSend,
        4,
        4,
        0,
        0,
        7,
        "n15 first tx reject",
    ));
    let duplicate_sequence = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n15-test",
        SemanticCommand::RecordNetworkBackpressure {
            backpressure: 1595,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            endpoint: Some(connected_endpoint),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            reason: NetworkBackpressureReason::QueueFull,
            action: NetworkBackpressureAction::RejectSend,
            queue_depth: 4,
            queue_limit: 4,
            dropped_packets: 0,
            dropped_bytes: 0,
            sequence: 7,
            note: "n15 duplicate sequence".to_string(),
        },
    ));
    assert_eq!(duplicate_sequence.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate_sequence.violations,
        vec!["network backpressure sequence already exists for queue direction".to_string()]
    );
}

#[test]
fn network_runtime_n15_invariants_reject_packet_queue_generation_leak() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();
    assert!(graph.record_network_backpressure_with_id(
        1594,
        1575,
        1,
        1541,
        1,
        1544,
        1,
        None,
        None,
        PacketBufferDirection::Rx,
        NetworkBackpressureReason::QueueHighWatermark,
        NetworkBackpressureAction::ThrottleProducer,
        4,
        4,
        0,
        0,
        1,
        "n15 rx high watermark throttle",
    ));
    graph.corrupt_network_backpressure_queue_generation_for_test(1594, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkBackpressureMissingQueue {
            backpressure: 1594,
            packet_queue: 1544,
        })
    );
}

#[test]
fn network_runtime_n16_driver_cleanup_cancels_socket_waits_and_revokes_packet_capability() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "n16-test",
                SemanticCommand::CreateWait {
                    wait: 1597,
                    owner_task: None,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    kind: SemanticWaitKind::SocketReadable,
                    generation: 1,
                    blockers: vec![blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: Some("n16 pending recv before driver fault".to_string()),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                2,
                "n16-test",
                SemanticCommand::RecordSocketWait {
                    socket_wait: 1598,
                    wait: 1597,
                    wait_generation: 1,
                    endpoint: connected_endpoint,
                    endpoint_generation: 1,
                    wait_kind: SemanticWaitKind::SocketReadable,
                    blocker,
                    note: "n16 pending socket wait before driver fault".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );

    let result = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n16-test",
        SemanticCommand::CleanupNetworkDriver {
            cleanup: 1599,
            io_cleanup: 1600,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
            reason: "device-fault".to_string(),
            note: "n16 network driver cleanup".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.network_driver_cleanup_count(), 1);
    assert_eq!(graph.io_cleanup_count(), 1);
    let cleanup = &graph.network_driver_cleanups()[0];
    assert_eq!(
        cleanup.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkDriverCleanup, 1599, 1)
    );
    assert_eq!(cleanup.state, NetworkDriverCleanupState::Completed);
    assert_eq!(cleanup.io_cleanup, 1600);
    assert_eq!(cleanup.cancelled_socket_waits.len(), 1);
    assert_eq!(
        cleanup.cancelled_socket_waits[0],
        ContractObjectRef::new(ContractObjectKind::SocketWait, 1598, 1)
    );
    assert_eq!(
        cleanup.cancelled_wait_tokens[0],
        ContractObjectRef::new(ContractObjectKind::WaitToken, 1597, 1)
    );
    assert_eq!(
        cleanup.revoked_packet_capabilities,
        vec![ContractObjectRef::new(
            ContractObjectKind::DeviceCapability,
            1570,
            1
        )]
    );
    let socket_wait = graph
        .socket_waits()
        .iter()
        .find(|record| record.id == 1598)
        .unwrap();
    assert_eq!(socket_wait.state, SocketWaitState::Cancelled);
    assert_eq!(
        socket_wait.cancel_reason,
        Some(WaitCancelReason::DeviceFault)
    );
    assert_eq!(
        graph
            .wait_records()
            .iter()
            .find(|record| record.id == 1597)
            .unwrap()
            .state,
        WaitState::Cancelled
    );
    assert_eq!(
        graph
            .driver_store_bindings()
            .iter()
            .find(|record| record.id == 1552)
            .unwrap()
            .state,
        DriverStoreBindingState::Released
    );
    assert_eq!(
        graph
            .device_capabilities()
            .iter()
            .find(|record| record.id == 1570)
            .unwrap()
            .state,
        DeviceCapabilityState::Revoked
    );
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkDriverCleanupCompleted cleanup=1599")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n16_rejects_stale_adapter_wrong_backend_and_duplicate_io_cleanup() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();

    let stale_adapter = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n16-test",
        SemanticCommand::CleanupNetworkDriver {
            cleanup: 1599,
            io_cleanup: 1600,
            adapter: 1575,
            adapter_generation: 2,
            packet_device: 1541,
            packet_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
            reason: "device-fault".to_string(),
            note: "n16 stale adapter".to_string(),
        },
    ));
    assert_eq!(stale_adapter.status, CommandStatus::Rejected);
    assert_eq!(
        stale_adapter.violations,
        vec!["network driver cleanup adapter generation is missing or inactive".to_string()]
    );

    let wrong_backend = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n16-test",
        SemanticCommand::CleanupNetworkDriver {
            cleanup: 1599,
            io_cleanup: 1600,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::FakeNetBackendObject, 1551, 1),
            reason: "device-fault".to_string(),
            note: "n16 wrong backend".to_string(),
        },
    ));
    assert_eq!(wrong_backend.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_backend.violations,
        vec!["network driver cleanup adapter does not match packet device/backend".to_string()]
    );

    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                3,
                "n16-test",
                SemanticCommand::CleanupNetworkDriver {
                    cleanup: 1599,
                    io_cleanup: 1600,
                    adapter: 1575,
                    adapter_generation: 1,
                    packet_device: 1541,
                    packet_device_generation: 1,
                    backend: ContractObjectRef::new(
                        ContractObjectKind::VirtioNetBackendObject,
                        1553,
                        1
                    ),
                    reason: "device-fault".to_string(),
                    note: "n16 first cleanup".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n16-test",
        SemanticCommand::CleanupNetworkDriver {
            cleanup: 1601,
            io_cleanup: 1600,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
            reason: "device-fault".to_string(),
            note: "n16 duplicate io cleanup".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["network driver cleanup backend driver binding is missing or inactive".to_string()]
    );
}

#[test]
fn network_runtime_n16_invariants_reject_stale_cleanup_effect_generation() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();
    assert!(graph.cleanup_network_driver_with_id(
        1599,
        1600,
        1575,
        1,
        1541,
        1,
        ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
        "device-fault",
        "n16 network driver cleanup",
    ));
    graph.corrupt_network_driver_cleanup_revoked_capability_generation_for_test(1599, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::NetworkDriverCleanupMissingEffectTarget {
                cleanup: 1599,
                target: ContractObjectRef::new(ContractObjectKind::DeviceCapability, 1570, 2),
            }
        )
    );
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

fn add_n17_dma_generation_fixture(
    graph: &mut SemanticGraph,
) -> (
    ContractObjectRef,
    ContractObjectRef,
    CapabilityHandle,
    StoreId,
    Generation,
) {
    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == 1552)
        .cloned()
        .unwrap();
    let dma_resource =
        graph.register_resource(ResourceKind::DmaBuffer, None, "dma:virtio-net2-tx0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_queue_object_with_id(
        1601,
        "virtio-net2-tx-dma",
        QueueObjectRole::Tx,
        1,
        4,
        1540,
        1,
        "n17 dma queue fixture",
    ));
    assert!(graph.record_descriptor_object_with_id(
        1602,
        1601,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        2048,
        "n17 dma descriptor fixture",
    ));
    assert!(graph.record_dma_buffer_object_with_id(
        1603,
        1602,
        1,
        dma_resource,
        dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        2048,
        "n17 dma buffer fixture",
    ));
    let dma_ref = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 1603, 1);
    let dma_capability = graph.grant_capability_with_authority_ref(
        "driver.virtio-net2",
        "dma.virtio-net2.tx0",
        AuthorityObjectRef::internal(CapabilityClass::DmaBuffer, dma_ref),
        &["sync-for-device"],
        "store",
        "n17-test",
        true,
    );
    let dma_handle = graph
        .capabilities()
        .record(dma_capability)
        .and_then(|record| record.store_local_handle(vec!["sync-for-device".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1604,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        dma_ref,
        CapabilityClass::DmaBuffer,
        "sync-for-device",
        dma_handle.clone(),
        "n17 dma capability fixture",
    ));
    (
        dma_ref,
        ContractObjectRef::new(ContractObjectKind::DeviceCapability, 1604, 1),
        dma_handle,
        binding_record.driver_store,
        binding_record.driver_store_generation,
    )
}

#[test]
fn network_runtime_n17_records_stale_packet_dma_generation_audit() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();
    let (dma_ref, dma_capability_ref, dma_handle, driver_store, driver_store_generation) =
        add_n17_dma_generation_fixture(&mut graph);

    let stale_packet_buffer = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n17-test",
        SemanticCommand::RecordPacketDescriptorObject {
            packet_descriptor: 1605,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 2,
            slot: 1,
            length: 64,
            note: "n17 stale packet buffer generation".to_string(),
        },
    ));
    assert_eq!(stale_packet_buffer.status, CommandStatus::Rejected);
    assert_eq!(
        stale_packet_buffer.violations,
        vec!["packet descriptor object buffer generation is missing or inactive".to_string()]
    );

    let stale_packet_descriptor = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n17-test",
        SemanticCommand::RecordNetworkTxCapabilityGate {
            tx_gate: 1606,
            driver_store,
            driver_store_generation,
            packet_descriptor: 1547,
            packet_descriptor_generation: 2,
            device_capability: 1570,
            device_capability_generation: 1,
            handle: graph
                .device_capabilities()
                .iter()
                .find(|record| record.id == 1570)
                .and_then(|record| graph.capabilities().record(record.capability))
                .and_then(|record| record.store_local_handle(vec!["tx".to_string()]))
                .unwrap(),
            note: "n17 stale packet descriptor generation".to_string(),
        },
    ));
    assert_eq!(stale_packet_descriptor.status, CommandStatus::Rejected);
    assert_eq!(
        stale_packet_descriptor.violations,
        vec!["network tx capability gate descriptor generation is missing or inactive".to_string()]
    );

    let stale_dma_target = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n17-test",
        SemanticCommand::RecordDeviceCapability {
            device_capability: 1607,
            driver_store,
            driver_store_generation,
            target: ContractObjectRef::new(ContractObjectKind::DmaBufferObject, dma_ref.id, 2),
            class: CapabilityClass::DmaBuffer,
            operation: "sync-for-device".to_string(),
            handle: dma_handle,
            note: "n17 stale dma buffer generation".to_string(),
        },
    ));
    assert_eq!(stale_dma_target.status, CommandStatus::Rejected);
    assert_eq!(
        stale_dma_target.violations,
        vec!["device capability target generation is missing or inactive".to_string()]
    );

    let audit = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n17-test",
        SemanticCommand::RecordNetworkGenerationAudit {
            audit: 1608,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: 1547,
            packet_descriptor_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            dma_buffer: dma_ref,
            device_capability: dma_capability_ref,
            rejected_packet_generation_probes: 2,
            rejected_dma_generation_probes: 1,
            note: "n17 stale packet and dma generation audit".to_string(),
        },
    ));
    assert_eq!(audit.status, CommandStatus::Applied, "{audit:?}");
    assert_eq!(graph.network_generation_audit_count(), 1);
    let audit = &graph.network_generation_audits()[0];
    assert_eq!(
        audit.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkGenerationAudit, 1608, 1)
    );
    assert_eq!(audit.packet_descriptor_generation, 1);
    assert_eq!(audit.dma_buffer, dma_ref);
    assert_eq!(audit.device_capability, dma_capability_ref);
    assert_eq!(audit.rejected_packet_generation_probes, 2);
    assert_eq!(audit.rejected_dma_generation_probes, 1);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkGenerationAuditRecorded audit=1608")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n17_rejects_missing_probe_counts_and_stale_audit_refs() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();
    let (dma_ref, dma_capability_ref, _, _, _) = add_n17_dma_generation_fixture(&mut graph);

    let missing_packet_probe = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n17-test",
        SemanticCommand::RecordNetworkGenerationAudit {
            audit: 1608,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: 1547,
            packet_descriptor_generation: 1,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            dma_buffer: dma_ref,
            device_capability: dma_capability_ref,
            rejected_packet_generation_probes: 0,
            rejected_dma_generation_probes: 1,
            note: "n17 missing packet probe count".to_string(),
        },
    ));
    assert_eq!(missing_packet_probe.status, CommandStatus::Rejected);
    assert_eq!(
        missing_packet_probe.violations,
        vec!["network generation audit requires rejected packet and dma probes".to_string()]
    );

    let stale_descriptor = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n17-test",
        SemanticCommand::RecordNetworkGenerationAudit {
            audit: 1608,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: 1547,
            packet_descriptor_generation: 2,
            packet_buffer: 1543,
            packet_buffer_generation: 1,
            dma_buffer: dma_ref,
            device_capability: dma_capability_ref,
            rejected_packet_generation_probes: 2,
            rejected_dma_generation_probes: 1,
            note: "n17 stale descriptor ref".to_string(),
        },
    ));
    assert_eq!(stale_descriptor.status, CommandStatus::Rejected);
    assert_eq!(
        stale_descriptor.violations,
        vec![
            "network generation audit packet descriptor generation is missing or inactive"
                .to_string()
        ]
    );
}

#[test]
fn network_runtime_n17_invariants_reject_packet_descriptor_generation_leak() {
    let (mut graph, _, _) = setup_n14_socket_wait_graph();
    let (dma_ref, dma_capability_ref, _, _, _) = add_n17_dma_generation_fixture(&mut graph);
    assert!(graph.record_network_generation_audit_with_id(
        1608,
        1575,
        1,
        1541,
        1,
        1545,
        1,
        1547,
        1,
        1543,
        1,
        dma_ref,
        dma_capability_ref,
        2,
        1,
        "n17 generation audit",
    ));
    graph.corrupt_network_generation_audit_descriptor_generation_for_test(1608, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::NetworkGenerationAuditMissingTarget {
                audit: 1608,
                target: ContractObjectRef::new(ContractObjectKind::PacketDescriptorObject, 1547, 2),
            }
        )
    );
}

#[test]
fn network_runtime_n18_records_packet_loss_and_error_injection() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();

    for (offset, command) in [
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 1609,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: Some(1547),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(1543),
            packet_buffer_generation: Some(1),
            endpoint: Some(connected_endpoint),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketLoss,
            effect: NetworkFaultInjectionEffect::DropPacket,
            injected_packets: 1,
            dropped_packets: 1,
            error_packets: 0,
            error_code: "".to_string(),
            sequence: 8,
            note: "n18 injected tx packet loss".to_string(),
        },
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 1610,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: Some(1547),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(1543),
            packet_buffer_generation: Some(1),
            endpoint: Some(connected_endpoint),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketError,
            effect: NetworkFaultInjectionEffect::ReportError,
            injected_packets: 1,
            dropped_packets: 0,
            error_packets: 1,
            error_code: "injected-checksum-error".to_string(),
            sequence: 9,
            note: "n18 injected tx checksum error".to_string(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let result =
            graph.apply_envelope(CommandEnvelope::new(1 + offset as u64, "n18-test", command));
        assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    }

    assert_eq!(graph.network_fault_injection_count(), 2);
    let loss = graph
        .network_fault_injections()
        .iter()
        .find(|record| record.id == 1609)
        .unwrap();
    assert_eq!(
        loss.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkFaultInjection, 1609, 1)
    );
    assert_eq!(loss.kind, NetworkFaultInjectionKind::PacketLoss);
    assert_eq!(loss.effect, NetworkFaultInjectionEffect::DropPacket);
    assert_eq!(loss.dropped_packets, 1);
    assert_eq!(loss.error_packets, 0);
    assert_eq!(loss.endpoint, Some(connected_endpoint));

    let error = graph
        .network_fault_injections()
        .iter()
        .find(|record| record.id == 1610)
        .unwrap();
    assert_eq!(error.kind, NetworkFaultInjectionKind::PacketError);
    assert_eq!(error.effect, NetworkFaultInjectionEffect::ReportError);
    assert_eq!(error.error_code, "injected-checksum-error");
    assert_eq!(error.packet_descriptor_generation, Some(1));
    assert_eq!(error.packet_buffer_generation, Some(1));
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkFaultInjectionRecorded injection=1610")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n18_rejects_stale_queue_and_malformed_error_injection() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let stale_queue = graph.apply_envelope(CommandEnvelope::new(
        1,
        "n18-test",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 1609,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 2,
            packet_descriptor: Some(1547),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(1543),
            packet_buffer_generation: Some(1),
            endpoint: Some(connected_endpoint),
            endpoint_generation: Some(1),
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketLoss,
            effect: NetworkFaultInjectionEffect::DropPacket,
            injected_packets: 1,
            dropped_packets: 1,
            error_packets: 0,
            error_code: "".to_string(),
            sequence: 8,
            note: "n18 stale packet queue generation".to_string(),
        },
    ));
    assert_eq!(stale_queue.status, CommandStatus::Rejected);
    assert_eq!(
        stale_queue.violations,
        vec!["network fault injection packet queue generation is missing or inactive".to_string()]
    );

    let missing_endpoint = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n18-test",
        SemanticCommand::RecordNetworkFaultInjection {
            injection: 1610,
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            packet_queue: 1545,
            packet_queue_generation: 1,
            packet_descriptor: Some(1547),
            packet_descriptor_generation: Some(1),
            packet_buffer: Some(1543),
            packet_buffer_generation: Some(1),
            endpoint: None,
            endpoint_generation: None,
            direction: PacketBufferDirection::Tx,
            kind: NetworkFaultInjectionKind::PacketError,
            effect: NetworkFaultInjectionEffect::ReportError,
            injected_packets: 1,
            dropped_packets: 0,
            error_packets: 1,
            error_code: "injected-checksum-error".to_string(),
            sequence: 9,
            note: "n18 malformed packet error injection".to_string(),
        },
    ));
    assert_eq!(missing_endpoint.status, CommandStatus::Rejected);
    assert_eq!(
        missing_endpoint.violations,
        vec![
            "network packet error injection requires endpoint, descriptor, buffer, and error code"
                .to_string()
        ]
    );
}

#[test]
fn network_runtime_n18_invariants_reject_packet_queue_generation_leak() {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    assert!(graph.record_network_fault_injection_with_id(
        1609,
        1575,
        1,
        1541,
        1,
        1545,
        1,
        Some(1547),
        Some(1),
        Some(1543),
        Some(1),
        Some(connected_endpoint),
        Some(1),
        PacketBufferDirection::Tx,
        NetworkFaultInjectionKind::PacketLoss,
        NetworkFaultInjectionEffect::DropPacket,
        1,
        1,
        0,
        "",
        8,
        "n18 packet loss injection",
    ));
    graph.corrupt_network_fault_injection_queue_generation_for_test(1609, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkFaultInjectionMissingTarget {
            injection: 1609,
            target: ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1545, 2),
        })
    );
}

fn setup_n19_network_benchmark_graph() -> (SemanticGraph, EndpointObjectId) {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    assert!(graph.record_network_tx_completion_with_id(
        1572,
        1571,
        1,
        ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
        1,
        "n19 tx completion evidence",
    ));
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
        "n19 rx interrupt evidence",
    ));
    let binding_record = graph
        .driver_store_bindings()
        .iter()
        .find(|record| record.id == 1552)
        .cloned()
        .unwrap();
    let rx_queue_ref = ContractObjectRef::new(ContractObjectKind::PacketQueueObject, 1544, 1);
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "n19-setup",
                SemanticCommand::CreateWait {
                    wait: 1611,
                    owner_task: None,
                    owner_store: Some(binding_record.driver_store),
                    owner_store_generation: Some(binding_record.driver_store_generation),
                    kind: SemanticWaitKind::DeviceIrq,
                    generation: 1,
                    blockers: vec![rx_queue_ref],
                    deadline: None,
                    restart_policy: RestartPolicy::InternalOnly,
                    saved_context: Some("n19 rx wait benchmark setup".to_string()),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert!(graph.record_io_wait_with_id(
        1612,
        1611,
        1,
        binding_record.driver_store,
        binding_record.driver_store_generation,
        1540,
        1,
        1552,
        1,
        rx_queue_ref,
        "n19 rx io wait evidence",
    ));
    assert!(graph.resolve_network_rx_wait_with_id(
        1613,
        1612,
        1,
        1556,
        1,
        "n19 rx wait resolution evidence",
    ));
    assert!(graph.record_network_backpressure_with_id(
        1596,
        1575,
        1,
        1541,
        1,
        1544,
        1,
        None,
        None,
        PacketBufferDirection::Rx,
        NetworkBackpressureReason::QueueFull,
        NetworkBackpressureAction::DropNewest,
        5,
        4,
        1,
        1514,
        3,
        "n19 rx drop newest evidence",
    ));
    (graph, connected_endpoint)
}

#[test]
fn network_runtime_n19_benchmark_records_throughput_latency_evidence() {
    let (mut graph, connected_endpoint) = setup_n19_network_benchmark_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n19-test",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 1614,
            scenario: "host-validation-network-throughput-latency".to_string(),
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_completion: 1572,
            tx_completion_generation: 1,
            rx_wait_resolution: 1613,
            rx_wait_resolution_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            backpressure: Some(1596),
            backpressure_generation: Some(1),
            sample_packets: 3,
            sample_bytes: 6000,
            tx_completed_packets: 1,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 120_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19 throughput latency benchmark".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.network_benchmark_count(), 1);
    let benchmark = &graph.network_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkBenchmark, 1614, 1)
    );
    assert_eq!(benchmark.endpoint, connected_endpoint);
    assert_eq!(benchmark.socket, 1580);
    assert_eq!(benchmark.backpressure, Some(1596));
    assert_eq!(benchmark.throughput_bytes_per_sec, 50_000_000);
    assert_eq!(benchmark.p99_latency_nanos, 48_000);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkBenchmarkRecorded benchmark=1614")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n19_rejects_stale_adapter_and_budget_overrun() {
    let (mut graph, connected_endpoint) = setup_n19_network_benchmark_graph();
    let stale_adapter = graph.apply_envelope(CommandEnvelope::new(
        2,
        "n19-test",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 1614,
            scenario: "host-validation-network-throughput-latency".to_string(),
            adapter: 1575,
            adapter_generation: 2,
            packet_device: 1541,
            packet_device_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_completion: 1572,
            tx_completion_generation: 1,
            rx_wait_resolution: 1613,
            rx_wait_resolution_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            backpressure: Some(1596),
            backpressure_generation: Some(1),
            sample_packets: 3,
            sample_bytes: 6000,
            tx_completed_packets: 1,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 120_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19 stale adapter".to_string(),
        },
    ));
    assert_eq!(stale_adapter.status, CommandStatus::Rejected);
    assert_eq!(
        stale_adapter.violations,
        vec!["network benchmark adapter generation is missing or inactive".to_string()]
    );

    let budget_overrun = graph.apply_envelope(CommandEnvelope::new(
        3,
        "n19-test",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 1614,
            scenario: "host-validation-network-throughput-latency".to_string(),
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_completion: 1572,
            tx_completion_generation: 1,
            rx_wait_resolution: 1613,
            rx_wait_resolution_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            backpressure: Some(1596),
            backpressure_generation: Some(1),
            sample_packets: 3,
            sample_bytes: 6000,
            tx_completed_packets: 1,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 260_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19 budget overrun".to_string(),
        },
    ));
    assert_eq!(budget_overrun.status, CommandStatus::Rejected);
    assert_eq!(
        budget_overrun.violations,
        vec!["network benchmark exceeds latency budget".to_string()]
    );

    let packet_accounting_overflow = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n19-test",
        SemanticCommand::RecordNetworkBenchmark {
            benchmark: 1614,
            scenario: "host-validation-network-throughput-latency".to_string(),
            adapter: 1575,
            adapter_generation: 1,
            packet_device: 1541,
            packet_device_generation: 1,
            tx_queue: 1545,
            tx_queue_generation: 1,
            rx_queue: 1544,
            rx_queue_generation: 1,
            tx_completion: 1572,
            tx_completion_generation: 1,
            rx_wait_resolution: 1613,
            rx_wait_resolution_generation: 1,
            endpoint: connected_endpoint,
            endpoint_generation: 1,
            backpressure: Some(1596),
            backpressure_generation: Some(1),
            sample_packets: 1,
            sample_bytes: 6000,
            tx_completed_packets: u32::MAX,
            rx_resolved_packets: 1,
            dropped_packets: 1,
            measured_nanos: 120_000,
            budget_nanos: 250_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 48_000,
            note: "n19 packet accounting overflow".to_string(),
        },
    ));
    assert_eq!(packet_accounting_overflow.status, CommandStatus::Rejected);
    assert_eq!(
        packet_accounting_overflow.violations,
        vec!["network benchmark packet accounting overflow".to_string()]
    );
}

#[test]
fn network_runtime_n19_invariants_reject_throughput_metric_drift() {
    let (mut graph, connected_endpoint) = setup_n19_network_benchmark_graph();
    assert!(graph.record_network_benchmark_with_id(
        1614,
        "host-validation-network-throughput-latency",
        1575,
        1,
        1541,
        1,
        1545,
        1,
        1544,
        1,
        1572,
        1,
        1613,
        1,
        connected_endpoint,
        1,
        Some(1596),
        Some(1),
        3,
        6000,
        1,
        1,
        1,
        120_000,
        250_000,
        18_000,
        48_000,
        "n19 benchmark",
    ));
    graph.corrupt_network_benchmark_throughput_for_test(1614, 49_999_999);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::NetworkBenchmarkInvalid { benchmark: 1614 })
    );
}

fn setup_n20_network_recovery_graph() -> SemanticGraph {
    let (mut graph, _, connected_endpoint) = setup_n14_socket_wait_graph();
    let owner_store = graph.store_id("linux_socket_service").unwrap();
    let owner_store_generation = graph.store_handle(owner_store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::EndpointObject, connected_endpoint, 1);
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "n20-setup",
                SemanticCommand::CreateWait {
                    wait: 1597,
                    owner_task: None,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    kind: SemanticWaitKind::SocketReadable,
                    generation: 1,
                    blockers: vec![blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: Some("n20 pending recv before driver fault".to_string()),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                2,
                "n20-setup",
                SemanticCommand::RecordSocketWait {
                    socket_wait: 1598,
                    wait: 1597,
                    wait_generation: 1,
                    endpoint: connected_endpoint,
                    endpoint_generation: 1,
                    wait_kind: SemanticWaitKind::SocketReadable,
                    blocker,
                    note: "n20 pending socket wait before driver fault".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                3,
                "n20-setup",
                SemanticCommand::RecordNetworkFaultInjection {
                    injection: 1609,
                    adapter: 1575,
                    adapter_generation: 1,
                    packet_device: 1541,
                    packet_device_generation: 1,
                    packet_queue: 1545,
                    packet_queue_generation: 1,
                    packet_descriptor: Some(1547),
                    packet_descriptor_generation: Some(1),
                    packet_buffer: Some(1543),
                    packet_buffer_generation: Some(1),
                    endpoint: Some(connected_endpoint),
                    endpoint_generation: Some(1),
                    direction: PacketBufferDirection::Tx,
                    kind: NetworkFaultInjectionKind::PacketError,
                    effect: NetworkFaultInjectionEffect::ReportError,
                    injected_packets: 1,
                    dropped_packets: 0,
                    error_packets: 1,
                    error_code: "injected-checksum-error".to_string(),
                    sequence: 19,
                    note: "n20 injected packet error before recovery".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert!(graph.cleanup_network_driver_with_id(
        1599,
        1600,
        1575,
        1,
        1541,
        1,
        ContractObjectRef::new(ContractObjectKind::VirtioNetBackendObject, 1553, 1),
        "device-fault",
        "n20 network driver cleanup",
    ));
    graph
}

#[test]
fn network_runtime_n20_recovery_benchmark_records_cleanup_latency_evidence() {
    let mut graph = setup_n20_network_recovery_graph();
    let cleanup = graph.network_driver_cleanups()[0].clone();
    let result = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n20-test",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 1615,
            scenario: "host-validation-network-driver-recovery".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(1609),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup.completed_at_event.unwrap(),
            cancelled_socket_waits: cleanup.cancelled_socket_waits.len() as u32,
            revoked_packet_capabilities: cleanup.revoked_packet_capabilities.len() as u32,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            note: "n20 recovery benchmark".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.network_recovery_benchmark_count(), 1);
    let benchmark = &graph.network_recovery_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::NetworkRecoveryBenchmark, 1615, 1)
    );
    assert_eq!(benchmark.cleanup, 1599);
    assert_eq!(benchmark.io_cleanup, 1600);
    assert_eq!(benchmark.fault_injection, Some(1609));
    assert_eq!(benchmark.cancelled_socket_waits, 1);
    assert_eq!(benchmark.revoked_packet_capabilities, 1);
    assert_eq!(benchmark.recovery_nanos, 90_000);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("NetworkRecoveryBenchmarkRecorded benchmark=1615")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn network_runtime_n20_rejects_stale_cleanup_and_budget_overrun() {
    let mut graph = setup_n20_network_recovery_graph();
    let cleanup = graph.network_driver_cleanups()[0].clone();
    let stale_cleanup = graph.apply_envelope(CommandEnvelope::new(
        4,
        "n20-test",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 1615,
            scenario: "host-validation-network-driver-recovery".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation.saturating_add(1),
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(1609),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup.completed_at_event.unwrap(),
            cancelled_socket_waits: cleanup.cancelled_socket_waits.len() as u32,
            revoked_packet_capabilities: cleanup.revoked_packet_capabilities.len() as u32,
            recovery_nanos: 90_000,
            budget_nanos: 200_000,
            note: "n20 stale cleanup generation".to_string(),
        },
    ));
    assert_eq!(stale_cleanup.status, CommandStatus::Rejected);
    assert_eq!(
        stale_cleanup.violations,
        vec!["network recovery benchmark cleanup generation is missing or incomplete".to_string()]
    );

    let budget_overrun = graph.apply_envelope(CommandEnvelope::new(
        5,
        "n20-test",
        SemanticCommand::RecordNetworkRecoveryBenchmark {
            benchmark: 1615,
            scenario: "host-validation-network-driver-recovery".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            fault_injection: Some(1609),
            fault_injection_generation: Some(1),
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: cleanup.completed_at_event.unwrap(),
            cancelled_socket_waits: cleanup.cancelled_socket_waits.len() as u32,
            revoked_packet_capabilities: cleanup.revoked_packet_capabilities.len() as u32,
            recovery_nanos: 210_000,
            budget_nanos: 200_000,
            note: "n20 recovery budget overrun".to_string(),
        },
    ));
    assert_eq!(budget_overrun.status, CommandStatus::Rejected);
    assert_eq!(
        budget_overrun.violations,
        vec!["network recovery benchmark exceeds recovery budget".to_string()]
    );
}

#[test]
fn network_runtime_n20_invariants_reject_cleanup_generation_drift() {
    let mut graph = setup_n20_network_recovery_graph();
    let cleanup = graph.network_driver_cleanups()[0].clone();
    assert!(graph.record_network_recovery_benchmark_with_id(
        1615,
        "host-validation-network-driver-recovery",
        cleanup.id,
        cleanup.generation,
        cleanup.io_cleanup,
        cleanup.io_cleanup_generation,
        Some(1609),
        Some(1),
        cleanup.started_at_event,
        cleanup.completed_at_event.unwrap(),
        cleanup.cancelled_socket_waits.len() as u32,
        cleanup.revoked_packet_capabilities.len() as u32,
        90_000,
        200_000,
        "n20 recovery benchmark",
    ));
    graph.corrupt_network_recovery_benchmark_cleanup_generation_for_test(1615, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::NetworkRecoveryBenchmarkMissingTarget {
                benchmark: 1615,
                target: ContractObjectRef::new(ContractObjectKind::NetworkDriverCleanup, 1599, 2),
            }
        )
    );
}

#[test]
fn block_runtime_b0_block_device_object_records_contract_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1701,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b0 backing device",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b0-test",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 1702,
            name: "blk0".to_string(),
            device: 1701,
            device_generation: 1,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0 block device object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_device_object_count(), 1);
    let block_device = &graph.block_device_objects()[0];
    assert_eq!(
        block_device.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockDeviceObject, 1702, 1)
    );
    assert_eq!(block_device.device, 1701);
    assert_eq!(block_device.device_generation, 1);
    assert_eq!(block_device.sector_size, 512);
    assert_eq!(block_device.sector_count, 4096);
    assert_eq!(block_device.max_transfer_sectors, 128);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockDeviceObjectRecorded block_device=1702 device=1701@1 sector_size=512 sector_count=4096 read_only=false max_transfer_sectors=128 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b0_rejects_stale_or_non_block_device() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Device, None, "device:not-block");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1703,
        "not-block0",
        "fake-device",
        resource,
        resource_generation,
        "fake-io-backend",
        "semantic-harness",
        "vmos",
        "fake-io-v1",
        "b0 wrong backing device",
    ));

    let wrong_class = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b0-test",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 1704,
            name: "blk0".to_string(),
            device: 1703,
            device_generation: 1,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0 wrong class".to_string(),
        },
    ));
    assert_eq!(wrong_class.status, CommandStatus::Rejected);

    let block_resource =
        graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk1");
    let block_resource_generation = graph.resource_handle(block_resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1705,
        "fake-block1",
        "block-device",
        block_resource,
        block_resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b0 stale backing device",
    ));
    let stale = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b0-test",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 1706,
            name: "blk1".to_string(),
            device: 1705,
            device_generation: 2,
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0 stale generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let bad_contract = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b0-test",
        SemanticCommand::RecordBlockDeviceObject {
            block_device: 1709,
            name: "blk1".to_string(),
            device: 1705,
            device_generation: 1,
            sector_size: 0,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            note: "b0 bad sector size".to_string(),
        },
    ));
    assert_eq!(bad_contract.status, CommandStatus::Rejected);
}

#[test]
fn block_runtime_b0_invariants_reject_block_device_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1707,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b0 invariant backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1708,
        "blk0",
        1707,
        1,
        512,
        4096,
        false,
        128,
        "b0 invariant block device",
    ));
    graph.corrupt_block_device_object_device_generation_for_test(1708, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockDeviceObjectMissingDevice {
            block_device: 1708,
            device: 1707,
        })
    );
}

#[test]
fn block_runtime_b1_block_range_records_sector_and_byte_bounds() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1710,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b1 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1711,
        "blk0",
        1710,
        1,
        512,
        4096,
        false,
        128,
        "b1 block device",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b1-test",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 1712,
            block_device: 1711,
            block_device_generation: 1,
            start_sector: 64,
            sector_count: 8,
            note: "b1 range".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_range_object_count(), 1);
    let block_range = &graph.block_range_objects()[0];
    assert_eq!(
        block_range.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockRangeObject, 1712, 1)
    );
    assert_eq!(block_range.block_device, 1711);
    assert_eq!(block_range.block_device_generation, 1);
    assert_eq!(block_range.start_sector, 64);
    assert_eq!(block_range.sector_count, 8);
    assert_eq!(block_range.byte_offset, 32768);
    assert_eq!(block_range.byte_len, 4096);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockRangeObjectRecorded block_range=1712 block_device=1711@1 start_sector=64 sector_count=8 byte_offset=32768 byte_len=4096 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b1_rejects_stale_out_of_bounds_and_over_transfer_ranges() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1713,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b1 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1714,
        "blk0",
        1713,
        1,
        512,
        4096,
        false,
        128,
        "b1 block device",
    ));

    let stale = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b1-test",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 1715,
            block_device: 1714,
            block_device_generation: 2,
            start_sector: 64,
            sector_count: 8,
            note: "b1 stale device generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let out_of_bounds = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b1-test",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 1716,
            block_device: 1714,
            block_device_generation: 1,
            start_sector: 4090,
            sector_count: 16,
            note: "b1 out of bounds".to_string(),
        },
    ));
    assert_eq!(out_of_bounds.status, CommandStatus::Rejected);

    let over_transfer = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b1-test",
        SemanticCommand::RecordBlockRangeObject {
            block_range: 1717,
            block_device: 1714,
            block_device_generation: 1,
            start_sector: 128,
            sector_count: 129,
            note: "b1 over transfer".to_string(),
        },
    ));
    assert_eq!(over_transfer.status, CommandStatus::Rejected);
}

#[test]
fn block_runtime_b1_invariants_reject_block_range_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1718,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b1 invariant backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1719,
        "blk0",
        1718,
        1,
        512,
        4096,
        false,
        128,
        "b1 invariant block device",
    ));
    assert!(graph.record_block_range_object_with_id(1720, 1719, 1, 64, 8, "b1 invariant range",));
    graph.corrupt_block_range_object_device_generation_for_test(1720, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRangeObjectMissingDevice {
            block_range: 1720,
            block_device: 1719,
        })
    );
}

#[test]
fn block_runtime_b2_block_request_records_range_identity() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1721,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b2 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1722,
        "blk0",
        1721,
        1,
        512,
        4096,
        false,
        128,
        "b2 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1723, 1722, 1, 64, 8, "b2 range",));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b2-test",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 1724,
            block_device: 1722,
            block_device_generation: 1,
            block_range: 1723,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 1,
            note: "b2 request".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_request_object_count(), 1);
    let request = &graph.block_request_objects()[0];
    assert_eq!(
        request.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1724, 1)
    );
    assert_eq!(request.block_device, 1722);
    assert_eq!(request.block_device_generation, 1);
    assert_eq!(request.block_range, 1723);
    assert_eq!(request.block_range_generation, 1);
    assert_eq!(request.operation, BlockRequestOperation::Read);
    assert_eq!(request.sequence, 1);
    assert_eq!(request.byte_len, 4096);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockRequestObjectRecorded block_request=1724 block_device=1722@1 block_range=1723@1 operation=read sequence=1 byte_len=4096 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b2_rejects_stale_duplicate_and_read_only_write() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1725,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b2 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1726,
        "blk0",
        1725,
        1,
        512,
        4096,
        true,
        128,
        "b2 read-only block device",
    ));
    assert!(graph.record_block_range_object_with_id(1727, 1726, 1, 64, 8, "b2 range",));
    assert!(graph.record_block_request_object_with_id(
        1728,
        1726,
        1,
        1727,
        1,
        BlockRequestOperation::Read,
        1,
        "b2 existing read",
    ));

    let stale_range = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b2-test",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 1729,
            block_device: 1726,
            block_device_generation: 1,
            block_range: 1727,
            block_range_generation: 2,
            operation: BlockRequestOperation::Read,
            sequence: 2,
            note: "b2 stale range".to_string(),
        },
    ));
    assert_eq!(stale_range.status, CommandStatus::Rejected);

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b2-test",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 1730,
            block_device: 1726,
            block_device_generation: 1,
            block_range: 1727,
            block_range_generation: 1,
            operation: BlockRequestOperation::Read,
            sequence: 1,
            note: "b2 duplicate sequence".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);

    let write_read_only = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b2-test",
        SemanticCommand::RecordBlockRequestObject {
            block_request: 1731,
            block_device: 1726,
            block_device_generation: 1,
            block_range: 1727,
            block_range_generation: 1,
            operation: BlockRequestOperation::Write,
            sequence: 3,
            note: "b2 write read-only".to_string(),
        },
    ));
    assert_eq!(write_read_only.status, CommandStatus::Rejected);
}

#[test]
fn block_runtime_b2_invariants_reject_block_request_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1732,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b2 invariant backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1733,
        "blk0",
        1732,
        1,
        512,
        4096,
        false,
        128,
        "b2 invariant block device",
    ));
    assert!(graph.record_block_range_object_with_id(1734, 1733, 1, 64, 8, "b2 invariant range",));
    assert!(graph.record_block_request_object_with_id(
        1735,
        1733,
        1,
        1734,
        1,
        BlockRequestOperation::Read,
        1,
        "b2 invariant request",
    ));
    graph.corrupt_block_request_range_generation_for_test(1735, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRequestObjectMissingRange {
            block_request: 1735,
            block_range: 1734,
        })
    );
}

#[test]
fn block_runtime_b3_block_completion_records_request_outcome() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1736,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b3 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1737,
        "blk0",
        1736,
        1,
        512,
        4096,
        false,
        128,
        "b3 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1738, 1737, 1, 64, 8, "b3 range",));
    assert!(graph.record_block_request_object_with_id(
        1739,
        1737,
        1,
        1738,
        1,
        BlockRequestOperation::Read,
        1,
        "b3 request",
    ));

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b3-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1740,
            block_request: 1739,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3 completion".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_completion_object_count(), 1);
    let completion = &graph.block_completion_objects()[0];
    assert_eq!(
        completion.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockCompletionObject, 1740, 1)
    );
    assert_eq!(completion.block_request, 1739);
    assert_eq!(completion.block_request_generation, 1);
    assert_eq!(completion.block_device, 1737);
    assert_eq!(completion.block_range, 1738);
    assert_eq!(completion.sequence, 1);
    assert_eq!(completion.completed_bytes, 4096);
    assert_eq!(completion.status, BlockCompletionStatus::Success);
    assert_eq!(
        graph.block_request_objects()[0].state,
        BlockRequestObjectState::Completed
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockCompletionObjectRecorded block_completion=1740 block_request=1739@1 block_device=1737@1 block_range=1738@1 sequence=1 completed_bytes=4096 status=success generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b3_rejects_stale_duplicate_and_bad_byte_count() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1741,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b3 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1742,
        "blk0",
        1741,
        1,
        512,
        4096,
        false,
        128,
        "b3 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1743, 1742, 1, 64, 8, "b3 range",));
    assert!(graph.record_block_request_object_with_id(
        1744,
        1742,
        1,
        1743,
        1,
        BlockRequestOperation::Read,
        1,
        "b3 existing request",
    ));

    let stale_request = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b3-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1745,
            block_request: 1744,
            block_request_generation: 2,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3 stale request".to_string(),
        },
    ));
    assert_eq!(stale_request.status, CommandStatus::Rejected);

    let completion = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b3-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1746,
            block_request: 1744,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3 completion".to_string(),
        },
    ));
    assert_eq!(completion.status, CommandStatus::Applied);

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b3-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1747,
            block_request: 1744,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b3 duplicate completion".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);

    assert!(graph.record_block_request_object_with_id(
        1748,
        1742,
        1,
        1743,
        1,
        BlockRequestOperation::Read,
        2,
        "b3 second request",
    ));
    let partial_success = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b3-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1749,
            block_request: 1748,
            block_request_generation: 1,
            sequence: 2,
            completed_bytes: 2048,
            status: BlockCompletionStatus::Success,
            note: "b3 partial success".to_string(),
        },
    ));
    assert_eq!(partial_success.status, CommandStatus::Rejected);
}

#[test]
fn block_runtime_b3_invariants_reject_completion_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1750,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b3 invariant backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1751,
        "blk0",
        1750,
        1,
        512,
        4096,
        false,
        128,
        "b3 invariant block device",
    ));
    assert!(graph.record_block_range_object_with_id(1752, 1751, 1, 64, 8, "b3 invariant range",));
    assert!(graph.record_block_request_object_with_id(
        1753,
        1751,
        1,
        1752,
        1,
        BlockRequestOperation::Read,
        1,
        "b3 invariant request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1754,
        1753,
        1,
        1,
        4096,
        BlockCompletionStatus::Success,
        "b3 invariant completion",
    ));
    graph.corrupt_block_completion_request_generation_for_test(1754, 2);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRequestObjectInvalid {
            block_request: 1753,
        })
    );
}

#[test]
fn block_runtime_b4_block_wait_bridges_wait_token_to_completion() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1755,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b4 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1756,
        "blk0",
        1755,
        1,
        512,
        4096,
        false,
        128,
        "b4 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1757, 1756, 1, 64, 8, "b4 range",));
    assert!(graph.record_block_request_object_with_id(
        1758,
        1756,
        1,
        1757,
        1,
        BlockRequestOperation::Read,
        1,
        "b4 request",
    ));
    let driver_store = graph.register_store(
        "driver.fake-block0",
        "driver.fake-block0.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1758, 1);
    let create_wait = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b4-test",
        SemanticCommand::CreateWait {
            wait: 1759,
            owner_task: None,
            owner_store: Some(driver_store),
            owner_store_generation: Some(driver_store_generation),
            kind: SemanticWaitKind::DriverCompletion,
            generation: 1,
            blockers: vec![blocker],
            deadline: None,
            restart_policy: RestartPolicy::InternalOnly,
            saved_context: Some("b4-block-wait".to_string()),
        },
    ));
    assert_eq!(create_wait.status, CommandStatus::Applied);

    let record_wait = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b4-test",
        SemanticCommand::RecordBlockWait {
            block_wait: 1760,
            wait: 1759,
            wait_generation: 1,
            block_request: 1758,
            block_request_generation: 1,
            note: "b4 block wait".to_string(),
        },
    ));
    assert_eq!(record_wait.status, CommandStatus::Applied);
    assert_eq!(graph.block_wait_count(), 1);
    assert_eq!(
        graph.block_waits()[0].object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockWait, 1760, 1)
    );
    assert_eq!(graph.block_waits()[0].wait, 1759);
    assert_eq!(graph.block_waits()[0].block_request, 1758);
    assert_eq!(graph.block_waits()[0].state, BlockWaitState::Pending);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockWaitCreated block_wait=1760 wait=1759@1 block_request=1758@1 block_device=1756@1 block_range=1757@1 operation=read sequence=1 byte_len=4096 generation=1"
    );

    let completion = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b4-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1761,
            block_request: 1758,
            block_request_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b4 completion".to_string(),
        },
    ));
    assert_eq!(completion.status, CommandStatus::Applied);
    let resolve_wait = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b4-test",
        SemanticCommand::ResolveBlockWait {
            block_wait: 1760,
            block_wait_generation: 1,
            block_completion: 1761,
            block_completion_generation: 1,
            note: "b4 resolve block wait".to_string(),
        },
    ));
    assert_eq!(resolve_wait.status, CommandStatus::Applied);
    assert_eq!(graph.block_waits()[0].state, BlockWaitState::Resolved);
    assert_eq!(graph.block_waits()[0].completion, Some(1761));
    assert_eq!(graph.wait_records()[0].state, WaitState::Resolved);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockWaitResolved block_wait=1760 wait=1759@1 block_completion=1761@1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b4_rejects_stale_duplicate_and_bad_completion_waits() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1762,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b4 reject backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1763,
        "blk0",
        1762,
        1,
        512,
        4096,
        false,
        128,
        "b4 reject block device",
    ));
    assert!(graph.record_block_range_object_with_id(1764, 1763, 1, 64, 8, "b4 reject range",));
    assert!(graph.record_block_request_object_with_id(
        1765,
        1763,
        1,
        1764,
        1,
        BlockRequestOperation::Read,
        1,
        "b4 reject request",
    ));
    let driver_store = graph.register_store(
        "driver.fake-block1",
        "driver.fake-block1.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1765, 1);
    assert!(matches!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "b4-test",
                SemanticCommand::CreateWait {
                    wait: 1766,
                    owner_task: None,
                    owner_store: Some(driver_store),
                    owner_store_generation: Some(driver_store_generation),
                    kind: SemanticWaitKind::DriverCompletion,
                    generation: 1,
                    blockers: vec![blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::InternalOnly,
                    saved_context: None,
                },
            ))
            .status,
        CommandStatus::Applied
    ));
    assert!(graph.record_block_wait_with_id(1767, 1766, 1, 1765, 1, "b4 existing wait"));

    let stale_request = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b4-test",
        SemanticCommand::RecordBlockWait {
            block_wait: 1768,
            wait: 1766,
            wait_generation: 1,
            block_request: 1765,
            block_request_generation: 2,
            note: "b4 stale request".to_string(),
        },
    ));
    assert_eq!(stale_request.status, CommandStatus::Rejected);

    let duplicate_wait = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b4-test",
        SemanticCommand::RecordBlockWait {
            block_wait: 1769,
            wait: 1766,
            wait_generation: 1,
            block_request: 1765,
            block_request_generation: 1,
            note: "b4 duplicate wait".to_string(),
        },
    ));
    assert_eq!(duplicate_wait.status, CommandStatus::Rejected);

    assert!(graph.record_block_request_object_with_id(
        1770,
        1763,
        1,
        1764,
        1,
        BlockRequestOperation::Read,
        2,
        "b4 other request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1771,
        1770,
        1,
        2,
        4096,
        BlockCompletionStatus::Success,
        "b4 other completion",
    ));
    let wrong_completion = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b4-test",
        SemanticCommand::ResolveBlockWait {
            block_wait: 1767,
            block_wait_generation: 1,
            block_completion: 1771,
            block_completion_generation: 1,
            note: "b4 wrong completion".to_string(),
        },
    ));
    assert_eq!(wrong_completion.status, CommandStatus::Rejected);

    graph.record_wait_resolved(1766, "b4-direct-wait-resolution");
    let stale_wait_state = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b4-test",
        SemanticCommand::CancelBlockWait {
            block_wait: 1767,
            block_wait_generation: 1,
            errno: 5,
            reason: WaitCancelReason::DeviceFault,
            note: "b4 stale wait state".to_string(),
        },
    ));
    assert_eq!(stale_wait_state.status, CommandStatus::Rejected);
}

#[test]
fn block_runtime_b4_cancelled_wait_records_reason_and_invariant_generation() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1772,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b4 cancel backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1773,
        "blk0",
        1772,
        1,
        512,
        4096,
        false,
        128,
        "b4 cancel block device",
    ));
    assert!(graph.record_block_range_object_with_id(1774, 1773, 1, 64, 8, "b4 cancel range",));
    assert!(graph.record_block_request_object_with_id(
        1775,
        1773,
        1,
        1774,
        1,
        BlockRequestOperation::Read,
        1,
        "b4 cancel request",
    ));
    let driver_store = graph.register_store(
        "driver.fake-block2",
        "driver.fake-block2.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    graph.record_wait_created_with_details(
        1776,
        None,
        Some(driver_store),
        Some(driver_store_generation),
        SemanticWaitKind::DriverCompletion,
        1,
        vec![ContractObjectRef::new(
            ContractObjectKind::BlockRequestObject,
            1775,
            1,
        )],
        None,
        RestartPolicy::InternalOnly,
        None,
    );
    assert!(graph.record_block_wait_with_id(1777, 1776, 1, 1775, 1, "b4 cancel wait"));
    let cancel = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b4-test",
        SemanticCommand::CancelBlockWait {
            block_wait: 1777,
            block_wait_generation: 1,
            errno: 5,
            reason: WaitCancelReason::DeviceFault,
            note: "b4 cancel block wait".to_string(),
        },
    ));
    assert_eq!(cancel.status, CommandStatus::Applied);
    assert_eq!(graph.block_waits()[0].state, BlockWaitState::Cancelled);
    assert_eq!(
        graph.block_waits()[0].cancel_reason,
        Some(WaitCancelReason::DeviceFault)
    );
    assert_eq!(graph.wait_records()[0].state, WaitState::Cancelled);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockWaitCancelled block_wait=1777 wait=1776@1 reason=device-fault generation=1"
    );
    assert!(graph.check_invariants().is_ok());

    graph.corrupt_block_wait_request_generation_for_test(1777, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockWaitMissingRequest {
            block_wait: 1777,
            block_request: 1775,
        })
    );
}

#[test]
fn block_runtime_b5_fake_block_backend_binds_exact_block_device_contract() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1778,
        "fake-block0",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b5 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1779,
        "blk0",
        1778,
        1,
        512,
        4096,
        false,
        128,
        "b5 block device",
    ));

    let command = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b5-test",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 1780,
            name: "fake-block0".to_string(),
            block_device: 1779,
            block_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-block-v1".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            deterministic_seed: 0x766d_6f73_626c_6b31,
            note: "b5 bind fake block backend".to_string(),
        },
    ));
    assert_eq!(command.status, CommandStatus::Applied);
    assert_eq!(graph.fake_block_backend_object_count(), 1);
    let backend = &graph.fake_block_backends()[0];
    assert_eq!(
        backend.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1780, 1)
    );
    assert_eq!(backend.block_device, 1779);
    assert_eq!(backend.block_device_generation, 1);
    assert_eq!(backend.state, FakeBlockBackendObjectState::Bound);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FakeBlockBackendObjectBound fake_block_backend=1780 block_device=1779@1 sector_size=512 sector_count=4096 read_only=false max_transfer_sectors=128 deterministic_seed=8533599410300152625 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b5_rejects_stale_duplicate_and_mismatched_backends() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk1");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1781,
        "fake-block1",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b5 reject backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1782,
        "blk1",
        1781,
        1,
        512,
        4096,
        false,
        128,
        "b5 reject block device",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1783,
        "fake-block1",
        1782,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b31,
        "b5 existing backend",
    ));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b5-test",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 1784,
            name: "fake-block1-duplicate".to_string(),
            block_device: 1782,
            block_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-block-v1".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            deterministic_seed: 0x766d_6f73_626c_6b31,
            note: "b5 duplicate backend".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);

    let stale = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b5-test",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 1785,
            name: "fake-block1-stale".to_string(),
            block_device: 1782,
            block_device_generation: 2,
            provider: "service_core".to_string(),
            profile: "fake-block-v1".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            deterministic_seed: 0x766d_6f73_626c_6b31,
            note: "b5 stale backend".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);

    let mismatch = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b5-test",
        SemanticCommand::RecordFakeBlockBackendObject {
            fake_block_backend: 1786,
            name: "fake-block1-mismatch".to_string(),
            block_device: 1782,
            block_device_generation: 1,
            provider: "service_core".to_string(),
            profile: "fake-block-v1".to_string(),
            sector_size: 512,
            sector_count: 8192,
            read_only: false,
            max_transfer_sectors: 128,
            deterministic_seed: 0x766d_6f73_626c_6b31,
            note: "b5 mismatched backend".to_string(),
        },
    ));
    assert_eq!(mismatch.status, CommandStatus::Rejected);
}

#[test]
fn block_runtime_b5_invariants_reject_fake_backend_generation_leak() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk2");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1787,
        "fake-block2",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b5 invariant backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1788,
        "blk2",
        1787,
        1,
        512,
        4096,
        false,
        128,
        "b5 invariant block device",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1789,
        "fake-block2",
        1788,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b31,
        "b5 invariant backend",
    ));
    graph.corrupt_fake_block_backend_block_device_generation_for_test(1789, 2);
    assert!(matches!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::FakeBlockBackendObjectMissingBlockDevice {
                fake_block_backend: 1789,
                block_device: 1788,
            }
        ),
    ));
}

fn setup_b6_virtio_blk_backend_graph() -> (SemanticGraph, DriverStoreBindingId) {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:vblk0");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1790,
        "virtio-blk0",
        "block-device",
        resource,
        resource_generation,
        "virtio-blk-backend-skeleton",
        "virtio-mmio",
        "virtio",
        "virtio-blk",
        "b6 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1791,
        "vblk0",
        1790,
        1,
        512,
        4096,
        false,
        128,
        "b6 block device",
    ));
    let driver_store = graph.register_store(
        "driver.virtio-blk0",
        "driver_virtio_blk.fake-aot",
        "driver",
        "restartable",
    );
    graph.set_store_state(driver_store, StoreState::Running);
    let driver_store_generation = graph.store_handle(driver_store).unwrap().generation;
    let device_ref = ContractObjectRef::new(ContractObjectKind::DeviceObject, 1790, 1);
    let cap = graph.grant_capability_with_authority_ref(
        "driver.virtio-blk0",
        "device.virtio-blk0",
        AuthorityObjectRef::internal(CapabilityClass::Device, device_ref),
        &["probe"],
        "store",
        "b6-test",
        true,
    );
    let handle = graph
        .capabilities()
        .record(cap)
        .and_then(|record| record.store_local_handle(vec!["probe".to_string()]))
        .unwrap();
    assert!(graph.record_device_capability_with_id(
        1792,
        driver_store,
        driver_store_generation,
        device_ref,
        CapabilityClass::Device,
        "probe",
        handle,
        "b6 device probe capability",
    ));
    assert!(graph.record_driver_store_binding_with_id(
        1793,
        driver_store,
        driver_store_generation,
        1790,
        1,
        1792,
        1,
        "b6 virtio block driver binding",
    ));
    (graph, 1793)
}

#[test]
fn block_runtime_b6_virtio_blk_backend_skeleton_binds_driver_and_block_device() {
    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 virtio block backend skeleton".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.virtio_blk_backend_object_count(), 1);
    let backend = &graph.virtio_blk_backends()[0];
    assert_eq!(
        backend.object_ref(),
        ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, 1794, 1)
    );
    assert_eq!(backend.block_device, 1791);
    assert_eq!(backend.block_device_generation, 1);
    assert_eq!(backend.driver_binding, binding);
    assert_eq!(backend.driver_binding_generation, 1);
    assert_eq!(backend.device, 1790);
    assert_eq!(backend.device_generation, 1);
    assert_eq!(backend.provider, "substrate_virtio");
    assert_eq!(backend.profile, "virtio-blk-backend-skeleton-v1");
    assert_eq!(backend.model, "virtio-blk");
    assert_eq!(backend.negotiated_features, 64);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "VirtioBlkBackendSkeletonBound virtio_blk_backend=1794 block_device=1791@1 driver_binding=1793@1 device=1790@1 queue_size=8 request_queue_index=0 negotiated_features=64 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b6_rejects_stale_duplicate_and_invalid_virtio_blk_backends() {
    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    let stale_block_device = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 2,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 stale block device".to_string(),
        },
    ));
    assert_eq!(stale_block_device.status, CommandStatus::Rejected);
    assert_eq!(
        stale_block_device.violations,
        vec![
            "virtio block backend object block device generation is missing or inactive"
                .to_string()
        ]
    );

    let stale_binding = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 2,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 stale binding".to_string(),
        },
    ));
    assert_eq!(stale_binding.status, CommandStatus::Rejected);
    assert_eq!(
        stale_binding.violations,
        vec![
            "virtio block backend object driver binding generation is missing or inactive"
                .to_string()
        ]
    );

    let bad_provider = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "service_core".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 bad provider".to_string(),
        },
    ));
    assert_eq!(bad_provider.status, CommandStatus::Rejected);
    assert_eq!(
        bad_provider.violations,
        vec!["virtio block backend object provider is unsupported".to_string()]
    );

    let feature_mismatch = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 512,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 bad feature negotiation".to_string(),
        },
    ));
    assert_eq!(feature_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        feature_mismatch.violations,
        vec!["virtio block backend negotiated features exceed device features".to_string()]
    );

    let contract_mismatch = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1794,
            name: "virtio-blk0-backend".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 8192,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 contract mismatch".to_string(),
        },
    ));
    assert_eq!(contract_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        contract_mismatch.violations,
        vec!["virtio block backend object contract does not match block device".to_string()]
    );

    assert!(graph.record_virtio_blk_backend_object_with_id(
        1794,
        "virtio-blk0-backend",
        1791,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-blk-backend-skeleton-v1",
        "virtio-blk",
        512,
        4096,
        false,
        128,
        64,
        64,
        64,
        0,
        8,
        6,
        "b6 first backend",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        6,
        "b6-test",
        SemanticCommand::RecordVirtioBlkBackendObject {
            virtio_blk_backend: 1795,
            name: "virtio-blk0-backend-dup".to_string(),
            block_device: 1791,
            block_device_generation: 1,
            driver_binding: binding,
            driver_binding_generation: 1,
            provider: "substrate_virtio".to_string(),
            profile: "virtio-blk-backend-skeleton-v1".to_string(),
            model: "virtio-blk".to_string(),
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: 64,
            driver_features: 64,
            negotiated_features: 64,
            request_queue_index: 0,
            queue_size: 8,
            irq_vector: 6,
            note: "b6 duplicate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["virtio block backend object already bound to block device generation".to_string()]
    );
}

#[test]
fn block_runtime_b6_invariants_reject_virtio_blk_generation_and_irq_leaks() {
    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    assert!(graph.record_virtio_blk_backend_object_with_id(
        1794,
        "virtio-blk0-backend",
        1791,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-blk-backend-skeleton-v1",
        "virtio-blk",
        512,
        4096,
        false,
        128,
        64,
        64,
        64,
        0,
        8,
        6,
        "b6 invariant backend",
    ));
    graph.corrupt_virtio_blk_backend_driver_binding_generation_for_test(1794, 2);
    assert!(matches!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::VirtioBlkBackendObjectMissingDriverBinding {
                virtio_blk_backend: 1794,
                driver_binding: 1793,
            }
        )
    ));

    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    assert!(graph.record_virtio_blk_backend_object_with_id(
        1794,
        "virtio-blk0-backend",
        1791,
        1,
        binding,
        1,
        "substrate_virtio",
        "virtio-blk-backend-skeleton-v1",
        "virtio-blk",
        512,
        4096,
        false,
        128,
        64,
        64,
        64,
        0,
        8,
        6,
        "b6 invariant backend",
    ));
    graph.corrupt_virtio_blk_backend_irq_vector_for_test(1794, 0);
    assert!(matches!(
        graph.check_invariants(),
        Err(SemanticInvariantError::VirtioBlkBackendObjectInvalid {
            virtio_blk_backend: 1794,
        })
    ));
}

fn setup_b7_block_read_graph() -> (SemanticGraph, u64) {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk7");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1796,
        "fake-block7",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b7 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1797,
        "blk7",
        1796,
        1,
        512,
        4096,
        false,
        128,
        "b7 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1798, 1797, 1, 64, 8, "b7 range"));
    assert!(graph.record_block_request_object_with_id(
        1799,
        1797,
        1,
        1798,
        1,
        BlockRequestOperation::Read,
        1,
        "b7 read request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1800,
        1799,
        1,
        1,
        4096,
        BlockCompletionStatus::Success,
        "b7 read completion",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1801,
        "fake-block7",
        1797,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b31,
        "b7 backend",
    ));
    let digest = SemanticGraph::expected_block_read_digest_v1(
        0x766d_6f73_626c_6b31,
        1797,
        1,
        1798,
        1,
        64,
        8,
        1,
        4096,
    );
    (graph, digest)
}

#[test]
fn block_runtime_b7_read_path_records_backend_request_completion_and_digest() {
    let (mut graph, digest) = setup_b7_block_read_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b7-test",
        SemanticCommand::RecordBlockReadPath {
            read_path: 1802,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
            block_request: 1799,
            block_request_generation: 1,
            block_completion: 1800,
            block_completion_generation: 1,
            data_digest: digest,
            note: "b7 record read path".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_read_path_count(), 1);
    let read_path = &graph.block_read_paths()[0];
    assert_eq!(
        read_path.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockReadPath, 1802, 1)
    );
    assert_eq!(
        read_path.backend,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1)
    );
    assert_eq!(read_path.block_request, 1799);
    assert_eq!(read_path.block_completion, 1800);
    assert_eq!(read_path.completed_bytes, 4096);
    assert_eq!(read_path.data_digest, digest);
    assert_eq!(read_path.state, BlockReadPathState::Completed);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "BlockReadPathRecorded read_path=1802 backend=fake-block-backend-object:1801@1 block_request=1799@1 block_completion=1800@1 block_device=1797@1 block_range=1798@1 sequence=1 completed_bytes=4096 data_digest={digest} generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b7_rejects_duplicate_stale_write_and_bad_digest_paths() {
    let (mut graph, digest) = setup_b7_block_read_graph();
    assert!(graph.record_block_read_path_with_id(
        1802,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
        1799,
        1,
        1800,
        1,
        digest,
        "b7 existing read path",
    ));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b7-test",
        SemanticCommand::RecordBlockReadPath {
            read_path: 1803,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
            block_request: 1799,
            block_request_generation: 1,
            block_completion: 1800,
            block_completion_generation: 1,
            data_digest: digest,
            note: "b7 duplicate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["block read path already exists for request generation".to_string()]
    );

    let stale_backend = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b7-test",
        SemanticCommand::RecordBlockReadPath {
            read_path: 1804,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 2),
            block_request: 1799,
            block_request_generation: 1,
            block_completion: 1800,
            block_completion_generation: 1,
            data_digest: digest,
            note: "b7 stale backend".to_string(),
        },
    ));
    assert_eq!(stale_backend.status, CommandStatus::Rejected);
    assert_eq!(
        stale_backend.violations,
        vec!["block read path backend generation is missing or inactive".to_string()]
    );

    let bad_digest = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b7-test",
        SemanticCommand::RecordBlockReadPath {
            read_path: 1805,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
            block_request: 1799,
            block_request_generation: 1,
            block_completion: 1800,
            block_completion_generation: 1,
            data_digest: digest.wrapping_add(1),
            note: "b7 bad digest".to_string(),
        },
    ));
    assert_eq!(bad_digest.status, CommandStatus::Rejected);
    assert_eq!(
        bad_digest.violations,
        vec!["block read path data digest mismatch".to_string()]
    );

    assert!(graph.record_block_request_object_with_id(
        1806,
        1797,
        1,
        1798,
        1,
        BlockRequestOperation::Write,
        2,
        "b7 write request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1807,
        1806,
        1,
        2,
        4096,
        BlockCompletionStatus::Success,
        "b7 write completion",
    ));
    let write_request = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b7-test",
        SemanticCommand::RecordBlockReadPath {
            read_path: 1808,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
            block_request: 1806,
            block_request_generation: 1,
            block_completion: 1807,
            block_completion_generation: 1,
            data_digest: digest,
            note: "b7 write as read".to_string(),
        },
    ));
    assert_eq!(write_request.status, CommandStatus::Rejected);
    assert_eq!(
        write_request.violations,
        vec!["block read path request operation is not read".to_string()]
    );
}

#[test]
fn block_runtime_b7_invariants_reject_backend_generation_and_digest_leaks() {
    let (mut graph, digest) = setup_b7_block_read_graph();
    assert!(graph.record_block_read_path_with_id(
        1802,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
        1799,
        1,
        1800,
        1,
        digest,
        "b7 invariant read path",
    ));
    graph.corrupt_block_read_path_backend_generation_for_test(1802, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockReadPathMissingBackend {
            read_path: 1802,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 2),
        })
    );

    let (mut graph, digest) = setup_b7_block_read_graph();
    assert!(graph.record_block_read_path_with_id(
        1802,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1801, 1),
        1799,
        1,
        1800,
        1,
        digest,
        "b7 invariant read path",
    ));
    graph.corrupt_block_read_path_data_digest_for_test(1802, digest.wrapping_add(1));
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockReadPathInvalid { read_path: 1802 })
    );
}

fn setup_b8_block_write_graph() -> (SemanticGraph, u64) {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk8");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1810,
        "fake-block8",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b8 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1811,
        "blk8",
        1810,
        1,
        512,
        4096,
        false,
        128,
        "b8 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1812, 1811, 1, 96, 8, "b8 range"));
    assert!(graph.record_block_request_object_with_id(
        1813,
        1811,
        1,
        1812,
        1,
        BlockRequestOperation::Write,
        2,
        "b8 write request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1814,
        1813,
        1,
        2,
        4096,
        BlockCompletionStatus::Success,
        "b8 write completion",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1815,
        "fake-block8",
        1811,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b38,
        "b8 backend",
    ));
    let digest = SemanticGraph::expected_block_write_payload_digest_v1(
        0x766d_6f73_626c_6b38,
        1811,
        1,
        1812,
        1,
        96,
        8,
        2,
        4096,
    );
    (graph, digest)
}

#[test]
fn block_runtime_b8_write_path_records_backend_request_completion_and_payload_digest() {
    let (mut graph, digest) = setup_b8_block_write_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b8-test",
        SemanticCommand::RecordBlockWritePath {
            write_path: 1816,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
            block_request: 1813,
            block_request_generation: 1,
            block_completion: 1814,
            block_completion_generation: 1,
            payload_digest: digest,
            note: "b8 record write path".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_write_path_count(), 1);
    let write_path = &graph.block_write_paths()[0];
    assert_eq!(
        write_path.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockWritePath, 1816, 1)
    );
    assert_eq!(
        write_path.backend,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1)
    );
    assert_eq!(write_path.block_request, 1813);
    assert_eq!(write_path.block_completion, 1814);
    assert_eq!(write_path.completed_bytes, 4096);
    assert_eq!(write_path.payload_digest, digest);
    assert_eq!(write_path.state, BlockWritePathState::Completed);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "BlockWritePathRecorded write_path=1816 backend=fake-block-backend-object:1815@1 block_request=1813@1 block_completion=1814@1 block_device=1811@1 block_range=1812@1 sequence=2 completed_bytes=4096 payload_digest={digest} generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b8_rejects_duplicate_stale_read_and_bad_digest_paths() {
    let (mut graph, digest) = setup_b8_block_write_graph();
    assert!(graph.record_block_write_path_with_id(
        1816,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
        1813,
        1,
        1814,
        1,
        digest,
        "b8 existing write path",
    ));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b8-test",
        SemanticCommand::RecordBlockWritePath {
            write_path: 1817,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
            block_request: 1813,
            block_request_generation: 1,
            block_completion: 1814,
            block_completion_generation: 1,
            payload_digest: digest,
            note: "b8 duplicate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["block write path already exists for request generation".to_string()]
    );

    let stale_backend = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b8-test",
        SemanticCommand::RecordBlockWritePath {
            write_path: 1818,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 2),
            block_request: 1813,
            block_request_generation: 1,
            block_completion: 1814,
            block_completion_generation: 1,
            payload_digest: digest,
            note: "b8 stale backend".to_string(),
        },
    ));
    assert_eq!(stale_backend.status, CommandStatus::Rejected);
    assert_eq!(
        stale_backend.violations,
        vec!["block write path backend generation is missing or inactive".to_string()]
    );

    let bad_digest = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b8-test",
        SemanticCommand::RecordBlockWritePath {
            write_path: 1819,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
            block_request: 1813,
            block_request_generation: 1,
            block_completion: 1814,
            block_completion_generation: 1,
            payload_digest: digest.wrapping_add(1),
            note: "b8 bad digest".to_string(),
        },
    ));
    assert_eq!(bad_digest.status, CommandStatus::Rejected);
    assert_eq!(
        bad_digest.violations,
        vec!["block write path payload digest mismatch".to_string()]
    );

    assert!(graph.record_block_request_object_with_id(
        1820,
        1811,
        1,
        1812,
        1,
        BlockRequestOperation::Read,
        3,
        "b8 read request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1821,
        1820,
        1,
        3,
        4096,
        BlockCompletionStatus::Success,
        "b8 read completion",
    ));
    let read_request = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b8-test",
        SemanticCommand::RecordBlockWritePath {
            write_path: 1822,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
            block_request: 1820,
            block_request_generation: 1,
            block_completion: 1821,
            block_completion_generation: 1,
            payload_digest: digest,
            note: "b8 read as write".to_string(),
        },
    ));
    assert_eq!(read_request.status, CommandStatus::Rejected);
    assert_eq!(
        read_request.violations,
        vec!["block write path request operation is not write".to_string()]
    );
}

#[test]
fn block_runtime_b8_invariants_reject_backend_generation_and_payload_digest_leaks() {
    let (mut graph, digest) = setup_b8_block_write_graph();
    assert!(graph.record_block_write_path_with_id(
        1816,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
        1813,
        1,
        1814,
        1,
        digest,
        "b8 invariant write path",
    ));
    graph.corrupt_block_write_path_backend_generation_for_test(1816, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockWritePathMissingBackend {
            write_path: 1816,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 2),
        })
    );

    let (mut graph, digest) = setup_b8_block_write_graph();
    assert!(graph.record_block_write_path_with_id(
        1816,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1815, 1),
        1813,
        1,
        1814,
        1,
        digest,
        "b8 invariant write path",
    ));
    graph.corrupt_block_write_path_payload_digest_for_test(1816, digest.wrapping_add(1));
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockWritePathInvalid { write_path: 1816 })
    );
}

fn setup_b9_block_request_queue_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::BlockDevice, None, "block-device:blk9");
    let resource_generation = graph.resource_handle(resource).unwrap().generation;
    assert!(graph.record_device_object_with_id(
        1823,
        "fake-block9",
        "block-device",
        resource,
        resource_generation,
        "fake-block-backend",
        "semantic-harness",
        "vmos",
        "fake-block-v1",
        "b9 backing device",
    ));
    assert!(graph.record_block_device_object_with_id(
        1824,
        "blk9",
        1823,
        1,
        512,
        4096,
        false,
        128,
        "b9 block device",
    ));
    assert!(graph.record_block_range_object_with_id(1825, 1824, 1, 128, 8, "b9 range"));
    assert!(graph.record_block_request_object_with_id(
        1826,
        1824,
        1,
        1825,
        1,
        BlockRequestOperation::Read,
        1,
        "b9 completed read request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1827,
        1826,
        1,
        1,
        4096,
        BlockCompletionStatus::Success,
        "b9 read completion",
    ));
    assert!(graph.record_block_request_object_with_id(
        1828,
        1824,
        1,
        1825,
        1,
        BlockRequestOperation::Write,
        2,
        "b9 pending write request",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1829,
        "fake-block9",
        1824,
        1,
        "service_core",
        "fake-block-v1",
        512,
        4096,
        false,
        128,
        0x766d_6f73_626c_6b39,
        "b9 backend",
    ));
    graph
}

#[test]
fn block_runtime_b9_request_queue_records_backend_device_request_order() {
    let mut graph = setup_b9_block_request_queue_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b9-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1830,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_device: 1824,
            block_device_generation: 1,
            depth: 4,
            entries: vec![
                BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
                BlockRequestQueueEntryRef::pending(1828, 1),
            ],
            note: "b9 record request queue".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_request_queue_count(), 1);
    let queue = &graph.block_request_queues()[0];
    assert_eq!(
        queue.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockRequestQueue, 1830, 1)
    );
    assert_eq!(
        queue.backend,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1)
    );
    assert_eq!(queue.block_device, 1824);
    assert_eq!(queue.depth, 4);
    assert_eq!(queue.entries.len(), 2);
    assert_eq!(queue.pending_count, 1);
    assert_eq!(queue.completed_count, 1);
    assert_eq!(queue.first_sequence, 1);
    assert_eq!(queue.last_sequence, 2);
    assert_eq!(
        queue.entries[0].state,
        BlockRequestQueueEntryState::Completed
    );
    assert_eq!(queue.entries[1].state, BlockRequestQueueEntryState::Pending);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockRequestQueueRecorded queue=1830 backend=fake-block-backend-object:1829@1 block_device=1824@1 depth=4 request_count=2 pending_count=1 completed_count=1 first_sequence=1 last_sequence=2 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b9_rejects_duplicate_stale_overdepth_and_bad_completion_queues() {
    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_block_request_queue_with_id(
        1830,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::pending(1828, 1),
        ],
        "b9 existing queue",
    ));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b9-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1831,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_device: 1824,
            block_device_generation: 1,
            depth: 4,
            entries: vec![BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1)],
            note: "b9 duplicate request".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["block request queue request already belongs to an active queue".to_string()]
    );

    let stale_backend = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b9-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1832,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 2),
            block_device: 1824,
            block_device_generation: 1,
            depth: 4,
            entries: vec![BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1)],
            note: "b9 stale backend".to_string(),
        },
    ));
    assert_eq!(stale_backend.status, CommandStatus::Rejected);
    assert_eq!(
        stale_backend.violations,
        vec!["block request queue backend generation is missing or inactive".to_string()]
    );

    let over_depth = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b9-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1833,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_device: 1824,
            block_device_generation: 1,
            depth: 1,
            entries: vec![
                BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
                BlockRequestQueueEntryRef::pending(1828, 1),
            ],
            note: "b9 over depth".to_string(),
        },
    ));
    assert_eq!(over_depth.status, CommandStatus::Rejected);
    assert_eq!(
        over_depth.violations,
        vec!["block request queue depth exceeded".to_string()]
    );

    assert!(graph.record_block_request_object_with_id(
        1834,
        1824,
        1,
        1825,
        1,
        BlockRequestOperation::Read,
        3,
        "b9 second completed request",
    ));
    assert!(graph.record_block_completion_object_with_id(
        1835,
        1834,
        1,
        3,
        4096,
        BlockCompletionStatus::Success,
        "b9 second completion",
    ));
    let bad_completion = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b9-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1836,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_device: 1824,
            block_device_generation: 1,
            depth: 4,
            entries: vec![BlockRequestQueueEntryRef::completed(1834, 1, 1827, 1)],
            note: "b9 bad completion".to_string(),
        },
    ));
    assert_eq!(bad_completion.status, CommandStatus::Rejected);
    assert_eq!(
        bad_completion.violations,
        vec!["block request queue completion does not match request".to_string()]
    );
}

#[test]
fn block_runtime_b9_invariants_reject_backend_generation_and_count_leaks() {
    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_block_request_queue_with_id(
        1830,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::pending(1828, 1),
        ],
        "b9 invariant queue",
    ));
    graph.corrupt_block_request_queue_backend_generation_for_test(1830, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRequestQueueMissingBackend {
            queue: 1830,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 2),
        })
    );

    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_block_request_queue_with_id(
        1830,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::pending(1828, 1),
        ],
        "b9 invariant queue",
    ));
    graph.corrupt_block_request_queue_block_device_generation_for_test(1830, 2);
    assert_eq!(
        graph.check_block_request_queue_invariants(),
        Err(
            SemanticInvariantError::BlockRequestQueueMissingBlockDevice {
                queue: 1830,
                block_device: 1824,
            }
        )
    );

    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_block_request_queue_with_id(
        1830,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::pending(1828, 1),
        ],
        "b9 invariant queue",
    ));
    graph.corrupt_block_request_queue_pending_count_for_test(1830, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockRequestQueueInvalid { queue: 1830 })
    );
}

fn setup_b10_block_dma_buffer_graph(access: DmaBufferObjectAccess) -> SemanticGraph {
    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_block_completion_object_with_id(
        1830,
        1828,
        1,
        2,
        4096,
        BlockCompletionStatus::Success,
        "b10 write completion",
    ));
    assert!(graph.record_queue_object_with_id(
        1831,
        "fake-block9-submit",
        QueueObjectRole::Submission,
        0,
        8,
        1823,
        1,
        "b10 block submission queue",
    ));
    assert!(graph.record_descriptor_object_with_id(
        1832,
        1831,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        4096,
        "b10 block dma descriptor",
    ));
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:block9-buf0");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_dma_buffer_object_with_id(
        1833,
        1832,
        1,
        dma_resource,
        dma_resource_generation,
        access,
        4096,
        "b10 block dma buffer",
    ));
    graph
}

fn b10_expected_digest(access: DmaBufferObjectAccess) -> u64 {
    SemanticGraph::expected_block_dma_buffer_digest_v1(
        0x766d_6f73_626c_6b39,
        1824,
        1,
        1825,
        1,
        1828,
        1,
        1833,
        1,
        1832,
        1,
        1831,
        1,
        BlockRequestOperation::Write,
        access,
        2,
        4096,
        4096,
    )
}

fn setup_b21_stale_block_request_generation_graph() -> SemanticGraph {
    let mut graph = setup_b9_block_request_queue_graph();
    assert!(graph.record_queue_object_with_id(
        1831,
        "fake-block9-submit",
        QueueObjectRole::Submission,
        0,
        8,
        1823,
        1,
        "b21 block submission queue",
    ));
    assert!(graph.record_descriptor_object_with_id(
        1832,
        1831,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        4096,
        "b21 block dma descriptor",
    ));
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:block9-b21");
    let dma_resource_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_dma_buffer_object_with_id(
        1833,
        1832,
        1,
        dma_resource,
        dma_resource_generation,
        DmaBufferObjectAccess::ReadWrite,
        4096,
        "b21 block dma buffer",
    ));
    graph
}

#[test]
fn block_runtime_b10_dma_backed_block_buffer_binds_request_to_dma_generation() {
    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    let digest = b10_expected_digest(DmaBufferObjectAccess::ReadWrite);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b10-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1834,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_request: 1828,
            block_request_generation: 1,
            dma_buffer: 1833,
            dma_buffer_generation: 1,
            buffer_digest: digest,
            note: "b10 bind write request to dma buffer".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_dma_buffer_count(), 1);
    let buffer = &graph.block_dma_buffers()[0];
    assert_eq!(
        buffer.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockDmaBuffer, 1834, 1)
    );
    assert_eq!(buffer.block_request, 1828);
    assert_eq!(buffer.dma_buffer, 1833);
    assert_eq!(buffer.descriptor, 1832);
    assert_eq!(buffer.queue, 1831);
    assert_eq!(buffer.operation, BlockRequestOperation::Write);
    assert_eq!(buffer.access, DmaBufferObjectAccess::ReadWrite);
    assert_eq!(buffer.byte_len, 4096);
    assert_eq!(buffer.buffer_len, 4096);
    assert_eq!(buffer.buffer_digest, digest);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "BlockDmaBufferBound block_dma_buffer=1834 backend=fake-block-backend-object:1829@1 block_request=1828@1 dma_buffer=1833@1 block_device=1824@1 block_range=1825@1 descriptor=1832@1 queue=1831@1 operation=write access=read-write byte_len=4096 buffer_len=4096 buffer_digest={digest} generation=1"
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b10_rejects_duplicate_stale_digest_and_access_mismatch() {
    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    let digest = b10_expected_digest(DmaBufferObjectAccess::ReadWrite);
    assert!(graph.record_block_dma_buffer_with_id(
        1834,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1828,
        1,
        1833,
        1,
        digest,
        "b10 existing buffer",
    ));

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b10-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1835,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_request: 1828,
            block_request_generation: 1,
            dma_buffer: 1833,
            dma_buffer_generation: 1,
            buffer_digest: digest,
            note: "b10 duplicate".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["block dma buffer request already has a bound dma buffer".to_string()]
    );

    let stale_dma = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b10-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1836,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_request: 1828,
            block_request_generation: 1,
            dma_buffer: 1833,
            dma_buffer_generation: 2,
            buffer_digest: digest,
            note: "b10 stale dma".to_string(),
        },
    ));
    assert_eq!(stale_dma.status, CommandStatus::Rejected);
    assert_eq!(
        stale_dma.violations,
        vec!["block dma buffer dma generation is missing or inactive".to_string()]
    );

    let bad_digest = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b10-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1837,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_request: 1828,
            block_request_generation: 1,
            dma_buffer: 1833,
            dma_buffer_generation: 1,
            buffer_digest: digest ^ 1,
            note: "b10 bad digest".to_string(),
        },
    ));
    assert_eq!(bad_digest.status, CommandStatus::Rejected);
    assert_eq!(
        bad_digest.violations,
        vec!["block dma buffer digest mismatch".to_string()]
    );

    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::WriteOnly);
    let wrong_access_digest = b10_expected_digest(DmaBufferObjectAccess::WriteOnly);
    let access_mismatch = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b10-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1834,
            backend: ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
            block_request: 1828,
            block_request_generation: 1,
            dma_buffer: 1833,
            dma_buffer_generation: 1,
            buffer_digest: wrong_access_digest,
            note: "b10 access mismatch".to_string(),
        },
    ));
    assert_eq!(access_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        access_mismatch.violations,
        vec!["block dma buffer access does not match request operation".to_string()]
    );
}

#[test]
fn block_runtime_b10_invariants_reject_dma_generation_and_digest_leaks() {
    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    let digest = b10_expected_digest(DmaBufferObjectAccess::ReadWrite);
    assert!(graph.record_block_dma_buffer_with_id(
        1834,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1828,
        1,
        1833,
        1,
        digest,
        "b10 invariant buffer",
    ));
    graph.corrupt_block_dma_buffer_dma_generation_for_test(1834, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockDmaBufferMissingDmaBuffer {
            block_dma_buffer: 1834,
            dma_buffer: 1833,
        })
    );

    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    assert!(graph.record_block_dma_buffer_with_id(
        1834,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1828,
        1,
        1833,
        1,
        digest,
        "b10 invariant buffer",
    ));
    graph.corrupt_block_dma_buffer_digest_for_test(1834, digest ^ 1);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockDmaBufferInvalid {
            block_dma_buffer: 1834,
        })
    );
}

fn setup_b11_block_page_object_graph() -> SemanticGraph {
    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    assert!(graph.record_block_dma_buffer_with_id(
        1834,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1828,
        1,
        1833,
        1,
        b10_expected_digest(DmaBufferObjectAccess::ReadWrite),
        "b11 existing dma buffer",
    ));
    graph
}

fn b11_aspace() -> ContractObjectRef {
    ContractObjectRef::new(ContractObjectKind::GuestAddressSpace, 1901, 1)
}

fn b11_vma_region() -> ContractObjectRef {
    ContractObjectRef::new(ContractObjectKind::VmaRegion, 1902, 1)
}

fn b11_page(id: u64) -> ContractObjectRef {
    ContractObjectRef::new(ContractObjectKind::PageObject, id, 1)
}

#[test]
fn block_runtime_b11_page_object_integration_records_exact_refs() {
    let mut graph = setup_b11_block_page_object_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b11-test",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 1835,
            block_dma_buffer: 1834,
            block_dma_buffer_generation: 1,
            block_completion: 1830,
            block_completion_generation: 1,
            aspace: b11_aspace(),
            vma_region: b11_vma_region(),
            page: b11_page(1903),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 0,
            byte_len: 4096,
            note: "b11 integrate block dma buffer with page object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_page_object_count(), 1);
    let page = &graph.block_page_objects()[0];
    assert_eq!(
        page.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockPageObject, 1835, 1)
    );
    assert_eq!(page.block_dma_buffer, 1834);
    assert_eq!(page.block_request, 1828);
    assert_eq!(page.block_completion, 1830);
    assert_eq!(page.dma_buffer, 1833);
    assert_eq!(page.aspace, b11_aspace());
    assert_eq!(page.vma_region, b11_vma_region());
    assert_eq!(page.page, b11_page(1903));
    assert_eq!(page.page_dirty_generation, 1);
    assert_eq!(page.page_backing, PageBacking::FileBacked);
    assert_eq!(page.cow_state, CowState::None);
    assert_eq!(page.page_state, PageObjectState::Live);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockPageObjectIntegrated block_page_object=1835 block_dma_buffer=1834@1 block_request=1828@1 block_completion=1830@1 dma_buffer=1833@1 block_device=1824@1 block_range=1825@1 aspace=guest-address-space:1901@1 vma_region=vma-region:1902@1 page=page-object:1903@1 page_dirty_generation=1 page_offset=0 byte_len=4096 operation=write generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b11_rejects_stale_dead_oversized_and_broken_page() {
    let mut graph = setup_b11_block_page_object_graph();
    assert!(graph.record_block_page_object_with_id(
        1835,
        1834,
        1,
        1830,
        1,
        b11_aspace(),
        b11_vma_region(),
        b11_page(1903),
        1,
        PageBacking::FileBacked,
        CowState::None,
        PageObjectState::Live,
        0,
        4096,
        "b11 existing page integration",
    ));

    let stale_dma = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b11-test",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 1836,
            block_dma_buffer: 1834,
            block_dma_buffer_generation: 2,
            block_completion: 1830,
            block_completion_generation: 1,
            aspace: b11_aspace(),
            vma_region: b11_vma_region(),
            page: b11_page(1904),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 0,
            byte_len: 4096,
            note: "stale dma buffer".to_string(),
        },
    ));
    assert_eq!(stale_dma.status, CommandStatus::Rejected);
    assert_eq!(
        stale_dma.violations,
        vec!["block page object dma buffer generation is missing or inactive".to_string()]
    );

    let dead_page = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b11-test",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 1837,
            block_dma_buffer: 1834,
            block_dma_buffer_generation: 1,
            block_completion: 1830,
            block_completion_generation: 1,
            aspace: b11_aspace(),
            vma_region: b11_vma_region(),
            page: b11_page(1904),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Dead,
            page_offset: 0,
            byte_len: 4096,
            note: "dead page".to_string(),
        },
    ));
    assert_eq!(dead_page.status, CommandStatus::Rejected);
    assert_eq!(
        dead_page.violations,
        vec!["block page object page must be live".to_string()]
    );

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b11-test",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 1838,
            block_dma_buffer: 1834,
            block_dma_buffer_generation: 1,
            block_completion: 1830,
            block_completion_generation: 1,
            aspace: b11_aspace(),
            vma_region: b11_vma_region(),
            page: b11_page(1904),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::None,
            page_state: PageObjectState::Live,
            page_offset: 1,
            byte_len: 4096,
            note: "oversized page range".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);
    assert_eq!(
        oversized.violations,
        vec!["block page object byte range exceeds page".to_string()]
    );

    let broken_cow = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b11-test",
        SemanticCommand::RecordBlockPageObject {
            block_page_object: 1839,
            block_dma_buffer: 1834,
            block_dma_buffer_generation: 1,
            block_completion: 1830,
            block_completion_generation: 1,
            aspace: b11_aspace(),
            vma_region: b11_vma_region(),
            page: b11_page(1904),
            page_dirty_generation: 1,
            page_backing: PageBacking::FileBacked,
            cow_state: CowState::Broken,
            page_state: PageObjectState::Live,
            page_offset: 0,
            byte_len: 4096,
            note: "broken cow".to_string(),
        },
    ));
    assert_eq!(broken_cow.status, CommandStatus::Rejected);
    assert_eq!(
        broken_cow.violations,
        vec!["block page object COW break must be revalidated before IO".to_string()]
    );
}

#[test]
fn block_runtime_b11_invariants_reject_page_generation_leak() {
    let mut graph = setup_b11_block_page_object_graph();
    assert!(graph.record_block_page_object_with_id(
        1835,
        1834,
        1,
        1830,
        1,
        b11_aspace(),
        b11_vma_region(),
        b11_page(1903),
        1,
        PageBacking::FileBacked,
        CowState::None,
        PageObjectState::Live,
        0,
        4096,
        "b11 invariant page integration",
    ));
    graph.corrupt_block_page_object_page_generation_for_test(1835, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockPageObjectInvalid {
            block_page_object: 1835,
        })
    );
}

fn setup_b12_buffer_cache_graph() -> SemanticGraph {
    let mut graph = setup_b11_block_page_object_graph();
    assert!(graph.record_block_page_object_with_id(
        1835,
        1834,
        1,
        1830,
        1,
        b11_aspace(),
        b11_vma_region(),
        b11_page(1903),
        1,
        PageBacking::FileBacked,
        CowState::None,
        PageObjectState::Live,
        0,
        4096,
        "b12 existing page integration",
    ));
    graph
}

#[test]
fn block_runtime_b12_buffer_cache_records_page_and_block_range_contract() {
    let mut graph = setup_b12_buffer_cache_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b12-test",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 1840,
            block_page_object: 1835,
            block_page_object_generation: 1,
            page: b11_page(1903),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 1,
            note: "b12 record dirty buffer cache entry".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.buffer_cache_object_count(), 1);
    let cache = &graph.buffer_cache_objects()[0];
    assert_eq!(
        cache.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BufferCacheObject, 1840, 1)
    );
    assert_eq!(cache.block_page_object, 1835);
    assert_eq!(cache.block_dma_buffer, 1834);
    assert_eq!(cache.block_device, 1824);
    assert_eq!(cache.block_range, 1825);
    assert_eq!(cache.page, b11_page(1903));
    assert_eq!(cache.page_dirty_generation, 1);
    assert_eq!(cache.cache_state, BufferCacheObjectState::Dirty);
    assert_eq!(cache.state, BufferCacheObjectState::Dirty);
    assert_eq!(cache.coherency_epoch, 1);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BufferCacheObjectRecorded buffer_cache_object=1840 block_page_object=1835@1 block_dma_buffer=1834@1 block_device=1824@1 block_range=1825@1 aspace=guest-address-space:1901@1 vma_region=vma-region:1902@1 page=page-object:1903@1 page_dirty_generation=1 page_offset=0 block_offset=0 byte_len=4096 operation=write cache_state=dirty coherency_epoch=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b12_rejects_stale_wrong_duplicate_and_oversized_cache() {
    let mut graph = setup_b12_buffer_cache_graph();

    let stale_page = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b12-test",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 1841,
            block_page_object: 1835,
            block_page_object_generation: 2,
            page: b11_page(1904),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 2,
            note: "stale page integration".to_string(),
        },
    ));
    assert_eq!(stale_page.status, CommandStatus::Rejected);
    assert_eq!(
        stale_page.violations,
        vec!["buffer cache object page integration generation is missing".to_string()]
    );

    let wrong_page = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b12-test",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 1842,
            block_page_object: 1835,
            block_page_object_generation: 1,
            page: b11_page(1904),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 3,
            note: "wrong page".to_string(),
        },
    ));
    assert_eq!(wrong_page.status, CommandStatus::Rejected);
    assert_eq!(
        wrong_page.violations,
        vec!["buffer cache object page ref does not match integration".to_string()]
    );

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b12-test",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 1843,
            block_page_object: 1835,
            block_page_object_generation: 1,
            page: b11_page(1903),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4097,
            cache_state: BufferCacheObjectState::Dirty,
            coherency_epoch: 4,
            note: "oversized cache range".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);
    assert_eq!(
        oversized.violations,
        vec!["buffer cache object byte range exceeds integrated page".to_string()]
    );

    assert!(graph.record_buffer_cache_object_with_id(
        1840,
        1835,
        1,
        b11_page(1903),
        1,
        0,
        4096,
        BufferCacheObjectState::Dirty,
        1,
        "b12 existing cache entry",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b12-test",
        SemanticCommand::RecordBufferCacheObject {
            buffer_cache_object: 1844,
            block_page_object: 1835,
            block_page_object_generation: 1,
            page: b11_page(1903),
            page_dirty_generation: 1,
            block_offset: 0,
            byte_len: 4096,
            cache_state: BufferCacheObjectState::WritebackPending,
            coherency_epoch: 5,
            note: "duplicate cache key".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["buffer cache object block range already cached".to_string()]
    );
}

#[test]
fn block_runtime_b12_invariants_reject_cache_page_generation_leak() {
    let mut graph = setup_b12_buffer_cache_graph();
    assert!(graph.record_buffer_cache_object_with_id(
        1840,
        1835,
        1,
        b11_page(1903),
        1,
        0,
        4096,
        BufferCacheObjectState::Dirty,
        1,
        "b12 invariant cache entry",
    ));
    graph.corrupt_buffer_cache_object_page_generation_for_test(1840, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BufferCacheObjectInvalid {
            buffer_cache_object: 1840,
        })
    );
}

fn setup_b13_file_object_graph() -> SemanticGraph {
    let mut graph = setup_b12_buffer_cache_graph();
    assert!(graph.record_buffer_cache_object_with_id(
        1840,
        1835,
        1,
        b11_page(1903),
        1,
        0,
        4096,
        BufferCacheObjectState::Dirty,
        1,
        "b13 source buffer cache entry",
    ));
    graph
}

#[test]
fn block_runtime_b13_file_object_records_cache_backed_file_contract() {
    let mut graph = setup_b13_file_object_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b13-test",
        SemanticCommand::RecordFileObject {
            file_object: 1845,
            buffer_cache_object: 1840,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_string(),
            file_key: "demo-file".to_string(),
            path: "/demo/file.txt".to_string(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "b13 record dirty file object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.file_object_count(), 1);
    let file = &graph.file_objects()[0];
    assert_eq!(
        file.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FileObject, 1845, 1)
    );
    assert_eq!(file.buffer_cache_object, 1840);
    assert_eq!(file.block_device, 1824);
    assert_eq!(file.block_range, 1825);
    assert_eq!(file.page, b11_page(1903));
    assert_eq!(file.namespace, "rootfs");
    assert_eq!(file.file_key, "demo-file");
    assert_eq!(file.path, "/demo/file.txt");
    assert_eq!(file.file_offset, 0);
    assert_eq!(file.byte_len, 4096);
    assert_eq!(file.file_size, 4096);
    assert_eq!(file.content_digest, 0xB13);
    assert_eq!(file.cache_state, BufferCacheObjectState::Dirty);
    assert_eq!(file.state, FileObjectState::Dirty);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FileObjectRecorded file_object=1845 buffer_cache_object=1840@1 block_device=1824@1 block_range=1825@1 page=page-object:1903@1 page_dirty_generation=1 namespace=rootfs file_key=demo-file path=/demo/file.txt file_offset=0 byte_len=4096 file_size=4096 content_digest=2835 cache_state=dirty state=dirty generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b13_rejects_stale_oversized_duplicate_and_invalid_file() {
    let mut graph = setup_b13_file_object_graph();

    let stale_cache = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b13-test",
        SemanticCommand::RecordFileObject {
            file_object: 1846,
            buffer_cache_object: 1840,
            buffer_cache_object_generation: 2,
            namespace: "rootfs".to_string(),
            file_key: "demo-file".to_string(),
            path: "/demo/file.txt".to_string(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "stale cache generation".to_string(),
        },
    ));
    assert_eq!(stale_cache.status, CommandStatus::Rejected);
    assert_eq!(
        stale_cache.violations,
        vec!["file object buffer cache generation is missing".to_string()]
    );

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b13-test",
        SemanticCommand::RecordFileObject {
            file_object: 1847,
            buffer_cache_object: 1840,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_string(),
            file_key: "demo-file".to_string(),
            path: "/demo/file.txt".to_string(),
            file_offset: 0,
            byte_len: 4097,
            file_size: 4097,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "oversized file object".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);
    assert_eq!(
        oversized.violations,
        vec!["file object byte range exceeds file or cache".to_string()]
    );

    let invalid_state = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b13-test",
        SemanticCommand::RecordFileObject {
            file_object: 1848,
            buffer_cache_object: 1840,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_string(),
            file_key: "demo-file".to_string(),
            path: "/demo/file.txt".to_string(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Invalidated,
            note: "invalidated file object".to_string(),
        },
    ));
    assert_eq!(invalid_state.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_state.violations,
        vec!["file object cannot be recorded as invalidated".to_string()]
    );

    assert!(graph.record_file_object_with_id(
        1845,
        1840,
        1,
        "rootfs",
        "demo-file",
        "/demo/file.txt",
        0,
        4096,
        4096,
        0xB13,
        FileObjectState::Dirty,
        "b13 existing file object",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b13-test",
        SemanticCommand::RecordFileObject {
            file_object: 1849,
            buffer_cache_object: 1840,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_string(),
            file_key: "demo-file".to_string(),
            path: "/demo/file.txt".to_string(),
            file_offset: 1024,
            byte_len: 1024,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "overlapping file range".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["file object range already materialized".to_string()]
    );
}

#[test]
fn block_runtime_b13_invariants_reject_file_page_generation_leak() {
    let mut graph = setup_b13_file_object_graph();
    assert!(graph.record_file_object_with_id(
        1845,
        1840,
        1,
        "rootfs",
        "demo-file",
        "/demo/file.txt",
        0,
        4096,
        4096,
        0xB13,
        FileObjectState::Dirty,
        "b13 invariant file object",
    ));
    graph.corrupt_file_object_page_generation_for_test(1845, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FileObjectInvalid { file_object: 1845 })
    );
}

fn setup_b14_directory_object_graph() -> SemanticGraph {
    let mut graph = setup_b13_file_object_graph();
    assert!(graph.record_file_object_with_id(
        1845,
        1840,
        1,
        "rootfs",
        "demo-file",
        "/demo/file.txt",
        0,
        4096,
        4096,
        0xB13,
        FileObjectState::Dirty,
        "b14 source file object",
    ));
    graph
}

#[test]
fn block_runtime_b14_directory_object_records_file_entry_contract() {
    let mut graph = setup_b14_directory_object_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b14-test",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 1850,
            file_object: 1845,
            file_object_generation: 1,
            namespace: "rootfs".to_string(),
            directory_key: "demo-dir".to_string(),
            directory_path: "/demo".to_string(),
            entry_name: "file.txt".to_string(),
            child_file_key: "demo-file".to_string(),
            child_path: "/demo/file.txt".to_string(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "b14 record directory entry".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.directory_object_count(), 1);
    let directory = &graph.directory_objects()[0];
    assert_eq!(
        directory.object_ref(),
        ContractObjectRef::new(ContractObjectKind::DirectoryObject, 1850, 1)
    );
    assert_eq!(directory.file_object, 1845);
    assert_eq!(directory.file_object_generation, 1);
    assert_eq!(directory.namespace, "rootfs");
    assert_eq!(directory.directory_key, "demo-dir");
    assert_eq!(directory.directory_path, "/demo");
    assert_eq!(directory.entry_name, "file.txt");
    assert_eq!(directory.child_file_key, "demo-file");
    assert_eq!(directory.child_path, "/demo/file.txt");
    assert_eq!(directory.entry_kind, DirectoryEntryKind::File);
    assert_eq!(directory.file_size, 4096);
    assert_eq!(directory.content_digest, 0xB13);
    assert_eq!(directory.state, DirectoryObjectState::Cached);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "DirectoryObjectRecorded directory_object=1850 file_object=1845@1 namespace=rootfs directory_key=demo-dir directory_path=/demo entry_name=file.txt child_file_key=demo-file child_path=/demo/file.txt entry_kind=file file_size=4096 content_digest=2835 state=cached generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b14_rejects_stale_mismatch_duplicate_and_invalid_directory() {
    let mut graph = setup_b14_directory_object_graph();

    let stale_file = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b14-test",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 1851,
            file_object: 1845,
            file_object_generation: 2,
            namespace: "rootfs".to_string(),
            directory_key: "demo-dir".to_string(),
            directory_path: "/demo".to_string(),
            entry_name: "stale.txt".to_string(),
            child_file_key: "demo-file".to_string(),
            child_path: "/demo/file.txt".to_string(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "stale file generation".to_string(),
        },
    ));
    assert_eq!(stale_file.status, CommandStatus::Rejected);
    assert_eq!(
        stale_file.violations,
        vec!["directory object file generation is missing".to_string()]
    );

    let mismatch = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b14-test",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 1852,
            file_object: 1845,
            file_object_generation: 1,
            namespace: "rootfs".to_string(),
            directory_key: "demo-dir".to_string(),
            directory_path: "/demo".to_string(),
            entry_name: "wrong.txt".to_string(),
            child_file_key: "demo-file".to_string(),
            child_path: "/demo/wrong.txt".to_string(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "wrong child path".to_string(),
        },
    ));
    assert_eq!(mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        mismatch.violations,
        vec!["directory object file identity mismatch".to_string()]
    );

    let invalid_state = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b14-test",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 1853,
            file_object: 1845,
            file_object_generation: 1,
            namespace: "rootfs".to_string(),
            directory_key: "demo-dir".to_string(),
            directory_path: "/demo".to_string(),
            entry_name: "invalid.txt".to_string(),
            child_file_key: "demo-file".to_string(),
            child_path: "/demo/file.txt".to_string(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Invalidated,
            note: "invalidated directory object".to_string(),
        },
    ));
    assert_eq!(invalid_state.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_state.violations,
        vec!["directory object cannot be recorded as invalidated".to_string()]
    );

    assert!(graph.record_directory_object_with_id(
        1850,
        1845,
        1,
        "rootfs",
        "demo-dir",
        "/demo",
        "file.txt",
        "demo-file",
        "/demo/file.txt",
        DirectoryEntryKind::File,
        4096,
        0xB13,
        DirectoryObjectState::Cached,
        "b14 existing directory entry",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b14-test",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 1854,
            file_object: 1845,
            file_object_generation: 1,
            namespace: "rootfs".to_string(),
            directory_key: "demo-dir".to_string(),
            directory_path: "/demo".to_string(),
            entry_name: "file.txt".to_string(),
            child_file_key: "demo-file".to_string(),
            child_path: "/demo/file.txt".to_string(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "duplicate directory entry".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["directory object entry already materialized".to_string()]
    );
}

#[test]
fn block_runtime_b14_invariants_reject_directory_file_generation_leak() {
    let mut graph = setup_b14_directory_object_graph();
    assert!(graph.record_directory_object_with_id(
        1850,
        1845,
        1,
        "rootfs",
        "demo-dir",
        "/demo",
        "file.txt",
        "demo-file",
        "/demo/file.txt",
        DirectoryEntryKind::File,
        4096,
        0xB13,
        DirectoryObjectState::Cached,
        "b14 invariant directory object",
    ));
    graph.corrupt_directory_object_file_generation_for_test(1850, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::DirectoryObjectMissingFileObject {
            directory_object: 1850,
            file_object: 1845,
        })
    );
}

fn setup_b15_fat_adapter_graph() -> SemanticGraph {
    let mut graph = setup_b14_directory_object_graph();
    assert!(graph.record_directory_object_with_id(
        1850,
        1845,
        1,
        "rootfs",
        "demo-dir",
        "/demo",
        "file.txt",
        "demo-file",
        "/demo/file.txt",
        DirectoryEntryKind::File,
        4096,
        0xB13,
        DirectoryObjectState::Cached,
        "b15 source directory object",
    ));
    graph
}

#[test]
fn block_runtime_b15_fat_adapter_records_read_write_contract() {
    let mut graph = setup_b15_fat_adapter_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b15-test",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 1855,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "fatfs".to_string(),
            version: "0.3.6".to_string(),
            profile: "fatfs-read-write-demo-v1".to_string(),
            volume_label: "VMOSFAT".to_string(),
            image_bytes: 1_048_576,
            adapter_path: "DEMO.TXT".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x5151,
            read_digest: 0x5151,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "b15 record fat adapter object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.fat_adapter_object_count(), 1);
    let adapter = &graph.fat_adapter_objects()[0];
    assert_eq!(
        adapter.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FatAdapterObject, 1855, 1)
    );
    assert_eq!(adapter.directory_object, 1850);
    assert_eq!(adapter.file_object, 1845);
    assert_eq!(adapter.block_device, 1824);
    assert_eq!(adapter.implementation, "fatfs");
    assert_eq!(adapter.profile, "fatfs-read-write-demo-v1");
    assert_eq!(adapter.adapter_path, "DEMO.TXT");
    assert_eq!(adapter.semantic_path, "/demo/file.txt");
    assert_eq!(adapter.bytes_written, 35);
    assert_eq!(adapter.bytes_read, 35);
    assert_eq!(adapter.write_digest, 0x5151);
    assert_eq!(adapter.read_digest, 0x5151);
    assert_eq!(adapter.file_content_digest, 0xB13);
    assert_eq!(adapter.state, FatAdapterObjectState::Verified);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FatAdapterObjectRecorded fat_adapter_object=1855 directory_object=1850@1 file_object=1845@1 block_device=1824@1 implementation=fatfs version=0.3.6 profile=fatfs-read-write-demo-v1 volume_label=VMOSFAT image_bytes=1048576 adapter_path=DEMO.TXT semantic_path=/demo/file.txt bytes_written=35 bytes_read=35 write_digest=20817 read_digest=20817 file_content_digest=2835 state=verified generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b15_rejects_stale_mismatch_duplicate_and_invalid_adapter() {
    let mut graph = setup_b15_fat_adapter_graph();

    let stale_directory = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b15-test",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 1856,
            directory_object: 1850,
            directory_object_generation: 2,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "fatfs".to_string(),
            version: "0.3.6".to_string(),
            profile: "fatfs-read-write-demo-v1".to_string(),
            volume_label: "VMOSFAT".to_string(),
            image_bytes: 1_048_576,
            adapter_path: "DEMO.TXT".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x5151,
            read_digest: 0x5151,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "stale directory generation".to_string(),
        },
    ));
    assert_eq!(stale_directory.status, CommandStatus::Rejected);
    assert_eq!(
        stale_directory.violations,
        vec!["fat adapter directory generation is missing".to_string()]
    );

    let digest_mismatch = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b15-test",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 1857,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "fatfs".to_string(),
            version: "0.3.6".to_string(),
            profile: "fatfs-read-write-demo-v1".to_string(),
            volume_label: "VMOSFAT".to_string(),
            image_bytes: 1_048_576,
            adapter_path: "BROKEN.TXT".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x5151,
            read_digest: 0x5152,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "digest mismatch".to_string(),
        },
    ));
    assert_eq!(digest_mismatch.status, CommandStatus::Rejected);
    assert_eq!(
        digest_mismatch.violations,
        vec!["fat adapter read/write roundtrip mismatch".to_string()]
    );

    let invalid_state = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b15-test",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 1858,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "fatfs".to_string(),
            version: "0.3.6".to_string(),
            profile: "fatfs-read-write-demo-v1".to_string(),
            volume_label: "VMOSFAT".to_string(),
            image_bytes: 1_048_576,
            adapter_path: "INVALID.TXT".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x5151,
            read_digest: 0x5151,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Rejected,
            note: "invalid adapter state".to_string(),
        },
    ));
    assert_eq!(invalid_state.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_state.violations,
        vec!["fat adapter object must be verified".to_string()]
    );

    assert!(graph.record_fat_adapter_object_with_id(
        1855,
        1850,
        1,
        1845,
        1,
        1824,
        1,
        "fatfs",
        "0.3.6",
        "fatfs-read-write-demo-v1",
        "VMOSFAT",
        1_048_576,
        "DEMO.TXT",
        "/demo/file.txt",
        35,
        35,
        0x5151,
        0x5151,
        0xB13,
        FatAdapterObjectState::Verified,
        "b15 existing fat adapter binding",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b15-test",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 1859,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "fatfs".to_string(),
            version: "0.3.6".to_string(),
            profile: "fatfs-read-write-demo-v1".to_string(),
            volume_label: "VMOSFAT".to_string(),
            image_bytes: 1_048_576,
            adapter_path: "DEMO.TXT".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_written: 35,
            bytes_read: 35,
            write_digest: 0x5151,
            read_digest: 0x5151,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "duplicate fat adapter binding".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["fat adapter binding already verified".to_string()]
    );
}

#[test]
fn block_runtime_b15_invariants_reject_fat_adapter_generation_leak() {
    let mut graph = setup_b15_fat_adapter_graph();
    assert!(graph.record_fat_adapter_object_with_id(
        1855,
        1850,
        1,
        1845,
        1,
        1824,
        1,
        "fatfs",
        "0.3.6",
        "fatfs-read-write-demo-v1",
        "VMOSFAT",
        1_048_576,
        "DEMO.TXT",
        "/demo/file.txt",
        35,
        35,
        0x5151,
        0x5151,
        0xB13,
        FatAdapterObjectState::Verified,
        "b15 invariant fat adapter object",
    ));
    graph.corrupt_fat_adapter_file_generation_for_test(1855, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FatAdapterObjectMissingFileObject {
            fat_adapter_object: 1855,
            file_object: 1845,
        })
    );
}

fn setup_b16_ext4_adapter_graph() -> SemanticGraph {
    setup_b15_fat_adapter_graph()
}

#[test]
fn block_runtime_b16_ext4_adapter_records_read_only_contract() {
    let mut graph = setup_b16_ext4_adapter_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b16-test",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 1860,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "ext4-view".to_string(),
            version: "0.9.3".to_string(),
            profile: "ext4-read-only-demo-v1".to_string(),
            volume_label: "VMOSEXT4".to_string(),
            image_bytes: 32_768,
            adapter_path: "/demo.txt".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_read: 34,
            read_digest: 0x6161,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: true,
            state: Ext4AdapterObjectState::Verified,
            note: "b16 record ext4 adapter object".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.ext4_adapter_object_count(), 1);
    let adapter = &graph.ext4_adapter_objects()[0];
    assert_eq!(
        adapter.object_ref(),
        ContractObjectRef::new(ContractObjectKind::Ext4AdapterObject, 1860, 1)
    );
    assert_eq!(adapter.directory_object, 1850);
    assert_eq!(adapter.file_object, 1845);
    assert_eq!(adapter.block_device, 1824);
    assert_eq!(adapter.implementation, "ext4-view");
    assert_eq!(adapter.profile, "ext4-read-only-demo-v1");
    assert_eq!(adapter.adapter_path, "/demo.txt");
    assert_eq!(adapter.semantic_path, "/demo/file.txt");
    assert_eq!(adapter.bytes_read, 34);
    assert_eq!(adapter.read_digest, 0x6161);
    assert_eq!(adapter.file_content_digest, 0xB13);
    assert_eq!(adapter.directory_entries, 1);
    assert!(adapter.read_only_enforced);
    assert_eq!(adapter.state, Ext4AdapterObjectState::Verified);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "Ext4AdapterObjectRecorded ext4_adapter_object=1860 directory_object=1850@1 file_object=1845@1 block_device=1824@1 implementation=ext4-view version=0.9.3 profile=ext4-read-only-demo-v1 volume_label=VMOSEXT4 image_bytes=32768 adapter_path=/demo.txt semantic_path=/demo/file.txt bytes_read=34 read_digest=24929 file_content_digest=2835 directory_entries=1 read_only_enforced=true state=verified generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b16_rejects_stale_not_read_only_duplicate_and_invalid_adapter() {
    let mut graph = setup_b16_ext4_adapter_graph();

    let stale_directory = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b16-test",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 1861,
            directory_object: 1850,
            directory_object_generation: 2,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "ext4-view".to_string(),
            version: "0.9.3".to_string(),
            profile: "ext4-read-only-demo-v1".to_string(),
            volume_label: "VMOSEXT4".to_string(),
            image_bytes: 32_768,
            adapter_path: "/demo.txt".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_read: 34,
            read_digest: 0x6161,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: true,
            state: Ext4AdapterObjectState::Verified,
            note: "stale directory generation".to_string(),
        },
    ));
    assert_eq!(stale_directory.status, CommandStatus::Rejected);
    assert_eq!(
        stale_directory.violations,
        vec!["ext4 adapter directory generation is missing".to_string()]
    );

    let not_read_only = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b16-test",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 1862,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "ext4-view".to_string(),
            version: "0.9.3".to_string(),
            profile: "ext4-read-only-demo-v1".to_string(),
            volume_label: "VMOSEXT4".to_string(),
            image_bytes: 32_768,
            adapter_path: "/demo-ro-false.txt".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_read: 34,
            read_digest: 0x6161,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: false,
            state: Ext4AdapterObjectState::Verified,
            note: "not read-only".to_string(),
        },
    ));
    assert_eq!(not_read_only.status, CommandStatus::Rejected);
    assert_eq!(
        not_read_only.violations,
        vec!["ext4 adapter object must be verified read-only evidence".to_string()]
    );

    let invalid_state = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b16-test",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 1863,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "ext4-view".to_string(),
            version: "0.9.3".to_string(),
            profile: "ext4-read-only-demo-v1".to_string(),
            volume_label: "VMOSEXT4".to_string(),
            image_bytes: 32_768,
            adapter_path: "/invalid.txt".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_read: 34,
            read_digest: 0x6161,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: true,
            state: Ext4AdapterObjectState::Rejected,
            note: "invalid adapter state".to_string(),
        },
    ));
    assert_eq!(invalid_state.status, CommandStatus::Rejected);
    assert_eq!(
        invalid_state.violations,
        vec!["ext4 adapter object must be verified read-only evidence".to_string()]
    );

    assert!(graph.record_ext4_adapter_object_with_id(
        1860,
        1850,
        1,
        1845,
        1,
        1824,
        1,
        "ext4-view",
        "0.9.3",
        "ext4-read-only-demo-v1",
        "VMOSEXT4",
        32_768,
        "/demo.txt",
        "/demo/file.txt",
        34,
        0x6161,
        0xB13,
        1,
        true,
        Ext4AdapterObjectState::Verified,
        "b16 existing ext4 adapter binding",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b16-test",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 1864,
            directory_object: 1850,
            directory_object_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            block_device: 1824,
            block_device_generation: 1,
            implementation: "ext4-view".to_string(),
            version: "0.9.3".to_string(),
            profile: "ext4-read-only-demo-v1".to_string(),
            volume_label: "VMOSEXT4".to_string(),
            image_bytes: 32_768,
            adapter_path: "/demo.txt".to_string(),
            semantic_path: "/demo/file.txt".to_string(),
            bytes_read: 34,
            read_digest: 0x6161,
            file_content_digest: 0xB13,
            directory_entries: 1,
            read_only_enforced: true,
            state: Ext4AdapterObjectState::Verified,
            note: "duplicate ext4 adapter binding".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["ext4 adapter binding already verified".to_string()]
    );
}

#[test]
fn block_runtime_b16_invariants_reject_ext4_adapter_generation_leak() {
    let mut graph = setup_b16_ext4_adapter_graph();
    assert!(graph.record_ext4_adapter_object_with_id(
        1860,
        1850,
        1,
        1845,
        1,
        1824,
        1,
        "ext4-view",
        "0.9.3",
        "ext4-read-only-demo-v1",
        "VMOSEXT4",
        32_768,
        "/demo.txt",
        "/demo/file.txt",
        34,
        0x6161,
        0xB13,
        1,
        true,
        Ext4AdapterObjectState::Verified,
        "b16 invariant ext4 adapter object",
    ));
    graph.corrupt_ext4_adapter_file_generation_for_test(1860, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::Ext4AdapterObjectMissingFileObject {
            ext4_adapter_object: 1860,
            file_object: 1845,
        })
    );
}

fn setup_b17_file_handle_capability_graph() -> (SemanticGraph, CapabilityHandle, CapabilityId) {
    let mut graph = setup_b16_ext4_adapter_graph();
    graph.register_store(
        "linux_syscall",
        "linux_syscall.wasm",
        "personality",
        "kill-on-trap",
    );
    let file_ref = ContractObjectRef::new(ContractObjectKind::FileObject, 1845, 1);
    let cap = graph.grant_capability_with_authority_ref(
        "linux_syscall",
        "file-handle./demo/file.txt",
        AuthorityObjectRef::internal(CapabilityClass::FileHandle, file_ref),
        &["read", "write"],
        "task",
        "b17-test",
        true,
    );
    let handle = graph
        .capabilities()
        .record(cap)
        .and_then(|record| record.store_local_handle(vec!["read".to_string()]))
        .unwrap();
    (graph, handle, cap)
}

#[test]
fn block_runtime_b17_file_handle_capability_gates_file_object() {
    let (mut graph, handle, cap) = setup_b17_file_handle_capability_graph();
    let cap_generation = graph.capabilities().record(cap).unwrap().generation;
    let store = graph.store_id("linux_syscall").unwrap();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b17-test",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 1865,
            owner_store: store,
            owner_store_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            directory_object: 1850,
            directory_object_generation: 1,
            capability: cap,
            capability_generation: cap_generation,
            handle: handle.clone(),
            operation: "read".to_string(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "b17 record file handle read capability".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.file_handle_capability_count(), 1);
    let gate = &graph.file_handle_capabilities()[0];
    assert_eq!(
        gate.object_ref(),
        ContractObjectRef::new(ContractObjectKind::FileHandleCapability, 1865, 1)
    );
    assert_eq!(gate.owner_store, store);
    assert_eq!(gate.file_object, 1845);
    assert_eq!(gate.directory_object, 1850);
    assert_eq!(gate.capability, cap);
    assert_eq!(gate.capability_generation, cap_generation);
    assert_eq!(gate.handle_slot, handle.slot);
    assert_eq!(gate.handle_generation, handle.generation);
    assert_eq!(gate.handle_tag, handle.tag);
    assert_eq!(gate.operation, "read");
    assert_eq!(gate.byte_len, 512);
    assert_eq!(gate.content_digest, 0xB13);
    assert_eq!(gate.state, FileHandleCapabilityState::Allowed);
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "FileHandleCapabilityRecorded file_handle_capability=1865 owner_store={store}@1 file_object=1845@1 directory_object=1850@1 capability={cap}@{cap_generation} handle_slot={} handle_generation={} handle_tag={} operation=read file_offset=0 byte_len=512 content_digest=2835 state=allowed generation=1",
            handle.slot, handle.generation, handle.tag
        )
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b17_rejects_stale_handle_duplicate_and_oversized_file_gate() {
    let (mut graph, handle, cap) = setup_b17_file_handle_capability_graph();
    let cap_generation = graph.capabilities().record(cap).unwrap().generation;
    let store = graph.store_id("linux_syscall").unwrap();

    let stale_file = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b17-test",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 1866,
            owner_store: store,
            owner_store_generation: 1,
            file_object: 1845,
            file_object_generation: 2,
            directory_object: 1850,
            directory_object_generation: 1,
            capability: cap,
            capability_generation: cap_generation,
            handle: handle.clone(),
            operation: "read".to_string(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "stale file generation".to_string(),
        },
    ));
    assert_eq!(stale_file.status, CommandStatus::Rejected);
    assert_eq!(
        stale_file.violations,
        vec!["file handle capability file generation is missing".to_string()]
    );

    let mut forged_handle = handle.clone();
    forged_handle.generation = forged_handle.generation.saturating_add(1);
    let bad_handle = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b17-test",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 1867,
            owner_store: store,
            owner_store_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            directory_object: 1850,
            directory_object_generation: 1,
            capability: cap,
            capability_generation: cap_generation,
            handle: forged_handle,
            operation: "read".to_string(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "forged handle generation".to_string(),
        },
    ));
    assert_eq!(bad_handle.status, CommandStatus::Rejected);
    assert_eq!(
        bad_handle.violations,
        vec!["file handle capability handle is not authorized".to_string()]
    );

    let oversized = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b17-test",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 1868,
            owner_store: store,
            owner_store_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            directory_object: 1850,
            directory_object_generation: 1,
            capability: cap,
            capability_generation: cap_generation,
            handle: handle.clone(),
            operation: "read".to_string(),
            file_offset: 4090,
            byte_len: 16,
            content_digest: 0xB13,
            note: "oversized file range".to_string(),
        },
    ));
    assert_eq!(oversized.status, CommandStatus::Rejected);
    assert_eq!(
        oversized.violations,
        vec!["file handle capability file binding mismatch".to_string()]
    );

    assert!(graph.record_file_handle_capability_with_id(
        1865,
        store,
        1,
        1845,
        1,
        1850,
        1,
        cap,
        cap_generation,
        handle.clone(),
        "read",
        0,
        512,
        0xB13,
        "existing file handle capability",
    ));
    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b17-test",
        SemanticCommand::RecordFileHandleCapability {
            file_handle_capability: 1869,
            owner_store: store,
            owner_store_generation: 1,
            file_object: 1845,
            file_object_generation: 1,
            directory_object: 1850,
            directory_object_generation: 1,
            capability: cap,
            capability_generation: cap_generation,
            handle,
            operation: "read".to_string(),
            file_offset: 0,
            byte_len: 512,
            content_digest: 0xB13,
            note: "duplicate file handle capability".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["file handle capability already allowed for file operation".to_string()]
    );
}

#[test]
fn block_runtime_b17_invariants_reject_file_handle_generation_leak() {
    let (mut graph, handle, cap) = setup_b17_file_handle_capability_graph();
    let cap_generation = graph.capabilities().record(cap).unwrap().generation;
    let store = graph.store_id("linux_syscall").unwrap();
    assert!(graph.record_file_handle_capability_with_id(
        1865,
        store,
        1,
        1845,
        1,
        1850,
        1,
        cap,
        cap_generation,
        handle,
        "read",
        0,
        512,
        0xB13,
        "b17 invariant file handle capability",
    ));
    graph.corrupt_file_handle_capability_generation_for_test(1865, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::FileHandleCapabilityMissingFileObject {
                file_handle_capability: 1865,
                file_object: 1845,
            }
        )
    );
}

fn setup_b18_fs_wait_graph() -> SemanticGraph {
    let (mut graph, handle, cap) = setup_b17_file_handle_capability_graph();
    let cap_generation = graph.capabilities().record(cap).unwrap().generation;
    let store = graph.store_id("linux_syscall").unwrap();
    assert!(graph.record_file_handle_capability_with_id(
        1865,
        store,
        1,
        1845,
        1,
        1850,
        1,
        cap,
        cap_generation,
        handle,
        "read",
        0,
        512,
        0xB13,
        "b18 file handle capability",
    ));
    graph
}

#[test]
fn block_runtime_b18_fs_wait_resolves_through_wait_token() {
    let mut graph = setup_b18_fs_wait_graph();
    let store = graph.store_id("linux_syscall").unwrap();
    let blocker = ContractObjectRef::new(ContractObjectKind::FileHandleCapability, 1865, 1);
    let create = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b18-test",
        SemanticCommand::CreateWait {
            wait: 1870,
            owner_task: None,
            owner_store: Some(store),
            owner_store_generation: Some(1),
            kind: SemanticWaitKind::FdReadable,
            generation: 1,
            blockers: vec![blocker],
            deadline: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: Some("b18 fs read wait".to_string()),
        },
    ));
    assert_eq!(create.status, CommandStatus::Applied);

    let record = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b18-test",
        SemanticCommand::RecordFsWait {
            fs_wait: 1871,
            wait: 1870,
            wait_generation: 1,
            file_handle_capability: 1865,
            file_handle_capability_generation: 1,
            operation: "read".to_string(),
            sequence: 1,
            note: "record fs wait".to_string(),
        },
    ));
    assert_eq!(record.status, CommandStatus::Applied);
    assert_eq!(graph.fs_wait_count(), 1);
    assert_eq!(graph.fs_waits()[0].state, FsWaitState::Pending);
    assert_eq!(
        graph.fs_waits()[0].object_ref(),
        ContractObjectRef::new(ContractObjectKind::FsWait, 1871, 1)
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        format!(
            "FsWaitCreated fs_wait=1871 wait=1870@1 owner_store={store}@1 file_object=1845@1 directory_object=1850@1 file_handle_capability=1865@1 operation=read blocker=file-handle-capability:1865@1 sequence=1 byte_len=512 generation=1"
        )
    );

    let resolve = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b18-test",
        SemanticCommand::ResolveFsWait {
            fs_wait: 1871,
            fs_wait_generation: 1,
            note: "resolve fs wait".to_string(),
        },
    ));
    assert_eq!(resolve.status, CommandStatus::Applied);
    assert_eq!(graph.fs_waits()[0].state, FsWaitState::Resolved);
    assert_eq!(
        graph
            .wait_index()
            .by_store
            .iter()
            .filter(|(_, _, wait)| *wait == 1870)
            .count(),
        1
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FsWaitResolved fs_wait=1871 wait=1870@1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b18_rejects_stale_or_duplicate_fs_wait_and_cancels_closefd() {
    let mut graph = setup_b18_fs_wait_graph();
    let store = graph.store_id("linux_syscall").unwrap();
    let blocker = ContractObjectRef::new(ContractObjectKind::FileHandleCapability, 1865, 1);
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                4,
                "b18-test",
                SemanticCommand::CreateWait {
                    wait: 1872,
                    owner_task: None,
                    owner_store: Some(store),
                    owner_store_generation: Some(1),
                    kind: SemanticWaitKind::FdReadable,
                    generation: 1,
                    blockers: vec![blocker],
                    deadline: None,
                    restart_policy: RestartPolicy::RestartIfAllowed,
                    saved_context: Some("b18 cancellable fs wait".to_string()),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                5,
                "b18-test",
                SemanticCommand::RecordFsWait {
                    fs_wait: 1873,
                    wait: 1872,
                    wait_generation: 1,
                    file_handle_capability: 1865,
                    file_handle_capability_generation: 1,
                    operation: "read".to_string(),
                    sequence: 2,
                    note: "record cancellable fs wait".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );

    let duplicate = graph.apply_envelope(CommandEnvelope::new(
        6,
        "b18-test",
        SemanticCommand::RecordFsWait {
            fs_wait: 1874,
            wait: 1872,
            wait_generation: 1,
            file_handle_capability: 1865,
            file_handle_capability_generation: 1,
            operation: "read".to_string(),
            sequence: 2,
            note: "duplicate pending fs wait".to_string(),
        },
    ));
    assert_eq!(duplicate.status, CommandStatus::Rejected);
    assert_eq!(
        duplicate.violations,
        vec!["fs wait token already has a pending fs wait".to_string()]
    );

    let stale = graph.apply_envelope(CommandEnvelope::new(
        7,
        "b18-test",
        SemanticCommand::RecordFsWait {
            fs_wait: 1875,
            wait: 1872,
            wait_generation: 1,
            file_handle_capability: 1865,
            file_handle_capability_generation: 2,
            operation: "read".to_string(),
            sequence: 3,
            note: "stale file handle generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["fs wait file handle capability generation is missing or not allowed".to_string()]
    );

    let cancel = graph.apply_envelope(CommandEnvelope::new(
        8,
        "b18-test",
        SemanticCommand::CancelFsWait {
            fs_wait: 1873,
            fs_wait_generation: 1,
            errno: 9,
            reason: WaitCancelReason::CloseFd,
            note: "close fd cancels fs wait".to_string(),
        },
    ));
    assert_eq!(cancel.status, CommandStatus::Applied);
    assert_eq!(graph.fs_waits()[0].state, FsWaitState::Cancelled);
    assert_eq!(
        graph.fs_waits()[0].cancel_reason,
        Some(WaitCancelReason::CloseFd)
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "FsWaitCancelled fs_wait=1873 wait=1872@1 reason=close-fd generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b18_invariants_reject_file_handle_generation_leak() {
    let mut graph = setup_b18_fs_wait_graph();
    let store = graph.store_id("linux_syscall").unwrap();
    let blocker = ContractObjectRef::new(ContractObjectKind::FileHandleCapability, 1865, 1);
    graph.record_wait_created_with_details(
        1876,
        None,
        Some(store),
        Some(1),
        SemanticWaitKind::FdReadable,
        1,
        vec![blocker],
        None,
        RestartPolicy::RestartIfAllowed,
        Some("b18 invariant fs wait".to_string()),
    );
    assert!(graph.record_fs_wait_with_id(
        1877,
        1876,
        1,
        1865,
        1,
        "read",
        4,
        "b18 invariant fs wait",
    ));
    graph.corrupt_fs_wait_file_handle_generation_for_test(1877, 0);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::FsWaitMissingFileHandleCapability {
            fs_wait: 1877,
            file_handle_capability: 1865,
        })
    );
}

fn setup_b19_block_driver_cleanup_graph() -> SemanticGraph {
    let (mut graph, binding) = setup_b6_virtio_blk_backend_graph();
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                1,
                "b19-setup",
                SemanticCommand::RecordVirtioBlkBackendObject {
                    virtio_blk_backend: 1880,
                    name: "virtio-blk0-cleanup-backend".to_string(),
                    block_device: 1791,
                    block_device_generation: 1,
                    driver_binding: binding,
                    driver_binding_generation: 1,
                    provider: "substrate_virtio".to_string(),
                    profile: "virtio-blk-backend-skeleton-v1".to_string(),
                    model: "virtio-blk".to_string(),
                    sector_size: 512,
                    sector_count: 4096,
                    read_only: false,
                    max_transfer_sectors: 128,
                    device_features: 64,
                    driver_features: 64,
                    negotiated_features: 64,
                    request_queue_index: 0,
                    queue_size: 8,
                    irq_vector: 6,
                    note: "b19 cleanup backend".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    assert!(graph.record_block_range_object_with_id(1881, 1791, 1, 8, 8, "b19 cleanup range",));
    assert!(graph.record_block_request_object_with_id(
        1882,
        1791,
        1,
        1881,
        1,
        BlockRequestOperation::Read,
        1,
        "b19 pending request",
    ));
    let store = graph.store_id("driver.virtio-blk0").unwrap();
    let store_generation = graph.store_handle(store).unwrap().generation;
    let blocker = ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1882, 1);
    graph.record_wait_created_with_details(
        1883,
        None,
        Some(store),
        Some(store_generation),
        SemanticWaitKind::DriverCompletion,
        1,
        vec![blocker],
        None,
        RestartPolicy::InternalOnly,
        Some("b19 pending block wait".to_string()),
    );
    assert_eq!(graph.check_invariants(), Ok(()));
    assert!(graph.record_block_wait_with_id(1884, 1883, 1, 1882, 1, "b19 pending block wait",));
    assert!(graph.record_queue_object_with_id(
        1885,
        "virtio-blk0-cleanup-submit",
        QueueObjectRole::Submission,
        1,
        8,
        1790,
        1,
        "b19 cleanup queue",
    ));
    assert!(graph.record_descriptor_object_with_id(
        1886,
        1885,
        1,
        0,
        DescriptorObjectAccess::ReadWrite,
        4096,
        "b19 cleanup descriptor",
    ));
    let dma_resource = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:b19-cleanup");
    let dma_generation = graph.resource_handle(dma_resource).unwrap().generation;
    assert!(graph.record_dma_buffer_object_with_id(
        1887,
        1886,
        1,
        dma_resource,
        dma_generation,
        DmaBufferObjectAccess::ReadWrite,
        4096,
        "b19 cleanup dma buffer",
    ));
    graph
}

#[test]
fn block_runtime_b19_disk_driver_fault_cleanup_cancels_wait_and_releases_authority() {
    let mut graph = setup_b19_block_driver_cleanup_graph();
    let result = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b19-test",
        SemanticCommand::CleanupBlockDriver {
            cleanup: 1888,
            io_cleanup: 1889,
            block_device: 1791,
            block_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, 1880, 1),
            reason: "virtio-blk-device-fault".to_string(),
            note: "b19 cleanup disk driver".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied);
    assert_eq!(graph.block_driver_cleanup_count(), 1);
    let cleanup = &graph.block_driver_cleanups()[0];
    assert_eq!(
        cleanup.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockDriverCleanup, 1888, 1)
    );
    assert_eq!(cleanup.state, BlockDriverCleanupState::Completed);
    assert_eq!(cleanup.cancelled_block_waits.len(), 1);
    assert_eq!(cleanup.cancelled_wait_tokens.len(), 1);
    assert_eq!(cleanup.released_dma_buffers.len(), 1);
    assert_eq!(cleanup.revoked_device_capabilities.len(), 1);
    assert_eq!(graph.block_waits()[0].state, BlockWaitState::Cancelled);
    assert_eq!(graph.wait_records()[0].state, WaitState::Cancelled);
    assert_eq!(
        graph
            .dma_buffer_objects()
            .iter()
            .find(|record| record.id == 1887)
            .unwrap()
            .state,
        DmaBufferObjectState::Released
    );
    assert_eq!(
        graph
            .driver_store_bindings()
            .iter()
            .find(|record| record.id == 1793)
            .unwrap()
            .state,
        DriverStoreBindingState::Released
    );
    assert_eq!(
        graph
            .virtio_blk_backends()
            .iter()
            .find(|record| record.id == 1880)
            .unwrap()
            .state,
        VirtioBlkBackendObjectState::Retired
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockDriverCleanupCompleted cleanup=1888 io_cleanup=1889@1 cancelled_block_waits=1 released_dma_buffers=1 revoked_device_capabilities=1 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b19_rejects_stale_cleanup_and_detects_effect_generation_leak() {
    let mut graph = setup_b19_block_driver_cleanup_graph();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b19-test",
        SemanticCommand::CleanupBlockDriver {
            cleanup: 1890,
            io_cleanup: 1891,
            block_device: 1791,
            block_device_generation: 2,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, 1880, 1),
            reason: "virtio-blk-device-fault".to_string(),
            note: "b19 stale cleanup".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["block driver cleanup block device generation is missing or inactive".to_string()]
    );
    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                4,
                "b19-test",
                SemanticCommand::CleanupBlockDriver {
                    cleanup: 1888,
                    io_cleanup: 1889,
                    block_device: 1791,
                    block_device_generation: 1,
                    backend: ContractObjectRef::new(
                        ContractObjectKind::VirtioBlkBackendObject,
                        1880,
                        1,
                    ),
                    reason: "virtio-blk-device-fault".to_string(),
                    note: "b19 cleanup disk driver".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    graph.corrupt_block_driver_cleanup_wait_generation_for_test(1888, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::BlockDriverCleanupMissingEffectTarget {
                cleanup: 1888,
                target: ContractObjectRef::new(ContractObjectKind::BlockWait, 1884, 2),
            }
        )
    );
}

fn setup_b20_pending_io_policy_graph() -> SemanticGraph {
    let mut graph = setup_b19_block_driver_cleanup_graph();
    assert!(graph.record_block_request_object_with_id(
        1891,
        1791,
        1,
        1881,
        1,
        BlockRequestOperation::Read,
        2,
        "b20 retry request",
    ));
    let store = graph.store_id("driver.virtio-blk0").unwrap();
    let store_generation = graph.store_handle(store).unwrap().generation;
    for (request, wait, block_wait, sequence) in [(1893, 1894, 1895, 3), (1896, 1897, 1898, 4)] {
        assert!(graph.record_block_request_object_with_id(
            request,
            1791,
            1,
            1881,
            1,
            BlockRequestOperation::Read,
            sequence,
            "b20 pending request",
        ));
        graph.record_wait_created_with_details(
            wait,
            None,
            Some(store),
            Some(store_generation),
            SemanticWaitKind::DriverCompletion,
            1,
            vec![ContractObjectRef::new(
                ContractObjectKind::BlockRequestObject,
                request,
                1,
            )],
            None,
            RestartPolicy::InternalOnly,
            Some("b20 pending block wait".to_string()),
        );
        assert!(graph.record_block_wait_with_id(
            block_wait,
            wait,
            1,
            request,
            1,
            "b20 pending block wait",
        ));
    }
    graph
}

#[test]
fn block_runtime_b20_pending_io_policy_records_retry_eio_and_cancel() {
    let mut graph = setup_b20_pending_io_policy_graph();
    for command in [
        CommandEnvelope::new(
            1,
            "b20-test",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 1892,
                block_wait: 1884,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Retry,
                retry_request: Some(1891),
                retry_request_generation: Some(1),
                errno: 11,
                retry_attempt: 1,
                max_retries: 2,
                note: "retry pending block io".to_string(),
            },
        ),
        CommandEnvelope::new(
            2,
            "b20-test",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 1899,
                block_wait: 1895,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Eio,
                retry_request: None,
                retry_request_generation: None,
                errno: 5,
                retry_attempt: 0,
                max_retries: 0,
                note: "return eio".to_string(),
            },
        ),
        CommandEnvelope::new(
            3,
            "b20-test",
            SemanticCommand::ApplyBlockPendingIoPolicy {
                policy: 1900,
                block_wait: 1898,
                block_wait_generation: 1,
                action: BlockPendingIoAction::Cancel,
                retry_request: None,
                retry_request_generation: None,
                errno: 125,
                retry_attempt: 0,
                max_retries: 0,
                note: "cancel pending io".to_string(),
            },
        ),
    ] {
        let result = graph.apply_envelope(command);
        assert_eq!(result.status, CommandStatus::Applied);
    }

    assert_eq!(graph.block_pending_io_policy_count(), 3);
    let retry = graph
        .block_pending_io_policies()
        .iter()
        .find(|record| record.id == 1892)
        .unwrap();
    assert_eq!(retry.action, BlockPendingIoAction::Retry);
    assert_eq!(retry.retry_request, Some(1891));
    assert_eq!(retry.state, BlockPendingIoPolicyState::RetryScheduled);
    assert_eq!(
        graph
            .block_waits()
            .iter()
            .find(|record| record.id == 1884)
            .unwrap()
            .cancel_reason,
        Some(WaitCancelReason::DeviceFault)
    );
    assert_eq!(
        graph
            .block_pending_io_policies()
            .iter()
            .find(|record| record.id == 1899)
            .unwrap()
            .state,
        BlockPendingIoPolicyState::EioReturned
    );
    assert_eq!(
        graph
            .block_waits()
            .iter()
            .find(|record| record.id == 1898)
            .unwrap()
            .cancel_reason,
        Some(WaitCancelReason::ResourceDropped)
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "BlockPendingIoPolicyApplied policy=1900 block_wait=1898@1 wait=1897@1 block_request=1896@1 retry_request=none block_device=1791@1 block_range=1881@1 action=cancel errno=125 retry_attempt=0 max_retries=0 generation=1"
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b20_rejects_stale_retry_and_detects_policy_generation_leak() {
    let mut graph = setup_b20_pending_io_policy_graph();
    let stale = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b20-test",
        SemanticCommand::ApplyBlockPendingIoPolicy {
            policy: 1901,
            block_wait: 1884,
            block_wait_generation: 1,
            action: BlockPendingIoAction::Retry,
            retry_request: Some(1891),
            retry_request_generation: Some(2),
            errno: 11,
            retry_attempt: 1,
            max_retries: 2,
            note: "stale retry generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["retry policy retry request generation is missing or not submitted".to_string()]
    );

    assert_eq!(
        graph
            .apply_envelope(CommandEnvelope::new(
                5,
                "b20-test",
                SemanticCommand::ApplyBlockPendingIoPolicy {
                    policy: 1892,
                    block_wait: 1884,
                    block_wait_generation: 1,
                    action: BlockPendingIoAction::Retry,
                    retry_request: Some(1891),
                    retry_request_generation: Some(1),
                    errno: 11,
                    retry_attempt: 1,
                    max_retries: 2,
                    note: "retry pending block io".to_string(),
                },
            ))
            .status,
        CommandStatus::Applied
    );
    graph.corrupt_block_pending_io_policy_retry_generation_for_test(1892, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::BlockPendingIoPolicyMissingRetryRequest {
                policy: 1892,
                block_request: 1891,
            }
        )
    );
}

#[test]
fn block_runtime_b21_records_stale_block_request_generation_audit() {
    let mut graph = setup_b21_stale_block_request_generation_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let dma_buffer = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 1833, 1);

    let stale_completion = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b21-test",
        SemanticCommand::RecordBlockCompletionObject {
            block_completion: 1840,
            block_request: 1828,
            block_request_generation: 2,
            sequence: 2,
            completed_bytes: 4096,
            status: BlockCompletionStatus::Success,
            note: "b21 stale completion generation".to_string(),
        },
    ));
    assert_eq!(stale_completion.status, CommandStatus::Rejected);
    assert_eq!(
        stale_completion.violations,
        vec!["block completion object block request generation is missing".to_string()]
    );

    graph.ensure_task(21, FrontendKind::Supervisor, "b21-stale-wait-owner");
    graph.record_wait_created_with_details(
        1841,
        Some(21),
        None,
        None,
        SemanticWaitKind::DriverCompletion,
        1,
        vec![ContractObjectRef::new(
            ContractObjectKind::BlockRequestObject,
            1828,
            2,
        )],
        None,
        RestartPolicy::InternalOnly,
        Some("b21 stale wait probe".to_string()),
    );
    let stale_wait = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b21-test",
        SemanticCommand::RecordBlockWait {
            block_wait: 1842,
            wait: 1841,
            wait_generation: 1,
            block_request: 1828,
            block_request_generation: 2,
            note: "b21 stale block wait generation".to_string(),
        },
    ));
    assert_eq!(stale_wait.status, CommandStatus::Rejected);
    assert_eq!(
        stale_wait.violations,
        vec!["block wait request generation is missing or not submitted".to_string()]
    );
    graph.record_wait_cancelled_with_reason(1841, 125, WaitCancelReason::GenerationMismatch);

    let stale_dma = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b21-test",
        SemanticCommand::RecordBlockDmaBuffer {
            block_dma_buffer: 1843,
            backend,
            block_request: 1828,
            block_request_generation: 2,
            dma_buffer: 1833,
            dma_buffer_generation: 1,
            buffer_digest: b10_expected_digest(DmaBufferObjectAccess::ReadWrite),
            note: "b21 stale dma request generation".to_string(),
        },
    ));
    assert_eq!(stale_dma.status, CommandStatus::Rejected);
    assert_eq!(
        stale_dma.violations,
        vec!["block dma buffer request generation is missing".to_string()]
    );

    let stale_queue = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b21-test",
        SemanticCommand::RecordBlockRequestQueue {
            queue: 1844,
            backend,
            block_device: 1824,
            block_device_generation: 1,
            depth: 4,
            entries: vec![BlockRequestQueueEntryRef::pending(1828, 2)],
            note: "b21 stale queue request generation".to_string(),
        },
    ));
    assert_eq!(stale_queue.status, CommandStatus::Rejected);
    assert_eq!(
        stale_queue.violations,
        vec!["block request queue request generation is missing".to_string()]
    );

    let audit = graph.apply_envelope(CommandEnvelope::new(
        5,
        "b21-test",
        SemanticCommand::RecordBlockRequestGenerationAudit {
            audit: 1845,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            block_request: 1828,
            block_request_generation: 1,
            backend,
            dma_buffer,
            rejected_completion_generation_probes: 1,
            rejected_wait_generation_probes: 1,
            rejected_dma_generation_probes: 1,
            rejected_queue_generation_probes: 1,
            note: "b21 stale request generation audit".to_string(),
        },
    ));
    assert_eq!(audit.status, CommandStatus::Applied, "{audit:?}");
    assert_eq!(graph.block_request_generation_audit_count(), 1);
    let audit = &graph.block_request_generation_audits()[0];
    assert_eq!(
        audit.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockRequestGenerationAudit, 1845, 1)
    );
    assert_eq!(audit.block_request, 1828);
    assert_eq!(audit.block_request_generation, 1);
    assert_eq!(audit.backend, backend);
    assert_eq!(audit.dma_buffer, dma_buffer);
    assert_eq!(audit.rejected_completion_generation_probes, 1);
    assert_eq!(audit.rejected_wait_generation_probes, 1);
    assert_eq!(audit.rejected_dma_generation_probes, 1);
    assert_eq!(audit.rejected_queue_generation_probes, 1);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("BlockRequestGenerationAuditRecorded audit=1845")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b21_rejects_missing_probe_counts_and_stale_audit_refs() {
    let mut graph = setup_b21_stale_block_request_generation_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let dma_buffer = ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 1833, 1);

    let missing_probe = graph.apply_envelope(CommandEnvelope::new(
        6,
        "b21-test",
        SemanticCommand::RecordBlockRequestGenerationAudit {
            audit: 1845,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            block_request: 1828,
            block_request_generation: 1,
            backend,
            dma_buffer,
            rejected_completion_generation_probes: 1,
            rejected_wait_generation_probes: 0,
            rejected_dma_generation_probes: 1,
            rejected_queue_generation_probes: 1,
            note: "b21 missing wait probe".to_string(),
        },
    ));
    assert_eq!(missing_probe.status, CommandStatus::Rejected);
    assert_eq!(
        missing_probe.violations,
        vec!["block request generation audit requires rejected probes for all paths".to_string()]
    );

    let stale_request = graph.apply_envelope(CommandEnvelope::new(
        7,
        "b21-test",
        SemanticCommand::RecordBlockRequestGenerationAudit {
            audit: 1845,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            block_request: 1828,
            block_request_generation: 2,
            backend,
            dma_buffer,
            rejected_completion_generation_probes: 1,
            rejected_wait_generation_probes: 1,
            rejected_dma_generation_probes: 1,
            rejected_queue_generation_probes: 1,
            note: "b21 stale audit request ref".to_string(),
        },
    ));
    assert_eq!(stale_request.status, CommandStatus::Rejected);
    assert_eq!(
        stale_request.violations,
        vec![
            "block request generation audit request generation is missing or inactive".to_string()
        ]
    );
}

#[test]
fn block_runtime_b21_invariants_reject_stale_audit_request_generation() {
    let mut graph = setup_b21_stale_block_request_generation_graph();
    assert!(graph.record_block_request_generation_audit_with_id(
        1845,
        1824,
        1,
        1825,
        1,
        1828,
        1,
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        ContractObjectRef::new(ContractObjectKind::DmaBufferObject, 1833, 1),
        1,
        1,
        1,
        1,
        "b21 generation audit",
    ));
    graph.corrupt_block_request_generation_audit_request_generation_for_test(1845, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::BlockRequestGenerationAuditMissingTarget {
                audit: 1845,
                target: ContractObjectRef::new(ContractObjectKind::BlockRequestObject, 1828, 2),
            }
        )
    );
}

fn setup_b22_disk_benchmark_graph() -> SemanticGraph {
    let mut graph = setup_b10_block_dma_buffer_graph(DmaBufferObjectAccess::ReadWrite);
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let read_digest = SemanticGraph::expected_block_read_digest_v1(
        0x766d_6f73_626c_6b39,
        1824,
        1,
        1825,
        1,
        128,
        8,
        1,
        4096,
    );
    let write_digest = SemanticGraph::expected_block_write_payload_digest_v1(
        0x766d_6f73_626c_6b39,
        1824,
        1,
        1825,
        1,
        128,
        8,
        2,
        4096,
    );
    assert!(graph.record_block_read_path_with_id(
        1846,
        backend,
        1826,
        1,
        1827,
        1,
        read_digest,
        "b22 benchmark read path",
    ));
    assert!(graph.record_block_write_path_with_id(
        1847,
        backend,
        1828,
        1,
        1830,
        1,
        write_digest,
        "b22 benchmark write path",
    ));
    assert!(graph.record_block_request_queue_with_id(
        1848,
        backend,
        1824,
        1,
        4,
        &[
            BlockRequestQueueEntryRef::completed(1826, 1, 1827, 1),
            BlockRequestQueueEntryRef::completed(1828, 1, 1830, 1),
        ],
        "b22 benchmark completed queue",
    ));
    assert!(graph.record_block_dma_buffer_with_id(
        1849,
        backend,
        1828,
        1,
        1833,
        1,
        b10_expected_digest(DmaBufferObjectAccess::ReadWrite),
        "b22 benchmark dma-backed write",
    ));
    graph
}

#[test]
fn block_runtime_b22_disk_benchmark_records_iops_latency_evidence() {
    let mut graph = setup_b22_disk_benchmark_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b22-test",
        SemanticCommand::RecordBlockBenchmark {
            benchmark: 1850,
            scenario: "fake block read/write benchmark".to_string(),
            backend,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            read_path: 1846,
            read_path_generation: 1,
            write_path: 1847,
            write_path_generation: 1,
            request_queue: 1848,
            request_queue_generation: 1,
            block_dma_buffer: 1849,
            block_dma_buffer_generation: 1,
            sample_requests: 2,
            sample_bytes: 8192,
            read_completed_requests: 1,
            write_completed_requests: 1,
            queue_completed_requests: 2,
            measured_nanos: 40_000,
            budget_nanos: 80_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 35_000,
            note: "b22 disk benchmark".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.block_benchmark_count(), 1);
    let benchmark = &graph.block_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockBenchmark, 1850, 1)
    );
    assert_eq!(benchmark.backend, backend);
    assert_eq!(benchmark.read_path, 1846);
    assert_eq!(benchmark.write_path, 1847);
    assert_eq!(benchmark.request_queue, 1848);
    assert_eq!(benchmark.block_dma_buffer, 1849);
    assert_eq!(benchmark.sample_requests, 2);
    assert_eq!(benchmark.sample_bytes, 8192);
    assert_eq!(benchmark.iops, 50_000);
    assert_eq!(benchmark.throughput_bytes_per_sec, 204_800_000);
    assert_eq!(benchmark.p50_latency_nanos, 18_000);
    assert_eq!(benchmark.p99_latency_nanos, 35_000);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("BlockBenchmarkRecorded benchmark=1850")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b22_rejects_stale_refs_and_invalid_metrics() {
    let mut graph = setup_b22_disk_benchmark_graph();
    let backend = ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1);
    let stale_read_path = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b22-test",
        SemanticCommand::RecordBlockBenchmark {
            benchmark: 1850,
            scenario: "stale read path".to_string(),
            backend,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            read_path: 1846,
            read_path_generation: 2,
            write_path: 1847,
            write_path_generation: 1,
            request_queue: 1848,
            request_queue_generation: 1,
            block_dma_buffer: 1849,
            block_dma_buffer_generation: 1,
            sample_requests: 2,
            sample_bytes: 8192,
            read_completed_requests: 1,
            write_completed_requests: 1,
            queue_completed_requests: 2,
            measured_nanos: 40_000,
            budget_nanos: 80_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 35_000,
            note: "b22 stale read path".to_string(),
        },
    ));
    assert_eq!(stale_read_path.status, CommandStatus::Rejected);
    assert_eq!(
        stale_read_path.violations,
        vec!["block benchmark read path generation is missing or inactive".to_string()]
    );

    let over_budget = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b22-test",
        SemanticCommand::RecordBlockBenchmark {
            benchmark: 1851,
            scenario: "over budget".to_string(),
            backend,
            block_device: 1824,
            block_device_generation: 1,
            block_range: 1825,
            block_range_generation: 1,
            read_path: 1846,
            read_path_generation: 1,
            write_path: 1847,
            write_path_generation: 1,
            request_queue: 1848,
            request_queue_generation: 1,
            block_dma_buffer: 1849,
            block_dma_buffer_generation: 1,
            sample_requests: 2,
            sample_bytes: 8192,
            read_completed_requests: 1,
            write_completed_requests: 1,
            queue_completed_requests: 2,
            measured_nanos: 90_000,
            budget_nanos: 80_000,
            p50_latency_nanos: 18_000,
            p99_latency_nanos: 35_000,
            note: "b22 over budget".to_string(),
        },
    ));
    assert_eq!(over_budget.status, CommandStatus::Rejected);
    assert_eq!(
        over_budget.violations,
        vec!["block benchmark exceeds latency budget".to_string()]
    );
}

#[test]
fn block_runtime_b22_invariants_reject_iops_metric_drift() {
    let mut graph = setup_b22_disk_benchmark_graph();
    assert!(graph.record_block_benchmark_with_id(
        1850,
        "b22 benchmark",
        ContractObjectRef::new(ContractObjectKind::FakeBlockBackendObject, 1829, 1),
        1824,
        1,
        1825,
        1,
        1846,
        1,
        1847,
        1,
        1848,
        1,
        1849,
        1,
        2,
        8192,
        1,
        1,
        2,
        40_000,
        80_000,
        18_000,
        35_000,
        "b22 invariant benchmark",
    ));
    graph.corrupt_block_benchmark_iops_for_test(1850, 50_001);
    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::BlockBenchmarkInvalid { benchmark: 1850 })
    );
}

fn setup_b23_disk_recovery_benchmark_graph() -> SemanticGraph {
    let mut graph = setup_b19_block_driver_cleanup_graph();
    let cleanup = graph.apply_envelope(CommandEnvelope::new(
        1,
        "b23-test",
        SemanticCommand::CleanupBlockDriver {
            cleanup: 1888,
            io_cleanup: 1889,
            block_device: 1791,
            block_device_generation: 1,
            backend: ContractObjectRef::new(ContractObjectKind::VirtioBlkBackendObject, 1880, 1),
            reason: "virtio-blk-device-fault".to_string(),
            note: "b23 cleanup disk driver".to_string(),
        },
    ));
    assert_eq!(cleanup.status, CommandStatus::Applied);
    graph
}

#[test]
fn block_runtime_b23_disk_recovery_benchmark_records_cleanup_latency_evidence() {
    let mut graph = setup_b23_disk_recovery_benchmark_graph();
    let cleanup = graph.block_driver_cleanups()[0].clone();
    let completed_at_event = cleanup.completed_at_event.unwrap();
    let result = graph.apply_envelope(CommandEnvelope::new(
        2,
        "b23-test",
        SemanticCommand::RecordBlockRecoveryBenchmark {
            benchmark: 1852,
            scenario: "disk driver recovery benchmark".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: completed_at_event,
            cancelled_block_waits: cleanup.cancelled_block_waits.len() as u32,
            cancelled_wait_tokens: cleanup.cancelled_wait_tokens.len() as u32,
            released_dma_buffers: cleanup.released_dma_buffers.len() as u32,
            revoked_device_capabilities: cleanup.revoked_device_capabilities.len() as u32,
            recovery_nanos: 70_000,
            budget_nanos: 150_000,
            note: "b23 disk recovery benchmark".to_string(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.block_recovery_benchmark_count(), 1);
    let benchmark = &graph.block_recovery_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::BlockRecoveryBenchmark, 1852, 1)
    );
    assert_eq!(benchmark.cleanup, cleanup.id);
    assert_eq!(benchmark.cleanup_generation, cleanup.generation);
    assert_eq!(benchmark.backend, cleanup.backend);
    assert_eq!(benchmark.block_device, cleanup.block_device);
    assert_eq!(benchmark.driver_store, cleanup.driver_store);
    assert_eq!(benchmark.cancelled_block_waits, 1);
    assert_eq!(benchmark.cancelled_wait_tokens, 1);
    assert_eq!(benchmark.released_dma_buffers, 1);
    assert_eq!(benchmark.revoked_device_capabilities, 1);
    assert_eq!(benchmark.recovery_nanos, 70_000);
    assert!(
        graph.event_log_tail(1)[0]
            .kind
            .summary()
            .contains("BlockRecoveryBenchmarkRecorded benchmark=1852")
    );
    assert!(graph.check_invariants().is_ok());
}

#[test]
fn block_runtime_b23_rejects_stale_cleanup_and_budget_overrun() {
    let mut graph = setup_b23_disk_recovery_benchmark_graph();
    let cleanup = graph.block_driver_cleanups()[0].clone();
    let completed_at_event = cleanup.completed_at_event.unwrap();
    let stale_cleanup = graph.apply_envelope(CommandEnvelope::new(
        3,
        "b23-test",
        SemanticCommand::RecordBlockRecoveryBenchmark {
            benchmark: 1852,
            scenario: "stale cleanup".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation + 1,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: completed_at_event,
            cancelled_block_waits: cleanup.cancelled_block_waits.len() as u32,
            cancelled_wait_tokens: cleanup.cancelled_wait_tokens.len() as u32,
            released_dma_buffers: cleanup.released_dma_buffers.len() as u32,
            revoked_device_capabilities: cleanup.revoked_device_capabilities.len() as u32,
            recovery_nanos: 70_000,
            budget_nanos: 150_000,
            note: "b23 stale cleanup".to_string(),
        },
    ));
    assert_eq!(stale_cleanup.status, CommandStatus::Rejected);
    assert_eq!(
        stale_cleanup.violations,
        vec!["block recovery benchmark cleanup generation is missing or incomplete".to_string()]
    );

    let over_budget = graph.apply_envelope(CommandEnvelope::new(
        4,
        "b23-test",
        SemanticCommand::RecordBlockRecoveryBenchmark {
            benchmark: 1853,
            scenario: "over budget".to_string(),
            cleanup: cleanup.id,
            cleanup_generation: cleanup.generation,
            io_cleanup: cleanup.io_cleanup,
            io_cleanup_generation: cleanup.io_cleanup_generation,
            recovery_start_event: cleanup.started_at_event,
            recovery_complete_event: completed_at_event,
            cancelled_block_waits: cleanup.cancelled_block_waits.len() as u32,
            cancelled_wait_tokens: cleanup.cancelled_wait_tokens.len() as u32,
            released_dma_buffers: cleanup.released_dma_buffers.len() as u32,
            revoked_device_capabilities: cleanup.revoked_device_capabilities.len() as u32,
            recovery_nanos: 160_000,
            budget_nanos: 150_000,
            note: "b23 over budget".to_string(),
        },
    ));
    assert_eq!(over_budget.status, CommandStatus::Rejected);
    assert_eq!(
        over_budget.violations,
        vec!["block recovery benchmark exceeds recovery budget".to_string()]
    );
}

#[test]
fn block_runtime_b23_invariants_reject_cleanup_generation_leak() {
    let mut graph = setup_b23_disk_recovery_benchmark_graph();
    let cleanup = graph.block_driver_cleanups()[0].clone();
    let completed_at_event = cleanup.completed_at_event.unwrap();
    assert!(graph.record_block_recovery_benchmark_with_id(
        1852,
        "b23 recovery benchmark",
        cleanup.id,
        cleanup.generation,
        cleanup.io_cleanup,
        cleanup.io_cleanup_generation,
        cleanup.started_at_event,
        completed_at_event,
        cleanup.cancelled_block_waits.len() as u32,
        cleanup.cancelled_wait_tokens.len() as u32,
        cleanup.released_dma_buffers.len() as u32,
        cleanup.revoked_device_capabilities.len() as u32,
        70_000,
        150_000,
        "b23 invariant benchmark",
    ));
    graph.corrupt_block_recovery_benchmark_cleanup_generation_for_test(1852, 2);
    assert_eq!(
        graph.check_invariants(),
        Err(
            SemanticInvariantError::BlockRecoveryBenchmarkMissingTarget {
                benchmark: 1852,
                target: ContractObjectRef::new(ContractObjectKind::BlockDriverCleanup, 1888, 2),
            }
        )
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
fn simd_runtime_v0_target_feature_set_records_default_discovery() {
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
fn simd_runtime_v0_rejects_inconsistent_target_feature_discovery() {
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
fn simd_runtime_v0_invariants_reject_vector_shape_drift() {
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
        Err(SemanticInvariantError::TargetFeatureSetInvalid {
            feature_set: 21_000
        })
    );
}

#[test]
fn simd_runtime_v4_vector_state_records_unavailable_context_object() {
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
fn simd_runtime_v4_rejects_reserved_vector_state_without_target_support() {
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
fn simd_runtime_v4_invariants_reject_vector_state_event_drift() {
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
        Err(SemanticInvariantError::VectorStateMissingEvent {
            vector_state: 22_000,
            event: 2
        })
    );
}

fn v5_activation_context_with_reserved_vector_state() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "simd-vector-task");
    let store = graph.register_store(
        "v5.simd.store",
        "v5-simd-context.fake-aot",
        "service",
        "restartable",
    );
    graph.set_store_state(store, StoreState::Running);
    let store_generation = graph
        .store_handle(store)
        .map(|handle| handle.generation)
        .expect("store generation");
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
fn simd_runtime_v5_activation_context_tracks_dirty_and_clean_vector_state() {
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
    assert_eq!(
        graph.activation_contexts()[0].vector_status,
        ActivationVectorState::Dirty
    );
    assert_eq!(
        graph.activation_contexts()[0].vector_state,
        Some(vector_ref)
    );
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
    assert_eq!(
        graph.activation_contexts()[0].vector_status,
        ActivationVectorState::Clean
    );
    assert_eq!(graph.activation_contexts()[0].generation, 3);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "ActivationContextVectorStateUpdated context=12@2->3 vector_state=vector-state:22000@1 vector_status=clean generation=1"
    );
}

#[test]
fn simd_runtime_v5_rejects_missing_or_stale_vector_state_ref() {
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
            vector_state: Some(ContractObjectRef::new(
                ContractObjectKind::VectorState,
                22_000,
                2,
            )),
            vector_status: ActivationVectorState::Clean,
            note: "stale vector generation".to_string(),
        },
    ));
    assert_eq!(stale.status, CommandStatus::Rejected);
    assert_eq!(
        stale.violations,
        vec!["activation context vector state is missing".to_string()]
    );
    assert_eq!(
        graph.activation_contexts()[0].vector_status,
        ActivationVectorState::Absent
    );
}

#[test]
fn simd_runtime_v5_invariants_reject_vector_context_generation_drift() {
    let mut graph = v5_activation_context_with_reserved_vector_state();
    assert!(graph.update_activation_context_vector_state(
        12,
        1,
        Some(ContractObjectRef::new(
            ContractObjectKind::VectorState,
            22_000,
            1,
        )),
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
fn simd_runtime_v6_lazy_enable_transitions_absent_context_to_dirty() {
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
    assert_eq!(
        graph.activation_contexts()[0].vector_status,
        ActivationVectorState::Dirty
    );
    assert_eq!(
        graph.activation_contexts()[0].vector_state,
        Some(vector_ref)
    );
    assert_eq!(graph.activation_contexts()[0].generation, 2);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "LazyVectorStateEnabled context=12@1->2 vector_state=vector-state:22000@1 vector_status=dirty generation=1"
    );
}

#[test]
fn simd_runtime_v6_rejects_lazy_enable_when_context_already_has_vector_state() {
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
fn simd_runtime_v6_rejects_lazy_enable_with_unavailable_vector_state() {
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
