use super::*;
use alloc::format;
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
