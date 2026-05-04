use super::*;

#[test]
pub(super) fn store_activation_roots_and_handles_are_generation_checked() {
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
    let handle = graph.store_activation_handle(store).expect("activation handle");
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
        Err(GenerationCheckError::GenerationMismatch { expected: 1, actual: Some(2) })
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
pub(super) fn capability_ledger_reports_owner_recovery_state() {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("driver", "driver", "driver", "restartable");
    graph.grant_manifest_capability("driver", "mmio.bar0", &["read", "write"], "store");
    graph.grant_capability("driver", "irq11", &["ack"], "store");
    let mmio =
        graph.capabilities().check("driver", "mmio.bar0", "read").expect("manifest capability");
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
pub(super) fn capability_check_records_denial_and_generation_mismatch() {
    let mut graph = SemanticGraph::new();
    let generation = {
        graph.grant_capability("linux_syscall", "timer.sleep", &["arm"], "wait-token");
        graph.capability_generation("linux_syscall", "timer.sleep").expect("capability generation")
    };

    assert!(graph.check_capability("linux_syscall", "timer.sleep", "arm").is_ok());
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
pub(super) fn wait_flow_is_recorded_in_event_log() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
    graph.set_task_state(7, TaskState::Running);

    graph.record_wait_created(11, 7, SemanticWaitKind::Futex, 1);
    graph.record_wait_resolved(11, "ready");

    assert_eq!(graph.wait_count(), 1);
    assert_eq!(graph.event_log_tail(1)[0].kind.summary(), "WaitResolved wait=11 reason=ready");
}

#[test]
pub(super) fn wait_token_event_bridge_indexes_resolves_cancels_and_restarts() {
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
    let cancelled = graph.wait_records().iter().find(|wait| wait.id == 22).expect("cancelled wait");
    assert_eq!(cancelled.state, WaitState::Cancelled);
    assert_eq!(cancelled.cancel_reason, Some(WaitCancelReason::CapabilityRevoked));

    graph.record_wait_created(23, 7, SemanticWaitKind::Futex, 1);
    let old_handle = graph.wait_handle(23).expect("wait handle");
    graph.record_wait_interrupted(23, WaitCancelReason::Signal);
    graph.record_wait_restarted(23, "restart-if-allowed");
    assert_eq!(
        graph.validate_wait_handle(old_handle),
        Err(GenerationCheckError::GenerationMismatch { expected: 1, actual: Some(2) })
    );
}

#[test]
pub(super) fn linux_wait_service_convergence_records_epoll_and_futex_states() {
    let mut graph = SemanticGraph::new();
    let epoll_store = graph.register_store(
        "epoll_service",
        "epoll_service.cwasm",
        "reference-service",
        "restartable",
    );
    let futex_store = graph.register_store(
        "futex_service",
        "futex_service.cwasm",
        "reference-service",
        "restartable",
    );
    let epoll_cap = graph.grant_capability(
        "epoll_service",
        "epoll.instance",
        &["create", "ctl", "wait"],
        "store",
    );
    let futex_cap = graph.grant_capability("futex_service", "futex.waitset", &["wait"], "store");
    let epoll_blocker = ContractObjectRef::new(ContractObjectKind::Capability, epoll_cap, 1);
    let futex_blocker = ContractObjectRef::new(ContractObjectKind::Capability, futex_cap, 1);

    graph.record_wait_created_with_details(
        31,
        None,
        Some(epoll_store),
        Some(1),
        SemanticWaitKind::Epoll,
        1,
        {
            let mut blockers = Vec::new();
            blockers.push(epoll_blocker);
            blockers
        },
        Some(250),
        RestartPolicy::RestartWithAdjustedTimeout,
        Some("linux-wait-service:epoll_wait:pending".to_string()),
    );
    graph.record_wait_created_with_details(
        32,
        None,
        Some(epoll_store),
        Some(1),
        SemanticWaitKind::Epoll,
        1,
        {
            let mut blockers = Vec::new();
            blockers.push(epoll_blocker);
            blockers
        },
        None,
        RestartPolicy::RestartIfAllowed,
        Some("linux-wait-service:epoll_wait:resume-ready".to_string()),
    );
    graph.record_wait_resolved(32, "epoll-ready");
    graph.record_wait_consumed(32);
    graph.record_wait_created_with_details(
        33,
        None,
        Some(futex_store),
        Some(1),
        SemanticWaitKind::Futex,
        1,
        {
            let mut blockers = Vec::new();
            blockers.push(futex_blocker);
            blockers
        },
        Some(500),
        RestartPolicy::InternalOnly,
        Some("linux-wait-service:futex_wait:timeout-cancel".to_string()),
    );
    graph.record_wait_cancelled_with_reason(33, 110, WaitCancelReason::Timeout);
    graph.record_wait_created_with_details(
        34,
        None,
        Some(epoll_store),
        Some(1),
        SemanticWaitKind::Epoll,
        1,
        {
            let mut blockers = Vec::new();
            blockers.push(epoll_blocker);
            blockers
        },
        Some(750),
        RestartPolicy::RestartIfAllowed,
        Some("linux-wait-service:epoll_wait:restart-driver".to_string()),
    );
    graph.record_wait_restarted(34, "driver-restart");

    let pending_epoll =
        graph.wait_records().iter().find(|wait| wait.id == 31).expect("pending epoll wait");
    assert_eq!(pending_epoll.kind, SemanticWaitKind::Epoll);
    assert_eq!(pending_epoll.state, WaitState::Pending);
    assert_eq!(pending_epoll.owner_store, Some(epoll_store));
    assert_eq!(pending_epoll.blockers, {
        let mut blockers = Vec::new();
        blockers.push(epoll_blocker);
        blockers
    });
    assert_eq!(
        pending_epoll.saved_context.as_deref(),
        Some("linux-wait-service:epoll_wait:pending")
    );

    let resumed_epoll =
        graph.wait_records().iter().find(|wait| wait.id == 32).expect("resumed epoll wait");
    assert_eq!(resumed_epoll.state, WaitState::Consumed);

    let cancelled_futex =
        graph.wait_records().iter().find(|wait| wait.id == 33).expect("cancelled futex wait");
    assert_eq!(cancelled_futex.kind, SemanticWaitKind::Futex);
    assert_eq!(cancelled_futex.state, WaitState::Cancelled);
    assert_eq!(cancelled_futex.cancel_reason, Some(WaitCancelReason::Timeout));
    assert_eq!(
        cancelled_futex.saved_context.as_deref(),
        Some("linux-wait-service:futex_wait:timeout-cancel")
    );

    let restarted_epoll =
        graph.wait_records().iter().find(|wait| wait.id == 34).expect("restarted epoll wait");
    assert_eq!(restarted_epoll.state, WaitState::Restarted);
    assert_eq!(restarted_epoll.generation, 2);
    assert!(
        graph
            .event_log_tail(8)
            .iter()
            .any(|event| event.kind.summary() == "WaitRestarted wait=34 class=driver-restart")
    );
}

#[test]
pub(super) fn wait_contract_graph_rejects_hidden_or_stale_live_waits() {
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
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
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
pub(super) fn contract_graph_rejects_active_capability_and_wait_owned_by_old_store_generation() {
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
        object_ref: Some(AuthorityObjectRef::internal(CapabilityClass::PacketDevice, object)),
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
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
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
