use super::*;

#[test]
pub(super) fn command_surface_grants_capability_and_precondition_failures_are_atomic() {
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
    assert!(graph.check_capability("driver", "packet-device.net0", "rx").is_ok());

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
pub(super) fn command_envelope_records_events_and_rejects_without_partial_mutation() {
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
pub(super) fn command_envelope_epoch_mismatch_is_atomic() {
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
pub(super) fn command_surface_rejected_precondition_leaves_semantic_state_unchanged() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "linux-thread-7");
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(11, 7, 1, None, None, None));

    let task_before = graph.tasks()[0].clone();
    let activation_before = graph.runtime_activations()[0].clone();
    let queue_before = graph.runnable_queues()[0].clone();
    let event_count_before = graph.event_count();
    let command_result_count_before = graph.command_results().len();

    let result = graph.apply(SemanticCommand::EnqueueRunnable {
        queue: 1,
        activation: 11,
        activation_generation: 99,
    });

    assert_eq!(
        result,
        Err(CommandError::PreconditionFailed("activation generation mismatch".to_string()))
    );
    assert_eq!(graph.tasks()[0], task_before);
    assert_eq!(graph.runtime_activations()[0], activation_before);
    assert_eq!(graph.runnable_queues()[0], queue_before);
    assert_eq!(graph.event_count(), event_count_before);
    assert_eq!(graph.command_results().len(), command_result_count_before);
    assert_eq!(graph.check_invariants(), Ok(()));
}

#[test]
pub(super) fn command_surface_wait_and_cleanup_transactions_are_canonical_and_idempotent() {
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
        .apply(SemanticCommand::ResolveWait { wait: 41, reason: "timer".to_string() })
        .expect("resolve wait");
    assert_eq!(graph.wait_records()[0].state, WaitState::Resolved);
    assert_eq!(
        graph.apply(SemanticCommand::CancelWait {
            wait: 41,
            errno: 125,
            reason: WaitCancelReason::Signal,
        }),
        Err(CommandError::PreconditionFailed("wait is not pending".to_string()))
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
    let first_commit =
        graph.apply(SemanticCommand::CommitCleanup { cleanup: 77 }).expect("commit cleanup");
    assert!(first_commit.changed);
    assert_eq!(graph.active_transaction_count(), 0);
    assert_eq!(
        graph.apply(SemanticCommand::CommitCleanup { cleanup: 77 }),
        Err(CommandError::PreconditionFailed("cleanup transaction is not active".to_string()))
    );
}

#[test]
pub(super) fn stale_resource_handles_are_rejected() {
    let mut graph = SemanticGraph::new();
    let resource = graph.register_resource(ResourceKind::Fd, None, "fd:/sandbox/hello.txt");
    let handle = graph.resource_handle(resource).expect("resource handle");

    assert_eq!(graph.validate_resource_handle(handle), Ok(()));
    graph.close_resource(resource);
    assert_eq!(
        graph.validate_resource_handle(handle),
        Err(GenerationCheckError::GenerationMismatch { expected: 1, actual: Some(2) })
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "ResourceHandleRejected resource=1 expected=1 actual=2 reason=generation-mismatch"
    );
}

#[test]
pub(super) fn stale_wait_tokens_are_rejected() {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
    graph.record_wait_created(11, 7, SemanticWaitKind::Timer, 3);
    let handle = graph.wait_handle(11).expect("wait handle");

    assert_eq!(graph.validate_wait_handle(handle), Ok(()));
    assert_eq!(
        graph.validate_wait_handle(WaitHandle::new(11, 2)),
        Err(GenerationCheckError::GenerationMismatch { expected: 2, actual: Some(3) })
    );
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "WaitTokenRejected wait=11 expected=2 actual=3 reason=generation-mismatch"
    );
}

#[test]
pub(super) fn store_lifecycle_rebinds_instance_resource() {
    let mut graph = SemanticGraph::new();
    let store = graph.register_store("procfs_service", "procfs", "service", "restartable");

    graph.set_store_state(store, StoreState::Instantiating);
    graph.set_store_state(store, StoreState::Running);
    let first_resource = graph.store_resource(store).expect("initial store resource");

    graph.record_store_trap(store, "injected procfs read fault");
    graph.set_store_state(store, StoreState::Draining);
    graph.set_store_state(store, StoreState::Restarting);
    let drop_report = graph.drop_store_instance(store).expect("dropped store instance");
    assert_eq!(drop_report.previous_resource, Some(first_resource));
    assert_eq!(drop_report.closed_resources, 1);
    assert_eq!(
        graph.validate_resource_handle(ResourceHandle::new(first_resource, 1)),
        Err(GenerationCheckError::GenerationMismatch { expected: 1, actual: Some(2) })
    );

    let rebind_report = graph.rebind_store_instance(store).expect("rebound store resource");
    let second_resource = rebind_report.resource;
    graph.set_store_state(store, StoreState::Running);

    assert_ne!(first_resource, second_resource);
    assert_eq!(graph.store_count(), 1);
    assert_eq!(graph.live_resource_count(), 1);
    assert_eq!(graph.stores()[0].restart_count, 1);
    assert_eq!(graph.stores()[0].state, StoreState::Running);
    assert_eq!(graph.event_log_tail(1)[0].kind.summary(), "FaultDomainRestarted domain=1");
}

#[test]
pub(super) fn store_executor_transitions_are_recorded_in_event_log() {
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
pub(super) fn transaction_rollback_and_store_owned_resource_cleanup_are_recorded() {
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
        Err(GenerationCheckError::GenerationMismatch { expected: 1, actual: Some(2) })
    );
    assert_eq!(graph.transactions()[0].state, TransactionState::RolledBack);
    assert!(graph.event_log_tail(32).iter().any(|event| matches!(
        event.kind,
        EventKind::FaultClassified { trap: TrapClass::ServiceTrap, class: FaultClass::Service, .. }
    )));
}
