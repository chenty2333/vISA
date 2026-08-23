use visa_coordinator::{
    ActionKind, ActionMode, AuthorityPort, Coordinator, Decision, Observation, RecordStore as _,
    RecoveryRequirement, RuntimePort, WorkflowIntent,
};
use visa_core::{
    ContinuationId, ContinuationIntent, Digest, ExternalCoordinate, LineageId, LineagePoint,
    OpaqueBytes, OperationId, Rights, ScopeId,
};
use visa_reference::{
    Authority, ReferenceDatabase, ReferenceRuntime, authority::REFERENCE_AUTHORITY_ID,
    store::RecordStore,
};

fn source_coordinate(binding: &visa_reference::SourceBinding) -> ExternalCoordinate {
    ExternalCoordinate {
        authority: REFERENCE_AUTHORITY_ID,
        value: OpaqueBytes(binding.binding_id.as_bytes().to_vec()),
    }
}

fn intent(id: u128, source: ExternalCoordinate) -> WorkflowIntent {
    WorkflowIntent {
        continuation: ContinuationIntent {
            id: ContinuationId::from_u128(id),
            scope: ScopeId::from_u128(1),
            lineage_parent: LineagePoint {
                semantic_domain: ReferenceRuntime::semantic_domain_ref()
                    .expect("embedded semantic domain"),
                lineage: LineageId::from_u128(1),
                generation: 0,
                state_digest: Digest::of_bytes(b"initial"),
            },
            profile: ReferenceRuntime::profile_ref(),
        },
        source,
        destination: ExternalCoordinate {
            authority: REFERENCE_AUTHORITY_ID,
            value: OpaqueBytes(b"reference-destination".to_vec()),
        },
    }
}

fn drive(
    coordinator: &mut Coordinator<RecordStore>,
    id: ContinuationId,
    runtime: &mut ReferenceRuntime,
    authority: &mut Authority,
    next_operation: &mut u128,
) {
    for _ in 0..64 {
        match coordinator.plan(&id).expect("plan") {
            Decision::Arm(_) => {
                coordinator.arm(&id, OperationId::from_u128(*next_operation)).expect("arm");
                *next_operation += 1;
            }
            Decision::Action { .. } => {
                coordinator.step(&id, runtime, authority).expect("step");
            }
            Decision::Complete => return,
            other => panic!("unexpected workflow decision: {other:?}"),
        }
    }
    panic!("workflow did not finish")
}

fn drive_until_permit(
    coordinator: &mut Coordinator<RecordStore>,
    id: ContinuationId,
    runtime: &mut ReferenceRuntime,
    authority: &mut Authority,
    next_operation: &mut u128,
) {
    for _ in 0..64 {
        match coordinator.plan(&id).expect("plan") {
            Decision::Arm(visa_coordinator::ActionKind::PermitActivation) => return,
            Decision::Arm(_) => {
                coordinator.arm(&id, OperationId::from_u128(*next_operation)).expect("arm");
                *next_operation += 1;
            }
            Decision::Action { .. } => {
                coordinator.step(&id, runtime, authority).expect("step");
            }
            other => panic!("unexpected pre-permit decision: {other:?}"),
        }
    }
    panic!("workflow did not reach activation permit")
}

fn drive_until_arm(
    coordinator: &mut Coordinator<RecordStore>,
    id: ContinuationId,
    runtime: &mut ReferenceRuntime,
    authority: &mut Authority,
    next_operation: &mut u128,
    target: ActionKind,
) {
    for _ in 0..64 {
        match coordinator.plan(&id).expect("plan") {
            Decision::Arm(kind) if kind == target => return,
            Decision::Arm(_) => {
                coordinator.arm(&id, OperationId::from_u128(*next_operation)).expect("arm");
                *next_operation += 1;
            }
            Decision::Action { .. } => {
                coordinator.step(&id, runtime, authority).expect("step");
            }
            other => panic!("unexpected workflow decision before {target:?}: {other:?}"),
        }
    }
    panic!("workflow did not reach {target:?}")
}

#[test]
fn continuation_uses_fresh_destination_and_preserves_counter_and_revision() {
    let database = ReferenceDatabase::in_memory().expect("database");
    let mut authority = Authority::new(database.clone()).expect("authority");
    let source = authority.bootstrap_source("counter", 1, Rights(3)).expect("source binding");
    let source_coord = source_coordinate(&source);
    let mut runtime =
        ReferenceRuntime::with_source(database.clone(), authority.clone(), source.clone())
            .expect("runtime");
    assert_eq!(runtime.increment_counter().expect("first increment"), (1, 1));
    assert_eq!(runtime.increment_counter().expect("second increment"), (2, 2));

    let store = RecordStore::new(database.clone());
    let probe = store.clone();
    let mut coordinator = Coordinator::new(store);
    let workflow = intent(1, source_coord.clone());
    let id = workflow.continuation.id;
    coordinator.begin(workflow).expect("begin");
    let mut operation = 10;
    drive_until_permit(&mut coordinator, id, &mut runtime, &mut authority, &mut operation);

    let record = probe.load(&id).expect("load").expect("record");
    let snapshot = record.core.snapshot.as_ref().expect("snapshot");
    let successor = snapshot.successor_point().expect("canonical successor");
    let mut overlapping = intent(2, source_coord.clone());
    overlapping.continuation.lineage_parent = successor.clone();
    assert!(
        Coordinator::new(RecordStore::new(database.clone())).begin(overlapping).is_err(),
        "committed continuation retains the lineage lease until retirement"
    );
    let preparation = record.destination_prepared.expect("preparation");
    assert!(
        runtime.destination_provider_value(preparation.operation).is_err(),
        "destination provider gate stays closed before permit"
    );
    let binding = record.bindings.expect("bindings");
    let destination_id =
        String::from_utf8(binding.grants[0].binding.value.0.clone()).expect("binding id");
    assert!(!authority.binding(&destination_id).expect("binding").expect("view").dispatch_open);
    drive(&mut coordinator, id, &mut runtime, &mut authority, &mut operation);
    assert_eq!(
        runtime
            .destination_provider_value(preparation.operation)
            .expect("provider value")
            .expect("entry")
            .1,
        2
    );
    assert_eq!(runtime.destination_value(preparation.operation).expect("destination value"), 2);
    assert_eq!(
        runtime
            .increment_destination_counter(preparation.operation)
            .expect("destination increment"),
        (3, 3)
    );
    let source_view = authority.binding(&source.binding_id).expect("binding").expect("source view");
    assert!(source_view.fenced);
    assert!(!source_view.active);
    assert!(runtime.increment_counter().is_err());

    let mut stale = Coordinator::new(RecordStore::new(database.clone()));
    assert!(stale.begin(intent(2, source_coord)).is_err(), "lineage head CAS rejects stale parent");
    let mut successor_intent = intent(3, source_coordinate(&source));
    successor_intent.continuation.lineage_parent = successor;
    Coordinator::new(RecordStore::new(database))
        .begin(successor_intent)
        .expect("retirement releases the lineage for its committed successor");
}

#[test]
fn capture_arm_is_indeterminate_and_sealed_restart_never_refreezes() {
    let database = ReferenceDatabase::in_memory().expect("database");
    let mut authority = Authority::new(database.clone()).expect("authority");
    let source = authority.bootstrap_source("counter", 1, Rights(3)).expect("source binding");
    let unsealed_coord = source_coordinate(&source);
    let mut runtime = ReferenceRuntime::with_source(database.clone(), authority.clone(), source)
        .expect("runtime");
    runtime.increment_counter().expect("increment");
    let store = RecordStore::new(database.clone());
    let mut coordinator = Coordinator::new(store);
    let workflow = intent(3, unsealed_coord);
    let id = workflow.continuation.id;
    coordinator.begin(workflow).expect("begin");
    let action = coordinator.arm(&id, OperationId::from_u128(30)).expect("capture arm");
    runtime.arm_capture_without_sealing_for_test(&action).expect("durable runtime arm");
    assert!(matches!(runtime.query_capture(&action), Observation::Indeterminate));
    let mut conflicting = action.clone();
    conflicting.request_digest = Digest::of_bytes(b"different request material");
    assert!(matches!(runtime.query_capture(&conflicting), Observation::Unverifiable(_)));
    coordinator.abort(&id).expect("operator abort request");
    assert!(matches!(
        coordinator.step(&id, &mut runtime, &mut authority).expect("query unknown capture"),
        Decision::Action { mode: ActionMode::Query, .. }
    ));
    assert_eq!(
        RecordStore::new(database.clone())
            .load(&id)
            .expect("load unknown capture")
            .expect("record")
            .recovery,
        Some(RecoveryRequirement::CaptureUnknown)
    );

    let database = ReferenceDatabase::in_memory().expect("second database");
    let mut authority = Authority::new(database.clone()).expect("second authority");
    let source = authority.bootstrap_source("restart", 1, Rights(3)).expect("source binding");
    let restarted_coord = source_coordinate(&source);
    let mut runtime = ReferenceRuntime::with_source(database.clone(), authority.clone(), source)
        .expect("runtime");
    runtime.increment_counter().expect("increment");
    let store = RecordStore::new(database.clone());
    let mut coordinator = Coordinator::new(store);
    let workflow = intent(4, restarted_coord);
    let id = workflow.continuation.id;
    coordinator.begin(workflow).expect("begin");
    let action = coordinator.arm(&id, OperationId::from_u128(40)).expect("capture arm");
    assert!(matches!(runtime.query_capture(&action), Observation::Absent));
    coordinator
        .observe(
            &id,
            &action,
            Observation::<visa_coordinator::CapturedSnapshot, visa_reference::RuntimeError>::Absent,
        )
        .expect("allow invoke");
    coordinator.begin_invoke(&id, &action).expect("persist invoke boundary");
    assert!(matches!(runtime.capture(&action), Observation::Applied(_)));
    drop(runtime);

    let mut restarted =
        ReferenceRuntime::new(database, authority.clone()).expect("restart runtime");
    assert!(matches!(
        coordinator.plan(&id).expect("restart plan"),
        Decision::Action { mode: ActionMode::Query, .. }
    ));
    assert!(matches!(restarted.query_capture(&action), Observation::Applied(_)));
    coordinator.step(&id, &mut restarted, &mut authority).expect("lost-ack recovery step");
}

#[test]
fn commit_and_runtime_activation_lost_acks_are_recovered_by_exact_query() {
    let database = ReferenceDatabase::in_memory().expect("database");
    let mut authority = Authority::new(database.clone()).expect("authority");
    let source = authority.bootstrap_source("lost-ack", 1, Rights(3)).expect("source binding");
    let mut runtime =
        ReferenceRuntime::with_source(database.clone(), authority.clone(), source.clone())
            .expect("runtime");
    runtime.increment_counter().expect("increment");
    let mut coordinator = Coordinator::new(RecordStore::new(database.clone()));
    let workflow = intent(7, source_coordinate(&source));
    let id = workflow.continuation.id;
    coordinator.begin(workflow).expect("begin");
    let mut operation = 70;

    drive_until_arm(
        &mut coordinator,
        id,
        &mut runtime,
        &mut authority,
        &mut operation,
        ActionKind::CommitFence,
    );
    let commit = coordinator.arm(&id, OperationId::from_u128(operation)).expect("commit arm");
    operation += 1;
    coordinator.step(&id, &mut runtime, &mut authority).expect("commit absent query");
    coordinator.begin_invoke(&id, &commit).expect("persist commit invoke");
    assert!(matches!(authority.commit_fence(&commit), Observation::Applied(_)));
    let mut coordinator = Coordinator::new(RecordStore::new(database.clone()));
    assert!(matches!(
        coordinator.plan(&id).expect("restart plan"),
        Decision::Action { mode: ActionMode::Query, .. }
    ));
    coordinator.step(&id, &mut runtime, &mut authority).expect("commit exact query");
    assert!(authority.binding(&source.binding_id).expect("binding").expect("source").fenced);

    drive_until_arm(
        &mut coordinator,
        id,
        &mut runtime,
        &mut authority,
        &mut operation,
        ActionKind::Activate,
    );
    let activation =
        coordinator.arm(&id, OperationId::from_u128(operation)).expect("activation arm");
    operation += 1;
    coordinator.step(&id, &mut runtime, &mut authority).expect("activation absent query");
    coordinator.begin_invoke(&id, &activation).expect("persist activation invoke");
    assert!(matches!(runtime.activate(&activation), Observation::Applied(_)));
    let mut coordinator = Coordinator::new(RecordStore::new(database));
    coordinator.step(&id, &mut runtime, &mut authority).expect("activation exact query");
    drive(&mut coordinator, id, &mut runtime, &mut authority, &mut operation);
}

#[test]
fn incompatible_profile_is_rejected_before_authority_commit() {
    let database = ReferenceDatabase::in_memory().expect("database");
    let mut authority = Authority::new(database.clone()).expect("authority");
    let source = authority.bootstrap_source("wrong-profile", 1, Rights(3)).expect("source");
    let mut runtime =
        ReferenceRuntime::with_source(database.clone(), authority.clone(), source.clone())
            .expect("runtime");
    let mut workflow = intent(8, source_coordinate(&source));
    workflow.continuation.profile.contract_digest = Digest::of_bytes(b"incompatible profile");
    let id = workflow.continuation.id;
    let mut coordinator = Coordinator::new(RecordStore::new(database));
    coordinator.begin(workflow).expect("begin");
    coordinator.arm(&id, OperationId::from_u128(80)).expect("capture arm");
    coordinator.step(&id, &mut runtime, &mut authority).expect("capture absent query");
    coordinator.step(&id, &mut runtime, &mut authority).expect("profile rejection");
    assert!(matches!(coordinator.plan(&id).expect("plan"), Decision::Complete));
    assert!(!authority.binding(&source.binding_id).expect("binding").expect("source").fenced);
}

#[test]
fn precommit_abort_restores_source_once_and_never_replays_old_capture() {
    let database = ReferenceDatabase::in_memory().expect("database");
    let mut authority = Authority::new(database.clone()).expect("authority");
    let source = authority.bootstrap_source("abort", 1, Rights(3)).expect("source binding");
    let source_coord = source_coordinate(&source);
    let mut runtime = ReferenceRuntime::with_source(database.clone(), authority.clone(), source)
        .expect("runtime");
    assert_eq!(runtime.increment_counter().expect("increment"), (1, 1));
    let mut coordinator = Coordinator::new(RecordStore::new(database));
    let workflow = intent(5, source_coord.clone());
    let id = workflow.continuation.id;
    coordinator.begin(workflow).expect("begin");
    let mut operation = 50;
    for _ in 0..32 {
        match coordinator.plan(&id).expect("plan") {
            Decision::Arm(visa_coordinator::ActionKind::CommitFence) => break,
            Decision::Arm(_) => {
                coordinator.arm(&id, OperationId::from_u128(operation)).expect("arm");
                operation += 1;
            }
            Decision::Action { .. } => {
                coordinator.step(&id, &mut runtime, &mut authority).expect("step");
            }
            other => panic!("unexpected pre-abort decision: {other:?}"),
        }
    }
    coordinator.abort(&id).expect("abort");
    coordinator.arm(&id, OperationId::from_u128(operation)).expect("abort arm");
    operation += 1;
    coordinator.step(&id, &mut runtime, &mut authority).expect("abort query");
    coordinator.step(&id, &mut runtime, &mut authority).expect("abort invoke");
    coordinator.arm(&id, OperationId::from_u128(operation)).expect("restore arm");
    coordinator.step(&id, &mut runtime, &mut authority).expect("restore query");
    coordinator.step(&id, &mut runtime, &mut authority).expect("restore invoke");
    assert_eq!(runtime.increment_counter().expect("source resumed"), (2, 2));
    assert!(matches!(coordinator.plan(&id).expect("complete"), Decision::Complete));
    assert_eq!(runtime.source_value().expect("query did not replay the old snapshot"), 2);
    assert!(coordinator.abort(&id).is_ok(), "abort remains idempotent after source restore");
    coordinator
        .begin(intent(6, source_coord))
        .expect("completed abort releases the unchanged lineage head");
}
