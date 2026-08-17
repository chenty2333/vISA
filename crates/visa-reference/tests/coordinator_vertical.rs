use visa_coordinator::{Coordinator, DriveResult, RecordStore as CoordinatorRecordStore};
use visa_core::{
    AuthorityId, ContinuationId, ContinuationIntent, ContinuationPhase, Digest, ExternalCoordinate,
    ExternalOperationKind, LineageAdvance, LineageId, LineagePoint, Progress, RecoveryCause,
    ScopeId, SnapshotId,
};
use visa_profile::DurableKvProfile;
use visa_reference::ReferenceDatabase;
use visa_reference::adapters::CoordinatorAuthorityAdapter;
use visa_reference::authority::{Authority, Rights};
use visa_reference::provider::{DurableKvProvider, ProviderError};
use visa_reference::runtime::{CoordinatorRuntimeAdapter, ReferenceInstance, WasmtimeVertical};
use visa_reference::store::RecordStore;
use visa_wasi::SnapshotContext;

fn coordinate(value: Vec<u8>) -> ExternalCoordinate {
    ExternalCoordinate { authority: AuthorityId::from_u128(1), value }
}

#[test]
fn missing_live_source_before_snapshot_fails_closed() {
    let database = ReferenceDatabase::in_memory().unwrap();
    let authority = Authority::new(database.clone()).unwrap();
    let source = authority.bootstrap("missing-source", 0, Rights::READ | Rights::WRITE).unwrap();
    let parent = LineagePoint {
        lineage: LineageId::from_u128(90),
        generation: 0,
        state_digest: Digest::ZERO,
    };
    let intent = ContinuationIntent {
        id: ContinuationId::from_u128(91),
        scope: ScopeId::from_u128(92),
        source: coordinate(source.binding_id.as_bytes().to_vec()),
        destination: coordinate(b"unreached-world".to_vec()),
        lineage_parent: parent,
        profile: DurableKvProfile.profile_ref(),
    };
    let runtime = CoordinatorRuntimeAdapter::new(
        authority.clone(),
        DurableKvProvider::new(database.clone()),
        WasmtimeVertical::new().unwrap(),
    );
    let mut coordinator = Coordinator::new(
        RecordStore::new(database),
        CoordinatorAuthorityAdapter::new(authority),
        runtime,
    );
    let id = coordinator.begin(intent).unwrap();
    assert_eq!(coordinator.drive(&id).unwrap(), DriveResult::Waiting);
    let record = coordinator.store.load(&id).unwrap().unwrap();
    assert!(matches!(
        record.phase,
        ContinuationPhase::RecoveryRequired {
            last_known: Progress::Preparing,
            cause: RecoveryCause::CaptureRejected { .. },
        }
    ));
    assert_eq!(coordinator.abort(&id).unwrap(), DriveResult::Waiting);
    let record = coordinator.store.load(&id).unwrap().unwrap();
    assert!(record.source_restoration.is_none());
    assert!(matches!(record.phase, ContinuationPhase::RecoveryRequired { .. }));
}

#[test]
fn capture_persistence_retry_reuses_the_sealed_safe_point_without_refreezing() {
    let database = ReferenceDatabase::in_memory().unwrap();
    let authority = Authority::new(database.clone()).unwrap();
    let source = authority.bootstrap("capture-retry", 0, Rights::READ | Rights::WRITE).unwrap();
    let provider = DurableKvProvider::new(database.clone());
    let source_binding = provider.bind_bootstrap_source(&authority, &source.binding_id).unwrap();
    let source_coordinate = coordinate(source.binding_id.as_bytes().to_vec());
    let lineage_parent = LineagePoint {
        lineage: LineageId::from_u128(93),
        generation: 0,
        state_digest: Digest::ZERO,
    };
    let intent = ContinuationIntent {
        id: ContinuationId::from_u128(94),
        scope: ScopeId::from_u128(95),
        source: source_coordinate.clone(),
        destination: coordinate(b"capture-retry-destination".to_vec()),
        lineage_parent: lineage_parent.clone(),
        profile: DurableKvProfile.profile_ref(),
    };
    let vertical = WasmtimeVertical::new().unwrap();
    let source_instance = ReferenceInstance::source_with_context(
        &vertical.prepared,
        provider.clone(),
        source_binding.clone(),
        SnapshotContext {
            snapshot: SnapshotId::from_u128(96),
            continuation: intent.id,
            scope: intent.scope,
            lineage: LineageAdvance { parent: lineage_parent, successor_generation: 1 },
            runtime: source_coordinate,
            cut_sequence: 0,
            receipt_digest: Digest::ZERO,
        },
    )
    .unwrap();
    let mut runtime = CoordinatorRuntimeAdapter::new(authority.clone(), provider, vertical);
    runtime.install_source(source_instance);
    runtime.inject_capture_persistence_failure_once();
    let mut coordinator = Coordinator::new(
        RecordStore::new(database),
        CoordinatorAuthorityAdapter::new(authority),
        runtime,
    );
    let id = coordinator.begin(intent).unwrap();

    assert_eq!(coordinator.drive(&id).unwrap(), DriveResult::Waiting);
    let unknown = coordinator.store.load(&id).unwrap().unwrap();
    assert!(unknown.snapshot.is_none());
    assert!(matches!(
        unknown.phase,
        ContinuationPhase::RecoveryRequired {
            cause: RecoveryCause::CaptureOutcomeUnknown { .. },
            ..
        }
    ));
    assert!(matches!(source_binding.get(b"counter"), Err(ProviderError::DispatchClosed(_))));

    assert_eq!(coordinator.recover(&id).unwrap(), DriveResult::DurableBoundary);
    let captured = coordinator.store.load(&id).unwrap().unwrap();
    assert!(captured.capture_receipt.is_some());
    assert!(captured.pending.is_none());
}

#[test]
fn armed_capture_after_persistence_failure_requires_fresh_runtime_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("armed-capture.sqlite");
    let database = ReferenceDatabase::open(&database_path).unwrap();
    let authority = Authority::new(database.clone()).unwrap();
    let source = authority.bootstrap("armed-capture", 0, Rights::READ | Rights::WRITE).unwrap();
    let provider = DurableKvProvider::new(database.clone());
    let source_binding = provider.bind_bootstrap_source(&authority, &source.binding_id).unwrap();
    let source_coordinate = coordinate(source.binding_id.as_bytes().to_vec());
    let lineage_parent = LineagePoint {
        lineage: LineageId::from_u128(97),
        generation: 0,
        state_digest: Digest::ZERO,
    };
    let intent = ContinuationIntent {
        id: ContinuationId::from_u128(98),
        scope: ScopeId::from_u128(99),
        source: source_coordinate.clone(),
        destination: coordinate(b"armed-capture-destination".to_vec()),
        lineage_parent: lineage_parent.clone(),
        profile: DurableKvProfile.profile_ref(),
    };
    let vertical = WasmtimeVertical::new().unwrap();
    let source_instance = ReferenceInstance::source_with_context(
        &vertical.prepared,
        provider.clone(),
        source_binding.clone(),
        SnapshotContext {
            snapshot: SnapshotId::from_u128(100),
            continuation: intent.id,
            scope: intent.scope,
            lineage: LineageAdvance { parent: lineage_parent, successor_generation: 1 },
            runtime: source_coordinate,
            cut_sequence: 0,
            receipt_digest: Digest::ZERO,
        },
    )
    .unwrap();
    let mut runtime = CoordinatorRuntimeAdapter::new(authority.clone(), provider, vertical);
    runtime.install_source(source_instance);
    runtime.inject_capture_persistence_failure_once();
    let mut coordinator = Coordinator::new(
        RecordStore::new(database),
        CoordinatorAuthorityAdapter::new(authority),
        runtime,
    );
    let id = coordinator.begin(intent).unwrap();
    assert_eq!(coordinator.drive(&id).unwrap(), DriveResult::Waiting);
    let pending_operation =
        coordinator.store.load(&id).unwrap().unwrap().pending.unwrap().operation;
    assert!(matches!(source_binding.get(b"counter"), Err(ProviderError::DispatchClosed(_))));

    // The capture row is armed, but its sealed facts were never persisted.
    // Dropping the source process must not turn that fact into a retryable
    // absent operation or invoke capture again in the fresh runtime.
    drop(coordinator);
    let recovered_database = ReferenceDatabase::open(&database_path).unwrap();
    let recovered_authority = Authority::new(recovered_database.clone()).unwrap();
    let recovered_runtime = CoordinatorRuntimeAdapter::new(
        recovered_authority.clone(),
        DurableKvProvider::new(recovered_database.clone()),
        WasmtimeVertical::new().unwrap(),
    );
    let mut recovered = Coordinator::new(
        RecordStore::new(recovered_database),
        CoordinatorAuthorityAdapter::new(recovered_authority),
        recovered_runtime,
    );
    assert_eq!(recovered.recover(&id).unwrap(), DriveResult::Waiting);
    let record = recovered.store.load(&id).unwrap().unwrap();
    assert_eq!(record.pending.as_ref().unwrap().operation, pending_operation);
    assert!(matches!(
        record.phase,
        ContinuationPhase::RecoveryRequired {
            cause: RecoveryCause::CaptureOutcomeUnknown { operation },
            ..
        } if operation == pending_operation
    ));
}

#[test]
fn coordinator_activates_fresh_wasmtime_destination_after_lost_ack() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("reference.sqlite");
    let database = ReferenceDatabase::open(&database_path).unwrap();
    let authority = Authority::new(database.clone()).unwrap();
    let source = authority.bootstrap("reference-owner", 0, Rights::READ | Rights::WRITE).unwrap();
    let provider = DurableKvProvider::new(database.clone());
    let old_handle = provider.bind_bootstrap_source(&authority, &source.binding_id).unwrap();
    let source_coordinate = coordinate(source.binding_id.as_bytes().to_vec());
    let lineage_parent = LineagePoint {
        lineage: LineageId::from_u128(9),
        generation: 0,
        state_digest: Digest::ZERO,
    };
    let intent = ContinuationIntent {
        id: ContinuationId::from_u128(7),
        scope: ScopeId::from_u128(8),
        source: source_coordinate.clone(),
        destination: coordinate(b"destination-host".to_vec()),
        lineage_parent: lineage_parent.clone(),
        profile: DurableKvProfile.profile_ref(),
    };
    let vertical = WasmtimeVertical::new().unwrap();
    let mut source_instance = ReferenceInstance::source_with_context(
        &vertical.prepared,
        provider.clone(),
        old_handle.clone(),
        SnapshotContext {
            snapshot: SnapshotId::from_u128(1),
            continuation: intent.id,
            scope: intent.scope,
            lineage: LineageAdvance { parent: lineage_parent, successor_generation: 1 },
            runtime: source_coordinate,
            cut_sequence: 0,
            receipt_digest: Digest::ZERO,
        },
    )
    .unwrap();
    assert_eq!(source_instance.increment().unwrap(), 1);
    assert_eq!(source_instance.increment().unwrap(), 2);
    source_instance.set_session(b"session-v1").unwrap();
    let mut runtime = CoordinatorRuntimeAdapter::new(authority.clone(), provider, vertical);
    runtime.install_source(source_instance);
    runtime.inject_capture_lost_ack_once();
    let mut coordinator = Coordinator::new(
        RecordStore::new(database.clone()),
        CoordinatorAuthorityAdapter::new(authority.clone()),
        runtime,
    );
    let id = coordinator.begin(intent).unwrap();

    assert_eq!(coordinator.drive(&id).unwrap(), DriveResult::Waiting);
    let capture_operation =
        coordinator.store.load(&id).unwrap().unwrap().pending.unwrap().operation;
    assert!(matches!(old_handle.get(b"counter"), Err(ProviderError::DispatchClosed(_))));

    // The runtime-owned capture transaction committed, but its acknowledgement
    // and the entire source process are lost. A fresh coordinator resolves the
    // exact capture operation and obtains the durable snapshot bytes.
    drop(coordinator);
    let capture_database = ReferenceDatabase::open(&database_path).unwrap();
    let capture_authority = Authority::new(capture_database.clone()).unwrap();
    let runtime = CoordinatorRuntimeAdapter::new(
        capture_authority.clone(),
        DurableKvProvider::new(capture_database.clone()),
        WasmtimeVertical::new().unwrap(),
    );
    let mut coordinator = Coordinator::new(
        RecordStore::new(capture_database),
        CoordinatorAuthorityAdapter::new(capture_authority),
        runtime,
    );
    assert_eq!(coordinator.discover_unfinished().unwrap(), vec![id]);
    assert_eq!(coordinator.recover(&id).unwrap(), DriveResult::DurableBoundary);
    let captured = coordinator.store.load(&id).unwrap().unwrap();
    assert_eq!(captured.capture_receipt.as_ref().unwrap().operation, capture_operation);
    assert!(captured.pending.is_none());

    assert!(matches!(coordinator.drive(&id).unwrap(), DriveResult::ExternalPending(_)));
    assert!(matches!(coordinator.drive(&id).unwrap(), DriveResult::ExternalPending(_)));
    assert_eq!(coordinator.drive(&id).unwrap(), DriveResult::DurableBoundary);
    assert!(matches!(coordinator.drive(&id).unwrap(), DriveResult::ExternalPending(_)));

    authority.inject_lost_ack_once();
    assert!(matches!(coordinator.drive(&id).unwrap(), DriveResult::ExternalPending(_)));
    let commit_operation = coordinator.store.load(&id).unwrap().unwrap().pending.unwrap().operation;

    // Simulate a coordinator process restart: all prepared/frozen runtime
    // tokens and call markers disappear. Reopen the SQLite file through a new
    // connection; only durable records and authority facts survive.
    drop(coordinator);
    let recovered_database = ReferenceDatabase::open(&database_path).unwrap();
    let recovered_authority = Authority::new(recovered_database.clone()).unwrap();
    let runtime = CoordinatorRuntimeAdapter::new(
        recovered_authority.clone(),
        DurableKvProvider::new(recovered_database.clone()),
        WasmtimeVertical::new().unwrap(),
    );
    let mut coordinator = Coordinator::new(
        RecordStore::new(recovered_database),
        CoordinatorAuthorityAdapter::new(recovered_authority),
        runtime,
    );
    assert_eq!(coordinator.recover(&id).unwrap(), DriveResult::DurableBoundary);
    let committed = coordinator.store.load(&id).unwrap().unwrap();
    assert_eq!(committed.authority_commit.as_ref().unwrap().operation, commit_operation);
    assert!(matches!(old_handle.get(b"counter"), Err(ProviderError::Fenced(_))));
    assert!(matches!(coordinator.drive(&id).unwrap(), DriveResult::ExternalPending(_)));
    assert!(matches!(coordinator.drive(&id).unwrap(), DriveResult::ExternalPending(_)));
    assert_eq!(coordinator.drive(&id).unwrap(), DriveResult::Activated);

    let activated = coordinator.store.load(&id).unwrap().unwrap();
    assert!(matches!(activated.phase, ContinuationPhase::Progress(Progress::Activated)));
    let portable_state = &activated.snapshot.as_ref().unwrap().body.state;
    assert!(
        portable_state
            .windows(source.binding_id.len())
            .all(|window| window != source.binding_id.as_bytes())
    );
    let counts_before_application_calls = coordinator.read_control_counts();
    let destination = coordinator.runtime.destination_mut().unwrap();
    assert_ne!(destination.binding().binding_id(), source.binding_id);
    assert_eq!(destination.binding().provider_generation(), old_handle.provider_generation() + 1);
    assert_eq!(destination.value().unwrap(), 2);
    assert_eq!(destination.session().unwrap().unwrap().value, b"session-v1");
    assert_eq!(destination.increment().unwrap(), 3);
    let first_destination_handle = destination.binding().clone();
    assert_eq!(
        coordinator.read_control_counts(),
        counts_before_application_calls,
        "ordinary guest/provider calls must not enter the vISA control path"
    );

    // Activation releases the lineage slot at the exact successor point. A
    // stale parent cannot fork it, while the committed generation can begin
    // the next continuation.
    let next_source = activated.binding_preparation.as_ref().unwrap().grants[0].binding.clone();
    let next_parent = LineagePoint {
        lineage: activated.intent.lineage_parent.lineage,
        generation: activated.snapshot.as_ref().unwrap().body.lineage.successor_generation,
        state_digest: activated.snapshot.as_ref().unwrap().body.state_digest,
    };
    let stale = ContinuationIntent {
        id: ContinuationId::from_u128(70),
        scope: ScopeId::from_u128(71),
        source: next_source.clone(),
        destination: coordinate(b"third-world".to_vec()),
        lineage_parent: activated.intent.lineage_parent,
        profile: DurableKvProfile.profile_ref(),
    };
    assert!(coordinator.begin(stale).is_err());
    let next = ContinuationIntent {
        id: ContinuationId::from_u128(72),
        scope: ScopeId::from_u128(73),
        source: next_source,
        destination: coordinate(b"third-world".to_vec()),
        lineage_parent: next_parent,
        profile: DurableKvProfile.profile_ref(),
    };
    let next_id = coordinator.begin(next).unwrap();
    assert_eq!(next_id, ContinuationId::from_u128(72));
    assert_eq!(coordinator.drive(&next_id).unwrap(), DriveResult::DurableBoundary);
    assert!(matches!(
        first_destination_handle.get(b"counter"),
        Err(ProviderError::DispatchClosed(_))
    ));
    let mut committed_again = false;
    for _ in 0..16 {
        match coordinator.drive(&next_id).unwrap() {
            DriveResult::DurableBoundary | DriveResult::ExternalPending(_) => {}
            other => panic!("second continuation stopped at {other:?}"),
        }
        let record = coordinator.store.load(&next_id).unwrap().unwrap();
        if record.phase.last_known() == Progress::Committed && record.pending.is_none() {
            committed_again = true;
            break;
        }
    }
    assert!(committed_again);
    assert!(matches!(first_destination_handle.get(b"counter"), Err(ProviderError::Fenced(_))));

    // Arm and execute activation, then lose the coordinator's acknowledgement
    // before Event::Activated reaches the record store. The destination may
    // run only after the durable authority permit reaches `activated`.
    assert!(matches!(coordinator.drive(&next_id).unwrap(), DriveResult::ExternalPending(_)));
    assert!(matches!(coordinator.drive(&next_id).unwrap(), DriveResult::ExternalPending(_)));
    let activation_pending = coordinator.store.load(&next_id).unwrap().unwrap();
    assert_eq!(activation_pending.phase.last_known(), Progress::Committed);
    assert_eq!(
        activation_pending.pending.as_ref().unwrap().kind,
        ExternalOperationKind::ActivateRuntime
    );
    assert!(activation_pending.activation.is_none());
    let second_destination = coordinator.runtime.destination_mut().unwrap();
    assert_eq!(second_destination.binding().provider_generation(), 2);
    assert_eq!(second_destination.value().unwrap(), 3);
    assert_eq!(second_destination.increment().unwrap(), 4);

    // A fresh coordinator resolves the lost acknowledgement from the exact
    // durable activation permit. It never creates a second runtime owner from
    // the pre-activation snapshot.
    drop(coordinator);
    let final_database = ReferenceDatabase::open(&database_path).unwrap();
    let final_authority = Authority::new(final_database.clone()).unwrap();
    let final_runtime = CoordinatorRuntimeAdapter::new(
        final_authority.clone(),
        DurableKvProvider::new(final_database.clone()),
        WasmtimeVertical::new().unwrap(),
    );
    let mut final_coordinator = Coordinator::new(
        RecordStore::new(final_database),
        CoordinatorAuthorityAdapter::new(final_authority),
        final_runtime,
    );
    assert_eq!(final_coordinator.recover(&next_id).unwrap(), DriveResult::Activated);
    assert!(final_coordinator.runtime.destination_mut().is_none());
}

#[test]
fn precommit_abort_survives_restart_and_recreates_source_from_portable_state() {
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("abort.sqlite");
    let database = ReferenceDatabase::open(&database_path).unwrap();
    let authority = Authority::new(database.clone()).unwrap();
    let source = authority.bootstrap("abort-owner", 4, Rights::READ | Rights::WRITE).unwrap();
    let provider = DurableKvProvider::new(database.clone());
    let source_binding = provider.bind_bootstrap_source(&authority, &source.binding_id).unwrap();
    let source_coordinate = coordinate(source.binding_id.as_bytes().to_vec());
    let lineage_parent = LineagePoint {
        lineage: LineageId::from_u128(19),
        generation: 3,
        state_digest: Digest::of_bytes(b"parent"),
    };
    let intent = ContinuationIntent {
        id: ContinuationId::from_u128(17),
        scope: ScopeId::from_u128(18),
        source: source_coordinate.clone(),
        destination: coordinate(b"unused-destination".to_vec()),
        lineage_parent: lineage_parent.clone(),
        profile: DurableKvProfile.profile_ref(),
    };
    let vertical = WasmtimeVertical::new().unwrap();
    let mut source_instance = ReferenceInstance::source_with_context(
        &vertical.prepared,
        provider.clone(),
        source_binding,
        SnapshotContext {
            snapshot: SnapshotId::from_u128(11),
            continuation: intent.id,
            scope: intent.scope,
            lineage: LineageAdvance { parent: lineage_parent, successor_generation: 4 },
            runtime: source_coordinate,
            cut_sequence: 2,
            receipt_digest: Digest::of_bytes(b"source-context"),
        },
    )
    .unwrap();
    assert_eq!(source_instance.increment().unwrap(), 1);
    assert_eq!(source_instance.increment().unwrap(), 2);
    source_instance.set_session(b"abort-session").unwrap();

    let mut runtime = CoordinatorRuntimeAdapter::new(authority.clone(), provider, vertical);
    runtime.install_source(source_instance);
    let mut coordinator = Coordinator::new(
        RecordStore::new(database),
        CoordinatorAuthorityAdapter::new(authority),
        runtime,
    );
    let id = coordinator.begin(intent).unwrap();
    assert_eq!(coordinator.drive(&id).unwrap(), DriveResult::DurableBoundary);
    assert!(matches!(coordinator.drive(&id).unwrap(), DriveResult::ExternalPending(_)));
    assert!(matches!(coordinator.drive(&id).unwrap(), DriveResult::ExternalPending(_)));
    assert_eq!(coordinator.drive(&id).unwrap(), DriveResult::DurableBoundary);

    let prepared = coordinator.store.load(&id).unwrap().unwrap();
    let destination_binding = String::from_utf8(
        prepared.binding_preparation.as_ref().unwrap().grants[0].binding.value.clone(),
    )
    .unwrap();
    assert!(matches!(coordinator.abort(&id).unwrap(), DriveResult::ExternalPending(_)));
    assert!(matches!(coordinator.drive(&id).unwrap(), DriveResult::ExternalPending(_)));

    // The abort was applied by the authority, but its acknowledgement and all
    // runtime-local objects are lost with this process.
    drop(coordinator);
    let recovered_database = ReferenceDatabase::open(&database_path).unwrap();
    let recovered_authority = Authority::new(recovered_database.clone()).unwrap();
    let runtime = CoordinatorRuntimeAdapter::new(
        recovered_authority.clone(),
        DurableKvProvider::new(recovered_database.clone()),
        WasmtimeVertical::new().unwrap(),
    );
    let mut coordinator = Coordinator::new(
        RecordStore::new(recovered_database),
        CoordinatorAuthorityAdapter::new(recovered_authority.clone()),
        runtime,
    );
    assert_eq!(coordinator.recover(&id).unwrap(), DriveResult::Aborted);
    assert!(recovered_authority.binding(&destination_binding).unwrap().is_none());

    assert_eq!(coordinator.recover(&id).unwrap(), DriveResult::SourceRestored);
    let source = coordinator.runtime.source_mut().unwrap();
    assert_eq!(source.value().unwrap(), 2);
    assert_eq!(source.session().unwrap().unwrap().value, b"abort-session");
    assert_eq!(source.increment().unwrap(), 3);
    assert_eq!(coordinator.recover(&id).unwrap(), DriveResult::SourceRestored);
    assert_eq!(coordinator.runtime.source_mut().unwrap().value().unwrap(), 3);

    // The durable receipt completes the old continuation. A later loss of the
    // process-local runtime is a new fault, not authority to reopen the
    // completed record or replay its snapshot over resumed work.
    drop(coordinator);
    let final_database = ReferenceDatabase::open(&database_path).unwrap();
    let final_authority = Authority::new(final_database.clone()).unwrap();
    let final_runtime = CoordinatorRuntimeAdapter::new(
        final_authority.clone(),
        DurableKvProvider::new(final_database.clone()),
        WasmtimeVertical::new().unwrap(),
    );
    let mut final_coordinator = Coordinator::new(
        RecordStore::new(final_database),
        CoordinatorAuthorityAdapter::new(final_authority),
        final_runtime,
    );
    assert_eq!(final_coordinator.recover(&id).unwrap(), DriveResult::SourceRestored);
    assert!(final_coordinator.runtime.source_mut().is_none());
    let record = final_coordinator.store.load(&id).unwrap().unwrap();
    assert!(matches!(record.phase, ContinuationPhase::Progress(Progress::Aborted)));
}
