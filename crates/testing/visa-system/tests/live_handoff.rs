use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use contract_core::{
    ActivationRole, ActivationStatus, AuthorityStatus, EffectKind, EffectOutcome, EffectRequest,
    EffectResult, EvidenceKind, EvidenceRef, HandoffPhase, IdempotencyKey, SchemaVersion,
    TimerDisposition, TimerStatus, VersionedValue,
};
use substrate_api::{LeasePort, LeaseRecord, ProviderErrorKind};
use substrate_host::SqliteProvider;
use visa_profile::ProviderSupport;
use visa_runtime::{
    CommandReceipt, Coordinator, SafePointTimer, SnapshotExpectations, TimerPoll, canonical_digest,
    validate_snapshot,
};
use visa_system::{
    component,
    fixture::{FixtureSpec, OpenProviders, derive_identity},
};
use visa_wasmtime::{ComponentAdapter, WorkloadPhase};

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

#[test]
fn live_handoff_preserves_component_state_effects_and_fencing() {
    let fixture = FixtureSpec::new("live-handoff").expect("fixture is valid");
    let database = TestDatabase::new("live-handoff");
    let OpenProviders { source: source_provider, destination: destination_provider } =
        fixture.open_providers(database.path()).expect("real SQLite providers open");
    let support = ProviderSupport::cooperative_handoff_v1(Vec::new());

    let mut source_coordinator =
        Coordinator::recover(fixture.source_state.clone(), source_provider)
            .expect("empty source journal recovers");
    source_coordinator
        .activate(
            fixture.activation.command,
            fixture.activation.source_authority,
            fixture.activation.initial_lease_epoch,
        )
        .expect("source leases and activation commit atomically");
    let mut source = ComponentAdapter::instantiate(
        component::bytes(),
        &fixture.profile,
        &support,
        source_coordinator,
    )
    .expect("source component instantiates");
    source
        .activate(&fixture.activation.to_wasmtime())
        .expect("guest writes, reads back, and arms its source timer");

    let active = source.status().expect("source status call succeeds").expect("source is active");
    assert_eq!(active.phase, WorkloadPhase::Armed);
    assert_eq!(active.expected_version, 1);
    assert_eq!(active.key, fixture.activation.key);

    source
        .coordinator_mut()
        .begin_quiesce(command(&fixture, "begin-quiesce"), fixture.ids.source_handoff_authority)
        .expect("source enters quiescing");
    let safe_point = source
        .safe_point(command(&fixture, "freeze"))
        .expect("guest and canonical state reach one safe point");
    let (remaining, source_arm) = match safe_point.timer {
        SafePointTimer::Pending { remaining, arm_operation } => (remaining, arm_operation),
        other => panic!("expected a suspended pending timer, got {other:?}"),
    };
    assert!(remaining.0 > 0);
    assert!(remaining.0 <= fixture.activation.delay_ns);
    assert!(source.resource_table_is_empty());
    assert_eq!(source.coordinator().state().phase, HandoffPhase::Frozen);
    assert_eq!(
        source.coordinator().state().timer.status,
        TimerStatus::Frozen(TimerDisposition::Pending { remaining, arm_operation: source_arm })
    );
    assert_eq!(source.coordinator().state().portable_state, safe_point.state.as_bytes());
    assert_source_read_back(&source, &fixture);

    thread::sleep(Duration::from_nanos(remaining.0) + Duration::from_millis(20));
    assert_eq!(
        source.coordinator_mut().poll_timer().expect("frozen source timer remains observable"),
        TimerPoll::Frozen(TimerDisposition::Pending { remaining, arm_operation: source_arm })
    );

    let (_, envelope) = source
        .coordinator_mut()
        .export_snapshot(
            command(&fixture, "export-snapshot"),
            fixture.ids.handoff,
            fixture.ids.snapshot,
            evidence(&fixture, "snapshot-evidence", EvidenceKind::SnapshotIntegrity),
        )
        .expect("portable snapshot exports");
    assert_eq!(envelope.body.portable_state, safe_point.state.as_bytes());
    let expectations = SnapshotExpectations {
        component_digest: fixture.component_digest,
        profile_digest: fixture.profile_digest,
        profile_version: SchemaVersion::new(
            fixture.profile.version.major,
            fixture.profile.version.minor,
        ),
        supported_extensions: fixture.profile.required_extensions.clone(),
        destination: fixture.ids.destination_node,
    };
    let validated =
        validate_snapshot(&envelope, &expectations).expect("snapshot validates for destination");

    let mut destination_coordinator = Coordinator::restore(validated.clone(), destination_provider)
        .expect("destination restores from the snapshot cursor");
    destination_coordinator
        .prepare_destination(
            command(&fixture, "prepare-destination"),
            fixture.handoff_authority.to_runtime(),
            fixture.timer_authority.to_runtime(),
            fixture.key_value_authority.to_runtime(),
        )
        .expect("destination authorities and bindings prepare");
    assert_eq!(destination_coordinator.state().phase, HandoffPhase::DestinationPrepared);
    assert_eq!(destination_coordinator.state().activation.status, ActivationStatus::Prepared);

    let commit_operation = command(&fixture, "lease-commit-operation");
    let commit_key = IdempotencyKey::from_bytes(command(&fixture, "lease-commit-idempotency").0);
    let commit = destination_coordinator
        .commit_handoff(command(&fixture, "commit-handoff"), commit_operation, commit_key)
        .expect("lease transition and canonical commit are atomic");
    let CommandReceipt::Effect(commit) = commit else {
        panic!("handoff commit must execute one lease effect");
    };
    assert!(matches!(
        commit.outcome,
        EffectOutcome::Succeeded {
            result: EffectResult::LeaseAdvanced {
                owner,
                epoch,
                ..
            },
            ..
        } if owner == fixture.ids.destination_node
            && epoch == fixture.activation.initial_lease_epoch.next().unwrap()
    ));

    let destination_epoch = fixture.activation.initial_lease_epoch.next().unwrap();
    let committed = destination_coordinator.state();
    assert_eq!(committed.phase, HandoffPhase::Committed);
    assert_eq!(committed.activation.role, ActivationRole::Destination);
    assert_eq!(committed.activation.status, ActivationStatus::Active);
    assert_eq!(committed.component, fixture.ids.destination_component);
    assert_eq!(committed.ownership.owner, Some(fixture.ids.destination_node));
    assert_eq!(committed.ownership.epoch, destination_epoch);
    for resource in [fixture.ids.timer_resource, fixture.ids.key_value_resource] {
        assert_eq!(
            destination_coordinator
                .provider()
                .current_lease(resource)
                .expect("committed lease reads"),
            Some(LeaseRecord {
                resource,
                owner: fixture.ids.destination_node,
                epoch: destination_epoch,
            })
        );
        assert_eq!(
            source
                .coordinator()
                .provider()
                .check_lease(
                    resource,
                    fixture.ids.source_node,
                    fixture.activation.initial_lease_epoch,
                )
                .expect_err("the old source lease is fenced")
                .kind,
            ProviderErrorKind::StaleEpoch
        );
    }

    let mut destination = ComponentAdapter::instantiate(
        component::bytes(),
        &fixture.profile,
        &support,
        destination_coordinator,
    )
    .expect("destination component instantiates");
    destination
        .restore(&safe_point.state, remaining.0)
        .expect("destination restores guest state and creates a fresh timer arm");
    let restored = destination
        .status()
        .expect("destination status call succeeds")
        .expect("destination guest is restored");
    assert_eq!(restored.phase, WorkloadPhase::Armed);
    assert_eq!(restored.expected_version, 1);
    let destination_arm = destination
        .coordinator()
        .state()
        .timer
        .active_operation
        .expect("destination timer is armed");
    assert_ne!(destination_arm, source_arm);
    let destination_arm_record = destination
        .coordinator()
        .state()
        .operations
        .iter()
        .find(|record| record.request.operation == destination_arm)
        .expect("destination arm is canonical");
    assert_eq!(destination_arm_record.request.causal_parent, Some(source_arm));
    assert_eq!(destination_arm_record.request.node, fixture.ids.destination_node);
    assert_eq!(destination_arm_record.request.subject, fixture.ids.destination_component);
    assert_eq!(destination_arm_record.request.lease_epoch, destination_epoch);

    destination
        .coordinator_mut()
        .resume_destination(command(&fixture, "resume-destination"))
        .expect("destination publishes running only after restore");
    assert_eq!(destination.coordinator().state().phase, HandoffPhase::Running);
    match destination.coordinator_mut().poll_timer().expect("fresh destination timer polls") {
        TimerPoll::Pending { arm_operation, remaining: destination_remaining } => {
            assert_eq!(arm_operation, destination_arm);
            assert!(destination_remaining.0 > 0);
        }
        other => panic!("time spent frozen must not fire the destination timer: {other:?}"),
    }

    thread::sleep(Duration::from_nanos(remaining.0) + Duration::from_millis(20));
    let fired = poll_until_fired(&mut destination, destination_arm);
    destination.timer_fired(fired).expect("timer completion is delivered to the guest");

    let completed = destination
        .status()
        .expect("completed status call succeeds")
        .expect("destination remains inspectable");
    assert_eq!(completed.phase, WorkloadPhase::Completed);
    assert_eq!(completed.expected_version, 2);
    assert_eq!(destination.coordinator().state().timer.status, TimerStatus::Completed);
    assert_eq!(destination.coordinator().state().key_value.last_version, Some(2));
    assert_eq!(
        read_completed_value(&mut destination, &fixture),
        VersionedValue { value: fixture.activation.completion_value.clone(), version: 2 }
    );

    let expected_position = destination.coordinator().journal_position();
    let expected_digest =
        destination.coordinator().state_digest().expect("final canonical state hashes");
    let replay_provider = SqliteProvider::open(
        database.path(),
        fixture.config_digest_input.destination_scope.to_runtime(),
    )
    .expect("destination journal reopens");
    let replayed = Coordinator::restore(validated, replay_provider)
        .expect("destination journal replays strictly after the snapshot cursor");
    assert_eq!(replayed.journal_position(), expected_position);
    assert_eq!(replayed.state_digest().expect("replayed canonical state hashes"), expected_digest);
    assert_eq!(replayed.state(), destination.coordinator().state());
}

fn assert_source_read_back(source: &ComponentAdapter<SqliteProvider>, fixture: &FixtureSpec) {
    let read = source
        .coordinator()
        .state()
        .operations
        .iter()
        .find(|record| {
            matches!(
                &record.request.kind,
                EffectKind::KeyValueRead { key } if key == fixture.activation.key.as_bytes()
            )
        })
        .expect("guest read-back is canonical");
    assert!(matches!(
        read.outcome.as_ref(),
        Some(EffectOutcome::Succeeded {
            result: EffectResult::KeyValueRead {
                value: Some(VersionedValue { value, version: 1 })
            },
            ..
        }) if value == &fixture.activation.initial_value
    ));
}

fn read_completed_value(
    destination: &mut ComponentAdapter<SqliteProvider>,
    fixture: &FixtureSpec,
) -> VersionedValue {
    let state = destination.coordinator().state();
    let authority = state
        .authorities
        .iter()
        .find(|grant| {
            grant.subject == state.component
                && grant.resource == state.key_value.claim.resource
                && grant.status == AuthorityStatus::Active
                && grant.rights.contains(contract_core::Rights::KV_READ)
        })
        .expect("destination has one active KV read grant")
        .authority;
    let kind = EffectKind::KeyValueRead { key: fixture.activation.key.as_bytes().to_vec() };
    let request = EffectRequest {
        operation: command(fixture, "verify-completed-value-operation"),
        idempotency_key: IdempotencyKey::from_bytes(
            command(fixture, "verify-completed-value-idempotency").0,
        ),
        causal_parent: None,
        node: state.activation.node,
        subject: state.component,
        resource: state.key_value.claim.resource,
        authority,
        lease_epoch: state.ownership.epoch,
        request_digest: canonical_digest(&kind).expect("read request hashes"),
        kind,
    };
    let receipt = destination
        .coordinator_mut()
        .effect(command(fixture, "verify-completed-value-command"), request)
        .expect("completed value reads through the coordinator");
    let CommandReceipt::Effect(receipt) = receipt else {
        panic!("verification read must execute exactly once");
    };
    match receipt.outcome {
        EffectOutcome::Succeeded {
            result: EffectResult::KeyValueRead { value: Some(value) },
            ..
        } => value,
        other => panic!("unexpected completed value read outcome: {other:?}"),
    }
}

fn poll_until_fired(
    destination: &mut ComponentAdapter<SqliteProvider>,
    expected_arm: contract_core::Identity,
) -> contract_core::Identity {
    for _ in 0..3 {
        match destination.coordinator_mut().poll_timer().expect("destination timer poll succeeds") {
            TimerPoll::Fired { arm_operation, receipt, .. } => {
                assert_eq!(arm_operation, expected_arm);
                assert!(matches!(
                    receipt.as_ref(),
                    CommandReceipt::Committed(_) | CommandReceipt::Replayed(_)
                ));
                return arm_operation;
            }
            TimerPoll::Pending { remaining, .. } => {
                thread::sleep(Duration::from_nanos(remaining.0) + Duration::from_millis(5));
            }
            other => panic!("destination timer did not fire: {other:?}"),
        }
    }
    panic!("destination timer remained pending after its remaining duration");
}

fn command(fixture: &FixtureSpec, label: &str) -> contract_core::Identity {
    derive_identity(&fixture.options.case_id, label)
}

fn evidence(fixture: &FixtureSpec, label: &str, kind: EvidenceKind) -> EvidenceRef {
    let identity = command(fixture, label);
    EvidenceRef {
        identity,
        kind,
        digest: canonical_digest(&(identity, kind)).expect("evidence hashes"),
    }
}

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new(label: &str) -> Self {
        let sequence = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("visa-system-{label}-{}-{sequence}.sqlite3", std::process::id()));
        remove_database_files(&path);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        remove_database_files(&self.0);
    }
}

fn remove_database_files(path: &Path) {
    let _ = fs::remove_file(path);
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        let _ = fs::remove_file(PathBuf::from(sidecar));
    }
}
