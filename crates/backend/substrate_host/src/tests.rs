use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use contract_core::{
    AuthorityGrant, CONTRACT_VERSION, CleanupStatus, Digest, EffectKind, EffectOutcome,
    EffectRequest, EffectResult, EntityRef, Event, EventKind, EvidenceKind, EvidenceRef,
    Generation, IdempotencyKey, Identity, JournalEntry, JournalPosition, LeaseEpoch,
    LogicalDurationNanos, NodeIdentity, Rights,
};
use substrate_api::{
    ActivationBundle, AuthorityPolicy, AuthorityPort, BindingKind, BindingPort, BindingRequest,
    CommitBundle, JournalPort, JournalScope, KvPort, LeasePort, LeaseRecord, ProviderErrorKind,
    ReauthorizationRequest, TimerObservation, TimerPort,
};

use crate::{FaultPoint, SqliteProvider};

static NEXT_DB: AtomicU64 = AtomicU64::new(1);

struct TestDb {
    path: PathBuf,
}

impl TestDb {
    fn new(label: &str) -> Self {
        let sequence = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("visa-substrate-host-{label}-{}-{sequence}.sqlite3", std::process::id()));
        remove_database_files(&path);
        Self { path }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        remove_database_files(&self.path);
    }
}

fn remove_database_files(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let _ = std::fs::remove_file(PathBuf::from(wal));
    let mut shm = path.as_os_str().to_owned();
    shm.push("-shm");
    let _ = std::fs::remove_file(PathBuf::from(shm));
}

fn id(value: u128) -> Identity {
    Identity::from_u128(value)
}

fn entity(value: u128) -> EntityRef {
    EntityRef::initial(id(value))
}

fn node(value: u128) -> NodeIdentity {
    NodeIdentity::new(id(value))
}

fn digest(value: u8) -> Digest {
    let mut bytes = [0_u8; 32];
    bytes[0] = value;
    Digest::from_bytes(bytes)
}

fn evidence(value: u128, kind: EvidenceKind) -> EvidenceRef {
    EvidenceRef { identity: id(value), kind, digest: digest(value as u8) }
}

fn journal_entry(position: u64, event: EventKind) -> JournalEntry {
    JournalEntry {
        version: CONTRACT_VERSION,
        position: JournalPosition(position),
        input_state: digest((position - 1) as u8),
        output_state: digest(position as u8),
        event: Event::new(id(8_000 + u128::from(position)), event),
    }
}

fn append_intent(provider: &mut SqliteProvider, position: u64, request: &EffectRequest) {
    provider
        .append_entry(&journal_entry(
            position,
            EventKind::EffectPrepared { request: request.clone() },
        ))
        .expect("intent is durable");
}

struct Fixture {
    source_node: NodeIdentity,
    destination_node: NodeIdentity,
    source_subject: EntityRef,
    destination_subject: EntityRef,
    timer: EntityRef,
    kv: EntityRef,
    handoff_resource: EntityRef,
    timer_authority: EntityRef,
    kv_authority: EntityRef,
    handoff_authority: EntityRef,
    destination_handoff_authority: EntityRef,
    destination_timer_authority: EntityRef,
    destination_kv_authority: EntityRef,
    handoff: Identity,
    snapshot: Identity,
}

fn configured_provider(path: &std::path::Path) -> (SqliteProvider, Fixture) {
    let fixture = Fixture {
        source_node: node(1),
        destination_node: node(2),
        source_subject: entity(10),
        destination_subject: EntityRef::new(id(10), Generation(1)),
        timer: entity(20),
        kv: entity(21),
        handoff_resource: entity(10),
        timer_authority: entity(30),
        kv_authority: entity(31),
        handoff_authority: entity(32),
        destination_handoff_authority: entity(35),
        destination_timer_authority: entity(33),
        destination_kv_authority: entity(34),
        handoff: id(40),
        snapshot: id(41),
    };
    let mut provider = SqliteProvider::open(
        path,
        JournalScope { node: fixture.source_node, component: fixture.source_subject.identity },
    )
    .expect("provider opens");

    let timer_rights = Rights::TIMER_ARM.union(Rights::TIMER_CANCEL).union(Rights::REBIND);
    let kv_rights = Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND);
    for policy in [
        AuthorityPolicy {
            subject: fixture.source_subject,
            resource: fixture.timer,
            allowed_rights: timer_rights,
        },
        AuthorityPolicy {
            subject: fixture.destination_subject,
            resource: fixture.timer,
            allowed_rights: timer_rights,
        },
        AuthorityPolicy {
            subject: fixture.source_subject,
            resource: fixture.kv,
            allowed_rights: kv_rights,
        },
        AuthorityPolicy {
            subject: fixture.destination_subject,
            resource: fixture.kv,
            allowed_rights: kv_rights,
        },
        AuthorityPolicy {
            subject: fixture.source_subject,
            resource: fixture.handoff_resource,
            allowed_rights: Rights::HANDOFF,
        },
        AuthorityPolicy {
            subject: fixture.destination_subject,
            resource: fixture.destination_subject,
            allowed_rights: Rights::HANDOFF,
        },
    ] {
        provider.install_policy(policy).expect("policy installs");
    }
    for grant in [
        AuthorityGrant::active_root(
            fixture.timer_authority,
            fixture.source_subject,
            fixture.timer,
            timer_rights,
        ),
        AuthorityGrant::active_root(
            fixture.kv_authority,
            fixture.source_subject,
            fixture.kv,
            kv_rights,
        ),
        AuthorityGrant::active_root(
            fixture.handoff_authority,
            fixture.source_subject,
            fixture.handoff_resource,
            Rights::HANDOFF,
        ),
    ] {
        provider.install_grant(&grant).expect("grant installs");
    }
    provider
        .reauthorize(ReauthorizationRequest {
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            source_authority: fixture.timer_authority,
            destination_authority: fixture.destination_timer_authority,
            destination_subject: fixture.destination_subject,
            resource: fixture.timer,
            required_rights: timer_rights,
        })
        .expect("timer reauthorization succeeds");
    provider
        .reauthorize(ReauthorizationRequest {
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            source_authority: fixture.kv_authority,
            destination_authority: fixture.destination_kv_authority,
            destination_subject: fixture.destination_subject,
            resource: fixture.kv,
            required_rights: kv_rights,
        })
        .expect("kv reauthorization succeeds");
    provider
        .reauthorize(ReauthorizationRequest {
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            source_authority: fixture.handoff_authority,
            destination_authority: fixture.destination_handoff_authority,
            destination_subject: fixture.destination_subject,
            resource: fixture.destination_subject,
            required_rights: Rights::HANDOFF,
        })
        .expect("handoff reauthorization succeeds");

    for resource in [fixture.timer, fixture.kv] {
        provider
            .initialize_lease(LeaseRecord {
                resource,
                owner: fixture.source_node,
                epoch: LeaseEpoch(1),
            })
            .expect("source lease initializes");
    }
    provider
        .provision_key_value_namespace(fixture.kv, id(50))
        .expect("source namespace provisions");
    provider
        .provision_key_value_namespace_availability(fixture.destination_node, id(50))
        .expect("destination namespace availability provisions");

    provider
        .prepare_binding(BindingRequest {
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            claim: fixture.timer,
            authority: fixture.destination_timer_authority,
            exposed_rights: timer_rights,
            expected_owner: fixture.source_node,
            expected_epoch: LeaseEpoch(1),
            candidate_owner: fixture.destination_node,
            candidate_epoch: LeaseEpoch(2),
            kind: BindingKind::PausedDurationTimer,
        })
        .expect("timer binding prepares");
    provider
        .prepare_binding(BindingRequest {
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            claim: fixture.kv,
            authority: fixture.destination_kv_authority,
            exposed_rights: kv_rights,
            expected_owner: fixture.source_node,
            expected_epoch: LeaseEpoch(1),
            candidate_owner: fixture.destination_node,
            candidate_epoch: LeaseEpoch(2),
            kind: BindingKind::KeyValueNamespace { namespace: id(50) },
        })
        .expect("kv binding prepares");

    (provider, fixture)
}

fn kv_request(fixture: &Fixture, operation: u128, expected_version: Option<u64>) -> EffectRequest {
    EffectRequest {
        operation: id(operation),
        idempotency_key: IdempotencyKey::from_u128(operation),
        causal_parent: None,
        node: fixture.source_node,
        subject: fixture.source_subject,
        resource: fixture.kv,
        authority: fixture.kv_authority,
        lease_epoch: LeaseEpoch(1),
        request_digest: digest(operation as u8),
        kind: EffectKind::KeyValueCompareAndSet {
            key: b"counter".to_vec(),
            expected_version,
            value: operation.to_be_bytes().to_vec(),
        },
    }
}

fn kv_read(fixture: &Fixture, operation: u128) -> EffectRequest {
    EffectRequest {
        operation: id(operation),
        idempotency_key: IdempotencyKey::from_u128(operation),
        causal_parent: None,
        node: fixture.source_node,
        subject: fixture.source_subject,
        resource: fixture.kv,
        authority: fixture.kv_authority,
        lease_epoch: LeaseEpoch(1),
        request_digest: digest(operation as u8),
        kind: EffectKind::KeyValueRead { key: b"counter".to_vec() },
    }
}

fn timer_arm(fixture: &Fixture, operation: u128, nanos: u64) -> EffectRequest {
    EffectRequest {
        operation: id(operation),
        idempotency_key: IdempotencyKey::from_u128(operation),
        causal_parent: None,
        node: fixture.source_node,
        subject: fixture.source_subject,
        resource: fixture.timer,
        authority: fixture.timer_authority,
        lease_epoch: LeaseEpoch(1),
        request_digest: digest(operation as u8),
        kind: EffectKind::TimerArm { remaining: LogicalDurationNanos(nanos) },
    }
}

fn lease_request(fixture: &Fixture, operation: u128) -> EffectRequest {
    EffectRequest {
        operation: id(operation),
        idempotency_key: IdempotencyKey::from_u128(operation),
        causal_parent: None,
        node: fixture.destination_node,
        subject: fixture.destination_subject,
        resource: fixture.destination_subject,
        authority: fixture.destination_handoff_authority,
        lease_epoch: LeaseEpoch(1),
        request_digest: digest(operation as u8),
        kind: EffectKind::LeaseCommit {
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            destination: fixture.destination_node,
            expected_epoch: LeaseEpoch(1),
            next_epoch: LeaseEpoch(2),
        },
    }
}

#[test]
fn sqlite_configuration_reopens_and_rejects_future_schema() {
    let db = TestDb::new("reopen");
    let (mut provider, fixture) = configured_provider(&db.path);
    let mode: String = provider
        .connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode reads");
    let synchronous: i64 = provider
        .connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .expect("synchronous reads");
    let foreign_keys: i64 = provider
        .connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .expect("foreign keys reads");
    assert_eq!(mode, "wal");
    assert_eq!(synchronous, 2);
    assert_eq!(foreign_keys, 1);

    let request = kv_request(&fixture, 100, None);
    append_intent(&mut provider, 1, &request);
    let outcome = provider.compare_and_set(&request).expect("kv applies");
    drop(provider);

    let scope =
        JournalScope { node: fixture.source_node, component: fixture.source_subject.identity };
    let reopened = SqliteProvider::open(&db.path, scope).expect("database reopens");
    assert_eq!(reopened.replay_from(None).expect("journal replays").len(), 1);
    assert_eq!(
        reopened
            .query_operation(request.operation, request.idempotency_key)
            .expect("operation query succeeds"),
        Some(outcome)
    );
    assert_eq!(reopened.timers.len(), 0, "host instants never reopen");
    drop(reopened);

    let connection = rusqlite::Connection::open(&db.path).expect("raw database opens");
    connection.pragma_update(None, "user_version", 6).expect("future version installs");
    drop(connection);
    let error = SqliteProvider::open(&db.path, scope).err().expect("future schema is rejected");
    assert_eq!(error.kind, ProviderErrorKind::Integrity);
    let connection = rusqlite::Connection::open(&db.path).expect("raw database reopens");
    let version: i64 =
        connection.query_row("PRAGMA user_version", [], |row| row.get(0)).expect("version reads");
    assert_eq!(version, 6, "open must not downgrade an unknown schema");
}

#[test]
fn sqlite_zero_version_nonempty_schema_is_rejected_before_mutation() {
    let db = TestDb::new("nonempty-v0-schema");
    let connection = rusqlite::Connection::open(&db.path).expect("raw database opens");
    connection
        .execute_batch("CREATE TABLE legacy_v0_state (value BLOB NOT NULL);")
        .expect("legacy table installs");
    let initial_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("initial version reads");
    assert_eq!(initial_version, 0, "legacy schema remains unversioned");
    drop(connection);

    let scope = JournalScope { node: node(252), component: id(253) };
    let error = SqliteProvider::open(&db.path, scope)
        .err()
        .expect("nonempty version-zero schema is rejected");
    assert_eq!(error.kind, ProviderErrorKind::Integrity);

    let connection = rusqlite::Connection::open(&db.path).expect("raw database reopens");
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("version reads after rejection");
    assert_eq!(version, 0, "rejected open must not assign a schema version");

    let mut statement = connection
        .prepare(
            "SELECT type, name FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'
             ORDER BY type, name",
        )
        .expect("schema query prepares");
    let objects = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .expect("schema query executes")
        .collect::<Result<Vec<_>, _>>()
        .expect("schema objects decode");
    assert_eq!(
        objects,
        vec![("table".to_owned(), "legacy_v0_state".to_owned())],
        "rejected open must not create provider tables or any other schema objects"
    );
}

#[test]
fn source_activation_atomically_commits_initial_leases_and_scoped_journal() {
    let db = TestDb::new("activation-bundle");
    let scope = JournalScope { node: node(250), component: id(251) };
    let mut provider = SqliteProvider::open(&db.path, scope).expect("provider opens");
    let timer = entity(252);
    let kv = entity(253);
    let entry = journal_entry(1, EventKind::Activated { lease_epoch: LeaseEpoch(1) });
    let bundle = ActivationBundle {
        entry: entry.clone(),
        initial_leases: vec![
            LeaseRecord { resource: timer, owner: scope.node, epoch: LeaseEpoch(1) },
            LeaseRecord { resource: kv, owner: scope.node, epoch: LeaseEpoch(1) },
        ],
    };

    assert_eq!(
        provider
            .append_entry(&entry)
            .expect_err("generic append cannot split activation from leases")
            .kind,
        ProviderErrorKind::InvalidRequest
    );
    provider.inject_failure_once(FaultPoint::BeforeActivationBundle);
    assert_eq!(
        provider
            .commit_activation(&bundle)
            .expect_err("pre-transaction activation fault is explicit")
            .kind,
        ProviderErrorKind::Unavailable
    );
    assert_eq!(provider.entry(JournalPosition(1)), Ok(None));
    assert_eq!(provider.current_lease(timer), Ok(None));
    assert_eq!(provider.current_lease(kv), Ok(None));
    assert_eq!(
        provider.fault_observation(),
        Some(crate::FaultObservation { point: FaultPoint::BeforeActivationBundle, count: 1 })
    );

    provider.inject_failure_once(FaultPoint::AfterActivationBundle);
    assert_eq!(
        provider
            .commit_activation(&bundle)
            .expect_err("activation acknowledgement is lost after commit")
            .kind,
        ProviderErrorKind::OutcomeUnknown
    );
    assert_eq!(provider.entry(JournalPosition(1)), Ok(Some(entry)));
    for resource in [timer, kv] {
        assert_eq!(
            provider.current_lease(resource),
            Ok(Some(LeaseRecord { resource, owner: scope.node, epoch: LeaseEpoch(1) }))
        );
    }
    assert_eq!(
        provider.fault_observation(),
        Some(crate::FaultObservation { point: FaultPoint::AfterActivationBundle, count: 2 })
    );
    provider.commit_activation(&bundle).expect("duplicate activation bundle is idempotent");
}

#[test]
fn kv_deduplicates_and_reconciles_a_lost_acknowledgement() {
    let db = TestDb::new("kv-dedup");
    let (mut provider, fixture) = configured_provider(&db.path);
    provider
        .provision_key_value_namespace(fixture.kv, id(50))
        .expect("same source provisioning is idempotent");
    assert_eq!(
        provider
            .provision_key_value_namespace(fixture.kv, id(51))
            .expect_err("namespace substitution is visible")
            .kind,
        ProviderErrorKind::Conflict
    );
    let request = kv_request(&fixture, 110, None);
    append_intent(&mut provider, 1, &request);
    provider.inject_failure_once(FaultPoint::AfterKvCommit);
    let error =
        provider.compare_and_set(&request).expect_err("acknowledgement is lost after commit");
    assert_eq!(error.kind, ProviderErrorKind::OutcomeUnknown);

    let observed = provider
        .query_operation(request.operation, request.idempotency_key)
        .expect("lost result is queryable")
        .expect("operation committed");
    assert!(matches!(
        observed,
        EffectOutcome::Succeeded {
            result: EffectResult::KeyValue { version: 1, applied: true },
            ..
        }
    ));
    assert_eq!(provider.compare_and_set(&request), Ok(observed));

    let next = kv_request(&fixture, 111, Some(1));
    append_intent(&mut provider, 2, &next);
    assert!(matches!(
        provider.compare_and_set(&next),
        Ok(EffectOutcome::Succeeded {
            result: EffectResult::KeyValue { version: 2, applied: true },
            ..
        })
    ));

    let read = kv_read(&fixture, 112);
    append_intent(&mut provider, 3, &read);
    let read_outcome = provider.read(&read).expect("versioned value reads");
    assert!(matches!(
        &read_outcome,
        EffectOutcome::Succeeded {
            result: EffectResult::KeyValueRead {
                value: Some(value)
            },
            ..
        } if value.version == 2 && value.value == 111_u128.to_be_bytes()
    ));
    assert_eq!(
        provider.query_operation(read.operation, read.idempotency_key).expect("read reconciles"),
        Some(read_outcome)
    );
}

#[test]
fn handoff_commit_atomically_fences_both_claims_and_survives_lost_ack() {
    let db = TestDb::new("handoff");
    let (mut provider, fixture) = configured_provider(&db.path);
    let request = lease_request(&fixture, 120);
    let extra_pending = entity(122);
    provider
        .reauthorize(ReauthorizationRequest {
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            source_authority: fixture.kv_authority,
            destination_authority: extra_pending,
            destination_subject: fixture.destination_subject,
            resource: fixture.kv,
            required_rights: Rights::KV_READ,
        })
        .expect("extra prepared grant installs");
    let mut wrong_scope = request.clone();
    wrong_scope.kind = EffectKind::LeaseCommit {
        handoff: fixture.handoff,
        snapshot: id(9_999),
        destination: fixture.destination_node,
        expected_epoch: LeaseEpoch(1),
        next_epoch: LeaseEpoch(2),
    };
    assert_eq!(
        provider
            .authorize_effect(&wrong_scope, Rights::HANDOFF)
            .expect_err("pending handoff authority cannot cross snapshot scope")
            .kind,
        ProviderErrorKind::Denied
    );
    append_intent(&mut provider, 1, &request);
    let prepared = provider
        .prepare_transitions(&request, &[fixture.timer, fixture.kv])
        .expect("both transitions prepare");
    let entry = journal_entry(
        2,
        EventKind::HandoffCommitted {
            operation: request.operation,
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            source: fixture.source_node,
            destination: fixture.destination_node,
            previous_epoch: LeaseEpoch(1),
            new_epoch: LeaseEpoch(2),
            outcome: prepared.outcome.clone(),
        },
    );
    let bundle = CommitBundle {
        entry: entry.clone(),
        lease_transitions: prepared.transitions,
        final_authorities: vec![
            fixture.destination_handoff_authority,
            fixture.destination_timer_authority,
            fixture.destination_kv_authority,
        ],
    };
    provider.inject_failure_once(FaultPoint::AfterCommitBundle);
    let error = provider.commit_bundle(&bundle).expect_err("commit acknowledgement is lost");
    assert_eq!(error.kind, ProviderErrorKind::OutcomeUnknown);
    assert_eq!(
        provider.fault_observation(),
        Some(crate::FaultObservation { point: FaultPoint::AfterCommitBundle, count: 1 })
    );

    for resource in [fixture.timer, fixture.kv] {
        assert_eq!(
            provider.current_lease(resource).expect("lease reads"),
            Some(LeaseRecord { resource, owner: fixture.destination_node, epoch: LeaseEpoch(2) })
        );
    }
    assert_eq!(provider.entry(JournalPosition(2)), Ok(Some(entry)));
    provider.commit_bundle(&bundle).expect("duplicate commit is idempotent");

    let mut destination_read = kv_read(&fixture, 123);
    destination_read.node = fixture.destination_node;
    destination_read.subject = fixture.destination_subject;
    destination_read.authority = fixture.destination_kv_authority;
    destination_read.lease_epoch = LeaseEpoch(2);
    assert_eq!(provider.authorize_effect(&destination_read, Rights::KV_READ), Ok(Rights::KV_READ));
    destination_read.authority = extra_pending;
    assert_eq!(
        provider
            .authorize_effect(&destination_read, Rights::KV_READ)
            .expect_err("non-final pending grant is revoked at commit")
            .kind,
        ProviderErrorKind::Revoked
    );

    let observed_before =
        provider.inspect_key_value(fixture.kv, b"counter").expect("key-value state is inspectable");
    let stale_without_intent = kv_request(&fixture, 124, Some(0));
    assert_eq!(
        provider
            .compare_and_set(&stale_without_intent)
            .expect_err("a stale source is fenced before intent lookup")
            .kind,
        ProviderErrorKind::StaleEpoch
    );
    assert_eq!(
        provider.inspect_key_value(fixture.kv, b"counter"),
        Ok(observed_before),
        "adversarial request cannot mutate KV before durable intent"
    );

    let stale = kv_request(&fixture, 121, Some(0));
    append_intent(&mut provider, 3, &stale);
    assert_eq!(
        provider.compare_and_set(&stale).expect_err("source is fenced").kind,
        ProviderErrorKind::StaleEpoch
    );
}

#[test]
fn source_and_destination_journals_are_scoped_while_leases_commit_globally() {
    let db = TestDb::new("scoped-journal");
    let (mut source, fixture) = configured_provider(&db.path);
    let request = lease_request(&fixture, 125);
    let intent = journal_entry(1, EventKind::EffectPrepared { request: request.clone() });
    source.append_entry(&intent).expect("source intent appends");

    let mut destination = SqliteProvider::open(
        &db.path,
        JournalScope {
            node: fixture.destination_node,
            component: fixture.destination_subject.identity,
        },
    )
    .expect("destination scope opens in the same database");
    destination
        .append_entry(&intent)
        .expect("same position and event id append in destination scope");
    assert_eq!(source.entry(JournalPosition(1)), Ok(Some(intent.clone())));
    assert_eq!(destination.entry(JournalPosition(1)), Ok(Some(intent)));

    let prepared = destination
        .prepare_transitions(&request, &[fixture.timer, fixture.kv])
        .expect("destination validates shared leases");
    let commit = journal_entry(
        2,
        EventKind::HandoffCommitted {
            operation: request.operation,
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            source: fixture.source_node,
            destination: fixture.destination_node,
            previous_epoch: LeaseEpoch(1),
            new_epoch: LeaseEpoch(2),
            outcome: prepared.outcome,
        },
    );
    destination
        .commit_bundle(&CommitBundle {
            entry: commit.clone(),
            lease_transitions: prepared.transitions,
            final_authorities: vec![
                fixture.destination_handoff_authority,
                fixture.destination_timer_authority,
                fixture.destination_kv_authority,
            ],
        })
        .expect("destination journal and shared leases commit atomically");

    assert_eq!(destination.entry(JournalPosition(2)), Ok(Some(commit)));
    assert_eq!(source.entry(JournalPosition(2)), Ok(None));
    assert_eq!(source.replay_from(None).expect("source replay reads").len(), 1);
    assert_eq!(destination.replay_from(None).expect("destination replay reads").len(), 2);
    for resource in [fixture.timer, fixture.kv] {
        let expected =
            Some(LeaseRecord { resource, owner: fixture.destination_node, epoch: LeaseEpoch(2) });
        assert_eq!(source.current_lease(resource), Ok(expected));
        assert_eq!(destination.current_lease(resource), Ok(expected));
    }

    let mut destination_arm = timer_arm(&fixture, 126, 50_000_000);
    destination_arm.node = fixture.destination_node;
    destination_arm.subject = fixture.destination_subject;
    destination_arm.authority = fixture.destination_timer_authority;
    destination_arm.lease_epoch = LeaseEpoch(2);
    append_intent(&mut destination, 3, &destination_arm);
    destination.arm(&destination_arm).expect("destination timer rearms");
    drop(destination);

    let mut recovered = SqliteProvider::open(
        &db.path,
        JournalScope {
            node: fixture.destination_node,
            component: fixture.destination_subject.identity,
        },
    )
    .expect("destination restarts after rearm");
    recovered
        .restore_timer_binding(
            &destination_arm,
            substrate_api::TimerRecovery::Running { remaining: LogicalDurationNanos(5_000_000) },
        )
        .expect("destination timer binding rebuilds");
    recovered
        .restore_timer_binding(
            &destination_arm,
            substrate_api::TimerRecovery::Running { remaining: LogicalDurationNanos(50_000_000) },
        )
        .expect("duplicate recovery does not reset the deadline");
    thread::sleep(Duration::from_millis(8));
    assert!(matches!(
        recovered.observe(destination_arm.operation),
        Ok(TimerObservation::Completed { .. })
    ));
}

#[test]
fn multi_claim_commit_rolls_back_if_one_epoch_changed_after_prepare() {
    let db = TestDb::new("atomic-rollback");
    let (mut provider, fixture) = configured_provider(&db.path);
    let request = lease_request(&fixture, 130);
    append_intent(&mut provider, 1, &request);
    let prepared = provider
        .prepare_transitions(&request, &[fixture.timer, fixture.kv])
        .expect("transitions prepare");
    provider
        .connection
        .execute(
            "UPDATE ownership SET epoch = ?2 WHERE resource_id = ?1",
            rusqlite::params![fixture.kv.identity.0.as_slice(), 9_u64.to_be_bytes()],
        )
        .expect("simulate concurrent lease change");
    let entry = journal_entry(
        2,
        EventKind::HandoffCommitted {
            operation: request.operation,
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            source: fixture.source_node,
            destination: fixture.destination_node,
            previous_epoch: LeaseEpoch(1),
            new_epoch: LeaseEpoch(2),
            outcome: prepared.outcome,
        },
    );
    let error = provider
        .commit_bundle(&CommitBundle {
            entry,
            lease_transitions: prepared.transitions,
            final_authorities: vec![
                fixture.destination_handoff_authority,
                fixture.destination_timer_authority,
                fixture.destination_kv_authority,
            ],
        })
        .expect_err("one stale claim aborts the whole transaction");
    assert_eq!(error.kind, ProviderErrorKind::StaleEpoch);
    assert_eq!(
        provider.current_lease(fixture.timer).expect("timer lease reads"),
        Some(LeaseRecord {
            resource: fixture.timer,
            owner: fixture.source_node,
            epoch: LeaseEpoch(1),
        }),
        "timer transition is rolled back"
    );
    assert_eq!(provider.entry(JournalPosition(2)), Ok(None));
}

#[test]
fn pending_reauthorization_narrows_policy_and_revocation_reaches_children() {
    let db = TestDb::new("authority");
    let (mut provider, fixture) = configured_provider(&db.path);
    let child = entity(140);
    let narrowed = provider
        .reauthorize(ReauthorizationRequest {
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            source_authority: fixture.kv_authority,
            destination_authority: child,
            destination_subject: fixture.destination_subject,
            resource: fixture.kv,
            required_rights: Rights::KV_READ,
        })
        .expect("narrow authority is granted");
    assert_eq!(narrowed.rights, Rights::KV_READ);

    let mut request = kv_request(&fixture, 141, None);
    request.node = fixture.destination_node;
    request.subject = fixture.destination_subject;
    request.authority = child;
    request.lease_epoch = LeaseEpoch(2);
    assert_eq!(
        provider
            .authorize_effect(&request, Rights::KV_READ)
            .expect_err("pending child cannot execute before commit")
            .kind,
        ProviderErrorKind::Denied
    );

    provider.revoke(fixture.kv_authority).expect("root revokes");
    assert_eq!(
        provider
            .authorize_effect(&request, Rights::KV_READ)
            .expect_err("revoked ancestor invalidates child")
            .kind,
        ProviderErrorKind::Denied
    );
    assert_eq!(
        provider
            .reauthorize(ReauthorizationRequest {
                handoff: fixture.handoff,
                snapshot: fixture.snapshot,
                source_authority: fixture.kv_authority,
                destination_authority: entity(142),
                destination_subject: fixture.destination_subject,
                resource: fixture.kv,
                required_rights: Rights::KV_READ,
            })
            .expect_err("snapshot cannot resurrect revoked ancestry")
            .kind,
        ProviderErrorKind::Revoked
    );
}

#[test]
fn journal_authority_events_atomically_update_provider_enforcement() {
    let db = TestDb::new("journal-authority-events");
    let (mut provider, fixture) = configured_provider(&db.path);
    let child = AuthorityGrant {
        authority: entity(180),
        parent: Some(fixture.kv_authority),
        subject: fixture.source_subject,
        resource: fixture.kv,
        rights: Rights::KV_READ,
        status: contract_core::AuthorityStatus::Active,
    };
    let attenuation = journal_entry(1, EventKind::AuthorityAttenuated { grant: child.clone() });

    provider.inject_failure_once(FaultPoint::AfterJournalWrite);
    assert_eq!(
        provider
            .append_entry(&attenuation)
            .expect_err("committed attenuation acknowledgement is lost")
            .kind,
        ProviderErrorKind::OutcomeUnknown
    );
    assert_eq!(provider.entry(JournalPosition(1)).unwrap(), Some(attenuation.clone()));
    provider.append_entry(&attenuation).expect("lost acknowledgement retry is idempotent");

    let child_request =
        EffectRequest { authority: child.authority, ..kv_request(&fixture, 181, None) };
    assert_eq!(provider.authorize_effect(&child_request, Rights::KV_READ), Ok(Rights::KV_READ));

    let revocation = journal_entry(
        2,
        EventKind::AuthorityRevoked {
            authority: fixture.kv_authority,
            revoked_generation: Generation(1),
        },
    );
    provider.append_entry(&revocation).expect("revocation commits with its journal entry");
    assert_eq!(provider.entry(JournalPosition(2)).unwrap(), Some(revocation));

    for request in [
        kv_request(&fixture, 182, None),
        child_request,
        EffectRequest {
            authority: EntityRef::new(fixture.kv_authority.identity, Generation(1)),
            ..kv_request(&fixture, 183, None)
        },
    ] {
        assert_eq!(
            provider
                .authorize_effect(&request, Rights::KV_READ)
                .expect_err("revocation rejects old, child, and advanced references")
                .kind,
            ProviderErrorKind::Revoked
        );
    }
}

#[test]
fn revoked_generation_tombstone_survives_reopen_and_blocks_root_reinstall() {
    let db = TestDb::new("authority-revocation-reopen");
    let (mut provider, fixture) = configured_provider(&db.path);
    let original = AuthorityGrant::active_root(
        fixture.kv_authority,
        fixture.source_subject,
        fixture.kv,
        Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND),
    );
    provider
        .append_entry(&journal_entry(
            1,
            EventKind::AuthorityRevoked {
                authority: fixture.kv_authority,
                revoked_generation: Generation(1),
            },
        ))
        .expect("canonical revocation commits");
    drop(provider);

    let mut reopened = SqliteProvider::open(
        &db.path,
        JournalScope { node: fixture.source_node, component: fixture.source_subject.identity },
    )
    .expect("provider reopens");
    assert_eq!(
        reopened
            .install_grant(&original)
            .expect_err("an older root generation cannot replace a revoked tombstone")
            .kind,
        ProviderErrorKind::StaleGeneration
    );
    assert_eq!(
        reopened
            .authorize_effect(&kv_request(&fixture, 184, None), Rights::KV_READ)
            .expect_err("the original authority remains revoked after reopen")
            .kind,
        ProviderErrorKind::Revoked
    );
}

#[test]
fn rejected_journal_attenuation_leaves_no_grant_or_journal_entry() {
    let db = TestDb::new("journal-authority-rollback");
    let (mut provider, fixture) = configured_provider(&db.path);
    let invalid_child = AuthorityGrant {
        authority: entity(190),
        parent: Some(fixture.kv_authority),
        subject: fixture.source_subject,
        resource: fixture.kv,
        rights: Rights::KV_READ.union(Rights::TIMER_ARM),
        status: contract_core::AuthorityStatus::Active,
    };
    let entry = journal_entry(1, EventKind::AuthorityAttenuated { grant: invalid_child.clone() });

    assert_eq!(
        provider.append_entry(&entry).expect_err("policy-amplifying attenuation is rejected").kind,
        ProviderErrorKind::Denied
    );
    assert_eq!(provider.entry(JournalPosition(1)).unwrap(), None);
    let request =
        EffectRequest { authority: invalid_child.authority, ..kv_request(&fixture, 191, None) };
    assert_eq!(
        provider
            .authorize_effect(&request, Rights::KV_READ)
            .expect_err("rolled-back attenuation never becomes enforceable")
            .kind,
        ProviderErrorKind::NotFound
    );
    assert_eq!(
        provider.authorize_effect(&kv_request(&fixture, 192, None), Rights::KV_READ),
        Ok(Rights::KV_READ)
    );
}

#[test]
fn handoff_reauthorization_allows_only_one_generation_step_for_same_component() {
    let db = TestDb::new("handoff-generation");
    let (mut provider, fixture) = configured_provider(&db.path);
    let component0 = entity(200);
    let component1 = EntityRef::new(component0.identity, Generation(1));
    let component2 = EntityRef::new(component0.identity, Generation(2));
    let other1 = EntityRef::new(id(201), Generation(1));
    let root = entity(210);
    provider
        .install_policy(AuthorityPolicy {
            subject: component0,
            resource: component0,
            allowed_rights: Rights::HANDOFF,
        })
        .expect("source handoff policy installs");
    for target in [component1, component2, other1] {
        provider
            .install_policy(AuthorityPolicy {
                subject: target,
                resource: target,
                allowed_rights: Rights::HANDOFF,
            })
            .expect("destination handoff policy installs");
    }
    provider
        .install_grant(&AuthorityGrant::active_root(root, component0, component0, Rights::HANDOFF))
        .expect("source handoff grant installs");

    let destination = entity(211);
    let grant = provider
        .reauthorize(ReauthorizationRequest {
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            source_authority: root,
            destination_authority: destination,
            destination_subject: component1,
            resource: component1,
            required_rights: Rights::HANDOFF,
        })
        .expect("adjacent component generation reauthorizes");
    assert_eq!(grant.parent, Some(root));
    assert_eq!(grant.subject, component1);
    assert_eq!(grant.resource, component1);

    for (authority, subject, resource) in
        [(entity(212), component2, component2), (entity(213), other1, other1)]
    {
        assert_eq!(
            provider
                .reauthorize(ReauthorizationRequest {
                    handoff: fixture.handoff,
                    snapshot: fixture.snapshot,
                    source_authority: root,
                    destination_authority: authority,
                    destination_subject: subject,
                    resource,
                    required_rights: Rights::HANDOFF,
                })
                .expect_err("jumped or different identity is denied")
                .kind,
            ProviderErrorKind::Denied
        );
    }

    let kv_component0 = entity(220);
    let kv_component1 = EntityRef::new(kv_component0.identity, Generation(1));
    let kv_root = entity(214);
    provider
        .install_policy(AuthorityPolicy {
            subject: kv_component0,
            resource: kv_component0,
            allowed_rights: Rights::KV_READ,
        })
        .expect("source kv policy installs");
    provider
        .install_policy(AuthorityPolicy {
            subject: kv_component1,
            resource: kv_component1,
            allowed_rights: Rights::KV_READ,
        })
        .expect("destination kv policy installs");
    provider
        .install_grant(&AuthorityGrant::active_root(
            kv_root,
            kv_component0,
            kv_component0,
            Rights::KV_READ,
        ))
        .expect("source kv grant installs");
    assert_eq!(
        provider
            .reauthorize(ReauthorizationRequest {
                handoff: fixture.handoff,
                snapshot: fixture.snapshot,
                source_authority: kv_root,
                destination_authority: entity(215),
                destination_subject: kv_component1,
                resource: kv_component1,
                required_rights: Rights::KV_READ,
            })
            .expect_err("non-handoff rights cannot cross resource generation")
            .kind,
        ProviderErrorKind::Denied
    );

    // Keep the shared fixture live so this test also proves the special rule
    // does not disturb ordinary exact-resource grants.
    assert_eq!(
        provider.authorize_effect(&kv_request(&fixture, 216, None), Rights::KV_WRITE),
        Ok(Rights::KV_WRITE)
    );
}

#[test]
fn prepared_authority_cleanup_is_snapshot_scoped_and_idempotent() {
    let db = TestDb::new("prepared-authority-cleanup");
    let (mut provider, fixture) = configured_provider(&db.path);
    provider.revoke_prepared(fixture.snapshot).expect("prepared grants revoke");
    provider.revoke_prepared(fixture.snapshot).expect("prepared grant cleanup repeats");

    let request = lease_request(&fixture, 230);
    assert_eq!(
        provider
            .authorize_effect(&request, Rights::HANDOFF)
            .expect_err("cleaned handoff authority stays revoked")
            .kind,
        ProviderErrorKind::Revoked
    );
    let mut destination_read = kv_read(&fixture, 231);
    destination_read.node = fixture.destination_node;
    destination_read.subject = fixture.destination_subject;
    destination_read.authority = fixture.destination_kv_authority;
    destination_read.lease_epoch = LeaseEpoch(2);
    assert_eq!(
        provider
            .authorize_effect(&destination_read, Rights::KV_READ)
            .expect_err("cleaned resource authority stays revoked")
            .kind,
        ProviderErrorKind::Revoked
    );
}

#[test]
fn destination_binding_cleanup_preserves_the_source_timer() {
    let db = TestDb::new("source-timer-binding-cleanup");
    let (mut provider, fixture) = configured_provider(&db.path);
    let request = timer_arm(&fixture, 232, 5_000_000_000);
    append_intent(&mut provider, 1, &request);
    provider.arm(&request).expect("source timer arms");

    provider
        .cleanup_binding(fixture.snapshot, fixture.timer)
        .expect("destination candidate binding cleans");
    assert!(matches!(provider.observe(request.operation), Ok(TimerObservation::Pending(_))));
}

#[test]
fn destination_kv_binding_requires_existing_mapping_and_node_availability() {
    let db = TestDb::new("destination-kv-availability");
    let (mut provider, fixture) = configured_provider(&db.path);
    let resource = entity(240);
    let source_authority = entity(241);
    let destination_authority = entity(242);
    let handoff = id(243);
    let snapshot = id(244);
    let rights = Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND);
    for policy in [
        AuthorityPolicy { subject: fixture.source_subject, resource, allowed_rights: rights },
        AuthorityPolicy { subject: fixture.destination_subject, resource, allowed_rights: rights },
    ] {
        provider.install_policy(policy).expect("kv policy installs");
    }
    provider
        .install_grant(&AuthorityGrant::active_root(
            source_authority,
            fixture.source_subject,
            resource,
            rights,
        ))
        .expect("source kv authority installs");
    provider
        .reauthorize(ReauthorizationRequest {
            handoff,
            snapshot,
            source_authority,
            destination_authority,
            destination_subject: fixture.destination_subject,
            resource,
            required_rights: rights,
        })
        .expect("destination kv authority prepares");
    provider
        .initialize_lease(LeaseRecord {
            resource,
            owner: fixture.source_node,
            epoch: LeaseEpoch(1),
        })
        .expect("resource lease initializes");
    provider.provision_key_value_namespace(resource, id(245)).expect("source mapping provisions");

    let request = |namespace| BindingRequest {
        handoff,
        snapshot,
        claim: resource,
        authority: destination_authority,
        exposed_rights: rights,
        expected_owner: fixture.source_node,
        expected_epoch: LeaseEpoch(1),
        candidate_owner: fixture.destination_node,
        candidate_epoch: LeaseEpoch(2),
        kind: BindingKind::KeyValueNamespace { namespace },
    };
    assert_eq!(
        provider
            .prepare_binding(request(id(245)))
            .expect_err("missing destination availability rejects")
            .kind,
        ProviderErrorKind::NotFound
    );
    provider
        .provision_key_value_namespace_availability(fixture.destination_node, id(246))
        .expect("wrong destination namespace provisions");
    assert_eq!(
        provider
            .prepare_binding(request(id(246)))
            .expect_err("wrong logical namespace cannot substitute")
            .kind,
        ProviderErrorKind::Conflict
    );
    provider
        .provision_key_value_namespace_availability(fixture.destination_node, id(245))
        .expect("correct destination namespace provisions");
    let receipt = provider.prepare_binding(request(id(245))).expect("correct binding prepares");
    assert_eq!(receipt.node, fixture.destination_node);
}

#[test]
fn timers_use_arm_operation_for_completion_cancellation_and_cleanup() {
    let db = TestDb::new("timer");
    let (mut provider, fixture) = configured_provider(&db.path);
    let completed = timer_arm(&fixture, 150, 1_000_000);
    append_intent(&mut provider, 1, &completed);
    provider.arm(&completed).expect("timer arms");
    thread::sleep(Duration::from_millis(3));
    assert!(matches!(
        provider.observe(completed.operation),
        Ok(TimerObservation::Completed { .. })
    ));

    let arm = timer_arm(&fixture, 151, 1_000_000_000);
    append_intent(&mut provider, 2, &arm);
    provider.arm(&arm).expect("second timer arms");
    assert!(matches!(provider.observe(arm.operation), Ok(TimerObservation::Pending(_))));
    let cancel = EffectRequest {
        operation: id(152),
        idempotency_key: IdempotencyKey::from_u128(152),
        causal_parent: Some(arm.operation),
        node: fixture.source_node,
        subject: fixture.source_subject,
        resource: fixture.timer,
        authority: fixture.timer_authority,
        lease_epoch: LeaseEpoch(1),
        request_digest: digest(152),
        kind: EffectKind::TimerCancel { target_operation: arm.operation },
    };
    append_intent(&mut provider, 3, &cancel);
    let outcome = provider.cancel(&cancel).expect("timer cancels");
    assert!(matches!(
        outcome,
        EffectOutcome::Succeeded { result: EffectResult::TimerCancelled, .. }
    ));
    assert_eq!(provider.cancel(&cancel), Ok(outcome));
    assert!(matches!(provider.observe(arm.operation), Ok(TimerObservation::Cancelled { .. })));
    provider.cleanup_timer(arm.operation).expect("first cleanup succeeds");
    provider.cleanup_timer(arm.operation).expect("repeated cleanup succeeds");
    assert_eq!(provider.observe(arm.operation), Ok(TimerObservation::Absent));

    let suspended = timer_arm(&fixture, 153, 20_000_000);
    append_intent(&mut provider, 4, &suspended);
    provider.arm(&suspended).expect("suspendable timer arms");
    let first = provider.suspend_timer(suspended.operation).expect("timer suspends");
    let TimerObservation::Pending(remaining) = first else {
        panic!("pending timer must suspend with a duration");
    };
    assert_eq!(provider.suspend_timer(suspended.operation), Ok(first));
    thread::sleep(Duration::from_millis(30));
    assert_eq!(provider.observe(suspended.operation), Ok(first));
    provider.resume_suspended(suspended.operation).expect("timer resumes");
    provider.resume_suspended(suspended.operation).expect("repeated resume is idempotent");
    thread::sleep(Duration::from_nanos(remaining.0).saturating_add(Duration::from_millis(3)));
    assert!(matches!(
        provider.observe(suspended.operation),
        Ok(TimerObservation::Completed { .. })
    ));
}

#[test]
fn suspended_timer_binding_recovers_without_consuming_frozen_duration() {
    let db = TestDb::new("suspended-timer-recovery");
    let (mut provider, fixture) = configured_provider(&db.path);
    let arm = timer_arm(&fixture, 155, 30_000_000);
    append_intent(&mut provider, 1, &arm);
    provider.arm(&arm).expect("source timer arms");
    let TimerObservation::Pending(remaining) =
        provider.suspend_timer(arm.operation).expect("source timer suspends")
    else {
        panic!("suspended source timer must retain remaining duration");
    };
    drop(provider);

    let mut recovered = SqliteProvider::open(
        &db.path,
        JournalScope { node: fixture.source_node, component: fixture.source_subject.identity },
    )
    .expect("frozen source restarts");
    recovered
        .restore_timer_binding(&arm, substrate_api::TimerRecovery::Suspended { remaining })
        .expect("suspended binding rebuilds");
    recovered
        .restore_timer_binding(&arm, substrate_api::TimerRecovery::Suspended { remaining })
        .expect("duplicate suspended recovery is idempotent");
    thread::sleep(Duration::from_nanos(remaining.0).saturating_add(Duration::from_millis(3)));
    assert_eq!(
        recovered.observe(arm.operation),
        Ok(TimerObservation::Pending(remaining)),
        "time spent frozen does not consume the logical duration"
    );
    recovered.resume_suspended(arm.operation).expect("source timer resumes after abort");
    thread::sleep(Duration::from_nanos(remaining.0).saturating_add(Duration::from_millis(3)));
    assert!(matches!(recovered.observe(arm.operation), Ok(TimerObservation::Completed { .. })));
}

#[test]
fn journal_failure_and_repeated_cleanup_leave_durable_truth_coherent() {
    let db = TestDb::new("cleanup");
    let (mut provider, fixture) = configured_provider(&db.path);
    let request = kv_request(&fixture, 160, None);
    provider.inject_failure_once(FaultPoint::BeforeJournalWrite);
    let entry = journal_entry(1, EventKind::EffectPrepared { request: request.clone() });
    assert_eq!(
        provider.append_entry(&entry).expect_err("journal failure is explicit").kind,
        ProviderErrorKind::Unavailable
    );
    assert_eq!(provider.operation(request.operation), Ok(None));
    assert!(provider.replay_from(None).expect("empty replay succeeds").is_empty());

    provider.append_entry(&entry).expect("retry appends intent");
    provider.compare_and_set(&request).expect("effect resolves");
    let cleanup = journal_entry(
        2,
        EventKind::OperationCleaned {
            operation: request.operation,
            evidence: evidence(161, EvidenceKind::Cleanup),
        },
    );
    provider.append_entry(&cleanup).expect("cleanup event appends");
    provider.append_entry(&cleanup).expect("duplicate cleanup event is idempotent");
    assert_eq!(
        provider
            .operation(request.operation)
            .expect("operation reads")
            .expect("operation exists")
            .record
            .cleanup,
        CleanupStatus::Cleaned
    );

    provider.cleanup_binding(fixture.snapshot, fixture.kv).expect("binding cleans");
    provider.cleanup_binding(fixture.snapshot, fixture.kv).expect("binding cleanup repeats");
    let error = provider
        .prepare_binding(BindingRequest {
            handoff: fixture.handoff,
            snapshot: fixture.snapshot,
            claim: fixture.kv,
            authority: fixture.destination_kv_authority,
            exposed_rights: Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND),
            expected_owner: fixture.source_node,
            expected_epoch: LeaseEpoch(1),
            candidate_owner: fixture.destination_node,
            candidate_epoch: LeaseEpoch(2),
            kind: BindingKind::KeyValueNamespace { namespace: id(50) },
        })
        .expect_err("cleaned binding cannot resurrect");
    assert_eq!(error.kind, ProviderErrorKind::Conflict);
}
