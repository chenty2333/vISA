use std::{fs, os::unix::fs::PermissionsExt};

use rusqlite::Connection;
use tempfile::tempdir;
use visa_local_rpc::common::{
    AgentRole, BootId, CohortId, LogicalIncarnation, PRODUCT_VERSION, ProcessNonce,
    RuntimeSessionId, StableAgentIdentity,
};

use super::{AgentStore, AgentStoreError, audit_unstarted, inspect_existing, publish_new};

fn identity(role: AgentRole, seed: u128) -> StableAgentIdentity {
    StableAgentIdentity {
        product_version: PRODUCT_VERSION,
        cohort: CohortId::from_u128(seed + 1),
        boot: BootId::from_u128(seed + 2),
        runtime_session: RuntimeSessionId::from_u128(seed + 3),
        role,
        logical_incarnation: LogicalIncarnation::from_u128(seed + 4),
    }
}

fn path() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private temporary directory");
    let database = directory.path().join("agent.sqlite");
    (directory, database)
}

#[test]
fn publish_audit_and_reopen_allocate_gap_free_process_bindings() {
    let (_directory, database) = path();
    let expected = identity(AgentRole::Source, 10);
    publish_new(&database, expected, ProcessNonce::from_u128(100)).expect("publish");

    let audit = audit_unstarted(&database, expected).expect("generation-zero audit");
    assert_eq!(audit.stable_identity, expected);
    assert_eq!(audit.process_generation, 0);
    assert_eq!(inspect_existing(&database).expect("identity inspection"), audit);

    let first = AgentStore::reopen_existing(&database, expected, ProcessNonce::from_u128(101))
        .expect("first process");
    assert_eq!(first.binding().process_generation, 1);
    assert_eq!(first.wire_binding().process_nonce, ProcessNonce::from_u128(101));
    assert!(expected.matches(first.wire_binding()));
    drop(first);

    let audit = audit_unstarted(&database, expected).expect("audit after first process");
    assert_eq!(audit.process_generation, 1);

    let second = AgentStore::reopen_existing(&database, expected, ProcessNonce::from_u128(102))
        .expect("second process");
    assert_eq!(second.binding().process_generation, 2);
    drop(second);

    assert_eq!(audit_unstarted(&database, expected).expect("final audit").process_generation, 2);
}

#[test]
fn runtime_reopen_never_creates_or_adopts_and_rejects_identity_or_nonce_substitution() {
    let (_directory, database) = path();
    let expected = identity(AgentRole::Destination, 20);
    let other = identity(AgentRole::Destination, 30);

    assert!(matches!(
        AgentStore::reopen_existing(&database, expected, ProcessNonce::from_u128(201)),
        Err(AgentStoreError::StoreMismatch)
            | Err(AgentStoreError::Storage)
            | Err(AgentStoreError::Integrity)
    ));
    publish_new(&database, expected, ProcessNonce::from_u128(200)).expect("publish");
    assert!(matches!(
        AgentStore::reopen_existing(&database, other, ProcessNonce::from_u128(201)),
        Err(AgentStoreError::StoreMismatch)
    ));

    let first = AgentStore::reopen_existing(&database, expected, ProcessNonce::from_u128(201))
        .expect("first process");
    drop(first);
    assert!(matches!(
        AgentStore::reopen_existing(&database, expected, ProcessNonce::from_u128(201)),
        Err(AgentStoreError::StoreMismatch)
    ));
}

#[test]
fn zero_nonce_and_invalid_identity_are_rejected_before_filesystem_mutation() {
    let (_directory, database) = path();
    let expected = identity(AgentRole::Source, 40);
    assert_eq!(
        publish_new(&database, expected, ProcessNonce::ZERO).expect_err("zero init nonce"),
        AgentStoreError::InvalidRequest
    );
    assert!(!database.exists());

    let mut invalid = expected;
    invalid.cohort = CohortId::ZERO;
    assert_eq!(
        publish_new(&database, invalid, ProcessNonce::from_u128(401)).expect_err("zero identity"),
        AgentStoreError::InvalidRequest
    );
    assert!(!database.exists());
}

#[test]
fn existing_sidecars_and_extra_schema_objects_fail_closed() {
    let (_directory, database) = path();
    let expected = identity(AgentRole::Source, 50);
    fs::write(format!("{}-wal", database.display()), b"untrusted").expect("sidecar");
    assert_eq!(
        publish_new(&database, expected, ProcessNonce::from_u128(501))
            .expect_err("sidecar must block publish"),
        AgentStoreError::StoreMismatch
    );
    fs::remove_file(format!("{}-wal", database.display())).expect("remove sidecar");

    publish_new(&database, expected, ProcessNonce::from_u128(502)).expect("publish");
    let connection = Connection::open(&database).expect("tamper connection");
    connection.execute_batch("CREATE TABLE untrusted_extra(value INTEGER)").expect("tamper schema");
    drop(connection);
    assert!(matches!(
        audit_unstarted(&database, expected),
        Err(AgentStoreError::Integrity) | Err(AgentStoreError::StoreMismatch)
    ));
}
