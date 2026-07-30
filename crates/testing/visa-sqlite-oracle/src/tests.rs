use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use rusqlite::Connection;
use visa_wasi_protocol::{
    BarrierPhase, LockLevel, NamespaceDescriptor, NamespaceLock, NamespaceObject, NamespacePath,
    NamespaceSnapshot, ObjectId, OwnerId, ProviderMode, SessionId, encode_namespace_snapshot,
};

use super::*;

const ROOT: ObjectId = ObjectId([1; 16]);
const DATABASE: ObjectId = ObjectId([2; 16]);
const JOURNAL: ObjectId = ObjectId([3; 16]);
const LOCK_DIRECTORY: ObjectId = ObjectId([4; 16]);
const TEMP_DIRECTORY: ObjectId = ObjectId([5; 16]);
const SCRATCH: ObjectId = ObjectId([6; 16]);
const UNLINKED: ObjectId = ObjectId([7; 16]);

fn regular(object: ObjectId, bytes: Vec<u8>) -> NamespaceObject {
    NamespaceObject {
        object,
        kind: 4,
        size: bytes.len() as u64,
        symlink_target: None,
        mode: 0o600,
        uid: 1000,
        gid: 1000,
        accessed_ns: 10,
        modified_ns: 11,
        changed_ns: 12,
        bytes,
    }
}

fn directory(object: ObjectId) -> NamespaceObject {
    NamespaceObject {
        object,
        kind: 3,
        size: 0,
        symlink_target: None,
        mode: 0o700,
        uid: 1000,
        gid: 1000,
        accessed_ns: 10,
        modified_ns: 11,
        changed_ns: 12,
        bytes: Vec::new(),
    }
}

fn stock_database(schema: &str, rows: &str) -> Vec<u8> {
    let temporary = tempfile::tempdir().expect("database temporary directory");
    let path = temporary.path().join("bank.db");
    let connection = Connection::open(&path).expect("open stock database");
    connection.pragma_update(None, "journal_mode", "DELETE").expect("delete journal mode");
    connection.pragma_update(None, "foreign_keys", false).expect("disable fixture fk checks");
    connection.execute_batch(schema).expect("create stock schema");
    connection.execute_batch(rows).expect("insert stock rows");
    connection.close().expect("close stock database");
    fs::read(path).expect("read stock database")
}

fn valid_database() -> Vec<u8> {
    stock_database(
        "CREATE TABLE accounts (\
             account_id INTEGER PRIMARY KEY,\
             balance INTEGER NOT NULL\
         );\
         CREATE TABLE transactions (\
             txid TEXT NOT NULL PRIMARY KEY,\
             from_account INTEGER NOT NULL REFERENCES accounts(account_id),\
             to_account INTEGER NOT NULL REFERENCES accounts(account_id),\
             amount INTEGER NOT NULL CHECK(amount > 0)\
         );",
        "INSERT INTO accounts(account_id, balance) VALUES (2, 30), (1, 70);\
         INSERT INTO transactions(txid, from_account, to_account, amount)\
         VALUES ('tx-001', 1, 2, 30);",
    )
}

fn alternate_valid_database() -> Vec<u8> {
    stock_database(
        "CREATE TABLE accounts (\
             account_id INTEGER PRIMARY KEY,\
             balance INTEGER NOT NULL\
         );\
         CREATE TABLE transactions (\
             txid TEXT NOT NULL PRIMARY KEY,\
             from_account INTEGER NOT NULL REFERENCES accounts(account_id),\
             to_account INTEGER NOT NULL REFERENCES accounts(account_id),\
             amount INTEGER NOT NULL CHECK(amount > 0)\
         );",
        "INSERT INTO accounts(account_id, balance) VALUES (2, 40), (1, 60);\
         INSERT INTO transactions(txid, from_account, to_account, amount)\
         VALUES ('tx-001', 1, 2, 30);",
    )
}

fn snapshot_with_database(database: Vec<u8>) -> NamespaceSnapshot {
    NamespaceSnapshot {
        version: visa_wasi_protocol::NAMESPACE_SNAPSHOT_VERSION,
        session: SessionId([8; 16]),
        authority_epoch: 4,
        mode: ProviderMode::Active,
        barrier: BarrierPhase::CheckpointReleased,
        effect_frontier: [9; 32],
        effects: 2,
        objects: vec![
            directory(ROOT),
            regular(DATABASE, database),
            regular(JOURNAL, Vec::new()),
            directory(LOCK_DIRECTORY),
            directory(TEMP_DIRECTORY),
            regular(SCRATCH, b"temporary-state".to_vec()),
            regular(UNLINKED, b"unlinked-open-state".to_vec()),
        ],
        paths: vec![
            NamespacePath { path: Vec::new(), object: ROOT },
            NamespacePath { path: b"bank.db".to_vec(), object: DATABASE },
            NamespacePath { path: b"bank.db-journal".to_vec(), object: JOURNAL },
            NamespacePath { path: b"bank.db.lock".to_vec(), object: LOCK_DIRECTORY },
            NamespacePath { path: b"tmp".to_vec(), object: TEMP_DIRECTORY },
            NamespacePath { path: b"tmp/scratch".to_vec(), object: SCRATCH },
            NamespacePath { path: b"tmp/scratch-alias".to_vec(), object: SCRATCH },
        ],
        descriptors: vec![
            NamespaceDescriptor {
                fd: 3,
                object: ROOT,
                directory_path: Vec::new(),
                offset: 0,
                flags: 0,
                rights_base: u64::MAX,
                rights_inheriting: u64::MAX,
                preopen: true,
            },
            NamespaceDescriptor {
                fd: 4,
                object: DATABASE,
                directory_path: Vec::new(),
                offset: 64,
                flags: 0,
                rights_base: 3,
                rights_inheriting: 0,
                preopen: false,
            },
            NamespaceDescriptor {
                fd: 5,
                object: UNLINKED,
                directory_path: Vec::new(),
                offset: 7,
                flags: 0,
                rights_base: 3,
                rights_inheriting: 0,
                preopen: false,
            },
        ],
        locks: vec![NamespaceLock {
            object: DATABASE,
            owner: OwnerId([2; 16]),
            level: LockLevel::Shared,
        }],
    }
}

fn expected(txids: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&ExpectedAcks {
        schema_version: EXPECTED_ACKS_SCHEMA_VERSION.to_owned(),
        initial_total_balance: 100,
        acknowledged_txids: txids.iter().map(|value| (*value).to_owned()).collect(),
    })
    .expect("expected acknowledgements")
}

fn evaluate_snapshot(snapshot: &NamespaceSnapshot, expected_txids: &[&str]) -> OracleReport {
    evaluate(
        &encode_namespace_snapshot(snapshot).expect("encode snapshot"),
        &expected(expected_txids),
        b"bank.db",
    )
}

fn assert_finding(report: &OracleReport, code: &str) {
    assert!(
        report.findings.iter().any(|finding| finding.code == code),
        "missing finding {code:?} in {:?}",
        report.findings
    );
}

#[test]
fn valid_snapshot_is_materialized_and_recomputed_with_native_sqlite() {
    let report = evaluate_snapshot(&snapshot_with_database(valid_database()), &["tx-001"]);
    assert!(report.accepted, "{:?}", report.findings);
    let projection = report.semantic_projection.as_ref().expect("semantic projection");
    assert_eq!(projection.schema_version, SEMANTIC_PROJECTION_SCHEMA_VERSION);
    assert_eq!(projection.logical_contents.account_rows, 2);
    assert_eq!(projection.logical_contents.transaction_rows, 1);
    assert_eq!(
        projection.logical_contents.accounts_sha256,
        "bf96567759cfb471e6bc31078e151787733b7a8135e26fabd0557b77c7d9b459"
    );
    assert_eq!(projection.logical_contents.transactions_sha256.len(), 64);
    assert!(projection.integrity_ok);
    assert!(projection.foreign_keys_ok);
    assert!(projection.schema_accepted);
    assert!(projection.acknowledgements.exact_match);
    let namespace = report.namespace.expect("namespace report");
    assert_eq!(namespace.sqlite_sidecars[0].utf8.as_deref(), Some("bank.db-journal"));
    assert_eq!(namespace.locks.len(), 1);
    assert_eq!(namespace.unlinked_objects.len(), 1);
    assert_eq!(namespace.unlinked_objects[0].open_descriptors, vec![5]);
    let sqlite = report.sqlite.expect("sqlite report");
    assert_eq!(sqlite.integrity_check, vec!["ok"]);
    assert!(sqlite.foreign_key_check.is_empty());
    assert_eq!(
        sqlite.logical_rows.accounts,
        vec![AccountRow { account_id: 1, balance: 70 }, AccountRow { account_id: 2, balance: 30 }]
    );
    assert_eq!(sqlite.logical_rows.transactions[0].txid, "tx-001");
    assert!(sqlite.balance.total_matches);
    assert!(sqlite.balance.all_nonnegative);
    assert!(sqlite.transactions.unique_txids);
    assert!(sqlite.acknowledgements.exact_match);
}

#[test]
fn semantic_projection_changes_when_logical_rows_change() {
    let first = evaluate_snapshot(&snapshot_with_database(valid_database()), &["tx-001"]);
    let second =
        evaluate_snapshot(&snapshot_with_database(alternate_valid_database()), &["tx-001"]);
    assert!(first.accepted, "{:?}", first.findings);
    assert!(second.accepted, "{:?}", second.findings);
    let first = first.semantic_projection.expect("first semantic projection");
    let second = second.semantic_projection.expect("second semantic projection");
    assert_ne!(first.logical_contents.accounts_sha256, second.logical_contents.accounts_sha256);
    assert_eq!(
        first.logical_contents.transactions_sha256,
        second.logical_contents.transactions_sha256
    );
}

#[cfg(unix)]
#[test]
fn complete_namespace_tree_preserves_sidecars_aliases_temp_and_unlinked_state() {
    let snapshot = snapshot_with_database(valid_database());
    let encoded = encode_namespace_snapshot(&snapshot).expect("encode snapshot");
    assert!(namespace::validate_snapshot(&encoded, &snapshot).is_empty());
    let materialized = namespace::materialize(&snapshot, b"bank.db").expect("materialize");
    let root = materialized.namespace_root();
    assert!(root.join("bank.db").is_file());
    assert!(root.join("bank.db-journal").is_file());
    assert!(root.join("bank.db.lock").is_dir());
    assert_eq!(fs::read(root.join("tmp/scratch")).unwrap(), b"temporary-state");
    assert_eq!(
        fs::metadata(root.join("tmp/scratch")).unwrap().ino(),
        fs::metadata(root.join("tmp/scratch-alias")).unwrap().ino()
    );
    assert_eq!(
        fs::read(materialized.unlinked_root().join(hex::encode(UNLINKED.0))).unwrap(),
        b"unlinked-open-state"
    );
}

#[test]
fn strict_snapshot_mutations_are_rejected() {
    let base = snapshot_with_database(valid_database());

    let mut mutated = base.clone();
    mutated.version += 1;
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-version");

    let mut mutated = base.clone();
    mutated.effect_frontier = [0; 32];
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-effect-frontier-zero");

    let mut mutated = base.clone();
    mutated.objects[1].size += 1;
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-object-size-bytes");

    let mut mutated = base.clone();
    mutated.objects.push(mutated.objects[1].clone());
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-object-duplicate");

    let mut mutated = base.clone();
    mutated.paths.push(mutated.paths[1].clone());
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-path-duplicate");

    let mut mutated = base.clone();
    mutated.paths[1].object = ObjectId([99; 16]);
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-path-object-missing");

    let mut mutated = base.clone();
    mutated.descriptors[1].object = ObjectId([99; 16]);
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-descriptor-object-missing");

    let mut mutated = base.clone();
    mutated.locks[0].object = ObjectId([99; 16]);
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-lock-object-missing");

    let mut mutated = base.clone();
    mutated.paths[5].path = b"tmp/../escape".to_vec();
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-path-noncanonical");

    let mut mutated = base.clone();
    let symlink = ObjectId([8; 16]);
    mutated.objects.push(NamespaceObject {
        object: symlink,
        kind: 7,
        size: 0,
        symlink_target: Some(b"../../outside".to_vec()),
        mode: 0o777,
        uid: 1000,
        gid: 1000,
        accessed_ns: 10,
        modified_ns: 11,
        changed_ns: 12,
        bytes: Vec::new(),
    });
    mutated.paths.insert(5, NamespacePath { path: b"tmp/escape".to_vec(), object: symlink });
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-symlink-escape");

    let mut mutated = base;
    mutated.descriptors.pop();
    assert_finding(&evaluate_snapshot(&mutated, &["tx-001"]), "snapshot-object-unreachable");
}

#[test]
fn trailing_snapshot_bytes_are_rejected() {
    let mut encoded =
        encode_namespace_snapshot(&snapshot_with_database(valid_database())).expect("snapshot");
    encoded.push(0);
    let report = evaluate(&encoded, &expected(&["tx-001"]), b"bank.db");
    assert!(!report.accepted);
    assert!(
        report.findings.iter().any(|finding| {
            finding.code == "snapshot-decode" || finding.code == "snapshot-noncanonical-encoding"
        }),
        "{:?}",
        report.findings
    );
}

#[test]
fn acknowledgement_mismatch_is_reported_exactly() {
    let report = evaluate_snapshot(&snapshot_with_database(valid_database()), &["tx-002"]);
    assert_finding(&report, "sqlite-acknowledged-txids");
    let acknowledgements = report.sqlite.expect("sqlite report").acknowledgements;
    assert_eq!(acknowledgements.missing_txids, vec!["tx-002"]);
    assert_eq!(acknowledgements.unexpected_txids, vec!["tx-001"]);
}

#[test]
fn balance_and_foreign_key_mutations_are_detected() {
    let database = stock_database(
        "CREATE TABLE accounts (\
             account_id INTEGER PRIMARY KEY, balance INTEGER NOT NULL\
         );\
         CREATE TABLE transactions (\
             txid TEXT NOT NULL PRIMARY KEY,\
             from_account INTEGER NOT NULL REFERENCES accounts(account_id),\
             to_account INTEGER NOT NULL REFERENCES accounts(account_id),\
             amount INTEGER NOT NULL CHECK(amount > 0)\
         );",
        "INSERT INTO accounts VALUES (1, -1), (2, 100);\
         INSERT INTO transactions VALUES ('tx-001', 1, 99, 1);",
    );
    let report = evaluate_snapshot(&snapshot_with_database(database), &["tx-001"]);
    assert_finding(&report, "sqlite-foreign-key-check");
    assert_finding(&report, "sqlite-balance-sum");
    assert_finding(&report, "sqlite-negative-balance");
}

#[test]
fn duplicate_txids_are_detected_even_when_schema_is_mutated() {
    let database = stock_database(
        "CREATE TABLE accounts (\
             account_id INTEGER PRIMARY KEY, balance INTEGER NOT NULL\
         );\
         CREATE TABLE transactions (\
             txid TEXT NOT NULL,\
             from_account INTEGER NOT NULL REFERENCES accounts(account_id),\
             to_account INTEGER NOT NULL REFERENCES accounts(account_id),\
             amount INTEGER NOT NULL CHECK(amount > 0)\
         );",
        "INSERT INTO accounts VALUES (1, 70), (2, 30);\
         INSERT INTO transactions VALUES ('tx-001', 1, 2, 1), ('tx-001', 2, 1, 1);",
    );
    let report = evaluate_snapshot(&snapshot_with_database(database), &["tx-001"]);
    assert_finding(&report, "sqlite-stock-schema");
    assert_finding(&report, "sqlite-txid-unique");
    assert_finding(&report, "sqlite-acknowledged-txids");
}

#[test]
fn expected_acknowledgement_json_is_strict() {
    let snapshot = encode_namespace_snapshot(&snapshot_with_database(valid_database())).unwrap();
    let duplicate = br#"{
        "schema_version":"visa-sqlite-expected-acks-v1",
        "initial_total_balance":100,
        "acknowledged_txids":["tx-001","tx-001"]
    }"#;
    assert_finding(&evaluate(&snapshot, duplicate, b"bank.db"), "expected-txid-duplicate");

    let unknown = br#"{
        "schema_version":"visa-sqlite-expected-acks-v1",
        "initial_total_balance":100,
        "acknowledged_txids":["tx-001"],
        "producer_passed":true
    }"#;
    assert_finding(&evaluate(&snapshot, unknown, b"bank.db"), "expected-acks-json");
}
