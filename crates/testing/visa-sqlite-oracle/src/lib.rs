//! Independent native-SQLite oracle for a serialized WASI namespace snapshot.
//!
//! The only vISA input is the verdict-free `NamespaceSnapshot` byte stream.
//! This crate does not depend on a provider, migration runner, receipt, or
//! producer assertion. It validates and materializes the snapshot itself, then
//! asks a bundled native SQLite library to inspect a disposable database copy.

mod namespace;
mod sqlite;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

pub use namespace::{ByteString, DescriptorReport, LockReport, NamespaceReport, PathReport};
use serde::{Deserialize, Serialize};
pub use sqlite::{
    AccountRow, AcknowledgementReport, BalanceReport, ForeignKeyViolation,
    LogicalContentsProjection, LogicalRows, SEMANTIC_PROJECTION_SCHEMA_VERSION, SchemaReport,
    SqliteReport, SqliteSemanticProjection, TransactionReport, TransactionRow,
};
use visa_wasi_protocol::decode_namespace_snapshot;

pub const REPORT_SCHEMA_VERSION: &str = "visa-sqlite-oracle-report-v2";
pub const EXPECTED_ACKS_SCHEMA_VERSION: &str = "visa-sqlite-expected-acks-v1";
const MAX_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;
const MAX_TXID_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedAcks {
    pub schema_version: String,
    pub initial_total_balance: i64,
    pub acknowledged_txids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleFinding {
    pub code: String,
    pub detail: String,
}

impl OracleFinding {
    pub(crate) fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { code: code.into(), detail: detail.into() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSummary {
    pub version: u16,
    pub session_hex: String,
    pub authority_epoch: u64,
    pub mode: String,
    pub barrier: String,
    pub effect_frontier_hex: String,
    pub effects: u64,
    pub objects: u64,
    pub paths: u64,
    pub descriptors: u64,
    pub locks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleReport {
    pub schema_version: String,
    pub accepted: bool,
    pub snapshot: Option<SnapshotSummary>,
    pub namespace: Option<NamespaceReport>,
    pub sqlite: Option<SqliteReport>,
    pub semantic_projection: Option<SqliteSemanticProjection>,
    pub findings: Vec<OracleFinding>,
}

impl OracleReport {
    fn rejected(finding: OracleFinding) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            accepted: false,
            snapshot: None,
            namespace: None,
            sqlite: None,
            semantic_projection: None,
            findings: vec![finding],
        }
    }
}

/// Recomputes the stock workload verdict from snapshot bytes and an external
/// acknowledgement set. `database_path` is a canonical guest-namespace byte
/// path, not a host path.
pub fn evaluate(
    snapshot_bytes: &[u8],
    expected_acks_json: &[u8],
    database_path: &[u8],
) -> OracleReport {
    let expected = match parse_expected_acks(expected_acks_json) {
        Ok(expected) => expected,
        Err(finding) => return OracleReport::rejected(finding),
    };
    if snapshot_bytes.len() > MAX_SNAPSHOT_BYTES {
        return OracleReport::rejected(OracleFinding::new(
            "snapshot-too-large",
            format!(
                "snapshot has {} bytes; the oracle limit is {MAX_SNAPSHOT_BYTES}",
                snapshot_bytes.len()
            ),
        ));
    }
    let snapshot = match decode_namespace_snapshot(snapshot_bytes) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return OracleReport::rejected(OracleFinding::new(
                "snapshot-decode",
                format!("invalid NamespaceSnapshot bytes: {error}"),
            ));
        }
    };
    let summary = namespace::snapshot_summary(&snapshot);
    let mut findings = namespace::validate_snapshot(snapshot_bytes, &snapshot);
    findings.extend(namespace::validate_database_path(&snapshot, database_path));
    if !findings.is_empty() {
        return OracleReport {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            accepted: false,
            snapshot: Some(summary),
            namespace: Some(namespace::namespace_report(&snapshot, database_path)),
            sqlite: None,
            semantic_projection: None,
            findings,
        };
    }

    let materialized = match namespace::materialize(&snapshot, database_path) {
        Ok(materialized) => materialized,
        Err(finding) => {
            return OracleReport {
                schema_version: REPORT_SCHEMA_VERSION.to_owned(),
                accepted: false,
                snapshot: Some(summary),
                namespace: Some(namespace::namespace_report(&snapshot, database_path)),
                sqlite: None,
                semantic_projection: None,
                findings: vec![finding],
            };
        }
    };
    let namespace = materialized.report().clone();
    let sqlite = match sqlite::inspect(materialized.analysis_database(), &expected) {
        Ok(report) => report,
        Err(finding) => {
            return OracleReport {
                schema_version: REPORT_SCHEMA_VERSION.to_owned(),
                accepted: false,
                snapshot: Some(summary),
                namespace: Some(namespace),
                sqlite: None,
                semantic_projection: None,
                findings: vec![finding],
            };
        }
    };
    let semantic_projection = sqlite.semantic_projection();
    findings.extend(sqlite.findings());
    OracleReport {
        schema_version: REPORT_SCHEMA_VERSION.to_owned(),
        accepted: findings.is_empty(),
        snapshot: Some(summary),
        namespace: Some(namespace),
        sqlite: Some(sqlite),
        semantic_projection: Some(semantic_projection),
        findings,
    }
}

/// Materialize the linked namespace represented by a snapshot into `target`.
/// This is an experiment-only raw-reopen primitive: it deliberately exports
/// bytes and paths, not descriptor offsets, locks, authority, or a verdict.
pub fn materialize_raw_namespace(
    snapshot_bytes: &[u8],
    database_path: &[u8],
    target: &std::path::Path,
) -> Result<NamespaceReport, OracleFinding> {
    let snapshot = decode_namespace_snapshot(snapshot_bytes).map_err(|error| {
        OracleFinding::new("snapshot-decode", format!("invalid NamespaceSnapshot bytes: {error}"))
    })?;
    let findings = namespace::validate_snapshot(snapshot_bytes, &snapshot);
    if !findings.is_empty() {
        return Err(findings.into_iter().next().expect("nonempty findings"));
    }
    let materialized = namespace::materialize(&snapshot, database_path)?;
    let root = materialized.namespace_root();
    if target.exists() {
        return Err(OracleFinding::new(
            "raw-export-target-exists",
            "raw namespace target already exists",
        ));
    }
    std::fs::create_dir_all(target).map_err(|error| {
        OracleFinding::new(
            "raw-export-target",
            format!("cannot create raw namespace target: {error}"),
        )
    })?;
    copy_tree(&root, target).map_err(|error| {
        OracleFinding::new("raw-export-copy", format!("cannot export raw namespace: {error}"))
    })?;
    Ok(materialized.report().clone())
}

fn copy_tree(source: &std::path::Path, target: &std::path::Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_dir() {
            std::fs::create_dir(&target_path)?;
            copy_tree(&source_path, &target_path)?;
        } else if metadata.file_type().is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(&source_path)?, &target_path)?;
        } else {
            std::fs::copy(&source_path, &target_path)?;
        }
    }
    Ok(())
}

fn parse_expected_acks(bytes: &[u8]) -> Result<ExpectedAcks, OracleFinding> {
    let expected: ExpectedAcks = serde_json::from_slice(bytes).map_err(|error| {
        OracleFinding::new("expected-acks-json", format!("invalid expected-acks JSON: {error}"))
    })?;
    if expected.schema_version != EXPECTED_ACKS_SCHEMA_VERSION {
        return Err(OracleFinding::new(
            "expected-acks-version",
            format!(
                "expected schema_version {EXPECTED_ACKS_SCHEMA_VERSION:?}, got {:?}",
                expected.schema_version
            ),
        ));
    }
    if expected.initial_total_balance < 0 {
        return Err(OracleFinding::new(
            "expected-balance-negative",
            "initial_total_balance must be nonnegative",
        ));
    }
    let mut unique = BTreeSet::new();
    for txid in &expected.acknowledged_txids {
        if txid.is_empty() || txid.len() > MAX_TXID_BYTES || txid.contains('\0') {
            return Err(OracleFinding::new(
                "expected-txid-invalid",
                format!("acknowledged txid must contain 1..={MAX_TXID_BYTES} non-NUL UTF-8 bytes"),
            ));
        }
        if !unique.insert(txid) {
            return Err(OracleFinding::new(
                "expected-txid-duplicate",
                format!("acknowledged txid {txid:?} appears more than once"),
            ));
        }
    }
    Ok(expected)
}
