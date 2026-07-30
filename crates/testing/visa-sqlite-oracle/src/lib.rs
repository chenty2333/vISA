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
    AccountRow, AcknowledgementReport, BalanceReport, ForeignKeyViolation, LogicalRows,
    SchemaReport, SqliteReport, TransactionReport, TransactionRow,
};
use visa_wasi_protocol::decode_namespace_snapshot;

pub const REPORT_SCHEMA_VERSION: &str = "visa-sqlite-oracle-report-v1";
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
                findings: vec![finding],
            };
        }
    };
    findings.extend(sqlite.findings());
    OracleReport {
        schema_version: REPORT_SCHEMA_VERSION.to_owned(),
        accepted: findings.is_empty(),
        snapshot: Some(summary),
        namespace: Some(namespace),
        sqlite: Some(sqlite),
        findings,
    }
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
