//! Real host provider for cooperative handoff and versioned resource profiles.
//!
//! Journal, key-value state, authorization policy, ownership, and binding
//! receipts share one SQLite transactional domain. Live timers, regular-file
//! descriptors, peer endpoints, and credential material remain host-local;
//! only canonical logical state and durable provider observations cross the
//! profile boundary.

mod authority;
mod binding;
mod joint;
mod journal;
mod kv;
mod lease;
mod logical_request;
mod regular_file;
mod timer;

use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, Instant},
};

use contract_core::{
    CleanupStatus, EffectOutcome, EffectRequest, EntityRef, Generation, Identity, JournalEntry,
    OperationRecord,
};
#[cfg(any(test, feature = "test-control"))]
pub use logical_request::{LoopbackLogicalPeer, LoopbackLogicalPeerBehavior};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use substrate_api::{JournalScope, OperationObservation, ProviderError, ProviderErrorKind};

#[cfg(test)]
mod tests;

const SCHEMA_VERSION: i64 = 5;
const GENERATED_ID_PREFIX: u128 = 0x7669_7361_2d68_6f73_0000_0000_0000_0000;

/// SQLite-backed provider plus process-local timer bindings.
pub struct SqliteProvider {
    pub(crate) connection: Connection,
    pub(crate) scope: JournalScope,
    pub(crate) timers: BTreeMap<Identity, HostTimer>,
    pub(crate) regular_files: BTreeMap<EntityRef, std::fs::File>,
    pub(crate) logical_credentials: BTreeMap<(contract_core::NodeIdentity, Identity), Vec<u8>>,
    faults: FaultControl,
}

impl SqliteProvider {
    /// Open or create a provider database with crash-safe SQLite settings.
    pub fn open(path: impl AsRef<Path>, scope: JournalScope) -> Result<Self, ProviderError> {
        if scope.node.is_zero() || scope.component.is_zero() {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        let connection = Connection::open(path).map_err(database_error)?;
        connection.busy_timeout(Duration::from_secs(5)).map_err(database_error)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;",
            )
            .map_err(database_error)?;
        initialize_schema(&connection)?;

        Ok(Self {
            connection,
            scope,
            timers: BTreeMap::new(),
            regular_files: BTreeMap::new(),
            logical_credentials: BTreeMap::new(),
            faults: FaultControl::default(),
        })
    }

    #[cfg(any(test, feature = "test-control"))]
    pub fn inject_failure_once(&mut self, point: FaultPoint) {
        self.faults.next = Some(point);
    }

    #[cfg(any(test, feature = "test-control"))]
    pub const fn fault_observation(&self) -> Option<FaultObservation> {
        match self.faults.last_fired {
            Some(point) => Some(FaultObservation { point, count: self.faults.fired_count }),
            None => None,
        }
    }

    pub(crate) fn take_fault(&mut self, point: FaultPoint) -> bool {
        if self.faults.next == Some(point) {
            self.faults.next = None;
            self.faults.last_fired = Some(point);
            self.faults.fired_count = self.faults.fired_count.saturating_add(1);
            true
        } else {
            false
        }
    }

    pub(crate) fn immediate_transaction(
        &mut self,
    ) -> Result<rusqlite::Transaction<'_>, ProviderError> {
        self.connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    BeforeJournalWrite,
    AfterJournalWrite,
    BeforeActivationBundle,
    AfterActivationBundle,
    BeforeCommitBundle,
    AfterCommitBundle,
    BeforeExternalSourceFence,
    AfterExternalSourceFence,
    AfterKvCommit,
    BeforeProfileEffect,
    AfterProfileEffect,
    AfterProfileCommit,
    BeforeLogicalRequestIo,
    AfterRegularFileMutation,
    AfterLogicalRequestSend,
    AfterLogicalRequestCommit,
    AfterLogicalCancelSend,
}

#[cfg(any(test, feature = "test-control"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultObservation {
    pub point: FaultPoint,
    pub count: u64,
}

#[derive(Default)]
struct FaultControl {
    next: Option<FaultPoint>,
    last_fired: Option<FaultPoint>,
    fired_count: u64,
}

pub(crate) struct HostTimer {
    pub resource: EntityRef,
    pub owner: contract_core::NodeIdentity,
    pub epoch: contract_core::LeaseEpoch,
    pub state: HostTimerState,
}

#[derive(Clone, Copy)]
pub(crate) enum HostTimerState {
    Pending { deadline: Instant },
    Suspended { remaining: contract_core::LogicalDurationNanos },
    Completed { evidence: contract_core::EvidenceRef },
    Cancelled { evidence: contract_core::EvidenceRef },
}

fn initialize_schema(connection: &Connection) -> Result<(), ProviderError> {
    let existing_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(database_error)?;
    if !matches!(existing_version, 0 | 3 | 4 | SCHEMA_VERSION) {
        return Err(error(ProviderErrorKind::Integrity, false));
    }
    if existing_version == 0 {
        let existing_objects: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if existing_objects != 0 {
            return Err(error(ProviderErrorKind::Integrity, false));
        }
    }
    if existing_version == 3 {
        migrate_schema_v3(connection)?;
    }
    if existing_version != 0 {
        require_hardened_regular_file_identity_schema(connection)?;
    }
    if matches!(existing_version, 3 | 4) {
        migrate_schema_v4(connection)?;
    }
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS provider_sequence (
                 name TEXT PRIMARY KEY,
                 next_value INTEGER NOT NULL CHECK (next_value > 0)
             ) WITHOUT ROWID;
             INSERT OR IGNORE INTO provider_sequence(name, next_value)
                 VALUES ('portable_identity', 1);

             CREATE TABLE IF NOT EXISTS canonical_journal (
                 node_id BLOB NOT NULL CHECK (length(node_id) = 16),
                 component_id BLOB NOT NULL CHECK (length(component_id) = 16),
                 position BLOB NOT NULL CHECK (length(position) = 8),
                 event_id BLOB NOT NULL CHECK (length(event_id) = 16),
                 entry BLOB NOT NULL,
                 PRIMARY KEY(node_id, component_id, position),
                 UNIQUE(node_id, component_id, event_id)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS provider_operation (
                 operation BLOB NOT NULL UNIQUE CHECK (length(operation) = 16),
                 idempotency_key BLOB NOT NULL UNIQUE CHECK (length(idempotency_key) = 16),
                 request BLOB NOT NULL,
                 outcome BLOB,
                 cleaned INTEGER NOT NULL DEFAULT 0 CHECK (cleaned IN (0, 1)),
                 PRIMARY KEY(operation)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS authority_policy (
                 subject_id BLOB NOT NULL CHECK (length(subject_id) = 16),
                 subject_generation BLOB NOT NULL CHECK (length(subject_generation) = 8),
                 resource_id BLOB NOT NULL CHECK (length(resource_id) = 16),
                 resource_generation BLOB NOT NULL CHECK (length(resource_generation) = 8),
                 allowed_rights INTEGER NOT NULL,
                 PRIMARY KEY(subject_id, subject_generation, resource_id, resource_generation)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS authority_grant (
                 authority_id BLOB NOT NULL CHECK (length(authority_id) = 16),
                 authority_generation BLOB NOT NULL CHECK (length(authority_generation) = 8),
                 parent_id BLOB,
                 parent_generation BLOB,
                 subject_id BLOB NOT NULL CHECK (length(subject_id) = 16),
                 subject_generation BLOB NOT NULL CHECK (length(subject_generation) = 8),
                 resource_id BLOB NOT NULL CHECK (length(resource_id) = 16),
                 resource_generation BLOB NOT NULL CHECK (length(resource_generation) = 8),
                 rights INTEGER NOT NULL,
                 status INTEGER NOT NULL CHECK (status IN (0, 1)),
                 pending INTEGER NOT NULL CHECK (pending IN (0, 1)),
                 usable INTEGER NOT NULL CHECK (usable IN (0, 1)),
                 handoff_id BLOB,
                 snapshot_id BLOB,
                 CHECK ((parent_id IS NULL) = (parent_generation IS NULL)),
                 CHECK ((pending = 0 AND handoff_id IS NULL AND snapshot_id IS NULL)
                     OR (pending = 1 AND length(handoff_id) = 16
                         AND length(snapshot_id) = 16)),
                 CHECK (NOT (pending = 1 AND usable = 1)),
                 PRIMARY KEY(authority_id, authority_generation)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS ownership (
                 resource_id BLOB PRIMARY KEY CHECK (length(resource_id) = 16),
                 resource_generation BLOB NOT NULL CHECK (length(resource_generation) = 8),
                 owner_id BLOB NOT NULL CHECK (length(owner_id) = 16),
                 epoch BLOB NOT NULL CHECK (length(epoch) = 8)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS kv_resource (
                 resource_id BLOB NOT NULL CHECK (length(resource_id) = 16),
                 resource_generation BLOB NOT NULL CHECK (length(resource_generation) = 8),
                 namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 16),
                 PRIMARY KEY(resource_id, resource_generation)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS kv_entry (
                 resource_id BLOB NOT NULL,
                 resource_generation BLOB NOT NULL,
                 key BLOB NOT NULL,
                 value BLOB NOT NULL,
                 version INTEGER NOT NULL CHECK (version > 0),
                 PRIMARY KEY(resource_id, resource_generation, key),
                 FOREIGN KEY(resource_id, resource_generation)
                     REFERENCES kv_resource(resource_id, resource_generation)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS kv_namespace_availability (
                 node_id BLOB NOT NULL CHECK (length(node_id) = 16),
                 namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 16),
                 PRIMARY KEY(node_id, namespace_id)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS binding (
                 snapshot_id BLOB NOT NULL CHECK (length(snapshot_id) = 16),
                 claim_id BLOB NOT NULL CHECK (length(claim_id) = 16),
                 claim_generation BLOB NOT NULL CHECK (length(claim_generation) = 8),
                 kind INTEGER NOT NULL CHECK (kind IN (0, 1, 2)),
                 namespace_id BLOB,
                 receipt BLOB NOT NULL,
                 cleaned INTEGER NOT NULL DEFAULT 0 CHECK (cleaned IN (0, 1)),
                 CHECK ((kind = 0 AND namespace_id IS NULL)
                     OR (kind IN (1, 2) AND length(namespace_id) = 16)),
                 PRIMARY KEY(snapshot_id, claim_id, claim_generation)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS regular_file_namespace_root (
                 node_id BLOB NOT NULL CHECK (length(node_id) = 16),
                 namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 16),
                 root_path BLOB NOT NULL CHECK (length(root_path) > 0),
                 device BLOB NOT NULL CHECK (length(device) = 8),
                 inode BLOB NOT NULL CHECK (length(inode) = 8),
                 btime_seconds BLOB NOT NULL CHECK (length(btime_seconds) = 8),
                 btime_nanoseconds BLOB NOT NULL CHECK (length(btime_nanoseconds) = 4),
                 PRIMARY KEY(node_id, namespace_id)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS regular_file_resource (
                 resource_id BLOB NOT NULL CHECK (length(resource_id) = 16),
                 resource_generation BLOB NOT NULL CHECK (length(resource_generation) = 8),
                 namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 16),
                 device BLOB NOT NULL CHECK (length(device) = 8),
                 inode BLOB NOT NULL CHECK (length(inode) = 8),
                 btime_seconds BLOB NOT NULL CHECK (length(btime_seconds) = 8),
                 btime_nanoseconds BLOB NOT NULL CHECK (length(btime_nanoseconds) = 4),
                 state BLOB NOT NULL,
                 PRIMARY KEY(resource_id, resource_generation),
                 UNIQUE(namespace_id, device, inode, btime_seconds, btime_nanoseconds)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS regular_file_plan (
                 operation BLOB PRIMARY KEY CHECK (length(operation) = 16),
                 plan BLOB NOT NULL,
                 FOREIGN KEY(operation) REFERENCES provider_operation(operation)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS logical_request_resource (
                 resource_id BLOB NOT NULL CHECK (length(resource_id) = 16),
                 resource_generation BLOB NOT NULL CHECK (length(resource_generation) = 8),
                 peer_identity BLOB NOT NULL CHECK (length(peer_identity) > 0),
                 credential_reference BLOB NOT NULL CHECK (length(credential_reference) = 16),
                 PRIMARY KEY(resource_id, resource_generation)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS logical_request_peer (
                 node_id BLOB NOT NULL CHECK (length(node_id) = 16),
                 peer_identity BLOB NOT NULL CHECK (length(peer_identity) > 0),
                 credential_reference BLOB NOT NULL CHECK (length(credential_reference) = 16),
                 endpoint TEXT NOT NULL CHECK (length(endpoint) > 0),
                 PRIMARY KEY(node_id, peer_identity)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS logical_request_ledger (
                 operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
                 record BLOB NOT NULL
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS logical_request_effect (
                 effect_operation BLOB PRIMARY KEY CHECK (length(effect_operation) = 16),
                 logical_operation BLOB NOT NULL CHECK (length(logical_operation) = 16),
                 FOREIGN KEY(effect_operation) REFERENCES provider_operation(operation),
                 FOREIGN KEY(logical_operation) REFERENCES logical_request_ledger(operation_id)
             ) WITHOUT ROWID;
             COMMIT;",
        )
        .map_err(database_error)?;

    if existing_version != SCHEMA_VERSION {
        connection.pragma_update(None, "user_version", SCHEMA_VERSION).map_err(database_error)?;
    }

    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(database_error)?;
    if version != SCHEMA_VERSION {
        return Err(error(ProviderErrorKind::Integrity, false));
    }
    let table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name IN (
                 'provider_sequence', 'canonical_journal', 'provider_operation',
                 'authority_policy', 'authority_grant', 'ownership',
                 'kv_resource', 'kv_entry', 'kv_namespace_availability', 'binding',
                 'regular_file_namespace_root', 'regular_file_resource', 'regular_file_plan',
                 'logical_request_resource', 'logical_request_peer', 'logical_request_ledger',
                 'logical_request_effect'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if table_count != 17 {
        return Err(error(ProviderErrorKind::Integrity, false));
    }
    require_hardened_regular_file_identity_schema(connection)?;
    Ok(())
}

fn require_hardened_regular_file_identity_schema(
    connection: &Connection,
) -> Result<(), ProviderError> {
    const ROOT_COLUMNS: &[(&str, &str, bool, i64)] = &[
        ("node_id", "BLOB", true, 1),
        ("namespace_id", "BLOB", true, 2),
        ("root_path", "BLOB", true, 0),
        ("device", "BLOB", true, 0),
        ("inode", "BLOB", true, 0),
        ("btime_seconds", "BLOB", true, 0),
        ("btime_nanoseconds", "BLOB", true, 0),
    ];
    const RESOURCE_COLUMNS: &[(&str, &str, bool, i64)] = &[
        ("resource_id", "BLOB", true, 1),
        ("resource_generation", "BLOB", true, 2),
        ("namespace_id", "BLOB", true, 0),
        ("device", "BLOB", true, 0),
        ("inode", "BLOB", true, 0),
        ("btime_seconds", "BLOB", true, 0),
        ("btime_nanoseconds", "BLOB", true, 0),
        ("state", "BLOB", true, 0),
    ];
    require_exact_table_columns(connection, "regular_file_namespace_root", ROOT_COLUMNS)?;
    require_exact_table_columns(connection, "regular_file_resource", RESOURCE_COLUMNS)?;

    let mut indexes = connection
        .prepare(
            "SELECT name FROM pragma_index_list('regular_file_resource')
             WHERE \"unique\" = 1",
        )
        .map_err(database_error)?;
    let index_names = indexes
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    let expected_identity =
        ["namespace_id", "device", "inode", "btime_seconds", "btime_nanoseconds"];
    for index_name in index_names {
        let mut columns = connection
            .prepare("SELECT name FROM pragma_index_info(?1) ORDER BY seqno")
            .map_err(database_error)?;
        let names = columns
            .query_map(params![index_name], |row| row.get::<_, String>(0))
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        if names.iter().map(String::as_str).eq(expected_identity) {
            return Ok(());
        }
    }
    Err(error(ProviderErrorKind::Integrity, false))
}

fn require_exact_table_columns(
    connection: &Connection,
    table: &str,
    expected: &[(&str, &str, bool, i64)],
) -> Result<(), ProviderError> {
    let mut statement = connection
        .prepare(
            "SELECT name, type, \"notnull\", pk
             FROM pragma_table_info(?1) ORDER BY cid",
        )
        .map_err(database_error)?;
    let actual = statement
        .query_map(params![table], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    if actual.len() != expected.len()
        || actual.iter().zip(expected).any(|(actual, expected)| {
            actual.0 != expected.0
                || actual.1 != expected.1
                || actual.2 != expected.2
                || actual.3 != expected.3
        })
    {
        return Err(error(ProviderErrorKind::Integrity, false));
    }
    Ok(())
}

fn migrate_schema_v3(connection: &Connection) -> Result<(), ProviderError> {
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             ALTER TABLE binding RENAME TO binding_v3;
             CREATE TABLE binding (
                 snapshot_id BLOB NOT NULL CHECK (length(snapshot_id) = 16),
                 claim_id BLOB NOT NULL CHECK (length(claim_id) = 16),
                 claim_generation BLOB NOT NULL CHECK (length(claim_generation) = 8),
                 kind INTEGER NOT NULL CHECK (kind IN (0, 1, 2)),
                 namespace_id BLOB,
                 receipt BLOB NOT NULL,
                 cleaned INTEGER NOT NULL DEFAULT 0 CHECK (cleaned IN (0, 1)),
                 CHECK ((kind = 0 AND namespace_id IS NULL)
                     OR (kind IN (1, 2) AND length(namespace_id) = 16)),
                 PRIMARY KEY(snapshot_id, claim_id, claim_generation)
             ) WITHOUT ROWID;
             INSERT INTO binding(
                 snapshot_id, claim_id, claim_generation, kind,
                 namespace_id, receipt, cleaned
             )
             SELECT snapshot_id, claim_id, claim_generation, kind,
                    namespace_id, receipt, cleaned
             FROM binding_v3;
             DROP TABLE binding_v3;

             CREATE TABLE regular_file_namespace_root (
                 node_id BLOB NOT NULL CHECK (length(node_id) = 16),
                 namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 16),
                 root_path BLOB NOT NULL CHECK (length(root_path) > 0),
                 device BLOB NOT NULL CHECK (length(device) = 8),
                 inode BLOB NOT NULL CHECK (length(inode) = 8),
                 btime_seconds BLOB NOT NULL CHECK (length(btime_seconds) = 8),
                 btime_nanoseconds BLOB NOT NULL CHECK (length(btime_nanoseconds) = 4),
                 PRIMARY KEY(node_id, namespace_id)
             ) WITHOUT ROWID;
             CREATE TABLE regular_file_resource (
                 resource_id BLOB NOT NULL CHECK (length(resource_id) = 16),
                 resource_generation BLOB NOT NULL CHECK (length(resource_generation) = 8),
                 namespace_id BLOB NOT NULL CHECK (length(namespace_id) = 16),
                 device BLOB NOT NULL CHECK (length(device) = 8),
                 inode BLOB NOT NULL CHECK (length(inode) = 8),
                 btime_seconds BLOB NOT NULL CHECK (length(btime_seconds) = 8),
                 btime_nanoseconds BLOB NOT NULL CHECK (length(btime_nanoseconds) = 4),
                 state BLOB NOT NULL,
                 PRIMARY KEY(resource_id, resource_generation),
                 UNIQUE(namespace_id, device, inode, btime_seconds, btime_nanoseconds)
             ) WITHOUT ROWID;
             CREATE TABLE regular_file_plan (
                 operation BLOB PRIMARY KEY CHECK (length(operation) = 16),
                 plan BLOB NOT NULL,
                 FOREIGN KEY(operation) REFERENCES provider_operation(operation)
             ) WITHOUT ROWID;
             PRAGMA user_version = 4;
             COMMIT;",
        )
        .map_err(database_error)
}

fn migrate_schema_v4(connection: &Connection) -> Result<(), ProviderError> {
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE logical_request_resource (
                 resource_id BLOB NOT NULL CHECK (length(resource_id) = 16),
                 resource_generation BLOB NOT NULL CHECK (length(resource_generation) = 8),
                 peer_identity BLOB NOT NULL CHECK (length(peer_identity) > 0),
                 credential_reference BLOB NOT NULL CHECK (length(credential_reference) = 16),
                 PRIMARY KEY(resource_id, resource_generation)
             ) WITHOUT ROWID;
             CREATE TABLE logical_request_peer (
                 node_id BLOB NOT NULL CHECK (length(node_id) = 16),
                 peer_identity BLOB NOT NULL CHECK (length(peer_identity) > 0),
                 credential_reference BLOB NOT NULL CHECK (length(credential_reference) = 16),
                 endpoint TEXT NOT NULL CHECK (length(endpoint) > 0),
                 PRIMARY KEY(node_id, peer_identity)
             ) WITHOUT ROWID;
             CREATE TABLE logical_request_ledger (
                 operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
                 record BLOB NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE logical_request_effect (
                 effect_operation BLOB PRIMARY KEY CHECK (length(effect_operation) = 16),
                 logical_operation BLOB NOT NULL CHECK (length(logical_operation) = 16),
                 FOREIGN KEY(effect_operation) REFERENCES provider_operation(operation),
                 FOREIGN KEY(logical_operation) REFERENCES logical_request_ledger(operation_id)
             ) WITHOUT ROWID;
             PRAGMA user_version = 5;
             COMMIT;",
        )
        .map_err(database_error)
}

pub(crate) fn database_error(source: rusqlite::Error) -> ProviderError {
    match source {
        rusqlite::Error::SqliteFailure(ref failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            error(ProviderErrorKind::Unavailable, true)
        }
        _ => error(ProviderErrorKind::Storage, false),
    }
}

pub(crate) const fn error(kind: ProviderErrorKind, retryable: bool) -> ProviderError {
    ProviderError::new(kind, retryable)
}

pub(crate) fn serialize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ProviderError> {
    serde_json::to_vec(value).map_err(|_| error(ProviderErrorKind::Integrity, false))
}

pub(crate) fn deserialize<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, ProviderError> {
    serde_json::from_slice(bytes).map_err(|_| error(ProviderErrorKind::Integrity, false))
}

pub(crate) const fn number(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub(crate) fn decode_number(bytes: Vec<u8>) -> Result<u64, rusqlite::Error> {
    let value: [u8; 8] = bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(u64::from_be_bytes(value))
}

pub(crate) fn decode_identity(bytes: Vec<u8>) -> Result<Identity, rusqlite::Error> {
    let value: [u8; 16] = bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(Identity::from_bytes(value))
}

pub(crate) fn next_identity(connection: &Connection) -> Result<Identity, ProviderError> {
    let next: i64 = connection
        .query_row(
            "UPDATE provider_sequence
             SET next_value = next_value + 1
             WHERE name = 'portable_identity'
             RETURNING next_value - 1",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    let next = u64::try_from(next).map_err(|_| error(ProviderErrorKind::Storage, false))?;
    Ok(Identity::from_u128(GENERATED_ID_PREFIX | u128::from(next)))
}

pub(crate) fn effect_evidence(
    connection: &Connection,
    request: &EffectRequest,
    result: &contract_core::EffectResult,
) -> Result<contract_core::EvidenceRef, ProviderError> {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    digest.update(serialize(request)?);
    digest.update(serialize(result)?);
    let digest: [u8; 32] = digest.finalize().into();
    Ok(contract_core::EvidenceRef {
        identity: next_identity(connection)?,
        kind: contract_core::EvidenceKind::EffectOutcome,
        digest: contract_core::Digest::from_bytes(digest),
    })
}

pub(crate) fn load_operation_by_identity(
    connection: &Connection,
    operation: Identity,
) -> Result<Option<OperationObservation>, ProviderError> {
    connection
        .query_row(
            "SELECT request, outcome, cleaned
             FROM provider_operation WHERE operation = ?1",
            params![operation.0.as_slice()],
            decode_operation_row,
        )
        .optional()
        .map_err(database_error)
}

pub(crate) fn load_operation_by_idempotency(
    connection: &Connection,
    idempotency_key: contract_core::IdempotencyKey,
) -> Result<Option<OperationObservation>, ProviderError> {
    connection
        .query_row(
            "SELECT request, outcome, cleaned
             FROM provider_operation WHERE idempotency_key = ?1",
            params![idempotency_key.0.as_slice()],
            decode_operation_row,
        )
        .optional()
        .map_err(database_error)
}

fn decode_operation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationObservation> {
    let request: Vec<u8> = row.get(0)?;
    let outcome: Option<Vec<u8>> = row.get(1)?;
    let cleaned: bool = row.get(2)?;
    let request: EffectRequest = serde_json::from_slice(&request).map_err(|source| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(source))
    })?;
    let outcome =
        outcome.map(|bytes| serde_json::from_slice(&bytes)).transpose().map_err(|source| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Blob,
                Box::new(source),
            )
        })?;
    Ok(OperationObservation {
        record: OperationRecord {
            request,
            outcome,
            cleanup: if cleaned { CleanupStatus::Cleaned } else { CleanupStatus::Pending },
        },
    })
}

pub(crate) fn ensure_intent(
    connection: &Connection,
    request: &EffectRequest,
) -> Result<OperationObservation, ProviderError> {
    let Some(entry) = load_operation_by_identity(connection, request.operation)? else {
        return Err(error(ProviderErrorKind::NotFound, false));
    };
    if entry.record.request != *request {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    Ok(entry)
}

pub(crate) fn write_outcome(
    connection: &Connection,
    operation: Identity,
    outcome: &EffectOutcome,
) -> Result<OperationObservation, ProviderError> {
    let existing = load_operation_by_identity(connection, operation)?
        .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;
    if let Some(current) = &existing.record.outcome {
        return if current == outcome {
            Ok(existing)
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    connection
        .execute(
            "UPDATE provider_operation SET outcome = ?2 WHERE operation = ?1",
            params![operation.0.as_slice(), serialize(outcome)?],
        )
        .map_err(database_error)?;
    load_operation_by_identity(connection, operation)?
        .ok_or_else(|| error(ProviderErrorKind::Storage, false))
}

pub(crate) fn write_reconciled_outcome(
    connection: &Connection,
    operation: Identity,
    outcome: &EffectOutcome,
) -> Result<OperationObservation, ProviderError> {
    if outcome.is_indeterminate() {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    let existing = load_operation_by_identity(connection, operation)?
        .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;
    match existing.record.outcome.as_ref() {
        Some(current) if current == outcome => return Ok(existing),
        Some(current) if current.is_indeterminate() => {}
        None => {}
        Some(_) => return Err(error(ProviderErrorKind::Conflict, false)),
    }
    connection
        .execute(
            "UPDATE provider_operation SET outcome = ?2 WHERE operation = ?1",
            params![operation.0.as_slice(), serialize(outcome)?],
        )
        .map_err(database_error)?;
    load_operation_by_identity(connection, operation)?
        .ok_or_else(|| error(ProviderErrorKind::Storage, false))
}

pub(crate) fn load_canonical_entry(
    connection: &Connection,
    scope: JournalScope,
    position: contract_core::JournalPosition,
) -> Result<Option<JournalEntry>, ProviderError> {
    let bytes = connection
        .query_row(
            "SELECT entry FROM canonical_journal
             WHERE node_id = ?1 AND component_id = ?2 AND position = ?3",
            params![scope.node.0.0.as_slice(), scope.component.0.as_slice(), number(position.0)],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(database_error)?;
    bytes.map(|value| deserialize(&value)).transpose()
}

pub(crate) fn generation(value: Generation) -> [u8; 8] {
    number(value.0)
}
