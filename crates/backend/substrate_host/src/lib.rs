//! Real host provider for the cooperative Stage 1 handoff profile.
//!
//! Journal, key-value state, authorization policy, ownership, and binding
//! receipts share one SQLite transactional domain. Live timers use host-local
//! [`std::time::Instant`] values which are intentionally never serialized.

mod authority;
mod binding;
mod journal;
mod kv;
mod lease;
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
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use substrate_api::{JournalScope, OperationObservation, ProviderError, ProviderErrorKind};

#[cfg(test)]
mod tests;

const SCHEMA_VERSION: i64 = 3;
const GENERATED_ID_PREFIX: u128 = 0x7669_7361_2d68_6f73_0000_0000_0000_0000;

/// SQLite-backed provider plus process-local timer bindings.
pub struct SqliteProvider {
    pub(crate) connection: Connection,
    pub(crate) scope: JournalScope,
    pub(crate) timers: BTreeMap<Identity, HostTimer>,
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

        Ok(Self { connection, scope, timers: BTreeMap::new(), faults: FaultControl::default() })
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
    AfterKvCommit,
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
    if !matches!(existing_version, 0 | SCHEMA_VERSION) {
        return Err(error(ProviderErrorKind::Integrity, false));
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
                 kind INTEGER NOT NULL CHECK (kind IN (0, 1)),
                 namespace_id BLOB,
                 receipt BLOB NOT NULL,
                 cleaned INTEGER NOT NULL DEFAULT 0 CHECK (cleaned IN (0, 1)),
                 CHECK ((kind = 0 AND namespace_id IS NULL)
                     OR (kind = 1 AND length(namespace_id) = 16)),
                 PRIMARY KEY(snapshot_id, claim_id, claim_generation)
             ) WITHOUT ROWID;
             COMMIT;",
        )
        .map_err(database_error)?;

    if existing_version == 0 {
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
                 'kv_resource', 'kv_entry', 'kv_namespace_availability', 'binding'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if table_count != 10 {
        return Err(error(ProviderErrorKind::Integrity, false));
    }
    Ok(())
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
