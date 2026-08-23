//! Shared SQLite opening for the reference vertical.
//!
//! SQLite is only a convenient host for the first vertical. Its tables are
//! intentionally partitioned by owner: continuation records, binding
//! authority, and the KV provider never read each other's projections.

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::Connection;

#[derive(Clone)]
pub struct ReferenceDatabase {
    connection: Arc<Mutex<Connection>>,
}

impl fmt::Debug for ReferenceDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ReferenceDatabase").finish_non_exhaustive()
    }
}

impl ReferenceDatabase {
    pub fn in_memory() -> Result<Self, ReferenceDatabaseError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReferenceDatabaseError> {
        Self::from_connection(Connection::open(path)?)
    }

    fn from_connection(connection: Connection) -> Result<Self, ReferenceDatabaseError> {
        let database = Self { connection: Arc::new(Mutex::new(connection)) };
        database.initialize()?;
        Ok(database)
    }

    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>, ReferenceDatabaseError> {
        self.connection.lock().map_err(|_| ReferenceDatabaseError::Poisoned)
    }

    fn initialize(&self) -> Result<(), ReferenceDatabaseError> {
        self.lock()?.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;

             -- Continuation-store ownership.
             CREATE TABLE IF NOT EXISTS visa_store_records (
                 continuation_id BLOB PRIMARY KEY NOT NULL CHECK(length(continuation_id) = 16),
                 lineage_id BLOB NOT NULL CHECK(length(lineage_id) = 16),
                 phase TEXT NOT NULL CHECK(phase IN ('capturing', 'captured', 'aborted')),
                 payload BLOB NOT NULL CHECK(length(payload) <= 1048576)
             );
             CREATE TABLE IF NOT EXISTS visa_store_lineages (
                 lineage_id BLOB PRIMARY KEY NOT NULL CHECK(length(lineage_id) = 16),
                 semantic_domain_id BLOB NOT NULL CHECK(length(semantic_domain_id) = 16),
                 semantic_contract_digest BLOB NOT NULL CHECK(length(semantic_contract_digest) = 32),
                 semantic_artifact_digest BLOB NOT NULL CHECK(length(semantic_artifact_digest) = 32),
                 head_generation INTEGER NOT NULL CHECK(head_generation >= 0),
                 head_state_digest BLOB NOT NULL CHECK(length(head_state_digest) = 32),
                 active_continuation BLOB CHECK(active_continuation IS NULL OR length(active_continuation) = 16)
             );

             -- Binding-authority ownership. Receipts are retained by exact
             -- operation id and never inferred from a binding's current view.
             CREATE TABLE IF NOT EXISTS visa_authority_bindings (
                 binding_id TEXT PRIMARY KEY NOT NULL,
                 owner TEXT NOT NULL,
                 generation INTEGER NOT NULL CHECK(generation >= 0),
                 rights INTEGER NOT NULL CHECK(rights >= 0),
                 epoch INTEGER NOT NULL CHECK(epoch >= 0),
                 role TEXT NOT NULL CHECK(role IN ('source', 'destination')),
                 active INTEGER NOT NULL CHECK(active IN (0, 1)),
                 fenced INTEGER NOT NULL CHECK(fenced IN (0, 1)),
                 dispatch_open INTEGER NOT NULL CHECK(dispatch_open IN (0, 1)),
                 operation_id BLOB CHECK(operation_id IS NULL OR length(operation_id) = 16),
                 source_binding_id TEXT,
                 phase TEXT NOT NULL CHECK(phase IN ('source', 'prepared', 'committed', 'aborted'))
             );
             CREATE TABLE IF NOT EXISTS visa_authority_operations (
                 operation_id BLOB PRIMARY KEY NOT NULL CHECK(length(operation_id) = 16),
                 kind TEXT NOT NULL CHECK(kind IN ('prepare', 'commit', 'abort', 'permit')),
                 request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                 outcome TEXT NOT NULL CHECK(outcome IN ('applied', 'rejected')),
                 receipt BLOB CHECK(receipt IS NULL OR length(receipt) <= 65536),
                 receipt_digest BLOB CHECK(receipt_digest IS NULL OR length(receipt_digest) = 32),
                 source_binding_id TEXT,
                 destination_binding_id TEXT,
                 rejection TEXT CHECK(rejection IS NULL OR length(rejection) <= 4096),
                 CHECK((outcome = 'applied' AND receipt IS NOT NULL AND receipt_digest IS NOT NULL AND rejection IS NULL)
                    OR (outcome = 'rejected' AND receipt IS NULL AND receipt_digest IS NULL AND rejection IS NOT NULL))
             );
             CREATE TABLE IF NOT EXISTS visa_authority_permits (
                 operation_id BLOB PRIMARY KEY NOT NULL,
                 destination_binding_id TEXT NOT NULL,
                 execution_epoch INTEGER NOT NULL CHECK(execution_epoch >= 0),
                 receipt_digest BLOB NOT NULL,
                 UNIQUE(destination_binding_id, execution_epoch)
             );

             -- Provider ownership. Values have no authority or continuation
             -- columns; every business operation checks a host-local binding.
             CREATE TABLE IF NOT EXISTS visa_provider_kv (
                 key BLOB PRIMARY KEY NOT NULL,
                 value BLOB NOT NULL,
                 revision INTEGER NOT NULL CHECK(revision >= 0)
             );
             CREATE INDEX IF NOT EXISTS visa_authority_bindings_operation
                 ON visa_authority_bindings(operation_id);
             CREATE UNIQUE INDEX IF NOT EXISTS visa_authority_prepare_receipt
                 ON visa_authority_operations(receipt_digest)
                 WHERE kind = 'prepare' AND outcome = 'applied';",
        )?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ReferenceDatabaseError {
    Sqlite(rusqlite::Error),
    Poisoned,
    Invalid(String),
}

impl fmt::Display for ReferenceDatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::Poisoned => formatter.write_str("reference database mutex poisoned"),
            Self::Invalid(message) => {
                write!(formatter, "invalid reference database value: {message}")
            }
        }
    }
}

impl std::error::Error for ReferenceDatabaseError {}

impl From<rusqlite::Error> for ReferenceDatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub(crate) fn u64_to_sqlite(value: u64, field: &str) -> Result<i64, ReferenceDatabaseError> {
    i64::try_from(value).map_err(|_| {
        ReferenceDatabaseError::Invalid(format!("{field}={value} exceeds SQLite INTEGER range"))
    })
}

pub(crate) fn sqlite_to_u64(value: i64, field: &str) -> Result<u64, ReferenceDatabaseError> {
    u64::try_from(value)
        .map_err(|_| ReferenceDatabaseError::Invalid(format!("{field}={value} is negative")))
}

pub(crate) fn sqlite_bool(value: i64, field: &str) -> Result<bool, ReferenceDatabaseError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        other => {
            Err(ReferenceDatabaseError::Invalid(format!("{field}={other} is not a SQLite boolean")))
        }
    }
}
