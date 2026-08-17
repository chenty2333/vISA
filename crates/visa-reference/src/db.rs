use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::Connection;

/// A SQLite database shared by the reference roles.
///
/// The connection is serialized in-process. SQLite remains the durable
/// boundary; role separation is expressed by table ownership and APIs.
#[derive(Clone)]
pub struct ReferenceDatabase {
    pub(crate) connection: Arc<Mutex<Connection>>,
}

impl fmt::Debug for ReferenceDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ReferenceDatabase").finish_non_exhaustive()
    }
}

impl ReferenceDatabase {
    pub fn in_memory() -> Result<Self, ReferenceDatabaseError> {
        let connection = Connection::open_in_memory()?;
        let database = Self { connection: Arc::new(Mutex::new(connection)) };
        database.initialize()?;
        Ok(database)
    }

    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, ReferenceDatabaseError> {
        let connection = Connection::open(path)?;
        let database = Self { connection: Arc::new(Mutex::new(connection)) };
        database.initialize()?;
        Ok(database)
    }

    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>, ReferenceDatabaseError> {
        self.connection.lock().map_err(|_| ReferenceDatabaseError::Poisoned)
    }

    fn initialize(&self) -> Result<(), ReferenceDatabaseError> {
        let connection = self.lock()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;

             CREATE TABLE IF NOT EXISTS visa_authority_bindings (
                 binding_id TEXT PRIMARY KEY,
                 owner TEXT NOT NULL,
                 provider_generation INTEGER NOT NULL,
                 rights INTEGER NOT NULL,
                 execution_epoch INTEGER NOT NULL,
                 role TEXT NOT NULL,
                 active INTEGER NOT NULL,
                 fenced INTEGER NOT NULL,
                 dispatch_open INTEGER NOT NULL,
                 source_binding_id TEXT,
                 operation_id TEXT
             );

             CREATE TABLE IF NOT EXISTS visa_authority_operations (
                 operation_id TEXT PRIMARY KEY,
                 request_digest BLOB NOT NULL,
                 source_binding_id TEXT NOT NULL,
                 destination_binding_id TEXT,
                 source_owner TEXT NOT NULL,
                 provider_generation INTEGER NOT NULL,
                 rights INTEGER NOT NULL,
                 status TEXT NOT NULL,
                 source_epoch INTEGER,
                 destination_epoch INTEGER
             );

             CREATE TABLE IF NOT EXISTS visa_authority_aborts (
                 operation_id TEXT PRIMARY KEY,
                 request_digest BLOB NOT NULL,
                 source_binding_id TEXT NOT NULL,
                 destination_binding_id TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS visa_authority_commits (
                 operation_id TEXT PRIMARY KEY,
                 preparation_operation_id TEXT NOT NULL,
                 request_digest BLOB NOT NULL,
                 source_binding_id TEXT NOT NULL,
                 destination_binding_id TEXT NOT NULL,
                 source_owner TEXT NOT NULL,
                 provider_generation INTEGER NOT NULL,
                 rights INTEGER NOT NULL,
                 status TEXT NOT NULL,
                 source_epoch INTEGER,
                 destination_epoch INTEGER
             );

             CREATE TABLE IF NOT EXISTS visa_authority_activation_permits (
                 operation_id TEXT PRIMARY KEY,
                 continuation_id BLOB NOT NULL,
                 snapshot_id BLOB NOT NULL,
                 destination_authority BLOB NOT NULL,
                 destination_value BLOB NOT NULL,
                 destination_binding_id TEXT NOT NULL,
                 authority_commit_digest BLOB NOT NULL,
                 execution_epoch INTEGER NOT NULL,
                 status TEXT NOT NULL,
                 UNIQUE(destination_binding_id, execution_epoch)
             );

             CREATE TABLE IF NOT EXISTS visa_provider_kv (
                 key BLOB PRIMARY KEY,
                 value BLOB NOT NULL,
                 revision INTEGER NOT NULL
             );

             CREATE INDEX IF NOT EXISTS visa_authority_bindings_operation
                 ON visa_authority_bindings(operation_id);

             CREATE TABLE IF NOT EXISTS visa_coordinator_records (
                 continuation_id BLOB PRIMARY KEY,
                 lineage_id BLOB NOT NULL,
                 revision INTEGER NOT NULL,
                 payload BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS visa_coordinator_lineages (
                 lineage_id BLOB PRIMARY KEY,
                 head_generation INTEGER NOT NULL,
                 head_state_digest BLOB NOT NULL,
                 active_record_id BLOB
             );
            ",
        )?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ReferenceDatabaseError {
    Sqlite(rusqlite::Error),
    Poisoned,
}

impl std::fmt::Display for ReferenceDatabaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::Poisoned => formatter.write_str("reference database mutex poisoned"),
        }
    }
}

impl std::error::Error for ReferenceDatabaseError {}

impl From<rusqlite::Error> for ReferenceDatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}
