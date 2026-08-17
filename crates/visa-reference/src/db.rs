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
                 provider_generation INTEGER NOT NULL CHECK(provider_generation >= 0),
                 rights INTEGER NOT NULL CHECK(rights >= 0),
                 execution_epoch INTEGER NOT NULL CHECK(execution_epoch >= 0),
                 role TEXT NOT NULL CHECK(role IN ('source', 'destination')),
                 active INTEGER NOT NULL CHECK(active IN (0, 1)),
                 fenced INTEGER NOT NULL CHECK(fenced IN (0, 1)),
                 dispatch_open INTEGER NOT NULL CHECK(dispatch_open IN (0, 1)),
                 source_binding_id TEXT,
                 operation_id TEXT
             );

             CREATE TABLE IF NOT EXISTS visa_authority_operations (
                 operation_id TEXT PRIMARY KEY,
                 request_digest BLOB NOT NULL,
                 source_binding_id TEXT NOT NULL,
                 destination_binding_id TEXT,
                 source_owner TEXT NOT NULL,
                 provider_generation INTEGER NOT NULL CHECK(provider_generation >= 0),
                 rights INTEGER NOT NULL CHECK(rights >= 0),
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
                 provider_generation INTEGER NOT NULL CHECK(provider_generation >= 0),
                 rights INTEGER NOT NULL CHECK(rights >= 0),
                 status TEXT NOT NULL,
                 source_epoch INTEGER,
                 destination_epoch INTEGER,
                 core_receipt BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS visa_authority_activation_permits (
                 operation_id TEXT PRIMARY KEY,
                 continuation_id BLOB NOT NULL,
                 snapshot_id BLOB NOT NULL,
                 destination_authority BLOB NOT NULL,
                 destination_value BLOB NOT NULL,
                 destination_binding_id TEXT NOT NULL,
                 authority_commit_digest BLOB NOT NULL,
                 execution_epoch INTEGER NOT NULL CHECK(execution_epoch >= 0),
                 status TEXT NOT NULL,
                 UNIQUE(destination_binding_id, execution_epoch)
             );

             CREATE TABLE IF NOT EXISTS visa_provider_kv (
                 key BLOB PRIMARY KEY,
                 value BLOB NOT NULL,
                 revision INTEGER NOT NULL CHECK(revision >= 0)
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

             CREATE TABLE IF NOT EXISTS visa_runtime_captures (
                 operation_id BLOB PRIMARY KEY,
                 request_digest BLOB NOT NULL,
                 status TEXT NOT NULL CHECK(status IN ('armed', 'captured')),
                 snapshot BLOB,
                 safe_point BLOB,
                 receipt BLOB
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
    Invalid(String),
}

impl std::fmt::Display for ReferenceDatabaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

/// SQLite INTEGER is signed, while authority/provider coordinates use u64.
/// Keep every conversion at the durable boundary checked and fail closed on
/// values that cannot be represented by SQLite.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_unsigned_conversions_fail_closed() {
        assert_eq!(sqlite_to_u64(0, "value").unwrap(), 0);
        assert!(matches!(sqlite_to_u64(-1, "value"), Err(ReferenceDatabaseError::Invalid(_))));
        assert_eq!(u64_to_sqlite(u64::try_from(i64::MAX).unwrap(), "value").unwrap(), i64::MAX);
        assert!(matches!(
            u64_to_sqlite(u64::try_from(i64::MAX).unwrap() + 1, "value"),
            Err(ReferenceDatabaseError::Invalid(_))
        ));
    }

    #[test]
    fn binding_role_is_constrained_by_sqlite() {
        let database = ReferenceDatabase::in_memory().unwrap();
        let connection = database.lock().unwrap();
        let error = connection
            .execute(
                "INSERT INTO visa_authority_bindings
                 (binding_id, owner, provider_generation, rights, execution_epoch, role,
                  active, fenced, dispatch_open)
                 VALUES ('bad', 'owner', 0, 0, 0, 'unknown', 1, 0, 1)",
                [],
            )
            .unwrap_err();
        assert!(matches!(error, rusqlite::Error::SqliteFailure(_, _)));
    }
}
