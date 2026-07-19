//! Durable identity and process-generation state for one vISA agent role.
//!
//! This crate owns neither effect admission nor ownership decisions.  It only
//! makes the stable agent identity and the live process incarnation durable
//! enough for the local RPC admission boundary to reject stale or substituted
//! callers.  The publication/open split is intentional:
//!
//! * [`publish_new`] is a bootstrap/cohort operation and leaves generation zero;
//! * [`audit_unstarted`] verifies that a store is exact without advancing it;
//! * [`AgentStore::reopen_existing`] is the runtime operation and advances the
//!   process generation transactionally.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior, params};
use visa_durable_sqlite::{
    DatabaseGuard, DurableStoreError, StoreLock, checkpoint_truncate,
    cleanup_owned_initialization_files, ensure_private_parent, ensure_sqlite_sidecars_absent,
    initialization_path, publish_noreplace, sync_file, sync_parent_directory,
};
use visa_local_rpc::{
    WireValidation,
    common::{AgentBinding, AgentRole, ProcessNonce},
};

const SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x5641_4745;
const SQLITE_PAGE_SIZE: i64 = 4096;

const AGENT_META_TABLE_SQL: &str = "CREATE TABLE agent_meta (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 product_major INTEGER NOT NULL CHECK(product_major = 0),
                 product_minor INTEGER NOT NULL CHECK(product_minor = 1),
                 product_patch INTEGER NOT NULL CHECK(product_patch = 0),
                 cohort BLOB NOT NULL CHECK(length(cohort) = 16),
                 boot BLOB NOT NULL CHECK(length(boot) = 16),
                 runtime_session BLOB NOT NULL CHECK(length(runtime_session) = 16),
                 role INTEGER NOT NULL CHECK(role IN (0, 1)),
                 logical_incarnation BLOB NOT NULL CHECK(length(logical_incarnation) = 16),
                 process_generation INTEGER NOT NULL CHECK(process_generation >= 0),
                 last_process_nonce BLOB NOT NULL CHECK(length(last_process_nonce) = 16)
             ) STRICT";

const PROCESS_INSTANCE_TABLE_SQL: &str = "CREATE TABLE process_instance (
                 process_generation INTEGER PRIMARY KEY CHECK(process_generation > 0),
                 process_nonce BLOB NOT NULL UNIQUE CHECK(length(process_nonce) = 16)
             ) STRICT";

const SCHEMA_TABLES: [(&str, &str); 2] =
    [("agent_meta", AGENT_META_TABLE_SQL), ("process_instance", PROCESS_INSTANCE_TABLE_SQL)];

/// Errors returned by the agent store.  The variants intentionally do not
/// expose SQLite details to callers: a malformed or substituted store is
/// always handled as a closed admission boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentStoreError {
    InvalidRequest,
    StoreBusy,
    StoreMismatch,
    Integrity,
    Storage,
}

impl From<DurableStoreError> for AgentStoreError {
    fn from(error: DurableStoreError) -> Self {
        match error {
            DurableStoreError::Busy => Self::StoreBusy,
            DurableStoreError::AlreadyExists
            | DurableStoreError::Missing
            | DurableStoreError::Insecure
            | DurableStoreError::NotSqlite
            | DurableStoreError::SidecarExists => Self::StoreMismatch,
            DurableStoreError::InvalidPath | DurableStoreError::Integrity => Self::Integrity,
            DurableStoreError::Io(_) | DurableStoreError::Sqlite(_) => Self::Storage,
        }
    }
}

/// The stable identity persisted in one role's store.
pub use visa_local_rpc::common::StableAgentIdentity;

/// The live process binding allocated by [`AgentStore::reopen_existing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentProcessBinding {
    pub stable_identity: StableAgentIdentity,
    pub process_nonce: ProcessNonce,
    pub process_generation: u64,
}

impl AgentProcessBinding {
    pub const fn as_wire(self) -> AgentBinding {
        self.stable_identity.binding(self.process_nonce, self.process_generation)
    }
}

/// Result of an audit that deliberately does not allocate a process generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentStoreAudit {
    pub stable_identity: StableAgentIdentity,
    pub process_generation: u64,
}

/// An opened agent store.  The lock and database descriptor remain held for
/// the lifetime of the process so a second runtime cannot advance the same
/// role concurrently.
pub struct AgentStore {
    _connection: Connection,
    _database_guard: DatabaseGuard,
    _lock: StoreLock,
    binding: AgentProcessBinding,
}

impl AgentStore {
    /// Reopens an already published store and allocates one fresh process
    /// generation.  This operation never creates, resets, adopts, or relabels
    /// a path.
    pub fn reopen_existing(
        database_path: impl AsRef<Path>,
        expected_identity: StableAgentIdentity,
        process_nonce: ProcessNonce,
    ) -> Result<Self, AgentStoreError> {
        validate_identity(expected_identity)?;
        validate_process_nonce(process_nonce)?;
        let database_path = database_path.as_ref();
        ensure_private_parent(database_path).map_err(AgentStoreError::from)?;
        let lock = StoreLock::acquire(lock_path(database_path)).map_err(AgentStoreError::from)?;
        let database_guard =
            DatabaseGuard::open_existing(database_path).map_err(AgentStoreError::from)?;
        let connection = open_connection(database_path)?;
        configure_session(&connection)?;
        audit_schema(&connection)?;
        let stored_identity = load_identity(&connection)?;
        if stored_identity != expected_identity {
            return Err(AgentStoreError::StoreMismatch);
        }
        audit_process_history(&connection)?;
        let process_generation = advance_process_generation(&connection, process_nonce)?;
        let binding = AgentProcessBinding {
            stable_identity: stored_identity,
            process_nonce,
            process_generation,
        };
        sync_file(database_guard.file()).map_err(AgentStoreError::from)?;
        sync_parent_directory(database_path).map_err(AgentStoreError::from)?;
        Ok(Self { _connection: connection, _database_guard: database_guard, _lock: lock, binding })
    }

    pub const fn binding(&self) -> AgentProcessBinding {
        self.binding
    }

    pub const fn wire_binding(&self) -> AgentBinding {
        self.binding.as_wire()
    }
}

/// Publishes a new generation-zero store with the exact stable identity.
///
/// `initialization_nonce` identifies this one bootstrap attempt and is used
/// only for the temporary filename. It is not a process generation and is not
/// persisted as a live process nonce.
pub fn publish_new(
    database_path: impl AsRef<Path>,
    stable_identity: StableAgentIdentity,
    initialization_nonce: ProcessNonce,
) -> Result<(), AgentStoreError> {
    validate_identity(stable_identity)?;
    validate_process_nonce(initialization_nonce)?;
    let database_path = database_path.as_ref();
    ensure_private_parent(database_path).map_err(AgentStoreError::from)?;
    let _lock = StoreLock::acquire(lock_path(database_path)).map_err(AgentStoreError::from)?;
    ensure_sqlite_sidecars_absent(database_path).map_err(AgentStoreError::from)?;
    let temporary_path = initialization_path(database_path, initialization_nonce.0);
    ensure_sqlite_sidecars_absent(&temporary_path).map_err(AgentStoreError::from)?;
    let database_guard =
        DatabaseGuard::create_new(&temporary_path).map_err(AgentStoreError::from)?;
    let result = (|| {
        let mut connection = open_connection(&temporary_path)?;
        configure_session(&connection)?;
        initialize_storage_mode(&connection)?;
        initialize_schema(&mut connection, stable_identity)?;
        audit_schema(&connection)?;
        if load_identity(&connection)? != stable_identity
            || audit_process_history(&connection)? != 0
        {
            return Err(AgentStoreError::Integrity);
        }
        checkpoint_truncate(&connection).map_err(AgentStoreError::from)?;
        connection.close().map_err(|_| AgentStoreError::Storage)?;
        ensure_sqlite_sidecars_absent(&temporary_path).map_err(AgentStoreError::from)?;
        ensure_sqlite_sidecars_absent(database_path).map_err(AgentStoreError::from)?;
        publish_noreplace(&temporary_path, database_path, database_guard.file())
            .map_err(AgentStoreError::from)
    })();
    if result.is_err() {
        cleanup_owned_initialization_files(&temporary_path, database_guard.file());
    }
    result
}

/// Audits an existing generation-zero or previously-run store without
/// allocating a process generation.  This is the operation used by cohort
/// bootstrap before the active manifest is published.
pub fn audit_unstarted(
    database_path: impl AsRef<Path>,
    expected_identity: StableAgentIdentity,
) -> Result<AgentStoreAudit, AgentStoreError> {
    validate_identity(expected_identity)?;
    let database_path = database_path.as_ref();
    ensure_private_parent(database_path).map_err(AgentStoreError::from)?;
    let _lock = StoreLock::acquire(lock_path(database_path)).map_err(AgentStoreError::from)?;
    let database_guard =
        DatabaseGuard::open_existing(database_path).map_err(AgentStoreError::from)?;
    let connection = open_connection(database_path)?;
    configure_session(&connection)?;
    audit_schema(&connection)?;
    let stored_identity = load_identity(&connection)?;
    if stored_identity != expected_identity {
        return Err(AgentStoreError::StoreMismatch);
    }
    let process_generation = audit_process_history(&connection)?;
    sync_file(database_guard.file()).map_err(AgentStoreError::from)?;
    Ok(AgentStoreAudit { stable_identity: stored_identity, process_generation })
}

fn validate_identity(identity: StableAgentIdentity) -> Result<(), AgentStoreError> {
    identity.validate().map_err(|_| AgentStoreError::InvalidRequest)
}

fn validate_process_nonce(nonce: ProcessNonce) -> Result<(), AgentStoreError> {
    nonce.validate().map_err(|_| AgentStoreError::InvalidRequest)
}

fn lock_path(database_path: &Path) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn open_connection(database_path: &Path) -> Result<Connection, AgentStoreError> {
    Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| AgentStoreError::Storage)
}

fn configure_session(connection: &Connection) -> Result<(), AgentStoreError> {
    connection.busy_timeout(Duration::from_secs(5)).map_err(|_| AgentStoreError::Storage)?;
    connection
        .execute_batch(
            "PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA wal_autocheckpoint = 1000;",
        )
        .map_err(|_| AgentStoreError::Storage)?;
    if pragma_i64(connection, "synchronous")? != 2
        || pragma_i64(connection, "foreign_keys")? != 1
        || pragma_i64(connection, "trusted_schema")? != 0
    {
        return Err(AgentStoreError::Integrity);
    }
    Ok(())
}

fn initialize_storage_mode(connection: &Connection) -> Result<(), AgentStoreError> {
    connection
        .pragma_update(None, "page_size", SQLITE_PAGE_SIZE)
        .map_err(|_| AgentStoreError::Storage)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|_| AgentStoreError::Storage)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(AgentStoreError::Integrity);
    }
    if pragma_i64(connection, "page_size")? != SQLITE_PAGE_SIZE {
        return Err(AgentStoreError::Integrity);
    }
    Ok(())
}

fn initialize_schema(
    connection: &mut Connection,
    identity: StableAgentIdentity,
) -> Result<(), AgentStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sqlite_error)?;
    for (_, sql) in SCHEMA_TABLES {
        transaction.execute_batch(sql).map_err(|_| AgentStoreError::Storage)?;
    }
    transaction
        .execute(
            "INSERT INTO agent_meta(
                 singleton, product_major, product_minor, product_patch,
                 cohort, boot, runtime_session, role, logical_incarnation,
                 process_generation, last_process_nonce
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
            params![
                identity.product_version.major,
                identity.product_version.minor,
                identity.product_version.patch,
                identity.cohort.0.as_slice(),
                identity.boot.0.as_slice(),
                identity.runtime_session.0.as_slice(),
                role_to_i64(identity.role),
                identity.logical_incarnation.0.as_slice(),
                [0_u8; 16].as_slice(),
            ],
        )
        .map_err(|_| AgentStoreError::Storage)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|_| AgentStoreError::Storage)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| AgentStoreError::Storage)?;
    transaction.commit().map_err(map_sqlite_error)
}

fn audit_schema(connection: &Connection) -> Result<(), AgentStoreError> {
    if pragma_i64(connection, "application_id")? != APPLICATION_ID
        || pragma_i64(connection, "user_version")? != SCHEMA_VERSION
        || !pragma_string(connection, "journal_mode")?.eq_ignore_ascii_case("wal")
        || pragma_i64(connection, "page_size")? != SQLITE_PAGE_SIZE
    {
        return Err(AgentStoreError::StoreMismatch);
    }
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|_| AgentStoreError::Storage)?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| AgentStoreError::Storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AgentStoreError::Storage)?;
    if objects.len() != SCHEMA_TABLES.len()
        || objects.iter().any(|(kind, name, table_name, sql)| {
            kind != "table"
                || name != table_name
                || SCHEMA_TABLES
                    .iter()
                    .find(|(expected, _)| name == expected)
                    .is_none_or(|(_, expected_sql)| sql != expected_sql)
        })
    {
        return Err(AgentStoreError::Integrity);
    }
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| AgentStoreError::Storage)?;
    if quick_check != "ok" {
        return Err(AgentStoreError::Integrity);
    }
    Ok(())
}

fn load_identity(connection: &Connection) -> Result<StableAgentIdentity, AgentStoreError> {
    let row = connection
        .query_row(
            "SELECT product_major, product_minor, product_patch, cohort, boot,
                    runtime_session, role, logical_incarnation
             FROM agent_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .map_err(|_| AgentStoreError::Integrity)?;
    let identity = StableAgentIdentity {
        product_version: visa_local_rpc::common::ProductVersion {
            major: u16::try_from(row.0).map_err(|_| AgentStoreError::Integrity)?,
            minor: u16::try_from(row.1).map_err(|_| AgentStoreError::Integrity)?,
            patch: u16::try_from(row.2).map_err(|_| AgentStoreError::Integrity)?,
        },
        cohort: visa_local_rpc::common::CohortId(array16(&row.3)?),
        boot: visa_local_rpc::common::BootId(array16(&row.4)?),
        runtime_session: visa_local_rpc::common::RuntimeSessionId(array16(&row.5)?),
        role: role_from_i64(row.6)?,
        logical_incarnation: visa_local_rpc::common::LogicalIncarnation(array16(&row.7)?),
    };
    validate_identity(identity)?;
    Ok(identity)
}

fn audit_process_history(connection: &Connection) -> Result<u64, AgentStoreError> {
    let (generation, last_nonce): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT process_generation, last_process_nonce
             FROM agent_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| AgentStoreError::Integrity)?;
    let generation = u64::try_from(generation).map_err(|_| AgentStoreError::Integrity)?;
    let last_nonce = array16(&last_nonce)?;
    let mut statement = connection
        .prepare(
            "SELECT process_generation, process_nonce
             FROM process_instance ORDER BY process_generation",
        )
        .map_err(|_| AgentStoreError::Storage)?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)))
        .map_err(|_| AgentStoreError::Storage)?;
    let mut expected = 1_u64;
    let mut previous_nonce = [0_u8; 16];
    let mut count = 0_u64;
    for row in rows {
        let (stored_generation, nonce) = row.map_err(|_| AgentStoreError::Storage)?;
        let stored_generation =
            u64::try_from(stored_generation).map_err(|_| AgentStoreError::Integrity)?;
        let nonce = array16(&nonce)?;
        if stored_generation != expected || nonce == [0; 16] || nonce == previous_nonce {
            return Err(AgentStoreError::Integrity);
        }
        previous_nonce = nonce;
        expected = expected.checked_add(1).ok_or(AgentStoreError::Integrity)?;
        count = count.checked_add(1).ok_or(AgentStoreError::Integrity)?;
    }
    if count != generation {
        return Err(AgentStoreError::Integrity);
    }
    if generation == 0 {
        if last_nonce != [0; 16] {
            return Err(AgentStoreError::Integrity);
        }
    } else if last_nonce != previous_nonce {
        return Err(AgentStoreError::Integrity);
    }
    Ok(generation)
}

fn advance_process_generation(
    connection: &Connection,
    process_nonce: ProcessNonce,
) -> Result<u64, AgentStoreError> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
        .map_err(map_sqlite_error)?;
    let (current, last_nonce): (i64, Vec<u8>) = transaction
        .query_row(
            "SELECT process_generation, last_process_nonce
             FROM agent_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| AgentStoreError::Storage)?;
    let current = u64::try_from(current).map_err(|_| AgentStoreError::Integrity)?;
    if array16(&last_nonce)? == process_nonce.0 {
        return Err(AgentStoreError::StoreMismatch);
    }
    let next = current.checked_add(1).ok_or(AgentStoreError::Integrity)?;
    transaction
        .execute(
            "INSERT INTO process_instance(process_generation, process_nonce)
             VALUES (?1, ?2)",
            params![
                i64::try_from(next).map_err(|_| AgentStoreError::Integrity)?,
                process_nonce.0.as_slice()
            ],
        )
        .map_err(map_process_insert_error)?;
    let changed = transaction
        .execute(
            "UPDATE agent_meta SET process_generation = ?1, last_process_nonce = ?2
             WHERE singleton = 1 AND process_generation = ?3",
            params![
                i64::try_from(next).map_err(|_| AgentStoreError::Integrity)?,
                process_nonce.0.as_slice(),
                i64::try_from(current).map_err(|_| AgentStoreError::Integrity)?,
            ],
        )
        .map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(AgentStoreError::Integrity);
    }
    transaction.commit().map_err(map_sqlite_error)?;
    Ok(next)
}

fn role_to_i64(role: AgentRole) -> i64 {
    match role {
        AgentRole::Source => 0,
        AgentRole::Destination => 1,
    }
}

fn role_from_i64(role: i64) -> Result<AgentRole, AgentStoreError> {
    match role {
        0 => Ok(AgentRole::Source),
        1 => Ok(AgentRole::Destination),
        _ => Err(AgentStoreError::Integrity),
    }
}

fn array16(bytes: &[u8]) -> Result<[u8; 16], AgentStoreError> {
    bytes.try_into().map_err(|_| AgentStoreError::Integrity)
}

fn pragma_i64(connection: &Connection, name: &str) -> Result<i64, AgentStoreError> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(|_| AgentStoreError::Storage)
}

fn pragma_string(connection: &Connection, name: &str) -> Result<String, AgentStoreError> {
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(|_| AgentStoreError::Storage)
}

fn map_sqlite_error(error: rusqlite::Error) -> AgentStoreError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            AgentStoreError::StoreBusy
        }
        Some(rusqlite::ErrorCode::ConstraintViolation) => AgentStoreError::Integrity,
        _ => AgentStoreError::Storage,
    }
}

fn map_process_insert_error(error: rusqlite::Error) -> AgentStoreError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            AgentStoreError::StoreBusy
        }
        Some(rusqlite::ErrorCode::ConstraintViolation) => AgentStoreError::StoreMismatch,
        _ => AgentStoreError::Storage,
    }
}

#[cfg(test)]
mod tests;
