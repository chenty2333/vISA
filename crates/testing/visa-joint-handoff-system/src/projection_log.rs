use std::{fmt, path::Path, time::Duration};

use joint_handoff_core::{DecodeError, canonical_bytes, canonical_from_bytes};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use visa_joint_handoff::{
    JointProjectionAppendError, JointProjectionAppendOutcome, JointProjectionLog,
    JointProjectionLogHead, JointProjectionRecord,
};

#[derive(Debug)]
pub enum SqliteProjectionLogError {
    Database(rusqlite::Error),
    Encode,
    Decode,
    NonCanonical,
}

impl fmt::Display for SqliteProjectionLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "SQLite projection log failed: {error}"),
            Self::Encode => formatter.write_str("projection log canonical encoding failed"),
            Self::Decode => formatter.write_str("projection log canonical decoding failed"),
            Self::NonCanonical => {
                formatter.write_str("projection log contains non-canonical bytes")
            }
        }
    }
}

impl std::error::Error for SqliteProjectionLogError {}

impl From<rusqlite::Error> for SqliteProjectionLogError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

/// Reference crash-stable implementation of the joint projection log port.
///
/// A record and its head are written in one `BEGIN IMMEDIATE` SQLite
/// transaction with WAL and `synchronous=FULL`. This is intentionally a
/// reference qualification backend, not a second ownership ledger.
pub struct SqliteJointProjectionLog {
    connection: Connection,
}

impl SqliteJointProjectionLog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteProjectionLogError> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS joint_projection_record (
                 sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
                 record BLOB NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS joint_projection_head (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 head BLOB NOT NULL
             ) STRICT;",
        )?;
        Ok(Self { connection })
    }
}

impl JointProjectionLog for SqliteJointProjectionLog {
    type Error = SqliteProjectionLogError;

    fn head(&self) -> Result<Option<JointProjectionLogHead>, Self::Error> {
        load_head(&self.connection)
    }

    fn read(&self, sequence: u64) -> Result<Option<JointProjectionRecord>, Self::Error> {
        let sequence = i64::try_from(sequence).map_err(|_| SqliteProjectionLogError::Decode)?;
        self.connection
            .query_row(
                "SELECT record FROM joint_projection_record WHERE sequence = ?1",
                [sequence],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|bytes| decode_record(&bytes))
            .transpose()
    }

    fn append(
        &mut self,
        expected_head: Option<JointProjectionLogHead>,
        record: &JointProjectionRecord,
    ) -> Result<JointProjectionAppendOutcome, JointProjectionAppendError<Self::Error>> {
        let record_bytes = record
            .canonical_bytes()
            .map_err(|_| JointProjectionAppendError::Backend(SqliteProjectionLogError::Encode))?;
        let record_digest = record
            .canonical_digest()
            .map_err(|_| JointProjectionAppendError::Backend(SqliteProjectionLogError::Encode))?;
        let result_head = JointProjectionLogHead {
            version: record.version,
            key: record.key,
            issuer_set_digest: record.issuer_set_digest,
            sequence: record.sequence,
            record_digest,
        };
        let expected_sequence = expected_head.map_or(1, |head| head.sequence.saturating_add(1));
        if record.sequence != expected_sequence
            || record.previous_record_digest != expected_head.map(|head| head.record_digest)
        {
            return Err(JointProjectionAppendError::Conflict);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                JointProjectionAppendError::Backend(SqliteProjectionLogError::Database(error))
            })?;
        let current_head = load_head(&transaction).map_err(JointProjectionAppendError::Backend)?;

        if current_head == Some(result_head) {
            let stored = load_record_bytes(&transaction, record.sequence)
                .map_err(JointProjectionAppendError::Backend)?;
            if stored.as_deref() == Some(record_bytes.as_slice()) {
                transaction.commit().map_err(|error| {
                    JointProjectionAppendError::Backend(SqliteProjectionLogError::Database(error))
                })?;
                return Ok(JointProjectionAppendOutcome::ExactReplay);
            }
            return Err(JointProjectionAppendError::Conflict);
        }
        if current_head != expected_head
            || load_record_bytes(&transaction, record.sequence)
                .map_err(JointProjectionAppendError::Backend)?
                .is_some()
        {
            return Err(JointProjectionAppendError::Conflict);
        }

        let sequence =
            i64::try_from(record.sequence).map_err(|_| JointProjectionAppendError::Conflict)?;
        transaction
            .execute(
                "INSERT INTO joint_projection_record(sequence, record) VALUES (?1, ?2)",
                params![sequence, record_bytes],
            )
            .map_err(|error| {
                JointProjectionAppendError::Backend(SqliteProjectionLogError::Database(error))
            })?;
        let head_bytes = encode_head(&result_head).map_err(JointProjectionAppendError::Backend)?;
        transaction
            .execute(
                "INSERT INTO joint_projection_head(singleton, head) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET head = excluded.head",
                [head_bytes],
            )
            .map_err(|error| {
                JointProjectionAppendError::Backend(SqliteProjectionLogError::Database(error))
            })?;
        transaction.commit().map_err(|error| {
            JointProjectionAppendError::Backend(SqliteProjectionLogError::Database(error))
        })?;
        Ok(JointProjectionAppendOutcome::Appended)
    }
}

fn encode_head(head: &JointProjectionLogHead) -> Result<Vec<u8>, SqliteProjectionLogError> {
    canonical_bytes(head).map_err(|_| SqliteProjectionLogError::Encode)
}

fn load_head(
    connection: &Connection,
) -> Result<Option<JointProjectionLogHead>, SqliteProjectionLogError> {
    connection
        .query_row("SELECT head FROM joint_projection_head WHERE singleton = 1", [], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .optional()?
        .map(|bytes| decode_head(&bytes))
        .transpose()
}

fn decode_head(bytes: &[u8]) -> Result<JointProjectionLogHead, SqliteProjectionLogError> {
    let head = match canonical_from_bytes(bytes) {
        Ok(value) => value,
        Err(DecodeError::Codec) => return Err(SqliteProjectionLogError::Decode),
        Err(DecodeError::TrailingBytes) => return Err(SqliteProjectionLogError::NonCanonical),
    };
    if encode_head(&head)?.as_slice() != bytes {
        return Err(SqliteProjectionLogError::NonCanonical);
    }
    Ok(head)
}

fn decode_record(bytes: &[u8]) -> Result<JointProjectionRecord, SqliteProjectionLogError> {
    JointProjectionRecord::from_canonical_bytes(bytes).map_err(|_| SqliteProjectionLogError::Decode)
}

fn load_record_bytes(
    transaction: &Transaction<'_>,
    sequence: u64,
) -> Result<Option<Vec<u8>>, SqliteProjectionLogError> {
    let sequence = i64::try_from(sequence).map_err(|_| SqliteProjectionLogError::Decode)?;
    transaction
        .query_row(
            "SELECT record FROM joint_projection_record WHERE sequence = ?1",
            [sequence],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use contract_core::{Digest, EntityRef, Identity, LeaseEpoch, NodeIdentity};
    use joint_handoff_core::JointHandoffKey;

    use super::*;

    static NEXT_DB: AtomicU64 = AtomicU64::new(1);

    fn id(value: u128) -> Identity {
        Identity::from_u128(value)
    }

    fn key() -> JointHandoffKey {
        JointHandoffKey {
            continuity_unit: EntityRef::initial(id(1)),
            handoff: id(2),
            source: NodeIdentity::new(id(3)),
            destination: NodeIdentity::new(id(4)),
            expected_epoch: LeaseEpoch(7),
            next_epoch: LeaseEpoch(8),
        }
    }

    fn record(sequence: u64, previous_record_digest: Option<Digest>) -> JointProjectionRecord {
        JointProjectionRecord {
            version: visa_joint_handoff::JOINT_PROJECTION_LOG_VERSION,
            key: key(),
            issuer_set_digest: Digest::from_bytes([9; 32]),
            sequence,
            previous_record_digest,
            kind: visa_joint_handoff::JointProjectionRecordKind::BeginDestinationActivation {
                command_identity: id(10 + u128::from(sequence)),
            },
        }
    }

    fn path(label: &str) -> std::path::PathBuf {
        let sequence = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "visa-joint-projection-{label}-{}-{sequence}.sqlite3",
            std::process::id()
        ))
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn append_reopen_and_exact_replay_preserve_one_atomic_head() {
        let path = path("reopen");
        cleanup(&path);
        let mut log = SqliteJointProjectionLog::open(&path).unwrap();
        let first = record(1, None);
        assert!(matches!(log.append(None, &first), Ok(JointProjectionAppendOutcome::Appended)));
        let first_head = log.head().unwrap().unwrap();
        drop(log);

        let mut reopened = SqliteJointProjectionLog::open(&path).unwrap();
        assert_eq!(reopened.head().unwrap(), Some(first_head));
        assert_eq!(reopened.read(1).unwrap(), Some(first.clone()));
        assert!(matches!(
            reopened.append(None, &first),
            Ok(JointProjectionAppendOutcome::ExactReplay)
        ));
        let second = record(2, Some(first_head.record_digest));
        assert!(matches!(
            reopened.append(Some(first_head), &second),
            Ok(JointProjectionAppendOutcome::Appended)
        ));
        assert_eq!(reopened.read(2).unwrap(), Some(second));
        cleanup(&path);
    }

    #[test]
    fn conflicting_append_does_not_replace_durable_history() {
        let path = path("conflict");
        cleanup(&path);
        let mut log = SqliteJointProjectionLog::open(&path).unwrap();
        let first = record(1, None);
        log.append(None, &first).unwrap();
        let conflicting = JointProjectionRecord {
            kind: visa_joint_handoff::JointProjectionRecordKind::BeginDestinationActivation {
                command_identity: id(99),
            },
            ..record(1, None)
        };
        assert!(matches!(
            log.append(None, &conflicting),
            Err(JointProjectionAppendError::Conflict)
        ));
        assert_eq!(log.read(1).unwrap(), Some(first));
        drop(log);
        cleanup(&path);
    }
}
