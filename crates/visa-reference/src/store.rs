//! Durable continuation records and lineage heads.

use std::fmt;

use rusqlite::{OptionalExtension, params};
use visa_coordinator::{
    LineageCreate, LineageUpdate, RecordStore as CoordinatorRecordStore, WorkflowRecord,
    WorkflowStatus,
};
use visa_core::{ContinuationId, Digest, LineagePoint, Progress};

use crate::db::{ReferenceDatabase, ReferenceDatabaseError, sqlite_to_u64, u64_to_sqlite};

const MAX_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct RecordStore {
    database: ReferenceDatabase,
}

impl fmt::Debug for RecordStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RecordStore").finish_non_exhaustive()
    }
}

impl RecordStore {
    pub fn new(database: ReferenceDatabase) -> Self {
        Self { database }
    }

    pub fn database(&self) -> ReferenceDatabase {
        self.database.clone()
    }
}

#[derive(Debug)]
pub enum StoreError {
    Database(ReferenceDatabaseError),
    Codec,
    Corrupt(String),
    AlreadyExists,
    Conflict,
    LineageConflict,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "record store database error: {error}"),
            Self::Codec => formatter.write_str("record store codec error"),
            Self::Corrupt(reason) => write!(formatter, "corrupt record store row: {reason}"),
            Self::AlreadyExists => formatter.write_str("continuation record already exists"),
            Self::Conflict => formatter.write_str("continuation record compare-and-swap conflict"),
            Self::LineageConflict => formatter.write_str("lineage head compare-and-swap conflict"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<ReferenceDatabaseError> for StoreError {
    fn from(value: ReferenceDatabaseError) -> Self {
        Self::Database(value)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value.into())
    }
}

impl CoordinatorRecordStore for RecordStore {
    type Error = StoreError;

    fn create(
        &mut self,
        record: WorkflowRecord,
        lineage: LineageCreate,
    ) -> Result<(), Self::Error> {
        if record.core.intent.id != lineage.active_continuation
            || record.core.intent.lineage_parent != lineage.parent
        {
            return Err(StoreError::LineageConflict);
        }
        let payload = encode(&record)?;
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        let existing = transaction
            .query_row(
                "SELECT 1 FROM visa_store_records WHERE continuation_id = ?1",
                params![record.core.intent.id.0.to_vec()],
                |_| Ok(()),
            )
            .optional()?;
        if existing.is_some() {
            return Err(StoreError::AlreadyExists);
        }
        let existing_lineage = lineage_row(&transaction, &lineage.parent.lineage.0)?;
        if let Some(ref head) = existing_lineage {
            if head.point != lineage.parent || head.active.is_some() {
                return Err(StoreError::LineageConflict);
            }
        } else {
            transaction.execute(
                "INSERT INTO visa_store_lineages
                 (lineage_id, semantic_domain_id, semantic_contract_digest,
                  semantic_artifact_digest, head_generation, head_state_digest,
                  active_continuation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    lineage.parent.lineage.0.to_vec(),
                    lineage.parent.semantic_domain.id.0.to_vec(),
                    lineage.parent.semantic_domain.contract_digest.0.to_vec(),
                    lineage.parent.semantic_domain.artifact_digest.0.to_vec(),
                    u64_to_sqlite(lineage.parent.generation, "lineage generation")?,
                    lineage.parent.state_digest.0.to_vec(),
                    lineage.active_continuation.0.to_vec(),
                ],
            )?;
        }
        if existing_lineage.is_some() {
            transaction.execute(
                "UPDATE visa_store_lineages SET active_continuation = ?2 WHERE lineage_id = ?1",
                params![lineage.parent.lineage.0.to_vec(), lineage.active_continuation.0.to_vec()],
            )?;
        }
        transaction.execute(
            "INSERT INTO visa_store_records (continuation_id, lineage_id, phase, payload)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                record.core.intent.id.0.to_vec(),
                lineage.parent.lineage.0.to_vec(),
                phase_text(record.core.phase),
                payload,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn load(&self, continuation: &ContinuationId) -> Result<Option<WorkflowRecord>, Self::Error> {
        let connection = self.database.lock()?;
        let row = connection
            .query_row(
                "SELECT lineage_id, phase, payload FROM visa_store_records
                 WHERE continuation_id = ?1",
                params![continuation.0.to_vec()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(lineage, phase, payload)| decode_row(continuation, &lineage, &phase, &payload))
            .transpose()
    }

    fn cas(
        &mut self,
        expected: &WorkflowRecord,
        next: WorkflowRecord,
        lineage: Option<LineageUpdate>,
    ) -> Result<(), Self::Error> {
        if expected.core.intent != next.core.intent {
            return Err(StoreError::Conflict);
        }
        let expected_payload = encode(expected)?;
        let next_payload = encode(&next)?;
        let continuation = expected.core.intent.id;
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;

        let stored = transaction
            .query_row(
                "SELECT payload FROM visa_store_records WHERE continuation_id = ?1",
                params![continuation.0.to_vec()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if stored.as_deref() != Some(expected_payload.as_slice()) {
            return Err(StoreError::Conflict);
        }

        if let Some(update) = lineage {
            let commit_transition = expected.commit.is_none()
                && next.commit.is_some()
                && update.next_active == Some(continuation);
            let activation_release = expected.runtime_activation.is_none()
                && next.runtime_activation.is_some()
                && update.next_active.is_none()
                && update.successor == update.expected_head;
            let rollback_release = expected.status != WorkflowStatus::RolledBack
                && next.status == WorkflowStatus::RolledBack
                && update.next_active.is_none()
                && update.successor == update.expected_head;
            if update.expected_active != continuation
                || update.successor.lineage != update.lineage
                || !(commit_transition || activation_release || rollback_release)
            {
                return Err(StoreError::LineageConflict);
            }
            let Some(head) = lineage_row(&transaction, &update.lineage.0)? else {
                return Err(StoreError::LineageConflict);
            };
            if head.point != update.expected_head || head.active != Some(update.expected_active) {
                return Err(StoreError::LineageConflict);
            }
            let updated = transaction.execute(
                "UPDATE visa_store_lineages
                 SET head_generation = ?2, head_state_digest = ?3, active_continuation = ?4
                 WHERE lineage_id = ?1 AND active_continuation = ?5",
                params![
                    update.lineage.0.to_vec(),
                    u64_to_sqlite(update.successor.generation, "successor generation")?,
                    update.successor.state_digest.0.to_vec(),
                    update.next_active.map(|id| id.0.to_vec()),
                    continuation.0.to_vec(),
                ],
            )?;
            if updated != 1 {
                return Err(StoreError::LineageConflict);
            }
        }

        let written = transaction.execute(
            "UPDATE visa_store_records SET payload = ?2, phase = ?4
             WHERE continuation_id = ?1 AND payload = ?3",
            params![
                continuation.0.to_vec(),
                next_payload,
                expected_payload,
                phase_text(next.core.phase)
            ],
        )?;
        if written != 1 {
            return Err(StoreError::Conflict);
        }
        transaction.commit()?;
        Ok(())
    }

    fn unfinished(&self) -> Result<Vec<ContinuationId>, Self::Error> {
        let connection = self.database.lock()?;
        let mut statement = connection.prepare(
            "SELECT continuation_id, payload FROM visa_store_records ORDER BY continuation_id",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
        let mut unfinished = Vec::new();
        for row in rows {
            let (id, payload) = row?;
            let continuation = continuation_id(&id)?;
            let record = decode(&continuation, &payload)?;
            if !finished(&record) {
                unfinished.push(continuation);
            }
        }
        Ok(unfinished)
    }
}

struct StoredLineage {
    point: LineagePoint,
    active: Option<ContinuationId>,
}

fn lineage_row(
    transaction: &rusqlite::Transaction<'_>,
    lineage: &[u8; 16],
) -> Result<Option<StoredLineage>, StoreError> {
    transaction
        .query_row(
            "SELECT semantic_domain_id, semantic_contract_digest, semantic_artifact_digest,
                    head_generation, head_state_digest, active_continuation
             FROM visa_store_lineages WHERE lineage_id = ?1",
            params![lineage.to_vec()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .optional()?
        .map(|(domain_id, contract_digest, artifact_digest, generation, state_digest, active)| {
            Ok(StoredLineage {
                point: LineagePoint {
                    semantic_domain: visa_core::SemanticDomainRef {
                        id: visa_core::SemanticDomainId(domain_id.try_into().map_err(|_| {
                            StoreError::Corrupt("semantic domain id is not 16 bytes".into())
                        })?),
                        contract_digest: digest(&contract_digest)?,
                        artifact_digest: digest(&artifact_digest)?,
                    },
                    lineage: visa_core::LineageId(*lineage),
                    generation: sqlite_to_u64(generation, "lineage generation")?,
                    state_digest: digest(&state_digest)?,
                },
                active: active.as_deref().map(continuation_id).transpose()?,
            })
        })
        .transpose()
}

fn encode(record: &WorkflowRecord) -> Result<Vec<u8>, StoreError> {
    let payload = postcard::to_allocvec(record).map_err(|_| StoreError::Codec)?;
    if payload.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Codec);
    }
    Ok(payload)
}

fn decode(continuation: &ContinuationId, payload: &[u8]) -> Result<WorkflowRecord, StoreError> {
    if payload.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Corrupt("record payload exceeds durable bound".into()));
    }
    let record: WorkflowRecord = postcard::from_bytes(payload).map_err(|_| StoreError::Codec)?;
    if record.core.intent.id != *continuation {
        return Err(StoreError::Corrupt("record id does not match durable key".into()));
    }
    Ok(record)
}

fn decode_row(
    continuation: &ContinuationId,
    lineage: &[u8],
    phase: &str,
    payload: &[u8],
) -> Result<WorkflowRecord, StoreError> {
    let record = decode(continuation, payload)?;
    if lineage != record.core.intent.lineage_parent.lineage.0
        || phase != phase_text(record.core.phase)
    {
        return Err(StoreError::Corrupt(
            "record payload does not match durable row metadata".into(),
        ));
    }
    Ok(record)
}

const fn phase_text(phase: Progress) -> &'static str {
    match phase {
        Progress::Capturing => "capturing",
        Progress::Captured => "captured",
        Progress::Aborted => "aborted",
    }
}

fn continuation_id(bytes: &[u8]) -> Result<ContinuationId, StoreError> {
    let array: [u8; 16] = bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("continuation id is not 16 bytes".into()))?;
    Ok(ContinuationId(array))
}

fn digest(bytes: &[u8]) -> Result<Digest, StoreError> {
    let array: [u8; 32] =
        bytes.try_into().map_err(|_| StoreError::Corrupt("digest is not 32 bytes".into()))?;
    Ok(Digest(array))
}

fn finished(record: &WorkflowRecord) -> bool {
    if record.recovery.is_some() {
        return false;
    }
    if record.status == WorkflowStatus::RolledBack {
        return true;
    }
    match record.core.phase {
        Progress::Captured => record.retired.is_some(),
        Progress::Aborted => {
            let bindings_done = record.bindings.is_none() || record.bindings_aborted.is_some();
            let source_done = record.core.snapshot.is_none() || record.source_restored.is_some();
            bindings_done && source_done
        }
        Progress::Capturing => false,
    }
}
