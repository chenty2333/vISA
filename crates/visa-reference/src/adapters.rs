//! Narrow adapters for the coordinator's typed ports.

use std::fmt;

use postcard::ser_flavors::Flavor;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use visa_coordinator::{self as coordinator, CallOutcome, QueryOutcome};
use visa_core::{
    AbortPreparationReceipt, AuthorityCommitReceipt, BindingPreparationReceipt, ContinuationId,
    ContinuationRecord, OperationId,
};

use crate::authority::{
    AbortRequest as ReferenceAbort, Authority, AuthorityError, CommitRequest as ReferenceCommit,
    PrepareRequest as ReferencePrepare,
};
use crate::db::ReferenceDatabaseError;
use crate::store::RecordStore;

type StoredLineage = (i64, Vec<u8>, Option<Vec<u8>>);

/// Maximum serialized size of a continuation record stored in SQLite.
///
/// This is deliberately an adapter limit: portable profile state has its own
/// limits, while the reference store must also protect itself from oversized
/// or corrupt database values.
pub const MAX_STORED_PAYLOAD_BYTES: usize = 1024 * 1024;

const MAX_PAYLOAD_READ_BYTES: usize = MAX_STORED_PAYLOAD_BYTES + 1;

#[derive(Debug)]
struct BoundedPayload {
    bytes: Vec<u8>,
}

impl BoundedPayload {
    fn new(capacity: usize) -> Self {
        Self { bytes: Vec::with_capacity(capacity) }
    }
}

impl Flavor for BoundedPayload {
    type Output = Vec<u8>;

    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        if self.bytes.len() >= MAX_STORED_PAYLOAD_BYTES {
            return Err(postcard::Error::SerializeBufferFull);
        }
        self.bytes.push(byte);
        Ok(())
    }

    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        let Some(new_len) = self.bytes.len().checked_add(bytes.len()) else {
            return Err(postcard::Error::SerializeBufferFull);
        };
        if new_len > MAX_STORED_PAYLOAD_BYTES {
            return Err(postcard::Error::SerializeBufferFull);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn finalize(self) -> postcard::Result<Self::Output> {
        Ok(self.bytes)
    }
}

/// Avoid letting a malicious postcard sequence length become a Vec capacity
/// hint before the decoder has proved that the bytes contain that sequence.
struct NoSizeHintSlice<'de>(postcard::de_flavors::Slice<'de>);

impl<'de> NoSizeHintSlice<'de> {
    fn new(bytes: &'de [u8]) -> Self {
        Self(postcard::de_flavors::Slice::new(bytes))
    }
}

impl<'de> postcard::de_flavors::Flavor<'de> for NoSizeHintSlice<'de> {
    type Remainder = &'de [u8];
    type Source = &'de [u8];

    fn pop(&mut self) -> postcard::Result<u8> {
        self.0.pop()
    }

    fn try_take_n(&mut self, count: usize) -> postcard::Result<&'de [u8]> {
        self.0.try_take_n(count)
    }

    fn try_take_n_temp<'a>(&'a mut self, count: usize) -> postcard::Result<&'a [u8]>
    where
        'de: 'a,
    {
        self.0.try_take_n_temp(count)
    }

    fn finalize(self) -> postcard::Result<Self::Remainder> {
        self.0.finalize()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorRejection(pub String);

impl fmt::Display for CoordinatorRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Adapter exposing the SQLite authority as the coordinator's typed port.
pub struct CoordinatorAuthorityAdapter {
    pub authority: Authority,
}

impl CoordinatorAuthorityAdapter {
    pub fn new(authority: Authority) -> Self {
        Self { authority }
    }
    fn rejection(error: AuthorityError) -> CoordinatorRejection {
        CoordinatorRejection(error.to_string())
    }

    fn reference_prepare(
        &self,
        operation: OperationId,
        binding: &coordinator::AuthorityBinding,
    ) -> ReferencePrepare {
        ReferencePrepare {
            operation,
            continuation: binding.continuation,
            snapshot: binding.snapshot,
            source: binding.source.clone(),
            destination: binding.destination.clone(),
            requirements: binding.requirements.clone(),
            capture_receipt: binding.capture_receipt.clone(),
            preparation_digest: binding.preparation_digest,
        }
    }

    fn reference_commit(&self, request: &coordinator::CommitRequest) -> ReferenceCommit {
        ReferenceCommit {
            operation: request.operation,
            continuation: request.binding.continuation,
            snapshot: request.binding.snapshot,
            source: request.binding.source.clone(),
            destination: request.binding.destination.clone(),
            requirements: request.binding.requirements.clone(),
            capture_receipt: request.binding.capture_receipt.clone(),
            preparation_digest: request.binding.preparation_digest,
            preparation: request.preparation.clone(),
        }
    }

    fn reference_abort(
        operation: OperationId,
        binding: &coordinator::AuthorityBinding,
        preparation: &BindingPreparationReceipt,
    ) -> ReferenceAbort {
        ReferenceAbort {
            operation,
            continuation: binding.continuation,
            snapshot: binding.snapshot,
            source: binding.source.clone(),
            destination: binding.destination.clone(),
            requirements: binding.requirements.clone(),
            capture_receipt: binding.capture_receipt.clone(),
            preparation_digest: binding.preparation_digest,
            preparation: preparation.clone(),
        }
    }
}

impl coordinator::AuthorityPort for CoordinatorAuthorityAdapter {
    type PrepareRejection = CoordinatorRejection;
    type CommitRejection = CoordinatorRejection;
    type AbortRejection = CoordinatorRejection;

    fn prepare(
        &mut self,
        request: coordinator::PrepareRequest,
    ) -> CallOutcome<BindingPreparationReceipt, Self::PrepareRejection> {
        let result =
            self.authority.prepare(self.reference_prepare(request.operation, &request.binding));
        match result {
            Ok(receipt) => CallOutcome::Applied(receipt.core_receipt),
            Err(AuthorityError::Indeterminate | AuthorityError::Database(_)) => {
                CallOutcome::Indeterminate
            }
            Err(error) => CallOutcome::Rejected(Self::rejection(error)),
        }
    }

    fn query_prepare(
        &mut self,
        request: coordinator::QueryPrepareRequest,
    ) -> QueryOutcome<BindingPreparationReceipt, Self::PrepareRejection> {
        let reference = self.reference_prepare(request.operation, &request.binding);
        match self.authority.query_preparation(&reference) {
            Ok(Some(receipt)) => QueryOutcome::Applied(receipt.core_receipt),
            Ok(None) => QueryOutcome::Absent,
            Err(AuthorityError::Indeterminate | AuthorityError::Database(_)) => {
                QueryOutcome::Indeterminate
            }
            Err(error) => QueryOutcome::Rejected(Self::rejection(error)),
        }
    }

    fn commit(
        &mut self,
        request: coordinator::CommitRequest,
    ) -> CallOutcome<AuthorityCommitReceipt, Self::CommitRejection> {
        let result = self.authority.commit(self.reference_commit(&request));
        match result {
            Ok(receipt) => CallOutcome::Applied(receipt.core_receipt),
            Err(AuthorityError::Indeterminate | AuthorityError::Database(_)) => {
                CallOutcome::Indeterminate
            }
            Err(error) => CallOutcome::Rejected(Self::rejection(error)),
        }
    }

    fn query_commit(
        &mut self,
        request: coordinator::QueryCommitRequest,
    ) -> QueryOutcome<AuthorityCommitReceipt, Self::CommitRejection> {
        let reference = ReferenceCommit {
            operation: request.operation,
            continuation: request.binding.continuation,
            snapshot: request.binding.snapshot,
            source: request.binding.source.clone(),
            destination: request.binding.destination.clone(),
            requirements: request.binding.requirements.clone(),
            capture_receipt: request.binding.capture_receipt.clone(),
            preparation_digest: request.binding.preparation_digest,
            preparation: request.preparation,
        };
        match self.authority.query_commit(&reference) {
            Ok(crate::authority::OperationQuery::Applied(receipt)) => {
                QueryOutcome::Applied(receipt.core_receipt)
            }
            Ok(crate::authority::OperationQuery::Rejected(reason)) => {
                QueryOutcome::Rejected(CoordinatorRejection(reason))
            }
            Ok(crate::authority::OperationQuery::Absent) => QueryOutcome::Absent,
            Ok(crate::authority::OperationQuery::Indeterminate) => QueryOutcome::Indeterminate,
            Err(AuthorityError::Indeterminate | AuthorityError::Database(_)) => {
                QueryOutcome::Indeterminate
            }
            Err(error) => QueryOutcome::Rejected(Self::rejection(error)),
        }
    }

    fn abort_preparation(
        &mut self,
        request: coordinator::AbortPreparationRequest,
    ) -> CallOutcome<AbortPreparationReceipt, Self::AbortRejection> {
        let reference =
            Self::reference_abort(request.operation, &request.binding, &request.preparation);
        match self.authority.abort_preparation(&reference) {
            Ok(receipt) => CallOutcome::Applied(receipt),
            Err(AuthorityError::Indeterminate | AuthorityError::Database(_)) => {
                CallOutcome::Indeterminate
            }
            Err(error) => CallOutcome::Rejected(Self::rejection(error)),
        }
    }
    fn query_abort(
        &mut self,
        request: coordinator::QueryAbortRequest,
    ) -> QueryOutcome<AbortPreparationReceipt, Self::AbortRejection> {
        let reference =
            Self::reference_abort(request.operation, &request.binding, &request.preparation);
        match self.authority.query_abort(&reference) {
            Ok(crate::authority::AbortQuery::Applied(receipt)) => QueryOutcome::Applied(*receipt),
            Ok(crate::authority::AbortQuery::Absent) => QueryOutcome::Absent,
            Err(AuthorityError::Indeterminate | AuthorityError::Database(_)) => {
                QueryOutcome::Indeterminate
            }
            Err(error) => QueryOutcome::Rejected(Self::rejection(error)),
        }
    }
}

#[derive(Debug)]
pub enum CoordinatorStoreError {
    Database(ReferenceDatabaseError),
    Codec,
    Corrupt(String),
    NumericOverflow,
    PayloadTooLarge { actual: usize, max: usize },
    NotFound,
    AlreadyExists,
    CasConflict,
    LineageFork,
}
impl fmt::Display for CoordinatorStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "coordinator SQLite store error: {self:?}")
    }
}
impl std::error::Error for CoordinatorStoreError {}
impl From<ReferenceDatabaseError> for CoordinatorStoreError {
    fn from(e: ReferenceDatabaseError) -> Self {
        Self::Database(e)
    }
}
impl From<rusqlite::Error> for CoordinatorStoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(ReferenceDatabaseError::Sqlite(e))
    }
}

fn sqlite_i64(value: u64) -> Result<i64, CoordinatorStoreError> {
    i64::try_from(value).map_err(|_| CoordinatorStoreError::NumericOverflow)
}

fn u64_from_sqlite(value: i64) -> Result<u64, CoordinatorStoreError> {
    u64::try_from(value).map_err(|_| CoordinatorStoreError::NumericOverflow)
}

fn usize_from_sqlite(value: i64) -> Result<usize, CoordinatorStoreError> {
    usize::try_from(value).map_err(|_| CoordinatorStoreError::NumericOverflow)
}

fn payload_read_limit() -> Result<i64, CoordinatorStoreError> {
    i64::try_from(MAX_PAYLOAD_READ_BYTES).map_err(|_| CoordinatorStoreError::NumericOverflow)
}

fn encode_payload(record: &ContinuationRecord) -> Result<Vec<u8>, CoordinatorStoreError> {
    // The flavor enforces the limit while encoding, avoiding a full extra
    // serialization pass on every coordinator CAS. Its small initial
    // capacity also avoids reserving the maximum for ordinary records.
    let payload =
        postcard::serialize_with_flavor(record, BoundedPayload::new(1024)).map_err(|error| {
            match error {
                postcard::Error::SerializeBufferFull => CoordinatorStoreError::PayloadTooLarge {
                    actual: MAX_STORED_PAYLOAD_BYTES.saturating_add(1),
                    max: MAX_STORED_PAYLOAD_BYTES,
                },
                _ => CoordinatorStoreError::Codec,
            }
        })?;
    debug_assert!(payload.len() <= MAX_STORED_PAYLOAD_BYTES);
    Ok(payload)
}

fn decode_stored_record(
    row_id: &[u8],
    sql_revision: i64,
    sql_lineage_id: &[u8],
    payload_length: i64,
    payload: &[u8],
) -> Result<ContinuationRecord, CoordinatorStoreError> {
    let declared_length = usize_from_sqlite(payload_length)?;
    if declared_length > MAX_STORED_PAYLOAD_BYTES {
        return Err(CoordinatorStoreError::PayloadTooLarge {
            actual: declared_length,
            max: MAX_STORED_PAYLOAD_BYTES,
        });
    }
    if payload.len() != declared_length {
        return Err(CoordinatorStoreError::Corrupt(format!(
            "payload length mismatch: SQL declared {declared_length}, fetched {}",
            payload.len()
        )));
    }
    let mut deserializer = postcard::Deserializer::from_flavor(NoSizeHintSlice::new(payload));
    let record = ContinuationRecord::deserialize(&mut deserializer).map_err(|error| {
        CoordinatorStoreError::Corrupt(format!("payload decode failed: {error}"))
    })?;
    let trailing = deserializer.finalize().map_err(|error| {
        CoordinatorStoreError::Corrupt(format!("payload finalization failed: {error}"))
    })?;
    if !trailing.is_empty() {
        return Err(CoordinatorStoreError::Corrupt(format!(
            "payload has {} trailing bytes",
            trailing.len()
        )));
    }
    if record.intent.id.0.as_slice() != row_id {
        return Err(CoordinatorStoreError::Corrupt(format!(
            "payload record id does not match SQL key (payload {}, SQL {})",
            record.intent.id.0.len(),
            row_id.len()
        )));
    }
    if u64_from_sqlite(sql_revision)? != record.revision {
        return Err(CoordinatorStoreError::Corrupt(
            "payload revision does not match SQL revision".to_owned(),
        ));
    }
    if record.intent.lineage_parent.lineage.0.as_slice() != sql_lineage_id {
        return Err(CoordinatorStoreError::Corrupt(
            "payload intent lineage does not match SQL lineage_id".to_owned(),
        ));
    }
    Ok(record)
}

fn validate_next_record(
    continuation: &ContinuationId,
    expected: &ContinuationRecord,
    next: &ContinuationRecord,
    lineage_id: &[u8],
) -> Result<(), CoordinatorStoreError> {
    let next_revision =
        expected.revision.checked_add(1).ok_or(CoordinatorStoreError::NumericOverflow)?;
    if next.intent.id != *continuation || next.revision != next_revision {
        return Err(CoordinatorStoreError::CasConflict);
    }
    if next.intent.lineage_parent.lineage.0.as_slice() != lineage_id {
        return Err(CoordinatorStoreError::LineageFork);
    }
    Ok(())
}

/// SQLite-backed implementation of the coordinator RecordStore trait. Core
/// records are encoded with postcard; the local authority/provider tables are
/// never used as a record projection.
impl coordinator::RecordStore for RecordStore {
    type Error = CoordinatorStoreError;

    fn create(
        &mut self,
        request: coordinator::CreateRecord,
    ) -> Result<ContinuationRecord, Self::Error> {
        let id = request.record.intent.id;
        if request.record.intent.lineage_parent != request.lineage.parent
            || request.lineage.active_continuation != id
        {
            return Err(CoordinatorStoreError::LineageFork);
        }
        let record_revision = sqlite_i64(request.record.revision)?;
        let parent_generation = sqlite_i64(request.lineage.parent.generation)?;
        let bytes = encode_payload(&request.record)?;
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        if tx
            .query_row(
                "SELECT 1 FROM visa_coordinator_records WHERE continuation_id = ?1",
                params![id.0.to_vec()],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(CoordinatorStoreError::AlreadyExists);
        }
        let lineage_key = request.lineage.parent.lineage.0.to_vec();
        let existing: Option<StoredLineage> = tx.query_row("SELECT head_generation, head_state_digest, active_record_id FROM visa_coordinator_lineages WHERE lineage_id = ?1", params![lineage_key.clone()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional()?;
        if let Some((generation, ref digest, ref active)) = existing
            && (u64_from_sqlite(generation)? != request.lineage.parent.generation
                || *digest != request.lineage.parent.state_digest.0
                || active.is_some())
        {
            return Err(CoordinatorStoreError::LineageFork);
        }
        tx.execute("INSERT INTO visa_coordinator_records(continuation_id, lineage_id, revision, payload) VALUES (?1, ?2, ?3, ?4)", params![id.0.to_vec(), request.lineage.parent.lineage.0.to_vec(), record_revision, bytes])?;
        if existing.is_none() {
            tx.execute("INSERT INTO visa_coordinator_lineages(lineage_id, head_generation, head_state_digest, active_record_id) VALUES (?1, ?2, ?3, ?4)", params![lineage_key, parent_generation, request.lineage.parent.state_digest.0.to_vec(), request.lineage.active_continuation.0.to_vec()])?;
        } else {
            tx.execute(
                "UPDATE visa_coordinator_lineages SET active_record_id = ?2 WHERE lineage_id = ?1",
                params![lineage_key, request.lineage.active_continuation.0.to_vec()],
            )?;
        }
        tx.commit()?;
        Ok(request.record)
    }

    fn load(
        &self,
        continuation: &ContinuationId,
    ) -> Result<Option<ContinuationRecord>, Self::Error> {
        let connection = self.database.lock()?;
        let payload_limit = payload_read_limit()?;
        let row = connection
            .query_row(
                "SELECT substr(continuation_id, 1, 17), revision,
                        substr(lineage_id, 1, 17), length(payload),
                        substr(payload, 1, ?2)
                 FROM visa_coordinator_records
                 WHERE continuation_id = ?1",
                params![continuation.0.to_vec(), payload_limit],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(row_id, revision, lineage_id, payload_length, payload)| {
            decode_stored_record(&row_id, revision, &lineage_id, payload_length, &payload)
        })
        .transpose()
    }

    fn discover_unfinished(&self) -> Result<Vec<ContinuationId>, Self::Error> {
        let connection = self.database.lock()?;
        let payload_limit = payload_read_limit()?;
        let mut statement = connection.prepare(
            "SELECT substr(continuation_id, 1, 17), revision,
                    substr(lineage_id, 1, 17), length(payload),
                        substr(payload, 1, ?1)
                 FROM visa_coordinator_records
                 ORDER BY continuation_id",
        )?;
        let rows = statement.query_map(params![payload_limit], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut unfinished = Vec::new();
        for row in rows {
            let (row_id, revision, lineage_id, payload_length, payload) = row?;
            let record =
                decode_stored_record(&row_id, revision, &lineage_id, payload_length, &payload)?;
            if !coordinator::record_is_terminal(&record) {
                unfinished.push(record.intent.id);
            }
        }
        Ok(unfinished)
    }

    fn cas(
        &mut self,
        continuation: &ContinuationId,
        expected: &ContinuationRecord,
        next: ContinuationRecord,
        lineage: Option<coordinator::LineageUpdate>,
    ) -> Result<ContinuationRecord, Self::Error> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        let current = tx
            .query_row(
                "SELECT substr(continuation_id, 1, 17), revision,
                        substr(lineage_id, 1, 17)
                 FROM visa_coordinator_records
                 WHERE continuation_id = ?1",
                params![continuation.0.to_vec()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((row_id, revision, lineage_id)) = current else {
            return Err(CoordinatorStoreError::NotFound);
        };
        if row_id.as_slice() != continuation.0
            || expected.intent.id != *continuation
            || expected.intent.lineage_parent.lineage.0.as_slice() != lineage_id
            || u64_from_sqlite(revision)? != expected.revision
        {
            return Err(CoordinatorStoreError::CasConflict);
        }
        validate_next_record(continuation, expected, &next, &lineage_id)?;
        let next_revision = sqlite_i64(next.revision)?;
        let expected_revision_sql = sqlite_i64(expected.revision)?;
        if let Some(update) = &lineage {
            if update.lineage.0.to_vec() != lineage_id
                || update.expected_head.lineage != update.lineage
                || update.new_head.lineage != update.lineage
            {
                return Err(CoordinatorStoreError::LineageFork);
            }
            let current_lineage: Option<StoredLineage> = tx
                .query_row(
                    "SELECT head_generation, head_state_digest, active_record_id FROM visa_coordinator_lineages WHERE lineage_id = ?1",
                    params![lineage_id.clone()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((generation, digest, active_record)) = current_lineage else {
                return Err(CoordinatorStoreError::LineageFork);
            };
            if u64_from_sqlite(generation)? != update.expected_head.generation
                || digest != update.expected_head.state_digest.0
                || active_record != update.expected_active.map(|id| id.0.to_vec())
            {
                return Err(CoordinatorStoreError::LineageFork);
            }
        }
        let payload = encode_payload(&next)?;
        let updated = tx.execute("UPDATE visa_coordinator_records SET revision = ?2, payload = ?3 WHERE continuation_id = ?1 AND revision = ?4", params![continuation.0.to_vec(), next_revision, payload, expected_revision_sql])?;
        if updated != 1 {
            return Err(CoordinatorStoreError::CasConflict);
        }
        if let Some(update) = lineage {
            let new_generation = sqlite_i64(update.new_head.generation)?;
            let updated_lineage = tx.execute("UPDATE visa_coordinator_lineages SET head_generation = ?2, head_state_digest = ?3, active_record_id = ?4 WHERE lineage_id = ?1", params![update.lineage.0.to_vec(), new_generation, update.new_head.state_digest.0.to_vec(), update.active_continuation.map(|id| id.0.to_vec())])?;
            if updated_lineage != 1 {
                return Err(CoordinatorStoreError::LineageFork);
            }
        }
        tx.commit()?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use visa_core::{
        AuthorityId, ContinuationIntent, Digest, Event, ExternalCoordinate, LineageId,
        LineagePoint, ProfileId, ProfileRef, ProfileVersion, SchemaId, SchemaRef, ScopeId, apply,
    };

    fn record() -> ContinuationRecord {
        let intent = ContinuationIntent {
            id: ContinuationId::from_u128(1),
            scope: ScopeId::from_u128(2),
            source: ExternalCoordinate { authority: AuthorityId::from_u128(3), value: vec![1] },
            destination: ExternalCoordinate {
                authority: AuthorityId::from_u128(4),
                value: vec![2],
            },
            lineage_parent: LineagePoint {
                lineage: LineageId::from_u128(5),
                generation: 0,
                state_digest: Digest::ZERO,
            },
            profile: ProfileRef {
                id: ProfileId::from_u128(6),
                version: ProfileVersion { major: 1, minor: 0 },
                contract_digest: Digest::ZERO,
                state_schema: SchemaRef { id: SchemaId::from_u128(7), version: 1 },
            },
        };
        apply(None, &Event::Begun(intent)).expect("test record is valid")
    }

    #[test]
    fn decode_rejects_row_metadata_mismatches() {
        let record = record();
        let payload = encode_payload(&record).expect("test payload is bounded");
        let row_id = record.intent.id.0;
        let lineage_id = record.intent.lineage_parent.lineage.0;

        let error = decode_stored_record(
            &[0; 16],
            0,
            &lineage_id,
            i64::try_from(payload.len()).unwrap(),
            &payload,
        )
        .unwrap_err();
        assert!(
            matches!(error, CoordinatorStoreError::Corrupt(message) if message.contains("record id"))
        );

        let error = decode_stored_record(
            &row_id,
            1,
            &lineage_id,
            i64::try_from(payload.len()).unwrap(),
            &payload,
        )
        .unwrap_err();
        assert!(
            matches!(error, CoordinatorStoreError::Corrupt(message) if message.contains("revision"))
        );

        let error = decode_stored_record(
            &row_id,
            0,
            &[9; 16],
            i64::try_from(payload.len()).unwrap(),
            &payload,
        )
        .unwrap_err();
        assert!(
            matches!(error, CoordinatorStoreError::Corrupt(message) if message.contains("lineage"))
        );
    }

    #[test]
    fn payload_encoder_and_decoder_are_bounded() {
        let mut record = record();
        record.intent.source.value = vec![0; MAX_STORED_PAYLOAD_BYTES];
        assert!(matches!(
            encode_payload(&record),
            Err(CoordinatorStoreError::PayloadTooLarge { .. })
        ));

        let error = decode_stored_record(
            &record.intent.id.0,
            0,
            &record.intent.lineage_parent.lineage.0,
            i64::try_from(MAX_STORED_PAYLOAD_BYTES + 1).unwrap(),
            &[],
        )
        .unwrap_err();
        assert!(matches!(error, CoordinatorStoreError::PayloadTooLarge { .. }));
    }

    #[test]
    fn decoder_does_not_trust_sequence_length_hint() {
        let encoded_length = [0xff; 9].into_iter().chain([1]).collect::<Vec<_>>();
        let mut deserializer =
            postcard::Deserializer::from_flavor(NoSizeHintSlice::new(&encoded_length));
        let result = Vec::<u8>::deserialize(&mut deserializer);
        assert!(result.is_err());
    }
}
