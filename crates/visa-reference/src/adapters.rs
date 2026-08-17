//! Narrow adapters for the coordinator's typed ports.

use std::fmt;

use rusqlite::{OptionalExtension, params};
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
            Ok(crate::authority::AbortQuery::Applied(receipt)) => QueryOutcome::Applied(receipt),
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
        let bytes =
            postcard::to_allocvec(&request.record).map_err(|_| CoordinatorStoreError::Codec)?;
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
            && (generation as u64 != request.lineage.parent.generation
                || *digest != request.lineage.parent.state_digest.0
                || active.is_some())
        {
            return Err(CoordinatorStoreError::LineageFork);
        }
        tx.execute("INSERT INTO visa_coordinator_records(continuation_id, lineage_id, revision, payload) VALUES (?1, ?2, ?3, ?4)", params![id.0.to_vec(), request.lineage.parent.lineage.0.to_vec(), request.record.revision as i64, bytes])?;
        if existing.is_none() {
            tx.execute("INSERT INTO visa_coordinator_lineages(lineage_id, head_generation, head_state_digest, active_record_id) VALUES (?1, ?2, ?3, ?4)", params![lineage_key, request.lineage.parent.generation as i64, request.lineage.parent.state_digest.0.to_vec(), request.lineage.active_continuation.0.to_vec()])?;
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
        let bytes = connection
            .query_row(
                "SELECT payload FROM visa_coordinator_records WHERE continuation_id = ?1",
                params![continuation.0.to_vec()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        bytes
            .map(|bytes| postcard::from_bytes(&bytes).map_err(|_| CoordinatorStoreError::Codec))
            .transpose()
    }

    fn cas(
        &mut self,
        continuation: &ContinuationId,
        expected_revision: u64,
        next: ContinuationRecord,
        lineage: Option<coordinator::LineageUpdate>,
    ) -> Result<ContinuationRecord, Self::Error> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        let current: Option<(i64, Vec<u8>)> = tx.query_row("SELECT revision, lineage_id FROM visa_coordinator_records WHERE continuation_id = ?1", params![continuation.0.to_vec()], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
        let Some((revision, lineage_id)) = current else {
            return Err(CoordinatorStoreError::NotFound);
        };
        if revision as u64 != expected_revision {
            return Err(CoordinatorStoreError::CasConflict);
        }
        if next.revision != expected_revision + 1 {
            return Err(CoordinatorStoreError::CasConflict);
        }
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
            if generation as u64 != update.expected_head.generation
                || digest != update.expected_head.state_digest.0
                || active_record != update.expected_active.map(|id| id.0.to_vec())
            {
                return Err(CoordinatorStoreError::LineageFork);
            }
        }
        let payload = postcard::to_allocvec(&next).map_err(|_| CoordinatorStoreError::Codec)?;
        tx.execute("UPDATE visa_coordinator_records SET revision = ?2, payload = ?3 WHERE continuation_id = ?1 AND revision = ?4", params![continuation.0.to_vec(), next.revision as i64, payload, expected_revision as i64])?;
        if let Some(update) = lineage {
            tx.execute("UPDATE visa_coordinator_lineages SET head_generation = ?2, head_state_digest = ?3, active_record_id = ?4 WHERE lineage_id = ?1", params![update.lineage.0.to_vec(), update.new_head.generation as i64, update.new_head.state_digest.0.to_vec(), update.active_continuation.map(|id| id.0.to_vec())])?;
        }
        tx.commit()?;
        Ok(next)
    }
}
