//! Minimal reference authority for World/provider rebinding and fencing.

use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use visa_core::{
    AbortPreparationReceipt, AuthorityCommitReceipt as CoreCommitReceipt, AuthorityId,
    BindingGrant, BindingPreparationReceipt, ContinuationId, Digest, ExternalCoordinate,
    OperationId, ResourceRequirement, SnapshotId, canonical_digest,
};

use crate::db::{
    ReferenceDatabase, ReferenceDatabaseError, sqlite_bool, sqlite_to_u64, u64_to_sqlite,
};

pub type BindingId = String;

const REFERENCE_AUTHORITY_ID: AuthorityId = AuthorityId::from_u128(1);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rights(u64);

impl Rights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const SESSION: Self = Self(1 << 2);

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Rights {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingRole {
    Source,
    Destination,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingView {
    pub binding_id: BindingId,
    pub owner: String,
    pub provider_generation: u64,
    pub rights: Rights,
    pub execution_epoch: u64,
    pub role: BindingRole,
    pub active: bool,
    pub fenced: bool,
    pub dispatch_open: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceBinding {
    pub binding_id: BindingId,
    pub owner: String,
    pub provider_generation: u64,
    pub rights: Rights,
    pub execution_epoch: u64,
}

/// Complete semantic input for one binding preparation. The authority hashes
/// these fields itself; the adapter supplies no digest that could omit them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareRequest {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub snapshot: SnapshotId,
    pub source: ExternalCoordinate,
    pub destination: ExternalCoordinate,
    pub requirements: Vec<ResourceRequirement>,
    pub preparation_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareReceipt {
    pub request_digest: Digest,
    pub source_binding_id: BindingId,
    pub destination_binding_id: BindingId,
    pub source_owner: String,
    pub destination_owner: String,
    pub provider_generation: u64,
    pub rights: Rights,
    pub source_execution_epoch: u64,
    pub core_receipt: BindingPreparationReceipt,
}

/// Complete semantic input for one authority commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitRequest {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub snapshot: SnapshotId,
    pub source: ExternalCoordinate,
    pub destination: ExternalCoordinate,
    pub requirements: Vec<ResourceRequirement>,
    pub preparation_digest: Digest,
    pub preparation: BindingPreparationReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbortRequest {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub snapshot: SnapshotId,
    pub source: ExternalCoordinate,
    pub destination: ExternalCoordinate,
    pub requirements: Vec<ResourceRequirement>,
    pub preparation_digest: Digest,
    pub preparation: BindingPreparationReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationAdmissionRequest {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub snapshot: SnapshotId,
    pub destination: ExternalCoordinate,
    pub destination_binding_id: BindingId,
    pub commit: CoreCommitReceipt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationAdmissionState {
    Absent,
    Admitted,
    Activated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbortQuery {
    Applied(Box<AbortPreparationReceipt>),
    Absent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityCommitReceipt {
    pub request_digest: Digest,
    pub source_binding_id: BindingId,
    pub destination_binding_id: BindingId,
    pub source_owner: String,
    pub provider_generation: u64,
    pub granted_rights: Rights,
    pub source_execution_epoch: u64,
    pub destination_execution_epoch: u64,
    pub core_receipt: CoreCommitReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationQuery {
    Applied(Box<AuthorityCommitReceipt>),
    Rejected(String),
    Absent,
    Indeterminate,
}

#[derive(Debug)]
pub enum AuthorityError {
    Database(ReferenceDatabaseError),
    Invalid(String),
    Conflict { operation_id: String },
    NotFound(String),
    InsufficientRights { requested: Rights, available: Rights },
    StaleGeneration { expected: u64, actual: u64 },
    Fenced,
    DispatchOpen,
    DispatchClosed,
    DestinationNotFresh,
    AlreadyCommitted,
    Rejected(String),
    Indeterminate,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "authority database error: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid authority request: {message}"),
            Self::Conflict { operation_id } => {
                write!(formatter, "operation {operation_id:?} conflicts with a previous request")
            }
            Self::NotFound(id) => write!(formatter, "authority object {id} not found"),
            Self::InsufficientRights { requested, available } => {
                write!(formatter, "rights {requested:?} exceed grant {available:?}")
            }
            Self::StaleGeneration { expected, actual } => {
                write!(formatter, "provider generation {expected} is stale (actual {actual})")
            }
            Self::Fenced => formatter.write_str("source binding is fenced"),
            Self::DispatchOpen => formatter.write_str("source provider dispatch is still open"),
            Self::DispatchClosed => formatter.write_str("provider dispatch is closed"),
            Self::DestinationNotFresh => formatter.write_str("destination binding is not fresh"),
            Self::AlreadyCommitted => formatter.write_str("operation is already committed"),
            Self::Rejected(reason) => write!(formatter, "authority rejected operation: {reason}"),
            Self::Indeterminate => {
                formatter.write_str("authority committed but acknowledgement was lost")
            }
        }
    }
}

impl std::error::Error for AuthorityError {}

impl From<ReferenceDatabaseError> for AuthorityError {
    fn from(error: ReferenceDatabaseError) -> Self {
        Self::Database(error)
    }
}

impl From<rusqlite::Error> for AuthorityError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(ReferenceDatabaseError::Sqlite(error))
    }
}

#[derive(Clone)]
pub struct Authority {
    pub(crate) database: ReferenceDatabase,
    lost_ack_once: Arc<AtomicBool>,
}

impl fmt::Debug for Authority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Authority").finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct BindingDigestMaterial<'a> {
    continuation: ContinuationId,
    snapshot: SnapshotId,
    source: &'a ExternalCoordinate,
    destination: &'a ExternalCoordinate,
    requirements: &'a [ResourceRequirement],
    preparation_digest: Digest,
}

#[derive(Serialize)]
struct OperationDigestMaterial<'a> {
    binding: BindingDigestMaterial<'a>,
    preparation: &'a BindingPreparationReceipt,
}

type BindingRow = (String, i64, i64, i64, String, i64, i64, i64);
type OperationRow = (Vec<u8>, String, Option<String>, String, i64, i64, String, Option<i64>);
type CommitRow = (String, Vec<u8>, String, String, String, i64, i64, String, i64, i64, Vec<u8>);
type ActivationPermitRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, Vec<u8>, i64, String);

impl Authority {
    pub fn new(database: ReferenceDatabase) -> Result<Self, AuthorityError> {
        database.lock()?.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(Self { database, lost_ack_once: Arc::new(AtomicBool::new(false)) })
    }

    pub fn database(&self) -> ReferenceDatabase {
        self.database.clone()
    }

    pub fn bootstrap(
        &self,
        source_owner: impl Into<String>,
        provider_generation: u64,
        rights: Rights,
    ) -> Result<SourceBinding, AuthorityError> {
        let owner = source_owner.into();
        if owner.is_empty() {
            return Err(AuthorityError::Invalid("source owner is empty".into()));
        }
        let binding_id = format!("source:{owner}:g{provider_generation}");
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        if let Some(row) = binding_row(&tx, &binding_id)? {
            if row.0 != owner
                || durable_u64(row.1, "provider_generation")? != provider_generation
                || durable_u64(row.2, "rights")? != rights.bits()
                || row.4 != "source"
            {
                return Err(AuthorityError::Conflict {
                    operation_id: format!("bootstrap:{binding_id}"),
                });
            }
            if !durable_bool(row.5, "active")? || durable_bool(row.6, "fenced")? {
                return Err(AuthorityError::Fenced);
            }
            if row.7 == 0 {
                return Err(AuthorityError::DispatchClosed);
            }
            tx.commit()?;
            return Ok(SourceBinding {
                binding_id,
                owner,
                provider_generation,
                rights,
                execution_epoch: durable_u64(row.3, "execution_epoch")?,
            });
        }
        let provider_generation_sql = durable_i64(provider_generation, "provider_generation")?;
        let rights_sql = durable_i64(rights.bits(), "rights")?;
        tx.execute(
            "INSERT INTO visa_authority_bindings
             (binding_id, owner, provider_generation, rights, execution_epoch, role, active,
              fenced, dispatch_open)
             VALUES (?1, ?2, ?3, ?4, 0, 'source', 1, 0, 1)",
            params![binding_id, owner, provider_generation_sql, rights_sql],
        )?;
        tx.commit()?;
        Ok(SourceBinding { binding_id, owner, provider_generation, rights, execution_epoch: 0 })
    }

    pub fn prepare(&self, request: PrepareRequest) -> Result<PrepareReceipt, AuthorityError> {
        if request.requirements.is_empty() {
            return Err(AuthorityError::Invalid(
                "preparation requires at least one resource requirement".into(),
            ));
        }
        validate_coordinate(&request.source)?;
        let source_binding_id = coordinate_text(&request.source)?;
        let destination_owner = coordinate_text(&request.destination)?;
        let operation_id = operation_text(request.operation);
        let request_digest = binding_digest(&request)?;
        let rights = requirements_rights(&request.requirements);
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;

        if let Some(row) = operation_row(&tx, &operation_id)? {
            let destination_binding_id = row
                .2
                .clone()
                .ok_or_else(|| AuthorityError::Rejected("preparation has no destination".into()))?;
            let source = binding_row(&tx, &source_binding_id)?
                .ok_or_else(|| AuthorityError::NotFound(source_binding_id.clone()))?;
            let destination = binding_row(&tx, &destination_binding_id)?
                .ok_or_else(|| AuthorityError::NotFound(destination_binding_id.clone()))?;
            if row.0 != request_digest.0
                || row.1 != source_binding_id
                || row.3 != source.0
                || row.4 != source.1
                || durable_u64(row.5, "rights")? != rights.bits()
                || destination.0 != destination_owner
            {
                return Err(AuthorityError::Conflict { operation_id });
            }
            if source.4 != "source" {
                return Err(AuthorityError::Invalid(
                    "preparation source is not a source binding".into(),
                ));
            }
            if destination.4 != "destination" {
                return Err(AuthorityError::Invalid(
                    "preparation destination is not a destination binding".into(),
                ));
            }
            if matches!(row.6.as_str(), "aborted" | "rejected") {
                return Err(AuthorityError::Rejected(format!("preparation is {}", row.6)));
            }
            let destination_generation = source_generation_successor(source.1)?;
            tx.commit()?;
            return prepare_receipt(
                &request,
                request_digest,
                source_binding_id,
                destination_binding_id,
                source,
                destination_owner,
                destination_generation,
                rights,
            );
        }

        let source = binding_row(&tx, &source_binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(source_binding_id.clone()))?;
        if source.4 != "source" {
            return Err(AuthorityError::Invalid(
                "preparation source is not a source binding".into(),
            ));
        }
        if !durable_bool(source.5, "active")? || durable_bool(source.6, "fenced")? {
            return Err(AuthorityError::Fenced);
        }
        if durable_bool(source.7, "dispatch_open")? {
            return Err(AuthorityError::DispatchOpen);
        }
        let available = Rights::from_bits(durable_u64(source.2, "rights")?);
        if !available.contains(rights) {
            return Err(AuthorityError::InsufficientRights { requested: rights, available });
        }
        let destination_generation = source_generation_successor(source.1)?;
        let destination_generation_sql =
            durable_i64(destination_generation, "provider_generation")?;
        let rights_sql = durable_i64(rights.bits(), "rights")?;
        let destination_binding_id = format!("destination:{operation_id}");
        tx.execute(
            "INSERT INTO visa_authority_bindings
             (binding_id, owner, provider_generation, rights, execution_epoch, role, active,
              fenced, dispatch_open, source_binding_id, operation_id)
             VALUES (?1, ?2, ?3, ?4, ?5, 'destination', 0, 0, 0, ?6, ?7)",
            params![
                destination_binding_id,
                destination_owner,
                destination_generation_sql,
                rights_sql,
                source.3,
                source_binding_id,
                operation_id,
            ],
        )?;
        tx.execute(
            "INSERT INTO visa_authority_operations
             (operation_id, request_digest, source_binding_id, destination_binding_id, source_owner,
              provider_generation, rights, status, source_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'prepared', ?8)",
            params![
                operation_id,
                request_digest.0,
                source_binding_id,
                destination_binding_id,
                source.0,
                source.1,
                rights_sql,
                source.3,
            ],
        )?;
        tx.commit()?;
        prepare_receipt(
            &request,
            request_digest,
            source_binding_id,
            destination_binding_id,
            source,
            destination_owner,
            destination_generation,
            rights,
        )
    }

    pub fn query_preparation(
        &self,
        request: &PrepareRequest,
    ) -> Result<Option<PrepareReceipt>, AuthorityError> {
        if request.requirements.is_empty() {
            return Err(AuthorityError::Invalid(
                "preparation requires at least one resource requirement".into(),
            ));
        }
        validate_coordinate(&request.source)?;
        let source_binding_id = coordinate_text(&request.source)?;
        let destination_owner = coordinate_text(&request.destination)?;
        let operation_id = operation_text(request.operation);
        let request_digest = binding_digest(request)?;
        let rights = requirements_rights(&request.requirements);
        let connection = self.database.lock()?;
        let Some(row) = operation_row(&connection, &operation_id)? else {
            return Ok(None);
        };
        let destination_binding_id = row
            .2
            .clone()
            .ok_or_else(|| AuthorityError::Rejected("preparation has no destination".into()))?;
        let source = binding_row(&connection, &source_binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(source_binding_id.clone()))?;
        let destination = binding_row(&connection, &destination_binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(destination_binding_id.clone()))?;
        if row.0 != request_digest.0
            || row.1 != source_binding_id
            || row.3 != source.0
            || row.4 != source.1
            || durable_u64(row.5, "rights")? != rights.bits()
            || destination.0 != destination_owner
        {
            return Err(AuthorityError::Conflict { operation_id });
        }
        if source.4 != "source" {
            return Err(AuthorityError::Invalid(
                "preparation source is not a source binding".into(),
            ));
        }
        if destination.4 != "destination" {
            return Err(AuthorityError::Invalid(
                "preparation destination is not a destination binding".into(),
            ));
        }
        if matches!(row.6.as_str(), "aborted" | "rejected") {
            return Err(AuthorityError::Rejected(format!("preparation is {}", row.6)));
        }
        let destination_generation = source_generation_successor(source.1)?;
        Ok(Some(prepare_receipt(
            request,
            request_digest,
            source_binding_id,
            destination_binding_id,
            source,
            destination_owner,
            destination_generation,
            rights,
        )?))
    }

    pub fn commit(&self, request: CommitRequest) -> Result<AuthorityCommitReceipt, AuthorityError> {
        validate_coordinate(&request.source)?;
        let source_binding_id = coordinate_text(&request.source)?;
        let destination_owner = coordinate_text(&request.destination)?;
        let destination_binding_id = preparation_binding(&request.preparation)?;
        let operation_id = operation_text(request.operation);
        let preparation_operation_id = operation_text(request.preparation.operation);
        let request_digest = commit_digest(&request)?;
        let rights = requirements_rights(&request.requirements);
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;

        if let Some(row) = commit_row(&tx, &operation_id)? {
            validate_commit_row(
                &row,
                &operation_id,
                &preparation_operation_id,
                request_digest,
                &source_binding_id,
                &destination_binding_id,
                rights,
            )?;
            let source = binding_row(&tx, &source_binding_id)?
                .ok_or_else(|| AuthorityError::NotFound(source_binding_id.clone()))?;
            if source.4 != "source" {
                return Err(AuthorityError::Invalid(
                    "commit source is not a source binding".into(),
                ));
            }
            if row.7 == "applied" {
                tx.commit()?;
                return commit_receipt_from_row(&request, request_digest, &row);
            }
            if row.7 == "rejected" {
                return Err(AuthorityError::Rejected("commit was rejected".into()));
            }
            return Err(AuthorityError::Indeterminate);
        }

        let preparation = operation_row(&tx, &preparation_operation_id)?
            .ok_or_else(|| AuthorityError::NotFound(preparation_operation_id.clone()))?;
        let source = binding_row(&tx, &source_binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(source_binding_id.clone()))?;
        let destination = binding_row(&tx, &destination_binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(destination_binding_id.clone()))?;
        let destination_generation = source_generation_successor(source.1)?;
        let expected_preparation = core_prepare_receipt(
            &PrepareRequest {
                operation: request.preparation.operation,
                continuation: request.continuation,
                snapshot: request.snapshot,
                source: request.source.clone(),
                destination: request.destination.clone(),
                requirements: request.requirements.clone(),
                preparation_digest: request.preparation_digest,
            },
            &destination_binding_id,
            destination_generation,
        );
        if expected_preparation != request.preparation
            || preparation.1 != source_binding_id
            || preparation.2.as_deref() != Some(&destination_binding_id)
            || preparation.3 != source.0
            || preparation.4 != source.1
            || durable_u64(preparation.5, "rights")? != rights.bits()
            || preparation.6 != "prepared"
        {
            return Err(AuthorityError::Conflict { operation_id: preparation_operation_id });
        }
        if !durable_bool(source.5, "active")? || durable_bool(source.6, "fenced")? {
            return Err(AuthorityError::Fenced);
        }
        if durable_bool(source.7, "dispatch_open")? {
            return Err(AuthorityError::DispatchOpen);
        }
        if source.4 != "source" {
            return Err(AuthorityError::Invalid("commit source is not a source binding".into()));
        }
        if destination.4 != "destination" {
            return Err(AuthorityError::Invalid(
                "commit destination is not a destination binding".into(),
            ));
        }
        let available = Rights::from_bits(durable_u64(source.2, "rights")?);
        if !available.contains(rights) {
            return Err(AuthorityError::InsufficientRights { requested: rights, available });
        }
        if destination.0 != destination_owner
            || durable_u64(destination.1, "provider_generation")? != destination_generation
            || durable_u64(destination.2, "rights")? != rights.bits()
            || durable_bool(destination.5, "active")?
            || durable_bool(destination.6, "fenced")?
            || durable_bool(destination.7, "dispatch_open")?
        {
            return Err(AuthorityError::DestinationNotFresh);
        }
        let destination_epoch = durable_u64(source.3, "execution_epoch")?
            .checked_add(1)
            .ok_or_else(|| AuthorityError::Invalid("execution epoch overflow".into()))?;
        let destination_epoch_sql = durable_i64(destination_epoch, "execution_epoch")?;
        let rights_sql = durable_i64(rights.bits(), "rights")?;
        let core_receipt = core_commit_receipt(
            &request,
            durable_u64(source.3, "execution_epoch")?,
            destination_epoch,
        );
        let core_receipt_bytes = postcard::to_allocvec(&core_receipt).map_err(|error| {
            AuthorityError::Invalid(format!("cannot encode commit receipt: {error}"))
        })?;
        if tx.execute(
            "UPDATE visa_authority_bindings
             SET active = 0, fenced = 1, dispatch_open = 0
             WHERE binding_id = ?1 AND active = 1 AND fenced = 0 AND dispatch_open = 0",
            params![source_binding_id],
        )? != 1
        {
            return Err(AuthorityError::Fenced);
        }
        if tx.execute(
            "UPDATE visa_authority_bindings
             SET active = 1, execution_epoch = ?2, dispatch_open = 0
             WHERE binding_id = ?1 AND active = 0 AND fenced = 0 AND dispatch_open = 0",
            params![destination_binding_id, destination_epoch_sql],
        )? != 1
        {
            return Err(AuthorityError::DestinationNotFresh);
        }
        if tx.execute(
            "UPDATE visa_authority_operations SET status = 'committed'
             WHERE operation_id = ?1 AND status = 'prepared'",
            params![preparation_operation_id],
        )? != 1
        {
            return Err(AuthorityError::DestinationNotFresh);
        }
        tx.execute(
            "INSERT INTO visa_authority_commits
             (operation_id, preparation_operation_id, request_digest, source_binding_id,
             destination_binding_id, source_owner, provider_generation, rights, status,
             source_epoch, destination_epoch, core_receipt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'applied', ?9, ?10, ?11)",
            params![
                operation_id,
                preparation_operation_id,
                request_digest.0,
                source_binding_id,
                destination_binding_id,
                source.0,
                source.1,
                rights_sql,
                source.3,
                destination_epoch_sql,
                core_receipt_bytes,
            ],
        )?;
        tx.commit()?;
        if self.lost_ack_once.swap(false, Ordering::SeqCst) {
            return Err(AuthorityError::Indeterminate);
        }
        let row = (
            preparation_operation_id,
            request_digest.0.to_vec(),
            source_binding_id,
            destination_binding_id,
            source.0,
            source.1,
            rights_sql,
            "applied".to_owned(),
            source.3,
            destination_epoch_sql,
            postcard::to_allocvec(&core_receipt).map_err(|error| {
                AuthorityError::Invalid(format!("cannot encode commit receipt: {error}"))
            })?,
        );
        commit_receipt_from_row(&request, request_digest, &row)
    }

    pub fn query_commit(&self, request: &CommitRequest) -> Result<OperationQuery, AuthorityError> {
        validate_coordinate(&request.source)?;
        let operation_id = operation_text(request.operation);
        let preparation_operation_id = operation_text(request.preparation.operation);
        let request_digest = commit_digest(request)?;
        let source_binding_id = coordinate_text(&request.source)?;
        let destination_binding_id = preparation_binding(&request.preparation)?;
        let rights = requirements_rights(&request.requirements);
        let connection = self.database.lock()?;
        let Some(row) = commit_row(&connection, &operation_id)? else {
            return Ok(OperationQuery::Absent);
        };
        validate_commit_row(
            &row,
            &operation_id,
            &preparation_operation_id,
            request_digest,
            &source_binding_id,
            &destination_binding_id,
            rights,
        )?;
        match row.7.as_str() {
            "applied" => Ok(OperationQuery::Applied(Box::new(commit_receipt_from_row(
                request,
                request_digest,
                &row,
            )?))),
            "rejected" => Ok(OperationQuery::Rejected("authority rejected commit".into())),
            _ => Ok(OperationQuery::Indeterminate),
        }
    }

    pub fn abort_preparation(
        &self,
        request: &AbortRequest,
    ) -> Result<AbortPreparationReceipt, AuthorityError> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        let validated = validate_abort_request(&tx, request)?;
        let operation_id = operation_text(request.operation);
        if let Some((digest, source, destination)) = abort_row(&tx, &operation_id)? {
            if digest != validated.request_digest.0
                || source != validated.source_binding_id
                || destination != validated.destination_binding_id
            {
                return Err(AuthorityError::Conflict { operation_id });
            }
            tx.commit()?;
            return Ok(validated.receipt);
        }
        if validated.preparation_status != "prepared" {
            return Err(AuthorityError::Conflict {
                operation_id: validated.preparation_operation_id,
            });
        }
        let source = binding_row(&tx, &validated.source_binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(validated.source_binding_id.clone()))?;
        if source.4 != "source" {
            return Err(AuthorityError::Invalid("abort source is not a source binding".into()));
        }
        if !durable_bool(source.5, "active")? || durable_bool(source.6, "fenced")? {
            return Err(AuthorityError::Fenced);
        }
        let destination = binding_row(&tx, &validated.destination_binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(validated.destination_binding_id.clone()))?;
        if destination.4 != "destination" {
            return Err(AuthorityError::Invalid(
                "abort destination is not a destination binding".into(),
            ));
        }
        if durable_bool(destination.5, "active")?
            || durable_bool(destination.6, "fenced")?
            || durable_bool(destination.7, "dispatch_open")?
        {
            return Err(AuthorityError::AlreadyCommitted);
        }
        let ownership: Option<(String, String)> = tx
            .query_row(
                "SELECT source_binding_id, operation_id FROM visa_authority_bindings
                 WHERE binding_id = ?1",
                params![validated.destination_binding_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if ownership.as_ref()
            != Some(&(
                validated.source_binding_id.clone(),
                validated.preparation_operation_id.clone(),
            ))
        {
            return Err(AuthorityError::Conflict {
                operation_id: validated.preparation_operation_id,
            });
        }
        if tx.execute(
            "UPDATE visa_authority_operations SET status = 'aborted'
             WHERE operation_id = ?1 AND status = 'prepared'",
            params![validated.preparation_operation_id],
        )? != 1
        {
            return Err(AuthorityError::AlreadyCommitted);
        }
        tx.execute(
            "DELETE FROM visa_authority_bindings WHERE binding_id = ?1",
            params![validated.destination_binding_id],
        )?;
        tx.execute(
            "INSERT INTO visa_authority_aborts
             (operation_id, request_digest, source_binding_id, destination_binding_id)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                operation_id,
                validated.request_digest.0,
                validated.source_binding_id,
                validated.destination_binding_id
            ],
        )?;
        tx.commit()?;
        Ok(validated.receipt)
    }

    pub fn query_abort(&self, request: &AbortRequest) -> Result<AbortQuery, AuthorityError> {
        let connection = self.database.lock()?;
        let validated = validate_abort_request(&connection, request)?;
        let operation_id = operation_text(request.operation);
        let Some((digest, source, destination)) = abort_row(&connection, &operation_id)? else {
            return Ok(AbortQuery::Absent);
        };
        if digest != validated.request_digest.0
            || source != validated.source_binding_id
            || destination != validated.destination_binding_id
            || validated.preparation_status != "aborted"
        {
            return Err(AuthorityError::Conflict { operation_id });
        }
        Ok(AbortQuery::Applied(Box::new(validated.receipt)))
    }

    /// Reopen a source only when no prepared destination remains. This covers
    /// local pre-snapshot rollback and source restoration after exact abort.
    pub fn resume_source(&self, binding_id: &str) -> Result<(), AuthorityError> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        let source = binding_row(&tx, binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(binding_id.to_owned()))?;
        if source.4 != "source" {
            return Err(AuthorityError::Invalid("resume target is not a source binding".into()));
        }
        if !durable_bool(source.5, "active")? || durable_bool(source.6, "fenced")? {
            return Err(AuthorityError::Fenced);
        }
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM visa_authority_operations
             WHERE source_binding_id = ?1 AND status = 'prepared'",
            params![binding_id],
            |row| row.get(0),
        )?;
        if pending != 0 {
            return Err(AuthorityError::DestinationNotFresh);
        }
        tx.execute(
            "UPDATE visa_authority_bindings SET dispatch_open = 1
             WHERE binding_id = ?1 AND active = 1 AND fenced = 0",
            params![binding_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Roll back a source dispatch opening if the reconstructed guest could
    /// not pass its local activation gate.
    pub fn close_source(&self, binding_id: &str) -> Result<(), AuthorityError> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        let source = binding_row(&tx, binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(binding_id.to_owned()))?;
        if source.4 != "source" {
            return Err(AuthorityError::Invalid("close target is not a source binding".into()));
        }
        if !durable_bool(source.5, "active")? || durable_bool(source.6, "fenced")? {
            return Err(AuthorityError::Fenced);
        }
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM visa_authority_operations
             WHERE source_binding_id = ?1 AND status = 'prepared'",
            params![binding_id],
            |row| row.get(0),
        )?;
        if pending != 0 {
            return Err(AuthorityError::DestinationNotFresh);
        }
        tx.execute(
            "UPDATE visa_authority_bindings SET dispatch_open = 0
             WHERE binding_id = ?1 AND active = 1 AND fenced = 0",
            params![binding_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Durably admit exactly one runtime activation owner and open provider
    /// dispatch for that owner in the same authority transaction.
    pub fn open_destination(
        &self,
        request: &ActivationAdmissionRequest,
    ) -> Result<(), AuthorityError> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        validate_activation_admission(&tx, request)?;
        let binding = binding_row(&tx, &request.destination_binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(request.destination_binding_id.clone()))?;
        let execution_epoch = durable_i64(request.commit.execution_epoch, "execution_epoch")?;
        if binding.4 != "destination"
            || !durable_bool(binding.5, "active")?
            || durable_bool(binding.6, "fenced")?
            || durable_u64(binding.3, "execution_epoch")? != request.commit.execution_epoch
        {
            return Err(AuthorityError::DestinationNotFresh);
        }
        let operation_id = operation_text(request.operation);
        let existing: Option<ActivationPermitRow> = tx
            .query_row(
                "SELECT continuation_id, snapshot_id, destination_authority, destination_value,
                        destination_binding_id, authority_commit_digest, execution_epoch, status
                 FROM visa_authority_activation_permits WHERE operation_id = ?1",
                params![operation_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing.0 != request.continuation.0
                || existing.1 != request.snapshot.0
                || existing.2 != request.destination.authority.0
                || existing.3 != request.destination.value
                || existing.4 != request.destination_binding_id
                || existing.5 != request.commit.receipt_digest.0
                || durable_u64(existing.6, "execution_epoch")? != request.commit.execution_epoch
            {
                return Err(AuthorityError::Conflict { operation_id });
            }
            if existing.7 == "activated" {
                return Err(AuthorityError::AlreadyCommitted);
            }
            if existing.7 != "admitted" {
                return Err(AuthorityError::Conflict { operation_id });
            }
        } else {
            let owner: Option<String> = tx
                .query_row(
                    "SELECT operation_id FROM visa_authority_activation_permits
                     WHERE destination_binding_id = ?1 AND execution_epoch = ?2",
                    params![request.destination_binding_id, execution_epoch],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(owner) = owner {
                return Err(AuthorityError::Conflict { operation_id: owner });
            }
            tx.execute(
                "INSERT INTO visa_authority_activation_permits
                 (operation_id, continuation_id, snapshot_id, destination_authority,
                  destination_value, destination_binding_id, authority_commit_digest,
                  execution_epoch, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'admitted')",
                params![
                    operation_id,
                    request.continuation.0,
                    request.snapshot.0,
                    request.destination.authority.0,
                    request.destination.value,
                    request.destination_binding_id,
                    request.commit.receipt_digest.0,
                    execution_epoch,
                ],
            )?;
        }
        if tx.execute(
            "UPDATE visa_authority_bindings SET dispatch_open = 1
             WHERE binding_id = ?1 AND active = 1 AND fenced = 0
               AND execution_epoch = ?2",
            params![request.destination_binding_id, execution_epoch],
        )? != 1
        {
            return Err(AuthorityError::DestinationNotFresh);
        }
        tx.commit()?;
        Ok(())
    }

    pub fn query_activation_admission(
        &self,
        request: &ActivationAdmissionRequest,
    ) -> Result<ActivationAdmissionState, AuthorityError> {
        let connection = self.database.lock()?;
        validate_activation_admission(&connection, request)?;
        let operation_id = operation_text(request.operation);
        let existing: Option<ActivationPermitRow> = connection
            .query_row(
                "SELECT continuation_id, snapshot_id, destination_authority,
                            destination_value, destination_binding_id, authority_commit_digest,
                            execution_epoch, status
                     FROM visa_authority_activation_permits WHERE operation_id = ?1",
                params![operation_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;
        let Some(existing) = existing else {
            return Ok(ActivationAdmissionState::Absent);
        };
        if existing.0 != request.continuation.0
            || existing.1 != request.snapshot.0
            || existing.2 != request.destination.authority.0
            || existing.3 != request.destination.value
            || existing.4 != request.destination_binding_id
            || existing.5 != request.commit.receipt_digest.0
            || durable_u64(existing.6, "execution_epoch")? != request.commit.execution_epoch
        {
            return Err(AuthorityError::Conflict { operation_id });
        }
        match existing.7.as_str() {
            "admitted" => Ok(ActivationAdmissionState::Admitted),
            "activated" => Ok(ActivationAdmissionState::Activated),
            _ => Err(AuthorityError::Conflict { operation_id }),
        }
    }

    /// Persist the runtime's successful local gate transition. Only this
    /// state produces an activation receipt during exact queries.
    pub fn confirm_destination_activation(
        &self,
        request: &ActivationAdmissionRequest,
    ) -> Result<(), AuthorityError> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        validate_activation_admission(&tx, request)?;
        let operation_id = operation_text(request.operation);
        let Some(existing): Option<ActivationPermitRow> = tx
            .query_row(
                "SELECT continuation_id, snapshot_id, destination_authority, destination_value,
                        destination_binding_id, authority_commit_digest, execution_epoch, status
                 FROM visa_authority_activation_permits WHERE operation_id = ?1",
                params![operation_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?
        else {
            return Err(AuthorityError::DestinationNotFresh);
        };
        validate_activation_permit(&existing, request)?;
        if existing.7 == "activated" {
            tx.commit()?;
            return Ok(());
        }
        if existing.7 != "admitted" {
            return Err(AuthorityError::Conflict { operation_id });
        }
        if tx.execute(
            "UPDATE visa_authority_activation_permits SET status = 'activated'
             WHERE operation_id = ?1 AND destination_binding_id = ?2
               AND authority_commit_digest = ?3 AND execution_epoch = ?4
               AND status = 'admitted'",
            params![
                operation_id,
                request.destination_binding_id,
                request.commit.receipt_digest.0,
                durable_i64(request.commit.execution_epoch, "execution_epoch")?,
            ],
        )? != 1
        {
            return Err(AuthorityError::DestinationNotFresh);
        }
        if tx.execute(
            "UPDATE visa_authority_bindings SET role = 'source'
             WHERE binding_id = ?1 AND role = 'destination' AND active = 1
               AND fenced = 0 AND execution_epoch = ?2",
            params![
                request.destination_binding_id,
                durable_i64(request.commit.execution_epoch, "execution_epoch")?,
            ],
        )? != 1
        {
            return Err(AuthorityError::DestinationNotFresh);
        }
        tx.commit()?;
        Ok(())
    }

    /// Roll back provider dispatch if local guest activation fails after the
    /// authority has admitted the committed destination.
    pub fn close_destination(
        &self,
        request: &ActivationAdmissionRequest,
    ) -> Result<(), AuthorityError> {
        let connection = self.database.lock()?;
        let tx = connection.unchecked_transaction()?;
        validate_activation_admission(&tx, request)?;
        let operation_id = operation_text(request.operation);
        let Some(existing): Option<ActivationPermitRow> = tx
            .query_row(
                "SELECT continuation_id, snapshot_id, destination_authority, destination_value,
                        destination_binding_id, authority_commit_digest, execution_epoch, status
                 FROM visa_authority_activation_permits WHERE operation_id = ?1",
                params![operation_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?
        else {
            tx.commit()?;
            return Ok(());
        };
        validate_activation_permit(&existing, request)?;
        if existing.7 == "activated" {
            return Err(AuthorityError::AlreadyCommitted);
        }
        if existing.7 != "admitted" {
            return Err(AuthorityError::Conflict { operation_id });
        }
        let binding = binding_row(&tx, &request.destination_binding_id)?
            .ok_or_else(|| AuthorityError::NotFound(request.destination_binding_id.clone()))?;
        let execution_epoch = durable_i64(request.commit.execution_epoch, "execution_epoch")?;
        if binding.4 != "destination"
            || !durable_bool(binding.5, "active")?
            || durable_bool(binding.6, "fenced")?
            || durable_u64(binding.3, "execution_epoch")? != request.commit.execution_epoch
        {
            return Err(AuthorityError::DestinationNotFresh);
        }
        if tx.execute(
            "UPDATE visa_authority_bindings SET dispatch_open = 0
             WHERE binding_id = ?1 AND active = 1 AND fenced = 0
               AND execution_epoch = ?2",
            params![request.destination_binding_id, execution_epoch],
        )? != 1
        {
            return Err(AuthorityError::DestinationNotFresh);
        }
        if tx.execute(
            "DELETE FROM visa_authority_activation_permits
             WHERE operation_id = ?1 AND status = 'admitted'
               AND destination_binding_id = ?2 AND authority_commit_digest = ?3
               AND execution_epoch = ?4",
            params![
                operation_id,
                request.destination_binding_id,
                request.commit.receipt_digest.0,
                execution_epoch,
            ],
        )? != 1
        {
            return Err(AuthorityError::DestinationNotFresh);
        }
        tx.commit()?;
        Ok(())
    }

    pub fn binding(&self, binding_id: &str) -> Result<Option<BindingView>, AuthorityError> {
        let connection = self.database.lock()?;
        let Some(row) = binding_row(&connection, binding_id)? else { return Ok(None) };
        let role = match row.4.as_str() {
            "source" => BindingRole::Source,
            "destination" => BindingRole::Destination,
            _ => return Err(AuthorityError::Invalid("binding has an unknown role".into())),
        };
        Ok(Some(BindingView {
            binding_id: binding_id.to_owned(),
            owner: row.0,
            provider_generation: durable_u64(row.1, "provider_generation")?,
            rights: Rights::from_bits(durable_u64(row.2, "rights")?),
            execution_epoch: durable_u64(row.3, "execution_epoch")?,
            role,
            active: durable_bool(row.5, "active")?,
            fenced: durable_bool(row.6, "fenced")?,
            dispatch_open: durable_bool(row.7, "dispatch_open")?,
        }))
    }

    pub fn inject_lost_ack_once(&self) {
        self.lost_ack_once.store(true, Ordering::SeqCst);
    }
}

fn validate_coordinate(coordinate: &ExternalCoordinate) -> Result<(), AuthorityError> {
    if coordinate.authority != REFERENCE_AUTHORITY_ID {
        return Err(AuthorityError::Invalid("coordinate has the wrong authority".into()));
    }
    let _ = coordinate_text(coordinate)?;
    Ok(())
}

fn validate_activation_admission(
    connection: &rusqlite::Connection,
    request: &ActivationAdmissionRequest,
) -> Result<(), AuthorityError> {
    validate_coordinate(&request.destination)?;
    request
        .commit
        .verify()
        .map_err(|error| AuthorityError::Invalid(format!("invalid commit receipt: {error}")))?;
    if request.commit.continuation != request.continuation
        || request.commit.snapshot != request.snapshot
        || request.commit.destination != request.destination
    {
        return Err(AuthorityError::Invalid(
            "activation admission does not match the authority commit".into(),
        ));
    }
    let commit_operation = operation_text(request.commit.operation);
    let row = commit_row(connection, &commit_operation)?
        .ok_or_else(|| AuthorityError::NotFound(commit_operation.clone()))?;
    let stored_receipt: CoreCommitReceipt = postcard::from_bytes(&row.10).map_err(|error| {
        AuthorityError::Invalid(format!("durable commit receipt is corrupt: {error}"))
    })?;
    stored_receipt.verify().map_err(|error| {
        AuthorityError::Invalid(format!("durable commit receipt is invalid: {error}"))
    })?;
    if stored_receipt != request.commit {
        return Err(AuthorityError::Conflict { operation_id: commit_operation });
    }
    let source_binding_id = coordinate_text(&request.commit.source)?;
    let destination_owner = coordinate_text(&request.commit.destination)?;
    let source = binding_row(connection, &source_binding_id)?
        .ok_or_else(|| AuthorityError::NotFound(source_binding_id.clone()))?;
    let destination = binding_row(connection, &request.destination_binding_id)?
        .ok_or_else(|| AuthorityError::NotFound(request.destination_binding_id.clone()))?;
    let row_provider_generation = durable_u64(row.5, "provider_generation")?;
    let row_rights = durable_u64(row.6, "rights")?;
    if row.2 != source_binding_id
        || row.4 != source.0
        || row.8 != source.3
        || source.4 != "source"
        || destination.0 != destination_owner
        || !matches!(destination.4.as_str(), "destination" | "source")
        || durable_u64(destination.1, "provider_generation")?
            != row_provider_generation
                .checked_add(1)
                .ok_or_else(|| AuthorityError::Invalid("provider generation overflow".into()))?
        || durable_u64(destination.2, "rights")? != row_rights
        || destination.3 != row.9
    {
        return Err(AuthorityError::Conflict { operation_id: commit_operation });
    }
    if row.3 != request.destination_binding_id
        || row.7 != "applied"
        || durable_u64(row.9, "destination_epoch")? != request.commit.execution_epoch
    {
        return Err(AuthorityError::Conflict { operation_id: commit_operation });
    }
    Ok(())
}

fn validate_activation_permit(
    existing: &ActivationPermitRow,
    request: &ActivationAdmissionRequest,
) -> Result<(), AuthorityError> {
    if existing.0 != request.continuation.0
        || existing.1 != request.snapshot.0
        || existing.2 != request.destination.authority.0
        || existing.3 != request.destination.value
        || existing.4 != request.destination_binding_id
        || existing.5 != request.commit.receipt_digest.0
        || durable_u64(existing.6, "execution_epoch")? != request.commit.execution_epoch
    {
        return Err(AuthorityError::Conflict { operation_id: operation_text(request.operation) });
    }
    Ok(())
}

fn coordinate_text(coordinate: &ExternalCoordinate) -> Result<String, AuthorityError> {
    if coordinate.authority != REFERENCE_AUTHORITY_ID {
        return Err(AuthorityError::Invalid("coordinate has the wrong authority".into()));
    }
    String::from_utf8(coordinate.value.clone())
        .map_err(|_| AuthorityError::Invalid("coordinate value is not exact UTF-8".into()))
}

fn operation_text(operation: OperationId) -> String {
    operation.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn requirements_rights(requirements: &[ResourceRequirement]) -> Rights {
    requirements.iter().fold(Rights::default(), |rights, requirement| {
        rights | Rights::from_bits(requirement.required_rights.0)
    })
}

fn binding_material(request: &PrepareRequest) -> BindingDigestMaterial<'_> {
    BindingDigestMaterial {
        continuation: request.continuation,
        snapshot: request.snapshot,
        source: &request.source,
        destination: &request.destination,
        requirements: &request.requirements,
        preparation_digest: request.preparation_digest,
    }
}

fn binding_digest(request: &PrepareRequest) -> Result<Digest, AuthorityError> {
    canonical_digest(&binding_material(request))
        .map_err(|error| AuthorityError::Invalid(format!("cannot encode binding: {error}")))
}

fn commit_digest(request: &CommitRequest) -> Result<Digest, AuthorityError> {
    canonical_digest(&OperationDigestMaterial {
        binding: BindingDigestMaterial {
            continuation: request.continuation,
            snapshot: request.snapshot,
            source: &request.source,
            destination: &request.destination,
            requirements: &request.requirements,
            preparation_digest: request.preparation_digest,
        },
        preparation: &request.preparation,
    })
    .map_err(|error| AuthorityError::Invalid(format!("cannot encode commit: {error}")))
}

fn abort_digest(request: &AbortRequest) -> Result<Digest, AuthorityError> {
    canonical_digest(&OperationDigestMaterial {
        binding: BindingDigestMaterial {
            continuation: request.continuation,
            snapshot: request.snapshot,
            source: &request.source,
            destination: &request.destination,
            requirements: &request.requirements,
            preparation_digest: request.preparation_digest,
        },
        preparation: &request.preparation,
    })
    .map_err(|error| AuthorityError::Invalid(format!("cannot encode abort: {error}")))
}

struct ValidatedAbort {
    request_digest: Digest,
    source_binding_id: String,
    destination_binding_id: String,
    preparation_operation_id: String,
    preparation_status: String,
    receipt: AbortPreparationReceipt,
}

fn validate_abort_request(
    connection: &rusqlite::Connection,
    request: &AbortRequest,
) -> Result<ValidatedAbort, AuthorityError> {
    request.preparation.verify().map_err(|error| {
        AuthorityError::Invalid(format!("invalid preparation receipt: {error}"))
    })?;
    validate_coordinate(&request.source)?;
    validate_coordinate(&request.destination)?;
    let source_binding_id = coordinate_text(&request.source)?;
    let destination_binding_id = preparation_binding(&request.preparation)?;
    let preparation_operation_id = operation_text(request.preparation.operation);
    let preparation = operation_row(connection, &preparation_operation_id)?
        .ok_or_else(|| AuthorityError::NotFound(preparation_operation_id.clone()))?;
    let source = binding_row(connection, &source_binding_id)?
        .ok_or_else(|| AuthorityError::NotFound(source_binding_id.clone()))?;
    if source.4 != "source" {
        return Err(AuthorityError::Invalid("abort source is not a source binding".into()));
    }
    let destination = binding_row(connection, &destination_binding_id)?;
    if destination.as_ref().is_some_and(|row| row.4 != "destination") {
        return Err(AuthorityError::Invalid(
            "abort destination is not a destination binding".into(),
        ));
    }
    let rights = requirements_rights(&request.requirements);
    let prepare_request = PrepareRequest {
        operation: request.preparation.operation,
        continuation: request.continuation,
        snapshot: request.snapshot,
        source: request.source.clone(),
        destination: request.destination.clone(),
        requirements: request.requirements.clone(),
        preparation_digest: request.preparation_digest,
    };
    let binding_request_digest = binding_digest(&prepare_request)?;
    let expected_preparation = core_prepare_receipt(
        &prepare_request,
        &destination_binding_id,
        source_generation_successor(source.1)?,
    );
    if expected_preparation != request.preparation
        || preparation.0 != binding_request_digest.0
        || preparation.1 != source_binding_id
        || preparation.2.as_deref() != Some(&destination_binding_id)
        || preparation.3 != source.0
        || preparation.4 != source.1
        || durable_u64(preparation.5, "rights")? != rights.bits()
        || !matches!(preparation.6.as_str(), "prepared" | "aborted")
        || (preparation.6 == "prepared" && destination.is_none())
    {
        return Err(AuthorityError::Conflict { operation_id: preparation_operation_id });
    }
    let request_digest = abort_digest(request)?;
    let receipt = AbortPreparationReceipt {
        operation: request.operation,
        continuation: request.continuation,
        snapshot: request.snapshot,
        snapshot_digest: request.preparation.snapshot_digest,
        source: request.source.clone(),
        destination: request.destination.clone(),
        preparation_receipt_digest: request.preparation.receipt_digest,
        receipt_digest: Digest::ZERO,
    }
    .seal()
    .map_err(|error| AuthorityError::Invalid(format!("cannot encode abort receipt: {error}")))?;
    Ok(ValidatedAbort {
        request_digest,
        source_binding_id,
        destination_binding_id,
        preparation_operation_id,
        preparation_status: preparation.6,
        receipt,
    })
}

fn source_generation_successor(source_generation: i64) -> Result<u64, AuthorityError> {
    durable_u64(source_generation, "provider_generation")?
        .checked_add(1)
        .ok_or_else(|| AuthorityError::Invalid("provider generation overflow".into()))
}

fn durable_u64(value: i64, field: &str) -> Result<u64, AuthorityError> {
    sqlite_to_u64(value, field).map_err(AuthorityError::from)
}

fn durable_i64(value: u64, field: &str) -> Result<i64, AuthorityError> {
    u64_to_sqlite(value, field).map_err(AuthorityError::from)
}

fn durable_bool(value: i64, field: &str) -> Result<bool, AuthorityError> {
    sqlite_bool(value, field).map_err(AuthorityError::from)
}

fn preparation_binding(receipt: &BindingPreparationReceipt) -> Result<String, AuthorityError> {
    let Some(first) = receipt.grants.first() else {
        return Err(AuthorityError::Invalid("preparation has no binding grants".into()));
    };
    let binding = coordinate_text(&first.binding)?;
    if receipt
        .grants
        .iter()
        .any(|grant| grant.binding != first.binding || grant.provider != first.provider)
    {
        return Err(AuthorityError::Invalid("preparation grants disagree on binding".into()));
    }
    Ok(binding)
}

fn core_prepare_receipt(
    request: &PrepareRequest,
    destination_binding_id: &str,
    destination_generation: u64,
) -> BindingPreparationReceipt {
    let provider = ExternalCoordinate {
        authority: REFERENCE_AUTHORITY_ID,
        value: format!("provider:g{destination_generation}").into_bytes(),
    };
    let binding = ExternalCoordinate {
        authority: REFERENCE_AUTHORITY_ID,
        value: destination_binding_id.as_bytes().to_vec(),
    };
    BindingPreparationReceipt {
        operation: request.operation,
        continuation: request.continuation,
        snapshot: request.snapshot,
        snapshot_digest: request.preparation_digest,
        destination: request.destination.clone(),
        grants: request
            .requirements
            .iter()
            .map(|requirement| BindingGrant {
                requirement: requirement.id,
                provider: provider.clone(),
                provider_generation: destination_generation,
                binding: binding.clone(),
                granted_rights: requirement.required_rights,
            })
            .collect(),
        receipt_digest: Digest::ZERO,
    }
    .seal()
    .expect("reference preparation receipt is encodable")
}

#[allow(clippy::too_many_arguments)]
fn prepare_receipt(
    request: &PrepareRequest,
    request_digest: Digest,
    source_binding_id: String,
    destination_binding_id: String,
    source: BindingRow,
    destination_owner: String,
    destination_generation: u64,
    rights: Rights,
) -> Result<PrepareReceipt, AuthorityError> {
    Ok(PrepareReceipt {
        request_digest,
        source_binding_id,
        destination_binding_id: destination_binding_id.clone(),
        source_owner: source.0,
        destination_owner,
        provider_generation: destination_generation,
        rights,
        source_execution_epoch: durable_u64(source.3, "execution_epoch")?,
        core_receipt: core_prepare_receipt(
            request,
            &destination_binding_id,
            destination_generation,
        ),
    })
}

fn core_commit_receipt(
    request: &CommitRequest,
    source_epoch: u64,
    destination_epoch: u64,
) -> CoreCommitReceipt {
    CoreCommitReceipt {
        operation: request.operation,
        continuation: request.continuation,
        snapshot: request.snapshot,
        snapshot_digest: request.preparation.snapshot_digest,
        source: request.source.clone(),
        source_fence_epoch: source_epoch,
        destination: request.destination.clone(),
        binding_receipt_digest: request.preparation.receipt_digest,
        execution_epoch: destination_epoch,
        receipt_digest: Digest::ZERO,
    }
    .seal()
    .expect("reference commit receipt is encodable")
}

fn commit_receipt_from_row(
    request: &CommitRequest,
    request_digest: Digest,
    row: &CommitRow,
) -> Result<AuthorityCommitReceipt, AuthorityError> {
    let core_receipt: CoreCommitReceipt = postcard::from_bytes(&row.10).map_err(|error| {
        AuthorityError::Invalid(format!("durable commit receipt is corrupt: {error}"))
    })?;
    core_receipt.verify().map_err(|error| {
        AuthorityError::Invalid(format!("durable commit receipt is invalid: {error}"))
    })?;
    if core_receipt
        != core_commit_receipt(
            request,
            durable_u64(row.8, "source_epoch")?,
            durable_u64(row.9, "destination_epoch")?,
        )
    {
        return Err(AuthorityError::Conflict { operation_id: operation_text(request.operation) });
    }
    Ok(AuthorityCommitReceipt {
        request_digest,
        source_binding_id: row.2.clone(),
        destination_binding_id: row.3.clone(),
        source_owner: row.4.clone(),
        provider_generation: durable_u64(row.5, "provider_generation")?
            .checked_add(1)
            .ok_or_else(|| AuthorityError::Invalid("provider generation overflow".into()))?,
        granted_rights: Rights::from_bits(durable_u64(row.6, "rights")?),
        source_execution_epoch: durable_u64(row.8, "source_epoch")?,
        destination_execution_epoch: durable_u64(row.9, "destination_epoch")?,
        core_receipt,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_commit_row(
    row: &CommitRow,
    operation_id: &str,
    preparation_operation_id: &str,
    request_digest: Digest,
    source_binding_id: &str,
    destination_binding_id: &str,
    rights: Rights,
) -> Result<(), AuthorityError> {
    if row.0 != preparation_operation_id
        || row.1 != request_digest.0
        || row.2 != source_binding_id
        || row.3 != destination_binding_id
        || durable_u64(row.6, "rights")? != rights.bits()
    {
        return Err(AuthorityError::Conflict { operation_id: operation_id.to_owned() });
    }
    Ok(())
}

fn binding_row(
    connection: &rusqlite::Connection,
    binding_id: &str,
) -> Result<Option<BindingRow>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT owner, provider_generation, rights, execution_epoch, role, active, fenced,
                    dispatch_open
             FROM visa_authority_bindings WHERE binding_id = ?1",
            params![binding_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
}

fn operation_row(
    connection: &rusqlite::Connection,
    operation_id: &str,
) -> Result<Option<OperationRow>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT request_digest, source_binding_id, destination_binding_id, source_owner,
                    provider_generation, rights, status, source_epoch
             FROM visa_authority_operations WHERE operation_id = ?1",
            params![operation_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
}

fn commit_row(
    connection: &rusqlite::Connection,
    operation_id: &str,
) -> Result<Option<CommitRow>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT preparation_operation_id, request_digest, source_binding_id,
                    destination_binding_id, source_owner, provider_generation, rights, status,
                    source_epoch, destination_epoch, core_receipt
             FROM visa_authority_commits WHERE operation_id = ?1",
            params![operation_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            },
        )
        .optional()
}

fn abort_row(
    connection: &rusqlite::Connection,
    operation_id: &str,
) -> Result<Option<(Vec<u8>, String, String)>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT request_digest, source_binding_id, destination_binding_id
             FROM visa_authority_aborts WHERE operation_id = ?1",
            params![operation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use visa_core::{RebindDisposition, RequirementId, Rights as CoreRights};

    fn coordinate(value: &str) -> ExternalCoordinate {
        ExternalCoordinate { authority: REFERENCE_AUTHORITY_ID, value: value.as_bytes().to_vec() }
    }

    fn requirement() -> ResourceRequirement {
        ResourceRequirement {
            id: RequirementId::from_u128(1),
            kind: b"kv".to_vec(),
            logical_name: b"counter".to_vec(),
            required_rights: CoreRights(Rights::READ.bits() | Rights::WRITE.bits()),
            disposition: RebindDisposition::Reconnect,
            profile_data: Vec::new(),
        }
    }

    fn prepare_request(source: &SourceBinding) -> PrepareRequest {
        PrepareRequest {
            operation: OperationId::from_u128(10),
            continuation: ContinuationId::from_u128(11),
            snapshot: SnapshotId::from_u128(12),
            source: coordinate(&source.binding_id),
            destination: coordinate("next-world"),
            requirements: vec![requirement()],
            preparation_digest: Digest::of_bytes(b"snapshot"),
        }
    }

    fn setup() -> (Authority, SourceBinding) {
        let database = ReferenceDatabase::in_memory().unwrap();
        let authority = Authority::new(database).unwrap();
        let source = authority
            .bootstrap("owner", 7, Rights::READ | Rights::WRITE | Rights::SESSION)
            .unwrap();
        {
            let connection = authority.database.lock().unwrap();
            connection
                .execute(
                    "UPDATE visa_authority_bindings SET dispatch_open = 0 WHERE binding_id = ?1",
                    params![source.binding_id],
                )
                .unwrap();
        }
        (authority, source)
    }

    #[test]
    fn exact_prepare_commit_and_query_are_idempotent() {
        let (authority, source) = setup();
        let prepare = prepare_request(&source);
        let prepared = authority.prepare(prepare.clone()).unwrap();
        assert_eq!(prepared, authority.prepare(prepare.clone()).unwrap());
        assert_eq!(prepared.provider_generation, 8);
        let commit = CommitRequest {
            operation: OperationId::from_u128(20),
            continuation: prepare.continuation,
            snapshot: prepare.snapshot,
            source: prepare.source,
            destination: prepare.destination,
            requirements: prepare.requirements,
            preparation_digest: prepare.preparation_digest,
            preparation: prepared.core_receipt,
        };
        let receipt = authority.commit(commit.clone()).unwrap();
        assert_eq!(receipt, authority.commit(commit.clone()).unwrap());
        assert!(matches!(authority.query_commit(&commit).unwrap(), OperationQuery::Applied(_)));
        let mut wrong = commit;
        wrong.operation = OperationId::from_u128(21);
        assert_eq!(authority.query_commit(&wrong).unwrap(), OperationQuery::Absent);
    }

    #[test]
    fn same_operation_cannot_change_destination_or_authority() {
        let (authority, source) = setup();
        let request = prepare_request(&source);
        authority.prepare(request.clone()).unwrap();
        let mut changed = request.clone();
        changed.destination = coordinate("different-world");
        assert!(matches!(authority.prepare(changed), Err(AuthorityError::Conflict { .. })));
        let mut wrong_authority = request;
        wrong_authority.source.authority = AuthorityId::from_u128(99);
        assert!(matches!(authority.prepare(wrong_authority), Err(AuthorityError::Invalid(_))));
    }

    #[test]
    fn abort_is_exact_and_allows_source_resume() {
        let (authority, source) = setup();
        let prepare = prepare_request(&source);
        let prepared = authority.prepare(prepare.clone()).unwrap();
        let abort = AbortRequest {
            operation: OperationId::from_u128(30),
            continuation: prepare.continuation,
            snapshot: prepare.snapshot,
            source: prepare.source,
            destination: prepare.destination,
            requirements: prepare.requirements,
            preparation_digest: prepare.preparation_digest,
            preparation: prepared.core_receipt,
        };
        let mut forged = abort.clone();
        forged.preparation.snapshot = SnapshotId::from_u128(999);
        forged.preparation = forged.preparation.seal().unwrap();
        assert!(matches!(
            authority.abort_preparation(&forged),
            Err(AuthorityError::Conflict { .. })
        ));
        authority.abort_preparation(&abort).unwrap();
        authority.abort_preparation(&abort).unwrap();
        assert!(matches!(
            authority.query_abort(&abort).unwrap(),
            AbortQuery::Applied(receipt) if receipt.verify().is_ok()
        ));
        authority.resume_source(&source.binding_id).unwrap();
        assert!(authority.binding(&source.binding_id).unwrap().unwrap().dispatch_open);
    }

    #[test]
    fn empty_requirements_are_rejected_before_preparation_state_changes() {
        let (authority, source) = setup();
        let mut request = prepare_request(&source);
        request.requirements.clear();
        assert!(matches!(
            authority.prepare(request),
            Err(AuthorityError::Invalid(message)) if message.contains("at least one")
        ));
        let binding = authority.binding(&source.binding_id).unwrap().unwrap();
        assert!(binding.active && !binding.fenced && !binding.dispatch_open);
    }

    #[test]
    fn activation_requires_the_exact_durable_core_commit_receipt() {
        let (authority, source) = setup();
        let prepare = prepare_request(&source);
        let prepared = authority.prepare(prepare.clone()).unwrap();
        let commit = CommitRequest {
            operation: OperationId::from_u128(40),
            continuation: prepare.continuation,
            snapshot: prepare.snapshot,
            source: prepare.source,
            destination: prepare.destination,
            requirements: prepare.requirements,
            preparation_digest: prepare.preparation_digest,
            preparation: prepared.core_receipt,
        };
        let receipt = authority.commit(commit).unwrap();
        let mut forged = receipt.core_receipt.clone();
        forged.source_fence_epoch += 1;
        forged = forged.seal().unwrap();
        let request = ActivationAdmissionRequest {
            operation: forged.operation,
            continuation: forged.continuation,
            snapshot: forged.snapshot,
            destination: forged.destination.clone(),
            destination_binding_id: receipt.destination_binding_id,
            commit: forged,
        };
        assert!(matches!(
            authority.open_destination(&request),
            Err(AuthorityError::Conflict { .. })
        ));
    }
}
