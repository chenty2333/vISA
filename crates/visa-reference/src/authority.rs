//! Binding authority for the reference continuation vertical.

use std::fmt;

use rusqlite::{OptionalExtension, params};
use visa_coordinator::{Action, ActionRequest, AuthorityPort, Observation};
use visa_core::{
    AbortPreparationReceipt, ActivationPermitReceipt, AuthorityCommitReceipt, AuthorityId,
    BindingGrant, BindingPreparationReceipt, Digest, ExternalCoordinate, OpaqueBytes, OperationId,
    RebindDisposition, Rights, canonical_digest,
};

use crate::db::{
    ReferenceDatabase, ReferenceDatabaseError, sqlite_bool, sqlite_to_u64, u64_to_sqlite,
};

pub type BindingId = String;

pub const REFERENCE_AUTHORITY_ID: AuthorityId = AuthorityId::from_u128(1);
const MAX_RECEIPT_BYTES: usize = 64 * 1024;
const MAX_REJECTION_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingRole {
    Source,
    Destination,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingView {
    pub binding_id: BindingId,
    pub owner: String,
    pub generation: u64,
    pub rights: Rights,
    pub execution_epoch: u64,
    pub role: BindingRole,
    pub active: bool,
    pub fenced: bool,
    pub dispatch_open: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceBinding {
    pub binding_id: BindingId,
    pub owner: String,
    pub generation: u64,
    pub rights: Rights,
    pub execution_epoch: u64,
}

#[derive(Debug)]
pub enum AuthorityError {
    Database(ReferenceDatabaseError),
    Invalid(String),
    Conflict(String),
    Corrupt(String),
    NotFound(String),
    Fenced,
    Rejected(String),
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "authority database error: {error}"),
            Self::Invalid(reason) => write!(formatter, "invalid authority request: {reason}"),
            Self::Conflict(operation) => {
                write!(formatter, "conflicting exact operation: {operation}")
            }
            Self::Corrupt(reason) => write!(formatter, "corrupt authority outcome: {reason}"),
            Self::NotFound(binding) => write!(formatter, "binding not found: {binding}"),
            Self::Fenced => formatter.write_str("source binding is permanently fenced"),
            Self::Rejected(reason) => write!(formatter, "authority rejected request: {reason}"),
        }
    }
}

impl std::error::Error for AuthorityError {}

impl From<ReferenceDatabaseError> for AuthorityError {
    fn from(value: ReferenceDatabaseError) -> Self {
        Self::Database(value)
    }
}

impl From<rusqlite::Error> for AuthorityError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value.into())
    }
}

#[derive(Clone, Debug)]
pub struct Authority {
    database: ReferenceDatabase,
}

impl Authority {
    pub fn new(database: ReferenceDatabase) -> Result<Self, AuthorityError> {
        database.lock()?.execute_batch("PRAGMA foreign_keys = ON")?;
        Ok(Self { database })
    }

    pub fn database(&self) -> ReferenceDatabase {
        self.database.clone()
    }

    /// Create the sole initial source binding. Repeating the same bootstrap is
    /// idempotent; a different material claim for the same owner is rejected.
    pub fn bootstrap_source(
        &self,
        owner: impl Into<String>,
        generation: u64,
        rights: Rights,
    ) -> Result<SourceBinding, AuthorityError> {
        let owner = owner.into();
        if owner.is_empty() {
            return Err(AuthorityError::Invalid("source owner is empty".into()));
        }
        let binding_id = format!("source:{owner}");
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        if let Some(view) = binding_in(&transaction, &binding_id)? {
            if view.role != BindingRole::Source
                || view.owner != owner
                || view.generation != generation
                || view.rights != rights
            {
                return Err(AuthorityError::Conflict(format!("bootstrap:{binding_id}")));
            }
            if view.fenced {
                return Err(AuthorityError::Fenced);
            }
            transaction.commit()?;
            return Ok(SourceBinding {
                binding_id,
                owner,
                generation,
                rights,
                execution_epoch: view.execution_epoch,
            });
        }
        transaction.execute(
            "INSERT INTO visa_authority_bindings
             (binding_id, owner, generation, rights, epoch, role, active, fenced, dispatch_open,
              phase)
             VALUES (?1, ?2, ?3, ?4, 0, 'source', 1, 0, 1, 'source')",
            params![
                binding_id,
                owner,
                u64_to_sqlite(generation, "binding generation")?,
                u64_to_sqlite(rights.0, "binding rights")?,
            ],
        )?;
        transaction.commit()?;
        Ok(SourceBinding { binding_id, owner, generation, rights, execution_epoch: 0 })
    }

    pub fn binding(&self, binding_id: &str) -> Result<Option<BindingView>, AuthorityError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        let view = binding_in(&transaction, binding_id)?;
        transaction.commit()?;
        Ok(view)
    }

    pub(crate) fn destination_binding(
        &self,
        operation: &[u8; 16],
    ) -> Result<BindingView, AuthorityError> {
        let connection = self.database.lock()?;
        let binding_id = destination_binding_id(operation);
        let transaction = connection.unchecked_transaction()?;
        let view =
            binding_in(&transaction, &binding_id)?.ok_or(AuthorityError::NotFound(binding_id))?;
        transaction.commit()?;
        Ok(view)
    }

    /// Store an exact operation result in the authority's own table. A caller
    /// can repeat an operation only with byte-identical semantic request
    /// material; a rejected operation is durable and queryable too.
    pub(crate) fn persist_operation(
        &self,
        operation: &[u8; 16],
        kind: OperationKind,
        request_digest: Digest,
        outcome: OperationOutcome<'_>,
    ) -> Result<(), AuthorityError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        persist_operation_in(&transaction, operation, kind, request_digest, outcome)?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn fence_and_persist(
        &self,
        source_id: &str,
        destination_id: &str,
        preparation_digest: Digest,
        expected_epoch: u64,
        operation: &OperationId,
        request_digest: Digest,
        durable_receipt_digest: Digest,
        receipt: &[u8],
    ) -> Result<(), AuthorityError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        let source = binding_in(&transaction, source_id)?
            .ok_or_else(|| AuthorityError::NotFound(source_id.into()))?;
        let destination = binding_in(&transaction, destination_id)?
            .ok_or_else(|| AuthorityError::NotFound(destination_id.into()))?;
        ensure_preparation_binding_in(&transaction, destination_id, preparation_digest)?;
        if durable_resolution_in(&transaction, preparation_digest)? == DurableResolution::Aborted {
            return Err(AuthorityError::Rejected("aborted preparation cannot be committed".into()));
        }
        if source.fenced {
            return Err(AuthorityError::Fenced);
        }
        if destination.role != BindingRole::Destination
            || !destination.active
            || destination.execution_epoch != expected_epoch
            || destination.owner != source.owner
            || destination.rights.0 & !source.rights.0 != 0
            || destination.execution_epoch
                != source.execution_epoch.checked_add(1).ok_or_else(|| {
                    AuthorityError::Invalid("source execution epoch overflow".into())
                })?
            || destination.generation
                != source
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| AuthorityError::Invalid("source generation overflow".into()))?
        {
            return Err(AuthorityError::Rejected(
                "destination binding does not match source successor".into(),
            ));
        }
        let fenced = transaction.execute(
            "UPDATE visa_authority_bindings
             SET fenced = 1, active = 0, dispatch_open = 0
             WHERE binding_id = ?1 AND role = 'source' AND active = 1
               AND fenced = 0 AND dispatch_open = 0",
            params![source_id],
        )?;
        if fenced != 1 {
            return Err(AuthorityError::Conflict(hex(&operation.0)));
        }
        let committed = transaction.execute(
            "UPDATE visa_authority_bindings SET phase = 'committed'
             WHERE binding_id = ?1 AND role = 'destination' AND phase = 'prepared'
               AND active = 1 AND fenced = 0 AND dispatch_open = 0
               AND source_binding_id = ?2",
            params![destination_id, source_id],
        )?;
        if committed != 1 {
            return Err(AuthorityError::Rejected(
                "destination is not the prepared successor of this source".into(),
            ));
        }
        persist_operation_in(
            &transaction,
            &operation.0,
            OperationKind::Commit,
            request_digest,
            OperationOutcome::Applied {
                receipt,
                receipt_digest: durable_receipt_digest,
                source_binding_id: Some(source_id),
                destination_binding_id: Some(destination_id),
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_and_persist(
        &self,
        operation: &OperationId,
        destination_id: &str,
        epoch: u64,
        permit_digest: Digest,
        commit: &AuthorityCommitReceipt,
        request_digest: Digest,
        receipt: &[u8],
    ) -> Result<(), AuthorityError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        let durable_commit = exact_commit_in(&transaction, commit)?;
        if durable_commit != *commit {
            return Err(AuthorityError::Rejected(
                "commit receipt is not this authority's exact durable receipt".into(),
            ));
        }
        let destination = binding_in(&transaction, destination_id)?
            .ok_or_else(|| AuthorityError::NotFound(destination_id.into()))?;
        if destination.role != BindingRole::Destination
            || !destination.active
            || destination.execution_epoch != epoch
            || destination.fenced
            || destination.dispatch_open
        {
            return Err(AuthorityError::Rejected("invalid destination activation permit".into()));
        }
        let opened = transaction.execute(
            "UPDATE visa_authority_bindings SET dispatch_open = 1
             WHERE binding_id = ?1 AND epoch = ?2 AND role = 'destination'
               AND phase = 'committed' AND active = 1 AND fenced = 0 AND dispatch_open = 0",
            params![destination_id, u64_to_sqlite(epoch, "execution epoch")?],
        )?;
        if opened != 1 {
            return Err(AuthorityError::Rejected(
                "destination dispatch was not closed and activatable".into(),
            ));
        }
        let inserted = transaction.execute(
            "INSERT INTO visa_authority_permits
             (operation_id, destination_binding_id, execution_epoch, receipt_digest)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                operation.0.to_vec(),
                destination_id,
                u64_to_sqlite(epoch, "execution epoch")?,
                permit_digest.0.to_vec()
            ],
        )?;
        if inserted != 1 {
            return Err(AuthorityError::Conflict(hex(&operation.0)));
        }
        persist_operation_in(
            &transaction,
            &operation.0,
            OperationKind::Permit,
            request_digest,
            OperationOutcome::Applied {
                receipt,
                receipt_digest: permit_digest,
                source_binding_id: None,
                destination_binding_id: Some(destination_id),
            },
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn persist_operation_in(
    transaction: &rusqlite::Transaction<'_>,
    operation: &[u8; 16],
    kind: OperationKind,
    request_digest: Digest,
    outcome: OperationOutcome<'_>,
) -> Result<(), AuthorityError> {
    let existing = transaction
        .query_row(
            "SELECT kind, request_digest, outcome, receipt, rejection
                 FROM visa_authority_operations WHERE operation_id = ?1",
            params![operation.to_vec()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    if let Some((stored_kind, stored_digest, stored_outcome, stored_receipt, stored_rejection)) =
        existing
    {
        if stored_kind != kind.as_str() || stored_digest != request_digest.0 {
            return Err(AuthorityError::Conflict(hex(operation)));
        }
        let same = match outcome {
            OperationOutcome::Applied { receipt, .. } => {
                stored_outcome == "applied" && stored_receipt.as_deref() == Some(receipt)
            }
            OperationOutcome::Rejected(reason) => {
                stored_outcome == "rejected" && stored_rejection.as_deref() == Some(reason)
            }
        };
        if !same {
            return Err(AuthorityError::Conflict(hex(operation)));
        }
    } else {
        let (
            outcome,
            receipt,
            receipt_digest,
            source_binding_id,
            destination_binding_id,
            rejection,
        ) = match outcome {
            OperationOutcome::Applied {
                receipt,
                receipt_digest,
                source_binding_id,
                destination_binding_id,
            } => {
                if receipt.len() > MAX_RECEIPT_BYTES {
                    return Err(AuthorityError::Invalid(
                        "authority receipt exceeds durable bound".into(),
                    ));
                }
                (
                    "applied",
                    Some(receipt),
                    Some(receipt_digest.0.to_vec()),
                    source_binding_id,
                    destination_binding_id,
                    None,
                )
            }
            OperationOutcome::Rejected(reason) => {
                if reason.len() > MAX_REJECTION_BYTES {
                    return Err(AuthorityError::Invalid(
                        "authority rejection exceeds durable bound".into(),
                    ));
                }
                ("rejected", None, None, None, None, Some(reason))
            }
        };
        transaction.execute(
            "INSERT INTO visa_authority_operations
                 (operation_id, kind, request_digest, outcome, receipt, receipt_digest,
                  source_binding_id, destination_binding_id, rejection)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                operation.to_vec(),
                kind.as_str(),
                request_digest.0.to_vec(),
                outcome,
                receipt,
                receipt_digest,
                source_binding_id,
                destination_binding_id,
                rejection
            ],
        )?;
    }
    Ok(())
}

impl Authority {
    pub(crate) fn operation(
        &self,
        operation: &[u8; 16],
        kind: OperationKind,
        request_digest: Digest,
    ) -> Result<OperationState, AuthorityError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        let state = operation_in(&transaction, operation, kind, request_digest)?;
        transaction.commit()?;
        Ok(state)
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_and_persist(
        &self,
        action: &Action,
        continuation: visa_core::ContinuationId,
        snapshot: visa_core::SnapshotId,
        snapshot_digest: Digest,
        source_coordinate: &ExternalCoordinate,
        destination: &ExternalCoordinate,
        resources: &[visa_core::ResourceRequirement],
    ) -> Result<BindingPreparationReceipt, AuthorityError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        match operation_in(
            &transaction,
            &action.operation.0,
            OperationKind::Prepare,
            action.request_digest,
        )? {
            OperationState::Applied(bytes) => {
                let receipt = decode_receipt(&bytes)?;
                transaction.commit()?;
                return Ok(receipt);
            }
            OperationState::Rejected(reason) => {
                return Err(AuthorityError::Rejected(reason));
            }
            OperationState::Conflict(operation) => {
                return Err(AuthorityError::Conflict(operation));
            }
            OperationState::Absent => {}
        }
        if source_coordinate.authority != REFERENCE_AUTHORITY_ID {
            return Err(AuthorityError::Rejected(
                "preparation source belongs to another authority".into(),
            ));
        }
        let source_id = coordinate_text(source_coordinate)?;
        let source = binding_in(&transaction, &source_id)?
            .ok_or_else(|| AuthorityError::NotFound(source_id.clone()))?;
        if source.role != BindingRole::Source || !source.active || source.fenced {
            return Err(AuthorityError::Fenced);
        }
        if resources
            .iter()
            .any(|requirement| requirement.disposition != RebindDisposition::Recreate)
        {
            return Err(AuthorityError::Rejected(
                "reference authority only supports fresh resource recreation".into(),
            ));
        }
        let requested_rights = resources
            .iter()
            .fold(Rights(0), |rights, requirement| rights | requirement.required_rights);
        if !source.rights.contains(requested_rights) {
            return Err(AuthorityError::Rejected(
                "requested destination rights exceed source rights".into(),
            ));
        }
        let binding =
            create_destination_in(&transaction, &action.operation.0, &source, requested_rights)?;
        let coordinate = ExternalCoordinate {
            authority: REFERENCE_AUTHORITY_ID,
            value: OpaqueBytes(binding.binding_id.clone().into_bytes()),
        };
        let grants = resources
            .iter()
            .map(|requirement| BindingGrant {
                requirement: requirement.id,
                provider: coordinate.clone(),
                provider_generation: binding.generation,
                binding: coordinate.clone(),
                granted_rights: requirement.required_rights,
                disposition: requirement.disposition,
            })
            .collect();
        let receipt = BindingPreparationReceipt {
            operation: action.operation,
            continuation,
            snapshot,
            snapshot_digest,
            destination: destination.clone(),
            grants,
            request_digest: action.request_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(|error| AuthorityError::Invalid(error.to_string()))?;
        let bytes = postcard::to_allocvec(&receipt)
            .map_err(|_| AuthorityError::Invalid("receipt encoding failed".into()))?;
        persist_operation_in(
            &transaction,
            &action.operation.0,
            OperationKind::Prepare,
            action.request_digest,
            OperationOutcome::Applied {
                receipt: &bytes,
                receipt_digest: receipt.receipt_digest,
                source_binding_id: Some(&source.binding_id),
                destination_binding_id: Some(&binding.binding_id),
            },
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    fn abort_and_persist(
        &self,
        action: &Action,
        source: &ExternalCoordinate,
        destination: &ExternalCoordinate,
        bindings: &BindingPreparationReceipt,
    ) -> Result<AbortPreparationReceipt, AuthorityError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        match operation_in(
            &transaction,
            &action.operation.0,
            OperationKind::Abort,
            action.request_digest,
        )? {
            OperationState::Applied(bytes) => {
                let receipt = decode_receipt(&bytes)?;
                transaction.commit()?;
                return Ok(receipt);
            }
            OperationState::Rejected(reason) => {
                return Err(AuthorityError::Rejected(reason));
            }
            OperationState::Conflict(operation) => {
                return Err(AuthorityError::Conflict(operation));
            }
            OperationState::Absent => {}
        }
        let prepared = preparation_by_digest_in(&transaction, bindings.receipt_digest)?;
        if &prepared != bindings {
            return Err(AuthorityError::Rejected(
                "abort does not reference the durable preparation".into(),
            ));
        }
        if bindings.destination != *destination {
            return Err(AuthorityError::Rejected(
                "abort destination does not match preparation".into(),
            ));
        }
        let source_id = coordinate_text(source)?;
        let source_binding = binding_in(&transaction, &source_id)?
            .ok_or_else(|| AuthorityError::NotFound(source_id.clone()))?;
        if source_binding.role != BindingRole::Source || source_binding.fenced {
            return Err(AuthorityError::Rejected(
                "committed source cannot be restored by abort".into(),
            ));
        }
        let destination_id = grant_binding(bindings)?;
        let binding = binding_in(&transaction, &destination_id)?
            .ok_or_else(|| AuthorityError::NotFound(destination_id.clone()))?;
        ensure_preparation_binding_in(&transaction, &destination_id, bindings.receipt_digest)?;
        if durable_resolution_in(&transaction, bindings.receipt_digest)?
            == DurableResolution::Committed
        {
            return Err(AuthorityError::Rejected("committed destination cannot be aborted".into()));
        }
        if binding.role != BindingRole::Destination
            || !binding.active
            || binding.fenced
            || binding.dispatch_open
            || binding.owner != source_binding.owner
            || binding.generation
                != source_binding
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| AuthorityError::Invalid("source generation overflow".into()))?
            || binding.execution_epoch
                != source_binding.execution_epoch.checked_add(1).ok_or_else(|| {
                    AuthorityError::Invalid("source execution epoch overflow".into())
                })?
            || binding.rights.0 & !source_binding.rights.0 != 0
        {
            return Err(AuthorityError::Rejected("destination cannot be aborted".into()));
        }
        let receipt = AbortPreparationReceipt {
            operation: action.operation,
            continuation: bindings.continuation,
            snapshot: bindings.snapshot,
            snapshot_digest: bindings.snapshot_digest,
            source: source.clone(),
            destination: destination.clone(),
            preparation_receipt_digest: bindings.receipt_digest,
            request_digest: action.request_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(|error| AuthorityError::Invalid(error.to_string()))?;
        let bytes = postcard::to_allocvec(&receipt)
            .map_err(|_| AuthorityError::Invalid("receipt encoding failed".into()))?;
        let aborted = transaction.execute(
            "UPDATE visa_authority_bindings
             SET active = 0, dispatch_open = 0, phase = 'aborted'
             WHERE binding_id = ?1 AND role = 'destination' AND phase = 'prepared'
               AND active = 1 AND fenced = 0 AND dispatch_open = 0",
            params![destination_id],
        )?;
        if aborted != 1 {
            return Err(AuthorityError::Rejected("destination cannot be aborted".into()));
        }
        persist_operation_in(
            &transaction,
            &action.operation.0,
            OperationKind::Abort,
            action.request_digest,
            OperationOutcome::Applied {
                receipt: &bytes,
                receipt_digest: receipt.receipt_digest,
                source_binding_id: Some(&source_id),
                destination_binding_id: Some(&destination_id),
            },
        )?;
        transaction.commit()?;
        Ok(receipt)
    }
}

fn operation_in(
    transaction: &rusqlite::Transaction<'_>,
    operation: &[u8; 16],
    kind: OperationKind,
    request_digest: Digest,
) -> Result<OperationState, AuthorityError> {
    let row = transaction
        .query_row(
            "SELECT kind, request_digest, outcome, receipt, rejection
                 FROM visa_authority_operations WHERE operation_id = ?1",
            params![operation.to_vec()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    match row {
        None => Ok(OperationState::Absent),
        Some((stored_kind, stored_digest, _outcome, _receipt, _rejection))
            if stored_kind != kind.as_str() || stored_digest != request_digest.0 =>
        {
            Ok(OperationState::Conflict(hex(operation)))
        }
        Some((_, _, outcome, receipt, _rejection)) if outcome == "applied" => {
            let receipt = receipt
                .ok_or_else(|| AuthorityError::Corrupt("applied operation lacks receipt".into()))?;
            validate_applied_receipt(kind, operation, request_digest, &receipt)?;
            Ok(OperationState::Applied(receipt))
        }
        Some((_, _, outcome, _, rejection)) if outcome == "rejected" => {
            let rejection = rejection.ok_or_else(|| {
                AuthorityError::Corrupt("rejected operation lacks durable reason".into())
            })?;
            if rejection.is_empty() || rejection.len() > MAX_REJECTION_BYTES {
                return Err(AuthorityError::Corrupt(
                    "rejected operation has invalid durable reason".into(),
                ));
            }
            Ok(OperationState::Rejected(rejection))
        }
        Some(_) => Err(AuthorityError::Corrupt("unknown durable operation outcome".into())),
    }
}

impl Authority {
    pub(crate) fn active_source(
        &self,
        source: &ExternalCoordinate,
    ) -> Result<BindingView, AuthorityError> {
        if source.authority != REFERENCE_AUTHORITY_ID {
            return Err(AuthorityError::Rejected("source belongs to another authority".into()));
        }
        let binding_id = coordinate_text(source)?;
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        let source =
            binding_in(&transaction, &binding_id)?.ok_or(AuthorityError::NotFound(binding_id))?;
        if source.role != BindingRole::Source || !source.active || source.fenced {
            return Err(AuthorityError::Fenced);
        }
        transaction.commit()?;
        Ok(source)
    }

    pub(crate) fn preparation_by_digest(
        &self,
        receipt_digest: Digest,
    ) -> Result<BindingPreparationReceipt, AuthorityError> {
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        let preparation = preparation_by_digest_in(&transaction, receipt_digest)?;
        transaction.commit()?;
        Ok(preparation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OperationKind {
    Prepare,
    Commit,
    Abort,
    Permit,
}

impl OperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Commit => "commit",
            Self::Abort => "abort",
            Self::Permit => "permit",
        }
    }
}

pub(crate) enum OperationOutcome<'a> {
    Applied {
        receipt: &'a [u8],
        receipt_digest: Digest,
        source_binding_id: Option<&'a str>,
        destination_binding_id: Option<&'a str>,
    },
    Rejected(&'a str),
}

pub(crate) enum OperationState {
    Applied(Vec<u8>),
    Rejected(String),
    Conflict(String),
    Absent,
}

fn binding_in(
    transaction: &rusqlite::Transaction<'_>,
    binding_id: &str,
) -> Result<Option<BindingView>, AuthorityError> {
    transaction
        .query_row(
            "SELECT owner, generation, rights, epoch, role, active, fenced, dispatch_open
             FROM visa_authority_bindings WHERE binding_id = ?1",
            params![binding_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?
        .map(|(owner, generation, rights, epoch, role, active, fenced, dispatch_open)| {
            let role = match role.as_str() {
                "source" => BindingRole::Source,
                "destination" => BindingRole::Destination,
                _ => return Err(AuthorityError::Invalid("unknown durable binding role".into())),
            };
            Ok(BindingView {
                binding_id: binding_id.into(),
                owner,
                generation: sqlite_to_u64(generation, "binding generation")?,
                rights: Rights(sqlite_to_u64(rights, "binding rights")?),
                execution_epoch: sqlite_to_u64(epoch, "execution epoch")?,
                role,
                active: sqlite_bool(active, "binding active")?,
                fenced: sqlite_bool(fenced, "binding fenced")?,
                dispatch_open: sqlite_bool(dispatch_open, "binding dispatch")?,
            })
        })
        .transpose()
}

fn create_destination_in(
    transaction: &rusqlite::Transaction<'_>,
    operation: &[u8; 16],
    source: &BindingView,
    rights: Rights,
) -> Result<BindingView, AuthorityError> {
    if source.role != BindingRole::Source || source.fenced || !source.active {
        return Err(AuthorityError::Fenced);
    }
    let epoch = source
        .execution_epoch
        .checked_add(1)
        .ok_or_else(|| AuthorityError::Invalid("execution epoch overflow".into()))?;
    let binding_id = destination_binding_id(operation);
    if let Some(existing) = binding_in(transaction, &binding_id)? {
        if existing.role != BindingRole::Destination
            || existing.generation
                != source
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| AuthorityError::Invalid("source generation overflow".into()))?
            || existing.rights != rights
            || existing.execution_epoch != epoch
        {
            return Err(AuthorityError::Conflict(hex(operation)));
        }
        return Ok(existing);
    }
    transaction.execute(
        "INSERT INTO visa_authority_bindings
         (binding_id, owner, generation, rights, epoch, role, active, fenced, dispatch_open,
          operation_id, source_binding_id, phase)
         VALUES (?1, ?2, ?3, ?4, ?5, 'destination', 1, 0, 0, ?6, ?7, 'prepared')",
        params![
            binding_id,
            source.owner,
            u64_to_sqlite(
                source
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| AuthorityError::Invalid("source generation overflow".into()))?,
                "binding generation"
            )?,
            u64_to_sqlite(rights.0, "binding rights")?,
            u64_to_sqlite(epoch, "execution epoch")?,
            operation.to_vec(),
            source.binding_id,
        ],
    )?;
    binding_in(transaction, &destination_binding_id(operation))?
        .ok_or_else(|| AuthorityError::Invalid("destination insert disappeared".into()))
}

fn preparation_by_digest_in(
    transaction: &rusqlite::Transaction<'_>,
    receipt_digest: Digest,
) -> Result<BindingPreparationReceipt, AuthorityError> {
    let row = transaction
        .query_row(
            "SELECT operation_id, request_digest, receipt, destination_binding_id
             FROM visa_authority_operations
             WHERE kind = 'prepare' AND outcome = 'applied' AND receipt_digest = ?1",
            params![receipt_digest.0.to_vec()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((operation, request_digest_bytes, bytes, destination_binding_id)) = row else {
        return Err(AuthorityError::NotFound("binding preparation receipt".into()));
    };
    let operation: [u8; 16] = operation
        .try_into()
        .map_err(|_| AuthorityError::Corrupt("operation id is not 16 bytes".into()))?;
    let stored_request_digest: [u8; 32] = request_digest_bytes
        .try_into()
        .map_err(|_| AuthorityError::Corrupt("request digest is not 32 bytes".into()))?;
    let receipt: BindingPreparationReceipt = decode_receipt(&bytes)?;
    receipt.verify().map_err(|error| {
        AuthorityError::Corrupt(format!("invalid preparation receipt: {error}"))
    })?;
    if receipt.operation.0 != operation
        || receipt.request_digest.0 != stored_request_digest
        || receipt.receipt_digest != receipt_digest
        || destination_binding_id.as_deref() != Some(grant_binding(&receipt)?.as_str())
    {
        return Err(AuthorityError::Corrupt(
            "preparation receipt does not match durable row metadata".into(),
        ));
    }
    Ok(receipt)
}

fn ensure_preparation_binding_in(
    transaction: &rusqlite::Transaction<'_>,
    binding_id: &str,
    preparation_digest: Digest,
) -> Result<(), AuthorityError> {
    let preparation = preparation_by_digest_in(transaction, preparation_digest)?;
    let operation_id = transaction
        .query_row(
            "SELECT operation_id FROM visa_authority_bindings WHERE binding_id = ?1",
            params![binding_id],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )?
        .ok_or_else(|| {
            AuthorityError::Corrupt("destination lacks preparation provenance".into())
        })?;
    if operation_id.as_slice() != preparation.operation.0 {
        return Err(AuthorityError::Rejected(
            "destination was not issued by the durable preparation operation".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableResolution {
    Unresolved,
    Committed,
    Aborted,
}

fn durable_resolution_in(
    transaction: &rusqlite::Transaction<'_>,
    preparation_digest: Digest,
) -> Result<DurableResolution, AuthorityError> {
    let preparation = preparation_by_digest_in(transaction, preparation_digest)?;
    let binding_id = grant_binding(&preparation)?;
    let phase = transaction
        .query_row(
            "SELECT phase FROM visa_authority_bindings
             WHERE binding_id = ?1 AND operation_id = ?2",
            params![binding_id, preparation.operation.0.to_vec()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| AuthorityError::Corrupt("preparation binding is missing".into()))?;
    match phase.as_str() {
        "prepared" => Ok(DurableResolution::Unresolved),
        "committed" => Ok(DurableResolution::Committed),
        "aborted" => Ok(DurableResolution::Aborted),
        _ => Err(AuthorityError::Corrupt("destination has an invalid durable phase".into())),
    }
}

fn exact_commit_in(
    transaction: &rusqlite::Transaction<'_>,
    commit: &AuthorityCommitReceipt,
) -> Result<AuthorityCommitReceipt, AuthorityError> {
    let bytes = match operation_in(
        transaction,
        &commit.operation.0,
        OperationKind::Commit,
        commit.request_digest,
    )? {
        OperationState::Applied(bytes) => bytes,
        OperationState::Rejected(reason) => return Err(AuthorityError::Rejected(reason)),
        OperationState::Conflict(operation) => return Err(AuthorityError::Conflict(operation)),
        OperationState::Absent => {
            return Err(AuthorityError::Rejected("commit was not durably executed".into()));
        }
    };
    let durable: AuthorityCommitReceipt = decode_receipt(&bytes)?;
    durable
        .verify()
        .map_err(|error| AuthorityError::Corrupt(format!("invalid durable commit: {error}")))?;
    if durable.operation != commit.operation || durable.request_digest != commit.request_digest {
        return Err(AuthorityError::Corrupt(
            "commit receipt does not match durable operation metadata".into(),
        ));
    }
    Ok(durable)
}

fn destination_binding_id(operation: &[u8; 16]) -> BindingId {
    format!("destination:{}", hex(operation))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn coordinate_text(coordinate: &ExternalCoordinate) -> Result<String, AuthorityError> {
    String::from_utf8(coordinate.value.0.clone())
        .map_err(|_| AuthorityError::Invalid("reference binding coordinate is not UTF-8".into()))
}

impl Authority {
    fn prepare_action(&self, action: &Action) -> Result<BindingPreparationReceipt, AuthorityError> {
        verify_action(action)?;
        let ActionRequest::PrepareBindings {
            continuation,
            snapshot,
            snapshot_digest,
            source,
            destination,
            resources,
        } = &action.request
        else {
            return Err(AuthorityError::Rejected("not a prepare-bindings action".into()));
        };
        if destination.authority != REFERENCE_AUTHORITY_ID || resources.is_empty() {
            return Err(AuthorityError::Rejected(
                "reference authority cannot prepare these bindings".into(),
            ));
        }
        self.prepare_and_persist(
            action,
            *continuation,
            *snapshot,
            *snapshot_digest,
            source,
            destination,
            resources,
        )
    }

    fn commit_action(&self, action: &Action) -> Result<AuthorityCommitReceipt, AuthorityError> {
        verify_action(action)?;
        match self.exact(action, OperationKind::Commit)? {
            OperationState::Applied(bytes) => return decode_receipt(&bytes),
            OperationState::Rejected(reason) => return Err(AuthorityError::Rejected(reason)),
            OperationState::Conflict(operation) => {
                return Err(AuthorityError::Conflict(operation));
            }
            OperationState::Absent => {}
        }
        let ActionRequest::CommitFence {
            continuation,
            snapshot,
            snapshot_digest,
            source,
            destination,
            binding_receipt_digest,
        } = &action.request
        else {
            return Err(AuthorityError::Rejected("not a commit-fence action".into()));
        };
        if source.authority != REFERENCE_AUTHORITY_ID
            || destination.authority != REFERENCE_AUTHORITY_ID
        {
            return Err(AuthorityError::Rejected("commit references another authority".into()));
        }
        let preparation = self.preparation_by_digest(*binding_receipt_digest)?;
        if preparation.continuation != *continuation
            || preparation.snapshot != *snapshot
            || preparation.snapshot_digest != *snapshot_digest
            || preparation.destination != *destination
        {
            return Err(AuthorityError::Rejected("commit does not match preparation".into()));
        }
        let source_binding = self.active_source(source)?;
        if source_binding.dispatch_open {
            return Err(AuthorityError::Rejected("source dispatch is still open".into()));
        }
        let destination_id = grant_binding(&preparation)?;
        let destination_binding = self
            .binding(&destination_id)?
            .ok_or_else(|| AuthorityError::NotFound(destination_id.clone()))?;
        let receipt = AuthorityCommitReceipt {
            operation: action.operation,
            continuation: *continuation,
            snapshot: *snapshot,
            snapshot_digest: *snapshot_digest,
            source: source.clone(),
            destination: destination.clone(),
            binding_receipt_digest: *binding_receipt_digest,
            source_fence_epoch: source_binding.execution_epoch,
            execution_epoch: destination_binding.execution_epoch,
            request_digest: action.request_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(|error| AuthorityError::Invalid(error.to_string()))?;
        let bytes = postcard::to_allocvec(&receipt)
            .map_err(|_| AuthorityError::Invalid("receipt encoding failed".into()))?;
        self.fence_and_persist(
            &source_binding.binding_id,
            &destination_id,
            preparation.receipt_digest,
            destination_binding.execution_epoch,
            &action.operation,
            action.request_digest,
            receipt.receipt_digest,
            &bytes,
        )?;
        Ok(receipt)
    }

    fn permit_action(&self, action: &Action) -> Result<ActivationPermitReceipt, AuthorityError> {
        verify_action(action)?;
        match self.exact(action, OperationKind::Permit)? {
            OperationState::Applied(bytes) => return decode_receipt(&bytes),
            OperationState::Rejected(reason) => return Err(AuthorityError::Rejected(reason)),
            OperationState::Conflict(operation) => {
                return Err(AuthorityError::Conflict(operation));
            }
            OperationState::Absent => {}
        }
        let ActionRequest::PermitActivation {
            continuation,
            snapshot,
            snapshot_digest,
            destination,
            commit,
        } = &action.request
        else {
            return Err(AuthorityError::Rejected("not a permit-activation action".into()));
        };
        if destination.authority != REFERENCE_AUTHORITY_ID
            || commit.continuation != *continuation
            || commit.snapshot != *snapshot
            || commit.snapshot_digest != *snapshot_digest
            || commit.destination != *destination
        {
            return Err(AuthorityError::Rejected("permit does not match commit".into()));
        }
        // The public receipt digest is an integrity checksum, not authority
        // authentication. Authority comes from the exact persisted operation.
        let durable_commit = match self.operation(
            &commit.operation.0,
            OperationKind::Commit,
            commit.request_digest,
        )? {
            OperationState::Applied(bytes) => decode_receipt::<AuthorityCommitReceipt>(&bytes)?,
            OperationState::Absent => {
                return Err(AuthorityError::Rejected("commit was not durably executed".into()));
            }
            OperationState::Rejected(reason) => return Err(AuthorityError::Rejected(reason)),
            OperationState::Conflict(operation) => {
                return Err(AuthorityError::Conflict(operation));
            }
        };
        if durable_commit != *commit || durable_commit.receipt_digest != commit.receipt_digest {
            return Err(AuthorityError::Rejected(
                "commit receipt is not this authority's exact durable receipt".into(),
            ));
        }
        let preparation = self.preparation_by_digest(commit.binding_receipt_digest)?;
        let destination_id = grant_binding(&preparation)?;
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        ensure_preparation_binding_in(
            &transaction,
            &destination_id,
            commit.binding_receipt_digest,
        )?;
        if durable_resolution_in(&transaction, commit.binding_receipt_digest)?
            != DurableResolution::Committed
        {
            return Err(AuthorityError::Rejected(
                "activation lacks this authority's durable commit provenance".into(),
            ));
        }
        let destination_binding = binding_in(&transaction, &destination_id)?
            .ok_or_else(|| AuthorityError::NotFound(destination_id.clone()))?;
        let source_id = coordinate_text(&commit.source)?;
        let source_binding = binding_in(&transaction, &source_id)?
            .ok_or_else(|| AuthorityError::NotFound(source_id.clone()))?;
        if source_binding.role != BindingRole::Source
            || !source_binding.fenced
            || source_binding.active
            || source_binding.dispatch_open
            || destination_binding.role != BindingRole::Destination
            || !destination_binding.active
            || destination_binding.fenced
            || destination_binding.dispatch_open
            || destination_binding.execution_epoch != commit.execution_epoch
            || destination_binding.owner != source_binding.owner
            || destination_binding.generation
                != source_binding
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| AuthorityError::Invalid("source generation overflow".into()))?
            || destination_binding.rights.0 & !source_binding.rights.0 != 0
        {
            return Err(AuthorityError::Rejected(
                "destination is not the current prepared successor of the committed source".into(),
            ));
        }
        transaction.commit()?;
        drop(connection);
        let receipt = ActivationPermitReceipt {
            operation: action.operation,
            continuation: *continuation,
            snapshot: *snapshot,
            snapshot_digest: *snapshot_digest,
            destination: destination.clone(),
            authority_commit_digest: commit.receipt_digest,
            execution_epoch: commit.execution_epoch,
            request_digest: action.request_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(|error| AuthorityError::Invalid(error.to_string()))?;
        let bytes = postcard::to_allocvec(&receipt)
            .map_err(|_| AuthorityError::Invalid("receipt encoding failed".into()))?;
        self.admit_and_persist(
            &action.operation,
            &destination_id,
            receipt.execution_epoch,
            receipt.receipt_digest,
            commit,
            action.request_digest,
            &bytes,
        )?;
        Ok(receipt)
    }

    fn abort_action(&self, action: &Action) -> Result<AbortPreparationReceipt, AuthorityError> {
        verify_action(action)?;
        let ActionRequest::AbortBindings {
            continuation,
            snapshot,
            snapshot_digest,
            source,
            destination,
            bindings,
        } = &action.request
        else {
            return Err(AuthorityError::Rejected("not an abort-bindings action".into()));
        };
        if source.authority != REFERENCE_AUTHORITY_ID
            || destination.authority != REFERENCE_AUTHORITY_ID
            || bindings.continuation != *continuation
            || bindings.snapshot != *snapshot
            || bindings.snapshot_digest != *snapshot_digest
        {
            return Err(AuthorityError::Rejected("abort does not match preparation".into()));
        }
        self.abort_and_persist(action, source, destination, bindings)
    }

    fn exact(
        &self,
        action: &Action,
        kind: OperationKind,
    ) -> Result<OperationState, AuthorityError> {
        verify_action(action)?;
        self.operation(&action.operation.0, kind, action.request_digest)
    }
}

impl AuthorityPort for Authority {
    type Error = AuthorityError;
    fn prepare_bindings(
        &mut self,
        action: &Action,
    ) -> Observation<BindingPreparationReceipt, Self::Error> {
        invoke(self, action, OperationKind::Prepare, self.prepare_action(action))
    }
    fn query_prepare_bindings(
        &mut self,
        action: &Action,
    ) -> Observation<BindingPreparationReceipt, Self::Error> {
        query_exact(self.exact(action, OperationKind::Prepare))
    }
    fn commit_fence(
        &mut self,
        action: &Action,
    ) -> Observation<AuthorityCommitReceipt, Self::Error> {
        invoke(self, action, OperationKind::Commit, self.commit_action(action))
    }
    fn query_commit_fence(
        &mut self,
        action: &Action,
    ) -> Observation<AuthorityCommitReceipt, Self::Error> {
        query_exact(self.exact(action, OperationKind::Commit))
    }
    fn permit_activation(
        &mut self,
        action: &Action,
    ) -> Observation<ActivationPermitReceipt, Self::Error> {
        invoke(self, action, OperationKind::Permit, self.permit_action(action))
    }
    fn query_permit_activation(
        &mut self,
        action: &Action,
    ) -> Observation<ActivationPermitReceipt, Self::Error> {
        query_exact(self.exact(action, OperationKind::Permit))
    }
    fn abort_bindings(
        &mut self,
        action: &Action,
    ) -> Observation<AbortPreparationReceipt, Self::Error> {
        invoke(self, action, OperationKind::Abort, self.abort_action(action))
    }
    fn query_abort_bindings(
        &mut self,
        action: &Action,
    ) -> Observation<AbortPreparationReceipt, Self::Error> {
        query_exact(self.exact(action, OperationKind::Abort))
    }
}

fn grant_binding(receipt: &BindingPreparationReceipt) -> Result<String, AuthorityError> {
    let grant = receipt
        .grants
        .first()
        .ok_or_else(|| AuthorityError::Rejected("preparation has no binding grant".into()))?;
    if grant.binding.authority != REFERENCE_AUTHORITY_ID {
        return Err(AuthorityError::Rejected("binding grant belongs to another authority".into()));
    }
    String::from_utf8(grant.binding.value.0.clone())
        .map_err(|_| AuthorityError::Invalid("binding id is not UTF-8".into()))
}

fn decode_receipt<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, AuthorityError> {
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(AuthorityError::Corrupt("durable authority receipt exceeds bound".into()));
    }
    postcard::from_bytes(bytes)
        .map_err(|_| AuthorityError::Corrupt("durable authority receipt cannot be decoded".into()))
}

fn validate_applied_receipt(
    kind: OperationKind,
    operation: &[u8; 16],
    request_digest: Digest,
    bytes: &[u8],
) -> Result<(), AuthorityError> {
    macro_rules! validate {
        ($ty:ty) => {{
            let receipt: $ty = decode_receipt(bytes)?;
            receipt
                .verify()
                .map_err(|error| AuthorityError::Corrupt(format!("invalid receipt: {error}")))?;
            if receipt.operation.0 != *operation || receipt.request_digest != request_digest {
                return Err(AuthorityError::Corrupt(
                    "receipt does not match durable operation metadata".into(),
                ));
            }
        }};
    }
    match kind {
        OperationKind::Prepare => validate!(BindingPreparationReceipt),
        OperationKind::Commit => validate!(AuthorityCommitReceipt),
        OperationKind::Abort => validate!(AbortPreparationReceipt),
        OperationKind::Permit => validate!(ActivationPermitReceipt),
    }
    Ok(())
}

fn query_exact<T: serde::de::DeserializeOwned>(
    state: Result<OperationState, AuthorityError>,
) -> Observation<T, AuthorityError> {
    match state {
        Ok(OperationState::Applied(bytes)) => {
            decode_receipt(&bytes).map_or_else(Observation::Unverifiable, Observation::Applied)
        }
        Ok(OperationState::Absent) => Observation::Absent,
        Ok(OperationState::Rejected(reason)) => {
            Observation::Rejected(AuthorityError::Rejected(reason))
        }
        Ok(OperationState::Conflict(operation)) => {
            Observation::Unverifiable(AuthorityError::Conflict(operation))
        }
        Err(AuthorityError::Database(_)) => Observation::Indeterminate,
        Err(error @ (AuthorityError::Conflict(_) | AuthorityError::Corrupt(_))) => {
            Observation::Unverifiable(error)
        }
        Err(error) => Observation::Rejected(error),
    }
}

fn invoke<T>(
    authority: &Authority,
    action: &Action,
    kind: OperationKind,
    result: Result<T, AuthorityError>,
) -> Observation<T, AuthorityError> {
    if let Err(error) = verify_action(action) {
        return Observation::Unverifiable(error);
    }
    match result {
        Ok(value) => Observation::Applied(value),
        Err(AuthorityError::Database(_)) => Observation::Indeterminate,
        Err(error @ (AuthorityError::Conflict(_) | AuthorityError::Corrupt(_))) => {
            Observation::Unverifiable(error)
        }
        Err(error) => {
            let reason = error.to_string();
            match authority.persist_operation(
                &action.operation.0,
                kind,
                action.request_digest,
                OperationOutcome::Rejected(&reason),
            ) {
                Ok(()) => Observation::Rejected(error),
                Err(AuthorityError::Database(_)) => Observation::Indeterminate,
                Err(_) => Observation::Unverifiable(error),
            }
        }
    }
}

fn verify_action(action: &Action) -> Result<(), AuthorityError> {
    let digest = canonical_digest(&(action.operation, &action.request))
        .map_err(|error| AuthorityError::Invalid(error.to_string()))?;
    if digest == action.request_digest {
        Ok(())
    } else {
        Err(AuthorityError::Conflict("action request digest does not match request body".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use visa_core::{
        RequirementId, ResourceRequirement, SchemaId, SchemaRef, SnapshotId, canonical_digest,
    };

    fn action(operation: u128, request: ActionRequest) -> Action {
        let operation = OperationId::from_u128(operation);
        let request_digest = canonical_digest(&(operation, &request)).unwrap();
        Action { operation, request, request_digest }
    }

    fn destination() -> ExternalCoordinate {
        ExternalCoordinate {
            authority: REFERENCE_AUTHORITY_ID,
            value: OpaqueBytes(b"destination".to_vec()),
        }
    }

    fn resource() -> visa_core::ResourceRequirement {
        ResourceRequirement {
            id: RequirementId::from_u128(4),
            schema: SchemaRef { id: SchemaId::from_u128(5), version: 1 },
            logical_name: OpaqueBytes(b"durable-kv".to_vec()),
            required_rights: Rights(1),
            disposition: RebindDisposition::Recreate,
            profile_data: OpaqueBytes::default(),
        }
    }

    fn prepare_request(operation: u128, snapshot: u128, source: &SourceBinding) -> Action {
        action(
            operation,
            ActionRequest::PrepareBindings {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(snapshot),
                snapshot_digest: Digest::of_bytes(&snapshot.to_be_bytes()),
                source: source_coordinate(source),
                destination: destination(),
                resources: vec![resource()],
            },
        )
    }

    fn source_coordinate(source: &SourceBinding) -> ExternalCoordinate {
        ExternalCoordinate {
            authority: REFERENCE_AUTHORITY_ID,
            value: OpaqueBytes(source.binding_id.as_bytes().to_vec()),
        }
    }

    fn prepared() -> (Authority, SourceBinding, Action, BindingPreparationReceipt) {
        let database = ReferenceDatabase::in_memory().unwrap();
        let mut authority = Authority::new(database).unwrap();
        let source = authority.bootstrap_source("source", 7, Rights(3)).unwrap();
        let action = prepare_request(10, 2, &source);
        let Observation::Applied(receipt) = authority.prepare_bindings(&action) else {
            panic!("preparation was not applied");
        };
        (authority, source, action, receipt)
    }

    fn close_source_dispatch(authority: &Authority, source: &SourceBinding) {
        let database = authority.database();
        database
            .lock()
            .unwrap()
            .execute(
                "UPDATE visa_authority_bindings SET dispatch_open = 0 WHERE binding_id = ?1",
                params![source.binding_id],
            )
            .unwrap();
    }

    #[test]
    fn prepare_is_exact_and_its_binding_is_durable_with_the_receipt() {
        let (mut authority, _source, action, receipt) = prepared();
        let destination_id = grant_binding(&receipt).unwrap();

        assert!(matches!(
            authority.query_prepare_bindings(&action),
            Observation::Applied(value) if value == receipt
        ));
        assert!(matches!(
            authority.prepare_bindings(&action),
            Observation::Applied(value) if value == receipt
        ));
        assert!(authority.binding(&destination_id).unwrap().unwrap().active);
        assert_eq!(authority.binding(&destination_id).unwrap().unwrap().generation, 8);
        assert_eq!(authority.binding(&destination_id).unwrap().unwrap().rights, Rights(1));
        assert_eq!(receipt.grants[0].granted_rights, Rights(1));

        let different_payload = prepare_request(10, 3, &_source);
        assert!(matches!(
            authority.prepare_bindings(&different_payload),
            Observation::Unverifiable(_)
        ));
        assert!(matches!(
            authority.query_prepare_bindings(&action),
            Observation::Applied(value) if value == receipt
        ));

        let mut forged_digest = action.clone();
        if let ActionRequest::PrepareBindings { destination, .. } = &mut forged_digest.request {
            destination.value = OpaqueBytes(b"different-destination".to_vec());
        }
        assert!(matches!(
            authority.query_prepare_bindings(&forged_digest),
            Observation::Unverifiable(AuthorityError::Conflict(_))
        ));
    }

    #[test]
    fn commit_fences_the_source_and_persists_its_receipt() {
        let (mut authority, source, _prepare, bindings) = prepared();
        close_source_dispatch(&authority, &source);
        let source = source_coordinate(&source);
        let action = action(
            11,
            ActionRequest::CommitFence {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(2),
                snapshot_digest: Digest::of_bytes(&2_u128.to_be_bytes()),
                source: source.clone(),
                destination: destination(),
                binding_receipt_digest: bindings.receipt_digest,
            },
        );

        let Observation::Applied(receipt) = authority.commit_fence(&action) else {
            panic!("commit was not applied");
        };
        assert!(matches!(
            authority.query_commit_fence(&action),
            Observation::Applied(value) if value == receipt
        ));
        let source_view = authority.binding(&coordinate_text(&source).unwrap()).unwrap().unwrap();
        assert!(source_view.fenced);
        assert!(!source_view.active);
    }

    #[test]
    fn permit_opens_destination_dispatch_with_a_queryable_receipt() {
        let (mut authority, source, _prepare, bindings) = prepared();
        close_source_dispatch(&authority, &source);
        let source = source_coordinate(&source);
        let commit_action = action(
            11,
            ActionRequest::CommitFence {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(2),
                snapshot_digest: Digest::of_bytes(&2_u128.to_be_bytes()),
                source,
                destination: destination(),
                binding_receipt_digest: bindings.receipt_digest,
            },
        );
        let Observation::Applied(commit) = authority.commit_fence(&commit_action) else {
            panic!("commit was not applied");
        };
        let destination_id = grant_binding(&bindings).unwrap();
        assert!(!authority.binding(&destination_id).unwrap().unwrap().dispatch_open);

        let permit_action = action(
            12,
            ActionRequest::PermitActivation {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(2),
                snapshot_digest: Digest::of_bytes(&2_u128.to_be_bytes()),
                destination: destination(),
                commit,
            },
        );
        let Observation::Applied(receipt) = authority.permit_activation(&permit_action) else {
            panic!("permit was not applied");
        };
        assert!(authority.binding(&destination_id).unwrap().unwrap().dispatch_open);
        assert!(matches!(
            authority.query_permit_activation(&permit_action),
            Observation::Applied(value) if value == receipt
        ));
    }

    #[test]
    fn abort_discards_the_active_destination_with_its_receipt() {
        let (mut authority, source, _prepare, bindings) = prepared();
        let destination_id = grant_binding(&bindings).unwrap();
        let action = action(
            13,
            ActionRequest::AbortBindings {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(2),
                snapshot_digest: Digest::of_bytes(&2_u128.to_be_bytes()),
                source: source_coordinate(&source),
                destination: destination(),
                bindings,
            },
        );

        let Observation::Applied(receipt) = authority.abort_bindings(&action) else {
            panic!("abort was not applied");
        };
        let destination = authority.binding(&destination_id).unwrap().unwrap();
        assert!(!destination.active);
        assert!(!destination.dispatch_open);
        assert!(matches!(
            authority.query_abort_bindings(&action),
            Observation::Applied(value) if value == receipt
        ));
    }

    #[test]
    fn durable_commit_prevents_abort_even_with_an_unfenced_alternate_source() {
        let (mut authority, source, _prepare, bindings) = prepared();
        let alternate = authority.bootstrap_source("alternate", 7, Rights(3)).unwrap();
        close_source_dispatch(&authority, &source);
        let commit_action = action(
            11,
            ActionRequest::CommitFence {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(2),
                snapshot_digest: Digest::of_bytes(&2_u128.to_be_bytes()),
                source: source_coordinate(&source),
                destination: destination(),
                binding_receipt_digest: bindings.receipt_digest,
            },
        );
        assert!(matches!(authority.commit_fence(&commit_action), Observation::Applied(_)));

        let abort_action = action(
            13,
            ActionRequest::AbortBindings {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(2),
                snapshot_digest: Digest::of_bytes(&2_u128.to_be_bytes()),
                source: source_coordinate(&alternate),
                destination: destination(),
                bindings: bindings.clone(),
            },
        );
        assert!(matches!(authority.abort_bindings(&abort_action), Observation::Rejected(_)));
        assert!(matches!(authority.query_abort_bindings(&abort_action), Observation::Rejected(_)));
        assert!(authority.binding(&grant_binding(&bindings).unwrap()).unwrap().unwrap().active);
    }

    #[test]
    fn a_publicly_resealed_commit_is_not_activation_authority() {
        let (mut authority, source, _prepare, bindings) = prepared();
        close_source_dispatch(&authority, &source);
        let commit_action = action(
            11,
            ActionRequest::CommitFence {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(2),
                snapshot_digest: Digest::of_bytes(&2_u128.to_be_bytes()),
                source: source_coordinate(&source),
                destination: destination(),
                binding_receipt_digest: bindings.receipt_digest,
            },
        );
        let Observation::Applied(mut forged) = authority.commit_fence(&commit_action) else {
            panic!("commit was not applied");
        };
        forged.execution_epoch += 1;
        forged = forged.seal().unwrap();
        let permit_action = action(
            12,
            ActionRequest::PermitActivation {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(2),
                snapshot_digest: Digest::of_bytes(&2_u128.to_be_bytes()),
                destination: destination(),
                commit: forged,
            },
        );

        assert!(matches!(authority.permit_activation(&permit_action), Observation::Rejected(_)));
        assert!(
            !authority.binding(&grant_binding(&bindings).unwrap()).unwrap().unwrap().dispatch_open
        );
    }

    #[test]
    fn inactive_destination_cannot_receive_activation_permit() {
        let (mut authority, source, _prepare, bindings) = prepared();
        close_source_dispatch(&authority, &source);
        let commit_action = action(
            21,
            ActionRequest::CommitFence {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(2),
                snapshot_digest: Digest::of_bytes(&2_u128.to_be_bytes()),
                source: source_coordinate(&source),
                destination: destination(),
                binding_receipt_digest: bindings.receipt_digest,
            },
        );
        let Observation::Applied(commit) = authority.commit_fence(&commit_action) else {
            panic!("commit was not applied");
        };
        let destination_id = grant_binding(&bindings).unwrap();
        authority
            .database()
            .lock()
            .unwrap()
            .execute(
                "UPDATE visa_authority_bindings SET active = 0 WHERE binding_id = ?1",
                params![destination_id],
            )
            .unwrap();
        let permit_action = action(
            22,
            ActionRequest::PermitActivation {
                continuation: visa_core::ContinuationId::from_u128(1),
                snapshot: SnapshotId::from_u128(2),
                snapshot_digest: Digest::of_bytes(&2_u128.to_be_bytes()),
                destination: destination(),
                commit,
            },
        );

        assert!(matches!(authority.permit_activation(&permit_action), Observation::Rejected(_)));
        assert!(matches!(
            authority.query_permit_activation(&permit_action),
            Observation::Rejected(_)
        ));
    }

    #[test]
    fn corrupt_applied_receipt_is_unverifiable_not_rejected() {
        let (mut authority, _source, action, _bindings) = prepared();
        authority
            .database()
            .lock()
            .unwrap()
            .execute(
                "UPDATE visa_authority_operations SET receipt = ?2 WHERE operation_id = ?1",
                params![action.operation.0.to_vec(), vec![0xff_u8]],
            )
            .unwrap();

        assert!(matches!(
            authority.query_prepare_bindings(&action),
            Observation::Unverifiable(AuthorityError::Corrupt(_))
        ));
        assert!(matches!(
            authority.prepare_bindings(&action),
            Observation::Unverifiable(AuthorityError::Corrupt(_))
        ));
    }
}
