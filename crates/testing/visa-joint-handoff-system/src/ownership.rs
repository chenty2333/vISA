use std::{path::Path, time::Duration};

use contract_core::{Digest, EntityRef, Identity, LeaseEpoch, NodeIdentity};
use joint_handoff_core::{
    JointHandoffKey, OwnershipAbortReceipt, OwnershipCommitReceipt, OwnershipPreparedReceipt,
    PrepareIntentReceipt, PreparedBindings, ReceiptHeader, ReceiptIssuerIdentity, ReceiptKind,
    ReceiptRef, TypedReceipt, canonical_bytes, canonical_digest, canonical_from_bytes,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: i64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipReserveRequest {
    pub key: JointHandoffKey,
    pub expected_state_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipSealRequest {
    pub key: JointHandoffKey,
    pub reservation: Identity,
    pub intent: ReceiptRef,
    pub visa_freeze: ReceiptRef,
    pub effect_freeze: ReceiptRef,
    pub destination_prepared: ReceiptRef,
    pub bindings: PreparedBindings,
    pub expected_state_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipAbortRequest {
    pub key: JointHandoffKey,
    pub reservation: Identity,
    pub basis: ReceiptRef,
    pub expected_state_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipCommitRequest {
    pub key: JointHandoffKey,
    pub reservation: Identity,
    pub prepared: ReceiptRef,
    pub expected_state_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnershipQuery {
    Reserved(PrepareIntentReceipt),
    Prepared(Box<OwnershipPreparedReceipt>),
    AbortDecided(OwnershipAbortReceipt),
    CommitDecided(OwnershipCommitReceipt),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitOwnershipQuery {
    pub continuity_unit: EntityRef,
    pub owner: NodeIdentity,
    pub epoch: LeaseEpoch,
    pub active_handoff: Option<Identity>,
    pub active_reservation: Option<Identity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnershipLogError {
    InvalidRequest,
    NotFound,
    Conflict,
    AcknowledgementLost,
    OwnershipMismatch { owner: NodeIdentity, epoch: LeaseEpoch },
    StaleSequence { expected: u64, actual: u64 },
    ExistingAbort(Box<OwnershipAbortReceipt>),
    ExistingCommit(Box<OwnershipCommitReceipt>),
    Integrity,
    Storage(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredPhase {
    Reserved,
    Prepared,
    AbortDecided,
    CommitDecided,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOwnership {
    key: JointHandoffKey,
    reservation: Identity,
    state_sequence: u64,
    phase: StoredPhase,
    reserve_request_digest: Digest,
    intent: PrepareIntentReceipt,
    seal_request_digest: Option<Digest>,
    prepared: Option<OwnershipPreparedReceipt>,
    abort_request_digest: Option<Digest>,
    abort: Option<OwnershipAbortReceipt>,
    commit_request_digest: Option<Digest>,
    commit: Option<OwnershipCommitReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredUnitOwnership {
    continuity_unit: EntityRef,
    owner: NodeIdentity,
    epoch: LeaseEpoch,
    active_handoff: Option<Identity>,
    active_reservation: Option<Identity>,
}

impl StoredUnitOwnership {
    fn query(self) -> UnitOwnershipQuery {
        UnitOwnershipQuery {
            continuity_unit: self.continuity_unit,
            owner: self.owner,
            epoch: self.epoch,
            active_handoff: self.active_handoff,
            active_reservation: self.active_reservation,
        }
    }

    fn active_pair_is_valid(self) -> bool {
        self.active_handoff.is_some() == self.active_reservation.is_some()
    }
}

pub struct ReferenceOwnershipLog {
    connection: Connection,
    issuer_namespace: ReceiptIssuerIdentity,
    lose_next_commit_ack: bool,
}

impl ReferenceOwnershipLog {
    pub fn open(
        path: impl AsRef<Path>,
        issuer_namespace: ReceiptIssuerIdentity,
    ) -> Result<Self, OwnershipLogError> {
        if !well_formed_issuer(issuer_namespace) {
            return Err(OwnershipLogError::InvalidRequest);
        }
        let connection = Connection::open(path).map_err(storage)?;
        connection.busy_timeout(Duration::from_secs(5)).map_err(storage)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS ownership_unit (
                     continuity_unit BLOB NOT NULL CHECK(length(continuity_unit) = 16),
                     continuity_generation BLOB NOT NULL CHECK(length(continuity_generation) = 8),
                     record BLOB NOT NULL,
                     PRIMARY KEY(continuity_unit, continuity_generation)
                 ) WITHOUT ROWID;
                 CREATE TABLE IF NOT EXISTS ownership_handoff (
                     handoff_id BLOB PRIMARY KEY CHECK(length(handoff_id) = 16),
                     continuity_unit BLOB NOT NULL CHECK(length(continuity_unit) = 16),
                     continuity_generation BLOB NOT NULL CHECK(length(continuity_generation) = 8),
                     expected_epoch BLOB NOT NULL CHECK(length(expected_epoch) = 8),
                     record BLOB NOT NULL,
                     FOREIGN KEY(continuity_unit, continuity_generation)
                       REFERENCES ownership_unit(continuity_unit, continuity_generation)
                 ) WITHOUT ROWID;",
            )
            .map_err(storage)?;
        let version: i64 =
            connection.query_row("PRAGMA user_version", [], |row| row.get(0)).map_err(storage)?;
        if !matches!(version, 0 | SCHEMA_VERSION) {
            return Err(OwnershipLogError::Integrity);
        }
        if version == 0 {
            connection.pragma_update(None, "user_version", SCHEMA_VERSION).map_err(storage)?;
        }
        Ok(Self { connection, issuer_namespace, lose_next_commit_ack: false })
    }

    /// Test-cell transport fault: commit the next new ownership decision with
    /// SQLite durability, then suppress the typed acknowledgement. Exact
    /// query/retry remains the only way to learn the terminal receipt.
    pub fn arm_next_commit_ack_loss(&mut self) -> Result<(), OwnershipLogError> {
        if self.lose_next_commit_ack {
            return Err(OwnershipLogError::Conflict);
        }
        self.lose_next_commit_ack = true;
        Ok(())
    }

    pub fn durability_settings(&self) -> Result<(String, i64), OwnershipLogError> {
        let mode = self
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .map_err(storage)?;
        let synchronous = self
            .connection
            .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
            .map_err(storage)?;
        Ok((mode, synchronous))
    }

    pub fn initialize_unit(
        &mut self,
        continuity_unit: EntityRef,
        owner: NodeIdentity,
        epoch: LeaseEpoch,
    ) -> Result<UnitOwnershipQuery, OwnershipLogError> {
        if continuity_unit.identity.is_zero() || owner.is_zero() {
            return Err(OwnershipLogError::InvalidRequest);
        }
        let transaction = self.immediate_transaction()?;
        if let Some(existing) = load_unit(&transaction, continuity_unit)? {
            return finish(
                transaction,
                if existing.continuity_unit == continuity_unit
                    && existing.owner == owner
                    && existing.epoch == epoch
                    && existing.active_pair_is_valid()
                {
                    Ok(existing.query())
                } else {
                    Err(OwnershipLogError::Conflict)
                },
            );
        }
        let stored = StoredUnitOwnership {
            continuity_unit,
            owner,
            epoch,
            active_handoff: None,
            active_reservation: None,
        };
        insert_unit(&transaction, &stored)?;
        finish(transaction, Ok(stored.query()))
    }

    pub fn reserve(
        &mut self,
        request: OwnershipReserveRequest,
    ) -> Result<PrepareIntentReceipt, OwnershipLogError> {
        if !request.key.is_well_formed() || request.expected_state_sequence != 0 {
            return Err(OwnershipLogError::InvalidRequest);
        }
        let request_digest = digest_request(&request)?;
        let issuer = ownership_receipt_issuer(self.issuer_namespace, request.key)?;
        let transaction = self.immediate_transaction()?;
        if let Some(existing) = load_handoff(&transaction, request.key.handoff)? {
            return finish(
                transaction,
                if existing.key == request.key && existing.reserve_request_digest == request_digest
                {
                    Ok(existing.intent)
                } else {
                    Err(OwnershipLogError::Conflict)
                },
            );
        }
        let mut unit = load_unit(&transaction, request.key.continuity_unit)?
            .ok_or(OwnershipLogError::NotFound)?;
        require_owned_source(&unit, request.key)?;
        if unit.active_handoff.is_some() || unit.active_reservation.is_some() {
            return Err(OwnershipLogError::Conflict);
        }
        let reservation = derived_identity(b"ownership-reservation", &request)?;
        let intent = PrepareIntentReceipt {
            header: header(issuer, ReceiptKind::PrepareIntent, 1, None),
            key: request.key,
            ownership_service: issuer.issuer,
            service_incarnation: issuer.issuer_incarnation,
            reservation,
            intent_revision: 1,
            request_digest,
        };
        let stored = StoredOwnership {
            key: request.key,
            reservation,
            state_sequence: 1,
            phase: StoredPhase::Reserved,
            reserve_request_digest: request_digest,
            intent: intent.clone(),
            seal_request_digest: None,
            prepared: None,
            abort_request_digest: None,
            abort: None,
            commit_request_digest: None,
            commit: None,
        };
        unit.active_handoff = Some(request.key.handoff);
        unit.active_reservation = Some(reservation);
        insert_handoff(&transaction, &stored)?;
        update_unit(&transaction, &unit)?;
        finish(transaction, Ok(intent))
    }

    pub fn seal(
        &mut self,
        request: OwnershipSealRequest,
    ) -> Result<OwnershipPreparedReceipt, OwnershipLogError> {
        let request_digest = digest_request(&request)?;
        let issuer = ownership_receipt_issuer(self.issuer_namespace, request.key)?;
        let transaction = self.immediate_transaction()?;
        let mut stored =
            load_handoff(&transaction, request.key.handoff)?.ok_or(OwnershipLogError::NotFound)?;
        validate_record_request(&stored, request.key, request.reservation)?;
        if let Some(existing_digest) = stored.seal_request_digest {
            let result = if existing_digest == request_digest {
                stored.prepared.clone().ok_or(OwnershipLogError::Integrity)
            } else {
                Err(OwnershipLogError::Conflict)
            };
            return finish(transaction, result);
        }
        let unit = load_unit(&transaction, request.key.continuity_unit)?
            .ok_or(OwnershipLogError::Integrity)?;
        require_active(&unit, &stored)?;
        require_sequence(stored.state_sequence, request.expected_state_sequence)?;
        if stored.phase != StoredPhase::Reserved
            || request.intent
                != stored.intent.receipt_ref().map_err(|_| OwnershipLogError::Integrity)?
            || !valid_reference(request.visa_freeze, ReceiptKind::VisaFreeze, request.key)
            || !valid_reference(request.effect_freeze, ReceiptKind::NexusFreeze, request.key)
            || !valid_reference(
                request.destination_prepared,
                ReceiptKind::DestinationPrepared,
                request.key,
            )
            || !bindings_match(&request)
        {
            return Err(OwnershipLogError::InvalidRequest);
        }
        let next_sequence = next_sequence(stored.state_sequence)?;
        let intent_ref = stored.intent.receipt_ref().map_err(|_| OwnershipLogError::Integrity)?;
        let prepared = OwnershipPreparedReceipt {
            header: header(
                issuer,
                ReceiptKind::OwnershipPrepared,
                next_sequence,
                Some(intent_ref.digest),
            ),
            key: request.key,
            reservation: request.reservation,
            intent: request.intent,
            visa_freeze: request.visa_freeze,
            nexus_freeze: request.effect_freeze,
            destination_prepared: request.destination_prepared,
            bindings: request.bindings,
            prepared_revision: next_sequence,
        };
        stored.state_sequence = next_sequence;
        stored.phase = StoredPhase::Prepared;
        stored.seal_request_digest = Some(request_digest);
        stored.prepared = Some(prepared.clone());
        update_handoff(&transaction, &stored)?;
        finish(transaction, Ok(prepared))
    }

    pub fn abort(
        &mut self,
        request: OwnershipAbortRequest,
    ) -> Result<OwnershipAbortReceipt, OwnershipLogError> {
        let request_digest = digest_request(&request)?;
        let issuer = ownership_receipt_issuer(self.issuer_namespace, request.key)?;
        let transaction = self.immediate_transaction()?;
        let mut stored =
            load_handoff(&transaction, request.key.handoff)?.ok_or(OwnershipLogError::NotFound)?;
        validate_record_request(&stored, request.key, request.reservation)?;
        if let Some(commit) = stored.commit {
            return Err(OwnershipLogError::ExistingCommit(Box::new(commit)));
        }
        if let Some(existing_digest) = stored.abort_request_digest {
            let result = if existing_digest == request_digest {
                stored.abort.ok_or(OwnershipLogError::Integrity)
            } else {
                Err(OwnershipLogError::Conflict)
            };
            return finish(transaction, result);
        }
        let mut unit = load_unit(&transaction, request.key.continuity_unit)?
            .ok_or(OwnershipLogError::Integrity)?;
        require_active(&unit, &stored)?;
        require_sequence(stored.state_sequence, request.expected_state_sequence)?;
        let (basis, basis_revision) = match &stored.prepared {
            Some(prepared) => (
                prepared.receipt_ref().map_err(|_| OwnershipLogError::Integrity)?,
                prepared.prepared_revision,
            ),
            None => (
                stored.intent.receipt_ref().map_err(|_| OwnershipLogError::Integrity)?,
                stored.intent.intent_revision,
            ),
        };
        if request.basis != basis {
            return Err(OwnershipLogError::InvalidRequest);
        }
        let sequence = next_sequence(stored.state_sequence)?;
        let abort = OwnershipAbortReceipt {
            header: header(issuer, ReceiptKind::OwnershipAbort, sequence, Some(basis.digest)),
            key: request.key,
            reservation: request.reservation,
            basis,
            basis_revision,
            decision_sequence: sequence,
            non_equivocation_root: decision_root(
                request.key,
                request.reservation,
                b"abort",
                sequence,
            )?,
        };
        stored.state_sequence = sequence;
        stored.phase = StoredPhase::AbortDecided;
        stored.abort_request_digest = Some(request_digest);
        stored.abort = Some(abort.clone());
        clear_active(&mut unit, &stored)?;
        update_handoff(&transaction, &stored)?;
        update_unit(&transaction, &unit)?;
        finish(transaction, Ok(abort))
    }

    pub fn commit(
        &mut self,
        request: OwnershipCommitRequest,
    ) -> Result<OwnershipCommitReceipt, OwnershipLogError> {
        let request_digest = digest_request(&request)?;
        let issuer = ownership_receipt_issuer(self.issuer_namespace, request.key)?;
        let transaction = self.immediate_transaction()?;
        let mut stored =
            load_handoff(&transaction, request.key.handoff)?.ok_or(OwnershipLogError::NotFound)?;
        validate_record_request(&stored, request.key, request.reservation)?;
        if let Some(abort) = stored.abort {
            return Err(OwnershipLogError::ExistingAbort(Box::new(abort)));
        }
        if let Some(existing_digest) = stored.commit_request_digest {
            let result = if existing_digest == request_digest {
                stored.commit.ok_or(OwnershipLogError::Integrity)
            } else {
                Err(OwnershipLogError::Conflict)
            };
            return finish(transaction, result);
        }
        let mut unit = load_unit(&transaction, request.key.continuity_unit)?
            .ok_or(OwnershipLogError::Integrity)?;
        require_active(&unit, &stored)?;
        require_sequence(stored.state_sequence, request.expected_state_sequence)?;
        let prepared = stored.prepared.as_ref().ok_or(OwnershipLogError::InvalidRequest)?;
        let prepared_ref = prepared.receipt_ref().map_err(|_| OwnershipLogError::Integrity)?;
        if stored.phase != StoredPhase::Prepared || request.prepared != prepared_ref {
            return Err(OwnershipLogError::InvalidRequest);
        }
        let sequence = next_sequence(stored.state_sequence)?;
        let commit = OwnershipCommitReceipt {
            header: header(
                issuer,
                ReceiptKind::OwnershipCommit,
                sequence,
                Some(prepared_ref.digest),
            ),
            key: request.key,
            reservation: request.reservation,
            prepared: prepared_ref,
            prepared_revision: prepared.prepared_revision,
            decision_sequence: sequence,
            non_equivocation_root: decision_root(
                request.key,
                request.reservation,
                b"commit",
                sequence,
            )?,
        };
        stored.state_sequence = sequence;
        stored.phase = StoredPhase::CommitDecided;
        stored.commit_request_digest = Some(request_digest);
        stored.commit = Some(commit.clone());
        clear_active(&mut unit, &stored)?;
        unit.owner = request.key.destination;
        unit.epoch = request.key.next_epoch;
        update_handoff(&transaction, &stored)?;
        update_unit(&transaction, &unit)?;
        let committed = finish(transaction, Ok(commit));
        if committed.is_ok() && self.lose_next_commit_ack {
            self.lose_next_commit_ack = false;
            return Err(OwnershipLogError::AcknowledgementLost);
        }
        committed
    }

    pub fn query(&self, handoff: Identity) -> Result<Option<OwnershipQuery>, OwnershipLogError> {
        let Some(stored) = load_handoff(&self.connection, handoff)? else {
            return Ok(None);
        };
        Ok(Some(match stored.phase {
            StoredPhase::Reserved => OwnershipQuery::Reserved(stored.intent),
            StoredPhase::Prepared => OwnershipQuery::Prepared(Box::new(
                stored.prepared.ok_or(OwnershipLogError::Integrity)?,
            )),
            StoredPhase::AbortDecided => {
                OwnershipQuery::AbortDecided(stored.abort.ok_or(OwnershipLogError::Integrity)?)
            }
            StoredPhase::CommitDecided => {
                OwnershipQuery::CommitDecided(stored.commit.ok_or(OwnershipLogError::Integrity)?)
            }
        }))
    }

    pub fn query_unit(
        &self,
        continuity_unit: EntityRef,
    ) -> Result<Option<UnitOwnershipQuery>, OwnershipLogError> {
        load_unit(&self.connection, continuity_unit)?
            .map(|stored| {
                if stored.active_pair_is_valid() {
                    Ok(stored.query())
                } else {
                    Err(OwnershipLogError::Integrity)
                }
            })
            .transpose()
    }

    fn immediate_transaction(&mut self) -> Result<Transaction<'_>, OwnershipLogError> {
        self.connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)
    }
}

fn require_owned_source(
    unit: &StoredUnitOwnership,
    key: JointHandoffKey,
) -> Result<(), OwnershipLogError> {
    if !unit.active_pair_is_valid() || unit.continuity_unit != key.continuity_unit {
        return Err(OwnershipLogError::Integrity);
    }
    if unit.owner != key.source || unit.epoch != key.expected_epoch {
        return Err(OwnershipLogError::OwnershipMismatch { owner: unit.owner, epoch: unit.epoch });
    }
    Ok(())
}

fn require_active(
    unit: &StoredUnitOwnership,
    stored: &StoredOwnership,
) -> Result<(), OwnershipLogError> {
    require_owned_source(unit, stored.key)?;
    if unit.active_handoff != Some(stored.key.handoff)
        || unit.active_reservation != Some(stored.reservation)
    {
        return Err(OwnershipLogError::Conflict);
    }
    Ok(())
}

fn clear_active(
    unit: &mut StoredUnitOwnership,
    stored: &StoredOwnership,
) -> Result<(), OwnershipLogError> {
    if unit.active_handoff != Some(stored.key.handoff)
        || unit.active_reservation != Some(stored.reservation)
    {
        return Err(OwnershipLogError::Conflict);
    }
    unit.active_handoff = None;
    unit.active_reservation = None;
    Ok(())
}

pub fn ownership_receipt_issuer(
    namespace: ReceiptIssuerIdentity,
    key: JointHandoffKey,
) -> Result<ReceiptIssuerIdentity, OwnershipLogError> {
    if !well_formed_issuer(namespace) || !key.is_well_formed() {
        return Err(OwnershipLogError::InvalidRequest);
    }
    let log_id = derived_identity(b"ownership-handoff-log", &(namespace.log_id, key.handoff))?;
    Ok(ReceiptIssuerIdentity { log_id, ..namespace })
}

fn well_formed_issuer(issuer: ReceiptIssuerIdentity) -> bool {
    !issuer.issuer.is_zero()
        && !issuer.issuer_incarnation.is_zero()
        && !issuer.key_id.is_zero()
        && !issuer.log_id.is_zero()
}

fn header(
    issuer: ReceiptIssuerIdentity,
    kind: ReceiptKind,
    sequence: u64,
    previous_digest: Option<Digest>,
) -> ReceiptHeader {
    ReceiptHeader {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        issuer: issuer.issuer,
        issuer_incarnation: issuer.issuer_incarnation,
        key_id: issuer.key_id,
        log_id: issuer.log_id,
        sequence,
        previous_digest,
    }
}

fn digest_request(request: &impl Serialize) -> Result<Digest, OwnershipLogError> {
    canonical_digest(request).map_err(|_| OwnershipLogError::InvalidRequest)
}

fn derived_identity(domain: &[u8], value: &impl Serialize) -> Result<Identity, OwnershipLogError> {
    let digest =
        canonical_digest(&(domain, value)).map_err(|_| OwnershipLogError::InvalidRequest)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    let identity = Identity::from_bytes(bytes);
    if identity.is_zero() { Err(OwnershipLogError::InvalidRequest) } else { Ok(identity) }
}

fn decision_root(
    key: JointHandoffKey,
    reservation: Identity,
    decision: &[u8],
    sequence: u64,
) -> Result<Digest, OwnershipLogError> {
    canonical_digest(&(
        b"vISA reference ownership decision v1".as_slice(),
        key,
        reservation,
        decision,
        sequence,
    ))
    .map_err(|_| OwnershipLogError::InvalidRequest)
}

fn validate_record_request(
    stored: &StoredOwnership,
    key: JointHandoffKey,
    reservation: Identity,
) -> Result<(), OwnershipLogError> {
    if !key.is_well_formed() || stored.key != key || stored.reservation != reservation {
        return Err(OwnershipLogError::InvalidRequest);
    }
    Ok(())
}

fn require_sequence(actual: u64, expected: u64) -> Result<(), OwnershipLogError> {
    if actual == expected {
        Ok(())
    } else {
        Err(OwnershipLogError::StaleSequence { expected, actual })
    }
}

fn next_sequence(current: u64) -> Result<u64, OwnershipLogError> {
    current.checked_add(1).ok_or(OwnershipLogError::InvalidRequest)
}

fn valid_reference(reference: ReceiptRef, kind: ReceiptKind, key: JointHandoffKey) -> bool {
    reference.version.is_supported()
        && reference.kind == kind
        && reference.handoff == key.handoff
        && !reference.issuer.is_zero()
        && !reference.issuer_incarnation.is_zero()
        && !reference.key_id.is_zero()
        && !reference.log_id.is_zero()
        && reference.sequence > 0
        && reference.digest != Digest::ZERO
}

fn bindings_match(request: &OwnershipSealRequest) -> bool {
    let bindings = request.bindings;
    bindings.prepare_intent_receipt_digest == request.intent.digest
        && bindings.visa_freeze_receipt_digest == request.visa_freeze.digest
        && bindings.effect_freeze_receipt_digest == request.effect_freeze.digest
        && bindings.destination_prepared_receipt_digest == request.destination_prepared.digest
        && bindings.snapshot != Identity::ZERO
        && [
            bindings.snapshot_integrity_digest,
            bindings.source_state_digest,
            bindings.component_digest,
            bindings.profile_digest,
            bindings.destination_state_digest,
            bindings.prepared_authorities_digest,
            bindings.prepared_bindings_digest,
            bindings.effect_cohort_manifest_digest,
            bindings.joint_mapping_manifest_digest,
        ]
        .into_iter()
        .all(|digest| digest != Digest::ZERO)
}

fn load_handoff(
    connection: &Connection,
    handoff: Identity,
) -> Result<Option<StoredOwnership>, OwnershipLogError> {
    let stored: Option<StoredOwnership> = load_record(
        connection,
        "SELECT record FROM ownership_handoff WHERE handoff_id = ?1",
        params![handoff.0.as_slice()],
    )?;
    if stored.as_ref().is_some_and(|record| record.key.handoff != handoff) {
        return Err(OwnershipLogError::Integrity);
    }
    Ok(stored)
}

fn load_unit(
    connection: &Connection,
    continuity_unit: EntityRef,
) -> Result<Option<StoredUnitOwnership>, OwnershipLogError> {
    let generation = continuity_unit.generation.0.to_be_bytes();
    let stored: Option<StoredUnitOwnership> = load_record(
        connection,
        "SELECT record FROM ownership_unit
         WHERE continuity_unit = ?1 AND continuity_generation = ?2",
        params![continuity_unit.identity.0.as_slice(), generation.as_slice()],
    )?;
    if stored.as_ref().is_some_and(|record| record.continuity_unit != continuity_unit) {
        return Err(OwnershipLogError::Integrity);
    }
    Ok(stored)
}

fn load_record<T>(
    connection: &Connection,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> Result<Option<T>, OwnershipLogError>
where
    T: for<'de> Deserialize<'de>,
{
    connection
        .query_row(sql, parameters, |row| row.get::<_, Vec<u8>>(0))
        .optional()
        .map_err(storage)?
        .map(|bytes| canonical_from_bytes(&bytes).map_err(|_| OwnershipLogError::Integrity))
        .transpose()
}

fn insert_unit(
    transaction: &Transaction<'_>,
    stored: &StoredUnitOwnership,
) -> Result<(), OwnershipLogError> {
    let bytes = canonical_bytes(stored).map_err(|_| OwnershipLogError::Integrity)?;
    let generation = stored.continuity_unit.generation.0.to_be_bytes();
    execute_change(
        transaction,
        "INSERT INTO ownership_unit(continuity_unit, continuity_generation, record)
         VALUES (?1, ?2, ?3)",
        params![stored.continuity_unit.identity.0.as_slice(), generation.as_slice(), bytes,],
    )
}

fn update_unit(
    transaction: &Transaction<'_>,
    stored: &StoredUnitOwnership,
) -> Result<(), OwnershipLogError> {
    let bytes = canonical_bytes(stored).map_err(|_| OwnershipLogError::Integrity)?;
    let generation = stored.continuity_unit.generation.0.to_be_bytes();
    let changed = transaction
        .execute(
            "UPDATE ownership_unit SET record = ?3
             WHERE continuity_unit = ?1 AND continuity_generation = ?2",
            params![stored.continuity_unit.identity.0.as_slice(), generation.as_slice(), bytes,],
        )
        .map_err(storage)?;
    if changed == 1 { Ok(()) } else { Err(OwnershipLogError::Integrity) }
}

fn insert_handoff(
    transaction: &Transaction<'_>,
    stored: &StoredOwnership,
) -> Result<(), OwnershipLogError> {
    let bytes = canonical_bytes(stored).map_err(|_| OwnershipLogError::Integrity)?;
    let generation = stored.key.continuity_unit.generation.0.to_be_bytes();
    let epoch = stored.key.expected_epoch.0.to_be_bytes();
    execute_change(
        transaction,
        "INSERT INTO ownership_handoff(
             handoff_id, continuity_unit, continuity_generation, expected_epoch, record
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            stored.key.handoff.0.as_slice(),
            stored.key.continuity_unit.identity.0.as_slice(),
            generation.as_slice(),
            epoch.as_slice(),
            bytes,
        ],
    )
}

fn update_handoff(
    transaction: &Transaction<'_>,
    stored: &StoredOwnership,
) -> Result<(), OwnershipLogError> {
    let bytes = canonical_bytes(stored).map_err(|_| OwnershipLogError::Integrity)?;
    let changed = transaction
        .execute(
            "UPDATE ownership_handoff SET record = ?2 WHERE handoff_id = ?1",
            params![stored.key.handoff.0.as_slice(), bytes],
        )
        .map_err(storage)?;
    if changed == 1 { Ok(()) } else { Err(OwnershipLogError::Integrity) }
}

fn execute_change(
    transaction: &Transaction<'_>,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> Result<(), OwnershipLogError> {
    transaction.execute(sql, parameters).map_err(|error| {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
            OwnershipLogError::Conflict
        } else {
            storage(error)
        }
    })?;
    Ok(())
}

fn finish<T>(
    transaction: Transaction<'_>,
    result: Result<T, OwnershipLogError>,
) -> Result<T, OwnershipLogError> {
    transaction.commit().map_err(storage)?;
    result
}

fn storage(error: rusqlite::Error) -> OwnershipLogError {
    OwnershipLogError::Storage(error.to_string())
}
