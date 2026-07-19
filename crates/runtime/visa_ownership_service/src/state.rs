use std::collections::BTreeMap;

use contract_core::{Digest, EntityRef, Generation, Identity, LeaseEpoch, NodeIdentity};
use joint_handoff_core::{
    ApplyResult, Command, CommandKind, Decision, DestinationPreparedReceipt, JointHandoffKey,
    JointState, NexusFreezeReceipt, OwnershipAbortReceipt, OwnershipCommitReceipt,
    OwnershipPreparedReceipt, PrepareIntentReceipt, ReceiptHeader, ReceiptIssuerIdentity,
    ReceiptIssuerRole, ReceiptKind, TypedReceipt, VisaFreezeReceipt, apply as apply_joint_event,
    canonical_bytes, canonical_digest, canonical_from_bytes, preflight as preflight_joint,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use visa_local_rpc::{
    WireValidation,
    common::{
        ContinuityUnitId, EntityRefWire, HandoffId, JointHandoffKeyWire, NodeId, ReservationId,
    },
    ownership as wire,
};

use crate::{
    LocalReceiptAuthenticator, OwnershipServiceError, PinnedLocalReceiptAuthenticator,
    SqliteFailureClass, classify_sqlite_error,
    proposal::{
        decode_abort_proposal, decode_commit_proposal, decode_reserve_proposal,
        decode_seal_proposal, require_supported_version,
    },
    receipt::{admit_receipt, ownership_issuer_for_handoff, receipt_artifact},
};

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

pub(crate) fn apply_operation<A: LocalReceiptAuthenticator>(
    transaction: &Transaction<'_>,
    request: &wire::Request,
    issuer_namespace: ReceiptIssuerIdentity,
    authenticator: &A,
) -> Result<wire::Outcome, OwnershipServiceError> {
    let result = match &request.operation {
        wire::Operation::InitializeUnit(value) => initialize_unit(transaction, *value),
        wire::Operation::Reserve(value) => {
            reserve(transaction, value, issuer_namespace).map(wire::Success::Reserved)
        }
        wire::Operation::Seal(value) => {
            seal(transaction, value, issuer_namespace, authenticator).map(wire::Success::Prepared)
        }
        wire::Operation::Abort(value) => {
            abort(transaction, value, issuer_namespace, authenticator).map(wire::Success::Aborted)
        }
        wire::Operation::Commit(value) => {
            commit(transaction, value, issuer_namespace, authenticator)
                .map(wire::Success::Committed)
        }
        wire::Operation::Query(value) => query(transaction, *value),
    };
    match result {
        Ok(success) => Ok(wire::Outcome::Success(success)),
        Err(SemanticError::Rejected(rejection)) => Ok(wire::Outcome::Rejected(*rejection)),
        Err(SemanticError::Integrity) => Err(OwnershipServiceError::Integrity),
        Err(SemanticError::Busy) => Err(OwnershipServiceError::StoreBusy),
        Err(SemanticError::Storage) => Err(OwnershipServiceError::Storage),
    }
}

fn initialize_unit(
    transaction: &Transaction<'_>,
    request: wire::InitializeUnitRequest,
) -> SemanticResult<wire::Success> {
    request.validate().map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    let continuity_unit = joint_entity(request.continuity_unit);
    let owner = joint_node(request.owner);
    if let Some(existing) = load_unit(transaction, continuity_unit)? {
        return if existing.continuity_unit == continuity_unit
            && existing.owner == owner
            && existing.epoch == LeaseEpoch(request.epoch)
            && existing.active_pair_is_valid()
        {
            Ok(wire::Success::Initialized(unit_to_wire(existing)))
        } else {
            Err(rejected(wire::Rejection::Conflict))
        };
    }
    let stored = StoredUnitOwnership {
        continuity_unit,
        owner,
        epoch: LeaseEpoch(request.epoch),
        active_handoff: None,
        active_reservation: None,
    };
    insert_unit(transaction, &stored)?;
    Ok(wire::Success::Initialized(unit_to_wire(stored)))
}

fn reserve(
    transaction: &Transaction<'_>,
    request: &wire::DecisionProposal,
    issuer_namespace: ReceiptIssuerIdentity,
) -> SemanticResult<visa_local_rpc::common::ReceiptArtifact> {
    let proposal = decode_reserve_proposal(&request.proposal)
        .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    require_supported_version(proposal.version)
        .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    let key = joint_key(request.key);
    if !key.is_well_formed() || request.expected_state_sequence != 0 {
        return Err(rejected(wire::Rejection::InvalidRequest));
    }
    let request_digest =
        semantic_digest(b"reserve", key, request.expected_state_sequence, &proposal)?;
    let issuer = ownership_issuer(issuer_namespace, key)?;
    if let Some(existing) = load_handoff(transaction, key.handoff)? {
        return if existing.key == key && existing.reserve_request_digest == request_digest {
            receipt_artifact(&existing.intent).map_err(|_| SemanticError::Integrity)
        } else {
            Err(rejected(wire::Rejection::Conflict))
        };
    }
    let mut unit = load_unit(transaction, key.continuity_unit)?
        .ok_or_else(|| rejected(wire::Rejection::NotFound))?;
    require_owned_source(&unit, key)?;
    if unit.active_handoff.is_some() || unit.active_reservation.is_some() {
        return Err(rejected(wire::Rejection::Conflict));
    }
    let reservation = derived_identity(
        b"vISA/ownership/reservation/v1\0",
        &(issuer_namespace, key, request_digest),
    )?;
    let intent = PrepareIntentReceipt {
        header: header(issuer, ReceiptKind::PrepareIntent, 1, None),
        key,
        ownership_service: issuer.issuer,
        service_incarnation: issuer.issuer_incarnation,
        reservation,
        intent_revision: 1,
        request_digest,
    };
    let stored = StoredOwnership {
        key,
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
    validate_stored_handoff(&stored, issuer_namespace)?;
    unit.active_handoff = Some(key.handoff);
    unit.active_reservation = Some(reservation);
    insert_handoff(transaction, &stored)?;
    update_unit(transaction, &unit)?;
    receipt_artifact(&intent).map_err(|_| SemanticError::Integrity)
}

fn seal<A: LocalReceiptAuthenticator>(
    transaction: &Transaction<'_>,
    request: &wire::DecisionProposal,
    issuer_namespace: ReceiptIssuerIdentity,
    authenticator: &A,
) -> SemanticResult<visa_local_rpc::common::ReceiptArtifact> {
    let proposal = decode_seal_proposal(&request.proposal)
        .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    require_supported_version(proposal.version)
        .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    let key = joint_key(request.key);
    let request_digest = semantic_digest(b"seal", key, request.expected_state_sequence, &proposal)?;
    let issuer = ownership_issuer(issuer_namespace, key)?;
    let mut stored = load_handoff(transaction, key.handoff)?
        .ok_or_else(|| rejected(wire::Rejection::NotFound))?;
    validate_record_request(&stored, key, proposal.reservation)?;
    if let Some(existing_digest) = stored.seal_request_digest {
        return if existing_digest == request_digest {
            stored
                .prepared
                .as_ref()
                .ok_or(SemanticError::Integrity)
                .and_then(|value| receipt_artifact(value).map_err(|_| SemanticError::Integrity))
        } else {
            Err(rejected(wire::Rejection::Conflict))
        };
    }
    let unit = load_unit(transaction, key.continuity_unit)?.ok_or(SemanticError::Integrity)?;
    require_active(&unit, &stored)?;
    require_sequence(stored.state_sequence, request.expected_state_sequence)?;
    if stored.phase != StoredPhase::Reserved {
        return Err(rejected(wire::Rejection::InvalidRequest));
    }

    let intent = admit_receipt::<PrepareIntentReceipt, _>(
        &proposal.intent,
        key,
        ReceiptIssuerRole::Ownership,
        authenticator,
    )
    .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    let expected_intent = receipt_artifact(&stored.intent).map_err(|_| SemanticError::Integrity)?;
    if proposal.intent != expected_intent || intent.receipt() != &stored.intent {
        return Err(rejected(wire::Rejection::InvalidRequest));
    }
    let visa_freeze = admit_receipt::<VisaFreezeReceipt, _>(
        &proposal.visa_freeze,
        key,
        ReceiptIssuerRole::VisaSource,
        authenticator,
    )
    .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    let nexus_freeze = admit_receipt::<NexusFreezeReceipt, _>(
        &proposal.nexus_freeze,
        key,
        ReceiptIssuerRole::EffectClosure,
        authenticator,
    )
    .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    let destination = admit_receipt::<DestinationPreparedReceipt, _>(
        &proposal.destination_prepared,
        key,
        ReceiptIssuerRole::VisaDestination,
        authenticator,
    )
    .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;

    let intent_ref = intent.reference();
    let visa_ref = visa_freeze.reference();
    let nexus_ref = nexus_freeze.reference();
    let destination_ref = destination.reference();
    let next_sequence = next_sequence(stored.state_sequence)?;
    let prepared = OwnershipPreparedReceipt {
        header: header(
            issuer,
            ReceiptKind::OwnershipPrepared,
            next_sequence,
            Some(intent_ref.digest),
        ),
        key,
        reservation: proposal.reservation,
        intent: intent_ref,
        visa_freeze: visa_ref,
        nexus_freeze: nexus_ref,
        destination_prepared: destination_ref,
        bindings: proposal.bindings,
        prepared_revision: next_sequence,
    };
    validate_seal_chain(
        &stored.intent,
        visa_freeze.receipt(),
        nexus_freeze.receipt(),
        destination.receipt(),
        &prepared,
    )?;
    stored.state_sequence = next_sequence;
    stored.phase = StoredPhase::Prepared;
    stored.seal_request_digest = Some(request_digest);
    stored.prepared = Some(prepared.clone());
    validate_stored_handoff(&stored, issuer_namespace)?;
    update_handoff(transaction, &stored)?;
    receipt_artifact(&prepared).map_err(|_| SemanticError::Integrity)
}

fn abort<A: LocalReceiptAuthenticator>(
    transaction: &Transaction<'_>,
    request: &wire::DecisionProposal,
    issuer_namespace: ReceiptIssuerIdentity,
    authenticator: &A,
) -> SemanticResult<visa_local_rpc::common::ReceiptArtifact> {
    let proposal = decode_abort_proposal(&request.proposal)
        .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    require_supported_version(proposal.version)
        .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    let key = joint_key(request.key);
    let request_digest =
        semantic_digest(b"abort", key, request.expected_state_sequence, &proposal)?;
    let issuer = ownership_issuer(issuer_namespace, key)?;
    let mut stored = load_handoff(transaction, key.handoff)?
        .ok_or_else(|| rejected(wire::Rejection::NotFound))?;
    validate_record_request(&stored, key, proposal.reservation)?;
    if let Some(commit) = stored.commit.as_ref() {
        let artifact = receipt_artifact(commit).map_err(|_| SemanticError::Integrity)?;
        return Err(rejected(wire::Rejection::ExistingCommit(artifact)));
    }
    if let Some(existing_digest) = stored.abort_request_digest {
        return if existing_digest == request_digest {
            stored
                .abort
                .as_ref()
                .ok_or(SemanticError::Integrity)
                .and_then(|value| receipt_artifact(value).map_err(|_| SemanticError::Integrity))
        } else {
            Err(rejected(wire::Rejection::Conflict))
        };
    }
    let mut unit = load_unit(transaction, key.continuity_unit)?.ok_or(SemanticError::Integrity)?;
    require_active(&unit, &stored)?;
    require_sequence(stored.state_sequence, request.expected_state_sequence)?;

    let (basis, basis_revision, expected_artifact) = match stored.prepared.as_ref() {
        Some(prepared) => {
            let admitted = admit_receipt::<OwnershipPreparedReceipt, _>(
                &proposal.basis,
                key,
                ReceiptIssuerRole::Ownership,
                authenticator,
            )
            .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
            (
                admitted.reference(),
                prepared.prepared_revision,
                receipt_artifact(prepared).map_err(|_| SemanticError::Integrity)?,
            )
        }
        None => {
            let admitted = admit_receipt::<PrepareIntentReceipt, _>(
                &proposal.basis,
                key,
                ReceiptIssuerRole::Ownership,
                authenticator,
            )
            .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
            (
                admitted.reference(),
                stored.intent.intent_revision,
                receipt_artifact(&stored.intent).map_err(|_| SemanticError::Integrity)?,
            )
        }
    };
    if proposal.basis != expected_artifact {
        return Err(rejected(wire::Rejection::InvalidRequest));
    }
    let sequence = next_sequence(stored.state_sequence)?;
    let abort = OwnershipAbortReceipt {
        header: header(issuer, ReceiptKind::OwnershipAbort, sequence, Some(basis.digest)),
        key,
        reservation: proposal.reservation,
        basis,
        basis_revision,
        decision_sequence: sequence,
        non_equivocation_root: decision_root(key, proposal.reservation, b"abort", sequence)?,
    };
    stored.state_sequence = sequence;
    stored.phase = StoredPhase::AbortDecided;
    stored.abort_request_digest = Some(request_digest);
    stored.abort = Some(abort.clone());
    clear_active(&mut unit, &stored)?;
    validate_stored_handoff(&stored, issuer_namespace)?;
    update_handoff(transaction, &stored)?;
    update_unit(transaction, &unit)?;
    receipt_artifact(&abort).map_err(|_| SemanticError::Integrity)
}

fn commit<A: LocalReceiptAuthenticator>(
    transaction: &Transaction<'_>,
    request: &wire::DecisionProposal,
    issuer_namespace: ReceiptIssuerIdentity,
    authenticator: &A,
) -> SemanticResult<visa_local_rpc::common::ReceiptArtifact> {
    let proposal = decode_commit_proposal(&request.proposal)
        .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    require_supported_version(proposal.version)
        .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    let key = joint_key(request.key);
    let request_digest =
        semantic_digest(b"commit", key, request.expected_state_sequence, &proposal)?;
    let issuer = ownership_issuer(issuer_namespace, key)?;
    let mut stored = load_handoff(transaction, key.handoff)?
        .ok_or_else(|| rejected(wire::Rejection::NotFound))?;
    validate_record_request(&stored, key, proposal.reservation)?;
    if let Some(abort) = stored.abort.as_ref() {
        let artifact = receipt_artifact(abort).map_err(|_| SemanticError::Integrity)?;
        return Err(rejected(wire::Rejection::ExistingAbort(artifact)));
    }
    if let Some(existing_digest) = stored.commit_request_digest {
        return if existing_digest == request_digest {
            stored
                .commit
                .as_ref()
                .ok_or(SemanticError::Integrity)
                .and_then(|value| receipt_artifact(value).map_err(|_| SemanticError::Integrity))
        } else {
            Err(rejected(wire::Rejection::Conflict))
        };
    }
    let mut unit = load_unit(transaction, key.continuity_unit)?.ok_or(SemanticError::Integrity)?;
    require_active(&unit, &stored)?;
    require_sequence(stored.state_sequence, request.expected_state_sequence)?;
    let prepared =
        stored.prepared.as_ref().ok_or_else(|| rejected(wire::Rejection::InvalidRequest))?;
    let admitted = admit_receipt::<OwnershipPreparedReceipt, _>(
        &proposal.prepared,
        key,
        ReceiptIssuerRole::Ownership,
        authenticator,
    )
    .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    let expected_artifact = receipt_artifact(prepared).map_err(|_| SemanticError::Integrity)?;
    if stored.phase != StoredPhase::Prepared
        || proposal.prepared != expected_artifact
        || admitted.receipt() != prepared
    {
        return Err(rejected(wire::Rejection::InvalidRequest));
    }
    let prepared_ref = admitted.reference();
    let sequence = next_sequence(stored.state_sequence)?;
    let commit = OwnershipCommitReceipt {
        header: header(issuer, ReceiptKind::OwnershipCommit, sequence, Some(prepared_ref.digest)),
        key,
        reservation: proposal.reservation,
        prepared: prepared_ref,
        prepared_revision: prepared.prepared_revision,
        decision_sequence: sequence,
        non_equivocation_root: decision_root(key, proposal.reservation, b"commit", sequence)?,
    };
    stored.state_sequence = sequence;
    stored.phase = StoredPhase::CommitDecided;
    stored.commit_request_digest = Some(request_digest);
    stored.commit = Some(commit.clone());
    clear_active(&mut unit, &stored)?;
    unit.owner = key.destination;
    unit.epoch = key.next_epoch;
    validate_stored_handoff(&stored, issuer_namespace)?;
    update_handoff(transaction, &stored)?;
    update_unit(transaction, &unit)?;
    receipt_artifact(&commit).map_err(|_| SemanticError::Integrity)
}

fn query(
    transaction: &Transaction<'_>,
    query: wire::QueryRequest,
) -> SemanticResult<wire::Success> {
    let result = match query {
        wire::QueryRequest::Unit(unit) => load_unit(transaction, joint_entity(unit))?
            .map(unit_to_wire)
            .map(wire::QueryResult::Unit)
            .unwrap_or(wire::QueryResult::Missing),
        wire::QueryRequest::Handoff(handoff) => {
            let Some(stored) = load_handoff(transaction, Identity::from_bytes(handoff.0))? else {
                return Ok(wire::Success::Query(wire::QueryResult::Missing));
            };
            match stored.phase {
                StoredPhase::Reserved => wire::QueryResult::Reserved(
                    receipt_artifact(&stored.intent).map_err(|_| SemanticError::Integrity)?,
                ),
                StoredPhase::Prepared => wire::QueryResult::Prepared(
                    receipt_artifact(stored.prepared.as_ref().ok_or(SemanticError::Integrity)?)
                        .map_err(|_| SemanticError::Integrity)?,
                ),
                StoredPhase::AbortDecided => wire::QueryResult::AbortDecided(
                    receipt_artifact(stored.abort.as_ref().ok_or(SemanticError::Integrity)?)
                        .map_err(|_| SemanticError::Integrity)?,
                ),
                StoredPhase::CommitDecided => wire::QueryResult::CommitDecided(
                    receipt_artifact(stored.commit.as_ref().ok_or(SemanticError::Integrity)?)
                        .map_err(|_| SemanticError::Integrity)?,
                ),
            }
        }
    };
    Ok(wire::Success::Query(result))
}

pub(crate) fn audit_authority_state(
    connection: &Connection,
    issuer_namespace: ReceiptIssuerIdentity,
) -> Result<(), OwnershipServiceError> {
    let mut stored_units = BTreeMap::new();
    let mut units = connection
        .prepare("SELECT continuity_unit, continuity_generation, record FROM ownership_unit")
        .map_err(|_| OwnershipServiceError::Storage)?;
    let unit_rows = units
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
        })
        .map_err(|_| OwnershipServiceError::Storage)?;
    for row in unit_rows {
        let (identity, generation, bytes) = row.map_err(|_| OwnershipServiceError::Storage)?;
        let stored: StoredUnitOwnership = decode_record(&bytes)?;
        if identity.as_slice() != stored.continuity_unit.identity.0
            || generation.as_slice() != stored.continuity_unit.generation.0.to_be_bytes()
            || !stored.active_pair_is_valid()
            || stored_units.insert(stored.continuity_unit, stored).is_some()
        {
            return Err(OwnershipServiceError::Integrity);
        }
    }

    let mut stored_handoffs: BTreeMap<EntityRef, Vec<StoredOwnership>> = BTreeMap::new();
    let mut handoffs = connection
        .prepare(
            "SELECT handoff_id, continuity_unit, continuity_generation, expected_epoch, record
             FROM ownership_handoff",
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    let handoff_rows = handoffs
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .map_err(|_| OwnershipServiceError::Storage)?;
    for row in handoff_rows {
        let (identity, continuity_unit, generation, expected_epoch, bytes) =
            row.map_err(|_| OwnershipServiceError::Storage)?;
        let stored: StoredOwnership = decode_record(&bytes)?;
        if identity.as_slice() != stored.key.handoff.0
            || continuity_unit.as_slice() != stored.key.continuity_unit.identity.0
            || generation.as_slice() != stored.key.continuity_unit.generation.0.to_be_bytes()
            || expected_epoch.as_slice() != stored.key.expected_epoch.0.to_be_bytes()
            || !stored_units.contains_key(&stored.key.continuity_unit)
        {
            return Err(OwnershipServiceError::Integrity);
        }
        validate_stored_handoff(&stored, issuer_namespace)
            .map_err(|_| OwnershipServiceError::Integrity)?;
        stored_handoffs.entry(stored.key.continuity_unit).or_default().push(stored);
    }

    for (continuity_unit, unit) in stored_units {
        let records = stored_handoffs.remove(&continuity_unit).unwrap_or_default();
        audit_unit_history(unit, &records)?;
    }
    if !stored_handoffs.is_empty() {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(())
}

pub(crate) fn audit_replay_projection(
    connection: &Connection,
    issuer_namespace: ReceiptIssuerIdentity,
    authenticator: &PinnedLocalReceiptAuthenticator,
) -> Result<(), OwnershipServiceError> {
    let mut shadow = Connection::open_in_memory().map_err(|_| OwnershipServiceError::Storage)?;
    shadow
        .execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
        .map_err(|_| OwnershipServiceError::Storage)?;
    for table in ["ownership_unit", "ownership_handoff"] {
        let sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| OwnershipServiceError::Integrity)?;
        shadow.execute_batch(&sql).map_err(|_| OwnershipServiceError::Integrity)?;
    }

    let transaction = shadow
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| OwnershipServiceError::Storage)?;
    let mut exchanges = connection
        .prepare(
            "SELECT request_bytes, response_bytes FROM rpc_exchange
             ORDER BY completion_order",
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    let rows = exchanges
        .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))
        .map_err(|_| OwnershipServiceError::Storage)?;
    for row in rows {
        let (request_bytes, response_bytes) = row.map_err(|_| OwnershipServiceError::Storage)?;
        let request =
            wire::decode_request(&request_bytes).map_err(|_| OwnershipServiceError::Integrity)?;
        let response = wire::decode_response_for(&request, &response_bytes)
            .map_err(|_| OwnershipServiceError::Integrity)?;
        let replayed = apply_operation(&transaction, &request, issuer_namespace, authenticator)
            .map_err(|_| OwnershipServiceError::Integrity)?;
        if replayed != response.outcome {
            return Err(OwnershipServiceError::Integrity);
        }
    }

    if collect_unit_rows(connection)? != collect_unit_rows(&transaction)?
        || collect_handoff_rows(connection)? != collect_handoff_rows(&transaction)?
    {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(())
}

type UnitRow = (Vec<u8>, Vec<u8>, Vec<u8>);

fn collect_unit_rows(connection: &Connection) -> Result<Vec<UnitRow>, OwnershipServiceError> {
    let mut statement = connection
        .prepare(
            "SELECT continuity_unit, continuity_generation, record
             FROM ownership_unit ORDER BY continuity_unit, continuity_generation",
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|_| OwnershipServiceError::Storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OwnershipServiceError::Storage)
}

type HandoffRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn collect_handoff_rows(connection: &Connection) -> Result<Vec<HandoffRow>, OwnershipServiceError> {
    let mut statement = connection
        .prepare(
            "SELECT handoff_id, continuity_unit, continuity_generation, expected_epoch, record
             FROM ownership_handoff ORDER BY handoff_id",
        )
        .map_err(|_| OwnershipServiceError::Storage)?;
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
        .map_err(|_| OwnershipServiceError::Storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OwnershipServiceError::Storage)
}

fn audit_unit_history(
    unit: StoredUnitOwnership,
    records: &[StoredOwnership],
) -> Result<(), OwnershipServiceError> {
    let mut commits = records
        .iter()
        .filter(|record| record.phase == StoredPhase::CommitDecided)
        .collect::<Vec<_>>();
    commits.sort_by_key(|record| record.key.expected_epoch);

    let (initial_owner, initial_epoch) = commits
        .first()
        .map_or((unit.owner, unit.epoch), |record| (record.key.source, record.key.expected_epoch));
    let mut authority_timeline = vec![(initial_epoch, initial_owner)];
    let mut previous_owner = initial_owner;
    let mut previous_epoch = initial_epoch;
    for record in commits {
        if record.key.source != previous_owner || record.key.expected_epoch != previous_epoch {
            return Err(OwnershipServiceError::Integrity);
        }
        previous_owner = record.key.destination;
        previous_epoch = record.key.next_epoch;
        authority_timeline.push((previous_epoch, previous_owner));
    }
    if unit.owner != previous_owner || unit.epoch != previous_epoch {
        return Err(OwnershipServiceError::Integrity);
    }

    let mut active = records
        .iter()
        .filter(|record| matches!(record.phase, StoredPhase::Reserved | StoredPhase::Prepared));
    let active_record = active.next();
    if active.next().is_some()
        || active_record.map(|record| (record.key.handoff, record.reservation))
            != unit.active_handoff.zip(unit.active_reservation)
        || active_record.is_some_and(|record| {
            record.key.source != unit.owner || record.key.expected_epoch != unit.epoch
        })
        || records.iter().any(|record| {
            !authority_timeline.contains(&(record.key.expected_epoch, record.key.source))
        })
    {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(())
}

fn validate_stored_handoff(
    stored: &StoredOwnership,
    issuer_namespace: ReceiptIssuerIdentity,
) -> SemanticResult<()> {
    if !stored.key.is_well_formed()
        || stored.reservation.is_zero()
        || stored.state_sequence == 0
        || stored.intent.key != stored.key
        || stored.intent.reservation != stored.reservation
        || stored.intent.header.kind != ReceiptKind::PrepareIntent
        || stored.intent.header.sequence != 1
        || stored.intent.intent_revision != 1
        || stored.intent.header.issuer != issuer_namespace.issuer
        || stored.intent.header.issuer_incarnation != issuer_namespace.issuer_incarnation
        || stored.intent.header.key_id != issuer_namespace.key_id
    {
        return Err(SemanticError::Integrity);
    }
    let expected_issuer = ownership_issuer(issuer_namespace, stored.key)?;
    if stored.intent.header.log_id != expected_issuer.log_id {
        return Err(SemanticError::Integrity);
    }
    match stored.phase {
        StoredPhase::Reserved => {
            if stored.state_sequence != 1
                || stored.seal_request_digest.is_some()
                || stored.prepared.is_some()
                || stored.abort_request_digest.is_some()
                || stored.abort.is_some()
                || stored.commit_request_digest.is_some()
                || stored.commit.is_some()
            {
                return Err(SemanticError::Integrity);
            }
        }
        StoredPhase::Prepared => {
            let prepared = stored.prepared.as_ref().ok_or(SemanticError::Integrity)?;
            let intent_ref = stored.intent.receipt_ref().map_err(|_| SemanticError::Integrity)?;
            if stored.state_sequence != 2
                || stored.seal_request_digest.is_none()
                || prepared.key != stored.key
                || prepared.reservation != stored.reservation
                || prepared.intent != intent_ref
                || prepared.header.kind != ReceiptKind::OwnershipPrepared
                || prepared.header.sequence != 2
                || prepared.header.previous_digest != Some(intent_ref.digest)
                || !header_uses_issuer(&prepared.header, expected_issuer)
                || stored.abort_request_digest.is_some()
                || stored.abort.is_some()
                || stored.commit_request_digest.is_some()
                || stored.commit.is_some()
            {
                return Err(SemanticError::Integrity);
            }
        }
        StoredPhase::AbortDecided => {
            let abort = stored.abort.as_ref().ok_or(SemanticError::Integrity)?;
            let expected_sequence = if stored.prepared.is_some() { 3 } else { 2 };
            if stored.state_sequence != expected_sequence
                || stored.abort_request_digest.is_none()
                || abort.key != stored.key
                || abort.reservation != stored.reservation
                || abort.header.kind != ReceiptKind::OwnershipAbort
                || abort.header.sequence != expected_sequence
                || abort.decision_sequence != expected_sequence
                || !header_uses_issuer(&abort.header, expected_issuer)
                || stored.commit_request_digest.is_some()
                || stored.commit.is_some()
            {
                return Err(SemanticError::Integrity);
            }
        }
        StoredPhase::CommitDecided => {
            let prepared = stored.prepared.as_ref().ok_or(SemanticError::Integrity)?;
            let commit = stored.commit.as_ref().ok_or(SemanticError::Integrity)?;
            let prepared_ref = prepared.receipt_ref().map_err(|_| SemanticError::Integrity)?;
            if stored.state_sequence != 3
                || stored.seal_request_digest.is_none()
                || stored.commit_request_digest.is_none()
                || commit.key != stored.key
                || commit.reservation != stored.reservation
                || commit.prepared != prepared_ref
                || commit.header.kind != ReceiptKind::OwnershipCommit
                || commit.header.sequence != 3
                || commit.decision_sequence != 3
                || commit.header.previous_digest != Some(prepared_ref.digest)
                || !header_uses_issuer(&commit.header, expected_issuer)
                || stored.abort_request_digest.is_some()
                || stored.abort.is_some()
            {
                return Err(SemanticError::Integrity);
            }
        }
    }
    Ok(())
}

fn validate_seal_chain(
    intent: &PrepareIntentReceipt,
    visa: &VisaFreezeReceipt,
    nexus: &NexusFreezeReceipt,
    destination: &DestinationPreparedReceipt,
    prepared: &OwnershipPreparedReceipt,
) -> SemanticResult<()> {
    let mut state =
        JointState::new(intent.key).map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    for (identity, kind) in [
        (1_u128, CommandKind::RecordPrepareIntent(intent.clone())),
        (2, CommandKind::RecordVisaFreeze(visa.clone())),
        (3, CommandKind::RecordNexusFreeze(nexus.clone())),
        (4, CommandKind::RecordDestinationPrepared(Box::new(destination.clone()))),
        (5, CommandKind::SealPreparedFrozen(Box::new(prepared.clone()))),
    ] {
        let command = Command::new(Identity::from_u128(identity), kind);
        let Decision::Commit(event) = preflight_joint(&state, &command) else {
            return Err(rejected(wire::Rejection::InvalidRequest));
        };
        let ApplyResult::Applied(next) = apply_joint_event(&state, &event)
            .map_err(|_| rejected(wire::Rejection::InvalidRequest))?
        else {
            return Err(rejected(wire::Rejection::InvalidRequest));
        };
        state = next;
    }
    Ok(())
}

impl StoredUnitOwnership {
    fn active_pair_is_valid(self) -> bool {
        self.active_handoff.is_some() == self.active_reservation.is_some()
    }
}

fn require_owned_source(unit: &StoredUnitOwnership, key: JointHandoffKey) -> SemanticResult<()> {
    if !unit.active_pair_is_valid() || unit.continuity_unit != key.continuity_unit {
        return Err(SemanticError::Integrity);
    }
    if unit.owner != key.source || unit.epoch != key.expected_epoch {
        return Err(rejected(wire::Rejection::OwnershipMismatch {
            owner: wire_node(unit.owner),
            epoch: unit.epoch.0,
        }));
    }
    Ok(())
}

fn require_active(unit: &StoredUnitOwnership, stored: &StoredOwnership) -> SemanticResult<()> {
    require_owned_source(unit, stored.key)?;
    if unit.active_handoff != Some(stored.key.handoff)
        || unit.active_reservation != Some(stored.reservation)
    {
        return Err(rejected(wire::Rejection::Conflict));
    }
    Ok(())
}

fn clear_active(unit: &mut StoredUnitOwnership, stored: &StoredOwnership) -> SemanticResult<()> {
    if unit.active_handoff != Some(stored.key.handoff)
        || unit.active_reservation != Some(stored.reservation)
    {
        return Err(rejected(wire::Rejection::Conflict));
    }
    unit.active_handoff = None;
    unit.active_reservation = None;
    Ok(())
}

fn validate_record_request(
    stored: &StoredOwnership,
    key: JointHandoffKey,
    reservation: Identity,
) -> SemanticResult<()> {
    if !key.is_well_formed() || stored.key != key || stored.reservation != reservation {
        Err(rejected(wire::Rejection::InvalidRequest))
    } else {
        Ok(())
    }
}

fn require_sequence(actual: u64, expected: u64) -> SemanticResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(rejected(wire::Rejection::StaleSequence { expected, actual }))
    }
}

fn next_sequence(current: u64) -> SemanticResult<u64> {
    current.checked_add(1).ok_or_else(|| rejected(wire::Rejection::InvalidRequest))
}

fn semantic_digest<T: Serialize>(
    operation: &[u8],
    key: JointHandoffKey,
    expected_state_sequence: u64,
    proposal: &T,
) -> SemanticResult<Digest> {
    canonical_digest(&(
        b"vISA/ownership/semantic-request/v1\0".as_slice(),
        operation,
        key,
        expected_state_sequence,
        proposal,
    ))
    .map_err(|_| rejected(wire::Rejection::InvalidRequest))
}

fn ownership_issuer(
    namespace: ReceiptIssuerIdentity,
    key: JointHandoffKey,
) -> SemanticResult<ReceiptIssuerIdentity> {
    if !key.is_well_formed() {
        return Err(rejected(wire::Rejection::InvalidRequest));
    }
    ownership_issuer_for_handoff(namespace, key.handoff)
        .ok_or_else(|| rejected(wire::Rejection::InvalidRequest))
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

fn header_uses_issuer(header: &ReceiptHeader, issuer: ReceiptIssuerIdentity) -> bool {
    header.issuer == issuer.issuer
        && header.issuer_incarnation == issuer.issuer_incarnation
        && header.key_id == issuer.key_id
        && header.log_id == issuer.log_id
}

fn derived_identity<T: Serialize>(domain: &[u8], value: &T) -> SemanticResult<Identity> {
    let digest = canonical_digest(&(domain, value))
        .map_err(|_| rejected(wire::Rejection::InvalidRequest))?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    let identity = Identity::from_bytes(bytes);
    if identity.is_zero() { Err(rejected(wire::Rejection::InvalidRequest)) } else { Ok(identity) }
}

fn decision_root(
    key: JointHandoffKey,
    reservation: Identity,
    decision: &[u8],
    sequence: u64,
) -> SemanticResult<Digest> {
    canonical_digest(&(
        b"vISA/ownership/decision/v1\0".as_slice(),
        key,
        reservation,
        decision,
        sequence,
    ))
    .map_err(|_| rejected(wire::Rejection::InvalidRequest))
}

fn load_handoff(
    connection: &Connection,
    handoff: Identity,
) -> SemanticResult<Option<StoredOwnership>> {
    let stored: Option<StoredOwnership> = load_record(
        connection,
        "SELECT record FROM ownership_handoff WHERE handoff_id = ?1",
        params![handoff.0.as_slice()],
    )?;
    if stored.as_ref().is_some_and(|record| record.key.handoff != handoff) {
        return Err(SemanticError::Integrity);
    }
    Ok(stored)
}

fn load_unit(
    connection: &Connection,
    continuity_unit: EntityRef,
) -> SemanticResult<Option<StoredUnitOwnership>> {
    let generation = continuity_unit.generation.0.to_be_bytes();
    let stored: Option<StoredUnitOwnership> = load_record(
        connection,
        "SELECT record FROM ownership_unit
         WHERE continuity_unit = ?1 AND continuity_generation = ?2",
        params![continuity_unit.identity.0.as_slice(), generation.as_slice()],
    )?;
    if stored.as_ref().is_some_and(|record| record.continuity_unit != continuity_unit) {
        return Err(SemanticError::Integrity);
    }
    Ok(stored)
}

fn load_record<T>(
    connection: &Connection,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> SemanticResult<Option<T>>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    connection
        .query_row(sql, parameters, |row| row.get::<_, Vec<u8>>(0))
        .optional()
        .map_err(|error| semantic_sqlite_error(&error, false))?
        .map(|bytes| decode_record(&bytes).map_err(|_| SemanticError::Integrity))
        .transpose()
}

fn decode_record<T>(bytes: &[u8]) -> Result<T, OwnershipServiceError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = canonical_from_bytes(bytes).map_err(|_| OwnershipServiceError::Integrity)?;
    if canonical_bytes(&value).ok().as_deref() != Some(bytes) {
        return Err(OwnershipServiceError::Integrity);
    }
    Ok(value)
}

fn insert_unit(transaction: &Transaction<'_>, stored: &StoredUnitOwnership) -> SemanticResult<()> {
    let bytes = canonical_bytes(stored).map_err(|_| SemanticError::Integrity)?;
    let generation = stored.continuity_unit.generation.0.to_be_bytes();
    execute_change(
        transaction,
        "INSERT INTO ownership_unit(continuity_unit, continuity_generation, record)
         VALUES (?1, ?2, ?3)",
        params![stored.continuity_unit.identity.0.as_slice(), generation.as_slice(), bytes],
    )
}

fn update_unit(transaction: &Transaction<'_>, stored: &StoredUnitOwnership) -> SemanticResult<()> {
    let bytes = canonical_bytes(stored).map_err(|_| SemanticError::Integrity)?;
    let generation = stored.continuity_unit.generation.0.to_be_bytes();
    let changed = transaction
        .execute(
            "UPDATE ownership_unit SET record = ?3
             WHERE continuity_unit = ?1 AND continuity_generation = ?2",
            params![stored.continuity_unit.identity.0.as_slice(), generation.as_slice(), bytes],
        )
        .map_err(|error| semantic_sqlite_error(&error, false))?;
    if changed == 1 { Ok(()) } else { Err(SemanticError::Integrity) }
}

fn insert_handoff(transaction: &Transaction<'_>, stored: &StoredOwnership) -> SemanticResult<()> {
    let bytes = canonical_bytes(stored).map_err(|_| SemanticError::Integrity)?;
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

fn update_handoff(transaction: &Transaction<'_>, stored: &StoredOwnership) -> SemanticResult<()> {
    let bytes = canonical_bytes(stored).map_err(|_| SemanticError::Integrity)?;
    let changed = transaction
        .execute(
            "UPDATE ownership_handoff SET record = ?2 WHERE handoff_id = ?1",
            params![stored.key.handoff.0.as_slice(), bytes],
        )
        .map_err(|error| semantic_sqlite_error(&error, false))?;
    if changed == 1 { Ok(()) } else { Err(SemanticError::Integrity) }
}

fn execute_change(
    transaction: &Transaction<'_>,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> SemanticResult<()> {
    transaction.execute(sql, parameters).map_err(|error| semantic_sqlite_error(&error, true))?;
    Ok(())
}

fn semantic_sqlite_error(error: &rusqlite::Error, unique_is_conflict: bool) -> SemanticError {
    match classify_sqlite_error(error) {
        SqliteFailureClass::Busy => SemanticError::Busy,
        SqliteFailureClass::Unique if unique_is_conflict => rejected(wire::Rejection::Conflict),
        SqliteFailureClass::Unique | SqliteFailureClass::Integrity => SemanticError::Integrity,
        SqliteFailureClass::Other => SemanticError::Storage,
    }
}

fn joint_entity(value: EntityRefWire) -> EntityRef {
    EntityRef::new(Identity::from_bytes(value.identity.0), Generation(value.generation))
}

fn joint_node(value: NodeId) -> NodeIdentity {
    NodeIdentity::new(Identity::from_bytes(value.0))
}

fn wire_node(value: NodeIdentity) -> NodeId {
    NodeId::from_bytes(value.0.0)
}

fn joint_key(value: JointHandoffKeyWire) -> JointHandoffKey {
    JointHandoffKey {
        continuity_unit: joint_entity(value.continuity_unit),
        handoff: Identity::from_bytes(value.handoff.0),
        source: joint_node(value.source),
        destination: joint_node(value.destination),
        expected_epoch: LeaseEpoch(value.expected_epoch),
        next_epoch: LeaseEpoch(value.next_epoch),
    }
}

fn unit_to_wire(value: StoredUnitOwnership) -> wire::UnitOwnership {
    wire::UnitOwnership {
        continuity_unit: EntityRefWire {
            identity: ContinuityUnitId::from_bytes(value.continuity_unit.identity.0),
            generation: value.continuity_unit.generation.0,
        },
        owner: wire_node(value.owner),
        epoch: value.epoch.0,
        active_handoff: value.active_handoff.map(|id| HandoffId::from_bytes(id.0)),
        active_reservation: value.active_reservation.map(|id| ReservationId::from_bytes(id.0)),
    }
}

type SemanticResult<T> = Result<T, SemanticError>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum SemanticError {
    Rejected(Box<wire::Rejection>),
    Integrity,
    Busy,
    Storage,
}

fn rejected(value: wire::Rejection) -> SemanticError {
    SemanticError::Rejected(Box::new(value))
}
