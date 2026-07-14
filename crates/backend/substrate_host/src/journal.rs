use contract_core::{
    CleanupStatus, EffectKind, EffectOutcome, EffectResult, EventKind, Identity, JournalEntry,
    JournalPosition,
};
use rusqlite::{OptionalExtension, params};
use substrate_api::{
    ActivationBundle, CommitBundle, JournalPort, JournalScope, OperationObservation, ProviderError,
    ProviderErrorKind,
};

use crate::{
    FaultPoint, SqliteProvider, database_error, deserialize, error, load_canonical_entry,
    load_operation_by_idempotency, load_operation_by_identity, number, serialize, write_outcome,
};

impl JournalPort for SqliteProvider {
    fn append_entry(&mut self, entry: &JournalEntry) -> Result<(), ProviderError> {
        if matches!(entry.event.kind, EventKind::Activated { .. }) {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        if self.take_fault(FaultPoint::BeforeJournalWrite) {
            return Err(error(ProviderErrorKind::Unavailable, true));
        }
        let scope = self.scope;
        let transaction = self.immediate_transaction()?;
        append_entry_on(&transaction, scope, entry)?;
        transaction.commit().map_err(database_error)?;
        if self.take_fault(FaultPoint::AfterJournalWrite) {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        Ok(())
    }

    fn commit_activation(&mut self, bundle: &ActivationBundle) -> Result<(), ProviderError> {
        validate_activation_bundle(self.scope, bundle)?;
        if self.take_fault(FaultPoint::BeforeActivationBundle) {
            return Err(error(ProviderErrorKind::Unavailable, true));
        }
        let scope = self.scope;
        let transaction = self.immediate_transaction()?;
        for lease in &bundle.initial_leases {
            crate::lease::initialize_lease_on(&transaction, *lease)?;
        }
        append_entry_on(&transaction, scope, &bundle.entry)?;
        transaction.commit().map_err(database_error)?;
        if self.take_fault(FaultPoint::AfterActivationBundle) {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        Ok(())
    }

    fn commit_bundle(&mut self, bundle: &CommitBundle) -> Result<(), ProviderError> {
        if self.take_fault(FaultPoint::BeforeCommitBundle) {
            return Err(error(ProviderErrorKind::Unavailable, true));
        }

        let scope = self.scope;
        let transaction = self.immediate_transaction()?;
        if let Some(commit) = handoff_commit(&bundle.entry)? {
            let observation = load_operation_by_identity(&transaction, commit.operation)?
                .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;
            validate_handoff_request(
                &observation.record.request,
                &commit,
                &bundle.lease_transitions,
                &bundle.final_authorities,
            )?;
            if !bundle.lease_transitions.is_empty() {
                crate::authority::authorize_effect_on(
                    &transaction,
                    &observation.record.request,
                    contract_core::Rights::HANDOFF,
                )?;
                match &observation.record.outcome {
                    Some(current) if current == commit.outcome => {
                        for transition in &bundle.lease_transitions {
                            crate::lease::ensure_transition_applied(&transaction, *transition)?;
                        }
                    }
                    Some(_) => return Err(error(ProviderErrorKind::Conflict, false)),
                    None => {
                        for transition in &bundle.lease_transitions {
                            crate::lease::apply_transition(&transaction, *transition)?;
                        }
                        crate::authority::activate_prepared_authorities(
                            &transaction,
                            commit.handoff,
                            commit.snapshot,
                            &bundle.final_authorities,
                        )?;
                    }
                }
            }
            write_outcome(&transaction, commit.operation, commit.outcome)?;
        } else if !bundle.lease_transitions.is_empty() || !bundle.final_authorities.is_empty() {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        append_entry_on(&transaction, scope, &bundle.entry)?;
        transaction.commit().map_err(database_error)?;

        if self.take_fault(FaultPoint::AfterCommitBundle) {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        Ok(())
    }

    fn entry(&self, position: JournalPosition) -> Result<Option<JournalEntry>, ProviderError> {
        load_canonical_entry(&self.connection, self.scope, position)
    }

    fn operation(
        &self,
        operation: Identity,
    ) -> Result<Option<OperationObservation>, ProviderError> {
        load_operation_by_identity(&self.connection, operation)
    }

    fn idempotency(
        &self,
        key: contract_core::IdempotencyKey,
    ) -> Result<Option<OperationObservation>, ProviderError> {
        load_operation_by_idempotency(&self.connection, key)
    }

    fn replay_from(
        &self,
        after: Option<JournalPosition>,
    ) -> Result<Vec<JournalEntry>, ProviderError> {
        let lower_bound = after.map_or(number(0), |position| number(position.0));
        let mut statement = self
            .connection
            .prepare(
                "SELECT entry FROM canonical_journal
                 WHERE node_id = ?1 AND component_id = ?2 AND position > ?3
                 ORDER BY position ASC",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map(
                params![
                    self.scope.node.0.0.as_slice(),
                    self.scope.component.0.as_slice(),
                    lower_bound
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(database_error)?;
        rows.map(|row| {
            let bytes = row.map_err(database_error)?;
            deserialize(&bytes)
        })
        .collect()
    }
}

fn validate_activation_bundle(
    scope: JournalScope,
    bundle: &ActivationBundle,
) -> Result<(), ProviderError> {
    let EventKind::Activated { lease_epoch } = bundle.entry.event.kind else {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    };
    if bundle.initial_leases.is_empty() {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    let mut resources = std::collections::BTreeSet::new();
    if bundle.initial_leases.iter().any(|lease| {
        !resources.insert(lease.resource) || lease.owner != scope.node || lease.epoch != lease_epoch
    }) {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    Ok(())
}

fn append_entry_on(
    connection: &rusqlite::Connection,
    scope: JournalScope,
    entry: &JournalEntry,
) -> Result<(), ProviderError> {
    if let Some(existing) = load_canonical_entry(connection, scope, entry.position)? {
        return if existing == *entry {
            Ok(())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }

    let previous = connection
        .query_row(
            "SELECT entry FROM canonical_journal
             WHERE node_id = ?1 AND component_id = ?2
             ORDER BY position DESC LIMIT 1",
            params![scope.node.0.0.as_slice(), scope.component.0.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(database_error)?
        .map(|bytes| deserialize::<JournalEntry>(&bytes))
        .transpose()?;
    if let Some(previous) = &previous {
        let expected_position =
            previous.position.next().ok_or_else(|| error(ProviderErrorKind::Storage, false))?;
        if entry.position != expected_position {
            return Err(error(ProviderErrorKind::Conflict, false));
        }
    } else if entry.position == JournalPosition::ORIGIN {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    if let Some(previous) = previous
        && previous.output_state != entry.input_state
    {
        return Err(error(ProviderErrorKind::Integrity, false));
    }

    apply_event_projection(connection, &entry.event.kind)?;
    connection
        .execute(
            "INSERT INTO canonical_journal(
                 node_id, component_id, position, event_id, entry
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                scope.node.0.0.as_slice(),
                scope.component.0.as_slice(),
                number(entry.position.0),
                entry.event.identity.0.as_slice(),
                serialize(entry)?
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

fn apply_event_projection(
    connection: &rusqlite::Connection,
    event: &EventKind,
) -> Result<(), ProviderError> {
    match event {
        EventKind::AuthorityAttenuated { grant } => {
            crate::authority::apply_attenuation_event(connection, grant)
        }
        EventKind::AuthorityRevoked { authority, revoked_generation } => {
            crate::authority::apply_revocation_event(connection, *authority, *revoked_generation)
        }
        EventKind::EffectPrepared { request } => {
            if let Some(existing) = load_operation_by_identity(connection, request.operation)? {
                return if existing.record.request == *request {
                    Ok(())
                } else {
                    Err(error(ProviderErrorKind::Conflict, false))
                };
            }
            if load_operation_by_idempotency(connection, request.idempotency_key)?.is_some() {
                return Err(error(ProviderErrorKind::Conflict, false));
            }
            connection
                .execute(
                    "INSERT INTO provider_operation(operation, idempotency_key, request)
                     VALUES (?1, ?2, ?3)",
                    params![
                        request.operation.0.as_slice(),
                        request.idempotency_key.0.as_slice(),
                        serialize(request)?
                    ],
                )
                .map_err(database_error)?;
            Ok(())
        }
        EventKind::EffectResolved { operation, outcome } => {
            write_outcome(connection, *operation, outcome)?;
            Ok(())
        }
        EventKind::EffectReconciled { operation, outcome } => {
            crate::write_reconciled_outcome(connection, *operation, outcome)?;
            Ok(())
        }
        EventKind::OperationCleaned { operation, .. } => {
            let observation = load_operation_by_identity(connection, *operation)?
                .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;
            if observation.record.cleanup == CleanupStatus::Pending {
                connection
                    .execute(
                        "UPDATE provider_operation SET cleaned = 1 WHERE operation = ?1",
                        params![operation.0.as_slice()],
                    )
                    .map_err(database_error)?;
            }
            Ok(())
        }
        EventKind::HandoffCommitted { operation, outcome, .. } => {
            write_outcome(connection, *operation, outcome)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

struct HandoffCommit<'a> {
    operation: Identity,
    handoff: Identity,
    snapshot: Identity,
    source: contract_core::NodeIdentity,
    destination: contract_core::NodeIdentity,
    previous_epoch: contract_core::LeaseEpoch,
    new_epoch: contract_core::LeaseEpoch,
    outcome: &'a EffectOutcome,
}

fn handoff_commit(entry: &JournalEntry) -> Result<Option<HandoffCommit<'_>>, ProviderError> {
    let EventKind::HandoffCommitted {
        operation,
        handoff,
        snapshot,
        source,
        destination,
        previous_epoch,
        new_epoch,
        outcome,
    } = &entry.event.kind
    else {
        return Ok(None);
    };
    Ok(Some(HandoffCommit {
        operation: *operation,
        handoff: *handoff,
        snapshot: *snapshot,
        source: *source,
        destination: *destination,
        previous_epoch: *previous_epoch,
        new_epoch: *new_epoch,
        outcome,
    }))
}

fn validate_handoff_request(
    request: &contract_core::EffectRequest,
    commit: &HandoffCommit<'_>,
    transitions: &[substrate_api::LeaseTransition],
    final_authorities: &[contract_core::EntityRef],
) -> Result<(), ProviderError> {
    let EffectKind::LeaseCommit { handoff, snapshot, destination, expected_epoch, next_epoch } =
        &request.kind
    else {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    };
    if request.operation != commit.operation
        || *handoff != commit.handoff
        || *snapshot != commit.snapshot
        || request.node != commit.destination
        || *destination != commit.destination
        || *expected_epoch != commit.previous_epoch
        || *next_epoch != commit.new_epoch
    {
        return Err(error(ProviderErrorKind::Conflict, false));
    }

    match commit.outcome {
        EffectOutcome::Succeeded {
            result: EffectResult::LeaseAdvanced { owner, epoch, .. },
            ..
        } if *owner == commit.destination && *epoch == commit.new_epoch => {
            if transitions.is_empty() || final_authorities.is_empty() {
                return Err(error(ProviderErrorKind::InvalidRequest, false));
            }
            let mut resources = std::collections::BTreeSet::new();
            if transitions.iter().any(|transition| {
                !resources.insert(transition.resource)
                    || transition.expected_owner != commit.source
                    || transition.next_owner != commit.destination
                    || transition.expected_epoch != commit.previous_epoch
                    || transition.next_epoch != commit.new_epoch
            }) {
                return Err(error(ProviderErrorKind::InvalidRequest, false));
            }
            Ok(())
        }
        EffectOutcome::Succeeded { .. } => Err(error(ProviderErrorKind::InvalidRequest, false)),
        _ if transitions.is_empty() && final_authorities.is_empty() => Ok(()),
        _ => Err(error(ProviderErrorKind::InvalidRequest, false)),
    }
}
