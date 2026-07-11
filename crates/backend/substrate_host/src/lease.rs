use contract_core::{
    Digest, EffectKind, EffectOutcome, EffectRequest, EffectResult, EntityRef, EvidenceKind,
    EvidenceRef, LeaseEpoch, NodeIdentity, Rights,
};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest as _, Sha256};
use substrate_api::{
    LeasePort, LeaseRecord, LeaseTransition, PreparedLeaseTransitions, ProviderError,
    ProviderErrorKind,
};

use crate::{
    SqliteProvider, authority::authorize_effect_on, database_error, decode_identity, decode_number,
    effect_evidence, ensure_intent, error, generation, next_identity, number, serialize,
};

impl LeasePort for SqliteProvider {
    fn initialize_lease(&mut self, lease: LeaseRecord) -> Result<(), ProviderError> {
        initialize_lease_on(&self.connection, lease)
    }

    fn prepare_transitions(
        &mut self,
        request: &EffectRequest,
        resources: &[EntityRef],
    ) -> Result<PreparedLeaseTransitions, ProviderError> {
        let EffectKind::LeaseCommit { destination, expected_epoch, next_epoch, .. } = request.kind
        else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };
        if request.lease_epoch != expected_epoch || expected_epoch.next() != Some(next_epoch) {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        if request.node != destination {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        if resources.is_empty() {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        let mut unique_resources = std::collections::BTreeSet::new();
        if resources.iter().any(|resource| !unique_resources.insert(*resource)) {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        ensure_intent(&self.connection, request)?;
        authorize_effect_on(&self.connection, request, Rights::HANDOFF)?;
        let mut source_owner = None;
        for resource in resources {
            let lease = load_lease(&self.connection, *resource)?
                .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;
            if lease.epoch != expected_epoch {
                return Err(error(ProviderErrorKind::StaleEpoch, false));
            }
            match source_owner {
                Some(owner) if owner != lease.owner => {
                    return Err(error(ProviderErrorKind::Conflict, false));
                }
                None => source_owner = Some(lease.owner),
                Some(_) => {}
            }
        }
        let source_owner = source_owner.ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;

        let transaction = self.immediate_transaction()?;
        let mut digest = Sha256::new();
        digest.update(b"vISA source fence");
        digest.update(serialize(request)?);
        let source_fence = EvidenceRef {
            identity: next_identity(&transaction)?,
            kind: EvidenceKind::SourceFence,
            digest: Digest::from_bytes(digest.finalize().into()),
        };
        let result =
            EffectResult::LeaseAdvanced { owner: destination, epoch: next_epoch, source_fence };
        let outcome = EffectOutcome::Succeeded {
            evidence: effect_evidence(&transaction, request, &result)?,
            result,
        };
        transaction.commit().map_err(database_error)?;
        Ok(PreparedLeaseTransitions {
            transitions: resources
                .iter()
                .map(|resource| LeaseTransition {
                    resource: *resource,
                    expected_owner: source_owner,
                    next_owner: destination,
                    expected_epoch,
                    next_epoch,
                })
                .collect(),
            outcome,
        })
    }

    fn current_lease(&self, resource: EntityRef) -> Result<Option<LeaseRecord>, ProviderError> {
        let lease = load_lease(&self.connection, resource)?;
        if lease.is_none() && resource_identity_exists(&self.connection, resource)? {
            return Err(error(ProviderErrorKind::StaleGeneration, false));
        }
        Ok(lease)
    }

    fn check_lease(
        &self,
        resource: EntityRef,
        owner: NodeIdentity,
        epoch: LeaseEpoch,
    ) -> Result<(), ProviderError> {
        check_lease_on(&self.connection, resource, owner, epoch)
    }
}

pub(crate) fn initialize_lease_on(
    connection: &rusqlite::Connection,
    lease: LeaseRecord,
) -> Result<(), ProviderError> {
    if let Some(existing) = load_lease(connection, lease.resource)? {
        return if existing == lease {
            Ok(())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    if resource_identity_exists(connection, lease.resource)? {
        return Err(error(ProviderErrorKind::StaleGeneration, false));
    }
    connection
        .execute(
            "INSERT INTO ownership(
                 resource_id, resource_generation, owner_id, epoch
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                lease.resource.identity.0.as_slice(),
                generation(lease.resource.generation),
                lease.owner.0.0.as_slice(),
                number(lease.epoch.0)
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

pub(crate) fn check_lease_on(
    connection: &rusqlite::Connection,
    resource: EntityRef,
    owner: NodeIdentity,
    epoch: LeaseEpoch,
) -> Result<(), ProviderError> {
    let Some(current) = load_lease(connection, resource)? else {
        return if resource_identity_exists(connection, resource)? {
            Err(error(ProviderErrorKind::StaleGeneration, false))
        } else {
            Err(error(ProviderErrorKind::NotFound, false))
        };
    };
    if current.epoch != epoch || current.owner != owner {
        return Err(error(ProviderErrorKind::StaleEpoch, false));
    }
    Ok(())
}

pub(crate) fn apply_transition(
    connection: &rusqlite::Connection,
    transition: LeaseTransition,
) -> Result<(), ProviderError> {
    let expected_next = transition
        .expected_epoch
        .next()
        .ok_or_else(|| error(ProviderErrorKind::InvalidRequest, false))?;
    if expected_next != transition.next_epoch {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    check_lease_on(
        connection,
        transition.resource,
        transition.expected_owner,
        transition.expected_epoch,
    )?;
    let changed = connection
        .execute(
            "UPDATE ownership
             SET owner_id = ?4, epoch = ?5
             WHERE resource_id = ?1 AND resource_generation = ?2
               AND owner_id = ?3 AND epoch = ?6",
            params![
                transition.resource.identity.0.as_slice(),
                generation(transition.resource.generation),
                transition.expected_owner.0.0.as_slice(),
                transition.next_owner.0.0.as_slice(),
                number(transition.next_epoch.0),
                number(transition.expected_epoch.0)
            ],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(error(ProviderErrorKind::StaleEpoch, false));
    }
    Ok(())
}

pub(crate) fn ensure_transition_applied(
    connection: &rusqlite::Connection,
    transition: LeaseTransition,
) -> Result<(), ProviderError> {
    check_lease_on(connection, transition.resource, transition.next_owner, transition.next_epoch)
}

fn load_lease(
    connection: &rusqlite::Connection,
    resource: EntityRef,
) -> Result<Option<LeaseRecord>, ProviderError> {
    connection
        .query_row(
            "SELECT owner_id, epoch
             FROM ownership
             WHERE resource_id = ?1 AND resource_generation = ?2",
            params![resource.identity.0.as_slice(), generation(resource.generation)],
            |row| {
                Ok(LeaseRecord {
                    resource,
                    owner: NodeIdentity::new(decode_identity(row.get(0)?)?),
                    epoch: LeaseEpoch(decode_number(row.get(1)?)?),
                })
            },
        )
        .optional()
        .map_err(database_error)
}

fn resource_identity_exists(
    connection: &rusqlite::Connection,
    resource: EntityRef,
) -> Result<bool, ProviderError> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM ownership
                 WHERE resource_id = ?1 AND resource_generation != ?2
             )",
            params![resource.identity.0.as_slice(), generation(resource.generation)],
            |row| row.get(0),
        )
        .map_err(database_error)
}
