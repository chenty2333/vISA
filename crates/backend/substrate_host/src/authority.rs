use contract_core::{
    AuthorityGrant, AuthorityStatus, EffectKind, EffectRequest, EntityRef, Generation, Rights,
};
use rusqlite::{OptionalExtension, params};
use substrate_api::{
    AuthorityPolicy, AuthorityPort, ProviderError, ProviderErrorKind, ReauthorizationRequest,
};

use crate::{SqliteProvider, database_error, decode_identity, decode_number, error, generation};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreparationScope {
    handoff: contract_core::Identity,
    snapshot: contract_core::Identity,
}

impl PreparationScope {
    fn new(
        handoff: contract_core::Identity,
        snapshot: contract_core::Identity,
    ) -> Result<Self, ProviderError> {
        if handoff.is_zero() || snapshot.is_zero() {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        Ok(Self { handoff, snapshot })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredGrant {
    grant: AuthorityGrant,
    pending: bool,
    usable: bool,
    preparation: Option<PreparationScope>,
}

impl AuthorityPort for SqliteProvider {
    fn install_policy(&mut self, policy: AuthorityPolicy) -> Result<(), ProviderError> {
        if let Some(existing) = load_policy(&self.connection, policy.subject, policy.resource)? {
            return if existing == policy.allowed_rights {
                Ok(())
            } else {
                Err(error(ProviderErrorKind::Conflict, false))
            };
        }
        self.connection
            .execute(
                "INSERT INTO authority_policy(
                     subject_id, subject_generation, resource_id,
                     resource_generation, allowed_rights
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    policy.subject.identity.0.as_slice(),
                    generation(policy.subject.generation),
                    policy.resource.identity.0.as_slice(),
                    generation(policy.resource.generation),
                    i64::from(policy.allowed_rights.bits())
                ],
            )
            .map_err(database_error)?;
        Ok(())
    }

    fn install_grant(&mut self, grant: &AuthorityGrant) -> Result<(), ProviderError> {
        let transaction = self.immediate_transaction()?;
        install_grant_on(&transaction, grant, None)?;
        transaction.commit().map_err(database_error)
    }

    fn attenuate(
        &mut self,
        handoff: contract_core::Identity,
        snapshot: contract_core::Identity,
        parent: EntityRef,
        derived: &AuthorityGrant,
    ) -> Result<AuthorityGrant, ProviderError> {
        if derived.parent != Some(parent) {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        }
        let preparation = PreparationScope::new(handoff, snapshot)?;
        let transaction = self.immediate_transaction()?;
        let parent_state = require_usable_or_pending_chain(&transaction, parent)?;
        if parent_state.preparation.is_some() && parent_state.preparation != Some(preparation) {
            return Err(error(ProviderErrorKind::Denied, false));
        }
        let parent_grant = &parent_state.grant;
        if !grant_edge_allowed(parent_grant, derived) || derived.status != AuthorityStatus::Active {
            return Err(error(ProviderErrorKind::Denied, false));
        }
        install_grant_on(&transaction, derived, Some(preparation))?;
        transaction.commit().map_err(database_error)?;
        Ok(derived.clone())
    }

    fn revoke(&mut self, authority: EntityRef) -> Result<(), ProviderError> {
        let Some(grant) = load_grant(&self.connection, authority)? else {
            return Err(classify_missing_authority(&self.connection, authority)?);
        };
        if grant.status == AuthorityStatus::Revoked {
            return Ok(());
        }
        self.connection
            .execute(
                "UPDATE authority_grant
                 SET status = 1, pending = 0, usable = 0,
                     handoff_id = NULL, snapshot_id = NULL
                 WHERE authority_id = ?1 AND authority_generation = ?2",
                params![authority.identity.0.as_slice(), generation(authority.generation)],
            )
            .map_err(database_error)?;
        Ok(())
    }

    fn reauthorize(
        &mut self,
        request: ReauthorizationRequest,
    ) -> Result<AuthorityGrant, ProviderError> {
        let transaction = self.immediate_transaction()?;
        let preparation = PreparationScope::new(request.handoff, request.snapshot)?;
        let source = require_active_chain(&transaction, request.source_authority)?;
        if !request.required_rights.is_subset_of(source.rights) {
            return Err(error(ProviderErrorKind::Denied, false));
        }
        let allowed = load_policy(&transaction, request.destination_subject, request.resource)?
            .ok_or_else(|| error(ProviderErrorKind::Denied, false))?;
        if !request.required_rights.is_subset_of(allowed) {
            return Err(error(ProviderErrorKind::Denied, false));
        }

        let grant = AuthorityGrant {
            authority: request.destination_authority,
            parent: Some(request.source_authority),
            subject: request.destination_subject,
            resource: request.resource,
            // Expose exactly what the destination needs, even when source and
            // host policy both offer broader authority.
            rights: request.required_rights,
            status: AuthorityStatus::Active,
        };
        if !grant_edge_allowed(&source, &grant) {
            return Err(error(ProviderErrorKind::Denied, false));
        }
        install_grant_on(&transaction, &grant, Some(preparation))?;
        transaction.commit().map_err(database_error)?;
        Ok(grant)
    }

    fn authorize_effect(
        &self,
        request: &EffectRequest,
        required_rights: Rights,
    ) -> Result<Rights, ProviderError> {
        authorize_effect_on(&self.connection, request, required_rights)
    }

    fn revoke_prepared(&mut self, snapshot: contract_core::Identity) -> Result<(), ProviderError> {
        self.connection
            .execute(
                "UPDATE authority_grant
                 SET status = 1, pending = 0, usable = 0,
                     handoff_id = NULL, snapshot_id = NULL
                 WHERE snapshot_id = ?1 AND pending = 1",
                params![snapshot.0.as_slice()],
            )
            .map_err(database_error)?;
        Ok(())
    }
}

pub(crate) fn authorize_effect_on(
    connection: &rusqlite::Connection,
    request: &EffectRequest,
    required_rights: Rights,
) -> Result<Rights, ProviderError> {
    let stored = load_grant_state(connection, request.authority)?.ok_or_else(|| {
        classify_missing_authority(connection, request.authority).unwrap_or_else(|error| error)
    })?;
    if stored.grant.status == AuthorityStatus::Revoked {
        return Err(error(ProviderErrorKind::Revoked, false));
    }
    let grant = if stored.pending {
        let EffectKind::LeaseCommit { handoff, snapshot, .. } = &request.kind else {
            return Err(error(ProviderErrorKind::Denied, false));
        };
        let expected = PreparationScope::new(*handoff, *snapshot)?;
        if required_rights != Rights::HANDOFF
            || stored.grant.rights != Rights::HANDOFF
            || stored.preparation != Some(expected)
        {
            return Err(error(ProviderErrorKind::Denied, false));
        }
        validate_ancestor_chain(connection, &stored.grant, Some(expected))?;
        stored.grant
    } else {
        require_active_chain(connection, request.authority)?
    };
    if grant.subject != request.subject || grant.resource != request.resource {
        return Err(error(ProviderErrorKind::Denied, false));
    }
    if !required_rights.is_subset_of(grant.rights) {
        return Err(error(ProviderErrorKind::Denied, false));
    }
    Ok(grant.rights.intersection(required_rights))
}

pub(crate) fn require_active_chain(
    connection: &rusqlite::Connection,
    authority: EntityRef,
) -> Result<AuthorityGrant, ProviderError> {
    let stored = load_grant_state(connection, authority)?.ok_or_else(|| {
        classify_missing_authority(connection, authority).unwrap_or_else(|error| error)
    })?;
    if stored.grant.status == AuthorityStatus::Revoked {
        return Err(error(ProviderErrorKind::Revoked, false));
    }
    if stored.pending || !stored.usable {
        return Err(error(ProviderErrorKind::Denied, false));
    }
    validate_ancestor_chain(connection, &stored.grant, None)?;
    Ok(stored.grant)
}

pub(crate) fn require_prepared_chain(
    connection: &rusqlite::Connection,
    authority: EntityRef,
    handoff: contract_core::Identity,
    snapshot: contract_core::Identity,
) -> Result<AuthorityGrant, ProviderError> {
    let expected = PreparationScope::new(handoff, snapshot)?;
    let stored = load_grant_state(connection, authority)?.ok_or_else(|| {
        classify_missing_authority(connection, authority).unwrap_or_else(|error| error)
    })?;
    if stored.grant.status == AuthorityStatus::Revoked {
        return Err(error(ProviderErrorKind::Revoked, false));
    }
    if !stored.pending || stored.preparation != Some(expected) {
        return Err(error(ProviderErrorKind::Denied, false));
    }
    validate_ancestor_chain(connection, &stored.grant, Some(expected))?;
    Ok(stored.grant)
}

fn require_usable_or_pending_chain(
    connection: &rusqlite::Connection,
    authority: EntityRef,
) -> Result<StoredGrant, ProviderError> {
    let stored = load_grant_state(connection, authority)?.ok_or_else(|| {
        classify_missing_authority(connection, authority).unwrap_or_else(|error| error)
    })?;
    if stored.grant.status == AuthorityStatus::Revoked {
        return Err(error(ProviderErrorKind::Revoked, false));
    }
    if stored.pending {
        validate_ancestor_chain(connection, &stored.grant, stored.preparation)?;
    } else {
        if !stored.usable {
            return Err(error(ProviderErrorKind::Denied, false));
        }
        validate_ancestor_chain(connection, &stored.grant, None)?;
    }
    Ok(stored)
}

fn validate_ancestor_chain(
    connection: &rusqlite::Connection,
    grant: &AuthorityGrant,
    pending_scope: Option<PreparationScope>,
) -> Result<(), ProviderError> {
    let mut child = grant.clone();
    let mut parent = child.parent;
    let mut depth = 0_usize;
    while let Some(authority) = parent {
        depth += 1;
        if depth > 64 {
            return Err(error(ProviderErrorKind::Integrity, false));
        }
        let ancestor = load_grant_state(connection, authority)?.ok_or_else(|| {
            classify_missing_authority(connection, authority).unwrap_or_else(|error| error)
        })?;
        if ancestor.grant.status == AuthorityStatus::Revoked {
            return Err(error(ProviderErrorKind::Revoked, false));
        }
        if ancestor.pending && ancestor.preparation != pending_scope {
            return Err(error(ProviderErrorKind::Integrity, false));
        }
        if !ancestor.pending && !ancestor.usable && pending_scope.is_some() {
            // A committed provenance-only ancestor remains valid, but a
            // pending chain may not attach to an unrelated unusable grant.
            return Err(error(ProviderErrorKind::Denied, false));
        }
        if !grant_edge_allowed(&ancestor.grant, &child) {
            return Err(error(ProviderErrorKind::Integrity, false));
        }
        child = ancestor.grant.clone();
        parent = ancestor.grant.parent;
    }
    Ok(())
}

fn install_grant_on(
    connection: &rusqlite::Connection,
    grant: &AuthorityGrant,
    preparation: Option<PreparationScope>,
) -> Result<(), ProviderError> {
    if let Some(existing) = load_grant_state(connection, grant.authority)? {
        return if existing.grant == *grant && existing.preparation == preparation {
            Ok(())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }
    if has_other_generation(connection, grant.authority)? {
        return Err(error(ProviderErrorKind::StaleGeneration, false));
    }
    let allowed = load_policy(connection, grant.subject, grant.resource)?
        .ok_or_else(|| error(ProviderErrorKind::Denied, false))?;
    if !grant.rights.is_subset_of(allowed) {
        return Err(error(ProviderErrorKind::Denied, false));
    }
    if let Some(parent) = grant.parent {
        let parent = require_usable_or_pending_chain(connection, parent)?;
        let scope_allowed = parent.preparation == preparation
            || (preparation.is_some() && parent.preparation.is_none() && parent.usable);
        if !scope_allowed || !grant_edge_allowed(&parent.grant, grant) {
            return Err(error(ProviderErrorKind::Denied, false));
        }
    }

    let (parent_id, parent_generation) = grant.parent.map_or((None, None), |parent| {
        (Some(parent.identity.0.to_vec()), Some(generation(parent.generation).to_vec()))
    });
    let (handoff_id, snapshot_id) = preparation.map_or((None, None), |scope| {
        (Some(scope.handoff.0.to_vec()), Some(scope.snapshot.0.to_vec()))
    });
    connection
        .execute(
            "INSERT INTO authority_grant(
                 authority_id, authority_generation, parent_id, parent_generation,
                 subject_id, subject_generation, resource_id, resource_generation,
                 rights, status, pending, usable, handoff_id, snapshot_id
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
             )",
            params![
                grant.authority.identity.0.as_slice(),
                generation(grant.authority.generation),
                parent_id,
                parent_generation,
                grant.subject.identity.0.as_slice(),
                generation(grant.subject.generation),
                grant.resource.identity.0.as_slice(),
                generation(grant.resource.generation),
                i64::from(grant.rights.bits()),
                i64::from(grant.status == AuthorityStatus::Revoked),
                i64::from(preparation.is_some()),
                i64::from(preparation.is_none() && grant.status == AuthorityStatus::Active),
                handoff_id,
                snapshot_id
            ],
        )
        .map_err(database_error)?;
    Ok(())
}

pub(crate) fn apply_attenuation_event(
    connection: &rusqlite::Connection,
    grant: &AuthorityGrant,
) -> Result<(), ProviderError> {
    if grant.authority.identity.is_zero()
        || grant.rights.is_empty()
        || grant.parent.is_none()
        || grant.status != AuthorityStatus::Active
    {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    install_grant_on(connection, grant, None)
}

pub(crate) fn apply_revocation_event(
    connection: &rusqlite::Connection,
    authority: EntityRef,
    revoked_generation: Generation,
) -> Result<(), ProviderError> {
    if authority.identity.is_zero() || authority.generation.next() != Some(revoked_generation) {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }

    let revoked = EntityRef::new(authority.identity, revoked_generation);
    if let Some(existing) = load_grant_state(connection, revoked)? {
        return if existing.grant.status == AuthorityStatus::Revoked {
            Ok(())
        } else {
            Err(error(ProviderErrorKind::Conflict, false))
        };
    }

    load_grant_state(connection, authority)?.ok_or_else(|| {
        classify_missing_authority(connection, authority).unwrap_or_else(|error| error)
    })?;
    let updated = connection
        .execute(
            "UPDATE authority_grant
             SET authority_generation = ?3, status = 1, pending = 0, usable = 0,
                 handoff_id = NULL, snapshot_id = NULL
             WHERE authority_id = ?1 AND authority_generation = ?2",
            params![
                authority.identity.0.as_slice(),
                generation(authority.generation),
                generation(revoked_generation)
            ],
        )
        .map_err(database_error)?;
    if updated != 1 {
        return Err(error(ProviderErrorKind::Conflict, false));
    }
    Ok(())
}

fn grant_edge_allowed(parent: &AuthorityGrant, child: &AuthorityGrant) -> bool {
    if !child.rights.is_subset_of(parent.rights) {
        return false;
    }
    if child.resource == parent.resource {
        return true;
    }

    child.rights == Rights::HANDOFF
        && parent.rights.contains(Rights::HANDOFF)
        && child.resource.identity == parent.resource.identity
        && parent.resource.generation.next() == Some(child.resource.generation)
        && child.subject.identity == parent.subject.identity
        && parent.subject.generation.next() == Some(child.subject.generation)
}

pub(crate) fn activate_prepared_authorities(
    connection: &rusqlite::Connection,
    handoff: contract_core::Identity,
    snapshot: contract_core::Identity,
    final_authorities: &[EntityRef],
) -> Result<(), ProviderError> {
    let preparation = PreparationScope::new(handoff, snapshot)?;
    if final_authorities.is_empty() {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    let finals = final_authorities.iter().copied().collect::<std::collections::BTreeSet<_>>();
    if finals.len() != final_authorities.len() {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }

    let mut retained = finals.clone();
    for authority in &finals {
        let stored = load_grant_state(connection, *authority)?
            .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;
        if stored.grant.status == AuthorityStatus::Revoked
            || !stored.pending
            || stored.preparation != Some(preparation)
        {
            return Err(error(ProviderErrorKind::Denied, false));
        }
        validate_ancestor_chain(connection, &stored.grant, Some(preparation))?;

        let mut parent = stored.grant.parent;
        while let Some(authority) = parent {
            let ancestor = load_grant_state(connection, authority)?.ok_or_else(|| {
                classify_missing_authority(connection, authority).unwrap_or_else(|error| error)
            })?;
            if !ancestor.pending {
                break;
            }
            if ancestor.preparation != Some(preparation) {
                return Err(error(ProviderErrorKind::Integrity, false));
            }
            retained.insert(authority);
            parent = ancestor.grant.parent;
        }
    }

    connection
        .execute(
            "UPDATE authority_grant
             SET status = 1, pending = 0, usable = 0,
                 handoff_id = NULL, snapshot_id = NULL
             WHERE handoff_id = ?1 AND snapshot_id = ?2 AND pending = 1",
            params![handoff.0.as_slice(), snapshot.0.as_slice()],
        )
        .map_err(database_error)?;
    for authority in retained {
        connection
            .execute(
                "UPDATE authority_grant
                 SET status = 0, pending = 0, usable = ?3,
                     handoff_id = NULL, snapshot_id = NULL
                 WHERE authority_id = ?1 AND authority_generation = ?2",
                params![
                    authority.identity.0.as_slice(),
                    generation(authority.generation),
                    i64::from(finals.contains(&authority))
                ],
            )
            .map_err(database_error)?;
    }
    Ok(())
}

fn load_policy(
    connection: &rusqlite::Connection,
    subject: EntityRef,
    resource: EntityRef,
) -> Result<Option<Rights>, ProviderError> {
    let bits = connection
        .query_row(
            "SELECT allowed_rights FROM authority_policy
             WHERE subject_id = ?1 AND subject_generation = ?2
               AND resource_id = ?3 AND resource_generation = ?4",
            params![
                subject.identity.0.as_slice(),
                generation(subject.generation),
                resource.identity.0.as_slice(),
                generation(resource.generation)
            ],
            |row| row.get::<_, u16>(0),
        )
        .optional()
        .map_err(database_error)?;
    bits.map(|bits| {
        Rights::from_bits(bits).ok_or_else(|| error(ProviderErrorKind::Integrity, false))
    })
    .transpose()
}

fn load_grant(
    connection: &rusqlite::Connection,
    authority: EntityRef,
) -> Result<Option<AuthorityGrant>, ProviderError> {
    Ok(load_grant_state(connection, authority)?.map(|stored| stored.grant))
}

fn load_grant_state(
    connection: &rusqlite::Connection,
    authority: EntityRef,
) -> Result<Option<StoredGrant>, ProviderError> {
    connection
        .query_row(
            "SELECT parent_id, parent_generation, subject_id, subject_generation,
                    resource_id, resource_generation, rights, status,
                    pending, usable, handoff_id, snapshot_id
             FROM authority_grant
             WHERE authority_id = ?1 AND authority_generation = ?2",
            params![authority.identity.0.as_slice(), generation(authority.generation)],
            |row| {
                let parent_id: Option<Vec<u8>> = row.get(0)?;
                let parent_generation: Option<Vec<u8>> = row.get(1)?;
                let parent = match (parent_id, parent_generation) {
                    (Some(identity), Some(generation)) => Some(EntityRef::new(
                        decode_identity(identity)?,
                        Generation(decode_number(generation)?),
                    )),
                    (None, None) => None,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                let rights: u16 = row.get(6)?;
                let status: bool = row.get(7)?;
                let pending: bool = row.get(8)?;
                let usable: bool = row.get(9)?;
                let handoff: Option<Vec<u8>> = row.get(10)?;
                let snapshot: Option<Vec<u8>> = row.get(11)?;
                let preparation = match (handoff, snapshot) {
                    (Some(handoff), Some(snapshot)) => Some(PreparationScope {
                        handoff: decode_identity(handoff)?,
                        snapshot: decode_identity(snapshot)?,
                    }),
                    (None, None) => None,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                if pending != preparation.is_some() || (pending && usable) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(StoredGrant {
                    grant: AuthorityGrant {
                        authority,
                        parent,
                        subject: EntityRef::new(
                            decode_identity(row.get(2)?)?,
                            Generation(decode_number(row.get(3)?)?),
                        ),
                        resource: EntityRef::new(
                            decode_identity(row.get(4)?)?,
                            Generation(decode_number(row.get(5)?)?),
                        ),
                        rights: Rights::from_bits(rights).ok_or(rusqlite::Error::InvalidQuery)?,
                        status: if status {
                            AuthorityStatus::Revoked
                        } else {
                            AuthorityStatus::Active
                        },
                    },
                    pending,
                    usable,
                    preparation,
                })
            },
        )
        .optional()
        .map_err(database_error)
}

fn has_other_generation(
    connection: &rusqlite::Connection,
    authority: EntityRef,
) -> Result<bool, ProviderError> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM authority_grant
                 WHERE authority_id = ?1
                   AND authority_generation != ?2
             )",
            params![authority.identity.0.as_slice(), generation(authority.generation)],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn classify_missing_authority(
    connection: &rusqlite::Connection,
    authority: EntityRef,
) -> Result<ProviderError, ProviderError> {
    let status = connection
        .query_row(
            "SELECT status FROM authority_grant
             WHERE authority_id = ?1
             ORDER BY authority_generation DESC LIMIT 1",
            params![authority.identity.0.as_slice()],
            |row| row.get::<_, bool>(0),
        )
        .optional()
        .map_err(database_error)?;
    Ok(error(
        match status {
            Some(true) => ProviderErrorKind::Revoked,
            Some(false) => ProviderErrorKind::StaleGeneration,
            None => ProviderErrorKind::NotFound,
        },
        false,
    ))
}
