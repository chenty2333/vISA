use contract_core::{
    AuthorityGrant, AuthorityStatus, CanonicalState, Decision, EntityRef, EventKind, Identity,
    PreparedDestination, Rejection, Replay, Rights,
};

use super::commit;

pub(super) fn preflight_attenuation(
    state: &CanonicalState,
    event_id: Identity,
    parent: EntityRef,
    derived: &AuthorityGrant,
) -> Decision {
    if derived.authority.identity.is_zero() || derived.rights.is_empty() {
        return Decision::Reject(Rejection::InvalidIdentity);
    }
    if let Some(existing) = grant_by_identity(state, derived.authority.identity) {
        return if existing == derived {
            Decision::Replay(Replay::NoChange)
        } else {
            Decision::Reject(Rejection::InvalidIdentity)
        };
    }
    if derived.parent != Some(parent) || derived.status != AuthorityStatus::Active {
        return Decision::Reject(Rejection::AuthoritySubjectMismatch);
    }
    let parent_grant = match exact_grant(state, parent) {
        Ok(grant) => grant,
        Err(rejection) => return Decision::Reject(rejection),
    };
    let available = match effective_rights(state, parent) {
        Ok(rights) => rights,
        Err(rejection) => return Decision::Reject(rejection),
    };
    if derived.subject.identity != parent_grant.subject.identity {
        return Decision::Reject(Rejection::AuthoritySubjectMismatch);
    }
    if derived.resource.identity != parent_grant.resource.identity {
        return Decision::Reject(Rejection::AuthorityResourceMismatch);
    }
    if !derived.rights.is_subset_of(available) {
        return Decision::Reject(Rejection::AuthorityAmplification {
            requested: derived.rights,
            available,
        });
    }
    commit(event_id, EventKind::AuthorityAttenuated { grant: derived.clone() })
}

pub(super) fn preflight_revocation(
    state: &CanonicalState,
    event_id: Identity,
    authority: EntityRef,
) -> Decision {
    let Some(grant) = grant_by_identity(state, authority.identity) else {
        return Decision::Reject(Rejection::UnknownAuthority { authority });
    };
    if grant.status == AuthorityStatus::Revoked {
        return Decision::Replay(Replay::NoChange);
    }
    if grant.authority.generation != authority.generation {
        return Decision::Reject(Rejection::StaleGeneration {
            identity: authority.identity,
            expected: grant.authority.generation,
            actual: authority.generation,
        });
    }
    let Some(revoked_generation) = authority.generation.next() else {
        return Decision::Reject(Rejection::GenerationExhausted);
    };
    commit(event_id, EventKind::AuthorityRevoked { authority, revoked_generation })
}

pub(super) fn validate_destination_authorities(
    state: &CanonicalState,
    prepared: &PreparedDestination,
) -> Result<(), Rejection> {
    let destination_subject =
        EntityRef::new(state.component.identity, prepared.component_generation);
    for (index, grant) in prepared.authorities.iter().enumerate() {
        if grant.authority.identity.is_zero()
            || grant.rights.is_empty()
            || grant.status != AuthorityStatus::Active
            || grant.subject != destination_subject
            || state
                .authorities
                .iter()
                .any(|existing| existing.authority.identity == grant.authority.identity)
            || prepared.authorities[..index]
                .iter()
                .any(|existing| existing.authority.identity == grant.authority.identity)
        {
            return Err(Rejection::InvalidIdentity);
        }
        let parent =
            grant.parent.ok_or(Rejection::UnknownAuthority { authority: grant.authority })?;
        let parent_grant = exact_grant(state, parent)?;
        if parent_grant.subject.identity != grant.subject.identity {
            return Err(Rejection::AuthoritySubjectMismatch);
        }
        if parent_grant.resource.identity != grant.resource.identity {
            return Err(Rejection::AuthorityResourceMismatch);
        }
        let available = effective_rights(state, parent)?;
        if !grant.rights.is_subset_of(available) {
            return Err(Rejection::AuthorityAmplification { requested: grant.rights, available });
        }
    }
    Ok(())
}

pub(super) fn authorize(
    state: &CanonicalState,
    authority: EntityRef,
    subject: EntityRef,
    resource: EntityRef,
    required: Rights,
) -> Result<(), Rejection> {
    let grant = any_exact_grant(state, authority)?;
    if grant.subject.identity == subject.identity && grant.subject.generation != subject.generation
    {
        return Err(Rejection::StaleGeneration {
            identity: subject.identity,
            expected: grant.subject.generation,
            actual: subject.generation,
        });
    }
    if grant.subject != subject {
        return Err(Rejection::AuthoritySubjectMismatch);
    }
    if grant.resource.identity == resource.identity
        && grant.resource.generation != resource.generation
    {
        return Err(Rejection::StaleGeneration {
            identity: resource.identity,
            expected: grant.resource.generation,
            actual: resource.generation,
        });
    }
    if grant.resource != resource {
        return Err(Rejection::AuthorityResourceMismatch);
    }
    let available = effective_rights_with_prepared(state, authority)?;
    if !available.contains(required) {
        return Err(Rejection::InsufficientAuthority { required, granted: available });
    }
    Ok(())
}

fn exact_grant(state: &CanonicalState, authority: EntityRef) -> Result<&AuthorityGrant, Rejection> {
    let Some(grant) = grant_by_identity(state, authority.identity) else {
        return Err(Rejection::UnknownAuthority { authority });
    };
    validate_grant_reference(grant, authority)
}

fn any_exact_grant(
    state: &CanonicalState,
    authority: EntityRef,
) -> Result<&AuthorityGrant, Rejection> {
    let grant = state
        .authorities
        .iter()
        .chain(state.prepared_destination.iter().flat_map(|prepared| prepared.authorities.iter()))
        .find(|grant| grant.authority.identity == authority.identity)
        .ok_or(Rejection::UnknownAuthority { authority })?;
    validate_grant_reference(grant, authority)
}

fn validate_grant_reference(
    grant: &AuthorityGrant,
    authority: EntityRef,
) -> Result<&AuthorityGrant, Rejection> {
    if grant.status == AuthorityStatus::Revoked {
        return Err(Rejection::AuthorityRevoked { authority });
    }
    if grant.authority.generation != authority.generation {
        return Err(Rejection::StaleGeneration {
            identity: authority.identity,
            expected: grant.authority.generation,
            actual: authority.generation,
        });
    }
    Ok(grant)
}

fn effective_rights(state: &CanonicalState, authority: EntityRef) -> Result<Rights, Rejection> {
    effective_rights_inner(state, authority, false)
}

fn effective_rights_with_prepared(
    state: &CanonicalState,
    authority: EntityRef,
) -> Result<Rights, Rejection> {
    effective_rights_inner(state, authority, true)
}

fn effective_rights_inner(
    state: &CanonicalState,
    authority: EntityRef,
    include_prepared: bool,
) -> Result<Rights, Rejection> {
    let mut current = authority;
    let mut effective = Rights::ALL;
    let max_depth = state.authorities.len()
        + if include_prepared {
            state.prepared_destination.as_ref().map_or(0, |prepared| prepared.authorities.len())
        } else {
            0
        }
        + 1;

    for _ in 0..max_depth {
        let grant = if include_prepared {
            any_exact_grant(state, current)?
        } else {
            exact_grant(state, current)?
        };
        effective = effective.intersection(grant.rights);
        let Some(parent) = grant.parent else {
            return Ok(effective);
        };
        current = parent;
    }
    Err(Rejection::UnknownAuthority { authority })
}

pub(super) fn grant_by_identity(
    state: &CanonicalState,
    identity: Identity,
) -> Option<&AuthorityGrant> {
    state.authorities.iter().find(|grant| grant.authority.identity == identity)
}
