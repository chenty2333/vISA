use std::collections::BTreeSet;

use contract_core::{Digest, EffectOutcome, EffectResult, EventKind, EvidenceKind, NodeIdentity};
use substrate_api::{
    ExternalHandoffProjectionPort, ExternalSourceFenceBundle, ProviderError, ProviderErrorKind,
};

use crate::{
    FaultPoint, SqliteProvider, database_error, error, journal::append_external_source_entry_on,
    load_canonical_entry,
};

impl ExternalHandoffProjectionPort for SqliteProvider {
    fn commit_external_source_fence(
        &mut self,
        bundle: &ExternalSourceFenceBundle,
    ) -> Result<(), ProviderError> {
        validate_bundle(self.scope.node, bundle)?;
        if self.take_fault(FaultPoint::BeforeExternalSourceFence) {
            return Err(error(ProviderErrorKind::Unavailable, true));
        }

        let scope = self.scope;
        let transaction = self.immediate_transaction()?;
        match load_canonical_entry(&transaction, scope, bundle.entry.position)? {
            Some(existing) if existing == bundle.entry => {
                for transition in &bundle.lease_transitions {
                    crate::lease::ensure_transition_applied(&transaction, *transition)?;
                }
            }
            Some(_) => return Err(error(ProviderErrorKind::Conflict, false)),
            None => {
                for transition in &bundle.lease_transitions {
                    crate::lease::apply_transition(&transaction, *transition)?;
                }
                append_external_source_entry_on(&transaction, scope, &bundle.entry)?;
            }
        }
        transaction.commit().map_err(database_error)?;

        if self.take_fault(FaultPoint::AfterExternalSourceFence) {
            return Err(error(ProviderErrorKind::OutcomeUnknown, true));
        }
        Ok(())
    }
}

fn validate_bundle(
    local_node: NodeIdentity,
    bundle: &ExternalSourceFenceBundle,
) -> Result<(), ProviderError> {
    if bundle.decision_digest == Digest::ZERO
        || bundle.closure_digest == Digest::ZERO
        || bundle.decision_digest == bundle.closure_digest
        || bundle.lease_transitions.is_empty()
    {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }

    let EventKind::HandoffCommitted {
        operation,
        handoff,
        snapshot,
        source,
        destination,
        previous_epoch,
        new_epoch,
        outcome,
    } = &bundle.entry.event.kind
    else {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    };
    if operation.is_zero()
        || handoff.is_zero()
        || snapshot.is_zero()
        || source.is_zero()
        || destination.is_zero()
        || source == destination
        || *source != local_node
        || previous_epoch.next() != Some(*new_epoch)
    {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }

    let EffectOutcome::Succeeded {
        result: EffectResult::LeaseAdvanced { owner, epoch, source_fence },
        evidence,
    } = outcome
    else {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    };
    if *owner != *destination
        || *epoch != *new_epoch
        || evidence.kind != EvidenceKind::AuthorityDecision
        || evidence.digest != bundle.decision_digest
        || source_fence.kind != EvidenceKind::SourceFence
        || source_fence.digest != bundle.closure_digest
        || evidence.identity.is_zero()
        || source_fence.identity.is_zero()
    {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }

    let mut resources = BTreeSet::new();
    if bundle.lease_transitions.iter().any(|transition| {
        !resources.insert(transition.resource)
            || transition.expected_owner != *source
            || transition.next_owner != *destination
            || transition.expected_epoch != *previous_epoch
            || transition.next_epoch != *new_epoch
    }) {
        return Err(error(ProviderErrorKind::InvalidRequest, false));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use contract_core::{
        EffectOutcome, EffectResult, Event, EvidenceRef, Identity, JournalEntry, JournalPosition,
        LeaseEpoch,
    };
    use substrate_api::{ExternalSourceFenceBundle, LeaseTransition};

    use super::*;

    fn identity(value: u128) -> Identity {
        Identity::from_u128(value)
    }

    fn node(value: u128) -> NodeIdentity {
        NodeIdentity::new(identity(value))
    }

    fn evidence(value: u128, kind: EvidenceKind, digest_byte: u8) -> EvidenceRef {
        EvidenceRef {
            identity: identity(value),
            kind,
            digest: Digest::from_bytes([digest_byte; 32]),
        }
    }

    fn bundle() -> ExternalSourceFenceBundle {
        let source = node(1);
        let destination = node(2);
        let decision = evidence(10, EvidenceKind::AuthorityDecision, 10);
        let closure = evidence(11, EvidenceKind::SourceFence, 11);
        let resource = contract_core::EntityRef::initial(identity(20));
        ExternalSourceFenceBundle {
            entry: JournalEntry {
                version: contract_core::CONTRACT_VERSION,
                position: JournalPosition(2),
                input_state: Digest::from_bytes([1; 32]),
                event: Event::new(
                    identity(30),
                    EventKind::HandoffCommitted {
                        operation: identity(31),
                        handoff: identity(32),
                        snapshot: identity(33),
                        source,
                        destination,
                        previous_epoch: LeaseEpoch(4),
                        new_epoch: LeaseEpoch(5),
                        outcome: EffectOutcome::Succeeded {
                            result: EffectResult::LeaseAdvanced {
                                owner: destination,
                                epoch: LeaseEpoch(5),
                                source_fence: closure,
                            },
                            evidence: decision,
                        },
                    },
                ),
                output_state: Digest::from_bytes([2; 32]),
            },
            lease_transitions: vec![LeaseTransition {
                resource,
                expected_owner: source,
                next_owner: destination,
                expected_epoch: LeaseEpoch(4),
                next_epoch: LeaseEpoch(5),
            }],
            decision_digest: decision.digest,
            closure_digest: closure.digest,
        }
    }

    #[test]
    fn validation_binds_native_decision_and_closure_digests() {
        let bundle = bundle();
        assert_eq!(validate_bundle(node(1), &bundle), Ok(()));

        let mut mutated = bundle.clone();
        mutated.closure_digest = Digest::from_bytes([12; 32]);
        assert_eq!(
            validate_bundle(node(1), &mutated),
            Err(error(ProviderErrorKind::InvalidRequest, false))
        );
    }

    #[test]
    fn validation_rejects_wrong_source_and_duplicate_resources() {
        let mut bundle = bundle();
        assert_eq!(
            validate_bundle(node(9), &bundle),
            Err(error(ProviderErrorKind::InvalidRequest, false))
        );
        bundle.lease_transitions.push(bundle.lease_transitions[0]);
        assert_eq!(
            validate_bundle(node(1), &bundle),
            Err(error(ProviderErrorKind::InvalidRequest, false))
        );
    }
}
