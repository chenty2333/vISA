use std::collections::BTreeMap;

use joint_handoff_core::{
    ClosureProgressReceipt, ClosureReceipt, DestinationPreparedReceipt, EffectScopeVersion,
    JointIssuerSet, JointPhase, NexusFreezeReceipt, NexusThawReceipt, OwnershipAbortReceipt,
    OwnershipCommitReceipt, OwnershipPreparedReceipt, PrepareIntentReceipt, ReceiptEnvelope,
    ReceiptIssuerIdentity, ReceiptKind, ReceiptRequest, RetainedTombstoneReceipt, TypedReceipt,
    VisaDestinationActivationReceipt, VisaFreezeReceipt, VisaSourceFenceReceipt,
    VisaSourceResumeReceipt, canonical_bytes, canonical_from_bytes,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use visa_conformance::{
    JointEvidenceBundle, JointRawEventKind, JointReceipt, JointTerminal,
    joint_reference_authentication,
};
use visa_joint_handoff::{
    NativeReceiptAuthenticator, ReceiptRecordError, ReceiptVerificationError,
    VerifiedCommandReceipt, VerifiedJointState, record_verified_receipt, verify_native_receipt,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionReplayReport {
    pub case_count: usize,
    pub accepted_receipts: usize,
    pub rejected_receipts: usize,
    pub replayed_receipts: usize,
    pub all_matched: bool,
    pub reference_cell: Option<crate::ReferenceCellReport>,
    pub durable_projection_cell: Option<crate::DurableProjectionCellReport>,
    pub host_substrate_cell: Option<crate::CoordinatorVerticalCellReport>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthenticationError {
    IssuerMismatch,
    EffectScopeMismatch,
    PayloadDecode,
    RequestMismatch,
    InvalidReferenceChecksum,
}

struct PinnedReceiptAuthenticator {
    issuers: JointIssuerSet,
    effect_scope: EffectScopeVersion,
    destination: ExpectedDestinationPrepared,
}

#[derive(Clone, Copy)]
struct ExpectedDestinationPrepared {
    snapshot: joint_handoff_core::SnapshotBinding,
    journal_position: contract_core::JournalPosition,
    state_digest: contract_core::Digest,
    prepared_destination_digest: contract_core::Digest,
    authorities_digest: contract_core::Digest,
    bindings_digest: contract_core::Digest,
    lease_commit_operation: contract_core::Identity,
    lease_commit_idempotency: contract_core::IdempotencyKey,
    lease_commit_request_digest: contract_core::Digest,
}

impl NativeReceiptAuthenticator for PinnedReceiptAuthenticator {
    type Error = AuthenticationError;

    fn authenticate(
        &self,
        envelope: &ReceiptEnvelope,
        _envelope_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let expected = issuer_for_kind(self.issuers, envelope.kind);
        if envelope.issuer != expected.issuer
            || envelope.issuer_incarnation != expected.issuer_incarnation
        {
            return Err(AuthenticationError::IssuerMismatch);
        }
        // The bounded reference artifact uses a disclosed, independently
        // recomputable checksum. This verifies its exact bytes but does not
        // promote it to a signature, MAC, or production authenticator.
        let evidence_envelope =
            mirror(envelope).map_err(|_| AuthenticationError::InvalidReferenceChecksum)?;
        let expected_authentication = joint_reference_authentication(&evidence_envelope)
            .map_err(|_| AuthenticationError::InvalidReferenceChecksum)?;
        if envelope.authentication != expected_authentication {
            return Err(AuthenticationError::InvalidReferenceChecksum);
        }
        if envelope.kind == ReceiptKind::NexusFreeze {
            let receipt: NexusFreezeReceipt = canonical_from_bytes(payload_bytes)
                .map_err(|_| AuthenticationError::PayloadDecode)?;
            if receipt.registry_instance != self.effect_scope.registry_instance
                || receipt.scope_id != self.effect_scope.scope_id
                || receipt.scope_generation != self.effect_scope.scope_generation
                || receipt.authority_epoch != self.effect_scope.authority_epoch
                || receipt.freeze_generation != self.effect_scope.freeze_generation
            {
                return Err(AuthenticationError::EffectScopeMismatch);
            }
        } else if envelope.kind == ReceiptKind::DestinationPrepared {
            let receipt: DestinationPreparedReceipt = canonical_from_bytes(payload_bytes)
                .map_err(|_| AuthenticationError::PayloadDecode)?;
            if receipt.snapshot != self.destination.snapshot
                || receipt.journal_position != self.destination.journal_position
                || receipt.state_digest != self.destination.state_digest
                || receipt.prepared_destination_digest
                    != self.destination.prepared_destination_digest
                || receipt.authorities_digest != self.destination.authorities_digest
                || receipt.bindings_digest != self.destination.bindings_digest
                || receipt.lease_commit_operation != self.destination.lease_commit_operation
                || receipt.lease_commit_idempotency != self.destination.lease_commit_idempotency
                || receipt.lease_commit_request_digest
                    != self.destination.lease_commit_request_digest
            {
                return Err(AuthenticationError::PayloadDecode);
            }
        }
        Ok(())
    }
}

pub fn replay_bundle_with_production_reducer(
    bundle: &JointEvidenceBundle,
) -> Result<ProductionReplayReport, String> {
    let mut report = ProductionReplayReport {
        case_count: bundle.cases.len(),
        accepted_receipts: 0,
        rejected_receipts: 0,
        replayed_receipts: 0,
        all_matched: true,
        reference_cell: None,
        durable_projection_cell: None,
        host_substrate_cell: None,
    };
    for (case_index, case) in bundle.cases.iter().enumerate() {
        let key = mirror(&case.trace.key)?;
        let initial_issuers = mirror(&case.trace.issuers)?;
        let mut state = VerifiedJointState::new(key, initial_issuers)
            .map_err(|error| format!("invalid key: {error:?}"))?;
        let mut authenticator = PinnedReceiptAuthenticator {
            issuers: initial_issuers,
            effect_scope: mirror(&case.trace.initial_scope)?,
            destination: ExpectedDestinationPrepared {
                snapshot: mirror(&case.trace.prepared_input.snapshot)?,
                journal_position: case.trace.prepared_input.destination_journal_position,
                state_digest: case.trace.prepared_input.destination_state_digest,
                prepared_destination_digest: case.trace.prepared_input.prepared_destination_digest,
                authorities_digest: case.trace.prepared_input.prepared_authorities_digest,
                bindings_digest: case.trace.prepared_input.prepared_bindings_digest,
                lease_commit_operation: case.trace.prepared_input.lease_commit_operation,
                lease_commit_idempotency: case.trace.prepared_input.lease_commit_idempotency,
                lease_commit_request_digest: case.trace.prepared_input.lease_commit_request_digest,
            },
        };
        let mut accepted_requests = BTreeMap::new();
        for event in &case.trace.events {
            match &event.event {
                JointRawEventKind::ReceiptAccepted { request, envelope, receipt } => {
                    let next = authenticate_and_record(
                        &state,
                        command_identity(case_index, event.index),
                        envelope,
                        request,
                        receipt,
                        &authenticator,
                        &mut accepted_requests,
                    )
                    .map_err(|error| {
                        format!(
                            "{} event {} {:?} was retained as accepted but production returned {error}",
                            case.case_id,
                            event.index,
                            receipt.kind()
                        )
                    })?;
                    if next == state {
                        report.replayed_receipts += 1;
                    } else {
                        report.accepted_receipts += 1;
                    }
                    state = next;
                }
                JointRawEventKind::ReceiptRejected { request, envelope, receipt, .. } => {
                    if authenticate_and_record(
                        &state,
                        command_identity(case_index, event.index),
                        envelope,
                        request,
                        receipt,
                        &authenticator,
                        &mut accepted_requests,
                    )
                    .is_ok()
                    {
                        return Err(format!(
                            "{} event {} {:?} was retained as rejected but production verifier/reducer accepted it",
                            case.case_id,
                            event.index,
                            receipt.kind()
                        ));
                    }
                    report.rejected_receipts += 1;
                }
                JointRawEventKind::NexusServiceRebound {
                    previous,
                    current,
                    previous_scope,
                    current_scope,
                    domain_bindings_manifest_digest,
                } => {
                    apply_effect_rebind(
                        &mut authenticator,
                        mirror(previous)?,
                        mirror(current)?,
                        mirror(previous_scope)?,
                        mirror(current_scope)?,
                        *domain_bindings_manifest_digest,
                    )
                    .map_err(|error| {
                        format!("{} event {} invalid rebind: {error}", case.case_id, event.index)
                    })?;
                }
                JointRawEventKind::DestinationActivationStarted {
                    commit,
                    closure,
                    activation_command,
                } => {
                    let commit = mirror(commit)?;
                    let closure = mirror(closure)?;
                    if state.state().decision
                        != joint_handoff_core::OwnershipDecision::Commit(commit)
                        || !matches!(
                            state.state().closure,
                            joint_handoff_core::ClosureStatus::Closed { receipt, .. }
                                if receipt == closure
                        )
                    {
                        return Err(format!(
                            "{} event {} activation references do not match verified state",
                            case.case_id, event.index
                        ));
                    }
                    state = state.begin_destination_activation(*activation_command).map_err(
                        |error| {
                            format!(
                                "{} event {} activation start failed: {error:?}",
                                case.case_id, event.index
                            )
                        },
                    )?;
                }
                JointRawEventKind::EffectPublication { .. }
                | JointRawEventKind::OwnershipQuery { .. }
                | JointRawEventKind::ExternalFault { .. }
                | JointRawEventKind::ActorCrashed { .. }
                | JointRawEventKind::ActorRestarted { .. } => {}
            }
        }
        if !terminal_matches(state.state().phase, case.claimed_terminal) {
            return Err(format!(
                "{} terminal mismatch: production={:?}, claimed={:?}",
                case.case_id,
                state.state().phase,
                case.claimed_terminal
            ));
        }
    }
    Ok(report)
}

fn authenticate_and_record(
    state: &VerifiedJointState,
    command_identity: contract_core::Identity,
    envelope: &visa_conformance::ReceiptEnvelope,
    request: &visa_conformance::ReceiptRequest,
    receipt: &JointReceipt,
    authenticator: &PinnedReceiptAuthenticator,
    accepted_requests: &mut BTreeMap<contract_core::Digest, contract_core::Digest>,
) -> Result<VerifiedJointState, String> {
    let envelope: ReceiptEnvelope = mirror(envelope)?;
    let request: ReceiptRequest = mirror(request)?;
    match receipt {
        JointReceipt::PrepareIntent(value) => verify_record::<PrepareIntentReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::VisaFreeze(value) => verify_record::<VisaFreezeReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::EffectFreeze(value) => verify_record::<NexusFreezeReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::DestinationPrepared(value) => verify_record::<DestinationPreparedReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value.as_ref())?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::OwnershipPrepared(value) => verify_record::<OwnershipPreparedReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value.as_ref())?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::OwnershipAbort(value) => verify_record::<OwnershipAbortReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::OwnershipCommit(value) => verify_record::<OwnershipCommitReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::EffectThaw(value) => verify_record::<NexusThawReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::ClosureProgress(value) => verify_record::<ClosureProgressReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::Closure(value) => verify_record::<ClosureReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::RetainedTombstone(value) => verify_record::<RetainedTombstoneReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::VisaSourceFence(value) => verify_record::<VisaSourceFenceReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::VisaSourceResume(value) => verify_record::<VisaSourceResumeReceipt>(
            state,
            command_identity,
            &envelope,
            &request,
            &mirror(value)?,
            authenticator,
            accepted_requests,
        ),
        JointReceipt::VisaDestinationActivation(value) => {
            verify_record::<VisaDestinationActivationReceipt>(
                state,
                command_identity,
                &envelope,
                &request,
                &mirror(value)?,
                authenticator,
                accepted_requests,
            )
        }
    }
}

fn verify_record<T>(
    state: &VerifiedJointState,
    command_identity: contract_core::Identity,
    envelope: &ReceiptEnvelope,
    request: &ReceiptRequest,
    receipt: &T,
    authenticator: &PinnedReceiptAuthenticator,
    accepted_requests: &mut BTreeMap<contract_core::Digest, contract_core::Digest>,
) -> Result<VerifiedJointState, String>
where
    T: TypedReceipt + VerifiedCommandReceipt + DeserializeOwned,
{
    if !envelope.matches_request(request, receipt).map_err(|_| {
        "verification rejected: typed request binding could not be encoded".to_owned()
    })? {
        return Err(format!("verification rejected: {:?}", AuthenticationError::RequestMismatch));
    }
    let receipt_digest = receipt
        .receipt_ref()
        .map_err(|_| "verification rejected: receipt digest encoding failed".to_owned())?
        .digest;
    if let Some(existing) = accepted_requests.get(&receipt_digest)
        && *existing != envelope.request_digest
    {
        return Err(
            "verification rejected: conflicting request digest for exact receipt".to_owned()
        );
    }
    let envelope_bytes = canonical_bytes(envelope).map_err(|error| format!("{error:?}"))?;
    let payload_bytes = canonical_bytes(receipt).map_err(|error| format!("{error:?}"))?;
    let verified = verify_native_receipt::<T, _>(&envelope_bytes, &payload_bytes, authenticator)
        .map_err(format_verification_error)?;
    let next =
        record_verified_receipt(state, command_identity, &verified).map_err(format_record_error)?;
    accepted_requests.insert(receipt_digest, envelope.request_digest);
    Ok(next)
}

fn format_verification_error(error: ReceiptVerificationError<AuthenticationError>) -> String {
    format!("verification rejected: {error:?}")
}

fn format_record_error(error: ReceiptRecordError) -> String {
    format!("reducer rejected: {error:?}")
}

fn apply_effect_rebind(
    authenticator: &mut PinnedReceiptAuthenticator,
    previous: ReceiptIssuerIdentity,
    current: ReceiptIssuerIdentity,
    previous_scope: EffectScopeVersion,
    current_scope: EffectScopeVersion,
    domain_bindings_manifest_digest: contract_core::Digest,
) -> Result<(), &'static str> {
    if authenticator.issuers.effect_closure != previous
        || authenticator.effect_scope != previous_scope
    {
        return Err("previous issuer/scope does not match pinned policy");
    }
    if current != previous
        || current_scope.scope_id != previous_scope.scope_id
        || current_scope.scope_generation
            != previous_scope.scope_generation.checked_add(1).unwrap_or(0)
        || current_scope.authority_epoch != previous_scope.authority_epoch
        || current_scope.freeze_generation
            != previous_scope.freeze_generation.checked_add(1).unwrap_or(0)
        || current_scope.registry_instance.is_zero()
        || current_scope.registry_instance == previous_scope.registry_instance
        || domain_bindings_manifest_digest == contract_core::Digest::ZERO
    {
        return Err("rebind did not advance the pinned lineage exactly once");
    }
    authenticator.effect_scope = current_scope;
    Ok(())
}

fn issuer_for_kind(issuers: JointIssuerSet, kind: ReceiptKind) -> ReceiptIssuerIdentity {
    match kind {
        ReceiptKind::PrepareIntent
        | ReceiptKind::OwnershipPrepared
        | ReceiptKind::OwnershipAbort
        | ReceiptKind::OwnershipCommit => issuers.ownership,
        ReceiptKind::VisaFreeze | ReceiptKind::VisaSourceFence | ReceiptKind::VisaSourceResume => {
            issuers.visa_source
        }
        ReceiptKind::DestinationPrepared | ReceiptKind::VisaDestinationActivation => {
            issuers.visa_destination
        }
        ReceiptKind::NexusFreeze
        | ReceiptKind::NexusThaw
        | ReceiptKind::ClosureProgress
        | ReceiptKind::Closure
        | ReceiptKind::RetainedTombstone => issuers.effect_closure,
    }
}

fn mirror<T, U>(value: &T) -> Result<U, String>
where
    T: Serialize,
    U: DeserializeOwned,
{
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn command_identity(case_index: usize, event_index: u64) -> contract_core::Identity {
    let case = u128::try_from(case_index).unwrap_or(u128::MAX);
    contract_core::Identity::from_u128(
        10_000 + case.saturating_mul(1_000) + u128::from(event_index),
    )
}

fn terminal_matches(phase: JointPhase, terminal: JointTerminal) -> bool {
    matches!(
        (phase, terminal),
        (JointPhase::SourceActive, JointTerminal::SourceActive)
            | (JointPhase::PreparedFrozen, JointTerminal::PreparedFrozen)
            | (JointPhase::FrozenUnsealed, JointTerminal::CommitBlocked)
            | (JointPhase::DestinationActive, JointTerminal::DestinationActive)
    )
}

#[cfg(test)]
mod tests {
    use visa_conformance::{
        JointEvidenceExpectations, JointRawEventKind, build_reference_joint_evidence_bundle,
        joint_raw_trace_sha256, seal_joint_evidence_bundle_id,
    };

    use super::*;

    #[test]
    fn production_authenticator_rejects_mutated_reference_checksum_after_outer_reseal() {
        let expectations = JointEvidenceExpectations {
            visa_git_sha: "a".repeat(40),
            nexus_git_sha: "b".repeat(40),
            neutral_git_sha: "c".repeat(40),
            neutral_tree: "3".repeat(40),
            neutral_bundle_sha256: "4".repeat(64),
            source_lock_sha256: "d".repeat(64),
            protocol_schema_sha256: "e".repeat(64),
            machine_contract_sha256: "f".repeat(64),
            refinement_map_sha256: "1".repeat(64),
            abstract_registry_sha256: "2".repeat(64),
        };
        let mut bundle = build_reference_joint_evidence_bundle(&expectations).unwrap();
        let case = bundle
            .cases
            .iter_mut()
            .find(|case| case.case_id == "effect-commit-wins-freeze")
            .unwrap();
        let envelope = case
            .trace
            .events
            .iter_mut()
            .find_map(|event| match &mut event.event {
                JointRawEventKind::ReceiptAccepted { envelope, .. } => Some(envelope),
                _ => None,
            })
            .unwrap();
        envelope.authentication[0] ^= 1;
        case.trace_sha256 = joint_raw_trace_sha256(&case.trace).unwrap();
        bundle.production_replay_sha256 = Some("9".repeat(64));
        seal_joint_evidence_bundle_id(&mut bundle).unwrap();

        let error = replay_bundle_with_production_reducer(&bundle).unwrap_err();
        assert!(error.contains("InvalidReferenceChecksum"), "{error}");
    }
}
