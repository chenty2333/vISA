use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};

use contract_core::{Digest, EffectOutcome, EffectRequest, Identity, LeaseEpoch};
use joint_handoff_core::{
    ClassificationCounts, ClosureProgressReceipt, ClosureReceipt, EffectScopeVersion,
    FreezeDisposition, JointHandoffKey, NexusFreezeReceipt, NexusThawReceipt,
    OwnershipAbortReceipt, OwnershipCommitReceipt, PrepareIntentReceipt, ReceiptHeader,
    ReceiptIssuerIdentity, ReceiptKind, ReceiptRef, RetainedTombstoneReceipt, TypedReceipt,
    canonical_digest,
};
use serde::{Deserialize, Serialize};
use substrate_api::{
    EffectAdmissionProfile, EffectClosureAuthenticationProfile, EffectClosureCapabilities,
    EffectClosureProtocolRange, EffectClosureProvider, EffectClosureProviderDescriptor,
    EffectClosureProviderLimits, EffectDispatchOutcome, EffectRequestBinding,
};
use visa_conformance::{
    JointEffectClassification, JointEffectRecord, joint_classification_counts,
    joint_classification_root, joint_effect_cohort_digest,
};

pub type ReferenceEffectRecord = JointEffectRecord;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectPeerConfig {
    pub key: JointHandoffKey,
    pub issuer: ReceiptIssuerIdentity,
    pub ownership_issuer: ReceiptIssuerIdentity,
    pub registry_instance: Identity,
    pub scope_id: Identity,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub freeze_generation: u64,
    pub domain_bindings_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectPublicationRequest {
    pub key: JointHandoffKey,
    pub registry_instance: Identity,
    pub scope_id: Identity,
    pub scope_generation: u64,
    pub source_epoch: LeaseEpoch,
    pub record: ReferenceEffectRecord,
}

/// Provider-SPI registration envelope binding the frozen publication selector
/// to the complete canonical effect request. This is deliberately local to the
/// v2 preview SPI and does not add a field to joint-handoff wire v1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectAdmissionRegistration {
    binding: EffectRequestBinding,
    publication: EffectPublicationRequest,
}

impl EffectAdmissionRegistration {
    pub fn new(
        effect: &EffectRequest,
        publication: EffectPublicationRequest,
    ) -> Result<Self, EffectPeerError> {
        let binding =
            EffectRequestBinding::from_effect(effect).map_err(|_| EffectPeerError::Integrity)?;
        Ok(Self { binding, publication })
    }

    pub const fn binding(&self) -> EffectRequestBinding {
        self.binding
    }

    pub const fn publication(&self) -> &EffectPublicationRequest {
        &self.publication
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectPublicationResult {
    Published,
    Replay,
}

/// In-process provider state returned after one exact effect registration.
/// Its private request binding prevents construction outside this adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceRegisteredEffect {
    effect: EffectRequest,
    registration: EffectAdmissionRegistration,
    replay: bool,
}

impl ReferenceRegisteredEffect {
    pub const fn is_replay(&self) -> bool {
        self.replay
    }
}

/// In-process provider state returned after the registered selector has been
/// checked against the live reference projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferencePreparedEffect {
    effect: EffectRequest,
    registration: EffectAdmissionRegistration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceEffectCommitMetadata {
    pub result: i64,
    pub domain_revision: u64,
}

/// Provider-local commit observation. The provider-typed admission permit,
/// rather than this copyable observation, carries dispatch authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceEffectCommitEvidence {
    pub result: i64,
    pub domain_revision: u64,
    pub replay: bool,
    effect: Identity,
    binding: EffectRequestBinding,
    dispatch_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceEffectDispatchFence {
    effect: Identity,
    binding: EffectRequestBinding,
    dispatch_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceEffectOutcomeEvidence {
    outcome: EffectOutcome,
    replay: bool,
}

impl ReferenceEffectOutcomeEvidence {
    pub const fn outcome(&self) -> &EffectOutcome {
        &self.outcome
    }

    pub const fn is_replay(&self) -> bool {
        self.replay
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceEffectCompletionRequest {
    pub result: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceEffectCompletionEvidence {
    pub result: i64,
    replay: bool,
}

impl ReferenceEffectCompletionEvidence {
    pub const fn is_replay(&self) -> bool {
        self.replay
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceEffectQueryPhase {
    Registered,
    Prepared,
    Committed,
    OutcomeRecorded,
    Completed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceEffectQueryObservation {
    phase: ReferenceEffectQueryPhase,
    outcome: Option<EffectOutcome>,
}

impl ReferenceEffectQueryObservation {
    pub const fn phase(&self) -> ReferenceEffectQueryPhase {
        self.phase
    }

    pub const fn outcome(&self) -> Option<&EffectOutcome> {
        self.outcome.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFreezeRequest {
    pub key: JointHandoffKey,
    pub intent: PrepareIntentReceipt,
    pub registry_instance: Identity,
    pub scope_id: Identity,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub freeze_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFreezeToken {
    pub key: JointHandoffKey,
    pub reservation: Identity,
    pub registry_instance: Identity,
    pub scope_id: Identity,
    pub scope_generation: u64,
    pub authority_epoch: u64,
    pub freeze_generation: u64,
    pub freeze: ReceiptRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectFreezeResult {
    pub receipt: NexusFreezeReceipt,
    pub token: EffectFreezeToken,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectThawRequest {
    pub token: EffectFreezeToken,
    pub abort: OwnershipAbortReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectCloseRequest {
    pub token: EffectFreezeToken,
    pub commit: OwnershipCommitReceipt,
    pub expected_closure_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectCloseResult {
    Progress(ClosureProgressReceipt),
    Closed(ClosureReceipt),
    RetainedTombstone(RetainedTombstoneReceipt),
}

impl EffectCloseResult {
    pub fn closure_revision(&self) -> u64 {
        match self {
            Self::Progress(receipt) => receipt.closure_revision,
            Self::Closed(receipt) => receipt.closure_revision,
            Self::RetainedTombstone(receipt) => receipt.closure_revision,
        }
    }

    pub(crate) fn receipt_ref(&self) -> Result<ReceiptRef, EffectPeerError> {
        match self {
            Self::Progress(receipt) => receipt.receipt_ref(),
            Self::Closed(receipt) => receipt.receipt_ref(),
            Self::RetainedTombstone(receipt) => receipt.receipt_ref(),
        }
        .map_err(|_| EffectPeerError::Integrity)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectPeerQuery {
    pub scope: EffectScopeVersion,
    pub gate_open: bool,
    pub effect_count: usize,
    pub freeze: Option<EffectFreezeResult>,
    pub thaw: Option<NexusThawReceipt>,
    pub latest_close: Option<EffectCloseResult>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectPeerError {
    InvalidRequest,
    HandoffMismatch,
    StaleRegistry,
    StaleScope,
    StaleEpoch,
    StaleFreezeGeneration,
    GateClosed,
    Revoked,
    PublicationConflict,
    StepConflict,
    TokenMismatch,
    NotFrozen,
    FreezeBlocked,
    LiveEffectOutcomePending,
    StaleRevision { expected: u64, actual: u64 },
    ExistingAbort(Box<NexusThawReceipt>),
    ExistingCommit(Box<EffectCloseResult>),
    AcknowledgementLost { request_id: u64 },
    AcknowledgementRecoveryConflict { request_id: u64 },
    Unsupported(&'static str),
    Transport(String),
    NativePeer { code: String, detail: String },
    NativeReceiptRejected(&'static str),
    Integrity,
}

pub trait EffectPeer: Send + Sync {
    fn publish(
        &self,
        request: EffectPublicationRequest,
    ) -> Result<EffectPublicationResult, EffectPeerError>;

    fn freeze(&self, request: EffectFreezeRequest) -> Result<EffectFreezeResult, EffectPeerError>;

    fn thaw(&self, request: EffectThawRequest) -> Result<NexusThawReceipt, EffectPeerError>;

    fn close(&self, request: EffectCloseRequest) -> Result<EffectCloseResult, EffectPeerError>;

    fn query(&self) -> Result<EffectPeerQuery, EffectPeerError>;

    fn rebind(
        &self,
        new_registry_instance: Identity,
    ) -> Result<EffectScopeVersion, EffectPeerError>;

    fn native_raw_responses(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EffectPhase {
    Frozen,
    Thawed,
    Closing,
    Closed,
    RetainedTombstone,
}

#[derive(Clone, Debug)]
struct StoredCloseStep {
    request_digest: Digest,
    result: EffectCloseResult,
}

#[derive(Clone, Debug)]
struct FreezeSession {
    request_digest: Digest,
    result: EffectFreezeResult,
    intent: ReceiptRef,
    ownership_issuer: ReceiptIssuerIdentity,
    frozen_effects: BTreeMap<Identity, ReferenceEffectRecord>,
    phase: EffectPhase,
    thaw_request_digest: Option<Digest>,
    thaw: Option<NexusThawReceipt>,
    commit: Option<ReceiptRef>,
    closure_revision: u64,
    close_remaining: Vec<Identity>,
    retained_tombstones: Vec<Identity>,
    close_steps: BTreeMap<u64, StoredCloseStep>,
    latest_close: Option<EffectCloseResult>,
}

#[derive(Debug)]
struct EffectPeerState {
    config: EffectPeerConfig,
    admission_profile: EffectAdmissionProfile,
    next_sequence: u64,
    effects: BTreeMap<Identity, ReferenceEffectRecord>,
    admissions: BTreeMap<Identity, ReferenceAdmission>,
    session: Option<FreezeSession>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReferenceAdmissionPhase {
    Registered,
    Prepared,
    Committed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReferenceDispatchPhase {
    Available,
    Consumed,
    GuestReturned,
    GuestFailed,
    Revoked,
}

#[derive(Clone, Debug)]
struct ReferenceAdmission {
    effect: EffectRequest,
    registration: EffectAdmissionRegistration,
    phase: ReferenceAdmissionPhase,
    commit: Option<ReferenceEffectCommitMetadata>,
    dispatch_generation: u64,
    dispatch_phase: ReferenceDispatchPhase,
    outcome: Option<EffectOutcome>,
    completion: Option<ReferenceEffectCompletionRequest>,
}

pub struct ReferenceEffectPeer {
    state: Mutex<EffectPeerState>,
}

pub fn effect_receipt_issuer(
    namespace: ReceiptIssuerIdentity,
    key: JointHandoffKey,
) -> Result<ReceiptIssuerIdentity, EffectPeerError> {
    if !well_formed_issuer(namespace) || !key.is_well_formed() {
        return Err(EffectPeerError::InvalidRequest);
    }
    let digest =
        canonical_digest(&(b"effect-handoff-log".as_slice(), namespace.log_id, key.handoff))
            .map_err(|_| EffectPeerError::InvalidRequest)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    let log_id = Identity::from_bytes(bytes);
    if log_id.is_zero() {
        return Err(EffectPeerError::InvalidRequest);
    }
    Ok(ReceiptIssuerIdentity { log_id, ..namespace })
}

impl ReferenceEffectPeer {
    pub fn new(config: EffectPeerConfig) -> Result<Self, EffectPeerError> {
        Self::new_with_profile(config, EffectAdmissionProfile::Compatibility)
    }

    pub fn new_admission_required(config: EffectPeerConfig) -> Result<Self, EffectPeerError> {
        Self::new_with_profile(config, EffectAdmissionProfile::AdmissionRequired)
    }

    fn new_with_profile(
        config: EffectPeerConfig,
        admission_profile: EffectAdmissionProfile,
    ) -> Result<Self, EffectPeerError> {
        if !well_formed_config(config) {
            return Err(EffectPeerError::InvalidRequest);
        }
        Ok(Self {
            state: Mutex::new(EffectPeerState {
                config,
                admission_profile,
                next_sequence: 0,
                effects: BTreeMap::new(),
                admissions: BTreeMap::new(),
                session: None,
            }),
        })
    }

    pub fn publish(
        &self,
        request: EffectPublicationRequest,
    ) -> Result<EffectPublicationResult, EffectPeerError> {
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        if state.admission_profile == EffectAdmissionProfile::AdmissionRequired {
            return Err(EffectPeerError::Unsupported(
                "legacy effect publication is disabled by the admission-required profile",
            ));
        }
        validate_publication_request(&state.config, &request)?;
        if let Some(existing) = state.effects.get(&request.record.effect) {
            if existing == &request.record {
                return Ok(EffectPublicationResult::Replay);
            }
            if resumed_frozen_registered_commit(state.session.as_ref(), existing, &request.record) {
                state.effects.insert(request.record.effect, request.record);
                return Ok(EffectPublicationResult::Published);
            }
            return Err(EffectPeerError::PublicationConflict);
        }
        if !gate_open(state.session.as_ref()) {
            return Err(EffectPeerError::GateClosed);
        }
        state.effects.insert(request.record.effect, request.record);
        Ok(EffectPublicationResult::Published)
    }

    pub fn freeze(
        &self,
        request: EffectFreezeRequest,
    ) -> Result<EffectFreezeResult, EffectPeerError> {
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        validate_freeze_request(&state.config, &request)?;
        let request_digest = request_digest(&request)?;
        if let Some(session) = &state.session {
            return if session.request_digest == request_digest {
                Ok(session.result.clone())
            } else {
                Err(EffectPeerError::StepConflict)
            };
        }
        let intent = validated_intent(&request.intent, request.key, state.config.ownership_issuer)?;
        let effects: Vec<_> = state.effects.values().cloned().collect();
        let conformance_key = conformance_key(request.key)?;
        let cohort = joint_effect_cohort_digest(conformance_key, effects.clone())
            .map_err(|_| EffectPeerError::Integrity)?;
        let classification = joint_classification_root(conformance_key, effects.clone())
            .map_err(|_| EffectPeerError::Integrity)?;
        let conformance_counts = joint_classification_counts(effects.clone());
        let counts = ClassificationCounts {
            registered: conformance_counts.registered,
            committed: conformance_counts.committed,
            aborted: conformance_counts.aborted,
            unresolved: conformance_counts.unresolved,
            tombstones: conformance_counts.tombstones,
        };
        let blocked = effects.iter().any(|record| {
            matches!(
                record.classification,
                JointEffectClassification::Registered
                    | JointEffectClassification::UnresolvedTombstone
            )
        });
        let disposition = if blocked {
            FreezeDisposition::Blocked { blocker_digest: classification }
        } else {
            FreezeDisposition::ReadyToCommit
        };
        let header = next_header(&mut state, ReceiptKind::NexusFreeze, None)?;
        let receipt = NexusFreezeReceipt {
            header,
            key: request.key,
            intent,
            registry_instance: request.registry_instance,
            scope_id: request.scope_id,
            scope_generation: request.scope_generation,
            authority_epoch: request.authority_epoch,
            freeze_generation: request.freeze_generation,
            domain_bindings_digest: state.config.domain_bindings_digest,
            effect_cohort_digest: cohort,
            classification_root: classification,
            counts,
            disposition,
        };
        let freeze = receipt.receipt_ref().map_err(|_| EffectPeerError::Integrity)?;
        let token = EffectFreezeToken {
            key: request.key,
            reservation: request.intent.reservation,
            registry_instance: request.registry_instance,
            scope_id: request.scope_id,
            scope_generation: request.scope_generation,
            authority_epoch: request.authority_epoch,
            freeze_generation: request.freeze_generation,
            freeze,
        };
        let result = EffectFreezeResult { receipt, token };
        state.session = Some(FreezeSession {
            request_digest,
            result: result.clone(),
            intent,
            ownership_issuer: state.config.ownership_issuer,
            frozen_effects: state.effects.clone(),
            phase: EffectPhase::Frozen,
            thaw_request_digest: None,
            thaw: None,
            commit: None,
            closure_revision: 0,
            close_remaining: Vec::new(),
            retained_tombstones: Vec::new(),
            close_steps: BTreeMap::new(),
            latest_close: None,
        });
        Ok(result)
    }

    pub fn thaw(&self, request: EffectThawRequest) -> Result<NexusThawReceipt, EffectPeerError> {
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        let request_digest = request_digest(&request)?;
        let session = state.session.as_mut().ok_or(EffectPeerError::NotFrozen)?;
        require_token(session, request.token)?;
        if let Some(commit) = &session.latest_close {
            return Err(EffectPeerError::ExistingCommit(Box::new(commit.clone())));
        }
        if let Some(existing_digest) = session.thaw_request_digest {
            return if existing_digest == request_digest {
                session.thaw.clone().ok_or(EffectPeerError::Integrity)
            } else {
                Err(EffectPeerError::StepConflict)
            };
        }
        if session.phase != EffectPhase::Frozen || !valid_abort_authority(session, &request.abort)?
        {
            return Err(EffectPeerError::InvalidRequest);
        }
        let abort = request.abort.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)?;
        let thaw_generation = request
            .token
            .freeze_generation
            .checked_add(1)
            .ok_or(EffectPeerError::InvalidRequest)?;
        let header =
            next_header(&mut state, ReceiptKind::NexusThaw, Some(request.token.freeze.digest))?;
        let receipt = NexusThawReceipt {
            header,
            key: request.token.key,
            abort,
            nexus_freeze: request.token.freeze,
            thaw_generation,
        };
        let session = state.session.as_mut().ok_or(EffectPeerError::Integrity)?;
        session.phase = EffectPhase::Thawed;
        session.thaw_request_digest = Some(request_digest);
        session.thaw = Some(receipt.clone());
        Ok(receipt)
    }

    pub fn close(&self, request: EffectCloseRequest) -> Result<EffectCloseResult, EffectPeerError> {
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        let request_digest = request_digest(&request)?;
        {
            let session = state.session.as_ref().ok_or(EffectPeerError::NotFrozen)?;
            require_token(session, request.token)?;
            if let Some(thaw) = &session.thaw {
                return Err(EffectPeerError::ExistingAbort(Box::new(thaw.clone())));
            }
            if let Some(step) = session.close_steps.get(&request.expected_closure_revision) {
                return if step.request_digest == request_digest {
                    Ok(step.result.clone())
                } else {
                    Err(EffectPeerError::StepConflict)
                };
            }
            if session.phase == EffectPhase::Closed {
                return Err(EffectPeerError::ExistingCommit(Box::new(
                    session.latest_close.clone().ok_or(EffectPeerError::Integrity)?,
                )));
            }
            if session.result.receipt.disposition != FreezeDisposition::ReadyToCommit {
                return Err(EffectPeerError::FreezeBlocked);
            }
            if request.expected_closure_revision != session.closure_revision {
                return Err(EffectPeerError::StaleRevision {
                    expected: request.expected_closure_revision,
                    actual: session.closure_revision,
                });
            }
            if !valid_commit_authority(session, &request.commit)? {
                return Err(EffectPeerError::InvalidRequest);
            }
        }

        initialize_close(&mut state, &request)?;
        let (parent, next_revision, remaining, retained, freeze, key, authority_epoch, cohort) = {
            let session = state.session.as_mut().ok_or(EffectPeerError::Integrity)?;
            if !session.close_remaining.is_empty() {
                session.close_remaining.remove(0);
            }
            let parent = session
                .latest_close
                .as_ref()
                .map_or(Ok(session.result.token.freeze), EffectCloseResult::receipt_ref)?;
            (
                parent,
                session.closure_revision.checked_add(1).ok_or(EffectPeerError::InvalidRequest)?,
                session.close_remaining.clone(),
                session.retained_tombstones.clone(),
                session.result.token.freeze,
                session.result.token.key,
                session.result.token.authority_epoch,
                session.result.receipt.effect_cohort_digest,
            )
        };
        let commit = request.commit.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)?;
        let result = if !remaining.is_empty() {
            let progress_root = canonical_digest(&(
                b"vISA reference effect close progress v1".as_slice(),
                key,
                commit,
                freeze,
                next_revision,
                &remaining,
            ))
            .map_err(|_| EffectPeerError::Integrity)?;
            EffectCloseResult::Progress(ClosureProgressReceipt {
                header: next_header(&mut state, ReceiptKind::ClosureProgress, Some(parent.digest))?,
                key,
                commit,
                nexus_freeze: freeze,
                closure_revision: next_revision,
                remaining_effects: u64::try_from(remaining.len())
                    .map_err(|_| EffectPeerError::Integrity)?,
                retained_tombstones: 0,
                progress_root,
            })
        } else if !retained.is_empty() {
            let tombstone_manifest_digest = canonical_digest(&(
                b"vISA reference retained tombstones v1".as_slice(),
                key,
                commit,
                freeze,
                next_revision,
                &retained,
            ))
            .map_err(|_| EffectPeerError::Integrity)?;
            EffectCloseResult::RetainedTombstone(RetainedTombstoneReceipt {
                header: next_header(
                    &mut state,
                    ReceiptKind::RetainedTombstone,
                    Some(parent.digest),
                )?,
                key,
                commit,
                nexus_freeze: freeze,
                closure_revision: next_revision,
                tombstone_count: u64::try_from(retained.len())
                    .map_err(|_| EffectPeerError::Integrity)?,
                tombstone_manifest_digest,
            })
        } else {
            EffectCloseResult::Closed(ClosureReceipt {
                header: next_header(&mut state, ReceiptKind::Closure, Some(parent.digest))?,
                key,
                commit,
                nexus_freeze: freeze,
                closure_revision: next_revision,
                effect_manifest_digest: cohort,
                closed_authority_epoch: authority_epoch,
            })
        };
        let session = state.session.as_mut().ok_or(EffectPeerError::Integrity)?;
        session.phase = match result {
            EffectCloseResult::Progress(_) => EffectPhase::Closing,
            EffectCloseResult::Closed(_) => EffectPhase::Closed,
            EffectCloseResult::RetainedTombstone(_) => EffectPhase::RetainedTombstone,
        };
        if matches!(result, EffectCloseResult::RetainedTombstone(_)) {
            session.retained_tombstones.clear();
        }
        session.closure_revision = next_revision;
        session.close_steps.insert(
            request.expected_closure_revision,
            StoredCloseStep { request_digest, result: result.clone() },
        );
        session.latest_close = Some(result.clone());
        Ok(result)
    }

    pub fn query(&self) -> Result<EffectPeerQuery, EffectPeerError> {
        let state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        Ok(EffectPeerQuery {
            scope: scope(&state.config),
            gate_open: gate_open(state.session.as_ref()),
            effect_count: state.effects.len(),
            freeze: state.session.as_ref().map(|session| session.result.clone()),
            thaw: state.session.as_ref().and_then(|session| session.thaw.clone()),
            latest_close: state.session.as_ref().and_then(|session| session.latest_close.clone()),
        })
    }

    pub fn rebind(
        &self,
        new_registry_instance: Identity,
    ) -> Result<EffectScopeVersion, EffectPeerError> {
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        if state.session.is_some() {
            return Err(EffectPeerError::GateClosed);
        }
        if new_registry_instance.is_zero()
            || new_registry_instance == state.config.registry_instance
        {
            return Err(EffectPeerError::InvalidRequest);
        }
        state.config.scope_generation =
            state.config.scope_generation.checked_add(1).ok_or(EffectPeerError::InvalidRequest)?;
        state.config.freeze_generation =
            state.config.freeze_generation.checked_add(1).ok_or(EffectPeerError::InvalidRequest)?;
        state.config.registry_instance = new_registry_instance;
        Ok(scope(&state.config))
    }

    pub fn revoke_effect_dispatch(&self, effect: Identity) -> Result<(), EffectPeerError> {
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        let admission = state.admissions.get_mut(&effect).ok_or(EffectPeerError::StepConflict)?;
        if admission.phase != ReferenceAdmissionPhase::Committed
            || admission.dispatch_phase != ReferenceDispatchPhase::Available
        {
            return Err(EffectPeerError::StepConflict);
        }
        admission.dispatch_phase = ReferenceDispatchPhase::Revoked;
        Ok(())
    }
}

impl EffectClosureProvider for ReferenceEffectPeer {
    type RegistrationRequest = EffectAdmissionRegistration;
    type Registered = ReferenceRegisteredEffect;
    type Prepared = ReferencePreparedEffect;
    type CommitMetadata = ReferenceEffectCommitMetadata;
    type CommitEvidence = ReferenceEffectCommitEvidence;
    type DispatchFence = ReferenceEffectDispatchFence;
    type OutcomeEvidence = ReferenceEffectOutcomeEvidence;
    type CompletionRequest = ReferenceEffectCompletionRequest;
    type CompletionEvidence = ReferenceEffectCompletionEvidence;
    type QueryObservation = ReferenceEffectQueryObservation;
    type Error = EffectPeerError;

    fn descriptor(&self) -> Result<EffectClosureProviderDescriptor, Self::Error> {
        let admission_profile =
            self.state.lock().map_err(|_| EffectPeerError::Integrity)?.admission_profile;
        Ok(EffectClosureProviderDescriptor {
            protocol: EffectClosureProtocolRange::v2_preview(),
            admission_profile,
            capabilities: EffectClosureCapabilities {
                effect_admission: true,
                outcome_recording: true,
                effect_completion: true,
                session_query: true,
                freeze_thaw: true,
                commit_close: true,
                crash_rebind: false,
                retained_device: false,
                persistent_query: false,
            },
            authentication: EffectClosureAuthenticationProfile::None,
            limits: EffectClosureProviderLimits {
                max_scopes: 1,
                max_effects_per_scope: 1,
                max_inflight_mutations: 1,
                max_request_bytes: 64 * 1024,
                max_receipt_bytes: 1024 * 1024,
            },
        })
    }

    fn register_effect(
        &self,
        effect: &EffectRequest,
        request: &Self::RegistrationRequest,
    ) -> Result<Self::Registered, Self::Error> {
        if !request.binding.matches(effect).map_err(|_| EffectPeerError::Integrity)? {
            return Err(EffectPeerError::InvalidRequest);
        }
        validate_reference_admission_binding(effect, &request.publication)?;
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        validate_publication_request(&state.config, &request.publication)?;
        if !gate_open(state.session.as_ref()) {
            return Err(EffectPeerError::GateClosed);
        }
        if let Some(existing) = state.admissions.get(&request.publication.record.effect) {
            return if existing.registration == *request && existing.effect == *effect {
                Ok(ReferenceRegisteredEffect {
                    effect: effect.clone(),
                    registration: request.clone(),
                    replay: true,
                })
            } else {
                Err(EffectPeerError::PublicationConflict)
            };
        }
        if state.effects.contains_key(&request.publication.record.effect) {
            return Err(EffectPeerError::PublicationConflict);
        }
        let dispatch_generation = state.config.scope_generation;
        state.effects.insert(request.publication.record.effect, request.publication.record.clone());
        state.admissions.insert(
            request.publication.record.effect,
            ReferenceAdmission {
                effect: effect.clone(),
                registration: request.clone(),
                phase: ReferenceAdmissionPhase::Registered,
                commit: None,
                dispatch_generation,
                dispatch_phase: ReferenceDispatchPhase::Available,
                outcome: None,
                completion: None,
            },
        );
        Ok(ReferenceRegisteredEffect {
            effect: effect.clone(),
            registration: request.clone(),
            replay: false,
        })
    }

    fn prepare_effect(
        &self,
        effect: &EffectRequest,
        registered: &Self::Registered,
    ) -> Result<Self::Prepared, Self::Error> {
        validate_reference_admission_binding(effect, &registered.registration.publication)?;
        if !registered
            .registration
            .binding
            .matches(effect)
            .map_err(|_| EffectPeerError::Integrity)?
        {
            return Err(EffectPeerError::PublicationConflict);
        }
        if registered.effect != *effect {
            return Err(EffectPeerError::PublicationConflict);
        }
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        validate_publication_request(&state.config, &registered.registration.publication)?;
        if !gate_open(state.session.as_ref()) {
            return Err(EffectPeerError::GateClosed);
        }
        match state.admissions.get_mut(&registered.registration.publication.record.effect) {
            Some(admission)
                if admission.registration == registered.registration
                    && admission.effect == *effect =>
            {
                if admission.phase == ReferenceAdmissionPhase::Registered {
                    admission.phase = ReferenceAdmissionPhase::Prepared;
                }
                Ok(ReferencePreparedEffect {
                    effect: effect.clone(),
                    registration: registered.registration.clone(),
                })
            }
            Some(_) => Err(EffectPeerError::PublicationConflict),
            None => Err(EffectPeerError::StepConflict),
        }
    }

    fn commit_effect(
        &self,
        effect: &EffectRequest,
        prepared: &Self::Prepared,
        metadata: &Self::CommitMetadata,
    ) -> Result<Self::CommitEvidence, Self::Error> {
        validate_reference_admission_binding(effect, &prepared.registration.publication)?;
        if !prepared.registration.binding.matches(effect).map_err(|_| EffectPeerError::Integrity)? {
            return Err(EffectPeerError::PublicationConflict);
        }
        if prepared.effect != *effect {
            return Err(EffectPeerError::PublicationConflict);
        }
        if metadata.domain_revision == 0 {
            return Err(EffectPeerError::InvalidRequest);
        }

        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        validate_publication_request(&state.config, &prepared.registration.publication)?;
        if metadata.domain_revision != state.config.scope_generation {
            return Err(EffectPeerError::StaleScope);
        }
        if !gate_open(state.session.as_ref()) {
            return Err(EffectPeerError::GateClosed);
        }
        let effect_identity = prepared.registration.publication.record.effect;
        let replay = match state.admissions.get_mut(&effect_identity) {
            Some(admission)
                if admission.registration == prepared.registration
                    && admission.effect == *effect =>
            {
                match admission.phase {
                    ReferenceAdmissionPhase::Registered => {
                        return Err(EffectPeerError::StepConflict);
                    }
                    ReferenceAdmissionPhase::Prepared => {
                        admission.phase = ReferenceAdmissionPhase::Committed;
                        admission.commit = Some(*metadata);
                        false
                    }
                    ReferenceAdmissionPhase::Committed if admission.commit == Some(*metadata) => {
                        true
                    }
                    ReferenceAdmissionPhase::Committed => {
                        return Err(EffectPeerError::StepConflict);
                    }
                }
            }
            Some(_) => return Err(EffectPeerError::PublicationConflict),
            None => return Err(EffectPeerError::StepConflict),
        };
        Ok(ReferenceEffectCommitEvidence {
            result: metadata.result,
            domain_revision: metadata.domain_revision,
            replay,
            effect: effect_identity,
            binding: prepared.registration.binding,
            dispatch_generation: state.config.scope_generation,
        })
    }

    fn consume_committed_effect(
        &self,
        effect: &EffectRequest,
        evidence: &Self::CommitEvidence,
    ) -> Result<Self::DispatchFence, Self::Error> {
        if !evidence.binding.matches(effect).map_err(|_| EffectPeerError::Integrity)? {
            return Err(EffectPeerError::PublicationConflict);
        }
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        if state.admission_profile != EffectAdmissionProfile::AdmissionRequired {
            return Err(EffectPeerError::Unsupported(
                "dispatch consumption requires the admission-required profile",
            ));
        }
        if evidence.dispatch_generation != state.config.scope_generation {
            return Err(EffectPeerError::StaleScope);
        }
        let admission =
            state.admissions.get_mut(&evidence.effect).ok_or(EffectPeerError::StepConflict)?;
        if admission.effect != *effect
            || admission.registration.binding != evidence.binding
            || admission.phase != ReferenceAdmissionPhase::Committed
            || admission.commit
                != Some(ReferenceEffectCommitMetadata {
                    result: evidence.result,
                    domain_revision: evidence.domain_revision,
                })
            || admission.dispatch_generation != evidence.dispatch_generation
        {
            return Err(EffectPeerError::PublicationConflict);
        }
        match admission.dispatch_phase {
            ReferenceDispatchPhase::Available => {
                admission.dispatch_phase = ReferenceDispatchPhase::Consumed;
            }
            ReferenceDispatchPhase::Revoked => return Err(EffectPeerError::Revoked),
            ReferenceDispatchPhase::Consumed
            | ReferenceDispatchPhase::GuestReturned
            | ReferenceDispatchPhase::GuestFailed => return Err(EffectPeerError::StepConflict),
        }
        Ok(ReferenceEffectDispatchFence {
            effect: evidence.effect,
            binding: evidence.binding,
            dispatch_generation: evidence.dispatch_generation,
        })
    }

    fn finish_effect_dispatch(
        &self,
        effect: &EffectRequest,
        fence: &Self::DispatchFence,
        outcome: EffectDispatchOutcome,
    ) -> Result<(), Self::Error> {
        if !fence.binding.matches(effect).map_err(|_| EffectPeerError::Integrity)? {
            return Err(EffectPeerError::PublicationConflict);
        }
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        if fence.dispatch_generation != state.config.scope_generation {
            return Err(EffectPeerError::StaleScope);
        }
        let admission =
            state.admissions.get_mut(&fence.effect).ok_or(EffectPeerError::StepConflict)?;
        if admission.effect != *effect
            || admission.registration.binding != fence.binding
            || admission.dispatch_generation != fence.dispatch_generation
            || admission.dispatch_phase != ReferenceDispatchPhase::Consumed
        {
            return Err(EffectPeerError::StepConflict);
        }
        admission.dispatch_phase = match outcome {
            EffectDispatchOutcome::GuestReturned => ReferenceDispatchPhase::GuestReturned,
            EffectDispatchOutcome::GuestFailed => ReferenceDispatchPhase::GuestFailed,
        };
        Ok(())
    }

    fn record_effect_outcome(
        &self,
        effect: &EffectRequest,
        committed: &Self::CommitEvidence,
        outcome: &EffectOutcome,
    ) -> Result<Self::OutcomeEvidence, Self::Error> {
        if !committed.binding.matches(effect).map_err(|_| EffectPeerError::Integrity)? {
            return Err(EffectPeerError::PublicationConflict);
        }
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        if state.admission_profile != EffectAdmissionProfile::AdmissionRequired {
            return Err(EffectPeerError::Unsupported(
                "outcome recording requires the admission-required profile",
            ));
        }
        if committed.dispatch_generation != state.config.scope_generation {
            return Err(EffectPeerError::StaleScope);
        }
        let effect_id = reference_admission_key(&state.admissions, effect)?
            .ok_or(EffectPeerError::StepConflict)?;
        let outcome_digest = canonical_digest(outcome).map_err(|_| EffectPeerError::Integrity)?;
        let replay = {
            let admission =
                state.admissions.get_mut(&effect_id).ok_or(EffectPeerError::Integrity)?;
            let Some(metadata) = admission.commit else {
                return Err(EffectPeerError::StepConflict);
            };
            if admission.phase != ReferenceAdmissionPhase::Committed
                || committed.result != metadata.result
                || committed.domain_revision != metadata.domain_revision
                || committed.effect != effect_id
                || committed.binding != admission.registration.binding
                || committed.dispatch_generation != admission.dispatch_generation
            {
                return Err(EffectPeerError::StepConflict);
            }
            match admission.outcome.as_ref() {
                Some(existing) if existing == outcome => true,
                Some(_) => return Err(EffectPeerError::PublicationConflict),
                None => {
                    if admission.dispatch_phase != ReferenceDispatchPhase::GuestReturned {
                        return Err(EffectPeerError::StepConflict);
                    }
                    admission.outcome = Some(outcome.clone());
                    false
                }
            }
        };
        if !replay {
            let record = state.effects.get_mut(&effect_id).ok_or(EffectPeerError::Integrity)?;
            record.classification = JointEffectClassification::Committed;
            record.outcome_digest = Some(outcome_digest);
            record.tombstone_digest = None;
        }
        Ok(ReferenceEffectOutcomeEvidence { outcome: outcome.clone(), replay })
    }

    fn complete_effect(
        &self,
        effect: &EffectRequest,
        request: &Self::CompletionRequest,
    ) -> Result<Self::CompletionEvidence, Self::Error> {
        let mut state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        let effect_id = reference_admission_key(&state.admissions, effect)?
            .ok_or(EffectPeerError::StepConflict)?;
        let admission = state.admissions.get_mut(&effect_id).ok_or(EffectPeerError::Integrity)?;
        if admission.outcome.is_none() {
            return Err(EffectPeerError::StepConflict);
        }
        let replay = match admission.completion {
            Some(existing) if existing == *request => true,
            Some(_) => return Err(EffectPeerError::PublicationConflict),
            None => {
                admission.completion = Some(*request);
                false
            }
        };
        Ok(ReferenceEffectCompletionEvidence { result: request.result, replay })
    }

    fn query_effect(
        &self,
        effect: &EffectRequest,
    ) -> Result<Option<Self::QueryObservation>, Self::Error> {
        let state = self.state.lock().map_err(|_| EffectPeerError::Integrity)?;
        let Some(effect_id) = reference_admission_key(&state.admissions, effect)? else {
            return Ok(None);
        };
        let admission = state.admissions.get(&effect_id).ok_or(EffectPeerError::Integrity)?;
        let phase = if admission.completion.is_some() {
            ReferenceEffectQueryPhase::Completed
        } else if admission.outcome.is_some() {
            ReferenceEffectQueryPhase::OutcomeRecorded
        } else {
            match admission.phase {
                ReferenceAdmissionPhase::Registered => ReferenceEffectQueryPhase::Registered,
                ReferenceAdmissionPhase::Prepared => ReferenceEffectQueryPhase::Prepared,
                ReferenceAdmissionPhase::Committed => ReferenceEffectQueryPhase::Committed,
            }
        };
        Ok(Some(ReferenceEffectQueryObservation { phase, outcome: admission.outcome.clone() }))
    }
}

fn reference_admission_key(
    admissions: &BTreeMap<Identity, ReferenceAdmission>,
    effect: &EffectRequest,
) -> Result<Option<Identity>, EffectPeerError> {
    let mut matching_operation =
        admissions.iter().filter(|(_, admission)| admission.effect.operation == effect.operation);
    let Some((effect_id, admission)) = matching_operation.next() else {
        return Ok(None);
    };
    if matching_operation.next().is_some() {
        return Err(EffectPeerError::Integrity);
    }
    if admission.effect != *effect {
        return Err(EffectPeerError::PublicationConflict);
    }
    Ok(Some(*effect_id))
}

fn validate_reference_admission_binding(
    effect: &EffectRequest,
    request: &EffectPublicationRequest,
) -> Result<(), EffectPeerError> {
    if request.record.operation != effect.operation
        || request.source_epoch != effect.lease_epoch
        || request.key.source != effect.node
        || request.record.classification != JointEffectClassification::Registered
        || request.record.outcome_digest.is_some()
        || request.record.tombstone_digest.is_some()
    {
        return Err(EffectPeerError::InvalidRequest);
    }
    Ok(())
}

impl EffectPeer for ReferenceEffectPeer {
    fn publish(
        &self,
        request: EffectPublicationRequest,
    ) -> Result<EffectPublicationResult, EffectPeerError> {
        ReferenceEffectPeer::publish(self, request)
    }

    fn freeze(&self, request: EffectFreezeRequest) -> Result<EffectFreezeResult, EffectPeerError> {
        ReferenceEffectPeer::freeze(self, request)
    }

    fn thaw(&self, request: EffectThawRequest) -> Result<NexusThawReceipt, EffectPeerError> {
        ReferenceEffectPeer::thaw(self, request)
    }

    fn close(&self, request: EffectCloseRequest) -> Result<EffectCloseResult, EffectPeerError> {
        ReferenceEffectPeer::close(self, request)
    }

    fn query(&self) -> Result<EffectPeerQuery, EffectPeerError> {
        ReferenceEffectPeer::query(self)
    }

    fn rebind(
        &self,
        new_registry_instance: Identity,
    ) -> Result<EffectScopeVersion, EffectPeerError> {
        ReferenceEffectPeer::rebind(self, new_registry_instance)
    }
}

fn gate_open(session: Option<&FreezeSession>) -> bool {
    session.is_none_or(|session| session.phase == EffectPhase::Thawed)
}

fn resumed_frozen_registered_commit(
    session: Option<&FreezeSession>,
    existing: &ReferenceEffectRecord,
    proposed: &ReferenceEffectRecord,
) -> bool {
    let Some(session) = session else {
        return false;
    };
    session.phase == EffectPhase::Thawed
        && session.thaw.is_some()
        && session.frozen_effects.get(&existing.effect).is_some_and(|frozen| frozen == existing)
        && existing.classification == JointEffectClassification::Registered
        && proposed.classification == JointEffectClassification::Committed
        && proposed.effect == existing.effect
        && proposed.operation == existing.operation
        && proposed.domain == existing.domain
        && proposed.binding_generation == existing.binding_generation
        && existing.outcome_digest.is_none()
        && existing.tombstone_digest.is_none()
        && proposed.outcome_digest.is_some_and(|digest| digest != Digest::ZERO)
        && proposed.tombstone_digest.is_none()
}

fn initialize_close(
    state: &mut EffectPeerState,
    request: &EffectCloseRequest,
) -> Result<(), EffectPeerError> {
    let session = state.session.as_mut().ok_or(EffectPeerError::NotFrozen)?;
    let commit = request.commit.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)?;
    if let Some(existing) = session.commit {
        if existing != commit {
            return Err(EffectPeerError::StepConflict);
        }
        return Ok(());
    }
    let mut remaining = BTreeSet::new();
    let mut retained = BTreeSet::new();
    for record in state.effects.values() {
        match record.classification {
            JointEffectClassification::Committed => {
                remaining.insert(record.effect);
            }
            JointEffectClassification::ResolvedTombstone => {
                retained.insert(record.effect);
            }
            JointEffectClassification::Registered
            | JointEffectClassification::UnresolvedTombstone => {
                return Err(EffectPeerError::FreezeBlocked);
            }
            JointEffectClassification::Aborted => {}
        }
    }
    session.commit = Some(commit);
    session.close_remaining = remaining.into_iter().collect();
    session.retained_tombstones = retained.into_iter().collect();
    Ok(())
}

fn validate_publication_request(
    config: &EffectPeerConfig,
    request: &EffectPublicationRequest,
) -> Result<(), EffectPeerError> {
    validate_scope(
        config,
        request.key,
        request.registry_instance,
        request.scope_id,
        request.scope_generation,
        request.source_epoch,
        None,
    )?;
    let record = &request.record;
    if record.effect.is_zero()
        || record.operation.is_zero()
        || record.domain.is_zero()
        || record.binding_generation != request.scope_generation
        || !well_formed_effect(record)
    {
        return Err(EffectPeerError::InvalidRequest);
    }
    Ok(())
}

fn validate_freeze_request(
    config: &EffectPeerConfig,
    request: &EffectFreezeRequest,
) -> Result<(), EffectPeerError> {
    validate_scope(
        config,
        request.key,
        request.registry_instance,
        request.scope_id,
        request.scope_generation,
        request.key.expected_epoch,
        Some(request.freeze_generation),
    )?;
    if request.authority_epoch != config.authority_epoch {
        return Err(EffectPeerError::StaleEpoch);
    }
    Ok(())
}

fn validate_scope(
    config: &EffectPeerConfig,
    key: JointHandoffKey,
    registry_instance: Identity,
    scope_id: Identity,
    scope_generation: u64,
    source_epoch: LeaseEpoch,
    freeze_generation: Option<u64>,
) -> Result<(), EffectPeerError> {
    if key.handoff != config.key.handoff || key != config.key {
        return Err(EffectPeerError::HandoffMismatch);
    }
    if registry_instance != config.registry_instance {
        return Err(EffectPeerError::StaleRegistry);
    }
    if scope_id != config.scope_id || scope_generation != config.scope_generation {
        return Err(EffectPeerError::StaleScope);
    }
    if source_epoch != config.key.expected_epoch {
        return Err(EffectPeerError::StaleEpoch);
    }
    if freeze_generation.is_some_and(|value| value != config.freeze_generation) {
        return Err(EffectPeerError::StaleFreezeGeneration);
    }
    Ok(())
}

fn validated_intent(
    intent: &PrepareIntentReceipt,
    key: JointHandoffKey,
    expected_issuer: ReceiptIssuerIdentity,
) -> Result<ReceiptRef, EffectPeerError> {
    if intent.key != key
        || intent.header.kind != ReceiptKind::PrepareIntent
        || !intent.header.version.is_supported()
        || intent.header.previous_digest.is_some()
        || intent.header.sequence == 0
        || intent.ownership_service != intent.header.issuer
        || intent.service_incarnation != intent.header.issuer_incarnation
        || intent.reservation.is_zero()
        || intent.request_digest == Digest::ZERO
        || !well_formed_issuer(issuer_from_header(&intent.header))
        || issuer_from_header(&intent.header) != expected_issuer
    {
        return Err(EffectPeerError::InvalidRequest);
    }
    intent.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)
}

fn valid_abort_authority(
    session: &FreezeSession,
    receipt: &OwnershipAbortReceipt,
) -> Result<bool, EffectPeerError> {
    let reference = receipt.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)?;
    let basis_is_intent = receipt.basis == session.intent;
    let basis_is_prepared = receipt.basis.kind == ReceiptKind::OwnershipPrepared
        && same_lineage(receipt.basis, session.ownership_issuer)
        && receipt.basis.handoff == session.result.token.key.handoff
        && receipt.basis.sequence > session.intent.sequence;
    Ok(receipt.key == session.result.token.key
        && receipt.header.kind == ReceiptKind::OwnershipAbort
        && receipt.header.version.is_supported()
        && receipt.reservation == session.result.token.reservation
        && same_lineage(reference, session.ownership_issuer)
        && (basis_is_intent || basis_is_prepared)
        && receipt.basis_revision == receipt.basis.sequence
        && receipt.header.previous_digest == Some(receipt.basis.digest)
        && receipt.header.sequence == receipt.decision_sequence
        && receipt.decision_sequence > receipt.basis_revision
        && receipt.non_equivocation_root != Digest::ZERO)
}

fn valid_commit_authority(
    session: &FreezeSession,
    receipt: &OwnershipCommitReceipt,
) -> Result<bool, EffectPeerError> {
    let reference = receipt.receipt_ref().map_err(|_| EffectPeerError::InvalidRequest)?;
    Ok(receipt.key == session.result.token.key
        && receipt.header.kind == ReceiptKind::OwnershipCommit
        && receipt.header.version.is_supported()
        && receipt.reservation == session.result.token.reservation
        && same_lineage(reference, session.ownership_issuer)
        && receipt.prepared.kind == ReceiptKind::OwnershipPrepared
        && same_lineage(receipt.prepared, session.ownership_issuer)
        && receipt.prepared.handoff == session.result.token.key.handoff
        && receipt.prepared.sequence > session.intent.sequence
        && receipt.prepared_revision == receipt.prepared.sequence
        && receipt.header.previous_digest == Some(receipt.prepared.digest)
        && receipt.header.sequence == receipt.decision_sequence
        && receipt.decision_sequence > receipt.prepared_revision
        && receipt.non_equivocation_root != Digest::ZERO)
}

fn require_token(session: &FreezeSession, token: EffectFreezeToken) -> Result<(), EffectPeerError> {
    if session.result.token == token { Ok(()) } else { Err(EffectPeerError::TokenMismatch) }
}

fn same_lineage(reference: ReceiptRef, issuer: ReceiptIssuerIdentity) -> bool {
    reference.version.is_supported()
        && reference.issuer == issuer.issuer
        && reference.issuer_incarnation == issuer.issuer_incarnation
        && reference.key_id == issuer.key_id
        && reference.log_id == issuer.log_id
        && reference.sequence > 0
        && reference.digest != Digest::ZERO
}

fn next_header(
    state: &mut EffectPeerState,
    kind: ReceiptKind,
    previous_digest: Option<Digest>,
) -> Result<ReceiptHeader, EffectPeerError> {
    state.next_sequence =
        state.next_sequence.checked_add(1).ok_or(EffectPeerError::InvalidRequest)?;
    Ok(ReceiptHeader {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        issuer: state.config.issuer.issuer,
        issuer_incarnation: state.config.issuer.issuer_incarnation,
        key_id: state.config.issuer.key_id,
        log_id: state.config.issuer.log_id,
        sequence: state.next_sequence,
        previous_digest,
    })
}

fn issuer_from_header(header: &ReceiptHeader) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: header.issuer,
        issuer_incarnation: header.issuer_incarnation,
        key_id: header.key_id,
        log_id: header.log_id,
    }
}

fn scope(config: &EffectPeerConfig) -> EffectScopeVersion {
    EffectScopeVersion {
        registry_instance: config.registry_instance,
        scope_id: config.scope_id,
        scope_generation: config.scope_generation,
        authority_epoch: config.authority_epoch,
        freeze_generation: config.freeze_generation,
    }
}

fn request_digest(request: &impl Serialize) -> Result<Digest, EffectPeerError> {
    canonical_digest(request).map_err(|_| EffectPeerError::InvalidRequest)
}

fn conformance_key(
    key: JointHandoffKey,
) -> Result<visa_conformance::JointHandoffKey, EffectPeerError> {
    let value = serde_json::to_value(key).map_err(|_| EffectPeerError::Integrity)?;
    serde_json::from_value(value).map_err(|_| EffectPeerError::Integrity)
}

fn well_formed_config(config: EffectPeerConfig) -> bool {
    config.key.is_well_formed()
        && well_formed_issuer(config.issuer)
        && well_formed_issuer(config.ownership_issuer)
        && config.issuer != config.ownership_issuer
        && !config.registry_instance.is_zero()
        && !config.scope_id.is_zero()
        && config.scope_generation > 0
        && config.authority_epoch > 0
        && config.freeze_generation > 0
        && config.domain_bindings_digest != Digest::ZERO
}

fn well_formed_issuer(issuer: ReceiptIssuerIdentity) -> bool {
    !issuer.issuer.is_zero()
        && !issuer.issuer_incarnation.is_zero()
        && !issuer.key_id.is_zero()
        && !issuer.log_id.is_zero()
}

fn well_formed_effect(record: &ReferenceEffectRecord) -> bool {
    let nonzero = |digest: Option<Digest>| digest.is_some_and(|value| value != Digest::ZERO);
    match record.classification {
        JointEffectClassification::Registered | JointEffectClassification::Aborted => {
            record.outcome_digest.is_none() && record.tombstone_digest.is_none()
        }
        JointEffectClassification::Committed => {
            nonzero(record.outcome_digest) && record.tombstone_digest.is_none()
        }
        JointEffectClassification::ResolvedTombstone => {
            nonzero(record.outcome_digest) && nonzero(record.tombstone_digest)
        }
        JointEffectClassification::UnresolvedTombstone => {
            record.outcome_digest.is_none() && nonzero(record.tombstone_digest)
        }
    }
}
