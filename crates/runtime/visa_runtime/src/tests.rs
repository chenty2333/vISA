extern crate std;

use alloc::{vec, vec::Vec};
use core::cell::Cell;

use contract_core::{
    ActivationStatus, AuthorityGrant, AuthorityStatus, BindingReceipt, CONTRACT_VERSION,
    CanonicalState, CleanupStatus, Digest, EffectKind, EffectOutcome, EffectRequest, EffectResult,
    EntityRef, EvidenceKind, EvidenceRef, Generation, HandoffPhase, IdempotencyKey, Identity,
    JournalEntry, JournalPosition, KeyValueClaim, LeaseEpoch, LogicalDurationNanos, NodeIdentity,
    OperationRecord, ResourceClaims, Rights, TimerClaim, TimerClock, TimerDisposition, TimerStatus,
};
use substrate_api::{
    ActivationBundle, AuthorityPolicy, AuthorityPort, BindingPort, BindingRequest, CommitBundle,
    JournalPort, KvPort, LeasePort, LeaseRecord, LeaseTransition, OperationObservation,
    PreparedLeaseTransitions, ProfilePort, ProviderError, ProviderErrorKind,
    ReauthorizationRequest, TimerObservation, TimerPort, TimerRecovery,
};

use super::*;

const COMPONENT: u8 = 1;
const TIMER: u8 = 2;
const KV: u8 = 3;
const SOURCE: u8 = 4;
const DESTINATION: u8 = 5;
const HANDOFF_AUTHORITY: u8 = 10;
const TIMER_AUTHORITY: u8 = 11;
const KV_AUTHORITY: u8 = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReauthorizationMode {
    Exact,
    Broader,
    Insufficient,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    JournalPrepared,
    JournalResolved,
    JournalOther,
    Effect,
    LeasePrepared,
    LeaseCommitted,
}

struct MockProvider {
    entries: Vec<JournalEntry>,
    operations: Vec<OperationRecord>,
    leases: Vec<LeaseRecord>,
    bindings: Vec<BindingReceipt>,
    pending_authorities: Vec<(Identity, AuthorityGrant)>,
    active_authorities: Vec<EntityRef>,
    actions: Vec<Action>,
    fail_append_once: Option<JournalPosition>,
    lost_append_once: Option<JournalPosition>,
    fail_activation_once: bool,
    lost_activation_once: bool,
    partial_activation_once: bool,
    fail_bundle_once: bool,
    lost_bundle_once: Cell<bool>,
    partial_bundle_once: Cell<bool>,
    effect_lost_ack_once: bool,
    effect_error_once: Option<ProviderError>,
    next_effect_outcome: Option<EffectOutcome>,
    reconciliation_truth: Option<EffectOutcome>,
    observe_observation: Option<TimerObservation>,
    suspend_observation: Option<TimerObservation>,
    suspended_timers: Vec<Identity>,
    resume_calls: usize,
    restore_timer_calls: Vec<(Identity, TimerRecovery)>,
    reauthorization_mode: ReauthorizationMode,
    fail_reauthorization_call: Option<usize>,
    reauthorization_calls: usize,
    attenuation_calls: usize,
    binding_prepare_calls: usize,
    fail_binding_call: Option<usize>,
    binding_cleanup_calls: usize,
    binding_destructive_cleanups: usize,
    lease_prepare_calls: usize,
    bundle_calls: usize,
}

impl Default for MockProvider {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            operations: Vec::new(),
            leases: Vec::new(),
            bindings: Vec::new(),
            pending_authorities: Vec::new(),
            active_authorities: Vec::new(),
            actions: Vec::new(),
            fail_append_once: None,
            lost_append_once: None,
            fail_activation_once: false,
            lost_activation_once: false,
            partial_activation_once: false,
            fail_bundle_once: false,
            lost_bundle_once: Cell::new(false),
            partial_bundle_once: Cell::new(false),
            effect_lost_ack_once: false,
            effect_error_once: None,
            next_effect_outcome: None,
            reconciliation_truth: None,
            observe_observation: None,
            suspend_observation: None,
            suspended_timers: Vec::new(),
            resume_calls: 0,
            restore_timer_calls: Vec::new(),
            reauthorization_mode: ReauthorizationMode::Exact,
            fail_reauthorization_call: None,
            reauthorization_calls: 0,
            attenuation_calls: 0,
            binding_prepare_calls: 0,
            fail_binding_call: None,
            binding_cleanup_calls: 0,
            binding_destructive_cleanups: 0,
            lease_prepare_calls: 0,
            bundle_calls: 0,
        }
    }
}

impl MockProvider {
    fn storage_error() -> ProviderError {
        ProviderError::new(ProviderErrorKind::Storage, true)
    }

    fn unknown_error() -> ProviderError {
        ProviderError::new(ProviderErrorKind::OutcomeUnknown, true)
    }

    fn store_entry(&mut self, entry: &JournalEntry) -> Result<(), ProviderError> {
        if let Some(existing) = self.entries.iter().find(|item| item.position == entry.position) {
            return if existing == entry {
                Ok(())
            } else {
                Err(ProviderError::new(ProviderErrorKind::Conflict, false))
            };
        }
        let expected = self
            .entries
            .last()
            .map_or(JournalPosition(1), |item| JournalPosition(item.position.0 + 1));
        if entry.position != expected {
            return Err(ProviderError::new(ProviderErrorKind::Conflict, false));
        }

        match &entry.event.kind {
            contract_core::EventKind::EffectPrepared { request } => {
                self.actions.push(Action::JournalPrepared);
                self.operations.push(OperationRecord::prepared(request.clone()));
            }
            contract_core::EventKind::EffectResolved { operation, outcome }
            | contract_core::EventKind::EffectReconciled { operation, outcome }
            | contract_core::EventKind::HandoffCommitted { operation, outcome, .. } => {
                self.actions.push(Action::JournalResolved);
                let record = self
                    .operations
                    .iter_mut()
                    .find(|record| record.request.operation == *operation)
                    .ok_or(ProviderError::new(ProviderErrorKind::NotFound, false))?;
                record.outcome = Some(outcome.clone());
            }
            contract_core::EventKind::OperationCleaned { operation, .. } => {
                self.actions.push(Action::JournalOther);
                let record = self
                    .operations
                    .iter_mut()
                    .find(|record| record.request.operation == *operation)
                    .ok_or(ProviderError::new(ProviderErrorKind::NotFound, false))?;
                record.cleanup = CleanupStatus::Cleaned;
            }
            _ => self.actions.push(Action::JournalOther),
        }
        self.entries.push(entry.clone());
        Ok(())
    }

    fn execute_outcome(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        self.actions.push(Action::Effect);
        if let Some(error) = self.effect_error_once.take() {
            return Err(error);
        }
        let outcome =
            self.next_effect_outcome.take().unwrap_or_else(|| successful_outcome(request));
        let record = self
            .operations
            .iter_mut()
            .find(|record| record.request.operation == request.operation)
            .ok_or(ProviderError::new(ProviderErrorKind::NotFound, false))?;
        record.outcome = Some(outcome.clone());
        if self.effect_lost_ack_once {
            self.effect_lost_ack_once = false;
            Err(Self::unknown_error())
        } else {
            Ok(outcome)
        }
    }
}

impl JournalPort for MockProvider {
    fn append_entry(&mut self, entry: &JournalEntry) -> Result<(), ProviderError> {
        if self.fail_append_once == Some(entry.position) {
            self.fail_append_once = None;
            return Err(Self::storage_error());
        }
        self.store_entry(entry)?;
        if self.lost_append_once == Some(entry.position) {
            self.lost_append_once = None;
            Err(Self::unknown_error())
        } else {
            Ok(())
        }
    }

    fn commit_activation(&mut self, bundle: &ActivationBundle) -> Result<(), ProviderError> {
        if self.fail_activation_once {
            self.fail_activation_once = false;
            return Err(Self::storage_error());
        }
        if bundle.initial_leases.iter().any(|expected| {
            self.leases
                .iter()
                .any(|existing| existing.resource == expected.resource && existing != expected)
        }) {
            return Err(ProviderError::new(ProviderErrorKind::Conflict, false));
        }
        self.store_entry(&bundle.entry)?;
        let count = if self.partial_activation_once {
            self.partial_activation_once = false;
            1
        } else {
            bundle.initial_leases.len()
        };
        for lease in bundle.initial_leases.iter().take(count) {
            if !self.leases.iter().any(|existing| existing.resource == lease.resource) {
                self.leases.push(*lease);
            }
        }
        if count != bundle.initial_leases.len() || self.lost_activation_once {
            self.lost_activation_once = false;
            Err(Self::unknown_error())
        } else {
            Ok(())
        }
    }

    fn commit_bundle(&mut self, bundle: &CommitBundle) -> Result<(), ProviderError> {
        self.bundle_calls += 1;
        if self.fail_bundle_once {
            self.fail_bundle_once = false;
            return Err(Self::storage_error());
        }
        for transition in &bundle.lease_transitions {
            let current = self
                .leases
                .iter()
                .find(|lease| lease.resource == transition.resource)
                .copied()
                .ok_or(ProviderError::new(ProviderErrorKind::NotFound, false))?;
            if current.owner != transition.expected_owner
                || current.epoch != transition.expected_epoch
            {
                return Err(ProviderError::new(ProviderErrorKind::StaleEpoch, false));
            }
        }
        let snapshot = match bundle.entry.event.kind {
            contract_core::EventKind::HandoffCommitted { snapshot, .. } => snapshot,
            _ => return Err(ProviderError::new(ProviderErrorKind::InvalidRequest, false)),
        };
        if bundle.final_authorities.iter().any(|authority| {
            !self
                .pending_authorities
                .iter()
                .any(|(candidate, grant)| *candidate == snapshot && grant.authority == *authority)
        }) {
            return Err(ProviderError::new(ProviderErrorKind::NotFound, false));
        }
        self.store_entry(&bundle.entry)?;
        let partial = self.partial_bundle_once.replace(false);
        let transition_count = if partial { 1 } else { bundle.lease_transitions.len() };
        for transition in bundle.lease_transitions.iter().take(transition_count) {
            let lease = self
                .leases
                .iter_mut()
                .find(|lease| lease.resource == transition.resource)
                .expect("validated lease exists");
            lease.owner = transition.next_owner;
            lease.epoch = transition.next_epoch;
        }
        if partial {
            return Err(Self::unknown_error());
        }
        for authority in &bundle.final_authorities {
            if !self.active_authorities.contains(authority) {
                self.active_authorities.push(*authority);
            }
        }
        self.pending_authorities.retain(|(candidate, _)| *candidate != snapshot);
        self.actions.push(Action::LeaseCommitted);
        if self.lost_bundle_once.replace(false) { Err(Self::unknown_error()) } else { Ok(()) }
    }

    fn entry(&self, position: JournalPosition) -> Result<Option<JournalEntry>, ProviderError> {
        Ok(self.entries.iter().find(|entry| entry.position == position).cloned())
    }

    fn operation(
        &self,
        operation: Identity,
    ) -> Result<Option<OperationObservation>, ProviderError> {
        Ok(self
            .operations
            .iter()
            .find(|record| record.request.operation == operation)
            .cloned()
            .map(|record| OperationObservation { record }))
    }

    fn idempotency(
        &self,
        key: IdempotencyKey,
    ) -> Result<Option<OperationObservation>, ProviderError> {
        Ok(self
            .operations
            .iter()
            .find(|record| record.request.idempotency_key == key)
            .cloned()
            .map(|record| OperationObservation { record }))
    }

    fn replay_from(
        &self,
        after: Option<JournalPosition>,
    ) -> Result<Vec<JournalEntry>, ProviderError> {
        let base = after.unwrap_or(JournalPosition::ORIGIN);
        Ok(self.entries.iter().filter(|entry| entry.position.0 > base.0).cloned().collect())
    }
}

impl KvPort for MockProvider {
    fn read(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        self.execute_outcome(request)
    }

    fn compare_and_set(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        self.execute_outcome(request)
    }

    fn query_operation(
        &self,
        operation: Identity,
        _idempotency_key: IdempotencyKey,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        if let Some(outcome) = &self.reconciliation_truth {
            return Ok(Some(outcome.clone()));
        }
        Ok(self
            .operations
            .iter()
            .find(|record| record.request.operation == operation)
            .and_then(|record| record.outcome.clone()))
    }
}

impl ProfilePort for MockProvider {
    fn execute_profile(
        &mut self,
        request: &EffectRequest,
        _extension: &contract_core::Extension,
    ) -> Result<EffectOutcome, ProviderError> {
        let outcome = self
            .next_effect_outcome
            .clone()
            .ok_or_else(|| ProviderError::new(ProviderErrorKind::Unsupported, false))?;
        if let Some(operation) =
            self.operations.iter_mut().find(|record| record.request.operation == request.operation)
        {
            operation.outcome = Some(outcome.clone());
        }
        Ok(outcome)
    }

    fn query_profile_operation(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<Option<EffectOutcome>, ProviderError> {
        Ok(self
            .operations
            .iter()
            .find(|record| {
                record.request.operation == operation
                    && record.request.idempotency_key == idempotency_key
            })
            .and_then(|record| record.outcome.clone())
            .or_else(|| self.reconciliation_truth.clone()))
    }

    fn cleanup_profile_operation(&mut self, _request: &EffectRequest) -> Result<(), ProviderError> {
        Ok(())
    }
}

impl TimerPort for MockProvider {
    fn arm(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        self.execute_outcome(request)
    }

    fn cancel(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        self.execute_outcome(request)
    }

    fn restore_timer_binding(
        &mut self,
        request: &EffectRequest,
        recovery: TimerRecovery,
    ) -> Result<(), ProviderError> {
        self.restore_timer_calls.push((request.operation, recovery));
        match recovery {
            TimerRecovery::Running { .. } => {
                self.suspended_timers.retain(|operation| *operation != request.operation);
            }
            TimerRecovery::Suspended { .. } => {
                if !self.suspended_timers.contains(&request.operation) {
                    self.suspended_timers.push(request.operation);
                }
            }
        }
        Ok(())
    }

    fn observe(&mut self, arm_operation: Identity) -> Result<TimerObservation, ProviderError> {
        if let Some(observation) = self.observe_observation.take() {
            return Ok(observation);
        }
        let record = self
            .operations
            .iter()
            .find(|record| record.request.operation == arm_operation)
            .ok_or(ProviderError::new(ProviderErrorKind::NotFound, false))?;
        Ok(match (&record.request.kind, &record.outcome) {
            (EffectKind::TimerArm { remaining }, None)
            | (
                EffectKind::TimerArm { remaining },
                Some(EffectOutcome::Succeeded { result: EffectResult::TimerArmed { .. }, .. }),
            ) => TimerObservation::Pending(*remaining),
            (_, Some(EffectOutcome::Cancelled { .. })) => {
                TimerObservation::Cancelled { evidence: evidence(83, EvidenceKind::EffectOutcome) }
            }
            _ => {
                TimerObservation::Completed { evidence: evidence(84, EvidenceKind::EffectOutcome) }
            }
        })
    }

    fn suspend_timer(
        &mut self,
        arm_operation: Identity,
    ) -> Result<TimerObservation, ProviderError> {
        let observation = match self.suspend_observation.take() {
            Some(observation) => observation,
            None => self.observe(arm_operation)?,
        };
        if matches!(observation, TimerObservation::Pending(_))
            && !self.suspended_timers.contains(&arm_operation)
        {
            self.suspended_timers.push(arm_operation);
        }
        Ok(observation)
    }

    fn resume_suspended(&mut self, arm_operation: Identity) -> Result<(), ProviderError> {
        self.resume_calls += 1;
        if let Some(index) =
            self.suspended_timers.iter().position(|operation| *operation == arm_operation)
        {
            self.suspended_timers.remove(index);
        }
        Ok(())
    }

    fn cleanup_timer(&mut self, _arm_operation: Identity) -> Result<(), ProviderError> {
        Ok(())
    }
}

impl AuthorityPort for MockProvider {
    fn install_policy(&mut self, _policy: AuthorityPolicy) -> Result<(), ProviderError> {
        Ok(())
    }

    fn install_grant(&mut self, _grant: &AuthorityGrant) -> Result<(), ProviderError> {
        Ok(())
    }

    fn attenuate(
        &mut self,
        _handoff: Identity,
        snapshot: Identity,
        _parent: EntityRef,
        derived: &AuthorityGrant,
    ) -> Result<AuthorityGrant, ProviderError> {
        self.attenuation_calls += 1;
        self.pending_authorities.push((snapshot, derived.clone()));
        Ok(derived.clone())
    }

    fn revoke(&mut self, _authority: EntityRef) -> Result<(), ProviderError> {
        Ok(())
    }

    fn reauthorize(
        &mut self,
        request: ReauthorizationRequest,
    ) -> Result<AuthorityGrant, ProviderError> {
        self.reauthorization_calls += 1;
        if self.fail_reauthorization_call == Some(self.reauthorization_calls) {
            return Err(Self::storage_error());
        }
        if self.reauthorization_mode == ReauthorizationMode::Revoked {
            return Err(ProviderError::new(ProviderErrorKind::Revoked, false));
        }
        let rights = match self.reauthorization_mode {
            ReauthorizationMode::Exact => request.required_rights,
            ReauthorizationMode::Broader => {
                request.required_rights.union(extra_right(request.required_rights))
            }
            ReauthorizationMode::Insufficient => Rights::NONE,
            ReauthorizationMode::Revoked => unreachable!(),
        };
        let grant = AuthorityGrant {
            authority: request.destination_authority,
            parent: Some(request.source_authority),
            subject: request.destination_subject,
            resource: request.resource,
            rights,
            status: AuthorityStatus::Active,
        };
        self.pending_authorities.push((request.snapshot, grant.clone()));
        Ok(grant)
    }

    fn authorize_effect(
        &self,
        _request: &EffectRequest,
        required_rights: Rights,
    ) -> Result<Rights, ProviderError> {
        Ok(required_rights)
    }

    fn revoke_prepared(&mut self, snapshot: Identity) -> Result<(), ProviderError> {
        self.pending_authorities.retain(|(candidate, _)| *candidate != snapshot);
        Ok(())
    }
}

impl LeasePort for MockProvider {
    fn initialize_lease(&mut self, lease: LeaseRecord) -> Result<(), ProviderError> {
        if let Some(existing) =
            self.leases.iter().find(|existing| existing.resource == lease.resource)
        {
            return if *existing == lease {
                Ok(())
            } else {
                Err(ProviderError::new(ProviderErrorKind::Conflict, false))
            };
        }
        self.leases.push(lease);
        Ok(())
    }

    fn prepare_transitions(
        &mut self,
        request: &EffectRequest,
        resources: &[EntityRef],
    ) -> Result<PreparedLeaseTransitions, ProviderError> {
        self.lease_prepare_calls += 1;
        self.actions.push(Action::LeasePrepared);
        let EffectKind::LeaseCommit { destination, expected_epoch, next_epoch, .. } = request.kind
        else {
            return Err(ProviderError::new(ProviderErrorKind::InvalidRequest, false));
        };
        let mut transitions = Vec::new();
        for resource in resources {
            let lease = self
                .leases
                .iter()
                .find(|lease| lease.resource == *resource)
                .copied()
                .ok_or(ProviderError::new(ProviderErrorKind::NotFound, false))?;
            if lease.epoch != expected_epoch {
                return Err(ProviderError::new(ProviderErrorKind::StaleEpoch, false));
            }
            transitions.push(LeaseTransition {
                resource: *resource,
                expected_owner: lease.owner,
                next_owner: destination,
                expected_epoch,
                next_epoch,
            });
        }
        Ok(PreparedLeaseTransitions {
            transitions,
            outcome: EffectOutcome::Succeeded {
                result: EffectResult::LeaseAdvanced {
                    owner: destination,
                    epoch: next_epoch,
                    source_fence: evidence(80, EvidenceKind::SourceFence),
                },
                evidence: evidence(81, EvidenceKind::LeaseCommit),
            },
        })
    }

    fn current_lease(&self, resource: EntityRef) -> Result<Option<LeaseRecord>, ProviderError> {
        Ok(self.leases.iter().find(|lease| lease.resource == resource).copied())
    }

    fn check_lease(
        &self,
        resource: EntityRef,
        owner: NodeIdentity,
        epoch: LeaseEpoch,
    ) -> Result<(), ProviderError> {
        let lease = self
            .leases
            .iter()
            .find(|lease| lease.resource == resource)
            .ok_or(ProviderError::new(ProviderErrorKind::NotFound, false))?;
        if lease.owner != owner || lease.epoch != epoch {
            Err(ProviderError::new(ProviderErrorKind::StaleEpoch, false))
        } else {
            Ok(())
        }
    }
}

impl BindingPort for MockProvider {
    fn prepare_binding(
        &mut self,
        request: BindingRequest,
    ) -> Result<BindingReceipt, ProviderError> {
        self.binding_prepare_calls += 1;
        if self.fail_binding_call == Some(self.binding_prepare_calls) {
            return Err(Self::storage_error());
        }
        if let Some(existing) = self
            .bindings
            .iter()
            .find(|receipt| receipt.snapshot == request.snapshot && receipt.claim == request.claim)
        {
            return Ok(existing.clone());
        }
        self.check_lease(request.claim, request.expected_owner, request.expected_epoch)?;
        let receipt = BindingReceipt {
            handoff: request.handoff,
            snapshot: request.snapshot,
            claim: request.claim,
            binding: entity(request.claim.identity.0[15].saturating_add(100)),
            node: request.candidate_owner,
            authority: request.authority,
            exposed_rights: request.exposed_rights,
            lease_epoch: request.candidate_epoch,
            evidence: evidence(
                request.claim.identity.0[15].saturating_add(120),
                EvidenceKind::Binding,
            ),
        };
        self.bindings.push(receipt.clone());
        Ok(receipt)
    }

    fn binding(
        &self,
        snapshot: Identity,
        claim: EntityRef,
    ) -> Result<Option<BindingReceipt>, ProviderError> {
        Ok(self
            .bindings
            .iter()
            .find(|receipt| receipt.snapshot == snapshot && receipt.claim == claim)
            .cloned())
    }

    fn cleanup_binding(
        &mut self,
        snapshot: Identity,
        claim: EntityRef,
    ) -> Result<(), ProviderError> {
        self.binding_cleanup_calls += 1;
        if let Some(index) = self
            .bindings
            .iter()
            .position(|receipt| receipt.snapshot == snapshot && receipt.claim == claim)
        {
            self.bindings.remove(index);
            self.binding_destructive_cleanups += 1;
        }
        Ok(())
    }
}

#[test]
fn canonical_encoding_is_pinned_and_deterministic() {
    let value = identity(1);
    assert_eq!(CANONICAL_ENCODING, "postcard-1.1.3");
    assert_eq!(DIGEST_ALGORITHM, "sha-256");
    assert_eq!(canonical_bytes(&value).unwrap(), value.0);
    assert_eq!(
        canonical_digest(&value).unwrap(),
        Digest::from_bytes([
            0x7c, 0x3c, 0xcd, 0x10, 0xbb, 0x7e, 0xc3, 0x7b, 0x46, 0xd3, 0x79, 0x26, 0xae, 0x62,
            0x74, 0x26, 0x7f, 0x00, 0x7a, 0x34, 0xae, 0xaf, 0x15, 0xc8, 0x82, 0xa7, 0x15, 0xa7,
            0xf3, 0x30, 0x05, 0x29,
        ])
    );
}

#[test]
fn activation_bundle_is_atomic_and_lost_ack_requires_both_leases() {
    let initial = initial_state(node(SOURCE));
    let provider = MockProvider { fail_activation_once: true, ..MockProvider::default() };
    let mut coordinator = Coordinator::recover(initial.clone(), provider).unwrap();
    assert!(matches!(
        coordinator.activate(identity(20), entity(HANDOFF_AUTHORITY), LeaseEpoch(1)),
        Err(RuntimeError::Provider(ProviderError { kind: ProviderErrorKind::Storage, .. }))
    ));
    assert_eq!(coordinator.state().phase, HandoffPhase::Dormant);
    assert!(coordinator.provider().entries.is_empty());
    assert!(coordinator.provider().leases.is_empty());

    let provider = MockProvider { lost_activation_once: true, ..MockProvider::default() };
    let mut coordinator = Coordinator::recover(initial.clone(), provider).unwrap();
    coordinator.activate(identity(20), entity(HANDOFF_AUTHORITY), LeaseEpoch(1)).unwrap();
    assert_eq!(coordinator.state().phase, HandoffPhase::Running);
    assert_eq!(coordinator.provider().leases.len(), 2);

    let provider = MockProvider { partial_activation_once: true, ..MockProvider::default() };
    let mut coordinator = Coordinator::recover(initial, provider).unwrap();
    assert!(matches!(
        coordinator.activate(identity(20), entity(HANDOFF_AUTHORITY), LeaseEpoch(1)),
        Err(RuntimeError::JournalOutcomeUnknown { .. })
    ));
    assert_eq!(coordinator.state().phase, HandoffPhase::Dormant);
}

#[test]
fn handoff_commit_facade_rejects_before_destination_preparation() {
    let mut coordinator = activated(MockProvider::default());
    assert_eq!(
        coordinator.commit_handoff(
            identity(30),
            identity(31),
            IdempotencyKey::from_bytes([31; 16]),
        ),
        Err(RuntimeError::SnapshotUnavailable)
    );
}

#[test]
fn rejected_preflight_does_not_change_state_or_journal() {
    let mut coordinator = activated(MockProvider::default());
    let before = coordinator.state_digest().unwrap();
    let entries = coordinator.provider().entries.len();
    let mut request = kv_request(30, LeaseEpoch(99));
    request.node = node(SOURCE);

    assert!(matches!(
        coordinator.effect(identity(31), request),
        Err(RuntimeError::Rejected(contract_core::Rejection::LeaseEpochMismatch { .. }))
    ));
    assert_eq!(coordinator.state_digest().unwrap(), before);
    assert_eq!(coordinator.provider().entries.len(), entries);
}

#[test]
fn effect_intent_is_durable_before_provider_execution() {
    let mut coordinator = activated(MockProvider::default());
    coordinator.effect(identity(31), kv_request(30, LeaseEpoch(1))).unwrap();

    let actions = &coordinator.provider().actions;
    let prepared = actions.iter().position(|action| *action == Action::JournalPrepared).unwrap();
    let effect = actions.iter().position(|action| *action == Action::Effect).unwrap();
    let resolved = actions.iter().rposition(|action| *action == Action::JournalResolved).unwrap();
    assert!(prepared < effect && effect < resolved);
}

#[test]
fn recovered_durable_intent_retries_through_the_idempotent_provider_path() {
    let initial = initial_state(node(SOURCE));
    let coordinator = activated(MockProvider::default());
    let request = kv_request(30, LeaseEpoch(1));
    let contract_core::Decision::Execute { intent, .. } = semantic_core::preflight(
        coordinator.state(),
        &contract_core::Command::new(
            identity(31),
            contract_core::CommandKind::RequestEffect(request.clone()),
        ),
    ) else {
        panic!("effect must preflight to an intent");
    };
    let next = semantic_core::apply(coordinator.state(), &intent).unwrap().into_state();
    let entry = JournalEntry {
        version: CONTRACT_VERSION,
        position: JournalPosition(2),
        input_state: coordinator.state_digest().unwrap(),
        output_state: state_digest(&next).unwrap(),
        event: intent,
    };
    let mut provider = coordinator.into_provider();
    provider.store_entry(&entry).unwrap();

    let mut recovered = Coordinator::recover(initial, provider).unwrap();
    recovered.effect(identity(32), request).unwrap();
    assert_eq!(
        recovered.provider().actions.iter().filter(|action| **action == Action::Effect).count(),
        1
    );
    assert!(matches!(
        recovered.state().operations[0].outcome,
        Some(EffectOutcome::Succeeded { .. })
    ));
}

#[test]
fn crash_recovery_replays_to_the_same_digest() {
    let initial = initial_state(node(SOURCE));
    let mut coordinator = Coordinator::recover(initial.clone(), MockProvider::default()).unwrap();
    coordinator.activate(identity(20), entity(HANDOFF_AUTHORITY), LeaseEpoch(1)).unwrap();
    coordinator.effect(identity(31), kv_request(30, LeaseEpoch(1))).unwrap();
    let expected = coordinator.state_digest().unwrap();

    let recovered = Coordinator::recover(initial, coordinator.into_provider()).unwrap();
    assert_eq!(recovered.state_digest().unwrap(), expected);
    assert_eq!(recovered.state().operations.len(), 1);
}

#[test]
fn journal_resolution_failure_recovers_from_operation_truth() {
    let provider =
        MockProvider { fail_append_once: Some(JournalPosition(3)), ..MockProvider::default() };
    let mut coordinator = activated(provider);
    let request = kv_request(30, LeaseEpoch(1));

    assert!(matches!(
        coordinator.effect(identity(31), request.clone()),
        Err(RuntimeError::Provider(ProviderError { kind: ProviderErrorKind::Storage, .. }))
    ));
    assert!(coordinator.state().operations[0].outcome.is_none());
    let effects =
        coordinator.provider().actions.iter().filter(|action| **action == Action::Effect).count();
    coordinator.effect(identity(32), request).unwrap();
    assert_eq!(
        coordinator.provider().actions.iter().filter(|action| **action == Action::Effect).count(),
        effects
    );
    assert!(matches!(
        coordinator.state().operations[0].outcome,
        Some(EffectOutcome::Succeeded { .. })
    ));
}

#[test]
fn retryable_provider_failure_keeps_the_intent_open_for_the_same_operation() {
    let provider = MockProvider {
        effect_error_once: Some(ProviderError::new(ProviderErrorKind::Unavailable, true)),
        ..MockProvider::default()
    };
    let mut coordinator = activated(provider);
    let request = kv_request(30, LeaseEpoch(1));

    assert!(matches!(
        coordinator.effect(identity(31), request.clone()),
        Err(RuntimeError::Provider(ProviderError {
            kind: ProviderErrorKind::Unavailable,
            retryable: true,
        }))
    ));
    assert_eq!(coordinator.state().operations.len(), 1);
    assert!(coordinator.state().operations[0].outcome.is_none());

    let receipt = coordinator.effect(identity(32), request).unwrap();
    assert!(matches!(receipt, CommandReceipt::Effect(_)));
    assert!(matches!(
        coordinator.state().operations[0].outcome,
        Some(EffectOutcome::Succeeded { .. })
    ));
    assert_eq!(
        coordinator.provider().actions.iter().filter(|action| **action == Action::Effect).count(),
        2
    );
}

#[test]
fn lost_kv_commit_ack_reconciles_durable_operation_truth_and_replays() {
    let provider = MockProvider { effect_lost_ack_once: true, ..MockProvider::default() };
    let mut coordinator = activated(provider);
    let request = kv_request(30, LeaseEpoch(1));
    let expected_outcome = successful_outcome(&request);

    let receipt = coordinator.effect(identity(31), request.clone()).unwrap();
    let CommandReceipt::Effect(effect) = receipt else {
        panic!("lost effect acknowledgement must reconcile");
    };
    assert_eq!(effect.outcome, expected_outcome);
    assert!(effect.reconciled);
    assert!(matches!(
        &effect.resolution.event.kind,
        contract_core::EventKind::EffectReconciled { operation, outcome }
            if *operation == request.operation && outcome == &expected_outcome
    ));

    let state_digest = coordinator.state_digest().unwrap();
    let journal_len = coordinator.provider().entries.len();
    assert!(matches!(
        coordinator.effect(identity(32), request),
        Ok(CommandReceipt::Replayed(contract_core::Replay::Operation(record)))
            if record.outcome.as_ref() == Some(&expected_outcome)
    ));
    assert_eq!(coordinator.state_digest().unwrap(), state_digest);
    assert_eq!(coordinator.provider().entries.len(), journal_len);
    assert_eq!(journal_len, 3);
}

#[test]
fn indeterminate_effect_reconciles_only_from_provider_truth() {
    let request = kv_request(30, LeaseEpoch(1));
    let truth = successful_outcome(&request);
    let provider = MockProvider {
        next_effect_outcome: Some(EffectOutcome::Indeterminate { evidence: None }),
        reconciliation_truth: Some(truth.clone()),
        ..MockProvider::default()
    };
    let mut coordinator = activated(provider);
    coordinator.effect(identity(31), request.clone()).unwrap();
    assert!(
        coordinator.state().operations[0]
            .outcome
            .as_ref()
            .is_some_and(EffectOutcome::is_indeterminate)
    );

    coordinator.effect(identity(32), request).unwrap();
    assert_eq!(coordinator.state().operations[0].outcome.as_ref(), Some(&truth));
}

#[test]
fn safe_point_resumes_a_suspended_timer_when_freeze_journal_fails() {
    let provider =
        MockProvider { fail_append_once: Some(JournalPosition(5)), ..MockProvider::default() };
    let mut coordinator = activated(provider);
    coordinator.effect(identity(31), timer_arm_request(30)).unwrap();
    coordinator.begin_quiesce(identity(32), entity(HANDOFF_AUTHORITY)).unwrap();

    let safe_point = coordinator.prepare_safe_point().unwrap();
    assert!(matches!(
        coordinator.commit_safe_point(identity(33), vec![1, 2], safe_point),
        Err(RuntimeError::Provider(ProviderError { kind: ProviderErrorKind::Storage, .. }))
    ));
    assert_eq!(coordinator.state().phase, HandoffPhase::Quiescing);
    assert!(matches!(coordinator.state().timer.status, TimerStatus::Armed { .. }));
    assert!(coordinator.provider().suspended_timers.is_empty());
    assert_eq!(coordinator.provider().resume_calls, 1);
}

#[test]
fn safe_point_commits_completion_before_freezing_completed_timer() {
    let provider = MockProvider {
        suspend_observation: Some(TimerObservation::Completed {
            evidence: evidence(84, EvidenceKind::EffectOutcome),
        }),
        ..MockProvider::default()
    };
    let mut coordinator = activated(provider);
    coordinator.effect(identity(31), timer_arm_request(30)).unwrap();
    coordinator.begin_quiesce(identity(32), entity(HANDOFF_AUTHORITY)).unwrap();
    let safe_point = coordinator.prepare_safe_point().unwrap();
    assert_eq!(safe_point.timer(), SafePointTimer::Completed { arm_operation: Some(identity(30)) });
    coordinator.commit_safe_point(identity(33), vec![1, 2], safe_point).unwrap();

    assert_eq!(coordinator.state().phase, HandoffPhase::Frozen);
    assert_eq!(coordinator.state().timer.status, TimerStatus::Frozen(TimerDisposition::Completed));
    assert!(
        coordinator.provider().entries.iter().any(|entry| matches!(
            entry.event.kind,
            contract_core::EventKind::TimerCompleted { .. }
        ))
    );
}

#[test]
fn timer_poll_commits_completion_before_returning_guest_delivery() {
    let provider = MockProvider {
        observe_observation: Some(TimerObservation::Completed {
            evidence: evidence(84, EvidenceKind::EffectOutcome),
        }),
        ..MockProvider::default()
    };
    let mut coordinator = activated(provider);
    coordinator.effect(identity(31), timer_arm_request(30)).unwrap();
    let poll = coordinator.poll_timer().unwrap();
    assert!(matches!(
        poll,
        TimerPoll::Fired {
            arm_operation,
            ..
        } if arm_operation == identity(30)
    ));
    assert_eq!(coordinator.state().timer.status, TimerStatus::Completed);
    assert_eq!(coordinator.poll_timer().unwrap(), TimerPoll::Completed);
}

#[test]
fn timer_cancelled_during_quiescence_is_not_recreated_at_freeze() {
    let mut coordinator = activated(MockProvider::default());
    coordinator.effect(identity(31), timer_arm_request(30)).unwrap();
    coordinator.begin_quiesce(identity(32), entity(HANDOFF_AUTHORITY)).unwrap();
    coordinator.effect(identity(34), timer_cancel_request(33, 30)).unwrap();
    let safe_point = coordinator.prepare_safe_point().unwrap();
    coordinator.commit_safe_point(identity(35), vec![1, 2], safe_point).unwrap();

    assert_eq!(coordinator.state().timer.status, TimerStatus::Frozen(TimerDisposition::Cancelled));
    assert!(coordinator.provider().suspended_timers.is_empty());
}

#[test]
fn abort_without_exported_snapshot_can_resume_the_source() {
    let mut source = activated(MockProvider::default());
    source.begin_quiesce(identity(30), entity(HANDOFF_AUTHORITY)).unwrap();
    let aborted = source.abort_handoff(identity(31), None, None).unwrap();
    assert!(aborted.cleanup.is_none());
    assert_eq!(source.state().phase, HandoffPhase::Aborted);
    source.resume_source(identity(32)).unwrap();
    assert_eq!(source.state().phase, HandoffPhase::Running);
}

#[test]
fn quiescing_only_admits_kv_effect_causally_owned_by_the_armed_timer() {
    let provider = MockProvider {
        observe_observation: Some(TimerObservation::Completed {
            evidence: evidence(84, EvidenceKind::EffectOutcome),
        }),
        ..MockProvider::default()
    };
    let mut coordinator = activated(provider);
    coordinator.effect(identity(31), timer_arm_request(30)).unwrap();
    coordinator.begin_quiesce(identity(32), entity(HANDOFF_AUTHORITY)).unwrap();
    assert!(matches!(coordinator.poll_timer().unwrap(), TimerPoll::Fired { .. }));
    let mut admitted = kv_request(33, LeaseEpoch(1));
    admitted.causal_parent = Some(identity(30));
    coordinator.effect(identity(34), admitted).unwrap();

    let before = coordinator.state_digest().unwrap();
    assert!(matches!(
        coordinator.effect(identity(36), kv_request(35, LeaseEpoch(1))),
        Err(RuntimeError::Rejected(contract_core::Rejection::InvalidPhase { .. }))
    ));
    assert_eq!(coordinator.state_digest().unwrap(), before);
}

#[test]
fn source_abort_cleans_preparation_then_resumes_timer_before_running() {
    let provider =
        MockProvider { fail_append_once: Some(JournalPosition(9)), ..MockProvider::default() };
    let mut source = activated(provider);
    source.effect(identity(31), timer_arm_request(30)).unwrap();
    source.begin_quiesce(identity(32), entity(HANDOFF_AUTHORITY)).unwrap();
    let safe_point = source.prepare_safe_point().unwrap();
    source.commit_safe_point(identity(33), vec![1, 2], safe_point).unwrap();
    source
        .export_snapshot(
            identity(34),
            identity(35),
            identity(36),
            evidence(37, EvidenceKind::SnapshotIntegrity),
        )
        .unwrap();
    source.abort_handoff(identity(38), None, None).unwrap();

    assert_eq!(source.state().phase, HandoffPhase::Aborted);
    assert!(matches!(source.state().timer.status, TimerStatus::Frozen(_)));
    assert!(source.state().preparation_cleanup.is_some());
    assert!(matches!(
        source.resume_source(identity(39)),
        Err(RuntimeError::Provider(ProviderError { kind: ProviderErrorKind::Storage, .. }))
    ));
    assert_eq!(source.state().phase, HandoffPhase::Aborted);

    let resumed = source.resume_source(identity(39)).unwrap();
    assert!(matches!(resumed.timer, TimerDisposition::Pending { .. }));
    assert_eq!(source.state().phase, HandoffPhase::Running);
    assert_eq!(source.provider().resume_calls, 2);
    source.effect(identity(41), kv_request(40, LeaseEpoch(1))).unwrap();
}

#[test]
fn destination_commit_fences_both_resources_atomically_and_applies_to_source() {
    let (source_state, mut destination, _prepared) =
        prepared_destination(ReauthorizationMode::Exact);
    let receipt = destination
        .commit_handoff(identity(71), identity(70), IdempotencyKey::from_bytes([70; 16]))
        .unwrap();
    let CommandReceipt::Effect(effect) = receipt else {
        panic!("lease commit must execute");
    };

    assert_eq!(destination.provider().bundle_calls, 1);
    assert_eq!(destination.provider().lease_prepare_calls, 1);
    assert!(destination.provider().pending_authorities.is_empty());
    assert_eq!(destination.provider().active_authorities.len(), 3);
    assert!(
        destination
            .provider()
            .leases
            .iter()
            .all(|lease| lease.owner == node(DESTINATION) && lease.epoch == LeaseEpoch(2))
    );
    assert_eq!(destination.state().activation.status, ActivationStatus::Active);
    assert_eq!(destination.state().ownership.owner, Some(node(DESTINATION)));

    let source_after =
        semantic_core::apply(&source_state, &effect.resolution.event).unwrap().into_state();
    assert_eq!(source_after.activation.status, ActivationStatus::Fenced);
    assert_eq!(source_after.ownership.owner, Some(node(DESTINATION)));
    assert!(matches!(
        destination.commit_handoff(
            identity(72),
            identity(70),
            IdempotencyKey::from_bytes([70; 16]),
        ),
        Ok(CommandReceipt::Replayed(_))
    ));
}

#[test]
fn lost_bundle_ack_selects_the_durable_destination_owner() {
    let (_, mut destination, _prepared) = prepared_destination(ReauthorizationMode::Exact);
    destination.provider().lost_bundle_once.set(true);
    destination
        .commit_handoff(identity(71), identity(70), IdempotencyKey::from_bytes([70; 16]))
        .unwrap();

    assert_eq!(destination.state().ownership.owner, Some(node(DESTINATION)));
    assert!(destination.provider().leases.iter().all(|lease| lease.owner == node(DESTINATION)));
}

#[test]
fn partial_lease_truth_after_lost_bundle_ack_never_activates_destination() {
    let (_, mut destination, _prepared) = prepared_destination(ReauthorizationMode::Exact);
    destination.provider().partial_bundle_once.set(true);
    assert!(matches!(
        destination.commit_handoff(
            identity(71),
            identity(70),
            IdempotencyKey::from_bytes([70; 16]),
        ),
        Err(RuntimeError::JournalOutcomeUnknown { .. })
    ));
    assert_eq!(destination.state().phase, HandoffPhase::DestinationPrepared);
    assert_eq!(destination.state().activation.status, ActivationStatus::Prepared);
    assert_ne!(destination.state().ownership.owner, Some(node(DESTINATION)));
}

#[test]
fn restore_replays_entries_strictly_after_the_snapshot_cursor() {
    let (envelope, mut provider) = exported_snapshot();
    let validated = validate_snapshot(&envelope, &expectations()).unwrap();
    let restored = Coordinator::restore(validated.clone(), provider).unwrap();
    let base_digest = restored.state_digest().unwrap();

    let event = contract_core::Event::new(
        identity(90),
        contract_core::EventKind::AuthorityRevoked {
            authority: entity(KV_AUTHORITY),
            revoked_generation: Generation(1),
        },
    );
    let next = semantic_core::apply(restored.state(), &event).unwrap().into_state();
    let entry = JournalEntry {
        version: CONTRACT_VERSION,
        position: JournalPosition(envelope.body.snapshot.journal_position.0 + 1),
        input_state: base_digest,
        output_state: state_digest(&next).unwrap(),
        event,
    };
    provider = restored.into_provider();
    provider.store_entry(&entry).unwrap();

    let recovered = Coordinator::restore(validated, provider).unwrap();
    assert_eq!(recovered.journal_position(), entry.position);
    assert_eq!(recovered.state_digest().unwrap(), entry.output_state);
}

#[test]
fn timer_binding_recovery_never_restores_a_source_arm_on_committed_destination() {
    let initial = initial_state(node(SOURCE));
    let mut running = Coordinator::recover(initial.clone(), MockProvider::default()).unwrap();
    running.activate(identity(20), entity(HANDOFF_AUTHORITY), LeaseEpoch(1)).unwrap();
    running.effect(identity(31), timer_arm_request(30)).unwrap();
    let mut provider = running.into_provider();
    provider.restore_timer_calls.clear();
    let recovered = Coordinator::recover(initial.clone(), provider).unwrap();
    assert_eq!(
        recovered.provider().restore_timer_calls,
        vec![(identity(30), TimerRecovery::Running { remaining: LogicalDurationNanos(100) })]
    );

    let (envelope, mut provider) = exported_pending_snapshot();
    let snapshot_position = envelope.body.snapshot.journal_position;
    provider.restore_timer_calls.clear();
    let recovered_source = Coordinator::recover(initial.clone(), provider).unwrap();
    assert!(matches!(
        recovered_source.provider().restore_timer_calls.as_slice(),
        [(
            operation,
            TimerRecovery::Suspended {
                remaining: LogicalDurationNanos(100)
            }
        )] if *operation == identity(30)
    ));

    let validated = validate_snapshot(&envelope, &expectations()).unwrap();
    let mut destination =
        Coordinator::restore(validated, recovered_source.into_provider()).unwrap();
    destination.prepare_destination(identity(60), handoff_plan(), timer_plan(), kv_plan()).unwrap();
    destination
        .commit_handoff(identity(71), identity(70), IdempotencyKey::from_bytes([70; 16]))
        .unwrap();
    let mut provider = destination.into_provider();
    provider.restore_timer_calls.clear();
    let validated = validate_snapshot(&envelope, &expectations()).unwrap();
    let restored_destination = Coordinator::restore(validated, provider).unwrap();
    assert!(restored_destination.provider().restore_timer_calls.is_empty());

    let mut stale_provider = restored_destination.into_provider();
    stale_provider.entries.retain(|entry| entry.position.0 <= snapshot_position.0);
    assert!(matches!(
        Coordinator::recover(initial, stale_provider),
        Err(RuntimeError::Provider(ProviderError { kind: ProviderErrorKind::StaleEpoch, .. }))
    ));
}

#[test]
fn destination_authority_rejects_insufficient_and_revoked_grants() {
    let (_, mut insufficient_provider) = exported_snapshot();
    insufficient_provider.reauthorization_mode = ReauthorizationMode::Insufficient;
    let envelope = envelope_from_provider(&insufficient_provider);
    let validated = validate_snapshot(&envelope, &expectations()).unwrap();
    let mut destination = Coordinator::restore(validated, insufficient_provider).unwrap();
    assert!(matches!(
        destination.prepare_destination(identity(60), handoff_plan(), timer_plan(), kv_plan(),),
        Err(RuntimeError::Rejected(contract_core::Rejection::InsufficientAuthority { .. }))
    ));
    assert!(destination.provider().bindings.is_empty());

    let (envelope, mut revoked_provider) = exported_snapshot();
    revoked_provider.reauthorization_mode = ReauthorizationMode::Revoked;
    let validated = validate_snapshot(&envelope, &expectations()).unwrap();
    let mut destination = Coordinator::restore(validated, revoked_provider).unwrap();
    assert!(matches!(
        destination.prepare_destination(identity(60), handoff_plan(), timer_plan(), kv_plan(),),
        Err(RuntimeError::Provider(ProviderError { kind: ProviderErrorKind::Revoked, .. }))
    ));
}

#[test]
fn failed_destination_preparation_revokes_pending_authority_and_bindings() {
    let (envelope, mut provider) = exported_snapshot();
    provider.fail_reauthorization_call = Some(2);
    let validated = validate_snapshot(&envelope, &expectations()).unwrap();
    let mut destination = Coordinator::restore(validated, provider).unwrap();
    assert!(
        destination
            .prepare_destination(identity(60), handoff_plan(), timer_plan(), kv_plan())
            .is_err()
    );
    assert!(destination.provider().pending_authorities.is_empty());
    assert!(destination.provider().bindings.is_empty());

    let (envelope, mut provider) = exported_snapshot();
    provider.fail_binding_call = Some(2);
    let validated = validate_snapshot(&envelope, &expectations()).unwrap();
    let mut destination = Coordinator::restore(validated, provider).unwrap();
    assert!(
        destination
            .prepare_destination(identity(60), handoff_plan(), timer_plan(), kv_plan())
            .is_err()
    );
    assert!(destination.provider().pending_authorities.is_empty());
    assert!(destination.provider().bindings.is_empty());

    let (envelope, mut provider) = exported_snapshot();
    provider.fail_append_once =
        Some(JournalPosition(envelope.body.snapshot.journal_position.0 + 1));
    let validated = validate_snapshot(&envelope, &expectations()).unwrap();
    let mut destination = Coordinator::restore(validated, provider).unwrap();
    assert!(
        destination
            .prepare_destination(identity(60), handoff_plan(), timer_plan(), kv_plan())
            .is_err()
    );
    assert!(destination.provider().pending_authorities.is_empty());
    assert!(destination.provider().bindings.is_empty());
}

#[test]
fn broader_authority_is_attenuated_and_prepare_cleanup_is_idempotent() {
    let (_, mut destination, _) = prepared_destination(ReauthorizationMode::Broader);
    assert_eq!(destination.provider().attenuation_calls, 3);
    assert!(
        destination
            .state()
            .prepared_destination
            .as_ref()
            .unwrap()
            .authorities
            .iter()
            .all(|grant| grant.rights == required_for_resource(grant.resource))
    );
    let prepare_calls = destination.provider().binding_prepare_calls;
    destination.prepare_destination(identity(61), handoff_plan(), timer_plan(), kv_plan()).unwrap();
    assert_eq!(destination.provider().binding_prepare_calls, prepare_calls);

    let snapshot = destination.state().exported_snapshot.as_ref().unwrap().snapshot;
    destination.abort_handoff(identity(62), None, None).unwrap();
    destination.abort_handoff(identity(63), None, None).unwrap();
    destination.cleanup_snapshot_bindings(snapshot).unwrap();
    destination.cleanup_snapshot_bindings(snapshot).unwrap();
    assert_eq!(destination.provider().binding_destructive_cleanups, 2);
    assert!(destination.provider().bindings.is_empty());
    assert!(destination.provider().pending_authorities.is_empty());
}

fn activated(provider: MockProvider) -> Coordinator<MockProvider> {
    let initial = initial_state(node(SOURCE));
    let mut coordinator = Coordinator::recover(initial, provider).unwrap();
    coordinator.activate(identity(20), entity(HANDOFF_AUTHORITY), LeaseEpoch(1)).unwrap();
    coordinator
}

fn exported_snapshot() -> (contract_core::SnapshotEnvelope, MockProvider) {
    let mut source = activated(MockProvider::default());
    source.begin_quiesce(identity(40), entity(HANDOFF_AUTHORITY)).unwrap();
    let safe_point = source.prepare_safe_point().unwrap();
    source.commit_safe_point(identity(41), vec![1, 2, 3], safe_point).unwrap();
    let (_, envelope) = source
        .export_snapshot(
            identity(42),
            identity(43),
            identity(44),
            evidence(45, EvidenceKind::SnapshotIntegrity),
        )
        .unwrap();
    (envelope, source.into_provider())
}

fn exported_pending_snapshot() -> (contract_core::SnapshotEnvelope, MockProvider) {
    let mut source = activated(MockProvider::default());
    source.effect(identity(31), timer_arm_request(30)).unwrap();
    source.begin_quiesce(identity(32), entity(HANDOFF_AUTHORITY)).unwrap();
    let safe_point = source.prepare_safe_point().unwrap();
    source.commit_safe_point(identity(33), vec![1, 2, 3], safe_point).unwrap();
    let (_, envelope) = source
        .export_snapshot(
            identity(34),
            identity(35),
            identity(36),
            evidence(37, EvidenceKind::SnapshotIntegrity),
        )
        .unwrap();
    (envelope, source.into_provider())
}

fn envelope_from_provider(provider: &MockProvider) -> contract_core::SnapshotEnvelope {
    let event = provider
        .entries
        .iter()
        .find(|entry| matches!(entry.event.kind, contract_core::EventKind::SnapshotExported { .. }))
        .expect("snapshot export exists");
    let initial = initial_state(node(SOURCE));
    let state =
        semantic_core::replay(&initial, &provider.entries, |state| state_digest(state).unwrap())
            .unwrap();
    let body = state.snapshot_body().unwrap();
    assert_eq!(body.snapshot.journal_position, event.position);
    contract_core::SnapshotEnvelope {
        version: CONTRACT_VERSION,
        integrity: snapshot_integrity(&body).unwrap(),
        body,
    }
}

fn prepared_destination(
    mode: ReauthorizationMode,
) -> (CanonicalState, Coordinator<MockProvider>, contract_core::PreparedDestination) {
    let (envelope, mut provider) = exported_snapshot();
    let source_initial = initial_state(node(SOURCE));
    let source_state = semantic_core::replay(&source_initial, &provider.entries, |state| {
        state_digest(state).unwrap()
    })
    .unwrap();
    provider.reauthorization_mode = mode;
    let validated = validate_snapshot(&envelope, &expectations()).unwrap();
    let mut destination = Coordinator::restore(validated, provider).unwrap();
    destination.prepare_destination(identity(60), handoff_plan(), timer_plan(), kv_plan()).unwrap();
    let prepared = destination.state().prepared_destination.clone().unwrap();
    (source_state, destination, prepared)
}

fn expectations() -> SnapshotExpectations {
    SnapshotExpectations {
        component_digest: digest(1),
        profile_digest: digest(2),
        profile_version: CONTRACT_VERSION,
        supported_extensions: Vec::new(),
        destination: node(DESTINATION),
    }
}

fn initial_state(node: NodeIdentity) -> CanonicalState {
    let component = entity(COMPONENT);
    let timer = entity(TIMER);
    let key_value = entity(KV);
    CanonicalState::dormant(
        component,
        node,
        digest(1),
        digest(2),
        CONTRACT_VERSION,
        ResourceClaims {
            timer: TimerClaim {
                resource: timer,
                clock: TimerClock::PausedMonotonicDuration,
                required_rights: Rights::TIMER_ARM
                    .union(Rights::TIMER_CANCEL)
                    .union(Rights::REBIND),
            },
            key_value: KeyValueClaim {
                resource: key_value,
                namespace: identity(9),
                required_rights: Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND),
                delivery: contract_core::DeliveryPolicy::Deduplicated,
            },
        },
        vec![
            AuthorityGrant::active_root(
                entity(HANDOFF_AUTHORITY),
                component,
                component,
                Rights::HANDOFF,
            ),
            AuthorityGrant::active_root(
                entity(TIMER_AUTHORITY),
                component,
                timer,
                Rights::TIMER_ARM.union(Rights::TIMER_CANCEL).union(Rights::REBIND),
            ),
            AuthorityGrant::active_root(
                entity(KV_AUTHORITY),
                component,
                key_value,
                Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND),
            ),
        ],
    )
}

fn kv_request(operation: u8, epoch: LeaseEpoch) -> EffectRequest {
    EffectRequest {
        operation: identity(operation),
        idempotency_key: IdempotencyKey::from_bytes([operation; 16]),
        causal_parent: None,
        node: node(SOURCE),
        subject: entity(COMPONENT),
        resource: entity(KV),
        authority: entity(KV_AUTHORITY),
        lease_epoch: epoch,
        request_digest: digest(operation),
        kind: EffectKind::KeyValueCompareAndSet {
            key: vec![1],
            expected_version: None,
            value: vec![2],
        },
    }
}

fn timer_arm_request(operation: u8) -> EffectRequest {
    EffectRequest {
        operation: identity(operation),
        idempotency_key: IdempotencyKey::from_bytes([operation; 16]),
        causal_parent: None,
        node: node(SOURCE),
        subject: entity(COMPONENT),
        resource: entity(TIMER),
        authority: entity(TIMER_AUTHORITY),
        lease_epoch: LeaseEpoch(1),
        request_digest: digest(operation),
        kind: EffectKind::TimerArm { remaining: LogicalDurationNanos(100) },
    }
}

fn timer_cancel_request(operation: u8, arm_operation: u8) -> EffectRequest {
    EffectRequest {
        operation: identity(operation),
        idempotency_key: IdempotencyKey::from_bytes([operation; 16]),
        causal_parent: Some(identity(arm_operation)),
        node: node(SOURCE),
        subject: entity(COMPONENT),
        resource: entity(TIMER),
        authority: entity(TIMER_AUTHORITY),
        lease_epoch: LeaseEpoch(1),
        request_digest: digest(operation),
        kind: EffectKind::TimerCancel { target_operation: identity(arm_operation) },
    }
}

fn successful_outcome(request: &EffectRequest) -> EffectOutcome {
    let result = match request.kind {
        EffectKind::TimerArm { remaining } => EffectResult::TimerArmed { remaining },
        EffectKind::TimerCancel { .. } => EffectResult::TimerCancelled,
        EffectKind::KeyValueRead { .. } => EffectResult::KeyValueRead { value: None },
        EffectKind::KeyValueCompareAndSet { .. } => {
            EffectResult::KeyValue { version: 1, applied: true }
        }
        EffectKind::Profile { profile, .. } => {
            EffectResult::Profile { profile, payload: Vec::new() }
        }
        EffectKind::LeaseCommit { destination, next_epoch, .. } => EffectResult::LeaseAdvanced {
            owner: destination,
            epoch: next_epoch,
            source_fence: evidence(80, EvidenceKind::SourceFence),
        },
    };
    EffectOutcome::Succeeded { result, evidence: evidence(82, EvidenceKind::EffectOutcome) }
}

fn handoff_plan() -> AuthorityPlan {
    AuthorityPlan {
        source_authority: entity(HANDOFF_AUTHORITY),
        destination_authority: entity(20),
        attenuated_authority: entity(21),
    }
}

fn timer_plan() -> AuthorityPlan {
    AuthorityPlan {
        source_authority: entity(TIMER_AUTHORITY),
        destination_authority: entity(22),
        attenuated_authority: entity(23),
    }
}

fn kv_plan() -> AuthorityPlan {
    AuthorityPlan {
        source_authority: entity(KV_AUTHORITY),
        destination_authority: entity(24),
        attenuated_authority: entity(25),
    }
}

fn required_for_resource(resource: EntityRef) -> Rights {
    if resource.identity == identity(COMPONENT) {
        Rights::HANDOFF
    } else if resource.identity == identity(TIMER) {
        Rights::TIMER_ARM.union(Rights::TIMER_CANCEL).union(Rights::REBIND)
    } else {
        Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND)
    }
}

fn extra_right(required: Rights) -> Rights {
    if required.contains(Rights::HANDOFF) { Rights::KV_READ } else { Rights::HANDOFF }
}

fn evidence(value: u8, kind: EvidenceKind) -> EvidenceRef {
    EvidenceRef { identity: identity(value), kind, digest: digest(value) }
}

fn entity(value: u8) -> EntityRef {
    EntityRef::new(identity(value), Generation::INITIAL)
}

fn node(value: u8) -> NodeIdentity {
    NodeIdentity::new(identity(value))
}

fn identity(value: u8) -> Identity {
    let mut bytes = [0_u8; 16];
    bytes[15] = value;
    Identity::from_bytes(bytes)
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}
