use alloc::{boxed::Box, vec, vec::Vec};

use contract_core::{
    ActivationRole, ActivationStatus, AuthorityGrant, AuthorityStatus, CONTRACT_VERSION,
    CanonicalState, CleanupStatus, Command, CommandKind, Decision, Digest, EffectFailure,
    EffectKind, EffectOutcome, EffectRequest, EffectResult, EntityRef, Event, EventKind,
    EvidenceRef, ExtensionSupport, FailureClass, HandoffPhase, IdempotencyKey, Identity,
    JournalEntry, JournalPosition, LeaseEpoch, NodeIdentity, PreparedDestination, Rejection,
    Replay, Rights, SchemaVersion, SnapshotEnvelope, SnapshotRecord, TimerDisposition, TimerStatus,
};
use semantic_core::{ReplayError, apply, preflight, replay, replay_from, restore};
use substrate_api::{
    ActivationBundle, AuthorityPort, BindingKind, BindingPort, BindingRequest, CommitBundle,
    JournalPort, KvPort, LeasePort, LeaseRecord, LeaseTransition, ProviderError, ProviderErrorKind,
    ReauthorizationRequest, TimerObservation, TimerPort, TimerRecovery,
};

use crate::codec::{EncodeError, canonical_digest, snapshot_integrity, state_digest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeError {
    Encode(EncodeError),
    Rejected(Rejection),
    ReducerInvariant(Rejection),
    Replay(ReplayError),
    Provider(ProviderError),
    JournalConflict { position: JournalPosition },
    JournalOutcomeUnknown { position: JournalPosition },
    OperationOutcomeUnknown { operation: Identity },
    InvalidProviderOutcome { operation: Identity },
    PositionExhausted,
    SnapshotUnavailable,
    InvalidAuthorityGrant { authority: EntityRef },
    InvalidSafePoint,
    PreparationCleanupFailed(ProviderError),
    SafePointRollbackFailed { arm_operation: Identity, error: ProviderError },
}

impl From<EncodeError> for RuntimeError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

impl From<ReplayError> for RuntimeError {
    fn from(error: ReplayError) -> Self {
        Self::Replay(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectReceipt {
    pub intent: Option<JournalEntry>,
    pub resolution: JournalEntry,
    pub outcome: EffectOutcome,
    pub reconciled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandReceipt {
    Committed(JournalEntry),
    Effect(Box<EffectReceipt>),
    Replayed(Replay),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceResumeReceipt {
    pub receipt: CommandReceipt,
    pub timer: TimerDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbortReceipt {
    pub abort: CommandReceipt,
    pub cleanup: Option<CommandReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityPlan {
    pub source_authority: EntityRef,
    pub destination_authority: EntityRef,
    pub attenuated_authority: EntityRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SafePointTimer {
    Idle,
    Pending { remaining: contract_core::LogicalDurationNanos, arm_operation: Identity },
    Completed { arm_operation: Option<Identity> },
    Cancelled,
    Cleaned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimerPoll {
    Idle,
    Pending { arm_operation: Identity, remaining: contract_core::LogicalDurationNanos },
    Fired { arm_operation: Identity, evidence: EvidenceRef, receipt: Box<CommandReceipt> },
    Completed,
    Cancelled,
    CancelledObserved { arm_operation: Identity, evidence: EvidenceRef },
    Cleaned,
    Absent { arm_operation: Identity },
    Frozen(TimerDisposition),
}

#[derive(Debug, PartialEq, Eq)]
pub struct SafePoint {
    timer: SafePointTimer,
    disposition: TimerDisposition,
    suspended_arm: Option<Identity>,
}

impl SafePoint {
    pub const fn timer(&self) -> SafePointTimer {
        self.timer
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotExpectations {
    pub component_digest: Digest,
    pub profile_digest: Digest,
    pub profile_version: SchemaVersion,
    pub supported_extensions: Vec<ExtensionSupport>,
    pub destination: NodeIdentity,
}

/// A compatibility-checked snapshot whose state cannot be extracted or
/// modified without placing it under a coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedSnapshot {
    state: CanonicalState,
    position: JournalPosition,
}

pub fn validate_snapshot(
    envelope: &SnapshotEnvelope,
    expectations: &SnapshotExpectations,
) -> Result<ValidatedSnapshot, RuntimeError> {
    let integrity = snapshot_integrity(&envelope.body)?;
    let state = restore(
        envelope,
        integrity,
        expectations.component_digest,
        expectations.profile_digest,
        expectations.profile_version,
        &expectations.supported_extensions,
        expectations.destination,
    )
    .map_err(RuntimeError::Rejected)?;
    Ok(ValidatedSnapshot { position: envelope.body.snapshot.journal_position, state })
}

/// The only owner of mutable canonical state in the runtime path.
pub struct Coordinator<P> {
    state: CanonicalState,
    position: JournalPosition,
    provider: P,
}

impl<P> Coordinator<P> {
    pub fn state(&self) -> &CanonicalState {
        &self.state
    }

    pub const fn journal_position(&self) -> JournalPosition {
        self.position
    }

    pub fn state_digest(&self) -> Result<Digest, RuntimeError> {
        state_digest(&self.state).map_err(Into::into)
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn into_provider(self) -> P {
        self.provider
    }
}

impl<P> Coordinator<P>
where
    P: JournalPort,
{
    pub fn recover(initial: CanonicalState, provider: P) -> Result<Self, RuntimeError>
    where
        P: LeasePort + TimerPort,
    {
        let entries = provider.replay_from(None).map_err(RuntimeError::Provider)?;
        let state = replay(&initial, &entries, infallible_state_digest)?;
        let position = entries.last().map_or(JournalPosition::ORIGIN, |entry| entry.position);
        let mut coordinator = Self { state, position, provider };
        coordinator.restore_timer_binding()?;
        Ok(coordinator)
    }

    pub fn restore(validated: ValidatedSnapshot, provider: P) -> Result<Self, RuntimeError>
    where
        P: LeasePort + TimerPort,
    {
        let entries =
            provider.replay_from(Some(validated.position)).map_err(RuntimeError::Provider)?;
        let state =
            replay_from(&validated.state, validated.position, &entries, infallible_state_digest)?;
        let position = entries.last().map_or(validated.position, |entry| entry.position);
        let mut coordinator = Self { state, position, provider };
        coordinator.restore_timer_binding()?;
        Ok(coordinator)
    }

    fn restore_timer_binding(&mut self) -> Result<(), RuntimeError>
    where
        P: LeasePort + TimerPort,
    {
        let local_owner = self.state.activation.status == ActivationStatus::Active
            && self.state.ownership.owner == Some(self.state.activation.node);
        let recovery = match self.state.timer.status {
            TimerStatus::Armed { remaining } if local_owner => {
                Some(TimerRecovery::Running { remaining })
            }
            TimerStatus::Frozen(TimerDisposition::Pending { remaining, .. })
                if local_owner
                    && self.state.activation.role == ActivationRole::Source
                    && matches!(
                        self.state.phase,
                        HandoffPhase::Frozen | HandoffPhase::Exported | HandoffPhase::Aborted
                    ) =>
            {
                Some(TimerRecovery::Suspended { remaining })
            }
            _ => None,
        };
        let Some(recovery) = recovery else {
            return Ok(());
        };
        let operation = self
            .state
            .timer
            .active_operation
            .or(match self.state.timer.status {
                TimerStatus::Frozen(TimerDisposition::Pending { arm_operation, .. }) => {
                    Some(arm_operation)
                }
                _ => None,
            })
            .ok_or(RuntimeError::Rejected(Rejection::TimerStateConflict))?;
        let record = self
            .state
            .operations
            .iter()
            .find(|record| record.request.operation == operation)
            .ok_or(RuntimeError::Rejected(Rejection::UnknownOperation { operation }))?;
        if record.request.resource != self.state.timer.claim.resource
            || record.request.node != self.state.activation.node
            || record.request.lease_epoch != self.state.ownership.epoch
            || !matches!(record.request.kind, EffectKind::TimerArm { .. })
            || !matches!(
                record.outcome,
                Some(EffectOutcome::Succeeded { result: EffectResult::TimerArmed { .. }, .. })
            )
        {
            return Err(RuntimeError::InvalidProviderOutcome { operation });
        }
        self.provider
            .check_lease(
                self.state.timer.claim.resource,
                self.state.activation.node,
                self.state.ownership.epoch,
            )
            .map_err(RuntimeError::Provider)?;
        self.provider
            .restore_timer_binding(&record.request, recovery)
            .map_err(RuntimeError::Provider)
    }

    fn build_entry(&self, event: Event) -> Result<(JournalEntry, CanonicalState), RuntimeError> {
        let position = self.position.next().ok_or(RuntimeError::PositionExhausted)?;
        let input_state = state_digest(&self.state)?;
        let next = apply(&self.state, &event).map_err(RuntimeError::ReducerInvariant)?.into_state();
        let output_state = state_digest(&next)?;
        Ok((
            JournalEntry { version: CONTRACT_VERSION, position, input_state, output_state, event },
            next,
        ))
    }

    fn append_entry(
        &mut self,
        entry: JournalEntry,
        next: CanonicalState,
    ) -> Result<JournalEntry, RuntimeError> {
        match self.provider.append_entry(&entry) {
            Ok(()) => self.publish(entry, next),
            Err(error) if error.kind == ProviderErrorKind::OutcomeUnknown => {
                self.verify_unknown_entry(&entry)?;
                self.publish(entry, next)
            }
            Err(error) => Err(RuntimeError::Provider(error)),
        }
    }

    fn publish(
        &mut self,
        entry: JournalEntry,
        next: CanonicalState,
    ) -> Result<JournalEntry, RuntimeError> {
        self.position = entry.position;
        self.state = next;
        Ok(entry)
    }

    fn verify_unknown_entry(&self, expected: &JournalEntry) -> Result<(), RuntimeError> {
        let observed = self.provider.entry(expected.position).map_err(RuntimeError::Provider)?;
        match observed {
            Some(entry) if entry == *expected => {}
            Some(_) => {
                return Err(RuntimeError::JournalConflict { position: expected.position });
            }
            None => {
                return Err(RuntimeError::JournalOutcomeUnknown { position: expected.position });
            }
        }

        let operation = match &expected.event.kind {
            EventKind::EffectPrepared { request } => {
                Some((request.operation, Some(request), None, false))
            }
            EventKind::EffectResolved { operation, outcome }
            | EventKind::EffectReconciled { operation, outcome } => {
                Some((*operation, None, Some(outcome), false))
            }
            EventKind::HandoffCommitted { operation, outcome, .. } => {
                Some((*operation, None, Some(outcome), false))
            }
            EventKind::OperationCleaned { operation, .. } => Some((*operation, None, None, true)),
            _ => None,
        };
        if let Some((operation, request, outcome, cleaned)) = operation {
            let observation = self
                .provider
                .operation(operation)
                .map_err(RuntimeError::Provider)?
                .ok_or(RuntimeError::OperationOutcomeUnknown { operation })?;
            if request.is_some_and(|expected| observation.record.request != *expected)
                || outcome
                    .is_some_and(|expected| observation.record.outcome.as_ref() != Some(expected))
                || (cleaned && observation.record.cleanup != CleanupStatus::Cleaned)
            {
                return Err(RuntimeError::InvalidProviderOutcome { operation });
            }
        }
        Ok(())
    }

    fn commit_event(&mut self, event: Event) -> Result<CommandReceipt, RuntimeError> {
        let (entry, next) = self.build_entry(event)?;
        self.append_entry(entry, next).map(CommandReceipt::Committed)
    }

    fn commit_command(&mut self, command: Command) -> Result<CommandReceipt, RuntimeError> {
        match preflight(&self.state, &command) {
            Decision::Commit(event) => self.commit_event(event),
            Decision::Replay(replay) => Ok(CommandReceipt::Replayed(replay)),
            Decision::Reject(rejection) => Err(RuntimeError::Rejected(rejection)),
            Decision::Execute { request, .. } => {
                Err(RuntimeError::InvalidProviderOutcome { operation: request.operation })
            }
        }
    }

    pub fn activate(
        &mut self,
        command: Identity,
        authority: EntityRef,
        lease_epoch: LeaseEpoch,
    ) -> Result<CommandReceipt, RuntimeError>
    where
        P: LeasePort,
    {
        let request = Command::new(command, CommandKind::Activate { authority, lease_epoch });
        match preflight(&self.state, &request) {
            Decision::Commit(event) => {
                let (entry, next) = self.build_entry(event)?;
                let initial_leases = self
                    .fenced_resources()
                    .into_iter()
                    .map(|resource| LeaseRecord {
                        resource,
                        owner: self.state.activation.node,
                        epoch: lease_epoch,
                    })
                    .collect::<Vec<_>>();
                let bundle = ActivationBundle {
                    entry: entry.clone(),
                    initial_leases: initial_leases.clone(),
                };
                match self.provider.commit_activation(&bundle) {
                    Ok(()) => {}
                    Err(error) if error.kind == ProviderErrorKind::OutcomeUnknown => {
                        self.verify_unknown_entry(&entry)?;
                        for expected in initial_leases {
                            if self
                                .provider
                                .current_lease(expected.resource)
                                .map_err(RuntimeError::Provider)?
                                != Some(expected)
                            {
                                return Err(RuntimeError::JournalOutcomeUnknown {
                                    position: entry.position,
                                });
                            }
                        }
                    }
                    Err(error) => return Err(RuntimeError::Provider(error)),
                }
                self.publish(entry, next).map(CommandReceipt::Committed)
            }
            Decision::Replay(replay) => Ok(CommandReceipt::Replayed(replay)),
            Decision::Reject(rejection) => Err(RuntimeError::Rejected(rejection)),
            Decision::Execute { request, .. } => {
                Err(RuntimeError::InvalidProviderOutcome { operation: request.operation })
            }
        }
    }

    pub fn attenuate_authority(
        &mut self,
        command: Identity,
        parent: EntityRef,
        derived: AuthorityGrant,
    ) -> Result<CommandReceipt, RuntimeError>
    where
        P: AuthorityPort,
    {
        self.commit_command(Command::new(
            command,
            CommandKind::AttenuateAuthority { parent, derived },
        ))
    }

    pub fn revoke_authority(
        &mut self,
        command: Identity,
        authority: EntityRef,
    ) -> Result<CommandReceipt, RuntimeError>
    where
        P: AuthorityPort,
    {
        self.commit_command(Command::new(command, CommandKind::RevokeAuthority { authority }))
    }

    pub fn begin_quiesce(
        &mut self,
        command: Identity,
        authority: EntityRef,
    ) -> Result<CommandReceipt, RuntimeError> {
        self.commit_command(Command::new(command, CommandKind::BeginHandoff { authority }))
    }

    fn commit_freeze(
        &mut self,
        command: Identity,
        portable_state: Vec<u8>,
        timer: TimerDisposition,
    ) -> Result<CommandReceipt, RuntimeError> {
        self.commit_command(Command::new(command, CommandKind::Freeze { portable_state, timer }))
    }

    pub fn timer_completed(
        &mut self,
        command: Identity,
        arm_operation: Identity,
        evidence: EvidenceRef,
    ) -> Result<CommandReceipt, RuntimeError> {
        self.commit_command(Command::new(
            command,
            CommandKind::TimerCompleted {
                timer: self.state.timer.claim.resource,
                arm_operation,
                lease_epoch: self.state.ownership.epoch,
                evidence,
            },
        ))
    }

    pub fn export_snapshot(
        &mut self,
        command: Identity,
        handoff: Identity,
        snapshot: Identity,
        evidence: EvidenceRef,
    ) -> Result<(CommandReceipt, SnapshotEnvelope), RuntimeError> {
        let record = if let Some(existing) = &self.state.exported_snapshot {
            if existing.handoff != handoff || existing.snapshot != snapshot {
                return Err(RuntimeError::Rejected(Rejection::SnapshotAlreadyExported));
            }
            existing.clone()
        } else {
            SnapshotRecord {
                handoff,
                snapshot,
                journal_position: self.position.next().ok_or(RuntimeError::PositionExhausted)?,
                evidence,
            }
        };
        let receipt = self.commit_command(Command::new(
            command,
            CommandKind::ExportSnapshot { snapshot: record },
        ))?;
        let body = self.state.snapshot_body().ok_or(RuntimeError::SnapshotUnavailable)?;
        let integrity = snapshot_integrity(&body)?;
        Ok((receipt, SnapshotEnvelope { version: CONTRACT_VERSION, body, integrity }))
    }

    pub fn resume_destination(
        &mut self,
        command: Identity,
    ) -> Result<CommandReceipt, RuntimeError> {
        self.commit_command(Command::new(command, CommandKind::ResumeDestination))
    }

    fn fenced_resources(&self) -> Vec<EntityRef> {
        let timer = self.state.timer.claim.resource;
        let key_value = self.state.key_value.claim.resource;
        if timer == key_value { vec![timer] } else { vec![timer, key_value] }
    }
}

impl<P> Coordinator<P>
where
    P: JournalPort + AuthorityPort + LeasePort + KvPort + TimerPort,
{
    pub fn commit_handoff(
        &mut self,
        command: Identity,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<CommandReceipt, RuntimeError> {
        let prepared =
            self.state.prepared_destination.clone().ok_or(RuntimeError::SnapshotUnavailable)?;
        let subject = EntityRef::new(self.state.component.identity, prepared.component_generation);
        let mut authorities = prepared.authorities.iter().filter(|grant| {
            grant.subject == subject
                && grant.resource == subject
                && grant.status == AuthorityStatus::Active
                && grant.rights.contains(Rights::HANDOFF)
        });
        let authority = authorities
            .next()
            .ok_or(RuntimeError::Rejected(Rejection::InsufficientAuthority {
                required: Rights::HANDOFF,
                granted: Rights::NONE,
            }))?
            .authority;
        if authorities.next().is_some() {
            return Err(RuntimeError::InvalidAuthorityGrant { authority });
        }
        let kind = EffectKind::LeaseCommit {
            handoff: prepared.handoff,
            snapshot: prepared.snapshot,
            destination: prepared.destination,
            expected_epoch: prepared.expected_epoch,
            next_epoch: prepared.next_epoch,
        };
        let request_digest = canonical_digest(&(
            operation,
            idempotency_key,
            prepared.destination,
            subject,
            authority,
            kind.clone(),
        ))?;
        self.effect(
            command,
            EffectRequest {
                operation,
                idempotency_key,
                causal_parent: None,
                node: prepared.destination,
                subject,
                resource: subject,
                authority,
                lease_epoch: prepared.expected_epoch,
                request_digest,
                kind,
            },
        )
    }

    pub fn effect(
        &mut self,
        command: Identity,
        request: EffectRequest,
    ) -> Result<CommandReceipt, RuntimeError> {
        let operation = request.operation;
        match preflight(&self.state, &Command::new(command, CommandKind::RequestEffect(request))) {
            Decision::Execute { intent, request } => self.execute(intent, request),
            Decision::Replay(Replay::Operation(record)) if record.outcome.is_none() => {
                self.retry_durable_intent(record.request)
            }
            Decision::Replay(Replay::Operation(record))
                if record.outcome.as_ref().is_some_and(EffectOutcome::is_indeterminate) =>
            {
                self.reconcile_effect(record.request.operation)
            }
            Decision::Replay(replay) => Ok(CommandReceipt::Replayed(replay)),
            Decision::Reject(rejection) => Err(RuntimeError::Rejected(rejection)),
            Decision::Commit(_) => Err(RuntimeError::InvalidProviderOutcome { operation }),
        }
    }

    fn execute(
        &mut self,
        intent: Event,
        request: EffectRequest,
    ) -> Result<CommandReceipt, RuntimeError> {
        let (intent_entry, intent_state) = self.build_entry(intent)?;
        let intent_entry = self.append_entry(intent_entry, intent_state)?;

        self.execute_durable_intent(request, Some(intent_entry))
    }

    fn retry_durable_intent(
        &mut self,
        request: EffectRequest,
    ) -> Result<CommandReceipt, RuntimeError> {
        if let Some(outcome) = self.query_operation_truth(&request)? {
            let (resolution, reconciled) =
                self.resolve_effect(&request, outcome.clone(), false, None)?;
            return Ok(CommandReceipt::Effect(Box::new(EffectReceipt {
                intent: None,
                resolution,
                outcome,
                reconciled,
            })));
        }
        self.execute_durable_intent(request, None)
    }

    fn execute_durable_intent(
        &mut self,
        request: EffectRequest,
        intent_entry: Option<JournalEntry>,
    ) -> Result<CommandReceipt, RuntimeError> {
        let required = required_rights(&request.kind);
        let execution = match self.provider.authorize_effect(&request, required) {
            Ok(rights) if rights.contains(required) => self.execute_after_authority(&request),
            Ok(_) => Ok(ExecutedEffect::ordinary(EffectOutcome::Failed(EffectFailure {
                class: FailureClass::Denied,
                retryable: false,
                evidence: None,
            }))),
            Err(error) => self.outcome_from_provider_error(&request, error),
        }?;

        let outcome = execution.outcome.clone();
        let (resolution, reconciled) = self.resolve_effect(
            &request,
            execution.outcome,
            execution.reconciled,
            execution.lease_transitions,
        )?;
        Ok(CommandReceipt::Effect(Box::new(EffectReceipt {
            intent: intent_entry,
            resolution,
            outcome,
            reconciled,
        })))
    }

    fn execute_after_authority(
        &mut self,
        request: &EffectRequest,
    ) -> Result<ExecutedEffect, RuntimeError> {
        let lease_result = match request.kind {
            EffectKind::LeaseCommit { .. } => {
                let owner = self.state.ownership.owner.ok_or(RuntimeError::Rejected(
                    Rejection::LeaseEpochMismatch {
                        expected: self.state.ownership.epoch,
                        actual: request.lease_epoch,
                    },
                ))?;
                self.fenced_resources().into_iter().try_for_each(|resource| {
                    self.provider.check_lease(resource, owner, request.lease_epoch)
                })
            }
            _ => self.provider.check_lease(request.resource, request.node, request.lease_epoch),
        };
        if let Err(error) = lease_result {
            return self.outcome_from_provider_error(request, error);
        }

        let result = match &request.kind {
            EffectKind::TimerArm { .. } => self.provider.arm(request),
            EffectKind::TimerCancel { .. } => self.provider.cancel(request),
            EffectKind::KeyValueRead { .. } => self.provider.read(request),
            EffectKind::KeyValueCompareAndSet { .. } => self.provider.compare_and_set(request),
            EffectKind::LeaseCommit { .. } => {
                return self.prepare_lease_effect(request);
            }
        };
        match result {
            Ok(outcome) => Ok(ExecutedEffect::ordinary(outcome)),
            Err(error) => self.outcome_from_provider_error(request, error),
        }
    }

    fn prepare_lease_effect(
        &mut self,
        request: &EffectRequest,
    ) -> Result<ExecutedEffect, RuntimeError> {
        let resources = self.fenced_resources();
        match self.provider.prepare_transitions(request, &resources) {
            Ok(prepared) => {
                self.validate_lease_transitions(request, &resources, &prepared.transitions)?;
                Ok(ExecutedEffect {
                    outcome: prepared.outcome,
                    reconciled: false,
                    lease_transitions: Some(prepared.transitions),
                })
            }
            Err(error) => self.outcome_from_provider_error(request, error),
        }
    }

    fn resolve_effect(
        &mut self,
        request: &EffectRequest,
        outcome: EffectOutcome,
        reconciliation: bool,
        lease_transitions: Option<Vec<LeaseTransition>>,
    ) -> Result<(JournalEntry, bool), RuntimeError> {
        let identity = derived_identity(
            request.operation,
            if reconciliation { b"reconcile" } else { b"resolve" },
        )?;
        let kind = if reconciliation {
            CommandKind::ReconcileEffect { operation: request.operation, outcome: outcome.clone() }
        } else {
            CommandKind::ResolveEffect { operation: request.operation, outcome: outcome.clone() }
        };
        let event = match preflight(&self.state, &Command::new(identity, kind)) {
            Decision::Commit(event) => event,
            Decision::Replay(_) => {
                return Err(RuntimeError::InvalidProviderOutcome { operation: request.operation });
            }
            Decision::Reject(rejection) => return Err(RuntimeError::Rejected(rejection)),
            Decision::Execute { .. } => {
                return Err(RuntimeError::InvalidProviderOutcome { operation: request.operation });
            }
        };
        let (entry, next) = self.build_entry(event)?;

        if matches!(entry.event.kind, EventKind::HandoffCommitted { .. }) {
            let resources = self.fenced_resources();
            let transitions = lease_transitions
                .ok_or(RuntimeError::InvalidProviderOutcome { operation: request.operation })?;
            self.validate_lease_transitions(request, &resources, &transitions)?;
            let final_authorities = self
                .state
                .prepared_destination
                .as_ref()
                .ok_or(RuntimeError::InvalidProviderOutcome { operation: request.operation })?
                .authorities
                .iter()
                .map(|grant| grant.authority)
                .collect();
            let bundle = CommitBundle {
                entry: entry.clone(),
                lease_transitions: transitions.clone(),
                final_authorities,
            };
            match self.provider.commit_bundle(&bundle) {
                Ok(()) => self.publish(entry, next).map(|entry| (entry, reconciliation)),
                Err(error) if error.kind == ProviderErrorKind::OutcomeUnknown => {
                    self.verify_unknown_bundle(&entry, &transitions, &outcome)?;
                    self.publish(entry, next).map(|entry| (entry, reconciliation))
                }
                Err(error) => Err(RuntimeError::Provider(error)),
            }
        } else {
            if lease_transitions.is_some() {
                return Err(RuntimeError::InvalidProviderOutcome { operation: request.operation });
            }
            self.append_entry(entry, next).map(|entry| (entry, reconciliation))
        }
    }

    fn validate_lease_transitions(
        &self,
        request: &EffectRequest,
        resources: &[EntityRef],
        transitions: &[LeaseTransition],
    ) -> Result<(), RuntimeError> {
        let EffectKind::LeaseCommit { destination, expected_epoch, next_epoch, .. } = request.kind
        else {
            return Err(RuntimeError::InvalidProviderOutcome { operation: request.operation });
        };
        let expected_owner = self
            .state
            .ownership
            .owner
            .ok_or(RuntimeError::InvalidProviderOutcome { operation: request.operation })?;
        if transitions.len() != resources.len()
            || resources.iter().any(|resource| {
                transitions.iter().filter(|item| item.resource == *resource).count() != 1
            })
            || transitions.iter().any(|item| {
                !resources.contains(&item.resource)
                    || item.expected_owner != expected_owner
                    || item.next_owner != destination
                    || item.expected_epoch != expected_epoch
                    || item.next_epoch != next_epoch
            })
        {
            return Err(RuntimeError::InvalidProviderOutcome { operation: request.operation });
        }
        Ok(())
    }

    fn verify_unknown_bundle(
        &self,
        entry: &JournalEntry,
        transitions: &[LeaseTransition],
        outcome: &EffectOutcome,
    ) -> Result<(), RuntimeError> {
        self.verify_unknown_entry(entry)?;
        for transition in transitions {
            let lease =
                self.provider.current_lease(transition.resource).map_err(RuntimeError::Provider)?;
            if lease
                != Some(LeaseRecord {
                    resource: transition.resource,
                    owner: transition.next_owner,
                    epoch: transition.next_epoch,
                })
            {
                return Err(RuntimeError::JournalOutcomeUnknown { position: entry.position });
            }
        }
        let operation = match entry.event.kind {
            EventKind::HandoffCommitted { operation, .. } => operation,
            _ => {
                return Err(RuntimeError::InvalidProviderOutcome { operation: Identity::ZERO });
            }
        };
        let observed = self
            .provider
            .operation(operation)
            .map_err(RuntimeError::Provider)?
            .ok_or(RuntimeError::OperationOutcomeUnknown { operation })?;
        if observed.record.outcome.as_ref() != Some(outcome) {
            return Err(RuntimeError::InvalidProviderOutcome { operation });
        }
        Ok(())
    }

    fn outcome_from_provider_error(
        &self,
        request: &EffectRequest,
        error: ProviderError,
    ) -> Result<ExecutedEffect, RuntimeError> {
        if error.kind != ProviderErrorKind::OutcomeUnknown {
            return Ok(ExecutedEffect::ordinary(provider_failure(error)));
        }
        Ok(match self.query_operation_truth(request)? {
            Some(outcome) => ExecutedEffect::reconciled(outcome),
            None => ExecutedEffect::ordinary(EffectOutcome::Indeterminate { evidence: None }),
        })
    }

    fn query_operation_truth(
        &self,
        request: &EffectRequest,
    ) -> Result<Option<EffectOutcome>, RuntimeError> {
        let journal = self
            .provider
            .operation(request.operation)
            .map_err(RuntimeError::Provider)?
            .and_then(|observed| observed.record.outcome)
            .filter(|outcome| !outcome.is_indeterminate());
        let resource = match request.kind {
            EffectKind::KeyValueRead { .. } | EffectKind::KeyValueCompareAndSet { .. } => self
                .provider
                .query_operation(request.operation, request.idempotency_key)
                .map_err(RuntimeError::Provider)?,
            _ => None,
        }
        .filter(|outcome| !outcome.is_indeterminate());
        match (journal, resource) {
            (Some(left), Some(right)) if left != right => {
                Err(RuntimeError::InvalidProviderOutcome { operation: request.operation })
            }
            (Some(outcome), _) | (_, Some(outcome)) => Ok(Some(outcome)),
            (None, None) => Ok(None),
        }
    }

    pub fn reconcile_effect(
        &mut self,
        operation: Identity,
    ) -> Result<CommandReceipt, RuntimeError> {
        let record = self
            .state
            .operations
            .iter()
            .find(|record| record.request.operation == operation)
            .cloned()
            .ok_or(RuntimeError::Rejected(Rejection::UnknownOperation { operation }))?;
        let reconciliation = match &record.outcome {
            None => false,
            Some(outcome) if outcome.is_indeterminate() => true,
            Some(_) => {
                return Err(RuntimeError::Rejected(Rejection::OperationAlreadyResolved {
                    operation,
                }));
            }
        };
        let outcome = self
            .query_operation_truth(&record.request)?
            .ok_or(RuntimeError::OperationOutcomeUnknown { operation })?;
        let (resolution, reconciled) =
            self.resolve_effect(&record.request, outcome.clone(), reconciliation, None)?;
        Ok(CommandReceipt::Effect(Box::new(EffectReceipt {
            intent: None,
            resolution,
            outcome,
            reconciled,
        })))
    }
}

impl<P> Coordinator<P>
where
    P: JournalPort + AuthorityPort + BindingPort,
{
    pub fn prepare_destination(
        &mut self,
        command: Identity,
        handoff_authority: AuthorityPlan,
        timer_authority: AuthorityPlan,
        key_value_authority: AuthorityPlan,
    ) -> Result<CommandReceipt, RuntimeError> {
        if let Some(prepared) = self.state.prepared_destination.clone() {
            return self
                .commit_command(Command::new(command, CommandKind::PrepareDestination(prepared)));
        }
        if self.state.phase != HandoffPhase::Exported {
            return Err(RuntimeError::Rejected(Rejection::InvalidPhase {
                actual: self.state.phase,
            }));
        }
        let snapshot =
            self.state.exported_snapshot.clone().ok_or(RuntimeError::SnapshotUnavailable)?;
        let result = self.prepare_destination_inner(
            command,
            &snapshot,
            handoff_authority,
            timer_authority,
            key_value_authority,
        );
        if let Err(error) = result {
            self.cleanup_preparation(snapshot.snapshot)?;
            return Err(error);
        }
        result
    }

    fn prepare_destination_inner(
        &mut self,
        command: Identity,
        snapshot: &SnapshotRecord,
        handoff_authority: AuthorityPlan,
        timer_authority: AuthorityPlan,
        key_value_authority: AuthorityPlan,
    ) -> Result<CommandReceipt, RuntimeError> {
        let component_generation = self
            .state
            .component
            .generation
            .next()
            .ok_or(RuntimeError::Rejected(Rejection::GenerationExhausted))?;
        let destination_subject =
            EntityRef::new(self.state.component.identity, component_generation);
        let next_epoch = self
            .state
            .ownership
            .epoch
            .next()
            .ok_or(RuntimeError::Rejected(Rejection::LeaseEpochExhausted))?;

        let handoff_grant = self.reauthorize_claim(
            snapshot.handoff,
            snapshot.snapshot,
            handoff_authority,
            destination_subject,
            destination_subject,
            Rights::HANDOFF,
        )?;
        let timer_grant = self.reauthorize_claim(
            snapshot.handoff,
            snapshot.snapshot,
            timer_authority,
            destination_subject,
            self.state.timer.claim.resource,
            self.state.timer.claim.required_rights,
        )?;
        let key_value_grant = self.reauthorize_claim(
            snapshot.handoff,
            snapshot.snapshot,
            key_value_authority,
            destination_subject,
            self.state.key_value.claim.resource,
            self.state.key_value.claim.required_rights,
        )?;

        let timer_request = BindingRequest {
            handoff: snapshot.handoff,
            snapshot: snapshot.snapshot,
            claim: self.state.timer.claim.resource,
            authority: timer_grant.authority,
            exposed_rights: self.state.timer.claim.required_rights,
            expected_owner: self
                .state
                .ownership
                .owner
                .ok_or(RuntimeError::Rejected(Rejection::SnapshotMismatch))?,
            expected_epoch: self.state.ownership.epoch,
            candidate_owner: self.state.activation.node,
            candidate_epoch: next_epoch,
            kind: BindingKind::PausedDurationTimer,
        };
        let timer_binding =
            self.provider.prepare_binding(timer_request).map_err(RuntimeError::Provider)?;
        let key_value_request = BindingRequest {
            handoff: snapshot.handoff,
            snapshot: snapshot.snapshot,
            claim: self.state.key_value.claim.resource,
            authority: key_value_grant.authority,
            exposed_rights: self.state.key_value.claim.required_rights,
            expected_owner: self
                .state
                .ownership
                .owner
                .ok_or(RuntimeError::Rejected(Rejection::SnapshotMismatch))?,
            expected_epoch: self.state.ownership.epoch,
            candidate_owner: self.state.activation.node,
            candidate_epoch: next_epoch,
            kind: BindingKind::KeyValueNamespace {
                namespace: self.state.key_value.claim.namespace,
            },
        };
        let key_value_binding =
            self.provider.prepare_binding(key_value_request).map_err(RuntimeError::Provider)?;

        let prepared = PreparedDestination {
            handoff: snapshot.handoff,
            snapshot: snapshot.snapshot,
            destination: self.state.activation.node,
            component_generation,
            expected_epoch: self.state.ownership.epoch,
            next_epoch,
            authorities: vec![handoff_grant, timer_grant, key_value_grant],
            bindings: vec![timer_binding, key_value_binding],
        };
        self.commit_command(Command::new(command, CommandKind::PrepareDestination(prepared)))
    }

    fn reauthorize_claim(
        &mut self,
        handoff: Identity,
        snapshot: Identity,
        plan: AuthorityPlan,
        subject: EntityRef,
        resource: EntityRef,
        required: Rights,
    ) -> Result<AuthorityGrant, RuntimeError> {
        let grant = self
            .provider
            .reauthorize(ReauthorizationRequest {
                handoff,
                snapshot,
                source_authority: plan.source_authority,
                destination_authority: plan.destination_authority,
                destination_subject: subject,
                resource,
                required_rights: required,
            })
            .map_err(RuntimeError::Provider)?;
        validate_reauthorized_grant(&grant, plan, subject, resource, required)?;
        if grant.rights == required {
            return Ok(grant);
        }

        let derived = AuthorityGrant {
            authority: plan.attenuated_authority,
            parent: Some(plan.source_authority),
            subject,
            resource,
            rights: required,
            status: AuthorityStatus::Active,
        };
        let attenuated = self
            .provider
            .attenuate(handoff, snapshot, plan.source_authority, &derived)
            .map_err(RuntimeError::Provider)?;
        if attenuated != derived {
            return Err(RuntimeError::InvalidAuthorityGrant { authority: attenuated.authority });
        }
        Ok(attenuated)
    }

    pub fn abort_handoff(
        &mut self,
        command: Identity,
        evidence: Option<EvidenceRef>,
        cleanup_evidence: Option<EvidenceRef>,
    ) -> Result<AbortReceipt, RuntimeError> {
        let snapshot = self
            .state
            .exported_snapshot
            .as_ref()
            .map(|record| record.snapshot)
            .or_else(|| self.state.preparation_cleanup.map(|cleanup| cleanup.snapshot));
        let abort =
            self.commit_command(Command::new(command, CommandKind::AbortHandoff { evidence }))?;
        let cleanup = if let Some(snapshot) = snapshot {
            self.cleanup_preparation(snapshot)?;
            let cleanup_identity = derived_identity(snapshot, b"cleanup-preparation")?;
            Some(self.commit_command(Command::new(
                cleanup_identity,
                CommandKind::CleanupPreparation { snapshot, evidence: cleanup_evidence },
            ))?)
        } else {
            None
        };
        Ok(AbortReceipt { abort, cleanup })
    }

    fn cleanup_preparation(&mut self, snapshot: Identity) -> Result<(), RuntimeError> {
        let mut first_error = None;
        for resource in self.fenced_resources() {
            if let Err(error) = self.provider.cleanup_binding(snapshot, resource)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Err(error) = self.provider.revoke_prepared(snapshot)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        match first_error {
            Some(error) => Err(RuntimeError::PreparationCleanupFailed(error)),
            None => Ok(()),
        }
    }

    pub fn cleanup_snapshot_bindings(&mut self, snapshot: Identity) -> Result<(), RuntimeError> {
        let resources = self.fenced_resources();
        for resource in resources {
            self.provider.cleanup_binding(snapshot, resource).map_err(RuntimeError::Provider)?;
        }
        Ok(())
    }
}

impl<P> Coordinator<P>
where
    P: JournalPort + LeasePort + TimerPort,
{
    pub fn poll_timer(&mut self) -> Result<TimerPoll, RuntimeError> {
        let (arm_operation, _remaining) = match self.state.timer.status {
            TimerStatus::Idle => return Ok(TimerPoll::Idle),
            TimerStatus::Completed => return Ok(TimerPoll::Completed),
            TimerStatus::Cancelled => return Ok(TimerPoll::Cancelled),
            TimerStatus::Cleaned => return Ok(TimerPoll::Cleaned),
            TimerStatus::Frozen(disposition) => return Ok(TimerPoll::Frozen(disposition)),
            TimerStatus::Armed { remaining } => (
                self.state
                    .timer
                    .active_operation
                    .ok_or(RuntimeError::Rejected(Rejection::TimerStateConflict))?,
                remaining,
            ),
        };
        self.provider
            .check_lease(
                self.state.timer.claim.resource,
                self.state.activation.node,
                self.state.ownership.epoch,
            )
            .map_err(RuntimeError::Provider)?;
        match self.provider.observe(arm_operation).map_err(RuntimeError::Provider)? {
            TimerObservation::Pending(remaining) => {
                Ok(TimerPoll::Pending { arm_operation, remaining })
            }
            TimerObservation::Completed { evidence } => {
                let completion = derived_identity(arm_operation, b"timer-completed")?;
                let receipt = self.timer_completed(completion, arm_operation, evidence)?;
                Ok(TimerPoll::Fired { arm_operation, evidence, receipt: Box::new(receipt) })
            }
            TimerObservation::Cancelled { evidence } => {
                Ok(TimerPoll::CancelledObserved { arm_operation, evidence })
            }
            TimerObservation::Absent => Ok(TimerPoll::Absent { arm_operation }),
        }
    }

    pub fn prepare_safe_point(&mut self) -> Result<SafePoint, RuntimeError> {
        if self.state.phase == HandoffPhase::Frozen {
            let TimerStatus::Frozen(disposition) = self.state.timer.status else {
                return Err(RuntimeError::Rejected(Rejection::TimerStateConflict));
            };
            return Ok(safe_point_from_disposition(disposition, None));
        }
        if self.state.phase != HandoffPhase::Quiescing {
            return Err(RuntimeError::Rejected(Rejection::InvalidPhase {
                actual: self.state.phase,
            }));
        }

        match self.state.timer.status {
            TimerStatus::Idle => Ok(safe_point_from_disposition(TimerDisposition::Idle, None)),
            TimerStatus::Completed => {
                Ok(safe_point_from_disposition(TimerDisposition::Completed, None))
            }
            TimerStatus::Cancelled => {
                Ok(safe_point_from_disposition(TimerDisposition::Cancelled, None))
            }
            TimerStatus::Cleaned => {
                Ok(safe_point_from_disposition(TimerDisposition::Cleaned, None))
            }
            TimerStatus::Frozen(disposition) => Ok(safe_point_from_disposition(disposition, None)),
            TimerStatus::Armed { .. } => {
                let arm_operation = self
                    .state
                    .timer
                    .active_operation
                    .ok_or(RuntimeError::Rejected(Rejection::TimerStateConflict))?;
                match self.provider.suspend_timer(arm_operation).map_err(RuntimeError::Provider)? {
                    TimerObservation::Pending(remaining) => Ok(SafePoint {
                        timer: SafePointTimer::Pending { remaining, arm_operation },
                        disposition: TimerDisposition::Pending { remaining, arm_operation },
                        suspended_arm: Some(arm_operation),
                    }),
                    TimerObservation::Completed { evidence } => {
                        let completion = derived_identity(arm_operation, b"timer-completed")?;
                        self.timer_completed(completion, arm_operation, evidence)?;
                        Ok(SafePoint {
                            timer: SafePointTimer::Completed { arm_operation: Some(arm_operation) },
                            disposition: TimerDisposition::Completed,
                            suspended_arm: None,
                        })
                    }
                    TimerObservation::Cancelled { .. } | TimerObservation::Absent => {
                        Err(RuntimeError::Rejected(Rejection::TimerStateConflict))
                    }
                }
            }
        }
    }

    pub fn commit_safe_point(
        &mut self,
        command: Identity,
        portable_state: Vec<u8>,
        safe_point: SafePoint,
    ) -> Result<CommandReceipt, RuntimeError> {
        if !safe_point_matches_state(&safe_point, &self.state) {
            return Err(RuntimeError::InvalidSafePoint);
        }
        match self.commit_freeze(command, portable_state, safe_point.disposition) {
            Ok(receipt) => Ok(receipt),
            Err(freeze_error) => {
                if let Some(arm_operation) = safe_point.suspended_arm
                    && let Err(error) = self.provider.resume_suspended(arm_operation)
                {
                    return Err(RuntimeError::SafePointRollbackFailed { arm_operation, error });
                }
                Err(freeze_error)
            }
        }
    }

    pub fn cancel_safe_point(&mut self, safe_point: SafePoint) -> Result<(), RuntimeError> {
        if let Some(arm_operation) = safe_point.suspended_arm {
            self.provider.resume_suspended(arm_operation).map_err(RuntimeError::Provider)?;
        }
        Ok(())
    }

    pub fn resume_source(
        &mut self,
        command: Identity,
    ) -> Result<SourceResumeReceipt, RuntimeError> {
        let command = Command::new(command, CommandKind::ResumeSource);
        let decision = preflight(&self.state, &command);
        let timer = source_resume_disposition(&self.state)?;
        match decision {
            Decision::Commit(event) => {
                let owner = self
                    .state
                    .ownership
                    .owner
                    .ok_or(RuntimeError::Rejected(Rejection::EventNotApplicable))?;
                for resource in self.fenced_resources() {
                    self.provider
                        .check_lease(resource, owner, self.state.ownership.epoch)
                        .map_err(RuntimeError::Provider)?;
                }
                if let TimerDisposition::Pending { arm_operation, .. } = timer {
                    self.provider
                        .resume_suspended(arm_operation)
                        .map_err(RuntimeError::Provider)?;
                }
                let (entry, next) = self.build_entry(event)?;
                let receipt = self.append_entry(entry, next).map(CommandReceipt::Committed)?;
                Ok(SourceResumeReceipt { receipt, timer })
            }
            Decision::Replay(replay) => {
                let owner = self
                    .state
                    .ownership
                    .owner
                    .ok_or(RuntimeError::Rejected(Rejection::EventNotApplicable))?;
                for resource in self.fenced_resources() {
                    self.provider
                        .check_lease(resource, owner, self.state.ownership.epoch)
                        .map_err(RuntimeError::Provider)?;
                }
                Ok(SourceResumeReceipt { receipt: CommandReceipt::Replayed(replay), timer })
            }
            Decision::Reject(rejection) => Err(RuntimeError::Rejected(rejection)),
            Decision::Execute { request, .. } => {
                Err(RuntimeError::InvalidProviderOutcome { operation: request.operation })
            }
        }
    }

    pub fn cleanup_operation(
        &mut self,
        command: Identity,
        operation: Identity,
        evidence: EvidenceRef,
    ) -> Result<CommandReceipt, RuntimeError> {
        let record = self
            .state
            .operations
            .iter()
            .find(|record| record.request.operation == operation)
            .cloned()
            .ok_or(RuntimeError::Rejected(Rejection::UnknownOperation { operation }))?;
        if record.cleanup != CleanupStatus::Cleaned {
            match record.request.kind {
                EffectKind::TimerArm { .. } => {
                    self.provider.cleanup_timer(operation).map_err(RuntimeError::Provider)?
                }
                EffectKind::TimerCancel { target_operation } => {
                    self.provider.cleanup_timer(target_operation).map_err(RuntimeError::Provider)?
                }
                _ => {}
            }
        }
        self.commit_command(Command::new(
            command,
            CommandKind::CleanupOperation { operation, evidence },
        ))
    }
}

fn validate_reauthorized_grant(
    grant: &AuthorityGrant,
    plan: AuthorityPlan,
    subject: EntityRef,
    resource: EntityRef,
    required: Rights,
) -> Result<(), RuntimeError> {
    if grant.authority != plan.destination_authority
        || grant.parent != Some(plan.source_authority)
        || grant.subject != subject
        || grant.resource != resource
        || grant.status != AuthorityStatus::Active
    {
        return Err(RuntimeError::InvalidAuthorityGrant { authority: grant.authority });
    }
    if !grant.rights.contains(required) {
        return Err(RuntimeError::Rejected(Rejection::InsufficientAuthority {
            required,
            granted: grant.rights,
        }));
    }
    Ok(())
}

fn safe_point_from_disposition(
    disposition: TimerDisposition,
    completed_arm: Option<Identity>,
) -> SafePoint {
    let timer = match disposition {
        TimerDisposition::Idle => SafePointTimer::Idle,
        TimerDisposition::Pending { remaining, arm_operation } => {
            SafePointTimer::Pending { remaining, arm_operation }
        }
        TimerDisposition::Completed => SafePointTimer::Completed { arm_operation: completed_arm },
        TimerDisposition::Cancelled => SafePointTimer::Cancelled,
        TimerDisposition::Cleaned => SafePointTimer::Cleaned,
    };
    SafePoint { timer, disposition, suspended_arm: None }
}

fn safe_point_matches_state(safe_point: &SafePoint, state: &CanonicalState) -> bool {
    if state.phase == HandoffPhase::Frozen {
        return state.timer.status == TimerStatus::Frozen(safe_point.disposition);
    }
    if state.phase != HandoffPhase::Quiescing {
        return false;
    }
    match (safe_point.disposition, state.timer.status) {
        (TimerDisposition::Idle, TimerStatus::Idle)
        | (TimerDisposition::Completed, TimerStatus::Completed)
        | (TimerDisposition::Cancelled, TimerStatus::Cancelled)
        | (TimerDisposition::Cleaned, TimerStatus::Cleaned) => true,
        (TimerDisposition::Pending { arm_operation, .. }, TimerStatus::Armed { .. }) => {
            state.timer.active_operation == Some(arm_operation)
        }
        _ => false,
    }
}

fn source_resume_disposition(state: &CanonicalState) -> Result<TimerDisposition, RuntimeError> {
    match state.timer.status {
        TimerStatus::Frozen(disposition) => Ok(disposition),
        TimerStatus::Idle => Ok(TimerDisposition::Idle),
        TimerStatus::Completed => Ok(TimerDisposition::Completed),
        TimerStatus::Cancelled => Ok(TimerDisposition::Cancelled),
        TimerStatus::Cleaned => Ok(TimerDisposition::Cleaned),
        TimerStatus::Armed { remaining } => state
            .timer
            .active_operation
            .map(|arm_operation| TimerDisposition::Pending { remaining, arm_operation })
            .ok_or(RuntimeError::Rejected(Rejection::TimerStateConflict)),
    }
}

fn required_rights(kind: &EffectKind) -> Rights {
    match kind {
        EffectKind::TimerArm { .. } => Rights::TIMER_ARM,
        EffectKind::TimerCancel { .. } => Rights::TIMER_CANCEL,
        EffectKind::KeyValueRead { .. } => Rights::KV_READ,
        EffectKind::KeyValueCompareAndSet { .. } => Rights::KV_WRITE,
        EffectKind::LeaseCommit { .. } => Rights::HANDOFF,
    }
}

fn provider_failure(error: ProviderError) -> EffectOutcome {
    if error.kind == ProviderErrorKind::Unsupported {
        return EffectOutcome::Unsupported { evidence: None };
    }
    let class = match error.kind {
        ProviderErrorKind::Denied | ProviderErrorKind::Revoked => FailureClass::Denied,
        ProviderErrorKind::Conflict
        | ProviderErrorKind::NotFound
        | ProviderErrorKind::StaleGeneration
        | ProviderErrorKind::StaleEpoch => FailureClass::Conflict,
        ProviderErrorKind::Unavailable | ProviderErrorKind::Storage => FailureClass::Unavailable,
        ProviderErrorKind::Integrity => FailureClass::Integrity,
        ProviderErrorKind::InvalidRequest | ProviderErrorKind::OutcomeUnknown => {
            FailureClass::Internal
        }
        ProviderErrorKind::Unsupported => unreachable!(),
    };
    EffectOutcome::Failed(EffectFailure { class, retryable: error.retryable, evidence: None })
}

struct ExecutedEffect {
    outcome: EffectOutcome,
    reconciled: bool,
    lease_transitions: Option<Vec<LeaseTransition>>,
}

impl ExecutedEffect {
    fn ordinary(outcome: EffectOutcome) -> Self {
        Self { outcome, reconciled: false, lease_transitions: None }
    }

    fn reconciled(outcome: EffectOutcome) -> Self {
        Self { outcome, reconciled: true, lease_transitions: None }
    }
}

fn derived_identity(operation: Identity, domain: &[u8]) -> Result<Identity, RuntimeError> {
    let digest = canonical_digest(&(operation, domain))?;
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&digest.0[..16]);
    Ok(Identity::from_bytes(identity))
}

fn infallible_state_digest(state: &CanonicalState) -> Digest {
    state_digest(state).expect("canonical state serialization cannot fail")
}
