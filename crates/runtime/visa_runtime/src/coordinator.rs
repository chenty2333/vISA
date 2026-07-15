use alloc::{boxed::Box, vec, vec::Vec};

use contract_core::{
    ActivationRole, ActivationStatus, AuthorityGrant, AuthorityStatus, CONTRACT_VERSION,
    CanonicalState, CleanupStatus, Command, CommandKind, Decision, Digest, EffectFailure,
    EffectKind, EffectOutcome, EffectRequest, EffectResult, EntityRef, Event, EventKind,
    EvidenceKind, EvidenceRef, ExtensionSupport, FailureClass, HandoffPhase, IdempotencyKey,
    Identity, JournalEntry, JournalPosition, LeaseEpoch, NodeIdentity, PreparedDestination,
    Rejection, Replay, Rights, SchemaVersion, SnapshotEnvelope, SnapshotRecord, TimerDisposition,
    TimerStatus,
};
use semantic_core::{ReplayError, apply, preflight, replay, replay_from, restore};
use substrate_api::{
    ActivationBundle, AuthorityPort, BindingKind, BindingPort, BindingRequest, CommitBundle,
    DestinationActivationProjectionRequest, ExternalHandoffProjectionPort,
    ExternalSourceFenceBundle, JournalPort, KvPort, LeasePort, LeaseRecord, LeaseTransition,
    ProfilePort, ProviderError, ProviderErrorKind, ReauthorizationRequest,
    SourceAbortProjectionRequest, TimerObservation, TimerPort, TimerRecovery,
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
pub struct ProfileAuthorityPlan {
    pub profile: Identity,
    pub resource: EntityRef,
    pub authority: AuthorityPlan,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationResumePreview {
    pub journal_position: JournalPosition,
    pub state_digest: Digest,
    /// Exact durable joint-log authorization record bound into the resume event.
    pub activation_record_digest: Digest,
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
        let mut resources = vec![self.state.timer.claim.resource];
        if !resources.contains(&self.state.key_value.claim.resource) {
            resources.push(self.state.key_value.claim.resource);
        }
        for grant in &self.state.authorities {
            if grant.status == AuthorityStatus::Active
                && grant.rights.contains(Rights::REBIND)
                && !resources.contains(&grant.resource)
            {
                resources.push(grant.resource);
            }
        }
        resources
    }
}

impl<P> Coordinator<P>
where
    P: JournalPort + AuthorityPort + LeasePort + KvPort + TimerPort + ProfilePort,
{
    pub fn commit_handoff(
        &mut self,
        command: Identity,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<CommandReceipt, RuntimeError> {
        let request = self.handoff_commit_request(operation, idempotency_key)?;
        self.effect(command, request)
    }

    /// Recompute the exact provider request digest for the currently prepared
    /// destination without executing it.
    pub fn handoff_commit_request_digest(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<Digest, RuntimeError> {
        Ok(self.handoff_commit_request(operation, idempotency_key)?.request_digest)
    }

    /// Joint-handoff variant. `resume_guard` is retained as the lease-commit
    /// causal parent, making a generic `ResumeDestination` distinguishable
    /// from the receipt-authorized exact resume path after recovery.
    pub fn guarded_handoff_commit_request_digest(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
        resume_guard: Identity,
    ) -> Result<Digest, RuntimeError> {
        Ok(self
            .handoff_commit_request_with_guard(operation, idempotency_key, Some(resume_guard))?
            .request_digest)
    }

    fn handoff_commit_request(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
    ) -> Result<EffectRequest, RuntimeError> {
        self.handoff_commit_request_with_guard(operation, idempotency_key, None)
    }

    fn handoff_commit_request_with_guard(
        &self,
        operation: Identity,
        idempotency_key: IdempotencyKey,
        resume_guard: Option<Identity>,
    ) -> Result<EffectRequest, RuntimeError> {
        if resume_guard == Some(Identity::ZERO) {
            return Err(RuntimeError::Rejected(Rejection::InvalidIdentity));
        }
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
            resume_guard,
            prepared.destination,
            subject,
            authority,
            kind.clone(),
        ))?;
        Ok(EffectRequest {
            operation,
            idempotency_key,
            causal_parent: resume_guard,
            node: prepared.destination,
            subject,
            resource: subject,
            authority,
            lease_epoch: prepared.expected_epoch,
            request_digest,
            kind,
        })
    }

    /// Execute or reconcile only the destination lease-commit projection. The
    /// canonical state remains `Committed`; workload admission stays closed
    /// until a separately durable activation receipt authorizes the exact
    /// `DestinationResumed` output.
    ///
    /// This is a trusted joint-composition primitive, not a workload-facing
    /// API. Possession of a second raw `Coordinator` handle is outside the
    /// bounded stage's exclusive-coordinator TCB assumption.
    #[doc(hidden)]
    pub fn project_destination_commit(
        &mut self,
        projection: DestinationActivationProjectionRequest,
    ) -> Result<(), RuntimeError> {
        let request = self.destination_projection_request(&projection)?;
        match self.inspect_destination_projection(&projection, &request, None)? {
            DestinationProjectionProgress::Committed | DestinationProjectionProgress::Resumed => {
                return Ok(());
            }
            DestinationProjectionProgress::PreState
            | DestinationProjectionProgress::IntentPending => {}
        }
        self.effect(projection.commit_command, request.clone())?;
        if self.inspect_destination_projection(&projection, &request, None)?
            != DestinationProjectionProgress::Committed
        {
            return Err(self.projection_conflict());
        }
        Ok(())
    }

    /// Compute the exact next journal position and state digest without
    /// appending a provider record. After a replayed resume, this returns the
    /// already committed output for the same command.
    #[doc(hidden)]
    pub fn preview_destination_resume(
        &self,
        projection: DestinationActivationProjectionRequest,
        activation_record_digest: Digest,
    ) -> Result<DestinationResumePreview, RuntimeError> {
        if activation_record_digest == Digest::ZERO {
            return Err(self.projection_conflict());
        }
        let request = self.destination_projection_request(&projection)?;
        match self.inspect_destination_projection(
            &projection,
            &request,
            Some(activation_record_digest),
        )? {
            DestinationProjectionProgress::PreState
            | DestinationProjectionProgress::IntentPending => Err(self.projection_conflict()),
            DestinationProjectionProgress::Committed => {
                let event = Event::new(
                    projection.resume_command,
                    EventKind::JointDestinationResumed { activation_record_digest },
                );
                let (entry, _) = self.build_entry(event)?;
                Ok(DestinationResumePreview {
                    journal_position: entry.position,
                    state_digest: entry.output_state,
                    activation_record_digest,
                })
            }
            DestinationProjectionProgress::Resumed => {
                let entries = self.provider.replay_from(None).map_err(RuntimeError::Provider)?;
                let resume = unique_event(&entries, projection.resume_command)?
                    .ok_or_else(|| self.projection_conflict())?;
                if !matches!(
                    resume.event.kind,
                    EventKind::JointDestinationResumed { activation_record_digest }
                        if activation_record_digest != Digest::ZERO
                ) {
                    return Err(RuntimeError::JournalConflict { position: resume.position });
                }
                Ok(DestinationResumePreview {
                    journal_position: resume.position,
                    state_digest: resume.output_state,
                    activation_record_digest,
                })
            }
        }
    }

    /// Append or reconcile the exact resume output authorized by a durable
    /// activation receipt.
    #[doc(hidden)]
    pub fn project_destination_resume(
        &mut self,
        projection: DestinationActivationProjectionRequest,
        activation_record_digest: Digest,
        expected: DestinationResumePreview,
    ) -> Result<(), RuntimeError> {
        if activation_record_digest == Digest::ZERO
            || expected.activation_record_digest != activation_record_digest
            || self.preview_destination_resume(projection, activation_record_digest)? != expected
        {
            return Err(self.projection_conflict());
        }
        let request = self.destination_projection_request(&projection)?;
        if self.inspect_destination_projection(&projection, &request, None)?
            == DestinationProjectionProgress::Committed
        {
            self.commit_event(Event::new(
                projection.resume_command,
                EventKind::JointDestinationResumed { activation_record_digest },
            ))?;
        }
        if self.inspect_destination_projection(
            &projection,
            &request,
            Some(activation_record_digest),
        )? != DestinationProjectionProgress::Resumed
            || self.preview_destination_resume(projection, activation_record_digest)? != expected
        {
            return Err(self.projection_conflict());
        }
        Ok(())
    }

    fn destination_projection_request(
        &self,
        projection: &DestinationActivationProjectionRequest,
    ) -> Result<EffectRequest, RuntimeError> {
        validate_destination_projection_request(projection)?;
        let timer_profile_matches = match self.state.phase {
            HandoffPhase::DestinationPrepared | HandoffPhase::Committed => {
                self.state.timer.status == TimerStatus::Frozen(TimerDisposition::Idle)
            }
            HandoffPhase::Running => {
                self.state.activation.role == ActivationRole::Destination
                    && self.state.activation.status == ActivationStatus::Active
                    && self.state.timer.status == TimerStatus::Idle
            }
            _ => false,
        };
        if !timer_profile_matches {
            return Err(RuntimeError::Rejected(Rejection::TimerStateConflict));
        }
        let request = self.handoff_commit_request_with_guard(
            projection.commit_operation,
            projection.commit_idempotency,
            Some(projection.resume_command),
        )?;
        if request.request_digest != projection.request_digest
            || !matches!(
                request.kind,
                EffectKind::LeaseCommit { handoff, .. } if handoff == projection.handoff
            )
        {
            return Err(self.projection_conflict());
        }
        Ok(request)
    }

    fn inspect_destination_projection(
        &self,
        projection: &DestinationActivationProjectionRequest,
        request: &EffectRequest,
        expected_activation_record_digest: Option<Digest>,
    ) -> Result<DestinationProjectionProgress, RuntimeError> {
        let entries = self.provider.replay_from(None).map_err(RuntimeError::Provider)?;
        let intent = unique_event(&entries, projection.commit_command)?;
        let resume = unique_event(&entries, projection.resume_command)?;
        let operation_entries = operation_entries(&entries, projection.commit_operation);

        let Some(intent) = intent else {
            if resume.is_some()
                || !operation_entries.is_empty()
                || self
                    .provider
                    .operation(projection.commit_operation)
                    .map_err(RuntimeError::Provider)?
                    .is_some()
                || self
                    .provider
                    .idempotency(projection.commit_idempotency)
                    .map_err(RuntimeError::Provider)?
                    .is_some()
                || self.state.phase != HandoffPhase::DestinationPrepared
            {
                return Err(self.projection_conflict());
            }
            return Ok(DestinationProjectionProgress::PreState);
        };
        if !matches!(&intent.event.kind, EventKind::EffectPrepared { request: actual } if actual == request)
        {
            return Err(RuntimeError::JournalConflict { position: intent.position });
        }

        let by_operation = self
            .provider
            .operation(projection.commit_operation)
            .map_err(RuntimeError::Provider)?
            .ok_or_else(|| self.projection_conflict())?;
        let by_idempotency = self
            .provider
            .idempotency(projection.commit_idempotency)
            .map_err(RuntimeError::Provider)?
            .ok_or_else(|| self.projection_conflict())?;
        if by_operation != by_idempotency || by_operation.record.request != *request {
            return Err(self.projection_conflict());
        }

        let resolution = operation_entries
            .iter()
            .copied()
            .find(|entry| matches!(entry.event.kind, EventKind::HandoffCommitted { .. }));
        if operation_entries.len() != usize::from(resolution.is_some()) + 1
            || operation_entries.first().copied() != Some(intent)
        {
            return Err(self.projection_conflict());
        }
        let Some(resolution) = resolution else {
            if resume.is_some() || self.state.phase != HandoffPhase::DestinationPrepared {
                return Err(self.projection_conflict());
            }
            return Ok(DestinationProjectionProgress::IntentPending);
        };
        if intent.position.next() != Some(resolution.position)
            || resolution.event.identity
                != derived_identity(projection.commit_operation, b"resolve")?
        {
            return Err(RuntimeError::JournalConflict { position: resolution.position });
        }

        let EffectKind::LeaseCommit { handoff, snapshot, destination, expected_epoch, next_epoch } =
            request.kind
        else {
            return Err(self.projection_conflict());
        };
        let EventKind::HandoffCommitted {
            operation,
            handoff: committed_handoff,
            snapshot: committed_snapshot,
            source,
            destination: committed_destination,
            previous_epoch,
            new_epoch,
            outcome,
        } = &resolution.event.kind
        else {
            return Err(RuntimeError::JournalConflict { position: resolution.position });
        };
        let EffectOutcome::Succeeded {
            result: EffectResult::LeaseAdvanced { owner, epoch, source_fence },
            evidence,
        } = outcome
        else {
            return Err(RuntimeError::JournalConflict { position: resolution.position });
        };
        if *operation != projection.commit_operation
            || *committed_handoff != handoff
            || *committed_snapshot != snapshot
            || source.is_zero()
            || *source == destination
            || *committed_destination != destination
            || *previous_epoch != expected_epoch
            || *new_epoch != next_epoch
            || *owner != destination
            || *epoch != next_epoch
            || !matches!(evidence.kind, EvidenceKind::EffectOutcome | EvidenceKind::LeaseCommit)
            || evidence.identity.is_zero()
            || evidence.digest == Digest::ZERO
            || source_fence.kind != EvidenceKind::SourceFence
            || source_fence.identity.is_zero()
            || source_fence.digest == Digest::ZERO
            || evidence.digest == source_fence.digest
            || by_operation.record.outcome.as_ref() != Some(outcome)
        {
            return Err(RuntimeError::JournalConflict { position: resolution.position });
        }
        self.verify_projection_leases(destination, next_epoch)?;

        let Some(resume) = resume else {
            if self.state.phase != HandoffPhase::Committed
                || self.position != resolution.position
                || self.state_digest()? != resolution.output_state
            {
                return Err(self.projection_conflict());
            }
            return Ok(DestinationProjectionProgress::Committed);
        };
        if !matches!(
            resume.event.kind,
            EventKind::JointDestinationResumed { activation_record_digest }
                if activation_record_digest != Digest::ZERO
                    && expected_activation_record_digest
                        .is_none_or(|expected| expected == activation_record_digest)
        ) || resolution.position.next() != Some(resume.position)
            || self.position != resume.position
            || self.state_digest()? != resume.output_state
            || self.state.phase != HandoffPhase::Running
            || self.state.activation.role != ActivationRole::Destination
            || self.state.activation.status != ActivationStatus::Active
            || self.state.ownership != contract_core::Ownership::owned(destination, next_epoch)
        {
            return Err(RuntimeError::JournalConflict { position: resume.position });
        }
        Ok(DestinationProjectionProgress::Resumed)
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
        if let Some(outcome) = self.query_operation_truth(&request, false)? {
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
            EffectKind::Profile { profile, .. } => {
                let extension =
                    self.state.extensions.iter().find(|extension| extension.id == *profile).ok_or(
                        RuntimeError::Rejected(Rejection::UnknownProfile { id: *profile }),
                    )?;
                self.provider.execute_profile(request, extension)
            }
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
        &mut self,
        request: &EffectRequest,
        error: ProviderError,
    ) -> Result<ExecutedEffect, RuntimeError> {
        if error.kind != ProviderErrorKind::OutcomeUnknown {
            if error.retryable {
                // Keep the durable intent unresolved. Replaying the same
                // operation/idempotency pair will retry provider execution;
                // resolving a transient failure would make it permanent.
                return Err(RuntimeError::Provider(error));
            }
            return Ok(ExecutedEffect::ordinary(provider_failure(error)));
        }
        Ok(match self.query_operation_truth(request, false)? {
            Some(outcome) => ExecutedEffect::reconciled(outcome),
            None => ExecutedEffect::ordinary(EffectOutcome::Indeterminate { evidence: None }),
        })
    }

    fn query_operation_truth(
        &mut self,
        request: &EffectRequest,
        reconcile_profile: bool,
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
            EffectKind::Profile { profile, .. } if reconcile_profile => {
                let extension = self
                    .state
                    .extensions
                    .iter()
                    .find(|extension| extension.id == profile)
                    .cloned()
                    .ok_or(RuntimeError::Rejected(Rejection::UnknownProfile { id: profile }))?;
                self.provider
                    .reconcile_profile_operation(request, &extension)
                    .map_err(RuntimeError::Provider)?
            }
            EffectKind::Profile { .. } => self
                .provider
                .query_profile_operation(request.operation, request.idempotency_key)
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
            .query_operation_truth(&record.request, true)?
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
    P: JournalPort + LeasePort,
{
    fn projection_conflict(&self) -> RuntimeError {
        RuntimeError::JournalConflict { position: self.position }
    }

    fn verify_projection_leases(
        &self,
        owner: NodeIdentity,
        epoch: LeaseEpoch,
    ) -> Result<(), RuntimeError> {
        for resource in self.fenced_resources() {
            if self.provider.current_lease(resource).map_err(RuntimeError::Provider)?
                != Some(LeaseRecord { resource, owner, epoch })
            {
                return Err(self.projection_conflict());
            }
        }
        Ok(())
    }
}

impl<P> Coordinator<P>
where
    P: JournalPort + LeasePort + ExternalHandoffProjectionPort,
{
    /// Project an externally authoritative commit and completed source closure
    /// into the source canonical journal and local provider leases.
    ///
    /// The caller must validate the native ownership and closure receipts. This
    /// method binds their digests into the existing `HandoffCommitted` event;
    /// it never makes an ownership decision itself.
    #[allow(clippy::too_many_arguments)]
    pub fn project_external_source_fence(
        &mut self,
        command: Identity,
        operation: Identity,
        destination: NodeIdentity,
        next_epoch: LeaseEpoch,
        decision_evidence: EvidenceRef,
        closure_evidence: EvidenceRef,
    ) -> Result<CommandReceipt, RuntimeError> {
        if command.is_zero()
            || operation.is_zero()
            || destination.is_zero()
            || decision_evidence.identity.is_zero()
            || decision_evidence.digest == Digest::ZERO
            || decision_evidence.kind != contract_core::EvidenceKind::AuthorityDecision
            || closure_evidence.identity.is_zero()
            || closure_evidence.digest == Digest::ZERO
            || closure_evidence.kind != contract_core::EvidenceKind::SourceFence
            || decision_evidence.digest == closure_evidence.digest
        {
            return Err(RuntimeError::Rejected(Rejection::InvalidIdentity));
        }

        let snapshot = self
            .state
            .exported_snapshot
            .as_ref()
            .cloned()
            .ok_or(RuntimeError::SnapshotUnavailable)?;
        let source = self.state.activation.node;
        let previous_epoch = if self.state.phase == HandoffPhase::Committed {
            let EventKind::HandoffCommitted { previous_epoch, .. } = self
                .inspect_external_source_fence(
                    command,
                    operation,
                    &snapshot,
                    source,
                    destination,
                    next_epoch,
                    decision_evidence,
                    closure_evidence,
                )?
                .event
                .kind
            else {
                return Err(self.projection_conflict());
            };
            return if previous_epoch.next() == Some(next_epoch) {
                Ok(CommandReceipt::Replayed(Replay::NoChange))
            } else {
                Err(self.projection_conflict())
            };
        } else {
            if self.state.phase != HandoffPhase::Exported {
                return Err(RuntimeError::Rejected(Rejection::EventNotApplicable));
            }
            self.ensure_external_source_fence_absent(command, operation)?;
            self.state.ownership.epoch
        };
        let owner = self
            .state
            .ownership
            .owner
            .ok_or(RuntimeError::Rejected(Rejection::EventNotApplicable))?;
        if previous_epoch.next() != Some(next_epoch) || owner != source || source == destination {
            return Err(RuntimeError::Rejected(Rejection::LeaseEpochMismatch {
                expected: previous_epoch.next().unwrap_or(previous_epoch),
                actual: next_epoch,
            }));
        }

        let outcome = EffectOutcome::Succeeded {
            result: EffectResult::LeaseAdvanced {
                owner: destination,
                epoch: next_epoch,
                source_fence: closure_evidence,
            },
            evidence: decision_evidence,
        };
        let event = Event::new(
            command,
            EventKind::HandoffCommitted {
                operation,
                handoff: snapshot.handoff,
                snapshot: snapshot.snapshot,
                source,
                destination,
                previous_epoch,
                new_epoch: next_epoch,
                outcome,
            },
        );
        let (entry, next) = self.build_entry(event)?;
        let transitions = self
            .fenced_resources()
            .into_iter()
            .map(|resource| LeaseTransition {
                resource,
                expected_owner: source,
                next_owner: destination,
                expected_epoch: previous_epoch,
                next_epoch,
            })
            .collect::<Vec<_>>();
        let bundle = ExternalSourceFenceBundle {
            entry: entry.clone(),
            lease_transitions: transitions.clone(),
            decision_digest: decision_evidence.digest,
            closure_digest: closure_evidence.digest,
        };
        match self.provider.commit_external_source_fence(&bundle) {
            Ok(()) => {}
            Err(error) if error.kind == ProviderErrorKind::OutcomeUnknown => {
                let observed =
                    self.provider.entry(entry.position).map_err(RuntimeError::Provider)?;
                if observed.as_ref() != Some(&entry) {
                    return Err(RuntimeError::JournalOutcomeUnknown { position: entry.position });
                }
                for transition in &transitions {
                    let observed = self
                        .provider
                        .current_lease(transition.resource)
                        .map_err(RuntimeError::Provider)?;
                    if observed
                        != Some(LeaseRecord {
                            resource: transition.resource,
                            owner: destination,
                            epoch: next_epoch,
                        })
                    {
                        return Err(RuntimeError::JournalOutcomeUnknown {
                            position: entry.position,
                        });
                    }
                }
            }
            Err(error) => return Err(RuntimeError::Provider(error)),
        }
        let committed = self.publish(entry, next).map(CommandReceipt::Committed)?;
        self.inspect_external_source_fence(
            command,
            operation,
            &snapshot,
            source,
            destination,
            next_epoch,
            decision_evidence,
            closure_evidence,
        )?;
        Ok(committed)
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_external_source_fence(
        &self,
        command: Identity,
        operation: Identity,
        snapshot: &SnapshotRecord,
        source: NodeIdentity,
        destination: NodeIdentity,
        next_epoch: LeaseEpoch,
        decision_evidence: EvidenceRef,
        closure_evidence: EvidenceRef,
    ) -> Result<JournalEntry, RuntimeError> {
        let entries = self.provider.replay_from(None).map_err(RuntimeError::Provider)?;
        let entry = unique_event(&entries, command)?.ok_or_else(|| self.projection_conflict())?;
        let operation_entries = operation_entries(&entries, operation);
        if operation_entries != [entry]
            || self.provider.operation(operation).map_err(RuntimeError::Provider)?.is_some()
        {
            return Err(self.projection_conflict());
        }
        let EventKind::HandoffCommitted {
            operation: actual_operation,
            handoff,
            snapshot: actual_snapshot,
            source: actual_source,
            destination: actual_destination,
            previous_epoch,
            new_epoch,
            outcome,
        } = &entry.event.kind
        else {
            return Err(RuntimeError::JournalConflict { position: entry.position });
        };
        let expected_outcome = EffectOutcome::Succeeded {
            result: EffectResult::LeaseAdvanced {
                owner: destination,
                epoch: next_epoch,
                source_fence: closure_evidence,
            },
            evidence: decision_evidence,
        };
        if *actual_operation != operation
            || *handoff != snapshot.handoff
            || *actual_snapshot != snapshot.snapshot
            || *actual_source != source
            || *actual_destination != destination
            || previous_epoch.next() != Some(next_epoch)
            || *new_epoch != next_epoch
            || *outcome != expected_outcome
            || self.position != entry.position
            || self.state_digest()? != entry.output_state
            || self.state.phase != HandoffPhase::Committed
            || self.state.activation.role != ActivationRole::Source
            || self.state.activation.status != ActivationStatus::Fenced
            || self.state.ownership != contract_core::Ownership::owned(destination, next_epoch)
        {
            return Err(RuntimeError::JournalConflict { position: entry.position });
        }
        self.verify_projection_leases(destination, next_epoch)?;
        Ok(entry.clone())
    }

    fn ensure_external_source_fence_absent(
        &self,
        command: Identity,
        operation: Identity,
    ) -> Result<(), RuntimeError> {
        let entries = self.provider.replay_from(None).map_err(RuntimeError::Provider)?;
        if unique_event(&entries, command)?.is_some()
            || !operation_entries(&entries, operation).is_empty()
            || self.provider.operation(operation).map_err(RuntimeError::Provider)?.is_some()
        {
            return Err(self.projection_conflict());
        }
        Ok(())
    }
}

impl<P> Coordinator<P>
where
    P: JournalPort + AuthorityPort + BindingPort + LeasePort + TimerPort + ProfilePort,
{
    /// Execute or reconcile an exact source abort/cleanup/resume projection.
    /// Completed local work is accepted only when its full canonical lineage
    /// and retained source leases match the request.
    pub fn project_source_abort_and_resume(
        &mut self,
        projection: SourceAbortProjectionRequest,
    ) -> Result<(), RuntimeError> {
        validate_source_abort_projection_request(&projection)?;
        if self.inspect_source_abort_projection(&projection)? == ProjectionProgress::Terminal {
            return Ok(());
        }
        self.abort_handoff(
            projection.abort_command,
            Some(projection.abort_evidence),
            projection.thaw_evidence,
        )?;
        self.resume_source(projection.resume_command)?;
        if self.inspect_source_abort_projection(&projection)? != ProjectionProgress::Terminal {
            return Err(self.projection_conflict());
        }
        Ok(())
    }

    fn inspect_source_abort_projection(
        &self,
        projection: &SourceAbortProjectionRequest,
    ) -> Result<ProjectionProgress, RuntimeError> {
        let entries = self.provider.replay_from(None).map_err(RuntimeError::Provider)?;
        let abort = unique_event(&entries, projection.abort_command)?;
        let resume = unique_event(&entries, projection.resume_command)?;

        if !projection.local_freeze_recorded {
            if projection.snapshot.is_some()
                || abort.is_some()
                || resume.is_some()
                || self.state.phase != HandoffPhase::Running
                || self.state.activation.role != ActivationRole::Source
                || self.state.activation.status != ActivationStatus::Active
                || self.state.ownership.owner != Some(self.state.activation.node)
            {
                return Err(self.projection_conflict());
            }
            self.verify_projection_leases(self.state.activation.node, self.state.ownership.epoch)?;
            return Ok(ProjectionProgress::Terminal);
        }

        let cleanup = if let Some(snapshot) = projection.snapshot {
            let snapshot_entry = entries.iter().find(|entry| {
                matches!(
                    &entry.event.kind,
                    EventKind::SnapshotExported { snapshot: record }
                        if record.handoff == projection.handoff && record.snapshot == snapshot
                )
            });
            if snapshot_entry.is_none() {
                return Err(self.projection_conflict());
            }
            let cleanup_command = derived_identity(snapshot, b"cleanup-preparation")?;
            unique_event(&entries, cleanup_command)?
        } else {
            None
        };

        let Some(abort) = abort else {
            if cleanup.is_some()
                || resume.is_some()
                || !matches!(
                    self.state.phase,
                    HandoffPhase::Quiescing | HandoffPhase::Frozen | HandoffPhase::Exported
                )
            {
                return Err(self.projection_conflict());
            }
            return Ok(ProjectionProgress::PreState);
        };
        if !matches!(
            &abort.event.kind,
            EventKind::HandoffAborted { evidence } if *evidence == Some(projection.abort_evidence)
        ) {
            return Err(RuntimeError::JournalConflict { position: abort.position });
        }

        let tail = if let Some(snapshot) = projection.snapshot {
            let Some(cleanup) = cleanup else {
                if resume.is_some() || self.state.phase != HandoffPhase::Aborted {
                    return Err(self.projection_conflict());
                }
                return Ok(ProjectionProgress::Partial);
            };
            if !matches!(
                &cleanup.event.kind,
                EventKind::PreparationCleaned { cleanup: actual }
                    if actual.snapshot == snapshot
                        && actual.evidence == projection.thaw_evidence
            ) || abort.position.next() != Some(cleanup.position)
            {
                return Err(RuntimeError::JournalConflict { position: cleanup.position });
            }
            cleanup
        } else {
            if entries.iter().any(|entry| {
                entry.position.0 > abort.position.0
                    && matches!(entry.event.kind, EventKind::PreparationCleaned { .. })
            }) {
                return Err(self.projection_conflict());
            }
            abort
        };

        let Some(resume) = resume else {
            if self.state.phase != HandoffPhase::Aborted || self.position != tail.position {
                return Err(self.projection_conflict());
            }
            return Ok(ProjectionProgress::Partial);
        };
        if !matches!(resume.event.kind, EventKind::SourceResumed)
            || tail.position.next() != Some(resume.position)
            || self.position != resume.position
            || self.state_digest()? != resume.output_state
            || self.state.phase != HandoffPhase::Running
            || self.state.activation.role != ActivationRole::Source
            || self.state.activation.status != ActivationStatus::Active
            || self.state.ownership.owner != Some(self.state.activation.node)
            || self.state.exported_snapshot.is_some()
            || self.state.preparation_cleanup.is_some()
        {
            return Err(RuntimeError::JournalConflict { position: resume.position });
        }
        self.verify_projection_leases(self.state.activation.node, self.state.ownership.epoch)?;
        Ok(ProjectionProgress::Terminal)
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
        self.prepare_destination_with_profiles(
            command,
            handoff_authority,
            timer_authority,
            key_value_authority,
            &[],
        )
    }

    pub fn prepare_destination_with_profiles(
        &mut self,
        command: Identity,
        handoff_authority: AuthorityPlan,
        timer_authority: AuthorityPlan,
        key_value_authority: AuthorityPlan,
        profile_authorities: &[ProfileAuthorityPlan],
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
            profile_authorities,
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
        profile_authorities: &[ProfileAuthorityPlan],
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

        let mut authorities = vec![handoff_grant, timer_grant, key_value_grant];
        let mut bindings = vec![timer_binding, key_value_binding];
        let profile_resources = visa_profile::profile_resources(&self.state.extensions)
            .map_err(|_| RuntimeError::Rejected(Rejection::ProfileMismatch))?;
        if profile_resources.len() != profile_authorities.len() {
            return Err(RuntimeError::Rejected(Rejection::ProfileMismatch));
        }
        for resource in profile_resources {
            let mut matching = profile_authorities.iter().filter(|plan| {
                plan.profile == resource.profile && plan.resource == resource.resource
            });
            let plan = matching.next().ok_or(RuntimeError::Rejected(Rejection::ProfileMismatch))?;
            if matching.next().is_some() {
                return Err(RuntimeError::Rejected(Rejection::ProfileMismatch));
            }
            let grant = self.reauthorize_claim(
                snapshot.handoff,
                snapshot.snapshot,
                plan.authority,
                destination_subject,
                resource.resource,
                resource.required_rights,
            )?;
            let binding = self
                .provider
                .prepare_binding(BindingRequest {
                    handoff: snapshot.handoff,
                    snapshot: snapshot.snapshot,
                    claim: resource.resource,
                    authority: grant.authority,
                    exposed_rights: resource.required_rights,
                    expected_owner: self
                        .state
                        .ownership
                        .owner
                        .ok_or(RuntimeError::Rejected(Rejection::SnapshotMismatch))?,
                    expected_epoch: self.state.ownership.epoch,
                    candidate_owner: self.state.activation.node,
                    candidate_epoch: next_epoch,
                    kind: BindingKind::Profile { profile: resource.profile },
                })
                .map_err(RuntimeError::Provider)?;
            authorities.push(grant);
            bindings.push(binding);
        }

        let prepared = PreparedDestination {
            handoff: snapshot.handoff,
            snapshot: snapshot.snapshot,
            destination: self.state.activation.node,
            component_generation,
            expected_epoch: self.state.ownership.epoch,
            next_epoch,
            authorities,
            bindings,
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
        let cleanup_snapshot = self
            .state
            .exported_snapshot
            .as_ref()
            .map(|record| record.snapshot)
            .or_else(|| self.state.preparation_cleanup.map(|cleanup| cleanup.snapshot));
        if self.state.phase != HandoffPhase::Aborted || cleanup_snapshot != Some(snapshot) {
            return Err(RuntimeError::SnapshotUnavailable);
        }
        let resources = self.fenced_resources();
        for resource in resources {
            self.provider.cleanup_binding(snapshot, resource).map_err(RuntimeError::Provider)?;
        }
        Ok(())
    }
}

impl<P> Coordinator<P>
where
    P: JournalPort + LeasePort + TimerPort + ProfilePort,
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
        let command = Command::new(command, CommandKind::CleanupOperation { operation, evidence });
        match preflight(&self.state, &command) {
            Decision::Commit(_) => {}
            Decision::Replay(replay) => return Ok(CommandReceipt::Replayed(replay)),
            Decision::Reject(rejection) => return Err(RuntimeError::Rejected(rejection)),
            Decision::Execute { request, .. } => {
                return Err(RuntimeError::InvalidProviderOutcome { operation: request.operation });
            }
        }
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
                EffectKind::Profile { .. } => self
                    .provider
                    .cleanup_profile_operation(&record.request)
                    .map_err(RuntimeError::Provider)?,
                _ => {}
            }
        }
        self.commit_command(command)
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
        EffectKind::Profile { access, .. } => access.required_rights(),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProjectionProgress {
    PreState,
    Partial,
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DestinationProjectionProgress {
    PreState,
    IntentPending,
    Committed,
    Resumed,
}

fn validate_source_abort_projection_request(
    projection: &SourceAbortProjectionRequest,
) -> Result<(), RuntimeError> {
    if projection.handoff.is_zero()
        || projection.abort_command.is_zero()
        || projection.resume_command.is_zero()
        || projection.abort_command == projection.resume_command
        || projection.abort_evidence.identity.is_zero()
        || projection.abort_evidence.digest == Digest::ZERO
        || projection.abort_evidence.kind != EvidenceKind::AuthorityDecision
        || projection.snapshot.is_some_and(Identity::is_zero)
        || projection.thaw_evidence.is_some_and(|evidence| {
            evidence.identity.is_zero()
                || evidence.digest == Digest::ZERO
                || evidence.kind != EvidenceKind::Cleanup
                || evidence.digest == projection.abort_evidence.digest
        })
    {
        return Err(RuntimeError::Rejected(Rejection::InvalidIdentity));
    }
    Ok(())
}

fn validate_destination_projection_request(
    projection: &DestinationActivationProjectionRequest,
) -> Result<(), RuntimeError> {
    if projection.handoff.is_zero()
        || projection.commit_command.is_zero()
        || projection.commit_operation.is_zero()
        || projection.commit_idempotency.0 == [0; 16]
        || projection.request_digest == Digest::ZERO
        || projection.resume_command.is_zero()
        || projection.commit_command == projection.commit_operation
        || projection.commit_command == projection.resume_command
        || projection.commit_operation == projection.resume_command
    {
        return Err(RuntimeError::Rejected(Rejection::InvalidIdentity));
    }
    Ok(())
}

fn unique_event(
    entries: &[JournalEntry],
    identity: Identity,
) -> Result<Option<&JournalEntry>, RuntimeError> {
    let mut matches = entries.iter().filter(|entry| entry.event.identity == identity);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(RuntimeError::JournalConflict {
            position: first.map_or(JournalPosition::ORIGIN, |entry| entry.position),
        });
    }
    Ok(first)
}

fn operation_entries(entries: &[JournalEntry], operation: Identity) -> Vec<&JournalEntry> {
    entries
        .iter()
        .filter(|entry| match &entry.event.kind {
            EventKind::EffectPrepared { request } => request.operation == operation,
            EventKind::EffectResolved { operation: actual, .. }
            | EventKind::EffectReconciled { operation: actual, .. }
            | EventKind::OperationCleaned { operation: actual, .. }
            | EventKind::HandoffCommitted { operation: actual, .. } => *actual == operation,
            _ => false,
        })
        .collect()
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
