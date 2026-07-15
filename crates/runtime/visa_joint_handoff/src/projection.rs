use contract_core::{
    Activation, ActivationRole, ActivationStatus, CanonicalState, Digest, EntityRef, EvidenceKind,
    EvidenceRef, HandoffPhase, IdempotencyKey, Identity, JournalPosition, LeaseEpoch, NodeIdentity,
    Ownership, PreparedDestination, SnapshotRecord,
};
use joint_handoff_core::{
    ClosureStatus, JointPhase, JointState, OwnershipDecision, ReceiptKind, ReceiptRef,
};
use substrate_api::{
    AuthorityPort, BindingPort, DestinationActivationProjectionRequest,
    ExternalHandoffProjectionPort, JournalPort, KvPort, LeasePort, ProfilePort,
    SourceAbortProjectionRequest, TimerPort,
};
use visa_runtime::{Coordinator, RuntimeError};

use crate::VerifiedJointState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalProjection {
    pub journal_position: JournalPosition,
    pub state_digest: Digest,
    /// Present only for destination resume projections. Equality therefore
    /// authenticates the event payload as well as its resulting state.
    pub authorization_record_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceAbortCommands {
    pub abort: Identity,
    pub resume: Identity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceFenceCommand {
    pub command: Identity,
    pub operation: Identity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationActivationCommands {
    pub commit_command: Identity,
    pub commit_operation: Identity,
    pub commit_idempotency: IdempotencyKey,
    pub resume_command: Identity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaRuntimeBinding {
    pub component: EntityRef,
    pub component_digest: Digest,
    pub profile_digest: Digest,
    pub phase: HandoffPhase,
    pub activation: Activation,
    pub ownership: Ownership,
    pub exported_snapshot: Option<SnapshotRecord>,
    pub prepared_destination: Option<PreparedDestination>,
    pub journal_position: JournalPosition,
    pub state_digest: Digest,
}

impl VisaRuntimeBinding {
    fn from_state(
        state: &CanonicalState,
        journal_position: JournalPosition,
        state_digest: Digest,
    ) -> Self {
        Self {
            component: state.component,
            component_digest: state.component_digest,
            profile_digest: state.profile_digest,
            phase: state.phase,
            activation: state.activation,
            ownership: state.ownership,
            exported_snapshot: state.exported_snapshot.clone(),
            prepared_destination: state.prepared_destination.clone(),
            journal_position,
            state_digest,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectionError<E> {
    InvalidJointPhase { actual: JointPhase },
    EffectFreezeOutcomeUnknown,
    MissingReceipt,
    ReceiptMismatch,
    InvalidCommand,
    Runtime(E),
}

pub trait VisaSourceRuntime {
    type Error;

    fn joint_runtime_binding(&self) -> Result<VisaRuntimeBinding, Self::Error>;

    fn abort_and_resume(
        &mut self,
        handoff: Identity,
        snapshot: Option<Identity>,
        local_freeze_recorded: bool,
        commands: SourceAbortCommands,
        abort_evidence: EvidenceRef,
        thaw_evidence: Option<EvidenceRef>,
    ) -> Result<LocalProjection, Self::Error>;

    fn project_source_fence(
        &mut self,
        command: SourceFenceCommand,
        destination: NodeIdentity,
        next_epoch: LeaseEpoch,
        decision_evidence: EvidenceRef,
        closure_evidence: EvidenceRef,
    ) -> Result<LocalProjection, Self::Error>;
}

pub trait VisaDestinationRuntime {
    type Error;

    fn joint_runtime_binding(&self) -> Result<VisaRuntimeBinding, Self::Error>;

    fn destination_commit_request_digest(
        &self,
        operation: Identity,
        idempotency: IdempotencyKey,
        resume_guard: Identity,
    ) -> Result<Digest, Self::Error>;

    fn commit_for_activation(
        &mut self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
    ) -> Result<(), Self::Error>;

    fn preview_activation_resume(
        &self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
        activation_record_digest: Digest,
    ) -> Result<LocalProjection, Self::Error>;

    fn resume_after_activation_receipt(
        &mut self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
        activation_record_digest: Digest,
        expected: LocalProjection,
    ) -> Result<LocalProjection, Self::Error>;
}

impl<T> VisaSourceRuntime for &mut T
where
    T: VisaSourceRuntime + ?Sized,
{
    type Error = T::Error;

    fn joint_runtime_binding(&self) -> Result<VisaRuntimeBinding, Self::Error> {
        (**self).joint_runtime_binding()
    }

    fn abort_and_resume(
        &mut self,
        handoff: Identity,
        snapshot: Option<Identity>,
        local_freeze_recorded: bool,
        commands: SourceAbortCommands,
        abort_evidence: EvidenceRef,
        thaw_evidence: Option<EvidenceRef>,
    ) -> Result<LocalProjection, Self::Error> {
        (**self).abort_and_resume(
            handoff,
            snapshot,
            local_freeze_recorded,
            commands,
            abort_evidence,
            thaw_evidence,
        )
    }

    fn project_source_fence(
        &mut self,
        command: SourceFenceCommand,
        destination: NodeIdentity,
        next_epoch: LeaseEpoch,
        decision_evidence: EvidenceRef,
        closure_evidence: EvidenceRef,
    ) -> Result<LocalProjection, Self::Error> {
        (**self).project_source_fence(
            command,
            destination,
            next_epoch,
            decision_evidence,
            closure_evidence,
        )
    }
}

impl<T> VisaDestinationRuntime for &mut T
where
    T: VisaDestinationRuntime + ?Sized,
{
    type Error = T::Error;

    fn joint_runtime_binding(&self) -> Result<VisaRuntimeBinding, Self::Error> {
        (**self).joint_runtime_binding()
    }

    fn destination_commit_request_digest(
        &self,
        operation: Identity,
        idempotency: IdempotencyKey,
        resume_guard: Identity,
    ) -> Result<Digest, Self::Error> {
        (**self).destination_commit_request_digest(operation, idempotency, resume_guard)
    }

    fn commit_for_activation(
        &mut self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
    ) -> Result<(), Self::Error> {
        (**self).commit_for_activation(handoff, request_digest, commands)
    }

    fn preview_activation_resume(
        &self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
        activation_record_digest: Digest,
    ) -> Result<LocalProjection, Self::Error> {
        (**self).preview_activation_resume(
            handoff,
            request_digest,
            commands,
            activation_record_digest,
        )
    }

    fn resume_after_activation_receipt(
        &mut self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
        activation_record_digest: Digest,
        expected: LocalProjection,
    ) -> Result<LocalProjection, Self::Error> {
        (**self).resume_after_activation_receipt(
            handoff,
            request_digest,
            commands,
            activation_record_digest,
            expected,
        )
    }
}

impl<P> VisaSourceRuntime for Coordinator<P>
where
    P: JournalPort
        + AuthorityPort
        + BindingPort
        + LeasePort
        + TimerPort
        + ProfilePort
        + ExternalHandoffProjectionPort,
{
    type Error = RuntimeError;

    fn joint_runtime_binding(&self) -> Result<VisaRuntimeBinding, Self::Error> {
        Ok(VisaRuntimeBinding::from_state(
            self.state(),
            self.journal_position(),
            self.state_digest()?,
        ))
    }

    fn abort_and_resume(
        &mut self,
        handoff: Identity,
        snapshot: Option<Identity>,
        local_freeze_recorded: bool,
        commands: SourceAbortCommands,
        abort_evidence: EvidenceRef,
        thaw_evidence: Option<EvidenceRef>,
    ) -> Result<LocalProjection, Self::Error> {
        self.project_source_abort_and_resume(SourceAbortProjectionRequest {
            handoff,
            snapshot,
            local_freeze_recorded,
            abort_command: commands.abort,
            resume_command: commands.resume,
            abort_evidence,
            thaw_evidence,
        })?;
        Ok(LocalProjection {
            journal_position: self.journal_position(),
            state_digest: self.state_digest()?,
            authorization_record_digest: None,
        })
    }

    fn project_source_fence(
        &mut self,
        command: SourceFenceCommand,
        destination: NodeIdentity,
        next_epoch: LeaseEpoch,
        decision_evidence: EvidenceRef,
        closure_evidence: EvidenceRef,
    ) -> Result<LocalProjection, Self::Error> {
        self.project_external_source_fence(
            command.command,
            command.operation,
            destination,
            next_epoch,
            decision_evidence,
            closure_evidence,
        )?;
        Ok(LocalProjection {
            journal_position: self.journal_position(),
            state_digest: self.state_digest()?,
            authorization_record_digest: None,
        })
    }
}

impl<P> VisaDestinationRuntime for Coordinator<P>
where
    P: JournalPort + AuthorityPort + LeasePort + KvPort + TimerPort + ProfilePort,
{
    type Error = RuntimeError;

    fn joint_runtime_binding(&self) -> Result<VisaRuntimeBinding, Self::Error> {
        Ok(VisaRuntimeBinding::from_state(
            self.state(),
            self.journal_position(),
            self.state_digest()?,
        ))
    }

    fn destination_commit_request_digest(
        &self,
        operation: Identity,
        idempotency: IdempotencyKey,
        resume_guard: Identity,
    ) -> Result<Digest, Self::Error> {
        self.guarded_handoff_commit_request_digest(operation, idempotency, resume_guard)
    }

    fn commit_for_activation(
        &mut self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
    ) -> Result<(), Self::Error> {
        self.project_destination_commit(DestinationActivationProjectionRequest {
            handoff,
            commit_command: commands.commit_command,
            commit_operation: commands.commit_operation,
            commit_idempotency: commands.commit_idempotency,
            request_digest,
            resume_command: commands.resume_command,
        })
    }

    fn preview_activation_resume(
        &self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
        activation_record_digest: Digest,
    ) -> Result<LocalProjection, Self::Error> {
        let preview = self.preview_destination_resume(
            DestinationActivationProjectionRequest {
                handoff,
                commit_command: commands.commit_command,
                commit_operation: commands.commit_operation,
                commit_idempotency: commands.commit_idempotency,
                request_digest,
                resume_command: commands.resume_command,
            },
            activation_record_digest,
        )?;
        Ok(LocalProjection {
            journal_position: preview.journal_position,
            state_digest: preview.state_digest,
            authorization_record_digest: Some(preview.activation_record_digest),
        })
    }

    fn resume_after_activation_receipt(
        &mut self,
        handoff: Identity,
        request_digest: Digest,
        commands: DestinationActivationCommands,
        activation_record_digest: Digest,
        expected: LocalProjection,
    ) -> Result<LocalProjection, Self::Error> {
        self.project_destination_resume(
            DestinationActivationProjectionRequest {
                handoff,
                commit_command: commands.commit_command,
                commit_operation: commands.commit_operation,
                commit_idempotency: commands.commit_idempotency,
                request_digest,
                resume_command: commands.resume_command,
            },
            activation_record_digest,
            visa_runtime::DestinationResumePreview {
                journal_position: expected.journal_position,
                state_digest: expected.state_digest,
                activation_record_digest: expected
                    .authorization_record_digest
                    .ok_or(RuntimeError::JournalConflict { position: self.journal_position() })?,
            },
        )?;
        Ok(LocalProjection {
            journal_position: self.journal_position(),
            state_digest: self.state_digest()?,
            authorization_record_digest: Some(activation_record_digest),
        })
    }
}

pub struct JointSource<S> {
    runtime: Option<S>,
}

impl<S> JointSource<S> {
    pub const fn new(runtime: S) -> Self {
        Self { runtime: Some(runtime) }
    }

    pub fn project_abort(
        &mut self,
        verified_state: &VerifiedJointState,
        commands: SourceAbortCommands,
    ) -> Result<LocalProjection, ProjectionError<S::Error>>
    where
        S: VisaSourceRuntime,
    {
        let state = verified_state.state();
        if !matches!(state.phase, JointPhase::AbortDecided | JointPhase::SourceThawPending) {
            return Err(ProjectionError::InvalidJointPhase { actual: state.phase });
        }
        validate_joint_state(state)?;
        let binding = self
            .runtime
            .as_ref()
            .ok_or(ProjectionError::MissingReceipt)?
            .joint_runtime_binding()
            .map_err(ProjectionError::Runtime)?;
        validate_source_abort_binding(state, &binding)?;
        let OwnershipDecision::Abort(abort) = state.decision else {
            return Err(ProjectionError::MissingReceipt);
        };
        validate_receipt(state, abort, ReceiptKind::OwnershipAbort)?;
        if state.source_resume.is_some() {
            return Err(ProjectionError::ReceiptMismatch);
        }
        let thaw_evidence = match state.phase {
            JointPhase::AbortDecided
                if state.visa_freeze.is_none()
                    && state.nexus_freeze.is_none()
                    && state.thaw.is_none() =>
            {
                None
            }
            JointPhase::SourceThawPending => {
                let freeze = state.nexus_freeze.ok_or(ProjectionError::MissingReceipt)?;
                validate_receipt(state, freeze, ReceiptKind::NexusFreeze)?;
                let thaw = state.thaw.ok_or(ProjectionError::MissingReceipt)?;
                validate_receipt(state, thaw, ReceiptKind::NexusThaw)?;
                Some(receipt_evidence(thaw, EvidenceKind::Cleanup)?)
            }
            JointPhase::AbortDecided
                if state.visa_freeze.is_some()
                    && state.nexus_freeze.is_none()
                    && state.thaw.is_none() =>
            {
                return Err(ProjectionError::EffectFreezeOutcomeUnknown);
            }
            _ => return Err(ProjectionError::InvalidJointPhase { actual: state.phase }),
        };
        validate_commands(&[commands.abort, commands.resume])?;
        let abort_evidence = receipt_evidence(abort, EvidenceKind::AuthorityDecision)?;
        self.runtime
            .as_mut()
            .ok_or(ProjectionError::MissingReceipt)?
            .abort_and_resume(
                state.key.handoff,
                state.pending_bindings.map(|prepared| prepared.snapshot),
                state.visa_freeze.is_some(),
                commands,
                abort_evidence,
                thaw_evidence,
            )
            .map_err(ProjectionError::Runtime)
    }

    pub fn project_commit_fence(
        &mut self,
        verified_state: &VerifiedJointState,
        command: SourceFenceCommand,
    ) -> Result<LocalProjection, ProjectionError<S::Error>>
    where
        S: VisaSourceRuntime,
    {
        let state = verified_state.state();
        if state.phase != JointPhase::SourceClosed {
            return Err(ProjectionError::InvalidJointPhase { actual: state.phase });
        }
        validate_joint_state(state)?;
        let binding = self
            .runtime
            .as_ref()
            .ok_or(ProjectionError::MissingReceipt)?
            .joint_runtime_binding()
            .map_err(ProjectionError::Runtime)?;
        validate_source_fence_binding(state, &binding)?;
        let OwnershipDecision::Commit(commit) = state.decision else {
            return Err(ProjectionError::MissingReceipt);
        };
        let ClosureStatus::Closed { receipt: closure, .. } = state.closure else {
            return Err(ProjectionError::MissingReceipt);
        };
        validate_receipt(state, commit, ReceiptKind::OwnershipCommit)?;
        validate_receipt(state, closure, ReceiptKind::Closure)?;
        if let Some(source_fence) = state.source_fence {
            validate_receipt(state, source_fence, ReceiptKind::VisaSourceFence)?;
        }
        validate_commands(&[command.command, command.operation])?;
        let decision_evidence = receipt_evidence(commit, EvidenceKind::AuthorityDecision)?;
        let closure_evidence = receipt_evidence(closure, EvidenceKind::SourceFence)?;
        self.runtime
            .as_mut()
            .ok_or(ProjectionError::MissingReceipt)?
            .project_source_fence(
                command,
                state.key.destination,
                state.key.next_epoch,
                decision_evidence,
                closure_evidence,
            )
            .map_err(ProjectionError::Runtime)
    }

    pub fn into_source_active(
        self,
        verified_state: &VerifiedJointState,
    ) -> Result<S, ProjectionError<S::Error>>
    where
        S: VisaSourceRuntime,
    {
        let state = verified_state.state();
        if state.phase != JointPhase::SourceActive || state.source_resume.is_none() {
            return Err(ProjectionError::InvalidJointPhase { actual: state.phase });
        }
        validate_joint_state(state)?;
        let binding = self
            .runtime
            .as_ref()
            .ok_or(ProjectionError::MissingReceipt)?
            .joint_runtime_binding()
            .map_err(ProjectionError::Runtime)?;
        validate_source_active_binding(state, &binding)?;
        let OwnershipDecision::Abort(abort) = state.decision else {
            return Err(ProjectionError::MissingReceipt);
        };
        validate_receipt(state, abort, ReceiptKind::OwnershipAbort)?;
        let source_resume = state.source_resume.ok_or(ProjectionError::MissingReceipt)?;
        validate_receipt(state, source_resume, ReceiptKind::VisaSourceResume)?;
        match (state.nexus_freeze, state.thaw) {
            (Some(freeze), Some(thaw)) => {
                validate_receipt(state, freeze, ReceiptKind::NexusFreeze)?;
                validate_receipt(state, thaw, ReceiptKind::NexusThaw)?;
            }
            (None, None) => {}
            _ => return Err(ProjectionError::ReceiptMismatch),
        }
        self.runtime.ok_or(ProjectionError::MissingReceipt)
    }

    pub fn close(
        mut self,
        verified_state: &VerifiedJointState,
    ) -> Result<(), ProjectionError<S::Error>>
    where
        S: VisaSourceRuntime,
    {
        let state = verified_state.state();
        if !matches!(state.phase, JointPhase::SourceClosed | JointPhase::DestinationActive)
            || state.source_fence.is_none()
        {
            return Err(ProjectionError::InvalidJointPhase { actual: state.phase });
        }
        validate_joint_state(state)?;
        let binding = self
            .runtime
            .as_ref()
            .ok_or(ProjectionError::MissingReceipt)?
            .joint_runtime_binding()
            .map_err(ProjectionError::Runtime)?;
        validate_source_closed_binding(state, &binding)?;
        let OwnershipDecision::Commit(commit) = state.decision else {
            return Err(ProjectionError::MissingReceipt);
        };
        let ClosureStatus::Closed { receipt: closure, .. } = state.closure else {
            return Err(ProjectionError::MissingReceipt);
        };
        validate_receipt(state, commit, ReceiptKind::OwnershipCommit)?;
        validate_receipt(state, closure, ReceiptKind::Closure)?;
        validate_receipt(
            state,
            state.source_fence.ok_or(ProjectionError::MissingReceipt)?,
            ReceiptKind::VisaSourceFence,
        )?;
        if state.phase == JointPhase::DestinationActive {
            validate_receipt(
                state,
                state.destination_activation.ok_or(ProjectionError::MissingReceipt)?,
                ReceiptKind::VisaDestinationActivation,
            )?;
        }
        self.runtime.take();
        Ok(())
    }
}

pub struct JointDestination<D> {
    runtime: Option<D>,
}

impl<D> JointDestination<D> {
    pub const fn new(runtime: D) -> Self {
        Self { runtime: Some(runtime) }
    }

    pub fn project_activation(
        &mut self,
        verified_state: &VerifiedJointState,
        commands: DestinationActivationCommands,
        activation_preview_record_digest: Digest,
    ) -> Result<LocalProjection, ProjectionError<D::Error>>
    where
        D: VisaDestinationRuntime,
    {
        let state = verified_state.state();
        if state.phase != JointPhase::DestinationActivationPending || state.source_fence.is_none() {
            return Err(ProjectionError::InvalidJointPhase { actual: state.phase });
        }
        validate_joint_state(state)?;
        let binding = self
            .runtime
            .as_ref()
            .ok_or(ProjectionError::MissingReceipt)?
            .joint_runtime_binding()
            .map_err(ProjectionError::Runtime)?;
        validate_destination_prepared_binding(state, &binding)?;
        let OwnershipDecision::Commit(commit) = state.decision else {
            return Err(ProjectionError::MissingReceipt);
        };
        let ClosureStatus::Closed { receipt: closure, .. } = state.closure else {
            return Err(ProjectionError::MissingReceipt);
        };
        validate_receipt(state, commit, ReceiptKind::OwnershipCommit)?;
        validate_receipt(state, closure, ReceiptKind::Closure)?;
        validate_receipt(
            state,
            state.source_fence.ok_or(ProjectionError::MissingReceipt)?,
            ReceiptKind::VisaSourceFence,
        )?;
        if state.destination_activation.is_some() {
            return Err(ProjectionError::ReceiptMismatch);
        }
        validate_commands(&[
            commands.commit_command,
            commands.commit_operation,
            commands.resume_command,
        ])?;
        if commands.commit_idempotency.0 == [0; 16] {
            return Err(ProjectionError::InvalidCommand);
        }
        if activation_preview_record_digest == Digest::ZERO {
            return Err(ProjectionError::InvalidCommand);
        }
        let prepared_commit =
            verified_state.destination_commit().ok_or(ProjectionError::MissingReceipt)?;
        if prepared_commit.operation != commands.commit_operation
            || prepared_commit.idempotency != commands.commit_idempotency
            || prepared_commit.request_digest == Digest::ZERO
        {
            return Err(ProjectionError::ReceiptMismatch);
        }
        let actual_request_digest = self
            .runtime
            .as_ref()
            .ok_or(ProjectionError::MissingReceipt)?
            .destination_commit_request_digest(
                commands.commit_operation,
                commands.commit_idempotency,
                commands.resume_command,
            )
            .map_err(ProjectionError::Runtime)?;
        if actual_request_digest != prepared_commit.request_digest {
            return Err(ProjectionError::ReceiptMismatch);
        }
        let runtime = self.runtime.as_mut().ok_or(ProjectionError::MissingReceipt)?;
        runtime
            .commit_for_activation(state.key.handoff, prepared_commit.request_digest, commands)
            .map_err(ProjectionError::Runtime)?;
        runtime
            .preview_activation_resume(
                state.key.handoff,
                prepared_commit.request_digest,
                commands,
                activation_preview_record_digest,
            )
            .map_err(ProjectionError::Runtime)
    }

    pub fn resume_activation(
        &mut self,
        verified_state: &VerifiedJointState,
        commands: DestinationActivationCommands,
        activation_record_digest: Digest,
        expected: LocalProjection,
    ) -> Result<LocalProjection, ProjectionError<D::Error>>
    where
        D: VisaDestinationRuntime,
    {
        let state = verified_state.state();
        if state.phase != JointPhase::DestinationActive || state.destination_activation.is_none() {
            return Err(ProjectionError::InvalidJointPhase { actual: state.phase });
        }
        validate_joint_state(state)?;
        let binding = self
            .runtime
            .as_ref()
            .ok_or(ProjectionError::MissingReceipt)?
            .joint_runtime_binding()
            .map_err(ProjectionError::Runtime)?;
        validate_destination_prepared_binding(state, &binding)?;
        let prepared_commit =
            verified_state.destination_commit().ok_or(ProjectionError::MissingReceipt)?;
        if prepared_commit.operation != commands.commit_operation
            || prepared_commit.idempotency != commands.commit_idempotency
            || prepared_commit.request_digest == Digest::ZERO
        {
            return Err(ProjectionError::ReceiptMismatch);
        }
        self.runtime
            .as_mut()
            .ok_or(ProjectionError::MissingReceipt)?
            .resume_after_activation_receipt(
                state.key.handoff,
                prepared_commit.request_digest,
                commands,
                activation_record_digest,
                expected,
            )
            .map_err(ProjectionError::Runtime)
    }

    pub fn into_active(
        self,
        verified_state: &VerifiedJointState,
    ) -> Result<D, ProjectionError<D::Error>>
    where
        D: VisaDestinationRuntime,
    {
        self.validate_active(verified_state)?;
        self.runtime.ok_or(ProjectionError::MissingReceipt)
    }

    pub fn validate_active(
        &self,
        verified_state: &VerifiedJointState,
    ) -> Result<(), ProjectionError<D::Error>>
    where
        D: VisaDestinationRuntime,
    {
        let state = verified_state.state();
        if state.phase != JointPhase::DestinationActive || state.destination_activation.is_none() {
            return Err(ProjectionError::InvalidJointPhase { actual: state.phase });
        }
        validate_joint_state(state)?;
        let binding = self
            .runtime
            .as_ref()
            .ok_or(ProjectionError::MissingReceipt)?
            .joint_runtime_binding()
            .map_err(ProjectionError::Runtime)?;
        validate_destination_active_binding(state, &binding)?;
        let OwnershipDecision::Commit(commit) = state.decision else {
            return Err(ProjectionError::MissingReceipt);
        };
        let ClosureStatus::Closed { receipt: closure, .. } = state.closure else {
            return Err(ProjectionError::MissingReceipt);
        };
        validate_receipt(state, commit, ReceiptKind::OwnershipCommit)?;
        validate_receipt(state, closure, ReceiptKind::Closure)?;
        validate_receipt(
            state,
            state.source_fence.ok_or(ProjectionError::MissingReceipt)?,
            ReceiptKind::VisaSourceFence,
        )?;
        validate_receipt(
            state,
            state.destination_activation.ok_or(ProjectionError::MissingReceipt)?,
            ReceiptKind::VisaDestinationActivation,
        )?;
        Ok(())
    }
}

fn validate_commands<E>(commands: &[Identity]) -> Result<(), ProjectionError<E>> {
    if commands.iter().any(|identity| identity.is_zero())
        || commands.iter().enumerate().any(|(index, identity)| commands[..index].contains(identity))
    {
        return Err(ProjectionError::InvalidCommand);
    }
    Ok(())
}

fn validate_common_binding<E>(
    state: &JointState,
    binding: &VisaRuntimeBinding,
) -> Result<(), ProjectionError<E>> {
    if binding.component.identity != state.key.continuity_unit.identity {
        return Err(ProjectionError::ReceiptMismatch);
    }
    if let Some(prepared) = state.pending_bindings
        && (binding.component_digest != prepared.component_digest
            || binding.profile_digest != prepared.profile_digest)
    {
        return Err(ProjectionError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_source_abort_binding<E>(
    state: &JointState,
    binding: &VisaRuntimeBinding,
) -> Result<(), ProjectionError<E>> {
    validate_common_binding(state, binding)?;
    validate_source_component(state, binding)?;
    if binding.activation.node != state.key.source
        || binding.activation.role != ActivationRole::Source
        || binding.ownership != Ownership::owned(state.key.source, state.key.expected_epoch)
    {
        return Err(ProjectionError::ReceiptMismatch);
    }
    if binding.phase == HandoffPhase::Running
        && binding.activation.status == ActivationStatus::Active
    {
        return Ok(());
    }
    if state.visa_freeze.is_none() {
        return Err(ProjectionError::ReceiptMismatch);
    } else {
        if binding.activation.status != ActivationStatus::Active {
            return Err(ProjectionError::ReceiptMismatch);
        }
        match binding.phase {
            HandoffPhase::Frozen if state.source_state_digest == Some(binding.state_digest) => {}
            HandoffPhase::Exported => {
                let snapshot =
                    binding.exported_snapshot.as_ref().ok_or(ProjectionError::MissingReceipt)?;
                if snapshot.handoff != state.key.handoff
                    || state.source_journal_position != Some(snapshot.journal_position)
                {
                    return Err(ProjectionError::ReceiptMismatch);
                }
            }
            _ => return Err(ProjectionError::ReceiptMismatch),
        }
    }
    if let Some(prepared) = state.pending_bindings {
        validate_source_snapshot(state, binding, prepared.snapshot)?;
    }
    Ok(())
}

fn validate_source_fence_binding<E>(
    state: &JointState,
    binding: &VisaRuntimeBinding,
) -> Result<(), ProjectionError<E>> {
    validate_common_binding(state, binding)?;
    validate_source_component(state, binding)?;
    let prepared = state.pending_bindings.ok_or(ProjectionError::MissingReceipt)?;
    if binding.phase == HandoffPhase::Committed {
        validate_source_closed_binding(state, binding)?;
    } else {
        if binding.phase != HandoffPhase::Exported
            || binding.activation.node != state.key.source
            || binding.activation.role != ActivationRole::Source
            || binding.activation.status != ActivationStatus::Active
            || binding.ownership != Ownership::owned(state.key.source, state.key.expected_epoch)
        {
            return Err(ProjectionError::ReceiptMismatch);
        }
    }
    validate_source_snapshot(state, binding, prepared.snapshot)
}

fn validate_source_snapshot<E>(
    state: &JointState,
    binding: &VisaRuntimeBinding,
    snapshot: Identity,
) -> Result<(), ProjectionError<E>> {
    let local = binding.exported_snapshot.as_ref().ok_or(ProjectionError::MissingReceipt)?;
    if local.handoff != state.key.handoff
        || local.snapshot != snapshot
        || state
            .pending_bindings
            .is_some_and(|prepared| local.journal_position != prepared.source_journal_position)
    {
        return Err(ProjectionError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_source_active_binding<E>(
    state: &JointState,
    binding: &VisaRuntimeBinding,
) -> Result<(), ProjectionError<E>> {
    validate_common_binding(state, binding)?;
    validate_source_component(state, binding)?;
    if binding.phase != HandoffPhase::Running
        || binding.activation.node != state.key.source
        || binding.activation.role != ActivationRole::Source
        || binding.activation.status != ActivationStatus::Active
        || binding.ownership != Ownership::owned(state.key.source, state.key.expected_epoch)
    {
        return Err(ProjectionError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_source_closed_binding<E>(
    state: &JointState,
    binding: &VisaRuntimeBinding,
) -> Result<(), ProjectionError<E>> {
    validate_common_binding(state, binding)?;
    validate_source_component(state, binding)?;
    if binding.phase != HandoffPhase::Committed
        || binding.activation.node != state.key.source
        || binding.activation.role != ActivationRole::Source
        || binding.activation.status != ActivationStatus::Fenced
        || binding.ownership != Ownership::owned(state.key.destination, state.key.next_epoch)
    {
        return Err(ProjectionError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_destination_prepared_binding<E>(
    state: &JointState,
    binding: &VisaRuntimeBinding,
) -> Result<(), ProjectionError<E>> {
    validate_common_binding(state, binding)?;
    let prepared = state.pending_bindings.ok_or(ProjectionError::MissingReceipt)?;
    let local = binding.prepared_destination.as_ref().ok_or(ProjectionError::MissingReceipt)?;
    if binding.activation.node != state.key.destination
        || binding.activation.role != ActivationRole::Destination
        || local.handoff != state.key.handoff
        || local.snapshot != prepared.snapshot
        || local.destination != state.key.destination
        || local.expected_epoch != state.key.expected_epoch
        || local.next_epoch != state.key.next_epoch
    {
        return Err(ProjectionError::ReceiptMismatch);
    }
    match binding.phase {
        HandoffPhase::DestinationPrepared
            if binding.activation.status == ActivationStatus::Prepared
                && binding.component == state.key.continuity_unit
                && binding.component.generation.next() == Some(local.component_generation)
                && binding.state_digest == prepared.destination_state_digest => {}
        HandoffPhase::Committed | HandoffPhase::Running
            if binding.activation.status == ActivationStatus::Active
                && binding.ownership
                    == Ownership::owned(state.key.destination, state.key.next_epoch)
                && local.component_generation == binding.component.generation => {}
        _ => return Err(ProjectionError::ReceiptMismatch),
    }
    Ok(())
}

fn validate_destination_active_binding<E>(
    state: &JointState,
    binding: &VisaRuntimeBinding,
) -> Result<(), ProjectionError<E>> {
    validate_common_binding(state, binding)?;
    let local = binding.prepared_destination.as_ref().ok_or(ProjectionError::MissingReceipt)?;
    if binding.phase != HandoffPhase::Running
        || binding.activation.node != state.key.destination
        || binding.activation.role != ActivationRole::Destination
        || binding.activation.status != ActivationStatus::Active
        || binding.ownership != Ownership::owned(state.key.destination, state.key.next_epoch)
        || local.component_generation != binding.component.generation
    {
        return Err(ProjectionError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_source_component<E>(
    state: &JointState,
    binding: &VisaRuntimeBinding,
) -> Result<(), ProjectionError<E>> {
    if binding.component == state.key.continuity_unit {
        Ok(())
    } else {
        Err(ProjectionError::ReceiptMismatch)
    }
}

fn validate_joint_state<E>(state: &JointState) -> Result<(), ProjectionError<E>> {
    if !state.version.is_supported() || !state.key.is_well_formed() || state.revision == 0 {
        return Err(ProjectionError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_receipt<E>(
    state: &JointState,
    receipt: ReceiptRef,
    expected_kind: ReceiptKind,
) -> Result<(), ProjectionError<E>> {
    if !receipt.version.is_supported()
        || receipt.kind != expected_kind
        || receipt.handoff != state.key.handoff
        || receipt.issuer.is_zero()
        || receipt.issuer_incarnation.is_zero()
        || receipt.key_id.is_zero()
        || receipt.log_id.is_zero()
        || receipt.sequence == 0
        || receipt.digest == Digest::ZERO
    {
        return Err(ProjectionError::ReceiptMismatch);
    }
    Ok(())
}

fn receipt_evidence<E>(
    receipt: ReceiptRef,
    kind: EvidenceKind,
) -> Result<EvidenceRef, ProjectionError<E>> {
    if receipt.digest == Digest::ZERO || receipt.handoff.is_zero() {
        return Err(ProjectionError::ReceiptMismatch);
    }
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&receipt.digest.0[..16]);
    let identity = Identity::from_bytes(identity);
    if identity.is_zero() {
        return Err(ProjectionError::ReceiptMismatch);
    }
    Ok(EvidenceRef { identity, kind, digest: receipt.digest })
}
