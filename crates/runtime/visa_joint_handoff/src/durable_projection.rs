use joint_handoff_core::{
    Identity, VisaDestinationActivationReceipt, canonical_bytes, canonical_from_bytes,
};

use crate::{
    DestinationActivationAttempt, DestinationActivationCommands, DurableJointSession,
    DurableJointSessionError, DurableRecordOutcome, JointDestination, JointProjectionLog,
    JointSource, LocalProjection, LocalProjectionObligation, NativeReceiptAuthenticator,
    ProjectionError, SourceAbortAttempt, SourceAbortCommands, SourceFenceAttempt,
    SourceFenceCommand, VisaDestinationRuntime, VisaSourceRuntime,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableProjectionExecution {
    pub write_ahead: DurableRecordOutcome,
    pub observation: DurableRecordOutcome,
    pub local: LocalProjection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurableProjectionError<LogError, AuthError, RuntimeError> {
    Durable(DurableJointSessionError<LogError, AuthError>),
    Projection(ProjectionError<RuntimeError>),
    PreStateMismatch,
    CompletionPending,
    CompletionDecode,
    CompletionProjectionMismatch,
}

pub type DurableProjectionResult<T, LogError, AuthError, RuntimeError> =
    Result<T, DurableProjectionError<LogError, AuthError, RuntimeError>>;

/// Couples the crash-stable joint projection log to the exact local runtime
/// projection. A local side effect is reachable only after its full invocation
/// has been durably appended. Reopening the two stores and invoking the same
/// method reconciles the exact terminal local lineage before a completion
/// receipt is appended.
pub struct DurableProjectionDriver<'a, L, A> {
    session: &'a mut DurableJointSession<L, A>,
}

impl<'a, L, A> DurableProjectionDriver<'a, L, A>
where
    L: JointProjectionLog,
    A: NativeReceiptAuthenticator,
{
    pub const fn new(session: &'a mut DurableJointSession<L, A>) -> Self {
        Self { session }
    }

    pub const fn session(&self) -> &DurableJointSession<L, A> {
        self.session
    }

    pub fn project_source_abort<S>(
        &mut self,
        runtime: &mut S,
        attempt: SourceAbortAttempt,
    ) -> DurableProjectionResult<DurableProjectionExecution, L::Error, A::Error, S::Error>
    where
        S: VisaSourceRuntime,
    {
        if self.session.source_abort_attempt().is_none() {
            ensure_pre_state(
                runtime,
                attempt.expected_pre_journal_position,
                attempt.expected_pre_state_digest,
            )?;
        }
        let write_ahead =
            self.session.begin_source_abort(attempt).map_err(DurableProjectionError::Durable)?;
        let mut source = JointSource::new(runtime);
        let local = source
            .project_abort(
                self.session.state(),
                SourceAbortCommands {
                    abort: attempt.abort_command,
                    resume: attempt.resume_command,
                },
            )
            .map_err(DurableProjectionError::Projection)?;
        let observation = self
            .session
            .record_source_abort_observed(local.journal_position, local.state_digest)
            .map_err(DurableProjectionError::Durable)?;
        Ok(DurableProjectionExecution { write_ahead, observation, local })
    }

    pub fn project_source_fence<S>(
        &mut self,
        runtime: &mut S,
        attempt: SourceFenceAttempt,
    ) -> DurableProjectionResult<DurableProjectionExecution, L::Error, A::Error, S::Error>
    where
        S: VisaSourceRuntime,
    {
        if self.session.source_fence_attempt().is_none() {
            ensure_pre_state(
                runtime,
                attempt.expected_pre_journal_position,
                attempt.expected_pre_state_digest,
            )?;
        }
        let write_ahead =
            self.session.begin_source_fence(attempt).map_err(DurableProjectionError::Durable)?;
        let mut source = JointSource::new(runtime);
        let local = source
            .project_commit_fence(
                self.session.state(),
                SourceFenceCommand {
                    command: attempt.fence_command,
                    operation: attempt.fence_operation,
                },
            )
            .map_err(DurableProjectionError::Projection)?;
        let observation = self
            .session
            .record_source_fence_observed(local.journal_position, local.state_digest)
            .map_err(DurableProjectionError::Durable)?;
        Ok(DurableProjectionExecution { write_ahead, observation, local })
    }

    /// Append an authenticated completion after the local projection. The
    /// durable session checks its kind, typed request digest, and causal refs
    /// against the write-ahead attempt before advancing the joint state.
    pub fn record_completion(
        &mut self,
        command_identity: Identity,
        request_bytes: &[u8],
        envelope_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<DurableRecordOutcome, DurableJointSessionError<L::Error, A::Error>> {
        self.session.record_native_receipt(
            command_identity,
            request_bytes,
            envelope_bytes,
            payload_bytes,
        )
    }
}

/// Owns a destination runtime from the first durable activation attempt until
/// the authenticated completion receipt is itself crash-stable. There is no
/// runtime accessor: dropping an incomplete guard closes the local handle, and
/// only [`Self::release`] can return it to a workload-admitting caller.
pub struct DurableDestinationGuard<'a, L, A, D> {
    session: &'a mut DurableJointSession<L, A>,
    runtime: Option<D>,
}

impl<'a, L, A, D> DurableDestinationGuard<'a, L, A, D>
where
    L: JointProjectionLog,
    A: NativeReceiptAuthenticator,
    D: VisaDestinationRuntime,
{
    pub const fn new(session: &'a mut DurableJointSession<L, A>, runtime: D) -> Self {
        Self { session, runtime: Some(runtime) }
    }

    pub fn project(
        &mut self,
        attempt: DestinationActivationAttempt,
    ) -> DurableProjectionResult<DurableProjectionExecution, L::Error, A::Error, D::Error> {
        let runtime = self.runtime.as_mut().ok_or(DurableProjectionError::CompletionPending)?;
        if self.session.destination_activation_attempt().is_none() {
            ensure_destination_pre_state(
                runtime,
                attempt.expected_pre_journal_position,
                attempt.expected_pre_state_digest,
            )?;
        }
        let write_ahead = self
            .session
            .begin_destination_activation(attempt)
            .map_err(DurableProjectionError::Durable)?;
        let activation_attempt_record_digest = self
            .session
            .destination_activation_attempt_record_digest()
            .ok_or(DurableProjectionError::CompletionPending)?;
        let mut destination = JointDestination::new(runtime);
        let local = destination
            .project_activation(
                self.session.state(),
                DestinationActivationCommands {
                    commit_command: attempt.commit_command,
                    commit_operation: attempt.commit_operation,
                    commit_idempotency: attempt.commit_idempotency,
                    resume_command: attempt.resume_command,
                },
                activation_attempt_record_digest,
            )
            .map_err(DurableProjectionError::Projection)?;
        if local.authorization_record_digest != Some(activation_attempt_record_digest) {
            return Err(DurableProjectionError::CompletionProjectionMismatch);
        }
        let observation = self
            .session
            .record_destination_activation_preview_observed(
                local.journal_position,
                local.state_digest,
            )
            .map_err(DurableProjectionError::Durable)?;
        Ok(DurableProjectionExecution { write_ahead, observation, local })
    }

    pub fn record_completion(
        &mut self,
        command_identity: Identity,
        request_bytes: &[u8],
        envelope_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> DurableProjectionResult<DurableRecordOutcome, L::Error, A::Error, D::Error> {
        let receipt: VisaDestinationActivationReceipt = canonical_from_bytes(payload_bytes)
            .map_err(|_| DurableProjectionError::CompletionDecode)?;
        if canonical_bytes(&receipt).ok().as_deref() != Some(payload_bytes) {
            return Err(DurableProjectionError::CompletionDecode);
        }
        let attempt = self
            .session
            .destination_activation_attempt()
            .ok_or(DurableProjectionError::CompletionPending)?;
        let activation_attempt_record_digest = self
            .session
            .destination_activation_attempt_record_digest()
            .ok_or(DurableProjectionError::CompletionPending)?;
        let runtime = self.runtime.as_mut().ok_or(DurableProjectionError::CompletionPending)?;
        let preview = JointDestination::new(runtime)
            .project_activation(
                self.session.state(),
                destination_commands(attempt),
                activation_attempt_record_digest,
            )
            .map_err(DurableProjectionError::Projection)?;
        if receipt.source_fence != attempt.source_fence
            || receipt.activation_command != attempt.joint_command
            || receipt.resume_command != attempt.resume_command
            || receipt.activation_attempt_record_digest != activation_attempt_record_digest
            || receipt.journal_position != preview.journal_position
            || receipt.state_digest != preview.state_digest
            || preview.authorization_record_digest != Some(activation_attempt_record_digest)
        {
            return Err(DurableProjectionError::CompletionProjectionMismatch);
        }
        self.session
            .record_native_receipt(command_identity, request_bytes, envelope_bytes, payload_bytes)
            .map_err(DurableProjectionError::Durable)
    }

    pub fn check_release(&mut self) -> DurableProjectionResult<(), L::Error, A::Error, D::Error> {
        if !matches!(
            self.session.destination_activation_obligation(),
            LocalProjectionObligation::ReceiptObserved { .. }
        ) {
            return Err(DurableProjectionError::CompletionPending);
        }
        let receipt = self
            .session
            .destination_activation_receipt()
            .ok_or(DurableProjectionError::CompletionPending)?;
        let activation_attempt_record_digest = self
            .session
            .destination_activation_attempt_record_digest()
            .ok_or(DurableProjectionError::CompletionPending)?;
        let activation_record_digest = self
            .session
            .destination_activation_completion_record_digest()
            .ok_or(DurableProjectionError::CompletionPending)?;
        let attempt = self
            .session
            .destination_activation_attempt()
            .ok_or(DurableProjectionError::CompletionPending)?;
        let expected = LocalProjection {
            journal_position: receipt.journal_position,
            state_digest: receipt.state_digest,
            authorization_record_digest: Some(activation_record_digest),
        };
        if receipt.activation_attempt_record_digest != activation_attempt_record_digest {
            return Err(DurableProjectionError::CompletionProjectionMismatch);
        }
        let runtime = self.runtime.as_mut().ok_or(DurableProjectionError::CompletionPending)?;
        let mut destination = JointDestination::new(runtime);
        let observed = destination
            .resume_activation(
                self.session.state(),
                destination_commands(attempt),
                activation_record_digest,
                expected,
            )
            .map_err(DurableProjectionError::Projection)?;
        if observed != expected {
            return Err(DurableProjectionError::CompletionProjectionMismatch);
        }
        destination
            .validate_active(self.session.state())
            .map_err(DurableProjectionError::Projection)
    }

    pub fn release(mut self) -> DurableProjectionResult<D, L::Error, A::Error, D::Error> {
        self.check_release()?;
        self.runtime.take().ok_or(DurableProjectionError::CompletionPending)
    }
}

const fn destination_commands(
    attempt: DestinationActivationAttempt,
) -> DestinationActivationCommands {
    DestinationActivationCommands {
        commit_command: attempt.commit_command,
        commit_operation: attempt.commit_operation,
        commit_idempotency: attempt.commit_idempotency,
        resume_command: attempt.resume_command,
    }
}

fn ensure_pre_state<S, LogError, AuthError>(
    runtime: &S,
    expected_position: contract_core::JournalPosition,
    expected_digest: contract_core::Digest,
) -> DurableProjectionResult<(), LogError, AuthError, S::Error>
where
    S: VisaSourceRuntime,
{
    let binding = runtime
        .joint_runtime_binding()
        .map_err(|error| DurableProjectionError::Projection(ProjectionError::Runtime(error)))?;
    if binding.journal_position != expected_position || binding.state_digest != expected_digest {
        return Err(DurableProjectionError::PreStateMismatch);
    }
    Ok(())
}

fn ensure_destination_pre_state<D, LogError, AuthError>(
    runtime: &D,
    expected_position: contract_core::JournalPosition,
    expected_digest: contract_core::Digest,
) -> DurableProjectionResult<(), LogError, AuthError, D::Error>
where
    D: VisaDestinationRuntime,
{
    let binding = runtime
        .joint_runtime_binding()
        .map_err(|error| DurableProjectionError::Projection(ProjectionError::Runtime(error)))?;
    if binding.journal_position != expected_position || binding.state_digest != expected_digest {
        return Err(DurableProjectionError::PreStateMismatch);
    }
    Ok(())
}
