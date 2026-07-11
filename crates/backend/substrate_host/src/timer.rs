use std::time::{Duration, Instant};

use contract_core::{
    Digest, EffectKind, EffectOutcome, EffectRequest, EffectResult, EvidenceKind, EvidenceRef,
    Identity, LogicalDurationNanos, Rights,
};
use sha2::{Digest as _, Sha256};
use substrate_api::{ProviderError, ProviderErrorKind, TimerObservation, TimerPort, TimerRecovery};

use crate::{
    HostTimer, HostTimerState, SqliteProvider, authority::authorize_effect_on, database_error,
    effect_evidence, ensure_intent, error, lease::check_lease_on, load_operation_by_identity,
    next_identity, number, write_outcome,
};

impl TimerPort for SqliteProvider {
    fn arm(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        let EffectKind::TimerArm { remaining } = request.kind else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };
        let intent = ensure_intent(&self.connection, request)?;
        if let Some(outcome) = intent.record.outcome {
            return Ok(outcome);
        }
        authorize_effect_on(&self.connection, request, Rights::TIMER_ARM)?;
        check_lease_on(&self.connection, request.resource, request.node, request.lease_epoch)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_nanos(remaining.0))
            .ok_or_else(|| error(ProviderErrorKind::Unsupported, false))?;
        if self.timers.contains_key(&request.operation) {
            return Err(error(ProviderErrorKind::Conflict, false));
        }

        self.timers.insert(
            request.operation,
            HostTimer {
                resource: request.resource,
                owner: request.node,
                epoch: request.lease_epoch,
                state: HostTimerState::Pending { deadline },
            },
        );
        let result = (|| {
            let transaction = self.immediate_transaction()?;
            let result = EffectResult::TimerArmed { remaining };
            let outcome = EffectOutcome::Succeeded {
                evidence: effect_evidence(&transaction, request, &result)?,
                result,
            };
            write_outcome(&transaction, request.operation, &outcome)?;
            transaction.commit().map_err(database_error)?;
            Ok(outcome)
        })();
        if result.is_err() {
            self.timers.remove(&request.operation);
        }
        result
    }

    fn cancel(&mut self, request: &EffectRequest) -> Result<EffectOutcome, ProviderError> {
        let EffectKind::TimerCancel { target_operation } = request.kind else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };
        let intent = ensure_intent(&self.connection, request)?;
        if let Some(outcome) = intent.record.outcome {
            return Ok(outcome);
        }
        authorize_effect_on(&self.connection, request, Rights::TIMER_CANCEL)?;
        check_lease_on(&self.connection, request.resource, request.node, request.lease_epoch)?;

        if let Some(timer) = self.timers.get(&target_operation) {
            if timer.resource != request.resource
                || timer.owner != request.node
                || timer.epoch != request.lease_epoch
            {
                return Err(error(ProviderErrorKind::StaleEpoch, false));
            }
        } else {
            let target = load_operation_by_identity(&self.connection, target_operation)?
                .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;
            if !matches!(target.record.request.kind, EffectKind::TimerArm { .. })
                || target.record.request.resource != request.resource
            {
                return Err(error(ProviderErrorKind::Conflict, false));
            }
        }

        let transaction = self.immediate_transaction()?;
        let result = EffectResult::TimerCancelled;
        let outcome = EffectOutcome::Succeeded {
            evidence: effect_evidence(&transaction, request, &result)?,
            result,
        };
        write_outcome(&transaction, request.operation, &outcome)?;
        transaction.commit().map_err(database_error)?;
        if let Some(timer) = self.timers.get_mut(&target_operation) {
            let evidence = match &outcome {
                EffectOutcome::Succeeded { evidence, .. } => *evidence,
                _ => return Err(error(ProviderErrorKind::Integrity, false)),
            };
            timer.state = HostTimerState::Cancelled { evidence };
        }
        Ok(outcome)
    }

    fn restore_timer_binding(
        &mut self,
        arm_request: &EffectRequest,
        recovery: TimerRecovery,
    ) -> Result<(), ProviderError> {
        let EffectKind::TimerArm { .. } = arm_request.kind else {
            return Err(error(ProviderErrorKind::InvalidRequest, false));
        };
        let durable = ensure_intent(&self.connection, arm_request)?;
        if !matches!(
            durable.record.outcome,
            Some(EffectOutcome::Succeeded { result: EffectResult::TimerArmed { .. }, .. })
        ) {
            return Err(error(ProviderErrorKind::Conflict, false));
        }
        authorize_effect_on(&self.connection, arm_request, Rights::TIMER_ARM)?;
        check_lease_on(
            &self.connection,
            arm_request.resource,
            arm_request.node,
            arm_request.lease_epoch,
        )?;

        if let Some(existing) = self.timers.get(&arm_request.operation) {
            if existing.resource != arm_request.resource
                || existing.owner != arm_request.node
                || existing.epoch != arm_request.lease_epoch
            {
                return Err(error(ProviderErrorKind::Conflict, false));
            }
            return match (existing.state, recovery) {
                (HostTimerState::Pending { .. }, TimerRecovery::Running { .. }) => Ok(()),
                (
                    HostTimerState::Suspended { remaining: actual },
                    TimerRecovery::Suspended { remaining: expected },
                ) if actual == expected => Ok(()),
                _ => Err(error(ProviderErrorKind::Conflict, false)),
            };
        }

        let state = match recovery {
            TimerRecovery::Running { remaining } => {
                let deadline = Instant::now()
                    .checked_add(Duration::from_nanos(remaining.0))
                    .ok_or_else(|| error(ProviderErrorKind::Unsupported, false))?;
                HostTimerState::Pending { deadline }
            }
            TimerRecovery::Suspended { remaining } => HostTimerState::Suspended { remaining },
        };
        self.timers.insert(
            arm_request.operation,
            HostTimer {
                resource: arm_request.resource,
                owner: arm_request.node,
                epoch: arm_request.lease_epoch,
                state,
            },
        );
        Ok(())
    }

    fn observe(&mut self, arm_operation: Identity) -> Result<TimerObservation, ProviderError> {
        let Some(timer) = self.timers.get(&arm_operation) else {
            return Ok(TimerObservation::Absent);
        };
        match timer.state {
            HostTimerState::Pending { deadline } => {
                let now = Instant::now();
                if now >= deadline {
                    self.complete_timer(arm_operation)
                } else {
                    Ok(TimerObservation::Pending(duration_until(deadline, now)))
                }
            }
            HostTimerState::Suspended { remaining } => Ok(TimerObservation::Pending(remaining)),
            HostTimerState::Completed { evidence } => Ok(TimerObservation::Completed { evidence }),
            HostTimerState::Cancelled { evidence } => Ok(TimerObservation::Cancelled { evidence }),
        }
    }

    fn suspend_timer(
        &mut self,
        arm_operation: Identity,
    ) -> Result<TimerObservation, ProviderError> {
        let Some(timer) = self.timers.get(&arm_operation) else {
            return Ok(TimerObservation::Absent);
        };
        match timer.state {
            HostTimerState::Pending { deadline } => {
                let now = Instant::now();
                if now >= deadline {
                    return self.complete_timer(arm_operation);
                }
                let remaining = duration_until(deadline, now);
                self.timers
                    .get_mut(&arm_operation)
                    .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?
                    .state = HostTimerState::Suspended { remaining };
                Ok(TimerObservation::Pending(remaining))
            }
            HostTimerState::Suspended { remaining } => Ok(TimerObservation::Pending(remaining)),
            HostTimerState::Completed { evidence } => Ok(TimerObservation::Completed { evidence }),
            HostTimerState::Cancelled { evidence } => Ok(TimerObservation::Cancelled { evidence }),
        }
    }

    fn resume_suspended(&mut self, arm_operation: Identity) -> Result<(), ProviderError> {
        let Some(timer) = self.timers.get(&arm_operation) else {
            return Err(error(ProviderErrorKind::NotFound, false));
        };
        match timer.state {
            HostTimerState::Suspended { remaining } => {
                let deadline = Instant::now()
                    .checked_add(Duration::from_nanos(remaining.0))
                    .ok_or_else(|| error(ProviderErrorKind::Unsupported, false))?;
                self.timers
                    .get_mut(&arm_operation)
                    .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?
                    .state = HostTimerState::Pending { deadline };
                Ok(())
            }
            HostTimerState::Pending { .. } => Ok(()),
            HostTimerState::Completed { .. } | HostTimerState::Cancelled { .. } => {
                Err(error(ProviderErrorKind::Conflict, false))
            }
        }
    }

    fn cleanup_timer(&mut self, arm_operation: Identity) -> Result<(), ProviderError> {
        self.timers.remove(&arm_operation);
        Ok(())
    }
}

impl SqliteProvider {
    fn complete_timer(
        &mut self,
        arm_operation: Identity,
    ) -> Result<TimerObservation, ProviderError> {
        let timer = self
            .timers
            .get(&arm_operation)
            .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?;
        if let HostTimerState::Completed { evidence } = timer.state {
            return Ok(TimerObservation::Completed { evidence });
        }
        let mut digest = Sha256::new();
        digest.update(b"vISA timer completion");
        digest.update(arm_operation.0);
        digest.update(timer.resource.identity.0);
        digest.update(number(timer.resource.generation.0));
        digest.update(timer.owner.0.0);
        digest.update(number(timer.epoch.0));
        let evidence = EvidenceRef {
            identity: next_identity(&self.connection)?,
            kind: EvidenceKind::EffectOutcome,
            digest: Digest::from_bytes(digest.finalize().into()),
        };
        self.timers
            .get_mut(&arm_operation)
            .ok_or_else(|| error(ProviderErrorKind::NotFound, false))?
            .state = HostTimerState::Completed { evidence };
        Ok(TimerObservation::Completed { evidence })
    }
}

fn duration_until(deadline: Instant, now: Instant) -> LogicalDurationNanos {
    let nanos = deadline.duration_since(now).as_nanos();
    LogicalDurationNanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}
