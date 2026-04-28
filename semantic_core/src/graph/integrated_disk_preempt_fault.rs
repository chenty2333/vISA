use super::*;

impl SemanticGraph {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn validate_integrated_disk_preempt_fault(
        &self,
        integrated: IntegratedDiskPreemptFaultId,
        scenario: &str,
        preemption: PreemptionId,
        preemption_generation: Generation,
        block_pending_io_policy: BlockPendingIoPolicyId,
        block_pending_io_policy_generation: Generation,
        invariant_checks: u32,
    ) -> Result<(), &'static str> {
        if integrated == 0 {
            return Err("integrated disk/preempt fault id=0 is invalid");
        }
        if self
            .integrated_disk_preempt_faults
            .iter()
            .any(|record| record.id == integrated)
        {
            return Err("integrated disk/preempt fault evidence already exists");
        }
        if scenario.is_empty() {
            return Err("integrated disk/preempt fault scenario is empty");
        }
        if preemption_generation == 0
            || block_pending_io_policy_generation == 0
            || invariant_checks == 0
        {
            return Err("integrated disk/preempt fault refs must carry generations");
        }

        let Some(preemption_record) = self
            .preemptions
            .iter()
            .find(|record| record.id == preemption && record.generation == preemption_generation)
        else {
            return Err("integrated disk/preempt fault missing preemption evidence");
        };
        if preemption_record.state != PreemptionState::Applied
            || preemption_record.activation_generation_after
                <= preemption_record.activation_generation_before
        {
            return Err("integrated disk/preempt fault requires applied preemption evidence");
        }

        let Some(timer) = self.timer_interrupts.iter().find(|record| {
            record.id == preemption_record.timer_interrupt
                && record.generation == preemption_record.timer_interrupt_generation
        }) else {
            return Err("integrated disk/preempt fault missing timer interrupt evidence");
        };
        if timer.state != TimerInterruptState::Recorded
            || timer.target_activation != Some(preemption_record.activation)
            || timer.target_activation_generation
                != Some(preemption_record.activation_generation_before)
        {
            return Err("integrated disk/preempt fault timer attribution mismatch");
        }

        let Some(policy) = self.block_pending_io_policies.iter().find(|record| {
            record.id == block_pending_io_policy
                && record.generation == block_pending_io_policy_generation
        }) else {
            return Err("integrated disk/preempt fault missing block pending IO policy");
        };
        if policy.action == BlockPendingIoAction::Cancel
            || policy.state == BlockPendingIoPolicyState::Cancelled
            || policy.errno <= 0
        {
            return Err("integrated disk/preempt fault requires device-fault retry or EIO policy");
        }

        let Some(block_wait) = self.block_waits.iter().find(|record| {
            record.id == policy.block_wait && record.generation == policy.block_wait_generation
        }) else {
            return Err("integrated disk/preempt fault missing block wait evidence");
        };
        if block_wait.state != BlockWaitState::Cancelled
            || block_wait.cancel_reason != Some(WaitCancelReason::DeviceFault)
            || block_wait.wait != policy.wait
            || block_wait.wait_generation != policy.wait_generation
            || block_wait.block_request != policy.block_request
            || block_wait.block_request_generation != policy.block_request_generation
            || block_wait.block_device != policy.block_device
            || block_wait.block_device_generation != policy.block_device_generation
            || block_wait.block_range != policy.block_range
            || block_wait.block_range_generation != policy.block_range_generation
        {
            return Err("integrated disk/preempt fault block wait attribution mismatch");
        }

        let Some(wait) = self
            .waits
            .iter()
            .find(|record| record.id == policy.wait && record.generation == policy.wait_generation)
        else {
            return Err("integrated disk/preempt fault missing wait token evidence");
        };
        if wait.state != WaitState::Cancelled
            || wait.cancel_reason != Some(WaitCancelReason::DeviceFault)
            || !wait.blockers.iter().any(|blocker| {
                *blocker
                    == ContractObjectRef::new(
                        ContractObjectKind::BlockRequestObject,
                        policy.block_request,
                        policy.block_request_generation,
                    )
            })
        {
            return Err("integrated disk/preempt fault wait token attribution mismatch");
        }

        let Some(request) = self.block_request_objects.iter().find(|record| {
            record.id == policy.block_request
                && record.generation == policy.block_request_generation
        }) else {
            return Err("integrated disk/preempt fault missing block request evidence");
        };
        let Some(block_device) = self.block_device_objects.iter().find(|record| {
            record.id == policy.block_device && record.generation == policy.block_device_generation
        }) else {
            return Err("integrated disk/preempt fault missing block device evidence");
        };
        let Some(block_range) = self.block_range_objects.iter().find(|record| {
            record.id == policy.block_range && record.generation == policy.block_range_generation
        }) else {
            return Err("integrated disk/preempt fault missing block range evidence");
        };
        if request.block_device != block_device.id
            || request.block_device_generation != block_device.generation
            || request.block_range != block_range.id
            || request.block_range_generation != block_range.generation
            || block_range.block_device != block_device.id
            || block_range.block_device_generation != block_device.generation
            || self.block_waits.iter().any(|record| {
                record.block_request == policy.block_request
                    && record.block_request_generation == policy.block_request_generation
                    && record.state == BlockWaitState::Pending
            })
        {
            return Err("integrated disk/preempt fault block object attribution mismatch");
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_integrated_disk_preempt_fault_with_id(
        &mut self,
        integrated: IntegratedDiskPreemptFaultId,
        scenario: &str,
        preemption: PreemptionId,
        preemption_generation: Generation,
        block_pending_io_policy: BlockPendingIoPolicyId,
        block_pending_io_policy_generation: Generation,
        invariant_checks: u32,
        note: &str,
    ) -> bool {
        if self
            .validate_integrated_disk_preempt_fault(
                integrated,
                scenario,
                preemption,
                preemption_generation,
                block_pending_io_policy,
                block_pending_io_policy_generation,
                invariant_checks,
            )
            .is_err()
        {
            return false;
        }

        let Some(preemption_record) = self
            .preemptions
            .iter()
            .find(|record| record.id == preemption && record.generation == preemption_generation)
        else {
            return false;
        };
        let Some(policy) = self.block_pending_io_policies.iter().find(|record| {
            record.id == block_pending_io_policy
                && record.generation == block_pending_io_policy_generation
        }) else {
            return false;
        };
        let Some(wait) = self
            .waits
            .iter()
            .find(|record| record.id == policy.wait && record.generation == policy.wait_generation)
        else {
            return false;
        };

        let timer_interrupt = preemption_record.timer_interrupt;
        let timer_interrupt_generation = preemption_record.timer_interrupt_generation;
        let block_wait = policy.block_wait;
        let block_wait_generation = policy.block_wait_generation;
        let wait_id = policy.wait;
        let wait_generation = policy.wait_generation;
        let block_request = policy.block_request;
        let block_request_generation = policy.block_request_generation;
        let retry_request = policy.retry_request;
        let retry_request_generation = policy.retry_request_generation;
        let block_device = policy.block_device;
        let block_device_generation = policy.block_device_generation;
        let block_range = policy.block_range;
        let block_range_generation = policy.block_range_generation;
        let driver_store = wait.owner_store;
        let driver_store_generation = wait.owner_store_generation;
        let action = policy.action;
        let errno = policy.errno;
        let preempted_activation = preemption_record.activation;
        let preempted_activation_generation_after = preemption_record.activation_generation_after;
        let generation = 1;
        self.next_integrated_disk_preempt_fault_id = self
            .next_integrated_disk_preempt_fault_id
            .max(integrated.saturating_add(1));
        let recorded_at_event = self.event_log.push(
            "integrated-runtime",
            EventKind::IntegratedDiskPreemptFaultRecorded {
                scenario: scenario.to_string(),
                integrated,
                preemption,
                preemption_generation,
                timer_interrupt,
                timer_interrupt_generation,
                block_pending_io_policy,
                block_pending_io_policy_generation,
                block_wait,
                block_wait_generation,
                wait: wait_id,
                wait_generation,
                block_request,
                block_request_generation,
                block_device,
                block_device_generation,
                action,
                errno,
                preempted_activation,
                preempted_activation_generation_after,
                invariant_checks,
                generation,
            },
        );
        self.integrated_disk_preempt_faults
            .push(IntegratedDiskPreemptFaultRecord {
                id: integrated,
                scenario: scenario.to_string(),
                preemption,
                preemption_generation,
                timer_interrupt,
                timer_interrupt_generation,
                block_pending_io_policy,
                block_pending_io_policy_generation,
                block_wait,
                block_wait_generation,
                wait: wait_id,
                wait_generation,
                block_request,
                block_request_generation,
                retry_request,
                retry_request_generation,
                block_device,
                block_device_generation,
                block_range,
                block_range_generation,
                driver_store,
                driver_store_generation,
                action,
                errno,
                preempted_activation,
                preempted_activation_generation_after,
                invariant_checks,
                generation,
                state: IntegratedDiskPreemptFaultState::Recorded,
                recorded_at_event,
                note: note.to_string(),
            });
        true
    }

    pub fn integrated_disk_preempt_faults(&self) -> &[IntegratedDiskPreemptFaultRecord] {
        &self.integrated_disk_preempt_faults
    }

    pub fn integrated_disk_preempt_fault_count(&self) -> usize {
        self.integrated_disk_preempt_faults.len()
    }

    pub fn check_integrated_disk_preempt_fault_invariants(
        &self,
    ) -> Result<(), SemanticInvariantError> {
        for record in &self.integrated_disk_preempt_faults {
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedDiskPreemptFaultState::Recorded
                || record.preemption_generation == 0
                || record.timer_interrupt_generation == 0
                || record.block_pending_io_policy_generation == 0
                || record.block_wait_generation == 0
                || record.wait_generation == 0
                || record.block_request_generation == 0
                || record.block_device_generation == 0
                || record.block_range_generation == 0
                || record.preempted_activation_generation_after == 0
                || record.invariant_checks == 0
                || record.errno <= 0
                || record.action == BlockPendingIoAction::Cancel
            {
                return Err(SemanticInvariantError::IntegratedDiskPreemptFaultInvalid {
                    integrated: record.id,
                });
            }
            for (label, id, generation, refs) in [
                (
                    "preemption",
                    record.preemption,
                    record.preemption_generation,
                    self.preemptions
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "timer-interrupt",
                    record.timer_interrupt,
                    record.timer_interrupt_generation,
                    self.timer_interrupts
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "block-pending-io-policy",
                    record.block_pending_io_policy,
                    record.block_pending_io_policy_generation,
                    self.block_pending_io_policies
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
                (
                    "block-wait",
                    record.block_wait,
                    record.block_wait_generation,
                    self.block_waits
                        .iter()
                        .map(|item| (item.id, item.generation))
                        .collect::<Vec<_>>(),
                ),
            ] {
                if id == 0
                    || generation == 0
                    || !refs.into_iter().any(|item| item == (id, generation))
                {
                    return Err(
                        SemanticInvariantError::IntegratedDiskPreemptFaultMissingEvidence {
                            integrated: record.id,
                            evidence: label,
                        },
                    );
                }
            }
            if self
                .validate_integrated_disk_preempt_fault(
                    u64::MAX,
                    &record.scenario,
                    record.preemption,
                    record.preemption_generation,
                    record.block_pending_io_policy,
                    record.block_pending_io_policy_generation,
                    record.invariant_checks,
                )
                .is_err()
            {
                return Err(SemanticInvariantError::IntegratedDiskPreemptFaultInvalid {
                    integrated: record.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == record.recorded_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IntegratedDiskPreemptFaultRecorded {
                            scenario,
                            integrated,
                            preemption,
                            preemption_generation,
                            timer_interrupt,
                            timer_interrupt_generation,
                            block_pending_io_policy,
                            block_pending_io_policy_generation,
                            block_wait,
                            block_wait_generation,
                            wait,
                            wait_generation,
                            block_request,
                            block_request_generation,
                            block_device,
                            block_device_generation,
                            action,
                            errno,
                            preempted_activation,
                            preempted_activation_generation_after,
                            invariant_checks,
                            generation,
                        } if scenario == &record.scenario
                            && *integrated == record.id
                            && *preemption == record.preemption
                            && *preemption_generation == record.preemption_generation
                            && *timer_interrupt == record.timer_interrupt
                            && *timer_interrupt_generation == record.timer_interrupt_generation
                            && *block_pending_io_policy == record.block_pending_io_policy
                            && *block_pending_io_policy_generation
                                == record.block_pending_io_policy_generation
                            && *block_wait == record.block_wait
                            && *block_wait_generation == record.block_wait_generation
                            && *wait == record.wait
                            && *wait_generation == record.wait_generation
                            && *block_request == record.block_request
                            && *block_request_generation == record.block_request_generation
                            && *block_device == record.block_device
                            && *block_device_generation == record.block_device_generation
                            && *action == record.action
                            && *errno == record.errno
                            && *preempted_activation == record.preempted_activation
                            && *preempted_activation_generation_after
                                == record.preempted_activation_generation_after
                            && *invariant_checks == record.invariant_checks
                            && *generation == record.generation
                    )
            }) {
                return Err(
                    SemanticInvariantError::IntegratedDiskPreemptFaultMissingEvent {
                        integrated: record.id,
                    },
                );
            }
        }
        Ok(())
    }
}
