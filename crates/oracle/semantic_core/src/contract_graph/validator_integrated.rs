use alloc::vec::Vec;

use super::*;

impl ContractGraphValidator {
    pub(super) fn validate_integrated_smp_preemption_cleanups(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_smp_preemption_cleanups {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSmpPreemptionCleanupState::Recorded
                || record.stress_run_generation == 0
                || record.preemption_generation == 0
                || record.timer_interrupt_generation == 0
                || record.saved_context_generation == 0
                || record.remote_preempt_generation == 0
                || record.activation_cleanup_generation == 0
                || record.smp_cleanup_quiescence_generation == 0
                || record.target_store_generation == 0
                || record.result_store_generation <= record.target_store_generation
                || record.cleanup_activation_generation_after == 0
                || record.hart_count < 2
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-smp-preemption-cleanup->contract",
                    from,
                    None,
                    "integrated SMP/preemption/cleanup evidence requires exact refs, 2+ harts, completed cleanup, and recorded state",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-smp-preemption-cleanup->smp-stress-run",
                    ContractObjectKind::SmpStressRun,
                    record.stress_run,
                    record.stress_run_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->preemption",
                    ContractObjectKind::Preemption,
                    record.preemption,
                    record.preemption_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->timer-interrupt",
                    ContractObjectKind::TimerInterrupt,
                    record.timer_interrupt,
                    record.timer_interrupt_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->saved-context",
                    ContractObjectKind::SavedContext,
                    record.saved_context,
                    record.saved_context_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->remote-preempt",
                    ContractObjectKind::RemotePreempt,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->activation-cleanup",
                    ContractObjectKind::ActivationCleanup,
                    record.activation_cleanup,
                    record.activation_cleanup_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->smp-cleanup-quiescence",
                    ContractObjectKind::SmpCleanupQuiescence,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                ),
                (
                    "integrated-smp-preemption-cleanup->cleanup-store",
                    ContractObjectKind::Store,
                    record.cleanup_store,
                    record.target_store_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(preemption) = snapshot.preemptions.iter().find(|preemption| {
                preemption.id == record.preemption
                    && preemption.generation == record.preemption_generation
            }) {
                if preemption.state != PreemptionState::Applied
                    || preemption.timer_interrupt != record.timer_interrupt
                    || preemption.timer_interrupt_generation != record.timer_interrupt_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-preemption-cleanup->preemption-binding",
                        from,
                        Some(preemption.object_ref()),
                        "integrated evidence preemption does not match timer attribution",
                    ));
                }
            }
            if let Some(saved) = snapshot.saved_contexts.iter().find(|saved| {
                saved.id == record.saved_context
                    && saved.generation == record.saved_context_generation
            }) {
                if saved.state == SavedContextState::Dropped
                    || saved.source_preemption != Some(record.preemption)
                    || saved.source_preemption_generation != Some(record.preemption_generation)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-preemption-cleanup->saved-context-binding",
                        from,
                        Some(saved.object_ref()),
                        "integrated evidence saved context is not attributed to the preemption",
                    ));
                }
            }
            if let Some(remote) = snapshot.remote_preempts.iter().find(|remote| {
                remote.id == record.remote_preempt
                    && remote.generation == record.remote_preempt_generation
            }) {
                if remote.state != RemotePreemptState::Applied
                    || remote.source_hart == remote.target_hart
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-preemption-cleanup->remote-preempt-binding",
                        from,
                        Some(remote.object_ref()),
                        "integrated evidence remote preempt is not cross-hart applied evidence",
                    ));
                }
            }
            if let Some(cleanup) = snapshot.activation_cleanups.iter().find(|cleanup| {
                cleanup.id == record.activation_cleanup
                    && cleanup.generation == record.activation_cleanup_generation
            }) {
                if cleanup.state != ActivationCleanupState::Completed
                    || cleanup.store != record.cleanup_store
                    || cleanup.target_store_generation != record.target_store_generation
                    || cleanup.result_store_generation != record.result_store_generation
                    || cleanup.activation != record.cleanup_activation
                    || cleanup.activation_generation_after
                        != record.cleanup_activation_generation_after
                    || cleanup.wait.is_none()
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-preemption-cleanup->cleanup-binding",
                        from,
                        Some(cleanup.object_ref()),
                        "integrated evidence cleanup does not prove completed wait-cancelling store cleanup",
                    ));
                }
            }
            if let Some(quiescence) = snapshot.smp_cleanup_quiescence.iter().find(|quiescence| {
                quiescence.id == record.smp_cleanup_quiescence
                    && quiescence.generation == record.smp_cleanup_quiescence_generation
            }) {
                if quiescence.state != SmpCleanupQuiescenceState::Validated
                    || quiescence.cleanup != record.activation_cleanup
                    || quiescence.cleanup_generation != record.activation_cleanup_generation
                    || quiescence.store != record.cleanup_store
                    || quiescence.target_store_generation != record.target_store_generation
                    || quiescence.result_store_generation != record.result_store_generation
                    || quiescence.participants.len() < 2
                    || !quiescence.no_running_activation
                    || !quiescence.no_pending_wait
                    || !quiescence.no_live_capability
                    || !quiescence.no_live_resource
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-preemption-cleanup->quiescence-binding",
                        from,
                        Some(quiescence.object_ref()),
                        "integrated evidence quiescence does not close the cleanup boundary",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_integrated_smp_network_faults(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_smp_network_faults {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSmpNetworkFaultState::Recorded
                || record.network_driver_cleanup_generation == 0
                || record.smp_stress_run_generation == 0
                || record.remote_preempt_generation == 0
                || record.smp_cleanup_quiescence_generation == 0
                || record.driver_store_generation == 0
                || record.packet_device_generation == 0
                || record.adapter_generation == 0
                || record.backend.generation == 0
                || record.io_cleanup_generation == 0
                || record.cancelled_socket_wait_count == 0
                || record.cancelled_wait_token_count == 0
                || record.revoked_packet_capability_count == 0
                || record.hart_count < 2
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-smp-network-fault->contract",
                    from,
                    None,
                    "integrated SMP/network-fault evidence requires exact refs, completed network cleanup effects, 2+ harts, and recorded state",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-smp-network-fault->network-driver-cleanup",
                    ContractObjectKind::NetworkDriverCleanup,
                    record.network_driver_cleanup,
                    record.network_driver_cleanup_generation,
                ),
                (
                    "integrated-smp-network-fault->smp-stress-run",
                    ContractObjectKind::SmpStressRun,
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                ),
                (
                    "integrated-smp-network-fault->remote-preempt",
                    ContractObjectKind::RemotePreempt,
                    record.remote_preempt,
                    record.remote_preempt_generation,
                ),
                (
                    "integrated-smp-network-fault->smp-cleanup-quiescence",
                    ContractObjectKind::SmpCleanupQuiescence,
                    record.smp_cleanup_quiescence,
                    record.smp_cleanup_quiescence_generation,
                ),
                (
                    "integrated-smp-network-fault->packet-device",
                    ContractObjectKind::PacketDeviceObject,
                    record.packet_device,
                    record.packet_device_generation,
                ),
                (
                    "integrated-smp-network-fault->network-stack-adapter",
                    ContractObjectKind::NetworkStackAdapter,
                    record.adapter,
                    record.adapter_generation,
                ),
                (
                    "integrated-smp-network-fault->io-cleanup",
                    ContractObjectKind::IoCleanup,
                    record.io_cleanup,
                    record.io_cleanup_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "integrated-smp-network-fault->backend",
                record.backend.kind,
                record.backend.id,
                record.backend.generation,
                ContractEdgeMode::Historical,
            );
            if let Some(cleanup) = snapshot.network_driver_cleanups.iter().find(|cleanup| {
                cleanup.id == record.network_driver_cleanup
                    && cleanup.generation == record.network_driver_cleanup_generation
            }) {
                if cleanup.state != NetworkDriverCleanupState::Completed
                    || cleanup.driver_store != record.driver_store
                    || cleanup.driver_store_generation != record.driver_store_generation
                    || cleanup.packet_device != record.packet_device
                    || cleanup.packet_device_generation != record.packet_device_generation
                    || cleanup.adapter != record.adapter
                    || cleanup.adapter_generation != record.adapter_generation
                    || cleanup.backend != record.backend
                    || cleanup.io_cleanup != record.io_cleanup
                    || cleanup.io_cleanup_generation != record.io_cleanup_generation
                    || cleanup.cancelled_socket_waits.len() as u32
                        != record.cancelled_socket_wait_count
                    || cleanup.cancelled_wait_tokens.len() as u32
                        != record.cancelled_wait_token_count
                    || cleanup.revoked_packet_capabilities.len() as u32
                        != record.revoked_packet_capability_count
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-network-fault->network-cleanup-binding",
                        from,
                        Some(cleanup.object_ref()),
                        "integrated evidence network cleanup does not match recorded closure effects",
                    ));
                }
            }
            if let Some(stress) = snapshot.smp_stress_runs.iter().find(|run| {
                run.id == record.smp_stress_run
                    && run.generation == record.smp_stress_run_generation
            }) {
                if stress.state != SmpStressRunState::Recorded
                    || stress.property_failures != 0
                    || stress.hart_count != record.hart_count
                    || stress.hart_count < 2
                    || stress.observed_remote_preempt_count == 0
                    || stress.observed_cleanup_quiescence_count == 0
                    || stress.last_remote_preempt != record.remote_preempt
                    || stress.last_remote_preempt_generation != record.remote_preempt_generation
                    || stress.last_cleanup_quiescence != record.smp_cleanup_quiescence
                    || stress.last_cleanup_quiescence_generation
                        != record.smp_cleanup_quiescence_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-network-fault->smp-stress-binding",
                        from,
                        Some(stress.object_ref()),
                        "integrated evidence stress run does not prove cross-hart cleanup context",
                    ));
                }
            }
            if let Some(remote) = snapshot.remote_preempts.iter().find(|remote| {
                remote.id == record.remote_preempt
                    && remote.generation == record.remote_preempt_generation
            }) {
                if remote.state != RemotePreemptState::Applied
                    || remote.source_hart == remote.target_hart
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-network-fault->remote-preempt-binding",
                        from,
                        Some(remote.object_ref()),
                        "integrated evidence remote preempt is not cross-hart applied evidence",
                    ));
                }
            }
            if let Some(quiescence) = snapshot.smp_cleanup_quiescence.iter().find(|quiescence| {
                quiescence.id == record.smp_cleanup_quiescence
                    && quiescence.generation == record.smp_cleanup_quiescence_generation
            }) {
                if quiescence.state != SmpCleanupQuiescenceState::Validated
                    || quiescence.participants.len() < 2
                    || quiescence.participants.iter().any(|participant| !participant.quiesced)
                    || !quiescence.no_running_activation
                    || !quiescence.no_pending_wait
                    || !quiescence.no_live_capability
                    || !quiescence.no_live_resource
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-smp-network-fault->quiescence-binding",
                        from,
                        Some(quiescence.object_ref()),
                        "integrated evidence quiescence does not prove an SMP-safe fault context",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_integrated_disk_preempt_faults(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_disk_preempt_faults {
            let from = record.object_ref();
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
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-disk-preempt-fault->contract",
                    from,
                    None,
                    "integrated disk/preempt fault evidence requires exact refs, applied preemption, cancelled block wait, and retry/EIO policy",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-disk-preempt-fault->preemption",
                    ContractObjectKind::Preemption,
                    record.preemption,
                    record.preemption_generation,
                ),
                (
                    "integrated-disk-preempt-fault->timer-interrupt",
                    ContractObjectKind::TimerInterrupt,
                    record.timer_interrupt,
                    record.timer_interrupt_generation,
                ),
                (
                    "integrated-disk-preempt-fault->block-pending-io-policy",
                    ContractObjectKind::BlockPendingIoPolicy,
                    record.block_pending_io_policy,
                    record.block_pending_io_policy_generation,
                ),
                (
                    "integrated-disk-preempt-fault->block-wait",
                    ContractObjectKind::BlockWait,
                    record.block_wait,
                    record.block_wait_generation,
                ),
                (
                    "integrated-disk-preempt-fault->wait",
                    ContractObjectKind::WaitToken,
                    record.wait,
                    record.wait_generation,
                ),
                (
                    "integrated-disk-preempt-fault->block-request",
                    ContractObjectKind::BlockRequestObject,
                    record.block_request,
                    record.block_request_generation,
                ),
                (
                    "integrated-disk-preempt-fault->block-device",
                    ContractObjectKind::BlockDeviceObject,
                    record.block_device,
                    record.block_device_generation,
                ),
                (
                    "integrated-disk-preempt-fault->block-range",
                    ContractObjectKind::BlockRangeObject,
                    record.block_range,
                    record.block_range_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let (Some(retry_request), Some(retry_generation)) =
                (record.retry_request, record.retry_request_generation)
            {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    "integrated-disk-preempt-fault->retry-request",
                    ContractObjectKind::BlockRequestObject,
                    retry_request,
                    retry_generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(preemption) = snapshot.preemptions.iter().find(|preemption| {
                preemption.id == record.preemption
                    && preemption.generation == record.preemption_generation
            }) {
                if preemption.state != PreemptionState::Applied
                    || preemption.timer_interrupt != record.timer_interrupt
                    || preemption.timer_interrupt_generation != record.timer_interrupt_generation
                    || preemption.activation != record.preempted_activation
                    || preemption.activation_generation_after
                        != record.preempted_activation_generation_after
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->preemption-binding",
                        from,
                        Some(preemption.object_ref()),
                        "integrated disk/preempt fault preemption attribution does not match the recorded preempted activation",
                    ));
                }
            }
            if let Some(timer) = snapshot.timer_interrupts.iter().find(|timer| {
                timer.id == record.timer_interrupt
                    && timer.generation == record.timer_interrupt_generation
            }) {
                if timer.state != TimerInterruptState::Recorded
                    || timer.target_activation != Some(record.preempted_activation)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->timer-binding",
                        from,
                        Some(timer.object_ref()),
                        "integrated disk/preempt fault timer interrupt does not target the preempted activation",
                    ));
                }
            }
            if let Some(policy) = snapshot.block_pending_io_policies.iter().find(|policy| {
                policy.id == record.block_pending_io_policy
                    && policy.generation == record.block_pending_io_policy_generation
            }) {
                let expected_state = match record.action {
                    BlockPendingIoAction::Retry => BlockPendingIoPolicyState::RetryScheduled,
                    BlockPendingIoAction::Eio => BlockPendingIoPolicyState::EioReturned,
                    BlockPendingIoAction::Cancel => BlockPendingIoPolicyState::Cancelled,
                };
                if policy.state != expected_state
                    || policy.action != record.action
                    || policy.errno != record.errno
                    || policy.block_wait != record.block_wait
                    || policy.block_wait_generation != record.block_wait_generation
                    || policy.wait != record.wait
                    || policy.wait_generation != record.wait_generation
                    || policy.block_request != record.block_request
                    || policy.block_request_generation != record.block_request_generation
                    || policy.retry_request != record.retry_request
                    || policy.retry_request_generation != record.retry_request_generation
                    || policy.block_device != record.block_device
                    || policy.block_device_generation != record.block_device_generation
                    || policy.block_range != record.block_range
                    || policy.block_range_generation != record.block_range_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->policy-binding",
                        from,
                        Some(policy.object_ref()),
                        "integrated disk/preempt fault policy binding does not match recorded pending IO fault evidence",
                    ));
                }
            }
            if let Some(block_wait) = snapshot.block_waits.iter().find(|wait| {
                wait.id == record.block_wait && wait.generation == record.block_wait_generation
            }) {
                if block_wait.state != BlockWaitState::Cancelled
                    || block_wait.cancel_reason != Some(WaitCancelReason::DeviceFault)
                    || block_wait.wait != record.wait
                    || block_wait.wait_generation != record.wait_generation
                    || block_wait.block_request != record.block_request
                    || block_wait.block_request_generation != record.block_request_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->block-wait-binding",
                        from,
                        Some(block_wait.object_ref()),
                        "integrated disk/preempt fault block wait is not the cancelled device-fault wait",
                    ));
                }
            }
            if let Some(wait) = snapshot
                .waits
                .iter()
                .find(|wait| wait.id == record.wait && wait.generation == record.wait_generation)
            {
                if wait.state != WaitState::Cancelled
                    || wait.cancel_reason != Some(WaitCancelReason::DeviceFault)
                    || wait.owner_store != record.driver_store
                    || wait.owner_store_generation != record.driver_store_generation
                    || !wait.blockers.iter().any(|blocker| {
                        *blocker
                            == ContractObjectRef::new(
                                ContractObjectKind::BlockRequestObject,
                                record.block_request,
                                record.block_request_generation,
                            )
                    })
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->wait-binding",
                        from,
                        Some(wait.object_ref()),
                        "integrated disk/preempt fault wait token does not carry the cancelled block request blocker",
                    ));
                }
            }
            if let Some(request) = snapshot.block_request_objects.iter().find(|request| {
                request.id == record.block_request
                    && request.generation == record.block_request_generation
            }) {
                if request.block_device != record.block_device
                    || request.block_device_generation != record.block_device_generation
                    || request.block_range != record.block_range
                    || request.block_range_generation != record.block_range_generation
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-disk-preempt-fault->request-binding",
                        from,
                        Some(request.object_ref()),
                        "integrated disk/preempt fault request does not match block device/range refs",
                    ));
                }
            }
            if snapshot.block_waits.iter().any(|wait| {
                wait.block_request == record.block_request
                    && wait.block_request_generation == record.block_request_generation
                    && wait.state == BlockWaitState::Pending
            }) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::LiveObjectReferencesDeadObject,
                    "integrated-disk-preempt-fault->pending-wait-leak",
                    from,
                    Some(ContractObjectRef::new(
                        ContractObjectKind::BlockRequestObject,
                        record.block_request,
                        record.block_request_generation,
                    )),
                    "integrated disk/preempt fault cannot leave the faulted block request pending",
                ));
            }
        }
    }

    pub(super) fn validate_integrated_simd_migrations(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_simd_migrations {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSimdMigrationState::Recorded
                || record.activation_migration_generation == 0
                || record.target_feature_set_generation == 0
                || record.source_vector_state.generation == 0
                || record.migrated_vector_state.generation == 0
                || record.activation_generation_before == 0
                || record.activation_generation_after <= record.activation_generation_before
                || record.context_generation_after == 0
                || record.source_hart_generation == 0
                || record.target_hart_generation == 0
                || record.source_hart == record.target_hart
                || record.source_queue_generation == 0
                || record.target_queue_generation == 0
                || record.simd_abi.is_empty()
                || record.vector_register_count == 0
                || record.vector_register_bits == 0
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-simd-migration->contract",
                    from,
                    None,
                    "integrated SIMD migration requires exact refs and clean cross-hart vector migration evidence",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-simd-migration->activation-migration",
                    ContractObjectKind::ActivationMigration,
                    record.activation_migration,
                    record.activation_migration_generation,
                ),
                (
                    "integrated-simd-migration->target-feature-set",
                    ContractObjectKind::TargetFeatureSet,
                    record.target_feature_set,
                    record.target_feature_set_generation,
                ),
                (
                    "integrated-simd-migration->activation-before",
                    ContractObjectKind::Activation,
                    record.activation,
                    record.activation_generation_before,
                ),
                (
                    "integrated-simd-migration->activation-after",
                    ContractObjectKind::Activation,
                    record.activation,
                    record.activation_generation_after,
                ),
                (
                    "integrated-simd-migration->source-hart",
                    ContractObjectKind::Hart,
                    u64::from(record.source_hart),
                    record.source_hart_generation,
                ),
                (
                    "integrated-simd-migration->target-hart",
                    ContractObjectKind::Hart,
                    u64::from(record.target_hart),
                    record.target_hart_generation,
                ),
                (
                    "integrated-simd-migration->source-queue",
                    ContractObjectKind::RunnableQueue,
                    record.source_queue,
                    record.source_queue_generation,
                ),
                (
                    "integrated-simd-migration->target-queue",
                    ContractObjectKind::RunnableQueue,
                    record.target_queue,
                    record.target_queue_generation,
                ),
                (
                    "integrated-simd-migration->context",
                    ContractObjectKind::ActivationContext,
                    record.context,
                    record.context_generation_after,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            for (label, object) in [
                ("integrated-simd-migration->source-vector-state", record.source_vector_state),
                ("integrated-simd-migration->migrated-vector-state", record.migrated_vector_state),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    object.kind,
                    object.id,
                    object.generation,
                    ContractEdgeMode::Historical,
                );
            }
            if let Some(migration) = snapshot.activation_migrations.iter().find(|migration| {
                migration.id == record.activation_migration
                    && migration.generation == record.activation_migration_generation
            }) {
                if migration.state != ActivationMigrationState::Applied
                    || migration.source_hart == migration.target_hart
                    || migration.activation != record.activation
                    || migration.activation_generation_before != record.activation_generation_before
                    || migration.activation_generation_after != record.activation_generation_after
                    || migration.source_hart != record.source_hart
                    || migration.source_hart_generation != record.source_hart_generation
                    || migration.target_hart != record.target_hart
                    || migration.target_hart_generation != record.target_hart_generation
                    || migration.source_queue != record.source_queue
                    || migration.source_queue_generation != record.source_queue_generation
                    || migration.target_queue != record.target_queue
                    || migration.target_queue_generation != record.target_queue_generation
                    || migration.context != Some(record.context)
                    || migration.context_generation_after != Some(record.context_generation_after)
                    || migration.source_vector_state != Some(record.source_vector_state)
                    || migration.migrated_vector_state != Some(record.migrated_vector_state)
                    || migration.vector_status != ActivationVectorState::Clean
                    || migration.vector_migrated_at_event.is_none()
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-simd-migration->activation-migration-binding",
                        from,
                        Some(migration.object_ref()),
                        "integrated SIMD migration activation migration binding does not match clean cross-hart vector evidence",
                    ));
                }
            }
            if let Some(feature) = snapshot.target_feature_sets.iter().find(|feature| {
                feature.id == record.target_feature_set
                    && feature.generation == record.target_feature_set_generation
            }) {
                if feature.state != TargetFeatureSetState::Discovered
                    || !feature.simd_supported
                    || feature.simd_abi != record.simd_abi
                    || feature.vector_register_count != record.vector_register_count
                    || feature.vector_register_bits != record.vector_register_bits
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-simd-migration->target-feature-binding",
                        from,
                        Some(feature.object_ref()),
                        "integrated SIMD migration target feature set does not support the recorded vector shape",
                    ));
                }
            }
            let source = snapshot.vector_states.iter().find(|vector| {
                vector.id == record.source_vector_state.id
                    && vector.generation == record.source_vector_state.generation
            });
            let migrated = snapshot.vector_states.iter().find(|vector| {
                vector.id == record.migrated_vector_state.id
                    && vector.generation == record.migrated_vector_state.generation
            });
            if let (Some(source), Some(migrated)) = (source, migrated) {
                if source.state != VectorStateState::Dropped
                    || migrated.state != VectorStateState::Reserved
                    || source.owner_activation
                        != ContractObjectRef::new(
                            ContractObjectKind::Activation,
                            record.activation,
                            record.activation_generation_before,
                        )
                    || migrated.owner_activation
                        != ContractObjectRef::new(
                            ContractObjectKind::Activation,
                            record.activation,
                            record.activation_generation_after,
                        )
                    || source.target_feature_set
                        != ContractObjectRef::new(
                            ContractObjectKind::TargetFeatureSet,
                            record.target_feature_set,
                            record.target_feature_set_generation,
                        )
                    || migrated.target_feature_set != source.target_feature_set
                    || source.simd_abi != record.simd_abi
                    || migrated.simd_abi != record.simd_abi
                    || source.vector_register_count != record.vector_register_count
                    || migrated.vector_register_count != record.vector_register_count
                    || source.vector_register_bits != record.vector_register_bits
                    || migrated.vector_register_bits != record.vector_register_bits
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-simd-migration->vector-binding",
                        from,
                        Some(migrated.object_ref()),
                        "integrated SIMD migration source/migrated vector state refs do not prove clean rehome semantics",
                    ));
                }
            }
            if let Some(context) = snapshot.activation_contexts.iter().find(|context| {
                context.id == record.context
                    && context.generation == record.context_generation_after
            }) {
                if context.activation != record.activation
                    || context.activation_generation != record.activation_generation_after
                    || context.vector_state != Some(record.migrated_vector_state)
                    || context.vector_status != ActivationVectorState::Clean
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-simd-migration->context-binding",
                        from,
                        Some(context.object_ref()),
                        "integrated SIMD migration context must point at the clean migrated vector state",
                    ));
                }
            }
            if snapshot.vector_states.iter().any(|vector| {
                vector.owner_activation
                    == ContractObjectRef::new(
                        ContractObjectKind::Activation,
                        record.activation,
                        record.activation_generation_before,
                    )
                    && vector.state == VectorStateState::Reserved
            }) {
                violations.push(ContractViolation::new(
                    ContractViolationKind::LiveObjectReferencesDeadObject,
                    "integrated-simd-migration->old-vector-live-leak",
                    from,
                    Some(ContractObjectRef::new(
                        ContractObjectKind::Activation,
                        record.activation,
                        record.activation_generation_before,
                    )),
                    "integrated SIMD migration cannot leave reserved vector state on the old activation generation",
                ));
            }
        }
    }

    pub(super) fn validate_integrated_network_disk_ios(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_network_disk_ios {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedNetworkDiskIoState::Recorded
                || record.network_benchmark_generation == 0
                || record.block_benchmark_generation == 0
                || record.network_owner_store_generation == 0
                || record.network_adapter_generation == 0
                || record.packet_device_generation == 0
                || record.socket_generation == 0
                || record.block_backend.generation == 0
                || record.block_device_generation == 0
                || record.block_request_queue_generation == 0
                || record.block_dma_buffer_generation == 0
                || record.network_sample_bytes == 0
                || record.block_sample_bytes == 0
                || record.network_sample_packets == 0
                || record.block_sample_requests == 0
                || record.concurrent_window_nanos == 0
                || record.combined_throughput_bytes_per_sec == 0
                || record.max_p99_latency_nanos == 0
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-network-disk-io->contract",
                    from,
                    None,
                    "integrated network/disk IO requires exact benchmark refs and measured window evidence",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-network-disk-io->network-benchmark",
                    ContractObjectKind::NetworkBenchmark,
                    record.network_benchmark,
                    record.network_benchmark_generation,
                ),
                (
                    "integrated-network-disk-io->block-benchmark",
                    ContractObjectKind::BlockBenchmark,
                    record.block_benchmark,
                    record.block_benchmark_generation,
                ),
                (
                    "integrated-network-disk-io->network-owner-store",
                    ContractObjectKind::Store,
                    record.network_owner_store,
                    record.network_owner_store_generation,
                ),
                (
                    "integrated-network-disk-io->network-adapter",
                    ContractObjectKind::NetworkStackAdapter,
                    record.network_adapter,
                    record.network_adapter_generation,
                ),
                (
                    "integrated-network-disk-io->packet-device",
                    ContractObjectKind::PacketDeviceObject,
                    record.packet_device,
                    record.packet_device_generation,
                ),
                (
                    "integrated-network-disk-io->socket",
                    ContractObjectKind::SocketObject,
                    record.socket,
                    record.socket_generation,
                ),
                (
                    "integrated-network-disk-io->block-device",
                    ContractObjectKind::BlockDeviceObject,
                    record.block_device,
                    record.block_device_generation,
                ),
                (
                    "integrated-network-disk-io->block-request-queue",
                    ContractObjectKind::BlockRequestQueue,
                    record.block_request_queue,
                    record.block_request_queue_generation,
                ),
                (
                    "integrated-network-disk-io->block-dma-buffer",
                    ContractObjectKind::BlockDmaBuffer,
                    record.block_dma_buffer,
                    record.block_dma_buffer_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "integrated-network-disk-io->block-backend",
                record.block_backend.kind,
                record.block_backend.id,
                record.block_backend.generation,
                ContractEdgeMode::Historical,
            );
            let network = snapshot.network_benchmarks.iter().find(|benchmark| {
                benchmark.id == record.network_benchmark
                    && benchmark.generation == record.network_benchmark_generation
            });
            let block = snapshot.block_benchmarks.iter().find(|benchmark| {
                benchmark.id == record.block_benchmark
                    && benchmark.generation == record.block_benchmark_generation
            });
            if let (Some(network), Some(block)) = (network, block) {
                let total_bytes =
                    network.sample_bytes.checked_add(block.sample_bytes).unwrap_or_default();
                let expected_window = network.measured_nanos.max(block.measured_nanos);
                let expected_throughput = if expected_window == 0 {
                    0
                } else {
                    total_bytes
                        .checked_mul(1_000_000_000)
                        .map(|scaled| scaled / expected_window)
                        .unwrap_or_default()
                };
                if network.state != NetworkBenchmarkState::Recorded
                    || block.state != BlockBenchmarkState::Recorded
                    || network.owner_store != record.network_owner_store
                    || network.owner_store_generation != record.network_owner_store_generation
                    || network.adapter != record.network_adapter
                    || network.adapter_generation != record.network_adapter_generation
                    || network.packet_device != record.packet_device
                    || network.packet_device_generation != record.packet_device_generation
                    || network.socket != record.socket
                    || network.socket_generation != record.socket_generation
                    || block.backend != record.block_backend
                    || block.block_device != record.block_device
                    || block.block_device_generation != record.block_device_generation
                    || block.request_queue != record.block_request_queue
                    || block.request_queue_generation != record.block_request_queue_generation
                    || block.block_dma_buffer != record.block_dma_buffer
                    || block.block_dma_buffer_generation != record.block_dma_buffer_generation
                    || network.sample_bytes != record.network_sample_bytes
                    || block.sample_bytes != record.block_sample_bytes
                    || network.sample_packets != record.network_sample_packets
                    || block.sample_requests != record.block_sample_requests
                    || record.concurrent_window_nanos != expected_window
                    || record.combined_throughput_bytes_per_sec != expected_throughput
                    || record.max_p99_latency_nanos
                        != network.p99_latency_nanos.max(block.p99_latency_nanos)
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-network-disk-io->benchmark-binding",
                        from,
                        Some(network.object_ref()),
                        "integrated network/disk IO record does not match benchmark evidence",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_integrated_display_scheduler_loads(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_display_scheduler_loads {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedDisplaySchedulerLoadState::Recorded
                || record.framebuffer_benchmark_generation == 0
                || record.scheduler_decision_generation == 0
                || record.owner_store_generation == 0
                || record.owner_task_generation == 0
                || record.queue_generation == 0
                || record.selected_activation_generation == 0
                || record.display_generation == 0
                || record.framebuffer_generation == 0
                || record.display_capability_generation == 0
                || record.framebuffer_write_generation == 0
                || record.framebuffer_flush_region_generation == 0
                || record.display_event_log_generation == 0
                || record.sample_frames == 0
                || record.sample_bytes == 0
                || record.scheduler_load_units == 0
                || record.display_measured_nanos == 0
                || record.scheduler_decided_at_event == 0
                || record.display_recorded_at_event == 0
                || record.scheduler_decided_at_event > record.display_recorded_at_event
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-display-scheduler-load->contract",
                    from,
                    None,
                    "integrated display/scheduler load requires exact display benchmark and scheduler evidence",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-display-scheduler-load->framebuffer-benchmark",
                    ContractObjectKind::FramebufferBenchmark,
                    record.framebuffer_benchmark,
                    record.framebuffer_benchmark_generation,
                ),
                (
                    "integrated-display-scheduler-load->scheduler-decision",
                    ContractObjectKind::SchedulerDecision,
                    record.scheduler_decision,
                    record.scheduler_decision_generation,
                ),
                (
                    "integrated-display-scheduler-load->owner-store",
                    ContractObjectKind::Store,
                    record.owner_store,
                    record.owner_store_generation,
                ),
                (
                    "integrated-display-scheduler-load->runnable-queue",
                    ContractObjectKind::RunnableQueue,
                    record.queue,
                    record.queue_generation,
                ),
                (
                    "integrated-display-scheduler-load->display",
                    ContractObjectKind::DisplayObject,
                    record.display,
                    record.display_generation,
                ),
                (
                    "integrated-display-scheduler-load->framebuffer",
                    ContractObjectKind::FramebufferObject,
                    record.framebuffer,
                    record.framebuffer_generation,
                ),
                (
                    "integrated-display-scheduler-load->display-capability",
                    ContractObjectKind::DisplayCapability,
                    record.display_capability,
                    record.display_capability_generation,
                ),
                (
                    "integrated-display-scheduler-load->framebuffer-write",
                    ContractObjectKind::FramebufferWrite,
                    record.framebuffer_write,
                    record.framebuffer_write_generation,
                ),
                (
                    "integrated-display-scheduler-load->framebuffer-flush-region",
                    ContractObjectKind::FramebufferFlushRegion,
                    record.framebuffer_flush_region,
                    record.framebuffer_flush_region_generation,
                ),
                (
                    "integrated-display-scheduler-load->display-event-log",
                    ContractObjectKind::DisplayEventLog,
                    record.display_event_log,
                    record.display_event_log_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
            let benchmark = snapshot.framebuffer_benchmarks.iter().find(|benchmark| {
                benchmark.id == record.framebuffer_benchmark
                    && benchmark.generation == record.framebuffer_benchmark_generation
            });
            let decision = snapshot.scheduler_decisions.iter().find(|decision| {
                decision.id == record.scheduler_decision
                    && decision.generation == record.scheduler_decision_generation
            });
            if let (Some(benchmark), Some(decision)) = (benchmark, decision) {
                if benchmark.state != FramebufferBenchmarkState::Recorded
                    || decision.state == SchedulerDecisionState::Dropped
                    || benchmark.owner_store != record.owner_store
                    || benchmark.owner_store_generation != record.owner_store_generation
                    || decision.owner_task != record.owner_task
                    || decision.owner_task_generation != record.owner_task_generation
                    || decision.queue != record.queue
                    || decision.queue_generation != record.queue_generation
                    || decision.selected_activation != record.selected_activation
                    || decision.selected_activation_generation
                        != record.selected_activation_generation
                    || benchmark.display != record.display
                    || benchmark.display_generation != record.display_generation
                    || benchmark.framebuffer != record.framebuffer
                    || benchmark.framebuffer_generation != record.framebuffer_generation
                    || benchmark.display_capability != record.display_capability
                    || benchmark.display_capability_generation
                        != record.display_capability_generation
                    || benchmark.framebuffer_write != record.framebuffer_write
                    || benchmark.framebuffer_write_generation != record.framebuffer_write_generation
                    || benchmark.framebuffer_flush_region != record.framebuffer_flush_region
                    || benchmark.framebuffer_flush_region_generation
                        != record.framebuffer_flush_region_generation
                    || benchmark.display_event_log != record.display_event_log
                    || benchmark.display_event_log_generation != record.display_event_log_generation
                    || benchmark.sample_frames != record.sample_frames
                    || benchmark.sample_bytes != record.sample_bytes
                    || benchmark.measured_nanos != record.display_measured_nanos
                    || decision.decided_at_event != record.scheduler_decided_at_event
                    || benchmark.recorded_at_event != record.display_recorded_at_event
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-display-scheduler-load->evidence-binding",
                        from,
                        Some(benchmark.object_ref()),
                        "integrated display/scheduler load record does not match source evidence",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_integrated_snapshot_io_lease_barriers(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_snapshot_io_lease_barriers {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedSnapshotIoLeaseBarrierState::Recorded
                || record.smp_snapshot_barrier_generation == 0
                || record.io_cleanup_generation == 0
                || record.display_snapshot_barrier_generation == 0
                || record.driver_store_generation == 0
                || record.device_generation == 0
                || record.display_generation == 0
                || record.framebuffer_generation == 0
                || record.active_dmw_lease_count != 0
                || record.in_flight_dma_count != 0
                || record.raw_dma_binding_count != 0
                || record.raw_mmio_binding_count != 0
                || record.active_framebuffer_window_lease_count != 0
                || record.active_framebuffer_mapping_count != 0
                || record.dirty_framebuffer_region_count != 0
                || record.released_dma_buffers == 0
                || record.released_mmio_regions == 0
                || record.released_irq_lines == 0
                || record.released_framebuffer_window_leases == 0
                || record.revoked_device_capabilities == 0
                || record.revoked_display_capabilities == 0
                || record.smp_barrier_event == 0
                || record.io_cleanup_completed_event == 0
                || record.display_barrier_event == 0
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-snapshot-io-lease-barrier->contract",
                    from,
                    None,
                    "integrated snapshot/io lease barrier requires clean snapshot barriers and cleanup evidence",
                ));
                continue;
            }
            for (label, kind, id, generation) in [
                (
                    "integrated-snapshot-io-lease-barrier->smp-snapshot-barrier",
                    ContractObjectKind::SmpSnapshotBarrier,
                    record.smp_snapshot_barrier,
                    record.smp_snapshot_barrier_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->io-cleanup",
                    ContractObjectKind::IoCleanup,
                    record.io_cleanup,
                    record.io_cleanup_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->display-snapshot-barrier",
                    ContractObjectKind::DisplaySnapshotBarrier,
                    record.display_snapshot_barrier,
                    record.display_snapshot_barrier_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->driver-store",
                    ContractObjectKind::Store,
                    record.driver_store,
                    record.driver_store_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->device",
                    ContractObjectKind::DeviceObject,
                    record.device,
                    record.device_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->display",
                    ContractObjectKind::DisplayObject,
                    record.display,
                    record.display_generation,
                ),
                (
                    "integrated-snapshot-io-lease-barrier->framebuffer",
                    ContractObjectKind::FramebufferObject,
                    record.framebuffer,
                    record.framebuffer_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }

            let smp_barrier = snapshot.smp_snapshot_barriers.iter().find(|barrier| {
                barrier.id == record.smp_snapshot_barrier
                    && barrier.generation == record.smp_snapshot_barrier_generation
            });
            let cleanup = snapshot.io_cleanups.iter().find(|cleanup| {
                cleanup.id == record.io_cleanup
                    && cleanup.generation == record.io_cleanup_generation
            });
            let display_barrier = snapshot.display_snapshot_barriers.iter().find(|barrier| {
                barrier.id == record.display_snapshot_barrier
                    && barrier.generation == record.display_snapshot_barrier_generation
            });
            if let (Some(smp_barrier), Some(cleanup), Some(display_barrier)) =
                (smp_barrier, cleanup, display_barrier)
            {
                let display_cleanup = display_barrier
                    .display_cleanup
                    .zip(display_barrier.display_cleanup_generation)
                    .and_then(|(cleanup_id, generation)| {
                        snapshot.display_cleanups.iter().find(|cleanup| {
                            cleanup.id == cleanup_id && cleanup.generation == generation
                        })
                    });
                if smp_barrier.state != SmpSnapshotBarrierState::Validated
                    || !smp_barrier.snapshot_validation_ok
                    || smp_barrier.active_dmw_lease_count != record.active_dmw_lease_count
                    || smp_barrier.in_flight_dma_count != record.in_flight_dma_count
                    || smp_barrier.raw_dma_binding_count != record.raw_dma_binding_count
                    || smp_barrier.raw_mmio_binding_count != record.raw_mmio_binding_count
                    || cleanup.state != IoCleanupState::Completed
                    || cleanup.driver_store != record.driver_store
                    || cleanup.driver_store_generation != record.driver_store_generation
                    || cleanup.device != record.device
                    || cleanup.device_generation != record.device_generation
                    || cleanup.released_dma_buffers.len() as u32 != record.released_dma_buffers
                    || cleanup.released_mmio_regions.len() as u32 != record.released_mmio_regions
                    || cleanup.released_irq_lines.len() as u32 != record.released_irq_lines
                    || cleanup.revoked_device_capabilities.len() as u32
                        != record.revoked_device_capabilities
                    || display_barrier.state != DisplaySnapshotBarrierState::Validated
                    || !display_barrier.snapshot_validation_ok
                    || display_barrier.display != record.display
                    || display_barrier.display_generation != record.display_generation
                    || display_barrier.framebuffer != record.framebuffer
                    || display_barrier.framebuffer_generation != record.framebuffer_generation
                    || display_barrier.active_framebuffer_window_lease_count
                        != record.active_framebuffer_window_lease_count
                    || display_barrier.active_framebuffer_mapping_count
                        != record.active_framebuffer_mapping_count
                    || display_barrier.dirty_framebuffer_region_count
                        != record.dirty_framebuffer_region_count
                    || smp_barrier.validated_at_event != record.smp_barrier_event
                    || cleanup.completed_at_event != record.io_cleanup_completed_event
                    || display_barrier.validated_at_event != record.display_barrier_event
                    || display_cleanup.is_none_or(|cleanup| {
                        cleanup.released_framebuffer_window_leases.len() as u32
                            != record.released_framebuffer_window_leases
                            || cleanup.revoked_display_capabilities.len() as u32
                                != record.revoked_display_capabilities
                    })
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-snapshot-io-lease-barrier->evidence-binding",
                        from,
                        Some(smp_barrier.object_ref()),
                        "integrated snapshot/io lease barrier record does not match source cleanup and barrier evidence",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_integrated_code_publish_smp_workloads(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_code_publish_smp_workloads {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedCodePublishSmpWorkloadState::Recorded
                || record.smp_stress_run_generation == 0
                || record.smp_code_publish_barrier_generation == 0
                || record.publish_rendezvous_generation == 0
                || record.publish_safe_point_generation == 0
                || record.hart_count < 2
                || record.workload_iterations < 3
                || record.observed_safe_point_count == 0
                || record.observed_rendezvous_count == 0
                || record.observed_code_publish_barrier_count == 0
                || record.code_publish_epoch_after != record.code_publish_epoch_before + 1
                || !record.remote_icache_sync_required
                || record.code_publish_executed
                || record.participant_count < 2
                || record.stress_event_log_cursor < record.barrier_event
                || record.stress_recorded_at_event <= record.barrier_event
                || record.invariant_checks == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-code-publish-smp-workload->contract",
                    from,
                    None,
                    "integrated code publish/SMP workload requires clean stress and semantic publish barrier evidence",
                ));
                continue;
            }

            for (label, kind, id, generation) in [
                (
                    "integrated-code-publish-smp-workload->smp-stress-run",
                    ContractObjectKind::SmpStressRun,
                    record.smp_stress_run,
                    record.smp_stress_run_generation,
                ),
                (
                    "integrated-code-publish-smp-workload->smp-code-publish-barrier",
                    ContractObjectKind::SmpCodePublishBarrier,
                    record.smp_code_publish_barrier,
                    record.smp_code_publish_barrier_generation,
                ),
                (
                    "integrated-code-publish-smp-workload->stop-the-world-rendezvous",
                    ContractObjectKind::StopTheWorldRendezvous,
                    record.publish_rendezvous,
                    record.publish_rendezvous_generation,
                ),
                (
                    "integrated-code-publish-smp-workload->smp-safe-point",
                    ContractObjectKind::SmpSafePoint,
                    record.publish_safe_point,
                    record.publish_safe_point_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }

            let stress = snapshot.smp_stress_runs.iter().find(|stress| {
                stress.id == record.smp_stress_run
                    && stress.generation == record.smp_stress_run_generation
            });
            let barrier = snapshot.smp_code_publish_barriers.iter().find(|barrier| {
                barrier.id == record.smp_code_publish_barrier
                    && barrier.generation == record.smp_code_publish_barrier_generation
            });
            let rendezvous = snapshot.stop_the_world_rendezvous.iter().find(|rendezvous| {
                rendezvous.id == record.publish_rendezvous
                    && rendezvous.generation == record.publish_rendezvous_generation
            });
            if let (Some(stress), Some(barrier), Some(rendezvous)) = (stress, barrier, rendezvous) {
                if stress.state != SmpStressRunState::Recorded
                    || stress.property_failures != 0
                    || stress.hart_count != record.hart_count
                    || stress.iterations != record.workload_iterations
                    || stress.observed_safe_point_count != record.observed_safe_point_count
                    || stress.observed_rendezvous_count != record.observed_rendezvous_count
                    || stress.observed_code_publish_barrier_count
                        != record.observed_code_publish_barrier_count
                    || stress.last_code_publish_barrier != barrier.id
                    || stress.last_code_publish_barrier_generation != barrier.generation
                    || stress.event_log_cursor != record.stress_event_log_cursor
                    || stress.recorded_at_event != record.stress_recorded_at_event
                    || barrier.state != SmpCodePublishBarrierState::Validated
                    || barrier.rendezvous != record.publish_rendezvous
                    || barrier.rendezvous_generation != record.publish_rendezvous_generation
                    || barrier.code_publish_epoch_before != record.code_publish_epoch_before
                    || barrier.code_publish_epoch_after != record.code_publish_epoch_after
                    || barrier.remote_icache_sync_required != record.remote_icache_sync_required
                    || barrier.code_publish_executed != record.code_publish_executed
                    || barrier.participants.len() as u32 != record.participant_count
                    || barrier.validated_at_event != record.barrier_event
                    || rendezvous.safe_point != record.publish_safe_point
                    || rendezvous.safe_point_generation != record.publish_safe_point_generation
                    || rendezvous.state != StopTheWorldRendezvousState::Completed
                    || !rendezvous.stop_new_activations
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-code-publish-smp-workload->evidence-binding",
                        from,
                        Some(barrier.object_ref()),
                        "integrated code publish/SMP workload record does not match stress and publish barrier evidence",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_integrated_display_panics(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_display_panics {
            let from = record.object_ref();
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedDisplayPanicState::Recorded
                || record.substrate_panic_event == 0
                || record.display_panic_last_frame_generation == 0
                || record.panic_ring_bytes != 65_536
                || record.panic_record_max_bytes != 4_096
                || record.panic_ring_oldest_seq == 0
                || record.panic_ring_newest_seq < record.panic_ring_oldest_seq
                || record.panic_ring_record_count < 2
                || record
                    .panic_ring_newest_seq
                    .saturating_sub(record.panic_ring_oldest_seq)
                    .saturating_add(1)
                    < u64::from(record.panic_ring_record_count)
                || record.panic_ring_lost_count != 0
                || record.jsonl_frame_count < record.panic_ring_record_count.saturating_add(2)
                || record.contract_panic_summary_records == 0
                || record.last_frame_summary_records == 0
                || record.corrupt_record_count != 0
                || record.truncated_record_count != 0
                || record.summary_record_bytes == 0
                || record.summary_record_bytes > record.panic_record_max_bytes
                || record.raw_framebuffer_bytes_exported
                || record.panic_path_allocates
                || record.invariant_checks == 0
                || record.recorded_at_event == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-display-panic->contract",
                    from,
                    None,
                    "integrated display panic requires clean panic-ring extraction and bounded last-frame summary",
                ));
                continue;
            }
            Self::check_generation_edge(
                snapshot,
                violations,
                from,
                "integrated-display-panic->display-panic-last-frame",
                ContractObjectKind::DisplayPanicLastFrame,
                record.display_panic_last_frame,
                record.display_panic_last_frame_generation,
                ContractEdgeMode::Historical,
            );
            if let Some(frame) = snapshot.display_panic_last_frames.iter().find(|frame| {
                frame.id == record.display_panic_last_frame
                    && frame.generation == record.display_panic_last_frame_generation
            }) {
                if frame.state != DisplayPanicLastFrameState::Recorded
                    || frame.raw_framebuffer_bytes_exported
                    || frame.summary_record_bytes != record.summary_record_bytes
                    || frame.panic_epoch != record.substrate_panic_epoch
                    || frame.panic_cpu != record.substrate_panic_cpu
                    || frame.panic_reason_code != record.substrate_panic_reason_code
                    || frame.panic_record_kind != "contract-panic-summary-v1"
                {
                    violations.push(ContractViolation::new(
                        ContractViolationKind::GenerationMismatch,
                        "integrated-display-panic->last-frame-binding",
                        from,
                        Some(frame.object_ref()),
                        "integrated display panic does not match last-frame panic summary evidence",
                    ));
                }
            }
        }
    }

    pub(super) fn validate_integrated_osctl_trace_replays(
        snapshot: &ContractGraphSnapshot,
        violations: &mut Vec<ContractViolation>,
    ) {
        for record in &snapshot.integrated_osctl_trace_replays {
            let from = record.object_ref();
            let source_events = [
                snapshot
                    .integrated_smp_preemption_cleanups
                    .iter()
                    .find(|source| {
                        source.id == record.integrated_smp_preemption_cleanup
                            && source.generation
                                == record.integrated_smp_preemption_cleanup_generation
                            && source.state == IntegratedSmpPreemptionCleanupState::Recorded
                    })
                    .map(|source| source.recorded_at_event),
                snapshot
                    .integrated_smp_network_faults
                    .iter()
                    .find(|source| {
                        source.id == record.integrated_smp_network_fault
                            && source.generation == record.integrated_smp_network_fault_generation
                            && source.state == IntegratedSmpNetworkFaultState::Recorded
                    })
                    .map(|source| source.recorded_at_event),
                snapshot
                    .integrated_disk_preempt_faults
                    .iter()
                    .find(|source| {
                        source.id == record.integrated_disk_preempt_fault
                            && source.generation == record.integrated_disk_preempt_fault_generation
                            && source.state == IntegratedDiskPreemptFaultState::Recorded
                    })
                    .map(|source| source.recorded_at_event),
                snapshot
                    .integrated_simd_migrations
                    .iter()
                    .find(|source| {
                        source.id == record.integrated_simd_migration
                            && source.generation == record.integrated_simd_migration_generation
                            && source.state == IntegratedSimdMigrationState::Recorded
                    })
                    .map(|source| source.recorded_at_event),
                snapshot
                    .integrated_network_disk_ios
                    .iter()
                    .find(|source| {
                        source.id == record.integrated_network_disk_io
                            && source.generation == record.integrated_network_disk_io_generation
                            && source.state == IntegratedNetworkDiskIoState::Recorded
                    })
                    .map(|source| source.recorded_at_event),
                snapshot
                    .integrated_display_scheduler_loads
                    .iter()
                    .find(|source| {
                        source.id == record.integrated_display_scheduler_load
                            && source.generation
                                == record.integrated_display_scheduler_load_generation
                            && source.state == IntegratedDisplaySchedulerLoadState::Recorded
                    })
                    .map(|source| source.recorded_at_event),
                snapshot
                    .integrated_snapshot_io_lease_barriers
                    .iter()
                    .find(|source| {
                        source.id == record.integrated_snapshot_io_lease_barrier
                            && source.generation
                                == record.integrated_snapshot_io_lease_barrier_generation
                            && source.state == IntegratedSnapshotIoLeaseBarrierState::Recorded
                    })
                    .map(|source| source.recorded_at_event),
                snapshot
                    .integrated_code_publish_smp_workloads
                    .iter()
                    .find(|source| {
                        source.id == record.integrated_code_publish_smp_workload
                            && source.generation
                                == record.integrated_code_publish_smp_workload_generation
                            && source.state == IntegratedCodePublishSmpWorkloadState::Recorded
                    })
                    .map(|source| source.recorded_at_event),
                snapshot
                    .integrated_display_panics
                    .iter()
                    .find(|source| {
                        source.id == record.integrated_display_panic
                            && source.generation == record.integrated_display_panic_generation
                            && source.state == IntegratedDisplayPanicState::Recorded
                    })
                    .map(|source| source.recorded_at_event),
            ];
            let roots_match_counts = record.integrated_scenario_count == 9
                && record.stable_view_count >= record.integrated_scenario_count
                && record.historical_edge_count >= record.integrated_scenario_count
                && record.replayed_root_count >= record.integrated_scenario_count
                && record.replay_fixture_count >= record.integrated_scenario_count;
            let graph_history_ok =
                source_events.iter().all(Option::is_some) && record.historical_edge_count >= 9;
            let max_source_event =
                source_events.iter().filter_map(|event| *event).max().unwrap_or(0);
            let replay_validation_ok = graph_history_ok
                && record.replay_event_cursor >= max_source_event
                && record.replay_event_cursor != 0;
            let contract_validation_ok = graph_history_ok
                && replay_validation_ok
                && roots_match_counts
                && record.invariant_checks != 0;
            if record.id == 0
                || record.generation == 0
                || record.scenario.is_empty()
                || record.state != IntegratedOsctlTraceReplayState::Recorded
                || record.replay_event_cursor == 0
                || record.integrated_scenario_count != 9
                || record.stable_view_count < 9
                || record.historical_edge_count < 9
                || record.replayed_root_count < 9
                || record.replay_fixture_count < 9
                || record.contract_validation_ok != contract_validation_ok
                || record.replay_validation_ok != replay_validation_ok
                || record.graph_history_ok != graph_history_ok
                || record.roots_match_counts != roots_match_counts
                || record.invariant_checks == 0
                || record.recorded_at_event == 0
            {
                violations.push(ContractViolation::new(
                    ContractViolationKind::ExternalEdgeMetadataMismatch,
                    "integrated-osctl-trace-replay->contract",
                    from,
                    None,
                    "integrated osctl trace replay derived evidence mismatch",
                ));
            }

            for (label, kind, id, generation) in [
                (
                    "integrated-osctl-trace-replay->x0-smp-preemption-cleanup",
                    ContractObjectKind::IntegratedSmpPreemptionCleanup,
                    record.integrated_smp_preemption_cleanup,
                    record.integrated_smp_preemption_cleanup_generation,
                ),
                (
                    "integrated-osctl-trace-replay->x1-smp-network-fault",
                    ContractObjectKind::IntegratedSmpNetworkFault,
                    record.integrated_smp_network_fault,
                    record.integrated_smp_network_fault_generation,
                ),
                (
                    "integrated-osctl-trace-replay->x2-disk-preempt-fault",
                    ContractObjectKind::IntegratedDiskPreemptFault,
                    record.integrated_disk_preempt_fault,
                    record.integrated_disk_preempt_fault_generation,
                ),
                (
                    "integrated-osctl-trace-replay->x3-simd-migration",
                    ContractObjectKind::IntegratedSimdMigration,
                    record.integrated_simd_migration,
                    record.integrated_simd_migration_generation,
                ),
                (
                    "integrated-osctl-trace-replay->x4-network-disk-io",
                    ContractObjectKind::IntegratedNetworkDiskIo,
                    record.integrated_network_disk_io,
                    record.integrated_network_disk_io_generation,
                ),
                (
                    "integrated-osctl-trace-replay->x5-display-scheduler-load",
                    ContractObjectKind::IntegratedDisplaySchedulerLoad,
                    record.integrated_display_scheduler_load,
                    record.integrated_display_scheduler_load_generation,
                ),
                (
                    "integrated-osctl-trace-replay->x6-snapshot-io-lease-barrier",
                    ContractObjectKind::IntegratedSnapshotIoLeaseBarrier,
                    record.integrated_snapshot_io_lease_barrier,
                    record.integrated_snapshot_io_lease_barrier_generation,
                ),
                (
                    "integrated-osctl-trace-replay->x7-code-publish-smp-workload",
                    ContractObjectKind::IntegratedCodePublishSmpWorkload,
                    record.integrated_code_publish_smp_workload,
                    record.integrated_code_publish_smp_workload_generation,
                ),
                (
                    "integrated-osctl-trace-replay->x8-display-panic",
                    ContractObjectKind::IntegratedDisplayPanic,
                    record.integrated_display_panic,
                    record.integrated_display_panic_generation,
                ),
            ] {
                Self::check_generation_edge(
                    snapshot,
                    violations,
                    from,
                    label,
                    kind,
                    id,
                    generation,
                    ContractEdgeMode::Historical,
                );
            }
        }
    }
}
