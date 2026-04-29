use alloc::vec::Vec;

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct SemanticDomains {
    pub(crate) capability: CapabilityDomain,
    pub(crate) resource: ResourceDomain,
    pub(crate) wait: WaitDomain,
    pub(crate) io: IoDomain,
    pub(crate) runtime: RuntimeDomain,
    pub(crate) lifecycle: LifecycleDomain,
    pub(crate) display: DisplayDomain,
    pub(crate) scheduler: SchedulerDomain,
    pub(crate) simd: SimdDomain,
    #[allow(dead_code)]
    pub(crate) memory: MemoryDomain,
}

impl SemanticDomains {
    pub(crate) fn new() -> Self {
        Self {
            capability: CapabilityDomain::new(),
            resource: ResourceDomain::new(),
            wait: WaitDomain::new(),
            io: IoDomain::new(),
            runtime: RuntimeDomain::new(),
            lifecycle: LifecycleDomain::new(),
            display: DisplayDomain::new(),
            scheduler: SchedulerDomain::new(),
            simd: SimdDomain::new(),
            memory: MemoryDomain::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CapabilityDomain {
    pub(crate) capabilities: CapabilityLedger,
}

impl CapabilityDomain {
    fn new() -> Self {
        Self { capabilities: CapabilityLedger::new() }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResourceDomain {
    pub(crate) resources: Vec<ResourceRecord>,
    pub(crate) authority_bindings: Vec<AuthorityBindingRecord>,
    pub(crate) next_resource_id: ResourceId,
    pub(crate) next_authority_id: AuthorityId,
}

impl ResourceDomain {
    fn new() -> Self {
        Self {
            resources: Vec::new(),
            authority_bindings: Vec::new(),
            next_resource_id: 1,
            next_authority_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct WaitDomain {
    pub(crate) waits: Vec<WaitRecord>,
}

impl WaitDomain {
    fn new() -> Self {
        Self { waits: Vec::new() }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IoDomain {
    pub(crate) io_waits: Vec<IoWaitRecord>,
    pub(crate) io_cleanups: Vec<IoCleanupRecord>,
    pub(crate) io_fault_injections: Vec<IoFaultInjectionRecord>,
    pub(crate) io_validation_reports: Vec<IoValidationReportRecord>,
    pub(crate) next_io_wait_id: IoWaitId,
    pub(crate) next_io_cleanup_id: IoCleanupId,
    pub(crate) next_io_fault_injection_id: IoFaultInjectionId,
    pub(crate) next_io_validation_report_id: IoValidationReportId,
}

impl IoDomain {
    fn new() -> Self {
        Self {
            io_waits: Vec::new(),
            io_cleanups: Vec::new(),
            io_fault_injections: Vec::new(),
            io_validation_reports: Vec::new(),
            next_io_wait_id: 1,
            next_io_cleanup_id: 1,
            next_io_fault_injection_id: 1,
            next_io_validation_report_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LifecycleDomain {
    pub(crate) fault_domains: Vec<FaultDomainRecord>,
    pub(crate) stores: Vec<StoreRecord>,
    pub(crate) transactions: Vec<SemanticTransactionRecord>,
    pub(crate) fast_path_plans: Vec<FastPathPlanRecord>,
    pub(crate) next_fault_domain_id: FaultDomainId,
    pub(crate) next_store_id: StoreId,
    pub(crate) next_transaction_id: TransactionId,
    pub(crate) next_plan_id: PlanId,
}

impl LifecycleDomain {
    fn new() -> Self {
        Self {
            fault_domains: Vec::new(),
            stores: Vec::new(),
            transactions: Vec::new(),
            fast_path_plans: Vec::new(),
            next_fault_domain_id: 1,
            next_store_id: 1,
            next_transaction_id: 1,
            next_plan_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DisplayDomain {
    pub(crate) framebuffer_objects: Vec<FramebufferObjectRecord>,
    pub(crate) display_objects: Vec<DisplayObjectRecord>,
    pub(crate) display_capabilities: Vec<DisplayCapabilityRecord>,
    pub(crate) framebuffer_window_leases: Vec<FramebufferWindowLeaseRecord>,
    pub(crate) framebuffer_mappings: Vec<FramebufferMappingRecord>,
    pub(crate) framebuffer_writes: Vec<FramebufferWriteRecord>,
    pub(crate) framebuffer_flush_regions: Vec<FramebufferFlushRegionRecord>,
    pub(crate) framebuffer_dirty_regions: Vec<FramebufferDirtyRegionRecord>,
    pub(crate) display_event_logs: Vec<DisplayEventLogRecord>,
    pub(crate) display_cleanups: Vec<DisplayCleanupRecord>,
    pub(crate) display_snapshot_barriers: Vec<DisplaySnapshotBarrierRecord>,
    pub(crate) display_panic_last_frames: Vec<DisplayPanicLastFrameRecord>,
    pub(crate) framebuffer_benchmarks: Vec<FramebufferBenchmarkRecord>,
    pub(crate) next_framebuffer_object_id: FramebufferObjectId,
    pub(crate) next_display_object_id: DisplayObjectId,
    pub(crate) next_display_capability_id: DisplayCapabilityId,
    pub(crate) next_framebuffer_window_lease_id: FramebufferWindowLeaseId,
    pub(crate) next_framebuffer_mapping_id: FramebufferMappingId,
    pub(crate) next_framebuffer_write_id: FramebufferWriteId,
    pub(crate) next_framebuffer_flush_region_id: FramebufferFlushRegionId,
    pub(crate) next_framebuffer_dirty_region_id: FramebufferDirtyRegionId,
    pub(crate) next_display_event_log_id: DisplayEventLogId,
    pub(crate) next_display_cleanup_id: DisplayCleanupId,
    pub(crate) next_display_snapshot_barrier_id: DisplaySnapshotBarrierId,
    pub(crate) next_display_panic_last_frame_id: DisplayPanicLastFrameId,
    pub(crate) next_framebuffer_benchmark_id: FramebufferBenchmarkId,
}

impl DisplayDomain {
    fn new() -> Self {
        Self {
            framebuffer_objects: Vec::new(),
            display_objects: Vec::new(),
            display_capabilities: Vec::new(),
            framebuffer_window_leases: Vec::new(),
            framebuffer_mappings: Vec::new(),
            framebuffer_writes: Vec::new(),
            framebuffer_flush_regions: Vec::new(),
            framebuffer_dirty_regions: Vec::new(),
            display_event_logs: Vec::new(),
            display_cleanups: Vec::new(),
            display_snapshot_barriers: Vec::new(),
            display_panic_last_frames: Vec::new(),
            framebuffer_benchmarks: Vec::new(),
            next_framebuffer_object_id: 1,
            next_display_object_id: 1,
            next_display_capability_id: 1,
            next_framebuffer_window_lease_id: 1,
            next_framebuffer_mapping_id: 1,
            next_framebuffer_write_id: 1,
            next_framebuffer_flush_region_id: 1,
            next_framebuffer_dirty_region_id: 1,
            next_display_event_log_id: 1,
            next_display_cleanup_id: 1,
            next_display_snapshot_barrier_id: 1,
            next_display_panic_last_frame_id: 1,
            next_framebuffer_benchmark_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SchedulerDomain {
    pub(crate) harts: Vec<HartRecord>,
    pub(crate) tasks: Vec<TaskRecord>,
    pub(crate) runtime_activations: Vec<RuntimeActivationRecord>,
    pub(crate) runnable_queues: Vec<RunnableQueueRecord>,
    pub(crate) activation_contexts: Vec<ActivationContextRecord>,
    pub(crate) saved_contexts: Vec<SavedContextRecord>,
    pub(crate) timer_interrupts: Vec<TimerInterruptRecord>,
    pub(crate) ipi_events: Vec<IpiEventRecord>,
    pub(crate) remote_preempts: Vec<RemotePreemptRecord>,
    pub(crate) remote_parks: Vec<RemoteParkRecord>,
    pub(crate) preemptions: Vec<PreemptionRecord>,
    pub(crate) scheduler_decisions: Vec<SchedulerDecisionRecord>,
    pub(crate) cross_hart_scheduler_decisions: Vec<CrossHartSchedulerDecisionRecord>,
    pub(crate) activation_migrations: Vec<ActivationMigrationRecord>,
    pub(crate) smp_safe_points: Vec<SmpSafePointRecord>,
    pub(crate) stop_the_world_rendezvous: Vec<StopTheWorldRendezvousRecord>,
    pub(crate) smp_code_publish_barriers: Vec<SmpCodePublishBarrierRecord>,
    pub(crate) smp_cleanup_quiescence: Vec<SmpCleanupQuiescenceRecord>,
    pub(crate) smp_snapshot_barriers: Vec<SmpSnapshotBarrierRecord>,
    pub(crate) smp_stress_runs: Vec<SmpStressRunRecord>,
    pub(crate) smp_scaling_benchmarks: Vec<SmpScalingBenchmarkRecord>,
    pub(crate) activation_resumes: Vec<ActivationResumeRecord>,
    pub(crate) activation_waits: Vec<ActivationWaitRecord>,
    pub(crate) activation_cleanups: Vec<ActivationCleanupRecord>,
    pub(crate) preemption_latency_samples: Vec<PreemptionLatencySampleRecord>,
    pub(crate) hart_event_attributions: Vec<HartEventAttributionRecord>,
    pub(crate) next_runtime_activation_id: ActivationId,
    pub(crate) next_runnable_queue_id: RunnableQueueId,
    pub(crate) next_activation_context_id: ActivationContextId,
    pub(crate) next_saved_context_id: SavedContextId,
    pub(crate) next_timer_interrupt_id: TimerInterruptId,
    pub(crate) next_ipi_event_id: IpiEventId,
    pub(crate) next_remote_preempt_id: RemotePreemptId,
    pub(crate) next_remote_park_id: RemoteParkId,
    pub(crate) next_preemption_id: PreemptionId,
    pub(crate) next_scheduler_decision_id: SchedulerDecisionId,
    pub(crate) next_cross_hart_scheduler_decision_id: CrossHartSchedulerDecisionId,
    pub(crate) next_activation_migration_id: ActivationMigrationId,
    pub(crate) next_smp_safe_point_id: SmpSafePointId,
    pub(crate) next_stop_the_world_rendezvous_id: StopTheWorldRendezvousId,
    pub(crate) next_smp_code_publish_barrier_id: SmpCodePublishBarrierId,
    pub(crate) next_smp_cleanup_quiescence_id: SmpCleanupQuiescenceId,
    pub(crate) next_smp_snapshot_barrier_id: SmpSnapshotBarrierId,
    pub(crate) next_smp_stress_run_id: SmpStressRunId,
    pub(crate) next_smp_scaling_benchmark_id: SmpScalingBenchmarkId,
    pub(crate) next_activation_resume_id: ActivationResumeId,
    pub(crate) next_activation_wait_id: ActivationWaitId,
    pub(crate) next_activation_cleanup_id: ActivationCleanupId,
    pub(crate) next_preemption_latency_sample_id: PreemptionLatencySampleId,
    pub(crate) next_hart_event_attribution_id: HartEventAttributionId,
}

impl SchedulerDomain {
    fn new() -> Self {
        Self {
            harts: Vec::new(),
            tasks: Vec::new(),
            runtime_activations: Vec::new(),
            runnable_queues: Vec::new(),
            activation_contexts: Vec::new(),
            saved_contexts: Vec::new(),
            timer_interrupts: Vec::new(),
            ipi_events: Vec::new(),
            remote_preempts: Vec::new(),
            remote_parks: Vec::new(),
            preemptions: Vec::new(),
            scheduler_decisions: Vec::new(),
            cross_hart_scheduler_decisions: Vec::new(),
            activation_migrations: Vec::new(),
            smp_safe_points: Vec::new(),
            stop_the_world_rendezvous: Vec::new(),
            smp_code_publish_barriers: Vec::new(),
            smp_cleanup_quiescence: Vec::new(),
            smp_snapshot_barriers: Vec::new(),
            smp_stress_runs: Vec::new(),
            smp_scaling_benchmarks: Vec::new(),
            activation_resumes: Vec::new(),
            activation_waits: Vec::new(),
            activation_cleanups: Vec::new(),
            preemption_latency_samples: Vec::new(),
            hart_event_attributions: Vec::new(),
            next_runtime_activation_id: 1,
            next_runnable_queue_id: 1,
            next_activation_context_id: 1,
            next_saved_context_id: 1,
            next_timer_interrupt_id: 1,
            next_ipi_event_id: 1,
            next_remote_preempt_id: 1,
            next_remote_park_id: 1,
            next_preemption_id: 1,
            next_scheduler_decision_id: 1,
            next_cross_hart_scheduler_decision_id: 1,
            next_activation_migration_id: 1,
            next_smp_safe_point_id: 1,
            next_stop_the_world_rendezvous_id: 1,
            next_smp_code_publish_barrier_id: 1,
            next_smp_cleanup_quiescence_id: 1,
            next_smp_snapshot_barrier_id: 1,
            next_smp_stress_run_id: 1,
            next_smp_scaling_benchmark_id: 1,
            next_activation_resume_id: 1,
            next_activation_wait_id: 1,
            next_activation_cleanup_id: 1,
            next_preemption_latency_sample_id: 1,
            next_hart_event_attribution_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SimdDomain {
    pub(crate) target_feature_sets: Vec<TargetFeatureSetRecord>,
    pub(crate) vector_states: Vec<VectorStateRecord>,
    pub(crate) simd_fault_injections: Vec<SimdFaultInjectionRecord>,
    pub(crate) simd_benchmarks: Vec<SimdBenchmarkRecord>,
    pub(crate) simd_context_switch_benchmarks: Vec<SimdContextSwitchBenchmarkRecord>,
    pub(crate) next_target_feature_set_id: TargetFeatureSetId,
    pub(crate) next_vector_state_id: VectorStateId,
    pub(crate) next_simd_fault_injection_id: SimdFaultInjectionId,
    pub(crate) next_simd_benchmark_id: SimdBenchmarkId,
    pub(crate) next_simd_context_switch_benchmark_id: SimdContextSwitchBenchmarkId,
}

impl SimdDomain {
    fn new() -> Self {
        Self {
            target_feature_sets: Vec::new(),
            vector_states: Vec::new(),
            simd_fault_injections: Vec::new(),
            simd_benchmarks: Vec::new(),
            simd_context_switch_benchmarks: Vec::new(),
            next_target_feature_set_id: 1,
            next_vector_state_id: 1,
            next_simd_fault_injection_id: 1,
            next_simd_benchmark_id: 1,
            next_simd_context_switch_benchmark_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeDomain {
    pub(crate) boundaries: Vec<BoundaryRecord>,
    pub(crate) artifact_verifications: Vec<ArtifactVerificationRecord>,
    pub(crate) store_activations: Vec<StoreActivationRecord>,
    pub(crate) next_boundary_id: BoundaryId,
    pub(crate) next_artifact_id: ArtifactId,
    pub(crate) next_activation_id: StoreActivationId,
}

impl RuntimeDomain {
    fn new() -> Self {
        Self {
            boundaries: Vec::new(),
            artifact_verifications: Vec::new(),
            store_activations: Vec::new(),
            next_boundary_id: 1,
            next_artifact_id: 1,
            next_activation_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MemoryDomain;

impl MemoryDomain {
    fn new() -> Self {
        Self
    }
}
