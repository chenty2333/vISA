#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontendKind {
    Supervisor,
    LinuxElf,
    WasmApp,
    FutureRuntime,
}

impl FrontendKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor",
            Self::LinuxElf => "linux-elf",
            Self::WasmApp => "wasm-app",
            Self::FutureRuntime => "future-runtime",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HartState {
    Created,
    Booting,
    Idle,
    Running,
    Parked,
    Offline,
    Faulted,
}

impl HartState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Booting => "booting",
            Self::Idle => "idle",
            Self::Running => "running",
            Self::Parked => "parked",
            Self::Offline => "offline",
            Self::Faulted => "faulted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HartEventAttributionState {
    Recorded,
}

impl HartEventAttributionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpiEventKind {
    SchedulerKick,
    RescheduleHint,
    Diagnostics,
}

impl IpiEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SchedulerKick => "scheduler-kick",
            Self::RescheduleHint => "reschedule-hint",
            Self::Diagnostics => "diagnostics",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpiEventState {
    Recorded,
    Dropped,
}

impl IpiEventState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemotePreemptState {
    Applied,
    Rejected,
}

impl RemotePreemptState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Runnable,
    Running,
    Pending,
    Cancelled,
    Faulted,
    Exited,
    SnapshotFrozen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeActivationState {
    Created,
    Runnable,
    Running,
    Pending,
    Blocked,
    Dead,
    Exited,
}

impl RuntimeActivationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Runnable => "runnable",
            Self::Running => "running",
            Self::Pending => "pending",
            Self::Blocked => "blocked",
            Self::Dead => "dead",
            Self::Exited => "exited",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnableQueueState {
    Active,
    Draining,
    Frozen,
    Dropped,
}

impl RunnableQueueState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Frozen => "frozen",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationContextState {
    Created,
    Current,
    Saved,
    Restoring,
    Dropped,
}

impl ActivationContextState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Current => "current",
            Self::Saved => "saved",
            Self::Restoring => "restoring",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationVectorState {
    Absent,
    Clean,
    Dirty,
}

impl ActivationVectorState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Clean => "clean",
            Self::Dirty => "dirty",
        }
    }

    pub const fn requires_vector_state(self) -> bool {
        matches!(self, Self::Clean | Self::Dirty)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavedContextState {
    Captured,
    Superseded,
    Restored,
    Dropped,
}

impl SavedContextState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Captured => "captured",
            Self::Superseded => "superseded",
            Self::Restored => "restored",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavedContextReason {
    Initial,
    CooperativeYield,
    TimerPreempt,
    WaitPark,
    FaultSnapshot,
}

impl SavedContextReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::CooperativeYield => "cooperative-yield",
            Self::TimerPreempt => "timer-preempt",
            Self::WaitPark => "wait-park",
            Self::FaultSnapshot => "fault-snapshot",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerInterruptState {
    Recorded,
    Delivered,
    Acknowledged,
    Dropped,
}

impl TimerInterruptState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Delivered => "delivered",
            Self::Acknowledged => "acknowledged",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteParkState {
    Parked,
    Rejected,
}

impl RemoteParkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parked => "parked",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossHartSchedulerDecisionState {
    Recorded,
    Rejected,
}

impl CrossHartSchedulerDecisionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationMigrationState {
    Applied,
    Rejected,
}

impl ActivationMigrationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpSafePointState {
    Recorded,
    Rejected,
}

impl SmpSafePointState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopTheWorldRendezvousState {
    Completed,
    Rejected,
}

impl StopTheWorldRendezvousState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpCodePublishBarrierState {
    Validated,
    Rejected,
}

impl SmpCodePublishBarrierState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpCleanupQuiescenceState {
    Validated,
    Rejected,
}

impl SmpCleanupQuiescenceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpSnapshotBarrierState {
    Validated,
    Rejected,
}

impl SmpSnapshotBarrierState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpStressRunState {
    Recorded,
    Rejected,
}

impl SmpStressRunState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmpScalingBenchmarkState {
    Recorded,
    Rejected,
}

impl SmpScalingBenchmarkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegratedSmpPreemptionCleanupState {
    Recorded,
    Rejected,
}

impl IntegratedSmpPreemptionCleanupState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegratedSmpNetworkFaultState {
    Recorded,
    Rejected,
}

impl IntegratedSmpNetworkFaultState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegratedDiskPreemptFaultState {
    Recorded,
    Rejected,
}

impl IntegratedDiskPreemptFaultState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegratedSimdMigrationState {
    Recorded,
    Rejected,
}

impl IntegratedSimdMigrationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegratedNetworkDiskIoState {
    Recorded,
    Rejected,
}

impl IntegratedNetworkDiskIoState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegratedDisplaySchedulerLoadState {
    Recorded,
    Rejected,
}

impl IntegratedDisplaySchedulerLoadState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegratedSnapshotIoLeaseBarrierState {
    Recorded,
    Rejected,
}

impl IntegratedSnapshotIoLeaseBarrierState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegratedCodePublishSmpWorkloadState {
    Recorded,
    Rejected,
}

impl IntegratedCodePublishSmpWorkloadState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegratedDisplayPanicState {
    Recorded,
    Rejected,
}

impl IntegratedDisplayPanicState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceObjectState {
    Registered,
    Removed,
}

impl DeviceObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Removed => "removed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueObjectRole {
    Rx,
    Tx,
    Control,
    Submission,
    Completion,
}

impl QueueObjectRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rx => "rx",
            Self::Tx => "tx",
            Self::Control => "control",
            Self::Submission => "submission",
            Self::Completion => "completion",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueObjectState {
    Registered,
    Removed,
}

impl QueueObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Removed => "removed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorObjectAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

impl DescriptorObjectAccess {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WriteOnly => "write-only",
            Self::ReadWrite => "read-write",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorObjectState {
    Registered,
    Removed,
}

impl DescriptorObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Removed => "removed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaBufferObjectAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

impl DmaBufferObjectAccess {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WriteOnly => "write-only",
            Self::ReadWrite => "read-write",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaBufferObjectState {
    Registered,
    Released,
}

impl DmaBufferObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioRegionObjectAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

impl MmioRegionObjectAccess {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WriteOnly => "write-only",
            Self::ReadWrite => "read-write",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmioRegionObjectState {
    Registered,
    Released,
}

impl MmioRegionObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqLineTrigger {
    Edge,
    Level,
}

impl IrqLineTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Edge => "edge",
            Self::Level => "level",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqLinePolarity {
    ActiveHigh,
    ActiveLow,
}

impl IrqLinePolarity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActiveHigh => "active-high",
            Self::ActiveLow => "active-low",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqLineObjectState {
    Registered,
    Released,
}

impl IrqLineObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqEventState {
    Recorded,
    Dropped,
}

impl IrqEventState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceCapabilityState {
    Active,
    Revoked,
}

impl DeviceCapabilityState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverStoreBindingState {
    Bound,
    Released,
}

impl DriverStoreBindingState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoWaitState {
    Pending,
    Resolved,
    Cancelled,
}

impl IoWaitState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Resolved => "resolved",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoCleanupState {
    Completed,
    SkippedStaleGeneration,
}

impl IoCleanupState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::SkippedStaleGeneration => "skipped-stale-generation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoCleanupStepKind {
    CancelIoWaits,
    RevokeDeviceCapabilities,
    ReleaseDriverBinding,
    ReleaseDmaBuffers,
    ReleaseMmioRegions,
    ReleaseIrqLines,
}

impl IoCleanupStepKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CancelIoWaits => "cancel-io-waits",
            Self::RevokeDeviceCapabilities => "revoke-device-capabilities",
            Self::ReleaseDriverBinding => "release-driver-binding",
            Self::ReleaseDmaBuffers => "release-dma-buffers",
            Self::ReleaseMmioRegions => "release-mmio-regions",
            Self::ReleaseIrqLines => "release-irq-lines",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoCleanupStepStatus {
    Done,
    SkippedNotPresent,
    SkippedStaleGeneration,
}

impl IoCleanupStepStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::SkippedNotPresent => "skipped-not-present",
            Self::SkippedStaleGeneration => "skipped-stale-generation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoFaultInjectionKind {
    DeviceFault,
}

impl IoFaultInjectionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceFault => "device-fault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoFaultInjectionState {
    Completed,
}

impl IoFaultInjectionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoValidationReportState {
    Passed,
    Failed,
}

impl IoValidationReportState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoValidationViolationCode {
    MissingStore,
    MissingDevice,
    MissingQueue,
    MissingDescriptor,
    MissingResource,
    MissingCapability,
    MissingWait,
    MissingCleanup,
    StaleGeneration,
    ActiveCapabilityWithoutBinding,
    PendingWaitAfterCleanup,
    CleanupLiveLeak,
    FaultCleanupMismatch,
}

impl IoValidationViolationCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingStore => "missing-store",
            Self::MissingDevice => "missing-device",
            Self::MissingQueue => "missing-queue",
            Self::MissingDescriptor => "missing-descriptor",
            Self::MissingResource => "missing-resource",
            Self::MissingCapability => "missing-capability",
            Self::MissingWait => "missing-wait",
            Self::MissingCleanup => "missing-cleanup",
            Self::StaleGeneration => "stale-generation",
            Self::ActiveCapabilityWithoutBinding => "active-capability-without-binding",
            Self::PendingWaitAfterCleanup => "pending-wait-after-cleanup",
            Self::CleanupLiveLeak => "cleanup-live-leak",
            Self::FaultCleanupMismatch => "fault-cleanup-mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDeviceObjectState {
    Registered,
    Retired,
}

impl PacketDeviceObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockDeviceObjectState {
    Registered,
    Retired,
}

impl BlockDeviceObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRangeObjectState {
    Registered,
    Retired,
}

impl BlockRangeObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRequestOperation {
    Read,
    Write,
}

impl BlockRequestOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRequestObjectState {
    Submitted,
    Cancelled,
    Completed,
}

impl BlockRequestObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Cancelled => "cancelled",
            Self::Completed => "completed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockCompletionStatus {
    Success,
    IoError,
}

impl BlockCompletionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::IoError => "io-error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockCompletionObjectState {
    Recorded,
    Retired,
}

impl BlockCompletionObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockWaitState {
    Pending,
    Resolved,
    Cancelled,
}

impl BlockWaitState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Resolved => "resolved",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeBlockBackendObjectState {
    Bound,
    Retired,
}

impl FakeBlockBackendObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioBlkBackendObjectState {
    SkeletonReady,
    Retired,
}

impl VirtioBlkBackendObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkeletonReady => "skeleton-ready",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockReadPathState {
    Completed,
    Retired,
}

impl BlockReadPathState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockWritePathState {
    Completed,
    Retired,
}

impl BlockWritePathState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRequestQueueState {
    Active,
    Retired,
}

impl BlockRequestQueueState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRequestQueueEntryState {
    Pending,
    Completed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockPageObjectState {
    Integrated,
    Invalidated,
}

impl BlockPageObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Integrated => "integrated",
            Self::Invalidated => "invalidated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferCacheObjectState {
    Clean,
    Dirty,
    WritebackPending,
    Invalidated,
}

impl BufferCacheObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Dirty => "dirty",
            Self::WritebackPending => "writeback-pending",
            Self::Invalidated => "invalidated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileObjectState {
    Clean,
    Dirty,
    Cached,
    Invalidated,
}

impl FileObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Dirty => "dirty",
            Self::Cached => "cached",
            Self::Invalidated => "invalidated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryEntryKind {
    File,
}

impl DirectoryEntryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryObjectState {
    Cached,
    Dirty,
    Invalidated,
}

impl DirectoryObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cached => "cached",
            Self::Dirty => "dirty",
            Self::Invalidated => "invalidated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatAdapterObjectState {
    Verified,
    Rejected,
}

impl FatAdapterObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ext4AdapterObjectState {
    Verified,
    Rejected,
}

impl Ext4AdapterObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Rejected => "rejected",
        }
    }
}

impl BlockRequestQueueEntryState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketBufferDirection {
    Rx,
    Tx,
}

impl PacketBufferDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rx => "rx",
            Self::Tx => "tx",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketBufferObjectState {
    Allocated,
    Filled,
    Released,
}

impl PacketBufferObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allocated => "allocated",
            Self::Filled => "filled",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketQueueRole {
    Rx,
    Tx,
}

impl PacketQueueRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rx => "rx",
            Self::Tx => "tx",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketQueueObjectState {
    Registered,
    Retired,
}

impl PacketQueueObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketDescriptorObjectState {
    Registered,
    Retired,
}

impl PacketDescriptorObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeNetBackendObjectState {
    Bound,
    Retired,
}

impl FakeNetBackendObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioNetBackendObjectState {
    SkeletonReady,
    Retired,
}

impl VirtioNetBackendObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkeletonReady => "skeleton-ready",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkRxInterruptState {
    Recorded,
    Retired,
}

impl NetworkRxInterruptState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkRxWaitResolutionState {
    Resolved,
    Retired,
}

impl NetworkRxWaitResolutionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreemptionState {
    Applied,
    Superseded,
    Dropped,
}

impl PreemptionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Superseded => "superseded",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerDecisionState {
    Recorded,
    Superseded,
    Dropped,
}

impl SchedulerDecisionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Superseded => "superseded",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkTxCapabilityGateState {
    Allowed,
    Retired,
}

impl NetworkTxCapabilityGateState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkTxCompletionState {
    Completed,
    Retired,
}

impl NetworkTxCompletionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkStackAdapterState {
    Bound,
    Retired,
}

impl NetworkStackAdapterState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketObjectState {
    Created,
    Closed,
}

impl SocketObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointObjectState {
    Allocated,
    Bound,
    Listening,
    Connected,
    Closed,
}

impl EndpointObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allocated => "allocated",
            Self::Bound => "bound",
            Self::Listening => "listening",
            Self::Connected => "connected",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOperationKind {
    Bind,
    Listen,
    Connect,
    Send,
    Recv,
}

impl SocketOperationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Listen => "listen",
            Self::Connect => "connect",
            Self::Send => "send",
            Self::Recv => "recv",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOperationState {
    Applied,
    Retired,
}

impl SocketOperationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketWaitState {
    Pending,
    Resolved,
    Cancelled,
}

impl SocketWaitState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Resolved => "resolved",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkBackpressureState {
    Recorded,
    Retired,
}

impl NetworkBackpressureState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkBackpressureReason {
    QueueHighWatermark,
    QueueFull,
    SocketCapacity,
    OversizePacket,
}

impl NetworkBackpressureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueHighWatermark => "queue-high-watermark",
            Self::QueueFull => "queue-full",
            Self::SocketCapacity => "socket-capacity",
            Self::OversizePacket => "oversize-packet",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkBackpressureAction {
    ThrottleProducer,
    DropNewest,
    DropOldest,
    RejectSend,
}

impl NetworkBackpressureAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ThrottleProducer => "throttle-producer",
            Self::DropNewest => "drop-newest",
            Self::DropOldest => "drop-oldest",
            Self::RejectSend => "reject-send",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileHandleCapabilityState {
    Allowed,
}

impl FileHandleCapabilityState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsWaitState {
    Pending,
    Resolved,
    Cancelled,
}

impl FsWaitState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Resolved => "resolved",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockDriverCleanupState {
    Started,
    Completed,
    Retired,
}

impl BlockDriverCleanupState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Completed => "completed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockPendingIoAction {
    Cancel,
    Retry,
    Eio,
}

impl BlockPendingIoAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancel => "cancel",
            Self::Retry => "retry",
            Self::Eio => "eio",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockPendingIoPolicyState {
    Cancelled,
    RetryScheduled,
    EioReturned,
}

impl BlockPendingIoPolicyState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::RetryScheduled => "retry-scheduled",
            Self::EioReturned => "eio-returned",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRequestGenerationAuditState {
    Recorded,
}

impl BlockRequestGenerationAuditState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockBenchmarkState {
    Recorded,
}

impl BlockBenchmarkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkDriverCleanupState {
    Started,
    Completed,
    Retired,
}

impl NetworkDriverCleanupState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Completed => "completed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkGenerationAuditState {
    Recorded,
}

impl NetworkGenerationAuditState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkFaultInjectionState {
    Recorded,
}

impl NetworkFaultInjectionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkFaultInjectionKind {
    PacketLoss,
    PacketError,
}

impl NetworkFaultInjectionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PacketLoss => "packet-loss",
            Self::PacketError => "packet-error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkFaultInjectionEffect {
    DropPacket,
    ReportError,
}

impl NetworkFaultInjectionEffect {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DropPacket => "drop-packet",
            Self::ReportError => "report-error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkBenchmarkState {
    Recorded,
}

impl NetworkBenchmarkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkRecoveryBenchmarkState {
    Recorded,
}

impl NetworkRecoveryBenchmarkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRecoveryBenchmarkState {
    Recorded,
}

impl BlockRecoveryBenchmarkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetFeatureSetState {
    Discovered,
}

impl TargetFeatureSetState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorStateState {
    Reserved,
    Unavailable,
    Dropped,
}

impl VectorStateState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Unavailable => "unavailable",
            Self::Dropped => "dropped",
        }
    }

    pub const fn is_live_owned(self) -> bool {
        matches!(self, Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdFaultInjectionKind {
    UnsupportedFeature,
    IllegalInstruction,
}

impl SimdFaultInjectionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedFeature => "unsupported-feature",
            Self::IllegalInstruction => "illegal-instruction",
        }
    }

    pub const fn trap_kind(self) -> &'static str {
        match self {
            Self::UnsupportedFeature => "simd-unsupported",
            Self::IllegalInstruction => "simd-illegal-instruction",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdFaultInjectionEffect {
    TrapRecorded,
    ActivationTrapped,
}

impl SimdFaultInjectionEffect {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrapRecorded => "trap-recorded",
            Self::ActivationTrapped => "activation-trapped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdFaultInjectionState {
    Recorded,
}

impl SimdFaultInjectionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdBenchmarkState {
    Recorded,
}

impl SimdBenchmarkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdContextSwitchBenchmarkState {
    Recorded,
}

impl SimdContextSwitchBenchmarkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferObjectState {
    Registered,
    Retired,
}

impl FramebufferObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayObjectState {
    Registered,
    Retired,
}

impl DisplayObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockDmaBufferState {
    Bound,
    Released,
}

impl BlockDmaBufferState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayCapabilityState {
    Active,
    Revoked,
}

impl DisplayCapabilityState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferWindowLeaseState {
    Active,
    Released,
}

impl FramebufferWindowLeaseState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferMappingState {
    Active,
    Unmapped,
}

impl FramebufferMappingState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Unmapped => "unmapped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferWriteState {
    Applied,
}

impl FramebufferWriteState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferFlushRegionState {
    Applied,
}

impl FramebufferFlushRegionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferDirtyRegionState {
    Dirty,
    Clean,
}

impl FramebufferDirtyRegionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dirty => "dirty",
            Self::Clean => "clean",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayEventLogState {
    Recorded,
}

impl DisplayEventLogState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayCleanupState {
    Completed,
}

impl DisplayCleanupState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplaySnapshotBarrierState {
    Validated,
}

impl DisplaySnapshotBarrierState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validated => "validated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayPanicLastFrameState {
    Recorded,
}

impl DisplayPanicLastFrameState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferBenchmarkState {
    Recorded,
}

impl FramebufferBenchmarkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayCleanupStepKind {
    UnmapFramebufferMappings,
    ReleaseFramebufferWindowLeases,
    RevokeDisplayCapabilities,
}

impl DisplayCleanupStepKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnmapFramebufferMappings => "unmap-framebuffer-mappings",
            Self::ReleaseFramebufferWindowLeases => "release-framebuffer-window-leases",
            Self::RevokeDisplayCapabilities => "revoke-display-capabilities",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayCleanupStepStatus {
    Done,
    SkippedNotPresent,
}

impl DisplayCleanupStepStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::SkippedNotPresent => "skipped-not-present",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationResumeState {
    Applied,
    Superseded,
    Dropped,
}

impl ActivationResumeState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Superseded => "superseded",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationWaitState {
    Pending,
    Cancelled,
    Resolved,
    Dropped,
}

impl ActivationWaitState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Cancelled => "cancelled",
            Self::Resolved => "resolved",
            Self::Dropped => "dropped",
        }
    }
}

impl TaskState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runnable => "runnable",
            Self::Running => "running",
            Self::Pending => "pending",
            Self::Cancelled => "cancelled",
            Self::Faulted => "faulted",
            Self::Exited => "exited",
            Self::SnapshotFrozen => "snapshot-frozen",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationCleanupState {
    Completed,
    Skipped,
    Failed,
}

impl ActivationCleanupState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationCleanupStepKind {
    StopNewActivation,
    CancelWait,
    MarkTaskFaulted,
    SealActivation,
    DropContext,
    DropResources,
    MarkStoreDead,
}

impl ActivationCleanupStepKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StopNewActivation => "stop-new-activation",
            Self::CancelWait => "cancel-wait",
            Self::MarkTaskFaulted => "mark-task-faulted",
            Self::SealActivation => "seal-activation",
            Self::DropContext => "drop-context",
            Self::DropResources => "drop-resources",
            Self::MarkStoreDead => "mark-store-dead",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationCleanupStepStatus {
    Done,
    SkippedStaleGeneration,
    SkippedNotPresent,
}

impl ActivationCleanupStepStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::SkippedStaleGeneration => "skipped-stale-generation",
            Self::SkippedNotPresent => "skipped-not-present",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreemptionLatencySampleState {
    Recorded,
    Dropped,
}

impl PreemptionLatencySampleState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    Fd,
    Timer,
    Futex,
    Epoll,
    Device,
    PacketDevice,
    BlockDevice,
    Framebuffer,
    NetInterface,
    NetSocket,
    SocketQueue,
    DmaPool,
    DmaBuffer,
    IrqLine,
    MmioRegion,
    PciDevice,
    AcpiTable,
    VirtioQueue,
    DmwWindow,
    GuestMemory,
    WindowLease,
    ServiceStore,
}

impl ResourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fd => "fd",
            Self::Timer => "timer",
            Self::Futex => "futex",
            Self::Epoll => "epoll",
            Self::Device => "device",
            Self::PacketDevice => "packet-device",
            Self::BlockDevice => "block-device",
            Self::Framebuffer => "framebuffer",
            Self::NetInterface => "net-interface",
            Self::NetSocket => "net-socket",
            Self::SocketQueue => "socket-queue",
            Self::DmaPool => "dma-pool",
            Self::DmaBuffer => "dma-buffer",
            Self::IrqLine => "irq-line",
            Self::MmioRegion => "mmio-region",
            Self::PciDevice => "pci-device",
            Self::AcpiTable => "acpi-table",
            Self::VirtioQueue => "virtio-queue",
            Self::DmwWindow => "dmw-window",
            Self::GuestMemory => "guest-memory",
            Self::WindowLease => "window-lease",
            Self::ServiceStore => "service-store",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityKind {
    Device,
    PacketDevice,
    BlockDevice,
    DmwWindow,
    MmioRegion,
    DmaPool,
    DmaBuffer,
    IrqLine,
    VirtioQueue,
}

impl AuthorityKind {
    pub const fn from_resource_kind(kind: ResourceKind) -> Option<Self> {
        match kind {
            ResourceKind::Device => Some(Self::Device),
            ResourceKind::PacketDevice => Some(Self::PacketDevice),
            ResourceKind::BlockDevice => Some(Self::BlockDevice),
            ResourceKind::DmwWindow => Some(Self::DmwWindow),
            ResourceKind::MmioRegion => Some(Self::MmioRegion),
            ResourceKind::DmaPool => Some(Self::DmaPool),
            ResourceKind::DmaBuffer => Some(Self::DmaBuffer),
            ResourceKind::IrqLine => Some(Self::IrqLine),
            ResourceKind::VirtioQueue => Some(Self::VirtioQueue),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::PacketDevice => "packet-device",
            Self::BlockDevice => "block-device",
            Self::DmwWindow => "dmw-window",
            Self::MmioRegion => "mmio-region",
            Self::DmaPool => "dma-pool",
            Self::DmaBuffer => "dma-buffer",
            Self::IrqLine => "irq-line",
            Self::VirtioQueue => "virtio-queue",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityState {
    Bound,
    Released,
    Revoked,
}

impl AuthorityState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Released => "released",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticWaitKind {
    Timer,
    Futex,
    Epoll,
    FdReadable,
    FdWritable,
    PacketRx,
    PacketTx,
    SocketReadable,
    SocketWritable,
    SocketAccept,
    DeviceIrq,
    DriverCompletion,
    Signal,
    ChildExit,
}

impl SemanticWaitKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timer => "timer",
            Self::Futex => "futex",
            Self::Epoll => "epoll",
            Self::FdReadable => "fd-readable",
            Self::FdWritable => "fd-writable",
            Self::PacketRx => "packet-rx",
            Self::PacketTx => "packet-tx",
            Self::SocketReadable => "socket-readable",
            Self::SocketWritable => "socket-writable",
            Self::SocketAccept => "socket-accept",
            Self::DeviceIrq => "device-irq",
            Self::DriverCompletion => "driver-completion",
            Self::Signal => "signal",
            Self::ChildExit => "child-exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitState {
    Created,
    Pending,
    Resolved,
    Ready,
    Consumed,
    Cancelled,
    Interrupted,
    Restarted,
}

impl WaitState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Pending => "pending",
            Self::Resolved => "resolved",
            Self::Ready => "ready",
            Self::Consumed => "consumed",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
            Self::Restarted => "restarted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitCancelReason {
    Timeout,
    Signal,
    CloseFd,
    StoreFault,
    CapabilityRevoked,
    DeviceFault,
    SnapshotBarrier,
    ResourceDropped,
    GenerationMismatch,
}

impl WaitCancelReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Signal => "signal",
            Self::CloseFd => "close-fd",
            Self::StoreFault => "store-fault",
            Self::CapabilityRevoked => "capability-revoked",
            Self::DeviceFault => "device-fault",
            Self::SnapshotBarrier => "snapshot-barrier",
            Self::ResourceDropped => "resource-dropped",
            Self::GenerationMismatch => "generation-mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPolicy {
    Never,
    RestartIfAllowed,
    RestartWithAdjustedTimeout,
    InternalOnly,
}

impl RestartPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::RestartIfAllowed => "restart-if-allowed",
            Self::RestartWithAdjustedTimeout => "restart-with-adjusted-timeout",
            Self::InternalOnly => "internal-only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultDomainState {
    Created,
    Initializing,
    Running,
    Degraded,
    Draining,
    Restarting,
    Dead,
}

impl FaultDomainState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Initializing => "initializing",
            Self::Running => "running",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Restarting => "restarting",
            Self::Dead => "dead",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreState {
    Created,
    Bound,
    Instantiating,
    Running,
    Suspended,
    Degraded,
    Draining,
    Faulted,
    Cleaning,
    Restarting,
    Rebinding,
    Rebound,
    Dead,
}

impl StoreState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Bound => "bound",
            Self::Instantiating => "instantiating",
            Self::Running => "running",
            Self::Suspended => "suspended",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Faulted => "faulted",
            Self::Cleaning => "cleaning",
            Self::Restarting => "restarting",
            Self::Rebinding => "rebinding",
            Self::Rebound => "rebound",
            Self::Dead => "dead",
        }
    }

    pub const fn fault_domain_state(self) -> FaultDomainState {
        match self {
            Self::Created => FaultDomainState::Created,
            Self::Bound | Self::Instantiating | Self::Cleaning | Self::Rebinding => {
                FaultDomainState::Initializing
            }
            Self::Running => FaultDomainState::Running,
            Self::Suspended => FaultDomainState::Draining,
            Self::Degraded => FaultDomainState::Degraded,
            Self::Draining => FaultDomainState::Draining,
            Self::Faulted | Self::Restarting => FaultDomainState::Restarting,
            Self::Rebound => FaultDomainState::Running,
            Self::Dead => FaultDomainState::Dead,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultClass {
    Guest,
    Service,
    Driver,
    Supervisor,
    Substrate,
}

impl FaultClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Guest => "guest",
            Self::Service => "service",
            Self::Driver => "driver",
            Self::Supervisor => "supervisor",
            Self::Substrate => "substrate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapClass {
    GuestSegfault,
    GuestIllegalInstruction,
    WasmBoundsTrap,
    WasmUnreachableTrap,
    WindowViolationTrap,
    MmioPermissionTrap,
    DmaPermissionTrap,
    CapabilityDenied,
    ServiceTrap,
    DriverTrap,
    SubstrateFault,
}

impl TrapClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GuestSegfault => "guest-segfault",
            Self::GuestIllegalInstruction => "guest-illegal-instruction",
            Self::WasmBoundsTrap => "wasm-bounds-trap",
            Self::WasmUnreachableTrap => "wasm-unreachable-trap",
            Self::WindowViolationTrap => "window-violation-trap",
            Self::MmioPermissionTrap => "mmio-permission-trap",
            Self::DmaPermissionTrap => "dma-permission-trap",
            Self::CapabilityDenied => "capability-denied",
            Self::ServiceTrap => "service-trap",
            Self::DriverTrap => "driver-trap",
            Self::SubstrateFault => "substrate-fault",
        }
    }

    pub const fn fault_class(self) -> FaultClass {
        match self {
            Self::GuestSegfault | Self::GuestIllegalInstruction => FaultClass::Guest,
            Self::DriverTrap | Self::MmioPermissionTrap | Self::DmaPermissionTrap => {
                FaultClass::Driver
            }
            Self::SubstrateFault => FaultClass::Substrate,
            Self::CapabilityDenied | Self::WindowViolationTrap => FaultClass::Supervisor,
            Self::WasmBoundsTrap | Self::WasmUnreachableTrap | Self::ServiceTrap => {
                FaultClass::Service
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalGuestIsa {
    Riscv64,
    Wasm32,
    None,
}

impl CanonicalGuestIsa {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Riscv64 => "riscv64",
            Self::Wasm32 => "wasm32",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallClass {
    PureQuery,
    ImmediatePrivilegedOp,
    AsyncOp,
}

impl HostcallClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PureQuery => "pure-query",
            Self::ImmediatePrivilegedOp => "immediate-privileged-op",
            Self::AsyncOp => "async-op",
        }
    }
}
