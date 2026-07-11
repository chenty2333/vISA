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
