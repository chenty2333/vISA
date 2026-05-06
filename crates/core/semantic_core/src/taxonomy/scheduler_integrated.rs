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
pub enum IntegratedOsctlTraceReplayState {
    Recorded,
    Rejected,
}

impl IntegratedOsctlTraceReplayState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Rejected => "rejected",
        }
    }
}
