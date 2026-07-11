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
