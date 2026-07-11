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
