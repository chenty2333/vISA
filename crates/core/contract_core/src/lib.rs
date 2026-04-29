use std::{error::Error, fmt};

use artifact_manifest::{
    CapabilityManifest, InterfaceRequirementManifest, ResourceLimitsManifest,
    SupervisorContractManifest,
};
use sha2::Digest;
pub use supervisor_catalog::{
    ARTIFACT_HASH_STATUS_MANIFEST_BOUND, ARTIFACT_SIGNATURE_STATUS_PROFILE_BOUND_UNVERIFIED,
    ARTIFACT_SIGNATURE_VERIFIED_DEFAULT,
};
use supervisor_catalog::{
    CAPABILITY_ABI_VERSION, COMPONENT_MODEL_VERSION, HOSTCALL_ABI_VERSION,
    SEMANTIC_CONTRACT_SCHEMA_VERSION, SUPERVISOR_CODE_PAYLOAD_FORMAT, SUPERVISOR_CONTRACT_VERSION,
    SUPERVISOR_WASM_MODULES, SUPERVISOR_WORLD, WASI_PROFILE_NONE, catalog_contract_fingerprint,
    module_interface_spec, package_set_fingerprint,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractError {
    message: String,
}

impl ContractError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ContractError {}

pub type ContractResult<T> = Result<T, ContractError>;

pub const CONTRACT_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new("semantic-contract-v0.1");
pub const CONTRACT_SCHEMA: &str = CONTRACT_SCHEMA_VERSION.name;
pub const VIEW_SCHEMA_V1: u16 = 1;
pub const EDGE_SCHEMA_V1: u16 = 1;
pub const EVENT_SCHEMA_V1: u16 = 1;
pub const TRACE_SCHEMA_V1: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaVersion {
    pub name: &'static str,
}

impl SchemaVersion {
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Hart,
    Task,
    RunnableQueue,
    ActivationContext,
    SavedContext,
    TimerInterrupt,
    IpiEvent,
    RemotePreempt,
    RemotePark,
    Preemption,
    SchedulerDecision,
    CrossHartSchedulerDecision,
    ActivationMigration,
    SmpSafePoint,
    StopTheWorldRendezvous,
    SmpCodePublishBarrier,
    SmpCleanupQuiescence,
    SmpSnapshotBarrier,
    SmpStressRun,
    SmpScalingBenchmark,
    IntegratedSmpPreemptionCleanup,
    IntegratedSmpNetworkFault,
    IntegratedDiskPreemptFault,
    IntegratedSimdMigration,
    IntegratedNetworkDiskIo,
    IntegratedDisplaySchedulerLoad,
    IntegratedSnapshotIoLeaseBarrier,
    IntegratedCodePublishSmpWorkload,
    IntegratedDisplayPanic,
    IntegratedOsctlTraceReplay,
    DeviceObject,
    QueueObject,
    DescriptorObject,
    DmaBufferObject,
    MmioRegionObject,
    IrqLineObject,
    IrqEvent,
    DeviceCapability,
    DriverStoreBinding,
    IoWait,
    IoCleanup,
    IoFaultInjection,
    IoValidationReport,
    PacketDeviceObject,
    PacketBufferObject,
    PacketQueueObject,
    PacketDescriptorObject,
    FakeNetBackendObject,
    VirtioNetBackendObject,
    NetworkRxInterrupt,
    NetworkRxWaitResolution,
    NetworkTxCapabilityGate,
    NetworkTxCompletion,
    NetworkStackAdapter,
    SocketObject,
    EndpointObject,
    SocketOperation,
    SocketWait,
    NetworkBackpressure,
    NetworkDriverCleanup,
    NetworkGenerationAudit,
    NetworkFaultInjection,
    NetworkBenchmark,
    NetworkRecoveryBenchmark,
    BlockDeviceObject,
    BlockRangeObject,
    BlockRequestObject,
    BlockCompletionObject,
    BlockWait,
    FakeBlockBackendObject,
    VirtioBlkBackendObject,
    BlockReadPath,
    BlockWritePath,
    BlockRequestQueue,
    BlockDmaBuffer,
    BlockPageObject,
    BufferCacheObject,
    FileObject,
    DirectoryObject,
    FatAdapterObject,
    Ext4AdapterObject,
    FileHandleCapability,
    FsWait,
    BlockDriverCleanup,
    BlockPendingIoPolicy,
    BlockRequestGenerationAudit,
    BlockBenchmark,
    BlockRecoveryBenchmark,
    TargetFeatureSet,
    VectorState,
    SimdFaultInjection,
    SimdBenchmark,
    SimdContextSwitchBenchmark,
    FramebufferObject,
    DisplayObject,
    DisplayCapability,
    FramebufferWindowLease,
    FramebufferMapping,
    FramebufferWrite,
    FramebufferFlushRegion,
    FramebufferDirtyRegion,
    DisplayEventLog,
    DisplayCleanup,
    DisplaySnapshotBarrier,
    DisplayPanicLastFrame,
    FramebufferBenchmark,
    ActivationResume,
    ActivationWait,
    ActivationCleanup,
    PreemptionLatency,
    HartEventAttribution,
    Resource,
    Capability,
    WaitToken,
    FaultDomain,
    Store,
    StoreActivation,
    Activation,
    Artifact,
    CodeObject,
    Boundary,
    Transaction,
    Event,
    Trap,
    Hostcall,
    Cleanup,
    MemoryObject,
    GuestAddressSpace,
    VmaRegion,
    PageObject,
    Tombstone,
    External,
}

impl ObjectKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hart => "hart",
            Self::Task => "task",
            Self::RunnableQueue => "runnable-queue",
            Self::ActivationContext => "activation-context",
            Self::SavedContext => "saved-context",
            Self::TimerInterrupt => "timer-interrupt",
            Self::IpiEvent => "ipi-event",
            Self::RemotePreempt => "remote-preempt",
            Self::RemotePark => "remote-park",
            Self::Preemption => "preemption",
            Self::SchedulerDecision => "scheduler-decision",
            Self::CrossHartSchedulerDecision => "cross-hart-scheduler-decision",
            Self::ActivationMigration => "activation-migration",
            Self::SmpSafePoint => "smp-safe-point",
            Self::StopTheWorldRendezvous => "stop-the-world-rendezvous",
            Self::SmpCodePublishBarrier => "smp-code-publish-barrier",
            Self::SmpCleanupQuiescence => "smp-cleanup-quiescence",
            Self::SmpSnapshotBarrier => "smp-snapshot-barrier",
            Self::SmpStressRun => "smp-stress-run",
            Self::SmpScalingBenchmark => "smp-scaling-benchmark",
            Self::IntegratedSmpPreemptionCleanup => "integrated-smp-preemption-cleanup",
            Self::IntegratedSmpNetworkFault => "integrated-smp-network-fault",
            Self::IntegratedDiskPreemptFault => "integrated-disk-preempt-fault",
            Self::IntegratedSimdMigration => "integrated-simd-migration",
            Self::IntegratedNetworkDiskIo => "integrated-network-disk-io",
            Self::IntegratedDisplaySchedulerLoad => "integrated-display-scheduler-load",
            Self::IntegratedSnapshotIoLeaseBarrier => "integrated-snapshot-io-lease-barrier",
            Self::IntegratedCodePublishSmpWorkload => "integrated-code-publish-smp-workload",
            Self::IntegratedDisplayPanic => "integrated-display-panic",
            Self::IntegratedOsctlTraceReplay => "integrated-osctl-trace-replay",
            Self::DeviceObject => "device-object",
            Self::QueueObject => "queue-object",
            Self::DescriptorObject => "descriptor-object",
            Self::DmaBufferObject => "dma-buffer-object",
            Self::MmioRegionObject => "mmio-region-object",
            Self::IrqLineObject => "irq-line-object",
            Self::IrqEvent => "irq-event",
            Self::DeviceCapability => "device-capability",
            Self::DriverStoreBinding => "driver-store-binding",
            Self::IoWait => "io-wait",
            Self::IoCleanup => "io-cleanup",
            Self::IoFaultInjection => "io-fault-injection",
            Self::IoValidationReport => "io-validation-report",
            Self::PacketDeviceObject => "packet-device-object",
            Self::PacketBufferObject => "packet-buffer-object",
            Self::PacketQueueObject => "packet-queue-object",
            Self::PacketDescriptorObject => "packet-descriptor-object",
            Self::FakeNetBackendObject => "fake-net-backend-object",
            Self::VirtioNetBackendObject => "virtio-net-backend-object",
            Self::NetworkRxInterrupt => "network-rx-interrupt",
            Self::NetworkRxWaitResolution => "network-rx-wait-resolution",
            Self::NetworkTxCapabilityGate => "network-tx-capability-gate",
            Self::NetworkTxCompletion => "network-tx-completion",
            Self::NetworkStackAdapter => "network-stack-adapter",
            Self::SocketObject => "socket-object",
            Self::EndpointObject => "endpoint-object",
            Self::SocketOperation => "socket-operation",
            Self::SocketWait => "socket-wait",
            Self::NetworkBackpressure => "network-backpressure",
            Self::NetworkDriverCleanup => "network-driver-cleanup",
            Self::NetworkGenerationAudit => "network-generation-audit",
            Self::NetworkFaultInjection => "network-fault-injection",
            Self::NetworkBenchmark => "network-benchmark",
            Self::NetworkRecoveryBenchmark => "network-recovery-benchmark",
            Self::BlockDeviceObject => "block-device-object",
            Self::BlockRangeObject => "block-range-object",
            Self::BlockRequestObject => "block-request-object",
            Self::BlockCompletionObject => "block-completion-object",
            Self::BlockWait => "block-wait",
            Self::FakeBlockBackendObject => "fake-block-backend-object",
            Self::VirtioBlkBackendObject => "virtio-blk-backend-object",
            Self::BlockReadPath => "block-read-path",
            Self::BlockWritePath => "block-write-path",
            Self::BlockRequestQueue => "block-request-queue",
            Self::BlockDmaBuffer => "block-dma-buffer",
            Self::BlockPageObject => "block-page-object",
            Self::BufferCacheObject => "buffer-cache-object",
            Self::FileObject => "file-object",
            Self::DirectoryObject => "directory-object",
            Self::FatAdapterObject => "fat-adapter-object",
            Self::Ext4AdapterObject => "ext4-adapter-object",
            Self::FileHandleCapability => "file-handle-capability",
            Self::FsWait => "fs-wait",
            Self::BlockDriverCleanup => "block-driver-cleanup",
            Self::BlockPendingIoPolicy => "block-pending-io-policy",
            Self::BlockRequestGenerationAudit => "block-request-generation-audit",
            Self::BlockBenchmark => "block-benchmark",
            Self::BlockRecoveryBenchmark => "block-recovery-benchmark",
            Self::TargetFeatureSet => "target-feature-set",
            Self::VectorState => "vector-state",
            Self::SimdFaultInjection => "simd-fault-injection",
            Self::SimdBenchmark => "simd-benchmark",
            Self::SimdContextSwitchBenchmark => "simd-context-switch-benchmark",
            Self::FramebufferObject => "framebuffer-object",
            Self::DisplayObject => "display-object",
            Self::DisplayCapability => "display-capability",
            Self::FramebufferWindowLease => "framebuffer-window-lease",
            Self::FramebufferMapping => "framebuffer-mapping",
            Self::FramebufferWrite => "framebuffer-write",
            Self::FramebufferFlushRegion => "framebuffer-flush-region",
            Self::FramebufferDirtyRegion => "framebuffer-dirty-region",
            Self::DisplayEventLog => "display-event-log",
            Self::DisplayCleanup => "display-cleanup",
            Self::DisplaySnapshotBarrier => "display-snapshot-barrier",
            Self::DisplayPanicLastFrame => "display-panic-last-frame",
            Self::FramebufferBenchmark => "framebuffer-benchmark",
            Self::ActivationResume => "activation-resume",
            Self::ActivationWait => "activation-wait",
            Self::ActivationCleanup => "activation-cleanup",
            Self::PreemptionLatency => "preemption-latency",
            Self::HartEventAttribution => "hart-event-attribution",
            Self::Resource => "resource",
            Self::Capability => "capability",
            Self::WaitToken => "wait-token",
            Self::FaultDomain => "fault-domain",
            Self::Store => "store",
            Self::StoreActivation => "store-activation",
            Self::Activation => "activation",
            Self::Artifact => "artifact",
            Self::CodeObject => "code-object",
            Self::Boundary => "boundary",
            Self::Transaction => "transaction",
            Self::Event => "event",
            Self::Trap => "trap",
            Self::Hostcall => "hostcall",
            Self::Cleanup => "cleanup",
            Self::MemoryObject => "memory-object",
            Self::GuestAddressSpace => "guest-address-space",
            Self::VmaRegion => "vma-region",
            Self::PageObject => "page-object",
            Self::Tombstone => "tombstone",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectRef {
    pub kind: ObjectKind,
    pub id: u64,
    pub generation: u64,
}

impl ObjectRef {
    pub fn new(kind: ObjectKind, id: u64, generation: u64) -> ContractResult<Self> {
        let reference = Self { kind, id, generation };
        reference.validate()?;
        Ok(reference)
    }

    pub const fn unchecked(kind: ObjectKind, id: u64, generation: u64) -> Self {
        Self { kind, id, generation }
    }

    pub fn validate(self) -> ContractResult<()> {
        if self.id == 0 {
            return Err(ContractError::new("object ref id=0 is invalid"));
        }
        if self.generation == 0 && self.kind != ObjectKind::External {
            return Err(ContractError::new(
                "object ref generation=0 is invalid for internal objects",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefMode {
    Live,
    Historical,
    CleanupEffect,
    External,
}

impl RefMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Historical => "historical",
            Self::CleanupEffect => "cleanup-effect",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractEdge {
    pub from: ObjectRef,
    pub to: ObjectRef,
    pub mode: RefMode,
    pub label: String,
    pub epoch: u64,
}

impl ContractEdge {
    pub fn new(from: ObjectRef, to: ObjectRef, mode: RefMode, label: &str, epoch: u64) -> Self {
        Self { from, to, mode, label: label.to_owned(), epoch }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstoneRecord {
    pub object: ObjectRef,
    pub died_at_event: u64,
    pub reason: String,
}

impl TombstoneRecord {
    pub fn new(object: ObjectRef, died_at_event: u64, reason: &str) -> Self {
        Self { object, died_at_event, reason: reason.to_owned() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypedRefError {
    KindMismatch { expected: ObjectKind, actual: ObjectKind },
    InvalidRef,
}

impl fmt::Display for TypedRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KindMismatch { expected, actual } => write!(
                f,
                "typed ref kind mismatch: expected {}, got {}",
                expected.as_str(),
                actual.as_str()
            ),
            Self::InvalidRef => f.write_str("invalid object ref"),
        }
    }
}

impl Error for TypedRefError {}

macro_rules! typed_ref {
    ($name:ident, $kind:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(pub ObjectRef);

        impl $name {
            pub fn new(id: u64, generation: u64) -> ContractResult<Self> {
                Ok(Self(ObjectRef::new($kind, id, generation)?))
            }

            pub fn try_from_ref(reference: ObjectRef) -> Result<Self, TypedRefError> {
                reference.validate().map_err(|_| TypedRefError::InvalidRef)?;
                if reference.kind != $kind {
                    return Err(TypedRefError::KindMismatch {
                        expected: $kind,
                        actual: reference.kind,
                    });
                }
                Ok(Self(reference))
            }

            pub const fn object_ref(self) -> ObjectRef {
                self.0
            }
        }
    };
}

typed_ref!(StoreRef, ObjectKind::Store);
typed_ref!(HartRef, ObjectKind::Hart);
typed_ref!(CapabilityRef, ObjectKind::Capability);
typed_ref!(WaitTokenRef, ObjectKind::WaitToken);
typed_ref!(CleanupRef, ObjectKind::Cleanup);
typed_ref!(TaskRef, ObjectKind::Task);
typed_ref!(RunnableQueueRef, ObjectKind::RunnableQueue);
typed_ref!(ActivationContextRef, ObjectKind::ActivationContext);
typed_ref!(SavedContextRef, ObjectKind::SavedContext);
typed_ref!(TimerInterruptRef, ObjectKind::TimerInterrupt);
typed_ref!(IpiEventRef, ObjectKind::IpiEvent);
typed_ref!(RemotePreemptRef, ObjectKind::RemotePreempt);
typed_ref!(RemoteParkRef, ObjectKind::RemotePark);
typed_ref!(PreemptionRef, ObjectKind::Preemption);
typed_ref!(SchedulerDecisionRef, ObjectKind::SchedulerDecision);
typed_ref!(CrossHartSchedulerDecisionRef, ObjectKind::CrossHartSchedulerDecision);
typed_ref!(ActivationMigrationRef, ObjectKind::ActivationMigration);
typed_ref!(SmpSafePointRef, ObjectKind::SmpSafePoint);
typed_ref!(StopTheWorldRendezvousRef, ObjectKind::StopTheWorldRendezvous);
typed_ref!(SmpCodePublishBarrierRef, ObjectKind::SmpCodePublishBarrier);
typed_ref!(SmpCleanupQuiescenceRef, ObjectKind::SmpCleanupQuiescence);
typed_ref!(SmpSnapshotBarrierRef, ObjectKind::SmpSnapshotBarrier);
typed_ref!(SmpStressRunRef, ObjectKind::SmpStressRun);
typed_ref!(SmpScalingBenchmarkRef, ObjectKind::SmpScalingBenchmark);
typed_ref!(IntegratedSmpPreemptionCleanupRef, ObjectKind::IntegratedSmpPreemptionCleanup);
typed_ref!(IntegratedSmpNetworkFaultRef, ObjectKind::IntegratedSmpNetworkFault);
typed_ref!(IntegratedDiskPreemptFaultRef, ObjectKind::IntegratedDiskPreemptFault);
typed_ref!(IntegratedSimdMigrationRef, ObjectKind::IntegratedSimdMigration);
typed_ref!(IntegratedNetworkDiskIoRef, ObjectKind::IntegratedNetworkDiskIo);
typed_ref!(IntegratedDisplaySchedulerLoadRef, ObjectKind::IntegratedDisplaySchedulerLoad);
typed_ref!(IntegratedSnapshotIoLeaseBarrierRef, ObjectKind::IntegratedSnapshotIoLeaseBarrier);
typed_ref!(IntegratedCodePublishSmpWorkloadRef, ObjectKind::IntegratedCodePublishSmpWorkload);
typed_ref!(IntegratedDisplayPanicRef, ObjectKind::IntegratedDisplayPanic);
typed_ref!(IntegratedOsctlTraceReplayRef, ObjectKind::IntegratedOsctlTraceReplay);
typed_ref!(DeviceObjectRef, ObjectKind::DeviceObject);
typed_ref!(QueueObjectRef, ObjectKind::QueueObject);
typed_ref!(DescriptorObjectRef, ObjectKind::DescriptorObject);
typed_ref!(DmaBufferObjectRef, ObjectKind::DmaBufferObject);
typed_ref!(MmioRegionObjectRef, ObjectKind::MmioRegionObject);
typed_ref!(IrqLineObjectRef, ObjectKind::IrqLineObject);
typed_ref!(IrqEventRef, ObjectKind::IrqEvent);
typed_ref!(DeviceCapabilityRef, ObjectKind::DeviceCapability);
typed_ref!(DriverStoreBindingRef, ObjectKind::DriverStoreBinding);
typed_ref!(IoWaitRef, ObjectKind::IoWait);
typed_ref!(IoCleanupRef, ObjectKind::IoCleanup);
typed_ref!(IoFaultInjectionRef, ObjectKind::IoFaultInjection);
typed_ref!(IoValidationReportRef, ObjectKind::IoValidationReport);
typed_ref!(PacketDeviceObjectRef, ObjectKind::PacketDeviceObject);
typed_ref!(PacketBufferObjectRef, ObjectKind::PacketBufferObject);
typed_ref!(PacketQueueObjectRef, ObjectKind::PacketQueueObject);
typed_ref!(PacketDescriptorObjectRef, ObjectKind::PacketDescriptorObject);
typed_ref!(FakeNetBackendObjectRef, ObjectKind::FakeNetBackendObject);
typed_ref!(VirtioNetBackendObjectRef, ObjectKind::VirtioNetBackendObject);
typed_ref!(NetworkRxInterruptRef, ObjectKind::NetworkRxInterrupt);
typed_ref!(NetworkRxWaitResolutionRef, ObjectKind::NetworkRxWaitResolution);
typed_ref!(NetworkTxCapabilityGateRef, ObjectKind::NetworkTxCapabilityGate);
typed_ref!(NetworkTxCompletionRef, ObjectKind::NetworkTxCompletion);
typed_ref!(NetworkStackAdapterRef, ObjectKind::NetworkStackAdapter);
typed_ref!(SocketObjectRef, ObjectKind::SocketObject);
typed_ref!(EndpointObjectRef, ObjectKind::EndpointObject);
typed_ref!(SocketOperationRef, ObjectKind::SocketOperation);
typed_ref!(SocketWaitRef, ObjectKind::SocketWait);
typed_ref!(NetworkBackpressureRef, ObjectKind::NetworkBackpressure);
typed_ref!(NetworkDriverCleanupRef, ObjectKind::NetworkDriverCleanup);
typed_ref!(NetworkGenerationAuditRef, ObjectKind::NetworkGenerationAudit);
typed_ref!(NetworkFaultInjectionRef, ObjectKind::NetworkFaultInjection);
typed_ref!(NetworkBenchmarkRef, ObjectKind::NetworkBenchmark);
typed_ref!(NetworkRecoveryBenchmarkRef, ObjectKind::NetworkRecoveryBenchmark);
typed_ref!(BlockDeviceObjectRef, ObjectKind::BlockDeviceObject);
typed_ref!(BlockRangeObjectRef, ObjectKind::BlockRangeObject);
typed_ref!(BlockRequestObjectRef, ObjectKind::BlockRequestObject);
typed_ref!(BlockCompletionObjectRef, ObjectKind::BlockCompletionObject);
typed_ref!(BlockWaitRef, ObjectKind::BlockWait);
typed_ref!(FakeBlockBackendObjectRef, ObjectKind::FakeBlockBackendObject);
typed_ref!(VirtioBlkBackendObjectRef, ObjectKind::VirtioBlkBackendObject);
typed_ref!(BlockReadPathRef, ObjectKind::BlockReadPath);
typed_ref!(BlockWritePathRef, ObjectKind::BlockWritePath);
typed_ref!(BlockRequestQueueRef, ObjectKind::BlockRequestQueue);
typed_ref!(BlockDmaBufferRef, ObjectKind::BlockDmaBuffer);
typed_ref!(BufferCacheObjectRef, ObjectKind::BufferCacheObject);
typed_ref!(FileObjectRef, ObjectKind::FileObject);
typed_ref!(DirectoryObjectRef, ObjectKind::DirectoryObject);
typed_ref!(FatAdapterObjectRef, ObjectKind::FatAdapterObject);
typed_ref!(Ext4AdapterObjectRef, ObjectKind::Ext4AdapterObject);
typed_ref!(FileHandleCapabilityRef, ObjectKind::FileHandleCapability);
typed_ref!(FsWaitRef, ObjectKind::FsWait);
typed_ref!(BlockDriverCleanupRef, ObjectKind::BlockDriverCleanup);
typed_ref!(BlockPendingIoPolicyRef, ObjectKind::BlockPendingIoPolicy);
typed_ref!(BlockRequestGenerationAuditRef, ObjectKind::BlockRequestGenerationAudit);
typed_ref!(BlockBenchmarkRef, ObjectKind::BlockBenchmark);
typed_ref!(BlockRecoveryBenchmarkRef, ObjectKind::BlockRecoveryBenchmark);
typed_ref!(TargetFeatureSetRef, ObjectKind::TargetFeatureSet);
typed_ref!(VectorStateRef, ObjectKind::VectorState);
typed_ref!(SimdFaultInjectionRef, ObjectKind::SimdFaultInjection);
typed_ref!(SimdBenchmarkRef, ObjectKind::SimdBenchmark);
typed_ref!(SimdContextSwitchBenchmarkRef, ObjectKind::SimdContextSwitchBenchmark);
typed_ref!(FramebufferObjectRef, ObjectKind::FramebufferObject);
typed_ref!(DisplayObjectRef, ObjectKind::DisplayObject);
typed_ref!(DisplayCapabilityRef, ObjectKind::DisplayCapability);
typed_ref!(FramebufferWindowLeaseRef, ObjectKind::FramebufferWindowLease);
typed_ref!(FramebufferMappingRef, ObjectKind::FramebufferMapping);
typed_ref!(FramebufferWriteRef, ObjectKind::FramebufferWrite);
typed_ref!(FramebufferFlushRegionRef, ObjectKind::FramebufferFlushRegion);
typed_ref!(FramebufferDirtyRegionRef, ObjectKind::FramebufferDirtyRegion);
typed_ref!(DisplayEventLogRef, ObjectKind::DisplayEventLog);
typed_ref!(DisplayCleanupRef, ObjectKind::DisplayCleanup);
typed_ref!(DisplaySnapshotBarrierRef, ObjectKind::DisplaySnapshotBarrier);
typed_ref!(DisplayPanicLastFrameRef, ObjectKind::DisplayPanicLastFrame);
typed_ref!(FramebufferBenchmarkRef, ObjectKind::FramebufferBenchmark);
typed_ref!(ActivationResumeRef, ObjectKind::ActivationResume);
typed_ref!(ActivationWaitRef, ObjectKind::ActivationWait);
typed_ref!(ActivationCleanupRef, ObjectKind::ActivationCleanup);
typed_ref!(PreemptionLatencyRef, ObjectKind::PreemptionLatency);
typed_ref!(HartEventAttributionRef, ObjectKind::HartEventAttribution);
typed_ref!(BlockPageObjectRef, ObjectKind::BlockPageObject);
typed_ref!(FaultDomainRef, ObjectKind::FaultDomain);
typed_ref!(ArtifactRef, ObjectKind::Artifact);
typed_ref!(CodeObjectRef, ObjectKind::CodeObject);
typed_ref!(ActivationRef, ObjectKind::Activation);
typed_ref!(TrapRef, ObjectKind::Trap);
typed_ref!(HostcallTraceRef, ObjectKind::Hostcall);
typed_ref!(GuestAddressSpaceRef, ObjectKind::GuestAddressSpace);
typed_ref!(VmaRegionRef, ObjectKind::VmaRegion);
typed_ref!(PageObjectRef, ObjectKind::PageObject);
typed_ref!(ExternalObjectRef, ObjectKind::External);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreViewV1 {
    pub schema: u16,
    pub kind: ObjectKind,
    pub object: ObjectRef,
    pub state: String,
    pub owner: Option<ObjectRef>,
    pub references: Vec<ContractEdge>,
    pub last_transition: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityViewV1 {
    pub schema: u16,
    pub kind: ObjectKind,
    pub object: ObjectRef,
    pub state: String,
    pub subject: ObjectRef,
    pub owner: Option<ObjectRef>,
    pub references: Vec<ContractEdge>,
    pub last_transition: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitViewV1 {
    pub schema: u16,
    pub kind: ObjectKind,
    pub object: ObjectRef,
    pub state: String,
    pub owner: Option<ObjectRef>,
    pub references: Vec<ContractEdge>,
    pub last_transition: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupViewV1 {
    pub schema: u16,
    pub kind: ObjectKind,
    pub object: ObjectRef,
    pub state: String,
    pub owner: Option<ObjectRef>,
    pub references: Vec<ContractEdge>,
    pub last_transition: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractViolationViewV1 {
    pub code: String,
    pub severity: String,
    pub subject: ObjectRef,
    pub relation: String,
    pub ref_mode: RefMode,
    pub expected_generation: Option<u64>,
    pub actual_generation: Option<u64>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractValidationViewV1 {
    pub schema: u16,
    pub kind: &'static str,
    pub package_id: String,
    pub ok: bool,
    pub violation_count: usize,
    pub violations: Vec<ContractViolationViewV1>,
}

pub const RUNTIME_MODE_RESEARCH: &str = "research";
pub const RUNTIME_MODE_PRODUCTION: &str = "production";
pub const RUNTIME_MODE_REPLAY: &str = "replay";
pub const TARGET_ARTIFACT_FORMAT_V1: &str = "target-artifact-image-v1";
pub const CODE_PAYLOAD_FORMAT_CWASM: &str = SUPERVISOR_CODE_PAYLOAD_FORMAT;
pub const WASMTIME_CRATE_VERSION: &str = "43.0.1";
pub const WASMTIME_COMPILATION_STRATEGY: &str = "cranelift";
pub const DEFAULT_MAX_MEMORY_PAGES: u32 = 16;
pub const DEFAULT_MAX_TABLE_ELEMENTS: u32 = 0;
pub const DEFAULT_MAX_HOSTCALLS_PER_ACTIVATION: u32 = 64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedArtifactPlan {
    pub artifact_profile: String,
    pub runtime_mode: String,
    pub contract_version: String,
    pub supervisor_world: String,
    pub target_arch: String,
    pub compiler_engine: String,
    pub compiler_execution_mode: String,
    pub artifact_format: String,
    pub target_artifact_format: String,
    pub runtime_executor_abi: String,
    pub modules: Vec<ValidatedArtifactEntry>,
}

impl ValidatedArtifactPlan {
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub fn capability_count(&self) -> usize {
        self.modules.iter().map(|entry| entry.capabilities.len()).sum()
    }

    pub fn expected_export_count(&self) -> usize {
        self.modules.iter().map(|entry| entry.expected_exports.len()).sum()
    }

    pub fn entry(&self, package: &str) -> Option<&ValidatedArtifactEntry> {
        self.modules.iter().find(|entry| entry.package == package)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedArtifactEntry {
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub fault_policy: String,
    pub wasm_path: String,
    pub cwasm_path: String,
    pub target_artifact_path: String,
    pub wasm_sha256: String,
    pub cwasm_sha256: String,
    pub target_artifact_sha256: String,
    pub code_payload_format: String,
    pub expected_exports: Vec<String>,
    pub capabilities: Vec<CapabilityManifest>,
    pub abi_fingerprint: String,
    pub service_dependencies: Vec<String>,
    pub resource_limits: ResourceLimitsManifest,
    pub interfaces: InterfaceRequirementManifest,
    pub signature_scheme: String,
    pub signer: String,
    pub manifest_binding_hash: String,
    pub hash_status: String,
    pub signature_status: String,
    pub signature_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateCompatibilityItem {
    pub authority: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSubstrateCompatibilityReport {
    pub package: String,
    pub substrate_profile_required: String,
    pub ok: bool,
    pub profile_ok: bool,
    pub authority_ok: bool,
    pub missing_required: Vec<SubstrateCompatibilityItem>,
    pub degraded_optional: Vec<SubstrateCompatibilityItem>,
    pub forbidden_requested: Vec<String>,
    pub forbidden_authorities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactSubstrateCompatibilityReport {
    pub artifact_profile: String,
    pub module_count: usize,
    pub ok: bool,
    pub modules: Vec<ModuleSubstrateCompatibilityReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceHostCapabilitySet {
    pub wasi_worlds: Vec<String>,
    pub custom_wit_worlds: Vec<String>,
    pub component_model_version: String,
    pub wasi_profile: String,
    pub hostcall_abi_version: String,
    pub capability_abi_version: String,
    pub semantic_contract_version: String,
}

impl InterfaceHostCapabilitySet {
    pub fn empty() -> Self {
        Self {
            wasi_worlds: Vec::new(),
            custom_wit_worlds: Vec::new(),
            component_model_version: COMPONENT_MODEL_VERSION.to_owned(),
            wasi_profile: WASI_PROFILE_NONE.to_owned(),
            hostcall_abi_version: HOSTCALL_ABI_VERSION.to_owned(),
            capability_abi_version: CAPABILITY_ABI_VERSION.to_owned(),
            semantic_contract_version: SEMANTIC_CONTRACT_SCHEMA_VERSION.to_owned(),
        }
    }

    pub fn host_validation() -> Self {
        let mut capabilities = Self::empty();
        for module in SUPERVISOR_WASM_MODULES {
            let interfaces = module_interface_spec(module);
            for world in interfaces.required_wasi_worlds {
                push_unique(&mut capabilities.wasi_worlds, world);
            }
            for world in interfaces.optional_wasi_worlds {
                push_unique(&mut capabilities.wasi_worlds, world);
            }
            for world in interfaces.custom_wit_worlds {
                push_unique(&mut capabilities.custom_wit_worlds, world);
            }
        }
        capabilities
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceVersionMismatch {
    pub field: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleInterfaceCompatibilityReport {
    pub package: String,
    pub ok: bool,
    pub missing_required_wasi_worlds: Vec<String>,
    pub degraded_optional_wasi_worlds: Vec<String>,
    pub missing_custom_wit_worlds: Vec<String>,
    pub version_mismatches: Vec<InterfaceVersionMismatch>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactInterfaceCompatibilityReport {
    pub artifact_profile: String,
    pub module_count: usize,
    pub ok: bool,
    pub modules: Vec<ModuleInterfaceCompatibilityReport>,
}

pub fn contract_hex(value: u64) -> String {
    format!("{value:016x}")
}

pub fn expected_supervisor_contract() -> SupervisorContractManifest {
    SupervisorContractManifest {
        contract_version: SUPERVISOR_CONTRACT_VERSION.to_owned(),
        supervisor_world: SUPERVISOR_WORLD.to_owned(),
        catalog_fingerprint: contract_hex(catalog_contract_fingerprint()),
        package_set_fingerprint: contract_hex(package_set_fingerprint()),
        module_count: SUPERVISOR_WASM_MODULES.len(),
        required_packages: SUPERVISOR_WASM_MODULES
            .iter()
            .map(|module| module.package.to_owned())
            .collect(),
    }
}

mod validate;
pub use validate::*;

#[cfg(test)]
mod tests;
