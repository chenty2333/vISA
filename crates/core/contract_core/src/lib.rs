//! vISA effect language.
//!
//! This crate is the stable encoding layer of the Semantic Virtual ISA. It
//! defines the ObjectRef, event, command, view, schema, evidence-boundary, and
//! package records that other crates use to agree on visible vISA effects.
//!
//! It is not the vISA itself, not a runtime executor, not a substrate trait
//! surface, and not a Linux/WASI compatibility layer.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::{borrow::ToOwned, string::String, vec, vec::Vec};
use core::{error::Error, fmt};

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
pub const CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION: &str = "contract-graph-snapshot-v0.1";
pub const FEATURE_002_ID: &str = "002-contract-core-stabilization";
pub const FEATURE_002_EVIDENCE_SHAPE_STATUS: &str = "feature-local";
pub const FEATURE_002_EVIDENCE_BOUNDARY: EvidenceBoundaryLevel =
    EvidenceBoundaryLevel::SemanticModel;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceBoundaryLevel {
    #[default]
    SemanticModel,
    ReferenceService,
    ReferenceAotHarness,
    PortableArtifactExecution,
    RealTargetSubstrate,
}

impl EvidenceBoundaryLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SemanticModel => "semantic-model",
            Self::ReferenceService => "reference-service",
            Self::ReferenceAotHarness => "reference-aot-harness",
            Self::PortableArtifactExecution => "portable-artifact-execution",
            Self::RealTargetSubstrate => "real-target-substrate",
        }
    }

    pub const fn rank(self) -> u8 {
        match self {
            Self::SemanticModel => 0,
            Self::ReferenceService => 1,
            Self::ReferenceAotHarness => 2,
            Self::PortableArtifactExecution => 3,
            Self::RealTargetSubstrate => 4,
        }
    }

    pub const fn satisfies(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }

    pub const fn can_claim(self, claimed: Self) -> bool {
        self.satisfies(claimed)
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "semantic-model" | "semantic model" => Some(Self::SemanticModel),
            "reference-service"
            | "reference service"
            | "reference-native-service"
            | "reference/native service"
            | "reference native service" => Some(Self::ReferenceService),
            "reference-aot-harness" | "reference AOT harness" | "reference-aot" => {
                Some(Self::ReferenceAotHarness)
            }
            "portable-artifact-execution" | "portable artifact execution" => {
                Some(Self::PortableArtifactExecution)
            }
            "real-target-substrate" | "real target substrate" => Some(Self::RealTargetSubstrate),
            _ => None,
        }
    }
}

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
    GuestMemoryOperation,
    // Process/Thread family
    Process,
    Thread,
    ThreadGroup,
    FdTable,
    OpenFileDescription,
    Credential,
    CredentialTransition,
    // Signal family
    SignalDisposition,
    PendingSignal,
    SignalMask,
    SignalFrame,
    SignalDelivery,
    // Memory expansion
    PageFaultEvent,
    CowBreakEvent,
    VmaSplitEvent,
    PageAllocSubstrateEvent,
    // Futex family
    FutexKey,
    FutexWait,
    FutexWake,
    FutexRequeue,
    RobustList,
    // Epoll readiness
    ReadySource,
    EpollWatcher,
    // Filesystem expansion
    FileLock,
    Xattr,
    // Existing tail
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
            Self::GuestMemoryOperation => "guest-memory-operation",
            // Process/Thread family
            Self::Process => "process",
            Self::Thread => "thread",
            Self::ThreadGroup => "thread-group",
            Self::FdTable => "fd-table",
            Self::OpenFileDescription => "open-file-description",
            Self::Credential => "credential",
            Self::CredentialTransition => "credential-transition",
            // Signal family
            Self::SignalDisposition => "signal-disposition",
            Self::PendingSignal => "pending-signal",
            Self::SignalMask => "signal-mask",
            Self::SignalFrame => "signal-frame",
            Self::SignalDelivery => "signal-delivery",
            // Memory expansion
            Self::PageFaultEvent => "page-fault-event",
            Self::CowBreakEvent => "cow-break-event",
            Self::VmaSplitEvent => "vma-split-event",
            Self::PageAllocSubstrateEvent => "page-alloc-substrate-event",
            // Futex family
            Self::FutexKey => "futex-key",
            Self::FutexWait => "futex-wait",
            Self::FutexWake => "futex-wake",
            Self::FutexRequeue => "futex-requeue",
            Self::RobustList => "robust-list",
            // Epoll readiness
            Self::ReadySource => "ready-source",
            Self::EpollWatcher => "epoll-watcher",
            // Filesystem expansion
            Self::FileLock => "file-lock",
            Self::Xattr => "xattr",
            // Existing
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
    pub evidence_level: EvidenceBoundaryLevel,
    pub label: String,
    pub epoch: u64,
}

impl ContractEdge {
    pub fn new(from: ObjectRef, to: ObjectRef, mode: RefMode, label: &str, epoch: u64) -> Self {
        Self {
            from,
            to,
            mode,
            evidence_level: EvidenceBoundaryLevel::SemanticModel,
            label: label.to_owned(),
            epoch,
        }
    }

    pub fn with_evidence_level(mut self, evidence_level: EvidenceBoundaryLevel) -> Self {
        self.evidence_level = evidence_level;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase2SemanticFamily {
    ObjectIdentity,
    Generation,
    GraphEdges,
    CapabilityAuthority,
    WaitState,
    EventEvidence,
    TrapAttribution,
    Cleanup,
    GuestMemory,
    StableViews,
    GraphValidation,
}

impl Phase2SemanticFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectIdentity => "object-identity",
            Self::Generation => "generation",
            Self::GraphEdges => "graph-edges",
            Self::CapabilityAuthority => "capability-authority",
            Self::WaitState => "wait-state",
            Self::EventEvidence => "event-evidence",
            Self::TrapAttribution => "trap-attribution",
            Self::Cleanup => "cleanup",
            Self::GuestMemory => "guest-memory",
            Self::StableViews => "stable-views",
            Self::GraphValidation => "graph-validation",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "object-identity" => Some(Self::ObjectIdentity),
            "generation" => Some(Self::Generation),
            "graph-edges" => Some(Self::GraphEdges),
            "capability-authority" => Some(Self::CapabilityAuthority),
            "wait-state" => Some(Self::WaitState),
            "event-evidence" => Some(Self::EventEvidence),
            "trap-attribution" => Some(Self::TrapAttribution),
            "cleanup" => Some(Self::Cleanup),
            "guest-memory" => Some(Self::GuestMemory),
            "stable-views" => Some(Self::StableViews),
            "graph-validation" => Some(Self::GraphValidation),
            _ => None,
        }
    }

    pub const fn all() -> &'static [Self] {
        &PHASE2_SEMANTIC_FAMILIES
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase2CoverageSurfaceKind {
    ObjectKind,
    EdgeMode,
    CommandArea,
    StateTransition,
}

impl Phase2CoverageSurfaceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectKind => "object-kind",
            Self::EdgeMode => "edge-mode",
            Self::CommandArea => "command-area",
            Self::StateTransition => "state-transition",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Phase2CoverageUnit {
    pub unit_id: &'static str,
    pub family: Phase2SemanticFamily,
    pub surface_kind: Phase2CoverageSurfaceKind,
    pub surface: &'static str,
    pub positive_scenario: &'static str,
    pub negative_scenario: &'static str,
}

pub const PHASE2_SEMANTIC_FAMILIES: [Phase2SemanticFamily; 11] = [
    Phase2SemanticFamily::ObjectIdentity,
    Phase2SemanticFamily::Generation,
    Phase2SemanticFamily::GraphEdges,
    Phase2SemanticFamily::CapabilityAuthority,
    Phase2SemanticFamily::WaitState,
    Phase2SemanticFamily::EventEvidence,
    Phase2SemanticFamily::TrapAttribution,
    Phase2SemanticFamily::Cleanup,
    Phase2SemanticFamily::GuestMemory,
    Phase2SemanticFamily::StableViews,
    Phase2SemanticFamily::GraphValidation,
];

pub const PHASE2_COVERAGE_UNITS: [Phase2CoverageUnit; 11] = [
    Phase2CoverageUnit {
        unit_id: "phase2.object-identity",
        family: Phase2SemanticFamily::ObjectIdentity,
        surface_kind: Phase2CoverageSurfaceKind::ObjectKind,
        surface: "stable-object-kind-and-nonzero-id",
        positive_scenario: "object ref has a stable kind and nonzero identity",
        negative_scenario: "object ref with id=0 is rejected",
    },
    Phase2CoverageUnit {
        unit_id: "phase2.generation",
        family: Phase2SemanticFamily::Generation,
        surface_kind: Phase2CoverageSurfaceKind::ObjectKind,
        surface: "generation-bearing-internal-object",
        positive_scenario: "internal object carries a nonzero generation",
        negative_scenario: "internal object generation=0 is rejected",
    },
    Phase2CoverageUnit {
        unit_id: "phase2.graph-edges",
        family: Phase2SemanticFamily::GraphEdges,
        surface_kind: Phase2CoverageSurfaceKind::EdgeMode,
        surface: "live-historical-cleanup-effect-external-edge",
        positive_scenario: "edge mode preserves live, history, cleanup, or external meaning",
        negative_scenario: "edge mode cannot claim stronger evidence than the carrier boundary",
    },
    Phase2CoverageUnit {
        unit_id: "phase2.capability-authority",
        family: Phase2SemanticFamily::CapabilityAuthority,
        surface_kind: Phase2CoverageSurfaceKind::StateTransition,
        surface: "grant-delegate-attenuate-revoke-authority",
        positive_scenario: "capability authority records subject, object, rights, and provenance",
        negative_scenario: "stale or unproven capability authority is rejected",
    },
    Phase2CoverageUnit {
        unit_id: "phase2.wait-state",
        family: Phase2SemanticFamily::WaitState,
        surface_kind: Phase2CoverageSurfaceKind::StateTransition,
        surface: "wait-create-pending-resolve-cancel-restart",
        positive_scenario: "wait lifecycle records owner generation and event bridge",
        negative_scenario: "wait referencing inactive owner generation is rejected",
    },
    Phase2CoverageUnit {
        unit_id: "phase2.event-evidence",
        family: Phase2SemanticFamily::EventEvidence,
        surface_kind: Phase2CoverageSurfaceKind::CommandArea,
        surface: "event-log-command-evidence",
        positive_scenario: "event evidence is bounded to semantic-model facts",
        negative_scenario: "event evidence cannot import private runtime state",
    },
    Phase2CoverageUnit {
        unit_id: "phase2.trap-attribution",
        family: Phase2SemanticFamily::TrapAttribution,
        surface_kind: Phase2CoverageSurfaceKind::ObjectKind,
        surface: "trap-attribution-to-stable-objects",
        positive_scenario: "trap is attributed to stable store, activation, code, or artifact refs",
        negative_scenario: "trap attribution missing a generation-bearing ref is rejected",
    },
    Phase2CoverageUnit {
        unit_id: "phase2.cleanup",
        family: Phase2SemanticFamily::Cleanup,
        surface_kind: Phase2CoverageSurfaceKind::StateTransition,
        surface: "cleanup-begin-step-commit-idempotence",
        positive_scenario: "cleanup effect records tombstone and release effects",
        negative_scenario: "cleanup effect cannot create live ownership",
    },
    Phase2CoverageUnit {
        unit_id: "phase2.guest-memory",
        family: Phase2SemanticFamily::GuestMemory,
        surface_kind: Phase2CoverageSurfaceKind::ObjectKind,
        surface: "guest-address-space-vma-page-operation",
        positive_scenario: "guest memory facts describe semantic addresses and operations",
        negative_scenario: "guest memory fact cannot claim physical substrate truth",
    },
    Phase2CoverageUnit {
        unit_id: "phase2.stable-views",
        family: Phase2SemanticFamily::StableViews,
        surface_kind: Phase2CoverageSurfaceKind::CommandArea,
        surface: "stable-validation-and-view-records",
        positive_scenario: "stable views expose semantic state and structured violations",
        negative_scenario: "stable view cannot expose private runtime fields",
    },
    Phase2CoverageUnit {
        unit_id: "phase2.graph-validation",
        family: Phase2SemanticFamily::GraphValidation,
        surface_kind: Phase2CoverageSurfaceKind::CommandArea,
        surface: "all-independent-violations",
        positive_scenario: "validator reports every independently detectable violation",
        negative_scenario: "missing positive or negative coverage for a Phase 2 unit is rejected",
    },
];

pub const fn phase2_semantic_families() -> &'static [Phase2SemanticFamily] {
    &PHASE2_SEMANTIC_FAMILIES
}

pub const fn phase2_coverage_units() -> &'static [Phase2CoverageUnit] {
    &PHASE2_COVERAGE_UNITS
}

pub fn phase2_coverage_unit(unit_id: &str) -> Option<&'static Phase2CoverageUnit> {
    PHASE2_COVERAGE_UNITS.iter().find(|unit| unit.unit_id == unit_id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandTransactionStatus {
    Applied,
    Noop,
    Rejected,
}

impl CommandTransactionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Noop => "noop",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractFactEffect {
    pub subject: ObjectRef,
    pub relation: String,
    pub detail: String,
    pub evidence_level: EvidenceBoundaryLevel,
}

impl ContractFactEffect {
    pub fn semantic(subject: ObjectRef, relation: &str, detail: &str) -> Self {
        Self {
            subject,
            relation: relation.to_owned(),
            detail: detail.to_owned(),
            evidence_level: FEATURE_002_EVIDENCE_BOUNDARY,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventEvidence {
    pub event_id: u64,
    pub kind: String,
    pub subject: ObjectRef,
    pub epoch: u64,
    pub evidence_level: EvidenceBoundaryLevel,
    pub claim_limit: EvidenceBoundaryLevel,
}

impl EventEvidence {
    pub fn semantic(event_id: u64, kind: &str, subject: ObjectRef, epoch: u64) -> Self {
        Self {
            event_id,
            kind: kind.to_owned(),
            subject,
            epoch,
            evidence_level: FEATURE_002_EVIDENCE_BOUNDARY,
            claim_limit: FEATURE_002_EVIDENCE_BOUNDARY,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableViewRecord {
    pub schema: u16,
    pub family: Phase2SemanticFamily,
    pub object: ObjectRef,
    pub state: String,
    pub evidence_level: EvidenceBoundaryLevel,
}

impl StableViewRecord {
    pub fn semantic(family: Phase2SemanticFamily, object: ObjectRef, state: &str) -> Self {
        Self {
            schema: VIEW_SCHEMA_V1,
            family,
            object,
            state: state.to_owned(),
            evidence_level: FEATURE_002_EVIDENCE_BOUNDARY,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationViolation {
    pub kind: String,
    pub subject: ObjectRef,
    pub relation: String,
    pub expected: String,
    pub actual: String,
    pub severity: String,
    pub message: String,
}

impl ValidationViolation {
    pub fn new(
        kind: &str,
        subject: ObjectRef,
        relation: &str,
        expected: &str,
        actual: &str,
        message: &str,
    ) -> Self {
        Self {
            kind: kind.to_owned(),
            subject,
            relation: relation.to_owned(),
            expected: expected.to_owned(),
            actual: actual.to_owned(),
            severity: "error".to_owned(),
            message: message.to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandTransaction {
    pub command_id: String,
    pub issuer: String,
    pub command_area: String,
    pub preconditions: Vec<String>,
    pub effects: Vec<ContractFactEffect>,
    pub events: Vec<EventEvidence>,
    pub postconditions: Vec<String>,
    pub status: CommandTransactionStatus,
    pub violations: Vec<ValidationViolation>,
}

impl CommandTransaction {
    pub fn new(command_id: &str, issuer: &str, command_area: &str) -> Self {
        Self {
            command_id: command_id.to_owned(),
            issuer: issuer.to_owned(),
            command_area: command_area.to_owned(),
            preconditions: Vec::new(),
            effects: Vec::new(),
            events: Vec::new(),
            postconditions: Vec::new(),
            status: CommandTransactionStatus::Noop,
            violations: Vec::new(),
        }
    }

    pub fn with_effect(mut self, effect: ContractFactEffect) -> Self {
        self.effects.push(effect);
        self
    }

    pub fn with_event(mut self, event: EventEvidence) -> Self {
        self.events.push(event);
        self
    }

    pub fn applied(mut self) -> Self {
        self.status = CommandTransactionStatus::Applied;
        self
    }

    pub fn rejected(mut self, violation: ValidationViolation) -> Self {
        self.status = CommandTransactionStatus::Rejected;
        self.effects.clear();
        self.events.clear();
        self.violations.push(violation);
        self
    }

    pub const fn is_rejected(&self) -> bool {
        matches!(self.status, CommandTransactionStatus::Rejected)
    }

    pub fn validates_no_mutation_on_reject(&self) -> ContractResult<()> {
        if self.is_rejected() && (!self.effects.is_empty() || !self.events.is_empty()) {
            return Err(ContractError::new(
                "rejected command transaction must not contain effects or events",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceBoundaryClaim {
    pub feature_id: String,
    pub level: EvidenceBoundaryLevel,
    pub claim_limit: EvidenceBoundaryLevel,
    pub stable_roots: Vec<String>,
    pub exclusions: Vec<String>,
}

impl EvidenceBoundaryClaim {
    pub fn feature_002() -> Self {
        Self {
            feature_id: FEATURE_002_ID.to_owned(),
            level: FEATURE_002_EVIDENCE_BOUNDARY,
            claim_limit: FEATURE_002_EVIDENCE_BOUNDARY,
            stable_roots: vec![
                "contract-core-records".to_owned(),
                "phase2-coverage-registry".to_owned(),
                "feature-local-evidence-carrier".to_owned(),
            ],
            exclusions: vec![
                "artifact-profile-completion".to_owned(),
                "frontend-personality-breadth".to_owned(),
                "real-target-substrate-behavior".to_owned(),
                "migration-restoration".to_owned(),
                "cross-isa-portability".to_owned(),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractEvidenceCarrierKind {
    ArtifactShaped,
    MigrationShaped,
}

impl ContractEvidenceCarrierKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactShaped => "artifact-shaped",
            Self::MigrationShaped => "migration-shaped",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "artifact-shaped" => Some(Self::ArtifactShaped),
            "migration-shaped" => Some(Self::MigrationShaped),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoadmapPhase {
    Phase3ArtifactProfile,
    Phase4FrontendPersonality,
    Phase5SubstrateAuthority,
    Phase6Portability,
}

impl RoadmapPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Phase3ArtifactProfile => "phase3-artifact-profile",
            Self::Phase4FrontendPersonality => "phase4-frontend-personality",
            Self::Phase5SubstrateAuthority => "phase5-substrate-authority",
            Self::Phase6Portability => "phase6-portability",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoadmapDeferral {
    pub phase: RoadmapPhase,
    pub surface: &'static str,
    pub reason: &'static str,
}

pub const FEATURE_002_ROADMAP_DEFERRALS: [RoadmapDeferral; 4] = [
    RoadmapDeferral {
        phase: RoadmapPhase::Phase3ArtifactProfile,
        surface: "artifact/profile gate completion",
        reason: "Feature 002 reuses artifact-shaped evidence without proving portable artifact execution",
    },
    RoadmapDeferral {
        phase: RoadmapPhase::Phase4FrontendPersonality,
        surface: "frontend/personality breadth",
        reason: "Feature 002 defines contract facts only, not Linux/WASI personality completeness",
    },
    RoadmapDeferral {
        phase: RoadmapPhase::Phase5SubstrateAuthority,
        surface: "real target substrate authority",
        reason: "Feature 002 remains at semantic-model evidence and excludes physical substrate behavior",
    },
    RoadmapDeferral {
        phase: RoadmapPhase::Phase6Portability,
        surface: "migration restoration and cross-ISA portability",
        reason: "Feature 002 uses migration-shaped carriers without claiming restored execution",
    },
];

pub const fn feature_002_roadmap_deferrals() -> &'static [RoadmapDeferral] {
    &FEATURE_002_ROADMAP_DEFERRALS
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
typed_ref!(GuestMemoryOperationRef, ObjectKind::GuestMemoryOperation);
typed_ref!(ExternalObjectRef, ObjectKind::External);
// Process/Thread family
typed_ref!(ProcessRef, ObjectKind::Process);
typed_ref!(ThreadRef, ObjectKind::Thread);
typed_ref!(ThreadGroupRef, ObjectKind::ThreadGroup);
typed_ref!(FdTableRef, ObjectKind::FdTable);
typed_ref!(OpenFileDescriptionRef, ObjectKind::OpenFileDescription);
typed_ref!(CredentialRef, ObjectKind::Credential);
typed_ref!(CredentialTransitionRef, ObjectKind::CredentialTransition);
// Signal family
typed_ref!(SignalDispositionRef, ObjectKind::SignalDisposition);
typed_ref!(PendingSignalRef, ObjectKind::PendingSignal);
typed_ref!(SignalMaskRef, ObjectKind::SignalMask);
typed_ref!(SignalFrameRef, ObjectKind::SignalFrame);
typed_ref!(SignalDeliveryRef, ObjectKind::SignalDelivery);
// Memory expansion
typed_ref!(PageFaultEventRef, ObjectKind::PageFaultEvent);
typed_ref!(CowBreakEventRef, ObjectKind::CowBreakEvent);
typed_ref!(VmaSplitEventRef, ObjectKind::VmaSplitEvent);
typed_ref!(PageAllocSubstrateEventRef, ObjectKind::PageAllocSubstrateEvent);
// Futex family
typed_ref!(FutexKeyRef, ObjectKind::FutexKey);
typed_ref!(FutexWaitRef, ObjectKind::FutexWait);
typed_ref!(FutexWakeRef, ObjectKind::FutexWake);
typed_ref!(FutexRequeueRef, ObjectKind::FutexRequeue);
typed_ref!(RobustListRef, ObjectKind::RobustList);
// Epoll readiness
typed_ref!(ReadySourceRef, ObjectKind::ReadySource);
typed_ref!(EpollWatcherRef, ObjectKind::EpollWatcher);
// Filesystem expansion
typed_ref!(FileLockRef, ObjectKind::FileLock);
typed_ref!(XattrRef, ObjectKind::Xattr);

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
pub struct CodeObjectViewV1 {
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
pub struct ActivationViewV1 {
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
pub struct TrapViewV1 {
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
pub const CODE_PAYLOAD_FORMAT_CWASM: &str = "cwasm";
pub const WASMTIME_CRATE_VERSION: &str = "43.0.2";
pub const WASMTIME_COMPILATION_STRATEGY: &str = "cranelift";
pub const DEFAULT_MAX_MEMORY_PAGES: u32 = 16;
pub const DEFAULT_MAX_TABLE_ELEMENTS: u32 = 0;
pub const DEFAULT_MAX_HOSTCALLS_PER_ACTIVATION: u32 = 64;
pub const DEFAULT_COMPONENT_MODEL_VERSION: &str = "wasm-core-module-v0";
pub const DEFAULT_WASI_PROFILE: &str = "none";
pub const DEFAULT_HOSTCALL_ABI_VERSION: &str = "visa-target-hostcall-frame-v1";
pub const DEFAULT_CAPABILITY_ABI_VERSION: &str = "visa-capability-handle-v1";
pub const DEFAULT_SEMANTIC_CONTRACT_SCHEMA_VERSION: &str = "semantic-contract-v0.1";

/// Evidence boundary for each ObjectKind.
///
/// - `SemanticModel`: portable across host ISAs, part of contract graph snapshot
/// - `ReferenceService` / `ReferenceAotHarness`: reference/native service evidence
/// - `PortableArtifactExecution`: artifact execution path evidence
/// - `RealTargetSubstrate`: requires real substrate backend (physical frame, MMIO, etc.)
/// - host-specific (not in portable snapshot): raw register frames, physical addresses, native page tables
pub fn object_kind_evidence_level(kind: ObjectKind) -> EvidenceBoundaryLevel {
    use EvidenceBoundaryLevel::*;
    match kind {
        // Process/Thread family — portable semantic models
        ObjectKind::Process
        | ObjectKind::Thread
        | ObjectKind::ThreadGroup
        | ObjectKind::FdTable
        | ObjectKind::OpenFileDescription
        | ObjectKind::Credential
        | ObjectKind::CredentialTransition => SemanticModel,

        // Signal family — dispositions, masks, deliveries are semantic; SignalFrame is arch-specific
        ObjectKind::SignalDisposition
        | ObjectKind::PendingSignal
        | ObjectKind::SignalMask
        | ObjectKind::SignalDelivery => SemanticModel,
        ObjectKind::SignalFrame => PortableArtifactExecution, // contains arch regs — arch-specific evidence layer

        // Memory expansion — semantic facts, NOT physical page table state
        ObjectKind::GuestMemoryOperation
        | ObjectKind::PageFaultEvent
        | ObjectKind::CowBreakEvent
        | ObjectKind::VmaSplitEvent => SemanticModel,
        ObjectKind::PageAllocSubstrateEvent => RealTargetSubstrate, // physical frame identity

        // Futex family — pure semantic
        ObjectKind::FutexKey
        | ObjectKind::FutexWait
        | ObjectKind::FutexWake
        | ObjectKind::FutexRequeue
        | ObjectKind::RobustList => SemanticModel,

        // Epoll readiness — semantic models
        ObjectKind::ReadySource | ObjectKind::EpollWatcher => SemanticModel,

        // Filesystem expansion — semantic
        ObjectKind::FileLock | ObjectKind::Xattr => SemanticModel,

        // Legacy kinds — keep explicit; not adding new kinds here is a review smell
        ObjectKind::Hart
        | ObjectKind::Task
        | ObjectKind::RunnableQueue
        | ObjectKind::ActivationContext
        | ObjectKind::SavedContext
        | ObjectKind::TimerInterrupt
        | ObjectKind::IpiEvent
        | ObjectKind::RemotePreempt
        | ObjectKind::RemotePark
        | ObjectKind::Preemption
        | ObjectKind::SchedulerDecision
        | ObjectKind::CrossHartSchedulerDecision
        | ObjectKind::ActivationMigration
        | ObjectKind::SmpSafePoint
        | ObjectKind::StopTheWorldRendezvous
        | ObjectKind::SmpCodePublishBarrier
        | ObjectKind::SmpCleanupQuiescence
        | ObjectKind::SmpSnapshotBarrier
        | ObjectKind::SmpStressRun
        | ObjectKind::SmpScalingBenchmark
        | ObjectKind::IntegratedSmpPreemptionCleanup
        | ObjectKind::IntegratedSmpNetworkFault
        | ObjectKind::IntegratedDiskPreemptFault
        | ObjectKind::IntegratedSimdMigration
        | ObjectKind::IntegratedNetworkDiskIo
        | ObjectKind::IntegratedDisplaySchedulerLoad
        | ObjectKind::IntegratedSnapshotIoLeaseBarrier
        | ObjectKind::IntegratedCodePublishSmpWorkload
        | ObjectKind::IntegratedDisplayPanic
        | ObjectKind::IntegratedOsctlTraceReplay
        | ObjectKind::DeviceObject
        | ObjectKind::QueueObject
        | ObjectKind::DescriptorObject
        | ObjectKind::DmaBufferObject
        | ObjectKind::MmioRegionObject
        | ObjectKind::IrqLineObject
        | ObjectKind::IrqEvent
        | ObjectKind::DeviceCapability
        | ObjectKind::DriverStoreBinding
        | ObjectKind::IoWait
        | ObjectKind::IoCleanup
        | ObjectKind::IoFaultInjection
        | ObjectKind::IoValidationReport
        | ObjectKind::PacketDeviceObject
        | ObjectKind::PacketBufferObject
        | ObjectKind::PacketQueueObject
        | ObjectKind::PacketDescriptorObject
        | ObjectKind::FakeNetBackendObject
        | ObjectKind::VirtioNetBackendObject
        | ObjectKind::NetworkRxInterrupt
        | ObjectKind::NetworkRxWaitResolution
        | ObjectKind::NetworkTxCapabilityGate
        | ObjectKind::NetworkTxCompletion
        | ObjectKind::NetworkStackAdapter
        | ObjectKind::SocketObject
        | ObjectKind::EndpointObject
        | ObjectKind::SocketOperation
        | ObjectKind::SocketWait
        | ObjectKind::NetworkBackpressure
        | ObjectKind::NetworkDriverCleanup
        | ObjectKind::NetworkGenerationAudit
        | ObjectKind::NetworkFaultInjection
        | ObjectKind::NetworkBenchmark
        | ObjectKind::NetworkRecoveryBenchmark
        | ObjectKind::BlockDeviceObject
        | ObjectKind::BlockRangeObject
        | ObjectKind::BlockRequestObject
        | ObjectKind::BlockCompletionObject
        | ObjectKind::BlockWait
        | ObjectKind::FakeBlockBackendObject
        | ObjectKind::VirtioBlkBackendObject
        | ObjectKind::BlockReadPath
        | ObjectKind::BlockWritePath
        | ObjectKind::BlockRequestQueue
        | ObjectKind::BlockDmaBuffer
        | ObjectKind::BlockPageObject
        | ObjectKind::BufferCacheObject
        | ObjectKind::FileObject
        | ObjectKind::DirectoryObject
        | ObjectKind::FatAdapterObject
        | ObjectKind::Ext4AdapterObject
        | ObjectKind::FileHandleCapability
        | ObjectKind::FsWait
        | ObjectKind::BlockDriverCleanup
        | ObjectKind::BlockPendingIoPolicy
        | ObjectKind::BlockRequestGenerationAudit
        | ObjectKind::BlockBenchmark
        | ObjectKind::BlockRecoveryBenchmark
        | ObjectKind::TargetFeatureSet
        | ObjectKind::VectorState
        | ObjectKind::SimdFaultInjection
        | ObjectKind::SimdBenchmark
        | ObjectKind::SimdContextSwitchBenchmark
        | ObjectKind::FramebufferObject
        | ObjectKind::DisplayObject
        | ObjectKind::DisplayCapability
        | ObjectKind::FramebufferWindowLease
        | ObjectKind::FramebufferMapping
        | ObjectKind::FramebufferWrite
        | ObjectKind::FramebufferFlushRegion
        | ObjectKind::FramebufferDirtyRegion
        | ObjectKind::DisplayEventLog
        | ObjectKind::DisplayCleanup
        | ObjectKind::DisplaySnapshotBarrier
        | ObjectKind::DisplayPanicLastFrame
        | ObjectKind::FramebufferBenchmark
        | ObjectKind::ActivationResume
        | ObjectKind::ActivationWait
        | ObjectKind::ActivationCleanup
        | ObjectKind::PreemptionLatency
        | ObjectKind::HartEventAttribution
        | ObjectKind::Resource
        | ObjectKind::Capability
        | ObjectKind::WaitToken
        | ObjectKind::FaultDomain
        | ObjectKind::Store
        | ObjectKind::StoreActivation
        | ObjectKind::Activation
        | ObjectKind::Artifact
        | ObjectKind::CodeObject
        | ObjectKind::Boundary
        | ObjectKind::Transaction
        | ObjectKind::Event
        | ObjectKind::Trap
        | ObjectKind::Hostcall
        | ObjectKind::Cleanup
        | ObjectKind::MemoryObject
        | ObjectKind::GuestAddressSpace
        | ObjectKind::VmaRegion
        | ObjectKind::PageObject
        | ObjectKind::Tombstone
        | ObjectKind::External => SemanticModel,
    }
}

/// Returns the total count of ObjectKind variants — used in tests to verify evidence boundary coverage.
#[doc(hidden)]
pub const fn object_kind_count() -> usize {
    // Update this when adding new ObjectKind variants to the enum.
    226
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_boundary_levels_are_ordered_by_claim_strength() {
        assert!(
            EvidenceBoundaryLevel::RealTargetSubstrate
                .satisfies(EvidenceBoundaryLevel::PortableArtifactExecution)
        );
        assert!(
            !EvidenceBoundaryLevel::ReferenceService
                .can_claim(EvidenceBoundaryLevel::PortableArtifactExecution)
        );
        assert!(
            !EvidenceBoundaryLevel::SemanticModel
                .can_claim(EvidenceBoundaryLevel::ReferenceService)
        );
    }

    #[test]
    fn evidence_boundary_parse_accepts_spec_names() {
        assert_eq!(
            EvidenceBoundaryLevel::parse("semantic model"),
            Some(EvidenceBoundaryLevel::SemanticModel)
        );
        assert_eq!(
            EvidenceBoundaryLevel::parse("reference/native service"),
            Some(EvidenceBoundaryLevel::ReferenceService)
        );
        assert_eq!(
            EvidenceBoundaryLevel::parse("reference-aot-harness"),
            Some(EvidenceBoundaryLevel::ReferenceAotHarness)
        );
        assert_eq!(
            EvidenceBoundaryLevel::parse("portable artifact execution"),
            Some(EvidenceBoundaryLevel::PortableArtifactExecution)
        );
        assert_eq!(
            EvidenceBoundaryLevel::parse("real-target-substrate"),
            Some(EvidenceBoundaryLevel::RealTargetSubstrate)
        );
    }

    #[test]
    fn phase2_registry_covers_every_semantic_family_once() {
        assert_eq!(phase2_semantic_families().len(), 11);
        assert_eq!(phase2_coverage_units().len(), phase2_semantic_families().len());
        for family in phase2_semantic_families() {
            let count =
                phase2_coverage_units().iter().filter(|unit| unit.family == *family).count();
            assert_eq!(count, 1, "{} must have exactly one canonical unit", family.as_str());
        }
        for unit in phase2_coverage_units() {
            assert_eq!(phase2_coverage_unit(unit.unit_id), Some(unit));
            assert!(!unit.positive_scenario.is_empty());
            assert!(!unit.negative_scenario.is_empty());
        }
    }

    #[test]
    fn object_refs_require_stable_kind_identity_and_generation() {
        let store = ObjectRef::new(ObjectKind::Store, 1, 1).expect("valid store ref");
        assert_eq!(store.kind, ObjectKind::Store);
        assert!(ObjectRef::new(ObjectKind::Store, 0, 1).is_err());
        assert!(ObjectRef::new(ObjectKind::Store, 1, 0).is_err());
        assert!(ObjectRef::new(ObjectKind::External, 1, 0).is_ok());
    }

    #[test]
    fn edge_modes_and_feature_002_evidence_boundary_are_stable_contract_names() {
        let store = ObjectRef::new(ObjectKind::Store, 1, 1).expect("valid store ref");
        let wait = ObjectRef::new(ObjectKind::WaitToken, 2, 1).expect("valid wait ref");
        let edge = ContractEdge::new(store, wait, RefMode::Live, "store->wait", 7);

        assert_eq!(RefMode::Live.as_str(), "live");
        assert_eq!(RefMode::Historical.as_str(), "historical");
        assert_eq!(RefMode::CleanupEffect.as_str(), "cleanup-effect");
        assert_eq!(RefMode::External.as_str(), "external");
        assert_eq!(edge.evidence_level, EvidenceBoundaryLevel::SemanticModel);
        assert!(!FEATURE_002_EVIDENCE_BOUNDARY.can_claim(EvidenceBoundaryLevel::ReferenceService));
    }

    #[test]
    fn command_transaction_event_view_and_violation_records_keep_rejections_effect_free() {
        let store = ObjectRef::new(ObjectKind::Store, 1, 1).expect("valid store ref");
        let effect = ContractFactEffect::semantic(store, "grants", "capability=9");
        let event = EventEvidence::semantic(10, "capability-grant", store, 1);
        let view =
            StableViewRecord::semantic(Phase2SemanticFamily::CapabilityAuthority, store, "granted");
        let violation = ValidationViolation::new(
            "precondition-failed",
            store,
            "generation",
            "1",
            "0",
            "stale generation",
        );

        let applied = CommandTransaction::new("cmd-1", "test", "capability")
            .with_effect(effect)
            .with_event(event)
            .applied();
        assert_eq!(applied.status, CommandTransactionStatus::Applied);
        assert_eq!(view.evidence_level, EvidenceBoundaryLevel::SemanticModel);

        let rejected = applied.rejected(violation);
        assert!(rejected.is_rejected());
        assert!(rejected.effects.is_empty());
        assert!(rejected.events.is_empty());
        rejected.validates_no_mutation_on_reject().expect("rejected command must not mutate");
    }

    #[test]
    fn feature_002_claim_and_deferrals_exclude_later_roadmap_surfaces() {
        let claim = EvidenceBoundaryClaim::feature_002();
        assert_eq!(claim.feature_id, FEATURE_002_ID);
        assert_eq!(claim.level, EvidenceBoundaryLevel::SemanticModel);
        assert_eq!(claim.claim_limit, EvidenceBoundaryLevel::SemanticModel);
        for exclusion in [
            "artifact-profile-completion",
            "frontend-personality-breadth",
            "real-target-substrate-behavior",
            "migration-restoration",
            "cross-isa-portability",
        ] {
            assert!(claim.exclusions.iter().any(|entry| entry == exclusion));
        }

        assert_eq!(feature_002_roadmap_deferrals().len(), 4);
        assert!(
            feature_002_roadmap_deferrals()
                .iter()
                .any(|deferral| deferral.phase == RoadmapPhase::Phase6Portability)
        );
    }

    #[test]
    fn phase1_process_types_are_portable_semantic() {
        use EvidenceBoundaryLevel::SemanticModel;
        for kind in [
            ObjectKind::Process,
            ObjectKind::Thread,
            ObjectKind::ThreadGroup,
            ObjectKind::FdTable,
            ObjectKind::Credential,
        ] {
            assert_eq!(
                object_kind_evidence_level(kind),
                SemanticModel,
                "{} must be SemanticModel (portable)",
                kind.as_str()
            );
        }
    }

    #[test]
    fn signal_frame_is_not_pure_semantic() {
        let level = object_kind_evidence_level(ObjectKind::SignalFrame);
        assert!(
            level.rank() >= EvidenceBoundaryLevel::PortableArtifactExecution.rank(),
            "SignalFrame must be at least PortableArtifactExecution (contains arch regs)"
        );
    }

    #[test]
    fn page_alloc_is_substrate_evidence_only() {
        let level = object_kind_evidence_level(ObjectKind::PageAllocSubstrateEvent);
        assert_eq!(
            level,
            EvidenceBoundaryLevel::RealTargetSubstrate,
            "PageAllocSubstrateEvent contains physical frame identity — substrate evidence only"
        );
    }

    #[test]
    fn all_new_process_family_kinds_have_explicit_boundary() {
        let new_kinds = [
            ObjectKind::Process,
            ObjectKind::Thread,
            ObjectKind::ThreadGroup,
            ObjectKind::FdTable,
            ObjectKind::OpenFileDescription,
            ObjectKind::Credential,
            ObjectKind::CredentialTransition,
            ObjectKind::SignalDisposition,
            ObjectKind::PendingSignal,
            ObjectKind::SignalMask,
            ObjectKind::SignalFrame,
            ObjectKind::SignalDelivery,
            ObjectKind::GuestMemoryOperation,
            ObjectKind::PageFaultEvent,
            ObjectKind::CowBreakEvent,
            ObjectKind::VmaSplitEvent,
            ObjectKind::PageAllocSubstrateEvent,
            ObjectKind::FutexKey,
            ObjectKind::FutexWait,
            ObjectKind::FutexWake,
            ObjectKind::FutexRequeue,
            ObjectKind::RobustList,
            ObjectKind::ReadySource,
            ObjectKind::EpollWatcher,
            ObjectKind::FileLock,
            ObjectKind::Xattr,
        ];
        for kind in new_kinds {
            // Must not panic — every kind must be handled in object_kind_evidence_level()
            let _level = object_kind_evidence_level(kind);
            assert!(
                _level.rank() <= EvidenceBoundaryLevel::RealTargetSubstrate.rank(),
                "{} has invalid evidence boundary",
                kind.as_str()
            );
        }
    }
}
