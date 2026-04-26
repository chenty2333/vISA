use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;
use target_abi::{
    OBJECT_KIND_CODE_OBJECT_V1, ObjectRefRaw, PcRangeEntryV1, PcRangeRuntimeEntryV1,
    TrapAttributionV1, TrapKindV1, TrapMapEntryV1, classify_trap_pc,
};

pub const TARGET_ARTIFACT_GENERATION_V1: Generation = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractObjectKind {
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
    ActivationResume,
    ActivationWait,
    ActivationCleanup,
    PreemptionLatencySample,
    HartEventAttribution,
    Resource,
    Artifact,
    CodeObject,
    Store,
    FaultDomain,
    Activation,
    Trap,
    Hostcall,
    Capability,
    WaitToken,
    CleanupTransaction,
    MemoryObject,
    GuestAddressSpace,
    VmaRegion,
    PageObject,
    EventLog,
    Tombstone,
    ExternalObject,
}

impl ContractObjectKind {
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
            Self::ActivationResume => "activation-resume",
            Self::ActivationWait => "activation-wait",
            Self::ActivationCleanup => "activation-cleanup",
            Self::PreemptionLatencySample => "preemption-latency",
            Self::HartEventAttribution => "hart-event-attribution",
            Self::Resource => "resource",
            Self::Artifact => "artifact",
            Self::CodeObject => "code-object",
            Self::Store => "store",
            Self::FaultDomain => "fault-domain",
            Self::Activation => "activation",
            Self::Trap => "trap",
            Self::Hostcall => "hostcall",
            Self::Capability => "capability",
            Self::WaitToken => "wait-token",
            Self::CleanupTransaction => "cleanup-transaction",
            Self::MemoryObject => "memory-object",
            Self::GuestAddressSpace => "guest-address-space",
            Self::VmaRegion => "vma-region",
            Self::PageObject => "page-object",
            Self::EventLog => "event-log",
            Self::Tombstone => "tombstone",
            Self::ExternalObject => "external-object",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractObjectRef {
    pub kind: ContractObjectKind,
    pub id: u64,
    pub generation: Generation,
}

impl ContractObjectRef {
    pub const fn new(kind: ContractObjectKind, id: u64, generation: Generation) -> Self {
        Self {
            kind,
            id,
            generation,
        }
    }

    pub fn summary(self) -> String {
        format!("{}:{}@{}", self.kind.as_str(), self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstoneRecord {
    pub kind: ContractObjectKind,
    pub id: u64,
    pub generation: Generation,
    pub died_at: EventId,
    pub reason: String,
}

impl TombstoneRecord {
    pub fn new(
        kind: ContractObjectKind,
        id: u64,
        generation: Generation,
        died_at: EventId,
        reason: &str,
    ) -> Self {
        Self {
            kind,
            id,
            generation,
            died_at,
            reason: reason.to_string(),
        }
    }

    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(self.kind, self.id, self.generation)
    }

    pub fn summary(&self) -> String {
        format!(
            "tombstone kind={} id={} generation={} died_at={} reason={}",
            self.kind.as_str(),
            self.id,
            self.generation,
            self.died_at,
            self.reason
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetArtifactKind {
    TargetArtifactImageV1,
    CwasmPayload,
    SupervisorCore,
    NativeStub,
}

impl TargetArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetArtifactImageV1 => "target-artifact-image-v1",
            Self::CwasmPayload => "cwasm-payload",
            Self::SupervisorCore => "supervisor-core",
            Self::NativeStub => "native-stub",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetMemoryPlan {
    pub max_memory_pages: u32,
    pub max_table_elements: u32,
    pub max_hostcalls_per_activation: u32,
}

impl TargetMemoryPlan {
    pub const fn new(
        max_memory_pages: u32,
        max_table_elements: u32,
        max_hostcalls_per_activation: u32,
    ) -> Self {
        Self {
            max_memory_pages,
            max_table_elements,
            max_hostcalls_per_activation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeRangePermission {
    ReadWrite,
    ReadOnly,
    ReadExecute,
}

impl CodeRangePermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadWrite => "rw",
            Self::ReadOnly => "ro",
            Self::ReadExecute => "rx",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetAddressRange {
    pub start: u64,
    pub len: u64,
    pub permission: CodeRangePermission,
}

impl TargetAddressRange {
    pub const fn new(start: u64, len: u64, permission: CodeRangePermission) -> Self {
        Self {
            start,
            len,
            permission,
        }
    }

    pub const fn end(self) -> u64 {
        self.start + self.len
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetAddressMapEntry {
    pub symbol: String,
    pub offset: u64,
    pub len: u64,
}

impl TargetAddressMapEntry {
    pub fn new(symbol: &str, offset: u64, len: u64) -> Self {
        Self {
            symbol: symbol.to_string(),
            offset,
            len,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetTrapMetadata {
    pub class: TargetTrapClass,
    pub symbol: String,
    pub offset: u64,
}

impl TargetTrapMetadata {
    pub fn new(class: TargetTrapClass, symbol: &str, offset: u64) -> Self {
        Self {
            class,
            symbol: symbol.to_string(),
            offset,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallCategory {
    Service,
    Device,
    PacketDevice,
    Mmio,
    Dma,
    Irq,
    Virtqueue,
    Dmw,
    CodePublish,
    Snapshot,
    GuestMemory,
    Timer,
    FaultDomain,
    EventLog,
    StoreControl,
    Wait,
}

impl HostcallCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Device => "device",
            Self::PacketDevice => "packet-device",
            Self::Mmio => "mmio",
            Self::Dma => "dma",
            Self::Irq => "irq",
            Self::Virtqueue => "virtqueue",
            Self::Dmw => "dmw",
            Self::CodePublish => "code-publish",
            Self::Snapshot => "snapshot",
            Self::GuestMemory => "guest-memory",
            Self::Timer => "timer",
            Self::FaultDomain => "fault-domain",
            Self::EventLog => "event-log",
            Self::StoreControl => "store-control",
            Self::Wait => "wait",
        }
    }

    pub const fn requires_capability(self) -> bool {
        matches!(
            self,
            Self::Device
                | Self::PacketDevice
                | Self::Mmio
                | Self::Dma
                | Self::Irq
                | Self::Virtqueue
                | Self::Dmw
                | Self::CodePublish
                | Self::Snapshot
                | Self::GuestMemory
                | Self::FaultDomain
                | Self::EventLog
                | Self::StoreControl
                | Self::Timer
        )
    }
}

pub const fn capability_class_requires_hostcall_gate(class: CapabilityClass) -> bool {
    matches!(
        class,
        CapabilityClass::Device
            | CapabilityClass::PacketDevice
            | CapabilityClass::CodePublish
            | CapabilityClass::MmioRegion
            | CapabilityClass::DmaBuffer
            | CapabilityClass::IrqLine
            | CapabilityClass::VirtioQueue
            | CapabilityClass::DmwWindow
            | CapabilityClass::Timer
            | CapabilityClass::Snapshot
            | CapabilityClass::FaultDomain
            | CapabilityClass::EventLog
            | CapabilityClass::StoreControl
            | CapabilityClass::NetInterface
            | CapabilityClass::NetSocket
            | CapabilityClass::GuestMemoryAccess
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostcallSpec {
    pub number: u32,
    pub name: String,
    pub category: HostcallCategory,
    pub object: String,
    pub operation: String,
    pub may_pending: bool,
}

impl HostcallSpec {
    pub fn new(
        number: u32,
        name: &str,
        category: HostcallCategory,
        object: &str,
        operation: &str,
        may_pending: bool,
    ) -> Self {
        Self {
            number,
            name: name.to_string(),
            category,
            object: object.to_string(),
            operation: operation.to_string(),
            may_pending,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "hostcall:{}:{}:{}:{}:pending{}",
            self.number,
            self.category.as_str(),
            self.object,
            self.operation,
            self.may_pending
        )
    }

    pub fn requires_capability(&self) -> bool {
        self.category.requires_capability()
            || capability_class_requires_hostcall_gate(CapabilityClass::from_object(&self.object))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityMatrixError {
    UnknownObjectClass,
    UnknownOperation,
}

impl AuthorityMatrixError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownObjectClass => "authority-unknown-object-class",
            Self::UnknownOperation => "authority-unknown-operation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityMatrixDecision {
    pub class: CapabilityClass,
    pub requires_capability: bool,
    pub required_right: Option<String>,
}

pub struct AuthorityMatrix;

impl AuthorityMatrix {
    pub fn check(
        object: &str,
        operation: &str,
        declared_capability: bool,
    ) -> Result<AuthorityMatrixDecision, AuthorityMatrixError> {
        let class = CapabilityClass::from_object(object);
        let right = match class {
            CapabilityClass::MmioRegion => match operation {
                "read" | "read8" | "read16" | "read32" | "read64" => Some("read"),
                "write" | "write8" | "write16" | "write32" | "write64" => Some("write"),
                "fence" => Some("fence"),
                "map" => Some("map"),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::DmaBuffer => match operation {
                "device_addr" => Some("device_addr"),
                "sync_for_device" | "sync_for_cpu" => Some("sync"),
                "free" => Some("free"),
                "submit" | "complete" | "cancel" | "map" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::IrqLine => match operation {
                "bind" | "ack" | "mask" | "unmask" | "deliver" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::DmwWindow => match operation {
                "map_user_window" => Some("map"),
                "unmap_user_window" => Some("unmap"),
                "read_window" | "write_window" => Some("access"),
                "open" | "close" | "acquire" | "release" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::CodePublish => match operation {
                "publish" | "retire" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::Snapshot => match operation {
                "enter_barrier" => Some("enter"),
                "export_package" => Some("export"),
                "import_package" => Some("import"),
                "enter" | "validate" | "replay" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::FaultDomain => match operation {
                "kill_store" => Some("kill"),
                "restart_store" => Some("restart"),
                "kill" | "restart" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::PacketDevice => match operation {
                "rx" | "tx" | "configure" | "poll" | "irq" | "dma" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::VirtioQueue => match operation {
                "notify" => Some("kick"),
                "consume" => Some("read"),
                "reset" => Some("reset"),
                "read" | "write" | "kick" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::Device => match operation {
                "probe" | "read" | "configure" | "reset" | "poll" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::GuestMemoryAccess => match operation {
                "read" | "write" | "map" | "unmap" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::Timer => match operation {
                "arm" | "cancel" | "read" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::EventLog => match operation {
                "append" | "inspect" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::StoreControl => match operation {
                "start" | "stop" | "restart" | "kill" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::NetInterface | CapabilityClass::NetSocket => Some(operation),
            CapabilityClass::ServiceImport => {
                if object.contains('.') || declared_capability {
                    Some(operation)
                } else {
                    return Err(AuthorityMatrixError::UnknownObjectClass);
                }
            }
        };
        let requires_capability = capability_class_requires_hostcall_gate(class)
            || declared_capability
            || class != CapabilityClass::ServiceImport;
        Ok(AuthorityMatrixDecision {
            class,
            requires_capability,
            required_right: right.map(ToString::to_string),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetCapabilitySpec {
    pub object: String,
    pub operations: Vec<String>,
    pub lifetime: String,
    pub class: CapabilityClass,
}

impl TargetCapabilitySpec {
    pub fn new(object: &str, operations: &[&str], lifetime: &str) -> Self {
        Self {
            object: object.to_string(),
            operations: operations
                .iter()
                .map(|operation| (*operation).to_string())
                .collect(),
            lifetime: lifetime.to_string(),
            class: CapabilityClass::from_object(object),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetArtifactImage {
    pub id: TargetArtifactId,
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub kind: TargetArtifactKind,
    pub target_profile: String,
    pub artifact_hash: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub memory_plan: TargetMemoryPlan,
    pub trap_metadata: Vec<TargetTrapMetadata>,
    pub address_map: Vec<TargetAddressMapEntry>,
    pub capabilities: Vec<TargetCapabilitySpec>,
    pub hostcalls: Vec<HostcallSpec>,
    pub payload_len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedTargetArtifact {
    pub package: String,
    pub artifact_name: String,
    pub target_profile: String,
    pub artifact_hash: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
}

impl ExpectedTargetArtifact {
    pub fn new(
        package: &str,
        artifact_name: &str,
        target_profile: &str,
        artifact_hash: &str,
        abi_fingerprint: &str,
        manifest_binding_hash: &str,
        code_hash: &str,
    ) -> Self {
        Self {
            package: package.to_string(),
            artifact_name: artifact_name.to_string(),
            target_profile: target_profile.to_string(),
            artifact_hash: artifact_hash.to_string(),
            abi_fingerprint: abi_fingerprint.to_string(),
            manifest_binding_hash: manifest_binding_hash.to_string(),
            code_hash: code_hash.to_string(),
        }
    }
}

impl TargetArtifactImage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: TargetArtifactId,
        package: &str,
        artifact_name: &str,
        role: &str,
        target_profile: &str,
        artifact_hash: &str,
        abi_fingerprint: &str,
        manifest_binding_hash: &str,
        code_hash: &str,
        memory_plan: TargetMemoryPlan,
    ) -> Self {
        Self {
            id,
            package: package.to_string(),
            artifact_name: artifact_name.to_string(),
            role: role.to_string(),
            kind: TargetArtifactKind::TargetArtifactImageV1,
            target_profile: target_profile.to_string(),
            artifact_hash: artifact_hash.to_string(),
            abi_fingerprint: abi_fingerprint.to_string(),
            manifest_binding_hash: manifest_binding_hash.to_string(),
            code_hash: code_hash.to_string(),
            imports: Vec::new(),
            exports: Vec::new(),
            memory_plan,
            trap_metadata: Vec::new(),
            address_map: Vec::new(),
            capabilities: Vec::new(),
            hostcalls: Vec::new(),
            payload_len: 0,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "target-artifact id={} package={} artifact={} kind={} profile={} artifact_hash={} abi={} binding={} code_hash={} exports={} hostcalls={} caps={}",
            self.id,
            self.package,
            self.artifact_name,
            self.kind.as_str(),
            self.target_profile,
            self.artifact_hash,
            self.abi_fingerprint,
            self.manifest_binding_hash,
            self.code_hash,
            self.exports.len(),
            self.hostcalls.len(),
            self.capabilities.len()
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedArtifact {
    pub artifact_id: TargetArtifactId,
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub target_profile: String,
    pub artifact_hash: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    pub memory_plan: TargetMemoryPlan,
    pub trap_metadata: Vec<TargetTrapMetadata>,
    pub address_map: Vec<TargetAddressMapEntry>,
    pub capabilities: Vec<TargetCapabilitySpec>,
    pub hostcalls: Vec<HostcallSpec>,
    pub payload_len: usize,
    pub generation: Generation,
}

impl VerifiedArtifact {
    pub fn summary(&self) -> String {
        format!(
            "verified-artifact id={} package={} profile={} artifact_hash={} abi={} binding={} code_hash={} generation={}",
            self.artifact_id,
            self.package,
            self.target_profile,
            self.artifact_hash,
            self.abi_fingerprint,
            self.manifest_binding_hash,
            self.code_hash,
            self.generation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactRegistryError {
    EmptyIdentity,
    EmptyManifestBinding,
    EmptyArtifactHash,
    EmptyCodeHash,
    EmptyTargetProfile,
    EmptyAbiFingerprint,
    DuplicateArtifact,
    UnexpectedArtifact,
    TargetProfileMismatch,
    AbiFingerprintMismatch,
    ManifestBindingMismatch,
    ArtifactHashMismatch,
    CodeHashMismatch,
}

impl ArtifactRegistryError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::EmptyIdentity => "artifact identity is incomplete",
            Self::EmptyManifestBinding => "artifact manifest binding hash is empty",
            Self::EmptyArtifactHash => "artifact hash is empty",
            Self::EmptyCodeHash => "artifact code hash is empty",
            Self::EmptyTargetProfile => "artifact target profile is empty",
            Self::EmptyAbiFingerprint => "artifact ABI fingerprint is empty",
            Self::DuplicateArtifact => "artifact identity was already verified",
            Self::UnexpectedArtifact => "artifact is not present in expected manifest policy",
            Self::TargetProfileMismatch => "artifact target profile does not match expected policy",
            Self::AbiFingerprintMismatch => {
                "artifact ABI fingerprint does not match expected policy"
            }
            Self::ManifestBindingMismatch => {
                "artifact manifest binding hash does not match expected policy"
            }
            Self::ArtifactHashMismatch => "artifact hash does not match expected policy",
            Self::CodeHashMismatch => "artifact code hash does not match expected policy",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactRegistry {
    expected: Vec<ExpectedTargetArtifact>,
    verified: Vec<VerifiedArtifact>,
}

impl ArtifactRegistry {
    pub const fn new() -> Self {
        Self {
            expected: Vec::new(),
            verified: Vec::new(),
        }
    }

    pub fn with_expected(expected: Vec<ExpectedTargetArtifact>) -> Self {
        Self {
            expected,
            verified: Vec::new(),
        }
    }

    pub fn verify(
        &mut self,
        image: TargetArtifactImage,
    ) -> Result<VerifiedArtifact, ArtifactRegistryError> {
        if image.id == 0 || image.package.is_empty() || image.artifact_name.is_empty() {
            return Err(ArtifactRegistryError::EmptyIdentity);
        }
        if image.manifest_binding_hash.is_empty() {
            return Err(ArtifactRegistryError::EmptyManifestBinding);
        }
        if image.artifact_hash.is_empty() {
            return Err(ArtifactRegistryError::EmptyArtifactHash);
        }
        if image.code_hash.is_empty() {
            return Err(ArtifactRegistryError::EmptyCodeHash);
        }
        if image.target_profile.is_empty() {
            return Err(ArtifactRegistryError::EmptyTargetProfile);
        }
        if image.abi_fingerprint.is_empty() {
            return Err(ArtifactRegistryError::EmptyAbiFingerprint);
        }
        if self
            .verified
            .iter()
            .any(|verified| verified.artifact_id == image.id)
        {
            return Err(ArtifactRegistryError::DuplicateArtifact);
        }
        if !self.expected.is_empty() {
            let Some(expected) = self.expected.iter().find(|expected| {
                expected.package == image.package && expected.artifact_name == image.artifact_name
            }) else {
                return Err(ArtifactRegistryError::UnexpectedArtifact);
            };
            if expected.target_profile != image.target_profile {
                return Err(ArtifactRegistryError::TargetProfileMismatch);
            }
            if expected.abi_fingerprint != image.abi_fingerprint {
                return Err(ArtifactRegistryError::AbiFingerprintMismatch);
            }
            if expected.manifest_binding_hash != image.manifest_binding_hash {
                return Err(ArtifactRegistryError::ManifestBindingMismatch);
            }
            if expected.artifact_hash != image.artifact_hash {
                return Err(ArtifactRegistryError::ArtifactHashMismatch);
            }
            if expected.code_hash != image.code_hash {
                return Err(ArtifactRegistryError::CodeHashMismatch);
            }
        }
        let verified = VerifiedArtifact {
            artifact_id: image.id,
            package: image.package,
            artifact_name: image.artifact_name,
            role: image.role,
            target_profile: image.target_profile,
            artifact_hash: image.artifact_hash,
            abi_fingerprint: image.abi_fingerprint,
            manifest_binding_hash: image.manifest_binding_hash,
            code_hash: image.code_hash,
            memory_plan: image.memory_plan,
            trap_metadata: image.trap_metadata,
            address_map: image.address_map,
            capabilities: image.capabilities,
            hostcalls: image.hostcalls,
            payload_len: image.payload_len,
            generation: 1,
        };
        self.verified.push(verified.clone());
        Ok(verified)
    }

    pub fn verified(&self) -> &[VerifiedArtifact] {
        &self.verified
    }
}

impl Default for ArtifactRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeObjectState {
    AllocatedRw,
    Filled,
    Sealed,
    PublishedRx,
    BoundToStore,
    Faulted,
    Retired,
    Unpublished,
}

impl CodeObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllocatedRw => "allocated-rw",
            Self::Filled => "filled",
            Self::Sealed => "sealed",
            Self::PublishedRx => "published-rx",
            Self::BoundToStore => "bound-to-store",
            Self::Faulted => "faulted",
            Self::Retired => "retired",
            Self::Unpublished => "unpublished",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeObject {
    pub id: CodeObjectId,
    pub artifact_id: TargetArtifactId,
    pub package: String,
    pub owner_profile: String,
    pub generation: Generation,
    pub text: TargetAddressRange,
    pub rodata: TargetAddressRange,
    pub trap_metadata: Vec<TargetTrapMetadata>,
    pub address_map: Vec<TargetAddressMapEntry>,
    pub hostcall_table: Option<HostcallTableId>,
    pub hostcalls: Vec<HostcallSpec>,
    pub state: CodeObjectState,
    pub bound_store: Option<StoreId>,
    pub bound_store_generation: Option<Generation>,
    pub code_hash: String,
}

impl CodeObject {
    pub fn summary(&self) -> String {
        let store = self
            .bound_store
            .map(|store| {
                format!(
                    "{store}@{}",
                    self.bound_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                )
            })
            .unwrap_or_else(|| "none".to_string());
        let hostcall_table = self
            .hostcall_table
            .map(|table| table.to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "code-object id={} artifact={} package={} state={} generation={} store={} hostcall_table={} text={:#x}-{:#x} rodata={:#x}-{:#x}",
            self.id,
            self.artifact_id,
            self.package,
            self.state.as_str(),
            self.generation,
            store,
            hostcall_table,
            self.text.start,
            self.text.end(),
            self.rodata.start,
            self.rodata.end()
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodePublisherError {
    CodeObjectMissing,
    InvalidTransition,
    ArtifactNotVerified,
    StoreMissing,
}

impl CodePublisherError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::CodeObjectMissing => "code object is missing",
            Self::InvalidTransition => "invalid code object transition",
            Self::ArtifactNotVerified => "artifact is not verified",
            Self::StoreMissing => "store is missing",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CodePublisher {
    next_code_id: CodeObjectId,
    next_tombstone_event: EventId,
    objects: Vec<CodeObject>,
    tombstones: Vec<TombstoneRecord>,
}

impl CodePublisher {
    pub const fn new() -> Self {
        Self {
            next_code_id: 1,
            next_tombstone_event: 1,
            objects: Vec::new(),
            tombstones: Vec::new(),
        }
    }

    pub fn allocate(
        &mut self,
        artifact: &VerifiedArtifact,
    ) -> Result<CodeObjectId, CodePublisherError> {
        if artifact.generation == 0 {
            return Err(CodePublisherError::ArtifactNotVerified);
        }
        let id = self.next_code_id;
        self.next_code_id += 1;
        let base = 0x1000_0000 + id * 0x10_0000;
        self.objects.push(CodeObject {
            id,
            artifact_id: artifact.artifact_id,
            package: artifact.package.clone(),
            owner_profile: artifact.target_profile.clone(),
            generation: 1,
            text: TargetAddressRange::new(base, 0x8000, CodeRangePermission::ReadWrite),
            rodata: TargetAddressRange::new(base + 0x8000, 0x4000, CodeRangePermission::ReadOnly),
            trap_metadata: artifact.trap_metadata.clone(),
            address_map: artifact.address_map.clone(),
            hostcall_table: None,
            hostcalls: artifact.hostcalls.clone(),
            state: CodeObjectState::AllocatedRw,
            bound_store: None,
            bound_store_generation: None,
            code_hash: artifact.code_hash.clone(),
        });
        Ok(id)
    }

    pub fn fill(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        self.transition(id, CodeObjectState::AllocatedRw, CodeObjectState::Filled)
    }

    pub fn seal(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        self.transition(id, CodeObjectState::Filled, CodeObjectState::Sealed)
    }

    pub fn publish_rx(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if object.state != CodeObjectState::Sealed {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::PublishedRx;
        object.text.permission = CodeRangePermission::ReadExecute;
        object.generation += 1;
        Ok(())
    }

    pub fn bind_to_store(
        &mut self,
        id: CodeObjectId,
        store: &StoreRecord,
    ) -> Result<(), CodePublisherError> {
        if store.id == 0 {
            return Err(CodePublisherError::StoreMissing);
        }
        let object = self.object_mut(id)?;
        if object.state != CodeObjectState::PublishedRx {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::BoundToStore;
        object.bound_store = Some(store.id);
        object.bound_store_generation = Some(store.generation);
        object.hostcall_table = Some(1000 + id);
        object.generation += 1;
        Ok(())
    }

    pub fn fault(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if matches!(
            object.state,
            CodeObjectState::Retired | CodeObjectState::Unpublished
        ) {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::Faulted;
        object.generation += 1;
        let generation = object.generation;
        self.record_tombstone(
            ContractObjectKind::CodeObject,
            id,
            generation,
            "code-faulted",
        );
        Ok(())
    }

    pub fn retire(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if object.state == CodeObjectState::Unpublished {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::Retired;
        object.generation += 1;
        let generation = object.generation;
        self.record_tombstone(
            ContractObjectKind::CodeObject,
            id,
            generation,
            "code-retired",
        );
        Ok(())
    }

    pub fn unpublish(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if object.state != CodeObjectState::Retired {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::Unpublished;
        object.bound_store = None;
        object.bound_store_generation = None;
        object.hostcall_table = None;
        object.generation += 1;
        Ok(())
    }

    pub fn object(&self, id: CodeObjectId) -> Option<&CodeObject> {
        self.objects.iter().find(|object| object.id == id)
    }

    pub fn objects(&self) -> &[CodeObject] {
        &self.objects
    }

    pub fn tombstones(&self) -> &[TombstoneRecord] {
        &self.tombstones
    }

    fn transition(
        &mut self,
        id: CodeObjectId,
        from: CodeObjectState,
        to: CodeObjectState,
    ) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if object.state != from {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = to;
        object.generation += 1;
        Ok(())
    }

    pub fn object_mut(&mut self, id: CodeObjectId) -> Result<&mut CodeObject, CodePublisherError> {
        self.objects
            .iter_mut()
            .find(|object| object.id == id)
            .ok_or(CodePublisherError::CodeObjectMissing)
    }

    fn record_tombstone(
        &mut self,
        kind: ContractObjectKind,
        id: u64,
        generation: Generation,
        reason: &str,
    ) {
        let event = self.next_tombstone_event;
        self.next_tombstone_event += 1;
        self.tombstones
            .push(TombstoneRecord::new(kind, id, generation, event, reason));
    }

    pub fn record_current_tombstone(
        &mut self,
        id: CodeObjectId,
        reason: &str,
    ) -> Result<(), CodePublisherError> {
        let generation = self
            .object(id)
            .ok_or(CodePublisherError::CodeObjectMissing)?
            .generation;
        self.record_tombstone(ContractObjectKind::CodeObject, id, generation, reason);
        Ok(())
    }
}

impl Default for CodePublisher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedStoreRecord {
    pub store: StoreRecord,
    pub resource_arena: String,
    pub rebind_policy: String,
}

impl ManagedStoreRecord {
    pub fn summary(&self) -> String {
        format!(
            "store id={} package={} state={} generation={} domain={} arena={} rebind_policy={}",
            self.store.id,
            self.store.package,
            self.store.state.as_str(),
            self.store.generation,
            self.store.fault_domain,
            self.resource_arena,
            self.rebind_policy
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetStoreManagerError {
    StoreMissing,
    InvalidTransition,
}

impl TargetStoreManagerError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::StoreMissing => "store is missing",
            Self::InvalidTransition => "invalid store lifecycle transition",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TargetStoreManager {
    next_store_id: StoreId,
    next_tombstone_event: EventId,
    records: Vec<ManagedStoreRecord>,
    tombstones: Vec<TombstoneRecord>,
}

impl TargetStoreManager {
    pub const fn new() -> Self {
        Self {
            next_store_id: 1,
            next_tombstone_event: 1,
            records: Vec::new(),
            tombstones: Vec::new(),
        }
    }

    pub fn register_verified_artifact(
        &mut self,
        artifact: &VerifiedArtifact,
        fault_policy: &str,
        rebind_policy: &str,
    ) -> StoreId {
        let id = self.next_store_id;
        self.next_store_id += 1;
        self.register_verified_artifact_with_id(id, artifact, fault_policy, rebind_policy)
    }

    pub fn register_verified_artifact_with_id(
        &mut self,
        store_id: StoreId,
        artifact: &VerifiedArtifact,
        fault_policy: &str,
        rebind_policy: &str,
    ) -> StoreId {
        self.next_store_id = self.next_store_id.max(store_id + 1);
        self.records.push(ManagedStoreRecord {
            store: StoreRecord {
                id: store_id,
                package: artifact.package.clone(),
                artifact: artifact.artifact_name.clone(),
                role: artifact.role.clone(),
                fault_policy: fault_policy.to_string(),
                fault_domain: store_id,
                resource: None,
                state: StoreState::Instantiating,
                generation: 1,
                restart_count: 0,
            },
            resource_arena: format!("store-arena:{}", artifact.package),
            rebind_policy: rebind_policy.to_string(),
        });
        store_id
    }

    pub fn set_running(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        self.set_state(store, StoreState::Running)
    }

    pub fn begin_draining(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        self.set_state(store, StoreState::Draining)
    }

    pub fn drop_store(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        self.set_state(store, StoreState::Dead)?;
        let generation = self
            .record(store)
            .ok_or(TargetStoreManagerError::StoreMissing)?
            .store
            .generation;
        self.record_tombstone(ContractObjectKind::Store, store, generation, "store-dead");
        Ok(())
    }

    pub fn rebind_store(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        let record = self.record_mut(store)?;
        if !matches!(
            record.store.state,
            StoreState::Restarting | StoreState::Dead
        ) {
            return Err(TargetStoreManagerError::InvalidTransition);
        }
        record.store.state = StoreState::Rebinding;
        record.store.generation += 1;
        record.store.restart_count += 1;
        Ok(())
    }

    pub fn record(&self, store: StoreId) -> Option<&ManagedStoreRecord> {
        self.records.iter().find(|record| record.store.id == store)
    }

    pub fn records(&self) -> &[ManagedStoreRecord] {
        &self.records
    }

    pub fn tombstones(&self) -> &[TombstoneRecord] {
        &self.tombstones
    }

    fn set_state(
        &mut self,
        store: StoreId,
        state: StoreState,
    ) -> Result<(), TargetStoreManagerError> {
        let record = self.record_mut(store)?;
        record.store.state = state;
        record.store.generation += 1;
        Ok(())
    }

    pub fn record_mut(
        &mut self,
        store: StoreId,
    ) -> Result<&mut ManagedStoreRecord, TargetStoreManagerError> {
        self.records
            .iter_mut()
            .find(|record| record.store.id == store)
            .ok_or(TargetStoreManagerError::StoreMissing)
    }

    pub fn record_current_tombstone(
        &mut self,
        store: StoreId,
        reason: &str,
    ) -> Result<(), TargetStoreManagerError> {
        let generation = self
            .record(store)
            .ok_or(TargetStoreManagerError::StoreMissing)?
            .store
            .generation;
        self.record_tombstone(ContractObjectKind::Store, store, generation, reason);
        Ok(())
    }

    fn record_tombstone(
        &mut self,
        kind: ContractObjectKind,
        id: u64,
        generation: Generation,
        reason: &str,
    ) {
        let event = self.next_tombstone_event;
        self.next_tombstone_event += 1;
        self.tombstones
            .push(TombstoneRecord::new(kind, id, generation, event, reason));
    }
}

impl Default for TargetStoreManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationEntry {
    Symbol(String),
    Hostcall(u32),
}

impl ActivationEntry {
    pub fn summary(&self) -> String {
        match self {
            Self::Symbol(symbol) => format!("symbol:{symbol}"),
            Self::Hostcall(hostcall) => format!("hostcall:{hostcall}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationState {
    Running,
    Pending,
    Trapped,
    Returned,
    Dropped,
}

impl ActivationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Pending => "pending",
            Self::Trapped => "trapped",
            Self::Returned => "returned",
            Self::Dropped => "dropped",
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallReturnTag {
    Ok = 0,
    Errno = 1,
    Pending = 2,
    Trap = 3,
    KillStore = 4,
    RestartSyscall = 5,
    BadAbi = 6,
}

impl HostcallReturnTag {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Errno => "errno",
            Self::Pending => "pending",
            Self::Trap => "trap",
            Self::KillStore => "kill-store",
            Self::RestartSyscall => "restart-syscall",
            Self::BadAbi => "bad-abi",
        }
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::Errno),
            2 => Some(Self::Pending),
            3 => Some(Self::Trap),
            4 => Some(Self::KillStore),
            5 => Some(Self::RestartSyscall),
            6 => Some(Self::BadAbi),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordMode {
    Deterministic = 0,
    RecordInput = 1,
    RecordOutput = 2,
    RecordInputOutput = 3,
    ForbiddenDuringReplay = 4,
}

impl RecordMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::RecordInput => "record-input",
            Self::RecordOutput => "record-output",
            Self::RecordInputOutput => "record-input-output",
            Self::ForbiddenDuringReplay => "forbidden-during-replay",
        }
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Deterministic),
            1 => Some(Self::RecordInput),
            2 => Some(Self::RecordOutput),
            3 => Some(Self::RecordInputOutput),
            4 => Some(Self::ForbiddenDuringReplay),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationRecord {
    pub id: ActivationId,
    pub store: StoreId,
    pub store_generation: Generation,
    pub code_object: CodeObjectId,
    pub code_generation: Generation,
    pub artifact: TargetArtifactId,
    pub entry: ActivationEntry,
    pub generation: Generation,
    pub state: ActivationState,
    pub start_event: EventId,
    pub exit_event: Option<EventId>,
    pub active_dmw_leases: u32,
    pub blocked_wait: Option<WaitId>,
    pub trap: Option<TargetTrapId>,
    pub return_tag: Option<HostcallReturnTag>,
}

impl ActivationRecord {
    pub fn summary(&self) -> String {
        let exit = self
            .exit_event
            .map(|event| event.to_string())
            .unwrap_or_else(|| "none".to_string());
        let wait = self
            .blocked_wait
            .map(|wait| wait.to_string())
            .unwrap_or_else(|| "none".to_string());
        let trap = self
            .trap
            .map(|trap| trap.to_string())
            .unwrap_or_else(|| "none".to_string());
        let return_tag = self.return_tag.map(|tag| tag.as_str()).unwrap_or("none");
        format!(
            "activation id={} store={} store_generation={} code={} code_generation={} artifact={} entry={} state={} generation={} start={} exit={} dmw_leases={} wait={} trap={} return={}",
            self.id,
            self.store,
            self.store_generation,
            self.code_object,
            self.code_generation,
            self.artifact,
            self.entry.summary(),
            self.state.as_str(),
            self.generation,
            self.start_event,
            exit,
            self.active_dmw_leases,
            wait,
            trap,
            return_tag
        )
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireObjectRef {
    pub id: u64,
    pub generation: u64,
}

impl WireObjectRef {
    pub const NULL: Self = Self {
        id: 0,
        generation: 0,
    };

    pub const fn new(id: u64, generation: u64) -> Self {
        Self { id, generation }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArtifactRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodeObjectRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivationRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrapRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitTokenRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityRefV1(pub WireObjectRef);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutorCapabilityHandleV1 {
    pub owner_store: StoreRefV1,
    pub slot: u32,
    pub slot_generation: u32,
    pub tag: u64,
    pub rights_mask: u64,
    pub object_class: u16,
    pub reserved: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorHostcallFrameV1 {
    pub magic: u32,
    pub abi_version: u16,
    pub frame_size: u16,
    pub flags: u32,
    pub record_mode: u16,
    pub ret_tag: u16,
    pub activation: ActivationRefV1,
    pub store: StoreRefV1,
    pub code_object: CodeObjectRefV1,
    pub artifact: ArtifactRefV1,
    pub hostcall_number: u32,
    pub cap_arg_count: u16,
    pub reserved0: u16,
    pub hostcall_seq: u64,
    pub caller_offset: u64,
    pub args: [u64; 6],
    pub cap_args: [ExecutorCapabilityHandleV1; 4],
    pub ret0: u64,
    pub ret1: u64,
    pub trap_out: TrapRefV1,
    pub wait_token_out: WaitTokenRefV1,
}

impl ExecutorHostcallFrameV1 {
    pub const MAGIC: u32 = 0x564d_4843;
    pub const ABI_VERSION: u16 = 1;
    pub const FRAME_SIZE: u16 = core::mem::size_of::<Self>() as u16;
    pub const CAP_ARG_CAPACITY: usize = 4;

    pub const fn activation_id(&self) -> ActivationId {
        self.activation.0.id
    }

    pub const fn activation_generation(&self) -> Generation {
        self.activation.0.generation
    }

    pub const fn store_id(&self) -> StoreId {
        self.store.0.id
    }

    pub const fn store_generation(&self) -> Generation {
        self.store.0.generation
    }

    pub const fn code_object_id(&self) -> CodeObjectId {
        self.code_object.0.id
    }

    pub const fn code_generation(&self) -> Generation {
        self.code_object.0.generation
    }

    pub const fn artifact_id(&self) -> TargetArtifactId {
        self.artifact.0.id
    }

    pub const fn artifact_generation(&self) -> Generation {
        self.artifact.0.generation
    }
}

impl Default for ExecutorHostcallFrameV1 {
    fn default() -> Self {
        Self {
            magic: Self::MAGIC,
            abi_version: Self::ABI_VERSION,
            frame_size: Self::FRAME_SIZE,
            flags: 0,
            record_mode: RecordMode::Deterministic.as_u16(),
            ret_tag: HostcallReturnTag::Ok.as_u16(),
            activation: ActivationRefV1(WireObjectRef::NULL),
            store: StoreRefV1(WireObjectRef::NULL),
            code_object: CodeObjectRefV1(WireObjectRef::NULL),
            artifact: ArtifactRefV1(WireObjectRef::NULL),
            hostcall_number: 0,
            cap_arg_count: 0,
            reserved0: 0,
            hostcall_seq: 0,
            caller_offset: 0,
            args: [0; 6],
            cap_args: [ExecutorCapabilityHandleV1::default(); 4],
            ret0: 0,
            ret1: 0,
            trap_out: TrapRefV1(WireObjectRef::NULL),
            wait_token_out: WaitTokenRefV1(WireObjectRef::NULL),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetTrapClass {
    GuestTrap,
    SupervisorStoreTrap,
    CapabilityTrap,
    WindowTrap,
    HostcallTrap,
    CodeObjectTrap,
    SubstrateFault,
}

impl TargetTrapClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GuestTrap => "guest-trap",
            Self::SupervisorStoreTrap => "supervisor-store-trap",
            Self::CapabilityTrap => "capability-trap",
            Self::WindowTrap => "window-trap",
            Self::HostcallTrap => "hostcall-trap",
            Self::CodeObjectTrap => "code-object-trap",
            Self::SubstrateFault => "substrate-fault",
        }
    }

    pub const fn legacy_trap(self) -> TrapClass {
        match self {
            Self::GuestTrap => TrapClass::GuestIllegalInstruction,
            Self::SupervisorStoreTrap => TrapClass::ServiceTrap,
            Self::CapabilityTrap => TrapClass::CapabilityDenied,
            Self::WindowTrap => TrapClass::WindowViolationTrap,
            Self::HostcallTrap => TrapClass::ServiceTrap,
            Self::CodeObjectTrap => TrapClass::WasmBoundsTrap,
            Self::SubstrateFault => TrapClass::SubstrateFault,
        }
    }
}

fn trap_class_for_attribution(kind: TrapKindV1) -> TargetTrapClass {
    match kind {
        TrapKindV1::CapabilityDenied => TargetTrapClass::CapabilityTrap,
        TrapKindV1::WindowViolation => TargetTrapClass::WindowTrap,
        TrapKindV1::HostcallFault => TargetTrapClass::HostcallTrap,
        TrapKindV1::UnknownCodeFault | TrapKindV1::SubstrateFault => {
            TargetTrapClass::SubstrateFault
        }
        TrapKindV1::UnknownCodeTrap | TrapKindV1::StaleCodeExecutionFault => {
            TargetTrapClass::CodeObjectTrap
        }
        TrapKindV1::WasmBounds
        | TrapKindV1::WasmUnreachable
        | TrapKindV1::BadIndirectCall
        | TrapKindV1::IntegerDivByZero
        | TrapKindV1::StackOverflow => TargetTrapClass::GuestTrap,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetTrapRecord {
    pub id: TargetTrapId,
    pub generation: Generation,
    pub class: TargetTrapClass,
    pub store: Option<StoreId>,
    pub store_generation: Option<Generation>,
    pub activation: Option<ActivationId>,
    pub activation_generation: Option<Generation>,
    pub code_object: Option<CodeObjectId>,
    pub code_generation: Option<Generation>,
    pub artifact: Option<TargetArtifactId>,
    pub artifact_generation: Option<Generation>,
    pub offset: Option<u64>,
    pub target_pc: Option<u64>,
    pub trap_kind: Option<String>,
    pub function_index: Option<u32>,
    pub wasm_offset: Option<u64>,
    pub debug_symbol: Option<u32>,
    pub classification_status: Option<String>,
    pub hostcall: Option<String>,
    pub fault_policy: String,
    pub effect: FailureEffect,
    pub detail: String,
}

impl TargetTrapRecord {
    pub fn summary(&self) -> String {
        let store = self
            .store
            .map(|store| store.to_string())
            .unwrap_or_else(|| "none".to_string());
        let activation = self
            .activation
            .map(|activation| activation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let store_generation = self
            .store_generation
            .map(|generation| generation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let activation_generation = self
            .activation_generation
            .map(|generation| generation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let code = self
            .code_object
            .map(|code| code.to_string())
            .unwrap_or_else(|| "none".to_string());
        let artifact = self
            .artifact
            .map(|artifact| artifact.to_string())
            .unwrap_or_else(|| "none".to_string());
        let code_generation = self
            .code_generation
            .map(|generation| generation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let artifact_generation = self
            .artifact_generation
            .map(|generation| generation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let offset = self
            .offset
            .map(|offset| format!("{offset:#x}"))
            .unwrap_or_else(|| "none".to_string());
        let hostcall = self.hostcall.as_deref().unwrap_or("none");
        format!(
            "trap id={} generation={} class={} store={} store_generation={} activation={} activation_generation={} code={} code_generation={} artifact={} artifact_generation={} offset={} hostcall={} policy={} effect={} detail={}",
            self.id,
            self.generation,
            self.class.as_str(),
            store,
            store_generation,
            activation,
            activation_generation,
            code,
            code_generation,
            artifact,
            artifact_generation,
            offset,
            hostcall,
            self.fault_policy,
            self.effect.summary(),
            self.detail
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityHandleArg {
    pub id: CapabilityId,
    pub object: String,
    pub object_ref: Option<AuthorityObjectRef>,
    pub generation: Generation,
    pub owner_store: Option<StoreId>,
    pub owner_store_generation: Option<Generation>,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub class_hint: Option<CapabilityClass>,
    pub rights_mask: u64,
    pub rights: Vec<String>,
}

impl CapabilityHandleArg {
    pub fn new(
        id: CapabilityId,
        object: &str,
        generation: Generation,
        rights_mask: u64,
        rights: &[&str],
    ) -> Self {
        let class = CapabilityClass::from_object(object);
        Self {
            id,
            object: object.to_string(),
            object_ref: Some(AuthorityObjectRef::from_label(class, object)),
            generation,
            owner_store: None,
            owner_store_generation: None,
            handle_slot: 0,
            handle_generation: 0,
            handle_tag: 0,
            class_hint: Some(class),
            rights_mask,
            rights: rights.iter().map(|right| (*right).to_string()).collect(),
        }
    }

    pub fn capability_handle(&self) -> Option<CapabilityHandle> {
        Some(CapabilityHandle::new(
            self.owner_store?,
            self.owner_store_generation?,
            self.handle_slot,
            self.handle_generation,
            self.handle_tag,
            self.rights.clone(),
            self.class_hint?,
        ))
    }

    pub fn from_record(record: &CapabilityRecord, rights_mask: u64, rights: &[&str]) -> Self {
        Self {
            id: record.id,
            object: record.debug_object_label.clone(),
            object_ref: record.object_ref,
            generation: record.generation,
            owner_store: record.owner_store,
            owner_store_generation: record.owner_store_generation,
            handle_slot: record.handle_slot,
            handle_generation: record.handle_generation,
            handle_tag: record.handle_tag,
            class_hint: Some(record.class),
            rights_mask,
            rights: rights.iter().map(|right| (*right).to_string()).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostcallFrame {
    pub abi_version: String,
    pub frame_size: u16,
    pub flags: u32,
    pub activation: ActivationId,
    pub activation_generation: Generation,
    pub store: StoreId,
    pub store_generation: Generation,
    pub code_object: CodeObjectId,
    pub code_generation: Generation,
    pub artifact: TargetArtifactId,
    pub artifact_generation: Generation,
    pub hostcall_number: u32,
    pub hostcall_seq: u64,
    pub caller_offset: u64,
    pub subject: String,
    pub object: String,
    pub operation: String,
    pub generation: Generation,
    pub args: [u64; 6],
    pub cap_args: Vec<CapabilityHandleArg>,
    pub record_mode: RecordMode,
    pub ret_tag: HostcallReturnTag,
    pub ret0: u64,
    pub ret1: u64,
    pub trap_out: Option<TargetTrapId>,
    pub trap_generation_out: Option<Generation>,
    pub wait_token_out: Option<WaitId>,
    pub wait_token_generation_out: Option<Generation>,
}

impl HostcallFrame {
    pub const ABI_VERSION: &'static str = "vmos-target-hostcall-frame-v1";
    pub const FRAME_SIZE: u16 = ExecutorHostcallFrameV1::FRAME_SIZE;

    pub fn new(
        activation: ActivationId,
        store: StoreId,
        hostcall_number: u32,
        subject: &str,
        object: &str,
        operation: &str,
        generation: Generation,
    ) -> Self {
        Self {
            abi_version: Self::ABI_VERSION.to_string(),
            frame_size: Self::FRAME_SIZE,
            flags: 0,
            activation,
            activation_generation: 1,
            store,
            store_generation: 0,
            code_object: 0,
            code_generation: 0,
            artifact: 0,
            artifact_generation: 0,
            hostcall_number,
            hostcall_seq: 1,
            caller_offset: 0,
            subject: subject.to_string(),
            object: object.to_string(),
            operation: operation.to_string(),
            generation,
            args: [0; 6],
            cap_args: Vec::new(),
            record_mode: RecordMode::Deterministic,
            ret_tag: HostcallReturnTag::Ok,
            ret0: 0,
            ret1: 0,
            trap_out: None,
            trap_generation_out: None,
            wait_token_out: None,
            wait_token_generation_out: None,
        }
    }

    pub fn new_bound(
        activation: ActivationId,
        store: &StoreRecord,
        code: &CodeObject,
        hostcall_number: u32,
        object: &str,
        operation: &str,
        generation: Generation,
    ) -> Self {
        let mut frame = Self::new(
            activation,
            store.id,
            hostcall_number,
            &code.package,
            object,
            operation,
            generation,
        );
        frame.store_generation = store.generation;
        frame.code_object = code.id;
        frame.code_generation = code.generation;
        frame.artifact = code.artifact_id;
        frame.artifact_generation = TARGET_ARTIFACT_GENERATION_V1;
        frame
    }

    pub fn with_args(mut self, args: [u64; 6]) -> Self {
        self.args = args;
        self
    }

    pub fn with_hostcall_seq(mut self, hostcall_seq: u64) -> Self {
        self.hostcall_seq = hostcall_seq;
        self
    }

    pub fn with_caller_offset(mut self, caller_offset: u64) -> Self {
        self.caller_offset = caller_offset;
        self
    }

    pub fn with_record_mode(mut self, record_mode: RecordMode) -> Self {
        self.record_mode = record_mode;
        self
    }

    pub fn with_cap_args(mut self, cap_args: Vec<CapabilityHandleArg>) -> Self {
        self.cap_args = cap_args;
        self
    }

    pub fn to_wire_frame(&self) -> ExecutorHostcallFrameV1 {
        let mut frame = ExecutorHostcallFrameV1 {
            flags: self.flags,
            record_mode: self.record_mode.as_u16(),
            ret_tag: self.ret_tag.as_u16(),
            activation: ActivationRefV1(WireObjectRef::new(
                self.activation,
                self.activation_generation,
            )),
            store: StoreRefV1(WireObjectRef::new(self.store, self.store_generation)),
            code_object: CodeObjectRefV1(WireObjectRef::new(
                self.code_object,
                self.code_generation,
            )),
            artifact: ArtifactRefV1(WireObjectRef::new(self.artifact, self.artifact_generation)),
            hostcall_number: self.hostcall_number,
            hostcall_seq: self.hostcall_seq,
            caller_offset: self.caller_offset,
            args: self.args,
            ret0: self.ret0,
            ret1: self.ret1,
            trap_out: self
                .trap_out
                .map_or(TrapRefV1(WireObjectRef::NULL), |trap| {
                    TrapRefV1(WireObjectRef::new(
                        trap,
                        self.trap_generation_out.unwrap_or(1),
                    ))
                }),
            wait_token_out: self.wait_token_out.map_or(
                WaitTokenRefV1(WireObjectRef::NULL),
                |wait| {
                    WaitTokenRefV1(WireObjectRef::new(
                        wait,
                        self.wait_token_generation_out.unwrap_or(1),
                    ))
                },
            ),
            ..ExecutorHostcallFrameV1::default()
        };
        frame.cap_arg_count = self
            .cap_args
            .len()
            .min(ExecutorHostcallFrameV1::CAP_ARG_CAPACITY) as u16;
        for (slot, arg) in self
            .cap_args
            .iter()
            .take(ExecutorHostcallFrameV1::CAP_ARG_CAPACITY)
            .enumerate()
        {
            frame.cap_args[slot] = ExecutorCapabilityHandleV1 {
                owner_store: StoreRefV1(WireObjectRef::new(
                    arg.owner_store.unwrap_or(0),
                    arg.owner_store_generation.unwrap_or(0),
                )),
                slot: arg.handle_slot,
                slot_generation: arg.handle_generation,
                tag: arg.handle_tag,
                rights_mask: arg.rights_mask,
                object_class: CapabilityClass::from_object(&arg.object).as_u16(),
                reserved: [0; 3],
            };
        }
        frame
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostcallTraceRecord {
    pub id: HostcallTraceId,
    pub generation: Generation,
    pub abi_version: String,
    pub frame_size: u16,
    pub flags: u32,
    pub activation: ActivationId,
    pub activation_generation: Generation,
    pub store: StoreId,
    pub store_generation: Generation,
    pub code_object: CodeObjectId,
    pub code_generation: Generation,
    pub artifact: TargetArtifactId,
    pub artifact_generation: Generation,
    pub hostcall_number: u32,
    pub hostcall_seq: u64,
    pub caller_offset: u64,
    pub name: String,
    pub category: HostcallCategory,
    pub subject: String,
    pub object: String,
    pub operation: String,
    pub args: [u64; 6],
    pub cap_args: Vec<CapabilityHandleArg>,
    pub record_mode: RecordMode,
    pub allowed: bool,
    pub result: String,
    pub ret_tag: HostcallReturnTag,
    pub ret0: u64,
    pub ret1: u64,
    pub trap_out: Option<TargetTrapId>,
    pub trap_generation_out: Option<Generation>,
    pub wait_token_out: Option<WaitId>,
    pub wait_token_generation_out: Option<Generation>,
}

impl HostcallTraceRecord {
    pub fn summary(&self) -> String {
        format!(
            "hostcall id={} generation={} abi={} frame_size={} seq={} caller_offset={} record_mode={} activation={} activation_generation={} store={} store_generation={} code={} code_generation={} artifact={} artifact_generation={} number={} name={} category={} subject={} object={} op={} allowed={} result={} ret={}",
            self.id,
            self.generation,
            self.abi_version,
            self.frame_size,
            self.hostcall_seq,
            self.caller_offset,
            self.record_mode.as_str(),
            self.activation,
            self.activation_generation,
            self.store,
            self.store_generation,
            self.code_object,
            self.code_generation,
            self.artifact,
            self.artifact_generation,
            self.hostcall_number,
            self.name,
            self.category.as_str(),
            self.subject,
            self.object,
            self.operation,
            self.allowed,
            self.result,
            self.ret_tag.as_str()
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationObjectClass {
    Migrated,
    Rebuilt,
    NeverMigrated,
}

impl MigrationObjectClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Migrated => "migrated",
            Self::Rebuilt => "rebuilt",
            Self::NeverMigrated => "never-migrated",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationObjectRecord {
    pub object: String,
    pub class: MigrationObjectClass,
    pub reason: String,
}

impl MigrationObjectRecord {
    pub fn new(object: &str, class: MigrationObjectClass, reason: &str) -> Self {
        Self {
            object: object.to_string(),
            class,
            reason: reason.to_string(),
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "migration-object object={} class={} reason={}",
            self.object,
            self.class.as_str(),
            self.reason
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmwLeaseRecord {
    pub id: DmwLeaseId,
    pub activation: ActivationId,
    pub handle: String,
    pub generation: Generation,
    pub active: bool,
}

impl DmwLeaseRecord {
    pub fn summary(&self) -> String {
        format!(
            "dmw-lease id={} activation={} handle={} generation={} active={}",
            self.id, self.activation, self.handle, self.generation, self.active
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupStep {
    StopNewActivation,
    SealActivation,
    PreventHostcalls,
    ReleaseDmwLeases,
    CancelWaitTokens,
    RevokeCapabilities,
    DropResourceArena,
    UnbindCodeObject,
    MarkStoreState,
    RecordTransition,
    EmitTombstones,
    RecordFailureEffect,
    EmitReport,
}

impl CleanupStep {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StopNewActivation => "stop-new-activation",
            Self::SealActivation => "seal-activation",
            Self::PreventHostcalls => "prevent-hostcalls",
            Self::ReleaseDmwLeases => "release-dmw-leases",
            Self::CancelWaitTokens => "cancel-wait-tokens",
            Self::RevokeCapabilities => "revoke-capabilities",
            Self::DropResourceArena => "drop-resource-arena",
            Self::UnbindCodeObject => "unbind-code-object",
            Self::MarkStoreState => "mark-store-state",
            Self::RecordTransition => "record-transition",
            Self::EmitTombstones => "emit-tombstones",
            Self::RecordFailureEffect => "record-failure-effect",
            Self::EmitReport => "emit-report",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupStepState {
    NotStarted,
    Done,
    SkippedStaleGeneration,
    FailedRecoverable,
    FailedFatal,
}

impl CleanupStepState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not-started",
            Self::Done => "done",
            Self::SkippedStaleGeneration => "skipped-stale-generation",
            Self::FailedRecoverable => "failed-recoverable",
            Self::FailedFatal => "failed-fatal",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupStepRecord {
    pub step: CleanupStep,
    pub target: Option<ContractObjectRef>,
    pub observed_generation: Option<Generation>,
    pub state: CleanupStepState,
    pub detail: String,
    pub error: Option<String>,
    pub idempotency_key: String,
    pub event_seq: EventId,
}

impl CleanupStepRecord {
    pub fn done(step: CleanupStep, detail: &str) -> Self {
        Self {
            step,
            target: None,
            observed_generation: None,
            state: CleanupStepState::Done,
            detail: detail.to_string(),
            error: None,
            idempotency_key: step.as_str().to_string(),
            event_seq: 0,
        }
    }

    pub fn pending(step: CleanupStep) -> Self {
        Self {
            step,
            target: None,
            observed_generation: None,
            state: CleanupStepState::NotStarted,
            detail: String::new(),
            error: None,
            idempotency_key: step.as_str().to_string(),
            event_seq: 0,
        }
    }

    pub fn skipped_stale_generation(
        step: CleanupStep,
        target: ContractObjectRef,
        observed_generation: Generation,
        event_seq: EventId,
    ) -> Self {
        Self {
            step,
            target: Some(target),
            observed_generation: Some(observed_generation),
            state: CleanupStepState::SkippedStaleGeneration,
            detail: "stale generation did not mutate newer object".to_string(),
            error: Some("stale-generation".to_string()),
            idempotency_key: step.as_str().to_string(),
            event_seq,
        }
    }

    pub fn with_target(mut self, target: ContractObjectRef) -> Self {
        self.target = Some(target);
        self
    }

    pub fn with_observed_generation(mut self, generation: Generation) -> Self {
        self.observed_generation = Some(generation);
        self
    }

    pub fn with_event_seq(mut self, event_seq: EventId) -> Self {
        self.event_seq = event_seq;
        self
    }

    pub fn summary(&self) -> String {
        let target = self
            .target
            .map(ContractObjectRef::summary)
            .unwrap_or_else(|| "none".to_string());
        let observed = self
            .observed_generation
            .map(|generation| generation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let error = self.error.clone().unwrap_or_else(|| "none".to_string());
        format!(
            "{}:{}:{}:target={}:observed={}:error={}:event={}:key={}",
            self.step.as_str(),
            self.state.as_str(),
            self.detail,
            target,
            observed,
            error,
            self.event_seq,
            self.idempotency_key
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupTransactionState {
    Pending,
    Completed,
    SkippedStaleGeneration,
}

impl CleanupTransactionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::SkippedStaleGeneration => "skipped-stale-generation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupEffectKind {
    StopNewActivation,
    SealActivation,
    ReleaseLeases,
    CancelWaits,
    RevokeCapability,
    DropResources,
    UnbindCode,
    MarkStoreDead,
    EmitTombstone,
    RecordFailureEffect,
}

impl CleanupEffectKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StopNewActivation => "stop-new-activation",
            Self::SealActivation => "seal-activation",
            Self::ReleaseLeases => "release-leases",
            Self::CancelWaits => "cancel-waits",
            Self::RevokeCapability => "revoke-capability",
            Self::DropResources => "drop-resources",
            Self::UnbindCode => "unbind-code",
            Self::MarkStoreDead => "mark-store-dead",
            Self::EmitTombstone => "emit-tombstone",
            Self::RecordFailureEffect => "record-failure-effect",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupEffectStatus {
    Applied,
    AlreadyApplied,
    SkippedStaleGeneration,
}

impl CleanupEffectStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::AlreadyApplied => "already-applied",
            Self::SkippedStaleGeneration => "skipped-stale-generation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupEffectRecord {
    pub kind: CleanupEffectKind,
    pub target: ContractObjectRef,
    pub expected_generation: Generation,
    pub status: CleanupEffectStatus,
    pub event_seq: EventId,
}

impl CleanupEffectRecord {
    pub const fn new(
        kind: CleanupEffectKind,
        target: ContractObjectRef,
        expected_generation: Generation,
        status: CleanupEffectStatus,
        event_seq: EventId,
    ) -> Self {
        Self {
            kind,
            target,
            expected_generation,
            status,
            event_seq,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "{}:{}:{}@{}:event={}",
            self.kind.as_str(),
            self.status.as_str(),
            self.target.summary(),
            self.expected_generation,
            self.event_seq
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultCleanupTransaction {
    pub id: CleanupTransactionId,
    pub store: StoreId,
    pub store_generation: Generation,
    pub result_store_generation: Option<Generation>,
    pub activation: Option<ActivationId>,
    pub activation_generation: Option<Generation>,
    pub code_object: Option<CodeObjectId>,
    pub code_generation: Option<Generation>,
    pub generation: Generation,
    pub started_at: EventId,
    pub finished_at: Option<EventId>,
    pub state: CleanupTransactionState,
    pub reason: String,
    pub steps: Vec<CleanupStepRecord>,
    pub effects: Vec<CleanupEffectRecord>,
    pub released_dmw_leases: u32,
    pub cancelled_waits: u32,
    pub revoked_capabilities: Vec<CapabilityId>,
    pub revoked_capability_refs: Vec<ContractObjectRef>,
    pub dropped_resources: u32,
    pub unbound_code_object: bool,
    pub effect: FailureEffect,
}

impl FaultCleanupTransaction {
    pub fn summary(&self) -> String {
        format!(
            "cleanup id={} target_store={}@{} result_store_generation={} activation={} code={} generation={} started={} finished={} state={} reason={} released_dmw={} cancelled_waits={} revoked_caps={} dropped_resources={} unbound_code={} effect={} steps={} effects={}",
            self.id,
            self.store,
            self.store_generation,
            self.result_store_generation
                .map(|generation| generation.to_string())
                .unwrap_or_else(|| "none".to_string()),
            self.activation
                .zip(self.activation_generation)
                .map(|(activation, generation)| format!("{activation}@{generation}"))
                .unwrap_or_else(|| "none".to_string()),
            self.code_object
                .zip(self.code_generation)
                .map(|(code, generation)| format!("{code}@{generation}"))
                .unwrap_or_else(|| "none".to_string()),
            self.generation,
            self.started_at,
            self.finished_at
                .map(|event| event.to_string())
                .unwrap_or_else(|| "none".to_string()),
            self.state.as_str(),
            self.reason,
            self.released_dmw_leases,
            self.cancelled_waits,
            self.revoked_capabilities.len(),
            self.dropped_resources,
            self.unbound_code_object,
            self.effect.summary(),
            self.steps
                .iter()
                .map(CleanupStepRecord::summary)
                .collect::<Vec<_>>()
                .join("|"),
            self.effects
                .iter()
                .map(CleanupEffectRecord::summary)
                .collect::<Vec<_>>()
                .join("|")
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetExecutorError {
    StoreNotRunning,
    CodeObjectNotBound,
    ActivationMissing,
    ActivationNotRunning,
    ActivationStoreMismatch,
    CodeObjectMismatch,
    HostcallFrameMismatch,
    HostcallSubjectMismatch,
    HostcallAbiMismatch,
    HostcallNotDeclared,
    CapabilityDenied,
    DmwLeaseActive,
    DmwLeaseMissing,
    PendingCleanupActive,
    CleanupTransactionMissing,
    CleanupStoreMismatch,
}

impl TargetExecutorError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::StoreNotRunning => "store is not running",
            Self::CodeObjectNotBound => "code object is not bound to the store",
            Self::ActivationMissing => "activation is missing",
            Self::ActivationNotRunning => "activation is not running",
            Self::ActivationStoreMismatch => "activation/store mismatch",
            Self::CodeObjectMismatch => "activation/code object attribution mismatch",
            Self::HostcallFrameMismatch => "hostcall frame does not match declared hostcall",
            Self::HostcallSubjectMismatch => "hostcall subject does not match code object package",
            Self::HostcallAbiMismatch => "hostcall frame ABI version mismatch",
            Self::HostcallNotDeclared => "hostcall is not declared by code object",
            Self::CapabilityDenied => "hostcall capability gate denied access",
            Self::DmwLeaseActive => "active DMW lease cannot cross exit boundary",
            Self::DmwLeaseMissing => "DMW lease is missing",
            Self::PendingCleanupActive => "pending cleanup transaction blocks this boundary",
            Self::CleanupTransactionMissing => "cleanup transaction is missing",
            Self::CleanupStoreMismatch => "cleanup transaction targets a different store",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TargetExecutor {
    next_activation_id: ActivationId,
    next_trap_id: TargetTrapId,
    next_hostcall_trace_id: HostcallTraceId,
    next_cleanup_id: CleanupTransactionId,
    next_lease_id: DmwLeaseId,
    next_event_id: EventId,
    activations: Vec<ActivationRecord>,
    traps: Vec<TargetTrapRecord>,
    dmw_leases: Vec<DmwLeaseRecord>,
    hostcall_trace: Vec<HostcallTraceRecord>,
    cleanup_transactions: Vec<FaultCleanupTransaction>,
    tombstones: Vec<TombstoneRecord>,
    event_log: Vec<String>,
}

impl TargetExecutor {
    pub const fn new() -> Self {
        Self {
            next_activation_id: 1,
            next_trap_id: 1,
            next_hostcall_trace_id: 1,
            next_cleanup_id: 1,
            next_lease_id: 1,
            next_event_id: 1,
            activations: Vec::new(),
            traps: Vec::new(),
            dmw_leases: Vec::new(),
            hostcall_trace: Vec::new(),
            cleanup_transactions: Vec::new(),
            tombstones: Vec::new(),
            event_log: Vec::new(),
        }
    }

    pub fn start_activation(
        &mut self,
        store: &StoreRecord,
        code: &CodeObject,
        entry: ActivationEntry,
    ) -> Result<ActivationId, TargetExecutorError> {
        if store.state != StoreState::Running {
            return Err(TargetExecutorError::StoreNotRunning);
        }
        if code.state != CodeObjectState::BoundToStore
            || code.bound_store != Some(store.id)
            || code.bound_store_generation != Some(store.generation)
        {
            return Err(TargetExecutorError::CodeObjectNotBound);
        }
        let id = self.next_activation_id;
        self.next_activation_id += 1;
        let start_event = self.next_event("activation-started");
        self.activations.push(ActivationRecord {
            id,
            store: store.id,
            store_generation: store.generation,
            code_object: code.id,
            code_generation: code.generation,
            artifact: code.artifact_id,
            entry,
            generation: 1,
            state: ActivationState::Running,
            start_event,
            exit_event: None,
            active_dmw_leases: 0,
            blocked_wait: None,
            trap: None,
            return_tag: None,
        });
        Ok(id)
    }

    fn bad_abi_reason(frame: &ExecutorHostcallFrameV1) -> Option<&'static str> {
        if frame.magic != ExecutorHostcallFrameV1::MAGIC {
            Some("bad-hostcall-magic")
        } else if frame.abi_version != ExecutorHostcallFrameV1::ABI_VERSION {
            Some("bad-hostcall-abi")
        } else if frame.frame_size != ExecutorHostcallFrameV1::FRAME_SIZE {
            Some("bad-frame-size")
        } else if frame.cap_arg_count as usize > ExecutorHostcallFrameV1::CAP_ARG_CAPACITY {
            Some("bad-cap-arg-count")
        } else if RecordMode::from_u16(frame.record_mode).is_none() {
            Some("bad-record-mode")
        } else if HostcallReturnTag::from_u16(frame.ret_tag).is_none() {
            Some("bad-return-tag")
        } else {
            None
        }
    }

    fn semantic_frame_from_wire(
        wire: &ExecutorHostcallFrameV1,
        code: &CodeObject,
        spec: &HostcallSpec,
        capabilities: &CapabilityLedger,
    ) -> (HostcallFrame, Option<&'static str>) {
        let (cap_args, cap_arg_decode_error) = Self::decode_capability_handles(wire, capabilities);
        let authority_object = AuthorityObjectRef::from_label(
            CapabilityClass::from_object(&spec.object),
            &spec.object,
        );
        let generation = cap_args
            .iter()
            .find(|arg| arg.object_ref == Some(authority_object))
            .map(|arg| arg.generation)
            .or_else(|| capabilities.generation_of_authority(&code.package, authority_object))
            .unwrap_or(0);
        (
            HostcallFrame {
                abi_version: if wire.abi_version == ExecutorHostcallFrameV1::ABI_VERSION {
                    HostcallFrame::ABI_VERSION.to_string()
                } else {
                    format!("wire-v{}", wire.abi_version)
                },
                frame_size: wire.frame_size,
                flags: wire.flags,
                activation: wire.activation_id(),
                activation_generation: wire.activation_generation(),
                store: wire.store_id(),
                store_generation: wire.store_generation(),
                code_object: wire.code_object_id(),
                code_generation: wire.code_generation(),
                artifact: wire.artifact_id(),
                artifact_generation: wire.artifact_generation(),
                hostcall_number: wire.hostcall_number,
                hostcall_seq: wire.hostcall_seq,
                caller_offset: wire.caller_offset,
                subject: code.package.clone(),
                object: spec.object.clone(),
                operation: spec.operation.clone(),
                generation,
                args: wire.args,
                cap_args,
                record_mode: RecordMode::from_u16(wire.record_mode)
                    .unwrap_or(RecordMode::Deterministic),
                ret_tag: HostcallReturnTag::from_u16(wire.ret_tag).unwrap_or(HostcallReturnTag::Ok),
                ret0: wire.ret0,
                ret1: wire.ret1,
                trap_out: (wire.trap_out.0.id != 0).then_some(wire.trap_out.0.id),
                trap_generation_out: (wire.trap_out.0.id != 0)
                    .then_some(wire.trap_out.0.generation),
                wait_token_out: (wire.wait_token_out.0.id != 0).then_some(wire.wait_token_out.0.id),
                wait_token_generation_out: (wire.wait_token_out.0.id != 0)
                    .then_some(wire.wait_token_out.0.generation),
            },
            cap_arg_decode_error,
        )
    }

    fn decode_capability_handles(
        wire: &ExecutorHostcallFrameV1,
        capabilities: &CapabilityLedger,
    ) -> (Vec<CapabilityHandleArg>, Option<&'static str>) {
        let mut args = Vec::new();
        let mut decode_error = None;
        for handle in wire.cap_args.iter().take(wire.cap_arg_count as usize) {
            let owner_store = handle.owner_store.0.id;
            let owner_store_generation = handle.owner_store.0.generation;
            let Some(record) = capabilities.records().iter().find(|record| {
                record.owner_store == Some(owner_store)
                    && record.owner_store_generation == Some(owner_store_generation)
                    && record.handle_slot == handle.slot
                    && !record.revoked
            }) else {
                decode_error.get_or_insert("cap-arg-missing");
                args.push(CapabilityHandleArg {
                    id: 0,
                    object: "<missing-capability>".to_string(),
                    object_ref: None,
                    generation: 0,
                    owner_store: Some(owner_store),
                    owner_store_generation: Some(owner_store_generation),
                    handle_slot: handle.slot,
                    handle_generation: handle.slot_generation,
                    handle_tag: handle.tag,
                    class_hint: CapabilityClass::from_u16(handle.object_class),
                    rights_mask: handle.rights_mask,
                    rights: Vec::new(),
                });
                continue;
            };
            if record.handle_generation != handle.slot_generation {
                decode_error.get_or_insert("cap-arg-generation");
            }
            if record.handle_tag != handle.tag {
                decode_error.get_or_insert("cap-arg-tag");
            }
            match CapabilityClass::from_u16(handle.object_class) {
                Some(class) if class == record.class => {}
                Some(_) => {
                    decode_error.get_or_insert("cap-arg-object-class");
                }
                None => {
                    decode_error.get_or_insert("cap-arg-object-class");
                }
            }
            let rights = match Self::capability_rights_from_mask(record, handle.rights_mask) {
                Some(rights) => rights,
                None => {
                    decode_error.get_or_insert("cap-arg-rights-mask");
                    Vec::new()
                }
            };
            args.push(CapabilityHandleArg {
                id: record.id,
                object: record.object.clone(),
                object_ref: record.object_ref,
                generation: record.generation,
                owner_store: record.owner_store,
                owner_store_generation: record.owner_store_generation,
                handle_slot: handle.slot,
                handle_generation: handle.slot_generation,
                handle_tag: handle.tag,
                class_hint: CapabilityClass::from_u16(handle.object_class),
                rights_mask: handle.rights_mask,
                rights,
            });
        }
        (args, decode_error)
    }

    pub fn invoke_hostcall(
        &mut self,
        code: &CodeObject,
        wire_frame: ExecutorHostcallFrameV1,
        capabilities: &CapabilityLedger,
    ) -> Result<(), TargetExecutorError> {
        let bad_abi = Self::bad_abi_reason(&wire_frame);
        if let Some(reason) = bad_abi {
            self.event_log.push(format!(
                "HostcallAbiMismatch activation={} reason={} abi={} expected={} frame_size={} expected_frame_size={}",
                wire_frame.activation_id(),
                reason,
                wire_frame.abi_version,
                ExecutorHostcallFrameV1::ABI_VERSION,
                wire_frame.frame_size,
                ExecutorHostcallFrameV1::FRAME_SIZE
            ));
        }
        let activation_index = self.activation_index(wire_frame.activation_id())?;
        let activation = self.activations[activation_index].clone();
        if activation.state != ActivationState::Running {
            return Err(TargetExecutorError::ActivationNotRunning);
        }
        if activation.store != wire_frame.store_id()
            || activation.store_generation != wire_frame.store_generation()
            || activation.generation != wire_frame.activation_generation()
        {
            return Err(TargetExecutorError::ActivationStoreMismatch);
        }
        if activation.code_object != code.id
            || activation.code_generation != code.generation
            || activation.artifact != code.artifact_id
            || wire_frame.code_object_id() != code.id
            || wire_frame.code_generation() != code.generation
            || wire_frame.artifact_id() != code.artifact_id
            || wire_frame.artifact_generation() != TARGET_ARTIFACT_GENERATION_V1
            || code.bound_store != Some(wire_frame.store_id())
            || code.bound_store_generation != Some(wire_frame.store_generation())
        {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::CodeObjectTrap,
                Some(code),
                Some(format!("hostcall#{}", wire_frame.hostcall_number)),
                "attribution-failure",
                FailureEffect::CompleteWithErrno(5),
                "hostcall wire frame did not match activation code object attribution",
            );
            return Err(TargetExecutorError::CodeObjectMismatch);
        }
        let derived_subject = code.package.as_str();
        if let Some(reason) = bad_abi {
            let spec = code
                .hostcalls
                .iter()
                .find(|spec| spec.number == wire_frame.hostcall_number)
                .cloned()
                .unwrap_or_else(|| {
                    HostcallSpec::new(
                        wire_frame.hostcall_number,
                        "hostcall.bad-abi",
                        HostcallCategory::Service,
                        "hostcall.bad-abi",
                        "decode",
                        false,
                    )
                });
            let (frame, _) = Self::semantic_frame_from_wire(&wire_frame, code, &spec, capabilities);
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::HostcallTrap,
                Some(code),
                Some(spec.name.clone()),
                reason,
                FailureEffect::CompleteWithErrno(22),
                "hostcall frame ABI version mismatch",
            );
            self.record_trace(
                &frame,
                &spec,
                false,
                reason,
                HostcallReturnTag::BadAbi,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::HostcallAbiMismatch);
        }
        let Some(spec) = code
            .hostcalls
            .iter()
            .find(|spec| spec.number == wire_frame.hostcall_number)
        else {
            let placeholder = HostcallSpec::new(
                wire_frame.hostcall_number,
                "hostcall.undeclared",
                HostcallCategory::Service,
                "hostcall.undeclared",
                "decode",
                false,
            );
            let (frame, _) =
                Self::semantic_frame_from_wire(&wire_frame, code, &placeholder, capabilities);
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::HostcallTrap,
                Some(code),
                Some(format!("hostcall#{}", wire_frame.hostcall_number)),
                "restart",
                FailureEffect::CompleteWithErrno(38),
                "hostcall not declared by artifact",
            );
            self.record_trace(
                &frame,
                &placeholder,
                false,
                "undeclared",
                HostcallReturnTag::BadAbi,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::HostcallNotDeclared);
        };
        let (frame, cap_arg_decode_error) =
            Self::semantic_frame_from_wire(&wire_frame, code, spec, capabilities);
        self.event_log.push(format!(
            "HostcallEntered activation={} name={} category={} subject={} object={} op={}",
            frame.activation,
            spec.name,
            spec.category.as_str(),
            derived_subject,
            frame.object,
            frame.operation
        ));
        let initial_authority_object = AuthorityObjectRef::from_label(
            CapabilityClass::from_object(&frame.object),
            &frame.object,
        );
        let declared_capability = capabilities
            .generation_of_authority(derived_subject, initial_authority_object)
            .is_some();
        let authority =
            match AuthorityMatrix::check(&frame.object, &frame.operation, declared_capability) {
                Ok(authority) => authority,
                Err(reason) => {
                    self.event_log.push(format!(
                        "AuthorityDenied activation={} subject={} object={} op={} reason={}",
                        frame.activation,
                        derived_subject,
                        frame.object,
                        frame.operation,
                        reason.as_str()
                    ));
                    let trap = self.record_trap_for_activation(
                        activation_index,
                        TargetTrapClass::CapabilityTrap,
                        Some(code),
                        Some(spec.name.clone()),
                        "authority-matrix",
                        FailureEffect::CompleteWithErrno(1),
                        "hostcall authority matrix rejected object/operation",
                    );
                    self.record_trace(
                        &frame,
                        spec,
                        false,
                        reason.as_str(),
                        HostcallReturnTag::Trap,
                        Some(trap),
                        None,
                    );
                    return Err(TargetExecutorError::CapabilityDenied);
                }
            };
        let required_right = authority
            .required_right
            .as_deref()
            .unwrap_or(&frame.operation);
        let authority_object = AuthorityObjectRef::from_label(authority.class, &frame.object);
        if authority.requires_capability {
            if let Some(reason) = cap_arg_decode_error.or_else(|| {
                Self::cap_arg_denial_reason(
                    &frame,
                    derived_subject,
                    authority_object,
                    required_right,
                    capabilities,
                )
            }) {
                self.event_log.push(format!(
                    "CapabilityDenied activation={} subject={} object={} op={} required_right={} reason={reason}",
                    frame.activation, derived_subject, frame.object, frame.operation, required_right
                ));
                let (class, ret_tag, policy, detail) =
                    if matches!(reason, "cap-arg-empty-rights" | "cap-arg-rights-mask") {
                        (
                            TargetTrapClass::HostcallTrap,
                            HostcallReturnTag::BadAbi,
                            "bad-capability-argument",
                            "hostcall capability handle argument was malformed",
                        )
                    } else {
                        (
                            TargetTrapClass::CapabilityTrap,
                            HostcallReturnTag::Trap,
                            "capability-handle",
                            "hostcall capability handle argument failed validation",
                        )
                    };
                let trap = self.record_trap_for_activation(
                    activation_index,
                    class,
                    Some(code),
                    Some(spec.name.clone()),
                    policy,
                    FailureEffect::CompleteWithErrno(1),
                    detail,
                );
                self.record_trace(&frame, spec, false, reason, ret_tag, Some(trap), None);
                return Err(TargetExecutorError::CapabilityDenied);
            }
            let handle = frame
                .cap_args
                .iter()
                .find(|arg| arg.object_ref == Some(authority_object))
                .and_then(CapabilityHandleArg::capability_handle);
            match capabilities.check_authority(
                derived_subject,
                authority_object,
                required_right,
                handle.as_ref(),
            ) {
                Ok(capability) => {
                    if capability.generation != frame.generation {
                        self.event_log.push(format!(
                            "CapabilityGenerationMismatch activation={} subject={} object={} op={} expected={} actual={}",
                            frame.activation,
                            derived_subject,
                            frame.object,
                            required_right,
                            frame.generation,
                            capability.generation
                        ));
                        let trap = self.record_trap_for_activation(
                            activation_index,
                            TargetTrapClass::CapabilityTrap,
                            Some(code),
                            Some(spec.name.clone()),
                            "rebind-or-fail",
                            FailureEffect::CompleteWithErrno(1),
                            "capability generation mismatch",
                        );
                        self.record_trace(
                            &frame,
                            spec,
                            false,
                            "capability-generation",
                            HostcallReturnTag::Trap,
                            Some(trap),
                            None,
                        );
                        return Err(TargetExecutorError::CapabilityDenied);
                    }
                }
                Err(reason) => {
                    self.event_log.push(format!(
                        "CapabilityDenied activation={} subject={} object={} op={} reason={}",
                        frame.activation,
                        derived_subject,
                        frame.object,
                        required_right,
                        reason.as_str()
                    ));
                    let trap = self.record_trap_for_activation(
                        activation_index,
                        TargetTrapClass::CapabilityTrap,
                        Some(code),
                        Some(spec.name.clone()),
                        "rebind-or-fail",
                        FailureEffect::CompleteWithErrno(1),
                        "hostcall capability gate denied access",
                    );
                    self.record_trace(
                        &frame,
                        spec,
                        false,
                        reason.as_str(),
                        HostcallReturnTag::Trap,
                        Some(trap),
                        None,
                    );
                    return Err(TargetExecutorError::CapabilityDenied);
                }
            }
        }
        if spec.may_pending && self.activations[activation_index].active_dmw_leases != 0 {
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                Some(code),
                Some(spec.name.clone()),
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "pending hostcall attempted with active DMW lease",
            );
            self.record_trace(
                &frame,
                spec,
                false,
                "dmw-lease-active",
                HostcallReturnTag::Trap,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        self.record_trace(
            &frame,
            spec,
            true,
            "complete",
            HostcallReturnTag::Ok,
            None,
            None,
        );
        let transition_event = self.next_event("activation-hostcall-complete");
        let old_generation = self.activations[activation_index].generation;
        self.retire_activation_generation(
            activation.id,
            old_generation,
            transition_event,
            "activation-hostcall-previous-generation",
        );
        let activation = &mut self.activations[activation_index];
        activation.return_tag = Some(HostcallReturnTag::Ok);
        activation.generation += 1;
        Ok(())
    }

    pub fn acquire_dmw_lease(
        &mut self,
        activation: ActivationId,
        handle: &str,
    ) -> Result<DmwLeaseId, TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].state != ActivationState::Running {
            return Err(TargetExecutorError::ActivationNotRunning);
        }
        let id = self.next_lease_id;
        self.next_lease_id += 1;
        self.dmw_leases.push(DmwLeaseRecord {
            id,
            activation,
            handle: handle.to_string(),
            generation: 1,
            active: true,
        });
        self.activations[activation_index].active_dmw_leases += 1;
        self.event_log.push(format!(
            "DmwLeaseAcquired activation={activation} lease={id} handle={handle}"
        ));
        Ok(id)
    }

    pub fn release_dmw_lease(&mut self, lease: DmwLeaseId) -> Result<(), TargetExecutorError> {
        let Some(lease_index) = self.dmw_leases.iter().position(|record| record.id == lease) else {
            return Err(TargetExecutorError::DmwLeaseMissing);
        };
        if !self.dmw_leases[lease_index].active {
            return Ok(());
        }
        let activation = self.dmw_leases[lease_index].activation;
        let activation_index = self.activation_index(activation)?;
        self.dmw_leases[lease_index].active = false;
        self.dmw_leases[lease_index].generation += 1;
        self.activations[activation_index].active_dmw_leases = self.activations[activation_index]
            .active_dmw_leases
            .saturating_sub(1);
        self.event_log.push(format!(
            "DmwLeaseReleased activation={activation} lease={lease}"
        ));
        Ok(())
    }

    pub fn release_all_leases_for_activation(
        &mut self,
        activation: ActivationId,
        reason: &str,
    ) -> Result<u32, TargetExecutorError> {
        self.activation_index(activation)?;
        Ok(self.release_all_leases_for_activation_id(activation, reason))
    }

    pub fn pending_exit(
        &mut self,
        activation: ActivationId,
        wait: WaitId,
    ) -> Result<(), TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                None,
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to enter pending with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        let exit_event = self.next_event("activation-pending");
        let activation_id = activation;
        let old_generation = self.activations[activation_index].generation;
        self.retire_activation_generation(
            activation_id,
            old_generation,
            exit_event,
            "activation-pending-previous-generation",
        );
        let record = &mut self.activations[activation_index];
        record.state = ActivationState::Pending;
        record.blocked_wait = Some(wait);
        record.return_tag = Some(HostcallReturnTag::Pending);
        record.exit_event = Some(exit_event);
        record.generation += 1;
        Ok(())
    }

    pub fn return_exit(&mut self, activation: ActivationId) -> Result<(), TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                None,
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to return with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        let activation_id = activation;
        let exit_event = self.next_event("activation-returned");
        let old_generation = self.activations[activation_index].generation;
        self.retire_activation_generation(
            activation_id,
            old_generation,
            exit_event,
            "activation-returned-previous-generation",
        );
        let record = &mut self.activations[activation_index];
        record.state = ActivationState::Returned;
        record.return_tag = Some(HostcallReturnTag::Ok);
        record.exit_event = Some(exit_event);
        record.generation += 1;
        Ok(())
    }

    pub fn trap_exit(
        &mut self,
        activation: ActivationId,
        class: TargetTrapClass,
        code: Option<&CodeObject>,
        detail: &str,
    ) -> Result<TargetTrapId, TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                code,
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to trap with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        Ok(self.record_trap_for_activation(
            activation_index,
            class,
            code,
            None,
            "trap-policy",
            FailureEffect::CompleteWithErrno(5),
            detail,
        ))
    }

    pub fn trap_exit_by_pc(
        &mut self,
        activation: ActivationId,
        code: &CodeObject,
        pc: u64,
        trap_map: &[TrapMapEntryV1],
    ) -> Result<TargetTrapId, TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        let activation_record = &self.activations[activation_index];
        let code_store_mismatch = code.state != CodeObjectState::Retired
            && (code.bound_store != Some(activation_record.store)
                || code.bound_store_generation != Some(activation_record.store_generation));
        if activation_record.code_object != code.id
            || activation_record.code_generation != code.generation
            || activation_record.artifact != code.artifact_id
            || code_store_mismatch
        {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::CodeObjectTrap,
                Some(code),
                None,
                "trap-attribution-failure",
                FailureEffect::CompleteWithErrno(5),
                "trap PC attribution did not match activation code object",
            );
            return Err(TargetExecutorError::CodeObjectMismatch);
        }
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                Some(code),
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to trap with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        let code_ref = ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation);
        let range = PcRangeEntryV1::new(code_ref, code.text.start, code.text.len, 0, 0);
        let runtime_range = if code.state == CodeObjectState::Retired {
            PcRangeRuntimeEntryV1::retired(range)
        } else {
            PcRangeRuntimeEntryV1::live(range)
        };
        let ranges = [runtime_range];
        let attribution = classify_trap_pc(pc, &ranges, trap_map);
        let class = trap_class_for_attribution(attribution.trap_kind);
        let detail = format!(
            "pc={pc:#x} code_offset={} trap_kind={}",
            attribution
                .code_offset
                .map(|offset| format!("{offset:#x}"))
                .unwrap_or_else(|| "none".to_string()),
            attribution.trap_kind.as_str()
        );
        Ok(self.record_trap_for_activation_attributed(
            activation_index,
            class,
            attribution.code_object.map(|_| code),
            None,
            attribution.trap_kind.as_str(),
            FailureEffect::CompleteWithErrno(5),
            &detail,
            attribution.code_offset,
            Some(attribution),
        ))
    }

    pub fn synthetic_trap(
        &mut self,
        class: TargetTrapClass,
        store: StoreId,
        activation: Option<ActivationId>,
        code: Option<&CodeObject>,
        hostcall: Option<&str>,
        detail: &str,
    ) -> TargetTrapId {
        let id = self.next_trap_id;
        self.next_trap_id += 1;
        let activation_generation = activation.and_then(|activation| {
            self.activations
                .iter()
                .find(|record| record.id == activation)
                .map(|record| record.generation)
        });
        let store_generation = code
            .and_then(|code| code.bound_store_generation)
            .or_else(|| {
                activation.and_then(|activation| {
                    self.activations
                        .iter()
                        .find(|record| record.id == activation)
                        .map(|record| record.store_generation)
                })
            });
        self.traps.push(TargetTrapRecord {
            id,
            generation: 1,
            class,
            store: Some(store),
            store_generation,
            activation,
            activation_generation,
            code_object: code.map(|code| code.id),
            code_generation: code.map(|code| code.generation),
            artifact: code.map(|code| code.artifact_id),
            artifact_generation: code.map(|_| TARGET_ARTIFACT_GENERATION_V1),
            offset: Some(0),
            target_pc: None,
            trap_kind: None,
            function_index: None,
            wasm_offset: None,
            debug_symbol: None,
            classification_status: None,
            hostcall: hostcall.map(|hostcall| hostcall.to_string()),
            fault_policy: "harness-classification".to_string(),
            effect: FailureEffect::CompleteWithErrno(5),
            detail: detail.to_string(),
        });
        self.event_log.push(format!(
            "TrapClassified trap={id} class={} store={store} detail={detail}",
            class.as_str()
        ));
        id
    }

    pub fn snapshot_barrier(&self) -> Result<(), TargetExecutorError> {
        let report = SnapshotBarrierValidator::validate(&self.snapshot_barrier_validation_state());
        for violation in report.violations {
            match violation.kind {
                BoundaryValidationErrorKind::ActiveDmwLease => {
                    return Err(TargetExecutorError::DmwLeaseActive);
                }
                BoundaryValidationErrorKind::PendingCleanup => {
                    return Err(TargetExecutorError::PendingCleanupActive);
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn snapshot_barrier_validation_state(&self) -> SnapshotBarrierValidationState {
        SnapshotBarrierValidationState {
            active_dmw_lease_count: self.dmw_leases.iter().filter(|lease| lease.active).count()
                as u32,
            pending_cleanup_count: self
                .cleanup_transactions
                .iter()
                .filter(|cleanup| cleanup.state == CleanupTransactionState::Pending)
                .count() as u32,
            ..SnapshotBarrierValidationState::default()
        }
    }

    pub fn begin_fault_cleanup_transaction(
        &mut self,
        store: &StoreRecord,
        activation: Option<ActivationId>,
        code: Option<&CodeObject>,
        reason: &str,
    ) -> CleanupTransactionId {
        let activation_generation = activation.and_then(|activation| {
            self.activations
                .iter()
                .find(|record| record.id == activation)
                .map(|record| record.generation)
        });
        let code_object = code.map(|code| code.id);
        let code_generation = code.map(|code| code.generation);
        if let Some(existing) = self.cleanup_transactions.iter().find(|cleanup| {
            cleanup.store == store.id
                && cleanup.store_generation == store.generation
                && cleanup.result_store_generation.is_none()
                && cleanup.activation == activation
                && cleanup.activation_generation == activation_generation
                && cleanup.code_object == code_object
                && cleanup.code_generation == code_generation
                && cleanup.reason == reason
                && cleanup.state == CleanupTransactionState::Pending
        }) {
            return existing.id;
        }
        let started_at = self.next_event("fault-cleanup-started");
        let id = self.next_cleanup_id;
        self.next_cleanup_id += 1;
        self.cleanup_transactions.push(FaultCleanupTransaction {
            id,
            store: store.id,
            store_generation: store.generation,
            result_store_generation: None,
            activation,
            activation_generation,
            code_object,
            code_generation,
            generation: 1,
            started_at,
            finished_at: None,
            state: CleanupTransactionState::Pending,
            reason: reason.to_string(),
            steps: Self::cleanup_step_order()
                .iter()
                .map(|step| CleanupStepRecord::pending(*step))
                .collect(),
            effects: Vec::new(),
            released_dmw_leases: 0,
            cancelled_waits: 0,
            revoked_capabilities: Vec::new(),
            revoked_capability_refs: Vec::new(),
            dropped_resources: 0,
            unbound_code_object: false,
            effect: FailureEffect::CompleteWithErrno(5),
        });
        self.event_log.push(format!(
            "FaultCleanupStarted cleanup={id} store={}@{} activation={} reason={reason}",
            store.id,
            store.generation,
            activation
                .zip(activation_generation)
                .map(|(activation, generation)| format!("{activation}@{generation}"))
                .unwrap_or_else(|| "none".to_string())
        ));
        id
    }

    pub fn run_fault_cleanup(
        &mut self,
        store: &mut StoreRecord,
        activation: Option<ActivationId>,
        code: Option<&mut CodeObject>,
        capabilities: &mut CapabilityLedger,
        reason: &str,
    ) -> Result<CleanupTransactionId, TargetExecutorError> {
        let activation_generation = activation.and_then(|activation| {
            self.activations
                .iter()
                .find(|record| record.id == activation)
                .map(|record| record.generation)
        });
        let code_object = code.as_deref().map(|code| code.id);
        let code_generation = code.as_deref().map(|code| code.generation);
        if let Some(existing) = self.cleanup_transactions.iter().find(|cleanup| {
            cleanup.store == store.id
                && cleanup.result_store_generation == Some(store.generation)
                && cleanup.activation == activation
                && cleanup.activation_generation == activation_generation
                && cleanup.code_object == code_object
                && cleanup.code_generation == code_generation
                && cleanup.reason == reason
                && store.state == StoreState::Dead
                && cleanup.state == CleanupTransactionState::Completed
        }) {
            return Ok(existing.id);
        }
        let id = self.begin_fault_cleanup_transaction(store, activation, code.as_deref(), reason);
        self.apply_fault_cleanup_transaction(id, store, code, capabilities)
    }

    pub fn apply_fault_cleanup_transaction(
        &mut self,
        cleanup_id: CleanupTransactionId,
        store: &mut StoreRecord,
        code: Option<&mut CodeObject>,
        capabilities: &mut CapabilityLedger,
    ) -> Result<CleanupTransactionId, TargetExecutorError> {
        let Some(cleanup_index) = self
            .cleanup_transactions
            .iter()
            .position(|cleanup| cleanup.id == cleanup_id)
        else {
            return Err(TargetExecutorError::CleanupTransactionMissing);
        };
        if self.cleanup_transactions[cleanup_index].state != CleanupTransactionState::Pending {
            return Ok(cleanup_id);
        }
        if self.cleanup_transactions[cleanup_index].store != store.id {
            return Err(TargetExecutorError::CleanupStoreMismatch);
        }

        let activation = self.cleanup_transactions[cleanup_index].activation;
        let reason = self.cleanup_transactions[cleanup_index].reason.clone();
        let expected_store_generation = self.cleanup_transactions[cleanup_index].store_generation;
        if store.generation != expected_store_generation {
            let event = self.next_event("fault-cleanup-stale-generation");
            let target = ContractObjectRef::new(
                ContractObjectKind::Store,
                store.id,
                expected_store_generation,
            );
            let cleanup = &mut self.cleanup_transactions[cleanup_index];
            cleanup.state = CleanupTransactionState::SkippedStaleGeneration;
            cleanup.generation += 1;
            cleanup.result_store_generation = Some(store.generation);
            cleanup.finished_at = Some(event);
            cleanup.steps = Self::cleanup_step_order()
                .iter()
                .map(|step| {
                    CleanupStepRecord::skipped_stale_generation(
                        *step,
                        target,
                        store.generation,
                        event,
                    )
                })
                .collect();
            cleanup.effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::RecordFailureEffect,
                target,
                expected_store_generation,
                CleanupEffectStatus::SkippedStaleGeneration,
                event,
            ));
            self.event_log.push(format!(
                "FaultCleanupSkipped cleanup={cleanup_id} store={} expected_generation={} observed_generation={}",
                store.id, expected_store_generation, store.generation
            ));
            return Ok(cleanup_id);
        }

        let released = activation
            .map(|activation| self.release_all_leases_for_activation_id(activation, &reason))
            .unwrap_or(0);
        let mut cancelled_waits = 0;
        let mut final_activation_generation = None;
        if let Some(activation) = activation {
            if let Some(index) = self
                .activations
                .iter()
                .position(|record| record.id == activation)
            {
                let exit_event = self.next_event("activation-cleanup-dropped");
                let old_generation = self.activations[index].generation;
                self.retire_activation_generation(
                    activation,
                    old_generation,
                    exit_event,
                    "fault-cleanup-activation-previous-generation",
                );
                let (activation_generation, cancelled) = {
                    let record = &mut self.activations[index];
                    record.state = ActivationState::Dropped;
                    record.return_tag = Some(HostcallReturnTag::KillStore);
                    record.exit_event = Some(exit_event);
                    let cancelled = if record.blocked_wait.take().is_some() {
                        1
                    } else {
                        0
                    };
                    record.active_dmw_leases = 0;
                    record.generation += 1;
                    (record.generation, cancelled)
                };
                cancelled_waits += cancelled;
                final_activation_generation = Some(activation_generation);
            }
        }
        let revoked = capabilities.revoke_owner_store(store.id, expected_store_generation);
        let revoked_refs = revoked
            .iter()
            .filter_map(|capability_id| {
                capabilities
                    .records()
                    .iter()
                    .find(|record| record.id == *capability_id)
                    .map(CapabilityRecord::object_ref)
            })
            .collect::<Vec<_>>();
        let mut unbound = false;
        let mut code_generation = None;
        let mut code_ref = None;
        if let Some(code) = code {
            if code.bound_store == Some(store.id)
                && code.bound_store_generation == Some(expected_store_generation)
            {
                code.bound_store = None;
                code.bound_store_generation = None;
                code.hostcall_table = None;
                code.state = CodeObjectState::Retired;
                code.generation += 1;
                unbound = true;
            }
            code_generation = Some(code.generation);
            code_ref = Some(code.object_ref());
        }
        store.state = StoreState::Dead;
        store.generation += 1;
        let store_ref = store.object_ref();
        if let Some(activation) = activation {
            if let Some(record) = self
                .activations
                .iter_mut()
                .find(|record| record.id == activation)
            {
                record.store_generation = store.generation;
                if let Some(code_generation) = code_generation {
                    record.code_generation = code_generation;
                }
            }
        }
        let finished_at = self.next_event("fault-cleanup-completed");
        self.tombstones.push(TombstoneRecord::new(
            ContractObjectKind::Store,
            store.id,
            expected_store_generation,
            finished_at,
            "fault-cleanup-store-target-retired",
        ));
        self.tombstones.push(TombstoneRecord::new(
            ContractObjectKind::Store,
            store.id,
            store.generation,
            finished_at,
            "fault-cleanup-store-dead",
        ));
        if let Some(activation) = activation {
            if let Some(generation) = final_activation_generation {
                self.tombstones.push(TombstoneRecord::new(
                    ContractObjectKind::Activation,
                    activation,
                    generation,
                    finished_at,
                    "fault-cleanup-activation-dropped",
                ));
            }
        }
        if let Some(code_ref) = code_ref {
            self.tombstones.push(TombstoneRecord::new(
                ContractObjectKind::CodeObject,
                code_ref.id,
                code_ref.generation,
                finished_at,
                "fault-cleanup-code-retired",
            ));
        }
        let cleanup = self
            .cleanup_transactions
            .iter_mut()
            .find(|cleanup| cleanup.id == cleanup_id)
            .expect("cleanup transaction must exist");
        cleanup.state = CleanupTransactionState::Completed;
        cleanup.generation += 1;
        cleanup.result_store_generation = Some(store.generation);
        cleanup.finished_at = Some(finished_at);
        cleanup.activation_generation =
            final_activation_generation.or(cleanup.activation_generation);
        cleanup.code_generation = code_generation.or(cleanup.code_generation);
        cleanup.released_dmw_leases = released;
        cleanup.cancelled_waits = cancelled_waits;
        cleanup.revoked_capabilities = revoked;
        cleanup.revoked_capability_refs = revoked_refs;
        cleanup.dropped_resources = 1;
        cleanup.unbound_code_object = unbound;
        cleanup.effect = FailureEffect::CompleteWithErrno(5);
        let mut steps = Vec::new();
        steps.push(
            CleanupStepRecord::done(CleanupStep::StopNewActivation, "new activations stopped")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::SealActivation, "activation sealed")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::PreventHostcalls, "activation dropped")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::ReleaseDmwLeases, "leases released")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::CancelWaitTokens, "no wait tokens in harness")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(
                CleanupStep::RevokeCapabilities,
                "store-owned capabilities revoked",
            )
            .with_target(store_ref)
            .with_observed_generation(store.generation)
            .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::DropResourceArena, "resource arena dropped")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::UnbindCodeObject, "code object unbound")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::MarkStoreState, "store marked dead")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::RecordTransition, "cleanup transition recorded")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::EmitTombstones, "cleanup tombstones emitted")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::RecordFailureEffect, "failure effect recorded")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        steps.push(
            CleanupStepRecord::done(CleanupStep::EmitReport, "cleanup report emitted")
                .with_target(store_ref)
                .with_observed_generation(store.generation)
                .with_event_seq(finished_at),
        );
        cleanup.steps = steps;
        cleanup.effects = Self::cleanup_effects_for_completed_transaction(
            store_ref,
            activation
                .zip(final_activation_generation)
                .map(|(id, generation)| {
                    ContractObjectRef::new(ContractObjectKind::Activation, id, generation)
                }),
            code_ref,
            &cleanup.revoked_capability_refs,
            released,
            cancelled_waits,
            cleanup.dropped_resources,
            finished_at,
        );
        self.event_log.push(format!(
            "FaultCleanupCompleted cleanup={cleanup_id} store={} released_dmw={} revoked_caps={} unbound_code={}",
            store.id,
            released,
            cleanup.revoked_capabilities.len(),
            unbound
        ));
        Ok(cleanup_id)
    }

    pub fn classify_migration_objects(
        &self,
        code_objects: &[CodeObject],
    ) -> Vec<MigrationObjectRecord> {
        let mut records = Vec::new();
        records.push(MigrationObjectRecord::new(
            "semantic-object-graph",
            MigrationObjectClass::Migrated,
            "semantic roots are serialized",
        ));
        records.push(MigrationObjectRecord::new(
            "store-records",
            MigrationObjectClass::Migrated,
            "StoreRecord lifecycle state is semantic",
        ));
        for code in code_objects {
            records.push(MigrationObjectRecord::new(
                &format!("code-object:{}", code.id),
                MigrationObjectClass::Rebuilt,
                "target republishes executable code from verified artifact",
            ));
        }
        records.push(MigrationObjectRecord::new(
            "native-stack",
            MigrationObjectClass::NeverMigrated,
            "native stacks are substrate state",
        ));
        records.push(MigrationObjectRecord::new(
            "dmw-pointer",
            MigrationObjectClass::NeverMigrated,
            "handle-mode leases cannot cross snapshot barrier",
        ));
        records
    }

    pub fn activations(&self) -> &[ActivationRecord] {
        &self.activations
    }

    pub fn traps(&self) -> &[TargetTrapRecord] {
        &self.traps
    }

    pub fn dmw_leases(&self) -> &[DmwLeaseRecord] {
        &self.dmw_leases
    }

    pub fn hostcall_trace(&self) -> &[HostcallTraceRecord] {
        &self.hostcall_trace
    }

    pub fn cleanup_transactions(&self) -> &[FaultCleanupTransaction] {
        &self.cleanup_transactions
    }

    pub fn tombstones(&self) -> &[TombstoneRecord] {
        &self.tombstones
    }

    pub fn cleanup_state_digest(
        &self,
        store: &StoreRecord,
        code: Option<&CodeObject>,
        capabilities: &CapabilityLedger,
    ) -> String {
        let code_state = code
            .map(|code| {
                format!(
                    "code:{}@{}:{}:bound={}@{}",
                    code.id,
                    code.generation,
                    code.state.as_str(),
                    code.bound_store
                        .map(|store| store.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    code.bound_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "none".to_string())
                )
            })
            .unwrap_or_else(|| "code:none".to_string());
        let activation_state = self
            .activations
            .iter()
            .map(|activation| {
                format!(
                    "act:{}@{}:{}:store={}@{}:code={}@{}:leases={}:wait={}",
                    activation.id,
                    activation.generation,
                    activation.state.as_str(),
                    activation.store,
                    activation.store_generation,
                    activation.code_object,
                    activation.code_generation,
                    activation.active_dmw_leases,
                    activation
                        .blocked_wait
                        .map(|wait| wait.to_string())
                        .unwrap_or_else(|| "none".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let lease_state = self
            .dmw_leases
            .iter()
            .map(|lease| {
                format!(
                    "lease:{}@{}:activation={}:active={}",
                    lease.id, lease.generation, lease.activation, lease.active
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let capability_state = capabilities
            .records()
            .iter()
            .map(|capability| {
                format!(
                    "cap:{}@{}:owner={}:revoked={}",
                    capability.id,
                    capability.generation,
                    capability
                        .owner_store
                        .map(|store| store.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    capability.revoked
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "store:{}@{}:{}|{}|activations=[{}]|leases=[{}]|caps=[{}]",
            store.id,
            store.generation,
            store.state.as_str(),
            code_state,
            activation_state,
            lease_state,
            capability_state
        )
    }

    pub fn event_log(&self) -> &[String] {
        &self.event_log
    }

    fn cleanup_step_order() -> [CleanupStep; 13] {
        [
            CleanupStep::StopNewActivation,
            CleanupStep::SealActivation,
            CleanupStep::PreventHostcalls,
            CleanupStep::ReleaseDmwLeases,
            CleanupStep::CancelWaitTokens,
            CleanupStep::RevokeCapabilities,
            CleanupStep::DropResourceArena,
            CleanupStep::UnbindCodeObject,
            CleanupStep::MarkStoreState,
            CleanupStep::RecordTransition,
            CleanupStep::EmitTombstones,
            CleanupStep::RecordFailureEffect,
            CleanupStep::EmitReport,
        ]
    }

    fn cleanup_effects_for_completed_transaction(
        store_ref: ContractObjectRef,
        activation_ref: Option<ContractObjectRef>,
        code_ref: Option<ContractObjectRef>,
        capability_refs: &[ContractObjectRef],
        released_dmw_leases: u32,
        cancelled_waits: u32,
        dropped_resources: u32,
        event_seq: EventId,
    ) -> Vec<CleanupEffectRecord> {
        let mut effects = Vec::new();
        effects.push(CleanupEffectRecord::new(
            CleanupEffectKind::StopNewActivation,
            store_ref,
            store_ref.generation,
            CleanupEffectStatus::Applied,
            event_seq,
        ));
        if let Some(activation_ref) = activation_ref {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::SealActivation,
                activation_ref,
                activation_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        if released_dmw_leases != 0 {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::ReleaseLeases,
                store_ref,
                store_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        if cancelled_waits != 0 {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::CancelWaits,
                store_ref,
                store_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        for capability_ref in capability_refs {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::RevokeCapability,
                *capability_ref,
                capability_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        if dropped_resources != 0 {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::DropResources,
                store_ref,
                store_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        if let Some(code_ref) = code_ref {
            effects.push(CleanupEffectRecord::new(
                CleanupEffectKind::UnbindCode,
                code_ref,
                code_ref.generation,
                CleanupEffectStatus::Applied,
                event_seq,
            ));
        }
        effects.push(CleanupEffectRecord::new(
            CleanupEffectKind::MarkStoreDead,
            store_ref,
            store_ref.generation,
            CleanupEffectStatus::Applied,
            event_seq,
        ));
        effects.push(CleanupEffectRecord::new(
            CleanupEffectKind::EmitTombstone,
            store_ref,
            store_ref.generation,
            CleanupEffectStatus::Applied,
            event_seq,
        ));
        effects.push(CleanupEffectRecord::new(
            CleanupEffectKind::RecordFailureEffect,
            store_ref,
            store_ref.generation,
            CleanupEffectStatus::Applied,
            event_seq,
        ));
        effects
    }

    fn cap_arg_denial_reason(
        frame: &HostcallFrame,
        subject: &str,
        object_ref: AuthorityObjectRef,
        required_right: &str,
        capabilities: &CapabilityLedger,
    ) -> Option<&'static str> {
        if frame.cap_args.is_empty() {
            return Some("cap-arg-required");
        }
        let mut matched_frame_object = false;
        for handle in &frame.cap_args {
            let Some(owner_store) = handle.owner_store else {
                return Some("cap-arg-missing");
            };
            let Some(owner_store_generation) = handle.owner_store_generation else {
                return Some("cap-arg-missing");
            };
            let Some(record) = capabilities.records().iter().find(|record| {
                record.owner_store == Some(owner_store)
                    && record.owner_store_generation == Some(owner_store_generation)
                    && record.handle_slot == handle.handle_slot
                    && !record.revoked
            }) else {
                return Some("cap-arg-missing");
            };
            if record.subject != subject {
                return Some("cap-arg-subject");
            }
            if record.object_ref != handle.object_ref || handle.object_ref != Some(object_ref) {
                return Some("cap-arg-object");
            }
            if handle.class_hint != Some(record.class) || record.class != object_ref.class() {
                return Some("cap-arg-object-class");
            }
            if record.handle_generation != handle.handle_generation
                || record.generation != handle.generation
            {
                return Some("cap-arg-generation");
            }
            if record.handle_tag != handle.handle_tag {
                return Some("cap-arg-tag");
            }
            if handle.rights.is_empty() {
                return Some("cap-arg-empty-rights");
            }
            if handle.rights_mask == 0 {
                return Some("cap-arg-rights-mask");
            }
            for right in &handle.rights {
                if !record.operations.contains(right) {
                    return Some("cap-arg-rights");
                }
            }
            let Some(rights_mask) = Self::capability_rights_mask(record, &handle.rights) else {
                return Some("cap-arg-rights-mask");
            };
            if rights_mask != handle.rights_mask {
                return Some("cap-arg-rights-mask");
            }
            if handle.object_ref == Some(object_ref)
                && handle.rights.iter().any(|right| right == required_right)
            {
                matched_frame_object = true;
            }
        }
        if !matched_frame_object {
            return Some("cap-arg-frame-right");
        }
        None
    }

    fn capability_rights_mask(record: &CapabilityRecord, rights: &[String]) -> Option<u64> {
        let mut mask = 0u64;
        for right in rights {
            let index = record
                .operations
                .as_slice()
                .iter()
                .position(|operation| operation == right)?;
            if index >= u64::BITS as usize {
                return None;
            }
            mask |= 1u64 << index;
        }
        Some(mask)
    }

    fn capability_rights_from_mask(
        record: &CapabilityRecord,
        rights_mask: u64,
    ) -> Option<Vec<String>> {
        if rights_mask == 0 {
            return None;
        }
        let mut rights = Vec::new();
        for (index, operation) in record.operations.as_slice().iter().enumerate() {
            if index >= u64::BITS as usize {
                return None;
            }
            if rights_mask & (1u64 << index) != 0 {
                rights.push(operation.clone());
            }
        }
        let known_mask = Self::capability_rights_mask(record, &rights)?;
        if known_mask == rights_mask {
            Some(rights)
        } else {
            None
        }
    }

    fn record_trace(
        &mut self,
        frame: &HostcallFrame,
        spec: &HostcallSpec,
        allowed: bool,
        result: &str,
        ret_tag: HostcallReturnTag,
        trap_out: Option<TargetTrapId>,
        wait_token_out: Option<WaitId>,
    ) {
        let id = self.next_hostcall_trace_id;
        self.next_hostcall_trace_id += 1;
        self.hostcall_trace.push(HostcallTraceRecord {
            id,
            generation: 1,
            abi_version: frame.abi_version.clone(),
            frame_size: frame.frame_size,
            flags: frame.flags,
            activation: frame.activation,
            activation_generation: frame.activation_generation,
            store: frame.store,
            store_generation: frame.store_generation,
            code_object: frame.code_object,
            code_generation: frame.code_generation,
            artifact: frame.artifact,
            artifact_generation: frame.artifact_generation,
            hostcall_number: spec.number,
            hostcall_seq: frame.hostcall_seq,
            caller_offset: frame.caller_offset,
            name: spec.name.clone(),
            category: spec.category,
            subject: frame.subject.clone(),
            object: spec.object.clone(),
            operation: spec.operation.clone(),
            args: frame.args,
            cap_args: frame.cap_args.clone(),
            record_mode: frame.record_mode,
            allowed,
            result: result.to_string(),
            ret_tag,
            ret0: frame.ret0,
            ret1: frame.ret1,
            trap_out,
            trap_generation_out: trap_out.map(|_| frame.trap_generation_out.unwrap_or(1)),
            wait_token_out,
            wait_token_generation_out: wait_token_out
                .map(|_| frame.wait_token_generation_out.unwrap_or(1)),
        });
    }

    fn record_trap_for_activation(
        &mut self,
        activation_index: usize,
        class: TargetTrapClass,
        code: Option<&CodeObject>,
        hostcall: Option<String>,
        fault_policy: &str,
        effect: FailureEffect,
        detail: &str,
    ) -> TargetTrapId {
        self.record_trap_for_activation_attributed(
            activation_index,
            class,
            code,
            hostcall,
            fault_policy,
            effect,
            detail,
            Some(0),
            None,
        )
    }

    fn record_trap_for_activation_attributed(
        &mut self,
        activation_index: usize,
        class: TargetTrapClass,
        code: Option<&CodeObject>,
        hostcall: Option<String>,
        fault_policy: &str,
        effect: FailureEffect,
        detail: &str,
        offset: Option<u64>,
        attribution: Option<TrapAttributionV1>,
    ) -> TargetTrapId {
        let activation_id = self.activations[activation_index].id;
        let store = self.activations[activation_index].store;
        let store_generation = self.activations[activation_index].store_generation;
        let old_activation_generation = self.activations[activation_index].generation;
        self.release_all_leases_for_activation_id(activation_id, "trap-quarantine");
        let id = self.next_trap_id;
        self.next_trap_id += 1;
        let exit_event = self.next_event("activation-trapped");
        self.retire_activation_generation(
            activation_id,
            old_activation_generation,
            exit_event,
            "activation-trapped-previous-generation",
        );
        let activation = &mut self.activations[activation_index];
        activation.state = ActivationState::Trapped;
        activation.trap = Some(id);
        activation.return_tag = Some(HostcallReturnTag::Trap);
        activation.exit_event = Some(exit_event);
        activation.generation += 1;
        let activation_generation = activation.generation;
        self.traps.push(TargetTrapRecord {
            id,
            generation: 1,
            class,
            store: Some(store),
            store_generation: Some(store_generation),
            activation: Some(activation_id),
            activation_generation: Some(activation_generation),
            code_object: code.map(|code| code.id),
            code_generation: code.map(|code| code.generation),
            artifact: code.map(|code| code.artifact_id),
            artifact_generation: code.map(|_| TARGET_ARTIFACT_GENERATION_V1),
            offset,
            target_pc: attribution.map(|attribution| attribution.pc),
            trap_kind: attribution.map(|attribution| attribution.trap_kind.as_str().to_string()),
            function_index: attribution.and_then(|attribution| attribution.function_index),
            wasm_offset: attribution.and_then(|attribution| attribution.wasm_offset),
            debug_symbol: attribution.and_then(|attribution| attribution.debug_symbol),
            classification_status: attribution
                .map(|attribution| attribution.trap_kind.as_str().to_string()),
            hostcall,
            fault_policy: fault_policy.to_string(),
            effect,
            detail: detail.to_string(),
        });
        id
    }

    fn retire_activation_generation(
        &mut self,
        activation: ActivationId,
        generation: Generation,
        event: EventId,
        reason: &str,
    ) {
        if generation == 0
            || self.tombstones.iter().any(|tombstone| {
                tombstone.object_ref()
                    == ContractObjectRef::new(
                        ContractObjectKind::Activation,
                        activation,
                        generation,
                    )
            })
        {
            return;
        }
        self.tombstones.push(TombstoneRecord::new(
            ContractObjectKind::Activation,
            activation,
            generation,
            event,
            reason,
        ));
    }

    fn release_all_leases_for_activation_id(
        &mut self,
        activation: ActivationId,
        reason: &str,
    ) -> u32 {
        let mut released = 0;
        for lease in &mut self.dmw_leases {
            if lease.activation == activation && lease.active {
                lease.active = false;
                lease.generation += 1;
                released += 1;
                self.event_log.push(format!(
                    "DmwLeaseReleased activation={activation} lease={} reason={reason}",
                    lease.id
                ));
            }
        }
        if released != 0 {
            if let Some(index) = self
                .activations
                .iter()
                .position(|record| record.id == activation)
            {
                self.activations[index].active_dmw_leases = self.activations[index]
                    .active_dmw_leases
                    .saturating_sub(released);
            }
            self.event_log.push(format!(
                "DmwLeaseQuarantined activation={activation} released={released} reason={reason}"
            ));
        }
        released
    }

    fn activation_index(&self, activation: ActivationId) -> Result<usize, TargetExecutorError> {
        self.activations
            .iter()
            .position(|record| record.id == activation)
            .ok_or(TargetExecutorError::ActivationMissing)
    }

    fn next_event(&mut self, label: &str) -> EventId {
        let id = self.next_event_id;
        self.next_event_id += 1;
        self.event_log
            .push(format!("TargetExecutorEvent id={id} label={label}"));
        id
    }
}

impl Default for TargetExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> TargetArtifactImage {
        let mut image = TargetArtifactImage::new(
            1,
            "driver_virtio_net",
            "driver_virtio_net.tart",
            "driver",
            "host-validation",
            "artifact-hash-1",
            "abi-1",
            "binding-1",
            "code-hash-1",
            TargetMemoryPlan::new(16, 32, 64),
        );
        image.exports.push("vmos_service_entry".to_string());
        image
            .address_map
            .push(TargetAddressMapEntry::new("_start", 0, 64));
        image.trap_metadata.push(TargetTrapMetadata::new(
            TargetTrapClass::CodeObjectTrap,
            "_start",
            0,
        ));
        image.capabilities.push(TargetCapabilitySpec::new(
            "mmio.virtio-net",
            &["map"],
            "store",
        ));
        image.hostcalls.push(HostcallSpec::new(
            1,
            "hostcall.mmio.map",
            HostcallCategory::Mmio,
            "mmio.virtio-net",
            "map",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            2,
            "hostcall.mmio.denied",
            HostcallCategory::Mmio,
            "mmio.denied",
            "map",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            3,
            "hostcall.dma.denied",
            HostcallCategory::Dma,
            "dma.denied",
            "map",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            4,
            "hostcall.irq.denied",
            HostcallCategory::Irq,
            "irq.denied",
            "bind",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            5,
            "hostcall.dmw.denied",
            HostcallCategory::Dmw,
            "dmw.denied",
            "open",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            6,
            "hostcall.code-publish.denied",
            HostcallCategory::CodePublish,
            "code-publish.denied",
            "publish",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            7,
            "hostcall.packet-device.denied",
            HostcallCategory::PacketDevice,
            "packet-device.net0",
            "rx",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            8,
            "hostcall.wait.pending",
            HostcallCategory::Wait,
            "wait.timer",
            "park",
            true,
        ));
        image.hostcalls.push(HostcallSpec::new(
            9,
            "hostcall.device.denied",
            HostcallCategory::Device,
            "device.denied",
            "read",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            10,
            "hostcall.virtqueue.denied",
            HostcallCategory::Virtqueue,
            "virtqueue.denied",
            "kick",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            11,
            "hostcall.timer.denied",
            HostcallCategory::Timer,
            "timer.denied",
            "arm",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            12,
            "hostcall.guest-memory.denied",
            HostcallCategory::GuestMemory,
            "guest-memory.denied",
            "read",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            13,
            "hostcall.snapshot.denied",
            HostcallCategory::Snapshot,
            "snapshot.denied",
            "enter",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            14,
            "hostcall.fault-domain.denied",
            HostcallCategory::FaultDomain,
            "fault-domain.denied",
            "restart",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            15,
            "hostcall.event-log.denied",
            HostcallCategory::EventLog,
            "event-log.denied",
            "append",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            16,
            "hostcall.store-control.denied",
            HostcallCategory::StoreControl,
            "store-control.denied",
            "kill",
            false,
        ));
        image
    }

    fn running_store_and_code() -> (
        VerifiedArtifact,
        ManagedStoreRecord,
        CodeObject,
        CapabilityLedger,
    ) {
        let mut registry = ArtifactRegistry::new();
        let verified = registry.verify(image()).unwrap();
        let mut stores = TargetStoreManager::new();
        let store_id =
            stores.register_verified_artifact(&verified, "restartable", "rebuild-from-artifact");
        stores.set_running(store_id).unwrap();
        let mut publisher = CodePublisher::new();
        let code_id = publisher.allocate(&verified).unwrap();
        publisher.fill(code_id).unwrap();
        publisher.seal(code_id).unwrap();
        publisher.publish_rx(code_id).unwrap();
        let store_record = stores.record(store_id).unwrap().store.clone();
        publisher.bind_to_store(code_id, &store_record).unwrap();
        let mut capabilities = CapabilityLedger::new();
        capabilities
            .grant_manifest_binding(
                "driver_virtio_net",
                "mmio.virtio-net",
                &["map"],
                "store",
                CapabilityClass::MmioRegion,
                Some(store_id),
                Some(store_record.generation),
                None,
                "target-executor-test",
            )
            .expect("test capability has owner store generation");
        (
            verified,
            stores.record(store_id).unwrap().clone(),
            publisher.object(code_id).unwrap().clone(),
            capabilities,
        )
    }

    fn cap_arg_for(
        capabilities: &CapabilityLedger,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> CapabilityHandleArg {
        let cap = capabilities.check(subject, object, operation).unwrap();
        let index = cap
            .operations
            .as_slice()
            .iter()
            .position(|right| right == operation)
            .unwrap();
        CapabilityHandleArg::from_record(cap, 1u64 << index, &[operation])
    }

    #[test]
    fn registry_only_verifies_artifact_identity_and_code_publisher_owns_publish_state() {
        let mut registry = ArtifactRegistry::new();
        let verified = registry.verify(image()).unwrap();
        assert_eq!(registry.verified().len(), 1);
        assert_eq!(verified.artifact_id, 1);

        let mut publisher = CodePublisher::new();
        let code_id = publisher.allocate(&verified).unwrap();
        assert_eq!(
            publisher.object(code_id).unwrap().state,
            CodeObjectState::AllocatedRw
        );
        assert_eq!(
            publisher.publish_rx(code_id),
            Err(CodePublisherError::InvalidTransition)
        );
        publisher.fill(code_id).unwrap();
        publisher.seal(code_id).unwrap();
        publisher.publish_rx(code_id).unwrap();
        assert_eq!(
            publisher.object(code_id).unwrap().text.permission,
            CodeRangePermission::ReadExecute
        );

        let mut stores = TargetStoreManager::new();
        let store_id =
            stores.register_verified_artifact(&verified, "restartable", "rebuild-from-artifact");
        stores.set_running(store_id).unwrap();
        let store_record = stores.record(store_id).unwrap().store.clone();
        publisher.bind_to_store(code_id, &store_record).unwrap();
        assert_eq!(
            publisher.object(code_id).unwrap().state,
            CodeObjectState::BoundToStore
        );
        assert_eq!(
            stores.record(store_id).unwrap().store.state,
            StoreState::Running
        );
    }

    #[test]
    fn registry_policy_rejects_manifest_binding_and_hash_mismatch() {
        let expected = ExpectedTargetArtifact::new(
            "driver_virtio_net",
            "driver_virtio_net.tart",
            "host-validation",
            "artifact-hash-1",
            "abi-1",
            "binding-1",
            "code-hash-1",
        );
        let mut expected_list = Vec::new();
        expected_list.push(expected);
        let mut registry = ArtifactRegistry::with_expected(expected_list);
        let mut bad = image();
        bad.code_hash = "hash-2".to_string();
        assert_eq!(
            registry.verify(bad),
            Err(ArtifactRegistryError::CodeHashMismatch)
        );

        let expected = ExpectedTargetArtifact::new(
            "driver_virtio_net",
            "driver_virtio_net.tart",
            "host-validation",
            "artifact-hash-1",
            "abi-1",
            "binding-1",
            "code-hash-1",
        );
        let mut expected_list = Vec::new();
        expected_list.push(expected);
        let mut registry = ArtifactRegistry::with_expected(expected_list);
        let mut bad = image();
        bad.artifact_hash = "artifact-hash-2".to_string();
        assert_eq!(
            registry.verify(bad),
            Err(ArtifactRegistryError::ArtifactHashMismatch)
        );

        let mut expected_list = Vec::new();
        expected_list.push(ExpectedTargetArtifact::new(
            "driver_virtio_net",
            "driver_virtio_net.tart",
            "host-validation",
            "artifact-hash-1",
            "abi-1",
            "binding-1",
            "code-hash-1",
        ));
        let mut registry = ArtifactRegistry::with_expected(expected_list);
        let verified = registry.verify(image()).unwrap();
        assert_eq!(verified.manifest_binding_hash, "binding-1");
    }

    #[test]
    fn hostcall_frame_v1_wire_abi_is_fixed_layout() {
        assert_eq!(
            ExecutorHostcallFrameV1::FRAME_SIZE as usize,
            core::mem::size_of::<ExecutorHostcallFrameV1>()
        );
        assert_eq!(
            ExecutorHostcallFrameV1::default().magic,
            ExecutorHostcallFrameV1::MAGIC
        );
        assert_eq!(
            ExecutorHostcallFrameV1::default().record_mode,
            RecordMode::Deterministic.as_u16()
        );
        assert_eq!(
            ExecutorHostcallFrameV1::default().ret_tag,
            HostcallReturnTag::Ok.as_u16()
        );
        assert_eq!(WireObjectRef::NULL, WireObjectRef::new(0, 0));
    }

    #[test]
    fn hostcall_capability_gate_allows_granted_mmio_and_traps_ungranted_privileged_hostcalls() {
        let (_artifact, store, code, capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut cap_args = Vec::new();
        cap_args.push(cap_arg_for(
            &capabilities,
            "driver_virtio_net",
            "mmio.virtio-net",
            "map",
        ));
        executor
            .invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    1,
                )
                .with_cap_args(cap_args)
                .to_wire_frame(),
                &capabilities,
            )
            .unwrap();
        assert!(executor.hostcall_trace()[0].allowed);
        assert_eq!(executor.hostcall_trace()[0].artifact_generation, 1);

        for (number, object, operation) in [
            (2, "mmio.denied", "map"),
            (3, "dma.denied", "map"),
            (4, "irq.denied", "bind"),
            (5, "dmw.denied", "open"),
            (6, "code-publish.denied", "publish"),
            (7, "packet-device.net0", "rx"),
            (9, "device.denied", "read"),
            (10, "virtqueue.denied", "kick"),
            (11, "timer.denied", "arm"),
            (12, "guest-memory.denied", "read"),
            (13, "snapshot.denied", "enter"),
            (14, "fault-domain.denied", "restart"),
            (15, "event-log.denied", "append"),
            (16, "store-control.denied", "kill"),
        ] {
            let activation = executor
                .start_activation(
                    &store.store,
                    &code,
                    ActivationEntry::Symbol("_start".to_string()),
                )
                .unwrap();
            assert_eq!(
                executor.invoke_hostcall(
                    &code,
                    HostcallFrame::new_bound(
                        activation,
                        &store.store,
                        &code,
                        number,
                        object,
                        operation,
                        1,
                    )
                    .to_wire_frame(),
                    &capabilities,
                ),
                Err(TargetExecutorError::CapabilityDenied)
            );
        }
        assert_eq!(executor.traps().len(), 14);
        assert!(
            executor
                .traps()
                .iter()
                .all(|trap| trap.class == TargetTrapClass::CapabilityTrap)
        );
        assert!(
            executor
                .event_log()
                .iter()
                .any(|event| event.contains("CapabilityDenied"))
        );
    }

    #[test]
    fn hostcall_rejects_code_object_attribution_mismatch() {
        let (_artifact, store, code, capabilities) = running_store_and_code();
        let mut other_code = code.clone();
        other_code.id = code.id + 100;
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        assert_eq!(
            executor.invoke_hostcall(
                &other_code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &other_code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    1,
                )
                .to_wire_frame(),
                &capabilities,
            ),
            Err(TargetExecutorError::CodeObjectMismatch)
        );
        assert_eq!(executor.traps()[0].class, TargetTrapClass::CodeObjectTrap);
    }

    #[test]
    fn hostcall_derives_subject_from_code_and_reports_bad_abi_with_trace() {
        let (_artifact, store, code, capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            &code,
            1,
            "mmio.virtio-net",
            "map",
            1,
        );
        let mut cap_args = Vec::new();
        cap_args.push(cap_arg_for(
            &capabilities,
            "driver_virtio_net",
            "mmio.virtio-net",
            "map",
        ));
        frame = frame.with_cap_args(cap_args);
        frame.subject = "other_store".to_string();
        executor
            .invoke_hostcall(&code, frame.to_wire_frame(), &capabilities)
            .unwrap();
        assert_eq!(executor.hostcall_trace()[0].subject, code.package);
        assert!(executor.hostcall_trace()[0].allowed);

        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            &code,
            1,
            "mmio.virtio-net",
            "map",
            1,
        );
        let mut wire_frame = frame.to_wire_frame();
        wire_frame.abi_version = 0;
        assert_eq!(
            executor.invoke_hostcall(&code, wire_frame, &capabilities),
            Err(TargetExecutorError::HostcallAbiMismatch)
        );
        assert!(
            executor
                .hostcall_trace()
                .iter()
                .any(|trace| trace.result == "bad-hostcall-abi")
        );
        assert!(
            executor
                .traps()
                .iter()
                .any(|trap| trap.class == TargetTrapClass::HostcallTrap
                    && trap.fault_policy == "bad-hostcall-abi")
        );

        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            &code,
            1,
            "mmio.virtio-net",
            "map",
            1,
        );
        let mut wire_frame = frame.to_wire_frame();
        wire_frame.frame_size = HostcallFrame::FRAME_SIZE + 8;
        assert_eq!(
            executor.invoke_hostcall(&code, wire_frame, &capabilities),
            Err(TargetExecutorError::HostcallAbiMismatch)
        );
        assert!(
            executor
                .hostcall_trace()
                .iter()
                .any(|trace| trace.result == "bad-frame-size"
                    && trace.ret_tag == HostcallReturnTag::BadAbi)
        );
    }

    #[test]
    fn cap_args_are_checked_against_ledger_generation_and_rights() {
        let (_artifact, store, code, capabilities) = running_store_and_code();
        let cap = capabilities
            .check("driver_virtio_net", "mmio.virtio-net", "map")
            .unwrap()
            .clone();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut cap_args = Vec::new();
        cap_args.push(CapabilityHandleArg::from_record(&cap, 1, &["map"]));
        executor
            .invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    cap.generation,
                )
                .with_cap_args(cap_args)
                .to_wire_frame(),
                &capabilities,
            )
            .unwrap();

        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut stale_cap_args = Vec::new();
        let mut stale_arg = CapabilityHandleArg::from_record(&cap, 1, &["map"]);
        stale_arg.handle_generation += 1;
        stale_cap_args.push(stale_arg);
        assert_eq!(
            executor.invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    cap.generation,
                )
                .with_cap_args(stale_cap_args)
                .to_wire_frame(),
                &capabilities,
            ),
            Err(TargetExecutorError::CapabilityDenied)
        );
        assert!(
            executor
                .hostcall_trace()
                .iter()
                .any(|trace| trace.result == "cap-arg-generation")
        );

        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut bad_mask_cap_args = Vec::new();
        bad_mask_cap_args.push(CapabilityHandleArg::from_record(&cap, 0, &["map"]));
        assert_eq!(
            executor.invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    cap.generation,
                )
                .with_cap_args(bad_mask_cap_args)
                .to_wire_frame(),
                &capabilities,
            ),
            Err(TargetExecutorError::CapabilityDenied)
        );
        assert!(
            executor
                .hostcall_trace()
                .iter()
                .any(|trace| trace.result == "cap-arg-rights-mask")
        );

        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut forged_global_id_args = Vec::new();
        let mut forged_global_id = CapabilityHandleArg::from_record(&cap, 1, &["map"]);
        forged_global_id.handle_slot =
            cap.object_ref.expect("authority object ref").object().id as u32;
        forged_global_id.handle_tag = 0;
        forged_global_id_args.push(forged_global_id);
        assert_eq!(
            executor.invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    cap.generation,
                )
                .with_cap_args(forged_global_id_args)
                .to_wire_frame(),
                &capabilities,
            ),
            Err(TargetExecutorError::CapabilityDenied)
        );
        assert!(
            executor
                .hostcall_trace()
                .iter()
                .any(|trace| trace.result == "cap-arg-missing" || trace.result == "cap-arg-tag")
        );
    }

    #[test]
    fn authority_matrix_covers_privileged_object_classes_and_fails_closed() {
        for (object, operation) in [
            ("mmio.regs", "read32"),
            ("dma.buf", "sync_for_device"),
            ("irq.net0", "ack"),
            ("dmw.window", "map_user_window"),
            ("code-publish.object", "publish"),
            ("snapshot.barrier", "enter"),
            ("packet-device.net0", "rx"),
            ("virtqueue.net0", "kick"),
            ("device.pulse", "read"),
            ("guest-memory.linear", "map"),
            ("timer.sleep", "arm"),
            ("fault-domain.driver", "restart"),
            ("event-log.store", "append"),
            ("store-control.driver", "kill"),
        ] {
            let decision = AuthorityMatrix::check(object, operation, false).unwrap();
            assert!(decision.requires_capability, "{object}:{operation}");
            assert!(decision.required_right.is_some(), "{object}:{operation}");
        }
        assert_eq!(
            AuthorityMatrix::check("mmio.regs", "teleport", false),
            Err(AuthorityMatrixError::UnknownOperation)
        );
        assert_eq!(
            AuthorityMatrix::check("unknown", "op", false),
            Err(AuthorityMatrixError::UnknownObjectClass)
        );
    }

    #[test]
    fn contract_graph_validator_reports_generation_dead_and_tombstone_edges() {
        let (artifact, store, code, _capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation_id = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let activation = executor
            .activations()
            .iter()
            .find(|activation| activation.id == activation_id)
            .unwrap()
            .clone();
        let mut stale_store = store.store.clone();
        stale_store.generation += 1;
        let mut retired_code = code.clone();
        retired_code.state = CodeObjectState::Retired;
        let tombstone = TombstoneRecord::new(
            ContractObjectKind::CodeObject,
            retired_code.id,
            retired_code.generation,
            42,
            "code-retired",
        );
        let trap = TargetTrapRecord {
            id: 99,
            generation: 1,
            class: TargetTrapClass::HostcallTrap,
            store: Some(stale_store.id),
            store_generation: Some(stale_store.generation),
            activation: Some(999),
            activation_generation: Some(1),
            code_object: Some(retired_code.id),
            code_generation: Some(retired_code.generation),
            artifact: Some(retired_code.artifact_id),
            artifact_generation: Some(1),
            offset: Some(0),
            target_pc: None,
            trap_kind: None,
            function_index: None,
            wasm_offset: None,
            debug_symbol: None,
            classification_status: None,
            hostcall: Some("hostcall.bad".to_string()),
            fault_policy: "debug".to_string(),
            effect: FailureEffect::CompleteWithErrno(22),
            detail: "dangling activation".to_string(),
        };
        let snapshot = ContractGraphSnapshot {
            artifacts: {
                let mut artifacts = Vec::new();
                artifacts.push(artifact);
                artifacts
            },
            code_objects: {
                let mut objects = Vec::new();
                objects.push(retired_code);
                objects
            },
            stores: {
                let mut stores = Vec::new();
                stores.push(stale_store);
                stores
            },
            activations: {
                let mut activations = Vec::new();
                activations.push(activation);
                activations
            },
            traps: {
                let mut traps = Vec::new();
                traps.push(trap);
                traps
            },
            hostcalls: Vec::new(),
            capabilities: Vec::new(),
            waits: Vec::new(),
            cleanup_transactions: Vec::new(),
            tombstones: {
                let mut tombstones = Vec::new();
                tombstones.push(tombstone);
                tombstones
            },
            external_objects: Vec::new(),
            explicit_edges: Vec::new(),
        };
        let violations = validate_contract_graph(&snapshot);
        assert!(violations.len() >= 4);
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::GenerationMismatch
                && violation.edge == "activation->store"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
                && violation.edge == "activation->code"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::TombstoneReferencedByLiveEdge
                && violation.edge == "activation->code"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::DanglingEdge
                && violation.edge == "trap->activation"
        }));
    }

    #[test]
    fn contract_graph_validator_rejects_cleanup_effect_mismatch() {
        let (artifact, store, code, capabilities) = running_store_and_code();
        let cleanup = FaultCleanupTransaction {
            id: 7,
            store: store.store.id,
            store_generation: store.store.generation,
            result_store_generation: Some(store.store.generation + 1),
            activation: None,
            activation_generation: None,
            code_object: Some(code.id),
            code_generation: Some(code.generation),
            generation: 1,
            started_at: 1,
            finished_at: Some(2),
            state: CleanupTransactionState::Completed,
            reason: "inconsistent-cleanup".to_string(),
            steps: Vec::new(),
            effects: Vec::new(),
            released_dmw_leases: 0,
            cancelled_waits: 0,
            revoked_capabilities: {
                let mut revoked = Vec::new();
                revoked.push(capabilities.records()[0].id);
                revoked
            },
            revoked_capability_refs: {
                let mut revoked = Vec::new();
                revoked.push(capabilities.records()[0].object_ref());
                revoked
            },
            dropped_resources: 1,
            unbound_code_object: true,
            effect: FailureEffect::CompleteWithErrno(5),
        };
        let snapshot = ContractGraphSnapshot {
            artifacts: {
                let mut artifacts = Vec::new();
                artifacts.push(artifact);
                artifacts
            },
            code_objects: {
                let mut objects = Vec::new();
                objects.push(code);
                objects
            },
            stores: {
                let mut stores = Vec::new();
                stores.push(store.store);
                stores
            },
            activations: Vec::new(),
            traps: Vec::new(),
            hostcalls: Vec::new(),
            capabilities: capabilities.records().to_vec(),
            waits: Vec::new(),
            cleanup_transactions: {
                let mut cleanups = Vec::new();
                cleanups.push(cleanup);
                cleanups
            },
            tombstones: Vec::new(),
            external_objects: Vec::new(),
            explicit_edges: Vec::new(),
        };
        let violations = validate_contract_graph(&snapshot);
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::GenerationMismatch
                && violation.edge == "cleanup->result-store"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
                && violation.edge == "cleanup->code"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
                && violation.edge == "cleanup->capability"
        }));
    }

    #[test]
    fn completed_cleanup_detects_code_still_bound_to_target_generation() {
        let (artifact, store, code, _capabilities) = running_store_and_code();
        let target_generation = store.store.generation;
        let mut dead_store = store.store.clone();
        dead_store.state = StoreState::Dead;
        dead_store.generation += 1;
        let cleanup = FaultCleanupTransaction {
            id: 19,
            store: dead_store.id,
            store_generation: target_generation,
            result_store_generation: Some(dead_store.generation),
            activation: None,
            activation_generation: None,
            code_object: Some(code.id),
            code_generation: Some(code.generation),
            generation: 1,
            started_at: 1,
            finished_at: Some(2),
            state: CleanupTransactionState::Completed,
            reason: "code-still-bound".to_string(),
            steps: Vec::new(),
            effects: Vec::new(),
            released_dmw_leases: 0,
            cancelled_waits: 0,
            revoked_capabilities: Vec::new(),
            revoked_capability_refs: Vec::new(),
            dropped_resources: 0,
            unbound_code_object: false,
            effect: FailureEffect::CompleteWithErrno(5),
        };
        let snapshot = ContractGraphSnapshot {
            artifacts: {
                let mut artifacts = Vec::new();
                artifacts.push(artifact);
                artifacts
            },
            code_objects: {
                let mut code_objects = Vec::new();
                code_objects.push(code);
                code_objects
            },
            stores: {
                let mut stores = Vec::new();
                stores.push(dead_store);
                stores
            },
            cleanup_transactions: {
                let mut cleanups = Vec::new();
                cleanups.push(cleanup);
                cleanups
            },
            tombstones: {
                let mut tombstones = Vec::new();
                tombstones.push(TombstoneRecord::new(
                    ContractObjectKind::Store,
                    store.store.id,
                    target_generation,
                    2,
                    "fault-cleanup-store-target-retired",
                ));
                tombstones
            },
            ..ContractGraphSnapshot::default()
        };
        let violations = validate_contract_graph(&snapshot);
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
                && violation.edge == "cleanup->code"
        }));
    }

    #[test]
    fn completed_cleanup_result_allows_rebound_store_with_result_tombstone() {
        let (_artifact, store, _code, _capabilities) = running_store_and_code();
        let target_generation = store.store.generation;
        let result_generation = target_generation + 1;
        let mut rebound_store = store.store.clone();
        rebound_store.state = StoreState::Running;
        rebound_store.generation = result_generation + 1;
        let cleanup = FaultCleanupTransaction {
            id: 23,
            store: rebound_store.id,
            store_generation: target_generation,
            result_store_generation: Some(result_generation),
            activation: None,
            activation_generation: None,
            code_object: None,
            code_generation: None,
            generation: 1,
            started_at: 1,
            finished_at: Some(2),
            state: CleanupTransactionState::Completed,
            reason: "old-cleanup-before-rebind".to_string(),
            steps: Vec::new(),
            effects: Vec::new(),
            released_dmw_leases: 0,
            cancelled_waits: 0,
            revoked_capabilities: Vec::new(),
            revoked_capability_refs: Vec::new(),
            dropped_resources: 0,
            unbound_code_object: false,
            effect: FailureEffect::CompleteWithErrno(5),
        };
        let snapshot = ContractGraphSnapshot {
            stores: {
                let mut stores = Vec::new();
                stores.push(rebound_store);
                stores
            },
            cleanup_transactions: {
                let mut cleanups = Vec::new();
                cleanups.push(cleanup);
                cleanups
            },
            tombstones: {
                let mut tombstones = Vec::new();
                tombstones.push(TombstoneRecord::new(
                    ContractObjectKind::Store,
                    store.store.id,
                    target_generation,
                    2,
                    "fault-cleanup-store-target-retired",
                ));
                tombstones.push(TombstoneRecord::new(
                    ContractObjectKind::Store,
                    store.store.id,
                    result_generation,
                    2,
                    "fault-cleanup-store-dead",
                ));
                tombstones
            },
            ..ContractGraphSnapshot::default()
        };
        assert_eq!(validate_contract_graph(&snapshot), Vec::new());
    }

    #[test]
    fn contract_graph_validator_allows_historical_hostcall_to_tombstoned_generation() {
        let (artifact, store, code, capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut cap_args = Vec::new();
        cap_args.push(cap_arg_for(
            &capabilities,
            "driver_virtio_net",
            "mmio.virtio-net",
            "map",
        ));
        executor
            .invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    1,
                )
                .with_cap_args(cap_args)
                .to_wire_frame(),
                &capabilities,
            )
            .unwrap();
        let mut current_code = code.clone();
        let historical_generation = current_code.generation;
        current_code.generation += 1;
        let mut activation_record = executor.activations()[0].clone();
        activation_record.code_generation = current_code.generation;
        let mut trace = executor.hostcall_trace()[0].clone();
        assert_eq!(trace.activation_generation, 1);
        assert_eq!(activation_record.generation, 2);
        trace.code_generation = historical_generation;
        let snapshot = ContractGraphSnapshot {
            artifacts: {
                let mut artifacts = Vec::new();
                artifacts.push(artifact);
                artifacts
            },
            code_objects: {
                let mut objects = Vec::new();
                objects.push(current_code);
                objects
            },
            stores: {
                let mut stores = Vec::new();
                stores.push(store.store);
                stores
            },
            activations: {
                let mut activations = Vec::new();
                activations.push(activation_record);
                activations
            },
            traps: Vec::new(),
            hostcalls: {
                let mut hostcalls = Vec::new();
                hostcalls.push(trace);
                hostcalls
            },
            capabilities: Vec::new(),
            waits: Vec::new(),
            cleanup_transactions: Vec::new(),
            tombstones: {
                let mut tombstones = executor.tombstones().to_vec();
                tombstones.push(TombstoneRecord::new(
                    ContractObjectKind::CodeObject,
                    code.id,
                    historical_generation,
                    99,
                    "code-generation-retired",
                ));
                tombstones
            },
            external_objects: Vec::new(),
            explicit_edges: Vec::new(),
        };
        let violations = validate_contract_graph(&snapshot);
        assert!(!violations.iter().any(|violation| {
            violation.edge == "hostcall->code"
                && matches!(
                    violation.kind,
                    ContractViolationKind::GenerationMismatch
                        | ContractViolationKind::TombstoneReferencedByLiveEdge
                )
        }));
    }

    #[test]
    fn contract_graph_validator_enforces_live_cleanup_and_external_edges() {
        let (artifact, store, code, capabilities) = running_store_and_code();
        let mut dead_store = store.store.clone();
        dead_store.state = StoreState::Dead;
        let mut activation = ActivationRecord {
            id: 55,
            store: dead_store.id,
            store_generation: dead_store.generation,
            code_object: code.id,
            code_generation: code.generation,
            artifact: code.artifact_id,
            entry: ActivationEntry::Symbol("_start".to_string()),
            generation: 1,
            state: ActivationState::Running,
            start_event: 1,
            exit_event: None,
            active_dmw_leases: 1,
            blocked_wait: None,
            trap: None,
            return_tag: None,
        };
        activation.active_dmw_leases = 1;
        let wait = WaitRecord {
            id: 77,
            owner_task: None,
            owner_task_generation: None,
            owner_store: Some(dead_store.id),
            owner_store_generation: Some(dead_store.generation),
            kind: SemanticWaitKind::Futex,
            generation: 1,
            state: WaitState::Pending,
            blockers: {
                let mut blockers = Vec::new();
                blockers.push(ContractObjectRef::new(ContractObjectKind::Resource, 1, 1));
                blockers
            },
            deadline: None,
            cancel_reason: None,
            restart_policy: RestartPolicy::RestartIfAllowed,
            saved_context: None,
        };
        let snapshot = ContractGraphSnapshot {
            artifacts: {
                let mut artifacts = Vec::new();
                artifacts.push(artifact);
                artifacts
            },
            code_objects: {
                let mut objects = Vec::new();
                objects.push(code.clone());
                objects
            },
            stores: {
                let mut stores = Vec::new();
                stores.push(dead_store.clone());
                stores
            },
            activations: {
                let mut activations = Vec::new();
                activations.push(activation);
                activations
            },
            traps: Vec::new(),
            hostcalls: Vec::new(),
            capabilities: capabilities.records().to_vec(),
            waits: {
                let mut waits = Vec::new();
                waits.push(wait);
                waits
            },
            cleanup_transactions: Vec::new(),
            tombstones: {
                let mut tombstones = Vec::new();
                tombstones.push(TombstoneRecord::new(
                    ContractObjectKind::CodeObject,
                    code.id,
                    code.generation + 1,
                    99,
                    "old-code-generation",
                ));
                tombstones
            },
            external_objects: Vec::new(),
            explicit_edges: {
                let mut edges = Vec::new();
                edges.push(ContractEdgeRecord::new(
                    dead_store.object_ref(),
                    ContractObjectRef::new(
                        ContractObjectKind::CodeObject,
                        code.id,
                        code.generation + 1,
                    ),
                    ContractEdgeMode::Live,
                    "store->stale-code-live",
                    1,
                ));
                edges.push(ContractEdgeRecord::new(
                    dead_store.object_ref(),
                    ContractObjectRef::new(
                        ContractObjectKind::CodeObject,
                        code.id,
                        code.generation + 2,
                    ),
                    ContractEdgeMode::Historical,
                    "store->missing-code-history",
                    1,
                ));
                edges.push(ContractEdgeRecord::new(
                    dead_store.object_ref(),
                    capabilities.records()[0].object_ref(),
                    ContractEdgeMode::CleanupEffect,
                    "owns",
                    1,
                ));
                edges.push(
                    ContractEdgeRecord::new(
                        dead_store.object_ref(),
                        ContractObjectRef::new(ContractObjectKind::ExternalObject, 41, 0),
                        ContractEdgeMode::External,
                        "store->external-device",
                        1,
                    )
                    .with_external_metadata("pci", "device"),
                );
                edges
            },
        };
        let violations = validate_contract_graph(&snapshot);
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
                && violation.edge == "activation->store"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
                && violation.edge == "activation->dmw-lease"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::LiveEdgeReferencesInactiveObject
                && violation.edge == "capability->owner-store"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::LiveEdgeReferencesInactiveObject
                && violation.edge == "wait->owner-store"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::TombstoneReferencedByLiveEdge
                && violation.edge == "store->stale-code-live"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::GenerationMismatch
                && violation.edge == "store->missing-code-history"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::CleanupEffectCreatesLiveOwnership
                && violation.edge == "owns"
        }));
        assert!(violations.iter().any(|violation| {
            violation.kind == ContractViolationKind::ExternalEdgeMissingDeclaration
                && violation.edge == "store->external-device"
        }));
    }

    #[test]
    fn contract_graph_validator_allows_historical_cleanup_and_declared_external_edges() {
        let (artifact, store, code, capabilities) = running_store_and_code();
        let mut current_store = store.store.clone();
        let historical_store_generation = current_store.generation;
        current_store.generation += 1;
        let mut revoked_capability = capabilities.records()[0].clone();
        revoked_capability.revoked = true;
        let cleanup = FaultCleanupTransaction {
            id: 17,
            store: current_store.id,
            store_generation: current_store.generation,
            result_store_generation: None,
            activation: None,
            activation_generation: None,
            code_object: None,
            code_generation: None,
            generation: 1,
            started_at: 1,
            finished_at: None,
            state: CleanupTransactionState::Pending,
            reason: "edge-mode-test".to_string(),
            steps: Vec::new(),
            effects: Vec::new(),
            released_dmw_leases: 0,
            cancelled_waits: 0,
            revoked_capabilities: Vec::new(),
            revoked_capability_refs: Vec::new(),
            dropped_resources: 0,
            unbound_code_object: false,
            effect: FailureEffect::CompleteWithErrno(5),
        };
        let trap = TargetTrapRecord {
            id: 23,
            generation: 1,
            class: TargetTrapClass::SupervisorStoreTrap,
            store: Some(current_store.id),
            store_generation: Some(historical_store_generation),
            activation: None,
            activation_generation: None,
            code_object: None,
            code_generation: None,
            artifact: None,
            artifact_generation: None,
            offset: None,
            target_pc: None,
            trap_kind: None,
            function_index: None,
            wasm_offset: None,
            debug_symbol: None,
            classification_status: None,
            hostcall: None,
            fault_policy: "history-only".to_string(),
            effect: FailureEffect::CompleteWithErrno(5),
            detail: "store history".to_string(),
        };
        let external = ExternalObjectDeclaration::new(
            ContractObjectRef::new(ContractObjectKind::ExternalObject, 9, 0),
            "pci",
            "device",
            "virtio-net",
        );
        let snapshot = ContractGraphSnapshot {
            artifacts: {
                let mut artifacts = Vec::new();
                artifacts.push(artifact);
                artifacts
            },
            code_objects: {
                let mut objects = Vec::new();
                objects.push(code.clone());
                objects
            },
            stores: {
                let mut stores = Vec::new();
                stores.push(current_store.clone());
                stores
            },
            activations: Vec::new(),
            traps: {
                let mut traps = Vec::new();
                traps.push(trap.clone());
                traps
            },
            hostcalls: {
                let mut hostcalls = Vec::new();
                hostcalls.push(HostcallTraceRecord {
                    id: 31,
                    generation: 1,
                    abi_version: HostcallFrame::ABI_VERSION.to_string(),
                    frame_size: HostcallFrame::FRAME_SIZE,
                    flags: 0,
                    activation: 44,
                    activation_generation: 1,
                    store: current_store.id,
                    store_generation: current_store.generation,
                    code_object: code.id,
                    code_generation: code.generation,
                    artifact: code.artifact_id,
                    artifact_generation: 1,
                    hostcall_number: 1,
                    hostcall_seq: 1,
                    caller_offset: 0,
                    name: "hostcall.history".to_string(),
                    category: HostcallCategory::Mmio,
                    subject: code.package.clone(),
                    object: "mmio.virtio-net".to_string(),
                    operation: "map".to_string(),
                    args: [0; 6],
                    cap_args: Vec::new(),
                    record_mode: RecordMode::Deterministic,
                    allowed: true,
                    result: "ok".to_string(),
                    ret_tag: HostcallReturnTag::Ok,
                    ret0: 0,
                    ret1: 0,
                    trap_out: None,
                    trap_generation_out: None,
                    wait_token_out: None,
                    wait_token_generation_out: None,
                });
                hostcalls
            },
            capabilities: {
                let mut caps = Vec::new();
                caps.push(revoked_capability.clone());
                caps
            },
            waits: Vec::new(),
            cleanup_transactions: {
                let mut cleanups = Vec::new();
                cleanups.push(cleanup.clone());
                cleanups
            },
            tombstones: {
                let mut tombstones = Vec::new();
                tombstones.push(TombstoneRecord::new(
                    ContractObjectKind::Store,
                    current_store.id,
                    historical_store_generation,
                    70,
                    "store-rebound",
                ));
                tombstones.push(TombstoneRecord::new(
                    ContractObjectKind::Activation,
                    44,
                    1,
                    71,
                    "activation-finished",
                ));
                tombstones
            },
            external_objects: {
                let mut external_objects = Vec::new();
                external_objects.push(external.clone());
                external_objects
            },
            explicit_edges: {
                let mut edges = Vec::new();
                edges.push(ContractEdgeRecord::new(
                    trap.object_ref(),
                    ContractObjectRef::new(
                        ContractObjectKind::Store,
                        current_store.id,
                        historical_store_generation,
                    ),
                    ContractEdgeMode::Historical,
                    "trap->store-history",
                    72,
                ));
                edges.push(ContractEdgeRecord::new(
                    cleanup.object_ref(),
                    revoked_capability.object_ref(),
                    ContractEdgeMode::CleanupEffect,
                    "cleanup->capability-revoked",
                    73,
                ));
                edges.push(
                    ContractEdgeRecord::new(
                        current_store.object_ref(),
                        external.object,
                        ContractEdgeMode::External,
                        "store->declared-external",
                        74,
                    )
                    .with_external_metadata("pci", "device"),
                );
                edges
            },
        };
        let violations = validate_contract_graph(&snapshot);
        assert!(!violations.iter().any(|violation| {
            violation.edge == "trap->store-history"
                || violation.edge == "cleanup->capability-revoked"
                || violation.edge == "store->declared-external"
                || violation.edge == "hostcall->activation"
        }));
    }

    #[test]
    fn fault_cleanup_transaction_is_idempotent_and_closes_owned_state() {
        let (_artifact, store, code, mut capabilities) = running_store_and_code();
        let mut store = store.store.clone();
        let mut code = code.clone();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(&store, &code, ActivationEntry::Symbol("_start".to_string()))
            .unwrap();
        executor
            .acquire_dmw_lease(activation, "dmw.cleanup.lease")
            .unwrap();
        assert_eq!(
            executor.snapshot_barrier(),
            Err(TargetExecutorError::DmwLeaseActive)
        );

        let cleanup_id = executor
            .run_fault_cleanup(
                &mut store,
                Some(activation),
                Some(&mut code),
                &mut capabilities,
                "fault-cleanup-test",
            )
            .unwrap();
        let cleanup = &executor.cleanup_transactions()[0];
        assert_eq!(cleanup.id, cleanup_id);
        assert_eq!(cleanup.state, CleanupTransactionState::Completed);
        assert_eq!(cleanup.released_dmw_leases, 1);
        assert_eq!(cleanup.cancelled_waits, 0);
        assert_eq!(cleanup.revoked_capabilities.len(), 1);
        assert_eq!(cleanup.dropped_resources, 1);
        assert!(cleanup.unbound_code_object);
        assert!(
            cleanup
                .steps
                .iter()
                .all(|step| step.state == CleanupStepState::Done)
        );
        assert!(
            executor
                .dmw_leases()
                .iter()
                .all(|lease| !lease.active && lease.generation == 2)
        );
        let activation_record = executor
            .activations()
            .iter()
            .find(|record| record.id == activation)
            .unwrap();
        assert_eq!(activation_record.state, ActivationState::Dropped);
        assert_eq!(activation_record.active_dmw_leases, 0);
        assert_eq!(
            activation_record.return_tag,
            Some(HostcallReturnTag::KillStore)
        );
        assert_eq!(store.state, StoreState::Dead);
        assert_eq!(code.state, CodeObjectState::Retired);
        assert_eq!(code.bound_store, None);
        assert!(capabilities.records().iter().all(|record| record.revoked));
        assert!(
            executor
                .tombstones()
                .iter()
                .any(|tombstone| tombstone.kind == ContractObjectKind::Store
                    && tombstone.id == store.id
                    && tombstone.generation == store.generation)
        );
        assert!(
            cleanup
                .effects
                .iter()
                .any(|effect| effect.kind == CleanupEffectKind::MarkStoreDead
                    && effect.status == CleanupEffectStatus::Applied
                    && effect.target == store.object_ref())
        );
        let digest_after_once = executor.cleanup_state_digest(&store, Some(&code), &capabilities);
        assert_eq!(executor.snapshot_barrier(), Ok(()));
        let completed_cleanup = &executor.cleanup_transactions()[0];
        assert_eq!(
            completed_cleanup.result_store_generation,
            Some(store.generation)
        );
        assert_eq!(
            completed_cleanup.activation_generation,
            Some(activation_record.generation)
        );
        assert_eq!(completed_cleanup.code_generation, Some(code.generation));

        let cleanup_id_again = executor
            .run_fault_cleanup(
                &mut store,
                Some(activation),
                Some(&mut code),
                &mut capabilities,
                "fault-cleanup-test",
            )
            .unwrap();
        assert_eq!(cleanup_id_again, cleanup_id);
        assert_eq!(executor.cleanup_transactions().len(), 1);
        assert_eq!(
            executor.cleanup_state_digest(&store, Some(&code), &capabilities),
            digest_after_once
        );
        assert_eq!(
            executor.cleanup_transactions()[0]
                .revoked_capabilities
                .len(),
            1
        );
    }

    #[test]
    fn completed_cleanup_for_old_generation_does_not_suppress_rebound_generation() {
        let (_artifact, store, code, mut capabilities) = running_store_and_code();
        let mut old_store = store.store.clone();
        let mut old_code = code.clone();
        let mut executor = TargetExecutor::new();

        let old_cleanup = executor
            .run_fault_cleanup(
                &mut old_store,
                None,
                Some(&mut old_code),
                &mut capabilities,
                "same-fault",
            )
            .unwrap();
        assert_eq!(old_store.state, StoreState::Dead);

        let mut rebound_store = old_store.clone();
        rebound_store.state = StoreState::Running;
        let mut rebound_code = old_code.clone();
        rebound_code.state = CodeObjectState::BoundToStore;
        rebound_code.bound_store = Some(rebound_store.id);
        rebound_code.bound_store_generation = Some(rebound_store.generation);
        rebound_code.generation += 1;

        let next_cleanup = executor
            .run_fault_cleanup(
                &mut rebound_store,
                None,
                Some(&mut rebound_code),
                &mut capabilities,
                "same-fault",
            )
            .unwrap();

        assert_ne!(next_cleanup, old_cleanup);
        assert_eq!(executor.cleanup_transactions().len(), 2);
        assert_eq!(rebound_store.state, StoreState::Dead);
        assert_eq!(rebound_code.bound_store, None);
    }

    #[test]
    fn fault_cleanup_stale_generation_is_visible_and_does_not_mutate_rebound_store() {
        let (_artifact, store, mut code, mut capabilities) = running_store_and_code();
        let mut store = store.store.clone();
        let mut executor = TargetExecutor::new();
        let cleanup_id = executor.begin_fault_cleanup_transaction(
            &store,
            None,
            Some(&code),
            "stale-cleanup-test",
        );
        assert_eq!(
            executor.snapshot_barrier(),
            Err(TargetExecutorError::PendingCleanupActive)
        );

        store.generation += 1;
        store.state = StoreState::Running;
        let digest_before = executor.cleanup_state_digest(&store, Some(&code), &capabilities);
        executor
            .apply_fault_cleanup_transaction(
                cleanup_id,
                &mut store,
                Some(&mut code),
                &mut capabilities,
            )
            .unwrap();
        assert_eq!(store.state, StoreState::Running);
        assert_eq!(code.state, CodeObjectState::BoundToStore);
        assert_eq!(code.bound_store, Some(store.id));
        assert!(capabilities.records().iter().all(|record| !record.revoked));
        assert_eq!(
            executor.cleanup_state_digest(&store, Some(&code), &capabilities),
            digest_before
        );
        let cleanup = &executor.cleanup_transactions()[0];
        assert_eq!(
            cleanup.state,
            CleanupTransactionState::SkippedStaleGeneration
        );
        assert!(cleanup.steps.iter().all(|step| step.state
            == CleanupStepState::SkippedStaleGeneration
            && step.observed_generation == Some(store.generation)));
        assert!(cleanup.effects.iter().any(|effect| {
            effect.status == CleanupEffectStatus::SkippedStaleGeneration
                && effect.target
                    == ContractObjectRef::new(
                        ContractObjectKind::Store,
                        store.id,
                        store.generation - 1,
                    )
        }));
        assert_eq!(executor.snapshot_barrier(), Ok(()));
    }

    #[test]
    fn fault_cleanup_cancels_blocked_wait_and_pending_cleanup_blocks_snapshot() {
        let (_artifact, store, code, mut capabilities) = running_store_and_code();
        let mut store = store.store.clone();
        let mut code = code.clone();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(&store, &code, ActivationEntry::Symbol("_start".to_string()))
            .unwrap();
        executor.pending_exit(activation, 77).unwrap();
        assert_eq!(
            executor
                .activations()
                .iter()
                .find(|record| record.id == activation)
                .unwrap()
                .blocked_wait,
            Some(77)
        );

        let cleanup_id = executor
            .run_fault_cleanup(
                &mut store,
                Some(activation),
                Some(&mut code),
                &mut capabilities,
                "wait-cleanup-test",
            )
            .unwrap();
        let cleanup = executor
            .cleanup_transactions()
            .iter()
            .find(|cleanup| cleanup.id == cleanup_id)
            .unwrap();
        assert_eq!(cleanup.cancelled_waits, 1);
        let activation_record = executor
            .activations()
            .iter()
            .find(|record| record.id == activation)
            .unwrap();
        assert_eq!(activation_record.state, ActivationState::Dropped);
        assert_eq!(activation_record.blocked_wait, None);

        let (_artifact, store, code, _capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        executor.begin_fault_cleanup_transaction(
            &store.store,
            None,
            Some(&code),
            "pending-cleanup-test",
        );
        assert_eq!(
            executor.snapshot_barrier(),
            Err(TargetExecutorError::PendingCleanupActive)
        );
    }

    #[test]
    fn dmw_handle_mode_lease_cannot_cross_pending_or_snapshot_barrier() {
        let (_artifact, store, code, capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let lease = executor
            .acquire_dmw_lease(activation, "dmw.handle.1")
            .unwrap();
        assert_eq!(
            executor.snapshot_barrier(),
            Err(TargetExecutorError::DmwLeaseActive)
        );
        assert_eq!(
            executor.invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    8,
                    "wait.timer",
                    "park",
                    1,
                )
                .to_wire_frame(),
                &capabilities,
            ),
            Err(TargetExecutorError::DmwLeaseActive)
        );
        assert_eq!(executor.traps()[0].class, TargetTrapClass::WindowTrap);
        assert!(!executor.dmw_leases()[0].active);
        executor.release_dmw_lease(lease).unwrap();
        assert_eq!(executor.snapshot_barrier(), Ok(()));
    }

    #[test]
    fn typed_trap_surface_and_migration_classification_are_queryable() {
        let (_artifact, store, code, _capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        for class in [
            TargetTrapClass::GuestTrap,
            TargetTrapClass::SupervisorStoreTrap,
            TargetTrapClass::CapabilityTrap,
            TargetTrapClass::WindowTrap,
            TargetTrapClass::HostcallTrap,
            TargetTrapClass::CodeObjectTrap,
            TargetTrapClass::SubstrateFault,
        ] {
            executor.synthetic_trap(
                class,
                store.store.id,
                Some(activation),
                Some(&code),
                None,
                "typed trap harness",
            );
        }
        assert_eq!(executor.traps().len(), 7);
        assert!(
            executor
                .traps()
                .iter()
                .any(|trap| trap.class == TargetTrapClass::CodeObjectTrap
                    && trap.code_object == Some(code.id)
                    && trap.artifact == Some(code.artifact_id))
        );
        let migration = executor.classify_migration_objects(core::slice::from_ref(&code));
        assert!(
            migration
                .iter()
                .any(|record| record.class == MigrationObjectClass::Migrated)
        );
        assert!(
            migration
                .iter()
                .any(|record| record.class == MigrationObjectClass::Rebuilt)
        );
        assert!(
            migration
                .iter()
                .any(|record| record.class == MigrationObjectClass::NeverMigrated)
        );
    }

    #[test]
    fn trap_record_uses_historical_refs() {
        let (_artifact, store, code, _capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("entry_trap_ebreak".to_string()),
            )
            .unwrap();
        let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
        let trap_map = [TrapMapEntryV1::new(
            ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
            offset,
            offset + 4,
            TrapKindV1::WasmUnreachable,
            1,
            0x20,
            7,
        )];

        let trap_id = executor
            .trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map)
            .unwrap();
        let trap = executor
            .traps()
            .iter()
            .find(|trap| trap.id == trap_id)
            .unwrap();

        assert_eq!(trap.store, Some(store.store.id));
        assert_eq!(trap.store_generation, Some(store.store.generation));
        assert_eq!(trap.activation, Some(activation));
        assert!(trap.activation_generation.is_some());
        assert_eq!(trap.code_object, Some(code.id));
        assert_eq!(trap.code_generation, Some(code.generation));
        assert_eq!(trap.artifact, Some(code.artifact_id));
        assert_eq!(
            trap.artifact_generation,
            Some(TARGET_ARTIFACT_GENERATION_V1)
        );
        assert_eq!(trap.offset, Some(offset));
        assert_eq!(trap.trap_kind.as_deref(), Some("wasm-unreachable"));
        assert_eq!(
            trap.classification_status.as_deref(),
            Some("wasm-unreachable")
        );
    }

    #[test]
    fn cleanup_targets_exact_store_generation() {
        let (_artifact, mut store, mut code, mut capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("entry_trap_ebreak".to_string()),
            )
            .unwrap();
        let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
        let trap_map = [TrapMapEntryV1::new(
            ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
            offset,
            offset + 4,
            TrapKindV1::WasmUnreachable,
            1,
            0x20,
            7,
        )];
        executor
            .trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map)
            .unwrap();
        let fault_generation = store.store.generation;

        let cleanup_id = executor
            .run_fault_cleanup(
                &mut store.store,
                Some(activation),
                Some(&mut code),
                &mut capabilities,
                "trap-cleanup",
            )
            .unwrap();
        let cleanup = executor
            .cleanup_transactions()
            .iter()
            .find(|cleanup| cleanup.id == cleanup_id)
            .unwrap();

        assert_eq!(cleanup.store_generation, fault_generation);
        assert_eq!(cleanup.result_store_generation, Some(fault_generation + 1));
    }

    #[test]
    fn trap_exit_rejects_code_object_attribution_mismatch() {
        let (_artifact, store, code, _capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("entry_trap_ebreak".to_string()),
            )
            .unwrap();
        let mut wrong_code = code.clone();
        wrong_code.id += 1;
        let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
        let trap_map = [TrapMapEntryV1::new(
            ObjectRefRaw::new(
                OBJECT_KIND_CODE_OBJECT_V1,
                wrong_code.id,
                wrong_code.generation,
            ),
            offset,
            offset + 4,
            TrapKindV1::WasmUnreachable,
            1,
            0x20,
            7,
        )];

        let result = executor.trap_exit_by_pc(
            activation,
            &wrong_code,
            wrong_code.text.start + offset,
            &trap_map,
        );

        assert_eq!(result, Err(TargetExecutorError::CodeObjectMismatch));
        let trap = executor.traps().last().expect("mismatch trap is visible");
        assert_eq!(trap.class, TargetTrapClass::CodeObjectTrap);
        assert_eq!(trap.fault_policy, "trap-attribution-failure");
        assert_eq!(trap.activation, Some(activation));
        assert!(trap.activation_generation.is_some());
    }
}
