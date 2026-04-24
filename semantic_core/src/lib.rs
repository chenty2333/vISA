#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub type TaskId = u32;
pub type ResourceId = u64;
pub type CapabilityId = u64;
pub type FaultDomainId = u64;
pub type EventId = u64;
pub type WaitId = u64;
pub type Generation = u64;
pub type SnapshotBarrierId = u64;
pub type StoreId = u64;
pub type TransactionId = u64;
pub type PlanId = u64;
pub type AuthorityId = u64;
pub type BoundaryId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeMode {
    Research,
    Production,
    Replay,
}

impl RuntimeMode {
    pub const fn all() -> [Self; 3] {
        [Self::Research, Self::Production, Self::Replay]
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "research" => Some(Self::Research),
            "production" => Some(Self::Production),
            "replay" => Some(Self::Replay),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Research => "research",
            Self::Production => "production",
            Self::Replay => "replay",
        }
    }

    pub const fn event_log_policy(self) -> &'static str {
        match self {
            Self::Research => "full",
            Self::Production => "sampled",
            Self::Replay => "deterministic",
        }
    }

    pub const fn dmw_policy(self) -> &'static str {
        match self {
            Self::Research => "strict-quarantine",
            Self::Production => "aggressive-reuse",
            Self::Replay => "barrier-locked",
        }
    }

    pub const fn fast_path_enabled(self) -> bool {
        matches!(self, Self::Production)
    }

    pub const fn deterministic_boundary(self) -> bool {
        matches!(self, Self::Replay)
    }

    pub const fn capability_audit_policy(self) -> &'static str {
        match self {
            Self::Research => "full",
            Self::Production => "sampled",
            Self::Replay => "deterministic",
        }
    }

    pub const fn debug_metadata_policy(self) -> &'static str {
        match self {
            Self::Research => "full",
            Self::Production => "reduced",
            Self::Replay => "log-derived",
        }
    }

    pub const fn nondeterminism_policy(self) -> &'static str {
        match self {
            Self::Research => "record-at-boundary",
            Self::Production => "record-sampled-boundary",
            Self::Replay => "read-from-event-log",
        }
    }
}

impl Default for RuntimeMode {
    fn default() -> Self {
        Self::Research
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryKind {
    ArtifactLoader,
    RuntimeExecutor,
    HostcallTable,
    Dmw,
    Dma,
    Mmio,
    Irq,
    PacketDevice,
    NetworkStack,
    TargetExecutor,
    FastPath,
    SnapshotReplay,
    StoreLifecycle,
    AuthorityPlane,
}

impl BoundaryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactLoader => "artifact-loader",
            Self::RuntimeExecutor => "runtime-executor",
            Self::HostcallTable => "hostcall-table",
            Self::Dmw => "dmw",
            Self::Dma => "dma",
            Self::Mmio => "mmio",
            Self::Irq => "irq",
            Self::PacketDevice => "packet-device",
            Self::NetworkStack => "network-stack",
            Self::TargetExecutor => "target-executor",
            Self::FastPath => "fastpath",
            Self::SnapshotReplay => "snapshot-replay",
            Self::StoreLifecycle => "store-lifecycle",
            Self::AuthorityPlane => "authority-plane",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryStatus {
    ManifestBacked,
    RuntimeContract,
    NotLinked,
    Logical,
    SemanticResource,
    Toy,
    HostSide,
    EventOnly,
    PackageOnly,
    ManagerOwned,
    LifecycleObject,
    CodePublished,
    HostcallsLinked,
    Runnable,
}

impl BoundaryStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManifestBacked => "manifest-backed",
            Self::RuntimeContract => "runtime-contract",
            Self::NotLinked => "not-linked",
            Self::Logical => "logical",
            Self::SemanticResource => "semantic-resource",
            Self::Toy => "toy",
            Self::HostSide => "host-side",
            Self::EventOnly => "event-only",
            Self::PackageOnly => "package-only",
            Self::ManagerOwned => "manager-owned",
            Self::LifecycleObject => "lifecycle-object",
            Self::CodePublished => "code-published",
            Self::HostcallsLinked => "hostcalls-linked",
            Self::Runnable => "runnable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryRecord {
    pub id: BoundaryId,
    pub name: String,
    pub kind: BoundaryKind,
    pub status: BoundaryStatus,
    pub backend: String,
    pub blocked_by: Option<String>,
    pub generation: Generation,
}

impl BoundaryRecord {
    pub fn summary(&self) -> String {
        let blocked_by = self
            .blocked_by
            .as_ref()
            .map(String::as_str)
            .unwrap_or("none");
        format!(
            "boundary {} kind={} status={} backend={} blocked={} generation={}",
            self.name,
            self.kind.as_str(),
            self.status.as_str(),
            self.backend,
            blocked_by,
            self.generation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceHandle {
    pub id: ResourceId,
    pub generation: Generation,
}

impl ResourceHandle {
    pub const fn new(id: ResourceId, generation: Generation) -> Self {
        Self { id, generation }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitHandle {
    pub id: WaitId,
    pub generation: Generation,
}

impl WaitHandle {
    pub const fn new(id: WaitId, generation: Generation) -> Self {
        Self { id, generation }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreHandle {
    pub id: StoreId,
    pub generation: Generation,
}

impl StoreHandle {
    pub const fn new(id: StoreId, generation: Generation) -> Self {
        Self { id, generation }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationCheckError {
    Missing,
    Dead {
        actual: Generation,
    },
    GenerationMismatch {
        expected: Generation,
        actual: Option<Generation>,
    },
}

impl GenerationCheckError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Dead { .. } => "dead",
            Self::GenerationMismatch { .. } => "generation-mismatch",
        }
    }
}

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
pub enum TaskState {
    Runnable,
    Running,
    Pending,
    Cancelled,
    Faulted,
    Exited,
    SnapshotFrozen,
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
pub enum ResourceKind {
    Fd,
    Timer,
    Futex,
    Epoll,
    Device,
    PacketDevice,
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
    Pending,
    Ready,
    Cancelled,
    Restarted,
}

impl WaitState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Cancelled => "cancelled",
            Self::Restarted => "restarted",
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
    Instantiating,
    Running,
    Degraded,
    Draining,
    Restarting,
    Rebinding,
    Dead,
}

impl StoreState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Instantiating => "instantiating",
            Self::Running => "running",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Restarting => "restarting",
            Self::Rebinding => "rebinding",
            Self::Dead => "dead",
        }
    }

    pub const fn fault_domain_state(self) -> FaultDomainState {
        match self {
            Self::Created => FaultDomainState::Created,
            Self::Instantiating | Self::Rebinding => FaultDomainState::Initializing,
            Self::Running => FaultDomainState::Running,
            Self::Degraded => FaultDomainState::Degraded,
            Self::Draining => FaultDomainState::Draining,
            Self::Restarting => FaultDomainState::Restarting,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSet {
    operations: Vec<String>,
}

impl OperationSet {
    pub fn from_static(operations: &[&str]) -> Self {
        Self {
            operations: operations.iter().map(|op| (*op).to_string()).collect(),
        }
    }

    pub fn contains_all(&self, requested: &[&str]) -> bool {
        requested
            .iter()
            .all(|requested| self.operations.iter().any(|op| op == requested))
    }

    pub fn contains(&self, requested: &str) -> bool {
        self.operations.iter().any(|op| op == requested)
    }

    pub fn as_slice(&self) -> &[String] {
        &self.operations
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityClass {
    ServiceImport,
    Device,
    PacketDevice,
    MmioRegion,
    DmaBuffer,
    IrqLine,
    VirtioQueue,
    DmwWindow,
    Timer,
    Snapshot,
    FaultDomain,
    NetInterface,
    NetSocket,
    GuestMemoryAccess,
}

impl CapabilityClass {
    pub fn from_object(object: &str) -> Self {
        if object.starts_with("packet-device.") {
            Self::PacketDevice
        } else if object.starts_with("device.") {
            Self::Device
        } else if object.starts_with("mmio.") {
            Self::MmioRegion
        } else if object.starts_with("dma.") {
            Self::DmaBuffer
        } else if object.starts_with("irq.") {
            Self::IrqLine
        } else if object.starts_with("virtqueue.") {
            Self::VirtioQueue
        } else if object.starts_with("dmw.") {
            Self::DmwWindow
        } else if object.starts_with("timer.") {
            Self::Timer
        } else if object.starts_with("snapshot.") {
            Self::Snapshot
        } else if object.starts_with("fault-domain.") {
            Self::FaultDomain
        } else if object.starts_with("net.interface") {
            Self::NetInterface
        } else if object.starts_with("net.socket") {
            Self::NetSocket
        } else if object.starts_with("guest-memory.") {
            Self::GuestMemoryAccess
        } else {
            Self::ServiceImport
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ServiceImport => "service-import",
            Self::Device => "device",
            Self::PacketDevice => "packet-device",
            Self::MmioRegion => "mmio-region",
            Self::DmaBuffer => "dma-buffer",
            Self::IrqLine => "irq-line",
            Self::VirtioQueue => "virtio-queue",
            Self::DmwWindow => "dmw-window",
            Self::Timer => "timer",
            Self::Snapshot => "snapshot",
            Self::FaultDomain => "fault-domain",
            Self::NetInterface => "net-interface",
            Self::NetSocket => "net-socket",
            Self::GuestMemoryAccess => "guest-memory-access",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRecord {
    pub id: CapabilityId,
    pub subject: String,
    pub object: String,
    pub operations: OperationSet,
    pub lifetime: String,
    pub class: CapabilityClass,
    pub owner_store: Option<StoreId>,
    pub owner_task: Option<TaskId>,
    pub source: String,
    pub generation: Generation,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityOwnerSummary {
    pub subject: String,
    pub active: usize,
    pub revoked: usize,
    pub generation_high_watermark: Generation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRevocationReport {
    pub subject: String,
    pub revoked: Vec<CapabilityId>,
}

impl CapabilityRevocationReport {
    pub fn count(&self) -> usize {
        self.revoked.len()
    }
}

#[derive(Clone, Debug)]
pub struct CapabilityLedger {
    next_id: CapabilityId,
    records: Vec<CapabilityRecord>,
}

impl CapabilityLedger {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            records: Vec::new(),
        }
    }

    pub fn grant(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> CapabilityId {
        self.grant_with_metadata(
            subject,
            object,
            operations,
            lifetime,
            CapabilityClass::from_object(object),
            None,
            None,
            "runtime-grant",
        )
    }

    pub fn grant_with_metadata(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
        class: CapabilityClass,
        owner_store: Option<StoreId>,
        owner_task: Option<TaskId>,
        source: &str,
    ) -> CapabilityId {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.subject == subject && record.object == object)
        {
            record.operations = OperationSet::from_static(operations);
            record.lifetime = lifetime.to_string();
            record.class = class;
            record.owner_store = owner_store;
            record.owner_task = owner_task;
            record.source = source.to_string();
            record.generation += 1;
            record.revoked = false;
            return record.id;
        }

        let id = self.next_id;
        self.next_id += 1;
        self.records.push(CapabilityRecord {
            id,
            subject: subject.to_string(),
            object: object.to_string(),
            operations: OperationSet::from_static(operations),
            lifetime: lifetime.to_string(),
            class,
            owner_store,
            owner_task,
            source: source.to_string(),
            generation: 1,
            revoked: false,
        });
        id
    }

    pub fn delegate(
        &mut self,
        parent_id: CapabilityId,
        subject: &str,
        lifetime: &str,
    ) -> Option<CapabilityId> {
        let parent = self.active(parent_id)?.clone();
        let operations = parent
            .operations
            .as_slice()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        Some(self.grant_with_metadata(
            subject,
            &parent.object,
            &operations,
            lifetime,
            parent.class,
            parent.owner_store,
            parent.owner_task,
            "delegated",
        ))
    }

    pub fn attenuate(
        &mut self,
        parent_id: CapabilityId,
        subject: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> Option<CapabilityId> {
        let parent = self.active(parent_id)?.clone();
        if !parent.operations.contains_all(operations) {
            return None;
        }
        Some(self.grant_with_metadata(
            subject,
            &parent.object,
            operations,
            lifetime,
            parent.class,
            parent.owner_store,
            parent.owner_task,
            "attenuated",
        ))
    }

    pub fn revoke(&mut self, id: CapabilityId) -> bool {
        let Some(record) = self.records.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        record.revoked = true;
        record.generation += 1;
        true
    }

    pub fn revoke_by_subject_object(
        &mut self,
        subject: &str,
        object: &str,
    ) -> Option<CapabilityId> {
        let record = self
            .records
            .iter_mut()
            .find(|record| record.subject == subject && record.object == object)?;
        record.revoked = true;
        record.generation += 1;
        Some(record.id)
    }

    pub fn revoke_subject(&mut self, subject: &str) -> usize {
        self.revoke_subject_report(subject).count()
    }

    pub fn revoke_subject_report(&mut self, subject: &str) -> CapabilityRevocationReport {
        let mut revoked_ids = Vec::new();
        for record in &mut self.records {
            if record.subject == subject && !record.revoked {
                record.revoked = true;
                record.generation += 1;
                revoked_ids.push(record.id);
            }
        }
        CapabilityRevocationReport {
            subject: subject.to_string(),
            revoked: revoked_ids,
        }
    }

    pub fn owner_summary(&self, subject: &str) -> CapabilityOwnerSummary {
        let mut active = 0;
        let mut revoked = 0;
        let mut generation_high_watermark = 0;
        for record in self
            .records
            .iter()
            .filter(|record| record.subject == subject)
        {
            if record.revoked {
                revoked += 1;
            } else {
                active += 1;
            }
            generation_high_watermark = generation_high_watermark.max(record.generation);
        }
        CapabilityOwnerSummary {
            subject: subject.to_string(),
            active,
            revoked,
            generation_high_watermark,
        }
    }

    pub fn active(&self, id: CapabilityId) -> Option<&CapabilityRecord> {
        self.records
            .iter()
            .find(|record| record.id == id && !record.revoked)
    }

    pub fn check(
        &self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> Result<&CapabilityRecord, CapabilityDenyReason> {
        let Some(record) = self
            .records
            .iter()
            .find(|record| record.subject == subject && record.object == object)
        else {
            return Err(CapabilityDenyReason::Missing);
        };
        if record.revoked {
            return Err(CapabilityDenyReason::Revoked);
        }
        if !record.operations.contains(operation) {
            return Err(CapabilityDenyReason::OperationDenied);
        }
        Ok(record)
    }

    pub fn generation_of(&self, subject: &str, object: &str) -> Option<Generation> {
        self.records
            .iter()
            .find(|record| record.subject == subject && record.object == object)
            .map(|record| record.generation)
    }

    pub fn records(&self) -> &[CapabilityRecord] {
        &self.records
    }

    pub fn active_count(&self) -> usize {
        self.records.iter().filter(|record| !record.revoked).count()
    }
}

impl Default for CapabilityLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityDenyReason {
    Missing,
    Revoked,
    OperationDenied,
    GenerationMismatch,
}

impl CapabilityDenyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Revoked => "revoked",
            Self::OperationDenied => "operation-denied",
            Self::GenerationMismatch => "generation-mismatch",
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskRecord {
    pub id: TaskId,
    pub label: String,
    pub frontend: FrontendKind,
    pub state: TaskState,
    pub fault_domain: Option<FaultDomainId>,
    pub pending_wait: Option<WaitId>,
    pub generation: Generation,
    pub resources: Vec<ResourceId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRecord {
    pub id: ResourceId,
    pub label: String,
    pub kind: ResourceKind,
    pub owner_task: Option<TaskId>,
    pub owner_store: Option<StoreId>,
    pub generation: Generation,
    pub live: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityBindingRecord {
    pub id: AuthorityId,
    pub resource: ResourceId,
    pub kind: AuthorityKind,
    pub subject: String,
    pub object: String,
    pub operations: OperationSet,
    pub lifetime: String,
    pub generation: Generation,
    pub state: AuthorityState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitRecord {
    pub id: WaitId,
    pub owner_task: TaskId,
    pub kind: SemanticWaitKind,
    pub generation: Generation,
    pub state: WaitState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultDomainRecord {
    pub id: FaultDomainId,
    pub name: String,
    pub role: String,
    pub state: FaultDomainState,
    pub generation: Generation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreRecord {
    pub id: StoreId,
    pub package: String,
    pub artifact: String,
    pub role: String,
    pub fault_policy: String,
    pub fault_domain: FaultDomainId,
    pub resource: Option<ResourceId>,
    pub state: StoreState,
    pub generation: Generation,
    pub restart_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreDropReport {
    pub store: StoreId,
    pub generation: Generation,
    pub previous_resource: Option<ResourceId>,
    pub closed_resources: usize,
    pub revoked_authorities: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreRebindReport {
    pub store: StoreId,
    pub generation: Generation,
    pub resource: ResourceId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreResourceCleanupReport {
    pub store: StoreId,
    pub closed_resources: usize,
    pub revoked_authorities: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionState {
    Begun,
    Committed,
    RolledBack,
}

impl TransactionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Begun => "begun",
            Self::Committed => "committed",
            Self::RolledBack => "rolled-back",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticTransactionRecord {
    pub id: TransactionId,
    pub label: String,
    pub store: Option<StoreId>,
    pub task: Option<TaskId>,
    pub state: TransactionState,
    pub generation: Generation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathPlanRecord {
    pub id: PlanId,
    pub subject: String,
    pub object: String,
    pub operation: String,
    pub generation: Generation,
    pub valid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureEffect {
    CompleteWithErrno(i32),
    RetryTransparent,
    RestartSyscall { wait: Option<WaitId> },
    CancelWaitToken { wait: WaitId, errno: i32 },
    MarkResourceDead(ResourceId),
    KillTask(TaskId),
    RebootFaultDomain(FaultDomainId),
}

impl FailureEffect {
    pub fn summary(self) -> String {
        match self {
            Self::CompleteWithErrno(errno) => format!("complete-with-errno({errno})"),
            Self::RetryTransparent => "retry-transparent".to_string(),
            Self::RestartSyscall { wait: Some(wait) } => format!("restart-syscall(wait={wait})"),
            Self::RestartSyscall { wait: None } => "restart-syscall".to_string(),
            Self::CancelWaitToken { wait, errno } => {
                format!("cancel-wait-token(wait={wait}, errno={errno})")
            }
            Self::MarkResourceDead(resource) => format!("mark-resource-dead({resource})"),
            Self::KillTask(task) => format!("kill-task({task})"),
            Self::RebootFaultDomain(domain) => format!("reboot-fault-domain({domain})"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    TaskCreated {
        task: TaskId,
        frontend: FrontendKind,
    },
    TaskStateChanged {
        task: TaskId,
        from: TaskState,
        to: TaskState,
    },
    ResourceCreated {
        resource: ResourceId,
        kind: ResourceKind,
        generation: Generation,
    },
    ResourceClosed {
        resource: ResourceId,
        generation: Generation,
    },
    ResourceHandleValidated {
        resource: ResourceId,
        generation: Generation,
    },
    ResourceHandleRejected {
        resource: ResourceId,
        expected: Generation,
        actual: Option<Generation>,
        reason: GenerationCheckError,
    },
    AuthorityBound {
        authority: AuthorityId,
        resource: ResourceId,
        kind: AuthorityKind,
        subject: String,
        object: String,
        generation: Generation,
    },
    AuthorityReleased {
        authority: AuthorityId,
        resource: ResourceId,
        generation: Generation,
        reason: String,
    },
    AuthorityRevoked {
        authority: AuthorityId,
        resource: ResourceId,
        generation: Generation,
        reason: String,
    },
    BoundaryPublished {
        boundary: BoundaryId,
        name: String,
        kind: BoundaryKind,
        status: BoundaryStatus,
        backend: String,
        blocked_by: Option<String>,
        generation: Generation,
    },
    WaitCreated {
        wait: WaitId,
        task: TaskId,
        kind: SemanticWaitKind,
        generation: Generation,
    },
    WaitResolved {
        wait: WaitId,
        reason: String,
    },
    WaitCancelled {
        wait: WaitId,
        errno: i32,
    },
    WaitRestarted {
        wait: WaitId,
        class: String,
    },
    WaitTokenValidated {
        wait: WaitId,
        generation: Generation,
    },
    WaitTokenRejected {
        wait: WaitId,
        expected: Generation,
        actual: Option<Generation>,
        reason: GenerationCheckError,
    },
    CapabilityGranted {
        cap: CapabilityId,
    },
    CapabilityRevoked {
        cap: CapabilityId,
    },
    CapabilityUsed {
        cap: CapabilityId,
        subject: String,
        object: String,
        operation: String,
        generation: Generation,
    },
    CapabilityDenied {
        subject: String,
        object: String,
        operation: String,
        reason: CapabilityDenyReason,
    },
    CapabilityGenerationMismatch {
        subject: String,
        object: String,
        operation: String,
        expected: Generation,
        actual: Option<Generation>,
    },
    HostcallEntered {
        label: String,
        class: HostcallClass,
        subject: String,
        object: String,
        operation: String,
    },
    FaultDomainRegistered {
        domain: FaultDomainId,
    },
    FaultDomainStateChanged {
        domain: FaultDomainId,
        from: FaultDomainState,
        to: FaultDomainState,
        generation: Generation,
    },
    FaultClassified {
        trap: TrapClass,
        class: FaultClass,
        store: Option<StoreId>,
        task: Option<TaskId>,
        detail: String,
    },
    DriverTrap {
        domain: Option<FaultDomainId>,
        trap: TrapClass,
        detail: String,
    },
    PacketReceived {
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    },
    PacketTransmitted {
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    },
    NetInterfaceStateChanged {
        interface: ResourceId,
        up: bool,
    },
    SocketStateChanged {
        socket: ResourceId,
        state: String,
    },
    DeviceIrqDelivered {
        irq: ResourceId,
        device: ResourceId,
        cause: String,
    },
    DriverCompletion {
        device: ResourceId,
        operation: String,
    },
    DmaSubmitted {
        buffer: ResourceId,
        device: ResourceId,
        len: usize,
    },
    DmaCompleted {
        buffer: ResourceId,
        device: ResourceId,
        len: usize,
    },
    FaultDomainRestarted {
        domain: FaultDomainId,
    },
    StoreRegistered {
        store: StoreId,
        domain: FaultDomainId,
        resource: ResourceId,
        generation: Generation,
    },
    StoreStateChanged {
        store: StoreId,
        from: StoreState,
        to: StoreState,
        generation: Generation,
    },
    StoreExecutorTransition {
        store: StoreId,
        from: String,
        to: String,
        blocked_by: Option<String>,
        hostcall_table: String,
        trap_surface: String,
    },
    StoreTrap {
        store: StoreId,
        trap: TrapClass,
        detail: String,
    },
    StoreDropped {
        store: StoreId,
        generation: Generation,
        resource: Option<ResourceId>,
    },
    StoreRebound {
        store: StoreId,
        generation: Generation,
        resource: ResourceId,
    },
    WindowLeaseCreated {
        lease: ResourceId,
        generation: Generation,
    },
    WindowLeaseDestroyed {
        lease: ResourceId,
        generation: Generation,
    },
    SnapshotBarrierEnter {
        barrier: u64,
    },
    SnapshotBarrierExit {
        barrier: u64,
    },
    FastPathPlanInstalled {
        plan: u64,
    },
    FastPathPlanInvalidated {
        plan: u64,
    },
    TransactionBegan {
        transaction: TransactionId,
        store: Option<StoreId>,
        task: Option<TaskId>,
        label: String,
    },
    TransactionCommitted {
        transaction: TransactionId,
        generation: Generation,
    },
    TransactionRolledBack {
        transaction: TransactionId,
        reason: String,
        generation: Generation,
    },
    FailureEffect {
        effect: FailureEffect,
    },
}

impl EventKind {
    pub fn summary(&self) -> String {
        match self {
            Self::TaskCreated { task, frontend } => {
                format!("TaskCreated task={task} frontend={}", frontend.as_str())
            }
            Self::TaskStateChanged { task, from, to } => {
                format!(
                    "TaskStateChanged task={task} {}->{}",
                    from.as_str(),
                    to.as_str()
                )
            }
            Self::ResourceCreated {
                resource,
                kind,
                generation,
            } => format!(
                "ResourceCreated resource={resource} kind={} generation={generation}",
                kind.as_str()
            ),
            Self::ResourceClosed {
                resource,
                generation,
            } => format!("ResourceClosed resource={resource} generation={generation}"),
            Self::ResourceHandleValidated {
                resource,
                generation,
            } => format!("ResourceHandleValidated resource={resource} generation={generation}"),
            Self::ResourceHandleRejected {
                resource,
                expected,
                actual,
                reason,
            } => match actual {
                Some(actual) => format!(
                    "ResourceHandleRejected resource={resource} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "ResourceHandleRejected resource={resource} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::AuthorityBound {
                authority,
                resource,
                kind,
                subject,
                object,
                generation,
            } => format!(
                "AuthorityBound authority={authority} resource={resource} kind={} subject={subject} object={object} generation={generation}",
                kind.as_str()
            ),
            Self::AuthorityReleased {
                authority,
                resource,
                generation,
                reason,
            } => format!(
                "AuthorityReleased authority={authority} resource={resource} generation={generation} reason={reason}"
            ),
            Self::AuthorityRevoked {
                authority,
                resource,
                generation,
                reason,
            } => format!(
                "AuthorityRevoked authority={authority} resource={resource} generation={generation} reason={reason}"
            ),
            Self::BoundaryPublished {
                boundary,
                name,
                kind,
                status,
                backend,
                blocked_by,
                generation,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "BoundaryPublished boundary={boundary} name={name} kind={} status={} backend={backend} blocked={blocked_by} generation={generation}",
                    kind.as_str(),
                    status.as_str()
                )
            }
            Self::WaitCreated {
                wait,
                task,
                kind,
                generation,
            } => format!(
                "WaitCreated wait={wait} task={task} kind={} generation={generation}",
                kind.as_str()
            ),
            Self::WaitResolved { wait, reason } => {
                format!("WaitResolved wait={wait} reason={reason}")
            }
            Self::WaitCancelled { wait, errno } => {
                format!("WaitCancelled wait={wait} errno={errno}")
            }
            Self::WaitRestarted { wait, class } => {
                format!("WaitRestarted wait={wait} class={class}")
            }
            Self::WaitTokenValidated { wait, generation } => {
                format!("WaitTokenValidated wait={wait} generation={generation}")
            }
            Self::WaitTokenRejected {
                wait,
                expected,
                actual,
                reason,
            } => match actual {
                Some(actual) => format!(
                    "WaitTokenRejected wait={wait} expected={expected} actual={actual} reason={}",
                    reason.as_str()
                ),
                None => format!(
                    "WaitTokenRejected wait={wait} expected={expected} actual=missing reason={}",
                    reason.as_str()
                ),
            },
            Self::CapabilityGranted { cap } => format!("CapabilityGranted cap={cap}"),
            Self::CapabilityRevoked { cap } => format!("CapabilityRevoked cap={cap}"),
            Self::CapabilityUsed {
                cap,
                subject,
                object,
                operation,
                generation,
            } => format!(
                "CapabilityUsed cap={cap} subject={subject} object={object} op={operation} generation={generation}"
            ),
            Self::CapabilityDenied {
                subject,
                object,
                operation,
                reason,
            } => format!(
                "CapabilityDenied subject={subject} object={object} op={operation} reason={}",
                reason.as_str()
            ),
            Self::CapabilityGenerationMismatch {
                subject,
                object,
                operation,
                expected,
                actual,
            } => match actual {
                Some(actual) => format!(
                    "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual={actual}"
                ),
                None => format!(
                    "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual=missing"
                ),
            },
            Self::HostcallEntered {
                label,
                class,
                subject,
                object,
                operation,
            } => format!(
                "HostcallEntered label={label} class={} subject={subject} object={object} op={operation}",
                class.as_str()
            ),
            Self::FaultDomainRegistered { domain } => {
                format!("FaultDomainRegistered domain={domain}")
            }
            Self::FaultDomainStateChanged {
                domain,
                from,
                to,
                generation,
            } => format!(
                "FaultDomainStateChanged domain={domain} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::FaultClassified {
                trap,
                class,
                store,
                task,
                detail,
            } => {
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let task = task
                    .map(|task| task.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "FaultClassified trap={} class={} store={store} task={task} detail={detail}",
                    trap.as_str(),
                    class.as_str()
                )
            }
            Self::DriverTrap {
                domain,
                trap,
                detail,
            } => match domain {
                Some(domain) => format!(
                    "DriverTrap domain={domain} trap={} detail={detail}",
                    trap.as_str()
                ),
                None => format!("DriverTrap trap={} detail={detail}", trap.as_str()),
            },
            Self::PacketReceived {
                interface,
                socket,
                ready_key,
                len,
            } => {
                let socket = socket
                    .map(|socket| socket.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "PacketReceived interface={interface} socket={socket} ready_key=0x{ready_key:x} len={len}"
                )
            }
            Self::PacketTransmitted {
                interface,
                socket,
                ready_key,
                len,
            } => {
                let socket = socket
                    .map(|socket| socket.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "PacketTransmitted interface={interface} socket={socket} ready_key=0x{ready_key:x} len={len}"
                )
            }
            Self::NetInterfaceStateChanged { interface, up } => {
                let state = if *up { "up" } else { "down" };
                format!("NetInterfaceStateChanged interface={interface} state={state}")
            }
            Self::SocketStateChanged { socket, state } => {
                format!("SocketStateChanged socket={socket} state={state}")
            }
            Self::DeviceIrqDelivered { irq, device, cause } => {
                format!("DeviceIrqDelivered irq={irq} device={device} cause={cause}")
            }
            Self::DriverCompletion { device, operation } => {
                format!("DriverCompletion device={device} operation={operation}")
            }
            Self::DmaSubmitted {
                buffer,
                device,
                len,
            } => format!("DmaSubmitted buffer={buffer} device={device} len={len}"),
            Self::DmaCompleted {
                buffer,
                device,
                len,
            } => format!("DmaCompleted buffer={buffer} device={device} len={len}"),
            Self::FaultDomainRestarted { domain } => {
                format!("FaultDomainRestarted domain={domain}")
            }
            Self::StoreRegistered {
                store,
                domain,
                resource,
                generation,
            } => format!(
                "StoreRegistered store={store} domain={domain} resource={resource} generation={generation}"
            ),
            Self::StoreStateChanged {
                store,
                from,
                to,
                generation,
            } => format!(
                "StoreStateChanged store={store} {}->{} generation={generation}",
                from.as_str(),
                to.as_str()
            ),
            Self::StoreExecutorTransition {
                store,
                from,
                to,
                blocked_by,
                hostcall_table,
                trap_surface,
            } => {
                let blocked_by = blocked_by.as_deref().unwrap_or("none");
                format!(
                    "StoreExecutorTransition store={store} {from}->{to} blocked={blocked_by} hostcalls={hostcall_table} traps={trap_surface}"
                )
            }
            Self::StoreTrap {
                store,
                trap,
                detail,
            } => {
                format!(
                    "StoreTrap store={store} trap={} detail={detail}",
                    trap.as_str()
                )
            }
            Self::StoreDropped {
                store,
                generation,
                resource,
            } => match resource {
                Some(resource) => format!(
                    "StoreDropped store={store} generation={generation} resource={resource}"
                ),
                None => format!("StoreDropped store={store} generation={generation}"),
            },
            Self::StoreRebound {
                store,
                generation,
                resource,
            } => format!("StoreRebound store={store} generation={generation} resource={resource}"),
            Self::WindowLeaseCreated { lease, generation } => {
                format!("WindowLeaseCreated lease={lease} generation={generation}")
            }
            Self::WindowLeaseDestroyed { lease, generation } => {
                format!("WindowLeaseDestroyed lease={lease} generation={generation}")
            }
            Self::SnapshotBarrierEnter { barrier } => {
                format!("SnapshotBarrierEnter barrier={barrier}")
            }
            Self::SnapshotBarrierExit { barrier } => {
                format!("SnapshotBarrierExit barrier={barrier}")
            }
            Self::FastPathPlanInstalled { plan } => {
                format!("FastPathPlanInstalled plan={plan}")
            }
            Self::FastPathPlanInvalidated { plan } => {
                format!("FastPathPlanInvalidated plan={plan}")
            }
            Self::TransactionBegan {
                transaction,
                store,
                task,
                label,
            } => {
                let store = store
                    .map(|store| store.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let task = task
                    .map(|task| task.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "TransactionBegan transaction={transaction} store={store} task={task} label={label}"
                )
            }
            Self::TransactionCommitted {
                transaction,
                generation,
            } => {
                format!("TransactionCommitted transaction={transaction} generation={generation}")
            }
            Self::TransactionRolledBack {
                transaction,
                reason,
                generation,
            } => {
                format!(
                    "TransactionRolledBack transaction={transaction} reason={reason} generation={generation}"
                )
            }
            Self::FailureEffect { effect } => {
                format!("FailureEffect {}", effect.summary())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub id: EventId,
    pub epoch: u64,
    pub source: String,
    pub causal_parent: Option<EventId>,
    pub kind: EventKind,
}

impl EventRecord {
    pub fn summary(&self) -> String {
        format!(
            "#{} epoch={} source={} {}",
            self.id,
            self.epoch,
            self.source,
            self.kind.summary()
        )
    }
}

#[derive(Clone, Debug)]
pub struct EventLog {
    next_id: EventId,
    epoch: u64,
    runtime_mode: RuntimeMode,
    events: Vec<EventRecord>,
}

impl EventLog {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            epoch: 0,
            runtime_mode: RuntimeMode::Research,
            events: Vec::new(),
        }
    }

    pub const fn with_runtime_mode(runtime_mode: RuntimeMode) -> Self {
        Self {
            next_id: 1,
            epoch: 0,
            runtime_mode,
            events: Vec::new(),
        }
    }

    pub const fn runtime_mode(&self) -> RuntimeMode {
        self.runtime_mode
    }

    pub fn push(&mut self, source: &str, kind: EventKind) -> EventId {
        let id = self.next_id;
        self.next_id += 1;
        self.epoch += 1;
        self.events.push(EventRecord {
            id,
            epoch: self.epoch,
            source: source.to_string(),
            causal_parent: None,
            kind,
        });
        id
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn cursor(&self) -> EventId {
        self.next_id.saturating_sub(1)
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn tail(&self, count: usize) -> &[EventRecord] {
        let start = self.events.len().saturating_sub(count);
        &self.events[start..]
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct SemanticGraph {
    tasks: Vec<TaskRecord>,
    resources: Vec<ResourceRecord>,
    authority_bindings: Vec<AuthorityBindingRecord>,
    waits: Vec<WaitRecord>,
    fault_domains: Vec<FaultDomainRecord>,
    stores: Vec<StoreRecord>,
    transactions: Vec<SemanticTransactionRecord>,
    fast_path_plans: Vec<FastPathPlanRecord>,
    boundaries: Vec<BoundaryRecord>,
    capabilities: CapabilityLedger,
    event_log: EventLog,
    next_resource_id: ResourceId,
    next_authority_id: AuthorityId,
    next_fault_domain_id: FaultDomainId,
    next_store_id: StoreId,
    next_transaction_id: TransactionId,
    next_plan_id: PlanId,
    next_boundary_id: BoundaryId,
}

impl SemanticGraph {
    pub fn new() -> Self {
        Self::with_runtime_mode(RuntimeMode::Research)
    }

    pub fn with_runtime_mode(runtime_mode: RuntimeMode) -> Self {
        Self {
            tasks: Vec::new(),
            resources: Vec::new(),
            authority_bindings: Vec::new(),
            waits: Vec::new(),
            fault_domains: Vec::new(),
            stores: Vec::new(),
            transactions: Vec::new(),
            fast_path_plans: Vec::new(),
            boundaries: Vec::new(),
            capabilities: CapabilityLedger::new(),
            event_log: EventLog::with_runtime_mode(runtime_mode),
            next_resource_id: 1,
            next_authority_id: 1,
            next_fault_domain_id: 1,
            next_store_id: 1,
            next_transaction_id: 1,
            next_plan_id: 1,
            next_boundary_id: 1,
        }
    }

    pub fn runtime_mode(&self) -> RuntimeMode {
        self.event_log.runtime_mode()
    }

    pub fn publish_boundary(
        &mut self,
        name: &str,
        kind: BoundaryKind,
        status: BoundaryStatus,
        backend: &str,
        blocked_by: Option<&str>,
    ) -> BoundaryId {
        if let Some(index) = self
            .boundaries
            .iter()
            .position(|boundary| boundary.name == name)
        {
            self.boundaries[index].kind = kind;
            self.boundaries[index].status = status;
            self.boundaries[index].backend = backend.to_string();
            self.boundaries[index].blocked_by = blocked_by.map(|value| value.to_string());
            self.boundaries[index].generation += 1;
            let id = self.boundaries[index].id;
            let name = self.boundaries[index].name.clone();
            let backend = self.boundaries[index].backend.clone();
            let blocked_by = self.boundaries[index].blocked_by.clone();
            let generation = self.boundaries[index].generation;
            self.event_log.push(
                "boundary",
                EventKind::BoundaryPublished {
                    boundary: id,
                    name,
                    kind,
                    status,
                    backend,
                    blocked_by,
                    generation,
                },
            );
            return id;
        }

        let id = self.next_boundary_id;
        self.next_boundary_id += 1;
        let boundary = BoundaryRecord {
            id,
            name: name.to_string(),
            kind,
            status,
            backend: backend.to_string(),
            blocked_by: blocked_by.map(|value| value.to_string()),
            generation: 1,
        };
        self.event_log.push(
            "boundary",
            EventKind::BoundaryPublished {
                boundary: id,
                name: boundary.name.clone(),
                kind,
                status,
                backend: boundary.backend.clone(),
                blocked_by: boundary.blocked_by.clone(),
                generation: boundary.generation,
            },
        );
        self.boundaries.push(boundary);
        id
    }

    pub fn ensure_task(&mut self, id: TaskId, frontend: FrontendKind, label: &str) {
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
            task.frontend = frontend;
            task.label = label.to_string();
            return;
        }

        self.tasks.push(TaskRecord {
            id,
            label: label.to_string(),
            frontend,
            state: TaskState::Runnable,
            fault_domain: None,
            pending_wait: None,
            generation: 1,
            resources: Vec::new(),
        });
        self.event_log
            .push("semantic", EventKind::TaskCreated { task: id, frontend });
    }

    pub fn set_task_state(&mut self, id: TaskId, state: TaskState) {
        let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) else {
            return;
        };
        let from = task.state;
        if from == state {
            return;
        }
        task.state = state;
        task.generation += 1;
        if state != TaskState::Pending {
            task.pending_wait = None;
        }
        self.event_log.push(
            "scheduler",
            EventKind::TaskStateChanged {
                task: id,
                from,
                to: state,
            },
        );
    }

    pub fn register_resource(
        &mut self,
        kind: ResourceKind,
        owner_task: Option<TaskId>,
        label: &str,
    ) -> ResourceId {
        self.register_resource_for_store(kind, owner_task, None, label)
    }

    pub fn register_resource_for_store(
        &mut self,
        kind: ResourceKind,
        owner_task: Option<TaskId>,
        owner_store: Option<StoreId>,
        label: &str,
    ) -> ResourceId {
        let id = self.next_resource_id;
        self.next_resource_id += 1;
        self.resources.push(ResourceRecord {
            id,
            label: label.to_string(),
            kind,
            owner_task,
            owner_store,
            generation: 1,
            live: true,
        });
        if let Some(owner_task) = owner_task
            && let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task)
        {
            task.resources.push(id);
        }
        self.event_log.push(
            "resource",
            EventKind::ResourceCreated {
                resource: id,
                kind,
                generation: 1,
            },
        );
        id
    }

    pub fn close_resource(&mut self, id: ResourceId) {
        let Some(resource) = self.resources.iter_mut().find(|resource| resource.id == id) else {
            return;
        };
        if !resource.live {
            return;
        }
        resource.live = false;
        resource.generation += 1;
        self.event_log.push(
            "resource",
            EventKind::ResourceClosed {
                resource: id,
                generation: resource.generation,
            },
        );
    }

    pub fn mark_resource_dead(&mut self, id: ResourceId) {
        self.close_resource(id);
        self.record_failure_effect(FailureEffect::MarkResourceDead(id));
    }

    pub fn close_resources_owned_by_store(&mut self, store: StoreId) -> usize {
        self.cleanup_resources_owned_by_store(store)
            .closed_resources
    }

    pub fn cleanup_resources_owned_by_store(
        &mut self,
        store: StoreId,
    ) -> StoreResourceCleanupReport {
        let resources = self
            .resources
            .iter()
            .filter(|resource| resource.owner_store == Some(store) && resource.live)
            .map(|resource| resource.id)
            .collect::<Vec<_>>();
        let count = resources.len();
        let mut revoked_authorities = 0usize;
        for resource in resources {
            revoked_authorities +=
                self.revoke_authority_for_resource(resource, "owner store dropped");
            if self
                .resources
                .iter()
                .any(|entry| entry.id == resource && entry.live)
            {
                self.mark_resource_dead(resource);
            }
        }
        StoreResourceCleanupReport {
            store,
            closed_resources: count,
            revoked_authorities,
        }
    }

    pub fn resource_handle(&self, id: ResourceId) -> Option<ResourceHandle> {
        self.resources
            .iter()
            .find(|resource| resource.id == id)
            .map(|resource| ResourceHandle::new(resource.id, resource.generation))
    }

    pub fn validate_resource_handle(
        &mut self,
        handle: ResourceHandle,
    ) -> Result<(), GenerationCheckError> {
        let resource = self
            .resources
            .iter()
            .find(|resource| resource.id == handle.id);
        let actual = resource.map(|resource| resource.generation);
        let result = match resource {
            None => Err(GenerationCheckError::Missing),
            Some(resource) if resource.generation != handle.generation => {
                Err(GenerationCheckError::GenerationMismatch {
                    expected: handle.generation,
                    actual,
                })
            }
            Some(resource) if !resource.live => Err(GenerationCheckError::Dead {
                actual: resource.generation,
            }),
            Some(_) => Ok(()),
        };

        match result {
            Ok(()) => {
                self.event_log.push(
                    "resource",
                    EventKind::ResourceHandleValidated {
                        resource: handle.id,
                        generation: handle.generation,
                    },
                );
                Ok(())
            }
            Err(reason) => {
                self.event_log.push(
                    "resource",
                    EventKind::ResourceHandleRejected {
                        resource: handle.id,
                        expected: handle.generation,
                        actual,
                        reason,
                    },
                );
                Err(reason)
            }
        }
    }

    pub fn bind_authority_resource(
        &mut self,
        resource: ResourceId,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> Option<AuthorityId> {
        let kind = {
            let resource = self
                .resources
                .iter()
                .find(|candidate| candidate.id == resource && candidate.live)?;
            AuthorityKind::from_resource_kind(resource.kind)?
        };
        let id = self.next_authority_id;
        self.next_authority_id += 1;
        self.authority_bindings.push(AuthorityBindingRecord {
            id,
            resource,
            kind,
            subject: subject.to_string(),
            object: object.to_string(),
            operations: OperationSet::from_static(operations),
            lifetime: lifetime.to_string(),
            generation: 1,
            state: AuthorityState::Bound,
        });
        self.grant_capability_with_source(
            subject,
            object,
            operations,
            lifetime,
            CapabilityClass::from_object(object),
            "authority-binding",
        );
        self.event_log.push(
            "authority",
            EventKind::AuthorityBound {
                authority: id,
                resource,
                kind,
                subject: subject.to_string(),
                object: object.to_string(),
                generation: 1,
            },
        );
        Some(id)
    }

    pub fn release_authority_binding(&mut self, id: AuthorityId, reason: &str) -> bool {
        let Some(index) = self
            .authority_bindings
            .iter()
            .position(|authority| authority.id == id)
        else {
            return false;
        };
        if self.authority_bindings[index].state != AuthorityState::Bound {
            return false;
        }
        self.authority_bindings[index].state = AuthorityState::Released;
        self.authority_bindings[index].generation += 1;
        let resource = self.authority_bindings[index].resource;
        let generation = self.authority_bindings[index].generation;
        let subject = self.authority_bindings[index].subject.clone();
        let object = self.authority_bindings[index].object.clone();
        self.capabilities
            .revoke_by_subject_object(&subject, &object);
        self.event_log.push(
            "authority",
            EventKind::AuthorityReleased {
                authority: id,
                resource,
                generation,
                reason: reason.to_string(),
            },
        );
        self.close_resource(resource);
        true
    }

    pub fn revoke_authority_for_resource(&mut self, resource: ResourceId, reason: &str) -> usize {
        let authorities = self
            .authority_bindings
            .iter()
            .filter(|authority| {
                authority.resource == resource && authority.state == AuthorityState::Bound
            })
            .map(|authority| authority.id)
            .collect::<Vec<_>>();
        let count = authorities.len();
        for authority in authorities {
            self.revoke_authority_binding(authority, reason);
        }
        count
    }

    pub fn revoke_authority_binding(&mut self, id: AuthorityId, reason: &str) -> bool {
        let Some(index) = self
            .authority_bindings
            .iter()
            .position(|authority| authority.id == id)
        else {
            return false;
        };
        if self.authority_bindings[index].state != AuthorityState::Bound {
            return false;
        }
        self.authority_bindings[index].state = AuthorityState::Revoked;
        self.authority_bindings[index].generation += 1;
        let resource = self.authority_bindings[index].resource;
        let generation = self.authority_bindings[index].generation;
        let subject = self.authority_bindings[index].subject.clone();
        let object = self.authority_bindings[index].object.clone();
        self.capabilities
            .revoke_by_subject_object(&subject, &object);
        self.event_log.push(
            "authority",
            EventKind::AuthorityRevoked {
                authority: id,
                resource,
                generation,
                reason: reason.to_string(),
            },
        );
        self.mark_resource_dead(resource);
        true
    }

    pub fn record_window_lease_created(
        &mut self,
        owner_task: Option<TaskId>,
        label: &str,
        generation: Generation,
    ) -> ResourceId {
        let lease = self.register_resource(ResourceKind::WindowLease, owner_task, label);
        self.event_log
            .push("dmw", EventKind::WindowLeaseCreated { lease, generation });
        lease
    }

    pub fn record_window_lease_destroyed(&mut self, lease: ResourceId, generation: Generation) {
        self.close_resource(lease);
        self.event_log
            .push("dmw", EventKind::WindowLeaseDestroyed { lease, generation });
    }

    pub fn register_fault_domain(&mut self, name: &str, role: &str) -> FaultDomainId {
        if let Some(domain) = self.fault_domains.iter().find(|domain| domain.name == name) {
            return domain.id;
        }

        let id = self.next_fault_domain_id;
        self.next_fault_domain_id += 1;
        self.fault_domains.push(FaultDomainRecord {
            id,
            name: name.to_string(),
            role: role.to_string(),
            state: FaultDomainState::Created,
            generation: 1,
        });
        self.event_log.push(
            "fault-domain",
            EventKind::FaultDomainRegistered { domain: id },
        );
        id
    }

    pub fn fault_domain_id(&self, name: &str) -> Option<FaultDomainId> {
        self.fault_domains
            .iter()
            .find(|domain| domain.name == name)
            .map(|domain| domain.id)
    }

    pub fn set_fault_domain_state(&mut self, id: FaultDomainId, state: FaultDomainState) {
        let Some(domain) = self.fault_domains.iter_mut().find(|domain| domain.id == id) else {
            return;
        };
        let from = domain.state;
        if domain.state == state {
            return;
        }
        domain.state = state;
        domain.generation += 1;
        let generation = domain.generation;
        self.event_log.push(
            "fault-domain",
            EventKind::FaultDomainStateChanged {
                domain: id,
                from,
                to: state,
                generation,
            },
        );
    }

    pub fn register_store(
        &mut self,
        package: &str,
        artifact: &str,
        role: &str,
        fault_policy: &str,
    ) -> StoreId {
        if let Some(store) = self.stores.iter().find(|store| store.package == package) {
            return store.id;
        }

        let id = self.next_store_id;
        self.next_store_id += 1;
        let fault_domain = self.register_fault_domain(package, role);
        let resource = self.register_resource_for_store(
            ResourceKind::ServiceStore,
            None,
            Some(id),
            &format!("store:{package}:{artifact}"),
        );
        self.stores.push(StoreRecord {
            id,
            package: package.to_string(),
            artifact: artifact.to_string(),
            role: role.to_string(),
            fault_policy: fault_policy.to_string(),
            fault_domain,
            resource: Some(resource),
            state: StoreState::Created,
            generation: 1,
            restart_count: 0,
        });
        self.event_log.push(
            "store",
            EventKind::StoreRegistered {
                store: id,
                domain: fault_domain,
                resource,
                generation: 1,
            },
        );
        id
    }

    pub fn store_id(&self, package: &str) -> Option<StoreId> {
        self.stores
            .iter()
            .find(|store| store.package == package)
            .map(|store| store.id)
    }

    pub fn store_handle(&self, id: StoreId) -> Option<StoreHandle> {
        self.stores
            .iter()
            .find(|store| store.id == id)
            .map(|store| StoreHandle::new(store.id, store.generation))
    }

    pub fn store_resource(&self, id: StoreId) -> Option<ResourceId> {
        self.stores
            .iter()
            .find(|store| store.id == id)
            .and_then(|store| store.resource)
    }

    pub fn validate_store_handle(
        &mut self,
        handle: StoreHandle,
    ) -> Result<(), GenerationCheckError> {
        let store = self.stores.iter().find(|store| store.id == handle.id);
        let actual = store.map(|store| store.generation);
        match store {
            None => Err(GenerationCheckError::Missing),
            Some(store) if store.generation != handle.generation => {
                Err(GenerationCheckError::GenerationMismatch {
                    expected: handle.generation,
                    actual,
                })
            }
            Some(store) if store.state == StoreState::Dead => Err(GenerationCheckError::Dead {
                actual: store.generation,
            }),
            Some(_) => Ok(()),
        }
    }

    pub fn set_store_state(&mut self, id: StoreId, state: StoreState) {
        let Some(index) = self.stores.iter().position(|store| store.id == id) else {
            return;
        };
        let from = self.stores[index].state;
        if from == state {
            return;
        }
        self.stores[index].state = state;
        self.stores[index].generation += 1;
        if state == StoreState::Restarting {
            self.stores[index].restart_count += 1;
        }
        let generation = self.stores[index].generation;
        let fault_domain = self.stores[index].fault_domain;
        self.event_log.push(
            "store",
            EventKind::StoreStateChanged {
                store: id,
                from,
                to: state,
                generation,
            },
        );
        self.set_fault_domain_state(fault_domain, state.fault_domain_state());
        if state == StoreState::Running && self.stores[index].restart_count > 0 {
            self.event_log.push(
                "fault-domain",
                EventKind::FaultDomainRestarted {
                    domain: fault_domain,
                },
            );
        }
    }

    pub fn record_store_executor_transition(
        &mut self,
        id: StoreId,
        from: &str,
        to: &str,
        blocked_by: Option<&str>,
        hostcall_table: &str,
        trap_surface: &str,
    ) {
        if !self.stores.iter().any(|store| store.id == id) {
            return;
        }
        self.event_log.push(
            "executor",
            EventKind::StoreExecutorTransition {
                store: id,
                from: from.to_string(),
                to: to.to_string(),
                blocked_by: blocked_by.map(|value| value.to_string()),
                hostcall_table: hostcall_table.to_string(),
                trap_surface: trap_surface.to_string(),
            },
        );
    }

    pub fn record_store_trap(&mut self, id: StoreId, trap: &str) {
        self.record_store_trap_class(id, TrapClass::ServiceTrap, trap);
    }

    pub fn record_store_trap_class(&mut self, id: StoreId, trap: TrapClass, detail: &str) {
        let domain = self
            .stores
            .iter()
            .find(|store| store.id == id)
            .map(|store| store.fault_domain);
        self.event_log.push(
            "fault",
            EventKind::FaultClassified {
                trap,
                class: trap.fault_class(),
                store: Some(id),
                task: None,
                detail: detail.to_string(),
            },
        );
        self.event_log.push(
            "store",
            EventKind::StoreTrap {
                store: id,
                trap,
                detail: detail.to_string(),
            },
        );
        self.record_driver_trap_class(domain, trap, detail);
        self.set_store_state(id, StoreState::Degraded);
    }

    pub fn drop_store_instance(&mut self, id: StoreId) -> Option<StoreDropReport> {
        let index = self.stores.iter().position(|store| store.id == id)?;
        let resource = self.stores[index].resource.take();
        let cleanup = self.cleanup_resources_owned_by_store(id);
        self.set_store_state(id, StoreState::Dead);
        let generation = self.stores[index].generation;
        self.event_log.push(
            "store",
            EventKind::StoreDropped {
                store: id,
                generation,
                resource,
            },
        );
        Some(StoreDropReport {
            store: id,
            generation,
            previous_resource: resource,
            closed_resources: cleanup.closed_resources,
            revoked_authorities: cleanup.revoked_authorities,
        })
    }

    pub fn rebind_store_instance(&mut self, id: StoreId) -> Option<StoreRebindReport> {
        let index = self.stores.iter().position(|store| store.id == id)?;
        let package = self.stores[index].package.clone();
        let artifact = self.stores[index].artifact.clone();
        let resource = self.register_resource_for_store(
            ResourceKind::ServiceStore,
            None,
            Some(id),
            &format!("store:{package}:{artifact}"),
        );
        self.stores[index].resource = Some(resource);
        self.stores[index].generation += 1;
        self.stores[index].state = StoreState::Rebinding;
        let generation = self.stores[index].generation;
        self.event_log.push(
            "store",
            EventKind::StoreRebound {
                store: id,
                generation,
                resource,
            },
        );
        self.set_fault_domain_state(
            self.stores[index].fault_domain,
            StoreState::Rebinding.fault_domain_state(),
        );
        Some(StoreRebindReport {
            store: id,
            generation,
            resource,
        })
    }

    pub fn record_driver_trap(&mut self, domain: Option<FaultDomainId>, trap: &str) {
        self.record_driver_trap_class(domain, TrapClass::DriverTrap, trap);
    }

    pub fn record_driver_trap_class(
        &mut self,
        domain: Option<FaultDomainId>,
        trap: TrapClass,
        detail: &str,
    ) {
        self.event_log.push(
            "trap",
            EventKind::DriverTrap {
                domain,
                trap,
                detail: detail.to_string(),
            },
        );
    }

    pub fn record_packet_received(
        &mut self,
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    ) {
        self.event_log.push(
            "net",
            EventKind::PacketReceived {
                interface,
                socket,
                ready_key,
                len,
            },
        );
    }

    pub fn record_packet_transmitted(
        &mut self,
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    ) {
        self.event_log.push(
            "net",
            EventKind::PacketTransmitted {
                interface,
                socket,
                ready_key,
                len,
            },
        );
    }

    pub fn record_net_interface_state_changed(&mut self, interface: ResourceId, up: bool) {
        self.event_log
            .push("net", EventKind::NetInterfaceStateChanged { interface, up });
    }

    pub fn record_socket_state_changed(&mut self, socket: ResourceId, state: &str) {
        self.event_log.push(
            "net",
            EventKind::SocketStateChanged {
                socket,
                state: state.to_string(),
            },
        );
    }

    pub fn record_device_irq_delivered(
        &mut self,
        irq: ResourceId,
        device: ResourceId,
        cause: &str,
    ) {
        self.event_log.push(
            "device",
            EventKind::DeviceIrqDelivered {
                irq,
                device,
                cause: cause.to_string(),
            },
        );
    }

    pub fn record_driver_completion(&mut self, device: ResourceId, operation: &str) {
        self.event_log.push(
            "driver",
            EventKind::DriverCompletion {
                device,
                operation: operation.to_string(),
            },
        );
    }

    pub fn record_dma_submitted(&mut self, buffer: ResourceId, device: ResourceId, len: usize) {
        self.event_log.push(
            "dma",
            EventKind::DmaSubmitted {
                buffer,
                device,
                len,
            },
        );
    }

    pub fn record_dma_completed(&mut self, buffer: ResourceId, device: ResourceId, len: usize) {
        self.event_log.push(
            "dma",
            EventKind::DmaCompleted {
                buffer,
                device,
                len,
            },
        );
    }

    pub fn grant_capability(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> CapabilityId {
        self.grant_capability_with_source(
            subject,
            object,
            operations,
            lifetime,
            CapabilityClass::from_object(object),
            "runtime-grant",
        )
    }

    pub fn grant_manifest_capability(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> CapabilityId {
        self.grant_capability_with_source(
            subject,
            object,
            operations,
            lifetime,
            CapabilityClass::from_object(object),
            "artifact-manifest",
        )
    }

    pub fn grant_capability_with_source(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
        class: CapabilityClass,
        source: &str,
    ) -> CapabilityId {
        let owner_store = self.store_id(subject);
        let cap = self.capabilities.grant_with_metadata(
            subject,
            object,
            operations,
            lifetime,
            class,
            owner_store,
            None,
            source,
        );
        self.event_log
            .push("capability", EventKind::CapabilityGranted { cap });
        cap
    }

    pub fn revoke_capability(&mut self, cap: CapabilityId) -> bool {
        if !self.capabilities.revoke(cap) {
            return false;
        }
        self.event_log
            .push("capability", EventKind::CapabilityRevoked { cap });
        true
    }

    pub fn revoke_capability_by_subject_object(
        &mut self,
        subject: &str,
        object: &str,
    ) -> Option<CapabilityId> {
        let cap = self
            .capabilities
            .revoke_by_subject_object(subject, object)?;
        self.event_log
            .push("capability", EventKind::CapabilityRevoked { cap });
        Some(cap)
    }

    pub fn revoke_capabilities_for_subject(&mut self, subject: &str) -> CapabilityRevocationReport {
        let report = self.capabilities.revoke_subject_report(subject);
        for cap in &report.revoked {
            self.event_log
                .push("capability", EventKind::CapabilityRevoked { cap: *cap });
        }
        report
    }

    pub fn check_capability(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> Result<CapabilityId, CapabilityDenyReason> {
        match self.capabilities.check(subject, object, operation) {
            Ok(record) => {
                let cap = record.id;
                let generation = record.generation;
                self.event_log.push(
                    "capability",
                    EventKind::CapabilityUsed {
                        cap,
                        subject: subject.to_string(),
                        object: object.to_string(),
                        operation: operation.to_string(),
                        generation,
                    },
                );
                Ok(cap)
            }
            Err(reason) => {
                self.event_log.push(
                    "capability",
                    EventKind::CapabilityDenied {
                        subject: subject.to_string(),
                        object: object.to_string(),
                        operation: operation.to_string(),
                        reason,
                    },
                );
                Err(reason)
            }
        }
    }

    pub fn check_capability_generation(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
        expected_generation: Generation,
    ) -> Result<CapabilityId, CapabilityDenyReason> {
        let actual_generation = self.capabilities.generation_of(subject, object);
        let record = match self.capabilities.check(subject, object, operation) {
            Ok(record) => record,
            Err(reason) => {
                self.event_log.push(
                    "capability",
                    EventKind::CapabilityDenied {
                        subject: subject.to_string(),
                        object: object.to_string(),
                        operation: operation.to_string(),
                        reason,
                    },
                );
                return Err(reason);
            }
        };
        if record.generation != expected_generation {
            self.event_log.push(
                "capability",
                EventKind::CapabilityGenerationMismatch {
                    subject: subject.to_string(),
                    object: object.to_string(),
                    operation: operation.to_string(),
                    expected: expected_generation,
                    actual: actual_generation,
                },
            );
            return Err(CapabilityDenyReason::GenerationMismatch);
        }
        let cap = record.id;
        let generation = record.generation;
        self.event_log.push(
            "capability",
            EventKind::CapabilityUsed {
                cap,
                subject: subject.to_string(),
                object: object.to_string(),
                operation: operation.to_string(),
                generation,
            },
        );
        Ok(cap)
    }

    pub fn capability_generation(&self, subject: &str, object: &str) -> Option<Generation> {
        self.capabilities.generation_of(subject, object)
    }

    pub fn capability_owner_summary(&self, subject: &str) -> CapabilityOwnerSummary {
        self.capabilities.owner_summary(subject)
    }

    pub fn record_hostcall(
        &mut self,
        label: &str,
        class: HostcallClass,
        subject: &str,
        object: &str,
        operation: &str,
    ) {
        self.event_log.push(
            "hostcall",
            EventKind::HostcallEntered {
                label: label.to_string(),
                class,
                subject: subject.to_string(),
                object: object.to_string(),
                operation: operation.to_string(),
            },
        );
    }

    pub fn record_wait_created(
        &mut self,
        wait: WaitId,
        owner_task: TaskId,
        kind: SemanticWaitKind,
        generation: Generation,
    ) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Pending;
            record.generation = generation;
        } else {
            self.waits.push(WaitRecord {
                id: wait,
                owner_task,
                kind,
                generation,
                state: WaitState::Pending,
            });
        }
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task) {
            task.pending_wait = Some(wait);
        }
        self.set_task_state(owner_task, TaskState::Pending);
        self.event_log.push(
            "wait",
            EventKind::WaitCreated {
                wait,
                task: owner_task,
                kind,
                generation,
            },
        );
    }

    pub fn record_wait_resolved(&mut self, wait: WaitId, reason: &str) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Ready;
        }
        self.event_log.push(
            "wait",
            EventKind::WaitResolved {
                wait,
                reason: reason.to_string(),
            },
        );
    }

    pub fn record_wait_cancelled(&mut self, wait: WaitId, errno: i32) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Cancelled;
        }
        self.event_log
            .push("wait", EventKind::WaitCancelled { wait, errno });
    }

    pub fn record_wait_restarted(&mut self, wait: WaitId, class: &str) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Restarted;
        }
        self.event_log.push(
            "wait",
            EventKind::WaitRestarted {
                wait,
                class: class.to_string(),
            },
        );
    }

    pub fn wait_handle(&self, id: WaitId) -> Option<WaitHandle> {
        self.waits
            .iter()
            .find(|wait| wait.id == id)
            .map(|wait| WaitHandle::new(wait.id, wait.generation))
    }

    pub fn validate_wait_handle(&mut self, handle: WaitHandle) -> Result<(), GenerationCheckError> {
        let wait = self.waits.iter().find(|wait| wait.id == handle.id);
        let actual = wait.map(|wait| wait.generation);
        let result = match wait {
            None => Err(GenerationCheckError::Missing),
            Some(wait) if wait.generation != handle.generation => {
                Err(GenerationCheckError::GenerationMismatch {
                    expected: handle.generation,
                    actual,
                })
            }
            Some(_) => Ok(()),
        };

        match result {
            Ok(()) => {
                self.event_log.push(
                    "wait",
                    EventKind::WaitTokenValidated {
                        wait: handle.id,
                        generation: handle.generation,
                    },
                );
                Ok(())
            }
            Err(reason) => {
                self.event_log.push(
                    "wait",
                    EventKind::WaitTokenRejected {
                        wait: handle.id,
                        expected: handle.generation,
                        actual,
                        reason,
                    },
                );
                Err(reason)
            }
        }
    }

    pub fn begin_transaction(
        &mut self,
        label: &str,
        store: Option<StoreId>,
        task: Option<TaskId>,
    ) -> TransactionId {
        let id = self.next_transaction_id;
        self.next_transaction_id += 1;
        self.transactions.push(SemanticTransactionRecord {
            id,
            label: label.to_string(),
            store,
            task,
            state: TransactionState::Begun,
            generation: 1,
        });
        self.event_log.push(
            "transaction",
            EventKind::TransactionBegan {
                transaction: id,
                store,
                task,
                label: label.to_string(),
            },
        );
        id
    }

    pub fn commit_transaction(&mut self, id: TransactionId) {
        let Some(transaction) = self
            .transactions
            .iter_mut()
            .find(|transaction| transaction.id == id)
        else {
            return;
        };
        if transaction.state != TransactionState::Begun {
            return;
        }
        transaction.state = TransactionState::Committed;
        transaction.generation += 1;
        self.event_log.push(
            "transaction",
            EventKind::TransactionCommitted {
                transaction: id,
                generation: transaction.generation,
            },
        );
    }

    pub fn rollback_transaction(&mut self, id: TransactionId, reason: &str) {
        let Some(transaction) = self
            .transactions
            .iter_mut()
            .find(|transaction| transaction.id == id)
        else {
            return;
        };
        if transaction.state != TransactionState::Begun {
            return;
        }
        transaction.state = TransactionState::RolledBack;
        transaction.generation += 1;
        self.event_log.push(
            "transaction",
            EventKind::TransactionRolledBack {
                transaction: id,
                reason: reason.to_string(),
                generation: transaction.generation,
            },
        );
    }

    pub fn install_fast_path_plan(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> PlanId {
        let id = self.next_plan_id;
        self.next_plan_id += 1;
        self.fast_path_plans.push(FastPathPlanRecord {
            id,
            subject: subject.to_string(),
            object: object.to_string(),
            operation: operation.to_string(),
            generation: 1,
            valid: true,
        });
        self.event_log
            .push("fastpath", EventKind::FastPathPlanInstalled { plan: id });
        id
    }

    pub fn invalidate_fast_path_plan(&mut self, id: PlanId) {
        let Some(plan) = self.fast_path_plans.iter_mut().find(|plan| plan.id == id) else {
            return;
        };
        if !plan.valid {
            return;
        }
        plan.valid = false;
        plan.generation += 1;
        self.event_log
            .push("fastpath", EventKind::FastPathPlanInvalidated { plan: id });
    }

    pub fn record_failure_effect(&mut self, effect: FailureEffect) {
        self.event_log
            .push("failure", EventKind::FailureEffect { effect });
    }

    pub fn record_snapshot_barrier_enter(&mut self, barrier: SnapshotBarrierId) {
        self.event_log
            .push("snapshot", EventKind::SnapshotBarrierEnter { barrier });
    }

    pub fn record_snapshot_barrier_exit(&mut self, barrier: SnapshotBarrierId) {
        self.event_log
            .push("snapshot", EventKind::SnapshotBarrierExit { barrier });
    }

    pub fn migration_package(
        &self,
        package_id: &str,
        source_host_arch: &str,
        target_host_arch_hint: &str,
        required_artifact_profile: ArtifactProfile,
        guest: GuestStateSnapshot,
        substrate_boundary: SubstrateBoundarySnapshot,
        barrier_id: SnapshotBarrierId,
        dmw_quiescent: bool,
    ) -> MigrationPackage {
        MigrationPackage {
            schema_version: 1,
            package_id: package_id.to_string(),
            source_host_arch: source_host_arch.to_string(),
            target_host_arch_hint: target_host_arch_hint.to_string(),
            required_artifact_profile,
            guest,
            substrate_boundary: substrate_boundary.clone(),
            semantic: SemanticSnapshot {
                barrier: SnapshotBarrierSnapshot {
                    id: barrier_id,
                    event_log_cursor: self.event_log.cursor(),
                    pending_wait_count: self.pending_wait_count(),
                    live_resource_count: self.live_resource_count(),
                    active_transaction_count: self.active_transaction_count(),
                    active_dmw_lease_count: substrate_boundary.active_dmw_lease_count,
                    dmw_quiescent,
                },
                tasks: self.tasks.clone(),
                resources: self.resources.clone(),
                authority_bindings: self.authority_bindings.clone(),
                waits: self.waits.clone(),
                fault_domains: self.fault_domains.clone(),
                stores: self.stores.clone(),
                transactions: self.transactions.clone(),
                fast_path_plans: self.fast_path_plans.clone(),
                boundaries: self.boundaries.clone(),
                capabilities: self.capabilities.records().to_vec(),
            },
        }
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    pub fn wait_count(&self) -> usize {
        self.waits.len()
    }

    pub fn fault_domain_count(&self) -> usize {
        self.fault_domains.len()
    }

    pub fn store_count(&self) -> usize {
        self.stores.len()
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    pub fn fast_path_plan_count(&self) -> usize {
        self.fast_path_plans.len()
    }

    pub fn boundary_count(&self) -> usize {
        self.boundaries.len()
    }

    pub fn active_fast_path_plan_count(&self) -> usize {
        self.fast_path_plans
            .iter()
            .filter(|plan| plan.valid)
            .count()
    }

    pub fn active_transaction_count(&self) -> usize {
        self.transactions
            .iter()
            .filter(|transaction| transaction.state == TransactionState::Begun)
            .count()
    }

    pub fn capability_count(&self) -> usize {
        self.capabilities.active_count()
    }

    pub fn event_count(&self) -> usize {
        self.event_log.len()
    }

    pub fn store_executor_transition_count(&self) -> usize {
        self.event_log
            .events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::StoreExecutorTransition { .. }))
            .count()
    }

    pub fn store_executor_transition_tail(&self, count: usize) -> Vec<String> {
        let mut lines = Vec::new();
        for event in self.event_log.events.iter().rev() {
            if matches!(event.kind, EventKind::StoreExecutorTransition { .. }) {
                lines.push(event.summary());
                if lines.len() == count {
                    break;
                }
            }
        }
        lines.reverse();
        lines
    }

    pub fn pending_wait_count(&self) -> usize {
        self.waits
            .iter()
            .filter(|wait| wait.state == WaitState::Pending)
            .count()
    }

    pub fn live_resource_count(&self) -> usize {
        self.resources
            .iter()
            .filter(|resource| resource.live)
            .count()
    }

    pub fn authority_count(&self) -> usize {
        self.authority_bindings.len()
    }

    pub fn active_authority_count(&self) -> usize {
        self.authority_bindings
            .iter()
            .filter(|authority| authority.state == AuthorityState::Bound)
            .count()
    }

    pub fn capabilities(&self) -> &CapabilityLedger {
        &self.capabilities
    }

    pub fn authority_bindings(&self) -> &[AuthorityBindingRecord] {
        &self.authority_bindings
    }

    pub fn event_log(&self) -> &EventLog {
        &self.event_log
    }

    pub fn stores(&self) -> &[StoreRecord] {
        &self.stores
    }

    pub fn transactions(&self) -> &[SemanticTransactionRecord] {
        &self.transactions
    }

    pub fn fast_path_plans(&self) -> &[FastPathPlanRecord] {
        &self.fast_path_plans
    }

    pub fn boundaries(&self) -> &[BoundaryRecord] {
        &self.boundaries
    }

    pub fn event_log_tail(&self, count: usize) -> &[EventRecord] {
        self.event_log.tail(count)
    }

    pub fn check_invariants(&self) -> Result<(), SemanticInvariantError> {
        for task in &self.tasks {
            for resource in &task.resources {
                if !self.resources.iter().any(|entry| entry.id == *resource) {
                    return Err(SemanticInvariantError::TaskReferencesMissingResource {
                        task: task.id,
                        resource: *resource,
                    });
                }
            }
        }

        for resource in &self.resources {
            if let Some(task) = resource.owner_task
                && !self.tasks.iter().any(|entry| entry.id == task)
            {
                return Err(SemanticInvariantError::ResourceReferencesMissingTask {
                    resource: resource.id,
                    task,
                });
            }
            if let Some(store) = resource.owner_store
                && !self.stores.iter().any(|entry| entry.id == store)
            {
                return Err(SemanticInvariantError::ResourceReferencesMissingStore {
                    resource: resource.id,
                    store,
                });
            }
        }

        for wait in &self.waits {
            if !self.tasks.iter().any(|entry| entry.id == wait.owner_task) {
                return Err(SemanticInvariantError::WaitReferencesMissingTask {
                    wait: wait.id,
                    task: wait.owner_task,
                });
            }
        }

        for store in &self.stores {
            if !self
                .fault_domains
                .iter()
                .any(|entry| entry.id == store.fault_domain)
            {
                return Err(SemanticInvariantError::StoreReferencesMissingFaultDomain {
                    store: store.id,
                    fault_domain: store.fault_domain,
                });
            }
            if store.state != StoreState::Dead {
                let Some(resource) = store.resource else {
                    return Err(SemanticInvariantError::LiveStoreMissingResource {
                        store: store.id,
                    });
                };
                if !self.resources.iter().any(|entry| {
                    entry.id == resource && entry.owner_store == Some(store.id) && entry.live
                }) {
                    return Err(SemanticInvariantError::StoreReferencesDeadResource {
                        store: store.id,
                        resource,
                    });
                }
            }
        }

        for authority in &self.authority_bindings {
            if authority.state != AuthorityState::Bound {
                continue;
            }
            let Some(resource) = self
                .resources
                .iter()
                .find(|entry| entry.id == authority.resource)
            else {
                return Err(SemanticInvariantError::AuthorityReferencesMissingResource {
                    authority: authority.id,
                    resource: authority.resource,
                });
            };
            if !resource.live {
                return Err(SemanticInvariantError::AuthorityReferencesDeadResource {
                    authority: authority.id,
                    resource: authority.resource,
                });
            }
            for operation in authority.operations.as_slice() {
                if self
                    .capabilities
                    .check(&authority.subject, &authority.object, operation)
                    .is_err()
                {
                    return Err(SemanticInvariantError::AuthorityCapabilityMissing {
                        authority: authority.id,
                    });
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactProfile {
    pub artifact_profile: String,
    pub target_arch: String,
    pub machine_abi_version: String,
    pub supervisor_abi_version: String,
    pub wasm_feature_profile: String,
    pub memory64: bool,
    pub multi_memory: bool,
    pub dmw_layout: String,
    pub network_contract_version: String,
    pub compiler_engine: String,
    pub compiler_execution_mode: String,
    pub artifact_format: String,
    pub runtime_executor_abi: String,
}

impl ArtifactProfile {
    pub fn summary(&self) -> String {
        format!(
            "artifact_profile={} target_arch={} machine_abi={} supervisor_abi={} wasm_profile={} dmw_layout={} network={} engine={} mode={} format={} runtime_executor={}",
            self.artifact_profile,
            self.target_arch,
            self.machine_abi_version,
            self.supervisor_abi_version,
            self.wasm_feature_profile,
            self.dmw_layout,
            self.network_contract_version,
            self.compiler_engine,
            self.compiler_execution_mode,
            self.artifact_format,
            self.runtime_executor_abi
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestStateSnapshot {
    pub canonical_isa: CanonicalGuestIsa,
    pub register_count: u32,
    pub memory_page_count: u64,
    pub vma_count: u32,
    pub signal_queue_count: u32,
    pub note: String,
}

impl GuestStateSnapshot {
    pub fn riscv64_placeholder() -> Self {
        Self {
            canonical_isa: CanonicalGuestIsa::Riscv64,
            register_count: 33,
            memory_page_count: 0,
            vma_count: 0,
            signal_queue_count: 0,
            note: "placeholder canonical guest state; real VM state is not implemented in prototype v0"
                .to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateBoundarySnapshot {
    pub timer_epoch: u64,
    pub pending_irq_causes: u32,
    pub pending_dma_completions: u32,
    pub active_dmw_lease_count: u32,
    pub active_mmio_authority_count: u32,
    pub active_dma_authority_count: u32,
    pub active_irq_authority_count: u32,
    pub active_packet_device_authority_count: u32,
    pub active_virtio_queue_authority_count: u32,
    pub pending_network_inputs: u32,
    pub random_epoch: u64,
    pub scheduler_decision_cursor: u64,
    pub cow_epoch: u64,
    pub background_copy_pages: u64,
    pub native_state_policy: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotBarrierSnapshot {
    pub id: SnapshotBarrierId,
    pub event_log_cursor: EventId,
    pub pending_wait_count: usize,
    pub live_resource_count: usize,
    pub active_transaction_count: usize,
    pub active_dmw_lease_count: u32,
    pub dmw_quiescent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticSnapshot {
    pub barrier: SnapshotBarrierSnapshot,
    pub tasks: Vec<TaskRecord>,
    pub resources: Vec<ResourceRecord>,
    pub authority_bindings: Vec<AuthorityBindingRecord>,
    pub waits: Vec<WaitRecord>,
    pub fault_domains: Vec<FaultDomainRecord>,
    pub stores: Vec<StoreRecord>,
    pub transactions: Vec<SemanticTransactionRecord>,
    pub fast_path_plans: Vec<FastPathPlanRecord>,
    pub boundaries: Vec<BoundaryRecord>,
    pub capabilities: Vec<CapabilityRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationPackage {
    pub schema_version: u32,
    pub package_id: String,
    pub source_host_arch: String,
    pub target_host_arch_hint: String,
    pub required_artifact_profile: ArtifactProfile,
    pub guest: GuestStateSnapshot,
    pub substrate_boundary: SubstrateBoundarySnapshot,
    pub semantic: SemanticSnapshot,
}

impl MigrationPackage {
    pub fn validate_portability(&self) -> Result<(), MigrationValidationError> {
        if self.schema_version != 1 {
            return Err(MigrationValidationError::UnsupportedSchema);
        }
        if self.semantic.barrier.active_dmw_lease_count != 0 || !self.semantic.barrier.dmw_quiescent
        {
            return Err(MigrationValidationError::ActiveDmwLease);
        }
        if self.substrate_boundary.pending_dma_completions != 0 {
            return Err(MigrationValidationError::InFlightDma);
        }
        if self.substrate_boundary.active_mmio_authority_count != 0 {
            return Err(MigrationValidationError::ActiveMmioAuthority);
        }
        if self.substrate_boundary.active_dma_authority_count != 0 {
            return Err(MigrationValidationError::ActiveDmaAuthority);
        }
        if self.substrate_boundary.active_irq_authority_count != 0 {
            return Err(MigrationValidationError::ActiveIrqAuthority);
        }
        if self.substrate_boundary.active_packet_device_authority_count != 0 {
            return Err(MigrationValidationError::ActivePacketDeviceAuthority);
        }
        if self.substrate_boundary.active_virtio_queue_authority_count != 0 {
            return Err(MigrationValidationError::ActiveVirtioQueueAuthority);
        }
        if self.semantic.barrier.active_transaction_count != 0 {
            return Err(MigrationValidationError::ActiveSemanticTransaction);
        }
        if self.guest.canonical_isa != CanonicalGuestIsa::Riscv64 {
            return Err(MigrationValidationError::UnsupportedGuestIsa);
        }
        Ok(())
    }

    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "migration package: id={} source_host={} target_hint={} guest_isa={}",
            self.package_id,
            self.source_host_arch,
            self.target_host_arch_hint,
            self.guest.canonical_isa.as_str()
        ));
        lines.push(format!(
            "snapshot barrier: id={} cursor={} pending_waits={} live_resources={} active_transactions={} active_dmw_leases={} active_mmio={} active_dma={} active_irq={} active_packet_device={} active_virtqueue={} pending_net={} cow_epoch={} background_pages={}",
            self.semantic.barrier.id,
            self.semantic.barrier.event_log_cursor,
            self.semantic.barrier.pending_wait_count,
            self.semantic.barrier.live_resource_count,
            self.semantic.barrier.active_transaction_count,
            self.semantic.barrier.active_dmw_lease_count,
            self.substrate_boundary.active_mmio_authority_count,
            self.substrate_boundary.active_dma_authority_count,
            self.substrate_boundary.active_irq_authority_count,
            self.substrate_boundary.active_packet_device_authority_count,
            self.substrate_boundary.active_virtio_queue_authority_count,
            self.substrate_boundary.pending_network_inputs,
            self.substrate_boundary.cow_epoch,
            self.substrate_boundary.background_copy_pages
        ));
        lines.push(format!(
            "semantic roots: tasks={} resources={} authorities={} waits={} capabilities={} fault_domains={} stores={} transactions={} fastpath_plans={} boundaries={}",
            self.semantic.tasks.len(),
            self.semantic.resources.len(),
            self.semantic.authority_bindings.len(),
            self.semantic.waits.len(),
            self.semantic.capabilities.len(),
            self.semantic.fault_domains.len(),
            self.semantic.stores.len(),
            self.semantic.transactions.len(),
            self.semantic.fast_path_plans.len(),
            self.semantic.boundaries.len()
        ));
        lines.push(format!(
            "required artifacts: {}",
            self.required_artifact_profile.summary()
        ));
        lines.push(
            "not migrated: raw pointers, native stacks, active semantic transactions, active DMW leases, DMA mappings, MMIO mappings, IRQ registrations, translated code cache"
                .to_string(),
        );
        lines
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationValidationError {
    UnsupportedSchema,
    ActiveDmwLease,
    InFlightDma,
    ActiveMmioAuthority,
    ActiveDmaAuthority,
    ActiveIrqAuthority,
    ActivePacketDeviceAuthority,
    ActiveVirtioQueueAuthority,
    ActiveSemanticTransaction,
    UnsupportedGuestIsa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticInvariantError {
    TaskReferencesMissingResource {
        task: TaskId,
        resource: ResourceId,
    },
    ResourceReferencesMissingTask {
        resource: ResourceId,
        task: TaskId,
    },
    ResourceReferencesMissingStore {
        resource: ResourceId,
        store: StoreId,
    },
    WaitReferencesMissingTask {
        wait: WaitId,
        task: TaskId,
    },
    StoreReferencesMissingFaultDomain {
        store: StoreId,
        fault_domain: FaultDomainId,
    },
    LiveStoreMissingResource {
        store: StoreId,
    },
    StoreReferencesDeadResource {
        store: StoreId,
        resource: ResourceId,
    },
    AuthorityReferencesMissingResource {
        authority: AuthorityId,
        resource: ResourceId,
    },
    AuthorityReferencesDeadResource {
        authority: AuthorityId,
        resource: ResourceId,
    },
    AuthorityCapabilityMissing {
        authority: AuthorityId,
    },
}

impl Default for SemanticGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_attenuation_cannot_expand_rights() {
        let mut ledger = CapabilityLedger::new();
        let parent = ledger.grant("driver", "mmio-bar0", &["read"], "store");

        assert!(
            ledger
                .attenuate(parent, "helper", &["read"], "activation")
                .is_some()
        );
        let helper = ledger
            .check("helper", "mmio-bar0", "read")
            .expect("attenuated capability");
        assert_eq!(helper.source, "attenuated");
        assert!(
            ledger
                .attenuate(parent, "helper", &["write"], "activation")
                .is_none()
        );
    }

    #[test]
    fn runtime_modes_publish_contract_policies() {
        let graph = SemanticGraph::with_runtime_mode(RuntimeMode::Replay);

        assert_eq!(graph.runtime_mode(), RuntimeMode::Replay);
        assert_eq!(graph.runtime_mode().event_log_policy(), "deterministic");
        assert!(graph.runtime_mode().deterministic_boundary());
        assert!(!graph.runtime_mode().fast_path_enabled());
    }

    #[test]
    fn boundary_status_is_queryable_and_versioned() {
        let mut graph = SemanticGraph::new();
        let boundary = graph.publish_boundary(
            "target-cwasm",
            BoundaryKind::RuntimeExecutor,
            BoundaryStatus::NotLinked,
            "runtime-only-executor-v1",
            Some("code-publish"),
        );

        assert_eq!(graph.boundary_count(), 1);
        assert_eq!(graph.boundaries()[0].id, boundary);
        assert_eq!(graph.boundaries()[0].status, BoundaryStatus::NotLinked);

        let same_boundary = graph.publish_boundary(
            "target-cwasm",
            BoundaryKind::RuntimeExecutor,
            BoundaryStatus::RuntimeContract,
            "runtime-only-executor-v1",
            Some("hostcall-trampoline"),
        );

        assert_eq!(same_boundary, boundary);
        assert_eq!(graph.boundary_count(), 1);
        assert_eq!(graph.boundaries()[0].generation, 2);
        assert_eq!(
            graph.boundaries()[0].summary(),
            "boundary target-cwasm kind=runtime-executor status=runtime-contract backend=runtime-only-executor-v1 blocked=hostcall-trampoline generation=2"
        );
        assert_eq!(
            graph.event_log_tail(1)[0].kind.summary(),
            "BoundaryPublished boundary=1 name=target-cwasm kind=runtime-executor status=runtime-contract backend=runtime-only-executor-v1 blocked=hostcall-trampoline generation=2"
        );
    }

    #[test]
    fn capability_ledger_reports_owner_recovery_state() {
        let mut graph = SemanticGraph::new();
        let store = graph.register_store("driver", "driver", "driver", "restartable");
        graph.grant_manifest_capability("driver", "mmio.bar0", &["read", "write"], "store");
        graph.grant_capability("driver", "irq11", &["ack"], "store");
        let mmio = graph
            .capabilities()
            .check("driver", "mmio.bar0", "read")
            .expect("manifest capability");
        assert_eq!(mmio.class, CapabilityClass::MmioRegion);
        assert_eq!(mmio.source, "artifact-manifest");
        assert_eq!(mmio.owner_store, Some(store));

        let report = graph.revoke_capabilities_for_subject("driver");
        let summary = graph.capability_owner_summary("driver");

        assert_eq!(report.count(), 2);
        assert_eq!(summary.active, 0);
        assert_eq!(summary.revoked, 2);
        assert_eq!(
            graph.check_capability("driver", "mmio.bar0", "read"),
            Err(CapabilityDenyReason::Revoked)
        );
    }

    #[test]
    fn capability_check_records_denial_and_generation_mismatch() {
        let mut graph = SemanticGraph::new();
        let generation = {
            graph.grant_capability("linux_syscall", "timer.sleep", &["arm"], "wait-token");
            graph
                .capability_generation("linux_syscall", "timer.sleep")
                .expect("capability generation")
        };

        assert!(
            graph
                .check_capability("linux_syscall", "timer.sleep", "arm")
                .is_ok()
        );
        graph.revoke_capability_by_subject_object("linux_syscall", "timer.sleep");
        assert_eq!(
            graph.check_capability("linux_syscall", "timer.sleep", "arm"),
            Err(CapabilityDenyReason::Revoked)
        );
        graph.grant_capability("linux_syscall", "timer.sleep", &["arm"], "wait-token");
        assert_eq!(
            graph.check_capability_generation("linux_syscall", "timer.sleep", "arm", generation),
            Err(CapabilityDenyReason::GenerationMismatch)
        );
    }

    #[test]
    fn wait_flow_is_recorded_in_event_log() {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
        graph.set_task_state(7, TaskState::Running);

        graph.record_wait_created(11, 7, SemanticWaitKind::Futex, 1);
        graph.record_wait_resolved(11, "ready");

        assert_eq!(graph.wait_count(), 1);
        assert_eq!(
            graph.event_log_tail(1)[0].kind.summary(),
            "WaitResolved wait=11 reason=ready"
        );
    }

    #[test]
    fn stale_resource_handles_are_rejected() {
        let mut graph = SemanticGraph::new();
        let resource = graph.register_resource(ResourceKind::Fd, None, "fd:/sandbox/hello.txt");
        let handle = graph.resource_handle(resource).expect("resource handle");

        assert_eq!(graph.validate_resource_handle(handle), Ok(()));
        graph.close_resource(resource);
        assert_eq!(
            graph.validate_resource_handle(handle),
            Err(GenerationCheckError::GenerationMismatch {
                expected: 1,
                actual: Some(2),
            })
        );
        assert_eq!(
            graph.event_log_tail(1)[0].kind.summary(),
            "ResourceHandleRejected resource=1 expected=1 actual=2 reason=generation-mismatch"
        );
    }

    #[test]
    fn stale_wait_tokens_are_rejected() {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
        graph.record_wait_created(11, 7, SemanticWaitKind::Timer, 3);
        let handle = graph.wait_handle(11).expect("wait handle");

        assert_eq!(graph.validate_wait_handle(handle), Ok(()));
        assert_eq!(
            graph.validate_wait_handle(WaitHandle::new(11, 2)),
            Err(GenerationCheckError::GenerationMismatch {
                expected: 2,
                actual: Some(3),
            })
        );
        assert_eq!(
            graph.event_log_tail(1)[0].kind.summary(),
            "WaitTokenRejected wait=11 expected=2 actual=3 reason=generation-mismatch"
        );
    }

    #[test]
    fn store_lifecycle_rebinds_instance_resource() {
        let mut graph = SemanticGraph::new();
        let store = graph.register_store("procfs_service", "procfs", "service", "restartable");

        graph.set_store_state(store, StoreState::Instantiating);
        graph.set_store_state(store, StoreState::Running);
        let first_resource = graph.store_resource(store).expect("initial store resource");

        graph.record_store_trap(store, "injected procfs read fault");
        graph.set_store_state(store, StoreState::Draining);
        graph.set_store_state(store, StoreState::Restarting);
        let drop_report = graph
            .drop_store_instance(store)
            .expect("dropped store instance");
        assert_eq!(drop_report.previous_resource, Some(first_resource));
        assert_eq!(drop_report.closed_resources, 1);
        assert_eq!(
            graph.validate_resource_handle(ResourceHandle::new(first_resource, 1)),
            Err(GenerationCheckError::GenerationMismatch {
                expected: 1,
                actual: Some(2),
            })
        );

        let rebind_report = graph
            .rebind_store_instance(store)
            .expect("rebound store resource");
        let second_resource = rebind_report.resource;
        graph.set_store_state(store, StoreState::Running);

        assert_ne!(first_resource, second_resource);
        assert_eq!(graph.store_count(), 1);
        assert_eq!(graph.live_resource_count(), 1);
        assert_eq!(graph.stores()[0].restart_count, 1);
        assert_eq!(graph.stores()[0].state, StoreState::Running);
        assert_eq!(
            graph.event_log_tail(1)[0].kind.summary(),
            "FaultDomainRestarted domain=1"
        );
    }

    #[test]
    fn store_executor_transitions_are_recorded_in_event_log() {
        let mut graph = SemanticGraph::new();
        let store = graph.register_store("vfs_service", "vfs", "service", "restartable");

        graph.record_store_executor_transition(
            store,
            "artifact-verified",
            "draining",
            Some("store-draining"),
            "not-linked",
            "contract-declared",
        );

        assert_eq!(
            graph.event_log_tail(1)[0].kind.summary(),
            "StoreExecutorTransition store=1 artifact-verified->draining blocked=store-draining hostcalls=not-linked traps=contract-declared"
        );
        assert_eq!(graph.store_executor_transition_count(), 1);
        assert!(
            graph.store_executor_transition_tail(1)[0].contains(
                "source=executor StoreExecutorTransition store=1 artifact-verified->draining blocked=store-draining hostcalls=not-linked traps=contract-declared"
            )
        );
    }

    #[test]
    fn transaction_rollback_and_store_owned_resource_cleanup_are_recorded() {
        let mut graph = SemanticGraph::new();
        let store = graph.register_store("devfs_service", "devfs", "service", "restartable");
        graph.set_store_state(store, StoreState::Running);
        let scratch = graph.register_resource_for_store(
            ResourceKind::Device,
            None,
            Some(store),
            "device:pulse-shadow",
        );
        let authority = graph
            .bind_authority_resource(
                scratch,
                "devfs_service",
                "device.pulse-shadow",
                &["read"],
                "store",
            )
            .expect("store-owned device authority");
        let transaction = graph.begin_transaction("devfs.read_device", Some(store), Some(9));

        graph.rollback_transaction(transaction, "devfs_service trapped");
        graph.record_store_trap_class(store, TrapClass::ServiceTrap, "devfs_service trapped");
        let cleanup = graph.cleanup_resources_owned_by_store(store);
        assert_eq!(cleanup.closed_resources, 2);
        assert_eq!(cleanup.revoked_authorities, 1);
        assert_eq!(
            graph
                .authority_bindings()
                .iter()
                .find(|binding| binding.id == authority)
                .expect("authority binding")
                .state,
            AuthorityState::Revoked
        );

        assert_eq!(
            graph.validate_resource_handle(ResourceHandle::new(scratch, 1)),
            Err(GenerationCheckError::GenerationMismatch {
                expected: 1,
                actual: Some(2),
            })
        );
        assert_eq!(graph.transactions()[0].state, TransactionState::RolledBack);
        assert!(graph.event_log_tail(32).iter().any(|event| matches!(
            event.kind,
            EventKind::FaultClassified {
                trap: TrapClass::ServiceTrap,
                class: FaultClass::Service,
                ..
            }
        )));
    }

    #[test]
    fn network_events_are_recorded_as_semantic_state() {
        let mut graph = SemanticGraph::new();
        let device =
            graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
        let interface =
            graph.register_resource(ResourceKind::NetInterface, None, "net-interface:net0");
        let socket = graph.register_resource(ResourceKind::NetSocket, Some(7), "socket:tcp:1");
        let irq = graph.register_resource(ResourceKind::IrqLine, None, "irq:net0");
        let dma = graph.register_resource(ResourceKind::DmaBuffer, None, "dma:net0-rx");

        graph.record_net_interface_state_changed(interface, true);
        graph.record_device_irq_delivered(irq, device, "rx");
        graph.record_dma_submitted(dma, device, 64);
        graph.record_dma_completed(dma, device, 64);
        graph.record_packet_received(interface, Some(socket), 0x6e6574307278, 64);

        assert!(graph.event_log_tail(8).iter().any(|event| matches!(
            event.kind,
            EventKind::PacketReceived {
                interface: recorded_interface,
                socket: Some(recorded_socket),
                len: 64,
                ..
            } if recorded_interface == interface && recorded_socket == socket
        )));
    }

    #[test]
    fn authority_bindings_drive_resource_and_capability_lifecycle() {
        let mut graph = SemanticGraph::new();
        let mmio = graph.register_resource(ResourceKind::MmioRegion, None, "mmio:virtio-net0");
        let authority = graph
            .bind_authority_resource(
                mmio,
                "driver_virtio_net",
                "mmio.virtio-net0",
                &["read", "write"],
                "store",
            )
            .expect("authority binding");

        assert_eq!(graph.authority_count(), 1);
        assert_eq!(graph.active_authority_count(), 1);
        assert!(
            graph
                .check_capability("driver_virtio_net", "mmio.virtio-net0", "write")
                .is_ok()
        );
        assert_eq!(graph.check_invariants(), Ok(()));

        assert!(graph.release_authority_binding(authority, "driver micro-reboot"));
        assert_eq!(graph.active_authority_count(), 0);
        assert_eq!(
            graph.check_capability("driver_virtio_net", "mmio.virtio-net0", "write"),
            Err(CapabilityDenyReason::Revoked)
        );
        assert_eq!(
            graph.validate_resource_handle(ResourceHandle::new(mmio, 1)),
            Err(GenerationCheckError::GenerationMismatch {
                expected: 1,
                actual: Some(2),
            })
        );
        assert!(graph.event_log_tail(8).iter().any(|event| matches!(
            event.kind,
            EventKind::AuthorityReleased {
                authority: recorded,
                resource: recorded_resource,
                ..
            } if recorded == authority && recorded_resource == mmio
        )));
        assert_eq!(graph.check_invariants(), Ok(()));
    }

    #[test]
    fn packet_device_authority_is_part_of_the_hardware_ledger() {
        let mut graph = SemanticGraph::new();
        let device =
            graph.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
        let authority = graph
            .bind_authority_resource(
                device,
                "driver_virtio_net",
                "packet-device.net0",
                &["rx", "tx", "poll"],
                "store",
            )
            .expect("packet device authority binding");

        assert_eq!(
            graph.authority_bindings()[0].kind,
            AuthorityKind::PacketDevice
        );
        assert!(
            graph
                .check_capability("driver_virtio_net", "packet-device.net0", "rx")
                .is_ok()
        );
        assert!(graph.revoke_authority_binding(authority, "driver restart"));
        assert_eq!(
            graph.check_capability("driver_virtio_net", "packet-device.net0", "rx"),
            Err(CapabilityDenyReason::Revoked)
        );
    }

    #[test]
    fn invariants_reject_bound_authority_without_capability() {
        let mut graph = SemanticGraph::new();
        let irq = graph.register_resource(ResourceKind::IrqLine, None, "irq:net0");
        let authority = graph
            .bind_authority_resource(irq, "driver_virtio_net", "irq.net0", &["ack"], "store")
            .expect("authority binding");

        graph.revoke_capability_by_subject_object("driver_virtio_net", "irq.net0");

        assert_eq!(
            graph.check_invariants(),
            Err(SemanticInvariantError::AuthorityCapabilityMissing { authority })
        );
    }

    #[test]
    fn migration_package_rejects_active_dmw_leases() {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
        graph.record_snapshot_barrier_enter(1);
        graph.record_snapshot_barrier_exit(1);

        let package = graph.migration_package(
            "test",
            "x86_64",
            "aarch64",
            test_artifact_profile(),
            GuestStateSnapshot::riscv64_placeholder(),
            SubstrateBoundarySnapshot {
                timer_epoch: 0,
                pending_irq_causes: 0,
                pending_dma_completions: 0,
                active_dmw_lease_count: 1,
                active_mmio_authority_count: 0,
                active_dma_authority_count: 0,
                active_irq_authority_count: 0,
                active_packet_device_authority_count: 0,
                active_virtio_queue_authority_count: 0,
                pending_network_inputs: 0,
                random_epoch: 0,
                scheduler_decision_cursor: 0,
                cow_epoch: 0,
                background_copy_pages: 0,
                native_state_policy: "rebuild".to_string(),
            },
            1,
            false,
        );

        assert_eq!(
            package.validate_portability(),
            Err(MigrationValidationError::ActiveDmwLease)
        );
    }

    #[test]
    fn migration_package_rejects_active_semantic_transactions() {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
        graph.begin_transaction("net.recvmsg", None, Some(1));

        let package = graph.migration_package(
            "test",
            "x86_64",
            "aarch64",
            test_artifact_profile(),
            GuestStateSnapshot::riscv64_placeholder(),
            SubstrateBoundarySnapshot {
                timer_epoch: 0,
                pending_irq_causes: 0,
                pending_dma_completions: 0,
                active_dmw_lease_count: 0,
                active_mmio_authority_count: 0,
                active_dma_authority_count: 0,
                active_irq_authority_count: 0,
                active_packet_device_authority_count: 0,
                active_virtio_queue_authority_count: 0,
                pending_network_inputs: 0,
                random_epoch: 0,
                scheduler_decision_cursor: 0,
                cow_epoch: 0,
                background_copy_pages: 0,
                native_state_policy: "rebuild".to_string(),
            },
            1,
            true,
        );

        assert_eq!(
            package.validate_portability(),
            Err(MigrationValidationError::ActiveSemanticTransaction)
        );
    }

    #[test]
    fn migration_package_rejects_active_substrate_authorities() {
        let cases: [(fn(&mut SubstrateBoundarySnapshot), MigrationValidationError); 5] = [
            (
                |boundary| boundary.active_mmio_authority_count = 1,
                MigrationValidationError::ActiveMmioAuthority,
            ),
            (
                |boundary| boundary.active_dma_authority_count = 1,
                MigrationValidationError::ActiveDmaAuthority,
            ),
            (
                |boundary| boundary.active_irq_authority_count = 1,
                MigrationValidationError::ActiveIrqAuthority,
            ),
            (
                |boundary| boundary.active_packet_device_authority_count = 1,
                MigrationValidationError::ActivePacketDeviceAuthority,
            ),
            (
                |boundary| boundary.active_virtio_queue_authority_count = 1,
                MigrationValidationError::ActiveVirtioQueueAuthority,
            ),
        ];

        for (set_active, expected) in cases {
            let mut graph = SemanticGraph::new();
            graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
            graph.record_snapshot_barrier_enter(1);
            graph.record_snapshot_barrier_exit(1);
            let mut boundary = test_substrate_boundary();
            set_active(&mut boundary);
            let package = graph.migration_package(
                "test",
                "x86_64",
                "aarch64",
                test_artifact_profile(),
                GuestStateSnapshot::riscv64_placeholder(),
                boundary,
                1,
                true,
            );

            assert_eq!(package.validate_portability(), Err(expected));
        }
    }

    fn test_substrate_boundary() -> SubstrateBoundarySnapshot {
        SubstrateBoundarySnapshot {
            timer_epoch: 0,
            pending_irq_causes: 0,
            pending_dma_completions: 0,
            active_dmw_lease_count: 0,
            active_mmio_authority_count: 0,
            active_dma_authority_count: 0,
            active_irq_authority_count: 0,
            active_packet_device_authority_count: 0,
            active_virtio_queue_authority_count: 0,
            pending_network_inputs: 0,
            random_epoch: 0,
            scheduler_decision_cursor: 0,
            cow_epoch: 0,
            background_copy_pages: 0,
            native_state_policy: "rebuild".to_string(),
        }
    }

    fn test_artifact_profile() -> ArtifactProfile {
        ArtifactProfile {
            artifact_profile: "test".to_string(),
            target_arch: "target-native".to_string(),
            machine_abi_version: "machine".to_string(),
            supervisor_abi_version: "supervisor".to_string(),
            wasm_feature_profile: "wasm32".to_string(),
            memory64: false,
            multi_memory: false,
            dmw_layout: "dmw".to_string(),
            network_contract_version: "network".to_string(),
            compiler_engine: "wasmtime".to_string(),
            compiler_execution_mode: "precompiled-core-module".to_string(),
            artifact_format: "cwasm".to_string(),
            runtime_executor_abi: "vmos-runtime-only-executor-v0".to_string(),
        }
    }
}
