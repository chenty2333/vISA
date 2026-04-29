use alloc::{format, string::String};

use super::*;

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
        let blocked_by = self.blocked_by.as_ref().map(String::as_str).unwrap_or("none");
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
