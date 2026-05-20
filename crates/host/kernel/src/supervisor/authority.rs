use alloc::{format, string::String};

use semantic_core::{
    AuthorityId, AuthorityKind, AuthorityState, CapabilityDenyReason, CapabilityOwnerSummary,
    Generation, HostcallClass, ResourceHandle, ResourceId, ResourceKind, SemanticGraph, StoreId,
};
use vmos_abi::PlanKind;

use super::runtime::PrototypeRuntime;

pub(crate) const SUBSTRATE_AUTHORITY_CONTRACT_VERSION: &str =
    "vmos-substrate-authority-contract-v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostcallBinding {
    pub(crate) class: HostcallClass,
    pub(crate) subject: &'static str,
    pub(crate) object: &'static str,
    pub(crate) operation: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubstrateAuthorityClass {
    DmwWindow,
    PacketDevice,
    MmioRegion,
    DmaBuffer,
    IrqLine,
    VirtioQueue,
}

impl SubstrateAuthorityClass {
    pub(crate) const fn resource_kind(self) -> ResourceKind {
        match self {
            Self::DmwWindow => ResourceKind::DmwWindow,
            Self::PacketDevice => ResourceKind::PacketDevice,
            Self::MmioRegion => ResourceKind::MmioRegion,
            Self::DmaBuffer => ResourceKind::DmaBuffer,
            Self::IrqLine => ResourceKind::IrqLine,
            Self::VirtioQueue => ResourceKind::VirtioQueue,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SubstrateAuthoritySpec {
    pub(crate) class: SubstrateAuthorityClass,
    pub(crate) subject: &'static str,
    pub(crate) object: &'static str,
    pub(crate) operations: &'static [&'static str],
    pub(crate) lifetime: &'static str,
    pub(crate) label: &'static str,
    pub(crate) owner_store: Option<StoreId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SubstrateAuthorityLease {
    pub(crate) class: SubstrateAuthorityClass,
    pub(crate) resource: ResourceId,
    pub(crate) authority: AuthorityId,
    pub(crate) handle: ResourceHandle,
}

pub(crate) struct AuthorityPlane;

impl AuthorityPlane {
    pub(crate) const fn new() -> Self {
        Self
    }

    pub(crate) fn record_hostcall_plan(
        &self,
        semantic: &mut SemanticGraph,
        label: &str,
        kind: PlanKind,
    ) {
        let binding = hostcall_binding(kind);
        semantic.record_hostcall(
            label,
            binding.class,
            binding.subject,
            binding.object,
            binding.operation,
        );
    }

    pub(crate) fn require(
        &self,
        semantic: &mut SemanticGraph,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> Result<(), CapabilityDenyReason> {
        semantic.check_capability(subject, object, operation).map(|_| ())
    }

    pub(crate) fn require_generation(
        &self,
        semantic: &mut SemanticGraph,
        subject: &str,
        object: &str,
        operation: &str,
        expected_generation: Generation,
    ) -> Result<(), CapabilityDenyReason> {
        semantic
            .check_capability_generation(subject, object, operation, expected_generation)
            .map(|_| ())
    }

    pub(crate) fn generation(
        &self,
        semantic: &SemanticGraph,
        subject: &str,
        object: &str,
    ) -> Option<Generation> {
        semantic.capability_generation(subject, object)
    }

    pub(crate) fn revoke(
        &self,
        semantic: &mut SemanticGraph,
        subject: &str,
        object: &str,
    ) -> Result<(), &'static str> {
        semantic
            .revoke_current_capability(subject, object)
            .map(|_| ())
            .ok_or("capability to revoke was not present")
    }

    pub(crate) fn owner_summary(
        &self,
        semantic: &SemanticGraph,
        subject: &str,
    ) -> CapabilityOwnerSummary {
        semantic.capability_owner_summary(subject)
    }

    pub(crate) fn grant(
        &self,
        semantic: &mut SemanticGraph,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) {
        semantic.grant_capability(subject, object, operations, lifetime);
    }

    pub(crate) fn bind_substrate_authority(
        &self,
        semantic: &mut SemanticGraph,
        spec: SubstrateAuthoritySpec,
    ) -> Result<SubstrateAuthorityLease, &'static str> {
        let resource = semantic.register_resource_for_store(
            spec.class.resource_kind(),
            None,
            spec.owner_store,
            spec.label,
        );
        self.bind_existing_substrate_authority(semantic, resource, spec)
    }

    pub(crate) fn bind_existing_substrate_authority(
        &self,
        semantic: &mut SemanticGraph,
        resource: ResourceId,
        spec: SubstrateAuthoritySpec,
    ) -> Result<SubstrateAuthorityLease, &'static str> {
        let authority = semantic
            .bind_authority_resource(
                resource,
                spec.subject,
                spec.object,
                spec.operations,
                spec.lifetime,
            )
            .ok_or("substrate authority resource could not be bound")?;
        let handle = semantic
            .resource_handle(resource)
            .ok_or("substrate authority resource did not publish a handle")?;
        Ok(SubstrateAuthorityLease { class: spec.class, resource, authority, handle })
    }

    pub(crate) fn substrate_authority_line(&self, semantic: &SemanticGraph) -> String {
        let mut dmw = 0usize;
        let mut device = 0usize;
        let mut mmio = 0usize;
        let mut dma = 0usize;
        let mut irq = 0usize;
        let mut virtqueue = 0usize;
        for authority in semantic
            .authority_bindings()
            .iter()
            .filter(|authority| authority.state == AuthorityState::Bound)
        {
            match authority.kind {
                AuthorityKind::DmwWindow => dmw += 1,
                AuthorityKind::Device
                | AuthorityKind::PacketDevice
                | AuthorityKind::BlockDevice => device += 1,
                AuthorityKind::MmioRegion => mmio += 1,
                AuthorityKind::DmaPool | AuthorityKind::DmaBuffer => dma += 1,
                AuthorityKind::IrqLine => irq += 1,
                AuthorityKind::VirtioQueue => virtqueue += 1,
            }
        }
        format!(
            "substrate authority contract={} active={}/{} device={} mmio={} dma={} irq={} virtqueue={} dmw={}",
            SUBSTRATE_AUTHORITY_CONTRACT_VERSION,
            semantic.active_authority_count(),
            semantic.authority_count(),
            device,
            mmio,
            dma,
            irq,
            virtqueue,
            dmw
        )
    }
}

pub(crate) fn hostcall_binding(kind: PlanKind) -> HostcallBinding {
    match kind {
        PlanKind::GetCwd | PlanKind::Uname => HostcallBinding {
            class: HostcallClass::PureQuery,
            subject: "linux_syscall",
            object: "process.metadata",
            operation: "query",
        },
        PlanKind::Write => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "console.write",
            operation: "write",
        },
        PlanKind::Writev => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "fd.table",
            operation: "writev",
        },
        PlanKind::OpenAt => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "vfs_service",
            object: "vfs.namespace",
            operation: "lookup",
        },
        PlanKind::Read => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "vfs_service",
            object: "vfs.namespace",
            operation: "read",
        },
        PlanKind::Readv => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "fd.table",
            operation: "readv",
        },
        PlanKind::Close => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "fd.table",
            operation: "close",
        },
        PlanKind::CloseRange => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "fd.table",
            operation: "close-range",
        },
        PlanKind::Dup => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "fd.table",
            operation: "dup",
        },
        PlanKind::GetDents64 => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "vfs_service",
            object: "vfs.namespace",
            operation: "list",
        },
        PlanKind::ReadLinkAt => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "vfs_service",
            object: "vfs.namespace",
            operation: "readlink",
        },
        PlanKind::LinkAt => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "vfs_service",
            object: "vfs.namespace",
            operation: "link",
        },
        PlanKind::Sleep => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "linux_syscall",
            object: "timer.sleep",
            operation: "arm",
        },
        PlanKind::Pause => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "linux_syscall",
            object: "signal.wait",
            operation: "pause",
        },
        PlanKind::FutexWait | PlanKind::FutexWaitBitset | PlanKind::FutexWaitRequeuePi => {
            HostcallBinding {
                class: HostcallClass::AsyncOp,
                subject: "futex_service",
                object: "futex.waitset",
                operation: "wait",
            }
        }
        PlanKind::FutexWake | PlanKind::FutexWakeBitset => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "futex_service",
            object: "futex.waitset",
            operation: "wake",
        },
        PlanKind::FutexRequeue | PlanKind::FutexCmpRequeue => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "futex_service",
            object: "futex.waitset",
            operation: "requeue",
        },
        PlanKind::FutexLockPi => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "futex_service",
            object: "futex.waitset",
            operation: "lock-pi",
        },
        PlanKind::FutexUnlockPi => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "futex_service",
            object: "futex.waitset",
            operation: "unlock-pi",
        },
        PlanKind::EpollCreate1 => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "epoll_service",
            object: "epoll.instance",
            operation: "create",
        },
        PlanKind::EpollCtl => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "epoll_service",
            object: "epoll.instance",
            operation: "ctl",
        },
        PlanKind::EpollWait | PlanKind::EpollReady => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "epoll_service",
            object: "epoll.instance",
            operation: "wait",
        },
        PlanKind::Socket => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "socket",
        },
        PlanKind::SocketPair => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "fd.socketpair",
            operation: "create",
        },
        PlanKind::Bind => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "bind",
        },
        PlanKind::Listen => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "listen",
        },
        PlanKind::Accept => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "accept",
        },
        PlanKind::Connect => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "connect",
        },
        PlanKind::SendTo => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "send",
        },
        PlanKind::RecvFrom => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "recv",
        },
        PlanKind::SetSockOpt => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "setsockopt",
        },
        PlanKind::GetSockOpt => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "getsockopt",
        },
        PlanKind::Fcntl => HostcallBinding {
            class: HostcallClass::PureQuery,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "fcntl",
        },
        PlanKind::FcntlSetlk => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "linux_syscall",
            object: "vfs.file-lock",
            operation: "fcntl-setlk",
        },
        PlanKind::FcntlGetlk => HostcallBinding {
            class: HostcallClass::PureQuery,
            subject: "linux_syscall",
            object: "vfs.file-lock",
            operation: "fcntl-getlk",
        },
        PlanKind::Pipe => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "fd.pipe",
            operation: "create",
        },
        PlanKind::Mmap | PlanKind::Munmap => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "process.memory",
            operation: "map",
        },
        PlanKind::Poll => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "linux_syscall",
            object: "linux.socket",
            operation: "poll",
        },
        PlanKind::ClockGettime | PlanKind::ClockGetres => HostcallBinding {
            class: HostcallClass::PureQuery,
            subject: "linux_syscall",
            object: "time.clock",
            operation: "query",
        },
        PlanKind::ClockAdjtime => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "time.clock",
            operation: "adjust",
        },
        PlanKind::TimerfdCreate => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "time.timerfd",
            operation: "create",
        },
        PlanKind::TimerfdSettime => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "time.timerfd",
            operation: "settime",
        },
        PlanKind::TimerfdGettime => HostcallBinding {
            class: HostcallClass::PureQuery,
            subject: "linux_syscall",
            object: "time.timerfd",
            operation: "gettime",
        },
        PlanKind::Eventfd => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "event.eventfd",
            operation: "create",
        },
        PlanKind::SetRobustList => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "thread.cleanup",
            operation: "set-robust-list",
        },
        PlanKind::GetRobustList => HostcallBinding {
            class: HostcallClass::PureQuery,
            subject: "linux_syscall",
            object: "thread.cleanup",
            operation: "get-robust-list",
        },
        PlanKind::Seccomp | PlanKind::Prctl => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "process.seccomp",
            operation: "configure",
        },
        // Future phases — unbound operations default to unsupported pure-query
        _ => HostcallBinding {
            class: HostcallClass::PureQuery,
            subject: "linux_syscall",
            object: "unsupported",
            operation: "unsupported",
        },
    }
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn record_hostcall_plan(&mut self, label: &str, kind: PlanKind) {
        self.authority.record_hostcall_plan(&mut self.semantic, label, kind);
    }

    pub(crate) fn require_capability(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> Result<(), CapabilityDenyReason> {
        self.authority.require(&mut self.semantic, subject, object, operation)
    }

    pub(crate) fn require_capability_generation(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
        expected_generation: u64,
    ) -> Result<(), CapabilityDenyReason> {
        self.authority.require_generation(
            &mut self.semantic,
            subject,
            object,
            operation,
            expected_generation,
        )
    }

    pub(crate) fn capability_generation(&self, subject: &str, object: &str) -> Option<u64> {
        self.authority.generation(&self.semantic, subject, object)
    }

    pub(crate) fn revoke_capability(
        &mut self,
        subject: &str,
        object: &str,
    ) -> Result<(), &'static str> {
        self.authority.revoke(&mut self.semantic, subject, object)
    }

    pub(crate) fn capability_owner_line(&self, subject: &str) -> alloc::string::String {
        let summary = self.authority.owner_summary(&self.semantic, subject);
        alloc::format!(
            "capability owner {} active={} revoked={} generation_high={}",
            summary.subject,
            summary.active,
            summary.revoked,
            summary.generation_high_watermark
        )
    }

    pub(crate) fn substrate_authority_line(&self) -> alloc::string::String {
        self.authority.substrate_authority_line(&self.semantic)
    }

    pub(crate) fn grant_capability(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) {
        self.authority.grant(&mut self.semantic, subject, object, operations, lifetime);
    }
}
