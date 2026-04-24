use semantic_core::{CapabilityDenyReason, Generation, HostcallClass, SemanticGraph};
use vmos_abi::PlanKind;

use super::runtime::PrototypeRuntime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HostcallBinding {
    pub(crate) class: HostcallClass,
    pub(crate) subject: &'static str,
    pub(crate) object: &'static str,
    pub(crate) operation: &'static str,
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
        semantic
            .check_capability(subject, object, operation)
            .map(|_| ())
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
            .revoke_capability_by_subject_object(subject, object)
            .map(|_| ())
            .ok_or("capability to revoke was not present")
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
        PlanKind::Close => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "linux_syscall",
            object: "fd.table",
            operation: "close",
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
        PlanKind::Sleep => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "linux_syscall",
            object: "timer.sleep",
            operation: "arm",
        },
        PlanKind::FutexWait => HostcallBinding {
            class: HostcallClass::AsyncOp,
            subject: "futex_service",
            object: "futex.waitset",
            operation: "wait",
        },
        PlanKind::FutexWake => HostcallBinding {
            class: HostcallClass::ImmediatePrivilegedOp,
            subject: "futex_service",
            object: "futex.waitset",
            operation: "wake",
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
    }
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn record_hostcall_plan(&mut self, label: &str, kind: PlanKind) {
        self.authority
            .record_hostcall_plan(&mut self.semantic, label, kind);
    }

    pub(crate) fn require_capability(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> Result<(), CapabilityDenyReason> {
        self.authority
            .require(&mut self.semantic, subject, object, operation)
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

    pub(crate) fn revoke_capability_for_demo(
        &mut self,
        subject: &str,
        object: &str,
    ) -> Result<(), &'static str> {
        self.authority.revoke(&mut self.semantic, subject, object)
    }

    pub(crate) fn grant_capability_for_demo(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) {
        self.authority
            .grant(&mut self.semantic, subject, object, operations, lifetime);
    }
}
