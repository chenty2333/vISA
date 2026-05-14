use vmos_abi::{
    ERR_EBADF, ERR_ENOENT, ERR_ENOTDIR, ERR_EPERM, FD_STDOUT, NodeKind, PlanKind, ServiceRoute,
};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{FdEntry, FdResource, ServiceCallError},
};

const O_DIRECTORY: u64 = 0o200000;
const O_STATUS_MASK: u64 = 0o3 | 0o2000 | 0o4000;

impl<'engine> PrototypeRuntime<'engine> {
    pub(crate) fn write_console_bytes(&mut self, bytes: &[u8]) -> Result<(), i32> {
        self.record_hostcall_plan("ring3_write", PlanKind::Write);
        if self.require_capability("linux_syscall", "console.write", "write").is_err() {
            return Err(ERR_EPERM);
        }
        self.console.write_bytes(bytes, false).map_err(|_| vmos_abi::ERR_EIO)
    }

    pub(super) fn plan_write(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "write plan fd overflowed")?;
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "write plan ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "write plan len overflowed")?;
        let bytes = self.linux.read_bytes(ptr, len)?;

        if fd == FD_STDOUT || fd == vmos_abi::FD_STDERR {
            if let Err(errno) = self.write_console_bytes(&bytes) {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            return Ok(LinuxCallResult::Ret(bytes.len() as i64));
        }

        if self
            .fd_entry(fd)
            .is_some_and(|entry| matches!(entry.resource, FdResource::Socket { .. }))
        {
            return self.plan_sendto(LinuxPlan {
                kind: PlanKind::SendTo,
                args: [fd as u64, ptr as u64, len as u64, 0, 0, 0],
            });
        }

        let entry = self.fd_entry(fd).ok_or("write targeted an unknown file descriptor")?;
        match &entry.resource {
            FdResource::ServiceNode { route, path, .. } if *route == ServiceRoute::Devfs => {
                let path = path.clone();
                if self.require_capability("devfs_service", "device.pulse", "poll").is_err() {
                    return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
                }
                match self.devfs.write_device(&path, bytes.len() as u32, false) {
                    Ok(count) => Ok(LinuxCallResult::Ret(count as i64)),
                    Err(ServiceCallError::Errno(errno)) => {
                        Ok(LinuxCallResult::Ret(-(errno as i64)))
                    }
                    Err(ServiceCallError::Trap(_)) => Err("devfs_service trapped during write"),
                    Err(ServiceCallError::Invalid(err)) => Err(err),
                }
            }
            FdResource::ServiceNode { route, node: NodeKind::File, .. }
                if *route == ServiceRoute::Vfs =>
            {
                match self.write_to_fd(fd, &bytes) {
                    Ok(count) => Ok(LinuxCallResult::Ret(count as i64)),
                    Err(ServiceCallError::Errno(errno)) => {
                        Ok(LinuxCallResult::Ret(-(errno as i64)))
                    }
                    Err(ServiceCallError::Trap(_)) => Err("vfs_service trapped during write"),
                    Err(ServiceCallError::Invalid(err)) => Err(err),
                }
            }
            _ => Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64))),
        }
    }
    pub(super) fn plan_openat(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "openat ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "openat len overflowed")?;
        let path = self.linux.read_bytes(ptr, len)?;
        let status_flags = linux_status_flags_from_open_flags(plan.args[3]);

        match self.lookup_path(&path) {
            Ok(info) => {
                if plan.args[3] & O_DIRECTORY != 0 && info.node != NodeKind::Directory {
                    return Ok(LinuxCallResult::Ret(-(ERR_ENOTDIR as i64)));
                }
                if !self.can_allocate_fds(1) {
                    return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EMFILE as i64)));
                }
                let fd = match self.alloc_fd(FdEntry {
                    resource: FdResource::ServiceNode { route: info.route, node: info.node, path },
                    cursor: 0,
                    fd_flags: 0,
                    status_flags,
                    cursor_group: None,
                }) {
                    Ok(fd) => fd,
                    Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
                };
                Ok(LinuxCallResult::Ret(fd as i64))
            }
            Err(ServiceCallError::Errno(ERR_ENOENT)) if plan.args[3] & 0o100 != 0 => {
                let mode = u32::try_from(plan.args[4]).map_err(|_| "openat mode overflowed")?;
                let uid = (plan.args[5] >> 32) as u32;
                let gid = plan.args[5] as u32;
                if !self.can_allocate_fds(1) {
                    return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EMFILE as i64)));
                }
                match self.vfs.create_file(&path, mode, uid, gid) {
                    Ok(()) => {
                        let fd = match self.alloc_fd(FdEntry {
                            resource: FdResource::ServiceNode {
                                route: ServiceRoute::Vfs,
                                node: NodeKind::File,
                                path,
                            },
                            cursor: 0,
                            fd_flags: 0,
                            status_flags,
                            cursor_group: None,
                        }) {
                            Ok(fd) => fd,
                            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
                        };
                        Ok(LinuxCallResult::Ret(fd as i64))
                    }
                    Err(ServiceCallError::Errno(errno)) => {
                        Ok(LinuxCallResult::Ret(-(errno as i64)))
                    }
                    Err(ServiceCallError::Trap(reason)) => {
                        crate::kwarn!("openat create: {}", reason);
                        Err("vfs_service trapped during openat create")
                    }
                    Err(ServiceCallError::Invalid(err)) => Err(err),
                }
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("openat: {}", reason);
                Err("a service trapped during openat")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_read(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "read plan fd overflowed")?;
        let count = u32::try_from(plan.args[1]).map_err(|_| "read plan count overflowed")?;
        if self
            .fd_entry(fd)
            .is_some_and(|entry| matches!(entry.resource, FdResource::Socket { .. }))
        {
            return self.plan_recvfrom(LinuxPlan {
                kind: PlanKind::RecvFrom,
                args: [fd as u64, 0, count as u64, 0, 0, 0],
            });
        }
        match self.read_from_fd(fd, count) {
            Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("read: {}", reason);
                Err("a service trapped during read")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_close(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "close plan fd overflowed")?;
        match self.close_fd_number(fd) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }
    pub(super) fn plan_getdents(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "getdents fd overflowed")?;
        let count = u32::try_from(plan.args[1]).map_err(|_| "getdents count overflowed")?;
        match self.read_dir_entries(fd, count) {
            Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("getdents64: {}", reason);
                Err("a service trapped during getdents")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_readlinkat(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "readlink ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "readlink len overflowed")?;
        let path = self.linux.read_bytes(ptr, len)?;

        match self.read_link_path(&path) {
            Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("readlinkat: {}", reason);
                Err("a service trapped during readlink")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
}

fn linux_status_flags_from_open_flags(flags: u64) -> u32 {
    (flags & O_STATUS_MASK) as u32
}
