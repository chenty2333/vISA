use alloc::vec::Vec;

use vmos_abi::{
    ERR_EBADF, ERR_EINVAL, ERR_ENOENT, ERR_ENOTDIR, ERR_EPERM, FD_STDOUT, NodeKind, PlanKind,
    ServiceRoute,
};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{FdEntry, FdResource, ServiceCallError},
};

const O_DIRECTORY: u64 = 0o200000;
const O_STATUS_MASK: u64 = 0o3 | 0o2000 | 0o4000;
const MAY_EXEC: u32 = 0x1;
const MAY_WRITE: u32 = 0x2;
const MAY_READ: u32 = 0x4;
const AT_FDCWD: i64 = -100;
const GENERIC_CWD: &[u8] = b"/sandbox";

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
        if self.is_pipe_fd(fd) {
            return match self.write_pipe_fd_bytes(fd, &bytes) {
                Ok(count) => Ok(LinuxCallResult::Ret(count as i64)),
                Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
        }
        if self.is_socketpair_fd(fd) {
            return match self.write_socketpair_fd_bytes(fd, &bytes) {
                Ok(count) => Ok(LinuxCallResult::Ret(count as i64)),
                Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
        }
        if self.is_eventfd_fd(fd) {
            let value = match bytes.get(..8).and_then(|bytes| bytes.try_into().ok()) {
                Some(bytes) => u64::from_le_bytes(bytes),
                None => return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64))),
            };
            return match self.write_eventfd_value(fd, value, bytes.len()) {
                Ok(count) => Ok(LinuxCallResult::Ret(count as i64)),
                Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
        }

        let entry = self.fd_entry(fd).ok_or("write targeted an unknown file descriptor")?;
        match &entry.resource {
            FdResource::TimerFd { .. } => Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64))),
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
        let access_mask = linux_open_access_mask(plan.args[3]);
        let access_state = self.current_access_state();
        let access = access_state.ids();

        match self.lookup_path(&path) {
            Ok(info) => {
                if plan.args[3] & O_DIRECTORY != 0 && info.node != NodeKind::Directory {
                    return Ok(LinuxCallResult::Ret(-(ERR_ENOTDIR as i64)));
                }
                if info.node == NodeKind::Directory && access_mask & MAY_WRITE != 0 {
                    return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EISDIR as i64)));
                }
                if let Err(errno) = self.check_path_access(&path, access_mask, access) {
                    return Ok(LinuxCallResult::Ret(-(errno as i64)));
                }
                if !self.can_allocate_fds(1) {
                    return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EMFILE as i64)));
                }
                let vfs_node_id = if info.route == ServiceRoute::Vfs {
                    self.vfs.node_id_for_path(&path)
                } else {
                    None
                };
                let fd = match self.alloc_fd(FdEntry {
                    resource: FdResource::ServiceNode {
                        route: info.route,
                        node: info.node,
                        path,
                        vfs_node_id,
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
            Err(ServiceCallError::Errno(ERR_ENOENT)) if plan.args[3] & 0o100 != 0 => {
                let mode = u32::try_from(plan.args[4]).map_err(|_| "openat mode overflowed")?;
                if let Err(errno) = self.check_parent_access(&path, MAY_WRITE | MAY_EXEC, access) {
                    return Ok(LinuxCallResult::Ret(-(errno as i64)));
                }
                if !self.can_allocate_fds(1) {
                    return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EMFILE as i64)));
                }
                match self.vfs.create_file(&path, mode, access.uid, access.gid) {
                    Ok(()) => {
                        let vfs_node_id = self.vfs.node_id_for_path(&path);
                        let fd = match self.alloc_fd(FdEntry {
                            resource: FdResource::ServiceNode {
                                route: ServiceRoute::Vfs,
                                node: NodeKind::File,
                                path,
                                vfs_node_id,
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
            return self.plan_recvfrom(
                LinuxPlan { kind: PlanKind::RecvFrom, args: [fd as u64, 0, count as u64, 0, 0, 0] },
                "generic_read_socket",
            );
        }
        if self
            .fd_entry(fd)
            .is_some_and(|entry| matches!(entry.resource, FdResource::TimerFd { .. }))
        {
            return match self.read_timerfd_value(fd, count as usize) {
                Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
                Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
        }
        if self.is_pipe_fd(fd) {
            return match self.read_pipe_fd_bytes(fd, count as usize) {
                Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
                Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
        }
        if self.is_socketpair_fd(fd) {
            return match self.read_socketpair_fd_bytes(fd, count as usize) {
                Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
                Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
        }
        if self.is_eventfd_fd(fd) {
            return match self.read_eventfd_value(fd, count as usize) {
                Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
                Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
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
        let access_state = self.current_access_state();
        let access = access_state.ids();

        match self.read_link_path_checked(&path, access) {
            Ok(bytes) => Ok(LinuxCallResult::Bytes(bytes)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("readlinkat: {}", reason);
                Err("a service trapped during readlink")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    pub(super) fn plan_fsetxattr(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "fsetxattr fd overflowed")?;
        let name_ptr = u32::try_from(plan.args[1]).map_err(|_| "fsetxattr name ptr overflowed")?;
        let name_len = u32::try_from(plan.args[2]).map_err(|_| "fsetxattr name len overflowed")?;
        let value_ptr =
            u32::try_from(plan.args[3]).map_err(|_| "fsetxattr value ptr overflowed")?;
        let value_len =
            u32::try_from(plan.args[4]).map_err(|_| "fsetxattr value len overflowed")?;
        let flags = u32::try_from(plan.args[5]).map_err(|_| "fsetxattr flags overflowed")?;
        let name = self.linux.read_bytes(name_ptr, name_len)?;
        let value = if value_len == 0 {
            Vec::new()
        } else {
            self.linux.read_bytes(value_ptr, value_len)?
        };
        let access_state = self.current_access_state();
        let access = access_state.ids();
        match self.fsetxattr_fd(fd, &name, &value, flags, access) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_fgetxattr(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "fgetxattr fd overflowed")?;
        let name_ptr = u32::try_from(plan.args[1]).map_err(|_| "fgetxattr name ptr overflowed")?;
        let name_len = u32::try_from(plan.args[2]).map_err(|_| "fgetxattr name len overflowed")?;
        let value_ptr =
            u32::try_from(plan.args[3]).map_err(|_| "fgetxattr value ptr overflowed")?;
        let size = usize::try_from(plan.args[4]).map_err(|_| "fgetxattr size overflowed")?;
        let name = self.linux.read_bytes(name_ptr, name_len)?;
        let access_state = self.current_access_state();
        let access = access_state.ids();
        match self.fgetxattr_fd(fd, &name, size, access) {
            Ok(value) => {
                if size != 0 {
                    if value_ptr == 0 {
                        return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64)));
                    }
                    self.linux.write_bytes(value_ptr, &value)?;
                }
                Ok(LinuxCallResult::Ret(value.len() as i64))
            }
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_flistxattr(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "flistxattr fd overflowed")?;
        let list_ptr = u32::try_from(plan.args[1]).map_err(|_| "flistxattr list ptr overflowed")?;
        let size = usize::try_from(plan.args[2]).map_err(|_| "flistxattr size overflowed")?;
        let access_state = self.current_access_state();
        let access = access_state.ids();
        match self.flistxattr_fd(fd, size, access) {
            Ok(names) => {
                if size != 0 {
                    if list_ptr == 0 {
                        return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64)));
                    }
                    self.linux.write_bytes(list_ptr, &names)?;
                }
                Ok(LinuxCallResult::Ret(names.len() as i64))
            }
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_fremovexattr(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "fremovexattr fd overflowed")?;
        let name_ptr =
            u32::try_from(plan.args[1]).map_err(|_| "fremovexattr name ptr overflowed")?;
        let name_len =
            u32::try_from(plan.args[2]).map_err(|_| "fremovexattr name len overflowed")?;
        let name = self.linux.read_bytes(name_ptr, name_len)?;
        let access_state = self.current_access_state();
        let access = access_state.ids();
        match self.fremovexattr_fd(fd, &name, access) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_renameat2(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let old_dirfd = plan.args[0] as i64;
        let old_ptr = u32::try_from(plan.args[1]).map_err(|_| "rename old ptr overflowed")?;
        let old_len = u32::try_from(plan.args[2]).map_err(|_| "rename old len overflowed")?;
        let new_dirfd = plan.args[3] as i64;
        let new_ptr = u32::try_from(plan.args[4]).map_err(|_| "rename new ptr overflowed")?;
        let new_len =
            u32::try_from(plan.args[5] & 0xffff_ffff).map_err(|_| "rename new len overflowed")?;
        let flags = u32::try_from(plan.args[5] >> 32).map_err(|_| "rename flags overflowed")?;
        let old_path = self.linux.read_bytes(old_ptr, old_len)?;
        let new_path = self.linux.read_bytes(new_ptr, new_len)?;
        let old_path = match self.resolve_plan_path(old_dirfd, &old_path) {
            Ok(path) => path,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let new_path = match self.resolve_plan_path(new_dirfd, &new_path) {
            Ok(path) => path,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let access_state = self.current_access_state();
        let access = access_state.ids();

        match self.rename_path(&old_path, &new_path, flags, access) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_linkat(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let old_dirfd = plan.args[0] as i64;
        let old_ptr = u32::try_from(plan.args[1]).map_err(|_| "link old ptr overflowed")?;
        let old_len = u32::try_from(plan.args[2]).map_err(|_| "link old len overflowed")?;
        let new_dirfd = plan.args[3] as i64;
        let new_ptr = u32::try_from(plan.args[4]).map_err(|_| "link new ptr overflowed")?;
        let new_len =
            u32::try_from(plan.args[5] & 0xffff_ffff).map_err(|_| "link new len overflowed")?;
        let flags = u32::try_from(plan.args[5] >> 32).map_err(|_| "link flags overflowed")?;
        if flags != 0 {
            return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64)));
        }

        let old_path = self.linux.read_bytes(old_ptr, old_len)?;
        let new_path = self.linux.read_bytes(new_ptr, new_len)?;
        let old_path = match self.resolve_plan_path(old_dirfd, &old_path) {
            Ok(path) => path,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let new_path = match self.resolve_plan_path(new_dirfd, &new_path) {
            Ok(path) => path,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let access_state = self.current_access_state();
        let access = access_state.ids();

        match self.link_path(&old_path, &new_path, access) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    fn resolve_plan_path(&mut self, dirfd: i64, path: &[u8]) -> Result<Vec<u8>, i32> {
        if path.is_empty() {
            return Err(ERR_ENOENT);
        }
        if path.starts_with(b"/") {
            return Ok(normalize_plan_path(path));
        }

        let base = if dirfd == AT_FDCWD {
            GENERIC_CWD.to_vec()
        } else if dirfd >= 0 {
            let base = self.fd_path(dirfd as u32).map_err(|_| ERR_EBADF)?;
            if self.path_kind(&base)? != NodeKind::Directory {
                return Err(ERR_ENOTDIR);
            }
            base
        } else {
            return Err(ERR_EBADF);
        };

        let mut resolved = base;
        if !resolved.ends_with(b"/") {
            resolved.push(b'/');
        }
        resolved.extend_from_slice(path);
        Ok(normalize_plan_path(&resolved))
    }
}

fn linux_status_flags_from_open_flags(flags: u64) -> u32 {
    (flags & O_STATUS_MASK) as u32
}

fn linux_open_access_mask(flags: u64) -> u32 {
    match flags & 0o3 {
        0 => MAY_READ,
        1 => MAY_WRITE,
        2 => MAY_READ | MAY_WRITE,
        _ => 0,
    }
}

fn normalize_plan_path(path: &[u8]) -> Vec<u8> {
    let mut components: Vec<&[u8]> = Vec::new();
    for component in path.split(|byte| *byte == b'/') {
        match component {
            b"" | b"." => {}
            b".." => {
                let _ = components.pop();
            }
            _ => components.push(component),
        }
    }
    let mut out = Vec::new();
    out.push(b'/');
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(component);
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec, vec::Vec};

    use service_core::packet::{PACKET_FRAME_CAPACITY, PacketFrameMeta, encode_frame};
    use vmos_abi::{
        AF_INET, ERR_EACCES, ERR_EFBIG, SOCK_STREAM, SYS_LINKAT, SYS_OPENAT, SYS_READ,
        SYS_READLINKAT, SYS_READV, SYS_RENAMEAT2, SYS_WRITE, SYS_WRITEV, SyscallContext,
    };

    use super::{
        super::{
            engine::RuntimeOnlyExecutor,
            runtime::PrototypeRuntime,
            types::{
                CAP_DAC_OVERRIDE, FdEntry, FdResource, ProcessAccessState, RLIMIT_FSIZE, Rlimit,
            },
        },
        *,
    };

    fn test_runtime() -> PrototypeRuntime<'static> {
        let engine = Box::leak(Box::new(RuntimeOnlyExecutor::default()));
        PrototypeRuntime::new(engine).expect("test runtime")
    }

    fn expect_ret(result: LinuxCallResult) -> i64 {
        match result {
            LinuxCallResult::Ret(ret) => ret,
            other => panic!("expected integer return, got {other:?}"),
        }
    }

    fn expect_bytes(result: LinuxCallResult) -> Vec<u8> {
        match result {
            LinuxCallResult::Bytes(bytes) => bytes,
            other => panic!("expected bytes return, got {other:?}"),
        }
    }

    fn set_current_access(runtime: &mut PrototypeRuntime<'_>, access: ProcessAccessState) {
        let pid = runtime.current_pid();
        runtime.processes.iter_mut().find(|process| process.pid == pid).unwrap().access = access;
    }

    fn write_fd(runtime: &mut PrototypeRuntime<'_>, fd: u32, bytes: &[u8]) -> i64 {
        let (ptr, len) = runtime.write_linux_arg_bytes(bytes).expect("arg bytes");
        let result = runtime
            .dispatch_linux_syscall(
                "test_write",
                SyscallContext::new(SYS_WRITE, [fd as u64, ptr as u64, len as u64, 0, 0, 0]),
            )
            .expect("write dispatch");
        expect_ret(result)
    }

    fn writev_fd(runtime: &mut PrototypeRuntime<'_>, fd: u32, chunks: &[&[u8]]) -> i64 {
        let (base, _) = runtime.write_linux_arg_bytes(&[]).expect("arg base");
        let iovec_len = chunks.len() * 16;
        let data_base = base + u32::try_from(iovec_len).expect("iovecs fit");
        let mut raw = Vec::new();
        let mut cursor = data_base;
        for chunk in chunks {
            push_iovec(&mut raw, cursor, chunk.len() as u64);
            cursor = cursor.checked_add(chunk.len() as u32).expect("chunk offset");
        }
        for chunk in chunks {
            raw.extend_from_slice(chunk);
        }
        let (iov_ptr, _) = runtime.write_linux_arg_bytes(&raw).expect("writev iovecs");
        let result = runtime
            .dispatch_linux_syscall(
                "test_writev",
                SyscallContext::new(
                    SYS_WRITEV,
                    [fd as u64, iov_ptr as u64, chunks.len() as u64, 0, 0, 0],
                ),
            )
            .expect("writev dispatch");
        expect_ret(result)
    }

    fn pending_signal_count(runtime: &PrototypeRuntime<'_>, signo: u8) -> usize {
        runtime
            .query_thread(runtime.current_tid())
            .expect("current thread")
            .pending_signals
            .iter()
            .filter(|signal| signal.signo == signo)
            .count()
    }

    fn read_fd(runtime: &mut PrototypeRuntime<'_>, fd: u32, count: u64) -> Vec<u8> {
        let result = runtime
            .dispatch_linux_syscall(
                "test_read",
                SyscallContext::new(SYS_READ, [fd as u64, 0, count, 0, 0, 0]),
            )
            .expect("read dispatch");
        expect_bytes(result)
    }

    fn open_created_file(runtime: &mut PrototypeRuntime<'_>, path: &[u8]) -> u32 {
        let (ptr, len) = runtime.write_linux_arg_bytes(path).expect("open path");
        let result = runtime
            .dispatch_linux_syscall(
                "test_openat_create",
                SyscallContext::new(SYS_OPENAT, [0, ptr as u64, len as u64, 0o102, 0o600, 0]),
            )
            .expect("openat dispatch");
        u32::try_from(expect_ret(result)).expect("created fd")
    }

    fn push_iovec(raw: &mut Vec<u8>, base: u32, len: u64) {
        raw.extend_from_slice(&(base as u64).to_le_bytes());
        raw.extend_from_slice(&len.to_le_bytes());
    }

    fn create_legacy_socket_fd(runtime: &mut PrototypeRuntime<'_>) -> (u32, u32) {
        let socket_id =
            runtime.net_core.create_socket(AF_INET, SOCK_STREAM, 0).expect("legacy socket");
        let ready_key = runtime.net_core.ready_key(socket_id).expect("legacy socket ready key");
        runtime
            .linux_socket
            .register_socket(socket_id, AF_INET, SOCK_STREAM, 0, ready_key)
            .expect("legacy linux socket registration");
        let fd = runtime
            .alloc_fd(FdEntry {
                resource: FdResource::Socket { socket_id: socket_id as u64, ready_key },
                cursor: 0,
                fd_flags: 0,
                status_flags: 0,
                cursor_group: None,
            })
            .expect("legacy socket fd");
        (fd, socket_id)
    }

    #[test]
    fn generic_openat_uses_runtime_fs_credentials_for_dac() {
        let mut runtime = test_runtime();
        runtime.vfs.mkdir(b"/tmp/fsuid-open", 0o700, 2000, 100).expect("private dir");
        set_current_access(
            &mut runtime,
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                2000,
                100,
                100,
                100,
                100,
                Vec::new(),
                0,
                0,
            ),
        );

        let (ptr, len) =
            runtime.write_linux_arg_bytes(b"/tmp/fsuid-open/created").expect("open path");
        let create = runtime
            .dispatch_linux_syscall(
                "test_openat_fsuid_create",
                SyscallContext::new(SYS_OPENAT, [0, ptr as u64, len as u64, 0o102, 0o600, 0]),
            )
            .expect("openat fsuid dispatch");
        assert!(expect_ret(create) >= 3);
        assert_eq!(runtime.vfs.owner_for_path(b"/tmp/fsuid-open/created"), (2000, 100));
    }

    #[test]
    fn generic_openat_honors_supplementary_groups_and_caps() {
        let mut runtime = test_runtime();
        runtime.vfs.create_file(b"/tmp/supp-readable", 0o640, 2000, 555).expect("group file");
        set_current_access(
            &mut runtime,
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                1000,
                100,
                100,
                100,
                100,
                vec![555],
                0,
                0,
            ),
        );
        let (ptr, len) = runtime.write_linux_arg_bytes(b"/tmp/supp-readable").expect("supp path");
        let read = runtime
            .dispatch_linux_syscall(
                "test_openat_supp_group",
                SyscallContext::new(SYS_OPENAT, [0, ptr as u64, len as u64, 0, 0, 0]),
            )
            .expect("supplementary group openat dispatch");
        assert!(expect_ret(read) >= 3);

        runtime.vfs.create_file(b"/tmp/cap-readable", 0o000, 2000, 555).expect("cap file");
        set_current_access(
            &mut runtime,
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                1000,
                100,
                100,
                100,
                100,
                Vec::new(),
                CAP_DAC_OVERRIDE,
                CAP_DAC_OVERRIDE,
            ),
        );
        let (ptr, len) = runtime.write_linux_arg_bytes(b"/tmp/cap-readable").expect("cap path");
        let read = runtime
            .dispatch_linux_syscall(
                "test_openat_cap_override",
                SyscallContext::new(SYS_OPENAT, [0, ptr as u64, len as u64, 0, 0, 0]),
            )
            .expect("cap override openat dispatch");
        assert!(expect_ret(read) >= 3);
    }

    #[test]
    fn generic_rename_and_link_use_runtime_fs_credentials() {
        let mut runtime = test_runtime();
        runtime.vfs.mkdir(b"/tmp/fsuid-links", 0o700, 3000, 300).expect("private dir");
        runtime.vfs.create_file(b"/tmp/fsuid-links/source", 0o600, 3000, 300).expect("source");
        set_current_access(
            &mut runtime,
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                3000,
                100,
                100,
                100,
                300,
                Vec::new(),
                0,
                0,
            ),
        );

        let old_path = b"/tmp/fsuid-links/source";
        let new_path = b"/tmp/fsuid-links/renamed";
        let mut rename_paths = Vec::new();
        rename_paths.extend_from_slice(old_path);
        rename_paths.extend_from_slice(new_path);
        let (paths_ptr, _) = runtime.write_linux_arg_bytes(&rename_paths).expect("rename paths");
        let old_ptr = paths_ptr;
        let new_ptr = paths_ptr + old_path.len() as u32;
        let rename = runtime
            .dispatch_linux_syscall(
                "test_renameat2_fsuid",
                SyscallContext::new(
                    SYS_RENAMEAT2,
                    [
                        AT_FDCWD as u64,
                        old_ptr as u64,
                        old_path.len() as u64,
                        AT_FDCWD as u64,
                        new_ptr as u64,
                        new_path.len() as u64,
                    ],
                ),
            )
            .expect("renameat2 fsuid dispatch");
        assert_eq!(expect_ret(rename), 0);

        let old_path = b"/tmp/fsuid-links/renamed";
        let new_path = b"/tmp/fsuid-links/hardlink";
        let mut link_paths = Vec::new();
        link_paths.extend_from_slice(old_path);
        link_paths.extend_from_slice(new_path);
        let (paths_ptr, _) = runtime.write_linux_arg_bytes(&link_paths).expect("link paths");
        let old_ptr = paths_ptr;
        let new_ptr = paths_ptr + old_path.len() as u32;
        let link = runtime
            .dispatch_linux_syscall(
                "test_linkat_fsuid",
                SyscallContext::new(
                    SYS_LINKAT,
                    [
                        AT_FDCWD as u64,
                        old_ptr as u64,
                        old_path.len() as u64,
                        AT_FDCWD as u64,
                        new_ptr as u64,
                        new_path.len() as u64,
                    ],
                ),
            )
            .expect("linkat fsuid dispatch");
        assert_eq!(expect_ret(link), 0);
        assert!(runtime.lookup_path(b"/tmp/fsuid-links/hardlink").is_ok());
    }

    #[test]
    fn generic_readlinkat_requires_runtime_traversal_access() {
        let mut runtime = test_runtime();
        runtime.vfs.mkdir(b"/tmp/private-links", 0o700, 4000, 400).expect("private dir");
        runtime.vfs.symlink(b"/tmp/private-links/readme", b"/sandbox/hello.txt").expect("symlink");
        set_current_access(
            &mut runtime,
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                1000,
                100,
                100,
                100,
                100,
                Vec::new(),
                0,
                0,
            ),
        );

        let (ptr, len) =
            runtime.write_linux_arg_bytes(b"/tmp/private-links/readme").expect("readlink path");
        let denied = runtime
            .dispatch_linux_syscall(
                "test_readlinkat_denied",
                SyscallContext::new(SYS_READLINKAT, [0, ptr as u64, len as u64, 0, 0, 0]),
            )
            .expect("readlinkat denied dispatch");
        assert_eq!(expect_ret(denied), -(ERR_EACCES as i64));

        set_current_access(
            &mut runtime,
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                4000,
                100,
                100,
                100,
                400,
                Vec::new(),
                0,
                0,
            ),
        );
        let allowed = runtime
            .dispatch_linux_syscall(
                "test_readlinkat_allowed",
                SyscallContext::new(SYS_READLINKAT, [0, ptr as u64, len as u64, 0, 0, 0]),
            )
            .expect("readlinkat allowed dispatch");
        assert_eq!(expect_bytes(allowed), b"/sandbox/hello.txt");
    }

    #[test]
    fn checked_path_stat_requires_runtime_traversal_access() {
        let mut runtime = test_runtime();
        runtime.vfs.mkdir(b"/tmp/private-stat", 0o700, 5000, 500).expect("private dir");
        runtime.vfs.symlink(b"/tmp/private-stat/readme", b"/sandbox/hello.txt").expect("symlink");
        set_current_access(
            &mut runtime,
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                1000,
                100,
                100,
                100,
                100,
                Vec::new(),
                0,
                0,
            ),
        );
        let access = runtime.current_access_state();
        assert_eq!(
            runtime.stat_path_abi_checked(b"/tmp/private-stat/readme", access.ids()),
            Err(ERR_EACCES)
        );
        assert_eq!(
            runtime.path_metadata_checked(b"/tmp/private-stat/readme", access.ids()),
            Err(ERR_EACCES)
        );

        set_current_access(
            &mut runtime,
            ProcessAccessState::from_credentials(
                1000,
                1000,
                1000,
                5000,
                100,
                100,
                100,
                500,
                Vec::new(),
                0,
                0,
            ),
        );
        let access = runtime.current_access_state();
        assert!(runtime.stat_path_abi_checked(b"/tmp/private-stat/readme", access.ids()).is_ok());
        assert!(runtime.path_metadata_checked(b"/tmp/private-stat/readme", access.ids()).is_ok());
    }

    #[test]
    fn generic_read_write_support_pipe_socketpair_and_eventfd() {
        let mut runtime = test_runtime();

        let (pipe_read, pipe_write) = runtime.create_pipe_pair().expect("pipe pair");
        assert_eq!(write_fd(&mut runtime, pipe_write, b"pipe"), 4);
        assert_eq!(read_fd(&mut runtime, pipe_read, 4), b"pipe");

        let (sock_a, sock_b) = runtime.create_socketpair().expect("socketpair");
        assert_eq!(write_fd(&mut runtime, sock_a, b"pair"), 4);
        assert_eq!(read_fd(&mut runtime, sock_b, 4), b"pair");

        let eventfd = runtime.create_eventfd(0, 0).expect("eventfd");
        assert_eq!(write_fd(&mut runtime, eventfd, &7u64.to_le_bytes()), 8);
        assert_eq!(read_fd(&mut runtime, eventfd, 8), 7u64.to_le_bytes());
    }

    #[test]
    fn rlimit_fsize_caps_regular_file_growth() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        assert!(runtime.set_rlimit(pid, RLIMIT_FSIZE, Rlimit { cur: 5, max: 5 }));
        let fd = open_created_file(&mut runtime, b"/tmp/rlimit-fsize");

        assert_eq!(write_fd(&mut runtime, fd, b"abcdef"), 5);
        runtime.seek_fd(fd, 0, 0).expect("rewind file");
        assert_eq!(read_fd(&mut runtime, fd, 8), b"abcde");

        assert_eq!(write_fd(&mut runtime, fd, b"z"), -(ERR_EFBIG as i64));
        let current_tid = runtime.current_tid();
        assert!(
            runtime
                .query_thread(current_tid)
                .expect("current thread")
                .pending_signals
                .iter()
                .any(|signal| signal.signo == 25)
        );
        assert_eq!(runtime.truncate_fd(fd, 6), Err(ERR_EFBIG));
    }

    #[test]
    fn rlimit_fsize_writev_partial_success_does_not_queue_sigxfsz() {
        const SIGXFSZ: u8 = 25;

        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        assert!(runtime.set_rlimit(pid, RLIMIT_FSIZE, Rlimit { cur: 5, max: 5 }));
        let fd = open_created_file(&mut runtime, b"/tmp/rlimit-fsize-writev");

        assert_eq!(writev_fd(&mut runtime, fd, &[b"abcde", b"f"]), 5);
        assert_eq!(pending_signal_count(&runtime, SIGXFSZ), 0);

        runtime.seek_fd(fd, 0, 0).expect("rewind file");
        assert_eq!(read_fd(&mut runtime, fd, 8), b"abcde");

        assert_eq!(write_fd(&mut runtime, fd, b"z"), -(ERR_EFBIG as i64));
        assert_eq!(pending_signal_count(&runtime, SIGXFSZ), 1);
    }

    #[test]
    fn generic_eventfd_readv_writev_support_split_iovecs() {
        let mut runtime = test_runtime();
        let eventfd = runtime.create_eventfd(0, 0).expect("eventfd");

        let (base, _) = runtime.write_linux_arg_bytes(&[]).expect("arg base");
        let data_base = base + 32;
        let mut writev_raw = Vec::new();
        push_iovec(&mut writev_raw, data_base, 4);
        push_iovec(&mut writev_raw, data_base + 4, 4);
        writev_raw.extend_from_slice(&11u64.to_le_bytes());
        let (iov_ptr, _) = runtime.write_linux_arg_bytes(&writev_raw).expect("writev iovecs");
        let writev_result = runtime
            .dispatch_linux_syscall(
                "test_eventfd_writev",
                SyscallContext::new(SYS_WRITEV, [eventfd as u64, iov_ptr as u64, 2, 0, 0, 0]),
            )
            .expect("writev dispatch");
        assert_eq!(expect_ret(writev_result), 8);

        let (base, _) = runtime.write_linux_arg_bytes(&[]).expect("arg base");
        let data_base = base + 32;
        let mut readv_raw = Vec::new();
        push_iovec(&mut readv_raw, data_base, 4);
        push_iovec(&mut readv_raw, data_base + 4, 4);
        readv_raw.extend_from_slice(&[0; 8]);
        let (iov_ptr, _) = runtime.write_linux_arg_bytes(&readv_raw).expect("readv iovecs");
        let readv_result = runtime
            .dispatch_linux_syscall(
                "test_eventfd_readv",
                SyscallContext::new(SYS_READV, [eventfd as u64, iov_ptr as u64, 2, 0, 0, 0]),
            )
            .expect("readv dispatch");
        assert_eq!(expect_ret(readv_result), 8);
        assert_eq!(
            runtime.linux.read_bytes(data_base, 8).expect("readv output"),
            11u64.to_le_bytes()
        );
    }

    #[test]
    fn generic_socket_readv_writev_use_socket_transfer_path() {
        let mut runtime = test_runtime();
        let (fd, socket_id) = create_legacy_socket_fd(&mut runtime);

        let (base, _) = runtime.write_linux_arg_bytes(&[]).expect("arg base");
        let data_base = base + 32;
        let mut writev_raw = Vec::new();
        push_iovec(&mut writev_raw, data_base, 5);
        push_iovec(&mut writev_raw, data_base + 5, 5);
        writev_raw.extend_from_slice(b"helloworld");
        let (iov_ptr, _) = runtime.write_linux_arg_bytes(&writev_raw).expect("socket writev");
        let writev_result = runtime
            .dispatch_linux_syscall(
                "test_socket_writev",
                SyscallContext::new(SYS_WRITEV, [fd as u64, iov_ptr as u64, 2, 0, 0, 0]),
            )
            .expect("socket writev dispatch");
        assert_eq!(expect_ret(writev_result), 10);

        let payload = b"abcde";
        let meta = PacketFrameMeta::demo_http_response(1, payload.len());
        let mut frame = [0u8; PACKET_FRAME_CAPACITY];
        let frame_len = encode_frame(meta, payload, &mut frame).expect("encode rx frame");
        runtime.net_core.deliver_packet_frame(&frame[..frame_len]).expect("deliver socket rx");

        let (base, _) = runtime.write_linux_arg_bytes(&[]).expect("arg base");
        let data_base = base + 32;
        let mut readv_raw = Vec::new();
        push_iovec(&mut readv_raw, data_base, 2);
        push_iovec(&mut readv_raw, data_base + 2, 3);
        readv_raw.extend_from_slice(&[0; 5]);
        let (iov_ptr, _) = runtime.write_linux_arg_bytes(&readv_raw).expect("socket readv");
        let readv_result = runtime
            .dispatch_linux_syscall(
                "test_socket_readv",
                SyscallContext::new(SYS_READV, [fd as u64, iov_ptr as u64, 2, 0, 0, 0]),
            )
            .expect("socket readv dispatch");
        assert_eq!(expect_ret(readv_result), 5);
        assert_eq!(runtime.linux.read_bytes(data_base, 5).expect("readv output"), payload);

        let _ = runtime.close_fd_number(fd);
        let _ = runtime.net_core.close_socket(socket_id);
    }
}
