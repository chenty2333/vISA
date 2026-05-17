use alloc::vec::Vec;

use vmos_abi::{
    ERR_EBADF, ERR_EINVAL, ERR_ENOENT, ERR_ENOTDIR, ERR_EPERM, FD_STDOUT, NodeKind, PlanKind,
    ServiceRoute,
};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{AccessIds, FdEntry, FdResource, ServiceCallError},
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
        let uid = (plan.args[5] >> 32) as u32;
        let gid = plan.args[5] as u32;
        let access = AccessIds::new(uid, gid, &[]);

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
                match self.vfs.create_file(&path, mode, uid, gid) {
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
            return self.plan_recvfrom(LinuxPlan {
                kind: PlanKind::RecvFrom,
                args: [fd as u64, 0, count as u64, 0, 0, 0],
            });
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
        let access = AccessIds::new(0, 0, &[]);

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
        let access = AccessIds::new(0, 0, &[]);

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
