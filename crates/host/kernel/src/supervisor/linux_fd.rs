use alloc::{vec, vec::Vec};

use semantic_core::ResourceHandle;
use vmos_abi::{
    EPOLLIN, EPOLLOUT, EPOLLRDHUP, ERR_EACCES, ERR_EAGAIN, ERR_EBADF, ERR_EINVAL, ERR_EMFILE,
    ERR_ENOTSOCK, ERR_EPERM, NodeKind, ServiceRoute,
};

use super::{
    events::Event,
    linux::LinuxCallResult,
    net::Ipv4SocketEndpoint,
    pulse::PulseDevice,
    runtime::PrototypeRuntime,
    semantic::{fd_resource_kind, fd_resource_label},
    services::ProcfsService,
    types::{
        AccessIds, CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_SYS_ADMIN,
        EventFdState, FdEntry, FdResource, FdTableSnapshot, InjectedFault, LookupInfo, PipeState,
        RLIMIT_NOFILE, ServiceCallError, SocketPairState, TaskId,
    },
    wait::{WaitRegistration, WaitSource},
};
use crate::interrupts;

const MAX_LINUX_FD: u32 = 1024;
const EPOLL_READY_TAG: u64 = 0x6000_0000_0000_0000;
const PIPE_READY_TAG: u64 = 0x7000_0000_0000_0000;
const SOCKETPAIR_READY_TAG: u64 = 0x8000_0000_0000_0000;
const EVENTFD_READY_TAG: u64 = 0x9000_0000_0000_0000;
const READY_TAG_MASK: u64 = 0xf000_0000_0000_0000;
const DEFAULT_PIPE_CAPACITY: usize = 65_536;
const EVENTFD_MAX_COUNTER: u64 = u64::MAX - 1;
const MAY_EXEC: u32 = 0x1;
const MAY_WRITE: u32 = 0x2;
const MAY_READ: u32 = 0x4;
const O_ACCMODE: u32 = 0o3;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const POLLIN: u16 = 0x001;
const POLLOUT: u16 = 0x004;
const POLLERR: u16 = 0x008;
const POLLHUP: u16 = 0x010;
const POLLRDNORM: u16 = 0x040;
const POLLWRNORM: u16 = 0x100;
const POLLRDHUP: u16 = 0x2000;
const POLL_READ_EVENTS: u16 = POLLIN | POLLRDNORM;
const POLL_WRITE_EVENTS: u16 = POLLOUT | POLLWRNORM;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn lookup_path(&mut self, path: &[u8]) -> Result<LookupInfo, ServiceCallError> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup")
            .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
        let info = self.vfs.lookup(path, false)?;
        match info.route {
            ServiceRoute::Vfs => Ok(info),
            ServiceRoute::Procfs => {
                self.require_capability("procfs_service", "procfs.tree", "lookup")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                let node = self.procfs_mut().lookup(path, false)?;
                Ok(LookupInfo { route: ServiceRoute::Procfs, node })
            }
            ServiceRoute::Devfs => {
                self.require_capability("devfs_service", "device.pulse", "read")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                let node = self.devfs.lookup(path, false)?;
                Ok(LookupInfo { route: ServiceRoute::Devfs, node })
            }
        }
    }

    pub(super) fn read_from_fd(
        &mut self,
        fd: u32,
        count: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        self.require_fd_readable(fd)?;
        let (route, node, cursor, path) = self.service_fd_snapshot(fd)?;
        if node == NodeKind::Directory {
            return Err(ServiceCallError::Errno(vmos_abi::ERR_EISDIR));
        }

        let bytes = match route {
            ServiceRoute::Vfs => {
                self.require_capability("vfs_service", "vfs.namespace", "read")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                self.vfs.read_file_range(&path, cursor, count)?
            }
            ServiceRoute::Procfs => {
                self.require_capability("procfs_service", "procfs.tree", "read")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                self.procfs_read_with_recovery(&path)?
            }
            ServiceRoute::Devfs => {
                self.require_capability("devfs_service", "device.pulse", "read")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                if let Some(bytes) = self.pulse.read(&path, count, interrupts::tick_count()) {
                    bytes.to_vec()
                } else if path.as_slice() == b"/dev/pulse" {
                    return Err(ServiceCallError::Errno(ERR_EAGAIN));
                } else {
                    self.devfs.read_device(&path, count, false)?
                }
            }
        };

        let chunk = match route {
            ServiceRoute::Vfs => bytes,
            ServiceRoute::Procfs | ServiceRoute::Devfs => {
                let start = cursor.min(bytes.len());
                let end = start.saturating_add(count as usize).min(bytes.len());
                bytes[start..end].to_vec()
            }
        };
        self.set_fd_cursor(fd, cursor.saturating_add(chunk.len()))?;
        Ok(chunk)
    }

    pub(super) fn write_to_fd(&mut self, fd: u32, bytes: &[u8]) -> Result<usize, ServiceCallError> {
        self.require_fd_writable(fd)?;
        let (route, node, cursor, path) = self.service_fd_snapshot(fd)?;
        if route != ServiceRoute::Vfs || node != NodeKind::File {
            return Err(ServiceCallError::Errno(ERR_EBADF));
        }
        self.require_capability("vfs_service", "vfs.namespace", "write")
            .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
        let written = self.vfs.write_file(&path, cursor, bytes)?;
        self.set_fd_cursor(fd, cursor + written)?;
        Ok(written)
    }

    pub(crate) fn write_vfs_fd_bytes(&mut self, fd: u32, bytes: &[u8]) -> Result<usize, i32> {
        self.write_to_fd(fd, bytes).map_err(errno_from_service_error)
    }

    pub(crate) fn is_vfs_file_fd(&self, fd: u32) -> bool {
        self.fd_entry(fd).is_some_and(|entry| {
            matches!(
                entry.resource,
                FdResource::ServiceNode { route: ServiceRoute::Vfs, node: NodeKind::File, .. }
            )
        })
    }

    pub(crate) fn truncate_fd(&mut self, fd: u32, len: usize) -> Result<(), i32> {
        self.require_fd_writable(fd).map_err(errno_from_service_error)?;
        let (route, node, cursor, path) =
            self.service_fd_snapshot(fd).map_err(errno_from_service_error)?;
        if route != ServiceRoute::Vfs || node != NodeKind::File {
            return Err(ERR_EBADF);
        }
        self.require_capability("vfs_service", "vfs.namespace", "write").map_err(|_| ERR_EPERM)?;
        self.vfs.truncate_file(&path, len).map_err(errno_from_service_error)?;
        if cursor > len {
            self.set_fd_cursor(fd, len).map_err(errno_from_service_error)?;
        }
        Ok(())
    }

    pub(crate) fn seek_fd(&mut self, fd: u32, offset: i64, whence: u32) -> Result<i64, i32> {
        const SEEK_SET: u32 = 0;
        const SEEK_CUR: u32 = 1;
        const SEEK_END: u32 = 2;

        let (route, node, cursor, path) =
            self.service_fd_snapshot(fd).map_err(errno_from_service_error)?;
        if node == NodeKind::Directory {
            return Err(ERR_EBADF);
        }
        let len = self.len_for_service_node(route, &path);
        let base = match whence {
            SEEK_SET => 0,
            SEEK_CUR => cursor as i64,
            SEEK_END => i64::try_from(len).map_err(|_| ERR_EINVAL)?,
            _ => return Err(ERR_EINVAL),
        };
        let next = base.checked_add(offset).ok_or(ERR_EINVAL)?;
        if next < 0 {
            return Err(ERR_EINVAL);
        }
        let next = usize::try_from(next).map_err(|_| ERR_EINVAL)?;
        self.set_fd_cursor(fd, next).map_err(errno_from_service_error)?;
        Ok(next as i64)
    }

    pub(crate) fn fcntl_setlk_fd(
        &mut self,
        fd: u32,
        owner: u32,
        lock_type: i16,
        whence: i16,
        start: i64,
        len: i64,
    ) -> Result<(), i32> {
        const F_RDLCK: i16 = 0;
        const F_WRLCK: i16 = 1;
        const F_UNLCK: i16 = 2;

        let (vfs_node_id, path, start, len) = self.fcntl_lock_target(fd, whence, start, len)?;
        match lock_type {
            F_RDLCK | F_WRLCK => {
                let result = self.vfs.fcntl_setlk(
                    vfs_node_id,
                    &path,
                    owner,
                    lock_type == F_WRLCK,
                    start,
                    len,
                );
                if result.is_ok() {
                    self.wake_ready_file_lock_waits();
                }
                result
            }
            F_UNLCK => {
                self.vfs.fcntl_unlock(vfs_node_id, &path, owner, start, len);
                self.wake_ready_file_lock_waits();
                Ok(())
            }
            _ => Err(ERR_EINVAL),
        }
    }

    pub(crate) fn fcntl_setlkw_fd(
        &mut self,
        fd: u32,
        owner: u32,
        lock_type: i16,
        whence: i16,
        start: i64,
        len: i64,
    ) -> Result<(), i32> {
        loop {
            match self.fcntl_setlk_fd(fd, owner, lock_type, whence, start, len) {
                Ok(()) => return Ok(()),
                Err(ERR_EAGAIN) => {
                    let token = self.waits.register(
                        self.scheduler.current_task(),
                        WaitRegistration::FileLock { fd, owner, lock_type, whence, start, len },
                        interrupts::tick_count(),
                        interrupts::TIMER_HZ,
                    );
                    self.record_wait_token(token);
                    match self.block_on_wait("ring3_fcntl_setlkw", token).map_err(|_| ERR_EINVAL)? {
                        LinuxCallResult::Ret(0) => {}
                        LinuxCallResult::Ret(ret) if ret < 0 => return Err((-ret) as i32),
                        _ => return Err(ERR_EINVAL),
                    }
                }
                Err(errno) => return Err(errno),
            }
        }
    }

    pub(super) fn file_lock_wait_is_ready(
        &mut self,
        fd: u32,
        owner: u32,
        lock_type: i16,
        whence: i16,
        start: i64,
        len: i64,
    ) -> bool {
        self.fcntl_lock_available_fd(fd, owner, lock_type, whence, start, len).unwrap_or(false)
    }

    pub(crate) fn fcntl_getlk_fd(
        &mut self,
        fd: u32,
        owner: u32,
        lock_type: i16,
        whence: i16,
        start: i64,
        len: i64,
    ) -> Result<Option<(bool, u32, i64, i64)>, i32> {
        const F_RDLCK: i16 = 0;
        const F_WRLCK: i16 = 1;
        const F_UNLCK: i16 = 2;

        let want_write = match lock_type {
            F_RDLCK => false,
            F_WRLCK => true,
            F_UNLCK => return Ok(None),
            _ => return Err(ERR_EINVAL),
        };
        let (vfs_node_id, path, start, len) = self.fcntl_lock_target(fd, whence, start, len)?;
        Ok(self.vfs.fcntl_getlk(vfs_node_id, &path, owner, want_write, start, len))
    }

    pub(crate) fn fsetxattr_fd(
        &mut self,
        fd: u32,
        name: &[u8],
        value: &[u8],
        flags: u32,
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        let path = self.xattr_target(fd)?;
        self.check_xattr_access(&path, name, XattrAccess::Write, access)?;
        self.vfs.fsetxattr(&path, name, value, flags).map_err(errno_from_service_error)
    }

    pub(crate) fn fgetxattr_fd(
        &mut self,
        fd: u32,
        name: &[u8],
        size: usize,
        access: AccessIds<'_>,
    ) -> Result<Vec<u8>, i32> {
        let path = self.xattr_target(fd)?;
        self.check_xattr_access(&path, name, XattrAccess::Read, access)?;
        self.vfs.fgetxattr(&path, name, size).map_err(errno_from_service_error)
    }

    pub(crate) fn flistxattr_fd(
        &mut self,
        fd: u32,
        size: usize,
        access: AccessIds<'_>,
    ) -> Result<Vec<u8>, i32> {
        let path = self.xattr_target(fd)?;
        let encoded = self.vfs.flistxattr(&path, 0).map_err(errno_from_service_error)?;
        let user_visible = self.check_path_access(&path, MAY_READ, access).is_ok();
        let privileged_visible = access.has_capability(CAP_SYS_ADMIN)
            && self.check_path_access(&path, 0, access).is_ok();
        let mut visible = Vec::new();
        for name in encoded.split(|byte| *byte == 0).filter(|name| !name.is_empty()) {
            match classify_xattr_namespace(name) {
                Ok(XattrNamespace::User) if user_visible => {
                    visible.extend_from_slice(name);
                    visible.push(0);
                }
                Ok(XattrNamespace::Privileged) if privileged_visible => {
                    visible.extend_from_slice(name);
                    visible.push(0);
                }
                _ => {}
            }
        }
        if size != 0 && size < visible.len() {
            return Err(vmos_abi::ERR_ERANGE);
        }
        Ok(visible)
    }

    pub(crate) fn fremovexattr_fd(
        &mut self,
        fd: u32,
        name: &[u8],
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        let path = self.xattr_target(fd)?;
        self.check_xattr_access(&path, name, XattrAccess::Write, access)?;
        self.vfs.fremovexattr(&path, name).map_err(errno_from_service_error)
    }

    fn fcntl_lock_available_fd(
        &mut self,
        fd: u32,
        owner: u32,
        lock_type: i16,
        whence: i16,
        start: i64,
        len: i64,
    ) -> Result<bool, i32> {
        const F_RDLCK: i16 = 0;
        const F_WRLCK: i16 = 1;
        const F_UNLCK: i16 = 2;

        let want_write = match lock_type {
            F_RDLCK => false,
            F_WRLCK => true,
            F_UNLCK => return Ok(true),
            _ => return Err(ERR_EINVAL),
        };
        let (vfs_node_id, path, start, len) = self.fcntl_lock_target(fd, whence, start, len)?;
        Ok(self.vfs.fcntl_getlk(vfs_node_id, &path, owner, want_write, start, len).is_none())
    }

    pub(super) fn wake_ready_file_lock_waits(&mut self) {
        let pending = self.waits.pending_sources();
        for (token, source) in pending {
            let WaitSource::FileLock { fd, owner, lock_type, whence, start, len } = source else {
                continue;
            };
            if self.file_lock_wait_is_ready(fd, owner, lock_type, whence, start, len) {
                self.scheduler.push_event(Event::WaitReady(token.id));
            }
        }
        self.drain_event_queue();
    }

    pub(crate) fn release_file_locks_for_pid(&mut self, pid: u32) {
        if self.vfs.fcntl_unlock_owner(pid) {
            self.wake_ready_file_lock_waits();
        }
    }

    fn fcntl_lock_target(
        &mut self,
        fd: u32,
        whence: i16,
        start: i64,
        len: i64,
    ) -> Result<(Option<u64>, Vec<u8>, i64, i64), i32> {
        let (route, node, cursor, path, vfs_node_id) =
            self.service_fd_lock_snapshot(fd).map_err(errno_from_service_error)?;
        if route != ServiceRoute::Vfs || node != NodeKind::File {
            return Err(ERR_EBADF);
        }
        let file_len = self.len_for_service_node(route, &path);
        let base = match whence {
            0 => 0i128,
            1 => cursor as i128,
            2 => file_len as i128,
            _ => return Err(ERR_EINVAL),
        };
        let mut range_start = base.checked_add(start as i128).ok_or(ERR_EINVAL)?;
        let mut range_len = len as i128;
        if range_len < 0 {
            range_start = range_start.checked_add(range_len).ok_or(ERR_EINVAL)?;
            range_len = -range_len;
        }
        if range_start < 0 || range_len > i64::MAX as i128 {
            return Err(ERR_EINVAL);
        }
        Ok((vfs_node_id, path, range_start as i64, range_len as i64))
    }

    fn xattr_target(&mut self, fd: u32) -> Result<Vec<u8>, i32> {
        let (route, _, _, path) = self.service_fd_snapshot(fd).map_err(errno_from_service_error)?;
        if route != ServiceRoute::Vfs {
            return Err(vmos_abi::ERR_EOPNOTSUPP);
        }
        Ok(path)
    }

    fn check_xattr_access(
        &mut self,
        path: &[u8],
        name: &[u8],
        op: XattrAccess,
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        match classify_xattr_namespace(name)? {
            XattrNamespace::User => {
                let mask = match op {
                    XattrAccess::Read => MAY_READ,
                    XattrAccess::Write => MAY_WRITE,
                };
                self.check_path_access(path, mask, access)
            }
            XattrNamespace::Privileged => {
                self.check_path_access(path, 0, access)?;
                if access.has_capability(CAP_SYS_ADMIN) { Ok(()) } else { Err(ERR_EPERM) }
            }
        }
    }

    pub(crate) fn check_path_access(
        &mut self,
        path: &[u8],
        mask: u32,
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        self.check_path_traversal_access(path, access)?;
        let info = self.lookup_path(path).map_err(errno_from_service_error)?;
        if mask == 0 {
            return Ok(());
        }
        let mode = self.mode_for_service_node(info.route, info.node, path);
        let (owner_uid, owner_gid) = self.owner_for_service_node(info.route, path);
        if mode_grants_access(mode, owner_uid, owner_gid, access, mask) {
            Ok(())
        } else {
            Err(ERR_EACCES)
        }
    }

    pub(crate) fn check_parent_access(
        &mut self,
        path: &[u8],
        mask: u32,
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        let Some(parent) = parent_path_for_access(path) else {
            return Err(ERR_EPERM);
        };
        self.check_path_traversal_access(&parent, access)?;
        let info = self.lookup_path(&parent).map_err(errno_from_service_error)?;
        if info.node != NodeKind::Directory {
            return Err(vmos_abi::ERR_ENOTDIR);
        }
        let mode = self.mode_for_service_node(info.route, info.node, &parent);
        let (owner_uid, owner_gid) = self.owner_for_service_node(info.route, &parent);
        if mode_grants_access(mode, owner_uid, owner_gid, access, mask) {
            Ok(())
        } else {
            Err(ERR_EACCES)
        }
    }

    fn check_path_traversal_access(
        &mut self,
        path: &[u8],
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        let mut parents = Vec::new();
        let mut current = parent_path_for_access(path);
        while let Some(parent) = current {
            let is_root = parent == b"/";
            current = if is_root { None } else { parent_path_for_access(&parent) };
            parents.push(parent);
        }
        for parent in parents.iter().rev() {
            let info = self.lookup_path(parent).map_err(errno_from_service_error)?;
            if info.node != NodeKind::Directory {
                return Err(vmos_abi::ERR_ENOTDIR);
            }
            let mode = self.mode_for_service_node(info.route, info.node, parent);
            let (owner_uid, owner_gid) = self.owner_for_service_node(info.route, parent);
            if !mode_grants_access(mode, owner_uid, owner_gid, access, MAY_EXEC) {
                return Err(ERR_EACCES);
            }
        }
        Ok(())
    }

    fn require_fd_readable(&self, fd: u32) -> Result<(), ServiceCallError> {
        let entry = self.fd_entry(fd).ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        match entry.status_flags & O_ACCMODE {
            O_WRONLY => Err(ServiceCallError::Errno(ERR_EBADF)),
            _ => Ok(()),
        }
    }

    fn require_fd_writable(&self, fd: u32) -> Result<(), ServiceCallError> {
        let entry = self.fd_entry(fd).ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        match entry.status_flags & O_ACCMODE {
            O_WRONLY | O_RDWR => Ok(()),
            _ => Err(ServiceCallError::Errno(ERR_EBADF)),
        }
    }

    pub(super) fn read_dir_entries(
        &mut self,
        fd: u32,
        count: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let (route, node, cursor, path) = self.service_fd_snapshot(fd)?;
        if node != NodeKind::Directory {
            return Err(ServiceCallError::Errno(vmos_abi::ERR_ENOTDIR));
        }

        let bytes = match route {
            ServiceRoute::Vfs => {
                self.require_capability("vfs_service", "vfs.namespace", "list")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                self.vfs.list_dir(&path, false)?
            }
            ServiceRoute::Procfs => {
                self.require_capability("procfs_service", "procfs.tree", "list")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                self.procfs_mut().list_dir(&path, false)?
            }
            ServiceRoute::Devfs => {
                self.require_capability("devfs_service", "device.pulse", "poll")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                self.devfs.list_dir(&path, false)?
            }
        };

        let start = cursor.min(bytes.len());
        let end = start.saturating_add(count as usize).min(bytes.len());
        let chunk = bytes[start..end].to_vec();
        self.set_fd_cursor(fd, end)?;
        Ok(chunk)
    }

    pub(super) fn read_link_path(&mut self, path: &[u8]) -> Result<Vec<u8>, ServiceCallError> {
        let info = self.lookup_path(path)?;
        if info.node != NodeKind::Symlink {
            return Err(ServiceCallError::Errno(ERR_EINVAL));
        }

        match info.route {
            ServiceRoute::Vfs => {
                self.require_capability("vfs_service", "vfs.namespace", "readlink")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                self.vfs.read_link(path, false)
            }
            ServiceRoute::Procfs => {
                self.require_capability("procfs_service", "procfs.tree", "readlink")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                self.procfs_mut().read_link(path, false)
            }
            ServiceRoute::Devfs => Err(ServiceCallError::Errno(ERR_EINVAL)),
        }
    }

    pub(crate) fn read_link_path_bytes(&mut self, path: &[u8]) -> Result<Vec<u8>, i32> {
        self.read_link_path(path).map_err(errno_from_service_error)
    }

    pub(super) fn build_dirent_records(
        &mut self,
        dir_path: &[u8],
        listing: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::new();
        for name in listing.split(|byte| *byte == b'\n') {
            if name.is_empty() {
                continue;
            }

            let dtype = match self
                .path_kind(&join_path(dir_path, name))
                .map_err(|_| "failed to classify directory entry kind")?
            {
                NodeKind::File => 8,
                NodeKind::Directory => 4,
                NodeKind::Symlink => 10,
                NodeKind::CharDevice => 2,
            };
            out.push(dtype);
            out.extend_from_slice(name);
            out.push(0);
        }
        Ok(out)
    }

    fn procfs_read_with_recovery(&mut self, path: &[u8]) -> Result<Vec<u8>, ServiceCallError> {
        let inject_fault = self.take_fault(InjectedFault::ProcfsRead);
        let store = self
            .store_id("procfs_service")
            .ok_or(ServiceCallError::Invalid("procfs store was not registered"))?;
        let transaction = self.begin_semantic_transaction("procfs.read_file", Some(store));
        match self.procfs_mut().read_file(path, inject_fault) {
            Ok(bytes) => {
                self.commit_semantic_transaction(transaction);
                Ok(bytes)
            }
            Err(ServiceCallError::Trap(reason)) if inject_fault => {
                crate::kinfo!("procfs_service trapped; recreating service store");
                self.rollback_semantic_transaction(transaction, reason);
                self.recover_procfs_store_after_trap(reason)?;
                let retry = self.begin_semantic_transaction("procfs.read_file.retry", Some(store));
                match self.procfs_mut().read_file(path, false) {
                    Ok(bytes) => {
                        self.commit_semantic_transaction(retry);
                        Ok(bytes)
                    }
                    Err(err) => {
                        self.rollback_semantic_transaction(retry, "procfs retry failed");
                        Err(err)
                    }
                }
            }
            Err(err) => {
                self.rollback_semantic_transaction(transaction, "procfs read failed");
                Err(err)
            }
        }
    }

    fn take_fault(&mut self, target: InjectedFault) -> bool {
        match self.fault {
            Some(current) if current == target => {
                self.fault = None;
                true
            }
            _ => false,
        }
    }

    pub(super) fn alloc_fd(&mut self, entry: FdEntry) -> Result<u32, i32> {
        let limit = self.fd_allocation_limit();
        let Some(fd) =
            (3..limit).find(|fd| self.fd_table.get(*fd as usize).is_none_or(Option::is_none))
        else {
            return Err(ERR_EMFILE);
        };
        self.install_fd_at(fd, entry);
        Ok(fd)
    }

    fn fd_allocation_limit(&self) -> u32 {
        self.get_rlimit(self.current_pid(), RLIMIT_NOFILE).cur.min(MAX_LINUX_FD as u64) as u32
    }

    fn available_fd_slots(&self) -> usize {
        (3..self.fd_allocation_limit())
            .filter(|fd| self.fd_table.get(*fd as usize).is_none_or(Option::is_none))
            .count()
    }

    pub(crate) fn can_allocate_fds(&self, count: usize) -> bool {
        self.available_fd_slots() >= count
    }

    fn install_fd_at(&mut self, entry_fd: u32, entry: FdEntry) {
        let owner_task = Some(self.scheduler.current_task());
        self.install_fd_at_for_owner(entry_fd, entry, owner_task);
    }

    fn install_fd_at_for_owner(&mut self, fd: u32, mut entry: FdEntry, owner_task: Option<TaskId>) {
        let resource_kind = fd_resource_kind(&entry.resource);
        let resource_label = fd_resource_label(&entry.resource);
        let resource_id =
            self.semantic.register_resource(resource_kind, owner_task, &resource_label);
        if entry.cursor_group.is_none() {
            entry.cursor_group = Some(resource_id);
        }
        let fd = fd as usize;
        while self.fd_table.len() <= fd {
            self.fd_table.push(None);
        }
        self.ensure_fd_handle_slot(fd);
        self.fd_table[fd] = Some(entry);
        self.fd_handles[fd] = self.semantic.resource_handle(resource_id);
    }

    pub(crate) fn fork_fd_table_for_owner(&mut self, owner_task: TaskId) -> FdTableSnapshot {
        let snapshot = self.capture_fd_table_snapshot();
        self.hidden_fd_table_refs.push(snapshot.fd_table.clone());
        let child_entries = snapshot.fd_table.clone();
        self.fd_table = vec![None; child_entries.len()];
        self.fd_handles = vec![None; child_entries.len()];
        for (fd, entry) in child_entries.into_iter().enumerate() {
            if let Some(entry) = entry {
                self.install_fd_at_for_owner(fd as u32, entry, Some(owner_task));
            }
        }
        snapshot
    }

    pub(crate) fn restore_fd_table_snapshot(&mut self, snapshot: FdTableSnapshot) {
        self.fd_table = snapshot.fd_table;
        self.fd_handles = snapshot.fd_handles;
    }

    pub(crate) fn pop_hidden_fd_table_refs(&mut self) {
        let _ = self.hidden_fd_table_refs.pop();
    }

    pub(crate) fn close_active_fd_table_for_process_exit(&mut self) {
        let len = self.fd_table.len();
        for fd in 3..len {
            let _ = self.close_fd_slot(fd as u32, false);
        }
    }

    pub(crate) fn close_cloexec_fds_for_exec(&mut self) {
        let fds: Vec<u32> = self
            .fd_table
            .iter()
            .enumerate()
            .filter_map(|(fd, entry)| {
                (fd >= 3 && entry.as_ref().is_some_and(|entry| entry.fd_flags & 1 != 0))
                    .then_some(fd as u32)
            })
            .collect();
        for fd in fds {
            if let Err(errno) = self.close_fd_slot(fd, false) {
                crate::kwarn!("exec close-on-exec fd {} failed errno={}", fd, errno);
            }
        }
    }

    fn capture_fd_table_snapshot(&self) -> FdTableSnapshot {
        FdTableSnapshot { fd_table: self.fd_table.clone(), fd_handles: self.fd_handles.clone() }
    }

    fn ensure_fd_handle_slot(&mut self, fd: usize) {
        while self.fd_handles.len() <= fd {
            self.fd_handles.push(None);
        }
    }

    pub(super) fn fd_entry(&self, fd: u32) -> Option<&FdEntry> {
        self.fd_table.get(fd as usize)?.as_ref()
    }

    pub(super) fn fd_handle(&self, fd: u32) -> Option<ResourceHandle> {
        self.fd_handles.get(fd as usize).copied().flatten()
    }

    pub(crate) fn dup_fd(&mut self, old_fd: u32) -> Result<u32, i32> {
        let entry = self.dup_source_entry(old_fd)?;
        let new_fd = (3..self.fd_allocation_limit())
            .find(|fd| self.fd_table.get(*fd as usize).is_none_or(Option::is_none))
            .ok_or(ERR_EMFILE)?;
        self.install_fd_at(new_fd, entry);
        Ok(new_fd)
    }

    pub(crate) fn dup_fd_from(&mut self, old_fd: u32, min_fd: u32) -> Result<u32, i32> {
        let limit = self.fd_allocation_limit();
        if min_fd >= limit {
            return Err(ERR_EINVAL);
        }
        let entry = self.dup_source_entry(old_fd)?;
        let new_fd = (min_fd.max(3)..limit)
            .find(|fd| self.fd_table.get(*fd as usize).is_none_or(Option::is_none))
            .ok_or(ERR_EMFILE)?;
        self.install_fd_at(new_fd, entry);
        Ok(new_fd)
    }

    pub(crate) fn dup_fd_to(
        &mut self,
        old_fd: u32,
        new_fd: u32,
        allow_same_fd: bool,
    ) -> Result<u32, i32> {
        if new_fd >= self.fd_allocation_limit() {
            return Err(ERR_EBADF);
        }
        if old_fd == new_fd {
            if allow_same_fd {
                let _ = self.dup_source_entry(old_fd)?;
                return Ok(new_fd);
            }
            return Err(ERR_EINVAL);
        }

        let entry = self.dup_source_entry(old_fd)?;
        self.close_fd_if_present(new_fd)?;
        self.install_fd_at(new_fd, entry);
        Ok(new_fd)
    }

    pub(crate) fn close_fd_number(&mut self, fd: u32) -> Result<(), i32> {
        if self.require_capability("linux_syscall", "fd.table", "close").is_err() {
            return Err(ERR_EPERM);
        }
        if fd < 3 {
            return Err(ERR_EBADF);
        }
        self.close_fd_slot(fd, true)
    }

    pub(crate) fn close_fd_range(&mut self, first: u32, last: u32) -> Result<(), i32> {
        if first > last {
            return Err(ERR_EINVAL);
        }
        if self.require_capability("linux_syscall", "fd.table", "close").is_err() {
            return Err(ERR_EPERM);
        }
        let end = last.min(MAX_LINUX_FD - 1);
        for fd in first.max(3)..=end {
            let _ = self.close_fd_slot(fd, true);
        }
        Ok(())
    }

    pub(crate) fn set_fd_flags_range(
        &mut self,
        first: u32,
        last: u32,
        flags: u32,
    ) -> Result<(), i32> {
        if first > last {
            return Err(ERR_EINVAL);
        }
        let end = last.min(MAX_LINUX_FD - 1);
        for fd in first.max(3)..=end {
            if let Some(entry) = self.fd_table.get_mut(fd as usize).and_then(Option::as_mut) {
                entry.fd_flags = flags;
            }
        }
        Ok(())
    }

    pub(crate) fn create_fifo_path(
        &mut self,
        path: &[u8],
        mode: u32,
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        if self.lookup_path(path).is_ok() {
            return Err(vmos_abi::ERR_EEXIST);
        }
        self.check_parent_access(path, MAY_WRITE | MAY_EXEC, access)?;
        self.vfs.create_file(path, mode, access.uid, access.gid).map_err(errno_from_service_error)
    }

    pub(crate) fn create_pipe_pair(&mut self) -> Result<(u32, u32), i32> {
        if self.available_fd_slots() < 2 {
            return Err(ERR_EMFILE);
        }
        let pipe_id = self.next_pipe_id;
        self.next_pipe_id = self.next_pipe_id.saturating_add(1);
        self.pipes.push(PipeState {
            id: pipe_id,
            buffer: Vec::new(),
            capacity: DEFAULT_PIPE_CAPACITY,
            read_open: true,
            write_open: true,
        });
        let read_fd = self.alloc_fd(FdEntry {
            resource: FdResource::PipeEnd { pipe_id, readable: true, writable: false },
            cursor: 0,
            fd_flags: 0,
            status_flags: 0,
            cursor_group: None,
        })?;
        let write_fd = self.alloc_fd(FdEntry {
            resource: FdResource::PipeEnd { pipe_id, readable: false, writable: true },
            cursor: 0,
            fd_flags: 0,
            status_flags: 0,
            cursor_group: None,
        })?;
        Ok((read_fd, write_fd))
    }

    pub(crate) fn create_socketpair(&mut self) -> Result<(u32, u32), i32> {
        if self.available_fd_slots() < 2 {
            return Err(ERR_EMFILE);
        }
        let pair_id = self.next_socketpair_id;
        self.next_socketpair_id = self.next_socketpair_id.saturating_add(1);
        self.socketpairs.push(SocketPairState {
            id: pair_id,
            a_to_b: Vec::new(),
            b_to_a: Vec::new(),
            capacity: DEFAULT_PIPE_CAPACITY,
            open_a: true,
            open_b: true,
        });
        let fd_a = self.alloc_fd(FdEntry {
            resource: FdResource::SocketPairEnd { pair_id, endpoint: 0 },
            cursor: 0,
            fd_flags: 0,
            status_flags: 0,
            cursor_group: None,
        })?;
        let fd_b = self.alloc_fd(FdEntry {
            resource: FdResource::SocketPairEnd { pair_id, endpoint: 1 },
            cursor: 0,
            fd_flags: 0,
            status_flags: 0,
            cursor_group: None,
        })?;
        Ok((fd_a, fd_b))
    }

    pub(crate) fn create_eventfd(&mut self, initval: u64, flags: u32) -> Result<u32, i32> {
        const EFD_SEMAPHORE: u32 = 1;
        const EFD_CLOEXEC: u32 = 0o2000000;
        const EFD_NONBLOCK: u32 = 0o0004000;

        if flags & !(EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK) != 0 {
            return Err(ERR_EINVAL);
        }
        if initval > EVENTFD_MAX_COUNTER {
            return Err(ERR_EINVAL);
        }
        if !self.can_allocate_fds(1) {
            return Err(ERR_EMFILE);
        }

        let eventfd_id = self.next_eventfd_id;
        self.next_eventfd_id = self.next_eventfd_id.saturating_add(1);
        self.eventfds.push(EventFdState {
            id: eventfd_id,
            counter: initval,
            semaphore: flags & EFD_SEMAPHORE != 0,
        });
        let fd = self.alloc_fd(FdEntry {
            resource: FdResource::EventFd { eventfd_id },
            cursor: 0,
            fd_flags: 0,
            status_flags: flags & EFD_NONBLOCK,
            cursor_group: None,
        })?;
        if flags & EFD_CLOEXEC != 0 {
            self.set_fd_flags(fd, 1)?;
        }
        Ok(fd)
    }

    pub(crate) fn is_pipe_fd(&self, fd: u32) -> bool {
        self.fd_entry(fd).is_some_and(|entry| matches!(entry.resource, FdResource::PipeEnd { .. }))
    }

    pub(crate) fn is_socketpair_fd(&self, fd: u32) -> bool {
        self.fd_entry(fd)
            .is_some_and(|entry| matches!(entry.resource, FdResource::SocketPairEnd { .. }))
    }

    pub(crate) fn require_socket_fd(&self, fd: u32) -> Result<(), i32> {
        let entry = self.fd_entry(fd).ok_or(ERR_EBADF)?;
        if matches!(entry.resource, FdResource::Socket { .. }) { Ok(()) } else { Err(ERR_ENOTSOCK) }
    }

    pub(crate) fn socket_ipv4_endpoint(
        &mut self,
        fd: u32,
        peer: bool,
    ) -> Result<Option<Ipv4SocketEndpoint>, i32> {
        let entry = self.fd_entry(fd).ok_or(ERR_EBADF)?;
        let socket_id = match &entry.resource {
            FdResource::Socket { socket_id, .. } => *socket_id as u32,
            FdResource::SocketPairEnd { .. } => return Ok(None),
            _ => return Err(ERR_ENOTSOCK),
        };
        if let Some(endpoint) = self.net_stack_socket_ipv4_endpoint(socket_id, peer) {
            return Ok(Some(endpoint));
        }
        self.linux_socket
            .ipv4_endpoint(socket_id, peer)
            .map(|endpoint| {
                endpoint.map(|(ipv4, port)| Ipv4SocketEndpoint { addr: ipv4.to_be_bytes(), port })
            })
            .map_err(errno_from_service_error)
    }

    pub(crate) fn is_eventfd_fd(&self, fd: u32) -> bool {
        self.fd_entry(fd).is_some_and(|entry| matches!(entry.resource, FdResource::EventFd { .. }))
    }

    pub(crate) fn read_pipe_fd_bytes(&mut self, fd: u32, count: usize) -> Result<Vec<u8>, i32> {
        let (pipe_id, readable) = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::PipeEnd { pipe_id, readable, .. } => (*pipe_id, *readable),
            _ => return Err(ERR_EBADF),
        };
        if !readable {
            return Err(ERR_EBADF);
        }
        let pipe = self.pipe_mut(pipe_id)?;
        if !pipe.read_open {
            return Err(ERR_EBADF);
        }
        if pipe.buffer.is_empty() {
            return if pipe.write_open { Err(ERR_EAGAIN) } else { Ok(Vec::new()) };
        }
        let len = count.min(pipe.buffer.len());
        let bytes = pipe.buffer.drain(..len).collect();
        if len != 0 {
            self.notify_ready_key(pipe_ready_key(pipe_id, false, true), "pipe write readiness");
        }
        Ok(bytes)
    }

    pub(crate) fn write_pipe_fd_bytes(&mut self, fd: u32, bytes: &[u8]) -> Result<usize, i32> {
        let (pipe_id, writable) = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::PipeEnd { pipe_id, writable, .. } => (*pipe_id, *writable),
            _ => return Err(ERR_EBADF),
        };
        if !writable {
            return Err(ERR_EBADF);
        }
        let pipe = self.pipe_mut(pipe_id)?;
        if !pipe.write_open {
            return Err(ERR_EBADF);
        }
        let available = pipe.capacity.saturating_sub(pipe.buffer.len());
        if available == 0 {
            return Err(ERR_EAGAIN);
        }
        let written = bytes.len().min(available);
        pipe.buffer.extend_from_slice(&bytes[..written]);
        if written != 0 {
            self.notify_ready_key(pipe_ready_key(pipe_id, true, false), "pipe read readiness");
        }
        Ok(written)
    }

    pub(crate) fn set_pipe_capacity(&mut self, fd: u32, requested: usize) -> Result<usize, i32> {
        let pipe_id = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::PipeEnd { pipe_id, .. } => *pipe_id,
            _ => return Err(ERR_EBADF),
        };
        let pipe = self.pipe_mut(pipe_id)?;
        let next = requested.max(pipe.buffer.len()).max(1);
        pipe.capacity = next;
        Ok(next)
    }

    pub(crate) fn pipe_capacity(&mut self, fd: u32) -> Result<usize, i32> {
        let pipe_id = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::PipeEnd { pipe_id, .. } => *pipe_id,
            _ => return Err(ERR_EBADF),
        };
        Ok(self.pipe_mut(pipe_id)?.capacity)
    }

    pub(crate) fn pipe_poll_revents(&self, fd: u32, events: u16) -> Result<u16, i32> {
        let (pipe_id, readable, writable) = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::PipeEnd { pipe_id, readable, writable } => (*pipe_id, *readable, *writable),
            _ => return Ok(0),
        };
        let pipe = self.pipes.iter().find(|pipe| pipe.id == pipe_id).ok_or(ERR_EBADF)?;
        let mut revents = 0u16;
        if readable && !pipe.buffer.is_empty() {
            revents |= requested_read_revents(events);
        }
        if readable && !pipe.write_open {
            revents |= POLLHUP;
        }
        if writable && pipe.read_open && pipe.buffer.len() < pipe.capacity {
            revents |= requested_write_revents(events);
        }
        if writable && !pipe.read_open {
            revents |= POLLERR;
        }
        Ok(revents)
    }

    pub(super) fn pipe_ready_key_matches_events(&mut self, ready_key: u64, events: u32) -> bool {
        if ready_key & READY_TAG_MASK != PIPE_READY_TAG {
            return false;
        }
        let pipe_id = (ready_key & 0x0fff_ffff_ffff_fffe) >> 1;
        let write_end = (ready_key & 1) != 0;
        self.pipes.iter().find(|pipe| pipe.id == pipe_id).is_some_and(|pipe| {
            if write_end {
                events & EPOLLOUT != 0 && pipe.read_open && pipe.write_open
            } else {
                events & EPOLLIN != 0 && pipe.read_open && !pipe.buffer.is_empty()
            }
        })
    }

    fn pipe_mut(&mut self, pipe_id: u64) -> Result<&mut PipeState, i32> {
        self.pipes.iter_mut().find(|pipe| pipe.id == pipe_id).ok_or(ERR_EBADF)
    }

    pub(crate) fn read_socketpair_fd_bytes(
        &mut self,
        fd: u32,
        count: usize,
    ) -> Result<Vec<u8>, i32> {
        let (pair_id, endpoint) = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::SocketPairEnd { pair_id, endpoint } => (*pair_id, *endpoint),
            _ => return Err(ERR_EBADF),
        };
        let pair = self.socketpair_mut(pair_id)?;
        let (incoming, peer_open) = if endpoint == 0 {
            (&mut pair.b_to_a, pair.open_b)
        } else {
            (&mut pair.a_to_b, pair.open_a)
        };
        if incoming.is_empty() {
            return if peer_open { Err(ERR_EAGAIN) } else { Ok(Vec::new()) };
        }
        let len = count.min(incoming.len());
        let bytes = incoming.drain(..len).collect();
        if len != 0 {
            self.notify_ready_key(
                socketpair_ready_key(pair_id, peer_endpoint(endpoint)),
                "socketpair write readiness",
            );
        }
        Ok(bytes)
    }

    pub(crate) fn write_socketpair_fd_bytes(
        &mut self,
        fd: u32,
        bytes: &[u8],
    ) -> Result<usize, i32> {
        let (pair_id, endpoint) = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::SocketPairEnd { pair_id, endpoint } => (*pair_id, *endpoint),
            _ => return Err(ERR_EBADF),
        };
        let pair = self.socketpair_mut(pair_id)?;
        let (outgoing, peer_open) = if endpoint == 0 {
            (&mut pair.a_to_b, pair.open_b)
        } else {
            (&mut pair.b_to_a, pair.open_a)
        };
        if !peer_open {
            return Err(ERR_EBADF);
        }
        let available = pair.capacity.saturating_sub(outgoing.len());
        if available == 0 {
            return Err(ERR_EAGAIN);
        }
        let written = bytes.len().min(available);
        outgoing.extend_from_slice(&bytes[..written]);
        if written != 0 {
            self.notify_ready_key(
                socketpair_ready_key(pair_id, peer_endpoint(endpoint)),
                "socketpair read readiness",
            );
        }
        Ok(written)
    }

    pub(crate) fn socketpair_poll_revents(&self, fd: u32, events: u16) -> Result<u16, i32> {
        let (pair_id, endpoint) = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::SocketPairEnd { pair_id, endpoint } => (*pair_id, *endpoint),
            _ => return Ok(0),
        };
        let pair = self.socketpairs.iter().find(|pair| pair.id == pair_id).ok_or(ERR_EBADF)?;
        let (incoming, outgoing, peer_open) = if endpoint == 0 {
            (&pair.b_to_a, &pair.a_to_b, pair.open_b)
        } else {
            (&pair.a_to_b, &pair.b_to_a, pair.open_a)
        };
        let mut revents = 0u16;
        if !incoming.is_empty() {
            revents |= requested_read_revents(events);
        }
        if !peer_open {
            revents |= POLLHUP;
            if events & POLLRDHUP != 0 {
                revents |= POLLRDHUP;
            }
        }
        if peer_open && outgoing.len() < pair.capacity {
            revents |= requested_write_revents(events);
        }
        Ok(revents)
    }

    pub(crate) fn simulate_socketpair_peer_activity(&mut self) {
        let mut ready = Vec::new();
        for pair in &mut self.socketpairs {
            if pair.open_a && pair.open_b && pair.b_to_a.len() < pair.capacity {
                pair.b_to_a.push(b'w');
                ready.push(socketpair_ready_key(pair.id, 0));
            }
        }
        for ready_key in ready {
            self.notify_ready_key(ready_key, "socketpair fake child write");
        }
    }

    pub(super) fn socketpair_ready_key_matches_events(
        &mut self,
        ready_key: u64,
        events: u32,
    ) -> bool {
        if ready_key & READY_TAG_MASK != SOCKETPAIR_READY_TAG {
            return false;
        }
        let pair_id = (ready_key & 0x0fff_ffff_ffff_fffe) >> 1;
        let endpoint = (ready_key & 1) as u8;
        self.socketpairs.iter().find(|pair| pair.id == pair_id).is_some_and(|pair| {
            let (incoming, outgoing, peer_open) = if endpoint == 0 {
                (&pair.b_to_a, &pair.a_to_b, pair.open_b)
            } else {
                (&pair.a_to_b, &pair.b_to_a, pair.open_a)
            };
            (events & EPOLLIN != 0 && !incoming.is_empty())
                || (events & EPOLLOUT != 0 && peer_open && outgoing.len() < pair.capacity)
                || (events & EPOLLRDHUP != 0 && !peer_open)
        })
    }

    fn socketpair_mut(&mut self, pair_id: u64) -> Result<&mut SocketPairState, i32> {
        self.socketpairs.iter_mut().find(|pair| pair.id == pair_id).ok_or(ERR_EBADF)
    }

    pub(crate) fn read_eventfd_value(&mut self, fd: u32, count: usize) -> Result<Vec<u8>, i32> {
        if count < 8 {
            return Err(ERR_EINVAL);
        }
        let eventfd_id = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::EventFd { eventfd_id } => *eventfd_id,
            _ => return Err(ERR_EBADF),
        };
        let (value, notify_writable) = {
            let eventfd = self.eventfd_mut(eventfd_id)?;
            if eventfd.counter == 0 {
                return Err(ERR_EAGAIN);
            }
            let value = if eventfd.semaphore { 1 } else { eventfd.counter };
            eventfd.counter = eventfd.counter.saturating_sub(value);
            (value, eventfd.counter < EVENTFD_MAX_COUNTER)
        };
        if notify_writable {
            self.notify_ready_key(eventfd_ready_key(eventfd_id), "eventfd write readiness");
        }
        Ok(value.to_le_bytes().to_vec())
    }

    pub(crate) fn write_eventfd_value(
        &mut self,
        fd: u32,
        value: u64,
        count: usize,
    ) -> Result<usize, i32> {
        if count < 8 || value == u64::MAX {
            return Err(ERR_EINVAL);
        }
        let eventfd_id = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::EventFd { eventfd_id } => *eventfd_id,
            _ => return Err(ERR_EBADF),
        };
        let notify_readable = {
            let eventfd = self.eventfd_mut(eventfd_id)?;
            if EVENTFD_MAX_COUNTER.saturating_sub(eventfd.counter) < value {
                return Err(ERR_EAGAIN);
            }
            eventfd.counter = eventfd.counter.saturating_add(value);
            value != 0
        };
        if notify_readable {
            self.notify_ready_key(eventfd_ready_key(eventfd_id), "eventfd read readiness");
        }
        Ok(8)
    }

    pub(crate) fn simulate_eventfd_child_activity(&mut self) {
        const FAKE_CHILD_EVENTFD_VALUE: u64 = 0xdead_beef;

        let mut ready = Vec::new();
        for eventfd in &mut self.eventfds {
            if EVENTFD_MAX_COUNTER.saturating_sub(eventfd.counter) >= FAKE_CHILD_EVENTFD_VALUE {
                eventfd.counter = eventfd.counter.saturating_add(FAKE_CHILD_EVENTFD_VALUE);
                ready.push(eventfd_ready_key(eventfd.id));
            }
        }
        for ready_key in ready {
            self.notify_ready_key(ready_key, "eventfd fake child write");
        }
    }

    pub(crate) fn fd_poll_revents(&mut self, fd: u32, events: u16) -> Result<u16, i32> {
        let Some(entry) = self.fd_entry(fd) else {
            return Err(ERR_EBADF);
        };
        match entry.resource {
            FdResource::ServiceNode { .. } => {
                Ok(service_node_poll_revents(entry.status_flags, events))
            }
            FdResource::PipeEnd { .. } => self.pipe_poll_revents(fd, events),
            FdResource::SocketPairEnd { .. } => self.socketpair_poll_revents(fd, events),
            FdResource::Socket { .. } => self.socket_poll_revents(fd, events),
            FdResource::EventFd { .. } => self.eventfd_poll_revents(fd, events),
            _ => Ok(0),
        }
    }

    pub(crate) fn fdset_wait_is_ready(
        &mut self,
        read_bits: [u64; 16],
        write_bits: [u64; 16],
        error_bits: [u64; 16],
        nfds: u16,
    ) -> bool {
        for fd in 0..nfds as usize {
            let word = fd / 64;
            let mask = 1u64 << (fd % 64);
            if read_bits[word] & mask != 0
                && self
                    .fd_poll_revents(fd as u32, POLLIN)
                    .is_ok_and(|events| events & (POLLIN | POLLHUP | POLLERR) != 0)
            {
                return true;
            }
            if write_bits[word] & mask != 0
                && self
                    .fd_poll_revents(fd as u32, POLLOUT)
                    .is_ok_and(|events| events & (POLLOUT | POLLHUP | POLLERR) != 0)
            {
                return true;
            }
            if error_bits[word] & mask != 0
                && self
                    .fd_poll_revents(fd as u32, 0)
                    .is_ok_and(|events| events & (POLLHUP | POLLERR) != 0)
            {
                return true;
            }
        }
        false
    }

    pub(crate) fn block_on_fdset_wait(
        &mut self,
        read_bits: [u64; 16],
        write_bits: [u64; 16],
        error_bits: [u64; 16],
        nfds: u16,
        timeout_ms: Option<u32>,
    ) -> Result<(), i32> {
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::FdSet { read_bits, write_bits, error_bits, nfds, timeout_ms },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        match self.block_on_wait("ring3_pselect6", token).map_err(|_| ERR_EINVAL)? {
            LinuxCallResult::Ret(ret) if ret < 0 => Err((-ret) as i32),
            LinuxCallResult::Ret(_) => Ok(()),
            _ => Err(ERR_EINVAL),
        }
    }

    fn socket_poll_revents(&mut self, fd: u32, events: u16) -> Result<u16, i32> {
        let (socket_id, ready_key, handle) =
            self.socket_fd_snapshot(fd).map_err(errno_from_service_error)?;
        let mut revents = 0u16;
        if self.socket_ready_key_is_readable(ready_key) {
            revents |= requested_read_revents(events);
        }
        if events & POLLRDHUP != 0
            && self.net_stack_socket_read_half_closed(socket_id, ready_key, handle).unwrap_or(false)
        {
            revents |= POLLRDHUP;
        }
        if events & POLL_WRITE_EVENTS != 0 {
            let writable = if let Some(writable) =
                self.net_stack_socket_writable(socket_id, ready_key, handle)
            {
                writable
            } else {
                self.net_core.poll_socket(socket_id).map_err(errno_from_service_error)? & EPOLLOUT
                    != 0
            };
            if writable {
                revents |= requested_write_revents(events);
            }
        }
        Ok(revents)
    }

    pub(crate) fn eventfd_poll_revents(&self, fd: u32, events: u16) -> Result<u16, i32> {
        let eventfd_id = match &self.fd_entry(fd).ok_or(ERR_EBADF)?.resource {
            FdResource::EventFd { eventfd_id } => *eventfd_id,
            _ => return Ok(0),
        };
        let eventfd =
            self.eventfds.iter().find(|eventfd| eventfd.id == eventfd_id).ok_or(ERR_EBADF)?;
        let mut revents = 0u16;
        if eventfd.counter > 0 {
            revents |= requested_read_revents(events);
        }
        if eventfd.counter < EVENTFD_MAX_COUNTER {
            revents |= requested_write_revents(events);
        }
        Ok(revents)
    }

    pub(super) fn eventfd_ready_key_matches_events(&mut self, ready_key: u64, events: u32) -> bool {
        if ready_key & READY_TAG_MASK != EVENTFD_READY_TAG {
            return false;
        }
        let eventfd_id = ready_key & !READY_TAG_MASK;
        self.eventfds.iter().find(|eventfd| eventfd.id == eventfd_id).is_some_and(|eventfd| {
            (events & EPOLLIN != 0 && eventfd.counter > 0)
                || (events & EPOLLOUT != 0 && eventfd.counter < EVENTFD_MAX_COUNTER)
        })
    }

    fn eventfd_mut(&mut self, eventfd_id: u64) -> Result<&mut EventFdState, i32> {
        self.eventfds.iter_mut().find(|eventfd| eventfd.id == eventfd_id).ok_or(ERR_EBADF)
    }

    fn dup_source_entry(&mut self, fd: u32) -> Result<FdEntry, i32> {
        if fd < 3 {
            return Ok(FdEntry {
                resource: FdResource::ServiceNode {
                    route: ServiceRoute::Devfs,
                    node: NodeKind::CharDevice,
                    path: b"/dev/null".to_vec(),
                    vfs_node_id: None,
                },
                cursor: 0,
                fd_flags: 0,
                status_flags: 0,
                cursor_group: None,
            });
        }
        self.validate_fd_handle(fd).map_err(errno_from_service_error)?;
        let mut entry = self.fd_entry(fd).cloned().ok_or(ERR_EBADF)?;
        entry.fd_flags = 0;
        Ok(entry)
    }

    fn close_fd_if_present(&mut self, fd: u32) -> Result<(), i32> {
        if self.fd_table.get(fd as usize).and_then(Option::as_ref).is_none() {
            return Ok(());
        }
        self.close_fd_slot(fd, true)
    }

    fn close_fd_slot(&mut self, fd: u32, validate_handle: bool) -> Result<(), i32> {
        let Some(handle) = self.fd_handle(fd) else {
            return Err(ERR_EBADF);
        };
        if validate_handle && self.validate_resource_handle(handle).is_err() {
            return Err(ERR_EBADF);
        }

        let closing_socket = self.fd_entry(fd).and_then(|entry| match &entry.resource {
            FdResource::Socket { socket_id, .. } => Some(*socket_id as u32),
            _ => None,
        });
        let closing_socket_last_ref = closing_socket
            .map(|socket_id| !self.has_other_socket_fd_ref(fd, socket_id))
            .unwrap_or(false);
        let closing_pipe = self.fd_entry(fd).and_then(|entry| match &entry.resource {
            FdResource::PipeEnd { pipe_id, readable, writable } => {
                Some((*pipe_id, *readable, *writable))
            }
            _ => None,
        });
        let closing_socketpair = self.fd_entry(fd).and_then(|entry| match &entry.resource {
            FdResource::SocketPairEnd { pair_id, endpoint } => Some((*pair_id, *endpoint)),
            _ => None,
        });
        let closing_vfs_file = self.fd_entry(fd).and_then(|entry| match &entry.resource {
            FdResource::ServiceNode {
                route: ServiceRoute::Vfs,
                node: NodeKind::File,
                path,
                vfs_node_id,
            } => Some((*vfs_node_id, path.clone())),
            _ => None,
        });
        if let Some(socket_id) = closing_socket
            && closing_socket_last_ref
        {
            if self.require_capability("linux_syscall", "linux.socket", "close").is_err()
                || self.require_capability("net_core", "net.socket", "close").is_err()
            {
                return Err(ERR_EPERM);
            }
            match self.linux_socket.close_socket(socket_id) {
                Ok(()) | Err(ServiceCallError::Errno(ERR_EBADF)) => {}
                Err(ServiceCallError::Errno(errno)) => return Err(errno),
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("linux_socket close: {}", reason);
                    return Err(ERR_EINVAL);
                }
                Err(ServiceCallError::Invalid(err)) => {
                    crate::kwarn!("linux_socket close: {}", err);
                    return Err(ERR_EINVAL);
                }
            }
            self.close_net_stack_socket(socket_id);
            match self.net_core.close_socket(socket_id) {
                Ok(()) | Err(ServiceCallError::Errno(ERR_EBADF)) => {}
                Err(ServiceCallError::Errno(errno)) => return Err(errno),
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("net_core close: {}", reason);
                    return Err(ERR_EINVAL);
                }
                Err(ServiceCallError::Invalid(err)) => {
                    crate::kwarn!("net_core close: {}", err);
                    return Err(ERR_EINVAL);
                }
            }
        }

        let slot = self.fd_table.get_mut(fd as usize).ok_or(ERR_EBADF)?;
        if slot.take().is_none() {
            return Err(ERR_EBADF);
        }
        let owner = self.current_pid();
        if let Some((vfs_node_id, path)) = closing_vfs_file
            && self.vfs.fcntl_unlock_owner_file(vfs_node_id, &path, owner)
        {
            self.wake_ready_file_lock_waits();
        }
        if let Some(slot) = self.fd_handles.get_mut(fd as usize)
            && let Some(handle) = slot.take()
        {
            if closing_socket_last_ref {
                self.semantic.record_socket_state_changed(handle.id, "closed");
            }
            self.semantic.close_resource(handle.id);
        }
        if let Some((pipe_id, readable, writable)) = closing_pipe {
            let other_read_open = self.has_pipe_read_fd_ref(pipe_id);
            let other_write_open = self.has_pipe_write_fd_ref(pipe_id);
            let pipe = self.pipe_mut(pipe_id)?;
            if readable {
                pipe.read_open = other_read_open;
            }
            if writable {
                pipe.write_open = other_write_open;
            }
        }
        if let Some((pair_id, endpoint)) = closing_socketpair {
            let same_endpoint_open = self.has_socketpair_endpoint_fd_ref(pair_id, endpoint);
            let pair = self.socketpair_mut(pair_id)?;
            if endpoint == 0 {
                pair.open_a = same_endpoint_open;
            } else {
                pair.open_b = same_endpoint_open;
            }
            self.notify_ready_key(
                socketpair_ready_key(pair_id, peer_endpoint(endpoint)),
                "socketpair peer close",
            );
        }
        Ok(())
    }

    fn has_other_socket_fd_ref(&self, closing_fd: u32, socket_id: u32) -> bool {
        let active_ref = self.fd_table.iter().enumerate().any(|(fd, entry)| {
            fd != closing_fd as usize
                && matches!(
                    entry.as_ref().map(|entry| &entry.resource),
                    Some(FdResource::Socket { socket_id: other, .. }) if *other as u32 == socket_id
                )
        });
        active_ref
            || self.hidden_fd_table_refs.iter().any(|table| {
                table.iter().filter_map(Option::as_ref).any(|entry| {
                    matches!(
                        entry.resource,
                        FdResource::Socket { socket_id: other, .. } if other as u32 == socket_id
                    )
                })
            })
    }

    fn has_pipe_read_fd_ref(&self, pipe_id: u64) -> bool {
        self.fd_table.iter().filter_map(Option::as_ref).any(|entry| {
            matches!(
                entry.resource,
                FdResource::PipeEnd { pipe_id: id, readable: true, .. } if id == pipe_id
            )
        }) || self.hidden_fd_table_refs.iter().any(|table| {
            table.iter().filter_map(Option::as_ref).any(|entry| {
                matches!(
                    entry.resource,
                    FdResource::PipeEnd { pipe_id: id, readable: true, .. } if id == pipe_id
                )
            })
        })
    }

    fn has_pipe_write_fd_ref(&self, pipe_id: u64) -> bool {
        self.fd_table.iter().filter_map(Option::as_ref).any(|entry| {
            matches!(
                entry.resource,
                FdResource::PipeEnd { pipe_id: id, writable: true, .. } if id == pipe_id
            )
        }) || self.hidden_fd_table_refs.iter().any(|table| {
            table.iter().filter_map(Option::as_ref).any(|entry| {
                matches!(
                    entry.resource,
                    FdResource::PipeEnd { pipe_id: id, writable: true, .. } if id == pipe_id
                )
            })
        })
    }

    fn has_socketpair_endpoint_fd_ref(&self, pair_id: u64, endpoint: u8) -> bool {
        self.fd_table.iter().filter_map(Option::as_ref).any(|entry| {
            matches!(
                entry.resource,
                FdResource::SocketPairEnd { pair_id: id, endpoint: ep }
                    if id == pair_id && ep == endpoint
            )
        }) || self.hidden_fd_table_refs.iter().any(|table| {
            table.iter().filter_map(Option::as_ref).any(|entry| {
                matches!(
                    entry.resource,
                    FdResource::SocketPairEnd { pair_id: id, endpoint: ep }
                        if id == pair_id && ep == endpoint
                )
            })
        })
    }

    pub(crate) fn fd_flags(&self, fd: u32) -> Result<u32, i32> {
        if fd < 3 {
            return Ok(0);
        }
        self.fd_entry(fd).map(|entry| entry.fd_flags).ok_or(ERR_EBADF)
    }

    pub(crate) fn set_fd_flags(&mut self, fd: u32, flags: u32) -> Result<(), i32> {
        if fd < 3 {
            return Ok(());
        }
        self.validate_fd_handle(fd).map_err(errno_from_service_error)?;
        let entry = self.fd_table.get_mut(fd as usize).and_then(Option::as_mut).ok_or(ERR_EBADF)?;
        entry.fd_flags = flags;
        Ok(())
    }

    pub(crate) fn file_status_flags(&self, fd: u32) -> Result<u32, i32> {
        if fd < 3 {
            return Ok(0);
        }
        self.fd_entry(fd).map(|entry| entry.status_flags).ok_or(ERR_EBADF)
    }

    pub(crate) fn set_file_status_flags(&mut self, fd: u32, flags: u32) -> Result<(), i32> {
        const O_ACCMODE: u32 = 0o3;
        const O_APPEND: u32 = 0o2000;
        const O_NONBLOCK: u32 = 0o4000;

        if fd < 3 {
            return Ok(());
        }
        self.validate_fd_handle(fd).map_err(errno_from_service_error)?;
        let entry = self.fd_table.get_mut(fd as usize).and_then(Option::as_mut).ok_or(ERR_EBADF)?;
        entry.status_flags = (entry.status_flags & O_ACCMODE) | (flags & (O_APPEND | O_NONBLOCK));
        Ok(())
    }

    fn socket_for_ready_key(&self, ready_key: u64) -> Option<(u32, ResourceHandle)> {
        for (fd, entry) in self.fd_table.iter().enumerate() {
            let Some(entry) = entry else {
                continue;
            };
            let FdResource::Socket { socket_id, ready_key: socket_key } = &entry.resource else {
                continue;
            };
            if *socket_key == ready_key {
                let handle = self.fd_handle(fd as u32)?;
                return Some((*socket_id as u32, handle));
            }
        }
        None
    }

    pub(super) fn socket_resource_for_ready_key(&self, ready_key: u64) -> Option<ResourceHandle> {
        self.socket_for_ready_key(ready_key).map(|(_, handle)| handle)
    }

    pub(super) fn socket_fd_snapshot(
        &mut self,
        fd: u32,
    ) -> Result<(u32, u64, ResourceHandle), ServiceCallError> {
        self.validate_fd_handle(fd)?;
        let entry = self.fd_entry(fd).ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        let FdResource::Socket { socket_id, ready_key } = &entry.resource else {
            return Err(ServiceCallError::Errno(ERR_ENOTSOCK));
        };
        let handle = self.fd_handle(fd).ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        Ok((*socket_id as u32, *ready_key, handle))
    }

    pub(super) fn socket_ready_key_is_readable(&mut self, ready_key: u64) -> bool {
        let Some((socket_id, handle)) = self.socket_for_ready_key(ready_key) else {
            return false;
        };
        if self
            .net_stack_socket_accept_ready(socket_id, ready_key, handle)
            .is_some_and(|ready| ready)
        {
            return true;
        }
        if self.linux_socket.pending_accept_count(socket_id).is_ok_and(|pending| pending > 0) {
            return true;
        }
        if let Some(readable) = self.net_stack_socket_readable(socket_id, ready_key, handle) {
            return readable;
        }
        self.net_core.poll_socket(socket_id).map(|events| events & EPOLLIN != 0).unwrap_or(false)
    }

    pub(super) fn socket_ready_key_matches_events(&mut self, ready_key: u64, events: u32) -> bool {
        let Some((socket_id, handle)) = self.socket_for_ready_key(ready_key) else {
            return false;
        };
        let readable = events & EPOLLIN != 0 && self.socket_ready_key_is_readable(ready_key);
        let writable = events & EPOLLOUT != 0 && {
            if let Some(writable) = self.net_stack_socket_writable(socket_id, ready_key, handle) {
                writable
            } else {
                self.net_core
                    .poll_socket(socket_id)
                    .map(|events| events & EPOLLOUT != 0)
                    .unwrap_or(false)
            }
        };
        let read_half_closed = events & EPOLLRDHUP != 0
            && self
                .net_stack_socket_read_half_closed(socket_id, ready_key, handle)
                .unwrap_or(false);
        readable || writable || read_half_closed
    }

    pub(super) fn socket_accept_fd_is_ready(&mut self, fd: u32) -> bool {
        let Ok((socket_id, ready_key, handle)) = self.socket_fd_snapshot(fd) else {
            return false;
        };
        if self
            .net_stack_socket_accept_ready(socket_id, ready_key, handle)
            .is_some_and(|ready| ready)
        {
            return true;
        }
        self.linux_socket.pending_accept_count(socket_id).is_ok_and(|pending| pending > 0)
    }

    pub(super) fn socket_connect_fd_is_ready(&mut self, fd: u32) -> bool {
        let Ok((socket_id, ready_key, handle)) = self.socket_fd_snapshot(fd) else {
            return false;
        };
        self.net_stack_socket_connected(socket_id, ready_key, handle).unwrap_or(false)
    }

    pub(super) fn notify_ready_key(&mut self, ready_key: u64, context: &str) {
        match self.epoll.notify_ready(ready_key) {
            Ok(wait_ids) => {
                for wait_id in wait_ids {
                    self.scheduler.push_event(Event::WaitReady(wait_id));
                }
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("{}: {}", context, reason);
            }
            Err(ServiceCallError::Invalid(err)) => {
                crate::kwarn!("{}: {}", context, err);
            }
            Err(ServiceCallError::Errno(errno)) => {
                crate::kwarn!("{} errno={}", context, errno);
            }
        }
    }

    pub(super) fn validate_fd_handle(&mut self, fd: u32) -> Result<(), ServiceCallError> {
        let handle = self.fd_handle(fd).ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        self.validate_resource_handle(handle).map_err(|_| ServiceCallError::Errno(ERR_EBADF))
    }

    pub(crate) fn mkdir_path(
        &mut self,
        path: &[u8],
        mode: u32,
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.check_parent_access(path, MAY_WRITE | MAY_EXEC, access)?;
        self.vfs.mkdir(path, mode, access.uid, access.gid).map_err(errno_from_service_error)
    }

    pub(crate) fn unlink_path(&mut self, path: &[u8], access: AccessIds<'_>) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.check_parent_access(path, MAY_WRITE | MAY_EXEC, access)?;
        self.check_sticky_removal_access(path, access)?;
        self.vfs.unlink(path).map_err(errno_from_service_error)
    }

    pub(crate) fn rmdir_path(&mut self, path: &[u8], access: AccessIds<'_>) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.check_parent_access(path, MAY_WRITE | MAY_EXEC, access)?;
        self.check_sticky_removal_access(path, access)?;
        self.vfs.rmdir(path).map_err(errno_from_service_error)
    }

    pub(crate) fn rename_path(
        &mut self,
        old_path: &[u8],
        new_path: &[u8],
        flags: u32,
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.check_parent_access(old_path, MAY_WRITE | MAY_EXEC, access)?;
        self.check_parent_access(new_path, MAY_WRITE | MAY_EXEC, access)?;
        self.check_sticky_removal_access(old_path, access)?;
        if self.lookup_path(new_path).is_ok() {
            self.check_sticky_removal_access(new_path, access)?;
        }
        self.vfs.rename(old_path, new_path, flags).map_err(errno_from_service_error)
    }

    pub(crate) fn chmod_path(
        &mut self,
        path: &[u8],
        mode: u32,
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.check_path_access(path, 0, access)?;
        let (owner_uid, _) = self.path_owner(path)?;
        if access.uid != owner_uid && !access.has_capability(CAP_FOWNER) {
            return Err(ERR_EPERM);
        }
        self.vfs.chmod(path, mode).map_err(errno_from_service_error)
    }

    pub(crate) fn chown_path(
        &mut self,
        path: &[u8],
        uid: Option<u32>,
        gid: Option<u32>,
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.check_path_access(path, 0, access)?;
        if (uid.is_some() || gid.is_some()) && !access.has_capability(CAP_CHOWN) {
            return Err(ERR_EPERM);
        }
        self.vfs.chown(path, uid, gid).map_err(errno_from_service_error)
    }

    pub(crate) fn symlink_path(
        &mut self,
        path: &[u8],
        target: &[u8],
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.check_parent_access(path, MAY_WRITE | MAY_EXEC, access)?;
        self.vfs.symlink(path, target).map_err(errno_from_service_error)
    }

    pub(crate) fn truncate_path(
        &mut self,
        path: &[u8],
        len: usize,
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "write").map_err(|_| ERR_EPERM)?;
        self.check_path_access(path, MAY_WRITE, access)?;
        self.vfs.truncate_file(path, len).map_err(errno_from_service_error)
    }

    pub(crate) fn stat_fd_abi(&mut self, fd: u32) -> Result<Vec<u8>, i32> {
        self.validate_fd_handle(fd).map_err(|_| ERR_EBADF)?;
        let entry = self.fd_entry(fd).ok_or(ERR_EBADF)?;
        if matches!(
            entry.resource,
            FdResource::PipeEnd { .. }
                | FdResource::SocketPairEnd { .. }
                | FdResource::EventFd { .. }
        ) {
            return Ok(encode_stat_abi(0o010666, 0, 0, 0));
        }
        let FdResource::ServiceNode { route, node, path, .. } = &entry.resource else {
            return Err(ERR_EBADF);
        };
        let mode = self.mode_for_service_node(*route, *node, path);
        let (uid, gid) = self.owner_for_service_node(*route, path);
        let len = self.len_for_service_node(*route, path);
        Ok(encode_stat_abi(mode, len, uid, gid))
    }

    pub(crate) fn stat_path_abi(&mut self, path: &[u8]) -> Result<Vec<u8>, i32> {
        let info = self.lookup_path(path).map_err(errno_from_service_error)?;
        let mode = self.mode_for_service_node(info.route, info.node, path);
        let (uid, gid) = self.owner_for_service_node(info.route, path);
        let len = self.len_for_service_node(info.route, path);
        Ok(encode_stat_abi(mode, len, uid, gid))
    }

    pub(crate) fn path_metadata(&mut self, path: &[u8]) -> Result<(NodeKind, u32, u64), i32> {
        let info = self.lookup_path(path).map_err(errno_from_service_error)?;
        let mode = self.mode_for_service_node(info.route, info.node, path);
        let len = self.len_for_service_node(info.route, path);
        Ok((info.node, mode, len))
    }

    pub(crate) fn read_vfs_file_path(
        &mut self,
        path: &[u8],
        access: AccessIds<'_>,
    ) -> Result<Vec<u8>, i32> {
        self.check_path_access(path, MAY_EXEC, access)?;
        self.vfs.read_file(path, false).map_err(errno_from_service_error)
    }

    fn path_owner(&mut self, path: &[u8]) -> Result<(u32, u32), i32> {
        let info = self.lookup_path(path).map_err(errno_from_service_error)?;
        Ok(self.owner_for_service_node(info.route, path))
    }

    fn check_sticky_removal_access(
        &mut self,
        path: &[u8],
        access: AccessIds<'_>,
    ) -> Result<(), i32> {
        let Some(parent) = parent_path_for_access(path) else {
            return Err(ERR_EPERM);
        };
        let parent_info = self.lookup_path(&parent).map_err(errno_from_service_error)?;
        let parent_mode = self.mode_for_service_node(parent_info.route, parent_info.node, &parent);
        if parent_mode & 0o1000 == 0 || access.has_capability(CAP_FOWNER) {
            return Ok(());
        }
        let (parent_uid, _) = self.owner_for_service_node(parent_info.route, &parent);
        let (target_uid, _) = self.path_owner(path)?;
        if access.uid == parent_uid || access.uid == target_uid { Ok(()) } else { Err(ERR_EPERM) }
    }

    fn mode_for_service_node(&self, route: ServiceRoute, node: NodeKind, path: &[u8]) -> u32 {
        match route {
            ServiceRoute::Vfs => self.vfs.mode_for_path(path, node),
            ServiceRoute::Procfs => match node {
                NodeKind::Directory => 0o040555,
                NodeKind::File => 0o100444,
                NodeKind::Symlink => 0o120777,
                NodeKind::CharDevice => 0o020666,
            },
            ServiceRoute::Devfs => devfs_mode_for_path(path),
        }
    }

    fn owner_for_service_node(&self, route: ServiceRoute, path: &[u8]) -> (u32, u32) {
        match route {
            ServiceRoute::Vfs => self.vfs.owner_for_path(path),
            ServiceRoute::Procfs | ServiceRoute::Devfs => (0, 0),
        }
    }

    fn len_for_service_node(&self, route: ServiceRoute, path: &[u8]) -> u64 {
        match route {
            ServiceRoute::Vfs => self.vfs.len_for_path(path),
            ServiceRoute::Procfs | ServiceRoute::Devfs => 0,
        }
    }

    fn service_fd_snapshot(
        &mut self,
        fd: u32,
    ) -> Result<(ServiceRoute, NodeKind, usize, Vec<u8>), ServiceCallError> {
        self.validate_fd_handle(fd)?;
        let entry = self.fd_entry(fd).ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        match &entry.resource {
            FdResource::ServiceNode { route, node, path, .. } => {
                Ok((*route, *node, entry.cursor, path.clone()))
            }
            FdResource::EpollInstance { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
            FdResource::Socket { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
            FdResource::PipeEnd { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
            FdResource::SocketPairEnd { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
            FdResource::EventFd { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
        }
    }

    fn service_fd_lock_snapshot(
        &mut self,
        fd: u32,
    ) -> Result<(ServiceRoute, NodeKind, usize, Vec<u8>, Option<u64>), ServiceCallError> {
        self.validate_fd_handle(fd)?;
        let entry = self.fd_entry(fd).ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        match &entry.resource {
            FdResource::ServiceNode { route, node, path, vfs_node_id } => {
                Ok((*route, *node, entry.cursor, path.clone(), *vfs_node_id))
            }
            FdResource::EpollInstance { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
            FdResource::Socket { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
            FdResource::PipeEnd { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
            FdResource::SocketPairEnd { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
            FdResource::EventFd { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
        }
    }

    pub(super) fn set_fd_cursor(&mut self, fd: u32, cursor: usize) -> Result<(), ServiceCallError> {
        let cursor_group = self
            .fd_table
            .get(fd as usize)
            .and_then(Option::as_ref)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?
            .cursor_group;
        if let Some(group) = cursor_group {
            for entry in self.fd_table.iter_mut().filter_map(Option::as_mut) {
                if entry.cursor_group == Some(group) {
                    entry.cursor = cursor;
                }
            }
        } else {
            let entry = self
                .fd_table
                .get_mut(fd as usize)
                .and_then(Option::as_mut)
                .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
            entry.cursor = cursor;
        }
        Ok(())
    }

    pub(super) fn epoll_id_from_fd(&mut self, fd: u32) -> Result<u32, ServiceCallError> {
        self.validate_fd_handle(fd)?;
        match self.fd_entry(fd) {
            Some(FdEntry { resource: FdResource::EpollInstance { epoll_id }, .. }) => Ok(*epoll_id),
            _ => Err(ServiceCallError::Errno(ERR_EBADF)),
        }
    }

    pub(super) fn fd_ready_key(&mut self, fd: u32) -> Result<u64, ServiceCallError> {
        self.validate_fd_handle(fd)?;
        let entry = self.fd_entry(fd).ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        match &entry.resource {
            FdResource::ServiceNode { route: ServiceRoute::Devfs, path, .. } => {
                PulseDevice::ready_key_for_path(path).ok_or(ServiceCallError::Errno(ERR_EINVAL))
            }
            FdResource::Socket { ready_key, .. } => Ok(*ready_key),
            FdResource::PipeEnd { pipe_id, readable, writable } => {
                Ok(pipe_ready_key(*pipe_id, *readable, *writable))
            }
            FdResource::SocketPairEnd { pair_id, endpoint } => {
                Ok(socketpair_ready_key(*pair_id, *endpoint))
            }
            FdResource::EventFd { eventfd_id } => Ok(eventfd_ready_key(*eventfd_id)),
            FdResource::EpollInstance { epoll_id } => Ok(epoll_ready_key(*epoll_id)),
            _ => Err(ServiceCallError::Errno(ERR_EPERM)),
        }
    }

    fn procfs_mut(&mut self) -> &mut ProcfsService {
        self.procfs.as_mut().expect("procfs service should always be installed outside recovery")
    }
}

fn pipe_ready_key(pipe_id: u64, readable: bool, writable: bool) -> u64 {
    let direction = u64::from(writable && !readable);
    PIPE_READY_TAG | (pipe_id << 1) | direction
}

fn epoll_ready_key(epoll_id: u32) -> u64 {
    EPOLL_READY_TAG | epoll_id as u64
}

fn socketpair_ready_key(pair_id: u64, endpoint: u8) -> u64 {
    SOCKETPAIR_READY_TAG | (pair_id << 1) | u64::from(endpoint & 1)
}

fn service_node_poll_revents(status_flags: u32, events: u16) -> u16 {
    let mut revents = 0u16;
    if status_flags & O_ACCMODE != O_WRONLY {
        revents |= requested_read_revents(events);
    }
    if matches!(status_flags & O_ACCMODE, O_WRONLY | O_RDWR) {
        revents |= requested_write_revents(events);
    }
    revents
}

fn requested_read_revents(events: u16) -> u16 {
    events & POLL_READ_EVENTS
}

fn requested_write_revents(events: u16) -> u16 {
    events & POLL_WRITE_EVENTS
}

fn eventfd_ready_key(eventfd_id: u64) -> u64 {
    EVENTFD_READY_TAG | eventfd_id
}

fn peer_endpoint(endpoint: u8) -> u8 {
    if endpoint == 0 { 1 } else { 0 }
}

fn join_path(base: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = Vec::with_capacity(base.len() + name.len() + 1);
    path.extend_from_slice(base);
    if !base.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

fn parent_path_for_access(path: &[u8]) -> Option<Vec<u8>> {
    if path == b"/" {
        return None;
    }
    let trimmed =
        if path.len() > 1 && path.ends_with(b"/") { &path[..path.len() - 1] } else { path };
    let slash = trimmed.iter().rposition(|byte| *byte == b'/')?;
    if slash == 0 { Some(b"/".to_vec()) } else { Some(trimmed[..slash].to_vec()) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XattrAccess {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XattrNamespace {
    User,
    Privileged,
}

fn classify_xattr_namespace(name: &[u8]) -> Result<XattrNamespace, i32> {
    const XATTR_NAME_MAX: usize = 255;

    if name.is_empty() || name.len() > XATTR_NAME_MAX || name.contains(&0) || !name.contains(&b'.')
    {
        return Err(ERR_EINVAL);
    }
    if name.starts_with(b"user.") {
        return Ok(XattrNamespace::User);
    }
    if name.starts_with(b"trusted.")
        || name.starts_with(b"security.")
        || name.starts_with(b"system.")
    {
        return Ok(XattrNamespace::Privileged);
    }
    Err(vmos_abi::ERR_EOPNOTSUPP)
}

fn mode_grants_access(
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    access: AccessIds<'_>,
    mask: u32,
) -> bool {
    if mask == 0 {
        return true;
    }
    let is_directory = mode & 0o170000 == 0o040000;
    if access.has_capability(CAP_DAC_OVERRIDE) {
        return mask & MAY_EXEC == 0 || mode & 0o111 != 0;
    }
    if access.has_capability(CAP_DAC_READ_SEARCH)
        && mask & MAY_WRITE == 0
        && (mask & MAY_EXEC == 0 || is_directory)
    {
        return true;
    }
    let shift = if access.uid == owner_uid {
        6
    } else if access.gid == owner_gid || access.supplementary_groups.contains(&owner_gid) {
        3
    } else {
        0
    };
    let granted = (mode >> shift) & 0o7;
    (mask & MAY_READ == 0 || granted & 0o4 != 0)
        && (mask & MAY_WRITE == 0 || granted & 0o2 != 0)
        && (mask & MAY_EXEC == 0 || granted & 0o1 != 0)
}

fn errno_from_service_error(err: ServiceCallError) -> i32 {
    match err {
        ServiceCallError::Errno(errno) => errno,
        ServiceCallError::Trap(_) | ServiceCallError::Invalid(_) => ERR_EINVAL,
    }
}

fn encode_stat_abi(mode: u32, size: u64, uid: u32, gid: u32) -> Vec<u8> {
    let mut out = alloc::vec![0u8; 144];
    write_u64(&mut out, 0, 1);
    write_u64(&mut out, 8, 1);
    write_u64(&mut out, 16, 1);
    write_u32(&mut out, 24, mode);
    write_u32(&mut out, 28, uid);
    write_u32(&mut out, 32, gid);
    write_u64(&mut out, 48, size);
    write_u64(&mut out, 56, 4096);
    write_u64(&mut out, 64, size.div_ceil(512));
    out
}

fn devfs_mode_for_path(path: &[u8]) -> u32 {
    if path == b"/dev/loop0" { 0o060660 } else { 0o020666 }
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
