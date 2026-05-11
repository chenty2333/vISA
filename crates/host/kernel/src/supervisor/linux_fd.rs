use alloc::vec::Vec;

use semantic_core::ResourceHandle;
use vmos_abi::{
    EPOLLIN, ERR_EAGAIN, ERR_EBADF, ERR_EINVAL, ERR_ENOTSOCK, ERR_EPERM, NodeKind, ServiceRoute,
};

use super::{
    events::Event,
    pulse::PulseDevice,
    runtime::PrototypeRuntime,
    semantic::{fd_resource_kind, fd_resource_label},
    services::ProcfsService,
    types::{FdEntry, FdResource, InjectedFault, LookupInfo, ServiceCallError},
};
use crate::interrupts;

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

    pub(super) fn alloc_fd(&mut self, entry: FdEntry) -> u32 {
        let resource_kind = fd_resource_kind(&entry.resource);
        let resource_label = fd_resource_label(&entry.resource);
        let owner_task = Some(self.scheduler.current_task());
        let resource_id =
            self.semantic.register_resource(resource_kind, owner_task, &resource_label);

        if let Some(fd) = (3..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            self.fd_table[fd] = Some(entry);
            self.ensure_fd_handle_slot(fd);
            self.fd_handles[fd] = self.semantic.resource_handle(resource_id);
            return fd as u32;
        }

        self.fd_table.push(Some(entry));
        self.fd_handles.push(self.semantic.resource_handle(resource_id));
        (self.fd_table.len() - 1) as u32
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
        let Some((socket_id, _)) = self.socket_for_ready_key(ready_key) else {
            return false;
        };
        self.net_core.poll_socket(socket_id).map(|events| events & EPOLLIN != 0).unwrap_or(false)
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

    pub(crate) fn mkdir_path(&mut self, path: &[u8], mode: u32) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.vfs.mkdir(path, mode).map_err(errno_from_service_error)
    }

    pub(crate) fn unlink_path(&mut self, path: &[u8]) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.vfs.unlink(path).map_err(errno_from_service_error)
    }

    pub(crate) fn rmdir_path(&mut self, path: &[u8]) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.vfs.rmdir(path).map_err(errno_from_service_error)
    }

    pub(crate) fn chmod_path(&mut self, path: &[u8], mode: u32) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "lookup").map_err(|_| ERR_EPERM)?;
        self.vfs.chmod(path, mode).map_err(errno_from_service_error)
    }

    pub(crate) fn truncate_path(&mut self, path: &[u8], len: usize) -> Result<(), i32> {
        self.require_capability("vfs_service", "vfs.namespace", "write").map_err(|_| ERR_EPERM)?;
        self.vfs.truncate_file(path, len).map_err(errno_from_service_error)
    }

    pub(crate) fn stat_fd_abi(&mut self, fd: u32) -> Result<Vec<u8>, i32> {
        self.validate_fd_handle(fd).map_err(|_| ERR_EBADF)?;
        let entry = self.fd_entry(fd).ok_or(ERR_EBADF)?;
        let FdResource::ServiceNode { route, node, path } = &entry.resource else {
            return Err(ERR_EBADF);
        };
        let mode = self.mode_for_service_node(*route, *node, path);
        let len = self.len_for_service_node(*route, path);
        Ok(encode_stat_abi(mode, len))
    }

    pub(crate) fn stat_path_abi(&mut self, path: &[u8]) -> Result<Vec<u8>, i32> {
        let info = self.lookup_path(path).map_err(errno_from_service_error)?;
        let mode = self.mode_for_service_node(info.route, info.node, path);
        let len = self.len_for_service_node(info.route, path);
        Ok(encode_stat_abi(mode, len))
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
            ServiceRoute::Devfs => 0o020666,
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
            FdResource::ServiceNode { route, node, path } => {
                Ok((*route, *node, entry.cursor, path.clone()))
            }
            FdResource::EpollInstance { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
            FdResource::Socket { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
        }
    }

    pub(super) fn set_fd_cursor(&mut self, fd: u32, cursor: usize) -> Result<(), ServiceCallError> {
        let entry = self
            .fd_table
            .get_mut(fd as usize)
            .and_then(Option::as_mut)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        entry.cursor = cursor;
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
            _ => Err(ServiceCallError::Errno(ERR_EINVAL)),
        }
    }

    fn procfs_mut(&mut self) -> &mut ProcfsService {
        self.procfs.as_mut().expect("procfs service should always be installed outside recovery")
    }
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

fn errno_from_service_error(err: ServiceCallError) -> i32 {
    match err {
        ServiceCallError::Errno(errno) => errno,
        ServiceCallError::Trap(_) | ServiceCallError::Invalid(_) => ERR_EINVAL,
    }
}

fn encode_stat_abi(mode: u32, size: u64) -> Vec<u8> {
    let mut out = alloc::vec![0u8; 144];
    write_u64(&mut out, 0, 1);
    write_u64(&mut out, 8, 1);
    write_u64(&mut out, 16, 1);
    write_u32(&mut out, 24, mode);
    write_u64(&mut out, 48, size);
    write_u64(&mut out, 56, 4096);
    write_u64(&mut out, 64, size.div_ceil(512));
    out
}

fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
