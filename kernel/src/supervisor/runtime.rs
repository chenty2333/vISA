use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::null_mut;

use wasmi::Engine;

use crate::interrupts;
use vmos_abi::{
    ERR_EBADF, ERR_EINVAL, FD_STDOUT, NodeKind, PackedStep, PlanKind, SYS_CLOSE, SYS_GETCWD,
    SYS_GETDENTS64, SYS_NANOSLEEP, SYS_OPENAT, SYS_READ, SYS_READLINKAT, SYS_UNAME, SYS_WRITE,
    ServiceRoute, StepTag, SyscallContext,
};

use super::linux::{LinuxCallResult, LinuxFrontend, LinuxPlan};
use super::services::{ConsoleService, DevfsService, ProcfsService, VfsService, WasmApp};
use super::types::{FdEntry, InjectedFault, LookupInfo, ServiceCallError};

pub(super) const CURRENT_CWD: &[u8] = b"/sandbox";
pub(super) const UNAME_BYTES: &[u8] = b"prototype2";

static mut ACTIVE_RUNTIME: *mut PrototypeRuntime<'static> = null_mut();

pub(crate) fn runtime() -> Result<&'static mut PrototypeRuntime<'static>, &'static str> {
    unsafe {
        if ACTIVE_RUNTIME.is_null() {
            let engine = Box::leak(Box::new(Engine::default()));
            crate::kdebug!("wasmi engine ready");
            let runtime = Box::leak(Box::new(PrototypeRuntime::new(engine)?));
            crate::kdebug!("prototype2 runtime ready");
            ACTIVE_RUNTIME = runtime as *mut _;
        }

        Ok(&mut *ACTIVE_RUNTIME)
    }
}

pub(crate) struct PrototypeRuntime<'engine> {
    pub(super) console: ConsoleService,
    pub(super) vfs: VfsService,
    pub(super) procfs: ProcfsService<'engine>,
    pub(super) devfs: DevfsService,
    pub(super) linux: LinuxFrontend<'engine>,
    pub(super) app: WasmApp<'engine>,
    pub(super) fd_table: Vec<Option<FdEntry>>,
    pub(super) fault: Option<InjectedFault>,
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        Ok(Self {
            console: ConsoleService::new(engine)?,
            vfs: VfsService::new(engine)?,
            procfs: ProcfsService::new(engine)?,
            devfs: DevfsService::new(engine)?,
            linux: LinuxFrontend::new(engine)?,
            app: WasmApp::new(engine)?,
            fd_table: vec![None, None, None],
            fault: None,
        })
    }

    pub(crate) fn sys_write(&mut self, fd: u32, bytes: &[u8]) -> Result<i64, &'static str> {
        let (ptr, len) = self.linux.write_arg_bytes(bytes)?;
        let result = self.dispatch_linux_syscall(
            "linux_write",
            SyscallContext::new(SYS_WRITE, [fd as u64, ptr as u64, len as u64, 0, 0, 0]),
        )?;
        self.expect_ret("write", result)
    }

    pub(crate) fn open_path(&mut self, path: &[u8]) -> Result<u32, &'static str> {
        let (ptr, len) = self.linux.write_arg_bytes(path)?;
        let result = self.dispatch_linux_syscall(
            "openat",
            SyscallContext::new(SYS_OPENAT, [0, ptr as u64, len as u64, 0, 0, 0]),
        )?;
        let fd = self.expect_ret("openat", result)?;
        if fd >= 0 {
            Ok(fd as u32)
        } else {
            Err(if fd == -(ERR_EBADF as i64) {
                "openat returned EBADF"
            } else {
                "openat returned an error"
            })
        }
    }

    pub(crate) fn read_fd(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, &'static str> {
        let result = self.dispatch_linux_syscall(
            "read",
            SyscallContext::new(SYS_READ, [fd as u64, 0, count as u64, 0, 0, 0]),
        )?;
        match result {
            LinuxCallResult::Bytes(bytes) => Ok(bytes),
            LinuxCallResult::Ret(0) => Ok(Vec::new()),
            LinuxCallResult::Ret(_) => Err("read returned a numeric error"),
            LinuxCallResult::Pending { token, delay_ms } => {
                crate::kwarn!(
                    "read unexpectedly returned Pending(token={}, delay_ms={})",
                    token,
                    delay_ms
                );
                Err("read returned an unexpected pending result")
            }
            LinuxCallResult::Exit(code) => {
                crate::kwarn!("read unexpectedly returned Exit({})", code);
                Err("read returned an unexpected exit result")
            }
        }
    }

    pub(crate) fn getdents(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, &'static str> {
        let result = self.dispatch_linux_syscall(
            "getdents64",
            SyscallContext::new(SYS_GETDENTS64, [fd as u64, 0, count as u64, 0, 0, 0]),
        )?;
        self.expect_bytes("getdents64", result)
    }

    pub(crate) fn readlinkat(&mut self, path: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (ptr, len) = self.linux.write_arg_bytes(path)?;
        let result = self.dispatch_linux_syscall(
            "readlinkat",
            SyscallContext::new(SYS_READLINKAT, [0, ptr as u64, len as u64, 0, 0, 0]),
        )?;
        self.expect_bytes("readlinkat", result)
    }

    pub(crate) fn getcwd(&mut self) -> Result<Vec<u8>, &'static str> {
        let result = self.dispatch_linux_syscall(
            "getcwd",
            SyscallContext::new(SYS_GETCWD, [0, 256, 0, 0, 0, 0]),
        )?;
        self.expect_bytes("getcwd", result)
    }

    pub(crate) fn uname(&mut self) -> Result<Vec<u8>, &'static str> {
        let result = self
            .dispatch_linux_syscall("uname", SyscallContext::new(SYS_UNAME, [0, 0, 0, 0, 0, 0]))?;
        self.expect_bytes("uname", result)
    }

    pub(crate) fn close_fd(&mut self, fd: u32) -> Result<i64, &'static str> {
        let result = self.dispatch_linux_syscall(
            "close",
            SyscallContext::new(SYS_CLOSE, [fd as u64, 0, 0, 0, 0, 0]),
        )?;
        self.expect_ret("close", result)
    }

    pub(crate) fn sleep_ms(&mut self, delay_ms: u64) -> Result<(), &'static str> {
        let pending = self.dispatch_linux_syscall(
            "linux_sleep",
            SyscallContext::new(SYS_NANOSLEEP, [delay_ms, 0, 0, 0, 0, 0]),
        )?;
        let token = match pending {
            LinuxCallResult::Pending { token, delay_ms } => {
                crate::kinfo!(
                    "linux_syscall returned Pending(token={}, delay_hint={}ms)",
                    token,
                    delay_ms
                );
                interrupts::sleep_ms(delay_ms);
                token
            }
            _ => return Err("sleep path did not enter pending state"),
        };

        let resumed = self.linux.resume_wait(token)?;
        match self.execute_linux_step("linux_resume", resumed)? {
            LinuxCallResult::Ret(_) => Ok(()),
            _ => Err("resume path returned an unexpected result"),
        }
    }

    pub(crate) fn fd_path(&self, fd: u32) -> Result<Vec<u8>, i32> {
        Ok(self.fd_entry(fd).ok_or(ERR_EBADF)?.path.clone())
    }

    pub(crate) fn path_kind(&mut self, path: &[u8]) -> Result<NodeKind, i32> {
        self.lookup_path(path)
            .map(|info| info.node)
            .map_err(|err| match err {
                ServiceCallError::Errno(errno) => errno,
                ServiceCallError::Trap(_) | ServiceCallError::Invalid(_) => vmos_abi::ERR_EINVAL,
            })
    }

    pub(crate) fn dispatch_linux_syscall(
        &mut self,
        label: &str,
        ctx: SyscallContext,
    ) -> Result<LinuxCallResult, &'static str> {
        let step = self.linux.dispatch(ctx)?;
        self.execute_linux_step(label, step)
    }

    pub(crate) fn write_linux_arg_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(u32, u32), &'static str> {
        self.linux.write_arg_bytes(bytes)
    }

    fn expect_ret(
        &self,
        context: &'static str,
        result: LinuxCallResult,
    ) -> Result<i64, &'static str> {
        match result {
            LinuxCallResult::Ret(ret) => Ok(ret),
            LinuxCallResult::Bytes(_) => Err("linux call returned bytes instead of an integer"),
            LinuxCallResult::Pending { token, delay_ms } => {
                crate::kwarn!(
                    "{} unexpectedly returned Pending(token={}, delay_ms={})",
                    context,
                    token,
                    delay_ms
                );
                Err("linux call returned an unexpected pending result")
            }
            LinuxCallResult::Exit(code) => {
                crate::kwarn!("{} unexpectedly returned Exit({})", context, code);
                Err("linux call returned an unexpected exit result")
            }
        }
    }

    fn expect_bytes(
        &self,
        context: &'static str,
        result: LinuxCallResult,
    ) -> Result<Vec<u8>, &'static str> {
        match result {
            LinuxCallResult::Bytes(bytes) => Ok(bytes),
            LinuxCallResult::Ret(ret) => {
                crate::kwarn!("{} unexpectedly returned Ret({})", context, ret);
                Err("linux call returned an integer instead of bytes")
            }
            LinuxCallResult::Pending { token, delay_ms } => {
                crate::kwarn!(
                    "{} unexpectedly returned Pending(token={}, delay_ms={})",
                    context,
                    token,
                    delay_ms
                );
                Err("linux call returned an unexpected pending result")
            }
            LinuxCallResult::Exit(code) => {
                crate::kwarn!("{} unexpectedly returned Exit({})", context, code);
                Err("linux call returned an unexpected exit result")
            }
        }
    }

    pub(super) fn execute_linux_step(
        &mut self,
        label: &str,
        step: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        let decoded = PackedStep::decode(step);
        match decoded.tag {
            StepTag::Ready => {
                crate::kdebug!("{}: Ready({})", label, decoded.value);
                Ok(LinuxCallResult::Ret(decoded.value as i64))
            }
            StepTag::Pending => Ok(LinuxCallResult::Pending {
                token: decoded.aux,
                delay_ms: decoded.value as u32,
            }),
            StepTag::Plan => {
                let kind = PlanKind::from_raw(decoded.aux).ok_or("linux plan kind was invalid")?;
                let plan = self.linux.current_plan(kind)?;
                self.execute_linux_plan(label, plan)
            }
            StepTag::ConsoleWrite => {
                let len = u32::try_from(decoded.value)
                    .map_err(|_| "linux console write length was negative")?;
                let bytes = self.linux.read_bytes(decoded.aux, len)?;
                self.console.write_bytes(&bytes, false)?;
                Ok(LinuxCallResult::Ret(len as i64))
            }
            StepTag::Exit => Ok(LinuxCallResult::Exit(decoded.value)),
            StepTag::Error => Ok(LinuxCallResult::Ret(decoded.value as i64)),
        }
    }

    fn execute_linux_plan(
        &mut self,
        label: &str,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        crate::kdebug!("{}: {:?}", label, plan.kind);
        match plan.kind {
            PlanKind::Write => self.plan_write(plan),
            PlanKind::OpenAt => self.plan_openat(plan),
            PlanKind::Read => self.plan_read(plan),
            PlanKind::Close => self.plan_close(plan),
            PlanKind::GetDents64 => self.plan_getdents(plan),
            PlanKind::ReadLinkAt => self.plan_readlinkat(plan),
            PlanKind::GetCwd => Ok(LinuxCallResult::Bytes(CURRENT_CWD.to_vec())),
            PlanKind::Uname => Ok(LinuxCallResult::Bytes(UNAME_BYTES.to_vec())),
        }
    }

    fn plan_write(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "write plan fd overflowed")?;
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "write plan ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "write plan len overflowed")?;
        let bytes = self.linux.read_bytes(ptr, len)?;

        if fd == FD_STDOUT || fd == vmos_abi::FD_STDERR {
            self.console.write_bytes(&bytes, false)?;
            return Ok(LinuxCallResult::Ret(bytes.len() as i64));
        }

        let (route, _node, _cursor, path) = self
            .fd_snapshot(fd)
            .map_err(|_| "write targeted an unknown file descriptor")?;
        match route {
            ServiceRoute::Devfs => {
                match self.devfs.write_device(&path, bytes.len() as u32, false) {
                    Ok(count) => Ok(LinuxCallResult::Ret(count as i64)),
                    Err(ServiceCallError::Errno(errno)) => {
                        Ok(LinuxCallResult::Ret(-(errno as i64)))
                    }
                    Err(ServiceCallError::Trap(_)) => Err("devfs_service trapped during write"),
                    Err(ServiceCallError::Invalid(err)) => Err(err),
                }
            }
            _ => Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64))),
        }
    }

    fn plan_openat(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "openat ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "openat len overflowed")?;
        let path = self.linux.read_bytes(ptr, len)?;

        match self.lookup_path(&path) {
            Ok(info) => {
                let fd = self.alloc_fd(FdEntry {
                    route: info.route,
                    node: info.node,
                    path,
                    cursor: 0,
                });
                Ok(LinuxCallResult::Ret(fd as i64))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("openat: {}", reason);
                Err("a service trapped during openat")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_read(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "read plan fd overflowed")?;
        let count = u32::try_from(plan.args[1]).map_err(|_| "read plan count overflowed")?;
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

    fn plan_close(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "close plan fd overflowed")?;
        if fd < 3 {
            return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64)));
        }

        let slot = self
            .fd_table
            .get_mut(fd as usize)
            .ok_or("close targeted an out-of-range file descriptor")?;
        if slot.take().is_none() {
            return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64)));
        }

        Ok(LinuxCallResult::Ret(0))
    }

    fn plan_getdents(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
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

    fn plan_readlinkat(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
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

    fn lookup_path(&mut self, path: &[u8]) -> Result<LookupInfo, ServiceCallError> {
        let info = self.vfs.lookup(path, false)?;
        match info.route {
            ServiceRoute::Vfs => Ok(info),
            ServiceRoute::Procfs => {
                let node = self.procfs.lookup(path, false)?;
                Ok(LookupInfo {
                    route: ServiceRoute::Procfs,
                    node,
                })
            }
            ServiceRoute::Devfs => {
                let node = self.devfs.lookup(path, false)?;
                Ok(LookupInfo {
                    route: ServiceRoute::Devfs,
                    node,
                })
            }
        }
    }

    fn read_from_fd(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, ServiceCallError> {
        let (route, node, cursor, path) = self.fd_snapshot(fd)?;
        if node == NodeKind::Directory {
            return Err(ServiceCallError::Errno(vmos_abi::ERR_EISDIR));
        }

        let bytes = match route {
            ServiceRoute::Vfs => self.vfs.read_file(&path, false)?,
            ServiceRoute::Procfs => self.procfs_read_with_recovery(&path)?,
            ServiceRoute::Devfs => self.devfs.read_device(&path, count, false)?,
        };

        let start = cursor.min(bytes.len());
        let end = start.saturating_add(count as usize).min(bytes.len());
        let chunk = bytes[start..end].to_vec();
        self.set_fd_cursor(fd, end)?;
        Ok(chunk)
    }

    fn read_dir_entries(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, ServiceCallError> {
        let (route, node, cursor, path) = self.fd_snapshot(fd)?;
        if node != NodeKind::Directory {
            return Err(ServiceCallError::Errno(vmos_abi::ERR_ENOTDIR));
        }

        let bytes = match route {
            ServiceRoute::Vfs => self.vfs.list_dir(&path, false)?,
            ServiceRoute::Procfs => self.procfs.list_dir(&path, false)?,
            ServiceRoute::Devfs => self.devfs.list_dir(&path, false)?,
        };

        let start = cursor.min(bytes.len());
        let end = start.saturating_add(count as usize).min(bytes.len());
        let chunk = bytes[start..end].to_vec();
        self.set_fd_cursor(fd, end)?;
        Ok(chunk)
    }

    fn read_link_path(&mut self, path: &[u8]) -> Result<Vec<u8>, ServiceCallError> {
        let info = self.lookup_path(path)?;
        if info.node != NodeKind::Symlink {
            return Err(ServiceCallError::Errno(ERR_EINVAL));
        }

        match info.route {
            ServiceRoute::Vfs => self.vfs.read_link(path, false),
            ServiceRoute::Procfs => self.procfs.read_link(path, false),
            ServiceRoute::Devfs => Err(ServiceCallError::Errno(ERR_EINVAL)),
        }
    }

    fn procfs_read_with_recovery(&mut self, path: &[u8]) -> Result<Vec<u8>, ServiceCallError> {
        let inject_fault = self.take_fault(InjectedFault::ProcfsRead);
        match self.procfs.read_file(path, inject_fault) {
            Ok(bytes) => Ok(bytes),
            Err(ServiceCallError::Trap(_)) if inject_fault => {
                crate::kinfo!("procfs_service trapped; recreating service store");
                let engine = self.procfs.engine;
                self.procfs = ProcfsService::new(engine).map_err(ServiceCallError::Invalid)?;
                self.procfs.read_file(path, false)
            }
            Err(err) => Err(err),
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

    fn alloc_fd(&mut self, entry: FdEntry) -> u32 {
        for (fd, slot) in self.fd_table.iter_mut().enumerate().skip(3) {
            if slot.is_none() {
                *slot = Some(entry);
                return fd as u32;
            }
        }

        self.fd_table.push(Some(entry));
        (self.fd_table.len() - 1) as u32
    }

    fn fd_entry(&self, fd: u32) -> Option<&FdEntry> {
        self.fd_table.get(fd as usize)?.as_ref()
    }

    fn fd_snapshot(
        &self,
        fd: u32,
    ) -> Result<(ServiceRoute, NodeKind, usize, Vec<u8>), ServiceCallError> {
        let entry = self
            .fd_entry(fd)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        Ok((entry.route, entry.node, entry.cursor, entry.path.clone()))
    }

    fn set_fd_cursor(&mut self, fd: u32, cursor: usize) -> Result<(), ServiceCallError> {
        let entry = self
            .fd_table
            .get_mut(fd as usize)
            .and_then(Option::as_mut)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        entry.cursor = cursor;
        Ok(())
    }
}
