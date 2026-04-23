use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::null_mut;

use crate::interrupts;
use vmos_abi::{
    ERR_EAGAIN, ERR_EBADF, ERR_EINVAL, FD_STDOUT, NodeKind, PackedStep, PlanKind, SYS_CLOSE,
    SYS_GETCWD, SYS_GETDENTS64, SYS_OPENAT, SYS_READ, SYS_READLINKAT, SYS_UNAME, SYS_WRITE,
    ServiceRoute, StepTag, SyscallContext,
};

use super::engine::SupervisorEngine;
use super::events::Event;
use super::linux::{LinuxCallResult, LinuxFrontend, LinuxPlan};
use super::pulse::{PulseDevice, PulseEvent};
use super::scheduler::Scheduler;
use super::services::{
    ConsoleService, DevfsService, EpollService, FutexService, ProcfsService, VfsService, WasmApp,
};
use super::types::{
    FdEntry, FdResource, InjectedFault, LookupInfo, ServiceCallError, TaskId, WaitRestartClass,
    WaitToken,
};
use super::wait::{WaitOutcome, WaitRegistration, WaitRegistry, WaitSource};

pub(super) const CURRENT_CWD: &[u8] = b"/sandbox";
pub(super) const UNAME_BYTES: &[u8] = b"prototype2";

static mut ACTIVE_RUNTIME: *mut PrototypeRuntime<'static> = null_mut();

pub(crate) fn runtime() -> Result<&'static mut PrototypeRuntime<'static>, &'static str> {
    unsafe {
        if ACTIVE_RUNTIME.is_null() {
            let engine = Box::leak(Box::new(SupervisorEngine::default()));
            crate::kdebug!("supervisor engine ready");
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
    pub(super) procfs_engine: &'engine SupervisorEngine,
    pub(super) procfs: Option<ProcfsService>,
    pub(super) devfs: DevfsService,
    pub(super) epoll: EpollService,
    pub(super) futex: FutexService,
    pub(super) linux: LinuxFrontend,
    pub(super) app: WasmApp,
    pub(super) fd_table: Vec<Option<FdEntry>>,
    pub(super) fault: Option<InjectedFault>,
    pub(super) scheduler: Scheduler,
    pub(super) waits: WaitRegistry,
    pub(super) pulse: PulseDevice,
    pub(super) restart_count: u64,
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn new(engine: &'engine SupervisorEngine) -> Result<Self, &'static str> {
        Ok(Self {
            console: ConsoleService::new(engine)?,
            vfs: VfsService::new(engine)?,
            procfs_engine: engine,
            procfs: Some(ProcfsService::new(engine)?),
            devfs: DevfsService::new(engine)?,
            epoll: EpollService::new(engine)?,
            futex: FutexService::new(engine)?,
            linux: LinuxFrontend::new(engine)?,
            app: WasmApp::new(engine)?,
            fd_table: vec![None, None, None],
            fault: None,
            scheduler: Scheduler::new(),
            waits: WaitRegistry::new(),
            pulse: PulseDevice::new(interrupts::tick_count()),
            restart_count: 0,
        })
    }

    pub(crate) fn allocate_task(&mut self) -> TaskId {
        self.scheduler.allocate_task()
    }

    pub(crate) fn set_current_task(&mut self, task: TaskId) {
        self.scheduler.set_current_task(task);
    }

    pub(crate) fn bootstrap_task(&self) -> TaskId {
        self.scheduler.bootstrap_task()
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
            LinuxCallResult::Pending(token) => {
                crate::kwarn!("read unexpectedly returned Pending({:?})", token);
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

    pub(crate) fn restart_count(&self) -> u64 {
        self.restart_count
    }

    pub(crate) fn inject_wait_restart(&mut self, token: WaitToken, class: WaitRestartClass) {
        self.scheduler
            .push_event(Event::WaitRestart(token.id, class));
        self.drain_event_queue();
    }

    pub(crate) fn fd_path(&self, fd: u32) -> Result<Vec<u8>, i32> {
        let entry = self.fd_entry(fd).ok_or(ERR_EBADF)?;
        match &entry.resource {
            FdResource::ServiceNode { path, .. } => Ok(path.clone()),
            FdResource::EpollInstance { .. } => Err(ERR_EBADF),
        }
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
        let result = self.dispatch_linux_syscall_raw(label, ctx)?;
        match result {
            LinuxCallResult::Pending(token) => self.block_on_wait(label, token),
            ready => Ok(ready),
        }
    }

    pub(crate) fn dispatch_linux_syscall_raw(
        &mut self,
        label: &str,
        ctx: SyscallContext,
    ) -> Result<LinuxCallResult, &'static str> {
        let step = self.linux.dispatch(ctx)?;
        self.execute_linux_step(label, step)
    }

    pub(crate) fn dispatch_linux_sleep_ms_raw(
        &mut self,
        label: &str,
        delay_ms: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        let step = self.linux.dispatch_sleep_ms(delay_ms)?;
        self.execute_linux_step(label, step)
    }

    pub(crate) fn dispatch_linux_futex_raw(
        &mut self,
        label: &str,
        key: u64,
        op: u64,
        val: u64,
        timeout_ms: u64,
        current_word: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        let step = self
            .linux
            .dispatch_futex_raw(key, op, val, timeout_ms, current_word)?;
        self.execute_linux_step(label, step)
    }

    pub(crate) fn uname_abi(&mut self) -> Result<Vec<u8>, &'static str> {
        let release = self.uname()?;
        self.linux.encode_uname(&release)
    }

    pub(crate) fn getdents64_abi(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, &'static str> {
        let dir_path = self
            .fd_path(fd)
            .map_err(|_| "getdents64 targeted an unknown fd")?;
        let listing = self.getdents(fd, count)?;
        let records = self.build_dirent_records(&dir_path, &listing)?;
        self.linux.encode_dirents64(&records, count)
    }

    pub(crate) fn write_linux_arg_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(u32, u32), &'static str> {
        self.linux.write_arg_bytes(bytes)
    }

    pub(crate) fn expect_ret(
        &self,
        context: &'static str,
        result: LinuxCallResult,
    ) -> Result<i64, &'static str> {
        match result {
            LinuxCallResult::Ret(ret) => Ok(ret),
            LinuxCallResult::Bytes(_) => Err("linux call returned bytes instead of an integer"),
            LinuxCallResult::Pending(token) => {
                crate::kwarn!("{} unexpectedly returned Pending({:?})", context, token);
                Err("linux call returned an unexpected pending result")
            }
            LinuxCallResult::Exit(code) => {
                crate::kwarn!("{} unexpectedly returned Exit({})", context, code);
                Err("linux call returned an unexpected exit result")
            }
        }
    }

    pub(crate) fn expect_bytes(
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
            LinuxCallResult::Pending(token) => {
                crate::kwarn!("{} unexpectedly returned Pending({:?})", context, token);
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
            StepTag::Pending => Err("linux_syscall returned a legacy Pending step"),
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
            PlanKind::Sleep => self.plan_sleep(plan),
            PlanKind::FutexWait => self.plan_futex_wait(plan),
            PlanKind::FutexWake => self.plan_futex_wake(plan),
            PlanKind::EpollCreate1 => self.plan_epoll_create1(plan),
            PlanKind::EpollCtl => self.plan_epoll_ctl(plan),
            PlanKind::EpollWait => self.plan_epoll_wait(plan),
            PlanKind::EpollReady => self.plan_epoll_ready(plan),
        }
    }

    fn plan_sleep(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let resume_cookie =
            u32::try_from(plan.args[0]).map_err(|_| "sleep resume cookie overflowed")?;
        let delay_ms = u32::try_from(plan.args[1]).map_err(|_| "sleep delay overflowed")?;
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::Timer {
                delay_ms,
                resume_cookie,
            },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        Ok(LinuxCallResult::Pending(token))
    }

    fn plan_futex_wait(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let key = plan.args[0];
        let timeout_ms = if plan.args[1] == u64::MAX {
            None
        } else {
            Some(u32::try_from(plan.args[1]).map_err(|_| "futex timeout overflowed")?)
        };
        let resume_cookie =
            u32::try_from(plan.args[2]).map_err(|_| "futex resume cookie overflowed")?;
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::Futex {
                timeout_ms,
                resume_cookie,
            },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );

        match self.futex.register_wait(key, token.id) {
            Ok(()) => Ok(LinuxCallResult::Pending(token)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("futex_wait: {}", reason);
                Err("futex_service trapped during futex wait")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_futex_wake(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let key = plan.args[0];
        let count = u32::try_from(plan.args[1]).map_err(|_| "futex wake count overflowed")?;
        match self.futex.wake(key, count) {
            Ok(wait_ids) => {
                for wait_id in &wait_ids {
                    self.scheduler.push_event(Event::WaitReady(*wait_id));
                }
                self.drain_event_queue();
                Ok(LinuxCallResult::Ret(wait_ids.len() as i64))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("futex_wake: {}", reason);
                Err("futex_service trapped during futex wake")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
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

        let entry = self
            .fd_entry(fd)
            .ok_or("write targeted an unknown file descriptor")?;
        match &entry.resource {
            FdResource::ServiceNode { route, path, .. } if *route == ServiceRoute::Devfs => {
                let path = path.clone();
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
                    resource: FdResource::ServiceNode {
                        route: info.route,
                        node: info.node,
                        path,
                    },
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

    fn plan_epoll_create1(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let flags = u32::try_from(plan.args[0]).map_err(|_| "epoll_create1 flags overflowed")?;
        match self.epoll.create(flags) {
            Ok(epoll_id) => {
                let fd = self.alloc_fd(FdEntry {
                    resource: FdResource::EpollInstance { epoll_id },
                    cursor: 0,
                });
                Ok(LinuxCallResult::Ret(fd as i64))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_create1: {}", reason);
                Err("epoll_service trapped during epoll_create1")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_epoll_ctl(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let epfd = u32::try_from(plan.args[0]).map_err(|_| "epoll_ctl epfd overflowed")?;
        let op = u32::try_from(plan.args[1]).map_err(|_| "epoll_ctl op overflowed")?;
        let fd = u32::try_from(plan.args[2]).map_err(|_| "epoll_ctl fd overflowed")?;
        let events = u32::try_from(plan.args[3]).map_err(|_| "epoll_ctl events overflowed")?;
        let data = plan.args[4];
        let epoll_id = self
            .epoll_id_from_fd(epfd)
            .map_err(|_| "epoll_ctl targeted an invalid epoll fd")?;
        let ready_key = self
            .fd_ready_key(fd)
            .map_err(|_| "epoll_ctl targeted a non-pollable fd")?;
        match self.epoll.ctl(epoll_id, op, ready_key, events, data) {
            Ok(()) => {
                if self.pulse.is_ready_key(ready_key) {
                    let _ = self.epoll.notify_ready(ready_key);
                }
                Ok(LinuxCallResult::Ret(0))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_ctl: {}", reason);
                Err("epoll_service trapped during epoll_ctl")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_epoll_wait(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let epfd = u32::try_from(plan.args[0]).map_err(|_| "epoll_wait epfd overflowed")?;
        let max_events =
            u32::try_from(plan.args[1]).map_err(|_| "epoll_wait max_events overflowed")?;
        let timeout_ms = if plan.args[2] == u64::MAX {
            None
        } else {
            Some(u32::try_from(plan.args[2]).map_err(|_| "epoll_wait timeout overflowed")?)
        };
        let resume_cookie =
            u32::try_from(plan.args[3]).map_err(|_| "epoll_wait resume cookie overflowed")?;
        let epoll_id = self
            .epoll_id_from_fd(epfd)
            .map_err(|_| "epoll_wait targeted an invalid epoll fd")?;

        self.pump_async_sources();
        let ready = match self.epoll.collect_ready(epoll_id, max_events) {
            Ok(bytes) => bytes,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_wait collect_ready: {}", reason);
                return Err("epoll_service trapped during epoll_wait");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        if !ready.is_empty() {
            return self.encode_epoll_ready(&ready, max_events);
        }
        if timeout_ms == Some(0) {
            return Ok(LinuxCallResult::Ret(0));
        }

        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::Epoll {
                epoll_id,
                max_events,
                timeout_ms,
                resume_cookie,
            },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        match self.epoll.arm_wait(epoll_id, token.id) {
            Ok(()) => Ok(LinuxCallResult::Pending(token)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_wait arm_wait: {}", reason);
                Err("epoll_service trapped during epoll_wait")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_epoll_ready(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let epoll_id =
            u32::try_from(plan.args[0]).map_err(|_| "epoll_ready epoll id overflowed")?;
        let max_events =
            u32::try_from(plan.args[1]).map_err(|_| "epoll_ready max_events overflowed")?;
        let ready = match self.epoll.collect_ready(epoll_id, max_events) {
            Ok(bytes) => bytes,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_ready: {}", reason);
                return Err("epoll_service trapped during epoll ready");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        if ready.is_empty() {
            return Ok(LinuxCallResult::Ret(0));
        }
        self.encode_epoll_ready(&ready, max_events)
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
                let node = self.procfs_mut().lookup(path, false)?;
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
        let (route, node, cursor, path) = self.service_fd_snapshot(fd)?;
        if node == NodeKind::Directory {
            return Err(ServiceCallError::Errno(vmos_abi::ERR_EISDIR));
        }

        let bytes = match route {
            ServiceRoute::Vfs => self.vfs.read_file(&path, false)?,
            ServiceRoute::Procfs => self.procfs_read_with_recovery(&path)?,
            ServiceRoute::Devfs => {
                if let Some(bytes) = self.pulse.read(&path, count, interrupts::tick_count()) {
                    bytes.to_vec()
                } else if path == b"/dev/pulse" {
                    return Err(ServiceCallError::Errno(ERR_EAGAIN));
                } else {
                    self.devfs.read_device(&path, count, false)?
                }
            }
        };

        let start = cursor.min(bytes.len());
        let end = start.saturating_add(count as usize).min(bytes.len());
        let chunk = bytes[start..end].to_vec();
        self.set_fd_cursor(fd, end)?;
        Ok(chunk)
    }

    fn read_dir_entries(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, ServiceCallError> {
        let (route, node, cursor, path) = self.service_fd_snapshot(fd)?;
        if node != NodeKind::Directory {
            return Err(ServiceCallError::Errno(vmos_abi::ERR_ENOTDIR));
        }

        let bytes = match route {
            ServiceRoute::Vfs => self.vfs.list_dir(&path, false)?,
            ServiceRoute::Procfs => self.procfs_mut().list_dir(&path, false)?,
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
            ServiceRoute::Procfs => self.procfs_mut().read_link(path, false),
            ServiceRoute::Devfs => Err(ServiceCallError::Errno(ERR_EINVAL)),
        }
    }

    fn build_dirent_records(
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
        match self.procfs_mut().read_file(path, inject_fault) {
            Ok(bytes) => Ok(bytes),
            Err(ServiceCallError::Trap(_)) if inject_fault => {
                crate::kinfo!("procfs_service trapped; recreating service store");
                let _ = self.procfs.take();
                self.procfs = Some(
                    ProcfsService::new(self.procfs_engine).map_err(ServiceCallError::Invalid)?,
                );
                self.procfs_mut().read_file(path, false)
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

    fn service_fd_snapshot(
        &self,
        fd: u32,
    ) -> Result<(ServiceRoute, NodeKind, usize, Vec<u8>), ServiceCallError> {
        let entry = self
            .fd_entry(fd)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        match &entry.resource {
            FdResource::ServiceNode { route, node, path } => {
                Ok((*route, *node, entry.cursor, path.clone()))
            }
            FdResource::EpollInstance { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
        }
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

    fn epoll_id_from_fd(&self, fd: u32) -> Result<u32, ServiceCallError> {
        match self.fd_entry(fd) {
            Some(FdEntry {
                resource: FdResource::EpollInstance { epoll_id },
                ..
            }) => Ok(*epoll_id),
            _ => Err(ServiceCallError::Errno(ERR_EBADF)),
        }
    }

    fn fd_ready_key(&self, fd: u32) -> Result<u64, ServiceCallError> {
        let entry = self
            .fd_entry(fd)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        match &entry.resource {
            FdResource::ServiceNode {
                route: ServiceRoute::Devfs,
                path,
                ..
            } => PulseDevice::ready_key_for_path(path).ok_or(ServiceCallError::Errno(ERR_EINVAL)),
            _ => Err(ServiceCallError::Errno(ERR_EINVAL)),
        }
    }

    fn procfs_mut(&mut self) -> &mut ProcfsService {
        self.procfs
            .as_mut()
            .expect("procfs service should always be installed outside recovery")
    }

    fn collect_epoll_ready(
        &mut self,
        epoll_id: u32,
        max_events: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        let ready = match self.epoll.collect_ready(epoll_id, max_events) {
            Ok(bytes) => bytes,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll collect_ready: {}", reason);
                return Err("epoll_service trapped while collecting ready events");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        if ready.is_empty() {
            return Ok(LinuxCallResult::Ret(0));
        }
        self.encode_epoll_ready(&ready, max_events)
    }

    fn encode_epoll_ready(
        &mut self,
        records: &[u8],
        max_events: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        let bytes = self.linux.encode_epoll_events(records, max_events)?;
        Ok(LinuxCallResult::Bytes(bytes))
    }

    pub(super) fn block_on_wait(
        &mut self,
        label: &str,
        token: WaitToken,
    ) -> Result<LinuxCallResult, &'static str> {
        crate::substrate::dmw::assert_quiescent()
            .map_err(|_| "entered Pending with an active DMW lease")?;
        loop {
            self.pump_async_sources();

            if let Some(resolution) = self.waits.take_resolution(token) {
                return match resolution.outcome {
                    WaitOutcome::Ready => match resolution.source {
                        WaitSource::Epoll {
                            epoll_id,
                            max_events,
                        } => {
                            let _ = self.linux.resume_wait(resolution.resume_cookie)?;
                            self.collect_epoll_ready(epoll_id, max_events)
                        }
                        _ => {
                            let resumed = self.linux.resume_wait(resolution.resume_cookie)?;
                            self.execute_linux_step("linux_resume", resumed)
                        }
                    },
                    WaitOutcome::Cancelled(errno) => {
                        match token.kind {
                            super::types::WaitKind::Futex => {
                                match self.futex.cancel_wait(token.id) {
                                    Ok(()) | Err(ServiceCallError::Errno(_)) => {}
                                    Err(ServiceCallError::Trap(reason)) => {
                                        crate::kwarn!("futex cancel: {}", reason);
                                    }
                                    Err(ServiceCallError::Invalid(err)) => {
                                        crate::kwarn!("futex cancel: {}", err);
                                    }
                                }
                            }
                            super::types::WaitKind::Epoll => {
                                match self.epoll.cancel_wait(token.id) {
                                    Ok(()) | Err(ServiceCallError::Errno(_)) => {}
                                    Err(ServiceCallError::Trap(reason)) => {
                                        crate::kwarn!("epoll cancel: {}", reason);
                                    }
                                    Err(ServiceCallError::Invalid(err)) => {
                                        crate::kwarn!("epoll cancel: {}", err);
                                    }
                                }
                            }
                            super::types::WaitKind::Timer => {}
                        }
                        let cancelled = self.linux.cancel_wait(resolution.resume_cookie, errno)?;
                        self.execute_linux_step("linux_cancel", cancelled)
                    }
                    WaitOutcome::Restart(class) => {
                        self.restart_count += 1;
                        crate::kinfo!("{} restarted as {:?}", label, class);
                        let restarted = self.linux.restart_wait(resolution.resume_cookie, class)?;
                        Ok(match self.execute_linux_step("linux_restart", restarted)? {
                            LinuxCallResult::Pending(next) => self.block_on_wait(label, next),
                            ready => Ok(ready),
                        }?)
                    }
                };
            }

            interrupts::wait_for_interrupt();
        }
    }

    fn drain_event_queue(&mut self) {
        while let Some(event) = self.scheduler.pop_event() {
            self.waits.apply_event(event);
        }
    }

    fn pump_async_sources(&mut self) {
        let mut due_events = vec![];
        self.waits
            .collect_due_events(interrupts::tick_count(), &mut due_events);
        for event in due_events {
            self.scheduler.push_event(event);
        }

        let mut pulse_events = Vec::new();
        self.pulse
            .collect_events(interrupts::tick_count(), &mut pulse_events);
        for event in pulse_events {
            match event {
                PulseEvent::Ready(ready_key) => match self.epoll.notify_ready(ready_key) {
                    Ok(wait_ids) => {
                        for wait_id in wait_ids {
                            self.scheduler.push_event(Event::WaitReady(wait_id));
                        }
                    }
                    Err(ServiceCallError::Trap(reason)) => {
                        crate::kwarn!("epoll ready notification: {}", reason);
                    }
                    Err(ServiceCallError::Invalid(err)) => {
                        crate::kwarn!("epoll ready notification: {}", err);
                    }
                    Err(ServiceCallError::Errno(errno)) => {
                        crate::kwarn!("epoll ready notification errno={}", errno);
                    }
                },
                PulseEvent::Restart(ready_key) => match self.epoll.restart_key(ready_key) {
                    Ok(wait_ids) => {
                        for wait_id in wait_ids {
                            self.scheduler.push_event(Event::WaitRestart(
                                wait_id,
                                WaitRestartClass::DriverRestart,
                            ));
                        }
                    }
                    Err(ServiceCallError::Trap(reason)) => {
                        crate::kwarn!("epoll restart notification: {}", reason);
                    }
                    Err(ServiceCallError::Invalid(err)) => {
                        crate::kwarn!("epoll restart notification: {}", err);
                    }
                    Err(ServiceCallError::Errno(errno)) => {
                        crate::kwarn!("epoll restart notification errno={}", errno);
                    }
                },
            }
        }
        self.drain_event_queue();
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
