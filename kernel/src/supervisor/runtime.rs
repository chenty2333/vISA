use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::null_mut;

use crate::interrupts;
use semantic_core::{FailureEffect, FrontendKind, ResourceHandle, SemanticGraph, TaskState};
use vmos_abi::{
    EPOLLIN, ERR_EAGAIN, ERR_EBADF, ERR_EFAULT, ERR_EINVAL, ERR_ENOSYS, ERR_ENOTSOCK,
    ERR_EOPNOTSUPP, ERR_EPERM, FD_STDOUT, NodeKind, PackedStep, PlanKind, SYS_CLOSE, SYS_GETCWD,
    SYS_GETDENTS64, SYS_OPENAT, SYS_READ, SYS_READLINKAT, SYS_UNAME, SYS_WRITE, ServiceRoute,
    StepTag, SyscallContext,
};

use super::engine::RuntimeOnlyExecutor;
use super::events::Event;
use super::linux::{LinuxCallResult, LinuxFrontend, LinuxPlan};
use super::net::NetworkPlane;
use super::pulse::{PulseDevice, PulseEvent};
use super::scheduler::Scheduler;
use super::semantic::{bootstrap_graph, fd_resource_kind, fd_resource_label};
use super::services::{
    ConsoleService, DevfsService, DriverNetEventKind, DriverVirtioNetService, EpollService,
    FutexService, LinuxSocketService, NetCoreService, ProcfsService, ReplaySnapshotService,
    VfsService, WasmApp,
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
            let engine = Box::leak(Box::new(RuntimeOnlyExecutor::default()));
            crate::kdebug!("runtime-only supervisor executor ready");
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
    pub(super) engine: &'engine RuntimeOnlyExecutor,
    pub(super) procfs: Option<ProcfsService>,
    pub(super) devfs: DevfsService,
    pub(super) epoll: EpollService,
    pub(super) futex: FutexService,
    pub(super) net_core: NetCoreService,
    pub(super) linux_socket: LinuxSocketService,
    pub(super) net_driver: DriverVirtioNetService,
    pub(super) replay_snapshot: ReplaySnapshotService,
    pub(super) linux: LinuxFrontend,
    pub(super) app: WasmApp,
    pub(super) fd_table: Vec<Option<FdEntry>>,
    pub(super) fd_handles: Vec<Option<ResourceHandle>>,
    pub(super) fault: Option<InjectedFault>,
    pub(super) scheduler: Scheduler,
    pub(super) waits: WaitRegistry,
    pub(super) pulse: PulseDevice,
    pub(super) net: NetworkPlane,
    pub(super) restart_count: u64,
    pub(super) semantic: SemanticGraph,
    pub(super) next_snapshot_barrier: u64,
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn new(engine: &'engine RuntimeOnlyExecutor) -> Result<Self, &'static str> {
        crate::kdebug!("bootstrapping semantic graph");
        let mut semantic = bootstrap_graph();
        crate::kdebug!("bootstrapping network plane");
        let net = NetworkPlane::new(&mut semantic);
        crate::kdebug!("instantiating console_service");
        let console = ConsoleService::new(engine)?;
        crate::kdebug!("instantiating vfs_service");
        let vfs = VfsService::new(engine)?;
        crate::kdebug!("instantiating procfs_service");
        let procfs = ProcfsService::new(engine)?;
        crate::kdebug!("instantiating devfs_service");
        let devfs = DevfsService::new(engine)?;
        crate::kdebug!("instantiating epoll_service");
        let epoll = EpollService::new(engine)?;
        crate::kdebug!("instantiating futex_service");
        let futex = FutexService::new(engine)?;
        crate::kdebug!("instantiating net_core");
        let net_core = NetCoreService::new(engine)?;
        crate::kdebug!("instantiating linux_socket_service");
        let linux_socket = LinuxSocketService::new(engine)?;
        crate::kdebug!("instantiating driver_virtio_net");
        let net_driver = DriverVirtioNetService::new(engine)?;
        crate::kdebug!("instantiating replay_snapshot");
        let replay_snapshot = ReplaySnapshotService::new(engine)?;
        crate::kdebug!("instantiating linux_syscall");
        let linux = LinuxFrontend::new(engine)?;
        crate::kdebug!("instantiating wasm_app");
        let app = WasmApp::new(engine)?;
        Ok(Self {
            console,
            vfs,
            engine,
            procfs: Some(procfs),
            devfs,
            epoll,
            futex,
            net_core,
            linux_socket,
            net_driver,
            replay_snapshot,
            linux,
            app,
            fd_table: vec![None, None, None],
            fd_handles: vec![None, None, None],
            fault: None,
            scheduler: Scheduler::new(),
            waits: WaitRegistry::new(),
            pulse: PulseDevice::new(interrupts::tick_count()),
            net,
            restart_count: 0,
            semantic,
            next_snapshot_barrier: 1,
        })
    }

    pub(crate) fn allocate_task(&mut self) -> TaskId {
        let task = self.scheduler.allocate_task();
        self.semantic
            .ensure_task(task, FrontendKind::LinuxElf, "linux-elf-task");
        task
    }

    pub(crate) fn set_current_task(&mut self, task: TaskId) {
        self.scheduler.set_current_task(task);
        self.semantic.set_task_state(task, TaskState::Running);
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

    pub(crate) fn fd_path(&mut self, fd: u32) -> Result<Vec<u8>, i32> {
        self.validate_fd_handle(fd).map_err(|_| ERR_EBADF)?;
        let entry = self.fd_entry(fd).ok_or(ERR_EBADF)?;
        match &entry.resource {
            FdResource::ServiceNode { path, .. } => Ok(path.clone()),
            FdResource::EpollInstance { .. } => Err(ERR_EBADF),
            FdResource::Socket { .. } => Err(ERR_EBADF),
        }
    }

    pub(crate) fn fd_handle_for_demo(&self, fd: u32) -> Option<ResourceHandle> {
        self.fd_handle(fd)
    }

    pub(crate) fn open_demo_socket_for_demo(&mut self) -> Result<u32, &'static str> {
        let socket_id = self
            .net_core
            .create_socket(vmos_abi::AF_INET, vmos_abi::SOCK_STREAM, 0)
            .map_err(|_| "net_core failed to create demo socket")?;
        let ready_key = self
            .net_core
            .ready_key(socket_id)
            .map_err(|_| "net_core did not return a socket ready key")?;
        self.linux_socket
            .register_socket(
                socket_id,
                vmos_abi::AF_INET,
                vmos_abi::SOCK_STREAM,
                0,
                ready_key,
            )
            .map_err(|_| "linux_socket_service failed to register demo socket")?;
        let fd = self.alloc_fd(FdEntry {
            resource: FdResource::Socket {
                socket_id: socket_id as u64,
                ready_key,
            },
            cursor: 0,
        });
        let handle = self
            .fd_handle(fd)
            .ok_or("demo socket fd did not publish a resource handle")?;
        self.semantic.record_socket_state_changed(handle.id, "open");
        Ok(fd)
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
                self.require_capability("linux_syscall", "console.write", "write")
                    .map_err(|_| "linux console write capability denied")?;
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
        self.record_hostcall_plan(label, plan.kind);
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
            PlanKind::Socket => self.plan_socket(plan),
            PlanKind::Bind => self.plan_socket_state(plan, "bind"),
            PlanKind::Listen => self.plan_socket_state(plan, "listen"),
            PlanKind::Accept => self.plan_accept(plan),
            PlanKind::Connect => self.plan_socket_state(plan, "connect"),
            PlanKind::SendTo => self.plan_sendto(plan),
            PlanKind::RecvFrom => self.plan_recvfrom(plan),
            PlanKind::SetSockOpt => self.plan_setsockopt(plan),
            PlanKind::GetSockOpt => self.plan_getsockopt(plan),
            PlanKind::Fcntl => self.plan_fcntl(plan),
            PlanKind::Mmap => self.plan_mmap(plan),
            PlanKind::Munmap => self.plan_munmap(plan),
            PlanKind::Poll => self.plan_poll(plan),
        }
    }

    fn plan_sleep(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("linux_syscall", "timer.sleep", "arm")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
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
        self.record_wait_token(token);
        Ok(LinuxCallResult::Pending(token))
    }

    fn plan_futex_wait(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("futex_service", "futex.waitset", "wait")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
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
            Ok(()) => {
                self.record_wait_token(token);
                Ok(LinuxCallResult::Pending(token))
            }
            Err(ServiceCallError::Errno(errno)) => {
                self.semantic.record_wait_cancelled(token.id, errno);
                self.semantic
                    .record_failure_effect(FailureEffect::CancelWaitToken {
                        wait: token.id,
                        errno,
                    });
                Ok(LinuxCallResult::Ret(-(errno as i64)))
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("futex_wait: {}", reason);
                self.record_service_trap("futex_service", reason);
                Err("futex_service trapped during futex wait")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_futex_wake(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("futex_service", "futex.waitset", "wake")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
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
            if self
                .require_capability("linux_syscall", "console.write", "write")
                .is_err()
            {
                return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
            }
            self.console.write_bytes(&bytes, false)?;
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

        let entry = self
            .fd_entry(fd)
            .ok_or("write targeted an unknown file descriptor")?;
        match &entry.resource {
            FdResource::ServiceNode { route, path, .. } if *route == ServiceRoute::Devfs => {
                let path = path.clone();
                if self
                    .require_capability("devfs_service", "device.pulse", "poll")
                    .is_err()
                {
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
        if self
            .require_capability("epoll_service", "epoll.instance", "create")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
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
        if self
            .require_capability("epoll_service", "epoll.instance", "ctl")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
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
                if self.pulse.is_ready_key(ready_key)
                    || self.socket_ready_key_is_readable(ready_key)
                {
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

    fn plan_socket(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("linux_syscall", "linux.socket", "socket")
            .is_err()
            || self
                .require_capability("net_core", "net.socket", "create")
                .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }

        let domain = u32::try_from(plan.args[0]).map_err(|_| "socket domain overflowed")?;
        let ty = u32::try_from(plan.args[1]).map_err(|_| "socket type overflowed")?;
        let protocol = u32::try_from(plan.args[2]).map_err(|_| "socket protocol overflowed")?;
        let socket_id = match self.net_core.create_socket(domain, ty, protocol) {
            Ok(socket_id) => socket_id,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("net_core create_socket: {}", reason);
                return Err("net_core trapped during socket");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        let ready_key = match self.net_core.ready_key(socket_id) {
            Ok(key) => key,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("net_core ready_key: {}", reason);
                return Err("net_core trapped while creating socket");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        match self
            .linux_socket
            .register_socket(socket_id, domain, ty, protocol, ready_key)
        {
            Ok(()) => {}
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket register_socket: {}", reason);
                return Err("linux_socket_service trapped during socket");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        }

        let fd = self.alloc_fd(FdEntry {
            resource: FdResource::Socket {
                socket_id: socket_id as u64,
                ready_key,
            },
            cursor: 0,
        });
        if let Some(handle) = self.fd_handle(fd) {
            self.semantic.record_socket_state_changed(handle.id, "open");
        }
        Ok(LinuxCallResult::Ret(fd as i64))
    }

    fn plan_socket_state(
        &mut self,
        plan: LinuxPlan,
        state: &'static str,
    ) -> Result<LinuxCallResult, &'static str> {
        let operation = match plan.kind {
            PlanKind::Bind => "bind",
            PlanKind::Listen => "listen",
            PlanKind::Connect => "connect",
            _ => "socket-state",
        };
        if self
            .require_capability("linux_syscall", "linux.socket", operation)
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }

        let fd = u32::try_from(plan.args[0]).map_err(|_| "socket fd overflowed")?;
        let (socket_id, _, handle) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("socket snapshot: {}", reason);
                return Err("socket snapshot trapped");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        let result = match plan.kind {
            PlanKind::Bind => {
                let addr_len =
                    u32::try_from(plan.args[2]).map_err(|_| "bind addr_len overflowed")?;
                self.linux_socket.bind_socket(socket_id, addr_len)
            }
            PlanKind::Listen => {
                let backlog =
                    u32::try_from(plan.args[1]).map_err(|_| "listen backlog overflowed")?;
                self.linux_socket.listen_socket(socket_id, backlog)
            }
            PlanKind::Connect => {
                let addr_len =
                    u32::try_from(plan.args[2]).map_err(|_| "connect addr_len overflowed")?;
                self.linux_socket.connect_socket(socket_id, addr_len)
            }
            _ => Ok(()),
        };
        match result {
            Ok(()) => {
                self.semantic.record_socket_state_changed(handle.id, state);
                Ok(LinuxCallResult::Ret(0))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket {}: {}", operation, reason);
                Err("linux_socket_service trapped during socket state change")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_accept(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("linux_syscall", "linux.socket", "accept")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "accept fd overflowed")?;
        let (socket_id, _, _) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("accept socket snapshot: {}", reason);
                return Err("socket snapshot trapped during accept");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        match self.linux_socket.accept_socket(socket_id) {
            Ok(_) => Ok(LinuxCallResult::Ret(-(ERR_EOPNOTSUPP as i64))),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket accept: {}", reason);
                Err("linux_socket_service trapped during accept")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_epoll_wait(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("epoll_service", "epoll.instance", "wait")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
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
            Ok(()) => {
                self.record_wait_token(token);
                Ok(LinuxCallResult::Pending(token))
            }
            Err(ServiceCallError::Errno(errno)) => {
                self.semantic.record_wait_cancelled(token.id, errno);
                self.semantic
                    .record_failure_effect(FailureEffect::CancelWaitToken {
                        wait: token.id,
                        errno,
                    });
                Ok(LinuxCallResult::Ret(-(errno as i64)))
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_wait arm_wait: {}", reason);
                self.record_service_trap("epoll_service", reason);
                Err("epoll_service trapped during epoll_wait")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_epoll_ready(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("epoll_service", "epoll.instance", "wait")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
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

    fn plan_sendto(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("linux_syscall", "linux.socket", "send")
            .is_err()
            || self
                .require_capability("net_core", "net.socket", "send")
                .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }

        let fd = u32::try_from(plan.args[0]).map_err(|_| "sendto fd overflowed")?;
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "sendto ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "sendto len overflowed")?;
        let bytes = self.linux.read_bytes(ptr, len)?;
        let (socket_id, ready_key, handle) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("sendto socket snapshot: {}", reason);
                return Err("socket snapshot trapped during sendto");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        match self.linux_socket.send_socket(socket_id, len) {
            Ok(_) => {}
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket send: {}", reason);
                return Err("linux_socket_service trapped during sendto");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        }
        match self.net_core.send_socket(socket_id, &bytes) {
            Ok(count) => {
                let frame = match self.net_core.take_tx_frame(socket_id) {
                    Ok(frame) => frame,
                    Err(ServiceCallError::Errno(errno)) => {
                        return Ok(LinuxCallResult::Ret(-(errno as i64)));
                    }
                    Err(ServiceCallError::Trap(reason)) => {
                        crate::kwarn!("net_core take_tx_frame: {}", reason);
                        return Err("net_core trapped while preparing send frame");
                    }
                    Err(ServiceCallError::Invalid(err)) => return Err(err),
                };
                match self
                    .net_driver
                    .submit_tx_frame(interrupts::tick_count(), &frame)
                {
                    Ok(_) => {}
                    Err(ServiceCallError::Errno(errno)) => {
                        return Ok(LinuxCallResult::Ret(-(errno as i64)));
                    }
                    Err(ServiceCallError::Trap(reason)) => {
                        crate::kwarn!("driver_virtio_net submit_tx_frame: {}", reason);
                        return Err("driver_virtio_net trapped while submitting tx frame");
                    }
                    Err(ServiceCallError::Invalid(err)) => return Err(err),
                }
                self.semantic.record_packet_transmitted(
                    self.net.interface.id,
                    Some(handle.id),
                    ready_key,
                    count as usize,
                );
                Ok(LinuxCallResult::Ret(count as i64))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("net_core send_socket: {}", reason);
                Err("net_core trapped during sendto")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_recvfrom(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("linux_syscall", "linux.socket", "recv")
            .is_err()
            || self
                .require_capability("net_core", "net.socket", "recv")
                .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }

        let fd = u32::try_from(plan.args[0]).map_err(|_| "recvfrom fd overflowed")?;
        let count = u32::try_from(plan.args[2]).map_err(|_| "recvfrom count overflowed")?;
        let (socket_id, _, _) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("recvfrom socket snapshot: {}", reason);
                return Err("socket snapshot trapped during recvfrom");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        match self.net_core.recv_socket(socket_id, count) {
            Ok(bytes) => {
                let _ = self.linux_socket.recv_socket(socket_id, bytes.len() as u32);
                Ok(LinuxCallResult::Bytes(bytes))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("net_core recv_socket: {}", reason);
                Err("net_core trapped during recvfrom")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_setsockopt(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("linux_syscall", "linux.socket", "setsockopt")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "setsockopt fd overflowed")?;
        let level = u32::try_from(plan.args[1]).map_err(|_| "setsockopt level overflowed")?;
        let optname = u32::try_from(plan.args[2]).map_err(|_| "setsockopt optname overflowed")?;
        let optlen = u32::try_from(plan.args[4]).map_err(|_| "setsockopt optlen overflowed")?;
        let (socket_id, _, _) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("setsockopt socket snapshot: {}", reason);
                return Err("socket snapshot trapped during setsockopt");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        match self
            .linux_socket
            .setsockopt(socket_id, level, optname, optlen)
        {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket setsockopt: {}", reason);
                Err("linux_socket_service trapped during setsockopt")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_getsockopt(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("linux_syscall", "linux.socket", "getsockopt")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "getsockopt fd overflowed")?;
        let level = u32::try_from(plan.args[1]).map_err(|_| "getsockopt level overflowed")?;
        let optname = u32::try_from(plan.args[2]).map_err(|_| "getsockopt optname overflowed")?;
        let (socket_id, _, _) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("getsockopt socket snapshot: {}", reason);
                return Err("socket snapshot trapped during getsockopt");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        match self.linux_socket.getsockopt(socket_id, level, optname) {
            Ok(value) => Ok(LinuxCallResult::Ret(value as i64)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket getsockopt: {}", reason);
                Err("linux_socket_service trapped during getsockopt")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn plan_fcntl(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("linux_syscall", "linux.socket", "fcntl")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "fcntl fd overflowed")?;
        match self.validate_fd_handle(fd) {
            Ok(()) => {}
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("fcntl fd validation: {}", reason);
                return Err("fcntl fd validation trapped");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        }
        let cmd = u32::try_from(plan.args[1]).map_err(|_| "fcntl cmd overflowed")?;
        let arg = plan.args[2];
        if let Ok((socket_id, _, _)) = self.socket_fd_snapshot(fd) {
            return match self.linux_socket.fcntl(socket_id, cmd, arg) {
                Ok(value) => Ok(LinuxCallResult::Ret(value as i64)),
                Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("linux_socket fcntl: {}", reason);
                    Err("linux_socket_service trapped during fcntl")
                }
                Err(ServiceCallError::Invalid(err)) => Err(err),
            };
        }
        Ok(LinuxCallResult::Ret(0))
    }

    fn plan_mmap(&mut self, _plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(-(ERR_EOPNOTSUPP as i64)))
    }

    fn plan_munmap(&mut self, _plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(0))
    }

    fn plan_poll(&mut self, _plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(-(ERR_ENOSYS as i64)))
    }

    fn plan_read(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
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

    fn plan_close(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self
            .require_capability("linux_syscall", "fd.table", "close")
            .is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "close plan fd overflowed")?;
        if fd < 3 {
            return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64)));
        }

        let Some(handle) = self.fd_handle(fd) else {
            return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64)));
        };
        if self.validate_resource_handle(handle).is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64)));
        }

        let closing_socket = self.fd_entry(fd).and_then(|entry| match &entry.resource {
            FdResource::Socket { socket_id, .. } => Some(*socket_id as u32),
            _ => None,
        });
        if let Some(socket_id) = closing_socket {
            if self
                .require_capability("linux_syscall", "linux.socket", "close")
                .is_err()
                || self
                    .require_capability("net_core", "net.socket", "close")
                    .is_err()
            {
                return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
            }
            match self.linux_socket.close_socket(socket_id) {
                Ok(()) | Err(ServiceCallError::Errno(ERR_EBADF)) => {}
                Err(ServiceCallError::Errno(errno)) => {
                    return Ok(LinuxCallResult::Ret(-(errno as i64)));
                }
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("linux_socket close: {}", reason);
                    return Err("linux_socket_service trapped during close");
                }
                Err(ServiceCallError::Invalid(err)) => return Err(err),
            }
            match self.net_core.close_socket(socket_id) {
                Ok(()) | Err(ServiceCallError::Errno(ERR_EBADF)) => {}
                Err(ServiceCallError::Errno(errno)) => {
                    return Ok(LinuxCallResult::Ret(-(errno as i64)));
                }
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("net_core close: {}", reason);
                    return Err("net_core trapped during close");
                }
                Err(ServiceCallError::Invalid(err)) => return Err(err),
            }
        }

        let slot = self
            .fd_table
            .get_mut(fd as usize)
            .ok_or("close targeted an out-of-range file descriptor")?;
        if slot.take().is_none() {
            return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64)));
        }
        if let Some(slot) = self.fd_handles.get_mut(fd as usize)
            && let Some(handle) = slot.take()
        {
            if closing_socket.is_some() {
                self.semantic
                    .record_socket_state_changed(handle.id, "closed");
            }
            self.semantic.close_resource(handle.id);
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
        self.require_capability("vfs_service", "vfs.namespace", "lookup")
            .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
        let info = self.vfs.lookup(path, false)?;
        match info.route {
            ServiceRoute::Vfs => Ok(info),
            ServiceRoute::Procfs => {
                self.require_capability("procfs_service", "procfs.tree", "lookup")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                let node = self.procfs_mut().lookup(path, false)?;
                Ok(LookupInfo {
                    route: ServiceRoute::Procfs,
                    node,
                })
            }
            ServiceRoute::Devfs => {
                self.require_capability("devfs_service", "device.pulse", "read")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
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
            ServiceRoute::Vfs => {
                self.require_capability("vfs_service", "vfs.namespace", "read")
                    .map_err(|_| ServiceCallError::Errno(ERR_EPERM))?;
                self.vfs.read_file(&path, false)?
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

    fn read_link_path(&mut self, path: &[u8]) -> Result<Vec<u8>, ServiceCallError> {
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

    fn alloc_fd(&mut self, entry: FdEntry) -> u32 {
        let resource_kind = fd_resource_kind(&entry.resource);
        let resource_label = fd_resource_label(&entry.resource);
        let owner_task = Some(self.scheduler.current_task());
        let resource_id =
            self.semantic
                .register_resource(resource_kind, owner_task, &resource_label);

        if let Some(fd) = (3..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            self.fd_table[fd] = Some(entry);
            self.ensure_fd_handle_slot(fd);
            self.fd_handles[fd] = self.semantic.resource_handle(resource_id);
            return fd as u32;
        }

        self.fd_table.push(Some(entry));
        self.fd_handles
            .push(self.semantic.resource_handle(resource_id));
        (self.fd_table.len() - 1) as u32
    }

    fn ensure_fd_handle_slot(&mut self, fd: usize) {
        while self.fd_handles.len() <= fd {
            self.fd_handles.push(None);
        }
    }

    fn fd_entry(&self, fd: u32) -> Option<&FdEntry> {
        self.fd_table.get(fd as usize)?.as_ref()
    }

    fn fd_handle(&self, fd: u32) -> Option<ResourceHandle> {
        self.fd_handles.get(fd as usize).copied().flatten()
    }

    fn socket_for_ready_key(&self, ready_key: u64) -> Option<(u32, ResourceHandle)> {
        for (fd, entry) in self.fd_table.iter().enumerate() {
            let Some(entry) = entry else {
                continue;
            };
            let FdResource::Socket {
                socket_id,
                ready_key: socket_key,
            } = &entry.resource
            else {
                continue;
            };
            if *socket_key == ready_key {
                let handle = self.fd_handle(fd as u32)?;
                return Some((*socket_id as u32, handle));
            }
        }
        None
    }

    fn socket_resource_for_ready_key(&self, ready_key: u64) -> Option<ResourceHandle> {
        self.socket_for_ready_key(ready_key)
            .map(|(_, handle)| handle)
    }

    fn socket_fd_snapshot(
        &mut self,
        fd: u32,
    ) -> Result<(u32, u64, ResourceHandle), ServiceCallError> {
        self.validate_fd_handle(fd)?;
        let entry = self
            .fd_entry(fd)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        let FdResource::Socket {
            socket_id,
            ready_key,
        } = &entry.resource
        else {
            return Err(ServiceCallError::Errno(ERR_ENOTSOCK));
        };
        let handle = self
            .fd_handle(fd)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        Ok((*socket_id as u32, *ready_key, handle))
    }

    fn socket_ready_key_is_readable(&mut self, ready_key: u64) -> bool {
        let Some((socket_id, _)) = self.socket_for_ready_key(ready_key) else {
            return false;
        };
        self.net_core
            .poll_socket(socket_id)
            .map(|events| events & EPOLLIN != 0)
            .unwrap_or(false)
    }

    fn notify_ready_key(&mut self, ready_key: u64, context: &str) {
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

    fn validate_fd_handle(&mut self, fd: u32) -> Result<(), ServiceCallError> {
        let handle = self
            .fd_handle(fd)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        self.validate_resource_handle(handle)
            .map_err(|_| ServiceCallError::Errno(ERR_EBADF))
    }

    fn service_fd_snapshot(
        &mut self,
        fd: u32,
    ) -> Result<(ServiceRoute, NodeKind, usize, Vec<u8>), ServiceCallError> {
        self.validate_fd_handle(fd)?;
        let entry = self
            .fd_entry(fd)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        match &entry.resource {
            FdResource::ServiceNode { route, node, path } => {
                Ok((*route, *node, entry.cursor, path.clone()))
            }
            FdResource::EpollInstance { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
            FdResource::Socket { .. } => Err(ServiceCallError::Errno(ERR_EBADF)),
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

    fn epoll_id_from_fd(&mut self, fd: u32) -> Result<u32, ServiceCallError> {
        self.validate_fd_handle(fd)?;
        match self.fd_entry(fd) {
            Some(FdEntry {
                resource: FdResource::EpollInstance { epoll_id },
                ..
            }) => Ok(*epoll_id),
            _ => Err(ServiceCallError::Errno(ERR_EBADF)),
        }
    }

    fn fd_ready_key(&mut self, fd: u32) -> Result<u64, ServiceCallError> {
        self.validate_fd_handle(fd)?;
        let entry = self
            .fd_entry(fd)
            .ok_or(ServiceCallError::Errno(ERR_EBADF))?;
        match &entry.resource {
            FdResource::ServiceNode {
                route: ServiceRoute::Devfs,
                path,
                ..
            } => PulseDevice::ready_key_for_path(path).ok_or(ServiceCallError::Errno(ERR_EINVAL)),
            FdResource::Socket { ready_key, .. } => Ok(*ready_key),
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
        self.validate_wait_token(token)
            .map_err(|_| "wait token generation check failed before blocking")?;
        if let Err(err) = crate::substrate::dmw::assert_quiescent() {
            self.semantic
                .record_failure_effect(FailureEffect::CompleteWithErrno(ERR_EFAULT));
            return Err(err);
        }
        loop {
            self.pump_async_sources();

            if let Some(resolution) = self.waits.take_resolution(token) {
                self.validate_wait_token(token)
                    .map_err(|_| "wait token generation check failed before resume")?;
                self.semantic
                    .set_task_state(token.owner_task, TaskState::Running);
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
                        self.semantic
                            .record_failure_effect(FailureEffect::CancelWaitToken {
                                wait: token.id,
                                errno,
                            });
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
                        self.semantic
                            .record_failure_effect(FailureEffect::RestartSyscall {
                                wait: Some(token.id),
                            });
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
            self.record_scheduler_event(event);
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

        let now_ticks = interrupts::tick_count();
        for _ in 0..8 {
            let event = match self.net_driver.poll_device(now_ticks) {
                Ok(event) => event,
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("driver_virtio_net poll: {}", reason);
                    break;
                }
                Err(ServiceCallError::Invalid(err)) => {
                    crate::kwarn!("driver_virtio_net poll: {}", err);
                    break;
                }
                Err(ServiceCallError::Errno(errno)) => {
                    crate::kwarn!("driver_virtio_net poll errno={}", errno);
                    break;
                }
            };
            match event.kind {
                DriverNetEventKind::None => break,
                DriverNetEventKind::Irq => self.semantic.record_device_irq_delivered(
                    self.net.irq.id,
                    self.net.device.id,
                    "virtio-net-rx",
                ),
                DriverNetEventKind::DmaSubmitted => self.semantic.record_dma_submitted(
                    self.net.dma_buffer.id,
                    self.net.device.id,
                    event.len as usize,
                ),
                DriverNetEventKind::DmaCompleted => self.semantic.record_dma_completed(
                    self.net.dma_buffer.id,
                    self.net.device.id,
                    event.len as usize,
                ),
                DriverNetEventKind::DriverCompletion => self
                    .semantic
                    .record_driver_completion(self.net.device.id, "virtio-net-rx"),
                DriverNetEventKind::PacketRx => {
                    match self.net_core.deliver_packet_frame(&event.frame) {
                        Ok(Some(ready_key)) => {
                            let socket = self
                                .socket_resource_for_ready_key(ready_key)
                                .map(|handle| handle.id);
                            self.semantic.record_packet_received(
                                self.net.interface.id,
                                socket,
                                ready_key,
                                event.len as usize,
                            );
                            self.notify_ready_key(ready_key, "epoll net ready notification");
                        }
                        Ok(None) => {
                            self.semantic.record_packet_received(
                                self.net.interface.id,
                                None,
                                0,
                                event.len as usize,
                            );
                        }
                        Err(ServiceCallError::Trap(reason)) => {
                            crate::kwarn!("net_core deliver_packet_frame: {}", reason);
                        }
                        Err(ServiceCallError::Invalid(err)) => {
                            crate::kwarn!("net_core deliver_packet_frame: {}", err);
                        }
                        Err(ServiceCallError::Errno(errno)) => {
                            crate::kwarn!("net_core deliver_packet_frame errno={}", errno);
                        }
                    }
                }
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
