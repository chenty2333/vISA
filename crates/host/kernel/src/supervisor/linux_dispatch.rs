use alloc::vec::Vec;

use vmos_abi::{
    ERR_EBADF, NodeKind, PackedStep, PlanKind, SYS_CLOSE, SYS_GETCWD, SYS_GETDENTS64, SYS_OPENAT,
    SYS_READ, SYS_READLINKAT, SYS_UNAME, SYS_WRITE, StepTag, SyscallContext,
};

use super::{
    events::Event,
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{FdResource, ServiceCallError, WaitRestartClass, WaitToken},
};

const CURRENT_CWD: &[u8] = b"/sandbox";
const UNAME_BYTES: &[u8] = b"prototype2";

impl<'engine> PrototypeRuntime<'engine> {
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
        self.scheduler.push_event(Event::WaitRestart(token.id, class));
    }
    pub(crate) fn fd_path(&mut self, fd: u32) -> Result<Vec<u8>, i32> {
        self.validate_fd_handle(fd).map_err(|_| ERR_EBADF)?;
        let entry = self.fd_entry(fd).ok_or(ERR_EBADF)?;
        match &entry.resource {
            FdResource::ServiceNode { path, .. } => Ok(path.clone()),
            FdResource::EpollInstance { .. } => Err(ERR_EBADF),
            FdResource::Socket { .. } => Err(ERR_EBADF),
            FdResource::PipeEnd { .. } => Err(ERR_EBADF),
            FdResource::SocketPairEnd { .. } => Err(ERR_EBADF),
            FdResource::EventFd { .. } => Err(ERR_EBADF),
        }
    }
    pub(crate) fn path_kind(&mut self, path: &[u8]) -> Result<NodeKind, i32> {
        self.lookup_path(path).map(|info| info.node).map_err(|err| match err {
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
        let step = self.linux.dispatch_futex_raw(key, op, val, timeout_ms, current_word)?;
        self.execute_linux_step(label, step)
    }
    pub(crate) fn uname_abi(&mut self) -> Result<Vec<u8>, &'static str> {
        let release = self.uname()?;
        self.linux.encode_uname(&release)
    }
    pub(crate) fn getdents64_abi(&mut self, fd: u32, count: u32) -> Result<Vec<u8>, &'static str> {
        let dir_path = self.fd_path(fd).map_err(|_| "getdents64 targeted an unknown fd")?;
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
}
