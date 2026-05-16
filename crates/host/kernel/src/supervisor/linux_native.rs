use alloc::vec::Vec;

use vmos_abi::{
    ERR_EAGAIN, ERR_EINVAL, ERR_ENOSYS, FUTEX_CMD_MASK, FUTEX_CMP_REQUEUE, FUTEX_CMP_REQUEUE_PI,
    FUTEX_REQUEUE, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAIT_REQUEUE_PI, FUTEX_WAKE,
    FUTEX_WAKE_BITSET, PackedStep, PlanKind, RestartClass, SYS_ACCEPT, SYS_BIND, SYS_CLOCK_ADJTIME,
    SYS_CLOSE, SYS_CONNECT, SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT, SYS_EXIT,
    SYS_EXIT_GROUP, SYS_FCNTL, SYS_FGETXATTR, SYS_FLISTXATTR, SYS_FREMOVEXATTR, SYS_FSETXATTR,
    SYS_FUTEX, SYS_GETCWD, SYS_GETDENTS64, SYS_GETRLIMIT, SYS_GETSOCKOPT, SYS_LISTEN, SYS_MMAP,
    SYS_MUNMAP, SYS_NANOSLEEP, SYS_OPENAT, SYS_POLL, SYS_PRLIMIT64, SYS_READ, SYS_READLINKAT,
    SYS_RECVFROM, SYS_RENAME, SYS_RENAMEAT, SYS_RENAMEAT2, SYS_SECCOMP, SYS_SENDTO, SYS_SETRLIMIT,
    SYS_SETSOCKOPT, SYS_SOCKET, SYS_UNAME, SYS_WRITE, SyscallContext, is_stdio_fd,
};

use super::{
    super::{engine::RuntimeOnlyExecutor, types::WaitRestartClass},
    LinuxPlan,
};

const ARG_BUFFER_BASE: u32 = 0x1000;
const RESULT_BUFFER_CAPACITY: usize = 1024;
const PENDING_SLOTS: usize = 8;
const UTS_FIELD_LEN: usize = 65;
const AT_FDCWD_ENCODED: u64 = -100i64 as u64;

#[derive(Clone, Copy, Debug)]
enum PendingOp {
    Empty,
    Sleep,
    FutexWait,
    EpollWait { epfd: u32, max_events: u32, timeout_ms: u64 },
}

pub(crate) struct LinuxFrontend {
    arg_buffer: Vec<u8>,
    result_buffer: Vec<u8>,
    plan_args: [u64; 6],
    pending_ops: [PendingOp; PENDING_SLOTS],
}

impl LinuxFrontend {
    pub(crate) fn new(_engine: &RuntimeOnlyExecutor) -> Result<Self, &'static str> {
        Ok(Self {
            arg_buffer: Vec::new(),
            result_buffer: Vec::new(),
            plan_args: [0; 6],
            pending_ops: [PendingOp::Empty; PENDING_SLOTS],
        })
    }

    pub(crate) fn dispatch(&mut self, ctx: SyscallContext) -> Result<u64, &'static str> {
        let [a0, a1, a2, a3, a4, a5] = ctx.args;
        let step = match ctx.nr {
            SYS_READ => self.plan_read(a0, a2),
            SYS_WRITE => self.plan_write(a0, a1, a2),
            SYS_CLOSE => self.plan_close(a0),
            SYS_NANOSLEEP => self.dispatch_nanosleep(a0, a1),
            SYS_FUTEX => self.dispatch_futex(a0, a1, a2, a3, a4, a5),
            SYS_EPOLL_CREATE1 => self.plan_epoll_create1(a0),
            SYS_EPOLL_CTL => self.plan_epoll_ctl(a0, a1, a2, a3, a4),
            SYS_EPOLL_WAIT => self.plan_epoll_wait(a0, a1, a2),
            SYS_SOCKET => self.plan_socket(a0, a1, a2),
            SYS_BIND => self.plan_bind(a0, a1, a2, a3, a4, a5),
            SYS_CONNECT => self.plan_connect(a0, a1, a2, a3, a4, a5),
            SYS_LISTEN => self.plan_listen(a0, a1),
            SYS_ACCEPT => self.plan_accept(a0, a1, a2),
            SYS_SENDTO => self.plan_sendto(a0, a1, a2, a3, a4, a5),
            SYS_RECVFROM => self.plan_recvfrom(a0, a1, a2, a3, a4, a5),
            SYS_SETSOCKOPT => self.plan_setsockopt(a0, a1, a2, a3, a4),
            SYS_GETSOCKOPT => self.plan_getsockopt(a0, a1, a2, a3, a4),
            SYS_FCNTL => self.plan_fcntl(a0, a1, a2),
            SYS_MMAP => self.plan_mmap(a0, a1, a2, a3, a4, a5),
            SYS_MUNMAP => self.plan_munmap(a0, a1),
            SYS_POLL => self.plan_poll(a0, a1, a2),
            SYS_UNAME => self.plan_simple(PlanKind::Uname),
            SYS_GETCWD => self.plan_getcwd(a1),
            SYS_GETDENTS64 => self.plan_getdents(a0, a2),
            SYS_OPENAT => self.plan_openat(a0, a1, a2, a3, a4),
            SYS_READLINKAT => self.plan_readlinkat(a0, a1, a2),
            SYS_FSETXATTR => self.plan_fsetxattr(a0, a1, a2, a3, a4, a5),
            SYS_FGETXATTR => self.plan_fgetxattr(a0, a1, a2, a3, a4),
            SYS_FLISTXATTR => self.plan_flistxattr(a0, a1, a2),
            SYS_FREMOVEXATTR => self.plan_fremovexattr(a0, a1, a2),
            SYS_GETRLIMIT => self.plan_getrlimit(a0, a1),
            SYS_SETRLIMIT => self.plan_setrlimit(a0, a1),
            SYS_PRLIMIT64 => self.plan_prlimit64(a0, a1, a2, a3),
            SYS_CLOCK_ADJTIME => self.plan_clock_adjtime(a0, a1),
            SYS_RENAME => self.plan_renameat2(
                AT_FDCWD_ENCODED,
                a0,
                a1,
                AT_FDCWD_ENCODED,
                a2,
                pack_rename_len_flags(a3, 0),
            ),
            SYS_RENAMEAT => self.plan_renameat2(a0, a1, a2, a3, a4, pack_rename_len_flags(a5, 0)),
            SYS_RENAMEAT2 => self.plan_renameat2(a0, a1, a2, a3, a4, a5),
            SYS_SECCOMP => self.plan_seccomp(a0, a1, a2),
            SYS_EXIT | SYS_EXIT_GROUP => PackedStep::exit(a0 as i32),
            _ => PackedStep::error(-ERR_ENOSYS),
        };
        Ok(step.raw())
    }

    pub(crate) fn resume_wait(&mut self, token: u32) -> Result<u64, &'static str> {
        let step = match self.take_pending_op(token) {
            Some(PendingOp::Sleep) => PackedStep::ready(0),
            Some(PendingOp::FutexWait) => PackedStep::ready(0),
            Some(PendingOp::EpollWait { epfd, max_events, .. }) => {
                self.reset_plan(PlanKind::EpollReady, [epfd as u64, max_events as u64, 0, 0, 0, 0]);
                PackedStep::plan(PlanKind::EpollReady)
            }
            _ => PackedStep::error(-ERR_EINVAL),
        };
        Ok(step.raw())
    }

    pub(crate) fn cancel_wait(&mut self, token: u32, errno: i32) -> Result<u64, &'static str> {
        let step = if self.take_pending_op(token).is_some() {
            PackedStep::error(-errno)
        } else {
            PackedStep::error(-ERR_EINVAL)
        };
        Ok(step.raw())
    }

    pub(crate) fn restart_wait(
        &mut self,
        token: u32,
        class: WaitRestartClass,
    ) -> Result<u64, &'static str> {
        let step = match self.peek_pending_op(token) {
            Some(PendingOp::EpollWait { epfd, max_events, timeout_ms }) => {
                self.restart_epoll_wait(token, epfd, max_events, timeout_ms, class)
            }
            _ => PackedStep::error(-ERR_EINVAL),
        };
        Ok(step.raw())
    }

    pub(crate) fn dispatch_sleep_ms(&mut self, delay_ms: u64) -> Result<u64, &'static str> {
        Ok(self.plan_sleep(delay_ms).raw())
    }

    pub(crate) fn dispatch_futex_raw(
        &mut self,
        key: u64,
        op: u64,
        val: u64,
        timeout_ms: u64,
        current_word: u64,
    ) -> Result<u64, &'static str> {
        Ok(self.plan_futex(key, op, val, timeout_ms, current_word).raw())
    }

    pub(crate) fn write_arg_bytes(&mut self, bytes: &[u8]) -> Result<(u32, u32), &'static str> {
        if bytes.len() > u32::MAX as usize {
            return Err("linux arg buffer overflowed");
        }
        self.arg_buffer.clear();
        self.arg_buffer.extend_from_slice(bytes);
        Ok((ARG_BUFFER_BASE, bytes.len() as u32))
    }

    pub(crate) fn read_bytes(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, &'static str> {
        let start = ptr
            .checked_sub(ARG_BUFFER_BASE)
            .ok_or("linux native pointer was outside arg buffer")? as usize;
        let end = start.checked_add(len as usize).ok_or("linux native read overflowed")?;
        if end > self.arg_buffer.len() {
            return Err("linux native pointer was outside arg buffer");
        }
        Ok(self.arg_buffer[start..end].to_vec())
    }

    pub(crate) fn write_bytes(&mut self, ptr: u32, bytes: &[u8]) -> Result<(), &'static str> {
        let start = ptr
            .checked_sub(ARG_BUFFER_BASE)
            .ok_or("linux native pointer was outside arg buffer")? as usize;
        let end = start.checked_add(bytes.len()).ok_or("linux native write overflowed")?;
        if end > self.arg_buffer.len() {
            return Err("linux native pointer was outside arg buffer");
        }
        self.arg_buffer[start..end].copy_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn encode_uname(&mut self, release: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.result_buffer.clear();
        push_c_field(&mut self.result_buffer, b"Linux");
        push_c_field(&mut self.result_buffer, b"prototype2");
        push_c_field(&mut self.result_buffer, release);
        push_c_field(&mut self.result_buffer, b"supervisor-world");
        push_c_field(&mut self.result_buffer, b"x86_64");
        push_c_field(&mut self.result_buffer, b"");
        Ok(self.result_buffer.clone())
    }

    pub(crate) fn encode_dirents64(
        &mut self,
        records: &[u8],
        max_len: u32,
    ) -> Result<Vec<u8>, &'static str> {
        pack_dirents64(records, max_len as usize)
    }

    pub(crate) fn encode_epoll_events(
        &mut self,
        records: &[u8],
        max_events: u32,
    ) -> Result<Vec<u8>, &'static str> {
        pack_epoll_events(records, max_events as usize)
    }

    pub(crate) fn current_plan(&mut self, kind: PlanKind) -> Result<LinuxPlan, &'static str> {
        Ok(LinuxPlan { kind, args: self.plan_args })
    }

    #[allow(dead_code)]
    pub(crate) fn decode_step(raw: u64) -> vmos_abi::DecodedStep {
        PackedStep::decode(raw)
    }

    fn dispatch_nanosleep(&mut self, ptr: u64, len: u64) -> PackedStep {
        match self.parse_timespec_ms(ptr as u32, len as u32) {
            Ok(delay_ms) => self.plan_sleep(delay_ms),
            Err(_) => PackedStep::error(-ERR_EINVAL),
        }
    }

    fn dispatch_futex(
        &mut self,
        key: u64,
        op: u64,
        val: u64,
        timeout_ptr: u64,
        timeout_len: u64,
        current_word: u64,
    ) -> PackedStep {
        let command = (op as u32) & FUTEX_CMD_MASK;
        let timeout_ms = match command {
            FUTEX_WAIT | FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI => {
                if timeout_ptr == 0 || timeout_len == 0 {
                    u64::MAX
                } else {
                    match self.parse_timespec_ms(timeout_ptr as u32, timeout_len as u32) {
                        Ok(ms) => ms,
                        Err(_) => return PackedStep::error(-ERR_EINVAL),
                    }
                }
            }
            FUTEX_REQUEUE | FUTEX_CMP_REQUEUE | FUTEX_CMP_REQUEUE_PI => timeout_ptr,
            _ => u64::MAX,
        };
        let aux_word = match command {
            FUTEX_REQUEUE | FUTEX_CMP_REQUEUE | FUTEX_CMP_REQUEUE_PI => timeout_len,
            _ => current_word,
        };
        self.plan_futex(key, op, val, timeout_ms, aux_word)
    }

    fn plan_sleep(&mut self, duration_ms: u64) -> PackedStep {
        let clamped = duration_ms.min(u32::MAX as u64) as u32;
        let Some(resume_cookie) = self.allocate_pending_op(PendingOp::Sleep) else {
            return PackedStep::error(-ERR_EINVAL);
        };
        self.reset_plan(PlanKind::Sleep, [resume_cookie as u64, clamped as u64, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::Sleep)
    }

    fn plan_futex(
        &mut self,
        key: u64,
        op: u64,
        val: u64,
        timeout_ms: u64,
        current_word: u64,
    ) -> PackedStep {
        match (op as u32) & FUTEX_CMD_MASK {
            FUTEX_WAIT => self.plan_futex_wait(key, val, timeout_ms, current_word),
            FUTEX_WAKE => self.plan_futex_wake(key, val),
            FUTEX_WAIT_BITSET => self.plan_futex_wait_bitset(key, val, timeout_ms, current_word),
            FUTEX_WAIT_REQUEUE_PI => {
                self.plan_futex_wait_requeue_pi(key, val, timeout_ms, current_word)
            }
            FUTEX_WAKE_BITSET => self.plan_futex_wake_bitset(key, val, current_word),
            FUTEX_REQUEUE => self.plan_futex_requeue(key, val, timeout_ms, current_word, false),
            FUTEX_CMP_REQUEUE => self.plan_futex_requeue(key, val, timeout_ms, current_word, true),
            _ => PackedStep::error(-ERR_EINVAL),
        }
    }

    fn plan_futex_wait(
        &mut self,
        key: u64,
        expected: u64,
        timeout_ms: u64,
        current_word: u64,
    ) -> PackedStep {
        if current_word != expected {
            return PackedStep::error(-ERR_EAGAIN);
        }
        let Some(resume_cookie) = self.allocate_pending_op(PendingOp::FutexWait) else {
            return PackedStep::error(-ERR_EINVAL);
        };
        let timeout =
            if timeout_ms == u64::MAX { u64::MAX } else { timeout_ms.min(u32::MAX as u64) };
        self.reset_plan(PlanKind::FutexWait, [key, timeout, resume_cookie as u64, 0, 0, 0]);
        PackedStep::plan(PlanKind::FutexWait)
    }

    fn plan_futex_wake(&mut self, key: u64, count: u64) -> PackedStep {
        self.reset_plan(PlanKind::FutexWake, [key, count.min(u32::MAX as u64), 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::FutexWake)
    }

    fn plan_futex_wait_bitset(
        &mut self,
        key: u64,
        expected: u64,
        timeout_ms: u64,
        bitset: u64,
    ) -> PackedStep {
        if bitset == 0 {
            return PackedStep::error(-ERR_EINVAL);
        }
        let Some(resume_cookie) = self.allocate_pending_op(PendingOp::FutexWait) else {
            return PackedStep::error(-ERR_EINVAL);
        };
        let timeout =
            if timeout_ms == u64::MAX { u64::MAX } else { timeout_ms.min(u32::MAX as u64) };
        self.reset_plan(
            PlanKind::FutexWaitBitset,
            [key, timeout, resume_cookie as u64, bitset, expected, 0],
        );
        PackedStep::plan(PlanKind::FutexWaitBitset)
    }

    fn plan_futex_wait_requeue_pi(
        &mut self,
        key: u64,
        expected: u64,
        timeout_ms: u64,
        current_word: u64,
    ) -> PackedStep {
        if current_word != expected {
            return PackedStep::error(-ERR_EAGAIN);
        }
        let Some(resume_cookie) = self.allocate_pending_op(PendingOp::FutexWait) else {
            return PackedStep::error(-ERR_EINVAL);
        };
        let timeout =
            if timeout_ms == u64::MAX { u64::MAX } else { timeout_ms.min(u32::MAX as u64) };
        self.reset_plan(
            PlanKind::FutexWaitRequeuePi,
            [key, timeout, resume_cookie as u64, 0, 0, 0],
        );
        PackedStep::plan(PlanKind::FutexWaitRequeuePi)
    }

    fn plan_futex_wake_bitset(&mut self, key: u64, count: u64, bitset: u64) -> PackedStep {
        if bitset == 0 {
            return PackedStep::error(-ERR_EINVAL);
        }
        self.reset_plan(
            PlanKind::FutexWakeBitset,
            [key, count.min(u32::MAX as u64), bitset, 0, 0, 0],
        );
        PackedStep::plan(PlanKind::FutexWakeBitset)
    }

    fn plan_futex_requeue(
        &mut self,
        src_key: u64,
        wake_count: u64,
        requeue_count: u64,
        dst_key: u64,
        compare_checked: bool,
    ) -> PackedStep {
        let kind = if compare_checked { PlanKind::FutexCmpRequeue } else { PlanKind::FutexRequeue };
        self.reset_plan(
            kind,
            [
                src_key,
                requeue_count.min(u32::MAX as u64),
                dst_key,
                wake_count.min(u32::MAX as u64),
                0,
                0,
            ],
        );
        PackedStep::plan(kind)
    }

    fn plan_epoll_create1(&mut self, flags: u64) -> PackedStep {
        self.reset_plan(PlanKind::EpollCreate1, [flags as u32 as u64, 0, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::EpollCreate1)
    }

    fn plan_epoll_ctl(
        &mut self,
        epfd: u64,
        op: u64,
        fd: u64,
        events: u64,
        data: u64,
    ) -> PackedStep {
        self.reset_plan(PlanKind::EpollCtl, [epfd, op, fd, events, data, 0]);
        PackedStep::plan(PlanKind::EpollCtl)
    }

    fn plan_epoll_wait(&mut self, epfd: u64, max_events: u64, timeout_ms: u64) -> PackedStep {
        if max_events == 0 {
            return PackedStep::error(-ERR_EINVAL);
        }
        let Some(resume_cookie) = self.allocate_pending_op(PendingOp::EpollWait {
            epfd: epfd as u32,
            max_events: max_events as u32,
            timeout_ms,
        }) else {
            return PackedStep::error(-ERR_EINVAL);
        };
        self.reset_plan(
            PlanKind::EpollWait,
            [epfd, max_events, timeout_ms, resume_cookie as u64, 0, 0],
        );
        PackedStep::plan(PlanKind::EpollWait)
    }

    fn plan_socket(&mut self, domain: u64, ty: u64, protocol: u64) -> PackedStep {
        self.reset_plan(PlanKind::Socket, [domain, ty, protocol, 0, 0, 0]);
        PackedStep::plan(PlanKind::Socket)
    }

    fn plan_bind(
        &mut self,
        fd: u64,
        addr: u64,
        addr_len: u64,
        family: u64,
        ipv4_addr: u64,
        port: u64,
    ) -> PackedStep {
        self.reset_plan(PlanKind::Bind, [fd, addr, addr_len, family, ipv4_addr, port]);
        PackedStep::plan(PlanKind::Bind)
    }

    fn plan_connect(
        &mut self,
        fd: u64,
        addr: u64,
        addr_len: u64,
        family: u64,
        ipv4_addr: u64,
        port: u64,
    ) -> PackedStep {
        self.reset_plan(PlanKind::Connect, [fd, addr, addr_len, family, ipv4_addr, port]);
        PackedStep::plan(PlanKind::Connect)
    }

    fn plan_listen(&mut self, fd: u64, backlog: u64) -> PackedStep {
        self.reset_plan(PlanKind::Listen, [fd, backlog, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::Listen)
    }

    fn plan_accept(&mut self, fd: u64, addr: u64, addr_len: u64) -> PackedStep {
        self.reset_plan(PlanKind::Accept, [fd, addr, addr_len, 0, 0, 0]);
        PackedStep::plan(PlanKind::Accept)
    }

    fn plan_sendto(
        &mut self,
        fd: u64,
        ptr: u64,
        len: u64,
        flags: u64,
        addr: u64,
        addr_len: u64,
    ) -> PackedStep {
        self.reset_plan(PlanKind::SendTo, [fd, ptr, len, flags, addr, addr_len]);
        PackedStep::plan(PlanKind::SendTo)
    }

    fn plan_recvfrom(
        &mut self,
        fd: u64,
        ptr: u64,
        len: u64,
        flags: u64,
        addr: u64,
        addr_len: u64,
    ) -> PackedStep {
        self.reset_plan(PlanKind::RecvFrom, [fd, ptr, len, flags, addr, addr_len]);
        PackedStep::plan(PlanKind::RecvFrom)
    }

    fn plan_setsockopt(
        &mut self,
        fd: u64,
        level: u64,
        optname: u64,
        optval: u64,
        optlen: u64,
    ) -> PackedStep {
        self.reset_plan(PlanKind::SetSockOpt, [fd, level, optname, optval, optlen, 0]);
        PackedStep::plan(PlanKind::SetSockOpt)
    }

    fn plan_getsockopt(
        &mut self,
        fd: u64,
        level: u64,
        optname: u64,
        optval: u64,
        optlen: u64,
    ) -> PackedStep {
        self.reset_plan(PlanKind::GetSockOpt, [fd, level, optname, optval, optlen, 0]);
        PackedStep::plan(PlanKind::GetSockOpt)
    }

    fn plan_fcntl(&mut self, fd: u64, cmd: u64, arg: u64) -> PackedStep {
        const F_GETLK: u64 = 5;
        const F_SETLK: u64 = 6;
        const F_SETLKW: u64 = 7;

        if matches!(cmd, F_GETLK | F_SETLK | F_SETLKW) {
            let Ok(arg_ptr) = u32::try_from(arg) else {
                return PackedStep::error(-ERR_EINVAL);
            };
            let Ok((lock_type, whence, start, len)) = self.parse_flock(arg_ptr) else {
                return PackedStep::error(-ERR_EINVAL);
            };
            let kind = if cmd == F_GETLK { PlanKind::FcntlGetlk } else { PlanKind::FcntlSetlk };
            let command_or_ptr = if cmd == F_GETLK { arg } else { cmd };
            self.reset_plan(
                kind,
                [
                    fd,
                    command_or_ptr,
                    lock_type as i64 as u64,
                    whence as i64 as u64,
                    start as u64,
                    len as u64,
                ],
            );
            return PackedStep::plan(kind);
        }

        self.reset_plan(PlanKind::Fcntl, [fd, cmd, arg, 0, 0, 0]);
        PackedStep::plan(PlanKind::Fcntl)
    }

    fn plan_mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: u64,
        offset: u64,
    ) -> PackedStep {
        self.reset_plan(PlanKind::Mmap, [addr, len, prot, flags, fd, offset]);
        PackedStep::plan(PlanKind::Mmap)
    }

    fn plan_munmap(&mut self, addr: u64, len: u64) -> PackedStep {
        self.reset_plan(PlanKind::Munmap, [addr, len, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::Munmap)
    }

    fn plan_poll(&mut self, ptr: u64, nfds: u64, timeout_ms: u64) -> PackedStep {
        self.reset_plan(PlanKind::Poll, [ptr, nfds, timeout_ms, 0, 0, 0]);
        PackedStep::plan(PlanKind::Poll)
    }

    fn plan_clock_adjtime(&mut self, clock_id: u64, timex_ptr: u64) -> PackedStep {
        self.reset_plan(PlanKind::ClockAdjtime, [clock_id, timex_ptr, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::ClockAdjtime)
    }

    fn plan_seccomp(&mut self, operation: u64, flags: u64, args_ptr: u64) -> PackedStep {
        self.reset_plan(PlanKind::Seccomp, [operation, flags, args_ptr, 0, 0, 0]);
        PackedStep::plan(PlanKind::Seccomp)
    }

    fn plan_write(&mut self, fd: u64, ptr: u64, len: u64) -> PackedStep {
        if !is_stdio_fd(fd) && fd < 3 {
            return PackedStep::error(-ERR_EINVAL);
        }
        self.reset_plan(PlanKind::Write, [fd, ptr, len, 0, 0, 0]);
        PackedStep::plan(PlanKind::Write)
    }

    fn plan_openat(&mut self, dirfd: u64, ptr: u64, len: u64, flags: u64, mode: u64) -> PackedStep {
        if len == 0 {
            return PackedStep::error(-ERR_EINVAL);
        }
        self.reset_plan(PlanKind::OpenAt, [dirfd, ptr, len, flags, mode, 0]);
        PackedStep::plan(PlanKind::OpenAt)
    }

    fn plan_read(&mut self, fd: u64, count: u64) -> PackedStep {
        self.reset_plan(PlanKind::Read, [fd, count, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::Read)
    }

    fn plan_close(&mut self, fd: u64) -> PackedStep {
        self.reset_plan(PlanKind::Close, [fd, 0, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::Close)
    }

    fn plan_getdents(&mut self, fd: u64, count: u64) -> PackedStep {
        self.reset_plan(PlanKind::GetDents64, [fd, count, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::GetDents64)
    }

    fn plan_readlinkat(&mut self, dirfd: u64, ptr: u64, len: u64) -> PackedStep {
        if len == 0 {
            return PackedStep::error(-ERR_EINVAL);
        }
        self.reset_plan(PlanKind::ReadLinkAt, [dirfd, ptr, len, 0, 0, 0]);
        PackedStep::plan(PlanKind::ReadLinkAt)
    }

    fn plan_fsetxattr(
        &mut self,
        fd: u64,
        name_ptr: u64,
        name_len: u64,
        value_ptr: u64,
        value_len: u64,
        flags: u64,
    ) -> PackedStep {
        if name_len == 0 {
            return PackedStep::error(-ERR_EINVAL);
        }
        self.reset_plan(PlanKind::Fsetxattr, [fd, name_ptr, name_len, value_ptr, value_len, flags]);
        PackedStep::plan(PlanKind::Fsetxattr)
    }

    fn plan_fgetxattr(
        &mut self,
        fd: u64,
        name_ptr: u64,
        name_len: u64,
        value_ptr: u64,
        size: u64,
    ) -> PackedStep {
        if name_len == 0 {
            return PackedStep::error(-ERR_EINVAL);
        }
        self.reset_plan(PlanKind::Fgetxattr, [fd, name_ptr, name_len, value_ptr, size, 0]);
        PackedStep::plan(PlanKind::Fgetxattr)
    }

    fn plan_flistxattr(&mut self, fd: u64, list_ptr: u64, size: u64) -> PackedStep {
        self.reset_plan(PlanKind::Flistxattr, [fd, list_ptr, size, 0, 0, 0]);
        PackedStep::plan(PlanKind::Flistxattr)
    }

    fn plan_fremovexattr(&mut self, fd: u64, name_ptr: u64, name_len: u64) -> PackedStep {
        if name_len == 0 {
            return PackedStep::error(-ERR_EINVAL);
        }
        self.reset_plan(PlanKind::Fremovexattr, [fd, name_ptr, name_len, 0, 0, 0]);
        PackedStep::plan(PlanKind::Fremovexattr)
    }

    fn plan_prlimit64(
        &mut self,
        pid: u64,
        resource: u64,
        new_limit_ptr: u64,
        old_limit_ptr: u64,
    ) -> PackedStep {
        self.reset_plan(PlanKind::Prlimit64, [pid, resource, new_limit_ptr, old_limit_ptr, 0, 0]);
        PackedStep::plan(PlanKind::Prlimit64)
    }

    fn plan_getrlimit(&mut self, resource: u64, old_limit_ptr: u64) -> PackedStep {
        self.reset_plan(PlanKind::Getrlimit, [resource, old_limit_ptr, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::Getrlimit)
    }

    fn plan_setrlimit(&mut self, resource: u64, new_limit_ptr: u64) -> PackedStep {
        self.reset_plan(PlanKind::Setrlimit, [resource, new_limit_ptr, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::Setrlimit)
    }

    fn plan_renameat2(
        &mut self,
        old_dirfd: u64,
        old_ptr: u64,
        old_len: u64,
        new_dirfd: u64,
        new_ptr: u64,
        new_len_flags: u64,
    ) -> PackedStep {
        let new_len = new_len_flags & 0xffff_ffff;
        if old_len == 0 || new_len == 0 {
            return PackedStep::error(-ERR_EINVAL);
        }
        self.reset_plan(
            PlanKind::RenameAt2,
            [old_dirfd, old_ptr, old_len, new_dirfd, new_ptr, new_len_flags],
        );
        PackedStep::plan(PlanKind::RenameAt2)
    }

    fn plan_getcwd(&mut self, size: u64) -> PackedStep {
        self.reset_plan(PlanKind::GetCwd, [size, 0, 0, 0, 0, 0]);
        PackedStep::plan(PlanKind::GetCwd)
    }

    fn plan_simple(&mut self, kind: PlanKind) -> PackedStep {
        self.reset_plan(kind, [0, 0, 0, 0, 0, 0]);
        PackedStep::plan(kind)
    }

    fn reset_plan(&mut self, _kind: PlanKind, args: [u64; 6]) {
        self.plan_args = args;
    }

    fn allocate_pending_op(&mut self, op: PendingOp) -> Option<u32> {
        for (index, slot) in self.pending_ops.iter_mut().enumerate() {
            if matches!(slot, PendingOp::Empty) {
                *slot = op;
                return Some((index + 1) as u32);
            }
        }
        None
    }

    fn take_pending_op(&mut self, token: u32) -> Option<PendingOp> {
        if token == 0 || token as usize > PENDING_SLOTS {
            return None;
        }
        let slot = &mut self.pending_ops[token as usize - 1];
        let op = *slot;
        *slot = PendingOp::Empty;
        if matches!(op, PendingOp::Empty) { None } else { Some(op) }
    }

    fn peek_pending_op(&self, token: u32) -> Option<PendingOp> {
        if token == 0 || token as usize > PENDING_SLOTS {
            return None;
        }
        let op = self.pending_ops[token as usize - 1];
        if matches!(op, PendingOp::Empty) { None } else { Some(op) }
    }

    fn restart_epoll_wait(
        &mut self,
        resume_cookie: u32,
        epfd: u32,
        max_events: u32,
        timeout_ms: u64,
        class: RestartClass,
    ) -> PackedStep {
        let _ = class;
        self.reset_plan(
            PlanKind::EpollWait,
            [epfd as u64, max_events as u64, timeout_ms, resume_cookie as u64, 0, 0],
        );
        PackedStep::plan(PlanKind::EpollWait)
    }

    fn parse_timespec_ms(&mut self, ptr: u32, len: u32) -> Result<u64, i32> {
        if len != 16 {
            return Err(-ERR_EINVAL);
        }
        let bytes = self.read_bytes(ptr, len).map_err(|_| -ERR_EINVAL)?;
        let mut sec = [0u8; 8];
        let mut nsec = [0u8; 8];
        sec.copy_from_slice(&bytes[..8]);
        nsec.copy_from_slice(&bytes[8..16]);
        let tv_sec = i64::from_le_bytes(sec);
        let tv_nsec = i64::from_le_bytes(nsec);
        if tv_sec < 0 || tv_nsec < 0 {
            return Err(-ERR_EINVAL);
        }
        Ok((tv_sec as u64)
            .saturating_mul(1000)
            .saturating_add((tv_nsec as u64).div_ceil(1_000_000)))
    }

    fn parse_flock(&mut self, ptr: u32) -> Result<(i16, i16, i64, i64), i32> {
        let bytes = self.read_bytes(ptr, 32).map_err(|_| -ERR_EINVAL)?;
        let mut lock_type = [0u8; 2];
        let mut whence = [0u8; 2];
        let mut start = [0u8; 8];
        let mut len = [0u8; 8];
        lock_type.copy_from_slice(&bytes[0..2]);
        whence.copy_from_slice(&bytes[2..4]);
        start.copy_from_slice(&bytes[8..16]);
        len.copy_from_slice(&bytes[16..24]);
        Ok((
            i16::from_le_bytes(lock_type),
            i16::from_le_bytes(whence),
            i64::from_le_bytes(start),
            i64::from_le_bytes(len),
        ))
    }
}

fn push_c_field(out: &mut Vec<u8>, value: &[u8]) {
    let mut field = [0u8; UTS_FIELD_LEN];
    let len = core::cmp::min(value.len(), UTS_FIELD_LEN - 1);
    field[..len].copy_from_slice(&value[..len]);
    out.extend_from_slice(&field);
}

fn pack_dirents64(records: &[u8], max_len: usize) -> Result<Vec<u8>, &'static str> {
    let limit = core::cmp::min(max_len, RESULT_BUFFER_CAPACITY);
    let mut out = Vec::new();
    let mut next_off = 1i64;
    let mut cursor = 0usize;

    while cursor < records.len() {
        let dtype = records[cursor];
        cursor += 1;
        let name_end = records[cursor..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| cursor + offset)
            .ok_or("linux dirent record was malformed")?;
        let name = &records[cursor..name_end];
        cursor = name_end + 1;

        let reclen = align_up(19 + name.len() + 1, 8);
        if reclen > limit {
            return Err("linux dirent output was too small");
        }
        if out.len() + reclen > limit {
            break;
        }

        let offset = out.len();
        out.resize(offset + reclen, 0);
        out[offset..offset + 8].copy_from_slice(&(next_off as u64).to_le_bytes());
        out[offset + 8..offset + 16].copy_from_slice(&next_off.to_le_bytes());
        out[offset + 16..offset + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
        out[offset + 18] = dtype;
        out[offset + 19..offset + 19 + name.len()].copy_from_slice(name);
        next_off += 1;
    }

    Ok(out)
}

fn pack_epoll_events(records: &[u8], max_events: usize) -> Result<Vec<u8>, &'static str> {
    if !records.len().is_multiple_of(12) {
        return Err("epoll records were malformed");
    }
    let count = core::cmp::min(records.len() / 12, max_events.max(1));
    let mut out = Vec::new();
    for index in 0..count {
        let offset = index * 12;
        let mut event_bytes = [0u8; 4];
        let mut data_bytes = [0u8; 8];
        event_bytes.copy_from_slice(&records[offset..offset + 4]);
        data_bytes.copy_from_slice(&records[offset + 4..offset + 12]);
        let events = u32::from_le_bytes(event_bytes);
        out.extend_from_slice(&events.to_le_bytes());
        out.extend_from_slice(&data_bytes);
    }
    Ok(out)
}

fn pack_rename_len_flags(new_len: u64, flags: u64) -> u64 {
    ((flags & 0xffff_ffff) << 32) | (new_len & 0xffff_ffff)
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}
