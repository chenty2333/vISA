#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::{ptr::addr_of_mut, slice};

use vmos_abi::{
    ERR_EAGAIN, ERR_EFAULT, ERR_EINVAL, ERR_ENOSYS, FUTEX_CLOCK_REALTIME, FUTEX_CMD_MASK,
    FUTEX_CMP_REQUEUE, FUTEX_CMP_REQUEUE_PI, FUTEX_LOCK_PI, FUTEX_LOCK_PI2,
    FUTEX_PI_TIMEOUT_MONOTONIC, FUTEX_PI_TIMEOUT_NONE, FUTEX_PI_TIMEOUT_REALTIME, FUTEX_REQUEUE,
    FUTEX_TRYLOCK_PI, FUTEX_UNLOCK_PI, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAIT_REQUEUE_PI,
    FUTEX_WAKE, FUTEX_WAKE_BITSET, PackedStep, PlanKind, RestartClass, SO_KEEPALIVE, SO_RCVBUF,
    SO_REUSEADDR, SO_REUSEPORT, SO_SNDBUF, SOL_SOCKET, SYS_ACCEPT, SYS_ACCEPT4, SYS_BIND, SYS_BPF,
    SYS_CAPGET, SYS_CAPSET, SYS_CLOCK_ADJTIME, SYS_CLOCK_GETRES, SYS_CLOCK_GETTIME, SYS_CLOSE,
    SYS_CLOSE_RANGE, SYS_CONNECT, SYS_DUP, SYS_DUP2, SYS_DUP3, SYS_EPOLL_CREATE, SYS_EPOLL_CREATE1,
    SYS_EPOLL_CTL, SYS_EPOLL_WAIT, SYS_EVENTFD, SYS_EVENTFD2, SYS_EXIT, SYS_EXIT_GROUP, SYS_FCNTL,
    SYS_FGETXATTR, SYS_FLISTXATTR, SYS_FLOCK, SYS_FREMOVEXATTR, SYS_FSETXATTR, SYS_FUTEX,
    SYS_GET_ROBUST_LIST, SYS_GETCWD, SYS_GETDENTS64, SYS_GETEGID, SYS_GETEUID, SYS_GETGID,
    SYS_GETGROUPS, SYS_GETPEERNAME, SYS_GETPGID, SYS_GETPGRP, SYS_GETPID, SYS_GETPPID,
    SYS_GETRESGID, SYS_GETRESUID, SYS_GETRLIMIT, SYS_GETSID, SYS_GETSOCKNAME, SYS_GETSOCKOPT,
    SYS_GETTID, SYS_GETUID, SYS_IOCTL, SYS_KILL, SYS_LINK, SYS_LINKAT, SYS_LISTEN, SYS_MLOCK,
    SYS_MLOCK2, SYS_MLOCKALL, SYS_MMAP, SYS_MUNLOCK, SYS_MUNLOCKALL, SYS_MUNMAP, SYS_NANOSLEEP,
    SYS_OPENAT, SYS_PAUSE, SYS_PIPE, SYS_PIPE2, SYS_POLL, SYS_PRCTL, SYS_PRLIMIT64, SYS_PTRACE,
    SYS_READ, SYS_READLINKAT, SYS_READV, SYS_RECVFROM, SYS_RECVMSG, SYS_RENAME, SYS_RENAMEAT,
    SYS_RENAMEAT2, SYS_RT_SIGACTION, SYS_RT_SIGPENDING, SYS_RT_SIGPROCMASK, SYS_SECCOMP,
    SYS_SENDMSG, SYS_SENDTO, SYS_SET_ROBUST_LIST, SYS_SET_TID_ADDRESS, SYS_SETFSGID, SYS_SETFSUID,
    SYS_SETGID, SYS_SETGROUPS, SYS_SETPGID, SYS_SETREGID, SYS_SETRESGID, SYS_SETRESUID,
    SYS_SETREUID, SYS_SETRLIMIT, SYS_SETSID, SYS_SETSOCKOPT, SYS_SETUID, SYS_SHUTDOWN, SYS_SOCKET,
    SYS_SOCKETPAIR, SYS_TGKILL, SYS_TIMERFD_CREATE, SYS_TIMERFD_GETTIME, SYS_TIMERFD_SETTIME,
    SYS_UNAME, SYS_WAIT4, SYS_WRITE, SYS_WRITEV, is_stdio_fd,
};

const ARG_BUFFER_CAPACITY: usize = 256;
const RESULT_BUFFER_CAPACITY: usize = 1024;
const PENDING_SLOTS: usize = 8;
const UTS_FIELD_LEN: usize = 65;
const AT_FDCWD_ENCODED: u64 = -100i64 as u64;

static mut ARG_BUFFER: [u8; ARG_BUFFER_CAPACITY] = [0; ARG_BUFFER_CAPACITY];
static mut RESULT_BUFFER: [u8; RESULT_BUFFER_CAPACITY] = [0; RESULT_BUFFER_CAPACITY];
static mut PLAN_ARGS: [u64; 6] = [0; 6];
static mut PENDING_OPS: [PendingOp; PENDING_SLOTS] = [PendingOp::Empty; PENDING_SLOTS];

#[derive(Clone, Copy)]
enum PendingOp {
    Empty,
    Sleep,
    FutexWait,
    EpollWait { epfd: u32, max_events: u32, timeout_ms: u64 },
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GuestTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
struct GuestUtsName {
    sysname: [u8; UTS_FIELD_LEN],
    nodename: [u8; UTS_FIELD_LEN],
    release: [u8; UTS_FIELD_LEN],
    version: [u8; UTS_FIELD_LEN],
    machine: [u8; UTS_FIELD_LEN],
    domainname: [u8; UTS_FIELD_LEN],
}

#[repr(C, packed)]
struct GuestEpollEvent {
    events: u32,
    data: u64,
}

#[unsafe(no_mangle)]
pub extern "C" fn dispatch(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let step = match nr {
        SYS_READ => plan_read(a0, a2),
        SYS_READV => plan_readv(a0, a1, a2),
        SYS_WRITE => plan_write(a0, a1, a2),
        SYS_WRITEV => plan_writev(a0, a1, a2),
        SYS_CLOSE => plan_close(a0),
        SYS_CLOSE_RANGE => plan_close_range(a0, a1, a2),
        SYS_DUP => plan_dup(a0, 0, 0, 0),
        SYS_DUP2 => plan_dup(a0, a1, 0, 1),
        SYS_DUP3 => plan_dup(a0, a1, a2, 2),
        SYS_NANOSLEEP => dispatch_nanosleep(a0, a1),
        SYS_FUTEX => dispatch_futex(a0, a1, a2, a3, a4, a5),
        SYS_EPOLL_CREATE => plan_epoll_create(a0),
        SYS_EPOLL_CREATE1 => plan_epoll_create1(a0),
        SYS_EPOLL_CTL => plan_epoll_ctl(a0, a1, a2, a3, a4),
        SYS_EPOLL_WAIT => plan_epoll_wait(a0, a1, a2),
        SYS_SOCKET => plan_socket(a0, a1, a2),
        SYS_BIND => plan_bind(a0, a1, a2, a3, a4, a5),
        SYS_CONNECT => plan_connect(a0, a1, a2, a3, a4, a5),
        SYS_LISTEN => plan_listen(a0, a1),
        SYS_ACCEPT => plan_accept(a0, a1, a2),
        SYS_ACCEPT4 => plan_accept4(a0, a1, a2, a3),
        SYS_SOCKETPAIR => plan_socketpair(a0, a1, a2, a3),
        SYS_SENDTO => plan_sendto(a0, a1, a2, a3, a4, a5),
        SYS_SENDMSG => plan_sendmsg(a0, a1, a2),
        SYS_RECVFROM => plan_recvfrom(a0, a1, a2, a3, a4, a5),
        SYS_RECVMSG => plan_recvmsg(a0, a1, a2),
        SYS_SHUTDOWN => plan_shutdown(a0, a1),
        SYS_GETSOCKNAME => plan_getsockname(a0, a1, a2),
        SYS_GETPEERNAME => plan_getpeername(a0, a1, a2),
        SYS_SETSOCKOPT => plan_setsockopt(a0, a1, a2, a3, a4),
        SYS_GETSOCKOPT => plan_getsockopt(a0, a1, a2, a3, a4),
        SYS_IOCTL => plan_ioctl(a0, a1, a2),
        SYS_FCNTL => plan_fcntl(a0, a1, a2),
        SYS_FLOCK => plan_flock(a0, a1),
        SYS_MMAP => plan_mmap(a0, a1, a2, a3, a4, a5),
        SYS_MLOCK => plan_mlock(a0, a1, 0),
        SYS_MLOCK2 => plan_mlock(a0, a1, a2),
        SYS_MUNLOCK => plan_munlock(a0, a1),
        SYS_MLOCKALL => plan_mlockall(a0),
        SYS_MUNLOCKALL => plan_munlockall(),
        SYS_MUNMAP => plan_munmap(a0, a1),
        SYS_PIPE => plan_pipe(a0, 0),
        SYS_PIPE2 => plan_pipe(a0, a1),
        SYS_POLL => plan_poll(a0, a1, a2),
        SYS_KILL => plan_kill(a0, a1),
        SYS_TGKILL => plan_tgkill(a0, a1, a2),
        SYS_RT_SIGACTION => plan_rt_sigaction(a0, a1, a2, a3),
        SYS_RT_SIGPROCMASK => plan_rt_sigprocmask(a0, a1, a2, a3),
        SYS_RT_SIGPENDING => plan_rt_sigpending(a0, a1),
        SYS_WAIT4 => plan_wait4(a0, a1, a2, a3),
        SYS_GETPID => plan_simple(PlanKind::GetPid),
        SYS_GETPPID => plan_simple(PlanKind::GetPpid),
        SYS_GETTID => plan_simple(PlanKind::GetTid),
        SYS_GETUID => plan_simple(PlanKind::GetUid),
        SYS_GETGID => plan_simple(PlanKind::GetGid),
        SYS_GETEUID => plan_simple(PlanKind::GetEuid),
        SYS_GETEGID => plan_simple(PlanKind::GetEgid),
        SYS_SETUID => plan_setuid(a0),
        SYS_SETGID => plan_setgid(a0),
        SYS_SETREUID => plan_setreuid(a0, a1),
        SYS_SETREGID => plan_setregid(a0, a1),
        SYS_SETRESUID => plan_setresuid(a0, a1, a2),
        SYS_GETRESUID => plan_getresuid(a0, a1, a2),
        SYS_SETRESGID => plan_setresgid(a0, a1, a2),
        SYS_GETRESGID => plan_getresgid(a0, a1, a2),
        SYS_SETFSUID => plan_setfsuid(a0),
        SYS_SETFSGID => plan_setfsgid(a0),
        SYS_GETGROUPS => plan_getgroups(a0, a1),
        SYS_SETGROUPS => plan_setgroups(a0, a1),
        SYS_CAPGET => plan_capget(a0, a1),
        SYS_CAPSET => plan_capset(a0, a1),
        SYS_GETPGID => plan_getpgid(a0),
        SYS_GETPGRP => plan_getpgid(0),
        SYS_GETSID => plan_getsid(a0),
        SYS_SETPGID => plan_setpgid(a0, a1),
        SYS_SETSID => plan_simple(PlanKind::SetSid),
        SYS_PAUSE => plan_simple(PlanKind::Pause),
        SYS_UNAME => plan_simple(PlanKind::Uname),
        SYS_GETCWD => plan_getcwd(a1),
        SYS_GETDENTS64 => plan_getdents(a0, a2),
        SYS_OPENAT => plan_openat(a0, a1, a2, a3, a4),
        SYS_READLINKAT => plan_readlinkat(a0, a1, a2),
        SYS_FSETXATTR => plan_fsetxattr(a0, a1, a2, a3, a4, a5),
        SYS_FGETXATTR => plan_fgetxattr(a0, a1, a2, a3, a4),
        SYS_FLISTXATTR => plan_flistxattr(a0, a1, a2),
        SYS_FREMOVEXATTR => plan_fremovexattr(a0, a1, a2),
        SYS_GETRLIMIT => plan_getrlimit(a0, a1),
        SYS_SETRLIMIT => plan_setrlimit(a0, a1),
        SYS_PRLIMIT64 => plan_prlimit64(a0, a1, a2, a3),
        SYS_CLOCK_GETTIME => plan_clock_gettime(a0, a1),
        SYS_CLOCK_GETRES => plan_clock_getres(a0, a1),
        SYS_CLOCK_ADJTIME => plan_clock_adjtime(a0, a1),
        SYS_EVENTFD => plan_eventfd(a0, 0),
        SYS_EVENTFD2 => plan_eventfd(a0, a1),
        SYS_TIMERFD_CREATE => plan_timerfd_create(a0, a1),
        SYS_TIMERFD_SETTIME => plan_timerfd_settime(a0, a1, a2, a3),
        SYS_TIMERFD_GETTIME => plan_timerfd_gettime(a0, a1),
        SYS_RENAME => plan_renameat2(
            AT_FDCWD_ENCODED,
            a0,
            a1,
            AT_FDCWD_ENCODED,
            a2,
            pack_rename_len_flags(a3, 0),
        ),
        SYS_RENAMEAT => plan_renameat2(a0, a1, a2, a3, a4, pack_rename_len_flags(a5, 0)),
        SYS_RENAMEAT2 => plan_renameat2(a0, a1, a2, a3, a4, a5),
        SYS_LINK => plan_linkat(
            AT_FDCWD_ENCODED,
            a0,
            a1,
            AT_FDCWD_ENCODED,
            a2,
            pack_rename_len_flags(a3, 0),
        ),
        SYS_LINKAT => plan_linkat(a0, a1, a2, a3, a4, a5),
        SYS_PRCTL => plan_prctl(a0, a1, a2, a3, a4),
        SYS_PTRACE => plan_ptrace(a0, a1, a2, a3),
        SYS_SECCOMP => plan_seccomp(a0, a1, a2),
        SYS_BPF => plan_bpf(a0, a1, a2),
        SYS_SET_ROBUST_LIST => plan_set_robust_list(a0, a1),
        SYS_GET_ROBUST_LIST => plan_get_robust_list(a0, a1, a2),
        SYS_SET_TID_ADDRESS => plan_set_tid_address(a0),
        SYS_EXIT | SYS_EXIT_GROUP => plan_exit(a0),
        _ => PackedStep::error(-ERR_ENOSYS),
    };

    step.raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn resume_wait(token: u32) -> u64 {
    match take_pending_op(token) {
        Some(PendingOp::Sleep) => PackedStep::ready(0).raw(),
        Some(PendingOp::FutexWait) => PackedStep::ready(0).raw(),
        Some(PendingOp::EpollWait { epfd, max_events, .. }) => {
            reset_plan(PlanKind::EpollReady, [epfd as u64, max_events as u64, 0, 0, 0, 0]);
            PackedStep::plan(PlanKind::EpollReady).raw()
        }
        _ => PackedStep::error(-ERR_EINVAL).raw(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn cancel_wait(token: u32, errno: i32) -> u64 {
    match take_pending_op(token) {
        Some(_) => PackedStep::error(-errno).raw(),
        None => PackedStep::error(-ERR_EINVAL).raw(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn restart_wait(token: u32, class: u32) -> u64 {
    let Some(class) = RestartClass::from_raw(class) else {
        return PackedStep::error(-ERR_EINVAL).raw();
    };
    match peek_pending_op(token) {
        Some(PendingOp::EpollWait { epfd, max_events, timeout_ms }) => {
            restart_epoll_wait(token, epfd, max_events, timeout_ms, class).raw()
        }
        Some(PendingOp::Sleep) | Some(PendingOp::FutexWait) | Some(PendingOp::Empty) | None => {
            PackedStep::error(-ERR_EINVAL).raw()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn arg_buffer_ptr() -> u32 {
    core::ptr::addr_of_mut!(ARG_BUFFER) as *mut u8 as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn arg_buffer_capacity() -> u32 {
    ARG_BUFFER_CAPACITY as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn result_buffer_ptr() -> u32 {
    addr_of_mut!(RESULT_BUFFER) as *mut u8 as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn result_buffer_capacity() -> u32 {
    RESULT_BUFFER_CAPACITY as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn plan_arg(index: u32) -> u64 {
    if index as usize >= 6 {
        return 0;
    }

    unsafe {
        let base = core::ptr::addr_of!(PLAN_ARGS) as *const u64;
        *base.add(index as usize)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dispatch_sleep_ms(duration_ms: u64) -> u64 {
    plan_sleep(duration_ms).raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn dispatch_futex_raw(
    key: u64,
    op: u64,
    val: u64,
    timeout_ms: u64,
    current_word: u64,
) -> u64 {
    plan_futex(key, op, val, timeout_ms, current_word).raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn encode_uname(release_ptr: u32, release_len: u32) -> i32 {
    let Ok(release) = arg_bytes(release_ptr, release_len) else {
        return -ERR_EINVAL;
    };

    let uts = GuestUtsName {
        sysname: c_field(b"VmOS"),
        nodename: c_field(b"prototype2"),
        release: c_field(release),
        version: c_field(b"supervisor-world"),
        machine: c_field(b"x86_64"),
        domainname: [0; UTS_FIELD_LEN],
    };
    write_result_bytes(unsafe {
        slice::from_raw_parts(
            (&uts as *const GuestUtsName).cast::<u8>(),
            core::mem::size_of::<GuestUtsName>(),
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn encode_dirents64(records_ptr: u32, records_len: u32, max_len: u32) -> i32 {
    let Ok(records) = arg_bytes(records_ptr, records_len) else {
        return -ERR_EINVAL;
    };
    pack_dirents64(records, max_len as usize)
}

#[unsafe(no_mangle)]
pub extern "C" fn encode_epoll_events(records_ptr: u32, records_len: u32, max_events: u32) -> i32 {
    let Ok(records) = arg_bytes(records_ptr, records_len) else {
        return -ERR_EINVAL;
    };
    pack_epoll_events(records, max_events as usize)
}

fn dispatch_nanosleep(ptr: u64, len: u64) -> PackedStep {
    let ptr = ptr as u32;
    let len = len as u32;
    let Ok(req) = parse_timespec_ms(ptr, len) else {
        return PackedStep::error(-ERR_EINVAL);
    };
    plan_sleep(req)
}

fn plan_sleep(duration_ms: u64) -> PackedStep {
    let clamped = if duration_ms > u32::MAX as u64 { u32::MAX } else { duration_ms as u32 };
    let Some(resume_cookie) = allocate_pending_op(PendingOp::Sleep) else {
        return PackedStep::error(-ERR_EINVAL);
    };
    reset_plan(PlanKind::Sleep, [resume_cookie as u64, clamped as u64, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Sleep)
}

fn dispatch_futex(
    key: u64,
    op: u64,
    val: u64,
    timeout_ptr: u64,
    timeout_len: u64,
    current_word: u64,
) -> PackedStep {
    let command = (op as u32) & FUTEX_CMD_MASK;
    if matches!(command, FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_TRYLOCK_PI) {
        return plan_futex_lock_pi(key, op as u32, timeout_ptr, timeout_len);
    }
    if command == FUTEX_UNLOCK_PI {
        return plan_futex_unlock_pi(key, op as u32);
    }
    let timeout_ms = match command {
        FUTEX_WAIT | FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI => {
            if timeout_ptr == 0 || timeout_len == 0 {
                u64::MAX
            } else {
                match parse_timespec_ms(timeout_ptr as u32, timeout_len as u32) {
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
    plan_futex(key, op, val, timeout_ms, aux_word)
}

fn plan_futex(key: u64, op: u64, val: u64, timeout_ms: u64, current_word: u64) -> PackedStep {
    match (op as u32) & FUTEX_CMD_MASK {
        FUTEX_WAIT => plan_futex_wait(key, val, timeout_ms, current_word),
        FUTEX_WAKE => plan_futex_wake(key, val),
        FUTEX_WAIT_BITSET => plan_futex_wait_bitset(key, val, timeout_ms, current_word),
        FUTEX_WAIT_REQUEUE_PI => plan_futex_wait_requeue_pi(key, val, timeout_ms, current_word),
        FUTEX_WAKE_BITSET => plan_futex_wake_bitset(key, val, current_word),
        FUTEX_REQUEUE => plan_futex_requeue(key, val, timeout_ms, current_word, false),
        FUTEX_CMP_REQUEUE => plan_futex_requeue(key, val, timeout_ms, current_word, true),
        FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_TRYLOCK_PI => {
            plan_futex_lock_pi(key, op as u32, 0, 0)
        }
        FUTEX_UNLOCK_PI => plan_futex_unlock_pi(key, op as u32),
        _ => PackedStep::error(-ERR_EINVAL),
    }
}

fn plan_futex_wait(key: u64, expected: u64, timeout_ms: u64, current_word: u64) -> PackedStep {
    if current_word != expected {
        return PackedStep::error(-ERR_EAGAIN);
    }

    let Some(resume_cookie) = allocate_pending_op(PendingOp::FutexWait) else {
        return PackedStep::error(-ERR_EINVAL);
    };
    let timeout = if timeout_ms == u64::MAX { u64::MAX } else { (timeout_ms as u32) as u64 };
    reset_plan(PlanKind::FutexWait, [key, timeout, resume_cookie as u64, 0, 0, 0]);
    PackedStep::plan(PlanKind::FutexWait)
}

fn plan_futex_wake(key: u64, count: u64) -> PackedStep {
    let count = count.min(u32::MAX as u64);
    reset_plan(PlanKind::FutexWake, [key, count, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::FutexWake)
}

fn plan_futex_wait_bitset(key: u64, expected: u64, timeout_ms: u64, bitset: u64) -> PackedStep {
    if bitset == 0 {
        return PackedStep::error(-ERR_EINVAL);
    }
    let Some(resume_cookie) = allocate_pending_op(PendingOp::FutexWait) else {
        return PackedStep::error(-ERR_EINVAL);
    };
    let timeout = if timeout_ms == u64::MAX { u64::MAX } else { (timeout_ms as u32) as u64 };
    reset_plan(
        PlanKind::FutexWaitBitset,
        [key, timeout, resume_cookie as u64, bitset, expected, 0],
    );
    PackedStep::plan(PlanKind::FutexWaitBitset)
}

fn plan_futex_wait_requeue_pi(
    key: u64,
    expected: u64,
    timeout_ms: u64,
    current_word: u64,
) -> PackedStep {
    if current_word != expected {
        return PackedStep::error(-ERR_EAGAIN);
    }

    let Some(resume_cookie) = allocate_pending_op(PendingOp::FutexWait) else {
        return PackedStep::error(-ERR_EINVAL);
    };
    let timeout = if timeout_ms == u64::MAX { u64::MAX } else { (timeout_ms as u32) as u64 };
    reset_plan(PlanKind::FutexWaitRequeuePi, [key, timeout, resume_cookie as u64, 0, 0, 0]);
    PackedStep::plan(PlanKind::FutexWaitRequeuePi)
}

fn plan_futex_wake_bitset(key: u64, count: u64, bitset: u64) -> PackedStep {
    if bitset == 0 {
        return PackedStep::error(-ERR_EINVAL);
    }
    let count = count.min(u32::MAX as u64);
    reset_plan(PlanKind::FutexWakeBitset, [key, count, bitset, 0, 0, 0]);
    PackedStep::plan(PlanKind::FutexWakeBitset)
}

fn plan_futex_requeue(
    src_key: u64,
    wake_count: u64,
    requeue_count: u64,
    dst_key: u64,
    compare_checked: bool,
) -> PackedStep {
    let wake_count = wake_count.min(u32::MAX as u64);
    let requeue_count = requeue_count.min(u32::MAX as u64);
    let kind = if compare_checked { PlanKind::FutexCmpRequeue } else { PlanKind::FutexRequeue };
    reset_plan(kind, [src_key, requeue_count, dst_key, wake_count, 0, 0]);
    PackedStep::plan(kind)
}

fn plan_futex_lock_pi(key: u64, raw_op: u32, timeout_ptr: u64, timeout_len: u64) -> PackedStep {
    let command = raw_op & FUTEX_CMD_MASK;
    if key & 0x3 != 0 {
        return PackedStep::error(-ERR_EINVAL);
    }
    if command == FUTEX_TRYLOCK_PI && raw_op & FUTEX_CLOCK_REALTIME != 0 {
        return PackedStep::error(-ERR_EINVAL);
    }
    let key_ptr = match u32::try_from(key) {
        Ok(ptr) => ptr,
        Err(_) => return PackedStep::error(-ERR_EFAULT),
    };
    let current_word = match arg_u32(key_ptr) {
        Ok(word) => word,
        Err(errno) => return PackedStep::error(errno),
    };
    let try_only = u64::from(command == FUTEX_TRYLOCK_PI);
    let (timeout_ptr, timeout_len) =
        if command == FUTEX_TRYLOCK_PI { (0, 0) } else { (timeout_ptr, timeout_len) };
    let timeout_clock = futex_pi_timeout_clock(raw_op, timeout_ptr, timeout_len);
    reset_plan(
        PlanKind::FutexLockPi,
        [key, current_word as u64, try_only, timeout_ptr, timeout_len, timeout_clock],
    );
    PackedStep::plan(PlanKind::FutexLockPi)
}

fn futex_pi_timeout_clock(raw_op: u32, timeout_ptr: u64, timeout_len: u64) -> u64 {
    if timeout_ptr == 0 && timeout_len == 0 {
        return FUTEX_PI_TIMEOUT_NONE;
    }
    let command = raw_op & FUTEX_CMD_MASK;
    if command == FUTEX_LOCK_PI2 && raw_op & FUTEX_CLOCK_REALTIME == 0 {
        FUTEX_PI_TIMEOUT_MONOTONIC
    } else {
        FUTEX_PI_TIMEOUT_REALTIME
    }
}

fn plan_futex_unlock_pi(key: u64, raw_op: u32) -> PackedStep {
    if key & 0x3 != 0 {
        return PackedStep::error(-ERR_EINVAL);
    }
    if raw_op & FUTEX_CLOCK_REALTIME != 0 {
        return PackedStep::error(-ERR_EINVAL);
    }
    let key_ptr = match u32::try_from(key) {
        Ok(ptr) => ptr,
        Err(_) => return PackedStep::error(-ERR_EFAULT),
    };
    let current_word = match arg_u32(key_ptr) {
        Ok(word) => word,
        Err(errno) => return PackedStep::error(errno),
    };
    reset_plan(PlanKind::FutexUnlockPi, [key, current_word as u64, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::FutexUnlockPi)
}

fn plan_epoll_create1(flags: u64) -> PackedStep {
    let flags = (flags as u32) as u64;
    reset_plan(PlanKind::EpollCreate1, [flags, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::EpollCreate1)
}

fn plan_epoll_create(size: u64) -> PackedStep {
    if size == 0 {
        return PackedStep::error(-ERR_EINVAL);
    }
    reset_plan(PlanKind::EpollCreate1, [0, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::EpollCreate1)
}

fn plan_epoll_ctl(epfd: u64, op: u64, fd: u64, events: u64, data: u64) -> PackedStep {
    reset_plan(PlanKind::EpollCtl, [epfd, op, fd, events, data, 0]);
    PackedStep::plan(PlanKind::EpollCtl)
}

fn plan_epoll_wait(epfd: u64, max_events: u64, timeout_ms: u64) -> PackedStep {
    if max_events == 0 {
        return PackedStep::error(-ERR_EINVAL);
    }

    let Some(resume_cookie) = allocate_pending_op(PendingOp::EpollWait {
        epfd: epfd as u32,
        max_events: max_events as u32,
        timeout_ms,
    }) else {
        return PackedStep::error(-ERR_EINVAL);
    };

    let timeout_ms = if timeout_ms < 0_i64 as u64 { u64::MAX } else { timeout_ms };
    reset_plan(PlanKind::EpollWait, [epfd, max_events, timeout_ms, resume_cookie as u64, 0, 0]);
    PackedStep::plan(PlanKind::EpollWait)
}

fn plan_socket(domain: u64, ty: u64, protocol: u64) -> PackedStep {
    reset_plan(PlanKind::Socket, [domain, ty, protocol, 0, 0, 0]);
    PackedStep::plan(PlanKind::Socket)
}

fn plan_bind(
    fd: u64,
    addr: u64,
    addr_len: u64,
    family: u64,
    ipv4_addr: u64,
    port: u64,
) -> PackedStep {
    reset_plan(PlanKind::Bind, [fd, addr, addr_len, family, ipv4_addr, port]);
    PackedStep::plan(PlanKind::Bind)
}

fn plan_connect(
    fd: u64,
    addr: u64,
    addr_len: u64,
    family: u64,
    ipv4_addr: u64,
    port: u64,
) -> PackedStep {
    reset_plan(PlanKind::Connect, [fd, addr, addr_len, family, ipv4_addr, port]);
    PackedStep::plan(PlanKind::Connect)
}

fn plan_listen(fd: u64, backlog: u64) -> PackedStep {
    reset_plan(PlanKind::Listen, [fd, backlog, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Listen)
}

fn plan_accept(fd: u64, addr: u64, addr_len: u64) -> PackedStep {
    reset_plan(PlanKind::Accept, [fd, addr, addr_len, 0, 0, 0]);
    PackedStep::plan(PlanKind::Accept)
}

fn plan_accept4(fd: u64, addr: u64, addr_len: u64, flags: u64) -> PackedStep {
    reset_plan(PlanKind::Accept, [fd, addr, addr_len, flags, 0, 0]);
    PackedStep::plan(PlanKind::Accept)
}

fn plan_socketpair(domain: u64, ty: u64, protocol: u64, sv_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::SocketPair, [domain, ty, protocol, sv_ptr, 0, 0]);
    PackedStep::plan(PlanKind::SocketPair)
}

fn plan_sendto(fd: u64, ptr: u64, len: u64, flags: u64, addr: u64, addr_len: u64) -> PackedStep {
    reset_plan(PlanKind::SendTo, [fd, ptr, len, flags, addr, addr_len]);
    PackedStep::plan(PlanKind::SendTo)
}

fn plan_sendmsg(fd: u64, msg_ptr: u64, flags: u64) -> PackedStep {
    reset_plan(PlanKind::SendMsg, [fd, msg_ptr, flags, 0, 0, 0]);
    PackedStep::plan(PlanKind::SendMsg)
}

fn plan_recvfrom(fd: u64, ptr: u64, len: u64, flags: u64, addr: u64, addr_len: u64) -> PackedStep {
    reset_plan(PlanKind::RecvFrom, [fd, ptr, len, flags, addr, addr_len]);
    PackedStep::plan(PlanKind::RecvFrom)
}

fn plan_recvmsg(fd: u64, msg_ptr: u64, flags: u64) -> PackedStep {
    reset_plan(PlanKind::RecvMsg, [fd, msg_ptr, flags, 0, 0, 0]);
    PackedStep::plan(PlanKind::RecvMsg)
}

fn plan_shutdown(fd: u64, how: u64) -> PackedStep {
    reset_plan(PlanKind::Shutdown, [fd, how, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Shutdown)
}

fn plan_getsockname(fd: u64, addr: u64, addr_len: u64) -> PackedStep {
    reset_plan(PlanKind::GetSockName, [fd, addr, addr_len, 0, 0, 0]);
    PackedStep::plan(PlanKind::GetSockName)
}

fn plan_getpeername(fd: u64, addr: u64, addr_len: u64) -> PackedStep {
    reset_plan(PlanKind::GetPeerName, [fd, addr, addr_len, 0, 0, 0]);
    PackedStep::plan(PlanKind::GetPeerName)
}

fn plan_setsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> PackedStep {
    let value = match setsockopt_u32_value(level, optname, optval, optlen) {
        Ok(value) => value,
        Err(errno) => return PackedStep::error(-(errno as i32)),
    };
    reset_plan(PlanKind::SetSockOpt, [fd, level, optname, optval, optlen, value]);
    PackedStep::plan(PlanKind::SetSockOpt)
}

fn plan_getsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> PackedStep {
    reset_plan(PlanKind::GetSockOpt, [fd, level, optname, optval, optlen, 0]);
    PackedStep::plan(PlanKind::GetSockOpt)
}

fn setsockopt_u32_value(level: u64, optname: u64, optval: u64, optlen: u64) -> Result<u64, i32> {
    let (Ok(level), Ok(optname)) = (u32::try_from(level), u32::try_from(optname)) else {
        return Ok(0);
    };
    if level != SOL_SOCKET
        || !matches!(optname, SO_REUSEADDR | SO_REUSEPORT | SO_KEEPALIVE | SO_SNDBUF | SO_RCVBUF)
    {
        return Ok(0);
    }
    if optlen < 4 {
        return Err(ERR_EINVAL);
    }
    let ptr = u32::try_from(optval).map_err(|_| ERR_EFAULT)?;
    let bytes = arg_bytes(ptr, 4).map_err(|_| ERR_EFAULT)?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| ERR_EFAULT)?) as u64)
}

fn plan_fcntl(fd: u64, cmd: u64, arg: u64) -> PackedStep {
    const F_GETLK: u64 = 5;
    const F_SETLK: u64 = 6;
    const F_SETLKW: u64 = 7;

    if matches!(cmd, F_GETLK | F_SETLK | F_SETLKW) {
        let Ok(arg_ptr) = u32::try_from(arg) else {
            return PackedStep::error(-ERR_EINVAL);
        };
        let Ok((lock_type, whence, start, len)) = parse_flock(arg_ptr) else {
            return PackedStep::error(-ERR_EINVAL);
        };
        let kind = if cmd == F_GETLK { PlanKind::FcntlGetlk } else { PlanKind::FcntlSetlk };
        let command_or_ptr = if cmd == F_GETLK { arg } else { cmd };
        reset_plan(
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

    reset_plan(PlanKind::Fcntl, [fd, cmd, arg, 0, 0, 0]);
    PackedStep::plan(PlanKind::Fcntl)
}

fn plan_flock(fd: u64, operation: u64) -> PackedStep {
    reset_plan(PlanKind::Flock, [fd, operation, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Flock)
}

fn plan_ioctl(fd: u64, request: u64, ptr: u64) -> PackedStep {
    reset_plan(PlanKind::Ioctl, [fd, request, ptr, 0, 0, 0]);
    PackedStep::plan(PlanKind::Ioctl)
}

fn plan_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, offset: u64) -> PackedStep {
    reset_plan(PlanKind::Mmap, [addr, len, prot, flags, fd, offset]);
    PackedStep::plan(PlanKind::Mmap)
}

fn plan_munmap(addr: u64, len: u64) -> PackedStep {
    reset_plan(PlanKind::Munmap, [addr, len, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Munmap)
}

fn plan_mlock(addr: u64, len: u64, flags: u64) -> PackedStep {
    reset_plan(PlanKind::Mlock, [addr, len, flags, 0, 0, 0]);
    PackedStep::plan(PlanKind::Mlock)
}

fn plan_munlock(addr: u64, len: u64) -> PackedStep {
    reset_plan(PlanKind::Munlock, [addr, len, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Munlock)
}

fn plan_mlockall(flags: u64) -> PackedStep {
    reset_plan(PlanKind::Mlockall, [flags, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Mlockall)
}

fn plan_munlockall() -> PackedStep {
    reset_plan(PlanKind::Munlockall, [0, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Munlockall)
}

fn plan_pipe(fds_ptr: u64, flags: u64) -> PackedStep {
    reset_plan(PlanKind::Pipe, [fds_ptr, flags, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Pipe)
}

fn plan_poll(ptr: u64, nfds: u64, timeout_ms: u64) -> PackedStep {
    reset_plan(PlanKind::Poll, [ptr, nfds, timeout_ms, 0, 0, 0]);
    PackedStep::plan(PlanKind::Poll)
}

fn plan_clock_adjtime(clock_id: u64, timex_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::ClockAdjtime, [clock_id, timex_ptr, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::ClockAdjtime)
}

fn plan_clock_gettime(clock_id: u64, timespec_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::ClockGettime, [clock_id, timespec_ptr, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::ClockGettime)
}

fn plan_clock_getres(clock_id: u64, timespec_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::ClockGetres, [clock_id, timespec_ptr, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::ClockGetres)
}

fn plan_timerfd_create(clock_id: u64, flags: u64) -> PackedStep {
    reset_plan(PlanKind::TimerfdCreate, [clock_id, flags, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::TimerfdCreate)
}

fn plan_eventfd(initval: u64, flags: u64) -> PackedStep {
    reset_plan(PlanKind::Eventfd, [initval, flags, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Eventfd)
}

fn plan_timerfd_settime(fd: u64, flags: u64, new_value_ptr: u64, old_value_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::TimerfdSettime, [fd, flags, new_value_ptr, old_value_ptr, 0, 0]);
    PackedStep::plan(PlanKind::TimerfdSettime)
}

fn plan_timerfd_gettime(fd: u64, curr_value_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::TimerfdGettime, [fd, curr_value_ptr, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::TimerfdGettime)
}

fn plan_seccomp(operation: u64, flags: u64, args_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::Seccomp, [operation, flags, args_ptr, 0, 0, 0]);
    PackedStep::plan(PlanKind::Seccomp)
}

fn plan_bpf(cmd: u64, attr_ptr: u64, attr_size: u64) -> PackedStep {
    reset_plan(PlanKind::Bpf, [cmd, attr_ptr, attr_size, 0, 0, 0]);
    PackedStep::plan(PlanKind::Bpf)
}

fn plan_prctl(option: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> PackedStep {
    reset_plan(PlanKind::Prctl, [option, arg2, arg3, arg4, arg5, 0]);
    PackedStep::plan(PlanKind::Prctl)
}

fn plan_ptrace(request: u64, pid: u64, addr: u64, data: u64) -> PackedStep {
    reset_plan(PlanKind::Ptrace, [request, pid, addr, data, 0, 0]);
    PackedStep::plan(PlanKind::Ptrace)
}

fn plan_set_robust_list(head: u64, len: u64) -> PackedStep {
    reset_plan(PlanKind::SetRobustList, [head, len, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetRobustList)
}

fn plan_set_tid_address(ptr: u64) -> PackedStep {
    reset_plan(PlanKind::SetTidAddress, [ptr, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetTidAddress)
}

fn plan_get_robust_list(pid: u64, head_ptr: u64, len_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::GetRobustList, [pid, head_ptr, len_ptr, 0, 0, 0]);
    PackedStep::plan(PlanKind::GetRobustList)
}

fn plan_write(fd: u64, ptr: u64, len: u64) -> PackedStep {
    if !is_stdio_fd(fd) && fd < 3 {
        return PackedStep::error(-ERR_EINVAL);
    }

    reset_plan(PlanKind::Write, [fd, ptr, len, 0, 0, 0]);
    PackedStep::plan(PlanKind::Write)
}

fn plan_writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> PackedStep {
    reset_plan(PlanKind::Writev, [fd, iov_ptr, iovcnt, 0, 0, 0]);
    PackedStep::plan(PlanKind::Writev)
}

fn plan_openat(dirfd: u64, ptr: u64, len: u64, flags: u64, mode: u64) -> PackedStep {
    if len == 0 {
        return PackedStep::error(-ERR_EINVAL);
    }

    reset_plan(PlanKind::OpenAt, [dirfd, ptr, len, flags, mode, 0]);
    PackedStep::plan(PlanKind::OpenAt)
}

fn plan_read(fd: u64, count: u64) -> PackedStep {
    reset_plan(PlanKind::Read, [fd, count, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Read)
}

fn plan_readv(fd: u64, iov_ptr: u64, iovcnt: u64) -> PackedStep {
    reset_plan(PlanKind::Readv, [fd, iov_ptr, iovcnt, 0, 0, 0]);
    PackedStep::plan(PlanKind::Readv)
}

fn plan_close(fd: u64) -> PackedStep {
    reset_plan(PlanKind::Close, [fd, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Close)
}

fn plan_close_range(first: u64, last: u64, flags: u64) -> PackedStep {
    reset_plan(PlanKind::CloseRange, [first, last, flags, 0, 0, 0]);
    PackedStep::plan(PlanKind::CloseRange)
}

fn plan_dup(old_fd: u64, new_fd: u64, flags: u64, mode: u64) -> PackedStep {
    reset_plan(PlanKind::Dup, [old_fd, new_fd, flags, mode, 0, 0]);
    PackedStep::plan(PlanKind::Dup)
}

fn plan_getdents(fd: u64, count: u64) -> PackedStep {
    reset_plan(PlanKind::GetDents64, [fd, count, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::GetDents64)
}

fn plan_readlinkat(dirfd: u64, ptr: u64, len: u64) -> PackedStep {
    if len == 0 {
        return PackedStep::error(-ERR_EINVAL);
    }

    reset_plan(PlanKind::ReadLinkAt, [dirfd, ptr, len, 0, 0, 0]);
    PackedStep::plan(PlanKind::ReadLinkAt)
}

fn plan_fsetxattr(
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
    reset_plan(PlanKind::Fsetxattr, [fd, name_ptr, name_len, value_ptr, value_len, flags]);
    PackedStep::plan(PlanKind::Fsetxattr)
}

fn plan_fgetxattr(fd: u64, name_ptr: u64, name_len: u64, value_ptr: u64, size: u64) -> PackedStep {
    if name_len == 0 {
        return PackedStep::error(-ERR_EINVAL);
    }
    reset_plan(PlanKind::Fgetxattr, [fd, name_ptr, name_len, value_ptr, size, 0]);
    PackedStep::plan(PlanKind::Fgetxattr)
}

fn plan_flistxattr(fd: u64, list_ptr: u64, size: u64) -> PackedStep {
    reset_plan(PlanKind::Flistxattr, [fd, list_ptr, size, 0, 0, 0]);
    PackedStep::plan(PlanKind::Flistxattr)
}

fn plan_fremovexattr(fd: u64, name_ptr: u64, name_len: u64) -> PackedStep {
    if name_len == 0 {
        return PackedStep::error(-ERR_EINVAL);
    }
    reset_plan(PlanKind::Fremovexattr, [fd, name_ptr, name_len, 0, 0, 0]);
    PackedStep::plan(PlanKind::Fremovexattr)
}

fn plan_prlimit64(pid: u64, resource: u64, new_limit_ptr: u64, old_limit_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::Prlimit64, [pid, resource, new_limit_ptr, old_limit_ptr, 0, 0]);
    PackedStep::plan(PlanKind::Prlimit64)
}

fn plan_getrlimit(resource: u64, old_limit_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::Getrlimit, [resource, old_limit_ptr, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Getrlimit)
}

fn plan_setrlimit(resource: u64, new_limit_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::Setrlimit, [resource, new_limit_ptr, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Setrlimit)
}

fn plan_renameat2(
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

    reset_plan(
        PlanKind::RenameAt2,
        [old_dirfd, old_ptr, old_len, new_dirfd, new_ptr, new_len_flags],
    );
    PackedStep::plan(PlanKind::RenameAt2)
}

fn plan_linkat(
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

    reset_plan(PlanKind::LinkAt, [old_dirfd, old_ptr, old_len, new_dirfd, new_ptr, new_len_flags]);
    PackedStep::plan(PlanKind::LinkAt)
}

fn pack_rename_len_flags(new_len: u64, flags: u64) -> u64 {
    ((flags & 0xffff_ffff) << 32) | (new_len & 0xffff_ffff)
}

fn plan_getcwd(size: u64) -> PackedStep {
    reset_plan(PlanKind::GetCwd, [size, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::GetCwd)
}

fn plan_simple(kind: PlanKind) -> PackedStep {
    reset_plan(kind, [0, 0, 0, 0, 0, 0]);
    PackedStep::plan(kind)
}

fn plan_kill(pid: u64, signal: u64) -> PackedStep {
    reset_plan(PlanKind::Kill, [pid, signal, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Kill)
}

fn plan_tgkill(tgid: u64, tid: u64, signal: u64) -> PackedStep {
    reset_plan(PlanKind::Tgkill, [tgid, tid, signal, 0, 0, 0]);
    PackedStep::plan(PlanKind::Tgkill)
}

fn plan_rt_sigaction(signo: u64, act: u64, oldact: u64, sigsetsize: u64) -> PackedStep {
    reset_plan(PlanKind::RtSigaction, [signo, act, oldact, sigsetsize, 0, 0]);
    PackedStep::plan(PlanKind::RtSigaction)
}

fn plan_rt_sigprocmask(how: u64, set: u64, oldset: u64, sigsetsize: u64) -> PackedStep {
    reset_plan(PlanKind::RtSigprocmask, [how, set, oldset, sigsetsize, 0, 0]);
    PackedStep::plan(PlanKind::RtSigprocmask)
}

fn plan_rt_sigpending(set: u64, sigsetsize: u64) -> PackedStep {
    reset_plan(PlanKind::RtSigpending, [set, sigsetsize, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::RtSigpending)
}

fn plan_wait4(selector: u64, status: u64, options: u64, rusage: u64) -> PackedStep {
    reset_plan(PlanKind::Wait4, [selector, status, options, rusage, 0, 0]);
    PackedStep::plan(PlanKind::Wait4)
}

fn plan_getpgid(pid: u64) -> PackedStep {
    reset_plan(PlanKind::GetPgid, [pid, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::GetPgid)
}

fn plan_getsid(pid: u64) -> PackedStep {
    reset_plan(PlanKind::GetSid, [pid, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::GetSid)
}

fn plan_setuid(uid: u64) -> PackedStep {
    reset_plan(PlanKind::SetUid, [uid, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetUid)
}

fn plan_setgid(gid: u64) -> PackedStep {
    reset_plan(PlanKind::SetGid, [gid, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetGid)
}

fn plan_setreuid(ruid: u64, euid: u64) -> PackedStep {
    reset_plan(PlanKind::SetReUid, [ruid, euid, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetReUid)
}

fn plan_setregid(rgid: u64, egid: u64) -> PackedStep {
    reset_plan(PlanKind::SetReGid, [rgid, egid, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetReGid)
}

fn plan_setresuid(ruid: u64, euid: u64, suid: u64) -> PackedStep {
    reset_plan(PlanKind::SetResUid, [ruid, euid, suid, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetResUid)
}

fn plan_getresuid(ruid_ptr: u64, euid_ptr: u64, suid_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::GetResUid, [ruid_ptr, euid_ptr, suid_ptr, 0, 0, 0]);
    PackedStep::plan(PlanKind::GetResUid)
}

fn plan_setresgid(rgid: u64, egid: u64, sgid: u64) -> PackedStep {
    reset_plan(PlanKind::SetResGid, [rgid, egid, sgid, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetResGid)
}

fn plan_getresgid(rgid_ptr: u64, egid_ptr: u64, sgid_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::GetResGid, [rgid_ptr, egid_ptr, sgid_ptr, 0, 0, 0]);
    PackedStep::plan(PlanKind::GetResGid)
}

fn plan_setfsuid(uid: u64) -> PackedStep {
    reset_plan(PlanKind::SetFsUid, [uid, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetFsUid)
}

fn plan_setfsgid(gid: u64) -> PackedStep {
    reset_plan(PlanKind::SetFsGid, [gid, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetFsGid)
}

fn plan_getgroups(size: u64, list_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::GetGroups, [size, list_ptr, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::GetGroups)
}

fn plan_setgroups(size: u64, list_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::SetGroups, [size, list_ptr, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetGroups)
}

fn plan_capget(header_ptr: u64, data_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::CapGet, [header_ptr, data_ptr, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::CapGet)
}

fn plan_capset(header_ptr: u64, data_ptr: u64) -> PackedStep {
    reset_plan(PlanKind::CapSet, [header_ptr, data_ptr, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::CapSet)
}

fn plan_setpgid(pid: u64, pgid: u64) -> PackedStep {
    reset_plan(PlanKind::SetPgid, [pid, pgid, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::SetPgid)
}

fn plan_exit(code: u64) -> PackedStep {
    reset_plan(PlanKind::Exit, [code, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Exit)
}

fn reset_plan(kind: PlanKind, args: [u64; 6]) {
    let _ = kind;
    unsafe {
        PLAN_ARGS = args;
    }
}

fn allocate_pending_op(op: PendingOp) -> Option<u32> {
    unsafe {
        let base = core::ptr::addr_of_mut!(PENDING_OPS) as *mut PendingOp;
        for index in 0..PENDING_SLOTS {
            let slot = base.add(index);
            if matches!(*slot, PendingOp::Empty) {
                *slot = op;
                return Some((index + 1) as u32);
            }
        }
    }
    None
}

fn take_pending_op(token: u32) -> Option<PendingOp> {
    if token == 0 || token as usize > PENDING_SLOTS {
        return None;
    }

    unsafe {
        let slot = (core::ptr::addr_of_mut!(PENDING_OPS) as *mut PendingOp).add(token as usize - 1);
        let op = *slot;
        *slot = PendingOp::Empty;
        match op {
            PendingOp::Empty => None,
            _ => Some(op),
        }
    }
}

fn peek_pending_op(token: u32) -> Option<PendingOp> {
    if token == 0 || token as usize > PENDING_SLOTS {
        return None;
    }

    unsafe {
        let slot = (core::ptr::addr_of!(PENDING_OPS) as *const PendingOp).add(token as usize - 1);
        let op = *slot;
        match op {
            PendingOp::Empty => None,
            _ => Some(op),
        }
    }
}

fn restart_epoll_wait(
    resume_cookie: u32,
    epfd: u32,
    max_events: u32,
    timeout_ms: u64,
    class: RestartClass,
) -> PackedStep {
    let _ = class;
    reset_plan(
        PlanKind::EpollWait,
        [epfd as u64, max_events as u64, timeout_ms, resume_cookie as u64, 0, 0],
    );
    PackedStep::plan(PlanKind::EpollWait)
}

fn parse_timespec_ms(ptr: u32, len: u32) -> Result<u64, i32> {
    if len != core::mem::size_of::<GuestTimespec>() as u32 {
        return Err(-ERR_EINVAL);
    }
    let bytes = arg_bytes(ptr, len)?;
    let mut raw = [0u8; core::mem::size_of::<GuestTimespec>()];
    raw.copy_from_slice(bytes);
    let tv_sec = i64::from_le_bytes(raw[0..8].try_into().unwrap());
    let tv_nsec = i64::from_le_bytes(raw[8..16].try_into().unwrap());
    if tv_sec < 0 || tv_nsec < 0 {
        return Err(-ERR_EINVAL);
    }

    Ok((tv_sec as u64).saturating_mul(1000).saturating_add((tv_nsec as u64).div_ceil(1_000_000)))
}

fn parse_flock(ptr: u32) -> Result<(i16, i16, i64, i64), i32> {
    const FLOCK_SIZE: u32 = 32;

    let bytes = arg_bytes(ptr, FLOCK_SIZE)?;
    let lock_type = i16::from_le_bytes(bytes[0..2].try_into().map_err(|_| -ERR_EINVAL)?);
    let whence = i16::from_le_bytes(bytes[2..4].try_into().map_err(|_| -ERR_EINVAL)?);
    let start = i64::from_le_bytes(bytes[8..16].try_into().map_err(|_| -ERR_EINVAL)?);
    let len = i64::from_le_bytes(bytes[16..24].try_into().map_err(|_| -ERR_EINVAL)?);
    Ok((lock_type, whence, start, len))
}

fn arg_bytes(ptr: u32, len: u32) -> Result<&'static [u8], i32> {
    let base_ptr = core::ptr::addr_of!(ARG_BUFFER) as *const u8;
    let base = base_ptr as usize as u32;
    let offset = ptr.checked_sub(base).ok_or(-ERR_EINVAL)?;
    let end = offset.checked_add(len).ok_or(-ERR_EINVAL)?;
    if end > ARG_BUFFER_CAPACITY as u32 {
        return Err(-ERR_EINVAL);
    }

    Ok(unsafe { slice::from_raw_parts(base_ptr.add(offset as usize), len as usize) })
}

fn arg_u32(ptr: u32) -> Result<u32, i32> {
    let bytes = arg_bytes(ptr, 4).map_err(|_| -ERR_EFAULT)?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| -ERR_EFAULT)?))
}

fn write_result_bytes(bytes: &[u8]) -> i32 {
    if bytes.len() > RESULT_BUFFER_CAPACITY {
        return -ERR_EINVAL;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            addr_of_mut!(RESULT_BUFFER) as *mut u8,
            bytes.len(),
        );
    }
    bytes.len() as i32
}

fn pack_dirents64(records: &[u8], max_len: usize) -> i32 {
    let limit = core::cmp::min(max_len, RESULT_BUFFER_CAPACITY);
    let mut out = [0u8; RESULT_BUFFER_CAPACITY];
    let mut out_len = 0usize;
    let mut next_off = 1i64;
    let mut cursor = 0usize;

    while cursor < records.len() {
        let dtype = records[cursor];
        cursor += 1;
        let name_end = records[cursor..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| cursor + offset)
            .ok_or(-ERR_EINVAL);
        let Ok(name_end) = name_end else {
            return -ERR_EINVAL;
        };
        let name = &records[cursor..name_end];
        cursor = name_end + 1;

        let reclen = align_up(19 + name.len() + 1, 8);
        if reclen > limit {
            return -ERR_EINVAL;
        }
        if out_len + reclen > limit {
            break;
        }

        out[out_len..out_len + 8].copy_from_slice(&(next_off as u64).to_le_bytes());
        out[out_len + 8..out_len + 16].copy_from_slice(&next_off.to_le_bytes());
        out[out_len + 16..out_len + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
        out[out_len + 18] = dtype;
        out[out_len + 19..out_len + 19 + name.len()].copy_from_slice(name);
        out_len += reclen;
        next_off += 1;
    }

    write_result_bytes(&out[..out_len])
}

fn pack_epoll_events(records: &[u8], max_events: usize) -> i32 {
    if !records.len().is_multiple_of(12) {
        return -ERR_EINVAL;
    }

    let count = core::cmp::min(records.len() / 12, max_events.max(1));
    let mut out = [0u8; RESULT_BUFFER_CAPACITY];
    let mut out_len = 0usize;
    for index in 0..count {
        let offset = index * 12;
        let event = GuestEpollEvent {
            events: u32::from_le_bytes(records[offset..offset + 4].try_into().unwrap()),
            data: u64::from_le_bytes(records[offset + 4..offset + 12].try_into().unwrap()),
        };
        let bytes = unsafe {
            slice::from_raw_parts(
                (&event as *const GuestEpollEvent).cast::<u8>(),
                core::mem::size_of::<GuestEpollEvent>(),
            )
        };
        if out_len + bytes.len() > RESULT_BUFFER_CAPACITY {
            break;
        }
        out[out_len..out_len + bytes.len()].copy_from_slice(bytes);
        out_len += bytes.len();
    }

    write_result_bytes(&out[..out_len])
}

fn c_field(value: &[u8]) -> [u8; UTS_FIELD_LEN] {
    let mut field = [0u8; UTS_FIELD_LEN];
    let len = core::cmp::min(value.len(), UTS_FIELD_LEN - 1);
    field[..len].copy_from_slice(&value[..len]);
    field
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn connect_plan_preserves_sockaddr_metadata() {
        let _guard = test_guard();
        let ipv4 = u32::from_be_bytes([10, 0, 2, 2]);
        let raw = dispatch(SYS_CONNECT, 7, 0x1000, 16, vmos_abi::AF_INET as u64, ipv4 as u64, 80);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Connect));
        assert_eq!(plan_arg(0), 7);
        assert_eq!(plan_arg(1), 0x1000);
        assert_eq!(plan_arg(2), 16);
        assert_eq!(plan_arg(3), vmos_abi::AF_INET as u64);
        assert_eq!(plan_arg(4), ipv4 as u64);
        assert_eq!(plan_arg(5), 80);
    }

    #[test]
    fn bind_plan_preserves_sockaddr_metadata() {
        let _guard = test_guard();
        let ipv4 = u32::from_be_bytes([127, 0, 0, 1]);
        let raw = dispatch(SYS_BIND, 8, 0x2000, 16, vmos_abi::AF_INET as u64, ipv4 as u64, 8080);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Bind));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 0x2000);
        assert_eq!(plan_arg(2), 16);
        assert_eq!(plan_arg(3), vmos_abi::AF_INET as u64);
        assert_eq!(plan_arg(4), ipv4 as u64);
        assert_eq!(plan_arg(5), 8080);
    }

    #[test]
    fn accept4_plan_preserves_flags() {
        let _guard = test_guard();
        const SOCK_NONBLOCK: u64 = 0o4000;
        const SOCK_CLOEXEC: u64 = 0o2000000;
        let flags = SOCK_CLOEXEC | SOCK_NONBLOCK;
        let raw = dispatch(SYS_ACCEPT4, 8, 0x2100, 0x2200, flags, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Accept));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 0x2100);
        assert_eq!(plan_arg(2), 0x2200);
        assert_eq!(plan_arg(3), flags);
    }

    #[test]
    fn socketpair_plan_preserves_type_and_writeback_pointer() {
        let _guard = test_guard();
        const SOCK_NONBLOCK: u64 = 0o4000;
        const SOCK_CLOEXEC: u64 = 0o2000000;
        let ty = vmos_abi::SOCK_STREAM as u64 | SOCK_CLOEXEC | SOCK_NONBLOCK;
        let raw = dispatch(SYS_SOCKETPAIR, vmos_abi::AF_UNIX as u64, ty, 0, 0x2300, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::SocketPair));
        assert_eq!(plan_arg(0), vmos_abi::AF_UNIX as u64);
        assert_eq!(plan_arg(1), ty);
        assert_eq!(plan_arg(2), 0);
        assert_eq!(plan_arg(3), 0x2300);
    }

    #[test]
    fn dup_plans_preserve_mode_flags_and_targets() {
        let _guard = test_guard();
        const O_CLOEXEC: u64 = 0o2000000;

        let dup = PackedStep::decode(dispatch(SYS_DUP, 8, 0xdead, 0xbeef, 0, 0, 0));
        assert_eq!(dup.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(dup.aux), Some(PlanKind::Dup));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 0);
        assert_eq!(plan_arg(2), 0);
        assert_eq!(plan_arg(3), 0);

        let dup2 = PackedStep::decode(dispatch(SYS_DUP2, 8, 15, 0xbeef, 0, 0, 0));
        assert_eq!(dup2.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(dup2.aux), Some(PlanKind::Dup));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 15);
        assert_eq!(plan_arg(2), 0);
        assert_eq!(plan_arg(3), 1);

        let dup3 = PackedStep::decode(dispatch(SYS_DUP3, 8, 16, O_CLOEXEC, 0, 0, 0));
        assert_eq!(dup3.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(dup3.aux), Some(PlanKind::Dup));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 16);
        assert_eq!(plan_arg(2), O_CLOEXEC);
        assert_eq!(plan_arg(3), 2);
    }

    #[test]
    fn close_range_plan_preserves_bounds_and_flags() {
        let _guard = test_guard();
        const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;
        let raw = dispatch(SYS_CLOSE_RANGE, 8, 128, CLOSE_RANGE_CLOEXEC, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::CloseRange));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 128);
        assert_eq!(plan_arg(2), CLOSE_RANGE_CLOEXEC);
    }

    #[test]
    fn readv_writev_plans_preserve_iovec_arguments() {
        let _guard = test_guard();

        let readv = PackedStep::decode(dispatch(SYS_READV, 8, 0x3000, 4, 0, 0, 0));
        assert_eq!(readv.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(readv.aux), Some(PlanKind::Readv));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 0x3000);
        assert_eq!(plan_arg(2), 4);

        let writev = PackedStep::decode(dispatch(SYS_WRITEV, 9, 0x4000, 5, 0, 0, 0));
        assert_eq!(writev.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(writev.aux), Some(PlanKind::Writev));
        assert_eq!(plan_arg(0), 9);
        assert_eq!(plan_arg(1), 0x4000);
        assert_eq!(plan_arg(2), 5);
    }

    #[test]
    fn recvmsg_plan_preserves_msghdr_pointer_and_flags() {
        let _guard = test_guard();

        let recvmsg = PackedStep::decode(dispatch(SYS_RECVMSG, 8, 0x3000, 0x40, 0, 0, 0));
        assert_eq!(recvmsg.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(recvmsg.aux), Some(PlanKind::RecvMsg));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 0x3000);
        assert_eq!(plan_arg(2), 0x40);
    }

    #[test]
    fn sendmsg_plan_preserves_msghdr_pointer_and_flags() {
        let _guard = test_guard();

        let sendmsg = PackedStep::decode(dispatch(SYS_SENDMSG, 8, 0x3000, 0x40, 0, 0, 0));
        assert_eq!(sendmsg.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(sendmsg.aux), Some(PlanKind::SendMsg));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 0x3000);
        assert_eq!(plan_arg(2), 0x40);
    }

    #[test]
    fn shutdown_plan_preserves_fd_and_how() {
        let _guard = test_guard();

        let shutdown = PackedStep::decode(dispatch(SYS_SHUTDOWN, 8, 2, 0, 0, 0, 0));
        assert_eq!(shutdown.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(shutdown.aux), Some(PlanKind::Shutdown));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 2);
    }

    #[test]
    fn socket_name_plans_preserve_writeback_pointers() {
        let _guard = test_guard();

        let getsockname = PackedStep::decode(dispatch(SYS_GETSOCKNAME, 8, 0x2100, 0x2200, 0, 0, 0));
        assert_eq!(getsockname.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getsockname.aux), Some(PlanKind::GetSockName));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), 0x2100);
        assert_eq!(plan_arg(2), 0x2200);

        let getpeername = PackedStep::decode(dispatch(SYS_GETPEERNAME, 9, 0x2300, 0x2400, 0, 0, 0));
        assert_eq!(getpeername.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getpeername.aux), Some(PlanKind::GetPeerName));
        assert_eq!(plan_arg(0), 9);
        assert_eq!(plan_arg(1), 0x2300);
        assert_eq!(plan_arg(2), 0x2400);
    }

    #[test]
    fn getsockopt_plan_preserves_writeback_pointers() {
        let _guard = test_guard();
        let raw = dispatch(
            SYS_GETSOCKOPT,
            8,
            vmos_abi::SOL_SOCKET as u64,
            vmos_abi::SO_ERROR as u64,
            0x2100,
            0x2200,
            0,
        );
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::GetSockOpt));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), vmos_abi::SOL_SOCKET as u64);
        assert_eq!(plan_arg(2), vmos_abi::SO_ERROR as u64);
        assert_eq!(plan_arg(3), 0x2100);
        assert_eq!(plan_arg(4), 0x2200);
    }

    #[test]
    fn setsockopt_plan_preserves_supported_u32_value() {
        let _guard = test_guard();
        let ptr = unsafe {
            let base = core::ptr::addr_of_mut!(ARG_BUFFER) as *mut u8;
            core::ptr::copy_nonoverlapping(1u32.to_le_bytes().as_ptr(), base, 4);
            base as usize as u32
        };
        let raw = dispatch(
            SYS_SETSOCKOPT,
            8,
            vmos_abi::SOL_SOCKET as u64,
            vmos_abi::SO_REUSEADDR as u64,
            ptr as u64,
            4,
            0,
        );
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::SetSockOpt));
        assert_eq!(plan_arg(0), 8);
        assert_eq!(plan_arg(1), vmos_abi::SOL_SOCKET as u64);
        assert_eq!(plan_arg(2), vmos_abi::SO_REUSEADDR as u64);
        assert_eq!(plan_arg(3), ptr as u64);
        assert_eq!(plan_arg(4), 4);
        assert_eq!(plan_arg(5), 1);

        let keepalive = PackedStep::decode(dispatch(
            SYS_SETSOCKOPT,
            8,
            vmos_abi::SOL_SOCKET as u64,
            vmos_abi::SO_KEEPALIVE as u64,
            ptr as u64,
            4,
            0,
        ));
        assert_eq!(keepalive.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(keepalive.aux), Some(PlanKind::SetSockOpt));
        assert_eq!(plan_arg(2), vmos_abi::SO_KEEPALIVE as u64);
        assert_eq!(plan_arg(5), 1);

        let sndbuf = PackedStep::decode(dispatch(
            SYS_SETSOCKOPT,
            8,
            vmos_abi::SOL_SOCKET as u64,
            vmos_abi::SO_SNDBUF as u64,
            ptr as u64,
            4,
            0,
        ));
        assert_eq!(sndbuf.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(sndbuf.aux), Some(PlanKind::SetSockOpt));
        assert_eq!(plan_arg(2), vmos_abi::SO_SNDBUF as u64);
        assert_eq!(plan_arg(5), 1);
    }

    #[test]
    fn setsockopt_plan_rejects_short_supported_u32_value() {
        let _guard = test_guard();
        let raw = dispatch(
            SYS_SETSOCKOPT,
            8,
            vmos_abi::SOL_SOCKET as u64,
            vmos_abi::SO_REUSEADDR as u64,
            0,
            3,
            0,
        );
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Error);
        assert_eq!(step.value, -ERR_EINVAL);
    }

    #[test]
    fn futex_wait_requeue_pi_plans_distinct_wait_kind() {
        let _guard = test_guard();
        let raw = dispatch_futex_raw(0x1000, FUTEX_WAIT_REQUEUE_PI as u64, 7, u64::MAX, 7);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::FutexWaitRequeuePi));
        assert_eq!(plan_arg(0), 0x1000);
        assert_eq!(plan_arg(1), u64::MAX);
        assert_ne!(plan_arg(2), 0);
    }

    #[test]
    fn pause_plans_signal_wait() {
        let _guard = test_guard();
        let raw = dispatch(SYS_PAUSE, 0, 0, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Pause));
    }

    #[test]
    fn wait4_plan_preserves_selector_status_options_and_rusage() {
        let _guard = test_guard();
        let raw = dispatch(SYS_WAIT4, u64::MAX, 0x1000, 1, 0x2000, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Wait4));
        assert_eq!(plan_arg(0), u64::MAX);
        assert_eq!(plan_arg(1), 0x1000);
        assert_eq!(plan_arg(2), 1);
        assert_eq!(plan_arg(3), 0x2000);
    }

    #[test]
    fn exit_plans_process_exit_instead_of_terminal_step() {
        let _guard = test_guard();
        let raw = dispatch(SYS_EXIT, 23, 0, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Exit));
        assert_eq!(plan_arg(0), 23);
    }

    #[test]
    fn process_metadata_and_group_plans_preserve_arguments() {
        let _guard = test_guard();

        let getpid = PackedStep::decode(dispatch(SYS_GETPID, 0, 0, 0, 0, 0, 0));
        assert_eq!(getpid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getpid.aux), Some(PlanKind::GetPid));

        let gettid = PackedStep::decode(dispatch(SYS_GETTID, 0, 0, 0, 0, 0, 0));
        assert_eq!(gettid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(gettid.aux), Some(PlanKind::GetTid));

        let getuid = PackedStep::decode(dispatch(SYS_GETUID, 0, 0, 0, 0, 0, 0));
        assert_eq!(getuid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getuid.aux), Some(PlanKind::GetUid));

        let getgid = PackedStep::decode(dispatch(SYS_GETGID, 0, 0, 0, 0, 0, 0));
        assert_eq!(getgid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getgid.aux), Some(PlanKind::GetGid));

        let geteuid = PackedStep::decode(dispatch(SYS_GETEUID, 0, 0, 0, 0, 0, 0));
        assert_eq!(geteuid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(geteuid.aux), Some(PlanKind::GetEuid));

        let getegid = PackedStep::decode(dispatch(SYS_GETEGID, 0, 0, 0, 0, 0, 0));
        assert_eq!(getegid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getegid.aux), Some(PlanKind::GetEgid));

        let sigpending = PackedStep::decode(dispatch(SYS_RT_SIGPENDING, 0x1000, 8, 0, 0, 0, 0));
        assert_eq!(sigpending.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(sigpending.aux), Some(PlanKind::RtSigpending));

        let setuid = PackedStep::decode(dispatch(SYS_SETUID, 1000, 0, 0, 0, 0, 0));
        assert_eq!(setuid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setuid.aux), Some(PlanKind::SetUid));
        assert_eq!(plan_arg(0), 1000);

        let setgid = PackedStep::decode(dispatch(SYS_SETGID, 100, 0, 0, 0, 0, 0));
        assert_eq!(setgid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setgid.aux), Some(PlanKind::SetGid));
        assert_eq!(plan_arg(0), 100);

        let setreuid = PackedStep::decode(dispatch(SYS_SETREUID, u64::MAX, 2000, 0, 0, 0, 0));
        assert_eq!(setreuid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setreuid.aux), Some(PlanKind::SetReUid));
        assert_eq!(plan_arg(0), u64::MAX);
        assert_eq!(plan_arg(1), 2000);

        let setregid = PackedStep::decode(dispatch(SYS_SETREGID, u64::MAX, 200, 0, 0, 0, 0));
        assert_eq!(setregid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setregid.aux), Some(PlanKind::SetReGid));
        assert_eq!(plan_arg(0), u64::MAX);
        assert_eq!(plan_arg(1), 200);

        let setresuid = PackedStep::decode(dispatch(SYS_SETRESUID, u64::MAX, 2000, 3000, 0, 0, 0));
        assert_eq!(setresuid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setresuid.aux), Some(PlanKind::SetResUid));
        assert_eq!(plan_arg(0), u64::MAX);
        assert_eq!(plan_arg(1), 2000);
        assert_eq!(plan_arg(2), 3000);

        let getresuid = PackedStep::decode(dispatch(SYS_GETRESUID, 0x10, 0x14, 0x18, 0, 0, 0));
        assert_eq!(getresuid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getresuid.aux), Some(PlanKind::GetResUid));
        assert_eq!(plan_arg(0), 0x10);
        assert_eq!(plan_arg(1), 0x14);
        assert_eq!(plan_arg(2), 0x18);

        let setresgid = PackedStep::decode(dispatch(SYS_SETRESGID, u64::MAX, 200, 300, 0, 0, 0));
        assert_eq!(setresgid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setresgid.aux), Some(PlanKind::SetResGid));
        assert_eq!(plan_arg(0), u64::MAX);
        assert_eq!(plan_arg(1), 200);
        assert_eq!(plan_arg(2), 300);

        let getresgid = PackedStep::decode(dispatch(SYS_GETRESGID, 0x20, 0x24, 0x28, 0, 0, 0));
        assert_eq!(getresgid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getresgid.aux), Some(PlanKind::GetResGid));
        assert_eq!(plan_arg(0), 0x20);
        assert_eq!(plan_arg(1), 0x24);
        assert_eq!(plan_arg(2), 0x28);

        let setfsuid = PackedStep::decode(dispatch(SYS_SETFSUID, 3000, 0, 0, 0, 0, 0));
        assert_eq!(setfsuid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setfsuid.aux), Some(PlanKind::SetFsUid));
        assert_eq!(plan_arg(0), 3000);

        let setfsgid = PackedStep::decode(dispatch(SYS_SETFSGID, 300, 0, 0, 0, 0, 0));
        assert_eq!(setfsgid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setfsgid.aux), Some(PlanKind::SetFsGid));
        assert_eq!(plan_arg(0), 300);

        let getgroups = PackedStep::decode(dispatch(SYS_GETGROUPS, 4, 0x30, 0, 0, 0, 0));
        assert_eq!(getgroups.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getgroups.aux), Some(PlanKind::GetGroups));
        assert_eq!(plan_arg(0), 4);
        assert_eq!(plan_arg(1), 0x30);

        let setgroups = PackedStep::decode(dispatch(SYS_SETGROUPS, 2, 0x40, 0, 0, 0, 0));
        assert_eq!(setgroups.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setgroups.aux), Some(PlanKind::SetGroups));
        assert_eq!(plan_arg(0), 2);
        assert_eq!(plan_arg(1), 0x40);

        let capget = PackedStep::decode(dispatch(SYS_CAPGET, 0x50, 0x58, 0, 0, 0, 0));
        assert_eq!(capget.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(capget.aux), Some(PlanKind::CapGet));
        assert_eq!(plan_arg(0), 0x50);
        assert_eq!(plan_arg(1), 0x58);

        let capset = PackedStep::decode(dispatch(SYS_CAPSET, 0x60, 0x68, 0, 0, 0, 0));
        assert_eq!(capset.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(capset.aux), Some(PlanKind::CapSet));
        assert_eq!(plan_arg(0), 0x60);
        assert_eq!(plan_arg(1), 0x68);

        let getpgid = PackedStep::decode(dispatch(SYS_GETPGID, 42, 0, 0, 0, 0, 0));
        assert_eq!(getpgid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getpgid.aux), Some(PlanKind::GetPgid));
        assert_eq!(plan_arg(0), 42);

        let getpgrp = PackedStep::decode(dispatch(SYS_GETPGRP, 99, 0, 0, 0, 0, 0));
        assert_eq!(getpgrp.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getpgrp.aux), Some(PlanKind::GetPgid));
        assert_eq!(plan_arg(0), 0);

        let getsid = PackedStep::decode(dispatch(SYS_GETSID, 43, 0, 0, 0, 0, 0));
        assert_eq!(getsid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(getsid.aux), Some(PlanKind::GetSid));
        assert_eq!(plan_arg(0), 43);

        let setpgid = PackedStep::decode(dispatch(SYS_SETPGID, 44, 45, 0, 0, 0, 0));
        assert_eq!(setpgid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setpgid.aux), Some(PlanKind::SetPgid));
        assert_eq!(plan_arg(0), 44);
        assert_eq!(plan_arg(1), 45);

        let setsid = PackedStep::decode(dispatch(SYS_SETSID, 0, 0, 0, 0, 0, 0));
        assert_eq!(setsid.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(setsid.aux), Some(PlanKind::SetSid));
    }

    #[test]
    fn kill_and_tgkill_plan_signal_delivery() {
        let _guard = test_guard();
        let kill = PackedStep::decode(dispatch(vmos_abi::SYS_KILL, 12, 10, 0, 0, 0, 0));
        assert_eq!(kill.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(kill.aux), Some(PlanKind::Kill));
        assert_eq!(plan_arg(0), 12);
        assert_eq!(plan_arg(1), 10);

        let tgkill = PackedStep::decode(dispatch(SYS_TGKILL, 12, 13, 15, 0, 0, 0));
        assert_eq!(tgkill.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(tgkill.aux), Some(PlanKind::Tgkill));
        assert_eq!(plan_arg(0), 12);
        assert_eq!(plan_arg(1), 13);
        assert_eq!(plan_arg(2), 15);
    }

    #[test]
    fn rt_signal_plans_preserve_abi_pointers() {
        let _guard = test_guard();
        let sigaction = PackedStep::decode(dispatch(SYS_RT_SIGACTION, 2, 0x1000, 0x2000, 8, 0, 0));
        assert_eq!(sigaction.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(sigaction.aux), Some(PlanKind::RtSigaction));
        assert_eq!(plan_arg(0), 2);
        assert_eq!(plan_arg(1), 0x1000);
        assert_eq!(plan_arg(2), 0x2000);
        assert_eq!(plan_arg(3), 8);

        let sigprocmask =
            PackedStep::decode(dispatch(SYS_RT_SIGPROCMASK, 1, 0x3000, 0x4000, 8, 0, 0));
        assert_eq!(sigprocmask.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(sigprocmask.aux), Some(PlanKind::RtSigprocmask));
        assert_eq!(plan_arg(0), 1);
        assert_eq!(plan_arg(1), 0x3000);
        assert_eq!(plan_arg(2), 0x4000);
        assert_eq!(plan_arg(3), 8);
    }

    #[test]
    fn futex_pi_plans_from_arg_buffer_word() {
        let _guard = test_guard();
        let (ptr, host_ptr) = unsafe {
            let base = core::ptr::addr_of_mut!(ARG_BUFFER) as *mut u8;
            let base_addr = base as usize;
            let aligned = (base_addr + 3) & !3usize;
            core::ptr::copy_nonoverlapping(0u32.to_le_bytes().as_ptr(), aligned as *mut u8, 4);
            (aligned as u32, aligned as *mut u8)
        };

        let raw = dispatch(SYS_FUTEX, ptr as u64, FUTEX_LOCK_PI as u64, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::FutexLockPi));
        assert_eq!(plan_arg(0), ptr as u64);
        assert_eq!(plan_arg(1), 0);
        assert_eq!(plan_arg(2), 0);
        assert_eq!(plan_arg(3), 0);
        assert_eq!(plan_arg(4), 0);
        assert_eq!(plan_arg(5), FUTEX_PI_TIMEOUT_NONE);

        unsafe {
            core::ptr::copy_nonoverlapping(7u32.to_le_bytes().as_ptr(), host_ptr, 4);
        }
        let raw = dispatch(SYS_FUTEX, ptr as u64, FUTEX_TRYLOCK_PI as u64, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::FutexLockPi));
        assert_eq!(plan_arg(1), 7);
        assert_eq!(plan_arg(2), 1);
        assert_eq!(plan_arg(3), 0);
        assert_eq!(plan_arg(4), 0);
        assert_eq!(plan_arg(5), FUTEX_PI_TIMEOUT_NONE);

        let raw = dispatch(SYS_FUTEX, ptr as u64, FUTEX_UNLOCK_PI as u64, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::FutexUnlockPi));
        assert_eq!(plan_arg(1), 7);
    }

    #[test]
    fn futex_pi_plan_preserves_timeout_pointer_and_clock() {
        let _guard = test_guard();
        let (ptr, timeout_ptr) = unsafe {
            let base = core::ptr::addr_of_mut!(ARG_BUFFER) as *mut u8;
            let base_addr = base as usize;
            let aligned = (base_addr + 3) & !3usize;
            core::ptr::copy_nonoverlapping(9u32.to_le_bytes().as_ptr(), aligned as *mut u8, 4);
            let timeout = (aligned as *mut u8).add(8);
            core::ptr::copy_nonoverlapping(2i64.to_le_bytes().as_ptr(), timeout, 8);
            core::ptr::copy_nonoverlapping(
                500_000_000i64.to_le_bytes().as_ptr(),
                timeout.add(8),
                8,
            );
            (aligned as u32, timeout as u32)
        };

        let raw =
            dispatch(SYS_FUTEX, ptr as u64, FUTEX_LOCK_PI2 as u64, 0, timeout_ptr as u64, 16, 0);
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::FutexLockPi));
        assert_eq!(plan_arg(0), ptr as u64);
        assert_eq!(plan_arg(1), 9);
        assert_eq!(plan_arg(2), 0);
        assert_eq!(plan_arg(3), timeout_ptr as u64);
        assert_eq!(plan_arg(4), 16);
        assert_eq!(plan_arg(5), FUTEX_PI_TIMEOUT_MONOTONIC);

        let raw = dispatch(
            SYS_FUTEX,
            ptr as u64,
            (FUTEX_LOCK_PI2 | FUTEX_CLOCK_REALTIME) as u64,
            0,
            timeout_ptr as u64,
            16,
            0,
        );
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::FutexLockPi));
        assert_eq!(plan_arg(5), FUTEX_PI_TIMEOUT_REALTIME);

        let raw =
            dispatch(SYS_FUTEX, ptr as u64, FUTEX_LOCK_PI2 as u64, 0, timeout_ptr as u64, 0, 0);
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::FutexLockPi));
        assert_eq!(plan_arg(3), timeout_ptr as u64);
        assert_eq!(plan_arg(4), 0);
        assert_eq!(plan_arg(5), FUTEX_PI_TIMEOUT_MONOTONIC);
    }

    #[test]
    fn epoll_create_legacy_plans_create1_without_flags() {
        let _guard = test_guard();
        let raw = dispatch(SYS_EPOLL_CREATE, 16, 0, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::EpollCreate1));
        assert_eq!(plan_arg(0), 0);

        let raw = dispatch(SYS_EPOLL_CREATE, 0, 0, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Error);
        assert_eq!(step.value, -ERR_EINVAL);
    }

    #[test]
    fn epoll_event_encoding_preserves_ready_mask() {
        let _guard = test_guard();
        let mut records = [0u8; 12];
        records[0..4].copy_from_slice(&vmos_abi::EPOLLOUT.to_le_bytes());
        records[4..12].copy_from_slice(&0xace0_0003u64.to_le_bytes());

        let len = pack_epoll_events(&records, 1);
        assert_eq!(len, 12);
        let result = unsafe {
            core::slice::from_raw_parts(
                core::ptr::addr_of!(RESULT_BUFFER) as *const u8,
                len as usize,
            )
        };
        assert_eq!(u32::from_le_bytes(result[0..4].try_into().unwrap()), vmos_abi::EPOLLOUT);
        assert_eq!(u64::from_le_bytes(result[4..12].try_into().unwrap()), 0xace0_0003);
    }

    #[test]
    fn fcntl_setlk_plan_decodes_flock_from_arg_buffer() {
        let _guard = test_guard();
        const F_SETLK: u64 = 6;
        const F_WRLCK: i16 = 1;
        const SEEK_SET: i16 = 0;

        let mut flock = [0u8; 32];
        flock[0..2].copy_from_slice(&F_WRLCK.to_le_bytes());
        flock[2..4].copy_from_slice(&SEEK_SET.to_le_bytes());
        flock[8..16].copy_from_slice(&16i64.to_le_bytes());
        flock[16..24].copy_from_slice(&8i64.to_le_bytes());

        let ptr = core::ptr::addr_of!(ARG_BUFFER) as usize as u32;
        unsafe {
            core::ptr::copy_nonoverlapping(
                flock.as_ptr(),
                core::ptr::addr_of_mut!(ARG_BUFFER) as *mut u8,
                flock.len(),
            );
        }

        let raw = dispatch(SYS_FCNTL, 4, F_SETLK, ptr as u64, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::FcntlSetlk));
        assert_eq!(plan_arg(0), 4);
        assert_eq!(plan_arg(1), F_SETLK);
        assert_eq!(plan_arg(2) as i16, F_WRLCK);
        assert_eq!(plan_arg(3) as i16, SEEK_SET);
        assert_eq!(plan_arg(4) as i64, 16);
        assert_eq!(plan_arg(5) as i64, 8);
    }

    #[test]
    fn fcntl_getlk_plan_decodes_flock_from_arg_buffer() {
        let _guard = test_guard();
        const F_GETLK: u64 = 5;
        const F_RDLCK: i16 = 0;
        const SEEK_SET: i16 = 0;

        let mut flock = [0u8; 32];
        flock[0..2].copy_from_slice(&F_RDLCK.to_le_bytes());
        flock[2..4].copy_from_slice(&SEEK_SET.to_le_bytes());
        flock[8..16].copy_from_slice(&16i64.to_le_bytes());
        flock[16..24].copy_from_slice(&8i64.to_le_bytes());

        let ptr = core::ptr::addr_of!(ARG_BUFFER) as usize as u32;
        unsafe {
            core::ptr::copy_nonoverlapping(
                flock.as_ptr(),
                core::ptr::addr_of_mut!(ARG_BUFFER) as *mut u8,
                flock.len(),
            );
        }

        let raw = dispatch(SYS_FCNTL, 4, F_GETLK, ptr as u64, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::FcntlGetlk));
        assert_eq!(plan_arg(0), 4);
        assert_eq!(plan_arg(1), ptr as u64);
        assert_eq!(plan_arg(2) as i16, F_RDLCK);
        assert_eq!(plan_arg(3) as i16, SEEK_SET);
        assert_eq!(plan_arg(4) as i64, 16);
        assert_eq!(plan_arg(5) as i64, 8);
    }

    #[test]
    fn flock_plan_preserves_fd_and_operation() {
        let _guard = test_guard();
        const LOCK_EX: u64 = 2;
        const LOCK_NB: u64 = 4;

        let raw = dispatch(SYS_FLOCK, 9, LOCK_EX | LOCK_NB, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Flock));
        assert_eq!(plan_arg(0), 9);
        assert_eq!(plan_arg(1), LOCK_EX | LOCK_NB);
    }

    #[test]
    fn ioctl_plan_preserves_fd_request_and_pointer() {
        let _guard = test_guard();
        let raw = dispatch(SYS_IOCTL, 9, 0x1234_5678, 0x2000, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Ioctl));
        assert_eq!(plan_arg(0), 9);
        assert_eq!(plan_arg(1), 0x1234_5678);
        assert_eq!(plan_arg(2), 0x2000);
    }

    #[test]
    fn renameat2_plan_preserves_paths_and_flags() {
        let _guard = test_guard();
        const RENAME_NOREPLACE: u64 = 1;

        let old = b"/sandbox/old";
        let new = b"/sandbox/new";
        let base = core::ptr::addr_of_mut!(ARG_BUFFER) as *mut u8;
        let old_ptr = base as usize as u32;
        let new_ptr = old_ptr + old.len() as u32;
        unsafe {
            core::ptr::copy_nonoverlapping(old.as_ptr(), base, old.len());
            core::ptr::copy_nonoverlapping(new.as_ptr(), base.add(old.len()), new.len());
        }

        let packed = pack_rename_len_flags(new.len() as u64, RENAME_NOREPLACE);
        let raw = dispatch(
            SYS_RENAMEAT2,
            AT_FDCWD_ENCODED,
            old_ptr as u64,
            old.len() as u64,
            AT_FDCWD_ENCODED,
            new_ptr as u64,
            packed,
        );
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::RenameAt2));
        assert_eq!(plan_arg(0), AT_FDCWD_ENCODED);
        assert_eq!(plan_arg(1), old_ptr as u64);
        assert_eq!(plan_arg(2), old.len() as u64);
        assert_eq!(plan_arg(3), AT_FDCWD_ENCODED);
        assert_eq!(plan_arg(4), new_ptr as u64);
        assert_eq!(plan_arg(5) & 0xffff_ffff, new.len() as u64);
        assert_eq!(plan_arg(5) >> 32, RENAME_NOREPLACE);
    }

    #[test]
    fn rename_and_renameat_pack_lengths_without_flags() {
        let _guard = test_guard();
        let old = b"/sandbox/a";
        let new = b"/sandbox/b";
        let base = core::ptr::addr_of_mut!(ARG_BUFFER) as *mut u8;
        let old_ptr = base as usize as u32;
        let new_ptr = old_ptr + old.len() as u32;
        unsafe {
            core::ptr::copy_nonoverlapping(old.as_ptr(), base, old.len());
            core::ptr::copy_nonoverlapping(new.as_ptr(), base.add(old.len()), new.len());
        }

        let raw = dispatch(
            SYS_RENAME,
            old_ptr as u64,
            old.len() as u64,
            new_ptr as u64,
            new.len() as u64,
            0,
            0,
        );
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::RenameAt2));
        assert_eq!(plan_arg(0), AT_FDCWD_ENCODED);
        assert_eq!(plan_arg(1), old_ptr as u64);
        assert_eq!(plan_arg(2), old.len() as u64);
        assert_eq!(plan_arg(3), AT_FDCWD_ENCODED);
        assert_eq!(plan_arg(4), new_ptr as u64);
        assert_eq!(plan_arg(5) & 0xffff_ffff, new.len() as u64);
        assert_eq!(plan_arg(5) >> 32, 0);

        let raw = dispatch(
            SYS_RENAMEAT,
            AT_FDCWD_ENCODED,
            old_ptr as u64,
            old.len() as u64,
            AT_FDCWD_ENCODED,
            new_ptr as u64,
            new.len() as u64,
        );
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::RenameAt2));
        assert_eq!(plan_arg(0), AT_FDCWD_ENCODED);
        assert_eq!(plan_arg(1), old_ptr as u64);
        assert_eq!(plan_arg(2), old.len() as u64);
        assert_eq!(plan_arg(3), AT_FDCWD_ENCODED);
        assert_eq!(plan_arg(4), new_ptr as u64);
        assert_eq!(plan_arg(5) & 0xffff_ffff, new.len() as u64);
        assert_eq!(plan_arg(5) >> 32, 0);
    }

    #[test]
    fn link_and_linkat_pack_lengths_and_flags() {
        let _guard = test_guard();
        const AT_SYMLINK_FOLLOW: u64 = 0x400;

        let old = b"/sandbox/source";
        let new = b"/sandbox/alias";
        let base = core::ptr::addr_of_mut!(ARG_BUFFER) as *mut u8;
        let old_ptr = base as usize as u32;
        let new_ptr = old_ptr + old.len() as u32;
        unsafe {
            core::ptr::copy_nonoverlapping(old.as_ptr(), base, old.len());
            core::ptr::copy_nonoverlapping(new.as_ptr(), base.add(old.len()), new.len());
        }

        let raw = dispatch(
            SYS_LINK,
            old_ptr as u64,
            old.len() as u64,
            new_ptr as u64,
            new.len() as u64,
            0,
            0,
        );
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::LinkAt));
        assert_eq!(plan_arg(0), AT_FDCWD_ENCODED);
        assert_eq!(plan_arg(1), old_ptr as u64);
        assert_eq!(plan_arg(2), old.len() as u64);
        assert_eq!(plan_arg(3), AT_FDCWD_ENCODED);
        assert_eq!(plan_arg(4), new_ptr as u64);
        assert_eq!(plan_arg(5) & 0xffff_ffff, new.len() as u64);
        assert_eq!(plan_arg(5) >> 32, 0);

        let packed = pack_rename_len_flags(new.len() as u64, AT_SYMLINK_FOLLOW);
        let raw = dispatch(
            SYS_LINKAT,
            AT_FDCWD_ENCODED,
            old_ptr as u64,
            old.len() as u64,
            AT_FDCWD_ENCODED,
            new_ptr as u64,
            packed,
        );
        let step = PackedStep::decode(raw);
        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::LinkAt));
        assert_eq!(plan_arg(5) & 0xffff_ffff, new.len() as u64);
        assert_eq!(plan_arg(5) >> 32, AT_SYMLINK_FOLLOW);
    }

    #[test]
    fn prlimit64_plan_preserves_limit_pointers() {
        let _guard = test_guard();
        let raw = dispatch(SYS_PRLIMIT64, 0, 7, 0x1000, 0x1010, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Prlimit64));
        assert_eq!(plan_arg(0), 0);
        assert_eq!(plan_arg(1), 7);
        assert_eq!(plan_arg(2), 0x1000);
        assert_eq!(plan_arg(3), 0x1010);
        assert_eq!(plan_arg(4), 0);
        assert_eq!(plan_arg(5), 0);
    }

    #[test]
    fn legacy_rlimit_syscalls_plan_distinct_operations() {
        let _guard = test_guard();
        let raw = dispatch(SYS_GETRLIMIT, 7, 0x2000, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Getrlimit));
        assert_eq!(plan_arg(0), 7);
        assert_eq!(plan_arg(1), 0x2000);
        assert_eq!(plan_arg(2), 0);

        let raw = dispatch(SYS_SETRLIMIT, 9, 0x2010, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Setrlimit));
        assert_eq!(plan_arg(0), 9);
        assert_eq!(plan_arg(1), 0x2010);
        assert_eq!(plan_arg(2), 0);
    }

    #[test]
    fn poll_plan_preserves_pollfd_pointer_count_and_timeout() {
        let _guard = test_guard();
        let raw = dispatch(SYS_POLL, 0x2000, 3, 250, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Poll));
        assert_eq!(plan_arg(0), 0x2000);
        assert_eq!(plan_arg(1), 3);
        assert_eq!(plan_arg(2), 250);
        assert_eq!(plan_arg(3), 0);
    }

    #[test]
    fn pipe_plans_preserve_pointer_and_flags() {
        let _guard = test_guard();

        let pipe = PackedStep::decode(dispatch(SYS_PIPE, 0x1000, 0xdead, 0, 0, 0, 0));
        assert_eq!(pipe.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(pipe.aux), Some(PlanKind::Pipe));
        assert_eq!(plan_arg(0), 0x1000);
        assert_eq!(plan_arg(1), 0);

        let pipe2 = PackedStep::decode(dispatch(SYS_PIPE2, 0x2000, 0o2004000, 0, 0, 0, 0));
        assert_eq!(pipe2.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(pipe2.aux), Some(PlanKind::Pipe));
        assert_eq!(plan_arg(0), 0x2000);
        assert_eq!(plan_arg(1), 0o2004000);
    }

    #[test]
    fn mmap_plan_preserves_flags_fd_and_offset() {
        let _guard = test_guard();
        let raw = dispatch(SYS_MMAP, 0, 0x3000, 0x3, 0x22, u64::MAX, 0x1000);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Mmap));
        assert_eq!(plan_arg(0), 0);
        assert_eq!(plan_arg(1), 0x3000);
        assert_eq!(plan_arg(2), 0x3);
        assert_eq!(plan_arg(3), 0x22);
        assert_eq!(plan_arg(4), u64::MAX);
        assert_eq!(plan_arg(5), 0x1000);
    }

    #[test]
    fn memlock_syscalls_plan_distinct_operations() {
        let _guard = test_guard();
        let raw = dispatch(SYS_MLOCK, 0x4003, 0x2000, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Mlock));
        assert_eq!(plan_arg(0), 0x4003);
        assert_eq!(plan_arg(1), 0x2000);
        assert_eq!(plan_arg(2), 0);

        let raw = dispatch(SYS_MLOCK2, 0x5000, 0x1000, 1, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Mlock));
        assert_eq!(plan_arg(0), 0x5000);
        assert_eq!(plan_arg(1), 0x1000);
        assert_eq!(plan_arg(2), 1);

        let raw = dispatch(SYS_MUNLOCK, 0x4000, 0x1000, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Munlock));
        assert_eq!(plan_arg(0), 0x4000);
        assert_eq!(plan_arg(1), 0x1000);

        let raw = dispatch(SYS_MLOCKALL, 0x3, 0, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Mlockall));
        assert_eq!(plan_arg(0), 0x3);

        let raw = dispatch(SYS_MUNLOCKALL, 0, 0, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Munlockall));
    }

    #[test]
    fn seccomp_plan_preserves_operation_flags_and_args_pointer() {
        let _guard = test_guard();
        let raw = dispatch(SYS_SECCOMP, 1, 2, 0x1234, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Seccomp));
        assert_eq!(plan_arg(0), 1);
        assert_eq!(plan_arg(1), 2);
        assert_eq!(plan_arg(2), 0x1234);
    }

    #[test]
    fn bpf_plan_preserves_command_attr_pointer_and_size() {
        let _guard = test_guard();
        let raw = dispatch(SYS_BPF, 2, 0x1234, 32, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Bpf));
        assert_eq!(plan_arg(0), 2);
        assert_eq!(plan_arg(1), 0x1234);
        assert_eq!(plan_arg(2), 32);
    }

    #[test]
    fn prctl_plan_preserves_option_and_arguments() {
        let _guard = test_guard();
        let raw = dispatch(SYS_PRCTL, 38, 1, 0x1234, 0x5678, 0x9abc, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Prctl));
        assert_eq!(plan_arg(0), 38);
        assert_eq!(plan_arg(1), 1);
        assert_eq!(plan_arg(2), 0x1234);
        assert_eq!(plan_arg(3), 0x5678);
        assert_eq!(plan_arg(4), 0x9abc);
    }

    #[test]
    fn ptrace_plan_preserves_request_pid_addr_and_data() {
        let _guard = test_guard();
        let raw = dispatch(SYS_PTRACE, 0x4206, 42, 0x1234, 0x80, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Ptrace));
        assert_eq!(plan_arg(0), 0x4206);
        assert_eq!(plan_arg(1), 42);
        assert_eq!(plan_arg(2), 0x1234);
        assert_eq!(plan_arg(3), 0x80);
    }

    #[test]
    fn robust_list_plans_preserve_registration_and_query_pointers() {
        let _guard = test_guard();
        let set = PackedStep::decode(dispatch(SYS_SET_ROBUST_LIST, 0x7000, 24, 0, 0, 0, 0));
        assert_eq!(set.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(set.aux), Some(PlanKind::SetRobustList));
        assert_eq!(plan_arg(0), 0x7000);
        assert_eq!(plan_arg(1), 24);

        let get = PackedStep::decode(dispatch(SYS_GET_ROBUST_LIST, 12, 0x7100, 0x7200, 0, 0, 0));
        assert_eq!(get.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(get.aux), Some(PlanKind::GetRobustList));
        assert_eq!(plan_arg(0), 12);
        assert_eq!(plan_arg(1), 0x7100);
        assert_eq!(plan_arg(2), 0x7200);
    }

    #[test]
    fn set_tid_address_plan_preserves_clear_child_tid_pointer() {
        let _guard = test_guard();
        let set = PackedStep::decode(dispatch(SYS_SET_TID_ADDRESS, 0x7300, 0, 0, 0, 0, 0));

        assert_eq!(set.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(set.aux), Some(PlanKind::SetTidAddress));
        assert_eq!(plan_arg(0), 0x7300);

        let clear = PackedStep::decode(dispatch(SYS_SET_TID_ADDRESS, 0, 0, 0, 0, 0, 0));
        assert_eq!(clear.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(clear.aux), Some(PlanKind::SetTidAddress));
        assert_eq!(plan_arg(0), 0);
    }

    #[test]
    fn clock_adjtime_plan_preserves_clock_and_timex_pointer() {
        let _guard = test_guard();
        let raw = dispatch(SYS_CLOCK_ADJTIME, 0, 0x3000, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::ClockAdjtime));
        assert_eq!(plan_arg(0), 0);
        assert_eq!(plan_arg(1), 0x3000);
        assert_eq!(plan_arg(2), 0);
    }

    #[test]
    fn timerfd_plans_preserve_arguments() {
        let _guard = test_guard();

        let create = PackedStep::decode(dispatch(SYS_TIMERFD_CREATE, 1, 0o2004000, 0, 0, 0, 0));
        assert_eq!(create.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(create.aux), Some(PlanKind::TimerfdCreate));
        assert_eq!(plan_arg(0), 1);
        assert_eq!(plan_arg(1), 0o2004000);

        let settime = PackedStep::decode(dispatch(SYS_TIMERFD_SETTIME, 7, 1, 0x3000, 0x3040, 0, 0));
        assert_eq!(settime.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(settime.aux), Some(PlanKind::TimerfdSettime));
        assert_eq!(plan_arg(0), 7);
        assert_eq!(plan_arg(1), 1);
        assert_eq!(plan_arg(2), 0x3000);
        assert_eq!(plan_arg(3), 0x3040);

        let gettime = PackedStep::decode(dispatch(SYS_TIMERFD_GETTIME, 7, 0x3080, 0, 0, 0, 0));
        assert_eq!(gettime.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(gettime.aux), Some(PlanKind::TimerfdGettime));
        assert_eq!(plan_arg(0), 7);
        assert_eq!(plan_arg(1), 0x3080);
    }

    #[test]
    fn eventfd_plans_preserve_initval_and_flags() {
        let _guard = test_guard();

        let eventfd = PackedStep::decode(dispatch(SYS_EVENTFD, 5, 0xdead, 0, 0, 0, 0));
        assert_eq!(eventfd.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(eventfd.aux), Some(PlanKind::Eventfd));
        assert_eq!(plan_arg(0), 5);
        assert_eq!(plan_arg(1), 0);

        let eventfd2 = PackedStep::decode(dispatch(SYS_EVENTFD2, 7, 0o2004001, 0, 0, 0, 0));
        assert_eq!(eventfd2.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(eventfd2.aux), Some(PlanKind::Eventfd));
        assert_eq!(plan_arg(0), 7);
        assert_eq!(plan_arg(1), 0o2004001);
    }

    #[test]
    fn clock_gettime_plan_preserves_clock_and_timespec_pointer() {
        let _guard = test_guard();
        let raw = dispatch(SYS_CLOCK_GETTIME, 11, 0x3040, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::ClockGettime));
        assert_eq!(plan_arg(0), 11);
        assert_eq!(plan_arg(1), 0x3040);
    }

    #[test]
    fn clock_getres_plan_preserves_clock_and_optional_timespec_pointer() {
        let _guard = test_guard();
        let raw = dispatch(SYS_CLOCK_GETRES, 1, 0, 0, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::ClockGetres));
        assert_eq!(plan_arg(0), 1);
        assert_eq!(plan_arg(1), 0);
    }

    #[test]
    fn xattr_plans_use_explicit_name_and_value_lengths() {
        let _guard = test_guard();
        let name = b"user.demo";
        let value = b"value";
        let base = core::ptr::addr_of_mut!(ARG_BUFFER) as *mut u8;
        let name_ptr = base as usize as u32;
        let value_ptr = name_ptr + name.len() as u32;
        unsafe {
            core::ptr::copy_nonoverlapping(name.as_ptr(), base, name.len());
            core::ptr::copy_nonoverlapping(value.as_ptr(), base.add(name.len()), value.len());
        }

        let raw = dispatch(
            SYS_FSETXATTR,
            4,
            name_ptr as u64,
            name.len() as u64,
            value_ptr as u64,
            value.len() as u64,
            1,
        );
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Fsetxattr));
        assert_eq!(plan_arg(0), 4);
        assert_eq!(plan_arg(1), name_ptr as u64);
        assert_eq!(plan_arg(2), name.len() as u64);
        assert_eq!(plan_arg(3), value_ptr as u64);
        assert_eq!(plan_arg(4), value.len() as u64);
        assert_eq!(plan_arg(5), 1);

        let raw =
            dispatch(SYS_FGETXATTR, 4, name_ptr as u64, name.len() as u64, value_ptr as u64, 64, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Fgetxattr));
        assert_eq!(plan_arg(0), 4);
        assert_eq!(plan_arg(1), name_ptr as u64);
        assert_eq!(plan_arg(2), name.len() as u64);
        assert_eq!(plan_arg(3), value_ptr as u64);
        assert_eq!(plan_arg(4), 64);

        let raw = dispatch(SYS_FLISTXATTR, 4, value_ptr as u64, 128, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Flistxattr));
        assert_eq!(plan_arg(0), 4);
        assert_eq!(plan_arg(1), value_ptr as u64);
        assert_eq!(plan_arg(2), 128);

        let raw = dispatch(SYS_FREMOVEXATTR, 4, name_ptr as u64, name.len() as u64, 0, 0, 0);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::Fremovexattr));
        assert_eq!(plan_arg(0), 4);
        assert_eq!(plan_arg(1), name_ptr as u64);
        assert_eq!(plan_arg(2), name.len() as u64);
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
