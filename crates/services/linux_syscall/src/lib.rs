#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::{ptr::addr_of_mut, slice};

use vmos_abi::{
    EPOLLIN, ERR_EAGAIN, ERR_EINVAL, ERR_ENOSYS, FUTEX_CMD_MASK, FUTEX_CMP_REQUEUE,
    FUTEX_CMP_REQUEUE_PI, FUTEX_REQUEUE, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAIT_REQUEUE_PI,
    FUTEX_WAKE, FUTEX_WAKE_BITSET, PackedStep, PlanKind, RestartClass, SYS_ACCEPT, SYS_BIND,
    SYS_CLOSE, SYS_CONNECT, SYS_EPOLL_CREATE1, SYS_EPOLL_CTL, SYS_EPOLL_WAIT, SYS_EXIT,
    SYS_EXIT_GROUP, SYS_FCNTL, SYS_FGETXATTR, SYS_FLISTXATTR, SYS_FREMOVEXATTR, SYS_FSETXATTR,
    SYS_FUTEX, SYS_GETCWD, SYS_GETDENTS64, SYS_GETRLIMIT, SYS_GETSOCKOPT, SYS_LISTEN, SYS_MMAP,
    SYS_MUNMAP, SYS_NANOSLEEP, SYS_OPENAT, SYS_POLL, SYS_PRLIMIT64, SYS_READ, SYS_READLINKAT,
    SYS_RECVFROM, SYS_RENAME, SYS_RENAMEAT, SYS_RENAMEAT2, SYS_SENDTO, SYS_SETRLIMIT,
    SYS_SETSOCKOPT, SYS_SOCKET, SYS_UNAME, SYS_WRITE, is_stdio_fd,
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
        SYS_WRITE => plan_write(a0, a1, a2),
        SYS_CLOSE => plan_close(a0),
        SYS_NANOSLEEP => dispatch_nanosleep(a0, a1),
        SYS_FUTEX => dispatch_futex(a0, a1, a2, a3, a4, a5),
        SYS_EPOLL_CREATE1 => plan_epoll_create1(a0),
        SYS_EPOLL_CTL => plan_epoll_ctl(a0, a1, a2, a3, a4),
        SYS_EPOLL_WAIT => plan_epoll_wait(a0, a1, a2),
        SYS_SOCKET => plan_socket(a0, a1, a2),
        SYS_BIND => plan_bind(a0, a1, a2, a3, a4, a5),
        SYS_CONNECT => plan_connect(a0, a1, a2, a3, a4, a5),
        SYS_LISTEN => plan_listen(a0, a1),
        SYS_ACCEPT => plan_accept(a0, a1, a2),
        SYS_SENDTO => plan_sendto(a0, a1, a2, a3, a4, a5),
        SYS_RECVFROM => plan_recvfrom(a0, a1, a2, a3, a4, a5),
        SYS_SETSOCKOPT => plan_setsockopt(a0, a1, a2, a3, a4),
        SYS_GETSOCKOPT => plan_getsockopt(a0, a1, a2, a3, a4),
        SYS_FCNTL => plan_fcntl(a0, a1, a2),
        SYS_MMAP => plan_mmap(a0, a1, a2, a3, a4, a5),
        SYS_MUNMAP => plan_munmap(a0, a1),
        SYS_POLL => plan_poll(a0, a1, a2),
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
        SYS_EXIT | SYS_EXIT_GROUP => PackedStep::exit(a0 as i32),
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

fn plan_epoll_create1(flags: u64) -> PackedStep {
    let flags = (flags as u32) as u64;
    reset_plan(PlanKind::EpollCreate1, [flags, 0, 0, 0, 0, 0]);
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

fn plan_sendto(fd: u64, ptr: u64, len: u64, flags: u64, addr: u64, addr_len: u64) -> PackedStep {
    reset_plan(PlanKind::SendTo, [fd, ptr, len, flags, addr, addr_len]);
    PackedStep::plan(PlanKind::SendTo)
}

fn plan_recvfrom(fd: u64, ptr: u64, len: u64, flags: u64, addr: u64, addr_len: u64) -> PackedStep {
    reset_plan(PlanKind::RecvFrom, [fd, ptr, len, flags, addr, addr_len]);
    PackedStep::plan(PlanKind::RecvFrom)
}

fn plan_setsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> PackedStep {
    reset_plan(PlanKind::SetSockOpt, [fd, level, optname, optval, optlen, 0]);
    PackedStep::plan(PlanKind::SetSockOpt)
}

fn plan_getsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> PackedStep {
    reset_plan(PlanKind::GetSockOpt, [fd, level, optname, optval, optlen, 0]);
    PackedStep::plan(PlanKind::GetSockOpt)
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

fn plan_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, offset: u64) -> PackedStep {
    reset_plan(PlanKind::Mmap, [addr, len, prot, flags, fd, offset]);
    PackedStep::plan(PlanKind::Mmap)
}

fn plan_munmap(addr: u64, len: u64) -> PackedStep {
    reset_plan(PlanKind::Munmap, [addr, len, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Munmap)
}

fn plan_poll(ptr: u64, nfds: u64, timeout_ms: u64) -> PackedStep {
    reset_plan(PlanKind::Poll, [ptr, nfds, timeout_ms, 0, 0, 0]);
    PackedStep::plan(PlanKind::Poll)
}

fn plan_write(fd: u64, ptr: u64, len: u64) -> PackedStep {
    if !is_stdio_fd(fd) && fd < 3 {
        return PackedStep::error(-ERR_EINVAL);
    }

    reset_plan(PlanKind::Write, [fd, ptr, len, 0, 0, 0]);
    PackedStep::plan(PlanKind::Write)
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

fn plan_close(fd: u64) -> PackedStep {
    reset_plan(PlanKind::Close, [fd, 0, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::Close)
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
            events: u32::from_le_bytes(records[offset..offset + 4].try_into().unwrap()) | EPOLLIN,
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
    use super::*;

    #[test]
    fn connect_plan_preserves_sockaddr_metadata() {
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
    fn futex_wait_requeue_pi_plans_distinct_wait_kind() {
        let raw = dispatch_futex_raw(0x1000, FUTEX_WAIT_REQUEUE_PI as u64, 7, u64::MAX, 7);
        let step = PackedStep::decode(raw);

        assert_eq!(step.tag, vmos_abi::StepTag::Plan);
        assert_eq!(PlanKind::from_raw(step.aux), Some(PlanKind::FutexWaitRequeuePi));
        assert_eq!(plan_arg(0), 0x1000);
        assert_eq!(plan_arg(1), u64::MAX);
        assert_ne!(plan_arg(2), 0);
    }

    #[test]
    fn fcntl_setlk_plan_decodes_flock_from_arg_buffer() {
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
    fn renameat2_plan_preserves_paths_and_flags() {
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
    fn prlimit64_plan_preserves_limit_pointers() {
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
    fn xattr_plans_use_explicit_name_and_value_lengths() {
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
