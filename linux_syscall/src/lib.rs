#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;
use core::slice;

use vmos_abi::{
    EPOLLIN, ERR_EAGAIN, ERR_EINVAL, ERR_ENOSYS, FUTEX_WAIT, FUTEX_WAKE, PackedStep, PlanKind,
    RestartClass, SYS_ACCEPT, SYS_BIND, SYS_CLOSE, SYS_CONNECT, SYS_EPOLL_CREATE1, SYS_EPOLL_CTL,
    SYS_EPOLL_WAIT, SYS_EXIT, SYS_EXIT_GROUP, SYS_FCNTL, SYS_FUTEX, SYS_GETCWD, SYS_GETDENTS64,
    SYS_GETSOCKOPT, SYS_LISTEN, SYS_MMAP, SYS_MUNMAP, SYS_NANOSLEEP, SYS_OPENAT, SYS_POLL,
    SYS_READ, SYS_READLINKAT, SYS_RECVFROM, SYS_SENDTO, SYS_SETSOCKOPT, SYS_SOCKET, SYS_UNAME,
    SYS_WRITE, is_stdio_fd,
};

const ARG_BUFFER_CAPACITY: usize = 256;
const RESULT_BUFFER_CAPACITY: usize = 1024;
const PENDING_SLOTS: usize = 8;
const UTS_FIELD_LEN: usize = 65;

static SLEEP_RESUMED: &[u8] = b"linux frontend: resumed after nanosleep\n";
static mut ARG_BUFFER: [u8; ARG_BUFFER_CAPACITY] = [0; ARG_BUFFER_CAPACITY];
static mut RESULT_BUFFER: [u8; RESULT_BUFFER_CAPACITY] = [0; RESULT_BUFFER_CAPACITY];
static mut PLAN_ARGS: [u64; 6] = [0; 6];
static mut PENDING_OPS: [PendingOp; PENDING_SLOTS] = [PendingOp::Empty; PENDING_SLOTS];

#[derive(Clone, Copy)]
enum PendingOp {
    Empty,
    Sleep,
    FutexWait,
    EpollWait {
        epfd: u32,
        max_events: u32,
        timeout_ms: u64,
    },
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
        SYS_BIND => plan_bind(a0, a1, a2),
        SYS_CONNECT => plan_connect(a0, a1, a2),
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
        SYS_EXIT | SYS_EXIT_GROUP => PackedStep::exit(a0 as i32),
        _ => PackedStep::error(-ERR_ENOSYS),
    };

    step.raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn resume_wait(token: u32) -> u64 {
    match take_pending_op(token) {
        Some(PendingOp::Sleep) => {
            reset_plan(
                PlanKind::Write,
                [
                    vmos_abi::FD_STDOUT as u64,
                    SLEEP_RESUMED.as_ptr() as u64,
                    SLEEP_RESUMED.len() as u64,
                    0,
                    0,
                    0,
                ],
            );
            PackedStep::plan(PlanKind::Write).raw()
        }
        Some(PendingOp::FutexWait) => PackedStep::ready(0).raw(),
        Some(PendingOp::EpollWait {
            epfd, max_events, ..
        }) => {
            reset_plan(
                PlanKind::EpollReady,
                [epfd as u64, max_events as u64, 0, 0, 0, 0],
            );
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
        Some(PendingOp::EpollWait {
            epfd,
            max_events,
            timeout_ms,
        }) => restart_epoll_wait(token, epfd, max_events, timeout_ms, class).raw(),
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
    let clamped = if duration_ms > u32::MAX as u64 {
        u32::MAX
    } else {
        duration_ms as u32
    };
    let Some(resume_cookie) = allocate_pending_op(PendingOp::Sleep) else {
        return PackedStep::error(-ERR_EINVAL);
    };
    reset_plan(
        PlanKind::Sleep,
        [resume_cookie as u64, clamped as u64, 0, 0, 0, 0],
    );
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
    let timeout_ms = if timeout_ptr == 0 || timeout_len == 0 {
        u64::MAX
    } else {
        match parse_timespec_ms(timeout_ptr as u32, timeout_len as u32) {
            Ok(ms) => ms,
            Err(_) => return PackedStep::error(-ERR_EINVAL),
        }
    };
    plan_futex(key, op, val, timeout_ms, current_word)
}

fn plan_futex(key: u64, op: u64, val: u64, timeout_ms: u64, current_word: u64) -> PackedStep {
    match op as u32 {
        FUTEX_WAIT => plan_futex_wait(key, val, timeout_ms, current_word),
        FUTEX_WAKE => plan_futex_wake(key, val),
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
    let timeout = if timeout_ms == u64::MAX {
        u64::MAX
    } else {
        (timeout_ms as u32) as u64
    };
    reset_plan(
        PlanKind::FutexWait,
        [key, timeout, resume_cookie as u64, 0, 0, 0],
    );
    PackedStep::plan(PlanKind::FutexWait)
}

fn plan_futex_wake(key: u64, count: u64) -> PackedStep {
    let count = count.min(u32::MAX as u64);
    reset_plan(PlanKind::FutexWake, [key, count, 0, 0, 0, 0]);
    PackedStep::plan(PlanKind::FutexWake)
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

    let timeout_ms = if timeout_ms < 0_i64 as u64 {
        u64::MAX
    } else {
        timeout_ms
    };
    reset_plan(
        PlanKind::EpollWait,
        [epfd, max_events, timeout_ms, resume_cookie as u64, 0, 0],
    );
    PackedStep::plan(PlanKind::EpollWait)
}

fn plan_socket(domain: u64, ty: u64, protocol: u64) -> PackedStep {
    reset_plan(PlanKind::Socket, [domain, ty, protocol, 0, 0, 0]);
    PackedStep::plan(PlanKind::Socket)
}

fn plan_bind(fd: u64, addr: u64, addr_len: u64) -> PackedStep {
    reset_plan(PlanKind::Bind, [fd, addr, addr_len, 0, 0, 0]);
    PackedStep::plan(PlanKind::Bind)
}

fn plan_connect(fd: u64, addr: u64, addr_len: u64) -> PackedStep {
    reset_plan(PlanKind::Connect, [fd, addr, addr_len, 0, 0, 0]);
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
    reset_plan(
        PlanKind::SetSockOpt,
        [fd, level, optname, optval, optlen, 0],
    );
    PackedStep::plan(PlanKind::SetSockOpt)
}

fn plan_getsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> PackedStep {
    reset_plan(
        PlanKind::GetSockOpt,
        [fd, level, optname, optval, optlen, 0],
    );
    PackedStep::plan(PlanKind::GetSockOpt)
}

fn plan_fcntl(fd: u64, cmd: u64, arg: u64) -> PackedStep {
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
        [
            epfd as u64,
            max_events as u64,
            timeout_ms,
            resume_cookie as u64,
            0,
            0,
        ],
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

    Ok((tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add((tv_nsec as u64).div_ceil(1_000_000)))
}

fn arg_bytes(ptr: u32, len: u32) -> Result<&'static [u8], i32> {
    let base = core::ptr::addr_of!(ARG_BUFFER) as usize as u32;
    let end = ptr.checked_add(len).ok_or(-ERR_EINVAL)?;
    if ptr < base || end > base + ARG_BUFFER_CAPACITY as u32 {
        return Err(-ERR_EINVAL);
    }

    Ok(unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) })
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
    if records.len() % 12 != 0 {
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

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
