#![no_std]

use core::panic::PanicInfo;

use vmos_abi::{
    ERR_EINVAL, ERR_ENOSYS, PackedStep, PlanKind, SYS_CLOSE, SYS_EXIT, SYS_EXIT_GROUP, SYS_GETCWD,
    SYS_GETDENTS64, SYS_NANOSLEEP, SYS_OPENAT, SYS_READ, SYS_READLINKAT, SYS_UNAME, SYS_WRITE,
    WAIT_TOKEN_SLEEP, is_stdio_fd,
};

const ARG_BUFFER_CAPACITY: usize = 256;

static SLEEP_RESUMED: &[u8] = b"linux frontend: resumed after nanosleep\n";
static mut ARG_BUFFER: [u8; ARG_BUFFER_CAPACITY] = [0; ARG_BUFFER_CAPACITY];
static mut PLAN_ARGS: [u64; 6] = [0; 6];

#[unsafe(no_mangle)]
pub extern "C" fn dispatch(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    _a3: u64,
    _a4: u64,
    _a5: u64,
) -> u64 {
    let step = match nr {
        SYS_READ => plan_read(a0, a2),
        SYS_WRITE => plan_write(a0, a1, a2),
        SYS_CLOSE => plan_close(a0),
        SYS_NANOSLEEP => dispatch_sleep(a0),
        SYS_UNAME => plan_simple(PlanKind::Uname),
        SYS_GETCWD => plan_getcwd(a1),
        SYS_GETDENTS64 => plan_getdents(a0, a2),
        SYS_OPENAT => plan_openat(a0, a1, a2, _a3, _a4),
        SYS_READLINKAT => plan_readlinkat(a0, a1, a2),
        SYS_EXIT | SYS_EXIT_GROUP => PackedStep::exit(a0 as i32),
        _ => PackedStep::error(-ERR_ENOSYS),
    };

    step.raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn resume_wait(token: u32) -> u64 {
    if token == WAIT_TOKEN_SLEEP {
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
    } else {
        PackedStep::error(-ERR_EINVAL).raw()
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
pub extern "C" fn plan_arg(index: u32) -> u64 {
    if index as usize >= 6 {
        return 0;
    }

    unsafe {
        let base = core::ptr::addr_of!(PLAN_ARGS) as *const u64;
        *base.add(index as usize)
    }
}

fn dispatch_sleep(duration_ms: u64) -> PackedStep {
    let clamped = if duration_ms > u32::MAX as u64 {
        u32::MAX
    } else {
        duration_ms as u32
    };
    PackedStep::pending(WAIT_TOKEN_SLEEP, clamped)
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

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
