#![no_std]

use core::panic::PanicInfo;

use vmos_abi::{
    ERR_EINVAL, ERR_ENOSYS, MSG_FAULT_RECOVERY, MSG_LINUX_WRITE, MSG_SLEEP_RESUMED, PackedStep,
    SYS_EXIT, SYS_EXIT_GROUP, SYS_NANOSLEEP, SYS_WRITE, WAIT_TOKEN_SLEEP, can_pack_console_ptr,
    is_stdio_fd,
};

static LINUX_WRITE: &[u8] = b"linux frontend: hello via linux_syscall\n";
static FAULT_RECOVERY: &[u8] = b"console service recovered after injected fault\n";
static SLEEP_RESUMED: &[u8] = b"linux frontend: resumed after nanosleep\n";

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
        SYS_WRITE => dispatch_write(a0, a1, a2),
        SYS_NANOSLEEP => dispatch_sleep(a0),
        SYS_EXIT | SYS_EXIT_GROUP => PackedStep::exit(a0 as i32),
        _ => PackedStep::error(-ERR_ENOSYS),
    };

    step.raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn resume_wait(token: u32) -> u64 {
    if token == WAIT_TOKEN_SLEEP {
        PackedStep::console_write(SLEEP_RESUMED.as_ptr() as u32, SLEEP_RESUMED.len() as u32).raw()
    } else {
        PackedStep::error(-ERR_EINVAL).raw()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn demo_message_ptr(message_id: u32) -> u32 {
    select_demo_message(message_id).unwrap_or(&[]).as_ptr() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn demo_message_len(message_id: u32) -> u32 {
    select_demo_message(message_id).unwrap_or(&[]).len() as u32
}

fn dispatch_write(fd: u64, ptr: u64, len: u64) -> PackedStep {
    if !is_stdio_fd(fd) {
        return PackedStep::error(-ERR_EINVAL);
    }

    let Ok(ptr) = u32::try_from(ptr) else {
        return PackedStep::error(-ERR_EINVAL);
    };
    let Ok(len) = u32::try_from(len) else {
        return PackedStep::error(-ERR_EINVAL);
    };
    if !can_pack_console_ptr(ptr) {
        return PackedStep::error(-ERR_EINVAL);
    }

    PackedStep::console_write(ptr, len)
}

fn dispatch_sleep(duration_ms: u64) -> PackedStep {
    let clamped = if duration_ms > u32::MAX as u64 {
        u32::MAX
    } else {
        duration_ms as u32
    };
    PackedStep::pending(WAIT_TOKEN_SLEEP, clamped)
}

fn select_demo_message(message_id: u32) -> Option<&'static [u8]> {
    match message_id {
        MSG_LINUX_WRITE => Some(LINUX_WRITE),
        MSG_FAULT_RECOVERY => Some(FAULT_RECOVERY),
        MSG_SLEEP_RESUMED => Some(SLEEP_RESUMED),
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
