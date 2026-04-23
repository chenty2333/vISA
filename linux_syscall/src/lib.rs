#![no_std]

use core::panic::PanicInfo;

use vmos_abi::{
    ERR_EINVAL, ERR_ENOSYS, PackedStep, SYS_EXIT, SYS_EXIT_GROUP, SYS_NANOSLEEP, SYS_WRITE,
    WAIT_TOKEN_SLEEP, is_known_message, is_stdio_fd,
};

#[unsafe(no_mangle)]
pub extern "C" fn dispatch(
    nr: u64,
    a0: u64,
    a1: u64,
    _a2: u64,
    _a3: u64,
    _a4: u64,
    _a5: u64,
) -> u64 {
    let step = match nr {
        SYS_WRITE => dispatch_write(a0, a1 as u32),
        SYS_NANOSLEEP => dispatch_sleep(a0),
        SYS_EXIT | SYS_EXIT_GROUP => PackedStep::exit(a0 as i32),
        _ => PackedStep::error(-ERR_ENOSYS),
    };

    step.raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn resume_wait(token: u32) -> u64 {
    if token == WAIT_TOKEN_SLEEP {
        PackedStep::console_write(vmos_abi::FD_STDOUT, vmos_abi::MSG_SLEEP_RESUMED).raw()
    } else {
        PackedStep::error(-ERR_EINVAL).raw()
    }
}

fn dispatch_write(fd: u64, message_id: u32) -> PackedStep {
    if !is_stdio_fd(fd) || !is_known_message(message_id) {
        return PackedStep::error(-ERR_EINVAL);
    }

    PackedStep::console_write(fd as u32, message_id)
}

fn dispatch_sleep(duration_ms: u64) -> PackedStep {
    let clamped = if duration_ms > u32::MAX as u64 {
        u32::MAX
    } else {
        duration_ms as u32
    };
    PackedStep::pending(WAIT_TOKEN_SLEEP, clamped)
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
