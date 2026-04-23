#![no_std]

use core::panic::PanicInfo;

use vmos_abi::{ERR_EINVAL, MSG_FAULT_RECOVERY, MSG_LINUX_WRITE, MSG_SLEEP_RESUMED, MSG_WASM_APP};

static WASM_APP: &[u8] = b"wasm frontend: hello from wasm_app\n";
static LINUX_WRITE: &[u8] = b"linux frontend: hello via linux_syscall\n";
static FAULT_RECOVERY: &[u8] = b"console service recovered after injected fault\n";
static SLEEP_RESUMED: &[u8] = b"linux frontend: resumed after nanosleep\n";
static INVALID: &[u8] = b"<invalid message id>\n";

#[unsafe(no_mangle)]
pub extern "C" fn write_message(message_id: u32, inject_fault: u32) -> i32 {
    if inject_fault != 0 && message_id == MSG_FAULT_RECOVERY {
        trap();
    }

    if select_message(message_id).is_some() {
        0
    } else {
        -ERR_EINVAL
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn message_ptr(message_id: u32) -> u32 {
    select_message(message_id).unwrap_or(INVALID).as_ptr() as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn message_len(message_id: u32) -> u32 {
    select_message(message_id).unwrap_or(INVALID).len() as u32
}

fn select_message(message_id: u32) -> Option<&'static [u8]> {
    match message_id {
        MSG_WASM_APP => Some(WASM_APP),
        MSG_LINUX_WRITE => Some(LINUX_WRITE),
        MSG_FAULT_RECOVERY => Some(FAULT_RECOVERY),
        MSG_SLEEP_RESUMED => Some(SLEEP_RESUMED),
        _ => None,
    }
}

#[inline(always)]
fn trap() -> ! {
    #[cfg(target_arch = "wasm32")]
    {
        core::arch::wasm32::unreachable()
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        panic!("console_service trap")
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
