#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use vmos_abi::{ERR_EAGAIN, ERR_EFAULT};

const REQUEST_CAPACITY: usize = 128;
const RESPONSE_CAPACITY: usize = 256;

static mut REQUEST: [u8; REQUEST_CAPACITY] = [0; REQUEST_CAPACITY];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut LAST_CURSOR: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn request_ptr() -> u32 {
    addr_of_mut!(REQUEST) as *mut u8 as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn request_capacity() -> u32 {
    REQUEST_CAPACITY as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn response_ptr() -> u32 {
    addr_of_mut!(RESPONSE) as *mut u8 as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn response_capacity() -> u32 {
    RESPONSE_CAPACITY as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn validate_barrier(
    pending_waits: u32,
    active_transactions: u32,
    active_dmw_leases: u32,
    pending_dma: u32,
) -> i32 {
    if active_dmw_leases != 0 || pending_dma != 0 {
        return -ERR_EFAULT;
    }
    if active_transactions != 0 {
        return -ERR_EAGAIN;
    }
    let _ = pending_waits;
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn replay_until(cursor: u64) -> u64 {
    unsafe {
        LAST_CURSOR = cursor;
        LAST_CURSOR
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn last_replay_cursor() -> u64 {
    unsafe { LAST_CURSOR }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
