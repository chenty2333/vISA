#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use vmos_abi::{ERR_EINVAL, ERR_EIO};

const RESPONSE_CAPACITY: usize = 8 * 16;
const MAX_WAITERS: usize = 16;

static mut REQUEST: [u8; 1] = [0; 1];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut WAITERS: [Waiter; MAX_WAITERS] = [Waiter::EMPTY; MAX_WAITERS];

#[derive(Clone, Copy)]
struct Waiter {
    key: u64,
    wait_id: u64,
    active: bool,
}

impl Waiter {
    const EMPTY: Self = Self { key: 0, wait_id: 0, active: false };
}

#[unsafe(no_mangle)]
pub extern "C" fn request_ptr() -> u32 {
    addr_of_mut!(REQUEST) as *mut u8 as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn request_capacity() -> u32 {
    1
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
pub extern "C" fn register_wait(key: u64, wait_id: u64) -> i32 {
    unsafe {
        let base = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        for index in 0..MAX_WAITERS {
            let slot = base.add(index);
            if !(*slot).active {
                *slot = Waiter { key, wait_id, active: true };
                return 0;
            }
        }
    }

    -ERR_EIO
}

#[unsafe(no_mangle)]
pub extern "C" fn wake(key: u64, max_count: u32) -> i32 {
    let max_count = max_count.max(1) as usize;
    let mut written = 0usize;

    unsafe {
        let waiters = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        let response = addr_of_mut!(RESPONSE) as *mut u8;
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if !(*slot).active || (*slot).key != key {
                continue;
            }
            if written == max_count {
                break;
            }

            let offset = written * 8;
            if offset + 8 > RESPONSE_CAPACITY {
                return -ERR_EIO;
            }

            core::ptr::copy_nonoverlapping(
                (*slot).wait_id.to_le_bytes().as_ptr(),
                response.add(offset),
                8,
            );
            *slot = Waiter::EMPTY;
            written += 1;
        }
    }

    (written * 8) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn cancel_wait(wait_id: u64) -> i32 {
    unsafe {
        let base = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        for index in 0..MAX_WAITERS {
            let slot = base.add(index);
            if (*slot).active && (*slot).wait_id == wait_id {
                *slot = Waiter::EMPTY;
                return 0;
            }
        }
    }

    -ERR_EINVAL
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
