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
    bitset: u32,
    active: bool,
}

impl Waiter {
    const EMPTY: Self = Self { key: 0, wait_id: 0, bitset: 0, active: false };
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
    register_wait_bitset(key, wait_id, u32::MAX)
}

#[unsafe(no_mangle)]
pub extern "C" fn register_wait_bitset(key: u64, wait_id: u64, bitset: u32) -> i32 {
    unsafe {
        let base = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        for index in 0..MAX_WAITERS {
            let slot = base.add(index);
            if !(*slot).active {
                *slot = Waiter { key, wait_id, bitset, active: true };
                return 0;
            }
        }
    }

    -ERR_EIO
}

#[unsafe(no_mangle)]
pub extern "C" fn wake(key: u64, max_count: u32) -> i32 {
    wake_bitset(key, max_count, u32::MAX)
}

#[unsafe(no_mangle)]
pub extern "C" fn wake_bitset(key: u64, max_count: u32, bitset: u32) -> i32 {
    let max_count = max_count as usize;
    let mut written = 0usize;

    unsafe {
        let waiters = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        let response = addr_of_mut!(RESPONSE) as *mut u8;
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if !(*slot).active || (*slot).key != key {
                continue;
            }
            // Bitset filter: only wake if waiter's bitset overlaps with wake bitset
            if (*slot).bitset & bitset == 0 {
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
pub extern "C" fn requeue(src_key: u64, count: u32, dst_key: u64, wake_count: u32) -> i32 {
    let count = count as usize;
    let wake_count = wake_count as usize;
    let mut woken = 0usize;

    unsafe {
        let waiters = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        let response = addr_of_mut!(RESPONSE) as *mut u8;
        if RESPONSE_CAPACITY < 8 {
            return -ERR_EIO;
        }

        // First pass: wake up to wake_count waiters from src_key
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if !(*slot).active || (*slot).key != src_key {
                continue;
            }
            if woken < wake_count {
                let offset = 8 + woken * 8;
                if offset + 8 > RESPONSE_CAPACITY {
                    return -ERR_EIO;
                }
                core::ptr::copy_nonoverlapping(
                    (*slot).wait_id.to_le_bytes().as_ptr(),
                    response.add(offset),
                    8,
                );
                *slot = Waiter::EMPTY;
                woken += 1;
            }
        }

        // Second pass: requeue up to count waiters from src_key to dst_key
        let mut requeued = 0usize;
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if !(*slot).active || (*slot).key != src_key {
                continue;
            }
            if requeued < count {
                (*slot).key = dst_key;
                requeued += 1;
            }
        }

        let total = (requeued + woken) as u64;
        core::ptr::copy_nonoverlapping(total.to_le_bytes().as_ptr(), response, 8);
    }

    (8 + woken * 8) as i32
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

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        unsafe {
            WAITERS = [Waiter::EMPTY; MAX_WAITERS];
            RESPONSE = [0; RESPONSE_CAPACITY];
        }
    }

    fn response_wait_id(index: usize) -> u64 {
        unsafe {
            let start = index * 8;
            u64::from_le_bytes(RESPONSE[start..start + 8].try_into().unwrap())
        }
    }

    fn requeue_total() -> u64 {
        unsafe { u64::from_le_bytes(RESPONSE[0..8].try_into().unwrap()) }
    }

    fn requeue_wait_id(index: usize) -> u64 {
        unsafe {
            let start = 8 + index * 8;
            u64::from_le_bytes(RESPONSE[start..start + 8].try_into().unwrap())
        }
    }

    #[test]
    fn wake_zero_count_wakes_no_waiters() {
        reset();
        assert_eq!(register_wait(11, 7), 0);
        assert_eq!(wake(11, 0), 0);
        unsafe {
            let waiters = core::ptr::addr_of!(WAITERS) as *const Waiter;
            assert!((*waiters).active);
            assert_eq!((*waiters).wait_id, 7);
        }
    }

    #[test]
    fn requeue_zero_count_moves_no_waiters() {
        reset();
        assert_eq!(register_wait(11, 7), 0);
        assert_eq!(requeue(11, 0, 22, 0), 8);
        assert_eq!(requeue_total(), 0);
        unsafe {
            let waiters = core::ptr::addr_of!(WAITERS) as *const Waiter;
            assert!((*waiters).active);
            assert_eq!((*waiters).key, 11);
            assert_eq!((*waiters).wait_id, 7);
        }
    }

    #[test]
    fn wake_bitset_only_wakes_overlapping_waiters() {
        reset();
        assert_eq!(register_wait_bitset(11, 7, 0b0100), 0);
        assert_eq!(register_wait_bitset(11, 8, 0b0010), 0);
        assert_eq!(wake_bitset(11, 10, 0b0100), 8);
        assert_eq!(response_wait_id(0), 7);
        unsafe {
            let waiters = core::ptr::addr_of!(WAITERS) as *const Waiter;
            assert!(!(*waiters).active);
            assert!((*waiters.add(1)).active);
            assert_eq!((*waiters.add(1)).wait_id, 8);
        }
    }

    #[test]
    fn requeue_wakes_then_moves_waiters() {
        reset();
        assert_eq!(register_wait(11, 7), 0);
        assert_eq!(register_wait(11, 8), 0);
        assert_eq!(register_wait(11, 9), 0);
        assert_eq!(requeue(11, 2, 22, 1), 16);
        assert_eq!(requeue_total(), 3);
        assert_eq!(requeue_wait_id(0), 7);
        unsafe {
            let waiters = core::ptr::addr_of!(WAITERS) as *const Waiter;
            assert!(!(*waiters).active);
            assert!((*waiters.add(1)).active);
            assert_eq!((*waiters.add(1)).key, 22);
            assert!((*waiters.add(2)).active);
            assert_eq!((*waiters.add(2)).key, 22);
        }
    }
}
