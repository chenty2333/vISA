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
    priority: u32,
    pi: bool,
    requeue_pi: bool,
    active: bool,
}

impl Waiter {
    const EMPTY: Self = Self {
        key: 0,
        wait_id: 0,
        bitset: 0,
        priority: 0,
        pi: false,
        requeue_pi: false,
        active: false,
    };
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
    register_wait_with_priority(key, wait_id, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn register_wait_bitset(key: u64, wait_id: u64, bitset: u32) -> i32 {
    register_wait_bitset_with_priority(key, wait_id, bitset, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn register_wait_with_priority(key: u64, wait_id: u64, priority: u32) -> i32 {
    register_wait_bitset_with_priority(key, wait_id, u32::MAX, priority)
}

#[unsafe(no_mangle)]
pub extern "C" fn register_wait_bitset_with_priority(
    key: u64,
    wait_id: u64,
    bitset: u32,
    priority: u32,
) -> i32 {
    register_wait_common(key, wait_id, bitset, priority, false, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn register_wait_pi(key: u64, wait_id: u64, priority: u32) -> i32 {
    register_wait_common(key, wait_id, u32::MAX, priority, true, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn register_wait_requeue_pi(key: u64, wait_id: u64, priority: u32) -> i32 {
    register_wait_common(key, wait_id, u32::MAX, priority, true, true)
}

fn register_wait_common(
    key: u64,
    wait_id: u64,
    bitset: u32,
    priority: u32,
    pi: bool,
    requeue_pi: bool,
) -> i32 {
    unsafe {
        let base = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        for index in 0..MAX_WAITERS {
            let slot = base.add(index);
            if !(*slot).active {
                *slot = Waiter { key, wait_id, bitset, priority, pi, requeue_pi, active: true };
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
pub extern "C" fn peek_waiter(key: u64) -> i32 {
    peek_waiter_common(key, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn peek_pi_waiter(key: u64) -> i32 {
    peek_waiter_common(key, true)
}

fn peek_waiter_common(key: u64, pi_only: bool) -> i32 {
    unsafe {
        let waiters = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        let response = addr_of_mut!(RESPONSE) as *mut u8;
        let Some(index) = select_waiter_index(waiters, key, u32::MAX, pi_only) else {
            return 0;
        };
        let slot = waiters.add(index);
        core::ptr::copy_nonoverlapping((*slot).wait_id.to_le_bytes().as_ptr(), response, 8);
    }
    8
}

#[unsafe(no_mangle)]
pub extern "C" fn waiter_count(key: u64) -> i32 {
    waiter_count_common(key, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn pi_waiter_count(key: u64) -> i32 {
    waiter_count_common(key, true)
}

fn waiter_count_common(key: u64, pi_only: bool) -> i32 {
    let mut count = 0i32;
    unsafe {
        let waiters = core::ptr::addr_of!(WAITERS) as *const Waiter;
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if (*slot).active
                && (*slot).key == key
                && !(*slot).requeue_pi
                && (!pi_only || (*slot).pi)
            {
                count += 1;
            }
        }
    }
    count
}

#[unsafe(no_mangle)]
pub extern "C" fn wake_bitset(key: u64, max_count: u32, bitset: u32) -> i32 {
    let max_count = max_count as usize;
    let mut written = 0usize;

    unsafe {
        let waiters = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        let response = addr_of_mut!(RESPONSE) as *mut u8;
        while written < max_count {
            let Some(index) = select_waiter_index(waiters, key, bitset, false) else {
                break;
            };
            let slot = waiters.add(index);
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

        // First pass: wake up to wake_count waiters from src_key.
        while woken < wake_count {
            let Some(index) = select_waiter_index(waiters, src_key, u32::MAX, false) else {
                break;
            };
            let slot = waiters.add(index);
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

        // Second pass: requeue up to count waiters from src_key to dst_key.
        let mut requeued = 0usize;
        while requeued < count {
            let Some(index) = select_waiter_index(waiters, src_key, u32::MAX, false) else {
                break;
            };
            let slot = waiters.add(index);
            (*slot).key = dst_key;
            requeued += 1;
        }

        let total = (requeued + woken) as u64;
        core::ptr::copy_nonoverlapping(total.to_le_bytes().as_ptr(), response, 8);
    }

    (8 + woken * 8) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn requeue_pi(src_key: u64, count: u32, dst_key: u64) -> i32 {
    let count = count as usize;
    let mut requeued = 0usize;

    unsafe {
        let waiters = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        let response = addr_of_mut!(RESPONSE) as *mut u8;
        if RESPONSE_CAPACITY < 8 {
            return -ERR_EIO;
        }

        while requeued < count {
            let Some(index) = select_requeue_pi_waiter_index(waiters, src_key) else {
                break;
            };
            let slot = waiters.add(index);
            (*slot).key = dst_key;
            (*slot).requeue_pi = false;
            requeued += 1;
        }

        core::ptr::copy_nonoverlapping((requeued as u64).to_le_bytes().as_ptr(), response, 8);
    }

    8
}

#[unsafe(no_mangle)]
pub extern "C" fn max_priority(key: u64) -> i32 {
    unsafe {
        let waiters = core::ptr::addr_of!(WAITERS) as *const Waiter;
        let mut best = 0u32;
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if !(*slot).active || (*slot).key != key || (*slot).requeue_pi {
                continue;
            }
            if (*slot).priority > best {
                best = (*slot).priority;
            }
        }
        best as i32
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn max_priority_excluding(key: u64, excluded_wait_id: u64) -> i32 {
    max_priority_excluding_common(key, excluded_wait_id, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn max_pi_priority_excluding(key: u64, excluded_wait_id: u64) -> i32 {
    max_priority_excluding_common(key, excluded_wait_id, true)
}

fn max_priority_excluding_common(key: u64, excluded_wait_id: u64, pi_only: bool) -> i32 {
    unsafe {
        let waiters = core::ptr::addr_of!(WAITERS) as *const Waiter;
        let mut best = 0u32;
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if !(*slot).active
                || (*slot).key != key
                || (*slot).wait_id == excluded_wait_id
                || (*slot).requeue_pi
                || (pi_only && !(*slot).pi)
            {
                continue;
            }
            if (*slot).priority > best {
                best = (*slot).priority;
            }
        }
        best as i32
    }
}

fn select_waiter_index(
    waiters: *mut Waiter,
    key: u64,
    bitset: u32,
    pi_only: bool,
) -> Option<usize> {
    let mut best_index = None;
    let mut best_priority = 0u32;
    unsafe {
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if !(*slot).active
                || (*slot).key != key
                || (*slot).requeue_pi
                || (pi_only && !(*slot).pi)
            {
                continue;
            }
            if bitset != u32::MAX && (*slot).bitset & bitset == 0 {
                continue;
            }
            if best_index.is_none() || (*slot).priority > best_priority {
                best_index = Some(index);
                best_priority = (*slot).priority;
            }
        }
    }
    best_index
}

fn select_requeue_pi_waiter_index(waiters: *mut Waiter, key: u64) -> Option<usize> {
    let mut best_index = None;
    let mut best_priority = 0u32;
    unsafe {
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if !(*slot).active || (*slot).key != key || !(*slot).requeue_pi {
                continue;
            }
            if best_index.is_none() || (*slot).priority > best_priority {
                best_index = Some(index);
                best_priority = (*slot).priority;
            }
        }
    }
    best_index
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
    fn wake_prefers_higher_priority_waiters() {
        reset();
        assert_eq!(register_wait_with_priority(11, 7, 1), 0);
        assert_eq!(register_wait_with_priority(11, 8, 9), 0);
        assert_eq!(register_wait_with_priority(11, 9, 4), 0);
        assert_eq!(wake(11, 1), 8);
        assert_eq!(response_wait_id(0), 8);
        unsafe {
            let waiters = core::ptr::addr_of!(WAITERS) as *const Waiter;
            let mut seen_7 = false;
            let mut seen_9 = false;
            for index in 0..MAX_WAITERS {
                let slot = waiters.add(index);
                if !(*slot).active {
                    continue;
                }
                match (*slot).wait_id {
                    7 => seen_7 = true,
                    9 => seen_9 = true,
                    other => panic!("unexpected waiter id {}", other),
                }
            }
            assert!(seen_7);
            assert!(seen_9);
        }
        assert_eq!(max_priority(11), 4);
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

    #[test]
    fn requeue_pi_waiters_are_not_woken_by_plain_wake() {
        reset();
        assert_eq!(register_wait_requeue_pi(11, 7, 5), 0);
        assert_eq!(wake(11, 1), 0);
        assert_eq!(waiter_count(11), 0);
        assert_eq!(requeue_pi(11, 1, 22), 8);
        assert_eq!(requeue_total(), 1);
        assert_eq!(waiter_count(22), 1);
        assert_eq!(wake(22, 1), 8);
        assert_eq!(response_wait_id(0), 7);
    }

    #[test]
    fn pi_waiter_queries_ignore_plain_waiters() {
        reset();
        assert_eq!(register_wait_with_priority(11, 7, 99), 0);
        assert_eq!(register_wait_pi(11, 8, 4), 0);
        assert_eq!(register_wait_pi(11, 9, 7), 0);

        assert_eq!(waiter_count(11), 3);
        assert_eq!(pi_waiter_count(11), 2);
        assert_eq!(max_priority(11), 99);
        assert_eq!(max_pi_priority_excluding(11, 9), 4);
        assert_eq!(max_pi_priority_excluding(11, 8), 7);

        assert_eq!(peek_waiter(11), 8);
        assert_eq!(response_wait_id(0), 7);
        assert_eq!(peek_pi_waiter(11), 8);
        assert_eq!(response_wait_id(0), 9);
    }

    #[test]
    fn requeue_pi_waiters_remain_pi_after_requeue() {
        reset();
        assert_eq!(register_wait_requeue_pi(11, 7, 5), 0);
        assert_eq!(register_wait_with_priority(22, 8, 99), 0);
        assert_eq!(pi_waiter_count(11), 0);

        assert_eq!(requeue_pi(11, 1, 22), 8);
        assert_eq!(requeue_total(), 1);
        assert_eq!(waiter_count(22), 2);
        assert_eq!(pi_waiter_count(22), 1);
        assert_eq!(max_pi_priority_excluding(22, 0), 5);
        assert_eq!(max_pi_priority_excluding(22, 7), 0);

        assert_eq!(peek_waiter(22), 8);
        assert_eq!(response_wait_id(0), 8);
        assert_eq!(peek_pi_waiter(22), 8);
        assert_eq!(response_wait_id(0), 7);
    }

    #[test]
    fn requeue_pi_moves_highest_priority_waiters_first() {
        reset();
        assert_eq!(register_wait_requeue_pi(11, 7, 1), 0);
        assert_eq!(register_wait_requeue_pi(11, 8, 9), 0);
        assert_eq!(register_wait_requeue_pi(11, 9, 4), 0);

        assert_eq!(requeue_pi(11, 2, 22), 8);
        assert_eq!(requeue_total(), 2);
        assert_eq!(wake(22, 2), 16);
        assert_eq!(response_wait_id(0), 8);
        assert_eq!(response_wait_id(1), 9);
        assert_eq!(requeue_pi(11, 1, 22), 8);
        assert_eq!(requeue_total(), 1);
        assert_eq!(wake(22, 1), 8);
        assert_eq!(response_wait_id(0), 7);
    }

    #[test]
    fn max_priority_reports_highest_waiter_priority() {
        reset();
        assert_eq!(register_wait_with_priority(11, 7, 3), 0);
        assert_eq!(register_wait_with_priority(11, 8, 11), 0);
        assert_eq!(max_priority(11), 11);
        assert_eq!(max_priority_excluding(11, 8), 3);
        assert_eq!(max_priority_excluding(11, 7), 11);
        assert_eq!(max_priority(22), 0);
    }

    #[test]
    fn peek_waiter_reports_highest_priority_without_removing() {
        reset();
        assert_eq!(register_wait_with_priority(11, 7, 3), 0);
        assert_eq!(register_wait_with_priority(11, 8, 11), 0);
        assert_eq!(register_wait_with_priority(11, 9, 5), 0);

        assert_eq!(peek_waiter(11), 8);
        assert_eq!(response_wait_id(0), 8);
        assert_eq!(waiter_count(11), 3);

        assert_eq!(wake(11, 1), 8);
        assert_eq!(response_wait_id(0), 8);
        assert_eq!(waiter_count(11), 2);
    }

    #[test]
    fn peek_waiter_reports_empty_key_as_zero_len() {
        reset();
        assert_eq!(peek_waiter(99), 0);
        assert_eq!(waiter_count(99), 0);
    }
}
