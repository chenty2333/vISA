#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use vmos_abi::{
    EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD, ERR_EEXIST, ERR_EINVAL, ERR_EIO, ERR_ELOOP,
    ERR_ENOENT,
};

const MAX_INSTANCES: usize = 8;
const MAX_WATCHERS: usize = 32;
const MAX_WAITERS: usize = 16;
const EPOLL_READY_RECORD_SIZE: usize = 20;
const RESPONSE_CAPACITY: usize = MAX_WATCHERS * EPOLL_READY_RECORD_SIZE;
const EPOLL_READY_TAG: u64 = 0x6000_0000_0000_0000;
const READY_TAG_MASK: u64 = 0xf000_0000_0000_0000;
const MAX_EPOLL_NESTING_DEPTH: u32 = 5;
const EPOLLONESHOT: u32 = 0x4000_0000;
const EPOLLET: u32 = 0x8000_0000;
const EPOLLEXCLUSIVE: u32 = 0x1000_0000;

static mut REQUEST: [u8; 1] = [0; 1];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut INSTANCES: [Instance; MAX_INSTANCES] = [Instance::EMPTY; MAX_INSTANCES];
static mut WATCHERS: [Watcher; MAX_WATCHERS] = [Watcher::EMPTY; MAX_WATCHERS];
static mut WAITERS: [Waiter; MAX_WAITERS] = [Waiter::EMPTY; MAX_WAITERS];

#[derive(Clone, Copy)]
struct Instance {
    epoll_id: u32,
    active: bool,
}

impl Instance {
    const EMPTY: Self = Self { epoll_id: 0, active: false };
}

#[derive(Clone, Copy)]
struct Watcher {
    epoll_id: u32,
    ready_key: u64,
    events: u32,
    data: u64,
    ready: bool,
    disabled: bool,
    active: bool,
    edge_triggered: bool,
    exclusive: bool,
    readiness_gen: u64,
}

impl Watcher {
    const EMPTY: Self = Self {
        epoll_id: 0,
        ready_key: 0,
        events: 0,
        data: 0,
        ready: false,
        disabled: false,
        active: false,
        edge_triggered: false,
        exclusive: false,
        readiness_gen: 0,
    };
}

#[derive(Clone, Copy)]
struct Waiter {
    epoll_id: u32,
    wait_id: u64,
    active: bool,
}

impl Waiter {
    const EMPTY: Self = Self { epoll_id: 0, wait_id: 0, active: false };
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
pub extern "C" fn create(flags: u32) -> i32 {
    if flags != 0 {
        return -ERR_EINVAL;
    }

    unsafe {
        let instances = core::ptr::addr_of_mut!(INSTANCES) as *mut Instance;
        for index in 0..MAX_INSTANCES {
            let slot = instances.add(index);
            if (*slot).active {
                continue;
            }

            let epoll_id = (index + 1) as u32;
            *slot = Instance { epoll_id, active: true };
            return epoll_id as i32;
        }
    }

    -ERR_EIO
}

#[unsafe(no_mangle)]
pub extern "C" fn ctl(epoll_id: u32, op: u32, ready_key: u64, events: u32, data: u64) -> i32 {
    if !has_instance(epoll_id) {
        return -ERR_ENOENT;
    }

    match op {
        EPOLL_CTL_ADD => add_watcher(epoll_id, ready_key, events, data),
        EPOLL_CTL_MOD => mod_watcher(epoll_id, ready_key, events, data),
        EPOLL_CTL_DEL => del_watcher(epoll_id, ready_key),
        _ => -ERR_EINVAL,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn collect_ready(epoll_id: u32, max_events: u32) -> i32 {
    if !has_instance(epoll_id) {
        return -ERR_ENOENT;
    }

    let max_events = max_events.max(1) as usize;
    let mut written = 0usize;
    unsafe {
        let watchers = core::ptr::addr_of_mut!(WATCHERS) as *mut Watcher;
        let response = addr_of_mut!(RESPONSE) as *mut u8;
        for index in 0..MAX_WATCHERS {
            let slot = watchers.add(index);
            if !(*slot).active || (*slot).disabled || !(*slot).ready || (*slot).epoll_id != epoll_id
            {
                continue;
            }
            if written == max_events {
                break;
            }

            let offset = written * EPOLL_READY_RECORD_SIZE;
            if offset + EPOLL_READY_RECORD_SIZE > RESPONSE_CAPACITY {
                return -ERR_EIO;
            }

            core::ptr::copy_nonoverlapping(
                (*slot).ready_key.to_le_bytes().as_ptr(),
                response.add(offset),
                8,
            );
            core::ptr::copy_nonoverlapping(
                (*slot).events.to_le_bytes().as_ptr(),
                response.add(offset + 8),
                4,
            );
            core::ptr::copy_nonoverlapping(
                (*slot).data.to_le_bytes().as_ptr(),
                response.add(offset + 12),
                8,
            );
            if (*slot).events & EPOLLONESHOT != 0 {
                (*slot).disabled = true;
            }
            // LT watchers: ready stays true if fd is still active (reflects current state)
            // ET watchers: ready cleared after collection (edge consumed)
            if (*slot).edge_triggered {
                (*slot).ready = false;
            }
            written += 1;
        }
    }

    (written * EPOLL_READY_RECORD_SIZE) as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn arm_wait(epoll_id: u32, wait_id: u64) -> i32 {
    if !has_instance(epoll_id) {
        return -ERR_ENOENT;
    }

    unsafe {
        let waiters = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if !(*slot).active {
                *slot = Waiter { epoll_id, wait_id, active: true };
                return 0;
            }
        }
    }

    -ERR_EIO
}

#[unsafe(no_mangle)]
pub extern "C" fn notify_ready(ready_key: u64) -> i32 {
    signal_waiters(ready_key, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn restart_key(ready_key: u64) -> i32 {
    signal_waiters(ready_key, true)
}

#[unsafe(no_mangle)]
pub extern "C" fn cancel_wait(wait_id: u64) -> i32 {
    unsafe {
        let waiters = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if (*slot).active && (*slot).wait_id == wait_id {
                *slot = Waiter::EMPTY;
                return 0;
            }
        }
    }

    -ERR_EINVAL
}

fn add_watcher(epoll_id: u32, ready_key: u64, events: u32, data: u64) -> i32 {
    if let Some(target_epoll_id) = epoll_id_from_ready_key(ready_key) {
        if target_epoll_id == epoll_id {
            return -ERR_EINVAL;
        }
        match epoll_reaches(target_epoll_id, epoll_id) {
            Ok(true) => return -ERR_ELOOP,
            Ok(false) => {}
            Err(errno) => return -errno,
        }
        match epoll_nesting_depth(target_epoll_id) {
            Ok(depth) if 1 + depth < MAX_EPOLL_NESTING_DEPTH => {}
            Ok(_) => return -ERR_EINVAL,
            Err(errno) => return -errno,
        }
    }

    unsafe {
        let watchers = core::ptr::addr_of_mut!(WATCHERS) as *mut Watcher;
        for index in 0..MAX_WATCHERS {
            let slot = watchers.add(index);
            if (*slot).active && (*slot).epoll_id == epoll_id && (*slot).ready_key == ready_key {
                return -ERR_EEXIST;
            }
        }

        for index in 0..MAX_WATCHERS {
            let slot = watchers.add(index);
            if !(*slot).active {
                *slot = Watcher {
                    epoll_id,
                    ready_key,
                    events,
                    data,
                    ready: false,
                    disabled: false,
                    active: true,
                    edge_triggered: events & EPOLLET != 0,
                    exclusive: events & EPOLLEXCLUSIVE != 0,
                    readiness_gen: 0,
                };
                return 0;
            }
        }
    }

    -ERR_EIO
}

fn mod_watcher(epoll_id: u32, ready_key: u64, events: u32, data: u64) -> i32 {
    unsafe {
        let watchers = core::ptr::addr_of_mut!(WATCHERS) as *mut Watcher;
        for index in 0..MAX_WATCHERS {
            let slot = watchers.add(index);
            if (*slot).active && (*slot).epoll_id == epoll_id && (*slot).ready_key == ready_key {
                (*slot).events = events;
                (*slot).data = data;
                (*slot).disabled = false;
                (*slot).edge_triggered = events & EPOLLET != 0;
                (*slot).exclusive = events & EPOLLEXCLUSIVE != 0;
                return 0;
            }
        }
    }

    -ERR_ENOENT
}

fn del_watcher(epoll_id: u32, ready_key: u64) -> i32 {
    unsafe {
        let watchers = core::ptr::addr_of_mut!(WATCHERS) as *mut Watcher;
        for index in 0..MAX_WATCHERS {
            let slot = watchers.add(index);
            if (*slot).active && (*slot).epoll_id == epoll_id && (*slot).ready_key == ready_key {
                *slot = Watcher::EMPTY;
                return 0;
            }
        }
    }

    -ERR_ENOENT
}

fn epoll_nesting_depth(epoll_id: u32) -> Result<u32, i32> {
    let mut seen = [0u32; MAX_INSTANCES];
    epoll_nesting_depth_inner(epoll_id, &mut seen, 0)
}

fn epoll_reaches(start_epoll_id: u32, target_epoll_id: u32) -> Result<bool, i32> {
    let mut seen = [0u32; MAX_INSTANCES];
    epoll_reaches_inner(start_epoll_id, target_epoll_id, &mut seen, 0)
}

fn epoll_reaches_inner(
    start_epoll_id: u32,
    target_epoll_id: u32,
    seen: &mut [u32; MAX_INSTANCES],
    seen_len: usize,
) -> Result<bool, i32> {
    if start_epoll_id == target_epoll_id {
        return Ok(true);
    }
    if seen[..seen_len].contains(&start_epoll_id) {
        return Err(ERR_ELOOP);
    }
    if seen_len == MAX_INSTANCES {
        return Err(ERR_ELOOP);
    }
    seen[seen_len] = start_epoll_id;

    unsafe {
        let watchers = core::ptr::addr_of!(WATCHERS) as *const Watcher;
        for index in 0..MAX_WATCHERS {
            let slot = watchers.add(index);
            if !(*slot).active || (*slot).epoll_id != start_epoll_id {
                continue;
            }
            if let Some(next_epoll_id) = epoll_id_from_ready_key((*slot).ready_key)
                && epoll_reaches_inner(next_epoll_id, target_epoll_id, seen, seen_len + 1)?
            {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn epoll_nesting_depth_inner(
    epoll_id: u32,
    seen: &mut [u32; MAX_INSTANCES],
    seen_len: usize,
) -> Result<u32, i32> {
    if seen[..seen_len].contains(&epoll_id) {
        return Err(ERR_EINVAL);
    }
    if seen_len == MAX_INSTANCES {
        return Err(ERR_EINVAL);
    }
    seen[seen_len] = epoll_id;

    let mut depth = 0u32;
    unsafe {
        let watchers = core::ptr::addr_of!(WATCHERS) as *const Watcher;
        for index in 0..MAX_WATCHERS {
            let slot = watchers.add(index);
            if !(*slot).active || (*slot).epoll_id != epoll_id {
                continue;
            }
            if let Some(target_epoll_id) = epoll_id_from_ready_key((*slot).ready_key) {
                let child_depth = epoll_nesting_depth_inner(target_epoll_id, seen, seen_len + 1)?;
                depth = depth.max(1 + child_depth);
            }
        }
    }
    Ok(depth)
}

fn epoll_id_from_ready_key(ready_key: u64) -> Option<u32> {
    if ready_key & READY_TAG_MASK == EPOLL_READY_TAG {
        u32::try_from(ready_key & !READY_TAG_MASK).ok()
    } else {
        None
    }
}

fn signal_waiters(ready_key: u64, restart: bool) -> i32 {
    // Update readiness for matching watchers
    unsafe {
        let watchers = core::ptr::addr_of_mut!(WATCHERS) as *mut Watcher;
        for index in 0..MAX_WATCHERS {
            let slot = watchers.add(index);
            if !(*slot).active || (*slot).ready_key != ready_key || (*slot).disabled {
                continue;
            }
            if restart {
                continue;
            }
            // LT: always set ready (current state)
            // ET: set ready only if this is a new edge (generation bumped)
            if (*slot).edge_triggered {
                (*slot).readiness_gen = (*slot).readiness_gen.wrapping_add(1);
            }
            (*slot).ready = true;
        }
    }

    // Wake waiters — exclusive semantics: at most one waiter per exclusive watcher
    let mut written = 0usize;
    unsafe {
        let waiters = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        let watchers = core::ptr::addr_of_mut!(WATCHERS) as *mut Watcher;
        let response = addr_of_mut!(RESPONSE) as *mut u8;

        // Track which exclusive watchers have already woken a waiter
        let mut exclusive_woken = [0u8; MAX_WATCHERS];

        for index in 0..MAX_WAITERS {
            let slot = waiters.add(index);
            if !(*slot).active {
                continue;
            }

            let mut should_wake = false;
            for watch_index in 0..MAX_WATCHERS {
                let watch = watchers.add(watch_index);
                if !(*watch).active || (*watch).epoll_id != (*slot).epoll_id {
                    continue;
                }
                if (*watch).ready && (*watch).ready_key == ready_key && !(*watch).disabled {
                    if (*watch).exclusive {
                        if exclusive_woken[watch_index] != 0 {
                            continue; // already woke one for this exclusive watcher
                        }
                        exclusive_woken[watch_index] = 1;
                    }
                    should_wake = true;
                    break;
                }
            }
            if !should_wake {
                continue;
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

fn has_instance(epoll_id: u32) -> bool {
    unsafe {
        let instances = core::ptr::addr_of!(INSTANCES) as *const Instance;
        for index in 0..MAX_INSTANCES {
            let slot = instances.add(index);
            if (*slot).active && (*slot).epoll_id == epoll_id {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn reset() {
        unsafe {
            INSTANCES = [Instance::EMPTY; MAX_INSTANCES];
            WATCHERS = [Watcher::EMPTY; MAX_WATCHERS];
            WAITERS = [Waiter::EMPTY; MAX_WAITERS];
            RESPONSE = [0; RESPONSE_CAPACITY];
        }
    }

    #[test]
    fn mod_watcher_updates_trigger_and_exclusive_flags() {
        let _guard = test_guard();
        reset();
        assert_eq!(create(0), 1);
        assert_eq!(ctl(1, EPOLL_CTL_ADD, 42, EPOLLET | EPOLLEXCLUSIVE | 1, 7), 0);
        assert_eq!(ctl(1, EPOLL_CTL_MOD, 42, 1, 9), 0);

        unsafe {
            let watchers = core::ptr::addr_of!(WATCHERS) as *const Watcher;
            for index in 0..MAX_WATCHERS {
                let watcher = watchers.add(index);
                if (*watcher).active && (*watcher).epoll_id == 1 && (*watcher).ready_key == 42 {
                    assert!(!(*watcher).edge_triggered);
                    assert!(!(*watcher).exclusive);
                    assert_eq!((*watcher).events, 1);
                    assert_eq!((*watcher).data, 9);
                    return;
                }
            }
        }
        panic!("watcher must remain registered");
    }

    #[test]
    fn collect_ready_records_ready_key_events_and_data() {
        let _guard = test_guard();
        reset();
        assert_eq!(create(0), 1);
        assert_eq!(ctl(1, EPOLL_CTL_ADD, 42, 0x5, 7), 0);
        assert_eq!(notify_ready(42), 0);
        assert_eq!(collect_ready(1, 1), EPOLL_READY_RECORD_SIZE as i32);

        unsafe {
            let response = core::ptr::addr_of!(RESPONSE) as *const u8;
            let bytes = core::slice::from_raw_parts(response, EPOLL_READY_RECORD_SIZE);
            assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 42);
            assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 0x5);
            assert_eq!(u64::from_le_bytes(bytes[12..20].try_into().unwrap()), 7);
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
