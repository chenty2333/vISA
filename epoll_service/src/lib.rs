#![no_std]

use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use vmos_abi::{EPOLL_CTL_ADD, EPOLL_CTL_DEL, ERR_EINVAL, ERR_EIO, ERR_ENOENT};

const RESPONSE_CAPACITY: usize = 16 * 16;
const MAX_INSTANCES: usize = 8;
const MAX_WATCHERS: usize = 32;
const MAX_WAITERS: usize = 16;

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
    const EMPTY: Self = Self {
        epoll_id: 0,
        active: false,
    };
}

#[derive(Clone, Copy)]
struct Watcher {
    epoll_id: u32,
    ready_key: u64,
    events: u32,
    data: u64,
    ready: bool,
    active: bool,
}

impl Watcher {
    const EMPTY: Self = Self {
        epoll_id: 0,
        ready_key: 0,
        events: 0,
        data: 0,
        ready: false,
        active: false,
    };
}

#[derive(Clone, Copy)]
struct Waiter {
    epoll_id: u32,
    wait_id: u64,
    active: bool,
}

impl Waiter {
    const EMPTY: Self = Self {
        epoll_id: 0,
        wait_id: 0,
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
            *slot = Instance {
                epoll_id,
                active: true,
            };
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
            if !(*slot).active || !(*slot).ready || (*slot).epoll_id != epoll_id {
                continue;
            }
            if written == max_events {
                break;
            }

            let offset = written * 12;
            if offset + 12 > RESPONSE_CAPACITY {
                return -ERR_EIO;
            }

            core::ptr::copy_nonoverlapping(
                (*slot).events.to_le_bytes().as_ptr(),
                response.add(offset),
                4,
            );
            core::ptr::copy_nonoverlapping(
                (*slot).data.to_le_bytes().as_ptr(),
                response.add(offset + 4),
                8,
            );
            (*slot).ready = false;
            written += 1;
        }
    }

    (written * 12) as i32
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
                *slot = Waiter {
                    epoll_id,
                    wait_id,
                    active: true,
                };
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
    unsafe {
        let watchers = core::ptr::addr_of_mut!(WATCHERS) as *mut Watcher;
        for index in 0..MAX_WATCHERS {
            let slot = watchers.add(index);
            if (*slot).active && (*slot).epoll_id == epoll_id && (*slot).ready_key == ready_key {
                return -ERR_EINVAL;
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
                    active: true,
                };
                return 0;
            }
        }
    }

    -ERR_EIO
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

fn signal_waiters(ready_key: u64, restart: bool) -> i32 {
    unsafe {
        let watchers = core::ptr::addr_of_mut!(WATCHERS) as *mut Watcher;
        for index in 0..MAX_WATCHERS {
            let slot = watchers.add(index);
            if (*slot).active && (*slot).ready_key == ready_key && !restart {
                (*slot).ready = true;
            }
        }
    }

    let mut written = 0usize;
    unsafe {
        let waiters = core::ptr::addr_of_mut!(WAITERS) as *mut Waiter;
        let watchers = core::ptr::addr_of_mut!(WATCHERS) as *mut Watcher;
        let response = addr_of_mut!(RESPONSE) as *mut u8;
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
                if (*watch).ready_key == ready_key {
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

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
