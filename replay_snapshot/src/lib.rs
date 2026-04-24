#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use service_core::replay::ReplaySnapshotState;

const REQUEST_CAPACITY: usize = 128;
const RESPONSE_CAPACITY: usize = 256;

static mut REQUEST: [u8; REQUEST_CAPACITY] = [0; REQUEST_CAPACITY];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut STATE: ReplaySnapshotState = ReplaySnapshotState::new();

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
    match unsafe {
        state().validate_barrier(
            pending_waits,
            active_transactions,
            active_dmw_leases,
            pending_dma,
        )
    } {
        Ok(()) => 0,
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn replay_until(cursor: u64) -> u64 {
    unsafe { state().replay_until(cursor) }
}

#[unsafe(no_mangle)]
pub extern "C" fn last_replay_cursor() -> u64 {
    unsafe { state().last_replay_cursor() }
}

unsafe fn state() -> &'static mut ReplaySnapshotState {
    unsafe { &mut *addr_of_mut!(STATE) }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
