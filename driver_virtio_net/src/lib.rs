#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use service_core::driver::{DriverVirtioNetState, REQUEST_CAPACITY, RESPONSE_CAPACITY};

pub use service_core::driver::{DriverNetEventKind, DriverNetEventKind as EventKind};

static mut REQUEST: [u8; REQUEST_CAPACITY] = [0; REQUEST_CAPACITY];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut STATE: DriverVirtioNetState = DriverVirtioNetState::new();

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
pub extern "C" fn reset_sequence(now_ticks: u64) {
    unsafe {
        state().reset_sequence(now_ticks);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn poll_device(now_ticks: u64) -> u32 {
    let response = unsafe {
        core::slice::from_raw_parts_mut(addr_of_mut!(RESPONSE) as *mut u8, RESPONSE_CAPACITY)
    };
    unsafe { state().poll_device(now_ticks, response).kind as u32 }
}

#[unsafe(no_mangle)]
pub extern "C" fn event_len() -> u32 {
    unsafe { state().event_len() }
}

#[unsafe(no_mangle)]
pub extern "C" fn consume_packet() {
    unsafe {
        state().consume_packet();
    }
}

unsafe fn state() -> &'static mut DriverVirtioNetState {
    unsafe { &mut *addr_of_mut!(STATE) }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
