#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use service_core::driver::{DriverVirtioNetState, REQUEST_CAPACITY, RESPONSE_CAPACITY};
use service_core::net_contract::{
    NETWORK_CONTRACT_ABI_VERSION, VIRTIO_NET0_MTU, VIRTIO_NET0_RX_QUEUE_DEPTH,
    VIRTIO_NET0_TX_QUEUE_DEPTH,
};

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
pub extern "C" fn network_contract_version() -> u32 {
    NETWORK_CONTRACT_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn packet_mtu() -> u32 {
    VIRTIO_NET0_MTU
}

#[unsafe(no_mangle)]
pub extern "C" fn packet_rx_queue_depth() -> u32 {
    VIRTIO_NET0_RX_QUEUE_DEPTH
}

#[unsafe(no_mangle)]
pub extern "C" fn packet_tx_queue_depth() -> u32 {
    VIRTIO_NET0_TX_QUEUE_DEPTH
}

#[unsafe(no_mangle)]
pub extern "C" fn reset_sequence(now_ticks: u64) {
    unsafe {
        state().reset_sequence(now_ticks);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn submit_tx_frame(now_ticks: u64, len: u32) -> i32 {
    let len = (len as usize).min(REQUEST_CAPACITY);
    let request = unsafe { core::slice::from_raw_parts(addr_of_mut!(REQUEST) as *const u8, len) };
    match unsafe { state().submit_tx_frame(now_ticks, request) } {
        Ok(len) => len as i32,
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn poll_device(now_ticks: u64) -> u32 {
    unsafe { state().poll_device(now_ticks).kind as u32 }
}

#[unsafe(no_mangle)]
pub extern "C" fn event_len() -> u32 {
    unsafe { state().event_len() }
}

#[unsafe(no_mangle)]
pub extern "C" fn dequeue_rx_frame() -> i32 {
    let response = unsafe {
        core::slice::from_raw_parts_mut(addr_of_mut!(RESPONSE) as *mut u8, RESPONSE_CAPACITY)
    };
    match unsafe { state().dequeue_rx_frame(response) } {
        Ok(len) => len as i32,
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pending_rx_frames() -> u32 {
    unsafe { state().pending_rx_frames() }
}

unsafe fn state() -> &'static mut DriverVirtioNetState {
    unsafe { &mut *addr_of_mut!(STATE) }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
