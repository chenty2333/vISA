#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use service_core::{
    net::{NetCoreState, QUEUE_CAPACITY},
    net_contract::{
        NETWORK_CONTRACT_ABI_VERSION, VIRTIO_NET0_MTU, VIRTIO_NET0_RX_QUEUE_DEPTH,
        VIRTIO_NET0_TX_QUEUE_DEPTH,
    },
    packet::PACKET_FRAME_CAPACITY,
};
use vmos_abi::ERR_EIO;

const REQUEST_CAPACITY: usize = 2048;
const RESPONSE_CAPACITY: usize = 2048;

static mut REQUEST: [u8; REQUEST_CAPACITY] = [0; REQUEST_CAPACITY];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut STATE: NetCoreState = NetCoreState::new();

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
pub extern "C" fn create_socket(domain: u32, ty: u32, protocol: u32) -> i32 {
    result_i32(unsafe { state().create_socket(domain, ty, protocol) })
}

#[unsafe(no_mangle)]
pub extern "C" fn close_socket(socket_id: u32) -> i32 {
    result_unit(unsafe { state().close_socket(socket_id) })
}

#[unsafe(no_mangle)]
pub extern "C" fn ready_key(socket_id: u32) -> u64 {
    unsafe { state().ready_key(socket_id).unwrap_or(0) }
}

#[unsafe(no_mangle)]
pub extern "C" fn poll_socket(socket_id: u32) -> u32 {
    unsafe { state().poll_socket(socket_id).unwrap_or(0) }
}

#[unsafe(no_mangle)]
pub extern "C" fn send_socket(socket_id: u32, len: u32) -> i32 {
    let len = len as usize;
    if len > REQUEST_CAPACITY || len > QUEUE_CAPACITY {
        return -ERR_EIO;
    }
    let bytes = unsafe { core::slice::from_raw_parts(addr_of_mut!(REQUEST) as *const u8, len) };
    result_i32(unsafe { state().send_socket(socket_id, bytes) })
}

#[unsafe(no_mangle)]
pub extern "C" fn take_tx_frame(socket_id: u32) -> i32 {
    let out = unsafe {
        core::slice::from_raw_parts_mut(addr_of_mut!(RESPONSE) as *mut u8, PACKET_FRAME_CAPACITY)
    };
    match unsafe { state().take_tx_frame(socket_id, out) } {
        Ok(len) => len as i32,
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn recv_socket(socket_id: u32, count: u32) -> i32 {
    let count = count as usize;
    if count > RESPONSE_CAPACITY {
        return -ERR_EIO;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(addr_of_mut!(RESPONSE) as *mut u8, count) };
    result_i32(unsafe { state().recv_socket(socket_id, count as u32, out) })
}

#[unsafe(no_mangle)]
pub extern "C" fn peek_socket(socket_id: u32, count: u32) -> i32 {
    let count = count as usize;
    if count > RESPONSE_CAPACITY {
        return -ERR_EIO;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(addr_of_mut!(RESPONSE) as *mut u8, count) };
    result_i32(unsafe { state().peek_socket(socket_id, count as u32, out) })
}

#[unsafe(no_mangle)]
pub extern "C" fn deliver_packet_frame(len: u32) -> i64 {
    let len = (len as usize).min(REQUEST_CAPACITY).min(PACKET_FRAME_CAPACITY);
    let bytes = unsafe { core::slice::from_raw_parts(addr_of_mut!(REQUEST) as *const u8, len) };
    match unsafe { state().deliver_packet_frame(bytes) } {
        Ok(Some(ready_key)) => ready_key as i64,
        Ok(None) => 0,
        Err(errno) => -(errno as i64),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn socket_count() -> u32 {
    unsafe { state().socket_count() }
}

#[unsafe(no_mangle)]
pub extern "C" fn queued_rx_bytes() -> u32 {
    unsafe { state().queued_rx_bytes() }
}

unsafe fn state() -> &'static mut NetCoreState {
    unsafe { &mut *addr_of_mut!(STATE) }
}

fn result_i32(result: Result<u32, i32>) -> i32 {
    match result {
        Ok(value) => value as i32,
        Err(errno) => -errno,
    }
}

fn result_unit(result: Result<(), i32>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(errno) => -errno,
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
