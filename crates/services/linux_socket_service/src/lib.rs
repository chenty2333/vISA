#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use service_core::{linux_socket::LinuxSocketState, net_contract::NETWORK_CONTRACT_ABI_VERSION};

const REQUEST_CAPACITY: usize = 512;
const RESPONSE_CAPACITY: usize = 512;

static mut REQUEST: [u8; REQUEST_CAPACITY] = [0; REQUEST_CAPACITY];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut STATE: LinuxSocketState = LinuxSocketState::new();

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
pub extern "C" fn register_socket(
    socket_id: u32,
    domain: u32,
    ty: u32,
    protocol: u32,
    ready_key: u64,
) -> i32 {
    result_unit(unsafe { state().register_socket(socket_id, domain, ty, protocol, ready_key) })
}

#[unsafe(no_mangle)]
pub extern "C" fn register_connected_socket(
    socket_id: u32,
    domain: u32,
    ty: u32,
    protocol: u32,
    ready_key: u64,
) -> i32 {
    result_unit(unsafe {
        state().register_connected_socket(socket_id, domain, ty, protocol, ready_key)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn close_socket(socket_id: u32) -> i32 {
    result_unit(unsafe { state().close_socket(socket_id) })
}

#[unsafe(no_mangle)]
pub extern "C" fn bind_socket(
    socket_id: u32,
    addr_len: u32,
    family: u32,
    ipv4: u32,
    port: u32,
) -> i32 {
    result_unit(unsafe { state().bind_socket(socket_id, addr_len, family, ipv4, port) })
}

#[unsafe(no_mangle)]
pub extern "C" fn connect_socket(
    socket_id: u32,
    addr_len: u32,
    family: u32,
    ipv4: u32,
    port: u32,
) -> i32 {
    result_unit(unsafe { state().connect_socket(socket_id, addr_len, family, ipv4, port) })
}

#[unsafe(no_mangle)]
pub extern "C" fn listen_socket(socket_id: u32, backlog: u32) -> i32 {
    result_unit(unsafe { state().listen_socket(socket_id, backlog) })
}

#[unsafe(no_mangle)]
pub extern "C" fn accept_socket(socket_id: u32, accepted_socket_id: u32, ready_key: u64) -> i32 {
    result_i32(unsafe { state().accept_socket(socket_id, accepted_socket_id, ready_key) })
}

#[unsafe(no_mangle)]
pub extern "C" fn pending_accept_count(socket_id: u32) -> i32 {
    result_i32(unsafe { state().pending_accept_count(socket_id) })
}

#[unsafe(no_mangle)]
pub extern "C" fn accept_ready_key_for_client(socket_id: u32) -> u64 {
    unsafe { state().accept_ready_key_for_client(socket_id).ok().flatten().unwrap_or(0) }
}

#[unsafe(no_mangle)]
pub extern "C" fn send_socket(socket_id: u32, len: u32) -> i32 {
    result_i32(unsafe { state().send_socket(socket_id, len) })
}

#[unsafe(no_mangle)]
pub extern "C" fn recv_socket(socket_id: u32, len: u32) -> i32 {
    result_i32(unsafe { state().recv_socket(socket_id, len) })
}

#[unsafe(no_mangle)]
pub extern "C" fn setsockopt(socket_id: u32, level: u32, optname: u32, optlen: u32) -> i32 {
    result_unit(unsafe { state().setsockopt(socket_id, level, optname, optlen) })
}

#[unsafe(no_mangle)]
pub extern "C" fn getsockopt(socket_id: u32, level: u32, optname: u32) -> i32 {
    result_i32(unsafe { state().getsockopt(socket_id, level, optname) })
}

#[unsafe(no_mangle)]
pub extern "C" fn fcntl(fd: u32, cmd: u32, arg: u64) -> i32 {
    result_i32(unsafe { state().fcntl(fd, cmd, arg) })
}

#[unsafe(no_mangle)]
pub extern "C" fn socket_count() -> u32 {
    unsafe { state().socket_count() }
}

unsafe fn state() -> &'static mut LinuxSocketState {
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
