#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use vmos_abi::{ERR_EBADF, ERR_EIO, ERR_EOPNOTSUPP};

const REQUEST_CAPACITY: usize = 512;
const RESPONSE_CAPACITY: usize = 512;
const MAX_SOCKETS: usize = 16;

static mut REQUEST: [u8; REQUEST_CAPACITY] = [0; REQUEST_CAPACITY];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut SOCKETS: [LinuxSocket; MAX_SOCKETS] = [LinuxSocket::EMPTY; MAX_SOCKETS];

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct LinuxSocket {
    socket_id: u32,
    domain: u32,
    ty: u32,
    protocol: u32,
    ready_key: u64,
    state: u32,
    active: bool,
}

impl LinuxSocket {
    const EMPTY: Self = Self {
        socket_id: 0,
        domain: 0,
        ty: 0,
        protocol: 0,
        ready_key: 0,
        state: 0,
        active: false,
    };
}

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
pub extern "C" fn register_socket(
    socket_id: u32,
    domain: u32,
    ty: u32,
    protocol: u32,
    ready_key: u64,
) -> i32 {
    unsafe {
        let sockets = addr_of_mut!(SOCKETS) as *mut LinuxSocket;
        for index in 0..MAX_SOCKETS {
            let slot = sockets.add(index);
            if !(*slot).active {
                *slot = LinuxSocket {
                    socket_id,
                    domain,
                    ty,
                    protocol,
                    ready_key,
                    state: 1,
                    active: true,
                };
                return 0;
            }
        }
    }
    -ERR_EIO
}

#[unsafe(no_mangle)]
pub extern "C" fn close_socket(socket_id: u32) -> i32 {
    with_socket_mut(socket_id, |socket| {
        *socket = LinuxSocket::EMPTY;
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn bind_socket(socket_id: u32, _addr_len: u32) -> i32 {
    with_socket_mut(socket_id, |socket| {
        socket.state = 2;
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn connect_socket(socket_id: u32, _addr_len: u32) -> i32 {
    with_socket_mut(socket_id, |socket| {
        socket.state = 3;
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn listen_socket(socket_id: u32, _backlog: u32) -> i32 {
    with_socket_mut(socket_id, |socket| {
        socket.state = 4;
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn accept_socket(_socket_id: u32) -> i32 {
    -ERR_EOPNOTSUPP
}

#[unsafe(no_mangle)]
pub extern "C" fn send_socket(socket_id: u32, len: u32) -> i32 {
    with_socket(socket_id, |_| len as i32)
}

#[unsafe(no_mangle)]
pub extern "C" fn recv_socket(socket_id: u32, len: u32) -> i32 {
    with_socket(socket_id, |_| len as i32)
}

#[unsafe(no_mangle)]
pub extern "C" fn setsockopt(_socket_id: u32, _level: u32, _optname: u32, _optlen: u32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn getsockopt(_socket_id: u32, _level: u32, _optname: u32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn fcntl(_fd: u32, _cmd: u32, _arg: u64) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn socket_count() -> u32 {
    let mut count = 0;
    unsafe {
        let sockets = addr_of_mut!(SOCKETS) as *mut LinuxSocket;
        for index in 0..MAX_SOCKETS {
            if (*sockets.add(index)).active {
                count += 1;
            }
        }
    }
    count
}

fn with_socket(socket_id: u32, f: impl FnOnce(LinuxSocket) -> i32) -> i32 {
    unsafe {
        let sockets = addr_of_mut!(SOCKETS) as *mut LinuxSocket;
        for index in 0..MAX_SOCKETS {
            let socket = sockets.add(index);
            if (*socket).active && (*socket).socket_id == socket_id {
                return f(*socket);
            }
        }
    }
    -ERR_EBADF
}

fn with_socket_mut(socket_id: u32, f: impl FnOnce(&mut LinuxSocket) -> i32) -> i32 {
    unsafe {
        let sockets = addr_of_mut!(SOCKETS) as *mut LinuxSocket;
        for index in 0..MAX_SOCKETS {
            let socket = sockets.add(index);
            if (*socket).active && (*socket).socket_id == socket_id {
                return f(&mut *socket);
            }
        }
    }
    -ERR_EBADF
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
