#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;

use vmos_abi::{EPOLLIN, EPOLLOUT, ERR_EAGAIN, ERR_EBADF, ERR_EIO};

const REQUEST_CAPACITY: usize = 2048;
const RESPONSE_CAPACITY: usize = 2048;
const MAX_SOCKETS: usize = 16;
const QUEUE_CAPACITY: usize = 512;
const READY_KEY_BASE: u64 = 0x6e65_7473_6f63_0000;

static mut REQUEST: [u8; REQUEST_CAPACITY] = [0; REQUEST_CAPACITY];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut SOCKETS: [Socket; MAX_SOCKETS] = [Socket::EMPTY; MAX_SOCKETS];
static mut RX_QUEUES: [[u8; QUEUE_CAPACITY]; MAX_SOCKETS] = [[0; QUEUE_CAPACITY]; MAX_SOCKETS];
static mut TX_QUEUES: [[u8; QUEUE_CAPACITY]; MAX_SOCKETS] = [[0; QUEUE_CAPACITY]; MAX_SOCKETS];
static mut NEXT_SOCKET_ID: u32 = 1;

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Socket {
    id: u32,
    domain: u32,
    ty: u32,
    protocol: u32,
    ready_key: u64,
    state: u32,
    rx_len: usize,
    tx_len: usize,
    active: bool,
}

impl Socket {
    const EMPTY: Self = Self {
        id: 0,
        domain: 0,
        ty: 0,
        protocol: 0,
        ready_key: 0,
        state: 0,
        rx_len: 0,
        tx_len: 0,
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
pub extern "C" fn create_socket(domain: u32, ty: u32, protocol: u32) -> i32 {
    unsafe {
        let socket_id = NEXT_SOCKET_ID;
        NEXT_SOCKET_ID = NEXT_SOCKET_ID.saturating_add(1);
        let sockets = addr_of_mut!(SOCKETS) as *mut Socket;
        for index in 0..MAX_SOCKETS {
            let slot = sockets.add(index);
            if !(*slot).active {
                *slot = Socket {
                    id: socket_id,
                    domain,
                    ty,
                    protocol,
                    ready_key: READY_KEY_BASE | socket_id as u64,
                    state: 1,
                    rx_len: 0,
                    tx_len: 0,
                    active: true,
                };
                return socket_id as i32;
            }
        }
    }

    -ERR_EIO
}

#[unsafe(no_mangle)]
pub extern "C" fn close_socket(socket_id: u32) -> i32 {
    with_socket_mut(socket_id, |index, socket| unsafe {
        *socket = Socket::EMPTY;
        RX_QUEUES[index] = [0; QUEUE_CAPACITY];
        TX_QUEUES[index] = [0; QUEUE_CAPACITY];
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ready_key(socket_id: u32) -> u64 {
    unsafe {
        let sockets = addr_of_mut!(SOCKETS) as *mut Socket;
        for index in 0..MAX_SOCKETS {
            let socket = sockets.add(index);
            if (*socket).active && (*socket).id == socket_id {
                return (*socket).ready_key;
            }
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn poll_socket(socket_id: u32) -> u32 {
    with_socket(socket_id, |_, socket| {
        let mut events = EPOLLOUT;
        if socket.rx_len > 0 {
            events |= EPOLLIN;
        }
        events as i32
    })
    .max(0) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn send_socket(socket_id: u32, len: u32) -> i32 {
    let len = len as usize;
    if len > REQUEST_CAPACITY || len > QUEUE_CAPACITY {
        return -ERR_EIO;
    }

    with_socket_mut(socket_id, |index, socket| unsafe {
        core::ptr::copy_nonoverlapping(
            addr_of_mut!(REQUEST) as *const u8,
            TX_QUEUES[index].as_mut_ptr(),
            len,
        );
        socket.tx_len = len;
        socket.state = 2;
        len as i32
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn recv_socket(socket_id: u32, count: u32) -> i32 {
    let count = count as usize;
    if count > RESPONSE_CAPACITY {
        return -ERR_EIO;
    }

    with_socket_mut(socket_id, |index, socket| unsafe {
        if socket.rx_len == 0 {
            return -ERR_EAGAIN;
        }

        let len = socket.rx_len.min(count);
        core::ptr::copy_nonoverlapping(
            RX_QUEUES[index].as_ptr(),
            addr_of_mut!(RESPONSE) as *mut u8,
            len,
        );
        socket.rx_len = 0;
        len as i32
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn inject_packet(len: u32) -> i64 {
    let len = (len as usize).min(REQUEST_CAPACITY).min(QUEUE_CAPACITY);

    unsafe {
        let sockets = addr_of_mut!(SOCKETS) as *mut Socket;
        for index in 0..MAX_SOCKETS {
            let socket = sockets.add(index);
            if !(*socket).active {
                continue;
            }
            core::ptr::copy_nonoverlapping(
                addr_of_mut!(REQUEST) as *const u8,
                RX_QUEUES[index].as_mut_ptr(),
                len,
            );
            (*socket).rx_len = len;
            (*socket).state = 3;
            return (*socket).ready_key as i64;
        }
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn socket_count() -> u32 {
    let mut count = 0u32;
    unsafe {
        let sockets = addr_of_mut!(SOCKETS) as *mut Socket;
        for index in 0..MAX_SOCKETS {
            if (*sockets.add(index)).active {
                count += 1;
            }
        }
    }
    count
}

#[unsafe(no_mangle)]
pub extern "C" fn queued_rx_bytes() -> u32 {
    let mut bytes = 0u32;
    unsafe {
        let sockets = addr_of_mut!(SOCKETS) as *mut Socket;
        for index in 0..MAX_SOCKETS {
            let socket = sockets.add(index);
            if (*socket).active {
                bytes = bytes.saturating_add((*socket).rx_len as u32);
            }
        }
    }
    bytes
}

fn with_socket(socket_id: u32, f: impl FnOnce(usize, Socket) -> i32) -> i32 {
    unsafe {
        let sockets = addr_of_mut!(SOCKETS) as *mut Socket;
        for index in 0..MAX_SOCKETS {
            let socket = sockets.add(index);
            if (*socket).active && (*socket).id == socket_id {
                return f(index, *socket);
            }
        }
    }
    -ERR_EBADF
}

fn with_socket_mut(socket_id: u32, f: impl FnOnce(usize, &mut Socket) -> i32) -> i32 {
    unsafe {
        let sockets = addr_of_mut!(SOCKETS) as *mut Socket;
        for index in 0..MAX_SOCKETS {
            let socket = sockets.add(index);
            if (*socket).active && (*socket).id == socket_id {
                return f(index, &mut *socket);
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
