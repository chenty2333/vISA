#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;
use core::slice;

use vmos_abi::{ERR_EINVAL, ERR_ENOENT, ERR_ENOTDIR, NodeKind};

const REQUEST_CAPACITY: usize = 256;
const RESPONSE_CAPACITY: usize = 4096;

static DEV_DIR: &[u8] = b"null\nzero\npulse\n";
static PULSE_BYTES: &[u8] = b"pulse\n";

static mut REQUEST: [u8; REQUEST_CAPACITY] = [0; REQUEST_CAPACITY];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut NODE_KIND: u32 = 0;

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
pub extern "C" fn node_kind() -> u32 {
    unsafe { NODE_KIND }
}

#[unsafe(no_mangle)]
pub extern "C" fn lookup(path_len: u32, inject_fault: u32) -> i32 {
    if inject_fault != 0 {
        trap();
    }

    match request_bytes(path_len) {
        Ok(b"/dev") => set_kind(NodeKind::Directory),
        Ok(b"/dev/null") | Ok(b"/dev/zero") | Ok(b"/dev/pulse") => set_kind(NodeKind::CharDevice),
        Ok(_) => -ERR_ENOENT,
        Err(errno) => errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn list_dir(path_len: u32, inject_fault: u32) -> i32 {
    if inject_fault != 0 {
        trap();
    }

    match request_bytes(path_len) {
        Ok(b"/dev") => copy_response(DEV_DIR),
        Ok(b"/dev/null") | Ok(b"/dev/zero") | Ok(b"/dev/pulse") => -ERR_ENOTDIR,
        Ok(_) => -ERR_ENOENT,
        Err(errno) => errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn read_device(path_len: u32, max_len: u32, inject_fault: u32) -> i32 {
    if inject_fault != 0 {
        trap();
    }

    match request_bytes(path_len) {
        Ok(b"/dev/null") => 0,
        Ok(b"/dev/zero") => {
            let count = core::cmp::min(max_len as usize, RESPONSE_CAPACITY);
            unsafe {
                core::ptr::write_bytes(addr_of_mut!(RESPONSE) as *mut u8, 0, count);
            }
            count as i32
        }
        Ok(b"/dev/pulse") => {
            copy_response(&PULSE_BYTES[..core::cmp::min(max_len as usize, PULSE_BYTES.len())])
        }
        Ok(_) => -ERR_ENOENT,
        Err(errno) => errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn write_device(path_len: u32, data_len: u32, inject_fault: u32) -> i32 {
    if inject_fault != 0 {
        trap();
    }

    match request_bytes(path_len) {
        Ok(b"/dev/null") => data_len as i32,
        Ok(b"/dev/zero") | Ok(b"/dev/pulse") => -ERR_EINVAL,
        Ok(_) => -ERR_ENOENT,
        Err(errno) => errno,
    }
}

fn set_kind(kind: NodeKind) -> i32 {
    unsafe {
        NODE_KIND = kind as u32;
    }
    0
}

fn request_bytes(path_len: u32) -> Result<&'static [u8], i32> {
    if path_len as usize > REQUEST_CAPACITY {
        return Err(-ERR_EINVAL);
    }

    let ptr = core::ptr::addr_of!(REQUEST) as *const u8;
    Ok(unsafe { slice::from_raw_parts(ptr, path_len as usize) })
}

fn copy_response(bytes: &[u8]) -> i32 {
    if bytes.len() > RESPONSE_CAPACITY {
        return -ERR_EINVAL;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            addr_of_mut!(RESPONSE) as *mut u8,
            bytes.len(),
        );
    }
    bytes.len() as i32
}

#[inline(always)]
fn trap() -> ! {
    #[cfg(target_arch = "wasm32")]
    {
        core::arch::wasm32::unreachable()
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        panic!("devfs_service trap")
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
