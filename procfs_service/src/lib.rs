#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;
use core::slice;

use vmos_abi::{ERR_EINVAL, ERR_EIO, ERR_EISDIR, ERR_ENOENT, ERR_ENOTDIR, NodeKind};

const REQUEST_CAPACITY: usize = 256;
const RESPONSE_CAPACITY: usize = 4096;

static PROC_DIR: &[u8] = b"self\nmeminfo\n";
static PROC_SELF_DIR: &[u8] = b"status\ncwd\n";
static PROC_STATUS: &[u8] = b"Name:\tvmos-demo\nState:\tR (running)\nSupervisor:\tPrototype2\n";
static PROC_MEMINFO: &[u8] = b"MemTotal:\t8192 kB\nMemFree:\t4096 kB\n";
static PROC_CWD: &[u8] = b"/sandbox";

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
        Ok(b"/proc") | Ok(b"/proc/self") => set_kind(NodeKind::Directory),
        Ok(b"/proc/self/status") | Ok(b"/proc/meminfo") => set_kind(NodeKind::File),
        Ok(b"/proc/self/cwd") => set_kind(NodeKind::Symlink),
        Ok(_) => -ERR_ENOENT,
        Err(errno) => errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn read_file(path_len: u32, inject_fault: u32) -> i32 {
    if inject_fault != 0 {
        trap();
    }

    match request_bytes(path_len) {
        Ok(b"/proc/self/status") => copy_response(PROC_STATUS),
        Ok(b"/proc/meminfo") => copy_response(PROC_MEMINFO),
        Ok(b"/proc") | Ok(b"/proc/self") => -ERR_EISDIR,
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
        Ok(b"/proc") => copy_response(PROC_DIR),
        Ok(b"/proc/self") => copy_response(PROC_SELF_DIR),
        Ok(b"/proc/self/status") | Ok(b"/proc/self/cwd") | Ok(b"/proc/meminfo") => -ERR_ENOTDIR,
        Ok(_) => -ERR_ENOENT,
        Err(errno) => errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn read_link(path_len: u32, inject_fault: u32) -> i32 {
    if inject_fault != 0 {
        trap();
    }

    match request_bytes(path_len) {
        Ok(b"/proc/self/cwd") => copy_response(PROC_CWD),
        Ok(b"/proc") | Ok(b"/proc/self") | Ok(b"/proc/self/status") | Ok(b"/proc/meminfo") => {
            -ERR_EINVAL
        }
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
        return -ERR_EIO;
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
        panic!("procfs_service trap")
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
