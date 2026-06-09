#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;
use core::{ptr::addr_of_mut, slice};

use visa_abi::{ERR_EINVAL, ERR_EIO, ERR_EISDIR, ERR_ENOENT, ERR_ENOTDIR, NodeKind, ServiceRoute};

const REQUEST_CAPACITY: usize = 256;
const RESPONSE_CAPACITY: usize = 4096;

static HELLO_TXT: &[u8] = b"sandbox file: supervisor world says hello\n";
static ROOT_DIR: &[u8] = b"sandbox\nproc\ndev\n";
static SANDBOX_DIR: &[u8] = b"hello.txt\nreadme.link\n";
static README_LINK: &[u8] = b"/sandbox/hello.txt";

static mut REQUEST: [u8; REQUEST_CAPACITY] = [0; REQUEST_CAPACITY];
static mut RESPONSE: [u8; RESPONSE_CAPACITY] = [0; RESPONSE_CAPACITY];
static mut ROUTE_KIND: u32 = 0;
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
pub extern "C" fn route_kind() -> u32 {
    unsafe { ROUTE_KIND }
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
        Ok(b"/") => set_lookup(ServiceRoute::Vfs, NodeKind::Directory),
        Ok(b"/sandbox") => set_lookup(ServiceRoute::Vfs, NodeKind::Directory),
        Ok(b"/sandbox/hello.txt") => set_lookup(ServiceRoute::Vfs, NodeKind::File),
        Ok(b"/sandbox/readme.link") => set_lookup(ServiceRoute::Vfs, NodeKind::Symlink),
        Ok(b"/proc")
        | Ok(b"/proc/self")
        | Ok(b"/proc/self/status")
        | Ok(b"/proc/self/cwd")
        | Ok(b"/proc/meminfo") => set_lookup(ServiceRoute::Procfs, infer_procfs_kind(path_len)),
        Ok(b"/dev") | Ok(b"/dev/null") | Ok(b"/dev/zero") | Ok(b"/dev/pulse") => {
            set_lookup(ServiceRoute::Devfs, infer_devfs_kind(path_len))
        }
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
        Ok(b"/sandbox/hello.txt") => copy_response(HELLO_TXT),
        Ok(b"/") | Ok(b"/sandbox") => -ERR_EISDIR,
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
        Ok(b"/") => copy_response(ROOT_DIR),
        Ok(b"/sandbox") => copy_response(SANDBOX_DIR),
        Ok(b"/sandbox/hello.txt") | Ok(b"/sandbox/readme.link") => -ERR_ENOTDIR,
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
        Ok(b"/sandbox/readme.link") => copy_response(README_LINK),
        Ok(b"/") | Ok(b"/sandbox") | Ok(b"/sandbox/hello.txt") => -ERR_EINVAL,
        Ok(_) => -ERR_ENOENT,
        Err(errno) => errno,
    }
}

fn infer_procfs_kind(path_len: u32) -> NodeKind {
    match request_bytes(path_len) {
        Ok(b"/proc") | Ok(b"/proc/self") => NodeKind::Directory,
        Ok(b"/proc/self/cwd") => NodeKind::Symlink,
        _ => NodeKind::File,
    }
}

fn infer_devfs_kind(path_len: u32) -> NodeKind {
    match request_bytes(path_len) {
        Ok(b"/dev") => NodeKind::Directory,
        _ => NodeKind::CharDevice,
    }
}

fn set_lookup(route: ServiceRoute, node: NodeKind) -> i32 {
    unsafe {
        ROUTE_KIND = route as u32;
        NODE_KIND = node as u32;
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
        panic!("vfs_service trap")
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
