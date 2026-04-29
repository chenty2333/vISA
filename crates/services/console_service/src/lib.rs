#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;

use vmos_abi::ERR_EINVAL;

const BUFFER_CAPACITY: usize = 4096;
static mut BUFFER: [u8; BUFFER_CAPACITY] = [0; BUFFER_CAPACITY];

#[unsafe(no_mangle)]
pub extern "C" fn commit_write(len: u32, inject_fault: u32) -> i32 {
    if inject_fault != 0 {
        trap();
    }

    if len as usize > BUFFER_CAPACITY {
        return -ERR_EINVAL;
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn buffer_ptr() -> u32 {
    core::ptr::addr_of_mut!(BUFFER) as *mut u8 as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn buffer_capacity() -> u32 {
    BUFFER_CAPACITY as u32
}

#[inline(always)]
fn trap() -> ! {
    #[cfg(target_arch = "wasm32")]
    {
        core::arch::wasm32::unreachable()
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        panic!("console_service trap")
    }
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
