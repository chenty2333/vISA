#![no_std]

use core::panic::PanicInfo;

use vmos_abi::{FD_STDOUT, MSG_WASM_APP, PackedStep};

#[unsafe(no_mangle)]
pub extern "C" fn run() -> u64 {
    PackedStep::console_write(FD_STDOUT, MSG_WASM_APP).raw()
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
