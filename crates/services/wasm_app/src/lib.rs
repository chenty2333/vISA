#![no_std]

#[cfg(not(target_arch = "wasm32"))]
extern crate std;

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;

use vmos_abi::PackedStep;

static APP_MESSAGE: &[u8] = b"wasm frontend: hello from wasm_app\n";

#[unsafe(no_mangle)]
pub extern "C" fn run() -> u64 {
    PackedStep::console_write(APP_MESSAGE.as_ptr() as u32, APP_MESSAGE.len() as u32).raw()
}

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
