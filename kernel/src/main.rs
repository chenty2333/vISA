#![cfg_attr(target_os = "none", feature(alloc_error_handler))]
#![feature(abi_x86_interrupt)]
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![cfg_attr(not(target_os = "none"), allow(dead_code, unused_imports))]

extern crate alloc;

mod debugcon;
mod frontends;
mod interrupts;
mod log;
mod qemu;
mod serial;
mod substrate;
mod supervisor;
mod user_mode;

#[cfg(target_os = "none")]
use bootloader_api::config::{BootloaderConfig, Mapping};
#[cfg(target_os = "none")]
use bootloader_api::{BootInfo, entry_point};
#[cfg(target_os = "none")]
use core::alloc::Layout;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;
#[cfg(target_os = "none")]
use linked_list_allocator::LockedHeap;
#[cfg(target_os = "none")]
use x86_64::instructions::hlt;

#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(target_os = "none")]
const HEAP_SIZE: usize = 32 * 1024 * 1024;
#[cfg(target_os = "none")]
static mut HEAP_SPACE: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[cfg(target_os = "none")]
const BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

#[cfg(target_os = "none")]
entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

#[cfg(target_os = "none")]
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    crate::ktrace!("kernel_main entered");
    serial::init();
    crate::ktrace!("serial ready");
    init_heap();
    crate::ktrace!("heap ready");
    user_mode::init();
    crate::ktrace!("user mode ready");
    interrupts::init();
    crate::ktrace!("interrupts ready");

    crate::kinfo!("booting substrate");
    crate::kinfo!("starting linear prototype");

    if let Err(err) = supervisor::run() {
        crate::kerror!("demo failed: {}", err);
        serial_println!("vmos: demo failed: {}", err);
        qemu::exit_failed();
    }

    if let Err(err) = user_mode::run_demo(boot_info) {
        crate::kerror!("user mode demo failed: {}", err);
        serial_println!("vmos: demo failed: {}", err);
        qemu::exit_failed();
    }

    crate::ktrace!("entering halt loop");
    hlt_loop();
}

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
fn init_heap() {
    unsafe {
        ALLOCATOR
            .lock()
            .init(core::ptr::addr_of_mut!(HEAP_SPACE) as *mut u8, HEAP_SIZE);
    }
}

#[cfg(target_os = "none")]
fn hlt_loop() -> ! {
    loop {
        hlt();
    }
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    crate::kerror!("panic: {}", info);
    serial_println!("panic: {}", info);
    qemu::exit_failed();
    hlt_loop()
}

#[cfg(target_os = "none")]
#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    crate::kerror!(
        "alloc error: size={} align={}",
        layout.size(),
        layout.align()
    );
    serial_println!(
        "alloc error: size={} align={}",
        layout.size(),
        layout.align()
    );
    qemu::exit_failed();
    hlt_loop()
}
