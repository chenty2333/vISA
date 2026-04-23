#![feature(alloc_error_handler)]
#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]

extern crate alloc;

mod debugcon;
mod demo;
mod interrupts;
mod log;
mod qemu;
mod serial;
mod user_mode;

use core::alloc::Layout;
use core::panic::PanicInfo;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{BootInfo, entry_point};
use linked_list_allocator::LockedHeap;
use x86_64::instructions::hlt;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

const HEAP_SIZE: usize = 8 * 1024 * 1024;
static mut HEAP_SPACE: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

const BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

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

    if let Err(err) = demo::run() {
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

fn init_heap() {
    unsafe {
        ALLOCATOR
            .lock()
            .init(core::ptr::addr_of_mut!(HEAP_SPACE) as *mut u8, HEAP_SIZE);
    }
}

fn hlt_loop() -> ! {
    loop {
        hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    crate::kerror!("panic: {}", info);
    serial_println!("panic: {}", info);
    qemu::exit_failed();
    hlt_loop()
}

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
