use bootloader_api::BootInfo;

pub fn init() {
    crate::substrate::ring3::init(crate::frontends::linux_elf::syscall_dispatch_from_asm);
}

pub fn run_demo(boot_info: &'static BootInfo) -> Result<(), &'static str> {
    crate::frontends::linux_elf::run_demo(boot_info)
}
