use std::{env, path::PathBuf};

use bootloader::BootConfig;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("missing OUT_DIR"));
    let kernel = PathBuf::from(
        env::var_os("CARGO_BIN_FILE_KERNEL_kernel")
            .expect("missing artifact dependency path for kernel"),
    );
    let uefi_path = out_dir.join("vmos-uefi.img");
    let boot_config = quiet_boot_config();

    let mut uefi = bootloader::UefiBoot::new(&kernel);
    uefi.set_boot_config(&boot_config)
        .create_disk_image(&uefi_path)
        .expect("failed to build UEFI image");

    println!("cargo:rustc-env=VMOS_UEFI_IMAGE={}", uefi_path.display());
    println!("cargo:rerun-if-changed=../kernel");
    println!("cargo:rerun-if-env-changed=CARGO_BIN_FILE_KERNEL_kernel");
}

fn quiet_boot_config() -> BootConfig {
    let mut config = BootConfig::default();
    config.frame_buffer_logging = false;
    config.serial_logging = false;
    config
}
