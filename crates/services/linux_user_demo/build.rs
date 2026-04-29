use std::{env, path::PathBuf};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("missing manifest dir"));
    let linker_script = manifest_dir.join("linker.ld");

    println!("cargo:rerun-if-changed={}", linker_script.display());
    println!("cargo:rustc-link-arg-bin=linux_user_demo=-T{}", linker_script.display());
    println!("cargo:rustc-link-arg-bin=linux_user_demo=-static");
    println!("cargo:rustc-link-arg-bin=linux_user_demo=-no-pie");
}
