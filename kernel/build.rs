use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use supervisor_catalog::{SUPERVISOR_WASM_MODULES, USER_BINARIES};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("missing manifest dir"));
    let workspace_root = manifest_dir
        .parent()
        .expect("kernel crate should live in workspace root");
    let target_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("missing OUT_DIR")).join("wasm-target");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

    for module in SUPERVISOR_WASM_MODULES {
        build_module(&cargo, workspace_root, &target_dir, module.package);
        expose_artifact_path(workspace_root, &target_dir, module.package);
    }

    let user_target_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("missing OUT_DIR")).join("user-target");
    for binary in USER_BINARIES {
        build_user_binary(&cargo, workspace_root, &user_target_dir, binary.package);
        expose_user_binary_path(workspace_root, &user_target_dir, binary.package);
    }
}

fn build_module(cargo: &str, workspace_root: &Path, target_dir: &Path, module: &str) {
    let status = Command::new(cargo)
        .current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", target_dir)
        .args(["build", "-p", module, "--target", "wasm32-unknown-unknown"])
        .status()
        .unwrap_or_else(|err| panic!("failed to spawn cargo for {module}: {err}"));

    if !status.success() {
        panic!("building {module} for wasm32-unknown-unknown failed");
    }
}

fn expose_artifact_path(workspace_root: &Path, target_dir: &Path, module: &str) {
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join(module).display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("abi").display()
    );

    let artifact = target_dir
        .join("wasm32-unknown-unknown")
        .join("debug")
        .join(format!("{module}.wasm"));
    let env_key = format!("VMOS_{}_WASM", module.to_ascii_uppercase());
    println!("cargo:rustc-env={}={}", env_key, artifact.display());
}

fn build_user_binary(cargo: &str, workspace_root: &Path, target_dir: &Path, binary: &str) {
    let status = Command::new(cargo)
        .current_dir(workspace_root)
        .env("CARGO_TARGET_DIR", target_dir)
        .args(["build", "-p", binary, "--target", "x86_64-unknown-none"])
        .status()
        .unwrap_or_else(|err| panic!("failed to spawn cargo for {binary}: {err}"));

    if !status.success() {
        panic!("building {binary} for x86_64-unknown-none failed");
    }
}

fn expose_user_binary_path(workspace_root: &Path, target_dir: &Path, binary: &str) {
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join(binary).display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("abi").display()
    );

    let artifact = target_dir
        .join("x86_64-unknown-none")
        .join("debug")
        .join(binary);
    let env_key = format!("VMOS_{}_ELF", binary.to_ascii_uppercase());
    println!("cargo:rustc-env={}={}", env_key, artifact.display());
}
