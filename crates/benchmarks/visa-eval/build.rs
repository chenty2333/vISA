use std::{env, fs, path::PathBuf, process::Command};

use sha2::{Digest as _, Sha256};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let workspace = manifest.join("../../..").canonicalize().expect("workspace root");
    let git_dir = workspace.join(".git");
    let lock = workspace.join("Cargo.lock");

    println!("cargo:rerun-if-changed={}", manifest.join("src").display());
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    println!("cargo:rerun-if-changed={}", git_dir.join("index").display());
    println!("cargo:rerun-if-changed={}", lock.display());

    let commit = git(&workspace, &["rev-parse", "HEAD"]);
    let dirty = !git(&workspace, &["status", "--porcelain", "--untracked-files=normal"]).is_empty();
    let rustc =
        command(PathBuf::from(env::var_os("RUSTC").expect("RUSTC")), &["-vV"]).replace('\n', " | ");
    let target = env::var("TARGET").expect("TARGET");
    let profile = env::var("PROFILE").expect("PROFILE");
    let opt_level = env::var("OPT_LEVEL").expect("OPT_LEVEL");
    let lock_sha256 =
        format!("{:x}", Sha256::digest(fs::read(&lock).expect("read workspace Cargo.lock")));

    println!("cargo:rustc-env=VISA_EVAL_BUILD_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=VISA_EVAL_BUILD_GIT_DIRTY={dirty}");
    println!("cargo:rustc-env=VISA_EVAL_BUILD_RUSTC_VERSION={rustc}");
    println!("cargo:rustc-env=VISA_EVAL_BUILD_TARGET={target}");
    println!("cargo:rustc-env=VISA_EVAL_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=VISA_EVAL_BUILD_OPT_LEVEL={opt_level}");
    println!("cargo:rustc-env=VISA_EVAL_BUILD_CARGO_LOCK_SHA256={lock_sha256}");
}

fn git(workspace: &std::path::Path, arguments: &[&str]) -> String {
    let mut command = Command::new("git");
    command.arg("-C").arg(workspace).args(arguments);
    run(command)
}

fn command(program: PathBuf, arguments: &[&str]) -> String {
    let mut command = Command::new(program);
    command.args(arguments);
    run(command)
}

fn run(mut command: Command) -> String {
    let output = command.output().expect("run provenance command");
    assert!(output.status.success(), "provenance command failed");
    String::from_utf8(output.stdout).expect("UTF-8 provenance output").trim().to_owned()
}
