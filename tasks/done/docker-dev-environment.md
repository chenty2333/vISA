# Docker Development Environment Result

## Goal
Configure a Docker-based development environment for the current vISA project.

## Result
Completed. Added project-local Docker development files:

- `Dockerfile`
- `compose.yaml`
- `.dockerignore`
- `.devcontainer/devcontainer.json`
- `docs/DOCKER.md`

The image installs the nightly Rust toolchain from `rust-toolchain.toml`, including `rust-src`, `rustfmt`, `clippy`, `llvm-tools-preview`, `wasm32-unknown-unknown`, and `x86_64-unknown-none`. It also installs QEMU/OVMF for the runner and C/autotools packages used by LTP helper scripts. Compose keeps Cargo registry/git, target, and LTP cache data on named volumes without hiding the image-installed Rust binaries.

## Evidence
Verified:

- `docker --version`
- `docker compose version`
- `docker compose config`
- `python3 -m json.tool .devcontainer/devcontainer.json`
- `git diff --check`
- legacy name scan remained clean
- `cargo metadata --no-deps --format-version 1`
- `cargo fmt --all --check`
- `cargo test -p visa-conformance`
- `cargo check -p visa_runtime -p visa_wasmtime -p visa-bench`
- `sudo docker compose build dev`
- container smoke check: workspace bind readable, Rust/Cargo/rustup targets visible, QEMU and OVMF present
- `sg docker -c 'docker info'`
- container `cargo metadata --no-deps --format-version 1`
- container `cargo fmt --all --check`
- container `cargo check-wasm`
- container `cargo check -p visa_runtime -p visa_wasmtime -p visa-bench`
- container `cargo test -p visa-conformance`
- container `cargo check -p kernel --target x86_64-unknown-none`

## Remaining Risk
The current shell may still need a new login session before ordinary `docker` commands work without `sudo`, even though host group membership is configured and `sg docker` verifies daemon access.
