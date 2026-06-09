# vISA Clean Baseline Result

## Goal
Establish a clean vISA baseline after the rename, Docker, toolchain, and task-state work.

## Result
Completed. The baseline now has coherent vISA naming, Docker development files and documentation, tracked docs/task state, and current validation evidence. `.gitignore` keeps build/local agent state out of Git while allowing project docs and task files to be tracked.

## Evidence
Verified:

- legacy-name literal scan is clean outside git metadata
- legacy filename scan is clean outside git metadata and `target`
- `git diff --check`
- `docker compose config --quiet`
- `cargo metadata --no-deps --format-version 1`
- `cargo fmt --all --check`
- `cargo test -p visa-conformance`
- `cargo check -p visa_runtime -p visa_wasmtime -p visa-bench`
- `cargo check-wasm`
- `cargo check -p kernel --target x86_64-unknown-none`

Earlier container verification also passed for the dev image build, workspace bind mount, Rust components/targets, QEMU/OVMF, `cargo metadata`, `cargo fmt`, `cargo check-wasm`, runtime/wasmtime/bench checks, conformance tests, and kernel target check.

## Remaining Risk
The kernel target check still emits existing dead-code warnings. The current host shell may need a new login session before ordinary Docker commands see the refreshed `docker` group membership, although `sg docker` already verifies daemon access.
