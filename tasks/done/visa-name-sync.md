# vISA Name Synchronization Result

## Goal
Synchronize remaining legacy project naming to the current project name, vISA.

## Result
Completed. User-facing project text, package/binary/script names, generated evidence identifiers, env vars, helper names, runtime crate names, Wasm hostcall module labels, and legacy vision file paths now use vISA/visa naming where the old name was only a project label.

## Scope Notes
No compatibility wrapper was kept for legacy script or runtime crate names because the accepted scope was full synchronization to vISA. `osctl` was left unchanged because `achieve/00_INDEX.md` defines it as the stable read-only control plane, not a project name.

## Evidence
Legacy literal and file-name scans for the former project names are clean outside git metadata. The scan included old project labels, old runtime crate names, old runtime package path forms, the old Wasm hostcall module label, and the old semantic vision slug.

Verified:

- `cargo metadata --no-deps --format-version 1`
- `cargo fmt --all --check`
- `git diff --check`
- `cargo check -p visa_runtime`
- `cargo check -p visa_wasmtime`
- `cargo check -p visa-bench`
- `cargo check -p visa-conformance`
- `cargo test -p visa-conformance`
- `cargo test -p visa_runtime`
- `cargo test -p visa_wasmtime`
- `cargo check -p target_executor`
- `cargo check-wasm`
- `cargo check -p kernel --target x86_64-unknown-none`

## Remaining Risk
`git ls-files` still reports legacy paths until the rename/delete/add changes are staged or committed. The working tree itself no longer contains those legacy paths.
