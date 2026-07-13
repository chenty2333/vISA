# vISA Development Guide

Status: current repository workflow.

Last reviewed: 2026-07-13.

This document describes commands that exist in the repository today. It is not
a claim that the current build and test surface validates the target system in
full. Read the project [vision](VISION.md) and [architecture](ARCHITECTURE.md)
before changing scope, contracts, dependency direction, or evidence claims.

## Supported environment

The supported development environment and current CI parity boundary is the
`dev` service in `compose.yaml`. Its image contains:

- the `nightly-2026-06-07` Rust toolchain declared by both `Dockerfile` and
  `rust-toolchain.toml`;
- `rust-src`, `rustfmt`, `clippy`, and `llvm-tools-preview`;
- the `wasm32-unknown-unknown` and `x86_64-unknown-none` targets;
- Node 24.15.0 with V8 13.6.233.17-node.48, installed from the official
  architecture-specific archive after SHA-256 verification;
- on linux/amd64 image builds, the official Go 1.26.5 archive plus the
  source-lock-bound Wacogo module zip and offline module-cache seed used only by
  the x86-64 Linux Strict Stage 2 gate;
- QEMU and OVMF for the current x86_64 kernel runner; and
- the C, autotools, and Linux packages used by the LTP helpers.

The Node x64 and arm64 archive digests are copied from the official
[`v24.15.0` checksum list](https://nodejs.org/dist/v24.15.0/SHASUMS256.txt).
The Rust toolchain is date-pinned because later nightly compiler changes can
break the bootloader dependency independently of vISA source. The
`debian:stable-slim` base image is not digest-pinned, so this environment still
provides local/CI parity rather than a bit-reproducible release toolchain.
Release claims require all inputs pinned.

Host-native Cargo commands are useful for short edit cycles, but the host is
not the CI parity boundary. A host workflow must independently provide
the declared Rust toolchain, targets, QEMU/OVMF when required, and any external
workload dependencies.

On SELinux hosts, Compose disables container labeling so the workspace remains
accessible. After changing Docker group membership, start a new login session.

## Build and enter the development image

For the usual UID and GID of 1000:

```sh
docker compose build dev
docker compose run --rm dev
```

On a host with different user IDs, build the image with matching values so
bind-mounted outputs remain owned by the developer:

```sh
VISA_DOCKER_UID="$(id -u)" VISA_DOCKER_GID="$(id -g)" \
  docker compose build dev
```

The repository is mounted at `/workspace`. Cargo and LTP caches use Docker
volumes by default.

## Repository gates

The repository exposes two cumulative repository tiers and four standalone
system tiers. Run the ordinary edit-loop gate with:

```sh
scripts/run-docker-ci-gate.sh fast
```

Run the pull-request gate with:

```sh
scripts/run-docker-ci-gate.sh full
```

Run the Stage 1 reference system gate with:

```sh
scripts/run-docker-ci-gate.sh system
```

Run the Stage 2b JcoNode reference cell with:

```sh
scripts/run-docker-ci-gate.sh system-jco-node
```

Run the complete four-direction Stage 2c matrix with:

```sh
scripts/run-docker-ci-gate.sh system-stage2
```

Run the locked Strict Stage 2 Wasmtime/Wacogo matrix with:

```sh
scripts/run-docker-ci-gate.sh system-stage2-strict
```

With no tier argument the wrapper runs `full`. It validates the Compose
configuration, builds the image, then invokes the same `scripts/ci-gate.sh`
implementation used by CI. `--skip-build` reuses an existing image.
`--ci-cache` overlays `compose.ci.yaml` and uses the bind-mounted `.ci-cache/`
layout used by GitHub Actions.

The strict Docker wrapper retains its gate root, locked Wacogo sidecar and build
receipt, Docker log, and exit receipt together below `.ci-cache/strict-stage2/`
by default. `--artifact-parent DIR` selects another parent. For a direct Host
run, provide the prefetched inputs named by `VISA_WACOGO_GO_ARCHIVE`,
`VISA_WACOGO_GO`, `VISA_WACOGO_MODULE_ZIP`, and
`VISA_WACOGO_GOMODCACHE`, then run:

```sh
scripts/ci-gate.sh system-stage2-strict
```

Both entries converge on `scripts/run-strict-stage2-local-gate.sh`; the Docker
path supplies the same locked inputs from the development image rather than
using a second implementation of the gate.

`fast` checks locked metadata, formatting, strict active-spine dependency
direction, the Stage 1 legacy-deletion/oracle boundary, first-party Rust file
sizes (including not-yet-added files), the locked JcoNode Cargo/source/Node/V8
identity, strict Clippy for active-spine targets, and active-spine tests. `full`
includes `fast`, then adds shell parsing,
default-feature workspace tests, every current opt-in feature, active no-std
compilation, selected Wasm packages, the kernel target, benchmark compilation,
and report/artifact fixture gates. Every `system*` tier is standalone and does
not repeat `fast` or `full`. See [VALIDATION.md](VALIDATION.md) for the exact
proof boundary.

Run the dependency-direction check directly with:

```sh
python3 scripts/check-dependency-direction.py
```

It rejects dependencies that point against the accepted contract -> reducer ->
coordinator -> adapter/tool direction. Oracle packages remain buildable under
`full`, but they cannot enter the protected production spine.

The implemented `system` tier creates a private artifact root below
`target/visa-system/`, runs all 31 Stage 1 registry cases through isolated
source and destination worker processes, writes an execution evidence bundle,
then invokes the independent `visa-conformance stage1` validator. The command
prints the retained artifact root and bundle path on success and preserves them
on failure for diagnosis.

On Linux, the verifier requires race-safe descriptor-relative artifact opens;
it never falls back to `canonicalize` followed by an ambient pathname read.
Digest and semantic validation share one captured byte view, and Stage 2 reuses
that view for its inner audits and normalization. Secure artifact inputs are
limited to 256 MiB per file and 128 MiB of retained Stage 1 bytes per cell;
digest-only executable provenance is streamed. An unavailable `openat2`, a
kernel-reported unstable resolution after bounded retries, a
symlink/magic-link/mount escape, a non-regular file, or an exceeded limit is a
gate failure.

`system-jco-node` applies the same 31-case and independent Stage 1 verification
flow to an explicitly selected JcoNode-to-JcoNode pair. `system-stage2` creates
one root containing all four Wasmtime/JcoNode source-destination cells, runs
124 cases, then invokes the independent Stage 2 verifier over the outer bundle.
This legacy v2 matrix retains its `cross-execution-path-portability` claim and
does not become independent-runtime evidence.

`system-stage2-strict` verifies the official Go toolchain, byte-exact Wacogo
source lock and module input, fixed Component, seven selected-runtime
qualification gates, and two byte-identical sidecar builds. It then runs the
focused live-sidecar and real-Wacogo tests, independently verifies the
Wacogo-to-Wacogo Stage 1 cell, and executes the strict v3 matrix in this exact
order: Wasmtime-to-Wasmtime, Wacogo-to-Wacogo, Wasmtime-to-Wacogo, and
Wacogo-to-Wasmtime. A pass covers 124/124 executions and 31/31 normalized
equality groups and earns only `strict-cross-runtime-continuity` on x86-64
Linux with the timer/KV profile. Both Stage 2 matrix gates are intentionally
expensive and are not part of `full`.

## Host Cargo commands

The repository defines these target-specific aliases in `.cargo/config.toml`:

```sh
cargo check-wasm
cargo wasm
cargo kernel
cargo run-vm --verbose
```

- `check-wasm` checks the selected Wasm-target packages for
  `wasm32-unknown-unknown`.
- `wasm` builds those packages.
- `kernel` builds the kernel for `x86_64-unknown-none`.
- `run-vm` runs the current QEMU runner and forwards following arguments.

For a changed package, prefer a focused command such as
`cargo test -p <package>` before a broader gate. Record the exact command and
result; do not describe a host-only check as equivalent to the Docker gate.

## Script hierarchy

The shell scripts are a transitional implementation surface, not a stable
public API. Use them according to their current role:

1. **Repository gate:** `run-docker-ci-gate.sh` is the supported outer entry;
   `ci-gate.sh` implements cumulative `fast`/`full` and the four standalone
   system tiers inside the development environment.
2. **System evidence:** `ci-gate.sh system`, `system-jco-node`, and
   `system-stage2` preserve the Stage 1 and legacy v2 paths;
   `system-stage2-strict` adds the unified locked Wasmtime/Wacogo v3 path. All
   orchestrate real runners followed by independent verifier processes. Invoke
   the binaries directly only when investigating a retained artifact root.
3. **Report checks:** `run-report-gates.sh` and
   `check-conformance-report.sh` exercise report and artifact rules without
   proving external workload execution. `run-visa-bench-conformance.sh` runs
   Criterion and gates the produced performance bundle.
4. **vISA-backed LTP:** `build-visa-ltp-static-syscalls.sh` prepares static
   binaries; `run-visa-ltp-conformance.sh` is the strict selected-suite entry;
   `run-visa-ltp-single.sh` is its per-case worker. The manifest runner is for
   larger exploratory runs and is not the stable strict gate.
5. **Reference-only LTP:** `run-host-ltp-log-adapter.sh` preserves logs from an
   external host `runltp`. Those logs do not prove execution through vISA.
6. **Structural maintenance:** `check-file-size.sh` scans tracked and
   not-yet-added first-party Rust sources and runs as part of `fast`. Hard-limit
   violations in active-spine sources fail the gate; oracle/reference and other
   out-of-spine findings remain informational.

Read each script's usage text, using `--help` where supported. Keep specialist
runners behind a small developer-facing surface.

## Outputs and caches

`target/` and `.ci-cache/` are ignored. The CI-cache overlay stores Cargo and
LTP caches below `.ci-cache/`; the normal Compose configuration uses named
volumes. LTP build helpers default to an XDG or home cache outside repository
build output because their artifacts can be large.

Local LTP binaries, generated manifests, logs, reports, and other runner output
must use a scenario-specific path below `target/<scenario>/` or a location
outside the repository. Do not create catch-all `output/`, `manifest/`, or log
directories beside source code and then hide them with broad ignore rules.

Do not commit generated logs, reports, binaries, or caches merely because a
runner produced them. Commit an evidence artifact only when a maintained
validation contract explicitly requires it and its provenance is recorded.

## Change and validation discipline

Before editing, inspect `git status --short --branch`. The worktree may contain
unrelated or uncommitted work; preserve it and keep the current change
reviewable. Do not reset, regenerate, or reformat unrelated files.

Choose validation based on the claim affected by the change:

- documentation only: check links and Markdown structure, then run
  `git diff --check`;
- manifests or repository metadata: add `metadata` and `fmt` as applicable;
- Rust behavior: run focused package tests, then the relevant target gate;
- Compose or Docker changes: run `docker compose config --quiet`, rebuild the
  image, and run the affected named gates;
- shell changes: run `bash -n` on changed scripts plus their smallest real
  invocation; and
- conformance claims: execute the named workload on the stated runtime, ISA,
  substrate, resource profile, authority boundary, and fault boundary.

Report what was run, what passed, what was skipped, and why. A green existing
gate must not be generalized beyond the proof boundary listed above.

## Next validation expansion

`fast`, `full`, and the four standalone system tiers are the implemented root
interface. The legacy JcoNode v2 matrix proves a second translated execution
path, not a fully independent Component Model implementation. The separate
source-lock-bound Wasmtime/Wacogo v3 matrix supplies that independence and only
the x86-64 Linux timer/KV `strict-cross-runtime-continuity` claim. File/network,
cross-ISA, confidential, release, performance, and production claims remain
unavailable until their exact cells and provenance inputs execute.
