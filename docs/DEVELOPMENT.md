# vISA Development Guide

Status: current repository workflow.

Last reviewed: 2026-07-11.

This document describes commands that exist in the repository today. It is not
a claim that the current build and test surface validates the target system in
full. Read the project [vision](VISION.md) and [architecture](ARCHITECTURE.md)
before changing scope, contracts, dependency direction, or evidence claims.

## Supported environment

The supported development environment and current CI parity boundary is the
`dev` service in `compose.yaml`. Its image contains:

- the floating nightly installed by `Dockerfile`, currently matching the
  channel declared in `rust-toolchain.toml`;
- `rust-src`, `rustfmt`, `clippy`, and `llvm-tools-preview`;
- the `wasm32-unknown-unknown` and `x86_64-unknown-none` targets;
- QEMU and OVMF for the current x86_64 kernel runner; and
- the C, autotools, and Linux packages used by the LTP helpers.

The current `nightly` toolchain and `debian:stable-slim` base image are not
digest-pinned. This environment provides current local/CI parity, not a
bit-reproducible release toolchain. Release claims require pinned inputs.

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

The repository exposes two implemented, cumulative repository tiers and one
standalone system tier. Run the ordinary edit-loop gate with:

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

With no tier argument the wrapper runs `full`. It validates the Compose
configuration, builds the image, then invokes the same `scripts/ci-gate.sh`
implementation used by CI. `--skip-build` reuses an existing image.
`--ci-cache` overlays `compose.ci.yaml` and uses the bind-mounted `.ci-cache/`
layout used by GitHub Actions.

`fast` checks locked metadata, formatting, strict active-spine dependency
direction, the Stage 1 legacy-deletion/oracle boundary, strict Clippy for
active-spine targets, and active-spine tests. `full` includes `fast`, then adds
shell parsing, default-feature workspace tests, every current opt-in feature,
active no-std compilation, selected Wasm packages, the kernel target, benchmark
compilation, and report/artifact fixture gates. `system` is standalone: it does
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
   `ci-gate.sh` implements the cumulative `fast` and `full` tiers and the
   standalone `system` tier inside the development environment.
2. **Stage 1 system:** `ci-gate.sh system` orchestrates the real runner and the
   independent verifier. Invoke the underlying binaries directly only when
   investigating a retained artifact root.
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
   `run-ltp-conformance.sh` is a deprecated compatibility alias and must not be
   used for new automation or evidence claims.
6. **Structural maintenance:** `check-file-size.sh` reports oversized Rust
   files. It is not currently part of the main CI gate.

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

`fast`, `full`, and standalone `system` are the implemented root interface.
The next validation expansions are release and claim gates for additional
declared runtime/ISA/substrate cells, beginning with the independent runtime
work in Stage 2. Those claims remain unavailable until their exact matrix cells
and provenance inputs execute.
