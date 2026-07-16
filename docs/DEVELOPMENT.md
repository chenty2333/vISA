# vISA Development Guide

Status: current repository workflow.

Last reviewed: 2026-07-16.

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
- the `wasm32-unknown-unknown`, `x86_64-unknown-none`, and
  `aarch64-unknown-linux-gnu` targets;
- Node 24.15.0 with V8 13.6.233.17-node.48, installed from the official
  architecture-specific archive after SHA-256 verification;
- on linux/amd64 image builds, the official Go 1.26.5 archive plus the
  source-lock-bound Wacogo module zip and offline module-cache seed used only by
  the x86-64 Linux Strict Stage 2 gate;
- QEMU and OVMF for the current x86_64 kernel runner;
- the GNU AArch64 cross-C toolchain, the AArch64 glibc development sysroot at
  `/usr/aarch64-linux-gnu`, and QEMU-user `qemu-x86_64`/`qemu-aarch64` for the
  bounded Stage 4 matrix; and
- the C, autotools, and Linux packages used by the LTP helpers.

The Node x64 and arm64 archive digests are copied from the official
[`v24.15.0` checksum list](https://nodejs.org/dist/v24.15.0/SHASUMS256.txt).
The Rust toolchain is date-pinned because later nightly compiler changes can
break the bootloader dependency independently of vISA source. The
`debian:stable-slim` base image is not digest-pinned, so this environment still
provides local/CI parity rather than a bit-reproducible release toolchain.
Release claims require all inputs pinned.

Host-native Cargo commands are useful for short edit cycles, but the host is
not the CI parity boundary. A host workflow must independently provide the
declared Rust toolchain, targets, cross linker, target glibc sysroot,
QEMU/OVMF or QEMU-user when required, and any external workload dependencies.
The bounded Stage 4 aggregate additionally fails closed unless its raw
`/usr/bin/uname -s -r -m` receipt identifies an x86_64 Linux orchestrator
execution environment.

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

The repository exposes two cumulative repository tiers, the Stage 1/2/3
standalone system gates, one Stage 3 aggregate, and one complete bounded Stage
4 aggregate with two edit-loop aliases, plus one candidate joint-handoff gate.
Run the ordinary edit-loop gate with:

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

Run the bounded Stage 3A regular-file gate with:

```sh
scripts/run-docker-ci-gate.sh system-stage3a
```

Run the bounded Stage 3B logical-request gate with:

```sh
scripts/run-docker-ci-gate.sh system-stage3b
```

Run both Stage 3 profiles in sequence with:

```sh
scripts/run-docker-ci-gate.sh system-stage3
```

Run the complete bounded Stage 4 target/substrate and emulated cross-ISA matrix
with:

```sh
scripts/run-docker-ci-gate.sh system-stage4
```

`system-stage4-target` and `system-stage4-isa` are names for focused edit
loops, not smaller claim gates. Both currently fail closed by running the same
complete seven-cell aggregate:

```sh
scripts/run-docker-ci-gate.sh system-stage4-target
scripts/run-docker-ci-gate.sh system-stage4-isa
```

Run the candidate joint-handoff cell with:

```sh
scripts/run-docker-ci-gate.sh system-joint-handoff
```

This tier deliberately requires a clean worktree at an exact vISA Git SHA. It
validates remote-accepted neutral implementation
`f4a8211f0e5fde13e0f6101be3c3322854458c79` at tree
`a65f264bb7eaf390cbd6285d791b4f7f43e9be25`. The vendored bundle SHA-256 is
`afe0fdfba1d2e47f5b6ee582833c03befca8e436f3a3d09d0b5df27612549e31`
and the complete source-lock SHA-256 is
`e8894d79ba2b3f164e94451d14139313a477481dc11c94d84a76a7ef774b9d50`.
The implementation's downloaded exact-SHA artifact passed independent
verification; `be250c30...` is its receipt lineage. The tier runs 16
production-reducer traces, executes 16 normative reference ownership/effect
cases plus one supplemental retained-tombstone recovery, reopens the durable
SQLite projection, and executes the HostSubstrate commit and abort verticals.
The Host cell retains exact 14-record commit and 9-record abort transcripts,
including canonical pre-call bytes for seven peer-invocation classes. The
independent verifier recomputes those transcripts, receipts, peer relations,
local journals, leases, checkpoints, and terminal states. The tier publishes an
exact two-file bundle and verifies it again after relocation.

The source lock still declares `adapter_qualification=false`; it is the neutral
mapping baseline, not Nexus execution evidence. The separate Nexus-local lane
is driven by:

```sh
scripts/run-nexus-handoff-qualification.sh \
  --checkout <clean-nexus-checkout> \
  --artifact-root <new-artifact-root>
```

That lane is locked to Nexus revision
`81c484c2fc2215803d8c719a86301e42ea7daa87`, source fingerprint
`b4c5de62...`, matrix `9f3f1579...`, and v2 qualification-lock SHA-256
`7c977ac7a552b6c7e03e26aada242d49309c8bdb1329152da9e3d489e648ba1b`.
The receipt records `production_registry_refinement_checked=true`. Its SHA-256
is specific to one generated run and is recorded only in a corresponding
validation receipt.

Run the standalone exact-binary process publisher with:

```sh
scripts/run-nexus-process-joint-cell.sh \
  --nexus-checkout <clean-nexus-checkout> \
  --nexus-bin <exact-nexus-effect-peer> \
  --artifact-root <new-final-artifact-root>
```

Exact-binary process tests cover raw-chain replay, Registered-effect abort preservation, the bounded
process qualification scenarios, and the real logical-request dual-lost-ack
cell. The latter is supplemental: it performs a post-durable ownership Commit acknowledgement loss
and a terminal Nexus response loss before adapter acceptance; both recover via
exact query/retry without duplicate execution or publication, but does not run
vISA freeze/fence/activation or put Nexus admission before the external effect.

The standalone runner validates both locks and the Nexus receipt, publishes an
exact three-file process artifact containing the executed binary, verifies it in
a second process, relocates it, and verifies the same bytes in a third. The
supplemental logical runner publishes five files: manifest, report, two SQLite
databases, and the same content-identified binary. Download verification accepts
artifact-service mode normalization, does not re-execute the binary, and does
not claim reproducible source-to-binary derivation. The smoke runs pass, but
the final artifact must wait until this vISA work is committed so the runner can
bind the final clean vISA SHA.

The Host refinement requires `exclusive_trusted_coordinator_api=true`: bypass
through a second raw `Coordinator`/provider handle or hostile public-projection
caller is outside the bounded TCB. None of these local lanes qualifies Registry
replacement, real OSTD, IRQ/SMP, the production retained-tombstone path,
cross-host, host-reboot, Byzantine-ownership, cryptographic,
anti-rollback/freshness, TEE/KMS, or Stage 5 behavior; their crash boundary is
same-boot.

With no tier argument the wrapper runs `full`. It validates the Compose
configuration, builds the image, then invokes the same `scripts/ci-gate.sh`
implementation used by CI. `--skip-build` reuses an existing image.
`--ci-cache` overlays `compose.ci.yaml`. It bind-mounts Cargo and LTP build state
below `.ci-cache/`, places system evidence below `.ci-artifacts/`, and disables
Cargo incremental compilation to match GitHub Actions. Inside the container,
the artifact mount is exposed at the ignored `/workspace/evidence` alias so a
clean-checking qualification gate cannot mistake its own output root for source.

The strict Docker wrapper retains its gate root, locked Wacogo sidecar and build
receipt, Docker log, and exit receipt together below `.ci-artifacts/strict-stage2/`
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
sizes (including not-yet-added files), the build/cache/evidence CI contract, the
locked JcoNode Cargo/source/Node/V8 identity, strict Clippy for active-spine
targets, and active-spine tests. `full`
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

The implemented `system` tier creates a private artifact root, runs all 31 Stage
1 registry cases through isolated source and destination worker processes,
writes an execution evidence bundle, then invokes the independent
`visa-conformance stage1` validator. Direct Host and normal Compose runs default
to `target/visa-system/`; `VISA_EVIDENCE_PARENT` selects another parent, and the
CI-cache overlay fixes it at the host-visible `.ci-artifacts/` mount. The command
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

The locked dev-profile Component was qualified with Cargo incremental mode.
The Strict gate therefore canonicalizes and records `CARGO_INCREMENTAL=1`
before building it, even though the general CI overlay uses `0` to reduce the
size and cross-run coupling of ephemeral target trees. Ambient CI settings
cannot silently select different Component bytes.

`system-stage3a` creates a private root under the same configurable evidence
parent, runs the fixed 12-case regular-file registry through the Stage 3A
Component, Wasmtime adapter, coordinator, scoped Linux file provider, handoff,
and evidence writer, then invokes `visa-conformance stage3a` independently over
the retained bundle.
Qualification requires Linux `openat2` and a filesystem that reports
`STATX_BTIME`. The provider compares device, inode, and birth time for both the
opened root and file; missing birth time is an unsupported capability with no
device/inode-only fallback. Its external-mutation cases detect identity,
content, or version drift already observable before a provider operation, and
provider tests deterministically race the final SQLite authority/lease/pre-state
fence against handoff commit. Lock/lease conflict behavior applies only to
writers participating in the same advisory protocol; the gate does not
establish atomic compare-and-mutate against an uncooperative writer that
bypasses it. Birth time is not a cryptographic identity or a Stage 5
host-attestation mechanism.

`system-stage3b` follows the same two-step runner/verifier shape for the fixed
14-case logical-request registry. It uses a real bounded loopback TCP
protocol/peer and a durable provider operation ledger, but it preserves logical
request identity and reconnect/replay state rather than a raw live transport.
The `VISALR03` handshake authenticates the configured peer with a fresh nonce
and HMAC-SHA-256 before sending an application request frame; credential
material is not transmitted, and Lookup/Cancel also authenticate the expected
request digest. Every application send performs a final authority, lease, and
binding check under the SQLite handoff transaction lock. Execute is bound by a
digest derived from the authenticated request bytes, while Lookup/Cancel carry
the expected digest. An immediate-transaction revision compare-and-save rejects
stale terminal/cursor/cleanup rollback. This bounded local admission fence is
not a general encrypted-channel or remote-effect atomicity claim.
`system-stage3` runs these two standalone gates in sequence and retains one
artifact root per profile.

The Stage 3 conformance commands are independent **structural bundle
verifiers**. The executable runner evaluates the case semantics; the verifier
then fixes the accepted registry and assertion shape, checks scope and runtime
identities, and revalidates the published artifact sizes and digests. Unlike
the typed Stage 2 normalizer, it does not recompute every semantic assertion
from the raw trace and request/response bytes.

Both Stage 3 gates currently use separate source and destination Wasmtime
stores, coordinators, and provider instances backed by local SQLite continuity
within one OS system-runner process on x86-64 Linux. This validates the current
local-rebinding profiles, not dual-worker process isolation, cross-host
transport, or a target change. Their bundles require
`independent_runtime_coverage=false` and list Wacogo as unsupported. Run
`system-stage2-strict` separately when checking the independent-runtime
timer/KV control; its conclusion does not transfer to Stage 3. The Stage 3 gates
do not claim arbitrary directory trees, devices, FIFOs, open fds, arbitrary
live TCP, socket state, generic future/stream continuation, or a general async
runtime.

`system-stage4` holds the Wasmtime implementation, timer/KV profile, and
31-case Stage 1 registry fixed while varying three target execution endpoints:

```text
Hx = artifact-owned x86_64-unknown-linux-gnu worker, executed natively
Qx = the same artifact-owned x86-64 worker under the artifact-owned
     qemu-x86_64 executable with -cpu max and the identified / sysroot
Qa = artifact-owned aarch64-unknown-linux-gnu worker under the artifact-owned
     qemu-aarch64 executable with -cpu max and the identified
     /usr/aarch64-linux-gnu sysroot
```

It cross-builds release x86-64 runner/worker/verifier binaries and the release
AArch64 worker, executes these seven unique cells, and independently verifies
the result:

```text
Hx -> Hx   Hx -> Qx   Qx -> Hx   Qx -> Qx
Qx -> Qa   Qa -> Qx   Qa -> Qa
```

That is 217 case executions, seven independently verified inner Stage 1
bundles, and 31 normalized observable groups compared across all seven cells.
The Stage 4 release build locks its own Component byte digest; it uses the same
Stage 1 source/WIT contract but is intentionally a different build artifact
from Strict Stage 2's dev-profile Component. The Stage 4 common input uses its
v2 schema to retain the same typed 3 Pending / 22 Precompleted / 6
ScenarioControlled timer-strategy partition as the Stage 2 common input; the
verifier checks both the snapshot disposition and authoritative final branch.
The aggregate publishes only `named-target-substrate-continuity-v1` for the
four Hx/Qx cells and `emulated-cross-isa-continuity-v1` for the four Qx/Qa
cells; the shared `Qx -> Qx` cell belongs to both claims. Workers, QEMU
executables, launcher/build/sysroot receipts, raw nonce-bound target hellos,
resolved loader-dependency digests, and the raw `uname` host receipt are
retained in the artifact root. Together with Hx's direct launcher, the host
receipt binds the run to an execution environment reporting x86-64 Linux and a
kernel release. It is not hardware attestation, bare-metal evidence, proof that
no outer virtualization/binfmt layer exists, or a cross-host proof.

The Stage 4 writer starts with `stage4-incomplete` and keeps
`stage4-status.json` after its initial status write succeeds. Runner failures
before publication normally retain those diagnostics; an earlier status-write
failure may retain only the marker. A success removes the status file, verifies
the complete staged artifact graph, and removes the incomplete marker only when
publication commits. A subsequent independent-verifier or relocation failure
is represented by the outer gate exit/log and does not recreate those runner
diagnostics. The separate
`visa-conformance stage4` process then checks all inner evidence, independently
recomputes normalization, validates the exact artifact set, and rejects native
fallback or claim expansion. The gate next renames the complete directory to
an unused `-relocated` path without rewriting any JSON and runs the verifier a
second time. `matrix.json` deliberately retains the historical execution root
for launcher-argv provenance while artifact lookup uses the new verifier root.
Unit negative coverage adds an unmanifested file, together with temporary,
symlink, hardlink, and special entries, and requires exact-set rejection.

The shared `performance-observations` input remains the original 50 ms timer.
Raw steady-state measurements are target-speed-dependent, so the runner now
waits for that timer outside the measured interruption interval, requires the
`Completed` safe-point branch before freeze, and verifies that restore does not
recreate it. This removes the observed QEMU-dependent Pending-versus-Completed
flake without lengthening or silently replacing the Stage 1 workload input.

This bounded matrix does not qualify real AArch64 hardware, the legacy
no-std/reference kernel, real-device enforcement, either Stage 3 resource
profile across targets, a second Stage 4 runtime, AOT binary portability,
cross-host execution, 32-bit or big-endian targets, hostile-host
confidentiality, performance, or production readiness. The Strict Stage 2
Wasmtime/Wacogo result remains a separate independent-runtime control and is
not inherited by Stage 4.

After one current image build, the stage-closing local control sweep is:

```sh
scripts/run-docker-ci-gate.sh --ci-cache --skip-build full
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-jco-node
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage2
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage2-strict
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage3a
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage3b
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage4
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-joint-handoff
```

`full` and every `system*` tier are standalone; no green tier implies one of
the omitted controls. The two Stage 4 aliases need not be repeated because they
execute the same aggregate.

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
   `ci-gate.sh` implements cumulative `fast`/`full`, the standalone system
   gates, the Stage 3 aggregate, and the complete Stage 4 aggregate inside the
   development environment, plus the joint-handoff vISA/reference gate.
2. **System evidence:** `ci-gate.sh system`, `system-jco-node`, and
   `system-stage2` preserve the Stage 1 and legacy v2 paths;
   `system-stage2-strict` adds the unified locked Wasmtime/Wacogo v3 path;
   `system-stage3a` and `system-stage3b` add the two bounded Wasmtime-only
   resource profiles, while `system-stage3` invokes both. `system-stage4`
   supplies the bounded native/QEMU-user target and cross-ISA aggregate;
   `system-stage4-target` and `system-stage4-isa` currently invoke that same
   full matrix. `system-joint-handoff` source-locks the neutral contract, runs
   production-reducer replay plus reference ownership/effect peers, and executes
   the separately reported HostSubstrate vertical; it remains an open candidate
   lane. All orchestrate runners followed by independent verifier processes.
   Invoke the binaries directly only when investigating a retained artifact
   root.
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

`target/`, `.ci-cache/`, `.ci-artifacts/`, and the CI-only `evidence/` bind alias
are ignored, but they have distinct lifecycles. The CI-cache overlay stores Cargo
registry/git state, transient Cargo target output, and the LTP build cache below
`.ci-cache/`; GitHub Actions restores only Cargo registry/git state across runs,
never the full target tree. The
quality job owns publication of that shared dependency cache, while claim lanes
restore it without publishing duplicates. Current CI does not run or cache an
external LTP build. CI sets `CARGO_INCREMENTAL=0`. The normal Compose
configuration uses named volumes. LTP build helpers default to an XDG or home
cache outside repository build output because their artifacts can be large.

`.ci-artifacts/` contains retained system evidence and gate logs. Keeping it
outside the Cargo target tree allows evidence to be uploaded, diagnosed, or
deleted without changing the build-cache lifecycle.

A successful joint-handoff run ends below a
`joint-handoff-reference-*/reference-relocated/` root with exactly
`joint-handoff-evidence.json` and `production-replay.json`. The outer CI
artifact may also contain `joint-handoff-reference-ci.log`; those names predate
the HostSubstrate subcell. The evidence intentionally keeps the fixed reference
peer trace lane separate from the HostSubstrate receipts, peer invocations,
journals, leases, checkpoints, and durable projection windows. It is not a
Nexus qualification artifact.

For a direct run, Stage 4 output defaults to `target/visa-system/`; a successful
run ends in `stage4-*-relocated/` because relocation is part of the gate, not a
cleanup rename. With `--ci-cache`, the evidence root is host-visible below
`.ci-artifacts/`. A prepublication runner failure normally leaves a partial root
with its marker and, after initialization, status diagnostics; a later gate
failure may instead leave a marker-free published root. The GitHub Stage 4 job
additionally tees gate output to `.ci-artifacts/stage4-ci.log`; `--ci-cache` and
the local Docker wrapper do not create that log by themselves. When rechecking a
downloaded Actions artifact, pass the inner `stage4-*-relocated/` directory and
its `stage4-evidence.json` to `visa-conformance stage4`; do not pass the artifact
parent, which also contains `stage4-ci.log`.

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

Bounded Roadmap Stage 4 is complete only for its two named claims. Accepted
qualification revision `457ae1d64915c0b3febd84e136d08be53063210f` passed all
eight independent qualification jobs and the exact-SHA closure in Actions run
`29386011420`; the downloaded Stage 4 artifact passed independent verification
at a different root. The complete receipt is recorded in
[validation](VALIDATION.md#stage-4-closure-receipt).

Current CI separates repository quality from claim qualification. One job runs
`full`; six matrix lanes independently run Stage 1, JcoNode, legacy Stage 2,
Strict Stage 2, Stage 3A, and Stage 3B; a separate lane runs the complete Stage 4
aggregate, one separate Docker lane runs the candidate reference/HostSubstrate
joint-handoff cell, and one host-built lane runs the clean exact-SHA Nexus-local
and process qualification. A final `Exact-SHA qualification closure` job fails
unless all ten prerequisite job executions succeed for the same source SHA,
making eleven jobs including closure. The reference-only lane does not qualify
Nexus, and neither joint lane substitutes for the other. Every Docker image is
built from that checkout and tagged `visa-dev:<SHA>`. Claim evidence and logs
upload from `.ci-artifacts/` on gate success or failure. Pull-request artifacts
are retained for 3 days and push artifacts for 14 days.

## Next validation expansion

`fast`, `full`, the Stage 1/2/3 standalone gates, the Stage 3 aggregate, the
bounded Stage 4 aggregate, and the candidate joint-handoff gate are the
implemented root interface. The legacy
JcoNode v2 matrix proves a second
translated execution path, not a fully independent Component Model
implementation. The separate source-lock-bound Wasmtime/Wacogo v3 matrix
supplies that independence and only the x86-64 Linux timer/KV
`strict-cross-runtime-continuity` claim. Stage 3A and Stage 3B add only the two
bounded Wasmtime-to-Wasmtime regular-file and logical-request claims. Completed
Stage 4 adds only the named native/QEMU-user target-substrate and emulated
x86-64/AArch64 timer/KV claims described above. The joint-handoff gate supports
only the candidate `bounded-joint-handoff-refinement-v1`; its HostSubstrate cell
is implemented and strictly verified, its Nexus-local lane is clean-qualified
locally, and all four exact-binary live process tests pass. The process
publisher/relocation runner has a smoke pass. The final clean joint vISA
artifact, local/Docker closure, pushed exact-SHA vISA CI, and downloaded-artifact
closure remain pending.
A second Stage 3 runtime, broader file/network families,
cross-process Stage 3 workers, real hardware/reference-kernel/device cells,
cross-host execution, confidential, release, performance, and production
claims remain unavailable until their exact cells and provenance inputs
execute.
