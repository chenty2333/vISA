# Quickstart and Evidence: Strict Stage 2 Closure

Status: active; repository convergence, the Jco sealed carrier, and a no-go
Runtime B qualification are recorded below. Strict Stage 2 is not earned.

This file records exact commands, pinned runtime/tool identities, retained
artifact roots, bundle IDs/digests, qualification decisions, and verifier
results while the slice is active. A command listed here is not evidence until
its exit status and retained output are recorded.

## Baseline

- Branch: `master`
- Entry commit: `30c2ca25f6c1cd2851609229e3d3c875e2d32583`
- Entry CI: `https://github.com/chenty2333/vISA/actions/runs/29172449174`
- Entry claim: `cross-execution-path-portability`
- Strict Stage 2: not yet earned

## Focused edit loop

```sh
scripts/run-docker-ci-gate.sh fast
```

Repository convergence evidence on 2026-07-12:

- `cargo metadata --locked --no-deps --format-version 1`: 48/48 workspace
  packages report `Apache-2.0`;
- root `LICENSE` SHA-256:
  `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`;
- `docker compose config --quiet`: passed;
- final Host `scripts/ci-gate.sh full`: passed;
- final Docker `scripts/run-docker-ci-gate.sh --ci-cache --skip-build full`:
  passed; and
- completed specs 003-007, the unused Dev Container, `deny.toml`, and the
  deprecated LTP alias were removed after canonical extraction.

## Full repository gate

```sh
scripts/run-docker-ci-gate.sh full
```

## Existing system baselines

```sh
scripts/run-docker-ci-gate.sh system
scripts/run-docker-ci-gate.sh system-jco-node
scripts/run-docker-ci-gate.sh system-stage2
```

## Runtime qualification

The machine-readable record is `runtime-b-qualification.json`; the locked WACS
decode, typed-harness, and CLI/AOT probes, the retained wacogo Go-module probe,
and their input resolver are under `qualification/`.

Fixed unchanged input:

```sh
cargo build --locked -p visa-system
COMPONENT="$(
  specs/008-strict-stage2-closure/qualification/resolve-component.sh
)"
WIT=wit/cooperative-handoff/world.wit
printf '%s  %s\n' \
  4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b \
  "$COMPONENT" | sha256sum -c -
printf '%s  %s\n' \
  709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920 \
  "$WIT" | sha256sum -c -
```

The resolver selects only the 146,486-byte artifact with the recorded digest;
it does not depend on Cargo's machine-local build fingerprint directory. Every
retained probe independently rechecks both digests and fails closed on drift.

Reproduce the wacogo probe with Go 1.25.5 or newer:

```sh
specs/008-strict-stage2-closure/qualification/run-wacogo-probe.sh \
  "$COMPONENT"
```

The script pins `github.com/partite-ai/wacogo` pseudo-version
`v0.0.0-20260617023329-3de16a61796c`, commit
`3de16a61796ce02d29795e4a074f37a33e6ebd87`, Apache-2.0, module sum
`h1:WAxQQFk9xW0jy0cu1Ql4JaaUJTUMo0GsK5TNn5Nliiw=`, and module-zip SHA-256
`ffc2004ea59076ef619d3043d4ae4400338cf3a8d2c67b294e582715ce5f26f4`.
Its checked `go.mod`, `go.sum`, and exact 23-dependency module list include the
binding generator and runtime closure. The executable Component path is
wacogo's own Go parser, validator, linker, Canonical ABI, and resource code over
wazero core execution; neither Wasmtime nor `wasmtime-environ` is in that path.
`go.bytecodealliance.org` and its embedded wasm-tools helper parse the WIT for
binding generation only, not the Component binary.

Result: the probe exits 0 after confirming an expected no-go. wacogo loads,
validates, and compiles the unchanged 146,486-byte Component, identifies both
interface-instance imports and the workload interface-instance export, and
generates and instantiates real key-value and timer host components from the
unchanged WIT. Supplying those instances to the Component then fails inside the
real nested-component instantiation plan:

```text
wacogo: instantiate component:
arg "import-type-kv-error" references unresolved type 24
```

The outer instance-import type check has already passed at that point; the
pinned implementation cannot resolve the nested direct interface-imported type
argument. Owned-resource transfer and `activate`, `status`, `freeze`, `restore`,
and cleanup were therefore not reached. No raw `CallRaw` or handwritten
Canonical ABI fallback was used.

Reproduce the WACS decode probe after installing .NET SDK 8.0.419:

```sh
dotnet restore \
  specs/008-strict-stage2-closure/qualification/wacs-decode/wacs-decode.csproj \
  --locked-mode
dotnet run \
  --project specs/008-strict-stage2-closure/qualification/wacs-decode/wacs-decode.csproj \
  -c Release --no-restore -- "$COMPONENT" "$WIT"
```

Result: pass. WACS 0.16.14 / ComponentModel 0.10.3 parsed three core
modules, one nested component, all six timer/KV method and resource-drop
imports, and the `visa:continuity/workload@0.1.0` `Instance` export.

Reproduce the unchanged-WIT typed harness probe after installing .NET SDK
9.0.301 and runtime 9.0.6:

```sh
DOTNET=dotnet \
  specs/008-strict-stage2-closure/qualification/run-wacs-harness-probe.sh \
  "$COMPONENT"
```

Result: the retained wrapper exits 0 only after confirming the underlying
harness exits 1 at the exact typed world-emission stage with the exact
`System.NotSupportedException` and package/input identities:

```text
emit=failed type=System.NotSupportedException
Anonymous variant types not supported in v0.2 (case 'kv' of variant 'workload-error').
```

The released CLI/Transpiler/NativeAOT path was separately exercised with .NET
SDK 9.0.301. The probe installs and verifies `WACS.Cli` 1.10.1 package SHA-256
`35dbe748e139888181ea91c5c1e0188a95f7fcdaac6b7ec1a8723e1494fa5ae3`;
the tool identifies itself as commit `e6e76340b9d38ec3846d39833136eac8846f9f81`
and bundles `WACS.Transpiler.Lib` 0.12.12.

```sh
DOTNET=dotnet \
  specs/008-strict-stage2-closure/qualification/run-wacs-cli-aot-probe.sh \
  "$COMPONENT"
```

Result: the probe exits 0 after confirming the expected no-go observations.
Both `wacs build --wit-dir` and `wacs aot --wit-dir` reject the unchanged
world's `key-value` and `timers` interface
imports because the v0 contract validator cannot compare interface-import
shapes. Without the WIT contract, `wacs build` emits a 311,296-byte assembly,
but the retained metadata probe finds only six raw core imports and seven raw
Canonical-ABI exports. `activate` is exposed as one `i32` indirect-area pointer,
no typed workload surface is emitted, and raw `status` execution exits 128
without a structured result. Writing that indirect ABI in a vISA adapter is an
explicitly prohibited bypass.

The earlier inference from raw `ComponentInstance.Invoke` to missing
interface-instance support was removed: the released typed harness does know
how to flatten interface exports. The actual no-go rests on executable typed
harness, CLI/Transpiler, and NativeAOT failures. WACS passes the independent
lineage test but fails the unchanged-world prerequisite; the real host-bridge
and lifecycle gates were therefore not reached.

The released `ComponentInstance` surface is not an untested semantic bypass.
Its multi-core mode instantiates only the primary core module and explicitly
skips the component adapter and post-return shim, while `Invoke` accepts only a
top-level `Func`. The unchanged vISA Component exports the workload as an
`Instance`; reaching its raw core exports would therefore require the same
adapter-authored Canonical ABI that this qualification forbids.

WasmEdge 0.17.1 was pinned and reproduced independently:

```sh
WASMEDGE_DIR="$(mktemp -d)"
curl -fL \
  https://github.com/WasmEdge/WasmEdge/releases/download/0.17.1/WasmEdge-0.17.1-manylinux_2_28_x86_64.tar.xz \
  -o "$WASMEDGE_DIR/WasmEdge-0.17.1.tar.xz"
printf '%s  %s\n' \
  e88199f7c48fe27fc1a23b104f4049d2615cef1ebe70b588b0e082ca9eb5f6e5 \
  "$WASMEDGE_DIR/WasmEdge-0.17.1.tar.xz" | sha256sum -c -
specs/008-strict-stage2-closure/qualification/run-wasmedge-probe.sh \
  "$COMPONENT" "$WASMEDGE_DIR/WasmEdge-0.17.1.tar.xz"
```

Result: the retained wrapper exits 0 only after confirming the pinned archive,
WasmEdge 0.17.1 identity, underlying exit 1, component-validation stage, and
exact canonical-section diagnostic. Validation rejects `canon resource.drop`
type index 10 because it does not accept that index as a resource.

Decision: **no-go for the three executable candidates recorded here: WACS,
WasmEdge, and wacogo**. This is not a claim that every released runtime or
source snapshot has been exhaustively qualified. The source-only Airbus WAMR
`dev/cm_wasip2_complete` branch is a future retest candidate, not evidence in
this decision.
`selected_runtime` is null. No adapter, selector, host bridge, or matrix cell
was created, so strict Stage 2 remains in progress until a candidate meets all
seven qualification conditions.

## Jco sealed execution carrier

Mechanism: `owned-bytes-stdin-frame-v1`. The prepared adapter owns the exact
generated JavaScript and core-Wasm graph. Preflight and execution consume those
same bytes through a bounded `VISAJCO1` stdin frame; the compiled-in Node driver
verifies the independent graph digest before data-URL import or in-memory core
module compilation. The former publisher pathname tree is not part of the
production load path.

Because carrier identity is now a required worker observation, the worker
protocol is v2, Stage 1 evidence is `visa-stage1-evidence-v0.3`, and the Stage 2
matrix manifest and evidence schemas are v2. Older evidence cannot silently
inherit the sealed-carrier claim.

Focused evidence:

```text
cargo test --locked -p visa_jco_node: 45 passed
cargo test --locked -p visa-conformance: 82 passed
cargo clippy --locked -p visa_jco_node --all-targets -- -D warnings: passed
python3 scripts/check-jco-node-toolchain.py: passed
scripts/check-file-size.sh: passed
```

Deterministic tests replace the captured entrypoint, core file, directory,
symlink, and entire publication root, and separately inject a structurally
valid graph with the wrong captured digest. The original owned bytes execute or
the process fails before import; the replacement marker never executes.

The independent evidence verifier also rejects exact-shape and deletion
attacks that a self-consistent hash rewrite must not legitimize. Initialize
requests bind the complete namespace/authority options and role-specific fault
to the ordered matrix; supplemental fault/retry workers bind to provider fault
coverage; source/destination raw sets are exact; both primary PIDs are derived
and must differ; every worker sequence starts at 1 and remains contiguous; and
each successful result kind must be possible for its closed command kind.
Tamper tests cover unknown options, legal-but-wrong faults, malformed silent
crashes, removed transcripts/pairs, PID splicing/collision, and forged
command/result pairings.

## Final Host and Docker revalidation

The final frozen implementation passed the existing executable claim on both
Host and Docker after the slow-container timer flake was removed. The
`kv-duplicate-idempotent-request` case now deliberately uses the
completed-timer handoff helper because that case tests operation replay, not
the pending-timer branch; scheduler speed can no longer select a different
semantic path.

Host results:

```text
scripts/ci-gate.sh full: passed
scripts/ci-gate.sh system: 31/31 and independent verifier passed
scripts/ci-gate.sh system-jco-node: 31/31 and independent verifier passed
scripts/ci-gate.sh system-stage2: 124/124 and independent verifier passed

Artifact root: target/visa-system/stage2-Dju1P1
Bundle ID: stage2-33208b7bb3da7e82a975c9c1
Evidence SHA-256: c2fd58ac6702f9cd911680114e3e8ecce2a3fc9749aef5caef30d640c4dbf880
Matrix SHA-256: 33208b7bb3da7e82a975c9c1e7ed58035e7809060bc4a6474e6f4079c8527930
```

Docker results:

```text
scripts/run-docker-ci-gate.sh --ci-cache --skip-build full: passed
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system: 31/31 and independent verifier passed
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-jco-node: 31/31 and independent verifier passed
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage2: 124/124 and independent verifier passed

Host-visible artifact root: .ci-cache/target/visa-system/stage2-Vhq0mm
Bundle ID: stage2-b15e0d75f02e1b454c46fcb6
Evidence SHA-256: d5a533fc661234bb27ff68d3086a6622820b0925a65c0c940b97bb628c4aba80
Matrix SHA-256: b15e0d75f02e1b454c46fcb6cad791d23af399706f7b1d97dec87fb1d14801f1
```

Both evidence bundles contain exactly four cells with 31 cases each, every
inner Stage 1 bundle is independently verified, all 31 normalized case groups
are equal, and every Jco translation provenance records
`owned-bytes-stdin-frame-v1`. Their only earned claim remains
`cross-execution-path-portability`; the guard
`strict_component_model_runtime_independence` is `not-proven`.

## Strict Stage 2 evidence

Qualified-runtime same-path root, strict matrix root, cell bundle identities,
31-case counts, normalized equality groups, independent verifier result, Host/
Docker parity, and final `strict-cross-runtime-continuity` claim remain pending.
They may be produced only after a Runtime B passes the unchanged-world
qualification gate. The active spec is retained for that reason.
