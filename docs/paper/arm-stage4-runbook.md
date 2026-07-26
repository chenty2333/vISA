# Real AArch64 Stage 4 re-run runbook

Status: working note, not a canonical truth source. Not part of the seven
canonical documents. Records analysis and a proposed procedure; it grants no
claim and changes no gate by itself.

Last reviewed: 2026-07-26.

## Scope

What it would take to re-run the Stage 4 matrix on real aarch64 Linux hardware
instead of QEMU-user emulation, and what would have to change in code, locks,
and the claim registry before such a run could be published.

This note does not claim that a real-hardware run has happened, and nothing
here weakens the existing boundary on the emulated result. `README.md` states
the current limit directly:

> This is semantic target/substrate and emulated cross-ISA evidence, not
> AOT-binary portability, real ARM hardware, Stage 3 resource portability
> across targets, or a second Stage 4 runtime.

and, on the `Qa` endpoint specifically:

> QEMU-user translates user-space instructions but still uses the same host
> kernel, so `Qa` is not a real ARM machine or an ARM-kernel result.

Removing "real ARM hardware" from that exclusion list is the entire point of
the work described here, and it cannot be done by re-running the existing gate
on different hardware. The reasons are in "What blocks a naive re-run" below.

## Existing Stage 4 evidence structure

### Endpoints and cells

Stage 4 qualifies three endpoints, defined as `Stage4EndpointId` in
`crates/testing/visa-conformance/src/stage4/model.rs`:

| Endpoint | Architecture | Target triple | Execution |
| --- | --- | --- | --- |
| `Hx` | `x86_64` | `x86_64-unknown-linux-gnu` | native on the x86-64 Linux host |
| `Qx` | `x86_64` | `x86_64-unknown-linux-gnu` | under artifact-owned `qemu-x86_64`, sysroot `/` |
| `Qa` | `aarch64` | `aarch64-unknown-linux-gnu` | under artifact-owned `qemu-aarch64`, sysroot `/usr/aarch64-linux-gnu` |

Cells are source-to-destination pairs. `named-target-substrate-continuity-v1`
covers `Hx->Hx`, `Hx->Qx`, `Qx->Hx`, and `Qx->Qx`;
`emulated-cross-isa-continuity-v1` covers `Qx->Qx`, `Qx->Qa`, `Qa->Qx`, and
`Qa->Qa`. `Qx->Qx` is shared, so the aggregate is 7 unique cells, 31 cases per
cell, 217 executions, and 31 recomputed equality groups.

### Artifact ownership model

"Artifact-owned" is literal. `crates/testing/visa-system/src/stage4_command.rs`
copies every executable it will run into the evidence root before running it,
via `copy_owned_executable` for both the per-endpoint worker and the QEMU
binary, and records a version receipt for QEMU through `retain_qemu_version`.
The sysroot is canonicalized (`canonical_directory`), its loader resolution is
captured, and a sysroot manifest and receipt are published alongside.

The consequence for a hardware re-run: the evidence bundle does not reference
host paths for the things that matter. It contains the binaries. That is what
makes the published bundle survive the relocation check in
`scripts/ci-gate.sh` — the gate moves the whole directory to a new absolute
path without rewriting any JSON and revalidates it. As `README.md` puts it,
"The recorded execution root remains historical launcher provenance," not a
live path the verifier depends on.

The publisher also writes a durable `stage4-incomplete` marker before running
cells; staged verification requires it, successful publication removes it, and
published verification rejects a bundle that still carries it.

### How the gate drives it

`gate_system_stage4` in `scripts/ci-gate.sh` builds release `visa-system` and
`visa-conformance` for `x86_64-unknown-linux-gnu`, builds the `visa-system`
worker for `aarch64-unknown-linux-gnu`, then runs the x86-64 worker as the
orchestrator with six mandatory environment variables:

```
VISA_STAGE4_X86_64_WORKER   VISA_STAGE4_QEMU_X86_64   VISA_STAGE4_QX_SYSROOT
VISA_STAGE4_AARCH64_WORKER  VISA_STAGE4_QEMU_AARCH64  VISA_STAGE4_QA_SYSROOT
```

QEMU paths come from `command -v qemu-x86_64` and `command -v qemu-aarch64` on
the gate host. Verification then runs the separately built `visa-conformance`
binary against the bundle, before and after relocation.

## What blocks a naive re-run

Running the current `system-stage4` tier on an aarch64 host does not produce
real-hardware evidence. It fails, and it should.

1. **The orchestrator is pinned to `Hx`.** `stage4_command.rs` calls
   `require_named_target(Stage4EndpointId::Hx, &orchestrator)` against the
   independently observed target, and `require_named_target` rejects anything
   whose triple and architecture are not `x86_64-unknown-linux-gnu` /
   `x86_64`. On an aarch64 host this fails with exit 64.

2. **There is no native-AArch64 endpoint.** `Stage4EndpointId` has exactly
   three variants, and `architecture()` / `target_triple()` are `const fn`
   matches over them. Native AArch64 needs a fourth endpoint — call it `Ha` —
   which is a model change, not a configuration change.

3. **All six environment variables are mandatory**, including
   `VISA_STAGE4_QEMU_AARCH64` and `VISA_STAGE4_QA_SYSROOT`. A native AArch64
   endpoint has no emulator and no cross sysroot. The endpoint preparation
   path already takes `qemu_input` as an `Option` and `Hx` passes `None`, so
   the internal shape supports it; the environment contract does not.

4. **The cell catalog and claim mapping are fixed.** `STAGE4_CELL_CATALOG` and
   the `Stage4ClaimId` enum in `model.rs` enumerate cells and the two existing
   claim ids. New endpoints mean new cells, and new cells have to be attributed
   to a claim.

5. **The host receipt is a single uname reading.** The aggregate retains raw
   stdout/stderr from `/usr/bin/uname -s -r -m` for one host. A run split
   across an x86-64 machine and an ARM machine has two hosts and no current
   place to record the second, or to bind the two halves together.

Point 5 is the deepest one. The existing design assumes a single host running
every endpoint, which is exactly what emulation buys. Real hardware either
requires two machines and a cross-machine evidence-joining story, or an
aarch64-only run that drops the `Hx`/`Qx` endpoints and therefore cannot
regress `named-target-substrate-continuity-v1`.

## Hardware and OS requirements

For an aarch64-native endpoint, whichever topology is chosen:

- aarch64 Linux, little-endian, LP64, glibc — `require_named_target` demands
  `os == "linux"`, `abi == "linux-gnu"`, `endianness == "little"`, and
  `pointer_width_bits == 64`. A musl or 32-bit userland does not qualify.
- Wasmtime must support the host. The Stage 4 worker is the Wasmtime worker;
  its aarch64 backend is the thing actually under test.
- `/usr/bin/uname` present at that exact path, since the host receipt executes
  it by absolute path.
- Enough disk under the evidence parent for two copies of the artifact root,
  because the relocation check moves rather than links. `VISA_EVIDENCE_PARENT`
  redirects this off the Cargo target directory.
- The Rust toolchain pinned by `rust-toolchain.toml`
  (`nightly-2026-06-07`), available for the host architecture.
- If the ARM machine also builds x86-64 artifacts, a reverse cross-toolchain;
  otherwise builds happen on the x86-64 side and binaries are transported.

Note that `.cargo/config.toml` already sets
`[target.aarch64-unknown-linux-gnu] linker = "aarch64-linux-gnu-gcc"`. On a
native aarch64 host that setting is wrong — the native `cc` should be used —
so a native build needs that entry overridden rather than inherited.

## Claim and registry changes

`claims/registry.json` has `schema`, `claims`, and `workflow_bindings`. A claim
entry carries exactly `id`, `track`, `status`, `scope_ref`, `validation_ref`,
`acceptance_ref`, `implementation_refs`, and `predecessor_ids`. The current
entry is:

```json
{
  "id": "emulated-cross-isa-continuity-v1",
  "track": "roadmap",
  "status": "earned",
  "scope_ref": {
    "path": "docs/ROADMAP.md",
    "heading": "Stage 4: Target, ISA, and substrate qualification"
  },
  "validation_ref": {
    "path": "docs/VALIDATION.md",
    "heading": "Claim-evidence matrix"
  },
  "acceptance_ref": {
    "kind": "canonical-validation",
    "path": "docs/VALIDATION.md",
    "heading": "Claim-evidence matrix"
  },
  "implementation_refs": [
    "crates/testing/visa-conformance/src/stage4/model.rs",
    "crates/testing/visa-conformance/src/stage4/verify.rs"
  ],
  "predecessor_ids": []
}
```

and it is bound to CI by:

```json
{
  "id": "stage4",
  "job": "docker-stage4-gate",
  "matrix_lane": null,
  "tier": "system-stage4",
  "artifact": "stage4-target-isa-system-evidence",
  "claims": [
    { "id": "emulated-cross-isa-continuity-v1", "role": "regresses" },
    { "id": "named-target-substrate-continuity-v1", "role": "regresses" }
  ]
}
```

### A new claim id is required

Real-hardware evidence must not be published under
`emulated-cross-isa-continuity-v1`. The word "emulated" is load-bearing: the id
names the boundary, the README exclusion list is written against it, and its
`acceptance_ref` points at a canonical validation heading describing a
seven-cell emulated matrix. Widening it in place would silently restate an
accepted claim, which is precisely what the registry gates exist to prevent.

The successor should be a new id — `native-arm-cross-isa-continuity-v1` is the
naming that matches existing convention (`^[a-z0-9][a-z0-9.-]*$`, a `-v1`
suffix, hyphenated words) — with
`predecessor_ids: ["emulated-cross-isa-continuity-v1"]`.

Constraints a new id must satisfy, from `scripts/claims_registry.py`,
`scripts/check-claims-registry.py`, and `scripts/check-claim-closures.py`:

- `status` is one of `candidate`, `earned`, `retired`. It starts as
  `candidate`. `GRANDFATHERED_EARNED_CLAIMS` is a closed set of eight existing
  ids; a new id is not in it and therefore cannot be declared `earned` without
  going through the full closure path.
- Reaching `earned` requires a committed closure record, a receipt under
  `claims/receipts`, and, for archive-kind acceptance, an archive manifest
  under `claims/archive-manifests` with `receipt_sha256`, `evidence_axes`,
  `semantic_contracts`, `source_repositories`, and `workflow_artifacts`.
- `scope_ref`, `validation_ref`, and `acceptance_ref` must resolve to headings
  that actually exist in the named documents, so ROADMAP and VALIDATION need
  the corresponding sections written first.
- The README claim table between the `<!-- claims-registry:start -->` and
  `<!-- claims-registry:end -->` markers is checked row-by-row against the
  registry and must be regenerated.

### Code-side id registration

The claim id is not only registry data. It also appears as a Rust enum variant
in `crates/testing/visa-conformance/src/stage4/model.rs`
(`Stage4ClaimId::EmulatedCrossIsaContinuityV1`) and in the allowlist in
`scripts/claims_registry.py`. A new claim id has to be added in all three
places, and the new cells attributed to it in `STAGE4_CELL_CATALOG`.

### CI contract

`.github/workflows/ci.yml` and `scripts/ci-gate.sh` are pinned by
`scripts/check-ci-contract.py`, which asserts specific job names, tiers, and
`run-docker-ci-gate.sh --ci-cache --skip-build <tier>` command strings, and by
`scripts/test-check-ci-contract.py`. A new hardware tier means a new binding
entry plus matching contract-checker updates. Since GitHub-hosted runners for
this project's Docker gate are x86-64, a real-hardware lane needs either a
self-hosted aarch64 runner or an explicitly out-of-CI, manually attested
evidence path — and the latter is a weaker form of evidence than every claim
currently in the registry, which should be stated plainly wherever it lands.

## Step-by-step checklist

Preparation, in dependency order. Steps 1-2 are done; the rest are not.

1. **Cross-compilation smoke check.** `scripts/check-aarch64-cross.sh` runs
   `cargo check --target aarch64-unknown-linux-gnu` over the pure-logic subset
   of the active spine. This is a compile-time signal only.
2. **Record the blockers.** This document.
3. **Decide the topology.** Two-machine (keeps all 7 existing cells, needs a
   cross-machine evidence join) or aarch64-only (simpler, cannot regress
   `named-target-substrate-continuity-v1`). This decision drives everything
   below and should be made before any code is written.
4. **Extend the model.** Add the `Ha` endpoint to `Stage4EndpointId`, make the
   QEMU and sysroot environment inputs optional for native endpoints, and relax
   the orchestrator pin so the orchestrating endpoint is derived rather than
   hardcoded to `Hx`.
5. **Extend the host receipt.** Decide how a multi-host run records and binds
   more than one uname receipt, or document why the run is single-host.
6. **Extend the cell catalog** with the new cells and attribute them to the new
   claim id.
7. **Provision hardware** against the requirements above and confirm Wasmtime,
   the pinned toolchain, and `/usr/bin/uname` on it.
8. **Trial run, unpublished.** Produce a bundle, verify it with the
   independently built `visa-conformance`, and repeat after relocation. Do not
   register a claim from a trial run.
9. **Write the canonical sections** in `docs/ROADMAP.md` and
   `docs/VALIDATION.md` that the new claim's refs will point at.
10. **Register the claim as `candidate`**, regenerate the README table, and get
    `check-claims-registry.py` green.
11. **Wire CI or document the manual path**, updating `check-ci-contract.py`
    and its mutation tests as required.
12. **Close the claim** with a receipt and closure record only after the
    evidence has passed at an exact commit, matching how the existing Stage 4
    closure receipt was recorded.

## Appendix: `cargo tree` panics in this workspace

### Symptom

Plain `cargo tree` aborts:

```
thread 'main' panicked at src/tools/cargo/src/cargo/core/resolver/features.rs:325:13:
did not find features for (PackageId { name: "contract_validate", version: "0.1.0",
source: "/home/ava/Desktop/vISA/crates/core/contract_validate" },
ArtifactDep(Tuple("x86_64-unknown-none"))) within activated_features
```

Reproduced on the pinned toolchain, cargo 1.98.0-nightly (0b1123a48 2026-06-01).

### Cause

This is a cargo resolver bug in the unstable artifact-dependencies
(`bindeps`) feature, which `.cargo/config.toml` enables workspace-wide with
`[unstable] bindeps = true`.

The triggering path is:

- `crates/host/runner/Cargo.toml` has a build-dependency
  `kernel = { path = "../kernel", artifact = "bin", target = "x86_64-unknown-none" }`
- `crates/host/kernel/Cargo.toml` has `contract_validate.workspace = true`
  under `[build-dependencies]`

So `contract_validate` is reached as a build-dependency of a package that is
itself resolved as an artifact dependency for `x86_64-unknown-none`. The
resolver fails to register features for that `(package, ArtifactDep)` pair and
panics instead of erroring.

The `x86_64-unknown-none` bin artifact is not the only trigger. All four
artifact-dependency manifests in the workspace reproduce a panic of the same
shape, and in every case the artifact dependency sits under
`[build-dependencies]`:

| Manifest | Artifact dependency | Panicking `(package, ArtifactDep)` |
| --- | --- | --- |
| `crates/host/runner` | `kernel`, `bin`, `x86_64-unknown-none` | `contract_validate`, `x86_64-unknown-none` |
| `crates/testing/visa-system` | `handoff-component`, `cdylib`, `wasm32-unknown-unknown` | `wit-bindgen-rust-macro`, `wasm32-unknown-unknown` |
| `crates/testing/visa-stage3-system` | `stage3-file-component`, `stage3-request-component` | same shape |
| `crates/testing/visa-joint-handoff-system` | `stage3-request-component` | same shape |

### Impact

Measured on this workspace:

| Command | Result |
| --- | --- |
| `cargo tree` | panics |
| `cargo tree --workspace` | panics |
| `cargo tree --workspace --exclude runner` | panics |
| `cargo tree --workspace --exclude runner --exclude kernel` | panics |
| `cargo tree --workspace --target x86_64-unknown-linux-gnu` | panics |
| `cargo tree --workspace --no-dedupe` | panics |
| `cargo tree -e build --workspace` | panics |
| `cargo tree -e normal,build --workspace` | panics |
| `cargo tree -p runner` | panics |
| `cargo tree -p visa-system` | panics |
| `cargo tree -p visa-stage3-system` | panics |
| `cargo tree -p visa-joint-handoff-system` | panics |
| `cargo tree -e normal --workspace` | **works** (997 lines) |
| `cargo tree -p <any other package>` | **works**, including `kernel`, `contract_validate`, `visa-conformance`, `visa-cli` |
| `cargo tree -e normal -p runner` | **works** |
| `cargo tree -e normal -p visa-system` | **works** |
| `cargo metadata --locked --format-version 1` | **works** |
| `cargo metadata --locked --no-deps --format-version 1` | **works** |

`--exclude` does not help, because the panic happens during whole-workspace
feature resolution, before package filtering. Disabling bindeps via
`CARGO_UNSTABLE_BINDEPS=false` also does not help, since the manifests still
declare artifact dependencies.

Because `cargo metadata` resolves the full graph without panicking, tools built
on it are not blocked by this. `cargo-deny` reads `cargo metadata` and should
work; `cargo-audit` reads `Cargo.lock` directly and should also work. Neither
is installed in this environment, so that is an inference from their input
format, not a measured result. `scripts/ci-gate.sh` uses `cargo metadata`
and is unaffected.

### Workaround

Every artifact dependency in this workspace is declared under
`[build-dependencies]`, so dropping build edges avoids the resolver path
entirely:

```
cargo tree -e normal --workspace
```

This is a real reduction — build-dependencies and dev-dependencies are not
shown. For build-dependency questions, query a single package that is not one
of the four listed above; per-package queries retain all edge kinds and do not
panic:

```
cargo tree -p kernel
```

For the four artifact-dependency packages themselves, only the `-e normal`
form works.

### Disposition

No workspace change is proposed. Removing the panic would mean dropping the
`x86_64-unknown-none` bin artifact dependency from `runner`, which is load-
bearing for the kernel build, or dropping `contract_validate` from the kernel's
build-dependencies, which is load-bearing for contract validation. Both are
worse than losing full-graph `cargo tree`. The item to track is the upstream
cargo bug; a future toolchain bump should re-test plain `cargo tree` and this
appendix should be updated or deleted when it stops reproducing.
