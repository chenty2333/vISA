# vISA Validation

Status: current validation truth and target validation contract.

Implementation status: the current automation covers only a subset of this
contract.

Last reviewed: 2026-07-11.

This document defines what each result proves and the acceptance boundary for
the first architecture-complete slice. Update it when executable gates change.

## Validation principle

Passing a test proves only what it exercised. A public claim must name the
environment, resource profile, authority boundary, and faults covered.

Compilation does not prove runtime behavior, schema validation does not prove
the reported execution occurred, and one hardware/runtime cell does not prove
another. A successful restore alone does not prove failure atomicity or source
fencing.

Validation follows public runtime and adapter boundaries. Deterministic fault
controls are allowed, but architecture claims cannot rely only on mocks, fake
providers, hand-written reports, or direct canonical-state mutation.

## Current automated gates

GitHub Actions currently runs one Docker-based job on pushes and pull requests.
It validates the Compose configuration, builds the development image, and runs
the gates in `scripts/ci-gate.sh`. The supported local wrapper is documented in
[DEVELOPMENT.md](DEVELOPMENT.md).

| Gate | Current operation | What a pass establishes |
| --- | --- | --- |
| `metadata` | `cargo metadata --no-deps` | Cargo can resolve workspace metadata. |
| `fmt` | `cargo fmt --all --check` | Workspace Rust source satisfies rustfmt. |
| `check-wasm` | `cargo check-wasm` | The selected service, driver, Linux, network, snapshot, VFS, and Wasm application packages type-check for `wasm32-unknown-unknown`. |
| `visa-conformance` | Tests the `visa-conformance` crate, then runs `validate-sample` | The conformance validator's tests pass and the checked-in catalog/sample reports satisfy its current format and minimum-matrix rules. |
| `kernel` | Checks the `kernel` package for `x86_64-unknown-none` | The kernel package type-checks for that target. |

The currently implemented local entry point is `scripts/run-docker-ci-gate.sh`;
it accepts the gate names above. The tiers below are a target organization,
not additional implemented command names.

### Current limitations

The standard CI job does not currently run:

- Clippy;
- a full workspace `cargo check` or `cargo test`;
- all core, runtime, adapter, and integration tests;
- an end-to-end handoff with real timer/KV adapters, destination
  reauthorization, source fencing, and lifecycle fault injection;
- the target multi-dimensional claim/evidence matrix: the current conformance
  report reduces execution strength to one ordered `Boundary`, so it cannot yet
  independently enforce runtime, ISA, substrate, resource, authority, fault,
  and provenance coverage;
- QEMU boot/runtime behavior beyond compiling the kernel target;
- two independent WebAssembly runtime implementations;
- a cross-ISA execution matrix;
- release provenance/performance gates or long-running concurrency, recovery,
  and security testing.

A green CI result means only that these repository checks passed. It does not
establish continuity, migration, heterogeneity, or production safety.

## Target validation tiers

Until a consolidated developer interface is implemented, these tiers define
coverage rather than shell commands.

### Fast

The fast tier is the ordinary edit loop: formatting, linting, metadata, focused
contract/reducer/coordinator and deterministic state-machine tests, plus
dependency-direction checks. It proves local logic and structural invariants,
not adapter or continuity behavior.

### Full

The full tier is the pull-request integration gate: all applicable workspace
tests, Clippy, feature combinations, host/`no_std`/Wasm/kernel checks,
compatibility round trips, and coordinator-adapter integration. It proves
repository consistency, not a live handoff or heterogeneous claim.

### System

The system tier executes public component/runtime/coordinator/provider paths
using isolated source and destination instances, fresh bindings, real resource
adapters, lifecycle faults, and durable evidence. Runtime behavior on QEMU or
another reference substrate belongs here. This is the minimum basis for a
state-continuity claim.

### Release

The release tier reruns system scenarios in declared runtime/ISA/substrate
cells with pinned inputs and provenance, then adds stress, recovery,
compatibility, performance, and artifact-integrity checks. Evidence must be
tied to source, toolchain, component, profile, configuration, and result
digests.

### Claim gates

A claim gate selects the exact tier evidence for one advertised statement. If
a matrix cell or fault boundary is absent, narrow the claim rather than infer
it from nearby results.

For example, “handoff works between two isolated Wasmtime processes on
x86-64 with the host timer/KV profile” is a different claim from “handoff works
between Wasmtime and WasmEdge” or “handoff works from x86-64 to AArch64.”

## Claim-evidence matrix

Every evidence record must identify these independent dimensions:

```text
compute-state carrier
  x source and destination runtime implementations/versions
  x source and destination host ISAs
  x substrates and providers
  x resource and continuity profiles
  x authority enforcement and lease service
  x lifecycle transitions and injected faults
  x artifact, build, configuration, and run provenance
```

The matrix is additive. Evidence in one row cannot silently fill another row.

| Claim | Minimum executable evidence | Explicitly not implied |
| --- | --- | --- |
| Report/schema validity | Parser/validator tests plus artifact digests | Runtime execution or real enforcement |
| Canonical transition correctness | Reducer model/property tests, rejection state digests, and journal replay | Substrate effect correctness |
| Single-runtime handoff | Isolated source/destination processes, fresh bindings, real profiled providers, reauthorization, commit/fencing, and lifecycle faults | A second runtime or ISA |
| Cross-runtime continuity | The same accepted workload and normalized semantic trace on each named runtime path, including a handoff between them | Cross-ISA behavior |
| Cross-ISA continuity | The same accepted workload across each named source/destination ISA pair with identified carrier and providers | Other runtimes or resources |
| Authority safety | Real policy enforcement, attenuation/revocation cases, stale-generation attempts, and post-commit source writes | General sandbox security |
| Crash-safe handoff | Durable journal/commit records and faults at every lifecycle transition | Arbitrary external-effect atomicity |
| Production readiness | Defined reliability, security, operability, compatibility, and performance criteria over representative workloads | Established by any current gate |

### Samples and fixtures

Checked-in sample reports are useful for parser regression, documentation, and
format compatibility. They are not executable evidence merely because their
hashes and fields validate.

An executable evidence bundle must be produced by the run it describes and
contain, or securely reference:

- the component and profile digests;
- source and destination runtime/ISA/substrate identities;
- normalized committed semantic trace and state digests;
- snapshot digest and resource-binding receipts;
- authority decision, lease epoch, and fencing results;
- declared fault schedule and observed recovery outcome; and
- toolchain, source revision, configuration, timestamps, and exit status.

The validator must reject overclaims, but validator acceptance alone never
upgrades a fixture into proof of the underlying execution.

## First architecture-complete capability slice

The first slice is **Cooperative Stateful Component Handoff** using one logical
timer and one durable key-value namespace.

It is called a slice because it takes one narrow workload vertically through
the intended complete architecture: component request, canonical reducer,
runtime coordinator, real effects, safe point, snapshot, destination
reauthorization, fresh bindings, handoff commit, source fencing, resume, and
evidence. It is not a temporary miniature architecture or a collection of
independent horizontal demos.

### Workload and resource profile

The component owns a portable work/session identity and a pending logical timer.
It has only the rights needed to read/conditionally update one durable KV
namespace and arm/cancel that timer.

The source records a baseline value and arms the timer. At freeze, the Stage 1
profile records its remaining duration rather than a host-monotonic timestamp.
The duration is paused during handoff; after commit, the destination rebinds the
same namespace and starts a fresh monotonic wait for that duration. On expiry,
one canonical operation conditionally updates the value. Operation identity,
an idempotency key, and a fencing epoch protect the effect; universal
exactly-once is not claimed. This profile does not preserve a wall-clock
deadline.

The system test uses two isolated runtime instances, fresh bindings, and real
timer/KV provider behavior. Fakes are allowed in unit tests but cannot satisfy
this claim. Other runtimes and ISAs require additional matrix cells.

### Required successful path

1. Activate the source with recorded authority derivation, generation, and lease epoch.
2. Execute the baseline KV operation and arm the timer through public ports.
3. Request an explicit safe point and stop admitting new effects.
4. Return borrows and classify every in-flight operation under its profile.
5. Export committed state, claims, and journal position without native handles or credentials.
6. Validate identity, integrity, extensions, and compatibility before destination execution.
7. Reauthorize sufficient non-amplified rights; create fresh bindings and receipts.
8. Prepare the destination without making it active.
9. Commit a new lease/fencing epoch, disable the source, and activate the destination.
10. Deliver the profiled timer, update KV conditionally, clean up, and derive evidence.

### Acceptance matrix

| Case | Required outcome |
| --- | --- |
| Positive timer duration at freeze | Destination recreates the timer from the recorded remaining duration; one canonical expiry outcome is observed. |
| Handoff lasts longer than the remaining duration | The paused-duration profile does not expire while frozen; countdown resumes only after destination commit. |
| Timer completes during quiescence before freeze | Its committed outcome is included; restore does not recreate a live duplicate. |
| Timer is cancelled during quiescence | Cancellation is committed and cleanup is idempotent; restore does not recreate the timer. |
| Sufficient narrower authority | Restore succeeds with only the required rights exposed. |
| Duplicate idempotent KV request | The same operation/idempotency identity cannot apply the externally visible update twice. |
| Repeated snapshot validation/prepare | Operations are idempotent and do not activate a second owner. |
| Journal replay | Replaying committed entries produces the same canonical state digest. |
| Post-commit stale source attempt | The KV/provider boundary rejects the old generation or lease epoch. |
| Evidence verification | Trace, snapshot, receipts, fault record, provenance, and final state agree by identity and digest. |
| Performance observations | Raw steady-state cost, snapshot size, and handoff interruption measurements are recorded without converting them into an unearned performance claim. |

### Failure and recovery matrix

| Injection or condition | Required behavior |
| --- | --- |
| Component cannot reach the safe point | Handoff times out or rejects explicitly; source ownership is unchanged. |
| Live unsupported resource or borrowed handle | Freeze rejects without exporting a handoff-ready snapshot. |
| KV effect has an unknown outcome | Reconcile by operation identity, or block handoff as indeterminate; never assume failure. |
| Corrupt snapshot or wrong component digest | Reject before bindings or component execution; canonical source state is unchanged. |
| Incompatible snapshot or component-profile version | Reject before bindings or component execution; do not guess a downgrade. |
| Unknown required extension/profile mismatch | Reject destination preparation without downgrade. |
| Missing or insufficient destination authority | Reject before execution; snapshot data grants no rights. |
| Required capability was revoked | Reject rebinding and prevent the snapshot from resurrecting the old authority. |
| Adapter returns broader authority | Attenuate to the authorized intersection or reject; never expose the excess. |
| Wrong/missing KV namespace binding | Reject preparation; do not substitute another namespace. |
| Timer deadline semantics unsupported | Reject preparation rather than silently changing clock behavior. |
| Destination crash before commit | Abort or retry preparation; source may continue under the old epoch. |
| Duplicate/lost prepare message | Preparation remains inactive and idempotent. |
| Lost commit acknowledgement | Durable commit/fencing truth selects one owner; both sides must not self-activate. |
| Source action racing with commit | Exactly one valid lease epoch reaches the provider after commit. |
| Destination crash after commit | Source remains fenced; only explicit destination recovery may continue. |
| Duplicate restore or stale snapshot replay | Generation, snapshot identity, and epoch checks prevent duplicate activation or authority resurrection. |
| Repeated cancel/abort/cleanup | Cleanup is idempotent and cannot repeat a destructive effect or resurrect a resource. |
| Durable journal/commit write fails | Do not report commit; follow the explicit pre-commit abort or indeterminate protocol. |
| Report generation fails after commit | Committed truth remains authoritative; regenerate evidence without changing state. |

Each rejected transition must leave its preflight state digest unchanged or
commit only a contract-defined diagnostic; independently completed operations
remain valid. No destination may be active after a pre-commit failure. After a
post-commit fault, the old source epoch must remain unusable.

The slice is complete only when these cases are automated, produce verifiable
artifacts, and run through one canonical model and one coordinator path. Code
coverage, scenario count, or a manually assembled report cannot substitute for
the matrix.

## Claims this slice does not prove

Even after the baseline slice passes, it does not prove:

- transparent migration of arbitrary native processes or unmodified Wasm;
- arbitrary descriptor, socket, device, or non-idempotent-effect preservation;
- universal exactly-once delivery or physical atomicity with external systems;
- cross-runtime or cross-ISA continuity until those exact cells execute;
- correctness of a complete Linux personality, kernel, Virtio, filesystem, or
  network stack;
- TEE attestation, KMS correctness, or general confidential-computing safety;
- production availability, security, scalability, or performance;
- compatibility with unspecified future schema/profile versions; or
- validated product demand.

Claims may expand only by adding executable matrix cells and keeping their
remaining uncertainty visible.
