# vISA Validation

Status: current validation truth and target validation contract.

Implementation status: `fast`, `full`, the two legacy same-path system cells,
the four-cell legacy v2 cross-execution-path matrix, and the separate four-cell
strict v3 Wasmtime/Wacogo matrix are automated. All current system cells use
x86-64/amd64 Linux and the timer/KV profile. File/network, cross-ISA,
confidential, release, and production validation remain outside the implemented
boundary.

Last reviewed: 2026-07-13.

This document defines what each result proves and the acceptance boundaries for
the first architecture-complete slice, the legacy Stage 2 execution-path
matrix, and the strict Stage 2 runtime matrix. Update it when executable gates
change.

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

GitHub Actions runs one Docker-based job on pushes and pull requests. It
validates the Compose configuration, builds the development image, then runs
the same `full`, `system`, `system-jco-node`, `system-stage2`, and
`system-stage2-strict` tier implementations exposed locally by
`scripts/run-docker-ci-gate.sh`. Each system step uploads its retained artifact
directory, including partial artifacts after a failure when any exist. The
strict wrapper additionally retains its Docker log, exit receipt, sidecar, and
build receipt. Current workflow artifacts use a 14-day retention period.

| Tier | Current operation | What a pass establishes |
| --- | --- | --- |
| `fast` | Locked metadata, formatting, strict active-spine dependency direction, the Stage 1 deletion/oracle-boundary audit, first-party Rust file-size maintenance, locked JcoNode Cargo/source/Node/V8 identity, strict active-spine Clippy, and active-spine tests | The selected contract, reducer, port, coordinator, adapters, profile, and evidence packages satisfy their local logic and structural edit-loop gates. |
| `full` | Everything in `fast`, shell parsing, default-feature workspace tests, current opt-in feature tests, active no-std check, selected Wasm check, kernel target check, benchmark compilation, and report/artifact fixture gates | The checked repository builds and tests across its declared compile targets and current fixture contracts. It does not prove a live handoff. |
| `system` | All 31 registered Stage 1 lifecycle and fault cases through isolated source/destination workers, followed by independent validation of the produced execution bundle | The named single-runtime reference cell satisfies the Stage 1 workload, resource, authority, recovery, fencing, and evidence contract. It does not repeat `full` or prove another runtime or ISA. |
| `system-jco-node` | The same 31 registered cases with JcoNode explicitly selected at source and destination, followed by independent Stage 1 validation | The pinned Jco/Node/V8 translated execution cell satisfies the Stage 1 contract without a Wasmtime execution fallback. It does not prove a fully independent Component Model implementation. |
| `system-stage2` | All four Wasmtime/JcoNode source-destination pairs, 31 cases per pair, four inner Stage 1 validations, and independent outer Stage 2 validation | The same portable state and normalized observable behavior pass in all four declared execution-path cells (124 executions). It does not prove strict runtime independence or cross-ISA portability. |
| `system-stage2-strict` | Locked Wacogo qualification and reproducible build, focused lifecycle gates, a Wacogo same-path Stage 1 cell, then the exact four Wasmtime/Wacogo cells with 31 cases per cell, four inner validations, and independent strict v3 outer validation | The fixed Component preserves the accepted timer/KV behavior across two independently implemented Component Model runtime lineages in all four directions (124/124 executions and 31/31 equality groups). It establishes only `strict-cross-runtime-continuity` on x86-64 Linux, not another ISA or resource profile. |

The named `system` reference cell uses the vISA Wasmtime adapter for both isolated
runtime processes on x86-64 Linux, host-process isolation, and a durable,
non-mock SQLite timer/KV provider. A `system` pass establishes only that cell.
The JcoNode cells run generated core WebAssembly in Node 24.15.0/V8
13.6.233.17-node.48 while disclosing the shared `wasmtime-environ` translator
lineage. This is why the legacy v2 Stage 2 gate is named cross-execution-path
rather than strict cross-runtime evidence.

The strict v3 cells pair the Wasmtime lineage with the source-lock-bound
`partite-ai/wacogo v0.0.0-20260617023329-3de16a61796c + vISA downstream patchset
v1` lineage, whose Component parser, validation, linking, Canonical ABI, and
instantiation do not derive from Wasmtime and whose core execution engine is
wazero. The selected derivative is qualified; unmodified upstream wacogo is not
reported as passing.

The strict dependency check protects the active production spine and rejects
dependencies that point against the accepted architecture. Comparison-oracle
packages such as `contract_validate` and the pre-reset models remain compiled by
`full`, but they are not production-spine truth and cannot enter that graph.

### Current limitations

The standard CI job does not currently run:

- workspace-wide Clippy outside the protected active spine;
- dependency-license, advisory, and duplicate-version policy; no supported
  `cargo deny` gate or reconciled policy is currently installed;
- QEMU boot/runtime behavior beyond compiling the kernel target;
- file or network continuity profiles;
- a cross-ISA execution matrix;
- TEE, attestation, KMS, or confidential-continuity integration;
- release provenance/performance gates or long-running concurrency, recovery,
  and security testing.

A green CI result establishes the repository checks, both legacy named
same-path cells, normalized behavior across the four declared Wasmtime/JcoNode
directions, and the separate source-lock-bound Wasmtime/Wacogo strict matrix.
The legacy v2 evidence establishes `cross-execution-path-portability`; strict
v3 establishes `strict-cross-runtime-continuity`. Both claims are limited to
the fixed x86-64 Linux timer/KV profile. Neither establishes cross-ISA or
additional-resource continuity, confidential continuity, transparent
migration, release quality, or production safety.

## Validation tiers

`fast`, `full`, `system`, `system-jco-node`, `system-stage2`, and
`system-stage2-strict` are implemented shell commands. `release` and later
claim gates below remain acceptance contracts until their exact matrix runners
exist.

### Fast

The fast tier is the ordinary edit loop: formatting, locked metadata, strict
linting and focused tests for the active spine, plus strict dependency direction.
It proves local logic and structural direction, not adapter or continuity
behavior.

### Full

The full tier is the pull-request integration gate. It adds workspace tests,
declared opt-in feature tests, host/no-std/Wasm/kernel compilation, benchmark
compilation, and compatibility/report fixture checks. Clippy is intentionally
strict on the active spine rather than frozen later-stage code. A pass proves
repository consistency within those named targets, not a live handoff or a
heterogeneous claim.

### System

The system tier executes public component/runtime/coordinator/provider paths
using isolated source and destination worker processes, fresh bindings, real
timer/KV adapters, destination reauthorization, source fencing, and lifecycle
faults. It runs all 31 registered cases, retains the raw artifacts and execution
bundle, then invokes an independent verifier over their identities, digests,
typed traces, receipts, faults, authority evidence, and provenance. It is
standalone and does not repeat `full`. This is the basis for the named
single-runtime reference-cell claim, not a broader continuity claim.

### Stage 2 system cells

`system-jco-node` executes the unchanged Stage 1 registry with JcoNode selected
for both workers and validates its ordinary Stage 1 bundle in a separate
process. `system-stage2` runs Wasmtime-to-Wasmtime, JcoNode-to-JcoNode, and both
mixed directions from one common input, then independently verifies all four
inner bundles and the normalized legacy v2 outer evidence. Both are standalone
gates; the matrix does not substitute for `full`, and neither result is
cross-ISA or strict independent-Component-Model evidence.

`system-stage2-strict` is a separate v3 path. It first verifies the official Go
1.26.5 linux/amd64 toolchain, exact Wacogo source lock and module zip, fixed
146,486-byte Component, seven selected-runtime qualification gates, and two
byte-identical 6,754,430-byte sidecar builds. Focused sidecar and real-runtime
tests precede a Wacogo-to-Wacogo Stage 1 run. The outer matrix then selects
exactly these cells in this order:

```text
wasmtime-to-wasmtime
wacogo-to-wacogo
wasmtime-to-wacogo
wacogo-to-wasmtime
```

Each cell runs the unchanged 31-case registry from one common input. The writer
and a separate verifier both require four complete inner validations, 124/124
executions, 31/31 normalized-v1 equality groups, exact requested -> prepared ->
live runtime identity chains, complete Wasmtime and Wacogo implementation
lineage, and no fallback. JcoNode is deliberately absent from strict v3 and
remains available through legacy v2.

The common input is immutable for each whole matrix and binds the original
Component, WIT world, profile, configuration, policy, case registry, fault
schedules, and schema/codec identities. Every cell uses fresh workers, runtime
instances, provider storage, and native handles. The outer verifier first
completes the full Stage 1 validation of every inner bundle, then independently
recomputes a versioned typed normalization and compares all 31 four-cell groups.
Runtime identity, translation provenance, cell completeness, and no-fallback
facts are checked exactly outside normalization. A normalization version may
exclude only its declared non-portable observations; it cannot expand its
exclusions to conceal a behavioral difference or malformed inner evidence.

### Stable artifact verification boundary

The Linux verifier opens each Stage 1 artifact root once as a directory
capability. Referenced files are opened relative to that descriptor with
`openat2`, `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`,
`RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_XDEV`; the opened descriptor must be a
regular file. FIFO, socket, device, symlinked, magic-linked, escaping,
mount-crossing, oversized, and concurrently unresolvable inputs fail closed.
Platforms without this secure reader do not fall back to pathname prechecks.

Each unique referenced artifact is opened and consumed once during capture.
Its reference digest and typed/semantic validation consume the same captured
bytes, and Stage 2 inner transcript, normalization, and cross-cell checks reuse
that stable Stage 1 view. Large digest-only provenance such as the executed
binary is streamed once instead of being retained. This closes the verifier's
pathname check/open and hash/semantic split-view windows. A contained regular
file replacement that
wins before `open` is accepted only when the same captured bytes satisfy the
declared digest and semantic checks; replacement cannot redirect resolution
outside the root or make a passing result bind one digest to different
semantic bytes.

This is an artifact-content guarantee, not a complete hostile-co-tenant
boundary. A same-UID process may still attempt denial of service or, where OS
policy permits, attack verifier memory/process state. Stage 2 publication-marker
and directory-topology checks remain part of the controlled single-publisher
workflow.

JcoNode separately closes its generated-artifact load window with the
`owned-bytes-stdin-frame-v1` execution carrier. Preflight owns the exact
generated JavaScript and core-Wasm bytes; the prepared manifest, graph digest,
Node preflight, startup frame, and executed modules all derive from that one
captured graph. The Node driver is compiled into the Rust adapter, receives the
bounded versioned frame over stdin, verifies every file and the complete graph
before import, loads JavaScript through a data URL, and compiles core modules
from memory. It never reopens the publisher tree. Worker transcripts and Stage
2 evidence name the exact carrier version, and the independent verifier rejects
missing or different carrier provenance. Hostile replacement of the old files,
directories, symlinks, or publication root therefore cannot substitute code;
unsupported translator output fails closed. The trusted Node executable and
its execution environment, loader, shared libraries, and toolchain remain
trusted inputs. Ptrace, process-memory, takeover, and denial-of-service
boundaries are likewise explicitly outside this claim. Current evidence uses
worker protocol v3 and Stage 1 evidence v0.4. Legacy Wasmtime/JcoNode outer
evidence remains v2, while the separate Wasmtime/Wacogo strict outer evidence
is v3; the two parsers reject mixed or unknown schemas, and older bundles do not
inherit either newer claim boundary.

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
| Cross-execution-path portability | The unchanged input and 31-case registry in all four Wasmtime/JcoNode directions, four complete inner validations, one normalized outer comparison, disclosed translator lineage, and no execution fallback | Independent Component Model implementations or cross-ISA behavior |
| Strict cross-runtime continuity | The fixed Component and timer/KV profile in all four Wasmtime/source-lock-bound-Wacogo directions, complete inner validation, exact runtime/build lineage and no-fallback proof, and equality across all 31 normalized groups | Cross-ISA behavior, additional resources, or support by unmodified upstream Wacogo |
| Cross-ISA continuity | The same accepted workload across each named source/destination ISA pair with identified carrier and providers | Other runtimes or resources |
| Authority safety | Real policy enforcement, attenuation/revocation cases, stale-generation attempts, and post-commit source writes | General sandbox security |
| Crash-safe handoff | Durable journal/commit records and faults at every lifecycle transition | Arbitrary external-effect atomicity |
| Production readiness | Defined reliability, security, operability, compatibility, and performance criteria over representative workloads | No current gate establishes this claim |

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

Implementation status: complete for the named reference cell above. All 31
registered cases executed and the resulting evidence bundle passed independent
validation.

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

The Stage 1 system test uses two isolated runtime instances, fresh bindings,
and real timer/KV provider behavior. Fakes are allowed in unit tests but cannot
satisfy this claim. Stage 2c separately adds the Jco-translated execution path,
and strict v3 separately adds the source-lock-bound Wacogo runtime path. Every
additional ISA or resource profile still requires its own matrix cells.

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

The named reference cell meets this completion rule: these cases are automated,
produce verifiable execution artifacts, and run through one canonical model and
one coordinator path. Code coverage, scenario count, or a manually assembled
report cannot substitute for the matrix in any additional claimed cell.

## Claims this slice does not prove

Even after the baseline slice passes, it does not prove:

- transparent migration of arbitrary native processes or unmodified Wasm;
- arbitrary descriptor, socket, device, or non-idempotent-effect preservation;
- universal exactly-once delivery or physical atomicity with external systems;
- cross-ISA or broader runtime/resource continuity; legacy Stage 2c separately
  earns only `cross-execution-path-portability`, while strict v3 separately
  earns only `strict-cross-runtime-continuity` for the named Wasmtime/Wacogo
  x86-64 Linux timer/KV matrix;
- correctness of a complete Linux personality, kernel, Virtio, filesystem, or
  network stack;
- TEE attestation, KMS correctness, or general confidential-computing safety;
- production availability, security, scalability, or performance;
- protection against a compromised runtime execution environment or toolchain,
  ptrace or process-memory modification, process takeover, or denial of
  service;
- compatibility with unspecified future schema/profile versions; or
- validated product demand.

Claims may expand only by adding executable matrix cells and keeping their
remaining uncertainty visible.
