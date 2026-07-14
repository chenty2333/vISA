# vISA Validation

Status: current validation truth and target validation contract.

Implementation status: `fast`, `full`, the two legacy same-path system cells,
the four-cell legacy v2 cross-execution-path matrix, and the separate four-cell
strict v3 Wasmtime/Wacogo matrix are automated. The Stage 3A bounded
regular-file and Stage 3B bounded logical-request gates are also automated and
wired into CI, with an aggregate local command that runs both. A bounded Stage
4 aggregate now locally passes all seven native/QEMU-user target cells, 217/217
timer/KV executions, seven complete inner Stage 1 validations, 31/31 normalized
equality groups, independent outer verification, exact-set checks, and
byte-identical directory relocation. Its stage-closing exact-SHA pushed-CI
qualification is still pending, so Roadmap Stage 4 is not yet complete. Stage 1
and Stage 2 use the timer/KV profile; the two Stage 3 gates are separate
Wasmtime-to-Wasmtime resource profiles and do not inherit the Strict Stage 2
cross-runtime result. The Stage 4 matrix also holds Wasmtime and timer/KV fixed
and does not inherit that independent-runtime claim. Confidential, release,
performance, and production validation remain outside the implemented
boundary.

Last reviewed: 2026-07-14.

This document defines what each result proves and the acceptance boundaries for
the first architecture-complete slice, the legacy Stage 2 execution-path
matrix, the strict Stage 2 runtime matrix, and the two bounded Stage 3 resource
profiles, plus the locally verified bounded Stage 4 target/substrate and
emulated cross-ISA matrix. Update it when executable gates change.

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

GitHub Actions runs two parallel Docker-based jobs on pushes and pull requests.
The existing development job validates Compose, builds the image, and runs the
same `full`, `system`, `system-jco-node`, `system-stage2`,
`system-stage2-strict`, `system-stage3a`, and `system-stage3b` implementations
exposed locally by `scripts/run-docker-ci-gate.sh`. A separate Stage 4 job
builds the same development image, runs `system-stage4`, captures its log, and
uploads the complete or failed Stage 4 artifact parent. Each system step
uploads retained artifacts, including partial artifacts after a failure when
any exist. The strict wrapper additionally retains its Docker log, exit
receipt, sidecar, and build receipt. Current workflow artifacts use a 14-day
retention period. The local `system-stage3` command runs Stage 3A and Stage 3B
in sequence; CI runs them as separate uploadable steps. A Stage 4 roadmap
closure requires both parallel jobs and therefore the complete workflow to pass
at the same exact pushed SHA, not merely the Stage 4 job.

| Tier | Current operation | What a pass establishes |
| --- | --- | --- |
| `fast` | Locked metadata, formatting, strict active-spine dependency direction, the Stage 1 deletion/oracle-boundary audit, first-party Rust file-size maintenance, locked JcoNode Cargo/source/Node/V8 identity, strict active-spine Clippy, and active-spine tests | The selected contract, reducer, port, coordinator, adapters, profile, and evidence packages satisfy their local logic and structural edit-loop gates. |
| `full` | Everything in `fast`, shell parsing, default-feature workspace tests, current opt-in feature tests, active no-std check, selected Wasm check, kernel target check, benchmark compilation, and report/artifact fixture gates | The checked repository builds and tests across its declared compile targets and current fixture contracts. It does not prove a live handoff. |
| `system` | All 31 registered Stage 1 lifecycle and fault cases through isolated source/destination workers, followed by independent validation of the produced execution bundle | The named single-runtime reference cell satisfies the Stage 1 workload, resource, authority, recovery, fencing, and evidence contract. It does not repeat `full` or prove another runtime or ISA. |
| `system-jco-node` | The same 31 registered cases with JcoNode explicitly selected at source and destination, followed by independent Stage 1 validation | The pinned Jco/Node/V8 translated execution cell satisfies the Stage 1 contract without a Wasmtime execution fallback. It does not prove a fully independent Component Model implementation. |
| `system-stage2` | All four Wasmtime/JcoNode source-destination pairs, 31 cases per pair, four inner Stage 1 validations, and independent outer Stage 2 validation | The same portable state and normalized observable behavior pass in all four declared execution-path cells (124 executions). It does not prove strict runtime independence or cross-ISA portability. |
| `system-stage2-strict` | Locked Wacogo qualification and reproducible build, focused lifecycle gates, a Wacogo same-path Stage 1 cell, then the exact four Wasmtime/Wacogo cells with 31 cases per cell, four inner validations, and independent strict v3 outer validation | The fixed Component preserves the accepted timer/KV behavior across two independently implemented Component Model runtime lineages in all four directions (124/124 executions and 31/31 equality groups). It establishes only `strict-cross-runtime-continuity` on x86-64 Linux, not another ISA or resource profile. |
| `system-stage3a` | All 12 accepted bounded regular-file cases through separate source/destination Wasmtime stores, the shared coordinator/profile path, a real Linux regular-file provider, handoff, and independent Stage 3A bundle validation | The `bounded-regular-file-continuity` claim passes for the named Wasmtime-to-Wasmtime x86-64 Linux cell. It does not imply arbitrary directory trees, devices, FIFOs, already-open fds, atomic exclusion of writers outside the advisory lock/lease protocol, another runtime, or another ISA/substrate. |
| `system-stage3b` | All 14 accepted bounded logical-request cases through separate source/destination Wasmtime stores, a durable provider ledger, a real bounded loopback TCP protocol/peer, handoff, and independent Stage 3B bundle validation | The `bounded-logical-request-continuity` claim passes for the named Wasmtime-to-Wasmtime x86-64 Linux cell. It does not preserve arbitrary live TCP, socket sequence state, credential bytes, runtime future/stream state, or prove another runtime. |
| `system-stage3` | `system-stage3a` followed by `system-stage3b`, retaining one evidence root for each profile | Both bounded Stage 3 profile gates pass in one local invocation. This aggregate adds no cross-profile, cross-runtime, cross-ISA, or production claim. |
| `system-stage4` | Release x86-64 runner/worker/verifier and AArch64 worker builds; raw x86-64 Linux host observation; all seven Hx/Qx/Qa cells and 217 executions; seven inner Stage 1 validations; 31 independently recomputed normalized equality groups; exact artifact inventory; independent verification before and after a real directory rename | Locally establishes only `named-target-substrate-continuity-v1` for Hx/Qx and `emulated-cross-isa-continuity-v1` for Qx/Qa with Wasmtime and timer/KV fixed. Exact-SHA pushed-CI closure is pending. It does not establish real AArch64 hardware, a no-std/reference kernel, real devices, Stage 3 resources, another runtime, AOT binary portability, cross-host behavior, confidentiality, performance, or production readiness. |
| `system-stage4-target`, `system-stage4-isa` | Each invokes the same complete fail-closed `system-stage4` aggregate | These are edit-loop aliases, not reduced matrices or independent additional claims. |

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

The current CI workflow does not establish:

- workspace-wide Clippy outside the protected active spine;
- dependency-license, advisory, and duplicate-version policy; no supported
  `cargo deny` gate or reconciled policy is currently installed;
- QEMU full-system boot/runtime behavior beyond compiling the legacy kernel
  target; Stage 4 uses QEMU-user and explicitly does not qualify that kernel;
- a qualified second runtime for either Stage 3 resource profile;
- arbitrary directory-tree/device/FIFO/open-fd continuity or arbitrary live
  TCP, socket-state, future/stream, and general async-runtime continuity;
- a process-isolated Stage 3 worker protocol; the current gates use separate
  source/destination stores, coordinators, and provider instances backed by
  local SQLite continuity in one OS runner process;
- real AArch64 hardware, a second Stage 4 runtime, AOT binary portability,
  cross-host target continuity, 32-bit/big-endian targets, or Stage 3 resources
  across the Stage 4 endpoints;
- TEE, attestation, KMS, or confidential-continuity integration;
- release provenance/performance gates or long-running concurrency, recovery,
  and security testing.

A green complete-workflow result at one exact SHA establishes the repository
checks, both legacy named
same-path cells, normalized behavior across the four declared Wasmtime/JcoNode
directions, the separate source-lock-bound Wasmtime/Wacogo strict matrix, and
the two bounded Wasmtime-only Stage 3 resource gates, plus the bounded
native/QEMU-user Stage 4 matrix. The legacy v2 evidence
establishes `cross-execution-path-portability`; strict v3 establishes
`strict-cross-runtime-continuity`. Those Stage 2 claims remain limited to the
fixed x86-64 Linux timer/KV profile. Stage 3A and Stage 3B separately establish
only their named regular-file and logical-request profiles with
`independent_runtime_coverage=false` and Wacogo explicitly unsupported. Stage 4
separately establishes only its named target/substrate and emulated cross-ISA
timer/KV claims; it holds Wasmtime fixed and does not transfer the Strict Stage
2 runtime result or either Stage 3 resource result into those cells. No current
result establishes a second Stage 3/4 runtime, real target hardware or device
enforcement, cross-host or confidential continuity, transparent migration,
release quality, or production safety. Until the first pushed exact-SHA Stage 4
workflow passes, this paragraph describes the configured closure bar and local
evidence rather than a completed Roadmap Stage 4 claim.

## Validation tiers

`fast`, `full`, `system`, `system-jco-node`, `system-stage2`,
`system-stage2-strict`, `system-stage3a`, `system-stage3b`, and the
`system-stage3` aggregate, `system-stage4`, and its `system-stage4-target` and
`system-stage4-isa` aliases are implemented shell commands. `release` and later
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

### Stage 3 resource-profile cells

`system-stage3a` runs the fixed 12-case regular-file registry. It exercises
logical object identity, relative-path rebinding, logical offset, read/write,
append, truncate, rename and replacement detection, pre-operation detection of
identity/content/version drift, durability, advisory lock/reacquisition,
reauthorization, source fencing, indeterminate outcome blocking, and
idempotent cleanup. The Linux provider uses scoped `openat2` resolution and
revalidates the native root and file identity with an fd-derived
device/inode/`STATX_BTIME` tuple. Birth time is required and never silently
replaced with zero or a device/inode-only fallback. Device, inode, birth time,
fd, and the absolute provider root are excluded from portable state. This
detects ordinary inode-number reuse with a different creation timestamp, but
does not claim a true inode-generation handle, cryptographic identity, or
hostile-host protection. A deterministic provider race test pauses after the
redo plan is durable, commits the next lease epoch through another provider,
then proves that the old source fails the final SQLite fence with no file
mutation; durable-plan reconciliation is fenced the same way. Drift rejection
covers state already observable before a provider operation. Concurrent writers
are ordered or rejected only when they participate in the same advisory
lock/lease protocol; the gate does not prove atomic compare-and-mutate against
an uncooperative writer that bypasses it. The race test is a provider test, not
one of the 12 published case assertions, and the structural bundle verifier does
not recompute it. The fence orders effect admission; the native file change and
SQLite outcome are not atomic, so post-effect finalization failure is reported
as indeterminate and requires reconciliation.

`system-stage3b` runs the fixed 14-case logical-request registry. It exercises
stable peer and logical-operation identity, provider-level deduplication,
pending-before-send, lost acknowledgement, unknown completion reconciliation,
partial-response cursor continuity, timeout, cancellation/completion races,
credential-reference reacquisition and denial, unsafe replay blocking, source
fencing, and idempotent cleanup. The provider uses a real bounded loopback TCP
protocol and durable logical-operation ledger, but the profile explicitly
rejects raw-live-TCP transport. Socket/TCP sequence state, credential material,
and runtime future state are absent from portable state and evidence. Its
`VISALR03` exchange uses a fresh nonce and HMAC-SHA-256 to authenticate the
configured peer before any application request frame; mismatch cases require
zero accepted application frames, and the reusable credential is never a wire
field. Execute is matched to the digest the peer derives from authenticated
request bytes; Lookup and Cancel explicitly carry the expected digest. The
provider test suite uses a real-TCP greeting barrier to verify deterministically
that, after handoff commit, the old source fails the final SQLite
authority/lease/binding check before an application frame is sent. Ledger
revision compare-and-save tests under an immediate transaction separately reject
stale saves and terminal, cursor, or cleanup regression. These provider tests
are not published 14-case assertions and are not recomputed by the structural
verifier. The checks do not make a remote effect atomic with the SQLite commit
or prove general transport encryption.

The `completed-before-freeze` cell removes both the destination-visible
provider operation entry and the peer operation ledger before reconciliation;
the retained canonical response metadata must recover the terminal result
without a second peer execution. `pending-before-send` uses a real TCP failure
after the peer has received the client hello but before it sends the greeting
or receives an authenticated application envelope. Peer/credential negative
assertions are runner-produced from the count of accepted application frames
and raw payloads captured in the peer-received (client-to-server) direction.
Those raw frames are not published, so the structural verifier does not
independently recompute these semantic assertions; the protocol's typed
greeting/reply structures separately ensure that reusable credential material
is not a server-to-client wire field.

Each gate creates separate source and destination Wasmtime stores,
coordinators, and provider instances backed by local SQLite continuity inside
one OS system-runner process, executes the public
Component/adapter/coordinator/provider/handoff path, publishes a
profile-specific evidence bundle, and invokes the independent structural
`visa-conformance stage3a` or `stage3b` command against the retained artifact
root. The verifier fixes the schema, claim, case registry/order, terminal
classes, assertion set, state digests, lease epochs, operation-ID form, artifact
digests, and runtime identities. It requires
`independent_runtime_coverage=false` and requires Wacogo to remain explicitly
unsupported for Stage 3.

The profile and configuration JSON files are publisher-generated, digest-bound
declarations. The structural verifier checks their exact bytes and publication
membership, but does not independently parse or enforce their key/value
semantics.

Unlike the typed Stage 2 transcript normalizer, the current Stage 3 verifier
does not recompute every case assertion from `trace.json` and the raw before/
after or request/response bytes. The semantic pass/fail decision is produced by
the executable system runner from the exact tested revision; the separate
verifier independently enforces publication completeness, fixed registry and
assertion shape, scope, identities, digests, epochs, artifact integrity, and
the no-overclaim boundary. Stage 3 evidence must therefore be described as
runner-produced semantic evidence plus independent structural verification,
not as a second independent semantic implementation.

`system-stage3` is only a convenience aggregate that invokes these two gates in
sequence. The profiles do not form a runtime matrix, and the Strict Stage 2
Wasmtime/Wacogo conclusion cannot be copied into them. Arbitrary filesystem
objects, arbitrary live transport continuation, generic future/stream state,
and general asynchronous-runtime behavior remain outside both claims. The
single-process topology is sufficient for the current local-rebinding profile
claims; dual workers, process isolation, cross-host transport, and cross-target
execution require later qualification.

### Stage 4 target/substrate and emulated cross-ISA cells

`system-stage4` fixes the Wasmtime implementation, the bounded timer/KV
Component profile, and the 31-case Stage 1 registry while varying three named
target execution endpoints:

```text
Hx = native x86_64-unknown-linux-gnu worker
Qx = the byte-identical x86_64 worker under owned qemu-x86_64 -cpu max -L /
Qa = an aarch64-unknown-linux-gnu worker under owned qemu-aarch64 -cpu max
     -L /usr/aarch64-linux-gnu
```

The exact seven-cell catalog is:

```text
Hx -> Hx   Hx -> Qx   Qx -> Hx   Qx -> Qx
Qx -> Qa   Qa -> Qx   Qa -> Qa
```

`named-target-substrate-continuity-v1` requires the four Hx/Qx cells.
`emulated-cross-isa-continuity-v1` requires the four Qx/Qa cells; `Qx -> Qx` is
the shared control. Every cell runs all 31 cases, producing 217/217 executions,
seven complete inner Stage 1 bundles, and 31 normalized observable groups. The
writer and the separate verifier both require every required cell to pass. The
verifier performs full inner Stage 1 validation, independently invokes the
typed Stage 2 normalizer over captured inner artifacts, and compares each case
across all seven cells rather than trusting the publisher's normalized cache.
The Stage 4 release build exact-locks its own Component bytes. Those bytes use
the same Stage 1 source and WIT contract but intentionally differ from Strict
Stage 2's dev-profile Component artifact; neither lock is substituted for the
other.

The x86-64 and AArch64 workers are separate target-native ELF binaries built
from one recorded source identity and one recorded Rust toolchain identity;
this is semantic cross-ISA evidence, not AOT binary portability. Hx and Qx must
retain byte-identical x86-64 workers. Qx and Qa must use the named owned
QEMU-user programs with `-cpu max`, explicit sysroots, no native fallback,
exact launcher argv, raw version output, and retained binary digests. The
target loader is executed in each target environment with `--list`; raw output
fixes the exact dependency path set, and the sysroot manifest binds the
resolved loader/libc digests. Nonce-bound raw source and destination
`target-hello` output binds each cell to the expected ELF ISA, target triple,
ABI, worker digest, protocol, and build identity.

Before endpoint execution, the runner invokes the exact
`/usr/bin/uname -s -r -m` path with a cleared environment, records that
program's digest and size, retains raw stdout/stderr, and requires a canonical
`Linux <kernel-release> x86_64` result. The independent verifier reconstructs
the typed host identity from those raw bytes. Together with Hx's direct
launcher, this identifies the observed x86-64 Linux execution environment; it
is not hardware attestation, proof of bare metal or absence of an outer
virtualization/binfmt layer, a trusted kernel measurement, a container-image
identity, or cross-host evidence.

The shared `performance-observations` workload keeps its original 50 ms timer.
Five raw steady-state samples are intentionally target-speed-dependent. The
runner therefore waits for the timer outside the measured interruption
interval, requires the deterministic `Completed` safe-point branch before
freeze, records that completion in the portable snapshot path, and proves that
the destination does not recreate a live timer. This corrects the observed
QEMU-dependent Pending-versus-Completed flake without changing the shared
Stage 1 timer input. Dedicated timer cases continue to validate pending timer
recreation and single expiry delivery.

Stage 4 publication is fail closed. `stage4-incomplete` exists before target
qualification or cell execution; after its initial write succeeds,
`stage4-status.json` records the active phase and completed-cell count. Runner
failures before publication normally retain both, but an early status-write
failure may leave only the marker. A successful runner removes the status file,
writes all referenced artifacts, runs staged prepublication verification with
the marker present, and removes the marker only after the complete exact
artifact graph passes. A later independent-verifier or relocation failure is
reported by the gate exit/log and does not recreate runner diagnostics.
Published-mode verification rejects a remaining marker, status file, temporary file,
unmanifested entry, unsafe path, symlink, hardlink, special file, missing file,
or size/digest mismatch. A negative unit test explicitly adds an extra file
alongside temporary, symlink, hardlink, and socket entries and requires the
exact-inventory verifier to reject them.

After the independent verifier accepts the original root, the system gate
renames that real directory to a previously unused `-relocated` path without
rewriting `stage4-evidence.json`, `matrix.json`, or any referenced artifact.
The independent verifier must accept the relocated root again. The matrix keeps
the historical absolute execution root solely to validate the launcher argv;
all artifact resolution remains relative to the verifier-supplied current
root. This is the local proof that an uploaded/downloaded byte-identical bundle
can be reverified at a different path.

The bounded claims explicitly exclude real AArch64 hardware, the unsupported
legacy no-std/reference-kernel path, real-device enforcement, Stage 3 file or
request resources across targets, a second Stage 4 runtime, AOT binary
portability, cross-host movement, 32-bit or big-endian targets, hostile-host or
confidential execution, and production/performance conclusions. Real AArch64
hardware is recorded as `not-run`; the legacy kernel is `unsupported` because
the runtime is not linked and its old engine path remains a stub. Neither state
is presented as a passing cell.

The complete bounded matrix and all negative/relocation checks are locally
green. Roadmap completion remains pending until the stage-closing pushed SHA
passes both parallel CI jobs, including `full`, Stage 1, JcoNode, legacy and
Strict Stage 2, Stage 3A/B, and the separate Stage 4 aggregate.

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

The Stage 3 verifiers reuse the same secure artifact-root reader. They reject an
incomplete publication marker, require unique referenced artifact URIs, open
each referenced regular file beneath the anchored root, and verify its declared
size and SHA-256 together with the profile-specific evidence shape. This
protects the current Stage 3 bundles from ambient-path and unsafe-file
substitution; it does not upgrade their Wasmtime-only, same-process,
local-rebinding scope.

The Stage 4 verifier builds on that reader and additionally reconstructs every
retained typed receipt and raw target/host observation, revalidates all seven
inner Stage 1 snapshots, recomputes the normalized comparison, and enumerates
the complete directory tree against the exact expected file and directory set.
Workers and QEMU programs are artifact-owned single-link regular files during
execution; loader dependencies remain digest-identified sysroot inputs rather
than copied release artifacts. Exact-set enumeration and publication markers
belong to the controlled single-publisher boundary, not to a hostile same-UID
filesystem adversary claim. The successful directory-rename check changes only
the verifier root: the historical execution path and launcher argv remain
immutable evidence and no JSON is regenerated after execution.

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
| Bounded regular-file continuity | The fixed 12-case Stage 3A registry through the named Wasmtime source/destination adapter, real scoped Linux file provider, reauthorization/fencing, artifact digests, and independent bundle validation | Arbitrary directory trees, devices, FIFOs, open fds, atomic compare-and-mutate against writers outside the advisory lock/lease protocol, a second runtime, or cross-ISA behavior |
| Bounded logical-request continuity | The fixed 14-case Stage 3B registry through the named Wasmtime source/destination adapter, real bounded loopback protocol and durable operation ledger, credential reacquisition, reauthorization/fencing, artifact digests, and independent bundle validation | Preservation of raw live TCP/socket state, credential transfer, generic future/stream continuation, a second runtime, or cross-ISA behavior |
| Named target/substrate continuity | The fixed Wasmtime timer/KV workload across Hx -> Hx, Hx -> Qx, Qx -> Hx, and Qx -> Qx; raw x86-64 Linux host receipt; owned worker/QEMU artifacts plus loader/sysroot receipts; four complete inner validations; and equality within the seven-cell aggregate | Real hardware, a new kernel/device substrate, another runtime/resource family, or cross-host behavior |
| Emulated cross-ISA continuity | The fixed workload across Qx -> Qx, Qx -> Qa, Qa -> Qx, and Qa -> Qa; separate x86-64/AArch64 worker ELFs, artifact-owned QEMU executables and identified sysroots, four complete inner validations, and equality within the seven-cell aggregate | AOT binary portability, real AArch64 hardware, a second runtime, Stage 3 resources, 32-bit/big-endian targets, or cross-host behavior |
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
| Performance observations | Raw steady-state cost, snapshot size, and handoff interruption measurements are recorded without converting them into an unearned performance claim. The unchanged 50 ms timer is allowed to complete outside the interruption interval before freeze; completion must be captured and must not be recreated after restore. |

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
- cross-ISA or broader runtime/resource continuity in the baseline cell; legacy
  Stage 2c separately earns only `cross-execution-path-portability`, strict v3
  separately earns only `strict-cross-runtime-continuity` for the named
  Wasmtime/Wacogo x86-64 Linux timer/KV matrix, and bounded Stage 4 separately
  adds only its named QEMU-user target/substrate and emulated x86-64/AArch64
  timer/KV cells after exact-SHA closure;
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
