# vISA Validation

Status: current validation truth and target validation contract.

Implementation status: `fast`, `full`, the two legacy same-path system cells,
the four-cell legacy v2 cross-execution-path matrix, and the separate four-cell
strict v3 Wasmtime/Wacogo matrix are automated. The Stage 3A bounded
regular-file and Stage 3B bounded logical-request gates are also automated and
wired into CI, with an aggregate local command that runs both. Bounded Stage 4
is complete only for `named-target-substrate-continuity-v1` and
`emulated-cross-isa-continuity-v1`: all seven native/QEMU-user target cells,
217/217 timer/KV executions, seven complete inner Stage 1 validations, 31/31
normalized equality groups, independent outer verification, exact-set checks,
directory relocation, the complete exact-SHA workflow, and downloaded-artifact
reverification passed. Stage 1 and Stage 2 use the timer/KV profile; the two
Stage 3 gates are separate Wasmtime-to-Wasmtime resource profiles and do not
inherit the Strict Stage 2 cross-runtime result. The Stage 4 matrix also holds
Wasmtime and timer/KV fixed
and does not inherit that independent-runtime claim. Confidential, release,
performance, and production validation remain outside the implemented
boundary. A separate `system-joint-handoff` lane combines a reference protocol
subreport with an independently verified HostSubstrate vertical for the
accepted bounded `bounded-joint-handoff-refinement-v1` claim. Nexus-local
qualification is locked to clean
`8e5123c46569e8ebdaba9f4f56bea6584ab58586`; the exact-binary process artifact
owns the executed binary, and the logical-request artifact remains explicitly
supplemental. Accepted vISA implementation
`d3b07f1114cb49e26dd62fb252a895022ac2a743` completed the clean local, Docker,
exact-SHA CI, relocation, and post-download obligations recorded in the
[joint-handoff closure receipt](#joint-handoff-closure-receipt). Nexus run
`29475464538` attempt 1 retained a QEMU timeout failure
artifact; any same-SHA retry must be evaluated as a separate attempt rather than
erasing that failure history.

Last reviewed: 2026-07-17.

This document defines what each result proves and the acceptance boundaries for
the first architecture-complete slice, the legacy Stage 2 execution-path
matrix, the strict Stage 2 runtime matrix, and the two bounded Stage 3 resource
profiles, plus the completed bounded Stage 4 target/substrate and emulated
cross-ISA matrix, and the accepted bounded joint-handoff boundary. Update it
when executable gates change.

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

GitHub Actions separates repository quality from claim qualification on pushes
and pull requests. One Docker job validates Compose and runs `full`. Six
parallel matrix lanes run the same `system`, `system-jco-node`, `system-stage2`,
`system-stage2-strict`, `system-stage3a`, and `system-stage3b` implementations
exposed locally by `scripts/run-docker-ci-gate.sh`; a separate lane runs the
complete `system-stage4` aggregate, and another separate lane runs
`system-joint-handoff` with a legacy reference-only artifact name but a distinct
HostSubstrate evidence subcell. Each
job rebuilds the development image from the exact checkout, tags it
`visa-dev:<SHA>`, and keeps Cargo target output ephemeral instead of restoring
it across workflow runs. System evidence and logs live outside that target tree
under `.ci-artifacts/` and upload on gate success or failure, including partial
artifacts when any exist. The strict wrapper additionally retains its Docker
log, exit receipt, sidecar, and build receipt. Pull-request artifacts use 3-day
retention; push artifacts use 14-day retention.

A final fail-closed `Exact-SHA qualification closure` job depends on the quality
job, all six claim lanes, Stage 4, the Docker reference/HostSubstrate joint lane,
and a separate host-built Nexus/process qualification lane, and
succeeds only when every result is `success`. The local `system-stage3` command
still runs Stage 3A and Stage 3B in sequence; CI runs them as separate
uploadable lanes. A Stage 4 qualification closure therefore requires the
complete workflow to pass at the same exact pushed SHA, not merely the Stage 4
lane. Success of either joint lane does not substitute for the other, the Nexus
v2 receipt, exact-binary process evidence, or final clean-vISA artifact.

| Tier | Current operation | What a pass establishes |
| --- | --- | --- |
| `fast` | Locked metadata, formatting, strict active-spine dependency direction, the Stage 1 deletion/oracle-boundary audit, first-party Rust file-size maintenance, the build/cache/evidence CI contract, the frozen vISA 0.1 exact-version target-contract checker and self-tests, locked JcoNode Cargo/source/Node/V8 identity, strict active-spine Clippy, and active-spine tests | The selected contract, reducer, port, coordinator, adapters, profile, evidence packages, and CI policy satisfy their local logic and structural edit-loop gates. The 0.1 target may be schema-valid while release closure remains incomplete. |
| `full` | Everything in `fast`, shell parsing, default-feature workspace tests, current opt-in feature tests, active no-std check, selected Wasm check, kernel target check, benchmark compilation, and report/artifact fixture gates | The checked repository builds and tests across its declared compile targets and current fixture contracts. It does not prove a live handoff. |
| `system` | All 31 registered Stage 1 lifecycle and fault cases through isolated source/destination workers, followed by independent validation of the produced execution bundle | The named single-runtime reference cell satisfies the Stage 1 workload, resource, authority, recovery, fencing, and evidence contract. It does not repeat `full` or prove another runtime or ISA. |
| `system-jco-node` | The same 31 registered cases with JcoNode explicitly selected at source and destination, followed by independent Stage 1 validation | The pinned Jco/Node/V8 translated execution cell satisfies the Stage 1 contract without a Wasmtime execution fallback. It does not prove a fully independent Component Model implementation. |
| `system-stage2` | All four Wasmtime/JcoNode source-destination pairs, 31 cases per pair, four inner Stage 1 validations, and independent outer Stage 2 validation | The same portable state and normalized observable behavior pass in all four declared execution-path cells (124 executions). It does not prove strict runtime independence or cross-ISA portability. |
| `system-stage2-strict` | Locked Wacogo qualification and reproducible build, focused lifecycle gates, a Wacogo same-path Stage 1 cell, then the exact four Wasmtime/Wacogo cells with 31 cases per cell, four inner validations, and independent strict v3 outer validation | The fixed Component preserves the accepted timer/KV behavior across two independently implemented Component Model runtime lineages in all four directions (124/124 executions and 31/31 equality groups). It establishes only `strict-cross-runtime-continuity` on x86-64 Linux, not another ISA or resource profile. |
| `system-stage3a` | All 12 accepted bounded regular-file cases through separate source/destination Wasmtime stores, the shared coordinator/profile path, a real Linux regular-file provider, handoff, and independent Stage 3A bundle validation | The `bounded-regular-file-continuity` claim passes for the named Wasmtime-to-Wasmtime x86-64 Linux cell. It does not imply arbitrary directory trees, devices, FIFOs, already-open fds, atomic exclusion of writers outside the advisory lock/lease protocol, another runtime, or another ISA/substrate. |
| `system-stage3b` | All 14 accepted bounded logical-request cases through separate source/destination Wasmtime stores, a durable provider ledger, a real bounded loopback TCP protocol/peer, handoff, and independent Stage 3B bundle validation | The `bounded-logical-request-continuity` claim passes for the named Wasmtime-to-Wasmtime x86-64 Linux cell. It does not preserve arbitrary live TCP, socket sequence state, credential bytes, runtime future/stream state, or prove another runtime. |
| `system-stage3` | `system-stage3a` followed by `system-stage3b`, retaining one evidence root for each profile | Both bounded Stage 3 profile gates pass in one local invocation. This aggregate adds no cross-profile, cross-runtime, cross-ISA, or production claim. |
| `system-stage4` | Release x86-64 runner/worker/verifier and AArch64 worker builds; raw x86-64 Linux host observation; all seven Hx/Qx/Qa cells and 217 executions; seven inner Stage 1 validations; 31 independently recomputed normalized equality groups; exact artifact inventory; independent verification before and after a real directory rename | Locally establishes only `named-target-substrate-continuity-v1` for Hx/Qx and `emulated-cross-isa-continuity-v1` for Qx/Qa with Wasmtime and timer/KV fixed. Roadmap closure additionally requires the complete-workflow and downloaded-artifact receipt recorded below. It does not establish real AArch64 hardware, a no-std/reference kernel, real devices, Stage 3 resources, another runtime, AOT binary portability, cross-host behavior, confidentiality, performance, or production readiness. |
| `system-stage4-target`, `system-stage4-isa` | Each invokes the same complete fail-closed `system-stage4` aggregate | These are edit-loop aliases, not reduced matrices or independent additional claims. |
| `system-joint-handoff` | Exact Git-object source-lock validation; 16 normative concrete production-reducer traces; 16 reference ownership/effect cases plus one supplemental retained-tombstone scenario; durable SQLite reopen; an online `Coordinator<SqliteProvider>` HostSubstrate cell with 14 commit records, 9 abort records, and seven canonical peer-invocation classes; exact two-file publication; strict independent semantic verification before and after relocation | Establishes the same-boot neutral/reference and vISA HostSubstrate axes of accepted `bounded-joint-handoff-refinement-v1`. It does not itself execute or absorb the separate Nexus-local and exact-binary process lanes. |
| `run-nexus-handoff-qualification.sh` | Clean exact-SHA Nexus checkout; source fingerprint; model, oracle, fault matrix, and production Registry refinement; independent v2 receipt verification; exact artifact copy and relocated recheck | Locally establishes only `same-boot-nexus-handoff-admission-only` for the locked Nexus revision. It does not execute the joint vISA cell, real OSTD/IRQ/SMP, reboot recovery, Registry replacement, or the production retained-tombstone path. |
| `run-nexus-process-joint-cell.sh` | Clean exact vISA and Nexus checkouts; current neutral source lock; Nexus v2 lock and receipt; exact Nexus binary; two process scenarios; strict three-file manifest/report/executed-binary publication; independent static and semantic verification before and after relocation | Establishes the self-contained exact-binary process axis when bound to the accepted clean vISA SHA, without re-executing the retained binary or claiming reproducible source-to-binary derivation. |
| `run-logical-request-lost-ack-cell.sh` | The same exact identities plus one real logical request, durable ownership Commit acknowledgement loss, terminal Nexus response loss, two SQLite databases, raw JSONL, and a strict five-file artifact including the executed binary | Supplemental observational evidence only. It proves the named retries and post-hoc lineage without duplicate execution/publication; it does not execute vISA freeze/fence/activation or prove Nexus admission preceded the external effect. |

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
- one monolithic production execution that combines the separately verified
  neutral/reference, HostSubstrate, Nexus-local, exact-binary process, and
  supplemental logical-request axes; acceptance is a bounded refinement claim,
  not evidence that every axis ran inside one cross-host handoff;
- provider- or kernel-enforced admission against a second raw coordinator or
  hostile caller of public projection APIs; the bounded Host cell declares
  `exclusive_trusted_coordinator_api=true` as a TCB assumption;
- real OSTD, IRQ/SMP, Registry replacement, or a production
  retained-tombstone path;
- host-reboot/permanent-source-loss recovery, cryptographic native receipt
  verification, hostile-storage rollback resistance, or an external freshness
  anchor for the joint profile;
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
release quality, or production safety. The accepted
[Stage 4 closure receipt](#stage-4-closure-receipt) confirms the required
complete workflow and post-CI artifact verification without widening any of
those exclusions. The same workflow also requires both joint-handoff jobs. The
Docker lane includes HostSubstrate evidence while the host-built lane supplies
the separate Nexus-local and process artifacts; neither absorbs the other or
adds cross-host, cryptographic, anti-rollback/freshness, or Stage 5 claims.

## Validation tiers

`fast`, `full`, `system`, `system-jco-node`, `system-stage2`,
`system-stage2-strict`, `system-stage3a`, `system-stage3b`, and the
`system-stage3` aggregate, `system-stage4`, and its `system-stage4-target` and
`system-stage4-isa` aliases are implemented shell commands. `release` and later
claim gates below remain acceptance contracts until their exact matrix runners
exist.

### Fast

The fast tier is the ordinary edit loop: formatting, locked metadata, strict
linting and focused tests for the active spine, plus strict dependency direction
and the [vISA 0.1 exact-version target-contract](../specs/release/visa-0.1.md)
checker/self-tests. The default contract check proves that frozen identifiers,
versions, digests, the six-process role/authority topology, three independent
bounded local UDS contracts, and the explicit pending/satisfied partition still
match. It also validates every attached satisfied-ID evidence path, digest,
exact revision, and verifier receipt. It does not make the separate
`--release-ready` admission pass. The tier proves local logic and structural
direction, not implemented adapter or continuity behavior.

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

Timer state is selected by an exhaustive case-registry strategy. The dedicated
`visa-stage2-common-input-v2` contract fixes all 31 cases as three `Pending`, 22
`Precompleted`, and six `ScenarioControlled` strategies. The dedicated positive,
paused, completed, cancelled, and cleanup cases retain their distinct branches.
`safe-point-unreachable` and `unsupported-live-resource-or-borrow` use explicit,
provenance-bound 180 s timers. That exceeds the sum of all 8 and 11 worker RPC
timeout budgets, respectively, from timer activation through their final source
dump. `timer-semantics-unsupported` retains its separately bound 60 s timer,
which exceeds its three pre-freeze RPC budgets and keeps the snapshot `Pending`
until destination capability validation rejects it. All other cases retain the
50 ms workload delay. These bounds do not include an externally suspended
runner or unbounded scheduling gaps between RPCs. Cases whose primary claim is
not timer disposition wait for that timer before handoff, require the
`Completed` snapshot branch, and prove that the authoritative final trace does
not recreate it. The
scenario-controlled safe-point/live-resource rejections publish no snapshot and
must return to a running source with a positive armed timer. Each case keeps the
same exact delay in every runtime cell, and every inner Stage 1 verifier checks
that delay against matrix, config, and transcript provenance before Stage 2
applies its existing semantic normalization; this change adds no new
normalization exclusion. Pre-commit abort checks derive their exact component,
timer, and KV expectation from the already locked snapshot branch.
This maintenance revision emits `visa-stage1-evidence-v0.5` with
`visa-stage1-matrix-provenance-v3`. The accepted exact-`I` archives remain
`v0.4`/`v2` evidence and must be checked with their retained exact-`I` verifier;
the schema change prevents either revision from silently accepting the other's
different timer-input contract.
The outer strategy check proves the case-specific snapshot disposition and
authoritative final branch. Ordering within quiescence remains a Stage 1
trace/raw-evidence obligation; it is not a wall-clock chronology claim or a
guarantee against an externally suspended worker.

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
schedules, typed snapshot-timer strategies, and schema/codec identities. Every
cell uses fresh workers, runtime instances, provider storage, and native handles.
The outer verifier first completes the full Stage 1 validation of every inner
bundle, then independently recomputes a versioned typed normalization, verifies
each actual snapshot and authoritative final branch against the accepted
strategy, and compares all 31 four-cell groups. Runtime identity, translation
provenance, cell completeness, and no-fallback facts are checked exactly outside
normalization. A normalization version may exclude only its declared
non-portable observations; it cannot expand its exclusions to conceal a
behavioral difference or malformed inner evidence.

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
Hx = artifact-owned x86_64-unknown-linux-gnu worker, executed natively
Qx = the same artifact-owned x86-64 worker under the artifact-owned
     qemu-x86_64 executable with -cpu max and the identified / sysroot
Qa = artifact-owned aarch64-unknown-linux-gnu worker under the artifact-owned
     qemu-aarch64 executable with -cpu max and the identified
     /usr/aarch64-linux-gnu sysroot
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
from one recorded source identity and one recorded Rust/Cargo toolchain
identity; this is semantic cross-ISA evidence, not AOT binary portability. Hx
and Qx must retain byte-identical x86-64 workers. Qx and Qa must use the named
artifact-owned QEMU-user executables with `-cpu max`, explicit, identified
sysroots, no native fallback, exact launcher argv, raw version output, and
retained binary digests. The
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
green. The accepted qualification SHA also passed the complete CI workflow,
including `full`, Stage 1, JcoNode, legacy and Strict Stage 2, Stage 3A/B, the
separate Stage 4 aggregate, and the exact-SHA closure; its downloaded artifact
passed independent verification again.

### Stage 4 closure receipt

Roadmap Stage 4 closed on 2026-07-15 at accepted qualification revision
[`457ae1d64915c0b3febd84e136d08be53063210f`](https://github.com/chenty2333/vISA/commit/457ae1d64915c0b3febd84e136d08be53063210f)
through GitHub Actions run
[`29386011420`](https://github.com/chenty2333/vISA/actions/runs/29386011420),
which completed at 2026-07-15 12:57:00 +08:00. All eight independent
qualification jobs and `Exact-SHA qualification closure` concluded `success`
at that exact SHA.

The run uploaded `stage4-target-isa-system-evidence` as artifact ID
`8332365550`; GitHub reported archive digest
`sha256:e6da2259f2e36f9053f48fe2c9fc7e2692cf887f4546a13f2570728eb17f0bf2`
and size `120726772` bytes. The artifact was downloaded below the host-local
`/tmp/visa-final-validation/` parent, distinct from the retained historical
execution root `/workspace/evidence/stage4-QMEhgk`. The inner
`stage4-QMEhgk-relocated` bundle passed the independent verifier built from the
same qualification revision. It was then moved without JSON changes to
`stage4-QMEhgk-relocated-again` and this exact command also exited 0:

```sh
cargo run --locked -q -p visa-conformance --bin visa-conformance -- \
  stage4 \
  /tmp/visa-final-validation/stage4-QMEhgk-relocated-again/stage4-evidence.json \
  /tmp/visa-final-validation/stage4-QMEhgk-relocated-again
```

That post-download verification rechecked marker/status absence, the exact
1,789-file inventory, 217/217 executions, all seven independently verified
inner Stage 1 bundles, and all 31 equal normalized groups. The downloaded
bundle ID is `stage4-437d2ad93d373e288eea1c39`; its
`stage4-evidence.json` SHA-256 is
`198718a8c1b833bca0fc2a9be02d0d9e68ae3994a0bde23b9364dd0a10496fbb`.
This receipt closes only the two named Stage 4 claims and does not promote the
host receipt, QEMU execution, or identified sysroots into portable semantic
truth.

### Joint-handoff closure receipt

Historical neutral evidence accepted the 16-case implementation at
[`873880c706c01ef25caad755224af266fcb4d43a`](https://github.com/chenty2333/visa-nexus-handoff/commit/873880c706c01ef25caad755224af266fcb4d43a).
GitHub Actions run `29433027304`, job `87412563666`, accepted artifact
`8350187442` (4,173,087 bytes, digest
`sha256:1258853b2491c44c425ec2ffd491aac64f7684e5151bd427ea740ffceba35901`,
expiry 2026-07-29). The artifact was downloaded under a different root and
passed the same independent verifier. Receipt commit
[`b5a46269295cf9f4711a39d7c902b95e107c2f87`](https://github.com/chenty2333/visa-nexus-handoff/commit/b5a46269295cf9f4711a39d7c902b95e107c2f87)
records that closure without replacing the accepted neutral implementation
identity.

The later native-v1 mapping extension was independently accepted at
[`8fcdaf42ec44ac30668eb2d4d704f28ac4191485`](https://github.com/chenty2333/visa-nexus-handoff/commit/8fcdaf42ec44ac30668eb2d4d704f28ac4191485),
tree `a502d643eadc878c39a51ae0a4e560af250c36c6`. GitHub Actions run
`29443480361`, job `87448018259`, accepted artifact `8354423097` (4,179,606
bytes, digest
`sha256:6922c63565d6cfbc027a21b814e34d4568b48dfccbfbd55851e73b6020f7d4d8`,
expiry 2026-07-29T19:10:55Z), and the downloaded artifact passed independent
verification at another root. This extension freezes a field-level mapping and
still declares `adapter_qualification=false`; it does not qualify Nexus. These
remote receipts remain valid historical evidence, but neither revision is the
current source-lock identity.

The current source lock pins accepted neutral implementation
`f4a8211f0e5fde13e0f6101be3c3322854458c79`, tree
`a65f264bb7eaf390cbd6285d791b4f7f43e9be25`. Its machine-contract SHA-256 is
`f054fa08d48b7eed8fef18c274a464f66443410e6698474ff721bfb1a6b5cbf5`,
vendored Git-bundle SHA-256 is
`afe0fdfba1d2e47f5b6ee582833c03befca8e436f3a3d09d0b5df27612549e31`,
and complete source-lock SHA-256 is
`e8894d79ba2b3f164e94451d14139313a477481dc11c94d84a76a7ef774b9d50`.
Its run `29476495326`, job `87550513459`, and artifact `8366758594` succeeded;
the downloaded ZIP digest matched GitHub metadata and its bundle passed the
exact verifier before and after another relocation. Receipt commit
`be250c30b99035807c553f26171aae72f651eb1e` passed its own CI and is
documentation lineage rather than the accepted neutral source identity.

The accepted joint closure binds these exact source identities:

| Role | Revision | Tree |
| --- | --- | --- |
| vISA accepted implementation (`I`) | `d3b07f1114cb49e26dd62fb252a895022ac2a743` | `e8115326b40c8031fba13be749760fbccc0491cb` |
| Qualified Nexus (`N`) | `8e5123c46569e8ebdaba9f4f56bea6584ab58586` | `f3a23189f818f62f1635644ed436a51245f5cf0b` |
| Nexus analyzed reference baseline | `7829e609b3d770b684316a30170a7412faa62f9b` | Not used as an executed checkout |
| Neutral implementation | `f4a8211f0e5fde13e0f6101be3c3322854458c79` | `a65f264bb7eaf390cbd6285d791b4f7f43e9be25` |

The neutral bundle SHA-256 is `afe0fdfba1d2e47f5b6ee582833c03befca8e436f3a3d09d0b5df27612549e31`;
the joint source-lock SHA-256 is
`e8894d79ba2b3f164e94451d14139313a477481dc11c94d84a76a7ef774b9d50`.
The Nexus source fingerprint is
`017c681be01ca123a1df9625f16dd7b0367f861f7ac3be1476baf11a89070f52`,
its fault-matrix SHA-256 is
`9f3f1579172bf66dd5d58d2299c42dd4cb303cc74298c8d7a3a141e8cdcffd3e`,
and its v2 qualification-lock SHA-256 is
`21b5404bc5c1ad1f48c4ffe37cf455d104acac8ab9deca98f326d7c9b06072d9`.

Clean exact-`I` local evidence passed the host `full` gate, Docker `full`, Docker
`system-joint-handoff`, the source-bound Nexus qualification, and the reference,
process, and logical publishers plus original-location and relocated independent
verification. The retained local archive's `SHA256SUMS` has SHA-256
`f7ce7349fdc71161c8c11c4683fa00482d9ee0d3af8f31e45ff8ef0c29260240`.

Nexus main push run `29536334333`, attempt 1, completed successfully at exact
`N`. Quick job `87748433403` and full job `87748433313` both passed. Its
`nexus-verification-bundle-1` artifact, ID `8391650885`, is 4,363,342 bytes;
its Actions digest and actual downloaded ZIP SHA-256 are both
`dc9e7a6a718645ccde3a48e4b6895dfa74454496252c383cf4fdecf556a5b595`,
with expiry `2026-10-14T21:31:05Z`. A fresh detached exact-`N` checkout passed
`./x verify-bundle` with 12 specifications, 17 stages, 58 artifacts,
`dirty=false`, and `rebuild=true`. That archived receipt's `SHA256SUMS` has
SHA-256 `75c86289bf0132a52dcf209812f532350f7fbf24c691e414a8e48f3cb636de26`.

vISA master push run `29539269117`, workflow run number 36 and attempt 1, ran
from `2026-07-16T22:21:15Z` through `2026-07-16T23:23:54Z`. It bound
`GITHUB_SHA=I`, completed successfully, and closed all eleven jobs:

| Job | Job ID |
| --- | ---: |
| Docker repository quality gate | `87757780812` |
| Docker Stage 1 reference gate | `87757780868` |
| Docker Stage 2b JcoNode gate | `87757780861` |
| Docker legacy Stage 2 gate | `87757780942` |
| Docker Strict Stage 2 gate | `87757780885` |
| Docker Stage 3A regular-file gate | `87757780949` |
| Docker Stage 3B logical-request gate | `87757780961` |
| Docker Stage 4 target and ISA gate | `87757780797` |
| Docker joint handoff reference-only gate | `87757780819` |
| Nexus + vISA exact-SHA same-boot qualification | `87757780791` |
| Exact-SHA qualification closure | `87766199846` |

The closure job recorded repository quality, the six claim lanes, Stage 4, the
joint reference lane, and the Nexus qualification lane as `success`. The final
workflow published the expected nine artifacts. The two joint artifacts were
downloaded under independent roots:

| Artifact | ID | Bytes | Actions digest and actual ZIP SHA-256 | Expiry |
| --- | ---: | ---: | --- | --- |
| `joint-handoff-reference-system-evidence` | `8391793362` | 377,480 | `57dde6da8bed93349bbab7e4d6b158b989dfd57690cb38870a0a95d4c5e645de` | `2026-07-30T22:23:07Z` |
| `nexus-visa-same-boot-qualification-evidence` | `8391815580` | 9,236,939 | `6e8896f02efe1dce640dbf2a2c9188abc3a0bd7ecfd7636fcc429d885828d8d4` | `2026-07-30T22:24:12Z` |

The reference artifact contains one exact two-file publication. Its inner
bundle ID is
`sha256:2f90a2c97a73c0cc8eaa1df84fb0162026e22df42dc336b032a70e3b4317123d`;
the downloaded `joint-handoff-evidence.json` and `production-replay.json`
SHA-256 values are respectively
`263768b0d47b75042d9b4aeb4780e5f22f7918a82df27c5d5cf05680d85c607e`
and `3d9f0945caab7f9a0b7efd9d349fbb5b5d4c771e55a7ed645ace10e67f1029ea`.

The qualification artifact retained the exact four-entry top-level inventory:
the Nexus qualification directory, process directory, supplemental logical
directory, and CI log. Selected downloaded SHA-256 values are:

| Content | SHA-256 |
| --- | --- |
| Nexus qualification receipt | `53661654c4b22886f549946a4022bac2481b25384e8ac02760b956b596e8cfd4` |
| CI-built Nexus binary | `cad710798438017ffcc9306877bade34403429cd3dab337fc1be04ff7a230ec4` |
| Process manifest | `b3e1e7d0ead1204946f3ab53877fe98cc2afb0196617a8a1b1f9f456a333b168` |
| Process report | `4d66a304d2b86a067663905673ecda3759a688993a18be14c45f35d28b8d2133` |
| Logical manifest | `081d089ff3b486eb9321f01ed8c24811f8eeb90b7c3ce2a330c671e01b314ebc` |
| Logical report | `557f5814c80d610179ba37ecca067d1d43eaf3f194a7f8babe92999fae7539ac` |
| Logical ownership SQLite | `e57fa7a3348fef22a9305d36f16879423f1600e535e3755e200d92b09f543c85` |
| Logical provider SQLite | `9866d2638a4847f9368bd8b89417b2a6b18add6b4db9a340258b02aeb5546e89` |

Four post-download paths passed against the committed locks and exact source
identities: `visa-conformance joint-handoff`, the source-bound Nexus
qualification checker, the process artifact verifier, and the supplemental
logical-request verifier. ZIP integrity, exact inventories, and all selected
content digests were rechecked again when sealing the retained run archive. Its
complete `SHA256SUMS` has SHA-256
`03f0b09cdcee4d7012273fd31acc345147d6afa929d365ef4d17f5fd5d7c0d13`.

The CI-built Nexus binary differs from the local exact-`N` binary SHA-256
`6bf845f8fecd2b3ff5833aa505f2a392fa3e07d726326cf65d07b39a87358f51`.
Both are run-local content identities. Neither the publisher nor this receipt
claims bit-reproducible source-to-binary derivation, and post-download
verification does not re-execute the retained binary or treat file mode as
evidence.

In that TLA+ model, `BeginFreeze` is one atomic abstract transition: admission
closes, source authority freezes, the generation advances, and the abstract
boundary becomes visible together. TLC checks safety and conditional progress
over that abstraction. It does not prove the Host implementation's
WAL-before-effect ordering around a real peer call. That stronger refinement is
established separately by the Rust durable session, SQLite append/reopen
behavior, canonical pre-call invocation bytes, and independently replayed
request-to-response relations.

The vISA source lock retains an offline Git bundle and verifies the exact
neutral commit, tree, required blobs, and bundle SHA-256 without relying on a
moving remote ref. It also retains byte digests for the neutral Markdown
contract, machine-readable refinement contract, refinement map, and abstract
fault matrix. The refinement map declares `adapter_qualification=false` and
relates the 16 abstract schedules to the 16 concrete cases by case identity
only. It does not claim identical internal traces or terminals. The concrete
reference system adds one supplemental
`supplemental-postcommit-retained-tombstone` recovery scenario, for 17 reference
ownership/effect peer scenarios in total.

The vISA system bundle contains exactly `joint-handoff-evidence.json` and
`production-replay.json`. The independent verifier strictly decodes every
native receipt, rechecks its retained bytes, recomputes the typed parent
chain, cohort and prepared-binding digests, rejects conflicting terminal
decisions and accepted stale probes, replays all 16 concrete traces through its
own oracle, and binds the production-replay report to the bundle. Publication
is fail closed and the gate verifies the exact inventory before and after a
real directory move.

The durable projection cell uses an append-only SQLite log, reopens it,
rechecks and semantically replays each retained native receipt, and
verifies that an effect-freeze attempt with unknown outcome remains a blocking
obligation after recovery. This proves the bounded reference projection
behavior; the projection is not an ownership ledger and does not establish
cross-host durability or rollback resistance.

The same published production report contains a distinct HostSubstrate cell.
It executes source abort, source fence, and destination activation online
through production `Coordinator<SqliteProvider>` APIs backed by independent
source and destination SQLite databases. Its exact 14-record commit transcript
and 9-record abort transcript include durable attempt/observed/completion
windows and seven classes of canonical ownership/effect `peer_invocation`
bytes, kept distinct from response-derived issuance requests. The strict
verifier reconstructs every peer request/response relation, receipt chain,
journal and lease lineage, conflict failure atomicity, completion-append
acknowledgement loss, reopen head, pre-resume `Committed` checkpoint, and the
single final `JointDestinationResumed` event bound to the activation completion
record digest. Publisher summary booleans are not proof inputs for those facts.

The Host evidence declares `exclusive_trusted_coordinator_api=true`. This is an
explicit TCB boundary: the owning guards enforce sequencing for a
non-Byzantine orchestrator, while a second raw `Coordinator`/provider handle or
hostile caller of public projection APIs is outside the claim. The cell does
not establish provider- or kernel-enforced adversarial joint membership.

The Nexus-local lane is locked to clean revision
`8e5123c46569e8ebdaba9f4f56bea6584ab58586`, source fingerprint
`017c681be01ca123a1df9625f16dd7b0367f861f7ac3be1476baf11a89070f52`,
matrix `9f3f1579172bf66dd5d58d2299c42dd4cb303cc74298c8d7a3a141e8cdcffd3e`,
and v2 qualification-lock SHA-256
`21b5404bc5c1ad1f48c4ffe37cf455d104acac8ab9deca98f326d7c9b06072d9`.
The receipt reports `production_registry_refinement_checked=true`, whereas the
neutral mapping reports `adapter_qualification=false`. The separate Nexus
qualification lock remains `prospective=true`. Acceptance in this document is
vISA's decision about the bounded evidence composition; it does not change
Nexus v0.1 or RFC acceptance and does not qualify the neutral adapter mapping.

Exact-binary process tests cover raw JSONL replay and chain preservation, Registered-effect survival
across abort/thaw, the bounded process qualification scenarios including
same-Registry service rebind, and the real logical-request dual-lost-ack cell.
Service rebind is not Registry replacement.

The supplemental logical-request cell performs two real transport-fault boundaries. The
ownership service commits its SQLite transaction with WAL and
`synchronous=FULL`, then suppresses the typed Commit acknowledgement; recovery
drops and reopens the connection, queries the durable decision, and retries the
exact request. Separately, the process adapter sends a terminal close-step to
the real Nexus child, reads and discards the child's first JSONL response before
adapter acceptance, then resends the same request ID and accepts only a
byte-identical replay. Evidence proves one external logical-request execution,
one native Register/Prepare/Commit sequence, and one accepted terminal chain
entry. The real `VISALR03` loopback peer sees the application request but not
credential material. The report retains the exact typed provider exchange and
all raw Nexus JSONL. The application request completes before native
Register/Prepare/Commit and no vISA source freeze/fence or destination activation
runs, so this does not establish Nexus admission ordering or a vISA runtime
handoff. It also does not claim retained raw TCP frame capture.

The exact-binary process publisher and relocation runner validate clean source
identities, both locks, the Nexus receipt, and the exact binary; publish a strict three-file
manifest/report/executed-binary artifact; verify in a separate process; relocate;
and verify the same bytes again. The supplemental logical publisher emits a
strict five-file artifact including both SQLite databases and the executed
binary. Static verification binds the binary content but does not re-execute it,
claim reproducible derivation, or treat upload/download file mode as evidence.
The accepted implementation identity is
`d3b07f1114cb49e26dd62fb252a895022ac2a743`; the later receipt-only commit is
documentation lineage and does not replace that implementation identity. The
combined vISA/Nexus/neutral identities, exact-SHA CI, artifact metadata, and
post-download rechecks are fixed above. This closes only the bounded joint
research claim and does not relax any same-boot, TCB, or non-claim boundary.

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
boundaries are likewise explicitly outside this claim. The current maintenance
verifier contract requires worker protocol v4, including Stage 4 target hello,
subordinate Stage 1 matrix provenance v3, and top-level Stage 1 evidence v0.5.
Protocol v4 and matrix v3 make the per-case timer delay an explicit wire and
config-provenance input; the exact verifier does not reinterpret matrix v2 under
that contract. The accepted exact-`I` verifier instead owns matrix v2 and
top-level evidence v0.4. Worker protocol remains v4 across both revisions
because its wire shape did not change; the evidence and matrix versions advance
to prevent incompatible timer-input semantics from sharing one schema. Legacy
Wasmtime/JcoNode outer evidence remains v2, while the separate
Wasmtime/Wacogo strict outer evidence is v3; the two parsers reject mixed or
unknown schemas, and older bundles do not inherit either newer claim boundary.

### Release

The machine-readable [vISA 0.1 exact-version target
contract](../specs/release/visa-0.1.toml) freezes the intended single-host,
same-boot Linux x86-64 product cell and its version/digest boundaries. Its
default checker is implemented in `fast`; release admission is a separate
fail-closed `python3 scripts/check-release-contract.py --release-ready` command.
The current contract is explicitly not release-ready and claims no supported
product cell. The target topology is one short-lived controller, two long-lived
agents that directly host Wasmtime and their real profile sinks, one independent
SQLite ownership authority, and one `visa-nexusd` supervising one native-v1
peer. Controller/agent/ownership/Nexus RPCs are local UDS only. Agent and
controller crash recovery may reconnect to the surviving Registry; adapter or
peer crash is terminal fail-closed in 0.1 and cannot be disguised by respawning
a replacement Registry.

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
| Bounded joint-handoff refinement | The remote-accepted neutral model/mapping and unchanged 16-case registries plus one supplemental reference case; the vISA HostSubstrate 14-record commit/9-record abort vertical; locked Nexus-local production-Registry refinement; exact-binary process evidence in a strict three-file artifact; a separately labeled supplemental logical-request dual-lost-ACK five-file artifact; and the exact-SHA/post-download closure receipt above | The evidence axes remain distinct, the logical cell is not normative, and `exclusive_trusted_coordinator_api=true` plus semantic lock approval remain in the TCB. This does not imply adversarial raw-API admission, Nexus ordering of the supplemental external effect, Registry replacement, a production retained-tombstone path, real OSTD/IRQ/SMP, host reboot/permanent-source-loss recovery, cross-host transport, cryptographic authenticity, anti-rollback/freshness, TEE/KMS behavior, confidentiality, or Stage 5. |
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

The component owns a portable work/session identity and one logical timer. It has
only the rights needed to read/conditionally update one durable KV namespace and
arm/cancel that timer. The accepted case strategy decides whether the safe point
captures that timer as pending, completed, cancelled, or no snapshot at all.

The source records a baseline value and arms the timer. A pending freeze records
its remaining duration rather than a host-monotonic timestamp. The duration is
paused during handoff; after commit, the destination rebinds the same namespace
and starts a fresh monotonic wait for that duration. Completed and cancelled
freezes instead retain their terminal disposition and must not create another
destination timer. On expiry, one canonical operation conditionally updates the
value. Operation identity, an idempotency key, and a fencing epoch protect the
effect; universal exactly-once is not claimed. This profile does not preserve a
wall-clock deadline.

Restoring a pending timer creates a fresh destination arm whose causal parent is
the source arm recorded at the safe point. Because real time elapses after that
rearm, the first non-delivering destination poll may observe the destination arm
either still `Pending` with positive remaining duration or already `Fired`.
Both branches must retain that destination arm identity; the subsequent
delivering poll must apply its expiry once, and a repeated poll must not deliver
it again.

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
| Required capability was revoked | Retain one `Completed` snapshot exactly projected by the authoritative source. The primary destination response lifecycle must be exactly `Initialize -> LoadDestination -> Dump -> PrepareDestination/Provider/Revoked -> Dump`; its two inert dumps bind the unclaimed destination trace base/final, preserve the two source-owned timer/KV leases and KV observation, and create no binding or workload session. A fresh source recovery must produce exactly one audit dump equal to the unique primary-source final dump, retaining `Exported + Frozen(Completed)` and the revoked authority without thawing the workload. |
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
  timer/KV cells under the recorded exact-SHA closure;
- any wider joint-handoff claim beyond accepted
  `bounded-joint-handoff-refinement-v1`; its separate evidence axes do not imply
  one monolithic cross-host or production execution;
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
