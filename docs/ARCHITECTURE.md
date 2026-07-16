# vISA Target Architecture

Status: accepted target architecture.

Implementation status: the Stage 1 reference path and the legacy Stage 2a,
2b, and 2c Wasmtime/JcoNode path are implemented; the latter continues to
establish only `cross-execution-path-portability`. A separate strict v3 path
now executes the unchanged timer/KV Component through Wasmtime and a
source-lock-bound Wacogo derivative whose accepted Component Model lineage is
independent of Wasmtime and `wasmtime-environ`. Fresh Host and Docker runs
completed the exact four runtime cells with 124/124 executions and 31/31
normalized equality groups, and all inner and outer independent verification
passed for `strict-cross-runtime-continuity`. Both paths remain limited to
x86-64/amd64 Linux. Roadmap Stage 2 is complete for this named timer/KV scope.
Stage 3A bounded regular-file and Stage 3B bounded logical-request resource
paths are implemented, and their 12-case and 14-case executable evidence passes
independent structural bundle verification. The stage-closing implementation
revision passed pushed CI at its exact commit, so Roadmap Stage 3 is complete
for these two named bounded profiles. Stage 3 evidence is
Wasmtime-to-Wasmtime only, requires `independent_runtime_coverage=false`, and
does not inherit the Strict Stage 2 Wasmtime/Wacogo result. Bounded Stage 4 is
complete only for `named-target-substrate-continuity-v1` and
`emulated-cross-isa-continuity-v1`: the accepted qualification revision passed
the complete exact-SHA workflow, and its uploaded evidence was downloaded and
independently reverified at another root. It keeps the Wasmtime timer/KV
Component, 31-case registry, host kernel, and SQLite provider fixed while
qualifying native x86-64 Linux and x86-64/AArch64 QEMU-user endpoints with
artifact-owned executables and identified sysroots. Its 7 unique cells
completed 217/217 executions and 31/31 normalized equality groups. This does
not establish AOT-binary portability, real ARM hardware, Stage 3 resource
coverage across targets, or a second Stage 4 runtime. Confidential continuity
and production readiness also remain unimplemented. The exact closure receipt
is in [validation](VALIDATION.md#stage-4-closure-receipt).

The separate candidate `bounded-joint-handoff-refinement-v1` track has an
accepted 16-case neutral model/contract, a source-locked native-v1 mapping
extension, a pure composition reducer, typed receipt admission, durable SQLite
recovery, an independent verifier, a reference protocol lane, and a complete
same-boot HostSubstrate vertical. It also has a locally clean Nexus-local
qualification, four passing exact-binary process tests, a real logical-request
dual-lost-ack experiment, and a standalone publisher/relocation runner. The
final clean-vISA artifact and remote CI remain open. This is not Roadmap Stage
5.

Last reviewed: 2026-07-16.

The repository is being migrated toward this architecture. This document does
not claim that every current code path already conforms to it.

See the [vision](VISION.md) for the project boundary, the
[roadmap](ROADMAP.md) for capability order, and [validation](VALIDATION.md) for
the evidence required before a target capability becomes a current claim.

## Architectural objective

vISA provides one authoritative path from a component request through a
validated semantic transition and authorized substrate effects to a canonical
commit, explicit abort, or explicit indeterminate outcome, with derived
state-continuity evidence.

The architecture must prevent three forms of drift:

1. multiple models claiming to be the canonical object or event vocabulary;
2. runtime, kernel, or test harness state being mistaken for semantic truth;
3. snapshots, views, and evidence becoming parallel ledgers that require manual
   synchronization.

## System context

```text
WIT/WASI component + vISA profile
                 |
        engine/personality adapter
                 |
                 v
        runtime coordinator
        |  decode and validate
        |  reducer preflight
        |  authorized effect through a port
        |  canonical commit / abort / indeterminate
                 |
                 v
       canonical state + effect journal
          |             |              |
        views     snapshot/rebind    evidence
                 |
                 v
       substrate/provider adapters
```

The component model, artifact carrier, runtime engine, substrate, and host ISA
may vary. The semantic contract and its observable invariants must not.

## Logical components

### Contract schema

The contract schema is the only public vocabulary for portable identity,
generation, authority, operations, results, waits, cancellation, failure,
cleanup, traps, snapshots, compatibility, and evidence references.

The Stage 1 reference path implements this responsibility in `contract_core`,
but the logical responsibility is more stable than the crate name. The schema
must remain small, versioned, `no_std`-compatible where practical, and
independent of runtime engines, personality breadth, providers, benchmarks, and
project planning metadata.

### Canonical reducer

The reducer is the only state-transition authority. It consumes contract
commands, validates preconditions and authority, and produces a deterministic
decision describing the proposed effects and state transition.

The Stage 1 reference path implements this responsibility in `semantic_core`.
The active production spine does not retain a second public object, command,
event, or tombstone schema; broader comparison models remain isolated under
`crates/oracle/`.

Rejected preflight must leave canonical state unchanged. Applied transitions
must be replayable from the committed journal under the contract's defined
nondeterminism rules.

### Runtime coordinator

The runtime coordinator owns transaction sequencing across the reducer and
substrate ports. The Stage 1 reference path implements it in `visa_runtime`.

For each operation it must:

1. decode and validate the request and profile;
2. ask the reducer for a preflight decision;
3. execute only the authorized substrate effects;
4. atomically commit the canonical transition or record an explicit abort or
   indeterminate external outcome; and
5. append the authoritative semantic result to the journal.

No engine, executor, kernel, or evidence runner may maintain a competing
semantic ledger.

### Substrate ports and adapters

`substrate_api` defines narrow machine and provider ports. Ports describe
mechanisms a substrate can enforce; they do not grant component authority or
define frontend policy.

Wasmtime, other WebAssembly runtimes, host services, kernels, Linux
personalities, Virtio devices, filesystems, and network stacks implement
adapters around these ports. Adapter-private handles, page tables, descriptors,
queues, runtime objects, and register frames are non-portable bindings.

`visa_component_adapter` owns the engine-neutral cooperative component
lifecycle, portable component-state codec, structured adapter/workload
failures, and host-call bridge. Concrete adapters such as `visa_wasmtime`,
`visa_jco_node`, and `visa_wacogo` own engine preparation, WIT lifting/lowering,
process/RPC transport, and native resource tables. No concrete adapter may
redefine the reducer, coordinator, authority model, effect identity, or
snapshot truth.

Destination runtime preparation is a non-executing preflight and must finish
before Coordinator restore, binding preparation, or handoff commit. Its result
is an opaque runtime-local carrier bound to the runtime identity, component,
profile, accepted world, and prepared artifacts. It is neither portable nor
serializable, and destination activation may not replace it with a different
component or re-run preparation against different bytes. Guest instantiation
occurs only after commit. Adapter and workload failures cross the shared
boundary as structured values; engine or process text remains diagnostic and
cannot define portable semantics.

### Snapshot and rebinding

A portable snapshot is a versioned projection of committed canonical state. It
is not a dump of every in-memory structure and must not become a separately
maintained domain model.

Snapshot loading validates structure, profile, extensions, artifact identity,
authority requirements, and replay/fencing epochs before component execution
begins.

### Conformance and evidence

Conformance runs real operations through public runtime and adapter boundaries.
Evidence is derived from committed state, semantic traces, validation results,
and identified execution environments.

A sample or schema fixture proves only that a format is self-consistent. It
does not prove runtime behavior, portable restoration, real substrate
enforcement, or cross-ISA equivalence.

The Stage 2c outer verifier composes four complete Stage 1 bundles, validates
their common input and exact execution identities, then compares a versioned
normalized observable projection. JcoNode executes the translated core Wasm in
Node/V8, but its translator uses disclosed `wasmtime-environ` lineage; this is
cross-execution-path evidence, not proof of two independent Component Model
implementations.

The separate strict v3 outer verifier selects exactly Wasmtime-to-Wasmtime,
Wacogo-to-Wacogo, Wasmtime-to-Wacogo, and Wacogo-to-Wasmtime. It binds the
Wacogo source lock, build receipt, executed sidecar, and requested, prepared,
and live runtime identities; requires every cell to pass the independent Stage
1 verifier; and recomputes all 31 normalized equality groups across 124
executions. This establishes only `strict-cross-runtime-continuity` for the
named x86-64/amd64 Linux timer/KV profile and does not alter the legacy JcoNode
claim.

Stage 3 deliberately uses separate WIT worlds, guests, adapter resource tables,
portable state codecs, case registries, evidence schemas, and verifiers for the
regular-file and logical-request profiles. Both feed the same canonical
authority, lease, effect journal, snapshot, reauthorization, and fencing path;
neither changes the frozen Stage 2 evidence contract. Their current executable
evidence selects only the named Wasmtime Stage 3 adapter on both sides and the
verifier rejects any independent-runtime overclaim.

The current Stage 3 system runner creates independent source and destination
Wasmtime stores, coordinators, and provider instances backed by local SQLite
continuity inside one OS process. That topology exercises the canonical
snapshot, reauthorization, local rebinding, lease transfer, and source-fencing
boundary for these profiles. It is not evidence for dual-worker process
isolation, cross-host transport, or a real target/ISA/substrate change; those
remain separate qualification cells.

### Bounded Stage 4 target and ISA qualification

Stage 4 changes only the target/execution endpoint dimension around the same
Stage 1 Component, Wasmtime source/destination runtime, timer/KV profile, and
31-case registry. Within the matrix it fixes the host kernel,
`host-process-isolation` substrate identity, and
`substrate_host SqliteProvider with bundled rusqlite` provider identity rather
than mixing resource, runtime, and provider changes into the target matrix.
Three named endpoints are admitted:

- `Hx` is an artifact-owned x86-64 worker executing natively on x86-64 Linux;
- `Qx` is the artifact-owned x86-64 worker executing through the
  artifact-owned `qemu-x86_64` with `-cpu max` and the identified `/` sysroot;
  and
- `Qa` is an artifact-owned AArch64 worker executing through the artifact-owned
  `qemu-aarch64` with `-cpu max` and the identified
  `/usr/aarch64-linux-gnu` sysroot.

The target worker protocol returns a nonce-bound hello containing target
triple, ISA, OS, ABI, endianness, pointer width, executed-worker digest, and
recorded build source and Rust/Cargo toolchain identity. The orchestrator independently records
`/usr/bin/uname -s -r -m`, including the executable identity, exact argv, exit
status, parsed Linux/x86-64 identity, and raw stdout/stderr artifacts. QEMU-user
changes user-space instruction execution and loader/sysroot selection but uses
the host kernel. Consequently, `Qa` is emulated AArch64 userspace evidence, not
real AArch64 hardware or an AArch64-kernel qualification.

The two admitted claims are exact cell sets:

- `named-target-substrate-continuity-v1`: `Hx->Hx`, `Hx->Qx`, `Qx->Hx`, and
  `Qx->Qx`;
- `emulated-cross-isa-continuity-v1`: `Qx->Qx`, `Qx->Qa`, `Qa->Qx`, and
  `Qa->Qa`.

Their shared `Qx->Qx` control yields 7 unique cells. Each cell runs all 31
cases, producing 31 × 7 = 217 case executions. Every inner Stage 1 bundle is
independently verified, Stage 2 normalization is independently recomputed, and
the outer verifier requires 31 equality groups to contain identical normalized
observations across all 7 cells.

The cross-ISA claim is semantic, not binary. The Wasm Component and portable
state/profile are held constant, while the x86-64 and AArch64 `visa-system`
workers are separately compiled ELF binaries whose machine types are checked.
Nothing in this result says that a Wasmtime AOT image or other native binary can
move between ISAs.

The Stage 4 publication protocol is fail closed. A durable
`stage4-incomplete` marker exists before target acquisition or cell execution,
and prepublication verification requires it. After staged verification passes,
the publisher removes the marker and then syncs the root; published-mode
verification rejects any remaining marker. `stage4-status.json` is a runner
progress diagnostic, not the publication commit record: failures after status
initialization normally retain it, while an earlier status-write failure may
leave only the marker and a later outer-gate failure may leave a marker-free
published root. The verifier derives the exact artifact inventory from the
evidence, matrix, endpoint receipts, cells, and inner Stage 1 bundles. It
rejects missing or unmanifested files and directories, temporary files,
symlinks, multi-link regular files, and special entries.

Relocation does not rewrite evidence. `execution_artifact_root` is the
historical absolute root used to verify the retained owned-worker/QEMU argv;
current artifact reads are relative to the verifier-supplied root. The local
gate verified the original root, moved the whole directory to a different
absolute path without changing any JSON, and verified it again. The historical
path remained available only for launcher-argv checks; no artifact was read
from the old location. The accepted Actions artifact was subsequently
downloaded under a different parent and independently verified, then moved
again without rewriting its JSON and independently verified once more. See the
[closure receipt](VALIDATION.md#stage-4-closure-receipt).

The `performance-observations` case preserves its original 50 ms workload
timer. Steady-state samples remain target-speed-dependent, but the case waits
for the timer plus the established margin before entering quiescence and then
requires the deterministic `Completed` branch. This prevents measurement or
QEMU overhead from turning performance variance into semantic inequality and
does not create a production performance claim.

The claim guards explicitly exclude real AArch64 hardware, the legacy no-std
reference kernel, real-device enforcement, Stage 3 file/logical-request
resources across targets, a second Stage 4 runtime, AOT-binary portability,
cross-host execution, 32-bit or big-endian targets, hostile-host or
confidential continuity, and production/performance readiness. The no-std
reference kernel is recorded as unsupported because its runtime is not linked
and its legacy engine remains a stub; real AArch64 hardware is recorded as
not-run because this qualification uses QEMU-user. The bounded implementation,
exact-SHA workflow, and downloaded-artifact rechecks complete Roadmap Stage 4
only for the two exact claims above.

### Candidate bounded joint-handoff refinement

The joint profile composes three authorities that remain independently owned:

1. vISA owns portable state, resource claims, the local handoff lifecycle, and
   projection of a verified terminal result into the local runtime.
2. One external ownership service owns the durable reservation and the single
   immutable abort-or-commit decision.
3. One effect-closure service owns scope membership, publication admission,
   the frozen effect cohort, native close order, and retained cleanup
   obligations.

The required order is:

```text
ownership reserve
  -> vISA source freeze
  -> durable effect-freeze attempt
  -> effect freeze
  -> vISA destination prepare
  -> ownership seal
  -> exactly one ownership decision
      -> abort: effect thaw -> vISA source resume
      -> commit: effect close -> vISA source fence -> destination activation
```

An unavailable decision or an effect-freeze request with unknown outcome keeps
the source frozen. A timeout, lookup miss, lease expiry, or local cache entry is
never an abort. Destination activation requires the exact commit, terminal
closure, and source-fence receipt chain. A retained tombstone is a post-commit
recovery obligation and cannot be converted into an abort.

The TLA+ model makes `BeginFreeze` one atomic abstract transition: it closes
admission, freezes source authority, advances the freeze generation, and
captures the effect/snapshot boundary together. TLC checks invariants and
conditional progress over that abstraction. It does not prove the concrete
WAL-before-effect ordering. That implementation refinement is established by
the Rust reducer/session rules, SQLite append-and-reopen behavior, retained
pre-call invocation bytes, and independent transcript replay described below.

`joint_handoff_core` defines the isolated typed protocol and pure reducer
without changing `contract_core::CONTRACT_VERSION` or the Stage 1-4 canonical
state shape. `visa_joint_handoff` admits native receipt bytes only through a
pinned authenticator, replays them into an opaque verified state, and exposes
source/destination projection adapters. `ReceiptRequest` is a response-derived
receipt-issuance/authentication binding; it is not the request sent to an
ownership or effect peer. Host refinement evidence therefore retains the
canonical pre-call `peer_invocation` separately for every mutating peer call.
Its append-only durable session persists the exact canonical effect-freeze
invocation before calling the effect peer. Recovery reauthenticates and
semantically replays every record; it never trusts a cached projection as
ownership truth.

The same-boot Host refinement also declares
`exclusive_trusted_coordinator_api=true`. Opening a second raw `Coordinator` or
provider handle that bypasses the durable joint guard, or invoking public
projection APIs through a hostile in-process caller, is a TCB violation. The
owning guards enforce non-Byzantine orchestrator discipline; provider- or
kernel-level adversarial joint-membership admission is not implemented.

The bounded adversary model covers crash-stop process failure, the named lost-
acknowledgement windows, retry, duplicate/reordered delivery, and malformed,
stale, or substituted receipts within one host boot. It trusts the ownership log
to be linearizable, durable, non-equivocating, and free from rollback. The Nexus
Registry/effect service, vISA reducer/coordinator and SQLite projection, receipt
admission code, exact schemas and executed binaries, and both publishers and
verifiers are in the TCB. Test receipt authentication binds pinned identities
and bytes; it is not a cryptographic authenticity or freshness mechanism.
Progress is conditional on ownership query, the closure worker, and destination
recovery eventually becoming available. Permanent loss may leave the source
Frozen forever without violating the safety claim.

Qualification-lock semantic review is also a trusted release step. The
automatic checker proves that the approved exact checkout, source fingerprint,
matrix, receipt shape, and expected test/log inventory agree; it cannot decide
that a new source diff still implements the intended semantics. The approved
`a890e5c3..a4016af3` increment changes only the two Linux-network evidence
scripts outside the locked handoff source set; treating that increment as
irrelevant to the handoff qualification is an explicit maintainer judgement.
The subsequent `a4016af3..979b66aa` increment changes only
`kernel/nexus-ostd/scripts/assert-linux-futex-startup-source.sh`,
`kernel/nexus-ostd/scripts/assert-linux-futex-startup.sh`,
`kernel/nexus-ostd/src/personality/linux_futex.rs`, and
`kernel/nexus-ostd/x`, also outside that locked source set. The final
`979b66aa` fix replaces runnable-parent yield polling with per-stage
`WaitQueue`s: the child Release-publishes readiness before `wake_one`; the
parent Acquire-checks readiness before and after wait-queue insertion and,
while still waiting, parks through the scheduler's `dequeue_current` path.
This removes the runnable-parent selection window without losing an early
notification. Its 128-tick assertion qualifies successful child-entry latency
only. `WaitQueue` has no timer-driven wake, so an absent receipt is failed
closed by the unchanged outer QEMU timeout, not an internal guest-tick failure
deadline. Accepting these same-boot futex-startup changes as semantically
irrelevant to the handoff model is another explicit maintainer judgement;
exact full CI and independent verification of the downloaded canonical Nexus
bundle remain separate closure prerequisites.

The next `979b66aa..81c484c2` increment adds the bounded one-vCPU
runtime-filesystem service-crash slice. Of the 50 qualification-locked Nexus
sources, only `ARCHITECTURE.md` and `tools/xtask/src/evidence.rs` change. The
former records that separate runtime-filesystem evidence axis; the latter marks
one real user-service crash as observed and updates its exact artifact prefixes,
while retaining `all_fault_paths=false`, `irq=false`, and `smp_vcpus=1`. The
handoff model, profile, matrix, production Registry, transition substrate, and
their test inventories do not change. The source fingerprint nevertheless
changes because the lock intentionally includes those evidence-boundary files.
Accepting this increment as preserving the handoff-admission semantics is an
explicit maintainer judgement. The filesystem QEMU slice is not executed by the
handoff qualification lane and does not upgrade `real_ostd_execution_claimed`,
`joint_visa_execution_claimed`, or `real_ostd_smp_claimed`.

The next `81c484c2..8e5123c` increment closes the bounded one-vCPU
same-boot timer-admission window. Of the 50 qualification-locked Nexus sources,
only `ARCHITECTURE.md`, `tools/xtask/src/evidence.rs`, and `x` change. The first
records the callback-completion-rearmed APIC logical tick and the first-switch
disabled-IRQ admission boundary. The evidence code adds exact task-entry
debugcon streams and their oracles to the verification population. The wrapper
mounts a linked worktree's Git common directory read-only for exact revision and
clean-state inspection and adds missing host doctor prerequisites. The handoff
TLA, profile, fault matrix, Rust model, transition substrate, production
Registry, test inventory, and `nexus-effect-peer` do not change. The source
fingerprint nevertheless changes because these three evidence-boundary and
execution-wrapper files are intentionally locked. Accepting this increment as
preserving the bounded handoff-admission semantics is an explicit maintainer
judgement. It does not upgrade `real_ostd_execution_claimed`,
`joint_visa_execution_claimed`, or `real_ostd_smp_claimed`, and it does not turn
the separate APIC/debugcon evidence into a retained-tombstone joint claim.

Likewise, the 11 `negative_mutations` names are a contract-locked falsifier
catalog, not evidence that eleven independently source-mutated Nexus builds ran.

The current SQLite projection exercises atomic append/head update, reopen,
exact replay, conflict rejection, and retention of an unresolved effect-freeze
obligation. It is a local crash-recovery projection, not an ownership ledger or
a cross-host authority service. The reference ownership peer separately uses a
SQLite current-owner row and immutable handoff history; that test peer is not a
production or cross-host service.

The HostSubstrate vertical executes the local source and destination projection
through production `Coordinator<SqliteProvider>` APIs. Source abort, source
fence, and destination activation each append a durable attempt before local
mutation, an observed record bound to the resulting journal position and state
digest, and an integrity-bound completion afterward. The retained evidence has
an exact 14-record commit transcript and 9-record abort transcript. Seven
ownership/effect peer-invocation classes retain canonical pre-call bytes
separately from response-derived receipt issuance requests. The independent
verifier reconstructs every record window, peer request/response relation,
receipt chain, journal, lease, lost-completion-append acknowledgement, and the
destination pre-resume checkpoint. Destination resume is bound to the durable
activation completion-record digest rather than merely to an attempted local
mutation.

The current source lock pins remote-accepted neutral implementation
`f4a8211f0e5fde13e0f6101be3c3322854458c79` at tree
`a65f264bb7eaf390cbd6285d791b4f7f43e9be25`. Its machine contract SHA-256
is `f054fa08d48b7eed8fef18c274a464f66443410e6698474ff721bfb1a6b5cbf5`.
It freezes the field-level mapping and 16-case identity relation to the vISA
registry while explicitly keeping `adapter_qualification=false`. Its downloaded
exact-SHA artifact passed independent verification; later `be250c30...` is
receipt lineage, not the source identity. The reference lane runs those 16 cases plus one supplemental
post-commit retained-tombstone recovery, while the HostSubstrate cell supplies
the separate online vISA runtime refinement evidence.

The Nexus-local model/oracle/fault-matrix and production Registry refinement are
locked to clean revision `8e5123c46569e8ebdaba9f4f56bea6584ab58586`, source
fingerprint `017c681be01ca123a1df9625f16dd7b0367f861f7ac3be1476baf11a89070f52`,
matrix `9f3f1579172bf66dd5d58d2299c42dd4cb303cc74298c8d7a3a141e8cdcffd3e`,
and qualification-lock SHA-256
`21b5404bc5c1ad1f48c4ffe37cf455d104acac8ab9deca98f326d7c9b06072d9`.
Its v2 receipt records `production_registry_refinement_checked=true`. This does not
conflict with the neutral machine mapping's `adapter_qualification=false`: the
former is executed Nexus-local evidence, while the latter refuses to infer
adapter execution from a composition relation.

Exact-binary process tests pass against that revision. A generated receipt SHA
and locally built binary SHA identify one run, not the revision; final artifacts
retain the executed binary bytes and bind them by content without claiming a
reproducible source-to-binary derivation. The supplemental logical-request cell binds the completed logical operation through the
Nexus effect cohort, ownership Prepared/Commit, and Closure. The ownership fault
commits with SQLite WAL and `synchronous=FULL` before suppressing the Commit
acknowledgement; recovery reopens, queries, and retries the exact request. The
Nexus fault discards the real terminal child response before adapter acceptance
and admits only a byte-identical replay under the same request ID. The external
logical request, native Register, Prepare, and Commit each execute once, but in
that order: the cell is post-hoc observational binding, not Nexus admission of
the external effect or a vISA freeze/fence/activation vertical.

The standalone process-cell publisher requires clean exact vISA and Nexus
checkouts, validates both source locks and the Nexus receipt, publishes a strict
three-file manifest/report/executed-binary artifact, verifies it in a second
process, relocates it, and verifies the same bytes in a third. The supplemental
logical cell analogously publishes five files, including its two SQLite
databases and the executed binary. Verification statically validates the
retained binary content and does not re-execute it; file mode is not evidence.
The implementations and smoke passes are complete; the
final artifact still awaits the committed clean vISA SHA.

Therefore `bounded-joint-handoff-refinement-v1` remains a candidate. Final
clean-vISA local/Docker gates, exact-SHA remote CI, final artifact publication,
and a combined closing receipt are still required. The current architecture
does not establish host reboot or permanent source-loss recovery, real OSTD
execution, IRQ/SMP behavior, Registry replacement, the production
retained-tombstone path, cross-host transport, Byzantine ownership-service
behavior, cryptographic receipt authenticity, hostile-storage anti-rollback or
freshness, TEE/KMS behavior, confidentiality, or production readiness.

## Canonical state versus native binding

A logical resource is represented in two parts:

- `ResourceClaim`: portable identity, required rights, attributes, version,
  continuity policy, and compatibility constraints;
- `ResourceBinding`: a host-local descriptor, connection, provider object,
  device lease, or runtime handle held only by an adapter.

Bindings are never serialized as authority. The destination creates new
bindings after profile validation and reauthorization, then reports how each
claim was satisfied.

The bounded regular-file profile is one concrete application of this split.
Its canonical extension carries object identity, relative path, logical offset,
version, size, content digest, durability, lock state, and operation identity;
the Linux binding keeps fd, inode/device validation, anchored root, and
exclusive-lock mechanism native. Rename can change the path without changing
the logical object identity. Provider operations reject identity, content, or
version drift that is already observable before the operation. Concurrent
writers are ordered or rejected only when they participate in the same
advisory lock/lease protocol; the profile does not provide atomic
compare-and-mutate against an uncooperative writer that bypasses it.

On a qualified Linux filesystem, the provider derives a native identity for
both the opened root and regular file with fd-based `statx`: device, inode, and
birth time must all match the provider binding database. `STATX_BTIME` is a
required capability; absence fails closed instead of degrading to device/inode.
The tuple detects ordinary inode-number reuse when the replacement has a new
creation timestamp. It is neither a kernel inode-generation handle nor a
cryptographic identity and does not resist timestamp collisions, privileged
metadata manipulation, or a hostile host. Immediately before a file effect,
the provider also acquires the SQLite writer domain, rechecks intent,
authority, lease epoch, and pre-state, and retains that transaction through the
native effect and provider outcome. This orders vISA provider effects against
handoff commit at the effect-admission boundary. The native file change and
SQLite outcome are not one atomic transaction: a local finalization failure is
retained as indeterminate and must reconcile before canonical handoff. The
fence also does not serialize a writer outside the advisory protocol.

The bounded logical-request profile is another. Its canonical extension carries
peer identity, credential reference, logical operation ID, request digest,
phase, response cursor and metadata, rejection, and continuity disposition.
Socket/TCP sequence state, credential bytes, and runtime future state remain
native. The destination reconnects to a logical peer, reacquires credentials,
and consults a durable provider ledger for deduplication or reconciliation; a
raw live TCP transport is explicitly unsupported. The bounded `VISALR03`
protocol authenticates the configured peer identity before disclosing an
application request by using a fresh nonce and HMAC-SHA-256
challenge/response. Credential material remains provider-local and is never a
wire field. Lookup and Cancel also carry the expected request digest, so an
operation ID cannot resolve or cancel a different request. Immediately before
every authenticated Execute, Lookup, or Cancel frame, the provider enters the
same SQLite `BEGIN IMMEDIATE` domain as handoff commit and rechecks authority,
lease epoch, and resource binding while writing the frame. Execute binds the
digest derived by the peer from the authenticated request bytes; Lookup and
Cancel carry the expected digest explicitly. An immediate-transaction,
revision-checked compare-and-save plus terminal/cursor/cleanup checks prevents a
stale provider snapshot from rolling durable truth backward. This linearizes local send permission
against the SQLite handoff commit; it neither makes the remote effect atomic
with that commit nor claims general channel encryption.

Each resource profile declares a continuity disposition. The following names
are conceptual categories, not a frozen wire-format enum:

- `portable`: serialize the semantic resource state;
- `recreate`: construct a new equivalent local resource;
- `reconnect`: establish a new connection to the logical peer;
- `reattach`: attach to an externally preserved resource;
- `proxy`: temporarily route operations through another owner;
- `replay`: reconstruct from a journal under an explicit delivery policy; or
- `reject`: block continuity while the resource is live.

Adapters may implement these policies, but may not silently choose a weaker one.

Timer profiles must also define their portable time basis. Host monotonic
instants are neither serialized nor compared across machines. A profile may,
for example, preserve a remaining logical duration and pause it during handoff,
or use an explicitly trusted continuous-time source. An adapter must reject a
timer whose required clock semantics it cannot preserve.

## Effect semantics

Every externally relevant effect must have enough canonical information to
reason about recovery:

- operation identity and causal parent;
- subject and resource identity with generation;
- authority provenance and lease/fencing epoch;
- request and precondition;
- result, error, cancellation, or indeterminate status;
- delivery policy and optional idempotency key; and
- postcondition and cleanup outcome.

vISA does not promise universal exactly-once execution. A resource profile must
state whether an effect is at-most-once, at-least-once, deduplicated,
replayable, or non-recoverable. An unknown result for a non-idempotent effect is
a continuity blocker unless the profile provides a safe resolution protocol.

The runtime cannot make an arbitrary external effect and a local canonical
state update physically atomic. Instead, it must persist enough intent and
outcome information to distinguish a committed result from failure,
cancellation, or an indeterminate result, then apply the resource profile's
idempotency, fencing, reconciliation, or rejection rule.

The conceptual operation lifecycle is:

```text
RECEIVED
  -> VALIDATED
  -> AUTHORIZED
  -> PREPARED
  -> IN_FLIGHT
  -> SUCCEEDED | FAILED | CANCELLED | UNSUPPORTED | INDETERMINATE
  -> CLEANED | RETAINED according to policy
```

These states define required semantics, not final API or wire-format names.

## Continuity lifecycle

The target lifecycle is:

```text
RUNNING
  -> QUIESCING
  -> FROZEN
  -> EXPORTED
  -> DESTINATION_PREPARED
  -> COMMITTED
  -> DESTINATION_RUNNING
```

The phases mean:

1. **Quiescing:** stop admitting new effects; complete, cancel, drain, or mark
   every in-flight operation according to its profile.
2. **Frozen:** all borrowed handles are returned and every live resource has a
   known disposition.
3. **Exported:** emit the portable state envelope without destroying source
   state or authority.
4. **Destination prepared:** validate compatibility, artifact identity,
   extensions, state integrity, and target authority; create candidate
   bindings without making the destination active.
5. **Committed:** publish one durable ownership decision, advance the fencing
   epoch, and make the old source authority unusable at the provider boundary.
6. **Destination running:** publish the restored activation and resume effects.

Before commit, failure must permit an explicit abort and continued source
execution. After commit, the source must be unable to act with the old lease.
Lost acknowledgements, retries, duplicate messages, and destination crashes must
not create two active owners.

If a failure happens after commit, the source remains fenced. Only the
destination or an explicit recovery protocol may continue; restarting both
sides is not an availability strategy. An indeterminate external effect must be
reconciled or surfaced, never converted to an assumed failure.

## Core invariants

All conforming implementations must preserve:

1. **Single truth:** one canonical state and journal define committed behavior.
2. **No native truth:** fd values, socket handles, host paths, native pointers,
   page tables, DMA/MMIO bindings, PC/SP/register frames, and runtime object IDs
   are never portable authority or semantic identity.
3. **Generation safety:** a stale reference or binding cannot become live again
   after replacement, revocation, cleanup, or restore.
4. **Authority monotonicity:** restored authority is equal to or narrower than
   compatible source authority; a snapshot never grants permission by itself.
5. **Failure atomicity:** rejection or pre-commit failure cannot leave a partial
   canonical transition or an active destination.
6. **Explicit uncertainty:** unknown completion, unsupported authority, and
   degraded behavior are visible results, never silent success.
7. **Idempotent cleanup:** repeated cancellation, abort, and cleanup cannot
   resurrect state or apply destructive effects twice.
8. **Source fencing:** at most one lease epoch can act after handoff commit.
9. **Derived projections:** views, snapshots, reports, and evidence are derived
   from committed truth and cannot override it.
10. **Claim honesty:** an implementation claims only the runtime, ISA,
    substrate, resource, fault, and authority dimensions actually exercised.

## Profiles, extensions, and compatibility

The stable core models common lifecycle and safety rules. Resource families,
personalities, providers, and experimental capabilities use versioned, typed
profiles or extensions rather than expanding one universal object enum.

Compatibility is established before execution:

- an unknown required extension rejects the load or restore;
- an unknown optional extension may be preserved as opaque data only when no
  behavior depends on interpreting it;
- authority and continuity requirements may not silently downgrade;
- version transitions require declared and tested transforms; and
- host layout or implementation details never define wire compatibility.

The exact serialization library and compression strategy are deferred. The
requirements for canonical representation, versioning, integrity, and unknown
data behavior are not deferred.

## Evidence dimensions

Evidence is a product of independent dimensions, not one strength ladder:

```text
compute-state carrier
  x runtime implementation
  x host ISA
  x substrate/provider
  x resource profile
  x authority enforcement
  x fault coverage
  x artifact and run provenance
```

For example, a real hardware run does not by itself prove cross-runtime
portability, and a portable artifact harness does not prove real device
authority. Every public claim must point to the executable matrix cell that
supports it.

Evidence validation uses a stable artifact view rather than ambient pathnames.
The Linux implementation anchors a root directory descriptor, opens contained
regular files with kernel-enforced `openat2` resolution, and binds each
reference digest and semantic parser to the same captured bytes. Stage 2 inner
audits and normalization reuse the verified Stage 1 view instead of reopening
the tree. Concurrent replacement cannot escape the anchored root or make the
digest and semantic parser observe different path targets. A contained regular
file that wins the race before `open` is accepted only when its captured bytes
satisfy both the declared digest and semantic checks. This does not turn the
verifier process or publication topology into a general hostile-same-UID
security boundary.

Runtime load carriers declare their own narrower boundary. JcoNode captures the
accepted generated JavaScript and core-Wasm graph as owned bytes, binds its
manifest and generated-graph digest to those bytes, and sends a versioned,
bounded startup frame to a compiled-in Node driver. The driver verifies the
frame before importing the JavaScript from a data URL or compiling core modules
from memory. The publisher's former pathname tree is therefore absent from the
final execution path. This protects against post-capture file, directory,
symlink, and publication-root replacement; it does not protect a compromised
Node execution environment or toolchain, including its loader and shared
libraries, ptrace or process-memory modification, process takeover, or denial
of service.

## Dependency direction

The intended logical dependency direction is:

```text
contract schema
    <- canonical reducer
    <- runtime coordinator
    <- engine/personality and substrate adapters
    <- tools, scenarios, benchmarks, and conformance runners
```

Wire schemas and validators may depend on stable contract/profile types, but
core validation must not depend on reference services, catalogs, benchmarks,
or host tools. Adapters may translate native facts into canonical effects; core
code must not import adapter-specific representations.

## Evolution of the current repository

Stage 1 completed this migration for its named reference path. Stage 2a
extracted the one runtime-neutral component adapter contract; Stage 2b added
the JcoNode reference execution cell; Stage 2c now exercises all four
directions without adding a second semantic implementation. The strict path
subsequently adds the qualified Wacogo runtime through the same adapter,
coordinator, semantic-state, and evidence boundaries without adding a second
semantic authority. Stage 3A and Stage 3B then extend the shared profile port
and reducer/coordinator path with bounded regular-file and logical-request
extensions, while retaining separate resource-specific WIT, codecs, providers,
registries, and verifiers. Bounded Stage 4 next varies the named target and
QEMU-user execution endpoints around the fixed Stage 1 Wasmtime timer/KV
control, without importing ISA-, loader-, or QEMU-specific identity into the
portable semantic core. As the broader repository evolves:

- do not expand legacy universal object, command, event, or snapshot schemas;
- migrate one complete lifecycle slice at a time and delete the replaced model
  and projection before calling the slice complete;
- allow old paths only as read-only comparison oracles, never as a second
  write authority;
- move benchmark, fault-injection, fake-provider, Linux-specific, Virtio, and
  filesystem implementation concepts out of the canonical vocabulary;
- make the runtime coordinator the only commit path before expanding behavior;
  and
- describe current implementation gaps honestly in README and validation docs.

Crate names, internal data structures, serialization libraries, async runtime,
cache design, and performance optimizations remain reversible implementation
decisions. The boundary, dependency direction, invariants, compatibility rules,
and claim semantics are durable architectural commitments.

Stage 1 fixes one reference continuity unit and profile, snapshot encoding,
SQLite journal/lease mechanism, and Wasmtime/x86-64 Linux/resource matrix cell.
The completed Stage 2a, 2b, and 2c engineering substages add a shared adapter
contract plus a Jco-translated Node/V8 execution path while retaining only the
legacy `cross-execution-path-portability` claim. The separate strict path adds
the source-lock-bound Wacogo derivative and has executed the exact four
Wasmtime/Wacogo cells over the same x86-64/amd64 Linux timer/KV profile, with
124/124 executions and 31/31 equality groups passing independent verification.
Roadmap Stage 2 is complete for this named matrix and claim. Cross-host
transport, alternative persistence and lease services, compatibility windows,
confidential continuity, performance targets, and production readiness remain
unimplemented. Roadmap Stage 3 is complete for the two bounded resource
profiles described above after their stage-closing implementation revision
passed pushed CI at its exact commit. They do not claim arbitrary directory
trees or open descriptors, preservation of raw live TCP, generic future/stream
continuation, a general async runtime, or a qualified second Stage 3 runtime.
Bounded Stage 4 is complete for the exact Hx/Qx/Qa matrix and two named claims
described above, including exact-SHA workflow and downloaded relocated-bundle
verification. It does not extend the claims to real ARM hardware, AOT-binary
portability, Stage 3 resources across targets, the no-std kernel, or a second
Stage 4 runtime.
