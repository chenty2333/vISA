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
File/network profiles, cross-ISA cells, confidential continuity, and production
readiness are not implemented.

Last reviewed: 2026-07-13.

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

## Canonical state versus native binding

A logical resource is represented in two parts:

- `ResourceClaim`: portable identity, required rights, attributes, version,
  continuity policy, and compatibility constraints;
- `ResourceBinding`: a host-local descriptor, connection, provider object,
  device lease, or runtime handle held only by an adapter.

Bindings are never serialized as authority. The destination creates new
bindings after profile validation and reauthorization, then reports how each
claim was satisfied.

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
semantic authority. As the broader repository evolves:

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
file/network resources, cross-ISA matrices, confidential continuity,
performance targets, and production readiness remain unimplemented.
