# Feature Specification: Stage 2b Jco/Node Reference Execution Cell

Status: accepted

Stage 2b adds a second named execution path for the completed cooperative
handoff profile. The exact Component artifact used by Wasmtime is translated
by Jco and executed as generated JavaScript plus core WebAssembly in a separate
Node/V8 process. The Rust coordinator, reducer, journal, authority checks, and
SQLite provider remain the only semantic and durable truth.

This is deliberately called an **execution cell**, not proof of a genuinely
independent Component Model runtime. The accepted toolchain is Jco 1.25.2 with
`js-component-bindgen` 2.0.11, whose translator dependency graph includes
`wasmtime-environ` 45.0.1. Node/V8 is an independent execution engine after
translation, but that shared Component Model translation lineage leaves the
strict Stage 2 independence claim open. The cell is useful engineering
evidence and prepares the four-direction matrix in Stage 2c without overstating
what it proves.

## Scope

- Add a `visa_jco_node` adapter implementation for the Stage 2a
  `visa_component_adapter` contract.
- Translate the same immutable cooperative-handoff Component bytes used by the
  Wasmtime cell into a checked JavaScript/core-Wasm execution graph.
- Run each source and destination guest in its own Node process while retaining
  the existing isolated Rust worker processes and shared durable SQLite truth.
- Route synchronous WIT host calls from Node back to the owning Rust adapter,
  and from there through the shared host bridge and
  `visa_runtime::Coordinator`.
- Implement owned KV/timer resource creation, method dispatch, drop, safe-point
  emptiness, and source rollback over fresh execution-local handles.
- Add an explicit `JcoNode` worker selector, observed execution identity,
  structured adapter failures, and a strict no-fallback rule.
- Execute the unchanged 31-case registry as a JcoNode-to-JcoNode cell, validate
  its evidence independently, and retain the Wasmtime-to-Wasmtime regression.

## Claim Boundary

The accepted names have precise meanings:

- **JcoNode execution path:** vISA's Rust adapter, Jco translation output, the
  Node driver, and V8 core-Wasm execution considered as one named path.
- **JcoNode-to-JcoNode cell:** separate source and destination Rust workers,
  each owning a separate Node guest process selected as `JcoNode`.
- **Independent execution engine:** the guest core Wasm executes in V8 rather
  than the Wasmtime engine.
- **Not proven:** independence of the complete Component Model implementation,
  because the pinned translator includes `wasmtime-environ` in its lineage.

`JcoNode` may occupy the B slot in the engineering matrix. Evidence, logs,
documentation, and validator output must not rename it to an
`IndependentRuntimeB`, add `CrossRuntimePortability`, or mark roadmap Stage 2
complete.

## Process and Authority Boundary

The production test path is:

```text
visa-system runner
  -> source Rust worker -> visa_jco_node -> source Node/V8 guest
  -> destination Rust worker -> visa_jco_node -> destination Node/V8 guest

Node guest host call
  -> adapter-private synchronous RPC
  -> visa_component_adapter host bridge
  -> visa_runtime::Coordinator
  -> substrate_host::SqliteProvider
  -> normalized WIT result over the same RPC connection
```

The Node process owns only generated guest execution, generated WIT lifting and
lowering, guest-local state, and mirror objects for execution-local resource
handles. It cannot open the provider database, append a journal event, decide
authority, derive a canonical effect independently, commit handoff, or maintain
a reducer/state ledger. The Rust adapter owns the live handle table and the
single coordinator used by all host calls for that instance.

The RPC protocol is adapter-private execution transport. It is versioned and
typed, but it is not a portable vISA contract, snapshot format, journal, or
evidence truth source. One lifecycle request is in flight at a time. During
that request Node may issue synchronous nested host-call or resource-drop
requests; Rust must answer each before Node continues and before the lifecycle
result is accepted. After that result, Node must emit a matching `settled`
frame proving that the command reached the reusable protocol boundary; a result
followed by EOF or any other frame is not accepted. Request IDs, resource kinds,
call ordering, integer ranges, byte encoding, frame limits, and terminal states
are validated. In particular, WIT `u64` values cross the JSON boundary as
canonical decimal strings rather than lossy JavaScript numbers.

## Artifact and Preflight Boundary

The original `.component.wasm` bytes and their existing component digest remain
the artifact identity used by the profile, snapshot, coordinator, and both
execution cells. Generated JavaScript, core-Wasm modules, import shims, paths,
and Jco metadata are derived execution artifacts. They receive their own
content hashes and provenance, but they never replace or alter the original
component digest.

JcoNode preflight must:

1. execute the shared profile/component digest checks;
2. verify the exact locked translator and Node toolchain;
3. translate the original Component with fixed, recorded options;
4. validate the complete generated output graph, required imports/exports, and
   hashes; and
5. return an opaque prepared value bound to the runtime selector, component
   digest, profile digest, runtime-local per-file manifest, and exact Node
   executable.

Preflight may run the translator, inspect generated files, and execute a
non-guest Node version/syntax probe. It must not import or instantiate the
generated guest module, call a guest export, create guest-visible resources,
restore a coordinator, mutate a provider, or append evidence of guest
execution. Destination Node module loading and guest instantiation remain
post-commit operations. Before using a prepared value, the adapter rechecks its
digests and tool identity; it must not silently translate different bytes or
select a different executable. Every preflight and execution Node command uses
the same locked launcher and removes ambient `NODE_OPTIONS`, so inherited
`--require` or `--import` hooks cannot redefine the declared execution cell.

The prepared token and its sorted per-file manifest remain process-local and
non-serializable. The adapter uses that manifest to reject missing, extra,
changed, linked, or escaping files immediately before spawn. Retained evidence
does not copy the manifest; it identifies the execution graph only through the
aggregate generated-tree digest, driver digest, and ordered core-module digest
list. None of these derived artifacts becomes portable component state or
canonical truth.

This reference cell assumes its process-private temporary directory is not
concurrently modified by another actor with the same host UID between the last
manifest check and Node loading the files. Pre-spawn revalidation detects
earlier mutation; it is not a sealed-artifact or hostile-co-tenant guarantee.
Closing that load-time TOCTOU would require an atomic or sealed execution
carrier and is part of later production/security hardening, not evidence earned
by this slice.

## Requirements

- **FR-001**: Wasmtime and JcoNode must consume the exact same original
  Component bytes and component digest. No Jco-specific guest source, WIT
  world, relinked Component, or destination-specific behavior is allowed.
- **FR-002**: The accepted execution baseline must pin Jco 1.25.2,
  `js-component-bindgen` 2.0.11, `wasmtime-environ` 45.0.1, Node v24.15.0, and
  V8 13.6.233.17-node.48. Cargo source/checksum integrity, translator lineage,
  translation options, and executable identity must be recorded. Every
  generated file must be hashed in the runtime-local manifest; retained
  evidence records only the aggregate generated-tree, driver, and core-module
  digests.
- **FR-003**: A floating Cargo range, unlocked translator dependency,
  unverified global `jco`, unverified `node` from `PATH`, or manually asserted
  transitive version is not an accepted toolchain pin. The current adapter
  uses the locked Rust translation API and must not add an npm/npx download.
- **FR-004**: JcoNode preflight must reject an invalid artifact, digest/world
  mismatch, unsupported generated interface, missing or wrong tool version,
  or modified translation graph before coordinator restore, destination
  binding preparation, or durable commit.
- **FR-005**: Destination preflight must not execute guest code. Destination
  Node guest instantiation remains after durable commit and source fencing;
  operational failure after that point is explicit and leaves the source
  fenced.
- **FR-006**: Executing a JcoNode instance must not load or invoke the Wasmtime
  engine, `visa_wasmtime`, a Wasmtime Store/Linker, or a Wasmtime fallback. The
  translator's `wasmtime-environ` lineage remains disclosed as build/preflight
  provenance.
- **FR-007**: Every guest KV/timer method call must synchronously enter the
  instance's Rust coordinator through the shared Stage 2a host bridge. Node may
  not call SQLite/provider ports directly or reproduce operation,
  idempotency, authority, lease, or outcome logic.
- **FR-008**: RPC messages must be typed and correlated, preserve WIT integer
  and byte values exactly, reject unknown/duplicate/out-of-order messages, and
  map transport, process-exit, translation, guest-trap, and workload failures
  to stable structured adapter/workload kinds. Engine text is diagnostic only.
- **FR-009**: Rust creates fresh KV/timer bindings from `BindingSet`, stores
  them in an execution-local typed handle table, and validates every use and
  raw drop. Node owns only mirror resource objects. Repeated high-level
  disposal is locally idempotent; unknown, stale, wrong-kind, duplicate raw
  drops, and leaked handles are rejected without resurrection.
- **FR-010**: Successful freeze must return all guest-owned imported resources
  and leave the Rust handle table empty. Safe-point rejection and source thaw
  must follow the shared lifecycle rollback path with fresh bindings, not a
  JcoNode-specific recovery ledger.
- **FR-011**: Source and destination use distinct Rust worker processes,
  distinct Node processes, distinct guest module instances, and distinct local
  handle namespaces. Neither process may inherit or reuse the other's guest
  globals or native handles.
- **FR-012**: Worker selection must add exactly one `JcoNode` implementation
  with no implicit default or fallback. Missing tools, failed translation,
  child startup failure, protocol failure, or unsupported behavior fails or
  explicitly skips the cell; it never substitutes Wasmtime.
- **FR-013**: Requested and preflight-verified execution identities must agree.
  The generated graph and driver are bound by runtime-local pre-spawn manifest
  revalidation, and the adapter must internally validate the Node/V8 `ready`
  envelope. The envelope is not persisted; retained typed instantiation is
  inferred only from successful bootstrap or post-commit resume protocol
  progression. A destination rejected before instantiation is recorded as
  preflighted/not-instantiated rather than assigned an instantiation
  observation.
- **FR-014**: Runtime selector, process IDs, RPC request IDs, handle IDs,
  generated paths, translator objects, and Node/V8 internals are execution
  metadata only and cannot enter the profile, portable state, snapshot,
  journal, canonical trace, or state digest.
- **FR-015**: The unchanged 31 case IDs, fault schedules, allowed outcomes,
  normalized traces, final/replay state digests, authority decisions, source
  fencing, cancellation, cleanup, and report-failure behavior must execute for
  JcoNode-to-JcoNode.
- **FR-016**: Each applicable case must exercise the selected JcoNode path.
  Worker-side emulation of guest exports, replaying Wasmtime outputs, or
  bypassing Node for a hard case is forbidden. Expected preflight and
  pre-instantiation rejection cases remain honestly non-executing.
- **FR-017**: The JcoNode cell's evidence must reference the original Component,
  aggregate generated-tree digest, driver digest, ordered core-module digest
  list, exact toolchain/lock integrity, adapter-verified Node/V8 identity,
  adapter/driver sources, raw worker transcripts, and the existing Stage 1
  semantic artifacts by checked hashes. The runtime-local per-file manifest and
  adapter-consumed `ready` envelope are not retained. Generated artifacts remain
  runtime provenance, never portable truth.
- **FR-018**: Acceptance must compose the complete independent Stage 1 bundle
  verifier with the locked JcoNode toolchain gate; the Stage 2 outer verifier
  additionally rejects selector/identity mismatch, missing translation
  provenance, changed generated artifacts, fallback identity, missing cases,
  or any broader claim.
- **FR-019**: The Wasmtime-to-Wasmtime 31-case cell must continue to pass after
  adding the second implementation. No mixed-runtime cell is claimed in this
  slice.
- **FR-020**: Focused adapter/protocol/resource tests, the complete local
  JcoNode cell, its independent verifier, the Wasmtime regression, and the
  corresponding locked Docker gates must pass.

## Non-goals

- Claiming a genuinely independent Component Model implementation or closing
  roadmap Stage 2.
- Running Wasmtime-to-JcoNode or JcoNode-to-Wasmtime; those cells belong to
  Stage 2c.
- Cross-ISA execution, file/network resources, WASI 0.3 async, arbitrary
  Component worlds, a general JavaScript host SDK, or a dynamic runtime plugin
  system.
- Moving the coordinator, reducer, provider, journal, authority enforcement,
  snapshot validation, or evidence derivation into Node.
- Serializing JavaScript objects, V8 state, RPC handles, Node module state, or
  generated file paths as portable component state.
- Using a Wasmtime wrapper, a destination-specific component, a mocked guest,
  or a silent fallback to make the second cell green.
- Production, security-isolation, confidential-computing, or performance
  claims for Node, Jco, the RPC bridge, or the overall system.

## Completion Rule

Stage 2b is complete only when exact locked Jco/Node translation provenance is
machine-checked, the same original Component digest executes through isolated
JcoNode source and destination processes, all synchronous host effects pass
through the one Rust coordinator, owned resources and rollback satisfy the
shared adapter contract, all 31 JcoNode-to-JcoNode cases and their independent
evidence validation pass, the Wasmtime 31-case regression remains green, and
local/Docker results agree without any fallback. Completion earns one named
second execution-path cell; it does not earn `CrossRuntimePortability`, strict
Component Model runtime independence, or completed Stage 2.
