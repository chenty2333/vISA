# Implementation Plan: Stage 2b Jco/Node Reference Execution Cell

Status: accepted

## Entry Condition

Complete `005-stage2a-runtime-adapter-contract` first and retain a fresh,
independently verified Wasmtime-to-Wasmtime 31/31 bundle. The shared state
codec, failure kinds, runtime selector, preflight ordering, and lifecycle/host
contract must have one definition before the JcoNode implementation begins.

The completed feasibility spike is an entry input, not completion evidence. It
established that Jco 1.25.2 with `js-component-bindgen` 2.0.11 can translate the
existing Component artifact, that Node v24.15.0/V8
13.6.233.17-node.48 can execute the generated graph, and that this path can
represent the profile's owned resources. It also established that the
translator uses `wasmtime-environ` 45.0.1, so this plan intentionally narrows
the resulting claim.

## Design Commitments

`visa_jco_node` is a concrete implementation of the Stage 2a adapter contract,
not a new semantic layer. `semantic_core` remains the only transition
authority. `visa_runtime::Coordinator` remains the only production sequencer
and commit path. The SQLite provider remains behind that coordinator. Shared
component state, binding/effect logic, lifecycle ordering, and normalized
failures remain in `visa_component_adapter`.

The path contains two materially different phases:

```text
original Component bytes
  -> pinned Jco/js-component-bindgen translation and checked output graph
  -> generated JavaScript plus core Wasm
  -> pinned Node/V8 guest execution
```

Evidence identifies both phases. Node/V8 independence is real at execution
time; full Component Model implementation independence is not claimed because
of the translator lineage.

The worker continues to use a closed enum over concrete adapters. It may add
`JcoNode` and concrete `PreparedAdapter`/`AdapterInstance` variants; it does not
add a dynamic plugin ABI, trait-object registry, or adapter-specific lifecycle
copy.

## Target Structure

```text
crates/runtime/visa_jco_node/
  Cargo.toml
  src/
    lib.rs
    adapter.rs
    driver.mjs
    error.rs
    preflight.mjs
    preflight.rs
    process.rs
    protocol.rs

crates/testing/visa-system/
  runtime-cell selection and JcoNode worker dispatch

crates/testing/visa-conformance/
  JcoNode provenance and no-overclaim validation
```

Files may be combined when that produces a clearer small module. Generated
Jco output belongs under a private build/run artifact directory, not in
`src/`, and is never hand-edited.

## Exact Toolchain and Provenance

The adapter calls the Rust `js-component-bindgen` API directly; it does not
install or invoke an npm Jco CLI. Its Cargo manifest pins
`js-component-bindgen` to `=2.0.11` and the disclosed translator dependency
`wasmtime-environ` to `=45.0.1`; `Cargo.lock` records their crates.io sources
and checksums. The Jco 1.25.2 value is the compatibility/source-lineage
identity recorded by this adapter, not a claim that an npm package is present.

The accepted execution toolchain is:

```text
Jco                         1.25.2
js-component-bindgen        2.0.11
wasmtime-environ lineage    45.0.1
Node                        v24.15.0
V8                          13.6.233.17-node.48
```

The Cargo lock entries/checksums, Node executable path/hash,
`process.versions`, translation options, original Component hash,
world/profile hash, driver source, and generated output graph are checked by
toolchain/build/run provenance. The sorted per-file output manifest is
runtime-local and non-serializable. Retained evidence contains only the
aggregate generated-tree digest, driver digest, and ordered core-module digest
list. CI installs the official pinned Node archive after SHA-256 verification.
It never invokes a global Jco command, `npm`, or `npx`.

## Translation and Preflight Design

`JcoNodeRuntime::preflight` first calls the shared
`validate_preflight_contract`. It then verifies the toolchain lock, translates
the supplied bytes with a fixed option set into a private directory, enumerates
the complete generated graph into a sorted runtime-local per-file manifest,
rejects path escapes or unmanifested outputs, and hashes every JavaScript,
core-Wasm, and metadata file. It verifies that the graph implements the
accepted cooperative-handoff world and that Node can parse the driver/generated
modules without importing or executing the guest.

The resulting `PreparedJcoNode` contains only process-local ownership and
verified references:

- selected implementation and adapter version;
- original component and profile digests;
- exact translator/Node identities;
- generated graph root plus the sorted runtime-local content manifest; and
- the fixed driver and RPC protocol versions.

It does not contain a coordinator, provider, guest process, resource binding,
or canonical state. The per-file manifest is part of this opaque prepared value;
it is never serialized into retained evidence, portable state, or a snapshot. A
content-addressed translation cache is allowed only when its key covers all
inputs above and every cache hit revalidates the manifest. Cache identity and
paths remain execution metadata. A miss and a hit must produce equivalent
preflight results and neither may execute guest code.

For a destination, `Coordinator::restore`, binding preparation, and durable
commit remain after successful preflight. `instantiate_prepared_recoverable`
revalidates the prepared graph, then starts Node and imports/instantiates the
generated module only after commit. If Node startup or module instantiation
fails, it returns the unchanged coordinator so the worker can report the
post-commit operational failure while retaining canonical truth.

For a source, the same prepared path may instantiate the Node guest during
source recovery/initialization before any guest export runs. Activation or
thaw still occurs only through the common lifecycle contract.

## Synchronous RPC Design

Each `visa_jco_node` instance owns one Node child with dedicated stdin/stdout
pipes. Node stdout is a strict, one-MiB-bounded protocol channel; stderr is
diagnostic-only and is not semantic evidence. Before spawn, Rust revalidates
the complete generated graph and fixed driver/helper bytes against the
runtime-local manifest. `NodeProcess::spawn` then consumes and strictly
validates the versioned Node/V8 `ready` envelope, including protocol, versions,
fields, and zero initial resources. The envelope is adapter-internal and is not
persisted. Together these checks bind the prepared graph to startup without
asking the child to self-assert a graph digest.

The protocol is a strict nested state machine:

```text
Rust sends one lifecycle-call request
  Node may send zero or more host-call/resource-drop requests
    Rust validates and answers one request synchronously
  Node sends exactly one lifecycle result
  Node sends one matching settled boundary
Rust returns to the shared lifecycle implementation
```

There is no second concurrent lifecycle call and no asynchronous callback in
this profile. Correlation IDs are monotonic within a connection. Unknown
messages, responses without requests, duplicate or skipped correlation IDs,
wrong resource kinds, invalid result/error shapes, missing or mismatched settled
boundaries, trailing frames, oversized frames, or child EOF terminate the
instance and become structured adapter failures. In particular, a lifecycle
result is provisional until Rust consumes the matching settled frame; this
removes any scheduling assumption from the result-to-EOF boundary. A production
child-call timeout policy is not part of this research cell's availability
claim and remains explicit follow-up hardening.

Semantic/WIT `u64` values use canonical decimal text; protocol-local command,
host-call, and resource IDs are positive JavaScript-safe integers. Byte lists
use bounded JSON byte arrays, WIT results use exact tagged variants, and every
message carries an explicit protocol version. Conversion and fake-child tests
cover malformed UTF-8/JSON, unknown or missing fields, wrong versions/types/
IDs, invalid result/error shapes, missing or mismatched settlement, trailing
frames, oversized frames, and EOF. The protocol does not carry canonical
commands, events, snapshots, authority grants, provider credentials, or SQLite
details.

## Host Resource Design

Before `activate`, `thaw`, or `restore`, Rust derives one `BindingSet` from the
coordinator and inserts its KV and timer bindings into a typed, instance-local
table. Node receives only opaque IDs wrapped by the Jco-generated owned-resource
surface. Method requests return to Rust, which looks up the binding and calls
the existing `kv_read`, `kv_conditional_put`, `timer_arm`, or `timer_cancel`
helper against its coordinator.

When guest ownership ends, generated/Jco resource drop calls remove the Rust
entry. Freeze succeeds only when the guest returned both profiled resources and
the Rust table is empty. Source rollback recreates bindings through
`BindingSet::for_state`; it never revives old IDs. Test-control for the existing
unsupported-live-resource case must retain a real unreturned entry in this
path's table and exercise the same common safe-point rejection, not short-
circuit the worker scenario.

Child exit closes and invalidates all local IDs. Cleanup may reclaim those
process-local entries, but it cannot invent a guest success, change a canonical
outcome, or unfence a committed source.

## Worker and Runner Design

Add `JcoNode` to the existing runtime selector and concrete dispatch enums.
Every worker initialization receives its selector explicitly. Source and
destination workers start separate Node children and validate separate
handshakes; their process IDs and handle namespaces must differ.

Parameterize the Stage 1 runner by an explicit pair:

```text
RuntimeCell {
  source: Wasmtime | JcoNode,
  destination: Wasmtime | JcoNode,
}
```

This slice executes `JcoNode -> JcoNode` and reruns `Wasmtime -> Wasmtime`.
The mixed pairs may compile only as selector plumbing if unavoidable, but they
must remain unclaimed and unexecuted until Stage 2c. Any requested adapter that
cannot initialize returns a structured failure; dispatch never catches it and
retries with the other variant.

Runtime identity is established in two layers. Initialization retains the
requested and preflight-verified adapter/toolchain identity without guest
execution; instantiation revalidates the runtime-local manifest immediately
before spawn, and the adapter internally validates the Node/V8 `ready`
envelope. Retained typed instantiation is then inferred only after successful
bootstrap or destination post-commit resume protocol progression; the raw
`ready` envelope is not retained. Cases intentionally rejected before
destination instantiation record that boundary explicitly rather than
fabricating a typed instantiation observation.

## Evidence Design

The JcoNode-to-JcoNode run continues to emit the existing Stage 1 per-case
semantic bundle and only the
`CooperativeStatefulComponentHandoff` claim. Its environment identifies the
named JcoNode adapter plus Node/V8 engine. Its hashed toolchain/matrix manifests
add:

- execution-path classification `translated-component-execution-path`;
- original Component and accepted world/profile hashes;
- Jco, `js-component-bindgen`, and disclosed `wasmtime-environ` lineage;
- Cargo manifest/lock source and integrity hashes;
- Node binary and adapter-verified Node/V8 versions;
- driver/RPC source and protocol versions;
- aggregate generated-tree digest, driver digest, and ordered core-module
  digest list;
- requested and preflight-verified identity plus typed instantiation inferred
  from successful protocol progression; and
- explicit `strict_component_model_runtime_independence: not-proven`.

The runtime-local sorted per-file manifest remains the enforcement mechanism for
missing, extra, changed, linked, or escaping files immediately before spawn. It
is deliberately not part of retained evidence, and the adapter-consumed `ready`
envelope is likewise not persisted.

Stage 2b acceptance combines the complete independent Stage 1 bundle/artifact
validation with the locked JcoNode toolchain check. Stage 2c then places this
unchanged inner bundle beside the other three cells and independently audits
the initialization and typed-instantiation observations, exact aggregate
translation provenance, same-input identity, absence of fallback, and
overclaim guards. It does not rewrite the 31-case semantic truth.

Stable semantic comparison dimensions remain the 31 IDs/outcomes, normalized
traces, state/replay digests, authority/fencing, receipts, fault schedules,
and portable component-state bytes. Process IDs, RPC IDs, local handles,
generated paths, runtime diagnostics, timing, bundle IDs, and whole-bundle
hashes are deliberately not equal across engines.

## Delivery Sequence

1. Finish Stage 2a and record its focused plus Wasmtime 31/31 baseline.
2. Pin the exact Rust translation dependencies and official Node archive plus a
   machine verifier for the accepted toolchain.
3. Add `visa_jco_node` and enforce one-way dependencies from the concrete
   adapter to the shared contract, never back into the core/coordinator.
4. Implement translation preflight, output-graph hashing, prepared-value
   validation, and no-guest-execution tests.
5. Implement the Node driver handshake and adapter-private synchronous RPC with
   exhaustive conversion/protocol tests.
6. Implement the Rust typed resource table and route all host calls through the
   shared host bridge and the one coordinator.
7. Implement the concrete runtime factory/instance methods by forwarding guest
   calls through RPC while reusing the shared lifecycle implementation.
8. Add `JcoNode` to worker prepared/instance dispatch, structured failure
   mapping, actual identity reporting, crash cleanup, and the no-fallback tests.
9. Parameterize the runner by a runtime pair and run focused successful,
   rollback, live-resource, preflight-rejection, and child-failure cases.
10. Execute and independently validate all 31 JcoNode-to-JcoNode cases with
    exact translation/Node provenance.
11. Rerun and independently validate all 31 Wasmtime-to-Wasmtime cases and
    compare stable Stage 1 dimensions.
12. Run locked local and Docker gates, audit dependencies/transcripts/claims,
    and record completion without closing strict Stage 2.

## Validation

```sh
python3 scripts/check-jco-node-toolchain.py
cargo fmt --all --check
cargo test --locked -p visa_component_adapter -p visa_jco_node \
  -p visa_wasmtime -p visa-system -p visa-conformance
cargo clippy --locked -p visa_component_adapter -p visa_jco_node \
  -p visa_wasmtime -p visa-system -p visa-conformance \
  --all-targets -- -D warnings
python3 scripts/check-dependency-direction.py
python3 scripts/check-stage1-deletions.py
scripts/ci-gate.sh fast
scripts/ci-gate.sh full
scripts/ci-gate.sh system
scripts/ci-gate.sh system-jco-node
scripts/run-docker-ci-gate.sh full
scripts/run-docker-ci-gate.sh system
scripts/run-docker-ci-gate.sh system-jco-node
git diff --check
```

`check-jco-node-toolchain.py` and the `system-jco-node` tier are deliverables of
this slice; they do not exist at the entry point. The new system tier must run
the full 31-case JcoNode cell and a separate conformance process, not substitute
focused tests or a fixture manifest.

## Constraints

- Do not modify the guest Component or accepted WIT world for Jco compatibility.
- Do not duplicate the reducer, coordinator, state codec, effect derivation,
  binding rules, or lifecycle rollback in JavaScript or the concrete adapter.
- Do not load the generated destination guest before durable commit.
- Do not let Node access SQLite/provider ports or accept canonical commands from
  untrusted RPC input.
- Do not infer successful resource drop only from JavaScript garbage
  collection; require the generated owned-resource drop path and an empty Rust
  table.
- Do not hide translator lineage, substitute an unlocked tool, or label this
  cell a genuinely independent Component Model runtime.
- Do not use Wasmtime for any selected JcoNode guest execution or fallback.
- Do not run or claim the mixed cells before Stage 2c.
- Preserve all Stage 1 semantic/evidence ordering and keep execution-local
  identifiers out of portable truth.
