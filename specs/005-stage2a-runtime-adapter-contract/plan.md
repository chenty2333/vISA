# Implementation Plan: Stage 2a Runtime-Neutral Component Adapter Contract

Status: accepted

## Entry Condition

Complete `004-stage1-spine-modularization` and record one fresh 31/31 Stage 1
bundle before changing adapter ownership. Do not run a system comparison while
source-provenance inputs are still moving.

## Design Commitments

This slice extracts only behavior already required by the accepted Stage 1
profile or by the pre-commit runtime compatibility gap. It does not design a
generic runtime plugin system.

`contract_core` owns portable vocabulary. `semantic_core` owns transitions.
`visa_runtime::Coordinator` owns provider sequencing and durable commit.
`visa_component_adapter` owns engine-neutral component/host lifecycle rules.
`visa_wasmtime` translates those rules to one Wasmtime Component Model
instance. `visa-system` selects a concrete implementation and records what ran.

The worker uses an enum over concrete implementations, not a trait object or
dynamic loader. Stage 2a has one enum variant. Stage 2b may add exactly one
variant after its runtime feasibility gate passes.

## Target Structure

```text
crates/runtime/visa_component_adapter/
  Cargo.toml
  src/
    lib.rs
    types.rs
    state.rs
    error.rs
    host.rs
    lifecycle.rs

crates/runtime/visa_wasmtime/src/
  lib.rs
  adapter.rs
  bindings.rs
  host.rs
  preflight.rs
```

File grouping may be simplified when a file would contain only forwarding
code. Ownership may not be blurred to avoid a move.

## Extraction Map

| Shared contract responsibility | Remains in `visa_wasmtime` |
| --- | --- |
| Activation request, safe-point result, normalized status/phase | Generated WIT value conversion |
| `VISACS01` codec and component digest | Wasmtime `Component`, `Engine`, and compiled artifact |
| Normalized adapter, workload, KV, timer, binding, and codec failures | Original Wasmtime diagnostic strings |
| Provider bound, logical binding context, authority/receipt checks | `ResourceTable` and typed resource handles |
| Operation/idempotency identity and canonical effect mapping | Generated host-trait method signatures/results |
| Safe-point match/rollback, restore/thaw preconditions, callback parent rules | Export invocation and Wasmtime trap conversion |
| Runtime-preflight request/result contract | Wasmtime compile, linker, and non-executing pre-instantiation token |

Compatibility re-exports from `visa_wasmtime` may temporarily preserve the
current Stage 1 public paths, but there must be one defining type and one codec,
not duplicated implementations.

## Runtime Preflight Design

For Wasmtime, preflight performs the existing profile and component-digest
checks, builds the configured engine, compiles the Component, installs the
declared host imports, and uses Wasmtime's non-executing pre-instantiation/link
validation. It does not create a `Store`, instantiate the component, call a
guest export, or issue a host effect.

The returned prepared value owns the engine-local compiled/pre-instantiated
objects required after commit. The common layer exposes it only as an opaque
runtime-owned value and associates it with:

- concrete runtime implementation and version;
- component digest;
- profile digest and provider support decision; and
- the cooperative-handoff Component Model world.

The destination worker retains this value in its pending state. The validated
snapshot and successful runtime preflight are both required before it may take
the pending provider and call `Coordinator::restore`. Post-commit
instantiation consumes or borrows the same prepared value; it must not silently
compile a different artifact.

Focused tests prove that valid repeated preflight is mutation-free, invalid
component bytes and incompatible Component Model linkage return normalized
preflight kinds, and load without a matching prepared value is rejected before
provider ownership changes. A test-only guest-call observation may prove that
preflight invoked no export, but it cannot bypass production lifecycle code.

## Structured Failure Design

The common layer defines stable `AdapterFailureKind` and
`WorkloadFailureKind` values plus the existing typed KV, timer, binding, and
state-codec subcategories. An error may carry an engine diagnostic for humans,
but equality, worker protocol fields, scenario assertions, and future
cross-runtime normalization use the structured kinds.

The categories distinguish at least:

- profile/support and profile/component digest rejection;
- invalid artifact and unsupported interface/link capability;
- engine initialization, instantiation, and guest trap;
- workload-declared failure;
- binding/live-resource and safe-point state mismatch;
- portable-state decode;
- coordinator failure; and
- safe-point or guest rollback failure.

Coordinator `Rejection` and provider failure types remain their existing typed
authorities. This slice maps them without inventing a second semantic error
schema or flattening them into adapter text.

## Worker and Evidence Design

Add a serializable `RuntimeImplementation` selector to `Initialize` and a
structured runtime identity to `Initialized`. The source and destination state
hold the selected concrete adapter. Stage 2a accepts only `Wasmtime` and has no
fallback path.

The runner supplies the selector explicitly for every worker, verifies that
the response matches it, and constructs the existing Stage 1 environment from
the observed identities. `WorkerError` carries normalized adapter/workload
kinds when applicable; its message remains diagnostic. Existing scenario
assertions that inspect adapter message substrings move to typed comparisons.

No Stage 2 bundle is created. The existing Stage 1 evidence bundle continues
to contain one Wasmtime-to-Wasmtime environment and must not include the
`CrossRuntimePortability` claim.

## Dependency Direction

The intended production direction is:

```text
contract_core + visa_profile + substrate_api + visa_runtime
  -> visa_component_adapter

visa_component_adapter + wasmtime
  -> visa_wasmtime

visa_component_adapter + visa_wasmtime + existing Stage 1 dependencies
  -> visa-system
```

Direct dependencies retained by `visa_wasmtime` must be justified by
engine-specific conversion or setup; they may not duplicate common host or
lifecycle policy. `visa_runtime`, `semantic_core`, `contract_core`,
`visa_profile`, and `substrate_api` must not depend on either concrete runtime
implementation. The strict dependency script and active-spine package list are
updated in the same slice.

## Delivery Sequence

1. Complete Stage 1 spine modularization and record focused and 31-case
   baselines.
2. Add `visa_component_adapter` and its one-way dependency policy.
3. Move shared types, component digest, and the exact state codec with golden
   byte and corruption tests; preserve compatibility re-exports.
4. Move normalized failure categories and replace message-based adapter/
   workload checks.
5. Extract logical binding/effect code from Wasmtime resource-table and WIT
   conversion glue.
6. Extract shared lifecycle validation and rollback rules, then make the
   Wasmtime implementation exercise that single path.
7. Implement Wasmtime non-executing preflight and make a matching prepared
   artifact mandatory before destination coordinator restore.
8. Add the worker selector, observed runtime identity, structured protocol
   errors, and evidence derivation.
9. Run focused tests and compare all 31 Wasmtime-to-Wasmtime cases against the
   accepted semantic baseline.
10. Run local and Docker full/system gates, independently verify retained
    bundles, update current project claims without marking Stage 2 complete,
    and finish dependency/diff audits.

## Compatibility Comparison

Compare these stable dimensions before and after Stage 2a:

- all 31 registry IDs, classes, and allowed outcomes;
- profile/config/policy digests and portable component-state bytes;
- normalized semantic trace and final/replayed canonical state digests;
- snapshot and binding receipt semantics;
- authority, lease, ownership, and source-fencing observations;
- fault schedules and assertion names/order; and
- independent verifier acceptance.

Do not compare bundle IDs, paths, timestamps, process IDs, source provenance,
human diagnostics, or whole-bundle hashes. Structured adapter projections and
observed runtime identity are intentionally more precise, but may not change a
canonical outcome.

## Validation

```sh
cargo fmt --all --check
cargo test --locked -p visa_component_adapter -p visa_wasmtime -p visa-system
cargo clippy --locked -p visa_component_adapter -p visa_wasmtime \
  -p visa-system --all-targets -- -D warnings
python3 scripts/check-dependency-direction.py
python3 scripts/check-stage1-deletions.py
scripts/ci-gate.sh fast
scripts/ci-gate.sh full
scripts/ci-gate.sh system
scripts/run-docker-ci-gate.sh full
scripts/run-docker-ci-gate.sh system
git diff --check
```

The system gate must still invoke the independent Stage 1 conformance process
over the retained execution bundle. Unit-only prepared-artifact fixtures cannot
satisfy the 31-case regression.

## Constraints

- Do not add Runtime B or a fake second runtime while extracting the contract.
- Do not duplicate WIT/component state or canonical error vocabularies between
  the common crate and `visa_wasmtime`.
- Do not let preflight mutate provider, coordinator, canonical state, resource
  bindings, or evidence.
- Do not instantiate before commit merely to make capability validation easy.
- Do not recompile or substitute a component after successful preflight.
- Preserve Stage 1 rejection precedence, rollback order, vector insertion
  order, and evidence artifact relationships.
- Do not turn engine strings, scheduling, table indices, or prepared objects
  into portable truth.
- Do not mark Stage 2 complete after this slice.
