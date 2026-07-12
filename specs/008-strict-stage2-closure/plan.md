# Implementation Plan: Strict Stage 2 Closure

Status: active; Phase 4 is blocked by the 2026-07-12 Runtime B no-go
qualification, not by an in-repository implementation failure.

## Entry Condition

Stage 1 and Stage 2a/2b/2c are complete for their named claims. The current
branch is clean at `30c2ca2`, and the exact commit passed the full Docker CI
job. Strict Stage 2 remains open solely because no second independently
implemented Component Model runtime has executed the accepted profile.

## Design Commitments

- `semantic_core` remains the only canonical transition authority.
- `visa_runtime::Coordinator` remains the only production effect sequencer and
  commit/fencing owner.
- `visa_component_adapter` remains the shared lifecycle and host-bridge
  boundary.
- Runtime-specific objects, generated artifacts, handles, paths, and execution
  metadata never enter portable state.
- Qualification precedes adapter implementation.
- Existing claims and gates remain executable while strict evidence is added.
- Each phase is reviewed and validated before the next phase expands scope.

## Phase 1: Repository Convergence

Extract durable decisions from completed slices into README and the six current
documents, then remove completed specs, `deny.toml`, the deprecated LTP alias,
and the unused Dev Container entry. Add Apache-2.0 licensing to every workspace
package. Update references and validation limitations so the repository does
not advertise unsupported entry points or inactive policy gates.

## Phase 2: JcoNode Sealed Execution Carrier

Capture the generated graph into an immutable representation owned by the
prepared value. Materialize or expose it to Node through a private execution
view that an artifact publisher cannot replace. Validate the view from the same
captured bytes/descriptor identities that Node will consume, keep it alive for
the child lifetime, and fail closed on unsupported platforms.

Prefer the smallest Linux mechanism that gives a demonstrable load-time
binding. The implementation decision must be recorded after comparing private
directory copies, open-descriptor paths, memfd-backed modules, and mount/process
isolation against Node ESM module resolution. Tests must control the race rather
than depend on timing.

## Phase 3: Independent Runtime Qualification

Evaluate candidates outside the production graph. Pin source/tool artifacts,
audit implementation lineage from dependency/source evidence, and advance the
unchanged Component through parse/world, exported-call, owned-resource, and
host-bridge gates in order. Stop at the first prerequisite that public,
supportable APIs cannot satisfy. A candidate that passes those prerequisites
must then run a minimal real timer/KV bridge before selection. Retain a
machine-readable qualification record and human-readable decision. Record a
no-go without building downstream bridge or lifecycle code when an earlier
gate fails; do not compensate with a runtime-specific guest.

## Phase 4: Qualified Runtime and Registry

Add one concrete runtime crate only after Phase 3 passes. Keep runtime-specific
preflight, process/embedding, provenance, and wire conversion inside that crate.
Refactor the worker's concrete adapter enum into one registry-created erased
instance boundary so lifecycle dispatch is defined once. Preserve recoverable
coordinator ownership across failed instantiation.

Replace the closed pair enum with a typed cell descriptor containing stable cell
ID, source runtime ID, destination runtime ID, and claim-set membership. Existing
Wasmtime/JcoNode cells remain the execution-path claim group; the Wasmtime/
qualified-runtime cells form the strict-runtime claim group.

## Phase 5: Evidence and Acceptance

Version evidence schemas when their accepted cell or provenance model changes.
The runner writes caches; `visa-conformance` independently captures artifacts,
validates every Stage 1 bundle, recomputes normalized traces, checks runtime
lineage and no-fallback facts, and decides each named claim group. Host and
Docker run the exact same scripts. Canonical docs are updated from retained
evidence, the completed active spec is removed, and the final diff is reviewed
before commit and push.

## Validation Order

1. focused unit and hostile-publisher tests;
2. affected-package format, Clippy, and tests;
3. runtime qualification gate;
4. `fast` and `full`;
5. Stage 1 and JcoNode same-path system gates;
6. existing cross-execution-path Stage 2 gate;
7. qualified-runtime same-path and strict Stage 2 gates;
8. Docker parity for all changed system gates;
9. final independent-verifier, provenance, claim, diff, and source-root audit;
10. pushed GitHub Actions result at the exact final commit.
