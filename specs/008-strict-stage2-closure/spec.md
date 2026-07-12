# Feature Specification: Strict Stage 2 Closure

Status: active; Phase 3 produced a no-go result on 2026-07-12, so independent
runtime implementation must not begin until a candidate passes the qualification
gate in this specification.

This slice closes the remaining strict Stage 2 boundary without weakening the
already-earned `cross-execution-path-portability` result. It first converges the
repository, closes the JcoNode prepared-artifact load window, qualifies a
genuinely independent Component Model runtime, and only then adds that runtime
to the unchanged cooperative-handoff profile and executable evidence matrix.

## Scope

- Converge the active repository surface around the six canonical project
  documents, supported build/validation entry points, and Apache-2.0 licensing.
- Replace JcoNode's final manifest-check-to-Node-pathname-load sequence with a
  sealed execution carrier whose verified bytes cannot be replaced by the
  untrusted artifact publisher before Node consumes them.
- Qualify one runtime whose Component Model implementation and execution path
  do not depend on Wasmtime, `wasmtime-environ`, or a Wasmtime-derived component
  translator.
- Execute the unchanged Stage 1 Component, WIT world, timer/KV profile,
  portable-state codec, authority model, and 31-case registry through that
  runtime.
- Add the qualified runtime's same-path cell and both Wasmtime/qualified-runtime
  mixed directions, with independent Stage 1 verification and a strict Stage 2
  outer claim gate.
- Generalize concrete runtime dispatch and matrix description only as required
  to add the qualified runtime without runtime-specific semantic bypasses.

## Explicitly Out of Scope

- file or network continuity;
- cross-ISA execution;
- TEE, attestation, KMS, or confidential continuity;
- a stable public API, production-readiness claim, or documentation website;
- transparent migration, arbitrary process continuation, or new exactly-once
  claims; and
- speculative adapters for runtimes that have not passed qualification.

## Security Boundary: JcoNode Sealed Carrier

The protected asset is the exact generated JavaScript/core-Wasm/driver graph
whose manifest was accepted by preflight. The attacker may run concurrently
under the same UID and may mutate, replace, rename, symlink, or republish the
old prepared-artifact pathname tree. Passing execution must bind Node's module
loads to a private, sealed view derived from the exact verified bytes. If the
platform cannot construct that view, JcoNode instantiation must fail closed.

This boundary does not claim protection from ptrace, process-memory writes,
denial of service, a compromised Node execution environment or toolchain
(including its loader and shared libraries), or a compromised verifier process.
Toolchain trust and same-UID process isolation remain separate declared
dimensions.

The following are not acceptable fixes:

- rehashing the same mutable pathname immediately before spawn;
- relying only on file permissions owned by the same hostile UID;
- passing a checked path to Node and assuming Node opens it before replacement;
- silently falling back to Wasmtime or to an unsealed Jco path; or
- copying from a mutable tree without binding the copy to the captured bytes.

## Runtime Qualification Gate

Before any production adapter code is added, the candidate must produce a
retained, reproducible qualification record that establishes all of the
following:

1. exact runtime implementation, version, source revision, artifact digest,
   license, installation/build recipe, and host requirements;
2. an implementation-lineage audit showing that Component parsing,
   canonical-ABI lowering/lifting, instantiation, and execution are independent
   of Wasmtime and `wasmtime-environ`;
3. acceptance of the byte-identical Stage 1 Component and the existing
   `visa:continuity/cooperative-handoff` WIT world, without a runtime-specific
   guest or relinked semantic variant;
4. real execution of the exported workload surface and real host handling of
   the timer/KV imports through a process or embedding boundary that can support
   the shared adapter contract;
5. deterministic structured failure for unsupported features, with no fallback;
6. a viable mapping for preflight, activation, safe point, portable state,
   restore, thaw, cancellation, status, cleanup, and runtime identity; and
7. a go/no-go decision based on executable evidence rather than API presence or
   documentation claims alone.

A no-go candidate remains research evidence and must not create a placeholder
workspace crate, runtime selector, matrix cell, or public support claim.

## Functional Requirements

- **FR-001**: The repository must contain the complete Apache License 2.0 text,
  expose `Apache-2.0` through workspace package metadata, and make the license
  discoverable from the README.
- **FR-002**: Completed feature specifications must be removed from the active
  tree only after all still-current contracts and claim boundaries are present
  in the canonical documents or executable tests. Git history remains the
  historical record; `specs/` contains only an active slice.
- **FR-003**: Unused or misleading repository entry points must be removed. A
  security/dependency-policy configuration may exist only when a supported gate
  actually executes it.
- **FR-004**: JcoNode must execute only from the sealed carrier after validating
  the carrier against the prepared-artifact manifest. The old publisher tree
  must not be consulted after the carrier is accepted.
- **FR-005**: Focused hostile-publisher tests must replace generated files,
  directories, symlinks, and publication roots at every exposed handoff and
  prove either execution of the originally captured bytes or fail-closed
  rejection. A substituted payload must never execute.
- **FR-006**: Existing JcoNode positive, failure, no-fallback, 31-case, Stage 2,
  Host, Docker, and independent-verifier behavior must remain unchanged except
  for new sealed-carrier provenance.
- **FR-007**: The independent runtime must not enter the active production spine
  until the qualification record passes all seven qualification conditions.
- **FR-008**: The qualified runtime must implement the existing
  `CooperativeRuntimeFactory`/`CooperativeRuntimeInstance` contract or a
  behaviorally equivalent shared port refinement; it must not fork the
  lifecycle, canonical reducer, coordinator, profile, or portable-state codec.
- **FR-009**: Runtime selection must use one extensible registry/factory boundary.
  Adding the qualified runtime must not multiply concrete-runtime matches across
  worker lifecycle operations.
- **FR-010**: Matrix cells must be data-described runtime pairs rather than one
  closed enum variant per pair. Claim gates must explicitly select their exact
  required cell set.
- **FR-011**: Existing Wasmtime/JcoNode four-direction evidence must continue to
  earn only `cross-execution-path-portability` and must retain translator-lineage
  disclosure.
- **FR-012**: Strict Stage 2 evidence must include Wasmtime-to-Wasmtime, the
  qualified runtime's same-path cell, and both mixed directions over all 31
  cases, using byte-identical common inputs and fresh isolated providers and
  workers.
- **FR-013**: Every strict cell must pass the complete independent Stage 1
  verifier before cross-cell normalization. The strict outer verifier must
  recompute normalized traces and require equality for all 31 case groups.
- **FR-014**: Strict evidence must machine-check requested, prepared, and live
  runtime identity, implementation lineage, no fallback, complete cell set,
  artifact integrity, and the exact `strict-cross-runtime-continuity` claim.
- **FR-015**: Unsupported runtime capabilities must appear as explicit profile
  or qualification results, never as skipped cells, adapted expectations, or a
  fallback execution path.
- **FR-016**: The locked Host and Docker gates must run the existing repository,
  Stage 1, JcoNode, and cross-execution-path suites plus the new qualification
  and strict Stage 2 suites. CI must retain diagnostic evidence on failure.

## Completion Rule

This slice is complete only when repository convergence, sealed Jco execution,
runtime qualification, the full qualified-runtime adapter, all four strict
runtime cells, independent verification, canonical documentation, Host/Docker
gates, and pushed CI have passed. At completion, Roadmap Stage 2 may change from
`in progress` to `complete` only for the two named independent runtime
implementations on x86-64 Linux with the timer/KV profile.
