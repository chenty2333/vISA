# Feature Specification: Stage 1 Cooperative Stateful Component Handoff

Status: complete

This feature turns the accepted Stage 1 contract in `docs/ROADMAP.md` and
`docs/VALIDATION.md` into one executable system capability. Those project docs
remain authoritative for architecture and claims; this package records the
completed implementation slice.

## Scope

A stateful WebAssembly component reaches an explicit safe point on a source
process, exports canonical portable state, is reauthorized and rebound in a
separate destination process, commits one durable ownership/fencing decision,
resumes a paused-duration timer, conditionally updates durable KV, and emits an
independently verifiable evidence bundle.

The production path is:

```text
contract_core <- visa_profile
contract_core <- semantic_core
contract_core <- substrate_api
contract_core + substrate_api <- substrate_host
contract_core + semantic_core + substrate_api <- visa_runtime
contract_core + substrate_api + visa_profile + visa_runtime <- visa_wasmtime
contract_core + semantic_core + visa_profile <- visa-conformance
contract_core + handoff-component + substrate_api + substrate_host
  + visa-conformance + visa_profile + visa_runtime + visa_wasmtime <- visa-system
```

Each arrow points from direct workspace dependencies on the left to the
dependent package on the right.

The old broad model under `crates/oracle/` may be compiled for comparison but
must not enter this path or define a second write authority.

## Requirements

- **FR-001**: The real WIT component, coordinator, reducer, SQLite provider,
  host timer, snapshot validation, destination binding, and source fencing must
  execute through public boundaries.
- **FR-002**: Source and destination must be separate persistent child
  processes with separate runtime stores and journal scopes over one durable
  provider transaction domain.
- **FR-003**: Rejected pre-commit cases must retain source ownership and leave
  no active destination; post-commit failures must keep the source fenced.
- **FR-004**: Snapshot integrity, component/profile versions, required
  extensions, authority, namespace binding, generation, and lease epoch must be
  checked before destination execution.
- **FR-005**: Timer state uses paused remaining duration. Host monotonic
  instants and native handles are never serialized.
- **FR-006**: KV effects carry operation and idempotency identity. Unknown
  outcomes are reconciled from provider truth or remain explicitly
  indeterminate.
- **FR-007**: Handoff commit durably couples the destination journal outcome,
  both resource lease transitions, and final destination authority.
- **FR-008**: Every case emits raw process/assertion output, semantic journals,
  applicable snapshot and binding receipts, state/replay digests, fault
  schedule, authority/fencing evidence, and provenance with checked hashes.
- **FR-009**: A separate `visa-conformance` process must validate the completed
  bundle and every referenced artifact.
- **FR-010**: Raw steady-state cost, snapshot size, and interruption samples
  are observations only and must not create a performance claim.
- **FR-011**: Replaced production write/projection paths are deleted before the
  feature is complete.
- **FR-012**: Local and Docker `system` gates run the same implementation.

## Required Cases

The executable registry is `visa_conformance::STAGE1_CASE_DEFINITIONS`. Its 31
IDs are the acceptance boundary:

```text
timer-positive-duration-at-freeze
timer-paused-during-long-handoff
timer-completes-during-quiescence
timer-cancelled-during-quiescence
authority-sufficient-narrower
kv-duplicate-idempotent-request
handoff-repeated-validation-prepare
journal-replay
source-post-commit-stale-attempt
evidence-verification
performance-observations
safe-point-unreachable
unsupported-live-resource-or-borrow
kv-unknown-outcome
corrupt-snapshot-or-component-digest
incompatible-snapshot-or-profile-version
unknown-extension-or-profile-mismatch
destination-authority-missing-or-insufficient
required-capability-revoked
adapter-broader-authority
kv-binding-wrong-or-missing
timer-semantics-unsupported
destination-crash-before-commit
prepare-message-duplicate-or-lost
commit-acknowledgement-lost
source-races-with-commit
destination-crash-after-commit
duplicate-restore-or-stale-snapshot
repeated-cancel-abort-cleanup
durable-journal-or-commit-write-fails
report-generation-fails-after-commit
```

## Non-goals

Stage 1 does not claim cross-runtime or cross-ISA portability, transparent
native-process migration, arbitrary socket/device continuity, universal
exactly-once execution, TEE/KMS correctness, production readiness, market
validation, or a performance target.

## Completion Rule

The feature is complete only when all 31 cases execute, the independent bundle
gate passes, local and Docker system gates agree, old production paths are
absent, and the project docs describe the resulting claims without overreach.
