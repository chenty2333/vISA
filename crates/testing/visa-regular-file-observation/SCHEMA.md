# Regular-file observation v2

`regular-file-observation-v2` is a verdict-free JSON contract for recording
regular-file executions. A producer emits raw observations; a separately
implemented oracle decodes the JSON, reconstructs profile semantics, and
compares an uninterrupted control with a candidate route.

## Publication shape

Each experiment publishes two complete bundles:

- `observations/regular-file-observation-control-v2.json`
- `observations/regular-file-observation-candidate-v2.json`

The control bundle uses `uninterrupted_control`. Candidate modes are
`handoff`, `restart`, `carrier_only`, `naive_reopen`, and
`visa_plus_carrier`. Both bundles identify the same per-case schedule by
`schedule_id` and lowercase `schedule_sha256`.

Production bundles contain each of these cases exactly once:

1. `read-write-offset`
2. `append-continuity`
3. `truncate-version`
4. `rename-object-identity`
5. `replacement-rejected`
6. `external-mutation-rejected`
7. `lock-conflict`
8. `durability-reconciled`
9. `stale-source-fenced`
10. `cleanup-idempotent`
11. `indeterminate-write-blocks-handoff`
12. `destination-reauthorization-denied`

The named carrier probe is a separate exact coverage class containing only
`read-write-offset` and `append-continuity`; arbitrary subsets are
development-only and are not accepted by either production gate.

## Event contract

Every case is one contiguous, zero-based event stream. Events record a phase,
an actor, and exactly one typed raw event. File paths are namespace-relative
byte strings, never observer-host absolute paths:

- `file_probe`: path, bytes, byte count, SHA-256, and OS object metadata;
- `operation_call`: operation id, zero-based attempt, idempotency key, typed
  request, and the exact returned output or error;
- `os_call`: external replacement, whole-file mutation, rename, or lock call;
- `protocol_call`: lifecycle command and raw return or error;
- `profile_state_probe`: decoded profile fields without an attached decision;
- `coordinator_state_probe`: phase, activation, owner, and epoch;
- `lease_probe` and `lease_check`: provider observations;
- `operation_ledger_probe`: raw operation, outcome, and cleanup records;
- `destination_binding_probe`: destination binding inventory;
- `client_output` and `process_exit`: black-box process observations;
- `carrier_call`: capture, restore, resume, or shutdown with a byte-bound
  inline payload or artifact reference.

`FileProbe.sha256` is SHA-256 over exactly the adjacent raw `bytes`.
`CarrierPayloadObservation::Inline.sha256` is SHA-256 over exactly its
adjacent raw `bytes`. An applied ledger `result_digest` is SHA-256 over the
raw profile-result payload. `ProfileStateObservation.object_binding` is the
stable logical resource binding; native object identity is derived only from
file-probe device, inode, generation, and birth-time observations.

## Excluded producer decisions

The contract has no field for a terminal, assertion, pass bit, expected
result, normalized summary, semantic projection, or producer claim. All
structures use strict unknown-field rejection. Adding any such field makes
the bundle invalid instead of allowing the oracle to accidentally consume a
producer decision.

The producer crate offers only types, constructors, and structural
pre-publication checks. It contains no case semantic predicates or reducer.
The standalone oracle has its own wire decoder, registry, structural checks,
semantic rules, and observable projection; its Cargo graph has no dependency
on this crate or another vISA workspace crate.
