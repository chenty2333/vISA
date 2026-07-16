# Feature 009 Plan

## Dependency Direction

```text
joint wire/profile types
  -> joint reducer and receipt policy
  -> vISA coordinator projection adapter
  -> reference ownership/effect peers
  -> HostSubstrate vertical
  -> system runner and evidence publisher

Nexus process-wire mirror
  -> process-backed production Registry cell

independent oracle + TLA+ model
  -> evidence verifier
```

The independent oracle must not depend on the production joint reducer. The
Nexus adapter and reference peer implement the same narrow boundary; neither is
allowed to expose or remotely control the native closure algorithm.

## Work Phases and Current State

1. Completed: freeze the threat model, state machine, v1 wire schemas,
   invariants, and 16-case normative registry at remote-accepted neutral
   revision `f4a8211f0e5fde13e0f6101be3c3322854458c79` (tree
   `a65f264bb7eaf390cbd6285d791b4f7f43e9be25`). Its exact-SHA artifact was
   downloaded and independently reverified.
2. Completed: implement the isolated vISA joint profile and durable recovery
   reducer without modifying the Stage 1-4 canonical schema.
3. Completed: implement the reference non-equivocating ownership log and
   reference fail-closed effect peer.
4. Completed: implement the independent Rust oracle, TLA+ model, and mutation
   corpus.
5. Completed in the current worktree: implement the system runner, reference
   lane, HostSubstrate attempt/observed/completion vertical, artifact publisher,
   relocation-safe verifier, and repository gate wiring.
6. Completed locally: run all four live process tests against Nexus revision
   `8e5123c46569e8ebdaba9f4f56bea6584ab58586` and exact binary SHA-256
   `6bf845f8fecd2b3ff5833aa505f2a392fa3e07d726326cf65d07b39a87358f51`.
   This includes raw JSONL replay, Registered-effect abort preservation,
   same-Registry service rebind, and the logical-request cell.
7. Completed locally: qualify Nexus handoff admission and production Registry
   refinement at the same clean revision; bind receipt SHA-256
   `f155d9d796ee4928b68ca2317268f5d622c4b3f2878440895e2c811add24ae6a`
   and v2 lock SHA-256
   `21b5404bc5c1ad1f48c4ffe37cf455d104acac8ab9deca98f326d7c9b06072d9`.
8. Completed locally: execute one real logical request while injecting
   post-durable ownership Commit acknowledgement loss and terminal Nexus
   response loss before adapter acceptance; recover both exactly without a
   duplicate external or native effect.
9. Completed as an implementation/smoke result: publish a strict three-file
   process manifest/report/executed-binary artifact, verify it in another
   process, relocate it, and verify the same bytes again. The separate logical
   supplemental publishes a strict five-file artifact.
10. Pending: rerun the standalone publisher after this vISA work is committed,
    bind the resulting clean exact SHA, close local and Docker evidence, then
    require pushed exact-SHA CI before changing roadmap status.

## Coordination Contract

The vISA side owns the portable handoff projection and its admission rules. The
Nexus side owns scope membership, publication serialization, closure ordering,
and native receipt production. The neutral composition artifact owns the joint
wire contract, refinement map, case registry, and evidence semantics.

No side imports another side's internal state machine or ledger implementation.

The reference lane, HostSubstrate vertical, Nexus process cell, logical-request
experiment, and Nexus-local v2 qualification are distinct evidence. A green
reference/HostSubstrate gate cannot be relabeled as Nexus qualification; the
source lock's `adapter_qualification=false` mapping cannot replace the v2
receipt's `production_registry_refinement_checked=true`; and same-Registry
service rebind cannot be relabeled as Registry replacement. The current process
lane also cannot be used to claim the unsupported production retained-tombstone
mapping, real OSTD IRQ/SMP, or reboot recovery.
