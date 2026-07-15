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
   invariants, and 16-case normative registry at local-clean neutral revision
   `75c5dacde8179e31eb88e17c5b7e8e3a9050e50b` (tree
   `1572ca83969e091898444c880d91885008d4cef7`). This revision is not pushed.
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
   `a890e5c3e25138662c213f19280ba3b209939813` and exact binary SHA-256
   `574580e5190f9aab2e54d37f3959c6872a1226ede5b22c064fa3609f35a3c689`.
   This includes raw JSONL replay, Registered-effect abort preservation,
   same-Registry service rebind, and the logical-request cell.
7. Completed locally: qualify Nexus handoff admission and production Registry
   refinement at the same clean revision; bind receipt SHA-256
   `4245c69f74bd492eb2aba0114c0d9584f112664c6d09854a157c4413c5760091`
   and v2 lock SHA-256
   `306ee1fff5a53b010f9906084925ca5fa6af44bd779bf3658957f4552a0bcb21`.
8. Completed locally: execute one real logical request while injecting
   post-durable ownership Commit acknowledgement loss and terminal Nexus
   response loss before adapter acceptance; recover both exactly without a
   duplicate external or native effect.
9. Completed as an implementation/smoke result: publish an exact two-file
   process artifact, verify it in another process, relocate it, and verify the
   same bytes again.
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
