# Incremental state digest spike (working note)

> This is an engineering working note, not a canonical specification, claim
> receipt, release artifact, or production replay decision.

## Question

The current `semantic_core::replay` path validates both the input and output
canonical state digest at every journal boundary. That is the right integrity
contract, but the operation ledger remains in `CanonicalState.operations` and
grows with every prepared effect. The existing quick harness showed roughly
0.4 ms at 10 effects, 7.9 ms at 100, and 543 ms at 1,000 for the
`coordinator-replay/journal-replay` arm. Those observations are retained in
`target/visa-eval/samples.jsonl` from the 2026-07-26 quick run; they are not
formal performance data.

## What is implemented

`crates/benchmarks/visa-eval/src/digest_spike.rs` adds the evaluation-only
`visa-eval digest-cost` subcommand. For operation counts 10, 100, 1,000, and
5,000 (customizable with `--digest-operations`) it records:

* the current full-state path, calling the canonical state digest twice per
  appended operation to model replay's input/output boundary checks;
* an independent fixed-capacity Merkle prototype whose append and replacement
  update one root-to-leaf path;
* final canonical state bytes and short root prefixes for traceability.

The prototype root intentionally does not equal `contract_core::state_digest`.
Its base and leaf layout are not a contract, and no verifier or runtime reads
it. The comparison is only a cost-shape experiment.

Example quick invocation:

```text
cargo run -p visa-eval -- digest-cost --runs 1 --digest-operations 10,100
```

The default operation set includes 5,000 so a longer run can be requested
explicitly. The formal multi-run result remains a CI/research measurement,
not a local completion gate.

## `push_evidence` review

The current call sites are in `semantic_core`'s effect-outcome reducer and
transition handling for operation cleanup, timer completion, handoff closure,
handoff abort, and preparation cleanup. Evidence is not guaranteed to arrive
in append order: terminal events from different operations and handoff paths
can interleave, and replay may encounter a duplicate that is not the current
tail. A tail-only or tail-K shortcut therefore cannot be proven from the
current contract. `push_evidence` remains unchanged.

## Migration decision

Do not replace production replay with this prototype. A real migration would
need a contract-level digest design that covers fixed state fields, operation
identity/idempotency/tombstone retention, snapshot anchoring, duplicate
cleanup, and cross-version compatibility. In particular, pruning cleaned
operation records is not a local optimization: preflight idempotency and
replay need durable tombstones or a checkpoint boundary. The next safe step is
to use the `digest-cost` receipt to choose a contract proposal, then add a
separate verifier and compatibility proof before changing `semantic_core`.
