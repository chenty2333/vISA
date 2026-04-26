# Golden Trace Contracts

Status: test evidence contract.

Golden traces are stable semantic evidence for checkpoint work. They are not
pretty logs and they are not substitutes for Rust tests. A golden trace should
show the contract-visible facts that a checkpoint promises to preserve.

## Required Shape

Every `*.trace.json` file must include:

```text
schema
checkpoint
contract_refs
no_goals
stimulus
events
expected
validation
```

The lightweight consistency script validates this minimal shape:

```bash
scripts/check-doc-consistency.sh
```

## Naming

Use checkpoint-oriented names:

```text
tests/golden/target-runtime/fake_aot_hostcall_tail.trace.json
tests/golden/target-runtime/fake_aot_ebreak_trap.trace.json
tests/golden/semantic-contract/guest_memory_fast_path.trace.json
```

## Rules

```text
Golden traces use stable object names and schema fields.
They must not depend on debug text.
They must not encode raw host pointers.
They must include no-goals when a feature is intentionally fake or rejected.
They should be updated only when the contract changes.
```
