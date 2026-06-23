# Command Transaction Surface

Commands are the mutation boundary for semantic effects. Direct mutation is an
implementation detail, not the public contract.

## Command Shape

Each applied command should have:

```text
precondition
mutation
event emission
postcondition
structured result
```

Failed preconditions leave graph state unchanged.

## First-Class Command Areas

```text
capability grant/revoke/delegate/attenuate
wait create/resolve/cancel/restart
trap and hostcall record
cleanup begin/step/commit
Store lifecycle transition
activation enter/exit/preempt/resume
artifact/code publish evidence
```

## Review Smell

```text
record method returns bool and drops failure reason
mutation path emits no event
postcondition is not checked
command accepts self-attested validation booleans
```
