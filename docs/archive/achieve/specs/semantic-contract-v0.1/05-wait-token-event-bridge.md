# WaitToken Event Bridge

WaitToken is the semantic form of blocking, pending, cancellation, and resume.
No operation should block invisibly inside a hostcall or adapter.

## Required State

```text
owner Store/Activation generation
kind
blockers
state: pending / resolved / cancelled / restarted
cancel reason
restart policy
event attribution
```

## Rules

```text
pending operation creates a WaitToken
resolve/cancel/restart is event-visible
dead owner generation cancels its waits
cancelled wait cannot resume
resume validates Store/Activation/Code generation
active DMW lease must not cross Pending unless explicitly allowed
```

## Frontend Wait-Service Convergence

```text
frontend wait evidence is represented as WaitToken records with stable kind,
owner, blockers, restart, state, and cancellation fields
Linux epoll_wait and futex_wait are examples, not the definition of the model
epoll_create/ctl/wait and futex wait/wake/cancel authority must become
capability evidence, not reference-service private state
pending/resume/cancel/restart outcomes must be visible through WaitToken state
and EventLog transitions
saved_context may name the Linux frontend operation, but stable checks must use
kind, owner generation, blockers, restart_policy, state, and cancel_reason
reference epoll/futex service tables are not portable artifact execution
```

## Review Smell

```text
adapter sleeps without WaitToken
wait is identified without owner generation
cancel reason is only debug text
resume path does not re-check generation
```
