# osctl Control Plane

`osctl` is a read-only view over stable contract state. It is not a mutation API
and not an internal struct dumper.

## Rules

```text
output stable View schemas
all references use ObjectRef or stable ids
views include schema/version
JSON is machine-readable
debug text is auxiliary only
internal adapter/runtime fields stay hidden unless promoted to contract views
```

## Required View Families

```text
object identity and lifecycle
capability and authority
wait and event state
cleanup and tombstone state
contract validation
artifact/runtime attribution
execution provenance
semantic debugger views over graph/history/effects
```

Artifact plan and artifact object JSON must expose package roots, artifact
manifest facts, capability manifest facts, target profile facts, hash status,
and signature status as contract-visible fields. A view may report a target
artifact as accepted only with explicit hash/signature status; it must not imply
cryptographic signature verification unless `signature_verified=true` is backed
by the signature policy.

Hostcall JSON must expose the gate outcome without collapsing reasons into
debug prose:

```text
subject_source
gate.status
gate.denial_reason
capability_handle_count
last_error = machine-readable denial reason when rejected
```

Bad frame, stale capability handle, ABI mismatch, and unsupported hostcall
outcomes must remain distinguishable in the read-only view.

Trap and cleanup JSON must expose attribution and idempotence without requiring
debug-string parsing:

```text
trap.attribution.status
trap.attribution.target_pc
trap.attribution.code_offset
cleanup.idempotence.state_digest
cleanup.idempotence.state_digest_present
```

TrapMap success, unknown PC, missing TrapMap entry, and stale CodeObject
execution must remain distinguishable. Cleanup idempotence is proven by state
digest equality, not by raw EventLog equality.

Frontend wait-service JSON must expose WaitToken evidence without debug-string
parsing. Linux epoll/futex records are examples of this shape:

```text
wait.kind_name
wait.state
wait.owner.store / wait.owner.store_generation
wait.references.blockers
wait.restart_policy
wait.cancel_reason
wait.saved_context
```

The `saved_context` field may identify frontend operations such as `epoll_wait`
or `futex_wait`, but machine checks must be able to use the stable WaitToken
fields above. Reference frontend stand-ins must not be labeled as portable
artifact execution or real target substrate.

The semantic debugger is a control-plane mode of osctl. It may explain graph
history, capability flow, waits, cleanup, traps, and provenance, but it must not
mutate graph state or bypass contract views.

## Review Smell

```text
CLI test greps prose instead of JSON
view serializes private record directly
view omits generation
view says verified when signature or replay was not enforced
```
