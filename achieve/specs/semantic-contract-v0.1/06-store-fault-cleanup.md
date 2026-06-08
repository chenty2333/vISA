# Store Fault Cleanup

Store is the restartable fault-domain incarnation. Cleanup is a transaction over
a specific Store generation.

## Cleanup Properties

```text
canonical order
generation-safe targeting
idempotent state effect
contract-verifiable postcondition
osctl-visible steps and skipped stale-generation effects
```

## Required Effects

```text
stop new activations
cancel waits
revoke capabilities
release leases and resources
drop or unbind runtime bindings
mark Store generation dead
emit tombstones and historical refs
```

## Reboot Rules

```text
same logical fault domain may reuse StoreId
reboot bumps generation
old cleanup cannot mutate new generation
old caps and waits do not cross reboot
new generation receives new grants through policy
```

## Idempotence

State digest after cleanup once and cleanup twice must match. EventLog may
append replay/skipped evidence; raw EventLog equality is not the idempotence
criterion.

Cleanup transaction evidence must export the state digest used for this check.
The digest is over semantic Store, Activation, CodeObject, DMW lease, and
CapabilityLedger state; it is not an EventLog hash. A stale-generation cleanup
records the unchanged digest and skipped-stale-generation effects.

## Review Smell

```text
cleanup targets id without generation
cleanup leaves live activation/capability/wait on dead Store
reboot resurrects old handles
cleanup failure is only panic/debug text
```
