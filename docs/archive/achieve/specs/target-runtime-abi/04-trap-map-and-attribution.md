# Trap Map And Attribution

Target traps must be attributable to semantic execution identity.

## Mapping

```text
hardware PC
  -> PcRangeEntry
  -> CodeObject ObjectRef
  -> code offset
  -> TrapMapEntry
  -> TrapRecord
```

TrapRecord references Store, Activation, and CodeObject as historical refs.
Traps do not create live ownership.

TrapRecord evidence must expose a machine-readable attribution status:

```text
trap-map-attributed       PC mapped to CodeObject offset and TrapMap entry
trap-map-missing-entry    PC mapped to CodeObject range but no TrapMap entry
trap-map-stale-code       PC mapped to retired CodeObject
trap-map-unknown-pc       PC did not map to a known live/retired CodeObject
synthetic                 trap was created by semantic harness or policy path
```

## Failure Cases

```text
PC outside known CodeObject -> UnknownCodeFault / SubstrateFault
PC in retired CodeObject -> StaleCodeExecutionFault
PC in CodeObject with no TrapMap entry -> UnknownCodeTrap
generation mismatch -> contract violation or target fault
```

## Review Smell

```text
trap stores only raw PC
trap points to live ownership edge
retired code can still be scheduled
unknown PC is silently bucketed as generic failure
```
