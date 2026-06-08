# Capability Authority

Capability is explicit authority over a generation-bearing object. Debug labels
are not authority.

## Authority Tuple

```text
subject Store/Activation generation
capability slot/handle
target ObjectRef generation
rights / operation set
state
manifest declaration
```

For handle-style ABIs, authority is ledger-backed:

```text
CapabilityLedger[StoreRef][slot]
```

The handle may carry a slot, generation, and optional unguessable tag. The
global object id alone is not a safe capability.

## Rules

```text
same label with different ObjectRef rejects
same ObjectRef with stale generation rejects
revoked capability rejects
attenuation cannot amplify rights
CapabilityClass is classification, not permission
external authority must be declared
manifest-required capability classes require manifest declaration provenance
capability handle slot/generation/tag are validator-visible and track capability generation
rebooted Store receives new grants; old caps never resurrect
```

## Review Smell

```text
requires_capability only checks a string or class
guest can guess a global object id
debug label participates in authorization
capability survives Store generation change
```
