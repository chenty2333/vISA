# Frontend And Personality Boundary

Frontend personalities are optional adapters into the Semantic Virtual ISA.
They are not the Semantic Virtual ISA itself.

## Position

```text
primary:

vISA artifact
  -> Semantic Virtual ISA operation
  -> contract ledger
  -> substrate trait backend

optional frontend:

Linux ELF / WASI / JS ABI / custom ABI
  -> personality artifact
  -> Semantic Virtual ISA operation
  -> same contract ledger / substrate trait backend
```

Linux, WASI, WIT worlds, socket APIs, filesystem APIs, futex, epoll, and signal
rules are frontend/personality concerns unless and until they are normalized
into vISA effects.

## Rules

```text
frontend resources are not vISA capabilities
frontend handles are not ObjectRefs
frontend blocking becomes WaitToken state
frontend traps become TrapMap-attributed target/runtime traps
frontend cleanup becomes explicit cleanup-effect edges
frontend unsupported behavior becomes EventLog evidence
frontend interface requirements are separate from substrate authority requirements
```

No frontend handle may carry raw host pointers, raw return addresses, native
stack pointers, raw DMA bindings, raw MMIO mappings, or untracked DMW leases.

## Linux And WASI

Linux compatibility and WASI support are useful personalities, but they are not
conformance targets for the vISA core. A Linux syscall path is conforming when
it becomes contract-visible vISA effects through TargetArtifactImage,
CodeObject, Activation, HostcallFrame, and TrapMap. A WASI path is conforming
under the same rule.

The old question "does this match Linux?" is secondary. The first question is:

```text
does this expose the right Semantic Virtual ISA effect with stable identity,
authority, lifetime, wait, trap, cleanup, and profile evidence?
```

## Manifest Split

Artifacts declare frontend interface requirements separately from substrate
machine authority requirements:

```text
required_frontend_worlds
optional_frontend_worlds
custom_wit_worlds
wit_package_versions
hostcall_abi_version
capability_abi_version
semantic_contract_version
substrate_profile_required
```

Loader errors must distinguish missing frontend world, missing substrate
authority, profile mismatch, ABI mismatch, schema mismatch, and unsupported
runtime use.

## Review Smells

```text
Linux syscall breadth is treated as vISA completeness
WASI resource id is treated as a vISA capability
frontend ABI register frame is treated as Activation truth
personality shortcut records no EventLog or ObjectRef evidence
substrate trait is exposed directly as Wasm ABI
```
