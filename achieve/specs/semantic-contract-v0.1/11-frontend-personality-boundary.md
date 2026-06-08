# Frontend Personality Boundary

Frontend interfaces are personality layers. They are not the Semantic Virtual
ISA, contract_core, or substrate_api.

This document covers contract-visible rules for WASI, WIT worlds, Linux syscall
personalities, socket/filesystem APIs, futex, epoll, signals, and future guest
ABI adapters. The vISA-level position is defined in
`../semantic-virtual-isa-v0/05-frontend-personality-boundary.md`.

## Paths

```text
primary:

vISA artifact
  -> HostcallFrame / TrapMap
  -> Semantic vISA effects
  -> contract ledger

optional frontend:

Wasm app / Linux ELF / custom guest ABI
  -> frontend world or personality artifact
  -> HostcallFrame / TrapMap
  -> Semantic vISA effects
  -> contract ledger
```

Privileged paths continue through target_executor capability and generation
gates, then to EventLog, contract graph, and substrate_api trait calls when
machine authority is required.

Rust substrate traits must never be exposed as Wasm ABI.

## Rules

```text
frontend resources are not VMOS capabilities
frontend handles are not VMOS ObjectRefs
Implementing a substrate trait is not authorization
Privileged custom WIT calls pass CapabilityGate
Blocking calls become WaitToken state
Visible effects become EventLog and osctl ViewV1 evidence
Unsupported interfaces or substrate authorities become semantic events
```

No handle may carry raw host pointers, raw return addresses, native stack
pointers, raw DMA bindings, raw MMIO mappings, or untracked DMW leases.

## Manifest Compatibility

Artifacts declare frontend interface requirements separately from substrate
machine requirements:

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

Loader errors must distinguish missing frontend world, missing custom WIT world,
missing substrate authority, profile mismatch, ABI mismatch, schema mismatch,
and unsupported runtime use.

## Review Smells

```text
Linux syscall breadth is treated as vISA completeness
WASI resource id is treated as a VMOS capability
frontend ABI register frame is treated as Activation truth
personality shortcut records no EventLog or ObjectRef evidence
substrate trait is exposed directly as Wasm ABI
```
