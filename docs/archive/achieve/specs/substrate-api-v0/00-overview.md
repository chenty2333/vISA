# Substrate API Overview

Status: active backend portability contract.

`substrate_api` defines the Rust trait backend for Semantic Virtual ISA machine
authorities. It is not a monolithic native kernel, not a Wasm ABI, and not a
semantic policy layer.

The parent vISA spec is `../semantic-virtual-isa-v0/00-overview.md`. This
sub-spec explains how real targets report and implement enforceable machine
authority for that vISA.

Substrate is:

```text
a set of authority traits
a capability discovery report
a target profile declaration
a conformance-test surface for hardware ports
```

Hardware ports implement only the authorities they can provide. Missing
authorities are reported at startup and become load-time incompatibilities,
optional degradation, or runtime `Unsupported` events.

## Layer Relation

```text
contract_core
    Stable language for virtual ISA effects: ObjectRef, Event, Command, View,
    schema, and invariants.

semantic_core
    In-memory effect ledger and verifier.

target-runtime-abi
    Artifact envelope, CodeObject, HostcallFrame, TrapMap, profile, and no_std
    extraction contracts.

target_executor
    Adapter from artifact/runtime ABI events to semantic effects and substrate
    trait calls.

substrate_api
    Rust trait backend for machine authorities.

hardware substrate
    Board, QEMU, or architecture-specific implementation of those traits.
```

Short rule:

```text
Rust traits define what the machine can provide.
CapabilityLedger decides who may use it.
contract_core defines how the Semantic Virtual ISA records it.
```

## Boundaries

Rust substrate traits are engineering boundaries, not security boundaries.
Security still comes from:

```text
manifest requirements
capability checks
generation validation
EventLog records
trap and cleanup policy
substrate enforcement
```

Rust substrate traits are not exposed to Wasm artifacts:

```text
artifact or frontend
  -> WASI/custom WIT/hostcall ABI
  -> target_executor validation
  -> semantic EventLog
  -> substrate_api trait method
  -> hardware substrate
```

Implementing `DmaAuthority` means the machine can provide DMA. It does not mean
any driver may use DMA; access still requires a valid capability and generation.

## Document Map

```text
01-authority-traits.md
    Authority trait families and default Unsupported behavior.

02-capability-discovery-profiles.md
    SubstrateCapabilitySet and profile matching.

03-unsupported-events-conformance.md
    Unsupported event reporting and conformance expectations.
```
