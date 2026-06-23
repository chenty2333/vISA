# Semantic Contract Overview

Status: active contract boundary.

The semantic contract is the effect language of the Semantic Virtual ISA. It is
not a workload plan and not a statement of Linux compatibility.

It is the encoding and validation layer of the vISA, not the vISA itself. The
system-level source of truth is `../semantic-virtual-isa-v0/00-overview.md`.

It defines how virtual ISA effects are named, related, validated, and exported:

```text
ObjectRef / generation / tombstone
live, historical, external, and cleanup-effect edges
Capability and CapabilityHandle authority
WaitToken pending, resolve, cancel, and restart state
Store / Activation / FaultDomain lifecycle
Task / Resource object families when exposed by a frontend/personality
GuestAddressSpace / VmaRegion / PageObject memory semantics
FaultCleanupTransaction effects
EventLog and stable osctl ViewV1 output
contract graph validation
test fixture and package validation shape
```

## Layer Contract

```text
contract_core
    Stable contract language: refs, commands, events, views, invariants,
    package schemas, and version anchors.

semantic_core
    In-memory implementation and verifier for virtual ISA effects.

target_executor
    Bridge from artifact/runtime ABI events to contract-visible effects. It
    validates hostcall/trap identity and records capability, wait, trap, and
    cleanup effects.

osctl
    Read-only control plane over stable views and packages.

substrate_api
    Rust backend traits for machine authorities. It does not define semantic
    policy and is not a Wasm ABI.
```

## Ownership Rules

The semantic contract owns:

```text
identity
authority
lifetime
wait/pending/resume
fault attribution
cleanup effects
guest memory object truth
Task/Resource truth when a personality exposes them
observable events and views
```

The semantic contract does not own:

```text
raw page table mutation
real W^X publication
real DMA/IOMMU/MMIO/IRQ mechanics
Wasmtime internal serialized module format
full WASI filesystem or socket implementation
Linux syscall breadth
benchmark performance claims
```

Those are backend, personality, or workload concerns. They must enter the
contract as explicit effects before they can be observed or validated.

Fast paths and debugger/control-plane views are derived from the contract. A
FastPathPlan may cache ObjectRefs, generations, and policy decisions, but it is
not semantic truth. The Semantic Debugger is an osctl-style view over contract
state, not a separate authority path.

## Frontend And Personality Boundary

Frontend interfaces such as WASI, WIT worlds, Linux syscalls, socket APIs,
filesystem APIs, futex, epoll, signals, and future guest ABIs are personality
concerns. They must map into the same ObjectRef, Capability, WaitToken,
EventLog, Store, trap, and cleanup model before they become semantic contract
truth.

Linux is a legacy ABI personality. Linux syscall handling is conforming when it
is translated into contract-visible effects. It is not complete portable
artifact execution until the relevant service or personality runs through
TargetArtifactImage, CodeObject, Activation, HostcallFrame, and TrapMap paths.

## Adjacent Specs

```text
01-contract-core-boundary.md
    What belongs in contract_core.

02-object-identity-and-refs.md
    Object identity, generation, tombstone, and typed refs.

03-contract-graph-edges.md
    Edge modes and graph validation rules.

04-capability-authority.md
    Capability handles and authorization rules.

05-wait-token-event-bridge.md
    WaitToken event semantics.

06-store-fault-cleanup.md
    Store lifecycle and cleanup transactions.

07-osctl-control-plane.md
    Stable read-only views.

08-validation-harness.md
    Test and validation boundaries.

10-command-transaction-surface.md
    Command application boundary.

11-frontend-personality-boundary.md
    Frontend/personality interface rules, including WASI, WIT, and Linux.

12-guest-memory-object-model.md
    GuestAddressSpace, VmaRegion, PageObject, and mapping truth.
```

The parent vISA spec lives in `../semantic-virtual-isa-v0/`. Target-side
binary/runtime mechanics live in `../target-runtime-abi/`. Substrate backend
traits live in `../substrate-api-v0/`.
