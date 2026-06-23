# Semantic Virtual ISA v0 Overview

Status: canonical system specification.

vISA is:

```text
a cross-ISA Semantic Virtual ISA for portable system semantics
```

Wasm is the base execution virtual ISA. vISA extends that execution substrate
with system-level virtual ISA semantics: authority, capability, generation,
lifetime, wait, event, trap, cleanup, artifact identity, hostcall attribution,
and target profiles.

This document is the hub spec. It defines what the Semantic Virtual ISA is and
how the surrounding sub-specs fit together. It does not replace the detailed
encoding, runtime, or substrate specs.

## Primary Path

The primary path starts from a vISA artifact, not from a guest ABI:

```text
vISA artifact
  -> Semantic Virtual ISA operation
  -> contract ledger
  -> substrate trait backend
  -> host ISA / hardware
```

Optional frontend personalities can adapt guest-visible ABIs into the same
path:

```text
Linux ELF / WASI / JS ABI / future guest ABI
  -> personality artifact
  -> Semantic Virtual ISA operation
  -> same contract ledger / substrate path
```

Linux and WASI are examples of frontend/personality layers. They are not the
system center.

## Non-Goals

vISA is not primarily:

```text
a Linux compatibility layer
a WASI implementation
an OS service framework
a semantic contract database
a standalone migration tool
```

vISA is primarily:

```text
a cross-ISA Semantic Virtual ISA
backed by Wasm execution infrastructure
extended with capability, lifetime, wait, trap, cleanup, artifact, and profile semantics
constrained downward by substrate traits and target profiles
exposed upward through vISA artifacts and optional frontend personalities
```

## Spec Stack

```text
semantic-virtual-isa-v0
    System center: ISA axes, operation families, profile matrix, artifact
    execution model, frontend/personality boundary, and conformance rules.

semantic-contract-v0.1
    Encoding and validation layer for vISA effects: ObjectRef, generation,
    tombstone, capability, wait, cleanup, events, views, and graph validation.

target-runtime-abi
    Runtime carrier for vISA artifacts: TargetArtifactImage, CodeObject,
    HostcallFrame, TrapMap, profile records, no_std extraction, and package
    load rules.

substrate-api-v0
    Backend trait contract for machine authority providers and profile
    discovery. It maps vISA machine authority to real target mechanisms.

visa_profile crate
    Stable profile types and compatibility matrix used by loaders,
    validators, substrate reports, and manifests.
```

## Design Rule

```text
Rust traits define what the machine can provide.
CapabilityLedger decides who may use it.
contract_core defines how the vISA records it.
visa_profile defines which feature set is required, optional, or forbidden.
```

Substrate traits are backend interfaces, not OS traits and not Wasm ABI.
Implementing an authority trait reports enforceable machine capability; it does
not grant permission to an artifact or driver.

## Review Question

Every architecture change should answer:

```text
Does this strengthen the Semantic Virtual ISA boundary, or does it add another
native stand-in workload, frontend shortcut, or substrate-specific leak?
```

If the answer depends on Linux behavior, Wasmtime private state, raw page table
state, native DMA/MMIO bindings, or host register frames as semantic truth, the
change is outside the vISA boundary or needs another normalization layer.

## Document Map

```text
01-isa-axes-and-execution-model.md
    Host ISA, Semantic vISA, Wasm payload, and optional guest ABI axes.

02-operation-families.md
    Canonical vISA operation families and their ownership boundaries.

03-profile-matrix.md
    Stable feature levels, compatibility rules, and enforcement requirements.

04-artifact-execution-model.md
    Artifact, CodeObject, Activation, HostcallFrame, TrapMap, and substrate
    dispatch path.

05-frontend-personality-boundary.md
    Linux/WASI/custom frontend rules and why frontend semantics are optional.

06-conformance-and-evidence-boundary.md
    Evidence levels, cross-ISA portability tests, and review smells.
```
