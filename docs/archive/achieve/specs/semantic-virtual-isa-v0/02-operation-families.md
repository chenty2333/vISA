# Operation Families

The Semantic Virtual ISA is defined by operation families, not by Linux syscall
breadth or service implementation shape.

## Canonical Families

```text
Wasm compute and memory
    module, load, store, call, branch, linear memory, trap.

Artifact and code identity
    TargetArtifactImage, manifest binding, CodeObject publish, W^X lifecycle,
    PcRange, TrapMap, hash/signature status, and profile requirements.

Authority
    capability check, grant, delegate, attenuate, revoke, handle generation,
    manifest-proven authority declaration.

Machine authority
    console, timer, event queue, code publish, guest memory, DMW, DMA, MMIO,
    IRQ, snapshot/replay extraction.

Lifetime
    object create, close, generation bump, tombstone, Store start/degrade/reboot,
    Activation enter/exit, FaultDomain lifecycle.

Async
    wait create, resolve, cancel, restart, pending, resume, event bridge.

Fault and cleanup
    trap attribution, trap classification, cleanup begin/step/commit,
    cleanup-effect edges, post-cleanup reuse rejection.

Observability
    EventLog emit, stable ViewV1 extraction, contract graph validation,
    no_std panic/log/osctl extraction.

Profile and compatibility
    required/optional/forbidden feature sets, substrate discovery, load-time
    compatibility, event-visible degradation.
```

## Ownership Boundaries

```text
semantic-virtual-isa-v0
    Names the operation families and states which boundaries must remain stable.

semantic-contract-v0.1
    Encodes effects, ObjectRefs, generations, edges, events, and views.

target-runtime-abi
    Carries artifact, code, hostcall, trap, profile, and extraction records.

substrate-api-v0
    Provides backend trait families for machine authority.

frontend/personality artifacts
    Implement guest-visible behavior by emitting vISA effects.
```

## Review Smells

```text
operation family is defined by Linux syscall breadth
machine authority trait encodes Linux/WASI policy
semantic object stores raw host pointer or raw register truth
service result is accepted without EventLog and ObjectRef evidence
profile use is checked after code starts running
unsupported authority disappears behind an untyped error
```
