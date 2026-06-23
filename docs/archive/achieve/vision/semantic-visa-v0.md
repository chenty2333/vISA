# Legacy Semantic vISA Architecture Note

Status: superseded by `../specs/semantic-virtual-isa-v0/00-overview.md`.

This file keeps the old "Semantic vISA" entry point so older references do not
break. The current architecture is no longer framed primarily as:

```text
new kernel
Linux compatibility layer
Wasm OS
semantic graph kernel
```

The current framing is:

```text
vISA is a capability-oriented Semantic Virtual ISA for portable system
semantics.
```

Read these files instead:

```text
references/vision/semantic-virtual-isa.md
    Narrative summary retained for orientation.

references/specs/semantic-virtual-isa-v0/00-overview.md
    Canonical system spec for the cross-ISA Semantic Virtual ISA.

references/specs/semantic-contract-v0.1/00-overview.md
    Contract ledger, ObjectRef, capability, wait, cleanup, and view boundaries.

references/specs/target-runtime-abi/00-overview.md
    TargetArtifactImage, CodeObject, HostcallFrame, TrapMap, profile, and
    no_std extraction boundaries.

references/specs/substrate-api-v0/00-overview.md
    Rust trait backend for machine authority providers.
```

## Translation From Old Terms

```text
Wasm Supervisor World
    Old term for the artifact/personality layer that implements semantics on
    top of the Semantic Virtual ISA.

Native Machine Substrate
    Still valid, but now described as the backend trait provider for virtual ISA
    machine authorities.

Semantic Object Graph
    Still valid as the inspectable contract ledger for virtual ISA effects.

Semantic vISA
    Historical shorthand. Prefer Semantic Virtual ISA when describing the
    system center.
```

## Stable Invariants That Survive The Rename

```text
Semantic effects stay above machine authority.
Substrate does not define Linux, VFS, socket, futex, epoll, or WASI semantics.
Frontend and personality artifacts define guest-visible behavior.
Capabilities, generations, waits, traps, cleanup, and events are explicit.
TargetArtifactImage is the vISA target-side artifact envelope.
.cwasm or Wasmtime serialized payloads are replaceable code payload variants,
not the vISA semantic ABI.
```

Historical long-form notes remain available under `references/archive/` and in
git history. Do not add new architecture material here; update
`../specs/semantic-virtual-isa-v0/` or the relevant child spec instead.
