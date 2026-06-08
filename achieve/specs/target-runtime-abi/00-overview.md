# Target Runtime ABI Overview

Status: active runtime/artifact contract.

The Target Runtime ABI defines how Semantic Virtual ISA artifacts become
loadable, callable, attributable runtime objects. It is not the semantic policy
layer and it is not the WASI application ABI.

The parent vISA spec is `../semantic-virtual-isa-v0/00-overview.md`. This
sub-spec explains how vISA artifacts are carried through target-runtime objects
without making frontend ABIs or substrate details semantic truth.

```text
TargetArtifactImage
    signed/hash-covered envelope for a payload and metadata.

CodeObject
    published executable identity with generation, W^X lifecycle, and TrapMap.

HostcallFrame
    stable wire ABI for entering virtual ISA machine and service operations.

PcRange / TrapMap
    target PC attribution back to CodeObject offsets and semantic traps.

Target profile
    required and optional virtual ISA feature set for the current substrate.

no_std extraction
    panic-safe, read-only JSONL/control-plane export path.
```

## Ownership

Target Runtime ABI owns:

```text
artifact envelope layout
section table and hash/signature coverage
CodeObject publish states
HostcallFrame wire layout and status values
trap PC attribution tables
profile compatibility records
runtime package layout
allocator/log/panic/osctl extraction boundaries
```

It does not own:

```text
Capability policy
WaitToken policy
Store lifecycle policy
FaultCleanupTransaction policy
WASI app-facing worlds
Linux syscall behavior
substrate implementation details
Wasmtime private serialized-module semantics
```

## Non-Negotiable Rules

```text
Artifact envelope is the only target-loadable unit; do not load naked code blobs.
CodeObject publish must enforce W^X; never publish RWX memory.
Published CodeObject bytes are immutable; changes create a new generation.
I-cache synchronization is a mandatory CodePublishAuthority step.
HostcallFrame is a wire ABI, not an internal Rust helper call.
Hostcall caller identity is derived from active Activation / Store / Code state.
Capability handles carry object generation but the ledger remains authority.
Trap PC must map to CodeObject offset or produce a target fault.
TrapRecord edges to Store / Activation / CodeObject are historical references.
Target profile decides load compatibility before code runs.
no_std panic/log/osctl extraction must not allocate, call Wasm, or mutate graph.
```

## Document Map

```text
01-target-artifact-image.md
    Envelope, FakeAotBlob, hash/signature, imports, and relocation boundary.

02-code-publish-and-cache.md
    W^X, CodeObject lifecycle, and cache synchronization.

03-hostcall-frame.md
    HostcallFrame, caller/capability refs, scratch memory, and status rules.

04-trap-map-and-attribution.md
    PcRange, TrapMap, and historical trap refs.

05-target-profile-and-runtime-package.md
    Target profile, package layout, QEMU profile, FDT, and reboot policy.

06-nostd-control-plane.md
    JSONL extraction, panic ring, allocator, log, and panic boundaries.

07-implementation-order.md
    Retained implementation boundary summary.

08-default-profile.md
    Default research profile values that tests currently pin.
```

The semantic contract remains the source of truth for ObjectRef, Capability,
WaitToken, Store, cleanup, and views. This runtime ABI consumes and emits those
objects; it does not redefine their policy.
