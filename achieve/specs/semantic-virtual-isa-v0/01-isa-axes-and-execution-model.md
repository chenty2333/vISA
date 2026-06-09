# ISA Axes And Execution Model

The Semantic Virtual ISA separates four axes that are easy to confuse:

```text
Host ISA
    Real target architecture and board profile: riscv64, x86_64, aarch64,
    QEMU profiles, SoC variants, and firmware entry contracts.

Wasm execution ISA
    The mature virtual execution substrate: modules, imports/exports, linear
    memory, structured control flow, traps, sandboxing, AOT/interpreter/JIT
    implementations, and Component Model ecosystem.

Semantic Virtual ISA
    vISA system semantics above Wasm: authority, capability, lifetime, wait,
    trap, cleanup, artifact identity, hostcall attribution, profile use, and
    contract-visible effects.

Guest ISA / ABI
    Optional frontend surface: Linux ELF, WASI app world, JS/runtime ABI, or
    another compatibility personality.
```

The Semantic Virtual ISA is the system center. Host ISA differences are
absorbed through substrate profiles. Guest ABI differences are absorbed through
frontend/personality artifacts.

## Primary Execution

```text
TargetArtifactImage
  -> CodeObject
  -> Store
  -> Activation
  -> HostcallFrame / TrapMap
  -> Semantic Virtual ISA operation
  -> contract ledger effect
  -> optional substrate_api trait call
  -> hardware substrate
```

No naked code blob, native helper, or service shortcut is a portable vISA
execution path until it is represented through this chain.

## Optional Frontend Execution

```text
guest ABI input
  -> personality artifact
  -> vISA artifact execution path
```

A Linux syscall, WASI call, or custom WIT call is conforming only when it
normalizes into vISA effects with ObjectRefs, generations, capabilities, waits,
events, traps, and cleanup edges where applicable.

## Portability Boundary

Portable semantic state:

```text
contract ledger objects
ObjectRef and generation graph
capability ledger
WaitToken state
Store / Activation / FaultDomain lifecycle
GuestAddressSpace / VmaRegion / PageObject model
artifact identity and profile requirements
EventLog and stable views
```

Host-specific state:

```text
native page tables
TLB state
raw register frames
native stack frames
DMA/IOMMU mappings
MMIO bindings
IRQ controller state
published native CodeObject bytes
Wasmtime private serialized-module details
```

Host-specific state may be dropped, rebuilt, replayed, or revalidated on a
destination substrate. It is not semantic truth.
