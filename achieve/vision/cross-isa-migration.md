# Cross-ISA Portability And Migration

Status: vision note.

Cross-ISA portability is not a standalone migration feature. It is a core
conformance test for the Semantic Virtual ISA boundary: if semantic state,
authority, lifetime, traps, waits, cleanup, artifact identity, and profile
requirements cannot survive host ISA changes, the vISA boundary is leaking
substrate detail.

```text
vISA artifact
  -> Semantic Virtual ISA operation
  -> contract ledger
  -> substrate backend profile
  -> host ISA
```

## What Can Migrate

Portable state:

```text
contract ledger objects
ObjectRef and generation graph
capability ledger
WaitToken state
Store lifecycle state
GuestAddressSpace / VmaRegion / PageObject model
artifact identity and manifest metadata
event log and stable views
```

Host-specific state:

```text
native page tables
TLB state
DMW windows
DMA/IOMMU mappings
MMIO bindings
IRQ controller state
published native CodeObject bytes
raw stack/register frames
```

Host-specific bindings must be dropped, replayed, or rebuilt on the target
substrate. They are not semantic truth.

## Migration Boundary

Migration is valid only if the destination profile can satisfy the artifact and
contract requirements:

```text
same semantic contract schema
compatible artifact/profile requirements
available required substrate authorities
rebuildable code payload or compatible target artifact
no active non-migratable leases
snapshot barrier completed
```

## Guest ISA / Frontend Position

Linux ELF or another guest ISA is a frontend concern. The frontend may need
architecture-specific register, syscall, signal, and memory layout handling, but
those details should normalize into the same Semantic Virtual ISA effects.

## Review Smell

```text
page table state treated as portable truth
DMA/MMIO binding appears in snapshot without lease cleanup
guest ABI register frame is confused with Semantic vISA activation state
destination substrate starts artifact before profile compatibility check
```
