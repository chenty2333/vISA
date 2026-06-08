# Guest Memory Object Model

Guest memory is semantic state, not substrate-owned page table truth.

```text
GuestAddressSpace is semantic truth.
Substrate mappings, DMW windows, TLBs, and shadow page tables are disposable
execution bindings.
```

## Objects

```text
GuestAddressSpace
    logical guest address space and generation.

VmaRegion
    guest VA range, permissions, flags, backing ref, generation.

PageObject
    backing memory object, COW state, dirty generation.

Mapping / lease
    temporary substrate binding for execution or zero-copy access.
```

The model is similar to a VMO/VMAR split, but the objects live in the Semantic
Virtual ISA contract ledger, not in a native kernel.

## Rules

```text
copyin/copyout validates VMA permissions and PageObject generation
fast paths cache semantic refs and generations only
COW break bumps PageObject generation and rebinds semantic VMA backing before
new fast paths or substrate mappings can be rebuilt
snapshot barrier rejects active leases or dirty untracked mappings
DMA/MMIO/raw host pointers are not guest memory truth
stale PageObject or VMA generation invalidates cached mapping
```

## Capability Handles

Guest-visible memory or resource handles must be ledger-backed:

```text
CapabilityLedger[StoreRef][slot]
```

Guest code must not gain authority by guessing object ids.

## Comparisons

VMOS resembles Zircon's VMO/VMAR split and seL4-style explicit authority, but
VMOS does not claim seL4-like verification. The claim is narrower: memory and
authority are explicit semantic objects that can be validated, replayed, and
observed across substrate bindings.

## Review Smell

```text
page table state becomes source of truth
fast path bypasses generation checks
active lease crosses wait/trap/cleanup/snapshot boundary
guest handle is just a global object id
```
