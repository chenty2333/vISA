# vISA Guest Memory Semantics

## Goal
Make `GuestAddressSpace`, `VmaRegion`, `PageObject`, COW, page fault, `mmap`/`munmap`/`mprotect`/`brk` stable semantic memory model state rather than a projection of host page tables.

## Accepted Scope
Promote guest memory objects and operations into contract-visible vISA state. `GuestAddressSpace`, `VmaRegion`, and `PageObject` need stable ObjectRef/generation/tombstone semantics; memory syscalls need contract-visible records and validator coverage; COW, page fault, permissions, generation drift, stale mappings, cleanup, snapshot barriers, and host mapping rebuilds need focused positive and negative evidence. Linux memory behavior must map into this semantic model instead of treating live page tables as semantic truth.

## Current Plan
1. Extend the guest-memory semantic model from object state into explicit operation records for `mmap`, `munmap`, `mprotect`, `brk`, COW, page fault, permission check, stale mapping, cleanup, and snapshot barriers.
2. Add validator positive and negative cases for those operation records and their ObjectRef/generation/tombstone edges.
3. Project operation records into package manifests, semantic roots, ViewV1, runtime restore, and conformance reports.
4. Connect Linux guest-memory projection to these semantic records without expanding Linux claims beyond the contract-visible evidence path.

## Progress
Policies under `docs/policies/` were read. The first contract-visible object-state slice is implemented for `GuestAddressSpace`, `VmaRegion`, `PageObject`, and guest-memory fault records. Existing `GuestMemoryManager` records now enter `SemanticGraph`, `ContractGraphSnapshot`, package manifest counts/records/roots, contract validation, `osctl` ViewV1 collection/show output, and `VisaRuntime::restore_portable_subset()`. Focused tests cover graph snapshot validation, stale VMA/page generation, malformed page/fault metadata, package root/count mismatch, package projection, ViewV1 aliases/show, and portable restore preservation.

## Next Actions
Implement explicit guest-memory operation records for `mmap`, `munmap`, `mprotect`, and `brk`, then add validator positive/negative coverage and project those records through package roots/counts and ViewV1.

## Risks
Goal 10 is not complete. The current slice proves object-state portability and visibility, but memory syscall operation records, COW/page fault operation records, cleanup lifecycle evidence, snapshot barrier contract records, and Linux syscall mapping are still incomplete. The Linux memory bridge still has substantial live page-table behavior, which is not sufficient completion evidence unless it maps into these semantic records.
