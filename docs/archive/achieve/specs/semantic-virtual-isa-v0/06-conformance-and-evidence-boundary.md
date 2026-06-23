# Conformance And Evidence Boundary

Evidence must say what it proves. A working reference service, host harness, or
native helper is not automatically portable vISA artifact execution.

## Evidence Levels

```text
semantic model
    Contract effects can be named, recorded, validated, and viewed.

reference/native service
    A host-side service produces the expected effects, but execution may still
    bypass artifact/runtime attribution.

reference AOT harness
    A target-runtime-shaped harness exercises artifact, hostcall, trap, and
    profile records, but not necessarily a real substrate.

portable artifact execution
    TargetArtifactImage, CodeObject, Activation, HostcallFrame, TrapMap, and
    profile gates are exercised without relying on host-only shortcuts.

real target substrate execution
    The same artifact path runs on a real board/QEMU substrate with enforceable
    machine authority and extraction evidence.
```

Do not claim a stronger level than the weakest boundary exercised.

## Cross-ISA Portability

Cross-ISA portability is not a standalone migration feature. It is a core
conformance test for the Semantic Virtual ISA boundary: if semantic state,
authority, lifetime, traps, waits, cleanup, artifact identity, and profile
requirements cannot survive host ISA changes, the vISA boundary is leaking
substrate detail.

Migration is valid only when:

```text
same semantic contract schema
compatible artifact/profile requirements
destination profile satisfies required substrate authorities
host-specific bindings are dropped, rebuilt, or replayed
no active non-migratable leases remain
snapshot barrier completed
stable views expose the evidence
```

## Required Reports

Conformance reports should name:

```text
claimed evidence level
artifact identity and profile requirement
substrate capability report
capability and generation checks exercised
EventLog/ViewV1 evidence roots
unsupported/degraded authority evidence
known host-specific state that was rebuilt or excluded
```

## Review Smells

```text
reference-service evidence claims portable artifact execution
real target claim lacks profile report
cross-ISA snapshot includes raw page tables or raw DMA/MMIO bindings
destination starts code before profile compatibility check
unsupported authority is invisible
test only checks CLI prose instead of stable evidence roots
```
