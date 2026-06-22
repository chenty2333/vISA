# vISA Substrate Authority Families

## Result
Completed. Console, timer, event, and memory now share a contract-visible substrate authority-family model through `visa_profile::AuthorityFamily`, `SubstrateCapabilitySet`, runtime authority descriptors, EventLog substrate events, target-runtime manifests, ViewV1 extraction, validator gates, and conformance report artifacts.

Each core authority family has a stable family id, profile authority declaration, substrate trait mapping, declared operations, and P1/P2 support checks. Runtime hostcall dispatch derives family-tagged authority descriptors for `ConsoleAuthority`, `TimerAuthority`, `EventQueueAuthority`, and `GuestMemoryAuthority`; successful dispatch records `SubstrateAuthorityExtracted`, unsupported backend dispatch records `SubstrateUnsupported`, and preflight/backend capability failures record `SubstrateCapabilityDenied` without committing false success evidence.

The native vISA artifact path exercises console, timer, event push/pop, and memory copyin/copyout through the portable `TargetArtifactImage -> CodeObject -> Store -> Activation -> HostcallFrame` path. Runtime evidence snapshots export combined `substrate-event-trace` JSONL with authority family, authority trait, operation, requester, artifact/store attribution, and capability handle/generation where present.

Target executor projection carries substrate authority evidence into `SubstrateEventManifest`; osctl ViewV1 exposes authority family, capability state/handle, unsupported, denied, and authority-extracted evidence. Conformance validates substrate event traces for family presence, known family ids, authority/family consistency, declared operations, attribution for unsupported/denied events, denied capability handle pairing, and reported metric counts. Reports with unsupported, denied, or authority-extraction metrics must attach substrate event evidence.

External audit now links event queue authority evidence back to `event-log` hostcalls as a real target extraction path, including a negative operation-mismatch case, so event authority evidence is not runtime-only.

## Evidence
Verified clean:

- `git diff --check`
- `cargo fmt --all --check`
- `cargo check -p visa_runtime -p semantic_core -p target_executor -p osctl-view -p visa-conformance -p contract_validate -p visa-bench -p substrate_api -p visa_profile`
- `cargo test -p visa_profile`
- `cargo test -p substrate_api`
- `cargo test -p visa_runtime`
- `cargo test -p semantic_core`
- `cargo test -p target_executor`
- `cargo test -p contract_validate`
- `cargo test -p visa-conformance`
- `cargo test -p osctl-view`
- `cargo test -p visa_wasmtime`
- `cargo test -p visa-bench --lib`

Focused tests additionally covered profile gate downgrade rejection, console and memory preflight capability denial, full console/timer/event/memory authority-family runtime extraction, substrate-event trace validation, ViewV1 denied/unsupported extraction, and external audit event queue linkage.

## Remaining Risk
Memory authority in this goal is intentionally limited to `GuestMemoryAuthority` profile/capability/runtime/evidence behavior. Full `GuestAddressSpace`, `VmaRegion`, `PageObject`, COW, mmap/munmap/mprotect/brk, and page-fault semantic truth belongs to the later guest-memory goal.

Runtime Store identity now supports multiple execution instances for the same artifact package. Future code should use store id/generation for runtime execution identity rather than assuming package is unique.
