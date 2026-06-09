# vISA Artifact Activation Path

## Result
Hardened the `TargetArtifactImage -> CodeObject -> Store -> Activation -> HostcallFrame -> TrapMap` path with focused tests and one runtime consistency fix.

Added runtime tests for malformed target artifact image rejection, missing `CodeObject` section rejection before substrate dispatch, and trap evidence preservation across artifact, code object, store, activation, and contract graph snapshot JSON. Added target executor coverage for stale activation-generation `HostcallFrame` rejection without success trace mutation or activation generation advancement.

The trap evidence test exposed a real runtime mismatch: `SemanticGraph` advanced the Store generation while the execution-side `TargetStoreManager` kept a separate generation before `CodeObject` binding. The runtime now mirrors the semantic `StoreRecord` into the store manager before binding and activation, keeping contract graph edge generations consistent.

## Evidence
Verified clean:

- `cargo fmt --all --check`
- `cargo test -p visa_runtime`
- `cargo test -p semantic_core`
- `cargo test -p target_abi`
- `cargo test -p visa-conformance`
- `git diff --check`
- old-name scan for legacy vISA names
- `sudo scripts/run-docker-ci-gate.sh --ci-cache`

Docker CI passed all gates: metadata, fmt, check-wasm, visa-conformance tests, sample validation, and kernel check. Kernel check emitted existing dead-code warnings only.

## Remaining Risk
The Store generation fix is intentionally scoped to the runtime mirror path. Standalone target executor store lifecycle behavior remains unchanged and covered by existing tests.
