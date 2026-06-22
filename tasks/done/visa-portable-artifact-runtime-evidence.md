# vISA Portable Artifact Runtime Evidence Result

## Goal
Promote portable artifact execution to the primary runtime/conformance evidence path.

## Accepted Scope
Core runtime and conformance evidence should default through `TargetArtifactImage -> CodeObject -> Store -> Activation -> HostcallFrame -> TrapMap`, not through reference/native service bypasses. Core hostcall, trap, wait, cleanup, and failure cases must be represented through the artifact execution path. Conformance reports must carry artifact identity, profile gate, activation, hostcall, trap, and event evidence. Reference harness evidence may remain useful for debug/baseline, but must not claim portable artifact execution.

## Result
Portable artifact execution evidence is now enforced by runtime snapshots and conformance artifact gates. `visa-conformance` rejects portable-or-stronger contract graph snapshots unless they contain artifact, code-object, store, activation, hostcall-or-trap evidence, and portable explicit edges for the artifact execution path. Wait tokens and cleanup transactions now need incoming portable edges. Successful paths stay live; trap/failure/completed-cleanup history may use historical portable edges so dead stores, retired code, and inactive activations are not represented as live.

`VisaRuntime` now emits portable artifact-path edges for artifact load, code object binding, store activation, hostcall dispatch, trap attribution, timer wait evidence, and pending/completed cleanup. Cleanup runtime events now distinguish started versus completed transactions correctly, with tests guarding the event names. Focused failure coverage includes profile-gate rejection, unsupported substrate/hostcall, capability denial before substrate dispatch, bad hostcall ABI, malformed artifact image, missing code section, and TrapMap-attributed Wasm trap. Repeated artifact execution uses distinct execution-store package keys while preserving artifact/code attribution to the source package.

Report generation boundaries are hardened. Host-side LTP log generation now defaults to `reference-service`, while vISA-backed LTP keeps `portable-artifact-execution`. The report gate explicitly proves host/reference raw logs cannot satisfy portable Linux personality claims without vISA trace artifacts. The full LTP conformance wrapper now defaults to `device-capable`, matching the cataloged socket subset profile requirement.

## Evidence
Verification passed:

- `scripts/check-conformance-report.sh`
- `cargo fmt --all --check`
- `cargo test -p visa-conformance`
- `cargo test -p visa_runtime`
- `cargo test -p visa_wasmtime`
- `cargo test -p semantic_core`

These checks cover the runtime artifact path, hostcall/trap/wait/cleanup linkage, failure attribution, report/artifact gates, host/reference boundary rejection, and current semantic graph invariants.

## Remaining Risk
Completed cleanup is proven for the runtime-owned no-wait/no-capability path. Cleanup that cancels active waits needs first-class wait cancellation evidence, and cleanup that revokes store-owned capabilities needs declared authority object evidence for revoked targets. Treat this as future cleanup hardening, not as a blocker for the portable artifact execution evidence path completed here.
