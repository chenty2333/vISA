# vISA Profile Enforcement Release Gate

## Result
Completed. P0-P4 profile enforcement is now a release gate across loader, runtime, osctl, validator, and conformance reports.

Profile parsing for P0-P4 flows through `visa_profile::SubstrateProfile::parse`. Reported capability labels flow through `capabilities_for_reported_profile`, keeping `host-validation` as a fixture/report label rather than a P0-P4 profile. The profile parsing audit found no remaining runtime/report/CLI P0-P4 parser bypasses; remaining string comparisons are artifact provenance labels, tests, frontend/personality labels, backend adapter profiles, or stable view equality checks.

The loader rejects unknown substrate profiles and enforced-profile downgrades before Wasmtime deserialization/code start. Runtime profile mismatch records `ProfileGateRejected` before substrate dispatch/code publish. Optional degradation records `ProfileGateDegraded` without rejecting otherwise-compatible loads. Target runtime evidence projects profile gate and unsupported substrate events through EventLog, runtime evidence snapshots, target manifests, semantic roots, osctl ViewV1, and package inspect paths.

Conformance reports now have structured `profile-gate-trace` and `substrate-event-trace` artifact kinds. Reports that declare profile gate event counts or unsupported substrate event counts must attach matching trace artifacts. Artifact validation checks event id/epoch, event kind, attribution, profile fields, and count consistency.

P0-P4 focused coverage now spans loader, runtime profile gate, substrate compatibility validation, osctl profile helper behavior, and conformance report/artifact gates.

## Evidence
Verified clean:

- `cargo fmt --all --check`
- `cargo test -p target_executor`
- `cargo test -p visa_runtime`
- `cargo test -p contract_validate`
- `cargo test -p osctl-view`
- `cargo test -p visa-conformance`

## Remaining Risk
The new conformance trace artifact formats are structured JSONL gates, not separately versioned schemas. They are validated enough for this release gate, but external runner adoption may justify promoting them to explicit schema-versioned trace formats later.
