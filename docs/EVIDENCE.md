# vISA Evidence Matrix

This document fixes the minimum mature evidence claims. The executable source of
truth is `visa_conformance::minimum_mature_evidence_matrix()` and
`cargo run -p visa-conformance -- evidence-matrix-json`; this document explains
the same matrix for engineering review.

## Semantic Model

Claim id: `mature.semantic-model`

This proves the vISA semantic contract model can name, record, validate, and
view the core contract graph invariants. It does not prove artifact execution,
personality compatibility, performance, or hardware authority.

Required report:

- Suite: `visa-layered-conformance`
- Boundary: `semantic-model`
- Gate: `cargo run -p visa-conformance -- validate-report <report.json>`

Required artifacts:

- `contract-graph-snapshot`
- Artifact gate: `cargo run -p visa-conformance -- validate-artifacts <report.json> <artifact-root>`

Required profile:

- `semantic-harness`
- No substrate authority claim is made at this layer.

Minimum proving specs:

- `visa.wait.trap.cleanup`

Known risk:

- Contract graph snapshots prove identity, generation, lifecycle, and edge shape.
  They do not prove runtime artifact execution or real target enforcement.

## Portable Artifact Execution

Claim id: `mature.portable-artifact-execution`

This proves target-runtime artifact execution through `TargetArtifactImage`,
`CodeObject`, `Store`, `Activation`, typed hostcalls, trap attribution, profile
gates, and portable snapshot evidence. It does not prove Linux compatibility or
real target substrate execution.

Required report:

- Suite: `visa-layered-conformance`
- Boundary: `portable-artifact-execution`
- Gate: `cargo run -p visa-conformance -- validate-report <report.json>`

Required artifacts:

- `contract-graph-snapshot`
- Combined gate: `cargo run -p visa-conformance -- validate-report-with-artifacts <report.json> <artifact-root>`

Required profile:

- Each result must satisfy its catalog profile.
- The minimum mature portable set includes `minimal-bare-metal`,
  `device-capable`, and `snapshot-replay-capable` vISA-native specs.

Minimum proving specs:

- `visa.artifact.load`
- `visa.capability.hostcall`
- `visa.snapshot.restore`
- `visa.native.full-hostcall-abi`

Known risk:

- Linux LTP or WASI results are separate personality-compatibility claims.
- Portable execution can still be host-side or Wasmtime-backed, so it cannot
  claim real target machine authority.
- A contract graph snapshot must not claim a stronger boundary than the result
  observed.

## Real Target Substrate Execution

Claim id: `mature.real-target-substrate-execution`

This proves substrate authority behavior on a real board or QEMU target path with
machine-authority extraction evidence. It is not satisfied by local semantic,
host-side substrate, or portable artifact execution tests alone.

Required report:

- Suite: `visa-substrate-profile-conformance`
- Boundary: `real-target-substrate`
- Gate: `cargo run -p visa-conformance -- validate-report <report.json>`

Required artifacts:

- `substrate-extraction-trace`
- `device-trace`
- Combined gate: `cargo run -p visa-conformance -- validate-report-with-artifacts <report.json> <artifact-root>`

Required profile:

- Report the actual target profile from substrate capability discovery.
- Every claimed profile spec up to that level must pass.
- Device and snapshot claims require `device-capable` or
  `snapshot-replay-capable` evidence respectively.

Minimum proving specs:

- `substrate.p0.semantic.harness`
- `substrate.p1.console.timer.event`
- `substrate.p2.memory.dmw`
- `substrate.p3.mmio.dma.irq`
- `substrate.p4.snapshot.replay`

Required trace context:

- Real-target extraction and device trace entries must carry `target_arch` and
  `target_board`.
- Substrate extraction entries must bind `authority`, `operation`, `event_id`,
  and `event_epoch`.
- Device trace entries must bind `device` or `device_id`, `operation`,
  `event_id`, and `event_epoch`.

Known risk:

- Linux personality compatibility and performance remain separate claims even
  when collected on the same target.
- Trace artifacts must be bundle-relative, content-validated, and hash-matched.
- A host-side substrate report cannot be upgraded to real target by changing only
  the boundary string.

## Personality And Performance Claims

Linux personality, WASI compatibility, and performance benchmarks are not part
of the minimum mature semantic/portable/real-target proof, but they remain
first-class report claims:

- Linux LTP results prove `personality-compatibility` only. Portable-or-stronger
  Linux LTP pass/fail results require both `ltp-raw-log` and
  `linux-personality-trace`.
- Performance benchmark results prove `performance-benchmark` only. They require
  finite metrics and `benchmark-raw-output`.

These results can strengthen a release evidence bundle, but they must not be
used to substitute for semantic model, portable artifact execution, or real
target substrate evidence.
