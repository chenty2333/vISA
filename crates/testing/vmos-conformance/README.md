# vmos-conformance

`vmos-conformance` defines the layered VMOS/vISA test taxonomy and report contract.

The suite separates four claims:

- `visa-semantic-conformance`: vISA artifact, ledger, activation, hostcall, capability, wait, trap, cleanup, snapshot, and restore behavior.
- `substrate-profile-conformance`: substrate authority behavior for the stable profile matrix.
- `personality-compatibility`: guest/personality compatibility suites such as Linux LTP and WASI.
- `performance-benchmark`: latency and throughput measurements.

LTP is intentionally cataloged under `personality-compatibility` with `personality=linux`.
Passing an LTP subset can prove Linux personality compatibility for that subset. It does not prove vISA semantic completeness, substrate profile conformance, or real target substrate execution unless those claims are reported separately with the required evidence boundary.
`substrate_report_from_conformance` converts `substrate_api` profile conformance
reports into this same report schema, including P0 semantic-harness through P4
snapshot-replay-capable profile claims.

Useful commands:

```sh
cargo run -p vmos-conformance -- plan-json
cargo run -p vmos-conformance -- sample-report-json
cargo run -p vmos-conformance -- ltp-plan-json
cargo run -p vmos-conformance -- ltp-plan-lines target/ltp
cargo run -p vmos-conformance -- vmos-ltp-plan-lines target/vmos-ltp /opt/ltp/testcases/bin
cargo run -p vmos-conformance -- sample-ltp-report-json
cargo run -p vmos-conformance -- sample-performance-report-json
cargo run -p vmos-conformance -- validate-sample
cargo run -p vmos-conformance -- write-sample-report target/vmos-conformance.json
cargo run -p vmos-conformance -- validate-report target/vmos-conformance.json
cargo run -p vmos-conformance -- validate-artifacts target/vmos-conformance.json .
cargo run -p vmos-conformance -- validate-report-with-artifacts target/vmos-conformance.json .
cargo run -p vmos-conformance -- ltp-report-from-logs target/ltp portable-artifact-execution guest-frontend
cargo run -p vmos-conformance -- ltp-vmos-report-from-logs target/vmos-ltp/logs portable-artifact-execution guest-frontend
cargo run -p vmos-conformance -- performance-plan-lines target/criterion
cargo run -p vmos-conformance -- performance-report-from-criterion target/criterion
cargo run -p vmos-conformance -- attach-evidence-artifact target/vmos-conformance.json '*' substrate-extraction-trace target/evidence/substrate.jsonl aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "real target extraction trace"
cargo run -p vmos-conformance -- attach-evidence-artifact-file target/vmos-conformance.json '*' substrate-extraction-trace target/evidence/substrate.jsonl "real target extraction trace"
scripts/run-host-ltp-log-adapter.sh target/host-ltp-run portable-artifact-execution guest-frontend runltp
scripts/run-vmos-ltp-conformance.sh target/vmos-ltp-run /opt/ltp/testcases/bin
scripts/run-vmos-bench-conformance.sh target/vmos-bench-run
scripts/run-report-gates.sh
```

The `sample-*` commands are schema fixtures. They are useful for checking JSON
shape and catalog wiring, but they are not executable evidence and should not be
reported as a real conformance pass. Use the LTP, benchmark, substrate, or
runtime runners for executable claims.

Executable LTP integration should consume the catalog entries whose ids start with
`linux-ltp.`, parse run output into `LtpCaseResult`, attach raw LTP logs, and
attach `linux-personality-trace` artifacts when the result claims VMOS-backed
portable artifact execution. Host-side LTP logs without VMOS trace artifacts are
valid parser inputs, but they must not be reported as VMOS Linux personality
conformance.
`validate-report` is the intended report gate for external runners; it accepts a
file path or `-` for stdin and exits non-zero when the JSON is malformed, references
unknown specs, overclaims an evidence boundary, omits pass/fail evidence, or contains
duplicate or empty result sets. It also exits non-zero when any reported result is
`fail`, `skip`, or `not-run`.
`validate-artifacts` is the local evidence artifact gate. It opens artifact files,
checks SHA-256 digests, and applies type-specific structure checks for raw LTP
logs, Criterion estimates, extraction traces, device traces, serial logs, and
contract graph snapshots. Evidence artifact URIs must be relative to the artifact
root passed to the command; absolute paths and `..` escapes are rejected so reports
can be moved as bundles.
`validate-report-with-artifacts` composes both gates and is the preferred local
package gate for executable evidence bundles. It fails when either the report
contract or any linked evidence artifact fails validation.
Portable-or-stronger `visa-semantic-conformance` pass/fail results must include a
`contract-graph-snapshot` artifact. Snapshot artifact files use
`schema_version=contract-graph-snapshot-v0.1`, declare `claimed_evidence_level`,
and carry the core snapshot arrays needed by the artifact gate. The artifact gate
rejects unknown snapshot schema ids, snapshot boundary overclaims relative to the
owning result, and artifact paths that are absolute or escape the artifact root.
Results that claim `real-target-substrate` must include a structured
`substrate-extraction-trace` or `device-trace` evidence artifact with a URI,
SHA-256 digest, and description. Free-form evidence text alone is not enough for
real target claims. `attach-evidence-artifact` can add this metadata to an
existing report for one spec id or for all results with `*`.
`attach-evidence-artifact-file` is the safer local runner variant: it reads the
artifact file and computes the SHA-256 digest before attaching the metadata. The
attached path must still be relative to the artifact root used by
`validate-artifacts` when the resulting report should be bundle-valid.
`ltp-report-from-logs` reads files named `<linux-ltp spec id>.log` from the given
directory, marks missing subset logs as `not-run`, and emits a Linux personality
compatibility report that can be piped into `validate-report`. Present subset logs
are attached as `ltp-raw-log` artifacts with SHA-256 hashes. If matching files
named `<linux-ltp spec id>.vmos-trace.jsonl` exist, they are attached as
`linux-personality-trace` artifacts.
`ltp-vmos-report-from-logs` emits a staged VMOS-backed subset report from the
logs that are present. It is intended for `scripts/run-vmos-ltp-conformance.sh`
and does not require unrelated LTP subsets to appear in the same bundle.
Portable-or-stronger LTP pass/fail results must carry both `ltp-raw-log` and
`linux-personality-trace` artifacts. The trace gate requires entries to identify
the VMOS Linux personality runner, state that VMOS execution and Linux dispatch
were observed, and record positive syscall/service counts.
`scripts/run-host-ltp-log-adapter.sh` is the host-side adapter for an external
`runltp` binary. It preserves raw logs and validates the raw-log artifact bundle,
but it is not VMOS-backed LTP evidence and its report gate is expected to fail
when VMOS trace artifacts are absent.
`scripts/run-vmos-ltp-conformance.sh` is the VMOS-backed runner. It embeds each
selected testcase ELF through `VMOS_LINUX_USER_ELF`, runs the QEMU VMOS runner,
captures serial output, emits raw LTP logs plus VMOS Linux personality traces,
and gates the resulting report/artifact bundle. Ordinary dynamic Linux binaries
may still fail until the VMOS Linux ELF frontend supports their loader, stack,
and auxv requirements; those failures are recorded as LTP failures, not hidden.
`scripts/run-ltp-conformance.sh` remains only as a deprecated compatibility alias
for the host log adapter.
Performance benchmark reports use the `vmos-performance-benchmark` suite id.
Passing or failing performance results must carry concrete finite, non-negative
numeric metrics and at least one `benchmark-raw-output` artifact. The current
required keys are `latency_ns` for hostcall, activation, and snapshot/restore
latency claims, scheduler preemption, SIMD context/speedup records, and display
framebuffer records, plus `block_iops` and `network_packets_per_sec` for the
block/network throughput claim.
`performance-report-from-criterion` reads Criterion `estimates.json` files under
`target/criterion`, maps known benchmark ids into those metrics, and reports
missing benchmark outputs as explicit `not-run` results. `performance-plan-lines`
exports the same benchmark-id to metric mapping for shell fixtures and external
runners that need to prepare or archive Criterion outputs.
When no boundary override is provided, each performance result uses its cataloged
minimum boundary. Mixed reports therefore keep SemanticGraph-only mutation
benchmarks separate from runtime/artifact-path benchmarks. A runner may pass an
explicit stronger boundary only when every result in the run can legitimately
claim that boundary.
`scripts/run-vmos-bench-conformance.sh` is the standard wrapper for running
`cargo bench -p vmos-bench`, preserving the generated performance report, and
gating it through `validate-report`, `validate-artifacts`, and
`validate-report-with-artifacts`. It emits `vmos-performance-report.json`,
`vmos-performance-gate.json`, `vmos-performance-artifact-gate.json`, and
`vmos-performance-combined-gate.json`.
