# vmos-conformance

`vmos-conformance` defines the layered VMOS/vISA test taxonomy and report contract.

The suite separates four claims:

- `visa-semantic-conformance`: vISA artifact, ledger, activation, hostcall, capability, wait, trap, cleanup, snapshot, and restore behavior.
- `substrate-profile-conformance`: substrate authority behavior for the stable profile matrix.
- `personality-compatibility`: guest/personality compatibility suites such as Linux LTP and WASI.
- `performance-benchmark`: latency and throughput measurements.

LTP is intentionally cataloged under `personality-compatibility` with `personality=linux`.
Passing an LTP subset can prove Linux personality compatibility for that subset. It does not prove vISA semantic completeness, substrate profile conformance, or real target substrate execution unless those claims are reported separately with the required evidence boundary.

Useful commands:

```sh
cargo run -p vmos-conformance -- plan-json
cargo run -p vmos-conformance -- sample-report-json
cargo run -p vmos-conformance -- ltp-plan-json
cargo run -p vmos-conformance -- ltp-plan-lines target/ltp
cargo run -p vmos-conformance -- sample-ltp-report-json
cargo run -p vmos-conformance -- sample-performance-report-json
cargo run -p vmos-conformance -- validate-sample
cargo run -p vmos-conformance -- write-sample-report target/vmos-conformance.json
cargo run -p vmos-conformance -- validate-report target/vmos-conformance.json
cargo run -p vmos-conformance -- ltp-report-from-logs target/ltp portable-artifact-execution guest-frontend
cargo run -p vmos-conformance -- performance-report-from-criterion target/criterion portable-artifact-execution
cargo run -p vmos-conformance -- attach-evidence-artifact target/vmos-conformance.json '*' substrate-extraction-trace target/evidence/substrate.jsonl aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "real target extraction trace"
scripts/run-ltp-conformance.sh target/ltp-run portable-artifact-execution guest-frontend runltp
scripts/run-vmos-bench-conformance.sh target/vmos-bench-run portable-artifact-execution
```

Executable LTP integration should consume the catalog entries whose ids start with
`linux-ltp.`, use `LtpInvocation` or `ltp-plan-lines` to derive subset commands,
parse run output into `LtpCaseResult`, and emit `ConformanceReport` JSON using the
schema in `src/lib.rs`.
`validate-report` is the intended report gate for external runners; it accepts a
file path or `-` for stdin and exits non-zero when the JSON is malformed, references
unknown specs, overclaims an evidence boundary, omits pass/fail evidence, or contains
duplicate or empty result sets. It also exits non-zero when any reported result is
`fail`, `skip`, or `not-run`.
Results that claim `real-target-substrate` must include a structured
`substrate-extraction-trace` or `device-trace` evidence artifact with a URI,
SHA-256 digest, and description. Free-form evidence text alone is not enough for
real target claims. `attach-evidence-artifact` can add this metadata to an
existing report for one spec id or for all results with `*`.
`ltp-report-from-logs` reads files named `<linux-ltp spec id>.log` from the given
directory, marks missing subset logs as `not-run`, and emits a Linux personality
compatibility report that can be piped into `validate-report`. Present subset logs
are attached as `ltp-raw-log` artifacts with SHA-256 hashes.
`scripts/run-ltp-conformance.sh` is the standard wrapper when a target already has
LTP installed. It runs the cataloged subsets, preserves raw logs, emits
`vmos-ltp-report.json`, and gates the result.
Performance benchmark reports use the `vmos-performance-benchmark` suite id.
Passing or failing performance results must carry concrete finite, non-negative
numeric metrics and at least one `benchmark-raw-output` artifact. The current
required keys are `latency_ns` for hostcall, activation, and snapshot/restore
latency claims, plus `block_iops` and `network_packets_per_sec` for the
block/network throughput claim.
`performance-report-from-criterion` reads Criterion `estimates.json` files under
`target/criterion`, maps known benchmark ids into those metrics, and reports
missing benchmark outputs as explicit `not-run` results.
`scripts/run-vmos-bench-conformance.sh` is the standard wrapper for running
`cargo bench -p vmos-bench`, preserving the generated performance report, and
gating it through `validate-report`.
