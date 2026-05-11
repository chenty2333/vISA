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
cargo run -p vmos-conformance -- sample-ltp-report-json
cargo run -p vmos-conformance -- validate-sample
```

Executable LTP integration should consume the catalog entries whose ids start with
`linux-ltp.`, use `LtpInvocation` to derive subset commands, parse run output into
`LtpCaseResult`, and emit `ConformanceReport` JSON using the schema in `src/lib.rs`.
