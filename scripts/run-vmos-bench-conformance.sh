#!/usr/bin/env bash
set -euo pipefail

# Run VMOS host-side microbenchmarks and gate the resulting performance report
# plus the raw Criterion artifacts referenced by that report.
#
# Usage:
#   scripts/run-vmos-bench-conformance.sh [output-dir] [boundary-override] [profile] [criterion-dir]
#
# Set VMOS_SKIP_BENCH_RUN=1 to reuse an existing Criterion directory. This is
# useful for validating parser/gate behavior with fixture estimates.

output_dir=${1:-target/vmos-bench-conformance}
boundary=${2:-}
profile=${3:-}
criterion_dir=${4:-target/criterion}

mkdir -p "$output_dir"

if [[ "${VMOS_SKIP_BENCH_RUN:-0}" != "1" ]]; then
    cargo bench -p vmos-bench
fi

report="$output_dir/vmos-performance-report.json"
gate="$output_dir/vmos-performance-gate.json"
artifact_gate="$output_dir/vmos-performance-artifact-gate.json"

if [[ -n "$boundary" && -n "$profile" ]]; then
    cargo run --quiet -p vmos-conformance -- \
        performance-report-from-criterion "$criterion_dir" "$boundary" "$profile" \
        >"$report"
elif [[ -n "$boundary" ]]; then
    cargo run --quiet -p vmos-conformance -- \
        performance-report-from-criterion "$criterion_dir" "$boundary" \
        >"$report"
elif [[ -n "$profile" ]]; then
    cargo run --quiet -p vmos-conformance -- \
        performance-report-from-criterion "$criterion_dir" "" "$profile" \
        >"$report"
else
    cargo run --quiet -p vmos-conformance -- \
        performance-report-from-criterion "$criterion_dir" \
        >"$report"
fi

cargo run --quiet -p vmos-conformance -- validate-report "$report" >"$gate"
cargo run --quiet -p vmos-conformance -- validate-artifacts "$report" >"$artifact_gate"

echo "Performance conformance report written to $report"
echo "Performance conformance gate written to $gate"
echo "Performance evidence artifact gate written to $artifact_gate"
