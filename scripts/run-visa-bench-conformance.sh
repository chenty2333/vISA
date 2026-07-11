#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-visa-bench-conformance.sh [output-dir] [boundary-override] [profile] [criterion-dir]

Runs vISA host-side microbenchmarks and gates the resulting performance report
plus the raw Criterion artifacts referenced by that report.

Set VISA_SKIP_BENCH_RUN=1 to reuse an existing Criterion directory. This is
useful for validating parser/gate behavior with fixture estimates.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 2
fi

output_dir=${1:-target/visa-bench-conformance}
boundary=${2:-}
profile=${3:-}
criterion_dir=${4:-target/criterion}

mkdir -p "$output_dir"

run_conformance() {
    cargo run --quiet -p conformance-oracle -- "$@"
}

if [[ "${VISA_SKIP_BENCH_RUN:-0}" != "1" ]]; then
    cargo bench -p visa-bench
fi

report="$output_dir/visa-performance-report.json"
gate="$output_dir/visa-performance-gate.json"
artifact_gate="$output_dir/visa-performance-artifact-gate.json"
combined_gate="$output_dir/visa-performance-combined-gate.json"

if [[ -n "$boundary" && -n "$profile" ]]; then
    run_conformance performance-report-from-criterion "$criterion_dir" "$boundary" "$profile" \
        >"$report"
elif [[ -n "$boundary" ]]; then
    run_conformance performance-report-from-criterion "$criterion_dir" "$boundary" \
        >"$report"
elif [[ -n "$profile" ]]; then
    run_conformance performance-report-from-criterion "$criterion_dir" "" "$profile" \
        >"$report"
else
    run_conformance performance-report-from-criterion "$criterion_dir" \
        >"$report"
fi

if ! run_conformance validate-report "$report" >"$gate"; then
    echo "Performance conformance report failed gate: $gate" >&2
    exit 1
fi
if ! run_conformance validate-artifacts "$report" "$criterion_dir" >"$artifact_gate"; then
    echo "Performance evidence artifacts failed gate: $artifact_gate" >&2
    exit 1
fi
if ! run_conformance validate-report-with-artifacts "$report" "$criterion_dir" >"$combined_gate"; then
    echo "Performance combined report/artifact gate failed: $combined_gate" >&2
    exit 1
fi

echo "Performance conformance report written to $report"
echo "Performance conformance gate written to $gate"
echo "Performance evidence artifact gate written to $artifact_gate"
echo "Performance combined gate written to $combined_gate"
