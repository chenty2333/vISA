#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-ltp-conformance.sh <output-dir> [boundary] [profile] [runltp]

Runs the VMOS Linux-personality LTP subsets with an installed runltp binary,
then emits:

  <output-dir>/logs/<linux-ltp spec id>.log
  <output-dir>/vmos-ltp-report.json
  <output-dir>/vmos-ltp-gate.json
  <output-dir>/vmos-ltp-artifact-gate.json
  <output-dir>/vmos-ltp-combined-gate.json

The script exits non-zero when runltp is missing, any runltp invocation fails,
the generated conformance report does not pass the report gate, or any evidence
artifact cannot be opened, hashed, parsed, or validated against the report.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -lt 1 ]]; then
    usage
    exit 2
fi

output_dir="$1"
boundary="${2:-portable-artifact-execution}"
profile="${3:-guest-frontend}"
runltp_bin="${4:-runltp}"

if ! command -v "$runltp_bin" >/dev/null 2>&1; then
    echo "runltp binary not found: $runltp_bin" >&2
    exit 127
fi

run_conformance() {
    cargo run --quiet -p vmos-conformance -- "$@"
}

logs_dir="$output_dir/logs"
mkdir -p "$logs_dir"

plan_file="$output_dir/ltp-plan.tsv"
run_conformance ltp-plan-lines "$logs_dir" >"$plan_file"

run_failures=0
while IFS=$'\t' read -r spec scenario result_log; do
    if [[ -z "$spec" || -z "$scenario" || -z "$result_log" ]]; then
        echo "invalid LTP plan row in $plan_file" >&2
        exit 1
    fi
    run_log="$logs_dir/$spec.run.log"
    echo "running $spec with runltp -f $scenario"
    if ! "$runltp_bin" -f "$scenario" -o "$result_log" >"$run_log" 2>&1; then
        echo "WARN: runltp failed for $spec; preserving logs and continuing" >&2
        run_failures=$((run_failures + 1))
    fi
done <"$plan_file"

report="$output_dir/vmos-ltp-report.json"
gate="$output_dir/vmos-ltp-gate.json"
artifact_gate="$output_dir/vmos-ltp-artifact-gate.json"
combined_gate="$output_dir/vmos-ltp-combined-gate.json"

run_conformance ltp-report-from-logs "$logs_dir" "$boundary" "$profile" >"$report"
if ! run_conformance validate-report "$report" >"$gate"; then
    echo "LTP conformance report failed gate: $gate" >&2
    exit 1
fi
if ! run_conformance validate-artifacts "$report" >"$artifact_gate"; then
    echo "LTP evidence artifacts failed gate: $artifact_gate" >&2
    exit 1
fi
if ! run_conformance validate-report-with-artifacts "$report" >"$combined_gate"; then
    echo "LTP combined report/artifact gate failed: $combined_gate" >&2
    exit 1
fi

if [[ "$run_failures" -ne 0 ]]; then
    echo "$run_failures runltp invocation(s) failed even though report gate passed" >&2
    exit 1
fi

echo "LTP conformance report passed: $report"
echo "LTP evidence artifact gate passed: $artifact_gate"
echo "LTP combined gate passed: $combined_gate"
