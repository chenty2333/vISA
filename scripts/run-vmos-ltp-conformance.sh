#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-vmos-ltp-conformance.sh <output-dir> <ltp-binary-root> [boundary] [profile] [single-runner]

Runs the minimal VMOS-backed LTP subset by embedding each selected LTP testcase
ELF into the VMOS Linux personality path and gating the resulting raw logs plus
VMOS execution traces.

Default subset:

  linux-ltp.fs.basic       open01
  linux-ltp.mm.mapping     mmap01
  linux-ltp.syscalls.core  getpid01

Each testcase produces:

  <output-dir>/logs/<spec>.log
  <output-dir>/logs/<spec>.vmos-trace.jsonl
  <output-dir>/logs/<spec>.serial.log
  <output-dir>/vmos-ltp-report.json
  <output-dir>/vmos-ltp-gate.json
  <output-dir>/vmos-ltp-artifact-gate.json
  <output-dir>/vmos-ltp-combined-gate.json

This wrapper fails if any testcase cannot execute through VMOS or if the report
or artifact gates reject the evidence bundle.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -lt 2 ]]; then
    usage
    exit 2
fi

output_dir="$1"
binary_root="$2"
boundary="${3:-portable-artifact-execution}"
profile="${4:-guest-frontend}"
single_runner="${5:-scripts/run-vmos-ltp-single.sh}"

if [[ ! -d "$binary_root" ]]; then
    echo "LTP binary root not found: $binary_root" >&2
    exit 66
fi
if [[ ! -x "$single_runner" ]]; then
    echo "VMOS LTP single runner is not executable: $single_runner" >&2
    exit 66
fi

run_conformance() {
    cargo run --quiet -p vmos-conformance -- "$@"
}

logs_dir="$output_dir/logs"
mkdir -p "$logs_dir"

plan_file="$output_dir/vmos-ltp-plan.tsv"
run_conformance vmos-ltp-plan-lines "$output_dir" "$binary_root" >"$plan_file"

run_failures=0
while IFS=$'\t' read -r spec case_id binary raw_log trace_log serial_log _scenario; do
    if [[ -z "$spec" || -z "$case_id" || -z "$binary" || -z "$raw_log" || -z "$trace_log" || -z "$serial_log" ]]; then
        echo "invalid VMOS LTP plan row in $plan_file" >&2
        exit 1
    fi
    echo "vmos-ltp $spec/$case_id: $binary"
    if ! "$single_runner" "$spec" "$case_id" "$binary" "$raw_log" "$trace_log" "$serial_log"; then
        echo "WARN: VMOS LTP testcase failed for $spec/$case_id; preserving logs and continuing" >&2
        run_failures=$((run_failures + 1))
    fi
done <"$plan_file"

report="$output_dir/vmos-ltp-report.json"
gate="$output_dir/vmos-ltp-gate.json"
artifact_gate="$output_dir/vmos-ltp-artifact-gate.json"
combined_gate="$output_dir/vmos-ltp-combined-gate.json"

run_conformance ltp-vmos-report-from-logs "$logs_dir" "$boundary" "$profile" >"$report"
if ! run_conformance validate-report "$report" >"$gate"; then
    echo "VMOS LTP conformance report failed gate: $gate" >&2
    exit 1
fi
if ! run_conformance validate-artifacts "$report" "$logs_dir" >"$artifact_gate"; then
    echo "VMOS LTP evidence artifacts failed gate: $artifact_gate" >&2
    exit 1
fi
if ! run_conformance validate-report-with-artifacts "$report" "$logs_dir" >"$combined_gate"; then
    echo "VMOS LTP combined report/artifact gate failed: $combined_gate" >&2
    exit 1
fi

if [[ "$run_failures" -ne 0 ]]; then
    echo "$run_failures VMOS LTP testcase(s) failed even though report gate passed" >&2
    exit 1
fi

echo "VMOS LTP conformance report passed: $report"
echo "VMOS LTP evidence artifact gate passed: $artifact_gate"
echo "VMOS LTP combined gate passed: $combined_gate"
