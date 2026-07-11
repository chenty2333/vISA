#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-visa-ltp-conformance.sh <output-dir> <ltp-binary-root> [boundary] [profile] [single-runner]

Runs the expanded vISA-backed LTP subset by embedding each selected LTP testcase
ELF into the vISA Linux personality path and gating the resulting raw logs plus
vISA execution traces.

Default subset:

  linux-ltp.fs.basic       open01
  linux-ltp.mm.mapping     mmap01 brk01
  linux-ltp.syscalls.core  getpid01 uname01 getuid01 gettid01 read01 write01
  linux-ltp.sched.timers   clock_gettime01 nanosleep01
  linux-ltp.net.socket     socket01

Each testcase produces:

  <output-dir>/logs/<spec>.<case>.log
  <output-dir>/logs/<spec>.<case>.visa-trace.jsonl
  <output-dir>/logs/<spec>.<case>.serial.log
  <output-dir>/visa-ltp-report.json
  <output-dir>/visa-ltp-gate.json
  <output-dir>/visa-ltp-artifact-gate.json
  <output-dir>/visa-ltp-combined-gate.json

This wrapper fails if any testcase cannot execute through vISA or if the report
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
profile="${4:-device-capable}"
single_runner="${5:-scripts/run-visa-ltp-single.sh}"

if [[ ! -d "$binary_root" ]]; then
    echo "LTP binary root not found: $binary_root" >&2
    exit 66
fi
if [[ ! -x "$single_runner" ]]; then
    echo "vISA LTP single runner is not executable: $single_runner" >&2
    exit 66
fi

run_conformance() {
    cargo run --quiet -p conformance-oracle -- "$@"
}

logs_dir="$output_dir/logs"
mkdir -p "$logs_dir"

plan_file="$output_dir/visa-ltp-plan.tsv"
run_conformance visa-ltp-plan-lines "$output_dir" "$binary_root" >"$plan_file"

run_failures=0
while IFS=$'\t' read -r spec case_id binary raw_log trace_log serial_log _scenario; do
    if [[ -z "$spec" || -z "$case_id" || -z "$binary" || -z "$raw_log" || -z "$trace_log" || -z "$serial_log" ]]; then
        echo "invalid vISA LTP plan row in $plan_file" >&2
        exit 1
    fi
    echo "visa-ltp $spec/$case_id: $binary"
    if ! "$single_runner" "$spec" "$case_id" "$binary" "$raw_log" "$trace_log" "$serial_log"; then
        echo "WARN: vISA LTP testcase failed for $spec/$case_id; preserving logs and continuing" >&2
        run_failures=$((run_failures + 1))
    fi
done <"$plan_file"

report="$output_dir/visa-ltp-report.json"
gate="$output_dir/visa-ltp-gate.json"
artifact_gate="$output_dir/visa-ltp-artifact-gate.json"
combined_gate="$output_dir/visa-ltp-combined-gate.json"

run_conformance ltp-visa-report-from-logs "$logs_dir" "$boundary" "$profile" >"$report"
if ! run_conformance validate-report "$report" >"$gate"; then
    echo "vISA LTP conformance report failed gate: $gate" >&2
    exit 1
fi
if ! run_conformance validate-artifacts "$report" "$logs_dir" >"$artifact_gate"; then
    echo "vISA LTP evidence artifacts failed gate: $artifact_gate" >&2
    exit 1
fi
if ! run_conformance validate-report-with-artifacts "$report" "$logs_dir" >"$combined_gate"; then
    echo "vISA LTP combined report/artifact gate failed: $combined_gate" >&2
    exit 1
fi

if [[ "$run_failures" -ne 0 ]]; then
    echo "$run_failures vISA LTP testcase(s) failed even though report gate passed" >&2
    exit 1
fi

echo "vISA LTP conformance report passed: $report"
echo "vISA LTP evidence artifact gate passed: $artifact_gate"
echo "vISA LTP combined gate passed: $combined_gate"
