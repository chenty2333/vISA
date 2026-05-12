#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-vmos-ltp-manifest.sh <output-dir> <ltp-binary-root> <manifest> [boundary] [profile] [single-runner]

Runs a VMOS-backed LTP manifest through the Linux personality path. The manifest
is TSV with at least:

  spec_id<TAB>case_id<TAB>relative_binary

Additional columns are ignored. This wrapper is for large exploratory runs; the
stable strict gate remains scripts/run-vmos-ltp-conformance.sh.

Environment:

  VMOS_LTP_ALLOW_FAILURES=1  Preserve reports and exit success even when cases fail.
  VMOS_LTP_START_AT=N        Start at 1-based plan row N.
  VMOS_LTP_LIMIT=N           Run at most N selected rows; 0 means no limit.
  VMOS_LTP_RUN_TIMEOUT=120s  Per-case timeout consumed by run-vmos-ltp-single.sh.
  VMOS_LTP_CLEAN_TARGET=1    Run cargo clean after the manifest round.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -lt 3 ]]; then
    usage
    exit 2
fi

output_dir="$1"
binary_root="$2"
manifest="$3"
boundary="${4:-portable-artifact-execution}"
profile="${5:-guest-frontend}"
single_runner="${6:-scripts/run-vmos-ltp-single.sh}"

if [[ ! -d "$binary_root" ]]; then
    echo "LTP binary root not found: $binary_root" >&2
    exit 66
fi
if [[ ! -f "$manifest" ]]; then
    echo "VMOS LTP manifest not found: $manifest" >&2
    exit 66
fi
if [[ ! -x "$single_runner" ]]; then
    echo "VMOS LTP single runner is not executable: $single_runner" >&2
    exit 66
fi

allow_failures="${VMOS_LTP_ALLOW_FAILURES:-0}"
start_at="${VMOS_LTP_START_AT:-1}"
limit="${VMOS_LTP_LIMIT:-0}"

case "$start_at" in
    ''|*[!0-9]*)
        echo "VMOS_LTP_START_AT must be a positive integer" >&2
        exit 64
        ;;
esac
case "$limit" in
    ''|*[!0-9]*)
        echo "VMOS_LTP_LIMIT must be a non-negative integer" >&2
        exit 64
        ;;
esac
if [[ "$start_at" -lt 1 ]]; then
    echo "VMOS_LTP_START_AT must be >= 1" >&2
    exit 64
fi

cleanup() {
    if [[ "${VMOS_LTP_CLEAN_TARGET:-0}" == "1" ]]; then
        cargo clean
    fi
}
trap cleanup EXIT

run_conformance() {
    cargo run --quiet -p vmos-conformance -- "$@"
}

logs_dir="$output_dir/logs"
mkdir -p "$logs_dir"

plan_file="$output_dir/vmos-ltp-manifest-plan.tsv"
run_conformance vmos-ltp-manifest-plan-lines "$output_dir" "$binary_root" "$manifest" >"$plan_file"

row_number=0
selected=0
run_failures=0
while IFS=$'\t' read -r spec case_id binary raw_log trace_log serial_log _scenario; do
    row_number=$((row_number + 1))
    if [[ "$row_number" -lt "$start_at" ]]; then
        continue
    fi
    if [[ "$limit" -ne 0 && "$selected" -ge "$limit" ]]; then
        break
    fi
    if [[ -z "$spec" || -z "$case_id" || -z "$binary" || -z "$raw_log" || -z "$trace_log" || -z "$serial_log" ]]; then
        echo "invalid VMOS LTP plan row in $plan_file" >&2
        exit 1
    fi
    selected=$((selected + 1))
    echo "vmos-ltp manifest row $row_number ($selected selected): $spec/$case_id: $binary"
    if ! "$single_runner" "$spec" "$case_id" "$binary" "$raw_log" "$trace_log" "$serial_log"; then
        echo "WARN: VMOS LTP testcase failed for $spec/$case_id; preserving logs and continuing" >&2
        run_failures=$((run_failures + 1))
    fi
done <"$plan_file"

if [[ "$selected" -eq 0 ]]; then
    echo "VMOS LTP manifest selected no cases" >&2
    exit 1
fi

report="$output_dir/vmos-ltp-report.json"
gate="$output_dir/vmos-ltp-gate.json"
artifact_gate="$output_dir/vmos-ltp-artifact-gate.json"
combined_gate="$output_dir/vmos-ltp-combined-gate.json"

run_conformance ltp-vmos-report-from-logs "$logs_dir" "$boundary" "$profile" >"$report"
if ! run_conformance validate-report "$report" >"$gate"; then
    echo "VMOS LTP manifest report failed gate: $gate" >&2
    if [[ "$allow_failures" != "1" ]]; then
        exit 1
    fi
fi
if ! run_conformance validate-artifacts "$report" "$logs_dir" >"$artifact_gate"; then
    echo "VMOS LTP manifest evidence artifacts failed gate: $artifact_gate" >&2
    exit 1
fi
if ! run_conformance validate-report-with-artifacts "$report" "$logs_dir" >"$combined_gate"; then
    echo "VMOS LTP manifest combined report/artifact gate failed: $combined_gate" >&2
    if [[ "$allow_failures" != "1" ]]; then
        exit 1
    fi
fi

if [[ "$run_failures" -ne 0 && "$allow_failures" != "1" ]]; then
    echo "$run_failures VMOS LTP testcase(s) failed" >&2
    exit 1
fi

echo "VMOS LTP manifest run completed: $selected selected, $run_failures runner failures"
echo "VMOS LTP manifest report: $report"
echo "VMOS LTP manifest artifact gate: $artifact_gate"
echo "VMOS LTP manifest combined gate: $combined_gate"
