#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-host-ltp-log-adapter.sh <output-dir> [boundary] [profile] [runltp]

Runs an external host-provided runltp binary and preserves raw LTP logs for the
vISA conformance log adapter.

This is not vISA-backed LTP execution. It does not prove vISA Linux personality
compatibility, vISA portable artifact execution, or real target substrate
execution. Use scripts/run-visa-ltp-conformance.sh when LTP test binaries must
execute through the vISA Linux personality path.

Outputs:

  <output-dir>/logs/<linux-ltp spec id>.log
  <output-dir>/host-ltp-log-adapter-report.json
  <output-dir>/host-ltp-log-adapter-artifact-gate.json
  <output-dir>/host-ltp-log-adapter-report-gate.json

The report gate is expected to fail for pure host logs when vISA-backed trace
artifacts are absent. The artifact gate validates the raw log bundle.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -lt 1 ]]; then
    usage
    exit 2
fi

output_dir="$1"
boundary="${2:-reference-service}"
profile="${3:-guest-frontend}"
runltp_bin="${4:-runltp}"

if ! command -v "$runltp_bin" >/dev/null 2>&1; then
    echo "runltp binary not found: $runltp_bin" >&2
    exit 127
fi

run_conformance() {
    cargo run --locked --quiet -p conformance-oracle -- "$@"
}

logs_dir="$output_dir/logs"
mkdir -p "$logs_dir"

plan_file="$output_dir/host-ltp-plan.tsv"
run_conformance ltp-plan-lines "$logs_dir" >"$plan_file"

run_failures=0
while IFS=$'\t' read -r spec scenario result_log; do
    if [[ -z "$spec" || -z "$scenario" || -z "$result_log" ]]; then
        echo "invalid LTP plan row in $plan_file" >&2
        exit 1
    fi
    run_log="$logs_dir/$spec.host-runltp.log"
    echo "host-runltp $spec: runltp -f $scenario"
    if ! "$runltp_bin" -f "$scenario" -o "$result_log" >"$run_log" 2>&1; then
        echo "WARN: host runltp failed for $spec; preserving logs and continuing" >&2
        run_failures=$((run_failures + 1))
    fi
done <"$plan_file"

report="$output_dir/host-ltp-log-adapter-report.json"
artifact_gate="$output_dir/host-ltp-log-adapter-artifact-gate.json"
report_gate="$output_dir/host-ltp-log-adapter-report-gate.json"

run_conformance ltp-report-from-logs "$logs_dir" "$boundary" "$profile" >"$report"
if ! run_conformance validate-artifacts "$report" "$logs_dir" >"$artifact_gate"; then
    echo "Host LTP raw log artifacts failed gate: $artifact_gate" >&2
    exit 1
fi

if ! run_conformance validate-report "$report" >"$report_gate"; then
    echo "Host LTP report did not pass vISA conformance gate, as expected for host-only logs: $report_gate" >&2
else
    echo "WARN: host-only LTP report passed conformance gate; verify the report contains vISA execution traces" >&2
fi

if [[ "$run_failures" -ne 0 ]]; then
    echo "$run_failures host runltp invocation(s) failed" >&2
    exit 1
fi

echo "Host LTP log adapter report written to $report"
echo "Host LTP artifact gate written to $artifact_gate"
