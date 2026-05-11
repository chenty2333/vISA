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

The script exits non-zero when runltp is missing, any runltp invocation fails,
or the generated conformance report does not pass the report gate.
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

declare -A scenarios=(
    ["linux-ltp.fs.basic"]="fs"
    ["linux-ltp.mm.mapping"]="mm"
    ["linux-ltp.ipc.futex"]="ipc"
    ["linux-ltp.sched.timers"]="sched,timers"
    ["linux-ltp.syscalls.core"]="syscalls"
    ["linux-ltp.net.socket"]="net.ipv4,net.tcp_cmds"
)

ordered_specs=(
    linux-ltp.fs.basic
    linux-ltp.mm.mapping
    linux-ltp.ipc.futex
    linux-ltp.sched.timers
    linux-ltp.syscalls.core
    linux-ltp.net.socket
)

run_failures=0
for spec in "${ordered_specs[@]}"; do
    scenario="${scenarios[$spec]}"
    result_log="$logs_dir/$spec.log"
    run_log="$logs_dir/$spec.run.log"
    echo "running $spec with runltp -f $scenario"
    if ! "$runltp_bin" -f "$scenario" -o "$result_log" >"$run_log" 2>&1; then
        echo "WARN: runltp failed for $spec; preserving logs and continuing" >&2
        run_failures=$((run_failures + 1))
    fi
done

report="$output_dir/vmos-ltp-report.json"
gate="$output_dir/vmos-ltp-gate.json"

run_conformance ltp-report-from-logs "$logs_dir" "$boundary" "$profile" >"$report"
if ! run_conformance validate-report "$report" >"$gate"; then
    echo "LTP conformance report failed gate: $gate" >&2
    exit 1
fi

if [[ "$run_failures" -ne 0 ]]; then
    echo "$run_failures runltp invocation(s) failed even though report gate passed" >&2
    exit 1
fi

echo "LTP conformance report passed: $report"
