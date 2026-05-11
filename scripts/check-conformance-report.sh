#!/usr/bin/env bash
set -euo pipefail

# Conformance report gate for VMOS/vISA test claims.
# This script exercises the report contract; real workload execution remains
# owned by the corresponding runner.

run_conformance() {
    cargo run --quiet -p vmos-conformance -- "$@"
}

tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT

run_conformance validate-sample >/dev/null
run_conformance sample-ltp-report-json | run_conformance validate-report - >/dev/null

pass_logs="$tmp_root/ltp-pass"
mkdir -p "$pass_logs"
for spec in \
    linux-ltp.fs.basic \
    linux-ltp.mm.mapping \
    linux-ltp.ipc.futex \
    linux-ltp.sched.timers \
    linux-ltp.syscalls.core \
    linux-ltp.net.socket
do
    printf '%s_case01 1 TPASS : passed\n' "$spec" >"$pass_logs/$spec.log"
done

pass_report="$tmp_root/ltp-pass-report.json"
run_conformance ltp-report-from-logs "$pass_logs" portable-artifact-execution guest-frontend \
    >"$pass_report"
run_conformance validate-report "$pass_report" >/dev/null

partial_logs="$tmp_root/ltp-partial"
mkdir -p "$partial_logs"
printf 'open01 1 TPASS : open succeeded\n' >"$partial_logs/linux-ltp.fs.basic.log"

partial_report="$tmp_root/ltp-partial-report.json"
run_conformance ltp-report-from-logs "$partial_logs" portable-artifact-execution guest-frontend \
    >"$partial_report"

if run_conformance validate-report "$partial_report" >"$tmp_root/partial-gate.json"; then
    echo "FAIL: incomplete LTP report unexpectedly passed conformance gate"
    exit 1
fi

echo "Conformance report gate passed."
