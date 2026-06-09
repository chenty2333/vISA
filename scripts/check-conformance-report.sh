#!/usr/bin/env bash
set -euo pipefail

# Conformance report gate for vISA test claims.
# This script exercises the report contract; real workload execution remains
# owned by the corresponding runner.

run_conformance() {
    cargo run --quiet -p visa-conformance -- "$@"
}

tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT

run_conformance validate-sample >/dev/null

performance_report="$tmp_root/performance-report.json"
run_conformance write-sample-performance-report "$performance_report"
run_conformance validate-report "$performance_report" >/dev/null

pass_logs="$tmp_root/ltp-pass"
mkdir -p "$pass_logs"
run_conformance ltp-plan-lines "$pass_logs" >"$tmp_root/ltp-plan.tsv"
while IFS=$'\t' read -r spec _scenario result_log; do
    printf '%s_case01 1 TPASS : passed\n' "$spec" >"$result_log"
    cat >"$pass_logs/$spec.visa-trace.jsonl" <<EOF
{"schema_version":"visa-ltp-execution-trace-v0.1","spec_id":"$spec","case_id":"${spec}_case01","test_binary":"target/ltp-bins/${spec}_case01","runner":"visa-linux-personality","entered_visa_execution":true,"linux_personality_dispatch":true,"syscalls_observed":1,"service_syscalls_observed":1,"exit_status":0,"runner_status":0,"raw_log_uri":"$spec.log","serial_log_uri":"$spec.serial.log"}
EOF
done <"$tmp_root/ltp-plan.tsv"

pass_report="$tmp_root/ltp-pass-report.json"
run_conformance ltp-report-from-logs "$pass_logs" portable-artifact-execution guest-frontend \
    >"$pass_report"
run_conformance validate-report "$pass_report" >/dev/null
run_conformance validate-artifacts "$pass_report" "$pass_logs" >/dev/null
run_conformance validate-report-with-artifacts "$pass_report" "$pass_logs" >/dev/null

real_target_trace="$pass_logs/substrate-extraction.jsonl"
cat >"$real_target_trace" <<'EOF'
{"event_id":1,"event_epoch":1,"authority":"ConsoleAuthority","operation":"console_write","target_arch":"riscv64","target_board":"qemu-virt"}
EOF
real_target_trace_sha=$(sha256sum "$real_target_trace" | awk '{ print $1 }')
real_target_report="$tmp_root/ltp-real-target-report.json"
run_conformance ltp-report-from-logs "$pass_logs" real-target-substrate guest-frontend \
    >"$real_target_report"
real_target_attached_report="$tmp_root/ltp-real-target-attached-report.json"
run_conformance attach-evidence-artifact \
    "$real_target_report" '*' substrate-extraction-trace "substrate-extraction.jsonl" \
    "$real_target_trace_sha" \
    "real target substrate extraction trace" \
    >"$real_target_attached_report"
run_conformance validate-report "$real_target_attached_report" >/dev/null
run_conformance validate-artifacts "$real_target_attached_report" "$pass_logs" >/dev/null
run_conformance validate-report-with-artifacts "$real_target_attached_report" "$pass_logs" >/dev/null

partial_logs="$tmp_root/ltp-partial"
mkdir -p "$partial_logs"
first_partial_log=$(
    run_conformance ltp-plan-lines "$partial_logs" \
        | awk -F '\t' 'NR == 1 { print $3 }'
)
printf 'open01 1 TPASS : open succeeded\n' >"$first_partial_log"

partial_report="$tmp_root/ltp-partial-report.json"
run_conformance ltp-report-from-logs "$partial_logs" portable-artifact-execution guest-frontend \
    >"$partial_report"

if run_conformance validate-report "$partial_report" >"$tmp_root/partial-gate.json"; then
    echo "FAIL: incomplete LTP report unexpectedly passed conformance gate"
    exit 1
fi
if run_conformance validate-report-with-artifacts "$partial_report" \
    "$partial_logs" \
    >"$tmp_root/partial-combined-gate.json"; then
    echo "FAIL: incomplete LTP report unexpectedly passed combined conformance gate"
    exit 1
fi

fake_runltp="$tmp_root/runltp"
cat >"$fake_runltp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

scenario=""
output=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -f)
            scenario="$2"
            shift 2
            ;;
        -o)
            output="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -z "$scenario" || -z "$output" ]]; then
    exit 2
fi

printf '%s_case01 1 TPASS : passed\n' "$scenario" >"$output"
EOF
chmod +x "$fake_runltp"

wrapper_output="$tmp_root/wrapper"
scripts/run-host-ltp-log-adapter.sh "$wrapper_output" portable-artifact-execution guest-frontend \
    "$fake_runltp" >/dev/null
test -s "$wrapper_output/host-ltp-log-adapter-report.json"
test -s "$wrapper_output/host-ltp-log-adapter-artifact-gate.json"
test -s "$wrapper_output/host-ltp-log-adapter-report-gate.json"
if run_conformance validate-report "$wrapper_output/host-ltp-log-adapter-report.json" \
    >"$tmp_root/host-wrapper-gate.json"; then
    echo "FAIL: host-only LTP adapter unexpectedly passed vISA conformance gate"
    exit 1
fi
run_conformance validate-artifacts "$wrapper_output/host-ltp-log-adapter-report.json" "$wrapper_output/logs" \
    >"$tmp_root/wrapper-artifact-gate.json"
if run_conformance validate-report-with-artifacts "$wrapper_output/host-ltp-log-adapter-report.json" "$wrapper_output/logs" \
    >"$tmp_root/host-wrapper-combined-gate.json"; then
    echo "FAIL: host-only LTP adapter unexpectedly passed combined vISA conformance gate"
    exit 1
fi

fake_ltp_root="$tmp_root/fake-ltp-bins"
mkdir -p "$fake_ltp_root"
touch "$fake_ltp_root/open01" "$fake_ltp_root/mmap01" "$fake_ltp_root/getpid01"
fake_visa_single="$tmp_root/run-visa-ltp-single"
cat >"$fake_visa_single" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
spec="$1"
case_id="$2"
_binary="$3"
raw_log="$4"
trace_log="$5"
serial_log="$6"
mkdir -p "$(dirname "$raw_log")" "$(dirname "$trace_log")" "$(dirname "$serial_log")"
cat >"$serial_log" <<SERIAL
== ring3 real ELF demo ==
${case_id} 1 TPASS : passed
HostcallEntered label=ring3_openat class=immediate-privileged-op subject=linux_syscall object=vfs_service op=lookup
visa: demo completed
SERIAL
printf '%s 1 TPASS : passed\n' "$case_id" >"$raw_log"
cat >"$trace_log" <<TRACE
{"schema_version":"visa-ltp-execution-trace-v0.1","spec_id":"$spec","case_id":"$case_id","test_binary":"$_binary","runner":"visa-linux-personality","entered_visa_execution":true,"linux_personality_dispatch":true,"syscalls_observed":1,"service_syscalls_observed":1,"exit_status":0,"runner_status":0,"raw_log_uri":"$(basename "$raw_log")","serial_log_uri":"$(basename "$serial_log")"}
TRACE
EOF
chmod +x "$fake_visa_single"

visa_wrapper_output="$tmp_root/visa-wrapper"
scripts/run-visa-ltp-conformance.sh "$visa_wrapper_output" "$fake_ltp_root" \
    portable-artifact-execution guest-frontend "$fake_visa_single" >/dev/null
test -s "$visa_wrapper_output/visa-ltp-gate.json"
test -s "$visa_wrapper_output/visa-ltp-artifact-gate.json"
test -s "$visa_wrapper_output/visa-ltp-combined-gate.json"
run_conformance validate-report "$visa_wrapper_output/visa-ltp-report.json" \
    >"$tmp_root/visa-wrapper-gate.json"
run_conformance validate-artifacts "$visa_wrapper_output/visa-ltp-report.json" "$visa_wrapper_output/logs" \
    >"$tmp_root/visa-wrapper-artifact-gate.json"
run_conformance validate-report-with-artifacts "$visa_wrapper_output/visa-ltp-report.json" "$visa_wrapper_output/logs" \
    >"$tmp_root/visa-wrapper-combined-gate.json"

visa_manifest="$tmp_root/visa-ltp-manifest.tsv"
cat >"$visa_manifest" <<'EOF'
# spec_id	case_id	relative_binary	source
linux-ltp.syscalls.core	getpid01	getpid01	fake
linux-ltp.fs.basic	open01	open01	fake
EOF

visa_manifest_output="$tmp_root/visa-manifest-wrapper"
scripts/run-visa-ltp-manifest.sh "$visa_manifest_output" "$fake_ltp_root" "$visa_manifest" \
    portable-artifact-execution guest-frontend "$fake_visa_single" >/dev/null
test -s "$visa_manifest_output/visa-ltp-gate.json"
test -s "$visa_manifest_output/visa-ltp-artifact-gate.json"
test -s "$visa_manifest_output/visa-ltp-combined-gate.json"
run_conformance validate-report "$visa_manifest_output/visa-ltp-report.json" \
    >"$tmp_root/visa-manifest-wrapper-gate.json"
run_conformance validate-artifacts "$visa_manifest_output/visa-ltp-report.json" "$visa_manifest_output/logs" \
    >"$tmp_root/visa-manifest-wrapper-artifact-gate.json"
run_conformance validate-report-with-artifacts "$visa_manifest_output/visa-ltp-report.json" "$visa_manifest_output/logs" \
    >"$tmp_root/visa-manifest-wrapper-combined-gate.json"

criterion_root="$tmp_root/criterion"
run_conformance performance-plan-lines "$criterion_root" >"$tmp_root/performance-plan.tsv"
while IFS=$'\t' read -r _spec_id _bench_id _metric estimate_path; do
    mkdir -p "$(dirname "$estimate_path")"
    cat >"$estimate_path" <<'EOF'
{
  "mean": {
    "confidence_interval": {
      "confidence_level": 0.95,
      "lower_bound": 1000.0,
      "upper_bound": 1000.0
    },
    "point_estimate": 1000.0,
    "standard_error": 0.0
  }
}
EOF
done <"$tmp_root/performance-plan.tsv"

bench_output="$tmp_root/visa-bench-run"
VISA_SKIP_BENCH_RUN=1 scripts/run-visa-bench-conformance.sh \
    "$bench_output" "" "" "$criterion_root" >/dev/null
test -s "$bench_output/visa-performance-gate.json"
test -s "$bench_output/visa-performance-artifact-gate.json"
test -s "$bench_output/visa-performance-combined-gate.json"
run_conformance validate-report "$bench_output/visa-performance-report.json" \
    >"$tmp_root/visa-bench-gate.json"
run_conformance validate-artifacts "$bench_output/visa-performance-report.json" "$criterion_root" \
    >"$tmp_root/visa-bench-artifact-gate.json"
run_conformance validate-report-with-artifacts "$bench_output/visa-performance-report.json" "$criterion_root" \
    >"$tmp_root/visa-bench-combined-gate.json"

echo "Conformance report gate passed."
