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
run_conformance sample-performance-report-json | run_conformance validate-report - >/dev/null

performance_report="$tmp_root/performance-report.json"
run_conformance write-sample-performance-report "$performance_report"
run_conformance validate-report "$performance_report" >/dev/null

pass_logs="$tmp_root/ltp-pass"
mkdir -p "$pass_logs"
run_conformance ltp-plan-lines "$pass_logs" >"$tmp_root/ltp-plan.tsv"
while IFS=$'\t' read -r spec _scenario result_log; do
    printf '%s_case01 1 TPASS : passed\n' "$spec" >"$result_log"
done <"$tmp_root/ltp-plan.tsv"

pass_report="$tmp_root/ltp-pass-report.json"
run_conformance ltp-report-from-logs "$pass_logs" portable-artifact-execution guest-frontend \
    >"$pass_report"
run_conformance validate-report "$pass_report" >/dev/null
run_conformance validate-artifacts "$pass_report" >/dev/null

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
scripts/run-ltp-conformance.sh "$wrapper_output" portable-artifact-execution guest-frontend \
    "$fake_runltp" >/dev/null
run_conformance validate-report "$wrapper_output/vmos-ltp-report.json" \
    >"$tmp_root/wrapper-gate.json"
run_conformance validate-artifacts "$wrapper_output/vmos-ltp-report.json" \
    >"$tmp_root/wrapper-artifact-gate.json"

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

bench_output="$tmp_root/vmos-bench-run"
VMOS_SKIP_BENCH_RUN=1 scripts/run-vmos-bench-conformance.sh \
    "$bench_output" portable-artifact-execution "" "$criterion_root" >/dev/null
run_conformance validate-report "$bench_output/vmos-performance-report.json" \
    >"$tmp_root/vmos-bench-gate.json"
run_conformance validate-artifacts "$bench_output/vmos-performance-report.json" \
    >"$tmp_root/vmos-bench-artifact-gate.json"

echo "Conformance report gate passed."
