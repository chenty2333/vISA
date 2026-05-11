#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-report-gates.sh [output-dir]

Runs the repository report-gate surface that does not require external LTP,
QEMU, or Criterion execution by default. External workload runners remain
separate:

  scripts/run-host-ltp-log-adapter.sh
  scripts/run-vmos-ltp-conformance.sh
  scripts/run-vmos-bench-conformance.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 2
fi

output_dir="${1:-target/vmos-report-gates}"
mkdir -p "$output_dir"

cargo test -p vmos-conformance >"$output_dir/vmos-conformance-tests.log" 2>&1
scripts/check-conformance-report.sh >"$output_dir/check-conformance-report.log" 2>&1

echo "Report gates passed. Logs written to $output_dir"
