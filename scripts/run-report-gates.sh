#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-report-gates.sh [output-dir]

Runs the repository report-gate surface that does not require external LTP,
QEMU, or Criterion execution by default. External workload runners remain
separate:

  scripts/run-host-ltp-log-adapter.sh
  scripts/run-visa-ltp-conformance.sh
  scripts/run-visa-bench-conformance.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 2
fi

output_dir="${1:-target/visa-report-gates}"
mkdir -p "$output_dir"

cargo test --locked -p conformance-oracle >"$output_dir/visa-conformance-tests.log" 2>&1
scripts/check-conformance-report.sh >"$output_dir/check-conformance-report.log" 2>&1

echo "Report gates passed. Logs written to $output_dir"
