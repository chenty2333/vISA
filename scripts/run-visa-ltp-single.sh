#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-visa-ltp-single.sh <spec-id> <case-id> <test-elf> <raw-log> <trace-log> <serial-log>

Builds/runs the vISA QEMU runner with <test-elf> embedded as the Linux
personality user ELF, captures serial output, extracts or synthesizes a raw LTP
case log, and emits a vISA Linux personality execution trace.

The test ELF must be loadable by the current vISA Linux ELF frontend. Ordinary
dynamic Linux binaries may fail until the frontend supports their loader, stack,
and auxv requirements; that failure is recorded as LTP failure evidence rather
than hidden.

Environment:

  VISA_LTP_RUN_TIMEOUT   Optional timeout passed to timeout(1) for the vISA run.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -ne 6 ]]; then
    usage
    exit 2
fi

spec_id="$1"
case_id="$2"
test_elf="$3"
raw_log="$4"
trace_log="$5"
serial_log="$6"

if [[ ! -f "$test_elf" ]]; then
    echo "vISA LTP test ELF not found: $test_elf" >&2
    exit 66
fi

mkdir -p "$(dirname "$raw_log")" "$(dirname "$trace_log")" "$(dirname "$serial_log")"
resource_dir="$(dirname "$test_elf")/.resources/$case_id"
runner_env=(VISA_LINUX_USER_ELF="$test_elf")
if [[ -d "$resource_dir" ]]; then
    runner_env+=(VISA_LINUX_USER_RESOURCE_DIR="$resource_dir")
fi
if [[ -n "${VISA_LTP_RUN_TIMEOUT:-}" && -z "${VISA_QEMU_TIMEOUT:-}" && -z "${VISA_QEMU_TIMEOUT_SECS:-}" ]]; then
    runner_env+=(VISA_QEMU_TIMEOUT="$VISA_LTP_RUN_TIMEOUT")
fi

set +e
if [[ -n "${VISA_LTP_RUN_TIMEOUT:-}" ]]; then
    timeout --kill-after=5s "$VISA_LTP_RUN_TIMEOUT" \
        env "${runner_env[@]}" cargo run --quiet -p runner -- --verbose \
        >"$serial_log" 2>&1
else
    env "${runner_env[@]}" cargo run --quiet -p runner -- --verbose >"$serial_log" 2>&1
fi
run_status=$?
set -e

raw_uri="$(basename "$raw_log")"
serial_uri="$(basename "$serial_log")"
cargo run --quiet -p conformance-oracle -- \
    ltp-raw-log-from-serial "$case_id" "$serial_log" "$run_status" >"$raw_log"
cargo run --quiet -p conformance-oracle -- \
    ltp-visa-trace-from-serial "$spec_id" "$case_id" "$test_elf" "$raw_uri" "$serial_uri" \
    "$serial_log" "$run_status" >"$trace_log"

exit "$run_status"
