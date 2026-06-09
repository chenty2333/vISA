#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/ci-gate.sh [all|metadata|fmt|check-wasm|visa-conformance|kernel]...

Runs the vISA CI gates inside the Docker development environment.
With no arguments, runs all gates in CI order.
EOF
}

in_github_actions() {
    [[ -n "${GITHUB_ACTIONS:-}" ]]
}

begin_group() {
    local label="$1"
    if in_github_actions; then
        printf '::group::%s\n' "$label"
    else
        printf '\n==> %s\n' "$label"
    fi
}

end_group() {
    if in_github_actions; then
        printf '::endgroup::\n'
    fi
}

run_gate() {
    local label="$1"
    shift

    begin_group "$label"
    printf '+'
    printf ' %q' "$@"
    printf '\n'

    local status=0
    "$@" || status=$?

    if [[ "$status" -eq 0 ]]; then
        end_group
        printf 'ok: %s\n' "$label"
        return 0
    fi

    end_group
    if in_github_actions; then
        printf '::error title=vISA CI gate failed::%s exited with status %s\n' "$label" "$status"
    fi
    printf 'ERROR: vISA CI gate failed: %s (exit %s)\n' "$label" "$status" >&2
    return "$status"
}

gate_metadata() {
    run_gate "metadata: cargo metadata" \
        bash -lc 'cargo metadata --no-deps --format-version 1 >/tmp/visa-cargo-metadata.json'
}

gate_fmt() {
    run_gate "fmt: cargo fmt" cargo fmt --all --check
}

gate_check_wasm() {
    run_gate "check-wasm: cargo check-wasm" cargo check-wasm
}

gate_visa_conformance() {
    run_gate "visa-conformance: cargo test" cargo test -p visa-conformance
    run_gate "visa-conformance: validate sample reports and evidence matrix" \
        cargo run -p visa-conformance -- validate-sample
}

gate_kernel() {
    run_gate "kernel: cargo check x86_64-unknown-none" \
        cargo check -p kernel --target x86_64-unknown-none
}

run_named_gate() {
    case "$1" in
        metadata) gate_metadata ;;
        fmt) gate_fmt ;;
        check-wasm) gate_check_wasm ;;
        visa-conformance) gate_visa_conformance ;;
        kernel) gate_kernel ;;
        all)
            gate_metadata
            gate_fmt
            gate_check_wasm
            gate_visa_conformance
            gate_kernel
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            printf 'unknown CI gate: %s\n' "$1" >&2
            usage
            return 64
            ;;
    esac
}

if [[ "$#" -eq 0 ]]; then
    set -- all
fi

for gate in "$@"; do
    run_named_gate "$gate"
done
