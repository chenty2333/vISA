#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/ci-gate.sh [fast|full|system]

Runs a validation tier inside the vISA development environment.
The full tier includes every fast-tier gate. With no argument, runs full.
The system tier independently runs and validates the real Stage 1 lifecycle;
it does not repeat the full tier.
EOF
}

system_artifact_root=""
system_bundle_path=""

on_error() {
    local status=$?
    trap - ERR
    if [[ -n "$system_artifact_root" ]]; then
        printf 'Stage 1 artifact root retained after failure: %s\n' "$system_artifact_root" >&2
        printf 'Stage 1 evidence bundle path: %s\n' "$system_bundle_path" >&2
    fi
    exit "$status"
}

trap on_error ERR

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

active_spine_packages=(
    contract_core
    handoff-component
    visa_profile
    semantic_core
    substrate_api
    substrate_host
    visa_runtime
    visa_wasmtime
    visa-conformance
    visa-system
)
active_spine_args=()
for package in "${active_spine_packages[@]}"; do
    active_spine_args+=(-p "$package")
done

gate_metadata() {
    run_gate "metadata: locked workspace resolution" \
        bash -lc 'cargo metadata --locked --no-deps --format-version 1 >/tmp/visa-cargo-metadata.json'
}

gate_fmt() {
    run_gate "fmt: workspace Rust formatting" cargo fmt --all --check
}

gate_dependency_direction() {
    run_gate "dependencies: strict active-spine direction" \
        python3 scripts/check-dependency-direction.py
}

gate_stage1_deletions() {
    run_gate "deletions: Stage 1 legacy and oracle boundary" \
        python3 scripts/check-stage1-deletions.py
}

gate_active_clippy() {
    run_gate "clippy: active spine and test targets" \
        cargo clippy --locked "${active_spine_args[@]}" --all-targets -- -D warnings
}

gate_active_tests() {
    run_gate "tests: active spine" \
        cargo test --locked "${active_spine_args[@]}"
}

gate_shell_syntax() {
    run_gate "shell: parse repository scripts" bash -n scripts/*.sh
}

gate_workspace_tests() {
    run_gate "tests: default-feature workspace" cargo test --locked --workspace
}

gate_feature_tests() {
    run_gate "features: substrate oracle conformance" \
        cargo test --locked -p substrate-oracle --features conformance
    run_gate "features: Linux host TAP adapter" \
        cargo test --locked -p substrate_virtio --features host-tap
    run_gate "features: seccomp service contract" \
        cargo test --locked -p service_core --features seccomp-filter
    run_gate "features: target executor host TAP path" \
        cargo test --locked -p target_executor --features host-tap
}

gate_active_no_std() {
    run_gate "no-std: active portable crates on x86_64-unknown-none" \
        cargo check --locked \
            -p contract_core \
            -p visa_profile \
            -p semantic_core \
            -p substrate_api \
            -p visa_runtime \
            --target x86_64-unknown-none
}

gate_check_wasm() {
    run_gate "wasm: selected service packages" cargo check-wasm --locked
}

gate_kernel() {
    run_gate "kernel: x86_64-unknown-none" \
        cargo check --locked -p kernel --target x86_64-unknown-none
}

gate_benches() {
    run_gate "benchmarks: compile Criterion targets" \
        cargo check --locked -p visa-bench --benches
}

gate_reports() {
    run_gate "reports: schema and artifact fixtures" scripts/run-report-gates.sh
}

gate_fast() {
    gate_metadata
    gate_fmt
    gate_dependency_direction
    gate_stage1_deletions
    gate_active_clippy
    gate_active_tests
}

gate_full() {
    gate_fast
    gate_shell_syntax
    gate_workspace_tests
    gate_feature_tests
    gate_active_no_std
    gate_check_wasm
    gate_kernel
    gate_benches
    gate_reports
}

gate_system() {
    local system_parent="$PWD/target/visa-system"
    mkdir -p "$system_parent"
    system_artifact_root="$(umask 077; mktemp -d "$system_parent/stage1-XXXXXX")"
    system_bundle_path="$system_artifact_root/stage1-evidence.json"

    run_gate "system: real Stage 1 lifecycle" \
        cargo run --locked -p visa-system --bin visa-system -- \
            stage1 "$system_artifact_root"
    run_gate "system: independent Stage 1 evidence validation" \
        cargo run --locked -p visa-conformance --bin visa-conformance -- \
            stage1 "$system_bundle_path" "$system_artifact_root"

    printf 'Stage 1 artifact root: %s\n' "$system_artifact_root"
    printf 'Stage 1 evidence bundle: %s\n' "$system_bundle_path"
}

if [[ "$#" -gt 1 ]]; then
    usage
    exit 64
fi

tier="${1:-full}"
case "$tier" in
    fast) gate_fast ;;
    full) gate_full ;;
    system) gate_system ;;
    -h|--help|help)
        usage
        ;;
    *)
        printf 'unknown validation tier: %s\n' "$tier" >&2
        usage
        exit 64
        ;;
esac
