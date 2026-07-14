#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/ci-gate.sh \
    [fast|full|system|system-jco-node|system-stage2|system-stage2-strict|
     system-stage3a|system-stage3b|system-stage3]

Runs a validation tier inside the vISA development environment.
The full tier includes every fast-tier gate. With no argument, runs full.
The system tier independently runs and validates the real Stage 1 lifecycle;
system-jco-node does the same for the JcoNode reference cell. system-stage2
runs and independently validates the complete four-cell Stage 2 matrix.
system-stage2-strict runs the locked Wacogo qualification, same-path cell, and
independently validated strict Wasmtime/Wacogo matrix through the unified local
gate. Set VISA_STRICT_STAGE2_ARTIFACT_ROOT to select its retained output root.
Locked inputs use the VISA_WACOGO_* variables documented by that local gate.
system-stage3a and system-stage3b run and independently validate the bounded
regular-file and logical-request continuity profiles. system-stage3 runs both
Stage 3 profiles in sequence. Stage 3 currently covers Wasmtime-to-Wasmtime
handoff only and does not inherit Strict Stage 2 independent-runtime coverage.
System tiers do not repeat the full tier.
EOF
}

system_artifact_root=""
system_bundle_path=""
system_artifact_kind="system"

on_error() {
    local status=$?
    trap - ERR
    if [[ -n "$system_artifact_root" ]]; then
        printf '%s artifact root retained after failure: %s\n' \
            "$system_artifact_kind" "$system_artifact_root" >&2
        if [[ -f "$system_bundle_path" && ! -L "$system_bundle_path" ]]; then
            printf '%s evidence bundle retained for diagnostics: %s\n' \
                "$system_artifact_kind" "$system_bundle_path" >&2
        else
            printf '%s evidence bundle was not published (expected path: %s)\n' \
                "$system_artifact_kind" "$system_bundle_path" >&2
        fi
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
    visa_component_adapter
    visa_jco_node
    visa_wacogo
    visa_wasmtime
    stage3-file-component
    stage3-request-component
    visa-conformance
    visa-stage3-system
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

gate_file_size() {
    run_gate "maintenance: first-party Rust file sizes" scripts/check-file-size.sh
}

gate_jco_node_toolchain() {
    run_gate "toolchain: locked JcoNode translation and Node/V8 execution" \
        python3 scripts/check-jco-node-toolchain.py
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
    gate_file_size
    gate_jco_node_toolchain
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
    system_artifact_kind="Stage 1 Wasmtime"
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

gate_system_jco_node() {
    local system_parent="$PWD/target/visa-system"
    mkdir -p "$system_parent"
    system_artifact_kind="Stage 2b JcoNode"
    system_artifact_root="$(umask 077; mktemp -d "$system_parent/jco-node-XXXXXX")"
    system_bundle_path="$system_artifact_root/stage1-evidence.json"

    gate_jco_node_toolchain
    run_gate "system-jco-node: real 31-case JcoNode lifecycle" \
        cargo run --locked -p visa-system --bin visa-system -- \
            cell jco-node jco-node "$system_artifact_root"
    run_gate "system-jco-node: independent Stage 1 evidence validation" \
        cargo run --locked -p visa-conformance --bin visa-conformance -- \
            stage1 "$system_bundle_path" "$system_artifact_root"

    printf 'JcoNode artifact root: %s\n' "$system_artifact_root"
    printf 'JcoNode evidence bundle: %s\n' "$system_bundle_path"
}

gate_system_stage2() {
    local system_parent="$PWD/target/visa-system"
    mkdir -p "$system_parent"
    system_artifact_kind="Stage 2 matrix"
    system_artifact_root="$(umask 077; mktemp -d "$system_parent/stage2-XXXXXX")"
    system_bundle_path="$system_artifact_root/stage2-evidence.json"

    gate_jco_node_toolchain
    run_gate "system-stage2: real four-cell 124-case matrix" \
        cargo run --locked -p visa-system --bin visa-system -- \
            stage2 "$system_artifact_root"
    run_gate "system-stage2: independent Stage 2 evidence validation" \
        cargo run --locked -p visa-conformance --bin visa-conformance -- \
            stage2 "$system_bundle_path" "$system_artifact_root"

    printf 'Stage 2 artifact root: %s\n' "$system_artifact_root"
    printf 'Stage 2 evidence bundle: %s\n' "$system_bundle_path"
}

gate_system_stage2_strict() {
    local system_parent="$PWD/target/visa-system"
    system_artifact_kind="Strict Stage 2"
    if [[ -n "${VISA_STRICT_STAGE2_ARTIFACT_ROOT:-}" ]]; then
        system_artifact_root="$VISA_STRICT_STAGE2_ARTIFACT_ROOT"
    else
        mkdir -p "$system_parent"
        system_artifact_root="$(umask 077; mktemp -d "$system_parent/stage2-strict-XXXXXX")"
    fi
    system_bundle_path="$system_artifact_root/strict/stage2-evidence.json"

    run_gate "system-stage2-strict: locked qualification, same-path, and strict matrix" \
        scripts/run-strict-stage2-local-gate.sh \
            --artifact-root "$system_artifact_root"

    printf 'Strict Stage 2 artifact root: %s\n' "$system_artifact_root"
    printf 'Strict Stage 2 evidence bundle: %s\n' "$system_bundle_path"
}

gate_system_stage3a() {
    local system_parent="$PWD/target/visa-system"
    mkdir -p "$system_parent"
    system_artifact_kind="Stage 3A regular-file continuity"
    system_artifact_root="$(umask 077; mktemp -d "$system_parent/stage3a-XXXXXX")"
    system_bundle_path="$system_artifact_root/stage3a-evidence.json"

    run_gate "system-stage3a: bounded regular-file continuity" \
        cargo run --locked -p visa-stage3-system --bin visa-stage3-system -- \
            stage3a "$system_artifact_root"
    run_gate "system-stage3a: independent evidence validation" \
        cargo run --locked -p visa-conformance --bin visa-conformance -- \
            stage3a "$system_bundle_path" "$system_artifact_root"

    printf 'Stage 3A artifact root: %s\n' "$system_artifact_root"
    printf 'Stage 3A evidence bundle: %s\n' "$system_bundle_path"
}

gate_system_stage3b() {
    local system_parent="$PWD/target/visa-system"
    mkdir -p "$system_parent"
    system_artifact_kind="Stage 3B logical-request continuity"
    system_artifact_root="$(umask 077; mktemp -d "$system_parent/stage3b-XXXXXX")"
    system_bundle_path="$system_artifact_root/stage3b-evidence.json"

    run_gate "system-stage3b: reconnectable logical-request continuity" \
        cargo run --locked -p visa-stage3-system --bin visa-stage3-system -- \
            stage3b "$system_artifact_root"
    run_gate "system-stage3b: independent evidence validation" \
        cargo run --locked -p visa-conformance --bin visa-conformance -- \
            stage3b "$system_bundle_path" "$system_artifact_root"

    printf 'Stage 3B artifact root: %s\n' "$system_artifact_root"
    printf 'Stage 3B evidence bundle: %s\n' "$system_bundle_path"
}

gate_system_stage3() {
    gate_system_stage3a
    gate_system_stage3b
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
    system-jco-node) gate_system_jco_node ;;
    system-stage2) gate_system_stage2 ;;
    system-stage2-strict) gate_system_stage2_strict ;;
    system-stage3a) gate_system_stage3a ;;
    system-stage3b) gate_system_stage3b ;;
    system-stage3) gate_system_stage3 ;;
    -h|--help|help)
        usage
        ;;
    *)
        printf 'unknown validation tier: %s\n' "$tier" >&2
        usage
        exit 64
        ;;
esac
