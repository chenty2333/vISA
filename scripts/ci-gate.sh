#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/ci-gate.sh \
    [fast|full|system|system-jco-node|system-stage2|system-stage2-strict|
     system-stage3a|system-stage3b|system-stage3|system-stage4-target|
     system-stage4-isa|system-stage4|system-joint-handoff]

Runs a validation tier inside the vISA development environment.
The full tier includes every fast-tier gate. With no argument, runs full.
Set VISA_EVIDENCE_PARENT to place system evidence outside Cargo's target
directory; the default remains target/visa-system for direct Host runs.
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
system-stage4 builds release x86-64 and AArch64 Wasmtime workers, runs the
complete seven-cell native/QEMU-user target and cross-ISA matrix, and verifies
the resulting evidence independently before and after a real directory
relocation. The evidence includes a raw uname-bound x86-64 Linux host receipt.
system-stage4-target and
system-stage4-isa are edit-loop aliases that currently fail closed by running
that same complete aggregate matrix; they do not publish reduced claims.
system-joint-handoff runs the fixed reference peers, production reducer replay,
independent verifier, and relocation check. It is reference-only evidence and
does not qualify the pinned Nexus revision named by its source lock.
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

system_evidence_parent() {
    local parent="${VISA_EVIDENCE_PARENT:-$PWD/target/visa-system}"

    if [[ "$parent" != /* ]]; then
        parent="$PWD/$parent"
    fi
    mkdir -p -- "$parent"
    if [[ ! -d "$parent" || -L "$parent" ]]; then
        printf 'system evidence parent is not a non-symlink directory: %s\n' \
            "$parent" >&2
        return 1
    fi
    (CDPATH='' cd -- "$parent" && pwd -P)
}

cargo_target_directory() {
    cargo metadata --locked --no-deps --format-version 1 \
        | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
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

active_spine_packages=(
    contract_core
    joint_handoff_core
    visa_local_rpc
    handoff-component
    visa_profile
    semantic_core
    substrate_api
    substrate_host
    visa_runtime
    visa_joint_handoff
    visa_local_transport
    visa_ownership_service
    visa-ownershipd
    visa_component_adapter
    visa_jco_node
    visa_wacogo
    visa_wasmtime
    stage3-file-component
    stage3-request-component
    visa-conformance
    visa-stage3-system
    visa-joint-handoff-system
    visa-system
)
active_spine_args=()
for package in "${active_spine_packages[@]}"; do
    active_spine_args+=(-p "$package")
done

gate_metadata() {
    run_gate "metadata: locked workspace resolution" \
        bash -c 'cargo metadata --locked --no-deps --format-version 1 >/dev/null'
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

gate_ci_contract() {
    run_gate "CI: build, cache, evidence, and closure contract" \
        python3 scripts/check-ci-contract.py
}

gate_release_contract() {
    run_gate "release: vISA 0.1 frozen target contract" \
        python3 scripts/check-release-contract.py
    run_gate "release: contract checker self-tests" \
        python3 scripts/test-check-release-contract.py
}

gate_local_rpc_artifacts() {
    run_gate "local RPC: dependency, family isolation, and serde policy" \
        python3 scripts/check-local-rpc-wire.py
    run_gate "local RPC: static policy checker self-tests" \
        python3 scripts/test-check-local-rpc-wire.py
    run_gate "local RPC: owned schemas, golden corpora, and executable negatives" \
        cargo run --quiet --locked -p visa-conformance \
            --bin visa-local-rpc-artifacts -- --check
}

gate_jco_node_toolchain() {
    run_gate "toolchain: locked JcoNode translation and Node/V8 execution" \
        python3 scripts/check-jco-node-toolchain.py
}

gate_joint_handoff_source_lock() {
    run_gate "source lock: reference-only joint handoff inputs" \
        python3 scripts/check-joint-handoff-source-lock.py
}

gate_nexus_handoff_verifier_self_tests() {
    run_gate "joint handoff source-lock checker self-tests" \
        python3 scripts/test-check-joint-handoff-source-lock.py
    run_gate "Nexus handoff qualification verifier self-tests" \
        python3 scripts/test-check-nexus-handoff-qualification.py
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
            -p joint_handoff_core \
            -p visa_profile \
            -p semantic_core \
            -p substrate_api \
            -p visa_runtime \
            -p visa_joint_handoff \
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
    gate_ci_contract
    gate_release_contract
    gate_local_rpc_artifacts
    gate_jco_node_toolchain
    gate_joint_handoff_source_lock
    gate_nexus_handoff_verifier_self_tests
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
    local system_parent
    system_parent="$(system_evidence_parent)"
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
    local system_parent
    system_parent="$(system_evidence_parent)"
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
    local system_parent
    system_parent="$(system_evidence_parent)"
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
    system_artifact_kind="Strict Stage 2"
    if [[ -n "${VISA_STRICT_STAGE2_ARTIFACT_ROOT:-}" ]]; then
        system_artifact_root="$VISA_STRICT_STAGE2_ARTIFACT_ROOT"
    else
        local system_parent
        system_parent="$(system_evidence_parent)"
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
    local system_parent
    system_parent="$(system_evidence_parent)"
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
    local system_parent
    system_parent="$(system_evidence_parent)"
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

gate_system_stage4() {
    local system_parent
    local cargo_target
    local x86_target
    local aarch64_target
    system_parent="$(system_evidence_parent)"
    cargo_target="$(cargo_target_directory)"
    x86_target="$cargo_target/x86_64-unknown-linux-gnu/release"
    aarch64_target="$cargo_target/aarch64-unknown-linux-gnu/release"
    local x86_worker="$x86_target/visa-system"
    local aarch64_worker="$aarch64_target/visa-system"
    local x86_conformance="$x86_target/visa-conformance"
    local qemu_x86_64
    local qemu_aarch64
    local relocated_root

    system_artifact_kind="Stage 4 target/substrate and cross-ISA matrix"
    system_artifact_root="$(umask 077; mktemp -d "$system_parent/stage4-XXXXXX")"
    system_bundle_path="$system_artifact_root/stage4-evidence.json"

    qemu_x86_64="$(command -v qemu-x86_64)"
    qemu_aarch64="$(command -v qemu-aarch64)"

    run_gate "system-stage4: release x86-64 runner, worker, and verifier" \
        cargo build --locked --release \
            --target x86_64-unknown-linux-gnu \
            -p visa-system \
            -p visa-conformance
    run_gate "system-stage4: release AArch64 worker" \
        cargo build --locked --release \
            --target aarch64-unknown-linux-gnu \
            -p visa-system \
            --bin visa-system
    run_gate "system-stage4: real seven-cell target/substrate and cross-ISA matrix" \
        env \
            VISA_STAGE4_X86_64_WORKER="$x86_worker" \
            VISA_STAGE4_AARCH64_WORKER="$aarch64_worker" \
            VISA_STAGE4_QEMU_X86_64="$qemu_x86_64" \
            VISA_STAGE4_QEMU_AARCH64="$qemu_aarch64" \
            VISA_STAGE4_QX_SYSROOT=/ \
            VISA_STAGE4_QA_SYSROOT=/usr/aarch64-linux-gnu \
            "$x86_worker" stage4 "$system_artifact_root"
    run_gate "system-stage4: independent Stage 4 evidence validation" \
        "$x86_conformance" stage4 "$system_bundle_path" "$system_artifact_root"

    relocated_root="${system_artifact_root}-relocated"
    run_gate "system-stage4: require an unused relocation path" \
        test ! -e "$relocated_root"
    run_gate "system-stage4: relocate the byte-identical published bundle" \
        mv -- "$system_artifact_root" "$relocated_root"
    system_artifact_root="$relocated_root"
    system_bundle_path="$system_artifact_root/stage4-evidence.json"
    run_gate "system-stage4: independently validate the relocated evidence" \
        "$x86_conformance" stage4 "$system_bundle_path" "$system_artifact_root"

    printf 'Stage 4 artifact root: %s\n' "$system_artifact_root"
    printf 'Stage 4 evidence bundle: %s\n' "$system_bundle_path"
}

gate_system_stage4_target() {
    printf '%s\n' \
        'system-stage4-target currently runs the complete fail-closed Stage 4 aggregate matrix.'
    gate_system_stage4
}

gate_system_stage4_isa() {
    printf '%s\n' \
        'system-stage4-isa currently runs the complete fail-closed Stage 4 aggregate matrix.'
    gate_system_stage4
}

gate_system_joint_handoff() {
    local system_parent
    local visa_sha
    local key
    local value
    local -A locked=()
    local -a required_lock_keys
    local -a expectation_args
    local run_root
    local reference_root
    local relocated_root
    local outer_incomplete

    visa_sha="$(git rev-parse --verify HEAD)"
    if [[ ! "$visa_sha" =~ ^[0-9a-f]{40}$ ]]; then
        printf 'joint handoff vISA revision is not an exact lowercase Git SHA: %s\n' \
            "$visa_sha" >&2
        return 1
    fi
    if [[ -n "${GITHUB_SHA:-}" && "$visa_sha" != "$GITHUB_SHA" ]]; then
        printf 'joint handoff checkout SHA differs from GITHUB_SHA: checkout=%s github=%s\n' \
            "$visa_sha" "$GITHUB_SHA" >&2
        return 1
    fi
    if ! git diff --quiet --ignore-submodules -- \
        || ! git diff --cached --quiet --ignore-submodules -- \
        || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
        printf '%s\n' \
            'joint handoff evidence requires a clean worktree at the recorded exact vISA SHA' >&2
        return 1
    fi

    gate_joint_handoff_source_lock
    while IFS='=' read -r key value; do
        case "$key" in
            nexus_revision|neutral_revision|neutral_tree|neutral_bundle_sha256|protocol_sha256|machine_contract_sha256|refinement_map_sha256|abstract_registry_sha256|source_lock_sha256) ;;
            *)
                printf 'joint handoff source lock emitted unknown key: %s\n' "$key" >&2
                return 1
                ;;
        esac
        if [[ -z "$value" || -n "${locked[$key]+present}" ]]; then
            printf 'joint handoff source lock emitted empty or duplicate key: %s\n' "$key" >&2
            return 1
        fi
        locked[$key]="$value"
    done < <(python3 scripts/check-joint-handoff-source-lock.py --emit-values)
    required_lock_keys=(
        nexus_revision neutral_revision neutral_tree neutral_bundle_sha256 protocol_sha256
        machine_contract_sha256 refinement_map_sha256 abstract_registry_sha256
        source_lock_sha256
    )
    for key in "${required_lock_keys[@]}"; do
        if [[ -z "${locked[$key]+present}" ]]; then
            printf 'joint handoff source lock omitted key: %s\n' "$key" >&2
            return 1
        fi
    done
    expectation_args=(
        "$visa_sha"
        "${locked[nexus_revision]}"
        "${locked[neutral_revision]}"
        "${locked[neutral_tree]}"
        "${locked[neutral_bundle_sha256]}"
        "${locked[source_lock_sha256]}"
        "${locked[protocol_sha256]}"
        "${locked[machine_contract_sha256]}"
        "${locked[refinement_map_sha256]}"
        "${locked[abstract_registry_sha256]}"
    )

    system_parent="$(system_evidence_parent)"
    run_root="$(umask 077; mktemp -d "$system_parent/joint-handoff-reference-XXXXXX")"
    reference_root="$run_root/reference"
    relocated_root="$run_root/reference-relocated"
    outer_incomplete="$run_root/joint-handoff-gate-incomplete"
    system_artifact_kind="joint handoff reference-only"
    system_artifact_root="$run_root"
    system_bundle_path="$reference_root/joint-handoff-evidence.json"
    printf '%s\n' 'joint handoff reference gate incomplete' >"$outer_incomplete"

    run_gate "system-joint-handoff: reference peers and production reducer replay" \
        cargo run --locked \
            -p visa-joint-handoff-system \
            --bin visa-joint-handoff-system \
            -- \
            "$reference_root" \
            "${expectation_args[@]}"
    run_gate "system-joint-handoff: publisher removed its incomplete marker" \
        bash -c 'test ! -e "$1" && test ! -L "$1"' \
            _ "$reference_root/joint-handoff-incomplete"
    run_gate "system-joint-handoff: exact reference artifact inventory" \
        bash -c '
            actual="$(find "$1" -mindepth 1 -maxdepth 1 -printf "%f\n" | LC_ALL=C sort)"
            expected="$(printf "%s\n" joint-handoff-evidence.json production-replay.json)"
            test "$actual" = "$expected"
        ' _ "$reference_root"
    run_gate "system-joint-handoff: independent evidence validation" \
        cargo run --locked -p visa-conformance --bin visa-conformance -- \
            joint-handoff "$system_bundle_path" "$reference_root" \
            "${expectation_args[@]}"
    run_gate "system-joint-handoff: require an unused relocation path" \
        test ! -e "$relocated_root"
    run_gate "system-joint-handoff: relocate the byte-identical publication" \
        mv -- "$reference_root" "$relocated_root"
    system_bundle_path="$relocated_root/joint-handoff-evidence.json"
    run_gate "system-joint-handoff: independently validate relocated evidence" \
        cargo run --locked -p visa-conformance --bin visa-conformance -- \
            joint-handoff "$system_bundle_path" "$relocated_root" \
            "${expectation_args[@]}"
    run_gate "system-joint-handoff: retain no incomplete publication marker" \
        bash -c '
            test ! -e "$1/joint-handoff-incomplete"
            test ! -L "$1/joint-handoff-incomplete"
            rm -- "$2"
        ' _ "$relocated_root" "$outer_incomplete"

    printf 'Joint handoff reference artifact root: %s\n' "$system_artifact_root"
    printf 'Joint handoff reference evidence bundle: %s\n' "$system_bundle_path"
    printf '%s\n' \
        'Joint handoff evidence status: reference-only; Nexus exact-SHA qualification not claimed.'
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
    system-stage4-target) gate_system_stage4_target ;;
    system-stage4-isa) gate_system_stage4_isa ;;
    system-stage4) gate_system_stage4 ;;
    system-joint-handoff) gate_system_joint_handoff ;;
    -h|--help|help)
        usage
        ;;
    *)
        printf 'unknown validation tier: %s\n' "$tier" >&2
        usage
        exit 64
        ;;
esac
