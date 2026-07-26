#!/usr/bin/env bash
set -euo pipefail

# AArch64 cross-compilation readiness check for the pure-logic subset of the
# active continuity spine. This is preparation for re-running the Stage 4
# matrix on real aarch64 Linux hardware; it proves only that these crates
# type-check for the target triple. It does not build, link, or run anything
# on AArch64, and it publishes no evidence and no claim.

TARGET=aarch64-unknown-linux-gnu
CI_GATE=scripts/ci-gate.sh

usage() {
    cat >&2 <<'EOF'
usage: scripts/check-aarch64-cross.sh [-h|--help]

Runs cargo check --target aarch64-unknown-linux-gnu over the subset of the
active continuity spine that carries no runtime or system-library dependency.

The candidate subset and its complement are checked against the
active_spine_packages array in scripts/ci-gate.sh, so this script fails closed
if that array changes without a matching decision here.

The aarch64 target is not installed automatically. When it is missing this
script prints the rustup command and exits 1.

Environment:

  VISA_AARCH64_CHECK_ARGS   Extra arguments appended to each cargo check.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 2
fi
if [[ "$#" -gt 0 ]]; then
    usage
    exit 2
fi

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_root"

if [[ ! -f "$CI_GATE" ]]; then
    echo "CI gate script not found: $CI_GATE" >&2
    exit 66
fi

# Pure-logic spine crates. Each depends only on contract_core and no_std-capable
# registry crates, so nothing here needs a C toolchain, a Wasm runtime, or a
# system bus to type-check for a foreign target.
cross_candidates=(
    contract_core
    joint_handoff_core
    semantic_core
    substrate_api
    visa_local_rpc
    visa_profile
)

# Spine crates deliberately outside the candidate subset, with the dependency
# that keeps them out. These are not failures; they are the crates whose real
# AArch64 story has to be settled on hardware rather than by cargo check.
declare -A cross_excluded=(
    [handoff-component]="wasm32-unknown-unknown component, not a host target"
    [stage3-file-component]="wasm32-unknown-unknown component, not a host target"
    [stage3-request-component]="wasm32-unknown-unknown component, not a host target"
    [substrate_host]="rusqlite, needs a cross C toolchain"
    [visa-cli]="zbus, needs a cross D-Bus/system stack"
    [visa-conformance]="pulls the runtime and system harness crates"
    [visa-joint-handoff-system]="system harness, drives real workers"
    [visa-stage3-system]="system harness, drives real workers"
    [visa-system]="system harness, drives real workers"
    [visa_agent_store]="rusqlite, needs a cross C toolchain"
    [visa_component_adapter]="reaches the component runtime stack"
    [visa_durable_sqlite]="rusqlite, needs a cross C toolchain"
    [visa_jco_node]="wasmtime-environ, plus a Node toolchain"
    [visa_joint_handoff]="reaches the runtime stack"
    [visa_local_transport]="zbus, needs a cross D-Bus/system stack"
    [visa_nexus_service]="rusqlite, needs a cross C toolchain"
    [visa_ownership_service]="rusqlite, needs a cross C toolchain"
    [visa-ownershipd]="rusqlite, needs a cross C toolchain"
    [visa_runtime]="reaches the runtime stack"
    [visa_wacogo]="pinned Wacogo sidecar toolchain"
    [visa_wasmtime]="wasmtime, the Stage 4 worker runtime itself"
)

read_active_spine() {
    # Reads the active_spine_packages array literal out of the CI gate rather
    # than restating it, so the two lists cannot drift silently.
    sed -n '/^active_spine_packages=(/,/^)/p' "$CI_GATE" \
        | sed -e '1d' -e '$d' -e 's/#.*//' \
        | tr -d ' \t' \
        | grep -v '^$'
}

active_spine=()
while IFS= read -r package; do
    active_spine+=("$package")
done < <(read_active_spine)

if [[ "${#active_spine[@]}" -eq 0 ]]; then
    echo "Could not read active_spine_packages from $CI_GATE." >&2
    exit 2
fi

partition_ok=true

for package in "${active_spine[@]}"; do
    classified=false
    for candidate in "${cross_candidates[@]}"; do
        if [[ "$package" == "$candidate" ]]; then
            classified=true
            break
        fi
    done
    if [[ "$classified" == false && -n "${cross_excluded[$package]:-}" ]]; then
        classified=true
    fi
    if [[ "$classified" == false ]]; then
        printf 'unclassified active-spine package: %s\n' "$package" >&2
        partition_ok=false
    fi
done

in_active_spine() {
    local needle="$1" package
    for package in "${active_spine[@]}"; do
        [[ "$package" == "$needle" ]] && return 0
    done
    return 1
}

for candidate in "${cross_candidates[@]}"; do
    if ! in_active_spine "$candidate"; then
        printf 'candidate is no longer an active-spine package: %s\n' "$candidate" >&2
        partition_ok=false
    fi
done

for package in "${!cross_excluded[@]}"; do
    if ! in_active_spine "$package"; then
        printf 'exclusion names a non-spine package: %s\n' "$package" >&2
        partition_ok=false
    fi
done

if [[ "$partition_ok" != true ]]; then
    cat >&2 <<EOF

The candidate and exclusion lists in this script no longer partition
active_spine_packages in $CI_GATE. Update this script to record a decision for
each changed package; do not edit the CI gate to satisfy this check.
EOF
    exit 2
fi

if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup not found; cannot confirm the $TARGET standard library." >&2
    exit 1
fi

if ! rustup target list --installed | grep -qx "$TARGET"; then
    cat >&2 <<EOF
Rust target $TARGET is not installed.

Install it, then re-run this script:

  rustup target add $TARGET

Cross-linking also expects the linker named for this target in
.cargo/config.toml (aarch64-linux-gnu-gcc). Library-only checks do not link, so
that toolchain is not required by this script.
EOF
    exit 1
fi

if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    printf 'note: aarch64-linux-gnu-gcc not found; cargo check does not link, so this only limits later build steps.\n'
fi

extra_args=()
if [[ -n "${VISA_AARCH64_CHECK_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    extra_args=(${VISA_AARCH64_CHECK_ARGS})
fi

printf 'AArch64 cross-check target: %s\n' "$TARGET"
printf 'Candidate spine crates: %s\n\n' "${#cross_candidates[@]}"

failed=()

for package in "${cross_candidates[@]}"; do
    printf '==> cargo check -p %s --target %s\n' "$package" "$TARGET"
    status=0
    cargo check --locked --quiet -p "$package" --target "$TARGET" \
        "${extra_args[@]+"${extra_args[@]}"}" || status=$?
    if [[ "$status" -eq 0 ]]; then
        printf 'ok: %s\n\n' "$package"
    else
        printf 'FAILED (exit %s): %s\n\n' "$status" "$package"
        failed+=("$package")
    fi
done

printf 'Excluded from this check (%s spine crates):\n' "${#cross_excluded[@]}"
for package in $(printf '%s\n' "${!cross_excluded[@]}" | sort); do
    printf '  %-28s %s\n' "$package" "${cross_excluded[$package]}"
done
printf '\n'

if [[ "${#failed[@]}" -gt 0 ]]; then
    printf '%s of %s candidate crate(s) failed to check for %s:\n' \
        "${#failed[@]}" "${#cross_candidates[@]}" "$TARGET" >&2
    printf '  %s\n' "${failed[@]}" >&2
    exit 1
fi

printf 'All %s candidate spine crates type-check for %s.\n' \
    "${#cross_candidates[@]}" "$TARGET"
printf 'This is a compile-time signal only; no AArch64 code was built or run.\n'
