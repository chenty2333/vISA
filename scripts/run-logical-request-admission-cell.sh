#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-logical-request-admission-cell.sh \
    --nexus-checkout NEXUS_CHECKOUT \
    --nexus-bin NEXUS_EFFECT_PEER_BINARY \
    --artifact-root NEW_FINAL_ARTIFACT_ROOT

Runs the bounded clean exact-SHA vISA + qualified Nexus same-boot
admission-ordered logical-request handoff cell. A verified Nexus v2
qualification receipt must already exist in the clean Nexus checkout.

Run mode makes and verifies a private single-link copy of the supplied external
Nexus binary, executes that copy before the logical request is sent, completes
the Wasmtime source freeze and destination activation, and publishes exactly
seven files: one canonical manifest, one terminal report, four finalized SQLite
databases, and the exact executed Nexus peer bytes.
Verification is a separate process which requires the externally fixed manifest
SHA-256. It securely reads the retained binary as opaque bytes and never
executes it. The artifact is then relocated and verified again with the same
manifest SHA-256.

PID, original executable path, and process start ticks are same-boot historical
observations, not relocatable provenance. The artifact does not claim real OSTD
execution, IRQ/SMP/device coverage, cross-host transfer, reboot recovery,
cryptographic freshness, Registry replacement, retained tombstones, general
exactly-once semantics, reproducible source-to-binary derivation, or remote CI.

The final artifact may live outside the vISA checkout or under the checkout's
ignored .ci-artifacts directory. Other in-checkout output paths are rejected.
EOF
}

fail() {
    printf 'Logical-request admission cell failed: %s\n' "$*" >&2
    return 1
}

root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
source_lock="$root/third_party/joint-handoff-qualification/source-lock.json"
qualification_lock="$root/third_party/joint-handoff-qualification/nexus-qualification-lock.json"
source_lock_verifier="$root/scripts/check-joint-handoff-source-lock.py"
qualification_lock_verifier="$root/scripts/check-nexus-handoff-qualification.py"
manifest_name="logical-request-admission-manifest.json"
nexus_checkout=""
nexus_bin=""
artifact_root=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --nexus-checkout)
            [[ "$#" -ge 2 ]] || { usage; exit 64; }
            nexus_checkout="$2"
            shift 2
            ;;
        --nexus-bin)
            [[ "$#" -ge 2 ]] || { usage; exit 64; }
            nexus_bin="$2"
            shift 2
            ;;
        --artifact-root)
            [[ "$#" -ge 2 ]] || { usage; exit 64; }
            artifact_root="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown logical-request admission argument: %s\n' "$1" >&2
            usage
            exit 64
            ;;
    esac
done

if [[ -z "$nexus_checkout" || -z "$nexus_bin" || -z "$artifact_root" ]]; then
    usage
    exit 64
fi
for command in cargo git python3 sha256sum mktemp mv install stat sync rm; do
    command -v "$command" >/dev/null 2>&1 \
        || fail "required command is unavailable: $command"
done
for path in \
    "$source_lock" \
    "$qualification_lock" \
    "$source_lock_verifier" \
    "$qualification_lock_verifier"; do
    [[ -f "$path" && ! -L "$path" ]] \
        || fail "trust-root input is not a regular non-symlink file: $path"
done

visa_toplevel="$(git -C "$root" rev-parse --show-toplevel)"
[[ "$visa_toplevel" == "$root" ]] || fail "script root is not the vISA Git toplevel"
nexus_checkout="$(CDPATH='' cd -- "$nexus_checkout" && pwd -P)"
[[ "$(git -C "$nexus_checkout" rev-parse --show-toplevel)" == "$nexus_checkout" ]] \
    || fail "Nexus checkout is not a Git toplevel: $nexus_checkout"

if [[ "$nexus_bin" != /* ]]; then
    nexus_bin="$PWD/$nexus_bin"
fi
[[ -f "$nexus_bin" && ! -L "$nexus_bin" && -x "$nexus_bin" ]] \
    || fail "Nexus effect peer is not an executable regular non-symlink file: $nexus_bin"
nexus_bin="$(
    CDPATH='' cd -- "$(dirname -- "$nexus_bin")"
    printf '%s/%s\n' "$PWD" "$(basename -- "$nexus_bin")"
)"

if [[ "$artifact_root" != /* ]]; then
    artifact_root="$PWD/$artifact_root"
fi
artifact_parent="$(dirname -- "$artifact_root")"
artifact_name="$(basename -- "$artifact_root")"
[[ -n "$artifact_name" && "$artifact_name" != . && "$artifact_name" != .. ]] \
    || fail "artifact root must name one new directory"
artifact_parent="$(CDPATH='' cd -- "$artifact_parent" && pwd -P)"
artifact_root="$artifact_parent/$artifact_name"
[[ ! -e "$artifact_root" && ! -L "$artifact_root" ]] \
    || fail "final artifact root already exists: $artifact_root"
case "$artifact_root/" in
    "$root/.ci-artifacts/"*)
        git -C "$root" check-ignore -q -- "$artifact_root" \
            || fail ".ci-artifacts output is not ignored by the vISA checkout"
        ;;
    "$root/"*)
        fail "artifact root must be outside the vISA checkout or below ignored .ci-artifacts"
        ;;
esac

require_clean_checkout() {
    local checkout="$1"
    local label="$2"
    if [[ -n "$(git -C "$checkout" status --porcelain=v1 --untracked-files=all)" ]]; then
        fail "$label checkout is not clean, including non-ignored untracked files"
    fi
}

visa_revision="$(git -C "$root" rev-parse --verify HEAD)"
[[ "$visa_revision" =~ ^[0-9a-f]{40}$ ]] \
    || fail "vISA HEAD is not an exact lowercase Git SHA: $visa_revision"
require_clean_checkout "$root" vISA
require_clean_checkout "$nexus_checkout" Nexus

declare -A locked=()
while IFS='=' read -r key value; do
    case "$key" in
        nexus_revision|neutral_revision|neutral_tree|neutral_bundle_sha256|protocol_sha256|machine_contract_sha256|refinement_map_sha256|abstract_registry_sha256|source_lock_sha256) ;;
        *) fail "source-lock verifier emitted unknown key: $key" ;;
    esac
    [[ -n "$value" && -z "${locked[$key]+present}" ]] \
        || fail "source-lock verifier emitted an empty or duplicate key: $key"
    locked[$key]="$value"
done < <(python3 "$source_lock_verifier" --emit-values "$source_lock")
for key in \
    nexus_revision neutral_revision neutral_tree neutral_bundle_sha256 \
    source_lock_sha256; do
    [[ -n "${locked[$key]+present}" ]] || fail "source lock omitted required value: $key"
done

mapfile -t qualification_values < <(
    python3 "$qualification_lock_verifier" \
        --lock "$qualification_lock" --emit-lock-values
)
[[ "${#qualification_values[@]}" -eq 4 ]] \
    || fail "Nexus v2 qualification lock did not emit exactly four values"
qualified_nexus_revision="${qualification_values[0]}"
nexus_reference_baseline_revision="${qualification_values[1]}"
[[ "$qualified_nexus_revision" =~ ^[0-9a-f]{40}$ ]] \
    || fail "qualified Nexus revision is not an exact lowercase Git SHA"
[[ "$nexus_reference_baseline_revision" =~ ^[0-9a-f]{40}$ ]] \
    || fail "Nexus reference baseline is not an exact lowercase Git SHA"
[[ "${locked[nexus_revision]}" == "$nexus_reference_baseline_revision" ]] \
    || fail "source-lock Nexus revision differs from the v2 analyzed reference baseline"
[[ "$(git -C "$nexus_checkout" rev-parse --verify HEAD)" == "$qualified_nexus_revision" ]] \
    || fail "clean Nexus checkout HEAD differs from the qualified Nexus revision"

nexus_receipt="$nexus_checkout/target/research/handoff-admission/receipt.json"
[[ -f "$nexus_receipt" && ! -L "$nexus_receipt" ]] \
    || fail "Nexus v2 qualification receipt is absent; run the locked qualification first"
python3 "$qualification_lock_verifier" \
    --lock "$qualification_lock" \
    --checkout "$nexus_checkout" \
    --receipt "$nexus_receipt"

actual_source_lock_sha256="$(sha256sum -- "$source_lock" | cut -d ' ' -f1)"
[[ "$actual_source_lock_sha256" == "${locked[source_lock_sha256]}" ]] \
    || fail "source-lock verifier digest differs from the exact lock bytes"
qualification_lock_sha256="$(sha256sum -- "$qualification_lock" | cut -d ' ' -f1)"
nexus_bin_sha256="$(sha256sum -- "$nexus_bin" | cut -d ' ' -f1)"
[[ "$qualification_lock_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || fail "Nexus qualification-lock SHA-256 is not canonical"
[[ "$nexus_bin_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || fail "Nexus executable SHA-256 is not canonical"

provenance_args=(
    "$visa_revision"
    "$nexus_bin_sha256"
    "$qualified_nexus_revision"
    "$nexus_reference_baseline_revision"
    "${locked[neutral_revision]}"
    "${locked[neutral_tree]}"
    "${locked[neutral_bundle_sha256]}"
    "$actual_source_lock_sha256"
    "$qualification_lock_sha256"
)

trust_root_digest() {
    sha256sum -- \
        "$source_lock" \
        "$qualification_lock" \
        "$source_lock_verifier" \
        "$qualification_lock_verifier" \
        "$root/scripts/run-logical-request-admission-cell.sh" \
        "$root/crates/testing/visa-conformance/src/artifact_io.rs" \
        "$root/crates/testing/visa-joint-handoff-system/src/bin/logical-request-admission.rs" \
        "$root/crates/testing/visa-joint-handoff-system/src/logical_request_admission_cell.rs" \
        "$root/crates/testing/visa-joint-handoff-system/src/logical_request_admission_verify.rs" \
        "$root/crates/testing/visa-joint-handoff-system/src/ownership.rs" \
        "$root/crates/testing/visa-joint-handoff-system/src/process_effect_peer.rs" \
        "$root/crates/testing/visa-joint-handoff-system/src/projection_log.rs" \
        | sha256sum | cut -d ' ' -f1
}
initial_trust_root_digest="$(trust_root_digest)"

umask 077
stage_parent="$(mktemp -d "$artifact_parent/.logical-request-admission.XXXXXX")"
live_root="$stage_parent/live"
execution_nexus_bin="$stage_parent/nexus-effect-peer.execution"
retained_path="$stage_parent"
on_error() {
    local status=$?
    trap - ERR
    printf 'Logical-request admission partial state retained at %s\n' "$retained_path" >&2
    if [[ "$retained_path" != "$stage_parent" && -d "$stage_parent" ]]; then
        printf 'Logical-request admission execution staging retained at %s\n' "$stage_parent" >&2
    fi
    exit "$status"
}
trap on_error ERR

install -m 0500 -- "$nexus_bin" "$execution_nexus_bin"
sync -d -- "$execution_nexus_bin"
[[ "$(stat -c '%h' -- "$execution_nexus_bin")" == 1 ]] \
    || fail "private Nexus execution copy is not single-link"
[[ "$(sha256sum -- "$execution_nexus_bin" | cut -d ' ' -f1)" == "$nexus_bin_sha256" ]] \
    || fail "private Nexus execution copy differs from the supplied exact bytes"

printf '%s\n' '==> exact Nexus process provider-conformance negatives'
(
    CDPATH='' cd -- "$root"
    env \
        NEXUS_EFFECT_PEER_BIN="$execution_nexus_bin" \
        NEXUS_EFFECT_PEER_SHA256="$nexus_bin_sha256" \
        NEXUS_EFFECT_PEER_REVISION="$qualified_nexus_revision" \
        cargo test --locked --quiet \
            -p visa-joint-handoff-system \
            provider_conformance::process_effect_peer_passes_the_shared_provider_harness -- \
            --ignored --exact --test-threads=1
)

run_artifact_command() {
    local mode="$1"
    local location="$2"
    local manifest_sha256="${3:-}"
    (
        CDPATH='' cd -- "$root"
        if [[ "$mode" == run ]]; then
            cargo run --locked --quiet \
                -p visa-joint-handoff-system \
                --bin logical-request-admission \
                -- run "$location" "$visa_revision" "$execution_nexus_bin" \
                "$nexus_bin_sha256" "$qualified_nexus_revision" \
                "$nexus_reference_baseline_revision" \
                "${locked[neutral_revision]}" "${locked[neutral_tree]}" \
                "${locked[neutral_bundle_sha256]}" "$actual_source_lock_sha256" \
                "$qualification_lock_sha256"
        else
            [[ "$manifest_sha256" =~ ^[0-9a-f]{64}$ ]] \
                || fail "verify invocation omitted a canonical manifest SHA-256"
            cargo run --locked --quiet \
                -p visa-joint-handoff-system \
                --bin logical-request-admission \
                -- verify "$location" "$manifest_sha256" "${provenance_args[@]}"
        fi
    )
}

run_artifact_command run "$live_root"
manifest_sha256="$(sha256sum -- "$live_root/$manifest_name" | cut -d ' ' -f1)"
[[ "$manifest_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || fail "published manifest SHA-256 is not canonical"
run_artifact_command verify "$live_root" "$manifest_sha256"
[[ "$(trust_root_digest)" == "$initial_trust_root_digest" ]] \
    || fail "logical-request admission cell modified its vISA trust roots"
[[ "$(sha256sum -- "$nexus_bin" | cut -d ' ' -f1)" == "$nexus_bin_sha256" ]] \
    || fail "Nexus executable changed during logical-request admission execution"
[[ "$(sha256sum -- "$execution_nexus_bin" | cut -d ' ' -f1)" == "$nexus_bin_sha256" ]] \
    || fail "private Nexus execution copy changed during logical-request admission execution"
require_clean_checkout "$root" vISA
require_clean_checkout "$nexus_checkout" Nexus

mv -- "$live_root" "$artifact_root"
retained_path="$artifact_root"
run_artifact_command verify "$artifact_root" "$manifest_sha256"
[[ "$(sha256sum -- "$artifact_root/$manifest_name" | cut -d ' ' -f1)" == "$manifest_sha256" ]] \
    || fail "relocated manifest differs from the externally fixed SHA-256"
[[ "$(trust_root_digest)" == "$initial_trust_root_digest" ]] \
    || fail "relocation verification modified its vISA trust roots"
[[ "$(sha256sum -- "$nexus_bin" | cut -d ' ' -f1)" == "$nexus_bin_sha256" ]] \
    || fail "Nexus executable changed during relocation verification"
[[ "$(sha256sum -- "$execution_nexus_bin" | cut -d ' ' -f1)" == "$nexus_bin_sha256" ]] \
    || fail "private Nexus execution copy changed during relocation verification"
require_clean_checkout "$root" vISA
require_clean_checkout "$nexus_checkout" Nexus
rm -- "$execution_nexus_bin"
rmdir -- "$stage_parent"
trap - ERR

printf 'Logical-request admission artifact: %s\n' "$artifact_root"
printf 'Manifest SHA-256: %s\n' "$manifest_sha256"
printf 'vISA exact revision: %s\n' "$visa_revision"
printf 'Qualified Nexus exact revision: %s\n' "$qualified_nexus_revision"
printf 'Nexus reference baseline revision: %s\n' "$nexus_reference_baseline_revision"
printf 'Nexus executable SHA-256: %s\n' "$nexus_bin_sha256"
printf '%s\n' \
    'Inventory: exactly seven single-link regular files; verification is root-FD anchored and never executes the artifact-owned Nexus binary.'
printf '%s\n' \
    'Limitations: same boot only; PID/path/start ticks are historical; no real OSTD, IRQ/SMP/device, cross-host, reboot, freshness, Registry replacement, retained tombstone, general exactly-once, source-to-binary reproducibility, or remote-CI claim.'
