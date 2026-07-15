#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-nexus-handoff-qualification.sh \
    --checkout NEXUS_CHECKOUT --artifact-root NEW_ARTIFACT_ROOT

Runs the source-locked Nexus same-boot handoff-admission and production Registry
refinement gate, verifies its v2 receipt independently, copies the exact
evidence to a relocation-safe artifact tree, and verifies the copied bytes
again. This lane qualifies only the Nexus-local admission/closure refinement;
it does not execute the joint vISA wire adapter or a real ostd runtime cell.
EOF
}

root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
lock="$root/third_party/joint-handoff-qualification/nexus-qualification-lock.json"
verifier="$root/scripts/check-nexus-handoff-qualification.py"
wrapper="$root/scripts/run-nexus-handoff-qualification.sh"
checkout=""
artifact_root=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --checkout)
            [[ "$#" -ge 2 ]] || { usage; exit 64; }
            checkout="$2"
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
            printf 'unknown Nexus qualification argument: %s\n' "$1" >&2
            usage
            exit 64
            ;;
    esac
done

if [[ -z "$checkout" || -z "$artifact_root" ]]; then
    usage
    exit 64
fi
if [[ ! -f "$lock" || -L "$lock" ]]; then
    printf 'Nexus qualification lock is absent or not a regular file: %s\n' "$lock" >&2
    exit 1
fi
if [[ ! -x "$verifier" ]]; then
    printf 'Nexus qualification verifier is not executable: %s\n' "$verifier" >&2
    exit 1
fi

trust_root_digest() {
    sha256sum -- "$lock" "$verifier" "$wrapper" | sha256sum | cut -d ' ' -f1
}
initial_trust_root_digest="$(trust_root_digest)"

checkout="$(CDPATH='' cd -- "$checkout" && pwd -P)"
if [[ "$artifact_root" != /* ]]; then
    artifact_root="$PWD/$artifact_root"
fi
if [[ -e "$artifact_root" || -L "$artifact_root" ]]; then
    printf 'Nexus qualification artifact root must not already exist: %s\n' \
        "$artifact_root" >&2
    exit 1
fi

mapfile -t lock_values < <("$verifier" --lock "$lock" --emit-lock-values)
if [[ "${#lock_values[@]}" -ne 4 ]]; then
    printf 'Nexus qualification lock emitted %s values, expected 4\n' \
        "${#lock_values[@]}" >&2
    exit 1
fi
nexus_revision="${lock_values[0]}"
if [[ ! "$nexus_revision" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'Nexus qualification revision is not an exact lowercase Git SHA: %s\n' \
        "$nexus_revision" >&2
    exit 1
fi
if [[ "$(git -C "$checkout" rev-parse --verify HEAD)" != "$nexus_revision" ]]; then
    printf 'Nexus checkout does not match qualification lock revision %s\n' \
        "$nexus_revision" >&2
    exit 1
fi
if [[ -n "$(git -C "$checkout" status --porcelain=v1 --untracked-files=all)" ]]; then
    printf 'Nexus qualification requires a clean exact-SHA checkout\n' >&2
    exit 1
fi

umask 077
mkdir -p -- "$artifact_root/qualification"
incomplete="$artifact_root/nexus-handoff-qualification-incomplete"
printf '%s\n' 'Nexus handoff qualification incomplete' >"$incomplete"

on_error() {
    local status=$?
    trap - ERR
    if [[ -d "$artifact_root" && ! -e "$incomplete" ]]; then
        printf '%s\n' 'Nexus handoff qualification incomplete' >"$incomplete"
    fi
    printf 'Nexus handoff qualification failed; partial evidence retained at %s\n' \
        "$artifact_root" >&2
    exit "$status"
}
trap on_error ERR

set -o pipefail
(
    CDPATH='' cd -- "$checkout"
    ./x research handoff-admission
) 2>&1 | tee "$artifact_root/qualification/nexus-handoff-admission.log"

if [[ "$(trust_root_digest)" != "$initial_trust_root_digest" ]]; then
    printf '%s\n' 'Nexus execution modified the vISA qualification trust root' >&2
    exit 1
fi

receipt_relative="target/research/handoff-admission/receipt.json"
"$verifier" \
    --lock "$lock" \
    --checkout "$checkout" \
    --receipt "$checkout/$receipt_relative" \
    2>&1 | tee "$artifact_root/qualification/live-verifier.log"

evidence_paths=(
    evaluation/handoff-admission/fault-matrix.toml
    target/research/handoff-admission/receipt.json
    target/research/handoff-admission/tla.log
    target/research/handoff-admission/rust-oracle.log
    target/research/handoff-admission/summary.txt
)
(
    CDPATH='' cd -- "$checkout"
    cp --parents -- "${evidence_paths[@]}" "$artifact_root"
)
cp -- "$lock" "$artifact_root/qualification/nexus-qualification-lock.json"

"$verifier" \
    --lock "$lock" \
    --checkout "$checkout" \
    --evidence-root "$artifact_root" \
    --receipt "$artifact_root/$receipt_relative" \
    2>&1 | tee "$artifact_root/qualification/relocated-verifier.log"

if [[ "$(trust_root_digest)" != "$initial_trust_root_digest" ]]; then
    printf '%s\n' 'qualification verification modified its own trust root' >&2
    exit 1
fi

typed_inventory() {
    find "$1" -mindepth 1 -printf '%y %P\n' | LC_ALL=C sort
}

expected_before_manifest="$(cat <<'EOF'
d evaluation
d evaluation/handoff-admission
d qualification
d target
d target/research
d target/research/handoff-admission
f evaluation/handoff-admission/fault-matrix.toml
f nexus-handoff-qualification-incomplete
f qualification/live-verifier.log
f qualification/nexus-handoff-admission.log
f qualification/nexus-qualification-lock.json
f qualification/relocated-verifier.log
f target/research/handoff-admission/receipt.json
f target/research/handoff-admission/rust-oracle.log
f target/research/handoff-admission/summary.txt
f target/research/handoff-admission/tla.log
EOF
)"
actual_inventory="$(typed_inventory "$artifact_root")"
if [[ "$actual_inventory" != "$expected_before_manifest" ]]; then
    printf 'Nexus qualification pre-manifest inventory drifted\nexpected:\n%s\nactual:\n%s\n' \
        "$expected_before_manifest" "$actual_inventory" >&2
    exit 1
fi

manifest_files=(
    evaluation/handoff-admission/fault-matrix.toml
    qualification/live-verifier.log
    qualification/nexus-handoff-admission.log
    qualification/nexus-qualification-lock.json
    qualification/relocated-verifier.log
    target/research/handoff-admission/receipt.json
    target/research/handoff-admission/rust-oracle.log
    target/research/handoff-admission/summary.txt
    target/research/handoff-admission/tla.log
)
(
    CDPATH='' cd -- "$artifact_root"
    sha256sum -- "${manifest_files[@]}" >artifact-sha256.txt
)

expected_with_manifest="$(
    printf '%s\n%s\n' "$expected_before_manifest" 'f artifact-sha256.txt' | LC_ALL=C sort
)"
actual_inventory="$(typed_inventory "$artifact_root")"
if [[ "$actual_inventory" != "$expected_with_manifest" ]]; then
    printf 'Nexus qualification artifact inventory drifted\nexpected:\n%s\nactual:\n%s\n' \
        "$expected_with_manifest" "$actual_inventory" >&2
    exit 1
fi

rm -- "$incomplete"
final_inventory="$(typed_inventory "$artifact_root")"
expected_final_inventory="$(
    printf '%s\n' "$expected_with_manifest" \
        | sed '/^f nexus-handoff-qualification-incomplete$/d'
)"
if [[ "$final_inventory" != "$expected_final_inventory" ]]; then
    printf 'Nexus qualification final artifact inventory drifted\nexpected:\n%s\nactual:\n%s\n' \
        "$expected_final_inventory" "$final_inventory" >&2
    exit 1
fi
printf 'Nexus local handoff-admission qualification artifact: %s\n' "$artifact_root"
printf 'Nexus exact revision: %s\n' "$nexus_revision"
printf '%s\n' \
    'Claim boundary: same-boot Nexus-local Registry refinement only; joint vISA and real ostd execution are false.'
