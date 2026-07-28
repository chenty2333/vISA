#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-stage4-native-hardware.sh [--skip-image-build] \
    [--artifact-parent DIR] --identity-file FILE \
    --host-key-sha256 SHA256:FINGERPRINT <user@aarch64-host>

Builds exact-source x86-64 and AArch64 release workers in the pinned vISA
container, deploys the AArch64 worker to a fresh remote /tmp directory, runs
the Hx->Hx, Hx->Ha, Ha->Hx, and Ha->Ha matrix, and independently verifies the
published evidence before and after relocation.

The remote host must use SSH port 22 and support key-based BatchMode login.
EOF
}

build_image=1
artifact_parent=""
identity_source=""
expected_host_key_sha256=""
remote_host=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --skip-image-build)
            build_image=0
            shift
            ;;
        --artifact-parent)
            if [[ "$#" -lt 2 ]]; then
                printf '%s\n' '--artifact-parent requires a directory' >&2
                usage
                exit 64
            fi
            artifact_parent=$2
            shift 2
            ;;
        --identity-file)
            if [[ "$#" -lt 2 ]]; then
                printf '%s\n' '--identity-file requires a file' >&2
                usage
                exit 64
            fi
            identity_source=$2
            shift 2
            ;;
        --host-key-sha256)
            if [[ "$#" -lt 2 ]]; then
                printf '%s\n' '--host-key-sha256 requires an OpenSSH SHA-256 fingerprint' >&2
                usage
                exit 64
            fi
            expected_host_key_sha256=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --*)
            printf 'unknown option: %s\n' "$1" >&2
            usage
            exit 64
            ;;
        *)
            if [[ -n "$remote_host" ]]; then
                printf '%s\n' 'only one remote host may be supplied' >&2
                usage
                exit 64
            fi
            remote_host=$1
            shift
            ;;
    esac
done

if [[ -z "$remote_host" \
    || "$remote_host" == -* \
    || ! "$remote_host" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$ ]]; then
    printf '%s\n' 'remote host must have the shell-safe form user@host' >&2
    usage
    exit 64
fi
if [[ ! "$expected_host_key_sha256" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]]; then
    printf '%s\n' 'a pre-confirmed ED25519 --host-key-sha256 fingerprint is required' >&2
    exit 64
fi
if [[ -z "$identity_source" || ! -f "$identity_source" || -L "$identity_source" ]]; then
    printf '%s\n' '--identity-file must name a non-symlink regular file' >&2
    exit 64
fi
identity_source=$(realpath -e "$identity_source")
identity_mode=$(stat -c '%a' "$identity_source")
if (( (8#$identity_mode & 077) != 0 )); then
    printf '%s\n' '--identity-file must not be accessible by group or other users' >&2
    exit 64
fi

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [[ -z "$artifact_parent" ]]; then
    artifact_parent="$repo_root/.ci-artifacts/stage4-native"
fi
artifact_parent=$(realpath -m "$artifact_parent")
mkdir -p -m 0700 "$artifact_parent"
if [[ -L "$artifact_parent" || ! -d "$artifact_parent" ]]; then
    printf 'unsafe artifact parent: %s\n' "$artifact_parent" >&2
    exit 64
fi

for directory in \
    .ci-cache/cargo-git \
    .ci-cache/cargo-registry \
    .ci-cache/stage4-native-hx-target \
    .ci-cache/target \
    .ci-cache/visa-ltp \
    .ci-artifacts; do
    mkdir -p "$directory"
done

compose=(docker compose -f compose.yaml -f compose.ci.yaml)
"${compose[@]}" config --quiet
if [[ "$build_image" -eq 1 ]]; then
    "${compose[@]}" build dev
fi

hx_target_root="$repo_root/.ci-cache/stage4-native-hx-target"
env CARGO_TARGET_DIR="$hx_target_root" bash -Eeuo pipefail -c '
    source scripts/canonical-component-build-env.sh
    visa_configure_canonical_component_build_environment
    cargo build --locked --release \
        --target x86_64-unknown-linux-gnu \
        -p visa-system \
        -p visa-conformance
'
"${compose[@]}" run --rm -T dev bash -Eeuo pipefail -c '
    source scripts/canonical-component-build-env.sh
    visa_configure_canonical_component_build_environment
    cargo build --locked --release \
        --target aarch64-unknown-linux-gnu \
        -p visa-system \
        --bin visa-system
'

hx_worker="$hx_target_root/x86_64-unknown-linux-gnu/release/visa-system"
ha_worker="$repo_root/.ci-cache/target/aarch64-unknown-linux-gnu/release/visa-system"
verifier="$hx_target_root/x86_64-unknown-linux-gnu/release/visa-conformance"
for executable in "$hx_worker" "$ha_worker" "$verifier"; do
    if [[ ! -x "$executable" || -L "$executable" ]]; then
        printf 'required release executable is absent or unsafe: %s\n' "$executable" >&2
        exit 1
    fi
done

temporary_root=$(mktemp -d)
known_hosts="$temporary_root/known_hosts"
identity_file="$temporary_root/id_ed25519"
install -m 0600 -- "$identity_source" "$identity_file"
remote_root=""
cleanup() {
    original_status=$?
    trap - EXIT
    set +e
    if [[ -n "$remote_root" \
        && "$remote_root" =~ ^/tmp/visa-stage4-native\.[A-Za-z0-9]+$ ]]; then
        ssh \
            -T \
            -F /dev/null \
            -o BatchMode=yes \
            -o ConnectTimeout=15 \
            -o ClearAllForwardings=yes \
            -o LogLevel=ERROR \
            -o StrictHostKeyChecking=yes \
            -o "UserKnownHostsFile=$known_hosts" \
            -o ServerAliveInterval=15 \
            -o ServerAliveCountMax=3 \
            "$remote_host" \
            rm -rf -- "$remote_root"
    fi
    rm -rf -- "$temporary_root"
    exit "$original_status"
}
trap cleanup EXIT

scan_host=${remote_host#*@}
ssh-keyscan -T 10 -t ed25519 "$scan_host" >"$known_hosts"
if [[ ! -s "$known_hosts" ]]; then
    printf 'ssh-keyscan returned no ED25519 host key for %s\n' "$scan_host" >&2
    exit 1
fi
chmod 0400 "$known_hosts"
observed_host_key_sha256=$(ssh-keygen -lf "$known_hosts" -E sha256 | awk 'NR == 1 { print $2 }')
observed_host_key_type=$(ssh-keygen -lf "$known_hosts" -E sha256 | awk 'NR == 1 { print $4 }')
if [[ "$observed_host_key_type" != '(ED25519)' \
    || "$observed_host_key_sha256" != "$expected_host_key_sha256" ]]; then
    printf 'remote ED25519 host-key mismatch: expected %s, observed %s %s\n' \
        "$expected_host_key_sha256" "$observed_host_key_sha256" "$observed_host_key_type" >&2
    exit 1
fi

ssh_options=(
    -T
    -F /dev/null
    -o BatchMode=yes
    -o ConnectTimeout=15
    -o ClearAllForwardings=yes
    -o ForwardAgent=no
    -o ForwardX11=no
    -o IdentitiesOnly=yes
    -o "IdentityFile=$identity_file"
    -o LogLevel=ERROR
    -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=$known_hosts"
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=3
)
remote_root=$(ssh "${ssh_options[@]}" "$remote_host" \
    mktemp -d /tmp/visa-stage4-native.XXXXXXXX)
if [[ ! "$remote_root" =~ ^/tmp/visa-stage4-native\.[A-Za-z0-9]+$ ]]; then
    printf 'remote mktemp returned an unsafe path: %s\n' "$remote_root" >&2
    exit 1
fi
remote_worker="$remote_root/visa-system"

scp \
    -F /dev/null \
    -o BatchMode=yes \
    -o ConnectTimeout=15 \
    -o ClearAllForwardings=yes \
    -o LogLevel=ERROR \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=$known_hosts" \
    -o ServerAliveInterval=15 \
    -o ServerAliveCountMax=3 \
    "$ha_worker" "$remote_host:$remote_worker"
ssh "${ssh_options[@]}" "$remote_host" chmod 0555 "$remote_worker"

local_ha_sha=$(sha256sum "$ha_worker" | cut -d' ' -f1)
remote_ha_sha=$(ssh "${ssh_options[@]}" "$remote_host" \
    sha256sum "$remote_worker" | cut -d' ' -f1)
if [[ "$local_ha_sha" != "$remote_ha_sha" ]]; then
    printf '%s\n' 'deployed AArch64 worker digest mismatch' >&2
    exit 1
fi

artifact_root=$(mktemp -d "$artifact_parent/native-XXXXXXXX")
"$hx_worker" stage4-native \
    "$artifact_root" \
    "$ha_worker" \
    /usr/bin/ssh \
    "$known_hosts" \
    "$identity_file" \
    "$remote_host" \
    "$remote_worker"

bundle="$artifact_root/stage4-native-evidence.json"
"$verifier" stage4-native "$bundle" "$artifact_root"

relocated_root="${artifact_root}-relocated"
if [[ -e "$relocated_root" ]]; then
    printf 'relocation target already exists: %s\n' "$relocated_root" >&2
    exit 1
fi
mv -- "$artifact_root" "$relocated_root"
artifact_root=$relocated_root
bundle="$artifact_root/stage4-native-evidence.json"
"$verifier" stage4-native "$bundle" "$artifact_root"

printf 'Stage 4 native artifact root: %s\n' "$artifact_root"
printf 'Stage 4 native evidence bundle: %s\n' "$bundle"
printf 'Stage 4 native host-key SHA-256: %s\n' "$(sha256sum "$known_hosts" | cut -d' ' -f1)"
printf 'Stage 4 native remote host-key fingerprint: %s\n' "$observed_host_key_sha256"
