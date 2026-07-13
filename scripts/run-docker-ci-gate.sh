#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-docker-ci-gate.sh [--ci-cache] [--skip-build] \
    [--artifact-parent DIR] \
    [fast|full|system|system-jco-node|system-stage2|system-stage2-strict]

Validates the Compose configuration, builds or reuses the vISA development
image, and runs the selected validation tier. With no tier, runs full.
System tiers are standalone and preserve their evidence under the container's
/workspace/target/visa-system directory. system-stage2 executes all four
runtime-pair cells and can be substantially slower than the other tiers.
system-stage2-strict calls the same local Strict Stage 2 gate used on the host,
with locked offline Wacogo inputs from the image. Its evidence, Docker log, and
sidecar binary/receipt are retained together under a host-visible run root.

Options:
  --ci-cache           Use compose.ci.yaml bind-mounted cache directories.
  --skip-build         Reuse the existing development image.
  --artifact-parent DIR
                       Parent for a unique Strict Stage 2 Docker run root.
                       Valid only with system-stage2-strict; defaults to
                       the repository's .ci-cache/strict-stage2. Custom paths
                       may be outside the repository. Existing symlink path
                       components are rejected in both cases; ':' and newline
                       are rejected because this path becomes a Docker bind.
EOF
}

use_ci_cache=0
build_image=1
tier=""
artifact_parent=""

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --ci-cache)
            use_ci_cache=1
            shift
            ;;
        --skip-build)
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
        -h|--help)
            usage
            exit 0
            ;;
        fast|full|system|system-jco-node|system-stage2|system-stage2-strict)
            if [[ -n "$tier" ]]; then
                printf 'only one validation tier may be selected\n' >&2
                usage
                exit 64
            fi
            tier="$1"
            shift
            ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            usage
            exit 64
            ;;
    esac
done

tier="${tier:-full}"
if [[ -n "$artifact_parent" && "$tier" != system-stage2-strict ]]; then
    printf '%s\n' '--artifact-parent is valid only with system-stage2-strict' >&2
    usage
    exit 64
fi

compose=(docker compose -f compose.yaml)
if [[ "$use_ci_cache" -eq 1 ]]; then
    compose+=(-f compose.ci.yaml)
fi

if [[ "$tier" != system-stage2-strict ]]; then
    if [[ "$use_ci_cache" -eq 1 ]]; then
        mkdir -p \
            .ci-cache/cargo-git \
            .ci-cache/cargo-registry \
            .ci-cache/target \
            .ci-cache/visa-ltp
    fi
    "${compose[@]}" config --quiet
    if [[ "$build_image" -eq 1 ]]; then
        "${compose[@]}" build dev
    fi
    "${compose[@]}" run --rm -T dev scripts/ci-gate.sh "$tier"
    exit $?
fi

repo_root=$(git rev-parse --show-toplevel)
artifact_parent_scope=custom
if [[ -z "$artifact_parent" ]]; then
    artifact_parent="$repo_root/.ci-cache/strict-stage2"
    artifact_parent_scope=repository
fi
artifact_parent=$(
    PYTHONDONTWRITEBYTECODE=1 python3 - \
        "$artifact_parent" "$repo_root" "$artifact_parent_scope" <<'PY'
import os
from pathlib import Path
import stat
import sys

path = Path(os.path.abspath(os.path.expanduser(sys.argv[1])))
repo = Path(os.path.abspath(sys.argv[2]))
scope = sys.argv[3]


def inspect_components(candidate: Path) -> None:
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            break
        except OSError as error:
            raise SystemExit(f"cannot inspect Strict Stage 2 artifact path {current}: {error}")
        if stat.S_ISLNK(mode):
            raise SystemExit(
                f"Strict Stage 2 artifact path contains a symlink component: {current}"
            )
        if not stat.S_ISDIR(mode):
            raise SystemExit(
                f"Strict Stage 2 artifact path component is not a directory: {current}"
            )


inspect_components(path)
try:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
except OSError as error:
    raise SystemExit(f"cannot prepare Strict Stage 2 artifact parent {path}: {error}")
inspect_components(path)
try:
    resolved = path.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"cannot resolve Strict Stage 2 artifact parent {path}: {error}")
if not resolved.is_dir():
    raise SystemExit(f"Strict Stage 2 artifact parent is not a directory: {resolved}")
if ":" in str(resolved) or "\n" in str(resolved):
    raise SystemExit(
        f"Strict Stage 2 artifact parent cannot contain ':' or newline: {resolved}"
    )
if scope == "repository":
    try:
        resolved.relative_to(repo.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise SystemExit(
            f"default Strict Stage 2 artifact parent escapes repository {repo}: {error}"
        )
print(resolved)
PY
)

run_root=$(mktemp -d "$artifact_parent/docker-strict-stage2-XXXXXXXX")
gate_root="$run_root/gate"
sidecar_root="$run_root/visa-wacogo"
docker_log="$run_root/docker.log"

report_strict_exit() {
    original_status=$?
    trap - EXIT
    set +e
    receipt_status=0
    footer_status=0
    printf '%s\n' "$original_status" >"$run_root/docker-exit-status" \
        || receipt_status=$?
    {
        printf 'docker-exit-status=%s\n' "$original_status"
        printf 'host-artifact-root=%s\n' "$run_root"
        printf 'host-gate-root=%s\n' "$gate_root"
        printf 'host-sidecar-root=%s\n' "$sidecar_root"
    } | tee -a "$docker_log" || footer_status=$?
    final_status=$original_status
    if [[ "$original_status" -eq 0 \
        && ( "$receipt_status" -ne 0 || "$footer_status" -ne 0 ) ]]; then
        final_status=1
        printf '%s\n' "$final_status" >"$run_root/docker-exit-status" || true
    fi
    exit "$final_status"
}
trap report_strict_exit EXIT

mkdir -m 0700 "$gate_root" "$sidecar_root"
{
    printf 'host-artifact-root=%s\n' "$run_root"
    printf 'host-gate-root=%s\n' "$gate_root"
    printf 'host-sidecar-root=%s\n' "$sidecar_root"
} | tee "$docker_log"

log_strict_command() {
    "$@" 2>&1 | tee -a "$docker_log"
}

if [[ "$use_ci_cache" -eq 1 ]]; then
    log_strict_command mkdir -p \
        .ci-cache/cargo-git \
        .ci-cache/cargo-registry \
        .ci-cache/target \
        .ci-cache/visa-ltp
fi
log_strict_command "${compose[@]}" config --quiet
if [[ "$build_image" -eq 1 ]]; then
    log_strict_command "${compose[@]}" build dev
fi

log_strict_command "${compose[@]}" run --rm -T \
    --volume "$run_root:/visa-strict-output" \
    --volume "$sidecar_root:/workspace/target/visa-wacogo" \
    dev \
    bash -Eeuo pipefail -c '
        runtime_module_cache=/tmp/visa-wacogo-gomodcache
        seed=/opt/visa-wacogo/gomodcache.tar.gz
        rm -rf -- "$runtime_module_cache"
        mkdir -m 0700 -- "$runtime_module_cache"
        tar --extract --gzip --file "$seed" --directory "$runtime_module_cache"
        test -f "$runtime_module_cache/github.com/regclient/regclient@v0.8.3/testdata/.wh.layer2.txt"
        test -f "$runtime_module_cache/github.com/regclient/regclient@v0.8.3/testdata/exdir/.wh..wh..opq"
        printf "module-cache-seed=%s sha256=%s\n" "$seed" "$(sha256sum "$seed" | cut -d" " -f1)"
        printf "materialized-module-cache=%s\n" "$runtime_module_cache"
        exec env \
            GOENV=off \
            GOPROXY=off \
            GOSUMDB=off \
            GOTELEMETRY=off \
            GOTOOLCHAIN=local \
            "GOVCS=*:off" \
            GOWORK=off \
            VISA_WACOGO_GOMODCACHE="$runtime_module_cache" \
            VISA_STRICT_STAGE2_ARTIFACT_ROOT=/visa-strict-output/gate \
            scripts/ci-gate.sh system-stage2-strict
    '
