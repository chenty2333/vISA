#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-docker-ci-gate.sh [--ci-cache] [--skip-build] [fast|full|system]

Validates the Compose configuration, builds or reuses the vISA development
image, and runs the selected validation tier. With no tier, runs full.
The system tier is standalone and preserves its Stage 1 artifacts under the
container's /workspace/target/visa-system directory.

Options:
  --ci-cache   Use compose.ci.yaml bind-mounted cache directories.
  --skip-build Reuse the existing development image.
EOF
}

use_ci_cache=0
build_image=1
tier=""

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
        -h|--help)
            usage
            exit 0
            ;;
        fast|full|system)
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
compose=(docker compose -f compose.yaml)
if [[ "$use_ci_cache" -eq 1 ]]; then
    compose+=(-f compose.ci.yaml)
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
