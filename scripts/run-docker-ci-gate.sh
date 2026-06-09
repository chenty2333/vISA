#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-docker-ci-gate.sh [--ci-cache] [--skip-build] [gate...]

Builds or reuses the vISA Docker development image and runs scripts/ci-gate.sh
inside it. With no gate arguments, runs all gates.

Options:
  --ci-cache   Use compose.ci.yaml bind-mounted cache directories.
  --skip-build Do not build the image before running gates.
EOF
}

use_ci_cache=0
build_image=1
gates=()

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --ci-cache)
            use_ci_cache=1
            shift
            ;;
        --skip-build|--no-build)
            build_image=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            gates+=("$1")
            shift
            ;;
    esac
done

if [[ "${#gates[@]}" -eq 0 ]]; then
    gates=(all)
fi

compose=(docker compose -f compose.yaml)
if [[ "$use_ci_cache" -eq 1 ]]; then
    compose+=(-f compose.ci.yaml)
    mkdir -p \
        .ci-cache/cargo-git \
        .ci-cache/cargo-registry \
        .ci-cache/target \
        .ci-cache/visa-ltp
fi

if [[ "$build_image" -eq 1 ]]; then
    "${compose[@]}" build dev
fi

"${compose[@]}" run --rm -T dev scripts/ci-gate.sh "${gates[@]}"
