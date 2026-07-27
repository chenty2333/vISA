#!/usr/bin/env bash
set -Eeuo pipefail

readonly BUILDX_VERSION='v0.35.0'
readonly BUILDKIT_IMAGE='moby/buildkit:v0.31.2@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec'
readonly MAX_PULL_ATTEMPTS=5
readonly PULL_TIMEOUT_SECONDS=300
readonly PULL_KILL_AFTER_SECONDS=15

for ((attempt = 1; attempt <= MAX_PULL_ATTEMPTS; attempt++)); do
    if timeout --foreground --signal=TERM \
        --kill-after="${PULL_KILL_AFTER_SECONDS}s" \
        "${PULL_TIMEOUT_SECONDS}s" \
        docker pull "$BUILDKIT_IMAGE"; then
        docker image inspect "$BUILDKIT_IMAGE" >/dev/null
        printf 'buildx-version=%s\n' "$BUILDX_VERSION"
        printf 'buildkit-image=%s\n' "$BUILDKIT_IMAGE"
        exit 0
    fi

    if ((attempt == MAX_PULL_ATTEMPTS)); then
        break
    fi
    delay_seconds=$((attempt * 2))
    printf 'BuildKit pull attempt %d/%d failed; retrying in %d seconds\n' \
        "$attempt" "$MAX_PULL_ATTEMPTS" "$delay_seconds" >&2
    sleep "$delay_seconds"
done

printf 'could not pull pinned BuildKit image after %d attempts: %s\n' \
    "$MAX_PULL_ATTEMPTS" "$BUILDKIT_IMAGE" >&2
exit 1
