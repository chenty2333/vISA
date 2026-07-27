#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT

mkdir -p "$test_root/bin"

cat >"$test_root/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
if [[ "$1" == pull ]]; then
    count=0
    if [[ -f "$FAKE_DOCKER_COUNT" ]]; then
        count=$(<"$FAKE_DOCKER_COUNT")
    fi
    count=$((count + 1))
    printf '%s\n' "$count" >"$FAKE_DOCKER_COUNT"
    ((count > FAKE_DOCKER_FAILURES))
    exit
fi
[[ "$1 $2" == 'image inspect' ]]
EOF
chmod +x "$test_root/bin/docker"

cat >"$test_root/bin/sleep" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$1" >>"$FAKE_SLEEP_LOG"
EOF
chmod +x "$test_root/bin/sleep"

cat >"$test_root/bin/timeout" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"$FAKE_TIMEOUT_LOG"
[[ "$1" == --foreground ]]
[[ "$2" == --signal=TERM ]]
[[ "$3" == --kill-after=15s ]]
[[ "$4" == 300s ]]
shift 4
exec "$@"
EOF
chmod +x "$test_root/bin/timeout"

run_case() {
    local name=$1
    local failures=$2
    local expected_status=$3
    local expected_pulls=$4
    local case_root="$test_root/$name"
    local status=0

    mkdir -p "$case_root"
    if env \
        PATH="$test_root/bin:$PATH" \
        FAKE_DOCKER_COUNT="$case_root/count" \
        FAKE_DOCKER_FAILURES="$failures" \
        FAKE_DOCKER_LOG="$case_root/docker.log" \
        FAKE_SLEEP_LOG="$case_root/sleep.log" \
        FAKE_TIMEOUT_LOG="$case_root/timeout.log" \
        "$script_dir/prepare-buildx.sh" \
        >"$case_root/stdout" 2>"$case_root/stderr"; then
        status=0
    else
        status=$?
    fi

    [[ "$status" == "$expected_status" ]]
    [[ "$(grep -c '^pull ' "$case_root/docker.log")" == "$expected_pulls" ]]
    [[ "$(wc -l <"$case_root/timeout.log" | tr -d '[:space:]')" == "$expected_pulls" ]]
    if [[ "$expected_status" == 0 ]]; then
        grep -Fx \
            'image inspect moby/buildkit:v0.31.2@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec' \
            "$case_root/docker.log" >/dev/null
        grep -Fx 'buildx-version=v0.35.0' "$case_root/stdout" >/dev/null
        [[ "$(wc -l <"$case_root/sleep.log" | tr -d '[:space:]')" == "$failures" ]]
    else
        ! grep -q '^image inspect ' "$case_root/docker.log"
        [[ "$(wc -l <"$case_root/sleep.log" | tr -d '[:space:]')" == 4 ]]
    fi
}

run_case succeeds_after_transient_failures 2 0 3
run_case fails_after_bound 5 1 5

printf '%s\n' 'pinned Buildx preparation tests passed'
