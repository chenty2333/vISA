#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

build_receipt=${VISA_WANCO_BUILD_RECEIPT:-$repo_root/target/.ci-cache/wanco-carrier/build-receipt.json}
if [[ ! -f $build_receipt ]]; then
    printf '%s\n' 'build the locked Wanco carrier before running its typed corpus' >&2
    exit 1
fi
image=${VISA_WANCO_IMAGE:-}
if [[ -z $image ]]; then
    image=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_tag"])' \
        "$build_receipt")
fi
docker image inspect "$image" >/dev/null
image_id=$(docker image inspect "$image" --format '{{.Id}}')

if [[ -n ${VISA_WANCO_CORPUS_ROOT:-} ]]; then
    artifact_root=$(realpath -m "$VISA_WANCO_CORPUS_ROOT")
    if [[ -e $artifact_root ]]; then
        printf 'refusing to overwrite corpus artifact root: %s\n' \
            "$artifact_root" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$artifact_root")"
else
    publication_parent=$(mktemp -d /tmp/visa-wanco-typed-corpus-publish.XXXXXXXX)
    artifact_root="$publication_parent/corpus"
fi
work_root=$(mktemp -d /tmp/visa-wanco-typed-corpus-work.XXXXXXXX)

host_uid=$(id -u)
host_gid=$(id -g)
install -m 0644 third_party/wanco/corpus/typed-stackmap.wat "$work_root/direct.wat"
install -m 0644 third_party/wanco/corpus/typed-stackmap-indirect.wat "$work_root/indirect.wat"
install -m 0644 third_party/wanco/corpus/data-segment-restore.c "$work_root/data-segment.c"
install -m 0644 third_party/wanco/corpus/post-import-root.wat "$work_root/post-import-root.wat"
install -m 0644 third_party/wanco/corpus/post-import-root-host.cc \
    "$work_root/post-import-root-host.cc"

declare -a live_containers=()
cleanup() {
    local name
    for name in "${live_containers[@]:-}"; do
        docker rm --force "$name" >/dev/null 2>&1 || true
    done
    case "$work_root" in
        /tmp/visa-wanco-typed-corpus-work.*)
            find "$work_root" -xdev -depth -delete 2>/dev/null || true
            ;;
        *)
            printf 'refusing unexpected typed-corpus scratch cleanup: %s\n' \
                "$work_root" >&2
            ;;
    esac
}
trap cleanup EXIT INT TERM

append_causal_event() {
    local path=$1
    local sequence=$2
    local event=$3
    local case_id=$4
    local event_image_id=$5
    local nonce=$6
    local container_id=$7
    local checkpoint_sha256=$8

    python3 - \
        "$path" "$sequence" "$event" "$case_id" "$event_image_id" \
        "$nonce" "$container_id" "$checkpoint_sha256" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

(
    raw_path,
    raw_sequence,
    event,
    case_id,
    image_id,
    nonce,
    container_id,
    raw_checkpoint_sha256,
) = sys.argv[1:]
sequence = int(raw_sequence, 10)
expected_events = {
    1: "host-import-entered",
    2: "runner-dispatched-sigusr1",
    3: "host-observed-post-signal-release",
    4: "post-import-exact-callsite-captured",
}
if expected_events.get(sequence) != event:
    raise SystemExit("causal event does not match its sequence")
if re.fullmatch(r"post-import-root-O[012]", case_id) is None:
    raise SystemExit("invalid post-import case identity")
if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
    raise SystemExit("invalid Wanco image identity")
if re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
    raise SystemExit("invalid post-import nonce")
if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
    raise SystemExit("invalid checkpoint container identity")
checkpoint_sha256 = None
if sequence == 4:
    if re.fullmatch(r"[0-9a-f]{64}", raw_checkpoint_sha256) is None:
        raise SystemExit("invalid checkpoint identity")
    checkpoint_sha256 = raw_checkpoint_sha256
elif raw_checkpoint_sha256 != "-":
    raise SystemExit("checkpoint identity appeared before persistence")

payload = {
    "case_id": case_id,
    "checkpoint_sha256": checkpoint_sha256,
    "container_id": container_id,
    "event": event,
    "image_id": image_id,
    "nonce": nonce,
    "sequence": sequence,
}
raw = (
    json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    + "\n"
).encode("ascii")
path = Path(raw_path)
flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC
if sequence == 1:
    flags |= os.O_CREAT | os.O_EXCL
descriptor = os.open(path, flags, 0o600)
try:
    offset = 0
    while offset < len(raw):
        offset += os.write(descriptor, raw[offset:])
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

write_process_observations() {
    local case_host=$1
    local case_id=$2
    local control_exit=$3
    local checkpoint_exit=$4
    local restore_exit=$5

    python3 - \
        "$case_host" "$case_id" "$control_exit" "$checkpoint_exit" \
        "$restore_exit" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

case_root = Path(sys.argv[1])
case_id = sys.argv[2]
statuses = {
    "control": int(sys.argv[3], 10),
    "checkpoint": int(sys.argv[4], 10),
    "restore": int(sys.argv[5], 10),
}
if any(status < 0 or status > 255 for status in statuses.values()):
    raise SystemExit("invalid process exit status")


def identity(path):
    digest = hashlib.sha256()
    size = 0
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"process artifact is not a regular file: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        if size != metadata.st_size:
            raise SystemExit(f"process artifact changed while hashing: {path}")
    finally:
        os.close(descriptor)
    return {"sha256": digest.hexdigest(), "size": size}


checkpoint = identity(case_root / "checkpoint.pb")
for role in ("control", "checkpoint", "restore"):
    payload = {
        "case_id": case_id,
        "checkpoint": None if role == "control" else checkpoint,
        "exit_status": statuses[role],
        "role": role,
        "schema": "visa-wanco-typed-process-observation-v1",
        "stderr": identity(case_root / f"{role}.stderr"),
        "stdout": identity(case_root / f"{role}.stdout"),
    }
    raw = (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")
    output = case_root / f"{role}.process.json"
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
PY
}

docker run --rm \
    --user "$host_uid:$host_gid" \
    --volume "$work_root:/work:Z" \
    --workdir /work \
    "$image" sh -ec '
        set -eu
        for profile in direct indirect; do
            for opt in 0 1 2; do
                wanco --enable-cr -O "$opt" -c \
                    -o "/work/${profile}-O${opt}.ll" "/work/${profile}.wat"
                clang++-17 -std=c++20 -flto -no-pie "-O${opt}" -g0 \
                    -Wl,--build-id=none "/work/${profile}-O${opt}.ll" \
                    -I/wanco/lib-rt /usr/local/lib/libwanco_rt.a \
                    -lprotobuf -lunwind -lunwind-x86_64 -lelf \
                    -ldl -lpthread -lm -o "/work/${profile}-O${opt}"
            done
        done
        for opt in 0 1 2; do
            clang-17 --target=wasm32-wasi -nostdlib "-O${opt}" \
                -Wl,--no-entry -Wl,--allow-undefined \
                -Wl,--export=_start \
                -o "/work/data-segment-O${opt}.wasm" \
                /work/data-segment.c
            wanco --enable-cr -O "$opt" -c \
                -o "/work/data-segment-O${opt}.ll" \
                "/work/data-segment-O${opt}.wasm"
            clang++-17 -std=c++20 -flto -no-pie "-O${opt}" -g0 \
                -Wl,--build-id=none "/work/data-segment-O${opt}.ll" \
                -I/wanco/lib-rt /usr/local/lib/libwanco_rt.a \
                -lprotobuf -lunwind -lunwind-x86_64 -lelf \
                -ldl -lpthread -lm -o "/work/data-segment-O${opt}"
            wanco --enable-cr -O "$opt" -c \
                -o "/work/post-import-root-O${opt}.ll" \
                /work/post-import-root.wat
            clang++-17 -std=c++20 -flto -no-pie "-O${opt}" -g0 \
                -Wl,--build-id=none "/work/post-import-root-O${opt}.ll" \
                /work/post-import-root-host.cc \
                -I/wanco/lib-rt /usr/local/lib/libwanco_rt.a \
                -lprotobuf -lunwind -lunwind-x86_64 -lelf \
                -ldl -lpthread -lm -o "/work/post-import-root-O${opt}"
        done
    ' >"$work_root/compile.stdout" 2>"$work_root/compile.stderr"

run_case() {
    local profile=$1
    local opt=$2
    local checkpoint_marker=$3
    local expected_frames=$4
    local expected_values=$5
    local ready_marker=${6:-$checkpoint_marker}
    local case_host="$work_root/results/${profile}-O${opt}"
    local case_container="/work/results/${profile}-O${opt}"
    local name="visa-wanco-corpus-${profile}-O${opt}-$$-$RANDOM"
    local container_id
    local container_exit_code
    local container_running
    local container_status
    local nonce=""
    local ready=false
    local release_observed=false
    local checkpoint_sha
    local control_exit
    local exit_code
    local restore_exit
    local -a witness_environment=()

    mkdir -p "$case_host"
    if docker run --rm \
        --user "$host_uid:$host_gid" \
        --volume "$work_root:/work:Z" \
        --workdir /work \
        "$image" "/work/${profile}-O${opt}" \
        >"$case_host/control.stdout" 2>"$case_host/control.stderr"; then
        control_exit=0
    else
        control_exit=$?
        printf 'control process failed for %s O%s: %s\n' \
            "$profile" "$opt" "$control_exit" >&2
        return 1
    fi

    if [[ $profile == post-import-root ]]; then
        nonce=$(
            printf '%s\n' "$image_id:$profile:O$opt" |
                sha256sum | cut -d' ' -f1
        )
        witness_environment=(
            --env "VISA_WANCO_IMPORT_WITNESS_NONCE=$nonce"
        )
    fi

    live_containers+=("$name")
    docker run --detach \
        --name "$name" \
        --user "$host_uid:$host_gid" \
        "${witness_environment[@]}" \
        --volume "$work_root:/work:Z" \
        --workdir "$case_container" \
        "$image" sh -ec \
        "exec /work/${profile}-O${opt} > checkpoint.stdout 2> checkpoint.stderr" \
        >"$case_host/container.id"
    container_id=$(tr -d '\n' <"$case_host/container.id")
    if [[ ! $container_id =~ ^[0-9a-f]{64}$ ]]; then
        printf 'invalid container identity for %s O%s: %s\n' \
            "$profile" "$opt" "$container_id" >&2
        return 1
    fi

    for _ in $(seq 1 300); do
        if grep -Fxq "$ready_marker" "$case_host/checkpoint.stdout" 2>/dev/null; then
            ready=true
            break
        fi
        sleep 0.02
    done
    if [[ $ready != true ]]; then
        container_running=$(
            docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null ||
                printf unavailable
        )
        container_status=$(
            docker inspect --format '{{.State.Status}}' "$name" 2>/dev/null ||
                printf unavailable
        )
        container_exit_code=$(
            docker inspect --format '{{.State.ExitCode}}' "$name" 2>/dev/null ||
                printf unavailable
        )
        docker logs "$name" >&2 || true
        printf 'checkpoint marker %s was not reached for %s O%s; container running=%s status=%s exit_code=%s\n' \
            "$ready_marker" "$profile" "$opt" "$container_running" \
            "$container_status" "$container_exit_code" >&2
        return 1
    fi

    if [[ $profile == post-import-root ]]; then
        grep -Fxq "entered $nonce" "$case_host/import-entered.txt"
        append_causal_event \
            "$case_host/causal-events.jsonl" 1 \
            host-import-entered "${profile}-O${opt}" "$image_id" \
            "$nonce" "$container_id" -
    fi
    docker kill --signal USR1 "$container_id" >"$case_host/signal.stdout"
    if [[ $profile == post-import-root ]]; then
        append_causal_event \
            "$case_host/causal-events.jsonl" 2 \
            runner-dispatched-sigusr1 "${profile}-O${opt}" "$image_id" \
            "$nonce" "$container_id" -
        printf 'signal-dispatched %s\n' "$nonce" \
            >"$case_host/signal-dispatched.tmp"
        mv "$case_host/signal-dispatched.tmp" \
            "$case_host/signal-dispatched.txt"
        for _ in $(seq 1 300); do
            if grep -Fxq "release-observed $nonce" \
                "$case_host/import-release-observed.txt" 2>/dev/null; then
                release_observed=true
                break
            fi
            sleep 0.02
        done
        if [[ $release_observed != true ]]; then
            docker logs "$name" >&2 || true
            printf 'post-import release was not observed for %s O%s\n' \
                "$profile" "$opt" >&2
            return 1
        fi
        append_causal_event \
            "$case_host/causal-events.jsonl" 3 \
            host-observed-post-signal-release "${profile}-O${opt}" \
            "$image_id" "$nonce" "$container_id" -
    fi
    exit_code=$(docker wait "$name")
    docker rm "$name" >"$case_host/remove.stdout"
    live_containers=("${live_containers[@]/$name}")
    if [[ $exit_code != 0 ]]; then
        printf 'checkpoint process failed for %s O%s: %s\n' \
            "$profile" "$opt" "$exit_code" >&2
        return 1
    fi
    test -s "$case_host/checkpoint.pb"
    grep -Fxq "$checkpoint_marker" "$case_host/checkpoint.stdout"
    if [[ $profile == post-import-root ]]; then
        grep -Fxq "$container_id" "$case_host/signal.stdout"
        grep -Fxq "signal-dispatched $nonce" \
            "$case_host/signal-dispatched.txt"
        grep -Fxq "release-observed $nonce" \
            "$case_host/import-release-observed.txt"
    fi

    if docker run --rm \
        --user "$host_uid:$host_gid" \
        --volume "$work_root:/work:Z" \
        --workdir "$case_container" \
        "$image" "/work/${profile}-O${opt}" \
        --restore "$case_container/checkpoint.pb" \
        >"$case_host/restore.stdout" 2>"$case_host/restore.stderr"; then
        restore_exit=0
    else
        restore_exit=$?
        printf 'restore process failed for %s O%s: %s\n' \
            "$profile" "$opt" "$restore_exit" >&2
        return 1
    fi

    cmp "$case_host/control.stdout" \
        <(awk '1' "$case_host/checkpoint.stdout" "$case_host/restore.stdout")
    if grep -Fxq 999 "$case_host/checkpoint.stdout" "$case_host/restore.stdout"; then
        printf 'restore selected the wrong indirect target for %s O%s\n' \
            "$profile" "$opt" >&2
        return 1
    fi
    grep -Fq -- "- call stack: $expected_frames frames" "$case_host/restore.stderr"
    grep -Fq -- "- value stack: $expected_values values" "$case_host/restore.stderr"
    sha256sum "$case_host/checkpoint.pb" >"$case_host/checkpoint.sha256"
    checkpoint_sha=$(cut -d' ' -f1 <"$case_host/checkpoint.sha256")
    if [[ $profile == post-import-root ]]; then
        append_causal_event \
            "$case_host/causal-events.jsonl" 4 \
            post-import-exact-callsite-captured "${profile}-O${opt}" \
            "$image_id" "$nonce" "$container_id" "$checkpoint_sha"
    fi
    write_process_observations \
        "$case_host" "${profile}-O${opt}" \
        "$control_exit" "$exit_code" "$restore_exit"

    printf '%s O%s: PASS (%s frames, %s typed stack values)\n' \
        "$profile" "$opt" "$expected_frames" "$expected_values"
}

for opt in 0 1 2; do
    run_case direct "$opt" 703 6 4
done
for opt in 0 1 2; do
    run_case indirect "$opt" 803 3 3
done
for opt in 0 1 2; do
    run_case data-segment "$opt" 903 4 0
done
for opt in 0 1 2; do
    run_case post-import-root "$opt" 1005 1 0 1003
done

python3 "$repo_root/scripts/wanco_typed_corpus.py" build \
    --source-root "$work_root" \
    --artifact-root "$artifact_root" \
    --image-tag "$image" \
    --image-id "$image_id" \
    --wanco-source-lock "$repo_root/third_party/wanco/source-lock.json" \
    --wanco-build-receipt "$build_receipt"

python3 "$repo_root/scripts/wanco_typed_corpus.py" validate \
    "$artifact_root/receipt.json"
printf 'typed checkpoint corpus artifact root: %s\n' "$artifact_root"
