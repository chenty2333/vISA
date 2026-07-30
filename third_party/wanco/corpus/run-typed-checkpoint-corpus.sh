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
    local nonce=""
    local ready=false
    local exit_code
    local -a witness_environment=()

    mkdir -p "$case_host"
    docker run --rm \
        --user "$host_uid:$host_gid" \
        --volume "$work_root:/work:Z" \
        --workdir /work \
        "$image" "/work/${profile}-O${opt}" \
        >"$case_host/control.stdout" 2>"$case_host/control.stderr"

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
        if ! docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null |
            grep -Fxq true; then
            break
        fi
        sleep 0.02
    done
    if [[ $ready != true ]]; then
        docker logs "$name" >&2 || true
        printf 'checkpoint marker %s was not reached for %s O%s\n' \
            "$ready_marker" "$profile" "$opt" >&2
        return 1
    fi

    if [[ $profile == post-import-root ]]; then
        grep -Fxq "entered $nonce" "$case_host/import-entered.txt"
    fi
    docker kill --signal USR1 "$container_id" >"$case_host/signal.stdout"
    if [[ $profile == post-import-root ]]; then
        printf 'signal-dispatched %s\n' "$nonce" \
            >"$case_host/signal-dispatched.tmp"
        mv "$case_host/signal-dispatched.tmp" \
            "$case_host/signal-dispatched.txt"
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

    docker run --rm \
        --user "$host_uid:$host_gid" \
        --volume "$work_root:/work:Z" \
        --workdir "$case_container" \
        "$image" "/work/${profile}-O${opt}" \
        --restore "$case_container/checkpoint.pb" \
        >"$case_host/restore.stdout" 2>"$case_host/restore.stderr"

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
    --wanco-build-receipt "$build_receipt"

python3 "$repo_root/scripts/wanco_typed_corpus.py" validate \
    "$artifact_root/receipt.json"
printf 'typed checkpoint corpus artifact root: %s\n' "$artifact_root"
