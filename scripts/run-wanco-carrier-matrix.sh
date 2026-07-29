#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [[ $(uname -m) != x86_64 ]]; then
    printf '%s\n' 'the locked Wanco carrier build currently requires a native x86_64 host' >&2
    exit 1
fi
git_sha=$(git rev-parse HEAD)
git_dirty=false
if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
    git_dirty=true
fi
if [[ -n ${GITHUB_SHA:-} ]]; then
    if [[ $git_sha != "$GITHUB_SHA" ]]; then
        printf 'HEAD does not match GITHUB_SHA: %s != %s\n' "$(git rev-parse HEAD)" "$GITHUB_SHA" >&2
        exit 1
    fi
fi
if [[ $git_dirty == true ]]; then
    printf '%s\n' 'canonical Wanco matrix evidence requires an exact clean HEAD' >&2
    exit 1
fi
started_at_unix_ms=$(date +%s%3N)

runs=${VISA_WANCO_RUNS:-3}
if [[ ! $runs =~ ^[0-9]+$ ]] || ((runs < 3)); then
    printf '%s\n' 'VISA_WANCO_RUNS must be an integer of at least 3' >&2
    exit 1
fi

evidence_parent=${VISA_EVIDENCE_PARENT:-"$repo_root/target/.ci-artifacts"}
artifact_root="$evidence_parent/wanco-carrier"
if [[ -e $artifact_root ]]; then
    printf 'refusing to overwrite existing Wanco evidence root: %s\n' "$artifact_root" >&2
    exit 1
fi
mkdir -p "$artifact_root/build"
artifact_root=$(realpath "$artifact_root")

scripts/build-wanco-carrier.sh
cargo build --locked -p visa-wanco-carrier -p visa-regular-file-oracle
cargo build --locked -p visa-conformance --bin visa-evidence-matrix

cargo_target=$(cargo metadata --locked --no-deps --format-version 1 |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
producer="$cargo_target/debug/visa-wanco-carrier"
oracle="$cargo_target/debug/visa-regular-file-oracle"
matrix_validator="$cargo_target/debug/visa-evidence-matrix"
matrix_summary=$("$matrix_validator" claims/evidence-matrix.json)
if [[ ! $matrix_summary =~ sha256=([0-9a-f]{64})$ ]]; then
    printf 'could not obtain the canonical evidence matrix SHA: %s\n' "$matrix_summary" >&2
    exit 1
fi
matrix_sha=${BASH_REMATCH[1]}
wanco_revision=$(python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["upstream"]["revision"])' \
    third_party/wanco/source-lock.json)
build_receipt="$repo_root/target/.ci-cache/wanco-carrier/build-receipt.json"
image_tag=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_tag"])' "$build_receipt")
image_id=$(docker image inspect --format '{{.Id}}' "$image_tag")
producer_sha=$(sha256sum "$producer" | cut -d' ' -f1)
oracle_sha=$(sha256sum "$oracle" | cut -d' ' -f1)
install -m 0644 "$build_receipt" "$artifact_root/build/wanco-image-receipt.json"

host_uid=$(id -u)
host_gid=$(id -g)
install -m 0644 \
    "$repo_root/crates/runtime/visa_wanco_carrier/guest/regular_file_workload.wat" \
    "$artifact_root/build/regular_file_workload.wat"
install -m 0644 \
    "$repo_root/crates/runtime/visa_wanco_carrier/guest/append_continuity_workload.wat" \
    "$artifact_root/build/append_continuity_workload.wat"
install -m 0644 \
    "$repo_root/crates/runtime/visa_wanco_carrier/guest/visa_ha_endpoint.cc" \
    "$artifact_root/build/visa_ha_endpoint.cc"
docker run --rm \
    --user "$host_uid:$host_gid" \
    --volume "$artifact_root/build:/work:Z" \
    --workdir /work \
    "$image_tag" sh -ec '
        set -eu
        test "$LLVM_SYS_170_PREFIX" = /usr/lib/llvm-17
        /usr/lib/llvm-17/bin/llvm-config --version
        wanco --enable-cr -O1 -c -o /work/read-write-offset.ll \
            /work/regular_file_workload.wat
        clang++-17 -std=c++20 -flto -no-pie -O1 -g \
            /work/read-write-offset.ll \
            /work/visa_ha_endpoint.cc \
            -I/wanco/lib-rt \
            /usr/local/lib/libwanco_rt.a /usr/local/lib/libwanco_wasi.a \
            -lprotobuf -lunwind -lunwind-x86_64 -lelf \
            -o /work/read-write-offset
        wanco --enable-cr -O1 -c -o /work/append-continuity.ll \
            /work/append_continuity_workload.wat
        clang++-17 -std=c++20 -flto -no-pie -O1 -g \
            /work/append-continuity.ll \
            /work/visa_ha_endpoint.cc \
            -I/wanco/lib-rt \
            /usr/local/lib/libwanco_rt.a /usr/local/lib/libwanco_wasi.a \
            -lprotobuf -lunwind -lunwind-x86_64 -lelf \
            -o /work/append-continuity
    ' >"$artifact_root/build/compile.stdout" 2>"$artifact_root/build/compile.stderr"

for executable in read-write-offset append-continuity; do
    test -x "$artifact_root/build/$executable"
    nm --defined-only "$artifact_root/build/$executable" |
        grep -Fq "visa_ha_$(if [[ $executable == read-write-offset ]]; then printf regular_file; else printf append; fi)_step"
done

python3 - "$artifact_root/build/receipt.json" "$image_tag" "$image_id" \
    "$producer_sha" "$oracle_sha" "$repo_root" <<'PY'
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

output, image_tag, image_id, producer_sha, oracle_sha, repo_root = sys.argv[1:]
build = Path(output).parent
receipt = {
    "schema": "visa-wanco-carrier-compile-receipt-v1",
    "git_sha": subprocess.check_output(
        ["git", "-C", repo_root, "rev-parse", "HEAD"], text=True
    ).strip(),
    "host_isa": platform.machine(),
    "image_tag": image_tag,
    "image_id": image_id,
    "producer_sha256": producer_sha,
    "oracle_sha256": oracle_sha,
    "executables": {},
}
for name in ("read-write-offset", "append-continuity"):
    payload = (build / name).read_bytes()
    receipt["executables"][name] = {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }
receipt["inputs"] = {}
for name in (
    "regular_file_workload.wat",
    "append_continuity_workload.wat",
    "visa_ha_endpoint.cc",
):
    payload = (build / name).read_bytes()
    receipt["inputs"][name] = {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }
temporary = Path(output).with_suffix(".tmp")
temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(temporary, output)
PY

declare -a live_containers=()
declare -A live_services=()
cleanup() {
    local name pid
    for name in "${live_containers[@]:-}"; do
        docker rm --force "$name" >/dev/null 2>&1 || true
    done
    for pid in "${!live_services[@]}"; do
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT INT TERM

seal_checkout() {
    local current_sha
    current_sha=$(git rev-parse HEAD)
    if [[ $current_sha != "$git_sha" ]]; then
        printf 'checkout HEAD changed during Wanco matrix run: %s != %s\n' \
            "$current_sha" "$git_sha" >&2
        return 1
    fi
    if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
        printf '%s\n' 'checkout became dirty during Wanco matrix run' >&2
        return 1
    fi
    if [[ -n ${GITHUB_SHA:-} && $current_sha != "$GITHUB_SHA" ]]; then
        printf 'final Wanco matrix HEAD does not match GITHUB_SHA: %s != %s\n' \
            "$current_sha" "$GITHUB_SHA" >&2
        return 1
    fi
}

case_initial() {
    case "$1" in
        read-write-offset) printf '%s' 'abcdef' ;;
        append-continuity) printf '%s' 'base' ;;
        *) return 1 ;;
    esac
}

launch_container() {
    local name=$1
    local directory=$2
    local case_name=$3
    local event_name=$4
    local role=$5
    local canonical_socket=$6
    local resume_gate=$7
    shift 7
    live_containers+=("$name")
    local -a environment=(
        --env "VISA_HA_EVENT_LOG=/work/$event_name"
    )
    if [[ $role != - ]]; then
        environment+=(
            --env "VISA_HA_ENDPOINT_ROLE=$role"
            --env "VISA_HA_CASE=$case_name"
        )
    fi
    if [[ $canonical_socket != - ]]; then
        environment+=(--env "VISA_HA_CANONICAL_SOCKET=/work/$canonical_socket")
    fi
    if [[ $resume_gate != - ]]; then
        environment+=(--env "VISA_HA_RESUME_GATE=/work/$resume_gate")
    fi
    # The canonical endpoint is a host process serving a Unix socket.  On
    # SELinux hosts, a container label cannot connect to an unconfined host
    # peer even when the socket inode is relabelled.  Disable only Docker's
    # process label for this same-host composition; no device, host network, or
    # privileged access is granted.
    docker run --detach --name "$name" \
        --security-opt label=disable \
        --user "$host_uid:$host_gid" \
        --volume "$directory:/work" \
        --volume "$artifact_root/build:/aot:ro" \
        --workdir /work \
        "${environment[@]}" \
        "$image_tag" "/aot/$case_name" "$@" >/dev/null
}

wait_container() {
    local name=$1
    local code
    code=$(timeout 30s docker wait "$name") || {
        docker logs "$name" >&2 || true
        printf 'container did not terminate: %s\n' "$name" >&2
        return 1
    }
    code=${code//$'\r'/}
    if [[ ! $code =~ ^[0-9]+$ ]]; then
        printf 'container returned invalid exit status: %s\n' "$code" >&2
        return 1
    fi
    printf '%s' "$code"
}

capture_logs_and_remove() {
    local name=$1
    local stdout=$2
    local stderr=$3
    docker logs "$name" >"$stdout" 2>"$stderr"
    docker rm "$name" >/dev/null
}

write_status_from_code() {
    local code=$1
    local output=$2
    if ((code >= 129 && code <= 192)); then
        printf 'signal\t%d\n' "$((code - 128))" >"$output"
    else
        printf 'code\t%d\n' "$code" >"$output"
    fi
}

wait_for_progress_four() {
    local name=$1
    local events=$2
    local attempt
    for attempt in $(seq 1 400); do
        if [[ -f $events ]] && grep -q $'^RETURN\t4\t' "$events"; then
            return 0
        fi
        if [[ $(docker inspect --format '{{.State.Running}}' "$name") != true ]]; then
            docker logs "$name" >&2 || true
            printf 'container exited before progress four: %s\n' "$name" >&2
            return 1
        fi
        sleep 0.025
    done
    printf 'timed out waiting for progress four: %s\n' "$name" >&2
    return 1
}

wait_for_destination_gate() {
    local name=$1
    local events=$2
    local attempt
    for attempt in $(seq 1 400); do
        if [[ -f $events ]] && grep -Fxq $'CALL\t5\t0' "$events"; then
            if grep -q $'^RETURN\t5\t' "$events"; then
                printf 'destination passed the resume gate before canonical RESUME: %s\n' \
                    "$name" >&2
                return 1
            fi
            return 0
        fi
        if [[ $(docker inspect --format '{{.State.Running}}' "$name") != true ]]; then
            docker logs "$name" >&2 || true
            printf 'destination exited before reaching the resume gate: %s\n' "$name" >&2
            return 1
        fi
        sleep 0.025
    done
    printf 'timed out waiting for destination resume gate: %s\n' "$name" >&2
    return 1
}

write_endpoint_config() {
    local directory=$1
    local role=$2
    local route=$3
    local case_name=$4
    local cell_id=$5
    local initial=$6
    local config="$directory/$role-config.json"
    local workload
    case "$case_name" in
        read-write-offset) workload=regular_file_workload.wat ;;
        append-continuity) workload=append_continuity_workload.wat ;;
        *) return 1 ;;
    esac
    install -m 0644 "$artifact_root/build/$workload" "$directory/workload.wat"
    python3 - "$config" "$role" "$route" "$case_name" "$cell_id" "$initial" <<'PY'
import json
import os
import sys
from pathlib import Path

output, role, route, workload, cell_id, initial = sys.argv[1:]
value = {
    "schema": "visa-wanco-canonical-endpoint-config-v1",
    "cell_id": cell_id,
    "route": route,
    "workload": workload,
    "database": f"{role}-provider.sqlite",
    "file_root": f"{role}-root",
    "component_input": "workload.wat",
    "session_id": f"{cell_id}-regular-file-session",
}
if role == "source":
    value["initial_content"] = list(initial.encode("ascii"))
path = Path(output)
temporary = path.with_suffix(".tmp")
temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(temporary, path)
PY
}

last_service_pid=
start_source_service() {
    local directory=$1
    local route=$2
    local case_name=$3
    local cell_id=$4
    local transfer=$5
    write_endpoint_config "$directory" source "$route" "$case_name" "$cell_id" \
        "$(case_initial "$case_name")"
    (
        cd "$directory"
        "$producer" canonical-source source-config.json endpoint.sock "$transfer" \
            source-receipt.json >source-service.stdout 2>source-service.stderr
    ) &
    last_service_pid=$!
    live_services["$last_service_pid"]=1
    wait_for_service_socket "$directory/endpoint.sock" "$last_service_pid" source
}

start_destination_service() {
    local directory=$1
    local route=$2
    local case_name=$3
    local cell_id=$4
    write_endpoint_config "$directory" destination "$route" "$case_name" "$cell_id" -
    (
        cd "$directory"
        "$producer" canonical-destination destination-config.json transfer.json endpoint.sock \
            destination-receipt.json >destination-service.stdout \
            2>destination-service.stderr
    ) &
    last_service_pid=$!
    live_services["$last_service_pid"]=1
    wait_for_service_socket "$directory/endpoint.sock" "$last_service_pid" destination
}

wait_for_service_socket() {
    local socket=$1
    local pid=$2
    local label=$3
    local attempt
    for attempt in $(seq 1 400); do
        if [[ -S $socket ]]; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            wait_service_success "$pid" "$label endpoint"
            printf '%s endpoint exited before publishing its Unix socket\n' "$label" >&2
            return 1
        fi
        sleep 0.025
    done
    printf 'timed out waiting for %s endpoint socket: %s\n' "$label" "$socket" >&2
    return 1
}

wait_service_success() {
    local pid=$1
    local label=$2
    local code=0
    wait "$pid" || code=$?
    unset 'live_services[$pid]'
    if ((code != 0)); then
        printf '%s failed with status %s\n' "$label" "$code" >&2
        return 1
    fi
}

canonical_control() {
    local directory=$1
    local command=$2
    (
        cd "$directory"
        "$producer" canonical-control endpoint.sock "$command"
    ) >>"$directory/canonical-control.log"
}

verify_transfer_portability() {
    local directory=$1
    python3 - "$directory/transfer.json" "$directory" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
execution_root = str(Path(sys.argv[2]).resolve())
value = json.loads(path.read_text(encoding="utf-8"))
forbidden_keys = {"device", "inode", "root_path", "file_device", "file_inode"}

def walk(node):
    if isinstance(node, dict):
        assert not (set(node) & forbidden_keys), set(node) & forbidden_keys
        for nested in node.values():
            walk(nested)
    elif isinstance(node, list):
        for nested in node:
            walk(nested)
    elif isinstance(node, str):
        assert not node.startswith("/"), node
        assert execution_root not in node, node

walk(value)
assert "source-root" not in path.read_text(encoding="utf-8")
assert "destination-root" not in path.read_text(encoding="utf-8")
PY
}

verify_fresh_destination() {
    local directory=$1
    python3 - "$directory/source-receipt.json" \
        "$directory/destination-receipt.json" "$directory" <<'PY'
import json
import sys
from pathlib import Path

source = json.load(open(sys.argv[1], encoding="utf-8"))["native_object"]
destination = json.load(open(sys.argv[2], encoding="utf-8"))["native_object"]
root = Path(sys.argv[3]).resolve()
assert source["root_path"] == str(root / "source-root"), source
assert destination["root_path"] == str(root / "destination-root"), destination
assert (source["root_device"], source["root_inode"]) != (
    destination["root_device"], destination["root_inode"]
)
assert (source["file_device"], source["file_inode"]) != (
    destination["file_device"], destination["file_inode"]
)
PY
    test -s "$directory/source-provider.sqlite"
    test -s "$directory/destination-provider.sqlite"
}

record_case() {
    local route=$1
    local case_name=$2
    local directory=$3
    local destination_events=$4
    local destination_stdout=$5
    local destination_status=$6
    local source_receipt=$7
    local destination_receipt=$8
    local subject_file=$9
    local checkpoint=${10}
    "$producer" record "$route" "$artifact_root" "$case_name" \
        "$directory/source.events" "$destination_events" \
        "$directory/source.stdout" "$destination_stdout" \
        "$directory/source.status" "$destination_status" \
        "$source_receipt" "$destination_receipt" "$subject_file" "$checkpoint" \
        "$directory/observation.json"
}

write_progress_receipt() {
    local route=$1
    local source_events=$2
    local destination_events=$3
    local output=$4
    python3 - "$route" "$source_events" "$destination_events" "$output" <<'PY'
import json
import os
import sys
from pathlib import Path

route, source_path, destination_path, output = sys.argv[1:]

def calls(path):
    values = []
    starts = []
    if path == "-":
        return values, starts
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if fields[0] == "CALL":
            values.append(int(fields[1]))
            starts.append(int(fields[2]))
    return values, starts

source, source_starts = calls(source_path)
destination, destination_starts = calls(destination_path)
if route == "uninterrupted":
    assert source == list(range(13)) and source_starts.count(1) == 1
    resumed = None
else:
    assert route in {"carrier-only", "visa-plus-carrier"}
    assert source == list(range(5)) and destination == list(range(5, 13))
    assert destination[0] > source[-1]
    assert source + destination == list(range(13))
    assert source_starts.count(1) == 1 and destination_starts.count(1) == 0
    resumed = True
receipt = {
    "schema": "visa-wanco-compute-progress-receipt-v1",
    "route": route,
    "source_progress": source,
    "destination_progress": destination,
    "destination_resumed_checkpoint": resumed,
    "logical_progress": source + destination,
}
path = Path(output)
temporary = path.with_suffix(".tmp")
temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(temporary, path)
PY
}

run_control_case() {
    local directory=$1
    local case_name=$2
    local name=$3
    local cell_id=$4
    mkdir -p "$directory"
    start_source_service "$directory" uninterrupted "$case_name" "$cell_id" -
    local source_service=$last_service_pid
    launch_container "$name" "$directory" "$case_name" source.events \
        source endpoint.sock -
    local code
    code=$(wait_container "$name")
    capture_logs_and_remove "$name" "$directory/source.stdout" "$directory/source.stderr"
    write_status_from_code "$code" "$directory/source.status"
    if ((code != 0)); then
        printf 'uninterrupted control failed with status %s\n' "$code" >&2
        return 1
    fi
    canonical_control "$directory" SHUTDOWN
    wait_service_success "$source_service" "uninterrupted source endpoint"
    test -s "$directory/source-receipt.json"
    write_progress_receipt uninterrupted "$directory/source.events" - \
        "$directory/progress-receipt.json"
    record_case uninterrupted "$case_name" "$directory" - - - \
        "$directory/source-receipt.json" - "$directory/source-root/data.bin" -
}

run_carrier_case() {
    local route=$1
    local directory=$2
    local case_name=$3
    local prefix=$4
    local cell_id=$5
    mkdir -p "$directory"
    local transfer=-
    [[ $route == visa-plus-carrier ]] && transfer=transfer.json
    start_source_service "$directory" "$route" "$case_name" "$cell_id" "$transfer"
    local source_service=$last_service_pid
    local source_name="${prefix}-source"
    launch_container "$source_name" "$directory" "$case_name" source.events \
        source endpoint.sock -
    wait_for_progress_four "$source_name" "$directory/source.events"
    if [[ $route == visa-plus-carrier ]]; then
        canonical_control "$directory" SAFE_POINT
    fi
    docker kill --signal USR1 "$source_name" >/dev/null
    local source_code
    source_code=$(wait_container "$source_name")
    capture_logs_and_remove "$source_name" "$directory/source.stdout" "$directory/source.stderr"
    write_status_from_code "$source_code" "$directory/source.status"
    if ((source_code != 0)) || [[ ! -s $directory/checkpoint.pb ]]; then
        printf 'Wanco capture failed for %s/%s (status %s)\n' \
            "$route" "$case_name" "$source_code" >&2
        return 1
    fi
    if [[ $route == visa-plus-carrier ]]; then
        canonical_control "$directory" EXPORT
        wait_service_success "$source_service" "canonical source export"
        test -s "$directory/transfer.json"
        test -s "$directory/source-receipt.json"
        verify_transfer_portability "$directory"
    else
        canonical_control "$directory" SHUTDOWN
        wait_service_success "$source_service" "carrier-only source endpoint"
        test -s "$directory/source-receipt.json"
    fi

    local destination_name="${prefix}-destination"
    local destination_receipt=-
    local final_subject="$directory/source-root/data.bin"
    if [[ $route == visa-plus-carrier ]]; then
        start_destination_service "$directory" "$route" "$case_name" "$cell_id"
        local destination_service=$last_service_pid
        launch_container "$destination_name" "$directory" "$case_name" destination.events \
            destination endpoint.sock resume.gate --restore /work/checkpoint.pb
        wait_for_destination_gate "$destination_name" "$directory/destination.events"
        canonical_control "$directory" RESUME
        : >"$directory/resume.gate"
        destination_receipt="$directory/destination-receipt.json"
        final_subject="$directory/destination-root/data.bin"
    else
        launch_container "$destination_name" "$directory" "$case_name" destination.events \
            - - - --restore /work/checkpoint.pb
    fi
    local destination_code
    destination_code=$(wait_container "$destination_name")
    capture_logs_and_remove "$destination_name" \
        "$directory/destination.stdout" "$directory/destination.stderr"
    write_status_from_code "$destination_code" "$directory/destination.status"
    if ((destination_code != 0)); then
        printf 'Wanco restore failed for %s/%s with status %s\n' \
            "$route" "$case_name" "$destination_code" >&2
        return 1
    fi
    if [[ $route == visa-plus-carrier ]]; then
        canonical_control "$directory" SHUTDOWN
        wait_service_success "$destination_service" "canonical destination endpoint"
        test -s "$destination_receipt"
        verify_fresh_destination "$directory"
    fi
    write_progress_receipt "$route" "$directory/source.events" \
        "$directory/destination.events" "$directory/progress-receipt.json"
    record_case "$route" "$case_name" "$directory" \
        "$directory/destination.events" "$directory/destination.stdout" \
        "$directory/destination.status" "$directory/source-receipt.json" \
        "$destination_receipt" "$final_subject" "$directory/checkpoint.pb"
}

evaluate_pair() {
    local control=$1
    local candidate=$2
    local report=$3
    local expected=$4
    local route=$5
    local oracle_exit=0
    "$oracle" --carrier-probe "$route" "$artifact_root" "$wanco_revision" \
        "$control" "$candidate" >"$report" || oracle_exit=$?
    python3 - "$report" "$expected" "$oracle_exit" "$route" <<'PY'
import json
import sys
from collections import Counter

report, expected, oracle_exit, route = sys.argv[1:]
value = json.load(open(report, encoding="utf-8"))
accepted = value.get("accepted") is True
assert int(oracle_exit) in {0, 1}, (report, oracle_exit)
assert accepted == (expected == "accepted"), (report, value.get("findings"))
assert (int(oracle_exit) == 0) == accepted, (report, oracle_exit, accepted)
assert (route, expected) in {
    ("carrier-only", "rejected"),
    ("visa-plus-carrier", "accepted"),
}, (report, route, expected)
case_ids = frozenset({"read-write-offset", "append-continuity"})

def exact_cases(cases, label):
    assert isinstance(cases, list) and len(cases) == len(case_ids), (
        report, label, cases
    )
    by_id = {case["case_id"]: case for case in cases}
    assert len(by_id) == len(cases) and frozenset(by_id) == case_ids, (
        report, label, cases
    )
    return by_id

equivalence_cases = exact_cases(value["cases"], "equivalence cases")
control_cases = exact_cases(
    value["control_validation"]["cases"], "control validation cases"
)
candidate_cases = exact_cases(
    value["candidate_validation"]["cases"], "candidate validation cases"
)
assert value["control_validation"]["accepted"] is True
assert not value["control_validation"]["findings"], (
    report, value["control_validation"]["findings"]
)
assert all(case["accepted"] is True and case["projection"] is not None
           for case in control_cases.values()), (report, control_cases)

if expected == "accepted":
    assert value["candidate_validation"]["accepted"] is True
    assert not value["candidate_validation"]["findings"], (
        report, value["candidate_validation"]["findings"]
    )
    assert all(case["accepted"] is True and case["projection"] is not None
               for case in candidate_cases.values()), (report, candidate_cases)
    assert not value["findings"]
    assert all(case["equivalent"] is True and
               case["control_projection"] is not None and
               case["candidate_projection"] is not None
               for case in equivalence_cases.values()), (
        report, equivalence_cases
    )
elif route == "carrier-only":
    assert value["candidate_validation"]["accepted"] is False
    assert all(case["accepted"] is False and case["projection"] is not None
               for case in candidate_cases.values()), (report, candidate_cases)
    assert all(case["equivalent"] is False and
               case["control_projection"] is not None and
               case["candidate_projection"] is not None
               for case in equivalence_cases.values()), (
        report, equivalence_cases
    )

    expected_outer_findings = Counter(
        (case_id, "observable-projection-mismatch") for case_id in case_ids
    )
    observed_outer_findings = Counter(
        (finding.get("case_id"), finding.get("code"))
        for finding in value["findings"]
    )
    assert observed_outer_findings == expected_outer_findings, (
        report, observed_outer_findings
    )

    carrier_semantic_triplet = frozenset({
        "invalid-committed-handoff-lifecycle",
        "semantic-assertion-failed",
        "unexpected-derived-terminal",
    })
    expected_candidate_findings = Counter(
        (case_id, code)
        for case_id in case_ids
        for code in carrier_semantic_triplet
    )
    observed_candidate_findings = Counter(
        (finding.get("case_id"), finding.get("code"))
        for finding in value["candidate_validation"]["findings"]
    )
    assert observed_candidate_findings == expected_candidate_findings, (
        report, observed_candidate_findings
    )
PY
}

routes=(carrier-only visa-plus-carrier)
cases=(read-write-offset append-continuity)
for run in $(seq 1 "$runs"); do
    run_name=$(printf 'run-%02d' "$run")
    shared_control="$artifact_root/$run_name/control"
    mkdir -p "$shared_control"
    for case_name in "${cases[@]}"; do
        prefix="visa-wc-${run}-control-${case_name//-/}-$$"
        cell_id="wanco-${run_name}-${case_name}"
        run_control_case "$shared_control/$case_name" "$case_name" "$prefix" "$cell_id"
    done
    "$producer" merge-probe \
        "$shared_control/read-write-offset/observation.json" \
        "$shared_control/append-continuity/observation.json" \
        "$artifact_root/$run_name/control.json"
    for route in "${routes[@]}"; do
        pair="$artifact_root/$run_name/$route"
        mkdir -p "$pair/candidate"
        for case_name in "${cases[@]}"; do
            prefix="visa-wc-${run}-${route//-/}-${case_name//-/}-$$"
            cell_id="wanco-${run_name}-${case_name}"
            run_carrier_case "$route" "$pair/candidate/$case_name" "$case_name" "$prefix" \
                "$cell_id"
        done
        "$producer" merge-probe \
            "$pair/candidate/read-write-offset/observation.json" \
            "$pair/candidate/append-continuity/observation.json" \
            "$pair/candidate.json"
        expectation=rejected
        [[ $route == visa-plus-carrier ]] && expectation=accepted
        evaluate_pair "$artifact_root/$run_name/control.json" "$pair/candidate.json" \
            "$pair/oracle-report.json" "$expectation" "$route"
    done
done

seal_checkout

python3 - "$artifact_root" "$runs" "$producer_sha" "$oracle_sha" "$image_tag" "$image_id" \
    "$git_sha" "$git_dirty" "$matrix_sha" <<'PY'
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
runs = int(sys.argv[2])
producer_sha, oracle_sha, image_tag, image_id, git_sha, git_dirty, matrix_sha = sys.argv[3:]
results = []
for run in range(1, runs + 1):
    for route in ("carrier-only", "visa-plus-carrier"):
        path = root / f"run-{run:02d}" / route / "oracle-report.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        results.append({
            "run": run,
            "route": route,
            "accepted": report["accepted"],
            "report": str(path.relative_to(root)),
            "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
assert len(results) == runs * 2
assert all(not item["accepted"] for item in results if item["route"] == "carrier-only")
assert all(item["accepted"] for item in results if item["route"] == "visa-plus-carrier")
receipt = {
    "schema": "visa-wanco-carrier-matrix-receipt-v1",
    "git_sha": git_sha,
    "git_dirty": git_dirty == "true",
    "evidence_matrix_sha256": matrix_sha,
    "runs_per_route_case": runs,
    "case_registry": ["read-write-offset", "append-continuity"],
    "required_expectations": {
        "carrier-only": "rejected",
        "visa-plus-carrier": "accepted",
    },
    "all_required_runs_agree": True,
    "producer_sha256": producer_sha,
    "standalone_oracle_sha256": oracle_sha,
    "wanco_image_tag": image_tag,
    "wanco_image_id": image_id,
    "relocation_verification_required": True,
    "results": results,
}
output = root / "matrix-receipt.json"
temporary = output.with_suffix(".tmp")
temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(temporary, output)
PY

original_root=$artifact_root
relocated_root="${artifact_root}-relocated"
if [[ -e $relocated_root ]]; then
    printf 'refusing to replace relocation target: %s\n' "$relocated_root" >&2
    exit 1
fi
mv -- "$original_root" "$relocated_root"
artifact_root=$relocated_root
mkdir -p "$artifact_root/relocation"
for run in $(seq 1 "$runs"); do
    run_name=$(printf 'run-%02d' "$run")
    for route in carrier-only visa-plus-carrier; do
        pair="$artifact_root/$run_name/$route"
        report="$artifact_root/relocation/${run_name}-${route}-oracle-report.json"
        expectation=rejected
        [[ $route == visa-plus-carrier ]] && expectation=accepted
        evaluate_pair "$artifact_root/$run_name/control.json" "$pair/candidate.json" \
            "$report" "$expectation" "$route"
    done
done

python3 - "$artifact_root" "$original_root" "$runs" "$oracle_sha" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
original_root = Path(sys.argv[2])
runs = int(sys.argv[3])
oracle_sha = sys.argv[4]
assert not original_root.exists()

def references(value):
    found = []
    if isinstance(value, dict):
        if {"uri", "sha256", "size"} <= set(value):
            found.append((value["uri"], value["sha256"], value["size"]))
        for nested in value.values():
            found.extend(references(nested))
    elif isinstance(value, list):
        for nested in value:
            found.extend(references(nested))
    return found

artifact_references = []
results = []
for run in range(1, runs + 1):
    run_name = f"run-{run:02d}"
    for route in ("carrier-only", "visa-plus-carrier"):
        candidate = root / run_name / route / "candidate.json"
        for uri, expected_sha, expected_size in references(
            json.loads(candidate.read_text(encoding="utf-8"))
        ):
            path = (root / uri).resolve(strict=True)
            path.relative_to(root)
            payload = path.read_bytes()
            assert len(payload) == expected_size
            assert hashlib.sha256(payload).hexdigest() == expected_sha
            artifact_references.append(uri)
        report_path = root / "relocation" / f"{run_name}-{route}-oracle-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        expected = route == "visa-plus-carrier"
        assert report["accepted"] is expected
        results.append({
            "run": run,
            "route": route,
            "accepted": report["accepted"],
            "report": str(report_path.relative_to(root)),
            "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        })

expected_references = runs * 2 * 2 * 2
assert len(artifact_references) == expected_references, (
    len(artifact_references), expected_references
)
receipt = {
    "schema": "visa-wanco-carrier-relocation-receipt-v1",
    "original_root_name": original_root.name,
    "relocated_root_name": root.name,
    "original_root_absent_after_move": True,
    "standalone_oracle_sha256": oracle_sha,
    "required_pairs_reverified": len(results),
    "artifact_references_verified": len(artifact_references),
    "all_required_runs_agree_after_relocation": True,
    "results": results,
}
output = root / "relocation-receipt.json"
temporary = output.with_suffix(".tmp")
temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(temporary, output)
PY

seal_checkout

python3 - "$artifact_root" "$original_root" "$runs" "$producer_sha" "$oracle_sha" \
    "$image_tag" "$image_id" "$matrix_sha" "$git_sha" "$git_dirty" \
    "$started_at_unix_ms" "$wanco_revision" "$repo_root/claims/evidence-matrix.json" <<'PY'
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path

(
    root_arg,
    original_root_arg,
    runs_arg,
    producer_sha,
    oracle_sha,
    image_tag,
    image_id,
    matrix_sha,
    git_sha,
    git_dirty_arg,
    started_at_arg,
    wanco_revision,
    matrix_path_arg,
) = sys.argv[1:]
root = Path(root_arg).resolve(strict=True)
original_root = Path(original_root_arg)
runs = int(runs_arg)
git_dirty = git_dirty_arg == "true"
started_at = int(started_at_arg)
matrix_path = Path(matrix_path_arg)
matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
claim_id = "bounded-wanco-regular-file-carrier-composition-v1"
route_cells = (
    ("carrier-only", "wanco.carrier-only.regular-file", False),
    ("visa-plus-carrier", "wanco.visa-plus-carrier.regular-file", True),
)
cells = {cell["id"]: cell for cell in matrix["cells"]}


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def artifact_reference(path):
    resolved = path.resolve(strict=True)
    resolved.relative_to(root)
    assert resolved.is_file() and not resolved.is_symlink(), resolved
    payload = resolved.read_bytes()
    assert payload, resolved
    return {
        "uri": resolved.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def observation_artifact_references(value):
    found = []
    if isinstance(value, dict):
        if set(value) == {"uri", "sha256", "size"}:
            found.append(value)
        for nested in value.values():
            found.extend(observation_artifact_references(nested))
    elif isinstance(value, list):
        for nested in value:
            found.extend(observation_artifact_references(nested))
    return found


def verify_expected_report(report, route, expected_accepted):
    case_ids = {"read-write-offset", "append-continuity"}
    assert report["accepted"] is expected_accepted
    assert {case["case_id"] for case in report["cases"]} == case_ids
    assert report["control_validation"]["accepted"] is True
    assert all(case["control_projection"] is not None for case in report["cases"])
    assert all(case["candidate_projection"] is not None for case in report["cases"])
    if expected_accepted:
        assert not report["findings"]
        assert report["candidate_validation"]["accepted"] is True
        assert all(case["equivalent"] is True for case in report["cases"])
    else:
        assert route == "carrier-only"
        assert all(case["equivalent"] is False for case in report["cases"])
        assert len(report["findings"]) == len(case_ids)
        assert {finding["case_id"] for finding in report["findings"]} == case_ids
        assert all(
            finding["code"] == "observable-projection-mismatch"
            for finding in report["findings"]
        )


receipts = []
for route, cell_id, expected_accepted in route_cells:
    cell = cells[cell_id]
    assert cell["claim_ids"] == [claim_id]
    coordinates = {
        key: cell[key]
        for key in (
            "source",
            "destination",
            "resource_profile",
            "handoff_topology",
            "fault_model",
            "verifier",
        )
    }
    for run in range(1, runs + 1):
        run_name = f"run-{run:02d}"
        pair = root / run_name / route
        report_path = root / "relocation" / f"{run_name}-{route}-oracle-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        verify_expected_report(report, route, expected_accepted)

        candidate_path = pair / "candidate.json"
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        checkpoint_references = {}
        for recorded in observation_artifact_references(candidate):
            actual = artifact_reference(root / recorded["uri"])
            assert actual == recorded, (recorded, actual)
            checkpoint_references[actual["uri"]] = actual

        evidence_path = pair / "canonical-evidence-bundle.json"
        control_root = root / run_name / "control"
        control_observation = root / run_name / "control.json"
        candidate_root = pair / "candidate"
        source_receipts = [
            candidate_root / case / "source-receipt.json"
            for case in ("read-write-offset", "append-continuity")
        ]
        destination_receipts = [
            candidate_root / case / "destination-receipt.json"
            for case in ("read-write-offset", "append-continuity")
            if (candidate_root / case / "destination-receipt.json").exists()
        ]
        transfer_artifacts = [
            candidate_root / case / "transfer.json"
            for case in ("read-write-offset", "append-continuity")
            if (candidate_root / case / "transfer.json").exists()
        ]
        evidence = {
            "schema": "visa-wanco-carrier-paired-evidence-v1",
            "cell_id": cell_id,
            "run_ordinal": run,
            "expected_oracle_outcome": "accepted" if expected_accepted else "rejected",
            "control_observation": artifact_reference(control_observation),
            "candidate_observation": artifact_reference(candidate_path),
            "control_progress_receipts": [
                artifact_reference(control_root / case / "progress-receipt.json")
                for case in ("read-write-offset", "append-continuity")
            ],
            "candidate_progress_receipts": [
                artifact_reference(pair / "candidate" / case / "progress-receipt.json")
                for case in ("read-write-offset", "append-continuity")
            ],
            "checkpoint_artifacts": [
                checkpoint_references[uri] for uri in sorted(checkpoint_references)
            ],
            "control_canonical_receipts": [
                artifact_reference(control_root / case / "source-receipt.json")
                for case in ("read-write-offset", "append-continuity")
            ],
            "candidate_source_canonical_receipts": [
                artifact_reference(path) for path in source_receipts
            ],
            "candidate_destination_canonical_receipts": [
                artifact_reference(path) for path in destination_receipts
            ],
            "canonical_transfers": [artifact_reference(path) for path in transfer_artifacts],
        }
        assert len(evidence["checkpoint_artifacts"]) == 2
        assert len(evidence["control_canonical_receipts"]) == 2
        assert len(evidence["candidate_source_canonical_receipts"]) == 2
        assert len(evidence["candidate_destination_canonical_receipts"]) == (
            2 if expected_accepted else 0
        )
        assert len(evidence["canonical_transfers"]) == (2 if expected_accepted else 0)
        write_json(evidence_path, evidence)

        environment_path = pair / "canonical-environment.json"
        environment = {
            "schema": "visa-wanco-carrier-environment-v1",
            "cell_id": cell_id,
            "run_ordinal": run,
            "coordinates": coordinates,
            "git_sha": git_sha,
            "git_dirty": git_dirty,
            "host": {
                "operating_system": platform.system().lower(),
                "isa": platform.machine(),
                "kernel_release": platform.release(),
            },
            "wanco": {
                "repository": "https://github.com/tamaroning/wanco.git",
                "revision": wanco_revision,
                "image_tag": image_tag,
                "image_id": image_id,
            },
            "container_security": {
                "docker_process_label": "disabled",
                "reason": "same-host canonical Unix-socket peer",
                "privileged": False,
                "host_network": False,
            },
            "producer_sha256": producer_sha,
            "standalone_oracle_sha256": oracle_sha,
            "relocation": {
                "original_root_name": original_root.name,
                "publication_root_name": root.name,
                "original_root_absent": not original_root.exists(),
            },
        }
        assert environment["host"]["operating_system"] == "linux"
        assert environment["host"]["isa"] == "x86_64"
        assert environment["relocation"]["original_root_absent"] is True
        write_json(environment_path, environment)

        receipts.append({
            "cell_id": cell_id,
            "run_ordinal": run,
            "coordinates": coordinates,
            "evidence_bundle": artifact_reference(evidence_path),
            "validation_report": artifact_reference(report_path),
            "environment": artifact_reference(environment_path),
            "verifier_identity": {
                "name": "visa-regular-file-oracle",
                "version": "regular-file-equivalence-oracle-report-v2",
                "executable_sha256": oracle_sha,
            },
            "expected_semantic_outcome": (
                "accepted" if expected_accepted else "rejected"
            ),
            "observed_semantic_outcome": (
                "accepted" if report["accepted"] else "rejected"
            ),
            "relocated_verification": True,
        })

receipts.sort(key=lambda receipt: (receipt["cell_id"], receipt["run_ordinal"]))
run = {
    "schema_version": "visa.evidence-matrix-run.v1",
    "matrix_sha256": matrix_sha,
    "git_sha": git_sha,
    "git_dirty": git_dirty,
    "run_id": f"wanco-carrier-{git_sha[:12]}-{started_at}",
    "started_at_unix_ms": started_at,
    "finished_at_unix_ms": int(time.time() * 1000),
    "claim_ids": [claim_id],
    "receipts": receipts,
}
run_path = root / "evidence-matrix-run.json"
write_json(run_path, run)

matrix_receipt_path = root / "matrix-receipt.json"
matrix_receipt = json.loads(matrix_receipt_path.read_text(encoding="utf-8"))
matrix_receipt["canonical_evidence_matrix_run"] = artifact_reference(run_path)
write_json(matrix_receipt_path, matrix_receipt)

relocation_receipt_path = root / "relocation-receipt.json"
relocation_receipt = json.loads(relocation_receipt_path.read_text(encoding="utf-8"))
relocation_receipt["canonical_evidence_matrix_run"] = artifact_reference(run_path)
write_json(relocation_receipt_path, relocation_receipt)
PY

"$matrix_validator" claims/evidence-matrix.json "$artifact_root/evidence-matrix-run.json" \
    "$artifact_root"
seal_checkout

trap - EXIT INT TERM
printf 'Wanco publication root: %s\n' "$artifact_root"
printf 'Required summary: carrier-only %d/%d expected rejections; visa-plus-carrier %d/%d acceptances\n' \
    "$runs" "$runs" "$runs" "$runs"
printf 'Wanco carrier matrix receipt: %s\n' "$artifact_root/matrix-receipt.json"
printf 'Canonical evidence matrix run: %s\n' "$artifact_root/evidence-matrix-run.json"
