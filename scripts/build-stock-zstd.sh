#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [[ $(uname -m) != x86_64 ]]; then
    printf '%s\n' 'the current stock-zstd Wanco carrier build requires x86_64' >&2
    exit 1
fi
if [[ -n ${VISA_ZSTD_WANCO_OPTIMIZATION:-} ]]; then
    printf '%s\n' \
        'VISA_ZSTD_WANCO_OPTIMIZATION is forbidden: use the exact source-locked carrier optimization' >&2
    exit 1
fi
jobs=${VISA_STOCK_ZSTD_JOBS:-2}
if [[ ! $jobs =~ ^[1-9][0-9]*$ ]] || ((jobs > 64)); then
    printf '%s\n' 'VISA_STOCK_ZSTD_JOBS must be an integer from 1 through 64' >&2
    exit 1
fi

read_lock() {
    python3 - "$1" <<'PY'
import json
import sys

with open("third_party/zstd/source-lock.json", encoding="utf-8") as source:
    value = json.load(source)
for component in sys.argv[1].split("."):
    if isinstance(value, list):
        value = value[int(component)]
    else:
        value = value[component]
if not isinstance(value, (str, int)):
    raise SystemExit(f"source-lock path is not scalar: {sys.argv[1]}")
print(value)
PY
}

python3 scripts/check-zstd-source.py

revision=$(read_lock upstream.revision)
zstd_tag=$(read_lock upstream.tag)
source_date_epoch=$(read_lock upstream.source_date_epoch)
wasi_libc_version=$(read_lock wasi_build.packages.0.version)
wasi_libc_sha=$(read_lock wasi_build.packages.0.sha256)
clang_rt_version=$(read_lock wasi_build.packages.1.version)
clang_rt_sha=$(read_lock wasi_build.packages.1.sha256)
expected_compiler_sha=$(read_lock carrier_build.wanco_compiler_sha256)
expected_runtime_sha=$(read_lock carrier_build.wanco_runtime_sha256)
expected_wanco_revision=$(read_lock carrier_build.wanco_revision)
carrier_optimization=$(read_lock carrier_build.optimization)
carrier_qualification=$(read_lock carrier_build.qualification)
carrier_o1_status=$(read_lock carrier_build.o1_status.status)
bridge_rust_toolchain=$(
    python3 - <<'PY'
import json

with open("third_party/wanco/source-lock.json", encoding="utf-8") as source:
    print(json.load(source)["build"]["rust_toolchain"])
PY
)
case "$carrier_optimization" in
    -O0)
        carrier_suffix=o0
        carrier_o1_qualified=false
        ;;
    -O1)
        carrier_suffix=o1
        if [[ $carrier_o1_status != qualified ]]; then
            printf 'source lock selects Wanco -O1 without a qualified O1 status: %s\n' \
                "$carrier_o1_status" >&2
            exit 1
        fi
        carrier_o1_qualified=true
        ;;
    *)
        printf 'unsupported source-locked Wanco optimization: %s\n' \
            "$carrier_optimization" >&2
        exit 1
        ;;
esac
lock_sha=$(sha256sum third_party/zstd/source-lock.json | cut -d' ' -f1)
cache_root="$repo_root/target/.ci-cache/stock-zstd"
mkdir -p "$cache_root"

wanco_receipt="$repo_root/target/.ci-cache/wanco-carrier/build-receipt.json"
expected_patch_set=$(
    python3 - <<'PY'
import hashlib
import json

with open("third_party/wanco/source-lock.json", encoding="utf-8") as source:
    patches = json.load(source)["patches"]
print(hashlib.sha256("".join(item["sha256"] for item in patches).encode()).hexdigest())
PY
)
reuse_wanco=false
if [[ -f $wanco_receipt ]]; then
    read -r candidate_schema candidate_image candidate_revision candidate_patch_set < <(
        python3 - "$wanco_receipt" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    receipt = json.load(source)
print(
    receipt.get("schema", ""),
    receipt.get("image_tag", ""),
    receipt.get("revision", ""),
    receipt.get("patch_set_sha256", ""),
)
PY
    )
    if [[ $candidate_schema == visa-wanco-carrier-build-receipt-v5 &&
        -n $candidate_image &&
        $candidate_revision == "$expected_wanco_revision" &&
        $candidate_patch_set == "$expected_patch_set" ]] &&
        docker image inspect "$candidate_image" >/dev/null 2>&1
    then
        reuse_wanco=true
    fi
fi
if [[ $reuse_wanco != true ]]; then
    scripts/build-wanco-carrier.sh
fi
wanco_image=$(python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["image_tag"])' \
    "$wanco_receipt")
wanco_image_id=$(docker image inspect --format '{{.Id}}' "$wanco_image")
wanco_revision=$(python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["revision"])' \
    "$wanco_receipt")
if [[ $wanco_revision != "$expected_wanco_revision" ]]; then
    printf 'Wanco build revision differs from the stock-zstd lock: %s != %s\n' \
        "$wanco_revision" "$expected_wanco_revision" >&2
    exit 1
fi
read -r actual_compiler_sha actual_runtime_sha < <(
    docker run --rm "$wanco_image" sh -ec \
        'printf "%s %s\n" "$(sha256sum /usr/local/bin/wanco | cut -d" " -f1)" "$(sha256sum /usr/local/lib/libwanco_rt.a | cut -d" " -f1)"'
)
if [[ $actual_compiler_sha != "$expected_compiler_sha" ]]; then
    printf 'Wanco compiler digest differs from the stock-zstd lock: %s != %s\n' \
        "$actual_compiler_sha" "$expected_compiler_sha" >&2
    exit 1
fi
if [[ $actual_runtime_sha != "$expected_runtime_sha" ]]; then
    printf 'Wanco runtime digest differs from the stock-zstd lock: %s != %s\n' \
        "$actual_runtime_sha" "$expected_runtime_sha" >&2
    exit 1
fi

source_cache="$repo_root/target/.ci-cache/stock-zstd/source-${revision:0:12}"
mkdir -p "$(dirname "$source_cache")"
if [[ ! -d "$source_cache/.git" ]]; then
    if [[ -e $source_cache ]]; then
        printf 'refusing non-Git stock-zstd source cache: %s\n' "$source_cache" >&2
        exit 1
    fi
    source_stage=$(mktemp -d "$(dirname "$source_cache")/.source-fetch.XXXXXXXX")
    if ! (
        git -C "$source_stage" -c init.defaultBranch=detached init
        git -C "$source_stage" remote add origin https://github.com/facebook/zstd.git
        git -C "$source_stage" -c protocol.version=2 fetch \
            --depth=1 \
            --no-tags \
            origin \
            "refs/tags/$zstd_tag:refs/tags/$zstd_tag"
        git -C "$source_stage" -c advice.detachedHead=false checkout --detach "$revision"
    ); then
        find "$source_stage" -xdev -depth -delete
        printf '%s\n' 'failed to fetch the exact stock-zstd tag' >&2
        exit 1
    fi
    mv "$source_stage" "$source_cache"
fi
python3 scripts/check-zstd-source.py --source "$source_cache"

build_image="visa-stock-zstd-build:${revision:0:12}-${lock_sha:0:12}"
docker build --progress=plain \
    --provenance=false \
    --build-arg "WANCO_BASE=$wanco_image" \
    --build-arg "WASI_LIBC_VERSION=$wasi_libc_version" \
    --build-arg "WASI_LIBC_SHA256=$wasi_libc_sha" \
    --build-arg "CLANG_RT_WASM32_VERSION=$clang_rt_version" \
    --build-arg "CLANG_RT_WASM32_SHA256=$clang_rt_sha" \
    --tag "$build_image" \
    --file third_party/zstd/Dockerfile \
    third_party/zstd
build_image_id=$(docker image inspect --format '{{.Id}}' "$build_image")
compiler_version=$(
    docker run --rm "$build_image" clang-17 --version | sed -n '1p'
)
expected_compiler_version=$(read_lock wasi_build.compiler_version)
if [[ $compiler_version != "$expected_compiler_version" ]]; then
    printf 'clang version differs from the stock-zstd lock: %s != %s\n' \
        "$compiler_version" "$expected_compiler_version" >&2
    exit 1
fi

bridge_source_sha=$(
    {
        sha256sum \
            third_party/zstd/bridge-Cargo.lock \
            third_party/zstd/bridge-workspace.toml
        find \
            crates/runtime/visa_wanco_wasi \
            crates/runtime/visa_wasi_protocol \
            -type f -print0 |
            sort -z |
            xargs -0 sha256sum
    } | sha256sum | cut -d' ' -f1
)
wanco_image_short=${wanco_image_id#sha256:}
bridge_cache="$cache_root/bridge-${bridge_source_sha:0:12}-${wanco_image_short:0:12}"
bridge="$bridge_cache/libvisa_wanco_wasi.a"
bridge_rustc_version=$(
    docker run --rm \
        --env "RUSTUP_TOOLCHAIN=$bridge_rust_toolchain" \
        "$build_image" rustc --version
)
bridge_cargo_version=$(
    docker run --rm \
        --env "RUSTUP_TOOLCHAIN=$bridge_rust_toolchain" \
        "$build_image" cargo --version
)
if [[ ! -f $bridge ]]; then
    bridge_publication="$bridge_cache.incomplete.$$"
    if [[ -e $bridge_publication ]]; then
        printf 'refusing existing incomplete bridge path: %s\n' \
            "$bridge_publication" >&2
        exit 1
    fi
    mkdir "$bridge_publication"
    docker run --rm \
        --network bridge \
        --security-opt label=disable \
        --volume "$repo_root:/repo:ro" \
        --volume "$bridge_publication:/bridge-out" \
        --workdir / \
        --env CARGO_TARGET_DIR=/cargo-target \
        --env "RUSTUP_TOOLCHAIN=$bridge_rust_toolchain" \
        --env "VISA_HOST_UID=$(id -u)" \
        --env "VISA_HOST_GID=$(id -g)" \
        --tmpfs /bridge-work:exec,size=67108864 \
        --tmpfs /cargo-target:exec,size=2147483648 \
        "$build_image" sh -ec '
            install -d /bridge-work/crates/runtime
            install -m 0644 \
                /repo/third_party/zstd/bridge-workspace.toml \
                /bridge-work/Cargo.toml
            install -m 0644 \
                /repo/third_party/zstd/bridge-Cargo.lock \
                /bridge-work/Cargo.lock
            cp -a \
                /repo/crates/runtime/visa_wasi_protocol \
                /repo/crates/runtime/visa_wanco_wasi \
                /bridge-work/crates/runtime/
            cd /bridge-work
            cargo build --release --locked -p visa_wanco_wasi
            install -m 0644 \
                /cargo-target/release/libvisa_wanco_wasi.a \
                /bridge-out/libvisa_wanco_wasi.a
            chown "$VISA_HOST_UID:$VISA_HOST_GID" \
                /bridge-out/libvisa_wanco_wasi.a
        ' || {
            find "$bridge_publication" -xdev -depth -delete
            exit 1
        }
    mv "$bridge_publication" "$bridge_cache"
fi
if [[ ! -f $bridge ]]; then
    printf 'stock-zstd Wanco bridge static library is absent: %s\n' "$bridge" >&2
    exit 1
fi
for symbol in \
    wasi_snapshot_preview1_args_get \
    wasi_snapshot_preview1_fd_read \
    wasi_snapshot_preview1_fd_write \
    wasi_snapshot_preview1_path_open \
    visa_wasi_metadata_path_chmod \
    visa_wasi_metadata_path_chown
do
    if ! nm -g --defined-only "$bridge" |
        awk -v expected="$symbol" '
            $3 == expected { found = 1 }
            END { exit found ? 0 : 1 }
        '
    then
        printf 'Wanco bridge does not define required symbol: %s\n' "$symbol" >&2
        exit 1
    fi
done
bridge_sha=$(sha256sum "$bridge" | cut -d' ' -f1)
build_recipe_sha=$(sha256sum "$repo_root/scripts/build-stock-zstd.sh" | cut -d' ' -f1)
wanco_source_lock_sha=$(sha256sum "$repo_root/third_party/wanco/source-lock.json" | cut -d' ' -f1)
wanco_receipt_sha=$(sha256sum "$wanco_receipt" | cut -d' ' -f1)

validate_carrier_abi() {
    local carrier_ir=$1
    local carrier_executable=$2
    local declaration count signature

    for candidate in "$carrier_ir" "$carrier_executable"; do
        if [[ -L $candidate || ! -f $candidate ]]; then
            printf 'stock-zstd carrier artifact is not a regular non-symlink file: %s\n' \
                "$candidate" >&2
            return 1
        fi
    done
    if grep -Eq '^declare .*@(chmod|chown)\(' "$carrier_ir"; then
        printf '%s\n' 'Wanco AOT IR retains an unsafe bare chmod/chown declaration' >&2
        return 1
    fi
    while read -r declaration signature; do
        count=$(grep -Ec "$signature" "$carrier_ir" || true)
        if [[ $count != 1 ]]; then
            printf 'Wanco AOT IR must contain exactly one collision-safe declaration for %s; found %s\n' \
                "$declaration" "$count" >&2
            return 1
        fi
        if ! nm -g --defined-only "$carrier_executable" |
            awk -v expected="$declaration" '
                $3 == expected { count += 1 }
                END { exit count == 1 ? 0 : 1 }
            '
        then
            printf 'Wanco AOT executable does not define exactly one bridge symbol: %s\n' \
                "$declaration" >&2
            return 1
        fi
    done <<'EOF'
visa_wasi_metadata_path_chmod ^declare i32 @visa_wasi_metadata_path_chmod\(ptr, i32, i32, i32, i32\)( #[0-9]+)?$
visa_wasi_metadata_path_chown ^declare i32 @visa_wasi_metadata_path_chown\(ptr, i32, i32, i32, i32, i32\)( #[0-9]+)?$
EOF
}

artifact_root=${VISA_STOCK_ZSTD_OUT:-"$repo_root/target/.ci-artifacts/stock-zstd-build"}
if [[ $artifact_root != /* ]]; then
    artifact_root="$repo_root/$artifact_root"
fi
artifact_root=$(realpath -m "$artifact_root")
if [[ $artifact_root == / || $artifact_root == "$repo_root" ]]; then
    printf 'refusing broad stock-zstd artifact path: %s\n' "$artifact_root" >&2
    exit 1
fi
if [[ -e $artifact_root ]]; then
    if [[ ! -f $artifact_root/receipt.json ]]; then
        printf 'refusing existing non-artifact stock-zstd output: %s\n' "$artifact_root" >&2
        exit 1
    fi
    python3 scripts/check-zstd-source.py --wasm "$artifact_root/zstd-v1.5.7.wasm"
    python3 - "$artifact_root" "$lock_sha" "$revision" \
        "$wanco_revision" "$carrier_optimization" "$carrier_qualification" \
        "$carrier_o1_qualified" \
        "$expected_compiler_sha" "$expected_runtime_sha" "$wanco_source_lock_sha" \
        "$wanco_receipt_sha" "$bridge_sha" "$build_recipe_sha" \
        "$wanco_image" "$wanco_image_id" "$build_image" "$build_image_id" \
        "$compiler_version" "$bridge_rustc_version" "$bridge_cargo_version" \
        "$carrier_suffix" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

(
    root,
    lock_sha,
    zstd_revision,
    wanco_revision,
    carrier_optimization,
    carrier_qualification,
    carrier_o1_qualified,
    wanco_compiler_sha,
    wanco_runtime_sha,
    wanco_source_lock_sha,
    wanco_receipt_sha,
    bridge_sha,
    build_recipe_sha,
    wanco_image,
    wanco_image_id,
    build_image,
    build_image_id,
    compiler_version,
    bridge_rustc_version,
    bridge_cargo_version,
    carrier_suffix,
) = sys.argv[1:]
root = Path(root)
receipt = json.loads((root / "receipt.json").read_text(encoding="utf-8"))
if receipt.get("schema") != "visa-stock-zstd-build-receipt-v1":
    raise SystemExit("existing stock-zstd receipt has an unknown schema")
expected_receipt = {
    "source_lock_sha256": lock_sha,
    "zstd_revision": zstd_revision,
    "zero_upstream_source_patches": True,
    "wanco_revision": wanco_revision,
    "wanco_optimization": carrier_optimization,
    "carrier_qualification": carrier_qualification,
    "wanco_o1_qualified": carrier_o1_qualified == "true",
    "wanco_compiler_sha256": wanco_compiler_sha,
    "wanco_runtime_sha256": wanco_runtime_sha,
    "wanco_source_lock_sha256": wanco_source_lock_sha,
    "wanco_build_receipt_sha256": wanco_receipt_sha,
    "bridge_sha256": bridge_sha,
    "build_recipe_sha256": build_recipe_sha,
    "wanco_image": wanco_image,
    "wanco_image_id": wanco_image_id,
    "build_image": build_image,
    "build_image_id": build_image_id,
    "compiler_version": compiler_version,
    "rustc_version": bridge_rustc_version,
    "cargo_version": bridge_cargo_version,
}
for key, expected in expected_receipt.items():
    if receipt.get(key) != expected:
        raise SystemExit(
            f"existing stock-zstd receipt field differs: "
            f"{key}={receipt.get(key)!r}, expected={expected!r}"
        )
expected_names = {
    "zstd-v1.5.7.wasm",
    f"zstd-v1.5.7-wanco-{carrier_suffix}.ll",
    f"zstd-v1.5.7-wanco-{carrier_suffix}",
}
artifacts = receipt.get("artifacts")
if not isinstance(artifacts, dict) or set(artifacts) != expected_names:
    raise SystemExit("existing stock-zstd receipt artifact set differs")
if {path.name for path in root.iterdir()} != expected_names | {"receipt.json"}:
    raise SystemExit("existing stock-zstd artifact directory contains unexpected entries")
for name, identity in artifacts.items():
    if (
        not isinstance(identity, dict)
        or set(identity) != {"sha256", "size"}
        or not isinstance(identity["size"], int)
        or identity["size"] < 0
    ):
        raise SystemExit(f"existing stock-zstd artifact identity is malformed: {name}")
    path = root / name
    stat = path.lstat()
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"existing stock-zstd artifact is not a regular file: {name}")
    if stat.st_size != identity["size"]:
        raise SystemExit(f"existing stock-zstd artifact size differs: {name}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != identity["sha256"]:
        raise SystemExit(f"existing stock-zstd artifact digest differs: {name}")
PY
    validate_carrier_abi \
        "$artifact_root/zstd-v1.5.7-wanco-$carrier_suffix.ll" \
        "$artifact_root/zstd-v1.5.7-wanco-$carrier_suffix"
    printf 'Reused verified stock-zstd artifacts: %s\n' "$artifact_root"
    exit 0
fi

work_root=$(mktemp -d "$cache_root/.build-work.XXXXXXXX")
publication="$artifact_root.incomplete.$$"
cleanup_work() {
    local resolved_cache resolved_work resolved_publication
    resolved_cache=$(realpath "$cache_root")
    if [[ -e $work_root ]]; then
        resolved_work=$(realpath "$work_root")
        case "$resolved_work" in
            "$resolved_cache"/.build-work.*)
                find "$resolved_work" -xdev -depth -delete
                ;;
            *)
                printf 'refusing to clean unexpected stock-zstd work path: %s\n' \
                    "$resolved_work" >&2
                ;;
        esac
    fi
    if [[ -e $publication ]]; then
        resolved_publication=$(realpath "$publication")
        if [[ $resolved_publication == "$artifact_root.incomplete.$$" ]]; then
            find "$resolved_publication" -xdev -depth -delete
        else
            printf 'refusing to clean unexpected incomplete publication path: %s\n' \
                "$resolved_publication" >&2
        fi
    fi
}
trap cleanup_work EXIT

mkdir -p "$work_root/source"
git -C "$source_cache" archive "$revision" | tar -x -C "$work_root/source"
host_uid=$(id -u)
host_gid=$(id -g)

docker run --rm \
    --user "$host_uid:$host_gid" \
    --volume "$work_root:/work:Z" \
    --volume "$repo_root/third_party/zstd:/visa-zstd:ro,Z" \
    --workdir /work \
    --env "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --env "VISA_STOCK_ZSTD_JOBS=$jobs" \
    "$build_image" sh -ec '
        set -eu
        clang-17 --target=wasm32-wasi --sysroot=/usr \
            -O1 -Wall -Wextra -Werror \
            -c /visa-zstd/abi/visa_zstd_posix_compat.c \
            -o /work/visa_zstd_posix_compat.o
        make -C /work/source/programs \
            -j"$VISA_STOCK_ZSTD_JOBS" \
            zstd-release \
            CC="clang-17 --target=wasm32-wasi --sysroot=/usr" \
            AR=llvm-ar-17 \
            HAVE_ZLIB=0 \
            HAVE_LZMA=0 \
            HAVE_LZ4=0 \
            BACKTRACE=0 \
            MOREFLAGS="-O1 -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -Wno-implicit-function-declaration" \
            LDLIBS="/work/visa_zstd_posix_compat.o -lwasi-emulated-signal -lwasi-emulated-process-clocks"
        install -m 0644 /work/source/programs/zstd /work/zstd-v1.5.7.wasm
    '

python3 scripts/check-zstd-source.py --wasm "$work_root/zstd-v1.5.7.wasm"

docker run --rm \
    --user "$host_uid:$host_gid" \
    --volume "$work_root:/work:Z" \
    --volume "$bridge:/bridge/libvisa_wanco_wasi.a:ro,Z" \
    --workdir /work \
    --env "VISA_WANCO_OPTIMIZATION=$carrier_optimization" \
    --env "VISA_WANCO_SUFFIX=$carrier_suffix" \
    "$build_image" sh -ec '
        set -eu
        wanco --enable-cr "$VISA_WANCO_OPTIMIZATION" -c \
            -o "/work/zstd-v1.5.7-wanco-$VISA_WANCO_SUFFIX.ll" \
            /work/zstd-v1.5.7.wasm
        clang++-17 -std=c++20 -flto -no-pie "$VISA_WANCO_OPTIMIZATION" -g0 \
            -Wl,--build-id=none \
            "/work/zstd-v1.5.7-wanco-$VISA_WANCO_SUFFIX.ll" \
            -I/wanco/lib-rt \
            /usr/local/lib/libwanco_rt.a \
            /bridge/libvisa_wanco_wasi.a \
            -lprotobuf -lunwind -lunwind-x86_64 -lelf \
            -ldl -lpthread -lm \
            -o "/work/zstd-v1.5.7-wanco-$VISA_WANCO_SUFFIX"
    '

carrier_ir="$work_root/zstd-v1.5.7-wanco-$carrier_suffix.ll"
carrier_executable="$work_root/zstd-v1.5.7-wanco-$carrier_suffix"
validate_carrier_abi "$carrier_ir" "$carrier_executable"

mkdir -p "$(dirname "$artifact_root")"
if [[ -e $publication ]]; then
    printf 'refusing existing incomplete publication path: %s\n' "$publication" >&2
    exit 1
fi
mkdir "$publication"
install -m 0644 "$work_root/zstd-v1.5.7.wasm" "$publication/zstd-v1.5.7.wasm"
install -m 0644 \
    "$carrier_ir" \
    "$publication/zstd-v1.5.7-wanco-$carrier_suffix.ll"
install -m 0755 \
    "$carrier_executable" \
    "$publication/zstd-v1.5.7-wanco-$carrier_suffix"

python3 - "$publication/receipt.json" "$publication" "$lock_sha" \
    "$revision" "$wanco_revision" "$wanco_image" "$build_image" \
    "$wanco_image_id" "$build_image_id" "$compiler_version" \
    "$carrier_optimization" "$carrier_qualification" "$carrier_suffix" \
    "$carrier_o1_qualified" \
    "$expected_compiler_sha" "$expected_runtime_sha" "$wanco_source_lock_sha" \
    "$wanco_receipt_sha" "$bridge_sha" "$build_recipe_sha" \
    "$bridge_rustc_version" "$bridge_cargo_version" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

(
    output,
    root,
    source_lock_sha,
    zstd_revision,
    wanco_revision,
    wanco_image,
    build_image,
    wanco_image_id,
    build_image_id,
    compiler_version,
    carrier_optimization,
    carrier_qualification,
    carrier_suffix,
    carrier_o1_qualified,
    wanco_compiler_sha,
    wanco_runtime_sha,
    wanco_source_lock_sha,
    wanco_receipt_sha,
    bridge_sha,
    build_recipe_sha,
    bridge_rustc_version,
    bridge_cargo_version,
) = sys.argv[1:]
root = Path(root)
artifacts = {}
for name in (
    "zstd-v1.5.7.wasm",
    f"zstd-v1.5.7-wanco-{carrier_suffix}.ll",
    f"zstd-v1.5.7-wanco-{carrier_suffix}",
):
    payload = (root / name).read_bytes()
    artifacts[name] = {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }
receipt = {
    "schema": "visa-stock-zstd-build-receipt-v1",
    "source_lock_sha256": source_lock_sha,
    "zstd_revision": zstd_revision,
    "zero_upstream_source_patches": True,
    "wanco_revision": wanco_revision,
    "wanco_optimization": carrier_optimization,
    "carrier_qualification": carrier_qualification,
    "wanco_o1_qualified": carrier_o1_qualified == "true",
    "wanco_image": wanco_image,
    "wanco_image_id": wanco_image_id,
    "wanco_compiler_sha256": wanco_compiler_sha,
    "wanco_runtime_sha256": wanco_runtime_sha,
    "wanco_source_lock_sha256": wanco_source_lock_sha,
    "wanco_build_receipt_sha256": wanco_receipt_sha,
    "build_image": build_image,
    "build_image_id": build_image_id,
    "compiler_version": compiler_version,
    "bridge_sha256": bridge_sha,
    "build_recipe_sha256": build_recipe_sha,
    "rustc_version": bridge_rustc_version,
    "cargo_version": bridge_cargo_version,
    "artifacts": artifacts,
}
path = Path(output)
temporary = path.with_suffix(".tmp")
temporary.write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
os.replace(temporary, path)
PY

mv "$publication" "$artifact_root"
printf 'Stock zstd Wasm: %s\n' "$artifact_root/zstd-v1.5.7.wasm"
printf 'Stock zstd Wanco %s IR: %s\n' \
    "$carrier_optimization" \
    "$artifact_root/zstd-v1.5.7-wanco-$carrier_suffix.ll"
printf 'Stock zstd Wanco %s executable: %s\n' \
    "$carrier_optimization" \
    "$artifact_root/zstd-v1.5.7-wanco-$carrier_suffix"
printf 'Stock zstd build receipt: %s\n' "$artifact_root/receipt.json"
