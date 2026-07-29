#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

python3 scripts/check-wanco-carrier-source.py

cache_root="$repo_root/target/.ci-cache/wanco-carrier"
mkdir -p "$cache_root"

revision=$(
    python3 -c 'import json; print(json.load(open("third_party/wanco/source-lock.json"))["upstream"]["revision"])'
)
mapfile -t patch_paths < <(
    python3 -c 'import json; print("\n".join(p["path"] for p in json.load(open("third_party/wanco/source-lock.json"))["patches"]))'
)
patch_set_sha=$(
    python3 -c 'import hashlib,json; p=json.load(open("third_party/wanco/source-lock.json"))["patches"]; print(hashlib.sha256("".join(x["sha256"] for x in p).encode()).hexdigest())'
)
source_root="$cache_root/source-${revision:0:12}-${patch_set_sha:0:12}"
image_tag="visa-wanco-carrier:${revision:0:12}-${patch_set_sha:0:12}"

if [[ ! -d "$source_root/.git" ]]; then
    if [[ -e "$source_root" ]]; then
        printf 'refusing to replace non-Git cache path: %s\n' "$source_root" >&2
        exit 1
    fi
    git -c core.hooksPath=/dev/null clone --no-checkout \
        https://github.com/tamaroning/wanco.git "$source_root"
    git -C "$source_root" sparse-checkout init --no-cone
    printf '%s\n' '/*' '!/benchmark/' >"$source_root/.git/info/sparse-checkout"
    git -C "$source_root" -c advice.detachedHead=false checkout --detach "$revision"
    python3 scripts/check-wanco-carrier-source.py --source "$source_root"
    for patch_path in "${patch_paths[@]}"; do
        git -C "$source_root" apply -- "$repo_root/$patch_path"
    done
fi

python3 scripts/check-wanco-carrier-source.py --source "$source_root" --patched
if [[ -e "$source_root/benchmark" ]]; then
    printf '%s\n' 'benchmark/ unexpectedly present in the sparse Wanco build source' >&2
    exit 1
fi

docker build --progress=plain --tag "$image_tag" "$source_root"
image_id=$(docker image inspect --format '{{.Id}}' "$image_tag")
llvm_config_version=$(
    docker run --rm "$image_tag" sh -ec \
        'test "$LLVM_SYS_170_PREFIX" = /usr/lib/llvm-17; /usr/lib/llvm-17/bin/llvm-config --version'
)
rustc_version=$(docker run --rm "$image_tag" rustc --version)
cargo_version=$(docker run --rm "$image_tag" cargo --version)
clang_version=$(docker run --rm "$image_tag" sh -ec 'clang++-17 --version | sed -n "1p"')
wanco_binary_sha256=$(docker run --rm "$image_tag" sha256sum /usr/local/bin/wanco | cut -d' ' -f1)

python3 - "$cache_root/build-receipt.json" "$revision" "$patch_set_sha" "$image_tag" "$image_id" \
    "$llvm_config_version" "$rustc_version" "$cargo_version" "$clang_version" \
    "$wanco_binary_sha256" "${patch_paths[@]}" <<'PY'
import json
import os
import sys
from pathlib import Path

(
    output,
    revision,
    patch_set_sha,
    image_tag,
    image_id,
    llvm_config_version,
    rustc_version,
    cargo_version,
    clang_version,
    wanco_binary_sha256,
    *patch_paths,
) = sys.argv[1:]
receipt = {
    "schema": "visa-wanco-carrier-build-receipt-v1",
    "revision": revision,
    "build_patch_set_sha256": patch_set_sha,
    "build_patches": patch_paths,
    "image_tag": image_tag,
    "image_id": image_id,
    "llvm_sys_170_prefix": "/usr/lib/llvm-17",
    "llvm_config_version": llvm_config_version,
    "rustc_version": rustc_version,
    "cargo_version": cargo_version,
    "clang_version": clang_version,
    "wanco_binary_sha256": wanco_binary_sha256,
    "benchmark_subtree_in_build_context": False,
}
path = Path(output)
temporary = path.with_suffix(".tmp")
temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(temporary, path)
PY

printf 'Wanco carrier image: %s\n' "$image_tag"
printf 'Wanco carrier image ID: %s\n' "$image_id"
printf 'Wanco compiler SHA-256: %s\n' "$wanco_binary_sha256"
printf 'Wanco carrier build receipt: %s\n' "$cache_root/build-receipt.json"
