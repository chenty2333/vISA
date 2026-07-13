#!/bin/sh
set -eu

component_sha=4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b
wit_sha=709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920
go_version=go1.26.5
go_binary_sha=8da5fd321795754b994c64e3eb8a5a14ff47bd285559a7e876f3c79abafc67f9
go_tree_sha=23638de611eeb09483b3ba982f98cc6aa863299dd8d69c72924866c63f007298
go_tree_files=15026
wacogo_version=v0.0.0-20260617023329-3de16a61796c
wacogo_revision=3de16a61796ce02d29795e4a074f37a33e6ebd87
wacogo_zip_size=8838002
wacogo_zip_sha=ffc2004ea59076ef619d3043d4ae4400338cf3a8d2c67b294e582715ce5f26f4
wacogo_module_sum='h1:WAxQQFk9xW0jy0cu1Ql4JaaUJTUMo0GsK5TNn5Nliiw='
wacogo_license_sha=46ae5f0dc2e06a18cde8b06bdb45abea0b6e28d169e6eff2069536780304cf6e
probe_main_sha=048e12e1bb4709ede55de0d78009574cdf14d79229524362b94622ece8bd673f
probe_mod_sha=6215baed9e8f18c090dbd4ad5d3262af2e1fa9e6ca44ab7c2eba6ff418569bd9
probe_sum_sha=4eba5686a0fc26a1955537b059ac41f1ffd892d64bc275273e5d2102b42d4b9f
series_sha=c883b21ac64332290ae6e8ae1db197af2cf5b690c15f74cfb79552c1fe081497
patch1_sha=c04b82a5ec2a95c45f5f81bdce5b2cbff11e25556865eb19928b48b6f94eed69
patch2_sha=3531ff7a61de7c41f4237d7077a4dd0602bedd15e3067db070fd3e659575a37e
patch3_sha=4b32fe31643aedab8472c42ae38d635abbfc9133093866b5ff1de9dcc4548d0e
patchset_sha=a377b3d3f0da455f14097638380a8bab566b2aa0d33a4f25d90326e7a2b211e2
patched_tree_sha=813eb9fad2d93d0c2237edf5d55d18316d1cc313ccf033e079c01fd18f653311

if [ "$#" -ne 1 ]; then
    printf '%s\n' 'usage: run-wacogo-probe.sh COMPONENT' >&2
    exit 64
fi

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
probe_source="$script_dir/wacogo-probe"
qualification_patch_dir="$script_dir/wacogo-patches"
patch_dir="$repo_root/third_party/wacogo/patches"
component=$1
world_wit="$repo_root/wit/cooperative-handoff/world.wit"
go_bin=${GO:-go}

case $go_bin in
    */*) ;;
    *) go_bin=$(command -v "$go_bin") || fail "Go executable not found: $go_bin" ;;
esac
unset GOROOT GOFLAGS GOEXPERIMENT GOTMPDIR
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0

go_identity=$($go_bin version 2>/dev/null || true)
if [ "$go_identity" != "go version $go_version linux/amd64" ]; then
    fail "wacogo qualification requires the official $go_version linux/amd64 toolchain; observed: ${go_identity:-unavailable}"
fi
printf '%s  %s\n' "$go_binary_sha" "$go_bin" | sha256sum -c -
go_root=$($go_bin env GOROOT)
observed_go_tree_sha=$(
    cd "$go_root"
    find . -type f -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 sha256sum \
        | sha256sum \
        | cut -d' ' -f1
)
observed_go_tree_files=$(find "$go_root" -type f | wc -l | tr -d '[:space:]')
if [ "$observed_go_tree_sha" != "$go_tree_sha" ] || [ "$observed_go_tree_files" != "$go_tree_files" ]; then
    fail "official Go tree mismatch: sha256=$observed_go_tree_sha files=$observed_go_tree_files"
fi
printf 'go-toolchain=%s binary-sha256=%s tree-sha256=%s files=%s\n' \
    "$go_version" "$go_binary_sha" "$go_tree_sha" "$go_tree_files"

printf '%s  %s\n' "$component_sha" "$component" | sha256sum -c -
printf '%s  %s\n' "$wit_sha" "$world_wit" | sha256sum -c -
printf '%s  %s\n' "$probe_main_sha" "$probe_source/cmd/probe/main.go" | sha256sum -c -
printf '%s  %s\n' "$probe_mod_sha" "$probe_source/go.mod" | sha256sum -c -
printf '%s  %s\n' "$probe_sum_sha" "$probe_source/go.sum" | sha256sum -c -
printf '%s  %s\n' "$series_sha" "$patch_dir/series" | sha256sum -c -
printf '%s  %s\n' "$patch1_sha" "$patch_dir/0001-host-export-named-defined-types.patch" | sha256sum -c -
printf '%s  %s\n' "$patch2_sha" "$patch_dir/0002-public-host-owned-values.patch" | sha256sum -c -
printf '%s  %s\n' "$patch3_sha" "$patch_dir/0003-public-non-executing-preflight.patch" | sha256sum -c -

for patch_name in \
    series \
    0001-host-export-named-defined-types.patch \
    0002-public-host-owned-values.patch \
    0003-public-non-executing-preflight.patch
do
    if ! cmp -s "$patch_dir/$patch_name" "$qualification_patch_dir/$patch_name"; then
        fail "qualification patch mirror drifted from canonical third_party source: $patch_name"
    fi
done
printf '%s\n' 'qualification-patch-mirror=canonical-third-party-byte-identical'

expected_series=$(printf '%s\n' \
    0001-host-export-named-defined-types.patch \
    0002-public-host-owned-values.patch \
    0003-public-non-executing-preflight.patch)
observed_series=$(cat "$patch_dir/series")
if [ "$observed_series" != "$expected_series" ]; then
    fail 'unexpected wacogo downstream patch order'
fi
observed_patchset_sha=$(
    while IFS= read -r patch_name; do
        cat "$patch_dir/$patch_name"
    done <"$patch_dir/series" | sha256sum | cut -d' ' -f1
)
if [ "$observed_patchset_sha" != "$patchset_sha" ]; then
    fail "wacogo patchset SHA-256 mismatch: expected $patchset_sha, observed $observed_patchset_sha"
fi
printf 'wacogo-patchset=v1 sha256=%s patches=3\n' "$patchset_sha"

stage=$(mktemp -d "${TMPDIR:-/tmp}/visa-wacogo-qualification.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/probe" "$stage/wacogo"
cp -R "$probe_source/." "$stage/probe/"

module_json=$(
    cd "$stage/probe"
    GOTOOLCHAIN=local GOENV=off GOWORK=off "$go_bin" mod download -json \
        "github.com/partite-ai/wacogo@$wacogo_version"
)
module_zip=$(printf '%s\n' "$module_json" | sed -n 's/^[[:space:]]*"Zip": "\([^"]*\)",$/\1/p')
module_dir=$(printf '%s\n' "$module_json" | sed -n 's/^[[:space:]]*"Dir": "\([^"]*\)",$/\1/p')
module_sum=$(printf '%s\n' "$module_json" | sed -n 's/^[[:space:]]*"Sum": "\([^"]*\)",$/\1/p')
origin_hash=$(printf '%s\n' "$module_json" | sed -n 's/^[[:space:]]*"Hash": "\([^"]*\)"$/\1/p')
if [ -z "$module_zip" ] || [ -z "$module_dir" ] || [ -z "$module_sum" ]; then
    fail 'failed to resolve pinned wacogo module identity'
fi
printf '%s  %s\n' "$wacogo_zip_sha" "$module_zip" | sha256sum -c -
observed_zip_size=$(wc -c <"$module_zip" | tr -d '[:space:]')
if [ "$observed_zip_size" != "$wacogo_zip_size" ]; then
    fail "unexpected wacogo module zip size: $observed_zip_size"
fi
if [ "$module_sum" != "$wacogo_module_sum" ]; then
    fail "unexpected wacogo module sum: $module_sum"
fi
if [ -n "$origin_hash" ] && [ "$origin_hash" != "$wacogo_revision" ]; then
    fail "unexpected wacogo source revision: $origin_hash"
fi
printf 'wacogo-upstream=%s revision=%s zip-sha256=%s sum=%s\n' \
    "$wacogo_version" "$wacogo_revision" "$wacogo_zip_sha" "$module_sum"

cp -R "$module_dir/." "$stage/wacogo/"
chmod -R u+w "$stage/wacogo"
printf '%s  %s\n' "$wacogo_license_sha" "$stage/wacogo/LICENSE" | sha256sum -c -

while IFS= read -r patch_name; do
    git -C "$stage/wacogo" apply --check --whitespace=error-all "$patch_dir/$patch_name"
    git -C "$stage/wacogo" apply --whitespace=error-all "$patch_dir/$patch_name"
done <"$patch_dir/series"

observed_tree_sha=$(
    cd "$stage/wacogo"
    find . -type f -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 sha256sum \
        | sha256sum \
        | cut -d' ' -f1
)
if [ "$observed_tree_sha" != "$patched_tree_sha" ]; then
    fail "patched wacogo tree SHA-256 mismatch: expected $patched_tree_sha, observed $observed_tree_sha"
fi
printf 'wacogo-patched-tree-sha256=%s files=%s\n' \
    "$observed_tree_sha" "$(find "$stage/wacogo" -type f | wc -l | tr -d '[:space:]')"

(
    cd "$stage/probe"
    GOTOOLCHAIN=local GOENV=off GOWORK=off "$go_bin" mod edit \
        -replace=github.com/partite-ai/wacogo=../wacogo
    GOTOOLCHAIN=local GOENV=off GOWORK=off "$go_bin" mod download all
)

export GOPROXY=off GOSUMDB=off
printf '%s\n' 'post-prefetch-module-network=disabled GOPROXY=off GOSUMDB=off'

mkdir -p "$stage/probe/generated"
(
    cd "$stage/probe"
    GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS=-mod=readonly \
        "$go_bin" tool wacogo-witgen generate \
        -w visa:continuity/cooperative-handoff \
        -o ./generated \
        -p visa.local/wacogo-qualification/generated \
        "$world_wit"
)

generated_files=$(find "$stage/probe/generated" -type f -name '*.go' | wc -l | tr -d '[:space:]')
if [ "$generated_files" -ne 6 ]; then
    fail "expected 6 generated import-binding files, observed $generated_files"
fi
if find "$stage/probe/generated" -type f -path '*/workload/*' | grep . >/dev/null; then
    fail 'qualification unexpectedly generated a workload wrapper'
fi
printf '%s\n' 'generated-host-interfaces=key-value,timers files=6'

(
    cd "$stage/probe"
    modules=$(GOTOOLCHAIN=local GOENV=off GOWORK=off "$go_bin" list -mod=readonly -m -f '{{.Path}} {{.Version}}' all | sort)
    expected_modules=$(printf '%s\n' \
        'github.com/coreos/go-semver v0.3.1' \
        'github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7' \
        'github.com/google/go-cmp v0.6.0' \
        'github.com/klauspost/compress v1.18.0' \
        'github.com/opencontainers/go-digest v1.0.0' \
        'github.com/partite-ai/wacogo v0.0.0-20260617023329-3de16a61796c' \
        'github.com/regclient/regclient v0.8.3' \
        'github.com/sergi/go-diff v1.3.1' \
        'github.com/sirupsen/logrus v1.9.3' \
        'github.com/tetratelabs/wazero v1.11.1-0.20260418165552-5cb4bb3ec0c1' \
        'github.com/ulikunitz/xz v0.5.12' \
        'github.com/urfave/cli/v3 v3.3.3' \
        'github.com/yuin/goldmark v1.4.13' \
        'go.bytecodealliance.org v0.7.0' \
        'go.bytecodealliance.org/cm v0.3.0' \
        'golang.org/x/mod v0.35.0' \
        'golang.org/x/net v0.53.0' \
        'golang.org/x/sync v0.20.0' \
        'golang.org/x/sys v0.43.0' \
        'golang.org/x/telemetry v0.0.0-20260409153401-be6f6cb8b1fa' \
        'golang.org/x/tools v0.44.0' \
        'gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405' \
        'gopkg.in/yaml.v3 v3.0.1' \
        'visa.local/wacogo-qualification ' | sort)
    if [ "$modules" != "$expected_modules" ]; then
        fail "unexpected Go module closure:\n$modules"
    fi
    replacements=$(GOTOOLCHAIN=local GOENV=off GOWORK=off "$go_bin" list -mod=readonly -m -f '{{if .Replace}}{{.Path}}=>{{.Replace.Path}}{{end}}' all | sed '/^$/d')
    if [ "$replacements" != 'github.com/partite-ai/wacogo=>../wacogo' ]; then
        fail "unexpected module replacements: $replacements"
    fi
    GOTOOLCHAIN=local GOENV=off GOWORK=off "$go_bin" mod verify >/dev/null
    printf '%s\n' 'module-closure=23-pinned-dependencies replacement=patched-wacogo verified'
    deps=$(GOTOOLCHAIN=local GOENV=off GOWORK=off "$go_bin" list -mod=readonly -deps ./cmd/probe)
    if printf '%s\n' "$deps" | grep -E '(^|/)(wasmtime|wasmtime-environ)(/|$)' >/dev/null; then
        fail 'forbidden Wasmtime package in executable dependency graph'
    fi
    if grep -R '"github.com/partite-ai/wacogo/internal/' cmd generated >/dev/null 2>&1; then
        fail 'qualification sidecar directly imports a wacogo internal package'
    fi
    printf '%s\n' 'executable-lineage=wacogo/{wasmparser,internal/core,internal/canon}+wazero no-wasmtime=true'
)

(
    cd "$stage/wacogo"
    "$go_bin" test ./host ./internal/canon . ./internal/witgen
    "$go_bin" test ./internal/core -run '^TestPlanResolveTypePopulatesInstanceTable$' -count=1
)
printf '%s\n' 'patched-upstream-focused-tests=passed'

(
    cd "$stage/probe"
    GOFLAGS=-mod=readonly "$go_bin" run ./cmd/probe "$component" "$world_wit"
)
