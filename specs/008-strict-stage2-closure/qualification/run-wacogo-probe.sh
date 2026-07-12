#!/bin/sh
set -eu

component_sha=4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b
wit_sha=709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920
wacogo_version=v0.0.0-20260617023329-3de16a61796c
wacogo_zip_sha=ffc2004ea59076ef619d3043d4ae4400338cf3a8d2c67b294e582715ce5f26f4

if [ "$#" -ne 1 ]; then
    printf '%s\n' 'usage: run-wacogo-probe.sh COMPONENT' >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
probe_dir="$script_dir/wacogo-probe"
component=$1
world_wit="$repo_root/wit/cooperative-handoff/world.wit"
go_bin=${GO:-go}

printf '%s  %s\n' "$component_sha" "$component" | sha256sum -c -
printf '%s  %s\n' "$wit_sha" "$world_wit" | sha256sum -c -

work=$(mktemp -d "${TMPDIR:-/tmp}/visa-wacogo-qualification.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
cp -R "$probe_dir/." "$work/"

module_json=$(
    cd "$work"
    "$go_bin" mod download -json "github.com/partite-ai/wacogo@$wacogo_version"
)
module_zip=$(printf '%s\n' "$module_json" | sed -n 's/^[[:space:]]*"Zip": "\([^"]*\)",$/\1/p')
module_sum=$(printf '%s\n' "$module_json" | sed -n 's/^[[:space:]]*"Sum": "\([^"]*\)",$/\1/p')
if [ -z "$module_zip" ] || [ -z "$module_sum" ]; then
    printf '%s\n' 'failed to resolve pinned wacogo module identity' >&2
    exit 1
fi
printf '%s  %s\n' "$wacogo_zip_sha" "$module_zip" | sha256sum -c -
if [ "$module_sum" != 'h1:WAxQQFk9xW0jy0cu1Ql4JaaUJTUMo0GsK5TNn5Nliiw=' ]; then
    printf 'unexpected wacogo module sum: %s\n' "$module_sum" >&2
    exit 1
fi
printf 'wacogo-module=%s sha256=%s sum=%s\n' \
    "$wacogo_version" "$wacogo_zip_sha" "$module_sum"

mkdir -p "$work/generated"
(
    cd "$work"
    GOFLAGS=-mod=readonly "$go_bin" tool wacogo-witgen generate \
        -w visa:continuity/cooperative-handoff \
        -o ./generated \
        -p visa.local/wacogo-qualification/generated \
        "$world_wit"
)

generated_files=$(find "$work/generated" -type f -name '*.go' | wc -l)
if [ "$generated_files" -ne 6 ]; then
    printf 'expected 6 generated host-binding files, observed %s\n' "$generated_files" >&2
    exit 1
fi
printf '%s\n' 'generated-host-interfaces=key-value,timers'

(
    cd "$work"
    modules=$("$go_bin" list -mod=readonly -m -f '{{.Path}} {{.Version}}' all | sort)
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
        printf 'unexpected Go module closure:\n%s\n' "$modules" >&2
        exit 1
    fi
    "$go_bin" mod verify >/dev/null
    printf '%s\n' 'module-closure=23-pinned-dependencies verified'
    deps=$("$go_bin" list -mod=readonly -deps ./cmd/probe)
    if printf '%s\n' "$deps" | grep -E '(^|/)(wasmtime|wasmtime-environ)(/|$)' >/dev/null; then
        printf '%s\n' 'forbidden Wasmtime package in executable dependency graph' >&2
        exit 1
    fi
    printf '%s\n' 'executable-lineage=github.com/partite-ai/wacogo/internal/{core,canon},wacogo/wasmparser,tetratelabs/wazero'
    "$go_bin" run -mod=readonly ./cmd/probe "$component" "$world_wit"
)
