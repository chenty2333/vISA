#!/bin/sh
set -eu

component_sha=4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b
wit_sha=709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920
archive_sha=e88199f7c48fe27fc1a23b104f4049d2615cef1ebe70b588b0e082ca9eb5f6e5
wasmedge_version=0.17.1

if [ "$#" -ne 2 ]; then
    printf '%s\n' \
        'usage: run-wasmedge-probe.sh COMPONENT WASMEDGE_ARCHIVE' >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
component=$1
archive=$2
world_wit="$repo_root/wit/cooperative-handoff/world.wit"

printf '%s  %s\n' "$component_sha" "$component" | sha256sum -c -
printf '%s  %s\n' "$wit_sha" "$world_wit" | sha256sum -c -
printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum -c -

work=$(mktemp -d "${TMPDIR:-/tmp}/visa-wasmedge-qualification.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/dist"
tar -xJf "$archive" -C "$work/dist"

wasmedge="$work/dist/bin/wasmedge"
if [ ! -x "$wasmedge" ] || [ ! -f "$work/dist/lib64/libwasmedge.so" ]; then
    printf '%s\n' 'pinned WasmEdge archive has an unexpected layout' >&2
    exit 1
fi

version_line=$(
    LD_LIBRARY_PATH="$work/dist/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "$wasmedge" --version | sed -n '1p'
)
case "$version_line" in
    *" version $wasmedge_version") ;;
    *)
        printf 'expected WasmEdge version %s, observed: %s\n' \
            "$wasmedge_version" "$version_line" >&2
        exit 1
        ;;
esac
printf 'wasmedge-version=%s archive-sha256=%s\n' \
    "$wasmedge_version" "$archive_sha"

set +e
LD_LIBRARY_PATH="$work/dist/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$wasmedge" --enable-component --reactor "$component" \
    >"$work/output" 2>&1
wasmedge_exit=$?
set -e

if [ "$wasmedge_exit" -ne 1 ]; then
    cat "$work/output" >&2
    printf 'expected WasmEdge exit 1, observed %s\n' "$wasmedge_exit" >&2
    exit 1
fi

sed 's/^\[[^]]*\] //' "$work/output" >"$work/normalized"
cat >"$work/expected" <<'EOF'
[warning] component model is enabled, this is experimental.
[warning] component model is an experimental proposal
[warning] Component Model Validation is in active development.
[error] validation failed: invalid type reference, Code: 0x2a3
[error]     canon resource.drop: type index 10 does not reference a resource
[error]     At AST node: component canonical
[error]     At AST node: component canonical section
[error]     At AST node: component model module
EOF

if ! cmp -s "$work/expected" "$work/normalized"; then
    printf '%s\n' 'unexpected WasmEdge validation failure:' >&2
    diff -u "$work/expected" "$work/normalized" >&2 || true
    exit 1
fi

cat "$work/output"
printf '%s\n' \
    'wasmedge-stage=component-validation/canonical-section result=unsupported'
printf '%s\n' 'decision=no-go'
