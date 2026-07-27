#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=canonical-component-build-env.sh
source "$script_dir/canonical-component-build-env.sh"

test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
mkdir -p "$test_root/cargo" "$test_root/rustup"
receipt="$test_root/receipt.env"

CARGO_HOME=$test_root/cargo
RUSTUP_HOME=$test_root/rustup
CARGO_INCREMENTAL=0
RUSTFLAGS='must-be-cleared'
CARGO_ENCODED_RUSTFLAGS='must-be-cleared'
CARGO_BUILD_RUSTFLAGS='must-be-cleared'
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='must-be-replaced'
export CARGO_HOME RUSTUP_HOME CARGO_INCREMENTAL RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS

visa_configure_canonical_component_build_environment "$receipt" >/dev/null

[[ "$CARGO_INCREMENTAL" == 1 ]]
[[ "$CARGO_HOME" == "$test_root/cargo" ]]
[[ "$RUSTUP_HOME" == "$test_root/rustup" ]]
[[ ! -v RUSTFLAGS && ! -v CARGO_ENCODED_RUSTFLAGS && ! -v CARGO_BUILD_RUSTFLAGS ]]
[[ "$CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS" == \
    "$VISA_COMPONENT_TARGET_RUSTFLAGS" ]]
[[ "$VISA_COMPONENT_TARGET_RUSTFLAGS" == \
    *"--remap-path-prefix=$test_root/cargo=/home/ava/.cargo"* ]]
[[ "$VISA_COMPONENT_TARGET_RUSTFLAGS" == \
    *"--remap-path-prefix=$test_root/rustup=/home/ava/.rustup"* ]]
grep -Fx 'schema=visa.canonical-component-build-environment.v1' "$receipt" >/dev/null
grep -Fx 'cargo-incremental.input=0' "$receipt" >/dev/null
grep -Fx 'cargo-incremental.locked=1' "$receipt" >/dev/null
[[ "$(stat -c '%a' "$receipt")" == 600 ]]

if (
    CARGO_HOME=$test_root/cargo
    RUSTUP_HOME=$test_root/cargo
    visa_configure_canonical_component_build_environment >/dev/null 2>&1
); then
    printf '%s\n' 'shared Cargo/Rustup root was incorrectly accepted' >&2
    exit 1
fi

mkdir -p "$test_root/cargo/nested"
if (
    CARGO_HOME=$test_root/cargo
    RUSTUP_HOME=$test_root/cargo/nested
    visa_configure_canonical_component_build_environment >/dev/null 2>&1
); then
    printf '%s\n' 'nested Cargo/Rustup roots were incorrectly accepted' >&2
    exit 1
fi

printf '%s\n' 'canonical Component build environment tests passed'
