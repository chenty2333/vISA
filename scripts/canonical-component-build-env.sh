#!/usr/bin/env bash

# Shared build contract for byte-locked wasm Components. This file is sourced
# by evidence gates; it deliberately does not change the caller until the
# public function is invoked.

visa_component_env_error() {
    printf 'canonical Component build environment: %s\n' "$*" >&2
    return 1
}

visa_component_canonical_directory() {
    local description=$1
    local path=$2

    [[ -d "$path" && ! -L "$path" ]] \
        || visa_component_env_error "$description must be a non-symlink directory: $path" \
        || return
    realpath -e -- "$path"
}

visa_configure_canonical_component_build_environment() {
    local record_path=${1:-}
    local configured_cargo_home=${CARGO_HOME:-}
    local configured_rustup_home=${RUSTUP_HOME:-}
    local configured_cargo_incremental=${CARGO_INCREMENTAL:-unset}
    local canonical_cargo_home
    local canonical_rustup_home

    if [[ -z "$configured_cargo_home" ]]; then
        [[ -n "${HOME:-}" ]] \
            || visa_component_env_error 'HOME is required when CARGO_HOME is unset or empty' \
            || return
        configured_cargo_home=$HOME/.cargo
    fi
    if [[ -z "$configured_rustup_home" ]]; then
        [[ -n "${HOME:-}" ]] \
            || visa_component_env_error 'HOME is required when RUSTUP_HOME is unset or empty' \
            || return
        configured_rustup_home=$HOME/.rustup
    fi

    for value in "$configured_cargo_home" "$configured_rustup_home"; do
        [[ "$value" != *[[:space:][:cntrl:]]* ]] \
            || visa_component_env_error "build root cannot be encoded safely in locked rustflags: $value" \
            || return
        [[ "$value" != *'='* ]] \
            || visa_component_env_error "build root cannot contain '=' in locked rustflags: $value" \
            || return
    done

    canonical_cargo_home=$(visa_component_canonical_directory \
        'actual Cargo home' "$configured_cargo_home") || return
    canonical_rustup_home=$(visa_component_canonical_directory \
        'actual Rustup home' "$configured_rustup_home") || return

    for value in "$canonical_cargo_home" "$canonical_rustup_home"; do
        [[ "$value" == /* && "$value" != / ]] \
            || visa_component_env_error "build root is not a safe absolute remap source: $value" \
            || return
        [[ "$value" != *[[:space:][:cntrl:]]* && "$value" != *'='* ]] \
            || visa_component_env_error "canonical build root cannot be encoded safely: $value" \
            || return
    done
    [[ "$canonical_cargo_home" != "$canonical_rustup_home" ]] \
        || visa_component_env_error 'actual Cargo and Rustup homes must be distinct remap sources' \
        || return
    [[ "$canonical_cargo_home/" != "$canonical_rustup_home/"* ]] \
        || visa_component_env_error 'actual Cargo home must not be nested under the Rustup home' \
        || return
    [[ "$canonical_rustup_home/" != "$canonical_cargo_home/"* ]] \
        || visa_component_env_error 'actual Rustup home must not be nested under the Cargo home' \
        || return

    VISA_COMPONENT_CARGO_HOME=$canonical_cargo_home
    VISA_COMPONENT_RUSTUP_HOME=$canonical_rustup_home
    VISA_COMPONENT_TARGET_RUSTFLAGS="-C target-feature=-bulk-memory,-multivalue,-reference-types,-sign-ext,-nontrapping-fptoint --remap-path-prefix=$VISA_COMPONENT_CARGO_HOME=/home/ava/.cargo --remap-path-prefix=$VISA_COMPONENT_RUSTUP_HOME=/home/ava/.rustup"

    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
    unset CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS
    CARGO_HOME=$VISA_COMPONENT_CARGO_HOME
    RUSTUP_HOME=$VISA_COMPONENT_RUSTUP_HOME
    CARGO_INCREMENTAL=1
    CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS=$VISA_COMPONENT_TARGET_RUSTFLAGS
    export CARGO_HOME RUSTUP_HOME CARGO_INCREMENTAL
    export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS
    export VISA_COMPONENT_CARGO_HOME VISA_COMPONENT_RUSTUP_HOME
    export VISA_COMPONENT_TARGET_RUSTFLAGS

    if [[ -n "$record_path" ]]; then
        [[ "$record_path" == /* ]] \
            || visa_component_env_error "receipt path must be absolute: $record_path" \
            || return
        [[ ! -L "$record_path" ]] \
            || visa_component_env_error "receipt path must not be a symlink: $record_path" \
            || return
        {
            printf '%s\n' 'schema=visa.canonical-component-build-environment.v1'
            printf 'cargo-home.input=%s\n' "$configured_cargo_home"
            printf 'cargo-home.canonical=%s\n' "$VISA_COMPONENT_CARGO_HOME"
            printf '%s\n' 'cargo-home.remapped=/home/ava/.cargo'
            printf 'rustup-home.input=%s\n' "$configured_rustup_home"
            printf 'rustup-home.canonical=%s\n' "$VISA_COMPONENT_RUSTUP_HOME"
            printf '%s\n' 'rustup-home.remapped=/home/ava/.rustup'
            printf 'cargo-incremental.input=%s\n' "$configured_cargo_incremental"
            printf '%s\n' 'cargo-incremental.locked=1'
            printf '%s\n' 'generic-rustflags=unset'
            printf 'target-rustflags=%s\n' "$VISA_COMPONENT_TARGET_RUSTFLAGS"
        } >"$record_path"
        chmod 600 -- "$record_path"
    fi

    printf 'component-cargo-home=%s remapped-to=/home/ava/.cargo\n' \
        "$VISA_COMPONENT_CARGO_HOME"
    printf 'component-rustup-home=%s remapped-to=/home/ava/.rustup\n' \
        "$VISA_COMPONENT_RUSTUP_HOME"
    if [[ -n "$record_path" ]]; then
        printf 'component-build-environment=%s sha256=%s\n' \
            "$record_path" "$(sha256sum "$record_path" | cut -d' ' -f1)"
    fi
}
