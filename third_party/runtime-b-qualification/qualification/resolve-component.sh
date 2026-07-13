#!/bin/sh
set -eu

expected=4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
case "$target_dir" in
    /*) ;;
    *) target_dir="$repo_root/$target_dir" ;;
esac

for candidate in "$target_dir"/debug/build/visa-system-*/out/handoff-component.component.wasm; do
    [ -f "$candidate" ] || continue
    observed=$(sha256sum "$candidate" | awk '{print $1}')
    if [ "$observed" = "$expected" ]; then
        printf '%s\n' "$candidate"
        exit 0
    fi
done

printf '%s\n' \
    "no built Stage 1 Component has expected SHA-256 $expected under $target_dir" \
    >&2
exit 1
