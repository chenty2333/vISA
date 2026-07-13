#!/bin/sh
set -eu

component_sha=4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b
wit_sha=709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920
cli_sha=35dbe748e139888181ea91c5c1e0188a95f7fcdaac6b7ec1a8723e1494fa5ae3
cli_version=1.10.1
cli_identity='Wacs.Console 1.10.1+e6e76340b9d38ec3846d39833136eac8846f9f81'

if [ "$#" -ne 1 ]; then
    printf '%s\n' 'usage: run-wacs-cli-aot-probe.sh COMPONENT' >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
component=$1
world_wit="$repo_root/wit/cooperative-handoff/world.wit"
wit_dir=$(dirname -- "$world_wit")
dotnet=${DOTNET:-dotnet}

printf '%s  %s\n' "$component_sha" "$component" | sha256sum -c -
printf '%s  %s\n' "$wit_sha" "$world_wit" | sha256sum -c -
wit_count=$(find "$wit_dir" -type f -name '*.wit' | wc -l)
if [ "$wit_count" -ne 1 ]; then
    printf 'expected one WIT file under %s, observed %s\n' "$wit_dir" "$wit_count" >&2
    exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/visa-wacs-cli-aot.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

dotnet_path=$(command -v "$dotnet")
dotnet_path=$(readlink -f "$dotnet_path")
export DOTNET_ROOT=${DOTNET_ROOT:-"$(dirname -- "$dotnet_path")"}
if [ -n "${WACS_TOOL_DIR:-}" ]; then
    tool_dir=$WACS_TOOL_DIR
else
    tool_dir="$work/tool"
    package_dir="$work/packages"
    mkdir -p "$tool_dir" "$package_dir"
    if ! NUGET_PACKAGES="$package_dir" "$dotnet_path" tool install \
        --tool-path "$tool_dir" WACS.Cli --version "$cli_version" \
        >"$work/install.stdout" 2>"$work/install.stderr"; then
        cat "$work/install.stdout" >&2
        cat "$work/install.stderr" >&2
        exit 1
    fi
fi

nupkg="$tool_dir/.store/wacs.cli/$cli_version/wacs.cli/$cli_version/wacs.cli.$cli_version.nupkg"
printf '%s  %s\n' "$cli_sha" "$nupkg" | sha256sum -c -
wacs="$tool_dir/wacs"
observed_identity=$("$wacs" --version | sed -n '1p')
if [ "$observed_identity" != "$cli_identity" ]; then
    printf 'WACS CLI identity mismatch: expected %s, observed %s\n' \
        "$cli_identity" "$observed_identity" >&2
    exit 1
fi
printf 'wacs-cli-identity=%s\n' "$observed_identity"

set +e
"$wacs" build "$component" --wit-dir "$wit_dir" \
    --output "$work/contract.dll" \
    >"$work/contract-build.stdout" 2>"$work/contract-build.stderr"
contract_build_exit=$?
set -e
if [ "$contract_build_exit" -ne 1 ]; then
    printf 'expected contract build exit 1, observed %s\n' "$contract_build_exit" >&2
    exit 1
fi
grep -Fq "import 'key-value' (interface ref): v0 validator does not yet compare interface-import shapes." \
    "$work/contract-build.stderr"
grep -Fq "import 'timers' (interface ref): v0 validator does not yet compare interface-import shapes." \
    "$work/contract-build.stderr"
printf 'contract-build=unsupported-interface-import-shape\n'

"$wacs" build "$component" --output "$work/raw.dll" \
    >"$work/raw-build.stdout" 2>"$work/raw-build.stderr"
"$dotnet_path" run \
    --project "$script_dir/wacs-aot-inspect/wacs-aot-inspect.csproj" \
    -c Release -- "$component" "$world_wit" "$work/raw.dll"

set +e
"$wacs" run "$component" --engine transpiler \
    --call 'visa:continuity/workload@0.1.0#status' \
    >"$work/raw-run.stdout" 2>"$work/raw-run.stderr"
raw_run_exit=$?
set -e
if [ "$raw_run_exit" -ne 128 ]; then
    printf 'expected raw status exit 128, observed %s\n' "$raw_run_exit" >&2
    exit 1
fi
printf 'raw-status-run-exit=%s\n' "$raw_run_exit"

set +e
"$wacs" aot "$component" --wit-dir "$wit_dir" \
    --output "$work/native" \
    >"$work/native-aot.stdout" 2>"$work/native-aot.stderr"
native_aot_exit=$?
set -e
if [ "$native_aot_exit" -ne 1 ]; then
    printf 'expected native AOT exit 1, observed %s\n' "$native_aot_exit" >&2
    exit 1
fi
grep -Fq "import 'key-value' (interface ref): v0 validator does not yet compare interface-import shapes." \
    "$work/native-aot.stderr"
grep -Fq "import 'timers' (interface ref): v0 validator does not yet compare interface-import shapes." \
    "$work/native-aot.stderr"
printf 'native-aot=unsupported-interface-import-shape\n'
printf 'decision=no-go\n'
