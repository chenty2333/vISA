#!/bin/sh
set -eu

component_sha=4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b
wit_sha=709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920
lock_sha=649f1a0ba4b8df293e1dca9f21f4978f5d1bac43a88d9947d3258114c4c154da
sdk_version=9.0.301
runtime_version=9.0.6

if [ "$#" -ne 1 ]; then
    printf '%s\n' 'usage: run-wacs-harness-probe.sh COMPONENT' >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
project="$script_dir/wacs-harness/wacs-harness.csproj"
lock_file="$script_dir/wacs-harness/packages.lock.json"
assembly="$script_dir/wacs-harness/bin/Release/net9.0/wacs-harness.dll"
component=$1
world_wit="$repo_root/wit/cooperative-handoff/world.wit"
wit_dir=$(dirname -- "$world_wit")
dotnet=${DOTNET:-dotnet}

printf '%s  %s\n' "$component_sha" "$component" | sha256sum -c -
printf '%s  %s\n' "$wit_sha" "$world_wit" | sha256sum -c -
printf '%s  %s\n' "$lock_sha" "$lock_file" | sha256sum -c -

wit_count=$(find "$wit_dir" -type f -name '*.wit' | wc -l)
if [ "$wit_count" -ne 1 ]; then
    printf 'expected one WIT file under %s, observed %s\n' "$wit_dir" "$wit_count" >&2
    exit 1
fi

dotnet_path=$(command -v "$dotnet")
dotnet_path=$(readlink -f "$dotnet_path")
export DOTNET_ROOT=${DOTNET_ROOT:-"$(dirname -- "$dotnet_path")"}

observed_sdk=$("$dotnet_path" --version)
if [ "$observed_sdk" != "$sdk_version" ]; then
    printf 'expected .NET SDK %s, observed %s\n' "$sdk_version" "$observed_sdk" >&2
    exit 1
fi
if ! "$dotnet_path" --list-runtimes | grep -Eq \
    "^Microsoft\\.NETCore\\.App $runtime_version \\["; then
    printf 'required Microsoft.NETCore.App %s is not installed\n' "$runtime_version" >&2
    exit 1
fi
printf 'dotnet-sdk=%s runtime=Microsoft.NETCore.App@%s\n' \
    "$observed_sdk" "$runtime_version"

"$dotnet_path" restore "$project" --locked-mode --nologo --verbosity quiet

global_packages=$(
    "$dotnet_path" nuget locals global-packages --list |
        sed -n 's/^global-packages: //p'
)
if [ -z "$global_packages" ] || [ ! -d "$global_packages" ]; then
    printf 'could not resolve NuGet global-packages directory: %s\n' \
        "$global_packages" >&2
    exit 1
fi
global_packages=${global_packages%/}

check_package() {
    id=$1
    version=$2
    expected=$3
    package="$global_packages/$id/$version/$id.$version.nupkg"
    printf '%s  %s\n' "$expected" "$package" | sha256sum -c -
}

check_package wacs 0.16.14 \
    c19d97e3ebf6f8634baf64b272c6efb77427c4f7947c9e439df9f0342518c29a
check_package wacs.componentmodel 0.10.3 \
    2896f10b71859be40a4aa7e7df74a4318c3f961022e81dec0d86fd5c6cd526d0
check_package wacs.componentmodel.harness.lib 0.27.2 \
    283b651a8085e1b7e60d5130836b77e33e37e5c0e0b7d59e3512ef9ad0fc95df
check_package wacs.componentmodel.harness.runtime 0.7.5 \
    cff5881b30b19ad7d0acf7262cbca00fa5d841bf289d86b82c0271f4420339ba
check_package wacs.componentmodel.parser 0.2.2 \
    05ff2603ab4b15facb94737bf682fe464be54ac7ef209e508ea3697984d1a1de

work=$(mktemp -d "${TMPDIR:-/tmp}/visa-wacs-harness.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

"$dotnet_path" build "$project" -c Release --no-restore --nologo --verbosity quiet
if [ ! -f "$assembly" ]; then
    printf 'typed harness build did not produce %s\n' "$assembly" >&2
    exit 1
fi

set +e
"$dotnet_path" exec --fx-version "$runtime_version" "$assembly" \
    "$component" "$wit_dir" >"$work/output" 2>&1
harness_exit=$?
set -e

if [ "$harness_exit" -ne 1 ]; then
    cat "$work/output" >&2
    printf 'expected typed harness exit 1, observed %s\n' "$harness_exit" >&2
    exit 1
fi

require_exact_line() {
    line=$1
    count=$(grep -Fxc "$line" "$work/output" || true)
    if [ "$count" -ne 1 ]; then
        cat "$work/output" >&2
        printf 'expected one exact diagnostic line, observed %s: %s\n' \
            "$count" "$line" >&2
        exit 1
    fi
}

require_stack_stage() {
    stage=$1
    if ! grep -Fq "$stage" "$work/output"; then
        cat "$work/output" >&2
        printf 'expected typed harness failure stage was not observed: %s\n' \
            "$stage" >&2
        exit 1
    fi
}

require_exact_line "dotnet-runtime=$runtime_version"
require_exact_line "component-sha256=$component_sha"
require_exact_line "world-wit-sha256=$wit_sha"
require_exact_line 'emit=failed type=System.NotSupportedException'
require_exact_line \
    "Anonymous variant types not supported in v0.2 (case 'kv' of variant 'workload-error')."
require_stack_stage \
    'Wacs.ComponentModel.Harness.Lib.WitTypeEmit.MapClrType'
require_stack_stage \
    'Wacs.ComponentModel.Harness.Lib.WitTypeEmit.PopulateVariant'
require_stack_stage \
    'Wacs.ComponentModel.Harness.Lib.HarnessEmitter.EmitInMemory'
if grep -Fq 'emit=passed' "$work/output"; then
    cat "$work/output" >&2
    printf '%s\n' 'typed harness unexpectedly reported success' >&2
    exit 1
fi

cat "$work/output"
printf '%s\n' \
    'typed-harness-stage=world-type-emission/anonymous-variant result=unsupported'
printf '%s\n' 'decision=no-go'
