#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/wacogo-build-sidecar.sh \
  --go-archive GO_ARCHIVE --go GO \
  --module-zip WACOGO_MODULE_ZIP --module-cache GOMODCACHE

Builds the production wacogo sidecar from the canonical source lock and only
pre-fetched local inputs. The script performs two independent staged builds,
requires byte-identical output, and atomically publishes the locked binary and
build receipt under target/visa-wacogo/.

Environment fallbacks:
  VISA_WACOGO_GO_ARCHIVE
  VISA_WACOGO_GO
  VISA_WACOGO_MODULE_ZIP
  VISA_WACOGO_GOMODCACHE
EOF
}

fail() {
    printf 'wacogo sidecar build failed: %s\n' "$*" >&2
    exit 1
}

validate_publish_paths() {
    PYTHONDONTWRITEBYTECODE=1 python3 - \
        "$repo_root" "$binary_output" "$receipt_output" <<'PY'
import os
from pathlib import Path
import stat
import sys

repo = Path(sys.argv[1])
try:
    resolved_repo = repo.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"cannot resolve repository root {repo}: {error}")
if not resolved_repo.is_dir():
    raise SystemExit(f"repository root is not a directory: {repo}")

for output in map(Path, sys.argv[2:]):
    try:
        relative = output.relative_to(repo)
    except ValueError:
        raise SystemExit(f"sidecar output escapes repository: {output}")
    if not relative.parts or relative.parts[0] != "target":
        raise SystemExit(f"sidecar output is outside target/: {output}")
    if any(part in {".", ".."} for part in relative.parts):
        raise SystemExit(f"sidecar output contains a non-canonical component: {output}")

    current = repo
    for part in relative.parts[:-1]:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        except OSError as error:
            raise SystemExit(f"cannot inspect sidecar output parent {current}: {error}")
        if stat.S_ISLNK(mode):
            raise SystemExit(f"sidecar output parent contains a symlink: {current}")
        if not stat.S_ISDIR(mode):
            raise SystemExit(f"sidecar output parent is not a directory: {current}")

    try:
        resolved_parent = output.parent.resolve(strict=False)
        resolved_parent.relative_to(resolved_repo)
    except (OSError, ValueError) as error:
        raise SystemExit(f"sidecar output parent escapes repository: {output.parent}: {error}")
PY
}

go_archive=${VISA_WACOGO_GO_ARCHIVE:-}
go_bin=${VISA_WACOGO_GO:-}
module_zip=${VISA_WACOGO_MODULE_ZIP:-}
module_cache=${VISA_WACOGO_GOMODCACHE:-}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --go-archive)
            [[ "$#" -ge 2 ]] || fail '--go-archive requires a path'
            go_archive=$2
            shift 2
            ;;
        --go)
            [[ "$#" -ge 2 ]] || fail '--go requires a path'
            go_bin=$2
            shift 2
            ;;
        --module-zip)
            [[ "$#" -ge 2 ]] || fail '--module-zip requires a path'
            module_zip=$2
            shift 2
            ;;
        --module-cache)
            [[ "$#" -ge 2 ]] || fail '--module-cache requires a path'
            module_cache=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            fail "unknown argument: $1"
            ;;
    esac
done

[[ -n "$go_archive" ]] || fail '--go-archive or VISA_WACOGO_GO_ARCHIVE is required'
[[ -n "$go_bin" ]] || fail '--go or VISA_WACOGO_GO is required'
[[ -n "$module_zip" ]] || fail '--module-zip or VISA_WACOGO_MODULE_ZIP is required'
[[ -n "$module_cache" ]] || fail '--module-cache or VISA_WACOGO_GOMODCACHE is required'

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
source_lock="$repo_root/third_party/wacogo/source-lock.json"
sidecar_source="$repo_root/crates/runtime/visa_wacogo/sidecar"

module_cache=$(
    PYTHONDONTWRITEBYTECODE=1 python3 - "$module_cache" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1]).expanduser()
try:
    resolved = path.resolve(strict=True)
except OSError as error:
    raise SystemExit(f"cannot resolve module cache {path}: {error}")
if not resolved.is_dir() or path.is_symlink():
    raise SystemExit(f"module cache must be a non-symlink directory: {path}")
print(resolved)
PY
)

mapfile -t locked < <(
    PYTHONDONTWRITEBYTECODE=1 python3 - "$source_lock" <<'PY'
import json
from pathlib import Path
import sys

lock = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
sidecar = lock["production_artifacts"]["sidecar"]
binary = sidecar["binary"]
go_module = sidecar["go_module"]
print(binary["file"])
print(binary["size"])
print(binary["sha256"])
print(go_module["directory"])
print(sidecar["module_path"])
print(sidecar["entry_package"])
print(sidecar["protocol_version"])
print(sidecar["carrier_version"])
print(sidecar["carrier_magic"])
PY
)
[[ "${#locked[@]}" -eq 9 ]] || fail 'cannot read production sidecar identity from source lock'
binary_relative=${locked[0]}
expected_binary_size=${locked[1]}
expected_binary_sha=${locked[2]}
sidecar_relative=${locked[3]}
expected_module=${locked[4]}
entry_package=${locked[5]}
expected_protocol=${locked[6]}
expected_carrier=${locked[7]}
expected_magic=${locked[8]}

[[ "$sidecar_source" == "$repo_root/$sidecar_relative" ]] \
    || fail 'source-lock Go module directory does not name the production sidecar source'
[[ "$binary_relative" == target/* ]] || fail 'locked sidecar output must remain under target/'
binary_output="$repo_root/$binary_relative"
receipt_output="$repo_root/target/visa-wacogo/build-receipt.json"
validate_publish_paths

PYTHONDONTWRITEBYTECODE=1 "$repo_root/scripts/wacogo-prepare-source.py" check
PYTHONDONTWRITEBYTECODE=1 "$repo_root/scripts/wacogo-check-toolchain.py" \
    --archive "$go_archive" --go "$go_bin"

go_bin=$(
    PYTHONDONTWRITEBYTECODE=1 python3 - "$go_bin" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve(strict=True))
PY
)
gofmt_bin="$(dirname -- "$go_bin")/gofmt"
[[ -f "$gofmt_bin" && ! -L "$gofmt_bin" ]] || fail "locked gofmt is unavailable: $gofmt_bin"
[[ -d "$sidecar_source" && ! -L "$sidecar_source" ]] \
    || fail "production sidecar source is not a non-symlink directory: $sidecar_source"
if find "$sidecar_source" -type l -print -quit | grep -q .; then
    fail 'production sidecar source contains a symlink'
fi
if find "$sidecar_source" ! -type f ! -type d -print -quit | grep -q .; then
    fail 'production sidecar source contains a special file'
fi
if grep -R '"github.com/partite-ai/wacogo/internal/' "$sidecar_source" --include='*.go' >/dev/null; then
    fail 'production sidecar directly imports a private wacogo package'
fi

stage=$(mktemp -d "${TMPDIR:-/tmp}/visa-wacogo-build.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
format_diff="$stage/gofmt.diff"
find "$sidecar_source" -type f -name '*.go' -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 "$gofmt_bin" -d >"$format_diff"
if [[ -s "$format_diff" ]]; then
    sed -n '1,240p' "$format_diff" >&2
    fail 'production sidecar Go sources are not gofmt-clean'
fi
printf '%s\n' 'wacogo-sidecar-gofmt=passed'

prepare_build_tree() {
    local name=$1
    local root="$stage/$name"
    mkdir -p "$root/sidecar" "$root/home" "$root/tmp" "$root/go-build-cache"
    cp -R "$sidecar_source/." "$root/sidecar/"
    PYTHONDONTWRITEBYTECODE=1 "$repo_root/scripts/wacogo-prepare-source.py" prepare \
        --module-zip "$module_zip" --output "$root/wacogo" >"$root/source-receipt.json"
    run_go "$root" mod edit -replace=github.com/partite-ai/wacogo=../wacogo
}

run_go() {
    local root=$1
    shift
    (
        cd "$root/sidecar"
        env -i \
            PATH=/usr/bin:/bin \
            HOME="$root/home" \
            TMPDIR="$root/tmp" \
            GOTOOLCHAIN=local \
            GOENV=off \
            GOWORK=off \
            GOPROXY=off \
            GOSUMDB=off \
            GOTELEMETRY=off \
            GOVCS='*:off' \
            CGO_ENABLED=0 \
            GOOS=linux \
            GOARCH=amd64 \
            GOAMD64=v1 \
            GOMODCACHE="$module_cache" \
            GOCACHE="$root/go-build-cache" \
            "$go_bin" "$@"
    )
}

prepare_build_tree build-a
prepare_build_tree build-b

run_go "$stage/build-a" mod verify
run_go "$stage/build-a" test -mod=readonly ./...
printf '%s\n' 'wacogo-sidecar-tests=passed'

imports="$stage/direct-imports.txt"
run_go "$stage/build-a" list -mod=readonly \
    -f '{{.ImportPath}}|{{join .Imports " "}}' ./... >"$imports"
PYTHONDONTWRITEBYTECODE=1 python3 - "$imports" <<'PY'
from pathlib import Path
import sys

allowed = {
    "github.com/partite-ai/wacogo",
    "github.com/partite-ai/wacogo/host",
}
observed: set[str] = set()
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    package, separator, imports = line.partition("|")
    if not separator:
        raise SystemExit(f"malformed go list import record: {line!r}")
    for imported in imports.split():
        if imported.startswith("github.com/partite-ai/wacogo"):
            if imported not in allowed:
                raise SystemExit(f"private or unapproved direct wacogo import in {package}: {imported}")
            observed.add(imported)
if observed != allowed:
    raise SystemExit(f"expected both public wacogo imports, observed {sorted(observed)}")
PY
printf '%s\n' 'wacogo-sidecar-public-imports=wacogo,wacogo/host no-internal=true'

closure="$stage/executable-module-closure.txt"
run_go "$stage/build-a" list -mod=readonly -deps \
    -f '{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{if .Module.Replace}}{{.Module.Replace.Path}}{{end}}{{end}}' \
    "$entry_package" \
    | sed '/^$/d' \
    | LC_ALL=C sort -u >"$closure"
PYTHONDONTWRITEBYTECODE=1 python3 - "$source_lock" "$closure" <<'PY'
import json
from pathlib import Path
import sys

lock = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
records = lock["production_artifacts"]["sidecar"]["executable_module_closure"]
expected = sorted(
    (record["path"], record["version"], record.get("replacement", ""))
    for record in records
)
observed = []
for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    fields = line.split("|")
    if len(fields) != 3:
        raise SystemExit(f"malformed executable module record: {line!r}")
    observed.append(tuple(fields))
if observed != expected:
    raise SystemExit(f"executable module closure mismatch: expected {expected}, observed {observed}")
if any("wasmtime" in path for path, _, _ in observed):
    raise SystemExit("forbidden Wasmtime module in executable closure")

sum_lines = {}
go_sum_path = Path(lock["production_artifacts"]["sidecar"]["go_module"]["go_sum"]["file"])
if not go_sum_path.is_absolute():
    go_sum_path = Path(sys.argv[1]).resolve().parents[2] / go_sum_path
for line in go_sum_path.read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) == 3 and not fields[1].endswith("/go.mod"):
        sum_lines[(fields[0], fields[1])] = fields[2]
for record in records:
    expected_sum = record.get("sum")
    if expected_sum is None:
        continue
    observed_sum = sum_lines.get((record["path"], record["version"]))
    if observed_sum != expected_sum:
        raise SystemExit(
            f"Go sum mismatch for {record['path']} {record['version']}: "
            f"expected {expected_sum}, observed {observed_sum}"
        )
PY
printf '%s\n' 'wacogo-sidecar-executable-closure=4 no-wasmtime=true relative-replacement=true'

for name in build-a build-b; do
    run_go "$stage/$name" build \
        -mod=readonly \
        -trimpath \
        -buildvcs=false \
        -ldflags='-s -w -buildid=' \
        -o "$stage/$name/visa-wacogo-runtime" \
        "$entry_package"
done
cmp "$stage/build-a/visa-wacogo-runtime" "$stage/build-b/visa-wacogo-runtime" \
    || fail 'independent sidecar builds are not byte-identical'

built_binary="$stage/build-a/visa-wacogo-runtime"
observed_binary_size=$(stat -c '%s' "$built_binary")
observed_binary_sha=$(sha256sum "$built_binary" | cut -d' ' -f1)
[[ "$observed_binary_size" == "$expected_binary_size" ]] \
    || fail "sidecar size mismatch: expected $expected_binary_size, observed $observed_binary_size"
[[ "$observed_binary_sha" == "$expected_binary_sha" ]] \
    || fail "sidecar SHA-256 mismatch: expected $expected_binary_sha, observed $observed_binary_sha"

build_info="$stage/go-version-m.txt"
"$go_bin" version -m "$built_binary" >"$build_info"
PYTHONDONTWRITEBYTECODE=1 python3 - \
    "$build_info" "$expected_module" "$entry_package" \
    "$expected_protocol" "$expected_carrier" "$expected_magic" <<'PY'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
module = sys.argv[2]
entry = sys.argv[3].removeprefix("./")
expected_fragments = {
    f"path\t{module}/{entry}",
    f"mod\t{module}\t(devel)\t",
    "build\t-trimpath=true",
    "build\tCGO_ENABLED=0",
    "build\tGOARCH=amd64",
    "build\tGOOS=linux",
    "build\tGOAMD64=v1",
}
stripped = {line.lstrip() for line in lines}
missing = expected_fragments - stripped
if missing:
    raise SystemExit(f"sidecar build info is missing locked fields: {sorted(missing)}")
if any("vcs." in line for line in stripped):
    raise SystemExit("sidecar build info unexpectedly contains VCS metadata")
if not any(
    line.startswith("dep\tgithub.com/partite-ai/wacogo\tv0.0.0-20260617023329-3de16a61796c")
    for line in stripped
):
    raise SystemExit("sidecar build info is missing the locked wacogo dependency")
if "=>\t../wacogo\t(devel)\t" not in stripped:
    raise SystemExit("sidecar build info is missing the relative patched-wacogo replacement")
if sys.argv[4] != "1" or sys.argv[5] != "owned-component-stdin-frame-v1" or sys.argv[6] != "VISAWCG1":
    raise SystemExit("source-lock protocol/carrier identity is not the accepted production identity")
PY

binary_description=$(file -b "$built_binary")
case "$binary_description" in
    *"ELF 64-bit"*"x86-64"*"statically linked"*"stripped"*) ;;
    *) fail "sidecar is not a stripped static x86-64 ELF: $binary_description" ;;
esac
printf 'wacogo-sidecar-reproducible-build=passed builds=2 size=%s sha256=%s\n' \
    "$observed_binary_size" "$observed_binary_sha"

output_parent=$(dirname -- "$binary_output")
receipt_parent=$(dirname -- "$receipt_output")
validate_publish_paths
mkdir -p "$output_parent" "$receipt_parent"
validate_publish_paths
if [[ -e "$binary_output" || -L "$binary_output" ]]; then
    [[ -f "$binary_output" && ! -L "$binary_output" ]] \
        || fail "refusing to replace a non-regular output: $binary_output"
fi
binary_temporary=$(mktemp "$output_parent/.visa-wacogo-runtime.XXXXXX")
cp "$built_binary" "$binary_temporary"
chmod 0755 "$binary_temporary"
mv -f "$binary_temporary" "$binary_output"

receipt_temporary=$(mktemp "$receipt_parent/.wacogo-build-receipt.XXXXXX")
PYTHONDONTWRITEBYTECODE=1 python3 - \
    "$source_lock" "$binary_relative" "$observed_binary_size" "$observed_binary_sha" \
    >"$receipt_temporary" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

lock_path = Path(sys.argv[1])
lock = json.loads(lock_path.read_text(encoding="utf-8"))
sidecar = lock["production_artifacts"]["sidecar"]
receipt = {
    "schema": "visa.wacogo-sidecar-build-receipt.v1",
    "source_lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
    "derivative_id": lock["derivative"]["id"],
    "accepted_component": sidecar["accepted_component"],
    "execution_host_requirements": sidecar["execution_host_requirements"],
    "upstream_module_zip_sha256": lock["upstream"]["module_zip"]["sha256"],
    "patchset_sha256": lock["patchset"]["ordered_concatenation_sha256"],
    "patched_source_tree_sha256": lock["patchset"]["post_patch_tree"]["sha256"],
    "go_archive_sha256": lock["build_toolchain"]["go"]["archive_sha256"],
    "go_binary_sha256": lock["build_toolchain"]["go"]["binary_sha256"],
    "go_mod_sha256": sidecar["go_module"]["go_mod"]["sha256"],
    "go_sum_sha256": sidecar["go_module"]["go_sum"]["sha256"],
    "go_source_tree": sidecar["go_module"]["source_tree"],
    "generated_bindings_sha256": sidecar["generated_bindings"][
        "ordered_concatenation_sha256"
    ],
    "go_build_flags": lock["build_policy"]["go_build_flags"],
    "go_linker_flags": lock["build_policy"]["go_linker_flags"],
    "executable_module_closure": sidecar["executable_module_closure"],
    "protocol_version": sidecar["protocol_version"],
    "carrier_version": sidecar["carrier_version"],
    "carrier_magic": sidecar["carrier_magic"],
    "binary": {
        "file": sys.argv[2],
        "size": int(sys.argv[3]),
        "sha256": sys.argv[4],
    },
    "independent_builds": 2,
    "gates": {
        "byte_identical_rebuild": "passed",
        "execution_host_requirements_locked": "passed",
        "generated_binding_identity": "passed",
        "gofmt": "passed",
        "go_test_all": "passed",
        "module_verify": "passed",
        "no_wasmtime_executable_lineage": "passed",
        "official_go_toolchain": "passed",
        "patched_source_identity": "passed",
        "public_wacogo_imports_only": "passed",
        "static_stripped_linux_amd64": "passed",
    },
}
json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
chmod 0644 "$receipt_temporary"
mv -f "$receipt_temporary" "$receipt_output"

printf 'wacogo-sidecar-artifact=%s\n' "$binary_output"
printf 'wacogo-sidecar-receipt=%s\n' "$receipt_output"
