#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/run-strict-stage2-local-gate.sh [OPTIONS]

Runs the locked local Strict Stage 2 gate in this fixed order:
  official Go toolchain -> source lock -> exact Component -> selected Wacogo
  qualification -> reproducible sidecar -> focused real-Wacogo failures ->
  Wacogo same-path run and independent verifier -> strict four-cell run and
  independent verifier.

Options:
  --artifact-root ROOT  New or existing empty output directory. If omitted,
                        create target/visa-system/strict-stage2-local-XXXXXX.
  --go-archive FILE     Prefetched official go1.26.5 linux/amd64 archive.
  --go FILE             go executable extracted from that archive.
  --module-zip FILE     Prefetched pinned partite-ai/wacogo module zip.
  --module-cache DIR    Prefetched GOMODCACHE used with all network disabled.
  --component FILE      Exact locked Component. If omitted, build visa-system
                        and discover the byte-identical build-script output.
  --dry-run             Print the locked plan without validating inputs,
                        creating artifacts, building, or executing tests.
  -h, --help            Show this help.

Environment fallbacks:
  VISA_WACOGO_GO_ARCHIVE
  VISA_WACOGO_GO
  VISA_WACOGO_MODULE_ZIP
  VISA_WACOGO_GOMODCACHE
  VISA_WACOGO_COMPONENT

The gate never downloads inputs. Failure retains ROOT/incomplete, all logs,
the gate status, and any partial same-path or strict evidence. Only complete
success removes ROOT/incomplete. The built sidecar and receipt are copied into
ROOT/qualification before any focused or system execution uses them.
EOF
}

usage_error() {
    printf 'strict Stage 2 local gate: %s\n' "$*" >&2
    usage
    exit 64
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)

artifact_root_input=""
go_archive=${VISA_WACOGO_GO_ARCHIVE:-}
go_bin=${VISA_WACOGO_GO:-}
module_zip=${VISA_WACOGO_MODULE_ZIP:-}
module_cache=${VISA_WACOGO_GOMODCACHE:-}
component_input=${VISA_WACOGO_COMPONENT:-}
dry_run=0

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --artifact-root)
            [[ "$#" -ge 2 ]] || usage_error '--artifact-root requires a path'
            artifact_root_input=$2
            shift 2
            ;;
        --go-archive)
            [[ "$#" -ge 2 ]] || usage_error '--go-archive requires a path'
            go_archive=$2
            shift 2
            ;;
        --go)
            [[ "$#" -ge 2 ]] || usage_error '--go requires a path'
            go_bin=$2
            shift 2
            ;;
        --module-zip)
            [[ "$#" -ge 2 ]] || usage_error '--module-zip requires a path'
            module_zip=$2
            shift 2
            ;;
        --module-cache)
            [[ "$#" -ge 2 ]] || usage_error '--module-cache requires a path'
            module_cache=$2
            shift 2
            ;;
        --component)
            [[ "$#" -ge 2 ]] || usage_error '--component requires a path'
            component_input=$2
            shift 2
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage_error "unknown argument: $1"
            ;;
    esac
done

if [[ "$dry_run" -eq 1 ]]; then
    printf 'dry-run=true\n'
    printf 'artifact-root=%s\n' "${artifact_root_input:-<auto-under-target/visa-system>}"
    printf 'go-archive=%s\n' "${go_archive:-<required>}"
    printf 'go=%s\n' "${go_bin:-<required>}"
    printf 'module-zip=%s\n' "${module_zip:-<required>}"
    printf 'module-cache=%s\n' "${module_cache:-<required>}"
    printf 'component=%s\n' "${component_input:-<build-and-discover>}"
    printf '%s\n' \
        'gate-order=toolchain,source-lock,component,selected-qualification,sidecar-build,retain-sidecar-output,live-sidecar-focused,focused-real-wacogo,same-path-run,same-path-verifier,strict-runner,strict-verifier'
    exit 0
fi

cd "$repo_root"
umask 077

prepare_artifact_root() {
    local requested=$1
    local parent
    local first_entry

    if [[ -z "$requested" ]]; then
        parent="$repo_root/target/visa-system"
        mkdir -p -- "$parent"
        [[ -d "$parent" && ! -L "$parent" ]] \
            || usage_error "default artifact parent is not a non-symlink directory: $parent"
        artifact_root=$(mktemp -d "$parent/strict-stage2-local-XXXXXX")
        return
    fi

    if [[ -e "$requested" || -L "$requested" ]]; then
        [[ -d "$requested" && ! -L "$requested" ]] \
            || usage_error "artifact root must be a non-symlink directory: $requested"
        if ! first_entry=$(find "$requested" -mindepth 1 -maxdepth 1 -print -quit); then
            usage_error "cannot inspect existing artifact root for emptiness: $requested"
        fi
        if [[ -n "$first_entry" ]]; then
            usage_error "existing artifact root must be empty: $requested"
        fi
        artifact_root=$(realpath -e -- "$requested")
        chmod 700 -- "$artifact_root"
        return
    fi

    parent=$(dirname -- "$requested")
    [[ -d "$parent" && ! -L "$parent" ]] \
        || usage_error "artifact root parent must already be a non-symlink directory: $parent"
    parent=$(realpath -e -- "$parent")
    requested="$parent/$(basename -- "$requested")"
    mkdir -m 700 -- "$requested"
    artifact_root=$(realpath -e -- "$requested")
}

prepare_artifact_root "$artifact_root_input"

incomplete_marker="$artifact_root/incomplete"
status_path="$artifact_root/gate-status.env"
logs_root="$artifact_root/logs"
qualification_root="$artifact_root/qualification"
same_path_root="$artifact_root/same-path"
strict_root="$artifact_root/strict"
same_path_evidence="$same_path_root/stage1-evidence.json"
strict_evidence="$strict_root/stage2-evidence.json"
strict_manifest="$strict_root/stage2-matrix-manifest.json"
strict_runner_marker="$strict_root/stage2-incomplete"
published_sidecar="$repo_root/target/visa-wacogo/visa-wacogo-runtime"
published_build_receipt="$repo_root/target/visa-wacogo/build-receipt.json"
qualified_component="$qualification_root/component.wasm"
retained_sidecar="$qualification_root/visa-wacogo-runtime"
retained_build_receipt="$qualification_root/build-receipt.json"

current_gate=setup
last_completed_gate=none
failed_gate=none
gate_exit_code=""
completed=0

write_status() {
    local state=$1
    local temporary="$status_path.tmp"
    {
        printf 'status=%s\n' "$state"
        printf 'current-gate=%s\n' "$current_gate"
        printf 'last-completed-gate=%s\n' "$last_completed_gate"
        printf 'failed-gate=%s\n' "$failed_gate"
        printf 'exit-code=%s\n' "$gate_exit_code"
    } >"$temporary"
    mv -f -- "$temporary" "$status_path"
}

path_state() {
    local key=$1
    local path=$2
    if [[ -f "$path" && ! -L "$path" ]]; then
        printf '%s=%s state=present\n' "$key" "$path" >&2
    else
        printf '%s=%s state=absent\n' "$key" "$path" >&2
    fi
}

report_partial_evidence() {
    local -a roots=()
    local path
    local found=0
    local cell_found=0
    [[ -d "$same_path_root" && ! -L "$same_path_root" ]] && roots+=("$same_path_root")
    [[ -d "$strict_root" && ! -L "$strict_root" ]] && roots+=("$strict_root")
    if [[ "${#roots[@]}" -gt 0 ]]; then
        while IFS= read -r path; do
            printf 'partial-evidence=%s\n' "$path" >&2
            found=1
        done < <(
            find "${roots[@]}" -type f \
                \( -name 'stage1-evidence.json' \
                -o -name 'stage2-evidence.json' \
                -o -name 'stage2-matrix-manifest.json' \
                -o -name 'stage2-incomplete' \) -print \
                | LC_ALL=C sort
        )
    fi
    if [[ "$found" -eq 0 ]]; then
        printf '%s\n' 'partial-evidence=none' >&2
    fi
    if [[ -d "$strict_root/cells" && ! -L "$strict_root/cells" ]]; then
        while IFS= read -r path; do
            printf 'partial-cell-root=%s\n' "$path" >&2
            cell_found=1
        done < <(
            find "$strict_root/cells" -mindepth 1 -maxdepth 1 -type d -print \
                | LC_ALL=C sort
        )
    fi
    if [[ "$cell_found" -eq 0 ]]; then
        printf '%s\n' 'partial-cell-root=none' >&2
    fi
}

on_exit() {
    local status=$?
    trap - EXIT
    set +e
    if [[ "$completed" -ne 1 ]]; then
        if [[ "$status" -eq 0 ]]; then
            status=1
        fi
        gate_exit_code=$status
        if [[ "$failed_gate" == none ]]; then
            failed_gate=$current_gate
        fi
        current_gate=none
        if [[ ! -e "$incomplete_marker" && ! -L "$incomplete_marker" ]]; then
            printf '%s\n' 'strict-stage2-local-gate=incomplete' >"$incomplete_marker"
        fi
        write_status failed
        printf '%s\n' 'ERROR: locked Strict Stage 2 local gate failed; partial evidence retained' >&2
        printf 'artifact-root=%s\n' "$artifact_root" >&2
        printf 'incomplete-marker=%s\n' "$incomplete_marker" >&2
        printf 'gate-status=%s\n' "$status_path" >&2
        printf 'last-completed-gate=%s\n' "$last_completed_gate" >&2
        printf 'failed-gate=%s\n' "$failed_gate" >&2
        printf 'exit-code=%s\n' "$status" >&2
        path_state same-path-evidence "$same_path_evidence"
        path_state strict-evidence "$strict_evidence"
        path_state strict-manifest "$strict_manifest"
        path_state strict-runner-incomplete "$strict_runner_marker"
        path_state sidecar "$retained_sidecar"
        path_state build-receipt "$retained_build_receipt"
        path_state published-sidecar "$published_sidecar"
        path_state published-build-receipt "$published_build_receipt"
        report_partial_evidence
        printf 'logs=%s\n' "$logs_root" >&2
    fi
    return "$status"
}

trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'artifact-root=%s\n' "$artifact_root"
mkdir -m 700 -- "$logs_root" "$qualification_root"
printf '%s\n' 'strict-stage2-local-gate=incomplete' >"$incomplete_marker"
write_status running

fail() {
    printf 'strict Stage 2 local gate failed: %s\n' "$*" >&2
    failed_gate=$current_gate
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

require_regular_file() {
    local description=$1
    local path=$2
    [[ -f "$path" && ! -L "$path" ]] \
        || fail "$description must be a non-symlink regular file: $path"
}

require_directory() {
    local description=$1
    local path=$2
    [[ -d "$path" && ! -L "$path" ]] \
        || fail "$description must be a non-symlink directory: $path"
}

canonical_file() {
    local description=$1
    local path=$2
    require_regular_file "$description" "$path"
    realpath -e -- "$path"
}

canonical_directory() {
    local description=$1
    local path=$2
    require_directory "$description" "$path"
    realpath -e -- "$path"
}

validate_publish_directories() {
    PYTHONDONTWRITEBYTECODE=1 python3 - "$repo_root" <<'PY'
import os
from pathlib import Path
import stat
import sys

repo = Path(sys.argv[1])
for description, path in (
    ("repository root", repo),
    ("repository target directory", repo / "target"),
    ("Wacogo publication directory", repo / "target" / "visa-wacogo"),
):
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        if path == repo:
            raise SystemExit(f"{description} is missing: {path}")
        continue
    except OSError as error:
        raise SystemExit(f"cannot lstat {description} {path}: {error}")
    if stat.S_ISLNK(mode):
        raise SystemExit(f"{description} must not be a symlink: {path}")
    if not stat.S_ISDIR(mode):
        raise SystemExit(f"{description} must be a directory: {path}")
PY
}

verify_locked_sidecar() {
    local path=$1
    local observed_size
    local observed_sha
    require_regular_file 'locked Wacogo sidecar' "$path"
    observed_size=$(wc -c <"$path" | tr -d '[:space:]')
    observed_sha=$(sha256sum "$path" | cut -d' ' -f1)
    [[ "$observed_size" == 6754430 ]] \
        || fail "Wacogo sidecar size mismatch: expected 6754430, observed $observed_size"
    [[ "$observed_sha" == \
        7dd8365e5132fcd32f92ac89d8d1b78b80ec1d285730d8e43b360de6378a0606 ]] \
        || fail "Wacogo sidecar SHA-256 mismatch: $observed_sha"
}

capture_sidecar_outputs() {
    local retained
    local retained_sha
    validate_publish_directories \
        || fail 'unsafe Wacogo publication directory; refusing to retain build outputs'
    require_regular_file 'published Wacogo sidecar' "$published_sidecar"
    require_regular_file 'published Wacogo build receipt' "$published_build_receipt"
    for retained in "$retained_sidecar" "$retained_build_receipt"; do
        [[ ! -e "$retained" && ! -L "$retained" ]] \
            || fail "refusing to replace a retained Wacogo artifact: $retained"
    done

    install -m 700 -- "$published_sidecar" "$retained_sidecar"
    install -m 600 -- "$published_build_receipt" "$retained_build_receipt"
    require_regular_file 'retained Wacogo sidecar' "$retained_sidecar"
    require_regular_file 'retained Wacogo build receipt' "$retained_build_receipt"
    cmp -s -- "$published_sidecar" "$retained_sidecar" \
        || fail 'retained Wacogo sidecar differs from the published build output'
    cmp -s -- "$published_build_receipt" "$retained_build_receipt" \
        || fail 'retained Wacogo receipt differs from the published build output'
    verify_locked_sidecar "$published_sidecar"
    verify_locked_sidecar "$retained_sidecar"
    retained_sha=$(sha256sum "$retained_sidecar" | cut -d' ' -f1)

    PYTHONDONTWRITEBYTECODE=1 python3 - \
        "$retained_build_receipt" "$retained_sha" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
try:
    receipt = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"cannot decode retained Wacogo build receipt: {error}")
if receipt.get("schema") != "visa.wacogo-sidecar-build-receipt.v1":
    raise SystemExit("retained Wacogo build receipt has the wrong schema")
expected_binary = {
    "file": "target/visa-wacogo/visa-wacogo-runtime",
    "size": 6754430,
    "sha256": sys.argv[2],
}
if receipt.get("binary") != expected_binary:
    raise SystemExit(
        f"retained Wacogo build receipt has the wrong binary identity: {receipt.get('binary')!r}"
    )
if receipt.get("independent_builds") != 2:
    raise SystemExit("retained Wacogo build receipt did not record two independent builds")
gates = receipt.get("gates")
if not isinstance(gates, dict) or not gates or set(gates.values()) != {"passed"}:
    raise SystemExit("retained Wacogo build receipt contains an incomplete gate result")
PY

    printf 'retained-sidecar=%s sha256=%s\n' "$retained_sidecar" "$retained_sha"
    printf 'retained-build-receipt=%s sha256=%s\n' \
        "$retained_build_receipt" \
        "$(sha256sum "$retained_build_receipt" | cut -d' ' -f1)"
}

run_gate() {
    local gate_id=$1
    local label=$2
    shift 2
    local log_path="$logs_root/$gate_id.log"
    local -a pipeline_status
    local command_status
    local tee_status
    local status

    current_gate=$gate_id
    failed_gate=none
    gate_exit_code=""
    write_status running

    printf '\n==> %s\n' "$label"
    printf '+'
    printf ' %q' "$@"
    printf '\n'

    set +e
    "$@" 2>&1 | tee "$log_path"
    pipeline_status=("${PIPESTATUS[@]}")
    set -e
    command_status=${pipeline_status[0]}
    tee_status=${pipeline_status[1]}
    status=$command_status
    if [[ "$status" -eq 0 && "$tee_status" -ne 0 ]]; then
        status=$tee_status
    fi

    if [[ "$status" -ne 0 ]]; then
        failed_gate=$gate_id
        gate_exit_code=$status
        write_status failed
        printf 'ERROR: %s failed with exit %s (log: %s)\n' \
            "$label" "$status" "$log_path" >&2
        return "$status"
    fi

    last_completed_gate=$gate_id
    current_gate=none
    write_status running
    printf 'ok: %s\n' "$label"
}

verify_locked_component() {
    local path=$1
    local expected_sha=4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b
    local observed_size
    local observed_sha
    require_regular_file 'Strict Stage 2 Component' "$path"
    observed_size=$(wc -c <"$path" | tr -d '[:space:]')
    observed_sha=$(sha256sum "$path" | cut -d' ' -f1)
    [[ "$observed_size" == 146486 ]] \
        || fail "Component size mismatch: expected 146486, observed $observed_size"
    [[ "$observed_sha" == "$expected_sha" ]] \
        || fail "Component SHA-256 mismatch: expected $expected_sha, observed $observed_sha"
}

configure_component_build_environment() {
    local configured_cargo_home=${CARGO_HOME:-}
    local configured_rustup_home=${RUSTUP_HOME:-}
    local canonical_cargo_home
    local canonical_rustup_home
    local record_path="$qualification_root/component-build-environment.env"

    if [[ -z "$configured_cargo_home" ]]; then
        [[ -n "${HOME:-}" ]] \
            || fail 'HOME is required when CARGO_HOME is unset or empty'
        configured_cargo_home=$HOME/.cargo
    fi
    if [[ -z "$configured_rustup_home" ]]; then
        [[ -n "${HOME:-}" ]] \
            || fail 'HOME is required when RUSTUP_HOME is unset or empty'
        configured_rustup_home=$HOME/.rustup
    fi

    [[ "$configured_cargo_home" != *[[:space:][:cntrl:]]* ]] \
        || fail "CARGO_HOME cannot be encoded safely in locked rustflags: $configured_cargo_home"
    [[ "$configured_rustup_home" != *[[:space:][:cntrl:]]* ]] \
        || fail "RUSTUP_HOME cannot be encoded safely in locked rustflags: $configured_rustup_home"
    [[ "$configured_cargo_home" != *'='* ]] \
        || fail "CARGO_HOME cannot contain '=' in locked rustflags: $configured_cargo_home"
    [[ "$configured_rustup_home" != *'='* ]] \
        || fail "RUSTUP_HOME cannot contain '=' in locked rustflags: $configured_rustup_home"

    canonical_cargo_home=$(canonical_directory 'actual Cargo home' "$configured_cargo_home")
    canonical_rustup_home=$(canonical_directory 'actual Rustup home' "$configured_rustup_home")
    [[ "$canonical_cargo_home" == /* && "$canonical_cargo_home" != / ]] \
        || fail "actual Cargo home is not a safe absolute remap source: $canonical_cargo_home"
    [[ "$canonical_rustup_home" == /* && "$canonical_rustup_home" != / ]] \
        || fail "actual Rustup home is not a safe absolute remap source: $canonical_rustup_home"
    [[ "$canonical_cargo_home" != *[[:space:][:cntrl:]]* ]] \
        || fail "canonical Cargo home cannot be encoded safely in locked rustflags: $canonical_cargo_home"
    [[ "$canonical_rustup_home" != *[[:space:][:cntrl:]]* ]] \
        || fail "canonical Rustup home cannot be encoded safely in locked rustflags: $canonical_rustup_home"
    [[ "$canonical_cargo_home" != *'='* ]] \
        || fail "canonical Cargo home cannot contain '=' in locked rustflags: $canonical_cargo_home"
    [[ "$canonical_rustup_home" != *'='* ]] \
        || fail "canonical Rustup home cannot contain '=' in locked rustflags: $canonical_rustup_home"
    [[ "$canonical_cargo_home" != "$canonical_rustup_home" ]] \
        || fail 'actual Cargo and Rustup homes must be distinct remap sources'
    [[ "$canonical_cargo_home/" != "$canonical_rustup_home/"* ]] \
        || fail 'actual Cargo home must not be nested under the Rustup home'
    [[ "$canonical_rustup_home/" != "$canonical_cargo_home/"* ]] \
        || fail 'actual Rustup home must not be nested under the Cargo home'

    component_cargo_home=$canonical_cargo_home
    component_rustup_home=$canonical_rustup_home
    component_target_rustflags="-C target-feature=-bulk-memory,-multivalue,-reference-types,-sign-ext,-nontrapping-fptoint --remap-path-prefix=$component_cargo_home=/home/ava/.cargo --remap-path-prefix=$component_rustup_home=/home/ava/.rustup"

    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
    unset CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS
    CARGO_HOME=$component_cargo_home
    RUSTUP_HOME=$component_rustup_home
    CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS=$component_target_rustflags
    export CARGO_HOME RUSTUP_HOME CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS

    {
        printf '%s\n' 'schema=visa.strict-stage2-component-build-environment.v1'
        printf 'cargo-home.input=%s\n' "$configured_cargo_home"
        printf 'cargo-home.canonical=%s\n' "$component_cargo_home"
        printf '%s\n' 'cargo-home.remapped=/home/ava/.cargo'
        printf 'rustup-home.input=%s\n' "$configured_rustup_home"
        printf 'rustup-home.canonical=%s\n' "$component_rustup_home"
        printf '%s\n' 'rustup-home.remapped=/home/ava/.rustup'
        printf '%s\n' 'generic-rustflags=unset'
        printf 'target-rustflags=%s\n' "$component_target_rustflags"
    } >"$record_path"
    chmod 600 -- "$record_path"

    printf 'component-cargo-home=%s remapped-to=/home/ava/.cargo\n' "$component_cargo_home"
    printf 'component-rustup-home=%s remapped-to=/home/ava/.rustup\n' "$component_rustup_home"
    printf 'component-build-environment=%s sha256=%s\n' \
        "$record_path" "$(sha256sum "$record_path" | cut -d' ' -f1)"
}

prepare_component() {
    local source=$component_input
    local cargo_metadata_path="$qualification_root/component-cargo-metadata.json"
    local cargo_messages_path="$qualification_root/component-cargo-messages.jsonl"
    local cargo_stderr_path="$qualification_root/component-cargo-stderr.txt"
    local cargo_diagnostics_path="$qualification_root/component-cargo-diagnostics.txt"
    local cargo_status_path="$qualification_root/component-cargo-status.env"
    local cargo_provenance_path="$qualification_root/component-cargo-provenance.json"
    local cargo_status
    local diagnostics_status

    [[ ! -v RUSTFLAGS && ! -v CARGO_ENCODED_RUSTFLAGS && ! -v CARGO_BUILD_RUSTFLAGS ]] \
        || fail 'inherited generic rustflags were not cleared before Component preparation'
    [[ "${CARGO_HOME:-}" == "$component_cargo_home" ]] \
        || fail 'Cargo home changed after Component build-environment canonicalization'
    [[ "${RUSTUP_HOME:-}" == "$component_rustup_home" ]] \
        || fail 'Rustup home changed after Component build-environment canonicalization'
    [[ "${CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS:-}" == \
        "$component_target_rustflags" ]] \
        || fail 'locked wasm32 Component target rustflags are not active'

    if [[ -z "$source" ]]; then
        cargo metadata --locked --no-deps --format-version 1 >"$cargo_metadata_path"

        set +e
        cargo build --locked -p visa-system --bin visa-system \
            --message-format=json-render-diagnostics \
            >"$cargo_messages_path" 2>"$cargo_stderr_path"
        cargo_status=$?
        set -e
        printf 'cargo-build-exit-code=%s\n' "$cargo_status" >"$cargo_status_path"

        set +e
        PYTHONDONTWRITEBYTECODE=1 python3 - \
            "$cargo_messages_path" "$cargo_stderr_path" "$cargo_diagnostics_path" <<'PY'
import json
from pathlib import Path
import sys

messages_path = Path(sys.argv[1])
stderr_path = Path(sys.argv[2])
diagnostics_path = Path(sys.argv[3])

try:
    stderr = stderr_path.read_text(encoding="utf-8")
except (OSError, UnicodeDecodeError) as error:
    raise SystemExit(f"cannot read Cargo stderr: {error}")

rendered = []
try:
    with messages_path.open(encoding="utf-8") as messages:
        for line_number, line in enumerate(messages, 1):
            try:
                message = json.loads(line)
            except json.JSONDecodeError as error:
                raise SystemExit(
                    f"Cargo JSON line {line_number} is malformed: {error}"
                ) from error
            if message.get("reason") != "compiler-message":
                continue
            diagnostic = message.get("message")
            if isinstance(diagnostic, dict) and isinstance(diagnostic.get("rendered"), str):
                rendered.append(diagnostic["rendered"])
except (OSError, UnicodeDecodeError) as error:
    raise SystemExit(f"cannot read Cargo JSON messages: {error}")

readable = stderr + "".join(rendered)
try:
    diagnostics_path.write_text(readable, encoding="utf-8")
except OSError as error:
    raise SystemExit(f"cannot retain readable Cargo diagnostics: {error}")
sys.stdout.write(readable)
PY
        diagnostics_status=$?
        set -e
        if [[ "$cargo_status" -ne 0 ]]; then
            printf 'cargo build failed with exit %s; raw messages: %s\n' \
                "$cargo_status" "$cargo_messages_path" >&2
            return "$cargo_status"
        fi
        [[ "$diagnostics_status" -eq 0 ]] \
            || fail 'cannot decode successful Cargo build diagnostics'

        PYTHONDONTWRITEBYTECODE=1 python3 - \
            "$repo_root" "$cargo_metadata_path" "$cargo_messages_path" \
            "$cargo_provenance_path" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

repo = Path(sys.argv[1]).resolve(strict=True)
metadata_path = Path(sys.argv[2])
messages_path = Path(sys.argv[3])
provenance_path = Path(sys.argv[4])


def fail(message: str) -> None:
    raise SystemExit(message)


def regular_file(path: Path, description: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"cannot inspect {description} {path}: {error}")
    if not stat.S_ISREG(mode):
        fail(f"{description} must be a non-symlink regular file: {path}")


def directory(path: Path, description: str) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"cannot inspect {description} {path}: {error}")
    if not stat.S_ISDIR(mode):
        fail(f"{description} must be a non-symlink directory: {path}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        fail(f"cannot hash Cargo artifact {path}: {error}")
    return digest.hexdigest()


try:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    fail(f"cannot decode Cargo metadata: {error}")


def package_id(relative_manifest: str) -> str:
    expected = (repo / relative_manifest).resolve(strict=True)
    matches = []
    for package in metadata.get("packages", []):
        manifest = package.get("manifest_path")
        identifier = package.get("id")
        if not isinstance(manifest, str) or not isinstance(identifier, str):
            continue
        try:
            observed = Path(manifest).resolve(strict=True)
        except OSError as error:
            fail(f"cannot canonicalize Cargo manifest {manifest}: {error}")
        if observed == expected:
            matches.append(identifier)
    if len(matches) != 1:
        fail(
            f"Cargo metadata must identify exactly one package for {expected}; "
            f"observed {len(matches)}"
        )
    return matches[0]


visa_system_id = package_id("crates/testing/visa-system/Cargo.toml")
handoff_id = package_id("crates/testing/handoff-component/Cargo.toml")

messages = []
try:
    with messages_path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                messages.append(json.loads(line))
            except json.JSONDecodeError as error:
                fail(f"Cargo JSON line {line_number} is malformed: {error}")
except (OSError, UnicodeDecodeError) as error:
    fail(f"cannot read Cargo JSON messages: {error}")

build_events = [
    message
    for message in messages
    if message.get("reason") == "build-script-executed"
    and message.get("package_id") == visa_system_id
]
if len(build_events) != 1:
    fail(
        "successful Cargo build must emit exactly one visa-system "
        f"build-script-executed event; observed {len(build_events)}"
    )
out_dir_value = build_events[0].get("out_dir")
if not isinstance(out_dir_value, str) or not os.path.isabs(out_dir_value):
    fail(f"visa-system build-script out_dir is not absolute: {out_dir_value!r}")
out_dir = Path(out_dir_value)
directory(out_dir, "visa-system build-script out_dir")

artifact_events = [
    message
    for message in messages
    if message.get("reason") == "compiler-artifact"
    and message.get("package_id") == handoff_id
    and message.get("target", {}).get("name") == "handoff_component"
]
if len(artifact_events) != 1:
    fail(
        "successful Cargo build must emit exactly one handoff-component "
        f"compiler-artifact event; observed {len(artifact_events)}"
    )
wasm_files = [
    Path(value)
    for value in artifact_events[0].get("filenames", [])
    if isinstance(value, str) and value.endswith(".wasm")
]
if len(wasm_files) != 1:
    fail(
        "handoff-component compiler-artifact must contain exactly one wasm file; "
        f"observed {len(wasm_files)}"
    )
raw_component = wasm_files[0]
regular_file(raw_component, "handoff-component raw wasm artifact")
raw_sha = sha256(raw_component)
expected_raw_sha = "282d3086db26cc575208e3f3c1352f8050e5effd29b2a89e6d7c295c5663febb"
if raw_sha != expected_raw_sha:
    fail(
        "handoff-component raw wasm SHA-256 mismatch: "
        f"expected {expected_raw_sha}, observed {raw_sha}"
    )

component = out_dir / "handoff-component.component.wasm"
regular_file(component, "Strict Stage 2 Component from selected Cargo out_dir")
component_sha = sha256(component)
expected_component_sha = "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b"
if component_sha != expected_component_sha:
    fail(
        "Strict Stage 2 Component SHA-256 mismatch in selected Cargo out_dir: "
        f"expected {expected_component_sha}, observed {component_sha}"
    )

provenance = {
    "schema": "visa.strict-stage2-component-cargo-provenance.v1",
    "visa_system": {
        "package_id": visa_system_id,
        "out_dir": os.fspath(out_dir),
    },
    "handoff_component": {
        "package_id": handoff_id,
        "artifact": os.fspath(raw_component),
        "size": raw_component.stat().st_size,
        "sha256": raw_sha,
        "fresh": artifact_events[0].get("fresh"),
    },
    "component": {
        "file": os.fspath(component),
        "size": component.stat().st_size,
        "sha256": component_sha,
    },
    "cargo": {
        "metadata": metadata_path.name,
        "messages": messages_path.name,
    },
}
temporary = provenance_path.with_suffix(provenance_path.suffix + ".tmp")
try:
    temporary.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(provenance_path)
except OSError as error:
    fail(f"cannot retain Component Cargo provenance: {error}")
print(os.fspath(component))
PY
        source=$(PYTHONDONTWRITEBYTECODE=1 python3 - "$cargo_provenance_path" <<'PY'
import json
from pathlib import Path
import sys

try:
    provenance = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    component = provenance["component"]["file"]
except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
    raise SystemExit(f"cannot recover selected Component from Cargo provenance: {error}")
if not isinstance(component, str):
    raise SystemExit("selected Component path in Cargo provenance is not a string")
print(component)
PY
)
        printf 'component-cargo-provenance=%s sha256=%s\n' \
            "$cargo_provenance_path" \
            "$(sha256sum "$cargo_provenance_path" | cut -d' ' -f1)"
    fi

    source=$(canonical_file 'Strict Stage 2 Component input' "$source")
    verify_locked_component "$source"
    install -m 600 -- "$source" "$qualified_component"
    verify_locked_component "$qualified_component"
    printf 'qualified-component=%s sha256=%s\n' \
        "$qualified_component" "$(sha256sum "$qualified_component" | cut -d' ' -f1)"
}

prepare_runner_root() {
    local path=$1
    local first_entry
    if [[ -e "$path" || -L "$path" ]]; then
        require_directory 'runner artifact root' "$path"
        if ! first_entry=$(find "$path" -mindepth 1 -maxdepth 1 -print -quit); then
            fail "cannot inspect runner artifact root for emptiness: $path"
        fi
        [[ -z "$first_entry" ]] || fail "runner artifact root is not empty: $path"
    else
        mkdir -m 700 -- "$path"
    fi
}

run_real_wacogo_focused() {
    env VISA_WACOGO_BIN="$retained_sidecar" \
        cargo test --locked -p visa-system real_wacogo_ -- \
            --test-threads=1 || return $?
    env VISA_WACOGO_BIN="$retained_sidecar" \
        cargo test --locked -p visa-system real_wacogo_ -- \
            --ignored --test-threads=1
}

current_gate=validate-inputs
for command_name in cargo cmp cut env find git install python3 realpath rm sha256sum sort tee tr wc; do
    require_command "$command_name"
done

current_gate=purge-stale-sidecar
validate_publish_directories \
    || fail 'unsafe Wacogo publication directory; refusing to purge stale outputs'
for stale in "$published_sidecar" "$published_build_receipt"; do
    if [[ -e "$stale" || -L "$stale" ]]; then
        require_regular_file 'stale published Wacogo artifact' "$stale"
        rm -f -- "$stale"
    fi
done
last_completed_gate=purge-stale-sidecar
current_gate=validate-inputs
write_status running

[[ -n "$go_archive" ]] \
    || fail '--go-archive or VISA_WACOGO_GO_ARCHIVE is required'
[[ -n "$go_bin" ]] || fail '--go or VISA_WACOGO_GO is required'
[[ -n "$module_zip" ]] \
    || fail '--module-zip or VISA_WACOGO_MODULE_ZIP is required'
[[ -n "$module_cache" ]] \
    || fail '--module-cache or VISA_WACOGO_GOMODCACHE is required'

go_archive=$(canonical_file 'Go release archive' "$go_archive")
go_bin=$(canonical_file 'Go executable' "$go_bin")
[[ -x "$go_bin" ]] || fail "Go executable is not executable: $go_bin"
module_zip=$(canonical_file 'wacogo module zip' "$module_zip")
module_cache=$(canonical_directory 'Go module cache' "$module_cache")
if [[ -n "$component_input" ]]; then
    component_input=$(canonical_file 'Strict Stage 2 Component input' "$component_input")
fi

cached_module_zip="$module_cache/cache/download/github.com/partite-ai/wacogo/@v/v0.0.0-20260617023329-3de16a61796c.zip"
require_regular_file 'cached pinned wacogo module zip' "$cached_module_zip"
cmp -s -- "$module_zip" "$cached_module_zip" \
    || fail 'the explicit module zip differs from the pinned zip used by offline qualification'
last_completed_gate=validate-inputs
current_gate=none
write_status running

run_gate 01-toolchain 'locked official Go toolchain' \
    env PYTHONDONTWRITEBYTECODE=1 \
    python3 scripts/wacogo-check-toolchain.py --archive "$go_archive" --go "$go_bin"

run_gate 02-source-lock 'locked Wacogo source and production assets' \
    env PYTHONDONTWRITEBYTECODE=1 \
    python3 scripts/wacogo-prepare-source.py check

current_gate=canonical-component-toolchain
printf '\n==> canonical locked Component build environment\n'
configure_component_build_environment
last_completed_gate=canonical-component-toolchain
current_gate=none
write_status running
printf '%s\n' 'ok: canonical locked Component build environment'

run_gate 03-component 'locked Strict Stage 2 Component' prepare_component

run_gate 04-selected-qualification 'selected patched Wacogo 7/7 qualification' \
    env \
        GO="$go_bin" \
        GOMODCACHE="$module_cache" \
        GOPROXY=off \
        GOSUMDB=off \
        GOTELEMETRY=off \
        GOTOOLCHAIN=local \
        GOVCS='*:off' \
        GOWORK=off \
        third_party/runtime-b-qualification/qualification/run-wacogo-probe.sh \
        "$qualified_component"

run_gate 05-sidecar-build 'reproducible production Wacogo sidecar' \
    scripts/wacogo-build-sidecar.sh \
        --go-archive "$go_archive" \
        --go "$go_bin" \
        --module-zip "$module_zip" \
        --module-cache "$module_cache"

current_gate=retain-sidecar-output
write_status running
capture_sidecar_outputs
last_completed_gate=retain-sidecar-output
current_gate=none
write_status running

run_gate 06-live-sidecar-focused 'focused pinned-sidecar live protocol and resource cleanup' \
    env \
        VISA_WACOGO_BIN="$retained_sidecar" \
        VISA_WACOGO_TEST_COMPONENT="$qualified_component" \
    cargo test --locked -p visa_wacogo --test live_sidecar -- \
        --ignored --test-threads=1

run_gate 07-focused-real-wacogo 'focused real-Wacogo no-fallback and recovery failures' \
    run_real_wacogo_focused

current_gate=prepare-same-path-root
prepare_runner_root "$same_path_root"
current_gate=none
run_gate 08-same-path-run 'real Wacogo-to-Wacogo 31-case same-path lifecycle' \
    env VISA_WACOGO_BIN="$retained_sidecar" \
    cargo run --locked -p visa-system --bin visa-system -- \
        cell wacogo wacogo "$same_path_root"

run_gate 09-same-path-verifier 'independent Wacogo same-path Stage 1 verification' \
    cargo run --locked -p visa-conformance --bin visa-conformance -- \
        stage1 "$same_path_evidence" "$same_path_root"

current_gate=prepare-strict-root
prepare_runner_root "$strict_root"
current_gate=none
run_gate 10-strict-runner 'real strict four-cell 124-case Wasmtime/Wacogo matrix' \
    env \
        VISA_WACOGO_BIN="$retained_sidecar" \
        VISA_WACOGO_BUILD_RECEIPT="$retained_build_receipt" \
    cargo run --locked -p visa-system --bin visa-system -- \
        stage2-strict "$strict_root"

run_gate 11-strict-verifier 'independent strict Stage 2 v3 verification' \
    cargo run --locked -p visa-conformance --bin visa-conformance -- \
        stage2-strict "$strict_evidence" "$strict_root"

current_gate=finalize
require_regular_file 'outer incomplete marker' "$incomplete_marker"
for required in \
    "$same_path_evidence" \
    "$strict_evidence" \
    "$strict_manifest" \
    "$retained_sidecar" \
    "$retained_build_receipt" \
    "$qualified_component"
do
    require_regular_file 'successful gate output' "$required"
done
[[ ! -e "$strict_runner_marker" && ! -L "$strict_runner_marker" ]] \
    || fail "strict runner incomplete marker remains after verification: $strict_runner_marker"

same_path_sha=$(sha256sum "$same_path_evidence" | cut -d' ' -f1)
strict_sha=$(sha256sum "$strict_evidence" | cut -d' ' -f1)
strict_manifest_sha=$(sha256sum "$strict_manifest" | cut -d' ' -f1)
sidecar_sha=$(sha256sum "$retained_sidecar" | cut -d' ' -f1)
build_receipt_sha=$(sha256sum "$retained_build_receipt" | cut -d' ' -f1)
component_sha=$(sha256sum "$qualified_component" | cut -d' ' -f1)

last_completed_gate=finalize
current_gate=none
failed_gate=none
gate_exit_code=0
write_status passed
current_gate=finalize
rm -f -- "$incomplete_marker"
completed=1
current_gate=none
trap - HUP INT TERM

set +e
printf 'strict-stage2-local-gate=passed\n'
printf 'artifact-root=%s\n' "$artifact_root"
printf 'same-path-evidence=%s sha256=%s\n' "$same_path_evidence" "$same_path_sha"
printf 'strict-evidence=%s sha256=%s\n' "$strict_evidence" "$strict_sha"
printf 'strict-manifest=%s sha256=%s\n' "$strict_manifest" "$strict_manifest_sha"
printf 'sidecar=%s sha256=%s\n' "$retained_sidecar" "$sidecar_sha"
printf 'build-receipt=%s sha256=%s\n' "$retained_build_receipt" "$build_receipt_sha"
printf 'published-sidecar=%s diagnostic-only=true\n' "$published_sidecar"
printf 'published-build-receipt=%s diagnostic-only=true\n' "$published_build_receipt"
printf 'component=%s sha256=%s\n' "$qualified_component" "$component_sha"
printf 'logs=%s\n' "$logs_root"
exit 0
