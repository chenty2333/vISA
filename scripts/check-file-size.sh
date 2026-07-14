#!/usr/bin/env bash
set -euo pipefail

# File-size maintenance gate for tracked and not-yet-added first-party Rust
# sources. Ignored build/cache outputs stay outside the scan.
WARN_LINES=3500
FAIL_LINES=5000

ACTIVE_SPINE_PREFIXES=(
    crates/core/contract_core/
    crates/testing/handoff-component/
    crates/core/visa_profile/
    crates/core/semantic_core/
    crates/backend/substrate_api/
    crates/backend/substrate_host/
    crates/runtime/visa_runtime/
    crates/runtime/visa_component_adapter/
    crates/runtime/visa_jco_node/
    crates/runtime/visa_wacogo/
    crates/runtime/visa_wasmtime/
    crates/testing/stage3-file-component/
    crates/testing/stage3-request-component/
    crates/testing/visa-conformance/
    crates/testing/visa-stage3-system/
    crates/testing/visa-system/
)

is_active_spine() {
    local file="$1"
    local prefix
    for prefix in "${ACTIVE_SPINE_PREFIXES[@]}"; do
        if [[ "$file" == "$prefix"* ]]; then
            return 0
        fi
    done
    return 1
}

tracked_rust_files=()
while IFS= read -r -d '' file; do
    # Only repository-owned crate sources participate. Generated or cache
    # dependencies are intentionally outside this maintenance signal.
    if [[ "$file" != crates/* || "$file" == */generated/* ]]; then
        continue
    fi
    tracked_rust_files+=("$file")
done < <(git ls-files -co --exclude-standard -z -- '*.rs')

if [[ "${#tracked_rust_files[@]}" -eq 0 ]]; then
    echo "File size check could not find tracked first-party Rust sources." >&2
    exit 2
fi

violations=0

report_group() {
    local label="$1"
    local active="$2"
    local enforce="$3"
    local reported=0
    local file lines

    printf '%s\n' "$label"
    for file in "${tracked_rust_files[@]}"; do
        if [[ "$active" == true ]]; then
            is_active_spine "$file" || continue
        else
            is_active_spine "$file" && continue
        fi

        lines=$(wc -l <"$file")
        if (( lines > FAIL_LINES )); then
            if [[ "$enforce" == true ]]; then
                printf '  FAIL: %s (%s lines) exceeds hard limit %s\n' \
                    "$file" "$lines" "$FAIL_LINES"
                violations=$((violations + 1))
            else
                printf '  INFO: %s (%s lines) exceeds active-spine hard limit %s\n' \
                    "$file" "$lines" "$FAIL_LINES"
            fi
            reported=1
        elif (( lines > WARN_LINES )); then
            if [[ "$enforce" == true ]]; then
                printf '  WARN: %s (%s lines) exceeds %s\n' "$file" "$lines" "$WARN_LINES"
            else
                printf '  INFO: %s (%s lines) exceeds active-spine warning limit %s\n' \
                    "$file" "$lines" "$WARN_LINES"
            fi
            reported=1
        fi
    done

    if (( reported == 0 )); then
        printf '  no files exceed %s lines\n' "$WARN_LINES"
    fi
}

report_group "Active continuity spine (enforced):" true true
report_group "Oracle/reference and later-stage sources (informational):" false false

if (( violations > 0 )); then
    printf '\n%s active-spine file(s) exceed the hard limit.\n' "$violations" >&2
    exit 1
fi

printf '\nFile size check passed for tracked active-spine Rust sources.\n'
