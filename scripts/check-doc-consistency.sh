#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
    printf 'check-doc-consistency: %s\n' "$*" >&2
    exit 1
}

require_file() {
    local path="$1"
    [[ -f "$path" ]] || fail "missing required file: $path"
}

require_literal() {
    local path="$1"
    local literal="$2"
    grep -Fq "$literal" "$path" || fail "missing literal in $path: $literal"
}

reject_regex_tree() {
    local path="$1"
    local regex="$2"
    local label="$3"
    if grep -R -nE "$regex" "$path" >/tmp/vmos-doc-reject.$$ 2>/dev/null; then
        cat /tmp/vmos-doc-reject.$$ >&2
        rm -f /tmp/vmos-doc-reject.$$
        fail "$label"
    fi
    rm -f /tmp/vmos-doc-reject.$$
}

required_files=(
    references/00_INDEX.md
    references/specs/execution-flow/agent-checkpoint-report.md
    references/specs/semantic-contract-v0.1/00-overview.md
    references/specs/semantic-contract-v0.1/02-object-identity-and-refs.md
    references/specs/semantic-contract-v0.1/04-capability-authority.md
    references/specs/semantic-contract-v0.1/12-guest-memory-object-model.md
    references/specs/target-runtime-abi/00-overview.md
    references/specs/target-runtime-abi/01-target-artifact-image.md
    references/specs/target-runtime-abi/03-hostcall-frame.md
    references/specs/target-runtime-abi/05-target-profile-and-runtime-package.md
    references/specs/target-runtime-abi/06-nostd-control-plane.md
    references/specs/target-runtime-abi/07-implementation-order.md
    references/specs/target-runtime-abi/08-default-profile.md
    tests/golden/README.md
    tests/golden/schema/vmos-golden-trace.schema.json
)

for path in "${required_files[@]}"; do
    require_file "$path"
done

reject_regex_tree \
    references/specs/target-runtime-abi \
    'entry_hostcall_demo|entry_hostcall_console_write|entry_trap_unreachable|ProductionEd25519|Open Decisions|lost_records' \
    'stale Target Runtime ABI wording found'

require_literal references/specs/target-runtime-abi/01-target-artifact-image.md 'entry_hostcall_tail'
require_literal references/specs/target-runtime-abi/01-target-artifact-image.md '13 05 00 00'
require_literal references/specs/target-runtime-abi/01-target-artifact-image.md '67 80 05 00'
require_literal references/specs/target-runtime-abi/01-target-artifact-image.md '73 00 10 00'
require_literal references/specs/target-runtime-abi/01-target-artifact-image.md 'UnsupportedRelocation'
require_literal references/specs/target-runtime-abi/01-target-artifact-image.md 'ImportDescriptorV1'
require_literal references/specs/target-runtime-abi/01-target-artifact-image.md 'RelocationEntryV1'
require_literal references/specs/target-runtime-abi/03-hostcall-frame.md 'a0 = HostcallFrameV1* frame'
require_literal references/specs/target-runtime-abi/05-target-profile-and-runtime-package.md 'target-to-host JSONL ViewV1'
require_literal references/specs/target-runtime-abi/05-target-profile-and-runtime-package.md 'ns16550a'
require_literal references/specs/target-runtime-abi/06-nostd-control-plane.md 'ring size = 64 KiB'
require_literal references/specs/target-runtime-abi/06-nostd-control-plane.md 'target-to-host only'
require_literal references/specs/target-runtime-abi/08-default-profile.md 'dev-ed25519'
require_literal references/specs/target-runtime-abi/08-default-profile.md 'panic_ring_size = 65536'

require_literal references/specs/semantic-contract-v0.1/12-guest-memory-object-model.md 'GuestAddressSpace is semantic truth'
require_literal references/specs/semantic-contract-v0.1/12-guest-memory-object-model.md 'VMOS does not claim seL4-like verification'
require_literal references/specs/semantic-contract-v0.1/04-capability-authority.md 'CapabilityLedger[StoreRef][slot]'
require_literal references/specs/semantic-contract-v0.1/02-object-identity-and-refs.md 'GuestAddressSpace'
require_literal references/00_INDEX.md '12-guest-memory-object-model.md'

python - <<'PY'
from pathlib import Path
import json
import sys

paths = [
    Path("references/00_INDEX.md"),
    Path("references/vision/semantic-os-v0.md"),
    Path("references/vision/cross-isa-migration.md"),
    Path("references/paper/plos-draft.md"),
]
paths.extend(Path("references/specs").rglob("*.md"))
paths.extend(Path("tests/golden").rglob("*.md"))
paths.extend(Path("tests/golden").rglob("*.json"))
paths.extend(Path("scripts").glob("*.sh"))

issues = []
for path in paths:
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        issues.append(f"{path}: missing final newline")
    for i, line in enumerate(data.splitlines(), 1):
        if line.rstrip() != line:
            issues.append(f"{path}:{i}: trailing whitespace")

for path in Path("tests/golden").rglob("*.json"):
    try:
        obj = json.loads(path.read_text())
    except Exception as exc:
        issues.append(f"{path}: invalid json: {exc}")
        continue
    if path.name.endswith(".trace.json"):
        for key in ("schema", "checkpoint", "contract_refs", "events", "validation"):
            if key not in obj:
                issues.append(f"{path}: missing golden trace key {key}")
        if obj.get("schema") != "vmos-golden-trace":
            issues.append(f"{path}: schema must be vmos-golden-trace")
        if not isinstance(obj.get("events", []), list):
            issues.append(f"{path}: events must be an array")
        validation = obj.get("validation", {})
        if not isinstance(validation, dict) or "ok" not in validation:
            issues.append(f"{path}: validation.ok is required")

if issues:
    print("\n".join(issues), file=sys.stderr)
    sys.exit(1)
print("check-doc-consistency: ok")
PY
