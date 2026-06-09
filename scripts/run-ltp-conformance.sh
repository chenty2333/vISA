#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
DEPRECATED: scripts/run-ltp-conformance.sh is a compatibility alias for
scripts/run-host-ltp-log-adapter.sh.

It runs an external host runltp binary and validates the raw-log adapter bundle.
It does not execute LTP through vISA and must not be used as vISA LTP evidence.

Use scripts/run-visa-ltp-conformance.sh for vISA-backed LTP execution.
EOF

exec scripts/run-host-ltp-log-adapter.sh "$@"
