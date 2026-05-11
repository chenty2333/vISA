#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
DEPRECATED: scripts/run-ltp-conformance.sh is a compatibility alias for
scripts/run-host-ltp-log-adapter.sh.

It runs an external host runltp binary and validates the raw-log adapter bundle.
It does not execute LTP through VMOS and must not be used as VMOS LTP evidence.

Use scripts/run-vmos-ltp-conformance.sh for VMOS-backed LTP execution.
EOF

exec scripts/run-host-ltp-log-adapter.sh "$@"
