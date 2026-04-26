#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_full=0
run_fmt=0

usage() {
    cat <<'EOF'
usage: scripts/validate-runtime-full.sh [--full] [--fmt]

Default:
  - run documentation/spec consistency checks
  - run target runtime contract validation
  - replay golden traces
  - validate runtime experiment/checkpoint/benchmark/fault evidence

Options:
  --fmt   additionally run cargo fmt --all -- --check
  --full  run --fmt and cargo test --workspace
EOF
}

while (($#)); do
    case "$1" in
        --full)
            run_full=1
            run_fmt=1
            ;;
        --fmt)
            run_fmt=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
    shift
done

scripts/check-doc-consistency.sh
scripts/validate-target-runtime-contract.sh
scripts/replay-golden-traces.sh
python scripts/validate-runtime-evidence.py

if (( run_fmt )); then
    cargo fmt --all -- --check
fi

if (( run_full )); then
    cargo test --workspace
fi

printf 'validate-runtime-full: ok\n'
