#!/usr/bin/env bash
set -Eeuo pipefail

# Applies the Stage 1 injected-defect corpus to an evidence bundle and renders
# the per-class detection rates as a markdown table.
#
# usage: scripts/defect-corpus.sh <bundle.json> <artifact-root> <out.json>
#
# With no arguments the corpus runs against the in-crate Stage 1 fixture through
# the conformance test driver instead of a published bundle.

render() {
    python3 - "$1" <<'PY'
import json, sys

report = json.load(open(sys.argv[1]))
summary = report["summary"]
print(f"# {report['schema']}")
print()
print(f"bundle: `{report['bundle']}`  ")
print(f"verifier: `{report['verifier']}`")
print()
print("| defect class | n | detected | rate |")
print("| --- | ---: | ---: | ---: |")
for name, rate in summary["per_class"]:
    print(f"| {name} | {rate['n']} | {rate['detected']} | {rate['rate']:.2f} |")
overall = summary["overall"]
print(f"| **overall** | {overall['n']} | {overall['detected']} | {overall['rate']:.2f} |")
print()
print(f"mismatches: {summary['mismatches']}  ")
print(f"incompletely resealed entries: {summary['integrity_family_hits']}")
print()
print("| entry | class | verdict | findings |")
print("| --- | --- | --- | --- |")
for entry in report["entries"]:
    codes = ", ".join(f"`{code}`" for code in entry["actual"]["finding_codes"]) or "-"
    boundary = " (boundary)" if entry["boundary"] else ""
    print(f"| `{entry['id']}`{boundary} | {entry['class']} | {entry['verdict']} | {codes} |")

if summary["mismatches"] or summary["integrity_family_hits"]:
    sys.exit(1)
PY
}

if [[ $# -eq 0 ]]; then
    out="${VISA_DEFECT_CORPUS_OUT:-target/visa-defect-corpus/fixture-report.json}"
    # cargo runs the test binary from the crate directory, so the report path
    # has to be absolute before it is handed to the test.
    [[ "$out" == /* ]] || out="$PWD/$out"
    mkdir -p -- "$(dirname -- "$out")"
    VISA_DEFECT_CORPUS_OUT="$out" cargo test --locked -p visa-conformance \
        --lib defect_corpus_tests::stage1_verifier_detection_rate_matches_the_defect_corpus \
        -- --exact >&2
    render "$out"
    exit 0
fi

if [[ $# -ne 3 ]]; then
    printf 'usage: %s [<bundle.json> <artifact-root> <out.json>]\n' "$0" >&2
    exit 64
fi

cargo run --locked -p visa-conformance --features defect-corpus \
    --bin visa-defect-corpus -- "$1" "$2" "$3" >&2
render "$3"
