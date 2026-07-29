#!/usr/bin/env python3
"""Black-box mutation audit for the regular-file observation v2 oracle."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


SCHEMA = "visa.regular-file-oracle-audit.v1"
CONTROL = "observations/regular-file-observation-control-v2.json"
CANDIDATE = "observations/regular-file-observation-candidate-v2.json"


class AuditError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise AuditError(f"{path} does not contain a JSON object")
    return value


def case(bundle: dict[str, Any], case_id: str) -> dict[str, Any]:
    for observed in bundle.get("cases", []):
        if isinstance(observed, dict) and observed.get("case_id") == case_id:
            return observed
    raise AuditError(f"candidate is missing case {case_id}")


def operation_events(observed: dict[str, Any], operation: str) -> list[dict[str, Any]]:
    matches = []
    for event in observed.get("events", []):
        body = event.get("body", {})
        data = body.get("data", {})
        operation_value = data.get("operation", {})
        if body.get("kind") == "operation_call" and operation_value.get("kind") == operation:
            matches.append(event)
    return matches


def returned_output(event: dict[str, Any], output: str) -> dict[str, Any]:
    result = event["body"]["data"]["result"]
    value = result.get("data", {}).get("output", {})
    if result.get("status") != "returned" or value.get("kind") != output:
        raise AuditError(f"operation event does not contain returned {output} output")
    return value["data"]


def resequence(observed: dict[str, Any]) -> None:
    for sequence, event in enumerate(observed["events"]):
        event["sequence"] = sequence


def changed_read_bytes(bundle: dict[str, Any]) -> None:
    observed = case(bundle, "read-write-offset")
    reads = operation_events(observed, "read")
    output = returned_output(reads[-1], "read")
    raw = output["bytes"]
    if not raw:
        raise AuditError("read-write-offset final read has no bytes to mutate")
    raw[0] ^= 1


def changed_read_offset(bundle: dict[str, Any]) -> None:
    observed = case(bundle, "read-write-offset")
    reads = operation_events(observed, "read")
    output = returned_output(reads[-1], "read")
    output["logical_offset"] += 1


def duplicate_append(bundle: dict[str, Any]) -> None:
    observed = case(bundle, "append-continuity")
    appends = operation_events(observed, "append")
    duplicate = copy.deepcopy(appends[-1])
    duplicate_data = duplicate["body"]["data"]
    duplicate_data["operation_id"] += "-injected"
    duplicate_data["attempt"] = 0
    duplicate_data["idempotency_key"] = "injected-duplicate-append"
    insertion = observed["events"].index(appends[-1]) + 1
    observed["events"].insert(insertion, duplicate)
    resequence(observed)


def delete_write_event(bundle: dict[str, Any]) -> None:
    observed = case(bundle, "read-write-offset")
    writes = operation_events(observed, "write")
    if len(writes) != 1:
        raise AuditError(f"expected one read-write-offset write, found {len(writes)}")
    observed["events"].remove(writes[0])
    resequence(observed)


def forge_terminal(bundle: dict[str, Any]) -> None:
    case(bundle, "read-write-offset")["terminal"] = "handoff_committed"


MUTATIONS: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
    ("changed-read-bytes", changed_read_bytes),
    ("changed-read-offset", changed_read_offset),
    ("duplicate-append", duplicate_append),
    ("deleted-write-operation-event", delete_write_event),
    ("forged-terminal", forge_terminal),
)


def run_oracle(
    oracle: Path,
    control: Path,
    candidate: Path,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    completed = subprocess.run(
        [str(oracle), str(control), str(candidate)],
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AuditError(
            f"oracle did not emit a JSON report: rc={completed.returncode}, "
            f"stdout={completed.stdout!r}, stderr={completed.stderr!r}"
        ) from error
    if not isinstance(report, dict):
        raise AuditError("oracle report root is not an object")
    return completed, report


def finding_codes(report: dict[str, Any]) -> list[str]:
    codes: set[str] = set()

    def collect(findings: object) -> None:
        if not isinstance(findings, list):
            return
        for finding in findings:
            if isinstance(finding, dict) and isinstance(finding.get("code"), str):
                codes.add(finding["code"])

    collect(report.get("findings"))
    for side in ("control_validation", "candidate_validation"):
        validation = report.get(side)
        if not isinstance(validation, dict):
            continue
        collect(validation.get("findings"))
        for observed in validation.get("cases", []):
            if isinstance(observed, dict):
                collect(observed.get("findings"))
    return sorted(codes)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    oracle = args.oracle.resolve(strict=True)
    root = args.artifact_root.resolve(strict=True)
    control = root / CONTROL
    candidate = root / CANDIDATE
    baseline_process, baseline = run_oracle(oracle, control, candidate)
    if baseline_process.returncode != 0 or baseline.get("accepted") is not True:
        raise AuditError(
            f"baseline observation was not accepted: rc={baseline_process.returncode}, "
            f"codes={finding_codes(baseline)}"
        )

    source = load_object(candidate)
    entries = []
    with tempfile.TemporaryDirectory(prefix="visa-regular-file-oracle-audit-") as temporary:
        temporary_root = Path(temporary)
        for mutation_id, mutate in MUTATIONS:
            mutated = copy.deepcopy(source)
            mutate(mutated)
            candidate_path = temporary_root / f"{mutation_id}.json"
            candidate_path.write_text(
                json.dumps(mutated, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            completed, report = run_oracle(oracle, control, candidate_path)
            rejected = completed.returncode == 1 and report.get("accepted") is False
            entry = {
                "id": mutation_id,
                "classification": "semantic-defect",
                "expected": "reject",
                "observed": "reject" if rejected else "accept",
                "return_code": completed.returncode,
                "finding_codes": finding_codes(report),
            }
            entries.append(entry)
            if not rejected:
                raise AuditError(f"oracle failed to reject {mutation_id}: {entry}")

    receipt = {
        "schema_version": SCHEMA,
        "oracle": {
            "sha256": sha256(oracle),
            "baseline_control_sha256": sha256(control),
            "baseline_candidate_sha256": sha256(candidate),
        },
        "baseline": {
            "accepted": True,
            "case_count": len(baseline.get("cases", [])),
        },
        "summary": {
            "semantic_defects": len(entries),
            "detected": sum(entry["observed"] == "reject" for entry in entries),
        },
        "entries": entries,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "regular-file oracle audit: "
        f"{receipt['summary']['detected']}/{receipt['summary']['semantic_defects']} rejected"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AuditError as error:
        print(f"regular-file oracle audit failed: {error}", file=sys.stderr)
        sys.exit(1)
