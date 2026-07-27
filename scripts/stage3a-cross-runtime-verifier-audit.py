#!/usr/bin/env python3
"""Black-box mutation audit for the cross-runtime Stage 3A verifier."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable


SCHEMA = "visa.stage3a-cross-runtime-verifier-audit.v1"
BUNDLE_NAME = "stage3a-cross-runtime-evidence.json"


class AuditError(RuntimeError):
    pass


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot read JSON object {path}: {error}") from error
    if not isinstance(value, dict):
        raise AuditError(f"JSON root is not an object: {path}")
    return value


def write_object(path: Path, value: dict[str, Any]) -> bytes:
    encoded = json.dumps(value, indent=2, ensure_ascii=True).encode()
    path.write_bytes(encoded)
    return encoded


def run_verifier(verifier: Path, root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(verifier), "stage3a-cross-runtime", str(root / BUNDLE_NAME), str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def finding_codes(completed: subprocess.CompletedProcess[str]) -> list[str]:
    try:
        result = json.loads(completed.stderr)
    except json.JSONDecodeError as error:
        raise AuditError(
            f"verifier failure was not structured JSON: {completed.stderr!r}"
        ) from error
    codes: set[str] = set()
    load_error = result.get("load_error")
    if isinstance(load_error, dict) and isinstance(load_error.get("code"), str):
        codes.add(load_error["code"])
    validation = result.get("validation")
    if isinstance(validation, dict):
        for finding in validation.get("findings", []):
            if isinstance(finding, dict) and isinstance(finding.get("code"), str):
                codes.add(finding["code"])
    return sorted(codes)


def remove_cell(bundle: dict[str, Any], _: Path) -> None:
    bundle["cells"].pop()


def duplicate_cell(bundle: dict[str, Any], _: Path) -> None:
    bundle["cells"].append(copy.deepcopy(bundle["cells"][0]))


def replace_aggregate_digest(bundle: dict[str, Any], _: Path) -> None:
    bundle["normalized_semantics_sha256"] = "0" * 64


def declare_fallback(bundle: dict[str, Any], root: Path) -> None:
    cell = bundle["cells"][0]
    reference = cell["environment"]
    environment_path = root / reference["uri"]
    environment = load_object(environment_path)
    environment["fallback_runtime"] = "wasmtime"
    encoded = write_object(environment_path, environment)
    reference["sha256"] = hashlib.sha256(encoded).hexdigest()
    reference["size"] = len(encoded)


Mutation = tuple[str, str, Callable[[dict[str, Any], Path], None]]
MUTATIONS: tuple[Mutation, ...] = (
    (
        "remove-required-cell-run",
        "incomplete-stage3a-cross-runtime-matrix",
        remove_cell,
    ),
    (
        "duplicate-cell-run",
        "duplicate-stage3a-cross-runtime-cell-run",
        duplicate_cell,
    ),
    (
        "replace-aggregate-normalization",
        "stage3a-cross-runtime-aggregate-normalization-mismatch",
        replace_aggregate_digest,
    ),
    (
        "declare-runtime-fallback",
        "invalid-stage3a-cross-runtime-environment",
        declare_fallback,
    ),
)


def audit(verifier: Path, artifact_root: Path) -> dict[str, Any]:
    verifier = verifier.resolve(strict=True)
    artifact_root = artifact_root.resolve(strict=True)
    if not verifier.is_file() or verifier.is_symlink():
        raise AuditError(f"verifier is not a regular non-symlink file: {verifier}")
    if not artifact_root.is_dir() or artifact_root.is_symlink():
        raise AuditError(
            f"artifact root is not a non-symlink directory: {artifact_root}"
        )
    baseline = run_verifier(verifier, artifact_root)
    if baseline.returncode != 0:
        raise AuditError(
            "accepted baseline failed before mutation audit: "
            f"stdout={baseline.stdout!r} stderr={baseline.stderr!r}"
        )

    entries: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="visa-stage3a-verifier-audit-") as temporary:
        temporary_root = Path(temporary)
        for mutation_id, expected_code, mutate in MUTATIONS:
            mutated_root = temporary_root / mutation_id
            shutil.copytree(artifact_root, mutated_root)
            bundle_path = mutated_root / BUNDLE_NAME
            bundle = load_object(bundle_path)
            mutate(bundle, mutated_root)
            write_object(bundle_path, bundle)
            completed = run_verifier(verifier, mutated_root)
            codes = finding_codes(completed) if completed.returncode != 0 else []
            detected = completed.returncode == 1 and expected_code in codes
            entries.append(
                {
                    "id": mutation_id,
                    "expected_finding_code": expected_code,
                    "exit_code": completed.returncode,
                    "finding_codes": codes,
                    "detected": detected,
                }
            )

    detected = sum(entry["detected"] for entry in entries)
    report = {
        "schema": SCHEMA,
        "verifier": str(verifier),
        "baseline_bundle_sha256": hashlib.sha256(
            (artifact_root / BUNDLE_NAME).read_bytes()
        ).hexdigest(),
        "entries": entries,
        "summary": {
            "n": len(entries),
            "detected": detected,
            "rate": detected / len(entries),
        },
    }
    if detected != len(entries):
        raise AuditError(f"verifier mutation audit failed: {report}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = audit(arguments.verifier, arguments.artifact_root)
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (AuditError, OSError, KeyError, IndexError, TypeError) as error:
        print(f"Stage 3A cross-runtime verifier audit failed: {error}", file=sys.stderr)
        return 1
    print(
        f"Stage 3A cross-runtime verifier audit: "
        f"{report['summary']['detected']}/{report['summary']['n']} detected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
