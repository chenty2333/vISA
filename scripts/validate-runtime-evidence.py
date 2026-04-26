#!/usr/bin/env python3
"""Validate VMOS runtime evidence files without external schema packages."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]


class EvidenceError(Exception):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except Exception as exc:  # pragma: no cover - command line diagnostics
        raise EvidenceError(f"{path}: invalid json: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{path}: top-level value must be an object")
    return value


def require_keys(path: Path, value: dict[str, Any], keys: tuple[str, ...]) -> None:
    for key in keys:
        if key not in value:
            raise EvidenceError(f"{path}: missing required key `{key}`")


def require_schema(path: Path, value: dict[str, Any], expected: str) -> None:
    actual = value.get("schema")
    if actual != expected:
        raise EvidenceError(f"{path}: schema must be `{expected}`, got `{actual}`")


def require_list(path: Path, value: dict[str, Any], key: str) -> None:
    if not isinstance(value.get(key), list):
        raise EvidenceError(f"{path}: `{key}` must be an array")


def require_object(path: Path, value: dict[str, Any], key: str) -> dict[str, Any]:
    obj = value.get(key)
    if not isinstance(obj, dict):
        raise EvidenceError(f"{path}: `{key}` must be an object")
    return obj


def require_bool(path: Path, value: dict[str, Any], key: str) -> None:
    if not isinstance(value.get(key), bool):
        raise EvidenceError(f"{path}: `{key}` must be a boolean")


def require_path_exists(path: Path, referenced: str) -> None:
    target = REPO_ROOT / referenced
    if not target.exists():
        raise EvidenceError(f"{path}: referenced file does not exist: {referenced}")


def validate_golden_trace(path: Path) -> None:
    value = load_json(path)
    require_schema(path, value, "vmos-golden-trace")
    require_keys(
        path,
        value,
        (
            "schema",
            "schema_version",
            "checkpoint",
            "contract_refs",
            "no_goals",
            "stimulus",
            "events",
            "expected",
            "validation",
        ),
    )
    require_list(path, value, "contract_refs")
    require_list(path, value, "no_goals")
    require_list(path, value, "events")
    require_object(path, value, "stimulus")
    require_object(path, value, "expected")
    validation = require_object(path, value, "validation")
    require_bool(path, validation, "ok")
    if not validation["ok"]:
        raise EvidenceError(f"{path}: validation.ok must be true for replayable evidence")
    for ref in value["contract_refs"]:
        if not isinstance(ref, str):
            raise EvidenceError(f"{path}: contract_refs entries must be strings")
        require_path_exists(path, ref)


def validate_checkpoint_report(path: Path) -> None:
    value = load_json(path)
    require_schema(path, value, "vmos-checkpoint-report")
    require_keys(
        path,
        value,
        (
            "schema",
            "schema_version",
            "checkpoint",
            "phase",
            "status",
            "scope",
            "no_goals",
            "changed_files",
            "tests_and_traces",
            "validation_commands",
            "evidence",
            "residual_gaps",
            "next_checkpoint",
        ),
    )
    if value["status"] not in ("pass", "fail", "blocked"):
        raise EvidenceError(f"{path}: status must be pass, fail, or blocked")
    for key in ("scope", "no_goals", "changed_files", "tests_and_traces", "residual_gaps"):
        require_list(path, value, key)
    require_object(path, value, "evidence")
    require_list(path, value, "validation_commands")
    for command in value["validation_commands"]:
        if not isinstance(command, dict):
            raise EvidenceError(f"{path}: validation_commands entries must be objects")
        require_keys(path, command, ("command", "status"))
        if command["status"] not in ("pass", "fail", "not-run", "blocked"):
            raise EvidenceError(f"{path}: invalid validation command status")
    for referenced in value["changed_files"] + value["tests_and_traces"]:
        if isinstance(referenced, str):
            require_path_exists(path, referenced)


def validate_experiment_report(path: Path) -> None:
    value = load_json(path)
    require_schema(path, value, "vmos-experiment-report")
    require_keys(
        path,
        value,
        (
            "schema",
            "schema_version",
            "name",
            "checkpoint",
            "commands",
            "events",
            "final_views",
            "metrics",
            "validation",
        ),
    )
    require_list(path, value, "commands")
    require_list(path, value, "events")
    require_object(path, value, "final_views")
    require_object(path, value, "metrics")
    validation = require_object(path, value, "validation")
    require_bool(path, validation, "contract_ok")
    require_bool(path, validation, "golden_replay_ok")


def validate_benchmark_report(path: Path) -> None:
    value = load_json(path)
    require_schema(path, value, "vmos-benchmark-report")
    require_keys(
        path,
        value,
        ("schema", "schema_version", "name", "checkpoint", "environment", "metrics", "validation"),
    )
    require_object(path, value, "environment")
    metrics = require_object(path, value, "metrics")
    if not metrics:
        raise EvidenceError(f"{path}: metrics must not be empty")
    validation = require_object(path, value, "validation")
    require_bool(path, validation, "ok")


def validate_fault_scenario(path: Path) -> None:
    value = load_json(path)
    require_schema(path, value, "vmos-fault-injection-scenario")
    require_keys(
        path,
        value,
        (
            "schema",
            "schema_version",
            "name",
            "checkpoint",
            "trigger",
            "expected_events",
            "expected_cleanup",
            "validation",
        ),
    )
    require_object(path, value, "trigger")
    require_list(path, value, "expected_events")
    require_object(path, value, "expected_cleanup")
    validation = require_object(path, value, "validation")
    require_bool(path, validation, "ok")


def collect(pattern: str) -> list[Path]:
    return sorted(REPO_ROOT.glob(pattern))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden-only", action="store_true")
    parser.add_argument("--reports-only", action="store_true")
    args = parser.parse_args()

    checks: list[tuple[str, list[Path], Any]] = []
    if not args.reports_only:
        checks.append(("golden traces", collect("tests/golden/**/*.trace.json"), validate_golden_trace))
    if not args.golden_only:
        checks.extend(
            [
                (
                    "checkpoint reports",
                    collect("tests/reports/checkpoints/*.checkpoint.json"),
                    validate_checkpoint_report,
                ),
                (
                    "experiment reports",
                    collect("tests/reports/experiments/*.experiment.json"),
                    validate_experiment_report,
                ),
                (
                    "benchmark reports",
                    collect("tests/reports/benchmarks/*.benchmark.json"),
                    validate_benchmark_report,
                ),
                (
                    "fault injection scenarios",
                    collect("tests/reports/fault-injection/*.fault.json"),
                    validate_fault_scenario,
                ),
            ]
        )

    errors: list[str] = []
    counts: list[str] = []
    for label, paths, validator in checks:
        if not paths:
            errors.append(f"missing evidence files for {label}")
            continue
        for path in paths:
            try:
                validator(path)
            except EvidenceError as exc:
                errors.append(str(exc))
        counts.append(f"{label}={len(paths)}")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("validate-runtime-evidence: ok " + " ".join(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
