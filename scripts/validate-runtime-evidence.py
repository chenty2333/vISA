#!/usr/bin/env python3
"""Validate VMOS runtime evidence files without external schema packages."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = REPO_ROOT / "tests/golden/schema"


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


def load_schema(path: Path) -> dict[str, Any]:
    schema = load_json(path)
    if schema.get("schema") != "json-schema-draft-07":
        raise EvidenceError(f"{path}: unsupported schema descriptor")
    return schema


def schema_type_matches(expected: str, value: Any) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def validate_json_schema_subset(
    path: Path,
    value: Any,
    schema: dict[str, Any],
    location: str = "$",
) -> None:
    if "const" in schema and value != schema["const"]:
        raise EvidenceError(f"{path}: {location} must be {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise EvidenceError(f"{path}: {location} must be one of {schema['enum']!r}")
    if "type" in schema:
        expected_types = schema["type"]
        if isinstance(expected_types, str):
            expected_types = [expected_types]
        if isinstance(expected_types, list) and not any(
            isinstance(kind, str) and schema_type_matches(kind, value)
            for kind in expected_types
        ):
            raise EvidenceError(f"{path}: {location} has wrong type")
    if isinstance(value, int) and not isinstance(value, bool) and "minimum" in schema:
        if value < schema["minimum"]:
            raise EvidenceError(f"{path}: {location} is below minimum {schema['minimum']}")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                raise EvidenceError(f"{path}: {location} missing required key `{key}`")
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, child_schema in properties.items():
                if key in value and isinstance(child_schema, dict):
                    validate_json_schema_subset(
                        path,
                        value[key],
                        child_schema,
                        f"{location}.{key}",
                    )
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            validate_json_schema_subset(path, item, schema["items"], f"{location}[{index}]")


def validate_against_named_schema(path: Path, value: dict[str, Any], schema_name: str) -> None:
    validate_json_schema_subset(path, value, load_schema(SCHEMA_ROOT / schema_name))


def require_nonempty_string(path: Path, value: dict[str, Any], key: str) -> None:
    if not isinstance(value.get(key), str) or not value[key]:
        raise EvidenceError(f"{path}: `{key}` must be a non-empty string")


def validate_golden_trace_smoke(path: Path, value: dict[str, Any]) -> None:
    stimulus = require_object(path, value, "stimulus")
    if not stimulus:
        raise EvidenceError(f"{path}: stimulus must not be empty")
    if not any(
        key in stimulus
        for key in (
            "commands",
            "command",
            "preconditions",
            "input",
            "runner",
            "entry",
            "slow_path",
            "fast_path_cache",
            "artifact",
            "trap",
            "registers",
        )
    ):
        raise EvidenceError(f"{path}: stimulus must describe replay input or command")
    if not value["events"]:
        raise EvidenceError(f"{path}: events must not be empty")
    for index, event in enumerate(value["events"]):
        if not isinstance(event, dict):
            raise EvidenceError(f"{path}: events[{index}] must be an object")
        require_nonempty_string(path, event, "kind")
    expected = require_object(path, value, "expected")
    if not expected:
        raise EvidenceError(f"{path}: expected replay result must not be empty")
    if "views" in expected and not isinstance(expected["views"], dict):
        raise EvidenceError(f"{path}: expected.views must be an object")
    if "invariants" in expected:
        invariants = expected["invariants"]
        if not isinstance(invariants, list) or not invariants:
            raise EvidenceError(f"{path}: expected.invariants must be a non-empty array")
    validation = require_object(path, value, "validation")
    evidence_keys = set(validation) - {"ok"}
    if not evidence_keys:
        raise EvidenceError(f"{path}: validation must name replay evidence beyond ok=true")
    if "required_tests" in validation:
        tests = validation["required_tests"]
        if not isinstance(tests, list) or not tests or not all(isinstance(test, str) for test in tests):
            raise EvidenceError(f"{path}: validation.required_tests must be non-empty strings")
    if "commands" in validation:
        commands = validation["commands"]
        if not isinstance(commands, list) or not commands or not all(
            isinstance(command, str) for command in commands
        ):
            raise EvidenceError(f"{path}: validation.commands must be non-empty strings")
    if "query" in validation and not isinstance(validation["query"], str):
        raise EvidenceError(f"{path}: validation.query must be a string")
    for report_key in ("experiment_report",):
        if report_key in validation:
            if not isinstance(validation[report_key], str):
                raise EvidenceError(f"{path}: validation.{report_key} must be a string")
            require_path_exists(path, validation[report_key])


def validate_golden_trace(path: Path) -> None:
    value = load_json(path)
    validate_against_named_schema(path, value, "vmos-golden-trace.schema.json")
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
    validate_golden_trace_smoke(path, value)


def validate_checkpoint_report(path: Path) -> None:
    value = load_json(path)
    validate_against_named_schema(path, value, "vmos-checkpoint-report.schema.json")
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
    validate_against_named_schema(path, value, "vmos-experiment-report.schema.json")
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
    validate_against_named_schema(path, value, "vmos-benchmark-report.schema.json")
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
    validate_against_named_schema(path, value, "vmos-fault-injection.schema.json")
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
