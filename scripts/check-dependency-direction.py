#!/usr/bin/env python3
"""Validate production dependency direction for the Stage 1 active spine."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


# Exact workspace dependencies allowed from each protected package. Dev-only
# dependencies are excluded because they cannot enter a production artifact.
ALLOWED_WORKSPACE_DEPENDENCIES = {
    "contract_core": frozenset(),
    "visa_profile": frozenset({"contract_core"}),
    "semantic_core": frozenset({"contract_core", "visa_profile"}),
    "substrate_api": frozenset({"contract_core", "visa_profile"}),
    "visa_runtime": frozenset(
        {"contract_core", "semantic_core", "substrate_api", "visa_profile"}
    ),
    "visa_wasmtime": frozenset(
        {"contract_core", "substrate_api", "visa_profile", "visa_runtime"}
    ),
    "visa-conformance": frozenset(
        {"contract_core", "substrate_api", "visa_profile"}
    ),
}

# Temporary reset debt. Migration mode permits only a shrinking subset of this
# set; a new or changed violation still fails. Delete the set and switch fast to
# --strict when these edges have been removed.
MIGRATION_DEBT = frozenset(
    {
        ("semantic_core", "target_abi", "normal"),
        ("visa_runtime", "target_abi", "normal"),
        ("visa_wasmtime", "semantic_core", "normal"),
        ("visa_wasmtime", "target_abi", "normal"),
    }
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="check active-spine workspace dependency direction"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--migration",
        action="store_true",
        help="allow only the documented shrinking migration-debt set (default)",
    )
    mode.add_argument(
        "--strict", action="store_true", help="reject every direction violation"
    )
    return parser.parse_args()


def cargo_metadata() -> dict:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def dependency_violations(metadata: dict) -> set[tuple[str, str, str]]:
    packages = {package["name"]: package for package in metadata["packages"]}
    workspace_roots = {
        Path(package["manifest_path"]).resolve().parent: package["name"]
        for package in metadata["packages"]
    }

    missing = sorted(set(ALLOWED_WORKSPACE_DEPENDENCIES) - set(packages))
    if missing:
        raise ValueError(f"dependency policy names missing packages: {', '.join(missing)}")

    violations: set[tuple[str, str, str]] = set()
    for source, allowed in ALLOWED_WORKSPACE_DEPENDENCIES.items():
        for dependency in packages[source]["dependencies"]:
            kind = dependency["kind"] or "normal"
            dependency_path = dependency.get("path")
            if kind == "dev" or dependency_path is None:
                continue

            dependency_root = Path(dependency_path).resolve()
            target = workspace_roots.get(dependency_root)
            if target is not None and target not in allowed:
                violations.add((source, target, kind))
    return violations


def print_edges(label: str, edges: set[tuple[str, str, str]]) -> None:
    if not edges:
        return
    print(label, file=sys.stderr)
    for source, target, kind in sorted(edges):
        print(f"  {source} --{kind}--> {target}", file=sys.stderr)


def main() -> int:
    args = parse_args()
    try:
        violations = dependency_violations(cargo_metadata())
    except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError) as error:
        print(f"dependency-direction check could not run: {error}", file=sys.stderr)
        return 2

    if args.strict:
        if violations:
            print_edges("dependency-direction violations:", violations)
            return 1
        print("dependency-direction check passed in strict mode")
        return 0

    new_violations = violations - MIGRATION_DEBT
    if new_violations:
        print_edges("new dependency-direction violations:", new_violations)
        print_edges("remaining documented migration debt:", violations & MIGRATION_DEBT)
        return 1

    remaining_debt = violations & MIGRATION_DEBT
    if remaining_debt:
        print_edges("warning: remaining dependency-direction migration debt:", remaining_debt)
        print(
            "migration guard passed; strict mode will fail until these edges are removed",
            file=sys.stderr,
        )
    else:
        print("dependency-direction migration debt is clear; enable --strict")
    return 0


if __name__ == "__main__":
    sys.exit(main())
