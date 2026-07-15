#!/usr/bin/env python3
"""Validate production dependency direction for the active continuity spine."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


# Exact workspace dependencies allowed from each protected package. Dev-only
# dependencies are excluded because they cannot enter a production artifact.
ALLOWED_WORKSPACE_DEPENDENCIES = {
    "contract_core": frozenset(),
    "joint_handoff_core": frozenset({"contract_core"}),
    "handoff-component": frozenset(),
    "visa_profile": frozenset({"contract_core"}),
    "semantic_core": frozenset({"contract_core", "visa_profile"}),
    "substrate_api": frozenset({"contract_core", "visa_profile"}),
    "substrate_host": frozenset({"contract_core", "substrate_api", "visa_profile"}),
    "visa_runtime": frozenset(
        {"contract_core", "semantic_core", "substrate_api", "visa_profile"}
    ),
    "visa_joint_handoff": frozenset(
        {"contract_core", "joint_handoff_core", "substrate_api", "visa_runtime"}
    ),
    "visa_component_adapter": frozenset(
        {"contract_core", "substrate_api", "visa_profile", "visa_runtime"}
    ),
    "visa_jco_node": frozenset(
        {
            "contract_core",
            "visa_component_adapter",
            "visa_profile",
            "visa_runtime",
        }
    ),
    "visa_wacogo": frozenset(
        {
            "contract_core",
            "visa_component_adapter",
            "visa_profile",
            "visa_runtime",
        }
    ),
    "visa_wasmtime": frozenset(
        {
            "contract_core",
            "substrate_api",
            "visa_component_adapter",
            "visa_profile",
            "visa_runtime",
        }
    ),
    "stage3-file-component": frozenset(),
    "stage3-request-component": frozenset(),
    "visa-conformance": frozenset(
        {"contract_core", "semantic_core", "substrate_api", "visa_profile"}
    ),
    "visa-stage3-system": frozenset(
        {
            "contract_core",
            "stage3-file-component",
            "stage3-request-component",
            "substrate_api",
            "substrate_host",
            "visa-conformance",
            "visa_component_adapter",
            "visa_profile",
            "visa_runtime",
            "visa_wasmtime",
        }
    ),
    "visa-joint-handoff-system": frozenset(
        {
            "contract_core",
            "joint_handoff_core",
            "substrate_api",
            "substrate_host",
            "visa-conformance",
            "visa_joint_handoff",
            "visa_runtime",
        }
    ),
    "visa-system": frozenset(
        {
            "contract_core",
            "handoff-component",
            "substrate_api",
            "substrate_host",
            "visa-conformance",
            "visa_component_adapter",
            "visa_jco_node",
            "visa_profile",
            "visa_runtime",
            "visa_wacogo",
            "visa_wasmtime",
        }
    ),
}

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
    try:
        violations = dependency_violations(cargo_metadata())
    except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError) as error:
        print(f"dependency-direction check could not run: {error}", file=sys.stderr)
        return 2

    if violations:
        print_edges("dependency-direction violations:", violations)
        return 1
    print("dependency-direction check passed in strict mode")
    return 0


if __name__ == "__main__":
    sys.exit(main())
