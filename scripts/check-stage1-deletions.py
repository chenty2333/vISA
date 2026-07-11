#!/usr/bin/env python3
"""Reject Stage 1 regressions into deleted service and oracle paths."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
ORACLE_ROOT = (ROOT / "crates/oracle").resolve()

ACTIVE_PACKAGES = {
    "contract_core": "crates/core/contract_core/Cargo.toml",
    "visa_profile": "crates/core/visa_profile/Cargo.toml",
    "semantic_core": "crates/core/semantic_core/Cargo.toml",
    "substrate_api": "crates/backend/substrate_api/Cargo.toml",
    "substrate_host": "crates/backend/substrate_host/Cargo.toml",
    "visa_runtime": "crates/runtime/visa_runtime/Cargo.toml",
    "visa_wasmtime": "crates/runtime/visa_wasmtime/Cargo.toml",
    "visa-conformance": "crates/testing/visa-conformance/Cargo.toml",
    "handoff-component": "crates/testing/handoff-component/Cargo.toml",
    "visa-system": "crates/testing/visa-system/Cargo.toml",
}

ACTIVE_WORKSPACE_ALIASES = {
    "contract_core": "crates/core/contract_core",
    "semantic_core": "crates/core/semantic_core",
    "substrate_api": "crates/backend/substrate_api",
    "visa_profile": "crates/core/visa_profile",
    "visa_runtime": "crates/runtime/visa_runtime",
    "visa_wasmtime": "crates/runtime/visa_wasmtime",
}

REMOVED_SERVICE_PATHS = (
    "crates/services/replay_snapshot",
    "crates/services/wasm_app",
)

ORACLE_SERVICE_PACKAGES = {
    "replay_snapshot": "crates/oracle/replay_snapshot/Cargo.toml",
    "wasm_app": "crates/oracle/wasm_app/Cargo.toml",
}

ACTIVE_TEXT_ROOTS = (".cargo", "scripts", ".github")
LEGACY_NAME = re.compile(r"\b(?:vmos|semantic os)\b", re.IGNORECASE)
REPLACED_PACKAGE_NAME = re.compile(r"\b(?:replay_snapshot|wasm_app)\b")
LEGACY_ALLOWED_PREFIXES = ("crates/oracle/", "docs/archive/")
TEXT_SUFFIXES = {
    ".json",
    ".md",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".wit",
    ".yaml",
    ".yml",
}


def cargo_metadata() -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def package_maps(metadata: dict) -> tuple[dict[str, dict], dict[Path, dict]]:
    by_name = {package["name"]: package for package in metadata["packages"]}
    by_root = {
        Path(package["manifest_path"]).resolve().parent: package
        for package in metadata["packages"]
    }
    return by_name, by_root


def check_active_packages(metadata: dict) -> list[str]:
    violations: list[str] = []
    by_name, by_root = package_maps(metadata)

    for name, expected_manifest in ACTIVE_PACKAGES.items():
        package = by_name.get(name)
        if package is None:
            violations.append(f"active package is missing from metadata: {name}")
            continue
        actual = relative(Path(package["manifest_path"]))
        if actual != expected_manifest:
            violations.append(
                f"active package {name} resolves to {actual}, expected {expected_manifest}"
            )

    for source_name in ACTIVE_PACKAGES:
        source = by_name.get(source_name)
        if source is None:
            continue
        pending = [(source, [source_name])]
        visited: set[str] = set()
        while pending:
            package, chain = pending.pop()
            package_id = package["id"]
            if package_id in visited:
                continue
            visited.add(package_id)
            for dependency in package["dependencies"]:
                dependency_path = dependency.get("path")
                if dependency_path is None:
                    continue
                dependency_root = Path(dependency_path).resolve()
                target = by_root.get(dependency_root)
                if target is None:
                    continue
                target_manifest = Path(target["manifest_path"]).resolve()
                next_chain = [*chain, target["name"]]
                if target_manifest.is_relative_to(ORACLE_ROOT):
                    violations.append(
                        "active dependency reaches oracle: " + " -> ".join(next_chain)
                    )
                    continue
                pending.append((target, next_chain))
    return violations


def check_workspace_configuration(metadata: dict) -> list[str]:
    violations: list[str] = []
    with (ROOT / "Cargo.toml").open("rb") as source:
        workspace = tomllib.load(source)["workspace"]
    dependencies = workspace.get("dependencies", {})

    for alias, expected_root in ACTIVE_WORKSPACE_ALIASES.items():
        value = dependencies.get(alias)
        if not isinstance(value, dict) or "path" not in value:
            violations.append(f"workspace dependency {alias} must be an active path alias")
            continue
        actual = relative(ROOT / value["path"])
        if actual != expected_root:
            violations.append(
                f"workspace dependency {alias} points to {actual}, expected {expected_root}"
            )
        if "package" in value:
            violations.append(f"workspace dependency {alias} must not rename an oracle package")

    members = set(workspace.get("members", []))
    for removed in REMOVED_SERVICE_PATHS:
        if removed in members:
            violations.append(f"removed service remains a workspace member: {removed}")
        if (ROOT / removed).exists():
            violations.append(f"removed service path exists: {removed}")

    by_name, _ = package_maps(metadata)
    for package in metadata["packages"]:
        manifest = Path(package["manifest_path"]).resolve()
        if not manifest.is_relative_to(ORACLE_ROOT):
            continue
        if package.get("publish") != []:
            violations.append(
                f"oracle package must set publish = false: {package['name']}"
            )
        package_metadata = package.get("metadata")
        visa_metadata = (
            package_metadata.get("visa") if isinstance(package_metadata, dict) else None
        )
        role = visa_metadata.get("role") if isinstance(visa_metadata, dict) else None
        if role != "comparison-oracle":
            violations.append(
                f"oracle package must declare comparison-oracle role: {package['name']}"
            )

    for name, expected_manifest in ORACLE_SERVICE_PACKAGES.items():
        package = by_name.get(name)
        if package is None:
            violations.append(f"historical oracle package is missing: {name}")
            continue
        actual = relative(Path(package["manifest_path"]))
        if actual != expected_manifest:
            violations.append(
                f"historical package {name} resolves to {actual}, expected {expected_manifest}"
            )
    return violations


def active_text_files() -> list[Path]:
    files: list[Path] = []
    for root_name in ACTIVE_TEXT_ROOTS:
        root = ROOT / root_name
        if not root.exists():
            continue
        files.extend(path for path in root.rglob("*") if path.is_file())
    return files


def check_active_surfaces() -> list[str]:
    violations: list[str] = []
    checker = Path(__file__).resolve()
    for path in active_text_files():
        if path.resolve() == checker:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for removed in REMOVED_SERVICE_PATHS:
            if removed in text:
                violations.append(f"active surface {relative(path)} references {removed}")
        if REPLACED_PACKAGE_NAME.search(text):
            violations.append(
                f"active surface {relative(path)} references a replaced service package"
            )
    return violations


def repository_text_files() -> list[Path]:
    skipped = {".git", ".ci-cache", "target"}
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
            continue
        relative_parts = path.relative_to(ROOT).parts
        if any(part in skipped for part in relative_parts):
            continue
        files.append(path)
    return files


def check_legacy_names() -> list[str]:
    violations: list[str] = []
    checker = Path(__file__).resolve()
    for path in repository_text_files():
        if path.resolve() == checker:
            continue
        name = relative(path)
        if name.startswith(LEGACY_ALLOWED_PREFIXES):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            if LEGACY_NAME.search(line):
                violations.append(f"legacy name outside oracle/archive: {name}:{line_number}")
    return violations


def main() -> int:
    try:
        metadata = cargo_metadata()
        violations = [
            *check_active_packages(metadata),
            *check_workspace_configuration(metadata),
            *check_active_surfaces(),
            *check_legacy_names(),
        ]
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"Stage 1 deletion check could not run: {error}", file=sys.stderr)
        return 2

    if violations:
        print("Stage 1 deletion violations:", file=sys.stderr)
        for violation in sorted(set(violations)):
            print(f"  {violation}", file=sys.stderr)
        return 1
    print("Stage 1 deletion check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
