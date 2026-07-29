#!/usr/bin/env python3
"""Mutation tests for the protected workspace dependency graph."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "scripts/check-dependency-direction.py"
SPEC = importlib.util.spec_from_file_location("dependency_direction_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


def synthetic_metadata() -> tuple[dict, dict[str, Path]]:
    roots = {
        name: (ROOT / "target" / "dependency-policy-fixture" / name).resolve()
        for name in POLICY.ALLOWED_WORKSPACE_DEPENDENCIES
    }
    packages = [
        {
            "name": name,
            "manifest_path": str(root / "Cargo.toml"),
            "dependencies": [],
        }
        for name, root in roots.items()
    ]
    return {"packages": packages}, roots


def add_edge(
    metadata: dict,
    roots: dict[str, Path],
    source: str,
    target: str,
    *,
    kind: str | None = None,
) -> None:
    package = next(item for item in metadata["packages"] if item["name"] == source)
    package["dependencies"].append(
        {
            "name": target,
            "kind": kind,
            "path": str(roots[target]),
        }
    )


class DependencyDirectionTests(unittest.TestCase):
    def test_new_observation_oracle_and_producer_edges_are_explicit(self) -> None:
        metadata, roots = synthetic_metadata()
        for source, target in (
            ("visa-wanco-carrier", "contract_core"),
            ("visa-wanco-carrier", "substrate_api"),
            ("visa-wanco-carrier", "substrate_host"),
            ("visa-wanco-carrier", "visa-regular-file-observation"),
            ("visa-wanco-carrier", "visa_component_adapter"),
            ("visa-wanco-carrier", "visa_profile"),
            ("visa-wanco-carrier", "visa_runtime"),
            ("visa-stage3-system", "visa-regular-file-observation"),
            ("visa-conformance", "visa-regular-file-oracle"),
        ):
            add_edge(metadata, roots, source, target)
        self.assertEqual(POLICY.dependency_violations(metadata), set())

    def test_producer_cannot_depend_on_semantic_oracle(self) -> None:
        metadata, roots = synthetic_metadata()
        add_edge(
            metadata,
            roots,
            "visa-wanco-carrier",
            "visa-regular-file-oracle",
        )
        self.assertEqual(
            POLICY.dependency_violations(metadata),
            {
                (
                    "visa-wanco-carrier",
                    "visa-regular-file-oracle",
                    "normal",
                )
            },
        )

    def test_wanco_integration_cannot_depend_on_semantic_core(self) -> None:
        metadata, roots = synthetic_metadata()
        add_edge(metadata, roots, "visa-wanco-carrier", "semantic_core")
        self.assertEqual(
            POLICY.dependency_violations(metadata),
            {("visa-wanco-carrier", "semantic_core", "normal")},
        )

    def test_observation_schema_cannot_depend_on_producer(self) -> None:
        metadata, roots = synthetic_metadata()
        add_edge(
            metadata,
            roots,
            "visa-regular-file-observation",
            "visa-wanco-carrier",
        )
        self.assertEqual(
            POLICY.dependency_violations(metadata),
            {
                (
                    "visa-regular-file-observation",
                    "visa-wanco-carrier",
                    "normal",
                )
            },
        )

    def test_dev_only_edges_do_not_enter_production_policy(self) -> None:
        metadata, roots = synthetic_metadata()
        add_edge(
            metadata,
            roots,
            "visa-wanco-carrier",
            "visa-regular-file-oracle",
            kind="dev",
        )
        self.assertEqual(POLICY.dependency_violations(metadata), set())

    def test_missing_protected_package_is_rejected(self) -> None:
        metadata, _ = synthetic_metadata()
        metadata["packages"] = [
            package
            for package in metadata["packages"]
            if package["name"] != "visa-regular-file-oracle"
        ]
        with self.assertRaisesRegex(
            ValueError,
            r"dependency policy names missing packages: visa-regular-file-oracle",
        ):
            POLICY.dependency_violations(metadata)


if __name__ == "__main__":
    unittest.main()
