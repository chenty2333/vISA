#!/usr/bin/env python3
"""Mutation tests for the canonical evidence matrix checker."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "scripts/evidence_matrix.py"
SPEC = importlib.util.spec_from_file_location("evidence_matrix_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)

Mutation = Callable[[dict[str, Any], dict[str, Any]], None]


class EvidenceMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.matrix = MATRIX.load_matrix(ROOT / "claims/evidence-matrix.json")
        cls.registry = MATRIX.load_registry(ROOT / "claims/registry.json")

    def assert_valid(self) -> None:
        MATRIX.validate_matrix(copy.deepcopy(self.matrix), copy.deepcopy(self.registry))

    def assert_rejected(self, expected: str, mutation: Mutation) -> None:
        self.assert_valid()
        matrix = copy.deepcopy(self.matrix)
        registry = copy.deepcopy(self.registry)
        mutation(matrix, registry)
        with self.assertRaisesRegex(MATRIX.EvidenceMatrixError, expected):
            MATRIX.validate_matrix(matrix, registry)

    def test_repository_matrix_is_valid(self) -> None:
        self.assert_valid()

    def test_unknown_cell_field_is_rejected(self) -> None:
        self.assert_rejected(
            r"cells\[0\] keys drifted",
            lambda matrix, _registry: matrix["cells"][0].__setitem__("unknown", True),
        )

    def test_duplicate_coordinate_is_rejected(self) -> None:
        def mutate(matrix: dict[str, Any], _registry: dict[str, Any]) -> None:
            matrix["cells"][1]["source"] = copy.deepcopy(matrix["cells"][0]["source"])
            matrix["cells"][1]["destination"] = copy.deepcopy(
                matrix["cells"][0]["destination"]
            )
            for field in (
                "resource_profile",
                "handoff_topology",
                "fault_model",
                "verifier",
            ):
                matrix["cells"][1][field] = matrix["cells"][0][field]

        self.assert_rejected(r"duplicate six-dimensional coordinate", mutate)

    def test_earned_claim_cannot_require_candidate_cell(self) -> None:
        self.assert_rejected(
            r"earned claim bounded-regular-file-continuity requires non-qualified cells",
            lambda matrix, _registry: next(
                cell
                for cell in matrix["cells"]
                if cell["id"] == "s3a.wasmtime-to-wasmtime.regular-file"
            ).__setitem__("disposition", "candidate"),
        )

    def test_declared_gap_cannot_bind_a_claim(self) -> None:
        self.assert_rejected(
            r"declared gap .* binds evidence",
            lambda matrix, _registry: matrix["cells"][0]["claim_ids"].append(
                "bounded-regular-file-continuity"
            ),
        )

    def test_unknown_workflow_binding_is_rejected(self) -> None:
        def mutate(matrix: dict[str, Any], _registry: dict[str, Any]) -> None:
            cell = next(cell for cell in matrix["cells"] if cell["id"].startswith("s1."))
            cell["workflow_binding_ids"] = sorted(
                [*cell["workflow_binding_ids"], "fabricated-workflow"]
            )

        self.assert_rejected(
            r"has unknown workflow fabricated-workflow",
            mutate,
        )

    def test_matrix_and_registry_claim_sets_must_match(self) -> None:
        self.assert_rejected(
            r"matrix claim IDs differ",
            lambda matrix, _registry: matrix["claim_requirements"].pop(),
        )

    def test_four_direction_successor_cannot_drop_a_cell(self) -> None:
        def mutate(matrix: dict[str, Any], _registry: dict[str, Any]) -> None:
            requirement = next(
                item
                for item in matrix["claim_requirements"]
                if item["claim_id"] == "cross-runtime-regular-file-continuity-v1"
            )
            requirement["required_cells"].pop()

        self.assert_rejected(r"orphaned evidence cell", mutate)


if __name__ == "__main__":
    unittest.main()
