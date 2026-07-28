#!/usr/bin/env python3
"""Unit tests for the Stage 3A outer-verifier mutation corpus."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("stage3a-cross-runtime-verifier-audit.py")
SPEC = importlib.util.spec_from_file_location("stage3a_cross_runtime_verifier_audit", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


def reference(uri: str, encoded: bytes) -> dict[str, object]:
    return {
        "uri": uri,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "size": len(encoded),
    }


def assert_reference(test: unittest.TestCase, root: Path, value: dict[str, object]) -> None:
    encoded = (root / str(value["uri"])).read_bytes()
    test.assertEqual(value["sha256"], hashlib.sha256(encoded).hexdigest())
    test.assertEqual(value["size"], len(encoded))


class CorpusTests(unittest.TestCase):
    def fixture(self, root: Path, ordinals: tuple[int, ...] = (2,)) -> dict[str, object]:
        cells: list[dict[str, object]] = []
        receipts: list[dict[str, object]] = []
        for ordinal in ordinals:
            child_references: dict[str, dict[str, object]] = {}
            for location in ("original", "relocated"):
                child_root = (
                    root
                    / f"runs/run-{ordinal}/{location}/wacogo-to-wacogo"
                )
                trace_uri = "cases/read-write-offset/evidence/trace.json"
                trace_path = child_root / trace_uri
                trace_path.parent.mkdir(parents=True)
                trace = {
                    "case_id": "read-write-offset",
                    "observations": {"offset": 6},
                }
                trace_encoded = audit.write_object(trace_path, trace)
                child = {
                    "bundle_id": "stage3a-baseline",
                    "started_at_unix_ms": 10,
                    "finished_at_unix_ms": 20,
                    "cases": [
                        {
                            "case_id": "read-write-offset",
                            "assertions": [
                                {"name": "bytes_preserved", "passed": True},
                                {
                                    "name": "logical_offset_preserved",
                                    "passed": True,
                                },
                            ],
                            "canonical_after_sha256": "a" * 64,
                            "artifacts": [reference(trace_uri, trace_encoded)],
                        }
                    ],
                }
                child_path = child_root / "stage3a-evidence.json"
                child_encoded = audit.write_object(child_path, child)
                child_references[location] = reference(
                    str(child_path.relative_to(root)), child_encoded
                )

            receipt_root = root / f"runs/run-{ordinal}/receipts/wacogo-to-wacogo"
            receipt_root.mkdir(parents=True)
            (receipt_root / "relocated-validation.json").write_text("{}")
            cell = {
                "cell_id": audit.TARGET_CELL_ID,
                "run_ordinal": ordinal,
                "original_bundle": child_references["original"],
                "relocated_bundle": child_references["relocated"],
                "validation_report": {
                    "uri": str(
                        (receipt_root / "relocated-validation.json").relative_to(root)
                    )
                },
            }
            cells.append(cell)
            receipts.append(
                {
                    "cell_id": audit.TARGET_CELL_ID,
                    "run_ordinal": ordinal,
                    "evidence_bundle": copy.deepcopy(child_references["relocated"]),
                }
            )

        matrix_path = root / "evidence-matrix-run.json"
        matrix_encoded = audit.write_object(matrix_path, {"receipts": receipts})
        return {
            "cells": cells,
            "matrix_run": reference(matrix_path.name, matrix_encoded),
        }

    def test_corpus_is_complete_unique_and_preclassified(self) -> None:
        manifest = audit.corpus_manifest()
        self.assertEqual(len(manifest), 8)
        self.assertEqual(len({entry["id"] for entry in manifest}), len(manifest))
        self.assertEqual(
            {entry["category"] for entry in manifest},
            {
                audit.SEMANTIC_DEFECT,
                audit.INTEGRITY_TAMPER,
                audit.BENIGN_EQUIVALENT,
                audit.TRUST_BOUNDARY,
            },
        )
        self.assertEqual(len(audit.corpus_sha256()), 64)

    def test_retained_observable_mutation_reseals_full_binding_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.fixture(root)
            audit.alter_retained_observable(bundle, root)

            cell = bundle["cells"][0]
            original = root / cell["original_bundle"]["uri"]
            relocated = root / cell["relocated_bundle"]["uri"]
            self.assertEqual(original.read_bytes(), relocated.read_bytes())
            child = audit.load_object(relocated)
            self.assertEqual(child["cases"][0]["canonical_after_sha256"], "0" * 64)
            assert_reference(self, root, cell["original_bundle"])
            assert_reference(self, root, cell["relocated_bundle"])
            assert_reference(self, root, bundle["matrix_run"])
            matrix = audit.load_object(root / bundle["matrix_run"]["uri"])
            self.assertEqual(
                matrix["receipts"][0]["evidence_bundle"],
                cell["relocated_bundle"],
            )

    def test_assertion_reordering_is_encoded_as_benign_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.fixture(root)
            audit.reorder_assertion_set(bundle, root)
            child_path = root / bundle["cells"][0]["relocated_bundle"]["uri"]
            child = audit.load_object(child_path)
            names = [value["name"] for value in child["cases"][0]["assertions"]]
            self.assertEqual(names, ["logical_offset_preserved", "bytes_preserved"])

    def test_contradictory_trace_is_resealed_as_explicit_trust_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.fixture(root)
            audit.contradict_raw_observation(bundle, root)
            child_path = root / bundle["cells"][0]["relocated_bundle"]["uri"]
            child = audit.load_object(child_path)
            trace_reference = child["cases"][0]["artifacts"][0]
            trace_root = child_path.parent
            trace = json.loads((trace_root / trace_reference["uri"]).read_text())
            self.assertEqual(trace["observations"]["offset"], 0)
            assert_reference(self, trace_root, trace_reference)

    def test_route_omission_removes_all_runs_and_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.fixture(root, (1, 2, 3))
            audit.remove_required_route(bundle, root)
            self.assertEqual(bundle["cells"], [])
            matrix = audit.load_object(root / bundle["matrix_run"]["uri"])
            self.assertEqual(matrix["receipts"], [])
            self.assertFalse((root / "runs/run-1/original/wacogo-to-wacogo").exists())

    def test_disposition_requires_expected_rejection_codes(self) -> None:
        mutation = audit.MUTATIONS[0]
        completed = subprocess.CompletedProcess([], 1, "", "")
        observed, matched = audit.observed_verdict(
            mutation, completed, ["unrelated-finding"]
        )
        self.assertEqual(observed, audit.REJECT)
        self.assertFalse(matched)


if __name__ == "__main__":
    unittest.main(verbosity=2)
