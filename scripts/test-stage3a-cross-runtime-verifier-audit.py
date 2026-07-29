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


def observation_fixture() -> dict[str, object]:
    def operation_event(
        sequence: int,
        operation_id: str,
        operation: dict[str, object],
        output: dict[str, object],
    ) -> dict[str, object]:
        return {
            "sequence": sequence,
            "phase": "destination_execution",
            "actor": "destination_runtime",
            "body": {
                "kind": "operation_call",
                "data": {
                    "operation_id": operation_id,
                    "attempt": 0,
                    "idempotency_key": operation_id,
                    "operation": operation,
                    "result": {
                        "status": "returned",
                        "data": {"output": output},
                    },
                },
            },
        }

    def file_probe_event(
        sequence: int, path: bytes, content: bytes
    ) -> dict[str, object]:
        return {
            "sequence": sequence,
            "phase": "final_observation",
            "actor": "external_observer",
            "body": {
                "kind": "file_probe",
                "data": {
                    "path": list(path),
                    "entry": {
                        "kind": "file",
                        "data": {
                            "bytes": list(content),
                            "size": len(content),
                            "sha256": hashlib.sha256(content).hexdigest(),
                            "metadata": {
                                "device": 1,
                                "inode": 2,
                                "generation": None,
                                "birth_time_unix_ns": None,
                                "mode": 0o100644,
                                "link_count": 1,
                            },
                        },
                    },
                },
            },
        }

    return {
        "schema_version": "regular-file-observation-v2",
        "bundle_id": "stage3a-candidate-fixture",
        "route": {
            "mode": "handoff",
            "source": {
                "instance_id": "source",
                "runtime": "visa_wacogo",
                "runtime_version": "fixture",
                "host_id": "fixture-host",
                "operating_system": "linux",
                "isa": "x86_64",
            },
            "destination": {
                "instance_id": "destination",
                "runtime": "visa_wacogo",
                "runtime_version": "fixture",
                "host_id": "fixture-host",
                "operating_system": "linux",
                "isa": "x86_64",
            },
            "execution_boundary": "fixture",
            "carrier": None,
        },
        "cases": [
            {
                "observation_id": "read-write-offset-fixture",
                "case_id": "read-write-offset",
                "schedule_id": "read-write-offset-schedule",
                "schedule_sha256": "1" * 64,
                "subject": {
                    "resource_id": "resource",
                    "initial_path": [100, 97, 116, 97, 46, 98, 105, 110],
                },
                "events": [
                    operation_event(
                        0,
                        "post-read",
                        {"kind": "read", "data": {"max_bytes": 16}},
                        {
                            "kind": "read",
                            "data": {
                                "bytes": [97, 98],
                                "logical_offset": 6,
                                "version": 2,
                                "size": 6,
                                "content_digest": [0] * 32,
                            },
                        },
                    )
                ],
            },
            {
                "observation_id": "append-continuity-fixture",
                "case_id": "append-continuity",
                "schedule_id": "append-continuity-schedule",
                "schedule_sha256": "2" * 64,
                "subject": {
                    "resource_id": "resource",
                    "initial_path": [100, 97, 116, 97, 46, 98, 105, 110],
                },
                "events": [
                    operation_event(
                        0,
                        "append-two",
                        {
                            "kind": "append",
                            "data": {
                                "bytes": [120],
                                "durability": "data",
                            },
                        },
                        {
                            "kind": "mutated",
                            "data": {
                                "logical_offset": 7,
                                "version": 2,
                                "size": 7,
                                "content_digest": [0] * 32,
                                "durable_through": "data",
                            },
                        },
                    )
                ],
            },
            {
                "observation_id": "rename-object-identity-fixture",
                "case_id": "rename-object-identity",
                "schedule_id": "rename-object-identity-schedule",
                "schedule_sha256": "3" * 64,
                "subject": {
                    "resource_id": "resource",
                    "initial_path": list(b"data.bin"),
                },
                "events": [file_probe_event(0, b"renamed.bin", b"rename-me")],
            },
        ],
    }


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
                observation_references = []
                for uri in (audit.CONTROL_OBSERVATION, audit.CANDIDATE_OBSERVATION):
                    observation_path = child_root / uri
                    observation_path.parent.mkdir(parents=True, exist_ok=True)
                    observation = observation_fixture()
                    if uri == audit.CONTROL_OBSERVATION:
                        observation["bundle_id"] = "stage3a-control-fixture"
                        observation["route"]["mode"] = "uninterrupted_control"
                        observation["route"]["destination"] = None
                    observation_encoded = audit.write_object(
                        observation_path, observation
                    )
                    observation_references.append(reference(uri, observation_encoded))
                trace_uri = "cases/read-write-offset/evidence/trace.json"
                trace_path = child_root / trace_uri
                trace_path.parent.mkdir(parents=True, exist_ok=True)
                trace = {
                    "case_id": "read-write-offset",
                    "observations": {"offset": 6},
                }
                trace_encoded = audit.write_object(trace_path, trace)
                child = {
                    "bundle_id": "stage3a-baseline",
                    "started_at_unix_ms": 10,
                    "finished_at_unix_ms": 20,
                    "raw_observations": observation_references,
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
        self.assertEqual(len(manifest), 20)
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
        counts = {
            category: sum(entry["category"] == category for entry in manifest)
            for category in {
                audit.SEMANTIC_DEFECT,
                audit.INTEGRITY_TAMPER,
                audit.BENIGN_EQUIVALENT,
                audit.TRUST_BOUNDARY,
            }
        }
        self.assertEqual(
            counts,
            {
                audit.SEMANTIC_DEFECT: 15,
                audit.INTEGRITY_TAMPER: 2,
                audit.BENIGN_EQUIVALENT: 2,
                audit.TRUST_BOUNDARY: 1,
            },
        )
        self.assertEqual(len(audit.corpus_sha256()), 64)

    def test_raw_observation_mutation_reseals_full_binding_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.fixture(root)
            audit.alter_observed_read_offset(bundle, root)

            cell = bundle["cells"][0]
            original = root / cell["original_bundle"]["uri"]
            relocated = root / cell["relocated_bundle"]["uri"]
            self.assertEqual(original.read_bytes(), relocated.read_bytes())
            child = audit.load_object(relocated)
            observation_reference = next(
                value
                for value in child["raw_observations"]
                if value["uri"] == audit.CANDIDATE_OBSERVATION
            )
            observation_path = relocated.parent / observation_reference["uri"]
            observation = audit.load_object(observation_path)
            read_case = next(
                value
                for value in observation["cases"]
                if value["case_id"] == "read-write-offset"
            )
            output = audit.returned_operation_output(
                audit.operation_events(read_case, "read")[-1], "read"
            )
            self.assertEqual(output["logical_offset"], 7)
            assert_reference(self, relocated.parent, observation_reference)
            assert_reference(self, root, cell["original_bundle"])
            assert_reference(self, root, cell["relocated_bundle"])
            assert_reference(self, root, bundle["matrix_run"])
            matrix = audit.load_object(root / bundle["matrix_run"]["uri"])
            self.assertEqual(
                matrix["receipts"][0]["evidence_bundle"],
                cell["relocated_bundle"],
            )

    def test_duplicate_append_is_inserted_and_resequenced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.fixture(root)
            audit.duplicate_observed_append(bundle, root)
            child_path = root / bundle["cells"][0]["relocated_bundle"]["uri"]
            child = audit.load_object(child_path)
            reference_value = next(
                value
                for value in child["raw_observations"]
                if value["uri"] == audit.CANDIDATE_OBSERVATION
            )
            observation = audit.load_object(child_path.parent / reference_value["uri"])
            append_case = next(
                value
                for value in observation["cases"]
                if value["case_id"] == "append-continuity"
            )
            appends = audit.operation_events(append_case, "append")
            self.assertEqual(len(appends), 2)
            self.assertEqual(
                [event["sequence"] for event in append_case["events"]],
                list(range(len(append_case["events"]))),
            )
            self.assertEqual(
                appends[-1]["body"]["data"]["idempotency_key"],
                "audit-duplicate-append",
            )

    def test_conflicting_probe_precedes_expected_probe_to_defeat_last_write_wins(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.fixture(root)
            audit.add_conflicting_final_file_probe(bundle, root)
            child_path = root / bundle["cells"][0]["relocated_bundle"]["uri"]
            child = audit.load_object(child_path)
            reference_value = next(
                value
                for value in child["raw_observations"]
                if value["uri"] == audit.CANDIDATE_OBSERVATION
            )
            observation = audit.load_object(child_path.parent / reference_value["uri"])
            rename_case = next(
                value
                for value in observation["cases"]
                if value["case_id"] == "rename-object-identity"
            )
            renamed_path = list(b"renamed.bin")
            probes = [
                event
                for event in rename_case["events"]
                if event["body"]["kind"] == "file_probe"
                and event["body"]["data"]["path"] == renamed_path
            ]
            contents = [
                bytes(probe["body"]["data"]["entry"]["data"]["bytes"])
                for probe in probes
            ]
            self.assertEqual(contents, [b"evil", b"rename-me"])
            self.assertEqual(
                [event["sequence"] for event in rename_case["events"]],
                list(range(len(rename_case["events"]))),
            )
            self.assertEqual(contents[-1], b"rename-me")

    def test_assertion_reordering_is_encoded_as_benign_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.fixture(root)
            audit.reorder_assertion_set(bundle, root)
            child_path = root / bundle["cells"][0]["relocated_bundle"]["uri"]
            child = audit.load_object(child_path)
            names = [value["name"] for value in child["cases"][0]["assertions"]]
            self.assertEqual(names, ["logical_offset_preserved", "bytes_preserved"])

    def test_unattested_observation_host_is_resealed_as_explicit_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.fixture(root)
            audit.reseal_unattested_observation_host(bundle, root)
            child_path = root / bundle["cells"][0]["relocated_bundle"]["uri"]
            child = audit.load_object(child_path)
            observation_reference = next(
                value
                for value in child["raw_observations"]
                if value["uri"] == audit.CANDIDATE_OBSERVATION
            )
            observation = json.loads(
                (child_path.parent / observation_reference["uri"]).read_text()
            )
            self.assertEqual(
                observation["route"]["source"]["host_id"],
                "fixture-host-unattested-audit",
            )
            assert_reference(self, child_path.parent, observation_reference)

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

    def test_raw_semantic_disposition_requires_nested_oracle_rejection(self) -> None:
        mutation = next(
            value
            for value in audit.MUTATIONS
            if audit.CHILD_BUNDLE_REJECTION in value.expected_finding_codes
        )
        completed = subprocess.CompletedProcess([], 1, "", "")
        observed, matched = audit.observed_verdict(
            mutation,
            completed,
            [audit.CHILD_BUNDLE_REJECTION],
            [],
        )
        self.assertEqual(observed, audit.REJECT)
        self.assertFalse(matched)

        observed, matched = audit.observed_verdict(
            mutation,
            completed,
            [audit.CHILD_BUNDLE_REJECTION],
            [audit.SEMANTIC_ORACLE_REJECTION],
        )
        self.assertEqual(observed, audit.REJECT)
        self.assertTrue(matched)


if __name__ == "__main__":
    unittest.main(verbosity=2)
