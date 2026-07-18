#!/usr/bin/env python3
"""Mutation tests for the project claim registry checker."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
REGISTRY_MODULE_PATH = ROOT / "scripts/claims_registry.py"
SPEC = importlib.util.spec_from_file_location(
    "claims_registry_under_test", REGISTRY_MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
REGISTRY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGISTRY)

Registry = dict[str, Any]
Mutation = Callable[[Registry], None]


class ClaimRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = REGISTRY.load_registry(ROOT / "claims/registry.json")

    def assert_baseline_valid(self, root: Path = ROOT) -> None:
        REGISTRY.validate_registry(copy.deepcopy(self.registry), root)

    def assert_rejected(
        self,
        expected_error: str,
        mutation: Mutation,
        *,
        root: Path = ROOT,
    ) -> None:
        self.assert_baseline_valid(root)
        candidate = copy.deepcopy(self.registry)
        mutation(candidate)
        with self.assertRaisesRegex(REGISTRY.RegistryError, expected_error):
            REGISTRY.validate_registry(candidate, root)

    def materialize_minimal_repository(self, root: Path) -> None:
        for relative in REGISTRY.CANONICAL_DOCS:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)

        for claim in self.registry["claims"]:
            for relative in claim["implementation_refs"]:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.touch()

    def test_repository_registry_is_valid(self) -> None:
        self.assert_baseline_valid()

    def test_unknown_claim_field_is_rejected(self) -> None:
        self.assert_rejected(
            r"claims\[0\] keys drifted",
            lambda value: value["claims"][0].__setitem__("unknown", True),
        )

    def test_unsorted_claims_are_rejected(self) -> None:
        self.assert_rejected(
            r"claims must be sorted by id",
            lambda value: value["claims"].reverse(),
        )

    def test_lineage_cycle_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            REGISTRY.RegistryError, r"predecessor graph contains a cycle"
        ):
            REGISTRY.check_lineage(
                {
                    "candidate-a": {"predecessor_ids": ["candidate-b"]},
                    "candidate-b": {"predecessor_ids": ["candidate-a"]},
                }
            )

    def test_self_predecessor_is_rejected(self) -> None:
        self.assert_rejected(
            r"cannot be its own predecessor",
            lambda value: value["claims"][1].__setitem__(
                "predecessor_ids", ["bounded-joint-handoff-refinement-v2"]
            ),
        )

    def test_unknown_predecessor_is_rejected(self) -> None:
        self.assert_rejected(
            r"has unknown predecessor unknown-claim",
            lambda value: value["claims"][1].__setitem__(
                "predecessor_ids", ["unknown-claim"]
            ),
        )

    def test_unknown_workflow_claim_is_rejected(self) -> None:
        self.assert_rejected(
            r"references unknown claim 'unknown-claim'",
            lambda value: value["workflow_bindings"][0]["claims"][0].__setitem__(
                "id", "unknown-claim"
            ),
        )

    def test_duplicate_claim_binding_is_rejected(self) -> None:
        def mutate(value: Registry) -> None:
            binding = value["workflow_bindings"][0]
            binding["claims"].append(copy.deepcopy(binding["claims"][0]))

        self.assert_rejected(r"binds .* more than once", mutate)

    def test_unsafe_implementation_path_is_rejected(self) -> None:
        self.assert_rejected(
            r"is not a safe repository-relative path: '\.\./outside'",
            lambda value: value["claims"][0].__setitem__(
                "implementation_refs", ["../outside"]
            ),
        )

    def test_implementation_directory_is_rejected(self) -> None:
        self.assert_rejected(
            r"must name a regular file: scripts",
            lambda value: value["claims"][0].__setitem__(
                "implementation_refs", ["scripts"]
            ),
        )

    def test_implementation_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.materialize_minimal_repository(root)
            target = root / "fixtures/implementation-target"
            link = root / "fixtures/implementation-link"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.touch()
            link.symlink_to(target.name)

            self.assert_rejected(
                r"traverses a symlink: fixtures/implementation-link",
                lambda value: value["claims"][0].__setitem__(
                    "implementation_refs", ["fixtures/implementation-link"]
                ),
                root=root,
            )

    def test_canonical_document_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.materialize_minimal_repository(root)
            self.assert_baseline_valid(root)
            roadmap = root / "docs/ROADMAP.md"
            roadmap.unlink()
            roadmap.symlink_to(ROOT / "docs/ROADMAP.md")

            with self.assertRaisesRegex(
                REGISTRY.RegistryError,
                r"scope_ref traverses a symlink: docs/ROADMAP.md",
            ):
                REGISTRY.validate_registry(copy.deepcopy(self.registry), root)

    def test_readme_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.materialize_minimal_repository(root)
            self.assert_baseline_valid(root)
            readme = root / "README.md"
            readme.unlink()
            readme.symlink_to(ROOT / "README.md")

            with self.assertRaisesRegex(
                REGISTRY.RegistryError,
                r"README claim index traverses a symlink: README.md",
            ):
                REGISTRY.validate_registry(copy.deepcopy(self.registry), root)

    def test_readme_index_rejects_extra_marker_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.materialize_minimal_repository(root)
            readme = root / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8").replace(
                    REGISTRY.README_END,
                    "contradictory unindexed claim\n" + REGISTRY.README_END,
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                REGISTRY.RegistryError,
                r"README claim index contains a noncanonical row",
            ):
                REGISTRY.validate_registry(copy.deepcopy(self.registry), root)

    def test_new_root_claim_cannot_use_historical_acceptance(self) -> None:
        claim = copy.deepcopy(self.registry["claims"][1])
        claim["id"] = "fabricated-earned-root"
        claim["status"] = "earned"
        claim["predecessor_ids"] = []
        claim["acceptance_ref"]["kind"] = "canonical-validation"
        claim["acceptance_ref"]["path"] = (
            "claims/receipts/fabricated-earned-root.json"
        )
        claim["acceptance_ref"]["receipt_sha256"] = "a" * 64
        with self.assertRaisesRegex(
            REGISTRY.RegistryError,
            r"fabricated-earned-root non-historical claim lacks a permanent receipt",
        ):
            REGISTRY.validate_acceptance_ref(ROOT, claim)

    def test_candidate_cannot_promote_itself_without_receipt(self) -> None:
        self.assert_rejected(
            r"bounded-joint-handoff-refinement-v2 non-historical claim lacks a permanent receipt",
            lambda value: value["claims"][1].__setitem__("status", "earned"),
        )

    def test_format_only_v1_receipt_cannot_promote_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.materialize_minimal_repository(root)
            candidate = copy.deepcopy(self.registry)
            claim = candidate["claims"][1]
            claim["status"] = "earned"
            claim["acceptance_ref"]["kind"] = "permanent-archive-receipt"
            for binding in candidate["workflow_bindings"]:
                for bound_claim in binding["claims"]:
                    if bound_claim["id"] == claim["id"]:
                        bound_claim["role"] = "regresses"

            readme = root / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8").replace(
                    "| `bounded-joint-handoff-refinement-v2` | `candidate` |",
                    "| `bounded-joint-handoff-refinement-v2` | `earned` |",
                ),
                encoding="utf-8",
            )
            receipt = root / claim["acceptance_ref"]["path"]
            receipt.parent.mkdir(parents=True, exist_ok=True)
            tag = "evidence-bounded-joint-handoff-refinement-v2-01234567"
            receipt.write_text(
                json.dumps(
                    {
                        "schema": "visa.project-claim-closure.v1",
                        "claim_id": claim["id"],
                        "accepted_revision": "a" * 40,
                        "workflow_run_id": 1,
                        "archive_manifest_sha256": "b" * 64,
                        "release_tag": tag,
                        "release_uri": (
                            "https://github.com/chenty2333/vISA/releases/tag/"
                            f"{tag}"
                        ),
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            claim["acceptance_ref"]["receipt_sha256"] = (
                hashlib.sha256(receipt.read_bytes()).hexdigest()
            )
            manifest = (
                root
                / "claims/archive-manifests/"
                "bounded-joint-handoff-refinement-v2.json"
            )
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(
                REGISTRY.RegistryError,
                r"permanent archive closure is invalid: .*keys drifted",
            ):
                REGISTRY.validate_registry(candidate, root)

    def test_candidate_rejects_unconsumed_closure_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.materialize_minimal_repository(root)
            self.assert_baseline_valid(root)

            receipt = (
                root
                / "claims/receipts/bounded-joint-handoff-refinement-v2.json"
            )
            receipt.parent.mkdir(parents=True, exist_ok=True)
            receipt.write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(
                REGISTRY.RegistryError,
                r"bounded-joint-handoff-refinement-v2 candidate has an unconsumed closure receipt",
            ):
                REGISTRY.validate_registry(copy.deepcopy(self.registry), root)

    def test_candidate_rejects_a_dangling_receipt_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.materialize_minimal_repository(root)
            receipt = (
                root
                / "claims/receipts/bounded-joint-handoff-refinement-v2.json"
            )
            receipt.parent.mkdir(parents=True, exist_ok=True)
            receipt.symlink_to("missing-receipt.json")

            with self.assertRaisesRegex(
                REGISTRY.RegistryError,
                r"bounded-joint-handoff-refinement-v2 candidate has an unconsumed closure receipt",
            ):
                REGISTRY.validate_registry(copy.deepcopy(self.registry), root)

    def test_invalid_workflow_role_is_rejected(self) -> None:
        self.assert_rejected(
            r"has invalid role 'qualifies'",
            lambda value: value["workflow_bindings"][0]["claims"][0].__setitem__(
                "role", "qualifies"
            ),
        )

    def test_candidate_cannot_be_regressed(self) -> None:
        self.assert_rejected(
            r"cannot regress unearned candidate bounded-joint-handoff-refinement-v2",
            lambda value: value["workflow_bindings"][0]["claims"][0].__setitem__(
                "role", "regresses"
            ),
        )

    def test_candidate_acceptance_artifacts_match_required_ci_evidence(self) -> None:
        self.assert_rejected(
            r"acceptance artifacts differ from bound CI evidence",
            lambda value: value["claims"][1]["acceptance_ref"].__setitem__(
                "workflow_artifacts",
                [
                    "joint-handoff-reference-system-evidence",
                    "unrelated-successful-artifact",
                ],
            ),
        )

    def test_candidate_semantic_contract_digest_is_checked(self) -> None:
        self.assert_rejected(
            r"scope semantic contract digest drifted",
            lambda value: value["claims"][1]["acceptance_ref"][
                "semantic_contracts"
            ].__setitem__("scope_sha256", "0" * 64),
        )

    def test_duplicate_json_key_is_rejected(self) -> None:
        self.assert_baseline_valid()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "registry.json"
            path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(
                REGISTRY.RegistryError, r"duplicate JSON key: schema"
            ):
                REGISTRY.load_registry(path)

    def test_registry_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "registry-target.json"
            target.write_text(json.dumps(self.registry), encoding="utf-8")
            link = root / "registry.json"
            link.symlink_to(target.name)
            with self.assertRaisesRegex(
                REGISTRY.RegistryError, r"claim registry must be a regular file"
            ):
                REGISTRY.load_registry(link)


if __name__ == "__main__":
    unittest.main()
