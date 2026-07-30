#!/usr/bin/env python3
"""Focused tests for retained receipt artifact publication and reading."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

import receipt_artifacts as ARTIFACTS


class ReceiptArtifactTests(unittest.TestCase):
    def test_publish_and_read_exact_reference(self) -> None:
        with tempfile.TemporaryDirectory(prefix="receipt-artifact-") as raw:
            temporary = Path(raw)
            root = temporary / "root"
            root.mkdir()
            source = temporary / "source"
            source.write_bytes(b"retained semantic observation\n")
            reference = ARTIFACTS.publish_reference(
                source, root, "observations/cell/raw.stdout"
            )
            self.assertEqual(
                reference,
                {
                    "path": "observations/cell/raw.stdout",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "size": source.stat().st_size,
                },
            )
            budget = ARTIFACTS.ReadBudget(1024)
            self.assertEqual(
                ARTIFACTS.read_reference(
                    root,
                    reference,
                    "fixture",
                    budget=budget,
                    max_bytes=1024,
                ),
                source.read_bytes(),
            )
            self.assertEqual(budget.total_bytes, source.stat().st_size)
            ARTIFACTS.read_reference(
                root,
                reference,
                "fixture repeat",
                budget=budget,
                max_bytes=1024,
            )
            self.assertEqual(budget.total_bytes, source.stat().st_size)

    def test_noncanonical_paths_are_rejected(self) -> None:
        for path in (
            "",
            "/absolute",
            "../escape",
            "a/../escape",
            "a/./file",
            "a//file",
            r"a\file",
        ):
            with self.subTest(path=path), self.assertRaises(
                ARTIFACTS.ArtifactError
            ):
                ARTIFACTS.canonical_relative_path(path, "fixture")

    def test_missing_tampered_symlink_and_hardlink_artifacts_are_rejected(self) -> None:
        scenarios = ("missing", "tampered", "symlink", "hardlink")
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="receipt-artifact-mutation-"
            ) as raw:
                temporary = Path(raw)
                root = temporary / "root"
                root.mkdir()
                source = temporary / "source"
                source.write_bytes(b"original")
                reference = ARTIFACTS.publish_reference(
                    source, root, "observations/raw"
                )
                retained = root / "observations" / "raw"
                if scenario == "missing":
                    retained.unlink()
                elif scenario == "tampered":
                    retained.write_bytes(b"forged")
                elif scenario == "symlink":
                    retained.unlink()
                    retained.symlink_to(source)
                else:
                    (temporary / "alias").hardlink_to(retained)
                with self.assertRaises(ARTIFACTS.ArtifactError):
                    ARTIFACTS.read_reference(
                        root,
                        reference,
                        "mutated fixture",
                        budget=ARTIFACTS.ReadBudget(1024),
                        max_bytes=1024,
                    )

    def test_symlinked_parent_and_root_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="receipt-artifact-link-") as raw:
            temporary = Path(raw)
            root = temporary / "root"
            root.mkdir()
            outside = temporary / "outside"
            outside.mkdir()
            source = temporary / "source"
            source.write_bytes(b"payload")
            (root / "observations").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ARTIFACTS.ArtifactError):
                ARTIFACTS.publish_reference(
                    source, root, "observations/raw"
                )
            linked_root = temporary / "linked-root"
            linked_root.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ARTIFACTS.ArtifactError):
                ARTIFACTS.publish_reference(source, linked_root, "raw")
            top_level = temporary / "receipt.json"
            top_level.write_bytes(b"{}\n")
            self.assertEqual(
                ARTIFACTS.read_bounded_file(
                    top_level, "top-level receipt", max_bytes=16
                ),
                b"{}\n",
            )
            top_level_alias = temporary / "receipt-alias.json"
            top_level_alias.hardlink_to(top_level)
            with self.assertRaises(ARTIFACTS.ArtifactError):
                ARTIFACTS.read_bounded_file(
                    top_level, "hard-linked receipt", max_bytes=16
                )
            top_level_alias.unlink()
            linked_receipt = temporary / "linked-receipt.json"
            linked_receipt.symlink_to(top_level)
            with self.assertRaises(ARTIFACTS.ArtifactError):
                ARTIFACTS.read_bounded_file(
                    linked_receipt, "symlinked receipt", max_bytes=16
                )

    def test_budget_and_declared_identity_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory(prefix="receipt-artifact-budget-") as raw:
            temporary = Path(raw)
            root = temporary / "root"
            root.mkdir()
            source = temporary / "source"
            source.write_bytes(b"0123456789")
            reference = ARTIFACTS.publish_reference(source, root, "raw")
            with self.assertRaises(ARTIFACTS.ArtifactError):
                ARTIFACTS.read_reference(
                    root,
                    reference,
                    "over budget",
                    budget=ARTIFACTS.ReadBudget(9),
                    max_bytes=10,
                )
            forged = dict(reference)
            forged["sha256"] = "00" * 32
            with self.assertRaises(ARTIFACTS.ArtifactError):
                ARTIFACTS.read_reference(
                    root,
                    forged,
                    "forged digest",
                    budget=ARTIFACTS.ReadBudget(10),
                    max_bytes=10,
                )

    def test_one_budget_rejects_same_path_mutation_between_reads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="receipt-artifact-repeat-") as raw:
            temporary = Path(raw)
            root = temporary / "root"
            root.mkdir()
            source = temporary / "source"
            source.write_bytes(b"original")
            reference = ARTIFACTS.publish_reference(source, root, "raw")
            budget = ARTIFACTS.ReadBudget(32)
            ARTIFACTS.read_reference(
                root,
                reference,
                "first read",
                budget=budget,
                max_bytes=16,
            )
            retained = root / "raw"
            retained.write_bytes(b"changed!")
            changed_reference = {
                "path": "raw",
                "sha256": hashlib.sha256(b"changed!").hexdigest(),
                "size": len(b"changed!"),
            }
            with self.assertRaisesRegex(
                ARTIFACTS.ArtifactError, "changed between reads"
            ):
                ARTIFACTS.read_reference(
                    root,
                    changed_reference,
                    "second read",
                    budget=budget,
                    max_bytes=16,
                )


if __name__ == "__main__":
    unittest.main()
