#!/usr/bin/env python3
"""Self-tests for the reference-only joint handoff source lock."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


CHECKER_PATH = Path(__file__).with_name("check-joint-handoff-source-lock.py")
SPEC = importlib.util.spec_from_file_location("joint_source_lock_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load joint source-lock checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class SourceLockTests(unittest.TestCase):
    def setUp(self) -> None:
        (CHECKER.ROOT / "target").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="joint-source-lock-test-",
            dir=CHECKER.ROOT / "target",
        )
        self.root = Path(self.temporary.name)
        self.document = json.loads(CHECKER.DEFAULT_LOCK.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_lock(self, document: object | None = None) -> Path:
        path = self.root / "source-lock.json"
        value = self.document if document is None else document
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        return path

    def test_current_lock_passes(self) -> None:
        CHECKER.validate(CHECKER.DEFAULT_LOCK)

    def test_neutral_revision_must_be_the_locked_bundle_head(self) -> None:
        self.document["joint_artifact"]["revision"] = "a" * 40
        with self.assertRaisesRegex(CHECKER.LockError, "head must equal"):
            CHECKER.validate(self.write_lock())

    def test_neutral_tree_must_match_the_exact_revision(self) -> None:
        self.document["joint_artifact"]["tree"] = "a" * 40
        with self.assertRaisesRegex(CHECKER.LockError, "neutral tree mismatch"):
            CHECKER.validate(self.write_lock())

    def test_neutral_bundle_head_must_equal_the_exact_revision(self) -> None:
        self.document["joint_artifact"]["source_bundle"]["head"] = "a" * 40
        with self.assertRaisesRegex(CHECKER.LockError, "head must equal"):
            CHECKER.validate(self.write_lock())

    def test_neutral_snapshot_blob_must_match_the_exact_revision(self) -> None:
        self.document["protocol_schema"]["git_blob"] = "a" * 40
        with self.assertRaisesRegex(CHECKER.LockError, "neutral blob mismatch"):
            CHECKER.validate(self.write_lock())

    def test_neutral_bundle_digest_is_pinned(self) -> None:
        self.document["joint_artifact"]["source_bundle"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "bundle digest mismatch"):
            CHECKER.validate(self.write_lock())

    def test_neutral_source_path_cannot_be_redirected(self) -> None:
        self.document["protocol_schema"]["source_path"] = (
            "specs/joint-handoff/wire-v1.toml"
        )
        with self.assertRaisesRegex(CHECKER.LockError, "source_path must be"):
            CHECKER.validate(self.write_lock())

    def test_machine_contract_is_the_native_refinement_toml(self) -> None:
        self.document["machine_contract"]["source_path"] = (
            "specs/joint-handoff/wire-v1.toml"
        )
        with self.assertRaisesRegex(CHECKER.LockError, "source_path must be"):
            CHECKER.validate(self.write_lock())

    def test_neutral_wire_contract_source_cannot_be_redirected(self) -> None:
        self.document["neutral_wire_contract"]["source_path"] = (
            "specs/joint-handoff/nexus-native-v1-refinement.toml"
        )
        with self.assertRaisesRegex(CHECKER.LockError, "source_path must be"):
            CHECKER.validate(self.write_lock())

    def test_machine_contract_digest_is_pinned(self) -> None:
        self.document["machine_contract"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "snapshot digest mismatch"):
            CHECKER.validate(self.write_lock())

    def test_machine_contract_cannot_claim_adapter_qualification(self) -> None:
        source = CHECKER.ROOT / CHECKER.EXPECTED_MACHINE_CONTRACT_PATH
        mutated = source.read_text(encoding="utf-8").replace(
            "adapter_qualification = false",
            "adapter_qualification = true",
            1,
        )
        path = self.root / "mutated-native-refinement.toml"
        path.write_text(mutated, encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.LockError, "adapter qualification"):
            CHECKER.validate_native_machine_contract(path)

    def test_reference_revision_must_equal_neutral_analyzed_baseline(self) -> None:
        self.document["nexus"]["revision"] = "a" * 40
        with self.assertRaisesRegex(CHECKER.LockError, "neutral analyzed baseline"):
            CHECKER.validate(self.write_lock())

    def test_nexus_execution_role_cannot_claim_qualification(self) -> None:
        self.document["nexus"]["execution"] = "executed-checkout"
        with self.assertRaisesRegex(CHECKER.LockError, "reference-peer-only"):
            CHECKER.validate(self.write_lock())

    def test_duplicate_json_key_is_rejected(self) -> None:
        raw = CHECKER.DEFAULT_LOCK.read_text(encoding="utf-8")
        raw = raw.replace(
            '  "schema": "visa.joint-handoff-qualification-source-lock.v1",\n',
            '  "schema": "visa.joint-handoff-qualification-source-lock.v1",\n'
            '  "schema": "visa.joint-handoff-qualification-source-lock.v1",\n',
            1,
        )
        path = self.root / "duplicate.json"
        path.write_text(raw, encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.LockError, "duplicate key"):
            CHECKER.validate(path)

    def test_symlink_lock_is_rejected(self) -> None:
        target = self.write_lock()
        link = self.root / "source-lock-link.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(CHECKER.LockError, "regular non-symlink"):
            CHECKER.validate(link)


if __name__ == "__main__":
    unittest.main()
