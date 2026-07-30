#!/usr/bin/env python3
"""Mutation tests for the strict stock-SQLite source and Wasm checker."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


CHECKER_PATH = Path(__file__).with_name("check-sqlite-source.py")
SPEC = importlib.util.spec_from_file_location("stock_sqlite_source_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load stock-SQLite source checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class StockSQLiteSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        (CHECKER.ROOT / "target").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="stock-sqlite-source-test-", dir=CHECKER.ROOT / "target"
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
        CHECKER.validate()

    def test_source_patch_cannot_be_introduced(self) -> None:
        self.document["source_policy"]["source_patches"] = ["sqlite.patch"]
        with self.assertRaisesRegex(CHECKER.LockError, "source_patches"):
            CHECKER.validate(self.write_lock())

    def test_official_archive_identity_is_fixed(self) -> None:
        self.document["upstream"]["archive"]["sha3_256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "archive.sha3_256"):
            CHECKER.validate(self.write_lock())

    def test_source_id_is_fixed(self) -> None:
        self.document["upstream"]["source_id"] = "rewritten"
        with self.assertRaisesRegex(CHECKER.LockError, "upstream.source_id"):
            CHECKER.validate(self.write_lock())

    def test_upstream_member_identity_is_fixed(self) -> None:
        self.document["upstream"]["files"][1]["sha256"] = "b" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "upstream.files"):
            CHECKER.validate(self.write_lock())

    def test_every_workload_is_content_pinned(self) -> None:
        self.document["source_policy"]["workloads"]["transaction"]["sha256"] = "c" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "transaction workload digest mismatch"):
            CHECKER.validate(self.write_lock())

    def test_workload_set_is_exact(self) -> None:
        self.document["source_policy"]["workloads"]["unlocked"] = {
            "path": "third_party/sqlite/workload/basic.sql",
            "sha256": "c" * 64,
        }
        with self.assertRaisesRegex(CHECKER.LockError, "source_policy.workloads keys drifted"):
            CHECKER.validate(self.write_lock())

    def test_compatibility_object_is_content_pinned(self) -> None:
        self.document["source_policy"]["compatibility_source"]["sha256"] = "d" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "compatibility source digest"):
            CHECKER.validate(self.write_lock())

    def test_build_definitions_cannot_enable_wal(self) -> None:
        self.document["wasi_build"]["definitions"].remove("SQLITE_OMIT_WAL")
        with self.assertRaisesRegex(CHECKER.LockError, "wasi_build.definitions"):
            CHECKER.validate(self.write_lock())

    def test_import_surface_is_exact(self) -> None:
        self.document["wasi_build"]["expected_imports"].append(["env", "fcntl"])
        with self.assertRaisesRegex(CHECKER.LockError, "expected_imports"):
            CHECKER.validate(self.write_lock())

    def test_carrier_optimization_cannot_be_changed(self) -> None:
        self.document["carrier_build"]["optimization"] = "-O0"
        with self.assertRaisesRegex(CHECKER.LockError, "carrier_build.optimization"):
            CHECKER.validate(self.write_lock())

    def test_duplicate_json_key_is_rejected(self) -> None:
        raw = CHECKER.DEFAULT_LOCK.read_text(encoding="utf-8")
        raw = raw.replace(
            '  "schema": "visa-stock-sqlite-source-lock-v1",\n',
            '  "schema": "visa-stock-sqlite-source-lock-v1",\n'
            '  "schema": "visa-stock-sqlite-source-lock-v1",\n',
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

    def test_wasm_parser_rejects_non_module_bytes(self) -> None:
        path = self.root / "not.wasm"
        path.write_bytes(b"not wasm")
        with self.assertRaisesRegex(CHECKER.LockError, "WebAssembly v1"):
            CHECKER.wasm_function_imports(path)

    def test_archive_validator_rejects_truncated_payload(self) -> None:
        path = self.root / "sqlite.zip"
        path.write_bytes(b"PK\x05\x06" + b"\0" * 18)
        with self.assertRaisesRegex(CHECKER.LockError, "archive size mismatch"):
            CHECKER.validate_archive(path, self.document)


if __name__ == "__main__":
    unittest.main()
