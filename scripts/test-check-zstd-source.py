#!/usr/bin/env python3
"""Self-tests for the strict stock-zstd source and Wasm lock checker."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


CHECKER_PATH = Path(__file__).with_name("check-zstd-source.py")
SPEC = importlib.util.spec_from_file_location("stock_zstd_source_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load stock-zstd source checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class StockZstdSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        (CHECKER.ROOT / "target").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="stock-zstd-source-test-",
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
        CHECKER.validate()

    def test_source_patches_cannot_be_introduced(self) -> None:
        self.document["source_policy"]["source_patches"] = ["fix-zstd.patch"]
        with self.assertRaisesRegex(CHECKER.LockError, "empty source_patches"):
            CHECKER.validate(self.write_lock())

    def test_upstream_tree_is_the_exact_v157_identity(self) -> None:
        self.document["upstream"]["tree"] = "a" * 40
        with self.assertRaisesRegex(CHECKER.LockError, "upstream.tree"):
            CHECKER.validate(self.write_lock())

    def test_upstream_license_payload_is_exact(self) -> None:
        self.document["upstream"]["licenses"][0]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, r"license\[0\]\.sha256"):
            CHECKER.validate(self.write_lock())

    def test_compatibility_object_digest_is_pinned(self) -> None:
        self.document["source_policy"]["compatibility_object"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "compatibility object digest"):
            CHECKER.validate(self.write_lock())

    def test_build_recipe_digest_is_pinned(self) -> None:
        self.document["source_policy"]["build_recipe"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "build recipe digest"):
            CHECKER.validate(self.write_lock())

    def test_bridge_workspace_digest_is_pinned(self) -> None:
        self.document["source_policy"]["bridge_workspace"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "bridge workspace digest"):
            CHECKER.validate(self.write_lock())

    def test_bridge_dependency_lock_digest_is_pinned(self) -> None:
        self.document["source_policy"]["bridge_lock"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "bridge dependency lock digest"):
            CHECKER.validate(self.write_lock())

    def test_dockerfile_digest_is_pinned(self) -> None:
        self.document["wasi_build"]["dockerfile"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "Dockerfile digest"):
            CHECKER.validate(self.write_lock())

    def test_wasi_package_payload_is_exact(self) -> None:
        self.document["wasi_build"]["packages"][0]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, r"package\[0\]\.sha256"):
            CHECKER.validate(self.write_lock())

    def test_wasm_digest_is_exact(self) -> None:
        self.document["wasi_build"]["expected_wasm_sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "expected_wasm_sha256"):
            CHECKER.validate(self.write_lock())

    def test_bare_native_metadata_symbols_are_forbidden(self) -> None:
        self.document["wasi_build"]["expected_imports"][0] = ["env", "chmod"]
        with self.assertRaisesRegex(CHECKER.LockError, "metadata compatibility imports"):
            CHECKER.validate(self.write_lock())

    def test_carrier_optimization_cannot_be_demoted_to_o0(self) -> None:
        self.document["carrier_build"]["optimization"] = "-O0"
        with self.assertRaisesRegex(CHECKER.LockError, "must be '-O1'"):
            CHECKER.validate(self.write_lock())

    def test_o1_qualification_basis_cannot_be_rewritten(self) -> None:
        self.document["carrier_build"]["o1_status"]["qualification_basis"] = (
            "unqualified-local-claim"
        )
        with self.assertRaisesRegex(CHECKER.LockError, "qualification_basis"):
            CHECKER.validate(self.write_lock())

    def test_wanco_source_lock_is_content_pinned(self) -> None:
        self.document["carrier_build"]["wanco_source_lock"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(CHECKER.LockError, "Wanco source-lock digest"):
            CHECKER.validate(self.write_lock())

    def test_duplicate_json_key_is_rejected(self) -> None:
        raw = CHECKER.DEFAULT_LOCK.read_text(encoding="utf-8")
        raw = raw.replace(
            '  "schema": "visa-stock-zstd-source-lock-v1",\n',
            '  "schema": "visa-stock-zstd-source-lock-v1",\n'
            '  "schema": "visa-stock-zstd-source-lock-v1",\n',
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


if __name__ == "__main__":
    unittest.main()
