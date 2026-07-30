#!/usr/bin/env python3
"""Focused self-tests for the stock-zstd transparent migration runner."""

from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


RUNNER = Path(__file__).with_name("run-stock-zstd-migration-matrix.py")
SPEC = importlib.util.spec_from_file_location("stock_zstd_migration_matrix", RUNNER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load stock-zstd migration runner")
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class RunnerTests(unittest.TestCase):
    @staticmethod
    def receipt_chain_fixture() -> dict[str, object]:
        source_lock_sha256 = "1" * 64
        wanco_source_lock_sha256 = "2" * 64
        wanco_receipt_sha256 = "3" * 64
        image_id = "sha256:" + "4" * 64
        compiler_sha256 = "5" * 64
        runtime_sha256 = "6" * 64
        wasm_sha256 = "7" * 64
        revision = "8" * 40
        build_receipt = {
            "artifacts": {
                "zstd-v1.5.7.wasm": {
                    "sha256": wasm_sha256,
                    "size": 1,
                }
            },
            "build_recipe_sha256": "9" * 64,
            "carrier_qualification": "qualified",
            "source_lock_sha256": source_lock_sha256,
            "wanco_build_receipt_sha256": wanco_receipt_sha256,
            "wanco_compiler_sha256": compiler_sha256,
            "wanco_image": "wanco:locked",
            "wanco_image_id": image_id,
            "wanco_optimization": "-O1",
            "wanco_revision": revision,
            "wanco_runtime_sha256": runtime_sha256,
            "wanco_source_lock_sha256": wanco_source_lock_sha256,
            "zero_upstream_source_patches": True,
            "zstd_revision": "a" * 40,
        }
        source_lock = {
            "schema": "visa-stock-zstd-source-lock-v1",
            "upstream": {"revision": "a" * 40},
            "source_policy": {
                "source_patches": [],
                "build_recipe": {"sha256": "9" * 64},
            },
            "wasi_build": {
                "expected_wasm_sha256": wasm_sha256,
                "optimization": "-O1",
            },
            "carrier_build": {
                "wanco_source_lock": {
                    "sha256": wanco_source_lock_sha256
                },
                "wanco_revision": revision,
                "wanco_compiler_sha256": compiler_sha256,
                "wanco_runtime_sha256": runtime_sha256,
                "optimization": "-O1",
                "qualification": "qualified",
            },
        }
        wanco_source_lock = {
            "schema": "visa-wanco-carrier-source-lock-v2",
            "upstream": {"revision": revision},
        }
        wanco_receipt = {
            "schema": "visa-wanco-carrier-build-receipt-v4",
            "revision": revision,
            "wanco_binary_sha256": compiler_sha256,
            "runtime_staticlib_sha256": runtime_sha256,
            "image_tag": "wanco:locked",
            "image_id": image_id,
            "stackmap_binding": "exact-active-callsite-id",
            "stackmap_layout": "typed-locals-and-value-stack-v2",
            "indirect_call_operands_retained": True,
            "active_data_segments_preserved_on_restore": True,
            "per_frame_callee_saved_registers": True,
            "post_import_checkpoint_points": True,
        }
        return {
            "build_receipt": build_receipt,
            "source_lock": source_lock,
            "source_lock_sha256": source_lock_sha256,
            "wanco_source_lock": wanco_source_lock,
            "wanco_source_lock_sha256": wanco_source_lock_sha256,
            "wanco_receipt": wanco_receipt,
            "wanco_receipt_sha256": wanco_receipt_sha256,
            "live_wanco_image_id": image_id,
        }

    def test_canonical_bytes_are_compact_sorted_utf8_json(self) -> None:
        payload = MATRIX.canonical_bytes({"z": "λ", "a": [2, 1]})
        self.assertEqual(payload, '{"a":[2,1],"z":"λ"}'.encode())
        self.assertEqual(json.loads(payload), {"a": [2, 1], "z": "λ"})

    def test_deterministic_input_is_exact_and_reproducible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="stock-zstd-runner-test-") as raw:
            root = Path(raw)
            first = root / "first"
            second = root / "second"
            MATRIX.write_deterministic_input(first, 131_101)
            MATRIX.write_deterministic_input(second, 131_101)
            self.assertEqual(first.stat().st_size, 131_101)
            self.assertEqual(MATRIX.file_identity(first), MATRIX.file_identity(second))

    def test_stable_id_is_nonzero_hex_and_label_bound(self) -> None:
        first = MATRIX.stable_id("first")
        self.assertEqual(len(first), 32)
        self.assertNotEqual(first, "0" * 32)
        self.assertNotEqual(first, MATRIX.stable_id("second"))

    def test_checkpoint_cut_uses_exact_barrier_not_byte_polling_or_signal(self) -> None:
        source = inspect.getsource(MATRIX.checkpoint_source)
        self.assertIn('"barrier-arm"', source)
        self.assertIn('"barrier-release"', source)
        self.assertIn('"checkpoint"', source)
        self.assertNotIn("bytes_written", source)
        self.assertNotIn("SIGUSR1", source)
        self.assertNotIn('"kill"', source)

    def test_expected_rejection_records_bounded_diagnostic(self) -> None:
        completed = subprocess.CompletedProcess(
            ["fixture"], 7, stdout=b"", stderr=b"x" * 800
        )
        result = MATRIX.expect_rejection(
            completed,
            "fixture-fault",
            detector="fixture-detector",
            expected_stderr_any=("xxx",),
        )
        self.assertEqual(result["exit_status"], 7)
        self.assertEqual(result["fault"], "fixture-fault")
        self.assertEqual(result["detector"], "fixture-detector")
        self.assertEqual(len(result["stderr_tail"]), 320)
        with self.assertRaises(MATRIX.MatrixFailure):
            MATRIX.expect_rejection(
                subprocess.CompletedProcess(
                    ["fixture"], 0, stdout=b"", stderr=b""
                ),
                "accepted",
                detector="fixture-detector",
                expected_stderr_any=("fixture",),
            )
        with self.assertRaises(MATRIX.MatrixFailure):
            MATRIX.expect_rejection(
                subprocess.CompletedProcess(
                    ["fixture"], 7, stdout=b"", stderr=b"unrelated"
                ),
                "wrong-detector",
                detector="fixture-detector",
                expected_stderr_any=("expected",),
            )

    def test_execution_input_chain_accepts_only_exact_cross_bindings(self) -> None:
        fixture = self.receipt_chain_fixture()
        binding = MATRIX.validate_execution_input_chain(**fixture)
        self.assertEqual(binding["wanco_image"], "wanco:locked")
        self.assertEqual(
            binding["wanco_image_id"], fixture["live_wanco_image_id"]
        )

        mutations = {
            "live-image": lambda value: value.__setitem__(
                "live_wanco_image_id", "sha256:" + "f" * 64
            ),
            "source-lock": lambda value: value["build_receipt"].__setitem__(
                "source_lock_sha256", "f" * 64
            ),
            "wanco-receipt": lambda value: value[
                "build_receipt"
            ].__setitem__("wanco_build_receipt_sha256", "f" * 64),
            "source-policy": lambda value: value["source_lock"][
                "source_policy"
            ].__setitem__("source_patches", ["forbidden.patch"]),
            "image-tag": lambda value: value["wanco_receipt"].__setitem__(
                "image_tag", "wanco:retargeted"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(fixture)
                mutate(changed)
                with self.assertRaises(MATRIX.MatrixFailure):
                    MATRIX.validate_execution_input_chain(**changed)

    def test_command_failure_does_not_echo_bearer_arguments(self) -> None:
        secret = "not-for-diagnostics-bearer"
        with tempfile.TemporaryDirectory(prefix="stock-zstd-runner-test-") as raw:
            with self.assertRaises(MATRIX.MatrixFailure) as raised:
                MATRIX.run(
                    ["/bin/sh", "-c", "exit 7", secret],
                    cwd=Path(raw),
                )
        self.assertNotIn(secret, str(raised.exception))
        self.assertIn("sh", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
