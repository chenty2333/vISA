#!/usr/bin/env python3
"""Focused self-tests for the stock-zstd transparent migration runner."""

from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RUNNER = Path(__file__).with_name("run-stock-zstd-migration-matrix.py")
SPEC = importlib.util.spec_from_file_location("stock_zstd_migration_matrix", RUNNER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load stock-zstd migration runner")
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class RunnerTests(unittest.TestCase):
    def test_native_oracle_accepts_package_owned_zstd_1_5_5(self) -> None:
        with tempfile.TemporaryDirectory(prefix="stock-zstd-oracle-test-") as raw:
            root = Path(raw)
            zstd = root / "zstd"
            zstd.write_bytes(b"package-owned-zstd-fixture")
            zstd.chmod(0o755)

            def fake_run(
                command: object, *, cwd: Path, check: bool = True, **_: object
            ) -> subprocess.CompletedProcess[bytes]:
                del cwd, check
                argv = list(command)
                if Path(argv[0]).resolve() == zstd.resolve():
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        b"*** Zstandard CLI (64-bit) v1.5.5, by Yann Collet ***\n",
                        b"",
                    )
                if argv[0] == "/test/rpm":
                    return subprocess.CompletedProcess(
                        argv, 0, b"zstd-1.5.5-1.x86_64", b""
                    )
                raise AssertionError(f"unexpected command: {argv!r}")

            with mock.patch.object(
                MATRIX, "run", side_effect=fake_run
            ), mock.patch.object(
                MATRIX.shutil,
                "which",
                side_effect=lambda name: "/test/rpm" if name == "rpm" else None,
            ):
                identity = MATRIX.native_zstd_identity(zstd, root)

        self.assertIn("v1.5.5", identity["version"])
        self.assertEqual(identity["path"], str(zstd.resolve()))
        self.assertEqual(
            identity["package"],
            {"manager": "rpm", "identity": "zstd-1.5.5-1.x86_64"},
        )

    def test_formal_cli_requires_an_explicit_stock_zstd_oracle(self) -> None:
        with mock.patch.object(MATRIX.sys, "argv", ["runner"]):
            with self.assertRaises(SystemExit) as raised:
                MATRIX.parse_args()
        self.assertEqual(raised.exception.code, 2)

        with mock.patch.object(
            MATRIX.sys,
            "argv",
            ["runner", "--stock-zstd", "/explicit/package-owned/zstd"],
        ):
            arguments = MATRIX.parse_args()
        self.assertEqual(
            arguments.stock_zstd, Path("/explicit/package-owned/zstd")
        )
        main_source = inspect.getsource(MATRIX.main)
        self.assertIn(
            "native_zstd_identity(arguments.stock_zstd, repository)",
            main_source,
        )
        self.assertNotIn('require_tool("zstd")', main_source)

    def test_formal_workload_rejects_custom_input_and_cut_sets(self) -> None:
        MATRIX.validate_formal_workload_arguments(
            MATRIX.DEFAULT_INPUT_MIB,
            MATRIX.DEFAULT_CUT_WRITE_OCCURRENCES,
        )
        for input_mib, cuts in (
            (12, MATRIX.DEFAULT_CUT_WRITE_OCCURRENCES),
            (MATRIX.DEFAULT_INPUT_MIB, (8, 32, 64)),
            (MATRIX.DEFAULT_INPUT_MIB, (64, 8)),
        ):
            with self.subTest(input_mib=input_mib, cuts=cuts), self.assertRaises(
                MATRIX.MatrixFailure
            ):
                MATRIX.validate_formal_workload_arguments(input_mib, cuts)

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
            "schema": "visa-wanco-carrier-source-lock-v3",
            "upstream": {"revision": revision},
        }
        wanco_receipt = {
            "schema": "visa-wanco-carrier-build-receipt-v5",
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
            "guest_tail_calls_disabled": True,
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

    def test_fault_raw_evidence_is_verdict_free_and_published_exactly(self) -> None:
        completed = subprocess.CompletedProcess(
            ["fixture"],
            1,
            stdout=b"ignored output",
            stderr=b"migration integrity failure: bound file content differs\n",
        )
        with tempfile.TemporaryDirectory(prefix="stock-zstd-fault-raw-") as raw:
            root = Path(raw)
            evidence = root / "scratch"
            artifact = root / "artifact"
            artifact.mkdir()
            fault = MATRIX.expect_rejection(
                completed,
                "cut-1-compute-checkpoint-tamper",
                detector="migration-manifest-bound-file-digest",
                expected_stderr_any=(
                    "migration integrity failure: bound file content differs",
                ),
                evidence_root=evidence,
            )
            fault["scope"] = "manifest-verification-path"
            published = MATRIX.publish_fault_raw_artifacts(artifact, fault)
            self.assertNotIn("_raw_stderr_path", published)
            self.assertNotIn("_raw_process_observation_path", published)
            self.assertEqual(
                published["raw_stderr"]["path"],
                "raw/faults/cut-1/compute-checkpoint-tamper.stderr",
            )
            self.assertEqual(
                published["raw_process_observation"]["path"],
                "raw/faults/cut-1/compute-checkpoint-tamper.process.json",
            )
            retained_stderr = artifact / published["raw_stderr"]["path"]
            self.assertEqual(retained_stderr.read_bytes(), completed.stderr)
            process = json.loads(
                (
                    artifact
                    / published["raw_process_observation"]["path"]
                ).read_bytes()
            )
            self.assertEqual(
                process["schema"], MATRIX.FAULT_PROCESS_OBSERVATION_SCHEMA
            )
            self.assertEqual(process["exit_status"], 1)
            self.assertEqual(process["stderr"], MATRIX.bytes_identity(completed.stderr))
            self.assertNotIn("detector", process)
            self.assertNotIn("verdict", process)

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

    def test_raw_oracle_report_is_canonical_and_cell_bound(self) -> None:
        zstd = shutil.which("zstd")
        if zstd is None:
            self.skipTest("stock zstd is unavailable")
        with tempfile.TemporaryDirectory(prefix="stock-zstd-runner-test-") as raw:
            root = Path(raw)
            original = root / "input.bin"
            compressed = root / "output.zst"
            decoded = root / "decoded.bin"
            original.write_bytes((b"raw-oracle-fixture-" * 8192) + b"done")
            subprocess.run(
                [zstd, "-q", "-f", original, "-o", compressed],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            oracle, report_path = MATRIX.external_oracle(
                zstd,
                compressed,
                original,
                decoded,
                root,
                "fixture-control",
            )
            payload = report_path.read_bytes()
            report = json.loads(payload)
            self.assertEqual(
                payload, MATRIX.canonical_bytes(report) + b"\n"
            )
            self.assertEqual(report["schema"], MATRIX.ORACLE_REPORT_SCHEMA)
            self.assertEqual(report["cell"], "fixture-control")
            self.assertEqual(report["compressed"], oracle["compressed"])
            self.assertEqual(report["decoded"], oracle["input"])
            self.assertEqual(report["command"]["stdout"], MATRIX.bytes_identity(b""))
            self.assertEqual(report["command"]["stderr"], MATRIX.bytes_identity(b""))

    def test_raw_artifact_publication_copies_and_uses_exact_layout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="stock-zstd-runner-test-") as raw:
            root = Path(raw)
            source = root / "source"
            artifact_root = root / "artifact"
            source.mkdir()
            artifact_root.mkdir()
            compressed = source / "output.zst"
            stdout = source / "application.stdout"
            stderr = source / "application.stderr"
            report = source / "oracle-report.json"
            compressed.write_bytes(b"compressed fixture")
            stdout.write_bytes(b"")
            stderr.write_bytes(b"")
            report.write_bytes(b'{"fixture":true}\n')
            published = MATRIX.publish_positive_raw_artifacts(
                artifact_root,
                "control",
                {
                    "application_runs": (("control", stdout, stderr, 0),),
                    "compressed_output": compressed,
                    "oracle_report": report,
                },
            )
            self.assertEqual(
                published["compressed_output"]["path"],
                "raw/positive-output.zst",
            )
            self.assertEqual(
                published["oracle_report"]["path"],
                "raw/control/oracle-report.json",
            )
            self.assertEqual(
                published["application_runs"][0]["stdout"]["path"],
                "raw/control/control.stdout",
            )
            self.assertEqual(
                published["application_runs"][0]["stderr"]["path"],
                "raw/control/control.stderr",
            )
            self.assertEqual(
                published["application_runs"][0]["exit_status"],
                0,
            )
            retained = artifact_root / "raw/positive-output.zst"
            self.assertEqual(retained.read_bytes(), compressed.read_bytes())
            self.assertNotEqual(retained.stat().st_ino, compressed.stat().st_ino)
            self.assertEqual(retained.stat().st_nlink, 1)

            migrated_stdout = source / "migrated.stdout"
            migrated_report = source / "migrated-oracle-report.json"
            migrated_stdout.write_bytes(b"")
            migrated_report.write_bytes(b'{"fixture":"migrated"}\n')
            migrated = MATRIX.publish_positive_raw_artifacts(
                artifact_root,
                "cut-1",
                {
                    "application_runs": (
                        ("source", migrated_stdout, stderr, 0),
                        ("destination", migrated_stdout, stderr, 0),
                    ),
                    "compressed_output": compressed,
                    "oracle_report": migrated_report,
                },
                shared_compressed_output=published["compressed_output"],
            )
            self.assertEqual(
                migrated["compressed_output"],
                published["compressed_output"],
            )
            self.assertFalse(
                (artifact_root / "raw/cut-1/output.zst").exists()
            )

            compressed.write_bytes(b"different compressed fixture")
            with self.assertRaisesRegex(
                MATRIX.MatrixFailure,
                r"differs from the retained shared output",
            ):
                MATRIX.publish_positive_raw_artifacts(
                    artifact_root,
                    "cut-2",
                    {
                        "application_runs": (),
                        "compressed_output": compressed,
                        "oracle_report": migrated_report,
                    },
                    shared_compressed_output=published["compressed_output"],
                )
            self.assertEqual(
                list((artifact_root / "raw").glob("*.zst")),
                [retained],
            )

    def test_v7_formal_runner_has_no_dirty_snapshot_escape(self) -> None:
        self.assertEqual(
            MATRIX.SCHEMA,
            "visa-stock-zstd-transparent-migration-matrix-v7",
        )
        parser_source = inspect.getsource(MATRIX.parse_args)
        main_source = inspect.getsource(MATRIX.main)
        self.assertNotIn("allow-dirty-snapshot", parser_source)
        self.assertIn("repository must be clean", main_source)
        self.assertIn("final_snapshot != source_snapshot", main_source)
        self.assertIn("final_revision != repository_revision", main_source)
        self.assertIn("sealed_snapshot != source_snapshot", main_source)
        self.assertIn("sealed_revision != repository_revision", main_source)


if __name__ == "__main__":
    unittest.main()
