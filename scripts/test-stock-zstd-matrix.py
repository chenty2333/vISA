#!/usr/bin/env python3
"""Mutation tests for the independent stock-zstd matrix receipt validator."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable


MODULE_PATH = Path(__file__).with_name("stock_zstd_matrix.py")
SPEC = importlib.util.spec_from_file_location("stock_zstd_matrix", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


CHECKPOINT_STDERR = (
    b"[info] Checkpoint started\n"
    b"[debug] Found exact stackmap record for func_19, wasm_op=-1, "
    b"native_return_pc_offset=0x2a\n"
    b"[info] Compressing memory\n"
    b"[info] Compression ratio: 0.275372\n"
    b"[info] Compression time: 1 ms\n"
    b"[info] Snapshot has been saved to checkpoint.pb\n"
    b"[info] Checkpoint time has been saved to chkpt-time.txt\n"
)
RESTORE_STDERR = (
    b"[info] Decompressing memory: 5 pages (327680 bytes)\n"
    b"[info] Checkpoint has been loaded\n"
    b"[info] - call stack: 21 frames\n"
    b"[info] - value stack: 0 values\n"
    b"[info] Restore time has been saved to restore-time.txt\n"
)
FAULT_DIAGNOSTICS = {
    "carrier-only-fresh-empty-provider": (
        b"zstd: error 25 : Read error : Bad file descriptor\n"
    ),
    "compute-checkpoint-tamper": (
        b"migration integrity failure: bound file content differs\n"
    ),
    "provider-capsule-tamper": (
        b"provider integrity failure: capsule state digest differs\n"
    ),
    "commit-fence-proof-pair-swap": (
        b"canonical proof rejected: source fence proof binding differs\n"
    ),
    "destination-guest-capability-spoof": (
        b"zstd: error 25 : Read error : Permission denied\n"
    ),
}


def sha(value: int) -> str:
    return f"{value:064x}"


def artifact(value: int, size: int | None = None) -> dict[str, object]:
    return {"sha256": sha(value), "size": value if size is None else size}


def file_reference(root: Path, relative: str) -> dict[str, object]:
    path = root / relative
    return {"path": relative, **MATRIX.file_identity(path)}


def status(
    *,
    mode: str = "active",
    epoch: int = 1,
    barrier: str = "open",
    effect: bool = False,
    remaining: int | None = None,
    bytes_read: int = 0,
    bytes_written: int = 0,
    requests: int = 0,
    session: int = 1,
) -> dict[str, object]:
    return {
        "authority_epoch": epoch,
        "barrier": barrier,
        "barrier_effect": list(range(16)) if effect else None,
        "barrier_remaining": remaining,
        "bytes_read": bytes_read,
        "bytes_written": bytes_written,
        "completed_requests": requests,
        "effects": requests,
        "locks": 0,
        "mode": mode,
        "objects": 3,
        "open_descriptors": 3 if requests < 408 else 1,
        "paths": 3,
        "session": [session] * 16,
    }


def raw_artifacts(root: Path, label: str, roles: tuple[str, ...]) -> dict[str, object]:
    return {
        "application_runs": [
            {
                "role": role,
                "exit_status": 0,
                "stdout": file_reference(root, f"raw/{label}/{role}.stdout"),
                "stderr": file_reference(root, f"raw/{label}/{role}.stderr"),
            }
            for role in roles
        ],
        "compressed_output": file_reference(root, "raw/positive-output.zst"),
        "oracle_report": file_reference(
            root, f"raw/{label}/oracle-report.json"
        ),
    }


def migrated_cell(
    root: Path,
    oracle: dict[str, object],
    index: int,
    occurrence: int,
) -> dict[str, object]:
    label = f"cut-{index}"
    read = 1_180_671 if index == 1 else 8_520_703
    written = 1_048_610 if index == 1 else 8_388_810
    requests = 33 if index == 1 else 145
    armed = status(barrier="armed", remaining=occurrence, session=index)
    held = status(
        barrier="held",
        effect=True,
        bytes_read=read,
        bytes_written=written,
        requests=requests,
        session=index,
    )
    released = {**held, "barrier": "checkpoint_released"}
    source = copy.deepcopy(released)
    frozen = {**released, "mode": "frozen"}
    prepared = {**released, "mode": "prepared"}
    fenced = {**released, "mode": "fenced"}
    active = status(
        epoch=2,
        bytes_read=read,
        bytes_written=written,
        requests=requests,
        session=index,
    )
    final = status(
        epoch=2,
        bytes_read=MATRIX.CANONICAL_INPUT_BYTES,
        bytes_written=oracle["compressed"]["size"],
        requests=408,
        session=index,
    )
    return {
        "active_status": active,
        "cell": f"{label}-visa-plus-carrier",
        "commit_proof_sha256": sha(20 + index),
        "compressed_bytes_equal_uninterrupted_control": True,
        "cut": {
            "armed_status": armed,
            "barrier_token": f"{index:032x}",
            "byte_counter_trigger_used": False,
            "checkpoint": artifact(30 + index, 1_000_000 + index),
            "checkpoint_released_status": released,
            "cut_location_source": "prearmed-post-hostcall-predicate",
            "held_status": held,
            "predicate": {
                "kind": "fd-write",
                "occurrence": occurrence,
                "outcome": "success",
                "resource": "path:output.zst",
            },
            "signal_checkpoint_used": False,
        },
        "destination_executed_manifest_bound_application": True,
        "fence_proof_sha256": sha(40 + index),
        "final_status": final,
        "manifest_sha256": sha(50 + index),
        "oracle": copy.deepcopy(oracle),
        "prepared_status": prepared,
        "raw_artifacts": raw_artifacts(
            root, label, ("source", "destination")
        ),
        "source_fenced_status": fenced,
        "source_frozen_status": frozen,
        "source_post_checkpoint_status": source,
        "topology": "fresh-provider-fresh-process",
    }


def fault_cells(root: Path) -> list[dict[str, object]]:
    specifications = (
        (
            "carrier-only-fresh-empty-provider",
            "stock-zstd-filesystem-error-from-fresh-empty-provider",
            "end-to-end",
        ),
        (
            "compute-checkpoint-tamper",
            "migration-manifest-bound-file-digest",
            "manifest-verification-path",
        ),
        (
            "provider-capsule-tamper",
            "provider-capsule-state-digest",
            "provider-restore-path",
        ),
        (
            "commit-fence-proof-pair-swap",
            "canonical-fence-to-commit-binding",
            "canonical-proof-verification-path",
        ),
        (
            "destination-guest-capability-spoof",
            "guest-capability-admission-before-provider-mutation",
            "end-to-end",
        ),
    )
    result: list[dict[str, object]] = []
    for cut in (1, 2):
        for offset, (suffix, detector, scope) in enumerate(specifications):
            name = f"cut-{cut}-{suffix}"
            stderr = FAULT_DIAGNOSTICS[suffix]
            prefix = f"raw/faults/cut-{cut}/{suffix}"
            stderr_path = root / f"{prefix}.stderr"
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.write_bytes(stderr)
            process = {
                "schema": MATRIX.FAULT_PROCESS_OBSERVATION_SCHEMA,
                "fault": name,
                "exit_status": 1,
                "stderr": MATRIX.bytes_identity(stderr),
            }
            process_path = root / f"{prefix}.process.json"
            process_path.write_bytes(MATRIX.canonical_bytes(process) + b"\n")
            cell: dict[str, object] = {
                "detector": detector,
                "exit_status": 1,
                "fault": name,
                "raw_process_observation": file_reference(
                    root, f"{prefix}.process.json"
                ),
                "raw_stderr": file_reference(root, f"{prefix}.stderr"),
                "scope": scope,
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "stderr_tail": stderr.decode(),
            }
            if suffix == "carrier-only-fresh-empty-provider":
                cell["provider_before"] = status(epoch=2, session=cut)
                cell["provider_after"] = status(
                    epoch=2, requests=1, session=cut
                )
            if suffix == "destination-guest-capability-spoof":
                cell["provider_state_unchanged"] = True
            result.append(cell)
    return result


def program_identity(zstd: Path) -> dict[str, object]:
    version = subprocess.run(
        [zstd, "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.decode().strip()
    return {
        "package": MATRIX.query_package_identity(
            zstd, "rpm" if shutil.which("rpm") is not None else "dpkg"
        ),
        "path": os.fspath(zstd),
        **MATRIX.file_identity(zstd),
        "version": version,
    }


def complete_receipt(root: Path, zstd: Path) -> dict[str, object]:
    empty = hashlib.sha256(b"").hexdigest()
    empty_manifest = hashlib.sha256(MATRIX.canonical_bytes([])).hexdigest()
    source_lock = sha(200)
    wanco_receipt = sha(201)
    input_identity = MATRIX.file_identity(root / "canonical-input.bin")
    compressed_identity = MATRIX.file_identity(root / "raw/positive-output.zst")
    oracle = {
        "compressed": compressed_identity,
        "decoded": copy.deepcopy(input_identity),
        "input": copy.deepcopy(input_identity),
    }
    return {
        "authority_model": {
            "artifact_and_receipt_binding_verified": True,
            "external_authority_authenticity_verified": False,
            "mode": "trusted-local-orchestration",
        },
        "contract_checks": [
            {
                "check": "activation-before-canonical-commit-and-fence",
                "rejected_by": "visa_wasi_migration::Driver",
                "scope": "driver-contract-unit-test-not-live-e2e",
                "test_stdout_sha256": sha(202),
            }
        ],
        "control": {
            "cell": "uninterrupted-control",
            "oracle": copy.deepcopy(oracle),
            "provider_status": status(
                bytes_read=MATRIX.CANONICAL_INPUT_BYTES,
                bytes_written=compressed_identity["size"],
                requests=408,
            ),
            "raw_artifacts": raw_artifacts(root, "control", ("control",)),
            "topology": "single-process-no-checkpoint",
        },
        "execution_input_binding": {
            "stock_zstd_source_lock_sha256": source_lock,
            "wanco_build_receipt_sha256": wanco_receipt,
            "wanco_image": "visa-wanco-carrier:locked",
            "wanco_image_id": "sha256:" + "ab" * 32,
            "wanco_runtime_sha256": sha(203),
            "wanco_source_lock_sha256": sha(204),
        },
        "external_oracle": {
            "observation": "decompress compressed bytes and compare raw SHA-256 and size",
            "program": program_identity(zstd),
        },
        "fault_cells": fault_cells(root),
        "input": input_identity,
        "migrated_cells": [
            migrated_cell(root, oracle, 1, 8),
            migrated_cell(root, oracle, 2, 64),
        ],
        "raw_oracle_artifacts_retained": True,
        "raw_fault_artifacts_retained": True,
        "repository_revision": "a" * 40,
        "repository_source_snapshot": {
            "clean": True,
            "status_sha256": empty,
            "tracked_patch_sha256": empty,
            "untracked_file_count": 0,
            "untracked_manifest_sha256": empty_manifest,
        },
        "schema": MATRIX.SCHEMA,
        "source_lock_sha256": source_lock,
        "stock_zstd_build_receipt_sha256": sha(206),
        "wanco_build_receipt_sha256": wanco_receipt,
        "wanco_optimization": "-O1",
        "zero_upstream_zstd_source_patches": True,
    }


def write_oracle_report(
    root: Path,
    label: str,
    cell: str,
    input_identity: dict[str, object],
    compressed_identity: dict[str, object],
) -> None:
    report = {
        "cell": cell,
        "command": {
            "exit_status": 0,
            "operation": "stock-zstd-decompress",
            "stderr": MATRIX.bytes_identity(b""),
            "stdout": MATRIX.bytes_identity(b""),
        },
        "compressed": compressed_identity,
        "decoded": input_identity,
        "input": input_identity,
        "schema": MATRIX.ORACLE_REPORT_SCHEMA,
    }
    path = root / f"raw/{label}/oracle-report.json"
    path.write_bytes(MATRIX.canonical_bytes(report) + b"\n")


class StockZstdMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        resolved = shutil.which("zstd")
        if resolved is None:
            raise unittest.SkipTest("stock zstd is unavailable")
        cls.zstd = Path(resolved).resolve()
        version = subprocess.run(
            [cls.zstd, "--version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.decode()
        if "v1.5.7" not in version:
            raise unittest.SkipTest("stock zstd 1.5.7 is unavailable")
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="stock-zstd-validator-test-"
        )
        cls.root = Path(cls.temporary.name)
        canonical_input = cls.root / "canonical-input.bin"
        MATRIX.write_canonical_input(canonical_input)
        control_output = cls.root / "raw/positive-output.zst"
        control_output.parent.mkdir(parents=True)
        subprocess.run(
            [
                cls.zstd,
                "-q",
                "-f",
                canonical_input,
                "-o",
                control_output,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        input_identity = MATRIX.file_identity(canonical_input)
        compressed_identity = MATRIX.file_identity(control_output)
        cells = (
            ("control", "uninterrupted-control", ("control",)),
            ("cut-1", "cut-1-visa-plus-carrier", ("source", "destination")),
            ("cut-2", "cut-2-visa-plus-carrier", ("source", "destination")),
        )
        for label, cell, roles in cells:
            directory = cls.root / "raw" / label
            directory.mkdir(parents=True, exist_ok=True)
            for role in roles:
                (directory / f"{role}.stdout").write_bytes(b"")
                stderr = (
                    CHECKPOINT_STDERR
                    if role == "source"
                    else RESTORE_STDERR if role == "destination" else b""
                )
                (directory / f"{role}.stderr").write_bytes(stderr)
            write_oracle_report(
                cls.root,
                label,
                cell,
                input_identity,
                compressed_identity,
            )
        cls.base_receipt = complete_receipt(cls.root, cls.zstd)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def write_receipt(self, receipt: dict[str, object]) -> Path:
        path = self.root / "receipt.json"
        path.write_bytes(MATRIX.canonical_bytes(receipt) + b"\n")
        return path

    def validate(self, receipt: dict[str, object]) -> dict[str, object]:
        return MATRIX.load_and_validate(
            self.write_receipt(receipt),
            "a" * 40,
            self.zstd,
        )

    def assert_rejected(
        self,
        mutation: Callable[[dict[str, object]], None],
        expected: str,
    ) -> None:
        receipt = copy.deepcopy(self.base_receipt)
        mutation(receipt)
        with self.assertRaisesRegex(MATRIX.ReceiptError, expected):
            self.validate(receipt)

    def test_complete_raw_receipt_is_accepted(self) -> None:
        self.validate(copy.deepcopy(self.base_receipt))

    def test_clean_exact_revision_is_required(self) -> None:
        fields = (
            ("clean", False, r"clean must be True"),
            ("status_sha256", sha(900), r"contains a status"),
            ("tracked_patch_sha256", sha(901), r"contains a status"),
            ("untracked_file_count", 1, r"contains untracked"),
            ("untracked_manifest_sha256", sha(902), r"nonempty untracked"),
        )
        for field, value, expected in fields:
            with self.subTest(field=field):
                self.assert_rejected(
                    lambda receipt, f=field, v=value: receipt[
                        "repository_source_snapshot"
                    ].__setitem__(f, v),
                    expected,
                )
        path = self.write_receipt(copy.deepcopy(self.base_receipt))
        with self.assertRaisesRegex(MATRIX.ReceiptError, r"expected exact SHA"):
            MATRIX.load_and_validate(path, "b" * 40, self.zstd)
        with self.assertRaisesRegex(MATRIX.ReceiptError, r"expected_revision"):
            MATRIX.load_and_validate(path, None, self.zstd)

    def test_cli_requires_revision_and_verifier_selected_stock_zstd(self) -> None:
        path = self.write_receipt(copy.deepcopy(self.base_receipt))
        completed = subprocess.run(
            [sys.executable, MODULE_PATH, "validate", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        diagnostic = completed.stderr.decode()
        self.assertIn("--expected-revision", diagnostic)
        self.assertIn("--stock-zstd", diagnostic)
        accepted = subprocess.run(
            [
                sys.executable,
                MODULE_PATH,
                "validate",
                path,
                "--expected-revision",
                "a" * 40,
                "--stock-zstd",
                self.zstd,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(
            accepted.returncode,
            0,
            accepted.stderr.decode("utf-8", errors="replace"),
        )
        self.assertIn(
            "revision=" + "a" * 40,
            accepted.stdout.decode("utf-8"),
        )

    def test_canonical_input_is_regenerated(self) -> None:
        self.assert_rejected(
            lambda receipt: receipt["input"].__setitem__("sha256", sha(999)),
            r"independently generated canonical input",
        )

    def test_native_package_identity_is_recomputed(self) -> None:
        self.assert_rejected(
            lambda receipt: receipt["external_oracle"]["program"]["package"].__setitem__(
                "identity", "forged-package"
            ),
            r"package identity differs",
        )

    def test_oracle_summary_cannot_override_raw_evidence(self) -> None:
        self.assert_rejected(
            lambda receipt: receipt["migrated_cells"][0]["oracle"][
                "decoded"
            ].__setitem__("sha256", sha(999)),
            r"lossless external decompression",
        )
        self.assert_rejected(
            lambda receipt: receipt["migrated_cells"][1]["oracle"][
                "compressed"
            ].__setitem__("sha256", sha(999)),
            r"differs from uninterrupted",
        )

    def test_raw_stdout_mutation_is_rejected_even_with_updated_reference(self) -> None:
        path = self.root / "raw/control/control.stdout"
        original = path.read_bytes()
        try:
            path.write_bytes(b"forged application summary\n")
            receipt = copy.deepcopy(self.base_receipt)
            receipt["control"]["raw_artifacts"]["application_runs"][0][
                "stdout"
            ] = file_reference(self.root, "raw/control/control.stdout")
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"application stdout must be empty"
            ):
                self.validate(receipt)
        finally:
            path.write_bytes(original)

    def test_raw_stderr_and_exit_status_mutations_are_rejected(self) -> None:
        self.assert_rejected(
            lambda receipt: receipt["migrated_cells"][0]["raw_artifacts"][
                "application_runs"
            ][1].__setitem__("exit_status", 9),
            r"application exit status must be zero",
        )
        path = self.root / "raw/cut-1/destination.stderr"
        original = path.read_bytes()
        try:
            path.write_bytes(b"coordinated hidden failure\n")
            receipt = copy.deepcopy(self.base_receipt)
            receipt["migrated_cells"][0]["raw_artifacts"]["application_runs"][1][
                "stderr"
            ] = file_reference(self.root, "raw/cut-1/destination.stderr")
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"extra or missing restore diagnostics"
            ):
                self.validate(receipt)
        finally:
            path.write_bytes(original)

    def test_fault_summaries_are_recomputed_from_retained_raw_evidence(self) -> None:
        self.assert_rejected(
            lambda receipt: receipt["fault_cells"][0].__setitem__(
                "exit_status", 7
            ),
            r"summary exit status differs from raw observation",
        )
        self.assert_rejected(
            lambda receipt: receipt["fault_cells"][0].__setitem__(
                "stderr_sha256", sha(999)
            ),
            r"summary stderr digest differs from raw stderr",
        )
        self.assert_rejected(
            lambda receipt: receipt["fault_cells"][0].__setitem__(
                "stderr_tail", "coordinated but unsupported tail"
            ),
            r"summary stderr tail differs from raw stderr",
        )

    def test_coordinated_fault_forgery_without_detector_signature_is_rejected(self) -> None:
        stderr_path = self.root / (
            "raw/faults/cut-1/compute-checkpoint-tamper.stderr"
        )
        process_path = self.root / (
            "raw/faults/cut-1/compute-checkpoint-tamper.process.json"
        )
        original_stderr = stderr_path.read_bytes()
        original_process = process_path.read_bytes()
        forged_stderr = b"coordinated failure that names no accepted detector\n"
        try:
            stderr_path.write_bytes(forged_stderr)
            process = {
                "schema": MATRIX.FAULT_PROCESS_OBSERVATION_SCHEMA,
                "fault": "cut-1-compute-checkpoint-tamper",
                "exit_status": 1,
                "stderr": MATRIX.bytes_identity(forged_stderr),
            }
            process_path.write_bytes(MATRIX.canonical_bytes(process) + b"\n")
            receipt = copy.deepcopy(self.base_receipt)
            fault = receipt["fault_cells"][1]
            fault["raw_stderr"] = file_reference(
                self.root,
                "raw/faults/cut-1/compute-checkpoint-tamper.stderr",
            )
            fault["raw_process_observation"] = file_reference(
                self.root,
                "raw/faults/cut-1/compute-checkpoint-tamper.process.json",
            )
            fault["exit_status"] = 1
            fault["stderr_sha256"] = hashlib.sha256(forged_stderr).hexdigest()
            fault["stderr_tail"] = forged_stderr.decode()
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"lacks the expected detector signature"
            ):
                self.validate(receipt)
        finally:
            stderr_path.write_bytes(original_stderr)
            process_path.write_bytes(original_process)

    def test_coordinated_fault_exit_status_forgery_is_rejected(self) -> None:
        process_path = self.root / (
            "raw/faults/cut-1/provider-capsule-tamper.process.json"
        )
        original = process_path.read_bytes()
        try:
            process = json.loads(original)
            process["exit_status"] = 7
            process_path.write_bytes(MATRIX.canonical_bytes(process) + b"\n")
            receipt = copy.deepcopy(self.base_receipt)
            fault = receipt["fault_cells"][2]
            fault["exit_status"] = 7
            fault["raw_process_observation"] = file_reference(
                self.root,
                "raw/faults/cut-1/provider-capsule-tamper.process.json",
            )
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"raw process exit status must be one"
            ):
                self.validate(receipt)
        finally:
            process_path.write_bytes(original)

    def test_fault_paths_are_exact_and_cannot_rebind_other_raw_evidence(self) -> None:
        self.assert_rejected(
            lambda receipt: receipt["fault_cells"][0]["raw_stderr"].update(
                receipt["fault_cells"][5]["raw_stderr"]
            ),
            r"raw stderr path differs",
        )
        self.assert_rejected(
            lambda receipt: receipt["fault_cells"][0][
                "raw_process_observation"
            ].__setitem__("path", "../fault.process.json"),
            r"canonical and relative",
        )

    def test_fault_raw_symlink_missing_and_byte_mutation_are_rejected(self) -> None:
        stderr_path = self.root / (
            "raw/faults/cut-2/destination-guest-capability-spoof.stderr"
        )
        original_stderr = stderr_path.read_bytes()
        try:
            stderr_path.write_bytes(original_stderr + b"mutated")
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"size differs|sha256 differs"
            ):
                self.validate(copy.deepcopy(self.base_receipt))
        finally:
            stderr_path.write_bytes(original_stderr)

        process_path = self.root / (
            "raw/faults/cut-2/commit-fence-proof-pair-swap.process.json"
        )
        process_backup = process_path.with_suffix(".missing")
        process_path.rename(process_backup)
        try:
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"cannot securely open"
            ):
                self.validate(copy.deepcopy(self.base_receipt))
        finally:
            process_backup.rename(process_path)

        stderr_path = self.root / (
            "raw/faults/cut-2/provider-capsule-tamper.stderr"
        )
        stderr_backup = stderr_path.with_suffix(".real")
        stderr_path.rename(stderr_backup)
        try:
            stderr_path.symlink_to(stderr_backup.name)
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"cannot securely open"
            ):
                self.validate(copy.deepcopy(self.base_receipt))
        finally:
            stderr_path.unlink()
            stderr_backup.rename(stderr_path)

        stderr_path = self.root / (
            "raw/faults/cut-1/carrier-only-fresh-empty-provider.stderr"
        )
        stderr_backup = stderr_path.with_suffix(".hardlink-source")
        stderr_path.rename(stderr_backup)
        try:
            os.link(stderr_backup, stderr_path)
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"must not be hard-linked"
            ):
                self.validate(copy.deepcopy(self.base_receipt))
        finally:
            stderr_path.unlink()
            stderr_backup.rename(stderr_path)

    def test_raw_oracle_report_mutation_is_rejected(self) -> None:
        path = self.root / "raw/control/oracle-report.json"
        original = path.read_bytes()
        try:
            report = json.loads(original)
            report["cell"] = "forged-control"
            path.write_bytes(MATRIX.canonical_bytes(report) + b"\n")
            receipt = copy.deepcopy(self.base_receipt)
            receipt["control"]["raw_artifacts"]["oracle_report"] = file_reference(
                self.root, "raw/control/oracle-report.json"
            )
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"schema or cell identity differs"
            ):
                self.validate(receipt)
        finally:
            path.write_bytes(original)

    def test_compressed_output_mutation_is_independently_decompressed(self) -> None:
        output = self.root / "raw/positive-output.zst"
        report_path = self.root / "raw/control/oracle-report.json"
        original_output = output.read_bytes()
        original_report = report_path.read_bytes()
        try:
            changed = bytearray(original_output)
            changed[len(changed) // 2] ^= 0x80
            output.write_bytes(changed)
            changed_identity = MATRIX.file_identity(output)
            report = json.loads(original_report)
            report["compressed"] = changed_identity
            report_path.write_bytes(MATRIX.canonical_bytes(report) + b"\n")
            receipt = copy.deepcopy(self.base_receipt)
            raw = receipt["control"]["raw_artifacts"]
            raw["compressed_output"] = file_reference(
                self.root, "raw/positive-output.zst"
            )
            raw["oracle_report"] = file_reference(
                self.root, "raw/control/oracle-report.json"
            )
            with self.assertRaisesRegex(
                MATRIX.ReceiptError,
                r"repeated stock-zstd decompression failed|differs from canonical input",
            ):
                self.validate(receipt)
        finally:
            output.write_bytes(original_output)
            report_path.write_bytes(original_report)

    def test_decompressed_output_is_bounded_to_canonical_size(self) -> None:
        output = self.root / "raw/positive-output.zst"
        report_path = self.root / "raw/control/oracle-report.json"
        original_output = output.read_bytes()
        original_report = report_path.read_bytes()
        oversized = self.root / "oversized-input.bin"
        try:
            oversized.write_bytes(b"\0" * (MATRIX.CANONICAL_INPUT_BYTES + 1))
            subprocess.run(
                [self.zstd, "-q", "-f", oversized, "-o", output],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            changed_identity = MATRIX.file_identity(output)
            report = json.loads(original_report)
            report["compressed"] = changed_identity
            report_path.write_bytes(MATRIX.canonical_bytes(report) + b"\n")
            receipt = copy.deepcopy(self.base_receipt)
            raw = receipt["control"]["raw_artifacts"]
            raw["compressed_output"] = file_reference(
                self.root, "raw/positive-output.zst"
            )
            raw["oracle_report"] = file_reference(
                self.root, "raw/control/oracle-report.json"
            )
            with self.assertRaisesRegex(
                MATRIX.ReceiptError,
                r"repeated stock-zstd decompression failed|output size is not canonical",
            ):
                self.validate(receipt)
        finally:
            output.write_bytes(original_output)
            report_path.write_bytes(original_report)
            oversized.unlink(missing_ok=True)

    def test_artifact_reference_paths_are_exact_and_bounded(self) -> None:
        mutations = (
            ("/tmp/output.zst", r"canonical and relative"),
            ("../output.zst", r"canonical and relative"),
            ("raw\\control\\output.zst", r"canonical POSIX"),
            ("raw/cut-1/output.zst", r"shared positive blob"),
        )
        for path, expected in mutations:
            with self.subTest(path=path):
                self.assert_rejected(
                    lambda receipt, p=path: receipt["control"]["raw_artifacts"][
                        "compressed_output"
                    ].__setitem__("path", p),
                    expected,
                )
        self.assert_rejected(
            lambda receipt: receipt["control"]["raw_artifacts"][
                "compressed_output"
            ].__setitem__("size", MATRIX.MAX_COMPRESSED_BYTES + 1),
            r"size differs",
        )
        self.assert_rejected(
            lambda receipt: receipt["control"]["raw_artifacts"][
                "compressed_output"
            ].__setitem__("sha256", sha(999)),
            r"sha256 differs",
        )

    def test_symlink_parent_symlink_leaf_and_hardlink_are_rejected(self) -> None:
        control = self.root / "raw/control"
        real = self.root / "raw/control-real"
        control.rename(real)
        try:
            control.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"cannot securely open"
            ):
                self.validate(copy.deepcopy(self.base_receipt))
        finally:
            control.unlink()
            real.rename(control)

        output = self.root / "raw/positive-output.zst"
        backup = self.root / "raw/positive-output.backup"
        output.rename(backup)
        try:
            output.symlink_to(backup.name)
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"cannot securely open"
            ):
                self.validate(copy.deepcopy(self.base_receipt))
        finally:
            output.unlink()
            backup.rename(output)

        output.rename(backup)
        try:
            os.link(backup, output)
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"must not be hard-linked"
            ):
                self.validate(copy.deepcopy(self.base_receipt))
        finally:
            output.unlink()
            backup.rename(output)

    def test_missing_artifact_and_wrong_stdout_roles_are_rejected(self) -> None:
        stdout = self.root / "raw/control/control.stdout"
        backup = self.root / "raw/control/control.backup"
        stdout.rename(backup)
        try:
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"cannot securely open"
            ):
                self.validate(copy.deepcopy(self.base_receipt))
        finally:
            backup.rename(stdout)
        self.assert_rejected(
            lambda receipt: receipt["migrated_cells"][0]["raw_artifacts"][
                "application_runs"
            ].reverse(),
            r"role/order differs",
        )

    def test_program_identity_and_session_cross_binding_are_enforced(self) -> None:
        self.assert_rejected(
            lambda receipt: receipt["external_oracle"]["program"].__setitem__(
                "sha256", sha(999)
            ),
            r"identity differs",
        )
        self.assert_rejected(
            lambda receipt: receipt["migrated_cells"][0]["active_status"].__setitem__(
                "session", [9] * 16
            ),
            r"destination session differs",
        )

    def test_cut_and_fault_inventory_remain_exact(self) -> None:
        self.assert_rejected(
            lambda receipt: receipt["migrated_cells"][1]["cut"].__setitem__(
                "checkpoint",
                copy.deepcopy(
                    receipt["migrated_cells"][0]["cut"]["checkpoint"]
                ),
            ),
            r"distinct compute checkpoints",
        )
        self.assert_rejected(
            lambda receipt: receipt["fault_cells"].pop(),
            r"exactly five faults per cut",
        )

    def test_canonical_receipt_duplicate_keys_and_hardlink_are_rejected(self) -> None:
        receipt = copy.deepcopy(self.base_receipt)
        valid = self.write_receipt(receipt)
        MATRIX.load_and_validate(valid, "a" * 40, self.zstd)
        pretty = self.root / "pretty.json"
        pretty.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(MATRIX.ReceiptError, r"not canonical"):
            MATRIX.load_and_validate(pretty, "a" * 40, self.zstd)
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(
            '{"schema":"one","schema":"two"}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(MATRIX.ReceiptError, r"duplicate JSON key"):
            MATRIX.load_and_validate(duplicate, "a" * 40, self.zstd)
        hardlink = self.root / "receipt-hardlink.json"
        os.link(valid, hardlink)
        try:
            with self.assertRaisesRegex(
                MATRIX.ReceiptError, r"must not be hard-linked"
            ):
                MATRIX.load_and_validate(valid, "a" * 40, self.zstd)
        finally:
            hardlink.unlink()


if __name__ == "__main__":
    unittest.main()
