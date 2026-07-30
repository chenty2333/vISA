#!/usr/bin/env python3
"""Mutation tests for the independent stock-zstd matrix receipt validator."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Callable


MODULE_PATH = Path(__file__).with_name("stock_zstd_matrix.py")
SPEC = importlib.util.spec_from_file_location("stock_zstd_matrix", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


def sha(value: int) -> str:
    return f"{value:064x}"


def artifact(value: int, size: int | None = None) -> dict[str, object]:
    return {"sha256": sha(value), "size": value if size is None else size}


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


def oracle() -> dict[str, object]:
    source = artifact(10, MATRIX.CANONICAL_INPUT_BYTES)
    return {
        "compressed": artifact(11, 25_166_414),
        "decoded": copy.deepcopy(source),
        "input": copy.deepcopy(source),
    }


def migrated_cell(index: int, occurrence: int) -> dict[str, object]:
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
        bytes_written=25_166_414,
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
        "oracle": oracle(),
        "prepared_status": prepared,
        "source_fenced_status": fenced,
        "source_frozen_status": frozen,
        "source_post_checkpoint_status": source,
        "topology": "fresh-provider-fresh-process",
    }


def fault_cells() -> list[dict[str, object]]:
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
            cell: dict[str, object] = {
                "detector": detector,
                "exit_status": 1,
                "fault": f"cut-{cut}-{suffix}",
                "scope": scope,
                "stderr_sha256": sha(100 + cut * 10 + offset),
                "stderr_tail": "expected rejection",
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


def complete_receipt() -> dict[str, object]:
    empty = hashlib.sha256(b"").hexdigest()
    empty_manifest = hashlib.sha256(MATRIX.canonical_bytes([])).hexdigest()
    source_lock = sha(200)
    wanco_receipt = sha(201)
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
            "oracle": oracle(),
            "provider_status": status(
                bytes_read=MATRIX.CANONICAL_INPUT_BYTES,
                bytes_written=25_166_414,
                requests=408,
            ),
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
            "program": {
                "package": {"identity": "zstd-1.5.7-1.x86_64", "manager": "rpm"},
                "path": "/usr/bin/zstd",
                "sha256": sha(205),
                "size": 100_000,
                "version": "Zstandard CLI v1.5.7",
            },
        },
        "fault_cells": fault_cells(),
        "input": artifact(10, MATRIX.CANONICAL_INPUT_BYTES),
        "large_artifacts_retained": False,
        "migrated_cells": [migrated_cell(1, 8), migrated_cell(2, 64)],
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


class StockZstdMatrixTests(unittest.TestCase):
    def assert_rejected(
        self,
        mutation: Callable[[dict[str, object]], None],
        expected: str,
    ) -> None:
        receipt = complete_receipt()
        mutation(receipt)
        with self.assertRaisesRegex(MATRIX.ReceiptError, expected):
            MATRIX.validate_document(receipt, "a" * 40)

    def test_complete_receipt_is_accepted(self) -> None:
        MATRIX.validate_document(complete_receipt(), "a" * 40)

    def test_clean_exact_revision_is_required(self) -> None:
        self.assert_rejected(
            lambda value: value["repository_source_snapshot"].__setitem__("clean", False),
            r"clean must be True",
        )
        with self.assertRaisesRegex(MATRIX.ReceiptError, r"expected exact SHA"):
            MATRIX.validate_document(complete_receipt(), "b" * 40)

    def test_byte_polling_and_wrong_hostcall_cut_are_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["migrated_cells"][0]["cut"].__setitem__(
                "byte_counter_trigger_used", True
            ),
            r"byte_counter_trigger_used must be False",
        )
        self.assert_rejected(
            lambda value: value["migrated_cells"][1]["cut"]["predicate"].__setitem__(
                "occurrence", 63
            ),
            r"predicate differs",
        )

    def test_oracle_mismatch_is_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["migrated_cells"][0]["oracle"]["decoded"].__setitem__(
                "sha256", sha(999)
            ),
            r"lossless external decompression",
        )
        self.assert_rejected(
            lambda value: value["migrated_cells"][1]["oracle"]["compressed"].__setitem__(
                "sha256", sha(999)
            ),
            r"differs from uninterrupted",
        )

    def test_non_mid_execution_cut_is_rejected(self) -> None:
        def terminal(value: dict[str, object]) -> None:
            cell = value["migrated_cells"][0]
            for key in (
                "source_post_checkpoint_status",
                "source_frozen_status",
                "prepared_status",
                "source_fenced_status",
            ):
                cell[key]["bytes_read"] = MATRIX.CANONICAL_INPUT_BYTES
            cell["cut"]["held_status"]["bytes_read"] = MATRIX.CANONICAL_INPUT_BYTES
            cell["cut"]["checkpoint_released_status"]["bytes_read"] = (
                MATRIX.CANONICAL_INPUT_BYTES
            )
            cell["active_status"]["bytes_read"] = MATRIX.CANONICAL_INPUT_BYTES
        self.assert_rejected(terminal, r"not mid-execution")

    def test_checkpoint_and_fault_inventory_are_exact(self) -> None:
        self.assert_rejected(
            lambda value: value["migrated_cells"][1]["cut"].__setitem__(
                "checkpoint", copy.deepcopy(value["migrated_cells"][0]["cut"]["checkpoint"])
            ),
            r"distinct compute checkpoints",
        )
        self.assert_rejected(
            lambda value: value["fault_cells"].pop(),
            r"exactly five faults per cut",
        )

    def test_input_and_source_bindings_are_exact(self) -> None:
        self.assert_rejected(
            lambda value: value["input"].__setitem__("size", 12 * 1024 * 1024),
            r"canonical 24 MiB",
        )
        self.assert_rejected(
            lambda value: value["execution_input_binding"].__setitem__(
                "stock_zstd_source_lock_sha256", sha(999)
            ),
            r"source lock cross-binding differs",
        )

    def test_canonical_file_and_duplicate_key_checks(self) -> None:
        receipt = complete_receipt()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            valid = root / "valid.json"
            valid.write_bytes(MATRIX.canonical_bytes(receipt) + b"\n")
            MATRIX.load_and_validate(valid, "a" * 40)
            pretty = root / "pretty.json"
            pretty.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(MATRIX.ReceiptError, r"not canonical"):
                MATRIX.load_and_validate(pretty, "a" * 40)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema":"one","schema":"two"}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(MATRIX.ReceiptError, r"duplicate JSON key"):
                MATRIX.load_and_validate(duplicate, "a" * 40)


if __name__ == "__main__":
    unittest.main()
