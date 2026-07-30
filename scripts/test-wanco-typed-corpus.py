#!/usr/bin/env python3
"""Raw-artifact and mutation tests for the Wanco typed-restore corpus."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import wanco_typed_corpus as CORPUS


IMAGE_TAG = "visa-wanco-carrier:locked"
IMAGE_ID = "sha256:" + "ab" * 32


def case_streams(spec: CORPUS.CaseSpec) -> tuple[list[int], list[int], list[int]]:
    if spec.profile == CORPUS.POST_IMPORT_PROFILE:
        return (
            [
                CORPUS.POST_IMPORT_ENTRY_MARKER,
                CORPUS.POST_IMPORT_CHECKPOINT_MARKER,
                1004,
            ],
            [CORPUS.POST_IMPORT_ENTRY_MARKER, CORPUS.POST_IMPORT_CHECKPOINT_MARKER],
            [1004],
        )
    prefix = [spec.marker - 1, spec.marker]
    suffix = [spec.marker + 1]
    return prefix + suffix, prefix, suffix


def write_values(path: Path, values: list[int]) -> None:
    path.write_text("".join(f"{value}\n" for value in values), encoding="ascii")


def build_receipt_payload() -> dict[str, object]:
    return {
        "schema": "visa-wanco-carrier-build-receipt-v5",
        "image_tag": IMAGE_TAG,
        "image_id": IMAGE_ID,
        "stackmap_binding": "exact-active-callsite-id",
        "stackmap_layout": "typed-locals-and-value-stack-v2",
        "indirect_call_operands_retained": True,
        "active_data_segments_preserved_on_restore": True,
        "per_frame_callee_saved_registers": True,
        "post_import_checkpoint_points": True,
        "guest_tail_calls_disabled": True,
    }


def materialize_source(root: Path) -> Path:
    build_receipt = root / "wanco-build.json"
    build_receipt.write_text(
        json.dumps(build_receipt_payload(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for index, spec in enumerate(CORPUS.CASE_SPECS, start=1):
        case = root / "results" / spec.case_id
        case.mkdir(parents=True)
        control, prefix, suffix = case_streams(spec)
        write_values(case / "control.stdout", control)
        write_values(case / "checkpoint.stdout", prefix)
        write_values(case / "restore.stdout", suffix)
        (case / "checkpoint.stderr").write_text(
            "".join(
                f"[debug] Found exact stackmap record for func_{frame}\n"
                for frame in range(spec.frames)
            )
            + "[info] Snapshot has been saved to checkpoint.pb\n",
            encoding="utf-8",
        )
        (case / "restore.stderr").write_text(
            f"[info] - call stack: {spec.frames} frames\n"
            f"[info] - value stack: {spec.typed_stack_values} values\n",
            encoding="utf-8",
        )
        (case / "checkpoint.pb").write_bytes(
            b"typed-checkpoint:" + spec.case_id.encode("ascii")
        )
        if spec.profile == CORPUS.POST_IMPORT_PROFILE:
            nonce = f"{index:064x}"
            container_id = f"{index + 100:064x}"
            (case / "import-entered.txt").write_text(
                f"entered {nonce}\n", encoding="ascii"
            )
            (case / "signal-dispatched.txt").write_text(
                f"signal-dispatched {nonce}\n", encoding="ascii"
            )
            (case / "import-release-observed.txt").write_text(
                f"release-observed {nonce}\n", encoding="ascii"
            )
            (case / "container.id").write_text(
                f"{container_id}\n", encoding="ascii"
            )
            (case / "signal.stdout").write_text(
                f"{container_id}\n", encoding="ascii"
            )
    return build_receipt


def build_fixture(root: Path) -> tuple[Path, dict[str, object], dict[str, object]]:
    source = root / "source"
    source.mkdir()
    build_receipt = materialize_source(source)
    artifact = root / "artifact"
    receipt, qualification = CORPUS.build_bundle(
        source_root=source,
        artifact_root=artifact,
        image_tag=IMAGE_TAG,
        image_id=IMAGE_ID,
        wanco_build_receipt=build_receipt,
    )
    return artifact / "receipt.json", receipt, qualification


def rewrite_receipt(path: Path, receipt: dict[str, object]) -> None:
    path.write_bytes(CORPUS.canonical_bytes(receipt) + b"\n")


def reference_for(
    receipt: dict[str, object], case_index: int, role: str
) -> dict[str, object]:
    artifacts = receipt["cases"][case_index]["artifacts"]
    if role in CORPUS.CASE_FILE_NAMES:
        return artifacts[role]
    return artifacts["post_import_witness"][role]


def reseal(
    receipt_path: Path,
    receipt: dict[str, object],
    case_index: int,
    role: str,
    payload: bytes,
) -> None:
    reference = reference_for(receipt, case_index, role)
    retained = receipt_path.parent.joinpath(*reference["path"].split("/"))
    retained.write_bytes(payload)
    reference.update(CORPUS.bytes_identity(payload))
    rewrite_receipt(receipt_path, receipt)


class TypedCorpusTests(unittest.TestCase):
    def test_bundle_retains_raw_bytes_and_rederives_twelve_cases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wanco-typed-v4-") as raw:
            receipt_path, receipt, qualification = build_fixture(Path(raw))
            loaded, rederived = CORPUS.load_and_validate(receipt_path)
            self.assertEqual(loaded, receipt)
            self.assertEqual(rederived, qualification)
            self.assertEqual(receipt["schema"], CORPUS.SCHEMA)
            self.assertEqual(qualification["schema"], CORPUS.QUALIFICATION_SCHEMA)
            self.assertEqual(len(receipt["cases"]), 12)
            self.assertEqual(len(qualification["cases"]), 12)
            self.assertNotIn("observed_frames", receipt["cases"][0])
            self.assertNotIn("control_values", receipt["cases"][0])
            paths = [reference["path"] for reference in CORPUS.iter_references(receipt)]
            self.assertEqual(len(paths), len(set(paths)))
            self.assertEqual(len(paths), 88)
            root_cases = [
                case
                for case in qualification["cases"]
                if case["profile"] == CORPUS.POST_IMPORT_PROFILE
            ]
            self.assertEqual(
                [
                    (
                        case["optimization"],
                        case["observed_frames"],
                        case["checkpoint_prefix_values"],
                        case["restored_suffix_values"],
                    )
                    for case in root_cases
                ],
                [
                    (0, 1, [1003, 1005], [1004]),
                    (1, 1, [1003, 1005], [1004]),
                    (2, 1, [1003, 1005], [1004]),
                ],
            )

    def test_summary_only_and_noncanonical_receipts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wanco-typed-summary-") as raw:
            root = Path(raw)
            receipt_path, receipt, _ = build_fixture(root)
            summary_only = copy.deepcopy(receipt)
            summary_only["schema"] = "visa-wanco-typed-checkpoint-corpus-v3"
            rewrite_receipt(receipt_path, summary_only)
            with self.assertRaises(CORPUS.CorpusFailure):
                CORPUS.load_and_validate(receipt_path)
            rewrite_receipt(receipt_path, receipt)
            receipt_path.write_bytes(
                json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            )
            with self.assertRaisesRegex(CORPUS.CorpusFailure, "not canonical JSON"):
                CORPUS.load_and_validate(receipt_path)

    def test_missing_tampered_and_resealed_semantic_mutations_are_rejected(self) -> None:
        scenarios = (
            "missing",
            "tampered",
            "control-divergence",
            "missing-stackmap",
            "wrong-frame-count",
            "empty-checkpoint",
            "detached-witness",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="wanco-typed-mutation-"
            ) as raw:
                receipt_path, receipt, _ = build_fixture(Path(raw))
                reference = reference_for(receipt, 0, "control_stdout")
                retained = receipt_path.parent.joinpath(*reference["path"].split("/"))
                if scenario == "missing":
                    retained.unlink()
                elif scenario == "tampered":
                    retained.write_bytes(b"forged\n")
                elif scenario == "control-divergence":
                    reseal(receipt_path, receipt, 0, "control_stdout", b"702\n703\n999\n")
                elif scenario == "missing-stackmap":
                    reseal(
                        receipt_path,
                        receipt,
                        0,
                        "checkpoint_stderr",
                        b"[debug] Found exact stackmap record\n" * 5,
                    )
                elif scenario == "wrong-frame-count":
                    reseal(
                        receipt_path,
                        receipt,
                        0,
                        "restore_stderr",
                        b"[info] - call stack: 0 frames\n"
                        b"[info] - value stack: 4 values\n",
                    )
                elif scenario == "empty-checkpoint":
                    reseal(receipt_path, receipt, 0, "checkpoint", b"")
                else:
                    witness_index = 9
                    reseal(
                        receipt_path,
                        receipt,
                        witness_index,
                        "release_gate",
                        b"signal-dispatched " + b"f" * 64 + b"\n",
                    )
                with self.assertRaises(CORPUS.CorpusFailure):
                    CORPUS.load_and_validate(receipt_path)

    def test_path_escape_alias_symlink_and_hardlink_are_rejected(self) -> None:
        scenarios = ("escape", "alias", "symlink", "hardlink")
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="wanco-typed-path-"
            ) as raw:
                root = Path(raw)
                receipt_path, receipt, _ = build_fixture(root)
                checkpoint = reference_for(receipt, 0, "checkpoint")
                retained = receipt_path.parent.joinpath(*checkpoint["path"].split("/"))
                if scenario == "escape":
                    checkpoint["path"] = "../checkpoint.pb"
                    rewrite_receipt(receipt_path, receipt)
                elif scenario == "alias":
                    checkpoint.update(copy.deepcopy(reference_for(receipt, 0, "control_stdout")))
                    rewrite_receipt(receipt_path, receipt)
                elif scenario == "symlink":
                    target = root / "outside-checkpoint"
                    target.write_bytes(retained.read_bytes())
                    retained.unlink()
                    retained.symlink_to(target)
                else:
                    (root / "checkpoint-alias").hardlink_to(retained)
                with self.assertRaises(CORPUS.CorpusFailure):
                    CORPUS.load_and_validate(receipt_path)

    def test_complete_bundle_relocation_preserves_raw_qualification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wanco-typed-relocate-") as raw:
            root = Path(raw)
            receipt_path, receipt, qualification = build_fixture(root)
            destination = root / "relocated"
            copied, copied_qualification = CORPUS.retain_bundle(
                receipt_path, destination
            )
            self.assertEqual(copied, receipt)
            self.assertEqual(copied_qualification, qualification)
            self.assertEqual(
                CORPUS.load_and_validate(destination / "receipt.json"),
                (receipt, qualification),
            )


if __name__ == "__main__":
    unittest.main()
