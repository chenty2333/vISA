#!/usr/bin/env python3
"""Mutation tests for the compact Wanco typed-restore corpus receipt."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import wanco_typed_corpus as CORPUS


def identity(seed: int) -> dict[str, object]:
    return {"sha256": f"{seed:064x}", "size": seed}


def complete_receipt() -> dict[str, object]:
    cases: list[dict[str, object]] = []
    for index, spec in enumerate(CORPUS.CASE_SPECS, start=1):
        prefix = [spec.marker - 1, spec.marker]
        suffix = [spec.marker + 1]
        cases.append(
            {
                "case_id": spec.case_id,
                "profile": spec.profile,
                "optimization": spec.optimization,
                "checkpoint_marker": spec.marker,
                "expected_frames": spec.frames,
                "observed_frames": spec.frames,
                "expected_typed_stack_values": spec.typed_stack_values,
                "observed_typed_stack_values": spec.typed_stack_values,
                "exact_stackmap_records": spec.frames,
                "control_values": prefix + suffix,
                "checkpoint_prefix_values": prefix,
                "restored_suffix_values": suffix,
                "control_stdout": CORPUS.values_identity(prefix + suffix),
                "checkpoint_stdout": CORPUS.values_identity(prefix),
                "restore_stdout": CORPUS.values_identity(suffix),
                "checkpoint_stderr": identity(index * 10 + 4),
                "restore_stderr": identity(index * 10 + 5),
                "checkpoint": identity(index * 10 + 6),
            }
        )
    return {
        "schema": CORPUS.SCHEMA,
        "image_tag": "visa-wanco-carrier:locked",
        "image_id": "sha256:" + "ab" * 32,
        "wanco_build_receipt": identity(500),
        "cases": cases,
    }


def inject_wrong_indirect_target(receipt: dict[str, object]) -> None:
    case = receipt["cases"][3]
    case["control_values"] = [999, 803, 804]
    case["checkpoint_prefix_values"] = [999, 803]
    case["restored_suffix_values"] = [804]
    case["control_stdout"] = CORPUS.values_identity(case["control_values"])
    case["checkpoint_stdout"] = CORPUS.values_identity(
        case["checkpoint_prefix_values"]
    )
    case["restore_stdout"] = CORPUS.values_identity(case["restored_suffix_values"])


class TypedCorpusTests(unittest.TestCase):
    def test_complete_twelve_case_receipt_is_accepted(self) -> None:
        CORPUS.validate_receipt(complete_receipt())
        root_cases = [
            case
            for case in complete_receipt()["cases"]
            if case["profile"] == "post-import-root"
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
                (0, 1, [1002, 1003], [1004]),
                (1, 1, [1002, 1003], [1004]),
                (2, 1, [1002, 1003], [1004]),
            ],
        )

    def test_builder_derives_observations_from_raw_case_outputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wanco-typed-corpus-") as raw:
            root = Path(raw)
            build_receipt = root / "wanco-build.json"
            build_receipt.write_text('{"schema":"build"}\n', encoding="utf-8")
            for spec in CORPUS.CASE_SPECS:
                case = root / "results" / spec.case_id
                case.mkdir(parents=True)
                prefix = [spec.marker - 1, spec.marker]
                suffix = [spec.marker + 1]
                (case / "control.stdout").write_text(
                    "".join(f"{value}\n" for value in prefix + suffix),
                    encoding="utf-8",
                )
                (case / "checkpoint.stdout").write_text(
                    "".join(f"{value}\n" for value in prefix), encoding="utf-8"
                )
                (case / "restore.stdout").write_text(
                    "".join(f"{value}\n" for value in suffix), encoding="utf-8"
                )
                (case / "checkpoint.stderr").write_text(
                    "".join(
                        "[debug] Found exact stackmap record\n"
                        for _ in range(spec.frames)
                    ),
                    encoding="utf-8",
                )
                (case / "restore.stderr").write_text(
                    f"[info] - call stack: {spec.frames} frames\n"
                    f"[info] - value stack: {spec.typed_stack_values} values\n",
                    encoding="utf-8",
                )
                (case / "checkpoint.pb").write_bytes(b"typed-checkpoint")
            receipt = CORPUS.build_receipt(
                root=root,
                image_tag="visa-wanco-carrier:locked",
                image_id="sha256:" + "cd" * 32,
                wanco_build_receipt=build_receipt,
            )
            CORPUS.validate_receipt(receipt)
            self.assertEqual(len(receipt["cases"]), 12)
            output = root / "receipt.json"
            CORPUS.publish(output, receipt)
            self.assertEqual(
                output.read_bytes(),
                CORPUS.canonical_bytes(json.loads(output.read_bytes())) + b"\n",
            )

    def test_semantic_and_inventory_mutations_are_rejected(self) -> None:
        mutations = {
            "missing-case": lambda receipt: receipt["cases"].pop(),
            "wrong-order": lambda receipt: receipt["cases"].reverse(),
            "wrong-optimization": lambda receipt: receipt["cases"][0].__setitem__(
                "optimization", 2
            ),
            "wrong-frame-count": lambda receipt: receipt["cases"][0].__setitem__(
                "observed_frames", 5
            ),
            "wrong-stack-value-count": lambda receipt: receipt["cases"][3].__setitem__(
                "observed_typed_stack_values", 2
            ),
            "missing-exact-stackmap": lambda receipt: receipt["cases"][0].__setitem__(
                "exact_stackmap_records", 5
            ),
            "missing-root-guest-frame": lambda receipt: receipt["cases"][9].__setitem__(
                "observed_frames", 0
            ),
            "wrong-marker": lambda receipt: receipt["cases"][0][
                "checkpoint_prefix_values"
            ].__setitem__(-1, 702),
            "restore-divergence": lambda receipt: receipt["cases"][0][
                "restored_suffix_values"
            ].__setitem__(0, 9999),
            "wrong-indirect-target": inject_wrong_indirect_target,
            "empty-checkpoint": lambda receipt: receipt["cases"][0].__setitem__(
                "checkpoint", {"sha256": "00" * 32, "size": 0}
            ),
            "invalid-image": lambda receipt: receipt.__setitem__(
                "image_id", "not-an-image-id"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                receipt = copy.deepcopy(complete_receipt())
                mutate(receipt)
                with self.assertRaises(CORPUS.CorpusFailure):
                    CORPUS.validate_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
