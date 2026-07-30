#!/usr/bin/env python3
"""Build and validate compact evidence for the Wanco typed-restore corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


SCHEMA = "visa-wanco-typed-checkpoint-corpus-v1"


class CorpusFailure(RuntimeError):
    """The retained typed-restore corpus is incomplete or inconsistent."""


@dataclass(frozen=True)
class CaseSpec:
    profile: str
    optimization: int
    marker: int
    frames: int
    typed_stack_values: int

    @property
    def case_id(self) -> str:
        return f"{self.profile}-O{self.optimization}"


CASE_SPECS = tuple(
    CaseSpec(profile, optimization, marker, frames, values)
    for profile, marker, frames, values in (
        ("direct", 703, 6, 4),
        ("indirect", 803, 3, 3),
        ("data-segment", 903, 4, 0),
    )
    for optimization in range(3)
)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def file_identity(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise CorpusFailure(f"expected a regular corpus artifact: {path}")
    size = path.stat().st_size
    if size <= 0:
        raise CorpusFailure(f"corpus artifact is empty: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "size": size}


def values_identity(values: Sequence[int]) -> dict[str, object]:
    raw = "".join(f"{value}\n" for value in values).encode("ascii")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def _require_identity(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"sha256", "size"}:
        raise CorpusFailure(f"{label} identity has the wrong fields")
    digest = value["sha256"]
    size = value["size"]
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
    ):
        raise CorpusFailure(f"{label} identity is invalid")


def _read_values(path: Path, label: str) -> list[int]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CorpusFailure(f"cannot read {label}: {error}") from error
    if not lines:
        raise CorpusFailure(f"{label} is empty")
    values: list[int] = []
    for line in lines:
        try:
            value = int(line, 10)
        except ValueError as error:
            raise CorpusFailure(f"{label} contains a non-integer line") from error
        if str(value) != line or value < -(2**31) or value >= 2**31:
            raise CorpusFailure(f"{label} contains a non-canonical i32 value")
        values.append(value)
    return values


def _single_count(raw: str, pattern: str, label: str) -> int:
    matches = re.findall(pattern, raw)
    if len(matches) != 1:
        raise CorpusFailure(f"{label} is missing or duplicated")
    return int(matches[0], 10)


def _build_case(root: Path, spec: CaseSpec) -> dict[str, object]:
    case_root = root / "results" / spec.case_id
    control_path = case_root / "control.stdout"
    checkpoint_stdout_path = case_root / "checkpoint.stdout"
    restore_stdout_path = case_root / "restore.stdout"
    checkpoint_stderr_path = case_root / "checkpoint.stderr"
    restore_stderr_path = case_root / "restore.stderr"
    checkpoint_path = case_root / "checkpoint.pb"

    control = _read_values(control_path, f"{spec.case_id} control stdout")
    prefix = _read_values(
        checkpoint_stdout_path, f"{spec.case_id} checkpoint-prefix stdout"
    )
    suffix = _read_values(restore_stdout_path, f"{spec.case_id} restore stdout")
    try:
        checkpoint_stderr = checkpoint_stderr_path.read_text(encoding="utf-8")
        restore_stderr = restore_stderr_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CorpusFailure(f"cannot read {spec.case_id} restore logs: {error}") from error

    observed_frames = _single_count(
        restore_stderr, r"- call stack: ([0-9]+) frames", "observed frame count"
    )
    observed_values = _single_count(
        restore_stderr,
        r"- value stack: ([0-9]+) values",
        "observed typed-stack count",
    )
    exact_records = checkpoint_stderr.count("[debug] Found exact stackmap record")
    case = {
        "case_id": spec.case_id,
        "profile": spec.profile,
        "optimization": spec.optimization,
        "checkpoint_marker": spec.marker,
        "expected_frames": spec.frames,
        "observed_frames": observed_frames,
        "expected_typed_stack_values": spec.typed_stack_values,
        "observed_typed_stack_values": observed_values,
        "exact_stackmap_records": exact_records,
        "control_values": control,
        "checkpoint_prefix_values": prefix,
        "restored_suffix_values": suffix,
        "control_stdout": file_identity(control_path),
        "checkpoint_stdout": file_identity(checkpoint_stdout_path),
        "restore_stdout": file_identity(restore_stdout_path),
        "checkpoint_stderr": file_identity(checkpoint_stderr_path),
        "restore_stderr": file_identity(restore_stderr_path),
        "checkpoint": file_identity(checkpoint_path),
    }
    _validate_case(case, spec)
    return case


def build_receipt(
    *,
    root: Path,
    image_tag: str,
    image_id: str,
    wanco_build_receipt: Path,
) -> dict[str, object]:
    receipt = {
        "schema": SCHEMA,
        "image_tag": image_tag,
        "image_id": image_id,
        "wanco_build_receipt": file_identity(wanco_build_receipt),
        "cases": [_build_case(root, spec) for spec in CASE_SPECS],
    }
    validate_receipt(receipt)
    return receipt


def _require_i32_list(value: object, label: str) -> list[int]:
    if not isinstance(value, list) or not value:
        raise CorpusFailure(f"{label} must be a nonempty i32 list")
    for item in value:
        if (
            not isinstance(item, int)
            or isinstance(item, bool)
            or item < -(2**31)
            or item >= 2**31
        ):
            raise CorpusFailure(f"{label} contains an invalid i32 value")
    return value


def _validate_case(case: object, spec: CaseSpec) -> None:
    fields = {
        "case_id",
        "profile",
        "optimization",
        "checkpoint_marker",
        "expected_frames",
        "observed_frames",
        "expected_typed_stack_values",
        "observed_typed_stack_values",
        "exact_stackmap_records",
        "control_values",
        "checkpoint_prefix_values",
        "restored_suffix_values",
        "control_stdout",
        "checkpoint_stdout",
        "restore_stdout",
        "checkpoint_stderr",
        "restore_stderr",
        "checkpoint",
    }
    if not isinstance(case, dict) or set(case) != fields:
        raise CorpusFailure(f"typed corpus case {spec.case_id} has the wrong fields")
    if (
        case["case_id"] != spec.case_id
        or case["profile"] != spec.profile
        or case["optimization"] != spec.optimization
        or case["checkpoint_marker"] != spec.marker
        or case["expected_frames"] != spec.frames
        or case["expected_typed_stack_values"] != spec.typed_stack_values
    ):
        raise CorpusFailure(f"typed corpus case {spec.case_id} changed its contract")
    if (
        case["observed_frames"] != spec.frames
        or case["observed_typed_stack_values"] != spec.typed_stack_values
        or case["exact_stackmap_records"] != spec.frames
    ):
        raise CorpusFailure(f"typed restore observations failed for {spec.case_id}")
    control = _require_i32_list(case["control_values"], "control values")
    prefix = _require_i32_list(
        case["checkpoint_prefix_values"], "checkpoint prefix values"
    )
    suffix = _require_i32_list(case["restored_suffix_values"], "restored suffix values")
    if prefix[-1] != spec.marker or prefix + suffix != control:
        raise CorpusFailure(f"fresh-process restore diverged for {spec.case_id}")
    if spec.profile == "indirect" and 999 in control:
        raise CorpusFailure("indirect restore selected the wrong table target")
    for values, name in (
        (control, "control_stdout"),
        (prefix, "checkpoint_stdout"),
        (suffix, "restore_stdout"),
    ):
        if case[name] != values_identity(values):
            raise CorpusFailure(f"{spec.case_id} {name} differs from compact values")
    for name in (
        "control_stdout",
        "checkpoint_stdout",
        "restore_stdout",
        "checkpoint_stderr",
        "restore_stderr",
        "checkpoint",
    ):
        _require_identity(case[name], f"{spec.case_id} {name}")


def validate_receipt(receipt: object) -> None:
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema",
        "image_tag",
        "image_id",
        "wanco_build_receipt",
        "cases",
    }:
        raise CorpusFailure("typed corpus receipt has the wrong fields")
    if receipt["schema"] != SCHEMA:
        raise CorpusFailure("unsupported typed corpus receipt schema")
    if not isinstance(receipt["image_tag"], str) or not receipt["image_tag"]:
        raise CorpusFailure("typed corpus image tag is empty")
    if (
        not isinstance(receipt["image_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["image_id"]) is None
    ):
        raise CorpusFailure("typed corpus image identity is invalid")
    _require_identity(receipt["wanco_build_receipt"], "Wanco build receipt")
    cases = receipt["cases"]
    if not isinstance(cases, list) or len(cases) != len(CASE_SPECS):
        raise CorpusFailure("typed corpus must contain exactly nine cases")
    for case, spec in zip(cases, CASE_SPECS, strict=True):
        _validate_case(case, spec)


def publish(path: Path, receipt: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_bytes(receipt) + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError as error:
        raise CorpusFailure(f"refusing to replace typed corpus receipt: {path}") from error
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--root", required=True, type=Path)
    build.add_argument("--image-tag", required=True)
    build.add_argument("--image-id", required=True)
    build.add_argument("--wanco-build-receipt", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    validate = subparsers.add_parser("validate")
    validate.add_argument("receipt", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        if arguments.command == "build":
            receipt = build_receipt(
                root=arguments.root,
                image_tag=arguments.image_tag,
                image_id=arguments.image_id,
                wanco_build_receipt=arguments.wanco_build_receipt,
            )
            publish(arguments.output, receipt)
            print(f"Wanco typed corpus receipt: {arguments.output}")
        else:
            receipt = json.loads(arguments.receipt.read_text(encoding="utf-8"))
            validate_receipt(receipt)
            print(f"Wanco typed corpus receipt is valid: {arguments.receipt}")
    except (CorpusFailure, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"Wanco typed corpus evidence failed: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
