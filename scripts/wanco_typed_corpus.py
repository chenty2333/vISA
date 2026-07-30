#!/usr/bin/env python3
"""Build and independently validate retained Wanco typed-restore evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping, Sequence

import receipt_artifacts as ARTIFACTS


SCHEMA = "visa-wanco-typed-checkpoint-corpus-v4"
QUALIFICATION_SCHEMA = "visa-wanco-typed-checkpoint-qualification-v1"
POST_IMPORT_WITNESS_SCHEMA = "visa-wanco-post-import-signal-witness-v2"
POST_IMPORT_PROFILE = "post-import-root"
POST_IMPORT_ENTRY_MARKER = 1003
POST_IMPORT_CHECKPOINT_MARKER = 1005
POST_IMPORT_CAUSAL_ORDER = [
    "host-import-entered",
    "runner-dispatched-sigusr1",
    "host-observed-post-signal-release",
    "post-import-exact-callsite-captured",
]

MAX_RECEIPT_BYTES = 1024 * 1024
MAX_BUILD_RECEIPT_BYTES = 256 * 1024
MAX_STDOUT_BYTES = 64 * 1024
MAX_STDERR_BYTES = 2 * 1024 * 1024
MAX_WITNESS_BYTES = 512
MAX_CHECKPOINT_BYTES = 16 * 1024 * 1024
MAX_RETAINED_BYTES = 64 * 1024 * 1024

CASE_FILE_NAMES = {
    "control_stdout": "control.stdout",
    "checkpoint_stdout": "checkpoint.stdout",
    "restore_stdout": "restore.stdout",
    "checkpoint_stderr": "checkpoint.stderr",
    "restore_stderr": "restore.stderr",
    "checkpoint": "checkpoint.pb",
}
WITNESS_FILE_NAMES = {
    "import_entered": "import-entered.txt",
    "signal_dispatch": "signal.stdout",
    "release_gate": "signal-dispatched.txt",
    "import_release_observed": "import-release-observed.txt",
    "container_identity": "container.id",
}


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
        (POST_IMPORT_PROFILE, POST_IMPORT_CHECKPOINT_MARKER, 1, 0),
    )
    for optimization in range(3)
)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def bytes_identity(raw: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def reference_identity(value: object, label: str = "artifact") -> dict[str, object]:
    reference = ARTIFACTS.validate_reference(value, label)
    return {"sha256": reference["sha256"], "size": reference["size"]}


def _case_relative(spec: CaseSpec, name: str) -> str:
    return f"raw/{spec.case_id}/{name}"


def _require_reference_path(value: object, expected: str, label: str) -> None:
    try:
        reference = ARTIFACTS.validate_reference(value, label)
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error
    if reference["path"] != expected:
        raise CorpusFailure(f"{label} must use the canonical path {expected}")


def _validate_case_structure(case: object, spec: CaseSpec) -> None:
    if not isinstance(case, dict) or set(case) != {
        "case_id",
        "profile",
        "optimization",
        "artifacts",
    }:
        raise CorpusFailure(f"typed corpus case {spec.case_id} has the wrong fields")
    if (
        case["case_id"] != spec.case_id
        or case["profile"] != spec.profile
        or case["optimization"] != spec.optimization
    ):
        raise CorpusFailure(f"typed corpus case {spec.case_id} changed its contract")
    artifacts = case["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {
        *CASE_FILE_NAMES,
        "post_import_witness",
    }:
        raise CorpusFailure(f"{spec.case_id} artifact manifest has the wrong fields")
    for role, name in CASE_FILE_NAMES.items():
        _require_reference_path(
            artifacts[role], _case_relative(spec, name), f"{spec.case_id} {role}"
        )
    witness = artifacts["post_import_witness"]
    if spec.profile != POST_IMPORT_PROFILE:
        if witness is not None:
            raise CorpusFailure(f"{spec.case_id} unexpectedly contains witness artifacts")
        return
    if not isinstance(witness, dict) or set(witness) != set(WITNESS_FILE_NAMES):
        raise CorpusFailure(f"{spec.case_id} witness manifest has the wrong fields")
    for role, name in WITNESS_FILE_NAMES.items():
        _require_reference_path(
            witness[role], _case_relative(spec, name), f"{spec.case_id} {role}"
        )


def iter_references(receipt: Mapping[str, object]) -> Iterator[dict[str, object]]:
    build = receipt["wanco_build_receipt"]
    assert isinstance(build, dict)
    yield build
    cases = receipt["cases"]
    assert isinstance(cases, list)
    for case in cases:
        assert isinstance(case, dict)
        artifacts = case["artifacts"]
        assert isinstance(artifacts, dict)
        for role in CASE_FILE_NAMES:
            reference = artifacts[role]
            assert isinstance(reference, dict)
            yield reference
        witness = artifacts["post_import_witness"]
        if witness is not None:
            assert isinstance(witness, dict)
            for role in WITNESS_FILE_NAMES:
                reference = witness[role]
                assert isinstance(reference, dict)
                yield reference


def validate_receipt_structure(receipt: object) -> None:
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
    _require_reference_path(
        receipt["wanco_build_receipt"],
        "inputs/wanco-build-receipt.json",
        "Wanco build receipt",
    )
    cases = receipt["cases"]
    if not isinstance(cases, list) or len(cases) != len(CASE_SPECS):
        raise CorpusFailure("typed corpus must contain exactly twelve cases")
    for case, spec in zip(cases, CASE_SPECS, strict=True):
        _validate_case_structure(case, spec)
    paths: list[str] = []
    for reference in iter_references(receipt):
        path = reference["path"]
        assert isinstance(path, str)
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise CorpusFailure("typed corpus contains aliased artifact paths")


def _read_reference(
    artifact_root: Path,
    value: object,
    label: str,
    *,
    budget: ARTIFACTS.ReadBudget,
    max_bytes: int,
) -> bytes:
    try:
        return ARTIFACTS.read_reference(
            artifact_root,
            value,
            label,
            budget=budget,
            max_bytes=max_bytes,
        )
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error


def _parse_values(raw: bytes, label: str) -> list[int]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw:
        raise CorpusFailure(f"{label} is not canonical newline-terminated output")
    try:
        lines = raw[:-1].decode("ascii").split("\n")
    except UnicodeError as error:
        raise CorpusFailure(f"{label} is not ASCII") from error
    if not lines or any(not line for line in lines):
        raise CorpusFailure(f"{label} contains an empty line")
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


def _parse_text(raw: bytes, label: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise CorpusFailure(f"{label} is not UTF-8") from error


def _canonical_line(raw: bytes, label: str) -> str:
    if not raw or len(raw) > MAX_WITNESS_BYTES or not raw.endswith(b"\n"):
        raise CorpusFailure(f"{label} is not one bounded canonical line")
    if b"\n" in raw[:-1] or b"\r" in raw:
        raise CorpusFailure(f"{label} is not one bounded canonical line")
    try:
        return raw[:-1].decode("ascii")
    except UnicodeError as error:
        raise CorpusFailure(f"{label} is not ASCII") from error


def _derive_witness(
    witness: Mapping[str, object],
    spec: CaseSpec,
    artifact_root: Path,
    budget: ARTIFACTS.ReadBudget,
) -> dict[str, object]:
    raw = {
        role: _read_reference(
            artifact_root,
            witness[role],
            f"{spec.case_id} {role}",
            budget=budget,
            max_bytes=MAX_WITNESS_BYTES,
        )
        for role in WITNESS_FILE_NAMES
    }
    entered = _canonical_line(raw["import_entered"], "post-import entered witness")
    signal = _canonical_line(raw["signal_dispatch"], "signal dispatch result")
    release = _canonical_line(raw["release_gate"], "post-import release gate")
    observed = _canonical_line(
        raw["import_release_observed"], "post-import release observation"
    )
    container_id = _canonical_line(
        raw["container_identity"], "checkpoint container identity"
    )
    match = re.fullmatch(r"entered ([0-9a-f]{64})", entered)
    if match is None:
        raise CorpusFailure("post-import entered witness has the wrong form")
    nonce = match.group(1)
    if release != f"signal-dispatched {nonce}":
        raise CorpusFailure("post-import release is detached from the entered nonce")
    if observed != f"release-observed {nonce}":
        raise CorpusFailure("post-import host did not acknowledge the release nonce")
    if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
        raise CorpusFailure("post-import container identity is invalid")
    if signal != container_id:
        raise CorpusFailure("SIGUSR1 was not dispatched to the checkpoint container")
    return {
        "schema": POST_IMPORT_WITNESS_SCHEMA,
        "protocol": "nonce-gated-hostcall-v1",
        "signal": "SIGUSR1",
        "nonce": nonce,
        "container_id": container_id,
        "causal_order": list(POST_IMPORT_CAUSAL_ORDER),
    }


def _derive_case(
    case: Mapping[str, object],
    spec: CaseSpec,
    artifact_root: Path,
    budget: ARTIFACTS.ReadBudget,
) -> dict[str, object]:
    artifacts = case["artifacts"]
    assert isinstance(artifacts, dict)
    control = _parse_values(
        _read_reference(
            artifact_root,
            artifacts["control_stdout"],
            f"{spec.case_id} control stdout",
            budget=budget,
            max_bytes=MAX_STDOUT_BYTES,
        ),
        f"{spec.case_id} control stdout",
    )
    prefix = _parse_values(
        _read_reference(
            artifact_root,
            artifacts["checkpoint_stdout"],
            f"{spec.case_id} checkpoint stdout",
            budget=budget,
            max_bytes=MAX_STDOUT_BYTES,
        ),
        f"{spec.case_id} checkpoint stdout",
    )
    suffix = _parse_values(
        _read_reference(
            artifact_root,
            artifacts["restore_stdout"],
            f"{spec.case_id} restore stdout",
            budget=budget,
            max_bytes=MAX_STDOUT_BYTES,
        ),
        f"{spec.case_id} restore stdout",
    )
    checkpoint_stderr = _parse_text(
        _read_reference(
            artifact_root,
            artifacts["checkpoint_stderr"],
            f"{spec.case_id} checkpoint stderr",
            budget=budget,
            max_bytes=MAX_STDERR_BYTES,
        ),
        f"{spec.case_id} checkpoint stderr",
    )
    restore_stderr = _parse_text(
        _read_reference(
            artifact_root,
            artifacts["restore_stderr"],
            f"{spec.case_id} restore stderr",
            budget=budget,
            max_bytes=MAX_STDERR_BYTES,
        ),
        f"{spec.case_id} restore stderr",
    )
    checkpoint = _read_reference(
        artifact_root,
        artifacts["checkpoint"],
        f"{spec.case_id} checkpoint",
        budget=budget,
        max_bytes=MAX_CHECKPOINT_BYTES,
    )
    if not checkpoint:
        raise CorpusFailure(f"{spec.case_id} checkpoint is empty")
    if "Fatal Error" in checkpoint_stderr or "Fatal Error" in restore_stderr:
        raise CorpusFailure(f"{spec.case_id} runtime reported a fatal error")
    frame_matches = re.findall(
        r"^(?:\[info\] )?- call stack: ([0-9]+) frames$",
        restore_stderr,
        flags=re.MULTILINE,
    )
    value_matches = re.findall(
        r"^(?:\[info\] )?- value stack: ([0-9]+) values$",
        restore_stderr,
        flags=re.MULTILINE,
    )
    if len(frame_matches) != 1 or len(value_matches) != 1:
        raise CorpusFailure(f"{spec.case_id} restore counts are missing or duplicated")
    observed_frames = int(frame_matches[0], 10)
    observed_values = int(value_matches[0], 10)
    exact_records = sum(
        line.startswith("[debug] Found exact stackmap record")
        for line in checkpoint_stderr.splitlines()
    )
    if (
        observed_frames != spec.frames
        or observed_values != spec.typed_stack_values
        or exact_records != spec.frames
    ):
        raise CorpusFailure(f"typed restore observations failed for {spec.case_id}")
    if prefix[-1] != spec.marker or prefix + suffix != control:
        raise CorpusFailure(f"fresh-process restore diverged for {spec.case_id}")
    if spec.profile == POST_IMPORT_PROFILE and (
        control != [POST_IMPORT_ENTRY_MARKER, POST_IMPORT_CHECKPOINT_MARKER, 1004]
        or prefix != [POST_IMPORT_ENTRY_MARKER, POST_IMPORT_CHECKPOINT_MARKER]
        or suffix != [1004]
    ):
        raise CorpusFailure(
            f"{spec.case_id} did not capture after the imported hostcall returned"
        )
    if spec.profile == "indirect" and 999 in control:
        raise CorpusFailure("indirect restore selected the wrong table target")
    witness_raw = artifacts["post_import_witness"]
    witness = None
    if spec.profile == POST_IMPORT_PROFILE:
        assert isinstance(witness_raw, dict)
        witness = _derive_witness(witness_raw, spec, artifact_root, budget)
    return {
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
        "post_import_signal_witness": witness,
    }


def validate_receipt(
    receipt: object, *, artifact_root: Path
) -> dict[str, object]:
    validate_receipt_structure(receipt)
    assert isinstance(receipt, dict)
    budget = ARTIFACTS.ReadBudget(MAX_RETAINED_BYTES)
    build_raw = _read_reference(
        artifact_root,
        receipt["wanco_build_receipt"],
        "Wanco build receipt",
        budget=budget,
        max_bytes=MAX_BUILD_RECEIPT_BYTES,
    )
    try:
        build = json.loads(build_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CorpusFailure(f"Wanco build receipt is invalid JSON: {error}") from error
    if (
        not isinstance(build, dict)
        or build.get("schema") != "visa-wanco-carrier-build-receipt-v5"
        or build.get("image_tag") != receipt["image_tag"]
        or build.get("image_id") != receipt["image_id"]
        or build.get("stackmap_binding") != "exact-active-callsite-id"
        or build.get("stackmap_layout") != "typed-locals-and-value-stack-v2"
        or build.get("indirect_call_operands_retained") is not True
        or build.get("active_data_segments_preserved_on_restore") is not True
        or build.get("per_frame_callee_saved_registers") is not True
        or build.get("post_import_checkpoint_points") is not True
        or build.get("guest_tail_calls_disabled") is not True
    ):
        raise CorpusFailure("Wanco build receipt lacks the typed-restore contract")
    cases = receipt["cases"]
    assert isinstance(cases, list)
    derived = [
        _derive_case(case, spec, artifact_root, budget)
        for case, spec in zip(cases, CASE_SPECS, strict=True)
        if isinstance(case, dict)
    ]
    if len(derived) != len(CASE_SPECS):
        raise CorpusFailure("typed corpus case representation is invalid")
    qualification = {
        "schema": QUALIFICATION_SCHEMA,
        "manifest": bytes_identity(canonical_bytes(receipt) + b"\n"),
        "image_tag": receipt["image_tag"],
        "image_id": receipt["image_id"],
        "wanco_build_receipt": reference_identity(
            receipt["wanco_build_receipt"], "Wanco build receipt"
        ),
        "cases": derived,
    }
    validate_qualification_structure(qualification)
    return qualification


def validate_qualification_structure(value: object) -> None:
    """Validate a derived summary's shape; acceptance still requires raw evidence."""
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "manifest",
        "image_tag",
        "image_id",
        "wanco_build_receipt",
        "cases",
    }:
        raise CorpusFailure("typed corpus qualification has the wrong fields")
    if value["schema"] != QUALIFICATION_SCHEMA:
        raise CorpusFailure("unsupported typed corpus qualification schema")
    manifest_identity = value["manifest"]
    if not isinstance(manifest_identity, dict) or set(manifest_identity) != {
        "sha256",
        "size",
    }:
        raise CorpusFailure("typed corpus qualification manifest identity is malformed")
    try:
        ARTIFACTS.validate_reference(
            {"path": "receipt.json", **manifest_identity},
            "qualification manifest",
        )
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error
    if not isinstance(value["image_tag"], str) or not value["image_tag"]:
        raise CorpusFailure("typed corpus qualification image tag is empty")
    if (
        not isinstance(value["image_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"]) is None
    ):
        raise CorpusFailure("typed corpus qualification image identity is invalid")
    build_identity = value["wanco_build_receipt"]
    if not isinstance(build_identity, dict) or set(build_identity) != {
        "sha256",
        "size",
    }:
        raise CorpusFailure("typed corpus qualification build identity is malformed")
    try:
        ARTIFACTS.validate_reference(
            {"path": "build.json", **build_identity}, "qualification build receipt"
        )
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error
    cases = value["cases"]
    if not isinstance(cases, list) or len(cases) != len(CASE_SPECS):
        raise CorpusFailure("typed corpus qualification must contain twelve cases")
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
        "post_import_signal_witness",
    }
    for case, spec in zip(cases, CASE_SPECS, strict=True):
        if not isinstance(case, dict) or set(case) != fields:
            raise CorpusFailure(f"qualification case {spec.case_id} has wrong fields")
        if (
            case["case_id"] != spec.case_id
            or case["profile"] != spec.profile
            or case["optimization"] != spec.optimization
            or case["checkpoint_marker"] != spec.marker
            or case["expected_frames"] != spec.frames
            or case["observed_frames"] != spec.frames
            or case["expected_typed_stack_values"] != spec.typed_stack_values
            or case["observed_typed_stack_values"] != spec.typed_stack_values
            or case["exact_stackmap_records"] != spec.frames
        ):
            raise CorpusFailure(f"qualification case {spec.case_id} changed its contract")
        control = case["control_values"]
        prefix = case["checkpoint_prefix_values"]
        suffix = case["restored_suffix_values"]
        if (
            not isinstance(control, list)
            or not isinstance(prefix, list)
            or not isinstance(suffix, list)
            or not prefix
            or prefix[-1] != spec.marker
            or prefix + suffix != control
            or any(
                not isinstance(item, int) or isinstance(item, bool)
                for item in [*control, *prefix, *suffix]
            )
        ):
            raise CorpusFailure(f"qualification case {spec.case_id} output diverged")
        witness = case["post_import_signal_witness"]
        if spec.profile != POST_IMPORT_PROFILE:
            if witness is not None:
                raise CorpusFailure(f"qualification case {spec.case_id} has a witness")
            continue
        if not isinstance(witness, dict) or set(witness) != {
            "schema",
            "protocol",
            "signal",
            "nonce",
            "container_id",
            "causal_order",
        }:
            raise CorpusFailure(f"qualification case {spec.case_id} witness is malformed")
        if (
            witness["schema"] != POST_IMPORT_WITNESS_SCHEMA
            or witness["protocol"] != "nonce-gated-hostcall-v1"
            or witness["signal"] != "SIGUSR1"
            or not isinstance(witness["nonce"], str)
            or re.fullmatch(r"[0-9a-f]{64}", witness["nonce"]) is None
            or not isinstance(witness["container_id"], str)
            or re.fullmatch(r"[0-9a-f]{64}", witness["container_id"]) is None
            or witness["causal_order"] != POST_IMPORT_CAUSAL_ORDER
        ):
            raise CorpusFailure(f"qualification case {spec.case_id} witness changed")


def _publish_receipt(path: Path, receipt: Mapping[str, object]) -> None:
    raw = canonical_bytes(receipt) + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise CorpusFailure(f"refusing to replace typed corpus receipt: {path}") from error
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _publish_source(
    source: Path, artifact_root: Path, relative: str
) -> dict[str, object]:
    try:
        return ARTIFACTS.publish_reference(source, artifact_root, relative)
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error


def build_bundle(
    *,
    source_root: Path,
    artifact_root: Path,
    image_tag: str,
    image_id: str,
    wanco_build_receipt: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    if artifact_root.exists() or artifact_root.is_symlink():
        raise CorpusFailure(f"refusing to reuse typed corpus artifact root: {artifact_root}")
    artifact_root.mkdir(mode=0o700)
    build_reference = _publish_source(
        wanco_build_receipt,
        artifact_root,
        "inputs/wanco-build-receipt.json",
    )
    cases: list[dict[str, object]] = []
    for spec in CASE_SPECS:
        case_source = source_root / "results" / spec.case_id
        artifacts = {
            role: _publish_source(
                case_source / name,
                artifact_root,
                _case_relative(spec, name),
            )
            for role, name in CASE_FILE_NAMES.items()
        }
        witness = None
        if spec.profile == POST_IMPORT_PROFILE:
            witness = {
                role: _publish_source(
                    case_source / name,
                    artifact_root,
                    _case_relative(spec, name),
                )
                for role, name in WITNESS_FILE_NAMES.items()
            }
        artifacts["post_import_witness"] = witness
        cases.append(
            {
                "case_id": spec.case_id,
                "profile": spec.profile,
                "optimization": spec.optimization,
                "artifacts": artifacts,
            }
        )
    receipt = {
        "schema": SCHEMA,
        "image_tag": image_tag,
        "image_id": image_id,
        "wanco_build_receipt": build_reference,
        "cases": cases,
    }
    qualification = validate_receipt(receipt, artifact_root=artifact_root)
    _publish_receipt(artifact_root / "receipt.json", receipt)
    return receipt, qualification


def load_and_validate(path: Path) -> tuple[dict[str, object], dict[str, object]]:
    absolute = path.absolute()
    try:
        raw = ARTIFACTS.read_bounded_file(
            absolute, "typed corpus receipt", max_bytes=MAX_RECEIPT_BYTES
        )
    except ARTIFACTS.ArtifactError as error:
        raise CorpusFailure(str(error)) from error
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CorpusFailure(f"typed corpus receipt is invalid JSON: {error}") from error
    if canonical_bytes(receipt) + b"\n" != raw:
        raise CorpusFailure("typed corpus receipt is not canonical JSON")
    if not isinstance(receipt, dict):
        raise CorpusFailure("typed corpus receipt is not an object")
    qualification = validate_receipt(receipt, artifact_root=absolute.parent)
    return receipt, qualification


def retain_bundle(
    source_receipt: Path, destination_root: Path
) -> tuple[dict[str, object], dict[str, object]]:
    receipt, qualification = load_and_validate(source_receipt)
    if destination_root.exists() or destination_root.is_symlink():
        raise CorpusFailure(
            f"refusing to reuse retained typed corpus root: {destination_root}"
        )
    destination_root.mkdir(mode=0o700)
    source_root = source_receipt.absolute().parent
    for reference in iter_references(receipt):
        relative = reference["path"]
        assert isinstance(relative, str)
        published = _publish_source(
            source_root.joinpath(*relative.split("/")), destination_root, relative
        )
        if published != reference:
            raise CorpusFailure(f"retained typed corpus changed while copying: {relative}")
    _publish_receipt(destination_root / "receipt.json", receipt)
    copied_receipt, copied_qualification = load_and_validate(
        destination_root / "receipt.json"
    )
    if copied_receipt != receipt or copied_qualification != qualification:
        raise CorpusFailure("retained typed corpus differs after relocation")
    return copied_receipt, copied_qualification


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--source-root", required=True, type=Path)
    build.add_argument("--artifact-root", required=True, type=Path)
    build.add_argument("--image-tag", required=True)
    build.add_argument("--image-id", required=True)
    build.add_argument("--wanco-build-receipt", required=True, type=Path)
    validate = subparsers.add_parser("validate")
    validate.add_argument("receipt", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        if arguments.command == "build":
            _, qualification = build_bundle(
                source_root=arguments.source_root,
                artifact_root=arguments.artifact_root,
                image_tag=arguments.image_tag,
                image_id=arguments.image_id,
                wanco_build_receipt=arguments.wanco_build_receipt,
            )
            print(
                "Wanco typed corpus artifact: "
                f"{arguments.artifact_root / 'receipt.json'} "
                f"({len(qualification['cases'])} cases)"
            )
        else:
            _, qualification = load_and_validate(arguments.receipt)
            print(
                "Wanco typed corpus raw evidence is valid: "
                f"{arguments.receipt} ({len(qualification['cases'])} cases)"
            )
    except (CorpusFailure, OSError) as error:
        print(f"Wanco typed corpus evidence failed: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
