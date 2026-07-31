#!/usr/bin/env python3
"""Validate the stock-zstd receipt and its retained raw oracle artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn

from receipt_artifacts import (
    ArtifactError,
    ReadBudget,
    read_bounded_file,
    read_reference,
    validate_reference,
)
import wanco_process_diagnostics as WANCO_DIAGNOSTICS

SCHEMA = "visa-stock-zstd-transparent-migration-matrix-v7"
ORACLE_REPORT_SCHEMA = "visa-stock-zstd-external-oracle-report-v1"
FAULT_PROCESS_OBSERVATION_SCHEMA = (
    "visa-stock-zstd-fault-process-observation-v1"
)
CANONICAL_INPUT_BYTES = 24 * 1024 * 1024
CANONICAL_INPUT_SEED = b"vISA stock zstd transparent migration input v1"
CUTS = (("cut-1", 8), ("cut-2", 64))
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_STDOUT_BYTES = 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
MAX_ORACLE_REPORT_BYTES = 1024 * 1024
MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_FAULT_STDERR_BYTES = 1024 * 1024
MAX_FAULT_PROCESS_OBSERVATION_BYTES = 64 * 1024
MAX_TOTAL_RAW_BYTES = MAX_COMPRESSED_BYTES + 24 * 1024 * 1024
TOP_LEVEL_KEYS = {
    "authority_model",
    "contract_checks",
    "control",
    "execution_input_binding",
    "external_oracle",
    "fault_cells",
    "input",
    "migrated_cells",
    "raw_oracle_artifacts_retained",
    "raw_fault_artifacts_retained",
    "repository_revision",
    "repository_source_snapshot",
    "schema",
    "source_lock_sha256",
    "stock_zstd_build_receipt_sha256",
    "wanco_build_receipt_sha256",
    "wanco_optimization",
    "zero_upstream_zstd_source_patches",
}
STATUS_KEYS = {
    "authority_epoch",
    "barrier",
    "barrier_effect",
    "barrier_remaining",
    "completed_barrier",
    "completed_barrier_effect",
    "bytes_read",
    "bytes_written",
    "completed_requests",
    "effects",
    "locks",
    "mode",
    "objects",
    "open_descriptors",
    "paths",
    "session",
}
CELL_KEYS = {
    "active_status",
    "cell",
    "commit_proof_sha256",
    "compressed_bytes_equal_uninterrupted_control",
    "cut",
    "destination_executed_manifest_bound_application",
    "fence_proof_sha256",
    "final_status",
    "manifest_sha256",
    "oracle",
    "prepared_status",
    "raw_artifacts",
    "source_fenced_status",
    "source_frozen_status",
    "source_post_checkpoint_status",
    "topology",
}
RAW_ARTIFACT_KEYS = {
    "application_runs",
    "compressed_output",
    "oracle_report",
}
FAULT_SPECIFICATIONS = {
    "carrier-only-fresh-empty-provider": (
        "stock-zstd-filesystem-error-from-fresh-empty-provider",
        "end-to-end",
        ("Bad file descriptor", "Read error", "Permission denied"),
        "zstd-stderr-code",
    ),
    "compute-checkpoint-tamper": (
        "migration-manifest-bound-file-digest",
        "manifest-verification-path",
        ("migration integrity failure: bound file content differs",),
        "canonical-cli-failure",
    ),
    "provider-capsule-tamper": (
        "provider-capsule-state-digest",
        "provider-restore-path",
        ("provider integrity failure: capsule state digest",),
        "canonical-cli-failure",
    ),
    "commit-fence-proof-pair-swap": (
        "canonical-fence-to-commit-binding",
        "canonical-proof-verification-path",
        ("canonical proof rejected: source fence proof binding differs",),
        "canonical-cli-failure",
    ),
    "destination-guest-capability-spoof": (
        "guest-capability-admission-before-provider-mutation",
        "end-to-end",
        ("Permission denied", "Read error", "Bad file descriptor"),
        "zstd-stderr-code",
    ),
}


class ReceiptError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise ReceiptError(message)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        fail(f"{label} keys differ: {actual}")
    return value


def exact_bool(value: Any, expected: bool, label: str) -> None:
    if value is not expected:
        fail(f"{label} must be {expected}")


def nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{label} must be a nonnegative integer")
    return value


def positive_int(value: Any, label: str) -> int:
    result = nonnegative_int(value, label)
    if result == 0:
        fail(f"{label} must be positive")
    return result


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256")
    return value


def identity(value: Any, label: str) -> dict[str, Any]:
    result = exact_object(value, {"sha256", "size"}, label)
    digest(result["sha256"], f"{label}.sha256")
    nonnegative_int(result["size"], f"{label}.size")
    return result


def validate_status(
    value: Any,
    label: str,
    *,
    mode: str,
    epoch: int,
    barrier: str,
    effect_required: bool,
) -> dict[str, Any]:
    status = exact_object(value, STATUS_KEYS, label)
    if status["mode"] != mode or status["authority_epoch"] != epoch:
        fail(f"{label} must be {mode}@{epoch}")
    if status["barrier"] != barrier:
        fail(f"{label}.barrier must be {barrier}")
    if effect_required:
        effect = status["barrier_effect"]
        if (
            not isinstance(effect, list)
            or len(effect) != 16
            or any(
                isinstance(item, bool)
                or not isinstance(item, int)
                or item < 0
                or item > 255
                for item in effect
            )
        ):
            fail(f"{label}.barrier_effect must be a 16-byte array")
    elif status["barrier_effect"] is not None:
        fail(f"{label}.barrier_effect must be null")
    completed_barrier = status["completed_barrier"]
    completed_effect = status["completed_barrier_effect"]
    if (completed_barrier is None) != (completed_effect is None):
        fail(f"{label} has a partial completed-barrier identity")
    for field, value in (
        ("completed_barrier", completed_barrier),
        ("completed_barrier_effect", completed_effect),
    ):
        if value is not None and (
            not isinstance(value, list)
            or len(value) != 16
            or any(
                isinstance(item, bool)
                or not isinstance(item, int)
                or item < 0
                or item > 255
                for item in value
            )
        ):
            fail(f"{label}.{field} must be null or a 16-byte array")
    if barrier == "armed":
        positive_int(status["barrier_remaining"], f"{label}.barrier_remaining")
    elif status["barrier_remaining"] is not None:
        fail(f"{label}.barrier_remaining must be null")
    for field in (
        "bytes_read",
        "bytes_written",
        "completed_requests",
        "effects",
        "locks",
        "objects",
        "open_descriptors",
        "paths",
    ):
        nonnegative_int(status[field], f"{label}.{field}")
    if status["completed_requests"] != status["effects"]:
        fail(f"{label} has incomplete response delivery")
    session = status["session"]
    if (
        not isinstance(session, list)
        or len(session) != 16
        or any(
            isinstance(item, bool)
            or not isinstance(item, int)
            or item < 0
            or item > 255
            for item in session
        )
    ):
        fail(f"{label}.session must be a 16-byte array")
    return status


def validate_oracle(
    value: Any,
    label: str,
    expected_input: dict[str, Any],
) -> dict[str, Any]:
    oracle = exact_object(value, {"compressed", "decoded", "input"}, label)
    observed_input = identity(oracle["input"], f"{label}.input")
    decoded = identity(oracle["decoded"], f"{label}.decoded")
    compressed = identity(oracle["compressed"], f"{label}.compressed")
    if observed_input != expected_input or decoded != expected_input:
        fail(f"{label} does not establish lossless external decompression")
    positive_int(compressed["size"], f"{label}.compressed.size")
    return oracle


def bytes_identity(payload: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def file_identity(path: Path) -> dict[str, Any]:
    digest_value = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest_value.update(chunk)
            size += len(chunk)
    return {"sha256": digest_value.hexdigest(), "size": size}


def write_canonical_input(path: Path) -> None:
    with path.open("xb") as stream:
        remaining = CANONICAL_INPUT_BYTES
        index = 0
        while remaining:
            block = hashlib.sha256(
                CANONICAL_INPUT_SEED + index.to_bytes(8, "little")
            ).digest()
            output = block[:remaining]
            stream.write(output)
            remaining -= len(output)
            index += 1


def parse_canonical_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse {label}: {error}")
    if not isinstance(document, dict):
        fail(f"{label} must be a JSON object")
    if payload != canonical_bytes(document) + b"\n":
        fail(f"{label} is not canonical sorted compact JSON with one trailing newline")
    return document


def validate_stock_zstd_program(
    requested: Path,
    program: dict[str, Any],
) -> Path:
    try:
        resolved = requested.resolve(strict=True)
        program_stat = resolved.stat()
    except OSError as error:
        fail(f"cannot resolve the verifier-selected stock zstd: {error}")
    if not stat.S_ISREG(program_stat.st_mode):
        fail("verifier-selected stock zstd is not a regular file")
    if os.fspath(resolved) != program["path"]:
        fail("verifier-selected stock zstd path differs from the receipt")
    observed = file_identity(resolved)
    if observed != {"sha256": program["sha256"], "size": program["size"]}:
        fail("verifier-selected stock zstd identity differs from the receipt")
    try:
        completed = subprocess.run(
            [resolved, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"cannot execute verifier-selected stock zstd: {error}")
    if completed.returncode != 0:
        fail("verifier-selected stock zstd --version failed")
    try:
        observed_version = completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        fail(f"verifier-selected stock zstd version is not UTF-8: {error}")
    if observed_version != program["version"] or "v1.5.7" not in observed_version:
        fail("verifier-selected stock zstd version differs from the receipt")
    return resolved


def query_package_identity(program: Path, manager: str) -> dict[str, str]:
    if manager == "rpm":
        rpm = shutil.which("rpm")
        if rpm is None:
            fail("receipt selects RPM provenance but rpm is unavailable")
        completed = subprocess.run(
            [
                rpm,
                "-qf",
                "--qf",
                "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}",
                program,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            fail("rpm could not verify the selected stock zstd owner")
        try:
            package_identity = completed.stdout.decode("utf-8")
        except UnicodeDecodeError as error:
            fail(f"rpm package identity is not UTF-8: {error}")
    elif manager == "dpkg":
        dpkg = shutil.which("dpkg")
        dpkg_query = shutil.which("dpkg-query")
        if dpkg is None or dpkg_query is None:
            fail("receipt selects dpkg provenance but dpkg tools are unavailable")
        owner = subprocess.run(
            [dpkg, "-S", program],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if owner.returncode != 0:
            fail("dpkg could not verify the selected stock zstd owner")
        try:
            owner_lines = owner.stdout.decode("utf-8").splitlines()
        except UnicodeDecodeError as error:
            fail(f"dpkg owner result is not UTF-8: {error}")
        if len(owner_lines) != 1 or ":" not in owner_lines[0]:
            fail("dpkg returned an ambiguous stock zstd owner")
        package_name = owner_lines[0].split(":", 1)[0]
        completed = subprocess.run(
            [
                dpkg_query,
                "-W",
                "-f=${Package}=${Version}:${Architecture}",
                package_name,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            fail("dpkg-query could not verify the selected stock zstd package")
        try:
            package_identity = completed.stdout.decode("utf-8")
        except UnicodeDecodeError as error:
            fail(f"dpkg package identity is not UTF-8: {error}")
    else:
        fail("external_oracle program has an unsupported package manager")
    if (
        not package_identity
        or package_identity != package_identity.strip()
        or "\n" in package_identity
    ):
        fail("stock zstd package identity is not one canonical nonempty line")
    return {"manager": manager, "identity": package_identity}


def validate_oracle_report(
    payload: bytes,
    label: str,
    cell: str,
    expected_input: dict[str, Any],
    observed_compressed: dict[str, Any],
) -> dict[str, Any]:
    report = exact_object(
        parse_canonical_json(payload, label),
        {"cell", "command", "compressed", "decoded", "input", "schema"},
        label,
    )
    if report["schema"] != ORACLE_REPORT_SCHEMA or report["cell"] != cell:
        fail(f"{label} schema or cell identity differs")
    command = exact_object(
        report["command"],
        {"exit_status", "operation", "stderr", "stdout"},
        f"{label}.command",
    )
    if (
        command["operation"] != "stock-zstd-decompress"
        or command["exit_status"] != 0
    ):
        fail(f"{label} does not record a successful stock-zstd decompression")
    empty = bytes_identity(b"")
    if (
        identity(command["stdout"], f"{label}.command.stdout") != empty
        or identity(command["stderr"], f"{label}.command.stderr") != empty
    ):
        fail(f"{label} native-zstd command emitted unexpected output")
    input_identity = identity(report["input"], f"{label}.input")
    decoded_identity = identity(report["decoded"], f"{label}.decoded")
    compressed_identity = identity(report["compressed"], f"{label}.compressed")
    if input_identity != expected_input or decoded_identity != expected_input:
        fail(f"{label} does not bind lossless decompression to canonical input")
    if compressed_identity != observed_compressed:
        fail(f"{label} compressed identity differs from the retained output")
    return {
        "input": input_identity,
        "decoded": decoded_identity,
        "compressed": compressed_identity,
    }


def repeat_stock_zstd_oracle(
    *,
    stock_zstd: Path,
    compressed_payload: bytes,
    canonical_input: Path,
    work: Path,
    label: str,
) -> dict[str, Any]:
    compressed = work / f"{label}.zst"
    decoded = work / f"{label}.decoded"
    compressed.write_bytes(compressed_payload)

    def limit_decoded_output() -> None:
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (CANONICAL_INPUT_BYTES, CANONICAL_INPUT_BYTES),
        )

    try:
        completed = subprocess.run(
            [stock_zstd, "-q", "-d", "-f", compressed, "-o", decoded],
            cwd=work,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
            preexec_fn=limit_decoded_output,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"{label} repeated stock-zstd oracle could not execute: {error}")
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")[-1000:]
        fail(f"{label} repeated stock-zstd decompression failed: {stderr}")
    if completed.stdout or completed.stderr:
        fail(f"{label} repeated quiet stock-zstd decompression emitted output")
    if not decoded.is_file() or decoded.stat().st_size != CANONICAL_INPUT_BYTES:
        fail(f"{label} repeated stock-zstd output size is not canonical")
    expected_input = file_identity(canonical_input)
    decoded_identity = file_identity(decoded)
    if decoded_identity != expected_input:
        fail(f"{label} repeated stock-zstd decompression differs from canonical input")
    return {
        "input": expected_input,
        "decoded": decoded_identity,
        "compressed": bytes_identity(compressed_payload),
    }


def validate_raw_artifacts(
    value: Any,
    *,
    label: str,
    cell: str,
    expected_roles: tuple[str, ...],
    expected_input: dict[str, Any],
    artifact_root: Path,
    budget: ReadBudget,
    stock_zstd: Path,
    canonical_input: Path,
    work: Path,
) -> tuple[dict[str, Any], bytes]:
    raw = exact_object(value, RAW_ARTIFACT_KEYS, f"{label}.raw_artifacts")
    prefix = f"raw/{label}"
    application_runs = raw["application_runs"]
    if not isinstance(application_runs, list) or len(application_runs) != len(
        expected_roles
    ):
        fail(f"{label}.raw_artifacts application run inventory differs")
    observed_roles: list[str] = []
    for index, (entry, expected_role) in enumerate(
        zip(application_runs, expected_roles, strict=True)
    ):
        item = exact_object(
            entry,
            {"exit_status", "role", "stderr", "stdout"},
            f"{label}.raw_artifacts.application_runs[{index}]",
        )
        if item["role"] != expected_role:
            fail(f"{label}.raw_artifacts application run role/order differs")
        if (
            not isinstance(item["exit_status"], int)
            or isinstance(item["exit_status"], bool)
            or item["exit_status"] != 0
        ):
            fail(f"{label} {expected_role} application exit status must be zero")
        observed_roles.append(expected_role)
        stdout_reference = validate_reference(
            item["stdout"],
            f"{label} {expected_role} application stdout",
        )
        if stdout_reference["path"] != f"{prefix}/{expected_role}.stdout":
            fail(f"{label} {expected_role} application stdout path differs")
        stdout_payload = read_reference(
            artifact_root,
            stdout_reference,
            f"{label} {expected_role} application stdout",
            budget=budget,
            max_bytes=MAX_STDOUT_BYTES,
        )
        if stdout_payload:
            fail(f"{label} {expected_role} application stdout must be empty")
        stderr_reference = validate_reference(
            item["stderr"],
            f"{label} {expected_role} application stderr",
        )
        if stderr_reference["path"] != f"{prefix}/{expected_role}.stderr":
            fail(f"{label} {expected_role} application stderr path differs")
        stderr_payload = read_reference(
            artifact_root,
            stderr_reference,
            f"{label} {expected_role} application stderr",
            budget=budget,
            max_bytes=MAX_STDERR_BYTES,
        )
        try:
            WANCO_DIAGNOSTICS.validate_application_stderr(
                expected_role,
                stderr_payload,
                f"{label} {expected_role} application stderr",
            )
        except WANCO_DIAGNOSTICS.DiagnosticFailure as error:
            fail(str(error))
    if tuple(observed_roles) != expected_roles:
        fail(f"{label}.raw_artifacts application run inventory differs")

    compressed_reference = validate_reference(
        raw["compressed_output"],
        f"{label} compressed output",
    )
    if compressed_reference["path"] != "raw/positive-output.zst":
        fail(f"{label} compressed output path is not the shared positive blob")
    compressed_payload = read_reference(
        artifact_root,
        compressed_reference,
        f"{label} compressed output",
        budget=budget,
        max_bytes=MAX_COMPRESSED_BYTES,
    )
    if not compressed_payload:
        fail(f"{label} compressed output must be nonempty")
    observed_compressed = bytes_identity(compressed_payload)
    report_reference = validate_reference(
        raw["oracle_report"],
        f"{label} oracle report",
    )
    if report_reference["path"] != f"{prefix}/oracle-report.json":
        fail(f"{label} oracle report path differs")
    report_payload = read_reference(
        artifact_root,
        report_reference,
        f"{label} oracle report",
        budget=budget,
        max_bytes=MAX_ORACLE_REPORT_BYTES,
    )
    reported = validate_oracle_report(
        report_payload,
        f"{label}.raw_artifacts.oracle_report",
        cell,
        expected_input,
        observed_compressed,
    )
    repeated = repeat_stock_zstd_oracle(
        stock_zstd=stock_zstd,
        compressed_payload=compressed_payload,
        canonical_input=canonical_input,
        work=work,
        label=label,
    )
    if reported != repeated:
        fail(f"{label} retained oracle report differs from independent recomputation")
    return repeated, compressed_payload


def validate_clean_snapshot(value: Any) -> None:
    snapshot = exact_object(
        value,
        {
            "clean",
            "status_sha256",
            "tracked_patch_sha256",
            "untracked_file_count",
            "untracked_manifest_sha256",
        },
        "repository_source_snapshot",
    )
    exact_bool(snapshot["clean"], True, "repository_source_snapshot.clean")
    empty = hashlib.sha256(b"").hexdigest()
    empty_manifest = hashlib.sha256(canonical_bytes([])).hexdigest()
    if snapshot["status_sha256"] != empty or snapshot["tracked_patch_sha256"] != empty:
        fail("clean repository snapshot contains a status or tracked patch")
    if snapshot["untracked_file_count"] != 0:
        fail("clean repository snapshot contains untracked files")
    if snapshot["untracked_manifest_sha256"] != empty_manifest:
        fail("clean repository snapshot has a nonempty untracked manifest")


def validate_cut(
    value: Any,
    label: str,
    occurrence: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    cut = exact_object(
        value,
        {
            "armed_status",
            "barrier_token",
            "byte_counter_trigger_used",
            "checkpoint",
            "checkpoint_released_status",
            "cut_location_source",
            "held_status",
            "predicate",
            "signal_checkpoint_used",
        },
        f"{label}.cut",
    )
    if cut["cut_location_source"] != "prearmed-post-hostcall-predicate":
        fail(f"{label} is not located by the exact post-hostcall predicate")
    exact_bool(cut["byte_counter_trigger_used"], False, f"{label}.byte_counter_trigger_used")
    exact_bool(cut["signal_checkpoint_used"], False, f"{label}.signal_checkpoint_used")
    token = cut["barrier_token"]
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{32}", token) is None:
        fail(f"{label}.barrier_token must be a 128-bit lowercase hex value")
    predicate = exact_object(
        cut["predicate"], {"kind", "occurrence", "outcome", "resource"}, f"{label}.predicate"
    )
    expected = {
        "kind": "fd-write",
        "resource": "path:output.zst",
        "outcome": "success",
        "occurrence": occurrence,
    }
    if predicate != expected:
        fail(f"{label}.predicate differs from the canonical cut")
    armed = validate_status(
        cut["armed_status"],
        f"{label}.armed_status",
        mode="active",
        epoch=1,
        barrier="armed",
        effect_required=False,
    )
    if armed["barrier_remaining"] != occurrence:
        fail(f"{label}.armed_status does not retain the requested occurrence")
    held = validate_status(
        cut["held_status"],
        f"{label}.held_status",
        mode="active",
        epoch=1,
        barrier="held",
        effect_required=True,
    )
    released = validate_status(
        cut["checkpoint_released_status"],
        f"{label}.checkpoint_released_status",
        mode="active",
        epoch=1,
        barrier="checkpoint_released",
        effect_required=True,
    )
    if held != {**released, "barrier": "held"}:
        fail(f"{label} held and checkpoint-released observations drifted")
    for name, status in (("armed", armed), ("held", held), ("released", released)):
        if status["completed_barrier"] is not None:
            fail(f"{label} {name} status retained an earlier barrier completion")
    checkpoint = identity(cut["checkpoint"], f"{label}.checkpoint")
    positive_int(checkpoint["size"], f"{label}.checkpoint.size")
    return released, checkpoint


def validate_cell(
    value: Any,
    label: str,
    occurrence: int,
    expected_input: dict[str, Any],
    control: dict[str, Any],
    *,
    artifact_root: Path,
    budget: ReadBudget,
    stock_zstd: Path,
    canonical_input: Path,
    work: Path,
    control_compressed_payload: bytes,
) -> str:
    cell = exact_object(value, CELL_KEYS, label)
    if cell["cell"] != f"{label}-visa-plus-carrier":
        fail(f"{label}.cell differs")
    if cell["topology"] != "fresh-provider-fresh-process":
        fail(f"{label}.topology must use a fresh provider and process")
    exact_bool(
        cell["destination_executed_manifest_bound_application"],
        True,
        f"{label}.destination_executed_manifest_bound_application",
    )
    exact_bool(
        cell["compressed_bytes_equal_uninterrupted_control"],
        True,
        f"{label}.compressed_bytes_equal_uninterrupted_control",
    )
    for field in ("manifest_sha256", "commit_proof_sha256", "fence_proof_sha256"):
        digest(cell[field], f"{label}.{field}")
    released, checkpoint = validate_cut(cell["cut"], label, occurrence)
    source_post = validate_status(
        cell["source_post_checkpoint_status"],
        f"{label}.source_post_checkpoint_status",
        mode="active",
        epoch=1,
        barrier="checkpoint_released",
        effect_required=True,
    )
    if source_post != released:
        fail(f"{label} source status differs from the released checkpoint cut")
    source_frozen = validate_status(
        cell["source_frozen_status"],
        f"{label}.source_frozen_status",
        mode="frozen",
        epoch=1,
        barrier="checkpoint_released",
        effect_required=True,
    )
    prepared = validate_status(
        cell["prepared_status"],
        f"{label}.prepared_status",
        mode="prepared",
        epoch=1,
        barrier="checkpoint_released",
        effect_required=True,
    )
    fenced = validate_status(
        cell["source_fenced_status"],
        f"{label}.source_fenced_status",
        mode="fenced",
        epoch=1,
        barrier="checkpoint_released",
        effect_required=True,
    )
    base = {key: value for key, value in source_post.items() if key != "mode"}
    for name, status in (("frozen", source_frozen), ("prepared", prepared), ("fenced", fenced)):
        if {key: value for key, value in status.items() if key != "mode"} != base:
            fail(f"{label} {name} transition changed frozen semantic state")
    active = validate_status(
        cell["active_status"],
        f"{label}.active_status",
        mode="active",
        epoch=2,
        barrier="open",
        effect_required=False,
    )
    expected_completed_barrier = list(bytes.fromhex(cell["cut"]["barrier_token"]))
    if (
        active["completed_barrier"] != expected_completed_barrier
        or active["completed_barrier_effect"] != released["barrier_effect"]
    ):
        fail(f"{label} activated destination is detached from the checkpoint barrier")
    for field in ("bytes_read", "bytes_written", "completed_requests", "effects"):
        if active[field] != source_post[field]:
            fail(f"{label} destination prepare changed {field}")
    if active["session"] != source_post["session"]:
        fail(f"{label} destination session differs from the source session")
    final = validate_status(
        cell["final_status"],
        f"{label}.final_status",
        mode="active",
        epoch=2,
        barrier="open",
        effect_required=False,
    )
    if (
        final["completed_barrier"] != active["completed_barrier"]
        or final["completed_barrier_effect"] != active["completed_barrier_effect"]
    ):
        fail(f"{label} final status changed the completed checkpoint barrier")
    if (
        source_post["bytes_read"] >= expected_input["size"]
        or source_post["bytes_written"] >= control["oracle"]["compressed"]["size"]
        or source_post["completed_requests"] >= control["provider_status"]["completed_requests"]
    ):
        fail(f"{label} checkpoint is not mid-execution")
    if final["session"] != source_post["session"]:
        fail(f"{label} final destination session differs from the source session")
    if final["bytes_read"] != expected_input["size"]:
        fail(f"{label} did not consume the complete input")
    if final["bytes_written"] != control["oracle"]["compressed"]["size"]:
        fail(f"{label} did not produce the control output size")
    if final["completed_requests"] != control["provider_status"]["completed_requests"]:
        fail(f"{label} request frontier differs from the control")
    oracle = validate_oracle(cell["oracle"], f"{label}.oracle", expected_input)
    if oracle != control["oracle"]:
        fail(f"{label} external oracle differs from uninterrupted execution")
    repeated_oracle, compressed_payload = validate_raw_artifacts(
        cell["raw_artifacts"],
        label=label,
        cell=f"{label}-visa-plus-carrier",
        expected_roles=("source", "destination"),
        expected_input=expected_input,
        artifact_root=artifact_root,
        budget=budget,
        stock_zstd=stock_zstd,
        canonical_input=canonical_input,
        work=work,
    )
    if repeated_oracle != oracle:
        fail(f"{label} inline oracle summary differs from retained raw artifacts")
    if compressed_payload != control_compressed_payload:
        fail(f"{label} retained compressed bytes differ from uninterrupted control")
    return checkpoint["sha256"]


def validate_faults(
    value: Any,
    *,
    artifact_root: Path,
    budget: ReadBudget,
) -> None:
    if not isinstance(value, list) or len(value) != len(CUTS) * 5:
        fail("fault_cells must contain exactly five faults per cut")
    observed: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            fail(f"fault_cells[{index}] must be an object")
        name = raw.get("fault")
        if not isinstance(name, str) or name in observed:
            fail(f"fault_cells[{index}] has an empty or duplicate identity")
        observed.add(name)
        cut = next((label for label, _ in CUTS if name.startswith(label + "-")), None)
        if cut is None:
            fail(f"fault cell has an unknown cut: {name}")
        suffix = name[len(cut) + 1 :]
        if suffix not in FAULT_SPECIFICATIONS:
            fail(f"fault cell has an unknown fault: {name}")
        detector, scope, stderr_signatures, exit_policy = (
            FAULT_SPECIFICATIONS[suffix]
        )
        required = {
            "detector",
            "exit_status",
            "fault",
            "raw_process_observation",
            "raw_stderr",
            "scope",
            "stderr_sha256",
            "stderr_tail",
        }
        if suffix == "carrier-only-fresh-empty-provider":
            required |= {"provider_before", "provider_after"}
        if suffix == "destination-guest-capability-spoof":
            required.add("provider_state_unchanged")
        exact_object(raw, required, f"fault {name}")
        if raw["detector"] != detector or raw["scope"] != scope:
            fail(f"fault {name} detector or scope differs")
        prefix = f"raw/faults/{cut}/{suffix}"
        stderr_reference = validate_reference(
            raw["raw_stderr"], f"fault {name} raw stderr"
        )
        if stderr_reference["path"] != f"{prefix}.stderr":
            fail(f"fault {name} raw stderr path differs")
        stderr_payload = read_reference(
            artifact_root,
            stderr_reference,
            f"fault {name} raw stderr",
            budget=budget,
            max_bytes=MAX_FAULT_STDERR_BYTES,
        )
        process_reference = validate_reference(
            raw["raw_process_observation"],
            f"fault {name} raw process observation",
        )
        if process_reference["path"] != f"{prefix}.process.json":
            fail(f"fault {name} raw process observation path differs")
        process_payload = read_reference(
            artifact_root,
            process_reference,
            f"fault {name} raw process observation",
            budget=budget,
            max_bytes=MAX_FAULT_PROCESS_OBSERVATION_BYTES,
        )
        process = exact_object(
            parse_canonical_json(
                process_payload, f"fault {name} raw process observation"
            ),
            {"exit_status", "fault", "schema", "stderr"},
            f"fault {name} raw process observation",
        )
        if (
            process["schema"] != FAULT_PROCESS_OBSERVATION_SCHEMA
            or process["fault"] != name
        ):
            fail(f"fault {name} raw process observation identity differs")
        observed_exit_status = positive_int(
            process["exit_status"],
            f"fault {name} raw process observation exit_status",
        )
        observed_stderr_identity = bytes_identity(stderr_payload)
        if (
            identity(
                process["stderr"],
                f"fault {name} raw process observation stderr",
            )
            != observed_stderr_identity
        ):
            fail(f"fault {name} raw process observation does not bind stderr")
        if raw["exit_status"] != observed_exit_status:
            fail(f"fault {name} summary exit status differs from raw observation")
        if raw["stderr_sha256"] != observed_stderr_identity["sha256"]:
            fail(f"fault {name} summary stderr digest differs from raw stderr")
        stderr_text = stderr_payload.decode("utf-8", errors="replace")
        if exit_policy == "zstd-stderr-code":
            observed_codes = re.findall(
                r"(?m)^zstd: error ([1-9][0-9]{0,2}) :", stderr_text
            )
            if len(observed_codes) != 1:
                fail(f"fault {name} raw stderr has no unique zstd exit code")
            stderr_exit_status = int(observed_codes[0])
            if (
                stderr_exit_status > 255
                or observed_exit_status != stderr_exit_status
            ):
                fail(
                    f"fault {name} raw process exit status differs from zstd stderr"
                )
        elif exit_policy == "canonical-cli-failure":
            if observed_exit_status != 1:
                fail(f"fault {name} raw process exit status must be one")
        else:
            fail(f"fault {name} has an unsupported exit-status policy")
        observed_tail = stderr_text[-320:]
        if raw["stderr_tail"] != observed_tail:
            fail(f"fault {name} summary stderr tail differs from raw stderr")
        if not any(signature in stderr_text for signature in stderr_signatures):
            fail(f"fault {name} raw stderr lacks the expected detector signature")
        if suffix == "carrier-only-fresh-empty-provider":
            before = validate_status(
                raw["provider_before"],
                f"fault {name}.provider_before",
                mode="active",
                epoch=2,
                barrier="open",
                effect_required=False,
            )
            after = validate_status(
                raw["provider_after"],
                f"fault {name}.provider_after",
                mode="active",
                epoch=2,
                barrier="open",
                effect_required=False,
            )
            if before["effects"] != 0 or after["effects"] != 1:
                fail(f"fault {name} does not expose the carrier-only resource failure")
        if suffix == "destination-guest-capability-spoof":
            exact_bool(raw["provider_state_unchanged"], True, f"fault {name}.provider_state_unchanged")
    required_names = {
        f"{cut}-{suffix}"
        for cut, _ in CUTS
        for suffix in FAULT_SPECIFICATIONS
    }
    if observed != required_names:
        fail("fault cell inventory differs from the canonical matrix")


def validate_positive_cells(
    receipt: dict[str, Any],
    expected_input: dict[str, Any],
    *,
    artifact_root: Path,
    stock_zstd: Path,
    budget: ReadBudget,
) -> None:
    with tempfile.TemporaryDirectory(
        prefix="visa-stock-zstd-independent-oracle-"
    ) as raw_work:
        work = Path(raw_work)
        canonical_input = work / "canonical-input.bin"
        write_canonical_input(canonical_input)
        if file_identity(canonical_input) != expected_input:
            fail("input identity differs from independently generated canonical input")

        control = exact_object(
            receipt["control"],
            {"cell", "oracle", "provider_status", "raw_artifacts", "topology"},
            "control",
        )
        if (
            control["cell"] != "uninterrupted-control"
            or control["topology"] != "single-process-no-checkpoint"
        ):
            fail("control cell identity or topology differs")
        control_oracle = validate_oracle(
            control["oracle"], "control.oracle", expected_input
        )
        control_status = validate_status(
            control["provider_status"],
            "control.provider_status",
            mode="active",
            epoch=1,
            barrier="open",
            effect_required=False,
        )
        if control_status["bytes_read"] != expected_input["size"]:
            fail("control did not consume the complete input")
        if control_status["bytes_written"] != control_oracle["compressed"]["size"]:
            fail("control provider/output byte counts differ")
        positive_int(
            control_status["completed_requests"], "control completed requests"
        )
        repeated_control, control_compressed_payload = validate_raw_artifacts(
            control["raw_artifacts"],
            label="control",
            cell="uninterrupted-control",
            expected_roles=("control",),
            expected_input=expected_input,
            artifact_root=artifact_root,
            budget=budget,
            stock_zstd=stock_zstd,
            canonical_input=canonical_input,
            work=work,
        )
        if repeated_control != control_oracle:
            fail("control inline oracle summary differs from retained raw artifacts")

        cells = receipt["migrated_cells"]
        if not isinstance(cells, list) or len(cells) != len(CUTS):
            fail("migrated_cells must contain exactly the two canonical cuts")
        checkpoint_digests = {
            validate_cell(
                raw,
                label,
                occurrence,
                expected_input,
                control,
                artifact_root=artifact_root,
                budget=budget,
                stock_zstd=stock_zstd,
                canonical_input=canonical_input,
                work=work,
                control_compressed_payload=control_compressed_payload,
            )
            for raw, (label, occurrence) in zip(cells, CUTS, strict=True)
        }
        if len(checkpoint_digests) != len(CUTS):
            fail("canonical cuts did not produce distinct compute checkpoints")


def validate_document(
    document: Any,
    expected_revision: str,
    *,
    artifact_root: Path,
    stock_zstd: Path,
) -> dict[str, Any]:
    receipt = exact_object(document, TOP_LEVEL_KEYS, "receipt")
    if receipt["schema"] != SCHEMA:
        fail("receipt schema differs")
    if not isinstance(expected_revision, str) or SHA1_RE.fullmatch(
        expected_revision
    ) is None:
        fail("expected_revision must be an exact lowercase 40-hex Git identity")
    revision = receipt["repository_revision"]
    if not isinstance(revision, str) or SHA1_RE.fullmatch(revision) is None:
        fail("repository_revision must be a lowercase 40-hex Git identity")
    if revision != expected_revision:
        fail("repository_revision differs from the expected exact SHA")
    validate_clean_snapshot(receipt["repository_source_snapshot"])
    for field in (
        "source_lock_sha256",
        "stock_zstd_build_receipt_sha256",
        "wanco_build_receipt_sha256",
    ):
        digest(receipt[field], field)
    if receipt["wanco_optimization"] != "-O1":
        fail("wanco_optimization must be -O1")
    exact_bool(
        receipt["zero_upstream_zstd_source_patches"],
        True,
        "zero_upstream_zstd_source_patches",
    )
    exact_bool(
        receipt["raw_oracle_artifacts_retained"],
        True,
        "raw_oracle_artifacts_retained",
    )
    exact_bool(
        receipt["raw_fault_artifacts_retained"],
        True,
        "raw_fault_artifacts_retained",
    )
    expected_input = identity(receipt["input"], "input")
    if expected_input["size"] != CANONICAL_INPUT_BYTES:
        fail("input must be the canonical 24 MiB workload")

    binding = exact_object(
        receipt["execution_input_binding"],
        {
            "stock_zstd_source_lock_sha256",
            "wanco_build_receipt_sha256",
            "wanco_image",
            "wanco_image_id",
            "wanco_runtime_sha256",
            "wanco_source_lock_sha256",
        },
        "execution_input_binding",
    )
    if binding["stock_zstd_source_lock_sha256"] != receipt["source_lock_sha256"]:
        fail("stock-zstd source lock cross-binding differs")
    if binding["wanco_build_receipt_sha256"] != receipt["wanco_build_receipt_sha256"]:
        fail("Wanco build receipt cross-binding differs")
    for field in (
        "stock_zstd_source_lock_sha256",
        "wanco_build_receipt_sha256",
        "wanco_runtime_sha256",
        "wanco_source_lock_sha256",
    ):
        digest(binding[field], f"execution_input_binding.{field}")
    if not isinstance(binding["wanco_image"], str) or not binding["wanco_image"]:
        fail("execution_input_binding.wanco_image must be nonempty")
    if (
        not isinstance(binding["wanco_image_id"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", binding["wanco_image_id"]) is None
    ):
        fail("execution_input_binding.wanco_image_id must be a Docker image digest")

    external = exact_object(
        receipt["external_oracle"], {"observation", "program"}, "external_oracle"
    )
    if external["observation"] != "decompress compressed bytes and compare raw SHA-256 and size":
        fail("external_oracle observation differs")
    program = exact_object(
        external["program"],
        {"package", "path", "sha256", "size", "version"},
        "external_oracle.program",
    )
    digest(program["sha256"], "external_oracle.program.sha256")
    positive_int(program["size"], "external_oracle.program.size")
    if not isinstance(program["path"], str) or not program["path"].startswith("/"):
        fail("external_oracle.program.path must be absolute")
    if not isinstance(program["version"], str) or "v1.5.7" not in program["version"]:
        fail("external_oracle program must identify native zstd v1.5.7")
    package = exact_object(program["package"], {"identity", "manager"}, "external_oracle.program.package")
    if package["manager"] not in {"rpm", "dpkg"} or not isinstance(package["identity"], str) or not package["identity"]:
        fail("external_oracle program has no RPM/dpkg identity")
    selected_stock_zstd = validate_stock_zstd_program(stock_zstd, program)
    if query_package_identity(selected_stock_zstd, package["manager"]) != package:
        fail("external_oracle program package identity differs from the verifier host")

    authority = exact_object(
        receipt["authority_model"],
        {
            "artifact_and_receipt_binding_verified",
            "external_authority_authenticity_verified",
            "mode",
        },
        "authority_model",
    )
    if authority["mode"] != "trusted-local-orchestration":
        fail("authority_model mode differs")
    exact_bool(authority["artifact_and_receipt_binding_verified"], True, "authority binding")
    exact_bool(authority["external_authority_authenticity_verified"], False, "external authority authenticity")

    raw_budget = ReadBudget(MAX_TOTAL_RAW_BYTES)
    validate_positive_cells(
        receipt,
        expected_input,
        artifact_root=artifact_root,
        stock_zstd=selected_stock_zstd,
        budget=raw_budget,
    )
    validate_faults(
        receipt["fault_cells"],
        artifact_root=artifact_root,
        budget=raw_budget,
    )

    checks = receipt["contract_checks"]
    if not isinstance(checks, list) or len(checks) != 1:
        fail("contract_checks must contain the activation ordering check")
    check = exact_object(
        checks[0], {"check", "rejected_by", "scope", "test_stdout_sha256"}, "contract check"
    )
    if check != {
        "check": "activation-before-canonical-commit-and-fence",
        "rejected_by": "visa_wasi_migration::Driver",
        "scope": "driver-contract-unit-test-not-live-e2e",
        "test_stdout_sha256": check["test_stdout_sha256"],
    }:
        fail("activation ordering contract check differs")
    digest(check["test_stdout_sha256"], "contract check test_stdout_sha256")
    return receipt


def load_and_validate(
    path: Path,
    expected_revision: str,
    stock_zstd: Path,
) -> dict[str, Any]:
    try:
        payload = read_bounded_file(path, "receipt", max_bytes=MAX_RECEIPT_BYTES)
    except ArtifactError as error:
        fail(str(error))
    document = parse_canonical_json(payload, "receipt")
    try:
        return validate_document(
            document,
            expected_revision,
            artifact_root=path.parent,
            stock_zstd=stock_zstd,
        )
    except ArtifactError as error:
        fail(str(error))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("receipt", type=Path)
    validate_parser.add_argument("--expected-revision", required=True)
    validate_parser.add_argument("--stock-zstd", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        receipt = load_and_validate(
            arguments.receipt,
            arguments.expected_revision,
            arguments.stock_zstd,
        )
    except (ArtifactError, OSError, ReceiptError) as error:
        print(f"stock-zstd matrix receipt invalid: {error}", file=sys.stderr)
        return 1
    print(
        "stock-zstd matrix receipt valid: "
        f"revision={receipt['repository_revision']} control=1 migrated=2 faults=10"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
