#!/usr/bin/env python3
"""Validate the compact stock-zstd transparent-migration receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn


SCHEMA = "visa-stock-zstd-transparent-migration-matrix-v3"
CANONICAL_INPUT_BYTES = 24 * 1024 * 1024
CUTS = (("cut-1", 8), ("cut-2", 64))
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
TOP_LEVEL_KEYS = {
    "authority_model",
    "contract_checks",
    "control",
    "execution_input_binding",
    "external_oracle",
    "fault_cells",
    "input",
    "large_artifacts_retained",
    "migrated_cells",
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
    "source_fenced_status",
    "source_frozen_status",
    "source_post_checkpoint_status",
    "topology",
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
    checkpoint = identity(cut["checkpoint"], f"{label}.checkpoint")
    positive_int(checkpoint["size"], f"{label}.checkpoint.size")
    return released, checkpoint


def validate_cell(
    value: Any,
    label: str,
    occurrence: int,
    expected_input: dict[str, Any],
    control: dict[str, Any],
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
    for field in ("bytes_read", "bytes_written", "completed_requests", "effects"):
        if active[field] != source_post[field]:
            fail(f"{label} destination prepare changed {field}")
    final = validate_status(
        cell["final_status"],
        f"{label}.final_status",
        mode="active",
        epoch=2,
        barrier="open",
        effect_required=False,
    )
    if (
        source_post["bytes_read"] >= expected_input["size"]
        or source_post["bytes_written"] >= control["oracle"]["compressed"]["size"]
        or source_post["completed_requests"] >= control["provider_status"]["completed_requests"]
    ):
        fail(f"{label} checkpoint is not mid-execution")
    if final["bytes_read"] != expected_input["size"]:
        fail(f"{label} did not consume the complete input")
    if final["bytes_written"] != control["oracle"]["compressed"]["size"]:
        fail(f"{label} did not produce the control output size")
    if final["completed_requests"] != control["provider_status"]["completed_requests"]:
        fail(f"{label} request frontier differs from the control")
    oracle = validate_oracle(cell["oracle"], f"{label}.oracle", expected_input)
    if oracle != control["oracle"]:
        fail(f"{label} external oracle differs from uninterrupted execution")
    return checkpoint["sha256"]


def validate_faults(value: Any) -> None:
    if not isinstance(value, list) or len(value) != len(CUTS) * 5:
        fail("fault_cells must contain exactly five faults per cut")
    expected = {
        "carrier-only-fresh-empty-provider": (
            "stock-zstd-filesystem-error-from-fresh-empty-provider",
            "end-to-end",
        ),
        "compute-checkpoint-tamper": (
            "migration-manifest-bound-file-digest",
            "manifest-verification-path",
        ),
        "provider-capsule-tamper": (
            "provider-capsule-state-digest",
            "provider-restore-path",
        ),
        "commit-fence-proof-pair-swap": (
            "canonical-fence-to-commit-binding",
            "canonical-proof-verification-path",
        ),
        "destination-guest-capability-spoof": (
            "guest-capability-admission-before-provider-mutation",
            "end-to-end",
        ),
    }
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
        if suffix not in expected:
            fail(f"fault cell has an unknown fault: {name}")
        detector, scope = expected[suffix]
        required = {"detector", "exit_status", "fault", "scope", "stderr_sha256", "stderr_tail"}
        if suffix == "carrier-only-fresh-empty-provider":
            required |= {"provider_before", "provider_after"}
        if suffix == "destination-guest-capability-spoof":
            required.add("provider_state_unchanged")
        exact_object(raw, required, f"fault {name}")
        if raw["detector"] != detector or raw["scope"] != scope:
            fail(f"fault {name} detector or scope differs")
        positive_int(raw["exit_status"], f"fault {name}.exit_status")
        digest(raw["stderr_sha256"], f"fault {name}.stderr_sha256")
        if not isinstance(raw["stderr_tail"], str) or not raw["stderr_tail"]:
            fail(f"fault {name}.stderr_tail must be nonempty")
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
        f"{cut}-{suffix}" for cut, _ in CUTS for suffix in expected
    }
    if observed != required_names:
        fail("fault cell inventory differs from the canonical matrix")


def validate_document(document: Any, expected_revision: str | None = None) -> dict[str, Any]:
    receipt = exact_object(document, TOP_LEVEL_KEYS, "receipt")
    if receipt["schema"] != SCHEMA:
        fail("receipt schema differs")
    revision = receipt["repository_revision"]
    if not isinstance(revision, str) or SHA1_RE.fullmatch(revision) is None:
        fail("repository_revision must be a lowercase 40-hex Git identity")
    if expected_revision is not None and revision != expected_revision:
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
    exact_bool(receipt["large_artifacts_retained"], False, "large_artifacts_retained")
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

    control = exact_object(
        receipt["control"], {"cell", "oracle", "provider_status", "topology"}, "control"
    )
    if control["cell"] != "uninterrupted-control" or control["topology"] != "single-process-no-checkpoint":
        fail("control cell identity or topology differs")
    control_oracle = validate_oracle(control["oracle"], "control.oracle", expected_input)
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
    positive_int(control_status["completed_requests"], "control completed requests")

    cells = receipt["migrated_cells"]
    if not isinstance(cells, list) or len(cells) != len(CUTS):
        fail("migrated_cells must contain exactly the two canonical cuts")
    checkpoint_digests = {
        validate_cell(raw, label, occurrence, expected_input, control)
        for raw, (label, occurrence) in zip(cells, CUTS, strict=True)
    }
    if len(checkpoint_digests) != len(CUTS):
        fail("canonical cuts did not produce distinct compute checkpoints")
    validate_faults(receipt["fault_cells"])

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


def load_and_validate(path: Path, expected_revision: str | None = None) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        fail(f"receipt is not a regular non-symlink file: {path}")
    payload = path.read_bytes()
    try:
        document = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse receipt: {error}")
    if payload != canonical_bytes(document) + b"\n":
        fail("receipt is not canonical sorted compact JSON with one trailing newline")
    return validate_document(document, expected_revision)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("receipt", type=Path)
    validate_parser.add_argument("--expected-revision")
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        receipt = load_and_validate(arguments.receipt, arguments.expected_revision)
    except (OSError, ReceiptError) as error:
        print(f"stock-zstd matrix receipt invalid: {error}", file=sys.stderr)
        return 1
    print(
        "stock-zstd matrix receipt valid: "
        f"revision={receipt['repository_revision']} control=1 migrated=2 faults=10"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
