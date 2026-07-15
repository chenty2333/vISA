#!/usr/bin/env python3
"""Verify a source-locked Nexus handoff-admission v2 Registry receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parent.parent

LOCK_SCHEMA = "visa.nexus-handoff-qualification-lock.v2"
EVIDENCE_STATUS = "same-boot-nexus-handoff-admission-only"
CLAIM_ID = "bounded-joint-handoff-refinement-v1"
NEXUS_ROLE = "nexus-local-handoff-admission-only"
RECEIPT_SCHEMA = "nexus.research.handoff-admission.v2"
SUMMARY_SCHEMA = "nexus.research.handoff-admission.summary.v2"
MATRIX_SCHEMA = "nexus.research.handoff-admission.fault-matrix.v1"
EXPECTED_REPOSITORY = "https://github.com/chenty2333/Nexus"
EXPECTED_COMMAND = "./x research handoff-admission"
EXPECTED_REGISTRY_SOURCE = "kernel/nexus-ostd/src/cser/effect_registry.rs"
EXPECTED_SUBSTRATE_SOURCE = "crates/cser-transition-gates/src/handoff.rs"

LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}")
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
FINAL_POPULATION = re.compile(
    r"([0-9][0-9,]*) states generated, "
    r"([0-9][0-9,]*) distinct states found, "
    r"([0-9][0-9,]*) states left on queue\."
)
FINAL_DEPTH = re.compile(
    r"The depth of the complete state graph search is ([0-9][0-9,]*)\."
)
RUST_TEST_MARKER = re.compile(r"test ([A-Za-z0-9_]+) \.\.\. ok")

MAX_LOCK_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_MATRIX_BYTES = 2 * 1024 * 1024
MAX_TLA_LOG_BYTES = 32 * 1024 * 1024
MAX_RUST_LOG_BYTES = 16 * 1024 * 1024
MAX_SUMMARY_BYTES = 256 * 1024
MAX_SOURCE_FILE_BYTES = 128 * 1024 * 1024

BOUNDARY_VALUES = {
    "same_boot_only": True,
    "crash_stop_only": True,
    "ownership_log_non_equivocation_in_tcb": True,
    "host_reboot_claimed": False,
    "malicious_rollback_claimed": False,
    "cryptographic_freshness_claimed": False,
    "production_registry_modified": True,
    "production_registry_refinement_checked": True,
    "joint_visa_execution_claimed": False,
    "real_ostd_smp_claimed": False,
    "canonical_v0_1_catalog_modified": False,
}


class QualificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise QualificationError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def reject_json_constant(value: str) -> None:
    fail(f"JSON contains non-finite number {value}")


def decode_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode {label}: {error}")


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        fail(
            f"{label} keys differ: missing={sorted(keys - actual)} "
            f"unknown={sorted(actual - keys)}"
        )
    return value


def exact_list(value: Any, label: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "a non-empty" if nonempty else "a"
        fail(f"{label} must be {qualifier} list")
    return value


def exact_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        fail(f"{label} must be a non-empty string without NUL")
    return value


def exact_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        fail(f"{label} must be a boolean")
    return value


def exact_uint(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or (positive and value == 0):
        qualifier = "positive" if positive else "non-negative"
        fail(f"{label} must be a {qualifier} integer")
    return value


def exact_sha(value: Any, pattern: re.Pattern[str], label: str) -> str:
    text = exact_string(value, label)
    if pattern.fullmatch(text) is None:
        fail(f"{label} must be an exact lowercase digest, got {text!r}")
    return text


def normalized_relative_path(value: Any, label: str) -> str:
    text = exact_string(value, label)
    if "\\" in text:
        fail(f"{label} must use POSIX separators")
    path = PurePosixPath(text)
    if path.is_absolute() or text != path.as_posix() or text in {".", ""}:
        fail(f"{label} must be a normalized relative path")
    if any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{label} escapes or is not normalized")
    return text


def canonical_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        metadata = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} must be a real directory, not a symlink")
    if resolved != absolute:
        fail(f"{label} path traverses a symlink: {path}")
    return absolute


def lexical_relative(root: Path, path: Path, label: str) -> str:
    candidate = path if path.is_absolute() else root / path
    absolute = Path(os.path.abspath(candidate))
    try:
        relative = absolute.relative_to(root)
    except ValueError:
        fail(f"{label} is outside {root}: {path}")
    return normalized_relative_path(relative.as_posix(), label)


def read_contained_regular(
    root: Path,
    relative: str,
    label: str,
    maximum: int,
) -> bytes:
    normalized = normalized_relative_path(relative, label)
    parts = PurePosixPath(normalized).parts
    flags = os.O_RDONLY | os.O_CLOEXEC
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = flags | os.O_DIRECTORY | nofollow
    descriptors: list[int] = []
    try:
        descriptor = os.open(root, directory_flags)
        descriptors.append(descriptor)
        for component in parts[:-1]:
            descriptor = os.open(
                component,
                directory_flags,
                dir_fd=descriptor,
            )
            descriptors.append(descriptor)
        file_descriptor = os.open(
            parts[-1],
            flags | nofollow,
            dir_fd=descriptor,
        )
        descriptors.append(file_descriptor)
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"{label} is not a regular file: {normalized}")
        if before.st_size > maximum:
            fail(f"{label} exceeds {maximum} bytes: {before.st_size}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            fail(f"{label} grew beyond {maximum} bytes while reading")
        after = os.fstat(file_descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after or len(raw) != after.st_size:
            fail(f"{label} changed while being read: {normalized}")
        return raw
    except OSError as error:
        fail(f"cannot read contained {label} {normalized}: {error}")
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(checkout: Path, arguments: list[str], label: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"cannot execute git for {label}: {error}")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        fail(f"git {label} failed with {result.returncode}: {detail}")
    return result.stdout


def canonical_repository(value: str) -> str:
    text = value.removesuffix(".git").rstrip("/")
    if text == "git@github.com:chenty2333/Nexus":
        return EXPECTED_REPOSITORY
    if text == "ssh://git@github.com/chenty2333/Nexus":
        return EXPECTED_REPOSITORY
    return text


def inspect_checkout(
    checkout: Path,
    expected_revision: str,
    analyzed_baseline_revision: str,
) -> tuple[str, str]:
    top = git(checkout, ["rev-parse", "--show-toplevel"], "show-toplevel")
    try:
        top_path = Path(top.decode("utf-8").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as error:
        fail(f"cannot decode Nexus repository root: {error}")
    if top_path != checkout:
        fail(f"--checkout is not the exact Nexus worktree root: {top_path}")

    revision = git(
        checkout,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        "rev-parse HEAD",
    ).decode("ascii", errors="strict").strip()
    if LOWER_GIT_SHA.fullmatch(revision) is None or revision != expected_revision:
        fail(
            "Nexus checkout HEAD differs from the qualification lock: "
            f"expected={expected_revision} actual={revision}"
        )
    git(
        checkout,
        ["merge-base", "--is-ancestor", analyzed_baseline_revision, expected_revision],
        "analyzed baseline ancestry",
    )
    if git(
        checkout,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        "status",
    ):
        fail("Nexus checkout is dirty; exact-SHA qualification requires clean state")
    origin = git(checkout, ["remote", "get-url", "origin"], "origin URL")
    try:
        repository = canonical_repository(origin.decode("utf-8").strip())
    except UnicodeDecodeError as error:
        fail(f"cannot decode Nexus origin URL: {error}")
    if repository != EXPECTED_REPOSITORY:
        fail(f"Nexus origin is not the locked repository: {repository!r}")
    return revision, repository


def dynamic_artifact_lock(value: Any, label: str) -> dict[str, str]:
    item = exact_object(value, {"path"}, label)
    return {"path": normalized_relative_path(item["path"], f"{label}.path")}


def static_artifact_lock(value: Any, label: str) -> dict[str, str]:
    item = exact_object(value, {"path", "sha256"}, label)
    return {
        "path": normalized_relative_path(item["path"], f"{label}.path"),
        "sha256": exact_sha(item["sha256"], LOWER_SHA256, f"{label}.sha256"),
    }


def string_list(value: Any, label: str, *, nonempty: bool = True) -> list[str]:
    items = exact_list(value, label, nonempty=nonempty)
    result = [exact_string(item, f"{label}[{index}]") for index, item in enumerate(items)]
    if len(set(result)) != len(result):
        fail(f"{label} contains duplicate values")
    return result


def validate_lock(document: Any) -> dict[str, Any]:
    lock = exact_object(
        document,
        {
            "schema",
            "evidence_status",
            "claim_id",
            "nexus",
            "artifacts",
            "fault_contract",
            "formal",
            "rust_oracle",
            "production_registry",
            "boundaries",
        },
        "qualification lock",
    )
    if lock["schema"] != LOCK_SCHEMA or lock["evidence_status"] != EVIDENCE_STATUS:
        fail("qualification lock schema or evidence_status is not the strict same-boot profile")
    if lock["claim_id"] != CLAIM_ID:
        fail(f"qualification lock.claim_id must be {CLAIM_ID}")

    nexus = exact_object(
        lock["nexus"],
        {
            "repository",
            "revision",
            "analyzed_baseline_revision",
            "role",
            "receipt_schema",
            "summary_schema",
            "command",
            "prospective",
            "source_fingerprint",
            "source_files",
        },
        "qualification lock.nexus",
    )
    if nexus["repository"] != EXPECTED_REPOSITORY:
        fail(f"qualification lock.nexus.repository must be {EXPECTED_REPOSITORY}")
    nexus["revision"] = exact_sha(
        nexus["revision"], LOWER_GIT_SHA, "qualification lock.nexus.revision"
    )
    nexus["analyzed_baseline_revision"] = exact_sha(
        nexus["analyzed_baseline_revision"],
        LOWER_GIT_SHA,
        "qualification lock.nexus.analyzed_baseline_revision",
    )
    if nexus["role"] != NEXUS_ROLE:
        fail(f"qualification lock.nexus.role must be {NEXUS_ROLE}")
    if nexus["receipt_schema"] != RECEIPT_SCHEMA:
        fail(f"qualification lock.nexus.receipt_schema must be {RECEIPT_SCHEMA}")
    if nexus["summary_schema"] != SUMMARY_SCHEMA:
        fail(f"qualification lock.nexus.summary_schema must be {SUMMARY_SCHEMA}")
    if nexus["command"] != EXPECTED_COMMAND:
        fail(f"qualification lock.nexus.command must be {EXPECTED_COMMAND}")
    if not exact_bool(nexus["prospective"], "qualification lock.nexus.prospective"):
        fail("qualification lock.nexus.prospective must remain true")
    nexus["source_fingerprint"] = exact_sha(
        nexus["source_fingerprint"],
        LOWER_SHA256,
        "qualification lock.nexus.source_fingerprint",
    )
    source_files = exact_list(
        nexus["source_files"], "qualification lock.nexus.source_files", nonempty=True
    )
    nexus["source_files"] = [
        normalized_relative_path(item, f"qualification lock.nexus.source_files[{index}]")
        for index, item in enumerate(source_files)
    ]
    if len(set(nexus["source_files"])) != len(nexus["source_files"]):
        fail("qualification lock.nexus.source_files contains duplicates")

    artifacts = exact_object(
        lock["artifacts"],
        {"receipt", "matrix", "tla_log", "rust_oracle_log", "summary"},
        "qualification lock.artifacts",
    )
    artifacts["matrix"] = static_artifact_lock(
        artifacts["matrix"], "qualification lock.artifacts.matrix"
    )
    for name in ["receipt", "tla_log", "rust_oracle_log", "summary"]:
        artifacts[name] = dynamic_artifact_lock(
            artifacts[name], f"qualification lock.artifacts.{name}"
        )
    artifact_paths = [item["path"] for item in artifacts.values()]
    if len(set(artifact_paths)) != len(artifact_paths):
        fail("qualification lock artifact paths must be distinct")
    if artifacts["matrix"]["path"] not in nexus["source_files"]:
        fail("the static fault matrix must be included in the source fingerprint")

    fault = exact_object(
        lock["fault_contract"],
        {
            "matrix_schema",
            "profile",
            "cells",
            "required_invariants",
            "negative_mutations",
            "fault_model",
            "ownership_log_tcb",
        },
        "qualification lock.fault_contract",
    )
    if fault["matrix_schema"] != MATRIX_SCHEMA:
        fail(f"qualification lock fault matrix schema must be {MATRIX_SCHEMA}")
    fault["profile"] = normalized_relative_path(
        fault["profile"], "qualification lock.fault_contract.profile"
    )
    fault["cells"] = exact_uint(
        fault["cells"], "qualification lock.fault_contract.cells", positive=True
    )
    fault["required_invariants"] = string_list(
        fault["required_invariants"],
        "qualification lock.fault_contract.required_invariants",
    )
    fault["negative_mutations"] = string_list(
        fault["negative_mutations"],
        "qualification lock.fault_contract.negative_mutations",
    )
    exact_string(fault["fault_model"], "qualification lock.fault_contract.fault_model")
    exact_string(
        fault["ownership_log_tcb"],
        "qualification lock.fault_contract.ownership_log_tcb",
    )
    if fault["fault_model"] != "same-boot-crash-stop-retry-reorder-lost-ack":
        fail("qualification lock widens the same-boot crash-stop fault model")
    if fault["ownership_log_tcb"] != "trusted-non-equivocating-no-rollback-tcb":
        fail("qualification lock weakens the ownership-log TCB declaration")

    formal = exact_object(
        lock["formal"],
        {
            "specification",
            "declarative_tla",
            "temporal_properties",
            "configurations",
            "witnesses",
        },
        "qualification lock.formal",
    )
    formal["specification"] = exact_string(
        formal["specification"], "qualification lock.formal.specification"
    )
    if not exact_bool(formal["declarative_tla"], "qualification lock.formal.declarative_tla"):
        fail("qualification lock must require declarative_tla=true")
    formal["temporal_properties"] = exact_uint(
        formal["temporal_properties"],
        "qualification lock.formal.temporal_properties",
        positive=True,
    )
    configurations = exact_list(
        formal["configurations"],
        "qualification lock.formal.configurations",
        nonempty=True,
    )
    if len(configurations) != 2:
        fail("qualification lock must contain exactly safety and progress configurations")
    normalized_configurations: list[dict[str, Any]] = []
    for index, value in enumerate(configurations):
        label = f"qualification lock.formal.configurations[{index}]"
        configuration = exact_object(
            value,
            {
                "config",
                "heading",
                "generated",
                "distinct",
                "depth",
                "states_left_on_queue",
                "property_mode",
                "temporal_branches",
            },
            label,
        )
        for field in ["config", "heading", "property_mode"]:
            configuration[field] = exact_string(
                configuration[field], f"{label}.{field}"
            )
        for field in [
            "generated",
            "distinct",
            "depth",
            "states_left_on_queue",
            "temporal_branches",
        ]:
            configuration[field] = exact_uint(
                configuration[field],
                f"{label}.{field}",
                positive=field in {"generated", "distinct", "depth"},
            )
        if configuration["states_left_on_queue"] != 0:
            fail(f"{label} must finish with zero queued states")
        normalized_configurations.append(configuration)
    if normalized_configurations[0]["temporal_branches"] != 0:
        fail("the safety configuration must not claim temporal branches")
    if normalized_configurations[1]["temporal_branches"] != formal["temporal_properties"]:
        fail("the progress configuration must bind every temporal property branch")
    formal["configurations"] = normalized_configurations

    witnesses = exact_list(
        formal["witnesses"], "qualification lock.formal.witnesses", nonempty=True
    )
    normalized_witnesses: list[dict[str, str]] = []
    for index, value in enumerate(witnesses):
        label = f"qualification lock.formal.witnesses[{index}]"
        witness = exact_object(value, {"invariant", "description"}, label)
        normalized_witnesses.append(
            {
                "invariant": exact_string(witness["invariant"], f"{label}.invariant"),
                "description": exact_string(
                    witness["description"], f"{label}.description"
                ),
            }
        )
    if len(normalized_witnesses) != fault["cells"]:
        fail("qualification lock must map one witness to every fault cell")
    if len({item["invariant"] for item in normalized_witnesses}) != len(
        normalized_witnesses
    ):
        fail("qualification lock.formal.witnesses contains duplicate invariants")
    formal["witnesses"] = normalized_witnesses

    rust = exact_object(
        lock["rust_oracle"],
        {"independent_from_production_registry", "suites"},
        "qualification lock.rust_oracle",
    )
    if not exact_bool(
        rust["independent_from_production_registry"],
        "qualification lock.rust_oracle.independent_from_production_registry",
    ):
        fail("qualification lock must require an independent Rust oracle")
    suites = exact_list(
        rust["suites"], "qualification lock.rust_oracle.suites", nonempty=True
    )
    normalized_suites: list[dict[str, Any]] = []
    for index, value in enumerate(suites):
        label = f"qualification lock.rust_oracle.suites[{index}]"
        suite = exact_object(value, {"kind", "heading", "tests"}, label)
        normalized_suites.append(
            {
                "kind": exact_string(suite["kind"], f"{label}.kind"),
                "heading": exact_string(suite["heading"], f"{label}.heading"),
                "tests": string_list(suite["tests"], f"{label}.tests"),
            }
        )
    if [suite["kind"] for suite in normalized_suites] != [
        "sequence",
        "property",
        "loom",
    ]:
        fail("qualification lock must retain sequence, property, and loom suites in order")
    all_tests = [test for suite in normalized_suites for test in suite["tests"]]
    if len(set(all_tests)) != len(all_tests):
        fail("qualification lock Rust oracle contains duplicate test names")
    if len(normalized_suites[0]["tests"]) != fault["cells"]:
        fail("qualification lock must map one sequence test to every fault cell")
    rust["suites"] = normalized_suites

    production = exact_object(
        lock["production_registry"],
        {
            "registry_source",
            "substrate_source",
            "handoff_index_owned_by_registry",
            "admission_and_publication_share_registry_lock",
            "commit_close_reuses_revoke_lifecycle",
            "local_fault_cells_mapped",
            "external_intent_only_cells",
            "real_ostd_execution_claimed",
            "suites",
        },
        "qualification lock.production_registry",
    )
    for field, expected in [
        ("registry_source", EXPECTED_REGISTRY_SOURCE),
        ("substrate_source", EXPECTED_SUBSTRATE_SOURCE),
    ]:
        production[field] = normalized_relative_path(
            production[field], f"qualification lock.production_registry.{field}"
        )
        if production[field] != expected:
            fail(f"qualification lock.production_registry.{field} must be {expected}")
        if production[field] not in nexus["source_files"]:
            fail(
                f"qualification lock.production_registry.{field} must be source-fingerprint bound"
            )
    for field in [
        "handoff_index_owned_by_registry",
        "admission_and_publication_share_registry_lock",
        "commit_close_reuses_revoke_lifecycle",
    ]:
        if not exact_bool(
            production[field], f"qualification lock.production_registry.{field}"
        ):
            fail(f"qualification lock.production_registry.{field} must be true")
    production["local_fault_cells_mapped"] = exact_uint(
        production["local_fault_cells_mapped"],
        "qualification lock.production_registry.local_fault_cells_mapped",
    )
    production["external_intent_only_cells"] = exact_uint(
        production["external_intent_only_cells"],
        "qualification lock.production_registry.external_intent_only_cells",
        positive=True,
    )
    if production["external_intent_only_cells"] != 1 or (
        production["local_fault_cells_mapped"]
        + production["external_intent_only_cells"]
        != fault["cells"]
    ):
        fail(
            "qualification lock production Registry cell mapping must bind one "
            "external-intent-only cell and every remaining local fault cell"
        )
    if exact_bool(
        production["real_ostd_execution_claimed"],
        "qualification lock.production_registry.real_ostd_execution_claimed",
    ):
        fail("qualification lock must not claim real ostd execution")

    production_suites = exact_list(
        production["suites"],
        "qualification lock.production_registry.suites",
        nonempty=True,
    )
    normalized_production_suites: list[dict[str, Any]] = []
    for index, value in enumerate(production_suites):
        label = f"qualification lock.production_registry.suites[{index}]"
        suite = exact_object(value, {"kind", "heading", "tests"}, label)
        normalized_production_suites.append(
            {
                "kind": exact_string(suite["kind"], f"{label}.kind"),
                "heading": exact_string(suite["heading"], f"{label}.heading"),
                "tests": string_list(suite["tests"], f"{label}.tests"),
            }
        )
    if [suite["kind"] for suite in normalized_production_suites] != [
        "substrate_loom",
        "registry_sequence",
    ]:
        fail(
            "qualification lock must retain substrate Loom and production Registry "
            "sequence suites in order"
        )
    production_tests = [
        test for suite in normalized_production_suites for test in suite["tests"]
    ]
    if len(set([*all_tests, *production_tests])) != len(all_tests) + len(
        production_tests
    ):
        fail("qualification lock contains duplicate Rust refinement test names")
    production["suites"] = normalized_production_suites

    boundaries = exact_object(
        lock["boundaries"], set(BOUNDARY_VALUES), "qualification lock.boundaries"
    )
    for key, expected in BOUNDARY_VALUES.items():
        actual = exact_bool(boundaries[key], f"qualification lock.boundaries.{key}")
        if actual is not expected:
            fail(f"qualification lock boundary {key} must be {str(expected).lower()}")

    return lock


def compute_source_fingerprint(checkout: Path, source_files: list[str]) -> str:
    digest = hashlib.sha256()
    for relative in source_files:
        tracked = git(
            checkout,
            ["ls-files", "--error-unmatch", "--", relative],
            f"source tracking for {relative}",
        )
        tracked_paths = tracked.decode("utf-8", errors="strict").splitlines()
        if tracked_paths != [relative]:
            fail(f"source fingerprint input is not one exact tracked path: {relative}")
        raw = read_contained_regular(
            checkout,
            relative,
            f"source fingerprint input {relative}",
            MAX_SOURCE_FILE_BYTES,
        )
        encoded_path = relative.encode("utf-8")
        digest.update(struct.pack("<Q", len(encoded_path)))
        digest.update(encoded_path)
        digest.update(struct.pack("<Q", len(raw)))
        digest.update(raw)
    return digest.hexdigest()


def validate_digest(raw: bytes, expected: str, label: str) -> None:
    actual = sha256(raw)
    if actual != expected:
        fail(f"{label} digest differs: expected={expected} actual={actual}")


def parse_matrix(raw: bytes, lock: dict[str, Any]) -> dict[str, Any]:
    try:
        matrix = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot decode Nexus handoff fault matrix: {error}")
    matrix = exact_object(
        matrix,
        {
            "schema",
            "profile",
            "expected_count",
            "fault_model",
            "ownership_log",
            "host_reboot_claimed",
            "malicious_rollback_claimed",
            "production_registry_modified",
            "required_invariants",
            "negative_mutations",
            "cell",
        },
        "fault matrix",
    )
    fault = lock["fault_contract"]
    expected_scalars = {
        "schema": fault["matrix_schema"],
        "profile": fault["profile"],
        "expected_count": fault["cells"],
        "fault_model": fault["fault_model"],
        "ownership_log": fault["ownership_log_tcb"],
        "host_reboot_claimed": False,
        "malicious_rollback_claimed": False,
        # The v1 matrix retains the independent first-round model boundary;
        # the v2 receipt separately binds the production Registry refinement.
        "production_registry_modified": False,
    }
    for key, expected in expected_scalars.items():
        if type(matrix[key]) is not type(expected) or matrix[key] != expected:
            fail(f"fault matrix {key} differs from the qualification lock")
    if matrix["required_invariants"] != fault["required_invariants"]:
        fail("fault matrix required_invariants differ from the qualification lock")
    if matrix["negative_mutations"] != fault["negative_mutations"]:
        fail("fault matrix negative_mutations differ from the qualification lock")
    cells = exact_list(matrix["cell"], "fault matrix.cell", nonempty=True)
    if len(cells) != fault["cells"]:
        fail("fault matrix cell count differs from the qualification lock")
    normalized_cells: list[dict[str, Any]] = []
    for index, value in enumerate(cells):
        label = f"fault matrix.cell[{index}]"
        cell = exact_object(
            value,
            {"id", "event_order", "expected", "tla_witness", "rust_test", "kill_condition"},
            label,
        )
        normalized_cells.append(
            {
                "id": exact_string(cell["id"], f"{label}.id"),
                "event_order": string_list(cell["event_order"], f"{label}.event_order"),
                "expected": exact_string(cell["expected"], f"{label}.expected"),
                "tla_witness": exact_string(cell["tla_witness"], f"{label}.tla_witness"),
                "rust_test": exact_string(cell["rust_test"], f"{label}.rust_test"),
                "kill_condition": exact_string(
                    cell["kill_condition"], f"{label}.kill_condition"
                ),
            }
        )
    if len({cell["id"] for cell in normalized_cells}) != len(normalized_cells):
        fail("fault matrix contains duplicate cell ids")
    if [cell["tla_witness"] for cell in normalized_cells] != [
        witness["invariant"] for witness in lock["formal"]["witnesses"]
    ]:
        fail("fault matrix does not map one-to-one to the locked TLA witnesses")
    if [cell["rust_test"] for cell in normalized_cells] != lock["rust_oracle"][
        "suites"
    ][0]["tests"]:
        fail("fault matrix does not map one-to-one to the locked sequence tests")
    matrix["cell"] = normalized_cells
    return matrix


def parse_uint_text(value: str, label: str) -> int:
    try:
        return int(value.replace(",", ""))
    except ValueError:
        fail(f"{label} is not an integer: {value!r}")


def graph_stats(block: list[str], label: str) -> dict[str, int]:
    populations = [FINAL_POPULATION.fullmatch(line) for line in block]
    populations = [match for match in populations if match is not None]
    depths = [FINAL_DEPTH.fullmatch(line) for line in block]
    depths = [match for match in depths if match is not None]
    if len(populations) != 1 or len(depths) != 1:
        fail(f"{label} must contain one exact final population and depth")
    population = populations[0]
    depth = depths[0]
    return {
        "generated": parse_uint_text(population.group(1), f"{label}.generated"),
        "distinct": parse_uint_text(population.group(2), f"{label}.distinct"),
        "states_left_on_queue": parse_uint_text(
            population.group(3), f"{label}.states_left_on_queue"
        ),
        "depth": parse_uint_text(depth.group(1), f"{label}.depth"),
    }


def parse_tla_log(raw: bytes, lock: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        fail(f"TLA log is not UTF-8: {error}")
    formal = lock["formal"]
    specification = formal["specification"]
    configurations = formal["configurations"]
    witnesses = formal["witnesses"]
    expected_headings = [f"==> {configurations[0]['heading']}"]
    expected_headings.extend(
        f"==> {specification} reachability: {witness['description']}"
        for witness in witnesses
    )
    expected_headings.append(f"==> {configurations[1]['heading']}")
    actual_headings = [
        line for line in lines if line.startswith(f"==> {specification} ")
    ]
    if actual_headings != expected_headings:
        fail("TLA log section population or order differs from the qualification lock")

    completion = "Model checking completed. No error has been found."
    if lines.count(completion) != len(configurations):
        fail("TLA log lacks the exact complete-graph marker count")
    expected_coverage = [
        f"COVERAGE_RESULT PASS {witness['description']}" for witness in witnesses
    ]
    actual_coverage = [line for line in lines if line.startswith("COVERAGE_RESULT ")]
    if actual_coverage != expected_coverage:
        fail("TLA log reachability witness markers differ from the qualification lock")
    expected_errors: list[str] = []
    for witness in witnesses:
        expected_errors.extend(
            [
                f"Error: Invariant {witness['invariant']} is violated.",
                "Error: The behavior up to this point is:",
            ]
        )
    actual_errors = [line for line in lines if line.startswith("Error:")]
    if actual_errors != expected_errors:
        fail("TLA log contains a missing, reordered, or unexpected error marker")
    for witness in witnesses:
        marker = f"Invariant {witness['invariant']} is violated"
        if sum(marker in line for line in lines) != 1:
            fail(f"TLA witness {witness['invariant']} lacks one exact violation marker")

    first_heading = expected_headings[0]
    progress_heading = expected_headings[-1]
    first_start = lines.index(first_heading)
    witness_start = lines.index(expected_headings[1])
    progress_start = lines.index(progress_heading)
    blocks = [lines[first_start:witness_start], lines[progress_start:]]
    observed: list[dict[str, Any]] = []
    for index, (configuration, block) in enumerate(zip(configurations, blocks)):
        label = f"TLA configuration {configuration['config']}"
        stats = graph_stats(block, label)
        expected_stats = {
            field: configuration[field]
            for field in ["generated", "distinct", "states_left_on_queue", "depth"]
        }
        if stats != expected_stats:
            fail(f"{label} graph statistics differ: expected={expected_stats} actual={stats}")
        if block.count(completion) != 1:
            fail(f"{label} lacks one complete graph marker")
        temporal_markers = [
            line
            for line in block
            if line.startswith("Implied-temporal checking--satisfiability problem has ")
        ]
        branches = configuration["temporal_branches"]
        if branches == 0:
            if temporal_markers:
                fail(f"{label} unexpectedly contains temporal checking")
        else:
            expected_marker = (
                "Implied-temporal checking--satisfiability problem has "
                f"{branches} branches."
            )
            if temporal_markers != [expected_marker]:
                fail(f"{label} lacks the exact temporal branch marker")
        observed.append(stats)
        if index == 0 and progress_start <= witness_start:
            fail("TLA progress graph is not ordered after every witness")
    return observed


def parse_rust_log(raw: bytes, lock: dict[str, Any]) -> None:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        fail(f"Rust oracle log is not UTF-8: {error}")
    suites = [
        *lock["rust_oracle"]["suites"],
        *lock["production_registry"]["suites"],
    ]
    headings = [
        (index, line)
        for index, line in enumerate(lines)
        if line.startswith("==> handoff-admission ")
    ]
    if [line for _, line in headings] != [suite["heading"] for suite in suites]:
        fail("Rust oracle suite population or order differs from the qualification lock")
    for index, suite in enumerate(suites):
        start = headings[index][0]
        end = headings[index + 1][0] if index + 1 < len(headings) else len(lines)
        block = lines[start:end]
        observed_tests = [
            match.group(1)
            for line in block
            if (match := RUST_TEST_MARKER.fullmatch(line)) is not None
        ]
        exact_test_lines = [
            line
            for line in block
            if line.startswith("test ") and not line.startswith("test result:")
        ]
        if set(exact_test_lines) != {
            f"test {test} ... ok" for test in suite["tests"]
        } or len(exact_test_lines) != len(suite["tests"]):
            fail(f"Rust {suite['kind']} suite contains an unexpected test result marker")
        if len(observed_tests) != len(set(observed_tests)):
            fail(f"Rust {suite['kind']} suite contains duplicate pass markers")
        if set(observed_tests) != set(suite["tests"]):
            fail(
                f"Rust {suite['kind']} exact test markers differ: "
                f"expected={sorted(suite['tests'])} actual={sorted(observed_tests)}"
            )
        count = len(suite["tests"])
        if block.count(f"running {count} tests") != 1:
            fail(f"Rust {suite['kind']} suite lacks the exact running count")
        result_prefix = (
            f"test result: ok. {count} passed; 0 failed; 0 ignored; "
            "0 measured; 0 filtered out;"
        )
        if sum(line.startswith(result_prefix) for line in block) != 1:
            fail(f"Rust {suite['kind']} suite lacks the exact pass result")


SUMMARY_KEYS = {
    "schema",
    "status",
    "prospective",
    "command",
    "revision",
    "worktree_dirty",
    "source_fingerprint",
    "fault_cells",
    "required_invariants",
    "negative_mutations",
    "complete_configurations",
    "reachability_witnesses",
    "temporal_properties",
    "rust_sequence_tests",
    "rust_property_tests",
    "rust_loom_tests",
    "production_registry_sequence_tests",
    "production_registry_loom_tests",
    "same_boot_only",
    "ownership_log_non_equivocation_in_tcb",
    "production_registry_modified",
    "production_registry_refinement_checked",
    "host_reboot_claimed",
    "malicious_rollback_claimed",
    "joint_visa_execution_claimed",
    "real_ostd_smp_claimed",
    "canonical_v0_1_catalog_modified",
    "receipt",
}


def parse_summary(raw: bytes, lock: dict[str, Any]) -> None:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        fail(f"summary is not UTF-8: {error}")
    values: dict[str, str] = {}
    for index, line in enumerate(lines, start=1):
        if not line or "=" not in line:
            fail(f"summary line {index} is not one key=value record")
        key, value = line.split("=", 1)
        if key in values:
            fail(f"summary contains duplicate key {key!r}")
        values[key] = value
    if set(values) != SUMMARY_KEYS:
        fail(
            f"summary keys differ: missing={sorted(SUMMARY_KEYS - set(values))} "
            f"unknown={sorted(set(values) - SUMMARY_KEYS)}"
        )
    fault = lock["fault_contract"]
    formal = lock["formal"]
    suites = lock["rust_oracle"]["suites"]
    production_suites = lock["production_registry"]["suites"]
    expected = {
        "schema": lock["nexus"]["summary_schema"],
        "status": "passed",
        "prospective": str(lock["nexus"]["prospective"]).lower(),
        "command": lock["nexus"]["command"],
        "revision": lock["nexus"]["revision"],
        "worktree_dirty": "false",
        "source_fingerprint": lock["nexus"]["source_fingerprint"],
        "fault_cells": str(fault["cells"]),
        "required_invariants": str(len(fault["required_invariants"])),
        "negative_mutations": str(len(fault["negative_mutations"])),
        "complete_configurations": str(len(formal["configurations"])),
        "reachability_witnesses": str(len(formal["witnesses"])),
        "temporal_properties": str(formal["temporal_properties"]),
        "rust_sequence_tests": str(len(suites[0]["tests"])),
        "rust_property_tests": str(len(suites[1]["tests"])),
        "rust_loom_tests": str(len(suites[2]["tests"])),
        "production_registry_sequence_tests": str(
            len(production_suites[1]["tests"])
        ),
        "production_registry_loom_tests": str(len(production_suites[0]["tests"])),
        "same_boot_only": "true",
        "ownership_log_non_equivocation_in_tcb": "true",
        "production_registry_modified": "true",
        "production_registry_refinement_checked": "true",
        "host_reboot_claimed": "false",
        "malicious_rollback_claimed": "false",
        "joint_visa_execution_claimed": "false",
        "real_ostd_smp_claimed": "false",
        "canonical_v0_1_catalog_modified": "false",
        "receipt": lock["artifacts"]["receipt"]["path"],
    }
    if values != expected:
        differences = [
            f"{key}: expected={expected[key]!r} actual={values.get(key)!r}"
            for key in sorted(expected)
            if values.get(key) != expected[key]
        ]
        fail("summary values differ from independent expectations: " + "; ".join(differences))


def validate_receipt(
    document: Any,
    lock: dict[str, Any],
    matrix: dict[str, Any],
    observed_digests: dict[str, str],
) -> None:
    receipt = exact_object(
        document,
        {
            "schema",
            "status",
            "prospective",
            "command",
            "revision",
            "worktree_dirty",
            "source_fingerprint",
            "source_files",
            "generated_unix_seconds",
            "fault_contract",
            "formal",
            "rust_oracle",
            "production_registry",
            "boundaries",
            "logs",
            "digests",
        },
        "Nexus handoff receipt",
    )
    nexus = lock["nexus"]
    scalar_expectations = {
        "schema": nexus["receipt_schema"],
        "status": "passed",
        "prospective": nexus["prospective"],
        "command": nexus["command"],
        "revision": nexus["revision"],
        "worktree_dirty": False,
        "source_fingerprint": nexus["source_fingerprint"],
        "source_files": nexus["source_files"],
    }
    for key, expected in scalar_expectations.items():
        if type(receipt[key]) is not type(expected) or receipt[key] != expected:
            fail(f"Nexus handoff receipt {key} differs from the qualification lock")
    if receipt["prospective"] is not True:
        fail("Nexus handoff receipt prospective must remain true")
    exact_uint(
        receipt["generated_unix_seconds"],
        "Nexus handoff receipt.generated_unix_seconds",
        positive=True,
    )

    fault = exact_object(
        receipt["fault_contract"],
        {
            "matrix",
            "matrix_sha256",
            "cells",
            "invariants",
            "negative_mutations",
            "fault_model",
            "ownership_log_tcb",
        },
        "Nexus handoff receipt.fault_contract",
    )
    expected_fault = {
        "matrix": lock["artifacts"]["matrix"]["path"],
        "matrix_sha256": lock["artifacts"]["matrix"]["sha256"],
        "cells": lock["fault_contract"]["cells"],
        "invariants": len(lock["fault_contract"]["required_invariants"]),
        "negative_mutations": len(lock["fault_contract"]["negative_mutations"]),
        "fault_model": lock["fault_contract"]["fault_model"],
        "ownership_log_tcb": lock["fault_contract"]["ownership_log_tcb"],
    }
    if fault != expected_fault:
        fail("Nexus handoff receipt fault_contract differs from independent matrix evidence")
    if len(matrix["cell"]) != fault["cells"]:
        fail("Nexus handoff receipt cell count differs from parsed matrix")

    formal_receipt = exact_object(
        receipt["formal"],
        {
            "specification",
            "declarative_tla",
            "complete_configurations",
            "configurations",
            "reachability_witnesses",
            "witnesses",
            "temporal_properties",
        },
        "Nexus handoff receipt.formal",
    )
    formal_lock = lock["formal"]
    expected_formal_scalars = {
        "specification": formal_lock["specification"],
        "declarative_tla": formal_lock["declarative_tla"],
        "complete_configurations": len(formal_lock["configurations"]),
        "reachability_witnesses": len(formal_lock["witnesses"]),
        "temporal_properties": formal_lock["temporal_properties"],
    }
    for key, expected in expected_formal_scalars.items():
        if type(formal_receipt[key]) is not type(expected) or formal_receipt[key] != expected:
            fail(f"Nexus handoff receipt.formal.{key} differs from the lock")
    receipt_configurations = exact_list(
        formal_receipt["configurations"],
        "Nexus handoff receipt.formal.configurations",
    )
    if len(receipt_configurations) != len(formal_lock["configurations"]):
        fail("Nexus handoff receipt formal configuration count differs")
    for index, (actual, expected) in enumerate(
        zip(receipt_configurations, formal_lock["configurations"])
    ):
        item = exact_object(
            actual,
            {
                "config",
                "status",
                "generated",
                "distinct",
                "depth",
                "states_left_on_queue",
                "property_mode",
            },
            f"Nexus handoff receipt.formal.configurations[{index}]",
        )
        expected_item = {
            key: expected[key]
            for key in [
                "config",
                "generated",
                "distinct",
                "depth",
                "states_left_on_queue",
                "property_mode",
            ]
        }
        expected_item["status"] = "complete"
        if item != expected_item:
            fail(f"Nexus handoff receipt formal configuration {index} differs")
    receipt_witnesses = exact_list(
        formal_receipt["witnesses"], "Nexus handoff receipt.formal.witnesses"
    )
    expected_witnesses = [
        {**witness, "status": "reachable"} for witness in formal_lock["witnesses"]
    ]
    for index, witness in enumerate(receipt_witnesses):
        exact_object(
            witness,
            {"invariant", "description", "status"},
            f"Nexus handoff receipt.formal.witnesses[{index}]",
        )
    if receipt_witnesses != expected_witnesses:
        fail("Nexus handoff receipt witnesses differ from the qualification lock")

    rust_receipt = exact_object(
        receipt["rust_oracle"],
        {
            "independent_from_production_registry",
            "sequence_tests",
            "property_tests",
            "loom_tests",
            "total_tests",
        },
        "Nexus handoff receipt.rust_oracle",
    )
    suites = lock["rust_oracle"]["suites"]
    expected_rust = {
        "independent_from_production_registry": True,
        "sequence_tests": len(suites[0]["tests"]),
        "property_tests": len(suites[1]["tests"]),
        "loom_tests": len(suites[2]["tests"]),
        "total_tests": sum(len(suite["tests"]) for suite in suites),
    }
    if rust_receipt != expected_rust:
        fail("Nexus handoff receipt Rust counts differ from exact log markers")

    production_receipt = exact_object(
        receipt["production_registry"],
        {
            "registry_source",
            "substrate_source",
            "handoff_index_owned_by_registry",
            "admission_and_publication_share_registry_lock",
            "commit_close_reuses_revoke_lifecycle",
            "sequence_tests",
            "loom_tests",
            "total_tests",
            "local_fault_cells_mapped",
            "external_intent_only_cells",
            "real_ostd_execution_claimed",
        },
        "Nexus handoff receipt.production_registry",
    )
    production_lock = lock["production_registry"]
    production_suites = production_lock["suites"]
    expected_production = {
        "registry_source": production_lock["registry_source"],
        "substrate_source": production_lock["substrate_source"],
        "handoff_index_owned_by_registry": True,
        "admission_and_publication_share_registry_lock": True,
        "commit_close_reuses_revoke_lifecycle": True,
        "sequence_tests": len(production_suites[1]["tests"]),
        "loom_tests": len(production_suites[0]["tests"]),
        "total_tests": sum(len(suite["tests"]) for suite in production_suites),
        "local_fault_cells_mapped": production_lock["local_fault_cells_mapped"],
        "external_intent_only_cells": production_lock["external_intent_only_cells"],
        "real_ostd_execution_claimed": False,
    }
    if production_receipt != expected_production:
        fail(
            "Nexus handoff receipt production_registry differs from exact source-bound "
            "refinement evidence"
        )

    boundaries = exact_object(
        receipt["boundaries"], set(BOUNDARY_VALUES), "Nexus handoff receipt.boundaries"
    )
    if boundaries != BOUNDARY_VALUES or boundaries != lock["boundaries"]:
        fail("Nexus handoff receipt weakens the mandatory same-boot non-claims")

    logs = exact_object(
        receipt["logs"], {"tla", "rust_oracle", "summary"}, "Nexus handoff receipt.logs"
    )
    expected_logs = {
        "tla": lock["artifacts"]["tla_log"]["path"],
        "rust_oracle": lock["artifacts"]["rust_oracle_log"]["path"],
        "summary": lock["artifacts"]["summary"]["path"],
    }
    if logs != expected_logs:
        fail("Nexus handoff receipt log paths differ from the qualification lock")
    digests = exact_object(
        receipt["digests"],
        {"tla_sha256", "rust_oracle_sha256", "summary_sha256"},
        "Nexus handoff receipt.digests",
    )
    if digests != observed_digests:
        fail("Nexus handoff receipt digests differ from the captured run artifacts")


def load_lock(lock_path: Path, *, lock_root: Path = ROOT) -> dict[str, Any]:
    trusted_lock_root = canonical_directory(lock_root, "qualification lock root")
    lock_relative = lexical_relative(
        trusted_lock_root, lock_path, "qualification lock"
    )
    lock_raw = read_contained_regular(
        trusted_lock_root,
        lock_relative,
        "qualification lock",
        MAX_LOCK_BYTES,
    )
    return validate_lock(decode_json(lock_raw, "qualification lock"))


def verify(
    lock_path: Path,
    checkout_path: Path,
    receipt_path: Path,
    *,
    evidence_root_path: Path | None = None,
    lock_root: Path = ROOT,
) -> None:
    lock = load_lock(lock_path, lock_root=lock_root)

    checkout = canonical_directory(checkout_path, "Nexus checkout")
    evidence_root = canonical_directory(
        evidence_root_path if evidence_root_path is not None else checkout,
        "Nexus evidence root",
    )
    receipt_relative = lexical_relative(
        evidence_root, receipt_path, "Nexus handoff receipt"
    )
    if receipt_relative != lock["artifacts"]["receipt"]["path"]:
        fail(
            "--receipt path differs from the qualification lock: "
            f"expected={lock['artifacts']['receipt']['path']} actual={receipt_relative}"
        )

    revision_before, repository_before = inspect_checkout(
        checkout,
        lock["nexus"]["revision"],
        lock["nexus"]["analyzed_baseline_revision"],
    )
    if repository_before != lock["nexus"]["repository"]:
        fail("Nexus checkout repository differs from the qualification lock")

    source_fingerprint = compute_source_fingerprint(
        checkout, lock["nexus"]["source_files"]
    )
    if source_fingerprint != lock["nexus"]["source_fingerprint"]:
        fail(
            "Nexus source fingerprint differs from the qualification lock: "
            f"expected={lock['nexus']['source_fingerprint']} actual={source_fingerprint}"
        )

    artifact_limits = {
        "receipt": MAX_RECEIPT_BYTES,
        "matrix": MAX_MATRIX_BYTES,
        "tla_log": MAX_TLA_LOG_BYTES,
        "rust_oracle_log": MAX_RUST_LOG_BYTES,
        "summary": MAX_SUMMARY_BYTES,
    }
    artifact_bytes: dict[str, bytes] = {}
    for name, maximum in artifact_limits.items():
        item = lock["artifacts"][name]
        raw = read_contained_regular(
            evidence_root,
            item["path"],
            f"Nexus qualification artifact {name}",
            maximum,
        )
        artifact_bytes[name] = raw

    validate_digest(
        artifact_bytes["matrix"],
        lock["artifacts"]["matrix"]["sha256"],
        "Nexus qualification artifact matrix",
    )
    observed_digests = {
        "tla_sha256": sha256(artifact_bytes["tla_log"]),
        "rust_oracle_sha256": sha256(artifact_bytes["rust_oracle_log"]),
        "summary_sha256": sha256(artifact_bytes["summary"]),
    }

    matrix = parse_matrix(artifact_bytes["matrix"], lock)
    parse_tla_log(artifact_bytes["tla_log"], lock)
    parse_rust_log(artifact_bytes["rust_oracle_log"], lock)
    parse_summary(artifact_bytes["summary"], lock)
    receipt = decode_json(artifact_bytes["receipt"], "Nexus handoff receipt")
    validate_receipt(receipt, lock, matrix, observed_digests)

    revision_after, repository_after = inspect_checkout(
        checkout,
        lock["nexus"]["revision"],
        lock["nexus"]["analyzed_baseline_revision"],
    )
    if revision_after != revision_before or repository_after != repository_before:
        fail("Nexus checkout identity changed during qualification verification")
    source_after = compute_source_fingerprint(checkout, lock["nexus"]["source_files"])
    if source_after != source_fingerprint:
        fail("Nexus source files changed during qualification verification")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a strict same-boot Nexus handoff-admission receipt"
    )
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--checkout", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument(
        "--evidence-root",
        type=Path,
        help="artifact root for receipt/matrix/log/summary paths (default: checkout)",
    )
    parser.add_argument(
        "--emit-lock-values",
        action="store_true",
        help=(
            "strictly parse the lock and print executed revision, analyzed baseline, "
            "source fingerprint, and matrix SHA"
        ),
    )
    arguments = parser.parse_args()
    try:
        if arguments.emit_lock_values:
            if any(
                value is not None
                for value in [
                    arguments.checkout,
                    arguments.receipt,
                    arguments.evidence_root,
                ]
            ):
                fail("--emit-lock-values accepts only --lock")
            lock = load_lock(arguments.lock)
            print(lock["nexus"]["revision"])
            print(lock["nexus"]["analyzed_baseline_revision"])
            print(lock["nexus"]["source_fingerprint"])
            print(lock["artifacts"]["matrix"]["sha256"])
            return 0
        if arguments.checkout is None or arguments.receipt is None:
            fail("normal verification requires --checkout and --receipt")
        verify(
            arguments.lock,
            arguments.checkout,
            arguments.receipt,
            evidence_root_path=arguments.evidence_root,
        )
    except (
        QualificationError,
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
    ) as error:
        print(f"Nexus handoff qualification failed: {error}", file=sys.stderr)
        return 1
    print(
        "Nexus handoff qualification passed: "
        "production Registry refinement checked, same-boot only; "
        "cross-host/host-reboot/rollback/crypto/joint-vISA/real-ostd "
        "claims remain false"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
