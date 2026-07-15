#!/usr/bin/env python3
"""Generate a strict v2 Nexus handoff qualification lock from executed evidence."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
CHECKER_PATH = Path(__file__).with_name("check-nexus-handoff-qualification.py")
DEFAULT_BASELINE_LOCK = (
    ROOT / "third_party" / "joint-handoff-qualification" / "source-lock.json"
)
EXPECTED_RECEIPT_PATH = "target/research/handoff-admission/receipt.json"
RUST_SUITE_HEADINGS = [
    "==> handoff-admission sequence oracle",
    "==> handoff-admission property oracle",
    "==> handoff-admission Loom oracle",
    "==> handoff-admission substrate Loom refinement",
    "==> handoff-admission production Registry refinement",
]
TEMPORAL_BRANCHES = re.compile(
    r"Implied-temporal checking--satisfiability problem has ([0-9]+) branches\."
)

SPEC = importlib.util.spec_from_file_location("nexus_qualification_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Nexus qualification checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def read_json(root: Path, relative: str, label: str, maximum: int) -> Any:
    raw = CHECKER.read_contained_regular(root, relative, label, maximum)
    return CHECKER.decode_json(raw, label)


def baseline_revision(path: Path) -> str:
    root = CHECKER.canonical_directory(path.parent, "baseline source-lock root")
    candidate = root / path.name
    relative = CHECKER.lexical_relative(root, candidate, "baseline source lock")
    document = read_json(root, relative, "baseline source lock", CHECKER.MAX_LOCK_BYTES)
    document = CHECKER.exact_object(
        document,
        {
            "schema",
            "evidence_status",
            "visa",
            "nexus",
            "joint_artifact",
            "protocol_schema",
            "neutral_wire_contract",
            "machine_contract",
            "refinement_map",
            "abstract_case_registry",
            "case_registry",
        },
        "baseline source lock",
    )
    if document["schema"] != "visa.joint-handoff-qualification-source-lock.v1":
        CHECKER.fail("baseline source lock has an unsupported schema")
    if document["evidence_status"] != "reference-only-not-nexus-qualified":
        CHECKER.fail("baseline source lock is not the analyzed reference-only input")
    nexus = CHECKER.exact_object(
        document["nexus"],
        {"repository", "revision", "execution"},
        "baseline source lock.nexus",
    )
    if nexus["repository"] != CHECKER.EXPECTED_REPOSITORY:
        CHECKER.fail("baseline source lock names a different Nexus repository")
    if nexus["execution"] != "reference-peer-only":
        CHECKER.fail("baseline source lock no longer records the analyzed reference input")
    return CHECKER.exact_sha(
        nexus["revision"], CHECKER.LOWER_GIT_SHA, "baseline source lock.nexus.revision"
    )


def checkout_identity(checkout: Path, analyzed_baseline: str) -> tuple[str, str]:
    revision = CHECKER.git(
        checkout, ["rev-parse", "--verify", "HEAD^{commit}"], "rev-parse HEAD"
    ).decode("ascii", errors="strict").strip()
    if CHECKER.LOWER_GIT_SHA.fullmatch(revision) is None:
        CHECKER.fail("Nexus checkout HEAD is not an exact lowercase Git SHA")
    return CHECKER.inspect_checkout(checkout, revision, analyzed_baseline)


def normalized_paths(receipt: dict[str, Any]) -> tuple[str, dict[str, str]]:
    fault = CHECKER.exact_object(
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
    matrix_path = CHECKER.normalized_relative_path(
        fault["matrix"], "Nexus handoff receipt.fault_contract.matrix"
    )
    logs = CHECKER.exact_object(
        receipt["logs"],
        {"tla", "rust_oracle", "summary"},
        "Nexus handoff receipt.logs",
    )
    normalized_logs = {
        name: CHECKER.normalized_relative_path(value, f"Nexus handoff receipt.logs.{name}")
        for name, value in logs.items()
    }
    paths = [EXPECTED_RECEIPT_PATH, matrix_path, *normalized_logs.values()]
    if len(set(paths)) != len(paths):
        CHECKER.fail("Nexus qualification artifact paths must be distinct")
    return matrix_path, normalized_logs


def matrix_contract(raw: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        matrix = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        CHECKER.fail(f"cannot decode Nexus handoff fault matrix: {error}")
    matrix = CHECKER.exact_object(
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
    expected = {
        "schema": CHECKER.MATRIX_SCHEMA,
        "fault_model": "same-boot-crash-stop-retry-reorder-lost-ack",
        "ownership_log": "trusted-non-equivocating-no-rollback-tcb",
        "host_reboot_claimed": False,
        "malicious_rollback_claimed": False,
        # The v1 matrix freezes the independent first-round model boundary.
        # The executed v2 receipt separately proves the production Registry
        # refinement and must report that boundary as true.
        "production_registry_modified": False,
    }
    for key, value in expected.items():
        if type(matrix[key]) is not type(value) or matrix[key] != value:
            CHECKER.fail(f"fault matrix {key} is outside the strict v2 profile")
    profile = CHECKER.normalized_relative_path(matrix["profile"], "fault matrix.profile")
    invariants = CHECKER.string_list(
        matrix["required_invariants"], "fault matrix.required_invariants"
    )
    mutations = CHECKER.string_list(matrix["negative_mutations"], "fault matrix.negative_mutations")
    cells = CHECKER.exact_list(matrix["cell"], "fault matrix.cell", nonempty=True)
    expected_count = CHECKER.exact_uint(
        matrix["expected_count"], "fault matrix.expected_count", positive=True
    )
    if expected_count != len(cells):
        CHECKER.fail("fault matrix expected_count differs from its cell population")
    normalized_cells: list[dict[str, Any]] = []
    for index, value in enumerate(cells):
        label = f"fault matrix.cell[{index}]"
        cell = CHECKER.exact_object(
            value,
            {"id", "event_order", "expected", "tla_witness", "rust_test", "kill_condition"},
            label,
        )
        normalized_cells.append(
            {
                "id": CHECKER.exact_string(cell["id"], f"{label}.id"),
                "event_order": CHECKER.string_list(cell["event_order"], f"{label}.event_order"),
                "expected": CHECKER.exact_string(cell["expected"], f"{label}.expected"),
                "tla_witness": CHECKER.exact_string(
                    cell["tla_witness"], f"{label}.tla_witness"
                ),
                "rust_test": CHECKER.exact_string(cell["rust_test"], f"{label}.rust_test"),
                "kill_condition": CHECKER.exact_string(
                    cell["kill_condition"], f"{label}.kill_condition"
                ),
            }
        )
    if len({cell["id"] for cell in normalized_cells}) != len(normalized_cells):
        CHECKER.fail("fault matrix contains duplicate cell ids")
    return (
        {
            "matrix_schema": CHECKER.MATRIX_SCHEMA,
            "profile": profile,
            "cells": len(normalized_cells),
            "required_invariants": invariants,
            "negative_mutations": mutations,
            "fault_model": expected["fault_model"],
            "ownership_log_tcb": expected["ownership_log"],
        },
        normalized_cells,
    )


def formal_contract(
    receipt: dict[str, Any], tla_raw: bytes, cells: list[dict[str, Any]]
) -> dict[str, Any]:
    formal = CHECKER.exact_object(
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
    specification = CHECKER.exact_string(formal["specification"], "receipt.formal.specification")
    if CHECKER.exact_bool(formal["declarative_tla"], "receipt.formal.declarative_tla") is not True:
        CHECKER.fail("receipt.formal.declarative_tla must be true")
    configurations = CHECKER.exact_list(
        formal["configurations"], "receipt.formal.configurations", nonempty=True
    )
    if len(configurations) != 2 or formal["complete_configurations"] != 2:
        CHECKER.fail("receipt must retain exactly two complete TLA configurations")
    witnesses = CHECKER.exact_list(formal["witnesses"], "receipt.formal.witnesses", nonempty=True)
    if formal["reachability_witnesses"] != len(witnesses) or len(witnesses) != len(cells):
        CHECKER.fail("receipt witness population differs from the fault matrix")
    witness_lock: list[dict[str, str]] = []
    for index, value in enumerate(witnesses):
        label = f"receipt.formal.witnesses[{index}]"
        witness = CHECKER.exact_object(value, {"invariant", "description", "status"}, label)
        if witness["status"] != "reachable" or witness["invariant"] != cells[index]["tla_witness"]:
            CHECKER.fail(f"{label} differs from the fault-matrix witness")
        witness_lock.append(
            {
                "invariant": CHECKER.exact_string(witness["invariant"], f"{label}.invariant"),
                "description": CHECKER.exact_string(
                    witness["description"], f"{label}.description"
                ),
            }
        )
    try:
        lines = tla_raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        CHECKER.fail(f"TLA log is not UTF-8: {error}")
    headings = [line for line in lines if line.startswith(f"==> {specification} ")]
    expected_middle = [
        f"==> {specification} reachability: {witness['description']}"
        for witness in witness_lock
    ]
    if len(headings) != len(witness_lock) + 2 or headings[1:-1] != expected_middle:
        CHECKER.fail("TLA headings do not bind the receipt witness population")
    starts = [lines.index(headings[0]), lines.index(headings[-1])]
    blocks = [lines[starts[0] : lines.index(headings[1])], lines[starts[1] :]]
    configuration_lock: list[dict[str, Any]] = []
    for index, (value, block) in enumerate(zip(configurations, blocks)):
        label = f"receipt.formal.configurations[{index}]"
        item = CHECKER.exact_object(
            value,
            {
                "config",
                "status",
                "generated",
                "distinct",
                "depth",
                "states_left_on_queue",
                "property_mode",
            },
            label,
        )
        if item["status"] != "complete":
            CHECKER.fail(f"{label}.status must be complete")
        temporal = [TEMPORAL_BRANCHES.fullmatch(line) for line in block]
        temporal = [match for match in temporal if match is not None]
        branches = 0 if index == 0 else int(temporal[0].group(1)) if len(temporal) == 1 else -1
        if branches < 0 or (index == 0 and temporal):
            CHECKER.fail(f"{label} has an invalid temporal branch marker")
        configuration_lock.append(
            {
                "config": CHECKER.exact_string(item["config"], f"{label}.config"),
                "heading": headings[0 if index == 0 else -1].removeprefix("==> "),
                "generated": CHECKER.exact_uint(
                    item["generated"], f"{label}.generated", positive=True
                ),
                "distinct": CHECKER.exact_uint(
                    item["distinct"], f"{label}.distinct", positive=True
                ),
                "depth": CHECKER.exact_uint(item["depth"], f"{label}.depth", positive=True),
                "states_left_on_queue": CHECKER.exact_uint(
                    item["states_left_on_queue"], f"{label}.states_left_on_queue"
                ),
                "property_mode": CHECKER.exact_string(
                    item["property_mode"], f"{label}.property_mode"
                ),
                "temporal_branches": branches,
            }
        )
    temporal_properties = CHECKER.exact_uint(
        formal["temporal_properties"], "receipt.formal.temporal_properties", positive=True
    )
    if configuration_lock[1]["temporal_branches"] != temporal_properties:
        CHECKER.fail("TLA progress branches differ from receipt.temporal_properties")
    return {
        "specification": specification,
        "declarative_tla": True,
        "temporal_properties": temporal_properties,
        "configurations": configuration_lock,
        "witnesses": witness_lock,
    }


def rust_suites(
    raw: bytes, cells: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        CHECKER.fail(f"Rust oracle log is not UTF-8: {error}")
    headings = [
        (index, line)
        for index, line in enumerate(lines)
        if line.startswith("==> handoff-admission ")
    ]
    if [line for _, line in headings] != RUST_SUITE_HEADINGS:
        CHECKER.fail("Rust evidence suite population or order is not the v2 contract")
    observed: list[list[str]] = []
    for index, (start, heading) in enumerate(headings):
        end = headings[index + 1][0] if index + 1 < len(headings) else len(lines)
        block = lines[start:end]
        tests = [
            match.group(1)
            for line in block
            if (match := CHECKER.RUST_TEST_MARKER.fullmatch(line)) is not None
        ]
        if not tests or len(tests) != len(set(tests)):
            CHECKER.fail(f"Rust evidence suite {heading} has no tests or duplicate markers")
        count = len(tests)
        if block.count(f"running {count} tests") != 1:
            CHECKER.fail(f"Rust evidence suite {heading} lacks its exact running count")
        result = (
            f"test result: ok. {count} passed; 0 failed; 0 ignored; "
            "0 measured; 0 filtered out;"
        )
        if sum(line.startswith(result) for line in block) != 1:
            CHECKER.fail(f"Rust evidence suite {heading} lacks its exact pass result")
        observed.append(tests)
    sequence_tests = [cell["rust_test"] for cell in cells]
    if set(observed[0]) != set(sequence_tests):
        CHECKER.fail("Rust sequence suite differs from the fault-matrix mapping")
    oracle = [
        {"kind": "sequence", "heading": headings[0][1], "tests": sequence_tests},
        {"kind": "property", "heading": headings[1][1], "tests": sorted(observed[1])},
        {"kind": "loom", "heading": headings[2][1], "tests": sorted(observed[2])},
    ]
    production = [
        {"kind": "substrate_loom", "heading": headings[3][1], "tests": sorted(observed[3])},
        {"kind": "registry_sequence", "heading": headings[4][1], "tests": sorted(observed[4])},
    ]
    return oracle, production


def build_lock(checkout_path: Path, receipt_path: Path, analyzed_baseline: str) -> dict[str, Any]:
    checkout = CHECKER.canonical_directory(checkout_path, "Nexus checkout")
    revision, repository = checkout_identity(checkout, analyzed_baseline)
    receipt_relative = CHECKER.lexical_relative(checkout, receipt_path, "Nexus handoff receipt")
    if receipt_relative != EXPECTED_RECEIPT_PATH:
        CHECKER.fail(f"Nexus receipt must be {EXPECTED_RECEIPT_PATH}")
    receipt_raw = CHECKER.read_contained_regular(
        checkout, receipt_relative, "Nexus handoff receipt", CHECKER.MAX_RECEIPT_BYTES
    )
    receipt = CHECKER.exact_object(
        CHECKER.decode_json(receipt_raw, "Nexus handoff receipt"),
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
    expected_scalars = {
        "schema": CHECKER.RECEIPT_SCHEMA,
        "status": "passed",
        "prospective": True,
        "command": CHECKER.EXPECTED_COMMAND,
        "revision": revision,
        "worktree_dirty": False,
    }
    for key, value in expected_scalars.items():
        if type(receipt[key]) is not type(value) or receipt[key] != value:
            CHECKER.fail(f"Nexus handoff receipt {key} is not generator-admissible")
    source_files = [
        CHECKER.normalized_relative_path(value, f"Nexus handoff receipt.source_files[{index}]")
        for index, value in enumerate(
            CHECKER.exact_list(receipt["source_files"], "receipt.source_files", nonempty=True)
        )
    ]
    if len(source_files) != len(set(source_files)):
        CHECKER.fail("Nexus handoff receipt.source_files contains duplicates")
    source_fingerprint = CHECKER.exact_sha(
        receipt["source_fingerprint"], CHECKER.LOWER_SHA256, "receipt.source_fingerprint"
    )
    if CHECKER.compute_source_fingerprint(checkout, source_files) != source_fingerprint:
        CHECKER.fail("Nexus receipt source fingerprint differs from the clean checkout")

    matrix_path, logs = normalized_paths(receipt)
    if matrix_path not in source_files:
        CHECKER.fail("Nexus fault matrix is not source-fingerprint bound")
    artifact_specs = {
        "matrix": (matrix_path, CHECKER.MAX_MATRIX_BYTES),
        "tla_log": (logs["tla"], CHECKER.MAX_TLA_LOG_BYTES),
        "rust_oracle_log": (logs["rust_oracle"], CHECKER.MAX_RUST_LOG_BYTES),
        "summary": (logs["summary"], CHECKER.MAX_SUMMARY_BYTES),
    }
    artifact_bytes = {
        name: CHECKER.read_contained_regular(checkout, path, name, maximum)
        for name, (path, maximum) in artifact_specs.items()
    }
    fault, cells = matrix_contract(artifact_bytes["matrix"])
    formal = formal_contract(receipt, artifact_bytes["tla_log"], cells)
    oracle_suites, production_suites = rust_suites(artifact_bytes["rust_oracle_log"], cells)
    production_receipt = CHECKER.exact_object(
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
    production_lock = {
        "registry_source": production_receipt["registry_source"],
        "substrate_source": production_receipt["substrate_source"],
        "handoff_index_owned_by_registry": production_receipt["handoff_index_owned_by_registry"],
        "admission_and_publication_share_registry_lock": production_receipt[
            "admission_and_publication_share_registry_lock"
        ],
        "commit_close_reuses_revoke_lifecycle": production_receipt[
            "commit_close_reuses_revoke_lifecycle"
        ],
        "local_fault_cells_mapped": production_receipt["local_fault_cells_mapped"],
        "external_intent_only_cells": production_receipt["external_intent_only_cells"],
        "real_ostd_execution_claimed": production_receipt["real_ostd_execution_claimed"],
        "suites": production_suites,
    }
    lock = {
        "schema": CHECKER.LOCK_SCHEMA,
        "evidence_status": CHECKER.EVIDENCE_STATUS,
        "claim_id": CHECKER.CLAIM_ID,
        "nexus": {
            "repository": repository,
            "revision": revision,
            "analyzed_baseline_revision": analyzed_baseline,
            "role": CHECKER.NEXUS_ROLE,
            "receipt_schema": CHECKER.RECEIPT_SCHEMA,
            "summary_schema": CHECKER.SUMMARY_SCHEMA,
            "command": CHECKER.EXPECTED_COMMAND,
            "prospective": True,
            "source_fingerprint": source_fingerprint,
            "source_files": source_files,
        },
        "artifacts": {
            "receipt": {"path": receipt_relative},
            "matrix": {"path": matrix_path, "sha256": CHECKER.sha256(artifact_bytes["matrix"])},
            "tla_log": {"path": logs["tla"]},
            "rust_oracle_log": {"path": logs["rust_oracle"]},
            "summary": {"path": logs["summary"]},
        },
        "fault_contract": fault,
        "formal": formal,
        "rust_oracle": {
            "independent_from_production_registry": True,
            "suites": oracle_suites,
        },
        "production_registry": production_lock,
        "boundaries": dict(CHECKER.BOUNDARY_VALUES),
    }
    lock = CHECKER.validate_lock(lock)
    matrix = CHECKER.parse_matrix(artifact_bytes["matrix"], lock)
    CHECKER.parse_tla_log(artifact_bytes["tla_log"], lock)
    CHECKER.parse_rust_log(artifact_bytes["rust_oracle_log"], lock)
    CHECKER.parse_summary(artifact_bytes["summary"], lock)
    observed_digests = {
        "tla_sha256": CHECKER.sha256(artifact_bytes["tla_log"]),
        "rust_oracle_sha256": CHECKER.sha256(artifact_bytes["rust_oracle_log"]),
        "summary_sha256": CHECKER.sha256(artifact_bytes["summary"]),
    }
    CHECKER.validate_receipt(receipt, lock, matrix, observed_digests)
    checkout_identity(checkout, analyzed_baseline)
    if CHECKER.compute_source_fingerprint(checkout, source_files) != source_fingerprint:
        CHECKER.fail("Nexus source files changed while generating the qualification lock")
    if CHECKER.read_contained_regular(
        checkout,
        receipt_relative,
        "Nexus handoff receipt",
        CHECKER.MAX_RECEIPT_BYTES,
    ) != receipt_raw:
        CHECKER.fail("Nexus handoff receipt changed while generating the qualification lock")
    for name, (path, maximum) in artifact_specs.items():
        if CHECKER.read_contained_regular(checkout, path, name, maximum) != artifact_bytes[name]:
            CHECKER.fail(
                f"Nexus qualification artifact {name} changed while generating the lock"
            )
    return lock


def write_new(path: Path, raw: bytes) -> None:
    parent = CHECKER.canonical_directory(path.parent, "qualification lock output parent")
    output = parent / path.name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output, flags, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while creating qualification lock")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(output)
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    directory = os.open(parent, directory_flags)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a v2 Nexus qualification lock from a clean exact checkout"
    )
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--baseline-source-lock",
        type=Path,
        default=DEFAULT_BASELINE_LOCK,
        help="trusted joint source lock containing the analyzed Nexus baseline",
    )
    arguments = parser.parse_args()
    try:
        analyzed_baseline = baseline_revision(arguments.baseline_source_lock)
        lock = build_lock(arguments.checkout, arguments.receipt, analyzed_baseline)
        raw = (json.dumps(lock, indent=2) + "\n").encode("utf-8")
        write_new(arguments.output, raw)
    except (
        CHECKER.QualificationError,
        OSError,
        KeyError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as error:
        print(f"Nexus qualification lock generation failed: {error}", file=sys.stderr)
        return 1
    print(f"Nexus qualification lock generated: {arguments.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
