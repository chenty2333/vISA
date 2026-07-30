#!/usr/bin/env python3
"""Validate the canonical six-dimensional evidence matrix against project claims."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from claims_registry import RegistryError, load_registry, validate_registry


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MATRIX = ROOT / "claims/evidence-matrix.json"
DEFAULT_REGISTRY = ROOT / "claims/registry.json"

TOP_LEVEL_KEYS = {"schema_version", "cells", "claim_requirements"}
CELL_KEYS = {
    "claim_ids",
    "destination",
    "disposition",
    "evidence_boundary",
    "fault_model",
    "handoff_topology",
    "id",
    "non_claims",
    "resource_profile",
    "source",
    "verifier",
    "workflow_binding_ids",
}
ENDPOINT_KEYS = {"isa", "runtime", "substrate"}
REQUIREMENT_KEYS = {
    "claim_id",
    "minimum_required_runs_per_cell",
    "minimum_supporting_runs_per_cell",
    "required_cells",
    "requires_clean_git",
    "requires_relocated_verification",
    "supporting_cells",
}
RUNTIMES = {
    "jco-node",
    "not-applicable",
    "source-locked-wacogo",
    "wanco-aot",
    "wasmtime",
}
ISAS = {"aarch64", "not-applicable", "x86-64"}
SUBSTRATES = {"linux-host", "linux-qemu-user", "neutral-model", "not-applicable"}
RESOURCE_PROFILES = {
    "joint-handoff",
    "logical-request",
    "regular-file",
    "sqlite-rollback-journal",
    "timer-kv",
    "zstd-streaming-regular-files",
}
HANDOFF_TOPOLOGIES = {
    "in-process-distinct-stores",
    "neutral-state-machine",
    "process-isolated-workers",
    "runner-with-destination-sidecar",
    "runner-with-dual-sidecars",
    "runner-with-source-sidecar",
    "same-boot-multi-process",
    "visa-plus-wanco-carrier",
    "visa-plus-wanco-carrier-with-provider-handoff",
    "wanco-carrier-only",
}
FAULT_MODELS = {
    "joint-admission-lost-ack",
    "joint-neutral-sixteen-case",
    "stage1-thirty-one-case",
    "stage3a-regular-file-twelve-case",
    "stage3b-logical-request-fourteen-case",
    "stage4-stage1-thirty-one-case",
    "sqlite-rollback-eight-cut-plus-process-crash",
    "wanco-regular-file-two-case",
    "zstd-two-post-fd-write-cuts-plus-negatives",
}
VERIFIERS = {
    "joint-admission-artifact-static",
    "joint-artifact-static",
    "joint-neutral-oracle",
    "stage1-artifact-semantic",
    "stage2-outer-normalized",
    "stage2-strict-outer-normalized",
    "stage3-structural",
    "regular-file-raw-observable-oracle",
    "sqlite-namespace-native-oracle",
    "stage3a-cross-runtime-outer-and-raw-oracle",
    "stage4-reconstructed-normalized",
    "native-zstd-decompression-and-control-byte-identity",
}
DISPOSITIONS = {"candidate", "declared-gap", "qualified"}
ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")


class EvidenceMatrixError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceMatrixError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceMatrixError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_matrix(path: Path = DEFAULT_MATRIX) -> dict[str, Any]:
    require(not path.is_symlink() and path.is_file(), f"matrix must be a regular file: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceMatrixError(f"cannot parse evidence matrix {path}: {error}") from error
    require(isinstance(value, dict), "evidence matrix must contain one JSON object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    require(set(value) == expected, f"{label} keys drifted: {sorted(value)}")


def string_array(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    require(allow_empty or bool(value), f"{label} must not be empty")
    require(all(isinstance(item, str) and item for item in value), f"{label} must contain strings")
    require(value == sorted(set(value)), f"{label} must be unique and sorted")
    return value


def enum_value(value: Any, accepted: set[str], label: str) -> str:
    require(isinstance(value, str) and value in accepted, f"{label} is invalid: {value!r}")
    return value


def validate_endpoint(value: Any, label: str) -> tuple[str, str, str]:
    require(isinstance(value, dict), f"{label} must be an object")
    exact_keys(value, ENDPOINT_KEYS, label)
    runtime = enum_value(value["runtime"], RUNTIMES, f"{label}.runtime")
    isa = enum_value(value["isa"], ISAS, f"{label}.isa")
    substrate = enum_value(value["substrate"], SUBSTRATES, f"{label}.substrate")
    require(
        (runtime == "not-applicable") == (isa == "not-applicable"),
        f"{label} runtime and ISA applicability disagree",
    )
    require(
        substrate != "neutral-model" or runtime == "not-applicable",
        f"{label} neutral model cannot name a runtime",
    )
    return runtime, isa, substrate


def validate_matrix(
    matrix: dict[str, Any],
    registry: dict[str, Any],
) -> None:
    exact_keys(matrix, TOP_LEVEL_KEYS, "evidence matrix")
    require(
        matrix["schema_version"] == "visa.evidence-matrix.v1",
        "unknown evidence matrix schema",
    )
    raw_cells = matrix["cells"]
    raw_requirements = matrix["claim_requirements"]
    require(isinstance(raw_cells, list) and raw_cells, "evidence matrix cells are empty")
    require(
        isinstance(raw_requirements, list) and raw_requirements,
        "evidence matrix claim requirements are empty",
    )

    cells: dict[str, dict[str, Any]] = {}
    coordinates: set[tuple[Any, ...]] = set()
    cell_order: list[str] = []
    for index, cell in enumerate(raw_cells):
        label = f"cells[{index}]"
        require(isinstance(cell, dict), f"{label} must be an object")
        exact_keys(cell, CELL_KEYS, label)
        cell_id = cell["id"]
        require(isinstance(cell_id, str) and ID_RE.fullmatch(cell_id), f"invalid cell id {cell_id!r}")
        require(cell_id not in cells, f"duplicate evidence cell {cell_id}")
        cells[cell_id] = cell
        cell_order.append(cell_id)
        source = validate_endpoint(cell["source"], f"{cell_id}.source")
        destination = validate_endpoint(cell["destination"], f"{cell_id}.destination")
        profile = enum_value(
            cell["resource_profile"], RESOURCE_PROFILES, f"{cell_id}.resource_profile"
        )
        topology = enum_value(
            cell["handoff_topology"], HANDOFF_TOPOLOGIES, f"{cell_id}.handoff_topology"
        )
        fault = enum_value(cell["fault_model"], FAULT_MODELS, f"{cell_id}.fault_model")
        verifier = enum_value(cell["verifier"], VERIFIERS, f"{cell_id}.verifier")
        disposition = enum_value(
            cell["disposition"], DISPOSITIONS, f"{cell_id}.disposition"
        )
        claims = string_array(cell["claim_ids"], f"{cell_id}.claim_ids", allow_empty=True)
        bindings = string_array(
            cell["workflow_binding_ids"],
            f"{cell_id}.workflow_binding_ids",
            allow_empty=True,
        )
        string_array(cell["non_claims"], f"{cell_id}.non_claims")
        require(
            isinstance(cell["evidence_boundary"], str) and cell["evidence_boundary"].strip(),
            f"{cell_id}.evidence_boundary is empty",
        )
        if disposition == "declared-gap":
            require(not claims and not bindings, f"declared gap {cell_id} binds evidence")
        else:
            require(claims and bindings, f"evidence cell {cell_id} is unbound")
        coordinate = (source, destination, profile, topology, fault, verifier)
        require(coordinate not in coordinates, f"duplicate six-dimensional coordinate at {cell_id}")
        coordinates.add(coordinate)
    require(cell_order == sorted(cell_order), "evidence cells must be sorted by id")

    requirements: dict[str, dict[str, Any]] = {}
    requirement_order: list[str] = []
    referenced: set[str] = set()
    for index, requirement in enumerate(raw_requirements):
        label = f"claim_requirements[{index}]"
        require(isinstance(requirement, dict), f"{label} must be an object")
        exact_keys(requirement, REQUIREMENT_KEYS, label)
        claim_id = requirement["claim_id"]
        require(
            isinstance(claim_id, str) and ID_RE.fullmatch(claim_id),
            f"invalid matrix claim id {claim_id!r}",
        )
        require(claim_id not in requirements, f"duplicate matrix claim {claim_id}")
        requirements[claim_id] = requirement
        requirement_order.append(claim_id)
        required = string_array(requirement["required_cells"], f"{claim_id}.required_cells")
        supporting = string_array(
            requirement["supporting_cells"],
            f"{claim_id}.supporting_cells",
            allow_empty=True,
        )
        require(
            isinstance(requirement["minimum_required_runs_per_cell"], int)
            and not isinstance(requirement["minimum_required_runs_per_cell"], bool)
            and requirement["minimum_required_runs_per_cell"] > 0,
            f"{claim_id}.minimum_required_runs_per_cell must be positive",
        )
        require(
            isinstance(requirement["minimum_supporting_runs_per_cell"], int)
            and not isinstance(requirement["minimum_supporting_runs_per_cell"], bool)
            and requirement["minimum_supporting_runs_per_cell"] > 0,
            f"{claim_id}.minimum_supporting_runs_per_cell must be positive",
        )
        require(
            isinstance(requirement["requires_clean_git"], bool),
            f"{claim_id}.requires_clean_git must be boolean",
        )
        require(
            isinstance(requirement["requires_relocated_verification"], bool),
            f"{claim_id}.requires_relocated_verification must be boolean",
        )
        require(not set(required) & set(supporting), f"{claim_id} cell sets overlap")
        for cell_id in [*required, *supporting]:
            require(cell_id in cells, f"{claim_id} references unknown cell {cell_id}")
            require(
                cells[cell_id]["disposition"] != "declared-gap",
                f"{claim_id} references declared gap {cell_id}",
            )
            require(
                claim_id in cells[cell_id]["claim_ids"],
                f"{claim_id} and {cell_id} bindings are asymmetric",
            )
            referenced.add(cell_id)
    require(requirement_order == sorted(requirement_order), "matrix claims must be sorted by id")

    registry_claims = {claim["id"]: claim for claim in registry["claims"]}
    registry_bindings = {binding["id"]: binding for binding in registry["workflow_bindings"]}
    require(
        set(requirements) == set(registry_claims),
        "matrix claim IDs differ from the project claim registry",
    )
    observed_workflow_bindings: set[str] = set()
    for cell_id, cell in cells.items():
        if cell["disposition"] == "declared-gap":
            continue
        require(cell_id in referenced, f"orphaned evidence cell {cell_id}")
        for claim_id in cell["claim_ids"]:
            require(claim_id in requirements, f"{cell_id} references unknown claim {claim_id}")
            requirement = requirements[claim_id]
            require(
                cell_id in requirement["required_cells"]
                or cell_id in requirement["supporting_cells"],
                f"{cell_id} and {claim_id} bindings are asymmetric",
            )
        cell_binding_claims: set[str] = set()
        for binding_id in cell["workflow_binding_ids"]:
            require(binding_id in registry_bindings, f"{cell_id} has unknown workflow {binding_id}")
            observed_workflow_bindings.add(binding_id)
            cell_binding_claims.update(
                claim["id"] for claim in registry_bindings[binding_id]["claims"]
            )
        require(
            set(cell["claim_ids"]) <= cell_binding_claims,
            f"{cell_id} claims are not all bound by its workflows",
        )

    require(
        observed_workflow_bindings == set(registry_bindings),
        "workflow bindings differ between the matrix and claim registry",
    )
    for claim_id, requirement in requirements.items():
        status = registry_claims[claim_id]["status"]
        required_dispositions = {
            cells[cell_id]["disposition"] for cell_id in requirement["required_cells"]
        }
        if status == "earned":
            require(
                required_dispositions == {"qualified"},
                f"earned claim {claim_id} requires non-qualified cells",
            )
        elif status == "candidate":
            require(
                "candidate" in required_dispositions,
                f"candidate claim {claim_id} has no candidate required cell",
            )
        else:
            raise EvidenceMatrixError(f"retired claim {claim_id} remains in the active matrix")


def validate_repository(
    matrix_path: Path = DEFAULT_MATRIX,
    registry_path: Path = DEFAULT_REGISTRY,
    root: Path = ROOT,
) -> dict[str, Any]:
    matrix = load_matrix(matrix_path)
    try:
        registry = load_registry(registry_path)
        validate_registry(registry, root)
    except RegistryError as error:
        raise EvidenceMatrixError(f"claim registry is invalid: {error}") from error
    validate_matrix(matrix, registry)
    return matrix
