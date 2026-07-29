#!/usr/bin/env python3
"""Preclassified black-box corpus for the production Stage 3A outer verifier.

Semantic mutations are applied to the verdict-free regular-file observation-v2
artifacts. Producer assertions and normalization digests remain diagnostics and
integrity bindings; they are never used here as the semantic oracle.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable


SCHEMA = "visa.stage3a-cross-runtime-verifier-audit.v4"
BUNDLE_NAME = "stage3a-cross-runtime-evidence.json"
TARGET_CELL_ID = "s3a.cross.wacogo-to-wacogo.regular-file"
CONTROL_OBSERVATION = "observations/regular-file-observation-control-v2.json"
CANDIDATE_OBSERVATION = "observations/regular-file-observation-candidate-v2.json"

SEMANTIC_DEFECT = "semantic-defect"
INTEGRITY_TAMPER = "integrity-tamper"
BENIGN_EQUIVALENT = "benign-equivalent"
TRUST_BOUNDARY = "trusted-observation-boundary"

REJECT = "reject"
ACCEPT = "accept"
ACCEPT_EQUIVALENT = "accept-equivalent"
ACCEPT_BOUNDARY = "accept-boundary"

CHILD_BUNDLE_REJECTION = "invalid-stage3a-cross-runtime-child-bundle"
SEMANTIC_ORACLE_REJECTION = "regular-file-semantic-oracle-rejected"


class AuditError(RuntimeError):
    pass


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuditError(f"cannot read JSON object {path}: {error}") from error
    if not isinstance(value, dict):
        raise AuditError(f"JSON root is not an object: {path}")
    return value


def encode_object(value: dict[str, Any]) -> bytes:
    return json.dumps(value, indent=2, ensure_ascii=True).encode()


def write_object(path: Path, value: dict[str, Any]) -> bytes:
    encoded = encode_object(value)
    path.write_bytes(encoded)
    return encoded


def reseal_reference(reference: dict[str, Any], encoded: bytes) -> None:
    reference["sha256"] = hashlib.sha256(encoded).hexdigest()
    reference["size"] = len(encoded)


def run_verifier(verifier: Path, root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(verifier), "stage3a-cross-runtime", str(root / BUNDLE_NAME), str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def run_child_verifier(
    verifier: Path, bundle: dict[str, Any], root: Path
) -> subprocess.CompletedProcess[str]:
    cell = selected_cell(bundle)
    reference = cell.get("relocated_bundle")
    uri = reference.get("uri") if isinstance(reference, dict) else None
    if not isinstance(uri, str) or not uri:
        raise AuditError("target cell has no relocated child bundle URI")
    bundle_path = root / uri
    return subprocess.run(
        [str(verifier), "stage3a", str(bundle_path), str(bundle_path.parent)],
        check=False,
        capture_output=True,
        text=True,
    )


def finding_codes(completed: subprocess.CompletedProcess[str]) -> list[str]:
    try:
        result = json.loads(completed.stderr)
    except json.JSONDecodeError as error:
        raise AuditError(
            f"verifier failure was not structured JSON: {completed.stderr!r}"
        ) from error
    codes: set[str] = set()
    load_error = result.get("load_error")
    if isinstance(load_error, dict) and isinstance(load_error.get("code"), str):
        codes.add(load_error["code"])
    validation = result.get("validation")
    if isinstance(validation, dict):
        for finding in validation.get("findings", []):
            if isinstance(finding, dict) and isinstance(finding.get("code"), str):
                codes.add(finding["code"])
    return sorted(codes)


def selected_cell(
    bundle: dict[str, Any], run_ordinal: int = 2
) -> dict[str, Any]:
    for cell in bundle["cells"]:
        if cell["cell_id"] == TARGET_CELL_ID and cell["run_ordinal"] == run_ordinal:
            return cell
    raise AuditError(f"missing target cell {TARGET_CELL_ID} run {run_ordinal}")


def reseal_matrix_run(
    bundle: dict[str, Any],
    root: Path,
    old_relocated: dict[str, Any],
    new_relocated: dict[str, Any],
) -> None:
    reference = bundle["matrix_run"]
    path = root / reference["uri"]
    matrix_run = load_object(path)
    matches = 0
    for receipt in matrix_run["receipts"]:
        evidence = receipt.get("evidence_bundle")
        if isinstance(evidence, dict) and evidence.get("uri") == old_relocated["uri"]:
            receipt["evidence_bundle"] = copy.deepcopy(new_relocated)
            matches += 1
    if matches == 0:
        raise AuditError(
            f"matrix run does not reference child {old_relocated['uri']}"
        )
    encoded = write_object(path, matrix_run)
    reseal_reference(reference, encoded)


ChildMutation = Callable[[dict[str, Any], Path], None]
ObservationMutation = Callable[[dict[str, Any]], None]


def reseal_child_pair(
    bundle: dict[str, Any],
    root: Path,
    mutate: ChildMutation,
    *,
    run_ordinal: int = 2,
) -> None:
    cell = selected_cell(bundle, run_ordinal)
    old_relocated = copy.deepcopy(cell["relocated_bundle"])
    encoded_children: list[bytes] = []
    for key in ("original_bundle", "relocated_bundle"):
        reference = cell[key]
        path = root / reference["uri"]
        child = load_object(path)
        mutate(child, path.parent)
        encoded = write_object(path, child)
        reseal_reference(reference, encoded)
        encoded_children.append(encoded)
    if encoded_children[0] != encoded_children[1]:
        raise AuditError("original and relocated child mutations were not byte-identical")
    reseal_matrix_run(bundle, root, old_relocated, cell["relocated_bundle"])


def observation_reference(
    child: dict[str, Any], uri: str
) -> dict[str, Any]:
    matches = [
        reference
        for reference in child.get("raw_observations", [])
        if isinstance(reference, dict) and reference.get("uri") == uri
    ]
    if len(matches) != 1:
        raise AuditError(
            f"expected one raw observation reference for {uri}, found {len(matches)}"
        )
    return matches[0]


def mutate_observation(
    child: dict[str, Any],
    child_root: Path,
    uri: str,
    mutate: ObservationMutation,
) -> None:
    reference = observation_reference(child, uri)
    path = child_root / uri
    observation = load_object(path)
    mutate(observation)
    encoded = write_object(path, observation)
    reseal_reference(reference, encoded)


def reseal_candidate_observation_pair(
    bundle: dict[str, Any],
    root: Path,
    mutate: ObservationMutation,
) -> None:
    def mutate_child(child: dict[str, Any], child_root: Path) -> None:
        mutate_observation(
            child,
            child_root,
            CANDIDATE_OBSERVATION,
            mutate,
        )

    reseal_child_pair(bundle, root, mutate_child)


def reseal_control_observation_pair(
    bundle: dict[str, Any],
    root: Path,
    mutate: ObservationMutation,
) -> None:
    def mutate_child(child: dict[str, Any], child_root: Path) -> None:
        mutate_observation(
            child,
            child_root,
            CONTROL_OBSERVATION,
            mutate,
        )

    reseal_child_pair(bundle, root, mutate_child)


def observed_case(
    observation: dict[str, Any], case_id: str
) -> dict[str, Any]:
    matches = [
        case
        for case in observation.get("cases", [])
        if isinstance(case, dict) and case.get("case_id") == case_id
    ]
    if len(matches) != 1:
        raise AuditError(
            f"expected one observation-v2 case {case_id}, found {len(matches)}"
        )
    return matches[0]


def operation_events(
    case: dict[str, Any], operation_kind: str
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for event in case.get("events", []):
        if not isinstance(event, dict):
            continue
        body = event.get("body")
        if not isinstance(body, dict) or body.get("kind") != "operation_call":
            continue
        data = body.get("data")
        if not isinstance(data, dict):
            continue
        operation = data.get("operation")
        if isinstance(operation, dict) and operation.get("kind") == operation_kind:
            matches.append(event)
    return matches


def protocol_events(case: dict[str, Any], action_kind: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for event in case.get("events", []):
        if not isinstance(event, dict):
            continue
        body = event.get("body")
        data = body.get("data") if isinstance(body, dict) else None
        action = data.get("action") if isinstance(data, dict) else None
        if (
            isinstance(body, dict)
            and body.get("kind") == "protocol_call"
            and isinstance(action, dict)
            and action.get("kind") == action_kind
        ):
            matches.append(event)
    return matches


def returned_operation_output(
    event: dict[str, Any], output_kind: str
) -> dict[str, Any]:
    body = event.get("body")
    data = body.get("data") if isinstance(body, dict) else None
    result = data.get("result") if isinstance(data, dict) else None
    result_data = result.get("data") if isinstance(result, dict) else None
    output = result_data.get("output") if isinstance(result_data, dict) else None
    output_data = output.get("data") if isinstance(output, dict) else None
    if (
        not isinstance(result, dict)
        or result.get("status") != "returned"
        or not isinstance(output, dict)
        or output.get("kind") != output_kind
        or not isinstance(output_data, dict)
    ):
        raise AuditError(
            f"operation event does not contain returned {output_kind} output"
        )
    return output_data


def resequence(case: dict[str, Any]) -> None:
    events = case.get("events")
    if not isinstance(events, list):
        raise AuditError("observation-v2 case events are not an array")
    for sequence, event in enumerate(events):
        if not isinstance(event, dict):
            raise AuditError("observation-v2 event is not an object")
        event["sequence"] = sequence


def remove_required_route(bundle: dict[str, Any], root: Path) -> None:
    removed = [cell for cell in bundle["cells"] if cell["cell_id"] == TARGET_CELL_ID]
    if len(removed) != 3:
        raise AuditError(f"expected three runs for omitted route, found {len(removed)}")
    bundle["cells"] = [cell for cell in bundle["cells"] if cell["cell_id"] != TARGET_CELL_ID]

    matrix_reference = bundle["matrix_run"]
    matrix_path = root / matrix_reference["uri"]
    matrix_run = load_object(matrix_path)
    matrix_run["receipts"] = [
        receipt
        for receipt in matrix_run["receipts"]
        if receipt["cell_id"] != TARGET_CELL_ID
    ]
    encoded = write_object(matrix_path, matrix_run)
    reseal_reference(matrix_reference, encoded)

    directories: set[Path] = set()
    for cell in removed:
        directories.add((root / cell["original_bundle"]["uri"]).parent)
        directories.add((root / cell["relocated_bundle"]["uri"]).parent)
        directories.add((root / cell["validation_report"]["uri"]).parent)
    for directory in sorted(directories, reverse=True):
        shutil.rmtree(directory)


def alter_observed_read_offset(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        case = observed_case(observation, "read-write-offset")
        reads = operation_events(case, "read")
        if not reads:
            raise AuditError("read-write-offset has no raw read operation")
        output = returned_operation_output(reads[-1], "read")
        logical_offset = output.get("logical_offset")
        if not isinstance(logical_offset, int) or isinstance(logical_offset, bool):
            raise AuditError("read-write-offset raw logical_offset is not an integer")
        output["logical_offset"] = logical_offset + 1

    reseal_candidate_observation_pair(bundle, root, mutate)


def duplicate_observed_append(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        case = observed_case(observation, "append-continuity")
        appends = operation_events(case, "append")
        if not appends:
            raise AuditError("append-continuity has no raw append operation")
        duplicate = copy.deepcopy(appends[-1])
        body = duplicate["body"]["data"]
        body["operation_id"] = f"{body['operation_id']}-audit-duplicate"
        body["attempt"] = 0
        body["idempotency_key"] = "audit-duplicate-append"
        insertion = case["events"].index(appends[-1]) + 1
        case["events"].insert(insertion, duplicate)
        resequence(case)

    reseal_candidate_observation_pair(bundle, root, mutate)


def mutate_output_digest(output: dict[str, Any], label: str) -> None:
    digest = output.get("content_digest")
    if (
        not isinstance(digest, list)
        or len(digest) != 32
        or any(not isinstance(byte, int) or isinstance(byte, bool) for byte in digest)
    ):
        raise AuditError(f"{label} does not contain one 32-byte content digest")
    digest[0] = (digest[0] + 1) % 256


def change_returned_read_content_digest(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        case = observed_case(observation, "read-write-offset")
        reads = operation_events(case, "read")
        if not reads:
            raise AuditError("read-write-offset has no raw read operation")
        mutate_output_digest(
            returned_operation_output(reads[-1], "read"),
            "returned read",
        )

    reseal_candidate_observation_pair(bundle, root, mutate)


def change_returned_mutation_content_digest(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        case = observed_case(observation, "read-write-offset")
        writes = operation_events(case, "write")
        if len(writes) != 1:
            raise AuditError(f"expected one read-write-offset write, found {len(writes)}")
        mutate_output_digest(
            returned_operation_output(writes[0], "mutated"),
            "returned mutation",
        )

    reseal_candidate_observation_pair(bundle, root, mutate)


def change_returned_rename_content_digest(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        case = observed_case(observation, "rename-object-identity")
        renames = operation_events(case, "rename")
        returned = []
        for event in renames:
            try:
                returned.append(returned_operation_output(event, "renamed"))
            except AuditError:
                continue
        if len(returned) != 1:
            raise AuditError(f"expected one successful rename, found {len(returned)}")
        mutate_output_digest(returned[0], "returned rename")

    reseal_candidate_observation_pair(bundle, root, mutate)


def change_safe_point_identity(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        case = observed_case(observation, "read-write-offset")
        freezes = protocol_events(case, "freeze_runtime")
        if len(freezes) != 1:
            raise AuditError(f"expected one FreezeRuntime, found {len(freezes)}")
        action = freezes[0]["body"]["data"]["action"]
        action_data = action.get("data")
        if not isinstance(action_data, dict) or not isinstance(
            action_data.get("safe_point_id"), str
        ):
            raise AuditError("FreezeRuntime lacks safe_point_id")
        action_data["safe_point_id"] = "audit-forged-safe-point"

    reseal_candidate_observation_pair(bundle, root, mutate)


def change_snapshot_identity(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        case = observed_case(observation, "read-write-offset")
        restores = protocol_events(case, "restore_runtime")
        if len(restores) != 1:
            raise AuditError(f"expected one RestoreRuntime, found {len(restores)}")
        action = restores[0]["body"]["data"]["action"]
        action_data = action.get("data")
        if not isinstance(action_data, dict) or not isinstance(
            action_data.get("snapshot_id"), str
        ):
            raise AuditError("RestoreRuntime lacks snapshot_id")
        action_data["snapshot_id"] = "audit-forged-snapshot"

    reseal_candidate_observation_pair(bundle, root, mutate)


def change_post_handoff_operation_actor(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        case = observed_case(observation, "read-write-offset")
        reads = operation_events(case, "read")
        if not reads:
            raise AuditError("read-write-offset has no raw read operation")
        reads[-1]["actor"] = "source_runtime"

    reseal_candidate_observation_pair(bundle, root, mutate)


def change_resume_context(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        case = observed_case(observation, "read-write-offset")
        resumes = protocol_events(case, "resume_destination")
        if len(resumes) != 1:
            raise AuditError(f"expected one ResumeDestination, found {len(resumes)}")
        resumes[0]["phase"] = "setup"
        resumes[0]["actor"] = "source_runtime"

    reseal_candidate_observation_pair(bundle, root, mutate)


def change_candidate_route_to_restart(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        route = observation.get("route")
        if not isinstance(route, dict) or route.get("mode") != "handoff":
            raise AuditError("candidate observation does not have the handoff route")
        route["mode"] = "restart"

    reseal_candidate_observation_pair(bundle, root, mutate)


def change_candidate_runtime_identity(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        route = observation.get("route")
        source = route.get("source") if isinstance(route, dict) else None
        destination = route.get("destination") if isinstance(route, dict) else None
        if not isinstance(source, dict) or not isinstance(destination, dict):
            raise AuditError("candidate observation lacks its two runtime endpoints")
        source["runtime"] = "forged-runtime-lineage"
        destination["runtime_version"] = "forged-runtime-version"

    reseal_candidate_observation_pair(bundle, root, mutate)


def change_candidate_execution_boundary(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        route = observation.get("route")
        if not isinstance(route, dict):
            raise AuditError("candidate observation has no route")
        route["execution_boundary"] = "forged-execution-boundary"

    reseal_candidate_observation_pair(bundle, root, mutate)


def add_control_destination_and_carrier(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        route = observation.get("route")
        source = route.get("source") if isinstance(route, dict) else None
        if not isinstance(route, dict) or not isinstance(source, dict):
            raise AuditError("control observation has no source route")
        destination = copy.deepcopy(source)
        destination["instance_id"] = "forged-control-destination"
        route["destination"] = destination
        route["carrier"] = {
            "implementation": "forged-carrier",
            "implementation_version": "1",
            "mode": "forged",
        }

    reseal_control_observation_pair(bundle, root, mutate)


def add_conflicting_final_file_probe(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        case = observed_case(observation, "rename-object-identity")
        renamed_path = list(b"renamed.bin")
        matches = []
        for event in case.get("events", []):
            body = event.get("body") if isinstance(event, dict) else None
            data = body.get("data") if isinstance(body, dict) else None
            if (
                isinstance(event, dict)
                and event.get("phase") == "final_observation"
                and isinstance(body, dict)
                and body.get("kind") == "file_probe"
                and isinstance(data, dict)
                and data.get("path") == renamed_path
            ):
                matches.append(event)
        if len(matches) != 1:
            raise AuditError(
                f"expected one final renamed.bin probe, found {len(matches)}"
            )
        expected = matches[0]
        conflicting = copy.deepcopy(expected)
        entry = conflicting["body"]["data"]["entry"]
        entry_data = entry.get("data") if isinstance(entry, dict) else None
        if not isinstance(entry_data, dict) or entry.get("kind") != "file":
            raise AuditError("final renamed.bin probe is not a file")
        replacement = b"evil"
        entry_data["bytes"] = list(replacement)
        entry_data["size"] = len(replacement)
        entry_data["sha256"] = hashlib.sha256(replacement).hexdigest()
        case["events"].insert(case["events"].index(expected), conflicting)
        resequence(case)

    reseal_candidate_observation_pair(bundle, root, mutate)


def replace_cell_normalized_cache(bundle: dict[str, Any], _: Path) -> None:
    selected_cell(bundle)["normalized_semantics_sha256"] = "0" * 64


def replace_aggregate_digest(bundle: dict[str, Any], _: Path) -> None:
    bundle["normalized_semantics_sha256"] = "0" * 64


def change_excluded_run_metadata(bundle: dict[str, Any], root: Path) -> None:
    def mutate(child: dict[str, Any], _: Path) -> None:
        child["bundle_id"] = "stage3a-benign-equivalent-run-metadata"
        child["started_at_unix_ms"] += 1
        child["finished_at_unix_ms"] += 1

    reseal_child_pair(bundle, root, mutate)


def reorder_assertion_set(bundle: dict[str, Any], root: Path) -> None:
    def mutate(child: dict[str, Any], _: Path) -> None:
        case = next(case for case in child["cases"] if case["case_id"] == "read-write-offset")
        case["assertions"].reverse()

    reseal_child_pair(bundle, root, mutate)


def reseal_unattested_observation_host(bundle: dict[str, Any], root: Path) -> None:
    def mutate(observation: dict[str, Any]) -> None:
        route = observation.get("route")
        source = route.get("source") if isinstance(route, dict) else None
        host_id = source.get("host_id") if isinstance(source, dict) else None
        if not isinstance(host_id, str) or not host_id:
            raise AuditError("candidate observation has no source host_id")
        source["host_id"] = f"{host_id}-unattested-audit"

    reseal_candidate_observation_pair(bundle, root, mutate)


MutationFunction = Callable[[dict[str, Any], Path], None]


@dataclass(frozen=True)
class Mutation:
    mutation_id: str
    category: str
    expected_disposition: str
    reason: str
    expected_finding_codes: tuple[str, ...]
    mutate: MutationFunction

    def preclassification(self) -> dict[str, Any]:
        return {
            "id": self.mutation_id,
            "category": self.category,
            "expected_disposition": self.expected_disposition,
            "reason": self.reason,
            "expected_finding_codes": list(self.expected_finding_codes),
        }


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        "omit-required-runtime-route",
        SEMANTIC_DEFECT,
        REJECT,
        "A claim cannot remain accepted after one registered runtime direction and all three stability runs are removed.",
        ("incomplete-stage3a-cross-runtime-matrix",),
        remove_required_route,
    ),
    Mutation(
        "raw-observation-logical-offset-divergence",
        SEMANTIC_DEFECT,
        REJECT,
        "A fully resealed candidate observation cannot change the returned logical offset derived by the independent oracle.",
        (CHILD_BUNDLE_REJECTION,),
        alter_observed_read_offset,
    ),
    Mutation(
        "raw-observation-duplicate-append",
        SEMANTIC_DEFECT,
        REJECT,
        "A fully resealed candidate observation with a second append call must be rejected by the independently derived exactly-once rule.",
        (CHILD_BUNDLE_REJECTION,),
        duplicate_observed_append,
    ),
    Mutation(
        "raw-observation-read-content-digest-drift",
        SEMANTIC_DEFECT,
        REJECT,
        "A fully resealed returned read digest must be independently recomputed from raw file bytes and operations.",
        (CHILD_BUNDLE_REJECTION,),
        change_returned_read_content_digest,
    ),
    Mutation(
        "raw-observation-mutation-content-digest-drift",
        SEMANTIC_DEFECT,
        REJECT,
        "A fully resealed returned mutation digest must be independently recomputed from raw file bytes and operations.",
        (CHILD_BUNDLE_REJECTION,),
        change_returned_mutation_content_digest,
    ),
    Mutation(
        "raw-observation-rename-content-digest-drift",
        SEMANTIC_DEFECT,
        REJECT,
        "A fully resealed returned rename digest must remain bound to the independently replayed file content.",
        (CHILD_BUNDLE_REJECTION,),
        change_returned_rename_content_digest,
    ),
    Mutation(
        "raw-observation-safe-point-identity-drift",
        SEMANTIC_DEFECT,
        REJECT,
        "Prepare, freeze, and commit must bind one safe-point identity after the observation is fully resealed.",
        (CHILD_BUNDLE_REJECTION,),
        change_safe_point_identity,
    ),
    Mutation(
        "raw-observation-snapshot-identity-drift",
        SEMANTIC_DEFECT,
        REJECT,
        "Export and restore must bind one snapshot identity after the observation is fully resealed.",
        (CHILD_BUNDLE_REJECTION,),
        change_snapshot_identity,
    ),
    Mutation(
        "raw-observation-post-handoff-source-actor",
        SEMANTIC_DEFECT,
        REJECT,
        "Successful work after CommitHandoff must execute at the resumed destination, not the source runtime.",
        (CHILD_BUNDLE_REJECTION,),
        change_post_handoff_operation_actor,
    ),
    Mutation(
        "raw-observation-resume-context-drift",
        SEMANTIC_DEFECT,
        REJECT,
        "ResumeDestination must retain its destination-execution phase and allowed actor after full resealing.",
        (CHILD_BUNDLE_REJECTION,),
        change_resume_context,
    ),
    Mutation(
        "raw-observation-route-restart",
        SEMANTIC_DEFECT,
        REJECT,
        "A fully resealed Stage 3A candidate cannot replace the declared handoff topology with restart.",
        (CHILD_BUNDLE_REJECTION,),
        change_candidate_route_to_restart,
    ),
    Mutation(
        "raw-observation-runtime-lineage-drift",
        SEMANTIC_DEFECT,
        REJECT,
        "A fully resealed raw endpoint cannot drift from the typed source and destination runtime scope.",
        (CHILD_BUNDLE_REJECTION,),
        change_candidate_runtime_identity,
    ),
    Mutation(
        "raw-observation-execution-boundary-drift",
        SEMANTIC_DEFECT,
        REJECT,
        "A fully resealed raw execution boundary must remain bound to the typed handoff boundary.",
        (CHILD_BUNDLE_REJECTION,),
        change_candidate_execution_boundary,
    ),
    Mutation(
        "raw-control-extra-destination-carrier",
        SEMANTIC_DEFECT,
        REJECT,
        "The uninterrupted control cannot acquire a destination endpoint or compute carrier after full resealing.",
        (CHILD_BUNDLE_REJECTION,),
        add_control_destination_and_carrier,
    ),
    Mutation(
        "raw-observation-conflicting-final-file-probe",
        SEMANTIC_DEFECT,
        REJECT,
        "Two final raw facts for one pathname cannot be collapsed with last-write-wins, even when the later probe matches the expected file.",
        (CHILD_BUNDLE_REJECTION,),
        add_conflicting_final_file_probe,
    ),
    Mutation(
        "replace-cell-normalized-cache",
        INTEGRITY_TAMPER,
        REJECT,
        "A producer-supplied per-cell normalized cache is advisory and must differ from the outer verifier's recomputation.",
        ("stage3a-cell-normalization-mismatch",),
        replace_cell_normalized_cache,
    ),
    Mutation(
        "replace-aggregate-normalization",
        INTEGRITY_TAMPER,
        REJECT,
        "A producer-supplied aggregate digest cannot substitute for the digest independently recomputed from all cells.",
        ("stage3a-cross-runtime-aggregate-normalization-mismatch",),
        replace_aggregate_digest,
    ),
    Mutation(
        "change-excluded-run-metadata",
        BENIGN_EQUIVALENT,
        ACCEPT_EQUIVALENT,
        "Bundle IDs and wall-clock timestamps are intentionally excluded from resource semantics.",
        (),
        change_excluded_run_metadata,
    ),
    Mutation(
        "reorder-semantic-assertion-set",
        BENIGN_EQUIVALENT,
        ACCEPT_EQUIVALENT,
        "Producer assertions are diagnostic noise for regular-file semantics; reordering their set cannot change the raw-observation oracle result.",
        (),
        reorder_assertion_set,
    ),
    Mutation(
        "reseal-unattested-observation-host",
        TRUST_BOUNDARY,
        ACCEPT_BOUNDARY,
        "The oracle derives resource semantics from raw facts but does not attest the producer-supplied observation endpoint identity; a coherently resealed host identifier remains an explicit capture-provenance boundary.",
        (),
        reseal_unattested_observation_host,
    ),
)


def corpus_manifest() -> list[dict[str, Any]]:
    return [mutation.preclassification() for mutation in MUTATIONS]


def corpus_sha256() -> str:
    encoded = json.dumps(
        corpus_manifest(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def observed_verdict(
    mutation: Mutation,
    completed: subprocess.CompletedProcess[str],
    codes: list[str],
    nested_child_codes: list[str] | tuple[str, ...] = (),
) -> tuple[str, bool]:
    if completed.returncode == 0:
        return ACCEPT, mutation.expected_disposition in (
            ACCEPT_EQUIVALENT,
            ACCEPT_BOUNDARY,
        )
    if completed.returncode == 1:
        matched_codes = all(code in codes for code in mutation.expected_finding_codes)
        nested_oracle_matched = (
            CHILD_BUNDLE_REJECTION not in mutation.expected_finding_codes
            or SEMANTIC_ORACLE_REJECTION in nested_child_codes
        )
        return (
            REJECT,
            mutation.expected_disposition == REJECT
            and matched_codes
            and nested_oracle_matched,
        )
    return f"verifier-error-{completed.returncode}", False


def audit(verifier: Path, artifact_root: Path) -> dict[str, Any]:
    verifier = verifier.resolve(strict=True)
    artifact_root = artifact_root.resolve(strict=True)
    if not verifier.is_file() or verifier.is_symlink():
        raise AuditError(f"verifier is not a regular non-symlink file: {verifier}")
    if not artifact_root.is_dir() or artifact_root.is_symlink():
        raise AuditError(
            f"artifact root is not a non-symlink directory: {artifact_root}"
        )
    baseline = run_verifier(verifier, artifact_root)
    if baseline.returncode != 0:
        raise AuditError(
            "accepted baseline failed before mutation audit: "
            f"stdout={baseline.stdout!r} stderr={baseline.stderr!r}"
        )

    entries: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="visa-stage3a-verifier-audit-") as temporary:
        temporary_root = Path(temporary)
        for mutation in MUTATIONS:
            mutated_root = temporary_root / mutation.mutation_id
            shutil.copytree(artifact_root, mutated_root)
            bundle_path = mutated_root / BUNDLE_NAME
            bundle = load_object(bundle_path)
            mutation.mutate(bundle, mutated_root)
            write_object(bundle_path, bundle)
            completed = run_verifier(verifier, mutated_root)
            codes = finding_codes(completed) if completed.returncode == 1 else []
            nested_child = None
            nested_child_codes: list[str] = []
            if CHILD_BUNDLE_REJECTION in mutation.expected_finding_codes:
                nested_child = run_child_verifier(verifier, bundle, mutated_root)
                if nested_child.returncode == 1:
                    nested_child_codes = finding_codes(nested_child)
            verdict, matched = observed_verdict(
                mutation,
                completed,
                codes,
                nested_child_codes,
            )
            entry = mutation.preclassification()
            entry.update(
                {
                    "exit_code": completed.returncode,
                    "finding_codes": codes,
                    "nested_child_exit_code": (
                        nested_child.returncode if nested_child is not None else None
                    ),
                    "nested_child_finding_codes": nested_child_codes,
                    "nested_semantic_oracle_rejection_observed": (
                        SEMANTIC_ORACLE_REJECTION in nested_child_codes
                        if nested_child is not None
                        else None
                    ),
                    "observed_verdict": verdict,
                    "matched_preclassification": matched,
                }
            )
            entries.append(entry)

    def count(category: str, verdict: str) -> tuple[int, int]:
        selected = [entry for entry in entries if entry["category"] == category]
        matched = sum(
            entry["matched_preclassification"]
            and entry["observed_verdict"] == verdict
            for entry in selected
        )
        return len(selected), matched

    semantic_n, semantic_rejected = count(SEMANTIC_DEFECT, REJECT)
    integrity_n, integrity_rejected = count(INTEGRITY_TAMPER, REJECT)
    benign_n, benign_accepted = count(BENIGN_EQUIVALENT, ACCEPT)
    boundary_n, boundary_recorded = count(TRUST_BOUNDARY, ACCEPT)
    nested_oracle_entries = [
        entry
        for entry in entries
        if CHILD_BUNDLE_REJECTION in entry["expected_finding_codes"]
    ]
    nested_oracle_rejected = sum(
        entry["nested_semantic_oracle_rejection_observed"]
        for entry in nested_oracle_entries
    )
    matched = sum(entry["matched_preclassification"] for entry in entries)
    report = {
        "schema": SCHEMA,
        "verifier": str(verifier),
        "verifier_sha256": file_sha256(verifier),
        "audit_script_sha256": file_sha256(Path(__file__).resolve()),
        "production_verifier_command": "visa-conformance stage3a-cross-runtime",
        "classification_locked_before_execution": True,
        "corpus_sha256": corpus_sha256(),
        "corpus_sha256_scope": "preclassification-manifest-only",
        "baseline_bundle_sha256": hashlib.sha256(
            (artifact_root / BUNDLE_NAME).read_bytes()
        ).hexdigest(),
        "entries": entries,
        "summary": {
            "n": len(entries),
            "matched_preclassification": matched,
            "semantic_defects": {
                "n": semantic_n,
                "rejected": semantic_rejected,
            },
            "integrity_tampers": {
                "n": integrity_n,
                "rejected": integrity_rejected,
            },
            "benign_equivalents": {
                "n": benign_n,
                "accepted": benign_accepted,
            },
            "trusted_observation_boundaries": {
                "n": boundary_n,
                "recorded": boundary_recorded,
            },
            "nested_semantic_oracle_rejections": {
                "n": len(nested_oracle_entries),
                "rejected": nested_oracle_rejected,
            },
        },
    }
    if matched != len(entries):
        raise AuditError(f"verifier mutation audit failed: {report}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = audit(arguments.verifier, arguments.artifact_root)
        arguments.out.parent.mkdir(parents=True, exist_ok=True)
        arguments.out.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (AuditError, OSError, KeyError, IndexError, StopIteration, TypeError) as error:
        print(f"Stage 3A cross-runtime verifier audit failed: {error}", file=sys.stderr)
        return 1
    summary = report["summary"]
    print(
        "Stage 3A cross-runtime verifier audit: "
        f"{summary['matched_preclassification']}/{summary['n']} dispositions matched; "
        f"semantic defects {summary['semantic_defects']['rejected']}/"
        f"{summary['semantic_defects']['n']} rejected; "
        f"nested semantic oracle rejections "
        f"{summary['nested_semantic_oracle_rejections']['rejected']}/"
        f"{summary['nested_semantic_oracle_rejections']['n']} rejected; "
        f"benign equivalents {summary['benign_equivalents']['accepted']}/"
        f"{summary['benign_equivalents']['n']} accepted; "
        f"trust boundaries {summary['trusted_observation_boundaries']['recorded']}/"
        f"{summary['trusted_observation_boundaries']['n']} recorded"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
