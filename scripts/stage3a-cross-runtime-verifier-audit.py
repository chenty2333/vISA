#!/usr/bin/env python3
"""Preclassified black-box corpus for the production Stage 3A outer verifier."""

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


SCHEMA = "visa.stage3a-cross-runtime-verifier-audit.v2"
BUNDLE_NAME = "stage3a-cross-runtime-evidence.json"
TARGET_CELL_ID = "s3a.cross.wacogo-to-wacogo.regular-file"

SEMANTIC_DEFECT = "semantic-defect"
INTEGRITY_TAMPER = "integrity-tamper"
BENIGN_EQUIVALENT = "benign-equivalent"
TRUST_BOUNDARY = "trusted-observation-boundary"

REJECT = "reject"
ACCEPT = "accept"
ACCEPT_EQUIVALENT = "accept-equivalent"
ACCEPT_BOUNDARY = "accept-boundary"


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


def substitute_semantic_assertion(bundle: dict[str, Any], root: Path) -> None:
    def mutate(child: dict[str, Any], _: Path) -> None:
        case = next(case for case in child["cases"] if case["case_id"] == "read-write-offset")
        assertion = next(
            assertion
            for assertion in case["assertions"]
            if assertion["name"] == "logical_offset_preserved"
        )
        assertion["name"] = "logical_offset_reset"

    reseal_child_pair(bundle, root, mutate)


def alter_retained_observable(bundle: dict[str, Any], root: Path) -> None:
    def mutate(child: dict[str, Any], _: Path) -> None:
        case = next(case for case in child["cases"] if case["case_id"] == "read-write-offset")
        case["canonical_after_sha256"] = "0" * 64

    reseal_child_pair(bundle, root, mutate)


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


def contradict_raw_observation(bundle: dict[str, Any], root: Path) -> None:
    def mutate(child: dict[str, Any], child_root: Path) -> None:
        case = next(case for case in child["cases"] if case["case_id"] == "read-write-offset")
        trace_reference = next(
            artifact
            for artifact in case["artifacts"]
            if artifact["uri"].endswith("/trace.json")
        )
        trace_path = child_root / trace_reference["uri"]
        trace = load_object(trace_path)
        trace["observations"]["offset"] = 0
        encoded = write_object(trace_path, trace)
        reseal_reference(trace_reference, encoded)

    reseal_child_pair(bundle, root, mutate)


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
        "substitute-required-semantic-assertion",
        SEMANTIC_DEFECT,
        REJECT,
        "A fully resealed child cannot replace the required logical-offset assertion with an opposite semantic assertion.",
        ("invalid-stage3a-cross-runtime-child-bundle",),
        substitute_semantic_assertion,
    ),
    Mutation(
        "over-normalization-retained-observable",
        SEMANTIC_DEFECT,
        REJECT,
        "A validly encoded but different retained canonical digest must change independent normalization and diverge from the matrix.",
        (
            "stage3a-cell-normalization-mismatch",
            "stage3a-cross-runtime-semantic-divergence",
        ),
        alter_retained_observable,
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
        "The required assertions form a set, so serialization order is not an observable resource difference.",
        (),
        reorder_assertion_set,
    ),
    Mutation(
        "reseal-contradictory-raw-observation",
        TRUST_BOUNDARY,
        ACCEPT_BOUNDARY,
        "The outer verifier checks a fully resealed raw trace for integrity but does not independently reinterpret runner-authored case semantics; faithful capture remains an explicit trust assumption.",
        (),
        contradict_raw_observation,
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
    mutation: Mutation, completed: subprocess.CompletedProcess[str], codes: list[str]
) -> tuple[str, bool]:
    if completed.returncode == 0:
        return ACCEPT, mutation.expected_disposition in (
            ACCEPT_EQUIVALENT,
            ACCEPT_BOUNDARY,
        )
    if completed.returncode == 1:
        matched_codes = all(code in codes for code in mutation.expected_finding_codes)
        return REJECT, mutation.expected_disposition == REJECT and matched_codes
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
            verdict, matched = observed_verdict(mutation, completed, codes)
            entry = mutation.preclassification()
            entry.update(
                {
                    "exit_code": completed.returncode,
                    "finding_codes": codes,
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
        f"benign equivalents {summary['benign_equivalents']['accepted']}/"
        f"{summary['benign_equivalents']['n']} accepted; "
        f"trust boundaries {summary['trusted_observation_boundaries']['recorded']}/"
        f"{summary['trusted_observation_boundaries']['n']} recorded"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
