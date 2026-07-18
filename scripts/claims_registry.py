"""Strict parser for the mechanical project-claim identity and lifecycle index."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from claim_archive import (
    ArchiveError,
    validate_closure_record,
    validate_semantic_contracts,
)


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = ROOT / "claims/registry.json"
CANONICAL_DOCS = {
    "README.md",
    "docs/ARCHITECTURE.md",
    "docs/DEVELOPMENT.md",
    "docs/RESEARCH.md",
    "docs/ROADMAP.md",
    "docs/VALIDATION.md",
    "docs/VISION.md",
}
TOP_LEVEL_KEYS = {"schema", "claims", "workflow_bindings"}
CLAIM_KEYS = {
    "acceptance_ref",
    "id",
    "implementation_refs",
    "predecessor_ids",
    "scope_ref",
    "status",
    "track",
    "validation_ref",
}
REFERENCE_KEYS = {"path", "heading"}
HISTORICAL_ACCEPTANCE_KEYS = {"kind", "path", "heading"}
ARCHIVE_ACCEPTANCE_KEYS = {
    "evidence_axes",
    "heading",
    "kind",
    "path",
    "receipt_sha256",
    "semantic_contracts",
    "source_repositories",
    "workflow_artifacts",
}
BINDING_KEYS = {"id", "job", "matrix_lane", "tier", "artifact", "claims"}
BINDING_CLAIM_KEYS = {"id", "role"}
STATUSES = {"candidate", "earned", "retired"}
ROLES = {"regresses", "required", "supports"}
GRANDFATHERED_EARNED_CLAIMS = {
    "bounded-joint-handoff-refinement-v1",
    "bounded-logical-request-continuity",
    "bounded-regular-file-continuity",
    "cooperative-stateful-component-handoff",
    "cross-execution-path-portability",
    "emulated-cross-isa-continuity-v1",
    "named-target-substrate-continuity-v1",
    "strict-cross-runtime-continuity",
}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
README_START = "<!-- claims-registry:start -->"
README_END = "<!-- claims-registry:end -->"
README_ROW_RE = re.compile(r"^\| `([^`]+)` \| `([^`]+)` \|$")
RECEIPT_ROOT = PurePosixPath("claims/receipts")
ARCHIVE_MANIFEST_ROOT = PurePosixPath("claims/archive-manifests")


class RegistryError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RegistryError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RegistryError(f"cannot parse {label} {path}: {error}") from error


def load_registry(path: Path = DEFAULT_REGISTRY) -> dict[str, Any]:
    require(
        not path.is_symlink() and path.is_file(),
        f"claim registry must be a regular file: {path}",
    )
    loaded = load_json(path, "claim registry")
    require(isinstance(loaded, dict), "claim registry must contain one JSON object")
    return loaded


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    require(set(value) == expected, f"{label} keys drifted: {sorted(value)}")


def safe_relative_path(value: Any, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a nonempty string")
    path = PurePosixPath(value)
    require(
        not path.is_absolute()
        and value == path.as_posix()
        and value not in {".", ".."}
        and ".." not in path.parts,
        f"{label} is not a safe repository-relative path: {value!r}",
    )
    return value


def canonical_section(root: Path, reference: Any, label: str) -> str:
    require(isinstance(reference, dict), f"{label} must be an object")
    exact_keys(reference, REFERENCE_KEYS, label)
    relative = safe_relative_path(reference["path"], f"{label}.path")
    require(relative in CANONICAL_DOCS, f"{label} must name a canonical narrative document")
    heading = reference["heading"]
    require(isinstance(heading, str) and heading, f"{label}.heading must be nonempty")
    path = root / relative
    require_regular_repository_file(root, relative, label)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise RegistryError(f"cannot read {relative}: {error}") from error

    matches: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        match = HEADING_RE.match(line)
        if match and match.group(2) == heading:
            matches.append((index, len(match.group(1))))
    require(len(matches) == 1, f"{label} heading must occur exactly once: {heading!r}")
    start, level = matches[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        match = HEADING_RE.match(lines[index])
        if match and len(match.group(1)) <= level:
            end = index
            break
    return "\n".join(lines[start:end])


def require_claim_token(section: str, claim_id: str, label: str) -> None:
    require(f"`{claim_id}`" in section, f"{claim_id} is absent as an exact token from {label}")


def require_regular_repository_file(root: Path, relative: str, label: str) -> None:
    root_resolved = root.resolve(strict=True)
    cursor = root
    for part in PurePosixPath(relative).parts:
        cursor /= part
        require(not cursor.is_symlink(), f"{label} traverses a symlink: {relative}")
    try:
        resolved = cursor.resolve(strict=True)
    except OSError as error:
        raise RegistryError(f"{label} is absent: {relative}: {error}") from error
    require(resolved.is_relative_to(root_resolved), f"{label} escapes the repository: {relative}")
    require(resolved.is_file(), f"{label} must name a regular file: {relative}")


def repository_entry_exists(root: Path, relative: str, label: str) -> bool:
    cursor = root
    for part in PurePosixPath(relative).parts:
        cursor /= part
        try:
            cursor.lstat()
        except FileNotFoundError:
            return False
        except OSError as error:
            raise RegistryError(f"cannot inspect {label} {relative}: {error}") from error
        if cursor.is_symlink():
            return True
    return True


def validate_acceptance_ref(
    root: Path,
    claim: dict[str, Any],
) -> None:
    claim_id = claim["id"]
    status = claim["status"]
    predecessors = claim["predecessor_ids"]
    acceptance = claim["acceptance_ref"]
    label = f"{claim_id}.acceptance_ref"
    require(isinstance(acceptance, dict), f"{label} must be an object")

    if claim_id in GRANDFATHERED_EARNED_CLAIMS:
        exact_keys(acceptance, HISTORICAL_ACCEPTANCE_KEYS, label)
        require(
            status in {"earned", "retired"},
            f"grandfathered claim {claim_id} cannot return to candidate",
        )
        require(
            not predecessors,
            f"{claim_id} historical acceptance cannot have predecessors",
        )
        kind = acceptance["kind"]
        relative = safe_relative_path(acceptance["path"], f"{label}.path")
        heading = acceptance["heading"]
        require(
            kind == "canonical-validation",
            f"{claim_id} historical acceptance kind drifted",
        )
        section = canonical_section(
            root,
            {"path": relative, "heading": heading},
            f"{claim_id}.acceptance_ref",
        )
        require_claim_token(section, claim_id, f"{claim_id}.acceptance_ref")
        return

    exact_keys(acceptance, ARCHIVE_ACCEPTANCE_KEYS, label)
    kind = acceptance["kind"]
    relative = safe_relative_path(acceptance["path"], f"{label}.path")
    heading = acceptance["heading"]
    expected_receipt = (RECEIPT_ROOT / f"{claim_id}.json").as_posix()
    expected_manifest = (ARCHIVE_MANIFEST_ROOT / f"{claim_id}.json").as_posix()
    require(
        relative == expected_receipt and heading is None,
        f"{claim_id} receipt path drifted",
    )

    for field in ("evidence_axes", "source_repositories", "workflow_artifacts"):
        values = acceptance[field]
        require(
            isinstance(values, list)
            and values
            and all(isinstance(value, str) and value for value in values),
            f"{claim_id} {field} must be a nonempty string array",
        )
        require(
            values == sorted(set(values)),
            f"{claim_id} {field} must be unique and sorted",
        )
    require(
        all(ID_RE.fullmatch(axis) for axis in acceptance["evidence_axes"]),
        f"{claim_id} evidence_axes contain an invalid identity",
    )
    require(
        all(
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            for repository in acceptance["source_repositories"]
        ),
        f"{claim_id} source_repositories contain an invalid repository",
    )
    require(
        all(
            PurePosixPath(artifact).name == artifact
            and artifact not in {".", ".."}
            for artifact in acceptance["workflow_artifacts"]
        ),
        f"{claim_id} workflow_artifacts contain an invalid asset name",
    )
    if status == "candidate":
        require(
            kind == "pending-permanent-archive-receipt",
            f"{claim_id} candidate guard drifted",
        )
        require(
            acceptance["receipt_sha256"] is None,
            f"{claim_id} candidate receipt digest must remain null",
        )
        require(
            not repository_entry_exists(root, relative, label),
            f"{claim_id} candidate has an unconsumed closure receipt",
        )
        require(
            not repository_entry_exists(root, expected_manifest, label),
            f"{claim_id} candidate has an unconsumed archive manifest",
        )
        try:
            validate_semantic_contracts(root, claim, acceptance)
        except ArchiveError as error:
            raise RegistryError(
                f"{claim_id} semantic contract is invalid: {error}"
            ) from error
        return

    require(
        kind == "permanent-archive-receipt",
        f"{claim_id} non-historical claim lacks a permanent receipt",
    )
    receipt_sha256 = acceptance["receipt_sha256"]
    require(
        isinstance(receipt_sha256, str) and SHA256_RE.fullmatch(receipt_sha256),
        f"{claim_id} permanent receipt digest is invalid",
    )
    try:
        validate_semantic_contracts(root, claim, acceptance)
        validate_closure_record(root, claim, acceptance)
    except ArchiveError as error:
        raise RegistryError(
            f"{claim_id} permanent archive closure is invalid: {error}"
        ) from error


def check_lineage(claims: dict[str, dict[str, Any]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(claim_id: str) -> None:
        if claim_id in visiting:
            raise RegistryError(f"claim predecessor graph contains a cycle at {claim_id}")
        if claim_id in visited:
            return
        visiting.add(claim_id)
        for predecessor in claims[claim_id]["predecessor_ids"]:
            require(predecessor in claims, f"{claim_id} has unknown predecessor {predecessor}")
            require(predecessor != claim_id, f"{claim_id} cannot be its own predecessor")
            visit(predecessor)
        visiting.remove(claim_id)
        visited.add(claim_id)

    for claim_id in claims:
        visit(claim_id)


def read_readme_index(root: Path) -> list[tuple[str, str]]:
    require_regular_repository_file(root, "README.md", "README claim index")
    try:
        lines = (root / "README.md").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise RegistryError(f"cannot read README claim index: {error}") from error
    require(lines.count(README_START) == 1, "README claim index start marker drifted")
    require(lines.count(README_END) == 1, "README claim index end marker drifted")
    start = lines.index(README_START)
    end = lines.index(README_END)
    require(start < end, "README claim index markers are reversed")
    body = lines[start + 1 : end]
    require(
        body[:2] == ["| Claim ID | Status |", "| --- | --- |"],
        "README claim index header drifted",
    )
    rows: list[tuple[str, str]] = []
    for line in body[2:]:
        match = README_ROW_RE.fullmatch(line)
        require(match is not None, f"README claim index contains a noncanonical row: {line!r}")
        rows.append((match.group(1), match.group(2)))
    require(rows, "README claim index has no machine-readable rows")
    return rows


def validate_registry(registry: dict[str, Any], root: Path = ROOT) -> None:
    exact_keys(registry, TOP_LEVEL_KEYS, "claim registry")
    require(registry["schema"] == "visa.project-claim-registry.v1", "unknown registry schema")
    raw_claims = registry["claims"]
    require(isinstance(raw_claims, list) and raw_claims, "claims must be a nonempty array")

    claims: dict[str, dict[str, Any]] = {}
    claim_order: list[str] = []
    for index, claim in enumerate(raw_claims):
        label = f"claims[{index}]"
        require(isinstance(claim, dict), f"{label} must be an object")
        exact_keys(claim, CLAIM_KEYS, label)
        claim_id = claim["id"]
        require(
            isinstance(claim_id, str) and ID_RE.fullmatch(claim_id),
            f"invalid claim id: {claim_id!r}",
        )
        require(claim_id not in claims, f"duplicate claim id: {claim_id}")
        require(isinstance(claim["track"], str) and claim["track"], f"{claim_id} track is empty")
        status = claim["status"]
        require(
            isinstance(status, str) and status in STATUSES,
            f"{claim_id} has invalid status",
        )
        claim_order.append(claim_id)
        claims[claim_id] = claim

        for kind in ("scope_ref", "validation_ref"):
            section = canonical_section(root, claim[kind], f"{claim_id}.{kind}")
            require_claim_token(section, claim_id, f"{claim_id}.{kind}")

        implementation_refs = claim["implementation_refs"]
        require(
            isinstance(implementation_refs, list)
            and implementation_refs
            and all(isinstance(item, str) for item in implementation_refs),
            f"{claim_id} implementation_refs must be a nonempty string array",
        )
        require(
            implementation_refs == sorted(set(implementation_refs)),
            f"{claim_id} implementation_refs must be unique and sorted",
        )
        for implementation in implementation_refs:
            relative = safe_relative_path(
                implementation, f"{claim_id}.implementation_refs"
            )
            require_regular_repository_file(
                root, relative, f"{claim_id}.implementation_refs"
            )

        predecessors = claim["predecessor_ids"]
        require(
            isinstance(predecessors, list)
            and all(isinstance(item, str) for item in predecessors),
            f"{claim_id} predecessor_ids must be a string array",
        )
        require(
            predecessors == sorted(set(predecessors)),
            f"{claim_id} predecessor_ids must be unique and sorted",
        )
        validate_acceptance_ref(root, claim)

    require(claim_order == sorted(claim_order), "claims must be sorted by id")
    check_lineage(claims)
    require(
        GRANDFATHERED_EARNED_CLAIMS <= set(claims),
        "a grandfathered earned claim was removed from the registry",
    )
    for claim_id in GRANDFATHERED_EARNED_CLAIMS:
        require(
            claims[claim_id]["status"] in {"earned", "retired"},
            f"grandfathered claim {claim_id} cannot return to candidate",
        )

    raw_bindings = registry["workflow_bindings"]
    require(isinstance(raw_bindings, list) and raw_bindings, "workflow_bindings must be nonempty")
    binding_ids: list[str] = []
    roles_by_claim: dict[str, list[str]] = {claim_id: [] for claim_id in claims}
    bound_artifacts_by_claim: dict[str, set[str]] = {
        claim_id: set() for claim_id in claims
    }
    for index, binding in enumerate(raw_bindings):
        label = f"workflow_bindings[{index}]"
        require(isinstance(binding, dict), f"{label} must be an object")
        exact_keys(binding, BINDING_KEYS, label)
        binding_id = binding["id"]
        require(
            isinstance(binding_id, str) and ID_RE.fullmatch(binding_id),
            f"invalid binding id: {binding_id!r}",
        )
        require(binding_id not in binding_ids, f"duplicate workflow binding: {binding_id}")
        binding_ids.append(binding_id)
        require(isinstance(binding["job"], str) and binding["job"], f"{binding_id} job is empty")
        require(
            binding["matrix_lane"] is None
            or (isinstance(binding["matrix_lane"], str) and binding["matrix_lane"]),
            f"{binding_id} matrix_lane is invalid",
        )
        require(
            binding["tier"] is None
            or (isinstance(binding["tier"], str) and binding["tier"]),
            f"{binding_id} tier is invalid",
        )
        require(
            binding["artifact"] is None
            or (isinstance(binding["artifact"], str) and binding["artifact"]),
            f"{binding_id} artifact is invalid",
        )
        bound_claims = binding["claims"]
        require(isinstance(bound_claims, list) and bound_claims, f"{binding_id} claims are empty")
        observed: list[tuple[str, str]] = []
        observed_ids: set[str] = set()
        for claim_binding in bound_claims:
            require(isinstance(claim_binding, dict), f"{binding_id} claim binding is not an object")
            exact_keys(claim_binding, BINDING_CLAIM_KEYS, f"{binding_id} claim binding")
            claim_id = claim_binding["id"]
            role = claim_binding["role"]
            require(
                isinstance(claim_id, str) and claim_id in claims,
                f"{binding_id} references unknown claim {claim_id!r}",
            )
            require(
                claim_id not in observed_ids,
                f"{binding_id} binds {claim_id} more than once",
            )
            require(
                isinstance(role, str) and role in ROLES,
                f"{binding_id} has invalid role {role!r}",
            )
            require(
                claims[claim_id]["status"] != "retired",
                f"{binding_id} binds retired claim {claim_id}",
            )
            require(
                claims[claim_id]["status"] != "candidate" or role != "regresses",
                f"{binding_id} cannot regress unearned candidate {claim_id}",
            )
            observed_ids.add(claim_id)
            observed.append((claim_id, role))
            roles_by_claim[claim_id].append(role)
            if isinstance(binding["artifact"], str):
                bound_artifacts_by_claim[claim_id].add(binding["artifact"])
        require(observed == sorted(observed), f"{binding_id} claim bindings must be sorted")
    require(binding_ids == sorted(binding_ids), "workflow_bindings must be sorted by id")

    for claim_id, claim in claims.items():
        roles = roles_by_claim[claim_id]
        acceptance = claim["acceptance_ref"]
        if acceptance["kind"] in {
            "pending-permanent-archive-receipt",
            "permanent-archive-receipt",
        }:
            require(
                bound_artifacts_by_claim[claim_id]
                == set(acceptance["workflow_artifacts"]),
                f"{claim_id} acceptance artifacts differ from bound CI evidence",
            )
        if claim["status"] == "candidate":
            require("required" in roles, f"candidate {claim_id} has no required CI evidence")
        elif claim["status"] == "earned":
            require(
                any(role in {"regresses", "supports"} for role in roles),
                f"earned {claim_id} has no CI regression or support binding",
            )
        else:
            require(not roles, f"retired {claim_id} remains bound to CI")

    expected_readme = [(item["id"], item["status"]) for item in raw_claims]
    require(read_readme_index(root) == expected_readme, "README claim index differs from registry")
