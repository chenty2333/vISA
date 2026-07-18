#!/usr/bin/env python3
"""Validate permanent project-claim receipts and their evidence archives."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import stat
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable


RECEIPT_SCHEMA = "visa.project-claim-closure.v2"
MANIFEST_SCHEMA = "visa.project-claim-archive.v1"
DEFINITION_SCHEMA = "visa.project-claim-definition.v1"
MANIFEST_MEMBER = "ARCHIVE-MANIFEST.json"
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
CLAIM_REGISTRY_PATH = "claims/registry.json"
CI_CLOSURE_JOB_NAME = "Exact-SHA qualification closure"
CI_JOB_COUNT = 12
CLAIM_WORKFLOW_ROLES = ("regresses", "required", "supports")
JOINT_SOURCE_LOCK_PATH = "third_party/joint-handoff-qualification/source-lock.json"
NEXUS_QUALIFICATION_LOCK_PATH = (
    "third_party/joint-handoff-qualification/nexus-qualification-lock.json"
)
ACCEPTED_SOURCE_STABLE_PATHS = (
    JOINT_SOURCE_LOCK_PATH,
    NEXUS_QUALIFICATION_LOCK_PATH,
)
RECEIPT_KEYS = {
    "schema",
    "claim_id",
    "claim_definition_sha256",
    "predecessor_ids",
    "accepted_source",
    "qualification",
    "archive",
    "second_copy",
}
MANIFEST_KEYS = {
    "schema",
    "claim_id",
    "claim_definition_sha256",
    "predecessor_ids",
    "accepted_source",
    "qualification",
    "actions_artifacts",
    "source_bundles",
    "evidence_axes",
    "members",
}
SOURCE_KEYS = {"repository", "revision", "tree"}
QUALIFICATION_KEYS = {
    "workflow_id",
    "workflow_path",
    "run_id",
    "run_attempt",
    "head_sha",
    "closure_job_id",
    "closure_job_name",
    "job_count",
}
ARCHIVE_KEYS = {
    "release_tag",
    "release_uri",
    "asset_name",
    "asset_size_bytes",
    "asset_sha256",
    "manifest_path",
    "manifest_sha256",
    "sha256sums_path",
    "sha256sums_sha256",
    "reverify_path",
    "reverify_sha256",
    "release_attestation",
}
ATTESTATION_KEYS = {"kind", "verification"}
SECOND_COPY_KEYS = {
    "kind",
    "record_id",
    "doi",
    "asset_name",
    "asset_size_bytes",
    "provider_checksum",
    "asset_sha256",
}
ACTION_KEYS = {
    "role",
    "artifact_id",
    "artifact_name",
    "path",
    "api_digest",
    "run_id",
    "run_attempt",
    "head_sha",
    "size_bytes",
    "expires_at",
}
BUNDLE_KEYS = {"id", "repository", "revision", "tree", "bundle_path", "bundle_ref"}
AXIS_KEYS = {"id", "claim_ids", "member_paths", "verifier"}
MEMBER_KEYS = {"path", "role", "media_type", "size_bytes", "sha256"}
CLAIM_DEFINITION_KEYS = {
    "id",
    "track",
    "scope_ref",
    "validation_ref",
    "implementation_refs",
    "predecessor_ids",
}
POLICY_KEYS = {"evidence_axes", "source_repositories", "workflow_artifacts"}
SEMANTIC_CONTRACT_KEYS = {"scope_sha256", "validation_sha256"}
SEMANTIC_CONTRACT_PATHS = {
    "scope": "docs/ROADMAP.md",
    "validation": "docs/VALIDATION.md",
}
PROMOTION_DOCUMENT_PATHS = {
    "README.md",
    "docs/ARCHITECTURE.md",
    "docs/DEVELOPMENT.md",
    "docs/RESEARCH.md",
    "docs/ROADMAP.md",
    "docs/VALIDATION.md",
    "docs/VISION.md",
}
REGISTRY_CLAIM_KEYS = {
    "acceptance_ref",
    "id",
    "implementation_refs",
    "predecessor_ids",
    "scope_ref",
    "status",
    "track",
    "validation_ref",
}
PERMANENT_ACCEPTANCE_KEYS = {
    "kind",
    "path",
    "heading",
    "receipt_sha256",
    "semantic_contracts",
    "evidence_axes",
    "source_repositories",
    "workflow_artifacts",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
REF_RE = re.compile(r"^refs/(heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]*$")
WORKFLOW_PATH_RE = re.compile(r"^\.github/workflows/[A-Za-z0-9._/-]+\.ya?ml$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024


class ArchiveError(RuntimeError):
    """A project-claim closure or archive violated its strict contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArchiveError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArchiveError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_bytes(data: bytes, label: str) -> Any:
    require(len(data) <= MAX_JSON_BYTES, f"{label} exceeds the size limit")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ArchiveError(f"cannot parse {label}: {error}") from error


def load_json_file(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ArchiveError(f"cannot read {label} {path}: {error}") from error
    value = load_json_bytes(data, label)
    require(isinstance(value, dict), f"{label} must contain one JSON object")
    return value, data


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == expected, f"{label} keys drifted: {sorted(value)}")
    return value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise ArchiveError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def safe_path(value: Any, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a nonempty string")
    require("\\" not in value and "\x00" not in value, f"{label} is not portable")
    path = PurePosixPath(value)
    require(
        not path.is_absolute()
        and path.as_posix() == value
        and value not in {".", ".."}
        and ".." not in path.parts
        and all(part not in {"", "."} for part in path.parts),
        f"unsafe {label}: {value!r}",
    )
    return value


def regular_repository_file(root: Path, relative: str, label: str) -> Path:
    safe_path(relative, f"{label} path")
    try:
        root_resolved = root.resolve(strict=True)
    except OSError as error:
        raise ArchiveError(f"cannot resolve repository root {root}: {error}") from error
    cursor = root
    for part in PurePosixPath(relative).parts:
        cursor /= part
        try:
            mode = cursor.lstat().st_mode
        except OSError as error:
            raise ArchiveError(f"cannot inspect {label} {relative}: {error}") from error
        require(not stat.S_ISLNK(mode), f"{label} traverses a symlink: {relative}")
    try:
        resolved = cursor.resolve(strict=True)
    except OSError as error:
        raise ArchiveError(f"cannot resolve {label} {relative}: {error}") from error
    require(
        resolved == root_resolved or root_resolved in resolved.parents,
        f"{label} escapes the repository",
    )
    require(stat.S_ISREG(resolved.stat().st_mode), f"{label} must be a regular file")
    return resolved


def nonempty_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and value, f"{label} must be a nonempty string")
    return value


def positive_int(value: Any, label: str) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and value > 0,
        f"{label} must be a positive integer",
    )
    return value


def digest_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value), f"{label} is invalid")
    return value


def git_sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and GIT_SHA_RE.fullmatch(value), f"{label} is invalid")
    return value


def release_tag(value: Any, label: str) -> str:
    tag = nonempty_string(value, label)
    require(ID_RE.fullmatch(tag) is not None, f"{label} is invalid")
    require(
        ".." not in tag
        and not tag.endswith(".")
        and not tag.endswith(".lock"),
        f"{label} is not a safe Git tag",
    )
    return tag


def github_timestamp(value: Any, label: str) -> datetime:
    timestamp = nonempty_string(value, label)
    require(timestamp.endswith("Z"), f"{label} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError as error:
        raise ArchiveError(f"{label} is invalid: {error}") from error
    require(parsed.tzinfo == timezone.utc, f"{label} is not UTC")
    return parsed


def sorted_unique_strings(value: Any, label: str, *, nonempty: bool = True) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    require(
        (not nonempty or value) and all(isinstance(item, str) and item for item in value),
        f"{label} must contain nonempty strings",
    )
    require(value == sorted(set(value)), f"{label} must be unique and sorted")
    return value


def github_slug(value: Any, label: str) -> str:
    slug = nonempty_string(value, label)
    parts = slug.split("/")
    require(
        len(parts) == 2
        and all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts),
        f"{label} must be an owner/repository slug",
    )
    return slug


def github_source_url(slug: str) -> str:
    return f"https://github.com/{slug}.git"


def zenodo_record_uri(record_id: int) -> str:
    return f"https://zenodo.org/api/records/{record_id}"


def zenodo_asset_uri(record_id: int, asset_name: str) -> str:
    return (
        f"https://zenodo.org/api/records/{record_id}/files/"
        f"{urllib.parse.quote(asset_name, safe='')}/content"
    )


def claim_definition_sha256(claim: dict[str, Any], acceptance: dict[str, Any]) -> str:
    """Digest the stable claim definition and its evidence-selection policy."""

    require(isinstance(claim, dict), "claim definition must be an object")
    missing = CLAIM_DEFINITION_KEYS - set(claim)
    require(not missing, f"claim definition is missing keys: {sorted(missing)}")
    require(isinstance(acceptance, dict), "claim acceptance policy must be an object")
    missing_policy = POLICY_KEYS - set(acceptance)
    require(not missing_policy, f"claim acceptance policy is missing keys: {sorted(missing_policy)}")
    claim_id = nonempty_string(claim["id"], "claim.id")
    require(ID_RE.fullmatch(claim_id) is not None, "claim.id is invalid")
    predecessors = sorted_unique_strings(
        claim["predecessor_ids"], "claim.predecessor_ids", nonempty=False
    )
    implementation_refs = sorted_unique_strings(
        claim["implementation_refs"], "claim.implementation_refs"
    )
    evidence_axes = sorted_unique_strings(acceptance["evidence_axes"], "acceptance.evidence_axes")
    repositories = sorted_unique_strings(
        acceptance["source_repositories"], "acceptance.source_repositories"
    )
    for index, repository in enumerate(repositories):
        github_slug(repository, f"acceptance.source_repositories[{index}]")
    workflow_artifacts = sorted_unique_strings(
        acceptance["workflow_artifacts"], "acceptance.workflow_artifacts"
    )
    semantic_contracts = exact_keys(
        acceptance["semantic_contracts"],
        SEMANTIC_CONTRACT_KEYS,
        "acceptance.semantic_contracts",
    )
    for key in sorted(SEMANTIC_CONTRACT_KEYS):
        digest_string(
            semantic_contracts[key], f"acceptance.semantic_contracts.{key}"
        )
    definition = {
        "schema": DEFINITION_SCHEMA,
        "id": claim_id,
        "track": nonempty_string(claim["track"], "claim.track"),
        "scope_ref": claim["scope_ref"],
        "validation_ref": claim["validation_ref"],
        "implementation_refs": implementation_refs,
        "predecessor_ids": predecessors,
        "evidence_axes": evidence_axes,
        "source_repositories": repositories,
        "workflow_artifacts": workflow_artifacts,
        "semantic_contracts": {
            key: semantic_contracts[key] for key in sorted(SEMANTIC_CONTRACT_KEYS)
        },
    }
    return sha256_bytes(canonical_json(definition))


def _semantic_contract_from_document(
    data: bytes,
    claim_id: str,
    kind: str,
    heading: str,
    label: str,
) -> bytes:
    require(len(data) <= MAX_JSON_BYTES, f"{label} exceeds the size limit")
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise ArchiveError(f"{label} is not UTF-8: {error}") from error
    lines = text.splitlines(keepends=True)
    heading_matches: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        match = re.fullmatch(r"(#{1,6})[ \t]+(.+?)[ \t]*(?:\r?\n)?", line)
        if match is not None and match.group(2) == heading:
            heading_matches.append((index, len(match.group(1))))
    require(
        len(heading_matches) == 1,
        f"{label} must contain exactly one referenced heading",
    )
    heading_index, heading_level = heading_matches[0]
    section_end = len(lines)
    for index in range(heading_index + 1, len(lines)):
        match = re.fullmatch(r"(#{1,6})[ \t]+(.+?)[ \t]*(?:\r?\n)?", lines[index])
        if match is not None and len(match.group(1)) <= heading_level:
            section_end = index
            break
    start_marker = f"<!-- claim-semantic-contract:{claim_id}:{kind}:start -->"
    end_marker = f"<!-- claim-semantic-contract:{claim_id}:{kind}:end -->"
    section = lines[heading_index + 1 : section_end]
    starts = [index for index, line in enumerate(section) if line.strip() == start_marker]
    ends = [index for index, line in enumerate(section) if line.strip() == end_marker]
    require(
        len(starts) == 1 and len(ends) == 1 and starts[0] + 1 < ends[0],
        f"{label} semantic-contract markers are missing, repeated, or empty",
    )
    return "".join(section[starts[0] : ends[0] + 1]).encode("utf-8")


def _semantic_contract_bytes(
    data: bytes, claim: dict[str, Any], kind: str, label: str
) -> bytes:
    require(kind in SEMANTIC_CONTRACT_PATHS, f"unknown semantic contract kind {kind!r}")
    reference = exact_keys(
        claim.get(f"{kind}_ref"),
        {"path", "heading"},
        f"{label} {kind}_ref",
    )
    path = safe_path(reference["path"], f"{label} {kind}_ref.path")
    require(
        path == SEMANTIC_CONTRACT_PATHS[kind],
        f"{label} {kind}_ref is not the canonical semantic document",
    )
    heading = nonempty_string(reference["heading"], f"{label} {kind}_ref.heading")
    claim_id = nonempty_string(claim.get("id"), f"{label} claim id")
    return _semantic_contract_from_document(data, claim_id, kind, heading, label)


def validate_semantic_contracts(
    root: Path, claim: dict[str, Any], acceptance: dict[str, Any]
) -> dict[str, str]:
    """Bind archive-governed claim pointers to marked normative document bytes."""

    configured = exact_keys(
        acceptance.get("semantic_contracts"),
        SEMANTIC_CONTRACT_KEYS,
        f"{claim.get('id', 'claim')}.semantic_contracts",
    )
    observed: dict[str, str] = {}
    for kind, path in SEMANTIC_CONTRACT_PATHS.items():
        document = regular_repository_file(root, path, f"{kind} semantic document")
        contract = _semantic_contract_bytes(
            document.read_bytes(), claim, kind, f"current {kind} semantic contract"
        )
        key = f"{kind}_sha256"
        expected = digest_string(configured[key], f"semantic_contracts.{key}")
        observed[key] = sha256_bytes(contract)
        require(
            observed[key] == expected,
            f"{claim['id']} {kind} semantic contract digest drifted",
        )
    return observed


def validate_source(value: Any, label: str) -> dict[str, Any]:
    source = exact_keys(value, SOURCE_KEYS, label)
    github_slug(source["repository"], f"{label}.repository")
    git_sha(source["revision"], f"{label}.revision")
    git_sha(source["tree"], f"{label}.tree")
    return source


def validate_qualification(value: Any, label: str) -> dict[str, Any]:
    qualification = exact_keys(value, QUALIFICATION_KEYS, label)
    positive_int(qualification["workflow_id"], f"{label}.workflow_id")
    path = nonempty_string(qualification["workflow_path"], f"{label}.workflow_path")
    safe_path(path, f"{label}.workflow_path")
    require(
        WORKFLOW_PATH_RE.fullmatch(path) is not None and path == CI_WORKFLOW_PATH,
        f"{label}.workflow_path is not the canonical CI workflow",
    )
    positive_int(qualification["run_id"], f"{label}.run_id")
    positive_int(qualification["run_attempt"], f"{label}.run_attempt")
    require(
        qualification["run_attempt"] == 1,
        f"{label}.run_attempt must be 1 for exact artifact-attempt closure",
    )
    git_sha(qualification["head_sha"], f"{label}.head_sha")
    positive_int(qualification["closure_job_id"], f"{label}.closure_job_id")
    closure_name = nonempty_string(
        qualification["closure_job_name"], f"{label}.closure_job_name"
    )
    require(
        closure_name == CI_CLOSURE_JOB_NAME,
        f"{label}.closure_job_name is not the canonical closure job",
    )
    positive_int(qualification["job_count"], f"{label}.job_count")
    require(
        qualification["job_count"] == CI_JOB_COUNT,
        f"{label}.job_count must bind all {CI_JOB_COUNT} workflow executions",
    )
    return qualification


def validate_receipt(receipt: dict[str, Any], claim: dict[str, Any], acceptance: dict[str, Any]) -> None:
    claim_id = nonempty_string(claim.get("id"), "claim.id")
    exact_keys(receipt, RECEIPT_KEYS, f"{claim_id} closure receipt")
    require(receipt["schema"] == RECEIPT_SCHEMA, "unknown project-claim closure schema")
    require(receipt["claim_id"] == claim_id, f"{claim_id} receipt identity drifted")
    expected_definition = claim_definition_sha256(claim, acceptance)
    require(
        receipt["claim_definition_sha256"] == expected_definition,
        f"{claim_id} claim-definition digest drifted",
    )
    predecessors = sorted_unique_strings(
        receipt["predecessor_ids"], f"{claim_id}.predecessor_ids", nonempty=False
    )
    require(predecessors == claim["predecessor_ids"], f"{claim_id} predecessor binding drifted")
    source = validate_source(receipt["accepted_source"], f"{claim_id}.accepted_source")
    require(source["repository"] == "chenty2333/vISA", "accepted source is not chenty2333/vISA")
    qualification = validate_qualification(receipt["qualification"], f"{claim_id}.qualification")
    require(
        qualification["head_sha"] == source["revision"],
        f"{claim_id} workflow head does not equal accepted revision",
    )

    archive = exact_keys(receipt["archive"], ARCHIVE_KEYS, f"{claim_id}.archive")
    tag = release_tag(archive["release_tag"], f"{claim_id}.archive.release_tag")
    expected_uri = f"https://github.com/chenty2333/vISA/releases/tag/{tag}"
    require(archive["release_uri"] == expected_uri, f"{claim_id} release URI drifted")
    require(
        archive["asset_name"] == f"{claim_id}-evidence.tar",
        f"{claim_id} archive asset name drifted",
    )
    positive_int(archive["asset_size_bytes"], f"{claim_id}.archive.asset_size_bytes")
    digest_string(archive["asset_sha256"], f"{claim_id}.archive.asset_sha256")
    expected_manifest = f"claims/archive-manifests/{claim_id}.json"
    require(archive["manifest_path"] == expected_manifest, f"{claim_id} manifest path drifted")
    digest_string(archive["manifest_sha256"], f"{claim_id}.archive.manifest_sha256")
    safe_path(archive["sha256sums_path"], f"{claim_id}.archive.sha256sums_path")
    digest_string(archive["sha256sums_sha256"], f"{claim_id}.archive.sha256sums_sha256")
    safe_path(archive["reverify_path"], f"{claim_id}.archive.reverify_path")
    digest_string(archive["reverify_sha256"], f"{claim_id}.archive.reverify_sha256")
    attestation = exact_keys(
        archive["release_attestation"], ATTESTATION_KEYS, f"{claim_id}.release_attestation"
    )
    require(
        attestation
        == {
            "kind": "github-immutable-release",
            "verification": "gh-release-verify-and-verify-asset",
        },
        f"{claim_id} release attestation contract drifted",
    )
    second = exact_keys(receipt["second_copy"], SECOND_COPY_KEYS, f"{claim_id}.second_copy")
    require(second["kind"] == "zenodo-record-file-v1", f"{claim_id} second-copy kind drifted")
    record_id = positive_int(
        second["record_id"], f"{claim_id}.second_copy.record_id"
    )
    require(
        second["doi"] == f"10.5281/zenodo.{record_id}",
        f"{claim_id} second-copy DOI is not the Zenodo-minted version DOI",
    )
    require(
        second["asset_name"] == archive["asset_name"],
        f"{claim_id} second-copy asset name drifted",
    )
    require(
        second["asset_size_bytes"] == archive["asset_size_bytes"],
        f"{claim_id} second-copy asset size drifted",
    )
    checksum = nonempty_string(
        second["provider_checksum"], f"{claim_id}.second_copy.provider_checksum"
    )
    require(
        re.fullmatch(r"md5:[0-9a-f]{32}", checksum) is not None,
        f"{claim_id} Zenodo provider checksum is invalid",
    )
    require(second["asset_sha256"] == archive["asset_sha256"], f"{claim_id} second-copy digest drifted")


def validate_action(value: Any, label: str, qualification: dict[str, Any]) -> dict[str, Any]:
    action = exact_keys(value, ACTION_KEYS, label)
    nonempty_string(action["role"], f"{label}.role")
    positive_int(action["artifact_id"], f"{label}.artifact_id")
    nonempty_string(action["artifact_name"], f"{label}.artifact_name")
    path = safe_path(action["path"], f"{label}.path")
    require(path.endswith(".zip"), f"{label}.path must end in .zip")
    digest = nonempty_string(action["api_digest"], f"{label}.api_digest")
    require(digest.startswith("sha256:") and SHA256_RE.fullmatch(digest[7:]), f"{label}.api_digest is invalid")
    require(action["run_id"] == qualification["run_id"], f"{label}.run_id drifted")
    require(action["run_attempt"] == qualification["run_attempt"], f"{label}.run_attempt drifted")
    require(action["head_sha"] == qualification["head_sha"], f"{label}.head_sha drifted")
    positive_int(action["size_bytes"], f"{label}.size_bytes")
    expires = nonempty_string(action["expires_at"], f"{label}.expires_at")
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", expires) is not None, f"{label}.expires_at is invalid")
    return action


def validate_bundle(value: Any, label: str) -> dict[str, Any]:
    bundle = exact_keys(value, BUNDLE_KEYS, label)
    bundle_id = nonempty_string(bundle["id"], f"{label}.id")
    require(ID_RE.fullmatch(bundle_id) is not None, f"{label}.id is invalid")
    repository = nonempty_string(bundle["repository"], f"{label}.repository")
    parsed = urllib.parse.urlsplit(repository)
    require(
        parsed.scheme == "https"
        and parsed.netloc == "github.com"
        and parsed.path.endswith(".git")
        and repository == github_source_url(parsed.path[1:-4]),
        f"{label}.repository is not a canonical GitHub source URL",
    )
    git_sha(bundle["revision"], f"{label}.revision")
    git_sha(bundle["tree"], f"{label}.tree")
    path = safe_path(bundle["bundle_path"], f"{label}.bundle_path")
    require(path.endswith(".bundle"), f"{label}.bundle_path must end in .bundle")
    ref = nonempty_string(bundle["bundle_ref"], f"{label}.bundle_ref")
    require(REF_RE.fullmatch(ref) is not None and ".." not in ref, f"{label}.bundle_ref is invalid")
    return bundle


def validate_axis(value: Any, label: str, known_claims: set[str]) -> dict[str, Any]:
    axis = exact_keys(value, AXIS_KEYS, label)
    axis_id = nonempty_string(axis["id"], f"{label}.id")
    require(ID_RE.fullmatch(axis_id) is not None, f"{label}.id is invalid")
    claim_ids = sorted_unique_strings(axis["claim_ids"], f"{label}.claim_ids")
    require(set(claim_ids) <= known_claims, f"{label}.claim_ids contains an unbound claim")
    for index, path in enumerate(sorted_unique_strings(axis["member_paths"], f"{label}.member_paths")):
        safe_path(path, f"{label}.member_paths[{index}]")
    nonempty_string(axis["verifier"], f"{label}.verifier")
    return axis


def validate_member(value: Any, label: str) -> dict[str, Any]:
    member = exact_keys(value, MEMBER_KEYS, label)
    safe_path(member["path"], f"{label}.path")
    nonempty_string(member["role"], f"{label}.role")
    media = nonempty_string(member["media_type"], f"{label}.media_type")
    require("/" in media and "\n" not in media, f"{label}.media_type is invalid")
    positive_int(member["size_bytes"], f"{label}.size_bytes")
    require(member["size_bytes"] <= MAX_MEMBER_BYTES, f"{label} exceeds the size limit")
    digest_string(member["sha256"], f"{label}.sha256")
    return member


def validate_manifest(
    manifest: dict[str, Any], claim: dict[str, Any], acceptance: dict[str, Any]
) -> None:
    claim_id = claim["id"]
    exact_keys(manifest, MANIFEST_KEYS, f"{claim_id} archive manifest")
    require(manifest["schema"] == MANIFEST_SCHEMA, "unknown project-claim archive schema")
    require(manifest["claim_id"] == claim_id, f"{claim_id} manifest identity drifted")
    definition = claim_definition_sha256(claim, acceptance)
    require(manifest["claim_definition_sha256"] == definition, f"{claim_id} manifest definition drifted")
    predecessors = sorted_unique_strings(
        manifest["predecessor_ids"], f"{claim_id}.manifest.predecessor_ids", nonempty=False
    )
    require(predecessors == claim["predecessor_ids"], f"{claim_id} manifest predecessors drifted")
    source = validate_source(manifest["accepted_source"], f"{claim_id}.manifest.accepted_source")
    qualification = validate_qualification(
        manifest["qualification"], f"{claim_id}.manifest.qualification"
    )
    require(qualification["head_sha"] == source["revision"], "manifest workflow head drifted")

    actions_raw = manifest["actions_artifacts"]
    require(isinstance(actions_raw, list) and len(actions_raw) == 2, "manifest must bind two Actions artifacts")
    actions = [
        validate_action(item, f"{claim_id}.actions_artifacts[{index}]", qualification)
        for index, item in enumerate(actions_raw)
    ]
    require(
        [item["artifact_name"] for item in actions]
        == sorted_unique_strings(acceptance["workflow_artifacts"], "acceptance.workflow_artifacts"),
        "manifest Actions artifacts differ from acceptance policy",
    )
    require(
        [item["role"] for item in actions] == sorted({item["role"] for item in actions}),
        "manifest Actions artifact roles must be unique and sorted",
    )
    require(len({item["artifact_id"] for item in actions}) == 2, "manifest repeats an artifact id")

    bundles_raw = manifest["source_bundles"]
    require(isinstance(bundles_raw, list) and len(bundles_raw) == 3, "manifest must bind three source bundles")
    bundles = [
        validate_bundle(item, f"{claim_id}.source_bundles[{index}]")
        for index, item in enumerate(bundles_raw)
    ]
    require([item["id"] for item in bundles] == sorted({item["id"] for item in bundles}), "source bundle ids must be unique and sorted")
    expected_repositories = [github_source_url(item) for item in acceptance["source_repositories"]]
    require(
        [item["repository"] for item in bundles] == expected_repositories,
        "manifest source repositories differ from acceptance policy",
    )
    visa_bundles = [item for item in bundles if item["repository"] == github_source_url("chenty2333/vISA")]
    require(len(visa_bundles) == 1, "manifest must contain one vISA source bundle")
    require(
        visa_bundles[0]["revision"] == source["revision"]
        and visa_bundles[0]["tree"] == source["tree"],
        "vISA source bundle differs from accepted source",
    )

    known_claims = {claim_id, *claim["predecessor_ids"]}
    axes_raw = manifest["evidence_axes"]
    require(isinstance(axes_raw, list) and axes_raw, "manifest evidence_axes must be nonempty")
    axes = [
        validate_axis(item, f"{claim_id}.evidence_axes[{index}]", known_claims)
        for index, item in enumerate(axes_raw)
    ]
    require([item["id"] for item in axes] == acceptance["evidence_axes"], "manifest axes differ from acceptance policy")
    require(
        all(claim_id in item["claim_ids"] for item in axes),
        "every evidence axis must bind the current successor claim",
    )

    members_raw = manifest["members"]
    require(isinstance(members_raw, list) and len(members_raw) == 7, "manifest must describe exactly seven payload members")
    members = [
        validate_member(item, f"{claim_id}.members[{index}]")
        for index, item in enumerate(members_raw)
    ]
    member_paths = [item["path"] for item in members]
    require(member_paths == sorted(set(member_paths)), "manifest member paths must be unique and sorted")
    expected_paths = {
        *(item["path"] for item in actions),
        *(item["bundle_path"] for item in bundles),
    }
    remaining = set(member_paths) - expected_paths
    require(len(remaining) == 2, "manifest must contain only SHA256SUMS and REVERIFY beyond evidence payloads")
    require(any(PurePosixPath(path).name == "SHA256SUMS" for path in remaining), "manifest lacks SHA256SUMS")
    require(any(PurePosixPath(path).name == "REVERIFY.md" for path in remaining), "manifest lacks REVERIFY.md")
    expected_paths |= remaining
    require(set(member_paths) == expected_paths, "manifest member inventory drifted")
    for action in actions:
        member = next(item for item in members if item["path"] == action["path"])
        require(member["size_bytes"] == action["size_bytes"], "Actions ZIP size differs from member record")
        require(member["sha256"] == action["api_digest"][7:], "Actions ZIP digest differs from API digest")
    axis_paths = {path for axis in axes for path in axis["member_paths"]}
    require(axis_paths <= set(member_paths), "evidence axis references a nonmember path")
    require(set(item["path"] for item in actions) <= axis_paths, "an Actions artifact is not bound to an evidence axis")


def validate_closure_record(
    root: Path, claim: dict[str, Any], acceptance: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate a committed receipt and manifest without network access."""

    claim_id = nonempty_string(claim.get("id"), "claim.id")
    require(isinstance(acceptance, dict), f"{claim_id} acceptance must be an object")
    expected_receipt_path = f"claims/receipts/{claim_id}.json"
    require(acceptance.get("path") == expected_receipt_path, f"{claim_id} receipt path drifted")
    receipt_path = regular_repository_file(
        root, expected_receipt_path, f"{claim_id} closure receipt"
    )
    manifest_path = regular_repository_file(
        root,
        f"claims/archive-manifests/{claim_id}.json",
        f"{claim_id} archive manifest",
    )
    receipt, receipt_bytes = load_json_file(receipt_path, f"{claim_id} closure receipt")
    manifest, manifest_bytes = load_json_file(manifest_path, f"{claim_id} archive manifest")
    digest_string(acceptance.get("receipt_sha256"), f"{claim_id}.acceptance.receipt_sha256")
    require(
        acceptance["receipt_sha256"] == sha256_bytes(receipt_bytes),
        f"{claim_id} committed receipt digest drifted",
    )
    validate_receipt(receipt, claim, acceptance)
    validate_manifest(manifest, claim, acceptance)
    validate_semantic_contracts(root, claim, acceptance)
    _validate_file_committed_at_head(
        root, expected_receipt_path, f"{claim_id} closure receipt"
    )
    _validate_file_committed_at_head(
        root,
        f"claims/archive-manifests/{claim_id}.json",
        f"{claim_id} archive manifest",
    )
    promotion_revision = _promotion_commit(root, claim_id)
    _validate_accepted_source_ancestor(
        root, receipt["accepted_source"], claim_id, promotion_revision
    )
    _validate_definition_against_accepted_candidate(
        root,
        receipt["accepted_source"],
        claim,
        acceptance,
        promotion_revision,
    )
    _validate_source_bundles_against_accepted_locks(
        root, receipt["accepted_source"], manifest
    )
    require(receipt["accepted_source"] == manifest["accepted_source"], "receipt/manifest accepted source differs")
    require(receipt["qualification"] == manifest["qualification"], "receipt/manifest qualification differs")
    archive = receipt["archive"]
    require(archive["manifest_path"] == f"claims/archive-manifests/{claim_id}.json", "receipt manifest path differs")
    require(archive["manifest_sha256"] == sha256_bytes(manifest_bytes), "committed manifest digest drifted")
    members = {item["path"]: item for item in manifest["members"]}
    require(archive["sha256sums_path"] in members, "receipt SHA256SUMS path is absent from manifest")
    require(archive["reverify_path"] in members, "receipt REVERIFY path is absent from manifest")
    require(
        archive["sha256sums_sha256"] == members[archive["sha256sums_path"]]["sha256"],
        "receipt SHA256SUMS digest differs from manifest",
    )
    require(
        archive["reverify_sha256"] == members[archive["reverify_path"]]["sha256"],
        "receipt REVERIFY digest differs from manifest",
    )
    return receipt, manifest


def _repository_git(root: Path, arguments: list[str], label: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ArchiveError(f"{label} failed: {result.stderr.strip() or 'nonzero exit'}")
    return result.stdout.strip()


def _git_blob_at_revision(root: Path, revision: str, relative: str, label: str) -> bytes:
    """Read one committed regular blob without consulting the worktree."""

    safe_path(relative, f"{label} path")
    object_name = f"{revision}:{relative}"
    kind = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-t", object_name],
        text=True,
        capture_output=True,
        check=False,
    )
    require(
        kind.returncode == 0 and kind.stdout.strip() == "blob",
        f"{label} is not a committed regular blob at baseline",
    )
    result = subprocess.run(
        ["git", "-C", str(root), "show", object_name],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise ArchiveError(f"cannot read baseline {label}: {stderr or 'nonzero exit'}")
    return result.stdout


def _json_blob_at_revision(
    root: Path, revision: str, relative: str, label: str
) -> dict[str, Any]:
    value = load_json_bytes(
        _git_blob_at_revision(root, revision, relative, label), label
    )
    require(isinstance(value, dict), f"{label} must contain one JSON object")
    return value


def _normalized_promotion_registry(
    registry: dict[str, Any],
    claim_id: str,
    *,
    expected_status: str,
    expected_kind: str,
    label: str,
) -> tuple[bytes, dict[str, Any]]:
    exact_keys(
        registry,
        {"schema", "claims", "workflow_bindings"},
        label,
    )
    require(
        registry["schema"] == "visa.project-claim-registry.v1",
        f"unknown {label} schema",
    )
    claims = registry["claims"]
    require(isinstance(claims, list), f"{label} claims must be an array")
    matches = [
        item
        for item in claims
        if isinstance(item, dict) and item.get("id") == claim_id
    ]
    require(len(matches) == 1, f"{label} must contain exactly one {claim_id}")
    target = exact_keys(matches[0], REGISTRY_CLAIM_KEYS, f"{label} {claim_id}")
    require(target["status"] == expected_status, f"{label} {claim_id} status drifted")
    acceptance = exact_keys(
        target["acceptance_ref"],
        PERMANENT_ACCEPTANCE_KEYS,
        f"{label} {claim_id} acceptance_ref",
    )
    require(
        acceptance["kind"] == expected_kind,
        f"{label} {claim_id} acceptance kind drifted",
    )
    if expected_status == "candidate":
        require(
            acceptance["receipt_sha256"] is None,
            f"{label} candidate receipt digest must be null",
        )
    else:
        digest_string(
            acceptance["receipt_sha256"], f"{label} {claim_id} receipt digest"
        )

    normalized = copy.deepcopy(registry)
    normalized_target = next(
        item for item in normalized["claims"] if item.get("id") == claim_id
    )
    normalized_target["status"] = "claim-lifecycle-status"
    normalized_target["acceptance_ref"]["kind"] = "claim-lifecycle-acceptance"
    normalized_target["acceptance_ref"]["receipt_sha256"] = None
    bindings = normalized["workflow_bindings"]
    require(isinstance(bindings, list), f"{label} workflow_bindings must be an array")
    roles: list[str] = []
    for binding in bindings:
        require(isinstance(binding, dict), f"{label} workflow binding must be an object")
        bound_claims = binding.get("claims")
        require(isinstance(bound_claims, list), f"{label} binding claims must be an array")
        for bound_claim in bound_claims:
            require(isinstance(bound_claim, dict), f"{label} bound claim must be an object")
            if bound_claim.get("id") == claim_id:
                role = bound_claim.get("role")
                require(
                    role in CLAIM_WORKFLOW_ROLES,
                    f"{label} {claim_id} lifecycle role is invalid",
                )
                roles.append(role)
                bound_claim["role"] = "claim-lifecycle-role"
    require(roles, f"{label} does not bind {claim_id} to CI")
    if expected_status == "candidate":
        require(
            "required" in roles and "regresses" not in roles,
            f"{label} candidate lifecycle roles drifted",
        )
    else:
        require(
            "required" not in roles
            and all(role in {"regresses", "supports"} for role in roles),
            f"{label} earned lifecycle roles drifted",
        )
    return canonical_json(normalized), target


def _validate_promotion_tree_changes(
    root: Path, accepted_revision: str, head: str, claim_id: str
) -> None:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--name-only",
            "--no-renames",
            "-z",
            accepted_revision,
            head,
            "--",
        ],
        capture_output=True,
        check=False,
    )
    require(result.returncode == 0, "cannot inspect promotion tree changes")
    try:
        changed = {
            item.decode("utf-8")
            for item in result.stdout.split(b"\0")
            if item
        }
    except UnicodeError as error:
        raise ArchiveError(f"promotion changed a non-UTF-8 path: {error}") from error
    for path in changed:
        safe_path(path, "promotion changed path")
    receipt_path = f"claims/receipts/{claim_id}.json"
    manifest_path = f"claims/archive-manifests/{claim_id}.json"
    allowed = {
        CI_WORKFLOW_PATH,
        CLAIM_REGISTRY_PATH,
        receipt_path,
        manifest_path,
        *PROMOTION_DOCUMENT_PATHS,
    }
    require(
        changed <= allowed,
        f"promotion changed non-receipt paths: {sorted(changed - allowed)}",
    )
    required = {
        CI_WORKFLOW_PATH,
        CLAIM_REGISTRY_PATH,
        "README.md",
        receipt_path,
        manifest_path,
    }
    require(
        required <= changed,
        f"promotion omitted required lifecycle paths: {sorted(required - changed)}",
    )


def _validate_definition_against_accepted_candidate(
    root: Path,
    source: dict[str, Any],
    claim: dict[str, Any],
    acceptance: dict[str, Any],
    promotion_revision: str,
) -> None:
    """Require the receipt to promote the exact candidate definition that CI accepted."""

    claim_id = nonempty_string(claim.get("id"), "claim.id")
    revision = source["revision"]
    registry = _json_blob_at_revision(
        root,
        revision,
        CLAIM_REGISTRY_PATH,
        "accepted claim registry",
    )
    accepted_registry, candidate = _normalized_promotion_registry(
        registry,
        claim_id,
        expected_status="candidate",
        expected_kind="pending-permanent-archive-receipt",
        label="accepted claim registry",
    )
    candidate_acceptance = candidate["acceptance_ref"]
    require(
        candidate_acceptance["path"] == f"claims/receipts/{claim_id}.json"
        and candidate_acceptance["heading"] is None,
        f"accepted {claim_id} candidate guard drifted",
    )
    accepted_definition = claim_definition_sha256(candidate, candidate_acceptance)
    current_definition = claim_definition_sha256(claim, acceptance)
    require(
        accepted_definition == current_definition,
        f"{claim_id} definition differs from the candidate accepted by CI",
    )
    promotion_registry, promotion_registry_claim = _normalized_promotion_registry(
        _json_blob_at_revision(
            root,
            promotion_revision,
            CLAIM_REGISTRY_PATH,
            "promotion claim registry",
        ),
        claim_id,
        expected_status="earned",
        expected_kind="permanent-archive-receipt",
        label="promotion claim registry",
    )
    require(
        claim_definition_sha256(
            promotion_registry_claim,
            promotion_registry_claim["acceptance_ref"],
        )
        == current_definition,
        f"promotion registry {claim_id} differs from the verified claim definition",
    )
    require(
        promotion_registry_claim["acceptance_ref"]["path"]
        == acceptance["path"]
        and promotion_registry_claim["acceptance_ref"]["heading"]
        == acceptance["heading"]
        and promotion_registry_claim["acceptance_ref"]["receipt_sha256"]
        == acceptance["receipt_sha256"],
        f"promotion registry {claim_id} closure identity drifted",
    )
    require(
        promotion_registry == accepted_registry,
        f"claim registry changed beyond {claim_id} lifecycle promotion",
    )
    for kind, path in SEMANTIC_CONTRACT_PATHS.items():
        accepted_contract = _semantic_contract_bytes(
            _git_blob_at_revision(
                root, revision, path, f"accepted {kind} semantic document"
            ),
            candidate,
            kind,
            f"accepted {kind} semantic contract",
        )
        promotion_contract = _semantic_contract_bytes(
            _git_blob_at_revision(
                root,
                promotion_revision,
                path,
                f"promotion {kind} semantic document",
            ),
            promotion_registry_claim,
            kind,
            f"promotion {kind} semantic contract",
        )
        key = f"{kind}_sha256"
        configured = candidate_acceptance["semantic_contracts"][key]
        require(
            sha256_bytes(accepted_contract) == configured,
            f"accepted {claim_id} {kind} semantic-contract digest drifted",
        )
        require(
            promotion_contract == accepted_contract,
            f"{claim_id} {kind} semantic contract changed after CI acceptance",
        )
    for relative in candidate["implementation_refs"]:
        accepted_implementation = _git_blob_at_revision(
            root,
            revision,
            relative,
            f"accepted implementation ref {relative}",
        )
        promotion_implementation = _git_blob_at_revision(
            root,
            promotion_revision,
            relative,
            f"promotion implementation ref {relative}",
        )
        require(
            promotion_implementation == accepted_implementation,
            f"implementation ref {relative} changed after CI acceptance",
        )
    _validate_promotion_tree_changes(
        root, revision, promotion_revision, claim_id
    )


def _validate_source_bundles_against_accepted_locks(
    root: Path,
    source: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    """Bind Nexus and neutral source bundles to locks in the accepted vISA tree."""

    revision = source["revision"]
    source_lock = _json_blob_at_revision(
        root,
        revision,
        JOINT_SOURCE_LOCK_PATH,
        "accepted joint-handoff source lock",
    )
    require(
        source_lock.get("schema") == "visa.joint-handoff-qualification-source-lock.v1",
        "accepted joint-handoff source-lock schema drifted",
    )
    source_nexus = source_lock.get("nexus")
    source_neutral = source_lock.get("joint_artifact")
    require(isinstance(source_nexus, dict), "accepted source lock lacks Nexus identity")
    require(isinstance(source_neutral, dict), "accepted source lock lacks neutral identity")

    qualification_lock = _json_blob_at_revision(
        root,
        revision,
        NEXUS_QUALIFICATION_LOCK_PATH,
        "accepted Nexus qualification lock",
    )
    require(
        qualification_lock.get("schema") == "visa.nexus-handoff-qualification-lock.v2",
        "accepted Nexus qualification-lock schema drifted",
    )
    qualified_nexus = qualification_lock.get("nexus")
    require(
        isinstance(qualified_nexus, dict),
        "accepted Nexus qualification lock lacks Nexus identity",
    )
    source_nexus_revision = git_sha(
        source_nexus.get("revision"), "accepted source-lock Nexus revision"
    )
    nexus_revision = git_sha(
        qualified_nexus.get("revision"), "accepted qualified Nexus revision"
    )
    require(
        qualified_nexus.get("analyzed_baseline_revision") == source_nexus_revision,
        "accepted Nexus qualification baseline differs from the neutral source lock",
    )
    require(
        source_nexus.get("repository") == "https://github.com/chenty2333/Nexus"
        and qualified_nexus.get("repository")
        == "https://github.com/chenty2333/Nexus",
        "accepted Nexus lock repository drifted",
    )

    neutral_revision = git_sha(
        source_neutral.get("revision"), "accepted neutral revision"
    )
    neutral_tree = git_sha(source_neutral.get("tree"), "accepted neutral tree")
    require(
        source_neutral.get("repository")
        == "https://github.com/chenty2333/visa-nexus-handoff",
        "accepted neutral lock repository drifted",
    )

    bundles = {
        item["repository"]: item for item in manifest["source_bundles"]
    }
    nexus_bundle = bundles.get(github_source_url("chenty2333/Nexus"))
    neutral_bundle = bundles.get(
        github_source_url("chenty2333/visa-nexus-handoff")
    )
    require(isinstance(nexus_bundle, dict), "manifest lacks the locked Nexus bundle")
    require(isinstance(neutral_bundle, dict), "manifest lacks the locked neutral bundle")
    require(
        nexus_bundle["revision"] == nexus_revision,
        "Nexus source bundle revision differs from the accepted qualification lock",
    )
    require(
        neutral_bundle["revision"] == neutral_revision
        and neutral_bundle["tree"] == neutral_tree,
        "neutral source bundle differs from the accepted source lock",
    )


def _normalized_claim_workflow(
    data: bytes, claim_id: str, label: str
) -> tuple[str, int]:
    try:
        workflow = data.decode("utf-8")
    except UnicodeError as error:
        raise ArchiveError(f"{label} is not UTF-8: {error}") from error
    placeholder = f"{claim_id}:claim-lifecycle-role"
    count = 0
    for role in CLAIM_WORKFLOW_ROLES:
        token = f"{claim_id}:{role}"
        count += workflow.count(token)
        workflow = workflow.replace(token, placeholder)
    require(count > 0, f"{label} does not bind the successor claim role")
    return workflow, count


def _validate_accepted_source_ancestor(
    root: Path,
    source: dict[str, Any],
    claim_id: str,
    promotion_revision: str,
) -> None:
    require(
        promotion_revision != source["revision"],
        "accepted revision must be a strict ancestor of the promotion commit",
    )
    accepted = _repository_git(
        root,
        ["rev-parse", "--verify", f"{source['revision']}^{{commit}}"],
        "accepted revision",
    )
    require(accepted == source["revision"], "accepted revision does not resolve exactly")
    tree = _repository_git(
        root,
        ["rev-parse", "--verify", f"{source['revision']}^{{tree}}"],
        "accepted tree",
    )
    require(tree == source["tree"], "accepted source tree differs from local Git history")
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "merge-base",
            "--is-ancestor",
            source["revision"],
            promotion_revision,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    require(
        result.returncode == 0,
        "accepted revision is not an ancestor of the promotion commit",
    )
    for relative in ACCEPTED_SOURCE_STABLE_PATHS:
        accepted_blob = _repository_git(
            root,
            ["rev-parse", "--verify", f"{source['revision']}:{relative}"],
            f"accepted {relative} blob",
        )
        promotion_blob = _repository_git(
            root,
            ["rev-parse", "--verify", f"{promotion_revision}:{relative}"],
            f"promotion {relative} blob",
        )
        require(
            accepted_blob == promotion_blob,
            f"{relative} changed between the accepted revision and promotion commit",
        )
    accepted_workflow, accepted_role_count = _normalized_claim_workflow(
        _git_blob_at_revision(
            root, source["revision"], CI_WORKFLOW_PATH, "accepted CI workflow"
        ),
        claim_id,
        "accepted CI workflow",
    )
    promotion_workflow, promotion_role_count = _normalized_claim_workflow(
        _git_blob_at_revision(
            root,
            promotion_revision,
            CI_WORKFLOW_PATH,
            "promotion CI workflow",
        ),
        claim_id,
        "promotion CI workflow",
    )
    require(
        accepted_role_count == promotion_role_count
        and accepted_workflow == promotion_workflow,
        "CI workflow changed beyond the successor claim lifecycle role",
    )


def _validate_file_committed_at_head(root: Path, relative: str, label: str) -> None:
    working_blob = _repository_git(
        root, ["hash-object", "--", relative], f"{label} working blob"
    )
    committed_blob = _repository_git(
        root, ["rev-parse", "--verify", f"HEAD:{relative}"], f"{label} HEAD blob"
    )
    require(working_blob == committed_blob, f"{label} is not byte-identical to committed HEAD")


def _promotion_commit(root: Path, claim_id: str) -> str:
    """Locate the unique commit that introduced both immutable closure carriers."""

    paths = (
        f"claims/receipts/{claim_id}.json",
        f"claims/archive-manifests/{claim_id}.json",
    )
    introduced: list[str] = []
    for path in paths:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "log",
                "--format=%H",
                "--diff-filter=A",
                "--",
                path,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        require(result.returncode == 0, f"cannot locate promotion commit for {path}")
        commits = [line for line in result.stdout.splitlines() if line]
        require(
            len(commits) == 1,
            f"{path} must have one unambiguous introduction commit",
        )
        introduced.append(commits[0])
    require(
        introduced[0] == introduced[1],
        "closure receipt and archive manifest were not introduced together",
    )
    promotion = introduced[0]
    head = _repository_git(
        root, ["rev-parse", "--verify", "HEAD^{commit}"], "repository HEAD"
    )
    for path in paths:
        require(
            _git_blob_at_revision(root, promotion, path, f"promotion {path}")
            == _git_blob_at_revision(root, head, path, f"current {path}"),
            f"{path} changed after its promotion commit",
        )
    return promotion


def permanent_claims_at_baseline(root: Path, baseline: str) -> dict[str, str]:
    """Return permanent claim IDs and receipt digests at a strict ancestor."""

    git_sha(baseline, "baseline revision")
    head = _repository_git(root, ["rev-parse", "--verify", "HEAD^{commit}"], "repository HEAD")
    require(baseline != head, "baseline revision must be a strict ancestor of HEAD")
    result = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", baseline, head],
        text=True,
        capture_output=True,
        check=False,
    )
    require(result.returncode == 0, "baseline revision is not an ancestor of HEAD")
    registry_path = "claims/registry.json"
    inventory = _repository_git(
        root,
        ["ls-tree", "--name-only", baseline, "--", registry_path],
        "baseline claim-registry inventory",
    )
    if inventory == "":
        return {}
    require(
        inventory == registry_path,
        "baseline claim-registry inventory is ambiguous",
    )
    result = subprocess.run(
        ["git", "-C", str(root), "show", f"{baseline}:{registry_path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise ArchiveError(f"cannot read baseline claim registry: {stderr or 'nonzero exit'}")
    registry = load_json_bytes(result.stdout, "baseline claim registry")
    exact_keys(
        registry,
        {"schema", "claims", "workflow_bindings"},
        "baseline claim registry",
    )
    require(
        registry["schema"] == "visa.project-claim-registry.v1",
        "unknown baseline claim-registry schema",
    )
    claims = registry["claims"]
    require(isinstance(claims, list), "baseline registry claims must be an array")
    observed: list[str] = []
    permanent: dict[str, str] = {}
    for index, claim in enumerate(claims):
        require(isinstance(claim, dict), f"baseline claims[{index}] must be an object")
        claim_id = nonempty_string(claim.get("id"), f"baseline claims[{index}].id")
        require(ID_RE.fullmatch(claim_id) is not None, f"baseline claim id is invalid: {claim_id!r}")
        require(claim_id not in observed, f"duplicate baseline claim id: {claim_id}")
        observed.append(claim_id)
        status = claim.get("status")
        require(status in {"candidate", "earned", "retired"}, f"{claim_id} baseline status is invalid")
        acceptance = claim.get("acceptance_ref")
        require(isinstance(acceptance, dict), f"{claim_id} baseline acceptance_ref is invalid")
        kind = acceptance.get("kind")
        require(
            kind
            in {
                "canonical-validation",
                "pending-permanent-archive-receipt",
                "permanent-archive-receipt",
            },
            f"{claim_id} baseline acceptance kind is invalid",
        )
        if kind == "permanent-archive-receipt":
            exact_keys(
                acceptance,
                PERMANENT_ACCEPTANCE_KEYS,
                f"{claim_id} baseline acceptance_ref",
            )
            require(status in {"earned", "retired"}, f"{claim_id} baseline permanent receipt is unearned")
            expected_receipt = f"claims/receipts/{claim_id}.json"
            expected_manifest = f"claims/archive-manifests/{claim_id}.json"
            require(
                acceptance.get("path") == expected_receipt
                and acceptance.get("heading") is None,
                f"{claim_id} baseline permanent receipt path drifted",
            )
            receipt_digest = acceptance.get("receipt_sha256")
            digest_string(receipt_digest, f"{claim_id} baseline receipt digest")
            receipt_bytes = _git_blob_at_revision(
                root, baseline, expected_receipt, f"{claim_id} baseline closure receipt"
            )
            require(
                sha256_bytes(receipt_bytes) == receipt_digest,
                f"{claim_id} baseline receipt digest does not match its committed blob",
            )
            manifest_bytes = _git_blob_at_revision(
                root, baseline, expected_manifest, f"{claim_id} baseline archive manifest"
            )
            try:
                baseline_receipt = load_json_bytes(
                    receipt_bytes, f"{claim_id} baseline closure receipt"
                )
                baseline_manifest = load_json_bytes(
                    manifest_bytes, f"{claim_id} baseline archive manifest"
                )
            except ArchiveError as error:
                raise ArchiveError(f"{claim_id} baseline permanent closure is invalid: {error}") from error
            require(isinstance(baseline_receipt, dict), f"{claim_id} baseline receipt is not an object")
            require(isinstance(baseline_manifest, dict), f"{claim_id} baseline manifest is not an object")
            try:
                validate_receipt(baseline_receipt, claim, acceptance)
                validate_manifest(baseline_manifest, claim, acceptance)
            except ArchiveError as error:
                raise ArchiveError(f"{claim_id} baseline permanent closure is invalid: {error}") from error
            require(
                baseline_receipt["archive"]["manifest_sha256"] == sha256_bytes(manifest_bytes),
                f"{claim_id} baseline manifest digest does not match its committed blob",
            )
            accepted_source = baseline_receipt["accepted_source"]
            accepted_revision = accepted_source["revision"]
            accepted_tree = _repository_git(
                root,
                ["rev-parse", "--verify", f"{accepted_revision}^{{tree}}"],
                f"{claim_id} baseline accepted tree",
            )
            require(
                accepted_tree == accepted_source["tree"],
                f"{claim_id} baseline accepted source tree drifted",
            )
            ancestor = subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "merge-base",
                    "--is-ancestor",
                    accepted_revision,
                    baseline,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            require(
                ancestor.returncode == 0 and accepted_revision != baseline,
                f"{claim_id} baseline accepted revision is not a strict ancestor",
            )
            permanent[claim_id] = receipt_digest
    require(observed == sorted(observed), "baseline claims must be sorted by id")
    return permanent


def require_permanent_claims_monotonic(
    baseline_receipts: dict[str, str], claims: dict[str, dict[str, Any]]
) -> None:
    """Prevent an earned permanent closure from disappearing or being rewritten."""

    require(
        isinstance(baseline_receipts, dict),
        "baseline permanent receipt map must be an object",
    )
    missing = sorted(set(baseline_receipts) - set(claims))
    require(not missing, f"permanent claims were deleted: {missing}")
    for claim_id, baseline_digest in baseline_receipts.items():
        digest_string(baseline_digest, f"{claim_id} baseline receipt digest")
        claim = claims[claim_id]
        require(isinstance(claim, dict), f"{claim_id} current claim is invalid")
        require(
            claim.get("status") in {"earned", "retired"},
            f"permanent claim {claim_id} cannot return to candidate",
        )
        acceptance = claim.get("acceptance_ref")
        require(isinstance(acceptance, dict), f"{claim_id} current acceptance is invalid")
        require(
            acceptance.get("kind") == "permanent-archive-receipt",
            f"permanent claim {claim_id} lost its archive receipt",
        )
        require(
            acceptance.get("receipt_sha256") == baseline_digest,
            f"permanent claim {claim_id} receipt digest cannot be replaced",
        )


def _validate_zip(path: Path, label: str) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            names: set[str] = set()
            require(archive.infolist(), f"{label} is empty")
            for info in archive.infolist():
                name = info.filename
                require(name not in names, f"{label} contains duplicate member {name!r}")
                names.add(name)
                if name.endswith("/"):
                    require(not name.endswith("//"), f"{label} member has repeated separators")
                    safe_path(name[:-1], f"{label} member")
                else:
                    safe_path(name, f"{label} member")
                require(info.flag_bits & 0x1 == 0, f"{label} contains encrypted member {name!r}")
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                kind = stat.S_IFMT(unix_mode)
                if name.endswith("/"):
                    require(kind in {0, stat.S_IFDIR}, f"{label} has non-directory {name!r}")
                else:
                    require(kind in {0, stat.S_IFREG}, f"{label} contains link or special member {name!r}")
                require(info.file_size <= MAX_MEMBER_BYTES, f"{label} member {name!r} exceeds size limit")
                if not name.endswith("/"):
                    with archive.open(info) as member:
                        while member.read(1024 * 1024):
                            pass
            bad = archive.testzip()
            require(bad is None, f"{label} CRC failed for {bad!r}")
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ArchiveError(f"cannot verify {label}: {error}") from error


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def run_checked(runner: Runner, command: list[str], label: str) -> str:
    result = runner(command)
    require(hasattr(result, "returncode"), f"{label} runner returned an invalid result")
    if result.returncode != 0:
        stderr = str(getattr(result, "stderr", "")).strip()
        raise ArchiveError(f"{label} failed: {stderr or 'nonzero exit'}")
    return str(getattr(result, "stdout", ""))


def _validate_bundle(path: Path, bundle: dict[str, Any], runner: Runner) -> None:
    output = run_checked(runner, ["git", "bundle", "list-heads", str(path)], "git bundle list-heads")
    lines = [line for line in output.splitlines() if line]
    require(len(lines) == 1, f"{bundle['id']} bundle must expose exactly one ref")
    parts = lines[0].split()
    require(
        parts == [bundle["revision"], bundle["bundle_ref"]],
        f"{bundle['id']} bundle head differs from manifest",
    )
    with tempfile.TemporaryDirectory(prefix="visa-claim-bundle-") as temporary:
        bare = Path(temporary) / "repository.git"
        run_checked(runner, ["git", "init", "--bare", "--quiet", str(bare)], "git init --bare")
        run_checked(runner, ["git", "-C", str(bare), "bundle", "verify", str(path)], "git bundle verify")
        run_checked(
            runner,
            ["git", "-C", str(bare), "fetch", "--quiet", "--no-tags", str(path), bundle["bundle_ref"]],
            "git bundle fetch",
        )
        revision = run_checked(
            runner, ["git", "-C", str(bare), "rev-parse", "FETCH_HEAD^{commit}"], "git revision"
        ).strip()
        tree = run_checked(
            runner, ["git", "-C", str(bare), "rev-parse", "FETCH_HEAD^{tree}"], "git tree"
        ).strip()
        require(revision == bundle["revision"], f"{bundle['id']} fetched revision drifted")
        require(tree == bundle["tree"], f"{bundle['id']} fetched tree drifted")


def _parse_sha256sums(data: bytes, expected_paths: set[str]) -> None:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise ArchiveError(f"SHA256SUMS is not UTF-8: {error}") from error
    records: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        require(match is not None, f"malformed SHA256SUMS line: {line!r}")
        path = safe_path(match.group(2), "SHA256SUMS path")
        require(path not in records, f"duplicate SHA256SUMS path: {path}")
        records[path] = match.group(1)
    require(list(records) == sorted(records), "SHA256SUMS records must be sorted by path")
    require(set(records) == expected_paths, "SHA256SUMS inventory differs from archive payloads")


def _validate_standalone_manifest_shape(manifest: dict[str, Any]) -> None:
    exact_keys(manifest, MANIFEST_KEYS, "archive manifest")
    require(manifest["schema"] == MANIFEST_SCHEMA, "unknown project-claim archive schema")
    claim_id = nonempty_string(manifest["claim_id"], "archive manifest claim_id")
    require(ID_RE.fullmatch(claim_id) is not None, "archive manifest claim_id is invalid")
    digest_string(manifest["claim_definition_sha256"], "archive manifest definition digest")
    predecessors = sorted_unique_strings(
        manifest["predecessor_ids"], "archive manifest predecessor_ids", nonempty=False
    )
    source = validate_source(manifest["accepted_source"], "archive manifest accepted_source")
    qualification = validate_qualification(
        manifest["qualification"], "archive manifest qualification"
    )
    require(source["revision"] == qualification["head_sha"], "archive manifest head differs")
    actions_raw = manifest["actions_artifacts"]
    require(isinstance(actions_raw, list) and len(actions_raw) == 2, "manifest must bind two Actions artifacts")
    actions = [
        validate_action(item, f"archive manifest actions_artifacts[{index}]", qualification)
        for index, item in enumerate(actions_raw)
    ]
    require(
        [item["artifact_name"] for item in actions]
        == sorted({item["artifact_name"] for item in actions}),
        "manifest Actions artifacts must be unique and sorted",
    )
    require(
        [item["role"] for item in actions] == sorted({item["role"] for item in actions}),
        "manifest Actions artifact roles must be unique and sorted",
    )
    bundles_raw = manifest["source_bundles"]
    require(isinstance(bundles_raw, list) and len(bundles_raw) == 3, "manifest must bind three source bundles")
    bundles = [
        validate_bundle(item, f"archive manifest source_bundles[{index}]")
        for index, item in enumerate(bundles_raw)
    ]
    require(
        [item["id"] for item in bundles] == sorted({item["id"] for item in bundles}),
        "manifest source bundle ids must be unique and sorted",
    )
    axes_raw = manifest["evidence_axes"]
    require(isinstance(axes_raw, list) and axes_raw, "manifest evidence_axes must be nonempty")
    axes = [
        validate_axis(
            item,
            f"archive manifest evidence_axes[{index}]",
            {claim_id, *predecessors},
        )
        for index, item in enumerate(axes_raw)
    ]
    require(
        [item["id"] for item in axes] == sorted({item["id"] for item in axes}),
        "manifest evidence axis ids must be unique and sorted",
    )
    require(
        all(claim_id in item["claim_ids"] for item in axes),
        "every evidence axis must bind the current successor claim",
    )
    members_raw = manifest["members"]
    require(isinstance(members_raw, list) and len(members_raw) == 7, "manifest must describe exactly seven payload members")
    members = [
        validate_member(item, f"archive manifest members[{index}]")
        for index, item in enumerate(members_raw)
    ]
    member_paths = [item["path"] for item in members]
    require(member_paths == sorted(set(member_paths)), "manifest member paths must be unique and sorted")
    expected_paths = {
        *(item["path"] for item in actions),
        *(item["bundle_path"] for item in bundles),
    }
    remaining = set(member_paths) - expected_paths
    require(
        len(remaining) == 2
        and {PurePosixPath(item).name for item in remaining} == {"SHA256SUMS", "REVERIFY.md"},
        "manifest payload inventory drifted",
    )
    axis_paths = {path for axis in axes for path in axis["member_paths"]}
    require(axis_paths <= set(member_paths), "manifest evidence axis references a nonmember")


def validate_archive_tar(
    archive_path: Path,
    manifest_source: Path | dict[str, Any],
    *,
    expected_sha256: str | None = None,
    expected_size_bytes: int | None = None,
    runner: Runner = default_runner,
) -> None:
    """Validate the strict eight-member release tar and every embedded carrier."""

    try:
        archive_size = archive_path.stat().st_size
    except OSError as error:
        raise ArchiveError(f"cannot inspect archive {archive_path}: {error}") from error
    require(archive_path.is_file() and not archive_path.is_symlink(), "archive must be a regular file")
    require(archive_size <= MAX_ARCHIVE_BYTES, "archive exceeds the size limit")
    if expected_size_bytes is not None:
        require(archive_size == expected_size_bytes, "archive size differs from receipt")
    if expected_sha256 is not None:
        require(sha256_file(archive_path) == expected_sha256, "archive digest differs from receipt")

    if isinstance(manifest_source, Path):
        manifest, manifest_bytes = load_json_file(manifest_source, "committed archive manifest")
    else:
        require(isinstance(manifest_source, dict), "manifest_source must be a path or object")
        manifest = manifest_source
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    _validate_standalone_manifest_shape(manifest)
    members_by_path = {item["path"]: item for item in manifest["members"]}
    require(len(members_by_path) == 7, "archive manifest member inventory is not unique")
    expected_names = {MANIFEST_MEMBER, *members_by_path}

    with tempfile.TemporaryDirectory(prefix="visa-claim-archive-") as temporary:
        extracted_root = Path(temporary)
        extracted_bytes: dict[str, bytes] = {}
        try:
            with tarfile.open(archive_path, mode="r:") as archive:
                require(not archive.pax_headers, "archive contains global PAX headers")
                observed: set[str] = set()
                for member in archive:
                    name = safe_path(member.name, "tar member path")
                    require(name not in observed, f"archive contains duplicate member {name!r}")
                    observed.add(name)
                    require(member.isfile(), f"archive contains link, directory, or special member {name!r}")
                    require(not member.pax_headers, f"archive member {name!r} contains PAX headers")
                    require(not getattr(member, "sparse", None), f"archive contains sparse member {name!r}")
                    require(0 <= member.size <= MAX_MEMBER_BYTES, f"archive member {name!r} exceeds size limit")
                    source = archive.extractfile(member)
                    require(source is not None, f"cannot read archive member {name!r}")
                    data = source.read(MAX_MEMBER_BYTES + 1)
                    require(len(data) == member.size, f"archive member {name!r} size drifted")
                    require(len(data) <= MAX_MEMBER_BYTES, f"archive member {name!r} exceeds size limit")
                    extracted_bytes[name] = data
                logical_eof = archive.offset
                require(
                    isinstance(logical_eof, int) and logical_eof % 512 == 0,
                    "archive parser did not expose a canonical logical EOF",
                )
                try:
                    with archive_path.open("rb") as raw_archive:
                        raw_archive.seek(logical_eof)
                        trailer = raw_archive.read()
                except OSError as error:
                    raise ArchiveError(f"cannot inspect release tar trailer: {error}") from error
                require(
                    len(trailer) >= 1024
                    and len(trailer) % 512 == 0
                    and not any(trailer),
                    "archive has nonzero or incomplete trailing tar blocks",
                )
                require(observed == expected_names, "archive member inventory differs from manifest")
        except (OSError, tarfile.TarError) as error:
            raise ArchiveError(f"cannot verify release tar: {error}") from error

        require(extracted_bytes[MANIFEST_MEMBER] == manifest_bytes, "archive manifest is not byte-identical to committed manifest")
        for name, record in members_by_path.items():
            data = extracted_bytes[name]
            require(len(data) == record["size_bytes"], f"archive member {name!r} size differs from manifest")
            require(sha256_bytes(data) == record["sha256"], f"archive member {name!r} digest differs from manifest")
            destination = extracted_root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)

        action_paths = {item["path"] for item in manifest["actions_artifacts"]}
        for path in sorted(action_paths):
            _validate_zip(extracted_root / path, f"Actions artifact {path}")
        for bundle in manifest["source_bundles"]:
            _validate_bundle(extracted_root / bundle["bundle_path"], bundle, runner)

        sums_path = next(path for path in members_by_path if PurePosixPath(path).name == "SHA256SUMS")
        reverify_path = next(path for path in members_by_path if PurePosixPath(path).name == "REVERIFY.md")
        checksum_paths = set(members_by_path) - {sums_path}
        _parse_sha256sums(extracted_bytes[sums_path], checksum_paths)
        records = {
            line[66:]: line[:64] for line in extracted_bytes[sums_path].decode("utf-8").splitlines()
        }
        for path, digest in records.items():
            require(sha256_bytes(extracted_bytes[path]) == digest, f"SHA256SUMS digest failed for {path}")
        try:
            instructions = extracted_bytes[reverify_path].decode("utf-8")
        except UnicodeError as error:
            raise ArchiveError(f"REVERIFY.md is not UTF-8: {error}") from error
        require(instructions.strip(), "REVERIFY.md is empty")
        require("sha256sum" in instructions and "git bundle verify" in instructions, "REVERIFY.md omits carrier verification")
        for axis in manifest["evidence_axes"]:
            require(axis["verifier"] in instructions, f"REVERIFY.md omits verifier for axis {axis['id']}")


def _gh_json(runner: Runner, endpoint: str, label: str) -> dict[str, Any]:
    output = run_checked(
        runner,
        [
            "gh",
            "api",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "X-GitHub-Api-Version: 2026-03-10",
            endpoint,
        ],
        label,
    )
    value = load_json_bytes(output.encode(), label)
    require(isinstance(value, dict), f"{label} must return one JSON object")
    return value


def _default_fetch(uri: str, limit: int) -> bytes:
    request = urllib.request.Request(uri, headers={"User-Agent": "vISA-claim-archive-verifier/1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            require(response.geturl() == uri, "second-copy request redirected")
            data = response.read(limit + 1)
    except (OSError, urllib.error.URLError) as error:
        raise ArchiveError(f"cannot download independent copy {uri}: {error}") from error
    require(len(data) <= limit, "independent copy exceeds expected size")
    return data


Fetcher = Callable[[str, int], bytes]


def _verify_live_actions(
    runner: Runner,
    repository: str,
    qualification: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    run_id = qualification["run_id"]
    attempt = qualification["run_attempt"]
    current_run = _gh_json(
        runner,
        f"repos/{repository}/actions/runs/{run_id}",
        "current workflow run",
    )
    require(current_run.get("id") == run_id, "current workflow run id differs")
    require(
        current_run.get("run_attempt") == attempt,
        "workflow run was rerun after the archived exact attempt",
    )
    require(
        current_run.get("head_sha") == qualification["head_sha"],
        "current workflow head differs",
    )
    current_head_repository = current_run.get("head_repository")
    require(
        current_run.get("event") == "push"
        and isinstance(current_head_repository, dict)
        and current_head_repository.get("full_name") == repository,
        "current workflow run is not an exact repository push",
    )
    run = _gh_json(
        runner,
        f"repos/{repository}/actions/runs/{run_id}/attempts/{attempt}",
        "workflow run attempt",
    )
    require(run.get("id") == run_id, "workflow run id differs")
    require(run.get("run_attempt") == attempt, "workflow run attempt differs")
    require(run.get("workflow_id") == qualification["workflow_id"], "workflow id differs")
    require(run.get("path") == qualification["workflow_path"], "workflow path differs")
    require(run.get("head_sha") == qualification["head_sha"], "workflow head differs")
    head_repository = run.get("head_repository")
    require(
        run.get("event") == "push"
        and isinstance(head_repository, dict)
        and head_repository.get("full_name") == repository,
        "workflow qualification is not an exact repository push",
    )
    require(
        run.get("status") == "completed" and run.get("conclusion") == "success",
        "workflow run did not succeed",
    )

    jobs = _gh_json(
        runner,
        f"repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100",
        "workflow jobs",
    )
    job_items = jobs.get("jobs")
    require(isinstance(job_items, list), "workflow jobs response lacks jobs")
    require(
        all(isinstance(item, dict) for item in job_items),
        "workflow jobs response contains a non-object entry",
    )
    require(
        jobs.get("total_count") == qualification["job_count"] == len(job_items),
        "workflow job count differs",
    )
    require(
        len({item.get("id") for item in job_items}) == len(job_items),
        "workflow jobs repeat an id",
    )
    attempt_started: list[datetime] = []
    attempt_completed: list[datetime] = []
    for job in job_items:
        require(isinstance(job, dict), "workflow job is not an object")
        require(type(job.get("id")) is int and job.get("id") > 0, "workflow job id is invalid")
        require(job.get("run_id") == run_id, "workflow job run id differs")
        require(job.get("run_attempt") == attempt, "workflow job attempt differs")
        require(job.get("head_sha") == qualification["head_sha"], "workflow job head differs")
        require(
            job.get("status") == "completed" and job.get("conclusion") == "success",
            "not all workflow jobs succeeded",
        )
        attempt_started.append(
            github_timestamp(job.get("started_at"), "workflow job started_at")
        )
        attempt_completed.append(
            github_timestamp(job.get("completed_at"), "workflow job completed_at")
        )
    require(
        min(attempt_started) <= max(attempt_completed),
        "workflow attempt timestamps are reversed",
    )
    closure_jobs = [
        item for item in job_items if item.get("id") == qualification["closure_job_id"]
    ]
    require(len(closure_jobs) == 1, "closure job id is absent")
    require(
        closure_jobs[0].get("name") == qualification["closure_job_name"],
        "closure job name differs",
    )

    artifacts = _gh_json(
        runner,
        f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100",
        "workflow artifacts",
    )
    artifact_items = artifacts.get("artifacts")
    require(isinstance(artifact_items, list), "workflow artifacts response lacks artifacts")
    require(
        all(isinstance(item, dict) for item in artifact_items),
        "workflow artifacts response contains a non-object entry",
    )
    for expected in manifest["actions_artifacts"]:
        matches = [
            item for item in artifact_items if item.get("id") == expected["artifact_id"]
        ]
        require(len(matches) == 1, f"Actions artifact {expected['artifact_id']} is absent")
        observed = matches[0]
        require(
            type(observed.get("id")) is int and observed.get("id") > 0,
            "Actions artifact id is invalid",
        )
        require(observed.get("name") == expected["artifact_name"], "Actions artifact name differs")
        require(
            type(observed.get("size_in_bytes")) is int
            and observed.get("size_in_bytes") == expected["size_bytes"],
            "Actions artifact size differs",
        )
        require(observed.get("digest") == expected["api_digest"], "Actions artifact digest differs")
        require(
            observed.get("expired") is False,
            "Actions artifact expired before archival verification",
        )
        artifact_created = github_timestamp(
            observed.get("created_at"), "Actions artifact created_at"
        )
        artifact_updated = github_timestamp(
            observed.get("updated_at"), "Actions artifact updated_at"
        )
        require(
            min(attempt_started)
            <= artifact_created
            <= artifact_updated
            <= max(attempt_completed),
            "Actions artifact timestamps do not bind it to the exact workflow attempt",
        )
        workflow_run = observed.get("workflow_run")
        require(isinstance(workflow_run, dict), "Actions artifact lacks workflow_run")
        require(
            workflow_run.get("id") == run_id
            and workflow_run.get("head_sha") == qualification["head_sha"],
            "Actions artifact workflow binding differs",
        )


def verify_online(
    root: Path,
    claim: dict[str, Any],
    acceptance: dict[str, Any],
    *,
    repository: str | None = None,
    require_live_actions: bool = True,
    runner: Runner = default_runner,
    fetcher: Fetcher = _default_fetch,
) -> None:
    """Reconcile a committed closure with GitHub and its independent byte copy."""

    receipt, manifest = validate_closure_record(root, claim, acceptance)
    source = receipt["accepted_source"]
    qualification = receipt["qualification"]
    archive = receipt["archive"]
    recorded_repository = source["repository"]
    if repository is not None:
        github_slug(repository, "configured repository")
        require(repository == recorded_repository, "configured repository differs from receipt")
    repository = recorded_repository
    require(
        isinstance(require_live_actions, bool),
        "require_live_actions must be a boolean",
    )
    if require_live_actions:
        _verify_live_actions(runner, repository, qualification, manifest)

    commit = _gh_json(runner, f"repos/{repository}/git/commits/{source['revision']}", "accepted commit")
    tree = commit.get("tree")
    require(commit.get("sha") == source["revision"], "accepted commit revision differs")
    require(isinstance(tree, dict) and tree.get("sha") == source["tree"], "accepted commit tree differs")

    encoded_tag = urllib.parse.quote(archive["release_tag"], safe="")
    tagged_commit = _gh_json(
        runner,
        f"repos/{repository}/commits/{encoded_tag}",
        "release tag target",
    )
    require(
        tagged_commit.get("sha") == source["revision"],
        "release tag does not resolve to the accepted revision",
    )

    release = _gh_json(runner, f"repos/{repository}/releases/tags/{archive['release_tag']}", "immutable release")
    require(release.get("tag_name") == archive["release_tag"], "release tag differs")
    require(release.get("html_url") == archive["release_uri"], "release URI differs")
    require(release.get("immutable") is True, "release is not immutable")
    assets = release.get("assets")
    require(isinstance(assets, list) and len(assets) == 1, "release must contain exactly one archive asset")
    asset = assets[0]
    require(isinstance(asset, dict), "release asset is not an object")
    require(asset.get("name") == archive["asset_name"], "release asset name differs")
    require(asset.get("state") == "uploaded", "release asset is not uploaded")
    require(
        type(asset.get("size")) is int
        and asset.get("size") == archive["asset_size_bytes"],
        "release asset size differs",
    )
    require(asset.get("digest") == f"sha256:{archive['asset_sha256']}", "release asset API digest differs")
    run_checked(runner, ["gh", "release", "verify", archive["release_tag"], "--repo", repository], "release attestation verification")

    with tempfile.TemporaryDirectory(prefix="visa-claim-release-") as temporary:
        destination = Path(temporary)
        run_checked(
            runner,
            [
                "gh",
                "release",
                "download",
                archive["release_tag"],
                "--repo",
                repository,
                "--pattern",
                archive["asset_name"],
                "--dir",
                str(destination),
            ],
            "release archive download",
        )
        archive_path = destination / archive["asset_name"]
        require(archive_path.is_file() and not archive_path.is_symlink(), "release download did not produce the archive")
        run_checked(
            runner,
            [
                "gh",
                "release",
                "verify-asset",
                archive["release_tag"],
                str(archive_path),
                "--repo",
                repository,
            ],
            "release asset attestation verification",
        )
        validate_archive_tar(
            archive_path,
            root / archive["manifest_path"],
            expected_sha256=archive["asset_sha256"],
            expected_size_bytes=archive["asset_size_bytes"],
            runner=runner,
        )

        second = receipt["second_copy"]
        record_uri = zenodo_record_uri(second["record_id"])
        asset_uri = zenodo_asset_uri(second["record_id"], second["asset_name"])
        record_data = fetcher(record_uri, MAX_JSON_BYTES)
        record = load_json_bytes(record_data, "Zenodo record")
        require(isinstance(record, dict), "Zenodo record must be an object")
        require(
            type(record.get("id")) is int
            and record.get("id") == second["record_id"],
            "Zenodo record id differs",
        )
        require(record.get("doi") == second["doi"], "Zenodo record DOI differs")
        require(record.get("status") == "published", "Zenodo record is not published")
        files = record.get("files")
        require(isinstance(files, list) and len(files) == 1, "Zenodo record must contain exactly one file")
        zenodo_file = files[0]
        require(isinstance(zenodo_file, dict), "Zenodo file record is not an object")
        require(zenodo_file.get("key") == second["asset_name"], "Zenodo file name differs")
        require(
            type(zenodo_file.get("size")) is int
            and zenodo_file.get("size") == second["asset_size_bytes"],
            "Zenodo file size differs",
        )
        links = zenodo_file.get("links")
        require(
            isinstance(links, dict) and links.get("self") == asset_uri,
            "Zenodo file link differs",
        )
        zenodo_checksum = zenodo_file.get("checksum")
        require(
            zenodo_checksum == second["provider_checksum"],
            "Zenodo file checksum differs from receipt",
        )
        independent = fetcher(asset_uri, second["asset_size_bytes"])
        release_bytes = archive_path.read_bytes()
        require(independent == release_bytes, "independent copy is not byte-identical to release asset")
        require(
            sha256_bytes(independent) == second["asset_sha256"],
            "Zenodo asset SHA-256 differs from receipt",
        )
        require(
            hashlib.md5(independent, usedforsecurity=False).hexdigest()
            == second["provider_checksum"].removeprefix("md5:"),
            "Zenodo MD5 transport checksum differs",
        )
