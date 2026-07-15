#!/usr/bin/env python3
"""Validate the pinned inputs for the reference-only joint handoff lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCK = ROOT / "third_party" / "joint-handoff-qualification" / "source-lock.json"
EXPECTED_SCHEMA = "visa.joint-handoff-qualification-source-lock.v1"
EXPECTED_STATUS = "reference-only-not-nexus-qualified"
EXPECTED_PROTOCOL_PATH = (
    "third_party/joint-handoff-qualification/joint-handoff-wire-v1.md"
)
EXPECTED_NEUTRAL_WIRE_CONTRACT_PATH = (
    "third_party/joint-handoff-qualification/wire-v1.toml"
)
EXPECTED_MACHINE_CONTRACT_PATH = (
    "third_party/joint-handoff-qualification/nexus-native-v1-refinement.toml"
)
EXPECTED_REFINEMENT_MAP_PATH = "third_party/joint-handoff-qualification/refinement-map.toml"
EXPECTED_ABSTRACT_REGISTRY_PATH = (
    "third_party/joint-handoff-qualification/neutral-fault-matrix.toml"
)
EXPECTED_VISA_REPOSITORY = "https://github.com/chenty2333/vISA"
EXPECTED_NEXUS_REPOSITORY = "https://github.com/chenty2333/Nexus"
EXPECTED_JOINT_REPOSITORY = "https://github.com/chenty2333/visa-nexus-handoff"
EXPECTED_NEUTRAL_BUNDLE_PATH = (
    "third_party/joint-handoff-qualification/neutral-source.bundle"
)
EXPECTED_REVISION_SOURCE = "checked-out-exact-git-sha"
EXPECTED_NEXUS_EXECUTION = "reference-peer-only"
EXPECTED_REFINEMENT_SCHEMA = "visa-nexus-handoff.refinement-map.v1"
EXPECTED_REFINEMENT_MAPPING_KIND = "case-id-identity-only"
EXPECTED_ANALYZED_STATUS = "pre-implementation-analysis-only"
EXPECTED_NATIVE_REFINEMENT_SCHEMA = (
    "visa-nexus-handoff.nexus-native-v1-refinement.v1"
)
EXPECTED_NATIVE_MAPPING_KIND = "field-level-deterministic-projection"
EXPECTED_NATIVE_REQUEST_SCHEMA = "nexus.effect-peer.request.v1"
EXPECTED_NATIVE_RESPONSE_SCHEMA = "nexus.effect-peer.response.v1"
EXPECTED_NATIVE_RECEIPT_SCHEMA = "nexus.effect-peer.native-receipt.v1"
EXPECTED_NEUTRAL_WIRE_SCHEMA = "visa-nexus-handoff.wire-contract.v1"
EXPECTED_CLAIM_ID = "bounded-joint-handoff-refinement-v1"
EXPECTED_NORMATIVE_CASE_COUNT = 16
EXPECTED_SUPPLEMENTAL_CASE_COUNT = 1
MODEL_PATH = (
    ROOT
    / "crates"
    / "testing"
    / "visa-conformance"
    / "src"
    / "joint_handoff"
    / "model.rs"
)

LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}")
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
HTTPS_REPOSITORY = re.compile(r"https://[^\s]+")


class LockError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise LockError(message)


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        fail(
            f"{label} keys drifted: missing={sorted(expected - actual)} "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty string")
    return value


def require_match(value: Any, pattern: re.Pattern[str], label: str) -> str:
    text = require_string(value, label)
    if pattern.fullmatch(text) is None:
        fail(f"{label} has an invalid exact identity: {text!r}")
    return text


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"source lock contains duplicate key {key!r}")
        result[key] = value
    return result


def read_regular_file(path: Path, label: str) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            fail(f"{label} is not a regular non-symlink file: {path}")
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve(strict=True))
        return resolved.read_bytes()
    except (OSError, ValueError) as error:
        fail(f"cannot read contained {label} {path}: {error}")


def rust_constant(source: str, name: str, pattern: str) -> str:
    match = re.search(
        rf"pub const {re.escape(name)}[^=]*=\s*({pattern});",
        source,
        flags=re.MULTILINE,
    )
    if match is None:
        fail(f"cannot read {name} from {MODEL_PATH.relative_to(ROOT)}")
    value = match.group(1)
    if value.startswith('"'):
        return value[1:-1]
    return value


def validate_snapshot(
    value: Any,
    label: str,
    expected_path: str,
    expected_source_path: str,
) -> tuple[str, str, str, bytes]:
    snapshot = require_exact_keys(
        value,
        {"path", "source_path", "git_blob", "sha256"},
        label,
    )
    if snapshot["path"] != expected_path:
        fail(f"{label}.path must be {expected_path}")
    if snapshot["source_path"] != expected_source_path:
        fail(f"{label}.source_path must be {expected_source_path}")
    git_blob = require_match(snapshot["git_blob"], LOWER_GIT_SHA, f"{label}.git_blob")
    locked_sha256 = require_match(snapshot["sha256"], LOWER_SHA256, f"{label}.sha256")
    snapshot_bytes = read_regular_file(ROOT / expected_path, f"{label} snapshot")
    actual_sha256 = hashlib.sha256(snapshot_bytes).hexdigest()
    if actual_sha256 != locked_sha256:
        fail(
            f"{label} snapshot digest mismatch: "
            f"locked={locked_sha256} actual={actual_sha256}"
        )
    return locked_sha256, expected_source_path, git_blob, snapshot_bytes


def run_git(
    arguments: list[str],
    label: str,
    *,
    git_dir: Path | None = None,
) -> bytes:
    command = ["git"]
    if git_dir is not None:
        command.append(f"--git-dir={git_dir}")
    command.extend(arguments)
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"cannot execute Git while checking {label}: {error}")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"Git rejected {label}: {detail or f'exit {completed.returncode}'}")
    return completed.stdout


def validate_neutral_bundle(
    joint: dict[str, Any],
    snapshots: list[tuple[str, str, str, bytes]],
) -> tuple[str, str]:
    tree = require_match(joint["tree"], LOWER_GIT_SHA, "joint_artifact.tree")
    bundle = require_exact_keys(
        joint["source_bundle"],
        {"path", "sha256", "head"},
        "joint_artifact.source_bundle",
    )
    if bundle["path"] != EXPECTED_NEUTRAL_BUNDLE_PATH:
        fail(
            "joint_artifact.source_bundle.path must be "
            f"{EXPECTED_NEUTRAL_BUNDLE_PATH}"
        )
    bundle_sha256 = require_match(
        bundle["sha256"], LOWER_SHA256, "joint_artifact.source_bundle.sha256"
    )
    bundle_head = require_match(
        bundle["head"], LOWER_GIT_SHA, "joint_artifact.source_bundle.head"
    )
    revision = require_match(
        joint["revision"], LOWER_GIT_SHA, "joint_artifact.revision"
    )
    if bundle_head != revision:
        fail(
            "neutral Git source bundle head must equal the exact locked revision: "
            f"revision={revision} head={bundle_head}"
        )
    bundle_path = ROOT / EXPECTED_NEUTRAL_BUNDLE_PATH
    bundle_bytes = read_regular_file(bundle_path, "neutral Git source bundle")
    actual_bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()
    if actual_bundle_sha256 != bundle_sha256:
        fail(
            "neutral Git source bundle digest mismatch: "
            f"locked={bundle_sha256} actual={actual_bundle_sha256}"
        )
    advertised_heads = run_git(
        ["bundle", "list-heads", str(bundle_path)],
        "neutral source bundle advertised head",
    )
    expected_heads = f"{bundle_head} refs/heads/main\n".encode("ascii")
    if advertised_heads != expected_heads:
        fail(
            "neutral Git source bundle must advertise only the exact locked main head: "
            f"expected={expected_heads.decode('ascii').strip()!r} "
            f"actual={advertised_heads.decode('utf-8', errors='replace').strip()!r}"
        )

    target = ROOT / "target"
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        fail(f"neutral bundle verification target is not a real directory: {target}")
    target.mkdir(exist_ok=True)
    try:
        target.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    except (OSError, ValueError) as error:
        fail(f"neutral bundle verification target escapes the repository: {error}")
    try:
        with tempfile.TemporaryDirectory(prefix="neutral-source-lock-", dir=target) as directory:
            git_dir = Path(directory) / "objects.git"
            run_git(["init", "--bare", "--quiet", str(git_dir)], "neutral bundle repository")
            run_git(
                ["bundle", "verify", str(bundle_path)],
                "neutral source bundle",
                git_dir=git_dir,
            )
            run_git(
                ["fetch", "--quiet", "--no-tags", str(bundle_path), bundle_head],
                "neutral source bundle head",
                git_dir=git_dir,
            )
            run_git(["cat-file", "-e", f"{revision}^{{commit}}"], "neutral revision", git_dir=git_dir)
            run_git(
                ["merge-base", "--is-ancestor", revision, bundle_head],
                "neutral revision ancestry",
                git_dir=git_dir,
            )
            actual_tree = (
                run_git(["rev-parse", f"{revision}^{{tree}}"], "neutral tree", git_dir=git_dir)
                .decode("ascii")
                .strip()
            )
            if actual_tree != tree:
                fail(f"neutral tree mismatch: locked={tree} actual={actual_tree}")

            for label, source_path, expected_blob, local_bytes in snapshots:
                actual_blob = (
                    run_git(
                        ["rev-parse", f"{revision}:{source_path}"],
                        f"{label} neutral blob",
                        git_dir=git_dir,
                    )
                    .decode("ascii")
                    .strip()
                )
                if actual_blob != expected_blob:
                    fail(
                        f"{label} neutral blob mismatch: "
                        f"locked={expected_blob} actual={actual_blob}"
                    )
                committed_bytes = run_git(
                    ["show", f"{revision}:{source_path}"],
                    f"{label} committed bytes",
                    git_dir=git_dir,
                )
                if committed_bytes != local_bytes:
                    fail(
                        f"{label} snapshot does not equal exact neutral revision {revision}"
                    )
    except OSError as error:
        fail(f"cannot create neutral bundle verification workspace: {error}")
    return tree, bundle_sha256


def validate_native_machine_contract(path: Path | None = None) -> None:
    contract_path = path or ROOT / EXPECTED_MACHINE_CONTRACT_PATH
    raw = read_regular_file(contract_path, "Nexus native-v1 machine contract")
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot decode Nexus native-v1 machine contract: {error}")

    expected_scalars = {
        "schema": EXPECTED_NATIVE_REFINEMENT_SCHEMA,
        "claim_id": EXPECTED_CLAIM_ID,
        "mapping_kind": EXPECTED_NATIVE_MAPPING_KIND,
        "native_request_schema": EXPECTED_NATIVE_REQUEST_SCHEMA,
        "native_response_schema": EXPECTED_NATIVE_RESPONSE_SCHEMA,
        "native_receipt_schema": EXPECTED_NATIVE_RECEIPT_SCHEMA,
        "neutral_wire_schema": EXPECTED_NEUTRAL_WIRE_SCHEMA,
        "normative_case_count": EXPECTED_NORMATIVE_CASE_COUNT,
        "supplemental_case_count": EXPECTED_SUPPLEMENTAL_CASE_COUNT,
    }
    for key, expected in expected_scalars.items():
        value = document.get(key)
        if type(value) is not type(expected) or value != expected:
            fail(
                "Nexus native-v1 machine contract identity drifted: "
                f"{key}={value!r} expected={expected!r}"
            )
    if document.get("adapter_qualification") is not False:
        fail("Nexus native-v1 machine contract must not claim adapter qualification")
    if document.get("ownership_truth_source") is not False:
        fail("Nexus native-v1 machine contract must not claim ownership authority")

    registry = require_exact_keys(
        document.get("registry_binding"),
        {
            "normative_case_count",
            "supplemental_case_count",
            "supplemental_case_id",
            "native_v1_full_registry_qualified",
            "unsupported_normative_case_ids",
            "unsupported_supplemental_case_ids",
        },
        "Nexus native-v1 registry_binding",
    )
    expected_registry = {
        "normative_case_count": EXPECTED_NORMATIVE_CASE_COUNT,
        "supplemental_case_count": EXPECTED_SUPPLEMENTAL_CASE_COUNT,
        "supplemental_case_id": "supplemental-postcommit-retained-tombstone",
        "native_v1_full_registry_qualified": False,
        "unsupported_normative_case_ids": ["frozen-service-crash-rebind"],
        "unsupported_supplemental_case_ids": [
            "supplemental-postcommit-retained-tombstone"
        ],
    }
    for key, expected in expected_registry.items():
        value = registry[key]
        if type(value) is not type(expected) or value != expected:
            fail(
                "Nexus native-v1 registry boundary drifted: "
                f"{key}={value!r} expected={expected!r}"
            )


def validate_refinement_baseline(nexus_revision: str) -> None:
    raw = read_regular_file(ROOT / EXPECTED_REFINEMENT_MAP_PATH, "refinement map snapshot")
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot decode refinement map snapshot: {error}")
    if document.get("schema") != EXPECTED_REFINEMENT_SCHEMA:
        fail("refinement map snapshot schema drifted")
    if document.get("mapping_kind") != EXPECTED_REFINEMENT_MAPPING_KIND:
        fail("refinement map snapshot no longer describes case identity only")
    if document.get("adapter_qualification") is not False:
        fail("refinement map snapshot must not claim adapter qualification")
    analyzed = require_exact_keys(
        document.get("analyzed_baselines"),
        {"visa_revision", "nexus_revision", "status"},
        "refinement_map.analyzed_baselines",
    )
    require_match(
        analyzed["visa_revision"],
        LOWER_GIT_SHA,
        "refinement_map.analyzed_baselines.visa_revision",
    )
    analyzed_nexus = require_match(
        analyzed["nexus_revision"],
        LOWER_GIT_SHA,
        "refinement_map.analyzed_baselines.nexus_revision",
    )
    if analyzed["status"] != EXPECTED_ANALYZED_STATUS:
        fail("refinement map baseline must remain pre-implementation analysis only")
    if analyzed_nexus != nexus_revision:
        fail(
            "reference source-lock Nexus revision differs from the neutral analyzed baseline: "
            f"source_lock={nexus_revision} refinement_map={analyzed_nexus}"
        )


def validate(lock_path: Path) -> tuple[str, str, str, str, str, str, str, str, str]:
    raw = read_regular_file(lock_path, "joint handoff source lock")
    source_lock_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot decode joint handoff source lock: {error}")

    document = require_exact_keys(
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
        "source lock",
    )
    if document["schema"] != EXPECTED_SCHEMA:
        fail(f"source lock schema must be {EXPECTED_SCHEMA}")
    if document["evidence_status"] != EXPECTED_STATUS:
        fail(
            "joint handoff CI input must remain reference-only and must not claim "
            "Nexus exact-SHA qualification"
        )

    visa = require_exact_keys(document["visa"], {"repository", "revision_source"}, "visa")
    if visa["repository"] != EXPECTED_VISA_REPOSITORY:
        fail("visa.repository drifted from the canonical repository")
    if visa["revision_source"] != EXPECTED_REVISION_SOURCE:
        fail(f"visa.revision_source must be {EXPECTED_REVISION_SOURCE}")

    nexus = require_exact_keys(
        document["nexus"], {"repository", "revision", "execution"}, "nexus"
    )
    if nexus["repository"] != EXPECTED_NEXUS_REPOSITORY:
        fail("nexus.repository drifted from the canonical repository")
    nexus_revision = require_match(nexus["revision"], LOWER_GIT_SHA, "nexus.revision")
    if nexus["execution"] != EXPECTED_NEXUS_EXECUTION:
        fail(
            f"nexus.execution must be {EXPECTED_NEXUS_EXECUTION}; the reference lane "
            "cannot qualify a Nexus implementation"
        )

    joint = require_exact_keys(
        document["joint_artifact"],
        {"repository", "revision", "tree", "source_bundle"},
        "joint_artifact",
    )
    repository = require_match(
        joint["repository"], HTTPS_REPOSITORY, "joint_artifact.repository"
    )
    if repository != EXPECTED_JOINT_REPOSITORY:
        fail("joint_artifact.repository drifted from the canonical neutral repository")
    joint_revision = require_match(
        joint["revision"], LOWER_GIT_SHA, "joint_artifact.revision"
    )

    protocol = validate_snapshot(
        document["protocol_schema"],
        "protocol_schema",
        EXPECTED_PROTOCOL_PATH,
        "specs/joint-handoff/joint-handoff-wire-v1.md",
    )
    neutral_wire_contract = validate_snapshot(
        document["neutral_wire_contract"],
        "neutral_wire_contract",
        EXPECTED_NEUTRAL_WIRE_CONTRACT_PATH,
        "specs/joint-handoff/wire-v1.toml",
    )
    machine_contract = validate_snapshot(
        document["machine_contract"],
        "machine_contract",
        EXPECTED_MACHINE_CONTRACT_PATH,
        "specs/joint-handoff/nexus-native-v1-refinement.toml",
    )
    validate_native_machine_contract()
    refinement_map = validate_snapshot(
        document["refinement_map"],
        "refinement_map",
        EXPECTED_REFINEMENT_MAP_PATH,
        "specs/joint-handoff/refinement-map.toml",
    )
    validate_refinement_baseline(nexus_revision)

    abstract_registry = require_exact_keys(
        document["abstract_case_registry"],
        {"claim_id", "case_count", "path", "source_path", "git_blob", "sha256"},
        "abstract_case_registry",
    )
    abstract_registry_snapshot = validate_snapshot(
        {
            "path": abstract_registry["path"],
            "source_path": abstract_registry["source_path"],
            "git_blob": abstract_registry["git_blob"],
            "sha256": abstract_registry["sha256"],
        },
        "abstract_case_registry",
        EXPECTED_ABSTRACT_REGISTRY_PATH,
        "specs/joint-handoff/fault-matrix.toml",
    )
    protocol_sha256 = protocol[0]
    machine_contract_sha256 = machine_contract[0]
    refinement_map_sha256 = refinement_map[0]
    abstract_sha256 = abstract_registry_snapshot[0]
    neutral_tree, neutral_bundle_sha256 = validate_neutral_bundle(
        joint,
        [
            ("protocol_schema", *protocol[1:]),
            ("neutral_wire_contract", *neutral_wire_contract[1:]),
            ("machine_contract", *machine_contract[1:]),
            ("refinement_map", *refinement_map[1:]),
            ("abstract_case_registry", *abstract_registry_snapshot[1:]),
        ],
    )

    registry = require_exact_keys(
        document["case_registry"], {"claim_id", "case_count", "sha256"}, "case_registry"
    )
    registry_sha256 = require_match(
        registry["sha256"], LOWER_SHA256, "case_registry.sha256"
    )
    model_source = read_regular_file(MODEL_PATH, "joint handoff registry model").decode("utf-8")
    accepted_claim = rust_constant(model_source, "JOINT_HANDOFF_CLAIM_ID", r'"[^"]+"')
    accepted_count = int(rust_constant(model_source, "JOINT_HANDOFF_CASE_COUNT", r"[0-9]+"))
    accepted_registry = rust_constant(
        model_source, "JOINT_HANDOFF_ACCEPTED_REGISTRY_SHA256", r'"[0-9a-f]{64}"'
    )
    if registry["claim_id"] != accepted_claim:
        fail("case_registry.claim_id differs from the verifier's accepted claim")
    if type(registry["case_count"]) is not int or registry["case_count"] != accepted_count:
        fail("case_registry.case_count differs from the verifier's exact registry")
    if registry_sha256 != accepted_registry:
        fail("case_registry.sha256 differs from the verifier's accepted registry digest")
    for label, value in [
        ("abstract_case_registry.claim_id", abstract_registry["claim_id"]),
        ("abstract_case_registry.case_count", abstract_registry["case_count"]),
    ]:
        expected = accepted_claim if label.endswith("claim_id") else accepted_count
        if type(value) is not type(expected) or value != expected:
            fail(f"{label} differs from the neutral-to-concrete refinement contract")
    if abstract_sha256 == registry_sha256:
        fail("abstract and concrete registry identities must remain distinct")

    return (
        nexus_revision,
        joint_revision,
        protocol_sha256,
        machine_contract_sha256,
        refinement_map_sha256,
        abstract_sha256,
        neutral_tree,
        neutral_bundle_sha256,
        source_lock_sha256,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-values", action="store_true")
    parser.add_argument("lock", nargs="?", type=Path, default=DEFAULT_LOCK)
    arguments = parser.parse_args()
    lock_path = arguments.lock
    if not lock_path.is_absolute():
        lock_path = ROOT / lock_path
    try:
        (
            nexus_revision,
            joint_revision,
            protocol_sha256,
            machine_contract_sha256,
            refinement_map_sha256,
            abstract_registry_sha256,
            neutral_tree,
            neutral_bundle_sha256,
            source_lock_sha256,
        ) = validate(lock_path)
    except (LockError, OSError) as error:
        print(f"joint handoff source-lock violation: {error}", file=sys.stderr)
        return 1

    if arguments.emit_values:
        print(f"nexus_revision={nexus_revision}")
        print(f"neutral_revision={joint_revision}")
        print(f"protocol_sha256={protocol_sha256}")
        print(f"machine_contract_sha256={machine_contract_sha256}")
        print(f"refinement_map_sha256={refinement_map_sha256}")
        print(f"abstract_registry_sha256={abstract_registry_sha256}")
        print(f"neutral_tree={neutral_tree}")
        print(f"neutral_bundle_sha256={neutral_bundle_sha256}")
        print(f"source_lock_sha256={source_lock_sha256}")
    else:
        print(
            "joint handoff reference-only source lock passed: "
            f"nexus={nexus_revision} joint={joint_revision} schema={protocol_sha256} "
            f"lock={source_lock_sha256}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
