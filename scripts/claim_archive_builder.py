#!/usr/bin/env python3
"""Build a deterministic permanent-claim evidence archive from one accepted CI run."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from claim_archive import (
    ArchiveError,
    CI_CLOSURE_JOB_NAME,
    CI_JOB_COUNT,
    CI_WORKFLOW_PATH,
    MANIFEST_MEMBER,
    MANIFEST_SCHEMA,
    _verify_live_actions,
    claim_definition_sha256,
    default_runner,
    github_source_url,
    require,
    sha256_file,
    validate_archive_tar,
    validate_manifest,
)
from claims_registry import DEFAULT_REGISTRY, ROOT, load_registry, validate_registry


CLAIM_ID = "cross-runtime-regular-file-continuity-v1"
REPOSITORY = "chenty2333/vISA"
SOURCE_BUNDLE_PATH = "sources/visa.bundle"
SOURCE_BUNDLE_REF = f"refs/heads/archive/{CLAIM_ID}"
SHA256SUMS_PATH = "SHA256SUMS"
REVERIFY_PATH = "REVERIFY.md"
EXPECTED_ARTIFACTS = (
    "stage3a-cross-runtime-regular-file-system-evidence",
    "stage3a-regular-file-system-evidence",
)
AXIS_VERIFIERS = {
    "exact-sha-closure": "scripts/check-ci-contract.py",
    "four-direction-runtime-matrix": "visa-conformance stage3a-cross-runtime",
    "regular-file-resource": "visa-conformance stage3a",
    "relocated-independent-verification": "visa-conformance stage3a-cross-runtime",
    "source-locked-runtime-lineage": "scripts/wacogo-prepare-source.py check",
    "typed-outer-normalization": "visa-conformance stage3a-cross-runtime",
}


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True).encode() + b"\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_text(command: list[str], label: str, *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ArchiveError(f"{label} failed: {result.stderr.strip() or 'nonzero exit'}")
    return result.stdout.strip()


def gh_json(endpoint: str, label: str) -> dict[str, Any]:
    output = run_text(["gh", "api", endpoint], label)
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        raise ArchiveError(f"cannot parse {label}: {error}") from error
    require(isinstance(value, dict), f"{label} must return one JSON object")
    return value


def download_actions_zip(repository: str, artifact_id: int, destination: Path) -> None:
    require(not destination.exists(), f"refusing to replace {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        result = subprocess.run(
            [
                "gh",
                "api",
                "-H",
                "Accept: application/vnd.github+json",
                f"repos/{repository}/actions/artifacts/{artifact_id}/zip",
            ],
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode != 0:
        destination.unlink(missing_ok=True)
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ArchiveError(f"Actions artifact {artifact_id} download failed: {detail}")


def pending_claim(registry_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    registry = load_registry(registry_path)
    validate_registry(registry, ROOT)
    matches = [claim for claim in registry["claims"] if claim.get("id") == CLAIM_ID]
    require(len(matches) == 1, f"registry must contain exactly one {CLAIM_ID}")
    claim = matches[0]
    acceptance = claim["acceptance_ref"]
    require(claim.get("status") == "candidate", f"{CLAIM_ID} is not a candidate")
    require(
        acceptance.get("kind") == "pending-permanent-archive-receipt",
        f"{CLAIM_ID} does not have a pending permanent receipt",
    )
    require(
        tuple(acceptance.get("workflow_artifacts", ())) == EXPECTED_ARTIFACTS,
        f"{CLAIM_ID} workflow artifact policy drifted",
    )
    require(
        set(acceptance.get("evidence_axes", ())) == set(AXIS_VERIFIERS),
        f"{CLAIM_ID} evidence-axis policy drifted",
    )
    require(
        acceptance.get("source_repositories") == [REPOSITORY],
        f"{CLAIM_ID} source repository policy drifted",
    )
    return claim, acceptance


def prepare_output_root(output_root: Path) -> tuple[Path, Path]:
    output_root = output_root.resolve(strict=False)
    require(not output_root.exists(), f"output already exists: {output_root}")
    try:
        output_root.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    except OSError as error:
        raise ArchiveError(f"cannot create archive output parent: {error}") from error
    parent = output_root.parent.resolve(strict=True)
    require(parent.is_dir(), f"archive output parent is not a directory: {parent}")
    return output_root, parent


def require_clean_source_checkout(root: Path) -> None:
    status = run_text(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        "source checkout status",
    )
    require(not status, "archive source checkout is dirty")


def collect_run(
    repository: str,
    run_id: int,
    expected_revision: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run = gh_json(f"repos/{repository}/actions/runs/{run_id}", "workflow run")
    require(run.get("id") == run_id, "workflow run id differs")
    require(run.get("run_attempt") == 1, "archive requires workflow attempt 1")
    require(run.get("path") == CI_WORKFLOW_PATH, "workflow path is not canonical CI")
    require(run.get("event") == "push", "qualification run is not a push")
    require(
        run.get("status") == "completed" and run.get("conclusion") == "success",
        "qualification run is not successful",
    )
    head_repository = run.get("head_repository")
    require(
        isinstance(head_repository, dict) and head_repository.get("full_name") == repository,
        "qualification run is not an exact-repository push",
    )
    revision = run.get("head_sha")
    require(
        isinstance(revision, str) and len(revision) == 40,
        "workflow head SHA is invalid",
    )
    if expected_revision is not None:
        require(revision == expected_revision, "workflow head differs from requested revision")

    jobs = gh_json(
        f"repos/{repository}/actions/runs/{run_id}/attempts/1/jobs?per_page=100",
        "workflow jobs",
    )
    job_items = jobs.get("jobs")
    require(isinstance(job_items, list), "workflow jobs response lacks jobs")
    require(
        jobs.get("total_count") == len(job_items) == CI_JOB_COUNT,
        f"workflow must contain exactly {CI_JOB_COUNT} successful executions",
    )
    require(
        all(
            isinstance(job, dict)
            and job.get("run_id") == run_id
            and job.get("run_attempt") == 1
            and job.get("head_sha") == revision
            and job.get("status") == "completed"
            and job.get("conclusion") == "success"
            for job in job_items
        ),
        "workflow jobs do not all bind the successful first attempt",
    )
    closure = [job for job in job_items if job.get("name") == CI_CLOSURE_JOB_NAME]
    require(len(closure) == 1, "workflow has no unique exact-SHA closure job")
    qualification = {
        "workflow_id": run["workflow_id"],
        "workflow_path": run["path"],
        "run_id": run_id,
        "run_attempt": 1,
        "head_sha": revision,
        "closure_job_id": closure[0]["id"],
        "closure_job_name": CI_CLOSURE_JOB_NAME,
        "job_count": len(job_items),
    }

    artifacts = gh_json(
        f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100",
        "workflow artifacts",
    ).get("artifacts")
    require(isinstance(artifacts, list), "workflow artifacts response lacks artifacts")
    selected: list[dict[str, Any]] = []
    for name in EXPECTED_ARTIFACTS:
        matches = [
            item
            for item in artifacts
            if isinstance(item, dict) and item.get("name") == name
        ]
        require(len(matches) == 1, f"workflow artifact {name} is not unique")
        item = matches[0]
        require(item.get("expired") is False, f"workflow artifact {name} is expired")
        require(
            isinstance(item.get("digest"), str) and item["digest"].startswith("sha256:"),
            f"workflow artifact {name} lacks an API digest",
        )
        selected.append(item)
    return qualification, selected


def create_source_bundle(
    root: Path,
    revision: str,
    tree: str,
    destination: Path,
) -> dict[str, Any]:
    require(run_text(["git", "-C", str(root), "rev-parse", "HEAD"], "current HEAD") == revision,
            "archive source checkout is not the accepted revision")
    require(
        run_text(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"], "current tree") == tree,
        "archive source tree is not the accepted tree",
    )
    existing = subprocess.run(
        ["git", "-C", str(root), "show-ref", "--verify", "--quiet", SOURCE_BUNDLE_REF],
        check=False,
    )
    require(existing.returncode == 1, f"temporary bundle ref already exists: {SOURCE_BUNDLE_REF}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    run_text(
        ["git", "-C", str(root), "update-ref", SOURCE_BUNDLE_REF, revision, "0" * 40],
        "create temporary bundle ref",
    )
    try:
        run_text(
            ["git", "-C", str(root), "bundle", "create", str(destination), SOURCE_BUNDLE_REF],
            "create accepted-source bundle",
        )
    finally:
        run_text(
            ["git", "-C", str(root), "update-ref", "-d", SOURCE_BUNDLE_REF, revision],
            "remove temporary bundle ref",
        )
    return {
        "id": "visa",
        "repository": github_source_url(REPOSITORY),
        "revision": revision,
        "tree": tree,
        "bundle_path": SOURCE_BUNDLE_PATH,
        "bundle_ref": SOURCE_BUNDLE_REF,
    }


def member(path: str, role: str, media_type: str, source: Path) -> dict[str, Any]:
    size = source.stat().st_size
    require(size > 0, f"archive payload {path} is empty")
    return {
        "path": path,
        "role": role,
        "media_type": media_type,
        "size_bytes": size,
        "sha256": sha256_file(source),
    }


def evidence_axes(
    claim: dict[str, Any],
    actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    action_paths = {item["artifact_name"]: item["path"] for item in actions}
    cross = action_paths[EXPECTED_ARTIFACTS[0]]
    predecessor = action_paths[EXPECTED_ARTIFACTS[1]]
    current = claim["id"]
    return [
        {
            "id": "exact-sha-closure",
            "claim_ids": [current],
            "member_paths": sorted([cross, predecessor, SOURCE_BUNDLE_PATH]),
            "verifier": AXIS_VERIFIERS["exact-sha-closure"],
        },
        {
            "id": "four-direction-runtime-matrix",
            "claim_ids": sorted([current, "strict-cross-runtime-continuity"]),
            "member_paths": sorted([cross, SOURCE_BUNDLE_PATH]),
            "verifier": AXIS_VERIFIERS["four-direction-runtime-matrix"],
        },
        {
            "id": "regular-file-resource",
            "claim_ids": sorted(["bounded-regular-file-continuity", current]),
            "member_paths": sorted([cross, predecessor, SOURCE_BUNDLE_PATH]),
            "verifier": AXIS_VERIFIERS["regular-file-resource"],
        },
        {
            "id": "relocated-independent-verification",
            "claim_ids": [current],
            "member_paths": sorted([cross, SOURCE_BUNDLE_PATH]),
            "verifier": AXIS_VERIFIERS["relocated-independent-verification"],
        },
        {
            "id": "source-locked-runtime-lineage",
            "claim_ids": sorted([current, "strict-cross-runtime-continuity"]),
            "member_paths": sorted([cross, SOURCE_BUNDLE_PATH]),
            "verifier": AXIS_VERIFIERS["source-locked-runtime-lineage"],
        },
        {
            "id": "typed-outer-normalization",
            "claim_ids": [current],
            "member_paths": sorted([cross, SOURCE_BUNDLE_PATH]),
            "verifier": AXIS_VERIFIERS["typed-outer-normalization"],
        },
    ]


def reverify_markdown(
    source: dict[str, Any],
    qualification: dict[str, Any],
    actions: list[dict[str, Any]],
) -> bytes:
    action_paths = {item["artifact_name"]: item["path"] for item in actions}
    verifier_lines = "\n".join(
        f"- `{axis}`: `{verifier}`" for axis, verifier in sorted(AXIS_VERIFIERS.items())
    )
    text = f"""# Reverify {CLAIM_ID}

This archive binds GitHub Actions run `{qualification['run_id']}`, attempt `1`,
and accepted vISA revision `{source['revision']}`. Run from the extracted
archive directory with Python 3, Git, Cargo, and the repository's locked
toolchains available.

```sh
sha256sum -c {SHA256SUMS_PATH}
git bundle verify {SOURCE_BUNDLE_PATH}
git clone {SOURCE_BUNDLE_PATH} visa-source
git -C visa-source checkout --detach {source['revision']}
test "$(git -C visa-source rev-parse HEAD^{{tree}})" = {source['tree']}
python3 visa-source/scripts/check-ci-contract.py
(cd visa-source && python3 scripts/wacogo-prepare-source.py check)

mkdir -p extracted/cross-runtime extracted/predecessor
python3 -m zipfile -e {action_paths[EXPECTED_ARTIFACTS[0]]} extracted/cross-runtime
python3 -m zipfile -e {action_paths[EXPECTED_ARTIFACTS[1]]} extracted/predecessor

cargo build --locked --manifest-path visa-source/Cargo.toml \
  -p visa-conformance --bin visa-conformance
cross_bundle="$(find extracted/cross-runtime -type f \
  -name stage3a-cross-runtime-evidence.json -print -quit)"
test -n "$cross_bundle"
visa-source/target/debug/visa-conformance stage3a-cross-runtime \
  "$cross_bundle" "$(dirname "$cross_bundle")"
predecessor_bundle="$(find extracted/predecessor -type f \
  -name stage3a-evidence.json -print -quit)"
test -n "$predecessor_bundle"
visa-source/target/debug/visa-conformance stage3a \
  "$predecessor_bundle" "$(dirname "$predecessor_bundle")"

detector="$(find extracted/cross-runtime -type f \
  -name stage1-defect-corpus-report.json -print -quit)"
python3 - "$detector" <<'PY'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
summary = report["summary"]
assert summary["semantic_defects"] == {{"n": 22, "detected": 22, "rate": 1.0}}
assert summary["benign_equivalents"] == {{"n": 3, "equivalent": 3, "rate": 1.0}}
assert summary["boundary_cases"] == {{"n": 1, "recorded": 1}}
assert summary["mismatches"] == 0
PY
```

The archive records the original Actions ZIP bytes. Do not recompress them:
their SHA-256 values are the API digests in `ARCHIVE-MANIFEST.json`.

Evidence-axis verifier map:

{verifier_lines}
"""
    return text.encode("ascii")


def write_ustar(
    destination: Path,
    manifest_data: bytes,
    payloads: dict[str, Path],
) -> None:
    require(not destination.exists(), f"refusing to replace {destination}")
    entries = {MANIFEST_MEMBER: manifest_data, **payloads}
    with tarfile.open(destination, mode="x:", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(entries):
            value = entries[name]
            if isinstance(value, Path):
                size = value.stat().st_size
                source = value.open("rb")
            else:
                size = len(value)
                source = io.BytesIO(value)
            try:
                info = tarfile.TarInfo(name)
                info.size = size
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.type = tarfile.REGTYPE
                archive.addfile(info, source)
            finally:
                source.close()


def assemble_archive(
    claim: dict[str, Any],
    acceptance: dict[str, Any],
    source: dict[str, Any],
    qualification: dict[str, Any],
    actions: list[dict[str, Any]],
    payloads: dict[str, Path],
    output_root: Path,
) -> tuple[Path, Path]:
    require(not output_root.exists(), f"output already exists: {output_root}")
    output_root.mkdir(parents=False, mode=0o700)
    reverify = output_root / REVERIFY_PATH
    reverify.write_bytes(reverify_markdown(source, qualification, actions))
    payloads = {**payloads, REVERIFY_PATH: reverify}

    sums = output_root / SHA256SUMS_PATH
    sums.write_text(
        "".join(f"{sha256_file(payloads[path])}  {path}\n" for path in sorted(payloads)),
        encoding="ascii",
    )
    payloads[SHA256SUMS_PATH] = sums

    action_by_path = {item["path"]: item for item in actions}
    records = []
    for path, file_path in payloads.items():
        if path in action_by_path:
            role = action_by_path[path]["role"]
            media = "application/zip"
        elif path == SOURCE_BUNDLE_PATH:
            role = "accepted-source"
            media = "application/x-git-bundle"
        elif path == REVERIFY_PATH:
            role = "offline-reverification"
            media = "text/markdown"
        else:
            role = "checksum-inventory"
            media = "text/plain"
        records.append(member(path, role, media, file_path))

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "claim_id": claim["id"],
        "claim_definition_sha256": claim_definition_sha256(claim, acceptance),
        "predecessor_ids": claim["predecessor_ids"],
        "accepted_source": source,
        "qualification": qualification,
        "actions_artifacts": actions,
        "source_bundles": [
            {
                "id": "visa",
                "repository": github_source_url(REPOSITORY),
                "revision": source["revision"],
                "tree": source["tree"],
                "bundle_path": SOURCE_BUNDLE_PATH,
                "bundle_ref": SOURCE_BUNDLE_REF,
            }
        ],
        "evidence_axes": evidence_axes(claim, actions),
        "members": sorted(records, key=lambda item: item["path"]),
    }
    validate_manifest(manifest, claim, acceptance)
    manifest_path = output_root / "claims/archive-manifests" / f"{claim['id']}.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_data = json_bytes(manifest)
    manifest_path.write_bytes(manifest_data)

    archive_path = output_root / f"{claim['id']}-evidence.tar"
    write_ustar(archive_path, manifest_data, payloads)
    validate_archive_tar(archive_path, manifest_path)
    return archive_path, manifest_path


def build_from_run(
    root: Path,
    registry_path: Path,
    repository: str,
    run_id: int,
    output_root: Path,
    expected_revision: str | None,
) -> tuple[Path, Path]:
    require(repository == REPOSITORY, f"archive repository must be {REPOSITORY}")
    claim, acceptance = pending_claim(registry_path)
    qualification, remote_artifacts = collect_run(repository, run_id, expected_revision)
    revision = qualification["head_sha"]
    tree = run_text(["git", "-C", str(root), "rev-parse", f"{revision}^{{tree}}"], "accepted tree")
    source = {"repository": repository, "revision": revision, "tree": tree}

    require_clean_source_checkout(root)
    output_root, parent = prepare_output_root(output_root)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=parent))
    os.chmod(staging, 0o700)
    try:
        payload_root = staging / ".payloads"
        payload_root.mkdir()
        actions: list[dict[str, Any]] = []
        payloads: dict[str, Path] = {}
        for index, artifact in enumerate(remote_artifacts, start=1):
            name = artifact["name"]
            archive_path = f"actions/{name}.zip"
            destination = payload_root / archive_path
            download_actions_zip(repository, artifact["id"], destination)
            require(destination.stat().st_size == artifact["size_in_bytes"],
                    f"Actions artifact {name} size differs after download")
            require(f"sha256:{sha256_file(destination)}" == artifact["digest"],
                    f"Actions artifact {name} digest differs after download")
            action = {
                "role": f"workflow-artifact-{index:02d}",
                "artifact_id": artifact["id"],
                "artifact_name": name,
                "path": archive_path,
                "api_digest": artifact["digest"],
                "run_id": run_id,
                "run_attempt": 1,
                "head_sha": revision,
                "size_bytes": artifact["size_in_bytes"],
                "expires_at": artifact["expires_at"],
            }
            actions.append(action)
            payloads[archive_path] = destination

        bundle_path = payload_root / SOURCE_BUNDLE_PATH
        create_source_bundle(root, revision, tree, bundle_path)
        payloads[SOURCE_BUNDLE_PATH] = bundle_path

        draft_root = staging / "result"
        archive_path, manifest_path = assemble_archive(
            claim,
            acceptance,
            source,
            qualification,
            actions,
            payloads,
            draft_root,
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        _verify_live_actions(default_runner, repository, qualification, manifest)
        result = {
            "schema": "visa.project-claim-archive-build-result.v1",
            "claim_id": CLAIM_ID,
            "archive": {
                "path": archive_path.name,
                "size_bytes": archive_path.stat().st_size,
                "sha256": sha256_file(archive_path),
            },
            "manifest": {
                "path": f"claims/archive-manifests/{CLAIM_ID}.json",
                "sha256": sha256_file(manifest_path),
            },
            "accepted_source": source,
            "qualification": qualification,
        }
        (draft_root / "BUILD-RESULT.json").write_bytes(json_bytes(result))
        shutil.rmtree(payload_root)
        draft_root.rename(output_root)
        shutil.rmtree(staging)
        return (
            output_root / archive_path.name,
            output_root / "claims/archive-manifests" / manifest_path.name,
        )
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", help="required workflow head SHA; defaults to current HEAD")
    parser.add_argument("--repository", default=REPOSITORY)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        revision = arguments.revision or run_text(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], "current HEAD"
        )
        archive, manifest = build_from_run(
            ROOT,
            arguments.registry,
            arguments.repository,
            arguments.run_id,
            arguments.output,
            revision,
        )
    except ArchiveError as error:
        print(f"claim archive build failed: {error}", file=os.sys.stderr)
        return 1
    print(f"claim-archive={archive} size={archive.stat().st_size} sha256={sha256_file(archive)}")
    print(f"claim-archive-manifest={manifest} sha256={sha256_file(manifest)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
