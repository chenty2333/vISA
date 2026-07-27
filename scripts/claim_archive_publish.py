#!/usr/bin/env python3
"""Publish one built claim archive to GitHub and Zenodo, then emit its receipt."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any

from claim_archive import (
    ArchiveError,
    MAX_JSON_BYTES,
    RECEIPT_SCHEMA,
    claim_definition_sha256,
    digest_string,
    exact_keys,
    git_sha,
    load_json_file,
    nonempty_string,
    positive_int,
    release_tag,
    require,
    sha256_file,
    validate_archive_tar,
    validate_manifest,
    validate_receipt,
)
from claim_archive_builder import CLAIM_ID, REPOSITORY, json_bytes, pending_claim
from claims_registry import DEFAULT_REGISTRY


ZENODO_API = "https://zenodo.org/api"
RELEASE_TAG = f"{CLAIM_ID}-evidence"
PUBLICATION_STATE_SCHEMA = "visa.project-claim-publication-state.v1"
PUBLICATION_STATE_NAME = "PUBLICATION-STATE.json"


def run(command: list[str], label: str) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise ArchiveError(f"{label} failed: {result.stderr.strip() or 'nonzero exit'}")
    return result.stdout.strip()


def gh_json(
    endpoint: str,
    label: str,
    *,
    allow_statuses: tuple[int, ...] = (),
) -> dict[str, Any] | None:
    result = subprocess.run(
        [
            "gh",
            "api",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2026-03-10",
            endpoint,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 and any(
        f"HTTP {status}" in result.stderr for status in allow_statuses
    ):
        return None
    if result.returncode != 0:
        raise ArchiveError(f"{label} failed: {result.stderr.strip() or 'nonzero exit'}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ArchiveError(f"cannot parse {label}: {error}") from error
    require(isinstance(value, dict), f"{label} must return one JSON object")
    return value


def request_json(
    method: str,
    path: str,
    *,
    token: str | None = None,
    value: Any | None = None,
    content_type: str = "application/json",
    raw: bytes | None = None,
    allow_not_found: bool = False,
) -> dict[str, Any] | list[Any] | None:
    require(path.startswith("/"), "Zenodo API path must be absolute")
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    data = raw
    if value is not None:
        require(raw is None, "Zenodo request cannot use JSON and raw bodies together")
        data = json.dumps(value, separators=(",", ":")).encode()
    if data is not None:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(
        ZENODO_API + path,
        method=method,
        headers=headers,
        data=data,
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            payload = response.read(MAX_JSON_BYTES + 1)
    except urllib.error.HTTPError as error:
        if allow_not_found and error.code == 404:
            return None
        detail = error.read().decode("utf-8", errors="replace")
        raise ArchiveError(f"Zenodo {method} {path} failed ({error.code}): {detail}") from error
    except urllib.error.URLError as error:
        raise ArchiveError(f"Zenodo {method} {path} failed: {error}") from error
    require(len(payload) <= MAX_JSON_BYTES, f"Zenodo {method} {path} response is too large")
    try:
        result = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ArchiveError(f"Zenodo {method} {path} returned invalid JSON: {error}") from error
    require(isinstance(result, (dict, list)), "Zenodo response has an invalid shape")
    return result


def md5_file(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def upload_zenodo_bucket_file(bucket_url: str, token: str, path: Path) -> dict[str, Any]:
    """Stream one archive to the authenticated Zenodo bucket API."""

    parsed = urllib.parse.urlsplit(bucket_url)
    require(
        parsed.scheme == "https"
        and parsed.hostname == "zenodo.org"
        and parsed.port is None
        and parsed.path.startswith("/api/files/")
        and not parsed.query
        and not parsed.fragment,
        "Zenodo bucket URL is outside the production files API",
    )
    target = f"{parsed.path.rstrip('/')}/{urllib.parse.quote(path.name, safe='')}"
    connection = http.client.HTTPSConnection(parsed.hostname, timeout=180)
    try:
        connection.putrequest("PUT", target)
        connection.putheader("Accept", "application/json")
        connection.putheader("Authorization", f"Bearer {token}")
        connection.putheader("Content-Type", "application/x-tar")
        connection.putheader("Content-Length", str(path.stat().st_size))
        connection.endheaders()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                connection.send(block)
        response = connection.getresponse()
        payload = response.read(MAX_JSON_BYTES + 1)
        require(len(payload) <= MAX_JSON_BYTES, "Zenodo bucket response is too large")
        if response.status < 200 or response.status >= 300:
            detail = payload.decode("utf-8", errors="replace")
            raise ArchiveError(
                f"Zenodo PUT {target} failed ({response.status}): {detail}"
            )
    except (OSError, http.client.HTTPException) as error:
        raise ArchiveError(f"Zenodo bucket upload failed: {error}") from error
    finally:
        connection.close()
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ArchiveError(f"Zenodo bucket upload returned invalid JSON: {error}") from error
    require(isinstance(value, dict), "Zenodo bucket upload response is not an object")
    return value


def zenodo_file_identity(file_record: Any, label: str) -> tuple[str, int, str]:
    require(isinstance(file_record, dict), f"{label} is not an object")
    name = file_record.get("key", file_record.get("filename", file_record.get("name")))
    size: Any = file_record.get("size", file_record.get("filesize"))
    if isinstance(size, str) and size.isdecimal():
        size = int(size)
    checksum = file_record.get("checksum")
    if isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{32}", checksum):
        checksum = f"md5:{checksum}"
    require(isinstance(name, str) and name, f"{label} name is invalid")
    require(type(size) is int and size > 0, f"{label} size is invalid")
    require(
        isinstance(checksum, str)
        and re.fullmatch(r"md5:[0-9a-f]{32}", checksum) is not None,
        f"{label} checksum is invalid",
    )
    return name, size, checksum


def require_archive_identity(file_record: Any, archive_path: Path, label: str) -> str:
    name, size, checksum = zenodo_file_identity(file_record, label)
    require(name == archive_path.name, f"{label} name differs")
    require(size == archive_path.stat().st_size, f"{label} size differs")
    require(checksum == f"md5:{md5_file(archive_path)}", f"{label} bytes differ")
    return checksum


def zenodo_metadata(
    creator: str,
    revision: str,
    release_uri: str | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "title": "vISA cross-runtime regular-file continuity evidence",
        "upload_type": "dataset",
        "description": (
            "Paper-grade evidence carrier for the vISA "
            f"{CLAIM_ID} claim at exact revision {revision}. The archive contains "
            "the original GitHub Actions ZIP bytes, accepted-source Git bundle, "
            "checksums, and independent reverification instructions."
        ),
        "creators": [{"name": creator}],
        "publication_date": date.today().isoformat(),
        "access_right": "open",
        "license": "apache-2.0",
        "keywords": [
            "WebAssembly",
            "component model",
            "cross-runtime continuity",
            "regular-file continuity",
            "reproducibility artifact",
        ],
        "version": revision,
    }
    if release_uri is not None:
        metadata["related_identifiers"] = [
            {
                "identifier": release_uri,
                "relation": "isIdenticalTo",
                "scheme": "url",
            }
        ]
    return metadata


def create_zenodo_deposition(token: str, creator: str, revision: str) -> int:
    created = request_json(
        "POST",
        "/deposit/depositions",
        token=token,
        value={"metadata": zenodo_metadata(creator, revision, None)},
    )
    require(isinstance(created, dict), "Zenodo create response is not an object")
    deposition_id = created.get("id")
    require(type(deposition_id) is int and deposition_id > 0, "Zenodo draft id is invalid")
    return deposition_id


def prepare_zenodo_deposition(
    token: str,
    archive_path: Path,
    creator: str,
    revision: str,
    deposition_id: int,
) -> int | None:
    deposition = request_json("GET", f"/deposit/depositions/{deposition_id}", token=token)
    require(isinstance(deposition, dict), "Zenodo deposition is not an object")
    require(deposition.get("id") == deposition_id, "Zenodo deposition id differs")
    metadata = deposition.get("metadata")
    require(isinstance(metadata, dict), "Zenodo deposition metadata is invalid")
    require(metadata.get("version") == revision, "Zenodo deposition revision differs")
    require(metadata.get("creators") == [{"name": creator}], "Zenodo deposition creator differs")
    if deposition.get("submitted") is True:
        record_id = deposition.get("record_id")
        require(
            type(record_id) is int and record_id > 0,
            "published deposition record id is invalid",
        )
        return record_id
    require(deposition.get("submitted") is False, "Zenodo deposition state is invalid")

    files = deposition.get("files")
    require(isinstance(files, list), "Zenodo draft file list is invalid")
    needs_upload = not files
    if files:
        require(len(files) == 1, "Zenodo draft must contain one file")
        file_record = files[0]
        require(isinstance(file_record, dict), "Zenodo draft file is not an object")
        name = file_record.get(
            "key", file_record.get("filename", file_record.get("name"))
        )
        require(name == archive_path.name, "Zenodo draft contains a foreign file")
        try:
            require_archive_identity(file_record, archive_path, "Zenodo draft file")
        except ArchiveError:
            needs_upload = True
    if needs_upload:
        links = deposition.get("links")
        require(isinstance(links, dict), "Zenodo deposition links are invalid")
        bucket = links.get("bucket")
        require(isinstance(bucket, str), "Zenodo deposition has no bucket URL")
        uploaded = upload_zenodo_bucket_file(bucket, token, archive_path)
        require_archive_identity(uploaded, archive_path, "Zenodo bucket upload")
        deposition = request_json("GET", f"/deposit/depositions/{deposition_id}", token=token)
        require(isinstance(deposition, dict), "Zenodo deposition is invalid after upload")
        files = deposition.get("files")
        require(isinstance(files, list), "Zenodo draft file list is invalid after upload")
    require(len(files) == 1, "Zenodo draft must contain one file")
    require_archive_identity(files[0], archive_path, "Zenodo draft file")
    return None


def validate_github_release(
    release: Any,
    archive_path: Path,
    tag: str,
    revision: str,
) -> dict[str, Any]:
    require(isinstance(release, dict), "GitHub release is not an object")
    require(release.get("tag_name") == tag, "GitHub release tag differs")
    require(release.get("draft") is False, "GitHub release is still a draft")
    require(release.get("immutable") is True, "GitHub release is not immutable")
    assets = release.get("assets")
    require(isinstance(assets, list) and len(assets) == 1, "GitHub release must have one asset")
    asset = assets[0]
    require(
        isinstance(asset, dict)
        and asset.get("name") == archive_path.name
        and asset.get("state") == "uploaded",
        "GitHub release asset identity differs",
    )
    require(asset.get("size") == archive_path.stat().st_size, "GitHub release asset size differs")
    require(
        asset.get("digest") == f"sha256:{sha256_file(archive_path)}",
        "GitHub release asset digest differs",
    )
    encoded = urllib.parse.quote(tag, safe="")
    target = gh_json(f"repos/{REPOSITORY}/commits/{encoded}", "release tag target")
    require(
        isinstance(target, dict) and target.get("sha") == revision,
        "GitHub release tag target differs",
    )
    return release


def preflight_github_release(
    archive_path: Path,
    tag: str,
    revision: str,
) -> dict[str, Any] | None:
    immutable = gh_json(f"repos/{REPOSITORY}/immutable-releases", "immutable-release policy")
    require(
        isinstance(immutable, dict) and immutable.get("enabled") is True,
        "repository Immutable Releases are not enabled",
    )
    encoded = urllib.parse.quote(tag, safe="")
    tag_target = gh_json(
        f"repos/{REPOSITORY}/commits/{encoded}",
        "existing release tag target",
        allow_statuses=(404, 422),
    )
    if tag_target is not None:
        require(tag_target.get("sha") == revision, "existing release tag targets another revision")
    release = gh_json(
        f"repos/{REPOSITORY}/releases/tags/{encoded}",
        "existing release",
        allow_statuses=(404,),
    )
    if release is not None:
        require(tag_target is not None, "existing release tag does not resolve")
        return validate_github_release(release, archive_path, tag, revision)
    return None


def ensure_github_release(
    archive_path: Path,
    tag: str,
    revision: str,
    existing_release: dict[str, Any] | None,
) -> dict[str, Any]:
    release = existing_release
    encoded = urllib.parse.quote(tag, safe="")
    if release is None:
        notes = (
            f"Permanent evidence for `{CLAIM_ID}` at accepted revision `{revision}`. "
            "The sole asset is independently mirrored byte-for-byte on Zenodo."
        )
        run(
            [
                "gh",
                "release",
                "create",
                tag,
                str(archive_path),
                "--repo",
                REPOSITORY,
                "--target",
                revision,
                "--title",
                f"vISA {CLAIM_ID} evidence",
                "--notes",
                notes,
                "--latest=false",
            ],
            "create immutable GitHub release",
        )
        release = gh_json(
            f"repos/{REPOSITORY}/releases/tags/{encoded}",
            "created release",
        )
    release = validate_github_release(release, archive_path, tag, revision)

    last_error = "release attestation was not available"
    for _ in range(12):
        result = subprocess.run(
            ["gh", "release", "verify", tag, "--repo", REPOSITORY],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            break
        last_error = result.stderr.strip() or last_error
        time.sleep(5)
    else:
        raise ArchiveError(f"GitHub release attestation verification failed: {last_error}")
    run(
        ["gh", "release", "verify-asset", tag, str(archive_path), "--repo", REPOSITORY],
        "verify GitHub release asset attestation",
    )
    with tempfile.TemporaryDirectory(prefix="visa-release-download-") as temporary:
        run(
            [
                "gh",
                "release",
                "download",
                tag,
                "--repo",
                REPOSITORY,
                "--pattern",
                archive_path.name,
                "--dir",
                temporary,
            ],
            "download GitHub release asset",
        )
        downloaded = Path(temporary) / archive_path.name
        require(
            downloaded.stat().st_size == archive_path.stat().st_size
            and sha256_file(downloaded) == sha256_file(archive_path),
            "downloaded GitHub release asset differs",
        )
    return release


def validate_published_zenodo_record(
    record: Any,
    record_id: int,
    archive_path: Path,
    revision: str,
) -> dict[str, Any]:
    require(isinstance(record, dict), "Zenodo public record is not an object")
    require(record.get("id") == record_id, "Zenodo public record id differs")
    require(record.get("status") == "published", "Zenodo public record is not published")
    require(record.get("doi") == f"10.5281/zenodo.{record_id}", "Zenodo version DOI differs")
    metadata = record.get("metadata")
    require(isinstance(metadata, dict), "Zenodo public metadata is invalid")
    require(metadata.get("version") == revision, "Zenodo public revision differs")
    files = record.get("files")
    require(isinstance(files, list) and len(files) == 1, "Zenodo record must have one file")
    require_archive_identity(files[0], archive_path, "Zenodo public file")

    content_uri = (
        f"{ZENODO_API}/records/{record_id}/files/"
        f"{urllib.parse.quote(archive_path.name, safe='')}/content"
    )
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(content_uri, timeout=180) as response:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                require(size <= archive_path.stat().st_size, "published Zenodo file is too large")
                digest.update(block)
    except urllib.error.URLError as error:
        raise ArchiveError(f"cannot download published Zenodo file: {error}") from error
    require(
        size == archive_path.stat().st_size and digest.hexdigest() == sha256_file(archive_path),
        "published Zenodo bytes differ",
    )
    return record


def publish_zenodo(
    token: str,
    deposition_id: int,
    archive_path: Path,
    creator: str,
    revision: str,
    release_uri: str,
    prepared_record_id: int | None,
) -> dict[str, Any]:
    record_id = prepared_record_id
    if record_id is None:
        updated = request_json(
            "PUT",
            f"/deposit/depositions/{deposition_id}",
            token=token,
            value={"metadata": zenodo_metadata(creator, revision, release_uri)},
        )
        require(isinstance(updated, dict), "Zenodo metadata update is not an object")
        published = request_json(
            "POST",
            f"/deposit/depositions/{deposition_id}/actions/publish",
            token=token,
        )
        require(isinstance(published, dict), "Zenodo publish response is not an object")
        record_id = published.get("record_id", published.get("id"))
        require(type(record_id) is int and record_id > 0, "Zenodo record id is invalid")

    record: dict[str, Any] | None = None
    for _ in range(24):
        observed = request_json("GET", f"/records/{record_id}", allow_not_found=True)
        if isinstance(observed, dict) and observed.get("status") == "published":
            record = observed
            break
        time.sleep(5)
    require(record is not None, "Zenodo public record did not reach published state")
    return validate_published_zenodo_record(record, record_id, archive_path, revision)


def validate_build_result(
    build_root: Path,
    archive_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
) -> None:
    result_path = build_root / "BUILD-RESULT.json"
    require(result_path.is_file() and not result_path.is_symlink(), "BUILD-RESULT.json is absent")
    result, _ = load_json_file(result_path, "claim archive build result")
    exact_keys(
        result,
        {"schema", "claim_id", "archive", "manifest", "accepted_source", "qualification"},
        "claim archive build result",
    )
    require(
        result["schema"] == "visa.project-claim-archive-build-result.v1",
        "claim archive build-result schema differs",
    )
    require(result["claim_id"] == CLAIM_ID, "claim archive build-result claim differs")
    archive = exact_keys(
        result["archive"], {"path", "size_bytes", "sha256"}, "build-result archive"
    )
    require(archive["path"] == archive_path.name, "build-result archive path differs")
    require(
        positive_int(archive["size_bytes"], "build-result archive size")
        == archive_path.stat().st_size,
        "build-result archive size differs",
    )
    require(
        digest_string(archive["sha256"], "build-result archive digest")
        == sha256_file(archive_path),
        "build-result archive digest differs",
    )
    manifest_result = exact_keys(
        result["manifest"], {"path", "sha256"}, "build-result manifest"
    )
    require(
        manifest_result["path"] == f"claims/archive-manifests/{CLAIM_ID}.json",
        "build-result manifest path differs",
    )
    require(
        digest_string(manifest_result["sha256"], "build-result manifest digest")
        == sha256_file(manifest_path),
        "build-result manifest digest differs",
    )
    require(result["accepted_source"] == manifest["accepted_source"], "build-result source differs")
    require(
        result["qualification"] == manifest["qualification"],
        "build-result qualification differs",
    )


def publication_state_value(
    archive_path: Path,
    revision: str,
    tag: str,
    creator: str,
    deposition_id: int,
) -> dict[str, Any]:
    return {
        "schema": PUBLICATION_STATE_SCHEMA,
        "claim_id": CLAIM_ID,
        "archive_name": archive_path.name,
        "archive_size_bytes": archive_path.stat().st_size,
        "archive_sha256": sha256_file(archive_path),
        "accepted_revision": revision,
        "release_tag": tag,
        "creator": creator,
        "zenodo_deposition_id": deposition_id,
    }


def resolve_zenodo_deposition(
    build_root: Path,
    archive_path: Path,
    revision: str,
    tag: str,
    creator: str,
    token: str,
    supplied_id: int | None,
) -> int:
    state_path = build_root / PUBLICATION_STATE_NAME
    if state_path.exists():
        require(state_path.is_file() and not state_path.is_symlink(), "publication state is unsafe")
        state, _ = load_json_file(state_path, "claim archive publication state")
        exact_keys(
            state,
            {
                "schema",
                "claim_id",
                "archive_name",
                "archive_size_bytes",
                "archive_sha256",
                "accepted_revision",
                "release_tag",
                "creator",
                "zenodo_deposition_id",
            },
            "claim archive publication state",
        )
        deposition_id = positive_int(
            state["zenodo_deposition_id"], "publication-state Zenodo deposition id"
        )
        require(
            state == publication_state_value(
                archive_path, revision, tag, creator, deposition_id
            ),
            "publication state differs from the requested archive",
        )
        if supplied_id is not None:
            require(
                supplied_id == deposition_id,
                "supplied Zenodo deposition id differs from state",
            )
        print(f"zenodo-draft-id={deposition_id}", flush=True)
        return deposition_id

    if supplied_id is None:
        deposition_id = create_zenodo_deposition(token, creator, revision)
    else:
        deposition_id = positive_int(supplied_id, "supplied Zenodo deposition id")
    print(f"zenodo-draft-id={deposition_id}", flush=True)
    state_data = json_bytes(
        publication_state_value(archive_path, revision, tag, creator, deposition_id)
    )
    with tempfile.NamedTemporaryFile(
        mode="wb", prefix=f".{PUBLICATION_STATE_NAME}.", dir=build_root, delete=False
    ) as temporary:
        temporary.write(state_data)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    os.chmod(temporary_path, 0o600)
    try:
        require(not state_path.exists(), "publication state appeared concurrently")
        os.replace(temporary_path, state_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return deposition_id


def preflight_publication(
    build_root: Path,
    registry_path: Path,
    tag: str,
    creator: str,
    token: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    Path,
    Path,
    dict[str, Any],
    str,
    dict[str, Any] | None,
]:
    require(
        build_root.is_dir() and not build_root.is_symlink(),
        "build root is absent or unsafe",
    )
    require(
        release_tag(tag, "publication release tag") == RELEASE_TAG,
        "release tag is not canonical",
    )
    require(
        nonempty_string(creator, "Zenodo creator") == creator.strip(),
        "creator has outer whitespace",
    )
    nonempty_string(token, "Zenodo access token")
    claim, acceptance = pending_claim(registry_path)
    archive_path = build_root / f"{CLAIM_ID}-evidence.tar"
    manifest_path = build_root / "claims/archive-manifests" / f"{CLAIM_ID}.json"
    require(
        archive_path.is_file()
        and not archive_path.is_symlink()
        and manifest_path.is_file()
        and not manifest_path.is_symlink(),
        "build output is incomplete or unsafe",
    )
    manifest, _ = load_json_file(manifest_path, "claim archive manifest")
    validate_manifest(manifest, claim, acceptance)
    validate_archive_tar(archive_path, manifest_path)
    validate_build_result(build_root, archive_path, manifest_path, manifest)
    revision = git_sha(manifest["accepted_source"]["revision"], "accepted revision")
    require(manifest["qualification"]["head_sha"] == revision, "qualification revision differs")
    existing_release = preflight_github_release(archive_path, tag, revision)
    return (
        claim,
        acceptance,
        archive_path,
        manifest_path,
        manifest,
        revision,
        existing_release,
    )


def closure_receipt(
    claim: dict[str, Any],
    acceptance: dict[str, Any],
    manifest: dict[str, Any],
    manifest_path: Path,
    archive_path: Path,
    release: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    members = {item["path"]: item for item in manifest["members"]}
    sums_path = next(path for path in members if Path(path).name == "SHA256SUMS")
    reverify_path = next(path for path in members if Path(path).name == "REVERIFY.md")
    record_id = record["id"]
    files = record["files"]
    _, _, provider_checksum = zenodo_file_identity(files[0], "Zenodo receipt file")
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "claim_id": claim["id"],
        "claim_definition_sha256": claim_definition_sha256(claim, acceptance),
        "predecessor_ids": claim["predecessor_ids"],
        "accepted_source": manifest["accepted_source"],
        "qualification": manifest["qualification"],
        "archive": {
            "release_tag": release["tag_name"],
            "release_uri": release["html_url"],
            "asset_name": archive_path.name,
            "asset_size_bytes": archive_path.stat().st_size,
            "asset_sha256": sha256_file(archive_path),
            "manifest_path": f"claims/archive-manifests/{claim['id']}.json",
            "manifest_sha256": sha256_file(manifest_path),
            "sha256sums_path": sums_path,
            "sha256sums_sha256": members[sums_path]["sha256"],
            "reverify_path": reverify_path,
            "reverify_sha256": members[reverify_path]["sha256"],
            "release_attestation": {
                "kind": "github-immutable-release",
                "verification": "gh-release-verify-and-verify-asset",
            },
        },
        "second_copy": {
            "kind": "zenodo-record-file-v1",
            "record_id": record_id,
            "doi": record["doi"],
            "asset_name": archive_path.name,
            "asset_size_bytes": archive_path.stat().st_size,
            "provider_checksum": provider_checksum,
            "asset_sha256": sha256_file(archive_path),
        },
    }
    validate_receipt(receipt, claim, acceptance)
    return receipt


def publish(
    build_root: Path,
    registry_path: Path,
    tag: str,
    creator: str,
    token: str,
    deposition_id: int | None,
) -> tuple[Path, dict[str, Any]]:
    (
        claim,
        acceptance,
        archive_path,
        manifest_path,
        manifest,
        revision,
        existing_release,
    ) = preflight_publication(build_root, registry_path, tag, creator, token)
    deposition_id = resolve_zenodo_deposition(
        build_root,
        archive_path,
        revision,
        tag,
        creator,
        token,
        deposition_id,
    )
    prepared_record_id = prepare_zenodo_deposition(
        token, archive_path, creator, revision, deposition_id
    )
    release = ensure_github_release(
        archive_path, tag, revision, existing_release
    )
    record = publish_zenodo(
        token,
        deposition_id,
        archive_path,
        creator,
        revision,
        release["html_url"],
        prepared_record_id,
    )
    receipt = closure_receipt(
        claim,
        acceptance,
        manifest,
        manifest_path,
        archive_path,
        release,
        record,
    )
    receipt_path = build_root / "claims/receipts" / f"{CLAIM_ID}.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_data = json_bytes(receipt)
    if receipt_path.exists():
        require(receipt_path.read_bytes() == receipt_data, "existing receipt differs")
    else:
        receipt_path.write_bytes(receipt_data)
    result = {
        "schema": "visa.project-claim-publication-result.v1",
        "claim_id": CLAIM_ID,
        "accepted_source": manifest["accepted_source"],
        "release": {
            "tag": release["tag_name"],
            "uri": release["html_url"],
            "immutable": release["immutable"],
        },
        "zenodo": {"record_id": record["id"], "doi": record["doi"]},
        "receipt": {
            "path": f"claims/receipts/{CLAIM_ID}.json",
            "sha256": hashlib.sha256(receipt_data).hexdigest(),
        },
    }
    result_path = build_root / "PUBLICATION-RESULT.json"
    result_data = json_bytes(result)
    if result_path.exists():
        require(result_path.read_bytes() == result_data, "existing publication result differs")
    else:
        result_path.write_bytes(result_data)
    return receipt_path, result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--tag", default=RELEASE_TAG)
    parser.add_argument("--creator", required=True)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--zenodo-token-env", default="ZENODO_ACCESS_TOKEN")
    parser.add_argument("--zenodo-deposition-id", type=int)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    token = os.environ.get(arguments.zenodo_token_env, "")
    if not token:
        print(
            f"claim archive publication failed: {arguments.zenodo_token_env} is not set",
            file=os.sys.stderr,
        )
        return 1
    try:
        receipt_path, result = publish(
            arguments.build_root,
            arguments.registry,
            arguments.tag,
            arguments.creator,
            token,
            arguments.zenodo_deposition_id,
        )
    except ArchiveError as error:
        print(f"claim archive publication failed: {error}", file=os.sys.stderr)
        return 1
    print(f"claim-receipt={receipt_path} sha256={result['receipt']['sha256']}")
    print(f"github-release={result['release']['uri']}")
    print(f"zenodo-doi={result['zenodo']['doi']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
