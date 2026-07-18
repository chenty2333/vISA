#!/usr/bin/env python3
"""Regression tests for permanent project-claim archive verification."""

from __future__ import annotations

import hashlib
import io
import json
import copy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from claim_archive import (  # noqa: E402
    ArchiveError,
    claim_definition_sha256,
    permanent_claims_at_baseline,
    require_permanent_claims_monotonic,
    validate_archive_tar,
    validate_closure_record,
    verify_online,
)


def json_bytes(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(command: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed: {command}: {result.stderr}")
    return result.stdout.strip()


class Fixture:
    claim_id = "bounded-joint-handoff-refinement-v2"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.payloads: dict[str, bytes] = {}
        run(["git", "init", "--quiet"], self.root)
        run(["git", "config", "user.email", "archive-test@example.invalid"], self.root)
        run(["git", "config", "user.name", "Archive Test"], self.root)
        self.external_repositories = self._prepare_external_repositories()
        self.claim = {
            "id": self.claim_id,
            "track": "joint-handoff",
            "status": "earned",
            "scope_ref": {"path": "docs/ROADMAP.md", "heading": "track"},
            "validation_ref": {"path": "docs/VALIDATION.md", "heading": "qualification"},
            "implementation_refs": ["scripts/run-logical-request-admission-cell.sh"],
            "predecessor_ids": ["bounded-joint-handoff-refinement-v1"],
        }
        self.acceptance = {
            "kind": "permanent-archive-receipt",
            "path": f"claims/receipts/{self.claim_id}.json",
            "heading": None,
            "evidence_axes": ["admission-order", "joint-refinement"],
            "source_repositories": [
                "chenty2333/Nexus",
                "chenty2333/vISA",
                "chenty2333/visa-nexus-handoff",
            ],
            "workflow_artifacts": [
                "joint-handoff-reference-system-evidence",
                "nexus-visa-same-boot-qualification-evidence",
            ],
            "receipt_sha256": None,
        }
        scope_contract = (
            f"<!-- claim-semantic-contract:{self.claim_id}:scope:start -->\n"
            "Normative fixture scope remains bounded.\n"
            f"<!-- claim-semantic-contract:{self.claim_id}:scope:end -->\n"
        )
        validation_contract = (
            f"<!-- claim-semantic-contract:{self.claim_id}:validation:start -->\n"
            "Normative fixture validation remains exact.\n"
            f"<!-- claim-semantic-contract:{self.claim_id}:validation:end -->\n"
        )
        docs = self.root / "docs"
        docs.mkdir()
        (docs / "ROADMAP.md").write_text(
            "# Fixture roadmap\n\n## track\n\n" + scope_contract,
            encoding="utf-8",
        )
        (docs / "VALIDATION.md").write_text(
            "# Fixture validation\n\n## qualification\n\n" + validation_contract,
            encoding="utf-8",
        )
        self.acceptance["semantic_contracts"] = {
            "scope_sha256": digest(scope_contract.encode()),
            "validation_sha256": digest(validation_contract.encode()),
        }
        implementation = self.root / "scripts/run-logical-request-admission-cell.sh"
        implementation.parent.mkdir()
        implementation.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (self.root / "fixture-source.txt").write_text("accepted source\n", encoding="utf-8")
        workflow = self.root / ".github/workflows/ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(
            "name: fixture-ci\n"
            f"claim: {self.claim_id}:required\n",
            encoding="utf-8",
        )
        locks = self.root / "third_party/joint-handoff-qualification"
        locks.mkdir(parents=True)
        nexus = self.external_repositories["nexus"]
        wire = self.external_repositories["wire"]
        (locks / "source-lock.json").write_bytes(
            json_bytes(
                {
                    "schema": "visa.joint-handoff-qualification-source-lock.v1",
                    "nexus": {
                        "repository": "https://github.com/chenty2333/Nexus",
                        "revision": nexus["baseline_revision"],
                    },
                    "joint_artifact": {
                        "repository": "https://github.com/chenty2333/visa-nexus-handoff",
                        "revision": wire["revision"],
                        "tree": wire["tree"],
                    },
                }
            )
        )
        (locks / "nexus-qualification-lock.json").write_bytes(
            json_bytes(
                {
                    "schema": "visa.nexus-handoff-qualification-lock.v2",
                    "nexus": {
                        "repository": "https://github.com/chenty2333/Nexus",
                        "revision": nexus["revision"],
                        "analyzed_baseline_revision": nexus["baseline_revision"],
                    },
                }
            )
        )
        candidate_claim = copy.deepcopy(self.claim)
        candidate_claim["status"] = "candidate"
        candidate_claim["acceptance_ref"] = copy.deepcopy(self.acceptance)
        candidate_claim["acceptance_ref"]["kind"] = (
            "pending-permanent-archive-receipt"
        )
        candidate_bindings = [
            {
                "id": "joint-reference",
                "job": "reference",
                "matrix_lane": None,
                "tier": None,
                "artifact": "joint-handoff-reference-system-evidence",
                "claims": [{"id": self.claim_id, "role": "required"}],
            },
            {
                "id": "nexus-admission",
                "job": "admission",
                "matrix_lane": None,
                "tier": None,
                "artifact": "nexus-visa-same-boot-qualification-evidence",
                "claims": [{"id": self.claim_id, "role": "required"}],
            },
        ]
        registry = self.root / "claims/registry.json"
        registry.parent.mkdir()
        registry.write_bytes(
            json_bytes(
                {
                    "schema": "visa.project-claim-registry.v1",
                    "claims": [candidate_claim],
                    "workflow_bindings": candidate_bindings,
                }
            )
        )
        readme = self.root / "README.md"
        readme.write_text(
            "# Fixture\n\n"
            "<!-- claims-registry:start -->\n"
            "| Claim | Status |\n"
            "| --- | --- |\n"
            f"| `{self.claim_id}` | `candidate` |\n"
            "<!-- claims-registry:end -->\n",
            encoding="utf-8",
        )
        run(
            [
                "git",
                "add",
                "fixture-source.txt",
                ".github",
                "README.md",
                "docs",
                "scripts/run-logical-request-admission-cell.sh",
                "third_party",
                "claims/registry.json",
            ],
            self.root,
        )
        run(["git", "commit", "--quiet", "-m", "accepted source"], self.root)
        self.bundles = self._make_bundles()
        self.accepted_source = {
            "repository": "chenty2333/vISA",
            "revision": self.bundles[1]["revision"],
            "tree": self.bundles[1]["tree"],
        }
        self.qualification = {
            "workflow_id": 1234,
            "workflow_path": ".github/workflows/ci.yml",
            "run_id": 9001,
            "run_attempt": 1,
            "head_sha": self.accepted_source["revision"],
            "closure_job_id": 7003,
            "closure_job_name": "Exact-SHA qualification closure",
            "job_count": 12,
        }
        self.actions = self._make_actions()
        self.manifest = self._make_manifest()
        self.manifest_path = self.root / f"claims/archive-manifests/{self.claim_id}.json"
        self.manifest_path.parent.mkdir(parents=True)
        self.manifest_path.write_bytes(json_bytes(self.manifest))
        self.archive_path = self.root / f"{self.claim_id}-evidence.tar"
        self.write_tar(self.archive_path, self.manifest, self.payloads)
        self.receipt = self._make_receipt()
        self.receipt_path = self.root / self.acceptance["path"]
        self.receipt_path.parent.mkdir(parents=True)
        self.write_receipt()
        permanent_claim = copy.deepcopy(self.claim)
        permanent_claim["acceptance_ref"] = copy.deepcopy(self.acceptance)
        permanent_bindings = copy.deepcopy(candidate_bindings)
        for binding in permanent_bindings:
            binding["claims"][0]["role"] = "regresses"
        registry.write_bytes(
            json_bytes(
                {
                    "schema": "visa.project-claim-registry.v1",
                    "claims": [permanent_claim],
                    "workflow_bindings": permanent_bindings,
                }
            )
        )
        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace(
                f"{self.claim_id}:required", f"{self.claim_id}:regresses"
            ),
            encoding="utf-8",
        )
        readme.write_text(
            readme.read_text(encoding="utf-8").replace(
                "| `candidate` |", "| `earned` |"
            ),
            encoding="utf-8",
        )
        run(["git", "add", "claims", ".github/workflows/ci.yml", "README.md"], self.root)
        run(["git", "commit", "--quiet", "-m", "closure receipt"], self.root)

    def _prepare_external_repositories(self) -> dict[str, dict[str, object]]:
        repositories: dict[str, dict[str, object]] = {}
        for bundle_id in ("nexus", "wire"):
            checkout = self.root / f"repo-{bundle_id}"
            checkout.mkdir()
            run(["git", "init", "--quiet"], checkout)
            run(["git", "config", "user.email", "archive-test@example.invalid"], checkout)
            run(["git", "config", "user.name", "Archive Test"], checkout)
            source = checkout / "source.txt"
            source.write_text(f"{bundle_id} baseline\n", encoding="utf-8")
            run(["git", "add", "source.txt"], checkout)
            run(["git", "commit", "--quiet", "-m", "fixture baseline"], checkout)
            baseline_revision = run(["git", "rev-parse", "HEAD"], checkout)
            if bundle_id == "nexus":
                source.write_text("nexus qualified\n", encoding="utf-8")
                run(["git", "add", "source.txt"], checkout)
                run(["git", "commit", "--quiet", "-m", "fixture qualified"], checkout)
            revision = run(["git", "rev-parse", "HEAD"], checkout)
            repositories[bundle_id] = {
                "checkout": checkout,
                "baseline_revision": baseline_revision,
                "revision": revision,
                "tree": run(["git", "rev-parse", "HEAD^{tree}"], checkout),
            }
        return repositories

    def _make_bundles(self) -> list[dict[str, object]]:
        values: list[dict[str, object]] = []
        definitions = [
            ("nexus", "chenty2333/Nexus"),
            ("visa", "chenty2333/vISA"),
            ("wire", "chenty2333/visa-nexus-handoff"),
        ]
        for bundle_id, repository in definitions:
            if bundle_id == "visa":
                checkout = self.root
                revision = run(["git", "rev-parse", "HEAD"], checkout)
                tree = run(["git", "rev-parse", "HEAD^{tree}"], checkout)
            else:
                external = self.external_repositories[bundle_id]
                checkout = external["checkout"]
                revision = external["revision"]
                tree = external["tree"]
            ref = f"refs/heads/archive/{bundle_id}"
            run(["git", "branch", f"archive/{bundle_id}", revision], checkout)
            bundle_path = f"sources/{bundle_id}.bundle"
            absolute = self.root / bundle_path
            absolute.parent.mkdir(parents=True, exist_ok=True)
            run(["git", "bundle", "create", str(absolute), ref], checkout)
            data = absolute.read_bytes()
            self.payloads[bundle_path] = data
            values.append(
                {
                    "id": bundle_id,
                    "repository": f"https://github.com/{repository}.git",
                    "revision": revision,
                    "tree": tree,
                    "bundle_path": bundle_path,
                    "bundle_ref": ref,
                }
            )
        return values

    def _zip_bytes(self, name: str, content: str) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
        return output.getvalue()

    def _make_actions(self) -> list[dict[str, object]]:
        definitions = [
            (
                "joint-reference",
                8101,
                "joint-handoff-reference-system-evidence",
                "actions/joint-handoff-reference-system-evidence.zip",
            ),
            (
                "nexus-admission",
                8102,
                "nexus-visa-same-boot-qualification-evidence",
                "actions/nexus-visa-same-boot-qualification-evidence.zip",
            ),
        ]
        actions: list[dict[str, object]] = []
        for role, artifact_id, artifact_name, path in definitions:
            data = self._zip_bytes("evidence/report.txt", f"{role}\n")
            self.payloads[path] = data
            actions.append(
                {
                    "role": role,
                    "artifact_id": artifact_id,
                    "artifact_name": artifact_name,
                    "path": path,
                    "api_digest": f"sha256:{digest(data)}",
                    "run_id": self.qualification["run_id"],
                    "run_attempt": self.qualification["run_attempt"],
                    "head_sha": self.qualification["head_sha"],
                    "size_bytes": len(data),
                    "expires_at": "2026-07-31T07:00:00Z",
                }
            )
        return actions

    def _make_manifest(self) -> dict[str, object]:
        reverify_path = "REVERIFY.md"
        reverify = (
            "# Reverify\n\n"
            "sha256sum -c SHA256SUMS\n"
            "git bundle verify sources/nexus.bundle\n"
            "visa-conformance joint-handoff\n"
            "logical-request-admission verify\n"
        ).encode()
        self.payloads[reverify_path] = reverify
        sums_path = "SHA256SUMS"
        checksum_paths = sorted(self.payloads)
        sums = "".join(f"{digest(self.payloads[path])}  {path}\n" for path in checksum_paths).encode()
        self.payloads[sums_path] = sums
        roles = {
            "actions/joint-handoff-reference-system-evidence.zip": "original-actions-reference",
            "actions/nexus-visa-same-boot-qualification-evidence.zip": "original-actions-admission",
            "sources/nexus.bundle": "source-nexus",
            "sources/visa.bundle": "source-visa",
            "sources/wire.bundle": "source-wire",
            "REVERIFY.md": "reverification-instructions",
            "SHA256SUMS": "payload-checksums",
        }
        media = {
            ".zip": "application/zip",
            ".bundle": "application/x-git-bundle",
            ".md": "text/markdown",
        }
        members = []
        for path in sorted(self.payloads):
            suffix = Path(path).suffix
            members.append(
                {
                    "path": path,
                    "role": roles[path],
                    "media_type": media.get(suffix, "text/plain"),
                    "size_bytes": len(self.payloads[path]),
                    "sha256": digest(self.payloads[path]),
                }
            )
        definition = claim_definition_sha256(self.claim, self.acceptance)
        return {
            "schema": "visa.project-claim-archive.v1",
            "claim_id": self.claim_id,
            "claim_definition_sha256": definition,
            "predecessor_ids": list(self.claim["predecessor_ids"]),
            "accepted_source": self.accepted_source,
            "qualification": self.qualification,
            "actions_artifacts": self.actions,
            "source_bundles": self.bundles,
            "evidence_axes": [
                {
                    "id": "admission-order",
                    "claim_ids": [self.claim_id],
                    "member_paths": ["actions/nexus-visa-same-boot-qualification-evidence.zip"],
                    "verifier": "logical-request-admission verify",
                },
                {
                    "id": "joint-refinement",
                    "claim_ids": [
                        "bounded-joint-handoff-refinement-v1",
                        self.claim_id,
                    ],
                    "member_paths": ["actions/joint-handoff-reference-system-evidence.zip"],
                    "verifier": "visa-conformance joint-handoff",
                },
            ],
            "members": members,
        }

    def _make_receipt(self) -> dict[str, object]:
        archive_data = self.archive_path.read_bytes()
        members = {item["path"]: item for item in self.manifest["members"]}
        return {
            "schema": "visa.project-claim-closure.v2",
            "claim_id": self.claim_id,
            "claim_definition_sha256": claim_definition_sha256(self.claim, self.acceptance),
            "predecessor_ids": list(self.claim["predecessor_ids"]),
            "accepted_source": self.accepted_source,
            "qualification": self.qualification,
            "archive": {
                "release_tag": "evidence-bounded-joint-handoff-refinement-v2",
                "release_uri": "https://github.com/chenty2333/vISA/releases/tag/evidence-bounded-joint-handoff-refinement-v2",
                "asset_name": f"{self.claim_id}-evidence.tar",
                "asset_size_bytes": len(archive_data),
                "asset_sha256": digest(archive_data),
                "manifest_path": f"claims/archive-manifests/{self.claim_id}.json",
                "manifest_sha256": digest(self.manifest_path.read_bytes()),
                "sha256sums_path": "SHA256SUMS",
                "sha256sums_sha256": members["SHA256SUMS"]["sha256"],
                "reverify_path": "REVERIFY.md",
                "reverify_sha256": members["REVERIFY.md"]["sha256"],
                "release_attestation": {
                    "kind": "github-immutable-release",
                    "verification": "gh-release-verify-and-verify-asset",
                },
            },
            "second_copy": {
                "kind": "zenodo-record-file-v1",
                "record_id": 424242,
                "doi": "10.5281/zenodo.424242",
                "asset_name": f"{self.claim_id}-evidence.tar",
                "asset_size_bytes": len(archive_data),
                "provider_checksum": (
                    "md5:"
                    + hashlib.md5(archive_data, usedforsecurity=False).hexdigest()
                ),
                "asset_sha256": digest(archive_data),
            },
        }

    @staticmethod
    def write_tar(path: Path, manifest: dict[str, object], payloads: dict[str, bytes]) -> None:
        with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
            entries = {"ARCHIVE-MANIFEST.json": json_bytes(manifest), **payloads}
            for name in sorted(entries):
                data = entries[name]
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))

    def write_receipt(self) -> None:
        data = json_bytes(self.receipt)
        self.receipt_path.write_bytes(data)
        self.acceptance["receipt_sha256"] = digest(data)

    def online_runner(
        self, *, tag_revision: str | None = None, immutable: bool = False
    ):
        def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            if command[0] == "git":
                return subprocess.run(
                    command, text=True, capture_output=True, check=False
                )
            if command[:3] == ["gh", "release", "verify"]:
                return subprocess.CompletedProcess(command, 0, "verified\n", "")
            if command[:3] == ["gh", "release", "verify-asset"]:
                if command[3] != self.receipt["archive"]["release_tag"]:
                    return subprocess.CompletedProcess(
                        command, 1, "", "release tag was not explicit"
                    )
                return subprocess.CompletedProcess(command, 0, "verified\n", "")
            if command[:3] == ["gh", "release", "download"]:
                destination = Path(command[command.index("--dir") + 1])
                shutil.copyfile(
                    self.archive_path,
                    destination / self.receipt["archive"]["asset_name"],
                )
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[:2] != ["gh", "api"]:
                raise AssertionError(f"unexpected command: {command}")
            endpoint = command[-1]
            if "/actions/runs/9001/attempts/1/jobs" in endpoint:
                definitions = [
                    (7001, "gate one"),
                    (7002, "gate two"),
                    (7003, "Exact-SHA qualification closure"),
                    *[(job_id, f"gate {job_id - 6999}") for job_id in range(7004, 7013)],
                ]
                jobs = [
                    {
                        "id": job_id,
                        "name": name,
                        "run_id": 9001,
                        "run_attempt": 1,
                        "head_sha": self.accepted_source["revision"],
                        "status": "completed",
                        "conclusion": "success",
                        "started_at": "2026-07-17T06:00:00Z",
                        "completed_at": "2026-07-17T06:20:00Z",
                    }
                    for job_id, name in definitions
                ]
                response = {"total_count": 12, "jobs": jobs}
            elif endpoint.endswith("/actions/runs/9001"):
                response = {
                    "id": 9001,
                    "run_attempt": 1,
                    "head_sha": self.accepted_source["revision"],
                    "event": "push",
                    "head_repository": {"full_name": "chenty2333/vISA"},
                }
            elif "/actions/runs/9001/attempts/1" in endpoint:
                response = {
                    "id": 9001,
                    "run_attempt": 1,
                    "workflow_id": 1234,
                    "path": ".github/workflows/ci.yml",
                    "head_sha": self.accepted_source["revision"],
                    "event": "push",
                    "head_repository": {"full_name": "chenty2333/vISA"},
                    "status": "completed",
                    "conclusion": "success",
                }
            elif "/actions/runs/9001/artifacts" in endpoint:
                response = {
                    "artifacts": [
                        {
                            "id": item["artifact_id"],
                            "name": item["artifact_name"],
                            "size_in_bytes": item["size_bytes"],
                            "digest": item["api_digest"],
                            "expired": False,
                            "created_at": "2026-07-17T06:10:00Z",
                            "updated_at": "2026-07-17T06:11:00Z",
                            "workflow_run": {
                                "id": 9001,
                                "head_sha": self.accepted_source["revision"],
                            },
                        }
                        for item in self.actions
                    ]
                }
            elif "/git/commits/" in endpoint:
                response = {
                    "sha": self.accepted_source["revision"],
                    "tree": {"sha": self.accepted_source["tree"]},
                }
            elif "/commits/" in endpoint:
                response = {
                    "sha": tag_revision or self.accepted_source["revision"]
                }
            elif "/releases/tags/" in endpoint:
                archive = self.receipt["archive"]
                response = {
                    "tag_name": archive["release_tag"],
                    "html_url": archive["release_uri"],
                    "immutable": immutable,
                    "assets": (
                        [
                            {
                                "name": archive["asset_name"],
                                "state": "uploaded",
                                "size": archive["asset_size_bytes"],
                                "digest": f"sha256:{archive['asset_sha256']}",
                            }
                        ]
                        if immutable
                        else []
                    ),
                }
            else:
                raise AssertionError(f"unexpected command: {command}")
            return subprocess.CompletedProcess(command, 0, json.dumps(response), "")

        return runner

    def rewrite_manifest(self) -> None:
        self.manifest_path.write_bytes(json_bytes(self.manifest))
        self.receipt["archive"]["manifest_sha256"] = digest(self.manifest_path.read_bytes())
        self.write_receipt()
        registry_path = self.root / "claims/registry.json"
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        current_claim = copy.deepcopy(self.claim)
        current_claim["acceptance_ref"] = copy.deepcopy(self.acceptance)
        registry["claims"] = [current_claim]
        registry_path.write_bytes(json_bytes(registry))
        run(["git", "add", "claims"], self.root)
        run(["git", "commit", "--quiet", "--amend", "--no-edit"], self.root)


class ClaimArchiveTests(unittest.TestCase):
    def make_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Fixture]:
        temporary = tempfile.TemporaryDirectory(prefix="visa-claim-archive-test-")
        return temporary, Fixture(Path(temporary.name))

    def test_complete_offline_fixture(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)
            validate_archive_tar(
                fixture.archive_path,
                fixture.manifest_path,
                expected_sha256=fixture.receipt["archive"]["asset_sha256"],
                expected_size_bytes=fixture.receipt["archive"]["asset_size_bytes"],
            )

    def test_nexus_bundle_must_match_the_accepted_source_lock(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            nexus = next(
                item
                for item in fixture.manifest["source_bundles"]
                if item["id"] == "nexus"
            )
            nexus["revision"] = "0" * 40
            fixture.rewrite_manifest()
            with self.assertRaisesRegex(ArchiveError, "Nexus source bundle revision"):
                validate_closure_record(
                    fixture.root, fixture.claim, fixture.acceptance
                )

    def test_receipt_commit_cannot_change_the_accepted_ci_workflow(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            workflow = fixture.root / ".github/workflows/ci.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8").replace(
                    "fixture-ci", "changed-after-acceptance"
                ),
                encoding="utf-8",
            )
            run(["git", "add", ".github/workflows/ci.yml"], fixture.root)
            run(
                ["git", "commit", "--quiet", "--amend", "--no-edit"],
                fixture.root,
            )
            with self.assertRaisesRegex(
                ArchiveError,
                "changed beyond the successor claim lifecycle role",
            ):
                validate_closure_record(
                    fixture.root, fixture.claim, fixture.acceptance
                )

    def test_durable_head_may_change_the_claim_lifecycle_role(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            workflow = fixture.root / ".github/workflows/ci.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8").replace(
                    f"{fixture.claim_id}:regresses",
                    f"{fixture.claim_id}:supports",
                ),
                encoding="utf-8",
            )
            run(["git", "add", ".github/workflows/ci.yml"], fixture.root)
            run(["git", "commit", "--quiet", "-m", "evolve claim role"], fixture.root)
            validate_closure_record(
                fixture.root, fixture.claim, fixture.acceptance
            )

    def test_durable_head_may_change_unrelated_implementation(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            source = fixture.root / "fixture-source.txt"
            source.write_text("normal development after release\n", encoding="utf-8")
            run(["git", "add", "fixture-source.txt"], fixture.root)
            run(["git", "commit", "--quiet", "-m", "continue development"], fixture.root)
            validate_closure_record(
                fixture.root, fixture.claim, fixture.acceptance
            )

    def test_receipt_commit_cannot_change_the_scope_contract(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            roadmap = fixture.root / "docs/ROADMAP.md"
            roadmap.write_text(
                roadmap.read_text(encoding="utf-8").replace(
                    "scope remains bounded", "scope is expanded"
                ),
                encoding="utf-8",
            )
            run(["git", "add", "docs/ROADMAP.md"], fixture.root)
            run(["git", "commit", "--quiet", "-m", "expand claim scope"], fixture.root)
            with self.assertRaisesRegex(
                ArchiveError,
                "scope semantic contract digest drifted",
            ):
                validate_closure_record(
                    fixture.root, fixture.claim, fixture.acceptance
                )

    def test_receipt_commit_cannot_change_an_implementation_ref(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            implementation = (
                fixture.root / "scripts/run-logical-request-admission-cell.sh"
            )
            implementation.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            run(["git", "add", str(implementation.relative_to(fixture.root))], fixture.root)
            run(
                ["git", "commit", "--quiet", "--amend", "--no-edit"],
                fixture.root,
            )
            with self.assertRaisesRegex(
                ArchiveError,
                "implementation ref .* changed after CI acceptance",
            ):
                validate_closure_record(
                    fixture.root, fixture.claim, fixture.acceptance
                )

    def test_promotion_commit_cannot_add_an_unrelated_file(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            (fixture.root / "unrelated.txt").write_text(
                "not receipt material\n", encoding="utf-8"
            )
            run(["git", "add", "unrelated.txt"], fixture.root)
            run(
                ["git", "commit", "--quiet", "--amend", "--no-edit"],
                fixture.root,
            )
            with self.assertRaisesRegex(
                ArchiveError,
                "promotion changed non-receipt paths",
            ):
                validate_closure_record(
                    fixture.root, fixture.claim, fixture.acceptance
                )

    def test_receipt_commit_cannot_redefine_the_accepted_candidate(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.claim["track"] = "redefined-after-acceptance"
            definition = claim_definition_sha256(fixture.claim, fixture.acceptance)
            fixture.receipt["claim_definition_sha256"] = definition
            fixture.manifest["claim_definition_sha256"] = definition
            fixture.rewrite_manifest()
            with self.assertRaisesRegex(
                ArchiveError,
                "definition differs from the candidate accepted by CI",
            ):
                validate_closure_record(
                    fixture.root, fixture.claim, fixture.acceptance
                )

    def test_receipt_commit_cannot_replace_the_accepted_artifact_policy(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            replacement_names = sorted(
                ["fabricated-reference", "fabricated-admission"]
            )
            fixture.acceptance["workflow_artifacts"] = replacement_names
            for action, replacement in zip(fixture.actions, replacement_names, strict=True):
                action["artifact_name"] = replacement
            definition = claim_definition_sha256(fixture.claim, fixture.acceptance)
            fixture.receipt["claim_definition_sha256"] = definition
            fixture.manifest["claim_definition_sha256"] = definition
            fixture.rewrite_manifest()
            with self.assertRaisesRegex(
                ArchiveError,
                "definition differs from the candidate accepted by CI",
            ):
                validate_closure_record(
                    fixture.root, fixture.claim, fixture.acceptance
                )

    def test_missing_acceptance_axis_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.acceptance["evidence_axes"] = ["joint-refinement"]
            definition = claim_definition_sha256(fixture.claim, fixture.acceptance)
            fixture.receipt["claim_definition_sha256"] = definition
            fixture.manifest["claim_definition_sha256"] = definition
            fixture.rewrite_manifest()
            with self.assertRaisesRegex(ArchiveError, "axes differ"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_every_axis_must_bind_the_successor_claim(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.manifest["evidence_axes"][0]["claim_ids"] = [
                "bounded-joint-handoff-refinement-v1"
            ]
            fixture.rewrite_manifest()
            with self.assertRaisesRegex(ArchiveError, "every evidence axis"):
                validate_closure_record(
                    fixture.root, fixture.claim, fixture.acceptance
                )

    def test_predecessor_drift_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.receipt["predecessor_ids"] = []
            fixture.write_receipt()
            with self.assertRaisesRegex(ArchiveError, "predecessor binding"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_receipt_digest_drift_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.acceptance["receipt_sha256"] = "0" * 64
            with self.assertRaisesRegex(ArchiveError, "committed receipt digest"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_accepted_revision_must_be_a_strict_ancestor(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            run(
                [
                    "git",
                    "update-ref",
                    "HEAD",
                    fixture.accepted_source["revision"],
                ],
                fixture.root,
            )
            with self.assertRaisesRegex(ArchiveError, "HEAD blob|strict ancestor"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_receipt_extra_key_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.receipt["unexpected"] = True
            fixture.write_receipt()
            with self.assertRaisesRegex(ArchiveError, "keys drifted"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_valid_but_uncommitted_receipt_bytes_are_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            data = fixture.receipt_path.read_bytes() + b"\n"
            fixture.receipt_path.write_bytes(data)
            fixture.acceptance["receipt_sha256"] = digest(data)
            with self.assertRaisesRegex(ArchiveError, "byte-identical to committed HEAD"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_second_copy_uri_is_not_part_of_the_provider_contract(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.receipt["second_copy"]["record_uri"] = (
                "https://169.254.169.254/latest/meta-data"
            )
            fixture.write_receipt()
            with self.assertRaisesRegex(ArchiveError, "keys drifted"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_zenodo_version_doi_is_bound_to_record_id(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.receipt["second_copy"]["doi"] = "10.5281/zenodo.999999"
            fixture.write_receipt()
            with self.assertRaisesRegex(ArchiveError, "Zenodo-minted version DOI"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_zenodo_provider_checksum_is_strict(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.receipt["second_copy"]["provider_checksum"] = "sha256:" + "0" * 64
            fixture.write_receipt()
            with self.assertRaisesRegex(ArchiveError, "provider checksum is invalid"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_attempt_two_is_rejected_offline(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.receipt["qualification"]["run_attempt"] = 2
            fixture.write_receipt()
            with self.assertRaisesRegex(ArchiveError, "run_attempt must be 1"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_duplicate_receipt_key_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            raw = fixture.receipt_path.read_text(encoding="utf-8")
            raw = raw.replace('"schema":', '"schema": "duplicate",\n  "schema":', 1)
            fixture.receipt_path.write_text(raw, encoding="utf-8")
            fixture.acceptance["receipt_sha256"] = digest(raw.encode())
            with self.assertRaisesRegex(ArchiveError, "duplicate JSON key"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)

    def test_tar_extra_member_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            payloads = dict(fixture.payloads)
            payloads["extra.txt"] = b"extra\n"
            target = fixture.root / "extra.tar"
            fixture.write_tar(target, fixture.manifest, payloads)
            with self.assertRaisesRegex(ArchiveError, "inventory differs"):
                validate_archive_tar(target, fixture.manifest_path)

    def test_tar_nonzero_trailing_data_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            target = fixture.root / "trailing.tar"
            target.write_bytes(fixture.archive_path.read_bytes() + b"trailing-junk")
            with self.assertRaisesRegex(ArchiveError, "trailing tar blocks"):
                validate_archive_tar(target, fixture.manifest_path)

    def test_tar_symlink_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            target = fixture.root / "symlink.tar"
            with tarfile.open(target, "w", format=tarfile.USTAR_FORMAT) as archive:
                entries = {"ARCHIVE-MANIFEST.json": json_bytes(fixture.manifest), **fixture.payloads}
                for name in sorted(entries):
                    info = tarfile.TarInfo(name)
                    if name == "REVERIFY.md":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "SHA256SUMS"
                        archive.addfile(info)
                    else:
                        data = entries[name]
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
            with self.assertRaisesRegex(ArchiveError, "link, directory, or special"):
                validate_archive_tar(target, fixture.manifest_path)

    def test_sha256sums_semantic_drift_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            lines = fixture.payloads["SHA256SUMS"].decode().splitlines()
            lines[0] = "0" * 64 + lines[0][64:]
            fixture.payloads["SHA256SUMS"] = ("\n".join(lines) + "\n").encode()
            member = next(item for item in fixture.manifest["members"] if item["path"] == "SHA256SUMS")
            member["sha256"] = digest(fixture.payloads["SHA256SUMS"])
            member["size_bytes"] = len(fixture.payloads["SHA256SUMS"])
            fixture.manifest_path.write_bytes(json_bytes(fixture.manifest))
            target = fixture.root / "bad-checksum.tar"
            fixture.write_tar(target, fixture.manifest, fixture.payloads)
            with self.assertRaisesRegex(ArchiveError, "SHA256SUMS digest failed"):
                validate_archive_tar(target, fixture.manifest_path)

    def test_actions_zip_traversal_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            path = fixture.actions[0]["path"]
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr("../escape.txt", "escape\n")
            fixture.payloads[path] = output.getvalue()
            fixture.actions[0]["api_digest"] = f"sha256:{digest(fixture.payloads[path])}"
            fixture.actions[0]["size_bytes"] = len(fixture.payloads[path])
            member = next(item for item in fixture.manifest["members"] if item["path"] == path)
            member["sha256"] = digest(fixture.payloads[path])
            member["size_bytes"] = len(fixture.payloads[path])
            fixture.manifest_path.write_bytes(json_bytes(fixture.manifest))
            target = fixture.root / "zip-traversal.tar"
            fixture.write_tar(target, fixture.manifest, fixture.payloads)
            with self.assertRaisesRegex(ArchiveError, "unsafe .* member"):
                validate_archive_tar(target, fixture.manifest_path)

    def test_online_run_attempt_drift_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
                endpoint = command[-1]
                if endpoint.endswith("/actions/runs/9001"):
                    response = {
                        "id": 9001,
                        "run_attempt": 1,
                        "head_sha": fixture.accepted_source["revision"],
                        "event": "push",
                        "head_repository": {"full_name": "chenty2333/vISA"},
                    }
                else:
                    self.assertIn("/attempts/1", endpoint)
                    response = {
                        "id": 9001,
                        "run_attempt": 2,
                        "workflow_id": 1234,
                        "path": ".github/workflows/ci.yml",
                        "head_sha": fixture.accepted_source["revision"],
                        "event": "push",
                        "head_repository": {"full_name": "chenty2333/vISA"},
                        "status": "completed",
                        "conclusion": "success",
                    }
                return subprocess.CompletedProcess(command, 0, json.dumps(response), "")

            with self.assertRaisesRegex(ArchiveError, "attempt differs"):
                verify_online(fixture.root, fixture.claim, fixture.acceptance, runner=runner)

    def test_online_pull_request_run_is_not_promotion_evidence(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            base_runner = fixture.online_runner(immutable=True)

            def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
                result = base_runner(command)
                if command[0] == "gh" and command[-1].endswith(
                    "/actions/runs/9001"
                ):
                    response = json.loads(result.stdout)
                    response["event"] = "pull_request"
                    return subprocess.CompletedProcess(
                        command, 0, json.dumps(response), ""
                    )
                return result

            with self.assertRaisesRegex(ArchiveError, "not an exact repository push"):
                verify_online(
                    fixture.root,
                    fixture.claim,
                    fixture.acceptance,
                    runner=runner,
                )

    def test_online_repository_override_must_match_receipt(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
                raise AssertionError(f"runner must not be called: {command}")

            with self.assertRaisesRegex(ArchiveError, "configured repository differs"):
                verify_online(
                    fixture.root,
                    fixture.claim,
                    fixture.acceptance,
                    repository="someone-else/vISA",
                    runner=runner,
                )

    def test_online_unsuccessful_job_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            calls = 0

            def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
                nonlocal calls
                calls += 1
                if calls == 1:
                    response = {
                        "id": 9001,
                        "run_attempt": 1,
                        "head_sha": fixture.accepted_source["revision"],
                        "event": "push",
                        "head_repository": {"full_name": "chenty2333/vISA"},
                    }
                elif calls == 2:
                    response = {
                        "id": 9001,
                        "run_attempt": 1,
                        "workflow_id": 1234,
                        "path": ".github/workflows/ci.yml",
                        "head_sha": fixture.accepted_source["revision"],
                        "event": "push",
                        "head_repository": {"full_name": "chenty2333/vISA"},
                        "status": "completed",
                        "conclusion": "success",
                    }
                else:
                    definitions = [
                        (7001, "gate one", "success"),
                        (7002, "gate two", "failure"),
                        (7003, "Exact-SHA qualification closure", "success"),
                        *[
                            (job_id, f"gate {job_id - 6999}", "success")
                            for job_id in range(7004, 7013)
                        ],
                    ]
                    jobs = []
                    for job_id, name, conclusion in definitions:
                        jobs.append(
                            {
                                "id": job_id,
                                "name": name,
                                "run_id": 9001,
                                "run_attempt": 1,
                                "head_sha": fixture.accepted_source["revision"],
                                "status": "completed",
                                "conclusion": conclusion,
                                "started_at": "2026-07-17T06:00:00Z",
                                "completed_at": "2026-07-17T06:20:00Z",
                            }
                        )
                    response = {"total_count": 12, "jobs": jobs}
                return subprocess.CompletedProcess(command, 0, json.dumps(response), "")

            with self.assertRaisesRegex(ArchiveError, "not all workflow jobs succeeded"):
                verify_online(fixture.root, fixture.claim, fixture.acceptance, runner=runner)

    def test_online_malformed_job_entry_is_an_archive_error(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            base_runner = fixture.online_runner(immutable=True)

            def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
                if command[0] == "gh" and command[-1].endswith(
                    "/attempts/1/jobs?per_page=100"
                ):
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        json.dumps({"total_count": 1, "jobs": [1]}),
                        "",
                    )
                return base_runner(command)

            with self.assertRaisesRegex(ArchiveError, "non-object entry"):
                verify_online(
                    fixture.root,
                    fixture.claim,
                    fixture.acceptance,
                    runner=runner,
                )

    def test_online_mutable_release_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            with self.assertRaisesRegex(ArchiveError, "release is not immutable"):
                verify_online(
                    fixture.root,
                    fixture.claim,
                    fixture.acceptance,
                    runner=fixture.online_runner(immutable=False),
                )

    def test_online_release_tag_target_drift_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            with self.assertRaisesRegex(ArchiveError, "tag does not resolve"):
                verify_online(
                    fixture.root,
                    fixture.claim,
                    fixture.acceptance,
                    runner=fixture.online_runner(tag_revision="0" * 40),
                )

    def test_durable_online_mode_skips_live_actions_and_checks_zenodo(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            seen: list[list[str]] = []
            base_runner = fixture.online_runner(immutable=True)

            def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
                seen.append(command)
                if command[0] == "gh" and len(command) > 2 and command[2] == "api":
                    self.assertNotIn("/actions/", command[-1])
                return base_runner(command)

            record_uri = "https://zenodo.org/api/records/424242"
            asset_uri = (
                "https://zenodo.org/api/records/424242/files/"
                f"{fixture.claim_id}-evidence.tar/content"
            )
            checksum = fixture.receipt["second_copy"]["provider_checksum"]

            def fetcher(uri: str, limit: int) -> bytes:
                if uri == record_uri:
                    return json_bytes(
                        {
                            "id": 424242,
                            "doi": "10.5281/zenodo.424242",
                            "status": "published",
                            "files": [
                                {
                                    "key": fixture.claim_id + "-evidence.tar",
                                    "size": fixture.receipt["archive"]["asset_size_bytes"],
                                    "checksum": checksum,
                                    "links": {"self": asset_uri},
                                }
                            ],
                        }
                    )
                if uri == asset_uri:
                    return fixture.archive_path.read_bytes()
                raise AssertionError(f"unexpected provider URI: {uri}")

            verify_online(
                fixture.root,
                fixture.claim,
                fixture.acceptance,
                require_live_actions=False,
                runner=runner,
                fetcher=fetcher,
            )
            self.assertTrue(seen)
            self.assertFalse(any("/actions/" in item[-1] for item in seen if item[-1]))

    def test_baseline_permanent_membership_is_commit_bound(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            self.assertEqual(
                permanent_claims_at_baseline(
                    fixture.root, fixture.accepted_source["revision"]
                ),
                {},
            )
            registry_path = fixture.root / "claims/registry.json"
            registry_path.parent.mkdir(exist_ok=True)
            candidate_revision = fixture.accepted_source["revision"]

            permanent_claim = copy.deepcopy(fixture.claim)
            permanent_claim["acceptance_ref"] = copy.deepcopy(fixture.acceptance)
            permanent_revision = run(["git", "rev-parse", "HEAD"], fixture.root)

            (fixture.root / "baseline-marker").write_text("head\n", encoding="utf-8")
            run(["git", "add", "baseline-marker"], fixture.root)
            run(["git", "commit", "--quiet", "-m", "post archive marker"], fixture.root)

            self.assertEqual(permanent_claims_at_baseline(fixture.root, candidate_revision), {})
            self.assertEqual(
                permanent_claims_at_baseline(fixture.root, permanent_revision),
                {fixture.claim_id: fixture.acceptance["receipt_sha256"]},
            )
            invalid_claim = copy.deepcopy(permanent_claim)
            invalid_claim["acceptance_ref"]["receipt_sha256"] = "0" * 64
            invalid_registry = {
                "schema": "visa.project-claim-registry.v1",
                "claims": [invalid_claim],
                "workflow_bindings": [],
            }
            registry_path.write_bytes(json_bytes(invalid_registry))
            run(["git", "add", "claims/registry.json"], fixture.root)
            run(["git", "commit", "--quiet", "-m", "invalid permanent registry"], fixture.root)
            invalid_revision = run(["git", "rev-parse", "HEAD"], fixture.root)
            (fixture.root / "invalid-baseline-marker").write_text("head\n", encoding="utf-8")
            run(["git", "add", "invalid-baseline-marker"], fixture.root)
            run(["git", "commit", "--quiet", "-m", "post invalid registry marker"], fixture.root)
            with self.assertRaisesRegex(ArchiveError, "does not match its committed blob"):
                permanent_claims_at_baseline(fixture.root, invalid_revision)
            with self.assertRaisesRegex(ArchiveError, "strict ancestor"):
                permanent_claims_at_baseline(
                    fixture.root, run(["git", "rev-parse", "HEAD"], fixture.root)
                )

    def test_permanent_claim_lifecycle_is_monotonic(self) -> None:
        claim_id = "bounded-joint-handoff-refinement-v2"
        receipt_digest = "a" * 64
        earned = {
            "status": "earned",
            "acceptance_ref": {
                "kind": "permanent-archive-receipt",
                "receipt_sha256": receipt_digest,
            },
        }
        require_permanent_claims_monotonic(
            {claim_id: receipt_digest}, {claim_id: copy.deepcopy(earned)}
        )

        candidate = copy.deepcopy(earned)
        candidate["status"] = "candidate"
        candidate["acceptance_ref"]["kind"] = (
            "pending-permanent-archive-receipt"
        )
        candidate["acceptance_ref"]["receipt_sha256"] = None
        with self.assertRaisesRegex(ArchiveError, "cannot return to candidate"):
            require_permanent_claims_monotonic(
                {claim_id: receipt_digest}, {claim_id: candidate}
            )
        with self.assertRaisesRegex(ArchiveError, "permanent claims were deleted"):
            require_permanent_claims_monotonic({claim_id: receipt_digest}, {})

        replaced = copy.deepcopy(earned)
        replaced["acceptance_ref"]["receipt_sha256"] = "b" * 64
        with self.assertRaisesRegex(ArchiveError, "digest cannot be replaced"):
            require_permanent_claims_monotonic(
                {claim_id: receipt_digest}, {claim_id: replaced}
            )

    def test_unsafe_release_tag_is_rejected(self) -> None:
        temporary, fixture = self.make_fixture()
        with temporary:
            fixture.receipt["archive"]["release_tag"] = "evidence..lock"
            fixture.write_receipt()
            with self.assertRaisesRegex(ArchiveError, "safe Git tag"):
                validate_closure_record(fixture.root, fixture.claim, fixture.acceptance)


if __name__ == "__main__":
    unittest.main()
