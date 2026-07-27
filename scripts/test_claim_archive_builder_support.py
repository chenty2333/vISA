"""Shared on-disk fixture for claim archive publisher tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from claim_archive import claim_definition_sha256
from claim_archive_builder import CLAIM_ID, json_bytes


class PublicationFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.claim = {
            "id": CLAIM_ID,
            "track": "roadmap",
            "status": "candidate",
            "scope_ref": {"path": "docs/ROADMAP.md", "heading": "scope"},
            "validation_ref": {"path": "docs/VALIDATION.md", "heading": "validation"},
            "implementation_refs": ["claims/evidence-matrix.json"],
            "predecessor_ids": [
                "bounded-regular-file-continuity",
                "strict-cross-runtime-continuity",
            ],
        }
        self.acceptance = {
            "kind": "pending-permanent-archive-receipt",
            "path": f"claims/receipts/{CLAIM_ID}.json",
            "heading": None,
            "receipt_sha256": None,
            "semantic_contracts": {"scope_sha256": "0" * 64, "validation_sha256": "1" * 64},
            "evidence_axes": [
                "exact-sha-closure",
                "four-direction-runtime-matrix",
                "regular-file-resource",
                "relocated-independent-verification",
                "source-locked-runtime-lineage",
                "typed-outer-normalization",
            ],
            "source_repositories": ["chenty2333/vISA"],
            "workflow_artifacts": [
                "stage3a-cross-runtime-regular-file-system-evidence",
                "stage3a-regular-file-system-evidence",
            ],
        }
        self.archive_path = root / f"{CLAIM_ID}-evidence.tar"
        self.archive_path.write_bytes(b"archive bytes\n")
        sums = hashlib.sha256(b"sums\n").hexdigest()
        reverify = hashlib.sha256(b"reverify\n").hexdigest()
        revision = "a" * 40
        tree = "b" * 40
        self.manifest = {
            "schema": "visa.project-claim-archive.v1",
            "claim_id": CLAIM_ID,
            "claim_definition_sha256": claim_definition_sha256(self.claim, self.acceptance),
            "predecessor_ids": self.claim["predecessor_ids"],
            "accepted_source": {
                "repository": "chenty2333/vISA",
                "revision": revision,
                "tree": tree,
            },
            "qualification": {
                "workflow_id": 1,
                "workflow_path": ".github/workflows/ci.yml",
                "run_id": 2,
                "run_attempt": 1,
                "head_sha": revision,
                "closure_job_id": 3,
                "closure_job_name": "Exact-SHA qualification closure",
                "job_count": 13,
            },
            "actions_artifacts": [],
            "source_bundles": [],
            "evidence_axes": [],
            "members": [
                {
                    "path": "REVERIFY.md",
                    "role": "offline-reverification",
                    "media_type": "text/markdown",
                    "size_bytes": 9,
                    "sha256": reverify,
                },
                {
                    "path": "SHA256SUMS",
                    "role": "checksum-inventory",
                    "media_type": "text/plain",
                    "size_bytes": 5,
                    "sha256": sums,
                },
            ],
        }
        self.manifest_path = root / f"{CLAIM_ID}.json"
        self.manifest_path.write_bytes(json_bytes(self.manifest))
        self.build_result = {
            "schema": "visa.project-claim-archive-build-result.v1",
            "claim_id": CLAIM_ID,
            "archive": {
                "path": self.archive_path.name,
                "size_bytes": self.archive_path.stat().st_size,
                "sha256": hashlib.sha256(self.archive_path.read_bytes()).hexdigest(),
            },
            "manifest": {
                "path": f"claims/archive-manifests/{CLAIM_ID}.json",
                "sha256": hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(),
            },
            "accepted_source": dict(self.manifest["accepted_source"]),
            "qualification": dict(self.manifest["qualification"]),
        }
        self.build_result_path = root / "BUILD-RESULT.json"
        self.build_result_path.write_bytes(json_bytes(self.build_result))
        self.release = {
            "tag_name": "cross-runtime-regular-file-continuity-v1-evidence",
            "html_url": (
                "https://github.com/chenty2333/vISA/releases/tag/"
                "cross-runtime-regular-file-continuity-v1-evidence"
            ),
        }
        self.record = {
            "id": 123456,
            "doi": "10.5281/zenodo.123456",
            "files": [
                {
                    "key": self.archive_path.name,
                    "size": self.archive_path.stat().st_size,
                    "checksum": "md5:"
                    + hashlib.md5(
                        self.archive_path.read_bytes(), usedforsecurity=False
                    ).hexdigest(),
                }
            ],
        }
