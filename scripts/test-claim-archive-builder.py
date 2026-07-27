#!/usr/bin/env python3
"""Regression tests for deterministic permanent-claim archive construction."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from claim_archive import ArchiveError, claim_definition_sha256, validate_archive_tar  # noqa: E402
from claim_archive_builder import (  # noqa: E402
    CLAIM_ID,
    EXPECTED_ARTIFACTS,
    SOURCE_BUNDLE_PATH,
    SOURCE_BUNDLE_REF,
    assemble_archive,
    create_source_bundle,
    prepare_output_root,
    require_clean_source_checkout,
    sha256_file,
)


def run(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout.strip()


def zip_bytes(name: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo(f"{name}/evidence.json")
        info.create_system = 3
        info.external_attr = 0o100644 << 16
        archive.writestr(info, b"{}\n")
    return output.getvalue()


class BuilderFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        run(["git", "init", "--quiet"], root)
        run(["git", "config", "user.email", "builder@example.invalid"], root)
        run(["git", "config", "user.name", "Archive Builder"], root)
        (root / "source.txt").write_text("accepted source\n", encoding="ascii")
        run(["git", "add", "source.txt"], root)
        run(["git", "commit", "--quiet", "-m", "accepted"], root)
        self.revision = run(["git", "rev-parse", "HEAD"], root)
        self.tree = run(["git", "rev-parse", "HEAD^{tree}"], root)
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
            "workflow_artifacts": list(EXPECTED_ARTIFACTS),
        }
        self.source = {
            "repository": "chenty2333/vISA",
            "revision": self.revision,
            "tree": self.tree,
        }
        self.qualification = {
            "workflow_id": 100,
            "workflow_path": ".github/workflows/ci.yml",
            "run_id": 200,
            "run_attempt": 1,
            "head_sha": self.revision,
            "closure_job_id": 300,
            "closure_job_name": "Exact-SHA qualification closure",
            "job_count": 13,
        }
        self.payload_root = root / "payload"
        self.payload_root.mkdir()
        bundle = self.payload_root / SOURCE_BUNDLE_PATH
        create_source_bundle(root, self.revision, self.tree, bundle)
        self.payloads = {SOURCE_BUNDLE_PATH: bundle}
        self.actions = []
        for index, name in enumerate(EXPECTED_ARTIFACTS, start=1):
            path = f"actions/{name}.zip"
            destination = self.payload_root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(zip_bytes(name))
            self.payloads[path] = destination
            self.actions.append(
                {
                    "role": f"workflow-artifact-{index:02d}",
                    "artifact_id": 400 + index,
                    "artifact_name": name,
                    "path": path,
                    "api_digest": f"sha256:{sha256_file(destination)}",
                    "run_id": 200,
                    "run_attempt": 1,
                    "head_sha": self.revision,
                    "size_bytes": destination.stat().st_size,
                    "expires_at": "2026-08-10T00:00:00Z",
                }
            )

    def build(self, output: Path) -> tuple[Path, Path]:
        return assemble_archive(
            self.claim,
            self.acceptance,
            self.source,
            self.qualification,
            self.actions,
            self.payloads,
            output,
        )


class ClaimArchiveBuilderTests(unittest.TestCase):
    def test_archive_source_checkout_must_be_clean(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-source-") as temporary:
            root = Path(temporary)
            run(["git", "init", "--quiet"], root)
            run(["git", "config", "user.email", "builder@example.invalid"], root)
            run(["git", "config", "user.name", "Archive Builder"], root)
            (root / "source.txt").write_text("accepted source\n", encoding="ascii")
            run(["git", "add", "source.txt"], root)
            run(["git", "commit", "--quiet", "-m", "accepted"], root)
            require_clean_source_checkout(root)
            (root / "untracked.txt").write_text("not accepted\n", encoding="ascii")
            with self.assertRaisesRegex(ArchiveError, "source checkout is dirty"):
                require_clean_source_checkout(root)

    def test_documented_nested_output_parent_is_created(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-output-") as temporary:
            requested = Path(temporary) / "target/claim-archives" / CLAIM_ID
            output, parent = prepare_output_root(requested)
            self.assertEqual(output, requested.resolve())
            self.assertEqual(parent, requested.parent.resolve())
            self.assertTrue(parent.is_dir())

    def test_two_builds_are_byte_identical_and_validate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-builder-") as temporary:
            fixture = BuilderFixture(Path(temporary))
            first, first_manifest = fixture.build(fixture.root / "first")
            second, second_manifest = fixture.build(fixture.root / "second")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_manifest.read_bytes(), second_manifest.read_bytes())
            validate_archive_tar(first, first_manifest)
            manifest = json.loads(first_manifest.read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["claim_definition_sha256"],
                claim_definition_sha256(fixture.claim, fixture.acceptance),
            )

    def test_ustar_headers_are_sorted_and_reproducible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-builder-") as temporary:
            fixture = BuilderFixture(Path(temporary))
            archive_path, _ = fixture.build(fixture.root / "result")
            with tarfile.open(archive_path, mode="r:") as archive:
                members = archive.getmembers()
            self.assertEqual([item.name for item in members], sorted(item.name for item in members))
            self.assertTrue(all(item.isfile() for item in members))
            self.assertTrue(all(item.mode == 0o644 for item in members))
            self.assertTrue(all(item.uid == item.gid == item.mtime == 0 for item in members))
            self.assertTrue(all(not item.pax_headers for item in members))

    def test_actions_api_digest_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-builder-") as temporary:
            fixture = BuilderFixture(Path(temporary))
            fixture.actions[0]["api_digest"] = "sha256:" + "f" * 64
            with self.assertRaisesRegex(ArchiveError, "Actions ZIP digest"):
                fixture.build(fixture.root / "invalid")


if __name__ == "__main__":
    unittest.main(verbosity=2)
