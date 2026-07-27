#!/usr/bin/env python3
"""Pure receipt and metadata tests for claim archive publication."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from claim_archive import ArchiveError, validate_receipt  # noqa: E402
from claim_archive_builder import CLAIM_ID, sha256_file  # noqa: E402
from claim_archive_publish import (  # noqa: E402
    PUBLICATION_STATE_NAME,
    RELEASE_TAG,
    closure_receipt,
    gh_json,
    prepare_zenodo_deposition,
    preflight_publication,
    resolve_zenodo_deposition,
    upload_zenodo_bucket_file,
    validate_build_result,
    zenodo_file_identity,
    zenodo_metadata,
)
from test_claim_archive_builder_support import PublicationFixture  # noqa: E402


class ClaimArchivePublishTests(unittest.TestCase):
    def test_missing_github_tag_allows_only_the_explicit_422(self) -> None:
        missing = subprocess.CompletedProcess(
            ["gh", "api"],
            1,
            "",
            "gh: No commit found for SHA: evidence-tag (HTTP 422)",
        )
        with mock.patch("claim_archive_publish.subprocess.run", return_value=missing):
            self.assertIsNone(
                gh_json("repos/example/project/commits/evidence-tag", "tag", allow_statuses=(422,))
            )
            with self.assertRaisesRegex(ArchiveError, "tag failed"):
                gh_json("repos/example/project/commits/evidence-tag", "tag")

    def test_build_result_binds_archive_manifest_and_qualification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-build-result-") as temporary:
            fixture = PublicationFixture(Path(temporary))
            validate_build_result(
                fixture.root,
                fixture.archive_path,
                fixture.manifest_path,
                fixture.manifest,
            )
            fixture.build_result["qualification"]["run_id"] += 1
            fixture.build_result_path.write_bytes(
                json.dumps(fixture.build_result, indent=2, sort_keys=True).encode() + b"\n"
            )
            with self.assertRaisesRegex(ArchiveError, "qualification differs"):
                validate_build_result(
                    fixture.root,
                    fixture.archive_path,
                    fixture.manifest_path,
                    fixture.manifest,
                )

    def test_receipt_binds_release_and_version_record(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-publish-") as temporary:
            fixture = PublicationFixture(Path(temporary))
            receipt = closure_receipt(
                fixture.claim,
                fixture.acceptance,
                fixture.manifest,
                fixture.manifest_path,
                fixture.archive_path,
                fixture.release,
                fixture.record,
            )
            validate_receipt(receipt, fixture.claim, fixture.acceptance)
            self.assertEqual(receipt["archive"]["asset_sha256"], sha256_file(fixture.archive_path))
            self.assertEqual(receipt["second_copy"]["doi"], "10.5281/zenodo.123456")

    def test_file_identity_normalizes_current_and_legacy_zenodo_shapes(self) -> None:
        current = {
            "key": "evidence.tar",
            "size": 42,
            "checksum": "md5:" + "a" * 32,
        }
        legacy = {
            "filename": "evidence.tar",
            "filesize": "42",
            "checksum": "a" * 32,
        }
        expected = ("evidence.tar", 42, "md5:" + "a" * 32)
        self.assertEqual(zenodo_file_identity(current, "current"), expected)
        self.assertEqual(zenodo_file_identity(legacy, "legacy"), expected)

    def test_bucket_upload_uses_documented_streaming_path_without_token_in_argv(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-curl-upload-") as temporary:
            archive = Path(temporary) / "evidence.tar"
            archive.write_bytes(b"archive bytes\n")
            response = {
                "key": archive.name,
                "size": archive.stat().st_size,
                "checksum": "md5:" + "a" * 32,
            }
            completed = subprocess.CompletedProcess(
                ["curl"], 0, json.dumps(response), ""
            )
            with mock.patch(
                "claim_archive_publish.subprocess.run", return_value=completed
            ) as execute:
                self.assertEqual(
                    upload_zenodo_bucket_file(
                        "https://zenodo.org/api/files/test-bucket",
                        "secret-token",
                        archive,
                    ),
                    response,
                )
            command = execute.call_args.args[0]
            self.assertNotIn("secret-token", command)
            self.assertIn("--upload-file", command)
            config = execute.call_args.kwargs["input"]
            self.assertIn("Authorization: Bearer secret-token", config)
            self.assertIn("Expect: 100-continue", config)

    def test_partial_same_name_zenodo_upload_is_replaced_on_resume(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-zenodo-resume-") as temporary:
            fixture = PublicationFixture(Path(temporary))
            correct_file = fixture.record["files"][0]
            draft = {
                "id": 123456,
                "metadata": {
                    "version": "a" * 40,
                    "creators": [{"name": "Chen, Tianyi", "affiliation": None}],
                },
                "submitted": False,
                "files": [
                    {
                        "key": fixture.archive_path.name,
                        "size": fixture.archive_path.stat().st_size,
                        "checksum": "md5:" + "0" * 32,
                    }
                ],
                "links": {"bucket": "https://zenodo.org/api/files/test-bucket"},
            }
            refreshed = {**draft, "files": [correct_file]}
            with mock.patch(
                "claim_archive_publish.request_json",
                side_effect=[draft, refreshed],
            ), mock.patch(
                "claim_archive_publish.upload_zenodo_bucket_file",
                return_value=correct_file,
            ) as upload:
                self.assertIsNone(
                    prepare_zenodo_deposition(
                        "test-token",
                        fixture.archive_path,
                        "Chen, Tianyi",
                        "a" * 40,
                        123456,
                    )
                )
            upload.assert_called_once()

    def test_zenodo_creator_normalization_does_not_hide_a_change(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-zenodo-creator-") as temporary:
            fixture = PublicationFixture(Path(temporary))
            draft = {
                "id": 123456,
                "metadata": {
                    "version": "a" * 40,
                    "creators": [{"name": "Another Author", "affiliation": None}],
                },
                "submitted": False,
                "files": [],
            }
            with mock.patch("claim_archive_publish.request_json", return_value=draft):
                with self.assertRaisesRegex(ArchiveError, "creator differs"):
                    prepare_zenodo_deposition(
                        "test-token",
                        fixture.archive_path,
                        "Chen, Tianyi",
                        "a" * 40,
                        123456,
                    )

    def test_publication_state_is_idempotent_and_binds_archive_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-state-") as temporary:
            fixture = PublicationFixture(Path(temporary))
            revision = "a" * 40
            arguments = (
                fixture.root,
                fixture.archive_path,
                revision,
                RELEASE_TAG,
                "Chen, Tianyi",
                "test-token",
                123456,
            )
            self.assertEqual(resolve_zenodo_deposition(*arguments), 123456)
            self.assertEqual(resolve_zenodo_deposition(*arguments), 123456)
            state = json.loads((fixture.root / PUBLICATION_STATE_NAME).read_text())
            self.assertEqual(state["zenodo_deposition_id"], 123456)
            fixture.archive_path.write_bytes(b"different archive bytes\n")
            with self.assertRaisesRegex(ArchiveError, "publication state differs"):
                resolve_zenodo_deposition(*arguments)

    def test_noncanonical_release_tag_fails_before_remote_preflight(self) -> None:
        with tempfile.TemporaryDirectory(prefix="visa-archive-tag-") as temporary:
            with self.assertRaisesRegex(ArchiveError, "release tag is not canonical"):
                preflight_publication(
                    Path(temporary),
                    Path("claims/registry.json"),
                    "temporary-test-release",
                    "Chen, Tianyi",
                    "test-token",
                )

    def test_zenodo_metadata_names_exact_revision_and_release(self) -> None:
        metadata = zenodo_metadata("Archive Author", "a" * 40, "https://example.invalid/release")
        self.assertEqual(metadata["version"], "a" * 40)
        self.assertEqual(metadata["creators"], [{"name": "Archive Author"}])
        self.assertEqual(metadata["license"], "apache-2.0")
        self.assertEqual(
            metadata["related_identifiers"][0]["identifier"],
            "https://example.invalid/release",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
