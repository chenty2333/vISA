#!/usr/bin/env python3
"""Self-tests for the frozen vISA 0.1 release-contract checker."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


CHECKER_PATH = Path(__file__).with_name("check-release-contract.py")
SPEC = importlib.util.spec_from_file_location("visa_release_contract_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release-contract checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

DISPATCHER_PATH = Path(__file__).with_name("verify-release-readiness.py")
DISPATCHER_SPEC = importlib.util.spec_from_file_location(
    "visa_release_readiness_dispatcher",
    DISPATCHER_PATH,
)
if DISPATCHER_SPEC is None or DISPATCHER_SPEC.loader is None:
    raise RuntimeError("cannot load release-readiness dispatcher")
DISPATCHER = importlib.util.module_from_spec(DISPATCHER_SPEC)
DISPATCHER_SPEC.loader.exec_module(DISPATCHER)


class ReleaseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        (CHECKER.ROOT / "target").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="release-contract-test-",
            dir=CHECKER.ROOT / "target",
        )
        self.root = Path(self.temporary.name)
        self.raw = CHECKER.DEFAULT_CONTRACT.read_text(encoding="utf-8")
        self.ledger_raw = CHECKER.DEFAULT_READINESS_LEDGER.read_text(encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mutated_contract(self, old: str, new: str) -> Path:
        self.assertEqual(self.raw.count(old), 1, f"mutation source must be unique: {old!r}")
        path = self.root / "visa-0.1.toml"
        path.write_text(self.raw.replace(old, new, 1), encoding="utf-8")
        return path

    @staticmethod
    def copy(relative: str, destination_root: Path) -> Path:
        source = CHECKER.ROOT / relative
        destination = destination_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        return destination

    @staticmethod
    def write_json(path: Path, value: object) -> bytes:
        raw = (CHECKER.json.dumps(value, sort_keys=True) + "\n").encode()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return raw

    @staticmethod
    def sha256(path: Path) -> str:
        return CHECKER.hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def trusted_attestation(arguments: list[str]) -> bytes:
        if len(arguments) == 2 and arguments[1] == "version":
            return (
                b"gh version 2.96.0 (2026-07-02)\n"
                b"https://github.com/cli/cli/releases/tag/v2.96.0\n"
            )
        required_flags = {
            "--repo",
            "--signer-workflow",
            "--signer-digest",
            "--source-digest",
            "--source-ref",
            "--bundle",
            "--custom-trusted-root",
            "--deny-self-hosted-runners",
            "--predicate-type",
            "--format",
        }
        if not Path(arguments[0]).is_absolute():
            raise AssertionError("attestation verifier must use the private absolute path")
        if not required_flags <= set(arguments):
            raise AssertionError(f"attestation policy flags missing: {required_flags - set(arguments)}")
        subject_sha256 = CHECKER.hashlib.sha256(Path(arguments[3]).read_bytes()).hexdigest()
        bundle_path = Path(arguments[arguments.index("--bundle") + 1])
        bundle_document = CHECKER.json.loads(bundle_path.read_text(encoding="utf-8"))
        repository = arguments[arguments.index("--repo") + 1]
        signer_workflow = arguments[arguments.index("--signer-workflow") + 1]
        source_revision = arguments[arguments.index("--source-digest") + 1]
        source_ref = arguments[arguments.index("--source-ref") + 1]
        predicate_type = arguments[arguments.index("--predicate-type") + 1]
        repository_url = f"https://github.com/{repository}"
        workflow_uri = f"https://github.com/{signer_workflow}@{source_ref}"
        embedded_statement = (
            bundle_document.get("statement")
            if isinstance(bundle_document, dict)
            else None
        )
        statement = (
            embedded_statement
            if isinstance(embedded_statement, dict)
            else {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": "subject",
                        "digest": {"sha256": subject_sha256},
                    }
                ],
                "predicateType": predicate_type,
                "predicate": {},
            }
        )
        certificate = {
            "certificateIssuer": "CN=test",
            "subjectAlternativeName": workflow_uri,
            "issuer": "https://token.actions.githubusercontent.com",
            "githubWorkflowTrigger": "push",
            "buildSignerURI": workflow_uri,
            "buildSignerDigest": source_revision,
            "runnerEnvironment": "github-hosted",
            "sourceRepositoryURI": repository_url,
            "sourceRepositoryDigest": source_revision,
            "sourceRepositoryRef": source_ref,
            "sourceRepositoryIdentifier": "1001",
            "sourceRepositoryOwnerURI": (
                f"https://github.com/{repository.split('/', 1)[0]}"
            ),
            "sourceRepositoryOwnerIdentifier": "2001",
            "buildConfigURI": workflow_uri,
            "buildConfigDigest": source_revision,
            "buildTrigger": "push",
            "runInvocationURI": (
                f"{repository_url}/actions/runs/3001/attempts/1"
            ),
            "sourceRepositoryVisibilityAtSigning": "public",
        }
        embedded_certificate = (
            bundle_document.get("certificate")
            if isinstance(bundle_document, dict)
            else None
        )
        if isinstance(embedded_certificate, dict):
            certificate.update(embedded_certificate)
        return (
            CHECKER.json.dumps(
                [
                    {
                        "attestation": {},
                        "verificationResult": {
                            "statement": statement,
                            "signature": {"certificate": certificate},
                        },
                    }
                ],
                sort_keys=True,
            )
            + "\n"
        ).encode()

    @staticmethod
    def typed_verifier_result(readiness_id: str, evidence_sha256: str) -> bytes:
        return (
            CHECKER.json.dumps(
                {
                    "schema": "visa.release-verifier-result.v1",
                    "readiness_id": readiness_id,
                    "verifier_id": f"visa.release.verify.{readiness_id}.v1",
                    "status": "verified",
                    "evidence_sha256": evidence_sha256,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode()

    @classmethod
    def trusted_release_verifier(
        cls,
        dispatcher_path: Path,
        readiness_id: str,
        input_snapshot: Path,
    ) -> tuple[int, bytes, bytes]:
        del dispatcher_path
        manifest = CHECKER.load_json_bytes(
            (input_snapshot / "input-manifest.json").read_bytes(),
            "test input snapshot",
        )
        if manifest["readiness_id"] != readiness_id:
            raise AssertionError("snapshot readiness ID drifted")
        evidence_binding = manifest["evidence"]
        evidence = CHECKER.read_regular_file(
            input_snapshot,
            f"archive/{evidence_binding['path']}",
            "test snapshot evidence",
        )
        return (
            0,
            cls.typed_verifier_result(readiness_id, evidence_binding["sha256"]),
            evidence,
        )

    def check_external_bundle(
        self,
        bundle: Path,
        index: dict,
        *,
        document: dict | None = None,
        attestation_runner=None,
        release_verifier_runner=None,
        release_stage: str = "final-release-verified",
        expected_source_revision: str | None = None,
        expected_source_tag: str | None = None,
        expected_source_tag_object: str | None = None,
        expected_final_tag_object: str | None = None,
    ) -> str:
        return CHECKER.check_external_release_index(
            document or CHECKER.load_contract(),
            CHECKER.DEFAULT_CONTRACT,
            bundle,
            index["archive"]["attestation_verifier_sha256"],
            index["archive"]["trusted_root_sha256"],
            expected_source_revision or self.expected_source_revision,
            expected_source_tag or self.expected_source_tag,
            expected_source_tag_object or self.expected_source_tag_object,
            (
                (
                    expected_final_tag_object
                    if expected_final_tag_object is not None
                    else self.expected_final_tag_object
                )
                if release_stage == "final-release-verified"
                else None
            ),
            attestation_runner or self.trusted_attestation,
            release_verifier_runner or self.trusted_release_verifier,
            release_stage,
        )

    def rewrite_index_binding(self, bundle: Path, index: dict) -> None:
        index_bytes = self.write_json(bundle / "index.json", index)
        finalization_path = bundle / "finalization.json"
        finalization = CHECKER.load_json_bytes(finalization_path.read_bytes(), "test finalization")
        finalization["index_sha256"] = CHECKER.hashlib.sha256(index_bytes).hexdigest()
        self.write_json(finalization_path, finalization)

    def refresh_payload_binding(self, bundle: Path, index: dict, relative: str) -> None:
        manifest_path = bundle / index["archive"]["manifest_path"]
        manifest = CHECKER.load_json_bytes(manifest_path.read_bytes(), "test archive manifest")
        matches = [entry for entry in manifest["files"] if entry["path"] == relative]
        self.assertEqual(len(matches), 1, relative)
        matches[0]["sha256"] = self.sha256(bundle / relative)
        matches[0]["size"] = (bundle / relative).stat().st_size
        manifest_bytes = self.write_json(manifest_path, manifest)
        sums_bytes = "".join(
            f"{entry['sha256']}  {entry['path']}\n" for entry in manifest["files"]
        ).encode()
        (bundle / index["archive"]["sha256sums_path"]).write_bytes(sums_bytes)
        index["archive"]["manifest_sha256"] = CHECKER.hashlib.sha256(manifest_bytes).hexdigest()
        index["archive"]["sha256sums_sha256"] = CHECKER.hashlib.sha256(sums_bytes).hexdigest()
        self.rewrite_index_binding(bundle, index)

    def external_bundle(self) -> tuple[Path, dict]:
        repository = self.root / "tagged-repository"
        contract_path = repository / "specs/release/visa-0.1.toml"
        contract_path.parent.mkdir(parents=True)
        contract_bytes = self.raw.encode()
        contract_path.write_bytes(contract_bytes)
        for relative in (
            "Cargo.lock",
            "rust-toolchain.toml",
            "scripts/verify-release-readiness.py",
        ):
            destination = repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((CHECKER.ROOT / relative).read_bytes())
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        subprocess.run(["git", "config", "user.name", "vISA test"], cwd=repository, check=True)
        subprocess.run(
            ["git", "config", "user.email", "visa-test@example.invalid"],
            cwd=repository,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "release candidate"], cwd=repository, check=True)
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        source_tag = "v0.1.0-rc.1"
        self.expected_source_revision = revision
        self.expected_source_tag = source_tag
        subprocess.run(["git", "tag", "-a", "-m", "RC admitted", source_tag], cwd=repository, check=True)

        target_sha = CHECKER.hashlib.sha256(contract_bytes).hexdigest()
        cargo_sha = CHECKER.hashlib.sha256((repository / "Cargo.lock").read_bytes()).hexdigest()
        toolchain_sha = CHECKER.hashlib.sha256(
            (repository / "rust-toolchain.toml").read_bytes()
        ).hexdigest()
        bundle = self.root / "external-bundle"
        bundle.mkdir()
        rc_bundle_path = bundle / "source/visa-v0.1.0-rc.bundle"
        rc_bundle_path.parent.mkdir(parents=True)
        subprocess.run(["git", "bundle", "create", str(rc_bundle_path), "--all"], cwd=repository, check=True)
        subprocess.run(["git", "tag", "-a", "-m", "final release", "v0.1.0"], cwd=repository, check=True)
        final_bundle_path = bundle / "source/visa-v0.1.0-final.bundle"
        subprocess.run(["git", "bundle", "create", str(final_bundle_path), "--all"], cwd=repository, check=True)
        source_tag_object = subprocess.run(
            ["git", "rev-parse", f"refs/tags/{source_tag}"],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        final_tag_object = subprocess.run(
            ["git", "rev-parse", "refs/tags/v0.1.0"],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        self.expected_source_tag_object = source_tag_object
        self.expected_final_tag_object = final_tag_object
        (bundle / "source/Cargo.lock").write_bytes((repository / "Cargo.lock").read_bytes())
        (bundle / "source/rust-toolchain.toml").write_bytes(
            (repository / "rust-toolchain.toml").read_bytes()
        )
        verifier_archive_path = bundle / "verifiers/verify-release-readiness.py"
        verifier_archive_path.parent.mkdir(parents=True)
        verifier_archive_path.write_bytes(
            (repository / "scripts/verify-release-readiness.py").read_bytes()
        )
        verifier_sha = self.sha256(verifier_archive_path)
        trusted_root_path = bundle / "attestations/trusted_root.jsonl"
        trusted_root_path.parent.mkdir(parents=True)
        trusted_root_path.write_bytes(b'{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}\n')
        attestation_verifier_path = bundle / "tools/gh"
        attestation_verifier_path.parent.mkdir(parents=True)
        attestation_verifier_path.write_bytes(
            b"#!/bin/sh\n"
            b"if [ \"$1\" = version ]; then\n"
            b"  printf '%s\\n' 'gh version 2.96.0 (2026-07-02)' "
            b"'https://github.com/cli/cli/releases/tag/v2.96.0'\n"
            b"  exit 0\n"
            b"fi\n"
            b"exit 1\n"
        )
        attestation_verifier_path.chmod(0o500)
        gh_sha256 = self.sha256(attestation_verifier_path)
        trusted_root_sha256 = self.sha256(trusted_root_path)
        (bundle / "REVERIFY.md").write_text(
            "RC_ARCHIVE_ROOT=/archive/visa-0.1.0-rc.1\n"
            "FINAL_ARCHIVE_ROOT=/archive/visa-0.1.0\n"
            "git clone source/visa-v0.1.0-rc.bundle visa-rc\n"
            "python3 scripts/check-release-contract.py --release-ready --release-stage rc-admitted --archive-root $RC_ARCHIVE_ROOT --attestation-verifier-sha256 $GH_SHA256 --trusted-root-sha256 $TRUSTED_ROOT_SHA256 --expected-source-tag v0.1.0-rc.1\n"
            "python3 scripts/check-release-contract.py --release-ready --release-stage final-release-verified --archive-root $FINAL_ARCHIVE_ROOT --attestation-verifier-sha256 $GH_SHA256 --trusted-root-sha256 $TRUSTED_ROOT_SHA256 --expected-source-tag v0.1.0-rc.1\n"
            "The checker invokes gh attestation verify with the archived bundle and custom trusted root.\n",
            encoding="utf-8",
        )

        supply_runtime_inputs = []
        for runtime_id, kind, relative, version in (
            (
                "rust-toolchain-archive",
                "data",
                "source/rust-toolchain.tar.zst",
                "rust-toolchain-archive-v1",
            ),
            (
                "rust-toolchain-inventory",
                "data",
                "source/rust-toolchain-inventory.json",
                "rust-toolchain-inventory-v1",
            ),
            (
                "cargo-vendor-config",
                "config",
                "source/cargo-vendor-config.toml",
                "cargo-vendor-config-v1",
            ),
            (
                "cargo-vendor-inventory",
                "data",
                "source/cargo-vendor-inventory.json",
                "cargo-vendor-inventory-v1",
            ),
            (
                "cargo-vendor-archive",
                "data",
                "source/cargo-vendor.tar.zst",
                "cargo-vendor-locked-versioned-dirs",
            ),
            (
                "verifier-host-runtime-inventory",
                "data",
                "build/verifier-host-runtime-inventory.json",
                "verifier-host-runtime-inventory-v1",
            ),
            (
                "build-producer-inventory",
                "data",
                "build/build-producer-inventory.json",
                "visa.release-build-producer-inventory.v1",
            ),
            (
                "buildx-metadata",
                "data",
                "build/buildx-metadata.json",
                "docker-buildx-metadata-json.v1",
            ),
            (
                "oci-layout-inventory",
                "data",
                "build/derived-image-oci-inventory.json",
                "visa.release-oci-layout-file-set.v1",
            ),
            (
                "supply-chain-tool-inventory",
                "data",
                "supply-chain/tool-inventory.json",
                "supply-chain-tool-inventory-v1",
            ),
            (
                "cargo-deny-config",
                "config",
                "supply-chain/deny.toml",
                "cargo-deny-config-v1",
            ),
            (
                "rustsec-advisory-db",
                "data",
                "supply-chain/rustsec-advisory-db.tar.zst",
                "rustsec-advisory-db-snapshot-v1",
            ),
            (
                "cargo-deny-report",
                "data",
                "supply-chain/cargo-deny-report.json",
                "cargo-deny-report-v1",
            ),
            (
                "cargo-auditable-inventory",
                "data",
                "supply-chain/cargo-auditable-inventory.json",
                "cargo-auditable-inventory-v1",
            ),
            (
                "cargo-about-config",
                "config",
                "supply-chain/about.toml",
                "cargo-about-config-v1",
            ),
            (
                "cargo-about-template",
                "config",
                "supply-chain/about.hbs",
                "cargo-about-template-v1",
            ),
            (
                "cargo-about-raw",
                "data",
                "supply-chain/cargo-about-raw.json",
                "cargo-about-raw-v1",
            ),
            (
                "third-party-notice",
                "data",
                "supply-chain/THIRD-PARTY-NOTICES.txt",
                "third-party-notice-v1",
            ),
            (
                "cargo-cyclonedx-sbom-set",
                "data",
                "supply-chain/cyclonedx-sbom-set.json",
                "cargo-cyclonedx-sbom-set-v1",
            ),
            (
                "syft-json-set",
                "data",
                "supply-chain/syft-json-set.json",
                "syft-json-set-v1",
            ),
            (
                "dependency-inventory-reconciliation",
                "data",
                "supply-chain/dependency-inventory-reconciliation.json",
                "dependency-inventory-reconciliation-v1",
            ),
        ):
            runtime_path = bundle / relative
            runtime_path.parent.mkdir(parents=True, exist_ok=True)
            runtime_path.write_bytes(f"test {runtime_id} {version}\n".encode())
            if kind == "executable":
                runtime_path.chmod(0o500)
            supply_runtime_inputs.append(
                {
                    "id": runtime_id,
                    "kind": kind,
                    "path": relative,
                    "sha256": self.sha256(runtime_path),
                    "version": version,
                }
            )

        builder_image_record_id = (
            f"visa.buildx.derived-image.v1:{revision}:linux-amd64"
        )
        layout_root = "build/derived-image.oci"
        config_bytes = self.write_json(
            bundle / f"{layout_root}/blobs/sha256/config-placeholder",
            {
                "architecture": "amd64",
                "config": {},
                "os": "linux",
                "rootfs": {"diff_ids": [], "type": "layers"},
            },
        )
        config_digest = CHECKER.hashlib.sha256(config_bytes).hexdigest()
        config_path = bundle / f"{layout_root}/blobs/sha256/{config_digest}"
        (bundle / f"{layout_root}/blobs/sha256/config-placeholder").replace(config_path)
        config_descriptor = {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": f"sha256:{config_digest}",
            "size": len(config_bytes),
        }
        manifest_bytes = self.write_json(
            bundle / f"{layout_root}/blobs/sha256/manifest-placeholder",
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": config_descriptor,
                "layers": [],
            },
        )
        manifest_digest = CHECKER.hashlib.sha256(manifest_bytes).hexdigest()
        manifest_path = bundle / f"{layout_root}/blobs/sha256/{manifest_digest}"
        (bundle / f"{layout_root}/blobs/sha256/manifest-placeholder").replace(manifest_path)
        image_descriptor = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": f"sha256:{manifest_digest}",
            "size": len(manifest_bytes),
        }
        self.write_json(
            bundle / f"{layout_root}/index.json",
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        **image_descriptor,
                        "platform": {"architecture": "amd64", "os": "linux"},
                    }
                ],
            },
        )
        self.write_json(
            bundle / f"{layout_root}/oci-layout",
            {"imageLayoutVersion": "1.0.0"},
        )
        layout_file_paths = sorted(
            path.relative_to(bundle).as_posix()
            for path in (bundle / layout_root).rglob("*")
            if path.is_file()
        )
        layout_file_entries = [
            {
                "path": relative,
                "size": (bundle / relative).stat().st_size,
                "sha256": self.sha256(bundle / relative),
            }
            for relative in layout_file_paths
        ]
        self.write_json(
            bundle / "build/buildx-metadata.json",
            {
                "containerimage.config.digest": config_descriptor["digest"],
                "containerimage.descriptor": image_descriptor,
                "containerimage.digest": image_descriptor["digest"],
            },
        )
        self.write_json(
            bundle / "build/derived-image-oci-inventory.json",
            {
                "schema": "visa.release-oci-layout-file-set.v1",
                "target_sha256": target_sha,
                "source_revision": revision,
                "source_tag": source_tag,
                "build_record_id": builder_image_record_id,
                "root": layout_root,
                "platform": "linux/amd64",
                "metadata_input_id": "buildx-metadata",
                "files": layout_file_entries,
            },
        )
        for runtime_input in supply_runtime_inputs:
            if runtime_input["id"] in {
                "buildx-metadata",
                "oci-layout-inventory",
            }:
                runtime_input["sha256"] = self.sha256(
                    bundle / runtime_input["path"]
                )

        inventory_path = "build/workspace-package-inventory.json"
        document = CHECKER.load_contract()
        root_artifacts = [
            "visa-cli-binary",
            "visa-agent-binary",
            "visa-ownershipd-binary",
            "visa-nexusd-binary",
        ]
        packages = []
        product_roots = []
        product_builds = {}
        for artifact_id in root_artifacts:
            package_id = f"{artifact_id} 0.1.0 (workspace)"
            build_record_id = (
                f"visa.cargo.product.v1:{artifact_id}:{revision}"
            )
            build_argv = [
                "cargo",
                "build",
                "--release",
                "--locked",
                "--package",
                artifact_id,
            ]
            packages.append(
                {
                    "package_id": package_id,
                    "name": artifact_id.removesuffix("-binary"),
                    "version": "0.1.0",
                    "source": f"workspace:crates/product/{artifact_id}/Cargo.toml",
                    "license": "Apache-2.0",
                    "features": [],
                }
            )
            product_build = {
                "artifact_id": artifact_id,
                "package_id": package_id,
                "build_record_id": build_record_id,
                "builder_image_record_id": builder_image_record_id,
                "target": "x86_64-unknown-linux-gnu",
                "profile": "release",
                "features": [],
                "metadata_argv": [
                    "cargo",
                    "metadata",
                    "--frozen",
                    "--format-version",
                    "1",
                    "--filter-platform",
                    "x86_64-unknown-linux-gnu",
                    "--manifest-path",
                    f"crates/product/{artifact_id}/Cargo.toml",
                ],
                "build_argv": build_argv,
            }
            product_roots.append(product_build)
            product_builds[artifact_id] = product_build
        inventory = {
            "schema": "visa.release-build-inventory.v4",
            "target_sha256": target_sha,
            "source_revision": revision,
            "source_tag": source_tag,
            "cargo_lock_sha256": cargo_sha,
            "rust_toolchain_sha256": toolchain_sha,
            "build_environment": {
                "base_image": document["host_compatibility"]["release_build_base_image"],
                "base_manifest_sha256": document["host_compatibility"]
                ["release_build_base_image"].rsplit("@sha256:", 1)[1],
                "runtime_inputs": supply_runtime_inputs,
                "cargo_vendor_argv": [
                    "cargo",
                    "vendor",
                    "--locked",
                    "--versioned-dirs",
                ],
                "cargo_metadata_argv_prefix": [
                    "cargo",
                    "metadata",
                    "--frozen",
                    "--format-version",
                    "1",
                ],
                "buildkit_oci_output_argv": [
                    "docker",
                    "buildx",
                    "build",
                    "--builder",
                    "visa-v01",
                    "--file",
                    "packaging/release/Containerfile",
                    "--platform",
                    "linux/amd64",
                    "--provenance=false",
                    "--sbom=false",
                    "--output",
                    "type=oci,dest=build/derived-image.oci,tar=false,oci-mediatypes=true",
                    "--metadata-file",
                    "build/buildx-metadata.json",
                    ".",
                ],
                "frozen_environment": [
                    "BUILDX_METADATA_PROVENANCE=disabled",
                    "BUILDX_METADATA_WARNINGS=0",
                    "CARGO_HOME=<private>",
                    "CARGO_NET_OFFLINE=true",
                    "GIT_CONFIG_NOSYSTEM=1",
                    "HOME=<private>",
                    "RUSTUP_HOME=<private>",
                ],
                "source_to_binary_reproducibility": False,
            },
            "derived_build_image": {
                "schema": "visa.release-derived-build-image-binding.v1",
                "build_record_id": builder_image_record_id,
                "builder_name": "visa-v01",
                "builder_driver": "docker-container",
                "buildx_version": "v0.35.0",
                "buildkit_version": "v0.31.2",
                "cwd": "source-root",
                "recipe_path": "packaging/release/Containerfile",
                "context_path": ".",
                "platform": "linux/amd64",
                "producer_input_id": "build-producer-inventory",
                "metadata_input_id": "buildx-metadata",
                "layout_inventory_input_id": "oci-layout-inventory",
                "output_root": "build/derived-image.oci",
                "destination_policy": "must-not-exist-before-build-no-update-or-reuse",
                "metadata_parent_policy": (
                    "build-directory-precreated-writable-and-outside-layout-root"
                ),
                "descriptor": {
                    **image_descriptor,
                },
            },
            "workspace_package_count": len(packages),
            "resolved_package_count": len(packages),
            "workspace_packages": packages,
            "resolved_packages": packages,
            "product_roots": product_roots,
            "dependency_edges": [],
            "direct_dependencies": [],
        }
        inventory_bytes = self.write_json(bundle / inventory_path, inventory)
        inventory_sha = CHECKER.hashlib.sha256(inventory_bytes).hexdigest()

        nexus_component_revision = document["nexus_wire_artifact"][
            "release_component_revision"
        ]
        nexus_source_bundle_path = "source/nexus-effect-peer-native-v1.bundle"
        nexus_source_bundle_file = bundle / nexus_source_bundle_path
        nexus_source_bundle_file.parent.mkdir(parents=True, exist_ok=True)
        nexus_source_bundle_file.write_bytes(
            f"test Nexus source bundle {nexus_component_revision}\n".encode()
        )
        nexus_source_graph_path = "build/nexus-component-source-graph.json"
        nexus_build_record_id = "external-build-record-nexus-effect-peer-binary-v1"
        nexus_source_graph_bytes = self.write_json(
            bundle / nexus_source_graph_path,
            {
                "schema": "visa.release-nexus-component-source-graph.v1",
                "component_source_revision": nexus_component_revision,
                "build_record_id": nexus_build_record_id,
                "root_package": "nexus-effect-peer",
                "target": "x86_64-unknown-linux-gnu",
                "profile": "release",
                "features": [],
                "build_argv": ["cargo", "build", "--release", "--locked"],
                "files": [],
            },
        )
        nexus_corpus_path = "evidence/nexus-native-v1-exported-corpus.json"
        nexus_corpus_bytes = self.write_json(
            bundle / nexus_corpus_path,
            {
                "schema": "nexus.effect-peer.native-v1-exported-corpus.v1",
                "component_source_revision": nexus_component_revision,
                "freeze_contract_id": "nexus-effect-peer-native-v1",
                "canonical_snapshot_sha256": document["nexus_native_v1"][
                    "canonical_snapshot_sha256"
                ],
            },
        )
        nexus_release_link_path = (
            "attestations/artifacts/"
            "nexus-effect-peer-binary.release-link.sigstore.jsonl"
        )

        artifact_entries = []
        for artifact_policy in document["release_artifact"]:
            artifact_id = artifact_policy["id"]
            artifact_path = artifact_policy["archive_path"]
            artifact_bytes = f"test artifact {artifact_id}\n".encode()
            artifact_file = bundle / artifact_path
            artifact_file.parent.mkdir(parents=True, exist_ok=True)
            artifact_file.write_bytes(artifact_bytes)
            attestation_path = f"attestations/artifacts/{artifact_id}.sigstore.jsonl"
            attestation_file = bundle / attestation_path
            attestation_file.parent.mkdir(parents=True, exist_ok=True)
            visa_owned = artifact_policy["source_repository"] == "chenty2333/vISA"
            product_build = product_builds.get(artifact_id)
            component_source_revision = artifact_policy.get(
                "component_source_revision",
                revision if visa_owned else "b" * 40,
            )
            attestation_source_revision = (
                revision if visa_owned else "c" * 40
            )
            build_record_id = (
                product_build["build_record_id"]
                if product_build is not None
                else f"external-build-record-{artifact_id}-v1"
            )
            if artifact_id == "nexus-effect-peer-binary":
                source_ref = "refs/tags/test-only-nexus-effect-peer-wire-v1"
                repository_url = "https://github.com/chenty2333/Nexus"
                workflow_path = document["nexus_wire_artifact"][
                    "build_provenance_workflow_path"
                ]
                workflow_uri = (
                    f"{repository_url}/{workflow_path}@{source_ref}"
                )
                artifact_sha256 = CHECKER.hashlib.sha256(
                    artifact_bytes
                ).hexdigest()
                self.write_json(
                    attestation_file,
                    {
                        "statement": {
                            "_type": "https://in-toto.io/Statement/v1",
                            "subject": [
                                {
                                    "name": document["nexus_wire_artifact"][
                                        "attested_subject_name"
                                    ],
                                    "digest": {"sha256": artifact_sha256},
                                }
                            ],
                            "predicateType": "https://slsa.dev/provenance/v1",
                            "predicate": {
                                "buildDefinition": {
                                    "buildType": document["nexus_wire_artifact"][
                                        "build_provenance_build_type"
                                    ],
                                    "externalParameters": {
                                        "workflow": {
                                            "ref": source_ref,
                                            "repository": repository_url,
                                            "path": workflow_path,
                                        }
                                    },
                                    "internalParameters": {
                                        "github": {
                                            "event_name": "push",
                                            "repository_id": "1001",
                                            "repository_owner_id": "2001",
                                            "runner_environment": "github-hosted",
                                        }
                                    },
                                    "resolvedDependencies": [
                                        {
                                            "uri": (
                                                f"git+{repository_url}@{source_ref}"
                                            ),
                                            "digest": {
                                                "gitCommit": attestation_source_revision
                                            },
                                        },
                                    ],
                                },
                                "runDetails": {
                                    "builder": {"id": workflow_uri},
                                    "metadata": {
                                        "invocationId": (
                                            f"{repository_url}/actions/runs/3001/"
                                            "attempts/1"
                                        )
                                    },
                                },
                            },
                        }
                    },
                )
                self.write_json(
                    bundle / nexus_release_link_path,
                    {
                        "statement": {
                            "_type": "https://in-toto.io/Statement/v1",
                            "subject": [
                                {
                                    "name": document["nexus_wire_artifact"][
                                        "attested_subject_name"
                                    ],
                                    "digest": {"sha256": artifact_sha256},
                                }
                            ],
                            "predicateType": (
                                "https://in-toto.io/attestation/link/v0.3"
                            ),
                            "predicate": {
                                "name": document["nexus_wire_artifact"][
                                    "release_link_name"
                                ],
                                "command": [
                                    "cargo",
                                    "build",
                                    "--release",
                                    "--locked",
                                ],
                                "materials": [
                                    {
                                        "name": (
                                            "nexus-component-source-revision"
                                        ),
                                        "uri": (
                                            f"git+{repository_url}@"
                                            f"{nexus_component_revision}"
                                        ),
                                        "digest": {
                                            "gitCommit": nexus_component_revision
                                        },
                                    },
                                    {
                                        "name": "nexus-component-source-bundle",
                                        "digest": {
                                            "sha256": self.sha256(
                                                nexus_source_bundle_file
                                            )
                                        },
                                    },
                                    {
                                        "name": "nexus-component-source-graph",
                                        "digest": {
                                            "sha256": CHECKER.hashlib.sha256(
                                                nexus_source_graph_bytes
                                            ).hexdigest()
                                        },
                                    },
                                    {
                                        "name": (
                                            "nexus-native-v1-exported-corpus"
                                        ),
                                        "digest": {
                                            "sha256": CHECKER.hashlib.sha256(
                                                nexus_corpus_bytes
                                            ).hexdigest()
                                        },
                                    },
                                ],
                                "byproducts": {
                                    "buildRecordId": build_record_id
                                },
                                "environment": {},
                            },
                        }
                    },
                )
            else:
                attestation_file.write_bytes(
                    f'{{"subject":"{artifact_id}"}}\n'.encode()
                )
            artifact_entries.append(
                {
                    "id": artifact_id,
                    "kind": artifact_policy["kind"],
                    "path": artifact_path,
                    "sha256": CHECKER.hashlib.sha256(artifact_bytes).hexdigest(),
                    "size": len(artifact_bytes),
                    "source_repository": artifact_policy["source_repository"],
                    "component_source_revision": component_source_revision,
                    "attestation_source_revision": attestation_source_revision,
                    "attestation_source_ref": (
                        f"refs/tags/{source_tag}"
                        if visa_owned
                        else "refs/tags/test-only-nexus-effect-peer-wire-v1"
                    ),
                    "signer_workflow": artifact_policy["signer_workflow"],
                    "target": "x86_64-unknown-linux-gnu" if artifact_policy["kind"] == "executable" else "noarch",
                    "profile": "release" if artifact_policy["kind"] == "executable" else "source",
                    "features": [],
                    "build_argv": (
                        product_build["build_argv"]
                        if product_build is not None
                        else (
                            ["cargo", "build", "--release", "--locked"]
                            if artifact_policy["kind"] == "executable"
                            else ["install", artifact_path]
                        )
                    ),
                    "build_record_id": build_record_id,
                    "attestation_bundle_path": attestation_path,
                    "attestation_bundle_sha256": self.sha256(attestation_file),
                    "handshake_roles": artifact_policy["handshake_roles"],
                }
            )
        artifact_inventory_path = "build/release-artifact-inventory.json"
        artifact_inventory_bytes = self.write_json(
            bundle / artifact_inventory_path,
            {
                "schema": "visa.release-artifact-inventory.v3",
                "source_revision": revision,
                "source_tag": source_tag,
                "artifacts": artifact_entries,
            },
        )
        artifact_inventory_sha = CHECKER.hashlib.sha256(artifact_inventory_bytes).hexdigest()
        nexus_artifact_entry = next(
            entry
            for entry in artifact_entries
            if entry["id"] == "nexus-effect-peer-binary"
        )
        nexus_wire_runtime_inputs = [
            {
                "id": "nexus-component-source-bundle",
                "kind": "data",
                "path": nexus_source_bundle_path,
                "sha256": self.sha256(nexus_source_bundle_file),
                "version": f"nexus-source@{nexus_component_revision}",
            },
            {
                "id": "nexus-component-source-graph",
                "kind": "data",
                "path": nexus_source_graph_path,
                "sha256": CHECKER.hashlib.sha256(
                    nexus_source_graph_bytes
                ).hexdigest(),
                "version": "visa.release-nexus-component-source-graph.v1",
            },
            {
                "id": "nexus-native-v1-exported-corpus",
                "kind": "data",
                "path": nexus_corpus_path,
                "sha256": CHECKER.hashlib.sha256(nexus_corpus_bytes).hexdigest(),
                "version": "nexus.effect-peer.native-v1-exported-corpus.v1",
            },
            {
                "id": "release-artifact-inventory",
                "kind": "data",
                "path": artifact_inventory_path,
                "sha256": artifact_inventory_sha,
                "version": "visa.release-artifact-inventory.v3",
            },
            {
                "id": "nexus-effect-peer-binary",
                "kind": "executable",
                "path": nexus_artifact_entry["path"],
                "sha256": nexus_artifact_entry["sha256"],
                "version": f"nexus-effect-peer@{nexus_component_revision}",
            },
            {
                "id": "nexus-effect-peer-build-provenance-bundle",
                "kind": "data",
                "path": nexus_artifact_entry["attestation_bundle_path"],
                "sha256": nexus_artifact_entry["attestation_bundle_sha256"],
                "version": "slsa-v1-actions-workflow-v1-sigstore-bundle",
            },
            {
                "id": "nexus-effect-peer-release-link-bundle",
                "kind": "data",
                "path": nexus_release_link_path,
                "sha256": self.sha256(bundle / nexus_release_link_path),
                "version": "in-toto-link-v0.3-sigstore-bundle",
            },
        ]

        evidence_entries = []
        owned_schema_by_readiness = {
            entry["readiness_id"]: entry
            for entry in document["required_owned_schema_artifact"]
        }
        for readiness_id in CHECKER.EXPECTED_REQUIRED_IDS:
            if readiness_id == "supply-chain-license-and-artifact-locks":
                evidence_path = inventory_path
                evidence_sha = inventory_sha
            else:
                owned_schema = owned_schema_by_readiness.get(readiness_id)
                evidence_path = (
                    owned_schema["path"]
                    if owned_schema is not None
                    else f"evidence/{readiness_id}.json"
                )
                evidence_bytes = self.write_json(
                    bundle / evidence_path,
                    (
                        {
                            "schema": owned_schema["schema_format"],
                            "artifact_id": owned_schema["id"],
                            "corpus_id": owned_schema["corpus_id"],
                            "readiness_id": readiness_id,
                            "result": "passed",
                        }
                        if owned_schema is not None
                        else {"readiness_id": readiness_id, "result": "passed"}
                    ),
                )
                evidence_sha = CHECKER.hashlib.sha256(evidence_bytes).hexdigest()
            receipt_path = f"receipts/{readiness_id}.json"
            inputs = {
                "specs/release/visa-0.1.toml": target_sha,
                "scripts/verify-release-readiness.py": verifier_sha,
                evidence_path: evidence_sha,
            }
            readiness_runtime_inputs = (
                supply_runtime_inputs
                if readiness_id == "supply-chain-license-and-artifact-locks"
                else (
                    nexus_wire_runtime_inputs
                    if readiness_id == "nexus-native-v1-wire-artifact"
                    else []
                )
            )
            inputs.update(
                {
                    runtime_input["path"]: runtime_input["sha256"]
                    for runtime_input in readiness_runtime_inputs
                }
            )
            if readiness_id == "supply-chain-license-and-artifact-locks":
                inputs["source/visa-v0.1.0-rc.bundle"] = self.sha256(rc_bundle_path)
                inputs["source/Cargo.lock"] = cargo_sha
                inputs["source/rust-toolchain.toml"] = toolchain_sha
                inputs[inventory_path] = inventory_sha
                inputs[artifact_inventory_path] = artifact_inventory_sha
                inputs.update(
                    {
                        entry["path"]: entry["sha256"]
                        for entry in layout_file_entries
                    }
                )
            receipt = {
                "schema": "visa.release-readiness-verifier-receipt.v2",
                "readiness_id": readiness_id,
                "target_path": "specs/release/visa-0.1.toml",
                "target_sha256": target_sha,
                "source_revision": revision,
                "source_tag": source_tag,
                "verifier_id": f"visa.release.verify.{readiness_id}.v1",
                "verifier_source_path": "scripts/verify-release-readiness.py",
                "verifier_source_sha256": verifier_sha,
                "exit_code": 0,
                "output_sha256": evidence_sha,
                "verifier_result_sha256": CHECKER.hashlib.sha256(
                    self.typed_verifier_result(readiness_id, evidence_sha)
                ).hexdigest(),
                "input_sha256": inputs,
            }
            receipt_bytes = self.write_json(bundle / receipt_path, receipt)
            evidence_entries.append(
                {
                    "id": readiness_id,
                    "evidence_path": evidence_path,
                    "evidence_sha256": evidence_sha,
                    "verifier_receipt_path": receipt_path,
                    "verifier_receipt_sha256": CHECKER.hashlib.sha256(receipt_bytes).hexdigest(),
                }
            )

        payload_paths = {
            "source/visa-v0.1.0-rc.bundle",
            "source/Cargo.lock",
            "source/rust-toolchain.toml",
            "verifiers/verify-release-readiness.py",
            "tools/gh",
            "attestations/trusted_root.jsonl",
            "REVERIFY.md",
            inventory_path,
            artifact_inventory_path,
        }
        payload_paths.update(entry["path"] for entry in artifact_entries)
        payload_paths.update(entry["attestation_bundle_path"] for entry in artifact_entries)
        payload_paths.update(entry["evidence_path"] for entry in evidence_entries)
        payload_paths.update(entry["verifier_receipt_path"] for entry in evidence_entries)
        payload_paths.update(runtime_input["path"] for runtime_input in supply_runtime_inputs)
        payload_paths.update(
            runtime_input["path"] for runtime_input in nexus_wire_runtime_inputs
        )
        payload_paths.update(layout_file_paths)
        manifest_entries = []
        for relative in sorted(payload_paths):
            path = bundle / relative
            manifest_entries.append(
                {"path": relative, "sha256": self.sha256(path), "size": path.stat().st_size}
            )
        manifest_bytes = self.write_json(
            bundle / "archive/manifest.json",
            {"schema": "visa.release-archive-manifest.v1", "files": manifest_entries},
        )
        sums_bytes = "".join(
            f"{entry['sha256']}  {entry['path']}\n" for entry in manifest_entries
        ).encode()
        (bundle / "archive/SHA256SUMS").write_bytes(sums_bytes)

        index = {
            "schema": "visa.release-readiness-index.v2",
            "state": "rc-admitted",
            "contract": {
                "contract_id": "visa-product-0.1",
                "target_path": "specs/release/visa-0.1.toml",
                "target_sha256": target_sha,
                "source_revision": revision,
                "source_tag": source_tag,
                "final_tag": "v0.1.0",
            },
            "archive": {
                "manifest_path": "archive/manifest.json",
                "manifest_sha256": CHECKER.hashlib.sha256(manifest_bytes).hexdigest(),
                "sha256sums_path": "archive/SHA256SUMS",
                "sha256sums_sha256": CHECKER.hashlib.sha256(sums_bytes).hexdigest(),
                "source_bundle_path": "source/visa-v0.1.0-rc.bundle",
                "source_bundle_sha256": self.sha256(rc_bundle_path),
                "cargo_lock_path": "source/Cargo.lock",
                "cargo_lock_sha256": cargo_sha,
                "rust_toolchain_path": "source/rust-toolchain.toml",
                "rust_toolchain_sha256": toolchain_sha,
                "verifier_archive_path": "verifiers/verify-release-readiness.py",
                "verifier_source_path": "scripts/verify-release-readiness.py",
                "verifier_sha256": verifier_sha,
                "attestation_verifier_path": "tools/gh",
                "attestation_verifier_sha256": gh_sha256,
                "attestation_verifier_version": "2.96.0",
                "trusted_root_path": "attestations/trusted_root.jsonl",
                "trusted_root_sha256": trusted_root_sha256,
                "python_version": (
                    f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
                ),
                "git_version": CHECKER.trusted_git_version(CHECKER.ROOT),
            },
            "verifier_registry": {
                "schema": "visa.release-verifier-registry.v2",
                "dispatcher_source_path": "scripts/verify-release-readiness.py",
                "dispatcher_sha256": verifier_sha,
                "entries": [
                    {
                        "readiness_id": readiness_id,
                        "verifier_id": f"visa.release.verify.{readiness_id}.v1",
                        "runtime_inputs": (
                            supply_runtime_inputs
                            if readiness_id == "supply-chain-license-and-artifact-locks"
                            else (
                                nexus_wire_runtime_inputs
                                if readiness_id == "nexus-native-v1-wire-artifact"
                                else []
                            )
                        ),
                    }
                    for readiness_id in CHECKER.EXPECTED_REQUIRED_IDS
                ],
            },
            "required_ids": CHECKER.EXPECTED_REQUIRED_IDS,
            "build_provenance": {
                "inventory_path": inventory_path,
                "inventory_sha256": inventory_sha,
                "artifact_inventory_path": artifact_inventory_path,
                "artifact_inventory_sha256": artifact_inventory_sha,
            },
            "evidence": evidence_entries,
        }
        index_bytes = self.write_json(bundle / "index.json", index)
        self.write_json(
            bundle / "finalization.json",
            {
                "schema": "visa.release-finalization-receipt.v1",
                "state": "final-release-verified",
                "rc_admission_state": "rc-admitted",
                "index_path": "index.json",
                "index_sha256": CHECKER.hashlib.sha256(index_bytes).hexdigest(),
                "source_revision": revision,
                "source_tag": source_tag,
                "source_tag_object": source_tag_object,
                "final_tag": "v0.1.0",
                "final_tag_object": final_tag_object,
                "final_source_bundle_path": "source/visa-v0.1.0-final.bundle",
                "final_source_bundle_sha256": self.sha256(final_bundle_path),
            },
        )
        (bundle / "attestations/index.provenance.sigstore.jsonl").write_bytes(b'{"subject":"index"}\n')
        (bundle / "attestations/finalization.provenance.sigstore.jsonl").write_bytes(
            b'{"subject":"finalization"}\n'
        )
        return bundle, index

    def test_real_dispatcher_schema_ids_and_cli_fail_closed_in_sync(self) -> None:
        document = CHECKER.load_contract()
        self.assertEqual(
            tuple(CHECKER.EXPECTED_REQUIRED_IDS),
            DISPATCHER.REQUIRED_IDS,
        )
        self.assertEqual(
            document["evidence_policy"]["verifier_input_snapshot_schema"],
            DISPATCHER.INPUT_SNAPSHOT_SCHEMA,
        )
        readiness_id = CHECKER.EXPECTED_REQUIRED_IDS[0]
        input_snapshot = self.root / "dispatcher-input"
        self.write_json(
            input_snapshot / "input-manifest.json",
            {
                "schema": DISPATCHER.INPUT_SNAPSHOT_SCHEMA,
                "readiness_id": readiness_id,
                "source_revision": "a" * 40,
                "source_tag": "v0.1.0-rc.1",
                "evidence": {
                    "origin": "archive",
                    "path": "evidence/result.json",
                    "sha256": "b" * 64,
                },
                "tagged_source_inputs": [],
                "archive_inputs": [],
            },
        )
        output_path = self.root / "dispatcher-output.bin"
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(DISPATCHER_PATH),
                "--id",
                readiness_id,
                "--input-snapshot",
                str(input_snapshot),
                "--output",
                str(output_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b"")
        failure = CHECKER.load_json_bytes(
            result.stderr,
            "real dispatcher fail-closed result",
        )
        self.assertEqual(failure["readiness_id"], readiness_id)
        self.assertEqual(failure["status"], "not-implemented-fail-closed")

        legacy = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(DISPATCHER_PATH),
                "--id",
                readiness_id,
                "--input-snapshot",
                str(input_snapshot),
                "--archive-root",
                str(input_snapshot),
                "--output",
                str(output_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(legacy.returncode, 2)
        self.assertIn(b"--archive-root", legacy.stderr)

    def test_current_contract_is_schema_valid_but_not_release_ready(self) -> None:
        pending = CHECKER.validate()
        document = CHECKER.load_contract()
        ledger = CHECKER.load_toml_bytes(
            CHECKER.DEFAULT_READINESS_LEDGER.read_bytes(), str(CHECKER.DEFAULT_READINESS_LEDGER)
        )
        self.assertEqual(pending, ledger["pending_ids"])
        self.assertNotIn("satisfied_ids", document["release_closure"])
        self.assertNotIn("pending_ids", document["release_closure"])

    def test_immutable_target_contains_no_mutable_progress_or_empty_evidence_slots(self) -> None:
        document = CHECKER.load_contract()
        forbidden_keys = {
            "satisfied_ids",
            "pending_ids",
            "evidence",
            "release_ready",
            "currently_release_supported_cells",
        }

        def inspect(value: object, path: tuple[str, ...] = ()) -> None:
            if isinstance(value, dict):
                for key, nested in value.items():
                    self.assertNotIn(key, forbidden_keys, ".".join((*path, key)))
                    if key == "status":
                        self.assertEqual(path, ())
                        self.assertEqual(nested, "immutable-release-target")
                    inspect(nested, (*path, key))
            elif isinstance(value, list):
                for index, nested in enumerate(value):
                    inspect(nested, (*path, str(index)))
            elif isinstance(value, str):
                self.assertNotEqual(value, "")
                self.assertNotEqual(value, "required-but-unsatisfied")
                self.assertNotEqual(value, "candidate-unqualified")

        inspect(document)

    def test_build_inventory_completeness_is_owned_by_supply_chain_receipt(self) -> None:
        document = CHECKER.load_contract()
        self.assertEqual(
            document["evidence_policy"]["build_inventory_verification"],
            "typed-supply-chain-verifier-extracts-exact-rust-toolchain-tree-and-vendor-into-"
            "private-homes-runs-absolute-cargo-metadata-frozen-offline-and-separately-validates-"
            "producer-records-and-oci-closure-without-executing-docker",
        )
        self.assertIn(
            "supply-chain-license-and-artifact-locks",
            document["release_closure"]["required_ids"],
        )

    def test_buildx_oci_producer_is_complete_and_has_no_ambient_metadata_modes(self) -> None:
        bundle, index = self.external_bundle()
        inventory_path = bundle / index["build_provenance"]["inventory_path"]
        inventory = CHECKER.load_json_bytes(
            inventory_path.read_bytes(),
            "test build inventory",
        )
        environment = inventory["build_environment"]
        self.assertEqual(
            environment["buildkit_oci_output_argv"],
            [
                "docker",
                "buildx",
                "build",
                "--builder",
                "visa-v01",
                "--file",
                "packaging/release/Containerfile",
                "--platform",
                "linux/amd64",
                "--provenance=false",
                "--sbom=false",
                "--output",
                "type=oci,dest=build/derived-image.oci,tar=false,oci-mediatypes=true",
                "--metadata-file",
                "build/buildx-metadata.json",
                ".",
            ],
        )
        self.assertIn(
            "BUILDX_METADATA_PROVENANCE=disabled",
            environment["frozen_environment"],
        )
        self.assertIn(
            "BUILDX_METADATA_WARNINGS=0",
            environment["frozen_environment"],
        )

    def test_release_ready_mode_requires_explicit_archive_root(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), "--release-ready"],
            cwd=CHECKER.ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("--release-ready requires --archive-root PATH", result.stderr)

    def test_product_version_drift_is_rejected(self) -> None:
        path = self.mutated_contract('product_version = "0.1.0"', 'product_version = "0.1.1"')
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "product_version drifted"):
            CHECKER.validate(path)

    def test_product_and_crate_namespaces_cannot_be_conflated(self) -> None:
        path = self.mutated_contract(
            'cargo_crate = "internal-packaging-version-not-product-or-wire-compatibility"',
            'cargo_crate = "same-as-product-semver"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "version namespaces drifted"):
            CHECKER.validate(path)

    def test_six_process_topology_cannot_grow_a_worker_child(self) -> None:
        path = self.mutated_contract(
            'agent_child_processes = "none"',
            'agent_child_processes = "one-worker-per-agent"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "single-host scope drifted"):
            CHECKER.validate(path)

    def test_release_host_baseline_is_not_the_development_fedora_host(self) -> None:
        compatibility = CHECKER.load_contract()["host_compatibility"]
        self.assertTrue(compatibility["release_build_base_image"].startswith("docker.io/library/debian@sha256:"))
        self.assertTrue(compatibility["supported_runtime_baseline"].startswith("ubuntu-24.04-lts"))
        self.assertEqual(compatibility["minimum_systemd_version"], 254)
        self.assertIn("not-a-release-baseline", compatibility["development_host_observation"])

    def test_untested_linux_distribution_cannot_be_promoted_to_supported(self) -> None:
        path = self.mutated_contract(
            'compatibility_policy = "only-exact-tested-matrix-cells-supported-untested-distributions-kernels-libcs-and-systemd-backports-are-nonclaims"',
            'compatibility_policy = "all-linux-x86_64-supported"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "release host compatibility"):
            CHECKER.validate(path)

    def test_nexusd_is_never_upheld_or_restart_scheduled(self) -> None:
        path = self.mutated_contract(
            'target_relationships = "target-wants-and-after-ownershipd-nexusd-and-both-agents-all-four-services-partof-target-no-upholds-bindsto-or-automatic-dependency-recovery"',
            'target_relationships = "target-upholds-ownershipd-agents-and-nexusd"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "systemd user supervision"):
            CHECKER.validate(path)

    def test_systemd_job_stream_is_active_before_start_or_stop(self) -> None:
        path = self.mutated_contract(
            'dbus_subscription = "manager-subscribe-once-per-connection-then-install-and-await-active-jobremoved-signal-stream-before-first-operation"',
            'dbus_subscription = "startunit-then-install-jobremoved-stream"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "systemd user supervision"):
            CHECKER.validate(path)

    def test_missing_notify_socket_can_never_be_treated_as_ready(self) -> None:
        path = self.mutated_contract(
            'readiness_delivery = "explicit-var-os-notify-socket-present-and-nonempty-precheck-then-ready-notification-send-must-succeed-missing-empty-or-send-failure-is-not-ready"',
            'readiness_delivery = "sd-notify-ok-means-ready"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "systemd user supervision"):
            CHECKER.validate(path)

    def test_controller_lock_is_flat_secure_and_never_unlinked(self) -> None:
        path = self.mutated_contract(
            'controller_operation_lease_path = "${XDG_RUNTIME_DIR}/visa-0.1-controller.lock"',
            'controller_operation_lease_path = "${XDG_RUNTIME_DIR}/visa/0.1/controller.lock"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "six-process topology"):
            CHECKER.validate(path)

    def test_six_process_inventory_is_exact(self) -> None:
        path = self.mutated_contract(
            "maximum_active_processes = 6\nmaximum_resident_product_processes",
            "maximum_active_processes = 7\nmaximum_resident_product_processes",
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "single-host scope drifted"):
            CHECKER.validate(path)

    def test_product_process_count_includes_cli_but_excludes_host_infrastructure(self) -> None:
        document = CHECKER.load_contract()
        self.assertEqual(document["process_topology"]["controller_processes"], 1)
        self.assertEqual(document["process_topology"]["maximum_active_processes"], 6)
        self.assertEqual(
            document["scope"]["process_count_scope"],
            "at-most-five-resident-admitted-product-roles-plus-one-exclusive-lease-holding-"
            "mutating-visa-cli-controller",
        )
        self.assertEqual(document["scope"]["maximum_resident_product_processes"], 5)
        self.assertIn("not-kernel-global-process-limit", document["scope"]["process_count_enforcement"])

    def test_mutating_cli_requires_one_exclusive_controller_lease(self) -> None:
        topology = CHECKER.load_contract()["process_topology"]
        self.assertEqual(topology["resident_processes"], 5)
        self.assertIn("first-product-owned-mutation-open", topology["controller_operation_lease"])
        self.assertIn("nonblocking-flock", topology["controller_operation_lease"])
        self.assertIn("never-unlink", topology["controller_operation_lease"])
        self.assertIn("before-mutation-or-rpc", topology["additional_mutating_cli"])
        self.assertEqual(topology["readonly_cli_operations"], ["status", "verify-evidence"])

    def test_release_topology_cannot_enable_socket_activation(self) -> None:
        path = self.mutated_contract("socket_activation = false", "socket_activation = true")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "systemd user supervision"):
            CHECKER.validate(path)

    def test_cli_cannot_spawn_systemctl_as_a_helper_child(self) -> None:
        path = self.mutated_contract(
            'cli_activation = "cohort-create-local-launch-manifest-then-direct-user-dbus-start-stop-status-no-systemctl-child-process"',
            'cli_activation = "spawn-systemctl"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "systemd user supervision"):
            CHECKER.validate(path)

    def test_boot_mismatch_cannot_recover_an_old_registry(self) -> None:
        path = self.mutated_contract(
            'boot_mismatch = "fail-closed-read-only-audit-no-mutation-no-recovery-no-new-registry-under-old-cohort"',
            'boot_mismatch = "recreate-registry-and-replay-old-decision"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "same-boot cohort"):
            CHECKER.validate(path)

    def test_cohort_create_is_pre_rpc_and_never_authority(self) -> None:
        document = CHECKER.load_contract()
        cli = next(entry for entry in document["public_surface"] if entry["id"] == "visa-cli")
        self.assertIn("cohort-create", cli["required_responsibilities"])
        self.assertIn("cohort-retire", cli["required_responsibilities"])
        self.assertNotIn("cohort-create", document["cli_agent_rpc_v1"]["required_operations"])
        self.assertIn("never-an-ownership-or-effect-receipt", document["same_boot_cohort"]["launch_manifest_authority"])

    def test_runtime_root_loss_cannot_resume_an_old_cohort(self) -> None:
        path = self.mutated_contract(
            'cohort_resume = "unsupported-in-0.1"',
            'cohort_resume = "reconstruct-active-registry-from-durable-state"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "same-boot cohort"):
            CHECKER.validate(path)

    def test_partial_cohort_start_rejects_existing_store_mismatch(self) -> None:
        path = self.mutated_contract(
            'partial_start = "exact-manifest-retry-may-create-only-never-initialized-role-stores-and-restart-allowed-roles-existing-mismatches-fail-closed"',
            'partial_start = "reset-mismatched-role-store-and-continue"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "same-boot cohort"):
            CHECKER.validate(path)

    def test_nexus_registry_attempt_prevents_peer_respawn_on_partial_start(self) -> None:
        path = self.mutated_contract(
            'nexus_retry_boundary = "marker-absent-may-retry-start-marker-present-requires-same-live-healthy-nexusd-process-otherwise-cohort-burned-no-startunit-or-peer-respawn"',
            'nexus_retry_boundary = "restart-peer-and-recreate-registry"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "same-boot cohort"):
            CHECKER.validate(path)

    def test_agent_process_generation_cannot_replace_logical_incarnation(self) -> None:
        path = self.mutated_contract(
            'logical_identity = "stable-role-slot-cohort-and-boot-scoped-incarnation"',
            'logical_identity = "fresh-per-process-start"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "logical agent incarnation"):
            CHECKER.validate(path)

    def test_local_rpc_frame_limit_cannot_reuse_the_test_worker_limit(self) -> None:
        path = self.mutated_contract(
            "max_inner_request_bytes = 1048576",
            "max_inner_request_bytes = 16777216",
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "local RPC defaults drifted"):
            CHECKER.validate(path)

    def test_preexisting_jsonl_measurement_is_mutable_readiness_evidence(self) -> None:
        self.assertNotIn("measured_existing_jsonl_max_bytes", self.raw)
        ledger = self.root / "visa-0.1-readiness.toml"
        ledger.write_text(
            self.ledger_raw.replace(
                "observed_max_jsonl_bytes = 53663",
                "observed_max_jsonl_bytes = 53664",
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "development measurements"):
            CHECKER.check_development_readiness(
                CHECKER.load_contract(), CHECKER.DEFAULT_CONTRACT, ledger, CHECKER.ROOT
            )

    def test_local_rpc_namespaces_cannot_be_conflated(self) -> None:
        path = self.mutated_contract(
            'schema = "visa.ownership.local.v1"',
            'schema = "visa.agent.control.v1"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "agent-ownership RPC v1 drifted"):
            CHECKER.validate(path)

    def test_local_rpc_inner_request_and_response_bounds_are_exact(self) -> None:
        path = self.mutated_contract(
            "max_inner_response_bytes = 1048576",
            "max_inner_response_bytes = 1048577",
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "local RPC defaults drifted"):
            CHECKER.validate(path)

    def test_local_rpc_interfaces_cannot_be_conflated(self) -> None:
        path = self.mutated_contract(
            'interface = "io.github.chenty2333.vISA.Ownership1"',
            'interface = "io.github.chenty2333.vISA.AgentControl1"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "agent-ownership RPC v1 drifted"):
            CHECKER.validate(path)

    def test_local_rpc_canonical_decode_cannot_accept_trailing_bytes(self) -> None:
        path = self.mutated_contract(
            'canonical_decode_policy = "reject-trailing-bytes-and-require-byte-identical-reencode"',
            'canonical_decode_policy = "accept-trailing-bytes"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "local RPC defaults drifted"):
            CHECKER.validate(path)

    def test_owned_schema_full_bytes_digest_scope_is_exact(self) -> None:
        old = 'digest_scope = "entire-artifact-exact-bytes-not-postcard-schema-fnv-key"'
        self.assertEqual(self.raw.count(old), 3)
        path = self.root / "visa-0.1.toml"
        path.write_text(self.raw.replace(old, 'digest_scope = "postcard-schema-fnv-key"', 1))
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError, "required owned local RPC schema artifacts"
        ):
            CHECKER.validate(path)

    def test_nexus_child_transport_remains_native_v1_jsonl(self) -> None:
        path = self.mutated_contract(
            'effect_provider_transport = "bounded-json-lines-lf"',
            'effect_provider_transport = "visa.local-user-bus-dbus-postcard.v1"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "single-host scope drifted"):
            CHECKER.validate(path)

    def test_same_uid_boundary_cannot_be_promoted_to_tenant_authentication(self) -> None:
        path = self.mutated_contract(
            'security_boundary = "local-tcb-admission-and-integrity-not-hostile-same-uid-ptrace-pid-namespace-or-allocation-dos-protection"',
            'security_boundary = "malicious-same-uid-authentication-and-tenant-isolation"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "local RPC defaults drifted"):
            CHECKER.validate(path)

    def test_pid_fallback_requires_double_credential_recheck(self) -> None:
        path = self.mutated_contract(
            'process_handle_admission = "prefer-credentials-processfd-else-query-unique-name-uid-pid-pidfd-open-requery-same-unique-name-same-uid-pid-any-change-fail-closed"',
            'process_handle_admission = "trust-single-process-id-query"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "local RPC defaults"):
            CHECKER.validate(path)

    def test_user_bus_rpc_disables_queue_replace_and_activation(self) -> None:
        document = CHECKER.load_contract()
        defaults = document["local_rpc_defaults"]
        self.assertEqual(
            defaults["service_name_policy"],
            "request-name-do-not-queue-no-replace-no-activation-files",
        )
        self.assertEqual(defaults["method_signature"], "ay-to-ay")
        self.assertIn("outer-dbus-bytes-not-locked", defaults["golden_boundary"])

    def test_user_bus_credentials_bind_peer_executable_not_payload_claim(self) -> None:
        defaults = CHECKER.load_contract()["local_rpc_defaults"]
        self.assertIn("get-connection-credentials", defaults["sender_identity"])
        self.assertIn("pidfd-and-secure-proc-exe", defaults["peer_executable_identity"])
        self.assertIn("exact-artifact-inventory", defaults["peer_executable_identity"])
        self.assertIn("name-owner-changed", defaults["credential_cache"])

    def test_user_bus_semantic_outcomes_never_depend_on_dbus_error(self) -> None:
        path = self.mutated_contract(
            'semantic_outcomes = "canonical-inner-success-rejected-unknown-and-internal-dbus-error-only-for-transport-or-pre-admission"',
            'semantic_outcomes = "dbus-error-for-semantic-unknown"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "local RPC defaults drifted"):
            CHECKER.validate(path)

    def test_ownership_authority_cannot_move_into_an_agent(self) -> None:
        path = self.mutated_contract(
            'decision_authority = "sole-reserve-seal-abort-commit-authority"',
            'decision_authority = "source-agent-or-ownershipd"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "ownership service drifted"):
            CHECKER.validate(path)

    def test_ownership_store_cannot_be_opened_by_an_agent(self) -> None:
        path = self.mutated_contract(
            'agent_store_access = "none-rpc-only"',
            'agent_store_access = "direct-sqlite"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "ownership service drifted"):
            CHECKER.validate(path)

    def test_selected_release_dependency_constraint_drift_is_rejected(self) -> None:
        path = self.mutated_contract(
            'wasmtime_release_choice = "=43.0.2"',
            'wasmtime_release_choice = "=44.0.0"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "release dependency constraints drifted"):
            CHECKER.validate(path)

    def test_target_does_not_freeze_current_crate_or_lock_inventory(self) -> None:
        document = CHECKER.load_contract()
        self.assertNotIn("build_crate_lock", document)
        self.assertNotIn("build_provenance", document)
        constraints = document["release_dependency_constraints"]
        self.assertEqual(
            constraints["cargo_lock_digest"], "external-evidence-index-only-at-exact-tag"
        )

    def test_wit_digest_field_drift_is_rejected(self) -> None:
        path = self.mutated_contract(
            'sha256 = "709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920"',
            f'sha256 = "{"a" * 64}"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "WIT locks drifted"):
            CHECKER.validate(path)

    def test_wit_source_byte_drift_is_rejected(self) -> None:
        document = CHECKER.load_contract()
        for _, path, _, _, _ in CHECKER.EXPECTED_WITS:
            self.copy(path, self.root)
        path = self.root / CHECKER.EXPECTED_WITS[0][1]
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "source SHA-256 drifted"):
            CHECKER.check_wits(document, self.root)

    def test_wit_package_id_drift_is_rejected_even_if_digest_were_updated(self) -> None:
        document = CHECKER.load_contract()
        for _, path, _, _, _ in CHECKER.EXPECTED_WITS:
            self.copy(path, self.root)
        path = self.root / CHECKER.EXPECTED_WITS[0][1]
        raw = path.read_text(encoding="utf-8").replace(
            "package visa:continuity@0.1.0;",
            "package visa:continuity@0.2.0;",
            1,
        )
        path.write_text(raw, encoding="utf-8")
        updated_digest = CHECKER.hashlib.sha256(path.read_bytes()).hexdigest()
        document["wit_lock"][0]["sha256"] = updated_digest
        original_wits = CHECKER.EXPECTED_WITS
        CHECKER.EXPECTED_WITS = [
            (*original_wits[0][:-1], updated_digest),
            *original_wits[1:],
        ]
        try:
            with self.assertRaisesRegex(CHECKER.ReleaseContractError, "package ID drifted"):
                CHECKER.check_wits(document, self.root)
        finally:
            CHECKER.EXPECTED_WITS = original_wits

    def test_postcard_golden_bytes_drift_is_rejected(self) -> None:
        old = '''id = "portable-contract-schema-version-1.0"
type = "contract_core::SchemaVersion"
semantic_value = "major=1,minor=0"
canonical_encoding = "postcard-1.1.3"
bytes_hex = "0100"'''
        new = old.replace('bytes_hex = "0100"', 'bytes_hex = "0101"')
        path = self.mutated_contract(old, new)
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "canonical bytes drifted"):
            CHECKER.validate(path)

    def test_release_semantic_vector_drift_is_rejected(self) -> None:
        path = self.mutated_contract(
            'id = "command-begin-handoff-v1"\ntype = "contract_core::Command"',
            'id = "command-begin-handoff-v2"\ntype = "contract_core::Command"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "release semantic vectors drifted"):
            CHECKER.validate(path)

    def test_seed_vectors_cannot_close_the_semantic_corpus(self) -> None:
        path = self.mutated_contract(
            'seed_baseline = "representative-seeds-only-not-release-closure"',
            'seed_baseline = "complete-release-corpus"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "semantic corpus closure drifted"):
            CHECKER.validate(path)

    def test_neutral_wire_bytes_drift_is_rejected(self) -> None:
        document = CHECKER.load_contract()
        paths = [
            document["neutral_wire_v1"]["machine_path"],
            document["neutral_wire_v1"]["protocol_path"],
            document["historical_nexus_mapping_v1"]["path"],
        ]
        for path in paths:
            self.copy(path, self.root)
        machine = self.root / paths[0]
        machine.write_bytes(machine.read_bytes() + b"\n")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "machine_sha256 drifted"):
            CHECKER.check_neutral_and_nexus(document, self.root)

    def test_historical_mapping_cannot_be_promoted_to_release_adapter(self) -> None:
        path = self.mutated_contract("adapter_qualification = false", "adapter_qualification = true")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "historical Nexus mapping v1 drifted"):
            CHECKER.validate(path)

    def test_current_mapping_snapshot_drift_is_rejected(self) -> None:
        old = 'nexus_canonical_snapshot_sha256 = "036bfa21c9c1359755d9cf9a8223e39b7ea1d4793bf4fa948efbf75c9fa52b08"'
        path = self.mutated_contract(old, f'nexus_canonical_snapshot_sha256 = "{"b" * 64}"')
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "required Nexus mapping v2 drifted"):
            CHECKER.validate(path)

    def test_nexus_freeze_cannot_be_called_a_released_v01_api(self) -> None:
        path = self.mutated_contract(
            'api_provenance = "frozen-source-contract-not-nexus-v0.1.0-released-api"',
            'api_provenance = "nexus-v0.1.0-released-api"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "Nexus native-v1 freeze drifted"):
            CHECKER.validate(path)

    def test_portal_v2_cannot_fill_the_native_v1_artifact_slot(self) -> None:
        path = self.mutated_contract(
            'wire_family = "nexus-effect-peer-native-v1"',
            'wire_family = "nexus.portal.v2"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "Nexus wire release artifact drifted"):
            CHECKER.validate(path)

    def test_release_nexus_component_revision_drift_is_rejected(self) -> None:
        path = self.mutated_contract(
            'release_component_revision = "1e49cca428cff39961fd79cadd833ffe0f7365f5"',
            f'release_component_revision = "{"a" * 40}"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "Nexus wire release artifact drifted"):
            CHECKER.validate(path)

    def test_serialized_grant_cannot_be_declared_the_in_process_permit(self) -> None:
        path = self.mutated_contract(
            "existing_committed_effect_permit_equivalence = false",
            "existing_committed_effect_permit_equivalence = true",
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "provider dispatch fence drifted"):
            CHECKER.validate(path)

    def test_dispatch_grant_retry_must_be_byte_identical(self) -> None:
        path = self.mutated_contract(
            'central_grant_replay = "same-request-id-and-bytes-return-byte-identical-grant-never-a-different-grant"',
            'central_grant_replay = "retry-may-mint-a-new-grant"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "provider dispatch fence drifted"):
            CHECKER.validate(path)

    def test_nexusd_crash_cannot_be_promoted_to_progress_recovery(self) -> None:
        old = '''role = "visa-nexusd"
crash_safety = "terminal-phase-relative-fail-closed-no-new-dispatch-or-fabricated-closure"
progress_recovery = "unsupported-in-0.1"'''
        new = old.replace('progress_recovery = "unsupported-in-0.1"', 'progress_recovery = "respawn-peer"')
        path = self.mutated_contract(old, new)
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "process failure matrix drifted"):
            CHECKER.validate(path)

    def test_adapter_crash_cannot_infer_that_a_pre_freeze_source_is_frozen(self) -> None:
        old = '''role = "visa-nexusd"
crash_safety = "terminal-phase-relative-fail-closed-no-new-dispatch-or-fabricated-closure"
progress_recovery = "unsupported-in-0.1"
registry_after_crash = "child-registry-is-not-reconnectable-or-replaceable"
source_disposition_after_crash = "already-frozen-remains-frozen-pre-freeze-retains-prior-disposition-never-inferred-frozen"'''
        path = self.mutated_contract(
            old,
            old.replace(
                "already-frozen-remains-frozen-pre-freeze-retains-prior-disposition-never-inferred-frozen",
                "source-is-always-frozen",
            ),
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "process failure matrix drifted"):
            CHECKER.validate(path)

    def test_provider_identity_requirement_drift_is_rejected(self) -> None:
        path = self.mutated_contract(
            'release_adapter_identity = "exact-visa-nexusd-revision-and-executable-plus-exact-nexus-revision-and-observed-child-executable"',
            'release_adapter_identity = "provider-name-only"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "provider SPI drifted"):
            CHECKER.validate(path)

    def test_provider_protocol_source_drift_is_rejected(self) -> None:
        document = CHECKER.load_contract()
        relative = "crates/backend/substrate_api/src/effect_closure.rs"
        path = self.copy(relative, self.root)
        text = path.read_text(encoding="utf-8").replace(
            "EFFECT_CLOSURE_PROVIDER_PROTOCOL_MAJOR: u16 = 2",
            "EFFECT_CLOSURE_PROVIDER_PROTOCOL_MAJOR: u16 = 3",
            1,
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "provider major.*drifted"):
            CHECKER.check_provider_spi(document, self.root)

    def test_provider_current_minor_source_drift_is_rejected(self) -> None:
        document = CHECKER.load_contract()
        for relative in (
            "crates/backend/substrate_api/src/effect_closure.rs",
            "crates/testing/visa-conformance/src/effect_closure_replay.rs",
        ):
            self.copy(relative, self.root)
        path = self.root / "crates/backend/substrate_api/src/effect_closure.rs"
        text = path.read_text(encoding="utf-8").replace(
            "EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR_V2_1: u16 = 1",
            "EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR_V2_1: u16 = 2",
            1,
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "required.*minor.*drifted"):
            CHECKER.check_provider_spi(document, self.root)

    def test_provider_admission_policy_cannot_collapse_2_1_to_v2_family(self) -> None:
        path = self.mutated_contract(
            '"effect-closure-provider-protocol-not-exactly-2.1-or-profile-not-admission-required",',
            '"effect-closure-provider-v2-preview",',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "admission rejection policy"):
            CHECKER.validate(path)

    def test_development_receipt_inputs_cannot_be_claimed_as_complete_closure(self) -> None:
        path = self.mutated_contract(
            (
                'development_receipt_input_policy = "selected-reproduction-inputs-not-'
                'complete-verifier-read-closure-current-checkout-revalidation-required"'
            ),
            'development_receipt_input_policy = "complete-verifier-input-closure"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "evidence policy drifted"):
            CHECKER.validate(path)

    def test_release_ready_field_cannot_be_written_into_immutable_target(self) -> None:
        path = self.mutated_contract(
            'contract_revision = 5',
            'contract_revision = 5\nrelease_ready = true',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "unknown=.*release_ready"):
            CHECKER.validate(path)

    def test_current_supported_cells_cannot_be_written_into_immutable_target(self) -> None:
        path = self.mutated_contract(
            "[support_policy]\nrequired_release_cells = [",
            '[support_policy]\ncurrently_release_supported_cells = []\nrequired_release_cells = [',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "support policy keys drifted"):
            CHECKER.validate(path)

    def test_development_ledger_target_digest_mismatch_is_rejected(self) -> None:
        document = CHECKER.load_contract()
        ledger = self.root / "visa-0.1-readiness.toml"
        current_digest = CHECKER.hashlib.sha256(CHECKER.DEFAULT_CONTRACT.read_bytes()).hexdigest()
        self.assertIn(current_digest, self.ledger_raw)
        ledger.write_text(self.ledger_raw.replace(current_digest, "0" * 64, 1), encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "development target SHA-256 drifted"):
            CHECKER.check_development_readiness(
                document,
                CHECKER.DEFAULT_CONTRACT,
                ledger,
                CHECKER.ROOT,
            )

    def test_development_ledger_cannot_drop_a_required_id(self) -> None:
        document = CHECKER.load_contract()
        path = self.root / "visa-0.1-readiness.toml"
        lines = self.ledger_raw.rsplit('  "exact-tag-release-evidence",\n', 1)
        self.assertEqual(len(lines), 2)
        path.write_text("".join(lines), encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "partition target required IDs"):
            CHECKER.check_development_readiness(
                document,
                CHECKER.DEFAULT_CONTRACT,
                path,
                CHECKER.ROOT,
            )

    def test_external_release_index_closes_all_required_ids_without_target_rewrite(self) -> None:
        bundle, index = self.external_bundle()
        document = CHECKER.load_contract()
        revision = self.check_external_bundle(bundle, index, document=document)
        self.assertRegex(revision, r"^[0-9a-f]{40}$")
        self.assertNotIn("satisfied_ids", document["release_closure"])

    def test_rc_admission_precedes_final_tag_verification(self) -> None:
        bundle, index = self.external_bundle()
        for relative in (
            "finalization.json",
            "source/visa-v0.1.0-final.bundle",
            "attestations/finalization.provenance.sigstore.jsonl",
        ):
            (bundle / relative).unlink()
        revision = self.check_external_bundle(bundle, index, release_stage="rc-admitted")
        self.assertRegex(revision, r"^[0-9a-f]{40}$")

    def test_final_archive_is_not_reused_as_the_rc_archive_root(self) -> None:
        bundle, index = self.external_bundle()
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError, "exact external archive file inventory"
        ):
            self.check_external_bundle(bundle, index, release_stage="rc-admitted")

    def test_external_release_index_missing_id_fails_closed(self) -> None:
        bundle, index = self.external_bundle()
        index["evidence"].pop()
        self.rewrite_index_binding(bundle, index)
        document = CHECKER.load_contract()
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "external evidence coverage"):
            self.check_external_bundle(bundle, index, document=document)

    def test_owned_schema_evidence_cannot_move_to_an_unbound_archive_path(self) -> None:
        bundle, index = self.external_bundle()
        entry = next(entry for entry in index["evidence"] if entry["id"] == "cli-agent-rpc-v1")
        entry["evidence_path"] = "evidence/unbound-agent-schema.json"
        self.rewrite_index_binding(bundle, index)
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "owned schema evidence path"):
            self.check_external_bundle(bundle, index)

    def test_finalization_must_bind_the_rc_admitted_revision(self) -> None:
        bundle, index = self.external_bundle()
        index["contract"]["source_revision"] = "a" * 40
        self.rewrite_index_binding(bundle, index)
        document = CHECKER.load_contract()
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "indexed out-of-band source revision"):
            self.check_external_bundle(bundle, index, document=document)

    def test_archive_index_cannot_select_a_different_valid_rc_tag(self) -> None:
        bundle, index = self.external_bundle()
        index["contract"]["source_tag"] = "v0.1.0-rc.2"
        self.rewrite_index_binding(bundle, index)
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "indexed out-of-band source tag"):
            self.check_external_bundle(bundle, index)

    def test_archive_rc_tag_object_must_match_the_trusted_checkout(self) -> None:
        bundle, index = self.external_bundle()
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "RC tag object against out-of-band trusted checkout",
        ):
            self.check_external_bundle(
                bundle,
                index,
                expected_source_tag_object="0" * 40,
            )

    def test_archive_final_tag_object_must_match_the_trusted_checkout(self) -> None:
        bundle, index = self.external_bundle()
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "final tag object against out-of-band trusted checkout",
        ):
            self.check_external_bundle(
                bundle,
                index,
                expected_final_tag_object="0" * 40,
            )

    def test_external_build_inventory_requires_package_license(self) -> None:
        bundle, index = self.external_bundle()
        inventory_path = bundle / index["build_provenance"]["inventory_path"]
        inventory = CHECKER.load_json_bytes(inventory_path.read_bytes(), "test inventory")
        inventory["workspace_packages"][0]["license"] = ""
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "non-empty strings"):
            CHECKER.check_build_inventory(
                inventory,
                index["contract"],
                {
                    "cargo_lock_sha256": index["archive"]["cargo_lock_sha256"],
                    "rust_toolchain_sha256": index["archive"]["rust_toolchain_sha256"],
                    "release_build_base_image": CHECKER.load_contract()["host_compatibility"]
                    ["release_build_base_image"],
                    "runtime_inputs": next(
                        entry["runtime_inputs"]
                        for entry in index["verifier_registry"]["entries"]
                        if entry["readiness_id"]
                        == "supply-chain-license-and-artifact-locks"
                    ),
                },
            )

    def test_supply_chain_registry_rejects_an_unknown_runtime_role(self) -> None:
        bundle, index = self.external_bundle()
        registry_entry = next(
            entry
            for entry in index["verifier_registry"]["entries"]
            if entry["readiness_id"] == "supply-chain-license-and-artifact-locks"
        )
        registry_entry["runtime_inputs"][-1]["id"] = "unknown-extra-role"
        self.rewrite_index_binding(bundle, index)
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "supply-chain runtime input roles and order",
        ):
            self.check_external_bundle(bundle, index)

    def test_nexus_producer_attestation_without_component_material_is_rejected(
        self,
    ) -> None:
        bundle, index = self.external_bundle()

        def omit_component_material(arguments: list[str]) -> bytes:
            trusted_output = self.trusted_attestation(arguments)
            if len(arguments) == 2 and arguments[1] == "version":
                return trusted_output
            output = CHECKER.json.loads(trusted_output)
            if (
                "--repo" in arguments
                and arguments[arguments.index("--repo") + 1] == "chenty2333/Nexus"
                and arguments[arguments.index("--predicate-type") + 1]
                == "https://in-toto.io/attestation/link/v0.3"
            ):
                materials = output[0]["verificationResult"]["statement"][
                    "predicate"
                ]["materials"]
                output[0]["verificationResult"]["statement"]["predicate"][
                    "materials"
                ] = [
                    entry
                    for entry in materials
                    if entry.get("name") != "nexus-component-source-revision"
                ]
            return (CHECKER.json.dumps(output, sort_keys=True) + "\n").encode()

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "release Link material names and order",
        ):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=omit_component_material,
            )

    def test_nexus_attested_substitute_source_graph_is_rejected(self) -> None:
        bundle, index = self.external_bundle()

        def substitute_source_graph(arguments: list[str]) -> bytes:
            trusted_output = self.trusted_attestation(arguments)
            if len(arguments) == 2 and arguments[1] == "version":
                return trusted_output
            output = CHECKER.json.loads(trusted_output)
            if (
                "--repo" in arguments
                and arguments[arguments.index("--repo") + 1] == "chenty2333/Nexus"
                and arguments[arguments.index("--predicate-type") + 1]
                == "https://in-toto.io/attestation/link/v0.3"
            ):
                materials = output[0]["verificationResult"]["statement"][
                    "predicate"
                ]["materials"]
                source_graph = next(
                    entry
                    for entry in materials
                    if entry.get("name") == "nexus-component-source-graph"
                )
                source_graph["digest"]["sha256"] = "0" * 64
            return (CHECKER.json.dumps(output, sort_keys=True) + "\n").encode()

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "release Link materials drifted",
        ):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=substitute_source_graph,
            )

    def test_nexus_standard_provenance_wrong_build_type_is_rejected(self) -> None:
        bundle, index = self.external_bundle()

        def wrong_build_type(arguments: list[str]) -> bytes:
            trusted_output = self.trusted_attestation(arguments)
            if len(arguments) == 2 and arguments[1] == "version":
                return trusted_output
            output = CHECKER.json.loads(trusted_output)
            if (
                arguments[arguments.index("--repo") + 1] == "chenty2333/Nexus"
                and arguments[arguments.index("--predicate-type") + 1]
                == "https://slsa.dev/provenance/v1"
            ):
                output[0]["verificationResult"]["statement"]["predicate"][
                    "buildDefinition"
                ]["buildType"] = "https://example.invalid/forged-build/v1"
            return (CHECKER.json.dumps(output, sort_keys=True) + "\n").encode()

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "Nexus effect-peer build type drifted",
        ):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=wrong_build_type,
            )

    def test_nexus_standard_provenance_extra_workflow_parameter_is_rejected(
        self,
    ) -> None:
        bundle, index = self.external_bundle()

        def extra_parameter(arguments: list[str]) -> bytes:
            trusted_output = self.trusted_attestation(arguments)
            if len(arguments) == 2 and arguments[1] == "version":
                return trusted_output
            output = CHECKER.json.loads(trusted_output)
            if (
                arguments[arguments.index("--repo") + 1] == "chenty2333/Nexus"
                and arguments[arguments.index("--predicate-type") + 1]
                == "https://slsa.dev/provenance/v1"
            ):
                output[0]["verificationResult"]["statement"]["predicate"][
                    "buildDefinition"
                ]["externalParameters"]["untrusted"] = "caller-controlled"
            return (CHECKER.json.dumps(output, sort_keys=True) + "\n").encode()

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "external workflow parameters drifted",
        ):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=extra_parameter,
            )

    def test_nexus_standard_provenance_builder_must_match_certificate(
        self,
    ) -> None:
        bundle, index = self.external_bundle()

        def substitute_builder(arguments: list[str]) -> bytes:
            trusted_output = self.trusted_attestation(arguments)
            if len(arguments) == 2 and arguments[1] == "version":
                return trusted_output
            output = CHECKER.json.loads(trusted_output)
            if (
                arguments[arguments.index("--repo") + 1] == "chenty2333/Nexus"
                and arguments[arguments.index("--predicate-type") + 1]
                == "https://slsa.dev/provenance/v1"
            ):
                output[0]["verificationResult"]["statement"]["predicate"][
                    "runDetails"
                ]["builder"]["id"] = "https://example.invalid/forged-builder"
            return (CHECKER.json.dumps(output, sort_keys=True) + "\n").encode()

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "authenticated Nexus effect-peer builder drifted",
        ):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=substitute_builder,
            )

    def test_nexus_standard_provenance_repository_id_must_match_certificate(
        self,
    ) -> None:
        bundle, index = self.external_bundle()

        def substitute_repository_id(arguments: list[str]) -> bytes:
            trusted_output = self.trusted_attestation(arguments)
            if len(arguments) == 2 and arguments[1] == "version":
                return trusted_output
            output = CHECKER.json.loads(trusted_output)
            if (
                arguments[arguments.index("--repo") + 1] == "chenty2333/Nexus"
                and arguments[arguments.index("--predicate-type") + 1]
                == "https://slsa.dev/provenance/v1"
            ):
                output[0]["verificationResult"]["statement"]["predicate"][
                    "buildDefinition"
                ]["internalParameters"]["github"]["repository_id"] = "9999"
            return (CHECKER.json.dumps(output, sort_keys=True) + "\n").encode()

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "repository ID against certificate drifted",
        ):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=substitute_repository_id,
            )

    def test_nexus_release_link_must_share_the_build_run_invocation(self) -> None:
        bundle, index = self.external_bundle()

        def different_link_run(arguments: list[str]) -> bytes:
            trusted_output = self.trusted_attestation(arguments)
            if len(arguments) == 2 and arguments[1] == "version":
                return trusted_output
            output = CHECKER.json.loads(trusted_output)
            if (
                arguments[arguments.index("--repo") + 1] == "chenty2333/Nexus"
                and arguments[arguments.index("--predicate-type") + 1]
                == "https://in-toto.io/attestation/link/v0.3"
            ):
                output[0]["verificationResult"]["signature"]["certificate"][
                    "runInvocationURI"
                ] = (
                    "https://github.com/chenty2333/Nexus/actions/runs/"
                    "3002/attempts/1"
                )
            return (CHECKER.json.dumps(output, sort_keys=True) + "\n").encode()

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "build provenance and release Link certificate coordinates drifted",
        ):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=different_link_run,
            )

    def test_nexus_release_link_substitute_build_record_is_rejected(self) -> None:
        bundle, index = self.external_bundle()

        def substitute_build_record(arguments: list[str]) -> bytes:
            trusted_output = self.trusted_attestation(arguments)
            if len(arguments) == 2 and arguments[1] == "version":
                return trusted_output
            output = CHECKER.json.loads(trusted_output)
            if (
                arguments[arguments.index("--repo") + 1] == "chenty2333/Nexus"
                and arguments[arguments.index("--predicate-type") + 1]
                == "https://in-toto.io/attestation/link/v0.3"
            ):
                output[0]["verificationResult"]["statement"]["predicate"][
                    "byproducts"
                ]["buildRecordId"] = "substituted-build-record"
            return (CHECKER.json.dumps(output, sort_keys=True) + "\n").encode()

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "release Link byproducts drifted",
        ):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=substitute_build_record,
            )

    def test_oci_file_set_cannot_omit_the_root_descriptor_blob(self) -> None:
        bundle, index = self.external_bundle()
        build_inventory = CHECKER.load_json_bytes(
            (bundle / index["build_provenance"]["inventory_path"]).read_bytes(),
            "test build inventory",
        )
        layout_inventory_path = bundle / "build/derived-image-oci-inventory.json"
        layout_inventory = CHECKER.load_json_bytes(
            layout_inventory_path.read_bytes(),
            "test OCI layout inventory",
        )
        descriptor_digest = build_inventory["derived_build_image"]["descriptor"][
            "digest"
        ].removeprefix("sha256:")
        descriptor_path = (
            f"{build_inventory['derived_build_image']['output_root']}/"
            f"blobs/sha256/{descriptor_digest}"
        )
        layout_inventory["files"] = [
            entry
            for entry in layout_inventory["files"]
            if entry["path"] != descriptor_path
        ]
        self.write_json(layout_inventory_path, layout_inventory)
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "omits the root descriptor blob",
        ):
            CHECKER.check_oci_layout_file_set(
                bundle,
                "build/derived-image-oci-inventory.json",
                index["contract"],
                build_inventory["derived_build_image"],
                CHECKER.ArchiveReadBudget(),
            )

    def test_oci_blob_path_must_equal_its_content_digest(self) -> None:
        bundle, index = self.external_bundle()
        build_inventory = CHECKER.load_json_bytes(
            (bundle / index["build_provenance"]["inventory_path"]).read_bytes(),
            "test build inventory",
        )
        layout_inventory_path = bundle / "build/derived-image-oci-inventory.json"
        layout_inventory = CHECKER.load_json_bytes(
            layout_inventory_path.read_bytes(),
            "test OCI layout inventory",
        )
        blob_entry = next(
            entry
            for entry in layout_inventory["files"]
            if "/blobs/sha256/" in entry["path"]
        )
        blob_entry["sha256"] = "0" * 64
        self.write_json(layout_inventory_path, layout_inventory)
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "OCI blob path-to-content digest",
        ):
            CHECKER.check_oci_layout_file_set(
                bundle,
                "build/derived-image-oci-inventory.json",
                index["contract"],
                build_inventory["derived_build_image"],
                CHECKER.ArchiveReadBudget(),
            )

    def test_oci_layout_rejects_docker_archive_manifest_json(self) -> None:
        bundle, index = self.external_bundle()
        build_inventory = CHECKER.load_json_bytes(
            (bundle / index["build_provenance"]["inventory_path"]).read_bytes(),
            "test build inventory",
        )
        layout_inventory_path = bundle / "build/derived-image-oci-inventory.json"
        layout_inventory = CHECKER.load_json_bytes(
            layout_inventory_path.read_bytes(),
            "test OCI layout inventory",
        )
        docker_manifest = bundle / "build/derived-image.oci/manifest.json"
        docker_manifest.write_bytes(b"[]\n")
        layout_inventory["files"].append(
            {
                "path": "build/derived-image.oci/manifest.json",
                "size": docker_manifest.stat().st_size,
                "sha256": self.sha256(docker_manifest),
            }
        )
        layout_inventory["files"].sort(key=lambda entry: entry["path"])
        self.write_json(layout_inventory_path, layout_inventory)
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "outside the closed layout shape",
        ):
            CHECKER.check_oci_layout_file_set(
                bundle,
                "build/derived-image-oci-inventory.json",
                index["contract"],
                build_inventory["derived_build_image"],
                CHECKER.ArchiveReadBudget(),
            )

    def test_supply_receipt_cannot_drop_an_oci_layout_file_input(self) -> None:
        bundle, index = self.external_bundle()
        evidence_entry = next(
            entry
            for entry in index["evidence"]
            if entry["id"] == "supply-chain-license-and-artifact-locks"
        )
        receipt_path = bundle / evidence_entry["verifier_receipt_path"]
        receipt = CHECKER.load_json_bytes(
            receipt_path.read_bytes(),
            "test supply-chain receipt",
        )
        receipt["input_sha256"].pop("build/derived-image.oci/index.json")
        receipt_bytes = self.write_json(receipt_path, receipt)
        evidence_entry["verifier_receipt_sha256"] = CHECKER.hashlib.sha256(
            receipt_bytes
        ).hexdigest()
        self.refresh_payload_binding(
            bundle,
            index,
            evidence_entry["verifier_receipt_path"],
        )
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "supply-chain OCI layout verifier input",
        ):
            self.check_external_bundle(bundle, index)

    def test_product_build_must_reference_the_derived_builder_record(self) -> None:
        bundle, index = self.external_bundle()
        inventory = CHECKER.load_json_bytes(
            (bundle / index["build_provenance"]["inventory_path"]).read_bytes(),
            "test build inventory",
        )
        inventory["product_roots"][0]["builder_image_record_id"] = (
            "visa.buildx.derived-image.v1:"
            f"{index['contract']['source_revision']}:wrong-platform"
        )
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "product root builder image record ID",
        ):
            CHECKER.check_build_inventory(
                inventory,
                index["contract"],
                {
                    "cargo_lock_sha256": index["archive"]["cargo_lock_sha256"],
                    "rust_toolchain_sha256": index["archive"]["rust_toolchain_sha256"],
                    "release_build_base_image": CHECKER.load_contract()[
                        "host_compatibility"
                    ]["release_build_base_image"],
                    "runtime_inputs": next(
                        entry["runtime_inputs"]
                        for entry in index["verifier_registry"]["entries"]
                        if entry["readiness_id"]
                        == "supply-chain-license-and-artifact-locks"
                    ),
                },
            )

    def test_build_inventory_rejects_an_incomplete_buildx_argv(self) -> None:
        bundle, index = self.external_bundle()
        inventory = CHECKER.load_json_bytes(
            (bundle / index["build_provenance"]["inventory_path"]).read_bytes(),
            "test build inventory",
        )
        inventory["build_environment"]["buildkit_oci_output_argv"].pop()
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "BuildKit OCI output argv",
        ):
            CHECKER.check_build_inventory(
                inventory,
                index["contract"],
                {
                    "cargo_lock_sha256": index["archive"]["cargo_lock_sha256"],
                    "rust_toolchain_sha256": index["archive"]["rust_toolchain_sha256"],
                    "release_build_base_image": CHECKER.load_contract()[
                        "host_compatibility"
                    ]["release_build_base_image"],
                    "runtime_inputs": next(
                        entry["runtime_inputs"]
                        for entry in index["verifier_registry"]["entries"]
                        if entry["readiness_id"]
                        == "supply-chain-license-and-artifact-locks"
                    ),
                },
            )

    def test_release_receipt_cannot_supply_an_arbitrary_verifier_command(self) -> None:
        bundle, index = self.external_bundle()
        entry = index["evidence"][0]
        receipt_path = bundle / entry["verifier_receipt_path"]
        receipt = CHECKER.load_json_bytes(receipt_path.read_bytes(), "test receipt")
        receipt["verifier_command"] = "true"
        receipt_bytes = self.write_json(receipt_path, receipt)
        entry["verifier_receipt_sha256"] = CHECKER.hashlib.sha256(receipt_bytes).hexdigest()
        self.refresh_payload_binding(bundle, index, entry["verifier_receipt_path"])
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "unknown=.*verifier_command"):
            self.check_external_bundle(bundle, index)

    def test_release_receipt_cannot_add_an_unbound_input_digest(self) -> None:
        bundle, index = self.external_bundle()
        entry = index["evidence"][0]
        receipt_path = bundle / entry["verifier_receipt_path"]
        receipt = CHECKER.load_json_bytes(receipt_path.read_bytes(), "test receipt")
        receipt["input_sha256"]["unbound/unused-input"] = "0" * 64
        receipt_bytes = self.write_json(receipt_path, receipt)
        entry["verifier_receipt_sha256"] = CHECKER.hashlib.sha256(
            receipt_bytes
        ).hexdigest()
        self.refresh_payload_binding(bundle, index, entry["verifier_receipt_path"])
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "closed typed verifier input paths",
        ):
            self.check_external_bundle(bundle, index)

    def test_archive_manifest_boolean_size_is_not_an_integer(self) -> None:
        bundle, index = self.external_bundle()
        manifest_path = bundle / index["archive"]["manifest_path"]
        manifest = CHECKER.load_json_bytes(
            manifest_path.read_bytes(),
            "test archive manifest",
        )
        manifest["files"][0]["size"] = True
        manifest_bytes = self.write_json(manifest_path, manifest)
        index["archive"]["manifest_sha256"] = CHECKER.hashlib.sha256(
            manifest_bytes
        ).hexdigest()
        self.rewrite_index_binding(bundle, index)
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "archive manifest size is invalid",
        ):
            self.check_external_bundle(bundle, index)

    def test_oci_file_count_bound_fits_the_receipt_byte_bound(self) -> None:
        input_sha256 = {
            "specs/release/visa-0.1.toml": "a" * 64,
            "scripts/verify-release-readiness.py": "b" * 64,
            "build/workspace-package-inventory.json": "c" * 64,
            "build/derived-image.oci/index.json": "d" * 64,
            "build/derived-image.oci/oci-layout": "e" * 64,
        }
        for index in range(CHECKER.MAX_OCI_LAYOUT_FILES - 2):
            digest = f"{index:064x}"
            input_sha256[
                f"build/derived-image.oci/blobs/sha256/{digest}"
            ] = digest
        for index in range(64):
            input_sha256[
                f"supply-chain/{index:04d}-{'x' * 180}"
            ] = "f" * 64
        receipt = {
            "schema": "visa.release-readiness-verifier-receipt.v2",
            "readiness_id": "supply-chain-license-and-artifact-locks",
            "target_path": "specs/release/visa-0.1.toml",
            "target_sha256": "a" * 64,
            "source_revision": "f" * 40,
            "source_tag": f"v0.1.0-rc.{'9' * 200}",
            "verifier_id": (
                "visa.release.verify.supply-chain-license-and-artifact-locks.v1"
            ),
            "verifier_source_path": "scripts/verify-release-readiness.py",
            "verifier_source_sha256": "b" * 64,
            "exit_code": 0,
            "output_sha256": "c" * 64,
            "verifier_result_sha256": "d" * 64,
            "input_sha256": input_sha256,
        }
        encoded = (CHECKER.json.dumps(receipt, sort_keys=True) + "\n").encode()
        self.assertLessEqual(len(encoded), CHECKER.MAX_VERIFIER_RECEIPT_BYTES)
        self.assertGreater(len(encoded), CHECKER.MAX_VERIFIER_RECEIPT_BYTES // 2)

    def test_typed_verifier_receives_only_its_closed_private_snapshot(self) -> None:
        bundle, index = self.external_bundle()
        observed_ids: list[str] = []

        def inspect_snapshot(
            dispatcher_path: Path,
            readiness_id: str,
            input_snapshot: Path,
        ) -> tuple[int, bytes, bytes]:
            manifest = CHECKER.load_json_bytes(
                (input_snapshot / "input-manifest.json").read_bytes(),
                "test private input snapshot",
            )
            expected_files = {"input-manifest.json"}
            expected_files.update(
                f"tagged-source/{entry['path']}"
                for entry in manifest["tagged_source_inputs"]
            )
            expected_files.update(
                f"archive/{entry['path']}" for entry in manifest["archive_inputs"]
            )
            self.assertEqual(
                CHECKER.archive_file_set(input_snapshot),
                expected_files,
            )
            self.assertFalse((input_snapshot / "archive/index.json").exists())
            self.assertFalse(
                (input_snapshot / "archive/archive/manifest.json").exists()
            )
            self.assertEqual(
                {path.name for path in dispatcher_path.parent.iterdir()},
                {"verify-release-readiness.py"},
            )
            observed_ids.append(readiness_id)
            return self.trusted_release_verifier(
                dispatcher_path,
                readiness_id,
                input_snapshot,
            )

        self.check_external_bundle(
            bundle,
            index,
            release_verifier_runner=inspect_snapshot,
        )
        self.assertEqual(observed_ids, CHECKER.EXPECTED_REQUIRED_IDS)

    def test_post_verifier_snapshot_mutation_is_rejected(self) -> None:
        bundle, index = self.external_bundle()

        def mutate_snapshot(
            dispatcher_path: Path,
            readiness_id: str,
            input_snapshot: Path,
        ) -> tuple[int, bytes, bytes]:
            del dispatcher_path
            manifest = CHECKER.load_json_bytes(
                (input_snapshot / "input-manifest.json").read_bytes(),
                "test private input snapshot",
            )
            evidence_binding = manifest["evidence"]
            evidence_path = input_snapshot / "archive" / evidence_binding["path"]
            original = evidence_path.read_bytes()
            evidence_path.chmod(0o600)
            evidence_path.write_bytes(b"mutated after snapshot validation\n")
            return (
                0,
                self.typed_verifier_result(
                    readiness_id,
                    evidence_binding["sha256"],
                ),
                original,
            )

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "post-verifier input snapshot digest",
        ):
            self.check_external_bundle(
                bundle,
                index,
                release_verifier_runner=mutate_snapshot,
            )

    def test_original_archive_mutation_cannot_change_a_running_snapshot(self) -> None:
        bundle, index = self.external_bundle()
        bounced = False

        def bounce_original_archive(
            dispatcher_path: Path,
            readiness_id: str,
            input_snapshot: Path,
        ) -> tuple[int, bytes, bytes]:
            nonlocal bounced
            manifest = CHECKER.load_json_bytes(
                (input_snapshot / "input-manifest.json").read_bytes(),
                "test private input snapshot",
            )
            evidence_binding = manifest["evidence"]
            snapshot_evidence = (
                input_snapshot / "archive" / evidence_binding["path"]
            ).read_bytes()
            if not bounced:
                original_path = bundle / evidence_binding["path"]
                original = original_path.read_bytes()
                original_path.write_bytes(b"temporary archive mutation\n")
                self.assertEqual(
                    (
                        input_snapshot / "archive" / evidence_binding["path"]
                    ).read_bytes(),
                    snapshot_evidence,
                )
                original_path.write_bytes(original)
                bounced = True
            return self.trusted_release_verifier(
                dispatcher_path,
                readiness_id,
                input_snapshot,
            )

        self.check_external_bundle(
            bundle,
            index,
            release_verifier_runner=bounce_original_archive,
        )
        self.assertTrue(bounced)

    def test_archive_runtime_input_cannot_shadow_tagged_source(self) -> None:
        bundle, index = self.external_bundle()
        registry_entry = index["verifier_registry"]["entries"][0]
        registry_entry["runtime_inputs"] = [
            {
                "id": "tagged-target-shadow",
                "kind": "data",
                "path": index["contract"]["target_path"],
                "sha256": index["contract"]["target_sha256"],
                "version": "forged-shadow-v1",
            }
        ]
        self.rewrite_index_binding(bundle, index)
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "runtime input collides with tagged-source input",
        ):
            self.check_external_bundle(bundle, index)

    def test_typed_verifier_id_cannot_be_substituted(self) -> None:
        bundle, index = self.external_bundle()
        entry = index["evidence"][0]
        receipt_path = bundle / entry["verifier_receipt_path"]
        receipt = CHECKER.load_json_bytes(receipt_path.read_bytes(), "test receipt")
        receipt["verifier_id"] = "visa.release.verify.anything.v1"
        receipt_bytes = self.write_json(receipt_path, receipt)
        entry["verifier_receipt_sha256"] = CHECKER.hashlib.sha256(receipt_bytes).hexdigest()
        self.refresh_payload_binding(bundle, index, entry["verifier_receipt_path"])
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "verifier ID drifted"):
            self.check_external_bundle(bundle, index)

    def test_failed_initial_index_attestation_executes_no_release_verifier(self) -> None:
        bundle, index = self.external_bundle()
        verifier_calls: list[str] = []

        def reject_index_attestation(arguments: list[str]) -> bytes:
            if len(arguments) == 2 and arguments[1] == "version":
                return self.trusted_attestation(arguments)
            raise CHECKER.ReleaseContractError("test index attestation rejected")

        def count_release_verifier(
            dispatcher_path: Path,
            readiness_id: str,
            input_snapshot: Path,
        ) -> tuple[int, bytes, bytes]:
            del dispatcher_path, input_snapshot
            verifier_calls.append(readiness_id)
            return 0, b"{}\n", b""

        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "index attestation rejected"):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=reject_index_attestation,
                release_verifier_runner=count_release_verifier,
            )
        self.assertEqual(verifier_calls, [])

    def test_failed_initial_finalization_attestation_executes_no_release_verifier(self) -> None:
        bundle, index = self.external_bundle()
        verifier_calls: list[str] = []

        def reject_finalization_attestation(arguments: list[str]) -> bytes:
            if len(arguments) == 2 and arguments[1] == "version":
                return self.trusted_attestation(arguments)
            source_ref = arguments[arguments.index("--source-ref") + 1]
            if source_ref == "refs/tags/v0.1.0":
                raise CHECKER.ReleaseContractError("test finalization attestation rejected")
            return self.trusted_attestation(arguments)

        def count_release_verifier(
            dispatcher_path: Path,
            readiness_id: str,
            input_snapshot: Path,
        ) -> tuple[int, bytes, bytes]:
            del dispatcher_path, input_snapshot
            verifier_calls.append(readiness_id)
            return 0, b"{}\n", b""

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError, "finalization attestation rejected"
        ):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=reject_finalization_attestation,
                release_verifier_runner=count_release_verifier,
            )
        self.assertEqual(verifier_calls, [])

    def test_finalization_is_not_parsed_before_its_attestation(self) -> None:
        bundle, index = self.external_bundle()
        (bundle / "finalization.json").write_bytes(b"not valid JSON\n")

        def reject_finalization_attestation(arguments: list[str]) -> bytes:
            if len(arguments) == 2 and arguments[1] == "version":
                return self.trusted_attestation(arguments)
            source_ref = arguments[arguments.index("--source-ref") + 1]
            if source_ref == "refs/tags/v0.1.0":
                raise CHECKER.ReleaseContractError("test finalization attestation rejected first")
            return self.trusted_attestation(arguments)

        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError, "finalization attestation rejected first"
        ):
            self.check_external_bundle(
                bundle,
                index,
                attestation_runner=reject_finalization_attestation,
            )

    def test_attestation_verifier_rejects_duplicate_verified_results(self) -> None:
        bundle, index = self.external_bundle()

        def duplicate_results(arguments: list[str]) -> bytes:
            output = self.trusted_attestation(arguments)
            if len(arguments) == 2 and arguments[1] == "version":
                return output
            result = CHECKER.json.loads(output)
            return (CHECKER.json.dumps(result + result, sort_keys=True) + "\n").encode()

        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "exactly one result"):
            self.check_external_bundle(bundle, index, attestation_runner=duplicate_results)

    def test_standard_and_link_attestation_bundle_digest_mismatch_is_rejected(
        self,
    ) -> None:
        archive_root = self.root / "attestation-bundle-digest"
        archive_root.mkdir()
        (archive_root / "bundle.jsonl").write_bytes(b'{"test":"bundle"}\n')
        trusted_root = archive_root / "trusted-root.jsonl"
        trusted_root.write_bytes(b'{"test":"root"}\n')

        def must_not_run(arguments: list[str]) -> bytes:
            del arguments
            self.fail("bundle digest mismatch must fail before invoking gh")

        for predicate_type in (
            "https://slsa.dev/provenance/v1",
            "https://in-toto.io/attestation/link/v0.3",
        ):
            with self.subTest(predicate_type=predicate_type):
                with self.assertRaisesRegex(
                    CHECKER.ReleaseContractError,
                    "captured attestation bundle digest drifted",
                ):
                    CHECKER.verify_attestation(
                        Path("/private/pinned/gh"),
                        archive_root,
                        "subject.bin",
                        b"subject",
                        "bundle.jsonl",
                        trusted_root,
                        "chenty2333/Nexus",
                        (
                            "chenty2333/Nexus/.github/workflows/"
                            "release-effect-peer-wire.yml"
                        ),
                        "c" * 40,
                        "refs/tags/test-only-nexus-effect-peer-wire-v1",
                        must_not_run,
                        CHECKER.ArchiveReadBudget(),
                        "test attestation",
                        expected_bundle_sha256="0" * 64,
                        predicate_type=predicate_type,
                    )

    def test_archive_cannot_select_its_own_bootstrap_digests(self) -> None:
        bundle, index = self.external_bundle()
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "attestation verifier out-of-band digest",
        ):
            CHECKER.check_external_release_index(
                CHECKER.load_contract(),
                CHECKER.DEFAULT_CONTRACT,
                bundle,
                "0" * 64,
                index["archive"]["trusted_root_sha256"],
                index["contract"]["source_revision"],
                index["contract"]["source_tag"],
                self.expected_source_tag_object,
                self.expected_final_tag_object,
                self.trusted_attestation,
                self.trusted_release_verifier,
            )
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "trusted root out-of-band digest",
        ):
            CHECKER.check_external_release_index(
                CHECKER.load_contract(),
                CHECKER.DEFAULT_CONTRACT,
                bundle,
                index["archive"]["attestation_verifier_sha256"],
                "0" * 64,
                index["contract"]["source_revision"],
                index["contract"]["source_tag"],
                self.expected_source_tag_object,
                self.expected_final_tag_object,
                self.trusted_attestation,
                self.trusted_release_verifier,
            )

    def test_attestation_verifier_rejects_wrong_release_url(self) -> None:
        def wrong_release_url(arguments: list[str]) -> bytes:
            self.assertEqual(arguments[1], "version")
            return (
                b"gh version 2.96.0 (2026-07-02)\n"
                b"https://example.invalid/not-gh\n"
            )

        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "release URL"):
            CHECKER.check_attestation_verifier_version(
                Path("/private/pinned/gh"),
                "2.96.0",
                wrong_release_url,
            )

    def test_default_attestation_runner_has_clean_offline_environment(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["/private/pinned/gh", "version"],
            returncode=0,
            stdout=b"verified\n",
            stderr=b"",
        )
        with mock.patch.object(CHECKER.subprocess, "run", return_value=completed) as run:
            self.assertEqual(
                CHECKER.default_attestation_runner(["/private/pinned/gh", "version"]),
                b"verified\n",
            )
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(Path(kwargs["cwd"]).is_absolute())
        environment = kwargs["env"]
        self.assertEqual(environment["GH_PROMPT_DISABLED"], "1")
        self.assertEqual(environment["NO_COLOR"], "1")
        self.assertNotIn("GH_TOKEN", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertFalse(any(key.lower().endswith("_proxy") for key in environment))

    def test_default_release_verifier_runner_has_no_ambient_executable_path(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[sys.executable, "/private/dispatcher.py"],
            returncode=3,
            stdout=b"failed closed\n",
            stderr=b"",
        )
        with mock.patch.object(CHECKER.subprocess, "run", return_value=completed) as run:
            exit_code, stdout, output = CHECKER.default_release_verifier_runner(
                Path("/private/dispatcher.py"),
                "contract-schema-frozen",
                Path("/private/input-snapshot"),
            )
            self.assertEqual((exit_code, stdout, output), (3, b"failed closed\n", b""))
            kwargs = run.call_args.kwargs
            environment = kwargs["env"]
            self.assertEqual(
                set(environment),
                {
                    "HOME",
                    "LANG",
                    "LC_ALL",
                    "PATH",
                    "PYTHONDONTWRITEBYTECODE",
                    "PYTHONHASHSEED",
                    "TZ",
                },
            )
            self.assertNotIn("/usr/bin", environment["PATH"])
            self.assertNotIn("/bin", environment["PATH"])
            self.assertEqual(Path(environment["PATH"]).name, "empty-bin")
            command = run.call_args.args[0]
            self.assertEqual(command[1:3], ["-I", "-S"])
            self.assertIn("--input-snapshot", command)
            self.assertNotIn("--archive-root", command)

    def test_default_release_verifier_runner_rejects_a_symlink_output_swap(self) -> None:
        def create_symlink_output(
            command: list[str],
            **kwargs: object,
        ) -> subprocess.CompletedProcess[bytes]:
            del kwargs
            output_path = Path(command[command.index("--output") + 1])
            output_path.symlink_to("/dev/null")
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout=b"{}\n",
                stderr=b"",
            )

        with mock.patch.object(
            CHECKER.subprocess,
            "run",
            side_effect=create_symlink_output,
        ):
            with self.assertRaisesRegex(
                CHECKER.ReleaseContractError,
                "cannot securely open typed release verifier",
            ):
                CHECKER.default_release_verifier_runner(
                    Path("/private/dispatcher.py"),
                    "contract-schema-frozen",
                    Path("/private/input-snapshot"),
                )

    def test_trusted_git_runner_has_clean_noninteractive_environment(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["/usr/bin/git", "--version"],
            returncode=0,
            stdout=b"git version 2.55.0\n",
            stderr=b"",
        )
        with mock.patch.object(CHECKER.subprocess, "run", return_value=completed) as run:
            self.assertEqual(
                CHECKER.run_trusted_git(["--version"], CHECKER.ROOT, "test git"),
                b"git version 2.55.0\n",
            )
        command = run.call_args.args[0]
        kwargs = run.call_args.kwargs
        self.assertTrue(Path(command[0]).is_absolute())
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        environment = kwargs["env"]
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertFalse(any(key.lower().endswith("_proxy") for key in environment))

    def test_forged_receipts_cannot_bypass_actual_dispatcher_execution(self) -> None:
        bundle, index = self.external_bundle()
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "actual verifier exit code"):
            self.check_external_bundle(
                bundle,
                index,
                release_verifier_runner=CHECKER.default_release_verifier_runner,
            )

    def test_fabricated_complete_archive_cannot_bypass_real_attestation_cli(self) -> None:
        bundle, index = self.external_bundle()
        result = subprocess.run(
            [
                sys.executable,
                str(CHECKER_PATH),
                "--release-ready",
                "--archive-root",
                str(bundle),
                "--attestation-verifier-sha256",
                index["archive"]["attestation_verifier_sha256"],
                "--trusted-root-sha256",
                index["archive"]["trusted_root_sha256"],
            ],
            cwd=CHECKER.ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("release-ready=yes", result.stdout)

    def test_final_tag_must_equal_the_rc_admitted_commit(self) -> None:
        bundle, index = self.external_bundle()
        finalization_path = bundle / "finalization.json"
        finalization = CHECKER.load_json_bytes(finalization_path.read_bytes(), "test finalization")
        finalization["source_revision"] = "c" * 40
        self.write_json(finalization_path, finalization)
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "finalization source_revision"):
            self.check_external_bundle(bundle, index)

    def test_archive_rejects_unreferenced_files(self) -> None:
        bundle, index = self.external_bundle()
        (bundle / "unreferenced.txt").write_text("not admitted\n", encoding="utf-8")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "exact external archive file inventory"):
            self.check_external_bundle(bundle, index)

    def test_archive_rejects_noncanonical_path_aliases(self) -> None:
        bundle, index = self.external_bundle()
        original = index["evidence"][0]["evidence_path"]
        index["evidence"][0]["evidence_path"] = original.replace("evidence/", "evidence//", 1)
        self.rewrite_index_binding(bundle, index)
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "canonical and relative"):
            self.check_external_bundle(bundle, index)

    def test_archive_rejects_symlink_and_hardlink_payloads(self) -> None:
        bundle, index = self.external_bundle()
        source = bundle / index["evidence"][0]["evidence_path"]
        replacement = source.with_name(f"{source.stem}-symlink.json")
        replacement.symlink_to(source.name)
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "must be regular"):
            self.check_external_bundle(bundle, index)

        hardlink_root = self.root / "hardlink-reader"
        hardlink_root.mkdir()
        (hardlink_root / "source").write_bytes(b"same inode")
        (hardlink_root / "alias").hardlink_to(hardlink_root / "source")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "must not be hard-linked"):
            CHECKER.read_regular_file(hardlink_root, "alias", "hardlink payload")

    def test_archive_reader_rejects_a_fifo_without_blocking(self) -> None:
        root = self.root / "fifo-reader"
        root.mkdir()
        os.mkfifo(root / "payload")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "regular file"):
            CHECKER.read_regular_file(root, "payload", "FIFO payload")

    def test_json_duplicate_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "duplicate JSON key"):
            CHECKER.load_json_bytes(b'{"a":1,"a":2}', "duplicate test")

    def test_archive_reader_enforces_file_and_aggregate_bounds(self) -> None:
        root = self.root / "reader-bounds"
        root.mkdir()
        (root / "one").write_bytes(b"12")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "file bound"):
            CHECKER.read_regular_file(root, "one", "bounded file", max_bytes=1)
        original = CHECKER.MAX_ARCHIVE_AGGREGATE_BYTES
        CHECKER.MAX_ARCHIVE_AGGREGATE_BYTES = 1
        try:
            with self.assertRaisesRegex(CHECKER.ReleaseContractError, "aggregate read bound"):
                CHECKER.read_regular_file(
                    root,
                    "one",
                    "bounded aggregate",
                    budget=CHECKER.ArchiveReadBudget(),
                )
        finally:
            CHECKER.MAX_ARCHIVE_AGGREGATE_BYTES = original

    def test_product_root_registry_dependency_must_use_an_exact_pin(self) -> None:
        bundle, index = self.external_bundle()
        inventory_path = bundle / index["build_provenance"]["inventory_path"]
        inventory = CHECKER.load_json_bytes(inventory_path.read_bytes(), "test inventory")
        inventory["direct_dependencies"].append(
            {
                "root_package_id": inventory["product_roots"][0]["package_id"],
                "name": "serde",
                "requirement": "1.0",
                "source_kind": "registry",
            }
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "exact equals pins"):
            CHECKER.check_build_inventory(
                inventory,
                index["contract"],
                {
                    "cargo_lock_sha256": index["archive"]["cargo_lock_sha256"],
                    "rust_toolchain_sha256": index["archive"]["rust_toolchain_sha256"],
                    "release_build_base_image": CHECKER.load_contract()["host_compatibility"]
                    ["release_build_base_image"],
                    "runtime_inputs": next(
                        entry["runtime_inputs"]
                        for entry in index["verifier_registry"]["entries"]
                        if entry["readiness_id"]
                        == "supply-chain-license-and-artifact-locks"
                    ),
                },
            )

    def test_artifact_inventory_binds_executable_handshake_roles(self) -> None:
        bundle, index = self.external_bundle()
        inventory_path = bundle / index["build_provenance"]["artifact_inventory_path"]
        inventory = CHECKER.load_json_bytes(inventory_path.read_bytes(), "test artifact inventory")
        inventory["artifacts"][0]["handshake_roles"] = ["wrong-role"]
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "handshake_roles drifted"):
            CHECKER.check_artifact_inventory(
                CHECKER.load_contract(),
                inventory,
                index["contract"],
                bundle,
                CHECKER.ArchiveReadBudget(),
                self.trusted_attestation,
                bundle / index["archive"]["attestation_verifier_path"],
                bundle / index["archive"]["trusted_root_path"],
            )

    def test_artifact_inventory_rejects_substitute_nexus_revision(self) -> None:
        bundle, index = self.external_bundle()
        inventory_path = bundle / index["build_provenance"]["artifact_inventory_path"]
        inventory = CHECKER.load_json_bytes(inventory_path.read_bytes(), "test artifact inventory")
        nexus = next(
            entry
            for entry in inventory["artifacts"]
            if entry["id"] == "nexus-effect-peer-binary"
        )
        nexus["component_source_revision"] = "a" * 40
        with self.assertRaisesRegex(
            CHECKER.ReleaseContractError,
            "nexus-effect-peer-binary component source revision drifted",
        ):
            CHECKER.check_artifact_inventory(
                CHECKER.load_contract(),
                inventory,
                index["contract"],
                bundle,
                CHECKER.ArchiveReadBudget(),
                self.trusted_attestation,
                bundle / index["archive"]["attestation_verifier_path"],
                bundle / index["archive"]["trusted_root_path"],
            )

    def test_archive_root_without_release_ready_is_rejected(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), "--archive-root", "/tmp/archive"],
            cwd=CHECKER.ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("only valid with --release-ready", result.stderr)

    def test_unknown_dependency_constraint_key_is_rejected(self) -> None:
        old = '[release_dependency_constraints]\nclassification = "selected-target-constraints-not-complete-build-provenance"'
        path = self.mutated_contract(old, old + '\nunreviewed = "claim"')
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "release dependency constraints drifted"):
            CHECKER.validate(path)

    def test_unknown_wit_lock_key_is_rejected(self) -> None:
        old = '''id = "cooperative-handoff"
path = "wit/cooperative-handoff/world.wit"
package = "visa:continuity@0.1.0"
world = "cooperative-handoff"
sha256 = "709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920"'''
        path = self.mutated_contract(old, old + '\nunreviewed = "claim"')
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "WIT lock entry keys drifted"):
            CHECKER.validate(path)

    def test_unknown_contract_key_is_rejected(self) -> None:
        path = self.mutated_contract(
            'contract_revision = 5',
            'contract_revision = 5\nunreviewed_claim = "production-ready"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "unknown=.*unreviewed_claim"):
            CHECKER.validate(path)

    def test_duplicate_toml_key_is_rejected(self) -> None:
        path = self.mutated_contract(
            'product_name = "vISA"',
            'product_name = "vISA"\nproduct_name = "substituted"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "cannot parse"):
            CHECKER.validate(path)

    def test_symlink_contract_is_rejected(self) -> None:
        link = self.root / "contract-link.toml"
        link.symlink_to(CHECKER.DEFAULT_CONTRACT)
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "must be regular"):
            CHECKER.validate(link)


if __name__ == "__main__":
    unittest.main()
