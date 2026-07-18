#!/usr/bin/env python3
"""Self-tests for the frozen vISA 0.1 release-contract checker."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


CHECKER_PATH = Path(__file__).with_name("check-release-contract.py")
SPEC = importlib.util.spec_from_file_location("visa_release_contract_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release-contract checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


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

    def external_bundle(self) -> tuple[Path, Path, Path, dict]:
        repository = self.root / "tagged-repository"
        contract_path = repository / "specs/release/visa-0.1.toml"
        contract_path.parent.mkdir(parents=True)
        contract_bytes = self.raw.encode()
        contract_path.write_bytes(contract_bytes)
        for relative in ("Cargo.lock", "rust-toolchain.toml"):
            destination = repository / relative
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
        subprocess.run(["git", "tag", source_tag], cwd=repository, check=True)

        target_sha = CHECKER.hashlib.sha256(contract_bytes).hexdigest()
        cargo_sha = CHECKER.hashlib.sha256((repository / "Cargo.lock").read_bytes()).hexdigest()
        toolchain_sha = CHECKER.hashlib.sha256(
            (repository / "rust-toolchain.toml").read_bytes()
        ).hexdigest()
        bundle = self.root / "external-bundle"
        inventory_path = "build/workspace-package-inventory.json"
        package = {
            "name": "visa-release-test",
            "version": "0.1.0",
            "source": "workspace:Cargo.toml",
            "license": "Apache-2.0",
        }
        inventory = {
            "schema": "visa.release-build-inventory.v1",
            "target_sha256": target_sha,
            "source_revision": revision,
            "source_tag": source_tag,
            "cargo_lock_sha256": cargo_sha,
            "rust_toolchain_sha256": toolchain_sha,
            "workspace_package_count": 1,
            "resolved_package_count": 1,
            "workspace_packages": [package],
            "resolved_packages": [package],
        }
        inventory_bytes = self.write_json(bundle / inventory_path, inventory)
        inventory_sha = CHECKER.hashlib.sha256(inventory_bytes).hexdigest()
        evidence_entries = []
        for readiness_id in CHECKER.EXPECTED_REQUIRED_IDS:
            if readiness_id == "supply-chain-license-and-artifact-locks":
                evidence_path = inventory_path
                evidence_sha = inventory_sha
            else:
                evidence_path = f"evidence/{readiness_id}.json"
                evidence_bytes = self.write_json(
                    bundle / evidence_path,
                    {"readiness_id": readiness_id, "result": "passed"},
                )
                evidence_sha = CHECKER.hashlib.sha256(evidence_bytes).hexdigest()
            receipt_path = f"receipts/{readiness_id}.json"
            inputs = {
                "specs/release/visa-0.1.toml": target_sha,
                evidence_path: evidence_sha,
            }
            if readiness_id == "supply-chain-license-and-artifact-locks":
                inputs["Cargo.lock"] = cargo_sha
                inputs["rust-toolchain.toml"] = toolchain_sha
            receipt = {
                "schema": "visa.release-readiness-verifier-receipt.v1",
                "readiness_id": readiness_id,
                "target_path": "specs/release/visa-0.1.toml",
                "target_sha256": target_sha,
                "source_revision": revision,
                "source_tag": source_tag,
                "verifier_command": f"verify-release-id {readiness_id}",
                "result": "passed",
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
        index = {
            "schema": "visa.release-readiness-index.v1",
            "contract": {
                "contract_id": "visa-product-0.1",
                "target_path": "specs/release/visa-0.1.toml",
                "target_sha256": target_sha,
                "source_revision": revision,
                "source_tag": source_tag,
                "final_tag": "v0.1.0",
            },
            "required_ids": CHECKER.EXPECTED_REQUIRED_IDS,
            "build_provenance": {
                "cargo_lock_path": "Cargo.lock",
                "cargo_lock_sha256": cargo_sha,
                "rust_toolchain_path": "rust-toolchain.toml",
                "rust_toolchain_sha256": toolchain_sha,
                "inventory_path": inventory_path,
                "inventory_sha256": inventory_sha,
            },
            "evidence": evidence_entries,
        }
        index_path = bundle / "index.json"
        self.write_json(index_path, index)
        return repository, contract_path, index_path, index

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

    def test_release_ready_mode_fails_closed_on_pending_items(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), "--release-ready"],
            cwd=CHECKER.ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("--release-ready requires --evidence-index PATH", result.stderr)

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

    def test_six_process_inventory_is_exact(self) -> None:
        path = self.mutated_contract(
            "maximum_active_processes = 6\nsource_destination_topology",
            "maximum_active_processes = 7\nsource_destination_topology",
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "single-host scope drifted"):
            CHECKER.validate(path)

    def test_local_rpc_frame_limit_cannot_reuse_the_test_worker_limit(self) -> None:
        path = self.mutated_contract(
            "max_frame_bytes_including_header = 1048576",
            "max_frame_bytes_including_header = 16777216",
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "local RPC defaults drifted"):
            CHECKER.validate(path)

    def test_local_rpc_frame_measurement_is_frozen(self) -> None:
        path = self.mutated_contract(
            "measured_existing_jsonl_max_bytes = 53663",
            "measured_existing_jsonl_max_bytes = 53664",
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "local RPC defaults drifted"):
            CHECKER.validate(path)

    def test_local_rpc_namespaces_cannot_be_conflated(self) -> None:
        path = self.mutated_contract(
            'schema = "visa.ownership.local.v1"',
            'schema = "visa.agent.control.v1"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "agent-ownership RPC v1 drifted"):
            CHECKER.validate(path)

    def test_local_rpc_header_and_payload_bounds_are_exact(self) -> None:
        path = self.mutated_contract("max_payload_bytes = 1048556", "max_payload_bytes = 1048557")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "local RPC defaults drifted"):
            CHECKER.validate(path)

    def test_local_rpc_magic_values_cannot_be_conflated(self) -> None:
        path = self.mutated_contract('magic = "VISAOWN1"', 'magic = "VISACTL1"')
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "agent-ownership RPC v1 drifted"):
            CHECKER.validate(path)

    def test_local_rpc_canonical_decode_cannot_accept_trailing_bytes(self) -> None:
        path = self.mutated_contract(
            'canonical_decode_policy = "reject-trailing-bytes-and-require-byte-identical-reencode"',
            'canonical_decode_policy = "accept-trailing-bytes"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "local RPC defaults drifted"):
            CHECKER.validate(path)

    def test_nexus_child_transport_remains_native_v1_jsonl(self) -> None:
        path = self.mutated_contract(
            'effect_provider_transport = "bounded-json-lines-lf"',
            'effect_provider_transport = "visa.local-uds-postcard.v1"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "single-host scope drifted"):
            CHECKER.validate(path)

    def test_same_uid_boundary_cannot_be_promoted_to_tenant_authentication(self) -> None:
        path = self.mutated_contract(
            'security_boundary = "local-tcb-admission-and-integrity-not-malicious-same-uid-authentication-or-tenant-isolation"',
            'security_boundary = "malicious-same-uid-authentication-and-tenant-isolation"',
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
            'wasmtime_release_choice = "43.0.2"',
            'wasmtime_release_choice = "44.0.0"',
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

    def test_release_ready_field_cannot_be_written_into_immutable_target(self) -> None:
        path = self.mutated_contract(
            'contract_revision = 4',
            'contract_revision = 4\nrelease_ready = true',
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
        repository, contract_path, index_path, _ = self.external_bundle()
        document = CHECKER.load_contract(contract_path)
        revision = CHECKER.check_external_release_index(
            document, contract_path, index_path, repository
        )
        self.assertRegex(revision, r"^[0-9a-f]{40}$")
        self.assertNotIn("satisfied_ids", document["release_closure"])

    def test_external_release_index_missing_id_fails_closed(self) -> None:
        repository, contract_path, index_path, index = self.external_bundle()
        index["evidence"].pop()
        self.write_json(index_path, index)
        document = CHECKER.load_contract(contract_path)
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "external evidence coverage"):
            CHECKER.check_external_release_index(document, contract_path, index_path, repository)

    def test_external_release_index_must_bind_exact_rc_tag_revision(self) -> None:
        repository, contract_path, index_path, index = self.external_bundle()
        index["contract"]["source_revision"] = "a" * 40
        self.write_json(index_path, index)
        document = CHECKER.load_contract(contract_path)
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "tag revision drifted"):
            CHECKER.check_external_release_index(document, contract_path, index_path, repository)

    def test_external_build_inventory_requires_package_license(self) -> None:
        _, _, index_path, index = self.external_bundle()
        inventory_path = index_path.parent / index["build_provenance"]["inventory_path"]
        inventory = CHECKER.load_json_bytes(inventory_path.read_bytes(), "test inventory")
        inventory["workspace_packages"][0]["license"] = ""
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "non-empty strings"):
            CHECKER.check_build_inventory(
                inventory,
                index["contract"],
                index["build_provenance"],
            )

    def test_evidence_index_without_release_ready_is_rejected(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER_PATH), "--evidence-index", "/tmp/index.json"],
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
            'contract_revision = 4',
            'contract_revision = 4\nunreviewed_claim = "production-ready"',
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
