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

    def test_current_contract_is_schema_valid_but_not_release_ready(self) -> None:
        pending = CHECKER.validate()
        self.assertEqual(pending, CHECKER.EXPECTED_PENDING_IDS)

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
        self.assertIn("release closure is incomplete", result.stderr)
        self.assertIn("nexus-wire-release-artifact", result.stderr)

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

    def test_crate_version_lock_drift_is_rejected(self) -> None:
        path = self.mutated_contract(
            'name = "contract_core"\npath = "crates/core/contract_core/Cargo.toml"\nversion = "0.3.0"',
            'name = "contract_core"\npath = "crates/core/contract_core/Cargo.toml"\nversion = "0.1.0"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "crate version locks drifted"):
            CHECKER.validate(path)

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
test_path = "crates/core/contract_core/tests/release_vectors.rs"
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
            'release_api_status = "frozen-source-contract-not-nexus-v0.1.0-released-api"',
            'release_api_status = "nexus-v0.1.0-released-api"',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "Nexus native-v1 freeze drifted"):
            CHECKER.validate(path)

    def test_provider_identity_requirement_drift_is_rejected(self) -> None:
        path = self.mutated_contract(
            'release_adapter_identity = "exact-nexus-revision-plus-executable-sha256-plus-observed-child-executable"',
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

    def test_release_ready_boolean_alone_cannot_close_pending_work(self) -> None:
        path = self.mutated_contract("release_ready = false", "release_ready = true")
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "must not claim release readiness"):
            CHECKER.validate(path)

    def test_supported_cells_cannot_be_claimed_before_closure(self) -> None:
        path = self.mutated_contract(
            "currently_release_supported_cells = []",
            'currently_release_supported_cells = ["single-host-wasmtime-timer-kv"]',
        )
        with self.assertRaisesRegex(CHECKER.ReleaseContractError, "current release support drifted"):
            CHECKER.validate(path)

    def test_unknown_contract_key_is_rejected(self) -> None:
        path = self.mutated_contract(
            'contract_revision = 1',
            'contract_revision = 1\nunreviewed_claim = "production-ready"',
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
