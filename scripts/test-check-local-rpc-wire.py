#!/usr/bin/env python3
"""Negative tests for check-local-rpc-wire.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts/check-local-rpc-wire.py"
SPEC = importlib.util.spec_from_file_location("check_local_rpc_wire", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class LocalRpcWireCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = {
            family: path.read_text(encoding="utf-8")
            for family, path in CHECKER.FAMILY_MODULES.items()
        }

    def mutated(self, family: str, old: str, new: str) -> dict[str, str]:
        sources = dict(self.sources)
        self.assertIn(old, sources[family])
        sources[family] = sources[family].replace(old, new, 1)
        return sources

    def test_current_sources_pass(self) -> None:
        CHECKER.check_source_policy(self.sources)
        CHECKER.check_dependencies()
        CHECKER.check_repository_sources()

    def test_family_ids_cannot_be_conflated(self) -> None:
        sources = self.mutated(
            "ownership",
            'pub const FAMILY_ID: [u8; 16] = *b"visa-own-rpc-v1\\0";',
            'pub const FAMILY_ID: [u8; 16] = *b"visa-nex-rpc-v1\\0";',
        )
        with self.assertRaisesRegex(CHECKER.LocalRpcWireError, "family IDs"):
            CHECKER.check_source_policy(sources)

    def test_sibling_wire_import_is_rejected(self) -> None:
        sources = self.mutated(
            "agent_control",
            "use postcard_schema::Schema;",
            "use postcard_schema::Schema;\nuse crate::ownership::Request as OwnershipRequest;",
        )
        with self.assertRaisesRegex(CHECKER.LocalRpcWireError, "imports sibling"):
            CHECKER.check_source_policy(sources)

    def test_all_serde_shape_attributes_are_rejected_fail_closed(self) -> None:
        for attribute in (
            "default",
            "transparent",
            "untagged",
            'tag = "kind"',
            'content = "payload"',
            'from = "WireInput"',
            'try_from = "WireInput"',
            'into = "WireOutput"',
            'rename = "wire-name"',
        ):
            with self.subTest(attribute=attribute):
                sources = self.mutated(
                    "agent_control",
                    "pub struct StatusRequest {",
                    f"#[serde({attribute})]\npub struct StatusRequest {{",
                )
                with self.assertRaisesRegex(
                    CHECKER.LocalRpcWireError, "unsupported serde attribute"
                ):
                    CHECKER.check_source_policy(sources)

    def test_manual_trait_implementation_variants_are_rejected(self) -> None:
        for implementation in (
            "impl serde::ser::Serialize for StatusRequest {",
            "impl ::serde::Serialize for StatusRequest {",
            "impl SerdeAlias for StatusRequest {",
        ):
            with self.subTest(implementation=implementation):
                sources = self.mutated(
                    "agent_control",
                    "pub struct StatusRequest {",
                    f"{implementation}\n}}\npub struct StatusRequest {{",
                )
                with self.assertRaisesRegex(
                    CHECKER.LocalRpcWireError, "manual trait implementation"
                ):
                    CHECKER.check_source_policy(sources)

    def test_serde_import_alias_is_rejected(self) -> None:
        sources = self.mutated(
            "agent_control",
            "use serde::{Deserialize, Serialize};",
            "use serde::{Deserialize, Serialize as SerdeAlias};",
        )
        with self.assertRaisesRegex(CHECKER.LocalRpcWireError, "Serde surface"):
            CHECKER.check_source_policy(sources)

    def test_float_and_unordered_map_are_rejected(self) -> None:
        for token, label in (("f64", "f64"), ("HashMap", "HashMap")):
            with self.subTest(token=token):
                sources = self.mutated(
                    "agent_control",
                    "pub struct StatusRequest {",
                    f"pub struct StatusRequest {{\n    pub forbidden: {token},",
                )
                with self.assertRaisesRegex(CHECKER.LocalRpcWireError, label):
                    CHECKER.check_source_policy(sources)

    def test_platform_sized_wire_integers_are_rejected(self) -> None:
        for token in ("usize", "isize"):
            with self.subTest(token=token):
                sources = self.mutated(
                    "agent_control",
                    "pub struct StatusRequest {",
                    f"pub struct StatusRequest {{\n    pub forbidden: {token},",
                )
                with self.assertRaisesRegex(CHECKER.LocalRpcWireError, "usize/isize"):
                    CHECKER.check_source_policy(sources)

    def test_new_nested_wire_modules_are_discovered_and_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wire_root = root / CHECKER.WIRE_ROOT.relative_to(CHECKER.ROOT)
            shutil.copytree(CHECKER.WIRE_ROOT, wire_root)
            future = wire_root / "agent_control/future_wire.rs"
            future.parent.mkdir()
            future.write_text(
                "#[serde(transparent)]\npub struct FutureWire(pub u64);\n",
                encoding="utf-8",
            )

            discovered = CHECKER.discover_wire_modules(root)
            self.assertIn("agent_control/future_wire", discovered)
            with self.assertRaisesRegex(
                CHECKER.LocalRpcWireError,
                "agent_control/future_wire.*unsupported serde attribute",
            ):
                CHECKER.check_repository_sources(root)

    def test_exact_replay_path_cannot_disappear(self) -> None:
        sources = self.mutated(
            "ownership",
            "pub struct ReplayRecord",
            "struct ReplayRecord",
        )
        with self.assertRaisesRegex(CHECKER.LocalRpcWireError, "replay"):
            CHECKER.check_source_policy(sources)

    def test_paired_response_api_cannot_be_made_private(self) -> None:
        sources = self.mutated(
            "ownership",
            "pub fn decode_response_for",
            "fn decode_response_for",
        )
        with self.assertRaisesRegex(CHECKER.LocalRpcWireError, "paired response"):
            CHECKER.check_source_policy(sources)


if __name__ == "__main__":
    unittest.main()
