#!/usr/bin/env python3
"""Validate the frozen vISA 0.1 target and its separate release closure."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACT = ROOT / "specs/release/visa-0.1.toml"

EXPECTED_TOP_LEVEL_KEYS = {
    "schema",
    "contract_id",
    "contract_revision",
    "status",
    "product_name",
    "product_version",
    "compatibility_policy",
    "version_namespaces",
    "scope",
    "portable_contract",
    "joint_protocol",
    "cooperative_profile",
    "resource_profile",
    "crate_lock",
    "implementation_lock",
    "wit_lock",
    "golden_vector",
    "release_semantic_vector",
    "neutral_wire_v1",
    "historical_nexus_mapping_v1",
    "nexus_native_v1",
    "nexus_freeze_source_lock",
    "nexus_wire_artifact",
    "required_nexus_mapping_v2",
    "provider_spi",
    "public_surface",
    "support_policy",
    "admission",
    "readiness",
}

EXPECTED_VERSION_NAMESPACES = {
    "product": "product-semver-selects-the-supported-release-as-a-whole",
    "cargo_crate": "internal-packaging-version-not-product-or-wire-compatibility",
    "portable_contract": "contract-core-schema-version",
    "joint_protocol": "joint-handoff-protocol-version",
    "profile": "profile-and-extension-schema-version",
    "wit_package": "component-model-package-semver-with-exact-source-bytes",
    "neutral_wire": "visa-nexus-handoff-neutral-wire-version",
    "nexus_wire": "nexus-effect-peer-native-wire-version",
    "provider_spi": "in-tree-rust-source-contract-only",
    "rust_trait_abi": "not-defined",
}

EXPECTED_SCOPE = {
    "host_count": 1,
    "boot_scope": "same-boot",
    "operating_system": "linux",
    "architecture": "x86_64",
    "endianness": "little",
    "pointer_width_bits": 64,
    "source_destination_topology": "two-distinct-visa-agent-processes",
    "orchestrator_topology": "separate-visa-cli-or-controller-process",
    "effect_provider_topology": "separate-nexus-effect-peer-process",
    "stage3_worker_protocol": "visa-agent-local-v1",
    "stage3_worker_transport": "bounded-json-lines-lf-over-stdio",
    "cli_agent_transport": "filesystem-unix-domain-socket",
    "cli_agent_socket_mode": "0600",
    "cli_agent_peer_identity": "linux-so-peercred-same-uid",
    "effect_provider_transport": "bounded-json-lines-lf",
    "network_control_transport": False,
    "failure_model": "same-boot-crash-stop-retry-reorder-lost-ack",
    "host_reboot_supported": False,
}

EXPECTED_CRATES = [
    ("contract_core", "crates/core/contract_core/Cargo.toml", "0.3.0"),
    ("joint_handoff_core", "crates/core/joint_handoff_core/Cargo.toml", "0.1.0"),
    ("visa_profile", "crates/core/visa_profile/Cargo.toml", "0.2.0"),
    ("semantic_core", "crates/core/semantic_core/Cargo.toml", "0.2.0"),
    ("substrate_api", "crates/backend/substrate_api/Cargo.toml", "0.2.0"),
    ("substrate_host", "crates/backend/substrate_host/Cargo.toml", "0.1.0"),
    ("visa_runtime", "crates/runtime/visa_runtime/Cargo.toml", "0.2.0"),
    ("visa_joint_handoff", "crates/runtime/visa_joint_handoff/Cargo.toml", "0.1.0"),
    (
        "visa_component_adapter",
        "crates/runtime/visa_component_adapter/Cargo.toml",
        "0.1.0",
    ),
    ("visa_wasmtime", "crates/runtime/visa_wasmtime/Cargo.toml", "0.2.0"),
]

EXPECTED_WITS = [
    (
        "cooperative-handoff",
        "wit/cooperative-handoff/world.wit",
        "visa:continuity@0.1.0",
        "cooperative-handoff",
        "709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920",
    ),
    (
        "regular-file-continuity",
        "wit/regular-file-continuity/world.wit",
        "visa:file-continuity@0.1.0",
        "regular-file-continuity",
        "a54f016908fe65c233b2fe8bbc44b7c7e7cee73fcc32ecc1bacc2abdb5d6fd8e",
    ),
    (
        "logical-request-continuity",
        "wit/logical-request-continuity/world.wit",
        "visa:request-continuity@0.1.0",
        "logical-request-continuity",
        "c214e8f0ba8b395e49b25e1332de7c93d004597d8147b7b75664cba4175c8f93",
    ),
]

EXPECTED_GOLDEN_VECTORS = [
    (
        "portable-contract-schema-version-1.0",
        "contract_core::SchemaVersion",
        "crates/core/contract_core/tests/release_vectors.rs",
    ),
    (
        "joint-protocol-version-1.0",
        "joint_handoff_core::JointProtocolVersion",
        "crates/core/joint_handoff_core/tests/release_vectors.rs",
    ),
    (
        "cooperative-profile-version-1.0",
        "visa_profile::ProfileVersion",
        "crates/core/visa_profile/tests/release_vectors.rs",
    ),
]

EXPECTED_RELEASE_SEMANTIC_VECTORS = [
    (
        "command-begin-handoff-v1",
        "contract_core::Command",
        "010000000000000000000000000000000001080000000000000000000000000000000201",
        "b600058adce044aa8ca33557dd1df596ea78806406bea61e08d8c393b4339f56",
    ),
    (
        "event-handoff-started-v1",
        "contract_core::Event",
        "01000000000000000000000000000000000308",
        "ac12160b47c3d811e8c8bf970ab8b6d1406405d4922604b04e88519455c96de4",
    ),
    (
        "journal-handoff-started-v1",
        "contract_core::JournalEntry",
        "0100040505050505050505050505050505050505050505050505050505050505050505060606060606060606060606060606060606060606060606060606060606060601000000000000000000000000000000000308",
        "612039494c98c0ca61e732547101f1f09866d9e33b0b65acfd59332eb86c8405",
    ),
    (
        "snapshot-envelope-minimal-v1",
        "contract_core::SnapshotEnvelope",
        "0100010001000000000000000000000000000000000700000000000000000000000000000008090000000000000000000000000000000a020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000000000000000000000000000000c0000000000000000000000000000000d010e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0202aa550000000000000000000000000000001001000100000000000000000000000000000011010000000000000000000000000000001204000105000000000000000000000000000000130107010000000000000000000000000000001400000064f953e59559e19d0bd4822984b470d2ad2d6dad6e120f1eefb26f4939b35a7e",
        "001ef85c3a98b842f2e817e263985fa533847e254e65d62403919ea5ac235d2f",
    ),
]

EXPECTED_REQUIRED_CELLS = [
    "single-host-wasmtime-timer-kv",
    "single-host-wasmtime-bounded-regular-file",
    "single-host-wasmtime-bounded-logical-request",
    "single-host-wasmtime-nexus-joint-handoff",
]

EXPECTED_REQUIRED_IDS = [
    "contract-schema-frozen",
    "public-cli",
    "public-agent",
    "stage3-dual-process",
    "visa-nexus-adapter",
    "provider-enforced-fence",
    "release-semantic-golden-vectors",
    "nexus-freeze-local-source-lock",
    "nexus-wire-release-artifact",
    "neutral-nexus-mapping-v2",
    "compatibility-recovery-observability-supply-chain",
    "external-workload",
    "exact-tag-release-evidence",
]

EXPECTED_SATISFIED_IDS = ["contract-schema-frozen", "release-semantic-golden-vectors"]
EXPECTED_PENDING_IDS = [value for value in EXPECTED_REQUIRED_IDS if value not in EXPECTED_SATISFIED_IDS]


class ReleaseContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseContractError(message)


def require_exact_keys(mapping: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(mapping)
    require(
        actual == expected,
        f"{label} keys drifted: missing={sorted(expected - actual)} unknown={sorted(actual - expected)}",
    )


def require_exact_value(actual: Any, expected: Any, label: str) -> None:
    require(actual == expected, f"{label} drifted: expected={expected!r} actual={actual!r}")


def is_lower_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None


def read_regular_file(root: Path, relative: str, label: str) -> bytes:
    path = Path(relative)
    require(not path.is_absolute() and ".." not in path.parts, f"{label} path must stay relative")
    root = root.resolve()
    candidate = root / path
    cursor = root
    for part in path.parts:
        cursor = cursor / part
        try:
            mode = cursor.lstat().st_mode
        except OSError as error:
            raise ReleaseContractError(f"cannot stat {label} {relative}: {error}") from error
        require(not stat.S_ISLNK(mode), f"{label} path must not traverse a symlink: {relative}")
    try:
        mode = candidate.stat().st_mode
        data = candidate.read_bytes()
    except OSError as error:
        raise ReleaseContractError(f"cannot read {label} {relative}: {error}") from error
    require(stat.S_ISREG(mode), f"{label} must be a regular file: {relative}")
    return data


def load_toml_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseContractError(f"cannot parse {label}: {error}") from error
    require(isinstance(document, dict), f"{label} must contain a TOML mapping")
    return document


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        raise ReleaseContractError(f"cannot stat release contract {path}: {error}") from error
    require(stat.S_ISREG(mode) and not stat.S_ISLNK(mode), "release contract must be regular")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ReleaseContractError(f"cannot read release contract {path}: {error}") from error
    return load_toml_bytes(raw, str(path))


def source_text(root: Path, relative: str) -> str:
    raw = read_regular_file(root, relative, "source lock")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseContractError(f"source lock is not UTF-8: {relative}") from error


def require_source_pattern(root: Path, relative: str, pattern: str, label: str) -> None:
    matches = re.findall(pattern, source_text(root, relative), flags=re.MULTILINE)
    require(len(matches) == 1, f"{label} source definition drifted in {relative}")


def check_header(document: dict[str, Any]) -> None:
    require_exact_keys(document, EXPECTED_TOP_LEVEL_KEYS, "release contract")
    expected = {
        "schema": "visa.release-contract.v1",
        "contract_id": "visa-product-0.1",
        "contract_revision": 1,
        "status": "frozen-target-not-release-ready",
        "product_name": "vISA",
        "product_version": "0.1.0",
        "compatibility_policy": "exact-version-only",
    }
    for field, value in expected.items():
        require_exact_value(document.get(field), value, field)
    require_exact_value(document["version_namespaces"], EXPECTED_VERSION_NAMESPACES, "version namespaces")
    require_exact_value(document["scope"], EXPECTED_SCOPE, "single-host scope")


def check_core_namespaces(document: dict[str, Any], root: Path) -> None:
    require_exact_value(
        document["portable_contract"],
        {
            "crate": "contract_core",
            "crate_version": "0.3.0",
            "schema_major": 1,
            "schema_minor": 0,
            "canonical_encoding": "postcard-1.1.3",
            "digest_algorithm": "sha-256",
        },
        "portable contract",
    )
    require_exact_value(
        document["joint_protocol"],
        {
            "crate": "joint_handoff_core",
            "crate_version": "0.1.0",
            "protocol_major": 1,
            "protocol_minor": 0,
            "canonical_encoding": "postcard-1.1.3",
            "digest_algorithm": "sha-256",
        },
        "joint protocol",
    )
    require_exact_value(
        document["cooperative_profile"],
        {"crate": "visa_profile", "crate_version": "0.2.0", "profile_major": 1, "profile_minor": 0},
        "cooperative profile",
    )

    require_source_pattern(
        root,
        "crates/core/contract_core/src/lib.rs",
        r"^pub const CONTRACT_VERSION: SchemaVersion = SchemaVersion::new\(1, 0\);$",
        "portable contract version",
    )
    require_source_pattern(
        root,
        "crates/core/contract_core/src/codec.rs",
        r'^pub const CANONICAL_ENCODING: &str = "postcard-1\.1\.3";$',
        "portable canonical encoding",
    )
    require_source_pattern(
        root,
        "crates/core/contract_core/src/codec.rs",
        r'^pub const DIGEST_ALGORITHM: &str = "sha-256";$',
        "portable digest algorithm",
    )
    require_source_pattern(
        root,
        "crates/core/joint_handoff_core/src/types.rs",
        r"^pub const JOINT_PROTOCOL_VERSION: JointProtocolVersion = JointProtocolVersion::new\(1, 0\);$",
        "joint protocol version",
    )
    require_source_pattern(
        root,
        "crates/core/joint_handoff_core/src/codec.rs",
        r'^pub const JOINT_CANONICAL_ENCODING: &str = "postcard-1\.1\.3";$',
        "joint canonical encoding",
    )
    require_source_pattern(
        root,
        "crates/core/joint_handoff_core/src/codec.rs",
        r'^pub const JOINT_DIGEST_ALGORITHM: &str = "sha-256";$',
        "joint digest algorithm",
    )
    require_source_pattern(
        root,
        "crates/core/visa_profile/src/lib.rs",
        r"^pub const COOPERATIVE_HANDOFF_VERSION: ProfileVersion = ProfileVersion::new\(1, 0\);$",
        "cooperative profile version",
    )


def check_resource_profiles(document: dict[str, Any], root: Path) -> None:
    expected = [
        {
            "id": "timer-and-conditional-kv",
            "kind": "cooperative-profile-built-in",
            "version_source": "cooperative-profile-1.0",
            "release_disposition": "required",
        },
        {
            "id": "bounded-regular-file",
            "kind": "required-extension",
            "extension_identity_hex": "766973613a66696c653a763100000000",
            "extension_major": 1,
            "extension_minor": 0,
            "release_disposition": "required",
        },
        {
            "id": "bounded-logical-request",
            "kind": "required-extension",
            "extension_identity_hex": "766973613a7265713a76310000000000",
            "extension_major": 1,
            "extension_minor": 0,
            "release_disposition": "required",
        },
    ]
    require_exact_value(document["resource_profile"], expected, "resource profiles")
    require_source_pattern(
        root,
        "crates/core/visa_profile/src/regular_file.rs",
        r"^pub const REGULAR_FILE_EXTENSION_VERSION: SchemaVersion = SchemaVersion::new\(1, 0\);$",
        "regular-file extension version",
    )
    require_source_pattern(
        root,
        "crates/core/visa_profile/src/logical_request.rs",
        r"^pub const LOGICAL_REQUEST_EXTENSION_VERSION: SchemaVersion = SchemaVersion::new\(1, 0\);$",
        "logical-request extension version",
    )
    require_source_pattern(
        root,
        "crates/core/visa_profile/src/regular_file.rs",
        r'^pub const REGULAR_FILE_EXTENSION_ID: Identity = Identity::from_bytes\(\*b"visa:file:v1\\0\\0\\0\\0"\);$',
        "regular-file extension identity",
    )
    require_source_pattern(
        root,
        "crates/core/visa_profile/src/logical_request.rs",
        r'^pub const LOGICAL_REQUEST_EXTENSION_ID: Identity = Identity::from_bytes\(\*b"visa:req:v1\\0\\0\\0\\0\\0"\);$',
        "logical-request extension identity",
    )


def check_crates_and_dependencies(document: dict[str, Any], root: Path) -> None:
    entries = document["crate_lock"]
    require(isinstance(entries, list), "crate_lock must be an array")
    observed = [(entry.get("name"), entry.get("path"), entry.get("version")) for entry in entries]
    require_exact_value(observed, EXPECTED_CRATES, "crate version locks")
    for name, path, version in EXPECTED_CRATES:
        cargo = load_toml_bytes(read_regular_file(root, path, f"{name} manifest"), path)
        package = cargo.get("package")
        require(isinstance(package, dict), f"{path} must define [package]")
        require_exact_value(package.get("name"), name, f"{name} Cargo package name")
        require_exact_value(package.get("version"), version, f"{name} Cargo package version")

    implementation = document["implementation_lock"]
    require_exact_value(
        implementation,
        {
            "wasmtime": "43.0.2",
            "rusqlite": "0.40.1-bundled",
            "cargo_lock": "required-at-exact-release-tag",
            "rust_trait_abi": "not-promised",
        },
        "implementation lock",
    )
    workspace = load_toml_bytes(read_regular_file(root, "Cargo.toml", "workspace manifest"), "Cargo.toml")
    wasmtime = workspace.get("workspace", {}).get("dependencies", {}).get("wasmtime")
    require(isinstance(wasmtime, dict), "workspace wasmtime dependency must be a table")
    require_exact_value(wasmtime.get("version"), "43.0.2", "Wasmtime dependency")
    host = load_toml_bytes(
        read_regular_file(root, "crates/backend/substrate_host/Cargo.toml", "substrate_host manifest"),
        "crates/backend/substrate_host/Cargo.toml",
    )
    rusqlite = host.get("dependencies", {}).get("rusqlite")
    require(isinstance(rusqlite, dict), "substrate_host rusqlite dependency must be a table")
    require_exact_value(rusqlite.get("version"), "0.40.1", "rusqlite dependency")
    require("bundled" in rusqlite.get("features", []), "rusqlite must retain the bundled feature")
    for path in (
        "crates/core/contract_core/Cargo.toml",
        "crates/core/joint_handoff_core/Cargo.toml",
    ):
        cargo = load_toml_bytes(read_regular_file(root, path, "postcard manifest"), path)
        postcard = cargo.get("dependencies", {}).get("postcard")
        require(isinstance(postcard, dict), f"{path} postcard dependency must be a table")
        require_exact_value(postcard.get("version"), "=1.1.3", f"{path} Postcard version")

    lock = load_toml_bytes(read_regular_file(root, "Cargo.lock", "Cargo lock"), "Cargo.lock")
    packages = lock.get("package")
    require(isinstance(packages, list), "Cargo.lock package list is missing")
    versions_by_name: dict[str, set[str]] = {}
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if isinstance(name, str) and isinstance(version, str):
            versions_by_name.setdefault(name, set()).add(version)
    for name, version in (("wasmtime", "43.0.2"), ("rusqlite", "0.40.1"), ("postcard", "1.1.3")):
        require_exact_value(versions_by_name.get(name, set()), {version}, f"Cargo.lock {name} versions")


def check_wits(document: dict[str, Any], root: Path) -> None:
    entries = document["wit_lock"]
    require(isinstance(entries, list), "wit_lock must be an array")
    observed = [
        (entry.get("id"), entry.get("path"), entry.get("package"), entry.get("world"), entry.get("sha256"))
        for entry in entries
    ]
    require_exact_value(observed, EXPECTED_WITS, "WIT locks")
    for _, path, package, world, expected_sha in EXPECTED_WITS:
        raw = read_regular_file(root, path, "WIT source")
        require_exact_value(hashlib.sha256(raw).hexdigest(), expected_sha, f"{path} source SHA-256")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ReleaseContractError(f"{path} is not UTF-8") from error
        packages = re.findall(r"^package ([^;]+);$", text, flags=re.MULTILINE)
        worlds = re.findall(r"^world ([a-z0-9-]+) \{$", text, flags=re.MULTILINE)
        require_exact_value(packages, [package], f"{path} package ID")
        require(world in worlds, f"{path} does not define exact world {world}")


def check_golden_vectors(document: dict[str, Any], root: Path) -> None:
    entries = document["golden_vector"]
    require(isinstance(entries, list), "golden_vector must be an array")
    observed = [(entry.get("id"), entry.get("type"), entry.get("test_path")) for entry in entries]
    require_exact_value(observed, EXPECTED_GOLDEN_VECTORS, "golden-vector identities")
    for entry in entries:
        require_exact_keys(
            entry,
            {
                "id",
                "type",
                "test_path",
                "semantic_value",
                "canonical_encoding",
                "bytes_hex",
                "sha256",
            },
            f"golden vector {entry.get('id')}",
        )
        require_exact_value(entry["semantic_value"], "major=1,minor=0", f"{entry['id']} semantic value")
        require_exact_value(entry["canonical_encoding"], "postcard-1.1.3", f"{entry['id']} encoding")
        require_exact_value(entry["bytes_hex"], "0100", f"{entry['id']} canonical bytes")
        require(is_lower_hex(entry["sha256"], 64), f"{entry['id']} SHA-256 must be lowercase hex")
        raw = bytes.fromhex(entry["bytes_hex"])
        require_exact_value(
            hashlib.sha256(raw).hexdigest(), entry["sha256"], f"{entry['id']} SHA-256"
        )
        test_source = source_text(root, entry["test_path"])
        require(test_source.count(entry["id"]) == 1, f"{entry['id']} must occur once in its Rust test")
        require(
            test_source.count(f'"{entry["bytes_hex"]}"') == 1,
            f"{entry['id']} bytes must occur once in its Rust test",
        )


def check_release_semantic_vectors(document: dict[str, Any], root: Path) -> None:
    entries = document["release_semantic_vector"]
    require(isinstance(entries, list), "release_semantic_vector must be an array")
    observed = [
        (entry.get("id"), entry.get("type"), entry.get("bytes_hex"), entry.get("sha256"))
        for entry in entries
    ]
    require_exact_value(observed, EXPECTED_RELEASE_SEMANTIC_VECTORS, "release semantic vectors")
    test_path = "crates/core/contract_core/tests/release_vectors.rs"
    test_source = source_text(root, test_path)
    require("fn release_vectors_are_exact()" in test_source, "release-vector test entry drifted")
    for entry in entries:
        require_exact_keys(
            entry,
            {"id", "type", "test_path", "canonical_encoding", "bytes_hex", "sha256"},
            f"release vector {entry.get('id')}",
        )
        require_exact_value(entry["test_path"], test_path, f"{entry['id']} test path")
        require_exact_value(entry["canonical_encoding"], "postcard-1.1.3", f"{entry['id']} encoding")
        require(re.fullmatch(r"(?:[0-9a-f]{2})+", entry["bytes_hex"]) is not None, f"{entry['id']} bytes must be hex")
        require(is_lower_hex(entry["sha256"], 64), f"{entry['id']} SHA-256 must be lowercase hex")
        raw = bytes.fromhex(entry["bytes_hex"])
        require_exact_value(hashlib.sha256(raw).hexdigest(), entry["sha256"], f"{entry['id']} SHA-256")
        require(test_source.count(entry["id"]) == 1, f"{entry['id']} must occur once in its Rust test")
        quoted_bytes = f'"{entry["bytes_hex"]}"'
        quoted_digest = f'"{entry["sha256"]}"'
        require(
            test_source.count(quoted_bytes) == 1,
            f"{entry['id']} bytes must occur once in its Rust test",
        )
        require(
            test_source.count(quoted_digest) == 1,
            f"{entry['id']} digest must occur once in its Rust test",
        )


def check_neutral_and_nexus(document: dict[str, Any], root: Path) -> None:
    neutral = document["neutral_wire_v1"]
    expected_neutral = {
        "status": "frozen",
        "schema": "visa-nexus-handoff.wire-contract.v1",
        "protocol_major": 1,
        "protocol_minor": 0,
        "machine_path": "third_party/joint-handoff-qualification/wire-v1.toml",
        "machine_sha256": "29d9fff455b1697ef80959b22862668ca7e09c6bf077812362c265013daad040",
        "protocol_path": "third_party/joint-handoff-qualification/joint-handoff-wire-v1.md",
        "protocol_sha256": "9caf3d39eb9a198a3a085691944e6665d4c4298b164276bf3df3d70e7328cf2d",
    }
    require_exact_value(neutral, expected_neutral, "neutral wire v1")
    for path_field, digest_field in (("machine_path", "machine_sha256"), ("protocol_path", "protocol_sha256")):
        raw = read_regular_file(root, neutral[path_field], "neutral wire")
        require_exact_value(hashlib.sha256(raw).hexdigest(), neutral[digest_field], digest_field)
    wire = load_toml_bytes(
        read_regular_file(root, neutral["machine_path"], "neutral machine contract"),
        neutral["machine_path"],
    )
    require_exact_value(wire.get("schema"), neutral["schema"], "neutral machine schema")
    require_exact_value(wire.get("protocol_major"), 1, "neutral protocol major")
    require_exact_value(wire.get("protocol_minor"), 0, "neutral protocol minor")

    historical = document["historical_nexus_mapping_v1"]
    expected_historical = {
        "status": "earned-historical-evidence-not-release-adapter",
        "schema": "visa-nexus-handoff.nexus-native-v1-refinement.v1",
        "path": "third_party/joint-handoff-qualification/nexus-native-v1-refinement.toml",
        "sha256": "f054fa08d48b7eed8fef18c274a464f66443410e6698474ff721bfb1a6b5cbf5",
        "adapter_qualification": False,
    }
    require_exact_value(historical, expected_historical, "historical Nexus mapping v1")
    raw = read_regular_file(root, historical["path"], "historical Nexus mapping")
    require_exact_value(hashlib.sha256(raw).hexdigest(), historical["sha256"], "historical mapping SHA-256")
    mapping_v1 = load_toml_bytes(raw, historical["path"])
    require_exact_value(mapping_v1.get("schema"), historical["schema"], "historical mapping schema")
    require(mapping_v1.get("adapter_qualification") is False, "historical mapping must remain unqualified")

    nexus = document["nexus_native_v1"]
    expected_nexus = {
        "status": "frozen-upstream-contract",
        "release_api_status": "frozen-source-contract-not-nexus-v0.1.0-released-api",
        "implementation_id": "nexus-effect-peer",
        "repository": "https://github.com/chenty2333/Nexus",
        "freeze_source_revision": "cb773539401107efe7a7ad036b80ff40d8ec305c",
        "freeze_source_path": "status/effect-peer-native-v1.json",
        "freeze_source_sha256": "d9bec4547eb0d09a081033e619bb16179c36d992db2b754659594831e21737d2",
        "freeze_schema": "nexus.effect-peer.wire-freeze.v1",
        "freeze_contract_id": "nexus-effect-peer-native-v1",
        "protocol_major": 1,
        "transport": "bounded-json-lines-lf",
        "request_schema": "nexus.effect-peer.request.v1",
        "response_schema": "nexus.effect-peer.response.v1",
        "receipt_schema": "nexus.effect-peer.native-receipt.v1",
        "authentication_boundary": "sha256-integrity-only-not-authenticity",
        "canonical_snapshot_sha256": "036bfa21c9c1359755d9cf9a8223e39b7ea1d4793bf4fa948efbf75c9fa52b08",
    }
    require_exact_value(nexus, expected_nexus, "Nexus native-v1 freeze")
    require(is_lower_hex(nexus["freeze_source_revision"], 40), "Nexus freeze revision must be exact")
    require(is_lower_hex(nexus["freeze_source_sha256"], 64), "Nexus freeze source digest must be exact")
    require(is_lower_hex(nexus["canonical_snapshot_sha256"], 64), "Nexus snapshot digest must be exact")

    freeze_lock = document["nexus_freeze_source_lock"]
    require_exact_value(
        freeze_lock,
        {
            "status": "required-but-unsatisfied",
            "upstream_revision": nexus["freeze_source_revision"],
            "upstream_path": nexus["freeze_source_path"],
            "upstream_sha256": nexus["freeze_source_sha256"],
            "local_path": "",
            "local_sha256": "",
        },
        "Nexus freeze source lock",
    )

    artifact = document["nexus_wire_artifact"]
    require_exact_value(
        artifact,
        {
            "status": "required-but-unsatisfied",
            "kind": "lightweight-versioned-crate-or-release-artifact",
            "artifact_id": "",
            "source_revision": "",
            "sha256": "",
        },
        "Nexus wire release artifact",
    )

    mapping = document["required_nexus_mapping_v2"]
    require_exact_value(
        mapping,
        {
            "status": "required-but-unsatisfied",
            "upstream_candidate_status": "candidate-unqualified",
            "schema": "visa-nexus-handoff.nexus-effect-peer-native-v1-refinement.v2",
            "contract_id": "current-nexus-effect-peer-native-v1-to-neutral-wire-v1",
            "repository": "https://github.com/chenty2333/visa-nexus-handoff",
            "source_path": "specs/joint-handoff/nexus-effect-peer-native-v1-refinement-v2.toml",
            "freeze_source_lock_path": "specs/joint-handoff/nexus-effect-peer-native-v1-freeze.json",
            "neutral_wire_schema": "visa-nexus-handoff.wire-contract.v1",
            "nexus_freeze_contract_id": "nexus-effect-peer-native-v1",
            "nexus_canonical_snapshot_sha256": nexus["canonical_snapshot_sha256"],
            "source_revision": "",
            "source_sha256": "",
            "local_lock_path": "",
        },
        "required Nexus mapping v2",
    )


def check_provider_spi(document: dict[str, Any], root: Path) -> None:
    expected = {
        "status": "in-tree-preview-not-public-0.1-abi",
        "trait": "substrate_api::EffectClosureProvider",
        "protocol_major": 2,
        "protocol_minor": 0,
        "stability": "rust-source-preview",
        "provider_identity_in_trait": False,
        "release_adapter_identity": "exact-nexus-revision-plus-executable-sha256-plus-observed-child-executable",
        "required_capabilities": [
            "effect-admission",
            "outcome-recording",
            "effect-completion",
            "session-query",
            "freeze-thaw",
            "commit-close",
        ],
        "release_provider_revision": "",
        "release_provider_executable_sha256": "",
    }
    require_exact_value(document["provider_spi"], expected, "provider SPI")
    path = "crates/backend/substrate_api/src/effect_closure.rs"
    require_source_pattern(
        root,
        path,
        r"^pub const EFFECT_CLOSURE_PROVIDER_PROTOCOL_MAJOR: u16 = 2;$",
        "effect-closure provider major",
    )
    require_source_pattern(
        root,
        path,
        r"^pub const EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR: u16 = 0;$",
        "effect-closure provider minor",
    )
    require_source_pattern(root, path, r"^pub trait EffectClosureProvider: Send \+ Sync \{$", "provider trait")


def check_public_surface(document: dict[str, Any]) -> None:
    require_exact_value(
        document["public_surface"],
        [
            {
                "id": "visa-cli",
                "binary": "visa",
                "status": "required-but-unsatisfied",
                "frozen_boundary": "binary-name-and-role",
                "required_responsibilities": ["status", "run", "handoff", "reconcile", "verify-evidence"],
                "typed_outcomes": "required-but-unsatisfied",
                "exit_code_policy": "required-but-unsatisfied",
            },
            {
                "id": "visa-agent",
                "binary": "visa-agent",
                "status": "required-but-unsatisfied",
                "frozen_boundary": "binary-name-worker-role-and-control-transport",
                "required_responsibilities": [
                    "source-worker",
                    "destination-worker",
                    "visa-agent-local-v1-stdio-worker",
                    "same-uid-filesystem-uds-service",
                ],
                "typed_outcomes": "required-but-unsatisfied",
                "exit_code_policy": "required-but-unsatisfied",
            },
        ],
        "public CLI/agent surface",
    )


def check_support_and_admission(document: dict[str, Any]) -> None:
    support = document["support_policy"]
    require_exact_keys(
        support,
        {"required_release_cells", "currently_release_supported_cells", "reject_at_admission", "non_claims"},
        "support policy",
    )
    require_exact_value(support["required_release_cells"], EXPECTED_REQUIRED_CELLS, "required release cells")
    require_exact_value(support["currently_release_supported_cells"], [], "current release support")
    require_exact_value(
        support["reject_at_admission"],
        [
            "product-version-not-exactly-0.1.0",
            "unknown-or-mismatched-required-contract-profile-or-wit-version",
            "wit-source-byte-digest-mismatch",
            "component-or-profile-digest-mismatch",
            "provider-implementation-revision-or-executable-digest-mismatch",
            "neutral-wire-nexus-freeze-or-v2-mapping-mismatch",
            "non-linux-non-x86_64-cross-host-or-cross-boot-request",
            "raw-live-tcp-continuity",
            "effect-closure-provider-v2-preview-without-the-versioned-nexus-adapter",
        ],
        "admission rejection policy",
    )
    required_non_claims = {
        "cross-host-ownership-or-transport",
        "host-reboot-or-permanent-source-loss-recovery",
        "mtls-cryptographic-receipt-authenticity-freshness-or-anti-rollback",
        "byzantine-ownership-provider-or-host-safety",
        "real-nexus-ostd-irq-smp-or-retained-device-recovery",
        "tee-kms-attestation-or-confidential-continuity",
        "universal-exactly-once-effects",
        "arbitrary-open-file-descriptor-directory-device-or-raw-tcp-continuity",
        "wacogo-stage3-or-wacogo-product-support",
        "rust-trait-binary-abi-or-unified-crate-semver",
        "oci-wkg-publication-bit-reproducible-build-or-slsa-level",
        "production-slo-security-hardening-performance-or-general-market-readiness",
    }
    non_claims = support["non_claims"]
    require(isinstance(non_claims, list) and len(non_claims) == len(set(non_claims)), "non-claims must be unique")
    require_exact_value(set(non_claims), required_non_claims, "release non-claims")

    admission = document["admission"]
    require_exact_value(admission.get("schema_check"), "python3 scripts/check-release-contract.py", "schema command")
    require_exact_value(
        admission.get("release_ready_check"),
        "python3 scripts/check-release-contract.py --release-ready",
        "release-ready command",
    )
    require_exact_value(
        admission.get("fail_closed_dimensions"),
        [
            "product-version",
            "crate-versions",
            "contract-joint-profile-and-resource-versions",
            "postcard-golden-vectors",
            "wit-package-ids-worlds-and-source-bytes",
            "neutral-wire-bytes",
            "nexus-freeze-contract-and-canonical-snapshot",
            "nexus-freeze-local-source-lock",
            "nexus-provider-identity",
            "neutral-to-current-nexus-mapping-v2",
            "release-readiness-closure",
        ],
        "fail-closed release dimensions",
    )


def check_readiness(document: dict[str, Any]) -> list[str]:
    readiness = document["readiness"]
    require_exact_keys(readiness, {"release_ready", "required_ids", "satisfied_ids", "pending_ids"}, "readiness")
    required = readiness["required_ids"]
    satisfied = readiness["satisfied_ids"]
    pending = readiness["pending_ids"]
    for label, values in (("required", required), ("satisfied", satisfied), ("pending", pending)):
        require(isinstance(values, list), f"{label} readiness IDs must be a list")
        require(len(values) == len(set(values)), f"{label} readiness IDs must be unique")
    require_exact_value(required, EXPECTED_REQUIRED_IDS, "required release closure IDs")
    require(set(satisfied).isdisjoint(pending), "satisfied and pending release IDs must be disjoint")
    require(set(satisfied) | set(pending) == set(required), "readiness IDs must partition required IDs")
    require_exact_value(satisfied, EXPECTED_SATISFIED_IDS, "satisfied release closure")
    require_exact_value(pending, EXPECTED_PENDING_IDS, "pending release closure")
    require(readiness["release_ready"] is False, "current contract must not claim release readiness")
    return pending


def validate(contract_path: Path = DEFAULT_CONTRACT, root: Path = ROOT) -> list[str]:
    document = load_contract(contract_path)
    check_header(document)
    check_core_namespaces(document, root)
    check_resource_profiles(document, root)
    check_crates_and_dependencies(document, root)
    check_wits(document, root)
    check_golden_vectors(document, root)
    check_release_semantic_vectors(document, root)
    check_neutral_and_nexus(document, root)
    check_provider_spi(document, root)
    check_public_surface(document)
    check_support_and_admission(document)
    return check_readiness(document)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument(
        "--release-ready",
        action="store_true",
        help="also require every product-release closure item to be satisfied",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        pending = validate(arguments.contract)
        if arguments.release_ready:
            require(not pending, "release closure is incomplete: " + ", ".join(pending))
    except (ReleaseContractError, OSError) as error:
        print(f"vISA 0.1 release contract violation: {error}", file=sys.stderr)
        return 1
    if pending:
        print(f"vISA 0.1 target contract passed; release-ready=no pending={len(pending)}")
    else:
        print("vISA 0.1 release contract passed; release-ready=yes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
