#!/usr/bin/env python3
"""Validate the frozen vISA 0.1 target and its separate release closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACT = ROOT / "specs/release/visa-0.1.toml"
DEFAULT_READINESS_LEDGER = ROOT / "specs/release/visa-0.1-readiness.toml"


class PrivateTemporaryDirectory:
    """Small silent-cleanup owner for private executable/input copies."""

    def __init__(self, prefix: str) -> None:
        self.name = tempfile.mkdtemp(prefix=prefix)

    def cleanup(self) -> None:
        if self.name:
            shutil.rmtree(self.name, ignore_errors=True)
            self.name = ""

    def __del__(self) -> None:
        self.cleanup()

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
    "host_compatibility",
    "process_topology",
    "supervision",
    "same_boot_cohort",
    "agent_incarnation",
    "local_rpc_defaults",
    "cli_agent_rpc_v1",
    "agent_ownership_rpc_v1",
    "agent_nexus_rpc_v1",
    "ownership_service",
    "portable_contract",
    "joint_protocol",
    "cooperative_profile",
    "resource_profile",
    "release_dependency_constraints",
    "supply_chain_tool_selection",
    "wit_lock",
    "golden_vector",
    "release_semantic_vector",
    "required_owned_schema_artifact",
    "release_semantic_corpus",
    "neutral_wire_v1",
    "historical_nexus_mapping_v1",
    "nexus_native_v1",
    "nexus_freeze_source_lock",
    "nexus_wire_artifact",
    "required_nexus_mapping_v2",
    "provider_spi",
    "provider_dispatch_fence",
    "public_surface",
    "release_artifact",
    "support_policy",
    "failure_matrix",
    "admission",
    "evidence_policy",
    "release_closure",
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
    "local_rpc": "independent-versioned-schema-per-local-process-boundary",
    "rust_trait_abi": "not-defined",
}

EXPECTED_SCOPE = {
    "host_count": 1,
    "boot_scope": "same-boot-and-active-systemd-user-manager-lifetime",
    "operating_system": "linux",
    "architecture": "x86_64",
    "endianness": "little",
    "pointer_width_bits": 64,
    "maximum_active_processes": 6,
    "maximum_resident_product_processes": 5,
    "process_count_scope": (
        "at-most-five-resident-admitted-product-roles-plus-one-exclusive-lease-holding-"
        "mutating-visa-cli-controller"
    ),
    "process_count_enforcement": (
        "role-admission-contract-not-kernel-global-process-limit-extra-unadmitted-binaries-"
        "have-no-mutation-or-controller-role"
    ),
    "readonly_cli_concurrency": (
        "status-and-verify-evidence-may-run-concurrently-without-controller-role-or-mutation-"
        "lease"
    ),
    "source_destination_topology": "two-long-lived-visa-agent-processes",
    "agent_execution_model": "in-process-wasmtime-local-provider-profile-sink-and-durable-projection",
    "orchestrator_topology": "one-short-lived-visa-cli-controller-process",
    "ownership_service_topology": "one-independent-visa-ownershipd-process",
    "nexus_adapter_topology": "one-independent-visa-nexusd-process",
    "effect_provider_topology": "one-nexus-effect-peer-child-of-visa-nexusd",
    "controller_child_processes": "no-product-role-child-cli-uses-direct-user-dbus",
    "agent_child_processes": "none",
    "local_control_transport": (
        "three-independent-versioned-user-bus-dbus-interfaces-via-zbus-with-canonical-"
        "postcard-ay-payloads"
    ),
    "effect_provider_transport": "bounded-json-lines-lf",
    "network_control_transport": False,
    "failure_model": (
        "same-user-manager-lifetime-within-one-boot-crash-stop-retry-reorder-lost-ack"
    ),
    "host_reboot_supported": False,
    "boot_identity_source": "/proc/sys/kernel/random/boot_id",
}

MAX_ARCHIVE_FILE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_AGGREGATE_BYTES = 4 * 1024 * 1024 * 1024
MAX_VERIFIER_RECEIPT_BYTES = 1024 * 1024
MAX_OCI_LAYOUT_FILES = 4096

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
    "single-host-six-process-role-inventory",
    "single-host-agent-and-ownershipd-crash-reconnect",
    "single-host-provider-dispatch-fence-at-real-profile-sinks",
]

EXPECTED_REQUIRED_IDS = [
    "contract-schema-frozen",
    "process-topology-frozen",
    "public-cli",
    "public-agent",
    "public-ownership-service",
    "public-nexus-adapter-service",
    "cli-agent-rpc-v1",
    "agent-ownership-rpc-v1",
    "agent-nexus-rpc-v1",
    "ownership-single-writer-restart-replay",
    "stage3-dual-process",
    "visa-nexus-adapter",
    "provider-enforced-fence",
    "release-semantic-golden-corpus",
    "nexus-freeze-local-source-lock",
    "nexus-native-v1-wire-artifact",
    "neutral-nexus-mapping-v2",
    "compatibility-matrix",
    "crash-recovery-and-replay",
    "observability-and-evidence",
    "supply-chain-license-and-artifact-locks",
    "external-workload",
    "exact-tag-release-evidence",
]

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


def canonical_relative_path(relative: Any, label: str) -> str:
    require(isinstance(relative, str) and bool(relative), f"{label} path must be non-empty")
    require("\\" not in relative and "\x00" not in relative, f"{label} path is not canonical POSIX")
    path = PurePosixPath(relative)
    require(
        not path.is_absolute()
        and path.as_posix() == relative
        and all(part not in ("", ".", "..") for part in path.parts),
        f"{label} path must be canonical and relative: {relative!r}",
    )
    return relative


class ArchiveReadBudget:
    def __init__(self) -> None:
        self.total = 0
        self.paths: dict[str, tuple[int, int]] = {}
        self.inodes: dict[tuple[int, int], str] = {}

    def account(self, relative: str, file_stat: os.stat_result, label: str) -> None:
        identity = (file_stat.st_dev, file_stat.st_ino)
        prior_identity = self.paths.get(relative)
        if prior_identity is not None:
            require(prior_identity == identity, f"{label} path changed during verification: {relative}")
            return
        prior_path = self.inodes.get(identity)
        require(prior_path is None, f"{label} aliases archive path {prior_path}: {relative}")
        self.paths[relative] = identity
        self.inodes[identity] = relative
        self.total += file_stat.st_size
        require(
            self.total <= MAX_ARCHIVE_AGGREGATE_BYTES,
            "external archive exceeds the aggregate read bound",
        )


def maybe_open_regular_file_at(
    root: Path,
    relative: str,
    label: str,
) -> tuple[int, os.stat_result] | None:
    canonical_relative_path(relative, label)
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise ReleaseContractError(f"cannot stat {label} root {root}: {error}") from error
    require(
        stat.S_ISDIR(root_stat.st_mode) and not stat.S_ISLNK(root_stat.st_mode),
        f"{label} root must be a real directory",
    )
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory_flags = flags | os.O_DIRECTORY
    descriptors: list[int] = []
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        parts = relative.split("/")
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        try:
            file_descriptor = os.open(parts[-1], flags, dir_fd=current)
        except FileNotFoundError:
            return None
        file_stat = os.fstat(file_descriptor)
    except OSError as error:
        raise ReleaseContractError(f"cannot securely open {label} {relative}: {error}") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    require(stat.S_ISREG(file_stat.st_mode), f"{label} must be a regular file: {relative}")
    require(file_stat.st_nlink == 1, f"{label} must not be hard-linked: {relative}")
    return file_descriptor, file_stat


def open_regular_file_at(root: Path, relative: str, label: str) -> tuple[int, os.stat_result]:
    opened = maybe_open_regular_file_at(root, relative, label)
    require(opened is not None, f"{label} does not exist: {relative}")
    return opened


def read_open_file(
    file_descriptor: int,
    file_stat: os.stat_result,
    relative: str,
    label: str,
    max_bytes: int,
) -> bytes:
    require(file_stat.st_size <= max_bytes, f"{label} exceeds the {max_bytes}-byte file bound: {relative}")
    chunks: list[bytes] = []
    remaining = file_stat.st_size
    try:
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 1024 * 1024))
            require(bool(chunk), f"{label} changed while reading: {relative}")
            chunks.append(chunk)
            remaining -= len(chunk)
        require(not os.read(file_descriptor, 1), f"{label} grew while reading: {relative}")
        after = os.fstat(file_descriptor)
        require(
            (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            == (file_stat.st_dev, file_stat.st_ino, file_stat.st_mode, file_stat.st_nlink, file_stat.st_size, file_stat.st_mtime_ns, file_stat.st_ctime_ns),
            f"{label} metadata changed while reading: {relative}",
        )
    except OSError as error:
        raise ReleaseContractError(f"cannot securely read {label} {relative}: {error}") from error
    finally:
        os.close(file_descriptor)
    return b"".join(chunks)


def read_regular_file(
    root: Path,
    relative: str,
    label: str,
    *,
    budget: ArchiveReadBudget | None = None,
    max_bytes: int = MAX_ARCHIVE_FILE_BYTES,
) -> bytes:
    file_descriptor, file_stat = open_regular_file_at(root, relative, label)
    if budget is not None:
        budget.account(relative, file_stat, label)
    return read_open_file(file_descriptor, file_stat, relative, label, max_bytes)


def read_optional_regular_file(
    root: Path,
    relative: str,
    label: str,
    *,
    max_bytes: int = MAX_ARCHIVE_FILE_BYTES,
) -> bytes | None:
    opened = maybe_open_regular_file_at(root, relative, label)
    if opened is None:
        return None
    file_descriptor, file_stat = opened
    return read_open_file(file_descriptor, file_stat, relative, label, max_bytes)


def hash_regular_file(
    root: Path,
    relative: str,
    label: str,
    *,
    budget: ArchiveReadBudget | None = None,
) -> str:
    file_descriptor, file_stat = open_regular_file_at(root, relative, label)
    require(file_stat.st_size <= MAX_ARCHIVE_FILE_BYTES, f"{label} exceeds the file bound: {relative}")
    if budget is not None:
        budget.account(relative, file_stat, label)
    digest = hashlib.sha256()
    remaining = file_stat.st_size
    try:
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 1024 * 1024))
            require(bool(chunk), f"{label} changed while hashing: {relative}")
            digest.update(chunk)
            remaining -= len(chunk)
        require(not os.read(file_descriptor, 1), f"{label} grew while hashing: {relative}")
        after = os.fstat(file_descriptor)
        require(
            (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            == (file_stat.st_dev, file_stat.st_ino, file_stat.st_mode, file_stat.st_nlink, file_stat.st_size, file_stat.st_mtime_ns, file_stat.st_ctime_ns),
            f"{label} metadata changed while hashing: {relative}",
        )
    except OSError as error:
        raise ReleaseContractError(f"cannot securely hash {label} {relative}: {error}") from error
    finally:
        os.close(file_descriptor)
    return digest.hexdigest()


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
        "contract_revision": 5,
        "status": "immutable-release-target",
        "product_name": "vISA",
        "product_version": "0.1.0",
        "compatibility_policy": "exact-version-only",
    }
    for field, value in expected.items():
        require_exact_value(document.get(field), value, field)
    require_exact_value(document["version_namespaces"], EXPECTED_VERSION_NAMESPACES, "version namespaces")
    require_exact_value(document["scope"], EXPECTED_SCOPE, "single-host scope")


def check_host_compatibility(document: dict[str, Any]) -> None:
    require_exact_value(
        document["host_compatibility"],
        {
            "release_target": "x86_64-unknown-linux-gnu",
            "release_build_base_image": (
                "docker.io/library/debian@sha256:"
                "63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e"
            ),
            "release_build_base_platform": (
                "linux-amd64-debian-12-bookworm-slim-glibc-2.36"
            ),
            "release_build_toolchain": (
                "nightly-2026-06-07-rustc-1.98.0-nightly-"
                "61d7280f3c4c63fa24c56bdaa9a446151b5a30dc-llvm-22.1.6"
            ),
            "release_build_recipe_path": "packaging/release/Containerfile",
            "release_build_context_path": ".",
            "derived_build_image_policy": (
                "exact-oci-manifest-digest-and-exported-layout-in-release-build-inventory-"
                "no-floating-tag-or-network-resolution"
            ),
            "supported_runtime_baseline": (
                "ubuntu-24.04-lts-amd64-glibc-2.39-systemd-255-linux-6.8"
            ),
            "minimum_systemd_version": 254,
            "required_systemd_features": [
                "user-manager",
                "user-session-bus",
                "ListUnitsByNames",
                "StateDirectory-XDG_STATE_HOME",
                "Type-notify",
                "user-DBus-Manager",
            ],
            "systemd_admission": (
                "feature-probe-manager-methods-effective-state-directory-user-bus-and-notify-"
                "behavior-version-string-alone-insufficient"
            ),
            "user_bus_process_identity_admission": (
                "feature-probe-getconnectioncredentials-processfd-preferred-pid-fallback-"
                "requires-double-credential-and-owner-recheck"
            ),
            "minimum_runtime_glibc": "2.39",
            "minimum_runtime_kernel": "6.8",
            "compatibility_policy": (
                "only-exact-tested-matrix-cells-supported-untested-distributions-kernels-"
                "libcs-and-systemd-backports-are-nonclaims"
            ),
            "development_host_observation": (
                "fedora-44-glibc-2.43-systemd-259-linux-7.1.3-not-a-release-baseline"
            ),
        },
        "release host compatibility",
    )


def check_process_topology_and_local_rpcs(document: dict[str, Any], root: Path) -> None:
    require_exact_value(
        document["process_topology"],
        {
            "controller_processes": 1,
            "agent_processes": 2,
            "ownership_service_processes": 1,
            "nexus_adapter_processes": 1,
            "nexus_effect_peer_processes": 1,
            "maximum_active_processes": 6,
            "resident_processes": 5,
            "source_agent_role": "source-wasmtime-local-provider-profile-sink-and-durable-projection",
            "destination_agent_role": "destination-wasmtime-local-provider-profile-sink-and-durable-projection",
            "ownership_service_role": "sole-durable-reservation-seal-abort-commit-and-query-authority",
            "nexus_adapter_role": "sole-native-v1-adapter-dispatch-grant-ledger-and-peer-supervisor",
            "nexus_effect_peer_role": "sole-in-memory-authoritative-nexus-registry",
            "controller_role": "short-lived-orchestrator-client-with-no-durable-decision-authority",
            "controller_operation_lease_path": (
                "${XDG_RUNTIME_DIR}/visa-0.1-controller.lock"
            ),
            "controller_operation_lease": (
                "first-product-owned-mutation-open-o-creat-o-rdwr-o-cloexec-o-nofollow-o-"
                "nonblock-flat-lock-fstat-regular-euid-owned-nlink1-mode0600-then-nonblocking-"
                "flock-held-before-all-other-mutation-dbus-or-rpc-never-unlink"
            ),
            "mutating_cli_operations": [
                "cohort-create",
                "cohort-retire",
                "run",
                "handoff",
                "reconcile",
            ],
            "readonly_cli_operations": ["status", "verify-evidence"],
            "additional_mutating_cli": (
                "typed-busy-rejection-before-mutation-or-rpc-not-an-admitted-controller-"
                "process"
            ),
            "registry_owner_during_controller_or_agent_crash": "nexus-effect-peer-owned-by-visa-nexusd",
            "binary_launch_model": "foreground-only-no-self-daemonization",
            "forbidden_topologies": [
                "controller-owned-agent-worker",
                "agent-owned-stdio-worker-child",
                "controller-or-agent-owned-ownership-database",
                "controller-or-agent-owned-nexus-effect-peer",
            ],
        },
        "six-process topology",
    )
    defaults = {
        "profile": "visa.local-user-bus-dbus-postcard.v1",
        "transport": "systemd-user-session-bus-dbus-via-zbus-5.18.0",
        "outer_encoding": "dbus-owned-by-daemon-and-zbus-not-release-byte-locked",
        "inner_encoding": "postcard-1.1.3-canonical-in-ay",
        "method_signature": "ay-to-ay",
        "max_inner_request_bytes": 1_048_576,
        "max_inner_response_bytes": 1_048_576,
        "outer_dbus_byte_array_hard_max_bytes": 67_108_864,
        "outer_dbus_message_hard_max_bytes": 134_217_728,
        "limit_policy": "check-inner-cap-before-send-and-at-method-entry-before-decode",
        "canonical_decode_policy": (
            "reject-trailing-bytes-and-require-byte-identical-reencode"
        ),
        "deterministic_type_policy": (
            "ordered-structs-tuples-bounded-vec-btreemap-and-btreeset-only-no-hashmap-hashset-"
            "or-float"
        ),
        "per_interface_golden_policy": (
            "each-rpc-request-and-response-type-all-enum-variants-bounds-non-minimal-varint-"
            "trailing-bytes-and-decode-reencode-identity"
        ),
        "schema_reflection_policy": (
            "postcard-schema-0.2.5-owned-schema-export-full-artifact-bytes-sha256-authoritative"
        ),
        "schema_key_policy": (
            "postcard-schema-fnv-key-is-noncryptographic-and-never-security-version-or-schema-"
            "authority"
        ),
        "serde_wire_attribute_policy": (
            "simple-serde-rename-allowed-only-when-owned-schema-and-corpus-lock-it-rename-all-"
            "directional-rename-flatten-with-skip-default-and-custom-serialize-deserialize-"
            "shapes-forbidden-in-v1"
        ),
        "semantic_outcomes": (
            "canonical-inner-success-rejected-unknown-and-internal-dbus-error-only-for-"
            "transport-or-pre-admission"
        ),
        "max_inflight_mutations_per_connection": 1,
        "max_queued_messages_per_connection": 16,
        "mutation_sequencing": (
            "single-visa-sequencer-per-service-correctness-by-request-id-and-durable-state-"
            "never-dbus-arrival-order"
        ),
        "large_artifact_policy": "digest-plus-secure-path-never-inline-no-unix-fd",
        "durable_native_request_bound_bytes": 65_536,
        "profile_response_chunk_bound_bytes": 65_536,
        "implementation_primitives": [
            "zbus-5.18.0-user-bus-proxy-and-interface",
            "org.freedesktop.DBus-get-connection-credentials-and-name-owner-changed",
            "rustix-1.1.4-process-pidfd-and-secure-proc-exe-identity",
            "joint-handoff-core-canonical-postcard-and-sha",
        ],
        "service_name_policy": "request-name-do-not-queue-no-replace-no-activation-files",
        "sender_identity": (
            "bus-controlled-unique-name-get-connection-credentials-unix-user-id-and-process-id"
        ),
        "process_handle_admission": (
            "prefer-credentials-processfd-else-query-unique-name-uid-pid-pidfd-open-requery-"
            "same-unique-name-same-uid-pid-any-change-fail-closed"
        ),
        "well_known_owner_recheck": (
            "client-requires-same-unique-name-remains-current-well-known-owner-after-process-"
            "handle-admission"
        ),
        "peer_executable_identity": (
            "pidfd-and-secure-proc-exe-file-identity-plus-sha256-must-match-exact-artifact-"
            "inventory"
        ),
        "client_service_identity": (
            "resolve-current-well-known-name-owner-and-verify-owner-uid-pid-exe-before-call"
        ),
        "credential_cache": (
            "keyed-by-bus-guid-unique-name-pid-and-exe-identity-invalidated-on-name-owner-"
            "changed-or-bus-restart"
        ),
        "user_bus_tcb": (
            "session-bus-daemon-zbus-systemd-user-manager-and-same-uid-processes-in-local-tcb"
        ),
        "bus_loss": (
            "application-fence-first-same-process-reconnect-and-name-reacquire-rpc-outcome-"
            "unknown-query-or-exact-replay"
        ),
        "readiness_order": (
            "initialize-and-validate-store-cohort-and-fences-register-interface-acquire-name-"
            "then-sd-notify-ready"
        ),
        "golden_boundary": (
            "well-known-name-interface-object-path-method-signature-and-inner-postcard-bytes-"
            "outer-dbus-bytes-not-locked"
        ),
        "forbidden_protocol_dependencies": [
            "handwritten-dbus-wire",
            "varlink",
            "zlink",
            "tarpc",
            "tonic",
        ],
        "compression": False,
        "unix_fd_passing": False,
        "in_band_upgrade": False,
        "security_boundary": (
            "local-tcb-admission-and-integrity-not-hostile-same-uid-ptrace-pid-namespace-or-"
            "allocation-dos-protection"
        ),
        "network_transport": False,
    }
    require_exact_value(document["local_rpc_defaults"], defaults, "local RPC defaults")
    require_source_pattern(
        root,
        "crates/runtime/visa_joint_handoff/src/durable.rs",
        r"^pub const MAX_NATIVE_REQUEST_BYTES: usize = 64 \* 1024;$",
        "durable native request bound",
    )
    require_source_pattern(
        root,
        "crates/core/visa_profile/src/logical_request.rs",
        r"^pub const MAX_LOGICAL_RESPONSE_CHUNK_BYTES: u32 = 64 \* 1024;$",
        "logical-response chunk bound",
    )
    require_source_pattern(
        root,
        "crates/runtime/visa_jco_node/src/protocol.rs",
        r"^pub\(crate\) const MAX_JSONL_MESSAGE_BYTES: usize = 1024 \* 1024;$",
        "existing product JSONL bound",
    )
    common_contract = {
        "protocol_major": 1,
        "protocol_minor": 0,
        "framing_profile": "visa.local-user-bus-dbus-postcard.v1",
        "method": "Execute",
        "request_signature": "ay",
        "response_signature": "ay",
    }
    cli_agent = {
        **common_contract,
        "schema": "visa.agent.control.v1",
        "well_known_names": [
            "io.github.chenty2333.vISA.Agent.Source1",
            "io.github.chenty2333.vISA.Agent.Destination1",
        ],
        "object_paths": [
            "/io/github/chenty2333/vISA/Agent/Source",
            "/io/github/chenty2333/vISA/Agent/Destination",
        ],
        "interface": "io.github.chenty2333.vISA.AgentControl1",
        "request_enum_namespace": "visa.agent.control.request.v1",
        "response_enum_namespace": "visa.agent.control.response.v1",
        "error_namespace": "visa.agent.control.error.v1",
        "replay_namespace": "visa.agent.control.replay.v1",
        "golden_corpus_id": "visa.agent.control.golden.v1",
        "owned_schema_artifact_id": "visa.agent.control.owned-schema.v1",
        "client": "visa-controller",
        "servers": ["source-visa-agent", "destination-visa-agent"],
        "required_operations": ["status", "run", "handoff", "reconcile", "verify-evidence"],
        "handshake": (
            "credential-bound-bus-guid-unique-name-uid-pid-pidfd-proc-exe-sha256-product-role-"
            "logical-incarnation-process-nonce-generation-cohort-and-boot-before-mutation"
        ),
        "request_replay": "same-id-same-canonical-bytes-same-response-conflicting-bytes-rejected",
        "timeout_disposition": "unknown-query-or-exact-replay-never-inferred-abort",
    }
    ownership = {
        **common_contract,
        "schema": "visa.ownership.local.v1",
        "well_known_name": "io.github.chenty2333.vISA.Ownership1",
        "object_path": "/io/github/chenty2333/vISA/Ownership",
        "interface": "io.github.chenty2333.vISA.Ownership1",
        "request_enum_namespace": "visa.ownership.local.request.v1",
        "response_enum_namespace": "visa.ownership.local.response.v1",
        "error_namespace": "visa.ownership.local.error.v1",
        "replay_namespace": "visa.ownership.local.replay.v1",
        "golden_corpus_id": "visa.ownership.local.golden.v1",
        "owned_schema_artifact_id": "visa.ownership.local.owned-schema.v1",
        "clients": ["source-visa-agent", "destination-visa-agent"],
        "server": "visa-ownershipd",
        "client_authority": (
            "submit-idempotent-proposals-and-query-only-no-receipt-issuance-or-local-decision"
        ),
        "required_operations": ["initialize-unit", "reserve", "seal", "abort", "commit", "query"],
        "handshake": (
            "credential-bound-bus-guid-unique-name-uid-pid-pidfd-proc-exe-sha256-product-role-"
            "logical-incarnation-process-nonce-generation-cohort-boot-and-service-incarnation-"
            "before-mutation"
        ),
        "request_replay": "same-id-same-canonical-bytes-same-receipt-conflicting-bytes-rejected",
        "timeout_disposition": "unknown-query-or-exact-replay-never-inferred-abort",
    }
    nexus = {
        **common_contract,
        "schema": "visa.nexus-adapter.local.v1",
        "well_known_name": "io.github.chenty2333.vISA.NexusAdapter1",
        "object_path": "/io/github/chenty2333/vISA/NexusAdapter",
        "interface": "io.github.chenty2333.vISA.NexusAdapter1",
        "request_enum_namespace": "visa.nexus-adapter.local.request.v1",
        "response_enum_namespace": "visa.nexus-adapter.local.response.v1",
        "error_namespace": "visa.nexus-adapter.local.error.v1",
        "replay_namespace": "visa.nexus-adapter.local.replay.v1",
        "golden_corpus_id": "visa.nexus-adapter.local.golden.v1",
        "owned_schema_artifact_id": "visa.nexus-adapter.local.owned-schema.v1",
        "clients": ["source-visa-agent", "destination-visa-agent"],
        "server": "visa-nexusd",
        "required_operations": [
            "descriptor",
            "register",
            "prepare",
            "commit-and-authorize-dispatch",
            "record-outcome",
            "complete",
            "freeze",
            "thaw",
            "close-step",
            "query",
        ],
        "handshake": (
            "credential-bound-bus-guid-unique-name-uid-pid-pidfd-proc-exe-sha256-product-role-"
            "native-wire-family-logical-incarnation-process-nonce-generation-cohort-boot-and-"
            "service-incarnation-before-mutation"
        ),
        "request_replay": (
            "same-id-same-canonical-bytes-byte-identical-response-or-grant-conflicting-bytes-"
            "rejected"
        ),
        "timeout_disposition": (
            "unknown-query-or-exact-replay-never-inferred-abort-or-dispatch"
        ),
        "agent_crash_after_grant": (
            "durable-armed-or-started-state-then-unknown-query-reconcile-never-grant-triggered-"
            "redispatch"
        ),
    }
    require_exact_value(document["cli_agent_rpc_v1"], cli_agent, "CLI-agent RPC v1")
    require_exact_value(document["agent_ownership_rpc_v1"], ownership, "agent-ownership RPC v1")
    require_exact_value(document["agent_nexus_rpc_v1"], nexus, "agent-Nexus RPC v1")
    schemas = {cli_agent["schema"], ownership["schema"], nexus["schema"]}
    require(len(schemas) == 3, "local RPC schemas must remain independent")
    for field in (
        "interface",
        "request_enum_namespace",
        "response_enum_namespace",
        "error_namespace",
        "replay_namespace",
        "golden_corpus_id",
        "owned_schema_artifact_id",
    ):
        values = [rpc[field] for rpc in (cli_agent, ownership, nexus)]
        require(len(set(values)) == 3, f"local RPC {field} values must remain independent")

    require_exact_value(
        document["ownership_service"],
        {
            "binary": "visa-ownershipd",
            "decision_authority": "sole-reserve-seal-abort-commit-authority",
            "storage": "single-sqlite-wal-full",
            "single_writer": "exclusive-process-lock-plus-immediate-transactions",
            "issuer_identity": "persisted-and-rechecked-across-process-restart",
            "decision_request_policy": (
                "client-requests-are-proposals-service-state-machine-alone-issues-immutable-"
                "receipts"
            ),
            "database_path_policy": "xdg-state-home-versioned-private-path",
            "database_parent_mode": "0700",
            "database_mode": "0600",
            "controller_store_access": "none",
            "agent_store_access": "none-rpc-only",
            "nexus_store_access": "none",
            "boot_cohort_binding": (
                "persist-exact-cohort-and-boot-id-refuse-mismatch-before-write"
            ),
        },
        "ownership service",
    )


def check_supervision_and_cohort(document: dict[str, Any]) -> None:
    require_exact_value(
        document["supervision"],
        {
            "supported_supervisor": "systemd-user",
            "supported_environment": (
                "linux-x86_64-with-available-systemd-user-manager-and-xdg-runtime-dir"
            ),
            "fallback": "manual-foreground-test-and-diagnostic-only-not-release-topology",
            "product_target": "visa-local.target",
            "source_agent_unit": "visa-agent@source.service",
            "destination_agent_unit": "visa-agent@destination.service",
            "ownership_unit": "visa-ownershipd.service",
            "nexus_adapter_unit": "visa-nexusd.service",
            "nexus_peer_unit": "none-child-only",
            "foreground_policy": "all-product-binaries-remain-foreground-and-never-self-daemonize",
            "cli_activation": (
                "cohort-create-local-launch-manifest-then-direct-user-dbus-start-stop-status-"
                "no-systemctl-child-process"
            ),
            "dbus_destination": "org.freedesktop.systemd1",
            "dbus_manager_path": "/org/freedesktop/systemd1",
            "dbus_manager_interface": "org.freedesktop.systemd1.Manager",
            "dbus_methods": [
                "Subscribe",
                "StartUnit",
                "StopUnit",
                "GetUnit",
                "ListUnitsByNames",
            ],
            "dbus_subscription": (
                "manager-subscribe-once-per-connection-then-install-and-await-active-jobremoved-"
                "signal-stream-before-first-operation"
            ),
            "dbus_job_semantics": (
                "start-or-stop-only-after-active-stream-match-returned-job-object-path-"
                "including-already-buffered-event-require-result-done-then-check-unit-and-"
                "product-health"
            ),
            "dbus_implementation_reuse": (
                "zbus-systemd-manager-proxy-or-minimal-zbus-typed-proxy-no-handwritten-dbus-wire"
            ),
            "target_relationships": (
                "target-wants-and-after-ownershipd-nexusd-and-both-agents-all-four-services-"
                "partof-target-no-upholds-bindsto-or-automatic-dependency-recovery"
            ),
            "agent_authority_dependencies": (
                "each-agent-after-ownershipd-and-nexusd-type-notify-ready-no-requires-wants-"
                "bindsto-or-upholds"
            ),
            "authority_start_completion": (
                "type-notify-ready-completes-after-order-before-either-agent-starts-or-reports-"
                "ready"
            ),
            "authority_failure_propagation": (
                "agents-application-fence-on-authority-name-loss-ownershipd-restart-reconnect-"
                "query-nexusd-loss-terminal-burns-cohort-no-systemd-nexus-or-agent-recovery-job"
            ),
            "ownershipd_service": (
                "Type=notify-Restart=on-failure-KillMode=control-group-SendSIGKILL=yes-"
                "TimeoutStopSec=10s"
            ),
            "nexusd_service": (
                "Type=notify-Restart=no-KillMode=control-group-SendSIGKILL=yes-"
                "TimeoutStopSec=10s"
            ),
            "agent_service": (
                "Type=notify-Restart=on-failure-KillMode=control-group-SendSIGKILL=yes-"
                "TimeoutStopSec=10s"
            ),
            "nexusd_ready": (
                "after-peer-spawn-handshake-dbus-interface-export-well-known-name-acquire-and-"
                "initial-cohort-epoch-fence-validation"
            ),
            "nexusd_peer_loss": "application-fence-first-then-nonzero-exit-no-peer-respawn",
            "ownershipd_restart": (
                "Restart=on-failure-RestartSec=1s-StartLimitIntervalSec=30s-"
                "StartLimitBurst=3"
            ),
            "agent_restart": (
                "Restart=on-failure-RestartSec=1s-StartLimitIntervalSec=30s-"
                "StartLimitBurst=3"
            ),
            "socket_activation": False,
            "linger_enablement": "never-automatic-operator-owned",
            "peer_child_management": (
                "tokio-process-retained-child-wait-reap-graceful-term-bounded-kill-lifeline-"
                "fallback"
            ),
            "readiness_library": "sd-notify-0.5.0",
            "readiness_delivery": (
                "explicit-var-os-notify-socket-present-and-nonempty-precheck-then-ready-"
                "notification-send-must-succeed-missing-empty-or-send-failure-is-not-ready"
            ),
            "shutdown_authority": "systemd-cleanup-is-not-effect-or-ownership-authority",
        },
        "systemd user supervision",
    )
    require_exact_value(
        document["same_boot_cohort"],
        {
            "cohort_id": (
                "operator-created-random-identity-namespaces-all-durable-state-and-runtime-paths"
            ),
            "boot_id_source": "/proc/sys/kernel/random/boot_id",
            "runtime_session_id": (
                "random-128-bit-lowercase-hex-create-new-under-xdg-runtime-root-and-bind-"
                "into-persistent-launch-manifest"
            ),
            "runtime_session_scope": (
                "same-systemd-user-manager-and-xdg-runtime-directory-lifetime-within-one-boot"
            ),
            "runtime_session_path": "${XDG_RUNTIME_DIR}/visa/0.1/runtime-session.json",
            "runtime_session_creation": (
                "secure-user-owned-mode-0600-no-symlink-create-new-write-fsync-file-and-"
                "parent-then-read-exact-existing"
            ),
            "cohort_create_order": (
                "read-or-create-runtime-session-then-create-or-match-persistent-launch-"
                "manifest-then-create-or-match-active-manifest-then-start-units"
            ),
            "cohort_create_argv": "visa cohort-create --cohort-id <32-lowercase-hex>",
            "cohort_create_boundary": (
                "local-pre-agent-rpc-launch-configuration-and-systemd-activation-never-"
                "ownership-receipt-or-effect-authority"
            ),
            "cohort_retire_argv": "visa cohort-retire --cohort-id <32-lowercase-hex>",
            "cohort_abandon_argv": (
                "visa cohort-retire --cohort-id <32-lowercase-hex> "
                "--acknowledge-stranded-state <reason>"
            ),
            "launch_manifest_path": (
                "${XDG_STATE_HOME:-$HOME/.local/state}/visa/0.1/cohorts/<cohort-id>/"
                "launch.json"
            ),
            "active_launch_manifest_path": (
                "${XDG_RUNTIME_DIR}/visa/0.1/active-cohort.json"
            ),
            "cohort_runtime_directory": (
                "${XDG_RUNTIME_DIR}/visa/0.1/cohorts/<cohort-id>"
            ),
            "launch_manifest_contents": (
                "canonical-product-version-cohort-id-boot-id-runtime-session-id-state-path-"
                "runtime-path"
            ),
            "launch_manifest_authority": (
                "non-authoritative-startup-configuration-never-an-ownership-or-effect-receipt"
            ),
            "cohort_create_retry": (
                "same-exact-manifest-boot-and-runtime-session-is-idempotent-and-may-converge-"
                "partial-start-any-difference-is-conflict"
            ),
            "active_cohort_exclusion": (
                "different-active-cohort-or-any-product-unit-active-activating-or-"
                "deactivating-is-conflict-same-exact-cohort-retry-only"
            ),
            "role_store_initialization": (
                "each-durable-role-create-new-or-open-exact-matching-store-before-ready-never-"
                "reset-or-adopt-mismatch"
            ),
            "partial_start": (
                "exact-manifest-retry-may-create-only-never-initialized-role-stores-and-"
                "restart-allowed-roles-existing-mismatches-fail-closed"
            ),
            "nexus_registry_attempt_tombstone": (
                "visa-nexusd-create-new-fsync-before-peer-spawn-or-registry-create"
            ),
            "nexus_retry_boundary": (
                "marker-absent-may-retry-start-marker-present-requires-same-live-healthy-"
                "nexusd-process-otherwise-cohort-burned-no-startunit-or-peer-respawn"
            ),
            "clean_retire": (
                "query-and-reconcile-require-no-frozen-unknown-or-inflight-handoff-and-sealed-"
                "required-evidence-then-dbus-stop-and-confirm-five-resident-processes-inactive"
            ),
            "retirement_tombstone": (
                "create-new-fsync-non-authoritative-record-then-remove-only-exact-active-"
                "manifest-never-delete-or-modify-role-stores-or-infer-receipt"
            ),
            "abandon": (
                "explicit-acknowledgement-records-unknown-or-stranded-reason-old-cohort-"
                "permanently-audit-only-new-cohort-requires-new-workload-and-state-identity"
            ),
            "abandon_stop_order": (
                "record-reason-then-dbus-stop-and-confirm-five-resident-processes-inactive-"
                "partial-stop-keeps-active-manifest-then-retirement-tombstone-and-remove-"
                "exact-active-manifest"
            ),
            "retire_retry": (
                "same-id-and-tombstone-is-idempotent-stop-ack-loss-queries-unit-state-partial-"
                "stop-never-removes-active-manifest"
            ),
            "persisted_by": [
                "visa-ownershipd",
                "source-visa-agent",
                "destination-visa-agent",
                "visa-nexusd",
            ],
            "registry_binding": (
                "nexus-effect-peer-registry-created-once-for-exact-cohort-and-boot-id"
            ),
            "startup_match": (
                "role-cohort-id-and-persisted-boot-id-must-match-before-mutation-or-recovery"
            ),
            "boot_mismatch": (
                "fail-closed-read-only-audit-no-mutation-no-recovery-no-new-registry-under-old-"
                "cohort"
            ),
            "old_state": (
                "retained-immutable-for-audit-never-combined-with-new-in-memory-registry"
            ),
            "runtime_loss": (
                "old-cohort-becomes-read-only-audit-state-new-cohort-id-required-no-runtime-"
                "manifest-reconstruction"
            ),
            "cohort_resume": "unsupported-in-0.1",
            "new_cohort": (
                "explicit-cohort-create-requires-new-cohort-id-and-new-versioned-state-and-"
                "runtime-paths"
            ),
            "reset": "never-in-place-never-delete-or-relabel-old-state",
            "admission_coverage": (
                "public-cli-and-process-topology-frozen-typed-verifiers-cover-create-exact-"
                "retry-conflict-each-partial-start-boundary-registry-attempt-stop-ack-loss-"
                "partial-stop-retire-abandon-runtime-loss-and-no-authority"
            ),
        },
        "same-boot cohort",
    )
    require_exact_value(
        document["agent_incarnation"],
        {
            "logical_identity": "stable-role-slot-cohort-and-boot-scoped-incarnation",
            "persistence": (
                "created-once-and-persisted-in-agent-projection-across-process-restart"
            ),
            "grant_binding": (
                "logical-agent-incarnation-role-slot-cohort-id-boot-id-and-exact-projection-"
                "digest"
            ),
            "process_identity": (
                "fresh-random-process-nonce-and-monotonic-generation-on-every-start"
            ),
            "handshake_binding": "logical-incarnation-plus-current-process-nonce-and-generation",
            "armed_recovery": (
                "query-authoritative-provider-and-ownership-state-then-resume-only-the-recorded-"
                "not-yet-started-dispatch"
            ),
            "started_recovery": (
                "without-durable-terminal-outcome-is-unknown-query-and-reconcile-never-redispatch"
            ),
            "state_loss": (
                "fail-closed-never-mint-replacement-incarnation-for-existing-cohort-slot"
            ),
        },
        "logical agent incarnation",
    )


def check_core_namespaces(document: dict[str, Any], root: Path) -> None:
    require_exact_value(
        document["portable_contract"],
        {
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
            "protocol_major": 1,
            "protocol_minor": 0,
            "canonical_encoding": "postcard-1.1.3",
            "digest_algorithm": "sha-256",
        },
        "joint protocol",
    )
    require_exact_value(
        document["cooperative_profile"],
        {"profile_major": 1, "profile_minor": 0},
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


def check_dependency_constraints(document: dict[str, Any], root: Path) -> None:
    constraints = document["release_dependency_constraints"]
    require_exact_value(
        constraints,
        {
            "classification": "selected-target-constraints-not-complete-build-provenance",
            "direct_dependency_policy": (
                "every-third-party-direct-dependency-of-each-release-product-root-uses-an-"
                "exact-equals-version-requirement"
            ),
            "postcard_wire_codec": "=1.1.3",
            "postcard_schema_reflection": "=0.2.5",
            "zbus_user_bus": "=5.18.0",
            "sd_notify_readiness": "=0.5.0",
            "rustix_secure_host": "=1.1.4-fs-process",
            "wasmtime_release_choice": "=43.0.2",
            "rusqlite_release_choice": "=0.40.1-bundled",
            "resolved_graph_policy": (
                "cargo-metadata-locked-per-product-root-target-profile-and-feature-set-"
                "reachable-graph-only"
            ),
            "complete_workspace_package_version_source_license_inventory": (
                "external-evidence-index-only-at-exact-tag"
            ),
            "cargo_lock_digest": "external-evidence-index-only-at-exact-tag",
            "rust_toolchain_digest": "external-evidence-index-only-at-exact-tag",
            "rust_trait_abi": "not-promised",
        },
        "release dependency constraints",
    )
    require_exact_value(
        document["supply_chain_tool_selection"],
        {
            "policy": (
                "maintained-exact-version-producers-feed-vISA-owned-typed-evidence-and-never-"
                "decide-release-admission"
            ),
            "docker_buildx": "=0.35.0",
            "docker_buildx_role": (
                "exact-oci-directory-export-and-raw-build-result-metadata-producer"
            ),
            "moby_buildkit": "=0.31.2",
            "moby_buildkit_role": (
                "docker-container-builder-backend-for-the-pinned-buildx-producer"
            ),
            "cargo_deny": "=0.20.2",
            "cargo_deny_role": (
                "license-source-ban-and-rustsec-policy-report-with-exact-advisory-db-revision-"
                "digest-and-observation-time"
            ),
            "cargo_auditable": "=0.7.5",
            "cargo_auditable_role": (
                "embed-dep-v0-in-every-final-rust-binary-and-export-a-binary-bound-inventory"
            ),
            "cargo_about": "=0.9.1",
            "cargo_about_role": (
                "generate-raw-license-inventory-and-third-party-notice-from-archived-config-"
                "template-lock-and-clarifications"
            ),
            "cargo_cyclonedx": "=0.5.9",
            "cargo_cyclonedx_role": (
                "generate-exact-target-and-feature-resolved-cyclonedx-sbom-set"
            ),
            "syft": "=1.48.0",
            "syft_role": (
                "observe-final-binaries-oci-layout-and-release-tree-into-native-json"
            ),
            "inventory_reconciliation": (
                "expected-cargo-graph-versus-dep-v0-and-syft-name-version-sets-must-match-or-"
                "have-a-typed-reviewed-explanation"
            ),
            "cargo_vet": "=0.10.2",
            "cargo_vet_disposition": (
                "phased-nonblocking-framework-exemptions-must-remain-counted-owned-reasoned-"
                "and-expiring"
            ),
            "cargo_dist": "=0.32.0",
            "cargo_dist_disposition": (
                "optional-packager-and-manifest-producer-only-never-release-admission-or-tool-"
                "installer"
            ),
            "excluded": [
                "askalono-archived-unmaintained",
                "cargo-native-sbom-nightly-unstable",
                "cargo-sbom-overlaps-selected-cyclonedx-path-unless-external-spdx-2.3-demand",
            ],
        },
        "supply-chain tool selection",
    )
    workspace = load_toml_bytes(read_regular_file(root, "Cargo.toml", "workspace manifest"), "Cargo.toml")
    wasmtime = workspace.get("workspace", {}).get("dependencies", {}).get("wasmtime")
    require(isinstance(wasmtime, dict), "workspace wasmtime dependency must be a table")
    require_exact_value(wasmtime.get("version"), "=43.0.2", "Wasmtime dependency")
    host = load_toml_bytes(
        read_regular_file(root, "crates/backend/substrate_host/Cargo.toml", "substrate_host manifest"),
        "crates/backend/substrate_host/Cargo.toml",
    )
    rusqlite = host.get("dependencies", {}).get("rusqlite")
    require(isinstance(rusqlite, dict), "substrate_host rusqlite dependency must be a table")
    require_exact_value(rusqlite.get("version"), "=0.40.1", "rusqlite dependency")
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
    for name, version in (
        ("wasmtime", "43.0.2"),
        ("rusqlite", "0.40.1"),
        ("postcard", "1.1.3"),
        ("rustix", "1.1.4"),
    ):
        require(
            version in versions_by_name.get(name, set()),
            f"Cargo.lock does not contain selected {name} {version}",
        )


def check_wits(document: dict[str, Any], root: Path) -> None:
    entries = document["wit_lock"]
    require(isinstance(entries, list), "wit_lock must be an array")
    for entry in entries:
        require(isinstance(entry, dict), "WIT lock entries must be tables")
        require_exact_keys(
            entry,
            {"id", "path", "package", "world", "sha256"},
            "WIT lock entry",
        )
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
    observed = [(entry.get("id"), entry.get("type")) for entry in entries]
    expected = [(vector_id, type_name) for vector_id, type_name, _ in EXPECTED_GOLDEN_VECTORS]
    require_exact_value(observed, expected, "golden-vector identities")
    for entry, (_, _, test_path) in zip(entries, EXPECTED_GOLDEN_VECTORS, strict=True):
        require_exact_keys(
            entry,
            {
                "id",
                "type",
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
        test_source = source_text(root, test_path)
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
            {"id", "type", "canonical_encoding", "bytes_hex", "sha256"},
            f"release vector {entry.get('id')}",
        )
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


def expected_owned_schema_artifacts() -> list[dict[str, str]]:
    shared = {
        "schema_format": "postcard-schema-owned-json.v1",
        "schema_envelope": "visa.postcard-owned-schema-artifact.v1",
        "canonical_json": "rfc8785-jcs-utf8-no-duplicate-keys-no-trailing-bytes",
        "postcard_schema_version": "0.2.5",
        "digest_algorithm": "sha-256",
        "digest_scope": "entire-artifact-exact-bytes-not-postcard-schema-fnv-key",
        "variant_coverage": (
            "request-response-error-all-variants-fields-bounds-and-discriminants"
        ),
        "serde_attribute_policy": (
            "simple-rename-only-when-artifact-and-corpus-lock-it-rename-all-directional-rename-"
            "flatten-with-skip-default-and-custom-shapes-forbidden"
        ),
    }
    return [
        {
            **shared,
            "id": "visa.agent.control.owned-schema.v1",
            "rpc_contract": "cli_agent_rpc_v1",
            "path": "schemas/local-rpc/visa-agent-control-v1.owned-schema.json",
            "corpus_id": "visa.agent.control.golden.v1",
            "readiness_id": "cli-agent-rpc-v1",
        },
        {
            **shared,
            "id": "visa.ownership.local.owned-schema.v1",
            "rpc_contract": "agent_ownership_rpc_v1",
            "path": "schemas/local-rpc/visa-ownership-local-v1.owned-schema.json",
            "corpus_id": "visa.ownership.local.golden.v1",
            "readiness_id": "agent-ownership-rpc-v1",
        },
        {
            **shared,
            "id": "visa.nexus-adapter.local.owned-schema.v1",
            "rpc_contract": "agent_nexus_rpc_v1",
            "path": "schemas/local-rpc/visa-nexus-adapter-local-v1.owned-schema.json",
            "corpus_id": "visa.nexus-adapter.local.golden.v1",
            "readiness_id": "agent-nexus-rpc-v1",
        },
    ]


def check_owned_schema_artifacts(document: dict[str, Any]) -> None:
    expected = expected_owned_schema_artifacts()
    require_exact_value(
        document["required_owned_schema_artifact"],
        expected,
        "required owned local RPC schema artifacts",
    )
    for entry in expected:
        canonical_relative_path(entry["path"], f"{entry['id']} owned schema")
        rpc = document[entry["rpc_contract"]]
        require_exact_value(
            rpc["owned_schema_artifact_id"], entry["id"], f"{entry['id']} RPC schema binding"
        )
        require_exact_value(
            rpc["golden_corpus_id"], entry["corpus_id"], f"{entry['id']} corpus binding"
        )
    for field in ("id", "path", "readiness_id", "corpus_id"):
        values = [entry[field] for entry in expected]
        require(len(values) == len(set(values)), f"owned schema {field} values must be unique")


def check_release_semantic_corpus(document: dict[str, Any]) -> None:
    require_exact_value(
        document["release_semantic_corpus"],
        {
            "seed_baseline": "representative-seeds-only-not-release-closure",
            "inventory_schema": "visa.release-semantic-type-inventory.v1",
            "corpus_schema": "visa.release-semantic-golden-corpus.v1",
            "required_crates": ["contract_core", "joint_handoff_core", "visa_profile"],
            "required_local_rpc_corpora": [
                "visa.agent.control.golden.v1",
                "visa.ownership.local.golden.v1",
                "visa.nexus-adapter.local.golden.v1",
            ],
            "required_owned_schema_artifact_ids": [
                "visa.agent.control.owned-schema.v1",
                "visa.ownership.local.owned-schema.v1",
                "visa.nexus-adapter.local.owned-schema.v1",
            ],
            "coverage_rule": "every-durable-or-public-serialized-type-and-every-enum-variant",
            "required_checks": [
                "exact-canonical-encode",
                "decode-round-trip",
                "decode-reencode-byte-identity",
                "non-minimal-varint-rejection",
                "unknown-and-trailing-byte-rejection",
                "ordered-map-set-and-no-float-domain",
                "optional-empty-nonempty-and-bounded-extrema",
                "rust-constructed-corpus-not-source-literal-presence",
            ],
            "closure_evidence": "exact-tag-external-index-artifact-and-verifier-receipt",
        },
        "release semantic corpus closure",
    )


def check_neutral_and_nexus(document: dict[str, Any], root: Path) -> None:
    neutral = document["neutral_wire_v1"]
    expected_neutral = {
        "provenance": "frozen-local-source-baseline",
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
        "provenance": "earned-historical-evidence-not-release-adapter",
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
        "provenance": "frozen-upstream-contract",
        "api_provenance": "frozen-source-contract-not-nexus-v0.1.0-released-api",
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
            "upstream_revision": nexus["freeze_source_revision"],
            "upstream_path": nexus["freeze_source_path"],
            "upstream_sha256": nexus["freeze_source_sha256"],
            "required_local_path": (
                "specs/joint-handoff/nexus-effect-peer-native-v1-freeze.json"
            ),
            "local_artifact_requirement": (
                "byte-identical-copy-bound-by-exact-tag-external-evidence"
            ),
        },
        "Nexus freeze source lock",
    )

    artifact = document["nexus_wire_artifact"]
    require_exact_value(
        artifact,
        {
            "kind": "nexus-owned-native-v1-wire-crate-or-release-bundle",
            "wire_family": "nexus-effect-peer-native-v1",
            "freeze_contract_id": "nexus-effect-peer-native-v1",
            "license": "MPL-2.0",
            "portal_v2_eligible": False,
            "freeze_origin_revision": "cb773539401107efe7a7ad036b80ff40d8ec305c",
            "release_component_revision": "1e49cca428cff39961fd79cadd833ffe0f7365f5",
            "release_component_entry_paths": [
                "crates/nexus-effect-peer",
                "crates/nexus-effect-peer-wire",
            ],
            "release_component_relation_to_freeze": (
                "exact-descendant-preserving-byte-identical-native-v1-freeze"
            ),
            "release_component_compatibility_requirement": (
                "verify-git-ancestry-freeze-json-canonical-corpus-exported-wire-v1-"
                "equivalence-and-complete-nexus-build-source-graph"
            ),
            "source_graph_requirement": (
                "closed-root-package-target-features-build-argv-build-record-workspace-"
                "manifest-lock-reachable-packages-path-dependencies-build-scripts-include-"
                "inputs-and-source-file-path-sha256-graph"
            ),
            "producer_source_bundle_requirement": (
                "git-bundle-includes-attestation-producer-revision-exact-tag-component-"
                "revision-freeze-origin-workflow-source-and-pinned-actions-attest-sha"
            ),
            "attested_subject_name": "nexus-effect-peer",
            "build_provenance_predicate_type": "https://slsa.dev/provenance/v1",
            "build_provenance_build_type": (
                "https://actions.github.io/buildtypes/workflow/v1"
            ),
            "build_provenance_workflow_path": (
                ".github/workflows/release-effect-peer-wire.yml"
            ),
            "build_provenance_event_name": "push",
            "build_provenance_runner_environment": "github-hosted",
            "actions_attest_revision": (
                "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"
            ),
            "producer_workflow_job_isolation": (
                "build-and-qualification-job-exact-permissions-contents-read-all-artifact-"
                "influencing-jobs-github-hosted-attest-only-job-exact-permissions-contents-"
                "read-id-token-write-attestations-write-and-no-component-code-execution"
            ),
            "producer_workflow_action_policy": (
                "every-third-party-action-pinned-by-full-commit-sha"
            ),
            "build_provenance_requirement": (
                "authenticated-exact-binary-subject-standard-actions-workflow-v1-exact-tag-"
                "producer-source-and-certificate-cross-check"
            ),
            "release_link_predicate_type": (
                "https://in-toto.io/attestation/link/v0.3"
            ),
            "release_link_name": (
                "nexus-effect-peer-native-v1-release-build-and-qualification"
            ),
            "release_link_material_names": [
                "nexus-component-source-revision",
                "nexus-component-source-bundle",
                "nexus-component-source-graph",
                "nexus-native-v1-exported-corpus",
            ],
            "release_link_build_record_byproduct": "buildRecordId",
            "release_link_environment": "empty-object",
            "release_link_step_semantics": (
                "source-bundle-source-graph-and-exported-corpus-are-prebuilt-validated-"
                "materials-consumed-by-the-attested-release-build-and-qualification-step"
            ),
            "release_link_requirement": (
                "authenticated-same-binary-subject-same-run-invocation-exact-build-command-"
                "build-record-and-component-source-bundle-source-graph-corpus-materials"
            ),
            "producer_workflow_tcb": (
                "exact-tag-push-without-caller-inputs-isolated-unprivileged-build-and-"
                "qualification-jobs-minimal-attest-only-job-nexus-workflow-source-full-action-"
                "sha-pins-github-hosted-runners-sigstore-and-verifiers-no-slsa-level-claimed"
            ),
            "typed_verifier_requirement": (
                "verify-producer-tag-workflow-job-permissions-hosted-runners-artifact-handoff-"
                "no-component-execution-in-attest-job-and-action-pins-source-bundle-component-"
                "and-freeze-ancestry-byte-identical-freeze-closed-source-graph-exported-corpus-"
                "artifact-inventory-build-record-binary-subject-standard-build-provenance-"
                "release-link-and-certificate-run-cross-pins"
            ),
            "required_negative_cases": [
                "standard-build-provenance-with-wrong-build-type-builder-workflow-or-"
                "certificate-cross-pin",
                "authenticated-release-link-without-pinned-component-material",
                "pinned-component-link-with-substituted-source-graph-build-record-or-corpus",
                "same-signer-release-link-from-different-run-invocation",
                "producer-workflow-job-permission-runner-execution-boundary-or-action-pin-"
                "drift",
            ],
            "identity_requirement": (
                "inventory-component-pin-plus-standard-producer-provenance-plus-authenticated-"
                "same-run-release-link-material-cross-pin-plus-closed-source-graph-and-corpus-"
                "evidence"
            ),
        },
        "Nexus wire release artifact",
    )

    mapping = document["required_nexus_mapping_v2"]
    require_exact_value(
        mapping,
        {
            "schema": "visa-nexus-handoff.nexus-effect-peer-native-v1-refinement.v2",
            "contract_id": "current-nexus-effect-peer-native-v1-to-neutral-wire-v1",
            "repository": "https://github.com/chenty2333/visa-nexus-handoff",
            "source_path": "specs/joint-handoff/nexus-effect-peer-native-v1-refinement-v2.toml",
            "source_revision": "8983e5396ede187ef8c2e58ce09cce0ba77e2e25",
            "source_sha256": "18e66054d7a76004d7df19e7137a7c8e36749abd3cdcef0e93b21f4596f788d9",
            "freeze_source_lock_path": "specs/joint-handoff/nexus-effect-peer-native-v1-freeze.json",
            "neutral_wire_schema": "visa-nexus-handoff.wire-contract.v1",
            "nexus_freeze_contract_id": "nexus-effect-peer-native-v1",
            "nexus_canonical_snapshot_sha256": nexus["canonical_snapshot_sha256"],
            "qualification_requirement": (
                "exact-tag-source-revision-sha256-local-lock-and-verifier-receipt"
            ),
            "release_component_compatibility_requirement": (
                "prove-release-component-revision-descends-from-freeze-origin-revision-and-"
                "preserves-freeze-json-canonical-corpus-and-exported-native-v1-contract-"
                "without-claiming-mapping-adapter-qualification"
            ),
        },
        "required Nexus mapping v2",
    )


def check_provider_spi(document: dict[str, Any], root: Path) -> None:
    expected = {
        "provenance": "in-tree-preview-not-public-0.1-abi",
        "trait": "substrate_api::EffectClosureProvider",
        "protocol_major": 2,
        "historical_protocol_minor": 0,
        "protocol_minor": 1,
        "historical_fault_matrix_schema": "visa.effect-closure-provider-fault-matrix.v1",
        "required_fault_matrix_schema": "visa.effect-closure-provider-fault-matrix.v2",
        "required_admission_profile": "admission-required",
        "stability": "rust-source-preview",
        "provider_identity_in_trait": False,
        "release_adapter_identity": (
            "exact-visa-nexusd-revision-and-executable-plus-exact-nexus-revision-and-"
            "observed-child-executable"
        ),
        "required_capabilities": [
            "effect-admission",
            "outcome-recording",
            "effect-completion",
            "session-query",
            "freeze-thaw",
            "commit-close",
        ],
        "release_identity_evidence": (
            "exact-tag-adapter-and-provider-revisions-and-executable-sha256"
        ),
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
        r"^pub const EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR_V2_0: u16 = 0;$",
        "historical effect-closure provider minor",
    )
    require_source_pattern(
        root,
        path,
        r"^pub const EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR_V2_1: u16 = 1;$",
        "required effect-closure provider minor",
    )
    require_source_pattern(
        root,
        path,
        (
            r"^pub const EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR: u16 = "
            r"EFFECT_CLOSURE_PROVIDER_PROTOCOL_MINOR_V2_1;$"
        ),
        "current effect-closure provider minor alias",
    )
    require_source_pattern(root, path, r"^pub trait EffectClosureProvider: Send \+ Sync \{$", "provider trait")
    conformance_path = "crates/testing/visa-conformance/src/effect_closure_replay.rs"
    require_source_pattern(
        root,
        conformance_path,
        r'^    "visa\.effect-closure-provider-fault-matrix\.v1";$',
        "historical effect-closure fault matrix schema",
    )
    require_source_pattern(
        root,
        conformance_path,
        r'^    "visa\.effect-closure-provider-fault-matrix\.v2";$',
        "required effect-closure fault matrix schema",
    )
    require_source_pattern(
        root,
        conformance_path,
        r"^pub const EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX_V2: &\[EffectClosureFaultCase\] = &\[$",
        "required effect-closure fault matrix",
    )


def check_provider_dispatch_fence(document: dict[str, Any]) -> None:
    require_exact_value(
        document["provider_dispatch_fence"],
        {
            "registry_process": "nexus-effect-peer",
            "registry_supervisor_and_native_adapter": "visa-nexusd",
            "native_commit_validation": (
                "visa-nexusd-validates-exact-native-v1-commit-receipt-and-chain"
            ),
            "central_grant_rule": (
                "visa-nexusd-atomically-consumes-one-exact-native-commit-into-one-exact-"
                "dispatch-grant"
            ),
            "central_grant_replay": (
                "same-request-id-and-bytes-return-byte-identical-grant-never-a-different-grant"
            ),
            "serializable_grant_boundary": (
                "commit-evidence-for-agent-validation-not-a-same-process-dispatch-permit"
            ),
            "grant_binding": (
                "effect-operation-id-idempotency-key-agent-role-slot-logical-incarnation-"
                "cohort-boot-projection-native-receipt-and-request-digests"
            ),
            "agent_local_validation": (
                "exact-grant-and-durable-local-projection-must-match-before-mint"
            ),
            "agent_local_authorization": (
                "private-non-clone-ProfileDispatchAuthorization-minted-and-consumed-in-one-"
                "agent-process"
            ),
            "agent_local_recovery": (
                "persist-grant-and-armed-or-started-before-sink-armed-authoritative-query-may-"
                "resume-started-without-outcome-is-unknown-never-grant-triggered-redispatch"
            ),
            "regular_file_sink_process": "corresponding-visa-agent",
            "logical_request_sink_process": "corresponding-visa-agent",
            "controller_sink_access": "none",
            "visa_nexusd_sink_access": "none",
            "same_process_requirement": (
                "authorize-dispatch-and-real-profile-sink-call-share-one-trusted-agent-process"
            ),
            "existing_committed_effect_permit_equivalence": False,
            "grant_security_claim": (
                "same-uid-local-tcb-replay-and-bypass-control-not-cryptographic-unforgeability"
            ),
        },
        "provider dispatch fence",
    )


def check_public_surface(document: dict[str, Any]) -> None:
    require_exact_value(
        document["public_surface"],
        [
            {
                "id": "visa-cli",
                "binary": "visa",
                "frozen_boundary": "binary-name-and-role",
                "required_responsibilities": [
                    "cohort-create",
                    "cohort-retire",
                    "status",
                    "run",
                    "handoff",
                    "reconcile",
                    "verify-evidence",
                ],
                "bootstrap_boundary": (
                    "cohort-create-is-local-pre-agent-rpc-non-authoritative-launch-config-plus-"
                    "user-dbus-activation"
                ),
                "bootstrap_conflict_policy": (
                    "exact-manifest-retry-only-existing-id-boot-session-path-or-role-store-"
                    "mismatch-fails-conflict"
                ),
                "operation_admission": (
                    "mutating-responsibilities-require-exclusive-controller-operation-lease-"
                    "readonly-responsibilities-never-mutate-or-count-as-controller-role"
                ),
                "typed_outcome_requirement": (
                    "versioned-total-success-rejected-unknown-operator-and-internal-classes"
                ),
                "exit_code_requirement": (
                    "documented-stable-nonoverlapping-mapping-for-every-typed-outcome"
                ),
            },
            {
                "id": "visa-agent",
                "binary": "visa-agent",
                "frozen_boundary": "binary-name-direct-runtime-role-local-sink-and-control-transport",
                "required_responsibilities": [
                    "source-or-destination-agent-selected-at-startup",
                    "in-process-wasmtime-runtime",
                    "in-process-local-provider-and-profile-sink",
                    "durable-local-projection",
                    "credential-bound-user-bus-dbus-service",
                ],
                "typed_outcome_requirement": (
                    "rpc-schema-total-success-rejected-unknown-and-internal-classes"
                ),
                "exit_code_requirement": (
                    "documented-stable-clean-config-integrity-temporary-and-internal-classes"
                ),
            },
            {
                "id": "visa-ownershipd",
                "binary": "visa-ownershipd",
                "frozen_boundary": "binary-name-single-authority-role-store-and-local-rpc",
                "required_responsibilities": [
                    "exclusive-ownership-store",
                    "reserve-seal-abort-commit-query",
                    "restart-and-exact-request-replay",
                    "credential-bound-user-bus-dbus-service",
                ],
                "typed_outcome_requirement": (
                    "rpc-schema-total-success-rejected-unknown-and-internal-classes"
                ),
                "exit_code_requirement": (
                    "documented-stable-clean-config-integrity-temporary-and-internal-classes"
                ),
            },
            {
                "id": "visa-nexusd",
                "binary": "visa-nexusd",
                "frozen_boundary": (
                    "binary-name-native-v1-adapter-grant-ledger-peer-supervisor-and-local-rpc"
                ),
                "required_responsibilities": [
                    "exclusive-nexus-effect-peer-child-supervision",
                    "native-v1-validation-and-neutral-v2-mapping",
                    "single-exact-dispatch-grant-ledger",
                    "credential-bound-user-bus-dbus-service",
                ],
                "typed_outcome_requirement": (
                    "rpc-schema-total-success-rejected-unknown-and-internal-classes"
                ),
                "exit_code_requirement": (
                    "documented-stable-clean-config-integrity-temporary-and-internal-classes"
                ),
            },
        ],
        "public CLI/agent surface",
    )


def check_release_artifacts(document: dict[str, Any]) -> None:
    def artifact(
        artifact_id: str,
        kind: str,
        archive_path: str,
        repository: str,
        workflow: str,
        roles: list[str],
        component_source_revision: str | None = None,
    ) -> dict[str, Any]:
        result = {
            "id": artifact_id,
            "kind": kind,
            "archive_path": archive_path,
            "source_repository": repository,
            "signer_workflow": workflow,
            "handshake_roles": roles,
        }
        if component_source_revision is not None:
            result["component_source_revision"] = component_source_revision
        return result

    visa_repository = "chenty2333/vISA"
    visa_workflow = "chenty2333/vISA/.github/workflows/release-evidence.yml"
    nexus_repository = "chenty2333/Nexus"
    nexus_workflow = "chenty2333/Nexus/.github/workflows/release-effect-peer-wire.yml"
    expected = [
        artifact("visa-cli-binary", "executable", "artifacts/bin/visa", visa_repository, visa_workflow, ["cli-agent-client"]),
        artifact(
            "visa-agent-binary",
            "executable",
            "artifacts/bin/visa-agent",
            visa_repository,
            visa_workflow,
            ["cli-agent-server", "ownership-client", "nexus-adapter-client"],
        ),
        artifact(
            "visa-ownershipd-binary",
            "executable",
            "artifacts/bin/visa-ownershipd",
            visa_repository,
            visa_workflow,
            ["ownership-server"],
        ),
        artifact(
            "visa-nexusd-binary",
            "executable",
            "artifacts/bin/visa-nexusd",
            visa_repository,
            visa_workflow,
            ["nexus-adapter-server", "native-peer-supervisor"],
        ),
        artifact(
            "nexus-effect-peer-binary",
            "executable",
            "artifacts/bin/nexus-effect-peer",
            nexus_repository,
            nexus_workflow,
            ["native-peer"],
            document["nexus_wire_artifact"]["release_component_revision"],
        ),
        artifact(
            "visa-local-target-unit",
            "systemd-user-unit",
            "artifacts/systemd/user/visa-local.target",
            visa_repository,
            visa_workflow,
            [],
        ),
        artifact(
            "visa-agent-template-unit",
            "systemd-user-unit",
            "artifacts/systemd/user/visa-agent@.service",
            visa_repository,
            visa_workflow,
            [],
        ),
        artifact(
            "visa-ownershipd-unit",
            "systemd-user-unit",
            "artifacts/systemd/user/visa-ownershipd.service",
            visa_repository,
            visa_workflow,
            [],
        ),
        artifact(
            "visa-nexusd-unit",
            "systemd-user-unit",
            "artifacts/systemd/user/visa-nexusd.service",
            visa_repository,
            visa_workflow,
            [],
        ),
    ]
    require_exact_value(document["release_artifact"], expected, "release artifact contract")
    paths = [entry["archive_path"] for entry in expected]
    roles = [role for entry in expected for role in entry["handshake_roles"]]
    require(len(paths) == len(set(paths)), "release artifact paths must be unique")
    require(len(roles) == len(set(roles)), "executable handshake roles must have one artifact owner")
    for path in paths:
        canonical_relative_path(path, "release artifact")


def check_failure_matrix(document: dict[str, Any]) -> None:
    expected = [
        {
            "role": "visa-controller",
            "crash_safety": "no-durable-authority-to-lose",
            "progress_recovery": "restart-and-reconnect-to-both-agents",
            "registry_after_crash": "unchanged-in-nexus-effect-peer",
            "source_disposition_after_crash": (
                "unchanged-until-authoritative-query-and-reconcile"
            ),
            "forbidden_fallback": "infer-abort-commit-or-dispatch-from-local-cache",
        },
        {
            "role": "visa-agent",
            "crash_safety": "durable-local-projection-reopens-fail-closed",
            "progress_recovery": "restart-reconnect-query-and-exact-rpc-replay",
            "registry_after_crash": "unchanged-in-nexus-effect-peer-owned-by-visa-nexusd",
            "source_disposition_after_crash": (
                "durable-local-state-reopened-then-authoritative-query-and-reconcile"
            ),
            "forbidden_fallback": "blind-redispatch-or-local-ownership-decision",
        },
        {
            "role": "visa-ownershipd",
            "crash_safety": "sqlite-wal-full-preserves-one-non-equivocating-decision",
            "progress_recovery": "restart-with-same-store-issuer-query-and-exact-replay",
            "registry_after_crash": "unchanged-in-nexus-effect-peer",
            "source_disposition_after_crash": (
                "unchanged-by-service-restart-and-governed-by-the-durable-decision"
            ),
            "forbidden_fallback": "second-writer-new-issuer-or-timeout-as-abort",
        },
        {
            "role": "visa-nexusd",
            "crash_safety": (
                "terminal-phase-relative-fail-closed-no-new-dispatch-or-fabricated-closure"
            ),
            "progress_recovery": "unsupported-in-0.1",
            "registry_after_crash": "child-registry-is-not-reconnectable-or-replaceable",
            "source_disposition_after_crash": (
                "already-frozen-remains-frozen-pre-freeze-retains-prior-disposition-never-"
                "inferred-frozen"
            ),
            "forbidden_fallback": "respawn-peer-or-mint-replacement-grant",
        },
        {
            "role": "nexus-effect-peer",
            "crash_safety": (
                "terminal-phase-relative-fail-closed-no-new-dispatch-or-fabricated-closure"
            ),
            "progress_recovery": "unsupported-in-0.1",
            "registry_after_crash": (
                "lost-in-memory-registry-cannot-be-recreated-as-the-same-authority"
            ),
            "source_disposition_after_crash": (
                "already-frozen-remains-frozen-pre-freeze-retains-prior-disposition-never-"
                "inferred-frozen"
            ),
            "forbidden_fallback": (
                "respawn-replay-as-original-registry-or-infer-effect-closure"
            ),
        },
    ]
    require_exact_value(document["failure_matrix"], expected, "process failure matrix")
    for entry in document["failure_matrix"]:
        require_exact_keys(
            entry,
            {
                "role",
                "crash_safety",
                "progress_recovery",
                "registry_after_crash",
                "source_disposition_after_crash",
                "forbidden_fallback",
            },
            "failure matrix entry",
        )


def check_support_and_admission(document: dict[str, Any]) -> None:
    support = document["support_policy"]
    require_exact_keys(
        support,
        {"required_release_cells", "reject_at_admission", "non_claims"},
        "support policy",
    )
    require_exact_value(support["required_release_cells"], EXPECTED_REQUIRED_CELLS, "required release cells")
    require_exact_value(
        support["reject_at_admission"],
        [
            "product-version-not-exactly-0.1.0",
            "unknown-or-mismatched-required-contract-profile-or-wit-version",
            "wit-source-byte-digest-mismatch",
            "component-or-profile-digest-mismatch",
            "provider-implementation-revision-or-executable-digest-mismatch",
            "local-rpc-schema-role-frame-limit-or-executable-digest-mismatch",
            "ownership-database-opened-outside-visa-ownershipd",
            "second-ownership-writer-or-receipt-issuer",
            "neutral-wire-nexus-freeze-or-v2-mapping-mismatch",
            "nexus-portal-v2-artifact-in-native-v1-slot",
            "serialized-dispatch-proof-used-directly-as-local-sink-permit",
            "respawned-nexus-peer-presented-as-the-original-registry",
            "stdio-agent-worker-or-controller-owned-agent-topology",
            "self-daemonizing-socket-activated-or-non-systemd-user-release-topology",
            "persisted-boot-id-cohort-or-logical-agent-incarnation-mismatch",
            "runtime-session-id-or-active-launch-manifest-mismatch",
            "unsupported-runtime-baseline-or-missing-systemd-feature-probe",
            "missing-or-relabelled-old-cohort-state",
            "non-linux-non-x86_64-cross-host-or-cross-boot-request",
            "raw-live-tcp-continuity",
            "effect-closure-provider-protocol-not-exactly-2.1-or-profile-not-admission-required",
            "effect-closure-provider-2.1-without-fault-matrix-v2-evidence",
            "effect-closure-provider-2.1-without-versioned-nexus-adapter",
        ],
        "admission rejection policy",
    )
    required_non_claims = {
        "cross-host-ownership-or-transport",
        "host-reboot-or-permanent-source-loss-recovery",
        "logout-user-manager-teardown-or-xdg-runtime-loss-cohort-resume",
        "untested-linux-distribution-kernel-libc-or-systemd-backport",
        "mtls-cryptographic-receipt-authenticity-freshness-or-anti-rollback",
        "byzantine-ownership-provider-or-host-safety",
        "real-nexus-ostd-irq-smp-or-retained-device-recovery",
        "nexus-portal-v2-integration-or-kernel-backend",
        "visa-nexusd-or-nexus-effect-peer-crash-progress-recovery",
        "serializable-dispatch-grant-as-same-process-provider-permit",
        "hostile-same-uid-ptrace-or-process-memory-safety",
        "same-uid-authentication-credential-separation-or-tenant-isolation",
        "cryptographic-unforgeability-of-local-dispatch-grants",
        "agent-worker-stdio-subprocess-or-network-control-transport",
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
    require_exact_keys(
        admission,
        {"schema_check", "rc_admission_check", "release_ready_check", "fail_closed_dimensions"},
        "release admission",
    )
    require_exact_value(admission.get("schema_check"), "python3 scripts/check-release-contract.py", "schema command")
    require_exact_value(
        admission.get("rc_admission_check"),
        "python3 scripts/check-release-contract.py --release-ready --release-stage rc-admitted "
        "--archive-root PATH --attestation-verifier-sha256 GH_SHA256 "
        "--trusted-root-sha256 TRUSTED_ROOT_SHA256 --expected-source-tag RC_TAG",
        "RC admission command",
    )
    require_exact_value(
        admission.get("release_ready_check"),
        "python3 scripts/check-release-contract.py --release-ready --release-stage "
        "final-release-verified --archive-root PATH --attestation-verifier-sha256 "
        "GH_SHA256 --trusted-root-sha256 TRUSTED_ROOT_SHA256 --expected-source-tag RC_TAG",
        "release-ready command",
    )
    require_exact_value(
        admission.get("fail_closed_dimensions"),
        [
            "product-version",
            "contract-joint-profile-and-resource-versions",
            "release-build-provenance",
            "six-process-role-and-authority-topology",
            "systemd-user-supervision-units-readiness-and-product-process-count",
            "same-boot-cohort-and-logical-agent-incarnation",
            "three-independent-local-rpc-schemas-and-golden-corpora",
            "ownership-single-writer-store-issuer-and-replay",
            "provider-dispatch-grant-and-agent-local-sink-authorization",
            "postcard-seed-vectors-and-complete-semantic-corpus",
            "wit-package-ids-worlds-and-source-bytes",
            "neutral-wire-bytes",
            "nexus-freeze-contract-and-canonical-snapshot",
            "nexus-freeze-local-source-lock",
            "nexus-provider-identity",
            "neutral-to-current-nexus-mapping-v2",
            "release-readiness-closure",
            "closed-typed-verifiers-evidence-self-contained-archive-and-trusted-"
            "attestations",
            "rc-admission-and-post-final-tag-verification",
        ],
        "fail-closed release dimensions",
    )


def check_evidence_policy_and_required_ids(document: dict[str, Any]) -> list[str]:
    require_exact_value(
        document["evidence_policy"],
        {
            "closure_location": (
                "external-evidence-self-contained-immutable-archive-not-release-source-tree"
            ),
            "development_ledger_schema": "visa.development-readiness-ledger.v1",
            "development_ledger_path": "specs/release/visa-0.1-readiness.toml",
            "development_receipt_schema": (
                "visa.development-readiness-verifier-receipt.v3"
            ),
            "development_receipt_input_policy": (
                "selected-reproduction-inputs-not-complete-verifier-read-closure-current-"
                "checkout-revalidation-required"
            ),
            "development_path_policy": "repository-relative-regular-file-no-symlink",
            "target_path": "specs/release/visa-0.1.toml",
            "index_schema": "visa.release-readiness-index.v2",
            "receipt_schema": "visa.release-readiness-verifier-receipt.v2",
            "verifier_registry_schema": "visa.release-verifier-registry.v2",
            "verifier_dispatcher_path": "scripts/verify-release-readiness.py",
            "verifier_policy": (
                "closed-required-id-to-typed-verifier-id-dispatch-no-receipt-command-or-cli-"
                "bypass"
            ),
            "verifier_runtime_input_policy": (
                "per-id-closed-path-sha256-kind-version-inventory-bound-by-receipt-and-archive-"
                "manifest"
            ),
            "verifier_input_snapshot_schema": (
                "visa.release-verifier-input-snapshot.v1"
            ),
            "verifier_input_snapshot_policy": (
                "outer-checker-generated-explicit-tagged-source-and-archive-namespaces-exact-"
                "receipt-path-sha256-closure-private-per-id-copy-and-post-run-rehash"
            ),
            "archive_file_bytes_limit": MAX_ARCHIVE_FILE_BYTES,
            "archive_aggregate_bytes_limit": MAX_ARCHIVE_AGGREGATE_BYTES,
            "verifier_receipt_bytes_limit": MAX_VERIFIER_RECEIPT_BYTES,
            "supply_chain_required_input_ids": [
                "rust-toolchain-archive",
                "rust-toolchain-inventory",
                "cargo-vendor-config",
                "cargo-vendor-inventory",
                "cargo-vendor-archive",
                "verifier-host-runtime-inventory",
                "build-producer-inventory",
                "buildx-metadata",
                "oci-layout-inventory",
                "supply-chain-tool-inventory",
                "cargo-deny-config",
                "rustsec-advisory-db",
                "cargo-deny-report",
                "cargo-auditable-inventory",
                "cargo-about-config",
                "cargo-about-template",
                "cargo-about-raw",
                "third-party-notice",
                "cargo-cyclonedx-sbom-set",
                "syft-json-set",
                "dependency-inventory-reconciliation",
            ],
            "nexus_wire_required_input_ids": [
                "nexus-component-source-bundle",
                "nexus-component-source-graph",
                "nexus-native-v1-exported-corpus",
                "release-artifact-inventory",
                "nexus-effect-peer-binary",
                "nexus-effect-peer-build-provenance-bundle",
                "nexus-effect-peer-release-link-bundle",
            ],
            "build_producer_inventory_schema": (
                "visa.release-build-producer-inventory.v1"
            ),
            "build_producer_inventory_path": "build/build-producer-inventory.json",
            "build_producer_inventory_policy": (
                "closed-unique-record-id-set-exactly-equals-derived-build-image-plus-every-"
                "release-artifact-build-record-id-no-orphan-or-duplicate-and-binds-role-"
                "producer-exact-version-binary-sha256-or-action-sha-argv-input-ids-output-"
                "ids-and-builder-image-record"
            ),
            "buildx_metadata_path": "build/buildx-metadata.json",
            "buildx_metadata_policy": (
                "preserve-raw-version-bound-docker-buildx-metadata-json-but-use-only-"
                "containerimage-descriptor-media-type-digest-size-and-equal-containerimage-"
                "digest-as-image-identity"
            ),
            "oci_layout_inventory_schema": "visa.release-oci-layout-file-set.v1",
            "oci_layout_inventory_path": "build/derived-image-oci-inventory.json",
            "oci_layout_output_root": "build/derived-image.oci",
            "oci_layout_file_count_limit": MAX_OCI_LAYOUT_FILES,
            "oci_descriptor_depth_limit": 32,
            "oci_descriptor_count_limit": 8192,
            "oci_blob_bytes_limit": MAX_ARCHIVE_FILE_BYTES,
            "oci_reachable_bytes_limit": MAX_ARCHIVE_AGGREGATE_BYTES,
            "oci_layout_regular_file_profile": (
                "visa-canonical-profile-allows-only-oci-layout-index-json-and-blobs-sha256-"
                "regular-files-empty-producer-internal-directories-have-no-identity"
            ),
            "oci_layout_runtime_input_policy": (
                "tar-false-output-every-regular-file-is-bound-by-the-owned-sorted-file-set-"
                "receipt-input-map-and-archive-manifest-no-derived-tar-or-untyped-dynamic-"
                "runtime-ids"
            ),
            "oci_layout_closure_policy": (
                "typed-verifier-requires-oci-layout-and-index-json-exactly-one-top-level-"
                "result-no-subject-or-attestation-walks-index-manifest-config-and-layer-"
                "descriptors-verifies-media-type-size-sha256-platform-and-no-missing-external-"
                "uninventoried-or-unreferenced-blob-content-with-depth-count-and-byte-bounds"
            ),
            "supply_chain_tool_inventory_policy": (
                "every-selected-producer-records-id-exact-version-binary-sha256-install-"
                "source-or-action-sha-argv-config-and-output-role"
            ),
            "supply_chain_output_policy": (
                "every-policy-sbom-license-auditable-observation-and-reconciliation-output-"
                "is-a-separate-typed-path-and-sha256-bound-input-to-the-supply-chain-verifier"
            ),
            "advisory_freshness_policy": (
                "exact-rc-scan-records-rustsec-db-revision-digest-and-attested-observation-"
                "time-later-database-changes-are-post-release-monitoring-not-retroactive-"
                "proof"
            ),
            "verifier_execution": (
                "release-ready-reruns-byte-identical-tagged-archived-dispatcher-with-python-"
                "isolated-no-site-fixed-argv-clean-environment-private-exact-input-snapshot-"
                "timeout-and-secure-temp-output"
            ),
            "verifier_result_schema": "visa.release-verifier-result.v1",
            "verifier_tcb": (
                "exact-tag-dispatcher-and-invoked-verifier-code-are-release-tcb-private-"
                "snapshot-is-input-closure-not-host-confinement-attestation-alone-does-not-"
                "prove-they-ran"
            ),
            "verifier_host_tcb": (
                "trusted-pre-existing-invoking-python-interpreter-and-stdlib-resolved-git-and-"
                "runtime-kernel-filesystem-and-nonhostile-same-uid-processes-recorded-versions-"
                "are-audit-observations-plus-operator-pinned-gh-and-trusted-root"
            ),
            "git_execution": (
                "resolved-absolute-regular-git-private-cwd-home-empty-template-no-system-or-"
                "global-config-hooks-replace-objects-network-or-prompt"
            ),
            "python_execution": (
                "checker-invocation-python-version-recorded-and-dispatcher-runs-same-absolute-"
                "sys-executable-with-isolated-no-site-and-clean-environment"
            ),
            "build_inventory_schema": "visa.release-build-inventory.v4",
            "build_inventory_generation": (
                "cargo-metadata-format-version-1-locked-per-product-root-target-profile-"
                "feature-set-reachable-resolve-plus-license-source-normalization"
            ),
            "build_inventory_verification": (
                "typed-supply-chain-verifier-extracts-exact-rust-toolchain-tree-and-vendor-"
                "into-private-homes-runs-absolute-cargo-metadata-frozen-offline-and-separately-"
                "validates-producer-records-and-oci-closure-without-executing-docker"
            ),
            "vendor_generation": (
                "cargo-vendor-locked-versioned-dirs-with-source-replacement-config-archive-"
                "and-file-inventory"
            ),
            "oci_build_provenance": (
                "release-time-buildkit-buildx-producer-tcb-records-exact-recipe-context-"
                "platform-output-type-oci-tar-false-provenance-disabled-metadata-file-owned-"
                "per-file-layout-set-descriptor-closure-builder-version-binary-or-action-sha-"
                "argv-and-build-record-id-offline-checker-does-not-rerun-build"
            ),
            "source_to_binary_reproducibility": (
                "not-claimed-artifact-attestation-and-byte-identity-only"
            ),
            "artifact_inventory_schema": "visa.release-artifact-inventory.v3",
            "artifact_inventory_verification": (
                "records-component-source-and-attestation-producer-identities-and-verifies-"
                "artifact-subject-attestation;relationship-is-proved-only-by-nexus-native-v1-"
                "wire-artifact-typed-verifier-with-authenticated-component-material-and-"
                "closed-source-graph"
            ),
            "hash_algorithm": "sha-256",
            "contract_binding": (
                "archived-source-bundle-path-sha256-exact-40-hex-source-revision-annotated-rc-"
                "tag-and-out-of-band-exact-rc-tag-object"
            ),
            "release_candidate_tag": "v0.1.0-rc.<positive-integer>",
            "final_tag": "v0.1.0",
            "candidate_final_relationship": (
                "annotated-final-tag-must-peel-to-the-exact-rc-admitted-source-commit"
            ),
            "closure_states": ["rc-admitted", "final-release-verified"],
            "archive_stage_policy": (
                "separate-immutable-rc-and-final-roots-final-reruns-complete-rc-validation-no-"
                "in-place-append"
            ),
            "final_archive_validation": (
                "final-stage-command-only-rc-stage-command-targets-the-preserved-rc-root"
            ),
            "finalization_schema": "visa.release-finalization-receipt.v1",
            "finalization_policy": (
                "post-tag-attested-receipt-binds-immutable-index-digest-and-annotated-final-"
                "tag-object-exactly-matching-the-out-of-band-trusted-checkout-at-the-rc-"
                "admitted-commit"
            ),
            "target_commit_mutation": "forbidden-after-evidence-generation",
            "required_for_every_id": [
                "evidence-path",
                "evidence-sha256",
                "verifier-receipt-path",
                "verifier-receipt-sha256",
                "typed-verifier-id",
                "verifier-source-path-and-sha256",
                "exact-input-digests-exit-code-and-output-digest",
                "typed-verifier-result-sha256",
                "private-origin-separated-input-snapshot-and-post-run-rehash",
            ],
            "archive_root_policy": (
                "explicit-root-for-archive-content-clean-trusted-checkout-only-for-out-of-band-"
                "head-and-tag-objects-no-ambient-cargo-state"
            ),
            "source_bundle_path": "source/visa-v0.1.0-rc.bundle",
            "source_bundle_policy": (
                "complete-prerequisite-git-bundle-with-annotated-rc-tag-exact-source-commit-"
                "and-out-of-band-matching-tag-object"
            ),
            "final_source_bundle_path": "source/visa-v0.1.0-final.bundle",
            "final_source_bundle_policy": (
                "post-tag-complete-git-bundle-with-annotated-rc-and-final-tags-peeling-to-same-"
                "commit-and-out-of-band-matching-tag-objects"
            ),
            "archived_lock_path": "source/Cargo.lock",
            "archived_toolchain_path": "source/rust-toolchain.toml",
            "archive_manifest_path": "archive/manifest.json",
            "sha256sums_path": "archive/SHA256SUMS",
            "offline_reverify_path": "REVERIFY.md",
            "archive_inventory_policy": (
                "canonical-posix-relative-paths-unique-regular-single-link-files-no-symlink-"
                "device-or-fifo-exact-manifest-and-sha256sums"
            ),
            "reader_limits": (
                "duplicate-json-keys-rejected-per-file-536870912-bytes-aggregate-"
                "4294967296-bytes"
            ),
            "path_policy": (
                "canonical-posix-index-directory-relative-regular-single-link-file-no-symlink-"
                "or-alias"
            ),
            "receipt_policy": (
                "closed-set-typed-verifier-id-source-digest-input-digests-exit-code-and-output-"
                "digest-no-command-string"
            ),
            "attestation_repository": "chenty2333/vISA",
            "attestation_signer_workflow": (
                "chenty2333/vISA/.github/workflows/release-evidence.yml"
            ),
            "attestation_predicate_type": "https://slsa.dev/provenance/v1",
            "attestation_verification": (
                "exact-gh-binary-at-or-above-2.93.0-offline-bundle-custom-trusted-root-repo-"
                "signer-workflow-signer-digest-source-digest-source-ref-deny-self-hosted"
            ),
            "attestation_bootstrap": (
                "trusted-checker-clean-tracked-checkout-head-and-operator-supplied-annotated-"
                "rc-tag-gh-binary-sha256-and-trusted-root-sha256-index-and-archive-may-select-"
                "none-of-these-values"
            ),
            "attestation_verifier_path": "tools/gh",
            "attestation_verifier_minimum_version": "2.93.0",
            "index_attestation_bundle_path": (
                "attestations/index.provenance.sigstore.jsonl"
            ),
            "finalization_attestation_bundle_path": (
                "attestations/finalization.provenance.sigstore.jsonl"
            ),
            "attestation_trusted_root_path": "attestations/trusted_root.jsonl",
            "post_release_claims_ledger": (
                "may-be-committed-after-release-without-moving-the-release-tag"
            ),
        },
        "readiness evidence policy",
    )
    closure = document["release_closure"]
    require_exact_keys(closure, {"required_ids"}, "release closure")
    required = closure["required_ids"]
    require(isinstance(required, list), "required readiness IDs must be a list")
    require(len(required) == len(set(required)), "required readiness IDs must be unique")
    require_exact_value(required, EXPECTED_REQUIRED_IDS, "required release closure IDs")
    return required


def read_direct_regular_file(path: Path, label: str) -> bytes:
    return read_regular_file(path.parent, path.name, label)


def load_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseContractError(f"duplicate JSON key in {label}: {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseContractError(f"cannot parse {label} as JSON") from error
    require(isinstance(document, dict), f"{label} must contain a JSON object")
    return document


def check_development_readiness(
    document: dict[str, Any],
    contract_path: Path,
    ledger_path: Path,
    root: Path,
) -> list[str]:
    required = check_evidence_policy_and_required_ids(document)
    ledger = load_toml_bytes(
        read_direct_regular_file(ledger_path, "development readiness ledger"),
        str(ledger_path),
    )
    require_exact_keys(
        ledger,
        {
            "schema",
            "target_path",
            "target_sha256",
            "status",
            "observed_cells",
            "satisfied_ids",
            "pending_ids",
            "measurements",
            "evidence",
        },
        "development readiness ledger",
    )
    require_exact_value(
        ledger["schema"],
        document["evidence_policy"]["development_ledger_schema"],
        "development readiness ledger schema",
    )
    require_exact_value(
        ledger["target_path"],
        document["evidence_policy"]["target_path"],
        "development readiness target path",
    )
    require_exact_value(
        ledger["status"],
        "development-progress-not-release-evidence",
        "development readiness status",
    )
    observed_cells = ledger["observed_cells"]
    require(isinstance(observed_cells, list), "observed development cells must be a list")
    require(
        len(observed_cells) == len(set(observed_cells)),
        "observed development cells must be unique",
    )
    require(
        set(observed_cells) <= set(EXPECTED_REQUIRED_CELLS),
        "observed development cells must be target release cells",
    )
    require_exact_value(
        ledger["measurements"],
        {
            "preexisting_jsonl": {
                "status": "development-observation-not-immutable-contract",
                "observed_max_jsonl_bytes": 53_663,
                "normative_inner_rpc_cap_bytes": 1_048_576,
                "basis": (
                    "preexisting-native-and-generated-system-jsonl-sample-not-dbus-wire-"
                    "evidence"
                ),
            }
        },
        "development measurements",
    )
    require(
        ledger["measurements"]["preexisting_jsonl"]["observed_max_jsonl_bytes"]
        < ledger["measurements"]["preexisting_jsonl"]["normative_inner_rpc_cap_bytes"],
        "development JSONL observation exceeds the normative inner RPC cap",
    )
    expected_contract = (root / ledger["target_path"]).resolve()
    require(
        contract_path.resolve() == expected_contract,
        "development readiness ledger must bind the validated target path",
    )
    target_bytes = read_regular_file(root, ledger["target_path"], "release target")
    target_sha256 = hashlib.sha256(target_bytes).hexdigest()
    require_exact_value(ledger["target_sha256"], target_sha256, "development target SHA-256")
    satisfied = ledger["satisfied_ids"]
    pending = ledger["pending_ids"]
    for label, values in (("satisfied", satisfied), ("pending", pending)):
        require(isinstance(values, list), f"{label} readiness IDs must be a list")
        require(len(values) == len(set(values)), f"{label} readiness IDs must be unique")
    require(set(satisfied).isdisjoint(pending), "satisfied and pending release IDs must be disjoint")
    require(
        set(satisfied) | set(pending) == set(required),
        "development readiness IDs must partition target required IDs",
    )
    evidence = ledger["evidence"]
    require(isinstance(evidence, list), "development readiness evidence must be a list")
    evidence_ids: list[str] = []
    for entry in evidence:
        require(isinstance(entry, dict), "development readiness evidence entries must be tables")
        require_exact_keys(
            entry,
            {
                "id",
                "evidence_path",
                "evidence_sha256",
                "verifier_receipt_path",
                "verifier_receipt_sha256",
            },
            "development readiness evidence entry",
        )
        readiness_id = entry["id"]
        require(readiness_id in satisfied, f"evidence exists for non-satisfied ID {readiness_id!r}")
        evidence_ids.append(readiness_id)
        require(is_lower_hex(entry["evidence_sha256"], 64), "evidence SHA-256 must be exact")
        require(
            is_lower_hex(entry["verifier_receipt_sha256"], 64),
            "verifier receipt SHA-256 must be exact",
        )
        evidence_bytes = read_regular_file(root, entry["evidence_path"], "development evidence")
        receipt_bytes = read_regular_file(
            root, entry["verifier_receipt_path"], "development verifier receipt"
        )
        require_exact_value(
            hashlib.sha256(evidence_bytes).hexdigest(),
            entry["evidence_sha256"],
            f"{readiness_id} development evidence SHA-256",
        )
        require_exact_value(
            hashlib.sha256(receipt_bytes).hexdigest(),
            entry["verifier_receipt_sha256"],
            f"{readiness_id} development verifier receipt SHA-256",
        )
        receipt = load_json_bytes(receipt_bytes, f"{readiness_id} development verifier receipt")
        require_exact_keys(
            receipt,
            {
                "schema",
                "readiness_id",
                "target_path",
                "target_sha256",
                "verifier_id",
                "verifier_source_path",
                "verifier_source_sha256",
                "verifier_test_path",
                "verifier_test_sha256",
                "exit_code",
                "output_sha256",
                "input_scope",
                "selected_input_sha256",
            },
            f"{readiness_id} development verifier receipt",
        )
        require_exact_value(
            receipt["schema"],
            document["evidence_policy"]["development_receipt_schema"],
            f"{readiness_id} development verifier receipt schema",
        )
        require_exact_value(receipt["readiness_id"], readiness_id, "receipt readiness ID")
        require_exact_value(receipt["target_path"], ledger["target_path"], "receipt target path")
        require_exact_value(receipt["target_sha256"], target_sha256, "receipt target digest")
        require_exact_value(
            receipt["verifier_id"],
            f"visa.development.verify.{readiness_id}.v1",
            f"{readiness_id} development verifier ID",
        )
        require_exact_value(
            receipt["verifier_source_path"],
            "scripts/check-release-contract.py",
            f"{readiness_id} development verifier source path",
        )
        require_exact_value(
            receipt["verifier_test_path"],
            "scripts/test-check-release-contract.py",
            f"{readiness_id} development verifier test path",
        )
        source_sha256 = hashlib.sha256(
            read_regular_file(root, receipt["verifier_source_path"], "development verifier source")
        ).hexdigest()
        test_sha256 = hashlib.sha256(
            read_regular_file(root, receipt["verifier_test_path"], "development verifier test")
        ).hexdigest()
        require_exact_value(
            receipt["verifier_source_sha256"],
            source_sha256,
            f"{readiness_id} development verifier source digest",
        )
        require_exact_value(
            receipt["verifier_test_sha256"],
            test_sha256,
            f"{readiness_id} development verifier test digest",
        )
        require_exact_value(receipt["exit_code"], 0, f"{readiness_id} verifier exit code")
        require_exact_value(
            receipt["output_sha256"],
            entry["evidence_sha256"],
            f"{readiness_id} verifier output digest",
        )
        require_exact_value(
            receipt["input_scope"],
            document["evidence_policy"]["development_receipt_input_policy"],
            f"{readiness_id} development receipt input scope",
        )
        inputs = receipt["selected_input_sha256"]
        require(isinstance(inputs, dict), f"{readiness_id} receipt inputs must be an object")
        require_exact_value(
            inputs.get(entry["evidence_path"]),
            entry["evidence_sha256"],
            f"{readiness_id} receipt evidence input",
        )
        require_exact_value(
            inputs.get(ledger["target_path"]),
            target_sha256,
            f"{readiness_id} receipt target input",
        )
        require_exact_value(
            inputs.get(receipt["verifier_source_path"]),
            source_sha256,
            f"{readiness_id} receipt verifier source input",
        )
        require_exact_value(
            inputs.get(receipt["verifier_test_path"]),
            test_sha256,
            f"{readiness_id} receipt verifier test input",
        )
        require(
            all(isinstance(path, str) and is_lower_hex(digest, 64) for path, digest in inputs.items()),
            f"{readiness_id} receipt input digests must be exact",
        )
        require_exact_value(
            set(inputs),
            {
                entry["evidence_path"],
                ledger["target_path"],
                receipt["verifier_source_path"],
                receipt["verifier_test_path"],
            },
            f"{readiness_id} development selected reproduction input set",
        )
    require(len(evidence_ids) == len(set(evidence_ids)), "development evidence IDs must be unique")
    require_exact_value(
        set(evidence_ids),
        set(satisfied),
        "satisfied development readiness evidence coverage",
    )
    return pending


def trusted_git_path() -> Path:
    candidate = shutil.which("git", path="/usr/bin:/bin")
    require(candidate is not None, "trusted verifier host does not provide git")
    try:
        path = Path(candidate).resolve(strict=True)
        file_stat = path.stat()
    except OSError as error:
        raise ReleaseContractError(f"cannot resolve trusted verifier-host git: {error}") from error
    require(path.is_absolute() and stat.S_ISREG(file_stat.st_mode), "trusted git must be an absolute regular file")
    return path


def run_trusted_git(
    arguments: list[str],
    cwd: Path,
    label: str,
    timeout: int = 30,
) -> bytes:
    with tempfile.TemporaryDirectory(prefix="visa-git-verifier-") as temporary:
        temporary_root = Path(temporary)
        home = temporary_root / "home"
        template = temporary_root / "empty-template"
        home.mkdir(mode=0o700)
        template.mkdir(mode=0o700)
        environment = {
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TZ": "UTC",
        }
        command = [
            str(trusted_git_path()),
            "--no-pager",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            f"init.templateDir={template}",
            *arguments,
        ]
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseContractError(f"cannot run git for {label}: {error}") from error
    require(result.returncode == 0, f"git verification failed for {label}")
    return result.stdout


def trusted_git_version(cwd: Path) -> str:
    raw = run_trusted_git(["--version"], cwd, "verifier-host git version")
    try:
        version = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ReleaseContractError("trusted git version output must be ASCII") from error
    require(re.fullmatch(r"git version [0-9]+\.[0-9]+\.[0-9]+", version) is not None, "trusted git version output drifted")
    return version.removeprefix("git version ")


def trusted_checkout_release_identity(
    expected_source_tag: str,
    release_stage: str,
) -> tuple[str, str, str | None]:
    require(
        re.fullmatch(r"v0\.1\.0-rc\.[1-9][0-9]*", expected_source_tag) is not None,
        "expected source tag must be an exact v0.1.0-rc.N tag",
    )
    require_exact_value(
        run_trusted_git(
            ["status", "--porcelain=v1", "--untracked-files=no"],
            ROOT,
            "trusted release checkout status",
        ),
        b"",
        "trusted release checkout tracked-tree cleanliness",
    )
    raw_revision = run_trusted_git(
        ["rev-parse", "--verify", "HEAD^{commit}"],
        ROOT,
        "trusted release checkout HEAD",
    )
    try:
        revision = raw_revision.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ReleaseContractError("trusted release checkout HEAD must be ASCII") from error
    require(is_lower_hex(revision, 40), "trusted release checkout HEAD must be exact")
    tag_object = require_annotated_tag(
        ROOT,
        expected_source_tag,
        revision,
        "trusted release checkout RC tag",
    )
    final_tag_object: str | None = None
    if release_stage == "final-release-verified":
        final_tag_object = require_annotated_tag(
            ROOT,
            "v0.1.0",
            revision,
            "trusted release checkout final tag",
        )
    else:
        require_exact_value(
            release_stage,
            "rc-admitted",
            "trusted release checkout stage",
        )
    return revision, tag_object, final_tag_object


def git_bytes(root: Path, arguments: list[str], label: str) -> bytes:
    return run_trusted_git(arguments, root, label)


def check_build_inventory(
    inventory: dict[str, Any],
    contract_binding: dict[str, Any],
    build: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    require_exact_keys(
        inventory,
        {
            "schema",
            "target_sha256",
            "source_revision",
            "source_tag",
            "cargo_lock_sha256",
            "rust_toolchain_sha256",
            "build_environment",
            "derived_build_image",
            "workspace_package_count",
            "resolved_package_count",
            "workspace_packages",
            "resolved_packages",
            "product_roots",
            "dependency_edges",
            "direct_dependencies",
        },
        "release build inventory",
    )
    require_exact_value(inventory["schema"], "visa.release-build-inventory.v4", "build inventory schema")
    for field in ("target_sha256", "source_revision", "source_tag"):
        require_exact_value(inventory[field], contract_binding[field], f"build inventory {field}")
    require_exact_value(
        inventory["cargo_lock_sha256"], build["cargo_lock_sha256"], "build inventory Cargo.lock digest"
    )
    require_exact_value(
        inventory["rust_toolchain_sha256"],
        build["rust_toolchain_sha256"],
        "build inventory rust-toolchain digest",
    )
    environment = inventory["build_environment"]
    require(isinstance(environment, dict), "build environment must be an object")
    require_exact_keys(
        environment,
        {
            "base_image",
            "base_manifest_sha256",
            "runtime_inputs",
            "cargo_vendor_argv",
            "cargo_metadata_argv_prefix",
            "buildkit_oci_output_argv",
            "frozen_environment",
            "source_to_binary_reproducibility",
        },
        "build environment",
    )
    require_exact_value(
        environment["base_image"], build["release_build_base_image"], "release build base image"
    )
    require_exact_value(
        environment["base_manifest_sha256"],
        build["release_build_base_image"].rsplit("@sha256:", 1)[1],
        "release build base manifest digest",
    )
    require_exact_value(
        environment["runtime_inputs"], build["runtime_inputs"], "build runtime input binding"
    )
    require_exact_value(
        environment["cargo_vendor_argv"],
        ["cargo", "vendor", "--locked", "--versioned-dirs"],
        "Cargo vendor argv",
    )
    require_exact_value(
        environment["cargo_metadata_argv_prefix"],
        ["cargo", "metadata", "--frozen", "--format-version", "1"],
        "Cargo metadata argv prefix",
    )
    require_exact_value(
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
        "BuildKit OCI output argv",
    )
    require_exact_value(
        environment["frozen_environment"],
        [
            "BUILDX_METADATA_PROVENANCE=disabled",
            "BUILDX_METADATA_WARNINGS=0",
            "CARGO_HOME=<private>",
            "CARGO_NET_OFFLINE=true",
            "GIT_CONFIG_NOSYSTEM=1",
            "HOME=<private>",
            "RUSTUP_HOME=<private>",
        ],
        "frozen build environment",
    )
    require(
        environment["source_to_binary_reproducibility"] is False,
        "build inventory must not claim source-to-binary reproducibility",
    )
    runtime_inputs = environment["runtime_inputs"]
    runtime_inputs_by_id = {
        entry["id"]: entry
        for entry in runtime_inputs
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    }
    require_exact_value(
        len(runtime_inputs_by_id),
        len(runtime_inputs),
        "build runtime input IDs",
    )
    for runtime_id, expected in {
        "build-producer-inventory": {
            "kind": "data",
            "path": "build/build-producer-inventory.json",
            "version": "visa.release-build-producer-inventory.v1",
        },
        "buildx-metadata": {
            "kind": "data",
            "path": "build/buildx-metadata.json",
            "version": "docker-buildx-metadata-json.v1",
        },
        "oci-layout-inventory": {
            "kind": "data",
            "path": "build/derived-image-oci-inventory.json",
            "version": "visa.release-oci-layout-file-set.v1",
        },
    }.items():
        require(runtime_id in runtime_inputs_by_id, f"build runtime input {runtime_id!r} is absent")
        for field, value in expected.items():
            require_exact_value(
                runtime_inputs_by_id[runtime_id][field],
                value,
                f"{runtime_id} {field}",
            )

    derived_image = inventory["derived_build_image"]
    require(isinstance(derived_image, dict), "derived build image binding must be an object")
    require_exact_keys(
        derived_image,
        {
            "schema",
            "build_record_id",
            "builder_name",
            "builder_driver",
            "buildx_version",
            "buildkit_version",
            "cwd",
            "recipe_path",
            "context_path",
            "platform",
            "producer_input_id",
            "metadata_input_id",
            "layout_inventory_input_id",
            "output_root",
            "destination_policy",
            "metadata_parent_policy",
            "descriptor",
        },
        "derived build image binding",
    )
    require_exact_value(
        derived_image["schema"],
        "visa.release-derived-build-image-binding.v1",
        "derived build image binding schema",
    )
    derived_image_record_id = (
        "visa.buildx.derived-image.v1:"
        f"{contract_binding['source_revision']}:linux-amd64"
    )
    require_exact_value(
        derived_image["build_record_id"],
        derived_image_record_id,
        "derived build image record ID",
    )
    for field, value in {
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
    }.items():
        require_exact_value(derived_image[field], value, f"derived build image {field}")
    descriptor = derived_image["descriptor"]
    require(isinstance(descriptor, dict), "derived build image descriptor must be an object")
    require_exact_keys(
        descriptor,
        {"mediaType", "digest", "size"},
        "derived build image descriptor",
    )
    require(
        descriptor["mediaType"]
        in {
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.manifest.v1+json",
        },
        "derived build image descriptor mediaType is invalid",
    )
    require(
        isinstance(descriptor["digest"], str)
        and descriptor["digest"].startswith("sha256:")
        and is_lower_hex(descriptor["digest"].removeprefix("sha256:"), 64),
        "derived build image descriptor digest must be exact SHA-256",
    )
    require(
        type(descriptor["size"]) is int and descriptor["size"] > 0,
        "derived build image descriptor size must be positive",
    )
    workspace_packages = inventory["workspace_packages"]
    resolved_packages = inventory["resolved_packages"]
    require(isinstance(workspace_packages, list) and bool(workspace_packages), "workspace inventory is empty")
    require(isinstance(resolved_packages, list) and bool(resolved_packages), "resolved inventory is empty")
    require_exact_value(
        inventory["workspace_package_count"], len(workspace_packages), "workspace package count"
    )
    require_exact_value(
        inventory["resolved_package_count"], len(resolved_packages), "resolved package count"
    )

    def package_keys(entries: list[Any], label: str) -> set[str]:
        package_ids: list[str] = []
        for entry in entries:
            require(isinstance(entry, dict), f"{label} package entry must be an object")
            require_exact_keys(
                entry,
                {"package_id", "name", "version", "source", "license", "features"},
                f"{label} package entry",
            )
            values = tuple(entry[field] for field in ("package_id", "name", "version", "source", "license"))
            require(
                all(isinstance(value, str) and bool(value) for value in values),
                f"{label} package fields must be non-empty strings",
            )
            features = entry["features"]
            require(
                isinstance(features, list)
                and features == sorted(features)
                and len(features) == len(set(features))
                and all(isinstance(feature, str) and bool(feature) for feature in features),
                f"{label} package features must be sorted unique strings",
            )
            package_ids.append(entry["package_id"])
        require(len(package_ids) == len(set(package_ids)), f"{label} package IDs must be unique")
        return set(package_ids)

    workspace_ids = package_keys(workspace_packages, "workspace")
    resolved_ids = package_keys(resolved_packages, "resolved")
    require(workspace_ids <= resolved_ids, "workspace packages must be covered by resolved inventory")
    require(
        all(entry["source"].startswith("workspace:") for entry in workspace_packages),
        "workspace package sources must be repository-relative workspace identities",
    )

    product_roots = inventory["product_roots"]
    require(isinstance(product_roots, list), "product roots must be a list")
    expected_artifacts = {
        "visa-cli-binary",
        "visa-agent-binary",
        "visa-ownershipd-binary",
        "visa-nexusd-binary",
    }
    root_packages: set[str] = set()
    observed_artifacts: list[str] = []
    for entry in product_roots:
        require(isinstance(entry, dict), "product root entry must be an object")
        require_exact_keys(
            entry,
            {
                "artifact_id",
                "package_id",
                "build_record_id",
                "builder_image_record_id",
                "target",
                "profile",
                "features",
                "metadata_argv",
                "build_argv",
            },
            "product root entry",
        )
        observed_artifacts.append(entry["artifact_id"])
        require(
            isinstance(entry["build_record_id"], str) and bool(entry["build_record_id"]),
            "product root build record ID must be non-empty",
        )
        require_exact_value(
            entry["build_record_id"],
            (
                "visa.cargo.product.v1:"
                f"{entry['artifact_id']}:{contract_binding['source_revision']}"
            ),
            "product root build record ID",
        )
        require_exact_value(
            entry["builder_image_record_id"],
            derived_image_record_id,
            "product root builder image record ID",
        )
        require(entry["package_id"] in workspace_ids, "product root must be a workspace package")
        root_packages.add(entry["package_id"])
        require_exact_value(entry["target"], "x86_64-unknown-linux-gnu", "product root target")
        require_exact_value(entry["profile"], "release", "product root profile")
        for field in ("features", "metadata_argv", "build_argv"):
            values = entry[field]
            require(
                isinstance(values, list)
                and bool(values if field in {"metadata_argv", "build_argv"} else [True])
                and all(isinstance(value, str) and bool(value) for value in values),
                f"product root {field} must be strings",
            )
        require(
            entry["features"] == sorted(entry["features"])
            and len(entry["features"]) == len(set(entry["features"])),
            "product root features must be sorted and unique",
        )
    require_exact_value(set(observed_artifacts), expected_artifacts, "release product root artifacts")
    require(len(observed_artifacts) == len(set(observed_artifacts)), "product root artifacts must be unique")
    build_record_ids = [entry["build_record_id"] for entry in product_roots]
    require(
        len(build_record_ids) == len(set(build_record_ids)),
        "product root build record IDs must be unique",
    )

    edges = inventory["dependency_edges"]
    require(isinstance(edges, list), "dependency edges must be a list")
    adjacency: dict[str, set[str]] = {package_id: set() for package_id in resolved_ids}
    edge_keys: list[tuple[str, str, str, str]] = []
    for edge in edges:
        require(isinstance(edge, dict), "dependency edge must be an object")
        require_exact_keys(edge, {"from", "to", "kind", "target"}, "dependency edge")
        require(edge["from"] in resolved_ids and edge["to"] in resolved_ids, "dependency edge package is absent")
        require(edge["kind"] in ("normal", "build"), "release graph cannot contain dev-only edges")
        require(isinstance(edge["target"], str), "dependency edge target must be a string")
        key = (edge["from"], edge["to"], edge["kind"], edge["target"])
        edge_keys.append(key)
        adjacency[edge["from"]].add(edge["to"])
    require(len(edge_keys) == len(set(edge_keys)), "dependency edges must be unique")
    reachable = set(root_packages)
    frontier = list(root_packages)
    while frontier:
        package_id = frontier.pop()
        for dependency in adjacency[package_id]:
            if dependency not in reachable:
                reachable.add(dependency)
                frontier.append(dependency)
    require_exact_value(reachable, resolved_ids, "product-root reachable resolved graph")

    direct_dependencies = inventory["direct_dependencies"]
    require(isinstance(direct_dependencies, list), "direct dependency requirements must be a list")
    direct_keys: list[tuple[str, str]] = []
    for dependency in direct_dependencies:
        require(isinstance(dependency, dict), "direct dependency must be an object")
        require_exact_keys(
            dependency,
            {"root_package_id", "name", "requirement", "source_kind"},
            "direct dependency",
        )
        require(dependency["root_package_id"] in root_packages, "direct dependency root is not a product root")
        require(
            all(isinstance(dependency[field], str) and bool(dependency[field]) for field in ("name", "requirement", "source_kind")),
            "direct dependency fields must be non-empty strings",
        )
        if dependency["source_kind"] == "registry":
            require(
                re.fullmatch(r"=[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", dependency["requirement"])
                is not None,
                "third-party product-root direct dependencies must use exact equals pins",
            )
        else:
            require_exact_value(dependency["source_kind"], "workspace", "direct dependency source kind")
        direct_keys.append((dependency["root_package_id"], dependency["name"]))
    require(len(direct_keys) == len(set(direct_keys)), "direct dependency requirements must be unique")
    return {entry["artifact_id"]: entry for entry in product_roots}


def check_oci_layout_file_set(
    archive_root: Path,
    inventory_path: str,
    contract_binding: dict[str, Any],
    derived_image: dict[str, Any],
    budget: ArchiveReadBudget,
) -> tuple[set[str], dict[str, str]]:
    raw = read_regular_file(
        archive_root,
        inventory_path,
        "OCI layout file-set inventory",
        budget=budget,
        max_bytes=16 * 1024 * 1024,
    )
    inventory = load_json_bytes(raw, "OCI layout file-set inventory")
    require_exact_keys(
        inventory,
        {
            "schema",
            "target_sha256",
            "source_revision",
            "source_tag",
            "build_record_id",
            "root",
            "platform",
            "metadata_input_id",
            "files",
        },
        "OCI layout file-set inventory",
    )
    require_exact_value(
        inventory["schema"],
        "visa.release-oci-layout-file-set.v1",
        "OCI layout file-set schema",
    )
    for field in ("target_sha256", "source_revision", "source_tag"):
        require_exact_value(
            inventory[field],
            contract_binding[field],
            f"OCI layout file-set {field}",
        )
    require_exact_value(
        inventory["build_record_id"],
        derived_image["build_record_id"],
        "OCI layout file-set build record ID",
    )
    require_exact_value(
        inventory["root"],
        derived_image["output_root"],
        "OCI layout file-set root",
    )
    require_exact_value(
        inventory["platform"],
        derived_image["platform"],
        "OCI layout file-set platform",
    )
    require_exact_value(
        inventory["metadata_input_id"],
        derived_image["metadata_input_id"],
        "OCI layout file-set metadata input ID",
    )

    files = inventory["files"]
    require(
        isinstance(files, list) and 3 <= len(files) <= MAX_OCI_LAYOUT_FILES,
        "OCI layout file-set count is outside the release bound",
    )
    root = derived_image["output_root"]
    root_prefix = f"{root}/"
    observed_paths: list[str] = []
    digests: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for entry in files:
        require(isinstance(entry, dict), "OCI layout file-set entry must be an object")
        require_exact_keys(entry, {"path", "size", "sha256"}, "OCI layout file-set entry")
        path = canonical_relative_path(entry["path"], "OCI layout file-set entry")
        require(path.startswith(root_prefix), "OCI layout file escapes the declared root")
        relative = path.removeprefix(root_prefix)
        if relative not in {"oci-layout", "index.json"}:
            require(
                re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", relative) is not None,
                "OCI layout file path is outside the closed layout shape",
            )
        require(
            type(entry["size"]) is int and entry["size"] >= 0,
            "OCI layout file size must be nonnegative",
        )
        require(is_lower_hex(entry["sha256"], 64), "OCI layout file digest must be exact")
        if relative.startswith("blobs/sha256/"):
            require_exact_value(
                entry["sha256"],
                relative.rsplit("/", 1)[1],
                "OCI blob path-to-content digest",
            )
        file_descriptor, file_stat = open_regular_file_at(
            archive_root,
            path,
            "OCI layout file",
        )
        os.close(file_descriptor)
        require_exact_value(file_stat.st_size, entry["size"], "OCI layout file size")
        require_exact_value(
            hash_regular_file(
                archive_root,
                path,
                "OCI layout file",
                budget=budget,
            ),
            entry["sha256"],
            "OCI layout file digest",
        )
        observed_paths.append(path)
        digests[path] = entry["sha256"]
        sizes[path] = entry["size"]
    require_exact_value(observed_paths, sorted(observed_paths), "OCI layout file-set order")
    require(
        len(observed_paths) == len(set(observed_paths)),
        "OCI layout file-set paths must be unique",
    )
    for required_path in (f"{root}/oci-layout", f"{root}/index.json"):
        require(required_path in digests, f"OCI layout file-set omits {required_path}")
    descriptor = derived_image["descriptor"]
    descriptor_path = f"{root}/blobs/sha256/{descriptor['digest'].removeprefix('sha256:')}"
    require(descriptor_path in digests, "OCI layout file-set omits the root descriptor blob")
    require_exact_value(
        sizes[descriptor_path],
        descriptor["size"],
        "OCI layout root descriptor size",
    )
    return set(observed_paths), digests


def check_artifact_inventory(
    document: dict[str, Any],
    inventory: dict[str, Any],
    contract_binding: dict[str, Any],
    archive_root: Path,
    budget: ArchiveReadBudget,
    attestation_runner: Callable[[list[str]], bytes],
    attestation_verifier_path: Path,
    trusted_root_path: Path,
    product_builds: dict[str, dict[str, Any]] | None = None,
) -> tuple[set[str], dict[str, dict[str, Any]]]:
    require_exact_keys(
        inventory,
        {"schema", "source_revision", "source_tag", "artifacts"},
        "release artifact inventory",
    )
    require_exact_value(inventory["schema"], "visa.release-artifact-inventory.v3", "artifact inventory schema")
    require_exact_value(inventory["source_revision"], contract_binding["source_revision"], "artifact inventory source revision")
    require_exact_value(inventory["source_tag"], contract_binding["source_tag"], "artifact inventory source tag")
    artifacts = inventory["artifacts"]
    require(isinstance(artifacts, list), "artifact inventory entries must be a list")
    expected = {entry["id"]: entry for entry in document["release_artifact"]}
    observed: list[str] = []
    referenced: set[str] = set()
    verified_artifacts: dict[str, dict[str, Any]] = {}
    for entry in artifacts:
        require(isinstance(entry, dict), "artifact inventory entry must be an object")
        require_exact_keys(
            entry,
            {
                "id",
                "kind",
                "path",
                "sha256",
                "size",
                "source_repository",
                "component_source_revision",
                "attestation_source_revision",
                "attestation_source_ref",
                "signer_workflow",
                "target",
                "profile",
                "features",
                "build_argv",
                "build_record_id",
                "attestation_bundle_path",
                "attestation_bundle_sha256",
                "handshake_roles",
            },
            "artifact inventory entry",
        )
        artifact_id = entry["id"]
        require(artifact_id in expected, f"unknown release artifact {artifact_id!r}")
        policy = expected[artifact_id]
        observed.append(artifact_id)
        for inventory_field, policy_field in (
            ("kind", "kind"),
            ("path", "archive_path"),
            ("source_repository", "source_repository"),
            ("signer_workflow", "signer_workflow"),
            ("handshake_roles", "handshake_roles"),
        ):
            require_exact_value(entry[inventory_field], policy[policy_field], f"{artifact_id} {inventory_field}")
        canonical_relative_path(entry["path"], f"{artifact_id} artifact")
        canonical_relative_path(entry["attestation_bundle_path"], f"{artifact_id} attestation")
        require(is_lower_hex(entry["sha256"], 64), f"{artifact_id} SHA-256 must be exact")
        require(type(entry["size"]) is int and entry["size"] >= 0, f"{artifact_id} size must be nonnegative")
        artifact_descriptor, artifact_stat = open_regular_file_at(archive_root, entry["path"], f"{artifact_id} artifact")
        os.close(artifact_descriptor)
        require_exact_value(artifact_stat.st_size, entry["size"], f"{artifact_id} size")
        artifact_bytes = read_regular_file(
            archive_root,
            entry["path"],
            f"{artifact_id} artifact",
            budget=budget,
        )
        require_exact_value(
            hashlib.sha256(artifact_bytes).hexdigest(),
            entry["sha256"],
            f"{artifact_id} digest",
        )
        require_exact_value(
            hash_regular_file(
                archive_root,
                entry["attestation_bundle_path"],
                f"{artifact_id} attestation bundle",
                budget=budget,
            ),
            entry["attestation_bundle_sha256"],
            f"{artifact_id} attestation bundle digest",
        )
        require(
            is_lower_hex(entry["component_source_revision"], 40),
            f"{artifact_id} component source revision must be exact",
        )
        require(
            is_lower_hex(entry["attestation_source_revision"], 40),
            f"{artifact_id} attestation source revision must be exact",
        )
        require(
            isinstance(entry["attestation_source_ref"], str)
            and entry["attestation_source_ref"].startswith("refs/tags/"),
            f"{artifact_id} attestation source ref must be an exact tag ref",
        )
        if entry["source_repository"] == "chenty2333/vISA":
            require_exact_value(
                entry["component_source_revision"],
                contract_binding["source_revision"],
                f"{artifact_id} component source revision",
            )
            require_exact_value(
                entry["attestation_source_revision"],
                contract_binding["source_revision"],
                f"{artifact_id} attestation source revision",
            )
            require_exact_value(
                entry["attestation_source_ref"],
                f"refs/tags/{contract_binding['source_tag']}",
                f"{artifact_id} attestation source ref",
            )
        if "component_source_revision" in policy:
            require_exact_value(
                entry["component_source_revision"],
                policy["component_source_revision"],
                f"{artifact_id} component source revision",
            )
        require_exact_value(
            entry["target"],
            "x86_64-unknown-linux-gnu" if entry["kind"] == "executable" else "noarch",
            f"{artifact_id} target",
        )
        require_exact_value(entry["profile"], "release" if entry["kind"] == "executable" else "source", f"{artifact_id} profile")
        require(
            isinstance(entry["features"], list)
            and entry["features"] == sorted(entry["features"])
            and len(entry["features"]) == len(set(entry["features"]))
            and all(isinstance(value, str) and bool(value) for value in entry["features"]),
            f"{artifact_id} features must be sorted unique strings",
        )
        require(
            isinstance(entry["build_argv"], list)
            and bool(entry["build_argv"])
            and all(isinstance(value, str) and bool(value) for value in entry["build_argv"]),
            f"{artifact_id} build argv must be a non-empty argv array",
        )
        require(
            isinstance(entry["build_record_id"], str) and bool(entry["build_record_id"]),
            f"{artifact_id} build record ID must be non-empty",
        )
        if product_builds is not None and artifact_id in product_builds:
            product_build = product_builds[artifact_id]
            for field in (
                "build_record_id",
                "target",
                "profile",
                "features",
                "build_argv",
            ):
                require_exact_value(
                    entry[field],
                    product_build[field],
                    f"{artifact_id} artifact-to-build {field}",
                )
        build_provenance = verify_attestation(
            attestation_verifier_path,
            archive_root,
            entry["path"],
            artifact_bytes,
            entry["attestation_bundle_path"],
            trusted_root_path,
            entry["source_repository"],
            entry["signer_workflow"],
            entry["attestation_source_revision"],
            entry["attestation_source_ref"],
            attestation_runner,
            budget,
            f"{artifact_id} artifact",
            expected_bundle_sha256=entry["attestation_bundle_sha256"],
        )
        verified_artifacts[artifact_id] = {
            "build_provenance": build_provenance,
            # The Nexus binary is verified twice. Retain the bytes captured
            # above so both signatures are checked against one immutable
            # snapshot instead of re-opening an attacker-controlled archive
            # path between the two checks.
            "subject_snapshot": (
                artifact_bytes
                if artifact_id == "nexus-effect-peer-binary"
                else None
            ),
        }
        referenced.update((entry["path"], entry["attestation_bundle_path"]))
    require_exact_value(observed, list(expected), "release artifact inventory coverage and order")
    return referenced, verified_artifacts


def check_nexus_wire_provenance_binding(
    document: dict[str, Any],
    artifact_inventory: dict[str, Any],
    runtime_inputs: list[dict[str, Any]],
    artifact_inventory_path: str,
    artifact_inventory_sha256: str,
    verified_artifacts: dict[str, dict[str, Any]],
    archive_root: Path,
    budget: ArchiveReadBudget,
    attestation_runner: Callable[[list[str]], bytes],
    attestation_verifier_path: Path,
    trusted_root_path: Path,
) -> None:
    runtime_by_id = {entry["id"]: entry for entry in runtime_inputs}
    require_exact_value(
        len(runtime_by_id),
        len(runtime_inputs),
        "Nexus wire runtime input IDs",
    )
    nexus_entries = [
        entry
        for entry in artifact_inventory["artifacts"]
        if entry["id"] == "nexus-effect-peer-binary"
    ]
    require_exact_value(
        len(nexus_entries),
        1,
        "Nexus effect-peer artifact inventory cardinality",
    )
    nexus_entry = nexus_entries[0]
    for runtime_id, expected in {
        "nexus-component-source-bundle": {"kind": "data"},
        "nexus-component-source-graph": {"kind": "data"},
        "nexus-native-v1-exported-corpus": {"kind": "data"},
        "release-artifact-inventory": {
            "kind": "data",
            "path": artifact_inventory_path,
            "sha256": artifact_inventory_sha256,
        },
        "nexus-effect-peer-binary": {
            "kind": "executable",
            "path": nexus_entry["path"],
            "sha256": nexus_entry["sha256"],
        },
        "nexus-effect-peer-build-provenance-bundle": {
            "kind": "data",
            "path": nexus_entry["attestation_bundle_path"],
            "sha256": nexus_entry["attestation_bundle_sha256"],
        },
        "nexus-effect-peer-release-link-bundle": {
            "kind": "data",
        },
    }.items():
        require(
            runtime_id in runtime_by_id,
            f"Nexus wire runtime input {runtime_id!r} is absent",
        )
        for field, value in expected.items():
            require_exact_value(
                runtime_by_id[runtime_id][field],
                value,
                f"{runtime_id} {field}",
            )

    require(
        runtime_by_id["nexus-effect-peer-release-link-bundle"]["path"]
        != nexus_entry["attestation_bundle_path"],
        "Nexus release Link bundle must be distinct from build provenance bundle",
    )
    verified_artifact = verified_artifacts.get("nexus-effect-peer-binary")
    require(
        isinstance(verified_artifact, dict),
        "authenticated Nexus effect-peer artifact record is absent",
    )
    build_provenance = verified_artifact.get("build_provenance")
    subject_snapshot = verified_artifact.get("subject_snapshot")
    require(
        isinstance(build_provenance, dict),
        "authenticated Nexus effect-peer build provenance is absent",
    )
    require(
        isinstance(subject_snapshot, bytes),
        "captured Nexus effect-peer binary snapshot is absent",
    )
    statement = build_provenance.get("statement")
    certificate = build_provenance.get("certificate")
    require(
        isinstance(statement, dict),
        "authenticated Nexus effect-peer provenance statement is absent",
    )
    require(
        isinstance(certificate, dict),
        "authenticated Nexus effect-peer provenance certificate is absent",
    )
    nexus_policy = document["nexus_wire_artifact"]
    require_exact_value(
        statement.get("predicateType"),
        nexus_policy["build_provenance_predicate_type"],
        "Nexus effect-peer provenance predicate type",
    )
    require_exact_keys(
        statement,
        {"_type", "subject", "predicateType", "predicate"},
        "authenticated Nexus effect-peer build provenance statement",
    )
    require_exact_value(
        statement["_type"],
        "https://in-toto.io/Statement/v1",
        "Nexus effect-peer build provenance statement type",
    )
    require_exact_value(
        statement["subject"],
        [
            {
                "name": nexus_policy["attested_subject_name"],
                "digest": {"sha256": nexus_entry["sha256"]},
            }
        ],
        "Nexus effect-peer build provenance subject",
    )
    predicate = statement.get("predicate")
    require(
        isinstance(predicate, dict),
        "authenticated Nexus effect-peer SLSA predicate is absent",
    )
    require_exact_keys(
        predicate,
        {"buildDefinition", "runDetails"},
        "authenticated Nexus effect-peer SLSA predicate",
    )
    build_definition = predicate.get("buildDefinition")
    require(
        isinstance(build_definition, dict),
        "authenticated Nexus effect-peer buildDefinition is absent",
    )
    require_exact_keys(
        build_definition,
        {
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        },
        "authenticated Nexus effect-peer buildDefinition",
    )
    require_exact_value(
        build_definition["buildType"],
        nexus_policy["build_provenance_build_type"],
        "authenticated Nexus effect-peer build type",
    )
    external_parameters = build_definition.get("externalParameters")
    require(
        isinstance(external_parameters, dict),
        "authenticated Nexus effect-peer externalParameters are absent",
    )
    repository_url = document["nexus_native_v1"]["repository"]
    workflow_path = nexus_policy["build_provenance_workflow_path"]
    source_ref = nexus_entry["attestation_source_ref"]
    source_revision = nexus_entry["attestation_source_revision"]
    workflow_uri = f"{repository_url}/{workflow_path}@{source_ref}"
    require_exact_value(
        external_parameters,
        {
            "workflow": {
                "ref": source_ref,
                "repository": repository_url,
                "path": workflow_path,
            }
        },
        "authenticated Nexus effect-peer external workflow parameters",
    )
    internal_parameters = build_definition.get("internalParameters")
    require(
        isinstance(internal_parameters, dict),
        "authenticated Nexus effect-peer internalParameters are absent",
    )
    require_exact_keys(
        internal_parameters,
        {"github"},
        "authenticated Nexus effect-peer internalParameters",
    )
    github_parameters = internal_parameters["github"]
    require(
        isinstance(github_parameters, dict),
        "authenticated Nexus effect-peer internal GitHub parameters are absent",
    )
    require_exact_keys(
        github_parameters,
        {
            "event_name",
            "repository_id",
            "repository_owner_id",
            "runner_environment",
        },
        "authenticated Nexus effect-peer internal GitHub parameters",
    )
    require_exact_value(
        github_parameters["event_name"],
        nexus_policy["build_provenance_event_name"],
        "authenticated Nexus effect-peer workflow event",
    )
    require_exact_value(
        github_parameters["event_name"],
        certificate.get("buildTrigger"),
        "Nexus effect-peer workflow event against certificate",
    )
    if certificate.get("githubWorkflowTrigger") is not None:
        require_exact_value(
            github_parameters["event_name"],
            certificate["githubWorkflowTrigger"],
            "Nexus effect-peer workflow event against legacy certificate extension",
        )
    require_exact_value(
        github_parameters["repository_id"],
        certificate.get("sourceRepositoryIdentifier"),
        "Nexus effect-peer repository ID against certificate",
    )
    require_exact_value(
        github_parameters["repository_owner_id"],
        certificate.get("sourceRepositoryOwnerIdentifier"),
        "Nexus effect-peer repository owner ID against certificate",
    )
    require_exact_value(
        github_parameters["runner_environment"],
        nexus_policy["build_provenance_runner_environment"],
        "authenticated Nexus effect-peer runner environment",
    )
    require_exact_value(
        github_parameters["runner_environment"],
        certificate.get("runnerEnvironment"),
        "Nexus effect-peer runner environment against certificate",
    )
    resolved_dependencies = build_definition.get("resolvedDependencies")
    require(
        isinstance(resolved_dependencies, list),
        "authenticated Nexus effect-peer resolvedDependencies are absent",
    )
    require_exact_value(
        resolved_dependencies,
        [
            {
                "uri": f"git+{repository_url}@{source_ref}",
                "digest": {"gitCommit": source_revision},
            }
        ],
        "authenticated Nexus effect-peer producer source dependency",
    )
    run_details = predicate.get("runDetails")
    require(
        isinstance(run_details, dict),
        "authenticated Nexus effect-peer runDetails are absent",
    )
    require_exact_keys(
        run_details,
        {"builder", "metadata"},
        "authenticated Nexus effect-peer runDetails",
    )
    require_exact_value(
        run_details["builder"],
        {"id": workflow_uri},
        "authenticated Nexus effect-peer builder",
    )
    require_exact_value(
        run_details["builder"]["id"],
        certificate.get("buildSignerURI"),
        "Nexus effect-peer builder against certificate",
    )
    require_exact_value(
        run_details["metadata"],
        {"invocationId": certificate.get("runInvocationURI")},
        "authenticated Nexus effect-peer invocation against certificate",
    )

    link_runtime = runtime_by_id["nexus-effect-peer-release-link-bundle"]
    release_link = verify_attestation(
        attestation_verifier_path,
        archive_root,
        nexus_entry["path"],
        subject_snapshot,
        link_runtime["path"],
        trusted_root_path,
        nexus_entry["source_repository"],
        nexus_entry["signer_workflow"],
        source_revision,
        source_ref,
        attestation_runner,
        budget,
        "Nexus effect-peer release Link",
        expected_bundle_sha256=link_runtime["sha256"],
        predicate_type=nexus_policy["release_link_predicate_type"],
    )
    link_statement = release_link["statement"]
    link_certificate = release_link["certificate"]
    certificate_coordinates = (
        "subjectAlternativeName",
        "issuer",
        "buildSignerURI",
        "buildSignerDigest",
        "runnerEnvironment",
        "sourceRepositoryURI",
        "sourceRepositoryDigest",
        "sourceRepositoryRef",
        "sourceRepositoryIdentifier",
        "sourceRepositoryOwnerURI",
        "sourceRepositoryOwnerIdentifier",
        "buildConfigURI",
        "buildConfigDigest",
        "buildTrigger",
        "runInvocationURI",
    )
    require_exact_value(
        {field: link_certificate.get(field) for field in certificate_coordinates},
        {field: certificate.get(field) for field in certificate_coordinates},
        "Nexus build provenance and release Link certificate coordinates",
    )
    require_exact_keys(
        link_statement,
        {"_type", "subject", "predicateType", "predicate"},
        "authenticated Nexus effect-peer release Link statement",
    )
    require_exact_value(
        link_statement["_type"],
        "https://in-toto.io/Statement/v1",
        "Nexus effect-peer release Link statement type",
    )
    require_exact_value(
        link_statement["subject"],
        [
            {
                "name": nexus_policy["attested_subject_name"],
                "digest": {"sha256": nexus_entry["sha256"]},
            }
        ],
        "Nexus effect-peer release Link subject",
    )
    link_predicate = link_statement.get("predicate")
    require(
        isinstance(link_predicate, dict),
        "authenticated Nexus effect-peer release Link predicate is absent",
    )
    require_exact_keys(
        link_predicate,
        {"name", "command", "materials", "byproducts", "environment"},
        "authenticated Nexus effect-peer release Link predicate",
    )
    require_exact_value(
        link_predicate["name"],
        nexus_policy["release_link_name"],
        "authenticated Nexus effect-peer release Link step name",
    )
    require_exact_value(
        link_predicate["command"],
        nexus_entry["build_argv"],
        "authenticated Nexus effect-peer release Link command",
    )
    require_exact_value(
        link_predicate["byproducts"],
        {
            nexus_policy["release_link_build_record_byproduct"]: (
                nexus_entry["build_record_id"]
            )
        },
        "authenticated Nexus effect-peer release Link byproducts",
    )
    require_exact_value(
        link_predicate["environment"],
        {},
        "authenticated Nexus effect-peer release Link environment",
    )
    materials = link_predicate["materials"]
    require(
        isinstance(materials, list),
        "authenticated Nexus effect-peer release Link materials are absent",
    )
    material_names: list[str] = []
    for material in materials:
        require(
            isinstance(material, dict),
            "authenticated Nexus effect-peer release Link material must be an object",
        )
        name = material.get("name")
        require(
            isinstance(name, str) and bool(name),
            "authenticated Nexus effect-peer release Link material name must be non-empty",
        )
        material_names.append(name)
    require_exact_value(
        len(material_names),
        len(set(material_names)),
        "authenticated Nexus effect-peer release Link material names",
    )
    require_exact_value(
        material_names,
        nexus_policy["release_link_material_names"],
        "Nexus effect-peer release Link material names and order",
    )

    component_revision = nexus_policy["release_component_revision"]
    expected_materials = [
        {
            "name": "nexus-component-source-revision",
            "uri": (
                f"git+{repository_url}@{component_revision}"
            ),
            "digest": {"gitCommit": component_revision},
        },
        *[
            {
                "name": runtime_id,
                "digest": {"sha256": runtime_by_id[runtime_id]["sha256"]},
            }
            for runtime_id in (
                "nexus-component-source-bundle",
                "nexus-component-source-graph",
                "nexus-native-v1-exported-corpus",
            )
        ],
    ]
    require_exact_value(
        materials,
        expected_materials,
        "authenticated Nexus effect-peer release Link materials",
    )


def default_attestation_runner(arguments: list[str]) -> bytes:
    with tempfile.TemporaryDirectory(prefix="visa-gh-verifier-") as temporary:
        temporary_root = Path(temporary)
        home = temporary_root / "home"
        config = temporary_root / "config"
        cache = temporary_root / "cache"
        for directory in (home, config, cache):
            directory.mkdir(mode=0o700)
        environment = {
            "GH_CONFIG_DIR": str(config / "gh"),
            "GH_PROMPT_DISABLED": "1",
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": "/usr/bin:/bin",
            "TZ": "UTC",
            "XDG_CACHE_HOME": str(cache),
            "XDG_CONFIG_HOME": str(config),
        }
        try:
            result = subprocess.run(
                arguments,
                cwd=temporary_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseContractError(
                f"cannot execute trusted attestation verifier: {error}"
            ) from error
    require(result.returncode == 0, "trusted GitHub/Sigstore verifier command failed")
    return result.stdout


def prepare_pinned_attestation_verifier(
    archive_root: Path,
    relative_path: str,
    indexed_sha256: str,
    expected_sha256: str,
    budget: ArchiveReadBudget,
) -> tuple[PrivateTemporaryDirectory, Path]:
    """Copy independently pinned verifier bytes to a private executable path.

    The archive/index may record the digest, but only the caller's expected
    digest bootstraps trust.  Executing a private copy also keeps the verified
    bytes stable if an untrusted archive path is replaced after it is read.
    """

    require(
        is_lower_hex(expected_sha256, 64),
        "operator-supplied attestation verifier SHA-256 must be exact",
    )
    require_exact_value(
        indexed_sha256,
        expected_sha256,
        "archived attestation verifier out-of-band digest",
    )
    raw = read_regular_file(
        archive_root,
        relative_path,
        "archived attestation verifier",
        budget=budget,
    )
    require_exact_value(
        hashlib.sha256(raw).hexdigest(),
        expected_sha256,
        "archived attestation verifier digest",
    )
    temporary = PrivateTemporaryDirectory(prefix="visa-attestation-verifier-")
    private_path = Path(temporary.name) / "gh"
    descriptor = os.open(
        private_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o500,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "cannot copy pinned attestation verifier")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require_exact_value(
        hashlib.sha256(read_direct_regular_file(private_path, "private attestation verifier")).hexdigest(),
        expected_sha256,
        "private attestation verifier digest",
    )
    return temporary, private_path.resolve()


def prepare_pinned_trusted_root(
    archive_root: Path,
    relative_path: str,
    indexed_sha256: str,
    expected_sha256: str,
    private_directory: Path,
    budget: ArchiveReadBudget,
) -> Path:
    require(
        is_lower_hex(expected_sha256, 64),
        "operator-supplied trusted-root SHA-256 must be exact",
    )
    require_exact_value(
        indexed_sha256,
        expected_sha256,
        "archived trusted root out-of-band digest",
    )
    raw = read_regular_file(
        archive_root,
        relative_path,
        "archived attestation trusted root",
        budget=budget,
    )
    require_exact_value(
        hashlib.sha256(raw).hexdigest(),
        expected_sha256,
        "archived attestation trusted root digest",
    )
    private_path = private_directory / "trusted-root.jsonl"
    descriptor = os.open(
        private_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "cannot copy pinned attestation trusted root")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require_exact_value(
        hashlib.sha256(read_direct_regular_file(private_path, "private attestation trusted root")).hexdigest(),
        expected_sha256,
        "private attestation trusted root digest",
    )
    return private_path.resolve()


def check_attestation_verifier_version(
    verifier_path: Path,
    expected_version: str,
    runner: Callable[[list[str]], bytes],
) -> None:
    output = runner([str(verifier_path), "version"])
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseContractError("attestation verifier version output must be UTF-8") from error
    require(len(lines) == 2, "attestation verifier version output shape drifted")
    require(
        re.fullmatch(rf"gh version {re.escape(expected_version)} \([^)]+\)", lines[0]) is not None,
        "attestation verifier version drifted",
    )
    require_exact_value(
        lines[1],
        f"https://github.com/cli/cli/releases/tag/v{expected_version}",
        "attestation verifier release URL",
    )


def write_private_regular_copy(
    directory: Path,
    name: str,
    raw: bytes,
    mode: int = 0o400,
) -> Path:
    path = directory / name
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, f"cannot create private copy {name}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    require_exact_value(
        read_direct_regular_file(path, f"private copy {name}"),
        raw,
        f"private copy {name} bytes",
    )
    return path.resolve()


def open_private_tree_destination(
    root: Path,
    relative: str,
    label: str,
    mode: int = 0o400,
) -> int:
    canonical_relative_path(relative, label)
    directory_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current: int | None = None
    try:
        current = os.open(root, directory_flags)
        parts = relative.split("/")
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=current)
            except FileExistsError:
                pass
            child = os.open(part, directory_flags, dir_fd=current)
            os.close(current)
            current = child
        return os.open(
            parts[-1],
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=current,
        )
    except OSError as error:
        raise ReleaseContractError(
            f"cannot create private {label} {relative}: {error}"
        ) from error
    finally:
        if current is not None:
            os.close(current)


def write_all(file_descriptor: int, raw: bytes, label: str) -> None:
    view = memoryview(raw)
    while view:
        try:
            written = os.write(file_descriptor, view)
        except OSError as error:
            raise ReleaseContractError(f"cannot write {label}: {error}") from error
        require(written > 0, f"cannot write {label}")
        view = view[written:]


def write_private_tree_bytes(
    root: Path,
    relative: str,
    raw: bytes,
    label: str,
) -> None:
    destination = open_private_tree_destination(root, relative, label)
    try:
        write_all(destination, raw, label)
        os.fsync(destination)
    finally:
        os.close(destination)
    require_exact_value(
        read_regular_file(root, relative, label),
        raw,
        f"{label} bytes",
    )


def copy_verified_archive_file_to_private(
    archive_root: Path,
    relative: str,
    expected_sha256: str,
    snapshot_root: Path,
    snapshot_relative: str,
    budget: ArchiveReadBudget,
    label: str,
) -> None:
    require(is_lower_hex(expected_sha256, 64), f"{label} digest must be exact")
    source, source_stat = open_regular_file_at(archive_root, relative, label)
    require(
        source_stat.st_size <= MAX_ARCHIVE_FILE_BYTES,
        f"{label} exceeds the file bound: {relative}",
    )
    budget.account(relative, source_stat, label)
    destination = open_private_tree_destination(
        snapshot_root,
        snapshot_relative,
        f"{label} snapshot",
    )
    digest = hashlib.sha256()
    remaining = source_stat.st_size
    try:
        while remaining:
            chunk = os.read(source, min(remaining, 1024 * 1024))
            require(bool(chunk), f"{label} changed while snapshotting: {relative}")
            digest.update(chunk)
            write_all(destination, chunk, f"{label} snapshot")
            remaining -= len(chunk)
        require(
            not os.read(source, 1),
            f"{label} grew while snapshotting: {relative}",
        )
        after = os.fstat(source)
        require(
            (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            == (
                source_stat.st_dev,
                source_stat.st_ino,
                source_stat.st_mode,
                source_stat.st_nlink,
                source_stat.st_size,
                source_stat.st_mtime_ns,
                source_stat.st_ctime_ns,
            ),
            f"{label} metadata changed while snapshotting: {relative}",
        )
        os.fsync(destination)
    except OSError as error:
        raise ReleaseContractError(
            f"cannot snapshot {label} {relative}: {error}"
        ) from error
    finally:
        os.close(source)
        os.close(destination)
    require_exact_value(
        digest.hexdigest(),
        expected_sha256,
        f"{label} snapshot digest",
    )
    require_exact_value(
        hash_regular_file(
            snapshot_root,
            snapshot_relative,
            f"{label} private snapshot",
        ),
        expected_sha256,
        f"{label} private snapshot digest",
    )


def add_snapshot_archive_input(
    archive_inputs: dict[str, dict[str, Any]],
    path: str,
    sha256: str,
    role: str,
    label: str,
) -> None:
    canonical_relative_path(path, label)
    require(is_lower_hex(sha256, 64), f"{label} digest must be exact")
    require(isinstance(role, str) and bool(role), f"{label} role must be non-empty")
    existing = archive_inputs.get(path)
    if existing is None:
        archive_inputs[path] = {"sha256": sha256, "roles": [role]}
        return
    require_exact_value(existing["sha256"], sha256, f"{label} aliased path digest")
    require(role not in existing["roles"], f"{label} duplicates role {role!r} at {path}")
    existing["roles"].append(role)


def prepare_closed_input_snapshot(
    snapshot_root: Path,
    readiness_id: str,
    source_revision: str,
    source_tag: str,
    evidence_path: str,
    evidence_sha256: str,
    source_inputs: dict[str, dict[str, Any]],
    archive_inputs: dict[str, dict[str, Any]],
    archive_root: Path,
    archive_payload_paths: set[str],
    budget: ArchiveReadBudget,
    snapshot_schema: str,
) -> dict[str, str]:
    require(
        set(source_inputs).isdisjoint(archive_inputs),
        f"{readiness_id} tagged-source/archive input origin collision",
    )
    require(
        set(archive_inputs) <= archive_payload_paths,
        f"{readiness_id} archive snapshot input is outside the authenticated payload",
    )
    all_logical_paths = sorted([*source_inputs, *archive_inputs])
    for previous, current in zip(all_logical_paths, all_logical_paths[1:]):
        require(
            not current.startswith(f"{previous}/"),
            f"{readiness_id} verifier input path aliases a parent file: "
            f"{previous!r} and {current!r}",
        )

    source_manifest: list[dict[str, Any]] = []
    archive_manifest: list[dict[str, Any]] = []
    expected_snapshot_files: dict[str, str] = {}
    for path in sorted(source_inputs):
        binding = source_inputs[path]
        require_exact_keys(
            binding,
            {"bytes", "sha256", "roles"},
            f"{readiness_id} tagged-source snapshot binding",
        )
        raw = binding["bytes"]
        digest = binding["sha256"]
        roles = binding["roles"]
        require(isinstance(raw, bytes), f"{readiness_id} tagged-source bytes are invalid")
        require(is_lower_hex(digest, 64), f"{readiness_id} tagged-source digest is invalid")
        require_exact_value(
            hashlib.sha256(raw).hexdigest(),
            digest,
            f"{readiness_id} tagged-source input digest {path}",
        )
        require(
            isinstance(roles, list)
            and roles == sorted(roles)
            and len(roles) == len(set(roles))
            and all(isinstance(role, str) and bool(role) for role in roles),
            f"{readiness_id} tagged-source roles are invalid",
        )
        physical = f"tagged-source/{path}"
        write_private_tree_bytes(
            snapshot_root,
            physical,
            raw,
            f"{readiness_id} tagged-source input",
        )
        expected_snapshot_files[physical] = digest
        source_manifest.append(
            {
                "origin": "tagged-source",
                "path": path,
                "sha256": digest,
                "roles": roles,
            }
        )

    for path in sorted(archive_inputs):
        binding = archive_inputs[path]
        require_exact_keys(
            binding,
            {"sha256", "roles"},
            f"{readiness_id} archive snapshot binding",
        )
        digest = binding["sha256"]
        roles = sorted(binding["roles"])
        require(
            len(roles) == len(set(roles))
            and all(isinstance(role, str) and bool(role) for role in roles),
            f"{readiness_id} archive roles are invalid",
        )
        physical = f"archive/{path}"
        copy_verified_archive_file_to_private(
            archive_root,
            path,
            digest,
            snapshot_root,
            physical,
            budget,
            f"{readiness_id} archive input",
        )
        expected_snapshot_files[physical] = digest
        archive_manifest.append(
            {
                "origin": "archive",
                "path": path,
                "sha256": digest,
                "roles": roles,
            }
        )

    manifest = {
        "schema": snapshot_schema,
        "readiness_id": readiness_id,
        "source_revision": source_revision,
        "source_tag": source_tag,
        "evidence": {
            "origin": "archive",
            "path": evidence_path,
            "sha256": evidence_sha256,
        },
        "tagged_source_inputs": source_manifest,
        "archive_inputs": archive_manifest,
    }
    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    write_private_tree_bytes(
        snapshot_root,
        "input-manifest.json",
        manifest_bytes,
        f"{readiness_id} input snapshot manifest",
    )
    expected_snapshot_files["input-manifest.json"] = hashlib.sha256(
        manifest_bytes
    ).hexdigest()
    return expected_snapshot_files


def verify_closed_input_snapshot(
    snapshot_root: Path,
    expected_snapshot_files: dict[str, str],
    readiness_id: str,
) -> None:
    require_exact_value(
        archive_file_set(snapshot_root),
        set(expected_snapshot_files),
        f"{readiness_id} exact private input snapshot file set",
    )
    for path, expected_sha256 in expected_snapshot_files.items():
        require_exact_value(
            hash_regular_file(
                snapshot_root,
                path,
                f"{readiness_id} post-verifier input snapshot",
            ),
            expected_sha256,
            f"{readiness_id} post-verifier input snapshot digest {path}",
        )


def invoke_release_verifier_with_snapshot(
    dispatcher_path: Path,
    dispatcher_sha256: str,
    readiness_id: str,
    source_revision: str,
    source_tag: str,
    evidence_path: str,
    evidence_sha256: str,
    receipt_inputs: dict[str, str],
    source_inputs: dict[str, dict[str, Any]],
    archive_inputs: dict[str, dict[str, Any]],
    archive_root: Path,
    archive_payload_paths: set[str],
    budget: ArchiveReadBudget,
    snapshot_schema: str,
    runner: Callable[[Path, str, Path], tuple[int, bytes, bytes]],
) -> tuple[int, bytes, bytes]:
    require_exact_value(
        hashlib.sha256(
            read_direct_regular_file(
                dispatcher_path,
                f"{readiness_id} private release dispatcher",
            )
        ).hexdigest(),
        dispatcher_sha256,
        f"{readiness_id} pre-verifier private dispatcher digest",
    )
    expected_input_sha256 = {
        path: binding["sha256"] for path, binding in source_inputs.items()
    }
    expected_input_sha256.update(
        {path: binding["sha256"] for path, binding in archive_inputs.items()}
    )
    require_exact_value(
        receipt_inputs,
        expected_input_sha256,
        f"{readiness_id} closed typed verifier input digest map",
    )
    with tempfile.TemporaryDirectory(prefix="visa-release-input-snapshot-") as temporary:
        snapshot_root = Path(temporary) / "input"
        snapshot_root.mkdir(mode=0o700)
        expected_snapshot_files = prepare_closed_input_snapshot(
            snapshot_root,
            readiness_id,
            source_revision,
            source_tag,
            evidence_path,
            evidence_sha256,
            source_inputs,
            archive_inputs,
            archive_root,
            archive_payload_paths,
            budget,
            snapshot_schema,
        )
        try:
            result = runner(dispatcher_path, readiness_id, snapshot_root)
        finally:
            verify_closed_input_snapshot(
                snapshot_root,
                expected_snapshot_files,
                readiness_id,
            )
            require_exact_value(
                hashlib.sha256(
                    read_direct_regular_file(
                        dispatcher_path,
                        f"{readiness_id} private release dispatcher",
                    )
                ).hexdigest(),
                dispatcher_sha256,
                f"{readiness_id} post-verifier private dispatcher digest",
            )
        return result


def default_release_verifier_runner(
    dispatcher_path: Path,
    readiness_id: str,
    input_snapshot: Path,
) -> tuple[int, bytes, bytes]:
    with tempfile.TemporaryDirectory(prefix="visa-release-verifier-") as temporary:
        temporary_root = Path(temporary)
        home = temporary_root / "home"
        empty_bin = temporary_root / "empty-bin"
        home.mkdir(mode=0o700)
        empty_bin.mkdir(mode=0o700)
        output_path = temporary_root / "verified-evidence.bin"
        environment = {
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": str(empty_bin),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
        }
        arguments = [
            sys.executable,
            "-I",
            "-S",
            str(dispatcher_path),
            "--id",
            readiness_id,
            "--input-snapshot",
            str(input_snapshot),
            "--output",
            str(output_path),
        ]
        try:
            result = subprocess.run(
                arguments,
                cwd=temporary_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseContractError(
                f"cannot execute typed release verifier {readiness_id}: {error}"
            ) from error
        require(
            len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 1024 * 1024,
            f"typed release verifier {readiness_id} exceeded the output bound",
        )
        output = read_optional_regular_file(
            temporary_root,
            "verified-evidence.bin",
            f"typed release verifier {readiness_id} output",
            max_bytes=MAX_ARCHIVE_FILE_BYTES,
        )
        if output is None:
            output = b""
        return result.returncode, result.stdout, output


def verify_attestation(
    attestation_verifier_path: Path,
    archive_root: Path,
    subject_path: str,
    subject: bytes,
    bundle_path: str,
    trusted_root_path: Path,
    repository: str,
    signer_workflow: str,
    source_revision: str,
    source_ref: str,
    runner: Callable[[list[str]], bytes],
    budget: ArchiveReadBudget,
    label: str,
    expected_bundle_sha256: str | None = None,
    predicate_type: str = "https://slsa.dev/provenance/v1",
) -> dict[str, Any]:
    for relative in (subject_path, bundle_path):
        canonical_relative_path(relative, label)
    require(trusted_root_path.is_absolute(), f"{label} trusted root path must be absolute")
    require(isinstance(subject, bytes), f"{label} subject snapshot must be bytes")
    bundle = read_regular_file(
        archive_root,
        bundle_path,
        f"{label} attestation bundle",
        budget=budget,
        max_bytes=64 * 1024 * 1024,
    )
    if expected_bundle_sha256 is not None:
        require(
            is_lower_hex(expected_bundle_sha256, 64),
            f"{label} expected attestation bundle SHA-256 must be exact",
        )
        require_exact_value(
            hashlib.sha256(bundle).hexdigest(),
            expected_bundle_sha256,
            f"{label} captured attestation bundle digest",
        )
    with tempfile.TemporaryDirectory(prefix="visa-attestation-input-") as temporary:
        private_root = Path(temporary)
        private_subject = write_private_regular_copy(private_root, "subject", subject)
        private_bundle = write_private_regular_copy(private_root, "bundle.jsonl", bundle)
        arguments = [
            str(attestation_verifier_path),
            "attestation",
            "verify",
            str(private_subject),
            "--repo",
            repository,
            "--signer-workflow",
            signer_workflow,
            "--signer-digest",
            source_revision,
            "--source-digest",
            source_revision,
            "--source-ref",
            source_ref,
            "--predicate-type",
            predicate_type,
            "--bundle",
            str(private_bundle),
            "--custom-trusted-root",
            str(trusted_root_path),
            "--deny-self-hosted-runners",
            "--format",
            "json",
        ]
        output = runner(arguments)
    try:
        result = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseContractError(f"trusted attestation verifier returned invalid JSON for {label}") from error
    require(
        isinstance(result, list) and len(result) == 1,
        f"trusted attestation verifier must return exactly one result for {label}",
    )
    verified = result[0]
    require(
        isinstance(verified, dict)
        and "attestation" in verified
        and "verificationResult" in verified,
        f"trusted attestation verifier result schema is invalid for {label}",
    )
    require(
        isinstance(verified["attestation"], dict),
        f"trusted attestation object is invalid for {label}",
    )
    verification_result = verified["verificationResult"]
    require(
        isinstance(verification_result, dict),
        f"trusted attestation verificationResult is invalid for {label}",
    )
    statement = verification_result.get("statement")
    require(
        isinstance(statement, dict),
        f"trusted attestation statement is missing for {label}",
    )
    require_exact_value(
        statement.get("_type"),
        "https://in-toto.io/Statement/v1",
        f"trusted attestation statement type for {label}",
    )
    require_exact_value(
        statement.get("predicateType"),
        predicate_type,
        f"trusted attestation predicate type for {label}",
    )
    subjects = statement.get("subject")
    require(
        isinstance(subjects, list) and len(subjects) == 1,
        f"trusted attestation must bind exactly one subject for {label}",
    )
    attested_subject = subjects[0]
    require(
        isinstance(attested_subject, dict) and isinstance(attested_subject.get("digest"), dict),
        f"trusted attestation subject digest is invalid for {label}",
    )
    require_exact_value(
        attested_subject["digest"].get("sha256"),
        hashlib.sha256(subject).hexdigest(),
        f"trusted attestation subject SHA-256 for {label}",
    )
    signature = verification_result.get("signature")
    require(
        isinstance(signature, dict),
        f"trusted attestation signature is missing for {label}",
    )
    certificate = signature.get("certificate")
    require(
        isinstance(certificate, dict),
        f"trusted attestation certificate is missing for {label}",
    )
    repository_url = f"https://github.com/{repository}"
    owner = repository.split("/", 1)[0]
    workflow_uri = f"https://github.com/{signer_workflow}@{source_ref}"
    expected_certificate = {
        "subjectAlternativeName": workflow_uri,
        "issuer": "https://token.actions.githubusercontent.com",
        "buildSignerURI": workflow_uri,
        "buildSignerDigest": source_revision,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": repository_url,
        "sourceRepositoryDigest": source_revision,
        "sourceRepositoryRef": source_ref,
        "sourceRepositoryOwnerURI": f"https://github.com/{owner}",
        "buildConfigURI": workflow_uri,
        "buildConfigDigest": source_revision,
    }
    for field, expected in expected_certificate.items():
        require_exact_value(
            certificate.get(field),
            expected,
            f"trusted attestation certificate {field} for {label}",
        )
    for field in (
        "sourceRepositoryIdentifier",
        "sourceRepositoryOwnerIdentifier",
    ):
        require(
            isinstance(certificate.get(field), str)
            and re.fullmatch(r"[1-9][0-9]*", certificate[field]) is not None,
            f"trusted attestation certificate {field} must be a positive decimal ID for {label}",
        )
    require(
        isinstance(certificate.get("runInvocationURI"), str)
        and re.fullmatch(
            rf"{re.escape(repository_url)}/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*",
            certificate["runInvocationURI"],
        )
        is not None,
        f"trusted attestation certificate runInvocationURI is invalid for {label}",
    )
    return {
        "statement": statement,
        "certificate": certificate,
    }


def clone_source_bundle(bundle: bytes, destination: Path, label: str) -> Path:
    bundle_path = destination.with_suffix(".bundle")
    bundle_path.write_bytes(bundle)
    repository = destination.with_suffix(".git")
    run_trusted_git(
        [
            "clone",
            "--bare",
            "--quiet",
            "--no-local",
            str(bundle_path),
            str(repository),
        ],
        destination.parent,
        label,
        timeout=60,
    )
    return repository


def require_annotated_tag(repository: Path, tag: str, revision: str, label: str) -> str:
    object_type = git_bytes(repository, ["cat-file", "-t", f"refs/tags/{tag}"], label).decode().strip()
    require_exact_value(object_type, "tag", f"{label} object type")
    tag_object = git_bytes(repository, ["rev-parse", f"refs/tags/{tag}"], label).decode().strip()
    require(is_lower_hex(tag_object, 40), f"{label} object ID must be exact")
    peeled = git_bytes(repository, ["rev-parse", f"refs/tags/{tag}^{{commit}}"], label).decode().strip()
    require_exact_value(peeled, revision, f"{label} peeled commit")
    return tag_object


def archive_file_set(root: Path) -> set[str]:
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise ReleaseContractError(f"cannot stat external archive root: {error}") from error
    require(stat.S_ISDIR(root_stat.st_mode) and not stat.S_ISLNK(root_stat.st_mode), "external archive root must be a real directory")
    files: set[str] = set()
    for directory, directories, names, _ in os.fwalk(root, topdown=True, follow_symlinks=False):
        directory_path = Path(directory)
        for name in directories:
            child = directory_path / name
            mode = child.lstat().st_mode
            require(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode), f"archive directory must not be a symlink: {child}")
        for name in names:
            child = directory_path / name
            file_stat = child.lstat()
            relative = child.relative_to(root).as_posix()
            canonical_relative_path(relative, "archive inventory")
            require(stat.S_ISREG(file_stat.st_mode) and not stat.S_ISLNK(file_stat.st_mode), f"archive entry must be regular: {relative}")
            require(file_stat.st_nlink == 1, f"archive entry must not be hard-linked: {relative}")
            files.add(relative)
    return files


def check_archive_manifest(
    root: Path,
    manifest_path: str,
    manifest_sha256: str,
    sums_path: str,
    sums_sha256: str,
    reserved: set[str],
    budget: ArchiveReadBudget,
) -> set[str]:
    manifest_bytes = read_regular_file(root, manifest_path, "archive manifest", budget=budget, max_bytes=16 * 1024 * 1024)
    require_exact_value(hashlib.sha256(manifest_bytes).hexdigest(), manifest_sha256, "archive manifest digest")
    manifest = load_json_bytes(manifest_bytes, "archive manifest")
    require_exact_keys(manifest, {"schema", "files"}, "archive manifest")
    require_exact_value(manifest["schema"], "visa.release-archive-manifest.v1", "archive manifest schema")
    entries = manifest["files"]
    require(isinstance(entries, list), "archive manifest files must be a list")
    paths: list[str] = []
    expected_sums: list[str] = []
    for entry in entries:
        require(isinstance(entry, dict), "archive manifest file must be an object")
        require_exact_keys(entry, {"path", "sha256", "size"}, "archive manifest file")
        path = canonical_relative_path(entry["path"], "archive manifest file")
        require(path not in reserved, f"archive payload path is reserved metadata: {path}")
        require(is_lower_hex(entry["sha256"], 64), f"archive manifest digest is invalid: {path}")
        require(type(entry["size"]) is int and entry["size"] >= 0, f"archive manifest size is invalid: {path}")
        descriptor, file_stat = open_regular_file_at(root, path, "archive payload")
        os.close(descriptor)
        require_exact_value(file_stat.st_size, entry["size"], f"archive payload size {path}")
        require_exact_value(hash_regular_file(root, path, "archive payload", budget=budget), entry["sha256"], f"archive payload digest {path}")
        paths.append(path)
        expected_sums.append(f"{entry['sha256']}  {path}\n")
    require(paths == sorted(paths) and len(paths) == len(set(paths)), "archive manifest paths must be sorted and unique")
    sums_bytes = read_regular_file(root, sums_path, "archive SHA256SUMS", budget=budget, max_bytes=16 * 1024 * 1024)
    require_exact_value(hashlib.sha256(sums_bytes).hexdigest(), sums_sha256, "archive SHA256SUMS digest")
    require_exact_value(sums_bytes, "".join(expected_sums).encode(), "archive SHA256SUMS contents")
    require_exact_value(archive_file_set(root), set(paths) | reserved, "exact external archive file inventory")
    return set(paths)


def check_external_release_index(
    document: dict[str, Any],
    contract_path: Path,
    archive_root: Path,
    expected_attestation_verifier_sha256: str,
    expected_trusted_root_sha256: str,
    expected_source_revision: str,
    expected_source_tag: str,
    expected_source_tag_object: str,
    expected_final_tag_object: str | None,
    attestation_runner: Callable[[list[str]], bytes] = default_attestation_runner,
    release_verifier_runner: Callable[[Path, str, Path], tuple[int, bytes, bytes]] = (
        default_release_verifier_runner
    ),
    release_stage: str = "final-release-verified",
) -> str:
    required = check_evidence_policy_and_required_ids(document)
    policy = document["evidence_policy"]
    require(release_stage in policy["closure_states"], "unknown release archive stage")
    require(is_lower_hex(expected_source_revision, 40), "expected source revision must be exact")
    require(
        isinstance(expected_source_tag, str)
        and re.fullmatch(r"v0\.1\.0-rc\.[1-9][0-9]*", expected_source_tag) is not None,
        "expected source tag must be exact",
    )
    require(
        is_lower_hex(expected_source_tag_object, 40),
        "expected source tag object must be exact",
    )
    if release_stage == "final-release-verified":
        require(
            is_lower_hex(expected_final_tag_object, 40),
            "expected final tag object must be exact at final release stage",
        )
    else:
        require(
            expected_final_tag_object is None,
            "RC admission must not depend on a final tag object",
        )
    index_path = "index.json"
    finalization_path = "finalization.json"
    budget = ArchiveReadBudget()
    index_bytes = read_regular_file(archive_root, index_path, "external release evidence index", budget=budget, max_bytes=16 * 1024 * 1024)
    index_sha256 = hashlib.sha256(index_bytes).hexdigest()
    index = load_json_bytes(index_bytes, "external release evidence index")
    require_exact_keys(
        index,
        {"schema", "state", "contract", "archive", "verifier_registry", "required_ids", "build_provenance", "evidence"},
        "external release evidence index",
    )
    require_exact_value(index["schema"], policy["index_schema"], "evidence index schema")
    require_exact_value(index["state"], "rc-admitted", "immutable evidence index state")
    require_exact_value(index["required_ids"], required, "evidence index required IDs")
    contract = index["contract"]
    require(isinstance(contract, dict), "evidence index contract binding must be an object")
    require_exact_keys(
        contract,
        {"contract_id", "target_path", "target_sha256", "source_revision", "source_tag", "final_tag"},
        "evidence index contract binding",
    )
    require_exact_value(contract["contract_id"], document["contract_id"], "indexed contract ID")
    require_exact_value(contract["target_path"], policy["target_path"], "indexed target path")
    require(is_lower_hex(contract["target_sha256"], 64), "indexed target SHA-256 must be exact")
    require(is_lower_hex(contract["source_revision"], 40), "indexed source revision must be exact")
    require(
        isinstance(contract["source_tag"], str)
        and re.fullmatch(r"v0\.1\.0-rc\.[1-9][0-9]*", contract["source_tag"]) is not None,
        "indexed source tag must be an exact v0.1.0-rc.N tag",
    )
    require_exact_value(
        contract["source_revision"], expected_source_revision, "indexed out-of-band source revision"
    )
    require_exact_value(
        contract["source_tag"], expected_source_tag, "indexed out-of-band source tag"
    )
    require_exact_value(contract["final_tag"], policy["final_tag"], "indexed final tag")
    require_exact_value(contract_path.resolve(), (ROOT / policy["target_path"]).resolve(), "validated target location")
    require_exact_value(hashlib.sha256(contract_path.read_bytes()).hexdigest(), contract["target_sha256"], "current checker target digest")

    archive = index["archive"]
    require(isinstance(archive, dict), "archive binding must be an object")
    require_exact_keys(
        archive,
        {
            "manifest_path", "manifest_sha256", "sha256sums_path", "sha256sums_sha256",
            "source_bundle_path", "source_bundle_sha256", "cargo_lock_path", "cargo_lock_sha256",
            "rust_toolchain_path", "rust_toolchain_sha256", "verifier_archive_path",
            "verifier_source_path", "verifier_sha256", "attestation_verifier_path",
            "attestation_verifier_sha256", "attestation_verifier_version",
            "trusted_root_path", "trusted_root_sha256", "python_version", "git_version",
        },
        "archive binding",
    )
    require_exact_value(archive["manifest_path"], policy["archive_manifest_path"], "archive manifest path")
    require_exact_value(archive["sha256sums_path"], policy["sha256sums_path"], "archive SHA256SUMS path")
    require_exact_value(archive["source_bundle_path"], policy["source_bundle_path"], "source bundle path")
    require_exact_value(archive["cargo_lock_path"], policy["archived_lock_path"], "archived Cargo.lock path")
    require_exact_value(archive["rust_toolchain_path"], policy["archived_toolchain_path"], "archived toolchain path")
    require_exact_value(archive["verifier_archive_path"], "verifiers/verify-release-readiness.py", "archived verifier path")
    require_exact_value(archive["verifier_source_path"], policy["verifier_dispatcher_path"], "verifier source path")
    require_exact_value(
        archive["attestation_verifier_path"],
        policy["attestation_verifier_path"],
        "attestation verifier path",
    )
    require(
        isinstance(archive["attestation_verifier_version"], str)
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", archive["attestation_verifier_version"])
        is not None,
        "attestation verifier version must be exact numeric SemVer",
    )
    require(
        tuple(int(part) for part in archive["attestation_verifier_version"].split("."))
        >= tuple(int(part) for part in policy["attestation_verifier_minimum_version"].split(".")),
        "attestation verifier version is below the security floor",
    )
    require_exact_value(archive["trusted_root_path"], policy["attestation_trusted_root_path"], "trusted root path")
    require_exact_value(
        archive["python_version"],
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "verifier-host Python version",
    )
    require_exact_value(
        archive["git_version"],
        trusted_git_version(ROOT),
        "verifier-host Git version",
    )
    for field in archive:
        if field.endswith("_sha256"):
            require(is_lower_hex(archive[field], 64), f"archive {field} must be exact")
    require(
        is_lower_hex(expected_trusted_root_sha256, 64),
        "operator-supplied trusted-root SHA-256 must be exact",
    )
    require_exact_value(
        archive["trusted_root_sha256"],
        expected_trusted_root_sha256,
        "archived trusted root out-of-band digest",
    )

    reserved = {
        index_path,
        archive["manifest_path"],
        archive["sha256sums_path"],
        policy["index_attestation_bundle_path"],
    }
    finalization: dict[str, Any] | None = None
    finalization_bytes: bytes | None = None
    finalization_sha256: str | None = None
    if release_stage == "final-release-verified":
        finalization_bytes = read_regular_file(
            archive_root,
            finalization_path,
            "post-tag finalization receipt",
            budget=budget,
            max_bytes=1024 * 1024,
        )
        finalization_sha256 = hashlib.sha256(finalization_bytes).hexdigest()
        reserved.update(
            {
                finalization_path,
                policy["finalization_attestation_bundle_path"],
                policy["final_source_bundle_path"],
            }
        )
    payload_paths = check_archive_manifest(
        archive_root,
        archive["manifest_path"],
        archive["manifest_sha256"],
        archive["sha256sums_path"],
        archive["sha256sums_sha256"],
        reserved,
        budget,
    )

    for path_field, digest_field, label in (
        ("source_bundle_path", "source_bundle_sha256", "RC source bundle"),
        ("cargo_lock_path", "cargo_lock_sha256", "archived Cargo.lock"),
        ("rust_toolchain_path", "rust_toolchain_sha256", "archived rust-toolchain"),
        ("verifier_archive_path", "verifier_sha256", "archived release verifier"),
        (
            "attestation_verifier_path",
            "attestation_verifier_sha256",
            "archived attestation verifier",
        ),
        ("trusted_root_path", "trusted_root_sha256", "archived attestation trusted root"),
    ):
        require_exact_value(hash_regular_file(archive_root, archive[path_field], label, budget=budget), archive[digest_field], f"{label} digest")
    # The trusted checker invocation, recorded Python/Git, and two
    # operator-supplied digests are the verifier-host TCB. Neither the
    # unauthenticated index nor archive may choose the gh executable or
    # Sigstore trusted root used for initial admission.
    _attestation_verifier_directory, attestation_verifier_path = (
        prepare_pinned_attestation_verifier(
            archive_root,
            archive["attestation_verifier_path"],
            archive["attestation_verifier_sha256"],
            expected_attestation_verifier_sha256,
            budget,
        )
    )
    trusted_root_path = prepare_pinned_trusted_root(
        archive_root,
        archive["trusted_root_path"],
        archive["trusted_root_sha256"],
        expected_trusted_root_sha256,
        Path(_attestation_verifier_directory.name),
        budget,
    )
    # Keep the TemporaryDirectory owner in this function's locals until every
    # verification is complete; the path is a private copy of the hashed bytes.
    check_attestation_verifier_version(
        attestation_verifier_path,
        archive["attestation_verifier_version"],
        attestation_runner,
    )

    # Authenticate the immutable index before executing any archived verifier
    # code. The signature proves subject/source/workflow identity; the actual
    # verifier execution below proves that the typed verifier ran.
    verify_attestation(
        attestation_verifier_path,
        archive_root,
        index_path,
        index_bytes,
        policy["index_attestation_bundle_path"],
        trusted_root_path,
        policy["attestation_repository"],
        policy["attestation_signer_workflow"],
        expected_source_revision,
        f"refs/tags/{expected_source_tag}",
        attestation_runner,
        budget,
        "release evidence index",
    )

    # The post-tag receipt selects the final source bundle and final tag object.
    # Authenticate it before cloning that bundle or executing any archived code.
    if finalization_bytes is not None:
        verify_attestation(
            attestation_verifier_path,
            archive_root,
            finalization_path,
            finalization_bytes,
            policy["finalization_attestation_bundle_path"],
            trusted_root_path,
            policy["attestation_repository"],
            policy["attestation_signer_workflow"],
            expected_source_revision,
            f"refs/tags/{contract['final_tag']}",
            attestation_runner,
            budget,
            "post-tag finalization receipt",
        )
        finalization = load_json_bytes(finalization_bytes, "post-tag finalization receipt")
        require_exact_keys(
            finalization,
            {
                "schema",
                "state",
                "rc_admission_state",
                "index_path",
                "index_sha256",
                "source_revision",
                "source_tag",
                "source_tag_object",
                "final_tag",
                "final_tag_object",
                "final_source_bundle_path",
                "final_source_bundle_sha256",
            },
            "post-tag finalization receipt",
        )
        require_exact_value(
            finalization["schema"], policy["finalization_schema"], "finalization schema"
        )
        require_exact_value(
            finalization["state"], "final-release-verified", "finalization state"
        )
        require_exact_value(
            finalization["rc_admission_state"], "rc-admitted", "finalization RC state"
        )
        require_exact_value(finalization["index_path"], index_path, "finalization index path")
        require_exact_value(
            finalization["index_sha256"], index_sha256, "finalization index digest"
        )
        for field in ("source_revision", "source_tag", "final_tag"):
            require_exact_value(finalization[field], contract[field], f"finalization {field}")
        require_exact_value(
            finalization["final_source_bundle_path"],
            policy["final_source_bundle_path"],
            "final source bundle path",
        )
        require(
            is_lower_hex(finalization["final_source_bundle_sha256"], 64),
            "final source bundle digest must be exact",
        )
        require_exact_value(
            hash_regular_file(
                archive_root,
                finalization["final_source_bundle_path"],
                "final source bundle",
                budget=budget,
            ),
            finalization["final_source_bundle_sha256"],
            "final source bundle digest",
        )

    rc_bundle = read_regular_file(archive_root, archive["source_bundle_path"], "RC source bundle", budget=budget)
    with tempfile.TemporaryDirectory(prefix="visa-release-source-") as temporary:
        temporary_root = Path(temporary)
        rc_repository = clone_source_bundle(rc_bundle, temporary_root / "rc", "RC source bundle")
        source_tag_object = require_annotated_tag(rc_repository, contract["source_tag"], contract["source_revision"], "RC tag")
        require_exact_value(
            source_tag_object,
            expected_source_tag_object,
            "RC tag object against out-of-band trusted checkout",
        )
        if finalization is not None:
            require_exact_value(finalization["source_tag_object"], source_tag_object, "finalization RC tag object")
        tagged_target = git_bytes(rc_repository, ["cat-file", "blob", f"{contract['source_revision']}:{contract['target_path']}"], "tagged release target")
        require_exact_value(hashlib.sha256(tagged_target).hexdigest(), contract["target_sha256"], "tagged target digest")
        tagged_lock = git_bytes(rc_repository, ["cat-file", "blob", f"{contract['source_revision']}:Cargo.lock"], "tagged Cargo.lock")
        tagged_toolchain = git_bytes(rc_repository, ["cat-file", "blob", f"{contract['source_revision']}:rust-toolchain.toml"], "tagged toolchain")
        tagged_verifier = git_bytes(rc_repository, ["cat-file", "blob", f"{contract['source_revision']}:{archive['verifier_source_path']}"], "tagged release verifier")
        require_exact_value(read_regular_file(archive_root, archive["cargo_lock_path"], "archived Cargo.lock", budget=budget), tagged_lock, "archived Cargo.lock bytes")
        require_exact_value(read_regular_file(archive_root, archive["rust_toolchain_path"], "archived toolchain", budget=budget), tagged_toolchain, "archived rust-toolchain bytes")
        require_exact_value(read_regular_file(archive_root, archive["verifier_archive_path"], "archived release verifier", budget=budget), tagged_verifier, "archived verifier bytes")
        require_exact_value(hashlib.sha256(tagged_verifier).hexdigest(), archive["verifier_sha256"], "tagged verifier digest")

        if finalization is not None:
            final_bundle = read_regular_file(
                archive_root,
                finalization["final_source_bundle_path"],
                "final source bundle",
                budget=budget,
            )
            final_repository = clone_source_bundle(final_bundle, temporary_root / "final", "final source bundle")
            require_exact_value(
                require_annotated_tag(
                    final_repository,
                    contract["source_tag"],
                    contract["source_revision"],
                    "final-bundle RC tag",
                ),
                expected_source_tag_object,
                "final bundle RC tag object against out-of-band trusted checkout",
            )
            final_tag_object = require_annotated_tag(final_repository, contract["final_tag"], contract["source_revision"], "final tag")
            require_exact_value(
                final_tag_object,
                expected_final_tag_object,
                "final tag object against out-of-band trusted checkout",
            )
            require_exact_value(finalization["final_tag_object"], final_tag_object, "finalization final tag object")

    _release_dispatcher_directory = PrivateTemporaryDirectory(
        prefix="visa-release-dispatcher-"
    )
    release_verifier_path = write_private_regular_copy(
        Path(_release_dispatcher_directory.name),
        "verify-release-readiness.py",
        tagged_verifier,
    )
    tagged_source_inputs = {
        contract["target_path"]: {
            "bytes": tagged_target,
            "sha256": contract["target_sha256"],
            "roles": ["release-target"],
        },
        archive["verifier_source_path"]: {
            "bytes": tagged_verifier,
            "sha256": archive["verifier_sha256"],
            "roles": ["release-dispatcher-source"],
        },
    }
    require(
        set(tagged_source_inputs).isdisjoint(payload_paths),
        "tagged-source logical inputs must not be shadowed by archive payload files",
    )

    registry = index["verifier_registry"]
    require(isinstance(registry, dict), "verifier registry must be an object")
    require_exact_keys(registry, {"schema", "dispatcher_source_path", "dispatcher_sha256", "entries"}, "verifier registry")
    require_exact_value(registry["schema"], policy["verifier_registry_schema"], "verifier registry schema")
    require_exact_value(registry["dispatcher_source_path"], archive["verifier_source_path"], "verifier registry dispatcher path")
    require_exact_value(registry["dispatcher_sha256"], archive["verifier_sha256"], "verifier registry dispatcher digest")
    registry_entries = registry["entries"]
    require(isinstance(registry_entries, list), "verifier registry entries must be a list")
    require_exact_value(
        [entry.get("readiness_id") if isinstance(entry, dict) else None for entry in registry_entries],
        required,
        "closed verifier registry IDs and order",
    )
    verifier_runtime_inputs: dict[str, list[dict[str, Any]]] = {}
    verifier_runtime_paths: set[str] = set()
    for entry in registry_entries:
        require(isinstance(entry, dict), "verifier registry entry must be an object")
        require_exact_keys(
            entry,
            {"readiness_id", "verifier_id", "runtime_inputs"},
            "verifier registry entry",
        )
        readiness_id = entry["readiness_id"]
        require_exact_value(
            entry["verifier_id"],
            f"visa.release.verify.{readiness_id}.v1",
            f"{readiness_id} registry verifier ID",
        )
        runtime_inputs = entry["runtime_inputs"]
        require(isinstance(runtime_inputs, list), f"{readiness_id} runtime inputs must be a list")
        runtime_ids: list[str] = []
        runtime_paths: list[str] = []
        for runtime_input in runtime_inputs:
            require(isinstance(runtime_input, dict), f"{readiness_id} runtime input must be an object")
            require_exact_keys(
                runtime_input,
                {"id", "kind", "path", "sha256", "version"},
                f"{readiness_id} runtime input",
            )
            require(
                isinstance(runtime_input["id"], str) and bool(runtime_input["id"]),
                f"{readiness_id} runtime input ID must be non-empty",
            )
            require(
                runtime_input["kind"] in {"executable", "config", "data"},
                f"{readiness_id} runtime input kind is invalid",
            )
            path = canonical_relative_path(
                runtime_input["path"], f"{readiness_id} runtime input"
            )
            require(
                path not in tagged_source_inputs,
                f"{readiness_id} runtime input collides with tagged-source input {path}",
            )
            require(
                is_lower_hex(runtime_input["sha256"], 64),
                f"{readiness_id} runtime input digest must be exact",
            )
            require(
                isinstance(runtime_input["version"], str) and bool(runtime_input["version"]),
                f"{readiness_id} runtime input version must be non-empty",
            )
            require_exact_value(
                hash_regular_file(
                    archive_root,
                    path,
                    f"{readiness_id} runtime input",
                    budget=budget,
                ),
                runtime_input["sha256"],
                f"{readiness_id} runtime input digest {path}",
            )
            runtime_ids.append(runtime_input["id"])
            runtime_paths.append(path)
            verifier_runtime_paths.add(path)
        require(
            len(runtime_ids) == len(set(runtime_ids)),
            f"{readiness_id} runtime input IDs must be unique",
        )
        require(
            len(runtime_paths) == len(set(runtime_paths)),
            f"{readiness_id} runtime input paths must be unique",
        )
        verifier_runtime_inputs[readiness_id] = runtime_inputs
    supply_runtime_ids = [
        runtime_input["id"]
        for runtime_input in verifier_runtime_inputs[
            "supply-chain-license-and-artifact-locks"
        ]
    ]
    require_exact_value(
        supply_runtime_ids,
        policy["supply_chain_required_input_ids"],
        "supply-chain runtime input roles and order",
    )
    nexus_wire_runtime_ids = [
        runtime_input["id"]
        for runtime_input in verifier_runtime_inputs[
            "nexus-native-v1-wire-artifact"
        ]
    ]
    require_exact_value(
        nexus_wire_runtime_ids,
        policy["nexus_wire_required_input_ids"],
        "Nexus wire runtime input roles and order",
    )

    build = index["build_provenance"]
    require(isinstance(build, dict), "build provenance binding must be an object")
    require_exact_keys(
        build,
        {"inventory_path", "inventory_sha256", "artifact_inventory_path", "artifact_inventory_sha256"},
        "external build provenance",
    )
    for field in ("inventory_sha256", "artifact_inventory_sha256"):
        require(is_lower_hex(build[field], 64), f"{field} must be an exact SHA-256")
    inventory_bytes = read_regular_file(archive_root, build["inventory_path"], "release build inventory", budget=budget, max_bytes=64 * 1024 * 1024)
    require_exact_value(hashlib.sha256(inventory_bytes).hexdigest(), build["inventory_sha256"], "release build inventory digest")
    inventory = load_json_bytes(inventory_bytes, "release build inventory")
    inventory_build_binding = {
        "cargo_lock_sha256": archive["cargo_lock_sha256"],
        "rust_toolchain_sha256": archive["rust_toolchain_sha256"],
        "release_build_base_image": document["host_compatibility"]["release_build_base_image"],
        "runtime_inputs": verifier_runtime_inputs[
            "supply-chain-license-and-artifact-locks"
        ],
    }
    product_builds = check_build_inventory(inventory, contract, inventory_build_binding)
    supply_runtime_inputs_by_id = {
        entry["id"]: entry
        for entry in verifier_runtime_inputs[
            "supply-chain-license-and-artifact-locks"
        ]
    }
    oci_layout_paths, oci_layout_digests = check_oci_layout_file_set(
        archive_root,
        supply_runtime_inputs_by_id["oci-layout-inventory"]["path"],
        contract,
        inventory["derived_build_image"],
        budget,
    )
    artifact_inventory_bytes = read_regular_file(archive_root, build["artifact_inventory_path"], "release artifact inventory", budget=budget, max_bytes=16 * 1024 * 1024)
    require_exact_value(hashlib.sha256(artifact_inventory_bytes).hexdigest(), build["artifact_inventory_sha256"], "release artifact inventory digest")
    artifact_inventory = load_json_bytes(artifact_inventory_bytes, "release artifact inventory")
    artifact_paths, verified_artifacts = check_artifact_inventory(
        document,
        artifact_inventory,
        contract,
        archive_root,
        budget,
        attestation_runner,
        attestation_verifier_path,
        trusted_root_path,
        product_builds,
    )
    check_nexus_wire_provenance_binding(
        document,
        artifact_inventory,
        verifier_runtime_inputs["nexus-native-v1-wire-artifact"],
        build["artifact_inventory_path"],
        build["artifact_inventory_sha256"],
        verified_artifacts,
        archive_root,
        budget,
        attestation_runner,
        attestation_verifier_path,
        trusted_root_path,
    )

    evidence = index["evidence"]
    require(isinstance(evidence, list), "external release evidence must be a list")
    evidence_ids: list[str] = []
    evidence_paths: set[str] = set()
    owned_schema_by_readiness = {
        entry["readiness_id"]: entry for entry in expected_owned_schema_artifacts()
    }
    for entry in evidence:
        require(isinstance(entry, dict), "external release evidence entry must be an object")
        require_exact_keys(entry, {"id", "evidence_path", "evidence_sha256", "verifier_receipt_path", "verifier_receipt_sha256"}, "external release evidence entry")
        readiness_id = entry["id"]
        require(readiness_id in required, f"external evidence has unknown ID {readiness_id!r}")
        if readiness_id in owned_schema_by_readiness:
            require_exact_value(
                entry["evidence_path"],
                owned_schema_by_readiness[readiness_id]["path"],
                f"{readiness_id} owned schema evidence path",
            )
        evidence_ids.append(readiness_id)
        for field in ("evidence_sha256", "verifier_receipt_sha256"):
            require(is_lower_hex(entry[field], 64), f"{readiness_id} {field} must be exact")
        evidence_bytes = read_regular_file(archive_root, entry["evidence_path"], "external readiness evidence", budget=budget)
        receipt_bytes = read_regular_file(
            archive_root,
            entry["verifier_receipt_path"],
            "external readiness verifier receipt",
            budget=budget,
            max_bytes=MAX_VERIFIER_RECEIPT_BYTES,
        )
        require_exact_value(hashlib.sha256(evidence_bytes).hexdigest(), entry["evidence_sha256"], f"{readiness_id} evidence digest")
        require_exact_value(hashlib.sha256(receipt_bytes).hexdigest(), entry["verifier_receipt_sha256"], f"{readiness_id} verifier receipt digest")
        receipt = load_json_bytes(receipt_bytes, f"{readiness_id} verifier receipt")
        require_exact_keys(
            receipt,
            {
                "schema", "readiness_id", "target_path", "target_sha256", "source_revision", "source_tag",
                "verifier_id", "verifier_source_path", "verifier_source_sha256", "exit_code",
                "output_sha256", "verifier_result_sha256", "input_sha256",
            },
            f"{readiness_id} verifier receipt",
        )
        require_exact_value(receipt["schema"], policy["receipt_schema"], "receipt schema")
        require_exact_value(receipt["readiness_id"], readiness_id, "receipt readiness ID")
        for field in ("target_path", "target_sha256", "source_revision", "source_tag"):
            require_exact_value(receipt[field], contract[field], f"{readiness_id} receipt {field}")
        require_exact_value(receipt["verifier_id"], f"visa.release.verify.{readiness_id}.v1", f"{readiness_id} verifier ID")
        require_exact_value(receipt["verifier_source_path"], archive["verifier_source_path"], f"{readiness_id} verifier source path")
        require_exact_value(receipt["verifier_source_sha256"], archive["verifier_sha256"], f"{readiness_id} verifier source digest")
        require_exact_value(receipt["exit_code"], 0, f"{readiness_id} verifier exit code")
        require_exact_value(receipt["output_sha256"], entry["evidence_sha256"], f"{readiness_id} verifier output digest")
        inputs = receipt["input_sha256"]
        require(isinstance(inputs, dict), f"{readiness_id} receipt inputs must be an object")
        for input_path, digest in inputs.items():
            canonical_relative_path(input_path, f"{readiness_id} verifier input")
            require(is_lower_hex(digest, 64), f"{readiness_id} verifier input digest must be exact")
        for input_path, digest in (
            (entry["evidence_path"], entry["evidence_sha256"]),
            (contract["target_path"], contract["target_sha256"]),
            (archive["verifier_source_path"], archive["verifier_sha256"]),
        ):
            require_exact_value(inputs.get(input_path), digest, f"{readiness_id} typed verifier input {input_path}")
        for runtime_input in verifier_runtime_inputs[readiness_id]:
            require_exact_value(
                inputs.get(runtime_input["path"]),
                runtime_input["sha256"],
                f"{readiness_id} runtime verifier input {runtime_input['path']}",
            )
        if readiness_id == "supply-chain-license-and-artifact-locks":
            for input_path, digest in (
                (archive["source_bundle_path"], archive["source_bundle_sha256"]),
                (archive["cargo_lock_path"], archive["cargo_lock_sha256"]),
                (archive["rust_toolchain_path"], archive["rust_toolchain_sha256"]),
                (build["inventory_path"], build["inventory_sha256"]),
                (build["artifact_inventory_path"], build["artifact_inventory_sha256"]),
            ):
                require_exact_value(inputs.get(input_path), digest, f"supply-chain verifier input {input_path}")
            for input_path, digest in oci_layout_digests.items():
                require_exact_value(
                    inputs.get(input_path),
                    digest,
                    f"supply-chain OCI layout verifier input {input_path}",
                )
        archive_snapshot_inputs: dict[str, dict[str, Any]] = {}
        add_snapshot_archive_input(
            archive_snapshot_inputs,
            entry["evidence_path"],
            entry["evidence_sha256"],
            "evidence",
            f"{readiness_id} evidence input",
        )
        for runtime_input in verifier_runtime_inputs[readiness_id]:
            add_snapshot_archive_input(
                archive_snapshot_inputs,
                runtime_input["path"],
                runtime_input["sha256"],
                f"runtime:{runtime_input['id']}",
                f"{readiness_id} runtime snapshot input",
            )
        if readiness_id == "supply-chain-license-and-artifact-locks":
            for input_path, digest, role in (
                (
                    archive["source_bundle_path"],
                    archive["source_bundle_sha256"],
                    "supply:rc-source-bundle",
                ),
                (
                    archive["cargo_lock_path"],
                    archive["cargo_lock_sha256"],
                    "supply:archived-cargo-lock",
                ),
                (
                    archive["rust_toolchain_path"],
                    archive["rust_toolchain_sha256"],
                    "supply:archived-rust-toolchain",
                ),
                (
                    build["inventory_path"],
                    build["inventory_sha256"],
                    "supply:build-inventory",
                ),
                (
                    build["artifact_inventory_path"],
                    build["artifact_inventory_sha256"],
                    "supply:artifact-inventory",
                ),
            ):
                add_snapshot_archive_input(
                    archive_snapshot_inputs,
                    input_path,
                    digest,
                    role,
                    f"{readiness_id} fixed supply-chain snapshot input",
                )
            for input_path in oci_layout_paths:
                add_snapshot_archive_input(
                    archive_snapshot_inputs,
                    input_path,
                    oci_layout_digests[input_path],
                    "supply:oci-layout-file",
                    f"{readiness_id} OCI snapshot input",
                )
        expected_input_paths = set(tagged_source_inputs) | set(
            archive_snapshot_inputs
        )
        require_exact_value(
            set(inputs),
            expected_input_paths,
            f"{readiness_id} closed typed verifier input paths",
        )
        (
            actual_exit_code,
            verifier_result_bytes,
            verified_output,
        ) = invoke_release_verifier_with_snapshot(
            release_verifier_path,
            archive["verifier_sha256"],
            readiness_id,
            contract["source_revision"],
            contract["source_tag"],
            entry["evidence_path"],
            entry["evidence_sha256"],
            inputs,
            tagged_source_inputs,
            archive_snapshot_inputs,
            archive_root,
            payload_paths,
            budget,
            policy["verifier_input_snapshot_schema"],
            release_verifier_runner,
        )
        require(
            len(verifier_result_bytes) <= 1024 * 1024,
            f"{readiness_id} typed verifier result exceeds the output bound",
        )
        require(
            len(verified_output) <= MAX_ARCHIVE_FILE_BYTES,
            f"{readiness_id} typed verifier evidence exceeds the file bound",
        )
        require_exact_value(actual_exit_code, receipt["exit_code"], f"{readiness_id} actual verifier exit code")
        require_exact_value(
            hashlib.sha256(verifier_result_bytes).hexdigest(),
            receipt["verifier_result_sha256"],
            f"{readiness_id} typed verifier result digest",
        )
        verifier_result = load_json_bytes(
            verifier_result_bytes,
            f"{readiness_id} typed verifier result",
        )
        require_exact_keys(
            verifier_result,
            {"schema", "readiness_id", "verifier_id", "status", "evidence_sha256"},
            f"{readiness_id} typed verifier result",
        )
        require_exact_value(
            verifier_result["schema"],
            policy["verifier_result_schema"],
            f"{readiness_id} typed verifier result schema",
        )
        require_exact_value(verifier_result["readiness_id"], readiness_id, "typed verifier readiness ID")
        require_exact_value(verifier_result["verifier_id"], receipt["verifier_id"], "typed verifier ID")
        require_exact_value(verifier_result["status"], "verified", f"{readiness_id} typed verifier status")
        require_exact_value(
            verifier_result["evidence_sha256"],
            entry["evidence_sha256"],
            f"{readiness_id} typed verifier evidence digest",
        )
        require_exact_value(
            hashlib.sha256(verified_output).hexdigest(),
            entry["evidence_sha256"],
            f"{readiness_id} rerun evidence output digest",
        )
        evidence_paths.update((entry["evidence_path"], entry["verifier_receipt_path"]))
    require_exact_value(evidence_ids, required, "external evidence coverage and order")

    referenced_payload = {
        archive["source_bundle_path"], archive["cargo_lock_path"], archive["rust_toolchain_path"],
        archive["verifier_archive_path"], archive["attestation_verifier_path"],
        archive["trusted_root_path"], policy["offline_reverify_path"],
        build["inventory_path"], build["artifact_inventory_path"],
    } | artifact_paths | evidence_paths | verifier_runtime_paths | oci_layout_paths
    require_exact_value(payload_paths, referenced_payload, "archive manifest referenced payload coverage")
    reverify_bytes = read_regular_file(
        archive_root,
        policy["offline_reverify_path"],
        "offline reverify instructions",
        budget=budget,
        max_bytes=1024 * 1024,
    )
    try:
        reverify = reverify_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseContractError("offline reverify instructions must be UTF-8") from error
    for required_text in (
        "git clone source/visa-v0.1.0-rc.bundle",
        "--release-stage rc-admitted",
        "--release-stage final-release-verified",
        "--archive-root",
        "--attestation-verifier-sha256",
        "--trusted-root-sha256",
        "--expected-source-tag",
        "gh attestation verify",
    ):
        require(required_text in reverify, f"offline reverify instructions omit {required_text!r}")

    # Archived verifiers are part of the trusted release source, but they run
    # as local code. Re-hash the complete archive graph after every verifier has
    # completed so persistent mutation cannot become admitted evidence.
    post_index_bytes = read_regular_file(
        archive_root,
        index_path,
        "post-verifier release index",
        budget=budget,
        max_bytes=16 * 1024 * 1024,
    )
    require_exact_value(
        hashlib.sha256(post_index_bytes).hexdigest(),
        index_sha256,
        "post-verifier release index digest",
    )
    require_exact_value(
        check_archive_manifest(
            archive_root,
            archive["manifest_path"],
            archive["manifest_sha256"],
            archive["sha256sums_path"],
            archive["sha256sums_sha256"],
            reserved,
            budget,
        ),
        payload_paths,
        "post-verifier archive payload",
    )
    post_finalization_bytes: bytes | None = None
    if finalization is not None:
        require(finalization_sha256 is not None, "finalization digest was not captured")
        post_finalization_bytes = read_regular_file(
            archive_root,
            finalization_path,
            "post-verifier finalization receipt",
            budget=budget,
            max_bytes=1024 * 1024,
        )
        require_exact_value(
            hashlib.sha256(post_finalization_bytes).hexdigest(),
            finalization_sha256,
            "post-verifier finalization receipt digest",
        )
        require_exact_value(
            hash_regular_file(
                archive_root,
                finalization["final_source_bundle_path"],
                "post-verifier final source bundle",
                budget=budget,
            ),
            finalization["final_source_bundle_sha256"],
            "post-verifier final source bundle digest",
        )

    require_exact_value(
        hashlib.sha256(
            read_direct_regular_file(
                attestation_verifier_path,
                "post-verifier private attestation verifier",
            )
        ).hexdigest(),
        expected_attestation_verifier_sha256,
        "post-verifier private attestation verifier digest",
    )
    require_exact_value(
        hashlib.sha256(
            read_direct_regular_file(
                trusted_root_path,
                "post-verifier private attestation trusted root",
            )
        ).hexdigest(),
        expected_trusted_root_sha256,
        "post-verifier private attestation trusted-root digest",
    )
    check_attestation_verifier_version(
        attestation_verifier_path,
        archive["attestation_verifier_version"],
        attestation_runner,
    )

    verify_attestation(
        attestation_verifier_path,
        archive_root,
        index_path,
        post_index_bytes,
        policy["index_attestation_bundle_path"],
        trusted_root_path,
        policy["attestation_repository"],
        policy["attestation_signer_workflow"],
        expected_source_revision,
        f"refs/tags/{expected_source_tag}",
        attestation_runner,
        budget,
        "post-verifier release evidence index",
    )

    if finalization is not None:
        require(
            post_finalization_bytes is not None,
            "post-verifier finalization snapshot was not captured",
        )
        verify_attestation(
            attestation_verifier_path,
            archive_root,
            finalization_path,
            post_finalization_bytes,
            policy["finalization_attestation_bundle_path"],
            trusted_root_path,
            policy["attestation_repository"],
            policy["attestation_signer_workflow"],
            expected_source_revision,
            f"refs/tags/{contract['final_tag']}",
            attestation_runner,
            budget,
            "post-tag finalization receipt",
        )
    _release_dispatcher_directory.cleanup()
    _attestation_verifier_directory.cleanup()
    return expected_source_revision


def validate(
    contract_path: Path = DEFAULT_CONTRACT,
    readiness_ledger_path: Path = DEFAULT_READINESS_LEDGER,
    root: Path = ROOT,
) -> list[str]:
    document = load_contract(contract_path)
    check_header(document)
    check_host_compatibility(document)
    check_process_topology_and_local_rpcs(document, root)
    check_supervision_and_cohort(document)
    check_core_namespaces(document, root)
    check_resource_profiles(document, root)
    check_dependency_constraints(document, root)
    check_wits(document, root)
    check_golden_vectors(document, root)
    check_release_semantic_vectors(document, root)
    check_owned_schema_artifacts(document)
    check_release_semantic_corpus(document)
    check_neutral_and_nexus(document, root)
    check_provider_spi(document, root)
    check_provider_dispatch_fence(document)
    check_public_surface(document)
    check_release_artifacts(document)
    check_failure_matrix(document)
    check_support_and_admission(document)
    return check_development_readiness(document, contract_path, readiness_ledger_path, root)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--readiness-ledger", type=Path, default=DEFAULT_READINESS_LEDGER)
    parser.add_argument(
        "--release-ready",
        action="store_true",
        help="validate complete exact-tag closure from an external evidence index",
    )
    parser.add_argument(
        "--archive-root",
        type=Path,
        help="self-contained immutable release archive root; required with --release-ready",
    )
    parser.add_argument(
        "--attestation-verifier-sha256",
        help="out-of-band SHA-256 of the exact archived gh verifier; required with --release-ready",
    )
    parser.add_argument(
        "--trusted-root-sha256",
        help="out-of-band SHA-256 of the archived Sigstore trusted root; required with --release-ready",
    )
    parser.add_argument(
        "--expected-source-tag",
        help="out-of-band annotated v0.1.0-rc.N tag expected at clean trusted checkout HEAD",
    )
    parser.add_argument(
        "--release-stage",
        choices=("rc-admitted", "final-release-verified"),
        default="final-release-verified",
        help="archive closure stage; final release verification is the default",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        require(
            arguments.release_ready
            or (
                arguments.archive_root is None
                and arguments.attestation_verifier_sha256 is None
                and arguments.trusted_root_sha256 is None
                and arguments.expected_source_tag is None
            ),
            "release archive and bootstrap pins are only valid with --release-ready",
        )
        pending = validate(arguments.contract, arguments.readiness_ledger)
        if arguments.release_ready:
            require(
                arguments.archive_root is not None,
                "--release-ready requires --archive-root PATH",
            )
            require(
                arguments.attestation_verifier_sha256 is not None,
                "--release-ready requires --attestation-verifier-sha256 HEX",
            )
            require(
                arguments.trusted_root_sha256 is not None,
                "--release-ready requires --trusted-root-sha256 HEX",
            )
            require(
                arguments.expected_source_tag is not None,
                "--release-ready requires --expected-source-tag v0.1.0-rc.N",
            )
            (
                expected_source_revision,
                expected_source_tag_object,
                expected_final_tag_object,
            ) = trusted_checkout_release_identity(
                arguments.expected_source_tag,
                arguments.release_stage,
            )
            document = load_contract(arguments.contract)
            revision = check_external_release_index(
                document,
                arguments.contract,
                arguments.archive_root,
                arguments.attestation_verifier_sha256,
                arguments.trusted_root_sha256,
                expected_source_revision,
                arguments.expected_source_tag,
                expected_source_tag_object,
                expected_final_tag_object,
                release_stage=arguments.release_stage,
            )
    except (ReleaseContractError, OSError) as error:
        print(f"vISA 0.1 release contract violation: {error}", file=sys.stderr)
        return 1
    if arguments.release_ready:
        print(
            "vISA 0.1 release contract passed; "
            f"release-stage={arguments.release_stage} source={revision}"
        )
    elif pending:
        print(f"vISA 0.1 target contract passed; release-ready=no pending={len(pending)}")
    else:
        print("vISA 0.1 target and development ledger passed; release-ready=no pending=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
