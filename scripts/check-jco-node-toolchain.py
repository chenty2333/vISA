#!/usr/bin/env python3
"""Verify the locked JcoNode translation and execution toolchain."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "crates/runtime/visa_jco_node/Cargo.toml"
LOCKFILE = ROOT / "Cargo.lock"
PREFLIGHT = ROOT / "crates/runtime/visa_jco_node/src/preflight.rs"
PROTOCOL = ROOT / "crates/runtime/visa_jco_node/src/protocol.rs"
DRIVER = ROOT / "crates/runtime/visa_jco_node/src/driver.mjs"
DOCKERFILE = ROOT / "Dockerfile"

EXPECTED_RPC_PROTOCOL_VERSION = 3

EXPECTED_CONSTANTS = {
    "JCO_VERSION": "1.25.2",
    "JS_COMPONENT_BINDGEN_VERSION": "2.0.11",
    "WASMTIME_ENVIRON_VERSION": "45.0.1",
    "NODE_VERSION": "24.15.0",
    "V8_VERSION": "13.6.233.17-node.48",
    "TRANSLATION_OPTIONS_SCHEMA": "visa-jco-node-transpile-options-v1",
}
EXPECTED_CRATES = {
    "js-component-bindgen": (
        "2.0.11",
        "b7c6dc1bab29fab71ad97680c0d270b5074005aa4e8aa19200bff19a2d968ec3",
    ),
    "wasmtime-environ": (
        "45.0.1",
        "0f337d68a62d868f3c297517b46d20dc7e293f0da36bbee2f6ec3c30eab938bd",
    ),
    "wit-component": (
        "0.251.0",
        "83a5e60173c413659c689f0581b0cf5d1a2404077568f9ffdce748a9eb2fc913",
    ),
    "wit-parser": (
        "0.251.0",
        "e960732e824fab95099971a09e638979347c94ca48568d3c854c945729196947",
    ),
}
EXPECTED_NODE_ARCHIVE_SHA256 = {
    "x64": "472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6",
    "arm64": "f3d5a797b5d210ce8e2cb265544c8e482eaedcb8aa409a8b46da7e8595d0dda0",
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def load_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")


def check_manifest() -> None:
    manifest = load_toml(MANIFEST)
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, dict):
        fail("visa_jco_node manifest has no dependency table")
    for crate, (version, _) in EXPECTED_CRATES.items():
        expected = f"={version}"
        if dependencies.get(crate) != expected:
            fail(f"{crate} must be pinned as {expected} in visa_jco_node/Cargo.toml")
    dev_dependencies = manifest.get("dev-dependencies")
    if not isinstance(dev_dependencies, dict):
        fail("visa_jco_node manifest has no dev-dependency table")
    fixture_tool = dev_dependencies.get("wit-component")
    if not isinstance(fixture_tool, dict):
        fail("visa_jco_node must configure wit-component for valid WIT fixtures")
    if fixture_tool.get("version") != "=0.251.0" or fixture_tool.get("features") != [
        "dummy-module"
    ]:
        fail("visa_jco_node WIT fixture tool must pin wit-component 0.251.0 dummy-module")


def package(lock: dict[str, object], name: str, version: str) -> dict[str, object]:
    packages = lock.get("package")
    if not isinstance(packages, list):
        fail("Cargo.lock has no package array")
    matches = [
        entry
        for entry in packages
        if isinstance(entry, dict)
        and entry.get("name") == name
        and entry.get("version") == version
    ]
    if len(matches) != 1:
        fail(f"Cargo.lock must contain exactly one {name} {version} package")
    return matches[0]


def check_lockfile() -> None:
    lock = load_toml(LOCKFILE)
    for crate, (version, checksum) in EXPECTED_CRATES.items():
        entry = package(lock, crate, version)
        if entry.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
            fail(f"Cargo.lock {crate} {version} does not use the crates.io registry source")
        if entry.get("checksum") != checksum:
            fail(f"Cargo.lock {crate} {version} checksum does not match the accepted lock")

    bindgen = package(lock, "js-component-bindgen", EXPECTED_CRATES["js-component-bindgen"][0])
    bindgen_dependencies = bindgen.get("dependencies")
    if not isinstance(bindgen_dependencies, list) or "wasmtime-environ 45.0.1" not in bindgen_dependencies:
        fail("js-component-bindgen must resolve through wasmtime-environ 45.0.1")

    adapter = package(lock, "visa_jco_node", "0.2.0")
    adapter_dependencies = adapter.get("dependencies")
    if not isinstance(adapter_dependencies, list):
        fail("Cargo.lock visa_jco_node package has no dependencies")
    for dependency in (
        "js-component-bindgen",
        "wasmtime-environ 45.0.1",
        "wit-component 0.251.0",
        "wit-parser 0.251.0",
    ):
        if dependency not in adapter_dependencies:
            fail(f"Cargo.lock visa_jco_node does not select {dependency}")


def check_source_constants() -> None:
    source = PREFLIGHT.read_text(encoding="utf-8")
    for name, expected in EXPECTED_CONSTANTS.items():
        matches = re.findall(
            rf'^pub const {re.escape(name)}: &str = "([^"]+)";$',
            source,
            flags=re.MULTILINE,
        )
        if matches != [expected]:
            fail(f"{PREFLIGHT.relative_to(ROOT)} must declare {name} as {expected}")

    protocol = PROTOCOL.read_text(encoding="utf-8")
    expected_protocol = (
        f"pub(crate) const PROTOCOL_VERSION: u32 = {EXPECTED_RPC_PROTOCOL_VERSION};"
    )
    if protocol.count(expected_protocol) != 1:
        fail(
            f"{PROTOCOL.relative_to(ROOT)} must lock the RPC protocol to "
            f"{EXPECTED_RPC_PROTOCOL_VERSION}"
        )

    driver = DRIVER.read_text(encoding="utf-8")
    expected_driver_protocol = f"const PROTOCOL = {EXPECTED_RPC_PROTOCOL_VERSION};"
    if driver.count(expected_driver_protocol) != 1:
        fail(
            f"{DRIVER.relative_to(ROOT)} must implement RPC protocol "
            f"{EXPECTED_RPC_PROTOCOL_VERSION}"
        )

    provenance_lock = (
        "pub const JCO_NODE_RPC_PROTOCOL_VERSION: u32 = "
        "crate::protocol::PROTOCOL_VERSION;"
    )
    if PREFLIGHT.read_text(encoding="utf-8").count(provenance_lock) != 1:
        fail("JcoNode provenance must bind the exact RPC protocol version")


def check_docker_pin() -> None:
    source = DOCKERFILE.read_text(encoding="utf-8")
    required_fragments = (
        f"VISA_NODE_VERSION={EXPECTED_CONSTANTS['NODE_VERSION']}",
        f"VISA_NODE_V8_VERSION={EXPECTED_CONSTANTS['V8_VERSION']}",
        *EXPECTED_NODE_ARCHIVE_SHA256.values(),
        "sha256sum -c -",
    )
    for fragment in required_fragments:
        if fragment not in source:
            fail(f"Dockerfile is missing the locked Node toolchain fragment: {fragment}")


def resolve_node() -> Path:
    configured = os.environ.get("VISA_NODE_BIN", "node")
    candidate = Path(configured).expanduser()
    if candidate.parent != Path(".") or "/" in configured:
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        if not candidate.is_file():
            fail(f"VISA_NODE_BIN does not name a file: {candidate}")
        return candidate.resolve()
    resolved = shutil.which(configured)
    if resolved is None:
        fail(f"cannot find the Node executable selected by VISA_NODE_BIN={configured!r}")
    return Path(resolved).resolve()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_node() -> tuple[Path, str]:
    node = resolve_node()
    command = [
        os.fspath(node),
        "-p",
        "JSON.stringify({node:process.versions.node,v8:process.versions.v8})",
    ]
    environment = os.environ.copy()
    environment.pop("NODE_OPTIONS", None)
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
            env=environment,
        )
        versions = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        fail(f"cannot inspect {node}: {error}")
    expected = {
        "node": EXPECTED_CONSTANTS["NODE_VERSION"],
        "v8": EXPECTED_CONSTANTS["V8_VERSION"],
    }
    if versions != expected:
        fail(f"JcoNode requires {expected}, but {node} reports {versions}")
    return node, file_sha256(node)


def main() -> int:
    try:
        check_manifest()
        check_lockfile()
        check_source_constants()
        check_docker_pin()
        node, node_sha256 = check_node()
    except (OSError, RuntimeError) as error:
        print(f"JcoNode toolchain check failed: {error}", file=sys.stderr)
        return 1

    print("JcoNode toolchain check passed")
    print(f"  Jco compatibility identity: {EXPECTED_CONSTANTS['JCO_VERSION']}")
    print(f"  js-component-bindgen: {EXPECTED_CONSTANTS['JS_COMPONENT_BINDGEN_VERSION']}")
    print(f"  wasmtime-environ lineage: {EXPECTED_CONSTANTS['WASMTIME_ENVIRON_VERSION']}")
    print(f"  Node executable: {node}")
    print(f"  Node executable SHA-256: {node_sha256}")
    print(f"  Node: {EXPECTED_CONSTANTS['NODE_VERSION']}")
    print(f"  V8: {EXPECTED_CONSTANTS['V8_VERSION']}")
    print(f"  RPC protocol: {EXPECTED_RPC_PROTOCOL_VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
