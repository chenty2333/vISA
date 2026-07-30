#!/usr/bin/env python3
"""Validate the stock-zstd source identity, zero-patch policy, and Wasm ABI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCK = ROOT / "third_party" / "zstd" / "source-lock.json"
EXPECTED_SCHEMA = "visa-stock-zstd-source-lock-v1"
HEX64 = re.compile(r"[0-9a-f]{64}")
EXPECTED_UPSTREAM = {
    "repository": "https://github.com/facebook/zstd.git",
    "tag": "v1.5.7",
    "tag_object": "ac66b19e6bd6b83238bf008eecc1298105298532",
    "revision": "f8745da6ff1ad1e7bab384bd1f9d742439278e99",
    "tree": "1a3cb277e9b9b37b01811a3c65f6c25d46a8f241",
    "source_date_epoch": 1_739_923_464,
}
EXPECTED_LICENSES = (
    (
        "LICENSE",
        "BSD-3-Clause",
        "7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8",
    ),
    (
        "COPYING",
        "GPL-2.0-only",
        "f9c375a1be4a41f7b70301dd83c91cb89e41567478859b77eef375a52d782505",
    ),
)
EXPECTED_PACKAGES = (
    (
        "wasi-libc",
        "0.0~git20220510.9886d3d-2",
        "513e25eeca77f7e31adf928b684714dd656cc6bc70c2970abfe3b4117e3b736f",
    ),
    (
        "libclang-rt-17-dev-wasm32",
        "1:17.0.6~++20231208085813+6009708b4367-1~exp1~20231208085906.81",
        "c87eb2672d2ea22e7757658761f577b8b0179201b118dd9c61740904e97ca282",
    ),
)
EXPECTED_WASM_SHA256 = (
    "35d9fbebbbab83eb9e5c8f2b90ee7998ecdf9edcbe797b879cb28460161e8096"
)
EXPECTED_WANCO_REVISION = "3c2e400dda5ce51d78333223f6fcbde08e6b198a"


class LockError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise LockError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"source lock contains duplicate key {key!r}")
        result[key] = value
    return result


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        fail(
            f"{label} keys drifted: missing={sorted(keys - actual)} "
            f"unknown={sorted(actual - keys)}"
        )
    return value


def exact_string(value: Any, expected: str, label: str) -> str:
    if value != expected:
        fail(f"{label} must be {expected!r}")
    return expected


def digest_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256")
    return value


def contained_regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is not a regular non-symlink file: {path}")
    try:
        path.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    except (OSError, ValueError) as error:
        fail(f"{label} escapes the repository: {error}")
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(source: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(source), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"git {' '.join(arguments)} failed: {detail or completed.returncode}")
    return completed.stdout


def read_lock(path: Path) -> dict[str, Any]:
    contained_regular_file(path, "source lock")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse source lock: {error}")
    return exact_object(
        value,
        {"schema", "upstream", "source_policy", "wasi_build", "carrier_build"},
        "source lock",
    )


def validate(lock_path: Path = DEFAULT_LOCK) -> dict[str, Any]:
    lock = read_lock(lock_path)
    exact_string(lock["schema"], EXPECTED_SCHEMA, "schema")

    upstream = exact_object(
        lock["upstream"],
        {
            "repository",
            "tag",
            "tag_object",
            "revision",
            "tree",
            "source_date_epoch",
            "licenses",
        },
        "upstream",
    )
    for key in ("repository", "tag", "tag_object", "revision", "tree"):
        exact_string(upstream[key], EXPECTED_UPSTREAM[key], f"upstream.{key}")
    if upstream["source_date_epoch"] != EXPECTED_UPSTREAM["source_date_epoch"]:
        fail("upstream.source_date_epoch differs from the locked commit time")
    licenses = upstream["licenses"]
    if not isinstance(licenses, list) or len(licenses) != len(EXPECTED_LICENSES):
        fail("upstream.licenses must contain the exact dual-license pair")
    for index, (raw, expected) in enumerate(
        zip(licenses, EXPECTED_LICENSES, strict=True)
    ):
        license_entry = exact_object(raw, {"path", "spdx", "sha256"}, f"license[{index}]")
        exact_string(license_entry["path"], expected[0], f"license[{index}].path")
        exact_string(license_entry["spdx"], expected[1], f"license[{index}].spdx")
        exact_string(
            license_entry["sha256"],
            expected[2],
            f"license[{index}].sha256",
        )

    policy = exact_object(
        lock["source_policy"],
        {
            "upstream_source_changes",
            "source_patches",
            "build_recipe",
            "compatibility_object",
            "bridge_workspace",
            "bridge_lock",
        },
        "source_policy",
    )
    exact_string(
        policy["upstream_source_changes"],
        "forbidden",
        "source_policy.upstream_source_changes",
    )
    if policy["source_patches"] != []:
        fail("stock zstd must have an empty source_patches list")
    build_recipe = exact_object(
        policy["build_recipe"],
        {"path", "sha256"},
        "source_policy.build_recipe",
    )
    exact_string(
        build_recipe["path"],
        "scripts/build-stock-zstd.sh",
        "build_recipe.path",
    )
    build_recipe_path = contained_regular_file(
        ROOT / build_recipe["path"], "stock-zstd build recipe"
    )
    if sha256(build_recipe_path) != digest_string(
        build_recipe["sha256"], "build_recipe.sha256"
    ):
        fail("stock-zstd build recipe digest mismatch")
    compatibility = exact_object(
        policy["compatibility_object"],
        {"path", "sha256", "relationship"},
        "source_policy.compatibility_object",
    )
    exact_string(
        compatibility["path"],
        "third_party/zstd/abi/visa_zstd_posix_compat.c",
        "compatibility_object.path",
    )
    exact_string(
        compatibility["relationship"],
        "additional-guest-object-not-upstream-source-patch",
        "compatibility_object.relationship",
    )
    compatibility_path = contained_regular_file(
        ROOT / compatibility["path"], "compatibility object"
    )
    if sha256(compatibility_path) != digest_string(
        compatibility["sha256"], "compatibility_object.sha256"
    ):
        fail("compatibility object digest mismatch")
    bridge_workspace = exact_object(
        policy["bridge_workspace"],
        {"path", "sha256", "relationship"},
        "source_policy.bridge_workspace",
    )
    exact_string(
        bridge_workspace["path"],
        "third_party/zstd/bridge-workspace.toml",
        "bridge_workspace.path",
    )
    exact_string(
        bridge_workspace["relationship"],
        "isolated-content-locked-workspace-for-stable-wanco-bridge-build",
        "bridge_workspace.relationship",
    )
    bridge_workspace_path = contained_regular_file(
        ROOT / bridge_workspace["path"], "bridge workspace"
    )
    if sha256(bridge_workspace_path) != digest_string(
        bridge_workspace["sha256"], "bridge_workspace.sha256"
    ):
        fail("bridge workspace digest mismatch")
    bridge_lock = exact_object(
        policy["bridge_lock"],
        {"path", "sha256", "relationship"},
        "source_policy.bridge_lock",
    )
    exact_string(
        bridge_lock["path"],
        "third_party/zstd/bridge-Cargo.lock",
        "bridge_lock.path",
    )
    exact_string(
        bridge_lock["relationship"],
        "exact-resolved-dependencies-for-isolated-bridge-workspace",
        "bridge_lock.relationship",
    )
    bridge_lock_path = contained_regular_file(
        ROOT / bridge_lock["path"], "bridge dependency lock"
    )
    if sha256(bridge_lock_path) != digest_string(
        bridge_lock["sha256"], "bridge_lock.sha256"
    ):
        fail("bridge dependency lock digest mismatch")

    wasi = exact_object(
        lock["wasi_build"],
        {
            "target",
            "compiler",
            "compiler_version",
            "optimization",
            "dockerfile",
            "packages",
            "expected_wasm_sha256",
            "expected_imports",
        },
        "wasi_build",
    )
    exact_string(wasi["target"], "wasm32-wasi", "wasi_build.target")
    exact_string(wasi["compiler"], "clang-17", "wasi_build.compiler")
    exact_string(
        wasi["compiler_version"],
        "Debian clang version 17.0.6 (++20231208085813+6009708b4367-1~exp1~20231208085906.81)",
        "wasi_build.compiler_version",
    )
    exact_string(wasi["optimization"], "-O1", "wasi_build.optimization")
    dockerfile = exact_object(wasi["dockerfile"], {"path", "sha256"}, "wasi_build.dockerfile")
    exact_string(
        dockerfile["path"], "third_party/zstd/Dockerfile", "wasi_build.dockerfile.path"
    )
    dockerfile_path = contained_regular_file(ROOT / dockerfile["path"], "zstd Dockerfile")
    if sha256(dockerfile_path) != digest_string(
        dockerfile["sha256"], "wasi_build.dockerfile.sha256"
    ):
        fail("zstd Dockerfile digest mismatch")
    packages = wasi["packages"]
    if not isinstance(packages, list) or len(packages) != 2:
        fail("wasi_build.packages must contain exactly two packages")
    for index, (raw, expected) in enumerate(
        zip(packages, EXPECTED_PACKAGES, strict=True)
    ):
        package = exact_object(raw, {"name", "version", "sha256"}, f"package[{index}]")
        exact_string(package["name"], expected[0], f"package[{index}].name")
        exact_string(package["version"], expected[1], f"package[{index}].version")
        exact_string(package["sha256"], expected[2], f"package[{index}].sha256")
    exact_string(
        wasi["expected_wasm_sha256"],
        EXPECTED_WASM_SHA256,
        "wasi_build.expected_wasm_sha256",
    )
    expected_imports(wasi["expected_imports"])

    carrier = exact_object(
        lock["carrier_build"],
        {
            "wanco_source_lock",
            "wanco_revision",
            "wanco_compiler_sha256",
            "wanco_runtime_sha256",
            "optimization",
            "qualification",
            "o1_status",
        },
        "carrier_build",
    )
    wanco_lock = exact_object(
        carrier["wanco_source_lock"], {"path", "sha256"}, "carrier_build.wanco_source_lock"
    )
    exact_string(
        wanco_lock["path"],
        "third_party/wanco/source-lock.json",
        "carrier_build.wanco_source_lock.path",
    )
    wanco_lock_path = contained_regular_file(ROOT / wanco_lock["path"], "Wanco source lock")
    if sha256(wanco_lock_path) != digest_string(
        wanco_lock["sha256"], "carrier_build.wanco_source_lock.sha256"
    ):
        fail("Wanco source-lock digest mismatch")
    exact_string(
        carrier["wanco_revision"],
        EXPECTED_WANCO_REVISION,
        "carrier_build.wanco_revision",
    )
    digest_string(carrier["wanco_compiler_sha256"], "carrier_build.wanco_compiler_sha256")
    digest_string(carrier["wanco_runtime_sha256"], "carrier_build.wanco_runtime_sha256")
    exact_string(carrier["optimization"], "-O1", "carrier_build.optimization")
    exact_string(
        carrier["qualification"],
        "wanco-v5-typed-restore-raw-v4-o1-carrier-qualified",
        "carrier_build.qualification",
    )
    o1 = exact_object(
        carrier["o1_status"],
        {"status", "qualification_basis"},
        "carrier_build.o1_status",
    )
    exact_string(
        o1["status"],
        "qualified",
        "carrier_build.o1_status.status",
    )
    exact_string(
        o1["qualification_basis"],
        "exact-callsite-typed-stackmap-twelve-cell-post-import-active-data-lz4-and-retained-raw-validation",
        "carrier_build.o1_status.qualification_basis",
    )
    return lock


def expected_imports(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list) or len(value) != 23:
        fail("wasi_build.expected_imports must contain exactly 23 function imports")
    imports: list[tuple[str, str]] = []
    for index, item in enumerate(value):
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not all(isinstance(part, str) and part for part in item)
        ):
            fail(f"expected_imports[{index}] must be [module, name]")
        imports.append((item[0], item[1]))
    if imports[:2] != [
        ("visa_wasi_metadata_v1", "visa_wasi_metadata_path_chmod"),
        ("visa_wasi_metadata_v1", "visa_wasi_metadata_path_chown"),
    ]:
        fail("metadata compatibility imports are absent or reordered")
    if any(module == "env" and name in {"chmod", "chown"} for module, name in imports):
        fail("bare env chmod/chown imports are forbidden")
    return imports


def validate_source(source: Path, lock: dict[str, Any]) -> None:
    try:
        source = source.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve source checkout: {error}")
    if not (source / ".git").exists():
        fail("source is not a Git checkout")
    upstream = lock["upstream"]
    revision = upstream["revision"]
    if (
        git(source, "remote", "get-url", "origin").decode().strip()
        != upstream["repository"]
    ):
        fail("source origin differs from the locked zstd repository")
    if git(source, "rev-parse", "HEAD^{commit}").decode().strip() != revision:
        fail("source HEAD differs from the locked zstd revision")
    if git(source, "rev-parse", "HEAD^{tree}").decode().strip() != upstream["tree"]:
        fail("source tree differs from the locked zstd tree")
    tag_ref = f"refs/tags/{upstream['tag']}"
    if git(source, "rev-parse", tag_ref).decode().strip() != upstream["tag_object"]:
        fail("annotated zstd tag object differs from the lock")
    if git(source, "cat-file", "-t", tag_ref).decode().strip() != "tag":
        fail("locked zstd tag is not an annotated tag object")
    if git(source, "rev-parse", f"{tag_ref}^{{commit}}").decode().strip() != revision:
        fail("locked zstd tag does not peel to the locked revision")
    if int(git(source, "show", "-s", "--format=%ct", revision).decode().strip()) != upstream[
        "source_date_epoch"
    ]:
        fail("locked source date epoch differs from the commit")
    for license_entry in upstream["licenses"]:
        committed = git(source, "show", f"{revision}:{license_entry['path']}")
        if hashlib.sha256(committed).hexdigest() != license_entry["sha256"]:
            fail(f"upstream {license_entry['path']} digest mismatch")
    if git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        fail("stock zstd source checkout is dirty")


def read_uleb(payload: bytes, cursor: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(5):
        if cursor >= len(payload):
            fail("truncated WebAssembly LEB128 value")
        byte = payload[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, cursor
        shift += 7
    fail("oversized WebAssembly LEB128 value")


def read_name(payload: bytes, cursor: int) -> tuple[str, int]:
    length, cursor = read_uleb(payload, cursor)
    end = cursor + length
    if end > len(payload):
        fail("truncated WebAssembly name")
    try:
        return payload[cursor:end].decode("utf-8"), end
    except UnicodeDecodeError as error:
        fail(f"invalid UTF-8 WebAssembly name: {error}")


def wasm_function_imports(path: Path) -> list[tuple[str, str]]:
    payload = contained_regular_file(path, "stock-zstd Wasm").read_bytes()
    if payload[:8] != b"\0asm\x01\0\0\0":
        fail("stock-zstd artifact is not a WebAssembly v1 module")
    cursor = 8
    imports: list[tuple[str, str]] = []
    while cursor < len(payload):
        section_id = payload[cursor]
        cursor += 1
        section_length, cursor = read_uleb(payload, cursor)
        section_end = cursor + section_length
        if section_end > len(payload):
            fail("truncated WebAssembly section")
        if section_id != 2:
            cursor = section_end
            continue
        count, cursor = read_uleb(payload, cursor)
        for _ in range(count):
            module, cursor = read_name(payload, cursor)
            name, cursor = read_name(payload, cursor)
            if cursor >= section_end:
                fail("truncated WebAssembly import")
            kind = payload[cursor]
            cursor += 1
            if kind == 0:
                _, cursor = read_uleb(payload, cursor)
                imports.append((module, name))
            else:
                fail("stock-zstd unexpectedly imports a non-function item")
        if cursor != section_end:
            fail("WebAssembly import section has trailing bytes")
    return imports


def validate_wasm(path: Path, lock: dict[str, Any]) -> None:
    wasi = lock["wasi_build"]
    if sha256(contained_regular_file(path, "stock-zstd Wasm")) != wasi["expected_wasm_sha256"]:
        fail("stock-zstd Wasm digest differs from the reproducible locked build")
    actual = wasm_function_imports(path)
    expected = expected_imports(wasi["expected_imports"])
    if actual != expected:
        fail(f"stock-zstd Wasm imports drifted: expected={expected!r} actual={actual!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--wasm", type=Path)
    args = parser.parse_args()
    try:
        lock = validate(args.lock)
        if args.source is not None:
            validate_source(args.source, lock)
        if args.wasm is not None:
            validate_wasm(args.wasm, lock)
    except LockError as error:
        print(f"stock-zstd source check: {error}", file=sys.stderr)
        return 1
    upstream = lock["upstream"]
    print(
        "stock-zstd-source-lock "
        f"tag-object={upstream['tag_object']} revision={upstream['revision']} "
        f"tree={upstream['tree']} zero-source-patches=true "
        f"carrier-optimization={lock['carrier_build']['optimization']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
