#!/usr/bin/env python3
"""Validate the official stock-SQLite source archive and reproducible Wasm ABI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCK = ROOT / "third_party" / "sqlite" / "source-lock.json"
EXPECTED_SCHEMA = "visa-stock-sqlite-source-lock-v1"
HEX64 = re.compile(r"[0-9a-f]{64}")
VERSION = "3.53.4"
VERSION_NUMBER = 3_053_004
SOURCE_ID = (
    "2026-07-24 19:02:57 "
    "bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc"
)
ARCHIVE_URL = "https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip"
ARCHIVE_SIZE = 2_946_650
ARCHIVE_SHA3_256 = "628a44cfe82c66aed1ccbbe85a562d2e33ebe64b3288981ed76285612227934e"
ARCHIVE_SHA256 = "1e71ddf93849c6a6ecf58b827c0692073d2dd7ee40196158068f7b29f422e87d"
ARCHIVE_ROOT = "sqlite-amalgamation-3530400"
SOURCE_FILES = (
    (
        "shell.c",
        1_185_915,
        "8011ed018aa12969f93573b7bb1eae2d939d64d0f451b297ff847a0211c85179",
    ),
    (
        "sqlite3.c",
        9_515_341,
        "b1dd5d74ec7f29055a6684fa06fb3c2f6821c87dd38f9a458dfd2e8a1db28189",
    ),
    (
        "sqlite3.h",
        690_838,
        "919e7f2e8ed1d8f56ac17b412b8971c76aa5d1a879752cc6058f75e7d5910e1d",
    ),
    (
        "sqlite3ext.h",
        39_175,
        "ac9645e5c9ff0cf176efdd6e75cb5e98f46295d38e02db5c4d208826a39ab4be",
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
EXPECTED_DEFINITIONS = (
    "_WASI_EMULATED_GETPID",
    "_WASI_EMULATED_PROCESS_CLOCKS",
    "_WASI_EMULATED_SIGNAL",
    "SQLITE_DEFAULT_MEMSTATUS=0",
    "SQLITE_NOHAVE_SYSTEM",
    "SQLITE_OMIT_LOAD_EXTENSION",
    "SQLITE_OMIT_WAL",
    "SQLITE_THREADSAFE=0",
)
EXPECTED_WASM_SHA256 = "d0b50c9ba120fdd48d20f38d7e9b41b311f7b26947612521256c11d28381c581"
EXPECTED_IMPORTS = (
    ("visa_wasi_metadata_v1", "visa_wasi_metadata_path_chmod"),
    ("wasi_snapshot_preview1", "args_get"),
    ("wasi_snapshot_preview1", "args_sizes_get"),
    ("wasi_snapshot_preview1", "environ_get"),
    ("wasi_snapshot_preview1", "environ_sizes_get"),
    ("wasi_snapshot_preview1", "clock_time_get"),
    ("wasi_snapshot_preview1", "fd_close"),
    ("wasi_snapshot_preview1", "fd_fdstat_get"),
    ("wasi_snapshot_preview1", "fd_fdstat_set_flags"),
    ("wasi_snapshot_preview1", "fd_filestat_get"),
    ("wasi_snapshot_preview1", "fd_filestat_set_size"),
    ("wasi_snapshot_preview1", "fd_prestat_get"),
    ("wasi_snapshot_preview1", "fd_prestat_dir_name"),
    ("wasi_snapshot_preview1", "fd_read"),
    ("wasi_snapshot_preview1", "fd_readdir"),
    ("wasi_snapshot_preview1", "fd_seek"),
    ("wasi_snapshot_preview1", "fd_sync"),
    ("wasi_snapshot_preview1", "fd_write"),
    ("wasi_snapshot_preview1", "path_create_directory"),
    ("wasi_snapshot_preview1", "path_filestat_get"),
    ("wasi_snapshot_preview1", "path_filestat_set_times"),
    ("wasi_snapshot_preview1", "path_open"),
    ("wasi_snapshot_preview1", "path_readlink"),
    ("wasi_snapshot_preview1", "path_remove_directory"),
    ("wasi_snapshot_preview1", "path_symlink"),
    ("wasi_snapshot_preview1", "path_unlink_file"),
    ("wasi_snapshot_preview1", "poll_oneoff"),
    ("wasi_snapshot_preview1", "proc_exit"),
)


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


def exact(value: Any, expected: Any, label: str) -> Any:
    if value != expected:
        fail(f"{label} must be {expected!r}")
    return expected


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{label} must be a lowercase 64-digit digest")
    return value


def regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is not a regular non-symlink file: {path}")
    return path


def repository_file(path: str, label: str) -> Path:
    candidate = regular_file(ROOT / path, label)
    try:
        candidate.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    except (OSError, ValueError) as error:
        fail(f"{label} escapes the repository: {error}")
    return candidate


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    value = hashlib.new(algorithm)
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def validate_pinned_path(value: Any, expected_path: str, label: str) -> None:
    item = exact_object(value, {"path", "sha256"}, label)
    exact(item["path"], expected_path, f"{label}.path")
    path = repository_file(expected_path, label)
    if hash_file(path) != digest(item["sha256"], f"{label}.sha256"):
        fail(f"{label} digest mismatch")


def read_lock(path: Path) -> dict[str, Any]:
    regular_file(path, "source lock")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
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
    exact(lock["schema"], EXPECTED_SCHEMA, "schema")
    upstream = exact_object(
        lock["upstream"],
        {"version", "version_number", "source_id", "archive", "files"},
        "upstream",
    )
    exact(upstream["version"], VERSION, "upstream.version")
    exact(upstream["version_number"], VERSION_NUMBER, "upstream.version_number")
    exact(upstream["source_id"], SOURCE_ID, "upstream.source_id")
    archive = exact_object(
        upstream["archive"], {"url", "size", "sha3_256", "sha256"}, "upstream.archive"
    )
    exact(archive["url"], ARCHIVE_URL, "upstream.archive.url")
    exact(archive["size"], ARCHIVE_SIZE, "upstream.archive.size")
    exact(archive["sha3_256"], ARCHIVE_SHA3_256, "upstream.archive.sha3_256")
    exact(archive["sha256"], ARCHIVE_SHA256, "upstream.archive.sha256")
    expected_files = [
        {"path": path, "size": size, "sha256": sha256}
        for path, size, sha256 in SOURCE_FILES
    ]
    exact(upstream["files"], expected_files, "upstream.files")

    policy = exact_object(
        lock["source_policy"],
        {
            "upstream_source_changes",
            "source_patches",
            "build_recipe",
            "compatibility_source",
            "compatibility_header",
            "workloads",
            "bridge_workspace",
            "bridge_lock",
        },
        "source_policy",
    )
    exact(policy["upstream_source_changes"], "forbidden", "source_policy.upstream_source_changes")
    exact(policy["source_patches"], [], "source_policy.source_patches")
    validate_pinned_path(policy["build_recipe"], "scripts/build-stock-sqlite.sh", "build recipe")
    validate_pinned_path(
        policy["compatibility_source"],
        "third_party/sqlite/abi/visa_sqlite_wasi_compat.c",
        "compatibility source",
    )
    validate_pinned_path(
        policy["compatibility_header"],
        "third_party/sqlite/abi/visa_sqlite_wasi_compat.h",
        "compatibility header",
    )
    workloads = exact_object(
        policy["workloads"],
        {"basic", "seed", "transaction", "cursor"},
        "source_policy.workloads",
    )
    for name in ("basic", "seed", "transaction", "cursor"):
        validate_pinned_path(
            workloads[name],
            f"third_party/sqlite/workload/{name}.sql",
            f"{name} workload",
        )
    validate_pinned_path(
        policy["bridge_workspace"],
        "third_party/sqlite/bridge-workspace.toml",
        "bridge workspace",
    )
    validate_pinned_path(
        policy["bridge_lock"], "third_party/sqlite/bridge-Cargo.lock", "bridge lock"
    )

    wasi = exact_object(
        lock["wasi_build"],
        {
            "target",
            "compiler",
            "compiler_version",
            "optimization",
            "definitions",
            "dockerfile",
            "packages",
            "expected_wasm_sha256",
            "expected_imports",
        },
        "wasi_build",
    )
    exact(wasi["target"], "wasm32-wasi", "wasi_build.target")
    exact(wasi["compiler"], "clang-17", "wasi_build.compiler")
    exact(
        wasi["compiler_version"],
        "Debian clang version 17.0.6 (++20231208085813+6009708b4367-1~exp1~20231208085906.81)",
        "wasi_build.compiler_version",
    )
    exact(wasi["optimization"], "-O1", "wasi_build.optimization")
    exact(wasi["definitions"], list(EXPECTED_DEFINITIONS), "wasi_build.definitions")
    validate_pinned_path(
        wasi["dockerfile"], "third_party/sqlite/Dockerfile", "SQLite Dockerfile"
    )
    expected_packages = [
        {"name": name, "version": version, "sha256": sha256}
        for name, version, sha256 in EXPECTED_PACKAGES
    ]
    exact(wasi["packages"], expected_packages, "wasi_build.packages")
    exact(wasi["expected_wasm_sha256"], EXPECTED_WASM_SHA256, "wasi_build.expected_wasm_sha256")
    exact(
        wasi["expected_imports"],
        [[module, name] for module, name in EXPECTED_IMPORTS],
        "wasi_build.expected_imports",
    )

    carrier = exact_object(
        lock["carrier_build"],
        {"wanco_source_lock", "wanco_revision", "optimization"},
        "carrier_build",
    )
    exact(
        carrier["wanco_source_lock"],
        "third_party/wanco/source-lock.json",
        "carrier_build.wanco_source_lock",
    )
    repository_file(carrier["wanco_source_lock"], "Wanco source lock")
    exact(
        carrier["wanco_revision"],
        "3c2e400dda5ce51d78333223f6fcbde08e6b198a",
        "carrier_build.wanco_revision",
    )
    exact(carrier["optimization"], "-O1", "carrier_build.optimization")
    return lock


def validate_archive(path: Path, lock: dict[str, Any]) -> None:
    path = regular_file(path, "SQLite archive")
    if path.stat().st_size != ARCHIVE_SIZE:
        fail("SQLite archive size mismatch")
    if hash_file(path, "sha3_256") != ARCHIVE_SHA3_256:
        fail("SQLite archive SHA3-256 mismatch")
    if hash_file(path) != ARCHIVE_SHA256:
        fail("SQLite archive SHA-256 mismatch")
    expected = {f"{ARCHIVE_ROOT}/"}
    expected.update(f"{ARCHIVE_ROOT}/{name}" for name, _, _ in SOURCE_FILES)
    try:
        with zipfile.ZipFile(path) as archive:
            if set(archive.namelist()) != expected or len(archive.infolist()) != len(expected):
                fail("SQLite archive member set differs from the official amalgamation")
            for name, size, sha256 in SOURCE_FILES:
                member = archive.getinfo(f"{ARCHIVE_ROOT}/{name}")
                if member.is_dir() or member.file_size != size:
                    fail(f"SQLite archive member shape differs: {name}")
                payload = archive.read(member)
                if hashlib.sha256(payload).hexdigest() != sha256:
                    fail(f"SQLite archive member digest mismatch: {name}")
    except (OSError, zipfile.BadZipFile, KeyError) as error:
        fail(f"cannot inspect SQLite archive: {error}")
    del lock


def validate_source(path: Path, lock: dict[str, Any]) -> None:
    try:
        path = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve SQLite source directory: {error}")
    if not path.is_dir() or path.is_symlink():
        fail("SQLite source is not a regular directory")
    expected_names = {name for name, _, _ in SOURCE_FILES}
    if {entry.name for entry in path.iterdir()} != expected_names:
        fail("SQLite extracted source member set differs")
    for name, size, sha256 in SOURCE_FILES:
        source = regular_file(path / name, f"SQLite {name}")
        if source.stat().st_size != size or hash_file(source) != sha256:
            fail(f"SQLite extracted source identity mismatch: {name}")
    sqlite3_c = (path / "sqlite3.c").read_text(encoding="utf-8")
    for declaration in (
        f'#define SQLITE_VERSION        "{VERSION}"',
        f"#define SQLITE_VERSION_NUMBER {VERSION_NUMBER}",
        f'#define SQLITE_SOURCE_ID      "{SOURCE_ID}"',
    ):
        if sqlite3_c.count(declaration) != 1:
            fail(f"SQLite source identity declaration differs: {declaration}")
    del lock


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
    payload = regular_file(path, "stock-SQLite Wasm").read_bytes()
    if payload[:8] != b"\0asm\x01\0\0\0":
        fail("stock-SQLite artifact is not a WebAssembly v1 module")
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
            if kind != 0:
                fail("stock-SQLite unexpectedly imports a non-function item")
            _, cursor = read_uleb(payload, cursor)
            imports.append((module, name))
        if cursor != section_end:
            fail("WebAssembly import section has trailing bytes")
    return imports


def validate_wasm(path: Path, lock: dict[str, Any]) -> None:
    if hash_file(regular_file(path, "stock-SQLite Wasm")) != EXPECTED_WASM_SHA256:
        fail("stock-SQLite Wasm digest differs from the locked build")
    actual = wasm_function_imports(path)
    if actual != list(EXPECTED_IMPORTS):
        fail(f"stock-SQLite Wasm imports drifted: {actual!r}")
    del lock


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--wasm", type=Path)
    args = parser.parse_args()
    try:
        lock = validate(args.lock)
        if args.archive is not None:
            validate_archive(args.archive, lock)
        if args.source is not None:
            validate_source(args.source, lock)
        if args.wasm is not None:
            validate_wasm(args.wasm, lock)
    except LockError as error:
        print(f"stock-SQLite source check: {error}", file=sys.stderr)
        return 1
    print(
        "stock-sqlite-source-lock "
        f"version={VERSION} source-id={SOURCE_ID.rsplit(' ', 1)[1]} "
        "zero-source-patches=true carrier-optimization=-O1"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
