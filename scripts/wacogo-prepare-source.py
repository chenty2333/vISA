#!/usr/bin/env python3
"""Verify and materialize the pinned vISA wacogo derivative offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
import re


ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = ROOT / "third_party" / "wacogo"
LOCK_PATH = THIRD_PARTY / "source-lock.json"
SCHEMA = "visa.wacogo-source-lock.v1"
TREE_ALGORITHM = "sha256-of-sorted-sha256sum-lines-v1"


class SourceError(RuntimeError):
    """A locked source input or staging invariant was violated."""


def fail(message: str) -> None:
    raise SourceError(message)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular_file(path: Path, description: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as error:
        fail(f"cannot inspect {description} {path}: {error}")
    if not stat.S_ISREG(mode):
        fail(f"{description} must be a regular file, not a symlink or special file: {path}")
    return path


def locked_relative_path(value: object, description: str) -> Path:
    if not isinstance(value, str) or not value:
        fail(f"{description} must be a non-empty relative path")
    if "\\" in value:
        fail(f"{description} must use '/' separators: {value!r}")
    raw_parts = value.split("/")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in raw_parts):
        fail(f"unsafe {description}: {value!r}")
    candidate = THIRD_PARTY.joinpath(*pure.parts)
    resolved_parent = candidate.parent.resolve(strict=True)
    if THIRD_PARTY.resolve() not in (resolved_parent, *resolved_parent.parents):
        fail(f"{description} escapes third_party/wacogo: {value!r}")
    return regular_file(candidate, description)


def repository_relative(value: object, description: str) -> tuple[str, Path]:
    if not isinstance(value, str) or not value:
        fail(f"{description} must be a non-empty repository-relative path")
    if "\\" in value:
        fail(f"{description} must use '/' separators: {value!r}")
    raw_parts = value.split("/")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in raw_parts):
        fail(f"unsafe {description}: {value!r}")
    candidate = ROOT.joinpath(*pure.parts)
    try:
        resolved_parent = candidate.parent.resolve(strict=False)
    except OSError as error:
        fail(f"cannot resolve parent of {description} {value!r}: {error}")
    if ROOT.resolve() not in (resolved_parent, *resolved_parent.parents):
        fail(f"{description} escapes the repository: {value!r}")
    return value, candidate


def repository_file(value: object, description: str) -> tuple[str, Path]:
    relative, candidate = repository_relative(value, description)
    return relative, regular_file(candidate, description)


def repository_directory(value: object, description: str) -> tuple[str, Path]:
    relative, candidate = repository_relative(value, description)
    try:
        mode = candidate.lstat().st_mode
    except OSError as error:
        fail(f"cannot inspect {description} {candidate}: {error}")
    if not stat.S_ISDIR(mode):
        fail(f"{description} must be a non-symlink directory: {candidate}")
    return relative, candidate


def object_field(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        fail(f"source lock field {name} must be an object")
    return value


def string_field(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"source lock field {name} must be a non-empty string")
    return value


def positive_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(f"source lock field {name} must be a positive integer")
    return value


def sha256_field(value: object, name: str) -> str:
    digest = string_field(value, name)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        fail(f"source lock field {name} is not a lowercase SHA-256 digest")
    return digest


def load_lock() -> dict[str, object]:
    try:
        with LOCK_PATH.open("r", encoding="utf-8") as stream:
            lock = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {LOCK_PATH.relative_to(ROOT)}: {error}")
    if not isinstance(lock, dict) or lock.get("schema") != SCHEMA:
        fail(f"source lock must use schema {SCHEMA}")
    return lock


def check_repository_assets(lock: dict[str, object]) -> None:
    derivative = object_field(lock.get("derivative"), "derivative")
    if derivative.get("upstream_is_qualified_without_patches") is not False:
        fail("source lock must not represent unmodified upstream wacogo as qualified")
    limitations = object_field(derivative.get("limitations"), "derivative.limitations")
    if limitations.get("add_type_host_scope") != "root-host-component-only":
        fail("source lock must retain the root-only AddType qualification boundary")
    if limitations.get("nested_host_scope_add_type_supported") is not False:
        fail("source lock must fail closed for nested host-scope AddType support")

    upstream = object_field(lock.get("upstream"), "upstream")
    module = string_field(upstream.get("module"), "upstream.module")
    version = string_field(upstream.get("version"), "upstream.version")
    revision = string_field(upstream.get("revision"), "upstream.revision")
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        fail("source lock upstream.revision must be a full lowercase Git commit")
    module_sum = string_field(upstream.get("module_sum"), "upstream.module_sum")
    if not module_sum.startswith("h1:"):
        fail("source lock upstream.module_sum must be a Go h1 module sum")
    sha256_field(upstream.get("go_mod_sha256"), "upstream.go_mod_sha256")
    sha256_field(upstream.get("go_sum_sha256"), "upstream.go_sum_sha256")
    upstream_license_sha = sha256_field(
        upstream.get("license_sha256"), "upstream.license_sha256"
    )
    module_zip = object_field(upstream.get("module_zip"), "upstream.module_zip")
    expected_zip_root = f"{module}@{version}/"
    if module_zip.get("root") != expected_zip_root:
        fail(
            "upstream.module_zip.root must be derived from the locked module and version"
        )
    positive_int(module_zip.get("size"), "upstream.module_zip.size")
    sha256_field(module_zip.get("sha256"), "upstream.module_zip.sha256")
    positive_int(
        module_zip.get("regular_file_count"),
        "upstream.module_zip.regular_file_count",
    )
    positive_int(
        module_zip.get("uncompressed_regular_file_bytes"),
        "upstream.module_zip.uncompressed_regular_file_bytes",
    )

    patchset = object_field(lock.get("patchset"), "patchset")
    series_path = locked_relative_path(patchset.get("series_file"), "patch series")
    expected_series_sha = sha256_field(
        patchset.get("series_sha256"), "patchset.series_sha256"
    )
    if file_sha256(series_path) != expected_series_sha:
        fail("committed wacogo patch series digest does not match source-lock.json")
    try:
        series = series_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        fail(f"cannot read patch series: {error}")
    if not series or len(series) != len(set(series)):
        fail("wacogo patch series must be non-empty and contain no duplicates")

    patches = patchset.get("patches")
    if not isinstance(patches, list) or len(patches) != 3:
        fail("source lock patchset.patches must contain exactly the qualified three patches")
    locked_patch_names: list[str] = []
    concatenated = hashlib.sha256()
    for index, entry_value in enumerate(patches):
        entry = object_field(entry_value, f"patchset.patches[{index}]")
        patch_path = locked_relative_path(
            entry.get("file"), f"patchset.patches[{index}].file"
        )
        expected_sha = sha256_field(
            entry.get("sha256"), f"patchset.patches[{index}].sha256"
        )
        data = patch_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected_sha:
            fail(f"committed patch digest does not match source lock: {patch_path.name}")
        locked_patch_names.append(patch_path.name)
        concatenated.update(data)
    if series != locked_patch_names:
        fail("patches/series order does not match patchset.patches")
    expected_concatenated = sha256_field(
        patchset.get("ordered_concatenation_sha256"),
        "patchset.ordered_concatenation_sha256",
    )
    if concatenated.hexdigest() != expected_concatenated:
        fail("ordered wacogo patchset digest does not match source-lock.json")

    post_patch_tree = object_field(
        patchset.get("post_patch_tree"), "patchset.post_patch_tree"
    )
    if post_patch_tree.get("algorithm") != TREE_ALGORITHM:
        fail(f"unsupported post-patch tree algorithm: {post_patch_tree.get('algorithm')!r}")
    sha256_field(post_patch_tree.get("sha256"), "patchset.post_patch_tree.sha256")
    positive_int(
        post_patch_tree.get("regular_file_count"),
        "patchset.post_patch_tree.regular_file_count",
    )

    go = object_field(
        object_field(lock.get("build_toolchain"), "build_toolchain").get("go"),
        "build_toolchain.go",
    )
    if go.get("distribution") != "official-go.dev-release":
        fail("wacogo builds must lock the official go.dev distribution")
    if go.get("os") != "linux" or go.get("arch") != "amd64":
        fail("Strict Stage 2 wacogo toolchain must remain linux/amd64")
    version = string_field(go.get("version"), "build_toolchain.go.version")
    expected_version_output = f"go version {version} {go['os']}/{go['arch']}"
    if go.get("version_output") != expected_version_output:
        fail("source lock Go version output is inconsistent with version/OS/architecture")
    positive_int(go.get("archive_size"), "build_toolchain.go.archive_size")
    sha256_field(go.get("archive_sha256"), "build_toolchain.go.archive_sha256")
    sha256_field(go.get("binary_sha256"), "build_toolchain.go.binary_sha256")

    build_policy = object_field(lock.get("build_policy"), "build_policy")
    required_policy = {
        "source_strategy": "verified-module-zip-plus-committed-patches",
        "full_upstream_source_vendored": False,
        "cargo_build_rs_allowed": False,
        "network_allowed": False,
        "requires_prefetched_module_cache": True,
        "go_linker_flags": "-s -w -buildid=",
    }
    for field, expected in required_policy.items():
        if build_policy.get(field) != expected:
            fail(f"source lock build_policy.{field} must be {expected!r}")
    expected_environment = {
        "CGO_ENABLED": "0",
        "GOARCH": "amd64",
        "GOENV": "off",
        "GOOS": "linux",
        "GOAMD64": "v1",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOTELEMETRY": "off",
        "GOTOOLCHAIN": "local",
        "GOVCS": "*:off",
        "GOWORK": "off",
    }
    if build_policy.get("environment") != expected_environment:
        fail("source lock build_policy.environment does not match the offline build boundary")
    if build_policy.get("go_build_flags") != [
        "-mod=readonly",
        "-trimpath",
        "-buildvcs=false",
    ]:
        fail("source lock build_policy.go_build_flags does not match the reproducible build boundary")

    check_production_assets(lock)

    redistribution = lock.get("redistribution_files")
    if not isinstance(redistribution, list) or not redistribution:
        fail("source lock redistribution_files must be a non-empty array")
    seen_files: set[Path] = set()
    observed_upstream_license = False
    for index, entry_value in enumerate(redistribution):
        entry = object_field(entry_value, f"redistribution_files[{index}]")
        string_field(entry.get("component"), f"redistribution_files[{index}].component")
        string_field(entry.get("version"), f"redistribution_files[{index}].version")
        path = locked_relative_path(
            entry.get("file"), f"redistribution_files[{index}].file"
        )
        if path in seen_files:
            fail(f"duplicate redistribution file: {path.relative_to(THIRD_PARTY)}")
        seen_files.add(path)
        expected_sha = sha256_field(
            entry.get("sha256"), f"redistribution_files[{index}].sha256"
        )
        if file_sha256(path) != expected_sha:
            fail(f"redistribution file digest mismatch: {path.relative_to(ROOT)}")
        if path == THIRD_PARTY / "LICENSE" and expected_sha == upstream_license_sha:
            observed_upstream_license = True
    if not observed_upstream_license:
        fail("redistribution files must retain the byte-exact upstream wacogo LICENSE")


def check_production_assets(lock: dict[str, object]) -> None:
    production = object_field(lock.get("production_artifacts"), "production_artifacts")
    sidecar = object_field(production.get("sidecar"), "production_artifacts.sidecar")
    accepted_component = object_field(
        sidecar.get("accepted_component"), "sidecar.accepted_component"
    )
    accepted_component_size = positive_int(
        accepted_component.get("size"), "sidecar.accepted_component.size"
    )
    accepted_component_sha256 = sha256_field(
        accepted_component.get("sha256"), "sidecar.accepted_component.sha256"
    )
    if accepted_component_size != 146486 or accepted_component_sha256 != (
        "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b"
    ):
        fail("production sidecar must accept only the byte-identical Strict Stage 2 Component")
    module_path = string_field(sidecar.get("module_path"), "sidecar.module_path")
    if module_path != "visa.local/wacogo-runtime":
        fail("production sidecar module path must be visa.local/wacogo-runtime")
    if sidecar.get("entry_package") != "./cmd/visa-wacogo-runtime":
        fail("production sidecar entry package must be ./cmd/visa-wacogo-runtime")
    if sidecar.get("protocol_version") != 1:
        fail("production sidecar protocol version must be 1")
    if sidecar.get("carrier_version") != "owned-component-stdin-frame-v1":
        fail("production sidecar carrier version must remain owned-component-stdin-frame-v1")
    if sidecar.get("carrier_magic") != "VISAWCG1":
        fail("production sidecar carrier magic must remain VISAWCG1")

    target = object_field(sidecar.get("target"), "sidecar.target")
    if target != {
        "goos": "linux",
        "goarch": "amd64",
        "goamd64": "v1",
        "cgo_enabled": False,
    }:
        fail("production sidecar target must be CGO-free linux/amd64/v1")

    execution_host_requirements = object_field(
        sidecar.get("execution_host_requirements"),
        "sidecar.execution_host_requirements",
    )
    if execution_host_requirements != {
        "os": "linux",
        "procfs": {
            "required_path": "/proc/self/fd",
            "fd_execution_required": True,
        },
        "memfd": {
            "required": True,
            "create_flags": ["MFD_CLOEXEC", "MFD_ALLOW_SEALING"],
            "execution_policy": "MFD_EXEC-or-legacy-executable-default",
            "required_fcntl_operations": ["F_ADD_SEALS", "F_GET_SEALS"],
            "required_seals": [
                "F_SEAL_WRITE",
                "F_SEAL_GROW",
                "F_SEAL_SHRINK",
                "F_SEAL_SEAL",
            ],
        },
        "security_policy": {"executable_memfd_allowed": True},
    }:
        fail("production sidecar execution host requirements are incomplete")

    binary = object_field(sidecar.get("binary"), "sidecar.binary")
    binary_relative, _ = repository_relative(binary.get("file"), "sidecar.binary.file")
    if not binary_relative.startswith("target/"):
        fail("production sidecar binary must be emitted under target/")
    positive_int(binary.get("size"), "sidecar.binary.size")
    sha256_field(binary.get("sha256"), "sidecar.binary.sha256")

    go_module = object_field(sidecar.get("go_module"), "sidecar.go_module")
    module_relative, module_directory = repository_directory(
        go_module.get("directory"), "sidecar.go_module.directory"
    )
    if module_relative != "crates/runtime/visa_wacogo/sidecar":
        fail("production Go module must remain under crates/runtime/visa_wacogo/sidecar")
    go_mod = object_field(go_module.get("go_mod"), "sidecar.go_module.go_mod")
    go_sum = object_field(go_module.get("go_sum"), "sidecar.go_module.go_sum")
    source_tree = object_field(
        go_module.get("source_tree"), "sidecar.go_module.source_tree"
    )
    if source_tree.get("algorithm") != TREE_ALGORITHM:
        fail("unsupported production sidecar source-tree algorithm")
    expected_source_tree_sha = sha256_field(
        source_tree.get("sha256"), "sidecar.go_module.source_tree.sha256"
    )
    expected_source_tree_files = positive_int(
        source_tree.get("regular_file_count"),
        "sidecar.go_module.source_tree.regular_file_count",
    )
    observed_source_tree_sha, observed_source_tree_files = source_tree_identity(module_directory)
    if (
        observed_source_tree_sha != expected_source_tree_sha
        or observed_source_tree_files != expected_source_tree_files
    ):
        fail(
            "production sidecar source tree mismatch: "
            f"expected {expected_source_tree_sha}/{expected_source_tree_files} files, "
            f"observed {observed_source_tree_sha}/{observed_source_tree_files} files"
        )
    for name, record in (("go.mod", go_mod), ("go.sum", go_sum)):
        relative, path = repository_file(record.get("file"), f"sidecar {name}")
        if path != module_directory / name:
            fail(f"production sidecar {name} path does not match its module directory: {relative}")
        expected = sha256_field(record.get("sha256"), f"sidecar {name} SHA-256")
        if file_sha256(path) != expected:
            fail(f"production sidecar {name} digest does not match source-lock.json")
    try:
        module_declaration = (module_directory / "go.mod").read_text(encoding="utf-8").splitlines()[0]
    except (OSError, UnicodeDecodeError, IndexError) as error:
        fail(f"cannot read production sidecar go.mod module declaration: {error}")
    if module_declaration != f"module {module_path}":
        fail("production sidecar go.mod module declaration does not match source lock")

    generated = object_field(
        sidecar.get("generated_bindings"), "sidecar.generated_bindings"
    )
    if generated.get("algorithm") != "raw-file-concatenation-in-listed-order-sha256-v1":
        fail("unsupported generated-binding concatenation algorithm")
    expected_concatenation = sha256_field(
        generated.get("ordered_concatenation_sha256"),
        "sidecar.generated_bindings.ordered_concatenation_sha256",
    )
    binding_records = generated.get("files")
    if not isinstance(binding_records, list) or len(binding_records) != 6:
        fail("production sidecar must lock exactly six generated binding files")
    expected_prefix = module_relative + "/generated/"
    listed_paths: list[str] = []
    concatenation = hashlib.sha256()
    for index, entry_value in enumerate(binding_records):
        entry = object_field(entry_value, f"sidecar.generated_bindings.files[{index}]")
        relative, path = repository_file(
            entry.get("file"), f"sidecar generated binding {index}"
        )
        if not relative.startswith(expected_prefix) or not relative.endswith(".go"):
            fail(f"generated binding is outside the committed Go package roots: {relative}")
        expected = sha256_field(entry.get("sha256"), f"generated binding {index} SHA-256")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            fail(f"generated binding digest mismatch: {relative}")
        listed_paths.append(relative)
        concatenation.update(data)
    if listed_paths != sorted(listed_paths) or len(listed_paths) != len(set(listed_paths)):
        fail("generated binding files must be unique and listed in bytewise path order")
    generated_root = module_directory / "generated"
    observed_paths: list[str] = []
    for path in generated_root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            fail(f"generated binding tree contains a link or special file: {path}")
        observed_paths.append(path.relative_to(ROOT).as_posix())
    if sorted(observed_paths) != listed_paths:
        fail("committed generated binding inventory differs from source-lock.json")
    if concatenation.hexdigest() != expected_concatenation:
        fail("generated binding ordered concatenation digest does not match source lock")

    closure = sidecar.get("executable_module_closure")
    if not isinstance(closure, list) or len(closure) != 4:
        fail("production sidecar executable module closure must contain exactly four modules")
    closure_paths: list[str] = []
    for index, entry_value in enumerate(closure):
        entry = object_field(entry_value, f"sidecar.executable_module_closure[{index}]")
        path = string_field(entry.get("path"), f"executable module {index} path")
        version = entry.get("version")
        if not isinstance(version, str):
            fail(f"executable module {path} version must be a string")
        if "wasmtime" in path:
            fail(f"forbidden Wasmtime module in wacogo executable closure: {path}")
        module_sum = entry.get("sum")
        if module_sum is not None and (
            not isinstance(module_sum, str) or not module_sum.startswith("h1:")
        ):
            fail(f"executable module {path} has an invalid Go sum")
        closure_paths.append(path)
    if closure_paths != sorted(closure_paths) or len(closure_paths) != len(set(closure_paths)):
        fail("executable module closure must be unique and sorted by module path")
    expected_paths = {
        "github.com/partite-ai/wacogo",
        "github.com/tetratelabs/wazero",
        "golang.org/x/sys",
        module_path,
    }
    if set(closure_paths) != expected_paths:
        fail(f"unexpected executable module closure: {closure_paths}")
    wacogo_entry = next(entry for entry in closure if entry["path"] == "github.com/partite-ai/wacogo")
    upstream = object_field(lock.get("upstream"), "upstream")
    if (
        wacogo_entry.get("version") != upstream.get("version")
        or wacogo_entry.get("sum") != upstream.get("module_sum")
        or wacogo_entry.get("replacement") != "../wacogo"
    ):
        fail("production executable must use the locked wacogo version through ../wacogo")

    for path in module_directory.rglob("*.go"):
        source = path.read_text(encoding="utf-8")
        if '"github.com/partite-ai/wacogo/internal/' in source:
            fail(f"production sidecar directly imports a private wacogo package: {path}")

    runtime_source = (module_directory / "internal/runtimecell/cell.go").read_text(
        encoding="utf-8"
    )
    if not re.search(
        rf"^\s*acceptedComponentSize\s*=\s*{accepted_component_size}\s*$",
        runtime_source,
        re.MULTILINE,
    ):
        fail("Go sidecar accepted Component size differs from source lock")
    if not re.search(
        rf'^\s*acceptedComponentSHA256\s*=\s*"{accepted_component_sha256}"\s*$',
        runtime_source,
        re.MULTILINE,
    ):
        fail("Go sidecar accepted Component SHA-256 differs from source lock")

    protocol_source = (module_directory / "internal/protocol/protocol.go").read_text(
        encoding="utf-8"
    )
    if not re.search(r"^\s*Version\s*=\s*uint32\(1\)\s*$", protocol_source, re.MULTILINE):
        fail("Go sidecar protocol version differs from source lock")
    if not re.search(
        r'^\s*CarrierVersion\s*=\s*"VISAWCG1"\s*$', protocol_source, re.MULTILINE
    ):
        fail("Go sidecar carrier magic differs from source lock")
    rust_protocol = (ROOT / "crates/runtime/visa_wacogo/src/protocol.rs").read_text(
        encoding="utf-8"
    )
    if "pub(crate) const PROTOCOL_VERSION: u32 = 1;" not in rust_protocol:
        fail("Rust adapter protocol version differs from source lock")
    rust_carrier = (ROOT / "crates/runtime/visa_wacogo/src/carrier.rs").read_text(
        encoding="utf-8"
    )
    if 'pub const EXECUTION_CARRIER: &str = "owned-component-stdin-frame-v1";' not in rust_carrier:
        fail("Rust adapter carrier version differs from source lock")
    if 'const FRAME_MAGIC: &[u8; 8] = b"VISAWCG1";' not in rust_carrier:
        fail("Rust adapter carrier magic differs from source lock")


def verify_module_zip(lock: dict[str, object], module_zip_path: Path) -> list[zipfile.ZipInfo]:
    regular_file(module_zip_path, "wacogo module zip")
    upstream = object_field(lock["upstream"], "upstream")
    locked_zip = object_field(upstream["module_zip"], "upstream.module_zip")
    observed_size = module_zip_path.stat().st_size
    expected_size = positive_int(locked_zip["size"], "upstream.module_zip.size")
    if observed_size != expected_size:
        fail(f"wacogo module zip size mismatch: expected {expected_size}, observed {observed_size}")
    observed_sha = file_sha256(module_zip_path)
    expected_sha = sha256_field(locked_zip["sha256"], "upstream.module_zip.sha256")
    if observed_sha != expected_sha:
        fail(f"wacogo module zip SHA-256 mismatch: expected {expected_sha}, observed {observed_sha}")

    root = string_field(locked_zip["root"], "upstream.module_zip.root")
    names: set[str] = set()
    files: list[zipfile.ZipInfo] = []
    uncompressed_bytes = 0
    try:
        with zipfile.ZipFile(module_zip_path) as archive:
            for info in archive.infolist():
                name = info.filename
                if name in names:
                    fail(f"module zip contains duplicate member {name!r}")
                names.add(name)
                if "\\" in name or not name.startswith(root):
                    fail(f"module zip member is outside locked module root: {name!r}")
                relative = name.removeprefix(root)
                raw_parts = relative.split("/")
                pure = PurePosixPath(relative)
                if (
                    not relative
                    or pure.is_absolute()
                    or any(part in ("", ".", "..") for part in raw_parts)
                ):
                    fail(f"unsafe module zip member path: {name!r}")
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(unix_mode)
                if info.is_dir():
                    if file_type not in (0, stat.S_IFDIR):
                        fail(f"module zip directory has an unsafe file type: {name!r}")
                    continue
                if file_type not in (0, stat.S_IFREG):
                    fail(f"module zip contains a link or special file: {name!r}")
                files.append(info)
                uncompressed_bytes += info.file_size
    except (OSError, zipfile.BadZipFile) as error:
        fail(f"cannot inspect wacogo module zip: {error}")

    expected_files = positive_int(
        locked_zip["regular_file_count"], "upstream.module_zip.regular_file_count"
    )
    expected_bytes = positive_int(
        locked_zip["uncompressed_regular_file_bytes"],
        "upstream.module_zip.uncompressed_regular_file_bytes",
    )
    if len(files) != expected_files or uncompressed_bytes != expected_bytes:
        fail(
            "wacogo module zip inventory mismatch: "
            f"expected {expected_files} files/{expected_bytes} bytes, "
            f"observed {len(files)} files/{uncompressed_bytes} bytes"
        )
    return files


def extract_module_zip(
    lock: dict[str, object], module_zip_path: Path, files: list[zipfile.ZipInfo], output: Path
) -> None:
    root = string_field(
        object_field(object_field(lock["upstream"], "upstream")["module_zip"], "upstream.module_zip")["root"],
        "upstream.module_zip.root",
    )
    with zipfile.ZipFile(module_zip_path) as archive:
        for info in files:
            relative = PurePosixPath(info.filename.removeprefix(root))
            destination = output.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            destination.chmod(0o644)


def check_upstream_files(lock: dict[str, object], source: Path) -> None:
    upstream = object_field(lock["upstream"], "upstream")
    checks = (
        ("LICENSE", upstream["license_sha256"]),
        ("go.mod", upstream["go_mod_sha256"]),
        ("go.sum", upstream["go_sum_sha256"]),
    )
    for relative, expected_value in checks:
        path = regular_file(source / relative, f"upstream {relative}")
        expected = sha256_field(expected_value, f"upstream {relative} digest")
        observed = file_sha256(path)
        if observed != expected:
            fail(f"upstream {relative} digest mismatch: expected {expected}, observed {observed}")


def apply_patches(lock: dict[str, object], source: Path) -> None:
    patchset = object_field(lock["patchset"], "patchset")
    patches = patchset["patches"]
    assert isinstance(patches, list)
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "LC_ALL": "C",
        }
    )
    for entry_value in patches:
        assert isinstance(entry_value, dict)
        patch_path = locked_relative_path(entry_value["file"], "patch file")
        command = [
            "git",
            "-C",
            os.fspath(source),
            "apply",
            "--check",
            "--whitespace=error-all",
            os.fspath(patch_path),
        ]
        try:
            subprocess.run(command, check=True, env=environment)
            command.remove("--check")
            subprocess.run(command, check=True, env=environment)
        except (OSError, subprocess.CalledProcessError) as error:
            fail(f"cannot apply locked patch {patch_path.name}: {error}")


def source_tree_identity(source: Path) -> tuple[str, int]:
    files: list[tuple[str, Path]] = []
    for path in source.rglob("*"):
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            fail(f"cannot inspect patched source path {path}: {error}")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            fail(f"patched source contains a link or special file: {path}")
        relative = path.relative_to(source).as_posix()
        files.append((relative, path))
    files.sort(key=lambda item: item[0].encode("utf-8"))
    tree = hashlib.sha256()
    for relative, path in files:
        line = f"{file_sha256(path)}  ./{relative}\n".encode("utf-8")
        tree.update(line)
    return tree.hexdigest(), len(files)


def prepare(lock: dict[str, object], module_zip: Path, output: Path, receipt: Path | None) -> None:
    files = verify_module_zip(lock, module_zip)
    output = output.expanduser().absolute()
    if os.path.lexists(output):
        fail(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    if receipt is not None:
        receipt = receipt.expanduser().absolute()
        if receipt == output or output in receipt.parents:
            fail("receipt must be outside the verified patched-source tree")
        if os.path.lexists(receipt):
            fail(f"receipt already exists: {receipt}")

    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    staged_source = stage / "source"
    staged_source.mkdir(mode=0o700)
    published = False
    try:
        extract_module_zip(lock, module_zip, files, staged_source)
        check_upstream_files(lock, staged_source)
        apply_patches(lock, staged_source)
        observed_tree, observed_files = source_tree_identity(staged_source)
        expected_tree = object_field(
            object_field(lock["patchset"], "patchset")["post_patch_tree"],
            "patchset.post_patch_tree",
        )
        expected_sha = sha256_field(expected_tree["sha256"], "post-patch tree SHA-256")
        expected_files = positive_int(expected_tree["regular_file_count"], "post-patch file count")
        if observed_tree != expected_sha or observed_files != expected_files:
            fail(
                "patched source tree mismatch: "
                f"expected {expected_sha}/{expected_files} files, "
                f"observed {observed_tree}/{observed_files} files"
            )
        if os.path.lexists(output):
            fail(f"output appeared while staging source: {output}")
        staged_source.rename(output)
        published = True

        result = {
            "schema": "visa.wacogo-prepared-source.v1",
            "derivative_id": object_field(lock["derivative"], "derivative")["id"],
            "upstream_module_zip_sha256": object_field(
                object_field(lock["upstream"], "upstream")["module_zip"],
                "upstream.module_zip",
            )["sha256"],
            "patchset_id": object_field(lock["patchset"], "patchset")["id"],
            "patchset_sha256": object_field(lock["patchset"], "patchset")[
                "ordered_concatenation_sha256"
            ],
            "source_tree_sha256": observed_tree,
            "regular_file_count": observed_files,
        }
        if receipt is not None:
            receipt.parent.mkdir(parents=True, exist_ok=True)
            temporary_receipt = receipt.with_name(f".{receipt.name}.tmp-{os.getpid()}")
            try:
                with temporary_receipt.open("x", encoding="utf-8") as stream:
                    json.dump(result, stream, indent=2, sort_keys=True)
                    stream.write("\n")
                temporary_receipt.rename(receipt)
            finally:
                temporary_receipt.unlink(missing_ok=True)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        if not published and os.path.lexists(output):
            # The script never intentionally publishes a partial tree. Do not
            # remove a destination that another process raced into place.
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="verify or materialize the locked vISA wacogo source without network access"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="verify committed source-lock, patch, and license inputs")
    prepare_parser = subparsers.add_parser(
        "prepare", help="verify, extract, patch, and publish a local module zip"
    )
    prepare_parser.add_argument("--module-zip", required=True, type=Path)
    prepare_parser.add_argument("--output", required=True, type=Path)
    prepare_parser.add_argument("--receipt", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        lock = load_lock()
        check_repository_assets(lock)
        if args.command == "prepare":
            prepare(lock, args.module_zip, args.output, args.receipt)
        else:
            patchset = object_field(lock["patchset"], "patchset")
            print(
                "wacogo-source-lock=verified "
                f"derivative={object_field(lock['derivative'], 'derivative')['id']} "
                f"patchset-sha256={patchset['ordered_concatenation_sha256']}"
            )
    except (OSError, SourceError) as error:
        print(f"wacogo source preparation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
