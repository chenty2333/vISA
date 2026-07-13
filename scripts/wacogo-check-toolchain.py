#!/usr/bin/env python3
"""Verify the official Go toolchain locked for the vISA wacogo build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "third_party" / "wacogo" / "source-lock.json"
SCHEMA = "visa.wacogo-source-lock.v1"


class ToolchainError(RuntimeError):
    """The selected Go distribution does not match the build lock."""


def fail(message: str) -> None:
    raise ToolchainError(message)


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


def load_go_lock() -> dict[str, object]:
    try:
        with LOCK_PATH.open("r", encoding="utf-8") as stream:
            lock = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {LOCK_PATH.relative_to(ROOT)}: {error}")
    if not isinstance(lock, dict) or lock.get("schema") != SCHEMA:
        fail(f"source lock must use schema {SCHEMA}")
    try:
        go = lock["build_toolchain"]["go"]
    except (KeyError, TypeError) as error:
        fail(f"source lock does not contain build_toolchain.go: {error}")
    if not isinstance(go, dict):
        fail("source lock build_toolchain.go must be an object")
    required_strings = (
        "distribution",
        "version",
        "os",
        "arch",
        "archive_name",
        "archive_sha256",
        "archive_binary_path",
        "binary_sha256",
        "version_output",
    )
    for field in required_strings:
        if not isinstance(go.get(field), str) or not go[field]:
            fail(f"source lock build_toolchain.go.{field} must be a non-empty string")
    if not isinstance(go.get("archive_size"), int) or go["archive_size"] <= 0:
        fail("source lock build_toolchain.go.archive_size must be a positive integer")
    if go["distribution"] != "official-go.dev-release":
        fail("wacogo requires the official go.dev distribution")
    if go["os"] != "linux" or go["arch"] != "amd64":
        fail("Strict Stage 2 wacogo requires the linux/amd64 Go distribution")
    try:
        sidecar = lock["production_artifacts"]["sidecar"]
        accepted_component = sidecar["accepted_component"]
        execution_host_requirements = sidecar["execution_host_requirements"]
        target = sidecar["target"]
        binary = sidecar["binary"]
    except (KeyError, TypeError) as error:
        fail(f"source lock does not contain the production sidecar identity: {error}")
    expected_target = {
        "goos": go["os"],
        "goarch": go["arch"],
        "goamd64": "v1",
        "cgo_enabled": False,
    }
    if target != expected_target:
        fail(f"production sidecar target does not match the locked Go distribution: {target!r}")
    if accepted_component != {
        "size": 146486,
        "sha256": "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b",
    }:
        fail("source lock production sidecar accepted Component identity is invalid")
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
        fail("source lock production execution host requirements are invalid")
    if (
        not isinstance(binary, dict)
        or not isinstance(binary.get("size"), int)
        or binary["size"] <= 0
        or not isinstance(binary.get("sha256"), str)
        or len(binary["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in binary["sha256"])
    ):
        fail("source lock production sidecar binary identity is invalid")
    return go


def check_archive(
    go: dict[str, object], archive_path: Path
) -> tuple[dict[str, tuple[int, str]], set[str]]:
    regular_file(archive_path, "Go release archive")
    observed_size = archive_path.stat().st_size
    expected_size = go["archive_size"]
    if observed_size != expected_size:
        fail(f"Go archive size mismatch: expected {expected_size}, observed {observed_size}")
    observed_sha = file_sha256(archive_path)
    expected_sha = go["archive_sha256"]
    if observed_sha != expected_sha:
        fail(f"Go archive SHA-256 mismatch: expected {expected_sha}, observed {observed_sha}")

    binary_member_name = go["archive_binary_path"]
    assert isinstance(binary_member_name, str)
    names: set[str] = set()
    files: dict[str, tuple[int, str]] = {}
    directories: set[str] = set()
    observed_binary_sha: str | None = None
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                name = member.name
                if name in names:
                    fail(f"Go archive contains duplicate member {name!r}")
                names.add(name)
                if "\\" in name:
                    fail(f"Go archive member uses a non-portable separator: {name!r}")
                raw_parts = name.split("/")
                pure = PurePosixPath(name)
                if (
                    pure.is_absolute()
                    or not pure.parts
                    or pure.parts[0] != "go"
                    or any(part in ("", ".", "..") for part in raw_parts)
                ):
                    fail(f"unsafe Go archive member path: {name!r}")
                if not (member.isfile() or member.isdir()):
                    fail(f"Go archive contains a link or special member: {name!r}")
                relative = PurePosixPath(*pure.parts[1:]).as_posix()
                if member.isdir():
                    if relative != ".":
                        directories.add(relative)
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    fail(f"cannot read Go archive member: {name!r}")
                digest = hashlib.sha256()
                for block in iter(lambda: extracted.read(1024 * 1024), b""):
                    digest.update(block)
                member_sha = digest.hexdigest()
                files[relative] = (member.size, member_sha)
                if name == binary_member_name:
                    observed_binary_sha = member_sha
    except (OSError, tarfile.TarError) as error:
        fail(f"cannot inspect Go release archive: {error}")
    if observed_binary_sha is None:
        fail(f"Go release archive is missing {binary_member_name}")
    if observed_binary_sha != go["binary_sha256"]:
        fail(
            "Go binary inside release archive does not match source lock: "
            f"expected {go['binary_sha256']}, observed {observed_binary_sha}"
        )
    return files, directories


def resolve_go(configured: str) -> Path:
    candidate = Path(configured).expanduser()
    if candidate.parent != Path(".") or "/" in configured:
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).absolute()
        regular_file(candidate, "Go executable")
        return candidate.resolve()
    resolved = shutil.which(configured)
    if resolved is None:
        fail(f"cannot find Go executable {configured!r}")
    path = Path(resolved)
    regular_file(path, "Go executable")
    return path.resolve()


def run_go(go_binary: Path, arguments: list[str], environment: dict[str, str]) -> str:
    try:
        result = subprocess.run(
            [os.fspath(go_binary), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"cannot inspect Go executable {go_binary}: {error}")
    if result.stderr:
        fail(f"Go inspection emitted unexpected stderr: {result.stderr.strip()}")
    return result.stdout.strip()


def check_go_binary(go: dict[str, object], configured: str) -> tuple[Path, Path]:
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        fail(
            "Strict Stage 2 wacogo builds require a Linux x86-64 host; "
            f"observed {platform.system()} {platform.machine()}"
        )
    go_binary = resolve_go(configured)
    observed_sha = file_sha256(go_binary)
    if observed_sha != go["binary_sha256"]:
        fail(
            "Go executable is not the locked official-release binary: "
            f"expected {go['binary_sha256']}, observed {observed_sha}"
        )

    environment = os.environ.copy()
    for name in (
        "GOENV",
        "GOEXPERIMENT",
        "GOFLAGS",
        "GOROOT",
        "GOTOOLDIR",
        "GOTOOLCHAIN",
        "GOWORK",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "CGO_ENABLED": "0",
            "GOARCH": str(go["arch"]),
            "GOENV": "off",
            "GOOS": str(go["os"]),
            "GOAMD64": "v1",
            "GOTELEMETRY": "off",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOVCS": "*:off",
            "GOWORK": "off",
        }
    )
    version_output = run_go(go_binary, ["version"], environment)
    if version_output != go["version_output"]:
        fail(
            f"Go version mismatch: expected {go['version_output']!r}, observed {version_output!r}"
        )
    raw_environment = run_go(
        go_binary,
        ["env", "-json", "GOOS", "GOARCH", "GOROOT", "GOTOOLDIR", "GOVERSION"],
        environment,
    )
    try:
        observed = json.loads(raw_environment)
    except json.JSONDecodeError as error:
        fail(f"cannot decode go env output: {error}")
    expected = {"GOOS": go["os"], "GOARCH": go["arch"], "GOVERSION": go["version"]}
    for name, value in expected.items():
        if observed.get(name) != value:
            fail(f"Go environment {name} mismatch: expected {value!r}, observed {observed.get(name)!r}")
    goroot_value = observed.get("GOROOT")
    gotooldir_value = observed.get("GOTOOLDIR")
    if not isinstance(goroot_value, str) or not isinstance(gotooldir_value, str):
        fail("go env did not return GOROOT and GOTOOLDIR strings")
    goroot = Path(goroot_value).resolve()
    gotooldir = Path(gotooldir_value).resolve()
    expected_binary = (goroot / "bin" / "go").resolve()
    if go_binary != expected_binary:
        fail(f"selected Go executable is not GOROOT/bin/go: {go_binary} != {expected_binary}")
    if goroot not in gotooldir.parents:
        fail(f"GOTOOLDIR escapes the selected official GOROOT: {gotooldir}")
    version_file = regular_file(goroot / "VERSION", "Go GOROOT VERSION file")
    try:
        first_version_line = version_file.read_text(encoding="utf-8").splitlines()[0]
    except (OSError, UnicodeDecodeError, IndexError) as error:
        fail(f"cannot read Go GOROOT VERSION file: {error}")
    if first_version_line != go["version"]:
        fail(
            f"Go GOROOT VERSION mismatch: expected {go['version']!r}, "
            f"observed {first_version_line!r}"
        )
    return go_binary, goroot


def check_goroot(
    goroot: Path,
    archive_files: dict[str, tuple[int, str]],
    archive_directories: set[str],
) -> None:
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for path in goroot.rglob("*"):
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            fail(f"cannot inspect selected GOROOT path {path}: {error}")
        relative = path.relative_to(goroot).as_posix()
        if stat.S_ISDIR(mode):
            observed_directories.add(relative)
            continue
        if not stat.S_ISREG(mode):
            fail(f"selected GOROOT contains a link or special file: {path}")
        observed_files.add(relative)
        expected = archive_files.get(relative)
        if expected is None:
            fail(f"selected GOROOT contains a file absent from the official archive: {relative}")
        expected_size, expected_sha = expected
        observed_size = path.stat().st_size
        if observed_size != expected_size:
            fail(
                f"selected GOROOT file size mismatch for {relative}: "
                f"expected {expected_size}, observed {observed_size}"
            )
        observed_sha = file_sha256(path)
        if observed_sha != expected_sha:
            fail(
                f"selected GOROOT file digest mismatch for {relative}: "
                f"expected {expected_sha}, observed {observed_sha}"
            )
    missing_files = sorted(set(archive_files) - observed_files)
    if missing_files:
        fail(f"selected GOROOT is missing official archive file: {missing_files[0]}")
    extra_directories = sorted(observed_directories - archive_directories)
    missing_directories = sorted(archive_directories - observed_directories)
    if extra_directories:
        fail(f"selected GOROOT contains an extra directory: {extra_directories[0]}")
    if missing_directories:
        fail(f"selected GOROOT is missing official archive directory: {missing_directories[0]}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="verify the exact official Go distribution used to build wacogo"
    )
    parser.add_argument(
        "--archive",
        required=True,
        type=Path,
        help="pre-fetched official go1.26.5 linux/amd64 archive",
    )
    parser.add_argument(
        "--go",
        default=os.environ.get("VISA_WACOGO_GO", "go"),
        help="go executable extracted from the locked archive",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        go = load_go_lock()
        archive_files, archive_directories = check_archive(go, args.archive.expanduser())
        go_binary, goroot = check_go_binary(go, args.go)
        check_goroot(goroot, archive_files, archive_directories)
    except (OSError, ToolchainError) as error:
        print(f"wacogo Go toolchain check failed: {error}", file=sys.stderr)
        return 1
    print(
        "wacogo-go-toolchain=verified "
        f"version={go['version']} os={go['os']} arch={go['arch']} "
        f"archive-sha256={go['archive_sha256']} binary={go_binary}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
