#!/usr/bin/env python3
"""Securely publish and read retained artifacts referenced by JSON receipts."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any


class ArtifactError(RuntimeError):
    """Raised when a retained artifact reference cannot be trusted."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactError(message)


def canonical_relative_path(value: object, label: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{label} path must be non-empty")
    assert isinstance(value, str)
    _require(
        "\\" not in value and "\x00" not in value,
        f"{label} path is not canonical POSIX",
    )
    path = PurePosixPath(value)
    _require(
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in ("", ".", "..") for part in path.parts),
        f"{label} path must be canonical and relative: {value!r}",
    )
    return value


def validate_reference(value: object, label: str) -> dict[str, Any]:
    _require(
        isinstance(value, dict) and set(value) == {"path", "sha256", "size"},
        f"{label} reference has the wrong fields",
    )
    assert isinstance(value, dict)
    relative = canonical_relative_path(value["path"], label)
    digest = value["sha256"]
    size = value["size"]
    _require(
        isinstance(digest, str)
        and len(digest) == 64
        and digest == digest.lower()
        and all(character in "0123456789abcdef" for character in digest),
        f"{label} sha256 is invalid",
    )
    _require(
        isinstance(size, int) and not isinstance(size, bool) and size >= 0,
        f"{label} size is invalid",
    )
    return {"path": relative, "sha256": digest, "size": size}


class ReadBudget:
    """Tracks aggregate bytes and rejects path/inode aliases during one validation."""

    def __init__(self, max_total_bytes: int) -> None:
        _require(max_total_bytes >= 0, "artifact read budget must be nonnegative")
        self.max_total_bytes = max_total_bytes
        self.total_bytes = 0
        self._paths: dict[
            str,
            tuple[
                tuple[int, int, int, int, int, int, int],
                tuple[str, int],
            ],
        ] = {}
        self._inodes: dict[tuple[int, int], str] = {}

    def account(
        self,
        relative: str,
        file_stat: os.stat_result,
        reference: dict[str, Any],
        label: str,
    ) -> None:
        identity = (file_stat.st_dev, file_stat.st_ino)
        metadata = (
            file_stat.st_dev,
            file_stat.st_ino,
            file_stat.st_mode,
            file_stat.st_nlink,
            file_stat.st_size,
            file_stat.st_mtime_ns,
            file_stat.st_ctime_ns,
        )
        declared = (reference["sha256"], reference["size"])
        prior = self._paths.get(relative)
        if prior is not None:
            _require(
                prior == (metadata, declared),
                f"{label} path or reference changed between reads: {relative}",
            )
            return
        prior_path = self._inodes.get(identity)
        _require(
            prior_path is None,
            f"{label} aliases retained artifact path {prior_path}: {relative}",
        )
        self._paths[relative] = (metadata, declared)
        self._inodes[identity] = relative
        self.total_bytes += file_stat.st_size
        _require(
            self.total_bytes <= self.max_total_bytes,
            "retained artifacts exceed the aggregate read bound",
        )


def _open_regular_file(
    root: Path, relative: str, label: str
) -> tuple[int, os.stat_result]:
    canonical_relative_path(relative, label)
    absolute_root = root.absolute()
    try:
        root_stat = absolute_root.lstat()
        resolved_root = absolute_root.resolve(strict=True)
    except OSError as error:
        raise ArtifactError(f"cannot stat {label} root {root}: {error}") from error
    _require(
        resolved_root == absolute_root,
        f"{label} root contains a symlink: {root}",
    )
    _require(
        stat.S_ISDIR(root_stat.st_mode) and not stat.S_ISLNK(root_stat.st_mode),
        f"{label} root must be a real directory",
    )
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY | os.O_CLOEXEC | nofollow | os.O_NONBLOCK
    directory_flags = flags | os.O_DIRECTORY
    descriptors: list[int] = []
    file_descriptor: int | None = None
    try:
        current = os.open(absolute_root, directory_flags)
        descriptors.append(current)
        parts = relative.split("/")
        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
        file_descriptor = os.open(parts[-1], flags, dir_fd=current)
        file_stat = os.fstat(file_descriptor)
    except OSError as error:
        if file_descriptor is not None:
            os.close(file_descriptor)
        raise ArtifactError(
            f"cannot securely open {label} {relative}: {error}"
        ) from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    assert file_descriptor is not None
    try:
        _require(
            stat.S_ISREG(file_stat.st_mode),
            f"{label} must be a regular file: {relative}",
        )
        _require(
            file_stat.st_nlink == 1,
            f"{label} must not be hard-linked: {relative}",
        )
    except ArtifactError:
        os.close(file_descriptor)
        raise
    return file_descriptor, file_stat


def read_reference(
    root: Path,
    value: object,
    label: str,
    *,
    budget: ReadBudget,
    max_bytes: int,
) -> bytes:
    reference = validate_reference(value, label)
    relative = reference["path"]
    file_descriptor, file_stat = _open_regular_file(root, relative, label)
    try:
        _require(
            file_stat.st_size == reference["size"],
            f"{label} size differs from its retained artifact",
        )
        _require(
            file_stat.st_size <= max_bytes,
            f"{label} exceeds the {max_bytes}-byte file bound",
        )
        budget.account(relative, file_stat, reference, label)
        chunks: list[bytes] = []
        remaining = file_stat.st_size
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 1024 * 1024))
            _require(bool(chunk), f"{label} changed while reading: {relative}")
            chunks.append(chunk)
            remaining -= len(chunk)
        _require(
            not os.read(file_descriptor, 1),
            f"{label} grew while reading: {relative}",
        )
        after = os.fstat(file_descriptor)
        before_metadata = (
            file_stat.st_dev,
            file_stat.st_ino,
            file_stat.st_mode,
            file_stat.st_nlink,
            file_stat.st_size,
            file_stat.st_mtime_ns,
            file_stat.st_ctime_ns,
        )
        after_metadata = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        _require(
            after_metadata == before_metadata,
            f"{label} metadata changed while reading: {relative}",
        )
    except OSError as error:
        raise ArtifactError(
            f"cannot securely read {label} {relative}: {error}"
        ) from error
    finally:
        os.close(file_descriptor)
    payload = b"".join(chunks)
    _require(
        hashlib.sha256(payload).hexdigest() == reference["sha256"],
        f"{label} sha256 differs from its retained artifact",
    )
    return payload


def read_bounded_file(path: Path, label: str, *, max_bytes: int) -> bytes:
    """Read a top-level single-link file through the same no-follow boundary."""
    _require(max_bytes >= 0, f"{label} file bound must be nonnegative")
    absolute = path.absolute()
    file_descriptor, file_stat = _open_regular_file(
        absolute.parent, absolute.name, label
    )
    try:
        _require(
            file_stat.st_size <= max_bytes,
            f"{label} exceeds the {max_bytes}-byte file bound",
        )
        chunks: list[bytes] = []
        remaining = file_stat.st_size
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 1024 * 1024))
            _require(bool(chunk), f"{label} changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        _require(not os.read(file_descriptor, 1), f"{label} grew while reading")
        after = os.fstat(file_descriptor)
        before_metadata = (
            file_stat.st_dev,
            file_stat.st_ino,
            file_stat.st_mode,
            file_stat.st_nlink,
            file_stat.st_size,
            file_stat.st_mtime_ns,
            file_stat.st_ctime_ns,
        )
        after_metadata = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        _require(
            after_metadata == before_metadata,
            f"{label} metadata changed while reading",
        )
    except OSError as error:
        raise ArtifactError(f"cannot securely read {label} {path}: {error}") from error
    finally:
        os.close(file_descriptor)
    return b"".join(chunks)


def publish_reference(source: Path, root: Path, relative: str) -> dict[str, Any]:
    canonical_relative_path(relative, "retained artifact")
    if source.is_symlink() or not source.is_file():
        raise ArtifactError(f"retained artifact source is not a regular file: {source}")
    absolute_root = root.absolute()
    try:
        resolved_root = absolute_root.resolve(strict=True)
    except OSError as error:
        raise ArtifactError(f"cannot resolve retained artifact root {root}: {error}") from error
    _require(
        resolved_root == absolute_root,
        f"retained artifact root contains a symlink: {root}",
    )
    root_stat = absolute_root.lstat()
    _require(
        stat.S_ISDIR(root_stat.st_mode) and not stat.S_ISLNK(root_stat.st_mode),
        f"retained artifact root must be a real directory: {root}",
    )
    parts = relative.split("/")
    leaf = parts[-1]
    temporary = leaf + f".tmp.{os.getpid()}"
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | nofollow | os.O_DIRECTORY
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | nofollow
    )
    try:
        source_descriptor = os.open(
            source, os.O_RDONLY | os.O_CLOEXEC | nofollow
        )
    except OSError as error:
        raise ArtifactError(
            f"cannot securely open retained artifact source {source}: {error}"
        ) from error
    directory_descriptors: list[int] = []
    destination_descriptor: int | None = None
    temporary_created = False
    digest = hashlib.sha256()
    copied_size = 0
    try:
        source_before = os.fstat(source_descriptor)
        _require(
            stat.S_ISREG(source_before.st_mode) and source_before.st_nlink >= 1,
            f"retained artifact source is not a regular file: {source}",
        )
        current = os.open(absolute_root, directory_flags)
        directory_descriptors.append(current)
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=current)
            except FileExistsError:
                pass
            current = os.open(part, directory_flags, dir_fd=current)
            directory_descriptors.append(current)
        try:
            os.stat(leaf, dir_fd=current, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ArtifactError(f"retained artifact already exists: {relative}")
        destination_descriptor = os.open(
            temporary, flags, 0o600, dir_fd=current
        )
        temporary_created = True
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            copied_size += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                view = view[written:]
        os.fsync(destination_descriptor)
        source_after = os.fstat(source_descriptor)
        source_metadata_before = (
            source_before.st_dev,
            source_before.st_ino,
            source_before.st_mode,
            source_before.st_nlink,
            source_before.st_size,
            source_before.st_mtime_ns,
            source_before.st_ctime_ns,
        )
        source_metadata_after = (
            source_after.st_dev,
            source_after.st_ino,
            source_after.st_mode,
            source_after.st_nlink,
            source_after.st_size,
            source_after.st_mtime_ns,
            source_after.st_ctime_ns,
        )
        _require(
            source_metadata_after == source_metadata_before
            and copied_size == source_before.st_size,
            f"retained artifact source changed while copying: {source}",
        )
        os.close(destination_descriptor)
        destination_descriptor = None
        os.link(
            temporary,
            leaf,
            src_dir_fd=current,
            dst_dir_fd=current,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=current)
        temporary_created = False
        os.fsync(current)
    except OSError as error:
        raise ArtifactError(f"cannot publish retained artifact {relative}: {error}") from error
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if temporary_created and directory_descriptors:
            try:
                os.unlink(temporary, dir_fd=directory_descriptors[-1])
            except FileNotFoundError:
                pass
        for descriptor in reversed(directory_descriptors):
            os.close(descriptor)
    return {
        "path": relative,
        "sha256": digest.hexdigest(),
        "size": copied_size,
    }
