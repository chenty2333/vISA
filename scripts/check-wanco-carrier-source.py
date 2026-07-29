#!/usr/bin/env python3
"""Validate the exact upstream Wanco source and local build-only patches."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "third_party" / "wanco" / "source-lock.json"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"wanco carrier source check: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(source: Path, *args: str, stdin: bytes | None = None) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source), *args],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout.decode("utf-8", errors="strict").strip()


def require_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        fail(f"{label} must contain exactly {sorted(keys)}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--patched", action="store_true")
    args = parser.parse_args()
    if args.patched and args.source is None:
        fail("--patched requires --source")

    lock = require_keys(
        json.loads(LOCK.read_text(encoding="utf-8")),
        {"schema", "upstream", "patches", "build"},
        "source lock",
    )
    if lock["schema"] != "visa-wanco-carrier-source-lock-v1":
        fail("unknown source-lock schema")
    upstream = require_keys(
        lock["upstream"],
        {
            "repository",
            "revision",
            "tree",
            "license",
            "license_sha256",
            "cargo_lock_sha256",
        },
        "upstream",
    )
    if upstream["repository"] != "https://github.com/tamaroning/wanco.git":
        fail("unexpected upstream repository")
    if upstream["license"] != "MIT":
        fail("unexpected upstream license")
    for field in ("revision", "tree"):
        if not isinstance(upstream[field], str) or HEX40.fullmatch(upstream[field]) is None:
            fail(f"upstream.{field} is not a lowercase Git object ID")
    for field in ("license_sha256", "cargo_lock_sha256"):
        if not isinstance(upstream[field], str) or HEX64.fullmatch(upstream[field]) is None:
            fail(f"upstream.{field} is not a lowercase SHA-256")
    build = require_keys(
        lock["build"],
        {
            "base",
            "llvm_major",
            "cache_root",
            "excluded_source_subtree",
            "patched_dockerfile_sha256",
        },
        "build",
    )
    if build["base"] != "debian:bookworm-slim" or build["llvm_major"] != 17:
        fail("unexpected locked build base or LLVM major")
    if (
        not isinstance(build["patched_dockerfile_sha256"], str)
        or HEX64.fullmatch(build["patched_dockerfile_sha256"]) is None
    ):
        fail("build.patched_dockerfile_sha256 is not a lowercase SHA-256")

    patches = lock["patches"]
    if not isinstance(patches, list) or len(patches) != 2:
        fail("exactly two ordered build-only patches are required")
    checked_patches: list[tuple[dict[str, object], Path]] = []
    for index, raw_patch in enumerate(patches):
        patch = require_keys(
            raw_patch,
            {"path", "sha256", "scope", "purpose"},
            f"patch[{index}]",
        )
        if patch["scope"] != "build-only":
            fail("Wanco runtime/compiler semantics must remain unpatched")
        patch_path = ROOT / str(patch["path"])
        if not patch_path.is_file() or patch_path.is_symlink():
            fail(f"patch is absent or unsafe: {patch_path}")
        if sha256(patch_path) != patch["sha256"]:
            fail(f"committed build patch digest differs for {patch_path}")
        checked_patches.append((patch, patch_path))

    if args.source is not None:
        source = args.source.resolve(strict=True)
        if git(source, "rev-parse", "HEAD^{commit}") != upstream["revision"]:
            fail("source HEAD differs from locked Wanco revision")
        if git(source, "rev-parse", "HEAD^{tree}") != upstream["tree"]:
            fail("source commit tree differs from locked Wanco tree")
        license_bytes = subprocess.run(
            ["git", "-C", str(source), "show", "HEAD:LICENSE"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        cargo_lock_bytes = subprocess.run(
            ["git", "-C", str(source), "show", "HEAD:Cargo.lock"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
        if hashlib.sha256(license_bytes).hexdigest() != upstream["license_sha256"]:
            fail("upstream LICENSE digest mismatch")
        if hashlib.sha256(cargo_lock_bytes).hexdigest() != upstream["cargo_lock_sha256"]:
            fail("upstream Cargo.lock digest mismatch")
        forward_patch_set = b"\n".join(path.read_bytes() for _, path in checked_patches)
        if args.patched:
            if git(source, "status", "--short") != "M Dockerfile":
                fail("patched source has changes outside the locked Dockerfile patches")
            if sha256(source / "Dockerfile") != build["patched_dockerfile_sha256"]:
                fail("patched Dockerfile differs from the locked build result")
        else:
            git(source, "apply", "--check", "-", stdin=forward_patch_set)
            if git(source, "status", "--short"):
                fail("unpatched source checkout is dirty")

    print(
        "wanco-carrier-source-lock "
        f"revision={upstream['revision']} tree={upstream['tree']} "
        "patch-sha256s="
        + ",".join(str(patch["sha256"]) for patch, _ in checked_patches)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
