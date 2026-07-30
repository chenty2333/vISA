#!/usr/bin/env python3
"""Validate the exact Wanco source and carrier platform patch set."""

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
        {"schema", "upstream", "patches", "qualification", "build"},
        "source lock",
    )
    if lock["schema"] != "visa-wanco-carrier-source-lock-v3":
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
    qualification = require_keys(
        lock["qualification"],
        {
            "schema",
            "case_count",
            "profiles",
            "optimizations",
            "runner",
            "validator",
            "artifact_reader",
            "inputs",
        },
        "qualification",
    )
    if (
        qualification["schema"] != "visa-wanco-typed-checkpoint-corpus-v4"
        or qualification["case_count"] != 12
        or qualification["profiles"]
        != ["direct", "indirect", "data-segment", "post-import-root"]
        or qualification["optimizations"] != [0, 1, 2]
    ):
        fail("typed-restore qualification inventory changed")
    qualification_paths = {
        "runner": "third_party/wanco/corpus/run-typed-checkpoint-corpus.sh",
        "validator": "scripts/wanco_typed_corpus.py",
        "artifact_reader": "scripts/receipt_artifacts.py",
    }
    for field, expected_path in qualification_paths.items():
        entry = require_keys(
            qualification[field], {"path", "sha256"}, f"qualification.{field}"
        )
        if entry["path"] != expected_path:
            fail(f"qualification.{field} path changed")
        path = ROOT / expected_path
        if (
            not path.is_file()
            or path.is_symlink()
            or not isinstance(entry["sha256"], str)
            or HEX64.fullmatch(entry["sha256"]) is None
            or sha256(path) != entry["sha256"]
        ):
            fail(f"qualification.{field} digest mismatch")
    expected_inputs = [
        "third_party/wanco/corpus/typed-stackmap.wat",
        "third_party/wanco/corpus/typed-stackmap-indirect.wat",
        "third_party/wanco/corpus/data-segment-restore.c",
        "third_party/wanco/corpus/post-import-root.wat",
        "third_party/wanco/corpus/post-import-root-host.cc",
    ]
    inputs = qualification["inputs"]
    if not isinstance(inputs, list) or len(inputs) != len(expected_inputs):
        fail("typed-restore qualification input inventory changed")
    for index, (raw_entry, expected_path) in enumerate(
        zip(inputs, expected_inputs, strict=True)
    ):
        entry = require_keys(
            raw_entry, {"path", "sha256"}, f"qualification.inputs[{index}]"
        )
        path = ROOT / expected_path
        if (
            entry["path"] != expected_path
            or not path.is_file()
            or path.is_symlink()
            or not isinstance(entry["sha256"], str)
            or HEX64.fullmatch(entry["sha256"]) is None
            or sha256(path) != entry["sha256"]
        ):
            fail(f"qualification input mismatch: {expected_path}")
    build = require_keys(
        lock["build"],
        {
            "platform",
            "base",
            "llvm_major",
            "rust_toolchain",
            "hyperfine",
            "cache_root",
            "excluded_source_subtree",
            "build_recipe",
            "patched_files",
        },
        "build",
    )
    if build["platform"] != "linux/amd64":
        fail("Wanco carrier is currently defined only for linux/amd64")
    if not str(build["base"]).startswith("debian:bookworm-slim@sha256:"):
        fail("build base is not digest pinned")
    if build["llvm_major"] != 17 or build["rust_toolchain"] != "1.97.1":
        fail("unexpected locked LLVM or Rust toolchain")
    if build["hyperfine"] != "1.20.0":
        fail("unexpected locked hyperfine version")
    build_recipe = require_keys(
        build["build_recipe"],
        {"path", "sha256"},
        "build.build_recipe",
    )
    if build_recipe["path"] != "scripts/build-wanco-carrier.sh":
        fail("unexpected Wanco build recipe path")
    build_recipe_path = ROOT / str(build_recipe["path"])
    if not build_recipe_path.is_file() or build_recipe_path.is_symlink():
        fail("Wanco build recipe is absent or unsafe")
    if (
        not isinstance(build_recipe["sha256"], str)
        or HEX64.fullmatch(build_recipe["sha256"]) is None
        or sha256(build_recipe_path) != build_recipe["sha256"]
    ):
        fail("Wanco build recipe digest mismatch")
    expected_patched_files = {
        "Dockerfile",
        "lib-rt/api.cc",
        "lib-rt/arch/x86_64.h",
        "lib-rt/chkpt/chkpt_protobuf.cc",
        "lib-rt/osr/asr_exit.cc",
        "lib-rt/osr/wasm_stacktrace.h",
        "lib-rt/stacktrace/stacktrace.cc",
        "lib-rt/stacktrace/stacktrace.h",
        "lib-rt/wanco.h",
        "wanco/src/compile/compile_module.rs",
        "wanco/src/compile/control.rs",
        "wanco/src/compile/cr/checkpoint.rs",
        "wanco/src/compile/synthesize.rs",
        "wanco/src/context.rs",
    }
    patched_files = build["patched_files"]
    if not isinstance(patched_files, dict) or set(patched_files) != expected_patched_files:
        fail("build.patched_files does not name the complete mutation set")
    if any(
        not isinstance(digest, str) or HEX64.fullmatch(digest) is None
        for digest in patched_files.values()
    ):
        fail("build.patched_files contains a malformed SHA-256")

    patches = lock["patches"]
    if not isinstance(patches, list) or len(patches) != 9:
        fail("exactly nine ordered carrier platform patches are required")
    expected_scopes = [
        "build",
        "build",
        "runtime-correctness",
        "runtime-correctness",
        "build",
        "runtime-correctness",
        "runtime-correctness",
        "runtime-correctness",
        "runtime-correctness",
    ]
    checked_patches: list[tuple[dict[str, object], Path]] = []
    for index, raw_patch in enumerate(patches):
        patch = require_keys(
            raw_patch,
            {"path", "sha256", "scope", "purpose"},
            f"patch[{index}]",
        )
        if patch["scope"] != expected_scopes[index]:
            fail(f"patch[{index}] has the wrong scope")
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
            status = {
                line.strip() for line in git(source, "status", "--short").splitlines()
            }
            expected_status = {f"M {path}" for path in patched_files}
            if status != expected_status:
                fail(f"patched source mutation set differs: {sorted(status)}")
            for relative, expected_digest in patched_files.items():
                if sha256(source / relative) != expected_digest:
                    fail(f"patched source digest differs: {relative}")
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
