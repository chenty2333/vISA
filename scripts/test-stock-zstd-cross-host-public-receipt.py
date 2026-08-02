#!/usr/bin/env python3
"""Focused black-box tests for public S3Z-H receipt redaction and validation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "make-stock-zstd-cross-host-public-receipt.py"
FORBIDDEN_PUBLIC_KEYS = {
    "endpoint_id_sha256",
    "hostname",
    "kernel_release",
    "os_release",
    "ssh_host_key_sha256",
    "ssh_known_hosts",
    "ssh_known_hosts_sha256",
}


def load_private_fixture() -> Any:
    path = ROOT / "scripts" / "test-stock-zstd-cross-host.py"
    spec = importlib.util.spec_from_file_location("stock_zstd_cross_host_private_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_json(path: Path, value: object) -> None:
    path.write_bytes(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def nested_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(nested_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(nested_keys(item) for item in value))
    return set()


def invoke(*arguments: str | Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["python3", TOOL, *(str(argument) for argument in arguments)],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
    )


def validate(path: Path, revision: str, zstd: Path) -> subprocess.CompletedProcess[bytes]:
    receipt = path / "receipt.json" if path.is_dir() else path
    return invoke(
        "validate",
        receipt,
        "--expected-revision",
        revision,
        "--stock-zstd",
        zstd,
    )


def assert_rejected(path: Path, revision: str, zstd: Path, label: str) -> None:
    result = validate(path, revision, zstd)
    if result.returncode == 0:
        raise AssertionError(f"public receipt mutation was accepted: {label}")


def assert_rejected_forbidden_field(
    path: Path, revision: str, zstd: Path, label: str, field: str
) -> None:
    result = validate(path, revision, zstd)
    if result.returncode == 0:
        raise AssertionError(f"public receipt mutation was accepted: {label}")
    expected = f"forbidden public field {field!r}".encode("ascii")
    if expected not in result.stderr:
        raise AssertionError(
            f"public receipt mutation did not reach the forbidden-field guard: {label}: "
            f"{result.stderr.decode(errors='replace')}"
        )


def candidate(source: Path, root: Path, name: str) -> Path:
    destination = root / name
    shutil.copytree(source, destination)
    return destination


def refresh_artifact_reference(root: Path, artifact_key: str) -> None:
    """Retain receipt integrity so a JSON mutation reaches the redaction guard."""

    receipt_path = root / "receipt.json"
    receipt = read_json(receipt_path)
    reference = receipt["artifacts"][artifact_key]
    assert isinstance(reference, dict)
    relative = reference["path"]
    assert isinstance(relative, str)
    payload = root / relative
    reference["sha256"] = hashlib.sha256(payload.read_bytes()).hexdigest()
    reference["size"] = payload.stat().st_size
    canonical_json(receipt_path, receipt)


def inject_forbidden_hostname(root: Path, artifact_key: str) -> None:
    receipt = read_json(root / "receipt.json")
    reference = receipt["artifacts"][artifact_key]
    assert isinstance(reference, dict)
    relative = reference["path"]
    assert isinstance(relative, str)
    artifact_path = root / relative
    document = read_json(artifact_path)
    document["redaction_guard_probe"] = {"hostname": "forbidden-host.invalid"}
    canonical_json(artifact_path, document)
    refresh_artifact_reference(root, artifact_key)


def extend_fixture_to_26_objects(
    root: Path, receipt: dict[str, Any], fixture: Any
) -> None:
    """Match the real S3Z-H transfer inventory without changing v1 semantics."""

    objects = receipt["transfer_objects"]
    assert isinstance(objects, list)
    for index in range(len(objects), 26):
        label = f"bound-object:fixture-{index:02d}"
        objects.append(
            {
                "label": label,
                "path": f"binding/fixture-{index:02d}.json",
                "identity": fixture.fake_identity(label.encode(), len(label)),
            }
        )
    transfer = root / "raw" / "transfer-manifest.json"
    canonical_json(
        transfer,
        {"schema": "visa-stock-zstd-cross-host-transfer-v1", "objects": objects},
    )
    receipt["artifacts"]["transfer_manifest"] = fixture.artifact(transfer, root)
    canonical_json(root / "receipt.json", receipt)


def main() -> int:
    zstd_name = shutil.which("zstd")
    assert zstd_name is not None, "native zstd is required for this test"
    zstd = Path(zstd_name)
    private_fixture = load_private_fixture()
    tests = 0

    with tempfile.TemporaryDirectory(prefix="visa-stock-zstd-public-receipt-test-") as value:
        temporary = Path(value)
        private_root = temporary / "private"
        _, private_receipt = private_fixture.build_fixture(private_root, zstd)
        extend_fixture_to_26_objects(private_root, private_receipt, private_fixture)
        revision = private_fixture.REVISION
        assert private_receipt["repository_revision"] == revision

        public_root = temporary / "public"
        created = invoke(
            "create",
            private_root,
            public_root,
            "--expected-revision",
            revision,
            "--stock-zstd",
            zstd,
        )
        assert created.returncode == 0, created.stderr.decode(errors="replace")
        accepted = validate(public_root, revision, zstd)
        assert accepted.returncode == 0, accepted.stderr.decode(errors="replace")
        tests += 1

        assert not (public_root / "raw" / "known_hosts").exists()
        for path in (
            public_root / "receipt.json",
            public_root / "raw" / "remote-endpoint.json",
            public_root / "raw" / "remote-observation.json",
        ):
            assert not nested_keys(read_json(path)).intersection(FORBIDDEN_PUBLIC_KEYS), path
        tests += 1

        role_mutation = candidate(public_root, temporary, "role-mismatch")
        receipt = read_json(role_mutation / "receipt.json")
        receipt["source"]["endpoint"]["role"] = "destination"
        canonical_json(role_mutation / "receipt.json", receipt)
        assert_rejected(role_mutation, revision, zstd, "source endpoint role")
        tests += 1

        id_mutation = candidate(public_root, temporary, "id-mismatch")
        receipt = read_json(id_mutation / "receipt.json")
        receipt["destination"]["endpoint"]["run_scoped_endpoint_id_sha256"] = "0" * 64
        canonical_json(id_mutation / "receipt.json", receipt)
        assert_rejected(id_mutation, revision, zstd, "destination endpoint ID")
        tests += 1

        output_mutation = candidate(public_root, temporary, "output-mutation")
        output = output_mutation / "raw" / "migrated-output.zst"
        original = output.read_bytes()
        output.write_bytes(bytes([original[0] ^ 0x80]) + original[1:])
        assert_rejected(output_mutation, revision, zstd, "migrated compressed bytes")
        tests += 1

        hostname_mutation = candidate(public_root, temporary, "forbidden-hostname")
        receipt = read_json(hostname_mutation / "receipt.json")
        receipt["source"]["endpoint"]["hostname"] = "forbidden-host.invalid"
        canonical_json(hostname_mutation / "receipt.json", receipt)
        assert_rejected_forbidden_field(
            hostname_mutation,
            revision,
            zstd,
            "forbidden receipt hostname field",
            "hostname",
        )
        tests += 1

        ssh_field_mutation = candidate(public_root, temporary, "forbidden-ssh-field")
        receipt = read_json(ssh_field_mutation / "receipt.json")
        receipt["topology"]["ssh_host_key_sha256"] = "forbidden"
        canonical_json(ssh_field_mutation / "receipt.json", receipt)
        assert_rejected_forbidden_field(
            ssh_field_mutation,
            revision,
            zstd,
            "forbidden receipt SSH topology field",
            "ssh_host_key_sha256",
        )
        tests += 1

        ssh_file_mutation = candidate(public_root, temporary, "forbidden-known-hosts")
        (ssh_file_mutation / "raw" / "known_hosts").write_text(
            "forbidden-host.invalid ssh-ed25519 AAAA\n", encoding="ascii"
        )
        assert_rejected(ssh_file_mutation, revision, zstd, "forbidden known_hosts file")
        tests += 1

        symlink_root = temporary / "symlink-root"
        symlink_root.symlink_to(public_root, target_is_directory=True)
        assert_rejected(symlink_root, revision, zstd, "symlink public evidence root")
        tests += 1

        symlink_receipt = temporary / "symlink-receipt.json"
        symlink_receipt.symlink_to(public_root / "receipt.json")
        assert_rejected(symlink_receipt, revision, zstd, "symlink public receipt")
        tests += 1

        json_artifact_keys = (
            "application_timing",
            "control_application_timing",
            "control_oracle_report",
            "remote_endpoint_observation",
            "remote_observation",
            "transfer_manifest",
        )
        for artifact_key in json_artifact_keys:
            artifact_mutation = candidate(
                public_root, temporary, f"forbidden-json-{artifact_key}"
            )
            inject_forbidden_hostname(artifact_mutation, artifact_key)
            assert_rejected_forbidden_field(
                artifact_mutation,
                revision,
                zstd,
                f"forbidden hostname in {artifact_key}",
                "hostname",
            )
            tests += 1

    print(f"stock-zstd cross-host public receipt tests: {tests}/16 passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
