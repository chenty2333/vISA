#!/usr/bin/env python3
"""Mutation tests for the stock-zstd cross-host raw-evidence validator."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

import stock_zstd_cross_host as evidence


ROOT = Path(__file__).resolve().parents[1]
REVISION = "1" * 40
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


def load_runner() -> Any:
    path = ROOT / "scripts" / "run-stock-zstd-cross-host.py"
    spec = importlib.util.spec_from_file_location("stock_zstd_cross_host_runner_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: object) -> None:
    path.write_bytes(evidence.canonical_bytes(value) + b"\n")


def fake_identity(seed: bytes = b"x", size: int | None = None) -> dict[str, object]:
    return {
        "sha256": hashlib.sha256(seed).hexdigest(),
        "size": len(seed) if size is None else size,
    }


def host(endpoint: str) -> dict[str, object]:
    return {
        "schema": evidence.HOST_SCHEMA,
        "endpoint_id_sha256": hashlib.sha256(endpoint.encode()).hexdigest(),
        "hostname": endpoint,
        "kernel_release": "6.8.0-test",
        "operating_system": "Linux",
        "os_release": "Ubuntu 24.04 LTS",
        "isa": "x86_64",
        "executable": fake_identity(b"runner", 6),
    }


def status(mode: str, epoch: int, requests: int) -> dict[str, object]:
    return {
        "mode": mode,
        "authority_epoch": epoch,
        "completed_requests": requests,
        "bytes_read": 100,
        "bytes_written": 200,
    }


def artifact(path: Path, root: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(root).as_posix(),
        **evidence.file_identity(path),
    }


def build_fixture(root: Path, zstd: Path) -> tuple[Path, dict[str, Any]]:
    raw = root / "raw"
    raw.mkdir(parents=True)
    canonical_input = root / "input.bin"
    evidence.write_canonical_input(canonical_input)
    compressed = raw / "migrated-output.zst"
    completed = subprocess.run(
        [zstd, "-q", "-f", canonical_input, "-o", compressed],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    input_identity = evidence.file_identity(canonical_input)
    compressed_identity = evidence.file_identity(compressed)
    source_host = host("source-host")
    destination_host = host("destination-host")
    prepared = status("prepared", 1, 64)
    active = status("active", 2, 65)
    final = status("active", 2, 96)
    stdout_path = raw / "destination.stdout"
    stderr_path = raw / "destination.stderr"
    stdout_path.write_bytes(b"")
    stderr_path.write_bytes(b"")
    control_stdout_path = raw / "control.stdout"
    control_stderr_path = raw / "control.stderr"
    control_stdout_path.write_bytes(b"")
    control_stderr_path.write_bytes(b"")
    process = {
        "exit_status": 0,
        "stdout": evidence.file_identity(stdout_path),
        "stderr": evidence.file_identity(stderr_path),
    }
    write_json(raw / "remote-endpoint.json", destination_host)
    key_path = root / "test-host-key"
    generated = subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key_path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr.decode(errors="replace")
    public_fields = (root / "test-host-key.pub").read_text(encoding="ascii").split()
    known_hosts = raw / "known_hosts"
    known_hosts.write_text(
        f"[destination-host]:22 {public_fields[0]} {public_fields[1]}\n",
        encoding="ascii",
    )
    fingerprint_fields = subprocess.run(
        ["ssh-keygen", "-lf", known_hosts, "-E", "sha256"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=True,
    ).stdout.decode().split()
    host_key_fingerprint = fingerprint_fields[1]
    remote = {
        "schema": evidence.REMOTE_SCHEMA,
        "endpoint": destination_host,
        "prepared_status": prepared,
        "active_status": active,
        "final_status": final,
        "process": process,
        "materialized_output": compressed_identity,
    }
    write_json(raw / "remote-observation.json", remote)
    phases = []
    start = 1
    for name in (
        "source-checkpoint",
        "source-freeze-export",
        "transfer-and-destination-prepare",
        "source-fence",
        "destination-activate-and-resume",
        "output-fetch-and-external-oracle",
    ):
        phases.append(
            {
                "phase": name,
                "start_monotonic_ns": start,
                "end_monotonic_ns": start + 10,
                "duration_ns": 10,
            }
        )
        start += 10
    timing = {
        "schema": evidence.TIMING_SCHEMA,
        "clock": "python-time.monotonic_ns-controller",
        "phases": phases,
    }
    write_json(raw / "application-timing.json", timing)
    control_timing = {
        "schema": "visa-application-timing-v1",
        "clock": "python-time.monotonic_ns",
        "phases": [
            {
                "phase": "application",
                "role": "uninterrupted-control",
                "start_monotonic_ns": 1,
                "end_monotonic_ns": 2,
                "duration_ns": 1,
                "exit_status": 0,
            }
        ],
    }
    write_json(raw / "control-application-timing.json", control_timing)
    write_json(
        raw / "control-oracle-report.json",
        {
            "schema": "visa-stock-zstd-external-oracle-report-v1",
            "cell": "uninterrupted-control",
            "command": {
                "operation": "stock-zstd-decompress",
                "exit_status": 0,
                "stdout": evidence.file_identity(control_stdout_path),
                "stderr": evidence.file_identity(control_stderr_path),
            },
            "input": input_identity,
            "decoded": input_identity,
            "compressed": compressed_identity,
        },
    )
    transfer = [
        {
            "label": label,
            "path": path,
            "identity": fake_identity(label.encode(), len(label)),
        }
        for label, path in (
            ("application-aot", "binding/artifacts/application.aot"),
            ("checkpoint", "binding/artifacts/checkpoint.pb"),
            ("capsule-manifest", "binding/capsule/manifest.json"),
            ("capsule-state", "binding/capsule/state.sqlite"),
            ("provider-binary", "tools/visa_wasi_host"),
            ("proof-binder", "tools/visa-wasi-migration-bind"),
            ("remote-helper", "tools/run-stock-zstd-cross-host.py"),
            ("runtime-loader", "runtime/ld-linux-x86-64.so.2"),
            ("runtime-library:libc.so.6", "runtime/lib/libc.so.6"),
        )
    ]
    write_json(
        raw / "transfer-manifest.json",
        {"schema": "visa-stock-zstd-cross-host-transfer-v1", "objects": transfer},
    )
    receipt = {
        "schema": evidence.SCHEMA,
        "repository_revision": REVISION,
        "repository_source_snapshot": {
            "clean": True,
            "status_sha256": EMPTY_SHA,
            "tracked_patch_sha256": EMPTY_SHA,
            "untracked_file_count": 0,
            "untracked_manifest_sha256": EMPTY_SHA,
        },
        "case": {
            "workload": "stock-zstd-1.5.7-streaming-compression",
            "cut_location_source": "prearmed-post-hostcall-predicate",
            "cut_write_occurrence": evidence.CUT_WRITE_OCCURRENCE,
        },
        "input": input_identity,
        "build": {
            "application_aot": fake_identity(b"application", 11),
            "stock_zstd_build_receipt_sha256": hashlib.sha256(b"zstd").hexdigest(),
            "wanco_build_receipt_sha256": hashlib.sha256(b"wanco").hexdigest(),
            "wanco_optimization": "-O1",
        },
        "topology": {
            "source_compute": "local-native-x86_64-wanco-aot",
            "source_provider": "local-process",
            "destination_compute": "remote-native-x86_64-wanco-aot",
            "destination_provider": "remote-fresh-process-restored-from-capsule",
            "provider_capsule_transferred": True,
            "transport": "openssh-content-addressed-files-plus-command-stdio",
            "ssh_host_key_sha256": host_key_fingerprint,
            "ssh_known_hosts_sha256": evidence.sha256_file(known_hosts),
        },
        "source": {
            "endpoint": source_host,
            "post_checkpoint_status": status("active", 1, 63),
            "frozen_status": status("frozen", 1, 64),
            "fenced_status": status("fenced", 1, 64),
        },
        "destination": {
            "endpoint": destination_host,
            "prepared_status": prepared,
            "active_status": active,
            "final_status": final,
            "process": process,
        },
        "control": {
            "compressed_output": compressed_identity,
            "process": {
                "exit_status": 0,
                "stdout": evidence.file_identity(control_stdout_path),
                "stderr": evidence.file_identity(control_stderr_path),
            },
        },
        "oracle": {
            "kind": "native-zstd-raw-decompression-and-control-byte-identity",
            "producer_verdict_used": False,
            "input": input_identity,
            "decoded": input_identity,
            "compressed": compressed_identity,
        },
        "authority_boundary": {
            "trusted_coordinator": True,
            "source_fenced_before_destination_activation": True,
            "distributed_fencing": False,
            "cryptographic_host_attestation": False,
        },
        "timing": timing,
        "transfer_objects": transfer,
        "artifacts": {
            "remote_endpoint_observation": artifact(raw / "remote-endpoint.json", root),
            "remote_observation": artifact(raw / "remote-observation.json", root),
            "destination_process_stdout": artifact(stdout_path, root),
            "destination_process_stderr": artifact(stderr_path, root),
            "shared_compressed_output": artifact(compressed, root),
            "application_timing": artifact(raw / "application-timing.json", root),
            "ssh_known_hosts": artifact(known_hosts, root),
            "transfer_manifest": artifact(raw / "transfer-manifest.json", root),
            "control_process_stdout": artifact(control_stdout_path, root),
            "control_process_stderr": artifact(control_stderr_path, root),
            "control_oracle_report": artifact(raw / "control-oracle-report.json", root),
            "control_application_timing": artifact(raw / "control-application-timing.json", root),
        },
        "explicit_non_claims": evidence.NON_CLAIMS,
    }
    receipt_path = root / "receipt.json"
    write_json(receipt_path, receipt)
    return receipt_path, receipt


def expect_rejected(
    root: Path,
    receipt: dict[str, Any],
    zstd: Path,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    candidate = copy.deepcopy(receipt)
    mutation(candidate)
    path = root / "mutated.json"
    write_json(path, candidate)
    try:
        evidence.validate_receipt(path, expected_revision=REVISION, stock_zstd=zstd)
    except evidence.EvidenceError:
        return
    raise AssertionError("mutated cross-host evidence was accepted")


def main() -> int:
    zstd_path = shutil.which("zstd")
    assert zstd_path is not None
    zstd = Path(zstd_path)
    tests = 0
    with tempfile.TemporaryDirectory(prefix="visa-stock-zstd-cross-host-test-") as value:
        root = Path(value)
        receipt_path, receipt = build_fixture(root, zstd)
        evidence.validate_receipt(receipt_path, expected_revision=REVISION, stock_zstd=zstd)
        tests += 1

        expect_rejected(
            root,
            receipt,
            zstd,
            lambda value: value["oracle"].__setitem__("producer_verdict_used", True),
        )
        tests += 1
        expect_rejected(
            root,
            receipt,
            zstd,
            lambda value: value["destination"]["final_status"].__setitem__(
                "completed_requests", value["destination"]["active_status"]["completed_requests"]
            ),
        )
        tests += 1
        expect_rejected(
            root,
            receipt,
            zstd,
            lambda value: value["transfer_objects"].__setitem__(
                slice(None),
                [item for item in value["transfer_objects"] if not item["label"].startswith("runtime-library:")],
            ),
        )
        tests += 1
        expect_rejected(
            root,
            receipt,
            zstd,
            lambda value: value["case"].__setitem__("cut_write_occurrence", 63),
        )
        tests += 1

        output = root / receipt["artifacts"]["shared_compressed_output"]["path"]
        original = output.read_bytes()
        output.write_bytes(bytes([original[0] ^ 0x80]) + original[1:])
        try:
            evidence.validate_receipt(receipt_path, expected_revision=REVISION, stock_zstd=zstd)
        except evidence.EvidenceError:
            tests += 1
        else:
            raise AssertionError("mutated compressed bytes were accepted")
        output.write_bytes(original)

    runner = load_runner()
    same_host = runner.load_same_host_runner(ROOT)
    assert Path(same_host.checkpoint_source.__code__.co_filename).resolve() == (
        ROOT / "scripts" / "run-stock-zstd-migration-matrix.py"
    ).resolve()
    tests += 1
    hello = subprocess.run(
        ["python3", ROOT / "scripts" / "run-stock-zstd-cross-host.py", "remote-hello"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    assert hello.returncode == 0, hello.stderr.decode(errors="replace")
    evidence.validate_host(
        evidence.parse_canonical_json(hello.stdout, "remote hello test"),
        "remote hello test",
    )
    tests += 1
    print(f"stock-zstd cross-host tests: {tests}/8 passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
