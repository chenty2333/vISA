#!/usr/bin/env python3
"""Validate raw evidence from one stock-zstd cross-host clean handoff."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, NoReturn


SCHEMA = "visa-stock-zstd-cross-host-clean-handoff-v1"
HOST_SCHEMA = "visa-cross-host-endpoint-observation-v1"
REMOTE_SCHEMA = "visa-stock-zstd-cross-host-remote-observation-v1"
TIMING_SCHEMA = "visa-stock-zstd-cross-host-timing-v1"
CANONICAL_INPUT_BYTES = 24 * 1024 * 1024
CANONICAL_INPUT_SEED = b"vISA stock zstd transparent migration input v1"
CUT_WRITE_OCCURRENCE = 64
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
HOST_KEY_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")

TOP_LEVEL_KEYS = {
    "artifacts",
    "authority_boundary",
    "build",
    "case",
    "control",
    "destination",
    "explicit_non_claims",
    "input",
    "oracle",
    "repository_revision",
    "repository_source_snapshot",
    "schema",
    "source",
    "timing",
    "topology",
    "transfer_objects",
}
ARTIFACT_KEYS = {
    "application_timing",
    "control_application_timing",
    "control_oracle_report",
    "control_process_stderr",
    "control_process_stdout",
    "destination_process_stderr",
    "destination_process_stdout",
    "remote_endpoint_observation",
    "remote_observation",
    "shared_compressed_output",
    "ssh_known_hosts",
    "transfer_manifest",
}
NON_CLAIMS = [
    "arbitrary-applications-or-resources",
    "cross-isa-execution",
    "distributed-fencing",
    "host-attestation-or-hostile-coordinator-security",
    "network-partition-lost-ack-or-reboot-recovery",
    "power-loss-or-storage-device-ordering",
    "production-orchestration",
    "sqlite-cross-host-execution",
    "statistical-performance-result",
]


class EvidenceError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise EvidenceError(message)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def file_identity(path: Path) -> dict[str, object]:
    return {"sha256": sha256_file(path), "size": path.stat().st_size}


def endpoint_observation(executable: Path) -> dict[str, object]:
    machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}", machine_id) is None:
        fail("host machine-id is not a 32-digit hexadecimal value")
    os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    pretty = next(
        (
            line.removeprefix("PRETTY_NAME=").strip().strip('"')
            for line in os_release.splitlines()
            if line.startswith("PRETTY_NAME=")
        ),
        "",
    )
    if not pretty:
        fail("host os-release has no PRETTY_NAME")
    executable = executable.resolve()
    material = b"visa-stock-zstd-cross-host-endpoint-v1\0" + machine_id.lower().encode()
    return {
        "schema": HOST_SCHEMA,
        "endpoint_id_sha256": sha256_bytes(material),
        "hostname": platform.node(),
        "kernel_release": platform.release(),
        "operating_system": platform.system(),
        "os_release": pretty,
        "isa": platform.machine(),
        "executable": file_identity(executable),
    }


def parse_canonical_json(payload: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                fail(f"{label} has duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse {label}: {error}")
    if canonical_bytes(value) + b"\n" != payload:
        fail(f"{label} is not canonical newline-terminated JSON")
    return value


def exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        fail(f"{label} keys differ: {actual}")
    return value


def string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a nonempty string")
    return value


def boolean(value: Any, expected: bool, label: str) -> None:
    if value is not expected:
        fail(f"{label} must be {expected}")


def integer(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{label} must be a nonnegative integer")
    if positive and value == 0:
        fail(f"{label} must be positive")
    return value


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail(f"{label} must be a lowercase SHA-256")
    return value


def identity(value: Any, label: str, *, positive: bool = False) -> dict[str, Any]:
    item = exact_object(value, {"sha256", "size"}, label)
    digest(item["sha256"], f"{label}.sha256")
    integer(item["size"], f"{label}.size", positive=positive)
    return item


def relative_path(value: Any, label: str) -> str:
    text = string(value, label)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or text != path.as_posix():
        fail(f"{label} is not a canonical relative path")
    return text


def read_reference(
    root: Path,
    value: Any,
    label: str,
    *,
    max_bytes: int,
) -> tuple[dict[str, Any], bytes]:
    reference = exact_object(value, {"path", "sha256", "size"}, label)
    path_text = relative_path(reference["path"], f"{label}.path")
    digest(reference["sha256"], f"{label}.sha256")
    size = integer(reference["size"], f"{label}.size")
    if size > max_bytes:
        fail(f"{label} exceeds its byte bound")
    path = root / path_text
    resolved_root = root.resolve()
    try:
        path.resolve(strict=True).relative_to(resolved_root)
    except (OSError, ValueError) as error:
        fail(f"{label} resolves outside the evidence root: {error}")
    current = path
    while current != root:
        if current.is_symlink():
            fail(f"{label} traverses a symbolic link")
        current = current.parent
    metadata = path.stat()
    if not path.is_file() or path.is_symlink() or metadata.st_size != size:
        fail(f"{label} is absent, unsafe, or has the wrong size")
    payload = path.read_bytes()
    if sha256_bytes(payload) != reference["sha256"]:
        fail(f"{label} digest differs")
    return reference, payload


def validate_host(value: Any, label: str) -> dict[str, Any]:
    host = exact_object(
        value,
        {
            "endpoint_id_sha256",
            "executable",
            "hostname",
            "isa",
            "kernel_release",
            "operating_system",
            "os_release",
            "schema",
        },
        label,
    )
    if host["schema"] != HOST_SCHEMA:
        fail(f"{label} schema differs")
    digest(host["endpoint_id_sha256"], f"{label}.endpoint_id_sha256")
    identity(host["executable"], f"{label}.executable", positive=True)
    for field in ("hostname", "kernel_release", "os_release"):
        string(host[field], f"{label}.{field}")
    if host["operating_system"] != "Linux" or host["isa"] not in {"x86_64", "amd64"}:
        fail(f"{label} is not a native x86-64 Linux endpoint")
    return host


def validate_status(value: Any, label: str, *, mode: str, epoch: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    if value.get("mode") != mode or value.get("authority_epoch") != epoch:
        fail(f"{label} mode or authority epoch differs")
    for field in ("completed_requests", "bytes_read", "bytes_written"):
        integer(value.get(field), f"{label}.{field}")
    return value


def validate_timing(value: Any) -> None:
    timing = exact_object(value, {"clock", "phases", "schema"}, "timing")
    if timing["schema"] != TIMING_SCHEMA or timing["clock"] != "python-time.monotonic_ns-controller":
        fail("timing schema or clock differs")
    expected = [
        "source-checkpoint",
        "source-freeze-export",
        "transfer-and-destination-prepare",
        "source-fence",
        "destination-activate-and-resume",
        "output-fetch-and-external-oracle",
    ]
    phases = timing["phases"]
    if not isinstance(phases, list) or len(phases) != len(expected):
        fail("timing phase inventory differs")
    previous_end = -1
    for name, value in zip(expected, phases, strict=True):
        phase = exact_object(
            value,
            {"duration_ns", "end_monotonic_ns", "phase", "start_monotonic_ns"},
            f"timing phase {name}",
        )
        if phase["phase"] != name:
            fail("timing phase order differs")
        start = integer(phase["start_monotonic_ns"], f"{name}.start")
        end = integer(phase["end_monotonic_ns"], f"{name}.end", positive=True)
        duration = integer(phase["duration_ns"], f"{name}.duration", positive=True)
        if end <= start or duration != end - start or start < previous_end:
            fail(f"timing phase {name} bounds are invalid")
        previous_end = end


def write_canonical_input(path: Path, size: int = CANONICAL_INPUT_BYTES) -> None:
    with path.open("xb") as stream:
        remaining = size
        index = 0
        while remaining:
            block = hashlib.sha256(
                CANONICAL_INPUT_SEED + index.to_bytes(8, "little")
            ).digest()
            output = block[:remaining]
            stream.write(output)
            remaining -= len(output)
            index += 1


def validate_document(
    document: Any,
    root: Path,
    *,
    expected_revision: str,
    stock_zstd: Path,
) -> dict[str, Any]:
    receipt = exact_object(document, TOP_LEVEL_KEYS, "receipt")
    if receipt["schema"] != SCHEMA:
        fail("receipt schema differs")
    if receipt["repository_revision"] != expected_revision or REVISION_RE.fullmatch(expected_revision) is None:
        fail("receipt repository revision differs")
    snapshot = exact_object(
        receipt["repository_source_snapshot"],
        {
            "clean",
            "status_sha256",
            "tracked_patch_sha256",
            "untracked_file_count",
            "untracked_manifest_sha256",
        },
        "repository_source_snapshot",
    )
    boolean(snapshot["clean"], True, "repository source snapshot clean")
    for field in ("status_sha256", "tracked_patch_sha256", "untracked_manifest_sha256"):
        digest(snapshot[field], f"repository_source_snapshot.{field}")
    integer(snapshot["untracked_file_count"], "repository_source_snapshot.untracked_file_count")

    case = exact_object(
        receipt["case"],
        {"cut_location_source", "cut_write_occurrence", "workload"},
        "case",
    )
    if case != {
        "workload": "stock-zstd-1.5.7-streaming-compression",
        "cut_location_source": "prearmed-post-hostcall-predicate",
        "cut_write_occurrence": CUT_WRITE_OCCURRENCE,
    }:
        fail("cross-host case identity differs")
    input_identity = identity(receipt["input"], "input", positive=True)
    if input_identity["size"] != CANONICAL_INPUT_BYTES:
        fail("canonical input size differs")

    build = exact_object(
        receipt["build"],
        {
            "application_aot",
            "stock_zstd_build_receipt_sha256",
            "wanco_build_receipt_sha256",
            "wanco_optimization",
        },
        "build",
    )
    identity(build["application_aot"], "build.application_aot", positive=True)
    digest(build["stock_zstd_build_receipt_sha256"], "stock-zstd build receipt")
    digest(build["wanco_build_receipt_sha256"], "Wanco build receipt")
    if build["wanco_optimization"] != "-O1":
        fail("cross-host Wanco optimization differs")

    topology = exact_object(
        receipt["topology"],
        {
            "destination_compute",
            "destination_provider",
            "provider_capsule_transferred",
            "source_compute",
            "source_provider",
            "ssh_host_key_sha256",
            "ssh_known_hosts_sha256",
            "transport",
        },
        "topology",
    )
    expected_topology = {
        "source_compute": "local-native-x86_64-wanco-aot",
        "source_provider": "local-process",
        "destination_compute": "remote-native-x86_64-wanco-aot",
        "destination_provider": "remote-fresh-process-restored-from-capsule",
        "provider_capsule_transferred": True,
        "transport": "openssh-content-addressed-files-plus-command-stdio",
    }
    observed_topology = dict(topology)
    host_key = observed_topology.pop("ssh_host_key_sha256", None)
    known_hosts_sha256 = observed_topology.pop("ssh_known_hosts_sha256", None)
    if observed_topology != expected_topology:
        fail("cross-host topology differs")
    if not isinstance(host_key, str) or HOST_KEY_FINGERPRINT_RE.fullmatch(host_key) is None:
        fail("SSH host-key fingerprint differs")
    digest(known_hosts_sha256, "SSH known-hosts digest")

    source = exact_object(
        receipt["source"],
        {"endpoint", "fenced_status", "frozen_status", "post_checkpoint_status"},
        "source",
    )
    source_host = validate_host(source["endpoint"], "source.endpoint")
    validate_status(source["post_checkpoint_status"], "source.post_checkpoint", mode="active", epoch=1)
    validate_status(source["frozen_status"], "source.frozen", mode="frozen", epoch=1)
    validate_status(source["fenced_status"], "source.fenced", mode="fenced", epoch=1)

    artifacts = exact_object(receipt["artifacts"], ARTIFACT_KEYS, "artifacts")
    _, remote_host_payload = read_reference(
        root, artifacts["remote_endpoint_observation"], "remote endpoint observation", max_bytes=MAX_JSON_BYTES
    )
    remote_host_raw = validate_host(parse_canonical_json(remote_host_payload, "remote endpoint observation"), "raw remote endpoint")
    known_hosts_ref, known_hosts_payload = read_reference(
        root, artifacts["ssh_known_hosts"], "SSH known-hosts", max_bytes=64 * 1024
    )
    if known_hosts_ref["sha256"] != known_hosts_sha256:
        fail("SSH known-hosts receipt digest differs")
    with tempfile.TemporaryDirectory(prefix="visa-zstd-host-key-") as value:
        known_hosts_path = Path(value) / "known_hosts"
        known_hosts_path.write_bytes(known_hosts_payload)
        key = subprocess.run(
            ["ssh-keygen", "-lf", known_hosts_path, "-E", "sha256"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        fields = key.stdout.decode("utf-8", errors="replace").split()
        if key.returncode != 0 or len(fields) < 2 or fields[1] != host_key:
            fail("raw SSH known-hosts key differs from its recorded fingerprint")
    destination = exact_object(
        receipt["destination"],
        {"active_status", "endpoint", "final_status", "prepared_status", "process"},
        "destination",
    )
    destination_host = validate_host(destination["endpoint"], "destination.endpoint")
    if destination_host != remote_host_raw:
        fail("destination endpoint differs from its raw observation")
    if source_host["endpoint_id_sha256"] == destination_host["endpoint_id_sha256"]:
        fail("source and destination endpoint identities are not distinct")
    prepared = validate_status(destination["prepared_status"], "destination.prepared", mode="prepared", epoch=1)
    active = validate_status(destination["active_status"], "destination.active", mode="active", epoch=2)
    final = validate_status(destination["final_status"], "destination.final", mode="active", epoch=2)
    if final["completed_requests"] <= active["completed_requests"]:
        fail("destination made no observable provider progress after activation")

    process = exact_object(destination["process"], {"exit_status", "stderr", "stdout"}, "destination.process")
    if process["exit_status"] != 0:
        fail("destination process did not exit cleanly")
    stdout_identity = identity(process["stdout"], "destination.process.stdout")
    stderr_identity = identity(process["stderr"], "destination.process.stderr")
    _, stdout_payload = read_reference(root, artifacts["destination_process_stdout"], "destination stdout", max_bytes=MAX_JSON_BYTES)
    _, stderr_payload = read_reference(root, artifacts["destination_process_stderr"], "destination stderr", max_bytes=MAX_JSON_BYTES)
    if file_like_identity(stdout_payload) != stdout_identity or file_like_identity(stderr_payload) != stderr_identity:
        fail("destination process stream identity differs")

    _, remote_payload = read_reference(
        root, artifacts["remote_observation"], "remote observation", max_bytes=MAX_JSON_BYTES
    )
    remote = exact_object(
        parse_canonical_json(remote_payload, "remote observation"),
        {"active_status", "endpoint", "final_status", "materialized_output", "prepared_status", "process", "schema"},
        "raw remote observation",
    )
    if remote["schema"] != REMOTE_SCHEMA:
        fail("remote observation schema differs")
    if remote["endpoint"] != destination_host or remote["prepared_status"] != prepared or remote["active_status"] != active or remote["final_status"] != final or remote["process"] != process:
        fail("destination summary differs from raw remote observation")
    remote_output = identity(remote["materialized_output"], "remote materialized output", positive=True)

    transfer = receipt["transfer_objects"]
    if not isinstance(transfer, list) or len(transfer) < 8:
        fail("transfer object inventory is incomplete")
    labels: set[str] = set()
    required = {"application-aot", "checkpoint", "capsule-manifest", "capsule-state", "provider-binary", "proof-binder", "remote-helper", "runtime-loader"}
    for index, value in enumerate(transfer):
        item = exact_object(value, {"identity", "label", "path"}, f"transfer object {index}")
        label = string(item["label"], f"transfer object {index}.label")
        if label in labels:
            fail("transfer object labels are not unique")
        labels.add(label)
        relative_path(item["path"], f"transfer object {index}.path")
        identity(item["identity"], f"transfer object {index}.identity", positive=True)
    if not required.issubset(labels) or not any(label.startswith("runtime-library:") for label in labels):
        fail("transfer object required set differs")
    _, transfer_payload = read_reference(
        root, artifacts["transfer_manifest"], "transfer manifest", max_bytes=MAX_JSON_BYTES
    )
    raw_transfer = exact_object(
        parse_canonical_json(transfer_payload, "transfer manifest"),
        {"objects", "schema"},
        "raw transfer manifest",
    )
    if raw_transfer["schema"] != "visa-stock-zstd-cross-host-transfer-v1" or raw_transfer["objects"] != transfer:
        fail("receipt transfer inventory differs from its raw manifest")

    authority = exact_object(
        receipt["authority_boundary"],
        {"cryptographic_host_attestation", "distributed_fencing", "source_fenced_before_destination_activation", "trusted_coordinator"},
        "authority_boundary",
    )
    boolean(authority["trusted_coordinator"], True, "trusted coordinator")
    boolean(authority["source_fenced_before_destination_activation"], True, "source fence ordering")
    boolean(authority["distributed_fencing"], False, "distributed fencing")
    boolean(authority["cryptographic_host_attestation"], False, "host attestation")

    _, timing_payload = read_reference(root, artifacts["application_timing"], "application timing", max_bytes=MAX_JSON_BYTES)
    raw_timing = parse_canonical_json(timing_payload, "application timing")
    if receipt["timing"] != raw_timing:
        fail("receipt timing differs from raw application timing")
    validate_timing(raw_timing)

    _, compressed = read_reference(
        root, artifacts["shared_compressed_output"], "shared compressed output", max_bytes=MAX_COMPRESSED_BYTES
    )
    compressed_identity = file_like_identity(compressed)
    control = exact_object(receipt["control"], {"compressed_output", "process"}, "control")
    if identity(control["compressed_output"], "control.compressed_output", positive=True) != compressed_identity:
        fail("uninterrupted control compressed identity differs")
    control_process = exact_object(
        control["process"], {"exit_status", "stderr", "stdout"}, "control.process"
    )
    if control_process["exit_status"] != 0:
        fail("uninterrupted control process did not exit cleanly")
    _, control_stdout = read_reference(
        root, artifacts["control_process_stdout"], "control stdout", max_bytes=MAX_JSON_BYTES
    )
    _, control_stderr = read_reference(
        root, artifacts["control_process_stderr"], "control stderr", max_bytes=MAX_JSON_BYTES
    )
    if identity(control_process["stdout"], "control.process.stdout") != file_like_identity(control_stdout) or identity(control_process["stderr"], "control.process.stderr") != file_like_identity(control_stderr):
        fail("uninterrupted control process stream identity differs")
    _, control_report_payload = read_reference(
        root, artifacts["control_oracle_report"], "control oracle report", max_bytes=MAX_JSON_BYTES
    )
    control_report = parse_canonical_json(control_report_payload, "control oracle report")
    if not isinstance(control_report, dict) or control_report.get("schema") != "visa-stock-zstd-external-oracle-report-v1":
        fail("uninterrupted control oracle report schema differs")
    if identity(control_report.get("input"), "control oracle input", positive=True) != input_identity or identity(control_report.get("decoded"), "control oracle decoded", positive=True) != input_identity or identity(control_report.get("compressed"), "control oracle compressed", positive=True) != compressed_identity:
        fail("uninterrupted control oracle raw identities differ")
    _, control_timing_payload = read_reference(
        root, artifacts["control_application_timing"], "control application timing", max_bytes=MAX_JSON_BYTES
    )
    control_timing = parse_canonical_json(control_timing_payload, "control application timing")
    if not isinstance(control_timing, dict) or control_timing.get("schema") != "visa-application-timing-v1" or not isinstance(control_timing.get("phases"), list) or not control_timing["phases"]:
        fail("uninterrupted control application timing differs")
    oracle = exact_object(
        receipt["oracle"],
        {"compressed", "decoded", "input", "kind", "producer_verdict_used"},
        "oracle",
    )
    if oracle["kind"] != "native-zstd-raw-decompression-and-control-byte-identity":
        fail("oracle kind differs")
    boolean(oracle["producer_verdict_used"], False, "oracle producer verdict usage")
    if identity(oracle["compressed"], "oracle.compressed", positive=True) != compressed_identity or remote_output != compressed_identity:
        fail("remote, retained, and oracle compressed identities differ")
    if identity(oracle["input"], "oracle.input", positive=True) != input_identity or identity(oracle["decoded"], "oracle.decoded", positive=True) != input_identity:
        fail("oracle input or decoded identity differs")

    if receipt["explicit_non_claims"] != NON_CLAIMS:
        fail("explicit non-claim inventory differs")

    stock_zstd = stock_zstd.resolve()
    if not stock_zstd.is_file() or not os.access(stock_zstd, os.X_OK):
        fail("selected native zstd oracle is unavailable")
    with tempfile.TemporaryDirectory(prefix="visa-zstd-cross-host-oracle-") as value:
        temporary = Path(value)
        compressed_path = temporary / "output.zst"
        decoded_path = temporary / "decoded.bin"
        input_path = temporary / "input.bin"
        compressed_path.write_bytes(compressed)
        write_canonical_input(input_path)
        completed = subprocess.run(
            [stock_zstd, "-q", "-d", "-f", compressed_path, "-o", decoded_path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        if completed.returncode != 0:
            fail("native zstd rejected the retained compressed output")
        actual_input = file_identity(input_path)
        actual_decoded = file_identity(decoded_path)
        if actual_input != input_identity or actual_decoded != input_identity:
            fail("native zstd raw decompression differs from the canonical input")
    return receipt


def file_like_identity(payload: bytes) -> dict[str, object]:
    return {"sha256": sha256_bytes(payload), "size": len(payload)}


def validate_receipt(
    receipt_path: Path,
    *,
    expected_revision: str,
    stock_zstd: Path,
) -> dict[str, Any]:
    receipt_path = receipt_path.resolve()
    if not receipt_path.is_file() or receipt_path.is_symlink() or receipt_path.stat().st_size > MAX_RECEIPT_BYTES:
        fail("receipt is absent, unsafe, or too large")
    document = parse_canonical_json(receipt_path.read_bytes(), "receipt")
    return validate_document(
        document,
        receipt_path.parent,
        expected_revision=expected_revision,
        stock_zstd=stock_zstd,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("receipt", type=Path)
    validate.add_argument("--expected-revision", required=True)
    validate.add_argument("--stock-zstd", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if arguments.command != "validate":
        fail("unsupported command")
    receipt = validate_receipt(
        arguments.receipt,
        expected_revision=arguments.expected_revision,
        stock_zstd=arguments.stock_zstd,
    )
    print(
        "stock-zstd cross-host clean handoff valid: "
        f"revision={receipt['repository_revision']} cut={CUT_WRITE_OCCURRENCE}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError, subprocess.TimeoutExpired) as error:
        print(f"stock-zstd cross-host evidence invalid: {error}", file=os.sys.stderr)
        raise SystemExit(1)
