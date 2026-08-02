#!/usr/bin/env python3
"""Create a public, endpoint-redacted derivative of one private S3Z-H receipt.

The private receipt remains the execution authority.  This tool intentionally
does not rerun the workload: it derives a separately named public receipt that
preserves the output/oracle, status, and transfer commitments while withholding
operational endpoint identifiers and the SSH host-key witness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import stock_zstd_cross_host as private

PRIVATE_SCHEMA = private.SCHEMA
PUBLIC_SCHEMA = "visa-stock-zstd-cross-host-clean-handoff-v2"
PUBLIC_HOST_SCHEMA = "visa-cross-host-endpoint-observation-v2"
PUBLIC_REMOTE_SCHEMA = "visa-stock-zstd-cross-host-remote-observation-v2"
RETAINED_ARTIFACTS = (
    "application-timing.json",
    "control-application-timing.json",
    "control-oracle-report.json",
    "control.stderr",
    "control.stdout",
    "destination.stderr",
    "destination.stdout",
    "migrated-output.zst",
    "transfer-manifest.json",
)
PUBLIC_ARTIFACT_KEYS = {
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
    "transfer_manifest",
}
PUBLIC_ARTIFACT_PATHS = {
    "application_timing": "raw/application-timing.json",
    "control_application_timing": "raw/control-application-timing.json",
    "control_oracle_report": "raw/control-oracle-report.json",
    "control_process_stderr": "raw/control.stderr",
    "control_process_stdout": "raw/control.stdout",
    "destination_process_stderr": "raw/destination.stderr",
    "destination_process_stdout": "raw/destination.stdout",
    "remote_endpoint_observation": "raw/remote-endpoint.json",
    "remote_observation": "raw/remote-observation.json",
    "shared_compressed_output": "raw/migrated-output.zst",
    "transfer_manifest": "raw/transfer-manifest.json",
}
PUBLIC_TOPOLOGY = {
    "source_compute": "local-native-x86_64-wanco-aot",
    "source_provider": "local-process",
    "destination_compute": "remote-native-x86_64-wanco-aot",
    "destination_provider": "remote-fresh-process-restored-from-capsule",
    "provider_capsule_transferred": True,
    "transport": "openssh-content-addressed-files-plus-command-stdio",
    "operational_endpoint_witness": "withheld-private-receipt",
}
PUBLIC_TREE = {"receipt.json", *PUBLIC_ARTIFACT_PATHS.values()}
PUBLIC_TOP_LEVEL_KEYS = {
    "artifacts",
    "authority_boundary",
    "build",
    "case",
    "control",
    "destination",
    "explicit_non_claims",
    "input",
    "oracle",
    "private_execution_receipt",
    "public_redaction",
    "repository_revision",
    "repository_source_snapshot",
    "schema",
    "source",
    "timing",
    "topology",
    "transfer_objects",
}
FORBIDDEN_PUBLIC_KEYS = {
    "endpoint_id_sha256",
    "hostname",
    "kernel_release",
    "os_release",
    "ssh_host_key_sha256",
    "ssh_known_hosts",
    "ssh_known_hosts_sha256",
}
WITHHELD_FIELDS = [
    "source endpoint hostname and endpoint identifier",
    "destination endpoint hostname and endpoint identifier",
    "SSH DNS name, port, known-hosts line, and host-key fingerprint",
]


class RedactionError(RuntimeError):
    pass


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def identity(path: Path) -> dict[str, object]:
    return {"sha256": sha256_file(path), "size": path.stat().st_size}


def write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_bytes(value) + b"\n")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RedactionError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise RedactionError(f"{path} is not a JSON object")
    return value


def public_endpoint(
    private_endpoint: dict[str, Any], role: str, private_receipt_sha256: str
) -> dict[str, Any]:
    private.validate_host(private_endpoint, f"private {role} endpoint")
    executable = private_endpoint.get("executable")
    if not isinstance(executable, dict):
        raise RedactionError(f"{role} endpoint has no executable identity")
    endpoint_id = private_endpoint["endpoint_id_sha256"]
    opaque_id = hashlib.sha256(
        b"visa-stock-zstd-cross-host-public-endpoint-v2\0"
        + private_receipt_sha256.encode("ascii")
        + b"\0"
        + role.encode("ascii")
        + b"\0"
        + endpoint_id.encode("ascii")
    ).hexdigest()
    return {
        "schema": PUBLIC_HOST_SCHEMA,
        "role": role,
        "run_scoped_endpoint_id_sha256": opaque_id,
        "isa": "x86_64",
        "operating_system": "Linux",
        "executable": executable,
    }


def artifact_ref(path: Path, root: Path) -> dict[str, object]:
    return {"path": path.relative_to(root).as_posix(), **identity(path)}


def require_equal(left: object, right: object, label: str) -> None:
    if left != right:
        raise RedactionError(f"private evidence mismatch: {label}")


def forbid_public_keys(value: object, label: str = "receipt") -> None:
    """Reject endpoint or SSH metadata anywhere in a public JSON document."""

    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_PUBLIC_KEYS:
                raise RedactionError(f"{label} contains forbidden public field {key!r}")
            forbid_public_keys(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            forbid_public_keys(item, f"{label}[{index}]")


def private_sensitive_literals(receipt: dict[str, Any], root: Path) -> set[bytes]:
    """Return strings which must not survive the public projection.

    This is a generation-time guard, not an assertion that the public receipt
    cryptographically proves endpoint provenance.  The private v1 validator
    establishes the execution record before this projection begins.
    """

    values: set[str] = set()
    for side in ("source", "destination"):
        endpoint = receipt[side]["endpoint"]
        for field in (
            "endpoint_id_sha256",
            "hostname",
            "kernel_release",
            "os_release",
        ):
            value = endpoint.get(field)
            if isinstance(value, str) and value:
                values.add(value)
    topology = receipt["topology"]
    for field in ("ssh_host_key_sha256", "ssh_known_hosts_sha256"):
        value = topology.get(field)
        if isinstance(value, str) and value:
            values.add(value)
    known_hosts = root / "raw" / "known_hosts"
    if known_hosts.is_file() and not known_hosts.is_symlink():
        payload = known_hosts.read_bytes()
        if payload:
            values.add(payload.decode("utf-8", errors="ignore"))
    return {value.encode("utf-8") for value in values if len(value.encode("utf-8")) >= 8}


def assert_public_literals_redacted(root: Path, forbidden_literals: set[bytes]) -> None:
    for relative in PUBLIC_TREE:
        path = root / relative
        payload = path.read_bytes()
        for literal in forbidden_literals:
            if literal in payload:
                raise RedactionError(
                    f"public projection retains a private endpoint or SSH literal in {relative}"
                )


def validate_public_tree(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise RedactionError("public evidence root is absent or unsafe")
    top_level = {path.name for path in root.iterdir()}
    if top_level != {"raw", "receipt.json"}:
        raise RedactionError("public evidence root is not an allowlisted tree")
    raw = root / "raw"
    if not raw.is_dir() or raw.is_symlink():
        raise RedactionError("public raw directory is absent or unsafe")
    observed_files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RedactionError("public evidence tree contains a symbolic link")
        relative = path.relative_to(root).as_posix()
        if path.is_file():
            observed_files.add(relative)
        elif path.is_dir() and relative != "raw":
            raise RedactionError("public evidence tree contains an unexpected directory")
        elif not path.is_dir():
            raise RedactionError("public evidence tree contains a non-regular entry")
    if observed_files != PUBLIC_TREE:
        raise RedactionError("public evidence tree files differ from its allowlist")


def parse_public_json_artifacts(payloads: dict[str, bytes]) -> dict[str, Any]:
    """Parse and redact-check every JSON object admitted by the public tree.

    Several raw files have intentionally narrow semantic consumers below.  A
    generic forbidden-field pass must happen before those consumers so that a
    newly admitted or weakly structured JSON artifact cannot become an endpoint
    metadata side channel.
    """

    documents: dict[str, Any] = {}
    for key, path in PUBLIC_ARTIFACT_PATHS.items():
        if Path(path).suffix != ".json":
            continue
        label = f"public artifact {key}"
        document = private.parse_canonical_json(payloads[key], label)
        forbid_public_keys(document, label)
        documents[key] = document
    return documents


def validate_public_endpoint(value: Any, label: str, role: str) -> dict[str, Any]:
    endpoint = private.exact_object(
        value,
        {
            "executable",
            "isa",
            "operating_system",
            "role",
            "run_scoped_endpoint_id_sha256",
            "schema",
        },
        label,
    )
    if endpoint["schema"] != PUBLIC_HOST_SCHEMA:
        raise RedactionError(f"{label} schema differs")
    if endpoint["role"] != role:
        raise RedactionError(f"{label} role differs")
    private.digest(
        endpoint["run_scoped_endpoint_id_sha256"],
        f"{label}.run_scoped_endpoint_id_sha256",
    )
    private.identity(endpoint["executable"], f"{label}.executable", positive=True)
    if endpoint["operating_system"] != "Linux" or endpoint["isa"] != "x86_64":
        raise RedactionError(f"{label} is not a native x86-64 Linux endpoint")
    return endpoint


def read_public_artifacts(
    root: Path, artifacts: dict[str, Any]
) -> dict[str, bytes]:
    if set(artifacts) != PUBLIC_ARTIFACT_KEYS:
        raise RedactionError("public artifact inventory differs")
    payloads: dict[str, bytes] = {}
    seen_paths: set[str] = set()
    for key, expected_path in PUBLIC_ARTIFACT_PATHS.items():
        reference, payload = private.read_reference(
            root,
            artifacts[key],
            f"public artifact {key}",
            max_bytes=(
                private.MAX_COMPRESSED_BYTES
                if key == "shared_compressed_output"
                else private.MAX_JSON_BYTES
            ),
        )
        if reference["path"] != expected_path:
            raise RedactionError(f"public artifact {key} has an unexpected path")
        if reference["path"] in seen_paths:
            raise RedactionError("public artifact paths are not unique")
        seen_paths.add(reference["path"])
        payloads[key] = payload
    return payloads


def validate_public_receipt(
    receipt_path: Path,
    *,
    expected_revision: str,
    stock_zstd: Path,
) -> dict[str, Any]:
    """Validate the public v2 projection without requiring private endpoint data."""

    try:
        supplied_receipt_path = receipt_path
        if supplied_receipt_path.is_symlink():
            raise RedactionError("public receipt path is a symbolic link")
        supplied_root = supplied_receipt_path.parent
        if supplied_root.is_symlink():
            raise RedactionError("public evidence root path is a symbolic link")
        receipt_path = supplied_receipt_path.resolve()
        if (
            not receipt_path.is_file()
            or receipt_path.is_symlink()
            or receipt_path.stat().st_size > private.MAX_RECEIPT_BYTES
        ):
            raise RedactionError("public receipt is absent, unsafe, or too large")
        root = receipt_path.parent
        validate_public_tree(root)
        document = private.parse_canonical_json(receipt_path.read_bytes(), "public receipt")
        receipt = private.exact_object(document, PUBLIC_TOP_LEVEL_KEYS, "public receipt")
        forbid_public_keys(receipt, "public receipt")
        if receipt["schema"] != PUBLIC_SCHEMA:
            raise RedactionError("public receipt schema differs")
        if (
            not isinstance(expected_revision, str)
            or private.REVISION_RE.fullmatch(expected_revision) is None
            or receipt["repository_revision"] != expected_revision
        ):
            raise RedactionError("public receipt repository revision differs")

        private_receipt = private.exact_object(
            receipt["private_execution_receipt"],
            {"retention", "schema", "sha256"},
            "private execution receipt",
        )
        if private_receipt["schema"] != PRIVATE_SCHEMA:
            raise RedactionError("private execution receipt schema differs")
        private.digest(private_receipt["sha256"], "private execution receipt digest")
        if private_receipt["retention"] != "private-operational-witness":
            raise RedactionError("private execution receipt retention differs")

        snapshot = private.exact_object(
            receipt["repository_source_snapshot"],
            {
                "clean",
                "status_sha256",
                "tracked_patch_sha256",
                "untracked_file_count",
                "untracked_manifest_sha256",
            },
            "public repository source snapshot",
        )
        private.boolean(snapshot["clean"], True, "public repository source snapshot clean")
        for field in (
            "status_sha256",
            "tracked_patch_sha256",
            "untracked_manifest_sha256",
        ):
            private.digest(snapshot[field], f"public repository source snapshot.{field}")
        private.integer(
            snapshot["untracked_file_count"],
            "public repository source snapshot.untracked_file_count",
        )

        case = private.exact_object(
            receipt["case"],
            {"cut_location_source", "cut_write_occurrence", "workload"},
            "public case",
        )
        if case != {
            "workload": "stock-zstd-1.5.7-streaming-compression",
            "cut_location_source": "prearmed-post-hostcall-predicate",
            "cut_write_occurrence": private.CUT_WRITE_OCCURRENCE,
        }:
            raise RedactionError("public cross-host case identity differs")
        input_identity = private.identity(receipt["input"], "public input", positive=True)
        if input_identity["size"] != private.CANONICAL_INPUT_BYTES:
            raise RedactionError("public canonical input size differs")

        build = private.exact_object(
            receipt["build"],
            {
                "application_aot",
                "stock_zstd_build_receipt_sha256",
                "wanco_build_receipt_sha256",
                "wanco_optimization",
            },
            "public build",
        )
        private.identity(build["application_aot"], "public build.application_aot", positive=True)
        private.digest(build["stock_zstd_build_receipt_sha256"], "public zstd build receipt")
        private.digest(build["wanco_build_receipt_sha256"], "public Wanco build receipt")
        if build["wanco_optimization"] != "-O1":
            raise RedactionError("public Wanco optimization differs")

        if receipt["topology"] != PUBLIC_TOPOLOGY:
            raise RedactionError("public topology differs")
        source = private.exact_object(
            receipt["source"],
            {"endpoint", "fenced_status", "frozen_status", "post_checkpoint_status"},
            "public source",
        )
        source_endpoint = validate_public_endpoint(source["endpoint"], "public source endpoint", "source")
        private.validate_status(
            source["post_checkpoint_status"],
            "public source post-checkpoint",
            mode="active",
            epoch=1,
        )
        private.validate_status(
            source["frozen_status"], "public source frozen", mode="frozen", epoch=1
        )
        private.validate_status(
            source["fenced_status"], "public source fenced", mode="fenced", epoch=1
        )

        destination = private.exact_object(
            receipt["destination"],
            {"active_status", "endpoint", "final_status", "prepared_status", "process"},
            "public destination",
        )
        destination_endpoint = validate_public_endpoint(
            destination["endpoint"], "public destination endpoint", "destination"
        )
        if (
            source_endpoint["run_scoped_endpoint_id_sha256"]
            == destination_endpoint["run_scoped_endpoint_id_sha256"]
        ):
            raise RedactionError("public source and destination endpoints are not distinct")
        prepared = private.validate_status(
            destination["prepared_status"], "public destination prepared", mode="prepared", epoch=1
        )
        active = private.validate_status(
            destination["active_status"], "public destination active", mode="active", epoch=2
        )
        final = private.validate_status(
            destination["final_status"], "public destination final", mode="active", epoch=2
        )
        if final["completed_requests"] <= active["completed_requests"]:
            raise RedactionError("public destination made no progress after activation")
        process = private.exact_object(
            destination["process"], {"exit_status", "stderr", "stdout"}, "public destination process"
        )
        if process["exit_status"] != 0:
            raise RedactionError("public destination process did not exit cleanly")
        stdout_identity = private.identity(
            process["stdout"], "public destination process stdout"
        )
        stderr_identity = private.identity(
            process["stderr"], "public destination process stderr"
        )

        artifacts = private.exact_object(receipt["artifacts"], PUBLIC_ARTIFACT_KEYS, "public artifacts")
        payloads = read_public_artifacts(root, artifacts)
        json_artifacts = parse_public_json_artifacts(payloads)
        raw_endpoint = validate_public_endpoint(
            json_artifacts["remote_endpoint_observation"],
            "public raw remote endpoint",
            "destination",
        )
        if raw_endpoint != destination_endpoint:
            raise RedactionError("public destination endpoint differs from raw endpoint observation")
        remote = private.exact_object(
            json_artifacts["remote_observation"],
            {
                "active_status",
                "endpoint",
                "final_status",
                "materialized_output",
                "prepared_status",
                "process",
                "schema",
            },
            "public raw remote observation",
        )
        if remote["schema"] != PUBLIC_REMOTE_SCHEMA:
            raise RedactionError("public remote observation schema differs")
        if (
            remote["endpoint"] != destination_endpoint
            or remote["prepared_status"] != prepared
            or remote["active_status"] != active
            or remote["final_status"] != final
            or remote["process"] != process
        ):
            raise RedactionError("public destination summary differs from raw remote observation")
        remote_output = private.identity(
            remote["materialized_output"], "public remote materialized output", positive=True
        )
        if private.file_like_identity(payloads["destination_process_stdout"]) != stdout_identity:
            raise RedactionError("public destination stdout identity differs")
        if private.file_like_identity(payloads["destination_process_stderr"]) != stderr_identity:
            raise RedactionError("public destination stderr identity differs")

        transfer = receipt["transfer_objects"]
        if not isinstance(transfer, list) or len(transfer) != 26:
            raise RedactionError("public transfer object inventory is not the 26-object handoff")
        labels: set[str] = set()
        required_labels = {
            "application-aot",
            "checkpoint",
            "capsule-manifest",
            "capsule-state",
            "provider-binary",
            "proof-binder",
            "remote-helper",
            "runtime-loader",
        }
        for index, item in enumerate(transfer):
            item = private.exact_object(item, {"identity", "label", "path"}, f"public transfer object {index}")
            label = private.string(item["label"], f"public transfer object {index}.label")
            if label in labels:
                raise RedactionError("public transfer object labels are not unique")
            labels.add(label)
            private.relative_path(item["path"], f"public transfer object {index}.path")
            private.identity(item["identity"], f"public transfer object {index}.identity", positive=True)
        if not required_labels.issubset(labels) or not any(
            label.startswith("runtime-library:") for label in labels
        ):
            raise RedactionError("public transfer object required set differs")
        raw_transfer = private.exact_object(
            json_artifacts["transfer_manifest"],
            {"objects", "schema"},
            "public raw transfer manifest",
        )
        if (
            raw_transfer["schema"] != "visa-stock-zstd-cross-host-transfer-v1"
            or raw_transfer["objects"] != transfer
        ):
            raise RedactionError("public transfer inventory differs from its raw manifest")

        authority = private.exact_object(
            receipt["authority_boundary"],
            {
                "cryptographic_host_attestation",
                "distributed_fencing",
                "source_fenced_before_destination_activation",
                "trusted_coordinator",
            },
            "public authority boundary",
        )
        private.boolean(authority["trusted_coordinator"], True, "public trusted coordinator")
        private.boolean(
            authority["source_fenced_before_destination_activation"],
            True,
            "public source fence ordering",
        )
        private.boolean(authority["distributed_fencing"], False, "public distributed fencing")
        private.boolean(
            authority["cryptographic_host_attestation"], False, "public host attestation"
        )

        timing = json_artifacts["application_timing"]
        if receipt["timing"] != timing:
            raise RedactionError("public receipt timing differs from raw application timing")
        private.validate_timing(timing)

        compressed = payloads["shared_compressed_output"]
        compressed_identity = private.file_like_identity(compressed)
        control = private.exact_object(
            receipt["control"], {"compressed_output", "process"}, "public control"
        )
        if (
            private.identity(control["compressed_output"], "public control compressed output", positive=True)
            != compressed_identity
        ):
            raise RedactionError("public uninterrupted control compressed identity differs")
        control_process = private.exact_object(
            control["process"], {"exit_status", "stderr", "stdout"}, "public control process"
        )
        if control_process["exit_status"] != 0:
            raise RedactionError("public uninterrupted control did not exit cleanly")
        if (
            private.identity(control_process["stdout"], "public control stdout")
            != private.file_like_identity(payloads["control_process_stdout"])
            or private.identity(control_process["stderr"], "public control stderr")
            != private.file_like_identity(payloads["control_process_stderr"])
        ):
            raise RedactionError("public uninterrupted control stream identity differs")
        control_report = json_artifacts["control_oracle_report"]
        if not isinstance(control_report, dict) or control_report.get("schema") != "visa-stock-zstd-external-oracle-report-v1":
            raise RedactionError("public uninterrupted control oracle report schema differs")
        if (
            private.identity(control_report.get("input"), "public control oracle input", positive=True)
            != input_identity
            or private.identity(control_report.get("decoded"), "public control oracle decoded", positive=True)
            != input_identity
            or private.identity(control_report.get("compressed"), "public control oracle compressed", positive=True)
            != compressed_identity
        ):
            raise RedactionError("public uninterrupted control oracle raw identities differ")
        control_timing = json_artifacts["control_application_timing"]
        if (
            not isinstance(control_timing, dict)
            or control_timing.get("schema") != "visa-application-timing-v1"
            or not isinstance(control_timing.get("phases"), list)
            or not control_timing["phases"]
        ):
            raise RedactionError("public uninterrupted control application timing differs")
        oracle = private.exact_object(
            receipt["oracle"], {"compressed", "decoded", "input", "kind", "producer_verdict_used"}, "public oracle"
        )
        if oracle["kind"] != "native-zstd-raw-decompression-and-control-byte-identity":
            raise RedactionError("public oracle kind differs")
        private.boolean(oracle["producer_verdict_used"], False, "public oracle producer verdict usage")
        if (
            private.identity(oracle["compressed"], "public oracle compressed", positive=True)
            != compressed_identity
            or remote_output != compressed_identity
            or private.identity(oracle["input"], "public oracle input", positive=True)
            != input_identity
            or private.identity(oracle["decoded"], "public oracle decoded", positive=True)
            != input_identity
        ):
            raise RedactionError("public oracle identities differ")

        if receipt["explicit_non_claims"] != private.NON_CLAIMS:
            raise RedactionError("public explicit non-claim inventory differs")
        redaction = private.exact_object(
            receipt["public_redaction"],
            {
                "endpoint_distinctness",
                "private_receipt_sha256",
                "transformation",
                "withheld_artifacts",
                "withheld_fields",
            },
            "public redaction",
        )
        if (
            redaction["endpoint_distinctness"]
            != "trusted-coordinator-private-observation"
            or redaction["withheld_fields"] != WITHHELD_FIELDS
            or redaction["withheld_artifacts"] != ["raw/known_hosts"]
            or redaction["transformation"]
            != "validated endpoint-redacted derivative without workload rerun"
            or redaction["private_receipt_sha256"] != private_receipt["sha256"]
        ):
            raise RedactionError("public redaction declaration differs")
        private.digest(redaction["private_receipt_sha256"], "public redaction private receipt digest")

        stock_zstd = stock_zstd.resolve()
        if not stock_zstd.is_file() or not os.access(stock_zstd, os.X_OK):
            raise RedactionError("selected native zstd oracle is unavailable")
        with tempfile.TemporaryDirectory(prefix="visa-zstd-cross-host-public-oracle-") as value:
            temporary = Path(value)
            compressed_path = temporary / "output.zst"
            decoded_path = temporary / "decoded.bin"
            input_path = temporary / "input.bin"
            compressed_path.write_bytes(compressed)
            private.write_canonical_input(input_path)
            completed = subprocess.run(
                [stock_zstd, "-q", "-d", "-f", compressed_path, "-o", decoded_path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
                check=False,
            )
            if completed.returncode != 0:
                raise RedactionError("native zstd rejected the public retained compressed output")
            if (
                private.file_identity(input_path) != input_identity
                or private.file_identity(decoded_path) != input_identity
            ):
                raise RedactionError("native zstd public decompression differs from canonical input")
        return receipt
    except private.EvidenceError as error:
        raise RedactionError(str(error)) from error


def make_public_receipt(
    private_root: Path,
    output: Path,
    *,
    expected_revision: str,
    stock_zstd: Path,
) -> dict[str, Any]:
    private_root = private_root.resolve()
    private_receipt_path = private_root / "receipt.json"
    try:
        private_receipt = private.validate_receipt(
            private_receipt_path,
            expected_revision=expected_revision,
            stock_zstd=stock_zstd,
        )
    except private.EvidenceError as error:
        raise RedactionError(f"private receipt does not validate: {error}") from error
    if private_receipt.get("schema") != PRIVATE_SCHEMA:
        raise RedactionError("private receipt schema differs")
    if output.exists():
        raise RedactionError(f"refusing to overwrite {output}")
    forbidden_literals = private_sensitive_literals(private_receipt, private_root)
    output.mkdir(mode=0o700, parents=True)
    try:
        raw = output / "raw"
        raw.mkdir(mode=0o700)

        for name in RETAINED_ARTIFACTS:
            source = private_root / "raw" / name
            if not source.is_file() or source.is_symlink():
                raise RedactionError(f"private raw artifact is absent or unsafe: {name}")
            shutil.copyfile(source, raw / name)

        private_source = private_receipt.get("source")
        private_destination = private_receipt.get("destination")
        private_topology = private_receipt.get("topology")
        if not isinstance(private_source, dict) or not isinstance(private_destination, dict):
            raise RedactionError("private receipt has invalid endpoint summaries")
        if not isinstance(private_topology, dict):
            raise RedactionError("private receipt has invalid topology summary")
        remote_private = read_json(private_root / "raw" / "remote-observation.json")
        require_equal(private_destination.get("endpoint"), remote_private.get("endpoint"), "destination endpoint")
        for field in ("prepared_status", "active_status", "final_status", "process"):
            require_equal(private_destination.get(field), remote_private.get(field), f"destination.{field}")
        source_private_id = private_source["endpoint"]["endpoint_id_sha256"]
        destination_private_id = private_destination["endpoint"]["endpoint_id_sha256"]
        if source_private_id == destination_private_id:
            raise RedactionError("private source and destination endpoint identities are not distinct")
        private_sha256 = sha256_file(private_receipt_path)
        source_endpoint = public_endpoint(private_source["endpoint"], "source", private_sha256)
        destination_endpoint = public_endpoint(private_destination["endpoint"], "destination", private_sha256)
        if (
            source_endpoint["run_scoped_endpoint_id_sha256"]
            == destination_endpoint["run_scoped_endpoint_id_sha256"]
        ):
            raise RedactionError("public endpoint identities are not distinct")
        remote_public = {
            "schema": PUBLIC_REMOTE_SCHEMA,
            "endpoint": destination_endpoint,
            "prepared_status": private_destination["prepared_status"],
            "active_status": private_destination["active_status"],
            "final_status": private_destination["final_status"],
            "process": private_destination["process"],
            "materialized_output": remote_private["materialized_output"],
        }
        write_json(raw / "remote-observation.json", remote_public)
        write_json(raw / "remote-endpoint.json", destination_endpoint)

        # The public derivative uses content identities and sequence facts, not
        # a connectable endpoint or host-key witness.
        artifacts = {
            "remote_endpoint_observation": artifact_ref(raw / "remote-endpoint.json", output),
            "remote_observation": artifact_ref(raw / "remote-observation.json", output),
            "destination_process_stdout": artifact_ref(raw / "destination.stdout", output),
            "destination_process_stderr": artifact_ref(raw / "destination.stderr", output),
            "shared_compressed_output": artifact_ref(raw / "migrated-output.zst", output),
            "application_timing": artifact_ref(raw / "application-timing.json", output),
            "transfer_manifest": artifact_ref(raw / "transfer-manifest.json", output),
            "control_process_stdout": artifact_ref(raw / "control.stdout", output),
            "control_process_stderr": artifact_ref(raw / "control.stderr", output),
            "control_oracle_report": artifact_ref(raw / "control-oracle-report.json", output),
            "control_application_timing": artifact_ref(raw / "control-application-timing.json", output),
        }
        topology = {
            key: private_topology[key]
            for key in (
                "source_compute",
                "source_provider",
                "destination_compute",
                "destination_provider",
                "provider_capsule_transferred",
                "transport",
            )
        }
        topology["operational_endpoint_witness"] = "withheld-private-receipt"
        public = {
            "schema": PUBLIC_SCHEMA,
            "private_execution_receipt": {
                "schema": PRIVATE_SCHEMA,
                "sha256": private_sha256,
                "retention": "private-operational-witness",
            },
            "repository_revision": private_receipt["repository_revision"],
            "repository_source_snapshot": private_receipt["repository_source_snapshot"],
            "case": private_receipt["case"],
            "input": private_receipt["input"],
            "build": private_receipt["build"],
            "topology": topology,
            "source": {
                "endpoint": source_endpoint,
                "post_checkpoint_status": private_source["post_checkpoint_status"],
                "frozen_status": private_source["frozen_status"],
                "fenced_status": private_source["fenced_status"],
            },
            "destination": {
                "endpoint": destination_endpoint,
                "prepared_status": private_destination["prepared_status"],
                "active_status": private_destination["active_status"],
                "final_status": private_destination["final_status"],
                "process": private_destination["process"],
            },
            "control": private_receipt["control"],
            "oracle": private_receipt["oracle"],
            "authority_boundary": private_receipt["authority_boundary"],
            "timing": private_receipt["timing"],
            "transfer_objects": private_receipt["transfer_objects"],
            "artifacts": artifacts,
            "explicit_non_claims": private_receipt["explicit_non_claims"],
            "public_redaction": {
                "endpoint_distinctness": "trusted-coordinator-private-observation",
                "withheld_fields": WITHHELD_FIELDS,
                "withheld_artifacts": ["raw/known_hosts"],
                "private_receipt_sha256": private_sha256,
                "transformation": "validated endpoint-redacted derivative without workload rerun",
            },
        }
        write_json(output / "receipt.json", public)
        forbid_public_keys(public, "generated public receipt")
        assert_public_literals_redacted(output, forbidden_literals)
        validate_public_receipt(
            output / "receipt.json",
            expected_revision=expected_revision,
            stock_zstd=stock_zstd,
        )
        return public
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("private_receipt_root", type=Path)
    create.add_argument("output", type=Path)
    create.add_argument("--expected-revision", required=True)
    create.add_argument("--stock-zstd", required=True, type=Path)
    validate = subparsers.add_parser("validate")
    validate.add_argument("receipt", type=Path)
    validate.add_argument("--expected-revision", required=True)
    validate.add_argument("--stock-zstd", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    if arguments.command == "create":
        public = make_public_receipt(
            arguments.private_receipt_root,
            arguments.output,
            expected_revision=arguments.expected_revision,
            stock_zstd=arguments.stock_zstd,
        )
        print(
            "stock-zstd cross-host public receipt created: "
            f"revision={public['repository_revision']} output={arguments.output}"
        )
    elif arguments.command == "validate":
        public = validate_public_receipt(
            arguments.receipt,
            expected_revision=arguments.expected_revision,
            stock_zstd=arguments.stock_zstd,
        )
        print(
            "stock-zstd cross-host public receipt valid: "
            f"revision={public['repository_revision']} cut={private.CUT_WRITE_OCCURRENCE}"
        )
    else:
        raise RedactionError("unsupported command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RedactionError, OSError, subprocess.TimeoutExpired) as error:
        print(f"stock-zstd public cross-host evidence invalid: {error}", file=sys.stderr)
        raise SystemExit(1)
