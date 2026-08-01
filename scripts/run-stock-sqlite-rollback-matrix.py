#!/usr/bin/env python3
"""Run the stock-SQLite/Wanco rollback-journal migration matrix.

The runner publishes a compact receipt only after every canonical cut has
completed a real source checkpoint, fresh-destination handoff, namespace
snapshot, and independent native-SQLite oracle.  Failed or partial runs never
publish the requested receipt.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import platform
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

import receipt_artifacts as ARTIFACTS

SCRIPT_ROOT = Path(__file__).resolve().parent
CONTRACT_PATH = SCRIPT_ROOT / "sqlite_rollback_matrix.py"
CONTRACT_SPEC = importlib.util.spec_from_file_location(
    "visa_sqlite_rollback_matrix_contract", CONTRACT_PATH
)
if CONTRACT_SPEC is None or CONTRACT_SPEC.loader is None:
    raise RuntimeError("cannot load SQLite rollback-journal matrix contract")
CONTRACT = importlib.util.module_from_spec(CONTRACT_SPEC)
sys.modules[CONTRACT_SPEC.name] = CONTRACT
CONTRACT_SPEC.loader.exec_module(CONTRACT)


PROCESS_TIMEOUT_SECONDS = 300
PROVIDER_START_TIMEOUT_SECONDS = 20
CHECKPOINT_TIMEOUT_SECONDS = 120
CURSOR_ROWS = 512
DATABASE_PATH = "workload/accounts.db"
INITIAL_TOTAL_BALANCE = 512000
EXPECTED_TXIDS = ["tx-000001"]
SEED_GUEST_PATH = "workload/seed.sql"
TRANSACTION_GUEST_PATH = "workload/transaction.sql"
CURSOR_GUEST_PATH = "workload/cursor.sql"
MAX_FRAME_BYTES = 2 * 1024 * 1024
REAL_MIGRATION_ADAPTER_SCHEMA = "visa-wasi-real-migration-adapter-v2"
ADAPTER_BINDING_SCHEMA = "visa-wasi-adapter-binding-v2"
CANONICAL_AUTHORITY_STATE_SCHEMA = "visa-wasi-canonical-authority-state-v2"
SOURCE_RETAINED_PROOF_SCHEMA = "visa-canonical-source-retained-proof-v1"
SOURCE_RETAINED_RECEIPT_SCHEMA = "visa-wasi-authority-source-retained-receipt-v1"
ORACLE_REPORT_SCHEMA = "visa-sqlite-oracle-report-v2"
ORACLE_PROJECTION_SCHEMA = "visa-sqlite-semantic-projection-v1"
APPLICATION_TIMING_SCHEMA = "visa-application-timing-v1"
APPLICATION_COST_EVENT_SCHEMA = "visa-application-cost-event-v1"
CONTROL_SCHEMA = CONTRACT.CONTROL_SCHEMA
EQUIVALENCE_PROJECTION_SCHEMA = "visa-stock-sqlite-equivalence-projection-v1"


def cost_event(label: str, **fields: object) -> None:
    """Optionally emit lifecycle events for the application-cost harness."""
    target = os.environ.get("VISA_APPLICATION_COST_EVENTS")
    if not target:
        return
    event = {
        "schema": APPLICATION_COST_EVENT_SCHEMA,
        "label": label,
        "monotonic_ns": time.monotonic_ns(),
        **fields,
    }
    path = Path(target)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("ab") as stream:
        stream.write(canonical_bytes(event) + b"\n")
        stream.flush()


MatrixFailure = CONTRACT.MatrixFailure


def canonical_bytes(value: object) -> bytes:
    return CONTRACT.canonical_bytes(value)


def write_application_timing(path: Path, phases: Sequence[dict[str, object]]) -> None:
    if not phases:
        raise MatrixFailure("application timing receipt has no phases")
    normalized: list[dict[str, object]] = []
    previous_end = -1
    for phase in phases:
        if set(phase) != {
            "phase", "role", "start_monotonic_ns", "end_monotonic_ns",
            "duration_ns", "exit_status",
        }:
            raise MatrixFailure("application timing phase has unexpected fields")
        start = phase["start_monotonic_ns"]
        end = phase["end_monotonic_ns"]
        duration = phase["duration_ns"]
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in (start, end, duration)):
            raise MatrixFailure("application timing phase has invalid integer bounds")
        if start < 0 or end <= start or duration != end - start or start < previous_end:
            raise MatrixFailure("application timing phase has invalid monotonic bounds")
        if phase["phase"] not in {"application", "reconciliation"} or not isinstance(phase["role"], str) or not phase["role"]:
            raise MatrixFailure("application timing phase identity is empty")
        if not isinstance(phase["exit_status"], int) or isinstance(phase["exit_status"], bool) or phase["exit_status"] < 0:
            raise MatrixFailure("application timing exit status is invalid")
        normalized.append(dict(phase))
        previous_end = end
    path.write_bytes(canonical_bytes({
        "schema": APPLICATION_TIMING_SCHEMA,
        "clock": "python-time.monotonic_ns",
        "phases": normalized,
    }) + b"\n")


def development_projection(value: Mapping[str, object]) -> dict[str, object]:
    """Remove runner-only filesystem handles from a development receipt."""
    return {key: item for key, item in value.items() if key != "_raw_paths"}


def sha256_file(path: Path) -> str:
    return str(CONTRACT.file_identity(path)["sha256"])


def run(
    command: Sequence[os.PathLike[str] | str],
    *,
    cwd: Path,
    timeout: int = PROCESS_TIMEOUT_SECONDS,
    check: bool = True,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    argv = [os.fspath(value) for value in command]
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=None if env is None else dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise MatrixFailure(
            f"command {Path(argv[0]).name} timed out after {timeout} seconds"
        ) from error
    if check and completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")[-4000:]
        raise MatrixFailure(
            f"command {Path(argv[0]).name} failed with status "
            f"{completed.returncode}: {stderr}"
        )
    return completed


def ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)


def stable_id(label: str) -> str:
    value = hashlib.sha256(("visa-stock-sqlite:" + label).encode()).digest()[:16]
    if not any(value):
        raise MatrixFailure("derived identity is zero")
    return value.hex()


def repository_snapshot(repository: Path) -> dict[str, object]:
    status = run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repository,
    ).stdout
    patch = run(
        ["git", "diff", "--binary", "--no-ext-diff", "HEAD", "--"],
        cwd=repository,
    ).stdout
    untracked = run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=repository,
    ).stdout
    manifest: list[dict[str, object]] = []
    for raw in untracked.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        path = repository / relative
        if path.is_symlink() or not path.is_file():
            raise MatrixFailure(f"untracked input is not a regular file: {relative}")
        manifest.append(
            {
                "path": relative.as_posix(),
                "mode": path.stat().st_mode & 0o777,
                **CONTRACT.file_identity(path),
            }
        )
    return {
        "clean": not status,
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "tracked_patch_sha256": hashlib.sha256(patch).hexdigest(),
        "untracked_file_count": len(manifest),
        "untracked_manifest_sha256": hashlib.sha256(
            canonical_bytes(manifest)
        ).hexdigest(),
    }


def write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def publish(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_bytes(value) + b"\n"
    descriptor, raw = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def retain_raw_evidence(
    record: dict[str, object],
    *,
    artifact_root: Path,
    label: str,
) -> None:
    raw_paths = record.pop("_raw_paths", None)
    if not isinstance(raw_paths, dict) or set(raw_paths) != {
        "application_runs",
        "client_stdout",
        "expected_acknowledgements",
        "namespace_snapshot",
        "oracle_report",
        "application_timing",
    }:
        raise MatrixFailure(f"{label} omitted its raw evidence paths")
    references: dict[str, object] = {}
    application_runs = raw_paths["application_runs"]
    if not isinstance(application_runs, tuple):
        raise MatrixFailure(f"{label} application run inventory is invalid")
    published_runs: list[dict[str, object]] = []
    for entry in application_runs:
        if (
            not isinstance(entry, tuple)
            or len(entry) != 4
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], Path)
            or not isinstance(entry[2], Path)
            or not isinstance(entry[3], int)
            or isinstance(entry[3], bool)
        ):
            raise MatrixFailure(f"{label} application run entry is invalid")
        role, stdout_path, stderr_path, exit_status = entry
        prefix = f"observations/{label}/runs/{role}"
        try:
            published_runs.append(
                {
                    "role": role,
                    "exit_status": exit_status,
                    "stdout": ARTIFACTS.publish_reference(
                        stdout_path, artifact_root, prefix + ".stdout"
                    ),
                    "stderr": ARTIFACTS.publish_reference(
                        stderr_path, artifact_root, prefix + ".stderr"
                    ),
                }
            )
        except ARTIFACTS.ArtifactError as error:
            raise MatrixFailure(str(error)) from error
    references["application_runs"] = published_runs
    filenames = {
        "client_stdout": "raw-client.stdout",
        "expected_acknowledgements": "expected-acks.json",
        "namespace_snapshot": "namespace.snapshot",
        "oracle_report": "oracle-report.json",
        "application_timing": "application-timing.json",
    }
    for name, filename in filenames.items():
        source = raw_paths[name]
        if not isinstance(source, Path):
            raise MatrixFailure(f"{label} raw evidence path {name} is invalid")
        relative = f"observations/{label}/{filename}"
        try:
            references[name] = ARTIFACTS.publish_reference(
                source, artifact_root, relative
            )
        except ARTIFACTS.ArtifactError as error:
            raise MatrixFailure(str(error)) from error
    record["retained_raw_evidence"] = references


def retain_provider_process_recovery_evidence(
    qualification: dict[str, object],
    *,
    artifact_root: Path,
) -> None:
    raw_paths = qualification.pop("_raw_paths", None)
    if not isinstance(raw_paths, dict) or set(raw_paths) != {
        "report",
        "stdout",
        "stderr",
    }:
        raise MatrixFailure(
            "provider process-recovery qualification omitted its raw evidence paths"
        )
    if (
        not isinstance(raw_paths["report"], Path)
        or not isinstance(raw_paths["stdout"], Path)
        or not isinstance(raw_paths["stderr"], Path)
    ):
        raise MatrixFailure(
            "provider process-recovery qualification has invalid raw evidence paths"
        )
    try:
        qualification["retained_raw_evidence"] = {
            "report": ARTIFACTS.publish_reference(
                raw_paths["report"],
                artifact_root,
                "observations/provider-process-recovery/report.json",
            ),
            "process": {
                "command": (
                    "cargo test --locked -p visa_wasi_host "
                    "--test provider_process_recovery -- --nocapture"
                ),
                "exit_status": 0,
                "stdout": ARTIFACTS.publish_reference(
                    raw_paths["stdout"],
                    artifact_root,
                    "observations/provider-process-recovery/process.stdout",
                ),
                "stderr": ARTIFACTS.publish_reference(
                    raw_paths["stderr"],
                    artifact_root,
                    "observations/provider-process-recovery/process.stderr",
                ),
            },
        }
    except ARTIFACTS.ArtifactError as error:
        raise MatrixFailure(str(error)) from error


def retain_source_abort_evidence(
    qualification: dict[str, object],
    *,
    artifact_root: Path,
) -> None:
    raw_paths = qualification.pop("_raw_paths", None)
    expected_paths = {
        "application_runs",
        "client_stdout",
        "expected_acknowledgements",
        "namespace_snapshot",
        "oracle_report",
        "application_timing",
        "compute_checkpoint",
        "migration_application",
        "resource_capsule_manifest",
        "resource_capsule_state",
        "driver_runs",
        "integrated_driver_report",
        "pending_driver_record",
        "final_driver_record",
        "crash_marker",
        "wanco_restore_started",
        "wanco_restore_completion",
        "source_exit_receipt",
        "source_authority_state",
        "committed_authority_state",
        "source_adapter_binding",
        "committed_adapter_binding",
        "source_retained_receipt",
    }
    if not isinstance(raw_paths, dict) or set(raw_paths) != expected_paths:
        raise MatrixFailure(
            "source-abort reconciliation omitted its raw evidence paths"
        )
    application_runs = raw_paths["application_runs"]
    if not isinstance(application_runs, tuple):
        raise MatrixFailure(
            "source-abort reconciliation application run inventory is invalid"
        )
    driver_runs = raw_paths["driver_runs"]
    if not isinstance(driver_runs, tuple):
        raise MatrixFailure(
            "source-abort reconciliation driver run inventory is invalid"
        )
    published_runs: list[dict[str, object]] = []
    try:
        for entry in application_runs:
            if (
                not isinstance(entry, tuple)
                or len(entry) != 4
                or not isinstance(entry[0], str)
                or not isinstance(entry[1], Path)
                or not isinstance(entry[2], Path)
                or not isinstance(entry[3], int)
                or isinstance(entry[3], bool)
            ):
                raise MatrixFailure(
                    "source-abort reconciliation application run entry is invalid"
                )
            role, stdout_path, stderr_path, exit_status = entry
            prefix = f"observations/source-abort/runs/{role}"
            published_runs.append(
                {
                    "role": role,
                    "exit_status": exit_status,
                    "stdout": ARTIFACTS.publish_reference(
                        stdout_path, artifact_root, prefix + ".stdout"
                    ),
                    "stderr": ARTIFACTS.publish_reference(
                        stderr_path, artifact_root, prefix + ".stderr"
                    ),
                }
            )
        published_driver_runs: list[dict[str, object]] = []
        for entry, spec in zip(
            driver_runs, CONTRACT.SOURCE_ABORT_DRIVER_RUNS, strict=True
        ):
            if (
                not isinstance(entry, tuple)
                or len(entry) != 4
                or not isinstance(entry[0], str)
                or not isinstance(entry[1], Path)
                or not isinstance(entry[2], Path)
                or not isinstance(entry[3], int)
                or isinstance(entry[3], bool)
                or entry[0] != spec[0]
            ):
                raise MatrixFailure(
                    "source-abort reconciliation driver run entry is invalid"
                )
            role, stdout_path, stderr_path, exit_status = entry
            prefix = f"observations/source-abort/driver-runs/{role}"
            published_driver_runs.append(
                {
                    "role": role,
                    "exit_status": exit_status,
                    "stdout": ARTIFACTS.publish_reference(
                        stdout_path, artifact_root, prefix + ".stdout"
                    ),
                    "stderr": ARTIFACTS.publish_reference(
                        stderr_path, artifact_root, prefix + ".stderr"
                    ),
                }
            )
        references: dict[str, object] = {
            "application_runs": published_runs,
            "driver_runs": published_driver_runs,
        }
        filenames = {
            "client_stdout": "raw-client.stdout",
            "expected_acknowledgements": "expected-acks.json",
            "namespace_snapshot": "namespace.snapshot",
            "oracle_report": "oracle-report.json",
            "application_timing": "application-timing.json",
            "compute_checkpoint": "compute-checkpoint.pb",
            "migration_application": "migration/application.aot",
            "resource_capsule_manifest": "migration/capsule-manifest.json",
            "resource_capsule_state": "migration/capsule-state.sqlite",
            "integrated_driver_report": "integrated-driver-report.json",
            "pending_driver_record": "pending-driver-record.json",
            "final_driver_record": "final-driver-record.json",
            "crash_marker": "crash-marker.json",
            "wanco_restore_started": "wanco-restore-started.json",
            "wanco_restore_completion": "wanco-restore-completion.json",
            "source_exit_receipt": "source-exit-receipt.json",
            "source_authority_state": "source-authority-state.json",
            "committed_authority_state": "committed-authority-state.json",
            "source_adapter_binding": "source-adapter-binding.json",
            "committed_adapter_binding": "committed-adapter-binding.json",
            "source_retained_receipt": "source-retained-receipt.json",
        }
        for name, filename in filenames.items():
            source = raw_paths[name]
            if not isinstance(source, Path):
                raise MatrixFailure(
                    f"source-abort reconciliation raw evidence path {name} is invalid"
                )
            references[name] = ARTIFACTS.publish_reference(
                source,
                artifact_root,
                f"observations/source-abort/{filename}",
            )
        qualification["retained_raw_evidence"] = references
    except ARTIFACTS.ArtifactError as error:
        raise MatrixFailure(str(error)) from error


class ShortSocketRoot:
    """Own short-lived socket and coordinator-private paths outside evidence."""

    def __init__(self) -> None:
        self.path: Path | None = None
        self.configuration_path: Path | None = None
        self._next = 0

    def __enter__(self) -> "ShortSocketRoot":
        self.path = Path(tempfile.mkdtemp(prefix="vss."))
        self.path.chmod(0o700)
        self.configuration_path = Path(tempfile.mkdtemp(prefix="vsc."))
        self.configuration_path.chmod(0o700)
        if len(os.fsencode(self.path)) >= 64:
            raise MatrixFailure(f"temporary socket root is unexpectedly long: {self.path}")
        return self

    def allocate(self) -> Path:
        if self.path is None:
            raise MatrixFailure("short socket root is not active")
        self._next += 1
        socket_path = self.path / f"s{self._next}.sock"
        if len(os.fsencode(socket_path)) >= 96:
            raise MatrixFailure(f"AF_UNIX path is not conservatively short: {socket_path}")
        return socket_path

    def __exit__(self, *_: object) -> None:
        if self.path is not None:
            shutil.rmtree(self.path, ignore_errors=True)
            self.path = None
        if self.configuration_path is not None:
            shutil.rmtree(self.configuration_path, ignore_errors=True)
            self.configuration_path = None


class Provider:
    def __init__(
        self,
        host_binary: Path,
        database: Path,
        socket_path: Path,
        admin_capability: str,
        log_root: Path,
    ) -> None:
        self.host_binary = host_binary
        self.database = database
        self.socket_path = socket_path
        self.admin_capability = admin_capability
        self.log_root = log_root
        self.process: subprocess.Popen[bytes] | None = None
        self.stdout: Any = None
        self.stderr: Any = None

    def start(self) -> None:
        ensure_private_directory(self.database.parent)
        self.stdout = (self.log_root / "provider.stdout").open("xb")
        self.stderr = (self.log_root / "provider.stderr").open("xb")
        self.process = subprocess.Popen(
            [self.host_binary, "serve", self.database, self.socket_path],
            cwd=self.log_root,
            stdin=subprocess.DEVNULL,
            stdout=self.stdout,
            stderr=self.stderr,
        )
        deadline = time.monotonic() + PROVIDER_START_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise MatrixFailure(
                    f"provider exited during startup with {self.process.returncode}"
                )
            if self.socket_path.exists():
                completed = self.control_raw("status")
                if completed.returncode == 0:
                    return
            time.sleep(0.025)
        raise MatrixFailure(f"provider did not publish {self.socket_path}")

    def control_raw(
        self, operation: str, *arguments: str | Path
    ) -> subprocess.CompletedProcess[bytes]:
        return run(
            [
                self.host_binary,
                "control",
                self.socket_path,
                self.admin_capability,
                operation,
                *arguments,
            ],
            cwd=self.log_root,
            timeout=60,
            check=False,
        )

    def control(self, operation: str, *arguments: str | Path) -> dict[str, object]:
        completed = self.control_raw(operation, *arguments)
        if completed.returncode != 0:
            raise MatrixFailure(
                f"provider control {operation!r} failed: "
                + completed.stderr.decode("utf-8", errors="replace")[-2000:]
            )
        try:
            response = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise MatrixFailure("provider control returned malformed JSON") from error
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise MatrixFailure(f"provider rejected control operation {operation!r}")
        return response

    def status(self) -> dict[str, object]:
        response = self.control("status")
        status = response.get("status")
        if not isinstance(status, dict):
            raise MatrixFailure("provider status response is missing")
        return status

    def adapter(self) -> Any:
        return CONTRACT.CliProviderControl(
            self.host_binary,
            self.socket_path,
            self.admin_capability,
            cwd=self.log_root,
        )

    def stop(self) -> None:
        process = self.process
        if process is not None and process.poll() is None:
            with contextlib.suppress(Exception):
                self.control("shutdown")
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if self.stdout is not None:
            self.stdout.close()
        if self.stderr is not None:
            self.stderr.close()
        self.process = None

    def __enter__(self) -> "Provider":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


class AotProcess:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        stdout: Any,
        stderr: Any,
        stdout_path: Path,
        stderr_path: Path,
        container_name: str,
        docker: str,
    ) -> None:
        self.process = process
        self.stdout = stdout
        self.stderr = stderr
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        self.container_name = container_name
        self.docker = docker
        self.start_monotonic_ns = time.monotonic_ns()
        self.end_monotonic_ns: int | None = None

    def wait(self, *, expect_checkpoint: bool = False) -> int:
        try:
            status = self.process.wait(timeout=PROCESS_TIMEOUT_SECONDS)
            self.end_monotonic_ns = time.monotonic_ns()
        except subprocess.TimeoutExpired as error:
            self.kill()
            raise MatrixFailure("stock SQLite AOT timed out") from error
        finally:
            self.stdout.close()
            self.stderr.close()
        if status != 0:
            diagnostic = self.stderr_path.read_text(errors="replace")[-8000:]
            raise MatrixFailure(
                f"stock SQLite AOT exited with status {status}: {diagnostic}"
            )
        if expect_checkpoint:
            checkpoint = self.stdout_path.parent / "checkpoint.pb"
            if not checkpoint.is_file() or checkpoint.stat().st_size == 0:
                raise MatrixFailure("Wanco did not publish a nonempty checkpoint.pb")
        return status

    def kill(self) -> None:
        run(
            [self.docker, "rm", "--force", self.container_name],
            cwd=self.stdout_path.parent,
            timeout=30,
            check=False,
        )
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        with contextlib.suppress(Exception):
            self.stdout.close()
        with contextlib.suppress(Exception):
            self.stderr.close()


def completed_application_run(
    role: str, process: AotProcess
) -> tuple[str, Path, Path, int]:
    status = process.process.returncode
    if not role or status is None or status != 0:
        raise MatrixFailure(f"{role or 'unnamed'} application segment did not complete cleanly")
    return role, process.stdout_path, process.stderr_path, status


def timing_phase(role: str, process: AotProcess) -> dict[str, object]:
    end = process.end_monotonic_ns
    if end is None:
        raise MatrixFailure(f"{role} application timing ended before process wait")
    return {
        "phase": "application",
        "role": role,
        "start_monotonic_ns": process.start_monotonic_ns,
        "end_monotonic_ns": end,
        "duration_ns": end - process.start_monotonic_ns,
        "exit_status": process.process.returncode,
    }


class DockerAot:
    def __init__(
        self,
        docker: str,
        image: str,
        executable: Path,
        socket_root: Path | None = None,
    ) -> None:
        self.docker = docker
        self.image = image
        self.executable = executable
        self.socket_root = socket_root

    @staticmethod
    def container_path(path: Path, case_root: Path) -> str:
        try:
            relative = path.resolve().relative_to(case_root.resolve())
        except ValueError as error:
            raise MatrixFailure(f"path is outside matrix case: {path}") from error
        return "/case/" + relative.as_posix()

    def container_socket_path(self, socket_path: Path, case_root: Path) -> str:
        try:
            socket_relative = socket_path.resolve().relative_to(case_root.resolve())
            return "/case/" + socket_relative.as_posix()
        except ValueError:
            if self.socket_root is None:
                raise MatrixFailure(
                    f"socket is outside the matrix case without a short socket root: {socket_path}"
                )
            try:
                socket_relative = socket_path.resolve().relative_to(
                    self.socket_root.resolve()
                )
            except ValueError as error:
                raise MatrixFailure(
                    f"socket is outside both the matrix case and short socket root: {socket_path}"
                ) from error
            return "/sockets/" + socket_relative.as_posix()

    def build_command(
        self,
        *,
        case_root: Path,
        cwd: Path,
        environment: Mapping[str, str],
        label: str,
        script_path: str,
        checkpoint: Path | None = None,
        socket_override: Path | None = None,
    ) -> tuple[str, list[str]]:
        name = f"visa-sqlite-{label}-{os.getpid()}-{secrets.token_hex(4)}"
        guest_environment = dict(environment)
        trace_guest = os.environ.get("VISA_WASI_TRACE_GUEST")
        if trace_guest is not None:
            guest_environment["VISA_WASI_TRACE_GUEST"] = trace_guest
        socket_path = socket_override or Path(guest_environment["VISA_WASI_SOCKET"])
        guest_environment["VISA_WASI_SOCKET"] = self.container_socket_path(
            socket_path, case_root
        )
        command = [
            self.docker,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "none",
            "--security-opt",
            "label=disable",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--volume",
            f"{case_root.resolve()}:/case:Z",
            "--volume",
            f"{self.executable.parent.resolve()}:/aot:ro,Z",
            "--workdir",
            self.container_path(cwd, case_root),
        ]
        if self.socket_root is not None:
            command.extend(
                [
                    "--volume",
                    f"{self.socket_root.resolve()}:/sockets:Z",
                ]
            )
        for key, value in sorted(guest_environment.items()):
            command.extend(["--env", f"{key}={value}"])
        command.extend([self.image, f"/aot/{self.executable.name}"])
        if checkpoint is not None:
            command.extend(
                ["--restore", self.container_path(checkpoint, case_root)]
            )
        command.extend(
            ["--", "-batch", "-bail", DATABASE_PATH, f".read {script_path}"]
        )
        return name, command

    def start(
        self,
        *,
        case_root: Path,
        cwd: Path,
        environment: Mapping[str, str],
        label: str,
        script_path: str,
        checkpoint: Path | None = None,
        socket_override: Path | None = None,
    ) -> AotProcess:
        name, command = self.build_command(
            case_root=case_root,
            cwd=cwd,
            environment=environment,
            label=label,
            script_path=script_path,
            checkpoint=checkpoint,
            socket_override=socket_override,
        )
        stdout_path = cwd / f"{label}.stdout"
        stderr_path = cwd / f"{label}.stderr"
        stdout = stdout_path.open("xb")
        stderr = stderr_path.open("xb")
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
            )
        except BaseException:
            stdout.close()
            stderr.close()
            raise
        return AotProcess(
            process, stdout, stderr, stdout_path, stderr_path, name, self.docker
        )


def require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise MatrixFailure(f"{label} is not a JSON object")
    return value


def hex_identity(value: object, size: int, label: str) -> str:
    if isinstance(value, str):
        result = value
    elif (
        isinstance(value, list)
        and len(value) == size
        and all(isinstance(item, int) and 0 <= item <= 255 for item in value)
    ):
        result = bytes(value).hex()
    else:
        raise MatrixFailure(f"{label} has an unsupported identity encoding")
    if (
        len(result) != size * 2
        or result.lower() != result
        or any(character not in "0123456789abcdef" for character in result)
        or result == "0" * (size * 2)
    ):
        raise MatrixFailure(f"{label} is not a nonzero {size}-byte identity")
    return result


def create_provider(
    host_binary: Path,
    database: Path,
    *,
    session: str,
    admin_capability: str,
    guest_capability: str,
    epoch: int,
    imports: Mapping[str, Path],
    cwd: Path,
) -> None:
    ensure_private_directory(database.parent)
    command: list[os.PathLike[str] | str] = [
        host_binary,
        "create",
        database,
        session,
        admin_capability,
        guest_capability,
        str(epoch),
    ]
    for guest, host in sorted(imports.items()):
        command.append(f"{guest}={host.resolve()}")
    run(command, cwd=cwd)


def restore_provider(
    host_binary: Path,
    bundle: Path,
    database: Path,
    admin_capability: str,
    guest_capability: str,
    cwd: Path,
) -> None:
    ensure_private_directory(database.parent)
    run(
        [
            host_binary,
            "restore",
            bundle,
            database,
            admin_capability,
            guest_capability,
        ],
        cwd=cwd,
    )


def guest_environment(
    socket_path: Path,
    *,
    session: str,
    owner: str,
    client: str,
    guest_capability: str,
    epoch: int,
) -> dict[str, str]:
    return {
        "VISA_WASI_SOCKET": os.fspath(socket_path),
        "VISA_WASI_SESSION_ID": session,
        "VISA_WASI_OWNER_ID": owner,
        "VISA_WASI_CLIENT_ID": client,
        "VISA_WASI_GUEST_CAPABILITY": guest_capability,
        "VISA_WASI_AUTHORITY_EPOCH": str(epoch),
    }


def copy_regular(source: Path, destination: Path) -> None:
    if not source.is_file() or source.is_symlink() or source.stat().st_size == 0:
        raise MatrixFailure(f"cannot bind missing or empty artifact {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_stream, destination.open("xb") as output_stream:
        shutil.copyfileobj(input_stream, output_stream, 1024 * 1024)
        output_stream.flush()
        os.fsync(output_stream.fileno())
    destination.chmod(source.stat().st_mode & 0o777)


def process_progress_guard(
    holder: Mapping[str, AotProcess], label: str
) -> Callable[[], None]:
    def guard() -> None:
        process = holder.get("process")
        if process is None:
            return
        status = process.process.poll()
        if status is None:
            return
        with contextlib.suppress(Exception):
            process.stdout.close()
        with contextlib.suppress(Exception):
            process.stderr.close()
        diagnostic = process.stderr_path.read_text(errors="replace")[-4000:]
        raise MatrixFailure(
            f"{label} exited before reaching its exact barrier with status "
            f"{status}: {diagnostic}"
        )

    return guard


def write_intent(
    path: Path,
    *,
    session: str,
    owner: str,
    handoff: str,
    checkpoint_barrier: str,
    source_client: str,
    source_restore_client: str,
    destination_client: str,
    build_receipt: Mapping[str, object],
    runtime_sha256: str,
    source_lock_sha256: str,
) -> None:
    platform_identity = {
        "operating_system": "linux",
        "architecture": platform.machine(),
        "abi": "wanco-aot-preview1",
        "runtime_name": "Wanco",
        "runtime_version": str(build_receipt["wanco_revision"]),
        "runtime_build_sha256": runtime_sha256,
    }
    document = {
        "files": {
            "application": "artifacts/application.aot",
            "compute_checkpoint": "artifacts/checkpoint.pb",
            "resource_capsule_manifest": "capsule/manifest.json",
            "resource_capsule_state": "capsule/state.sqlite",
        },
        "session_hex": session,
        "stable_owner_hex": owner,
        "handoff_hex": handoff,
        "checkpoint_barrier_hex": checkpoint_barrier,
        "source_epoch": 1,
        "destination_epoch": 2,
        "source_client_hex": source_client,
        "source_restore_client_hex": source_restore_client,
        "destination_client_hex": destination_client,
        "application_build": {
            "source_revision": str(build_receipt["sqlite_version"]),
            "toolchain": str(build_receipt["compiler"]),
            "build_configuration_sha256": source_lock_sha256,
        },
        "source_platform": platform_identity,
        "destination_platform": platform_identity,
    }
    write_new(path, canonical_bytes(document))


def bind_command(
    bind_binary: Path, command: str, root: Path, *arguments: str | Path
) -> subprocess.CompletedProcess[bytes]:
    return run(
        [bind_binary, command, root, *arguments],
        cwd=root,
        timeout=60,
        check=False,
    )


def require_success(
    completed: subprocess.CompletedProcess[bytes], label: str
) -> subprocess.CompletedProcess[bytes]:
    if completed.returncode != 0:
        raise MatrixFailure(
            f"{label} failed with status {completed.returncode}: "
            + completed.stderr.decode("utf-8", errors="replace")[-3000:]
        )
    return completed


def read_exact(stream: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.recv(size - len(chunks))
        if not chunk:
            raise MatrixFailure("wire connection closed inside a frame")
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(stream: socket.socket) -> bytes:
    length = int.from_bytes(read_exact(stream, 4), "big")
    if length <= 0 or length > MAX_FRAME_BYTES:
        raise MatrixFailure("wire frame length is outside the protocol bound")
    return read_exact(stream, length)


def write_frame(stream: socket.socket, frame: bytes) -> None:
    if not frame or len(frame) > MAX_FRAME_BYTES:
        raise MatrixFailure("wire response length is outside the protocol bound")
    stream.sendall(len(frame).to_bytes(4, "big") + frame)


class LostResponseRelay:
    """Drop exactly the target guest response after its durable effect commits."""

    def __init__(self, proxy: Path, upstream: Path, provider: Provider) -> None:
        self.proxy = proxy
        self.upstream = upstream
        self.provider = provider
        self.listener: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.dropped_event = threading.Event()
        self.allow_retry = threading.Event()
        self.failed_event = threading.Event()
        self.failure: BaseException | None = None
        self.target_request: bytes | None = None
        self.target_response: bytes | None = None
        self.replay_request: bytes | None = None
        self.replay_response: bytes | None = None
        self.target_status: dict[str, object] | None = None
        self.replay_status: dict[str, object] | None = None
        self.forwarded_frames = 0

    def start(self) -> None:
        ensure_private_directory(self.proxy.parent)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(os.fspath(self.proxy))
        os.chmod(self.proxy, 0o600)
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _exchange_upstream(self, request: bytes) -> bytes:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
            upstream.settimeout(30)
            upstream.connect(os.fspath(self.upstream))
            write_frame(upstream, request)
            return read_frame(upstream)

    def _serve(self) -> None:
        try:
            assert self.listener is not None
            while not self.stop_event.is_set():
                try:
                    downstream, _ = self.listener.accept()
                except TimeoutError:
                    continue
                with downstream:
                    downstream.settimeout(30)
                    request = read_frame(downstream)
                    is_retry = self.target_request is not None and self.replay_request is None
                    if is_retry:
                        if not self.allow_retry.wait(PROCESS_TIMEOUT_SECONDS):
                            raise MatrixFailure("lost-response retry was never released")
                        if request != self.target_request:
                            raise MatrixFailure(
                                "source runtime did not retry the exact encoded request"
                            )
                    response = self._exchange_upstream(request)
                    self.forwarded_frames += 1
                    status = CONTRACT.status_projection(self.provider.status())
                    if self.target_request is None and status["barrier"] == "triggered":
                        self.target_request = request
                        self.target_response = response
                        self.target_status = status
                        self.dropped_event.set()
                        continue
                    if is_retry:
                        self.replay_request = request
                        self.replay_response = response
                        self.replay_status = status
                    write_frame(downstream, response)
        except BaseException as error:
            if not self.stop_event.is_set():
                self.failure = error
                self.failed_event.set()
                self.dropped_event.set()

    def wait_for_drop(self) -> None:
        if not self.dropped_event.wait(CHECKPOINT_TIMEOUT_SECONDS):
            raise MatrixFailure("relay did not observe a dropped target response")
        self.raise_if_failed()
        if self.target_request is None or self.target_response is None:
            raise MatrixFailure("relay drop event lacks the target protocol frames")

    def raise_if_failed(self) -> None:
        if self.failure is not None:
            raise MatrixFailure(f"lost-response relay failed: {self.failure}") from self.failure

    def trace(self) -> dict[str, object]:
        self.raise_if_failed()
        if self.target_request is None or self.target_response is None:
            raise MatrixFailure("lost-response relay has no dropped target")
        result: dict[str, object] = {
            "schema": "visa-sqlite-lost-response-relay-trace-v1",
            "injection": "drop-guest-response-after-durable-effect",
            "forwarded_frames": self.forwarded_frames,
            "target_request_sha256": hashlib.sha256(self.target_request).hexdigest(),
            "target_request_bytes": len(self.target_request),
            "target_response_sha256": hashlib.sha256(self.target_response).hexdigest(),
            "target_response_bytes": len(self.target_response),
            "target_status": self.target_status,
        }
        if self.replay_request is not None and self.replay_response is not None:
            result.update(
                {
                    "replay_request_sha256": hashlib.sha256(
                        self.replay_request
                    ).hexdigest(),
                    "replay_request_bytes": len(self.replay_request),
                    "replay_response_sha256": hashlib.sha256(
                        self.replay_response
                    ).hexdigest(),
                    "replay_response_bytes": len(self.replay_response),
                    "replay_status": self.replay_status,
                    "exact_request_replay": self.replay_request == self.target_request,
                }
            )
        return result

    def stop(self) -> None:
        self.stop_event.set()
        self.allow_retry.set()
        if self.listener is not None:
            with contextlib.suppress(OSError):
                self.listener.close()
        if self.thread is not None:
            self.thread.join(timeout=5)
        with contextlib.suppress(FileNotFoundError):
            self.proxy.unlink()

    def __enter__(self) -> "LostResponseRelay":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


def request_binding(database: Path, effect: str) -> dict[str, object]:
    try:
        connection = sqlite3.connect(database, timeout=10)
        row = connection.execute(
            "SELECT hex(client), sequence, hex(effect_id), completed "
            "FROM requests WHERE effect_id = ?",
            (bytes.fromhex(effect),),
        ).fetchone()
    except sqlite3.Error as error:
        raise MatrixFailure(f"cannot inspect durable request binding: {error}") from error
    finally:
        if "connection" in locals():
            connection.close()
    if row is None:
        raise MatrixFailure("target effect has no durable request binding")
    client, sequence, effect_hex, completed = row
    if (
        not isinstance(client, str)
        or not isinstance(sequence, int)
        or sequence <= 0
        or not isinstance(effect_hex, str)
        or effect_hex.lower() != effect
        or completed != 0
    ):
        raise MatrixFailure("target request binding is malformed or already completed")
    return {
        "client": client.lower(),
        "sequence": sequence,
        "effect": effect_hex.lower(),
        "completed": completed,
    }


def strict_stdout_observation(
    *,
    transcript: Path,
    components: Sequence[Path],
    source_cursor_stdout: Path | None,
    expect_cursor: bool = False,
) -> tuple[dict[str, object], list[str]]:
    payload = bytearray()
    for path in components:
        raw = path.read_bytes()
        if payload and not payload.endswith(b"\n"):
            payload.extend(b"\n")
        payload.extend(raw)
    if not payload:
        raise MatrixFailure("stock SQLite produced no raw client stdout")
    write_new(transcript, bytes(payload))
    try:
        lines = transcript.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise MatrixFailure("stock SQLite stdout is not UTF-8") from error
    if any(
        line != "delete"
        and not line.startswith(("VISA_ACK|", "VISA_ROW|", "VISA_CURSOR_DONE|"))
        for line in lines
    ):
        raise MatrixFailure("stock SQLite emitted an unexpected stdout line")
    if [line for line in lines if line == "delete"] != ["delete"]:
        raise MatrixFailure(
            "stock SQLite did not emit one exact DELETE journal-mode result"
        )
    ack_lines = [line for line in lines if line.startswith("VISA_ACK|")]
    txids: list[str] = []
    for line in ack_lines:
        fields = line.split("|")
        if len(fields) != 2 or not fields[1]:
            raise MatrixFailure("stock SQLite emitted a malformed ACK terminal")
        txids.append(fields[1])
    if txids != EXPECTED_TXIDS:
        raise MatrixFailure(
            f"raw stock SQLite ACK terminals differ from the workload: {txids!r}"
        )

    row_lines = [line for line in lines if line.startswith("VISA_ROW|")]
    rows: list[tuple[int, int]] = []
    for line in row_lines:
        fields = line.split("|")
        if len(fields) != 3:
            raise MatrixFailure("stock SQLite emitted a malformed cursor row")
        try:
            rows.append((int(fields[1]), int(fields[2])))
        except ValueError as error:
            raise MatrixFailure("stock SQLite cursor row is not numeric") from error
    done_lines = [line for line in lines if line.startswith("VISA_CURSOR_DONE|")]
    done_count = len(done_lines)
    prefix_rows = 0
    if expect_cursor:
        expected_rows = [
            (account, 999 if account <= 256 else 1001)
            for account in range(1, CURSOR_ROWS + 1)
        ]
        if (
            rows != expected_rows
            or done_lines != [f"VISA_CURSOR_DONE|{CURSOR_ROWS}"]
        ):
            raise MatrixFailure("cursor output is not one exact ordered result")
        if source_cursor_stdout is not None:
            source_lines = source_cursor_stdout.read_text(encoding="utf-8").splitlines()
            if any(not line.startswith("VISA_ROW|") for line in source_lines):
                raise MatrixFailure(
                    "source cursor stdout contains a non-row output line"
                )
            prefix_rows = sum(line.startswith("VISA_ROW|") for line in source_lines)
            if not 0 < prefix_rows < CURSOR_ROWS:
                raise MatrixFailure(
                    "source cursor output is not a strict nonterminal prefix"
                )
    elif rows or done_count:
        raise MatrixFailure("transaction cut emitted unexpected cursor terminals")

    cursor_rows_sha256 = account_rows_sha256(rows) if rows else None
    return (
        {
            "stdout": CONTRACT.file_identity(transcript),
            "acknowledged_txids": txids,
            "ack_terminal_count": len(ack_lines),
            "cursor_prefix_rows": prefix_rows,
            "cursor_total_rows": len(rows),
            "cursor_done_count": done_count,
            "cursor_rows_sha256": cursor_rows_sha256,
        },
        txids,
    )


def account_rows_sha256(rows: Sequence[tuple[int, int]]) -> str:
    digest = hashlib.sha256()
    digest.update(b"visa-sqlite-account-rows-v1\0")
    digest.update(struct.pack(">Q", len(rows)))
    for account_id, balance in rows:
        digest.update(struct.pack(">q", account_id))
        digest.update(struct.pack(">q", balance))
    return digest.hexdigest()


def write_expected_acks(path: Path, txids: Sequence[str]) -> dict[str, object]:
    if list(txids) != EXPECTED_TXIDS:
        raise MatrixFailure("cannot derive oracle ACK input from unexpected stdout terminals")
    write_new(
        path,
        canonical_bytes(
            {
                "schema_version": "visa-sqlite-expected-acks-v1",
                "initial_total_balance": INITIAL_TOTAL_BALANCE,
                "acknowledged_txids": list(txids),
            }
        )
        + b"\n",
    )
    return CONTRACT.file_identity(path)


def read_json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise MatrixFailure(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise MatrixFailure(f"{label} is not a JSON object")
    return value


def read_canonical_json(path: Path, label: str) -> dict[str, object]:
    value = read_json(path, label)
    if path.read_bytes() != canonical_bytes(value) + b"\n":
        raise MatrixFailure(f"{label} is not canonical JSON")
    return value


def verify_receipt_identity(path: Path, expected: object, label: str) -> None:
    if not isinstance(expected, dict) or set(expected) != {"sha256", "size"}:
        raise MatrixFailure(f"{label} receipt identity is malformed")
    if not path.is_file() or path.is_symlink():
        raise MatrixFailure(f"{label} is not a regular file")
    actual = {"sha256": sha256_file(path), "size": path.stat().st_size}
    if actual != expected:
        raise MatrixFailure(f"{label} differs from its build receipt")


def docker_image_id(docker: str, image_name: str, cwd: Path) -> str:
    completed = run(
        [docker, "image", "inspect", image_name, "--format", "{{.Id}}"],
        cwd=cwd,
    )
    result = completed.stdout.decode("utf-8", errors="strict").strip()
    if not result.startswith("sha256:") or len(result) != 71:
        raise MatrixFailure(f"Docker returned an invalid image identity for {image_name}")
    return result


def verify_execution_inputs(
    *,
    repository: Path,
    artifact_root: Path,
    sqlite_source_lock_path: Path,
    wanco_source_lock_path: Path,
    wanco_build_receipt_path: Path,
    typed_corpus_receipt_path: Path,
    host_binary: Path,
    bind_binary: Path,
    driver_binary: Path,
    oracle_binary: Path,
    docker: str,
) -> tuple[
    dict[str, object],
    DockerAot,
    dict[str, dict[str, object]],
    dict[str, Path],
    dict[str, object],
]:
    build_receipt_path = artifact_root / "receipt.json"
    build_receipt = read_json(build_receipt_path, "stock SQLite build receipt")
    source_lock = read_json(sqlite_source_lock_path, "stock SQLite source lock")
    wanco_source_lock = read_json(wanco_source_lock_path, "Wanco source lock")
    wanco_receipt = read_json(wanco_build_receipt_path, "Wanco build receipt")
    try:
        typed_corpus, typed_qualification = CONTRACT.TYPED_CORPUS.load_and_validate(
            typed_corpus_receipt_path
        )
    except CONTRACT.TYPED_CORPUS.CorpusFailure as error:
        raise MatrixFailure(f"Wanco typed corpus evidence is invalid: {error}") from error
    if build_receipt.get("schema") != "visa-stock-sqlite-build-receipt-v1":
        raise MatrixFailure("unsupported stock SQLite build receipt schema")
    if source_lock.get("schema") != "visa-stock-sqlite-source-lock-v1":
        raise MatrixFailure("unsupported stock SQLite source lock schema")
    if wanco_source_lock.get("schema") != "visa-wanco-carrier-source-lock-v3":
        raise MatrixFailure("unsupported Wanco source lock schema")
    if wanco_receipt.get("schema") != "visa-wanco-carrier-build-receipt-v5":
        raise MatrixFailure("unsupported Wanco build receipt schema")
    if (
        wanco_receipt.get("stackmap_binding") != "exact-active-callsite-id"
        or wanco_receipt.get("stackmap_layout")
        != "typed-locals-and-value-stack-v2"
        or wanco_receipt.get("indirect_call_operands_retained") is not True
        or wanco_receipt.get("active_data_segments_preserved_on_restore") is not True
        or wanco_receipt.get("per_frame_callee_saved_registers") is not True
        or wanco_receipt.get("post_import_checkpoint_points") is not True
        or wanco_receipt.get("guest_tail_calls_disabled") is not True
    ):
        raise MatrixFailure("Wanco build lacks the qualified typed-restore contract")
    if (
        typed_qualification["wanco_build_receipt"]
        != CONTRACT.file_identity(wanco_build_receipt_path)
        or typed_corpus["image_tag"] != wanco_receipt.get("image_tag")
        or typed_corpus["image_id"] != wanco_receipt.get("image_id")
    ):
        raise MatrixFailure("Wanco typed corpus is detached from the locked build")
    if (
        build_receipt.get("zero_upstream_source_patches") is not True
        or require_object(source_lock.get("source_policy"), "SQLite source policy").get(
            "source_patches"
        )
        != []
        or build_receipt.get("journal_mode") != "delete"
        or build_receipt.get("synchronous") != "full"
        or build_receipt.get("database_guest_path") != DATABASE_PATH
        or build_receipt.get("wanco_optimization") != "-O1"
    ):
        raise MatrixFailure("stock SQLite build does not match the rollback-matrix profile")

    artifacts = require_object(build_receipt.get("artifacts"), "SQLite build artifacts")
    aot_names = [name for name in artifacts if name.endswith("-wanco-o1")]
    wasm_names = [name for name in artifacts if name.endswith(".wasm")]
    if len(aot_names) != 1 or len(wasm_names) != 1 or "imports.json" not in artifacts:
        raise MatrixFailure("stock SQLite receipt does not bind one Wasm/AOT/import trace")
    aot = artifact_root / aot_names[0]
    wasm = artifact_root / wasm_names[0]
    imports_trace = artifact_root / "imports.json"
    for path, label in (
        (aot, "stock SQLite AOT"),
        (wasm, "stock SQLite Wasm"),
        (imports_trace, "stock SQLite import trace"),
    ):
        verify_receipt_identity(path, artifacts[path.name], label)

    source_lock_sha = sha256_file(sqlite_source_lock_path)
    wanco_lock_sha = sha256_file(wanco_source_lock_path)
    wanco_receipt_sha = sha256_file(wanco_build_receipt_path)
    if build_receipt.get("source_lock_sha256") != source_lock_sha:
        raise MatrixFailure("SQLite build receipt is detached from its source lock")
    if build_receipt.get("wanco_source_lock_sha256") != wanco_lock_sha:
        raise MatrixFailure("SQLite build receipt is detached from the Wanco source lock")
    if build_receipt.get("wanco_build_receipt_sha256") != wanco_receipt_sha:
        raise MatrixFailure("SQLite build receipt is detached from the Wanco build receipt")
    upstream = require_object(wanco_source_lock.get("upstream"), "Wanco upstream")
    if (
        build_receipt.get("wanco_revision") != upstream.get("revision")
        or wanco_receipt.get("revision") != upstream.get("revision")
        or build_receipt.get("wanco_compiler_sha256")
        != wanco_receipt.get("wanco_binary_sha256")
        or build_receipt.get("wanco_runtime_sha256")
        != wanco_receipt.get("runtime_staticlib_sha256")
    ):
        raise MatrixFailure("Wanco revision or runtime identity chain is inconsistent")
    patches = wanco_source_lock.get("patches")
    if not isinstance(patches, list) or not patches:
        raise MatrixFailure("Wanco source lock has no explicit patch set")
    patch_digest = hashlib.sha256(
        "".join(str(require_object(item, "Wanco patch")["sha256"]) for item in patches).encode()
    ).hexdigest()
    if wanco_receipt.get("patch_set_sha256") != patch_digest:
        raise MatrixFailure("Wanco build receipt patch-set digest is stale")
    image = str(build_receipt.get("wanco_image", ""))
    live_image_id = docker_image_id(docker, image, repository)
    if live_image_id != build_receipt.get("wanco_image_id") or live_image_id != wanco_receipt.get(
        "image_id"
    ):
        raise MatrixFailure("live Wanco image differs from the locked build chain")

    checker = repository / "scripts" / "check-sqlite-source.py"
    run(
        [sys.executable, checker, "--lock", sqlite_source_lock_path, "--wasm", wasm],
        cwd=repository,
    )
    source_policy = require_object(source_lock["source_policy"], "SQLite source policy")
    workload_lock = require_object(source_policy.get("workloads"), "SQLite workloads")
    workload_paths: dict[str, Path] = {}
    for name in ("seed", "transaction", "cursor"):
        entry = require_object(workload_lock.get(name), f"SQLite workload {name}")
        path = repository / str(entry.get("path", ""))
        if sha256_file(path) != entry.get("sha256"):
            raise MatrixFailure(f"source-locked SQLite workload drifted: {name}")
        workload_paths[name] = path

    for path, label in (
        (host_binary, "vISA WASI host"),
        (bind_binary, "migration binder"),
        (driver_binary, "migration driver"),
        (oracle_binary, "SQLite oracle"),
    ):
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise MatrixFailure(f"{label} binary is missing or empty: {path}")
    inputs = {
        "sqlite_source_lock": CONTRACT.file_identity(sqlite_source_lock_path),
        "sqlite_build_receipt": CONTRACT.file_identity(build_receipt_path),
        "wanco_source_lock": CONTRACT.file_identity(wanco_source_lock_path),
        "wanco_build_receipt": CONTRACT.file_identity(wanco_build_receipt_path),
        "wanco_typed_restore_corpus": CONTRACT.file_identity(
            typed_corpus_receipt_path
        ),
        "stock_sqlite_wasm": CONTRACT.file_identity(wasm),
        "stock_sqlite_aot": CONTRACT.file_identity(aot),
        "stock_sqlite_import_trace": CONTRACT.file_identity(imports_trace),
        "visa_wasi_host": CONTRACT.file_identity(host_binary),
        "visa_migration_bind": CONTRACT.file_identity(bind_binary),
        "visa_migration_driver": CONTRACT.file_identity(driver_binary),
        "visa_sqlite_oracle": CONTRACT.file_identity(oracle_binary),
    }
    return (
        build_receipt,
        DockerAot(docker, image, aot),
        inputs,
        workload_paths,
        typed_qualification,
    )


def build_runtime_binaries(repository: Path) -> None:
    run(
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "visa_wasi_host",
            "-p",
            "visa_wasi_migration",
            "-p",
            "visa-sqlite-oracle",
        ],
        cwd=repository,
        timeout=1200,
    )


def qualify_provider_process_recovery(repository: Path, root: Path) -> dict[str, object]:
    command = (
        "cargo test --locked -p visa_wasi_host "
        "--test provider_process_recovery -- --nocapture"
    )
    completed = run(
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "visa_wasi_host",
            "--test",
            "provider_process_recovery",
            "--",
            "--nocapture",
        ],
        cwd=repository,
        timeout=1200,
        check=False,
    )
    stdout_path = root / "provider-process-recovery.stdout"
    stderr_path = root / "provider-process-recovery.stderr"
    write_new(stdout_path, completed.stdout)
    write_new(stderr_path, completed.stderr)
    names = [
        "response_loss_then_provider_kill_reopen_replays_exactly_once",
        "fd_sync_and_datasync_survive_provider_kill_reopen_in_process_crash_model",
    ]
    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    if completed.returncode != 0 or any(name not in output for name in names):
        raise MatrixFailure("provider kill/reopen qualification did not pass both exact tests")
    report_path = root / "provider-process-recovery.json"
    write_new(
        report_path,
        canonical_bytes(
            {
                "schema": "visa-sqlite-provider-process-recovery-v1",
                "command": command,
                "exit_status": completed.returncode,
                "qualified_tests": names,
                "stdout": CONTRACT.file_identity(stdout_path, allow_empty=True),
                "stderr": CONTRACT.file_identity(stderr_path, allow_empty=True),
                "scope": "provider-process-kill-reopen",
                "nonclaims": [
                    "power-loss",
                    "torn-sector",
                    "device-write-reordering",
                ],
            }
        )
        + b"\n",
    )
    return {
        "schema": "visa-sqlite-provider-process-recovery-v2",
        "scope": "provider-process-kill-reopen",
        "qualified_tests": names,
        "nonclaims": [
            "power-loss",
            "torn-sector",
            "device-write-reordering",
        ],
        "_raw_paths": {
            "report": report_path,
            "stdout": stdout_path,
            "stderr": stderr_path,
        },
    }


def run_script(
    runtime: DockerAot,
    *,
    case_root: Path,
    cwd: Path,
    environment: Mapping[str, str],
    label: str,
    script_path: str,
    checkpoint: Path | None = None,
    socket_override: Path | None = None,
) -> AotProcess:
    process = runtime.start(
        case_root=case_root,
        cwd=cwd,
        environment=environment,
        label=label,
        script_path=script_path,
        checkpoint=checkpoint,
        socket_override=socket_override,
    )
    try:
        process.wait()
    except BaseException:
        process.kill()
        raise
    return process


def seed_source(
    runtime: DockerAot,
    *,
    case_root: Path,
    cwd: Path,
    environment: Mapping[str, str],
) -> AotProcess:
    cost_event("sqlite.seed.start")
    process = run_script(
        runtime,
        case_root=case_root,
        cwd=cwd,
        environment=environment,
        label="seed",
        script_path=SEED_GUEST_PATH,
    )
    lines = process.stdout_path.read_text(encoding="utf-8").splitlines()
    if lines.count("VISA_SEED|accounts=512|balance=512000") != 1:
        raise MatrixFailure("source-locked seed workload did not establish its exact baseline")
    cost_event("sqlite.seed.complete")
    return process


def checkpoint_regular_cut(
    runtime: DockerAot,
    *,
    case_root: Path,
    source: Path,
    provider: Provider,
    environment: Mapping[str, str],
    token: str,
    predicate: Mapping[str, object],
    script_path: str,
) -> tuple[dict[str, object], AotProcess, Path]:
    cost_event("sqlite.cut.checkpoint_start", cell=source.name)
    holder: dict[str, AotProcess] = {}

    def start_segment() -> None:
        holder["process"] = runtime.start(
            case_root=case_root,
            cwd=source,
            environment=environment,
            label="source-cut",
            script_path=script_path,
        )

    def await_checkpoint() -> Path:
        process = holder.get("process")
        if process is None:
            raise MatrixFailure("source cut did not launch stock SQLite")
        process.wait(expect_checkpoint=True)
        return source / "checkpoint.pb"

    try:
        capture = CONTRACT.execute_checkpoint_cut(
            provider.adapter(),
            token=token,
            predicate=predicate,
            start_segment=start_segment,
            await_checkpoint=await_checkpoint,
            progress_guard=process_progress_guard(holder, "source stock SQLite"),
            timeout_seconds=CHECKPOINT_TIMEOUT_SECONDS,
        )
    except BaseException:
        if "process" in holder:
            holder["process"].kill()
        raise
    checkpoint = source / "checkpoint.pb"
    cost_event("sqlite.cut.checkpoint_complete", cell=source.name)
    return capture, holder["process"], checkpoint


def checkpoint_lost_response_cut(
    runtime: DockerAot,
    *,
    case_root: Path,
    source: Path,
    provider: Provider,
    source_database: Path,
    environment: Mapping[str, str],
    token: str,
    predicate: Mapping[str, object],
    source_client: str,
    proxy_socket: Path,
) -> tuple[dict[str, object], dict[str, object], AotProcess, Path]:
    cost_event("sqlite.cut.lost_response_start", cell=source.name)
    holder: dict[str, AotProcess] = {}
    with LostResponseRelay(proxy_socket, provider.socket_path, provider) as relay:

        def start_segment() -> None:
            holder["process"] = runtime.start(
                case_root=case_root,
                cwd=source,
                environment=environment,
                label="source-cut",
                script_path=TRANSACTION_GUEST_PATH,
                socket_override=proxy_socket,
            )

        try:
            barrier = CONTRACT.execute_lost_response_trigger(
                provider.adapter(),
                token=token,
                predicate=predicate,
                start_injected_segment=start_segment,
                progress_guard=process_progress_guard(
                    holder, "lost-response source stock SQLite"
                ),
                timeout_seconds=CHECKPOINT_TIMEOUT_SECONDS,
            )
            relay.wait_for_drop()
            target = barrier["target"]
            effect = str(target["barrier_effect"])
            binding = request_binding(source_database, effect)
            if binding["client"] != source_client:
                raise MatrixFailure("lost response is not bound to the source process client")
            effects_before = int(target["effects"])
            relay.allow_retry.set()
            controller = CONTRACT.ExactBarrierController(
                provider.adapter(), timeout_seconds=CHECKPOINT_TIMEOUT_SECONDS
            )
            replay_held = controller.await_target("held")
            relay.raise_if_failed()
            if relay.replay_request != relay.target_request:
                raise MatrixFailure("lost response did not use an exact encoded retry")
            if replay_held["effects"] != effects_before:
                raise MatrixFailure("lost response retry duplicated the durable effect")
            checkpoint_released = controller.release_checkpoint(token, replay_held)
            cost_event("sqlite.cut.checkpoint_complete", cell=source.name)
            process = holder["process"]
            process.wait(expect_checkpoint=True)
            replay_binding = request_binding_completed(source_database, effect)
            if replay_binding != {**binding, "completed": 1}:
                raise MatrixFailure("same-source replay did not complete the original request")
            trace_path = source / "lost-response-trace.json"
            write_new(
                trace_path,
                canonical_bytes(
                    {
                        **relay.trace(),
                        "request_binding_before_replay": binding,
                        "request_binding_after_replay": replay_binding,
                    }
                )
                + b"\n",
            )
            delivery = {
                "injection": "drop-guest-response-after-durable-effect",
                "injector": CONTRACT.file_identity(Path(__file__)),
                "injection_trace": CONTRACT.file_identity(trace_path),
                "triggered_effect": effect,
                "replayed_effect": effect,
                "source_client": source_client,
                "replay_client": source_client,
                "source_sequence": binding["sequence"],
                "replay_sequence": binding["sequence"],
                "effects_before_replay": effects_before,
                "effects_after_replay": replay_held["effects"],
                "replay_held": replay_held,
                "checkpoint_released": checkpoint_released,
            }
        except BaseException:
            if "process" in holder:
                holder["process"].kill()
            raise
    return barrier, delivery, holder["process"], source / "checkpoint.pb"


def request_binding_completed(database: Path, effect: str) -> dict[str, object]:
    try:
        connection = sqlite3.connect(database, timeout=10)
        row = connection.execute(
            "SELECT hex(client), sequence, hex(effect_id), completed "
            "FROM requests WHERE effect_id = ?",
            (bytes.fromhex(effect),),
        ).fetchone()
    except sqlite3.Error as error:
        raise MatrixFailure(f"cannot inspect completed request binding: {error}") from error
    finally:
        if "connection" in locals():
            connection.close()
    if row is None:
        raise MatrixFailure("replayed effect has no durable request binding")
    return {
        "client": str(row[0]).lower(),
        "sequence": int(row[1]),
        "effect": str(row[2]).lower(),
        "completed": int(row[3]),
    }


def run_source_death_negative(
    runtime: DockerAot,
    *,
    root: Path,
    host_binary: Path,
    imports: Mapping[str, Path],
    sockets: ShortSocketRoot,
) -> dict[str, object]:
    case = root / "lost-response-source-death"
    ensure_private_directory(case)
    session = stable_id("lost-response-source-death-session")
    owner = stable_id("lost-response-source-death-owner")
    seed_client = stable_id("lost-response-source-death-seed-client")
    client = stable_id("lost-response-source-death-client")
    token = stable_id("lost-response-source-death-barrier")
    handoff = stable_id("lost-response-source-death-handoff")
    admin = secrets.token_hex(32)
    guest = secrets.token_hex(32)
    database = case / "provider" / "state.sqlite"
    socket_path = sockets.allocate()
    create_provider(
        host_binary,
        database,
        session=session,
        admin_capability=admin,
        guest_capability=guest,
        epoch=1,
        imports=imports,
        cwd=case,
    )
    with Provider(host_binary, database, socket_path, admin, case) as provider:
        seed_source(
            runtime,
            case_root=case,
            cwd=case,
            environment=guest_environment(
                socket_path,
                session=session,
                owner=owner,
                client=seed_client,
                guest_capability=guest,
                epoch=1,
            ),
        )
        predicate = CONTRACT.cell_plan(DATABASE_PATH, "lost-response")["predicate"]
        proxy = sockets.allocate()
        holder: dict[str, AotProcess] = {}
        with LostResponseRelay(proxy, socket_path, provider) as relay:

            def start_segment() -> None:
                holder["process"] = runtime.start(
                    case_root=case,
                    cwd=case,
                    environment=guest_environment(
                        socket_path,
                        session=session,
                        owner=owner,
                        client=client,
                        guest_capability=guest,
                        epoch=1,
                    ),
                    label="source-death",
                    script_path=TRANSACTION_GUEST_PATH,
                    socket_override=proxy,
                )

            barrier = CONTRACT.execute_lost_response_trigger(
                provider.adapter(),
                token=token,
                predicate=predicate,
                start_injected_segment=start_segment,
                progress_guard=process_progress_guard(
                    holder, "source-death stock SQLite"
                ),
                timeout_seconds=CHECKPOINT_TIMEOUT_SECONDS,
            )
            relay.wait_for_drop()
            holder["process"].kill()
            triggered = CONTRACT.status_projection(provider.status())
            if triggered["barrier"] != "triggered":
                raise MatrixFailure("source death did not retain incomplete delivery state")
            attempt = provider.control_raw("freeze", token, handoff, "2")
            if attempt.returncode == 0:
                raise MatrixFailure("migration was accepted after pre-completion source death")
            diagnostic = (attempt.stdout + attempt.stderr).decode(
                "utf-8", errors="replace"
            )
            if "freeze transition rejected" not in diagnostic:
                raise MatrixFailure("source-death migration failed outside the drain gate")
            trace_path = case / "migration-rejection.json"
            write_new(
                trace_path,
                canonical_bytes(
                    {
                        "schema": "visa-sqlite-pre-completion-source-death-v1",
                        "barrier": barrier,
                        "relay": relay.trace(),
                        "triggered_status": triggered,
                        "migration_attempt_exit_status": attempt.returncode,
                        "migration_attempt_stdout_sha256": hashlib.sha256(
                            attempt.stdout
                        ).hexdigest(),
                        "migration_attempt_stderr_sha256": hashlib.sha256(
                            attempt.stderr
                        ).hexdigest(),
                        "rejected_by": "incomplete-delivery-drain-gate",
                    }
                )
                + b"\n",
            )
    return {
        "triggered_status": triggered,
        "migration_attempt_trace": CONTRACT.file_identity(trace_path),
        "migration_attempt_exit_status": attempt.returncode,
        "rejected_by": "incomplete-delivery-drain-gate",
    }


def seal_migration_binding(
    *,
    bind_binary: Path,
    binding_root: Path,
    session: str,
    owner: str,
    handoff: str,
    checkpoint_barrier: str,
    source_client: str,
    source_restore_client: str,
    destination_client: str,
    build_receipt: Mapping[str, object],
    runtime_sha256: str,
    source_lock_sha256: str,
) -> str:
    ensure_private_directory(binding_root / "artifacts")
    ensure_private_directory(binding_root / "proofs")
    intent_path = binding_root / "intent.json"
    write_intent(
        intent_path,
        session=session,
        owner=owner,
        handoff=handoff,
        checkpoint_barrier=checkpoint_barrier,
        source_client=source_client,
        source_restore_client=source_restore_client,
        destination_client=destination_client,
        build_receipt=build_receipt,
        runtime_sha256=runtime_sha256,
        source_lock_sha256=source_lock_sha256,
    )
    sealed = require_success(
        bind_command(
            bind_binary,
            "seal",
            binding_root,
            "intent.json",
            "migration-manifest.json",
        ),
        "migration manifest sealing",
    )
    manifest_sha256 = sealed.stdout.decode("utf-8", errors="strict").strip()
    hex_identity(manifest_sha256, 32, "migration manifest")
    verified = require_success(
        bind_command(
            bind_binary, "verify", binding_root, "migration-manifest.json"
        ),
        "migration manifest verification",
    )
    if verified.stdout.decode("utf-8", errors="strict").strip() != manifest_sha256:
        raise MatrixFailure("migration manifest verification returned a different digest")
    return manifest_sha256


def bind_authority_proofs(
    *,
    bind_binary: Path,
    binding_root: Path,
    session: str,
    handoff: str,
    manifest_sha256: str,
) -> tuple[str, str]:
    commit_receipt = {
        "action": "trusted-local-commit-projection",
        "destination_epoch": 2,
        "handoff_hex": handoff,
        "migration_manifest_sha256": manifest_sha256,
        "session_hex": session,
    }
    fence_receipt = {
        "action": "trusted-local-fence-authorization",
        "destination_epoch": 2,
        "handoff_hex": handoff,
        "migration_manifest_sha256": manifest_sha256,
        "session_hex": session,
    }
    write_new(
        binding_root / "proofs" / "commit.receipt",
        canonical_bytes(commit_receipt),
    )
    write_new(
        binding_root / "proofs" / "fence.receipt",
        canonical_bytes(fence_receipt),
    )
    bound = require_success(
        bind_command(
            bind_binary,
            "bind-proofs",
            binding_root,
            "migration-manifest.json",
            "proofs/commit.receipt",
            "proofs/fence.receipt",
            "proofs/commit.json",
            "proofs/fence.json",
        ),
        "authority proof binding",
    )
    digests = bound.stdout.decode("utf-8", errors="strict").strip().split()
    if len(digests) != 2:
        raise MatrixFailure("authority proof binder returned the wrong digest count")
    for index, digest in enumerate(digests):
        hex_identity(digest, 32, ("commit", "fence")[index] + " proof")
    require_success(
        bind_command(
            bind_binary,
            "verify-proofs",
            binding_root,
            "migration-manifest.json",
            "proofs/commit.json",
            "proofs/fence.json",
        ),
        "authority proof verification",
    )
    return digests[0], digests[1]


def run_destination_continuation(
    runtime: DockerAot,
    *,
    case_root: Path,
    destination: Path,
    provider: Provider,
    environment: Mapping[str, str],
    checkpoint: Path,
    script_path: str,
    continuation: Mapping[str, object] | None,
    cell_id: str,
) -> tuple[AotProcess, dict[str, object] | None]:
    holder: dict[str, AotProcess] = {}

    def start_segment() -> None:
        holder["process"] = runtime.start(
            case_root=case_root,
            cwd=destination,
            environment=environment,
            label="destination",
            script_path=script_path,
            checkpoint=checkpoint,
        )

    try:
        if continuation is None:
            start_segment()
            witness = None
        else:
            witness = CONTRACT.execute_continue_witness(
                provider.adapter(),
                token=stable_id(cell_id + "-continuation-barrier"),
                predicate=continuation,
                start_segment=start_segment,
                progress_guard=process_progress_guard(
                    holder, "restored stock SQLite"
                ),
                timeout_seconds=CHECKPOINT_TIMEOUT_SECONDS,
            )
        process = holder["process"]
        process.wait()
    except BaseException:
        if "process" in holder:
            holder["process"].kill()
        raise
    return process, witness


def snapshot_namespace(
    runtime: DockerAot,
    *,
    case_root: Path,
    destination: Path,
    provider: Provider,
    environment: Mapping[str, str],
    cell_id: str,
) -> dict[str, object]:
    gate = destination / "snapshot-gate"
    ensure_private_directory(gate)
    holder: dict[str, AotProcess] = {}
    predicate = {
        "kind": "path-open",
        "resource": "path:" + DATABASE_PATH,
        "outcome": "success",
        "occurrence": 1,
    }

    def start_segment() -> None:
        holder["process"] = runtime.start(
            case_root=case_root,
            cwd=gate,
            environment=environment,
            label="snapshot-gate",
            script_path=CURSOR_GUEST_PATH,
        )

    def await_checkpoint() -> Path:
        process = holder["process"]
        process.wait(expect_checkpoint=True)
        return gate / "checkpoint.pb"

    try:
        CONTRACT.execute_checkpoint_cut(
            provider.adapter(),
            token=stable_id(cell_id + "-snapshot-barrier"),
            predicate=predicate,
            start_segment=start_segment,
            await_checkpoint=await_checkpoint,
            progress_guard=process_progress_guard(holder, "snapshot-gate stock SQLite"),
            timeout_seconds=CHECKPOINT_TIMEOUT_SECONDS,
        )
    except BaseException:
        if "process" in holder:
            holder["process"].kill()
        raise
    snapshot_path = destination / "namespace.snapshot"
    response = provider.control("snapshot-namespace", snapshot_path)
    snapshot = response.get("snapshot")
    if not isinstance(snapshot, dict):
        raise MatrixFailure("provider omitted the namespace snapshot receipt")
    artifact = CONTRACT.file_identity(snapshot_path)
    encoded_bytes = snapshot.get("encoded_bytes")
    if artifact["sha256"] != hex_identity(snapshot.get("sha256"), 32, "snapshot"):
        raise MatrixFailure("namespace snapshot digest differs from provider receipt")
    if artifact["size"] != encoded_bytes:
        raise MatrixFailure("namespace snapshot size differs from provider receipt")
    effects = snapshot.get("effects")
    if not isinstance(effects, int) or isinstance(effects, bool) or effects <= 0:
        raise MatrixFailure("namespace snapshot contains no durable effects")
    return {
        "artifact": artifact,
        "effect_frontier": hex_identity(
            snapshot.get("effect_frontier"), 32, "snapshot effect frontier"
        ),
        "effects": effects,
        "path": snapshot_path,
    }


def native_oracle_semantic_projection(
    report: Mapping[str, object],
) -> dict[str, object]:
    projection = report.get("semantic_projection")
    fields = {
        "schema_version",
        "logical_contents",
        "integrity_ok",
        "foreign_keys_ok",
        "schema_accepted",
        "balance",
        "transactions",
        "acknowledgements",
    }
    if not isinstance(projection, dict) or set(projection) != fields:
        raise MatrixFailure("SQLite oracle omitted its exact semantic projection")
    if projection["schema_version"] != ORACLE_PROJECTION_SCHEMA:
        raise MatrixFailure("SQLite oracle semantic projection has the wrong schema")
    logical = projection["logical_contents"]
    if not isinstance(logical, dict) or set(logical) != {
        "account_rows",
        "accounts_sha256",
        "transaction_rows",
        "transactions_sha256",
    }:
        raise MatrixFailure("SQLite oracle logical-content projection is malformed")
    if logical["account_rows"] != CURSOR_ROWS or logical["transaction_rows"] != 1:
        raise MatrixFailure("SQLite oracle observed the wrong logical row counts")
    hex_identity(logical["accounts_sha256"], 32, "SQLite account rows")
    hex_identity(logical["transactions_sha256"], 32, "SQLite transaction rows")
    if (
        projection["integrity_ok"] is not True
        or projection["foreign_keys_ok"] is not True
        or projection["schema_accepted"] is not True
    ):
        raise MatrixFailure("SQLite oracle semantic integrity invariants failed")
    if projection["balance"] != {
        "expected_total": INITIAL_TOTAL_BALANCE,
        "observed_total": INITIAL_TOTAL_BALANCE,
        "total_matches": True,
        "negative_accounts": 0,
        "all_nonnegative": True,
    }:
        raise MatrixFailure("SQLite oracle balance projection is invalid")
    if projection["transactions"] != {
        "rows": 1,
        "nonnull_txids": 1,
        "distinct_txids": 1,
        "unique_txids": True,
        "nonpositive_amounts": 0,
        "all_amounts_positive": True,
    }:
        raise MatrixFailure("SQLite oracle transaction projection is invalid")
    if projection["acknowledgements"] != {
        "expected_txids": EXPECTED_TXIDS,
        "observed_txids": EXPECTED_TXIDS,
        "missing_txids": [],
        "unexpected_txids": [],
        "exact_match": True,
    }:
        raise MatrixFailure("SQLite oracle acknowledgement projection is invalid")
    return projection


def build_equivalence_projection(
    external_oracle: Mapping[str, object],
    observation: Mapping[str, object],
) -> dict[str, object]:
    oracle_projection = external_oracle.get("semantic_projection")
    if not isinstance(oracle_projection, dict):
        raise MatrixFailure("external oracle has no semantic projection")
    logical = oracle_projection.get("logical_contents")
    acknowledgements = oracle_projection.get("acknowledgements")
    if not isinstance(logical, dict) or not isinstance(acknowledgements, dict):
        raise MatrixFailure("external oracle semantic projection is incomplete")
    if (
        observation.get("acknowledged_txids") != EXPECTED_TXIDS
        or observation.get("ack_terminal_count") != len(EXPECTED_TXIDS)
        or acknowledgements.get("observed_txids") != observation["acknowledged_txids"]
        or acknowledgements.get("exact_match") is not True
    ):
        raise MatrixFailure("raw ACK terminals differ from the native SQLite projection")
    cursor_sha256 = observation.get("cursor_rows_sha256")
    if (
        observation.get("cursor_total_rows") != CURSOR_ROWS
        or observation.get("cursor_done_count") != 1
        or cursor_sha256 != logical.get("accounts_sha256")
    ):
        raise MatrixFailure("raw cursor rows differ from the native SQLite projection")
    return {
        "schema": EQUIVALENCE_PROJECTION_SCHEMA,
        "logical_contents": dict(logical),
        "invariants": {
            "integrity_ok": oracle_projection["integrity_ok"],
            "foreign_keys_ok": oracle_projection["foreign_keys_ok"],
            "schema_accepted": oracle_projection["schema_accepted"],
            "balance": dict(oracle_projection["balance"]),
            "transactions": dict(oracle_projection["transactions"]),
        },
        "acknowledgements": {
            "txids": list(observation["acknowledged_txids"]),
            "terminal_count": observation["ack_terminal_count"],
            "oracle": dict(acknowledgements),
        },
        "cursor": {
            "rows_sha256": cursor_sha256,
            "total_rows": observation["cursor_total_rows"],
            "done_count": observation["cursor_done_count"],
        },
    }


def run_sqlite_oracle(
    *,
    oracle_binary: Path,
    snapshot: Path,
    expected_acks: Path,
    cwd: Path,
) -> dict[str, object]:
    completed = run(
        [oracle_binary, snapshot, expected_acks, DATABASE_PATH],
        cwd=cwd,
        timeout=300,
        check=False,
    )
    report_path = cwd / "sqlite-oracle-report.json"
    write_new(report_path, completed.stdout or b"{}\n")
    stderr_path = cwd / "sqlite-oracle.stderr"
    write_new(stderr_path, completed.stderr)
    try:
        report = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixFailure("SQLite oracle did not emit a JSON report") from error
    if (
        completed.returncode != 0
        or not isinstance(report, dict)
        or report.get("schema_version") != ORACLE_REPORT_SCHEMA
        or report.get("accepted") is not True
    ):
        raise MatrixFailure(
            "independent SQLite oracle rejected the migrated namespace: "
            + completed.stderr.decode("utf-8", errors="replace")[-2000:]
        )
    semantic_projection = native_oracle_semantic_projection(report)
    return {
        "program": CONTRACT.file_identity(oracle_binary),
        "report": CONTRACT.file_identity(report_path),
        "report_schema": ORACLE_REPORT_SCHEMA,
        "semantic_projection": semantic_projection,
        "exit_status": completed.returncode,
        "accepted": True,
        "_report_path": report_path,
    }


def run_uninterrupted_control(
    *,
    root: Path,
    sockets: ShortSocketRoot,
    host_binary: Path,
    oracle_binary: Path,
    runtime: DockerAot,
    workload_paths: Mapping[str, Path],
) -> dict[str, object]:
    case = root / "uninterrupted-control"
    execution = case / "execution"
    ensure_private_directory(case)
    ensure_private_directory(execution)
    imports = {
        SEED_GUEST_PATH: workload_paths["seed"],
        TRANSACTION_GUEST_PATH: workload_paths["transaction"],
        CURSOR_GUEST_PATH: workload_paths["cursor"],
    }
    session = stable_id("uninterrupted-control-session")
    owner = stable_id("uninterrupted-control-owner")
    seed_client = stable_id("uninterrupted-control-seed-client")
    transaction_client = stable_id("uninterrupted-control-transaction-client")
    cursor_client = stable_id("uninterrupted-control-cursor-client")
    snapshot_client = stable_id("uninterrupted-control-snapshot-client")
    admin = secrets.token_hex(32)
    guest = secrets.token_hex(32)
    database = execution / "provider" / "state.sqlite"
    socket_path = sockets.allocate()
    create_provider(
        host_binary,
        database,
        session=session,
        admin_capability=admin,
        guest_capability=guest,
        epoch=1,
        imports=imports,
        cwd=execution,
    )
    with Provider(host_binary, database, socket_path, admin, execution) as provider:
        seed_source(
            runtime,
            case_root=case,
            cwd=execution,
            environment=guest_environment(
                socket_path,
                session=session,
                owner=owner,
                client=seed_client,
                guest_capability=guest,
                epoch=1,
            ),
        )
        transaction = run_script(
            runtime,
            case_root=case,
            cwd=execution,
            environment=guest_environment(
                socket_path,
                session=session,
                owner=owner,
                client=transaction_client,
                guest_capability=guest,
                epoch=1,
            ),
            label="uninterrupted-transaction",
            script_path=TRANSACTION_GUEST_PATH,
        )
        cursor = run_script(
            runtime,
            case_root=case,
            cwd=execution,
            environment=guest_environment(
                socket_path,
                session=session,
                owner=owner,
                client=cursor_client,
                guest_capability=guest,
                epoch=1,
            ),
            label="uninterrupted-cursor",
            script_path=CURSOR_GUEST_PATH,
        )
        observation, txids = strict_stdout_observation(
            transcript=case / "raw-client.stdout",
            components=[transaction.stdout_path, cursor.stdout_path],
            source_cursor_stdout=None,
            expect_cursor=True,
        )
        application_runs = (
            completed_application_run("transaction", transaction),
            completed_application_run("cursor", cursor),
        )
        expected_path = case / "expected-acks.json"
        expected_identity = write_expected_acks(expected_path, txids)
        namespace = snapshot_namespace(
            runtime,
            case_root=case,
            destination=execution,
            provider=provider,
            environment=guest_environment(
                socket_path,
                session=session,
                owner=owner,
                client=snapshot_client,
                guest_capability=guest,
                epoch=1,
            ),
            cell_id="uninterrupted-control",
        )
        snapshot_path = namespace.pop("path")
        external_oracle = run_sqlite_oracle(
            oracle_binary=oracle_binary,
            snapshot=snapshot_path,
            expected_acks=expected_path,
            cwd=execution,
        )
        oracle_report_path = external_oracle.pop("_report_path")
        timing_path = case / "application-timing.json"
        write_application_timing(
            timing_path,
            [timing_phase("transaction", transaction), timing_phase("cursor", cursor)],
        )
    return {
        "schema": CONTROL_SCHEMA,
        "execution": "single-provider-uninterrupted-transaction-and-readback",
        "namespace_snapshot": namespace,
        "external_oracle": external_oracle,
        "expected_acknowledgements": expected_identity,
        "raw_client_observation": observation,
        "equivalence_projection": build_equivalence_projection(
            external_oracle, observation
        ),
        "_raw_paths": {
            "application_runs": application_runs,
            "client_stdout": case / "raw-client.stdout",
            "expected_acknowledgements": expected_path,
            "namespace_snapshot": snapshot_path,
            "oracle_report": oracle_report_path,
            "application_timing": timing_path,
        },
    }


def run_matrix_cell(
    *,
    root: Path,
    sockets: ShortSocketRoot,
    spec: Any,
    plan_entry: Mapping[str, object],
    host_binary: Path,
    bind_binary: Path,
    oracle_binary: Path,
    runtime: DockerAot,
    build_receipt: Mapping[str, object],
    inputs: Mapping[str, object],
    workload_paths: Mapping[str, Path],
    source_lock_sha256: str,
) -> dict[str, object]:
    cell_id = str(spec.cell_id)
    cost_event("sqlite.cut.start", cell=cell_id)
    case = root / "cells" / cell_id
    source = case / "source"
    destination = case / "destination"
    binding_root = case / "binding"
    for path in (case, source, destination, binding_root):
        ensure_private_directory(path)
    imports = {
        SEED_GUEST_PATH: workload_paths["seed"],
        TRANSACTION_GUEST_PATH: workload_paths["transaction"],
        CURSOR_GUEST_PATH: workload_paths["cursor"],
    }
    session = stable_id(cell_id + "-session")
    owner = stable_id(cell_id + "-owner")
    seed_client = stable_id(cell_id + "-seed-client")
    setup_client = stable_id(cell_id + "-setup-client")
    source_client = stable_id(cell_id + "-source-client")
    source_restore_client = stable_id(cell_id + "-source-restore-client")
    destination_client = stable_id(cell_id + "-destination-client")
    projection_client = stable_id(cell_id + "-projection-client")
    snapshot_client = stable_id(cell_id + "-snapshot-client")
    token = stable_id(cell_id + "-checkpoint-barrier")
    handoff = stable_id(cell_id + "-handoff")
    source_admin = secrets.token_hex(32)
    source_guest = secrets.token_hex(32)
    destination_admin = secrets.token_hex(32)
    destination_guest = secrets.token_hex(32)
    source_database = source / "provider" / "state.sqlite"
    source_socket = sockets.allocate()
    create_provider(
        host_binary,
        source_database,
        session=session,
        admin_capability=source_admin,
        guest_capability=source_guest,
        epoch=1,
        imports=imports,
        cwd=source,
    )
    setup_process: AotProcess | None = None
    delivery_fault: dict[str, object] | None = None
    with Provider(
        host_binary,
        source_database,
        source_socket,
        source_admin,
        source,
    ) as source_provider:
        seed_source(
            runtime,
            case_root=case,
            cwd=source,
            environment=guest_environment(
                source_socket,
                session=session,
                owner=owner,
                client=seed_client,
                guest_capability=source_guest,
                epoch=1,
            ),
        )
        if cell_id == "active-read-cursor":
            setup = run_script(
                runtime,
                case_root=case,
                cwd=source,
                environment=guest_environment(
                    source_socket,
                    session=session,
                    owner=owner,
                    client=setup_client,
                    guest_capability=source_guest,
                    epoch=1,
                ),
                label="transaction-setup",
                script_path=TRANSACTION_GUEST_PATH,
            )
            setup_process = setup
        source_environment = guest_environment(
            source_socket,
            session=session,
            owner=owner,
            client=source_client,
            guest_capability=source_guest,
            epoch=1,
        )
        script_path = (
            CURSOR_GUEST_PATH
            if cell_id == "active-read-cursor"
            else TRANSACTION_GUEST_PATH
        )
        if cell_id == "lost-response":
            barrier, delivery_fault, source_process, checkpoint = (
                checkpoint_lost_response_cut(
                    runtime,
                    case_root=case,
                    source=source,
                    provider=source_provider,
                    source_database=source_database,
                    environment=source_environment,
                    token=token,
                    predicate=plan_entry["predicate"],
                    source_client=source_client,
                    proxy_socket=sockets.allocate(),
                )
            )
            delivery_fault["pre_completion_source_death"] = run_source_death_negative(
                runtime,
                root=case,
                host_binary=host_binary,
                imports=imports,
                sockets=sockets,
            )
            barrier_capture = barrier
            checkpoint_identity = CONTRACT.file_identity(checkpoint)
        else:
            capture, source_process, checkpoint = checkpoint_regular_cut(
                runtime,
                case_root=case,
                source=source,
                provider=source_provider,
                environment=source_environment,
                token=token,
                predicate=plan_entry["predicate"],
                script_path=script_path,
            )
            barrier_capture = capture["barrier"]
            checkpoint_identity = capture["compute_checkpoint"]

        source_provider.control("freeze", token, handoff, "2")
        cost_event("sqlite.cut.source_frozen", cell=cell_id)
        source_frozen = CONTRACT.status_projection(source_provider.status())
        # The stock-application baseline needs a source-side raw namespace
        # control at the same compute cut.  Keep this opt-in and outside the
        # formal receipt: it is an experimental negative-control input, not a
        # new SQLite claim or a producer-generated verdict.
        if os.environ.get("VISA_BASELINE_SOURCE_CONTROLS") == "1":
            source_snapshot_path = source / "source-namespace.snapshot"
            source_provider.control("snapshot-namespace", source_snapshot_path)
        source_provider.control("export", binding_root / "capsule")
        copy_regular(runtime.executable, binding_root / "artifacts" / "application.aot")
        copy_regular(checkpoint, binding_root / "artifacts" / "checkpoint.pb")
        manifest_sha256 = seal_migration_binding(
            bind_binary=bind_binary,
            binding_root=binding_root,
            session=session,
            owner=owner,
            handoff=handoff,
            checkpoint_barrier=token,
            source_client=source_client,
            source_restore_client=source_restore_client,
            destination_client=destination_client,
            build_receipt=build_receipt,
            runtime_sha256=str(build_receipt["wanco_runtime_sha256"]),
            source_lock_sha256=source_lock_sha256,
        )
        destination_database = destination / "provider" / "state.sqlite"
        restore_provider(
            host_binary,
            binding_root / "capsule",
            destination_database,
            destination_admin,
            destination_guest,
            destination,
        )
        cost_event("sqlite.cut.destination_prepared", cell=cell_id)
        destination_socket = sockets.allocate()
        with Provider(
            host_binary,
            destination_database,
            destination_socket,
            destination_admin,
            destination,
        ) as destination_provider:
            destination_prepared = CONTRACT.status_projection(
                destination_provider.status()
            )
            commit_digest, fence_digest = bind_authority_proofs(
                bind_binary=bind_binary,
                binding_root=binding_root,
                session=session,
                handoff=handoff,
                manifest_sha256=manifest_sha256,
            )
            source_provider.control("fence", handoff, "2")
            cost_event("sqlite.cut.source_fenced", cell=cell_id)
            source_fenced = CONTRACT.status_projection(source_provider.status())
            destination_provider.control("activate", handoff, "2")
            cost_event("sqlite.cut.destination_activated", cell=cell_id)
            destination_active = CONTRACT.status_projection(
                destination_provider.status()
            )
            require_success(
                bind_command(
                    bind_binary,
                    "verify-proofs",
                    binding_root,
                    "migration-manifest.json",
                    "proofs/commit.json",
                    "proofs/fence.json",
                ),
                "pre-execution migration proof verification",
            )
            binding_report = binding_root / "binding-report.json"
            write_new(
                binding_report,
                canonical_bytes(
                    {
                        "schema": "visa-sqlite-migration-binding-v1",
                        "manifest_sha256": manifest_sha256,
                        "commit_proof_sha256": commit_digest,
                        "fence_proof_sha256": fence_digest,
                    }
                )
                + b"\n",
            )
            bound_runtime = DockerAot(
                runtime.docker,
                runtime.image,
                binding_root / "artifacts" / "application.aot",
                socket_root=runtime.socket_root,
            )
            destination_process, continuation_witness = run_destination_continuation(
                bound_runtime,
                case_root=case,
                destination=destination,
                provider=destination_provider,
                environment=guest_environment(
                    destination_socket,
                    session=session,
                    owner=owner,
                    client=destination_client,
                    guest_capability=destination_guest,
                    epoch=2,
                ),
                checkpoint=binding_root / "artifacts" / "checkpoint.pb",
                script_path=script_path,
                continuation=plan_entry.get("continuation_witness"),
                cell_id=cell_id,
            )
            cost_event("sqlite.cut.destination_complete", cell=cell_id)
            application_runs: list[tuple[str, Path, Path, int]] = [
                completed_application_run("source", source_process),
                completed_application_run("destination", destination_process),
            ]
            timing_processes: list[tuple[str, AotProcess]] = [
                ("source", source_process),
                ("destination", destination_process),
            ]
            source_cursor_stdout: Path | None = None
            if setup_process is not None:
                application_runs.insert(
                    0, completed_application_run("transaction-setup", setup_process)
                )
                timing_processes.insert(0, ("transaction-setup", setup_process))
                source_cursor_stdout = source_process.stdout_path
            else:
                readback = run_script(
                    bound_runtime,
                    case_root=case,
                    cwd=destination,
                    environment=guest_environment(
                        destination_socket,
                        session=session,
                        owner=owner,
                        client=projection_client,
                        guest_capability=destination_guest,
                        epoch=2,
                    ),
                    label="post-handoff-readback",
                    script_path=CURSOR_GUEST_PATH,
                )
                application_runs.append(
                    completed_application_run("readback", readback)
                )
                timing_processes.append(("readback", readback))
            components = [entry[1] for entry in application_runs]
            observation, txids = strict_stdout_observation(
                transcript=case / "raw-client.stdout",
                components=components,
                source_cursor_stdout=source_cursor_stdout,
                expect_cursor=True,
            )
            expected_path = case / "expected-acks.json"
            expected_identity = write_expected_acks(expected_path, txids)
            namespace = snapshot_namespace(
                bound_runtime,
                case_root=case,
                destination=destination,
                provider=destination_provider,
                environment=guest_environment(
                    destination_socket,
                    session=session,
                    owner=owner,
                    client=snapshot_client,
                    guest_capability=destination_guest,
                    epoch=2,
                ),
                cell_id=cell_id,
            )
            snapshot_path = namespace.pop("path")
            external_oracle = run_sqlite_oracle(
                oracle_binary=oracle_binary,
                snapshot=snapshot_path,
                expected_acks=expected_path,
                cwd=destination,
            )
            cost_event("sqlite.cut.oracle_complete", cell=cell_id)
            oracle_report_path = external_oracle.pop("_report_path")
            timing_path = case / "application-timing.json"
            write_application_timing(
                timing_path,
                [timing_phase(role, process) for role, process in timing_processes],
            )

    cell: dict[str, object] = {
        "schema": CONTRACT.CELL_SCHEMA,
        "cell_id": cell_id,
        "plan_entry_sha256": CONTRACT.canonical_sha256(plan_entry),
        "barrier": barrier_capture,
        "compute_checkpoint": checkpoint_identity,
        "handoff": {
            "source_frozen": source_frozen,
            "destination_prepared": destination_prepared,
            "source_fenced": source_fenced,
            "destination_active": destination_active,
            "source_client": source_client,
            "destination_client": destination_client,
        },
        "namespace_snapshot": namespace,
        "external_oracle": external_oracle,
        "expected_acknowledgements": expected_identity,
        "raw_client_observation": observation,
        "equivalence_projection": build_equivalence_projection(
            external_oracle, observation
        ),
        "_raw_paths": {
            "application_runs": tuple(application_runs),
            "client_stdout": case / "raw-client.stdout",
            "expected_acknowledgements": expected_path,
            "namespace_snapshot": snapshot_path,
            "oracle_report": oracle_report_path,
            "application_timing": timing_path,
        },
    }
    if continuation_witness is not None:
        cell["continuation_witness"] = continuation_witness
    if spec.external_anchor is not None:
        anchor: dict[str, object] = {
            "kind": spec.external_anchor,
            "observation": observation["stdout"],
        }
        if cell_id == "active-read-cursor":
            anchor["observed_prefix_rows"] = observation["cursor_prefix_rows"]
        cell["external_anchor"] = anchor
    if delivery_fault is not None:
        cell["delivery_fault"] = delivery_fault
    return cell


def qualify_source_abort_reconciliation(
    *,
    root: Path,
    sockets: ShortSocketRoot,
    host_binary: Path,
    driver_binary: Path,
    oracle_binary: Path,
    runtime: DockerAot,
    build_receipt: Mapping[str, object],
    workload_paths: Mapping[str, Path],
    source_lock_sha256: str,
) -> dict[str, object]:
    case = root / "source-abort-real-driver"
    ensure_private_directory(case)
    binding_root = case / "binding"
    ensure_private_directory(binding_root)
    driver_root = case / "driver"
    ensure_private_directory(driver_root)
    imports = {
        SEED_GUEST_PATH: workload_paths["seed"],
        TRANSACTION_GUEST_PATH: workload_paths["transaction"],
        CURSOR_GUEST_PATH: workload_paths["cursor"],
    }
    session = stable_id("source-abort-session")
    owner = stable_id("source-abort-owner")
    seed_client = stable_id("source-abort-seed-client")
    source_client = stable_id("source-abort-source-client")
    source_restore_client = stable_id("source-abort-source-restore-client")
    destination_client = stable_id("source-abort-unused-destination-client")
    readback_client = stable_id("source-abort-readback-client")
    snapshot_client = stable_id("source-abort-snapshot-client")
    token = stable_id("source-abort-barrier")
    handoff = stable_id("source-abort-handoff")
    admin = secrets.token_hex(32)
    guest = secrets.token_hex(32)
    database = case / "provider" / "state.sqlite"
    socket_path = sockets.allocate()
    record_path = driver_root / "record.json"
    adapter_binding_path = Path(os.fspath(record_path) + ".adapter-binding.json")
    if sockets.configuration_path is None:
        raise MatrixFailure("short-lived private configuration root is unavailable")
    adapter_path = sockets.configuration_path / f"adapter-{secrets.token_hex(8)}.json"
    authority_state_path = sockets.configuration_path / f"authority-{secrets.token_hex(8)}.json"
    authority_probe_adapter_path = (
        sockets.configuration_path / f"adapter-probe-{secrets.token_hex(8)}.json"
    )
    authority_probe_state_path = (
        sockets.configuration_path / f"authority-probe-{secrets.token_hex(8)}.json"
    )
    supervisor_spec_path = sockets.configuration_path / f"wanco-{secrets.token_hex(8)}.json"
    supervisor_lock_path = sockets.configuration_path / f"wanco-{secrets.token_hex(8)}.lock"
    authority_snapshot_path = driver_root / "authority-state.json"
    authority_probe_snapshot_path = driver_root / "authority-committed-probe.json"
    source_retained_receipt_path = binding_root / "authority" / "source-retained.json"
    source_retained_receipt_semantic_path = "authority/source-retained.json"
    supervisor_started_path = driver_root / "source-restore-started.json"
    crash_marker_path = driver_root / "crash-marker.json"
    create_provider(
        host_binary,
        database,
        session=session,
        admin_capability=admin,
        guest_capability=guest,
        epoch=1,
        imports=imports,
        cwd=case,
    )
    with Provider(host_binary, database, socket_path, admin, case) as provider:
        seed_source(
            runtime,
            case_root=case,
            cwd=case,
            environment=guest_environment(
                socket_path,
                session=session,
                owner=owner,
                client=seed_client,
                guest_capability=guest,
                epoch=1,
            ),
        )
        plan_entry = CONTRACT.cell_plan(DATABASE_PATH, "partial-journal")
        capture, source_process, checkpoint = checkpoint_regular_cut(
            runtime,
            case_root=case,
            source=case,
            provider=provider,
            environment=guest_environment(
                socket_path,
                session=session,
                owner=owner,
                client=source_client,
                guest_capability=guest,
                epoch=1,
            ),
            token=token,
            predicate=plan_entry["predicate"],
            script_path=TRANSACTION_GUEST_PATH,
        )
        copy_regular(runtime.executable, binding_root / "artifacts" / "application.aot")
        copy_regular(checkpoint, binding_root / "artifacts" / "checkpoint.pb")
        intent_path = binding_root / "intent.json"
        write_intent(
            intent_path,
            session=session,
            owner=owner,
            handoff=handoff,
            checkpoint_barrier=token,
            source_client=source_client,
            source_restore_client=source_restore_client,
            destination_client=destination_client,
            build_receipt=build_receipt,
            runtime_sha256=str(build_receipt["wanco_runtime_sha256"]),
            source_lock_sha256=source_lock_sha256,
        )
        bound_runtime = DockerAot(
            runtime.docker,
            runtime.image,
            binding_root / "artifacts" / "application.aot",
            socket_root=runtime.socket_root,
        )
        container_name, restore_argv = bound_runtime.build_command(
            case_root=case,
            environment=guest_environment(
                socket_path,
                session=session,
                owner=owner,
                client=source_restore_client,
                guest_capability=guest,
                epoch=1,
            ),
            cwd=case,
            label="source-restore",
            checkpoint=binding_root / "artifacts" / "checkpoint.pb",
            script_path=TRANSACTION_GUEST_PATH,
        )
        checkpoint_argument = bound_runtime.container_path(
            binding_root / "artifacts" / "checkpoint.pb", case
        )
        source_exit_path = driver_root / "source-exit.json"
        write_new(
            source_exit_path,
            canonical_bytes(
                {
                    "schema": "visa-wanco-source-exit-v1",
                    "exit_status": 0,
                    "checkpoint": CONTRACT.file_identity(
                        binding_root / "artifacts" / "checkpoint.pb"
                    ),
                }
            )
            + b"\n",
        )
        adapter_document = {
            "schema": REAL_MIGRATION_ADAPTER_SCHEMA,
            "canonical_authority": {
                "state": os.fspath(authority_state_path),
                "source_retained_receipt": source_retained_receipt_semantic_path,
            },
            "source_provider": {
                "socket": os.fspath(socket_path),
                "admin_capability_hex": admin,
            },
            "destination_provider": None,
            "source_exit_receipt": os.fspath(source_exit_path),
            "source_restore": {
                "argv": restore_argv,
                "cwd": os.fspath(case),
                "stdout": os.fspath(case / "source-restore.stdout"),
                "stderr": os.fspath(case / "source-restore.stderr"),
                "completion_receipt": os.fspath(
                    driver_root / "source-restore-completion.json"
                ),
                "supervisor_binary": os.fspath(driver_binary),
                "supervisor_spec": os.fspath(supervisor_spec_path),
                "supervisor_started_receipt": os.fspath(supervisor_started_path),
                "supervisor_lock": os.fspath(supervisor_lock_path),
                "application_argument": f"/aot/{bound_runtime.executable.name}",
                "checkpoint_argument": checkpoint_argument,
                "client_hex": source_restore_client,
                "authority_epoch": 1,
                "timeout_seconds": PROCESS_TIMEOUT_SECONDS,
                "cleanup_argv": [
                    os.fspath(driver_binary),
                    "cleanup-docker-container",
                    runtime.docker,
                    container_name,
                ],
            },
            "destination_restore": None,
        }
        adapter_bytes = canonical_bytes(adapter_document) + b"\n"
        write_new(adapter_path, adapter_bytes)
        adapter_sha256 = hashlib.sha256(adapter_bytes).hexdigest()

        init = run(
            [
                driver_binary,
                "init-precommit",
                binding_root,
                intent_path,
                record_path,
                adapter_path,
            ],
            cwd=case,
            timeout=PROCESS_TIMEOUT_SECONDS,
            check=False,
        )
        init_stdout = driver_root / "init.stdout"
        init_stderr = driver_root / "init.stderr"
        write_new(init_stdout, init.stdout)
        write_new(init_stderr, init.stderr)
        if init.returncode != 0:
            raise MatrixFailure(
                "real migration driver failed before pre-commit abort: "
                + init.stderr.decode("utf-8", errors="replace")[-3000:]
            )
        initialized_record = read_json(record_path, "initialized driver record")
        if (
            initialized_record.get("phase") != "manifest_sealed"
            or initialized_record.get("pending_action") is not None
        ):
            raise MatrixFailure("real migration driver did not seal a clean pre-commit record")
        initialized_manifest = require_object(
            initialized_record.get("migration_manifest"), "initialized migration manifest"
        )
        manifest_sha256 = hashlib.sha256(
            canonical_bytes(initialized_manifest)
        ).hexdigest()
        adapter_binding = read_json(adapter_binding_path, "migration adapter binding")
        if (
            adapter_binding.get("schema") != ADAPTER_BINDING_SCHEMA
            or require_object(adapter_binding.get("adapter"), "bound migration adapter")
            != CONTRACT.file_identity(adapter_path)
        ):
            raise MatrixFailure("migration driver did not bind its adapter configuration")
        manifest_binding = {
            "migration_manifest_sha256": manifest_sha256,
            "session_hex": initialized_manifest["session_hex"],
            "stable_owner_hex": initialized_manifest["stable_owner_hex"],
            "handoff_hex": initialized_manifest["handoff_hex"],
            "source_epoch": initialized_manifest["source_epoch"],
            "destination_epoch": initialized_manifest["destination_epoch"],
        }
        source_retained_receipt_document = {
            "schema": SOURCE_RETAINED_RECEIPT_SCHEMA,
            "decision": "source_retained",
            **manifest_binding,
        }
        write_new(
            source_retained_receipt_path,
            canonical_bytes(source_retained_receipt_document) + b"\n",
        )
        source_retained_receipt_identity = CONTRACT.file_identity(
            source_retained_receipt_path
        )
        source_retained_proof = {
            "schema": SOURCE_RETAINED_PROOF_SCHEMA,
            **manifest_binding,
            "canonical_receipt": {
                "semantic_path": source_retained_receipt_semantic_path,
                **source_retained_receipt_identity,
            },
        }
        authority_init = run(
            [
                driver_binary,
                "authority-init",
                binding_root,
                record_path,
                adapter_path,
            ],
            cwd=case,
            timeout=PROCESS_TIMEOUT_SECONDS,
            check=False,
        )
        authority_init_stdout = driver_root / "authority-init.stdout"
        authority_init_stderr = driver_root / "authority-init.stderr"
        write_new(authority_init_stdout, authority_init.stdout)
        write_new(authority_init_stderr, authority_init.stderr)
        if authority_init.returncode != 0:
            raise MatrixFailure(
                "canonical authority initialization failed: "
                + authority_init.stderr.decode("utf-8", errors="replace")[-3000:]
            )
        initial_authority = read_canonical_json(
            authority_state_path, "initialized canonical authority"
        )
        if initial_authority != {
            "schema": CANONICAL_AUTHORITY_STATE_SCHEMA,
            "generation": 1,
            "migration_manifest_sha256": manifest_sha256,
            "decision": "uncommitted",
            "source_retained_proof": None,
            "ownership_commit_proof": None,
            "source_fence_proof": None,
        }:
            raise MatrixFailure("canonical authority did not initialize once as uncommitted")

        authority_commit_receipt_path = binding_root / "authority" / "commit.json"
        authority_commit_receipt_document = {
            "schema": "visa-wasi-authority-commit-receipt-v1",
            "migration_manifest_sha256": manifest_sha256,
        }
        write_new(
            authority_commit_receipt_path,
            canonical_bytes(authority_commit_receipt_document) + b"\n",
        )
        commit_receipt_identity = CONTRACT.file_identity(authority_commit_receipt_path)
        commit_proof = {
            "schema": "visa-canonical-ownership-commit-proof-v1",
            **manifest_binding,
            "canonical_receipt": {
                "semantic_path": "authority/commit.json",
                **commit_receipt_identity,
            },
        }
        authority_commit_proof_path = driver_root / "authority-commit-proof.json"
        write_new(authority_commit_proof_path, canonical_bytes(commit_proof) + b"\n")

        authority_probe_record = driver_root / "authority-probe-record.json"
        authority_probe_binding = Path(
            os.fspath(authority_probe_record) + ".adapter-binding.json"
        )
        write_new(authority_probe_record, record_path.read_bytes())
        authority_probe_record.chmod(0o600)
        authority_probe_adapter_document = {
            **adapter_document,
            "canonical_authority": {
                "state": os.fspath(authority_probe_state_path),
                "source_retained_receipt": source_retained_receipt_semantic_path,
            },
        }
        authority_probe_adapter_bytes = (
            canonical_bytes(authority_probe_adapter_document) + b"\n"
        )
        write_new(authority_probe_adapter_path, authority_probe_adapter_bytes)
        authority_probe_adapter_sha256 = hashlib.sha256(
            authority_probe_adapter_bytes
        ).hexdigest()
        authority_probe_init = run(
            [
                driver_binary,
                "authority-init",
                binding_root,
                authority_probe_record,
                authority_probe_adapter_path,
            ],
            cwd=case,
            timeout=PROCESS_TIMEOUT_SECONDS,
            check=False,
        )
        authority_probe_init_stdout = driver_root / "authority-probe-init.stdout"
        authority_probe_init_stderr = driver_root / "authority-probe-init.stderr"
        write_new(
            authority_probe_init_stdout,
            authority_probe_init.stdout,
        )
        write_new(
            authority_probe_init_stderr,
            authority_probe_init.stderr,
        )
        if authority_probe_init.returncode != 0:
            raise MatrixFailure(
                "commit-probe authority initialization failed: "
                + authority_probe_init.stderr.decode("utf-8", errors="replace")[-3000:]
            )
        authority_probe_binding_document = read_canonical_json(
            authority_probe_binding, "commit-probe adapter binding"
        )
        if authority_probe_binding_document != {
            "schema": ADAPTER_BINDING_SCHEMA,
            "adapter": CONTRACT.file_identity(authority_probe_adapter_path),
        }:
            raise MatrixFailure("commit probe did not bind its independent adapter")
        authority_probe_commit = run(
            [
                driver_binary,
                "authority-commit",
                binding_root,
                authority_probe_record,
                authority_probe_adapter_path,
                authority_commit_proof_path,
            ],
            cwd=case,
            timeout=PROCESS_TIMEOUT_SECONDS,
            check=False,
        )
        authority_probe_commit_stdout = driver_root / "authority-probe-commit.stdout"
        authority_probe_commit_stderr = driver_root / "authority-probe-commit.stderr"
        write_new(
            authority_probe_commit_stdout,
            authority_probe_commit.stdout,
        )
        write_new(
            authority_probe_commit_stderr,
            authority_probe_commit.stderr,
        )
        if authority_probe_commit.returncode != 0:
            raise MatrixFailure(
                "commit-probe terminal authority CAS failed: "
                + authority_probe_commit.stderr.decode("utf-8", errors="replace")[-3000:]
            )
        committed_authority = read_canonical_json(
            authority_probe_state_path, "committed probe authority"
        )
        if committed_authority != {
            "schema": CANONICAL_AUTHORITY_STATE_SCHEMA,
            "generation": 2,
            "migration_manifest_sha256": manifest_sha256,
            "decision": "ownership_committed",
            "source_retained_proof": None,
            "ownership_commit_proof": commit_proof,
            "source_fence_proof": None,
        }:
            raise MatrixFailure("commit probe did not retain the expected terminal authority")
        write_new(
            authority_probe_snapshot_path,
            canonical_bytes(committed_authority) + b"\n",
        )
        authority_probe = run(
            [
                driver_binary,
                "recover-abort",
                binding_root,
                authority_probe_record,
                authority_probe_adapter_path,
            ],
            cwd=case,
            timeout=PROCESS_TIMEOUT_SECONDS,
            check=False,
        )
        authority_probe_stdout = driver_root / "authority-probe.stdout"
        authority_probe_stderr = driver_root / "authority-probe.stderr"
        write_new(authority_probe_stdout, authority_probe.stdout)
        write_new(authority_probe_stderr, authority_probe.stderr)
        if authority_probe.returncode == 0:
            raise MatrixFailure("canonical ownership commit did not block source abort")
        frozen = CONTRACT.status_projection(provider.status())
        if frozen["mode"] != "frozen":
            raise MatrixFailure("canonical commit probe changed the frozen source provider")

        injected = run(
            [
                driver_binary,
                "recover-abort",
                binding_root,
                record_path,
                adapter_path,
                "--inject-exit-after-provider-resume",
                crash_marker_path,
            ],
            cwd=case,
            timeout=PROCESS_TIMEOUT_SECONDS,
            check=False,
        )
        injected_stdout = driver_root / "injected.stdout"
        injected_stderr = driver_root / "injected.stderr"
        write_new(injected_stdout, injected.stdout)
        write_new(injected_stderr, injected.stderr)
        if injected.returncode != 75:
            raise MatrixFailure(
                "coordinator did not die at the injected provider-resume boundary: "
                + injected.stderr.decode("utf-8", errors="replace")[-3000:]
            )
        crash_marker = read_json(crash_marker_path, "coordinator crash marker")
        pending_record = read_json(record_path, "pending driver record")
        if (
            crash_marker.get("schema") != "visa-wasi-coordinator-crash-marker-v1"
            or crash_marker.get("injected_after") != "resume_source_provider"
            or crash_marker.get("session_hex") != session
            or crash_marker.get("authority_epoch") != 1
            or pending_record.get("phase") != "source_retained"
            or pending_record.get("pending_action") != "resume_source_provider"
            or pending_record.get("source_retained_proof") != source_retained_proof
        ):
            raise MatrixFailure("coordinator death did not retain the exact pending action")
        pending_record_path = driver_root / "pending-record.json"
        write_new(pending_record_path, record_path.read_bytes())
        resumed = CONTRACT.status_projection(provider.status())
        if (
            resumed["mode"] != "active"
            or resumed["barrier"] != "open"
            or resumed["authority_epoch"] != 1
        ):
            raise MatrixFailure("source provider was not restored before coordinator death")

        recovered_start_ns = time.monotonic_ns()
        recovered = run(
            [
                driver_binary,
                "recover-abort",
                binding_root,
                record_path,
                adapter_path,
            ],
            cwd=case,
            timeout=PROCESS_TIMEOUT_SECONDS,
            check=False,
        )
        recovered_end_ns = time.monotonic_ns()
        recovered_stdout = driver_root / "recovered.stdout"
        recovered_stderr = driver_root / "recovered.stderr"
        write_new(recovered_stdout, recovered.stdout)
        write_new(recovered_stderr, recovered.stderr)
        if recovered.returncode != 0:
            raise MatrixFailure(
                "migration driver recovery did not restore source compute: "
                + recovered.stderr.decode("utf-8", errors="replace")[-3000:]
            )
        final_record = read_json(record_path, "recovered driver record")
        if (
            final_record.get("phase") != "source_resumed"
            or final_record.get("pending_action") is not None
            or final_record.get("source_retained_proof") != source_retained_proof
            or final_record.get("ownership_commit_proof") is not None
            or final_record.get("source_fence_proof") is not None
        ):
            raise MatrixFailure(
                "recovered migration driver did not retain the source authority terminal"
            )
        completion_path = driver_root / "source-restore-completion.json"
        completion = read_json(completion_path, "Wanco restore completion")
        if (
            completion.get("schema") != "visa-wanco-restore-completion-v1"
            or completion.get("operation") != "restore_source"
            or completion.get("exit_status") != 0
        ):
            raise MatrixFailure("real Wanco restore did not publish a valid completion")
        readback = run_script(
            bound_runtime,
            case_root=case,
            cwd=case,
            environment=guest_environment(
                socket_path,
                session=session,
                owner=owner,
                client=readback_client,
                guest_capability=guest,
                epoch=1,
            ),
            label="source-abort-readback",
            script_path=CURSOR_GUEST_PATH,
        )
        final_provider = CONTRACT.status_projection(provider.status())
        observation, txids = strict_stdout_observation(
            transcript=case / "raw-client.stdout",
            components=[
                source_process.stdout_path,
                case / "source-restore.stdout",
                readback.stdout_path,
            ],
            source_cursor_stdout=None,
            expect_cursor=True,
        )
        expected_path = case / "expected-acks.json"
        expected_identity = write_expected_acks(expected_path, txids)
        namespace = snapshot_namespace(
            bound_runtime,
            case_root=case,
            destination=case,
            provider=provider,
            environment=guest_environment(
                socket_path,
                session=session,
                owner=owner,
                client=snapshot_client,
                guest_capability=guest,
                epoch=1,
            ),
            cell_id="source-abort",
        )
        snapshot_path = namespace.pop("path")
        oracle = run_sqlite_oracle(
            oracle_binary=oracle_binary,
            snapshot=snapshot_path,
            expected_acks=expected_path,
            cwd=case,
        )
        oracle_report_path = oracle.pop("_report_path")
        application_runs = (
            completed_application_run("source", source_process),
            (
                "destination",
                case / "source-restore.stdout",
                case / "source-restore.stderr",
                0,
            ),
            completed_application_run("readback", readback),
        )
        source_start_ns = source_process.start_monotonic_ns
        source_end_ns = source_process.end_monotonic_ns
        if source_end_ns is None:
            raise MatrixFailure("source-abort source timing did not finish")
        timing_path = case / "application-timing.json"
        write_application_timing(
            timing_path,
            [
                {
                    "phase": "application",
                    "role": "source",
                    "start_monotonic_ns": source_start_ns,
                    "end_monotonic_ns": source_end_ns,
                    "duration_ns": source_end_ns - source_start_ns,
                    "exit_status": 0,
                },
                {
                    "phase": "application",
                    "role": "destination",
                    "start_monotonic_ns": recovered_start_ns,
                    "end_monotonic_ns": recovered_end_ns,
                    "duration_ns": recovered_end_ns - recovered_start_ns,
                    "exit_status": recovered.returncode,
                },
                timing_phase("readback", readback),
            ],
        )
        migration_manifest = require_object(
            final_record.get("migration_manifest"), "driver migration manifest"
        )
        if canonical_bytes(migration_manifest) != canonical_bytes(initialized_manifest):
            raise MatrixFailure("migration manifest changed across coordinator restart")
        source_retained_authority = read_canonical_json(
            authority_state_path, "source-retained canonical authority"
        )
        if source_retained_authority != {
            "schema": CANONICAL_AUTHORITY_STATE_SCHEMA,
            "generation": 2,
            "migration_manifest_sha256": manifest_sha256,
            "decision": "source_retained",
            "source_retained_proof": source_retained_proof,
            "ownership_commit_proof": None,
            "source_fence_proof": None,
        }:
            raise MatrixFailure(
                "source recovery did not retain the expected terminal authority proof"
            )
        if read_canonical_json(
            authority_probe_state_path, "reopened committed probe authority"
        ) != committed_authority:
            raise MatrixFailure("committed probe authority was modified after terminal CAS")
        write_new(
            authority_snapshot_path,
            canonical_bytes(source_retained_authority) + b"\n",
        )
    with contextlib.suppress(FileNotFoundError):
        adapter_path.unlink()
    with contextlib.suppress(FileNotFoundError):
        authority_probe_adapter_path.unlink()

    source_retained_terminal = {
        "authority_schema": CANONICAL_AUTHORITY_STATE_SCHEMA,
        "generation": 2,
        "decision": "source_retained",
        "state": CONTRACT.file_identity(authority_snapshot_path),
        "proof": source_retained_proof,
        "receipt": source_retained_receipt_identity,
        "receipt_document": source_retained_receipt_document,
    }
    committed_probe_terminal = {
        "authority_schema": CANONICAL_AUTHORITY_STATE_SCHEMA,
        "generation": 2,
        "decision": "ownership_committed",
        "state": CONTRACT.file_identity(authority_probe_snapshot_path),
        "proof": commit_proof,
        "receipt": commit_receipt_identity,
        "receipt_document": authority_commit_receipt_document,
        "adapter_configuration_sha256": authority_probe_adapter_sha256,
        "adapter_binding_receipt": CONTRACT.file_identity(authority_probe_binding),
        "adapter_binding_document": authority_probe_binding_document,
    }
    report_path = case / "source-abort-real-driver.json"
    write_new(
        report_path,
        canonical_bytes(
            {
                "schema": "visa-sqlite-source-abort-real-driver-v5",
                "cut": capture,
                "source_frozen": frozen,
                "source_provider_resumed_before_restart": resumed,
                "source_provider_after_recovery": final_provider,
                "source_client": source_client,
                "source_restore_client": source_restore_client,
                "clients_pairwise_distinct": len(
                    {source_client, source_restore_client, destination_client}
                )
                == 3,
                "manifest_sha256": manifest_sha256,
                "adapter_configuration_sha256": adapter_sha256,
                "adapter_binding_receipt": CONTRACT.file_identity(adapter_binding_path),
                "adapter_binding_document": adapter_binding,
                "source_retained_terminal": source_retained_terminal,
                "committed_probe_terminal": committed_probe_terminal,
                "driver_record": CONTRACT.file_identity(record_path),
                "compute_checkpoint": CONTRACT.file_identity(
                    binding_root / "artifacts" / "checkpoint.pb"
                ),
                "source_exit_receipt": CONTRACT.file_identity(source_exit_path),
                "wanco_restore_completion": CONTRACT.file_identity(completion_path),
                "wanco_restore_started": CONTRACT.file_identity(supervisor_started_path),
                "coordinator_restart": {
                    "init_exit_status": init.returncode,
                    "injected_exit_status": injected.returncode,
                    "injected_after": "resume_source_provider",
                    "durable_pending_action": "resume_source_provider",
                    "pending_record": CONTRACT.file_identity(pending_record_path),
                    "recovery_exit_status": recovered.returncode,
                    "final_phase": "source_resumed",
                    "crash_marker": CONTRACT.file_identity(crash_marker_path),
                    "canonical_commit_abort_exit_status": authority_probe.returncode,
                    "authority_init_exit_status": authority_init.returncode,
                    "commit_probe_init_exit_status": authority_probe_init.returncode,
                    "commit_probe_commit_exit_status": authority_probe_commit.returncode,
                    "canonical_commit_abort_stdout": CONTRACT.file_identity(
                        authority_probe_stdout, allow_empty=True
                    ),
                    "canonical_commit_abort_stderr": CONTRACT.file_identity(
                        authority_probe_stderr, allow_empty=True
                    ),
                    "init_stdout": CONTRACT.file_identity(
                        init_stdout, allow_empty=True
                    ),
                    "init_stderr": CONTRACT.file_identity(
                        init_stderr, allow_empty=True
                    ),
                    "authority_init_stdout": CONTRACT.file_identity(
                        authority_init_stdout, allow_empty=True
                    ),
                    "authority_init_stderr": CONTRACT.file_identity(
                        authority_init_stderr, allow_empty=True
                    ),
                    "commit_probe_init_stdout": CONTRACT.file_identity(
                        authority_probe_init_stdout, allow_empty=True
                    ),
                    "commit_probe_init_stderr": CONTRACT.file_identity(
                        authority_probe_init_stderr, allow_empty=True
                    ),
                    "commit_probe_commit_stdout": CONTRACT.file_identity(
                        authority_probe_commit_stdout, allow_empty=True
                    ),
                    "commit_probe_commit_stderr": CONTRACT.file_identity(
                        authority_probe_commit_stderr, allow_empty=True
                    ),
                    "injected_stdout": CONTRACT.file_identity(
                        injected_stdout, allow_empty=True
                    ),
                    "injected_stderr": CONTRACT.file_identity(
                        injected_stderr, allow_empty=True
                    ),
                    "recovered_stdout": CONTRACT.file_identity(
                        recovered_stdout, allow_empty=True
                    ),
                    "recovered_stderr": CONTRACT.file_identity(
                        recovered_stderr, allow_empty=True
                    ),
                },
                "raw_client_observation": observation,
                "namespace_snapshot": namespace,
                "external_oracle": oracle,
            }
        )
        + b"\n",
    )
    return {
        "schema": CONTRACT.SOURCE_ABORT_SCHEMA,
        "scope": "pre-commit-source-compute-abort",
        "integrated_driver_report": CONTRACT.file_identity(report_path),
        "compute_checkpoint": CONTRACT.file_identity(
            binding_root / "artifacts" / "checkpoint.pb"
        ),
        "coordinator_crash_exit_status": injected.returncode,
        "durable_pending_action": "resume_source_provider",
        "pending_driver_record": CONTRACT.file_identity(pending_record_path),
        "adapter_configuration_sha256": adapter_sha256,
        "adapter_binding_receipt": CONTRACT.file_identity(adapter_binding_path),
        "adapter_binding_document": adapter_binding,
        "migration_manifest_sha256": manifest_sha256,
        "source_retained_terminal": source_retained_terminal,
        "committed_probe_terminal": committed_probe_terminal,
        "authority_init_exit_status": authority_init.returncode,
        "commit_probe_init_exit_status": authority_probe_init.returncode,
        "commit_probe_commit_exit_status": authority_probe_commit.returncode,
        "canonical_commit_abort_exit_status": authority_probe.returncode,
        "recovery_exit_status": recovered.returncode,
        "final_phase": "source_resumed",
        "wanco_restore_completion": CONTRACT.file_identity(completion_path),
        "wanco_restore_started": CONTRACT.file_identity(supervisor_started_path),
        "external_oracle_report": oracle["report"],
        "raw_client_observation": observation,
        "expected_acknowledgements": expected_identity,
        "namespace_snapshot": namespace,
        "external_oracle": oracle,
        "equivalence_projection": build_equivalence_projection(oracle, observation),
        "accepted": True,
        "source_client": source_client,
        "source_restore_client": source_restore_client,
        "_raw_paths": {
            "application_runs": application_runs,
            "client_stdout": case / "raw-client.stdout",
            "expected_acknowledgements": expected_path,
            "namespace_snapshot": snapshot_path,
            "oracle_report": oracle_report_path,
            "application_timing": timing_path,
            "compute_checkpoint": binding_root / "artifacts" / "checkpoint.pb",
            "migration_application": binding_root / "artifacts" / "application.aot",
            "resource_capsule_manifest": binding_root / "capsule" / "manifest.json",
            "resource_capsule_state": binding_root / "capsule" / "state.sqlite",
            "driver_runs": (
                ("init", init_stdout, init_stderr, init.returncode),
                (
                    "authority-init",
                    authority_init_stdout,
                    authority_init_stderr,
                    authority_init.returncode,
                ),
                (
                    "commit-probe-init",
                    authority_probe_init_stdout,
                    authority_probe_init_stderr,
                    authority_probe_init.returncode,
                ),
                (
                    "commit-probe-commit",
                    authority_probe_commit_stdout,
                    authority_probe_commit_stderr,
                    authority_probe_commit.returncode,
                ),
                (
                    "committed-probe-abort",
                    authority_probe_stdout,
                    authority_probe_stderr,
                    authority_probe.returncode,
                ),
                (
                    "injected-recovery",
                    injected_stdout,
                    injected_stderr,
                    injected.returncode,
                ),
                (
                    "restart-recovery",
                    recovered_stdout,
                    recovered_stderr,
                    recovered.returncode,
                ),
            ),
            "integrated_driver_report": report_path,
            "pending_driver_record": pending_record_path,
            "final_driver_record": record_path,
            "crash_marker": crash_marker_path,
            "wanco_restore_started": supervisor_started_path,
            "wanco_restore_completion": completion_path,
            "source_exit_receipt": source_exit_path,
            "source_authority_state": authority_snapshot_path,
            "committed_authority_state": authority_probe_snapshot_path,
            "source_adapter_binding": adapter_binding_path,
            "committed_adapter_binding": authority_probe_binding,
            "source_retained_receipt": source_retained_receipt_path,
        },
    }


def absolute_from(repository: Path, path: Path) -> Path:
    return path if path.is_absolute() else repository / path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=SCRIPT_ROOT.parent)
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=Path("target/.ci-artifacts/stock-sqlite-build"),
    )
    parser.add_argument(
        "--sqlite-source-lock",
        type=Path,
        default=Path("third_party/sqlite/source-lock.json"),
    )
    parser.add_argument(
        "--wanco-source-lock",
        type=Path,
        default=Path("third_party/wanco/source-lock.json"),
    )
    parser.add_argument(
        "--wanco-build-receipt",
        type=Path,
        default=Path("target/.ci-cache/wanco-carrier/build-receipt.json"),
    )
    parser.add_argument(
        "--typed-corpus-receipt",
        type=Path,
        default=Path("target/.ci-artifacts/wanco-typed-corpus/receipt.json"),
    )
    parser.add_argument(
        "--host-binary", type=Path, default=Path("target/debug/visa_wasi_host")
    )
    parser.add_argument(
        "--bind-binary",
        type=Path,
        default=Path("target/debug/visa-wasi-migration-bind"),
    )
    parser.add_argument(
        "--driver-binary",
        type=Path,
        default=Path("target/debug/visa-wasi-migration-driver"),
    )
    parser.add_argument(
        "--oracle-binary",
        type=Path,
        default=Path("target/debug/visa-sqlite-oracle"),
    )
    parser.add_argument("--docker", default="docker")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/.ci-artifacts/stock-sqlite-rollback-matrix/receipt.json"),
    )
    parser.add_argument(
        "--work-root",
        type=Path,
        help="new private directory for retained raw execution evidence",
    )
    parser.add_argument(
        "--skip-runtime-build",
        action="store_true",
        help="use the explicitly supplied runtime binaries without rebuilding",
    )
    parser.add_argument(
        "--only-cell",
        choices=[spec.cell_id for spec in CONTRACT.CUT_SPECS],
        help="development run; never publishes a matrix receipt",
    )
    parser.add_argument(
        "--only-source-abort",
        action="store_true",
        help="development run of the real driver restart qualification only",
    )
    return parser.parse_args()


def run_matrix(
    arguments: argparse.Namespace, sockets: ShortSocketRoot
) -> Path | None:
    repository = arguments.repository.resolve()
    if not (repository / ".git").exists():
        raise MatrixFailure(f"not a repository root: {repository}")
    artifact_root = absolute_from(repository, arguments.artifact_root).resolve()
    sqlite_source_lock = absolute_from(repository, arguments.sqlite_source_lock).resolve()
    wanco_source_lock = absolute_from(repository, arguments.wanco_source_lock).resolve()
    wanco_build_receipt = absolute_from(
        repository, arguments.wanco_build_receipt
    ).resolve()
    typed_corpus_receipt = absolute_from(
        repository, arguments.typed_corpus_receipt
    ).resolve()
    host_binary = absolute_from(repository, arguments.host_binary).resolve()
    bind_binary = absolute_from(repository, arguments.bind_binary).resolve()
    driver_binary = absolute_from(repository, arguments.driver_binary).resolve()
    oracle_binary = absolute_from(repository, arguments.oracle_binary).resolve()
    output = absolute_from(repository, arguments.output).resolve()
    if arguments.only_cell is not None and arguments.only_source_abort:
        raise MatrixFailure("--only-cell and --only-source-abort are mutually exclusive")
    if arguments.only_cell is None and not arguments.only_source_abort and output.exists():
        raise MatrixFailure(f"refusing to replace an existing matrix receipt: {output}")
    if not arguments.skip_runtime_build:
        build_runtime_binaries(repository)
    build_receipt, runtime, inputs, workload_paths, typed_qualification = verify_execution_inputs(
        repository=repository,
        artifact_root=artifact_root,
        sqlite_source_lock_path=sqlite_source_lock,
        wanco_source_lock_path=wanco_source_lock,
        wanco_build_receipt_path=wanco_build_receipt,
        typed_corpus_receipt_path=typed_corpus_receipt,
        host_binary=host_binary,
        bind_binary=bind_binary,
        driver_binary=driver_binary,
        oracle_binary=oracle_binary,
        docker=arguments.docker,
    )
    runtime.socket_root = sockets.path
    revision = run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.decode().strip()
    if len(revision) != 40:
        raise MatrixFailure("repository HEAD is not a full Git object identity")
    source_snapshot = repository_snapshot(repository)
    if source_snapshot["clean"] is not True:
        raise MatrixFailure("repository must be clean before a formal SQLite matrix run")
    retained_root = output.parent / "observations"
    if retained_root.exists() or retained_root.is_symlink():
        raise MatrixFailure(
            f"refusing to reuse an existing retained-observation root: {retained_root}"
        )
    default_work = output.parent / "evidence"
    work_root = absolute_from(repository, arguments.work_root).resolve() if arguments.work_root else default_work
    if work_root.exists():
        raise MatrixFailure(f"refusing to reuse an existing matrix work root: {work_root}")
    ensure_private_directory(work_root)
    plan = CONTRACT.build_plan(DATABASE_PATH)
    workload_binding_path = work_root / "workload-binding.json"
    write_new(
        workload_binding_path,
        canonical_bytes(
            {
                "schema": "visa-stock-sqlite-workload-binding-v1",
                "database_path": DATABASE_PATH,
                "initial_total_balance": INITIAL_TOTAL_BALANCE,
                "expected_txids": EXPECTED_TXIDS,
                "expected_cursor_rows": CURSOR_ROWS,
                "seed": CONTRACT.file_identity(workload_paths["seed"]),
                "transaction": CONTRACT.file_identity(workload_paths["transaction"]),
                "cursor": CONTRACT.file_identity(workload_paths["cursor"]),
            }
        )
        + b"\n",
    )
    process_recovery = None
    source_abort = None
    uninterrupted_control = None
    if arguments.only_cell is None:
        source_abort = qualify_source_abort_reconciliation(
            root=work_root,
            sockets=sockets,
            host_binary=host_binary,
            driver_binary=driver_binary,
            oracle_binary=oracle_binary,
            runtime=runtime,
            build_receipt=build_receipt,
            workload_paths=workload_paths,
            source_lock_sha256=sha256_file(sqlite_source_lock),
        )
        if arguments.only_source_abort:
            development = work_root / "development-source-abort.json"
            development_qualification = development_projection(source_abort)
            write_new(
                development,
                canonical_bytes(
                    {
                        "artifact_class": "partial-development-run-not-matrix-evidence",
                        "source_abort_reconciliation_qualification": (
                            development_qualification
                        ),
                    }
                )
                + b"\n",
            )
            print(
                f"source-abort development qualification retained at {development}; "
                "no matrix receipt published"
            )
            return None
        process_recovery = qualify_provider_process_recovery(repository, work_root)
        print("[control] stock SQLite uninterrupted transaction and readback")
        uninterrupted_control = run_uninterrupted_control(
            root=work_root,
            sockets=sockets,
            host_binary=host_binary,
            oracle_binary=oracle_binary,
            runtime=runtime,
            workload_paths=workload_paths,
        )
    selected = [
        (spec, plan["cells"][index])
        for index, spec in enumerate(CONTRACT.CUT_SPECS)
        if arguments.only_cell is None or spec.cell_id == arguments.only_cell
    ]
    cells: list[dict[str, object]] = []
    for index, (spec, entry) in enumerate(selected, start=1):
        print(f"[{index}/{len(selected)}] stock SQLite rollback cut: {spec.cell_id}")
        cells.append(
            run_matrix_cell(
                root=work_root,
                sockets=sockets,
                spec=spec,
                plan_entry=entry,
                host_binary=host_binary,
                bind_binary=bind_binary,
                oracle_binary=oracle_binary,
                runtime=runtime,
                build_receipt=build_receipt,
                inputs=inputs,
                workload_paths=workload_paths,
                source_lock_sha256=sha256_file(sqlite_source_lock),
            )
        )
    if arguments.only_cell is not None:
        development = work_root / "development-cell.json"
        development_cell = development_projection(cells[0])
        write_new(
            development,
            canonical_bytes(
                {
                    "artifact_class": "partial-development-run-not-matrix-evidence",
                    "cell": development_cell,
                }
            )
            + b"\n",
        )
        print(f"partial development cell retained at {development}; no receipt published")
        return None
    if source_abort is None:
        raise MatrixFailure("full matrix omitted source-abort reconciliation")
    if process_recovery is None:
        raise MatrixFailure("full matrix omitted provider process-recovery qualification")
    if uninterrupted_control is None:
        raise MatrixFailure("full matrix omitted the uninterrupted control")
    expected_ack_identity = cells[0]["expected_acknowledgements"]
    if any(cell["expected_acknowledgements"] != expected_ack_identity for cell in cells):
        raise MatrixFailure("cells derived different expected ACK inputs from raw stdout")
    if uninterrupted_control["expected_acknowledgements"] != expected_ack_identity:
        raise MatrixFailure("uninterrupted control derived a different expected ACK input")
    retain_raw_evidence(
        uninterrupted_control,
        artifact_root=output.parent,
        label="uninterrupted-control",
    )
    retain_provider_process_recovery_evidence(
        process_recovery,
        artifact_root=output.parent,
    )
    retain_source_abort_evidence(
        source_abort,
        artifact_root=output.parent,
    )
    for cell in cells:
        cell_id = cell["cell_id"]
        if not isinstance(cell_id, str):
            raise MatrixFailure("matrix cell omitted its canonical identity")
        retain_raw_evidence(
            cell,
            artifact_root=output.parent,
            label=cell_id,
        )
    try:
        _, retained_typed_qualification = CONTRACT.TYPED_CORPUS.retain_bundle(
            typed_corpus_receipt, output.parent / "wanco-typed-corpus"
        )
    except CONTRACT.TYPED_CORPUS.CorpusFailure as error:
        raise MatrixFailure(f"cannot retain Wanco typed corpus evidence: {error}") from error
    if retained_typed_qualification != typed_qualification:
        raise MatrixFailure("retained Wanco typed corpus qualification changed")
    final_revision = run(
        ["git", "rev-parse", "HEAD"], cwd=repository
    ).stdout.decode().strip()
    final_snapshot = repository_snapshot(repository)
    if final_revision != revision or final_snapshot != source_snapshot:
        raise MatrixFailure(
            "repository revision or clean source snapshot changed during the matrix run"
        )
    receipt = {
        "schema": CONTRACT.MATRIX_SCHEMA,
        "repository_revision": revision,
        "repository_source_snapshot": source_snapshot,
        "execution_inputs": inputs,
        "plan": plan,
        "plan_sha256": CONTRACT.canonical_sha256(plan),
        "workload": {
            "stock_sqlite_artifact": inputs["stock_sqlite_aot"],
            "sql_input": CONTRACT.file_identity(workload_binding_path),
            "expected_acknowledgements": expected_ack_identity,
            "initial_total_balance": INITIAL_TOTAL_BALANCE,
            "expected_acknowledgement_txids": EXPECTED_TXIDS,
            "minimum_dirty_database_pages": 3,
            "expected_cursor_rows": CURSOR_ROWS,
        },
        "uninterrupted_control": uninterrupted_control,
        "cells": cells,
        "typed_restore_corpus_qualification": typed_qualification,
        "process_recovery_qualification": process_recovery,
        "source_abort_reconciliation_qualification": source_abort,
        "durability_scope": {
            "provider_process_crash": True,
            "power_loss": False,
            "torn_sector": False,
            "device_write_reordering": False,
        },
    }
    CONTRACT.validate_receipt(receipt, revision)
    CONTRACT.validate_retained_evidence(receipt, output.parent, oracle_binary)
    publish(output, receipt)
    raw = output.read_bytes()
    if raw != canonical_bytes(receipt) + b"\n":
        raise MatrixFailure("published matrix receipt is not canonical")
    CONTRACT.load_and_validate(
        output,
        expected_revision=revision,
        oracle_binary=oracle_binary,
    )
    return output


def main() -> int:
    arguments = parse_arguments()
    work_hint: Path | None = None
    try:
        repository = arguments.repository.resolve()
        output = absolute_from(repository, arguments.output).resolve()
        work_hint = (
            absolute_from(repository, arguments.work_root).resolve()
            if arguments.work_root
            else output.parent / "evidence"
        )
        with ShortSocketRoot() as sockets:
            result = run_matrix(arguments, sockets)
        if result is not None:
            print(f"stock SQLite rollback-journal matrix receipt: {result}")
        return 0
    except (MatrixFailure, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"stock SQLite rollback-journal matrix failed: {error}", file=sys.stderr)
        if work_hint is not None and work_hint.exists():
            print(f"failed-run evidence retained at: {work_hint}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
