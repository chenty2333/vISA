#!/usr/bin/env python3
"""Run the stock-zstd transparent Wanco/vISA migration matrix.

The canonical input, Wanco checkpoints, provider capsules, decoded outputs, and
unrelated diagnostic logs remain private temporary data. After all positive
outputs compare byte-identically, the formal artifact retains one shared
compressed blob, application streams, native-zstd oracle reports, and bounded
verdict-free raw observations for every negative cell so the standalone
validator can recompute the claimed evidence.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator, Sequence

from receipt_artifacts import ArtifactError, publish_reference


SCHEMA = "visa-stock-zstd-transparent-migration-matrix-v8"
ORACLE_REPORT_SCHEMA = "visa-stock-zstd-external-oracle-report-v1"
APPLICATION_TIMING_SCHEMA = "visa-application-timing-v1"
APPLICATION_COST_EVENT_SCHEMA = "visa-application-cost-event-v1"
FAULT_PROCESS_OBSERVATION_SCHEMA = (
    "visa-stock-zstd-fault-process-observation-v1"
)
DEFAULT_INPUT_MIB = 24
MAX_FAULT_STDERR_BYTES = 1024 * 1024
MAX_FAULT_PROCESS_OBSERVATION_BYTES = 64 * 1024
# Stock zstd writes its output through Preview1 fd_write.  These are exact
# hostcall occurrences, not byte-count approximations.
DEFAULT_CUT_WRITE_OCCURRENCES = (8, 64)
PROCESS_TIMEOUT_SECONDS = 300
PROVIDER_START_TIMEOUT_SECONDS = 20
CHECKPOINT_CUT_TIMEOUT_SECONDS = 120
ZSTD_CLI_VERSION_RE = re.compile(
    r"\bZstandard CLI\b.*\bv[0-9]+\.[0-9]+\.[0-9]+\b"
)


def cost_event(label: str, **fields: object) -> None:
    """Optionally emit lifecycle events for the application-cost harness.

    The normal evidence lane is unchanged.  A caller that sets
    ``VISA_APPLICATION_COST_EVENTS`` receives an append-only, monotonic event
    stream from the real runner, allowing end-to-end phase intervals to be
    measured without treating runner summaries as semantic evidence.
    """
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


class MatrixFailure(RuntimeError):
    """A matrix invariant failed."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def file_identity(path: Path) -> dict[str, object]:
    return {"sha256": sha256_file(path), "size": path.stat().st_size}


def bytes_identity(payload: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def write_application_timing(
    path: Path, phases: Sequence[dict[str, object]]
) -> None:
    """Persist measured application phase timings without semantic verdicts."""
    if not phases:
        raise MatrixFailure("application timing receipt has no phases")
    normalized: list[dict[str, object]] = []
    previous_end = 0
    for phase in phases:
        if set(phase) != {
            "phase",
            "role",
            "start_monotonic_ns",
            "end_monotonic_ns",
            "duration_ns",
            "exit_status",
        }:
            raise MatrixFailure("application timing phase has unexpected fields")
        start = phase["start_monotonic_ns"]
        end = phase["end_monotonic_ns"]
        duration = phase["duration_ns"]
        if not all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in (start, end, duration)
        ) or start < 0 or end < start or duration != end - start or duration <= 0:
            raise MatrixFailure("application timing phase has invalid monotonic bounds")
        if start < previous_end:
            raise MatrixFailure("application timing phases overlap or are unordered")
        if not isinstance(phase["phase"], str) or not phase["phase"]:
            raise MatrixFailure("application timing phase name is empty")
        if not isinstance(phase["role"], str) or not phase["role"]:
            raise MatrixFailure("application timing role is empty")
        if (
            not isinstance(phase["exit_status"], int)
            or isinstance(phase["exit_status"], bool)
            or phase["exit_status"] < 0
        ):
            raise MatrixFailure("application timing exit status is invalid")
        normalized.append(dict(phase))
        previous_end = end
    document = {
        "schema": APPLICATION_TIMING_SCHEMA,
        "clock": "python-time.monotonic_ns",
        "phases": normalized,
    }
    path.write_bytes(canonical_bytes(document) + b"\n")


def run(
    command: Sequence[os.PathLike[str] | str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: int = PROCESS_TIMEOUT_SECONDS,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    argv = [os.fspath(value) for value in command]
    command_name = Path(argv[0]).name
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise MatrixFailure(
            f"command {command_name} timed out after {timeout} seconds"
        ) from error
    if check and completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")[-4000:]
        raise MatrixFailure(
            f"command failed with status {completed.returncode}: "
            f"{command_name}\n{stderr}"
        )
    return completed


def require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise MatrixFailure(f"required tool is unavailable: {name}")
    return resolved


def write_deterministic_input(path: Path, size: int) -> None:
    seed = b"vISA stock zstd transparent migration input v1"
    with path.open("xb") as stream:
        remaining = size
        index = 0
        while remaining:
            block = hashlib.sha256(seed + index.to_bytes(8, "little")).digest()
            output = block[:remaining]
            stream.write(output)
            remaining -= len(output)
            index += 1
        stream.flush()
        os.fsync(stream.fileno())


def stable_id(label: str) -> str:
    value = hashlib.sha256(("visa-stock-zstd:" + label).encode("utf-8")).digest()[:16]
    if not any(value):
        raise MatrixFailure("derived identity was unexpectedly zero")
    return value.hex()


def copy_regular(source: Path, destination: Path) -> None:
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)


def repository_snapshot(repository: Path) -> dict[str, object]:
    status = run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repository,
    ).stdout
    tracked_patch = run(
        ["git", "diff", "--binary", "--no-ext-diff", "HEAD", "--"],
        cwd=repository,
    ).stdout
    untracked = run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=repository,
    ).stdout
    untracked_manifest: list[dict[str, object]] = []
    for raw in untracked.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        path = repository / relative
        if path.is_symlink() or not path.is_file():
            raise MatrixFailure(
                f"workspace snapshot contains a non-regular file: {relative}"
            )
        untracked_manifest.append(
            {
                "path": relative.as_posix(),
                "mode": path.stat().st_mode & 0o777,
                **file_identity(path),
            }
        )
    return {
        "clean": not status,
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "tracked_patch_sha256": hashlib.sha256(tracked_patch).hexdigest(),
        "untracked_file_count": len(untracked_manifest),
        "untracked_manifest_sha256": hashlib.sha256(
            canonical_bytes(untracked_manifest)
        ).hexdigest(),
    }


def native_zstd_identity(zstd: Path, repository: Path) -> dict[str, object]:
    try:
        path = zstd.resolve(strict=True)
        mode = path.stat().st_mode
    except OSError as error:
        raise MatrixFailure(
            f"cannot resolve the external stock-zstd oracle: {error}"
        ) from error
    if not path.is_file() or mode & 0o111 == 0:
        raise MatrixFailure(
            f"external stock-zstd oracle is not an executable regular file: {path}"
        )
    version = run([path, "--version"], cwd=repository).stdout.decode().strip()
    if ZSTD_CLI_VERSION_RE.search(version) is None:
        raise MatrixFailure(
            f"external oracle does not identify a native zstd CLI: {version}"
        )
    package: dict[str, str] | None = None
    rpm = shutil.which("rpm")
    if rpm is not None:
        completed = run(
            [
                rpm,
                "-qf",
                "--qf",
                "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}",
                path,
            ],
            cwd=repository,
            check=False,
        )
        if completed.returncode == 0:
            package = {
                "manager": "rpm",
                "identity": completed.stdout.decode().strip(),
            }
    if package is None:
        dpkg_query = shutil.which("dpkg-query")
        dpkg = shutil.which("dpkg")
        if dpkg_query is not None and dpkg is not None:
            owner = run(
                [dpkg, "-S", path],
                cwd=repository,
                check=False,
            )
            if owner.returncode == 0:
                package_name = owner.stdout.decode().split(":", 1)[0]
                completed = run(
                    [
                        dpkg_query,
                        "-W",
                        "-f=${Package}=${Version}:${Architecture}",
                        package_name,
                    ],
                    cwd=repository,
                    check=False,
                )
                if completed.returncode == 0:
                    package = {
                        "manager": "dpkg",
                        "identity": completed.stdout.decode().strip(),
                    }
    if package is None:
        raise MatrixFailure(
            f"external oracle binary has no verified RPM/dpkg owner: {path}"
        )
    return {
        "path": os.fspath(path),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "version": version,
        "package": package,
    }


class Provider:
    def __init__(
        self,
        host_binary: Path,
        database: Path,
        socket: Path,
        capability: str,
        log_root: Path,
    ) -> None:
        self.host_binary = host_binary
        self.database = database
        self.socket = socket
        self.capability = capability
        self.log_root = log_root
        self.process: subprocess.Popen[bytes] | None = None
        self.stdout: Any = None
        self.stderr: Any = None

    def start(self) -> None:
        try:
            ensure_private_directory(self.socket.parent)
            self.stdout = (self.log_root / f"{self.socket.name}.stdout").open("xb")
            self.stderr = (self.log_root / f"{self.socket.name}.stderr").open("xb")
            self.process = subprocess.Popen(
                [
                    os.fspath(self.host_binary),
                    "serve",
                    os.fspath(self.database),
                    os.fspath(self.socket),
                ],
                stdin=subprocess.DEVNULL,
                stdout=self.stdout,
                stderr=self.stderr,
            )
            deadline = time.monotonic() + PROVIDER_START_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise MatrixFailure(
                        "provider exited during startup with status "
                        f"{self.process.returncode}"
                    )
                if self.socket.exists():
                    status = self.control("status", check=False)
                    if status.returncode == 0:
                        return
                time.sleep(0.025)
            raise MatrixFailure(f"provider did not publish socket {self.socket}")
        except BaseException:
            self.stop()
            raise

    def control(
        self, operation: str, *arguments: str | Path, check: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        return run(
            [
                self.host_binary,
                "control",
                self.socket,
                self.capability,
                operation,
                *arguments,
            ],
            cwd=self.log_root,
            check=check,
            timeout=60,
        )

    def stop(self) -> None:
        process = self.process
        if process is not None and process.poll() is None:
            with contextlib.suppress(Exception):
                self.control("shutdown")
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if self.stdout is not None:
            self.stdout.close()
            self.stdout = None
        if self.stderr is not None:
            self.stderr.close()
            self.stderr = None
        self.process = None

    def __enter__(self) -> "Provider":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


class DockerAot:
    def __init__(self, docker: str, image: str, executable: Path) -> None:
        self.docker = docker
        self.image = image
        self.executable = executable
        self.uid = os.getuid()
        self.gid = os.getgid()

    @staticmethod
    def container_path(path: Path, case_root: Path) -> str:
        try:
            relative = path.resolve().relative_to(case_root.resolve())
        except ValueError as error:
            raise MatrixFailure(
                f"AOT path {path} is outside matrix case {case_root}"
            ) from error
        return "/case/" + relative.as_posix()

    def command(
        self,
        *,
        case_root: Path,
        cwd: Path,
        environment: dict[str, str],
        name: str,
        checkpoint: Path | None = None,
    ) -> list[str]:
        socket = Path(environment["VISA_WASI_SOCKET"])
        container_environment = {
            **environment,
            "VISA_WASI_SOCKET": self.container_path(socket, case_root),
        }
        workdir = self.container_path(cwd, case_root)
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
            f"{self.uid}:{self.gid}",
            "--volume",
            f"{case_root.resolve()}:/case",
            "--volume",
            f"{self.executable.parent.resolve()}:/aot:ro",
            "--workdir",
            workdir,
        ]
        for key, value in sorted(container_environment.items()):
            command.extend(["--env", f"{key}={value}"])
        command.extend([self.image, f"/aot/{self.executable.name}"])
        if checkpoint is not None:
            command.extend(
                ["--restore", self.container_path(checkpoint, case_root)]
            )
        command.extend(
            ["--", "-q", "-f", "input.bin", "-o", "output.zst"]
        )
        return command

    def remove(self, name: str) -> None:
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                [self.docker, "rm", "--force", name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )


def create_provider(
    host_binary: Path,
    database: Path,
    session: str,
    admin_capability: str,
    guest_capability: str,
    epoch: int,
    input_path: Path,
    cwd: Path,
) -> None:
    ensure_private_directory(database.parent)
    run(
        [
            host_binary,
            "create",
            database,
            session,
            admin_capability,
            guest_capability,
            str(epoch),
            f"input.bin={input_path}",
        ],
        cwd=cwd,
    )


def restore_provider(
    host_binary: Path,
    bundle: Path,
    database: Path,
    admin_capability: str,
    guest_capability: str,
    cwd: Path,
) -> subprocess.CompletedProcess[bytes]:
    ensure_private_directory(database.parent)
    return run(
        [
            host_binary,
            "restore",
            bundle,
            database,
            admin_capability,
            guest_capability,
        ],
        cwd=cwd,
        check=False,
    )


def guest_environment(
    socket: Path,
    session: str,
    owner: str,
    client: str,
    guest_capability: str,
    epoch: int,
) -> dict[str, str]:
    return {
        "VISA_WASI_SOCKET": os.fspath(socket),
        "VISA_WASI_SESSION_ID": session,
        "VISA_WASI_OWNER_ID": owner,
        "VISA_WASI_CLIENT_ID": client,
        "VISA_WASI_GUEST_CAPABILITY": guest_capability,
        "VISA_WASI_AUTHORITY_EPOCH": str(epoch),
    }


def checkpoint_source(
    runtime: DockerAot,
    case_root: Path,
    source_directory: Path,
    provider: Provider,
    environment: dict[str, str],
    barrier_token: str,
    write_occurrence: int,
) -> tuple[Path, dict[str, object]]:
    if write_occurrence <= 0:
        raise MatrixFailure("checkpoint write occurrence must be positive")
    predicate = {
        "kind": "fd-write",
        "resource": "path:output.zst",
        "outcome": "success",
        "occurrence": write_occurrence,
    }
    cost_event(
        "zstd.cut.predicate_armed",
        cell=source_directory.parent.name,
        occurrence=write_occurrence,
    )
    provider.control(
        "barrier-arm",
        barrier_token,
        predicate["kind"],
        predicate["resource"],
        predicate["outcome"],
        str(write_occurrence),
    )
    armed_status = read_status(provider.control("status"))
    if (
        armed_status.get("barrier") != "armed"
        or armed_status.get("barrier_remaining") != write_occurrence
        or armed_status.get("barrier_effect") is not None
    ):
        raise MatrixFailure("provider did not retain the exact prearmed zstd predicate")

    stdout_path = source_directory / "aot.stdout"
    stderr_path = source_directory / "aot.stderr"
    container_name = (
        f"visa-zstd-checkpoint-{os.getpid()}-{secrets.token_hex(4)}"
    )
    started_ns = time.monotonic_ns()
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.Popen(
            runtime.command(
                case_root=case_root,
                cwd=source_directory,
                environment=environment,
                name=container_name,
            ),
            cwd=source_directory,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )
        try:
            deadline = time.monotonic() + CHECKPOINT_CUT_TIMEOUT_SECONDS
            held_status: dict[str, object] | None = None
            while time.monotonic() < deadline:
                status = process.poll()
                if status is not None:
                    raise MatrixFailure(
                        f"source AOT exited before checkpoint cut with status {status}"
                    )
                current = read_status(provider.control("status"))
                phase = current.get("barrier")
                if phase == "held":
                    held_status = current
                    cost_event(
                        "zstd.cut.barrier_held",
                        cell=source_directory.parent.name,
                        occurrence=write_occurrence,
                    )
                    break
                if phase not in ("armed", "triggered"):
                    raise MatrixFailure(
                        f"source barrier left its exact-cut path at phase {phase!r}"
                    )
                time.sleep(0.005)
            else:
                raise MatrixFailure(
                    "source AOT did not reach the exact post-hostcall barrier at "
                    f"fd-write occurrence {write_occurrence}"
                )
            if held_status is None or held_status.get("barrier_effect") is None:
                raise MatrixFailure("held zstd barrier has no durable target effect")
            released_status = read_status(
                provider.control("barrier-release", barrier_token, "checkpoint")
            )
            cost_event(
                "zstd.cut.checkpoint_release",
                cell=source_directory.parent.name,
                occurrence=write_occurrence,
            )
            if (
                released_status.get("barrier") != "checkpoint_released"
                or released_status.get("barrier_effect")
                != held_status.get("barrier_effect")
            ):
                raise MatrixFailure("provider did not release the exact zstd checkpoint")
            try:
                status = process.wait(timeout=PROCESS_TIMEOUT_SECONDS)
                ended_ns = time.monotonic_ns()
            except subprocess.TimeoutExpired as error:
                raise MatrixFailure(
                    "source AOT did not finish checkpointing"
                ) from error
        finally:
            if process.poll() is None:
                runtime.remove(container_name)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    if status != 0:
        stderr_tail = stderr_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        raise MatrixFailure(
            f"source AOT checkpoint exit status was {status}\n{stderr_tail}"
        )
    checkpoint = source_directory / "checkpoint.pb"
    if not checkpoint.is_file() or checkpoint.stat().st_size == 0:
        raise MatrixFailure("Wanco did not publish a non-empty checkpoint.pb")
    cost_event(
        "zstd.cut.checkpoint_complete",
        cell=source_directory.parent.name,
        occurrence=write_occurrence,
    )
    return checkpoint, {
        "cut_location_source": "prearmed-post-hostcall-predicate",
        "byte_counter_trigger_used": False,
        "signal_checkpoint_used": False,
        "barrier_token": barrier_token,
        "predicate": predicate,
        "armed_status": armed_status,
        "held_status": held_status,
        "checkpoint_released_status": released_status,
        "checkpoint": file_identity(checkpoint),
        "application_start_monotonic_ns": started_ns,
        "application_end_monotonic_ns": ended_ns,
    }


def run_aot(
    runtime: DockerAot,
    case_root: Path,
    cwd: Path,
    environment: dict[str, str],
    label: str,
    *,
    checkpoint: Path | None = None,
    check: bool,
) -> subprocess.CompletedProcess[bytes]:
    container_name = (
        f"visa-zstd-{label}-{os.getpid()}-{secrets.token_hex(4)}"
    )
    try:
        completed = run(
            runtime.command(
                case_root=case_root,
                cwd=cwd,
                environment=environment,
                name=container_name,
                checkpoint=checkpoint,
            ),
            cwd=cwd,
            check=False,
        )
    finally:
        runtime.remove(container_name)
    (cwd / f"{label}.stdout").write_bytes(completed.stdout)
    (cwd / f"{label}.stderr").write_bytes(completed.stderr)
    if check and completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")[-4000:]
        raise MatrixFailure(
            f"{label} AOT failed with status {completed.returncode}\n{stderr}"
        )
    return completed


def external_oracle(
    zstd: Path,
    compressed: Path,
    original: Path,
    decoded: Path,
    cwd: Path,
    cell: str,
) -> tuple[dict[str, object], Path]:
    completed = run(
        [zstd, "-q", "-d", "-f", compressed, "-o", decoded],
        cwd=cwd,
    )
    original_identity = file_identity(original)
    decoded_identity = file_identity(decoded)
    if decoded_identity != original_identity:
        raise MatrixFailure(
            "external stock-zstd oracle observed decompressed bytes different from input"
        )
    oracle = {
        "input": original_identity,
        "decoded": decoded_identity,
        "compressed": file_identity(compressed),
    }
    report = {
        "schema": ORACLE_REPORT_SCHEMA,
        "cell": cell,
        "command": {
            "operation": "stock-zstd-decompress",
            "exit_status": completed.returncode,
            "stdout": bytes_identity(completed.stdout),
            "stderr": bytes_identity(completed.stderr),
        },
        **oracle,
    }
    report_path = cwd / "oracle-report.json"
    report_path.write_bytes(canonical_bytes(report) + b"\n")
    return oracle, report_path


def materialize_and_check(
    provider: Provider,
    output: Path,
    input_path: Path,
    decoded: Path,
    zstd: Path,
    cwd: Path,
    cell: str,
) -> tuple[dict[str, object], Path]:
    provider.control("materialize", "output.zst", output)
    return external_oracle(zstd, output, input_path, decoded, cwd, cell)


def read_status(completed: subprocess.CompletedProcess[bytes]) -> dict[str, object]:
    value = json.loads(completed.stdout)
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise MatrixFailure("provider returned an invalid successful status")
    status = value.get("status")
    if not isinstance(status, dict):
        raise MatrixFailure("provider status is absent")
    return status


def require_status(
    status: dict[str, object], *, mode: str, epoch: int, label: str
) -> None:
    if status.get("mode") != mode or status.get("authority_epoch") != epoch:
        raise MatrixFailure(
            f"{label} provider status is not {mode}@{epoch}: "
            f"{status.get('mode')}@{status.get('authority_epoch')}"
        )


def run_control(
    root: Path,
    host_binary: Path,
    runtime: DockerAot,
    input_path: Path,
    zstd: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    case = root / "control"
    ensure_private_directory(case)
    session = stable_id("control-session")
    owner = stable_id("control-owner")
    client = stable_id("control-client")
    admin_capability = secrets.token_hex(32)
    guest_capability = secrets.token_hex(32)
    database = case / "provider" / "state.sqlite"
    socket = case / "provider.sock"
    create_provider(
        host_binary,
        database,
        session,
        admin_capability,
        guest_capability,
        1,
        input_path,
        case,
    )
    with Provider(
        host_binary, database, socket, admin_capability, case
    ) as provider:
        cost_event("zstd.control.start", cell="control")
        application_start_ns = time.monotonic_ns()
        completed = run_aot(
            runtime,
            case,
            case,
            guest_environment(
                socket, session, owner, client, guest_capability, 1
            ),
            "control",
            check=True,
        )
        application_end_ns = time.monotonic_ns()
        cost_event("zstd.control.complete", cell="control")
        timing_path = case / "application-timing.json"
        write_application_timing(
            timing_path,
            [{
                "phase": "application",
                "role": "control",
                "start_monotonic_ns": application_start_ns,
                "end_monotonic_ns": application_end_ns,
                "duration_ns": application_end_ns - application_start_ns,
                "exit_status": completed.returncode,
            }],
        )
        oracle, oracle_report = materialize_and_check(
            provider,
            case / "control-output.zst",
            input_path,
            case / "control-decoded.bin",
            zstd,
            case,
            "uninterrupted-control",
        )
        status = read_status(provider.control("status"))
        require_status(
            status,
            mode="active",
            epoch=1,
            label="uninterrupted control",
        )
    return (
        {
            "cell": "uninterrupted-control",
            "topology": "single-process-no-checkpoint",
            "provider_status": status,
            "oracle": oracle,
        },
        {
            "compressed_output": case / "control-output.zst",
            "application_timing": timing_path,
            "application_runs": (
                (
                    "control",
                    case / "control.stdout",
                    case / "control.stderr",
                    completed.returncode,
                ),
            ),
            "oracle_report": oracle_report,
        },
    )


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
    build_receipt: dict[str, object],
    build_configuration_sha256: str,
    runtime_sha256: str,
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
            "source_revision": str(build_receipt["zstd_revision"]),
            "toolchain": str(build_receipt["compiler_version"]),
            "build_configuration_sha256": build_configuration_sha256,
        },
        "source_platform": platform_identity,
        "destination_platform": platform_identity,
    }
    path.write_bytes(canonical_bytes(document))


def mutate_one_byte(path: Path) -> None:
    with path.open("r+b") as stream:
        first = stream.read(1)
        if not first:
            raise MatrixFailure(f"cannot mutate empty artifact {path}")
        stream.seek(0)
        stream.write(bytes([first[0] ^ 0x80]))
        stream.flush()
        os.fsync(stream.fileno())


def expect_rejection(
    completed: subprocess.CompletedProcess[bytes],
    label: str,
    *,
    detector: str,
    expected_stderr_any: Sequence[str],
    evidence_root: Path | None = None,
) -> dict[str, object]:
    if completed.returncode <= 0:
        raise MatrixFailure(f"{label} was unexpectedly accepted")
    if not expected_stderr_any:
        raise MatrixFailure(f"{label} has no expected detector signature")
    stderr_text = completed.stderr.decode("utf-8", errors="replace")
    if not any(signature in stderr_text for signature in expected_stderr_any):
        raise MatrixFailure(
            f"{label} failed outside the expected detector class {detector}"
        )
    result: dict[str, object] = {
        "fault": label,
        "detector": detector,
        "exit_status": completed.returncode,
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        "stderr_tail": stderr_text[-320:],
    }
    if evidence_root is not None:
        if re.fullmatch(r"cut-[12]-[a-z0-9-]+", label) is None:
            raise MatrixFailure(f"fault evidence label is not canonical: {label}")
        ensure_private_directory(evidence_root)
        stderr_path = evidence_root / f"{label}.stderr"
        process_path = evidence_root / f"{label}.process.json"
        with stderr_path.open("xb") as stream:
            stream.write(completed.stderr)
            stream.flush()
            os.fsync(stream.fileno())
        process_observation = {
            "schema": FAULT_PROCESS_OBSERVATION_SCHEMA,
            "fault": label,
            "exit_status": completed.returncode,
            "stderr": bytes_identity(completed.stderr),
        }
        with process_path.open("xb") as stream:
            stream.write(canonical_bytes(process_observation) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        result["_raw_stderr_path"] = stderr_path
        result["_raw_process_observation_path"] = process_path
    return result


def bind_command(
    bind_binary: Path, command: str, root: Path, *arguments: str | Path
) -> subprocess.CompletedProcess[bytes]:
    return run(
        [bind_binary, command, root, *arguments],
        cwd=root,
        check=False,
        timeout=60,
    )


def copy_tree_hardlink(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, copy_function=os.link)


def run_migrated_cell(
    root: Path,
    index: int,
    write_occurrence: int,
    host_binary: Path,
    bind_binary: Path,
    runtime: DockerAot,
    input_path: Path,
    zstd: Path,
    build_receipt: dict[str, object],
    build_configuration_sha256: str,
    runtime_sha256: str,
    control: dict[str, object],
) -> tuple[dict[str, object], list[dict[str, object]], dict[str, object]]:
    label = f"cut-{index + 1}"
    case = root / label
    ensure_private_directory(case)
    fault_evidence_root = case / "fault-evidence"
    source = case / "source"
    ensure_private_directory(source)
    binding_root = case / "binding"
    ensure_private_directory(binding_root)
    ensure_private_directory(binding_root / "artifacts")
    ensure_private_directory(binding_root / "proofs")

    session = stable_id(f"{label}-session")
    owner = stable_id(f"{label}-owner")
    source_client = stable_id(f"{label}-source-client")
    source_restore_client = stable_id(f"{label}-source-restore-client")
    destination_client = stable_id(f"{label}-destination-client")
    carrier_only_client = stable_id(f"{label}-carrier-only-client")
    spoofed_client = stable_id(f"{label}-spoofed-client")
    handoff = stable_id(f"{label}-handoff")
    checkpoint_barrier = stable_id(f"{label}-checkpoint-barrier")
    source_admin_capability = secrets.token_hex(32)
    source_guest_capability = secrets.token_hex(32)
    destination_admin_capability = secrets.token_hex(32)
    destination_guest_capability = secrets.token_hex(32)
    source_database = source / "provider" / "state.sqlite"
    source_socket = source / "provider.sock"
    create_provider(
        host_binary,
        source_database,
        session,
        source_admin_capability,
        source_guest_capability,
        1,
        input_path,
        source,
    )

    with Provider(
        host_binary,
        source_database,
        source_socket,
        source_admin_capability,
        source,
    ) as source_provider:
        cost_event("zstd.cut.start", cell=label, occurrence=write_occurrence)
        checkpoint, checkpoint_observation = checkpoint_source(
            runtime,
            case,
            source,
            source_provider,
            guest_environment(
                source_socket,
                session,
                owner,
                source_client,
                source_guest_capability,
                1,
            ),
            checkpoint_barrier,
            write_occurrence,
        )

        source_post_checkpoint_status = read_status(
            source_provider.control("status")
        )
        require_status(
            source_post_checkpoint_status,
            mode="active",
            epoch=1,
            label=f"{label} post-checkpoint source",
        )
        control_status = control["provider_status"]
        control_oracle = control["oracle"]
        if not isinstance(control_status, dict) or not isinstance(
            control_oracle, dict
        ):
            raise MatrixFailure("control cell is malformed")
        control_compressed = control_oracle.get("compressed")
        if not isinstance(control_compressed, dict):
            raise MatrixFailure("control compressed identity is absent")
        if (
            source_post_checkpoint_status["bytes_written"]
            >= control_compressed["size"]
            or source_post_checkpoint_status["completed_requests"]
            >= control_status["completed_requests"]
        ):
            raise MatrixFailure(
                f"{label} checkpoint was taken after the workload reached a terminal state"
            )

        carrier_only_root = case / "carrier-only"
        ensure_private_directory(carrier_only_root)
        carrier_only_database = carrier_only_root / "provider" / "state.sqlite"
        carrier_only_socket = carrier_only_root / "provider.sock"
        carrier_only_admin_capability = secrets.token_hex(32)
        carrier_only_guest_capability = secrets.token_hex(32)
        create_provider(
            host_binary,
            carrier_only_database,
            session,
            carrier_only_admin_capability,
            carrier_only_guest_capability,
            2,
            input_path,
            carrier_only_root,
        )
        with Provider(
            host_binary,
            carrier_only_database,
            carrier_only_socket,
            carrier_only_admin_capability,
            carrier_only_root,
        ) as carrier_only_provider:
            carrier_only_before = read_status(
                carrier_only_provider.control("status")
            )
            require_status(
                carrier_only_before,
                mode="active",
                epoch=2,
                label=f"{label} carrier-only provider before execution",
            )
            carrier_only_start_ns = time.monotonic_ns()
            carrier_only = run_aot(
                runtime,
                case,
                carrier_only_root,
                guest_environment(
                    carrier_only_socket,
                    session,
                    owner,
                    carrier_only_client,
                    carrier_only_guest_capability,
                    2,
                ),
                "carrier-only",
                checkpoint=checkpoint,
                check=False,
            )
            carrier_only_end_ns = time.monotonic_ns()
            carrier_only_after = read_status(
                carrier_only_provider.control("status")
            )
            require_status(
                carrier_only_after,
                mode="active",
                epoch=2,
                label=f"{label} carrier-only provider after execution",
            )
        carrier_only_fault = expect_rejection(
            carrier_only,
            f"{label}-carrier-only-fresh-empty-provider",
            detector="stock-zstd-filesystem-error-from-fresh-empty-provider",
            expected_stderr_any=(
                "Bad file descriptor",
                "Read error",
                "Permission denied",
            ),
            evidence_root=fault_evidence_root,
        )
        carrier_only_fault.update(
            {
                "scope": "end-to-end",
                "provider_before": carrier_only_before,
                "provider_after": carrier_only_after,
            }
        )

        source_provider.control("freeze", checkpoint_barrier, handoff, "2")
        cost_event("zstd.cut.source_frozen", cell=label)
        source_frozen_status = read_status(source_provider.control("status"))
        require_status(
            source_frozen_status,
            mode="frozen",
            epoch=1,
            label=f"{label} frozen source",
        )
        source_provider.control("export", binding_root / "capsule")
        copy_regular(
            runtime.executable,
            binding_root / "artifacts" / "application.aot",
        )
        shutil.copy2(
            checkpoint, binding_root / "artifacts" / "checkpoint.pb"
        )
        write_intent(
            binding_root / "intent.json",
            session=session,
            owner=owner,
            handoff=handoff,
            checkpoint_barrier=checkpoint_barrier,
            source_client=source_client,
            source_restore_client=source_restore_client,
            destination_client=destination_client,
            build_receipt=build_receipt,
            build_configuration_sha256=build_configuration_sha256,
            runtime_sha256=runtime_sha256,
        )
        seal = bind_command(
            bind_binary,
            "seal",
            binding_root,
            "intent.json",
            "migration-manifest.json",
        )
        if seal.returncode != 0:
            raise MatrixFailure(
                "migration manifest seal failed: "
                + seal.stderr.decode("utf-8", errors="replace")
            )
        manifest_sha256 = seal.stdout.decode().strip()
        bound_runtime = DockerAot(
            runtime.docker,
            runtime.image,
            binding_root / "artifacts" / "application.aot",
        )

        faults: list[dict[str, object]] = [carrier_only_fault]

        checkpoint_tamper = case / "checkpoint-tamper"
        copy_tree_hardlink(binding_root, checkpoint_tamper)
        tampered_checkpoint = (
            checkpoint_tamper / "artifacts" / "checkpoint.pb"
        )
        tampered_checkpoint.unlink()
        shutil.copy2(
            binding_root / "artifacts" / "checkpoint.pb",
            tampered_checkpoint,
        )
        mutate_one_byte(tampered_checkpoint)
        faults.append(
            {
                **expect_rejection(
                    bind_command(
                        bind_binary,
                        "verify",
                        checkpoint_tamper,
                        "migration-manifest.json",
                    ),
                    f"{label}-compute-checkpoint-tamper",
                    detector="migration-manifest-bound-file-digest",
                    expected_stderr_any=(
                        "migration integrity failure: bound file content differs",
                    ),
                    evidence_root=fault_evidence_root,
                ),
                "scope": "manifest-verification-path",
            }
        )

        capsule_tamper = case / "capsule-tamper"
        copy_tree_hardlink(binding_root / "capsule", capsule_tamper)
        tampered_state = capsule_tamper / "state.sqlite"
        tampered_state.unlink()
        shutil.copy2(binding_root / "capsule" / "state.sqlite", tampered_state)
        mutate_one_byte(tampered_state)
        tampered_restore = restore_provider(
            host_binary,
            capsule_tamper,
            case / "tampered-provider" / "state.sqlite",
            secrets.token_hex(32),
            secrets.token_hex(32),
            case,
        )
        faults.append(
            {
                **expect_rejection(
                    tampered_restore,
                    f"{label}-provider-capsule-tamper",
                    detector="provider-capsule-state-digest",
                    expected_stderr_any=(
                        "provider integrity failure: capsule state digest",
                    ),
                    evidence_root=fault_evidence_root,
                ),
                "scope": "provider-restore-path",
            }
        )

        destination = case / "destination"
        destination_database = destination / "provider" / "state.sqlite"
        restored = restore_provider(
            host_binary,
            binding_root / "capsule",
            destination_database,
            destination_admin_capability,
            destination_guest_capability,
            case,
        )
        if restored.returncode != 0:
            raise MatrixFailure(
                "destination provider restore failed: "
                + restored.stderr.decode("utf-8", errors="replace")
            )
        cost_event("zstd.cut.destination_prepared", cell=label)
        destination_socket = destination / "provider.sock"
        with Provider(
            host_binary,
            destination_database,
            destination_socket,
            destination_admin_capability,
            destination,
        ) as destination_provider:
            prepared_status = read_status(destination_provider.control("status"))
            require_status(
                prepared_status,
                mode="prepared",
                epoch=1,
                label=f"{label} restored destination",
            )

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
            (binding_root / "proofs" / "commit.receipt").write_bytes(
                canonical_bytes(commit_receipt)
            )
            (binding_root / "proofs" / "fence.receipt").write_bytes(
                canonical_bytes(fence_receipt)
            )
            proofs = bind_command(
                bind_binary,
                "bind-proofs",
                binding_root,
                "migration-manifest.json",
                "proofs/commit.receipt",
                "proofs/fence.receipt",
                "proofs/commit.json",
                "proofs/fence.json",
            )
            if proofs.returncode != 0:
                raise MatrixFailure(
                    "commit/fence receipt binding failed: "
                    + proofs.stderr.decode("utf-8", errors="replace")
                )
            proof_digests = proofs.stdout.decode().strip().split()
            if len(proof_digests) != 2:
                raise MatrixFailure("proof binder returned invalid digests")
            verified = bind_command(
                bind_binary,
                "verify-proofs",
                binding_root,
                "migration-manifest.json",
                "proofs/commit.json",
                "proofs/fence.json",
            )
            if verified.returncode != 0:
                raise MatrixFailure(
                    "commit/fence receipt verification failed: "
                    + verified.stderr.decode("utf-8", errors="replace")
                )

            (binding_root / "proofs" / "alternate-commit.receipt").write_bytes(
                canonical_bytes(
                    {
                        **commit_receipt,
                        "authority_decision": "different-commit-instance",
                    }
                )
            )
            alternate = bind_command(
                bind_binary,
                "bind-proofs",
                binding_root,
                "migration-manifest.json",
                "proofs/alternate-commit.receipt",
                "proofs/fence.receipt",
                "proofs/alternate-commit.json",
                "proofs/alternate-fence.json",
            )
            if alternate.returncode != 0:
                raise MatrixFailure(
                    "alternate proof binding failed: "
                    + alternate.stderr.decode("utf-8", errors="replace")
                )
            faults.append(
                {
                    **expect_rejection(
                        bind_command(
                            bind_binary,
                            "verify-proofs",
                            binding_root,
                            "migration-manifest.json",
                            "proofs/alternate-commit.json",
                            "proofs/fence.json",
                        ),
                        f"{label}-commit-fence-proof-pair-swap",
                        detector="canonical-fence-to-commit-binding",
                        expected_stderr_any=(
                            "canonical proof rejected: source fence proof binding differs",
                        ),
                        evidence_root=fault_evidence_root,
                    ),
                    "scope": "canonical-proof-verification-path",
                }
            )

            source_provider.control("fence", handoff, "2")
            cost_event("zstd.cut.source_fenced", cell=label)
            source_fenced_status = read_status(
                source_provider.control("status")
            )
            require_status(
                source_fenced_status,
                mode="fenced",
                epoch=1,
                label=f"{label} fenced source",
            )
            destination_provider.control("activate", handoff, "2")
            cost_event("zstd.cut.destination_activated", cell=label)
            active_status = read_status(destination_provider.control("status"))
            require_status(
                active_status,
                mode="active",
                epoch=2,
                label=f"{label} activated destination",
            )

            pre_exec_verified = bind_command(
                bind_binary,
                "verify-proofs",
                binding_root,
                "migration-manifest.json",
                "proofs/commit.json",
                "proofs/fence.json",
            )
            if pre_exec_verified.returncode != 0:
                raise MatrixFailure(
                    "manifest/proof verification immediately before destination "
                    "execution failed: "
                    + pre_exec_verified.stderr.decode(
                        "utf-8", errors="replace"
                    )
                )
            spoof_before = read_status(destination_provider.control("status"))
            require_status(
                spoof_before,
                mode="active",
                epoch=2,
                label=f"{label} destination before guest-capability spoof",
            )
            spoofed_destination = run_aot(
                bound_runtime,
                case,
                destination,
                guest_environment(
                    destination_socket,
                    session,
                    owner,
                    spoofed_client,
                    source_guest_capability,
                    2,
                ),
                "destination-spoofed-admission",
                checkpoint=binding_root
                / "artifacts"
                / "checkpoint.pb",
                check=False,
            )
            spoof_after = read_status(destination_provider.control("status"))
            require_status(
                spoof_after,
                mode="active",
                epoch=2,
                label=f"{label} destination after guest-capability spoof",
            )
            if spoof_after != spoof_before:
                raise MatrixFailure(
                    "rejected destination admission changed provider semantic state"
                )
            faults.append(
                {
                    **expect_rejection(
                        spoofed_destination,
                        f"{label}-destination-guest-capability-spoof",
                        detector="guest-capability-admission-before-provider-mutation",
                        expected_stderr_any=(
                            "Permission denied",
                            "Read error",
                            "Bad file descriptor",
                        ),
                        evidence_root=fault_evidence_root,
                    ),
                    "scope": "end-to-end",
                    "provider_state_unchanged": True,
                }
            )
            destination_start_ns = time.monotonic_ns()
            destination_completed = run_aot(
                bound_runtime,
                case,
                destination,
                guest_environment(
                    destination_socket,
                    session,
                    owner,
                    destination_client,
                    destination_guest_capability,
                    2,
                ),
                "destination",
                checkpoint=binding_root
                / "artifacts"
                / "checkpoint.pb",
                check=True,
            )
            destination_end_ns = time.monotonic_ns()
            cost_event("zstd.cut.destination_complete", cell=label)
            if destination_completed.returncode != 0:
                raise MatrixFailure("restored destination did not exit cleanly")
            source_start_ns = checkpoint_observation.get("application_start_monotonic_ns")
            source_end_ns = checkpoint_observation.get("application_end_monotonic_ns")
            if not isinstance(source_start_ns, int) or not isinstance(source_end_ns, int):
                raise MatrixFailure(f"{label} source application timing is absent")
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
                        "start_monotonic_ns": destination_start_ns,
                        "end_monotonic_ns": destination_end_ns,
                        "duration_ns": destination_end_ns - destination_start_ns,
                        "exit_status": destination_completed.returncode,
                    },
                ],
            )
            oracle, oracle_report = materialize_and_check(
                destination_provider,
                destination / "migrated-output.zst",
                input_path,
                destination / "migrated-decoded.bin",
                zstd,
                destination,
                f"{label}-visa-plus-carrier",
            )
            cost_event("zstd.cut.oracle_complete", cell=label)
            final_status = read_status(destination_provider.control("status"))
            require_status(
                final_status,
                mode="active",
                epoch=2,
                label=f"{label} completed destination",
            )
            if (
                final_status["bytes_written"]
                <= source_post_checkpoint_status["bytes_written"]
                or final_status["completed_requests"]
                <= source_post_checkpoint_status["completed_requests"]
            ):
                raise MatrixFailure(
                    f"{label} destination made no observable provider progress"
                )
            if oracle["compressed"] != control_compressed:
                raise MatrixFailure(
                    f"{label} compressed bytes differ from uninterrupted control"
                )

    cut = {
        key: value
        for key, value in checkpoint_observation.items()
        if key not in {
            "application_start_monotonic_ns",
            "application_end_monotonic_ns",
        }
    }
    cell = {
        "cell": f"{label}-visa-plus-carrier",
        "topology": "fresh-provider-fresh-process",
        "cut": cut,
        "source_post_checkpoint_status": source_post_checkpoint_status,
        "source_frozen_status": source_frozen_status,
        "manifest_sha256": manifest_sha256,
        "commit_proof_sha256": proof_digests[0],
        "fence_proof_sha256": proof_digests[1],
        "prepared_status": prepared_status,
        "source_fenced_status": source_fenced_status,
        "active_status": active_status,
        "final_status": final_status,
        "destination_executed_manifest_bound_application": True,
        "compressed_bytes_equal_uninterrupted_control": True,
        "oracle": oracle,
    }
    return (
        cell,
        faults,
        {
            "compressed_output": destination / "migrated-output.zst",
            "application_runs": (
                ("source", source / "aot.stdout", source / "aot.stderr", 0),
                (
                    "destination",
                    destination / "destination.stdout",
                    destination / "destination.stderr",
                    destination_completed.returncode,
                ),
            ),
            "application_timing": timing_path,
            "oracle_report": oracle_report,
        },
    )


def verify_build_artifacts(
    artifact_root: Path,
) -> tuple[dict[str, object], Path]:
    receipt_path = artifact_root / "receipt.json"
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MatrixFailure(f"cannot read stock-zstd build receipt: {error}") from error
    if receipt.get("schema") != "visa-stock-zstd-build-receipt-v1":
        raise MatrixFailure("stock-zstd build receipt schema is unsupported")
    optimization = receipt.get("wanco_optimization")
    suffix = {"-O0": "o0", "-O1": "o1"}.get(optimization)
    if suffix is None:
        raise MatrixFailure("stock-zstd build receipt has unknown optimization")
    if optimization != "-O1" or receipt.get("wanco_o1_qualified") is not True:
        raise MatrixFailure(
            "the transparent migration matrix requires a qualified Wanco -O1 stock-zstd build"
        )
    executable = artifact_root / f"zstd-v1.5.7-wanco-{suffix}"
    artifacts = receipt.get("artifacts")
    expected_names = {
        executable.name,
        f"{executable.name}.ll",
        "zstd-v1.5.7.wasm",
    }
    if not isinstance(artifacts, dict) or set(artifacts) != expected_names:
        raise MatrixFailure(
            "stock-zstd build receipt does not own the exact artifact set"
        )
    for name in sorted(expected_names):
        identity = artifacts.get(name)
        path = artifact_root / name
        if not isinstance(identity, dict) or file_identity(path) != identity:
            raise MatrixFailure(
                f"stock-zstd artifact differs from its build receipt: {name}"
            )
    if receipt.get("zero_upstream_source_patches") is not True:
        raise MatrixFailure(
            "stock-zstd build receipt does not establish zero upstream source patches"
        )
    return receipt, executable


def require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise MatrixFailure(f"{label} is not an object")
    return value


def validate_execution_input_chain(
    *,
    build_receipt: dict[str, object],
    source_lock: dict[str, object],
    source_lock_sha256: str,
    wanco_source_lock: dict[str, object],
    wanco_source_lock_sha256: str,
    wanco_receipt: dict[str, object],
    wanco_receipt_sha256: str,
    live_wanco_image_id: str,
) -> dict[str, str]:
    source_policy = require_object(
        source_lock.get("source_policy"), "stock-zstd source policy"
    )
    upstream = require_object(
        source_lock.get("upstream"), "stock-zstd upstream identity"
    )
    wasi_build = require_object(
        source_lock.get("wasi_build"), "stock-zstd WASI build"
    )
    carrier_build = require_object(
        source_lock.get("carrier_build"), "stock-zstd carrier build"
    )
    locked_wanco = require_object(
        carrier_build.get("wanco_source_lock"),
        "stock-zstd Wanco source-lock binding",
    )
    build_recipe = require_object(
        source_policy.get("build_recipe"), "stock-zstd build recipe"
    )
    artifacts = require_object(
        build_receipt.get("artifacts"), "stock-zstd build artifacts"
    )
    wasm_identity = require_object(
        artifacts.get("zstd-v1.5.7.wasm"), "stock-zstd Wasm identity"
    )
    wanco_upstream = require_object(
        wanco_source_lock.get("upstream"), "Wanco upstream identity"
    )

    if source_lock.get("schema") != "visa-stock-zstd-source-lock-v1":
        raise MatrixFailure("stock-zstd source-lock schema is unsupported")
    if source_policy.get("source_patches") != []:
        raise MatrixFailure("stock-zstd source lock contains upstream source patches")
    if build_receipt.get("zero_upstream_source_patches") is not True:
        raise MatrixFailure(
            "stock-zstd build receipt does not bind zero upstream source patches"
        )
    if wanco_source_lock.get("schema") != "visa-wanco-carrier-source-lock-v3":
        raise MatrixFailure("Wanco source-lock schema is unsupported")
    if wanco_receipt.get("schema") != "visa-wanco-carrier-build-receipt-v5":
        raise MatrixFailure("Wanco build receipt schema is unsupported")
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

    equalities = (
        (
            build_receipt.get("source_lock_sha256"),
            source_lock_sha256,
            "stock-zstd build receipt to source lock",
        ),
        (
            build_receipt.get("build_recipe_sha256"),
            build_recipe.get("sha256"),
            "stock-zstd build receipt to build recipe",
        ),
        (
            build_receipt.get("zstd_revision"),
            upstream.get("revision"),
            "stock-zstd revision",
        ),
        (
            wasm_identity.get("sha256"),
            wasi_build.get("expected_wasm_sha256"),
            "stock-zstd Wasm digest",
        ),
        (
            build_receipt.get("wanco_optimization"),
            wasi_build.get("optimization"),
            "stock-zstd WASI optimization",
        ),
        (
            build_receipt.get("wanco_optimization"),
            carrier_build.get("optimization"),
            "stock-zstd carrier optimization",
        ),
        (
            build_receipt.get("carrier_qualification"),
            carrier_build.get("qualification"),
            "stock-zstd carrier qualification",
        ),
        (
            locked_wanco.get("sha256"),
            wanco_source_lock_sha256,
            "stock-zstd source lock to Wanco source lock",
        ),
        (
            build_receipt.get("wanco_source_lock_sha256"),
            wanco_source_lock_sha256,
            "stock-zstd build receipt to Wanco source lock",
        ),
        (
            build_receipt.get("wanco_build_receipt_sha256"),
            wanco_receipt_sha256,
            "stock-zstd build receipt to Wanco build receipt",
        ),
        (
            build_receipt.get("wanco_revision"),
            carrier_build.get("wanco_revision"),
            "stock-zstd carrier revision",
        ),
        (
            build_receipt.get("wanco_revision"),
            wanco_upstream.get("revision"),
            "Wanco source revision",
        ),
        (
            wanco_receipt.get("revision"),
            build_receipt.get("wanco_revision"),
            "Wanco build revision",
        ),
        (
            build_receipt.get("wanco_compiler_sha256"),
            carrier_build.get("wanco_compiler_sha256"),
            "stock-zstd Wanco compiler digest",
        ),
        (
            wanco_receipt.get("wanco_binary_sha256"),
            build_receipt.get("wanco_compiler_sha256"),
            "Wanco compiler artifact digest",
        ),
        (
            build_receipt.get("wanco_runtime_sha256"),
            carrier_build.get("wanco_runtime_sha256"),
            "stock-zstd Wanco runtime digest",
        ),
        (
            wanco_receipt.get("runtime_staticlib_sha256"),
            build_receipt.get("wanco_runtime_sha256"),
            "Wanco runtime artifact digest",
        ),
        (
            wanco_receipt.get("image_tag"),
            build_receipt.get("wanco_image"),
            "Wanco image tag",
        ),
        (
            wanco_receipt.get("image_id"),
            build_receipt.get("wanco_image_id"),
            "Wanco image receipt identity",
        ),
        (
            live_wanco_image_id,
            build_receipt.get("wanco_image_id"),
            "live Wanco image identity",
        ),
    )
    for actual, expected, label in equalities:
        if actual != expected:
            raise MatrixFailure(f"{label} binding differs")

    image = build_receipt.get("wanco_image")
    image_id = build_receipt.get("wanco_image_id")
    runtime_sha256 = build_receipt.get("wanco_runtime_sha256")
    if not all(isinstance(value, str) and value for value in (image, image_id, runtime_sha256)):
        raise MatrixFailure("Wanco execution identity is incomplete")
    image_digest = image_id.removeprefix("sha256:")
    if (
        not image_id.startswith("sha256:")
        or len(image_digest) != 64
        or any(character not in "0123456789abcdef" for character in image_digest)
    ):
        raise MatrixFailure("Wanco execution image ID is not a canonical SHA-256")
    return {
        "stock_zstd_source_lock_sha256": source_lock_sha256,
        "wanco_source_lock_sha256": wanco_source_lock_sha256,
        "wanco_build_receipt_sha256": wanco_receipt_sha256,
        "wanco_image": image,
        "wanco_image_id": image_id,
        "wanco_runtime_sha256": runtime_sha256,
    }


def verify_execution_inputs(
    repository: Path,
    docker: str,
    build_receipt: dict[str, object],
) -> dict[str, str]:
    run(
        [sys.executable, repository / "scripts" / "check-zstd-source.py"],
        cwd=repository,
    )
    run(
        [
            sys.executable,
            repository / "scripts" / "check-wanco-carrier-source.py",
        ],
        cwd=repository,
    )
    source_lock_path = repository / "third_party" / "zstd" / "source-lock.json"
    wanco_source_lock_path = (
        repository / "third_party" / "wanco" / "source-lock.json"
    )
    wanco_receipt_path = (
        repository / "target" / ".ci-cache" / "wanco-carrier" / "build-receipt.json"
    )
    try:
        source_lock = require_object(
            json.loads(source_lock_path.read_text(encoding="utf-8")),
            "stock-zstd source lock",
        )
        wanco_source_lock = require_object(
            json.loads(wanco_source_lock_path.read_text(encoding="utf-8")),
            "Wanco source lock",
        )
        wanco_receipt = require_object(
            json.loads(wanco_receipt_path.read_text(encoding="utf-8")),
            "Wanco build receipt",
        )
    except (OSError, json.JSONDecodeError) as error:
        raise MatrixFailure(f"cannot read execution input chain: {error}") from error

    image = build_receipt.get("wanco_image")
    if not isinstance(image, str) or not image:
        raise MatrixFailure("stock-zstd build receipt has no Wanco image")
    inspected = run(
        [docker, "image", "inspect", "--format", "{{.Id}}", image],
        cwd=repository,
        timeout=60,
        check=False,
    )
    if inspected.returncode != 0:
        raise MatrixFailure(f"source-locked Wanco runtime image is absent: {image}")
    try:
        live_wanco_image_id = inspected.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise MatrixFailure("Docker returned a non-ASCII Wanco image identity") from error
    binding = validate_execution_input_chain(
        build_receipt=build_receipt,
        source_lock=source_lock,
        source_lock_sha256=sha256_file(source_lock_path),
        wanco_source_lock=wanco_source_lock,
        wanco_source_lock_sha256=sha256_file(wanco_source_lock_path),
        wanco_receipt=wanco_receipt,
        wanco_receipt_sha256=sha256_file(wanco_receipt_path),
        live_wanco_image_id=live_wanco_image_id,
    )
    return binding


def publish_receipt(output: Path, receipt: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_bytes(receipt) + b"\n"
    temporary = output.with_name(output.name + f".tmp.{os.getpid()}")
    with temporary.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, output)
    directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def publish_positive_raw_artifacts(
    artifact_root: Path,
    label: str,
    raw: dict[str, object],
    *,
    shared_compressed_output: dict[str, object] | None = None,
) -> dict[str, object]:
    compressed = raw.get("compressed_output")
    report = raw.get("oracle_report")
    timing = raw.get("application_timing")
    application_runs = raw.get("application_runs")
    if (
        not isinstance(compressed, Path)
        or not isinstance(report, Path)
        or not isinstance(application_runs, tuple)
        or not isinstance(timing, Path)
    ):
        raise MatrixFailure(f"{label} raw artifact set is malformed")
    prefix = f"raw/{label}"
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
            raise MatrixFailure(f"{label} application run entry is malformed")
        role, stdout_path, stderr_path, exit_status = entry
        published_runs.append(
            {
                "role": role,
                "exit_status": exit_status,
                "stdout": publish_reference(
                    stdout_path,
                    artifact_root,
                    f"{prefix}/{role}.stdout",
                ),
                "stderr": publish_reference(
                    stderr_path,
                    artifact_root,
                    f"{prefix}/{role}.stderr",
                ),
            }
        )
    if shared_compressed_output is None:
        compressed_reference = publish_reference(
            compressed,
            artifact_root,
            "raw/positive-output.zst",
        )
    else:
        if file_identity(compressed) != {
            "sha256": shared_compressed_output.get("sha256"),
            "size": shared_compressed_output.get("size"),
        }:
            raise MatrixFailure(
                f"{label} compressed output differs from the retained shared output"
            )
        compressed_reference = dict(shared_compressed_output)
    return {
        "application_runs": published_runs,
        "compressed_output": compressed_reference,
        "oracle_report": publish_reference(
            report,
            artifact_root,
            f"{prefix}/oracle-report.json",
        ),
        "application_timing": publish_reference(
            timing,
            artifact_root,
            f"{prefix}/application-timing.json",
        ),
    }


def publish_fault_raw_artifacts(
    artifact_root: Path,
    fault: dict[str, object],
) -> dict[str, object]:
    published = dict(fault)
    stderr_path = published.pop("_raw_stderr_path", None)
    process_path = published.pop("_raw_process_observation_path", None)
    name = published.get("fault")
    if (
        not isinstance(stderr_path, Path)
        or not isinstance(process_path, Path)
        or not isinstance(name, str)
    ):
        raise MatrixFailure("fault raw artifact set is malformed")
    match = re.fullmatch(r"(cut-[12])-([a-z0-9-]+)", name)
    if match is None:
        raise MatrixFailure(f"fault identity is not canonical: {name!r}")
    if stderr_path.stat().st_size > MAX_FAULT_STDERR_BYTES:
        raise MatrixFailure(f"fault stderr exceeds its bounded retention limit: {name}")
    if process_path.stat().st_size > MAX_FAULT_PROCESS_OBSERVATION_BYTES:
        raise MatrixFailure(
            f"fault process observation exceeds its bounded retention limit: {name}"
        )
    prefix = f"raw/faults/{match.group(1)}/{match.group(2)}"
    published["raw_stderr"] = publish_reference(
        stderr_path,
        artifact_root,
        f"{prefix}.stderr",
    )
    published["raw_process_observation"] = publish_reference(
        process_path,
        artifact_root,
        f"{prefix}.process.json",
    )
    return published


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=Path("target/.ci-artifacts/stock-zstd-build"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "target/.ci-artifacts/stock-zstd-migration-matrix/summary.json"
        ),
    )
    parser.add_argument("--input-mib", type=int, default=DEFAULT_INPUT_MIB)
    parser.add_argument(
        "--stock-zstd",
        required=True,
        type=Path,
        help=(
            "package-owned native zstd executable used as the independent "
            "decompression oracle"
        ),
    )
    parser.add_argument(
        "--cut-write-occurrence",
        type=int,
        nargs="+",
        default=list(DEFAULT_CUT_WRITE_OCCURRENCES),
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--keep-work", type=Path)
    return parser.parse_args()


def validate_formal_workload_arguments(
    input_mib: int, cut_write_occurrences: Sequence[int]
) -> None:
    if input_mib != DEFAULT_INPUT_MIB:
        raise MatrixFailure(
            f"formal stock-zstd evidence requires exactly {DEFAULT_INPUT_MIB} MiB"
        )
    if tuple(cut_write_occurrences) != tuple(DEFAULT_CUT_WRITE_OCCURRENCES):
        raise MatrixFailure(
            "formal stock-zstd evidence requires the exact ordered cuts "
            + ",".join(str(value) for value in DEFAULT_CUT_WRITE_OCCURRENCES)
        )


@contextlib.contextmanager
def work_directory(requested: Path | None) -> Iterator[Path]:
    if requested is None:
        with tempfile.TemporaryDirectory(
            prefix="visa-stock-zstd-migration-"
        ) as value:
            root = Path(value)
            root.chmod(0o700)
            yield root
    else:
        requested.mkdir(mode=0o700, parents=True)
        if any(requested.iterdir()):
            raise MatrixFailure("--keep-work directory must be empty")
        yield requested.resolve()


def main() -> int:
    arguments = parse_args()
    repository = Path(
        run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=Path.cwd(),
        ).stdout.decode().strip()
    )
    repository_revision = run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=repository,
    ).stdout.decode().strip()
    if (
        len(repository_revision) != 40
        or any(character not in "0123456789abcdef" for character in repository_revision)
    ):
        raise MatrixFailure("repository HEAD is not an exact lowercase Git SHA")
    source_snapshot = repository_snapshot(repository)
    if not source_snapshot["clean"]:
        raise MatrixFailure("repository must be clean before the formal matrix runs")
    validate_formal_workload_arguments(
        arguments.input_mib, arguments.cut_write_occurrence
    )
    artifact_root = (repository / arguments.artifact_root).resolve()
    output = (repository / arguments.output).resolve()
    if output.exists() or output.is_symlink():
        raise MatrixFailure(f"refusing to replace an existing matrix receipt: {output}")
    if (output.parent / "raw").exists() or (output.parent / "raw").is_symlink():
        raise MatrixFailure(
            f"refusing an existing raw artifact root: {output.parent / 'raw'}"
        )
    if not arguments.skip_build:
        run(
            [repository / "scripts" / "build-stock-zstd.sh"],
            cwd=repository,
            timeout=3600,
        )
    run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "-p",
            "visa_wasi_host",
            "-p",
            "visa_wasi_migration",
        ],
        cwd=repository,
        timeout=1200,
    )
    build_receipt, executable = verify_build_artifacts(artifact_root)
    docker = require_tool("docker")
    execution_input_binding = verify_execution_inputs(
        repository, docker, build_receipt
    )
    runtime = DockerAot(
        docker,
        execution_input_binding["wanco_image_id"],
        executable,
    )
    cargo_target = Path(
        json.loads(
            run(
                ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
                cwd=repository,
            ).stdout
        )["target_directory"]
    )
    host_binary = cargo_target / "release" / "visa_wasi_host"
    bind_binary = cargo_target / "release" / "visa-wasi-migration-bind"
    if not host_binary.is_file() or not bind_binary.is_file():
        raise MatrixFailure("required release control binaries are absent")

    zstd = arguments.stock_zstd.resolve()
    zstd_identity = native_zstd_identity(arguments.stock_zstd, repository)
    runtime_sha256 = execution_input_binding["wanco_runtime_sha256"]

    with work_directory(arguments.keep_work) as work:
        input_path = work / "input.bin"
        write_deterministic_input(
            input_path, arguments.input_mib * 1024 * 1024
        )
        control, control_raw = run_control(
            work, host_binary, runtime, input_path, zstd
        )
        migrated_cells: list[dict[str, object]] = []
        migrated_raw: list[dict[str, object]] = []
        fault_cells: list[dict[str, object]] = []
        for index, write_occurrence in enumerate(
            arguments.cut_write_occurrence
        ):
            cell, faults, raw = run_migrated_cell(
                work,
                index,
                write_occurrence,
                host_binary,
                bind_binary,
                runtime,
                input_path,
                zstd,
                build_receipt,
                execution_input_binding[
                    "stock_zstd_source_lock_sha256"
                ],
                runtime_sha256,
                control,
            )
            migrated_cells.append(cell)
            migrated_raw.append(raw)
            fault_cells.extend(faults)
        if len(fault_cells) != len(arguments.cut_write_occurrence) * 5:
            raise MatrixFailure(
                "each migration cut must publish exactly five fault cells"
            )
        checkpoint_digests = {
            str(
                require_object(
                    require_object(cell.get("cut"), "migration cut").get(
                        "checkpoint"
                    ),
                    "migration checkpoint",
                ).get("sha256")
            )
            for cell in migrated_cells
        }
        if len(checkpoint_digests) != len(migrated_cells):
            raise MatrixFailure(
                "migration cuts did not produce distinct compute checkpoints"
            )

        early_activation = run(
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "visa_wasi_migration",
                "--test",
                "migration",
                "activation_before_commit_or_fence_is_fail_closed",
                "--",
                "--exact",
            ],
            cwd=repository,
            timeout=600,
        )
        contract_checks = [
            {
                "check": "activation-before-canonical-commit-and-fence",
                "scope": "driver-contract-unit-test-not-live-e2e",
                "rejected_by": "visa_wasi_migration::Driver",
                "test_stdout_sha256": hashlib.sha256(
                    early_activation.stdout
                ).hexdigest(),
            }
        ]
        final_revision = run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=repository,
        ).stdout.decode().strip()
        final_snapshot = repository_snapshot(repository)
        if final_revision != repository_revision:
            raise MatrixFailure("repository HEAD changed while the matrix was running")
        if final_snapshot != source_snapshot or not final_snapshot["clean"]:
            raise MatrixFailure(
                "repository source snapshot changed while the matrix was running"
            )

        control["raw_artifacts"] = publish_positive_raw_artifacts(
            output.parent,
            "control",
            control_raw,
        )
        shared_compressed_output = control["raw_artifacts"]["compressed_output"]
        if not isinstance(shared_compressed_output, dict):
            raise MatrixFailure("control omitted its shared compressed output")
        for index, (cell, raw) in enumerate(
            zip(migrated_cells, migrated_raw, strict=True),
            start=1,
        ):
            cell["raw_artifacts"] = publish_positive_raw_artifacts(
                output.parent,
                f"cut-{index}",
                raw,
                shared_compressed_output=shared_compressed_output,
            )
        fault_cells = [
            publish_fault_raw_artifacts(output.parent, fault)
            for fault in fault_cells
        ]
        sealed_revision = run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=repository,
        ).stdout.decode().strip()
        sealed_snapshot = repository_snapshot(repository)
        if (
            sealed_revision != repository_revision
            or sealed_snapshot != source_snapshot
            or not sealed_snapshot["clean"]
        ):
            raise MatrixFailure(
                "repository changed while raw matrix artifacts were being sealed"
            )
        receipt = {
            "schema": SCHEMA,
            "repository_revision": repository_revision,
            "repository_source_snapshot": source_snapshot,
            "source_lock_sha256": execution_input_binding[
                "stock_zstd_source_lock_sha256"
            ],
            "stock_zstd_build_receipt_sha256": sha256_file(
                artifact_root / "receipt.json"
            ),
            "wanco_build_receipt_sha256": execution_input_binding[
                "wanco_build_receipt_sha256"
            ],
            "execution_input_binding": execution_input_binding,
            "wanco_optimization": build_receipt["wanco_optimization"],
            "zero_upstream_zstd_source_patches": build_receipt[
                "zero_upstream_source_patches"
            ],
            "input": file_identity(input_path),
            "external_oracle": {
                "program": zstd_identity,
                "observation": "decompress compressed bytes and compare raw SHA-256 and size",
            },
            "authority_model": {
                "mode": "trusted-local-orchestration",
                "artifact_and_receipt_binding_verified": True,
                "external_authority_authenticity_verified": False,
            },
            "control": control,
            "migrated_cells": migrated_cells,
            "fault_cells": fault_cells,
            "contract_checks": contract_checks,
            "raw_oracle_artifacts_retained": True,
            "raw_fault_artifacts_retained": True,
        }
        publish_receipt(output, receipt)
    print(f"stock-zstd transparent migration matrix: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ArtifactError, MatrixFailure, OSError, subprocess.TimeoutExpired) as error:
        print(f"stock-zstd migration matrix failed: {error}", file=sys.stderr)
        raise SystemExit(1)
