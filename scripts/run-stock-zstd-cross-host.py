#!/usr/bin/env python3
"""Run one native x86-64 stock-zstd clean handoff over OpenSSH.

The controller reuses the exact post-hostcall checkpoint function from the
canonical same-host runner.  Remote subcommands are intentionally contained in
this file so the transferred helper has no repository checkout dependency.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
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
from typing import Any, Iterator, Mapping, Sequence

import stock_zstd_cross_host as evidence


PROCESS_TIMEOUT_SECONDS = 300
REMOTE_ROOT_RE = re.compile(r"^/tmp/visa-stock-zstd-cross-host\.[A-Za-z0-9]+$")
REMOTE_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$")
HOST_KEY_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


class RunFailure(RuntimeError):
    pass


def run(
    command: Sequence[os.PathLike[str] | str],
    *,
    cwd: Path,
    input_bytes: bytes | None = None,
    timeout: int = PROCESS_TIMEOUT_SECONDS,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        [os.fspath(value) for value in command],
        cwd=cwd,
        env=env,
        input=input_bytes,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        tail = completed.stderr.decode("utf-8", errors="replace")[-4000:]
        raise RunFailure(
            f"command {Path(os.fspath(command[0])).name} failed with status "
            f"{completed.returncode}: {tail}"
        )
    return completed


def load_same_host_runner(repository: Path) -> Any:
    path = repository / "scripts" / "run-stock-zstd-migration-matrix.py"
    spec = importlib.util.spec_from_file_location("visa_stock_zstd_same_host_runner", path)
    if spec is None or spec.loader is None:
        raise RunFailure("cannot load the canonical stock-zstd runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "checkpoint_source", None)):
        raise RunFailure("canonical runner has no exact checkpoint_source function")
    return module


def write_json(path: Path, value: object) -> None:
    path.write_bytes(evidence.canonical_bytes(value) + b"\n")


def read_json(path: Path, label: str) -> Any:
    return evidence.parse_canonical_json(path.read_bytes(), label)


def ref(path: Path, root: Path) -> dict[str, object]:
    return {
        "path": path.resolve().relative_to(root.resolve()).as_posix(),
        **evidence.file_identity(path),
    }


def bytes_identity(payload: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def timing_phase(name: str, start: int, end: int) -> dict[str, object]:
    if end <= start:
        raise RunFailure(f"timing phase {name} is not positive")
    return {
        "phase": name,
        "start_monotonic_ns": start,
        "end_monotonic_ns": end,
        "duration_ns": end - start,
    }


def checked_build_configuration_sha256(execution: Mapping[str, object]) -> str:
    """Return the source-lock digest used as the migration build identity.

    ``verify_execution_inputs`` owns the provenance check; this local guard
    makes the cross-host glue fail clearly if that canonical contract changes.
    """

    value = execution.get("stock_zstd_source_lock_sha256")
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RunFailure(
            "validated execution binding has no canonical stock-zstd source-lock digest"
        )
    return value


def ensure_private_directory(path: Path) -> None:
    """Create an owned runner directory with the mode required by the host."""

    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)


def remote_provider_command(root: Path, request: dict[str, Any], *args: str | Path) -> list[str]:
    return [
        os.fspath(root / "tools" / "visa_wasi_host"),
        "control",
        os.fspath(root / "destination" / "provider.sock"),
        request["destination_admin_capability"],
        *map(os.fspath, args),
    ]


@contextlib.contextmanager
def remote_provider(root: Path, request: dict[str, Any]) -> Iterator[subprocess.Popen[bytes]]:
    destination = root / "destination"
    ensure_private_directory(destination)
    socket = destination / "provider.sock"
    socket.unlink(missing_ok=True)
    stdout = (destination / "provider.stdout").open("ab")
    stderr = (destination / "provider.stderr").open("ab")
    process = subprocess.Popen(
        [
            root / "tools" / "visa_wasi_host",
            "serve",
            destination / "provider" / "state.sqlite",
            socket,
        ],
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RunFailure(f"remote provider exited during startup: {process.returncode}")
            if socket.exists():
                status = run(
                    remote_provider_command(root, request, "status"),
                    cwd=destination,
                    check=False,
                    timeout=10,
                )
                if status.returncode == 0:
                    break
            time.sleep(0.025)
        else:
            raise RunFailure("remote provider did not publish its socket")
        yield process
    finally:
        if process.poll() is None:
            with contextlib.suppress(Exception):
                run(
                    remote_provider_command(root, request, "shutdown"),
                    cwd=destination,
                    check=False,
                    timeout=10,
                )
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=10)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        stdout.close()
        stderr.close()


def parse_status(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RunFailure(f"cannot parse {label} status: {error}") from error
    if not isinstance(value, dict):
        raise RunFailure(f"{label} status is not an object")
    return value


def verify_transfer_manifest(root: Path) -> None:
    document = read_json(root / "transfer-manifest.json", "transfer manifest")
    if not isinstance(document, dict) or set(document) != {"objects", "schema"}:
        raise RunFailure("transfer manifest shape differs")
    if document["schema"] != "visa-stock-zstd-cross-host-transfer-v1":
        raise RunFailure("transfer manifest schema differs")
    objects = document["objects"]
    if not isinstance(objects, list) or not objects:
        raise RunFailure("transfer manifest is empty")
    for item in objects:
        if not isinstance(item, dict) or set(item) != {"identity", "label", "path"}:
            raise RunFailure("transfer object shape differs")
        path = Path(item["path"])
        if path.is_absolute() or ".." in path.parts:
            raise RunFailure("transfer object path is unsafe")
        candidate = root / path
        if candidate.is_symlink() or not candidate.is_file():
            raise RunFailure(f"transfer object is absent or unsafe: {item['label']}")
        actual = evidence.file_identity(candidate)
        if actual != item["identity"]:
            raise RunFailure(f"transfer object differs: {item['label']}")


def remote_hello() -> int:
    write_json_to_stdout(evidence.endpoint_observation(Path(__file__)))
    return 0


def load_remote_request(root: Path) -> dict[str, Any]:
    request = read_json(root / "request.json", "remote request")
    required = {
        "destination_admin_capability",
        "destination_client",
        "destination_guest_capability",
        "handoff",
        "owner",
        "session",
    }
    if not isinstance(request, dict) or set(request) != required:
        raise RunFailure("remote request shape differs")
    for field in required:
        if not isinstance(request[field], str) or not request[field]:
            raise RunFailure(f"remote request {field} is empty")
    return request


def remote_prepare(root: Path) -> int:
    root = root.resolve()
    verify_transfer_manifest(root)
    request = load_remote_request(root)
    destination = root / "destination"
    database = destination / "provider" / "state.sqlite"
    # The provider creates its own immediate database parent.  The socket is
    # placed directly under ``destination``, which must itself be private.
    ensure_private_directory(destination)
    restored = run(
        [
            root / "tools" / "visa_wasi_host",
            "restore",
            root / "binding" / "capsule",
            database,
            request["destination_admin_capability"],
            request["destination_guest_capability"],
        ],
        cwd=root,
        check=False,
    )
    if restored.returncode != 0:
        raise RunFailure(
            "remote destination provider restore failed: "
            + restored.stderr.decode("utf-8", errors="replace")[-2000:]
        )
    with remote_provider(root, request):
        status = run(remote_provider_command(root, request, "status"), cwd=destination)
        prepared = parse_status(status.stdout, "prepared destination")
    observation = {
        "schema": "visa-stock-zstd-cross-host-remote-prepare-v1",
        "endpoint": evidence.endpoint_observation(Path(__file__)),
        "prepared_status": prepared,
    }
    write_json(root / "prepared-observation.json", observation)
    write_json_to_stdout(observation)
    return 0


def remote_resume(root: Path) -> int:
    root = root.resolve()
    verify_transfer_manifest(root)
    request = load_remote_request(root)
    destination = root / "destination"
    with remote_provider(root, request):
        verified = run(
            [
                root / "tools" / "visa-wasi-migration-bind",
                "verify-proofs",
                root / "binding",
                "migration-manifest.json",
                "proofs/commit.json",
                "proofs/fence.json",
            ],
            cwd=root,
            check=False,
        )
        if verified.returncode != 0:
            raise RunFailure(
                "remote manifest/proof verification failed: "
                + verified.stderr.decode("utf-8", errors="replace")[-2000:]
            )
        prepared = parse_status(
            run(remote_provider_command(root, request, "status"), cwd=destination).stdout,
            "reopened prepared destination",
        )
        active = parse_status(
            run(
                remote_provider_command(root, request, "activate", request["handoff"], "2"),
                cwd=destination,
            ).stdout,
            "active destination",
        )
        stdout_path = destination / "destination.stdout"
        stderr_path = destination / "destination.stderr"
        environment = {
            **os.environ,
            "VISA_WASI_SOCKET": os.fspath(destination / "provider.sock"),
            "VISA_WASI_SESSION_ID": request["session"],
            "VISA_WASI_OWNER_ID": request["owner"],
            "VISA_WASI_CLIENT_ID": request["destination_client"],
            "VISA_WASI_GUEST_CAPABILITY": request["destination_guest_capability"],
            "VISA_WASI_AUTHORITY_EPOCH": "2",
        }
        command = [
            root / "runtime" / "ld-linux-x86-64.so.2",
            "--library-path",
            root / "runtime" / "lib",
            root / "binding" / "artifacts" / "application.aot",
            "--restore",
            root / "binding" / "artifacts" / "checkpoint.pb",
            "--",
            "-q",
            "-f",
            "input.bin",
            "-o",
            "output.zst",
        ]
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.run(
                list(map(os.fspath, command)),
                cwd=destination,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=PROCESS_TIMEOUT_SECONDS,
                check=False,
            )
        if process.returncode != 0:
            tail = stderr_path.read_text(encoding="utf-8", errors="replace")[-3000:]
            raise RunFailure(f"remote Wanco continuation failed: {process.returncode}: {tail}")
        output = destination / "migrated-output.zst"
        run(
            remote_provider_command(root, request, "materialize", "output.zst", output),
            cwd=destination,
        )
        final = parse_status(
            run(remote_provider_command(root, request, "status"), cwd=destination).stdout,
            "final destination",
        )
    observation = {
        "schema": evidence.REMOTE_SCHEMA,
        "endpoint": evidence.endpoint_observation(Path(__file__)),
        "prepared_status": prepared,
        "active_status": active,
        "final_status": final,
        "process": {
            "exit_status": process.returncode,
            "stdout": evidence.file_identity(stdout_path),
            "stderr": evidence.file_identity(stderr_path),
        },
        "materialized_output": evidence.file_identity(output),
    }
    write_json(root / "remote-observation.json", observation)
    write_json_to_stdout(observation)
    return 0


def write_json_to_stdout(value: object) -> None:
    sys.stdout.buffer.write(evidence.canonical_bytes(value) + b"\n")
    sys.stdout.buffer.flush()


class SshEndpoint:
    def __init__(
        self,
        *,
        remote: str,
        port: int,
        expected_host_key: str,
        identity_file: Path | None,
        scratch: Path,
    ) -> None:
        self.remote = remote
        self.port = port
        self.expected_host_key = expected_host_key
        self.identity_file = identity_file
        self.scratch = scratch
        self.known_hosts = scratch / "known_hosts"
        self.control = scratch / "ssh-control"
        self.remote_root: str | None = None

    def start(self) -> None:
        scan = run(
            ["ssh-keyscan", "-T", "10", "-p", str(self.port), "-t", "ed25519", self.remote.split("@", 1)[1]],
            cwd=self.scratch,
            check=False,
            timeout=15,
        )
        if scan.returncode != 0 or not scan.stdout:
            raise RunFailure("remote endpoint did not publish an ED25519 host key")
        self.known_hosts.write_bytes(scan.stdout)
        self.known_hosts.chmod(0o400)
        fingerprint = run(
            ["ssh-keygen", "-lf", self.known_hosts, "-E", "sha256"], cwd=self.scratch
        ).stdout.decode().split()
        if len(fingerprint) < 2 or fingerprint[1] != self.expected_host_key:
            observed = fingerprint[1] if len(fingerprint) >= 2 else "unavailable"
            raise RunFailure(
                f"remote ED25519 host-key mismatch: expected {self.expected_host_key}, observed {observed}"
            )
        command = ["ssh", "-M", "-S", self.control, "-N", "-f", *self.base_options(batch=False), self.remote]
        # Password authentication, when selected by OpenSSH, happens on the
        # caller's terminal.  The runner never reads or stores that password.
        completed = subprocess.run(command, cwd=self.scratch, timeout=60, check=False)
        if completed.returncode != 0:
            raise RunFailure(f"cannot establish SSH control connection: {completed.returncode}")

    def base_options(self, *, batch: bool) -> list[str]:
        values = [
            "-F", "/dev/null",
            "-p", str(self.port),
            "-o", f"BatchMode={'yes' if batch else 'no'}",
            "-o", "ConnectTimeout=15",
            "-o", "ConnectionAttempts=1",
            "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "IdentitiesOnly=yes",
            "-o", "LogLevel=ERROR",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
        ]
        if self.identity_file is not None:
            values.extend(["-o", f"IdentityFile={self.identity_file}"])
        return values

    def ssh(self, *arguments: str, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return run(
            ["ssh", "-S", self.control, *self.base_options(batch=True), self.remote, *arguments],
            cwd=self.scratch,
            input_bytes=input_bytes,
            timeout=PROCESS_TIMEOUT_SECONDS,
            check=check,
        )

    def scp_to(self, source: Path, remote_path: str, *, recursive: bool = False) -> None:
        command = [
            "scp", "-F", "/dev/null", "-P", str(self.port),
            "-o", f"ControlPath={self.control}", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self.known_hosts}",
        ]
        if recursive:
            command.append("-r")
        command.extend([source, f"{self.remote}:{remote_path}"])
        completed = subprocess.run(list(map(os.fspath, command)), cwd=self.scratch, timeout=600, check=False)
        if completed.returncode != 0:
            raise RunFailure(f"scp upload failed with status {completed.returncode}")

    def scp_from(self, remote_path: str, destination: Path) -> None:
        command = [
            "scp", "-F", "/dev/null", "-P", str(self.port),
            "-o", f"ControlPath={self.control}", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self.known_hosts}",
            f"{self.remote}:{remote_path}", destination,
        ]
        completed = subprocess.run(list(map(os.fspath, command)), cwd=self.scratch, timeout=600, check=False)
        if completed.returncode != 0:
            raise RunFailure(f"scp download failed with status {completed.returncode}")

    def close(self) -> None:
        if self.remote_root is not None and REMOTE_ROOT_RE.fullmatch(self.remote_root):
            with contextlib.suppress(Exception):
                self.ssh("rm", "-rf", "--", self.remote_root, check=False)
        with contextlib.suppress(Exception):
            subprocess.run(
                ["ssh", "-S", self.control, "-O", "exit", *self.base_options(batch=True), self.remote],
                cwd=self.scratch,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )


def extract_runtime_closure(local: Any, runtime: Any, output: Path) -> list[dict[str, object]]:
    output.mkdir(mode=0o700)
    library_root = output / "lib"
    library_root.mkdir()
    script = r'''
set -eu
app=$1
out=$2
ldd "$app" > /tmp/visa-zstd-ldd
if grep -q 'not found' /tmp/visa-zstd-ldd; then cat /tmp/visa-zstd-ldd >&2; exit 1; fi
awk '$2 == "=>" && $3 ~ /^\// { print $1 " " $3 }
     $1 ~ /^\// { name=$1; sub(".*/", "", name); print name " " $1 }' /tmp/visa-zstd-ldd |
while read -r name source; do cp -L -- "$source" "$out/lib/$name"; done
loader=$(awk '$1 ~ /^\// && $1 ~ /ld-linux/ { print $1; exit }' /tmp/visa-zstd-ldd)
test -n "$loader"
cp -L -- "$loader" "$out/ld-linux-x86-64.so.2"
'''
    app_in_container = f"/aot/{runtime.executable.name}"
    local.run(
        [
            runtime.docker,
            "run", "--rm", "--network", "none", "--security-opt", "label=disable",
            "--volume", f"{runtime.executable.parent.resolve()}:/aot:ro",
            "--volume", f"{output.resolve()}:/closure",
            runtime.image,
            "sh", "-ec", script, "sh", app_in_container, "/closure",
        ],
        cwd=output,
        timeout=300,
    )
    objects = [
        {"label": "runtime-loader", "path": "runtime/ld-linux-x86-64.so.2", "identity": evidence.file_identity(output / "ld-linux-x86-64.so.2")}
    ]
    for path in sorted(library_root.iterdir()):
        if path.is_file() and not path.is_symlink():
            objects.append(
                {"label": f"runtime-library:{path.name}", "path": f"runtime/lib/{path.name}", "identity": evidence.file_identity(path)}
            )
    if len(objects) < 2:
        raise RunFailure("Wanco runtime closure is empty")
    return objects


def transfer_inventory(deployment: Path) -> list[dict[str, object]]:
    fixed = dict([
        ("application-aot", "binding/artifacts/application.aot"),
        ("checkpoint", "binding/artifacts/checkpoint.pb"),
        ("capsule-manifest", "binding/capsule/manifest.json"),
        ("capsule-state", "binding/capsule/state.sqlite"),
        ("provider-binary", "tools/visa_wasi_host"),
        ("proof-binder", "tools/visa-wasi-migration-bind"),
        ("remote-helper", "tools/run-stock-zstd-cross-host.py"),
        ("remote-validator-library", "tools/stock_zstd_cross_host.py"),
        ("runtime-loader", "runtime/ld-linux-x86-64.so.2"),
    ])
    labels_by_path = {path: label for label, path in fixed.items()}
    objects: list[dict[str, object]] = []
    for path in sorted(candidate for candidate in deployment.rglob("*") if candidate.is_file()):
        relative = path.relative_to(deployment).as_posix()
        if relative in {"request.json", "transfer-manifest.json"}:
            continue
        label = labels_by_path.get(relative)
        if label is None and relative.startswith("runtime/lib/"):
            label = f"runtime-library:{path.name}"
        if label is None:
            label = f"bound-object:{relative}"
        objects.append(
            {
                "label": label,
                "path": relative,
                "identity": evidence.file_identity(path),
            }
        )
    return objects


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="role")
    subparsers.add_parser("remote-hello")
    prepare = subparsers.add_parser("remote-prepare")
    prepare.add_argument("root", type=Path)
    resume = subparsers.add_parser("remote-resume")
    resume.add_argument("root", type=Path)
    parser.add_argument("--artifact-root", type=Path, default=Path("target/.ci-artifacts/stock-zstd-build"))
    parser.add_argument("--output", type=Path, default=Path("target/.ci-artifacts/stock-zstd-cross-host/receipt.json"))
    parser.add_argument("--stock-zstd", type=Path)
    parser.add_argument("--remote")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--host-key-sha256")
    parser.add_argument("--identity-file", type=Path)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--keep-work", type=Path)
    return parser.parse_args()


def main_controller(arguments: argparse.Namespace) -> int:
    if arguments.stock_zstd is None or arguments.remote is None or arguments.host_key_sha256 is None:
        raise RunFailure("controller requires --stock-zstd, --remote, and --host-key-sha256")
    if REMOTE_RE.fullmatch(arguments.remote) is None:
        raise RunFailure("remote endpoint must have the shell-safe form user@host")
    if not (1 <= arguments.port <= 65535):
        raise RunFailure("SSH port is outside 1..65535")
    if HOST_KEY_RE.fullmatch(arguments.host_key_sha256) is None:
        raise RunFailure("--host-key-sha256 is not an OpenSSH SHA-256 fingerprint")
    if arguments.identity_file is not None:
        identity_file = arguments.identity_file.resolve()
        metadata = identity_file.stat()
        if not identity_file.is_file() or identity_file.is_symlink() or metadata.st_mode & 0o077:
            raise RunFailure("SSH identity must be a private non-symlink regular file")
    else:
        identity_file = None

    repository = Path(
        run(["git", "rev-parse", "--show-toplevel"], cwd=Path.cwd()).stdout.decode().strip()
    )
    revision = run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.decode().strip()
    local = load_same_host_runner(repository)
    source_snapshot = local.repository_snapshot(repository)
    if not source_snapshot["clean"]:
        raise RunFailure("repository must be clean before formal cross-host evidence runs")
    artifact_root = (repository / arguments.artifact_root).resolve()
    output = (repository / arguments.output).resolve()
    if output.exists() or output.parent.exists():
        raise RunFailure("refusing an existing cross-host output root")
    if not arguments.skip_build:
        local.run([repository / "scripts" / "build-stock-zstd.sh"], cwd=repository, timeout=3600)
    local.run(
        ["cargo", "build", "--release", "--locked", "-p", "visa_wasi_host", "-p", "visa_wasi_migration"],
        cwd=repository,
        timeout=1200,
    )
    build_receipt, executable = local.verify_build_artifacts(artifact_root)
    docker = local.require_tool("docker")
    execution = local.verify_execution_inputs(repository, docker, build_receipt)
    runtime = local.DockerAot(docker, execution["wanco_image_id"], executable)
    build_configuration_sha256 = checked_build_configuration_sha256(execution)
    cargo_target = Path(
        json.loads(local.run(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=repository).stdout)["target_directory"]
    )
    host_binary = cargo_target / "release" / "visa_wasi_host"
    bind_binary = cargo_target / "release" / "visa-wasi-migration-bind"
    zstd = arguments.stock_zstd.resolve()
    local.native_zstd_identity(zstd, repository)

    requested = arguments.keep_work.resolve() if arguments.keep_work else None
    temporary_context: Any
    if requested is None:
        temporary_context = tempfile.TemporaryDirectory(prefix="visa-stock-zstd-cross-host-")
    else:
        requested.mkdir(mode=0o700, parents=True)
        if any(requested.iterdir()):
            raise RunFailure("--keep-work directory must be empty")
        temporary_context = contextlib.nullcontext(os.fspath(requested))

    with temporary_context as value:
        work = Path(value)
        input_path = work / "input.bin"
        local.write_deterministic_input(input_path, evidence.CANONICAL_INPUT_BYTES)
        control, control_raw = local.run_control(work, host_binary, runtime, input_path, zstd)
        case = work / "cross-host-cut-64"
        source = case / "source"
        binding = case / "binding"
        for directory in (case, source, binding, binding / "artifacts", binding / "proofs"):
            local.ensure_private_directory(directory)
        session = local.stable_id("cross-host-cut-64-session")
        owner = local.stable_id("cross-host-cut-64-owner")
        source_client = local.stable_id("cross-host-cut-64-source-client")
        source_restore_client = local.stable_id("cross-host-cut-64-source-restore-client")
        destination_client = local.stable_id("cross-host-cut-64-destination-client")
        handoff = local.stable_id("cross-host-cut-64-handoff")
        barrier = local.stable_id("cross-host-cut-64-checkpoint-barrier")
        source_admin = secrets.token_hex(32)
        source_guest = secrets.token_hex(32)
        destination_admin = secrets.token_hex(32)
        destination_guest = secrets.token_hex(32)
        source_database = source / "provider" / "state.sqlite"
        source_socket = source / "provider.sock"
        local.create_provider(host_binary, source_database, session, source_admin, source_guest, 1, input_path, source)

        phases: list[dict[str, object]] = []
        with local.Provider(host_binary, source_database, source_socket, source_admin, source) as provider:
            checkpoint_start = time.monotonic_ns()
            checkpoint, cut = local.checkpoint_source(
                runtime,
                case,
                source,
                provider,
                local.guest_environment(source_socket, session, owner, source_client, source_guest, 1),
                barrier,
                evidence.CUT_WRITE_OCCURRENCE,
            )
            checkpoint_end = time.monotonic_ns()
            phases.append(timing_phase("source-checkpoint", checkpoint_start, checkpoint_end))
            post_checkpoint = local.read_status(provider.control("status"))
            freeze_start = time.monotonic_ns()
            provider.control("freeze", barrier, handoff, "2")
            frozen = local.read_status(provider.control("status"))
            provider.control("export", binding / "capsule")
            local.copy_regular(runtime.executable, binding / "artifacts" / "application.aot")
            shutil.copy2(checkpoint, binding / "artifacts" / "checkpoint.pb")
            local.write_intent(
                binding / "intent.json",
                session=session,
                owner=owner,
                handoff=handoff,
                checkpoint_barrier=barrier,
                source_client=source_client,
                source_restore_client=source_restore_client,
                destination_client=destination_client,
                build_receipt=build_receipt,
                build_configuration_sha256=build_configuration_sha256,
                runtime_sha256=execution["wanco_runtime_sha256"],
            )
            seal = local.bind_command(bind_binary, "seal", binding, "intent.json", "migration-manifest.json")
            if seal.returncode != 0:
                raise RunFailure("cannot seal cross-host migration manifest")
            manifest_sha = seal.stdout.decode().strip()
            commit = {
                "action": "trusted-cross-host-commit-projection",
                "destination_epoch": 2,
                "handoff_hex": handoff,
                "migration_manifest_sha256": manifest_sha,
                "session_hex": session,
            }
            fence = {**commit, "action": "trusted-cross-host-fence-authorization"}
            (binding / "proofs" / "commit.receipt").write_bytes(evidence.canonical_bytes(commit))
            (binding / "proofs" / "fence.receipt").write_bytes(evidence.canonical_bytes(fence))
            proofs = local.bind_command(
                bind_binary,
                "bind-proofs",
                binding,
                "migration-manifest.json",
                "proofs/commit.receipt",
                "proofs/fence.receipt",
                "proofs/commit.json",
                "proofs/fence.json",
            )
            if proofs.returncode != 0:
                raise RunFailure("cannot bind cross-host migration proofs")
            freeze_end = time.monotonic_ns()
            phases.append(timing_phase("source-freeze-export", freeze_start, freeze_end))

            deployment = case / "deployment"
            shutil.copytree(binding, deployment / "binding")
            (deployment / "tools").mkdir(mode=0o700, parents=True)
            shutil.copy2(host_binary, deployment / "tools" / "visa_wasi_host")
            shutil.copy2(bind_binary, deployment / "tools" / "visa-wasi-migration-bind")
            shutil.copy2(Path(__file__), deployment / "tools" / "run-stock-zstd-cross-host.py")
            shutil.copy2(repository / "scripts" / "stock_zstd_cross_host.py", deployment / "tools" / "stock_zstd_cross_host.py")
            extract_runtime_closure(local, runtime, deployment / "runtime")
            request = {
                "session": session,
                "owner": owner,
                "handoff": handoff,
                "destination_client": destination_client,
                "destination_admin_capability": destination_admin,
                "destination_guest_capability": destination_guest,
            }
            write_json(deployment / "request.json", request)
            objects = transfer_inventory(deployment)
            write_json(deployment / "transfer-manifest.json", {"schema": "visa-stock-zstd-cross-host-transfer-v1", "objects": objects})

            transport_start = time.monotonic_ns()
            ssh_scratch = work / "ssh"
            ssh_scratch.mkdir(mode=0o700)
            endpoint = SshEndpoint(
                remote=arguments.remote,
                port=arguments.port,
                expected_host_key=arguments.host_key_sha256,
                identity_file=identity_file,
                scratch=ssh_scratch,
            )
            try:
                endpoint.start()
                remote_root = endpoint.ssh("mktemp", "-d", "/tmp/visa-stock-zstd-cross-host.XXXXXXXX").stdout.decode().strip()
                if REMOTE_ROOT_RE.fullmatch(remote_root) is None:
                    raise RunFailure("remote mktemp returned an unsafe path")
                endpoint.remote_root = remote_root
                endpoint.scp_to(deployment, remote_root, recursive=True)
                remote_deployment = f"{remote_root}/{deployment.name}"
                hello_bytes = endpoint.ssh(
                    "python3", f"{remote_deployment}/tools/run-stock-zstd-cross-host.py", "remote-hello"
                ).stdout
                remote_host = evidence.parse_canonical_json(hello_bytes, "remote endpoint hello")
                evidence.validate_host(remote_host, "remote endpoint")
                source_host = evidence.endpoint_observation(Path(__file__))
                if source_host["endpoint_id_sha256"] == remote_host["endpoint_id_sha256"]:
                    raise RunFailure("remote endpoint identity equals the source endpoint")
                prepared_bytes = endpoint.ssh(
                    "python3",
                    f"{remote_deployment}/tools/run-stock-zstd-cross-host.py",
                    "remote-prepare",
                    remote_deployment,
                ).stdout
                prepared_observation = evidence.parse_canonical_json(prepared_bytes, "remote prepared observation")
                prepared = prepared_observation["prepared_status"]
                evidence.validate_status(prepared, "remote prepared", mode="prepared", epoch=1)
                transport_end = time.monotonic_ns()
                phases.append(timing_phase("transfer-and-destination-prepare", transport_start, transport_end))

                fence_start = time.monotonic_ns()
                provider.control("fence", handoff, "2")
                source_fenced = local.read_status(provider.control("status"))
                fence_end = time.monotonic_ns()
                phases.append(timing_phase("source-fence", fence_start, fence_end))

                resume_start = time.monotonic_ns()
                remote_bytes = endpoint.ssh(
                    "python3",
                    f"{remote_deployment}/tools/run-stock-zstd-cross-host.py",
                    "remote-resume",
                    remote_deployment,
                ).stdout
                remote_observation = evidence.parse_canonical_json(remote_bytes, "remote observation")
                resume_end = time.monotonic_ns()
                phases.append(timing_phase("destination-activate-and-resume", resume_start, resume_end))

                fetch_start = time.monotonic_ns()
                retained = work / "retained"
                raw = retained / "raw"
                raw.mkdir(mode=0o700, parents=True)
                control_run = control_raw["application_runs"][0]
                control_label, control_stdout_source, control_stderr_source, control_exit = control_run
                if control_label != "control" or control_exit != 0:
                    raise RunFailure("uninterrupted control raw process observation differs")
                shutil.copy2(control_stdout_source, raw / "control.stdout")
                shutil.copy2(control_stderr_source, raw / "control.stderr")
                shutil.copy2(control_raw["oracle_report"], raw / "control-oracle-report.json")
                shutil.copy2(control_raw["application_timing"], raw / "control-application-timing.json")
                remote_paths = {
                    "remote-observation.json": "remote-observation.json",
                    "destination.stdout": "destination/destination.stdout",
                    "destination.stderr": "destination/destination.stderr",
                    "migrated-output.zst": "destination/migrated-output.zst",
                }
                for local_name, remote_name in remote_paths.items():
                    endpoint.scp_from(f"{remote_deployment}/{remote_name}", raw / local_name)
                write_json(raw / "remote-endpoint.json", remote_host)
                shutil.copy2(endpoint.known_hosts, raw / "known_hosts")
                shutil.copy2(deployment / "transfer-manifest.json", raw / "transfer-manifest.json")
                migrated = raw / "migrated-output.zst"
                oracle, _ = local.external_oracle(
                    zstd,
                    migrated,
                    input_path,
                    work / "cross-host-decoded.bin",
                    work,
                    "cross-host-cut-64",
                )
                if oracle["compressed"] != control["oracle"]["compressed"]:
                    raise RunFailure("cross-host output differs byte-for-byte from uninterrupted control")
                fetch_end = time.monotonic_ns()
                phases.append(timing_phase("output-fetch-and-external-oracle", fetch_start, fetch_end))
            finally:
                endpoint.close()

        timing = {"schema": evidence.TIMING_SCHEMA, "clock": "python-time.monotonic_ns-controller", "phases": phases}
        write_json(raw / "application-timing.json", timing)
        output.parent.mkdir(mode=0o700, parents=True)
        shutil.copytree(raw, output.parent / "raw")
        stdout_payload = (raw / "destination.stdout").read_bytes()
        stderr_payload = (raw / "destination.stderr").read_bytes()
        receipt = {
            "schema": evidence.SCHEMA,
            "repository_revision": revision,
            "repository_source_snapshot": source_snapshot,
            "case": {
                "workload": "stock-zstd-1.5.7-streaming-compression",
                "cut_location_source": "prearmed-post-hostcall-predicate",
                "cut_write_occurrence": evidence.CUT_WRITE_OCCURRENCE,
            },
            "input": evidence.file_identity(input_path),
            "build": {
                "application_aot": evidence.file_identity(runtime.executable),
                "stock_zstd_build_receipt_sha256": evidence.sha256_file(artifact_root / "receipt.json"),
                "wanco_build_receipt_sha256": execution["wanco_build_receipt_sha256"],
                "wanco_optimization": build_receipt["wanco_optimization"],
            },
            "topology": {
                "source_compute": "local-native-x86_64-wanco-aot",
                "source_provider": "local-process",
                "destination_compute": "remote-native-x86_64-wanco-aot",
                "destination_provider": "remote-fresh-process-restored-from-capsule",
                "provider_capsule_transferred": True,
                "transport": "openssh-content-addressed-files-plus-command-stdio",
                "ssh_host_key_sha256": arguments.host_key_sha256,
                "ssh_known_hosts_sha256": evidence.sha256_file(raw / "known_hosts"),
            },
            "source": {
                "endpoint": source_host,
                "post_checkpoint_status": post_checkpoint,
                "frozen_status": frozen,
                "fenced_status": source_fenced,
            },
            "destination": {
                "endpoint": remote_host,
                "prepared_status": remote_observation["prepared_status"],
                "active_status": remote_observation["active_status"],
                "final_status": remote_observation["final_status"],
                "process": remote_observation["process"],
            },
            "control": {
                "compressed_output": control["oracle"]["compressed"],
                "process": {
                    "exit_status": control_exit,
                    "stdout": evidence.file_identity(raw / "control.stdout"),
                    "stderr": evidence.file_identity(raw / "control.stderr"),
                },
            },
            "oracle": {
                "kind": "native-zstd-raw-decompression-and-control-byte-identity",
                "producer_verdict_used": False,
                **oracle,
            },
            "authority_boundary": {
                "trusted_coordinator": True,
                "source_fenced_before_destination_activation": True,
                "distributed_fencing": False,
                "cryptographic_host_attestation": False,
            },
            "timing": timing,
            "transfer_objects": objects,
            "artifacts": {
                "remote_endpoint_observation": ref(raw / "remote-endpoint.json", retained),
                "remote_observation": ref(raw / "remote-observation.json", retained),
                "destination_process_stdout": ref(raw / "destination.stdout", retained),
                "destination_process_stderr": ref(raw / "destination.stderr", retained),
                "shared_compressed_output": ref(migrated, retained),
                "application_timing": ref(raw / "application-timing.json", retained),
                "ssh_known_hosts": ref(raw / "known_hosts", retained),
                "transfer_manifest": ref(raw / "transfer-manifest.json", retained),
                "control_process_stdout": ref(raw / "control.stdout", retained),
                "control_process_stderr": ref(raw / "control.stderr", retained),
                "control_oracle_report": ref(raw / "control-oracle-report.json", retained),
                "control_application_timing": ref(raw / "control-application-timing.json", retained),
            },
            "explicit_non_claims": evidence.NON_CLAIMS,
        }
        staged = output.parent / ".incomplete"
        staged.write_text("incomplete\n", encoding="ascii")
        write_json(output, receipt)
        evidence.validate_receipt(output, expected_revision=revision, stock_zstd=zstd)
        staged.unlink()
    print(f"stock-zstd cross-host clean handoff: {output}")
    return 0


def main() -> int:
    arguments = parse_args()
    if arguments.role == "remote-hello":
        return remote_hello()
    if arguments.role == "remote-prepare":
        return remote_prepare(arguments.root)
    if arguments.role == "remote-resume":
        return remote_resume(arguments.root)
    return main_controller(arguments)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RunFailure, evidence.EvidenceError, OSError, subprocess.TimeoutExpired) as error:
        print(f"stock-zstd cross-host handoff failed: {error}", file=sys.stderr)
        raise SystemExit(1)
