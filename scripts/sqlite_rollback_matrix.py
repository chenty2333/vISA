#!/usr/bin/env python3
"""Exact-cut controller and evidence contract for stock SQLite rollback mode.

This module deliberately contains no workload simulator.  A matrix receipt is
valid only after a real stock-SQLite/Wanco run supplies every checkpoint,
handoff, namespace-snapshot, and independent-oracle identity required below.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Protocol

import wanco_typed_corpus as TYPED_CORPUS
import receipt_artifacts as ARTIFACTS
import wanco_process_diagnostics as WANCO_DIAGNOSTICS


PLAN_SCHEMA = "visa-stock-sqlite-rollback-journal-plan-v1"
CELL_SCHEMA = "visa-stock-sqlite-rollback-journal-cell-v4"
MATRIX_SCHEMA = "visa-stock-sqlite-rollback-journal-matrix-v9"
CONTROL_SCHEMA = "visa-stock-sqlite-uninterrupted-control-v3"
ORACLE_REPORT_SCHEMA = "visa-sqlite-oracle-report-v2"
ORACLE_PROJECTION_SCHEMA = "visa-sqlite-semantic-projection-v1"
EQUIVALENCE_PROJECTION_SCHEMA = "visa-stock-sqlite-equivalence-projection-v1"
PROCESS_RECOVERY_SCHEMA = "visa-sqlite-provider-process-recovery-v2"
PROCESS_RECOVERY_REPORT_SCHEMA = "visa-sqlite-provider-process-recovery-v1"
SOURCE_ABORT_SCHEMA = "visa-sqlite-source-abort-reconciliation-v2"
DRIVER_RECORD_SCHEMA = "visa-wasi-migration-driver-record-v4"
MIGRATION_MANIFEST_SCHEMA = "visa-transparent-wasi-migration-v3"
PROVIDER_SCHEMA_VERSION = 5
CANONICAL_AUTHORITY_STATE_SCHEMA = "visa-wasi-canonical-authority-state-v2"
SOURCE_RETAINED_PROOF_SCHEMA = "visa-canonical-source-retained-proof-v1"
SOURCE_RETAINED_RECEIPT_SCHEMA = "visa-wasi-authority-source-retained-receipt-v1"
DEFAULT_DATABASE_PATH = "workload/accounts.db"
DEFAULT_TIMEOUT_SECONDS = 120.0
POLL_INTERVAL_SECONDS = 0.02
SHA1_RE = re.compile(r"[0-9a-f]{40}")
MAX_SQLITE_STDOUT_BYTES = 4 * 1024 * 1024
MAX_SQLITE_STDERR_BYTES = 1024 * 1024
MAX_SQLITE_JSON_BYTES = 2 * 1024 * 1024
MAX_SQLITE_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_SQLITE_RETAINED_BYTES = 128 * 1024 * 1024
PROCESS_RECOVERY_COMMAND = (
    "cargo test --locked -p visa_wasi_host --test "
    "provider_process_recovery -- --nocapture"
)
PROCESS_RECOVERY_TESTS = (
    "response_loss_then_provider_kill_reopen_replays_exactly_once",
    "fd_sync_and_datasync_survive_provider_kill_reopen_in_process_crash_model",
)
PROCESS_RECOVERY_NONCLAIMS = (
    "power-loss",
    "torn-sector",
    "device-write-reordering",
)
SOURCE_ABORT_DRIVER_RUNS = (
    ("init", "init", "init_exit_status", 0),
    ("authority-init", "authority_init", "authority_init_exit_status", 0),
    (
        "commit-probe-init",
        "commit_probe_init",
        "commit_probe_init_exit_status",
        0,
    ),
    (
        "commit-probe-commit",
        "commit_probe_commit",
        "commit_probe_commit_exit_status",
        0,
    ),
    (
        "committed-probe-abort",
        "canonical_commit_abort",
        "canonical_commit_abort_exit_status",
        1,
    ),
    ("injected-recovery", "injected", "injected_exit_status", 75),
    ("restart-recovery", "recovered", "recovery_exit_status", 0),
)
CANONICAL_COMMIT_ABORT_STDERR = (
    b"visa-wasi-migration-driver: migration integrity failure: "
    b"canonical ownership committed from an incompatible local phase\n"
)


class MatrixFailure(RuntimeError):
    """The exact-cut protocol or retained evidence is invalid."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_identity(path: Path, *, allow_empty: bool = False) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise MatrixFailure(f"expected a regular retained artifact: {path}")
    size = path.stat().st_size
    if size == 0 and not allow_empty:
        raise MatrixFailure(f"retained artifact is empty: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "size": size}


def _canonical_guest_path(value: str) -> str:
    if not value or "\x00" in value:
        raise MatrixFailure("guest database path is empty or contains NUL")
    encoded = value.encode("utf-8")
    if len(encoded) > 4096:
        raise MatrixFailure("guest database path is too long")
    path = PurePosixPath(value)
    if path.is_absolute() or value.endswith("/"):
        raise MatrixFailure("guest database path must be relative and canonical")
    parts = path.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise MatrixFailure("guest database path must not contain dot components")
    canonical = path.as_posix()
    if canonical != value:
        raise MatrixFailure("guest database path is not canonical")
    return canonical


@dataclass(frozen=True)
class PredicateSpec:
    kind: str
    resource_role: str
    occurrence: int = 1
    outcome: str = "success"

    def render(self, database_path: str) -> dict[str, object]:
        database_path = _canonical_guest_path(database_path)
        resources = {
            "database": database_path,
            "journal": database_path + "-journal",
            "dotlock": database_path + ".lock",
        }
        try:
            path = resources[self.resource_role]
        except KeyError as error:
            raise MatrixFailure(
                f"unsupported SQLite resource role {self.resource_role!r}"
            ) from error
        if self.occurrence <= 0:
            raise MatrixFailure("barrier occurrence must be positive")
        return {
            "kind": self.kind,
            "resource": "path:" + path,
            "outcome": self.outcome,
            "occurrence": self.occurrence,
        }


@dataclass(frozen=True)
class CutSpec:
    cell_id: str
    sqlite_section: str
    sqlite_stage: str
    predicate: PredicateSpec
    target_phase: str = "held"
    continuation_witness: PredicateSpec | None = None
    external_anchor: str | None = None

    def render(self, database_path: str) -> dict[str, object]:
        result: dict[str, object] = {
            "cell_id": self.cell_id,
            "sqlite_atomic_commit_section": self.sqlite_section,
            "sqlite_stage": self.sqlite_stage,
            "predicate": self.predicate.render(database_path),
            "target_phase": self.target_phase,
        }
        if self.continuation_witness is not None:
            result["continuation_witness"] = self.continuation_witness.render(
                database_path
            )
        if self.external_anchor is not None:
            result["external_anchor"] = self.external_anchor
        return result


# Stock SQLite under __wasi__ selects unix-dotfile.  The first lock is an
# ordinary mkdir(<db>.lock); it does not call the private vISA VfsLock ABI.
CUT_SPECS: tuple[CutSpec, ...] = (
    CutSpec(
        "lock-acquired",
        "3.2",
        "first successful unix-dotfile lock-directory acquisition",
        PredicateSpec("path-create-directory", "dotlock"),
        continuation_witness=PredicateSpec("path-open", "journal"),
    ),
    CutSpec(
        "partial-journal",
        "3.5",
        "first rollback-journal write before journal construction completes",
        PredicateSpec("fd-write", "journal"),
        continuation_witness=PredicateSpec("fd-write", "journal"),
    ),
    CutSpec(
        "post-journal-sync",
        "3.7",
        "second successful rollback-journal sync before database-page writes",
        PredicateSpec("fd-sync", "journal", occurrence=2),
        continuation_witness=PredicateSpec("fd-write", "database"),
    ),
    CutSpec(
        "mid-db-page-write",
        "3.9",
        "second database-page write with a later database write required",
        PredicateSpec("fd-write", "database", occurrence=2),
        continuation_witness=PredicateSpec("fd-write", "database"),
    ),
    CutSpec(
        "post-db-sync",
        "3.10",
        "successful database sync before the rollback journal is deleted",
        PredicateSpec("fd-sync", "database"),
        continuation_witness=PredicateSpec("path-unlink-file", "journal"),
    ),
    CutSpec(
        "journal-delete-commit-point",
        "3.11",
        "successful DELETE-mode journal removal, SQLite's commit point",
        PredicateSpec("path-unlink-file", "journal"),
        external_anchor="transaction acknowledgement emitted exactly once",
    ),
    CutSpec(
        "lost-response",
        "3.11 + delivery fault",
        "journal-delete effect durable while its response is made uncertain",
        PredicateSpec("path-unlink-file", "journal"),
        target_phase="triggered",
        external_anchor="same source request replayed before completed-ACK drain",
    ),
    CutSpec(
        "active-read-cursor",
        "3.3",
        "twelfth database read after a nonterminal SELECT row prefix is visible",
        PredicateSpec("fd-read", "database", occurrence=12),
        external_anchor="strictly partial ordered row-output prefix",
    ),
)


def build_plan(database_path: str = DEFAULT_DATABASE_PATH) -> dict[str, object]:
    database_path = _canonical_guest_path(database_path)
    cells = [spec.render(database_path) for spec in CUT_SPECS]
    return {
        "schema": PLAN_SCHEMA,
        "artifact_class": "plan-not-execution-evidence",
        "database_path": database_path,
        "journal_mode": "delete",
        "synchronous": "full",
        "locking_substrate": {
            "name": "sqlite-unix-dotfile",
            "first_lock_operation": "path-create-directory",
            "path": database_path + ".lock",
            "visa_vfs_lock_extension_used": False,
        },
        "stock_wasi_io_imports": {
            "read": "fd_read",
            "write": "fd_write",
            "sync": "fd_sync",
        },
        "cut_location_source": "prearmed-hostcall-predicate",
        "bytes_written_polling_allowed": False,
        "cells": cells,
    }


def cell_plan(database_path: str, cell_id: str) -> dict[str, object]:
    for cell in build_plan(database_path)["cells"]:
        if cell["cell_id"] == cell_id:
            return cell
    raise MatrixFailure(f"unknown SQLite rollback-journal cell {cell_id!r}")


class ProviderControl(Protocol):
    def status(self) -> Mapping[str, object]: ...

    def arm(self, token: str, predicate: Mapping[str, object]) -> None: ...

    def release(self, token: str, action: str) -> None: ...


def _require_hex(value: object, bytes_count: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != bytes_count * 2:
        raise MatrixFailure(f"{label} must be {bytes_count * 2} lowercase hex digits")
    if value.lower() != value or any(character not in "0123456789abcdef" for character in value):
        raise MatrixFailure(f"{label} must be lowercase hexadecimal")
    if value == "0" * (bytes_count * 2):
        raise MatrixFailure(f"{label} must be nonzero")
    return value


def _effect_hex(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return _require_hex(value, 16, "barrier effect")
    if (
        isinstance(value, list)
        and len(value) == 16
        and all(isinstance(item, int) and 0 <= item <= 255 for item in value)
    ):
        return _require_hex(bytes(value).hex(), 16, "barrier effect")
    raise MatrixFailure("provider barrier effect has an unsupported encoding")


def status_projection(status: Mapping[str, object]) -> dict[str, object]:
    barrier = status.get("barrier")
    mode = status.get("mode")
    epoch = status.get("authority_epoch")
    remaining = status.get("barrier_remaining")
    if barrier not in {"open", "armed", "triggered", "held", "checkpoint_released"}:
        raise MatrixFailure("provider returned an unknown barrier phase")
    if mode not in {"active", "frozen", "prepared", "fenced"}:
        raise MatrixFailure("provider returned an unknown mode")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= 0:
        raise MatrixFailure("provider returned an invalid authority epoch")
    if remaining is not None and (
        not isinstance(remaining, int) or isinstance(remaining, bool) or remaining <= 0
    ):
        raise MatrixFailure("provider returned an invalid barrier remaining count")
    projection: dict[str, object] = {
        "mode": mode,
        "authority_epoch": epoch,
        "barrier": barrier,
        "barrier_remaining": remaining,
        "barrier_effect": _effect_hex(status.get("barrier_effect")),
    }
    for name in ("effects", "completed_requests"):
        value = status.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise MatrixFailure(f"provider returned an invalid {name} counter")
        projection[name] = value
    if projection["effects"] != projection["completed_requests"]:
        raise MatrixFailure("provider effect and completed-request counters diverged")
    return projection


class ExactBarrierController:
    """Drive the provider barrier without using workload progress counters."""

    def __init__(
        self,
        provider: ProviderControl,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
        pause: Callable[[float], None] = time.sleep,
    ) -> None:
        if timeout_seconds <= 0:
            raise MatrixFailure("barrier timeout must be positive")
        self.provider = provider
        self.timeout_seconds = timeout_seconds
        self.monotonic = monotonic
        self.pause = pause

    def arm(self, token: str, predicate: Mapping[str, object]) -> dict[str, object]:
        _require_hex(token, 16, "barrier token")
        _validate_predicate(predicate, "barrier predicate")
        before = status_projection(self.provider.status())
        if before["mode"] != "active" or before["barrier"] != "open":
            raise MatrixFailure("barrier must be armed from active/open")
        self.provider.arm(token, predicate)
        armed = status_projection(self.provider.status())
        if armed["mode"] != "active" or armed["barrier"] != "armed":
            raise MatrixFailure("provider did not enter active/armed")
        if armed["barrier_remaining"] != predicate["occurrence"]:
            raise MatrixFailure("provider armed a different occurrence")
        if armed["barrier_effect"] is not None:
            raise MatrixFailure("an armed barrier already has a target effect")
        return {"before": before, "armed": armed}

    def await_target(self, target_phase: str = "held") -> dict[str, object]:
        if target_phase not in {"held", "triggered"}:
            raise MatrixFailure("cut target phase must be held or triggered")
        deadline = self.monotonic() + self.timeout_seconds
        permitted = {"armed", "triggered"}
        if target_phase == "held":
            permitted.add("held")
        while self.monotonic() < deadline:
            status = status_projection(self.provider.status())
            phase = status["barrier"]
            if phase == target_phase:
                if status["mode"] != "active" or status["barrier_effect"] is None:
                    raise MatrixFailure("target barrier phase lacks its durable effect")
                return status
            if target_phase == "triggered" and phase == "held":
                raise MatrixFailure(
                    "lost-response injection did not stop guest completion"
                )
            if phase not in permitted:
                raise MatrixFailure(
                    f"barrier reached {phase!r} before target {target_phase!r}"
                )
            self.pause(POLL_INTERVAL_SECONDS)
        raise MatrixFailure(f"timed out waiting for barrier phase {target_phase}")

    def release_checkpoint(self, token: str, held: Mapping[str, object]) -> dict[str, object]:
        _require_hex(token, 16, "barrier token")
        if held.get("barrier") != "held" or held.get("barrier_effect") is None:
            raise MatrixFailure("checkpoint release requires a held target effect")
        self.provider.release(token, "checkpoint")
        released = status_projection(self.provider.status())
        if released["mode"] != "active" or released["barrier"] != "checkpoint_released":
            raise MatrixFailure("provider did not enter checkpoint_released")
        if released["barrier_effect"] != held["barrier_effect"]:
            raise MatrixFailure("checkpoint release changed the target effect")
        return released

    def release_continue(self, token: str, held: Mapping[str, object]) -> dict[str, object]:
        _require_hex(token, 16, "barrier token")
        if held.get("barrier") != "held" or held.get("barrier_effect") is None:
            raise MatrixFailure("continue release requires a held target effect")
        self.provider.release(token, "continue")
        released = status_projection(self.provider.status())
        if released["mode"] != "active" or released["barrier"] != "open":
            raise MatrixFailure("provider did not reopen after continue release")
        if released["barrier_effect"] is not None:
            raise MatrixFailure("continued barrier retained a target effect")
        return released


def execute_checkpoint_cut(
    provider: ProviderControl,
    *,
    token: str,
    predicate: Mapping[str, object],
    start_segment: Callable[[], None],
    await_checkpoint: Callable[[], Path],
    progress_guard: Callable[[], None] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Pre-arm, execute one segment, and retain an exact post-hostcall cut.

    ``start_segment`` may launch a process or release a workload-side gate. It
    is deliberately called only after the provider reports ``armed``.
    ``await_checkpoint`` is called only after ``checkpoint_released``.
    """

    def guarded_pause(seconds: float) -> None:
        if progress_guard is not None:
            progress_guard()
        time.sleep(seconds)

    controller = ExactBarrierController(
        provider, timeout_seconds=timeout_seconds, pause=guarded_pause
    )
    armed = controller.arm(token, predicate)
    start_segment()
    held = controller.await_target("held")
    released = controller.release_checkpoint(token, held)
    checkpoint = await_checkpoint()
    return {
        "barrier": {
            "token": token,
            "predicate": dict(predicate),
            "armed": armed["armed"],
            "target": held,
            "checkpoint_released": released,
        },
        "compute_checkpoint": file_identity(checkpoint),
    }


def execute_continue_witness(
    provider: ProviderControl,
    *,
    token: str,
    predicate: Mapping[str, object],
    start_segment: Callable[[], None],
    progress_guard: Callable[[], None] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Prove a later matching operation without taking a second checkpoint."""

    def guarded_pause(seconds: float) -> None:
        if progress_guard is not None:
            progress_guard()
        time.sleep(seconds)

    controller = ExactBarrierController(
        provider, timeout_seconds=timeout_seconds, pause=guarded_pause
    )
    armed = controller.arm(token, predicate)
    start_segment()
    held = controller.await_target("held")
    continued = controller.release_continue(token, held)
    return {
        "token": token,
        "predicate": dict(predicate),
        "armed": armed["armed"],
        "target": held,
        "continued": continued,
    }


def execute_lost_response_trigger(
    provider: ProviderControl,
    *,
    token: str,
    predicate: Mapping[str, object],
    start_injected_segment: Callable[[], None],
    progress_guard: Callable[[], None] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Stop at durable response/uncertain completion for an external injector."""

    def guarded_pause(seconds: float) -> None:
        if progress_guard is not None:
            progress_guard()
        time.sleep(seconds)

    controller = ExactBarrierController(
        provider, timeout_seconds=timeout_seconds, pause=guarded_pause
    )
    armed = controller.arm(token, predicate)
    start_injected_segment()
    triggered = controller.await_target("triggered")
    return {
        "token": token,
        "predicate": dict(predicate),
        "armed": armed["armed"],
        "target": triggered,
    }


class CliProviderControl:
    """Administrative adapter for ``visa_wasi_host control``."""

    def __init__(
        self,
        host_binary: Path,
        socket: Path,
        admin_capability: str,
        *,
        cwd: Path,
    ) -> None:
        self.host_binary = host_binary
        self.socket = socket
        self.admin_capability = admin_capability
        self.cwd = cwd

    def _control(self, *arguments: str) -> Mapping[str, object]:
        completed = subprocess.run(
            [
                os.fspath(self.host_binary),
                "control",
                os.fspath(self.socket),
                self.admin_capability,
                *arguments,
            ],
            cwd=self.cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            diagnostic = completed.stderr.decode("utf-8", errors="replace")[-1000:]
            raise MatrixFailure(
                f"provider control {arguments[0]!r} failed: {diagnostic}"
            )
        try:
            response = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise MatrixFailure("provider control returned malformed JSON") from error
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise MatrixFailure("provider control rejected the operation")
        return response

    def status(self) -> Mapping[str, object]:
        response = self._control("status")
        status = response.get("status")
        if not isinstance(status, dict):
            raise MatrixFailure("provider status response has no status object")
        return status

    def arm(self, token: str, predicate: Mapping[str, object]) -> None:
        _validate_predicate(predicate, "barrier predicate")
        self._control(
            "barrier-arm",
            token,
            str(predicate["kind"]),
            str(predicate["resource"]),
            str(predicate["outcome"]),
            str(predicate["occurrence"]),
        )

    def release(self, token: str, action: str) -> None:
        if action not in {"checkpoint", "continue"}:
            raise MatrixFailure("unknown barrier release action")
        self._control("barrier-release", token, action)


def _validate_predicate(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "kind",
        "resource",
        "outcome",
        "occurrence",
    }:
        raise MatrixFailure(f"{label} has the wrong fields")
    if value["kind"] not in {
        "fd-read",
        "fd-write",
        "fd-pread",
        "fd-pwrite",
        "fd-sync",
        "path-create-directory",
        "path-open",
        "path-unlink-file",
    }:
        raise MatrixFailure(f"{label} uses an unsupported hostcall kind")
    resource = value["resource"]
    if not isinstance(resource, str) or not resource.startswith("path:"):
        raise MatrixFailure(f"{label} must use an exact path selector")
    _canonical_guest_path(resource.removeprefix("path:"))
    if value["outcome"] != "success":
        raise MatrixFailure(f"{label} must select successful completion")
    occurrence = value["occurrence"]
    if not isinstance(occurrence, int) or isinstance(occurrence, bool) or occurrence <= 0:
        raise MatrixFailure(f"{label} has an invalid occurrence")
    return value


def _validate_file_identity(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"sha256", "size"}:
        raise MatrixFailure(f"{label} has the wrong fields")
    _require_hex(value["sha256"], 32, label + " sha256")
    if not isinstance(value["size"], int) or isinstance(value["size"], bool) or value["size"] <= 0:
        raise MatrixFailure(f"{label} size must be positive")


def _artifact_identity(
    reference: object,
    label: str,
    *,
    allow_empty: bool = False,
) -> dict[str, object]:
    try:
        validated = ARTIFACTS.validate_reference(reference, label)
    except ARTIFACTS.ArtifactError as error:
        raise MatrixFailure(str(error)) from error
    if validated["size"] == 0 and not allow_empty:
        raise MatrixFailure(f"{label} size must be positive")
    return {"sha256": validated["sha256"], "size": validated["size"]}


def _validate_raw_evidence_references(
    value: object,
    *,
    label: str,
    path_label: str,
    source_cursor_required: bool,
) -> Mapping[str, object]:
    fields = {
        "application_runs",
        "client_stdout",
        "expected_acknowledgements",
        "namespace_snapshot",
        "oracle_report",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixFailure(f"{label} retained raw evidence has the wrong fields")
    expected_paths = {
        "client_stdout": f"observations/{path_label}/raw-client.stdout",
        "expected_acknowledgements": f"observations/{path_label}/expected-acks.json",
        "namespace_snapshot": f"observations/{path_label}/namespace.snapshot",
        "oracle_report": f"observations/{path_label}/oracle-report.json",
    }
    for name in (
        "client_stdout",
        "expected_acknowledgements",
        "namespace_snapshot",
        "oracle_report",
    ):
        reference = value[name]
        _artifact_identity(reference, f"{label} retained {name}")
        assert isinstance(reference, dict)
        if reference["path"] != expected_paths[name]:
            raise MatrixFailure(
                f"{label} retained {name} does not use its canonical cell path"
            )
    expected_roles = (
        ("transaction", "cursor")
        if path_label == "uninterrupted-control"
        else (
            ("transaction-setup", "source", "destination")
            if source_cursor_required
            else ("source", "destination", "readback")
        )
    )
    runs = value["application_runs"]
    if not isinstance(runs, list) or len(runs) != len(expected_roles):
        raise MatrixFailure(f"{label} retained application run inventory differs")
    for index, (raw_run, expected_role) in enumerate(
        zip(runs, expected_roles, strict=True)
    ):
        if not isinstance(raw_run, dict) or set(raw_run) != {
            "role",
            "exit_status",
            "stdout",
            "stderr",
        }:
            raise MatrixFailure(f"{label} retained application run {index} is malformed")
        if raw_run["role"] != expected_role:
            raise MatrixFailure(f"{label} retained application run role/order differs")
        exit_status = raw_run["exit_status"]
        if (
            not isinstance(exit_status, int)
            or isinstance(exit_status, bool)
            or exit_status != 0
        ):
            raise MatrixFailure(
                f"{label} retained {expected_role} application exit status must be zero"
            )
        for stream in ("stdout", "stderr"):
            reference = raw_run[stream]
            try:
                validated_reference = ARTIFACTS.validate_reference(
                    reference,
                    f"{label} retained {expected_role} application {stream}",
                )
            except ARTIFACTS.ArtifactError as error:
                raise MatrixFailure(str(error)) from error
            expected_path = (
                f"observations/{path_label}/runs/{expected_role}.{stream}"
            )
            if validated_reference["path"] != expected_path:
                raise MatrixFailure(
                    f"{label} retained {expected_role} application {stream} "
                    "does not use its canonical cell path"
                )
    return value


def _validate_namespace_snapshot(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "artifact",
        "effect_frontier",
        "effects",
    }:
        raise MatrixFailure(f"{label} namespace snapshot has the wrong fields")
    _validate_file_identity(value["artifact"], f"{label} namespace snapshot")
    _require_hex(value["effect_frontier"], 32, f"{label} namespace effect frontier")
    if (
        not isinstance(value["effects"], int)
        or isinstance(value["effects"], bool)
        or value["effects"] <= 0
    ):
        raise MatrixFailure(f"{label} namespace snapshot has no durable effects")


def _validate_oracle_projection(
    value: object,
    workload: Mapping[str, object],
    label: str,
) -> Mapping[str, object]:
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
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixFailure(f"{label} semantic projection has the wrong fields")
    if value["schema_version"] != ORACLE_PROJECTION_SCHEMA:
        raise MatrixFailure(f"{label} semantic projection has the wrong schema")
    logical = value["logical_contents"]
    if not isinstance(logical, dict) or set(logical) != {
        "account_rows",
        "accounts_sha256",
        "transaction_rows",
        "transactions_sha256",
    }:
        raise MatrixFailure(f"{label} logical-content projection is malformed")
    expected_txids = workload["expected_acknowledgement_txids"]
    expected_rows = workload["expected_cursor_rows"]
    if (
        logical["account_rows"] != expected_rows
        or logical["transaction_rows"] != len(expected_txids)
    ):
        raise MatrixFailure(f"{label} logical row counts differ from the workload")
    _require_hex(logical["accounts_sha256"], 32, f"{label} account rows sha256")
    _require_hex(
        logical["transactions_sha256"], 32, f"{label} transaction rows sha256"
    )
    if (
        value["integrity_ok"] is not True
        or value["foreign_keys_ok"] is not True
        or value["schema_accepted"] is not True
    ):
        raise MatrixFailure(f"{label} SQLite integrity invariants did not pass")
    expected_total = workload["initial_total_balance"]
    if value["balance"] != {
        "expected_total": expected_total,
        "observed_total": expected_total,
        "total_matches": True,
        "negative_accounts": 0,
        "all_nonnegative": True,
    }:
        raise MatrixFailure(f"{label} balance projection is invalid")
    transaction_count = len(expected_txids)
    if value["transactions"] != {
        "rows": transaction_count,
        "nonnull_txids": transaction_count,
        "distinct_txids": transaction_count,
        "unique_txids": True,
        "nonpositive_amounts": 0,
        "all_amounts_positive": True,
    }:
        raise MatrixFailure(f"{label} transaction projection is invalid")
    if value["acknowledgements"] != {
        "expected_txids": expected_txids,
        "observed_txids": expected_txids,
        "missing_txids": [],
        "unexpected_txids": [],
        "exact_match": True,
    }:
        raise MatrixFailure(f"{label} acknowledgement projection is invalid")
    return value


def _validate_oracle_snapshot_binding(
    value: object,
    namespace: Mapping[str, object],
    label: str,
) -> None:
    fields = {
        "version",
        "session_hex",
        "authority_epoch",
        "mode",
        "barrier",
        "effect_frontier_hex",
        "effects",
        "objects",
        "paths",
        "descriptors",
        "locks",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixFailure(f"{label} oracle snapshot summary has the wrong fields")
    for field in (
        "version",
        "authority_epoch",
        "effects",
        "objects",
        "paths",
        "descriptors",
        "locks",
    ):
        field_value = value[field]
        if (
            not isinstance(field_value, int)
            or isinstance(field_value, bool)
            or field_value < 0
        ):
            raise MatrixFailure(f"{label} oracle snapshot {field} is invalid")
    if value["version"] == 0:
        raise MatrixFailure(f"{label} oracle snapshot version is invalid")
    _require_hex(value["session_hex"], 16, f"{label} oracle snapshot session")
    _require_hex(
        value["effect_frontier_hex"],
        32,
        f"{label} oracle snapshot effect frontier",
    )
    if not isinstance(value["mode"], str) or not value["mode"]:
        raise MatrixFailure(f"{label} oracle snapshot mode is invalid")
    if not isinstance(value["barrier"], str) or not value["barrier"]:
        raise MatrixFailure(f"{label} oracle snapshot barrier is invalid")
    if (
        value["effects"] != namespace["effects"]
        or value["effect_frontier_hex"] != namespace["effect_frontier"]
    ):
        raise MatrixFailure(
            f"{label} namespace counters differ from the raw snapshot oracle"
        )


def _validate_external_oracle(
    value: object,
    workload: Mapping[str, object],
    execution_inputs: Mapping[str, object],
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "program",
        "report",
        "report_schema",
        "semantic_projection",
        "exit_status",
        "accepted",
    }:
        raise MatrixFailure(f"{label} external oracle evidence has the wrong fields")
    _validate_file_identity(value["program"], f"{label} external oracle program")
    _validate_file_identity(value["report"], f"{label} external oracle report")
    if (
        value["report_schema"] != ORACLE_REPORT_SCHEMA
        or value["exit_status"] != 0
        or value["accepted"] is not True
    ):
        raise MatrixFailure(f"{label} independent SQLite oracle did not accept")
    if value["program"] != execution_inputs["visa_sqlite_oracle"]:
        raise MatrixFailure(f"{label} used a different SQLite oracle program")
    return _validate_oracle_projection(
        value["semantic_projection"], workload, f"{label} oracle"
    )


def _validate_raw_client_observation(
    value: object,
    workload: Mapping[str, object],
    *,
    label: str,
    migrated_cursor: bool,
) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "stdout",
        "acknowledged_txids",
        "ack_terminal_count",
        "cursor_prefix_rows",
        "cursor_total_rows",
        "cursor_done_count",
        "cursor_rows_sha256",
    }:
        raise MatrixFailure(f"{label} raw client observation has the wrong fields")
    _validate_file_identity(value["stdout"], f"{label} raw client stdout")
    expected_txids = workload["expected_acknowledgement_txids"]
    if (
        value["acknowledged_txids"] != expected_txids
        or value["ack_terminal_count"] != len(expected_txids)
    ):
        raise MatrixFailure(f"{label} raw stdout lacks each expected ACK exactly once")
    prefix = value["cursor_prefix_rows"]
    expected_rows = workload["expected_cursor_rows"]
    if (
        not isinstance(prefix, int)
        or isinstance(prefix, bool)
        or value["cursor_total_rows"] != expected_rows
        or value["cursor_done_count"] != 1
    ):
        raise MatrixFailure(f"{label} cursor observation is not one complete result")
    if migrated_cursor:
        if prefix <= 0 or prefix >= expected_rows:
            raise MatrixFailure(f"{label} cursor continuation lacks a strict source prefix")
    elif prefix != 0:
        raise MatrixFailure(f"{label} uninterrupted cursor readback has a source prefix")
    _require_hex(value["cursor_rows_sha256"], 32, f"{label} cursor rows sha256")
    return value


def _derive_equivalence_projection(
    oracle: Mapping[str, object],
    observation: Mapping[str, object],
    label: str,
) -> dict[str, object]:
    logical = oracle["logical_contents"]
    acknowledgements = oracle["acknowledgements"]
    assert isinstance(logical, dict)
    assert isinstance(acknowledgements, dict)
    if (
        acknowledgements["observed_txids"] != observation["acknowledged_txids"]
        or acknowledgements["exact_match"] is not True
    ):
        raise MatrixFailure(f"{label} raw ACKs differ from the native SQLite projection")
    if observation["cursor_rows_sha256"] != logical["accounts_sha256"]:
        raise MatrixFailure(f"{label} raw cursor rows differ from native SQLite rows")
    return {
        "schema": EQUIVALENCE_PROJECTION_SCHEMA,
        "logical_contents": dict(logical),
        "invariants": {
            "integrity_ok": oracle["integrity_ok"],
            "foreign_keys_ok": oracle["foreign_keys_ok"],
            "schema_accepted": oracle["schema_accepted"],
            "balance": dict(oracle["balance"]),
            "transactions": dict(oracle["transactions"]),
        },
        "acknowledgements": {
            "txids": list(observation["acknowledged_txids"]),
            "terminal_count": observation["ack_terminal_count"],
            "oracle": dict(acknowledgements),
        },
        "cursor": {
            "rows_sha256": observation["cursor_rows_sha256"],
            "total_rows": observation["cursor_total_rows"],
            "done_count": observation["cursor_done_count"],
        },
    }


def _reject_duplicate_json_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise MatrixFailure(f"retained JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def _parse_json_bytes(payload: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixFailure(f"{label} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise MatrixFailure(f"{label} is not a JSON object")
    return value


def _validate_bound_file(
    value: object,
    *,
    semantic_path: str,
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "semantic_path",
        "size",
        "sha256",
    }:
        raise MatrixFailure(f"{label} bound file has the wrong fields")
    size = value["size"]
    if (
        value["semantic_path"] != semantic_path
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
    ):
        raise MatrixFailure(f"{label} bound file is invalid")
    digest = _require_hex(value["sha256"], 32, f"{label} sha256")
    return {"sha256": digest, "size": size}


def _identity_array_hex(value: object, label: str) -> str:
    if (
        not isinstance(value, list)
        or len(value) != 16
        or any(
            not isinstance(item, int)
            or isinstance(item, bool)
            or item < 0
            or item > 255
            for item in value
        )
    ):
        raise MatrixFailure(f"{label} must be one exact 16-byte identity")
    return _require_hex(bytes(value).hex(), 16, label)


def _validate_build_identity(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "source_revision",
        "toolchain",
        "build_configuration_sha256",
    }:
        raise MatrixFailure(f"{label} build identity has the wrong fields")
    if (
        not isinstance(value["source_revision"], str)
        or not value["source_revision"]
        or not isinstance(value["toolchain"], str)
        or not value["toolchain"]
    ):
        raise MatrixFailure(f"{label} build identity is incomplete")
    _require_hex(
        value["build_configuration_sha256"],
        32,
        f"{label} build configuration sha256",
    )


def _validate_platform_identity(value: object, label: str) -> None:
    fields = {
        "operating_system",
        "architecture",
        "abi",
        "runtime_name",
        "runtime_version",
        "runtime_build_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixFailure(f"{label} platform identity has the wrong fields")
    for field in fields - {"runtime_build_sha256"}:
        if not isinstance(value[field], str) or not value[field]:
            raise MatrixFailure(f"{label} platform identity is incomplete")
    _require_hex(
        value["runtime_build_sha256"],
        32,
        f"{label} runtime build sha256",
    )


def _account_rows_sha256(rows: list[tuple[int, int]]) -> str:
    digest = hashlib.sha256()
    digest.update(b"visa-sqlite-account-rows-v1\0")
    digest.update(struct.pack(">Q", len(rows)))
    for account_id, balance in rows:
        digest.update(struct.pack(">q", account_id))
        digest.update(struct.pack(">q", balance))
    return digest.hexdigest()


def _parse_client_stdout_bytes(
    payload: bytes,
    workload: Mapping[str, object],
    *,
    label: str,
    source_cursor_payload: bytes | None,
) -> dict[str, object]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise MatrixFailure(f"{label} raw client stdout is not UTF-8") from error
    txids: list[str] = []
    rows: list[tuple[int, int]] = []
    done_values: list[int] = []
    journal_modes: list[str] = []
    for line in lines:
        if line == "delete":
            journal_modes.append(line)
        elif line.startswith("VISA_ACK|"):
            fields = line.split("|")
            if len(fields) != 2 or not fields[1]:
                raise MatrixFailure(f"{label} raw stdout has a malformed ACK terminal")
            txids.append(fields[1])
        elif line.startswith("VISA_ROW|"):
            fields = line.split("|")
            if len(fields) != 3:
                raise MatrixFailure(f"{label} raw stdout has a malformed cursor row")
            try:
                rows.append((int(fields[1]), int(fields[2])))
            except ValueError as error:
                raise MatrixFailure(
                    f"{label} raw stdout has a nonnumeric cursor row"
                ) from error
        elif line.startswith("VISA_CURSOR_DONE|"):
            fields = line.split("|")
            if len(fields) != 2:
                raise MatrixFailure(f"{label} raw stdout has a malformed cursor terminal")
            try:
                done_values.append(int(fields[1]))
            except ValueError as error:
                raise MatrixFailure(
                    f"{label} raw stdout has a nonnumeric cursor terminal"
                ) from error
        else:
            raise MatrixFailure(f"{label} raw stdout has an unexpected output line")
    expected_txids = workload["expected_acknowledgement_txids"]
    expected_rows = workload["expected_cursor_rows"]
    if journal_modes != ["delete"]:
        raise MatrixFailure(
            f"{label} raw stdout does not contain one exact DELETE journal-mode result"
        )
    if txids != expected_txids:
        raise MatrixFailure(f"{label} raw stdout lacks each expected ACK exactly once")
    if len(rows) != expected_rows or done_values != [expected_rows]:
        raise MatrixFailure(f"{label} raw stdout is not one complete cursor result")
    prefix_rows = 0
    if source_cursor_payload is not None:
        try:
            source_lines = source_cursor_payload.decode("utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise MatrixFailure(f"{label} source cursor stdout is not UTF-8") from error
        source_rows: list[tuple[int, int]] = []
        for line in source_lines:
            if line.startswith("VISA_CURSOR_DONE|"):
                raise MatrixFailure(f"{label} source cursor unexpectedly completed")
            if not line.startswith("VISA_ROW|"):
                raise MatrixFailure(
                    f"{label} source cursor stdout has an unexpected output line"
                )
            fields = line.split("|")
            if len(fields) != 3:
                raise MatrixFailure(f"{label} source cursor row is malformed")
            try:
                source_rows.append((int(fields[1]), int(fields[2])))
            except ValueError as error:
                raise MatrixFailure(f"{label} source cursor row is nonnumeric") from error
        prefix_rows = len(source_rows)
        if not 0 < prefix_rows < expected_rows or source_rows != rows[:prefix_rows]:
            raise MatrixFailure(f"{label} source cursor is not a strict result prefix")
    return {
        "acknowledged_txids": txids,
        "ack_terminal_count": len(txids),
        "cursor_prefix_rows": prefix_rows,
        "cursor_total_rows": len(rows),
        "cursor_done_count": len(done_values),
        "cursor_rows_sha256": _account_rows_sha256(rows),
    }


def _read_retained_reference(
    artifact_root: Path,
    reference: object,
    label: str,
    *,
    budget: ARTIFACTS.ReadBudget,
    max_bytes: int,
) -> bytes:
    try:
        return ARTIFACTS.read_reference(
            artifact_root,
            reference,
            label,
            budget=budget,
            max_bytes=max_bytes,
        )
    except ARTIFACTS.ArtifactError as error:
        raise MatrixFailure(str(error)) from error


def _validate_process_recovery_qualification(value: object) -> None:
    fields = {
        "schema",
        "scope",
        "qualified_tests",
        "nonclaims",
        "retained_raw_evidence",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixFailure("provider process-recovery qualification has the wrong fields")
    if (
        value["schema"] != PROCESS_RECOVERY_SCHEMA
        or value["scope"] != "provider-process-kill-reopen"
        or value["qualified_tests"] != list(PROCESS_RECOVERY_TESTS)
        or value["nonclaims"] != list(PROCESS_RECOVERY_NONCLAIMS)
    ):
        raise MatrixFailure("provider process-recovery qualification changed its contract")
    retained = value["retained_raw_evidence"]
    if not isinstance(retained, dict) or set(retained) != {"report", "process"}:
        raise MatrixFailure("provider process-recovery raw evidence has the wrong fields")
    report = retained["report"]
    _artifact_identity(report, "provider process-recovery raw report")
    assert isinstance(report, dict)
    if report["path"] != "observations/provider-process-recovery/report.json":
        raise MatrixFailure("provider process-recovery report has a noncanonical path")
    process = retained["process"]
    if not isinstance(process, dict) or set(process) != {
        "command",
        "exit_status",
        "stdout",
        "stderr",
    }:
        raise MatrixFailure("provider process-recovery process observation is malformed")
    if (
        process["command"] != PROCESS_RECOVERY_COMMAND
        or process["exit_status"] != 0
    ):
        raise MatrixFailure("provider process-recovery process did not complete cleanly")
    for stream in ("stdout", "stderr"):
        reference = process[stream]
        _artifact_identity(
            reference,
            f"provider process-recovery {stream}",
            allow_empty=True,
        )
        assert isinstance(reference, dict)
        expected_path = f"observations/provider-process-recovery/process.{stream}"
        if reference["path"] != expected_path:
            raise MatrixFailure(
                f"provider process-recovery {stream} has a noncanonical path"
            )


def _recompute_process_recovery(
    value: Mapping[str, object],
    *,
    artifact_root: Path,
    budget: ARTIFACTS.ReadBudget,
) -> None:
    retained = value["retained_raw_evidence"]
    assert isinstance(retained, dict)
    process = retained["process"]
    assert isinstance(process, dict)
    stdout = _read_retained_reference(
        artifact_root,
        process["stdout"],
        "provider process-recovery stdout",
        budget=budget,
        max_bytes=MAX_SQLITE_STDOUT_BYTES,
    )
    stderr = _read_retained_reference(
        artifact_root,
        process["stderr"],
        "provider process-recovery stderr",
        budget=budget,
        max_bytes=MAX_SQLITE_STDERR_BYTES,
    )
    report_bytes = _read_retained_reference(
        artifact_root,
        retained["report"],
        "provider process-recovery report",
        budget=budget,
        max_bytes=MAX_SQLITE_JSON_BYTES,
    )
    report = _parse_json_bytes(report_bytes, "provider process-recovery report")
    if report_bytes != canonical_bytes(report) + b"\n":
        raise MatrixFailure("provider process-recovery report is not canonical JSON")
    if set(report) != {
        "schema",
        "command",
        "exit_status",
        "qualified_tests",
        "stdout",
        "stderr",
        "scope",
        "nonclaims",
    }:
        raise MatrixFailure("provider process-recovery report has the wrong fields")
    if (
        report["schema"] != PROCESS_RECOVERY_REPORT_SCHEMA
        or report["command"] != PROCESS_RECOVERY_COMMAND
        or report["exit_status"] != 0
        or report["qualified_tests"] != list(PROCESS_RECOVERY_TESTS)
        or report["scope"] != value["scope"]
        or report["nonclaims"] != list(PROCESS_RECOVERY_NONCLAIMS)
        or report["stdout"] != _artifact_identity(
            process["stdout"],
            "provider process-recovery report stdout",
            allow_empty=True,
        )
        or report["stderr"] != _artifact_identity(
            process["stderr"],
            "provider process-recovery report stderr",
            allow_empty=True,
        )
    ):
        raise MatrixFailure("provider process-recovery report differs from raw execution")
    try:
        output = (stdout + b"\n" + stderr).decode("utf-8")
    except UnicodeDecodeError as error:
        raise MatrixFailure("provider process-recovery output is not UTF-8") from error
    terminals = re.findall(
        r"(?m)^test ([A-Za-z0-9_]+) \.\.\. ([A-Za-z]+)\r?$",
        output,
    )
    if sorted(terminals) != sorted((name, "ok") for name in PROCESS_RECOVERY_TESTS):
        raise MatrixFailure(
            "provider process-recovery output does not contain the exact passing tests"
        )
    summaries = re.findall(
        r"(?m)^test result: ok\. 2 passed; 0 failed; 0 ignored; "
        r"0 measured; 0 filtered out; finished in [^\r\n]+\r?$",
        output,
    )
    if len(summaries) != 1:
        raise MatrixFailure(
            "provider process-recovery output lacks one exact successful harness terminal"
        )


def _validate_source_abort_retained_references(
    value: object,
    abort: Mapping[str, object],
) -> None:
    fields = {
        "application_runs",
        "client_stdout",
        "expected_acknowledgements",
        "namespace_snapshot",
        "oracle_report",
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
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixFailure("source-abort retained raw evidence has the wrong fields")
    filenames = {
        "client_stdout": "raw-client.stdout",
        "expected_acknowledgements": "expected-acks.json",
        "namespace_snapshot": "namespace.snapshot",
        "oracle_report": "oracle-report.json",
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
        reference = value[name]
        _artifact_identity(reference, f"source-abort retained {name}")
        assert isinstance(reference, dict)
        if reference["path"] != f"observations/source-abort/{filename}":
            raise MatrixFailure(f"source-abort retained {name} has a noncanonical path")
    runs = value["application_runs"]
    expected_roles = ("source", "destination", "readback")
    if not isinstance(runs, list) or len(runs) != len(expected_roles):
        raise MatrixFailure("source-abort retained application run inventory differs")
    for raw_run, expected_role in zip(runs, expected_roles, strict=True):
        if not isinstance(raw_run, dict) or set(raw_run) != {
            "role",
            "exit_status",
            "stdout",
            "stderr",
        }:
            raise MatrixFailure("source-abort retained application run is malformed")
        if raw_run["role"] != expected_role or raw_run["exit_status"] != 0:
            raise MatrixFailure("source-abort retained application run did not succeed")
        for stream in ("stdout", "stderr"):
            reference = raw_run[stream]
            _artifact_identity(
                reference,
                f"source-abort {expected_role} application {stream}",
                allow_empty=stream == "stderr",
            )
            assert isinstance(reference, dict)
            expected_path = (
                f"observations/source-abort/runs/{expected_role}.{stream}"
            )
            if reference["path"] != expected_path:
                raise MatrixFailure(
                    f"source-abort {expected_role} {stream} has a noncanonical path"
                )
    driver_runs = value["driver_runs"]
    if not isinstance(driver_runs, list) or len(driver_runs) != len(
        SOURCE_ABORT_DRIVER_RUNS
    ):
        raise MatrixFailure("source-abort retained driver run inventory differs")
    for raw_run, (role, _, _, expected_status) in zip(
        driver_runs, SOURCE_ABORT_DRIVER_RUNS, strict=True
    ):
        if not isinstance(raw_run, dict) or set(raw_run) != {
            "role",
            "exit_status",
            "stdout",
            "stderr",
        }:
            raise MatrixFailure("source-abort retained driver run is malformed")
        exit_status = raw_run["exit_status"]
        if (
            raw_run["role"] != role
            or not isinstance(exit_status, int)
            or isinstance(exit_status, bool)
            or exit_status != expected_status
        ):
            raise MatrixFailure("source-abort retained driver run status differs")
        for stream in ("stdout", "stderr"):
            reference = raw_run[stream]
            _artifact_identity(
                reference,
                f"source-abort {role} driver {stream}",
                allow_empty=True,
            )
            assert isinstance(reference, dict)
            expected_path = (
                f"observations/source-abort/driver-runs/{role}.{stream}"
            )
            if reference["path"] != expected_path:
                raise MatrixFailure(
                    f"source-abort {role} driver {stream} has a noncanonical path"
                )
    identity_bindings = {
        "integrated_driver_report": abort["integrated_driver_report"],
        "compute_checkpoint": abort["compute_checkpoint"],
        "pending_driver_record": abort["pending_driver_record"],
        "wanco_restore_started": abort["wanco_restore_started"],
        "wanco_restore_completion": abort["wanco_restore_completion"],
        "oracle_report": abort["external_oracle_report"],
    }
    source_terminal = abort["source_retained_terminal"]
    committed_terminal = abort["committed_probe_terminal"]
    assert isinstance(source_terminal, dict)
    assert isinstance(committed_terminal, dict)
    identity_bindings.update(
        {
            "source_authority_state": source_terminal["state"],
            "committed_authority_state": committed_terminal["state"],
            "source_adapter_binding": abort["adapter_binding_receipt"],
            "committed_adapter_binding": committed_terminal[
                "adapter_binding_receipt"
            ],
            "source_retained_receipt": source_terminal["receipt"],
        }
    )
    for name, expected in identity_bindings.items():
        if _artifact_identity(value[name], f"source-abort retained {name}") != expected:
            raise MatrixFailure(f"source-abort retained {name} identity differs")
    raw_observation = abort["raw_client_observation"]
    namespace = abort["namespace_snapshot"]
    assert isinstance(raw_observation, dict)
    assert isinstance(namespace, dict)
    if (
        _artifact_identity(value["client_stdout"], "source-abort retained stdout")
        != raw_observation["stdout"]
        or _artifact_identity(
            value["expected_acknowledgements"], "source-abort retained ACK input"
        )
        != abort["expected_acknowledgements"]
        or _artifact_identity(
            value["namespace_snapshot"], "source-abort retained namespace"
        )
        != namespace["artifact"]
    ):
        raise MatrixFailure("source-abort retained semantic inputs differ from the summary")


def _recompute_retained_observation(
    record: Mapping[str, object],
    *,
    label: str,
    workload: Mapping[str, object],
    execution_inputs: Mapping[str, object],
    artifact_root: Path,
    oracle_binary: Path,
    budget: ARTIFACTS.ReadBudget,
    source_cursor_required: bool,
) -> None:
    retained = record["retained_raw_evidence"]
    assert isinstance(retained, dict)
    application_runs = retained["application_runs"]
    assert isinstance(application_runs, list)
    joined_stdout = bytearray()
    source_cursor_bytes = None
    for raw_run in application_runs:
        assert isinstance(raw_run, dict)
        role = raw_run["role"]
        assert isinstance(role, str)
        run_stdout = _read_retained_reference(
            artifact_root,
            raw_run["stdout"],
            f"{label} {role} application stdout",
            budget=budget,
            max_bytes=MAX_SQLITE_STDOUT_BYTES,
        )
        run_stderr = _read_retained_reference(
            artifact_root,
            raw_run["stderr"],
            f"{label} {role} application stderr",
            budget=budget,
            max_bytes=MAX_SQLITE_STDERR_BYTES,
        )
        try:
            WANCO_DIAGNOSTICS.validate_application_stderr(
                role, run_stderr, f"{label} {role} application stderr"
            )
        except WANCO_DIAGNOSTICS.DiagnosticFailure as error:
            raise MatrixFailure(str(error)) from error
        if joined_stdout and not joined_stdout.endswith(b"\n"):
            joined_stdout.extend(b"\n")
        joined_stdout.extend(run_stdout)
        if source_cursor_required and role == "source":
            source_cursor_bytes = run_stdout
    stdout_bytes = _read_retained_reference(
        artifact_root,
        retained["client_stdout"],
        f"{label} client stdout",
        budget=budget,
        max_bytes=MAX_SQLITE_STDOUT_BYTES,
    )
    expected_bytes = _read_retained_reference(
        artifact_root,
        retained["expected_acknowledgements"],
        f"{label} expected acknowledgements",
        budget=budget,
        max_bytes=MAX_SQLITE_JSON_BYTES,
    )
    snapshot_bytes = _read_retained_reference(
        artifact_root,
        retained["namespace_snapshot"],
        f"{label} namespace snapshot",
        budget=budget,
        max_bytes=MAX_SQLITE_SNAPSHOT_BYTES,
    )
    report_bytes = _read_retained_reference(
        artifact_root,
        retained["oracle_report"],
        f"{label} oracle report",
        budget=budget,
        max_bytes=MAX_SQLITE_JSON_BYTES,
    )
    if bytes(joined_stdout) != stdout_bytes:
        raise MatrixFailure(
            f"{label} retained application stdout does not reconstruct the transcript"
        )
    if source_cursor_required and source_cursor_bytes is None:
        raise MatrixFailure(f"{label} retained application runs omit the source cursor")

    expected = _parse_json_bytes(expected_bytes, f"{label} expected acknowledgements")
    canonical_expected = {
        "schema_version": "visa-sqlite-expected-acks-v1",
        "initial_total_balance": workload["initial_total_balance"],
        "acknowledged_txids": workload["expected_acknowledgement_txids"],
    }
    if expected != canonical_expected or expected_bytes != canonical_bytes(expected) + b"\n":
        raise MatrixFailure(f"{label} retained expected acknowledgements are not canonical")

    derived_observation = _parse_client_stdout_bytes(
        stdout_bytes,
        workload,
        label=label,
        source_cursor_payload=source_cursor_bytes,
    )
    recorded_observation = record["raw_client_observation"]
    assert isinstance(recorded_observation, dict)
    recorded_without_identity = {
        key: value
        for key, value in recorded_observation.items()
        if key != "stdout"
    }
    if derived_observation != recorded_without_identity:
        raise MatrixFailure(f"{label} raw stdout summary was not independently derived")

    retained_report = _parse_json_bytes(report_bytes, f"{label} oracle report")
    if (
        retained_report.get("schema_version") != ORACLE_REPORT_SCHEMA
        or retained_report.get("accepted") is not True
    ):
        raise MatrixFailure(f"{label} retained independent oracle report did not accept")
    oracle = oracle_binary.resolve()
    if oracle.is_symlink() or not oracle.is_file():
        raise MatrixFailure("SQLite oracle binary is not a regular non-symlink file")
    if file_identity(oracle) != execution_inputs["visa_sqlite_oracle"]:
        raise MatrixFailure("SQLite oracle binary differs from the receipt execution input")
    with tempfile.TemporaryDirectory(prefix="visa-sqlite-oracle-recheck-") as raw:
        temporary = Path(raw)
        snapshot_path = temporary / "namespace.snapshot"
        expected_path = temporary / "expected-acks.json"
        snapshot_path.write_bytes(snapshot_bytes)
        expected_path.write_bytes(expected_bytes)
        completed = subprocess.run(
            [oracle, snapshot_path, expected_path, DEFAULT_DATABASE_PATH],
            cwd=temporary,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace")[-1000:]
        raise MatrixFailure(f"{label} independent oracle recheck rejected: {diagnostic}")
    recomputed_report = _parse_json_bytes(
        completed.stdout, f"{label} recomputed oracle report"
    )
    if recomputed_report != retained_report:
        raise MatrixFailure(f"{label} retained oracle report was not independently reproduced")
    projection = _validate_oracle_projection(
        retained_report.get("semantic_projection"),
        workload,
        f"{label} retained oracle",
    )
    namespace = record["namespace_snapshot"]
    assert isinstance(namespace, dict)
    _validate_oracle_snapshot_binding(
        retained_report.get("snapshot"),
        namespace,
        label,
    )
    external = record["external_oracle"]
    assert isinstance(external, dict)
    if projection != external["semantic_projection"]:
        raise MatrixFailure(f"{label} oracle summary differs from the raw oracle report")


def _read_canonical_retained_json(
    artifact_root: Path,
    reference: object,
    label: str,
    *,
    budget: ARTIFACTS.ReadBudget,
) -> dict[str, object]:
    payload = _read_retained_reference(
        artifact_root,
        reference,
        label,
        budget=budget,
        max_bytes=MAX_SQLITE_JSON_BYTES,
    )
    value = _parse_json_bytes(payload, label)
    if payload != canonical_bytes(value) + b"\n":
        raise MatrixFailure(f"{label} is not canonical JSON")
    return value


def _read_bare_canonical_retained_json(
    artifact_root: Path,
    reference: object,
    label: str,
    *,
    budget: ARTIFACTS.ReadBudget,
) -> dict[str, object]:
    payload = _read_retained_reference(
        artifact_root,
        reference,
        label,
        budget=budget,
        max_bytes=MAX_SQLITE_JSON_BYTES,
    )
    value = _parse_json_bytes(payload, label)
    if payload != canonical_bytes(value):
        raise MatrixFailure(f"{label} is not bare canonical RFC 8785 JSON")
    return value


def _parse_pretty_json_line(payload: bytes, label: str) -> dict[str, object]:
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        raise MatrixFailure(f"{label} is not one newline-terminated JSON document")
    value = _parse_json_bytes(payload[:-1], label)
    expected = (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            separators=(",", ": "),
        ).encode("utf-8")
        + b"\n"
    )
    if payload != expected:
        raise MatrixFailure(f"{label} is not the production pretty JSON encoding")
    return value


def _derive_provider_capsule_status(
    payload: bytes,
    *,
    manifest: Mapping[str, object],
    cut_token: str,
    cut_effect: str,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="visa-capsule-verify-") as raw:
        database = Path(raw) / "state.sqlite"
        database.write_bytes(payload)
        try:
            connection = sqlite3.connect(
                f"file:{database}?mode=ro&immutable=1",
                uri=True,
                timeout=0,
            )
            try:
                connection.execute("PRAGMA query_only = ON")
                integrity = connection.execute("PRAGMA integrity_check").fetchall()
                version = connection.execute("PRAGMA user_version").fetchone()
                rows = connection.execute(
                    """
                    SELECT schema_version, hex(session), mode, authority_epoch,
                           hex(handoff), destination_epoch, barrier_phase,
                           hex(barrier_token), barrier_remaining,
                           hex(barrier_effect), completed_requests,
                           (SELECT count(*) FROM effects)
                    FROM meta WHERE singleton = 1
                    """
                ).fetchall()
            finally:
                connection.close()
        except sqlite3.Error as error:
            raise MatrixFailure(
                f"source-abort provider capsule is not a readable SQLite state: {error}"
            ) from error
    if (
        integrity != [("ok",)]
        or version != (PROVIDER_SCHEMA_VERSION,)
        or len(rows) != 1
    ):
        raise MatrixFailure("source-abort provider capsule failed independent integrity")
    (
        schema_version,
        session_hex,
        mode,
        authority_epoch,
        handoff_hex,
        destination_epoch,
        barrier_phase,
        barrier_token_hex,
        barrier_remaining,
        barrier_effect_hex,
        completed_requests,
        effects,
    ) = rows[0]
    if (
        schema_version != PROVIDER_SCHEMA_VERSION
        or session_hex.lower() != manifest["session_hex"]
        or mode != 1
        or authority_epoch != manifest["source_epoch"]
        or handoff_hex.lower() != manifest["handoff_hex"]
        or destination_epoch != manifest["destination_epoch"]
        or barrier_phase != 4
        or barrier_token_hex.lower() != cut_token
        or barrier_remaining is not None
        or barrier_effect_hex.lower() != cut_effect
        or not isinstance(completed_requests, int)
        or not isinstance(effects, int)
        or completed_requests != effects
        or effects <= 0
    ):
        raise MatrixFailure("source-abort provider capsule state is detached from the cut")
    return {
        "mode": "frozen",
        "authority_epoch": authority_epoch,
        "barrier": "checkpoint_released",
        "barrier_remaining": None,
        "barrier_effect": barrier_effect_hex.lower(),
        "effects": effects,
        "completed_requests": completed_requests,
    }


def _validate_source_abort_manifest(
    manifest: object,
    intent: object,
    *,
    execution_inputs: Mapping[str, object],
    abort: Mapping[str, object],
    source_proof: Mapping[str, object],
    cut_token: str,
    migration_application: Mapping[str, object],
    capsule_manifest: Mapping[str, object],
    capsule_state: Mapping[str, object],
    capsule_manifest_payload: bytes,
    capsule_state_payload: bytes,
    cut_effect: str,
) -> dict[str, object]:
    manifest_fields = {
        "schema",
        "application",
        "compute_checkpoint",
        "resource_capsule_manifest",
        "resource_capsule_state",
        "session_hex",
        "stable_owner_hex",
        "handoff_hex",
        "checkpoint_barrier_hex",
        "source_epoch",
        "destination_epoch",
        "clients",
        "application_build",
        "source_platform",
        "destination_platform",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != manifest_fields
        or manifest["schema"] != MIGRATION_MANIFEST_SCHEMA
    ):
        raise MatrixFailure("source-abort migration manifest has the wrong schema or fields")
    bound_application = _validate_bound_file(
        manifest["application"],
        semantic_path="artifacts/application.aot",
        label="source-abort migration application",
    )
    bound_checkpoint = _validate_bound_file(
        manifest["compute_checkpoint"],
        semantic_path="artifacts/checkpoint.pb",
        label="source-abort migration checkpoint",
    )
    bound_capsule_manifest = _validate_bound_file(
        manifest["resource_capsule_manifest"],
        semantic_path="capsule/manifest.json",
        label="source-abort capsule manifest",
    )
    bound_capsule_state = _validate_bound_file(
        manifest["resource_capsule_state"],
        semantic_path="capsule/state.sqlite",
        label="source-abort capsule state",
    )
    if (
        bound_application != migration_application
        or bound_application != execution_inputs["stock_sqlite_aot"]
        or bound_checkpoint != abort["compute_checkpoint"]
        or bound_capsule_manifest != capsule_manifest
        or bound_capsule_state != capsule_state
    ):
        raise MatrixFailure("source-abort migration manifest is detached from retained bytes")

    for field in (
        "session_hex",
        "stable_owner_hex",
        "handoff_hex",
        "checkpoint_barrier_hex",
    ):
        _require_hex(manifest[field], 16, f"source-abort manifest {field}")
    if (
        manifest["session_hex"] != source_proof["session_hex"]
        or manifest["stable_owner_hex"] != source_proof["stable_owner_hex"]
        or manifest["handoff_hex"] != source_proof["handoff_hex"]
        or manifest["checkpoint_barrier_hex"] != cut_token
        or manifest["source_epoch"] != source_proof["source_epoch"]
        or manifest["destination_epoch"] != source_proof["destination_epoch"]
        or manifest["destination_epoch"] != manifest["source_epoch"] + 1
    ):
        raise MatrixFailure("source-abort migration manifest authority binding differs")
    clients = manifest["clients"]
    if not isinstance(clients, dict) or set(clients) != {
        "source_client_hex",
        "source_restore_client_hex",
        "destination_client_hex",
    }:
        raise MatrixFailure("source-abort migration client lineage is malformed")
    for field in clients:
        _require_hex(clients[field], 16, f"source-abort manifest {field}")
    if (
        clients["source_client_hex"] != abort["source_client"]
        or clients["source_restore_client_hex"] != abort["source_restore_client"]
        or len(set(clients.values())) != 3
    ):
        raise MatrixFailure("source-abort migration client lineage is detached")
    _validate_build_identity(
        manifest["application_build"], "source-abort migration application"
    )
    _validate_platform_identity(
        manifest["source_platform"], "source-abort source"
    )
    _validate_platform_identity(
        manifest["destination_platform"], "source-abort destination"
    )

    intent_fields = {
        "files",
        "session",
        "stable_owner",
        "handoff",
        "checkpoint_barrier",
        "source_epoch",
        "destination_epoch",
        "source_client",
        "source_restore_client",
        "destination_client",
        "application_build",
        "source_platform",
        "destination_platform",
    }
    if not isinstance(intent, dict) or set(intent) != intent_fields:
        raise MatrixFailure("source-abort migration intent has the wrong fields")
    if intent["files"] != {
        "application": "artifacts/application.aot",
        "compute_checkpoint": "artifacts/checkpoint.pb",
        "resource_capsule_manifest": "capsule/manifest.json",
        "resource_capsule_state": "capsule/state.sqlite",
    }:
        raise MatrixFailure("source-abort migration intent file roles differ")
    identity_bindings = (
        ("session", "session_hex"),
        ("stable_owner", "stable_owner_hex"),
        ("handoff", "handoff_hex"),
        ("checkpoint_barrier", "checkpoint_barrier_hex"),
    )
    for intent_field, manifest_field in identity_bindings:
        if (
            _identity_array_hex(
                intent[intent_field], f"source-abort intent {intent_field}"
            )
            != manifest[manifest_field]
        ):
            raise MatrixFailure("source-abort migration intent identity differs")
    client_bindings = (
        ("source_client", "source_client_hex"),
        ("source_restore_client", "source_restore_client_hex"),
        ("destination_client", "destination_client_hex"),
    )
    for intent_field, manifest_field in client_bindings:
        if (
            _identity_array_hex(
                intent[intent_field], f"source-abort intent {intent_field}"
            )
            != clients[manifest_field]
        ):
            raise MatrixFailure("source-abort migration intent client differs")
    if (
        intent["source_epoch"] != manifest["source_epoch"]
        or intent["destination_epoch"] != manifest["destination_epoch"]
        or intent["application_build"] != manifest["application_build"]
        or intent["source_platform"] != manifest["source_platform"]
        or intent["destination_platform"] != manifest["destination_platform"]
    ):
        raise MatrixFailure("source-abort migration intent projection differs")

    descriptor = _parse_json_bytes(
        capsule_manifest_payload, "source-abort retained capsule manifest"
    )
    expected_descriptor = {
        "schema": "visa-wasi-filesystem-capsule-v2",
        "session_hex": manifest["session_hex"],
        "source_epoch": manifest["source_epoch"],
        "destination_epoch": manifest["destination_epoch"],
        "handoff_hex": manifest["handoff_hex"],
        "state_file": "state.sqlite",
        "state_size": bound_capsule_state["size"],
        "state_sha256": bound_capsule_state["sha256"],
    }
    expected_capsule_bytes = json.dumps(
        expected_descriptor,
        ensure_ascii=False,
        indent=2,
        separators=(",", ": "),
    ).encode("utf-8")
    if (
        descriptor != expected_descriptor
        or capsule_manifest_payload != expected_capsule_bytes
    ):
        raise MatrixFailure("source-abort retained capsule descriptor is detached")
    return _derive_provider_capsule_status(
        capsule_state_payload,
        manifest=manifest,
        cut_token=cut_token,
        cut_effect=cut_effect,
    )


def _recompute_source_abort(
    abort: Mapping[str, object],
    *,
    workload: Mapping[str, object],
    execution_inputs: Mapping[str, object],
    artifact_root: Path,
    oracle_binary: Path,
    budget: ARTIFACTS.ReadBudget,
) -> None:
    _recompute_retained_observation(
        abort,
        label="source-abort",
        workload=workload,
        execution_inputs=execution_inputs,
        artifact_root=artifact_root,
        oracle_binary=oracle_binary,
        budget=budget,
        source_cursor_required=False,
    )
    retained = abort["retained_raw_evidence"]
    assert isinstance(retained, dict)
    checkpoint = _read_retained_reference(
        artifact_root,
        retained["compute_checkpoint"],
        "source-abort compute checkpoint",
        budget=budget,
        max_bytes=MAX_SQLITE_SNAPSHOT_BYTES,
    )
    migration_application = _read_retained_reference(
        artifact_root,
        retained["migration_application"],
        "source-abort retained migration application",
        budget=budget,
        max_bytes=MAX_SQLITE_SNAPSHOT_BYTES,
    )
    try:
        TYPED_CORPUS.derive_checkpoint_application_compatibility(
            migration_application,
            checkpoint,
            "source-abort",
        )
    except TYPED_CORPUS.CorpusFailure as error:
        raise MatrixFailure(
            "source-abort checkpoint/application compatibility is invalid: "
            f"{error}"
        ) from error
    capsule_manifest_payload = _read_retained_reference(
        artifact_root,
        retained["resource_capsule_manifest"],
        "source-abort retained resource capsule manifest",
        budget=budget,
        max_bytes=MAX_SQLITE_JSON_BYTES,
    )
    capsule_state_payload = _read_retained_reference(
        artifact_root,
        retained["resource_capsule_state"],
        "source-abort retained resource capsule state",
        budget=budget,
        max_bytes=MAX_SQLITE_SNAPSHOT_BYTES,
    )
    document_names = (
        "integrated_driver_report",
        "crash_marker",
        "wanco_restore_started",
        "wanco_restore_completion",
        "source_exit_receipt",
        "source_authority_state",
        "committed_authority_state",
        "source_adapter_binding",
        "committed_adapter_binding",
        "source_retained_receipt",
    )
    documents = {
        name: _read_canonical_retained_json(
            artifact_root,
            retained[name],
            f"source-abort retained {name}",
            budget=budget,
        )
        for name in document_names
    }
    documents["pending_driver_record"] = _read_bare_canonical_retained_json(
        artifact_root,
        retained["pending_driver_record"],
        "source-abort retained pending_driver_record",
        budget=budget,
    )
    documents["final_driver_record"] = _read_bare_canonical_retained_json(
        artifact_root,
        retained["final_driver_record"],
        "source-abort retained final_driver_record",
        budget=budget,
    )
    report = documents["integrated_driver_report"]
    cut = report.get("cut")
    if not isinstance(cut, dict) or set(cut) != {
        "barrier",
        "compute_checkpoint",
    }:
        raise MatrixFailure("source-abort integrated cut has the wrong fields")
    if cut["compute_checkpoint"] != abort["compute_checkpoint"]:
        raise MatrixFailure("source-abort cut is detached from its compute checkpoint")
    plan_entry = cell_plan(DEFAULT_DATABASE_PATH, "partial-journal")
    cut_effect = _validate_capture(
        cut["barrier"],
        plan_entry["predicate"],
        target_phase="held",
        release_phase="checkpoint_released",
    )
    barrier = cut["barrier"]
    assert isinstance(barrier, dict)
    cut_token = _require_hex(
        barrier["token"], 16, "source-abort checkpoint barrier token"
    )
    source_terminal = abort["source_retained_terminal"]
    committed_terminal = abort["committed_probe_terminal"]
    assert isinstance(source_terminal, dict)
    assert isinstance(committed_terminal, dict)
    source_proof = source_terminal["proof"]
    committed_proof = committed_terminal["proof"]
    assert isinstance(source_proof, dict)
    assert isinstance(committed_proof, dict)
    expected_source_authority = {
        "schema": CANONICAL_AUTHORITY_STATE_SCHEMA,
        "generation": 2,
        "migration_manifest_sha256": abort["migration_manifest_sha256"],
        "decision": "source_retained",
        "source_retained_proof": source_proof,
        "ownership_commit_proof": None,
        "source_fence_proof": None,
    }
    expected_committed_authority = {
        "schema": CANONICAL_AUTHORITY_STATE_SCHEMA,
        "generation": 2,
        "migration_manifest_sha256": abort["migration_manifest_sha256"],
        "decision": "ownership_committed",
        "source_retained_proof": None,
        "ownership_commit_proof": committed_proof,
        "source_fence_proof": None,
    }
    if (
        documents["source_authority_state"] != expected_source_authority
        or documents["committed_authority_state"] != expected_committed_authority
        or documents["source_adapter_binding"] != abort["adapter_binding_document"]
        or documents["committed_adapter_binding"]
        != committed_terminal["adapter_binding_document"]
        or documents["source_retained_receipt"]
        != source_terminal["receipt_document"]
    ):
        raise MatrixFailure("source-abort retained authority documents diverged")
    pending = documents["pending_driver_record"]
    final = documents["final_driver_record"]
    driver_record_fields = {
        "schema",
        "generation",
        "phase",
        "pending_action",
        "intent",
        "migration_manifest",
        "source_retained_proof",
        "ownership_commit_proof",
        "source_fence_proof",
    }
    for record, label in ((pending, "pending"), (final, "final")):
        generation = record.get("generation")
        if (
            set(record) != driver_record_fields
            or record.get("schema") != DRIVER_RECORD_SCHEMA
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation <= 0
            or not isinstance(record.get("intent"), dict)
            or not isinstance(record.get("migration_manifest"), dict)
        ):
            raise MatrixFailure(f"source-abort retained {label} driver record is invalid")
    manifest = pending["migration_manifest"]
    capsule_status = _validate_source_abort_manifest(
        manifest,
        pending["intent"],
        execution_inputs=execution_inputs,
        abort=abort,
        source_proof=source_proof,
        cut_token=cut_token,
        migration_application=_artifact_identity(
            retained["migration_application"],
            "source-abort retained migration application",
        ),
        capsule_manifest=_artifact_identity(
            retained["resource_capsule_manifest"],
            "source-abort retained resource capsule manifest",
        ),
        capsule_state=_artifact_identity(
            retained["resource_capsule_state"],
            "source-abort retained resource capsule state",
        ),
        capsule_manifest_payload=capsule_manifest_payload,
        capsule_state_payload=capsule_state_payload,
        cut_effect=cut_effect,
    )
    if (
        pending.get("phase") != "source_retained"
        or pending.get("pending_action") != "resume_source_provider"
        or pending.get("source_retained_proof") != source_proof
        or pending.get("ownership_commit_proof") is not None
        or pending.get("source_fence_proof") is not None
        or pending["generation"] != 11
        or final.get("phase") != "source_resumed"
        or final.get("pending_action") is not None
        or final.get("source_retained_proof") != source_proof
        or final.get("ownership_commit_proof") is not None
        or final.get("source_fence_proof") is not None
        or final["generation"] != 14
        or pending.get("intent") != final.get("intent")
        or pending.get("migration_manifest") != final.get("migration_manifest")
        or final["generation"] != pending["generation"] + 3
        or canonical_sha256(final.get("migration_manifest"))
        != abort["migration_manifest_sha256"]
    ):
        raise MatrixFailure("source-abort retained driver records do not reconcile")
    crash = documents["crash_marker"]
    if (
        set(crash)
        != {"schema", "injected_after", "session_hex", "authority_epoch"}
        or crash["schema"] != "visa-wasi-coordinator-crash-marker-v1"
        or crash["injected_after"] != "resume_source_provider"
        or crash["session_hex"] != source_proof["session_hex"]
        or crash["authority_epoch"] != source_proof["source_epoch"]
    ):
        raise MatrixFailure("source-abort retained crash marker is invalid")
    started = documents["wanco_restore_started"]
    completion = documents["wanco_restore_completion"]
    if (
        set(started)
        != {"schema", "command_fingerprint", "attempt", "supervisor_pid"}
        or set(completion)
        != {
            "schema",
            "operation",
            "command_fingerprint",
            "attempt",
            "exit_status",
            "stdout",
            "stderr",
        }
        or started["schema"] != "visa-wanco-supervisor-started-v1"
        or completion["schema"] != "visa-wanco-restore-completion-v1"
        or completion["operation"] != "restore_source"
        or completion["exit_status"] != 0
        or completion["command_fingerprint"] != started["command_fingerprint"]
        or completion["attempt"] != started["attempt"]
        or not isinstance(started["attempt"], int)
        or isinstance(started["attempt"], bool)
        or started["attempt"] <= 0
        or not isinstance(started["supervisor_pid"], int)
        or isinstance(started["supervisor_pid"], bool)
        or started["supervisor_pid"] <= 0
    ):
        raise MatrixFailure("source-abort retained Wanco restore receipts diverged")
    _require_hex(
        started["command_fingerprint"],
        32,
        "source-abort Wanco command fingerprint",
    )
    runs = retained["application_runs"]
    assert isinstance(runs, list)
    destination = runs[1]
    assert isinstance(destination, dict)
    if (
        completion["stdout"]
        != _artifact_identity(destination["stdout"], "source-abort restore stdout")
        or completion["stderr"]
        != _artifact_identity(destination["stderr"], "source-abort restore stderr")
    ):
        raise MatrixFailure("source-abort Wanco completion is detached from its output")
    source_exit = documents["source_exit_receipt"]
    if source_exit != {
        "schema": "visa-wanco-source-exit-v1",
        "exit_status": 0,
        "checkpoint": abort["compute_checkpoint"],
    }:
        raise MatrixFailure("source-abort source-exit receipt is detached from the checkpoint")
    report_fields = {
        "schema",
        "cut",
        "source_frozen",
        "source_provider_resumed_before_restart",
        "source_provider_after_recovery",
        "source_client",
        "source_restore_client",
        "clients_pairwise_distinct",
        "manifest_sha256",
        "adapter_configuration_sha256",
        "adapter_binding_receipt",
        "adapter_binding_document",
        "source_retained_terminal",
        "committed_probe_terminal",
        "driver_record",
        "compute_checkpoint",
        "source_exit_receipt",
        "wanco_restore_completion",
        "wanco_restore_started",
        "coordinator_restart",
        "raw_client_observation",
        "namespace_snapshot",
        "external_oracle",
    }
    if set(report) != report_fields or report["schema"] != (
        "visa-sqlite-source-abort-real-driver-v4"
    ):
        raise MatrixFailure("source-abort integrated driver report has the wrong fields")
    restart = report["coordinator_restart"]
    if not isinstance(restart, dict) or set(restart) != {
        "init_exit_status",
        "injected_exit_status",
        "injected_after",
        "durable_pending_action",
        "pending_record",
        "recovery_exit_status",
        "final_phase",
        "crash_marker",
        "canonical_commit_abort_exit_status",
        "authority_init_exit_status",
        "commit_probe_init_exit_status",
        "commit_probe_commit_exit_status",
        "canonical_commit_abort_stdout",
        "canonical_commit_abort_stderr",
        "init_stdout",
        "init_stderr",
        "authority_init_stdout",
        "authority_init_stderr",
        "commit_probe_init_stdout",
        "commit_probe_init_stderr",
        "commit_probe_commit_stdout",
        "commit_probe_commit_stderr",
        "injected_stdout",
        "injected_stderr",
        "recovered_stdout",
        "recovered_stderr",
    }:
        raise MatrixFailure("source-abort restart report has the wrong fields")
    if (
        report["source_client"] != abort["source_client"]
        or report["source_restore_client"] != abort["source_restore_client"]
        or report["clients_pairwise_distinct"] is not True
        or report["manifest_sha256"] != abort["migration_manifest_sha256"]
        or report["adapter_configuration_sha256"]
        != abort["adapter_configuration_sha256"]
        or report["adapter_binding_receipt"] != abort["adapter_binding_receipt"]
        or report["adapter_binding_document"] != abort["adapter_binding_document"]
        or report["source_retained_terminal"] != source_terminal
        or report["committed_probe_terminal"] != committed_terminal
        or report["driver_record"]
        != _artifact_identity(
            retained["final_driver_record"], "source-abort final driver record"
        )
        or report["compute_checkpoint"] != abort["compute_checkpoint"]
        or report["source_exit_receipt"]
        != _artifact_identity(
            retained["source_exit_receipt"], "source-abort source-exit receipt"
        )
        or report["wanco_restore_completion"] != abort["wanco_restore_completion"]
        or report["wanco_restore_started"] != abort["wanco_restore_started"]
        or report["raw_client_observation"] != abort["raw_client_observation"]
        or report["namespace_snapshot"] != abort["namespace_snapshot"]
        or report["external_oracle"] != abort["external_oracle"]
        or restart["injected_exit_status"] != 75
        or restart["injected_after"] != "resume_source_provider"
        or restart["durable_pending_action"] != "resume_source_provider"
        or restart["pending_record"] != abort["pending_driver_record"]
        or restart["recovery_exit_status"] != 0
        or restart["final_phase"] != "source_resumed"
        or restart["crash_marker"]
        != _artifact_identity(retained["crash_marker"], "source-abort crash marker")
        or restart["canonical_commit_abort_exit_status"] == 0
        or restart["authority_init_exit_status"] != 0
        or restart["commit_probe_init_exit_status"] != 0
        or restart["commit_probe_commit_exit_status"] != 0
        or restart["init_exit_status"] != 0
        or restart["injected_exit_status"]
        != abort["coordinator_crash_exit_status"]
        or restart["authority_init_exit_status"]
        != abort["authority_init_exit_status"]
        or restart["commit_probe_init_exit_status"]
        != abort["commit_probe_init_exit_status"]
        or restart["commit_probe_commit_exit_status"]
        != abort["commit_probe_commit_exit_status"]
        or restart["canonical_commit_abort_exit_status"]
        != abort["canonical_commit_abort_exit_status"]
        or restart["recovery_exit_status"] != abort["recovery_exit_status"]
    ):
        raise MatrixFailure("source-abort integrated report differs from retained evidence")

    driver_runs = retained["driver_runs"]
    assert isinstance(driver_runs, list)
    driver_payloads: dict[str, tuple[bytes, bytes]] = {}
    for raw_run, (role, report_prefix, status_field, expected_status) in zip(
        driver_runs, SOURCE_ABORT_DRIVER_RUNS, strict=True
    ):
        assert isinstance(raw_run, dict)
        streams: dict[str, bytes] = {}
        for stream in ("stdout", "stderr"):
            streams[stream] = _read_retained_reference(
                artifact_root,
                raw_run[stream],
                f"source-abort retained {role} driver {stream}",
                budget=budget,
                max_bytes=MAX_SQLITE_STDERR_BYTES,
            )
            if restart[f"{report_prefix}_{stream}"] != _artifact_identity(
                raw_run[stream],
                f"source-abort {role} driver {stream}",
                allow_empty=True,
            ):
                raise MatrixFailure(
                    f"source-abort {role} driver output is detached from retained bytes"
                )
        status = raw_run["exit_status"]
        if (
            status != restart[status_field]
            or status != expected_status
        ):
            raise MatrixFailure(f"source-abort {role} driver exit status differs")
        driver_payloads[role] = (streams["stdout"], streams["stderr"])

    init_stdout, init_stderr = driver_payloads["init"]
    init_record = _parse_pretty_json_line(
        init_stdout, "source-abort init driver stdout"
    )
    if (
        set(init_record) != driver_record_fields
        or init_record.get("schema") != DRIVER_RECORD_SCHEMA
        or init_record.get("generation") != 8
        or init_record.get("phase") != "manifest_sealed"
        or init_record.get("pending_action") is not None
        or init_record.get("intent") != pending["intent"]
        or init_record.get("migration_manifest") != pending["migration_manifest"]
        or init_record.get("source_retained_proof") is not None
        or init_record.get("ownership_commit_proof") is not None
        or init_record.get("source_fence_proof") is not None
        or init_stderr
    ):
        raise MatrixFailure("source-abort init process did not emit generation 8")

    recovered_stdout, recovered_stderr = driver_payloads["restart-recovery"]
    if (
        _parse_pretty_json_line(
            recovered_stdout, "source-abort restart driver stdout"
        )
        != final
        or recovered_stderr
    ):
        raise MatrixFailure("source-abort restart output differs from generation 14")

    for role in (
        "authority-init",
        "commit-probe-init",
        "commit-probe-commit",
        "injected-recovery",
    ):
        if driver_payloads[role] != (b"", b""):
            raise MatrixFailure(f"source-abort {role} emitted unexpected process output")
    if driver_payloads["committed-probe-abort"] != (
        b"",
        CANONICAL_COMMIT_ABORT_STDERR,
    ):
        raise MatrixFailure(
            "source-abort committed probe did not emit the exact fail-closed diagnostic"
        )

    status_fields = {
        "mode",
        "authority_epoch",
        "barrier",
        "barrier_remaining",
        "barrier_effect",
        "effects",
        "completed_requests",
    }
    status_values: dict[str, dict[str, object]] = {}
    for name in (
        "source_frozen",
        "source_provider_resumed_before_restart",
        "source_provider_after_recovery",
    ):
        raw_status = report[name]
        if not isinstance(raw_status, dict) or set(raw_status) != status_fields:
            raise MatrixFailure(f"source-abort {name} status has the wrong fields")
        status_values[name] = status_projection(raw_status)
    frozen = status_values["source_frozen"]
    resumed = status_values["source_provider_resumed_before_restart"]
    recovered = status_values["source_provider_after_recovery"]
    source_epoch = source_proof["source_epoch"]
    released = status_projection(barrier["checkpoint_released"])
    if (
        frozen["mode"] != "frozen"
        or frozen["authority_epoch"] != source_epoch
        or frozen["barrier"] != "checkpoint_released"
        or frozen["barrier_remaining"] is not None
        or frozen["barrier_effect"] != cut_effect
        or frozen != capsule_status
        or resumed["mode"] != "active"
        or resumed["authority_epoch"] != source_epoch
        or resumed["barrier"] != "open"
        or resumed["barrier_remaining"] is not None
        or resumed["barrier_effect"] is not None
        or recovered["mode"] != "active"
        or recovered["authority_epoch"] != source_epoch
        or recovered["barrier"] != "open"
        or recovered["barrier_remaining"] is not None
        or recovered["barrier_effect"] is not None
        or frozen["effects"] != released["effects"]
        or frozen["completed_requests"] != released["completed_requests"]
        or resumed["effects"] != frozen["effects"]
        or resumed["completed_requests"] != frozen["completed_requests"]
        or recovered["effects"] <= resumed["effects"]
        or recovered["completed_requests"] <= resumed["completed_requests"]
        or recovered["effects"] != abort["namespace_snapshot"]["effects"]
    ):
        raise MatrixFailure("source-abort provider state chain is invalid")


def validate_retained_evidence(
    receipt: Mapping[str, object],
    artifact_root: Path,
    oracle_binary: Path,
) -> None:
    workload = receipt["workload"]
    execution_inputs = receipt["execution_inputs"]
    assert isinstance(workload, dict)
    assert isinstance(execution_inputs, dict)
    typed_receipt_path = artifact_root / "wanco-typed-corpus" / "receipt.json"
    try:
        typed_manifest, rederived_typed_qualification = (
            TYPED_CORPUS.load_and_validate(typed_receipt_path)
        )
    except TYPED_CORPUS.CorpusFailure as error:
        raise MatrixFailure(f"retained typed restore corpus is invalid: {error}") from error
    if rederived_typed_qualification != receipt["typed_restore_corpus_qualification"]:
        raise MatrixFailure(
            "typed restore qualification was not reproduced from retained raw bytes"
        )
    typed_raw = TYPED_CORPUS.canonical_bytes(typed_manifest) + b"\n"
    if execution_inputs["wanco_typed_restore_corpus"] != {
        "sha256": hashlib.sha256(typed_raw).hexdigest(),
        "size": len(typed_raw),
    }:
        raise MatrixFailure("retained typed restore manifest identity is invalid")
    budget = ARTIFACTS.ReadBudget(MAX_SQLITE_RETAINED_BYTES)
    recovery = receipt["process_recovery_qualification"]
    assert isinstance(recovery, dict)
    _recompute_process_recovery(
        recovery,
        artifact_root=artifact_root,
        budget=budget,
    )
    abort = receipt["source_abort_reconciliation_qualification"]
    assert isinstance(abort, dict)
    _recompute_source_abort(
        abort,
        workload=workload,
        execution_inputs=execution_inputs,
        artifact_root=artifact_root,
        oracle_binary=oracle_binary,
        budget=budget,
    )
    control = receipt["uninterrupted_control"]
    assert isinstance(control, dict)
    _recompute_retained_observation(
        control,
        label="uninterrupted control",
        workload=workload,
        execution_inputs=execution_inputs,
        artifact_root=artifact_root,
        oracle_binary=oracle_binary,
        budget=budget,
        source_cursor_required=False,
    )
    cells = receipt["cells"]
    assert isinstance(cells, list)
    for cell, spec in zip(cells, CUT_SPECS, strict=True):
        assert isinstance(cell, dict)
        _recompute_retained_observation(
            cell,
            label=f"cell {spec.cell_id}",
            workload=workload,
            execution_inputs=execution_inputs,
            artifact_root=artifact_root,
            oracle_binary=oracle_binary,
            budget=budget,
            source_cursor_required=spec.cell_id == "active-read-cursor",
        )


def _validate_uninterrupted_control(
    value: object,
    workload: Mapping[str, object],
    execution_inputs: Mapping[str, object],
) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "execution",
        "namespace_snapshot",
        "external_oracle",
        "expected_acknowledgements",
        "raw_client_observation",
        "retained_raw_evidence",
        "equivalence_projection",
    }:
        raise MatrixFailure("uninterrupted control has the wrong fields")
    if (
        value["schema"] != CONTROL_SCHEMA
        or value["execution"]
        != "single-provider-uninterrupted-transaction-and-readback"
    ):
        raise MatrixFailure("uninterrupted control has the wrong execution contract")
    _validate_namespace_snapshot(value["namespace_snapshot"], "uninterrupted control")
    oracle = _validate_external_oracle(
        value["external_oracle"], workload, execution_inputs, "uninterrupted control"
    )
    if value["expected_acknowledgements"] != workload["expected_acknowledgements"]:
        raise MatrixFailure("uninterrupted control uses a different ACK input")
    observation = _validate_raw_client_observation(
        value["raw_client_observation"],
        workload,
        label="uninterrupted control",
        migrated_cursor=False,
    )
    retained = _validate_raw_evidence_references(
        value["retained_raw_evidence"],
        label="uninterrupted control",
        path_label="uninterrupted-control",
        source_cursor_required=False,
    )
    if (
        _artifact_identity(retained["client_stdout"], "control stdout")
        != observation["stdout"]
        or _artifact_identity(
            retained["expected_acknowledgements"], "control expected acknowledgements"
        )
        != value["expected_acknowledgements"]
        or _artifact_identity(retained["namespace_snapshot"], "control namespace")
        != value["namespace_snapshot"]["artifact"]
        or _artifact_identity(retained["oracle_report"], "control oracle report")
        != value["external_oracle"]["report"]
    ):
        raise MatrixFailure("uninterrupted control raw evidence identity binding is invalid")
    derived = _derive_equivalence_projection(
        oracle, observation, "uninterrupted control"
    )
    if value["equivalence_projection"] != derived:
        raise MatrixFailure("uninterrupted control projection was not independently derived")
    return derived


def _canonical_document_identity(value: object) -> dict[str, object]:
    payload = canonical_bytes(value) + b"\n"
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def _validate_authority_proof_binding(
    proof: object,
    *,
    expected_schema: str,
    manifest_sha256: str,
    receipt: object,
    semantic_path: str,
    label: str,
) -> Mapping[str, object]:
    fields = {
        "schema",
        "migration_manifest_sha256",
        "session_hex",
        "stable_owner_hex",
        "handoff_hex",
        "source_epoch",
        "destination_epoch",
        "canonical_receipt",
    }
    if not isinstance(proof, dict) or set(proof) != fields:
        raise MatrixFailure(f"{label} proof has the wrong fields")
    if proof["schema"] != expected_schema or proof["migration_manifest_sha256"] != manifest_sha256:
        raise MatrixFailure(f"{label} proof differs from the sealed manifest")
    for name in ("session_hex", "stable_owner_hex", "handoff_hex"):
        _require_hex(proof[name], 16, f"{label} {name}")
    source_epoch = proof["source_epoch"]
    destination_epoch = proof["destination_epoch"]
    if (
        not isinstance(source_epoch, int)
        or isinstance(source_epoch, bool)
        or source_epoch <= 0
        or not isinstance(destination_epoch, int)
        or isinstance(destination_epoch, bool)
        or destination_epoch != source_epoch + 1
    ):
        raise MatrixFailure(f"{label} proof has invalid authority epochs")
    bound_receipt = proof["canonical_receipt"]
    if not isinstance(bound_receipt, dict) or set(bound_receipt) != {
        "semantic_path",
        "sha256",
        "size",
    }:
        raise MatrixFailure(f"{label} proof has a malformed receipt binding")
    if bound_receipt["semantic_path"] != semantic_path:
        raise MatrixFailure(f"{label} proof has the wrong receipt semantic path")
    _validate_file_identity(
        {"sha256": bound_receipt["sha256"], "size": bound_receipt["size"]},
        f"{label} bound receipt",
    )
    if {
        "sha256": bound_receipt["sha256"],
        "size": bound_receipt["size"],
    } != receipt:
        raise MatrixFailure(f"{label} proof differs from the retained receipt")
    return proof


def _validate_source_retained_terminal(value: object, manifest_sha256: str) -> None:
    fields = {
        "authority_schema",
        "generation",
        "decision",
        "state",
        "proof",
        "receipt",
        "receipt_document",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixFailure("source-retained terminal has the wrong fields")
    if (
        value["authority_schema"] != CANONICAL_AUTHORITY_STATE_SCHEMA
        or value["generation"] != 2
        or value["decision"] != "source_retained"
    ):
        raise MatrixFailure("source-retained authority did not win its terminal CAS")
    _validate_file_identity(value["state"], "source-retained authority state")
    _validate_file_identity(value["receipt"], "source-retained authority receipt")
    proof = _validate_authority_proof_binding(
        value["proof"],
        expected_schema=SOURCE_RETAINED_PROOF_SCHEMA,
        manifest_sha256=manifest_sha256,
        receipt=value["receipt"],
        semantic_path="authority/source-retained.json",
        label="source-retained authority",
    )
    receipt_document = value["receipt_document"]
    receipt_fields = {
        "schema",
        "decision",
        "migration_manifest_sha256",
        "session_hex",
        "stable_owner_hex",
        "handoff_hex",
        "source_epoch",
        "destination_epoch",
    }
    if not isinstance(receipt_document, dict) or set(receipt_document) != receipt_fields:
        raise MatrixFailure("source-retained receipt document has the wrong fields")
    if (
        receipt_document["schema"] != SOURCE_RETAINED_RECEIPT_SCHEMA
        or receipt_document["decision"] != "source_retained"
        or any(
            receipt_document[name] != proof[name]
            for name in receipt_fields - {"schema", "decision"}
        )
    ):
        raise MatrixFailure("source-retained receipt is not bound to its proof")
    if value["receipt"] != _canonical_document_identity(receipt_document):
        raise MatrixFailure("source-retained receipt identity differs from its document")
    authority_document = {
        "schema": value["authority_schema"],
        "generation": value["generation"],
        "migration_manifest_sha256": manifest_sha256,
        "decision": value["decision"],
        "source_retained_proof": value["proof"],
        "ownership_commit_proof": None,
        "source_fence_proof": None,
    }
    if value["state"] != _canonical_document_identity(authority_document):
        raise MatrixFailure("source-retained state identity differs from its terminal document")


def _validate_adapter_binding(
    receipt: object,
    document: object,
    adapter_configuration_sha256: object,
    label: str,
) -> dict[str, object]:
    _validate_file_identity(receipt, f"{label} receipt")
    configuration_sha256 = _require_hex(
        adapter_configuration_sha256, 32, f"{label} adapter configuration sha256"
    )
    if not isinstance(document, dict) or set(document) != {"schema", "adapter"}:
        raise MatrixFailure(f"{label} document has the wrong fields")
    if document["schema"] != "visa-wasi-adapter-binding-v2":
        raise MatrixFailure(f"{label} document has the wrong schema")
    adapter = document["adapter"]
    _validate_file_identity(adapter, f"{label} adapter")
    if adapter["sha256"] != configuration_sha256:
        raise MatrixFailure(f"{label} does not bind its adapter configuration")
    if receipt != _canonical_document_identity(document):
        raise MatrixFailure(f"{label} receipt identity differs from its document")
    return adapter


def _validate_committed_probe_terminal(value: object, manifest_sha256: str) -> None:
    fields = {
        "authority_schema",
        "generation",
        "decision",
        "state",
        "proof",
        "receipt",
        "receipt_document",
        "adapter_configuration_sha256",
        "adapter_binding_receipt",
        "adapter_binding_document",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise MatrixFailure("committed probe terminal has the wrong fields")
    if (
        value["authority_schema"] != CANONICAL_AUTHORITY_STATE_SCHEMA
        or value["generation"] != 2
        or value["decision"] != "ownership_committed"
    ):
        raise MatrixFailure("commit probe did not win its independent terminal CAS")
    _validate_file_identity(value["state"], "committed probe authority state")
    _validate_file_identity(value["receipt"], "committed probe authority receipt")
    _validate_adapter_binding(
        value["adapter_binding_receipt"],
        value["adapter_binding_document"],
        value["adapter_configuration_sha256"],
        "committed probe adapter binding",
    )
    _validate_authority_proof_binding(
        value["proof"],
        expected_schema="visa-canonical-ownership-commit-proof-v1",
        manifest_sha256=manifest_sha256,
        receipt=value["receipt"],
        semantic_path="authority/commit.json",
        label="committed probe authority",
    )
    receipt_document = value["receipt_document"]
    if receipt_document != {
        "schema": "visa-wasi-authority-commit-receipt-v1",
        "migration_manifest_sha256": manifest_sha256,
    }:
        raise MatrixFailure("committed probe receipt differs from the sealed manifest")
    if value["receipt"] != _canonical_document_identity(receipt_document):
        raise MatrixFailure("committed probe receipt identity differs from its document")
    authority_document = {
        "schema": value["authority_schema"],
        "generation": value["generation"],
        "migration_manifest_sha256": manifest_sha256,
        "decision": value["decision"],
        "source_retained_proof": None,
        "ownership_commit_proof": value["proof"],
        "source_fence_proof": None,
    }
    if value["state"] != _canonical_document_identity(authority_document):
        raise MatrixFailure("committed probe state identity differs from its terminal document")


def _validate_capture(
    value: object,
    expected_predicate: Mapping[str, object],
    *,
    target_phase: str,
    release_phase: str | None,
) -> str:
    required = {"token", "predicate", "armed", "target"}
    release_field = {
        None: None,
        "checkpoint_released": "checkpoint_released",
        "open": "continued",
    }.get(release_phase)
    if release_phase is not None and release_field is None:
        raise MatrixFailure("barrier capture has an unsupported release phase")
    if release_field is not None:
        required.add(release_field)
    if not isinstance(value, dict) or set(value) != required:
        raise MatrixFailure("barrier capture has the wrong fields")
    _require_hex(value["token"], 16, "barrier token")
    if value["predicate"] != expected_predicate:
        raise MatrixFailure("barrier capture predicate differs from the plan")
    armed = status_projection(value["armed"])
    target = status_projection(value["target"])
    if (
        armed["mode"] != "active"
        or armed["barrier"] != "armed"
        or armed["barrier_remaining"] != expected_predicate["occurrence"]
        or armed["barrier_effect"] is not None
        or target["mode"] != "active"
        or target["authority_epoch"] != armed["authority_epoch"]
        or target["barrier_remaining"] is not None
        or target["effects"] <= armed["effects"]
        or target["completed_requests"] <= armed["completed_requests"]
    ):
        raise MatrixFailure("barrier capture lacks the exact armed occurrence")
    if target["barrier"] != target_phase or target["barrier_effect"] is None:
        raise MatrixFailure("barrier capture lacks its exact target phase/effect")
    effect = str(target["barrier_effect"])
    if release_field is not None:
        released = status_projection(value[release_field])
        if (
            released["mode"] != "active"
            or released["authority_epoch"] != target["authority_epoch"]
            or released["barrier"] != release_phase
            or released["barrier_remaining"] is not None
            or released["effects"] != target["effects"]
            or released["completed_requests"] != target["completed_requests"]
        ):
            raise MatrixFailure("barrier capture lacks its required release phase")
        if release_phase == "checkpoint_released":
            if released["barrier_effect"] != effect:
                raise MatrixFailure("barrier effect changed at checkpoint release")
        elif released["barrier_effect"] is not None:
            raise MatrixFailure("continued barrier retained its target effect")
    return effect


def _validate_handoff(value: object) -> None:
    required = {
        "source_frozen",
        "destination_prepared",
        "source_fenced",
        "destination_active",
        "source_client",
        "destination_client",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise MatrixFailure("handoff evidence has the wrong fields")
    source = status_projection(value["source_frozen"])
    prepared = status_projection(value["destination_prepared"])
    fenced = status_projection(value["source_fenced"])
    active = status_projection(value["destination_active"])
    if [source["mode"], prepared["mode"], fenced["mode"], active["mode"]] != [
        "frozen",
        "prepared",
        "fenced",
        "active",
    ]:
        raise MatrixFailure("handoff mode chain is invalid")
    if not (
        source["authority_epoch"]
        == prepared["authority_epoch"]
        == fenced["authority_epoch"]
        and active["authority_epoch"] == source["authority_epoch"] + 1
    ):
        raise MatrixFailure("handoff authority epochs are invalid")
    source_client = _require_hex(value["source_client"], 16, "source client")
    destination_client = _require_hex(
        value["destination_client"], 16, "destination client"
    )
    if source_client == destination_client:
        raise MatrixFailure("destination compute did not use a fresh client")


def validate_matrix_receipt(
    receipt: object, expected_revision: str | None = None
) -> None:
    if not isinstance(receipt, dict):
        raise MatrixFailure("matrix receipt must be a JSON object")
    required = {
        "schema",
        "repository_revision",
        "repository_source_snapshot",
        "execution_inputs",
        "plan",
        "plan_sha256",
        "workload",
        "uninterrupted_control",
        "cells",
        "typed_restore_corpus_qualification",
        "process_recovery_qualification",
        "source_abort_reconciliation_qualification",
        "durability_scope",
    }
    if set(receipt) != required or receipt.get("schema") != MATRIX_SCHEMA:
        raise MatrixFailure("matrix receipt schema or fields are invalid")
    revision = receipt["repository_revision"]
    if not isinstance(revision, str) or SHA1_RE.fullmatch(revision) is None:
        raise MatrixFailure("repository revision must be a lowercase 40-hex Git identity")
    if expected_revision is not None:
        if SHA1_RE.fullmatch(expected_revision) is None:
            raise MatrixFailure("expected revision must be a lowercase 40-hex Git identity")
        if revision != expected_revision:
            raise MatrixFailure("repository revision differs from the expected exact SHA")
    source_snapshot = receipt["repository_source_snapshot"]
    if not isinstance(source_snapshot, dict) or set(source_snapshot) != {
        "clean",
        "status_sha256",
        "tracked_patch_sha256",
        "untracked_file_count",
        "untracked_manifest_sha256",
    }:
        raise MatrixFailure("repository source snapshot has the wrong fields")
    if source_snapshot["clean"] is not True:
        raise MatrixFailure("repository source snapshot clean must be true")
    for name in (
        "status_sha256",
        "tracked_patch_sha256",
        "untracked_manifest_sha256",
    ):
        _require_hex(source_snapshot[name], 32, "repository " + name)
    if (
        not isinstance(source_snapshot["untracked_file_count"], int)
        or isinstance(source_snapshot["untracked_file_count"], bool)
        or source_snapshot["untracked_file_count"] != 0
    ):
        raise MatrixFailure("repository source snapshot must have no untracked files")
    empty = hashlib.sha256(b"").hexdigest()
    empty_manifest = hashlib.sha256(canonical_bytes([])).hexdigest()
    if (
        source_snapshot["status_sha256"] != empty
        or source_snapshot["tracked_patch_sha256"] != empty
        or source_snapshot["untracked_manifest_sha256"] != empty_manifest
    ):
        raise MatrixFailure("repository source snapshot does not encode a clean tree")
    execution_inputs = receipt["execution_inputs"]
    expected_inputs = {
        "sqlite_source_lock",
        "sqlite_build_receipt",
        "wanco_source_lock",
        "wanco_build_receipt",
        "wanco_typed_restore_corpus",
        "stock_sqlite_wasm",
        "stock_sqlite_aot",
        "stock_sqlite_import_trace",
        "visa_wasi_host",
        "visa_migration_bind",
        "visa_migration_driver",
        "visa_sqlite_oracle",
    }
    if not isinstance(execution_inputs, dict) or set(execution_inputs) != expected_inputs:
        raise MatrixFailure("execution input binding has the wrong fields")
    for name in sorted(expected_inputs):
        _validate_file_identity(execution_inputs[name], "execution input " + name)
    typed_corpus = receipt["typed_restore_corpus_qualification"]
    try:
        TYPED_CORPUS.validate_qualification_structure(typed_corpus)
    except TYPED_CORPUS.CorpusFailure as error:
        raise MatrixFailure(f"typed restore qualification is invalid: {error}") from error
    if typed_corpus["wanco_build_receipt"] != execution_inputs["wanco_build_receipt"]:
        raise MatrixFailure("typed restore corpus uses a different Wanco build receipt")
    if typed_corpus["manifest"] != execution_inputs["wanco_typed_restore_corpus"]:
        raise MatrixFailure("typed restore corpus manifest identity is invalid")
    plan = receipt["plan"]
    if not isinstance(plan, dict) or plan != build_plan(DEFAULT_DATABASE_PATH):
        raise MatrixFailure("matrix receipt does not contain the canonical cut plan")
    if receipt["plan_sha256"] != canonical_sha256(plan):
        raise MatrixFailure("matrix plan digest is invalid")
    workload = receipt["workload"]
    if not isinstance(workload, dict) or set(workload) != {
        "stock_sqlite_artifact",
        "sql_input",
        "expected_acknowledgements",
        "initial_total_balance",
        "expected_acknowledgement_txids",
        "minimum_dirty_database_pages",
        "expected_cursor_rows",
    }:
        raise MatrixFailure("workload evidence has the wrong fields")
    for name in (
        "stock_sqlite_artifact",
        "sql_input",
        "expected_acknowledgements",
    ):
        _validate_file_identity(workload[name], "workload " + name)
    if workload["stock_sqlite_artifact"] != execution_inputs["stock_sqlite_aot"]:
        raise MatrixFailure("workload does not use the bound stock SQLite AOT")
    if workload["initial_total_balance"] != 512000:
        raise MatrixFailure("workload initial balance does not match the stock seed")
    if workload["expected_acknowledgement_txids"] != ["tx-000001"]:
        raise MatrixFailure("workload acknowledgement set does not match the stock transfer")
    if (
        not isinstance(workload["minimum_dirty_database_pages"], int)
        or isinstance(workload["minimum_dirty_database_pages"], bool)
        or workload["minimum_dirty_database_pages"] < 3
    ):
        raise MatrixFailure("workload must dirty at least three database pages")
    if (
        not isinstance(workload["expected_cursor_rows"], int)
        or isinstance(workload["expected_cursor_rows"], bool)
        or workload["expected_cursor_rows"] < 3
    ):
        raise MatrixFailure("cursor workload must contain at least three rows")
    control_projection = _validate_uninterrupted_control(
        receipt["uninterrupted_control"], workload, execution_inputs
    )
    recovery = receipt["process_recovery_qualification"]
    _validate_process_recovery_qualification(recovery)
    assert isinstance(recovery, dict)
    abort = receipt["source_abort_reconciliation_qualification"]
    if not isinstance(abort, dict) or set(abort) != {
        "schema",
        "scope",
        "integrated_driver_report",
        "compute_checkpoint",
        "coordinator_crash_exit_status",
        "durable_pending_action",
        "pending_driver_record",
        "adapter_configuration_sha256",
        "adapter_binding_receipt",
        "adapter_binding_document",
        "migration_manifest_sha256",
        "source_retained_terminal",
        "committed_probe_terminal",
        "authority_init_exit_status",
        "commit_probe_init_exit_status",
        "commit_probe_commit_exit_status",
        "canonical_commit_abort_exit_status",
        "recovery_exit_status",
        "final_phase",
        "wanco_restore_completion",
        "wanco_restore_started",
        "external_oracle_report",
        "raw_client_observation",
        "expected_acknowledgements",
        "namespace_snapshot",
        "external_oracle",
        "equivalence_projection",
        "accepted",
        "source_client",
        "source_restore_client",
        "retained_raw_evidence",
    }:
        raise MatrixFailure("source-abort reconciliation qualification has the wrong fields")
    if (
        abort["schema"] != SOURCE_ABORT_SCHEMA
        or abort["scope"] != "pre-commit-source-compute-abort"
    ):
        raise MatrixFailure("source-abort reconciliation qualification has the wrong scope")
    _validate_file_identity(
        abort["integrated_driver_report"], "source-abort integrated driver report"
    )
    _validate_file_identity(
        abort["compute_checkpoint"], "source-abort compute checkpoint"
    )
    _validate_file_identity(abort["pending_driver_record"], "source-abort pending driver record")
    source_adapter = _validate_adapter_binding(
        abort["adapter_binding_receipt"],
        abort["adapter_binding_document"],
        abort["adapter_configuration_sha256"],
        "source-abort adapter binding",
    )
    manifest_sha256 = _require_hex(
        abort["migration_manifest_sha256"], 32, "source-abort migration manifest sha256"
    )
    _validate_source_retained_terminal(abort["source_retained_terminal"], manifest_sha256)
    _validate_committed_probe_terminal(abort["committed_probe_terminal"], manifest_sha256)
    source_terminal = abort["source_retained_terminal"]
    commit_terminal = abort["committed_probe_terminal"]
    assert isinstance(source_terminal, dict)
    assert isinstance(commit_terminal, dict)
    commit_adapter = commit_terminal["adapter_binding_document"]["adapter"]
    if (
        source_adapter == commit_adapter
        or abort["adapter_binding_receipt"] == commit_terminal["adapter_binding_receipt"]
        or abort["adapter_configuration_sha256"]
        == commit_terminal["adapter_configuration_sha256"]
    ):
        raise MatrixFailure("abort and commit probe did not use independent authority adapters")
    source_proof = source_terminal["proof"]
    commit_proof = commit_terminal["proof"]
    assert isinstance(source_proof, dict)
    assert isinstance(commit_proof, dict)
    shared_binding_fields = {
        "migration_manifest_sha256",
        "session_hex",
        "stable_owner_hex",
        "handoff_hex",
        "source_epoch",
        "destination_epoch",
    }
    if any(source_proof[field] != commit_proof[field] for field in shared_binding_fields):
        raise MatrixFailure("abort and commit-probe authorities bind different migrations")
    _validate_file_identity(
        abort["wanco_restore_completion"], "source-abort Wanco completion"
    )
    _validate_file_identity(abort["wanco_restore_started"], "source-abort Wanco started receipt")
    _validate_file_identity(
        abort["external_oracle_report"], "source-abort SQLite oracle report"
    )
    if abort["expected_acknowledgements"] != workload["expected_acknowledgements"]:
        raise MatrixFailure("source-abort uses a different ACK input")
    _validate_namespace_snapshot(abort["namespace_snapshot"], "source-abort")
    abort_oracle = _validate_external_oracle(
        abort["external_oracle"],
        workload,
        execution_inputs,
        "source-abort",
    )
    abort_observation = _validate_raw_client_observation(
        abort["raw_client_observation"],
        workload,
        label="source-abort",
        migrated_cursor=False,
    )
    abort_equivalence = _derive_equivalence_projection(
        abort_oracle,
        abort_observation,
        "source-abort",
    )
    if (
        abort["external_oracle_report"]
        != abort["external_oracle"]["report"]
        or abort["equivalence_projection"]
        != abort_equivalence
        or abort_equivalence != control_projection
    ):
        raise MatrixFailure("source-abort semantic projection differs from its control")
    _validate_source_abort_retained_references(
        abort["retained_raw_evidence"],
        abort,
    )
    if (
        abort["coordinator_crash_exit_status"] != 75
        or abort["authority_init_exit_status"] != 0
        or abort["commit_probe_init_exit_status"] != 0
        or abort["commit_probe_commit_exit_status"] != 0
        or abort["canonical_commit_abort_exit_status"] == 0
        or abort["durable_pending_action"] != "resume_source_provider"
        or abort["recovery_exit_status"] != 0
        or abort["final_phase"] != "source_resumed"
    ):
        raise MatrixFailure("real migration driver restart reconciliation did not complete")
    source_client = _require_hex(abort["source_client"], 16, "abort source client")
    restore_client = _require_hex(
        abort["source_restore_client"], 16, "abort source restore client"
    )
    if source_client == restore_client or abort["accepted"] is not True:
        raise MatrixFailure("real Wanco source abort did not restore with a fresh client")
    scope = receipt["durability_scope"]
    if scope != {
        "provider_process_crash": True,
        "power_loss": False,
        "torn_sector": False,
        "device_write_reordering": False,
    }:
        raise MatrixFailure("durability scope overclaims or omits the qualified model")
    cells = receipt["cells"]
    if not isinstance(cells, list) or len(cells) != len(CUT_SPECS):
        raise MatrixFailure("matrix must contain exactly eight cells")
    plans = {cell["cell_id"]: cell for cell in plan["cells"]}
    seen: set[str] = set()
    for index, cell in enumerate(cells):
        if not isinstance(cell, dict) or cell.get("schema") != CELL_SCHEMA:
            raise MatrixFailure("matrix cell schema is invalid")
        cell_id = cell.get("cell_id")
        if cell_id in seen or cell_id != CUT_SPECS[index].cell_id:
            raise MatrixFailure("matrix cells are duplicated or out of canonical order")
        seen.add(str(cell_id))
        _validate_cell(
            cell,
            plans[str(cell_id)],
            CUT_SPECS[index],
            workload,
            execution_inputs,
            control_projection,
        )


def _validate_cell(
    cell: Mapping[str, object],
    plan: Mapping[str, object],
    spec: CutSpec,
    workload: Mapping[str, object],
    execution_inputs: Mapping[str, object],
    control_projection: Mapping[str, object],
) -> None:
    required = {
        "schema",
        "cell_id",
        "plan_entry_sha256",
        "barrier",
        "compute_checkpoint",
        "handoff",
        "namespace_snapshot",
        "external_oracle",
        "expected_acknowledgements",
        "raw_client_observation",
        "retained_raw_evidence",
        "equivalence_projection",
    }
    if spec.continuation_witness is not None:
        required.add("continuation_witness")
    if spec.external_anchor is not None:
        required.add("external_anchor")
    if spec.cell_id == "lost-response":
        required.add("delivery_fault")
    if set(cell) != required:
        raise MatrixFailure(f"cell {spec.cell_id} has the wrong fields")
    if cell["plan_entry_sha256"] != canonical_sha256(plan):
        raise MatrixFailure(f"cell {spec.cell_id} plan binding is invalid")
    effect = _validate_capture(
        cell["barrier"],
        plan["predicate"],
        target_phase=spec.target_phase,
        release_phase="checkpoint_released" if spec.target_phase == "held" else None,
    )
    _validate_file_identity(cell["compute_checkpoint"], "compute checkpoint")
    _validate_handoff(cell["handoff"])
    _validate_namespace_snapshot(cell["namespace_snapshot"], f"cell {spec.cell_id}")
    oracle_projection = _validate_external_oracle(
        cell["external_oracle"],
        workload,
        execution_inputs,
        f"cell {spec.cell_id}",
    )
    if cell["expected_acknowledgements"] != workload["expected_acknowledgements"]:
        raise MatrixFailure("cell acknowledgement input differs from the workload binding")
    observation = _validate_raw_client_observation(
        cell["raw_client_observation"],
        workload,
        label=f"cell {spec.cell_id}",
        migrated_cursor=spec.cell_id == "active-read-cursor",
    )
    retained = _validate_raw_evidence_references(
        cell["retained_raw_evidence"],
        label=f"cell {spec.cell_id}",
        path_label=spec.cell_id,
        source_cursor_required=spec.cell_id == "active-read-cursor",
    )
    if (
        _artifact_identity(retained["client_stdout"], f"cell {spec.cell_id} stdout")
        != observation["stdout"]
        or _artifact_identity(
            retained["expected_acknowledgements"],
            f"cell {spec.cell_id} expected acknowledgements",
        )
        != cell["expected_acknowledgements"]
        or _artifact_identity(
            retained["namespace_snapshot"], f"cell {spec.cell_id} namespace"
        )
        != cell["namespace_snapshot"]["artifact"]
        or _artifact_identity(
            retained["oracle_report"], f"cell {spec.cell_id} oracle report"
        )
        != cell["external_oracle"]["report"]
    ):
        raise MatrixFailure(f"cell {spec.cell_id} raw evidence identity binding is invalid")
    derived_projection = _derive_equivalence_projection(
        oracle_projection, observation, f"cell {spec.cell_id}"
    )
    if cell["equivalence_projection"] != derived_projection:
        raise MatrixFailure(f"cell {spec.cell_id} projection was not independently derived")
    if derived_projection != control_projection:
        raise MatrixFailure(
            f"cell {spec.cell_id} behavior differs from the uninterrupted control"
        )
    if spec.continuation_witness is not None:
        witness = cell["continuation_witness"]
        witness_effect = _validate_capture(
            witness,
            plan["continuation_witness"],
            target_phase="held",
            release_phase="open",
        )
        if witness_effect == effect:
            raise MatrixFailure("continuation witness reused the cut effect")
        if witness["token"] == cell["barrier"]["token"]:
            raise MatrixFailure("continuation witness reused the cut barrier token")
    if spec.external_anchor is not None:
        anchor = cell["external_anchor"]
        if not isinstance(anchor, dict) or anchor.get("kind") != spec.external_anchor:
            raise MatrixFailure(f"cell {spec.cell_id} external anchor is invalid")
        _validate_file_identity(anchor.get("observation"), "external anchor observation")
        if anchor["observation"] != observation["stdout"]:
            raise MatrixFailure("external anchor is not bound to the raw client stdout")
        if spec.cell_id == "active-read-cursor":
            rows = anchor.get("observed_prefix_rows")
            if (
                not isinstance(rows, int)
                or isinstance(rows, bool)
                or rows <= 0
                or rows >= workload["expected_cursor_rows"]
            ):
                raise MatrixFailure("active cursor anchor is not a strict row prefix")
    if spec.cell_id == "lost-response":
        fault = cell["delivery_fault"]
        expected_fields = {
            "injection",
            "injector",
            "injection_trace",
            "triggered_effect",
            "replayed_effect",
            "source_client",
            "replay_client",
            "source_sequence",
            "replay_sequence",
            "effects_before_replay",
            "effects_after_replay",
            "replay_held",
            "checkpoint_released",
            "pre_completion_source_death",
        }
        if not isinstance(fault, dict) or set(fault) != expected_fields:
            raise MatrixFailure("lost-response evidence has the wrong fields")
        if fault["injection"] != "drop-guest-response-after-durable-effect":
            raise MatrixFailure("lost-response injection point is invalid")
        _validate_file_identity(fault["injector"], "lost-response injector")
        _validate_file_identity(fault["injection_trace"], "lost-response injection trace")
        triggered = _require_hex(fault["triggered_effect"], 16, "triggered effect")
        replayed = _require_hex(fault["replayed_effect"], 16, "replayed effect")
        if triggered != replayed or triggered != effect:
            raise MatrixFailure("lost response did not replay the same stable effect")
        source_client = _require_hex(fault["source_client"], 16, "source client")
        replay_client = _require_hex(fault["replay_client"], 16, "replay client")
        if source_client != replay_client:
            raise MatrixFailure("lost response retry changed the source process client")
        source_sequence = fault["source_sequence"]
        replay_sequence = fault["replay_sequence"]
        if (
            not isinstance(source_sequence, int)
            or isinstance(source_sequence, bool)
            or source_sequence <= 0
            or replay_sequence != source_sequence
        ):
            raise MatrixFailure("lost response retry changed the source request sequence")
        before = fault["effects_before_replay"]
        after = fault["effects_after_replay"]
        if (
            not isinstance(before, int)
            or isinstance(before, bool)
            or before <= 0
            or after != before
        ):
            raise MatrixFailure("lost response replay changed the durable effect count")
        replay_held = status_projection(fault["replay_held"])
        released = status_projection(fault["checkpoint_released"])
        if replay_held["barrier"] != "held" or replay_held["barrier_effect"] != effect:
            raise MatrixFailure("lost response replay did not complete the same barrier")
        if released["barrier"] != "checkpoint_released" or released["barrier_effect"] != effect:
            raise MatrixFailure("lost response replay was not checkpoint-released")
        cell_handoff = cell["handoff"]
        if cell_handoff["source_client"] != source_client:
            raise MatrixFailure("lost response source client differs from handoff evidence")
        death = fault["pre_completion_source_death"]
        if not isinstance(death, dict) or set(death) != {
            "triggered_status",
            "migration_attempt_trace",
            "migration_attempt_exit_status",
            "rejected_by",
        }:
            raise MatrixFailure("pre-completion source-death evidence has the wrong fields")
        death_status = status_projection(death["triggered_status"])
        if death_status["barrier"] != "triggered" or death_status["barrier_effect"] is None:
            raise MatrixFailure("source-death negative control is not at a durable target effect")
        _validate_file_identity(
            death["migration_attempt_trace"], "source-death migration rejection trace"
        )
        exit_status = death["migration_attempt_exit_status"]
        if not isinstance(exit_status, int) or isinstance(exit_status, bool) or exit_status == 0:
            raise MatrixFailure("source-death migration attempt was not rejected")
        if death["rejected_by"] != "incomplete-delivery-drain-gate":
            raise MatrixFailure("source death was not rejected by the delivery drain gate")


# Runner-facing name: a receipt is valid only when the strict matrix validator
# accepts every canonical cell and the process-crash qualification.
validate_receipt = validate_matrix_receipt


def load_and_validate(
    path: Path,
    *,
    expected_revision: str,
    oracle_binary: Path,
) -> Mapping[str, object]:
    absolute = path.absolute()
    try:
        raw = ARTIFACTS.read_bounded_file(
            absolute, "matrix receipt", max_bytes=MAX_SQLITE_JSON_BYTES
        )
    except ARTIFACTS.ArtifactError as error:
        raise MatrixFailure(str(error)) from error
    receipt = _parse_json_bytes(raw, "matrix receipt")
    if canonical_bytes(receipt) + b"\n" != raw:
        raise MatrixFailure("matrix receipt is not canonical newline-terminated JSON")
    validate_matrix_receipt(receipt, expected_revision)
    validate_retained_evidence(receipt, absolute.parent, oracle_binary)
    return receipt


def _publish(path: Path, value: object) -> None:
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
        if temporary.exists():
            temporary.unlink()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="emit the canonical non-evidence cut plan")
    plan.add_argument("--database-path", default=DEFAULT_DATABASE_PATH)
    plan.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate", help="validate a completed matrix receipt")
    validate.add_argument("receipt", type=Path)
    validate.add_argument("--expected-revision", required=True)
    validate.add_argument("--oracle-binary", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    try:
        if arguments.command == "plan":
            _publish(arguments.output, build_plan(arguments.database_path))
            print(f"SQLite rollback-journal cut plan: {arguments.output}")
            return 0
        load_and_validate(
            arguments.receipt,
            expected_revision=arguments.expected_revision,
            oracle_binary=arguments.oracle_binary,
        )
        print(f"SQLite rollback-journal matrix receipt is valid: {arguments.receipt}")
        return 0
    except (MatrixFailure, OSError, json.JSONDecodeError) as error:
        print(f"SQLite rollback-journal matrix failed: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
