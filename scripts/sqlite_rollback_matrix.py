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
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Protocol

import wanco_typed_corpus as TYPED_CORPUS


PLAN_SCHEMA = "visa-stock-sqlite-rollback-journal-plan-v1"
CELL_SCHEMA = "visa-stock-sqlite-rollback-journal-cell-v2"
MATRIX_SCHEMA = "visa-stock-sqlite-rollback-journal-matrix-v5"
CONTROL_SCHEMA = "visa-stock-sqlite-uninterrupted-control-v1"
ORACLE_REPORT_SCHEMA = "visa-sqlite-oracle-report-v2"
ORACLE_PROJECTION_SCHEMA = "visa-sqlite-semantic-projection-v1"
EQUIVALENCE_PROJECTION_SCHEMA = "visa-stock-sqlite-equivalence-projection-v1"
CANONICAL_AUTHORITY_STATE_SCHEMA = "visa-wasi-canonical-authority-state-v2"
SOURCE_RETAINED_PROOF_SCHEMA = "visa-canonical-source-retained-proof-v1"
SOURCE_RETAINED_RECEIPT_SCHEMA = "visa-wasi-authority-source-retained-receipt-v1"
DEFAULT_DATABASE_PATH = "workload/accounts.db"
DEFAULT_TIMEOUT_SECONDS = 120.0
POLL_INTERVAL_SECONDS = 0.02


class MatrixFailure(RuntimeError):
    """The exact-cut protocol or retained evidence is invalid."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_identity(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise MatrixFailure(f"expected a regular retained artifact: {path}")
    size = path.stat().st_size
    if size <= 0:
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
        armed["barrier"] != "armed"
        or armed["barrier_remaining"] != expected_predicate["occurrence"]
    ):
        raise MatrixFailure("barrier capture lacks the exact armed occurrence")
    if target["barrier"] != target_phase or target["barrier_effect"] is None:
        raise MatrixFailure("barrier capture lacks its exact target phase/effect")
    effect = str(target["barrier_effect"])
    if release_field is not None:
        released = status_projection(value[release_field])
        if released["barrier"] != release_phase:
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


def validate_matrix_receipt(receipt: object) -> None:
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
    _require_hex(receipt["repository_revision"], 20, "repository revision")
    source_snapshot = receipt["repository_source_snapshot"]
    if not isinstance(source_snapshot, dict) or set(source_snapshot) != {
        "clean",
        "status_sha256",
        "tracked_patch_sha256",
        "untracked_file_count",
        "untracked_manifest_sha256",
    }:
        raise MatrixFailure("repository source snapshot has the wrong fields")
    if not isinstance(source_snapshot["clean"], bool):
        raise MatrixFailure("repository source snapshot clean flag is invalid")
    for name in (
        "status_sha256",
        "tracked_patch_sha256",
        "untracked_manifest_sha256",
    ):
        _require_hex(source_snapshot[name], 32, "repository " + name)
    if (
        not isinstance(source_snapshot["untracked_file_count"], int)
        or isinstance(source_snapshot["untracked_file_count"], bool)
        or source_snapshot["untracked_file_count"] < 0
    ):
        raise MatrixFailure("repository untracked file count is invalid")
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
        TYPED_CORPUS.validate_receipt(typed_corpus)
    except TYPED_CORPUS.CorpusFailure as error:
        raise MatrixFailure(f"typed restore corpus is invalid: {error}") from error
    if typed_corpus["wanco_build_receipt"] != execution_inputs["wanco_build_receipt"]:
        raise MatrixFailure("typed restore corpus uses a different Wanco build receipt")
    typed_raw = TYPED_CORPUS.canonical_bytes(typed_corpus) + b"\n"
    if execution_inputs["wanco_typed_restore_corpus"] != {
        "sha256": hashlib.sha256(typed_raw).hexdigest(),
        "size": len(typed_raw),
    }:
        raise MatrixFailure("typed restore corpus qualification identity is invalid")
    plan = receipt["plan"]
    if not isinstance(plan, dict) or plan != build_plan(str(plan.get("database_path", ""))):
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
    if not isinstance(recovery, dict) or set(recovery) != {
        "scope",
        "report",
        "exit_status",
        "qualified_tests",
    }:
        raise MatrixFailure("provider process-recovery qualification has the wrong fields")
    if recovery["scope"] != "provider-process-kill-reopen":
        raise MatrixFailure("provider process-recovery qualification has the wrong scope")
    _validate_file_identity(recovery["report"], "provider process-recovery report")
    if recovery["exit_status"] != 0 or recovery["qualified_tests"] != [
        "response_loss_then_provider_kill_reopen_replays_exactly_once",
        "fd_sync_and_datasync_survive_provider_kill_reopen_in_process_crash_model",
    ]:
        raise MatrixFailure("provider kill/reopen qualification did not pass both required cases")
    abort = receipt["source_abort_reconciliation_qualification"]
    if not isinstance(abort, dict) or set(abort) != {
        "scope",
        "integrated_driver_report",
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
        "accepted",
        "source_client",
        "source_restore_client",
    }:
        raise MatrixFailure("source-abort reconciliation qualification has the wrong fields")
    if abort["scope"] != "pre-commit-source-compute-abort":
        raise MatrixFailure("source-abort reconciliation qualification has the wrong scope")
    _validate_file_identity(
        abort["integrated_driver_report"], "source-abort integrated driver report"
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
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    try:
        if arguments.command == "plan":
            _publish(arguments.output, build_plan(arguments.database_path))
            print(f"SQLite rollback-journal cut plan: {arguments.output}")
            return 0
        raw = arguments.receipt.read_bytes()
        receipt = json.loads(raw)
        if canonical_bytes(receipt) + b"\n" != raw:
            raise MatrixFailure("matrix receipt is not canonical newline-terminated JSON")
        validate_matrix_receipt(receipt)
        print(f"SQLite rollback-journal matrix receipt is valid: {arguments.receipt}")
        return 0
    except (MatrixFailure, OSError, json.JSONDecodeError) as error:
        print(f"SQLite rollback-journal matrix failed: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
