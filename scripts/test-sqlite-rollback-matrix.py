#!/usr/bin/env python3
"""Focused tests for the exact stock-SQLite rollback-journal matrix contract."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("sqlite_rollback_matrix.py")
SPEC = importlib.util.spec_from_file_location("sqlite_rollback_matrix", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load SQLite rollback matrix module")
MATRIX = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MATRIX
SPEC.loader.exec_module(MATRIX)

WANCO_FIXTURE_PATH = Path(__file__).with_name("test-wanco-typed-corpus.py")
WANCO_FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "wanco_typed_corpus_test_fixture", WANCO_FIXTURE_PATH
)
if WANCO_FIXTURE_SPEC is None or WANCO_FIXTURE_SPEC.loader is None:
    raise RuntimeError("cannot load Wanco typed-corpus test fixture")
WANCO_FIXTURE = importlib.util.module_from_spec(WANCO_FIXTURE_SPEC)
sys.modules[WANCO_FIXTURE_SPEC.name] = WANCO_FIXTURE
WANCO_FIXTURE_SPEC.loader.exec_module(WANCO_FIXTURE)


CHECKPOINT_STDERR = (
    b"[info] Checkpoint started\n"
    b"[debug] Found exact stackmap record for func_19, wasm_op=-1, "
    b"native_return_pc_offset=0x2a\n"
    b"[info] Compressing memory\n"
    b"[info] Compression ratio: 0.275372\n"
    b"[info] Compression time: 1 ms\n"
    b"[info] Snapshot has been saved to checkpoint.pb\n"
    b"[info] Checkpoint time has been saved to chkpt-time.txt\n"
)
RESTORE_STDERR = (
    b"[info] Decompressing memory: 5 pages (327680 bytes)\n"
    b"[info] Checkpoint has been loaded\n"
    b"[info] - call stack: 21 frames\n"
    b"[info] - value stack: 0 values\n"
    b"[info] Restore time has been saved to restore-time.txt\n"
)
MIGRATION_APPLICATION_BYTES = WANCO_FIXTURE.aot_elf_payload(
    MATRIX.TYPED_CORPUS.CASE_SPECS[0]
)


def fixture_capsule_state_bytes() -> bytes:
    with tempfile.TemporaryDirectory(prefix="sqlite-capsule-fixture-") as raw:
        path = Path(raw) / "state.sqlite"
        connection = sqlite3.connect(path)
        try:
            connection.executescript(
                """
                PRAGMA user_version = 5;
                CREATE TABLE meta (
                    singleton INTEGER PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    session BLOB NOT NULL,
                    mode INTEGER NOT NULL,
                    authority_epoch INTEGER NOT NULL,
                    handoff BLOB,
                    destination_epoch INTEGER,
                    barrier_phase INTEGER NOT NULL,
                    barrier_token BLOB,
                    barrier_remaining INTEGER,
                    barrier_effect BLOB,
                    completed_barrier BLOB,
                    completed_barrier_effect BLOB,
                    completed_requests INTEGER NOT NULL
                );
                CREATE TABLE effects (effect_id BLOB PRIMARY KEY);
                """
            )
            connection.execute(
                """
                INSERT INTO meta VALUES
                    (1, 5, ?, 1, 1, ?, 2, 4, ?, NULL, ?, NULL, NULL, 20)
                """,
                (
                    bytes.fromhex("c1" * 16),
                    bytes.fromhex("c3" * 16),
                    bytes.fromhex("c4" * 16),
                    bytes.fromhex("f1" * 16),
                ),
            )
            connection.executemany(
                "INSERT INTO effects VALUES (?)",
                [
                    (bytes.fromhex(f"{index:032x}"),)
                    for index in range(1, 20)
                ]
                + [(bytes.fromhex("f1" * 16),)],
            )
            connection.commit()
        finally:
            connection.close()
        return path.read_bytes()


CAPSULE_STATE_BYTES = fixture_capsule_state_bytes()


def identity(seed: int) -> dict[str, object]:
    return {"sha256": f"{seed:064x}", "size": seed}


def retained(seed: int, path: str) -> dict[str, object]:
    return {"path": path, **identity(seed)}


def retained_application_runs(
    seed: int, path_label: str, roles: tuple[str, ...]
) -> list[dict[str, object]]:
    return [
        {
            "role": role,
            "exit_status": 0,
            "stdout": retained(
                seed + index * 2,
                f"observations/{path_label}/runs/{role}.stdout",
            ),
            "stderr": retained(
                seed + index * 2 + 1,
                f"observations/{path_label}/runs/{role}.stderr",
            ),
        }
        for index, role in enumerate(roles)
    ]


def retained_driver_runs(seed: int) -> list[dict[str, object]]:
    runs: list[dict[str, object]] = []
    for index, (role, _, _, expected_status) in enumerate(
        MATRIX.SOURCE_ABORT_DRIVER_RUNS
    ):
        runs.append(
            {
                "role": role,
                "exit_status": (
                    expected_status if expected_status is not None else 1
                ),
                "stdout": retained(
                    seed + index * 2,
                    f"observations/source-abort/driver-runs/{role}.stdout",
                ),
                "stderr": retained(
                    seed + index * 2 + 1,
                    f"observations/source-abort/driver-runs/{role}.stderr",
                ),
            }
        )
    return runs


def canonical_identity(value: object) -> dict[str, object]:
    payload = MATRIX.canonical_bytes(value) + b"\n"
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def reference_identity(reference: dict[str, object]) -> dict[str, object]:
    return {"sha256": reference["sha256"], "size": reference["size"]}


def payload_identity(payload: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def fixture_capsule_manifest_bytes() -> bytes:
    state = payload_identity(CAPSULE_STATE_BYTES)
    return json.dumps(
        {
            "schema": "visa-wasi-filesystem-capsule-v2",
            "session_hex": "c1" * 16,
            "source_epoch": 1,
            "destination_epoch": 2,
            "handoff_hex": "c3" * 16,
            "state_file": "state.sqlite",
            "state_size": state["size"],
            "state_sha256": state["sha256"],
        },
        ensure_ascii=False,
        indent=2,
        separators=(",", ": "),
    ).encode()


def pretty_json_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            separators=(",", ": "),
        ).encode()
        + b"\n"
    )


def fixture_migration_manifest() -> dict[str, object]:
    checkpoint = WANCO_FIXTURE.checkpoint_payload(
        MATRIX.TYPED_CORPUS.CASE_SPECS[0]
    )
    platform = {
        "operating_system": "linux",
        "architecture": "x86_64",
        "abi": "wanco-aot-preview1",
        "runtime_name": "Wanco",
        "runtime_version": "fixture-revision",
        "runtime_build_sha256": "a4" * 32,
    }
    return {
        "schema": MATRIX.MIGRATION_MANIFEST_SCHEMA,
        "application": {
            "semantic_path": "artifacts/application.aot",
            **payload_identity(MIGRATION_APPLICATION_BYTES),
        },
        "compute_checkpoint": {
            "semantic_path": "artifacts/checkpoint.pb",
            **payload_identity(checkpoint),
        },
        "resource_capsule_manifest": {
            "semantic_path": "capsule/manifest.json",
            **payload_identity(fixture_capsule_manifest_bytes()),
        },
        "resource_capsule_state": {
            "semantic_path": "capsule/state.sqlite",
            **payload_identity(CAPSULE_STATE_BYTES),
        },
        "session_hex": "c1" * 16,
        "stable_owner_hex": "c2" * 16,
        "handoff_hex": "c3" * 16,
        "checkpoint_barrier_hex": "c4" * 16,
        "source_epoch": 1,
        "destination_epoch": 2,
        "clients": {
            "source_client_hex": "d1" * 16,
            "source_restore_client_hex": "d2" * 16,
            "destination_client_hex": "d3" * 16,
        },
        "application_build": {
            "source_revision": "sqlite-fixture",
            "toolchain": "clang-fixture",
            "build_configuration_sha256": "a5" * 32,
        },
        "source_platform": copy.deepcopy(platform),
        "destination_platform": copy.deepcopy(platform),
    }


def fixture_migration_intent(
    manifest: dict[str, object],
) -> dict[str, object]:
    def identity_array(value: str) -> list[int]:
        return list(bytes.fromhex(value))

    clients = manifest["clients"]
    assert isinstance(clients, dict)
    return {
        "files": {
            "application": "artifacts/application.aot",
            "compute_checkpoint": "artifacts/checkpoint.pb",
            "resource_capsule_manifest": "capsule/manifest.json",
            "resource_capsule_state": "capsule/state.sqlite",
        },
        "session": identity_array(str(manifest["session_hex"])),
        "stable_owner": identity_array(str(manifest["stable_owner_hex"])),
        "handoff": identity_array(str(manifest["handoff_hex"])),
        "checkpoint_barrier": identity_array(
            str(manifest["checkpoint_barrier_hex"])
        ),
        "source_epoch": manifest["source_epoch"],
        "destination_epoch": manifest["destination_epoch"],
        "source_client": identity_array(str(clients["source_client_hex"])),
        "source_restore_client": identity_array(
            str(clients["source_restore_client_hex"])
        ),
        "destination_client": identity_array(
            str(clients["destination_client_hex"])
        ),
        "application_build": copy.deepcopy(manifest["application_build"]),
        "source_platform": copy.deepcopy(manifest["source_platform"]),
        "destination_platform": copy.deepcopy(manifest["destination_platform"]),
    }


def oracle_projection() -> dict[str, object]:
    return {
        "schema_version": MATRIX.ORACLE_PROJECTION_SCHEMA,
        "logical_contents": {
            "account_rows": 5,
            "accounts_sha256": "a1" * 32,
            "transaction_rows": 1,
            "transactions_sha256": "b2" * 32,
        },
        "integrity_ok": True,
        "foreign_keys_ok": True,
        "schema_accepted": True,
        "balance": {
            "expected_total": 512000,
            "observed_total": 512000,
            "total_matches": True,
            "negative_accounts": 0,
            "all_nonnegative": True,
        },
        "transactions": {
            "rows": 1,
            "nonnull_txids": 1,
            "distinct_txids": 1,
            "unique_txids": True,
            "nonpositive_amounts": 0,
            "all_amounts_positive": True,
        },
        "acknowledgements": {
            "expected_txids": ["tx-000001"],
            "observed_txids": ["tx-000001"],
            "missing_txids": [],
            "unexpected_txids": [],
            "exact_match": True,
        },
    }


def raw_observation(seed: int, *, prefix_rows: int = 0) -> dict[str, object]:
    return {
        "stdout": identity(seed),
        "acknowledged_txids": ["tx-000001"],
        "ack_terminal_count": 1,
        "cursor_prefix_rows": prefix_rows,
        "cursor_total_rows": 5,
        "cursor_done_count": 1,
        "cursor_rows_sha256": "a1" * 32,
    }


def equivalence_projection() -> dict[str, object]:
    projection = oracle_projection()
    return {
        "schema": MATRIX.EQUIVALENCE_PROJECTION_SCHEMA,
        "logical_contents": copy.deepcopy(projection["logical_contents"]),
        "invariants": {
            "integrity_ok": True,
            "foreign_keys_ok": True,
            "schema_accepted": True,
            "balance": copy.deepcopy(projection["balance"]),
            "transactions": copy.deepcopy(projection["transactions"]),
        },
        "acknowledgements": {
            "txids": ["tx-000001"],
            "terminal_count": 1,
            "oracle": copy.deepcopy(projection["acknowledgements"]),
        },
        "cursor": {
            "rows_sha256": "a1" * 32,
            "total_rows": 5,
            "done_count": 1,
        },
    }


def typed_corpus_qualification(build_receipt: dict[str, object]) -> dict[str, object]:
    image_id = WANCO_FIXTURE.IMAGE_ID
    cases: list[dict[str, object]] = []
    for index, spec in enumerate(MATRIX.TYPED_CORPUS.CASE_SPECS, start=1):
        control = list(spec.expected_control)
        marker_index = control.index(spec.marker)
        prefix = control[: marker_index + 1]
        suffix = control[marker_index + 1 :]
        if spec.profile == MATRIX.TYPED_CORPUS.POST_IMPORT_PROFILE:
            nonce = MATRIX.TYPED_CORPUS.expected_post_import_nonce(image_id, spec)
            container_id = f"{index + 100:064x}"
            witness: dict[str, object] | None = {
                "schema": MATRIX.TYPED_CORPUS.POST_IMPORT_WITNESS_SCHEMA,
                "protocol": "nonce-gated-hostcall-v1",
                "signal": "SIGUSR1",
                "nonce": nonce,
                "container_id": container_id,
                "causal_order": list(MATRIX.TYPED_CORPUS.POST_IMPORT_CAUSAL_ORDER),
                "event_trace": identity(300 + index),
            }
        else:
            witness = None
        cases.append(
            {
                "case_id": spec.case_id,
                "profile": spec.profile,
                "optimization": spec.optimization,
                "checkpoint_marker": spec.marker,
                "expected_frames": spec.frames,
                "observed_frames": spec.frames,
                "expected_typed_stack_values": spec.typed_stack_values,
                "observed_typed_stack_values": spec.typed_stack_values,
                "exact_stackmap_records": spec.frames,
                "control_values": control,
                "checkpoint_prefix_values": prefix,
                "restored_suffix_values": suffix,
                "process_exit_statuses": {
                    "control": 0,
                    "checkpoint": 0,
                    "restore": 0,
                },
                "checkpoint_envelope": {
                    "schema": MATRIX.TYPED_CORPUS.CHECKPOINT_ENVELOPE_SCHEMA,
                    **identity(200 + index),
                    "frame_count": spec.frames,
                    "local_value_count": len(spec.required_local_types),
                    "local_types_present": list(spec.required_local_types),
                    "stack_value_count": spec.typed_stack_values,
                    "stack_types": list(spec.expected_stack_types),
                    "memory_pages": 2 if spec.profile == "data-segment" else 1,
                    "memory_encoding": "lz4-block-exact-length",
                    "compressed_memory_bytes": 100 + index,
                },
                "post_import_signal_witness": witness,
            }
        )
    return {
        "schema": MATRIX.TYPED_CORPUS.QUALIFICATION_SCHEMA,
        "manifest": identity(19),
        "wanco_source_lock": identity(18),
        "wanco_build_receipt": build_receipt,
        "image_tag": WANCO_FIXTURE.IMAGE_TAG,
        "image_id": image_id,
        "cases": cases,
    }


def status(
    mode: str,
    barrier: str,
    *,
    epoch: int = 1,
    remaining: int | None = None,
    effect: str | None = None,
    effects: int = 20,
    completed: int = 20,
    completed_barrier: str | None = None,
    completed_effect: str | None = None,
) -> dict[str, object]:
    return {
        "mode": mode,
        "authority_epoch": epoch,
        "barrier": barrier,
        "barrier_remaining": remaining,
        "barrier_effect": effect,
        "completed_barrier": completed_barrier,
        "completed_barrier_effect": completed_effect,
        "effects": effects,
        "completed_requests": completed,
        # Deliberately present: this counter is not a cut-location input.
        "bytes_written": "not-consumed-by-the-controller",
    }


def capture(
    predicate: dict[str, object],
    effect: str,
    token: str,
    *,
    target: str = "held",
    release: str | None = "checkpoint_released",
) -> dict[str, object]:
    result = {
        "token": token,
        "predicate": predicate,
        "armed": status(
            "active",
            "armed",
            remaining=int(predicate["occurrence"]),
            effects=19,
            completed=19,
        ),
        "target": status(
            "active", target, effect=effect, effects=20, completed=20
        ),
    }
    if release == "checkpoint_released":
        result["checkpoint_released"] = status(
            "active",
            "checkpoint_released",
            effect=effect,
            effects=20,
            completed=20,
        )
    elif release == "open":
        result["continued"] = status(
            "active",
            "open",
            effects=20,
            completed=20,
            completed_barrier=token,
            completed_effect=effect,
        )
    return result


def handoff(
    source_client: str,
    destination_client: str,
    barrier_token: str,
    barrier_effect: str,
) -> dict[str, object]:
    return {
        "source_frozen": status(
            "frozen", "checkpoint_released", effect=barrier_effect
        ),
        "destination_prepared": status(
            "prepared", "checkpoint_released", effect=barrier_effect
        ),
        "source_fenced": status(
            "fenced", "checkpoint_released", effect=barrier_effect
        ),
        "destination_active": status(
            "active",
            "open",
            epoch=2,
            completed_barrier=barrier_token,
            completed_effect=barrier_effect,
        ),
        "source_client": source_client,
        "destination_client": destination_client,
    }


def complete_receipt() -> dict[str, object]:
    plan = MATRIX.build_plan()
    acknowledgement = identity(4)
    wanco_build_receipt = identity(13)
    typed_corpus = typed_corpus_qualification(wanco_build_receipt)
    execution_inputs = {
        "sqlite_source_lock": identity(10),
        "sqlite_build_receipt": identity(11),
        "wanco_source_lock": identity(12),
        "wanco_build_receipt": wanco_build_receipt,
        "wanco_typed_restore_corpus": identity(19),
        "stock_sqlite_wasm": identity(14),
        "stock_sqlite_aot": payload_identity(MIGRATION_APPLICATION_BYTES),
        "stock_sqlite_import_trace": identity(17),
        "visa_wasi_host": identity(15),
        "visa_migration_bind": identity(16),
        "visa_migration_driver": identity(18),
        "visa_sqlite_oracle": identity(500),
    }
    workload = {
        "stock_sqlite_artifact": payload_identity(MIGRATION_APPLICATION_BYTES),
        "sql_input": identity(2),
        "expected_acknowledgements": acknowledgement,
        "initial_total_balance": 512000,
        "expected_acknowledgement_txids": ["tx-000001"],
        "minimum_dirty_database_pages": 4,
        "expected_cursor_rows": 5,
    }
    cells: list[dict[str, object]] = []
    for index, spec in enumerate(MATRIX.CUT_SPECS):
        plan_cell = plan["cells"][index]
        effect = f"{index + 1:032x}"
        token = f"{index + 20:032x}"
        source_client = f"{index + 40:032x}"
        destination_client = f"{index + 60:032x}"
        cell: dict[str, object] = {
            "schema": MATRIX.CELL_SCHEMA,
            "cell_id": spec.cell_id,
            "plan_entry_sha256": MATRIX.canonical_sha256(plan_cell),
            "barrier": capture(
                plan_cell["predicate"],
                effect,
                token,
                target=spec.target_phase,
                release=(
                    "checkpoint_released" if spec.target_phase == "held" else None
                ),
            ),
            "compute_checkpoint": identity(index + 100),
            "handoff": handoff(
                source_client,
                destination_client,
                token,
                effect,
            ),
            "namespace_snapshot": {
                "artifact": identity(index + 200),
                "effect_frontier": f"{index + 300:064x}",
                "effects": index + 20,
            },
            "external_oracle": {
                "program": identity(500),
                "report": identity(index + 600),
                "report_schema": MATRIX.ORACLE_REPORT_SCHEMA,
                "semantic_projection": oracle_projection(),
                "exit_status": 0,
                "accepted": True,
            },
            "expected_acknowledgements": acknowledgement,
            "raw_client_observation": raw_observation(
                index + 700,
                prefix_rows=2 if spec.cell_id == "active-read-cursor" else 0,
            ),
            "retained_raw_evidence": {
                "application_runs": retained_application_runs(
                    index + 1100,
                    spec.cell_id,
                    (
                        ("transaction-setup", "source", "destination")
                        if spec.cell_id == "active-read-cursor"
                        else ("source", "destination", "readback")
                    ),
                ),
                "client_stdout": retained(
                    index + 700, f"observations/{spec.cell_id}/raw-client.stdout"
                ),
                "expected_acknowledgements": retained(
                    4, f"observations/{spec.cell_id}/expected-acks.json"
                ),
                "namespace_snapshot": retained(
                    index + 200,
                    f"observations/{spec.cell_id}/namespace.snapshot",
                ),
                "oracle_report": retained(
                    index + 600,
                    f"observations/{spec.cell_id}/oracle-report.json",
                ),
            },
            "equivalence_projection": equivalence_projection(),
        }
        if spec.continuation_witness is not None:
            cell["continuation_witness"] = capture(
                plan_cell["continuation_witness"],
                f"{index + 101:032x}",
                f"{index + 120:032x}",
                release="open",
            )
        if spec.external_anchor is not None:
            anchor: dict[str, object] = {
                "kind": spec.external_anchor,
                "observation": identity(index + 700),
            }
            if spec.cell_id == "active-read-cursor":
                anchor["observed_prefix_rows"] = 2
            cell["external_anchor"] = anchor
        if spec.cell_id == "lost-response":
            cell["delivery_fault"] = {
                "injection": "drop-guest-response-after-durable-effect",
                "injector": identity(800),
                "injection_trace": identity(801),
                "triggered_effect": effect,
                "replayed_effect": effect,
                "source_client": source_client,
                "replay_client": source_client,
                "source_sequence": 17,
                "replay_sequence": 17,
                "effects_before_replay": 26,
                "effects_after_replay": 26,
                "replay_held": status("active", "held", effect=effect),
                "checkpoint_released": status(
                    "active", "checkpoint_released", effect=effect
                ),
                "pre_completion_source_death": {
                    "triggered_status": status("active", "triggered", effect=effect),
                    "migration_attempt_trace": identity(802),
                    "migration_attempt_exit_status": 1,
                    "rejected_by": "incomplete-delivery-drain-gate",
                },
            }
        cells.append(cell)
    migration_manifest = fixture_migration_manifest()
    manifest_sha256 = MATRIX.canonical_sha256(migration_manifest)
    authority_binding = {
        "migration_manifest_sha256": manifest_sha256,
        "session_hex": "c1" * 16,
        "stable_owner_hex": "c2" * 16,
        "handoff_hex": "c3" * 16,
        "source_epoch": 1,
        "destination_epoch": 2,
    }
    source_retained_receipt_document = {
        "schema": MATRIX.SOURCE_RETAINED_RECEIPT_SCHEMA,
        "decision": "source_retained",
        **authority_binding,
    }
    source_retained_receipt = canonical_identity(source_retained_receipt_document)
    source_retained_proof = {
        "schema": MATRIX.SOURCE_RETAINED_PROOF_SCHEMA,
        **authority_binding,
        "canonical_receipt": {
            "semantic_path": "authority/source-retained.json",
            **source_retained_receipt,
        },
    }
    source_retained_authority = {
        "schema": MATRIX.CANONICAL_AUTHORITY_STATE_SCHEMA,
        "generation": 2,
        "migration_manifest_sha256": manifest_sha256,
        "decision": "source_retained",
        "source_retained_proof": source_retained_proof,
        "ownership_commit_proof": None,
        "source_fence_proof": None,
    }
    commit_receipt_document = {
        "schema": "visa-wasi-authority-commit-receipt-v1",
        "migration_manifest_sha256": manifest_sha256,
    }
    commit_receipt = canonical_identity(commit_receipt_document)
    commit_proof = {
        "schema": "visa-canonical-ownership-commit-proof-v1",
        **authority_binding,
        "canonical_receipt": {
            "semantic_path": "authority/commit.json",
            **commit_receipt,
        },
    }
    committed_authority = {
        "schema": MATRIX.CANONICAL_AUTHORITY_STATE_SCHEMA,
        "generation": 2,
        "migration_manifest_sha256": manifest_sha256,
        "decision": "ownership_committed",
        "source_retained_proof": None,
        "ownership_commit_proof": commit_proof,
        "source_fence_proof": None,
    }
    source_adapter = identity(915)
    source_adapter_binding_document = {
        "schema": "visa-wasi-adapter-binding-v2",
        "adapter": source_adapter,
    }
    probe_adapter = identity(921)
    probe_adapter_binding_document = {
        "schema": "visa-wasi-adapter-binding-v2",
        "adapter": probe_adapter,
    }
    return {
        "schema": MATRIX.MATRIX_SCHEMA,
        "repository_revision": "ab" * 20,
        "repository_source_snapshot": {
            "clean": True,
            "status_sha256": hashlib.sha256(b"").hexdigest(),
            "tracked_patch_sha256": hashlib.sha256(b"").hexdigest(),
            "untracked_file_count": 0,
            "untracked_manifest_sha256": hashlib.sha256(
                MATRIX.canonical_bytes([])
            ).hexdigest(),
        },
        "execution_inputs": execution_inputs,
        "plan": plan,
        "plan_sha256": MATRIX.canonical_sha256(plan),
        "workload": workload,
        "uninterrupted_control": {
            "schema": MATRIX.CONTROL_SCHEMA,
            "execution": "single-provider-uninterrupted-transaction-and-readback",
            "namespace_snapshot": {
                "artifact": identity(580),
                "effect_frontier": "c4" * 32,
                "effects": 19,
            },
            "external_oracle": {
                "program": identity(500),
                "report": identity(590),
                "report_schema": MATRIX.ORACLE_REPORT_SCHEMA,
                "semantic_projection": oracle_projection(),
                "exit_status": 0,
                "accepted": True,
            },
            "expected_acknowledgements": acknowledgement,
            "raw_client_observation": raw_observation(595),
            "retained_raw_evidence": {
                "application_runs": retained_application_runs(
                    1200,
                    "uninterrupted-control",
                    ("transaction", "cursor"),
                ),
                "client_stdout": retained(
                    595, "observations/uninterrupted-control/raw-client.stdout"
                ),
                "expected_acknowledgements": retained(
                    4, "observations/uninterrupted-control/expected-acks.json"
                ),
                "namespace_snapshot": retained(
                    580, "observations/uninterrupted-control/namespace.snapshot"
                ),
                "oracle_report": retained(
                    590, "observations/uninterrupted-control/oracle-report.json"
                ),
            },
            "equivalence_projection": equivalence_projection(),
        },
        "cells": cells,
        "typed_restore_corpus_qualification": typed_corpus,
        "process_recovery_qualification": {
            "schema": MATRIX.PROCESS_RECOVERY_SCHEMA,
            "scope": "provider-process-kill-reopen",
            "qualified_tests": list(MATRIX.PROCESS_RECOVERY_TESTS),
            "nonclaims": list(MATRIX.PROCESS_RECOVERY_NONCLAIMS),
            "retained_raw_evidence": {
                "report": retained(
                    900, "observations/provider-process-recovery/report.json"
                ),
                "process": {
                    "command": MATRIX.PROCESS_RECOVERY_COMMAND,
                    "exit_status": 0,
                    "stdout": retained(
                        901, "observations/provider-process-recovery/process.stdout"
                    ),
                    "stderr": retained(
                        902, "observations/provider-process-recovery/process.stderr"
                    ),
                },
            },
        },
        "source_abort_reconciliation_qualification": {
            "schema": MATRIX.SOURCE_ABORT_SCHEMA,
            "scope": "pre-commit-source-compute-abort",
            "integrated_driver_report": identity(910),
            "compute_checkpoint": identity(917),
            "coordinator_crash_exit_status": 75,
            "durable_pending_action": "resume_source_provider",
            "pending_driver_record": identity(913),
            "adapter_configuration_sha256": source_adapter["sha256"],
            "adapter_binding_receipt": canonical_identity(source_adapter_binding_document),
            "adapter_binding_document": source_adapter_binding_document,
            "migration_manifest_sha256": manifest_sha256,
            "source_retained_terminal": {
                "authority_schema": MATRIX.CANONICAL_AUTHORITY_STATE_SCHEMA,
                "generation": 2,
                "decision": "source_retained",
                "state": canonical_identity(source_retained_authority),
                "proof": source_retained_proof,
                "receipt": source_retained_receipt,
                "receipt_document": source_retained_receipt_document,
            },
            "committed_probe_terminal": {
                "authority_schema": MATRIX.CANONICAL_AUTHORITY_STATE_SCHEMA,
                "generation": 2,
                "decision": "ownership_committed",
                "state": canonical_identity(committed_authority),
                "proof": commit_proof,
                "receipt": commit_receipt,
                "receipt_document": commit_receipt_document,
                "adapter_configuration_sha256": probe_adapter["sha256"],
                "adapter_binding_receipt": canonical_identity(
                    probe_adapter_binding_document
                ),
                "adapter_binding_document": probe_adapter_binding_document,
            },
            "authority_init_exit_status": 0,
            "commit_probe_init_exit_status": 0,
            "commit_probe_commit_exit_status": 0,
            "canonical_commit_abort_exit_status": 1,
            "recovery_exit_status": 0,
            "final_phase": "source_resumed",
            "wanco_restore_completion": identity(911),
            "wanco_restore_started": identity(916),
            "external_oracle_report": identity(912),
            "raw_client_observation": raw_observation(595),
            "expected_acknowledgements": acknowledgement,
            "namespace_snapshot": {
                "artifact": identity(580),
                "effect_frontier": "c4" * 32,
                "effects": 21,
            },
            "external_oracle": {
                "program": identity(500),
                "report": identity(912),
                "report_schema": MATRIX.ORACLE_REPORT_SCHEMA,
                "semantic_projection": oracle_projection(),
                "exit_status": 0,
                "accepted": True,
            },
            "equivalence_projection": equivalence_projection(),
            "accepted": True,
            "source_client": "d1" * 16,
            "source_restore_client": "d2" * 16,
            "retained_raw_evidence": {
                "application_runs": retained_application_runs(
                    1300,
                    "source-abort",
                    ("source", "destination", "readback"),
                ),
                "client_stdout": retained(
                    595, "observations/source-abort/raw-client.stdout"
                ),
                "expected_acknowledgements": retained(
                    4, "observations/source-abort/expected-acks.json"
                ),
                "namespace_snapshot": retained(
                    580, "observations/source-abort/namespace.snapshot"
                ),
                "oracle_report": retained(
                    912, "observations/source-abort/oracle-report.json"
                ),
                "compute_checkpoint": retained(
                    917, "observations/source-abort/compute-checkpoint.pb"
                ),
                "migration_application": {
                    "path": "observations/source-abort/migration/application.aot",
                    **{
                        key: migration_manifest["application"][key]
                        for key in ("sha256", "size")
                    },
                },
                "resource_capsule_manifest": {
                    "path": (
                        "observations/source-abort/migration/"
                        "capsule-manifest.json"
                    ),
                    **{
                        key: migration_manifest["resource_capsule_manifest"][key]
                        for key in ("sha256", "size")
                    },
                },
                "resource_capsule_state": {
                    "path": (
                        "observations/source-abort/migration/"
                        "capsule-state.sqlite"
                    ),
                    **{
                        key: migration_manifest["resource_capsule_state"][key]
                        for key in ("sha256", "size")
                    },
                },
                "driver_runs": retained_driver_runs(1400),
                "integrated_driver_report": retained(
                    910, "observations/source-abort/integrated-driver-report.json"
                ),
                "pending_driver_record": retained(
                    913, "observations/source-abort/pending-driver-record.json"
                ),
                "final_driver_record": retained(
                    918, "observations/source-abort/final-driver-record.json"
                ),
                "crash_marker": retained(
                    919, "observations/source-abort/crash-marker.json"
                ),
                "wanco_restore_started": retained(
                    916, "observations/source-abort/wanco-restore-started.json"
                ),
                "wanco_restore_completion": retained(
                    911, "observations/source-abort/wanco-restore-completion.json"
                ),
                "source_exit_receipt": retained(
                    920, "observations/source-abort/source-exit-receipt.json"
                ),
                "source_authority_state": {
                    "path": "observations/source-abort/source-authority-state.json",
                    **canonical_identity(source_retained_authority),
                },
                "committed_authority_state": {
                    "path": "observations/source-abort/committed-authority-state.json",
                    **canonical_identity(committed_authority),
                },
                "source_adapter_binding": {
                    "path": "observations/source-abort/source-adapter-binding.json",
                    **canonical_identity(source_adapter_binding_document),
                },
                "committed_adapter_binding": {
                    "path": "observations/source-abort/committed-adapter-binding.json",
                    **canonical_identity(probe_adapter_binding_document),
                },
                "source_retained_receipt": {
                    "path": "observations/source-abort/source-retained-receipt.json",
                    **source_retained_receipt,
                },
            },
        },
        "durability_scope": {
            "provider_process_crash": True,
            "power_loss": False,
            "torn_sector": False,
            "device_write_reordering": False,
        },
    }


def materialize_typed_corpus(
    root: Path,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    source = root / "typed-source"
    source.mkdir()
    build_path = WANCO_FIXTURE.materialize_source(source)
    manifest, qualification = MATRIX.TYPED_CORPUS.build_bundle(
        source_root=source,
        artifact_root=root / "wanco-typed-corpus",
        image_tag=WANCO_FIXTURE.IMAGE_TAG,
        image_id=WANCO_FIXTURE.IMAGE_ID,
        wanco_source_lock=MATRIX.TYPED_CORPUS.DEFAULT_SOURCE_LOCK,
        wanco_build_receipt=build_path,
    )
    manifest_raw = MATRIX.TYPED_CORPUS.canonical_bytes(manifest) + b"\n"
    return (
        {
            "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "size": len(manifest_raw),
        },
        MATRIX.file_identity(build_path),
        qualification,
    )


def materialize_retained_receipt(
    root: Path,
) -> tuple[Path, Path, dict[str, object]]:
    receipt = complete_receipt()
    typed_identity, build_identity, typed_qualification = materialize_typed_corpus(
        root
    )
    receipt["execution_inputs"]["wanco_build_receipt"] = build_identity
    receipt["execution_inputs"]["wanco_typed_restore_corpus"] = typed_identity
    receipt["typed_restore_corpus_qualification"] = typed_qualification
    rows = [(1, 999), (2, 999), (3, 1000), (4, 1001), (5, 1001)]
    row_lines = [f"VISA_ROW|{account}|{balance}" for account, balance in rows]
    stdout_bytes = (
        "\n".join(
            ["delete", "VISA_ACK|tx-000001", *row_lines, "VISA_CURSOR_DONE|5"]
        )
        + "\n"
    ).encode()
    source_cursor_bytes = ("\n".join(row_lines[:2]) + "\n").encode()
    expected_bytes = (
        MATRIX.canonical_bytes(
            {
                "schema_version": "visa-sqlite-expected-acks-v1",
                "initial_total_balance": 512000,
                "acknowledged_txids": ["tx-000001"],
            }
        )
        + b"\n"
    )
    projection = oracle_projection()
    projection["logical_contents"]["accounts_sha256"] = (
        MATRIX._account_rows_sha256(rows)
    )
    report = {
        "schema_version": MATRIX.ORACLE_REPORT_SCHEMA,
        "accepted": True,
        "snapshot": {
            "version": 2,
            "session_hex": "c1" * 16,
            "authority_epoch": 1,
            "mode": "active",
            "barrier": "checkpoint_released",
            "effect_frontier_hex": "c4" * 32,
            "effects": 21,
            "objects": 4,
            "paths": 4,
            "descriptors": 1,
            "locks": 0,
        },
        "namespace": {"fixture": True},
        "sqlite": {"fixture": True},
        "semantic_projection": projection,
        "findings": [],
    }
    report_bytes = json.dumps(report, indent=2, sort_keys=True).encode() + b"\n"
    oracle_path = root / "fixture-sqlite-oracle"
    oracle_path.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"sys.stdout.buffer.write({report_bytes!r})\n",
        encoding="utf-8",
    )
    oracle_path.chmod(0o700)
    oracle_identity = MATRIX.file_identity(oracle_path)
    receipt["execution_inputs"]["visa_sqlite_oracle"] = oracle_identity
    expected_identity = {
        "sha256": hashlib.sha256(expected_bytes).hexdigest(),
        "size": len(expected_bytes),
    }
    receipt["workload"]["expected_acknowledgements"] = expected_identity

    def write_reference(relative: str, payload: bytes) -> dict[str, object]:
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return {
            "path": relative,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }

    records = [
        ("uninterrupted-control", receipt["uninterrupted_control"], False),
        (
            "source-abort",
            receipt["source_abort_reconciliation_qualification"],
            False,
        ),
        *[
            (spec.cell_id, cell, spec.cell_id == "active-read-cursor")
            for spec, cell in zip(MATRIX.CUT_SPECS, receipt["cells"], strict=True)
        ],
    ]
    for label, record, source_cursor_required in records:
        record["namespace_snapshot"]["effect_frontier"] = "c4" * 32
        record["namespace_snapshot"]["effects"] = 21
        transaction_bytes = b"delete\nVISA_ACK|tx-000001\n"
        cursor_bytes = ("\n".join([*row_lines, "VISA_CURSOR_DONE|5"]) + "\n").encode()
        if label == "uninterrupted-control":
            run_payloads = (
                ("transaction", transaction_bytes),
                ("cursor", cursor_bytes),
            )
        elif label == "source-abort":
            run_payloads = (
                ("source", b"delete\n"),
                ("destination", b"VISA_ACK|tx-000001\n"),
                ("readback", cursor_bytes),
            )
        elif source_cursor_required:
            run_payloads = (
                ("transaction-setup", transaction_bytes),
                ("source", source_cursor_bytes),
                (
                    "destination",
                    (
                        "\n".join([*row_lines[2:], "VISA_CURSOR_DONE|5"]) + "\n"
                    ).encode(),
                ),
            )
        else:
            run_payloads = (
                ("source", b"delete\n"),
                ("destination", b"VISA_ACK|tx-000001\n"),
                ("readback", cursor_bytes),
            )
        if b"".join(payload for _, payload in run_payloads) != stdout_bytes:
            raise AssertionError("application run fixture does not reconstruct stdout")
        application_runs = []
        for role, payload in run_payloads:
            stderr_payload = (
                CHECKPOINT_STDERR
                if role == "source"
                else RESTORE_STDERR if role == "destination" else b""
            )
            application_runs.append(
                {
                    "role": role,
                    "exit_status": 0,
                    "stdout": write_reference(
                        f"observations/{label}/runs/{role}.stdout", payload
                    ),
                    "stderr": write_reference(
                        f"observations/{label}/runs/{role}.stderr", stderr_payload
                    ),
                }
            )
        stdout = write_reference(
            f"observations/{label}/raw-client.stdout", stdout_bytes
        )
        expected = write_reference(
            f"observations/{label}/expected-acks.json", expected_bytes
        )
        snapshot_bytes = ("namespace:" + label).encode()
        snapshot = write_reference(
            f"observations/{label}/namespace.snapshot", snapshot_bytes
        )
        oracle_report = write_reference(
            f"observations/{label}/oracle-report.json", report_bytes
        )
        observation = {
            "stdout": {
                "sha256": stdout["sha256"],
                "size": stdout["size"],
            },
            **MATRIX._parse_client_stdout_bytes(
                stdout_bytes,
                receipt["workload"],
                label=label,
                source_cursor_payload=(
                    source_cursor_bytes if source_cursor_required else None
                ),
            ),
        }
        record["raw_client_observation"] = observation
        record["expected_acknowledgements"] = copy.deepcopy(expected_identity)
        record["namespace_snapshot"]["artifact"] = {
            "sha256": snapshot["sha256"],
            "size": snapshot["size"],
        }
        record["external_oracle"] = {
            "program": copy.deepcopy(oracle_identity),
            "report": {
                "sha256": oracle_report["sha256"],
                "size": oracle_report["size"],
            },
            "report_schema": MATRIX.ORACLE_REPORT_SCHEMA,
            "semantic_projection": copy.deepcopy(projection),
            "exit_status": 0,
            "accepted": True,
        }
        retained_observation = {
            "application_runs": application_runs,
            "client_stdout": stdout,
            "expected_acknowledgements": expected,
            "namespace_snapshot": snapshot,
            "oracle_report": oracle_report,
        }
        if label == "source-abort":
            record["retained_raw_evidence"].update(retained_observation)
        else:
            record["retained_raw_evidence"] = retained_observation
        record["equivalence_projection"] = MATRIX._derive_equivalence_projection(
            record["external_oracle"]["semantic_projection"],
            observation,
            label,
        )
        if "external_anchor" in record:
            record["external_anchor"]["observation"] = copy.deepcopy(
                observation["stdout"]
            )
            if source_cursor_required:
                record["external_anchor"]["observed_prefix_rows"] = 2
    abort = receipt["source_abort_reconciliation_qualification"]
    abort_retained = abort["retained_raw_evidence"]
    abort["external_oracle_report"] = copy.deepcopy(
        abort["external_oracle"]["report"]
    )

    checkpoint_bytes = WANCO_FIXTURE.checkpoint_payload(
        MATRIX.TYPED_CORPUS.CASE_SPECS[0]
    )
    checkpoint_reference = write_reference(
        "observations/source-abort/compute-checkpoint.pb",
        checkpoint_bytes,
    )
    abort_retained["compute_checkpoint"] = checkpoint_reference
    abort["compute_checkpoint"] = reference_identity(checkpoint_reference)
    migration_application_reference = write_reference(
        "observations/source-abort/migration/application.aot",
        MIGRATION_APPLICATION_BYTES,
    )
    capsule_manifest_reference = write_reference(
        "observations/source-abort/migration/capsule-manifest.json",
        fixture_capsule_manifest_bytes(),
    )
    capsule_state_reference = write_reference(
        "observations/source-abort/migration/capsule-state.sqlite",
        CAPSULE_STATE_BYTES,
    )
    abort_retained["migration_application"] = migration_application_reference
    abort_retained["resource_capsule_manifest"] = capsule_manifest_reference
    abort_retained["resource_capsule_state"] = capsule_state_reference
    manifest = fixture_migration_manifest()
    if (
        reference_identity(migration_application_reference)
        != {
            key: manifest["application"][key]
            for key in ("sha256", "size")
        }
        or reference_identity(capsule_manifest_reference)
        != {
            key: manifest["resource_capsule_manifest"][key]
            for key in ("sha256", "size")
        }
        or reference_identity(capsule_state_reference)
        != {
            key: manifest["resource_capsule_state"][key]
            for key in ("sha256", "size")
        }
    ):
        raise AssertionError("migration bound-file fixtures diverged")
    receipt["execution_inputs"]["stock_sqlite_aot"] = reference_identity(
        migration_application_reference
    )
    receipt["workload"]["stock_sqlite_artifact"] = reference_identity(
        migration_application_reference
    )
    source_terminal = abort["source_retained_terminal"]
    committed_terminal = abort["committed_probe_terminal"]
    pending_record_value = {
        "schema": MATRIX.DRIVER_RECORD_SCHEMA,
        "generation": 11,
        "phase": "source_retained",
        "pending_action": "resume_source_provider",
        "intent": fixture_migration_intent(manifest),
        "migration_manifest": manifest,
        "source_retained_proof": source_terminal["proof"],
        "ownership_commit_proof": None,
        "source_fence_proof": None,
    }
    final_record_value = {
        **pending_record_value,
        "generation": 14,
        "phase": "source_resumed",
        "pending_action": None,
    }
    init_record_value = {
        **pending_record_value,
        "generation": 8,
        "phase": "manifest_sealed",
        "pending_action": None,
        "source_retained_proof": None,
    }
    crash_marker_value = {
        "schema": "visa-wasi-coordinator-crash-marker-v1",
        "injected_after": "resume_source_provider",
        "session_hex": source_terminal["proof"]["session_hex"],
        "authority_epoch": source_terminal["proof"]["source_epoch"],
    }
    started_value = {
        "schema": "visa-wanco-supervisor-started-v1",
        "command_fingerprint": "ad" * 32,
        "attempt": 1,
        "supervisor_pid": 1234,
    }
    destination_run = abort_retained["application_runs"][1]
    completion_value = {
        "schema": "visa-wanco-restore-completion-v1",
        "operation": "restore_source",
        "command_fingerprint": started_value["command_fingerprint"],
        "attempt": 1,
        "exit_status": 0,
        "stdout": reference_identity(destination_run["stdout"]),
        "stderr": reference_identity(destination_run["stderr"]),
    }
    source_exit_value = {
        "schema": "visa-wanco-source-exit-v1",
        "exit_status": 0,
        "checkpoint": abort["compute_checkpoint"],
    }
    source_authority_value = {
        "schema": MATRIX.CANONICAL_AUTHORITY_STATE_SCHEMA,
        "generation": 2,
        "migration_manifest_sha256": abort["migration_manifest_sha256"],
        "decision": "source_retained",
        "source_retained_proof": source_terminal["proof"],
        "ownership_commit_proof": None,
        "source_fence_proof": None,
    }
    committed_authority_value = {
        "schema": MATRIX.CANONICAL_AUTHORITY_STATE_SCHEMA,
        "generation": 2,
        "migration_manifest_sha256": abort["migration_manifest_sha256"],
        "decision": "ownership_committed",
        "source_retained_proof": None,
        "ownership_commit_proof": committed_terminal["proof"],
        "source_fence_proof": None,
    }
    raw_documents = {
        "pending_driver_record": pending_record_value,
        "final_driver_record": final_record_value,
        "crash_marker": crash_marker_value,
        "wanco_restore_started": started_value,
        "wanco_restore_completion": completion_value,
        "source_exit_receipt": source_exit_value,
        "source_authority_state": source_authority_value,
        "committed_authority_state": committed_authority_value,
        "source_adapter_binding": abort["adapter_binding_document"],
        "committed_adapter_binding": committed_terminal[
            "adapter_binding_document"
        ],
        "source_retained_receipt": source_terminal["receipt_document"],
    }
    document_filenames = {
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
    for name, document in raw_documents.items():
        payload = MATRIX.canonical_bytes(document)
        if name not in {"pending_driver_record", "final_driver_record"}:
            payload += b"\n"
        abort_retained[name] = write_reference(
            f"observations/source-abort/{document_filenames[name]}",
            payload,
        )
    abort["pending_driver_record"] = reference_identity(
        abort_retained["pending_driver_record"]
    )
    abort["wanco_restore_started"] = reference_identity(
        abort_retained["wanco_restore_started"]
    )
    abort["wanco_restore_completion"] = reference_identity(
        abort_retained["wanco_restore_completion"]
    )
    restart_output_fields: dict[str, object] = {}
    retained_driver_runs: list[dict[str, object]] = []
    for role, report_prefix, _, expected_status in MATRIX.SOURCE_ABORT_DRIVER_RUNS:
        exit_status = expected_status
        if role == "init":
            stdout_payload = pretty_json_line(init_record_value)
            stderr_payload = b""
        elif role == "restart-recovery":
            stdout_payload = pretty_json_line(final_record_value)
            stderr_payload = b""
        elif role == "committed-probe-abort":
            stdout_payload = b""
            stderr_payload = MATRIX.CANONICAL_COMMIT_ABORT_STDERR
        else:
            stdout_payload = b""
            stderr_payload = b""
        stdout_reference = write_reference(
            f"observations/source-abort/driver-runs/{role}.stdout",
            stdout_payload,
        )
        stderr_reference = write_reference(
            f"observations/source-abort/driver-runs/{role}.stderr",
            stderr_payload,
        )
        retained_driver_runs.append(
            {
                "role": role,
                "exit_status": exit_status,
                "stdout": stdout_reference,
                "stderr": stderr_reference,
            }
        )
        restart_output_fields[f"{report_prefix}_stdout"] = reference_identity(
            stdout_reference
        )
        restart_output_fields[f"{report_prefix}_stderr"] = reference_identity(
            stderr_reference
        )
    abort_retained["driver_runs"] = retained_driver_runs
    partial_journal = MATRIX.cell_plan(
        MATRIX.DEFAULT_DATABASE_PATH, "partial-journal"
    )
    source_abort_cut = {
        "barrier": capture(
            partial_journal["predicate"],
            "f1" * 16,
            "c4" * 16,
        ),
        "compute_checkpoint": abort["compute_checkpoint"],
    }
    integrated_report_value = {
        "schema": "visa-sqlite-source-abort-real-driver-v5",
        "cut": source_abort_cut,
        "source_frozen": MATRIX.status_projection(
            status("frozen", "checkpoint_released", effect="f1" * 16)
        ),
        "source_provider_resumed_before_restart": MATRIX.status_projection(
            status(
                "active",
                "open",
                epoch=1,
                completed_barrier="c4" * 16,
                completed_effect="f1" * 16,
            )
        ),
        "source_provider_after_recovery": MATRIX.status_projection(
            status(
                "active",
                "open",
                epoch=1,
                effects=21,
                completed=21,
                completed_barrier="c4" * 16,
                completed_effect="f1" * 16,
            )
        ),
        "source_client": abort["source_client"],
        "source_restore_client": abort["source_restore_client"],
        "clients_pairwise_distinct": True,
        "manifest_sha256": abort["migration_manifest_sha256"],
        "adapter_configuration_sha256": abort["adapter_configuration_sha256"],
        "adapter_binding_receipt": abort["adapter_binding_receipt"],
        "adapter_binding_document": abort["adapter_binding_document"],
        "source_retained_terminal": source_terminal,
        "committed_probe_terminal": committed_terminal,
        "driver_record": reference_identity(abort_retained["final_driver_record"]),
        "compute_checkpoint": abort["compute_checkpoint"],
        "source_exit_receipt": reference_identity(
            abort_retained["source_exit_receipt"]
        ),
        "wanco_restore_completion": abort["wanco_restore_completion"],
        "wanco_restore_started": abort["wanco_restore_started"],
        "coordinator_restart": {
            "init_exit_status": 0,
            "injected_exit_status": 75,
            "injected_after": "resume_source_provider",
            "durable_pending_action": "resume_source_provider",
            "pending_record": abort["pending_driver_record"],
            "recovery_exit_status": 0,
            "final_phase": "source_resumed",
            "crash_marker": reference_identity(abort_retained["crash_marker"]),
            "canonical_commit_abort_exit_status": 1,
            "authority_init_exit_status": 0,
            "commit_probe_init_exit_status": 0,
            "commit_probe_commit_exit_status": 0,
            **restart_output_fields,
        },
        "raw_client_observation": abort["raw_client_observation"],
        "namespace_snapshot": abort["namespace_snapshot"],
        "external_oracle": abort["external_oracle"],
    }
    integrated_report = write_reference(
        "observations/source-abort/integrated-driver-report.json",
        MATRIX.canonical_bytes(integrated_report_value) + b"\n",
    )
    abort_retained["integrated_driver_report"] = integrated_report
    abort["integrated_driver_report"] = reference_identity(integrated_report)
    recovery_stdout_bytes = (
        "running 2 tests\n"
        "test fd_sync_and_datasync_survive_provider_kill_reopen_in_process_crash_model ... ok\n"
        "test response_loss_then_provider_kill_reopen_replays_exactly_once ... ok\n"
        "\n"
        "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; "
        "0 filtered out; finished in 0.02s\n"
    ).encode("ascii")
    recovery_stderr_bytes = b"Finished test profile\n"
    recovery_stdout = write_reference(
        "observations/provider-process-recovery/process.stdout",
        recovery_stdout_bytes,
    )
    recovery_stderr = write_reference(
        "observations/provider-process-recovery/process.stderr",
        recovery_stderr_bytes,
    )
    recovery_report_value = {
        "schema": MATRIX.PROCESS_RECOVERY_REPORT_SCHEMA,
        "command": MATRIX.PROCESS_RECOVERY_COMMAND,
        "exit_status": 0,
        "qualified_tests": list(MATRIX.PROCESS_RECOVERY_TESTS),
        "stdout": {
            "sha256": recovery_stdout["sha256"],
            "size": recovery_stdout["size"],
        },
        "stderr": {
            "sha256": recovery_stderr["sha256"],
            "size": recovery_stderr["size"],
        },
        "scope": "provider-process-kill-reopen",
        "nonclaims": list(MATRIX.PROCESS_RECOVERY_NONCLAIMS),
    }
    recovery_report = write_reference(
        "observations/provider-process-recovery/report.json",
        MATRIX.canonical_bytes(recovery_report_value) + b"\n",
    )
    receipt["process_recovery_qualification"]["retained_raw_evidence"] = {
        "report": recovery_report,
        "process": {
            "command": MATRIX.PROCESS_RECOVERY_COMMAND,
            "exit_status": 0,
            "stdout": recovery_stdout,
            "stderr": recovery_stderr,
        },
    }
    receipt_path = root / "receipt.json"
    receipt_path.write_bytes(MATRIX.canonical_bytes(receipt) + b"\n")
    return receipt_path, oracle_path, receipt


def reseal_raw_file(
    receipt: dict[str, object],
    root: Path,
    *,
    cell_index: int,
    role: str,
    payload: bytes,
) -> None:
    cell = receipt["cells"][cell_index]
    reference = cell["retained_raw_evidence"][role]
    path = root.joinpath(*reference["path"].split("/"))
    path.write_bytes(payload)
    identity_value = {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }
    reference.update(identity_value)
    if role == "client_stdout":
        cell["raw_client_observation"]["stdout"] = copy.deepcopy(identity_value)
        if "external_anchor" in cell:
            cell["external_anchor"]["observation"] = copy.deepcopy(identity_value)
    elif role == "oracle_report":
        cell["external_oracle"]["report"] = copy.deepcopy(identity_value)
    receipt_path = root / "receipt.json"
    receipt_path.write_bytes(MATRIX.canonical_bytes(receipt) + b"\n")


def rebind_committed_probe_to_a_different_handoff(receipt: dict[str, object]) -> None:
    abort = receipt["source_abort_reconciliation_qualification"]
    assert isinstance(abort, dict)
    terminal = abort["committed_probe_terminal"]
    assert isinstance(terminal, dict)
    proof = terminal["proof"]
    assert isinstance(proof, dict)
    proof["handoff_hex"] = "ef" * 16
    terminal["state"] = canonical_identity(
        {
            "schema": terminal["authority_schema"],
            "generation": terminal["generation"],
            "migration_manifest_sha256": abort["migration_manifest_sha256"],
            "decision": terminal["decision"],
            "source_retained_proof": None,
            "ownership_commit_proof": proof,
            "source_fence_proof": None,
        }
    )


def reuse_source_adapter_for_committed_probe(receipt: dict[str, object]) -> None:
    abort = receipt["source_abort_reconciliation_qualification"]
    assert isinstance(abort, dict)
    terminal = abort["committed_probe_terminal"]
    assert isinstance(terminal, dict)
    terminal["adapter_configuration_sha256"] = abort["adapter_configuration_sha256"]
    terminal["adapter_binding_receipt"] = copy.deepcopy(abort["adapter_binding_receipt"])
    terminal["adapter_binding_document"] = copy.deepcopy(abort["adapter_binding_document"])


def rebind_first_cell_to_alternate_logical_rows(receipt: dict[str, object]) -> None:
    cell = receipt["cells"][0]
    assert isinstance(cell, dict)
    digest = "d4" * 32
    cell["external_oracle"]["semantic_projection"]["logical_contents"][
        "accounts_sha256"
    ] = digest
    cell["raw_client_observation"]["cursor_rows_sha256"] = digest
    cell["equivalence_projection"]["logical_contents"]["accounts_sha256"] = digest
    cell["equivalence_projection"]["cursor"]["rows_sha256"] = digest


class ScriptedProvider:
    def __init__(self, statuses: list[dict[str, object]]) -> None:
        self.statuses = list(statuses)
        self.last = statuses[-1]
        self.arms: list[tuple[str, dict[str, object]]] = []
        self.releases: list[tuple[str, str]] = []
        self.events: list[str] = []
        self.status_calls = 0

    def status(self) -> dict[str, object]:
        self.status_calls += 1
        if self.statuses:
            self.last = self.statuses.pop(0)
        self.events.append("status:" + str(self.last["barrier"]))
        return self.last

    def arm(self, token: str, predicate: dict[str, object]) -> None:
        self.arms.append((token, dict(predicate)))
        self.events.append("arm")

    def release(self, token: str, action: str) -> dict[str, object]:
        self.releases.append((token, action))
        self.events.append("release:" + action)
        if self.statuses:
            self.last = self.statuses.pop(0)
        self.events.append("atomic-release-status:" + str(self.last["barrier"]))
        return self.last


class MatrixContractTests(unittest.TestCase):
    def test_capsule_fixture_tracks_the_production_provider_schema(self) -> None:
        provider_source = (
            MODULE_PATH.parent.parent
            / "crates"
            / "runtime"
            / "visa_wasi_host"
            / "src"
            / "provider.rs"
        ).read_text(encoding="utf-8")
        self.assertIn(
            f"const SCHEMA_VERSION: i64 = {MATRIX.PROVIDER_SCHEMA_VERSION};",
            provider_source,
        )
        with tempfile.TemporaryDirectory(prefix="sqlite-capsule-version-") as raw:
            database = Path(raw) / "state.sqlite"
            database.write_bytes(CAPSULE_STATE_BYTES)
            connection = sqlite3.connect(
                f"file:{database}?mode=ro&immutable=1",
                uri=True,
            )
            try:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone(),
                    (MATRIX.PROVIDER_SCHEMA_VERSION,),
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT schema_version FROM meta WHERE singleton = 1"
                    ).fetchone(),
                    (MATRIX.PROVIDER_SCHEMA_VERSION,),
                )
            finally:
                connection.close()

    def test_plan_has_all_eight_exact_official_model_cells(self) -> None:
        plan = MATRIX.build_plan("workload/accounts.db")
        self.assertEqual(plan["schema"], MATRIX.PLAN_SCHEMA)
        self.assertEqual(plan["artifact_class"], "plan-not-execution-evidence")
        self.assertFalse(plan["bytes_written_polling_allowed"])
        self.assertEqual(len(plan["cells"]), 8)
        self.assertEqual(
            [cell["cell_id"] for cell in plan["cells"]],
            [spec.cell_id for spec in MATRIX.CUT_SPECS],
        )
        self.assertEqual(
            plan["cells"][0]["predicate"],
            {
                "kind": "path-create-directory",
                "resource": "path:workload/accounts.db.lock",
                "outcome": "success",
                "occurrence": 1,
            },
        )
        self.assertFalse(plan["locking_substrate"]["visa_vfs_lock_extension_used"])
        self.assertEqual(
            plan["stock_wasi_io_imports"],
            {"read": "fd_read", "write": "fd_write", "sync": "fd_sync"},
        )
        encoded_plan = json.dumps(plan)
        self.assertNotIn("fd-pwrite", encoded_plan)
        self.assertNotIn("fd-pread", encoded_plan)
        self.assertEqual(plan["cells"][1]["predicate"]["kind"], "fd-write")
        self.assertEqual(plan["cells"][2]["predicate"]["occurrence"], 2)
        self.assertEqual(plan["cells"][7]["predicate"]["kind"], "fd-read")
        self.assertEqual(plan["cells"][7]["predicate"]["occurrence"], 12)
        for cell in plan["cells"]:
            self.assertTrue(cell["predicate"]["resource"].startswith("path:"))
            self.assertNotEqual(cell["predicate"]["kind"], "any")
            self.assertNotEqual(cell["predicate"]["resource"], "any")

    def test_plan_rejects_noncanonical_database_paths(self) -> None:
        for path in ("", "/accounts.db", "workload/../accounts.db", "./accounts.db"):
            with self.subTest(path=path), self.assertRaises(MATRIX.MatrixFailure):
                MATRIX.build_plan(path)

    def test_formal_receipt_rejects_a_coherently_relocated_database_path(self) -> None:
        receipt = complete_receipt()
        plan = MATRIX.build_plan("other/forged.db")
        receipt["plan"] = plan
        receipt["plan_sha256"] = MATRIX.canonical_sha256(plan)
        for cell, plan_cell in zip(receipt["cells"], plan["cells"], strict=True):
            cell["plan_entry_sha256"] = MATRIX.canonical_sha256(plan_cell)
            cell["barrier"]["predicate"] = copy.deepcopy(plan_cell["predicate"])
            cell["barrier"]["armed"]["barrier_remaining"] = plan_cell["predicate"][
                "occurrence"
            ]
            if "continuation_witness" in cell:
                cell["continuation_witness"]["predicate"] = copy.deepcopy(
                    plan_cell["continuation_witness"]
                )
                cell["continuation_witness"]["armed"]["barrier_remaining"] = plan_cell[
                    "continuation_witness"
                ]["occurrence"]
        with self.assertRaisesRegex(MATRIX.MatrixFailure, "canonical cut plan"):
            MATRIX.validate_matrix_receipt(receipt, "ab" * 20)

    def test_controller_arms_before_wait_and_releases_only_after_held(self) -> None:
        predicate = MATRIX.build_plan()["cells"][2]["predicate"]
        effect = "11" * 16
        provider = ScriptedProvider(
            [
                status("active", "open"),
                status("active", "armed", remaining=2),
                status("active", "armed", remaining=2),
                status("active", "triggered", effect=effect),
                status("active", "held", effect=effect),
                status("active", "checkpoint_released", effect=effect),
            ]
        )
        controller = MATRIX.ExactBarrierController(
            provider, timeout_seconds=1, pause=lambda _: None
        )
        armed = controller.arm("22" * 16, predicate)
        self.assertEqual(armed["armed"]["barrier"], "armed")
        held = controller.await_target()
        released = controller.release_checkpoint("22" * 16, held)
        self.assertEqual(released["barrier"], "checkpoint_released")
        self.assertEqual(provider.arms, [("22" * 16, predicate)])
        self.assertEqual(provider.releases, [("22" * 16, "checkpoint")])
        self.assertNotIn(
            "bytes_written", inspect.getsource(MATRIX.ExactBarrierController)
        )

    def test_lost_response_requires_observable_triggered_not_held(self) -> None:
        provider = ScriptedProvider(
            [status("active", "held", effect="11" * 16)]
        )
        controller = MATRIX.ExactBarrierController(
            provider, timeout_seconds=1, pause=lambda _: None
        )
        with self.assertRaisesRegex(
            MATRIX.MatrixFailure, "did not stop guest completion"
        ):
            controller.await_target("triggered")

    def test_continue_release_uses_atomic_status_and_exact_completion_identity(self) -> None:
        predicate = MATRIX.build_plan()["cells"][0]["continuation_witness"]
        token = "23" * 16
        effect = "24" * 16
        provider = ScriptedProvider(
            [
                status("active", "open"),
                status("active", "armed", remaining=1, effects=19, completed=19),
                status("active", "held", effect=effect),
                status(
                    "active",
                    "open",
                    completed_barrier=token,
                    completed_effect=effect,
                ),
            ]
        )
        witness = MATRIX.execute_continue_witness(
            provider,
            token=token,
            predicate=predicate,
            start_segment=lambda: provider.events.append("start-segment"),
            timeout_seconds=1,
        )
        self.assertEqual(provider.status_calls, 3)
        self.assertEqual(witness["continued"]["completed_barrier"], token)
        self.assertEqual(witness["continued"]["completed_barrier_effect"], effect)
        self.assertEqual(
            witness["continued"]["effects"], witness["target"]["effects"]
        )

    def test_execution_helper_orders_arm_segment_release_and_checkpoint(self) -> None:
        predicate = MATRIX.build_plan()["cells"][4]["predicate"]
        effect = "31" * 16
        provider = ScriptedProvider(
            [
                status("active", "open"),
                status("active", "armed", remaining=1),
                status("active", "held", effect=effect),
                status("active", "checkpoint_released", effect=effect),
            ]
        )
        with tempfile.TemporaryDirectory(prefix="sqlite-cut-executor-test-") as raw:
            checkpoint = Path(raw) / "checkpoint.pb"
            checkpoint.write_bytes(b"real-checkpoint-fixture")

            def start() -> None:
                provider.events.append("start-segment")

            def await_checkpoint() -> Path:
                provider.events.append("await-checkpoint")
                return checkpoint

            result = MATRIX.execute_checkpoint_cut(
                provider,
                token="32" * 16,
                predicate=predicate,
                start_segment=start,
                await_checkpoint=await_checkpoint,
                timeout_seconds=1,
            )
        self.assertLess(provider.events.index("arm"), provider.events.index("start-segment"))
        self.assertLess(
            provider.events.index("release:checkpoint"),
            provider.events.index("await-checkpoint"),
        )
        self.assertEqual(result["barrier"]["target"]["barrier"], "held")
        self.assertEqual(result["compute_checkpoint"]["size"], 23)

    def test_controller_rejects_target_without_durable_effect(self) -> None:
        provider = ScriptedProvider([status("active", "held")])
        controller = MATRIX.ExactBarrierController(
            provider, timeout_seconds=1, pause=lambda _: None
        )
        with self.assertRaisesRegex(MATRIX.MatrixFailure, "lacks its durable effect"):
            controller.await_target("held")

    def test_complete_receipt_validates(self) -> None:
        MATRIX.validate_matrix_receipt(complete_receipt(), "ab" * 20)

    def test_retained_raw_evidence_is_recomputed_by_the_cli_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-retained-test-") as raw:
            root = Path(raw)
            receipt_path, oracle_path, _ = materialize_retained_receipt(root)
            MATRIX.load_and_validate(
                receipt_path,
                expected_revision="ab" * 20,
                oracle_binary=oracle_path,
            )

    def test_provider_recovery_is_rederived_from_raw_harness_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-provider-recovery-") as raw:
            root = Path(raw)
            receipt_path, oracle_path, receipt = materialize_retained_receipt(root)
            recovery = receipt["process_recovery_qualification"]
            retained_raw = recovery["retained_raw_evidence"]
            stdout_reference = retained_raw["process"]["stdout"]
            stdout_path = root.joinpath(*stdout_reference["path"].split("/"))
            payload = stdout_path.read_bytes().replace(
                b"test response_loss_then_provider_kill_reopen_replays_exactly_once ... ok",
                b"test forged_provider_recovery_claim ... ok",
            )
            stdout_path.write_bytes(payload)
            stdout_identity = {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
            stdout_reference.update(stdout_identity)
            report_reference = retained_raw["report"]
            report_path = root.joinpath(*report_reference["path"].split("/"))
            report = json.loads(report_path.read_bytes())
            report["stdout"] = stdout_identity
            report_payload = MATRIX.canonical_bytes(report) + b"\n"
            report_path.write_bytes(report_payload)
            report_reference.update(
                {
                    "sha256": hashlib.sha256(report_payload).hexdigest(),
                    "size": len(report_payload),
                }
            )
            receipt_path.write_bytes(MATRIX.canonical_bytes(receipt) + b"\n")
            with self.assertRaisesRegex(
                MATRIX.MatrixFailure, "exact passing tests"
            ):
                MATRIX.load_and_validate(
                    receipt_path,
                    expected_revision="ab" * 20,
                    oracle_binary=oracle_path,
                )

    def test_source_abort_raw_recovery_documents_are_rederived(self) -> None:
        for scenario in (
            "init-stdout-content",
            "restart-stdout-content",
            "authority-stderr-content",
            "committed-abort-diagnostic-status",
            "coordinated-generations",
            "pending-commit-proof",
            "coordinated-status-counters",
            "recovered-only-status-counters",
            "final-phase",
            "checkpoint",
            "valid-unrelated-checkpoint",
            "coordinator-stream-identity",
            "forged-cut",
            "frozen-epoch",
            "manifest-application",
            "duplicate-ack",
        ):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="sqlite-source-abort-"
            ) as raw:
                root = Path(raw)
                receipt_path, oracle_path, receipt = materialize_retained_receipt(
                    root
                )
                abort = receipt["source_abort_reconciliation_qualification"]
                retained_raw = abort["retained_raw_evidence"]

                def rewrite(reference: dict[str, object], payload: bytes) -> None:
                    path = root.joinpath(*reference["path"].split("/"))
                    path.write_bytes(payload)
                    reference.update(
                        {
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "size": len(payload),
                        }
                    )

                if scenario in {
                    "init-stdout-content",
                    "restart-stdout-content",
                    "authority-stderr-content",
                    "committed-abort-diagnostic-status",
                }:
                    role, stream, payload, report_field = {
                        "init-stdout-content": (
                            "init",
                            "stdout",
                            b"forged init record\n",
                            "init_stdout",
                        ),
                        "restart-stdout-content": (
                            "restart-recovery",
                            "stdout",
                            b'{"phase":"source_resumed"}\n',
                            "recovered_stdout",
                        ),
                        "authority-stderr-content": (
                            "authority-init",
                            "stderr",
                            b"unexpected success diagnostic\n",
                            "authority_init_stderr",
                        ),
                        "committed-abort-diagnostic-status": (
                            "committed-probe-abort",
                            "stderr",
                            b"unrelated failure\n",
                            "canonical_commit_abort_stderr",
                        ),
                    }[scenario]
                    run = next(
                        item
                        for item in retained_raw["driver_runs"]
                        if item["role"] == role
                    )
                    reference = run[stream]
                    rewrite(reference, payload)
                    report_reference = retained_raw["integrated_driver_report"]
                    report_path = root.joinpath(
                        *report_reference["path"].split("/")
                    )
                    report = json.loads(report_path.read_bytes())
                    report["coordinator_restart"][report_field] = (
                        reference_identity(reference)
                    )
                    if scenario == "committed-abort-diagnostic-status":
                        run["exit_status"] = 7
                        report["coordinator_restart"][
                            "canonical_commit_abort_exit_status"
                        ] = 7
                        abort["canonical_commit_abort_exit_status"] = 7
                    rewrite(
                        report_reference,
                        MATRIX.canonical_bytes(report) + b"\n",
                    )
                    abort["integrated_driver_report"] = reference_identity(
                        report_reference
                    )
                elif scenario == "coordinated-generations":
                    pending_reference = retained_raw["pending_driver_record"]
                    final_reference = retained_raw["final_driver_record"]
                    pending = json.loads(
                        root.joinpath(
                            *pending_reference["path"].split("/")
                        ).read_bytes()
                    )
                    final = json.loads(
                        root.joinpath(
                            *final_reference["path"].split("/")
                        ).read_bytes()
                    )
                    pending["generation"] = 20
                    final["generation"] = 23
                    rewrite(
                        pending_reference, MATRIX.canonical_bytes(pending)
                    )
                    rewrite(final_reference, MATRIX.canonical_bytes(final))
                    abort["pending_driver_record"] = reference_identity(
                        pending_reference
                    )
                    init_record = {
                        **pending,
                        "generation": 17,
                        "phase": "manifest_sealed",
                        "pending_action": None,
                        "source_retained_proof": None,
                    }
                    init_run = next(
                        item
                        for item in retained_raw["driver_runs"]
                        if item["role"] == "init"
                    )
                    restart_run = next(
                        item
                        for item in retained_raw["driver_runs"]
                        if item["role"] == "restart-recovery"
                    )
                    rewrite(init_run["stdout"], pretty_json_line(init_record))
                    rewrite(restart_run["stdout"], pretty_json_line(final))
                    report_reference = retained_raw["integrated_driver_report"]
                    report_path = root.joinpath(
                        *report_reference["path"].split("/")
                    )
                    report = json.loads(report_path.read_bytes())
                    report["driver_record"] = reference_identity(final_reference)
                    report["coordinator_restart"]["pending_record"] = (
                        reference_identity(pending_reference)
                    )
                    report["coordinator_restart"]["init_stdout"] = (
                        reference_identity(init_run["stdout"])
                    )
                    report["coordinator_restart"]["recovered_stdout"] = (
                        reference_identity(restart_run["stdout"])
                    )
                    rewrite(
                        report_reference,
                        MATRIX.canonical_bytes(report) + b"\n",
                    )
                    abort["integrated_driver_report"] = reference_identity(
                        report_reference
                    )
                elif scenario == "pending-commit-proof":
                    pending_reference = retained_raw["pending_driver_record"]
                    pending_path = root.joinpath(
                        *pending_reference["path"].split("/")
                    )
                    pending = json.loads(pending_path.read_bytes())
                    pending["ownership_commit_proof"] = abort[
                        "committed_probe_terminal"
                    ]["proof"]
                    rewrite(
                        pending_reference, MATRIX.canonical_bytes(pending)
                    )
                    abort["pending_driver_record"] = reference_identity(
                        pending_reference
                    )
                    report_reference = retained_raw["integrated_driver_report"]
                    report_path = root.joinpath(
                        *report_reference["path"].split("/")
                    )
                    report = json.loads(report_path.read_bytes())
                    report["coordinator_restart"]["pending_record"] = (
                        reference_identity(pending_reference)
                    )
                    rewrite(
                        report_reference,
                        MATRIX.canonical_bytes(report) + b"\n",
                    )
                    abort["integrated_driver_report"] = reference_identity(
                        report_reference
                    )
                elif scenario == "coordinated-status-counters":
                    report_reference = retained_raw["integrated_driver_report"]
                    report_path = root.joinpath(
                        *report_reference["path"].split("/")
                    )
                    report = json.loads(report_path.read_bytes())
                    barrier = report["cut"]["barrier"]
                    for name, counter in (
                        ("armed", 900),
                        ("target", 901),
                        ("checkpoint_released", 901),
                    ):
                        barrier[name]["effects"] = counter
                        barrier[name]["completed_requests"] = counter
                    for name, counter in (
                        ("source_frozen", 901),
                        ("source_provider_resumed_before_restart", 901),
                        ("source_provider_after_recovery", 902),
                    ):
                        report[name]["effects"] = counter
                        report[name]["completed_requests"] = counter
                    report["namespace_snapshot"]["effects"] = 902
                    abort["namespace_snapshot"]["effects"] = 902
                    rewrite(
                        report_reference,
                        MATRIX.canonical_bytes(report) + b"\n",
                    )
                    abort["integrated_driver_report"] = reference_identity(
                        report_reference
                    )
                elif scenario == "recovered-only-status-counters":
                    report_reference = retained_raw["integrated_driver_report"]
                    report_path = root.joinpath(
                        *report_reference["path"].split("/")
                    )
                    report = json.loads(report_path.read_bytes())
                    report["source_provider_after_recovery"]["effects"] = 77
                    report["source_provider_after_recovery"][
                        "completed_requests"
                    ] = 77
                    report["namespace_snapshot"]["effects"] = 77
                    abort["namespace_snapshot"]["effects"] = 77
                    rewrite(
                        report_reference,
                        MATRIX.canonical_bytes(report) + b"\n",
                    )
                    abort["integrated_driver_report"] = reference_identity(
                        report_reference
                    )
                elif scenario == "final-phase":
                    final_reference = retained_raw["final_driver_record"]
                    final_path = root.joinpath(*final_reference["path"].split("/"))
                    final = json.loads(final_path.read_bytes())
                    final["phase"] = "source_retained"
                    rewrite(
                        final_reference,
                        MATRIX.canonical_bytes(final),
                    )
                    report_reference = retained_raw["integrated_driver_report"]
                    report_path = root.joinpath(*report_reference["path"].split("/"))
                    report = json.loads(report_path.read_bytes())
                    report["driver_record"] = reference_identity(final_reference)
                    rewrite(
                        report_reference,
                        MATRIX.canonical_bytes(report) + b"\n",
                    )
                    abort["integrated_driver_report"] = reference_identity(
                        report_reference
                    )
                elif scenario in ("checkpoint", "valid-unrelated-checkpoint"):
                    checkpoint_reference = retained_raw["compute_checkpoint"]
                    checkpoint_payload = (
                        b"coordinated-forged-checkpoint"
                        if scenario == "checkpoint"
                        else WANCO_FIXTURE.checkpoint_payload(
                            MATRIX.TYPED_CORPUS.CASE_SPECS[3]
                        )
                    )
                    rewrite(checkpoint_reference, checkpoint_payload)
                    abort["compute_checkpoint"] = reference_identity(
                        checkpoint_reference
                    )
                    exit_reference = retained_raw["source_exit_receipt"]
                    source_exit = {
                        "schema": "visa-wanco-source-exit-v1",
                        "exit_status": 0,
                        "checkpoint": abort["compute_checkpoint"],
                    }
                    rewrite(
                        exit_reference,
                        MATRIX.canonical_bytes(source_exit) + b"\n",
                    )
                    report_reference = retained_raw["integrated_driver_report"]
                    report_path = root.joinpath(*report_reference["path"].split("/"))
                    report = json.loads(report_path.read_bytes())
                    report["compute_checkpoint"] = abort["compute_checkpoint"]
                    report["source_exit_receipt"] = reference_identity(
                        exit_reference
                    )
                    rewrite(
                        report_reference,
                        MATRIX.canonical_bytes(report) + b"\n",
                    )
                    abort["integrated_driver_report"] = reference_identity(
                        report_reference
                    )
                elif scenario in {
                    "coordinator-stream-identity",
                    "forged-cut",
                    "frozen-epoch",
                }:
                    report_reference = retained_raw["integrated_driver_report"]
                    report_path = root.joinpath(*report_reference["path"].split("/"))
                    report = json.loads(report_path.read_bytes())
                    if scenario == "coordinator-stream-identity":
                        report["coordinator_restart"]["init_stdout"] = None
                    elif scenario == "forged-cut":
                        report["cut"] = {"arbitrary": "forged"}
                    else:
                        report["source_frozen"]["authority_epoch"] = 999
                    rewrite(
                        report_reference,
                        MATRIX.canonical_bytes(report) + b"\n",
                    )
                    abort["integrated_driver_report"] = reference_identity(
                        report_reference
                    )
                elif scenario == "manifest-application":
                    pending_reference = retained_raw["pending_driver_record"]
                    final_reference = retained_raw["final_driver_record"]
                    pending_path = root.joinpath(*pending_reference["path"].split("/"))
                    final_path = root.joinpath(*final_reference["path"].split("/"))
                    pending = json.loads(pending_path.read_bytes())
                    final = json.loads(final_path.read_bytes())
                    for record in (pending, final):
                        record["migration_manifest"]["application"]["sha256"] = (
                            "ef" * 32
                        )
                    rewrite(
                        pending_reference,
                        MATRIX.canonical_bytes(pending),
                    )
                    rewrite(
                        final_reference,
                        MATRIX.canonical_bytes(final),
                    )
                    abort["pending_driver_record"] = reference_identity(
                        pending_reference
                    )
                    report_reference = retained_raw["integrated_driver_report"]
                    report_path = root.joinpath(*report_reference["path"].split("/"))
                    report = json.loads(report_path.read_bytes())
                    report["driver_record"] = reference_identity(final_reference)
                    report["coordinator_restart"]["pending_record"] = (
                        reference_identity(pending_reference)
                    )
                    rewrite(
                        report_reference,
                        MATRIX.canonical_bytes(report) + b"\n",
                    )
                    abort["integrated_driver_report"] = reference_identity(
                        report_reference
                    )
                else:
                    stdout_reference = retained_raw["client_stdout"]
                    stdout_path = root.joinpath(*stdout_reference["path"].split("/"))
                    payload = stdout_path.read_bytes().replace(
                        b"VISA_ACK|tx-000001\n",
                        b"VISA_ACK|tx-000001\nVISA_ACK|tx-000001\n",
                    )
                    rewrite(stdout_reference, payload)
                    abort["raw_client_observation"]["stdout"] = reference_identity(
                        stdout_reference
                    )
                receipt_path.write_bytes(MATRIX.canonical_bytes(receipt) + b"\n")
                expected_failure = (
                    "checkpoint/application compatibility"
                    if scenario == "valid-unrelated-checkpoint"
                    else None
                )
                failure_context = (
                    self.assertRaisesRegex(MATRIX.MatrixFailure, expected_failure)
                    if expected_failure is not None
                    else self.assertRaises(MATRIX.MatrixFailure)
                )
                with failure_context:
                    MATRIX.load_and_validate(
                        receipt_path,
                        expected_revision="ab" * 20,
                        oracle_binary=oracle_path,
                    )

    def test_cli_requires_the_retained_typed_corpus_raw_bytes(self) -> None:
        for scenario in ("missing", "tampered"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="sqlite-typed-corpus-"
            ) as raw:
                root = Path(raw)
                receipt_path, oracle_path, receipt = materialize_retained_receipt(root)
                typed_manifest = json.loads(
                    (root / "wanco-typed-corpus" / "receipt.json").read_text()
                )
                reference = typed_manifest["cases"][0]["artifacts"]["control_stdout"]
                retained = (root / "wanco-typed-corpus").joinpath(
                    *reference["path"].split("/")
                )
                if scenario == "missing":
                    retained.unlink()
                else:
                    retained.write_bytes(b"forged\n")
                with self.assertRaises(MATRIX.MatrixFailure):
                    MATRIX.load_and_validate(
                        receipt_path,
                        expected_revision=receipt["repository_revision"],
                        oracle_binary=oracle_path,
                    )

    def test_cli_rejects_forged_application_execution_records(self) -> None:
        for scenario in ("exit", "stderr", "detached-stdout"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="sqlite-application-run-mutation-"
            ) as raw:
                root = Path(raw)
                receipt_path, oracle_path, receipt = materialize_retained_receipt(
                    root
                )
                run = receipt["cells"][0]["retained_raw_evidence"][
                    "application_runs"
                ][0]
                if scenario == "exit":
                    run["exit_status"] = 9
                else:
                    stream = "stderr" if scenario == "stderr" else "stdout"
                    reference = run[stream]
                    path = root.joinpath(*reference["path"].split("/"))
                    payload = b"\xff" if scenario == "stderr" else b"delete\nforged\n"
                    path.write_bytes(payload)
                    reference.update(
                        {
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "size": len(payload),
                        }
                    )
                receipt_path.write_bytes(MATRIX.canonical_bytes(receipt) + b"\n")
                with self.assertRaises(MATRIX.MatrixFailure):
                    MATRIX.load_and_validate(
                        receipt_path,
                        expected_revision="ab" * 20,
                        oracle_binary=oracle_path,
                    )

    def test_cli_rejects_rebinding_a_cell_to_control_raw_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-retained-rebind-") as raw:
            root = Path(raw)
            receipt_path, oracle_path, receipt = materialize_retained_receipt(root)
            control = receipt["uninterrupted_control"]
            cell = receipt["cells"][0]
            cell["retained_raw_evidence"] = copy.deepcopy(
                control["retained_raw_evidence"]
            )
            cell["namespace_snapshot"]["artifact"] = copy.deepcopy(
                control["namespace_snapshot"]["artifact"]
            )
            cell["external_oracle"]["report"] = copy.deepcopy(
                control["external_oracle"]["report"]
            )
            cell["expected_acknowledgements"] = copy.deepcopy(
                control["expected_acknowledgements"]
            )
            cell["raw_client_observation"]["stdout"] = copy.deepcopy(
                control["raw_client_observation"]["stdout"]
            )
            receipt_path.write_bytes(MATRIX.canonical_bytes(receipt) + b"\n")
            with self.assertRaisesRegex(MATRIX.MatrixFailure, "canonical cell path"):
                MATRIX.load_and_validate(
                    receipt_path,
                    expected_revision="ab" * 20,
                    oracle_binary=oracle_path,
                )

    def test_missing_tampered_and_forged_raw_evidence_is_rejected(self) -> None:
        scenarios = (
            "missing",
            "row",
            "ack",
            "terminal",
            "unexpected-line",
            "oracle",
            "symlink",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="sqlite-retained-mutation-"
            ) as raw:
                root = Path(raw)
                receipt_path, oracle_path, receipt = materialize_retained_receipt(
                    root
                )
                reference = receipt["cells"][0]["retained_raw_evidence"][
                    "client_stdout"
                ]
                stdout_path = root.joinpath(*reference["path"].split("/"))
                stdout = stdout_path.read_bytes()
                if scenario == "missing":
                    stdout_path.unlink()
                elif scenario == "row":
                    reseal_raw_file(
                        receipt,
                        root,
                        cell_index=0,
                        role="client_stdout",
                        payload=stdout.replace(b"VISA_ROW|1|999", b"VISA_ROW|1|998"),
                    )
                elif scenario == "ack":
                    reseal_raw_file(
                        receipt,
                        root,
                        cell_index=0,
                        role="client_stdout",
                        payload=stdout.replace(b"VISA_ACK|tx-000001\n", b""),
                    )
                elif scenario == "terminal":
                    reseal_raw_file(
                        receipt,
                        root,
                        cell_index=0,
                        role="client_stdout",
                        payload=stdout.replace(
                            b"VISA_CURSOR_DONE|5", b"VISA_CURSOR_DONE|4"
                        ),
                    )
                elif scenario == "unexpected-line":
                    reseal_raw_file(
                        receipt,
                        root,
                        cell_index=0,
                        role="client_stdout",
                        payload=stdout + b"UNEXPECTED APPLICATION ERROR\n",
                    )
                elif scenario == "oracle":
                    report_reference = receipt["cells"][0][
                        "retained_raw_evidence"
                    ]["oracle_report"]
                    report_path = root.joinpath(*report_reference["path"].split("/"))
                    report = json.loads(report_path.read_bytes())
                    report["accepted"] = False
                    reseal_raw_file(
                        receipt,
                        root,
                        cell_index=0,
                        role="oracle_report",
                        payload=json.dumps(report, sort_keys=True).encode() + b"\n",
                    )
                else:
                    target = root / "symlink-target"
                    target.write_bytes(stdout)
                    stdout_path.unlink()
                    stdout_path.symlink_to(target)
                with self.assertRaises(MATRIX.MatrixFailure):
                    MATRIX.load_and_validate(
                        receipt_path,
                        expected_revision="ab" * 20,
                        oracle_binary=oracle_path,
                    )

    def test_receipt_rejects_semantic_gaps_and_overclaims(self) -> None:
        mutations = {
            "missing-uninterrupted-control": lambda receipt: receipt.pop(
                "uninterrupted_control"
            ),
            "dirty-source-snapshot": lambda receipt: receipt[
                "repository_source_snapshot"
            ].__setitem__("clean", False),
            "nonempty-source-status": lambda receipt: receipt[
                "repository_source_snapshot"
            ].__setitem__("status_sha256", "cd" * 32),
            "untracked-source-files": lambda receipt: receipt[
                "repository_source_snapshot"
            ].__setitem__("untracked_file_count", 1),
            "raw-client-reference-drift": lambda receipt: receipt["cells"][0][
                "retained_raw_evidence"
            ]["client_stdout"].__setitem__("sha256", "d3" * 32),
            "raw-reference-path-escape": lambda receipt: receipt["cells"][0][
                "retained_raw_evidence"
            ]["client_stdout"].__setitem__("path", "../raw-client.stdout"),
            "cell-raw-reference-rebound-to-control": lambda receipt: receipt["cells"][
                0
            ].__setitem__(
                "retained_raw_evidence",
                copy.deepcopy(
                    receipt["uninterrupted_control"]["retained_raw_evidence"]
                ),
            ),
            "control-oracle-logical-mutation": lambda receipt: receipt[
                "uninterrupted_control"
            ]["external_oracle"]["semantic_projection"]["logical_contents"].__setitem__(
                "accounts_sha256", "d3" * 32
            ),
            "control-raw-cursor-mutation": lambda receipt: receipt[
                "uninterrupted_control"
            ]["raw_client_observation"].__setitem__("cursor_rows_sha256", "d3" * 32),
            "control-projection-forgery": lambda receipt: receipt[
                "uninterrupted_control"
            ]["equivalence_projection"]["cursor"].__setitem__(
                "rows_sha256", "d3" * 32
            ),
            "cell-oracle-raw-divergence": lambda receipt: receipt["cells"][0][
                "external_oracle"
            ]["semantic_projection"]["logical_contents"].__setitem__(
                "accounts_sha256", "d3" * 32
            ),
            "cell-internally-consistent-but-differs-from-control": (
                rebind_first_cell_to_alternate_logical_rows
            ),
            "cell-projection-forgery": lambda receipt: receipt["cells"][0][
                "equivalence_projection"
            ]["logical_contents"].__setitem__("transactions_sha256", "d3" * 32),
            "non-cursor-cell-claims-source-prefix": lambda receipt: receipt["cells"][0][
                "raw_client_observation"
            ].__setitem__("cursor_prefix_rows", 1),
            "predicate-drift": lambda receipt: receipt["cells"][2]["barrier"][
                "predicate"
            ].__setitem__("occurrence", 3),
            "missing-continuation-witness": lambda receipt: receipt["cells"][1].pop(
                "continuation_witness"
            ),
            "continuation-completed-token-drift": lambda receipt: receipt["cells"][0][
                "continuation_witness"
            ]["continued"].__setitem__("completed_barrier", "d1" * 16),
            "continuation-completed-effect-drift": lambda receipt: receipt["cells"][0][
                "continuation_witness"
            ]["continued"].__setitem__("completed_barrier_effect", "d2" * 16),
            "continuation-release-counter-advance": lambda receipt: receipt["cells"][0][
                "continuation_witness"
            ]["continued"].update({"effects": 21, "completed_requests": 21}),
            "fresh-client-uncertain-replay": lambda receipt: receipt["cells"][6][
                "delivery_fault"
            ].__setitem__(
                "replay_client",
                receipt["cells"][6]["handoff"]["destination_client"],
            ),
            "duplicated-effect-on-replay": lambda receipt: receipt["cells"][6][
                "delivery_fault"
            ].__setitem__("effects_after_replay", 27),
            "source-death-not-drained": lambda receipt: receipt["cells"][6][
                "delivery_fault"
            ]["pre_completion_source_death"].__setitem__(
                "rejected_by", "unsafe-migration-accepted"
            ),
            "cursor-at-terminal": lambda receipt: receipt["cells"][7][
                "external_anchor"
            ].__setitem__("observed_prefix_rows", 5),
            "oracle-rejected": lambda receipt: receipt["cells"][0][
                "external_oracle"
            ].__setitem__("accepted", False),
            "power-loss-overclaim": lambda receipt: receipt[
                "durability_scope"
            ].__setitem__("power_loss", True),
            "process-recovery-missing-case": lambda receipt: receipt[
                "process_recovery_qualification"
            ]["qualified_tests"].pop(),
            "typed-corpus-missing-case": lambda receipt: receipt[
                "typed_restore_corpus_qualification"
            ]["cases"].pop(),
            "typed-corpus-restore-divergence": lambda receipt: receipt[
                "typed_restore_corpus_qualification"
            ]["cases"][0]["restored_suffix_values"].__setitem__(0, 9999),
            "typed-corpus-wrong-build": lambda receipt: receipt[
                "typed_restore_corpus_qualification"
            ].__setitem__("wanco_build_receipt", identity(777)),
            "typed-corpus-identity-drift": lambda receipt: receipt[
                "execution_inputs"
            ]["wanco_typed_restore_corpus"].__setitem__("size", 777),
            "ack-not-observed": lambda receipt: receipt["cells"][0][
                "raw_client_observation"
            ].__setitem__("ack_terminal_count", 0),
            "abort-reuses-source-client": lambda receipt: receipt[
                "source_abort_reconciliation_qualification"
            ].__setitem__(
                "source_restore_client",
                receipt["source_abort_reconciliation_qualification"]["source_client"],
            ),
            "abort-loses-pending-action": lambda receipt: receipt[
                "source_abort_reconciliation_qualification"
            ].__setitem__("durable_pending_action", "none"),
            "abort-authority-not-source-retained": lambda receipt: receipt[
                "source_abort_reconciliation_qualification"
            ]["source_retained_terminal"].__setitem__(
                "decision", "ownership_committed"
            ),
            "abort-authority-not-terminal-generation": lambda receipt: receipt[
                "source_abort_reconciliation_qualification"
            ]["source_retained_terminal"].__setitem__("generation", 1),
            "abort-authority-proof-manifest-drift": lambda receipt: receipt[
                "source_abort_reconciliation_qualification"
            ]["source_retained_terminal"]["proof"].__setitem__(
                "migration_manifest_sha256", "ee" * 32
            ),
            "abort-authority-receipt-identity-drift": lambda receipt: receipt[
                "source_abort_reconciliation_qualification"
            ]["source_retained_terminal"]["receipt"].__setitem__("size", 921),
            "abort-authority-coordinated-receipt-forgery": lambda receipt: (
                receipt["source_abort_reconciliation_qualification"][
                    "source_retained_terminal"
                ]["receipt"].__setitem__("size", 921),
                receipt["source_abort_reconciliation_qualification"][
                    "source_retained_terminal"
                ]["proof"]["canonical_receipt"].__setitem__("size", 921),
            ),
            "commit-probe-not-terminal": lambda receipt: receipt[
                "source_abort_reconciliation_qualification"
            ]["committed_probe_terminal"].__setitem__("decision", "uncommitted"),
            "commit-probe-cas-failed": lambda receipt: receipt[
                "source_abort_reconciliation_qualification"
            ].__setitem__("commit_probe_commit_exit_status", 1),
            "commit-probe-handoff-differs-from-abort": (
                rebind_committed_probe_to_a_different_handoff
            ),
            "commit-probe-reuses-source-adapter": reuse_source_adapter_for_committed_probe,
            "commit-probe-state-identity-drift": lambda receipt: receipt[
                "source_abort_reconciliation_qualification"
            ]["committed_probe_terminal"]["state"].__setitem__("size", 922),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                receipt = complete_receipt()
                mutate(receipt)
                with self.assertRaises(MATRIX.MatrixFailure):
                    MATRIX.validate_matrix_receipt(receipt, "ab" * 20)

    def test_exact_revision_is_required_when_bound(self) -> None:
        with self.assertRaisesRegex(MATRIX.MatrixFailure, "expected exact SHA"):
            MATRIX.validate_matrix_receipt(complete_receipt(), "cd" * 20)

    def test_plan_cli_emits_canonical_non_evidence_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-cut-plan-test-") as raw:
            output = Path(raw) / "plan.json"
            completed = subprocess.run(
                [
                    "python3",
                    MODULE_PATH,
                    "plan",
                    "--database-path",
                    "workload/accounts.db",
                    "--output",
                    output,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            payload = output.read_bytes()
            self.assertEqual(payload, MATRIX.canonical_bytes(json.loads(payload)) + b"\n")
            self.assertEqual(
                json.loads(payload)["artifact_class"], "plan-not-execution-evidence"
            )


if __name__ == "__main__":
    unittest.main()
