#!/usr/bin/env python3
"""Focused tests for the exact stock-SQLite rollback-journal matrix contract."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
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


def canonical_identity(value: object) -> dict[str, object]:
    payload = MATRIX.canonical_bytes(value) + b"\n"
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


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
    cases: list[dict[str, object]] = []
    for index, spec in enumerate(MATRIX.TYPED_CORPUS.CASE_SPECS, start=1):
        if spec.profile == MATRIX.TYPED_CORPUS.POST_IMPORT_PROFILE:
            control = [
                MATRIX.TYPED_CORPUS.POST_IMPORT_ENTRY_MARKER,
                MATRIX.TYPED_CORPUS.POST_IMPORT_CHECKPOINT_MARKER,
                1004,
            ]
            prefix = [
                MATRIX.TYPED_CORPUS.POST_IMPORT_ENTRY_MARKER,
                MATRIX.TYPED_CORPUS.POST_IMPORT_CHECKPOINT_MARKER,
            ]
            suffix = [1004]
            nonce = f"{index:064x}"
            container_id = f"{index + 100:064x}"
            witness: dict[str, object] | None = {
                "schema": MATRIX.TYPED_CORPUS.POST_IMPORT_WITNESS_SCHEMA,
                "protocol": "nonce-gated-hostcall-v1",
                "signal": "SIGUSR1",
                "nonce": nonce,
                "container_id": container_id,
                "causal_order": list(MATRIX.TYPED_CORPUS.POST_IMPORT_CAUSAL_ORDER),
            }
        else:
            prefix = [spec.marker - 1, spec.marker]
            suffix = [spec.marker + 1]
            control = prefix + suffix
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
                "post_import_signal_witness": witness,
            }
        )
    return {
        "schema": MATRIX.TYPED_CORPUS.QUALIFICATION_SCHEMA,
        "manifest": identity(19),
        "image_tag": "visa-wanco-carrier:locked",
        "image_id": "sha256:" + "ab" * 32,
        "wanco_build_receipt": build_receipt,
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
) -> dict[str, object]:
    return {
        "mode": mode,
        "authority_epoch": epoch,
        "barrier": barrier,
        "barrier_remaining": remaining,
        "barrier_effect": effect,
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
            "active", "armed", remaining=int(predicate["occurrence"])
        ),
        "target": status("active", target, effect=effect),
    }
    if release == "checkpoint_released":
        result["checkpoint_released"] = status(
            "active", "checkpoint_released", effect=effect
        )
    elif release == "open":
        result["continued"] = status("active", "open")
    return result


def handoff(source_client: str, destination_client: str) -> dict[str, object]:
    return {
        "source_frozen": status(
            "frozen", "checkpoint_released", effect="aa" * 16
        ),
        "destination_prepared": status(
            "prepared", "checkpoint_released", effect="aa" * 16
        ),
        "source_fenced": status(
            "fenced", "checkpoint_released", effect="aa" * 16
        ),
        "destination_active": status("active", "open", epoch=2),
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
        "stock_sqlite_aot": identity(1),
        "stock_sqlite_import_trace": identity(17),
        "visa_wasi_host": identity(15),
        "visa_migration_bind": identity(16),
        "visa_migration_driver": identity(18),
        "visa_sqlite_oracle": identity(500),
    }
    workload = {
        "stock_sqlite_artifact": identity(1),
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
            "handoff": handoff(source_client, destination_client),
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
    manifest_sha256 = "ab" * 32
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
            "scope": "provider-process-kill-reopen",
            "report": identity(900),
            "exit_status": 0,
            "qualified_tests": [
                "response_loss_then_provider_kill_reopen_replays_exactly_once",
                "fd_sync_and_datasync_survive_provider_kill_reopen_in_process_crash_model",
            ],
        },
        "source_abort_reconciliation_qualification": {
            "scope": "pre-commit-source-compute-abort",
            "integrated_driver_report": identity(910),
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
            "accepted": True,
            "source_client": "d1" * 16,
            "source_restore_client": "d2" * 16,
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
    build = {
        "schema": "visa-wanco-carrier-build-receipt-v5",
        "image_tag": "visa-wanco-carrier:locked",
        "image_id": "sha256:" + "ab" * 32,
        "stackmap_binding": "exact-active-callsite-id",
        "stackmap_layout": "typed-locals-and-value-stack-v2",
        "indirect_call_operands_retained": True,
        "active_data_segments_preserved_on_restore": True,
        "per_frame_callee_saved_registers": True,
        "post_import_checkpoint_points": True,
        "guest_tail_calls_disabled": True,
    }
    build_path = source / "wanco-build.json"
    build_path.write_text(json.dumps(build, indent=2, sort_keys=True) + "\n")
    for index, spec in enumerate(MATRIX.TYPED_CORPUS.CASE_SPECS, start=1):
        case = source / "results" / spec.case_id
        case.mkdir(parents=True)
        if spec.profile == MATRIX.TYPED_CORPUS.POST_IMPORT_PROFILE:
            control = [
                MATRIX.TYPED_CORPUS.POST_IMPORT_ENTRY_MARKER,
                MATRIX.TYPED_CORPUS.POST_IMPORT_CHECKPOINT_MARKER,
                1004,
            ]
            prefix = control[:2]
            suffix = control[2:]
        else:
            prefix = [spec.marker - 1, spec.marker]
            suffix = [spec.marker + 1]
            control = prefix + suffix
        for name, values in (
            ("control.stdout", control),
            ("checkpoint.stdout", prefix),
            ("restore.stdout", suffix),
        ):
            (case / name).write_text(
                "".join(f"{value}\n" for value in values), encoding="ascii"
            )
        (case / "checkpoint.stderr").write_text(
            "[debug] Found exact stackmap record\n" * spec.frames,
            encoding="utf-8",
        )
        (case / "restore.stderr").write_text(
            f"[info] - call stack: {spec.frames} frames\n"
            f"[info] - value stack: {spec.typed_stack_values} values\n",
            encoding="utf-8",
        )
        (case / "checkpoint.pb").write_bytes(b"checkpoint:" + spec.case_id.encode())
        if spec.profile == MATRIX.TYPED_CORPUS.POST_IMPORT_PROFILE:
            nonce = f"{index:064x}"
            container_id = f"{index + 100:064x}"
            (case / "import-entered.txt").write_text(f"entered {nonce}\n")
            (case / "signal-dispatched.txt").write_text(
                f"signal-dispatched {nonce}\n"
            )
            (case / "import-release-observed.txt").write_text(
                f"release-observed {nonce}\n"
            )
            (case / "container.id").write_text(f"{container_id}\n")
            (case / "signal.stdout").write_text(f"{container_id}\n")
    manifest, qualification = MATRIX.TYPED_CORPUS.build_bundle(
        source_root=source,
        artifact_root=root / "wanco-typed-corpus",
        image_tag=build["image_tag"],
        image_id=build["image_id"],
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
        "snapshot": {"fixture": True},
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
        *[
            (spec.cell_id, cell, spec.cell_id == "active-read-cursor")
            for spec, cell in zip(MATRIX.CUT_SPECS, receipt["cells"], strict=True)
        ],
    ]
    for label, record, source_cursor_required in records:
        transaction_bytes = b"delete\nVISA_ACK|tx-000001\n"
        cursor_bytes = ("\n".join([*row_lines, "VISA_CURSOR_DONE|5"]) + "\n").encode()
        if label == "uninterrupted-control":
            run_payloads = (
                ("transaction", transaction_bytes),
                ("cursor", cursor_bytes),
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
        record["retained_raw_evidence"] = {
            "application_runs": application_runs,
            "client_stdout": stdout,
            "expected_acknowledgements": expected,
            "namespace_snapshot": snapshot,
            "oracle_report": oracle_report,
        }
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

    def status(self) -> dict[str, object]:
        if self.statuses:
            self.last = self.statuses.pop(0)
        self.events.append("status:" + str(self.last["barrier"]))
        return self.last

    def arm(self, token: str, predicate: dict[str, object]) -> None:
        self.arms.append((token, dict(predicate)))
        self.events.append("arm")

    def release(self, token: str, action: str) -> None:
        self.releases.append((token, action))
        self.events.append("release:" + action)


class MatrixContractTests(unittest.TestCase):
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
