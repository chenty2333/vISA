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


def identity(seed: int) -> dict[str, object]:
    return {"sha256": f"{seed:064x}", "size": seed}


def canonical_identity(value: object) -> dict[str, object]:
    payload = MATRIX.canonical_bytes(value) + b"\n"
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


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
    execution_inputs = {
        "sqlite_source_lock": identity(10),
        "sqlite_build_receipt": identity(11),
        "wanco_source_lock": identity(12),
        "wanco_build_receipt": identity(13),
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
                "exit_status": 0,
                "accepted": True,
            },
            "expected_acknowledgements": acknowledgement,
            "raw_client_observation": {
                "stdout": identity(index + 700),
                "acknowledged_txids": ["tx-000001"],
                "ack_terminal_count": 1,
                "cursor_prefix_rows": 2 if spec.cell_id == "active-read-cursor" else 0,
                "cursor_total_rows": 5 if spec.cell_id == "active-read-cursor" else 0,
                "cursor_done_count": 1 if spec.cell_id == "active-read-cursor" else 0,
            },
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
            "clean": False,
            "status_sha256": "cd" * 32,
            "tracked_patch_sha256": "ce" * 32,
            "untracked_file_count": 3,
            "untracked_manifest_sha256": "cf" * 32,
        },
        "execution_inputs": execution_inputs,
        "plan": plan,
        "plan_sha256": MATRIX.canonical_sha256(plan),
        "workload": workload,
        "cells": cells,
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
        MATRIX.validate_matrix_receipt(complete_receipt())

    def test_receipt_rejects_semantic_gaps_and_overclaims(self) -> None:
        mutations = {
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
                    MATRIX.validate_matrix_receipt(receipt)

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
