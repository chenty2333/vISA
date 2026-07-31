#!/usr/bin/env python3
"""Focused tests for the real stock-SQLite rollback-matrix runner."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


RUNNER_PATH = Path(__file__).with_name("run-stock-sqlite-rollback-matrix.py")
SPEC = importlib.util.spec_from_file_location("stock_sqlite_matrix_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load stock SQLite matrix runner")
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class RunnerTests(unittest.TestCase):
    def test_development_projection_is_json_serializable(self) -> None:
        projected = RUNNER.development_projection(
            {
                "schema": "fixture",
                "nested": {"accepted": True},
                "_raw_paths": {"capsule": Path("/tmp/capsule")},
            }
        )
        self.assertEqual(
            json.loads(RUNNER.canonical_bytes(projected)),
            {"nested": {"accepted": True}, "schema": "fixture"},
        )
        self.assertNotIn("_raw_paths", projected)

    def test_application_runs_retain_stdout_stderr_and_exit_status(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-runner-retained-") as raw:
            root = Path(raw)
            source = root / "source"
            artifact = root / "artifact"
            source.mkdir()
            artifact.mkdir()
            paths = {
                "stdout": source / "source.stdout",
                "stderr": source / "source.stderr",
                "client": source / "client.stdout",
                "acks": source / "acks.json",
                "snapshot": source / "namespace.snapshot",
                "oracle": source / "oracle.json",
            }
            for name, path in paths.items():
                path.write_bytes((name + "\n").encode())
            record = {
                "_raw_paths": {
                    "application_runs": (
                        ("source", paths["stdout"], paths["stderr"], 0),
                    ),
                    "client_stdout": paths["client"],
                    "expected_acknowledgements": paths["acks"],
                    "namespace_snapshot": paths["snapshot"],
                    "oracle_report": paths["oracle"],
                }
            }
            RUNNER.retain_raw_evidence(
                record,
                artifact_root=artifact,
                label="fixture",
            )
            retained = record["retained_raw_evidence"]
            run = retained["application_runs"][0]
            self.assertEqual(run["role"], "source")
            self.assertEqual(run["exit_status"], 0)
            self.assertEqual(
                run["stdout"]["path"],
                "observations/fixture/runs/source.stdout",
            )
            self.assertEqual(
                run["stderr"]["path"],
                "observations/fixture/runs/source.stderr",
            )

    def test_source_abort_retains_driver_runs_and_all_manifest_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-source-abort-retained-") as raw:
            root = Path(raw)
            source = root / "source"
            artifact = root / "artifact"
            source.mkdir()
            artifact.mkdir()

            def materialize(name: str) -> Path:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((name + "\n").encode())
                return path

            document_names = (
                "client_stdout",
                "expected_acknowledgements",
                "namespace_snapshot",
                "oracle_report",
                "compute_checkpoint",
                "migration_application",
                "resource_capsule_manifest",
                "resource_capsule_state",
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
            )
            raw_paths: dict[str, object] = {
                name: materialize(name) for name in document_names
            }
            raw_paths["application_runs"] = (
                (
                    "source",
                    materialize("application-source.stdout"),
                    materialize("application-source.stderr"),
                    0,
                ),
                (
                    "destination",
                    materialize("application-destination.stdout"),
                    materialize("application-destination.stderr"),
                    0,
                ),
            )
            raw_paths["driver_runs"] = tuple(
                (
                    role,
                    materialize(f"{role}.stdout"),
                    materialize(f"{role}.stderr"),
                    expected_status if expected_status is not None else 1,
                )
                for role, _, _, expected_status in RUNNER.CONTRACT.SOURCE_ABORT_DRIVER_RUNS
            )
            qualification = {"_raw_paths": raw_paths}
            RUNNER.retain_source_abort_evidence(
                qualification,
                artifact_root=artifact,
            )
            retained = qualification["retained_raw_evidence"]
            self.assertEqual(
                [run["role"] for run in retained["driver_runs"]],
                [
                    spec[0]
                    for spec in RUNNER.CONTRACT.SOURCE_ABORT_DRIVER_RUNS
                ],
            )
            self.assertEqual(
                retained["migration_application"]["path"],
                "observations/source-abort/migration/application.aot",
            )
            self.assertEqual(
                retained["resource_capsule_state"]["path"],
                "observations/source-abort/migration/capsule-state.sqlite",
            )

    def test_completed_application_run_requires_zero_exit(self) -> None:
        process = SimpleNamespace(
            process=SimpleNamespace(returncode=0),
            stdout_path=Path("stdout"),
            stderr_path=Path("stderr"),
        )
        self.assertEqual(
            RUNNER.completed_application_run("source", process),
            ("source", Path("stdout"), Path("stderr"), 0),
        )
        process.process.returncode = 9
        with self.assertRaises(RUNNER.MatrixFailure):
            RUNNER.completed_application_run("source", process)

    def test_short_socket_root_stays_below_unix_path_limit_and_is_removed(self) -> None:
        with RUNNER.ShortSocketRoot() as sockets:
            root = sockets.path
            configuration_root = sockets.configuration_path
            first = sockets.allocate()
            second = sockets.allocate()
            self.assertIsNotNone(root)
            self.assertEqual(first.parent, root)
            self.assertNotEqual(first, second)
            self.assertLess(len(str(first).encode()), 96)
            self.assertIsNotNone(configuration_root)
            self.assertNotEqual(configuration_root, root)
        self.assertIsNotNone(root)
        self.assertIsNotNone(configuration_root)
        self.assertFalse(root.exists())
        self.assertFalse(configuration_root.exists())

    def test_aot_maps_short_host_sockets_to_dedicated_container_mount(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-runner-case-") as raw:
            case = Path(raw)
            with RUNNER.ShortSocketRoot() as sockets:
                runtime = RUNNER.DockerAot(
                    "docker", "image", case / "application.aot", sockets.path
                )
                self.assertEqual(
                    runtime.container_socket_path(sockets.allocate(), case),
                    "/sockets/s1.sock",
                )
                with self.assertRaises(RUNNER.MatrixFailure):
                    runtime.container_socket_path(Path("/var/tmp/outside.sock"), case)

    def test_transaction_ack_is_derived_from_raw_stdout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-runner-ack-") as raw:
            root = Path(raw)
            source = root / "source.stdout"
            destination = root / "destination.stdout"
            transcript = root / "raw.stdout"
            source.write_text("delete\n", encoding="utf-8")
            destination.write_text("VISA_ACK|tx-000001\n", encoding="utf-8")
            observation, txids = RUNNER.strict_stdout_observation(
                transcript=transcript,
                components=[source, destination],
                source_cursor_stdout=None,
            )
            expected = root / "expected.json"
            identity = RUNNER.write_expected_acks(expected, txids)
            self.assertEqual(txids, ["tx-000001"])
            self.assertEqual(observation["ack_terminal_count"], 1)
            self.assertEqual(observation["stdout"], RUNNER.CONTRACT.file_identity(transcript))
            self.assertEqual(identity, RUNNER.CONTRACT.file_identity(expected))
            self.assertEqual(
                json.loads(expected.read_bytes()),
                {
                    "schema_version": "visa-sqlite-expected-acks-v1",
                    "initial_total_balance": 512000,
                    "acknowledged_txids": ["tx-000001"],
                },
            )

    def test_duplicate_or_invented_ack_is_rejected(self) -> None:
        for payload in (
            "VISA_ACK|tx-000001\nVISA_ACK|tx-000001\n",
            "VISA_ACK|tx-invented\n",
            "",
        ):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory(
                prefix="sqlite-runner-bad-ack-"
            ) as raw:
                root = Path(raw)
                output = root / "output"
                output.write_text(payload, encoding="utf-8")
                with self.assertRaises(RUNNER.MatrixFailure):
                    RUNNER.strict_stdout_observation(
                        transcript=root / "raw.stdout",
                        components=[output],
                        source_cursor_stdout=None,
                    )

    def test_cursor_requires_strict_prefix_and_exact_continuation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-runner-cursor-") as raw:
            root = Path(raw)
            setup = root / "setup.stdout"
            source = root / "source.stdout"
            destination = root / "destination.stdout"
            setup.write_text("delete\nVISA_ACK|tx-000001\n", encoding="utf-8")
            rows = [
                f"VISA_ROW|{account}|{999 if account <= 256 else 1001}\n"
                for account in range(1, RUNNER.CURSOR_ROWS + 1)
            ]
            source.write_text("".join(rows[:111]), encoding="utf-8")
            destination.write_text(
                "".join(rows[111:]) + "VISA_CURSOR_DONE|512\n",
                encoding="utf-8",
            )
            observation, _ = RUNNER.strict_stdout_observation(
                transcript=root / "raw.stdout",
                components=[setup, source, destination],
                source_cursor_stdout=source,
                expect_cursor=True,
            )
            self.assertEqual(observation["cursor_prefix_rows"], 111)
            self.assertEqual(observation["cursor_total_rows"], 512)
            self.assertEqual(observation["cursor_done_count"], 1)

    def test_cursor_rejects_duplicate_row_after_restore(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-runner-cursor-dup-") as raw:
            root = Path(raw)
            setup = root / "setup.stdout"
            source = root / "source.stdout"
            destination = root / "destination.stdout"
            setup.write_text("delete\nVISA_ACK|tx-000001\n", encoding="utf-8")
            source.write_text("VISA_ROW|1|999\n", encoding="utf-8")
            destination.write_text(
                "VISA_ROW|1|999\nVISA_CURSOR_DONE|512\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(RUNNER.MatrixFailure, "exact ordered result"):
                RUNNER.strict_stdout_observation(
                    transcript=root / "raw.stdout",
                    components=[setup, source, destination],
                    source_cursor_stdout=source,
                    expect_cursor=True,
                )

    def test_cursor_rejects_forged_terminal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-runner-cursor-terminal-") as raw:
            root = Path(raw)
            setup = root / "setup.stdout"
            cursor = root / "cursor.stdout"
            setup.write_text("delete\nVISA_ACK|tx-000001\n", encoding="utf-8")
            cursor.write_text(
                "".join(
                    f"VISA_ROW|{account}|{999 if account <= 256 else 1001}\n"
                    for account in range(1, RUNNER.CURSOR_ROWS + 1)
                )
                + "VISA_CURSOR_DONE|forged\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RUNNER.MatrixFailure, "exact ordered result"):
                RUNNER.strict_stdout_observation(
                    transcript=root / "raw.stdout",
                    components=[setup, cursor],
                    source_cursor_stdout=None,
                    expect_cursor=True,
                )

    def test_uninterrupted_cursor_projection_matches_oracle_row_encoding(self) -> None:
        rows = [
            (account, 999 if account <= 256 else 1001)
            for account in range(1, RUNNER.CURSOR_ROWS + 1)
        ]
        self.assertEqual(
            RUNNER.account_rows_sha256(rows),
            "af296aaf2dbda56ab9dfaae715f7c99e918c5eefc017bf2e96063a95484294b3",
        )
        with tempfile.TemporaryDirectory(prefix="sqlite-runner-control-") as raw:
            root = Path(raw)
            transaction = root / "transaction.stdout"
            cursor = root / "cursor.stdout"
            transaction.write_text(
                "delete\nVISA_ACK|tx-000001\n", encoding="utf-8"
            )
            cursor.write_text(
                "".join(
                    f"VISA_ROW|{account}|{balance}\n"
                    for account, balance in rows
                )
                + "VISA_CURSOR_DONE|512\n",
                encoding="utf-8",
            )
            observation, _ = RUNNER.strict_stdout_observation(
                transcript=root / "raw.stdout",
                components=[transaction, cursor],
                source_cursor_stdout=None,
                expect_cursor=True,
            )
        self.assertEqual(observation["cursor_prefix_rows"], 0)
        self.assertEqual(observation["cursor_total_rows"], RUNNER.CURSOR_ROWS)
        self.assertEqual(
            observation["cursor_rows_sha256"],
            "af296aaf2dbda56ab9dfaae715f7c99e918c5eefc017bf2e96063a95484294b3",
        )

    def test_equivalence_projection_requires_raw_oracle_agreement(self) -> None:
        oracle_projection = {
            "schema_version": RUNNER.ORACLE_PROJECTION_SCHEMA,
            "logical_contents": {
                "account_rows": RUNNER.CURSOR_ROWS,
                "accounts_sha256": "af" * 32,
                "transaction_rows": 1,
                "transactions_sha256": "be" * 32,
            },
            "integrity_ok": True,
            "foreign_keys_ok": True,
            "schema_accepted": True,
            "balance": {
                "expected_total": RUNNER.INITIAL_TOTAL_BALANCE,
                "observed_total": RUNNER.INITIAL_TOTAL_BALANCE,
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
        observation = {
            "acknowledged_txids": ["tx-000001"],
            "ack_terminal_count": 1,
            "cursor_total_rows": RUNNER.CURSOR_ROWS,
            "cursor_done_count": 1,
            "cursor_rows_sha256": "af" * 32,
        }
        projection = RUNNER.build_equivalence_projection(
            {"semantic_projection": oracle_projection}, observation
        )
        self.assertEqual(
            projection["logical_contents"]["accounts_sha256"], "af" * 32
        )
        observation["cursor_rows_sha256"] = "cd" * 32
        with self.assertRaisesRegex(RUNNER.MatrixFailure, "cursor rows differ"):
            RUNNER.build_equivalence_projection(
                {"semantic_projection": oracle_projection}, observation
            )

    def test_migration_intent_binds_three_distinct_clients(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sqlite-runner-intent-") as raw:
            path = Path(raw) / "intent.json"
            RUNNER.write_intent(
                path,
                session="01" * 16,
                owner="02" * 16,
                handoff="03" * 16,
                checkpoint_barrier="09" * 16,
                source_client="04" * 16,
                source_restore_client="05" * 16,
                destination_client="06" * 16,
                build_receipt={
                    "wanco_revision": "a" * 40,
                    "sqlite_version": "3.53.4",
                    "compiler": "clang-17",
                },
                runtime_sha256="07" * 32,
                source_lock_sha256="08" * 32,
            )
            intent = json.loads(path.read_bytes())
            clients = {
                intent["source_client_hex"],
                intent["source_restore_client_hex"],
                intent["destination_client_hex"],
            }
            self.assertEqual(len(clients), 3)
            self.assertEqual(intent["checkpoint_barrier_hex"], "09" * 16)

    def test_runner_contains_no_progress_counter_or_embedded_sql_trigger(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("bytes_written", source)
        self.assertNotIn("BEGIN IMMEDIATE;", source)
        self.assertIn("third_party/sqlite/source-lock.json", source)
        self.assertIn("partial-development-run-not-matrix-evidence", source)

    def test_source_abort_uses_one_real_driver_recovery_path(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("def qualify_driver_source_abort", source)
        self.assertNotIn("def qualify_real_wanco_source_abort", source)
        source_abort = source.split(
            "def qualify_source_abort_reconciliation(", maxsplit=1
        )[1].split("def absolute_from(", maxsplit=1)[0]
        self.assertIn('oracle.pop("_report_path")', source_abort)
        self.assertIn('"init-precommit"', source)
        self.assertEqual(
            len(
                re.findall(
                    r"driver_binary,\s*\n\s*\"authority-init\"",
                    source_abort,
                )
            ),
            2,
        )
        self.assertEqual(
            len(
                re.findall(
                    r"driver_binary,\s*\n\s*\"authority-commit\"",
                    source_abort,
                )
            ),
            1,
        )
        self.assertEqual(
            len(
                re.findall(
                    r"driver_binary,\s*\n\s*\"recover-abort\"",
                    source_abort,
                )
            ),
            3,
        )
        self.assertIn('"ownership_committed"', source)
        self.assertIn('"source_retained"', source)
        self.assertIn("authority-probe-record.json", source)
        self.assertIn("authority_probe_adapter_path", source)
        self.assertNotIn("write_new(authority_probe_binding", source)
        self.assertNotIn("write_new(authority_state_path", source)
        self.assertNotIn("publish(authority_state_path", source)
        self.assertEqual(source.count('"decision": "uncommitted"'), 1)
        self.assertIn('"resume_source_provider"', source)
        self.assertIn('"source_resumed"', source)


if __name__ == "__main__":
    unittest.main()
