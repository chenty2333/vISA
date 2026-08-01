#!/usr/bin/env python3
"""Focused contract tests for the stock-application baseline receipt."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "visa_stock_application_baseline", ROOT / "stock_application_baseline.py"
)
assert SPEC is not None and SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CONTRACT
sys.modules["stock_application_baseline"] = CONTRACT
SPEC.loader.exec_module(CONTRACT)

RUNNER_SPEC = importlib.util.spec_from_file_location(
    "visa_stock_application_baseline_runner", ROOT / "run-stock-application-baseline.py"
)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
sys.modules[RUNNER_SPEC.name] = RUNNER
RUNNER_SPEC.loader.exec_module(RUNNER)


def identity(size: int = 1) -> dict[str, object]:
    return {"sha256": "0" * 63 + "1", "size": size}


def timing(status: int = 0) -> dict[str, object]:
    return {
        "clock": CONTRACT.CLOCK,
        "interval": {"start_monotonic_ns": 1, "end_monotonic_ns": 2, "duration_ns": 1},
        "interval_kind": "test",
        "phases": [{
            "role": "test",
            "start_monotonic_ns": 1,
            "end_monotonic_ns": 2,
            "duration_ns": 1,
            "exit_status": status,
        }],
    }


def sample(workload: str, fixture: int, cut: str | None, arm: str) -> dict[str, object]:
    if arm in CONTRACT.POSITIVE_ARMS:
        workload_metrics: dict[str, object]
        if workload == "zstd":
            workload_metrics = {
                "kind": "zstd",
                "input_sha256": "1" * 64,
                "compressed_sha256": "2" * 64,
                "native_decompression_accepted": True,
                "application_elapsed_ns": 1,
                "throughput_bytes_per_second": 1_000_000_000,
                "source_quiesce_ns": 0,
                "compute_checkpoint_ns": 0,
            }
        else:
            workload_metrics = {
                "kind": "sqlite",
                "ack_count": 1,
                "integrity_ok": True,
                "foreign_keys_ok": True,
                "account_rows": 1,
                "transaction_rows": 1,
                "accounts_sha256": "3" * 64,
                "transactions_sha256": "4" * 64,
                "unique_txids": True,
            }
        return {
            "workload": workload,
            "fixture": fixture,
            "cut": cut,
            "arm": arm,
            "expectation": "observable-equivalence",
            "outcome": "equivalent",
            "throughput_eligible": True,
            "process": {"exit_status": 0, "stdout": identity(), "stderr": identity()},
            "timing": timing(),
            "sizes": {
                "input_bytes": 1,
                "output_bytes": 1,
                "checkpoint_bytes": 1,
                "resource_state_bytes": 1,
            },
            "oracle": {"kind": "test", "accepted": True, "observation_sha256": "0" * 64},
            "detector": None,
            "workload_metrics": workload_metrics,
        }
    return RUNNER.negative_sample(
        workload=workload,
        fixture=fixture,
        cut=cut or "test-cut",
        arm=arm,
        completed=subprocess.CompletedProcess(
            ["negative-control"], 1, stdout=b"", stderr=b"detected"
        ),
        start_ns=1,
        end_ns=2,
        detector="test-semantic-divergence",
        oracle_kind="test-negative-oracle",
        oracle_observation={"accepted": False},
        input_bytes=1,
        output_bytes=1,
        checkpoint_bytes=1,
        resource_state_bytes=1,
    )


def receipt() -> dict[str, object]:
    samples: list[dict[str, object]] = []
    for workload in ("zstd", "sqlite"):
        cuts = CONTRACT.ZSTD_CUTS if workload == "zstd" else CONTRACT.SQLITE_CUTS
        for fixture in range(1, CONTRACT.RUNS_PER_ARM + 1):
            samples.append(sample(workload, fixture, None, "uninterrupted-control"))
            samples.append(sample(workload, fixture, None, "fresh-process-restart"))
            for cut in cuts:
                for arm in ("wanco-carrier-only", "naive-raw-resource-reopen", "visa-plus-wanco"):
                    samples.append(sample(workload, fixture, cut, arm))
    return {
        "schema": CONTRACT.SCHEMA,
        "repository_revision": "a" * 40,
        "runs_per_arm": CONTRACT.RUNS_PER_ARM,
        "sampling": {
            "zstd": {"cuts": list(CONTRACT.ZSTD_CUTS), "fixtures": CONTRACT.RUNS_PER_ARM},
            "sqlite": {"cuts": list(CONTRACT.SQLITE_CUTS), "fixtures": CONTRACT.RUNS_PER_ARM},
        },
        "execution_inputs": {"runner": identity()},
        "samples": samples,
        "scope": {
            "same_host_x86_64": True,
            "cross_host": False,
            "power_loss": False,
            "third_party_migration_baseline": False,
            "negative_arms_are_throughput_baselines": False,
            "fresh_process_restart_is_checkpoint_restore": False,
        },
    }


class StockApplicationBaselineTests(unittest.TestCase):
    def test_canonical_inventory_validates(self) -> None:
        value = receipt()
        self.assertEqual(CONTRACT.validate_receipt(value), value)
        self.assertEqual(len(value["samples"]), 160)

    def test_missing_arm_is_rejected(self) -> None:
        value = receipt()
        value["samples"].pop()
        with self.assertRaises(CONTRACT.BaselineError):
            CONTRACT.validate_receipt(value)

    def test_duplicate_sample_is_rejected(self) -> None:
        value = receipt()
        value["samples"].append(copy.deepcopy(value["samples"][0]))
        with self.assertRaises(CONTRACT.BaselineError):
            CONTRACT.validate_receipt(value)

    def test_negative_arm_requires_a_detector(self) -> None:
        value = receipt()
        candidate = next(item for item in value["samples"] if item["arm"] == "wanco-carrier-only")
        candidate["detector"] = None
        with self.assertRaises(CONTRACT.BaselineError):
            CONTRACT.validate_receipt(value)

    def test_negative_arm_cannot_be_throughput_eligible(self) -> None:
        value = receipt()
        candidate = next(item for item in value["samples"] if item["arm"] == "naive-raw-resource-reopen")
        candidate["throughput_eligible"] = True
        with self.assertRaises(CONTRACT.BaselineError):
            CONTRACT.validate_receipt(value)

    def test_positive_arm_requires_workload_metrics(self) -> None:
        value = receipt()
        candidate = next(
            item
            for item in value["samples"]
            if item["workload"] == "sqlite" and item["arm"] == "visa-plus-wanco"
        )
        candidate.pop("workload_metrics")
        with self.assertRaises(CONTRACT.BaselineError):
            CONTRACT.validate_receipt(value)

    def test_zstd_control_rejects_placeholder_timing(self) -> None:
        value = receipt()
        candidate = next(
            item
            for item in value["samples"]
            if item["workload"] == "zstd"
            and item["arm"] == "uninterrupted-control"
        )
        candidate["workload_metrics"]["application_elapsed_ns"] = 2
        candidate["workload_metrics"]["throughput_bytes_per_second"] = 500_000_000
        with self.assertRaises(CONTRACT.BaselineError):
            CONTRACT.validate_receipt(value)

    def test_zstd_outer_fixture_identity_overrides_runner_local_fixture(self) -> None:
        control = sample("zstd", 1, None, "uninterrupted-control")
        restart = sample("zstd", 1, None, "fresh-process-restart")
        observations = [
            restart,
            sample("zstd", 1, "write-occurrence-64", "wanco-carrier-only"),
            sample(
                "zstd",
                1,
                "write-occurrence-64",
                "naive-raw-resource-reopen",
            ),
            sample("zstd", 1, "write-occurrence-64", "visa-plus-wanco"),
        ]
        samples = RUNNER.zstd_sample_from_observation(
            {
                "control": control,
                "restart": restart,
                "observations": observations,
            },
            fixture=2,
            root=ROOT,
        )
        self.assertEqual(len(samples), 5)
        self.assertEqual({item["fixture"] for item in samples}, {2})
        self.assertEqual(
            {item["arm"] for item in samples},
            CONTRACT.ARMS,
        )

    def test_noncanonical_json_is_rejected(self) -> None:
        path = ROOT / ".test-stock-baseline.json"
        try:
            path.write_text(json.dumps(receipt(), indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(CONTRACT.BaselineError):
                CONTRACT.load_and_validate(path)
        finally:
            path.unlink(missing_ok=True)

    def test_empty_stdout_is_valid_for_a_rejected_negative_arm(self) -> None:
        value = receipt()
        CONTRACT.validate_receipt(value)

    def test_exact_destination_reproduction_is_not_a_negative_control(self) -> None:
        completed = subprocess.CompletedProcess(
            ["control"], 0, stdout=b"same", stderr=b""
        )
        with self.assertRaises(RuntimeError):
            RUNNER.require_detected_divergence(
                completed=completed,
                expected_destination_stdout=b"same",
                label="test-control",
            )

    def test_matching_stdout_with_divergent_resources_is_detected(self) -> None:
        completed = subprocess.CompletedProcess(
            ["control"], 0, stdout=b"same", stderr=b""
        )
        self.assertEqual(
            RUNNER.require_detected_divergence(
                completed=completed,
                expected_destination_stdout=b"same",
                label="test-control",
                resource_equivalent=False,
            ),
            ("diverged", "test-control-resource-state-diverged"),
        )


if __name__ == "__main__":
    unittest.main()
