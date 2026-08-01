#!/usr/bin/env python3
"""Schema and validator for bounded stock-application baseline receipts.

The baseline receipt is intentionally separate from the semantic matrix
receipts.  It records measured process and lifecycle intervals, artifact
identities, and oracle outcomes.  A negative arm is never eligible for a
throughput comparison merely because its failure was detected quickly.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Mapping, Sequence


SCHEMA = "visa-stock-application-baseline-v1"
CLOCK = "python-time.monotonic_ns"
RUNS_PER_ARM = 10
POSITIVE_ARMS = {"uninterrupted-control", "fresh-process-restart", "visa-plus-wanco"}
NEGATIVE_ARMS = {"wanco-carrier-only", "naive-raw-resource-reopen"}
ARMS = POSITIVE_ARMS | NEGATIVE_ARMS
ZSTD_CUTS = ("write-occurrence-64",)
SQLITE_CUTS = (
    "post-journal-sync",
    "journal-delete-commit-point",
    "active-read-cursor",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


class BaselineError(RuntimeError):
    """A baseline receipt is malformed or overclaims its observation."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def fail(message: str) -> None:
    raise BaselineError(message)


def require_object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_identity(value: object, label: str, *, allow_zero: bool = False) -> None:
    identity = require_object(value, label)
    if set(identity) != {"sha256", "size"}:
        fail(f"{label} must contain only sha256 and size")
    digest = identity["sha256"]
    size = identity["size"]
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        fail(f"{label}.sha256 is not a canonical SHA-256")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or (size == 0 and not allow_zero)
    ):
        fail(f"{label}.size is invalid")


def require_interval(value: object, label: str) -> None:
    interval = require_object(value, label)
    if set(interval) != {"start_monotonic_ns", "end_monotonic_ns", "duration_ns"}:
        fail(f"{label} has unexpected fields")
    start = interval["start_monotonic_ns"]
    end = interval["end_monotonic_ns"]
    duration = interval["duration_ns"]
    if not all(
        isinstance(item, int) and not isinstance(item, bool)
        for item in (start, end, duration)
    ):
        fail(f"{label} is not an integer interval")
    if start < 0 or end <= start or duration != end - start:
        fail(f"{label} is not a positive monotonic interval")


def require_timing(value: object, label: str) -> None:
    timing = require_object(value, label)
    if set(timing) != {"clock", "interval", "interval_kind", "phases"}:
        fail(f"{label} has unexpected fields")
    if timing["clock"] != CLOCK:
        fail(f"{label} uses an unsupported clock")
    if not isinstance(timing["interval_kind"], str) or not timing["interval_kind"]:
        fail(f"{label}.interval_kind is empty")
    require_interval(timing["interval"], f"{label}.interval")
    phases = timing["phases"]
    if not isinstance(phases, list) or not phases:
        fail(f"{label}.phases is empty")
    for index, phase_value in enumerate(phases):
        phase = require_object(phase_value, f"{label}.phases[{index}]")
        if set(phase) != {
            "role",
            "start_monotonic_ns",
            "end_monotonic_ns",
            "duration_ns",
            "exit_status",
        }:
            fail(f"{label}.phases[{index}] has unexpected fields")
        require_interval(
            {
                "start_monotonic_ns": phase["start_monotonic_ns"],
                "end_monotonic_ns": phase["end_monotonic_ns"],
                "duration_ns": phase["duration_ns"],
            },
            f"{label}.phases[{index}]",
        )
        if not isinstance(phase["role"], str) or not phase["role"]:
            fail(f"{label}.phases[{index}].role is empty")
        status = phase["exit_status"]
        if not isinstance(status, int) or isinstance(status, bool) or status < 0:
            fail(f"{label}.phases[{index}].exit_status is invalid")


def require_workload_metrics(value: object, workload: str, label: str) -> None:
    metrics = require_object(value, label)
    if workload == "zstd":
        if set(metrics) != {
            "kind",
            "input_sha256",
            "compressed_sha256",
            "native_decompression_accepted",
            "application_elapsed_ns",
            "throughput_bytes_per_second",
            "source_quiesce_ns",
            "compute_checkpoint_ns",
        }:
            fail(f"{label} has unexpected zstd fields")
        if metrics["kind"] != "zstd" or metrics["native_decompression_accepted"] is not True:
            fail(f"{label} does not bind an accepted native-zstd oracle")
        for name in ("input_sha256", "compressed_sha256"):
            digest = metrics[name]
            if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                fail(f"{label}.{name} is invalid")
        for name in ("application_elapsed_ns", "throughput_bytes_per_second"):
            item = metrics[name]
            if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
                fail(f"{label}.{name} is invalid")
        for name in ("source_quiesce_ns", "compute_checkpoint_ns"):
            item = metrics[name]
            if not isinstance(item, int) or isinstance(item, bool) or item < 0:
                fail(f"{label}.{name} is invalid")
        return
    if set(metrics) != {
        "kind",
        "ack_count",
        "integrity_ok",
        "foreign_keys_ok",
        "account_rows",
        "transaction_rows",
        "accounts_sha256",
        "transactions_sha256",
        "unique_txids",
    }:
        fail(f"{label} has unexpected SQLite fields")
    if (
        metrics["kind"] != "sqlite"
        or metrics["integrity_ok"] is not True
        or metrics["foreign_keys_ok"] is not True
        or metrics["unique_txids"] is not True
    ):
        fail(f"{label} does not bind accepted SQLite invariants")
    for name in ("ack_count", "account_rows", "transaction_rows"):
        item = metrics[name]
        if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
            fail(f"{label}.{name} is invalid")
    for name in ("accounts_sha256", "transactions_sha256"):
        digest = metrics[name]
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            fail(f"{label}.{name} is invalid")


def require_sample(value: object, index: int) -> tuple[str, int, str | None, str]:
    sample = require_object(value, f"samples[{index}]")
    expected_fields = {
        "workload",
        "fixture",
        "cut",
        "arm",
        "expectation",
        "outcome",
        "throughput_eligible",
        "process",
        "timing",
        "sizes",
        "oracle",
        "detector",
        "workload_metrics",
    }
    if set(sample) - expected_fields - {"reason"}:
        fail(f"samples[{index}] has unexpected fields")
    workload = sample["workload"]
    fixture = sample["fixture"]
    cut = sample["cut"]
    arm = sample["arm"]
    if workload not in {"zstd", "sqlite"}:
        fail(f"samples[{index}].workload is unsupported")
    if not isinstance(fixture, int) or isinstance(fixture, bool) or not 1 <= fixture <= RUNS_PER_ARM:
        fail(f"samples[{index}].fixture is outside 1..{RUNS_PER_ARM}")
    if cut is not None and (not isinstance(cut, str) or not cut):
        fail(f"samples[{index}].cut is invalid")
    if arm not in ARMS:
        fail(f"samples[{index}].arm is unsupported")
    if arm in {"uninterrupted-control", "fresh-process-restart"}:
        if cut is not None:
            fail(f"samples[{index}] control/restart arm must not name a cut")
    else:
        allowed = ZSTD_CUTS if workload == "zstd" else SQLITE_CUTS
        if cut not in allowed:
            fail(f"samples[{index}] has an unsupported {workload} cut")

    process = require_object(sample["process"], f"samples[{index}].process")
    if set(process) != {"exit_status", "stdout", "stderr"}:
        fail(f"samples[{index}].process has unexpected fields")
    status = process["exit_status"]
    if not isinstance(status, int) or isinstance(status, bool) or status < 0:
        fail(f"samples[{index}].process.exit_status is invalid")
    require_identity(process["stdout"], f"samples[{index}].process.stdout", allow_zero=True)
    require_identity(process["stderr"], f"samples[{index}].process.stderr", allow_zero=True)
    require_timing(sample["timing"], f"samples[{index}].timing")

    sizes = require_object(sample["sizes"], f"samples[{index}].sizes")
    if set(sizes) != {
        "input_bytes",
        "output_bytes",
        "checkpoint_bytes",
        "resource_state_bytes",
    }:
        fail(f"samples[{index}].sizes has unexpected fields")
    for name, item in sizes.items():
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            fail(f"samples[{index}].sizes.{name} is invalid")

    oracle = require_object(sample["oracle"], f"samples[{index}].oracle")
    if set(oracle) != {"kind", "accepted", "observation_sha256"}:
        fail(f"samples[{index}].oracle has unexpected fields")
    if not isinstance(oracle["kind"], str) or not oracle["kind"]:
        fail(f"samples[{index}].oracle.kind is empty")
    if not isinstance(oracle["accepted"], bool):
        fail(f"samples[{index}].oracle.accepted is not boolean")
    observation = oracle["observation_sha256"]
    if observation is not None and (
        not isinstance(observation, str) or SHA256_RE.fullmatch(observation) is None
    ):
        fail(f"samples[{index}].oracle.observation_sha256 is invalid")

    detector = sample["detector"]
    reason = sample.get("reason")
    if reason is not None and (not isinstance(reason, str) or not reason):
        fail(f"samples[{index}].reason is invalid")
    if arm in POSITIVE_ARMS:
        if (
            sample["expectation"] != "observable-equivalence"
            or sample["outcome"] != "equivalent"
            or sample["throughput_eligible"] is not True
            or status != 0
            or oracle["accepted"] is not True
            or detector is not None
            or reason is not None
            or "workload_metrics" not in sample
        ):
            fail(f"samples[{index}] positive arm is not an accepted equivalence")
        require_workload_metrics(
            sample["workload_metrics"], str(workload), f"samples[{index}].workload_metrics"
        )
        if workload == "zstd":
            metrics = sample["workload_metrics"]
            input_bytes = sample["sizes"]["input_bytes"]
            elapsed_ns = metrics["application_elapsed_ns"]
            if metrics["throughput_bytes_per_second"] != (
                input_bytes * 1_000_000_000 // elapsed_ns
            ):
                fail(f"samples[{index}] zstd throughput is not derived from elapsed time")
            if arm in {"uninterrupted-control", "fresh-process-restart"}:
                phase_elapsed_ns = sum(
                    phase["duration_ns"] for phase in sample["timing"]["phases"]
                )
                if elapsed_ns != phase_elapsed_ns:
                    fail(
                        f"samples[{index}] zstd application timing and workload metrics differ"
                    )
    elif sample["expectation"] == "unsupported":
        if (
            arm not in NEGATIVE_ARMS
            or sample["outcome"] != "unsupported"
            or sample["throughput_eligible"] is not False
            or oracle["accepted"] is not False
            or not isinstance(detector, str)
            or not detector
            or not isinstance(reason, str)
            or not reason
            or status != 125
        ):
            fail(f"samples[{index}] unsupported arm lacks an explicit capability reason")
    else:
        if "workload_metrics" in sample:
            fail(f"samples[{index}] negative arm must not publish positive metrics")
        if (
            sample["expectation"] != "negative-control"
            or sample["outcome"] not in {"rejected", "diverged"}
            or sample["throughput_eligible"] is not False
            or oracle["accepted"] is not False
            or not isinstance(detector, str)
            or not detector
        ):
            fail(f"samples[{index}] negative arm is not a detected negative control")
        if sample["outcome"] == "rejected" and status == 0:
            fail(f"samples[{index}] rejected arm exited successfully")
        if sample["outcome"] == "diverged" and status != 0:
            fail(f"samples[{index}] diverged arm did not complete")
    return str(workload), fixture, cut if isinstance(cut, str) else None, str(arm)


def expected_keys() -> set[tuple[str, int, str | None, str]]:
    keys: set[tuple[str, int, str | None, str]] = set()
    for workload in ("zstd", "sqlite"):
        cuts: Sequence[str] = ZSTD_CUTS if workload == "zstd" else SQLITE_CUTS
        for fixture in range(1, RUNS_PER_ARM + 1):
            keys.add((workload, fixture, None, "uninterrupted-control"))
            keys.add((workload, fixture, None, "fresh-process-restart"))
            for cut in cuts:
                for arm in (
                    "wanco-carrier-only",
                    "naive-raw-resource-reopen",
                    "visa-plus-wanco",
                ):
                    keys.add((workload, fixture, cut, arm))
    return keys


def validate_receipt(document: object) -> Mapping[str, object]:
    receipt = require_object(document, "receipt")
    if set(receipt) != {
        "schema",
        "repository_revision",
        "runs_per_arm",
        "sampling",
        "execution_inputs",
        "samples",
        "scope",
    }:
        fail("receipt has unexpected fields")
    if receipt["schema"] != SCHEMA:
        fail("unsupported baseline schema")
    revision = receipt["repository_revision"]
    if not isinstance(revision, str) or SHA40_RE.fullmatch(revision) is None:
        fail("repository_revision is not a full lowercase Git SHA")
    if receipt["runs_per_arm"] != RUNS_PER_ARM:
        fail(f"runs_per_arm must be exactly {RUNS_PER_ARM}")
    sampling = require_object(receipt["sampling"], "sampling")
    if sampling != {
        "zstd": {"cuts": list(ZSTD_CUTS), "fixtures": RUNS_PER_ARM},
        "sqlite": {"cuts": list(SQLITE_CUTS), "fixtures": RUNS_PER_ARM},
    }:
        fail("sampling does not match the bounded baseline design")

    execution_inputs = require_object(receipt["execution_inputs"], "execution_inputs")
    if not execution_inputs:
        fail("execution_inputs is empty")
    for name, identity in execution_inputs.items():
        if not isinstance(name, str) or not name:
            fail("execution_inputs contains an empty name")
        require_identity(identity, f"execution_inputs.{name}")

    samples = receipt["samples"]
    if not isinstance(samples, list):
        fail("samples must be a list")
    observed: set[tuple[str, int, str | None, str]] = set()
    for index, sample in enumerate(samples):
        key = require_sample(sample, index)
        if key in observed:
            fail(f"duplicate baseline sample {key}")
        observed.add(key)
    expected = expected_keys()
    if observed != expected:
        missing = sorted(expected - observed, key=str)
        extra = sorted(observed - expected, key=str)
        fail(f"baseline sample inventory differs; missing={missing[:3]} extra={extra[:3]}")

    scope = require_object(receipt["scope"], "scope")
    if scope != {
        "same_host_x86_64": True,
        "cross_host": False,
        "power_loss": False,
        "third_party_migration_baseline": False,
        "negative_arms_are_throughput_baselines": False,
        "fresh_process_restart_is_checkpoint_restore": False,
    }:
        fail("scope boundary is missing or overclaimed")
    return receipt


def load_and_validate(path: Path) -> Mapping[str, object]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BaselineError(f"cannot read baseline receipt: {error}") from error
    if raw != canonical_bytes(value) + b"\n":
        fail("baseline receipt is not canonical JSON")
    return validate_receipt(value)
