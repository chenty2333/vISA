#!/usr/bin/env python3
"""Run the bounded five-arm stock-application baseline study.

This driver is independent of the semantic matrix receipts.  It invokes the
real stock-zstd and stock-SQLite runners in fresh private roots, retains the
runner hashes and raw observations, and emits only timing/size/oracle records.
Every canonical arm is a real execution; negative controls are never promoted
to throughput points merely because they reject quickly.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping

import stock_application_baseline as CONTRACT


ROOT = Path(__file__).resolve().parents[1]
RUN_REPOSITORY = ROOT
ZSTD_RUNNER = ROOT / "scripts/run-stock-zstd-migration-matrix.py"
SQLITE_RUNNER = ROOT / "scripts/run-stock-sqlite-rollback-matrix.py"
PAPER_REPOSITORY = ROOT.parent / "vISA-paper"
DEFAULT_ZSTD_ARTIFACT = ROOT / "target/final-stock-zstd-build"
DEFAULT_SQLITE_ARTIFACT = ROOT / "target/final-stock-sqlite-build"
DEFAULT_TYPED_CORPUS = PAPER_REPOSITORY / "artifact-data/apps-8a6d8533/stock-sqlite/wanco-typed-corpus/receipt.json"
DEFAULT_WANCO_RECEIPT = ROOT / "target/.ci-cache/wanco-carrier/build-receipt.json"
DEFAULT_SQLITE_ORACLE = ROOT / "target/debug/visa-sqlite-oracle"
DEFAULT_NATIVE_SQLITE = Path("/usr/bin/sqlite3")


def canonical(value: object) -> bytes:
    return CONTRACT.canonical_bytes(value)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def identity(path: Path, *, allow_empty: bool = False) -> dict[str, object]:
    payload = path.read_bytes()
    if not payload and not allow_empty:
        raise RuntimeError(f"empty artifact is not allowed: {path}")
    return {"sha256": sha256_bytes(payload), "size": len(payload)}


def run(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=None if env is None else dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load runner module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def timing_from_file(path: Path, *, interval_kind: str) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    phases = document.get("phases") if isinstance(document, dict) else None
    if not isinstance(phases, list) or not phases:
        raise RuntimeError(f"timing receipt has no phases: {path}")
    normalized: list[dict[str, object]] = []
    for phase in phases:
        if not isinstance(phase, dict):
            raise RuntimeError(f"timing phase is malformed: {path}")
        normalized.append({
            "role": phase["role"],
            "start_monotonic_ns": int(phase["start_monotonic_ns"]),
            "end_monotonic_ns": int(phase["end_monotonic_ns"]),
            "duration_ns": int(phase["duration_ns"]),
            "exit_status": int(phase["exit_status"]),
        })
    start = min(int(item["start_monotonic_ns"]) for item in normalized)
    end = max(int(item["end_monotonic_ns"]) for item in normalized)
    return {
        "clock": CONTRACT.CLOCK,
        "interval": {
            "start_monotonic_ns": start,
            "end_monotonic_ns": end,
            "duration_ns": end - start,
        },
        "interval_kind": interval_kind,
        "phases": normalized,
    }


def process_from_runs(
    runs: list[Mapping[str, object]], *, root: Path
) -> dict[str, object]:
    stdout = bytearray()
    stderr = bytearray()
    status = 0
    for run_value in runs:
        status = max(status, int(run_value["exit_status"]))
        for stream, target in (("stdout", stdout), ("stderr", stderr)):
            reference = run_value.get(stream)
            if not isinstance(reference, dict):
                raise RuntimeError("runner application run omitted a stream reference")
            path = root / str(reference["path"])
            target.extend(path.read_bytes())
    return {
        "exit_status": status,
        "stdout": {"sha256": sha256_bytes(bytes(stdout)), "size": len(stdout)},
        "stderr": {"sha256": sha256_bytes(bytes(stderr)), "size": len(stderr)},
    }


def timing_interval(start: int, end: int) -> dict[str, int]:
    if start < 0 or end <= start:
        raise RuntimeError("baseline timing interval is not positive")
    return {
        "start_monotonic_ns": start,
        "end_monotonic_ns": end,
        "duration_ns": end - start,
    }


def negative_sample(
    *,
    workload: str,
    fixture: int,
    cut: str,
    arm: str,
    completed: subprocess.CompletedProcess[bytes],
    start_ns: int,
    end_ns: int,
    detector: str,
    oracle_kind: str,
    oracle_observation: Mapping[str, object],
    input_bytes: int,
    output_bytes: int,
    checkpoint_bytes: int,
    resource_state_bytes: int,
) -> dict[str, object]:
    return {
        "workload": workload,
        "fixture": fixture,
        "cut": cut,
        "arm": arm,
        "expectation": "negative-control",
        "outcome": "diverged" if completed.returncode == 0 else "rejected",
        "throughput_eligible": False,
        "process": {
            "exit_status": completed.returncode,
            "stdout": {
                "sha256": sha256_bytes(completed.stdout),
                "size": len(completed.stdout),
            },
            "stderr": {
                "sha256": sha256_bytes(completed.stderr),
                "size": len(completed.stderr),
            },
        },
        "timing": {
            "clock": CONTRACT.CLOCK,
            "interval": timing_interval(start_ns, end_ns),
            "interval_kind": "negative-control-execution",
            "phases": [{
                "role": arm,
                **timing_interval(start_ns, end_ns),
                "exit_status": completed.returncode,
            }],
        },
        "sizes": {
            "input_bytes": input_bytes,
            "output_bytes": output_bytes,
            "checkpoint_bytes": checkpoint_bytes,
            "resource_state_bytes": resource_state_bytes,
        },
        "oracle": {
            "kind": oracle_kind,
            "accepted": False,
            "observation_sha256": sha256_bytes(canonical(dict(oracle_observation))),
        },
        "detector": detector,
        "reason": None,
    }


def tree_size(root: Path) -> int:
    return sum(
        path.stat().st_size
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def sqlite_artifact_runtime(
    sqlite_runner: Any,
    *,
    artifact_root: Path,
    socket_root: Path,
    docker: str,
) -> Any:
    build_receipt = json.loads(
        (artifact_root / "receipt.json").read_text(encoding="utf-8")
    )
    artifacts = build_receipt.get("artifacts")
    if not isinstance(artifacts, dict):
        raise RuntimeError("SQLite build receipt omitted its artifact inventory")
    candidates = [name for name in artifacts if name.endswith("-wanco-o1")]
    if len(candidates) != 1:
        raise RuntimeError("SQLite build receipt does not bind exactly one Wanco AOT")
    image = build_receipt.get("wanco_image")
    if not isinstance(image, str) or not image:
        raise RuntimeError("SQLite build receipt omitted its Wanco image")
    executable = artifact_root / candidates[0]
    expected = artifacts[candidates[0]]
    if identity(executable) != expected:
        raise RuntimeError("SQLite Wanco AOT differs from its build receipt")
    return sqlite_runner.DockerAot(
        docker, image, executable, socket_root=socket_root
    )


def sqlite_run_stream(
    receipt: Mapping[str, object], root: Path, cut: str, role: str
) -> bytes:
    cell = next(item for item in receipt["cells"] if item["cell_id"] == cut)
    runs = cell["retained_raw_evidence"]["application_runs"]
    entry = next(item for item in runs if item["role"] == role)
    return (root / str(entry["stdout"]["path"])).read_bytes()


def require_detected_divergence(
    *,
    completed: subprocess.CompletedProcess[bytes],
    expected_destination_stdout: bytes,
    label: str,
    resource_equivalent: bool = True,
) -> tuple[str, str]:
    if completed.returncode != 0:
        return "rejected", f"{label}-rejected"
    if completed.stdout != expected_destination_stdout:
        return "diverged", f"{label}-lost-compute-continuation"
    if not resource_equivalent:
        return "diverged", f"{label}-resource-state-diverged"
    raise RuntimeError(
        f"{label} unexpectedly reproduced both the destination continuation "
        "and final resource semantics"
    )


def run_sqlite_carrier_only(
    *,
    sqlite_runner: Any,
    fixture: int,
    cut: str,
    output_root: Path,
    receipt: Mapping[str, object],
    sqlite_artifact: Path,
    oracle_binary: Path,
    docker: str,
) -> dict[str, object]:
    case = output_root / "controls" / cut / "wanco-carrier-only"
    case.mkdir(mode=0o700, parents=True)
    checkpoint = output_root / "work" / "cells" / cut / "source" / "checkpoint.pb"
    if not checkpoint.is_file() or checkpoint.stat().st_size == 0:
        raise RuntimeError(f"SQLite source checkpoint is missing for {cut}")
    source_stdout = sqlite_run_stream(receipt, output_root, cut, "source")
    destination_stdout = sqlite_run_stream(receipt, output_root, cut, "destination")
    imports = {
        sqlite_runner.SEED_GUEST_PATH: RUN_REPOSITORY / "third_party/sqlite/workload/seed.sql",
        sqlite_runner.TRANSACTION_GUEST_PATH: RUN_REPOSITORY / "third_party/sqlite/workload/transaction.sql",
        sqlite_runner.CURSOR_GUEST_PATH: RUN_REPOSITORY / "third_party/sqlite/workload/cursor.sql",
    }
    session = sqlite_runner.stable_id(cut + "-session")
    owner = sqlite_runner.stable_id(cut + "-owner")
    client = sqlite_runner.stable_id(cut + "-carrier-only-client")
    admin = os.urandom(32).hex()
    guest = os.urandom(32).hex()
    database = case / "provider" / "state.sqlite"
    script_path = (
        sqlite_runner.CURSOR_GUEST_PATH
        if cut == "active-read-cursor"
        else sqlite_runner.TRANSACTION_GUEST_PATH
    )
    with sqlite_runner.ShortSocketRoot() as sockets:
        socket_path = sockets.allocate()
        sqlite_runner.create_provider(
            RUN_REPOSITORY / "target/debug/visa_wasi_host",
            database,
            session=session,
            admin_capability=admin,
            guest_capability=guest,
            epoch=2,
            imports=imports,
            cwd=case,
        )
        runtime = sqlite_artifact_runtime(
            sqlite_runner,
            artifact_root=sqlite_artifact,
            socket_root=sockets.path,
            docker=docker,
        )
        with sqlite_runner.Provider(
            RUN_REPOSITORY / "target/debug/visa_wasi_host",
            database,
            socket_path,
            admin,
            case,
        ) as provider:
            status_before = sqlite_runner.CONTRACT.status_projection(provider.status())
            _, command = runtime.build_command(
                case_root=output_root,
                cwd=case,
                environment=sqlite_runner.guest_environment(
                    socket_path,
                    session=session,
                    owner=owner,
                    client=client,
                    guest_capability=guest,
                    epoch=2,
                ),
                label=f"carrier-only-{fixture}-{cut}",
                script_path=script_path,
                checkpoint=checkpoint,
            )
            start_ns = time.monotonic_ns()
            completed = run(command, cwd=case, timeout=300)
            end_ns = time.monotonic_ns()
            status_after = sqlite_runner.CONTRACT.status_projection(provider.status())
            snapshot_client = sqlite_runner.stable_id(
                f"{cut}-carrier-only-snapshot-client"
            )
            fresh_namespace = sqlite_runner.snapshot_namespace(
                runtime,
                case_root=output_root,
                destination=case,
                provider=provider,
                environment=sqlite_runner.guest_environment(
                    socket_path,
                    session=session,
                    owner=owner,
                    client=snapshot_client,
                    guest_capability=guest,
                    epoch=2,
                ),
                cell_id=f"baseline-carrier-{fixture}-{cut}",
            )
            fresh_snapshot = fresh_namespace.pop("path")
    cell = next(item for item in receipt["cells"] if item["cell_id"] == cut)
    expected_reference = cell["retained_raw_evidence"]["expected_acknowledgements"]
    expected_acks = output_root / str(expected_reference["path"])
    resource_oracle = run(
        [
            str(oracle_binary),
            str(fresh_snapshot),
            str(expected_acks),
            sqlite_runner.DATABASE_PATH,
        ],
        cwd=case,
        timeout=300,
    )
    fresh_projection: Mapping[str, object] | None = None
    resource_equivalent = False
    if resource_oracle.returncode == 0:
        try:
            fresh_report = json.loads(resource_oracle.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("fresh-provider SQLite oracle returned invalid JSON") from error
        fresh_projection = sqlite_runner.native_oracle_semantic_projection(fresh_report)
        resource_equivalent = (
            fresh_projection == cell["external_oracle"]["semantic_projection"]
        )
    _, detector = require_detected_divergence(
        completed=completed,
        expected_destination_stdout=destination_stdout,
        label="fresh-provider-carrier-restore",
        resource_equivalent=resource_equivalent,
    )
    observation = {
        "schema": "visa-sqlite-negative-control-observation-v1",
        "arm": "wanco-carrier-only",
        "cut": cut,
        "source_checkpoint": identity(checkpoint),
        "fresh_provider_status_before": status_before,
        "fresh_provider_status_after": status_after,
        "fresh_provider_namespace": identity(fresh_snapshot),
        "fresh_provider_snapshot_gate": fresh_namespace,
        "fresh_provider_oracle": {
            "exit_status": resource_oracle.returncode,
            "stdout": {
                "sha256": sha256_bytes(resource_oracle.stdout),
                "size": len(resource_oracle.stdout),
            },
            "stderr": {
                "sha256": sha256_bytes(resource_oracle.stderr),
                "size": len(resource_oracle.stderr),
            },
            "semantic_projection": fresh_projection,
        },
        "source_stdout": {"sha256": sha256_bytes(source_stdout), "size": len(source_stdout)},
        "expected_destination_stdout": {
            "sha256": sha256_bytes(destination_stdout),
            "size": len(destination_stdout),
        },
        "actual_restore_stdout": {
            "sha256": sha256_bytes(completed.stdout),
            "size": len(completed.stdout),
        },
        "expected_complete_stdout": {
            "sha256": sha256_bytes(source_stdout + destination_stdout),
            "size": len(source_stdout + destination_stdout),
        },
        "actual_complete_stdout": {
            "sha256": sha256_bytes(source_stdout + completed.stdout),
            "size": len(source_stdout + completed.stdout),
        },
        "resource_state_rebound": False,
        "compute_continuation_resumed": completed.returncode == 0,
    }
    return negative_sample(
        workload="sqlite",
        fixture=fixture,
        cut=cut,
        arm="wanco-carrier-only",
        completed=completed,
        start_ns=start_ns,
        end_ns=end_ns,
        detector=detector,
        oracle_kind="external-continuation-output-comparison",
        oracle_observation=observation,
        input_bytes=int(receipt["execution_inputs"]["stock_sqlite_wasm"]["size"]),
        output_bytes=len(completed.stdout),
        checkpoint_bytes=checkpoint.stat().st_size,
        resource_state_bytes=fresh_snapshot.stat().st_size,
    )


def run_sqlite_raw_reopen(
    *,
    fixture: int,
    cut: str,
    output_root: Path,
    receipt: Mapping[str, object],
    oracle_binary: Path,
    native_sqlite: Path,
) -> dict[str, object]:
    case = output_root / "controls" / cut / "naive-raw-resource-reopen"
    case.mkdir(mode=0o700, parents=True)
    snapshot = output_root / "work" / "cells" / cut / "source" / "source-namespace.snapshot"
    checkpoint = output_root / "work" / "cells" / cut / "source" / "checkpoint.pb"
    if not snapshot.is_file() or snapshot.stat().st_size == 0:
        raise RuntimeError(f"SQLite source namespace snapshot is missing for {cut}")
    if not checkpoint.is_file() or checkpoint.stat().st_size == 0:
        raise RuntimeError(f"SQLite source checkpoint is missing for {cut}")
    raw_namespace = case / "raw-namespace"
    exported = run(
        [
            str(oracle_binary),
            "export-raw",
            str(snapshot),
            "workload/accounts.db",
            str(raw_namespace),
        ],
        cwd=case,
        timeout=300,
    )
    if exported.returncode != 0:
        raise RuntimeError(
            "raw SQLite namespace export failed: "
            + exported.stderr.decode(errors="replace")[-2000:]
        )
    try:
        export_report = json.loads(exported.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("raw SQLite namespace export returned invalid JSON") from error
    database = raw_namespace / "workload/accounts.db"
    script = RUN_REPOSITORY / "third_party/sqlite/workload" / (
        "cursor.sql" if cut == "active-read-cursor" else "transaction.sql"
    )
    source_stdout = sqlite_run_stream(receipt, output_root, cut, "source")
    destination_stdout = sqlite_run_stream(receipt, output_root, cut, "destination")
    start_ns = time.monotonic_ns()
    completed = run(
        [
            str(native_sqlite),
            "-batch",
            "-bail",
            str(database),
            f".read {script}",
        ],
        cwd=raw_namespace,
        timeout=300,
    )
    end_ns = time.monotonic_ns()
    _, detector = require_detected_divergence(
        completed=completed,
        expected_destination_stdout=destination_stdout,
        label="native-sqlite-raw-reopen",
    )
    observation = {
        "schema": "visa-sqlite-negative-control-observation-v1",
        "arm": "naive-raw-resource-reopen",
        "cut": cut,
        "source_checkpoint": identity(checkpoint),
        "source_namespace_snapshot": identity(snapshot),
        "raw_export_report": {
            "sha256": sha256_bytes(canonical(export_report)),
            "size": len(canonical(export_report)),
        },
        "source_stdout": {"sha256": sha256_bytes(source_stdout), "size": len(source_stdout)},
        "expected_destination_stdout": {
            "sha256": sha256_bytes(destination_stdout),
            "size": len(destination_stdout),
        },
        "actual_reopen_stdout": {
            "sha256": sha256_bytes(completed.stdout),
            "size": len(completed.stdout),
        },
        "expected_complete_stdout": {
            "sha256": sha256_bytes(source_stdout + destination_stdout),
            "size": len(source_stdout + destination_stdout),
        },
        "actual_complete_stdout": {
            "sha256": sha256_bytes(source_stdout + completed.stdout),
            "size": len(source_stdout + completed.stdout),
        },
        "descriptor_state_rebound": False,
        "compute_continuation_resumed": False,
    }
    return negative_sample(
        workload="sqlite",
        fixture=fixture,
        cut=cut,
        arm="naive-raw-resource-reopen",
        completed=completed,
        start_ns=start_ns,
        end_ns=end_ns,
        detector=detector,
        oracle_kind="raw-namespace-native-sqlite-continuation-comparison",
        oracle_observation=observation,
        input_bytes=int(receipt["execution_inputs"]["stock_sqlite_wasm"]["size"]),
        output_bytes=tree_size(raw_namespace),
        checkpoint_bytes=checkpoint.stat().st_size,
        resource_state_bytes=snapshot.stat().st_size,
    )


def zstd_sample_from_observation(
    observation: Mapping[str, object], *, fixture: int, root: Path
) -> list[dict[str, object]]:
    samples: list[dict[str, object]] = []
    control = observation["control"]
    control_output = int(control["sizes"]["output_bytes"])
    for arm in ("uninterrupted-control", "fresh-process-restart"):
        if arm == "uninterrupted-control":
            value = dict(control)
        else:
            value = dict(observation["restart"])
        samples.append({"workload": "zstd", "fixture": fixture, "cut": None, "arm": arm, **value})
    for item in observation["observations"]:
        if item["arm"] == "fresh-process-restart":
            continue
        sample = dict(item)
        sample["fixture"] = fixture
        if sample["arm"] == "naive-raw-resource-reopen" and sample["outcome"] == "equivalent":
            raise RuntimeError("naive zstd reopen unexpectedly accepted equivalence")
        samples.append(sample)
    if len(samples) != 5:
        raise RuntimeError(f"zstd observation contains unexpected sample count: {len(samples)}")
    return samples


def run_zstd_fixture(
    *, fixture: int, root: Path, zstd_artifact: Path, stock_zstd: Path
) -> tuple[list[dict[str, object]], dict[str, object]]:
    output_root = root / f"zstd-{fixture}"
    output_root.mkdir(mode=0o700)
    matrix_output = output_root / "matrix.json"
    baseline_output = output_root / "baseline.json"
    command = [
        sys.executable,
        str(ZSTD_RUNNER),
        "--stock-zstd",
        str(stock_zstd),
        "--artifact-root",
        str(zstd_artifact),
        "--output",
        str(matrix_output),
        "--baseline-output",
        str(baseline_output),
        "--cut-write-occurrence",
        "8",
        "64",
        "--skip-build",
    ]
    started = time.monotonic_ns()
    completed = run(command, cwd=RUN_REPOSITORY, timeout=3600)
    if completed.returncode != 0:
        raise RuntimeError(
            f"zstd fixture {fixture} failed: {completed.stderr.decode(errors='replace')[-3000:]}"
        )
    sidecar = json.loads(baseline_output.read_text(encoding="utf-8"))
    sidecar["observations"] = sidecar.pop("observations")
    control = dict(sidecar["control"])
    # The sidecar control is deliberately compact; attach the real retained
    # timing and process identities from the formal receipt.
    matrix = json.loads(matrix_output.read_text(encoding="utf-8"))
    control_raw = matrix["control"]["raw_artifacts"]
    control_timing = output_root / "raw/control/application-timing.json"
    control["process"] = process_from_runs(control_raw["application_runs"], root=output_root)
    control["timing"] = timing_from_file(control_timing, interval_kind="uninterrupted-control")
    control["sizes"]["checkpoint_bytes"] = 0
    control["sizes"]["resource_state_bytes"] = 0
    restart_raw = None
    for item in sidecar["observations"]:
        if item["arm"] == "fresh-process-restart":
            restart_raw = item
            break
    if restart_raw is None:
        raise RuntimeError("zstd sidecar omitted fresh-process restart")
    restart = dict(restart_raw)
    observation = {"control": control, "restart": restart, "observations": sidecar["observations"]}
    selected = [
        item
        for item in sidecar["observations"]
        if item.get("cut") == "write-occurrence-64"
        or item.get("arm") == "fresh-process-restart"
    ]
    observation["observations"] = selected
    samples = zstd_sample_from_observation(observation, fixture=fixture, root=output_root)
    return samples, {
        "runner": {"sha256": sha256_bytes(ZSTD_RUNNER.read_bytes()), "size": ZSTD_RUNNER.stat().st_size},
        "wall_interval": {"start_monotonic_ns": started, "end_monotonic_ns": time.monotonic_ns()},
    }


def sqlite_positive_sample(
    *, receipt: Mapping[str, object], fixture: int, cut: str, root: Path
) -> dict[str, object]:
    cell = next(item for item in receipt["cells"] if item["cell_id"] == cut)
    raw = cell["retained_raw_evidence"]
    timing_path = root / str(raw["application_timing"]["path"])
    runs = raw["application_runs"]
    output = cell["external_oracle"]["semantic_projection"]
    snapshot_bytes = int(cell["namespace_snapshot"]["artifact"]["size"])
    checkpoint_bytes = int(cell["compute_checkpoint"]["size"])
    input_bytes = int(receipt["execution_inputs"]["stock_sqlite_wasm"]["size"])
    return {
        "workload": "sqlite",
        "fixture": fixture,
        "cut": cut,
        "arm": "visa-plus-wanco",
        "expectation": "observable-equivalence",
        "outcome": "equivalent",
        "throughput_eligible": True,
        "process": process_from_runs(runs, root=root),
        "timing": timing_from_file(timing_path, interval_kind="source-freeze-to-external-oracle"),
        "sizes": {
            "input_bytes": input_bytes,
            "output_bytes": snapshot_bytes,
            "checkpoint_bytes": checkpoint_bytes,
            "resource_state_bytes": snapshot_bytes,
        },
        "oracle": {
            "kind": "native-sqlite-namespace-oracle",
            "accepted": True,
            "observation_sha256": sha256_bytes(canonical(output)),
        },
        "detector": None,
        "reason": None,
    }


def sqlite_control_sample(
    *, receipt: Mapping[str, object], fixture: int, root: Path, interval_kind: str
) -> dict[str, object]:
    control = receipt["uninterrupted_control"]
    control_root = root / "observations/uninterrupted-control"
    timing = timing_from_file(
        control_root / "application-timing.json", interval_kind=interval_kind
    )
    raw = control["retained_raw_evidence"]
    projection = control["equivalence_projection"]
    snapshot = int(control["namespace_snapshot"]["artifact"]["size"])
    return {
        "workload": "sqlite",
        "fixture": fixture,
        "cut": None,
        "arm": "uninterrupted-control"
        if interval_kind == "uninterrupted-control"
        else "fresh-process-restart",
        "expectation": "observable-equivalence",
        "outcome": "equivalent",
        "throughput_eligible": True,
        "process": process_from_runs(raw["application_runs"], root=root),
        "timing": timing,
        "sizes": {
            "input_bytes": int(receipt["execution_inputs"]["stock_sqlite_wasm"]["size"]),
            "output_bytes": snapshot,
            "checkpoint_bytes": 0,
            "resource_state_bytes": snapshot,
        },
        "oracle": {
            "kind": "native-sqlite-namespace-oracle",
            "accepted": True,
            "observation_sha256": sha256_bytes(canonical(projection)),
        },
        "detector": None,
        "reason": None,
    }


def run_sqlite_fixture(
    *,
    fixture: int,
    root: Path,
    sqlite_artifact: Path,
    typed_corpus: Path,
    wanco_receipt: Path,
    oracle_binary: Path,
    native_sqlite: Path,
    docker: str,
) -> list[dict[str, object]]:
    output_root = root / f"sqlite-{fixture}"
    output_root.mkdir(mode=0o700)
    matrix_output = output_root / "matrix.json"
    command = [
        sys.executable,
        str(SQLITE_RUNNER),
        "--repository",
        str(RUN_REPOSITORY),
        "--artifact-root",
        str(sqlite_artifact),
        "--typed-corpus-receipt",
        str(typed_corpus),
        "--wanco-build-receipt",
        str(wanco_receipt),
        "--sqlite-source-lock",
        str(RUN_REPOSITORY / "third_party/sqlite/source-lock.json"),
        "--wanco-source-lock",
        str(RUN_REPOSITORY / "third_party/wanco/source-lock.json"),
        "--host-binary",
        str(RUN_REPOSITORY / "target/debug/visa_wasi_host"),
        "--bind-binary",
        str(RUN_REPOSITORY / "target/debug/visa-wasi-migration-bind"),
        "--driver-binary",
        str(RUN_REPOSITORY / "target/debug/visa-wasi-migration-driver"),
        "--oracle-binary",
        str(RUN_REPOSITORY / "target/debug/visa-sqlite-oracle"),
        "--output",
        str(matrix_output),
        "--work-root",
        str(output_root / "work"),
        "--docker",
        docker,
        "--skip-runtime-build",
    ]
    completed = run(
        command,
        cwd=RUN_REPOSITORY,
        timeout=3600,
        env={**os.environ, "VISA_BASELINE_SOURCE_CONTROLS": "1"},
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"SQLite fixture {fixture} failed: {completed.stderr.decode(errors='replace')[-3000:]}"
        )
    receipt = json.loads(matrix_output.read_text(encoding="utf-8"))

    # A restart baseline is a second, independent invocation of the complete
    # SQLite runner.  It is intentionally not derived from the first control.
    restart_root = output_root / "fresh-process-rerun"
    restart_root.mkdir(mode=0o700)
    restart_command = list(command)
    restart_command[restart_command.index("--output") + 1] = str(
        restart_root / "matrix.json"
    )
    restart_command[restart_command.index("--work-root") + 1] = str(
        restart_root / "work"
    )
    restart_completed = run(restart_command, cwd=RUN_REPOSITORY, timeout=3600)
    if restart_completed.returncode != 0:
        raise RuntimeError(
            "SQLite fresh-process rerun failed: "
            + restart_completed.stderr.decode(errors="replace")[-3000:]
        )
    restart_receipt = json.loads(
        (restart_root / "matrix.json").read_text(encoding="utf-8")
    )
    sqlite_runner = load_module(
        SQLITE_RUNNER, f"visa_stock_sqlite_baseline_runtime_{fixture}"
    )
    samples: list[dict[str, object]] = []
    samples.append(
        sqlite_control_sample(
            receipt=receipt,
            fixture=fixture,
            root=output_root,
            interval_kind="uninterrupted-control",
        )
    )
    samples.append(
        sqlite_control_sample(
            receipt=restart_receipt,
            fixture=fixture,
            root=restart_root,
            interval_kind="fresh-process-full-rerun",
        )
    )
    for cut in CONTRACT.SQLITE_CUTS:
        samples.append(sqlite_positive_sample(receipt=receipt, fixture=fixture, cut=cut, root=output_root))
        samples.append(
            run_sqlite_carrier_only(
                sqlite_runner=sqlite_runner,
                fixture=fixture,
                cut=cut,
                output_root=output_root,
                receipt=receipt,
                sqlite_artifact=sqlite_artifact,
                oracle_binary=oracle_binary,
                docker=docker,
            )
        )
        samples.append(
            run_sqlite_raw_reopen(
                fixture=fixture,
                cut=cut,
                output_root=output_root,
                receipt=receipt,
                oracle_binary=oracle_binary,
                native_sqlite=native_sqlite,
            )
        )
    return samples


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=CONTRACT.RUNS_PER_ARM)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stock-zstd", type=Path, default=Path("/usr/bin/zstd"))
    parser.add_argument("--zstd-artifact-root", type=Path, default=DEFAULT_ZSTD_ARTIFACT)
    parser.add_argument("--sqlite-artifact-root", type=Path, default=DEFAULT_SQLITE_ARTIFACT)
    parser.add_argument("--sqlite-typed-corpus", type=Path, default=DEFAULT_TYPED_CORPUS)
    parser.add_argument("--wanco-build-receipt", type=Path, default=DEFAULT_WANCO_RECEIPT)
    parser.add_argument("--sqlite-oracle", type=Path, default=DEFAULT_SQLITE_ORACLE)
    parser.add_argument("--native-sqlite", type=Path, default=DEFAULT_NATIVE_SQLITE)
    parser.add_argument("--docker", default="docker")
    args = parser.parse_args()
    if args.runs != CONTRACT.RUNS_PER_ARM:
        raise SystemExit(f"baseline requires exactly {CONTRACT.RUNS_PER_ARM} fixtures per arm")
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing to replace {output}")
    samples: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="visa-stock-baseline-") as temporary:
        temp_root = Path(temporary)
        zstd_meta: dict[str, object] | None = None
        for fixture in range(1, args.runs + 1):
            zstd_samples, zstd_meta = run_zstd_fixture(
                fixture=fixture,
                root=temp_root,
                zstd_artifact=args.zstd_artifact_root.resolve(),
                stock_zstd=args.stock_zstd.resolve(),
            )
            samples.extend(zstd_samples)
        for fixture in range(1, args.runs + 1):
            samples.extend(run_sqlite_fixture(
                fixture=fixture,
                root=temp_root,
                sqlite_artifact=args.sqlite_artifact_root.resolve(),
                typed_corpus=args.sqlite_typed_corpus.resolve(),
                wanco_receipt=args.wanco_build_receipt.resolve(),
                oracle_binary=args.sqlite_oracle.resolve(),
                native_sqlite=args.native_sqlite.resolve(),
                docker=args.docker,
            ))
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=RUN_REPOSITORY, text=True).strip()
    receipt = {
        "schema": CONTRACT.SCHEMA,
        "repository_revision": revision,
        "runs_per_arm": CONTRACT.RUNS_PER_ARM,
        "sampling": {
            "zstd": {"cuts": list(CONTRACT.ZSTD_CUTS), "fixtures": CONTRACT.RUNS_PER_ARM},
            "sqlite": {"cuts": list(CONTRACT.SQLITE_CUTS), "fixtures": CONTRACT.RUNS_PER_ARM},
        },
        "execution_inputs": {
            "stock_zstd_runner": identity(ZSTD_RUNNER),
            "stock_sqlite_runner": identity(SQLITE_RUNNER),
            "stock_zstd_artifact_receipt": identity(args.zstd_artifact_root.resolve() / "receipt.json"),
            "stock_sqlite_artifact_receipt": identity(args.sqlite_artifact_root.resolve() / "receipt.json"),
            "sqlite_typed_corpus": identity(args.sqlite_typed_corpus.resolve()),
            "wanco_build_receipt": identity(args.wanco_build_receipt.resolve()),
            "sqlite_oracle": identity(args.sqlite_oracle.resolve()),
            "native_sqlite": identity(args.native_sqlite.resolve()),
        },
        "samples": samples,
        "scope": {
            "same_host_x86_64": platform.machine() in {"x86_64", "amd64"},
            "cross_host": False,
            "power_loss": False,
            "third_party_migration_baseline": False,
            "negative_arms_are_throughput_baselines": False,
            "fresh_process_restart_is_checkpoint_restore": False,
        },
    }
    CONTRACT.validate_receipt(receipt)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.write_bytes(canonical(receipt) + b"\n")
    print(f"stock application baseline receipt: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, CONTRACT.BaselineError) as error:
        print(f"stock application baseline failed: {error}", file=sys.stderr)
        raise SystemExit(1)
