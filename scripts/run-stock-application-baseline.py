#!/usr/bin/env python3
"""Run the bounded five-arm stock-application baseline study.

This driver is independent of the semantic matrix receipts.  It invokes the
real stock-zstd and stock-SQLite runners in fresh private roots, retains the
runner hashes and raw observations, and emits only timing/size/oracle records.
Unsupported arms are explicit capability records (exit 125), never synthetic
successes or throughput points.
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
UNSUPPORTED = 125


def canonical(value: object) -> bytes:
    return CONTRACT.canonical_bytes(value)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def identity(path: Path, *, allow_empty: bool = False) -> dict[str, object]:
    payload = path.read_bytes()
    if not payload and not allow_empty:
        raise RuntimeError(f"empty artifact is not allowed: {path}")
    return {"sha256": sha256_bytes(payload), "size": len(payload)}


def run(command: list[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
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


def unsupported_sample(
    *, workload: str, fixture: int, cut: str, arm: str, reason: str
) -> dict[str, object]:
    zero = {"sha256": sha256_bytes(b""), "size": 0}
    return {
        "workload": workload,
        "fixture": fixture,
        "cut": cut,
        "arm": arm,
        "expectation": "unsupported",
        "outcome": "unsupported",
        "throughput_eligible": False,
        "process": {"exit_status": UNSUPPORTED, "stdout": zero, "stderr": zero},
        "timing": {
            "clock": CONTRACT.CLOCK,
            "interval": {"start_monotonic_ns": 1, "end_monotonic_ns": 2, "duration_ns": 1},
            "interval_kind": "unsupported-capability",
            "phases": [{
                "role": "unsupported",
                "start_monotonic_ns": 1,
                "end_monotonic_ns": 2,
                "duration_ns": 1,
                "exit_status": UNSUPPORTED,
            }],
        },
        "sizes": {"input_bytes": 0, "output_bytes": 0, "checkpoint_bytes": 0, "resource_state_bytes": 0},
        "oracle": {"kind": "not-run", "accepted": False, "observation_sha256": None},
        "detector": "capability-not-implemented",
        "reason": reason,
    }


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
    *, fixture: int, root: Path, sqlite_artifact: Path, typed_corpus: Path, wanco_receipt: Path
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
        "--skip-runtime-build",
    ]
    completed = run(command, cwd=RUN_REPOSITORY, timeout=3600)
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
    # SQLite's current canonical runner has no raw carrier-only/reopen route;
    # retain that fact as an unsupported capability instead of fabricating it.
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
        for arm in ("wanco-carrier-only", "naive-raw-resource-reopen"):
            samples.append(unsupported_sample(
                workload="sqlite",
                fixture=fixture,
                cut=cut,
                arm=arm,
                reason="current SQLite runner does not expose a carrier-only or raw namespace reopen execution path; no result is claimed",
            ))
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
