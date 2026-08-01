#!/usr/bin/env python3
"""Run receipt-bound lifecycle timing arms for the stock application lanes.

This is deliberately separate from semantic matrix receipts.  It invokes the
real stock-zstd and stock-SQLite matrix runners with an opt-in monotonic event
log, and reports only lifecycle intervals and tool availability.  No timing
value is used as a semantic verdict or as a third-party baseline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "visa-stock-application-cost-v1"
EVENT_SCHEMA = "visa-application-cost-events-v1"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False)


def tool_status() -> dict[str, Any]:
    tools = {name: shutil.which(name) for name in ("docker", "criu", "wasmtime", "wamrc", "wasmedge", "wazero")}
    criu_check: dict[str, Any] = {"available": False}
    if tools["criu"]:
        completed = subprocess.run([tools["criu"], "check"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        criu_check = {"available": completed.returncode == 0,
                      "exit_status": completed.returncode,
                      "stderr_tail": completed.stderr.decode(errors="replace")[-1024:]}
    return {"executables": tools, "criu_check": criu_check}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stock-zstd", type=Path, default=Path("/usr/bin/zstd"))
    parser.add_argument("--zstd-artifact-root", type=Path, required=True)
    parser.add_argument("--sqlite-artifact-root", type=Path, required=True)
    parser.add_argument("--sqlite-typed-corpus", type=Path, required=True)
    parser.add_argument("--wanco-build-receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1 or args.runs > 20:
        raise SystemExit("--runs must be between 1 and 20")
    output = (ROOT / args.output).resolve()
    if output.exists():
        raise SystemExit(f"refusing existing output: {output}")
    root = output.parent
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    arms: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="visa-stock-cost-") as temporary:
        temporary_root = Path(temporary)
        for index in range(args.runs):
            for workload, script, extra in (
                ("zstd", ROOT / "scripts/run-stock-zstd-migration-matrix.py", ["--stock-zstd", str(args.stock_zstd), "--skip-build"]),
                ("sqlite", ROOT / "scripts/run-stock-sqlite-rollback-matrix.py", ["--skip-runtime-build"]),
            ):
                event_path = temporary_root / f"{workload}-{index}.jsonl"
                # Each matrix runner refuses to overwrite a formal receipt. Use
                # an isolated private output root for every timing arm.
                arm_root = temporary_root / f"{workload}-{index}-artifact"
                if workload == "zstd":
                    extra += [
                        "--artifact-root", str((ROOT / args.zstd_artifact_root).resolve()),
                        "--output", str(arm_root / "summary.json"),
                    ]
                else:
                    extra += [
                        "--artifact-root", str((ROOT / args.sqlite_artifact_root).resolve()),
                        "--typed-corpus-receipt", str((ROOT / args.sqlite_typed_corpus).resolve()),
                        "--wanco-build-receipt", str((ROOT / args.wanco_build_receipt).resolve()),
                        "--output", str(arm_root / "receipt.json"),
                        "--work-root", str(arm_root / "work"),
                    ]
                env = dict(os.environ, VISA_APPLICATION_COST_EVENTS=str(event_path))
                command = [sys.executable, str(script), *extra]
                started = time.monotonic_ns()
                completed = run(command, cwd=ROOT, env=env, timeout=3600)
                ended = time.monotonic_ns()
                events: list[dict[str, Any]] = []
                if event_path.exists():
                    for line in event_path.read_text(encoding="utf-8").splitlines():
                        value = json.loads(line)
                        if not isinstance(value, dict) or "label" not in value or "monotonic_ns" not in value:
                            raise RuntimeError(f"invalid event in {event_path}")
                        events.append(value)
                arms.append({
                    "workload": workload, "run": index + 1,
                    "command": command, "exit_status": completed.returncode,
                    "wall_start_monotonic_ns": started, "wall_end_monotonic_ns": ended,
                    "wall_duration_ns": ended - started,
                    "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
                    "events": events,
                })
                if completed.returncode != 0:
                    raise RuntimeError(f"{workload} cost run {index + 1} failed: {completed.stderr.decode(errors='replace')[-2000:]}")
    receipt = {
        "schema": SCHEMA,
        "event_schema": EVENT_SCHEMA,
        "repository_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "runs_per_workload": args.runs,
        "arms": arms,
        "tool_status": tool_status(),
        "scope": {
            "timing": "real runner lifecycle intervals and process wall time",
            "semantic_verdict": False,
            "third_party_baseline": False,
            "cross_host": False,
            "power_loss": False,
        },
    }
    output.write_bytes(canonical(receipt) + b"\n")
    print(f"stock application cost receipt: {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"stock application cost failed: {error}", file=sys.stderr)
        raise SystemExit(1)
