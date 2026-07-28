#!/usr/bin/env python3
"""Unit tests for run-level vISA evaluation summaries."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("eval-summarize.py")
SPEC = importlib.util.spec_from_file_location("eval_summarize", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
summary = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = summary
SPEC.loader.exec_module(summary)


def sample(run: int, iteration: int, value: int) -> dict[str, object]:
    return {
        "schema": "visa-eval-sample-v1",
        "measure": "measure",
        "arm": "arm",
        "phase": "phase",
        "config": {},
        "run": run,
        "iter": iteration,
        "value_ns": value,
        "bytes": None,
    }


class RunLevelSummaryTests(unittest.TestCase):
    def test_rows_treat_runs_not_iterations_as_independent_samples(self) -> None:
        samples = [sample(0, 0, 1), sample(0, 1, 100), sample(1, 0, 10), sample(1, 1, 20)]
        row = summary.rows(summary.group(samples, "value_ns"), "ns")[0]

        self.assertEqual(row["runs"], 2)
        self.assertEqual(row["samples"], 4)
        self.assertEqual(row["p50"], 1)
        self.assertEqual(row["p95"], 10)

    def test_drift_computes_windows_within_each_run(self) -> None:
        samples = []
        for run, offset in [(0, 0), (1, 100)]:
            samples.extend(sample(run, iteration, offset + iteration + 1) for iteration in range(20))

        first, last, runs = next(iter(summary.drift(samples).values()))
        self.assertEqual((first, last, runs), (1, 19, 2))

    def test_multiple_files_keep_same_numbered_runs_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = []
            for source_index, offset in enumerate((0, 100)):
                path = Path(temporary) / f"samples-{source_index}.jsonl"
                rows = [sample(run, 0, offset + run + 1) for run in range(2)]
                path.write_text(
                    "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
                )
                paths.append(path)

            loaded = summary.load(paths)
            row = summary.rows(summary.group(loaded, "value_ns"), "ns")[0]

        self.assertEqual(row["runs"], 4)
        self.assertEqual(row["samples"], 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
