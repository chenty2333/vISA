#!/usr/bin/env python3
"""Summarize visa-eval sample files into a Markdown and CSV table.

Reads one or more `samples.jsonl` files produced by `visa-eval`, groups the
samples by (measure, arm, phase, config), and reports count, p50, and p95 for
each group. Duration groups and size groups are reported separately because
their units differ; `count-*` phases carry record counts rather than bytes.

Percentiles use the nearest-rank definition, matching the terminal recap the
harness prints, so the two never disagree about the same file.

usage:
  scripts/eval-summarize.py <samples.jsonl> [more.jsonl ...]
      [--csv <path>] [--markdown <path>] [--measure <name>] [--drift]
      [--stat-bundle <path>]
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
import sys

SAMPLE_SCHEMA = "visa-eval-sample-v1"


def percentile(sorted_values: list[int], percent: float) -> int:
    """Nearest-rank percentile over an already sorted list."""
    if not sorted_values:
        return 0
    rank = math.ceil(percent / 100.0 * len(sorted_values))
    index = min(max(rank - 1, 0), len(sorted_values) - 1)
    return sorted_values[index]


def config_label(config: dict) -> str:
    if not config:
        return ""
    return ",".join(f"{key}={value}" for key, value in sorted(config.items()))


def load(paths: list[Path]) -> list[dict]:
    samples = []
    for path in paths:
        with path.open(encoding="utf-8") as source:
            for number, line in enumerate(source, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    sample = json.loads(line)
                except json.JSONDecodeError as error:
                    raise SystemExit(f"{path}:{number}: {error}") from error
                if sample.get("schema") != SAMPLE_SCHEMA:
                    raise SystemExit(
                        f"{path}:{number}: unexpected schema {sample.get('schema')!r}"
                    )
                samples.append(sample)
    return samples


def group(samples: list[dict], field: str) -> dict[tuple, list[int]]:
    grouped: dict[tuple, list[int]] = {}
    for sample in samples:
        value = sample.get(field)
        if value is None:
            continue
        key = (
            sample["measure"],
            sample["arm"],
            sample["phase"],
            config_label(sample.get("config") or {}),
        )
        grouped.setdefault(key, []).append(int(value))
    return grouped


def drift(samples: list[dict]) -> dict[tuple, tuple[int, int]]:
    """Median of the first and last tenth of each duration group, in iteration
    order. A large gap means the measure is not in a steady state: the
    coordinator's per-effect cost grows with the operation ledger it carries.
    """
    ordered: dict[tuple, list[tuple[int, int, int]]] = {}
    for sample in samples:
        if sample.get("value_ns") is None:
            continue
        key = (
            sample["measure"],
            sample["arm"],
            sample["phase"],
            config_label(sample.get("config") or {}),
        )
        ordered.setdefault(key, []).append(
            (int(sample["run"]), int(sample["iter"]), int(sample["value_ns"]))
        )
    result = {}
    for key, entries in ordered.items():
        if len(entries) < 20:
            continue
        entries.sort()
        window = max(1, len(entries) // 10)
        first = sorted(value for _, _, value in entries[:window])
        last = sorted(value for _, _, value in entries[-window:])
        result[key] = (percentile(first, 50.0), percentile(last, 50.0))
    return result


def rows(grouped: dict[tuple, list[int]], unit: str) -> list[dict]:
    table = []
    for key, values in sorted(grouped.items()):
        values.sort()
        measure, arm, phase, config = key
        table.append(
            {
                "measure": measure,
                "arm": arm,
                "phase": phase,
                "config": config,
                "unit": "count" if phase.startswith("count-") else unit,
                "count": len(values),
                "p50": percentile(values, 50.0),
                "p95": percentile(values, 95.0),
                "min": values[0],
                "max": values[-1],
            }
        )
    return table


def markdown(table: list[dict], title: str) -> str:
    if not table:
        return f"### {title}\n\n_no samples_\n"
    header = ["measure", "arm", "phase", "config", "unit", "count", "p50", "p95"]
    lines = [f"### {title}", "", "| " + " | ".join(header) + " |",
             "|" + "|".join("---" for _ in header) + "|"]
    for row in table:
        lines.append("| " + " | ".join(str(row[column]) for column in header) + " |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--csv", type=Path, help="write the combined table as CSV")
    parser.add_argument("--markdown", type=Path, help="write the tables as Markdown")
    parser.add_argument("--measure", action="append", help="restrict to these measures")
    parser.add_argument(
        "--drift",
        action="store_true",
        help="report first-tenth against last-tenth medians per duration group",
    )
    parser.add_argument(
        "--stat-bundle",
        type=Path,
        action="append",
        help="also report the size of an existing evidence bundle for comparison",
    )
    arguments = parser.parse_args()

    samples = load(arguments.samples)
    if arguments.measure:
        wanted = set(arguments.measure)
        samples = [sample for sample in samples if sample["measure"] in wanted]
    if not samples:
        print("no samples matched", file=sys.stderr)
        return 1

    durations = rows(group(samples, "value_ns"), "ns")
    sizes = rows(group(samples, "bytes"), "bytes")

    document = [
        markdown(durations, "Durations"),
        markdown(sizes, "Sizes"),
    ]

    if arguments.drift:
        measured = drift(samples)
        lines = ["### Drift (median of first tenth vs last tenth, ns)", ""]
        if measured:
            lines += [
                "| measure | arm | phase | config | first | last | ratio |",
                "|---|---|---|---|---|---|---|",
            ]
            for key, (first, last) in sorted(measured.items()):
                ratio = f"{last / first:.2f}" if first else "n/a"
                lines.append("| " + " | ".join([*key, str(first), str(last), ratio]) + " |")
        else:
            lines.append("_not enough samples per group_")
        lines.append("")
        document.append("\n".join(lines))

    for bundle in arguments.stat_bundle or []:
        if not bundle.exists():
            document.append(f"_bundle {bundle} does not exist_\n")
            continue
        if bundle.is_dir():
            total = sum(item.stat().st_size for item in bundle.rglob("*") if item.is_file())
        else:
            total = bundle.stat().st_size
        document.append(f"Existing bundle `{bundle}`: {total} bytes\n")

    rendered = "\n".join(document)
    print(rendered)

    if arguments.markdown:
        arguments.markdown.write_text(rendered, encoding="utf-8")
    if arguments.csv:
        combined = durations + sizes
        with arguments.csv.open("w", newline="", encoding="utf-8") as target:
            writer = csv.DictWriter(target, fieldnames=list(combined[0].keys()))
            writer.writeheader()
            writer.writerows(combined)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
