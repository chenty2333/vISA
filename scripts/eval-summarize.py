#!/usr/bin/env python3
"""Summarize visa-eval sample files into a Markdown and CSV table.

Reads one or more `samples.jsonl` files produced by `visa-eval`, groups the
samples by (measure, arm, phase, config) and then by independent run. It first
computes one median per run and reports quantiles across those run medians.
Duration groups and size groups are separate because their units differ;
`count-*` phases carry record counts rather than bytes.

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
    for source_index, path in enumerate(paths):
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
                sample["_source_index"] = source_index
                samples.append(sample)
    return samples


def run_identity(sample: dict) -> tuple[int, int]:
    return int(sample.get("_source_index", 0)), int(sample["run"])


def group(samples: list[dict], field: str) -> dict[tuple, dict[tuple[int, int], list[int]]]:
    grouped: dict[tuple, dict[tuple[int, int], list[int]]] = {}
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
        grouped.setdefault(key, {}).setdefault(run_identity(sample), []).append(int(value))
    return grouped


def drift(samples: list[dict]) -> dict[tuple, tuple[int, int, int]]:
    """Across-run medians of each run's first- and last-tenth medians."""
    ordered: dict[tuple, dict[tuple[int, int], list[tuple[int, int]]]] = {}
    for sample in samples:
        if sample.get("value_ns") is None:
            continue
        key = (
            sample["measure"],
            sample["arm"],
            sample["phase"],
            config_label(sample.get("config") or {}),
        )
        run = run_identity(sample)
        ordered.setdefault(key, {}).setdefault(run, []).append(
            (int(sample["iter"]), int(sample["value_ns"]))
        )
    result = {}
    for key, by_run in ordered.items():
        first_medians = []
        last_medians = []
        for entries in by_run.values():
            if len(entries) < 20:
                continue
            entries.sort()
            window = max(1, len(entries) // 10)
            first = sorted(value for _, value in entries[:window])
            last = sorted(value for _, value in entries[-window:])
            first_medians.append(percentile(first, 50.0))
            last_medians.append(percentile(last, 50.0))
        if first_medians:
            first_medians.sort()
            last_medians.sort()
            result[key] = (
                percentile(first_medians, 50.0),
                percentile(last_medians, 50.0),
                len(first_medians),
            )
    return result


def rows(grouped: dict[tuple, dict[tuple[int, int], list[int]]], unit: str) -> list[dict]:
    table = []
    for key, by_run in sorted(grouped.items()):
        medians = []
        sample_count = 0
        for values in by_run.values():
            values.sort()
            sample_count += len(values)
            medians.append(percentile(values, 50.0))
        medians.sort()
        measure, arm, phase, config = key
        table.append(
            {
                "measure": measure,
                "arm": arm,
                "phase": phase,
                "config": config,
                "unit": "count" if phase.startswith("count-") else unit,
                "runs": len(medians),
                "samples": sample_count,
                "p25": percentile(medians, 25.0),
                "p50": percentile(medians, 50.0),
                "p75": percentile(medians, 75.0),
                "p95": percentile(medians, 95.0),
                "min": medians[0],
                "max": medians[-1],
            }
        )
    return table


def markdown(table: list[dict], title: str) -> str:
    if not table:
        return f"### {title}\n\n_no samples_\n"
    header = [
        "measure",
        "arm",
        "phase",
        "config",
        "unit",
        "runs",
        "samples",
        "p25",
        "p50",
        "p75",
        "p95",
    ]
    lines = [
        f"### {title}",
        "",
        "| " + " | ".join(header) + " |",
        "|" + "|".join("---" for _ in header) + "|",
    ]
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
                "| measure | arm | phase | config | first | last | ratio | runs |",
                "|---|---|---|---|---|---|---|---|",
            ]
            for key, (first, last, runs) in sorted(measured.items()):
                ratio = f"{last / first:.2f}" if first else "n/a"
                lines.append(
                    "| " + " | ".join([*key, str(first), str(last), ratio, str(runs)]) + " |"
                )
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
