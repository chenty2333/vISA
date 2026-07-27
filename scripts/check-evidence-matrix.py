#!/usr/bin/env python3
"""Validate the canonical evidence matrix and its claim/workflow bindings."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from evidence_matrix import (
    DEFAULT_MATRIX,
    DEFAULT_REGISTRY,
    EvidenceMatrixError,
    ROOT,
    validate_repository,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        matrix = validate_repository(arguments.matrix, arguments.registry, ROOT)
    except EvidenceMatrixError as error:
        print(f"evidence matrix invalid: {error}", file=sys.stderr)
        return 1
    print(
        "evidence matrix valid: "
        f"{len(matrix['cells'])} cells, "
        f"{len(matrix['claim_requirements'])} claim requirements"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

