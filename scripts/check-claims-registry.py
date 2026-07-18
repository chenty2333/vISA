#!/usr/bin/env python3
"""Validate the project-claim identity/lifecycle index and canonical references."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from claims_registry import (
    DEFAULT_REGISTRY,
    ROOT,
    RegistryError,
    load_registry,
    validate_registry,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    return parser.parse_args()


def main() -> int:
    try:
        registry = load_registry(parse_args().registry)
        validate_registry(registry, ROOT)
    except RegistryError as error:
        print(f"claim registry invalid: {error}", file=sys.stderr)
        return 1
    print(
        f"claim registry valid: {len(registry['claims'])} claims, "
        f"{len(registry['workflow_bindings'])} workflow bindings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
