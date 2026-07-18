#!/usr/bin/env python3
"""Validate committed successor-claim closures, optionally against remote state."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from claim_archive import (
    ArchiveError,
    permanent_claims_at_baseline,
    require_permanent_claims_monotonic,
    validate_closure_record,
    verify_online,
)
from claims_registry import DEFAULT_REGISTRY, ROOT, RegistryError, load_registry, validate_registry


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--claim", action="append", default=[], help="claim id to check")
    parser.add_argument(
        "--repository",
        help="expected owner/repository slug (must equal every online receipt)",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="also reconcile earned successor closures with GitHub and the second copy",
    )
    parser.add_argument(
        "--baseline",
        help="strict ancestor commit used to distinguish new promotions from durable closures",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        if arguments.baseline is not None and not arguments.online:
            raise ArchiveError("--baseline requires --online")
        baseline_revision = arguments.baseline
        if baseline_revision in {"", "0" * 40}:
            baseline_revision = None
        registry = load_registry(arguments.registry)
        validate_registry(registry, ROOT)
        baseline_permanent_receipts = (
            permanent_claims_at_baseline(ROOT, baseline_revision)
            if baseline_revision is not None
            else None
        )
        by_id = {claim["id"]: claim for claim in registry["claims"]}
        if baseline_permanent_receipts is not None:
            require_permanent_claims_monotonic(
                baseline_permanent_receipts, by_id
            )
        requested = arguments.claim or sorted(by_id)
        unknown = sorted(set(requested) - set(by_id))
        if unknown:
            raise ArchiveError(f"unknown claim ids: {unknown}")

        checked = 0
        online = 0
        for claim_id in requested:
            claim = by_id[claim_id]
            acceptance = claim["acceptance_ref"]
            kind = acceptance["kind"]
            if kind == "pending-permanent-archive-receipt":
                print(f"claim closure pending: {claim_id} (candidate; no network access)")
                continue
            if kind == "canonical-validation":
                print(f"claim closure historical: {claim_id} (canonical validation; no network access)")
                continue
            if kind != "permanent-archive-receipt":
                raise ArchiveError(f"{claim_id} has unknown acceptance kind {kind!r}")
            validate_closure_record(ROOT, claim, acceptance)
            checked += 1
            if arguments.online:
                require_live_actions = (
                    baseline_permanent_receipts is None
                    or baseline_permanent_receipts.get(claim_id)
                    != acceptance["receipt_sha256"]
                )
                verify_online(
                    ROOT,
                    claim,
                    acceptance,
                    repository=arguments.repository,
                    require_live_actions=require_live_actions,
                )
                online += 1
                mode = "live-actions+durable" if require_live_actions else "durable"
            else:
                mode = "offline"
            print(
                f"claim closure valid: {claim_id} "
                f"({mode})"
            )
    except (ArchiveError, RegistryError) as error:
        print(f"claim closure invalid: {error}", file=sys.stderr)
        return 1
    print(f"claim closures valid: offline={checked} online={online}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
