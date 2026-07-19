#!/usr/bin/env python3
"""Closed release-readiness verifier dispatcher.

The exact-RC workflow invokes this source-controlled entry point by readiness
ID.  A verifier is admitted only after its implementation is registered here;
unknown and intentionally pending IDs fail closed.  Receipts record the typed
ID and this file's digest, never an arbitrary command supplied by evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REQUIRED_IDS = (
    "contract-schema-frozen",
    "process-topology-frozen",
    "public-cli",
    "public-agent",
    "public-ownership-service",
    "public-nexus-adapter-service",
    "cli-agent-rpc-v1",
    "agent-ownership-rpc-v1",
    "agent-nexus-rpc-v1",
    "ownership-single-writer-restart-replay",
    "stage3-dual-process",
    "visa-nexus-adapter",
    "provider-enforced-fence",
    "release-semantic-golden-corpus",
    "nexus-freeze-local-source-lock",
    "nexus-native-v1-wire-artifact",
    "neutral-nexus-mapping-v2",
    "compatibility-matrix",
    "crash-recovery-and-replay",
    "observability-and-evidence",
    "supply-chain-license-and-artifact-locks",
    "external-workload",
    "exact-tag-release-evidence",
)

INPUT_SNAPSHOT_SCHEMA = "visa.release-verifier-input-snapshot.v1"


def verifier_id(readiness_id: str) -> str:
    return f"visa.release.verify.{readiness_id}.v1"


# Implementations are added only with their corresponding product surface and
# adversarial tests.  Keeping this empty makes the current pre-0.1 tree unable
# to mint a passing release receipt by construction.
IMPLEMENTED: dict[str, object] = {}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True, choices=REQUIRED_IDS)
    parser.add_argument("--input-snapshot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def load_input_snapshot(root: Path, readiness_id: str) -> dict[str, object]:
    manifest_path = root / "input-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("release verifier input snapshot is unreadable") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "readiness_id",
        "source_revision",
        "source_tag",
        "evidence",
        "tagged_source_inputs",
        "archive_inputs",
    }:
        raise RuntimeError("release verifier input snapshot shape drifted")
    if manifest["schema"] != INPUT_SNAPSHOT_SCHEMA:
        raise RuntimeError("release verifier input snapshot schema drifted")
    if manifest["readiness_id"] != readiness_id:
        raise RuntimeError("release verifier input snapshot readiness ID drifted")
    return manifest


def main() -> int:
    arguments = parse_arguments()
    load_input_snapshot(arguments.input_snapshot, arguments.id)
    if arguments.id not in IMPLEMENTED:
        result = {
            "schema": "visa.release-verifier-dispatch.v1",
            "readiness_id": arguments.id,
            "verifier_id": verifier_id(arguments.id),
            "status": "not-implemented-fail-closed",
        }
        print(json.dumps(result, sort_keys=True), file=sys.stderr)
        return 3
    raise RuntimeError("registered verifier must return a typed result")


if __name__ == "__main__":
    sys.exit(main())
