#!/usr/bin/env python3
"""Fail closed when the checked CI/cache/evidence topology drifts."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent.parent

EXPECTED_CLAIMS = {
    "stage1": ("system", "stage1-system-evidence"),
    "jco-node": ("system-jco-node", "stage2b-jco-node-system-evidence"),
    "legacy-stage2": ("system-stage2", "stage2-cross-execution-path-evidence"),
    "strict-stage2": ("system-stage2-strict", "strict-stage2-docker-evidence"),
    "stage3a": ("system-stage3a", "stage3a-regular-file-system-evidence"),
    "stage3b": ("system-stage3b", "stage3b-logical-request-system-evidence"),
}

QUALIFICATION_JOBS = (
    "docker-quality-gate",
    "docker-claim-gates",
    "docker-stage4-gate",
)

EXACT_SHA_IMAGE = "visa-dev:${{ github.sha }}"
RETENTION_POLICY = "${{ github.event_name == 'pull_request' && 3 || 14 }}"
CARGO_CACHE_KEY = (
    "docker-cargo-${{ runner.os }}-"
    "${{ hashFiles('Cargo.lock', 'rust-toolchain.toml', 'Dockerfile', "
    "'compose.yaml', 'compose.ci.yaml') }}"
)


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load_yaml(relative: str) -> dict[str, Any]:
    path = ROOT / relative
    try:
        loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    except (OSError, yaml.YAMLError) as error:
        raise ContractError(f"cannot parse {relative}: {error}") from error
    require(isinstance(loaded, dict), f"{relative} must contain a YAML mapping")
    return loaded


def steps_using(job: dict[str, Any], prefix: str) -> list[dict[str, Any]]:
    steps = job.get("steps")
    require(isinstance(steps, list), "workflow job must contain a steps sequence")
    return [
        step
        for step in steps
        if isinstance(step, dict) and str(step.get("uses", "")).startswith(prefix)
    ]


def step_with_id(job: dict[str, Any], step_id: str) -> dict[str, Any]:
    steps = job.get("steps", [])
    matches = [step for step in steps if isinstance(step, dict) and step.get("id") == step_id]
    require(len(matches) == 1, f"expected exactly one workflow step with id {step_id}")
    return matches[0]


def check_ignores() -> None:
    for relative in (".gitignore", ".dockerignore"):
        lines = (ROOT / relative).read_text(encoding="utf-8").splitlines()
        require(
            "/.ci-artifacts/" in lines,
            f"{relative} must exclude the generated .ci-artifacts directory",
        )


def check_compose() -> None:
    base = load_yaml("compose.yaml")
    overlay = load_yaml("compose.ci.yaml")
    base_dev = base.get("services", {}).get("dev", {})
    overlay_dev = overlay.get("services", {}).get("dev", {})

    require(
        base_dev.get("image") == "${VISA_DEV_IMAGE:-visa-dev:latest}",
        "compose.yaml must select the exact-SHA image through VISA_DEV_IMAGE",
    )

    environment = overlay_dev.get("environment", {})
    require(
        environment.get("CARGO_INCREMENTAL") == "0",
        "compose.ci.yaml must disable Cargo incremental compilation",
    )
    require(
        environment.get("VISA_EVIDENCE_PARENT") == "/workspace/evidence",
        "compose.ci.yaml must place evidence outside Cargo's target directory",
    )

    volumes = overlay_dev.get("volumes", [])
    require(
        "./.ci-artifacts:/workspace/evidence" in volumes,
        "compose.ci.yaml must bind .ci-artifacts at /workspace/evidence",
    )
    require(
        "./.ci-cache/target:/workspace/target" in volumes,
        "compose.ci.yaml must keep transient Cargo output under .ci-cache/target",
    )


def check_cache_paths(jobs: dict[str, Any]) -> None:
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        cache_steps = steps_using(job, "actions/cache@")
        cache_steps += steps_using(job, "actions/cache/restore@")
        for step in cache_steps:
            cache_path = str(step.get("with", {}).get("path", ""))
            require(cache_path, f"{job_name}: cache action must declare a path")
            for forbidden in (".ci-cache/target", ".ci-artifacts"):
                require(
                    forbidden not in cache_path,
                    f"{job_name}: Actions cache must not include {forbidden}",
                )


def check_dependency_caches(jobs: dict[str, Any]) -> None:
    expected_paths = {".ci-cache/cargo-git", ".ci-cache/cargo-registry"}
    for job_name in QUALIFICATION_JOBS:
        job = jobs[job_name]
        cache_steps = steps_using(job, "actions/cache@")
        cache_steps += steps_using(job, "actions/cache/restore@")
        require(len(cache_steps) == 1, f"{job_name}: expected one Cargo dependency cache")
        step = cache_steps[0]
        settings = step.get("with", {})
        actual_paths = {line.strip() for line in str(settings.get("path", "")).splitlines()}
        require(
            actual_paths == expected_paths,
            f"{job_name}: dependency cache must contain only Cargo registry/git state",
        )
        require(
            settings.get("key") == CARGO_CACHE_KEY,
            f"{job_name}: dependency cache key must be shared across qualification jobs",
        )

        uses = str(step.get("uses", ""))
        if job_name == "docker-quality-gate":
            require(
                uses.startswith("actions/cache@"),
                "quality job must own dependency-cache publication",
            )
        else:
            require(
                uses.startswith("actions/cache/restore@"),
                f"{job_name}: claim jobs must not publish duplicate dependency caches",
            )


def check_action_pins(jobs: dict[str, Any]) -> None:
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict) or "uses" not in step:
                continue
            uses = str(step["uses"])
            if uses.startswith("./") or uses.startswith("docker://"):
                continue
            action, separator, revision = uses.rpartition("@")
            require(
                bool(action)
                and separator == "@"
                and re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
                f"{job_name}: external action is not pinned to a full commit: {uses}",
            )


def check_checkouts(jobs: dict[str, Any]) -> None:
    for job_name in QUALIFICATION_JOBS:
        checkouts = steps_using(jobs[job_name], "actions/checkout@")
        require(len(checkouts) == 1, f"{job_name}: expected exactly one checkout")
        require(
            checkouts[0].get("with", {}).get("persist-credentials") == "false",
            f"{job_name}: checkout credentials must not persist",
        )


def check_upload(job_name: str, job: dict[str, Any], gate_id: str) -> None:
    uploads = steps_using(job, "actions/upload-artifact@")
    require(len(uploads) == 1, f"{job_name}: expected exactly one artifact upload")
    expected_condition = (
        "${{ always() && (steps."
        + gate_id
        + ".outcome == 'success' || steps."
        + gate_id
        + ".outcome == 'failure') }}"
    )
    require(
        uploads[0].get("if") == expected_condition,
        f"{job_name}: evidence must upload after gate success or failure",
    )
    settings = uploads[0].get("with", {})
    require(
        settings.get("path") == ".ci-artifacts/",
        f"{job_name}: artifact upload must use .ci-artifacts/",
    )
    require(
        settings.get("include-hidden-files") == "true",
        f"{job_name}: hidden .ci-artifacts contents must be explicitly included",
    )
    require(
        settings.get("if-no-files-found") == "error",
        f"{job_name}: an empty evidence upload must fail",
    )
    require(
        settings.get("retention-days") == RETENTION_POLICY,
        f"{job_name}: artifact retention must be 3 days for PRs and 14 for pushes",
    )


def check_claim_matrix(job: dict[str, Any]) -> None:
    strategy = job.get("strategy", {})
    require(strategy.get("fail-fast") == "false", "claim matrix must run every lane")
    require(strategy.get("max-parallel") == "6", "all six claim lanes must be parallel")
    include = job.get("strategy", {}).get("matrix", {}).get("include", [])
    require(isinstance(include, list), "claim matrix include must be a sequence")
    actual: dict[str, tuple[str, str]] = {}
    for entry in include:
        require(isinstance(entry, dict), "claim matrix entries must be mappings")
        lane = str(entry.get("lane", ""))
        require(lane and lane not in actual, f"duplicate or empty claim lane: {lane!r}")
        actual[lane] = (str(entry.get("tier", "")), str(entry.get("artifact", "")))
    require(actual == EXPECTED_CLAIMS, "claim matrix lane/tier/artifact catalog drifted")

    gate = step_with_id(job, "claim_gate")
    require(
        gate.get("env")
        == {"LANE": "${{ matrix.lane }}", "TIER": "${{ matrix.tier }}"},
        "claim gate must bind the selected matrix lane and tier",
    )
    command = str(gate.get("run", ""))
    require(
        'scripts/run-docker-ci-gate.sh --ci-cache --skip-build "$TIER"' in command,
        "claim matrix must invoke its selected Docker system tier",
    )
    require(".ci-artifacts/${LANE}-ci.log" in command, "claim lane must retain its gate log")


def check_quality_and_stage4(jobs: dict[str, Any]) -> None:
    quality_commands = "\n".join(
        str(step.get("run", "")) for step in jobs["docker-quality-gate"].get("steps", [])
    )
    require(
        "scripts/run-docker-ci-gate.sh --ci-cache --skip-build full" in quality_commands,
        "quality job must run the complete repository gate",
    )

    stage4 = step_with_id(jobs["docker-stage4-gate"], "stage4_system_gate")
    command = str(stage4.get("run", ""))
    require(
        "scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage4" in command,
        "Stage 4 job must run the complete aggregate gate",
    )
    require(".ci-artifacts/stage4-ci.log" in command, "Stage 4 must retain its gate log")


def check_closure(job: dict[str, Any]) -> None:
    require(
        job.get("name") == "Exact-SHA qualification closure",
        "closure check name must remain stable for repository policy",
    )
    needs = job.get("needs", [])
    require(
        isinstance(needs, list) and set(needs) == set(QUALIFICATION_JOBS),
        "exact-SHA closure must depend on quality, claim matrix, and Stage 4 jobs",
    )
    require(job.get("if") == "${{ always() }}", "exact-SHA closure must always evaluate")

    steps = job.get("steps", [])
    require(isinstance(steps, list) and len(steps) == 1, "closure must have one decision step")
    step = steps[0]
    environment = step.get("env", {})
    expected_results = {
        "QUALITY_RESULT": "${{ needs.docker-quality-gate.result }}",
        "CLAIMS_RESULT": "${{ needs.docker-claim-gates.result }}",
        "STAGE4_RESULT": "${{ needs.docker-stage4-gate.result }}",
    }
    require(environment == expected_results, "closure result bindings drifted")

    command = str(step.get("run", ""))
    for variable in expected_results:
        require(
            re.search(rf'"\${variable}"\s*!=\s*success', command) is not None,
            f"closure must reject non-success {variable}",
        )
    require("exit 1" in command, "closure must exit nonzero when a dependency failed")


def check_workflow() -> None:
    workflow = load_yaml(".github/workflows/ci.yml")
    require(
        workflow.get("permissions") == {"contents": "read"},
        "workflow permissions must remain read-only",
    )
    concurrency = workflow.get("concurrency", {})
    require(
        concurrency.get("cancel-in-progress") == "${{ github.event_name == 'pull_request' }}",
        "only pull-request workflows may cancel an in-progress exact-SHA run",
    )
    jobs = workflow.get("jobs", {})
    require(isinstance(jobs, dict), "workflow jobs must be a mapping")
    for job_name in (*QUALIFICATION_JOBS, "exact-sha-closure"):
        require(job_name in jobs, f"workflow is missing required job {job_name}")

    for job_name in QUALIFICATION_JOBS:
        image = jobs[job_name].get("env", {}).get("VISA_DEV_IMAGE")
        require(image == EXACT_SHA_IMAGE, f"{job_name}: Docker image is not exact-SHA tagged")

    check_action_pins(jobs)
    check_checkouts(jobs)
    check_cache_paths(jobs)
    check_dependency_caches(jobs)
    check_claim_matrix(jobs["docker-claim-gates"])
    check_quality_and_stage4(jobs)
    check_upload("docker-claim-gates", jobs["docker-claim-gates"], "claim_gate")
    check_upload("docker-stage4-gate", jobs["docker-stage4-gate"], "stage4_system_gate")
    check_closure(jobs["exact-sha-closure"])


def main() -> int:
    try:
        check_ignores()
        check_compose()
        check_workflow()
    except (ContractError, OSError) as error:
        print(f"CI contract violation: {error}", file=sys.stderr)
        return 1
    print("CI build/cache/evidence contract passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
