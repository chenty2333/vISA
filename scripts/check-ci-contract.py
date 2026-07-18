#!/usr/bin/env python3
"""Fail closed when the checked CI/cache/evidence topology drifts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent.parent
CURRENT_STATUS_PATH = "status/current-capabilities.toml"

EXPECTED_CLAIMS = {
    "stage1": ("system", "stage1-system-evidence"),
    "jco-node": ("system-jco-node", "stage2b-jco-node-system-evidence"),
    "legacy-stage2": ("system-stage2", "stage2-cross-execution-path-evidence"),
    "strict-stage2": ("system-stage2-strict", "strict-stage2-docker-evidence"),
    "stage3a": ("system-stage3a", "stage3a-regular-file-system-evidence"),
    "stage3b": ("system-stage3b", "stage3b-logical-request-system-evidence"),
}

STAGE_QUALIFICATION_JOBS = (
    "docker-quality-gate",
    "docker-claim-gates",
    "docker-stage4-gate",
)
JOINT_REFERENCE_JOB = "docker-joint-handoff-reference-gate"
JOINT_NEXUS_JOB = "docker-joint-handoff-nexus-qualification"
VISA_DOCKER_GATE_JOBS = (*STAGE_QUALIFICATION_JOBS, JOINT_REFERENCE_JOB)
CLOSURE_JOBS = (*VISA_DOCKER_GATE_JOBS, JOINT_NEXUS_JOB)

NEXUS_LOCK_PATH = (
    "third_party/joint-handoff-qualification/nexus-qualification-lock.json"
)
NEXUS_REPOSITORY = "chenty2333/Nexus"
NEXUS_CHECKOUT_PATH = ".ci-nexus"
NEXUS_ARTIFACT_ROOT = ".ci-artifacts/nexus-handoff-qualification"
NEXUS_EFFECT_PEER = ".ci-nexus/target/debug/nexus-effect-peer"
NEXUS_PROCESS_ARTIFACT_ROOT = ".ci-artifacts/nexus-process-joint-cell"
NEXUS_LOGICAL_ARTIFACT_ROOT = ".ci-artifacts/logical-request-lost-ack-cell"
NEXUS_ADMISSION_ARTIFACT_ROOT = ".ci-artifacts/logical-request-admission-cell"
NEXUS_GATE_LOG = ".ci-artifacts/nexus-visa-same-boot-qualification-ci.log"
NEXUS_QUALIFICATION_ARTIFACT = "nexus-visa-same-boot-qualification-evidence"
NEXUS_CLAIM_BOUNDARY = (
    "Claim boundary: clean exact-SHA same-boot Nexus-local refinement, "
    "process-backed joint handoff, and one bounded admission-ordered Wasmtime "
    "logical-request/lost-ACK handoff. The admission artifact checks production "
    "Registry admission before external send, one source execution, ownership "
    "recovery, source closure and fence, destination activation, and Reconcile "
    "inside this host cell; the older logical-request dual-lost-ACK artifact remains "
    "supplemental. This is a host-build qualification, not a vISA Docker-image lane, "
    "and does not claim Registry replacement, retained tombstone, "
    "cross-host/reboot/permanent-source-loss recovery, "
    "Byzantine/rollback/freshness or TEE/KMS, raw TCP capture, real service "
    "death/OSTD/IRQ/SMP, a production live-wire adapter, general exactly-once "
    "semantics, or performance."
)

EXACT_SHA_IMAGE = "visa-dev:${{ github.sha }}"
RETENTION_POLICY = "${{ github.event_name == 'pull_request' && 3 || 14 }}"
CARGO_CACHE_KEY = (
    "docker-cargo-${{ runner.os }}-"
    "${{ hashFiles('Cargo.lock', 'rust-toolchain.toml', 'Dockerfile', "
    "'compose.yaml', 'compose.ci.yaml') }}"
)
IMAGE_REVISION_LABEL = "org.opencontainers.image.revision=${{ github.sha }}"
IMAGE_SOURCE_LABEL = (
    "org.opencontainers.image.source="
    "${{ github.server_url }}/${{ github.repository }}"
)
LOCKED_CARGO_WRAPPERS = (
    "scripts/run-logical-request-admission-cell.sh",
    "scripts/run-logical-request-lost-ack-cell.sh",
    "scripts/run-nexus-process-joint-cell.sh",
    "scripts/run-host-ltp-log-adapter.sh",
    "scripts/run-visa-bench-conformance.sh",
    "scripts/run-visa-ltp-conformance.sh",
    "scripts/run-visa-ltp-manifest.sh",
    "scripts/run-visa-ltp-single.sh",
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


def step_with_name(job: dict[str, Any], name: str) -> dict[str, Any]:
    steps = job.get("steps", [])
    matches = [step for step in steps if isinstance(step, dict) and step.get("name") == name]
    require(len(matches) == 1, f"expected exactly one workflow step named {name}")
    return matches[0]


def check_ignores() -> None:
    for relative in (".gitignore", ".dockerignore"):
        lines = (ROOT / relative).read_text(encoding="utf-8").splitlines()
        require(
            "/.ci-artifacts/" in lines,
            f"{relative} must exclude the generated .ci-artifacts directory",
        )
        require(
            "/.ci-nexus/" in lines,
            f"{relative} must exclude the generated .ci-nexus checkout",
        )
        require(
            "/evidence/" in lines,
            f"{relative} must exclude compose.ci.yaml's in-worktree evidence bind alias",
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
    require(
        environment.get("GITHUB_SHA") == "${GITHUB_SHA:-}",
        "compose.ci.yaml must pass the workflow SHA into qualification containers",
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


def check_toolchain_alignment() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    matches = re.findall(r"^ARG RUST_TOOLCHAIN=([^\s]+)$", dockerfile, flags=re.MULTILINE)
    require(len(matches) == 1, "Dockerfile must declare exactly one RUST_TOOLCHAIN default")

    try:
        with (ROOT / "rust-toolchain.toml").open("rb") as file:
            toolchain_document = tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ContractError(f"cannot parse rust-toolchain.toml: {error}") from error
    toolchain = toolchain_document.get("toolchain", {})
    require(isinstance(toolchain, dict), "rust-toolchain.toml must contain [toolchain]")
    require(
        toolchain.get("channel") == matches[0],
        "Dockerfile RUST_TOOLCHAIN must match rust-toolchain.toml channel",
    )


def check_locked_cargo_wrappers() -> None:
    cargo_command = re.compile(r"\bcargo\s+(?:run|bench)\b")
    for relative in LOCKED_CARGO_WRAPPERS:
        for line_number, line in enumerate(
            (ROOT / relative).read_text(encoding="utf-8").splitlines(), start=1
        ):
            if cargo_command.search(line):
                require(
                    "--locked" in line or "--frozen" in line,
                    f"{relative}:{line_number}: qualification Cargo command is not lockfile-bound",
                )


def check_current_status() -> None:
    try:
        with (ROOT / CURRENT_STATUS_PATH).open("rb") as file:
            status = tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ContractError(f"cannot parse {CURRENT_STATUS_PATH}: {error}") from error

    def require_string(mapping: dict[str, Any], field: str) -> str:
        value = mapping.get(field)
        require(
            isinstance(value, str) and bool(value.strip()),
            f"current capability ledger {field} must be a nonempty string",
        )
        return value

    def require_string_list(mapping: dict[str, Any], field: str) -> list[str]:
        value = mapping.get(field)
        require(
            isinstance(value, list)
            and bool(value)
            and all(isinstance(item, str) and bool(item.strip()) for item in value)
            and len(value) == len(set(value)),
            f"current capability ledger {field} must contain unique nonempty strings",
        )
        return value

    def require_sha(mapping: dict[str, Any], field: str, length: int = 40) -> str:
        value = require_string(mapping, field)
        require(
            re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None,
            f"current capability ledger {field} must be a lowercase {length}-hex digest",
        )
        return value

    require(status.get("schema") == "visa.current-capability-ledger.v1", "current capability ledger schema drifted")
    require(status.get("ledger_revision") == 1, "current capability ledger revision drifted")
    require(
        re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", require_string(status, "as_of"))
        is not None,
        "current capability ledger as_of must use YYYY-MM-DD",
    )
    require(
        status.get("classification") == "current-checkpoints-not-release-evidence",
        "current capability ledger classification drifted",
    )
    require(
        status.get("accepted_joint_claim") == "bounded-joint-handoff-refinement-v1"
        and status.get("accepted_joint_implementation")
        == "d3b07f1114cb49e26dd62fb252a895022ac2a743",
        "current ledger must not rewrite the accepted joint implementation identity",
    )
    require(
        status.get("neutral_wire_v1") == "frozen"
        and status.get("nexus_native_wire_v1") == "frozen"
        and status.get("new_provider_capabilities")
        == "v2-or-explicit-versioned-extension",
        "wire v1 freeze or provider v2 policy drifted",
    )
    require(
        status.get("policy")
        == {
            "checkpoint": "backward-pointer-to-exact-claims-revision",
            "supersession": "append-or-replace-current-entry-with-explicit-revision-and-boundary",
            "external_evidence": "never-upgrades-a-separately-owned-project-claim",
            "archive": "github-actions-artifacts-are-ephemeral-transport",
        },
        "current capability ledger policy drifted",
    )

    checkpoints = status.get("checkpoint")
    require(
        isinstance(checkpoints, list)
        and len(checkpoints) == status.get("checkpoint_count") == 2,
        "current capability ledger must contain exactly two distinguished checkpoints",
    )
    require(
        all(isinstance(checkpoint, dict) for checkpoint in checkpoints),
        "current capability checkpoints must be TOML tables",
    )
    ids = [require_string(checkpoint, "id") for checkpoint in checkpoints]
    require(len(ids) == len(set(ids)), "current capability checkpoint IDs must be unique")
    by_kind = {require_string(checkpoint, "kind"): checkpoint for checkpoint in checkpoints}
    require(
        set(by_kind) == {"accepted", "current"},
        "current capability ledger must distinguish one accepted and one current checkpoint",
    )
    accepted = by_kind["accepted"]
    current = by_kind["current"]
    for checkpoint in checkpoints:
        require(
            re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}",
                require_string(checkpoint, "recorded_on"),
            )
            is not None,
            "checkpoint recorded_on must use YYYY-MM-DD",
        )
        require_string(checkpoint, "status")
        require_string(checkpoint, "claim_id")
        require_string_list(checkpoint, "capabilities")
        require_string_list(checkpoint, "boundaries")
        for source in require_string_list(checkpoint, "sources"):
            source_file, _, source_fragment = source.partition("#")
            source_path = ROOT / source_file
            require(
                bool(source_file)
                and ("#" not in source or bool(source_fragment))
                and not source_file.startswith("/")
                and ".." not in Path(source_file).parts
                and source_path.is_file()
                and not source_path.is_symlink(),
                f"current capability ledger source is not a regular repository file: {source}",
            )

    require(
        accepted.get("status") == "accepted-exact-sha-historical-boundary"
        and require_sha(accepted, "revision") == status.get("accepted_joint_implementation")
        and accepted.get("claim_id") == status.get("accepted_joint_claim")
        and accepted.get("logical_request_lane") == "supplemental-post-hoc-dual-lost-ack"
        and "supplemental-external-effect-completes-before-native-register-prepare-commit"
        in accepted.get("boundaries", []),
        "accepted supplemental lane identity or historical boundary drifted",
    )

    current_revision = require_sha(current, "revision")
    nexus_revision = require_sha(current, "nexus_revision")
    qualification_lock_sha256 = require_sha(
        current, "nexus_qualification_lock_sha256", 64
    )
    artifact_digest = require_string(current, "artifact_digest")
    require(
        current.get("status") == "exact-sha-ci-checked-not-canonical-or-archived"
        and current_revision != accepted.get("revision")
        and nexus_revision != current_revision
        and type(current.get("ci_run")) is int
        and current.get("ci_run", 0) > 0
        and re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_digest) is not None
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            require_string(current, "artifact_expires_at"),
        )
        is not None
        and current.get("archive_status")
        == "ephemeral-actions-artifact-not-long-term-checkpoint",
        "current checkpoint exact-revision, CI, or ephemeral-artifact identity is malformed",
    )
    require_string(current, "artifact_name")

    try:
        qualification_lock_bytes = (ROOT / NEXUS_LOCK_PATH).read_bytes()
        qualification_lock = json.loads(qualification_lock_bytes)
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot parse {NEXUS_LOCK_PATH}: {error}") from error
    require(
        isinstance(qualification_lock, dict),
        f"{NEXUS_LOCK_PATH} must contain a JSON object",
    )
    locked_nexus = qualification_lock.get("nexus")
    require(
        qualification_lock.get("schema") == "visa.nexus-handoff-qualification-lock.v2"
        and isinstance(locked_nexus, dict)
        and locked_nexus.get("revision") == nexus_revision,
        "current capability ledger Nexus revision must match the qualification lock",
    )
    require(
        hashlib.sha256(qualification_lock_bytes).hexdigest()
        == qualification_lock_sha256,
        "current capability ledger qualification-lock digest does not match repository bytes",
    )

    try:
        ancestry = subprocess.run(
            ["git", "merge-base", "--is-ancestor", current_revision, "HEAD"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise ContractError(f"cannot verify current checkpoint ancestry: {error}") from error
    require(
        ancestry.returncode == 0,
        "current capability ledger revision must be an ancestor of repository HEAD",
    )


def check_joint_expectation_wiring() -> None:
    source = (ROOT / "scripts/ci-gate.sh").read_text(encoding="utf-8")
    expected = """\
    expectation_args=(
        "$visa_sha"
        "${locked[nexus_revision]}"
        "${locked[neutral_revision]}"
        "${locked[neutral_tree]}"
        "${locked[neutral_bundle_sha256]}"
        "${locked[source_lock_sha256]}"
        "${locked[protocol_sha256]}"
        "${locked[machine_contract_sha256]}"
        "${locked[refinement_map_sha256]}"
        "${locked[abstract_registry_sha256]}"
    )"""
    require(
        expected in source,
        "joint publisher/verifier expectations must retain their keyed semantic order",
    )
    require(
        source.count('"${expectation_args[@]}"') == 3,
        "joint runner must pass the same ten provenance expectations to the publisher "
        "and both verifier invocations",
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
    for job_name in VISA_DOCKER_GATE_JOBS:
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
    for job_name in VISA_DOCKER_GATE_JOBS:
        checkouts = steps_using(jobs[job_name], "actions/checkout@")
        require(len(checkouts) == 1, f"{job_name}: expected exactly one checkout")
        require(
            checkouts[0].get("with", {}).get("persist-credentials") == "false",
            f"{job_name}: checkout credentials must not persist",
        )
        if job_name == "docker-quality-gate":
            require(
                checkouts[0].get("with", {}).get("fetch-depth") == "0",
                "docker-quality-gate: full history is required to prove "
                "capability-checkpoint ancestry",
            )


def check_exact_sha_images(jobs: dict[str, Any]) -> None:
    expected_labels = {IMAGE_REVISION_LABEL, IMAGE_SOURCE_LABEL}
    for job_name in VISA_DOCKER_GATE_JOBS:
        job = jobs[job_name]
        image = job.get("env", {}).get("VISA_DEV_IMAGE")
        require(image == EXACT_SHA_IMAGE, f"{job_name}: Docker image is not exact-SHA tagged")

        builds = steps_using(job, "docker/build-push-action@")
        require(len(builds) == 1, f"{job_name}: expected exactly one Docker image build")
        settings = builds[0].get("with", {})
        require(settings.get("context") == ".", f"{job_name}: Docker build context drifted")
        require(settings.get("file") == "Dockerfile", f"{job_name}: Dockerfile path drifted")
        require(settings.get("load") == "true", f"{job_name}: Docker image must be loaded")
        require(
            settings.get("tags") == "${{ env.VISA_DEV_IMAGE }}",
            f"{job_name}: Docker build must use the exact-SHA image tag",
        )
        labels = {line.strip() for line in str(settings.get("labels", "")).splitlines()}
        require(labels == expected_labels, f"{job_name}: Docker image identity labels drifted")

        inspect = step_with_name(job, "Inspect exact-SHA Docker image")
        command = str(inspect.get("run", ""))
        require(
            "docker image inspect" in command
            and "org.opencontainers.image.revision" in command
            and '"$VISA_DEV_IMAGE"' in command
            and 'test "$actual_revision" = "$GITHUB_SHA"' in command,
            f"{job_name}: exact-SHA image inspection must verify the OCI revision label",
        )


def check_upload(
    job_name: str,
    job: dict[str, Any],
    gate_id: str,
    *,
    include_cancelled: bool = False,
) -> None:
    uploads = steps_using(job, "actions/upload-artifact@")
    require(len(uploads) == 1, f"{job_name}: expected exactly one artifact upload")
    if include_cancelled:
        expected_condition = (
            "${{ always() && steps." + gate_id + ".outcome != 'skipped' }}"
        )
    else:
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
    require("set -o pipefail" in command, "claim matrix gate must protect tee")


def check_quality_stage4_and_joint_reference(jobs: dict[str, Any]) -> None:
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
    require("set -o pipefail" in command, "Stage 4 gate must protect tee")

    joint_job = jobs[JOINT_REFERENCE_JOB]
    require(
        joint_job.get("name") == "Docker joint handoff reference-only gate",
        "joint handoff job must remain explicitly reference-only",
    )
    joint = step_with_id(joint_job, "joint_reference_gate")
    command = str(joint.get("run", ""))
    require(
        "scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-joint-handoff"
        in command,
        "joint handoff reference job must run the dedicated Docker system tier",
    )
    require(
        ".ci-artifacts/joint-handoff-reference-ci.log" in command,
        "joint handoff reference job must retain its gate log",
    )
    require("set -o pipefail" in command, "joint handoff reference gate must protect tee")
    uploads = steps_using(joint_job, "actions/upload-artifact@")
    require(len(uploads) == 1, "joint handoff reference job must upload one artifact")
    require(
        uploads[0].get("with", {}).get("name")
        == "joint-handoff-reference-system-evidence",
        "joint handoff artifact name must remain explicitly reference-only",
    )


def check_nexus_qualification(job: dict[str, Any]) -> None:
    require(
        job.get("name") == "Nexus + vISA exact-SHA same-boot qualification",
        "Nexus qualification job name drifted",
    )
    require(
        job.get("runs-on") == "ubuntu-latest"
        and job.get("timeout-minutes") == "120",
        "Nexus qualification job must retain its bounded runner and timeout",
    )
    require(
        job.get("env", {}) == {} and "container" not in job,
        "Nexus qualification job must remain a host lane without a vISA Docker "
        "image or job container",
    )

    steps = job.get("steps", [])
    require(isinstance(steps, list), "Nexus qualification job must contain steps")
    require(
        [step.get("name") for step in steps if isinstance(step, dict)]
        == [
            "Checkout exact vISA SHA",
            "Read committed Nexus qualification lock",
            "Checkout exact locked Nexus SHA",
            "Run Nexus + vISA same-boot qualification",
            "Upload Nexus + vISA same-boot qualification evidence",
            "Remove Nexus + vISA qualification checkout and evidence from runner",
        ],
        "Nexus qualification step inventory or order drifted",
    )
    checkouts = steps_using(job, "actions/checkout@")
    require(len(checkouts) == 2, "Nexus qualification job must have exactly two checkouts")
    visa_checkout, nexus_checkout = checkouts
    require(
        visa_checkout.get("name") == "Checkout exact vISA SHA"
        and visa_checkout.get("with")
        == {
            "ref": "${{ github.sha }}",
            "persist-credentials": "false",
        },
        "Nexus qualification must first checkout the exact workflow vISA SHA",
    )

    lock_step = step_with_id(job, "nexus_lock")
    lock_command = str(lock_step.get("run", ""))
    require(
        "scripts/check-nexus-handoff-qualification.py" in lock_command
        and f"--lock {NEXUS_LOCK_PATH}" in lock_command
        and "--emit-lock-values" in lock_command,
        "Nexus revision must be parsed from the committed qualification lock",
    )
    require(
        '"${#lock_values[@]}" -ne 4' in lock_command
        and "^[0-9a-f]{40}$" in lock_command
        and 'printf \'revision=%s\\n\' "$revision" >> "$GITHUB_OUTPUT"'
        in lock_command,
        "Nexus lock step must validate and export exactly one lowercase revision",
    )
    require(
        nexus_checkout.get("name") == "Checkout exact locked Nexus SHA"
        and nexus_checkout.get("with")
        == {
            "repository": NEXUS_REPOSITORY,
            "ref": "${{ steps.nexus_lock.outputs.revision }}",
            "path": NEXUS_CHECKOUT_PATH,
            "fetch-depth": "0",
            "persist-credentials": "false",
        },
        "Nexus checkout must use the dynamic exact revision emitted by the lock step",
    )
    require(
        steps.index(visa_checkout) < steps.index(lock_step) < steps.index(nexus_checkout),
        "vISA checkout, lock parsing, and Nexus checkout order drifted",
    )

    for prefix in (
        "actions/cache@",
        "actions/cache/restore@",
        "docker/setup-buildx-action@",
        "docker/build-push-action@",
    ):
        require(
            not steps_using(job, prefix),
            "Nexus qualification must use Nexus's own pinned environment, not the "
            f"vISA image/cache path ({prefix})",
        )

    gate = step_with_id(job, "nexus_qualification")
    command = str(gate.get("run", ""))
    local_command = (
        "run_logged scripts/run-nexus-handoff-qualification.sh \\\n"
        f"  --checkout {NEXUS_CHECKOUT_PATH} \\\n"
        f"  --artifact-root {NEXUS_ARTIFACT_ROOT}"
    )
    require(
        local_command in command,
        "Nexus qualification gate source-locked wrapper command or exact arguments "
        "drifted",
    )
    require(
        "rm -rf .ci-artifacts" in command
        and "mkdir -p .ci-artifacts" in command
        and "set -Eeuo pipefail" in command
        and f"gate_log={NEXUS_GATE_LOG}" in command
        and '"$@" 2>&1 | tee -a "$gate_log"' in command,
        "Nexus qualification must retain a top-level log and fail closed across tee",
    )

    host_build = re.compile(
        rf"\(\n\s+CDPATH='' cd -- {re.escape(NEXUS_CHECKOUT_PATH)}\n"
        r"\s+cargo build --locked \\\n"
        r"\s+--package nexus-effect-peer \\\n"
        r"\s+--bin nexus-effect-peer\n"
        r'\s*\) 2>&1 \| tee -a "\$gate_log"'
    )
    require(
        host_build.search(command) is not None and "--manifest-path" not in command,
        "Nexus effect peer must be host-built from the locked Nexus toolchain cwd",
    )

    process_command = (
        "run_logged scripts/run-nexus-process-joint-cell.sh \\\n"
        f"  --nexus-checkout {NEXUS_CHECKOUT_PATH} \\\n"
        f"  --nexus-bin {NEXUS_EFFECT_PEER} \\\n"
        f"  --artifact-root {NEXUS_PROCESS_ARTIFACT_ROOT}"
    )
    logical_command = (
        "run_logged scripts/run-logical-request-lost-ack-cell.sh \\\n"
        f"  --nexus-checkout {NEXUS_CHECKOUT_PATH} \\\n"
        f"  --nexus-bin {NEXUS_EFFECT_PEER} \\\n"
        f"  --artifact-root {NEXUS_LOGICAL_ARTIFACT_ROOT}"
    )
    admission_command = (
        "run_logged scripts/run-logical-request-admission-cell.sh \\\n"
        f"  --nexus-checkout {NEXUS_CHECKOUT_PATH} \\\n"
        f"  --nexus-bin {NEXUS_EFFECT_PEER} \\\n"
        f"  --artifact-root {NEXUS_ADMISSION_ARTIFACT_ROOT}"
    )
    require(
        process_command in command,
        "Nexus process joint cell command or exact arguments drifted",
    )
    require(
        logical_command in command,
        "logical-request lost-ACK cell command or exact arguments drifted",
    )
    require(
        admission_command in command,
        "logical-request admission cell command or exact arguments drifted",
    )
    require(
        command.count("run_logged scripts/") == 4,
        "Nexus qualification must contain exactly the four locked runner commands",
    )
    ordered_commands = (
        "scripts/run-nexus-handoff-qualification.sh",
        "cargo build --locked",
        "scripts/run-nexus-process-joint-cell.sh",
        "scripts/run-logical-request-lost-ack-cell.sh",
        "scripts/run-logical-request-admission-cell.sh",
        "find .ci-artifacts -mindepth 1 -maxdepth 1",
        NEXUS_CLAIM_BOUNDARY,
    )
    command_offsets = [command.find(fragment) for fragment in ordered_commands]
    require(
        all(offset >= 0 for offset in command_offsets)
        and command_offsets == sorted(command_offsets),
        "Nexus qualification command order or claim boundary drifted",
    )
    require(
        "find .ci-artifacts -mindepth 1 -maxdepth 1 -printf '%y %f\\n'"
        in command
        and "LC_ALL=C sort" in command
        and (
            "d logical-request-admission-cell\\n"
            "d logical-request-lost-ack-cell\\n"
            "d nexus-handoff-qualification\\n"
            "d nexus-process-joint-cell\\n"
            "f nexus-visa-same-boot-qualification-ci.log"
        ) in command
        and '"$actual_inventory" != "$expected_inventory"' in command,
        "Nexus qualification top-level artifact inventory must fail closed",
    )
    require(
        "scripts/run-docker-ci-gate.sh" not in command
        and "VISA_DEV_IMAGE" not in command
        and ".ci-cache" not in command,
        "Nexus qualification must not masquerade as a vISA Docker-image lane",
    )

    uploads = steps_using(job, "actions/upload-artifact@")
    require(len(uploads) == 1, "Nexus qualification must upload exactly one artifact")
    require(
        uploads[0].get("with", {}).get("name")
        == NEXUS_QUALIFICATION_ARTIFACT,
        "Nexus qualification artifact identity drifted",
    )
    require(
        uploads[0].get("with", {}).get("path") == ".ci-artifacts/",
        "Nexus artifact upload must contain the four qualification trees and gate log",
    )


def check_closure(job: dict[str, Any]) -> None:
    require(
        job.get("name") == "Exact-SHA qualification closure",
        "closure check name must remain stable for repository policy",
    )
    needs = job.get("needs", [])
    require(
        isinstance(needs, list)
        and len(needs) == len(CLOSURE_JOBS)
        and set(needs) == set(CLOSURE_JOBS),
        "exact-SHA closure must depend on quality, Stage 1-4, joint reference, "
        "and Nexus qualification jobs",
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
        "JOINT_REFERENCE_RESULT": (
            "${{ needs.docker-joint-handoff-reference-gate.result }}"
        ),
        "JOINT_NEXUS_RESULT": (
            "${{ needs.docker-joint-handoff-nexus-qualification.result }}"
        ),
    }
    require(environment == expected_results, "closure result bindings drifted")

    command = str(step.get("run", ""))
    for variable in expected_results:
        require(
            re.search(rf'"\${variable}"\s*!=\s*success', command) is not None,
            f"closure must reject non-success {variable}",
        )
    require("exit 1" in command, "closure must exit nonzero when a dependency failed")
    require(
        "Nexus + vISA exact-SHA same-boot lane" in command
        and "${JOINT_NEXUS_RESULT}" in command,
        "closure summary must report the independent Nexus qualification result",
    )


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
    for job_name in (*CLOSURE_JOBS, "exact-sha-closure"):
        require(job_name in jobs, f"workflow is missing required job {job_name}")

    check_action_pins(jobs)
    check_checkouts(jobs)
    check_exact_sha_images(jobs)
    check_cache_paths(jobs)
    check_dependency_caches(jobs)
    check_claim_matrix(jobs["docker-claim-gates"])
    check_quality_stage4_and_joint_reference(jobs)
    check_nexus_qualification(jobs[JOINT_NEXUS_JOB])
    check_upload("docker-claim-gates", jobs["docker-claim-gates"], "claim_gate")
    check_upload("docker-stage4-gate", jobs["docker-stage4-gate"], "stage4_system_gate")
    check_upload(JOINT_REFERENCE_JOB, jobs[JOINT_REFERENCE_JOB], "joint_reference_gate")
    check_upload(
        JOINT_NEXUS_JOB,
        jobs[JOINT_NEXUS_JOB],
        "nexus_qualification",
        include_cancelled=True,
    )
    check_closure(jobs["exact-sha-closure"])


def main() -> int:
    try:
        check_ignores()
        check_compose()
        check_toolchain_alignment()
        check_locked_cargo_wrappers()
        check_current_status()
        check_joint_expectation_wiring()
        check_workflow()
    except (ContractError, OSError) as error:
        print(f"CI contract violation: {error}", file=sys.stderr)
        return 1
    print("CI build/cache/evidence contract passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
