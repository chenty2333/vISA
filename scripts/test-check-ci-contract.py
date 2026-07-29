#!/usr/bin/env python3
"""Mutation tests for claim-to-workflow binding enforcement."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "scripts/check-ci-contract.py"
SPEC = importlib.util.spec_from_file_location("ci_contract_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)


class ClaimWorkflowBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        workflow = CONTRACT.load_yaml(".github/workflows/ci.yml")
        cls.jobs = workflow["jobs"]
        cls.registry = CONTRACT.CLAIM_REGISTRY

    def setUp(self) -> None:
        CONTRACT.CLAIM_REGISTRY = copy.deepcopy(self.registry)

    def tearDown(self) -> None:
        CONTRACT.CLAIM_REGISTRY = self.registry

    def test_repository_bindings_are_valid(self) -> None:
        CONTRACT.check_claim_workflow_bindings(copy.deepcopy(self.jobs))

    def test_buildx_bootstrap_is_pinned_and_ordered(self) -> None:
        CONTRACT.check_buildx_bootstrap(copy.deepcopy(self.jobs))

    def test_docker_base_image_is_digest_pinned(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        CONTRACT.check_docker_base_identity(dockerfile)

    def test_mutable_docker_base_image_is_rejected(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        mutable = dockerfile.replace(CONTRACT.DOCKER_BASE_IMAGE, "debian:stable-slim")
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"exact digest-pinned Debian identity",
        ):
            CONTRACT.check_docker_base_identity(mutable)

    def test_docker_hub_mirror_drift_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"Docker Hub mirror configuration drifted",
        ):
            CONTRACT.check_buildkit_config(
                {"registry": {"docker.io": {"mirrors": ["docker.io"]}}}
            )

    def test_missing_buildkit_preload_is_rejected(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        steps = jobs["docker-quality-gate"]["steps"]
        steps[:] = [
            step
            for step in steps
            if step.get("name") != CONTRACT.BUILDKIT_PRELOAD_STEP
        ]
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"expected exactly one workflow step named Preload pinned BuildKit image",
        ):
            CONTRACT.check_buildx_bootstrap(jobs)

    def test_mutable_buildkit_or_buildx_identity_is_rejected(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        setup = CONTRACT.steps_using(
            jobs["docker-quality-gate"], "docker/setup-buildx-action@"
        )[0]
        setup["with"]["version"] = "latest"
        setup["with"]["driver-opts"] = "image=moby/buildkit:buildx-stable-1"
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"Buildx, BuildKit, or registry mirror identity drifted",
        ):
            CONTRACT.check_buildx_bootstrap(jobs)

    def test_missing_buildkit_mirror_binding_is_rejected(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        setup = CONTRACT.steps_using(
            jobs["docker-quality-gate"], "docker/setup-buildx-action@"
        )[0]
        del setup["with"]["buildkitd-config"]
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"Buildx, BuildKit, or registry mirror identity drifted",
        ):
            CONTRACT.check_buildx_bootstrap(jobs)

    def test_swapped_claim_identities_are_rejected(self) -> None:
        bindings = {
            binding["id"]: binding
            for binding in CONTRACT.CLAIM_REGISTRY["workflow_bindings"]
        }
        bindings["stage1"]["claims"][0]["id"] = (
            "bounded-regular-file-continuity"
        )
        bindings["stage3a"]["claims"][0]["id"] = (
            "cooperative-stateful-component-handoff"
        )

        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"matrix binding/claims/tier/artifact catalog differs",
        ):
            CONTRACT.check_claim_workflow_bindings(copy.deepcopy(self.jobs))

    def test_missing_bound_job_is_rejected(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        del jobs["docker-stage4-gate"]
        with self.assertRaisesRegex(CONTRACT.ContractError, r"workflow job .* is absent"):
            CONTRACT.check_claim_workflow_bindings(jobs)

    def test_matrix_tier_drift_is_rejected(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        include = jobs["docker-claim-gates"]["strategy"]["matrix"]["include"]
        include[0]["tier"] = "system-stage3a"
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"matrix binding/claims/tier/artifact catalog differs",
        ):
            CONTRACT.check_claim_workflow_bindings(jobs)

    def test_wanco_lane_cannot_build_the_unused_dev_image(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        builds = CONTRACT.steps_using(
            jobs["docker-claim-gates"], "docker/build-push-action@"
        )
        del builds[0]["if"]
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"must skip the unused vISA development image build",
        ):
            CONTRACT.check_wanco_carrier_host_lane(jobs["docker-claim-gates"])

    def test_wanco_lane_cannot_inspect_an_omitted_dev_image(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        inspection = CONTRACT.step_with_name(
            jobs["docker-claim-gates"], "Inspect exact-SHA Docker image"
        )
        inspection["if"] = "${{ always() }}"
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"must skip inspection of the omitted development image",
        ):
            CONTRACT.check_wanco_carrier_host_lane(jobs["docker-claim-gates"])

    def test_wanco_canonical_evidence_closure_is_wired(self) -> None:
        gate = (ROOT / "scripts/ci-gate.sh").read_text(encoding="utf-8")
        runner = (ROOT / "scripts/run-wanco-carrier-matrix.sh").read_text(
            encoding="utf-8"
        )
        CONTRACT.check_wanco_canonical_evidence_closure(gate, runner)

    def test_wanco_runner_cannot_require_unprovisioned_ripgrep(self) -> None:
        gate = (ROOT / "scripts/ci-gate.sh").read_text(encoding="utf-8")
        runner = (ROOT / "scripts/run-wanco-carrier-matrix.sh").read_text(
            encoding="utf-8"
        )
        mutated = runner.replace("grep -Fq", "rg -q", 1)
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"baseline host tools and not assume ripgrep",
        ):
            CONTRACT.check_wanco_canonical_evidence_closure(gate, mutated)

    def test_wanco_ci_cannot_drop_canonical_run_validation(self) -> None:
        gate = (ROOT / "scripts/ci-gate.sh").read_text(encoding="utf-8")
        runner = (ROOT / "scripts/run-wanco-carrier-matrix.sh").read_text(
            encoding="utf-8"
        )
        mutated = gate.replace(
            "canonical six-dimensional matrix-run closure",
            "custom receipt only",
        )
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"validate the canonical evidence-matrix run",
        ):
            CONTRACT.check_wanco_canonical_evidence_closure(mutated, runner)

    def test_wanco_negative_cannot_become_an_untyped_rejection(self) -> None:
        gate = (ROOT / "scripts/ci-gate.sh").read_text(encoding="utf-8")
        runner = (ROOT / "scripts/run-wanco-carrier-matrix.sh").read_text(
            encoding="utf-8"
        )
        mutated = runner.replace(
            "observed_outer_findings == expected_outer_findings",
            "bool(observed_outer_findings)",
        )
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"structural negative with semantic mismatches",
        ):
            CONTRACT.check_wanco_canonical_evidence_closure(gate, mutated)

    def test_wanco_negative_requires_exact_lifecycle_finding_triplet(self) -> None:
        gate = (ROOT / "scripts/ci-gate.sh").read_text(encoding="utf-8")
        runner = (ROOT / "scripts/run-wanco-carrier-matrix.sh").read_text(
            encoding="utf-8"
        )
        mutated = runner.replace(
            '        "invalid-committed-handoff-lifecycle",\n',
            "",
            1,
        )
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"exact per-case semantic finding triplet",
        ):
            CONTRACT.check_wanco_canonical_evidence_closure(gate, mutated)

    def test_wanco_positive_requires_zero_candidate_findings(self) -> None:
        gate = (ROOT / "scripts/ci-gate.sh").read_text(encoding="utf-8")
        runner = (ROOT / "scripts/run-wanco-carrier-matrix.sh").read_text(
            encoding="utf-8"
        )
        mutated = runner.replace(
            'assert not value["candidate_validation"]["findings"]',
            'assert value["candidate_validation"]["findings"] is not None',
            1,
        )
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"zero findings and positive equivalence",
        ):
            CONTRACT.check_wanco_canonical_evidence_closure(gate, mutated)

    def test_nonmatrix_artifact_drift_is_rejected(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        uploads = CONTRACT.steps_using(
            jobs["docker-stage4-gate"], "actions/upload-artifact@"
        )
        uploads[0]["with"]["name"] = "substituted-evidence"
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"stage4: workflow artifact upload differs from registry",
        ):
            CONTRACT.check_claim_workflow_bindings(jobs)

    def test_null_artifact_binding_rejects_an_upload(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        jobs["exact-sha-closure"]["steps"].append(
            {
                "uses": "actions/upload-artifact@invalid",
                "with": {"name": "unregistered-evidence"},
            }
        )
        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"exact-sha-closure: null artifact binding must not upload evidence",
        ):
            CONTRACT.check_claim_workflow_bindings(jobs)

    def test_claim_closure_job_rejects_write_permission(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        jobs["claim-closure-verification"]["permissions"]["contents"] = "write"

        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"only read-only archive permissions",
        ):
            CONTRACT.check_claim_closure_verification(
                jobs["claim-closure-verification"]
            )

    def test_claim_closure_job_requires_history_baseline_binding(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        del jobs["claim-closure-verification"]["steps"][1]["env"][
            "CLAIM_CLOSURE_BASELINE"
        ]

        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"token, repository, or baseline binding drifted",
        ):
            CONTRACT.check_claim_closure_verification(
                jobs["claim-closure-verification"]
            )

    def test_exact_closure_requires_claim_closure_verification(self) -> None:
        jobs = copy.deepcopy(self.jobs)
        jobs["exact-sha-closure"]["needs"].remove(
            "claim-closure-verification"
        )

        with self.assertRaisesRegex(
            CONTRACT.ContractError,
            r"must depend on claim closure verification",
        ):
            CONTRACT.check_closure(jobs["exact-sha-closure"])


if __name__ == "__main__":
    unittest.main()
