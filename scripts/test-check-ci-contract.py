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
