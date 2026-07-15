#!/usr/bin/env python3
"""Self-tests for the Nexus qualification v2 verifier and lock generator."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


CHECKER_PATH = Path(__file__).with_name("check-nexus-handoff-qualification.py")
GENERATOR_PATH = Path(__file__).with_name(
    "generate-nexus-handoff-qualification-lock.py"
)
SPEC = importlib.util.spec_from_file_location("nexus_qualification_checker", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Nexus qualification checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def write(path: Path, value: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode("utf-8") if isinstance(value, str) else value)


def run_git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


class QualificationFixture:
    def __init__(self, parent: Path) -> None:
        self.checkout = parent / "checkout"
        self.lock_root = parent / "lock-root"
        self.lock_path = self.lock_root / "qualification-lock.json"
        self.baseline_lock_path = parent / "joint-source-lock.json"
        self.checkout.mkdir()
        self.lock_root.mkdir()
        self.matrix_path = "evaluation/handoff-admission/fault-matrix.toml"
        self.registry_path = "kernel/nexus-ostd/src/cser/effect_registry.rs"
        self.substrate_path = "crates/cser-transition-gates/src/handoff.rs"
        self.source_files = [
            "src/model.rs",
            self.registry_path,
            self.substrate_path,
            self.matrix_path,
        ]
        write(self.checkout / "src/model.rs", "pub const MODEL: &str = \"same-boot\";\n")
        write(self.checkout / self.registry_path, "pub struct HandoffIndex;\n")
        write(self.checkout / self.substrate_path, "pub struct HandoffGate;\n")
        write(self.checkout / self.matrix_path, self.matrix_text())
        write(self.checkout / ".gitignore", "/target/\n")
        run_git(self.checkout, "init", "-q")
        run_git(self.checkout, "config", "user.name", "Qualification Test")
        run_git(self.checkout, "config", "user.email", "qualification@example.invalid")
        run_git(
            self.checkout,
            "remote",
            "add",
            "origin",
            "git@github.com:chenty2333/Nexus.git",
        )
        run_git(self.checkout, "add", ".")
        run_git(self.checkout, "commit", "-q", "-m", "fixture")
        self.revision = run_git(self.checkout, "rev-parse", "HEAD")
        self.source_fingerprint = CHECKER.compute_source_fingerprint(
            self.checkout, self.source_files
        )
        self.lock = self.lock_document()
        write(self.lock_path, json_bytes(self.lock))
        write(
            self.baseline_lock_path,
            json_bytes(
                {
                    "schema": "visa.joint-handoff-qualification-source-lock.v1",
                    "evidence_status": "reference-only-not-nexus-qualified",
                    "visa": {},
                    "nexus": {
                        "repository": "https://github.com/chenty2333/Nexus",
                        "revision": self.revision,
                        "execution": "reference-peer-only",
                    },
                    "joint_artifact": {},
                    "protocol_schema": {},
                    "neutral_wire_contract": {},
                    "machine_contract": {},
                    "refinement_map": {},
                    "abstract_case_registry": {},
                    "case_registry": {},
                }
            ),
        )

    @staticmethod
    def matrix_text() -> str:
        return """\
schema = "nexus.research.handoff-admission.fault-matrix.v1"
profile = "docs/rfcs/0002-handoff-admission-profile.md"
expected_count = 1
fault_model = "same-boot-crash-stop-retry-reorder-lost-ack"
ownership_log = "trusted-non-equivocating-no-rollback-tcb"
host_reboot_claimed = false
malicious_rollback_claimed = false
production_registry_modified = false
required_invariants = ["AtMostOneExecutionAuthority"]
negative_mutations = ["activate-before-closure"]

[[cell]]
id = "freeze-before-first-commit"
event_order = ["PrepareIntent", "FreezeAdmission", "FirstCommitProbe"]
expected = "first commit rejects"
tla_witness = "FreezeBeforeCommitAbsent"
rust_test = "freeze_before_first_commit"
kill_condition = "post-freeze commit is admitted"
"""

    def lock_document(self) -> dict[str, object]:
        matrix = (self.checkout / self.matrix_path).read_bytes()
        return {
            "schema": "visa.nexus-handoff-qualification-lock.v2",
            "evidence_status": "same-boot-nexus-handoff-admission-only",
            "claim_id": "bounded-joint-handoff-refinement-v1",
            "nexus": {
                "repository": "https://github.com/chenty2333/Nexus",
                "revision": self.revision,
                "analyzed_baseline_revision": self.revision,
                "role": "nexus-local-handoff-admission-only",
                "receipt_schema": "nexus.research.handoff-admission.v2",
                "summary_schema": "nexus.research.handoff-admission.summary.v2",
                "command": "./x research handoff-admission",
                "prospective": True,
                "source_fingerprint": self.source_fingerprint,
                "source_files": self.source_files,
            },
            "artifacts": {
                "receipt": {"path": "target/research/handoff-admission/receipt.json"},
                "matrix": {
                    "path": self.matrix_path,
                    "sha256": hashlib.sha256(matrix).hexdigest(),
                },
                "tla_log": {"path": "target/research/handoff-admission/tla.log"},
                "rust_oracle_log": {
                    "path": "target/research/handoff-admission/rust-oracle.log"
                },
                "summary": {"path": "target/research/handoff-admission/summary.txt"},
            },
            "fault_contract": {
                "matrix_schema": "nexus.research.handoff-admission.fault-matrix.v1",
                "profile": "docs/rfcs/0002-handoff-admission-profile.md",
                "cells": 1,
                "required_invariants": ["AtMostOneExecutionAuthority"],
                "negative_mutations": ["activate-before-closure"],
                "fault_model": "same-boot-crash-stop-retry-reorder-lost-ack",
                "ownership_log_tcb": "trusted-non-equivocating-no-rollback-tcb",
            },
            "formal": {
                "specification": "HandoffAdmissionCser",
                "declarative_tla": True,
                "temporal_properties": 2,
                "configurations": [
                    {
                        "config": "HandoffAdmissionCserSafetyMC.cfg",
                        "heading": "HandoffAdmissionCser complete local safety graph",
                        "generated": 10,
                        "distinct": 7,
                        "depth": 4,
                        "states_left_on_queue": 0,
                        "property_mode": "safety-with-postcommit-retention",
                        "temporal_branches": 0,
                    },
                    {
                        "config": "HandoffAdmissionCserProgressMC.cfg",
                        "heading": "HandoffAdmissionCser conditional local closure progress",
                        "generated": 20,
                        "distinct": 11,
                        "depth": 5,
                        "states_left_on_queue": 0,
                        "property_mode": "conditional-progress-2-temporal-branches",
                        "temporal_branches": 2,
                    },
                ],
                "witnesses": [
                    {
                        "invariant": "FreezeBeforeCommitAbsent",
                        "description": "freeze wins before first commit",
                    }
                ],
            },
            "rust_oracle": {
                "independent_from_production_registry": True,
                "suites": [
                    {
                        "kind": "sequence",
                        "heading": "==> handoff-admission sequence oracle",
                        "tests": ["freeze_before_first_commit"],
                    },
                    {
                        "kind": "property",
                        "heading": "==> handoff-admission property oracle",
                        "tests": ["arbitrary_population_preserves_invariants"],
                    },
                    {
                        "kind": "loom",
                        "heading": "==> handoff-admission Loom oracle",
                        "tests": ["freeze_and_commit_have_one_winner"],
                    },
                ],
            },
            "production_registry": {
                "registry_source": self.registry_path,
                "substrate_source": self.substrate_path,
                "handoff_index_owned_by_registry": True,
                "admission_and_publication_share_registry_lock": True,
                "commit_close_reuses_revoke_lifecycle": True,
                "local_fault_cells_mapped": 0,
                "external_intent_only_cells": 1,
                "real_ostd_execution_claimed": False,
                "suites": [
                    {
                        "kind": "substrate_loom",
                        "heading": "==> handoff-admission substrate Loom refinement",
                        "tests": ["freeze_and_source_mutation_have_one_outer_lock_winner"],
                    },
                    {
                        "kind": "registry_sequence",
                        "heading": "==> handoff-admission production Registry refinement",
                        "tests": [
                            "production_freeze_abort_ack_and_thaw_reopen_exact_admission"
                        ],
                    },
                ],
            },
            "boundaries": dict(CHECKER.BOUNDARY_VALUES),
        }

    def create_evidence(self, root: Path, *, timestamp: int, variant: int) -> None:
        matrix = (self.checkout / self.matrix_path).read_bytes()
        tla = f"""\
==> HandoffAdmissionCser complete local safety graph
Model checking completed. No error has been found.
10 states generated, 7 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 4.
Finished in 0{variant}s
==> HandoffAdmissionCser reachability: freeze wins before first commit
Error: Invariant FreezeBeforeCommitAbsent is violated.
Error: The behavior up to this point is:
COVERAGE_RESULT PASS freeze wins before first commit
==> HandoffAdmissionCser conditional local closure progress
Implied-temporal checking--satisfiability problem has 2 branches.
Model checking completed. No error has been found.
20 states generated, 11 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 5.
Finished in 0{variant}s
""".encode("utf-8")
        rust = f"""\
==> handoff-admission sequence oracle
running 1 tests
test freeze_before_first_commit ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0{variant}s
==> handoff-admission property oracle
running 1 tests
test arbitrary_population_preserves_invariants ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0{variant}s
==> handoff-admission Loom oracle
running 1 tests
test freeze_and_commit_have_one_winner ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0{variant}s
==> handoff-admission substrate Loom refinement
running 1 tests
test freeze_and_source_mutation_have_one_outer_lock_winner ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0{variant}s
==> handoff-admission production Registry refinement
running 1 tests
test production_freeze_abort_ack_and_thaw_reopen_exact_admission ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0{variant}s
""".encode("utf-8")
        summary = self.summary_text().encode("utf-8")
        paths = self.lock["artifacts"]
        write(root / paths["matrix"]["path"], matrix)
        write(root / paths["tla_log"]["path"], tla)
        write(root / paths["rust_oracle_log"]["path"], rust)
        write(root / paths["summary"]["path"], summary)
        receipt = self.receipt_document(timestamp, tla, rust, summary)
        write(root / paths["receipt"]["path"], json_bytes(receipt))

    def summary_text(self) -> str:
        receipt_path = self.lock["artifacts"]["receipt"]["path"]
        return f"""\
schema=nexus.research.handoff-admission.summary.v2
status=passed
prospective=true
command=./x research handoff-admission
revision={self.revision}
worktree_dirty=false
source_fingerprint={self.source_fingerprint}
fault_cells=1
required_invariants=1
negative_mutations=1
complete_configurations=2
reachability_witnesses=1
temporal_properties=2
rust_sequence_tests=1
rust_property_tests=1
rust_loom_tests=1
production_registry_sequence_tests=1
production_registry_loom_tests=1
same_boot_only=true
ownership_log_non_equivocation_in_tcb=true
production_registry_modified=true
production_registry_refinement_checked=true
host_reboot_claimed=false
malicious_rollback_claimed=false
joint_visa_execution_claimed=false
real_ostd_smp_claimed=false
canonical_v0_1_catalog_modified=false
receipt={receipt_path}
"""

    def receipt_document(
        self,
        timestamp: int,
        tla: bytes,
        rust: bytes,
        summary: bytes,
    ) -> dict[str, object]:
        matrix = (self.checkout / self.matrix_path).read_bytes()
        return {
            "schema": "nexus.research.handoff-admission.v2",
            "status": "passed",
            "prospective": True,
            "command": "./x research handoff-admission",
            "revision": self.revision,
            "worktree_dirty": False,
            "source_fingerprint": self.source_fingerprint,
            "source_files": self.source_files,
            "generated_unix_seconds": timestamp,
            "fault_contract": {
                "matrix": self.matrix_path,
                "matrix_sha256": hashlib.sha256(matrix).hexdigest(),
                "cells": 1,
                "invariants": 1,
                "negative_mutations": 1,
                "fault_model": "same-boot-crash-stop-retry-reorder-lost-ack",
                "ownership_log_tcb": "trusted-non-equivocating-no-rollback-tcb",
            },
            "formal": {
                "specification": "HandoffAdmissionCser",
                "declarative_tla": True,
                "complete_configurations": 2,
                "configurations": [
                    {
                        "config": "HandoffAdmissionCserSafetyMC.cfg",
                        "status": "complete",
                        "generated": 10,
                        "distinct": 7,
                        "depth": 4,
                        "states_left_on_queue": 0,
                        "property_mode": "safety-with-postcommit-retention",
                    },
                    {
                        "config": "HandoffAdmissionCserProgressMC.cfg",
                        "status": "complete",
                        "generated": 20,
                        "distinct": 11,
                        "depth": 5,
                        "states_left_on_queue": 0,
                        "property_mode": "conditional-progress-2-temporal-branches",
                    },
                ],
                "reachability_witnesses": 1,
                "witnesses": [
                    {
                        "invariant": "FreezeBeforeCommitAbsent",
                        "description": "freeze wins before first commit",
                        "status": "reachable",
                    }
                ],
                "temporal_properties": 2,
            },
            "rust_oracle": {
                "independent_from_production_registry": True,
                "sequence_tests": 1,
                "property_tests": 1,
                "loom_tests": 1,
                "total_tests": 3,
            },
            "production_registry": {
                "registry_source": self.registry_path,
                "substrate_source": self.substrate_path,
                "handoff_index_owned_by_registry": True,
                "admission_and_publication_share_registry_lock": True,
                "commit_close_reuses_revoke_lifecycle": True,
                "sequence_tests": 1,
                "loom_tests": 1,
                "total_tests": 2,
                "local_fault_cells_mapped": 0,
                "external_intent_only_cells": 1,
                "real_ostd_execution_claimed": False,
            },
            "boundaries": dict(CHECKER.BOUNDARY_VALUES),
            "logs": {
                "tla": self.lock["artifacts"]["tla_log"]["path"],
                "rust_oracle": self.lock["artifacts"]["rust_oracle_log"]["path"],
                "summary": self.lock["artifacts"]["summary"]["path"],
            },
            "digests": {
                "tla_sha256": hashlib.sha256(tla).hexdigest(),
                "rust_oracle_sha256": hashlib.sha256(rust).hexdigest(),
                "summary_sha256": hashlib.sha256(summary).hexdigest(),
            },
        }

    def verify(self, evidence_root: Path) -> None:
        receipt = self.lock["artifacts"]["receipt"]["path"]
        CHECKER.verify(
            self.lock_path,
            self.checkout,
            Path(receipt),
            evidence_root_path=evidence_root,
            lock_root=self.lock_root,
        )

    def generate_lock(self, output: Path) -> subprocess.CompletedProcess[str]:
        receipt = self.checkout / self.lock["artifacts"]["receipt"]["path"]
        return subprocess.run(
            [
                sys.executable,
                str(GENERATOR_PATH),
                "--checkout",
                str(self.checkout),
                "--receipt",
                str(receipt),
                "--output",
                str(output),
                "--baseline-source-lock",
                str(self.baseline_lock_path),
            ],
            cwd=CHECKER.ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )


class QualificationVerifierTests(unittest.TestCase):
    def with_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], QualificationFixture]:
        temporary = tempfile.TemporaryDirectory(prefix="nexus-qualification-test-")
        return temporary, QualificationFixture(Path(temporary.name))

    def test_relocated_runs_with_different_timestamp_and_log_bytes_pass(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            first = Path(temporary.name) / "download-one"
            second = Path(temporary.name) / "download-two"
            first.mkdir()
            second.mkdir()
            fixture.create_evidence(first, timestamp=1, variant=1)
            fixture.create_evidence(second, timestamp=2, variant=2)
            fixture.verify(first)
            fixture.verify(second)

    def test_emit_lock_values_uses_the_strict_lock_parser(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            name = f"nexus-qualification-lock-test-{self.id().rsplit('.', 1)[-1]}"
            target = CHECKER.ROOT / "target" / name
            try:
                target.mkdir(parents=True)
                lock_path = target / "lock.json"
                shutil.copyfile(fixture.lock_path, lock_path)
                relative = lock_path.relative_to(CHECKER.ROOT)
                result = subprocess.run(
                    [
                        sys.executable,
                        str(CHECKER_PATH),
                        "--lock",
                        str(relative),
                        "--emit-lock-values",
                    ],
                    cwd=CHECKER.ROOT,
                    check=True,
                    stdout=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(
                    result.stdout.splitlines(),
                    [
                        fixture.revision,
                        fixture.revision,
                        fixture.source_fingerprint,
                        fixture.lock["artifacts"]["matrix"]["sha256"],
                    ],
                )
            finally:
                shutil.rmtree(target, ignore_errors=True)

    def test_cli_verifies_a_relocated_evidence_root(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            evidence = Path(temporary.name) / "download"
            evidence.mkdir()
            fixture.create_evidence(evidence, timestamp=3, variant=3)
            name = f"nexus-qualification-cli-test-{self.id().rsplit('.', 1)[-1]}"
            target = CHECKER.ROOT / "target" / name
            try:
                target.mkdir(parents=True)
                lock_path = target / "lock.json"
                shutil.copyfile(fixture.lock_path, lock_path)
                result = subprocess.run(
                    [
                        sys.executable,
                        str(CHECKER_PATH),
                        "--lock",
                        str(lock_path.relative_to(CHECKER.ROOT)),
                        "--checkout",
                        str(fixture.checkout),
                        "--evidence-root",
                        str(evidence),
                        "--receipt",
                        fixture.lock["artifacts"]["receipt"]["path"],
                    ],
                    cwd=CHECKER.ROOT,
                    check=True,
                    stdout=subprocess.PIPE,
                    text=True,
                )
                self.assertIn("Nexus handoff qualification passed", result.stdout)
            finally:
                shutil.rmtree(target, ignore_errors=True)

    def test_dirty_checkout_is_rejected(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            evidence = Path(temporary.name) / "download"
            evidence.mkdir()
            fixture.create_evidence(evidence, timestamp=1, variant=1)
            write(fixture.checkout / "untracked", "dirty\n")
            with self.assertRaisesRegex(CHECKER.QualificationError, "dirty"):
                fixture.verify(evidence)

    def test_executed_revision_must_descend_from_the_analyzed_baseline(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            evidence = Path(temporary.name) / "download"
            evidence.mkdir()
            fixture.create_evidence(evidence, timestamp=1, variant=1)
            fixture.lock["nexus"]["analyzed_baseline_revision"] = "a" * 40
            write(fixture.lock_path, json_bytes(fixture.lock))
            with self.assertRaisesRegex(CHECKER.QualificationError, "analyzed baseline ancestry"):
                fixture.verify(evidence)

    def test_claim_and_local_role_are_fixed(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            fixture.lock["claim_id"] = "different-claim"
            write(fixture.lock_path, json_bytes(fixture.lock))
            with self.assertRaisesRegex(CHECKER.QualificationError, "claim_id"):
                CHECKER.load_lock(fixture.lock_path, lock_root=fixture.lock_root)

            fixture.lock["claim_id"] = "bounded-joint-handoff-refinement-v1"
            fixture.lock["nexus"]["role"] = "joint-live-wire"
            write(fixture.lock_path, json_bytes(fixture.lock))
            with self.assertRaisesRegex(CHECKER.QualificationError, "nexus.role"):
                CHECKER.load_lock(fixture.lock_path, lock_root=fixture.lock_root)

    def test_lock_cannot_disable_prospective_boundary(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            fixture.lock["nexus"]["prospective"] = False
            write(fixture.lock_path, json_bytes(fixture.lock))
            with self.assertRaisesRegex(CHECKER.QualificationError, "must remain true"):
                CHECKER.load_lock(fixture.lock_path, lock_root=fixture.lock_root)

    def test_rehashed_tla_stat_tamper_is_rejected_semantically(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            evidence = Path(temporary.name) / "download"
            evidence.mkdir()
            fixture.create_evidence(evidence, timestamp=1, variant=1)
            paths = fixture.lock["artifacts"]
            tla_path = evidence / paths["tla_log"]["path"]
            tampered = tla_path.read_bytes().replace(
                b"10 states generated", b"11 states generated", 1
            )
            write(tla_path, tampered)
            receipt_path = evidence / paths["receipt"]["path"]
            receipt = json.loads(receipt_path.read_text())
            receipt["digests"]["tla_sha256"] = hashlib.sha256(tampered).hexdigest()
            write(receipt_path, json_bytes(receipt))
            with self.assertRaisesRegex(CHECKER.QualificationError, "graph statistics"):
                fixture.verify(evidence)

    def test_duplicate_receipt_key_is_rejected(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            evidence = Path(temporary.name) / "download"
            evidence.mkdir()
            fixture.create_evidence(evidence, timestamp=1, variant=1)
            receipt_path = evidence / fixture.lock["artifacts"]["receipt"]["path"]
            raw = receipt_path.read_text()
            raw = raw.replace('  "status": "passed",\n', '  "status": "passed",\n  "status": "passed",\n', 1)
            write(receipt_path, raw)
            with self.assertRaisesRegex(CHECKER.QualificationError, "duplicate key"):
                fixture.verify(evidence)

    def test_nonclaim_flip_is_rejected(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            evidence = Path(temporary.name) / "download"
            evidence.mkdir()
            fixture.create_evidence(evidence, timestamp=1, variant=1)
            receipt_path = evidence / fixture.lock["artifacts"]["receipt"]["path"]
            receipt = json.loads(receipt_path.read_text())
            receipt["boundaries"]["host_reboot_claimed"] = True
            write(receipt_path, json_bytes(receipt))
            with self.assertRaisesRegex(CHECKER.QualificationError, "non-claims"):
                fixture.verify(evidence)

    def test_v2_production_registry_refinement_is_required(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            evidence = Path(temporary.name) / "download"
            evidence.mkdir()
            fixture.create_evidence(evidence, timestamp=1, variant=1)
            receipt_path = evidence / fixture.lock["artifacts"]["receipt"]["path"]
            receipt = json.loads(receipt_path.read_text())
            receipt["production_registry"]["commit_close_reuses_revoke_lifecycle"] = False
            write(receipt_path, json_bytes(receipt))
            with self.assertRaisesRegex(CHECKER.QualificationError, "production_registry"):
                fixture.verify(evidence)

    def test_fault_matrix_must_retain_the_independent_first_round_boundary(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            contradictory = fixture.matrix_text().replace(
                "production_registry_modified = false",
                "production_registry_modified = true",
                1,
            )
            with self.assertRaisesRegex(
                CHECKER.QualificationError,
                "fault matrix production_registry_modified",
            ):
                CHECKER.parse_matrix(contradictory.encode(), fixture.lock)

    def test_v2_registry_refinement_boundary_cannot_be_disabled(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            evidence = Path(temporary.name) / "download"
            evidence.mkdir()
            fixture.create_evidence(evidence, timestamp=1, variant=1)
            receipt_path = evidence / fixture.lock["artifacts"]["receipt"]["path"]
            receipt = json.loads(receipt_path.read_text())
            receipt["boundaries"]["production_registry_refinement_checked"] = False
            write(receipt_path, json_bytes(receipt))
            with self.assertRaisesRegex(CHECKER.QualificationError, "non-claims"):
                fixture.verify(evidence)

    def test_generator_builds_and_self_verifies_the_exact_v2_lock(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            fixture.create_evidence(fixture.checkout, timestamp=1, variant=1)
            output = Path(temporary.name) / "generated-lock.json"
            result = fixture.generate_lock(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            generated = json.loads(output.read_text())
            self.assertEqual(generated, fixture.lock)
            CHECKER.verify(
                output,
                fixture.checkout,
                Path(fixture.lock["artifacts"]["receipt"]["path"]),
                evidence_root_path=fixture.checkout,
                lock_root=Path(temporary.name),
            )

    def test_generator_rejects_a_dirty_checkout_without_output(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            fixture.create_evidence(fixture.checkout, timestamp=1, variant=1)
            write(fixture.checkout / "untracked", "dirty\n")
            output = Path(temporary.name) / "generated-lock.json"
            result = fixture.generate_lock(output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("dirty", result.stderr)
            self.assertFalse(output.exists())

    def test_generator_rejects_a_v1_receipt_without_output(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            fixture.create_evidence(fixture.checkout, timestamp=1, variant=1)
            receipt_path = fixture.checkout / fixture.lock["artifacts"]["receipt"]["path"]
            receipt = json.loads(receipt_path.read_text())
            receipt["schema"] = "nexus.research.handoff-admission.v1"
            write(receipt_path, json_bytes(receipt))
            output = Path(temporary.name) / "generated-lock.json"
            result = fixture.generate_lock(output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("schema", result.stderr)
            self.assertFalse(output.exists())

    def test_generator_rejects_a_fabricated_source_fingerprint(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            fixture.create_evidence(fixture.checkout, timestamp=1, variant=1)
            receipt_path = fixture.checkout / fixture.lock["artifacts"]["receipt"]["path"]
            receipt = json.loads(receipt_path.read_text())
            receipt["source_fingerprint"] = "a" * 64
            write(receipt_path, json_bytes(receipt))
            output = Path(temporary.name) / "generated-lock.json"
            result = fixture.generate_lock(output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source fingerprint", result.stderr)
            self.assertFalse(output.exists())

    def test_symlinked_artifact_is_rejected(self) -> None:
        temporary, fixture = self.with_fixture()
        with temporary:
            evidence = Path(temporary.name) / "download"
            evidence.mkdir()
            fixture.create_evidence(evidence, timestamp=1, variant=1)
            summary_path = evidence / fixture.lock["artifacts"]["summary"]["path"]
            outside = Path(temporary.name) / "outside-summary"
            shutil.copyfile(summary_path, outside)
            summary_path.unlink()
            summary_path.symlink_to(outside)
            with self.assertRaisesRegex(CHECKER.QualificationError, "cannot read contained"):
                fixture.verify(evidence)


if __name__ == "__main__":
    unittest.main()
