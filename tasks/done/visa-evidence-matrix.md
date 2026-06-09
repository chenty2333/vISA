# vISA Evidence Matrix Result

## Goal
Define the minimum mature vISA evidence matrix.

## Result
Completed. The minimum mature evidence matrix is now durable documentation and executable conformance data. It fixes three required mature claims: semantic model, portable artifact execution, and real target substrate execution. Each entry names its report suite/gate, artifact gate, required artifact kinds, profile rule, proving specs/tests, and known risks.

The source of truth lives in `visa_conformance::minimum_mature_evidence_matrix()` and is available through `cargo run -p visa-conformance -- evidence-matrix-json`. `validate-sample` now validates the conformance catalog, sample reports, and evidence matrix, and the Docker CI `visa-conformance` gate runs that command.

## Evidence
Verified:

- `cargo fmt --all --check`
- `cargo test -p visa-conformance` with 68 passed tests
- `cargo run -p visa-conformance -- validate-sample`
- `cargo run -p visa-conformance -- evidence-matrix-json`
- Docker `scripts/run-docker-ci-gate.sh --ci-cache --skip-build visa-conformance`
- legacy-name literal scan outside git metadata, `target`, and `.ci-cache`
- legacy filename scan outside git metadata, `target`, and `.ci-cache`
- `git diff --check`

## Remaining Risk
The matrix defines the minimum mature evidence standard and validates its shape. It does not create the missing real-target runner; real target substrate execution remains unproven until a report and artifact bundle from a real board or QEMU substrate path passes the matrix gates.
