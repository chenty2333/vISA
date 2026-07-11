# Stage 1 Spine Modularization Verification

## Baseline

The accepted pre-refactor baseline is commit
`be7b75918a83d29c19949324f020c87dd661032d`.

The pre-refactor registry passed all 31 cases and the independent verifier.
Its ephemeral bundle path, ID, and whole-bundle hash are intentionally not
retained as current evidence: source provenance changes when files move, and
the only current retained roots are recorded in the final closeout below.

## Edit Loop

```sh
cargo fmt --all --check
cargo test --locked -p semantic_core -p visa-system
cargo check --locked -p semantic_core --target x86_64-unknown-none
python3 scripts/check-dependency-direction.py
python3 scripts/check-stage1-deletions.py
```

## Focused Post-Move Verification

The modularized Stage 1 spine passed the focused host checks on 2026-07-11:

```sh
cargo fmt --all --check
cargo check --locked -p visa-system
cargo test --locked -p semantic_core -p visa-system
cargo check --locked -p semantic_core --target x86_64-unknown-none
cargo clippy --locked -p semantic_core -p visa-system --all-targets -- -D warnings
bash -n scripts/check-file-size.sh
scripts/check-file-size.sh
git diff --check -- crates/testing/visa-system/src/runner.rs \
  crates/testing/visa-system/src/runner scripts/check-file-size.sh \
  specs/004-stage1-spine-modularization
```

Observed results:

- `semantic_core`: 12 unit tests passed and the no-std check passed.
- `visa-system`: 21 library tests, 1 binary test, and 1 live-handoff
  integration test passed; doc tests also passed.
- Strict Clippy completed with no warnings for both focused packages and all
  their targets.
- The tracked first-party file-size check passed for the active Stage 1 spine.
  Oversized oracle/reference and later-stage files were reported as
  informational and were not changed by this slice.
- `runner.rs` and `semantic_core/src/lib.rs` are thin module roots. Detailed
  responsibility-file sizes may evolve; `scripts/check-file-size.sh` is the
  maintained size boundary.

These focused results do not replace the system, independent-verifier, or
Docker acceptance runs below.

## Acceptance

```sh
scripts/ci-gate.sh fast
scripts/ci-gate.sh full
scripts/ci-gate.sh system
scripts/run-docker-ci-gate.sh full
scripts/run-docker-ci-gate.sh system
git diff --check
```

Record the fresh retained bundle, verifier result, case count, and the semantic
comparison dimensions from `plan.md` after the final run.

## Final Closeout Evidence

The final acceptance run passed focused tests, strict Clippy, no-std,
dependency/deletion/file-size/toolchain checks, the host and Docker `full`
gates, both Stage 1 system gates, and independent bundle verification:

| Environment | Root | Bundle ID | Evidence SHA-256 | Result |
| --- | --- | --- | --- | --- |
| Host | `target/visa-system/stage1-pVx1kC` | `stage1-1783800561117-06da27e97f68c1d4` | `cbfca6e2fca0b73f4666c5bdd016e0ce13408b2c5a89913c1e2d84ff4b62c0e7` | 31/31; verifier passed |
| Docker linux/amd64 | `/workspace/target/visa-system/stage1-V3WnAk` | `stage1-1783803040332-06da27e97f68c1d4` | `aa9b499766a13761e135f411ecb5c1e73e7df0b51b38b3dbdc3c0a7fbf67257a` | 31/31; verifier passed |

The Docker root is retained in the default Compose named volume and is valid
only through the container's `/workspace` view. The final bundles were
reverified without substituting a host pathname:

```sh
target/debug/visa-conformance stage1 \
  target/visa-system/stage1-pVx1kC/stage1-evidence.json \
  target/visa-system/stage1-pVx1kC
docker compose -f compose.yaml run --rm -T dev \
  /workspace/target/debug/visa-conformance stage1 \
  /workspace/target/visa-system/stage1-V3WnAk/stage1-evidence.json \
  /workspace/target/visa-system/stage1-V3WnAk
```

Both bundles bind source digest
`23a65724d16edf0474a23e0266931272ff82834cac8e59fab70863eb675246fd`,
toolchain digest
`33bd760b0d42eee90cf79af2bd3a30df1de6535fb53d34ebbb2542625adc9bf3`,
profile digest
`da6babca82e0e34ac32c591d9494fb77d8d2c6f7b4201c7feb67669400da2241`,
configuration digest
`06da27e97f68c1d45919dcacf70b7d92ef1bae0cafbfa3ad8e0ddef9128eb07b`,
and authority-policy digest
`853697466509d7b106bf7f099e870a934c42047c42d85f9750ca21d4a3c6ab3e`.
The host Component digest is
`4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b`;
the Docker Component digest is
`d4f1a2e8bfacb0659d26569850a0f489c861a021ecad4cf068ca5d67748e04eb`.

All stable case outcomes, exit statuses, configuration and policy digests,
fault schedules, and authority/fencing projections match the accepted
pre-refactor behavior. Each final-state digest equals its own replay digest.
Raw timing-bearing snapshot, trace, and state digests are not cross-run
constants; Stage 2 compares the accepted observable projection.

The final environment uses `nightly-2026-06-07`. The Docker image is
`sha256:ca7c91e726c7fbce36cb152fcf56b8bc89d7c773ef7d4e3817cd8ad5051bfce0`
on linux/amd64. The obsolete repository-local `AGENTS.md`, `.specify/`, and
`.agents/skills/` remain absent.
