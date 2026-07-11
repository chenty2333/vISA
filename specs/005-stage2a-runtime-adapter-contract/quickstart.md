# Stage 2a Runtime Adapter Contract Verification

## Entry Baseline

Finish `004-stage1-spine-modularization` first. Record its final retained
31/31 bundle, independent-verifier result, and semantic comparison dimensions
before adapter files begin moving. Bundle IDs and whole-bundle hashes are not
cross-refactor equality targets.

## Focused Edit Loop

After `visa_component_adapter` exists, run:

```sh
cargo fmt --all --check
cargo check --locked -p visa_component_adapter -p visa_wasmtime -p visa-system
cargo test --locked -p visa_component_adapter -p visa_wasmtime -p visa-system
cargo clippy --locked -p visa_component_adapter -p visa_wasmtime \
  -p visa-system --all-targets -- -D warnings
python3 scripts/check-dependency-direction.py
python3 scripts/check-stage1-deletions.py
```

The focused tests must include:

- golden `VISACS01` byte compatibility, deterministic round-trip, corruption,
  and trailing-data rejection;
- exhaustive normalized mapping for workload, KV, timer, binding, coordinator,
  artifact, link, instantiation, trap, and rollback failures;
- safe-point success and every existing rollback branch;
- preflight success without guest invocation or provider/coordinator mutation;
- invalid component and incompatible interface rejection before destination
  load;
- missing, stale, or selector-mismatched prepared artifact rejection;
- worker protocol round-trips for the explicit Wasmtime selector, observed
  runtime identity, and structured failure kinds; and
- proof that the selector and runtime identity are absent from portable state,
  profile, snapshot, and canonical digests.

## Acceptance

Run all local gates:

```sh
scripts/ci-gate.sh fast
scripts/ci-gate.sh full
scripts/ci-gate.sh system
```

Then run the declared container gates:

```sh
scripts/run-docker-ci-gate.sh full
scripts/run-docker-ci-gate.sh system
```

The `system` runner must explicitly select Wasmtime for both workers, execute
the unchanged 31-case registry, derive both runtime identities from worker
responses, write the existing Stage 1 evidence bundle, and invoke the separate
`visa-conformance` process. Recheck a retained bundle when diagnosing it:

```sh
cargo run --locked -p visa-conformance --bin visa-conformance -- \
  stage1 <bundle.json> <artifact-root>
```

## Preflight Acceptance Observation

The destination transcript and focused lifecycle tests must establish this
order:

```text
profile/snapshot validation
  < runtime preflight
  < Coordinator restore
  < destination prepare/bindings
  < durable commit/source fencing
  < engine instantiation
  < guest restore
  < canonical resume
```

For an invalid artifact or incompatible Component Model world, record a
structured preflight failure and show that no destination coordinator was
restored, no binding receipt or destination journal entry was created, no guest
export ran, and source ownership remained usable. For an operational failure
after commit, show instead that the source remains fenced.

## Completion Evidence to Record

- focused test and strict-Clippy results;
- dependency-direction result proving no reverse concrete-runtime edge;
- retained local and Docker bundle paths, IDs, SHA-256 values, and 31/31 counts;
- independent verifier results for both retained bundles;
- requested, observed, and bundled Wasmtime implementation/version identities;
- preflight no-execution and pre-commit no-mutation test results; and
- semantic comparison results listed in `plan.md`.

Do not record a Runtime B, cross-runtime, cross-ISA, or completed Stage 2 claim
from these results.

## Final Stage 2a Closeout

The final host and Docker acceptance runs used the pinned
`nightly-2026-06-07` toolchain and passed `full`, dependency/deletion/file-size
checks, strict active-spine Clippy, all focused adapter tests, the complete
Wasmtime system gate, and independent Stage 1 verification:

| Environment | Root | Bundle ID | Evidence SHA-256 | Result |
| --- | --- | --- | --- | --- |
| Host | `target/visa-system/stage1-pVx1kC` | `stage1-1783800561117-06da27e97f68c1d4` | `cbfca6e2fca0b73f4666c5bdd016e0ce13408b2c5a89913c1e2d84ff4b62c0e7` | 31/31; verifier passed |
| Docker linux/amd64 | `/workspace/target/visa-system/stage1-V3WnAk` | `stage1-1783803040332-06da27e97f68c1d4` | `aa9b499766a13761e135f411ecb5c1e73e7df0b51b38b3dbdc3c0a7fbf67257a` | 31/31; verifier passed |

Both bundles report `visa_wasmtime` 0.2.0 with Wasmtime 43.0.2. The shared
`VISACS01` codec and runtime-neutral adapter lifecycle are the Stage 2a result.
Their only claim is `cooperative-stateful-component-handoff`; they do not
claim Runtime B, cross-runtime, cross-ISA, or completed strict Roadmap Stage 2.

The retained provenance binds the same source, toolchain, profile,
configuration, and authority-policy digests recorded in the Stage 1 closeout.
The host Component digest is
`4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b`;
the Docker Component digest is
`d4f1a2e8bfacb0659d26569850a0f489c861a021ecad4cf068ca5d67748e04eb`.
The Docker bundle remains a named-volume artifact and must be rechecked at its
exact `/workspace` path, as shown in the Stage 1 closeout. Stage 2b and Stage
2c have separate completion records, and their cross-execution-path result
does not close strict Roadmap Stage 2.
