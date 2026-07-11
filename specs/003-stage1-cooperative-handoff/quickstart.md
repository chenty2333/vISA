# Stage 1 Verification Quickstart

Run the architecture checks and focused production tests while editing:

```sh
python3 scripts/check-dependency-direction.py
cargo test --locked -p contract_core -p semantic_core -p visa_profile \
  -p substrate_api -p substrate_host -p visa_runtime -p visa_wasmtime \
  -p handoff-component -p visa-conformance -p visa-system
```

Run both local acceptance tiers:

```sh
scripts/ci-gate.sh full
scripts/ci-gate.sh system
```

Then run both tiers in the declared development container:

```sh
scripts/run-docker-ci-gate.sh full
scripts/run-docker-ci-gate.sh system
```

`full` runs the fast gates plus the complete workspace, feature, no-std, Wasm,
kernel, benchmark, and report acceptance path. `system` is a standalone real
Stage 1 lifecycle and independent evidence-validation gate; it intentionally
does not repeat `full`. A complete local or Docker acceptance run therefore
requires both commands. All Cargo invocations in these gates use the locked
dependency graph.

The system command prints the retained artifact root and bundle path. Verify a
retained result again through the independent CLI when investigating it:

```sh
cargo run --locked -p visa-conformance --bin visa-conformance -- \
  stage1 <bundle.json> <artifact-root>
```

## Completion evidence

The final post-fix gate run on 2026-07-11 passed local `fast`, `full`, and
`system`, followed by Docker `full` and `system`.

- Local `system`: 31/31 cases; bundle ID
  `stage1-1783732398663-06da27e97f68c1d4`; bundle SHA-256
  `e9df43f25fe1ce0c4694334b7017c94c3f8fefb4e523368ff850f9ccf5ca4f11`;
  retained at `target/visa-system/stage1-n4uQSS/`.
- Docker `system`: 31/31 cases; bundle ID
  `stage1-1783732557698-06da27e97f68c1d4`; bundle SHA-256
  `4dce8188071c59bd2f95eabfac6aa840d62f46d64b6e146b9e3459976ccf240a`;
  retained at `/workspace/target/visa-system/stage1-AmsyvI/` in the Compose
  target volume.

Both system runs invoked the independent validator successfully. These retained
paths are diagnostic evidence from this completion run, not stable checked-in
artifacts or portable path contracts.
