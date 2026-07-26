# Historical comparison oracles

Status: frozen read-only comparison implementations. Not active code.

Every package in this directory is a pre-reset historical implementation kept
only as a differential comparison oracle. Governance pins this layout:

- `scripts/check-stage1-deletions.py` requires each oracle package to exist,
  to set `publish = false`, and to declare
  `package.metadata.visa.role = "comparison-oracle"`, and rejects any active
  package whose dependency chain reaches this directory.
- `scripts/ci-gate.sh full` still executes
  `cargo test -p substrate-oracle --features conformance` as a comparison
  gate.

Do not fix, extend, or refactor code here; the value of an oracle is that it
does not move. If a directory name here collides with an active crate, the
active one lives outside `crates/oracle/` and the package names differ by an
`-oracle` suffix:

| Directory here            | Package name          | Active counterpart              |
| ------------------------- | --------------------- | ------------------------------- |
| `semantic_core/`          | `semantic-oracle`     | `crates/core/semantic_core`     |
| `contract_core/`          | `contract-oracle`     | `crates/core/contract_core`     |
| `substrate_api/`          | `substrate-oracle`    | `crates/backend/substrate_api`  |
| `visa_profile/`           | `profile-oracle`      | `crates/core/visa_profile`      |
| `visa_runtime/`           | `runtime-oracle`      | `crates/runtime/visa_runtime`   |
| `visa_wasmtime/`          | `wasmtime-oracle`     | `crates/runtime/visa_wasmtime`  |
| `visa-conformance/`       | `conformance-oracle`  | `crates/testing/visa-conformance` |
| `replay_snapshot/`        | `replay_snapshot`     | none (historical shell)         |
| `wasm_app/`               | `wasm_app`            | none (historical shell)         |

When searching or editing the active spine, exclude this directory first:
`grep -rn <pattern> crates --include='*.rs' --exclude-dir=oracle`.
