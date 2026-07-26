# Structure and governance disposition

Status: working note, not a canonical truth source. Not part of the seven
canonical documents. Records analysis and options; it grants no claim and
changes no gate by itself.

Last reviewed: 2026-07-26.

## Scope

Two structural debts and one governance-cost question, with the constraints
that currently pin each of them. "Blocked by" below means an executable gate
fails if the change is made naively, not that the change is forbidden
forever.

## 1. `crates/oracle/` (about 145k lines, 9 packages)

Finding: the largest directory in the repository is frozen comparison code.
Directory names collide with active crates (`semantic_core`, `visa_runtime`,
`visa_wasmtime`, `visa_profile`, `substrate_api`, `contract_core`,
`visa-conformance` each exist twice), which taxes every search and every new
contributor.

Pinned by:

- `scripts/check-stage1-deletions.py` requires the oracle packages to exist
  in workspace metadata with `publish = false` and the `comparison-oracle`
  role, pins `replay_snapshot`/`wasm_app` manifest paths, and forbids active
  packages from depending on anything under `crates/oracle/`.
- `scripts/ci-gate.sh full` runs
  `cargo test -p substrate-oracle --features conformance`.

Disposition taken now: `crates/oracle/README.md` documents the frozen role
and the name-collision table; no code moved.

Options if the collision tax grows (in increasing blast radius):

1. Keep layout; rely on `--exclude-dir=oracle` search discipline (status
   quo, cost stays).
2. Rename oracle directories to `<name>_oracle/` (package names unchanged).
   Requires updating root `Cargo.toml` members and any oracle path aliases,
   the two pinned manifest paths in `check-stage1-deletions.py`, and
   regenerating `Cargo.lock`. Gates that key on package names
   (`substrate-oracle` test, dependency direction) are unaffected.
3. Move `crates/oracle/` to a separate workspace under `legacy/`. Blocked
   by: `check-stage1-deletions.py` metadata requirements, the `full` gate
   oracle test, and `--locked` metadata assumptions. Requires a deliberate
   gate revision and should be treated as a Stage-0-style governance change,
   not a cleanup.

## 2. `crates/services/` (13 packages, about 8.4k lines)

Finding: no reverse dependencies anywhere in the workspace; the kernel
carries its own supervisor service implementations. These are dangling
leaves that still cost `cargo test --workspace` time and reader attention.

Pinned by: nothing hard. `check-stage1-deletions.py` only concerns the two
service names that already moved to oracle. No claim references these paths.

Disposition taken now: `crates/services/README.md` marks the frozen status.

Options:

1. Status quo with the README marker (taken).
2. Drop the 13 packages from workspace `members` without deleting files.
   Reversible in one commit; they stop compiling in `--workspace` runs, so
   bit-rot becomes invisible — acceptable for retained history, but record
   the decision in the Roadmap if taken.
3. Delete the directory (history remains in Git and in the
   `pre-architecture-reset-2026-07-11` tag). Cleanest, destructive to the
   working tree; needs an explicit maintainer decision, not a cleanup
   commit.

Recommendation: option 2 or 3 at the next governance-touching commit; there
is no evidence value in recompiling these crates on every push.

## 3. Governance cost observations

These are recorded as facts with options; none of them is applied, because
each interacts with the claim-closure machinery.

### 3.1 CI runs everything on every push

`on: push` has no branch or path filter, and eleven of the twelve jobs run
Docker builds with 120–180 minute timeouts.

Do NOT add path filters: claim promotion requires the complete workflow to
pass at the exact governance SHA, and governance commits are frequently
documentation/registry-only — a path filter would make those SHAs unable to
produce a closure run at all.

Safer options, in order:

1. Branch-filter `push` to `master` plus a `claim/**` naming convention for
   qualification branches; feature-branch review still gets full coverage
   through pull requests. Requires a matching expectation update in
   `scripts/check-ci-contract.py` and its mutation tests.
2. Keep triggers, but make the six claim lanes conditional on a
   `[claim-gate]` commit-message marker or label for pull requests only,
   never for push. Higher contract churn; only worth it if PR volume grows.

### 3.2 `CI_JOB_COUNT = 12` is a hardcoded constant

`scripts/claim_archive.py:30` binds online verification to exactly twelve
job executions. Any job addition silently invalidates future closure
verification until the constant moves. Option: derive the expected job set
from `claims/registry.json` `workflow_bindings` plus the parsed workflow
instead of an integer, with the mutation tests updated to inject a
mismatched lane. Until then, treat "add a CI job" as a five-file change:
`ci.yml`, `claims/registry.json`, `check-ci-contract.py` expectations, its
tests, and `claim_archive.py`.

### 3.3 `check-release-contract.py` weight

6,144 lines of checker plus 3,367 lines of checker tests protect the frozen
0.1 release contract, which currently has no external consumer. The check is
cheap at runtime, so removing it buys little; the real cost is edit
friction. Option: none needed now. Revisit only if the 0.1 contract itself
is superseded; do not weaken the checker while the contract it freezes is
still the published product boundary.

### 3.4 Nightly artifact-dependency fallout

The workspace's `x86_64-unknown-none` artifact dependency breaks
`cargo tree` (panic in the feature resolver), which also blocks
`cargo audit`/`cargo deny` workflows that shell out to the resolver. This is
an upstream cargo bug; the practical workaround and its limits are recorded
in `docs/paper/arm-stage4-runbook.md`.
