# Implementation Plan: Stage 1 Cooperative Stateful Component Handoff

Status: complete

## Design Commitments

`contract_core` owns the portable vocabulary. `semantic_core` is the only
state-transition authority. `visa_runtime::Coordinator` is the only production
sequencer and commit path. Providers enforce effects and leases but do not
invent semantic commands or events. Snapshots, reports, and views are derived
from the canonical state and journal.

The system fixture builds a real WIT component. Each case starts isolated
source and destination worker processes. They use distinct Wasmtime stores and
SQLite journal scopes while sharing durable KV, leases, authority, and handoff
commit truth. Fault controls are enabled only in `visa-system` and are selected
before a provider is moved into a coordinator; production APIs expose no
mutable provider bypass.

## Delivery Sequence

1. Stabilize the contract, reducer, profile, provider, coordinator, Component
   Model adapter, and structural conformance validator.
2. Prove one real successful handoff with Component, SQLite, host timer, replay,
   and provider-boundary source fencing.
3. Add persistent JSON-lines workers and a parent runner for all registry cases.
4. Materialize content-addressed artifacts and an execution evidence bundle.
5. Run the independent conformance CLI against the bundle.
6. Add local/Docker `system` gates and update claim documentation.
7. Delete replaced production paths and audit dependency/name residue.

## System Artifacts

Each case directory contains, when applicable:

- the canonical snapshot envelope and component state;
- source and destination semantic journal traces;
- timer and KV binding receipts;
- raw source/destination protocol transcripts and assertion results;
- fault schedule and observed ownership/fencing result; and
- final and replayed canonical state digests.

The bundle records actual file hashes and relative paths. It is invalid if an
artifact is absent, changed, duplicated, outside the root, or disagrees on
bundle/case/execution/handoff/snapshot/component/profile identity.

## Validation

```sh
scripts/ci-gate.sh fast
scripts/ci-gate.sh full
scripts/ci-gate.sh system
scripts/run-docker-ci-gate.sh full
scripts/run-docker-ci-gate.sh system
python3 scripts/check-dependency-direction.py
git diff --check
```

The `system` gate must retain its generated bundle long enough to invoke the
separate `visa-conformance stage1 <bundle> <artifact-root>` process. Tests that
only construct fixture JSON cannot satisfy this plan.

## Constraints

- Do not add a second command/event/journal schema in a worker or provider.
- Do not whitelist an adapter dependency on a workload artifact.
- Do not serialize Wasmtime stores, host instants, credentials, or native
  handles.
- Do not convert unknown outcomes into assumed failure.
- Do not activate a destination before durable commit.
- Do not let a pre-commit rejection fence the source permanently.
- Do not claim unsupported runtime, ISA, substrate, security, or performance
  matrix cells.
