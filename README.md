# vISA

**Portable code is only half the story. Portable state moves; native resources
are rebound.**

vISA is a research prototype for capability-safe state continuity across
WebAssembly Component Model runtimes and host substrates. It defines and tests
what must happen when a stateful component stops at an explicit safe point,
carries portable logical state forward, reacquires authority, rebuilds
host-bound resources, and reconciles in-flight effects.

> Current evidence is limited to the named profiles, runtimes, and Linux cells
> summarized below. It does not establish transparent migration, arbitrary
> live-resource transfer, physical cross-host deployment, or production
> readiness.

## The problem

WebAssembly makes code portable. It does not by itself make a running system's
state portable.

A stateful component may own logical data while depending on host-bound files,
clocks, pending operations, credentials, or network sessions. Copying memory or
a runtime-private snapshot cannot safely answer:

- whether an in-flight effect completed, failed, or has an indeterminate
  outcome;
- how a resource should be revalidated, recreated, reconnected, or rejected;
- whether the destination may reacquire equal or narrower authority;
- how to fence the source before activating the destination; or
- what evidence is sufficient to compare behavior across implementations.

vISA defines and exercises that system-resource continuity boundary.

## Continuity contract

The project concentrates portable meaning in versioned resource profiles and a
canonical lifecycle. A profile defines:

- portable logical state, never file descriptors, sockets, native pointers,
  credentials, or runtime-private objects;
- resource disposition and typed recovery outcomes;
- operation identity, idempotency, replay eligibility, and reconciliation;
- authority compatibility, attenuation, reauthorization, and revocation;
- quiescence, handoff, source fencing, destination activation, and cleanup; and
- normalized observations and executable conformance evidence.

Engines, kernels, filesystems, network stacks, QEMU, and external ownership
services are adapters, providers, or comparison systems. They do not define the
portable semantic truth.

## Execution model

```text
WIT/WASI component + continuity profile
                |
       engine/personality adapter
                |
                v
       vISA runtime coordinator
       |  preflight canonical transition
       |  execute effect through a port
       |  commit outcome or record abort/indeterminate
                |
                v
      canonical state + effect journal
         |              |             |
       views      snapshot/rebind   evidence
                |
                v
        substrate/provider adapters
```

## Evidence snapshot

| Profile or track | Qualified cell | Important boundary |
| --- | --- | --- |
| Timer and durable KV | 31 cases in all four directions formed by Wasmtime and a source-locked Wacogo derivative | 124 executions and 31 normalized equality groups on x86-64 Linux under one shared coordinator |
| Regular file | 12 cases in the same four runtime directions, with three required stability runs per cell | One bounded Linux regular-file profile on x86-64 Linux |
| Logical request | 14 cases from Wasmtime to Wasmtime | Reconnectable logical session, not preservation of a live socket; no independent-runtime coverage |
| Emulated target and ISA | Fixed timer/KV workload across seven Hx/Qx/Qa native and QEMU-user cells | QEMU-user and the host kernel; no real AArch64 hardware, AOT-binary portability, or physical cross-host execution |
| Native host and ISA supplement | Fixed timer/KV workload across Hx -> Hx, Hx -> Ha, Ha -> Hx, and Ha -> Ha | 124/124 executions on a physical x86-64 host and Raspberry Pi Zero 2 W; the provider remains on Hx, so this does not establish provider migration or provider-substrate cross-ISA portability |
| Joint handoff | Bounded same-boot composition with an admission-ordered successor | `v1` is earned; `v2` remains a candidate; neither is a production Nexus adapter |

These are executable research cells, not a product support matrix. Exact case
catalogs, source lineage, acceptance receipts, and non-claims live in the
[validation contract](docs/VALIDATION.md), [roadmap](docs/ROADMAP.md), and
[claim registry](claims/registry.json).

The standards-facing problem statement is the
[State Continuity Profiles discussion draft](docs/proposals/continuity-profile/README.md);
community feedback is tracked in
[WebAssembly/WASI#946](https://github.com/WebAssembly/WASI/issues/946).

## Non-goals

vISA does not currently claim:

- a standard memory, process, or runtime snapshot format;
- transfer of live native handles or transparent preemptive migration;
- universal exactly-once effects, distributed consensus, or remote-effect
  atomicity;
- hostile-host security, confidential continuity, or rollback protection;
- a new WebAssembly instruction set, operating system, Linux ABI, or device
  stack; or
- a stable API, performance result, or production-ready system.

## Repository map

| Path | Purpose |
| --- | --- |
| [`wit/`](wit/) | Component worlds and continuity-profile interfaces |
| [`crates/core/`](crates/core/) | Canonical contracts, state, and effect semantics |
| [`crates/runtime/`](crates/runtime/) and [`crates/host/`](crates/host/) | Runtime coordination and host-facing adapters |
| [`crates/testing/`](crates/testing/) | Conformance runners, matrices, and independent verifiers |
| [`claims/`](claims/) | Mechanical claim registry and closure receipts |
| [`scripts/`](scripts/) | Repository gates, evidence publishers, and integrity checks |
| [`docs/`](docs/) | Architecture, roadmap, development, validation, and research detail |

## Development

The supported environment is Docker-based:

```sh
docker compose build dev
docker compose run --rm dev
```

Run the ordinary edit-loop gate and the cumulative repository gate with:

```sh
scripts/run-docker-ci-gate.sh fast
scripts/run-docker-ci-gate.sh
```

System and evidence gates intentionally remain in the
[development guide](docs/DEVELOPMENT.md), where each command is paired with its
prerequisites. Their claim boundaries are defined in
[validation](docs/VALIDATION.md).

## Documentation

- [Vision](docs/VISION.md): project purpose, users, and ownership boundary.
- [Architecture](docs/ARCHITECTURE.md): components, lifecycle, dependency
  direction, and invariants.
- [Roadmap](docs/ROADMAP.md): capability and evidence sequence.
- [Development](docs/DEVELOPMENT.md): environment, commands, and contribution
  workflow.
- [Validation](docs/VALIDATION.md): gates, evidence semantics, receipts, and
  explicit non-claims.
- [Research](docs/RESEARCH.md): related work, novelty boundaries, and
  falsifiable questions.
- [Continuity profile discussion](docs/proposals/continuity-profile/README.md):
  standards-facing pre-proposal for WIT/WASI resource continuity.

## Claim lifecycle index

This table is a machine-checked identity and lifecycle index. It does not widen
the scope or evidence defined by the roadmap, validation contract, and receipts.

<!-- claims-registry:start -->
| Claim ID | Status |
| --- | --- |
| `bounded-joint-handoff-refinement-v1` | `earned` |
| `bounded-joint-handoff-refinement-v2` | `candidate` |
| `bounded-logical-request-continuity` | `earned` |
| `bounded-regular-file-continuity` | `earned` |
| `bounded-stock-sqlite-rollback-migration-v1` | `earned` |
| `bounded-wanco-regular-file-carrier-composition-v1` | `earned` |
| `cooperative-stateful-component-handoff` | `earned` |
| `cross-execution-path-portability` | `earned` |
| `cross-runtime-regular-file-continuity-v1` | `earned` |
| `emulated-cross-isa-continuity-v1` | `earned` |
| `named-target-substrate-continuity-v1` | `earned` |
| `strict-cross-runtime-continuity` | `earned` |
<!-- claims-registry:end -->

## Engineering principles

- Keep one canonical model and one authoritative execution truth.
- Preserve portable semantic state; rebuild or explicitly reject native
  bindings.
- Reauthorize on restore and fence the source before destination activation.
- Make effects, failure, cancellation, cleanup, and indeterminate outcomes
  explicit.
- Derive views, snapshots, and evidence from execution truth rather than
  parallel ledgers.
- Tie every public claim to an executable scenario and an identified runtime,
  resource profile, substrate, ISA, and fault boundary.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
