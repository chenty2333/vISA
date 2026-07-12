# vISA

**Portable code is only half the story. Portable state moves; native resources
are rebound.**

vISA is a research system for capability-safe state continuity and conformance
across heterogeneous WebAssembly runtimes and substrates. Its first reference
capability lets a stateful component stop at an explicit safe point, carry
portable semantic state instead of native handles, reacquire authority, rebuild
resource bindings, resume, and produce executable evidence about what happened.

> **Project status:** research prototype. The Stage 1 named Wasmtime reference
> cell is complete for all 31 registered lifecycle and fault cases. The Stage
> 2a runtime-neutral adapter contract, Stage 2b Jco-translated Node/V8 execution
> cell, and Stage 2c four-direction matrix are also complete; the matrix runs
> the unchanged registry in all four Wasmtime/JcoNode source/destination pairs,
> for 124 executions. This earns only the named
> `cross-execution-path-portability` result. Every current cell uses
> x86-64/amd64 Linux and the timer/KV profile. Because Jco's translator lineage
> includes `wasmtime-environ`, strict Roadmap Stage 2 remains in progress.
> Independent Component Model runtime, cross-ISA, file/network, confidential,
> stable API, and production claims remain unearned.

## The problem

WebAssembly makes code portable. It does not by itself make a running system's
state portable.

A stateful component may own logical data while also depending on host-bound
files, sockets, clocks, pending asynchronous operations, credentials, or device
leases. Copying memory or a runtime-internal snapshot cannot safely answer:

- whether an in-flight effect completed, failed, or must be retried;
- how a resource should be recreated, reconnected, proxied, or rejected;
- whether the destination is allowed to reacquire the same authority;
- how to prevent the source and destination from acting at the same time; or
- what evidence is sufficient to claim equivalent behavior after recovery.

vISA is intended to define and implement that missing system-resource
continuity boundary.

## What vISA owns

- a versioned semantic contract for identity, generation, authority, effects,
  waits, cancellation, failure, cleanup, and recovery;
- one canonical state machine and effect journal;
- runtime coordination for canonical commit, explicit abort or indeterminate
  outcomes, quiescence, handoff, and source fencing;
- portable snapshot envelopes and explicit resource rebinding rules;
- compatibility profiles and executable conformance evidence; and
- adapter contracts for runtimes, substrates, personalities, and resource
  providers.

## What vISA integrates with

WebAssembly engines, kernels, Linux personalities, Virtio devices, filesystems,
network stacks, CRIU/QEMU, and confidential-computing services are adapters,
reference implementations, or comparison systems. They do not define vISA's
portable semantic truth.

In particular, vISA is not intended to become another WebAssembly compute ISA,
a new general-purpose operating system, a complete Linux compatibility layer,
a device stack, or a transparent migration system for arbitrary native
processes.

## Target execution model

```text
WIT/WASI component + vISA profile
                |
       engine/personality adapter
                |
                v
       vISA runtime coordinator
       |  preflight canonical transition
       |  execute effect through a port
       |  commit canonical outcome or record abort/indeterminate
                |
                v
      canonical state + effect journal
         |              |             |
       views      snapshot/rebind   evidence
                |
                v
        substrate/provider adapters
```

See [the vision](docs/VISION.md) for the problem and project boundary,
[the architecture](docs/ARCHITECTURE.md) for responsibilities and invariants,
and [the roadmap](docs/ROADMAP.md) for the first architecture-complete
capability.

## Current repository

The active production spine covers the Stage 1 continuity path and the Stage
2a, 2b, and 2c adapter, execution-cell, and matrix paths. Strict
dependency-direction, legacy-deletion, toolchain-identity, and file-size checks
protect it. Broader pre-reset models and target experiments remain isolated as
oracle, reference, or compile-only paths; they do not define portable semantic
truth.

Current documentation:

- [Vision](docs/VISION.md): why vISA exists, who it is for, and what it does not
  own.
- [Architecture](docs/ARCHITECTURE.md): the accepted target boundary, lifecycle,
  dependency direction, and invariants.
- [Roadmap](docs/ROADMAP.md): capability and evidence sequence, including the
  first cooperative stateful handoff slice.
- [Development](docs/DEVELOPMENT.md): current Docker, Cargo, script, and
  worktree workflow.
- [Validation](docs/VALIDATION.md): current gate limits, target tiers, and
  claim-to-evidence rules.
- [Research](docs/RESEARCH.md): related work, non-novelty boundaries, and
  falsifiable hypotheses.

## Development

The current supported environment is Docker-based. See the
[development guide](docs/DEVELOPMENT.md) for details:

```sh
docker compose build dev
docker compose run --rm dev
```

Run the current repository gates with:

```sh
scripts/run-docker-ci-gate.sh
```

Run the ordinary edit-loop gate while developing:

```sh
scripts/run-docker-ci-gate.sh fast
```

The cumulative `full` gate additionally covers workspace and feature tests,
selected Wasm packages, no-std and kernel target checks, benchmark compilation,
and report fixtures. It is not a live handoff gate.

Run the standalone Stage 1 system gate with:

```sh
scripts/run-docker-ci-gate.sh system
```

`system` executes the real 31-case source/destination lifecycle, retains its
artifacts, and independently validates the resulting evidence bundle. It does
not repeat `full`; run both tiers when validating the repository and the named
Stage 1 reference cell together.

Run the Stage 2b JcoNode same-path cell with:

```sh
scripts/run-docker-ci-gate.sh system-jco-node
```

Run the complete Stage 2c four-direction matrix with:

```sh
scripts/run-docker-ci-gate.sh system-stage2
```

`system-jco-node` runs the same 31 cases through isolated Jco-translated
Node/V8 workers. `system-stage2` runs all four Wasmtime/JcoNode pairs, for 124
executions, and independently verifies the normalized outer bundle. Both are
standalone system tiers and neither proves strict runtime independence or
cross-ISA portability.

## Engineering principles

- Keep one canonical model and one authoritative execution path.
- Preserve portable semantic state; rebuild or explicitly reject native
  bindings.
- Reauthorize on restore. Never treat an old native handle as authority.
- Make failure, cancellation, cleanup, rollback, and unsupported behavior
  explicit.
- Derive views, snapshots, and evidence from execution truth rather than
  maintaining parallel ledgers.
- Tie every public claim to an executable scenario and an identified runtime,
  ISA, substrate, resource profile, and fault boundary.
- Keep durable documentation short; use code and tests as the final proof of
  implemented behavior.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
