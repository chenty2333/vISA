# vISA

**Portable code is only half the story. Portable state moves; native resources
are rebound.**

vISA is a research system for capability-safe state continuity and conformance
across heterogeneous WebAssembly runtimes and substrates. Its initial design
direction is to let a stateful component stop at an explicit safe point, carry
portable semantic state instead of native handles, reacquire authority, rebuild
resource bindings, resume, and produce executable evidence about what happened.

> **Project status:** architecture reset and research prototype. The target
> boundary is documented, but the current implementation is still converging
> toward one canonical state model and one runtime path. Do not interpret the
> existing breadth of crates, scenarios, or sample reports as a stable public
> API or as proof of cross-runtime or cross-ISA continuity.

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

The repository contains substantial exploratory work across semantic modeling,
artifact/runtime paths, a no-std kernel target, Linux and service personalities,
Virtio-backed adapters, migration packages, benchmarks, and conformance report
tooling. Some of these paths predate the current boundary and are migration or
deletion candidates rather than stable architecture.

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

Or run selected gates while editing documentation or repository metadata:

```sh
scripts/run-docker-ci-gate.sh metadata fmt
```

The current gate covers metadata, formatting, selected Wasm packages,
`visa-conformance` report/schema checks, and the kernel target check. It is not
yet a complete workspace, cross-runtime, cross-ISA, or system-continuity gate.
The developer command surface will be consolidated as implementation work
proceeds; the target validation tiers are already defined in the validation
document.

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
