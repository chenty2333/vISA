# vISA

**Portable code is only half the story. Portable state moves; native resources
are rebound.**

vISA is a research system for capability-safe state continuity and conformance
across heterogeneous WebAssembly runtimes and substrates. Its first reference
capability lets a stateful component stop at an explicit safe point, carry
portable semantic state instead of native handles, reacquire authority, rebuild
resource bindings, resume, and produce executable evidence about what happened.

> **Project status:** research prototype. The Stage 1 named Wasmtime reference
> cell is complete for all 31 registered lifecycle and fault cases. The legacy
> Stage 2a, 2b, and 2c Wasmtime/JcoNode path is also complete for its original
> `cross-execution-path-portability` claim. A separate strict v3 path now runs
> the unchanged Component and timer/KV profile through Wasmtime and a
> source-lock-bound Wacogo derivative whose accepted Component Model lineage is
> independent of Wasmtime and `wasmtime-environ`. Its exact four runtime cells
> completed 124/124 executions and 31/31 normalized equality groups in fresh
> Host and Docker runs, with all inner and outer independent verification
> passing. The strict verifier accepts only
> `strict-cross-runtime-continuity`. Both evidence paths remain limited to
> x86-64/amd64 Linux. Roadmap Stage 2 is complete for this named timer/KV
> scope and remains the independent-runtime control baseline. Stage 3A has a
> bounded regular-file implementation and a qualified 12-case executable
> evidence path; Stage 3B has a bounded logical-request (reconnectable-session)
> implementation and a qualified 14-case evidence path. Both gates and their
> independent structural bundle verifiers passed on the stage-closing
> implementation revision, which passed pushed CI at its exact commit. Roadmap
> Stage 3 is complete for these two named bounded profiles. Both Stage 3 paths
> run Wasmtime to Wasmtime, explicitly record
> `independent_runtime_coverage=false`, list Wacogo as unsupported, and do not
> inherit the Stage 2 cross-runtime result. Cross-ISA/substrate,
> confidential-continuity, stable API, and production claims remain unearned.

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

The active continuity spine covers the Stage 1 path, the legacy Stage 2a, 2b,
and 2c Wasmtime/JcoNode paths, the source-lock-bound Wasmtime/Wacogo
strict-runtime adapter and matrix paths, and the two Stage 3 resource
qualification paths. Strict
dependency-direction, legacy-deletion, toolchain-identity, and file-size checks
protect it. Broader pre-reset models and target experiments remain isolated as
oracle, reference, or compile-only paths; they do not define portable semantic
truth.

The Stage 3 qualification work uses separate regular-file and logical-request
WIT worlds, guests, Wasmtime adapters, profile state codecs, host providers,
system runners, evidence schemas, case registries, and independent structural
bundle verifiers.
It reuses the canonical authority, lease, journal, snapshot, reauthorization,
and fencing path; it does not modify or re-sign the Strict Stage 2 Component,
timer/KV registry, normalizer, or digest locks.

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

Run the strict independent-runtime matrix with:

```sh
scripts/run-docker-ci-gate.sh system-stage2-strict
```

`system-stage2-strict` qualifies and reproducibly builds the source-lock-bound
Wacogo sidecar, runs the exact Wasmtime/Wacogo four-cell matrix over the
unchanged 31-case timer/KV registry, and independently verifies all 124
executions and 31 normalized equality groups. It supports only
`strict-cross-runtime-continuity` on x86-64/amd64 Linux; it does not prove
cross-ISA portability or additional resource profiles.

Run the bounded Stage 3 resource gates separately with:

```sh
scripts/run-docker-ci-gate.sh system-stage3a
scripts/run-docker-ci-gate.sh system-stage3b
scripts/run-docker-ci-gate.sh system-stage3
```

`system-stage3a` exercises one bounded regular file through read/write,
logical-offset, append, truncate, rename/replacement, external-mutation,
durability, lock/lease, reauthorization, fencing, and cleanup cases.
On Linux filesystems that report `STATX_BTIME`, the provider revalidates both
the namespace root and file with the fd-derived device/inode/birth-time tuple;
missing birth time is unsupported and never falls back to device/inode alone.
This detects ordinary inode-number reuse with a different creation timestamp,
but birth time is not an inode-generation counter or cryptographic identity and
does not establish a hostile-host claim. A second SQLite immediate transaction
rechecks the durable intent, authority, lease epoch, and pre-state and remains
held while the provider attempts the file effect and records its outcome. This
orders admission to a vISA provider effect against handoff commit; the file
mutation and SQLite outcome are not atomic, so a post-effect failure remains
outcome-unknown and is reconciled from the durable plan. External-mutation
coverage detects identity, content, or version drift already observable before
a provider operation. Concurrent writers are ordered or rejected only when
they participate in the same advisory lock/lease protocol; Stage 3A does not
provide atomic compare-and-mutate against a writer that bypasses that protocol.
`system-stage3b` exercises logical request identity, peer and credential
validation, operation-ID deduplication, partial responses, unknown completion,
timeout, cancellation, reconnect/replay policy, fencing, and cleanup over a
real bounded loopback transport. Its `VISALR03` handshake uses a fresh nonce
and HMAC-SHA-256 challenge/response to authenticate the configured peer before
an application request frame is sent; reusable credential material is not put
on the wire. Lookup and Cancel frames bind the logical operation ID to the
expected request digest. Each application frame is emitted under an SQLite
send fence that rechecks authority, lease epoch, and resource binding, while
ledger revisions reject stale saves and terminal, cursor, or cleanup rollback.
These are host-local transactional guarantees for the bounded profile, not
remote-effect atomicity or general transport encryption. Their claims exclude
arbitrary directory trees, devices, FIFOs, arbitrary open file descriptors,
preservation of a raw live TCP connection, runtime future/stream state, and a
general async runtime.
`system-stage3` runs both profiles in sequence. These are Wasmtime-only Stage 3
qualification gates; run
`system-stage2-strict` separately to preserve the independent-runtime control.
Both Stage 3 profiles still trust the host process, kernel, SQLite state, and
provider-local credential store. `STATX_BTIME`, SQLite fencing, and `VISALR03`
peer authentication do not establish a hostile-host or confidential-channel
boundary.

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
