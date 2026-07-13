# Runtime B qualification record

This directory is the durable, repository-owned record of the executable
Runtime B qualification used by Strict Stage 2. The machine-readable authority
is [`runtime-b-qualification.json`](runtime-b-qualification.json), whose
`visa-runtime-b-qualification-v1` schema records exact inputs, candidate
lineage, observations, seven qualification gates, and the selected runtime.
Paths beginning with `qualification/` in that record are relative to this
directory.

## Qualified identity and decision

All candidates were tested against the unchanged 146,486-byte Stage 1
Component (SHA-256
`4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b`)
and `visa:continuity/cooperative-handoff@0.1.0` WIT world (SHA-256
`709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920`).

The selected Runtime B is
`partite-ai/wacogo v0.0.0-20260617023329-3de16a61796c + vISA downstream
patchset v1`. With the official Go 1.26.5 linux/amd64 toolchain, that pinned
derivative passed all 7/7 gates through public typed Component Model APIs. Its
parser, linker, Canonical ABI, resource implementation, and wazero execution
lineage do not depend on Wasmtime or `wasmtime-environ`.

The no-go results remain deliberately narrower:

- WACS parses the Component but its retained typed-harness and CLI paths do not
  expose a usable typed surface for the unchanged world.
- WasmEdge 0.17.1 rejects the unchanged Component during resource validation.
- Unmodified upstream wacogo loads the Component but fails while resolving the
  nested imported `kv-error` type before workload execution.

These results neither disqualify every version of those projects nor imply
upstream support for the selected downstream derivative.

## Reproduction

From the repository root, first build and resolve the byte-exact Component:

```sh
cargo build --locked -p visa-system
COMPONENT=$(third_party/runtime-b-qualification/qualification/resolve-component.sh)
```

Then reproduce the selected and unmodified-upstream decisions with the pinned
official Go toolchain:

```sh
GO=/tmp/go1.26.5-official/bin/go \
  third_party/runtime-b-qualification/qualification/run-wacogo-probe.sh \
  "$COMPONENT"

GO=/tmp/go1.26.5-official/bin/go \
  third_party/runtime-b-qualification/qualification/run-wacogo-upstream-probe.sh \
  "$COMPONENT"
```

The selected probe fails closed on toolchain, module, Component, WIT, license,
patch, post-patch tree, dependency-closure, and executable-lineage drift. The
retained `qualification/wacogo-patches/` directory is a byte-identical audit
mirror of the canonical [`third_party/wacogo/patches`](../wacogo/patches)
series; the probe enforces that relationship before execution.

## Scope boundary

This record qualifies only the named x86-64 Linux timer/KV profile and proves
candidate selection, not project completion by itself. It does not claim
file/network continuity, cross-ISA execution, real-target coverage, TEE,
attestation, KMS, confidential continuity, release status, or production
readiness.

The composed repository gate is `scripts/ci-gate.sh system-stage2-strict`.
Current status and evidence interpretation are governed by the
[Roadmap](../../docs/ROADMAP.md) and [Validation contract](../../docs/VALIDATION.md).
