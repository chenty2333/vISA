# Project operating rules

vISA is a personal, pre-consumer project with no production deployment,
external users, or compatibility commitments. Its current source tree is not a
compatibility boundary. Internal APIs, WIT interfaces, schemas, snapshot and
journal formats, crate boundaries, repository structure, and implementations
may be broken, replaced, or deleted whenever that materially improves the
selected design.

Do not invent deprecation periods, compatibility layers, migration tooling,
dual implementations, archive workspaces, or release-transition machinery for
hypothetical consumers. Superseded code and documentation should normally be
deleted; Git history is sufficient for archaeology. Historical claims,
evidence bundles, receipts, matrices, and exact-source validation do not impose
requirements on the new implementation unless the user explicitly restores
one of those requirements.

## Project direction

vISA is the portable semantic-continuation layer of the Semantic World
architecture. It owns portable continuation state, continuity profiles, state
lineage, runtime safe-point semantics, resource-rebinding requirements, and
the validation that permits a prepared runtime to continue.

It does not own TheKernel's worlds, provider bindings, capabilities, native
resources, admission or execution fences. It does not own Nexus/CSER escaped
effects, custody, outcomes, physical claims, settlement, or retirement. It may
coordinate these authorities through exact receipts and queries, but a local
continuation record must never become a second source of truth for facts owned
elsewhere.

The active implementation should remain small. Prefer one complete vertical
path over multiple runtimes, profiles, target matrices, reference kernels,
oracles, evidence systems, and product shells. Add a second abstraction or
adapter only when a real consumer or invariant requires it.

## Implementation posture

- Prioritize the selected continuity core and its first end-to-end path over
  preserving current code.
- Keep portable state free of file descriptors, sockets, native pointers,
  physical addresses, DMA state, credentials, capabilities, and runtime- or
  provider-private handles.
- Keep runtime preparation and native binding tokens opaque, host-local, and
  non-serializable.
- Keep pure transition validation separate from effects and persistence.
- Treat missing or indeterminate external facts as recovery requirements, not
  as success, failure, abort, or retry authority.
- Do not place vISA on ordinary syscall, provider-call, or application hot
  paths. It participates in freeze, update, move, restore, and rebind control
  paths.
- Keep testing proportional: focused core tests, recovery cuts that protect
  real invariants, and one genuine end-to-end path. Do not recreate the old
  claim/evidence infrastructure unless the user explicitly asks for it.

## Project maproom

Read `maproom/terrain.md`, `maproom/basecamp.md`, `maproom/route.md`, and
`maproom/hazards.md` when relevant.

The user alone decides when `terrain.md`, `basecamp.md`, or `route.md` is
updated. Do not modify them as routine progress bookkeeping. Keep
`hazards.md` limited to verified vISA-specific pitfalls that prevent repeated
failures; it is not a status report, plan, result ledger, or generic guidance.
