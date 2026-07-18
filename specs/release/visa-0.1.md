# vISA 0.1 exact-version release contract

Status: frozen target contract; not release-ready.

The machine authority is [`visa-0.1.toml`](visa-0.1.toml). It defines one exact
product cell: vISA `0.1.0`, same host and same boot, Linux x86-64, with at most
six active processes. It is a release-admission target, not evidence that these
product surfaces already exist.

## Six-process topology and authority

One short-lived `visa` process is the CLI and controller. Two long-lived
`visa-agent` processes are the source and destination. Each agent directly owns
its Wasmtime instance, local continuity provider, profile adapter and real
regular-file/logical-request sink, and durable local projection. There is no
agent-owned stdio worker child in 0.1; Stage 3 dual-process means exactly two
distinct agent PIDs.

One independent `visa-ownershipd` process owns the only ownership database,
durable reservation, seal, and immutable abort-or-commit decision. It uses one
private SQLite store with WAL, `synchronous=FULL`, an exclusive process lock,
and a persisted receipt issuer. The controller, agents, Nexus adapter, and
Nexus peer neither open this database nor issue ownership receipts.

One independent `visa-nexusd` process owns the production native-v1 adapter,
dispatch-grant ledger, and exactly one `nexus-effect-peer` child. The child owns
the in-memory authoritative Nexus Registry. Controller or agent failure does
not transfer or recreate that Registry: both reconnect to the surviving
services. `visa-nexusd` or peer failure is terminal and fail-closed for 0.1;
no new dispatch or fabricated closure is admitted, and a respawned peer cannot
claim the old Registry. If the cohort was already durably frozen, the source
remains Frozen. A pre-freeze failure retains the source's prior disposition and
must not be rewritten as an inferred freeze.

The maximum active inventory is therefore:

```text
1 visa controller/CLI
2 visa-agent processes
1 visa-ownershipd
1 visa-nexusd
1 nexus-effect-peer
= 6 processes
```

## Three independent local RPC contracts

The product freezes three separate version namespaces and golden corpora:

1. `visa.agent.control.v1` for controller-to-agent control;
2. `visa.ownership.local.v1` for agent-to-ownership-service requests;
3. `visa.nexus-adapter.local.v1` for agent-to-`visa-nexusd` requests.

They share one framing implementation, but never a command/response enum,
error namespace, replay namespace, schema, or golden corpus. All use a fixed
20-byte header followed by a canonical Postcard 1.1.3 payload over filesystem
Unix stream sockets. The header is `magic[8]`, major `u16`, minor `u16`, flags
`u32`, and payload length `u32`; every integer is big-endian. The three exact
magics are `VISACTL1`, `VISAOWN1`, and `VISANEX1`. Flags must be zero. A reader
must read and validate the entire header, including the length bound, before it
allocates the payload. Decode rejects trailing bytes and successful payloads
must re-encode byte-identically. There is no compression, multiplexing, file
descriptor passing, or in-band upgrade in 0.1.

The implementation target reuses standard-library `UnixListener`/`UnixStream`,
the locked rustix 1.1.4 filesystem/network/process facilities, and the existing
`joint_handoff_core` canonical Postcard/SHA pattern. It does not add varlink,
zlink, tarpc, tonic, or another RPC framework. This transport is only for the
three vISA-local boundaries: the `visa-nexusd` to `nexus-effect-peer` boundary
remains the separately frozen Nexus native-v1 bounded JSONL protocol.

The versioned runtime directory is below `${XDG_RUNTIME_DIR}`, mode `0700`;
sockets are mode `0600`; every server checks same-UID `SO_PEERCRED`, rejects
symlinked directories or sockets, uses short role names, and preflights the
platform `sun_path` limit. No local control RPC admits a network endpoint.
These checks define a same-UID local TCB/admission and accidental-bypass
boundary, not authentication or tenant isolation against a malicious process
running as that UID. Same-UID ptrace, process-memory access, credential
separation, and cryptographic channel authentication remain outside 0.1.

The exact whole-frame limit is 1,048,576 bytes, including the 20-byte header;
the payload limit is therefore 1,048,556 bytes. This is not inherited from the
16 MiB test-worker allowance: the largest generated existing vISA system JSONL
line is about 53,663 bytes; durable native requests and profile response chunks
are bounded at 64 KiB; and existing product Jco and Wacogo JSONL carriers use
1 MiB. The new RPCs do not inline Component binaries, full evidence bundles,
databases, or the profile's total 4 MiB logical response. Large objects travel
only as a digest plus a securely opened path; descriptor passing is absent.

Every protocol requires an exact product/protocol/role/executable handshake
before mutation, one in-flight mutation per connection, same-ID/same-canonical-
bytes replay, and conflict on ID reuse with different bytes. Timeout after a
mutation is unknown outcome: clients query or replay the exact request and never
infer abort, commit, dispatch, or closure.

## Provider fence and real sinks

The current in-process `CommittedEffectPermit` binds one provider instance by
reference and is deliberately non-cloneable. A serializable RPC proof cannot be
treated as that same-process permit.

The 0.1 target therefore requires a two-boundary refinement:

1. `visa-nexusd` validates the exact native-v1 commit receipt and chain, then
   atomically consumes that commit into one ledger entry and returns its one
   exact dispatch grant. Exact request replay with the same request ID and bytes
   returns the byte-identical grant and never another grant for the commit.
2. The corresponding agent validates the grant against its durable local
   projection, persists the grant plus `armed` or `started` state before the
   real sink, and privately mints a non-cloneable
   `ProfileDispatchAuthorization`. Authorization and the actual regular-file
   or logical-request sink call occur in the same trusted agent process.

The grant binds the effect operation, idempotency identity, agent role and
incarnation, and native request/receipt digests. Neither the controller nor
`visa-nexusd` executes profile I/O. After an agent crash, a started dispatch
without a durable outcome becomes Unknown and enters provider query/reconcile;
replaying the grant never by itself executes the sink again. This refinement
and its real sink tests remain pending; the target does not claim that the
current in-process `ProfileDispatchControl` proves process-restart recovery, or
that serializable evidence already equals the existing in-process permit. A
dispatch grant controls replay and bypass inside the local same-UID TCB; it is
not claimed to be cryptographically unforgeable.

## Version and artifact boundaries

Product SemVer does not replace any internal namespace. The portable contract,
joint protocol, profiles/extensions, WIT packages, three local RPCs, neutral
wire, Nexus native wire, and provider SPI evolve under their own rules. Cargo
crate versions, the complete workspace/package inventory, Cargo.lock, and the
Rust toolchain are exact-tag release-build provenance, not additional public
compatibility namespaces and not fields in the immutable target. The target
only freezes selected implementation constraints that affect its intended cell:
Postcard 1.1.3 for canonical wire bytes, rustix 1.1.4 for local IPC facilities,
Wasmtime 43.0.2, and bundled rusqlite 0.40.1. The complete package/version/
source/license inventory and exact lock/toolchain digests are generated into
the external release bundle. Adding the planned CLI, agent, ownership, IPC, or
Nexus-adapter crates therefore updates build evidence without rewriting the
product target. The current `EffectClosureProvider` v2 surface remains an
in-tree Rust preview rather than a promised Rust ABI.

The pinned Nexus native-v1 freeze is an exact source contract at
`cb773539401107efe7a7ad036b80ff40d8ec305c`; it is not described as a Nexus
`v0.1.0` released API. The required consumable artifact must be Nexus-owned,
MPL-2.0, and explicitly identify the `nexus-effect-peer-native-v1` wire family.
The separate `nexus.portal.v2` preview cannot satisfy the native-v1 artifact,
adapter, mapping, or release-readiness slots. Local byte-exact freeze bytes and
the current native-to-neutral v2 mapping remain separate pending closure items.

The contract locks the three WIT package IDs and exact source bytes. WIT already
has package SemVer; vISA does not invent another 0.1 package format. Publication
and supply-chain evidence are independent release items.

## Semantic corpus and evidence closure

The four current Postcard command/event/journal/snapshot vectors remain useful
seed examples, while the three version vectors lock namespace values. They do
not close the release semantic corpus. Release readiness requires a generated,
committed type inventory and golden corpus covering every durable or public
serialized type and every enum variant in `contract_core`,
`joint_handoff_core`, and `visa_profile`, including round-trip, unknown/trailing
byte rejection, optional/collection cases, and bounded extrema. Rust must
construct and verify the corpus; source-literal presence is not execution
evidence.

The immutable target contract records required IDs and evidence policy but no
current satisfied/pending state and no closure artifacts. A separate mutable
`visa-0.1-readiness.toml` development ledger binds the target's exact SHA-256,
tracks the current partition, and may cite repository-relative development
evidence. That ledger is useful for progress and is checked by the default
command, but it is explicitly not final release evidence.

Final closure lives in a separately archived, immutable evidence bundle. Its
index binds the exact target path and SHA-256, a 40-hex source commit, and an
exact `v0.1.0-rc.N` tag that resolves to that commit. Every required ID has one
bundle-relative regular evidence file and one machine-readable verifier receipt,
both named by SHA-256; every receipt repeats the target, revision, and tag
binding. The index separately binds the tagged Cargo.lock and toolchain bytes
and a complete package/version/source/license inventory. Symlinks and paths
escaping the bundle are rejected.

The release flow is deliberately non-self-referential: freeze source commit
`C`, create an exact RC tag such as `v0.1.0-rc.1` at `C`, generate and archive
the external bundle against that tag and commit, then run release admission with
that bundle. The final `v0.1.0` tag may point to the same `C`; neither evidence
generation nor final tagging rewrites `C`. A later claims-ledger receipt may be
committed on the main development line, but it does not move or alter either
release tag. Compatibility, crash recovery, observability, and
supply-chain/license closure remain separate IDs so partial work cannot close
the whole release.

Two checks deliberately have different meanings:

```sh
python3 scripts/check-release-contract.py
python3 scripts/check-release-contract.py --release-ready \
  --evidence-index /archive/visa-0.1.0/index.json
```

The first verifies the immutable target plus the target-bound mutable
development ledger: exact local locks, authority/failure topology, current
pending/satisfied partition, and attached development receipts. It never treats
that ledger as release closure. The second additionally requires an external
index, checks its complete ID coverage, paths, digests, receipts, and build
inventory, verifies that its RC tag resolves to its exact source revision, and
checks that the target, Cargo.lock, and toolchain bytes at that revision match
the indexed digests. With no complete external bundle it fails by design. A
schema-valid target or development ledger is never itself product or release
evidence.
