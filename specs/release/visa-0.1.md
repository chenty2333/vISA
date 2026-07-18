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

They may share a framing implementation, but never a command schema or golden
corpus. All use bounded UTF-8 JSON Lines over filesystem Unix stream sockets.
The versioned runtime directory is below `${XDG_RUNTIME_DIR}`, mode `0700`;
sockets are mode `0600`; every server checks same-UID `SO_PEERCRED`, rejects
symlinked directories or sockets, uses short role names, and preflights the
platform `sun_path` limit. No local control RPC admits a network endpoint.
These checks define a same-UID local TCB/admission and accidental-bypass
boundary, not authentication or tenant isolation against a malicious process
running as that UID. Same-UID ptrace, process-memory access, credential
separation, and cryptographic channel authentication remain outside 0.1.

The exact frame limit is 1,048,576 bytes excluding the terminating LF. This is
not inherited from the 16 MiB test-worker allowance: the largest generated
existing vISA system JSONL line is about 53,663 bytes; durable native requests
and profile response chunks are bounded at 64 KiB; and existing product Jco and
Wacogo JSONL carriers use 1 MiB. The new RPCs do not inline Component binaries,
full evidence bundles, databases, or the profile's total 4 MiB logical response.
Large objects travel only as a digest plus securely opened path or descriptor.

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
crate versions, Wasmtime/rusqlite selection, Cargo.lock, and the Rust toolchain
are exact release-build provenance, not additional public compatibility
namespaces. The current `EffectClosureProvider` v2 surface remains an in-tree
Rust preview rather than a promised Rust ABI.

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

Every satisfied readiness ID must name a repository-relative regular evidence
file, its SHA-256, an exact 40-hex source revision, and a machine-readable
verifier receipt with its own SHA-256. Compatibility, crash recovery,
observability, and supply-chain/license closure remain separate IDs so partial
work cannot close the whole release.

Two checks deliberately have different meanings:

```sh
python3 scripts/check-release-contract.py
python3 scripts/check-release-contract.py --release-ready
```

The first verifies the current target schema, exact local locks, authority and
failure topology, pending/satisfied partition, and any attached readiness
evidence. The second additionally requires every closure item to be satisfied.
It currently fails by design. A schema-valid contract is never itself product
or release evidence.
