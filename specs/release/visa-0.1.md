# vISA 0.1 exact-version release contract

Status: immutable release target; the development ledger is not release-ready.

The machine authority is [`visa-0.1.toml`](visa-0.1.toml). It defines one exact
product cell: vISA `0.1.0`, same host and same boot, Linux x86-64, with at most
six active vISA/Nexus product-role processes, including the short-lived `visa`
CLI. The existing user systemd manager, D-Bus daemon, and library-internal
threads are host infrastructure and are not counted; the CLI has no helper
child. It is a release-admission target, not evidence that these product
surfaces already exist.

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

A mutating CLI first opens the flat
`${XDG_RUNTIME_DIR}/visa-0.1-controller.lock` with
`O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK`, verifies a regular,
euid-owned, single-link mode-`0600` file, and takes a nonblocking `flock`. It
holds the lease through the durable outcome and never unlinks the file. This
secure open/acquire is the first product-owned mutation; read-only diagnostics
do not take a controller role.

## systemd user supervision

The supported 0.1 launch topology is `systemd --user`. All five product
binaries remain foreground-only and never self-daemonize. `visa-local.target`
uses `Wants=` for `visa-ownershipd`, `visa-nexusd`, and both
`visa-agent@.service` instances, with all four `PartOf=` the target. It uses no
`Upholds=`, `Requires=`, or `BindsTo=` recovery cascade; there is no peer unit
because `nexus-effect-peer` is the
sole retained child of `visa-nexusd`. Manual foreground launch remains a test
and diagnostic harness, not a second release topology. Socket activation and
automatic lingering are excluded.

Both authority services and the agents use `Type=notify`. Each agent is ordered
`After=` both authorities, so their successful READY notifications complete
before either agent starts or reports ready. Runtime authority-name or
connection loss is handled inside the resident agent: it fences first and then
waits for a reconnect/query without systemd dependency stop/start behavior.
`visa-ownershipd` may recover under its bounded `Restart=on-failure`; Nexus
adapter or peer loss is terminal, burns the cohort, and schedules no Nexus or
agent recovery job. A missing
`NOTIFY_SOCKET` or failed READY notification is a startup failure, never an
implicit ready state. `visa-nexusd` uses `Restart=no`, `KillMode=control-group`,
`SendSIGKILL=yes`, and a 10-second stop bound. It reports ready only after peer
spawn and handshake, D-Bus interface export, well-known-name acquisition, and
initial cohort/epoch/fence validation.
Peer loss first fences admission in the application and then terminates
`visa-nexusd` nonzero; systemd cleanup is never treated as effect or ownership
authority. Agents and `visa-ownershipd` use the frozen bounded
`Restart=on-failure` policy: one-second delay, three starts per 30 seconds.

The CLI does not spawn `systemctl` or another product process. On each Manager
connection it calls `Subscribe` once, installs and awaits an active `JobRemoved`
signal stream, then calls `StartUnit` or `StopUnit`. It matches the returned job
object path including an already-buffered event, requires result `done`, then checks each product
member and Nexus health rather
than trusting target activity alone. Implementation should reuse a maintained
typed zbus/systemd proxy; the contract deliberately does not invent D-Bus wire
code.

## Same-boot cohort and agent identity

Every durable store and runtime path is namespaced by an operator-created
cohort ID, Linux boot ID, and volatile user-manager session ID. `visa
cohort-create --cohort-id <32-lowercase-hex>` first creates or reads a mode
`0600` `${XDG_RUNTIME_DIR}/visa/0.1/runtime-session.json`, then atomically
creates the non-authoritative persistent and active launch manifests, and only
then starts units through the user-bus systemd Manager. An exact retry may
converge a partial start; a different boot, session, path, active cohort, or
existing role-store identity is a typed conflict. The launch manifest never
issues an ownership or effect receipt.

Five resident roles are mutually exclusive with any different active cohort.
`visa-nexusd` writes and fsyncs a registry-attempt tombstone before spawning its
peer. Once that marker exists, a missing or different `visa-nexusd` process
burns the cohort; no retry may recreate the Registry. Clean `cohort-retire`
first proves there is no Frozen, Unknown, or in-flight handoff, seals required
evidence, stops and observes all five resident processes inactive, writes a
retirement tombstone, and only then removes the exact active manifest. An
explicit `--acknowledge-stranded-state` first records abandonment without
inferring a receipt, stops and confirms all five residents inactive, and only
then writes the retirement tombstone and removes the exact active manifest. A
partial stop leaves that manifest in place. Role stores are never reset,
deleted, or relabelled.

The 0.1 claim is narrower than the boot lifetime: it requires one continuous
systemd user-manager and `${XDG_RUNTIME_DIR}` lifetime. Logout/user-manager
teardown or runtime-root loss makes the old cohort read-only audit state; 0.1
does not reconstruct or resume it. A new runtime session requires a new cohort,
workload, and state identity.

An agent's logical incarnation is stable across process restart and binds its
role, slot, cohort, boot ID, and projection. A fresh process nonce and
monotonic generation are separate handshake values for each start. Grants bind
the stable logical incarnation, not merely a PID. Loss of this durable identity
fails closed. An `armed` record may resume only after authoritative ownership
and provider queries confirm the exact not-yet-started dispatch. A `started`
record without a durable terminal outcome is Unknown and can only be queried
and reconciled; it is never redispatched from the grant.

The agent failure-matrix phrase "exact RPC replay" is scoped to a surviving
agent process after an ownership-service or user-bus disruption. That process
retains the same process nonce and generation and may resend the exact
canonical request bytes. An agent process restart instead creates a new nonce
and monotonically later generation; the restarted agent must issue a new
current-binding `Query` and reconcile the authoritative state. It must not
present request bytes containing the prior process binding as a current call.
Likewise, an exactly replayed ownership response retains the server process
binding that originally committed it: those server nonce/generation fields are
historical execution evidence, while the current transport endpoint is
verified independently.

## Three independent local RPC contracts

The product freezes three separate version namespaces and golden corpora:

1. `visa.agent.control.v1` for controller-to-agent control;
2. `visa.ownership.local.v1` for agent-to-ownership-service requests;
3. `visa.nexus-adapter.local.v1` for agent-to-`visa-nexusd` requests.

They reuse three independent versioned interfaces on the systemd user session
bus via zbus. Each exposes `Execute(ay) -> ay`; the byte array contains canonical
Postcard 1.1.3 request/response data. The golden contract locks each well-known
name, object path, interface, method, signature, and inner Postcard bytes. It
does not lock the outer D-Bus serialization. D-Bus errors are reserved for
transport or pre-admission failure; semantic Success, Rejected, Unknown, and
Internal outcomes are total canonical inner responses.

All three inner type families are restricted to deterministic ordered structs,
tuples, bounded vectors, `BTreeMap`, and `BTreeSet`; unordered maps/sets and
floating-point values are excluded. Each independent corpus must cover every
request and response variant, bounds, non-minimal varints, trailing bytes, and
decode/re-encode byte identity. “Canonical Postcard” is therefore an executable
per-interface property rather than a label on the codec.

Field-level schema export reuses exact `postcard-schema` 0.2.5 (schema support
only, not `postcard-rpc`). Each family emits a complete owned schema artifact
whose full bytes are SHA-256 bound alongside its Rust-constructed all-variant
corpus. The crate's FNV key is only a non-cryptographic lookup aid and is never
schema, version, or security authority. A simple Serde `rename` is allowed only
when both artifact and corpus lock it; `rename_all`, directional rename,
`flatten`, `with`, `skip`, `default`, and custom serialize/deserialize shapes
are forbidden in v1.

Services request names with DoNotQueue/no-replace semantics and install no
D-Bus activation files. A server obtains the bus-controlled sender unique name
and `GetConnectionCredentials`. A returned `ProcessFD` is preferred. On stock
buses without it, the verifier queries unique name/UID/PID, opens the pidfd,
then re-queries the same unique name and requires unchanged UID/PID; clients
also require that unique name still owns the well-known service name. Any race
fails closed. It then verifies a secure `/proc/<pid>/exe` identity and SHA-256
against the exact artifact inventory. Credential
caches bind bus GUID, unique name, PID, and executable identity and are dropped
on `NameOwnerChanged` or bus restart; executable identity is never accepted
from self-reported payload text.

Both inner request and response are capped at 1 MiB before send and again at
method entry, below D-Bus's 64 MiB byte-array and 128 MiB whole-message hard
ceilings. zbus
concurrent dispatch feeds one service mutation sequencer; correctness follows
stable request identity and durable state, never bus arrival order. Large
objects remain digest-plus-secure-path references and Unix FD passing is absent.
The user bus is part of the 0.1 host TCB; hostile same-UID ptrace/PID-namespace
attacks and allocation denial of service remain nonclaims. Bus loss fences
effects first; the same process may reconnect and reacquire its name, while an
uncertain RPC is queried or exactly replayed. The Nexus child boundary remains
the separately frozen native-v1 bounded JSONL protocol.

The supported runtime baseline is Ubuntu 24.04 LTS amd64 (glibc 2.39, systemd
255, Linux 6.8), with systemd 254 as the feature floor and feature probes at
admission. Release builds start from the exact Debian 12 amd64 OCI manifest and
the pinned Rust nightly through the release-only
`packaging/release/Containerfile`, and the derived image digest is archived.
The development `Dockerfile` is not silently promoted into the release recipe.
Other Linux
distributions or backports are unsupported until their exact compatibility
cell passes; the Fedora development host is not a release baseline. This is
intentionally narrower than Rust's generic Linux target support.

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

The grant binds the effect operation, idempotency identity, role/slot, stable
logical incarnation, cohort, boot ID, exact projection, and native
request/receipt digests. Neither the controller nor `visa-nexusd` executes
profile I/O. After an agent crash, `armed` and `started` follow the separate
recovery rules above; replaying the grant never by itself executes the sink
again. This refinement
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
freezes exact Postcard `=1.1.3`, rustix `=1.1.4`, Wasmtime `=43.0.2`, and
bundled rusqlite `=0.40.1`. Every third-party direct dependency of a release
product root must use an exact `=` requirement. The external build inventory is
generated separately for each product root's target, release profile, and
feature set; it retains that root's reachable locked graph, dependency edges,
enabled features, sources, versions, and licenses. Adding the planned CLI,
agent, ownership, IPC, or Nexus-adapter crates therefore updates build evidence
without rewriting the product target. The current `EffectClosureProvider`
surface remains an in-tree Rust preview rather than a promised Rust ABI.
Protocol 2.0 and fault-matrix v1 remain historical; the 0.1 release profile
requires protocol 2.1, `AdmissionRequired`, and fault-matrix v2.

The pinned Nexus native-v1 freeze is an exact source contract at
`cb773539401107efe7a7ad036b80ff40d8ec305c`; it is not described as a Nexus
`v0.1.0` released API. The required consumable artifact must be Nexus-owned,
MPL-2.0, and explicitly identify the `nexus-effect-peer-native-v1` wire family.
The separate `nexus.portal.v2` preview cannot satisfy the native-v1 artifact,
adapter, mapping, or release-readiness slots. Local byte-exact freeze bytes and
the current native-to-neutral v2 mapping remain separate pending closure items.
The release component implementation is independently pinned to merged Nexus
revision `1e49cca428cff39961fd79cadd833ffe0f7365f5`, covering
the `crates/nexus-effect-peer` and `crates/nexus-effect-peer-wire` entry paths;
the complete build-source graph also includes their exact-revision workspace
locks, path dependencies, and path-included sources. That current
implementation pin does not rewrite the historical native-v1 freeze origin.
The mapping source is pinned to merged neutral-repository revision
`8983e5396ede187ef8c2e58ce09cce0ba77e2e25` and mapping digest
`18e66054d7a76004d7df19e7137a7c8e36749abd3cdcef0e93b21f4596f788d9`.
That mapping remains a candidate with `adapter_qualification=false`; a later
exact qualification receipt must consume the Nexus-owned corpus exported at
the release component revision without rewriting the `8983e539...` source
artifact. The final exact executable digest, complete source/build graph, and
Nexus-owned producer attestations must still fill the external inventory. The
artifact inventory keeps the pinned component source revision distinct from
the exact revision and tag of the workflow that produced its attestation; a
source revision alone is not executable provenance, and the inventory record
does not by itself prove the relationship. The component Git bundle must include
the historical freeze origin, component revision, and tagged producer revision,
including the exact release workflow and its full-SHA action pins, so that the
producer trust boundary remains inspectable offline.

The Nexus wire verifier receives a closed seven-role input set: the component
source bundle, complete source graph, exported native-v1 corpus, release
artifact inventory, exact binary, its standard build-provenance bundle, and a
separate release-Link bundle. The first attestation is the default SLSA v1
provenance emitted by `actions/attest` at exact commit
`f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6`. The outer checker requires the
official `https://actions.github.io/buildtypes/workflow/v1` shape and
cross-checks its workflow, producer revision/ref, repository IDs, hosted-runner
identity, builder, and invocation against the verified signing certificate. It
does not reinterpret `resolvedDependencies` as custom component materials.

The second attestation uses the existing in-toto Link v0.3 predicate under a
strict vISA/Nexus profile. It binds the same captured binary and same
certificate run invocation to the exact build argv and build-record ID, the
component revision, and the prebuilt source-bundle, source-graph, and corpus
digests. Logical material names plus digests identify archive inputs; vISA does
not fabricate `file:` URIs from later archive paths. For both attestations, the
checker hashes the bundle bytes it actually passes to the private `gh` copy and
compares that digest with the artifact inventory or runtime-input binding. The
typed verifier must additionally prove the producer tag/workflow/action pins,
source/freeze ancestry, byte-identical freeze bytes, graph closure, corpus
equivalence, and matching build-record and binary identities.

The exact-tag producer uses a no-input `push` workflow. Every
artifact-influencing job is GitHub-hosted. Build and qualification jobs declare
an exact job-level permission map containing only `contents: read`; a separate
minimal attestation job may only download and validate their outputs and must
not execute component code. The attestation job declares exactly
`contents: read`, `id-token: write`, and `attestations: write`; every omitted
scope is `none`, and every third-party action is pinned by full commit SHA. A
valid signature with the wrong standard shape, a missing or substituted Link
material/build record, or a Link from another run fails closed. This profile
does not claim hermetic derivation, source-to-binary reproducibility, or a SLSA
level.

The contract locks the three WIT package IDs and exact source bytes. WIT already
has package SemVer; vISA does not invent another 0.1 package format. Publication
and supply-chain evidence are independent release items.

## Semantic corpus and evidence closure

The four current Postcard command/event/journal/snapshot vectors remain useful
seed examples, while the three version vectors lock namespace values. They do
not close the release semantic corpus. Release readiness requires a generated,
committed type inventory and golden corpus covering every durable or public
serialized type and every enum variant in `contract_core`,
`joint_handoff_core`, and `visa_profile`, plus the three independent local RPC
corpora, including round-trip, decode/re-encode identity, non-minimal varint and
unknown/trailing-byte rejection, ordered collection cases, and bounded extrema. Rust must
construct and verify the corpus; source-literal presence is not execution
evidence.

The immutable target contract records required IDs and evidence policy but no
current satisfied/pending state and no closure artifacts. A separate mutable
`visa-0.1-readiness.toml` development ledger binds the target's exact SHA-256,
tracks the current partition, and may cite repository-relative development
evidence. That ledger is useful for progress and is checked by the default
command, but it is explicitly not final release evidence. Its development
receipts bind selected reproduction anchors rather than the full set of files
read by the repository checker; they require a fresh current-checkout checker
run and cannot serve as historical input-closure receipts.

Final closure lives in an evidence-self-contained immutable archive, not an ambient
checkout. The archive retains a complete Git source bundle with an annotated RC
tag, the original `Cargo.lock` and `rust-toolchain.toml` bytes, the exact typed
verifier dispatcher, all evidence and receipts, both build inventories, all
five executable artifacts, four systemd user units, their attestations, an
exact payload manifest, `SHA256SUMS`, an exact `gh` binary at or above the
2.93.0 security floor, the offline
trusted root, and `REVERIFY.md`. Verification extracts Git objects from that bundle and
compares both annotated tag objects with the separately trusted release checkout;
the archive cannot select a different annotation that peels to the same commit.
It never consults ambient Cargo state or source files for archive-selected
identity. The invoking Python interpreter and standard library, resolved Git and
its runtime, kernel/filesystem, and non-hostile same-UID processes are a
pre-existing verifier-host TCB. Their recorded versions are compatibility and
audit observations, not byte-authenticity pins; the archive is not a runtime-free
trust bootstrap.

Each required ID maps to one closed typed verifier ID. A receipt binds the
fixed dispatcher path and digest, exact input digests, exit code, and output
digest. There is no receipt-supplied command and no CLI bypass. The current
dispatcher deliberately has no implemented release verifiers, so this
pre-0.1 tree cannot mint release-ready evidence even if a structurally plausible
receipt says “passed.” Implementations are added with the corresponding product
surface and adversarial tests.

Before invoking a typed verifier, the outer checker projects that ID's exact
receipt map into a fresh private input snapshot. Authenticated Git blobs occupy
`tagged-source/`; authenticated archive carrier files occupy `archive/`; an
outer-checker-generated `input-manifest.json` records both origins and roles.
The original archive path is never passed to the dispatcher, the dispatcher
runs under the invoking Python with `-I -S`, and the snapshot plus private
dispatcher bytes are rehashed after each run. This removes ordinary archive
TOCTOU and accidental undeclared reads from the verifier interface. It is not an
OS sandbox against a malicious tagged verifier, `/proc`/ptrace inspection, or a
hostile same-UID process; those remain inside or outside the declared host TCB,
not a 0.1 confinement claim.
The file/count/byte/time limits bound normal verification work but do not claim
multi-tenant availability against a deliberately expensive operator-selected
archive or unbounded output from malicious code already inside the tagged
verifier TCB.

The checker rejects duplicate JSON keys, noncanonical or aliased paths,
symlinks, hardlinks, non-regular entries, per-file/aggregate size overflow, and
any file outside the exact archive inventory. Descriptor-relative `O_NOFOLLOW`
opens keep path validation and reads on the same file identity. A typed artifact
inventory binds target, profile, features, argv-form build command, byte digest,
attestation, and every executable hash used by an RPC handshake.

Structural receipts alone are never release authority. The trusted GitHub
workflow attests `index.json` itself with `actions/attest`; release admission
uses offline `gh attestation verify` with the repository, exact signer workflow,
signer digest, source digest, RC tag ref, archived Sigstore bundle, the CLI's
`--custom-trusted-root`, and self-hosted-runner denial fixed by policy. The
pre-existing verifier host described above and independently supplied SHA-256
values for the archived `gh` binary and trusted-root snapshot are the
verifier-host TCB; neither the index nor archive may choose the two digests. The
checker verifies the binary bytes, copies them to a private path,
checks the exact version and security floor, and authenticates the index before
any archived dispatcher runs. At the final stage it also authenticates the
post-tag receipt before cloning the receipt-selected final bundle or running any
archived dispatcher. Git and `gh` receive private working/config
directories, clean allowlisted environments, no prompts, credentials, proxy,
hooks, replacement objects, or network-capable protocol. It does not trust custom predicate
prose as proof. Each shipped artifact receives the analogous
source/workflow-bound verification. The dispatcher is kept outside the private
`gh`/trusted-root directory; both bootstrap inputs are rehashed and the `gh`
version is rechecked before the index is authenticated again after all typed
verifier executions and archive rehashing.

The supply-chain verifier reuses `cargo vendor --locked --versioned-dirs` and
archives the vendor tree, source-replacement config, and file inventory. From a
private `CARGO_HOME` with networking disabled it extracts a complete archived
Rust toolchain tree and runs its absolute Cargo with `cargo metadata --frozen
--offline` for every product-root target/feature set, then compares the graph
with the archived inventory. It does not pretend that two standalone
`cargo`/`rustc` files constitute a toolchain.

The exact producer set is also frozen instead of being deferred until RC.
Buildx 0.35.0 drives a BuildKit 0.31.2 `docker-container` builder for the OCI
directory export. These are exact release inputs, not floating “latest” aliases;
BuildKit 0.31.2 is the current security-patch release selected on 2026-07-19.
`cargo-deny` 0.20.2 records license/source/ban policy plus the exact RustSec
database revision, digest, and observation time; `cargo-auditable` 0.7.5 embeds
and exports the `.dep-v0` inventory of every final Rust binary; `cargo-about`
0.9.1 produces raw license data and the notice; `cargo-cyclonedx` 0.5.9
produces the target/feature-specific expected dependency graph; and Syft 1.48.0
observes the final binaries, OCI layout, and release tree. The expected graph,
embedded inventory, and Syft name/version sets must agree or carry a typed,
reviewed explanation. `cargo-vet` 0.10.2 remains a phased framework with
explicitly counted, owned, reasoned, expiring exemptions. `cargo-dist` 0.32.0
may later package already-admitted bytes but may neither install floating tools
nor decide admission. Archived askalono, nightly Cargo SBOM, and a redundant
second Cargo SBOM generator are not on the 0.1 release path.

Per-verifier input inventories bind every selected tool identity, exact version,
binary digest or action commit, argv, config, advisory snapshot, SBOM, license
output, observation, and reconciliation report into both the receipt and
archive manifest. Build-image provenance separately reuses BuildKit/Buildx
with an exact recipe, context, `linux/amd64` platform,
named builder, `type=oci,tar=false,oci-mediatypes=true`, disabled implicit
provenance and SBOM attestations, and `--metadata-file`. The producer must start
with an absent layout destination and a pre-created metadata parent; an existing
layout is rejected instead of being updated.
The OCI layout's unmodified regular-file bytes are archived as an owned sorted file set:
each regular file is an individually hashed verifier-receipt input, so no second
"deterministic tar" format or extraction TCB is invented. The typed verifier
preserves the raw version-bound Buildx metadata but treats only the standard
`mediaType`/`digest`/`size` descriptor and equal `containerimage.digest` as
image identity. It cross-checks that descriptor with the sole top-level
`index.json` result, then walks the OCI index/manifest/config/layer descriptor
closure and rejects missing, external, uninventoried, or unreferenced blob
content under explicit depth/count/byte bounds. The producer record-ID set is
closed and unique: it is exactly the derived image record plus every release
artifact build record, with no orphan or duplicate. Those records bind exact
producer versions or action commits, binaries, argv, inputs, outputs, and the
builder-image record. Offline
verification does not execute Docker. This verifies inputs, graph, provenance,
and artifact bytes; it does not claim an offline image rebuild,
source-to-binary reproducibility, or a SLSA level.

Those bounds are part of the target rather than verifier-local defaults: at
most 4,096 layout files and 8,192 reachable descriptors, descriptor depth 32,
512 MiB per archive file/blob, 1 MiB per verifier receipt, and 4 GiB for both
the complete archive read budget and reachable OCI bytes. The 4,096-file bound
is intentionally encodable as individual path/digest entries inside the receipt
limit. The OCI specification permits extra files, but the narrower vISA
canonical producer profile admits only regular files `oci-layout`, `index.json`,
and `blobs/sha256/*`; Docker-archive `manifest.json` is rejected by this profile,
not by OCI itself. Empty producer-internal directories such as BuildKit's
`ingest/` carry no file identity and are ignored, while any file beneath them is
rejected. A real release recipe that exceeds these bounds must revise and
re-review the target; it cannot silently raise a verifier constant.

The flow has two explicit immutable archive roots. First, freeze source commit `C`, create an
annotated `v0.1.0-rc.N` tag at `C`, archive and attest the immutable RC index,
and verify `rc-admitted`; that RC root is never appended to. Then create an
annotated `v0.1.0` tag. A separate final root re-runs the complete RC validation
and adds a post-tag receipt that binds the immutable index digest, both tag
objects, a final source bundle, and proves both tags peel to exactly `C`; both
objects must also equal the tags in the separately trusted checkout. Its own
attestation is verified at the final tag ref. Only that second step is
`final-release-verified`. Any source change requires a new RC. A later claims
ledger may advance on main without moving either release tag.

The checks deliberately have different meanings:

```sh
python3 scripts/check-release-contract.py
python3 scripts/check-release-contract.py --release-ready \
  --release-stage rc-admitted --archive-root /archive/visa-v0.1.0-rc.N \
  --attestation-verifier-sha256 "$GH_SHA256" \
  --trusted-root-sha256 "$TRUSTED_ROOT_SHA256" \
  --expected-source-tag "v0.1.0-rc.N"
python3 scripts/check-release-contract.py --release-ready \
  --release-stage final-release-verified --archive-root /archive/visa-v0.1.0-final \
  --attestation-verifier-sha256 "$GH_SHA256" \
  --trusted-root-sha256 "$TRUSTED_ROOT_SHA256" \
  --expected-source-tag "v0.1.0-rc.N"
```

The first verifies the immutable target plus the target-bound mutable
development ledger: exact local locks, authority/failure topology, current
pending/satisfied partition, and attached development receipts. It never treats
that ledger as release closure. The second admits the exact RC archive; the
third additionally requires the post-final-tag bundle, receipt, and attestation.
Both release stages validate complete ID coverage, typed receipts, source and
artifact identities, reachable build graphs, exact archive inventory, and the
trusted attestation policy. With no complete authenticated archive they fail by
design. A schema-valid target or development ledger is never itself product or
release evidence.
