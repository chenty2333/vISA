# vISA Development Guide

Status: current repository workflow.

Last reviewed: 2026-07-19.

This document describes commands that exist in the repository today. It is not
a claim that the current build and test surface validates the target system in
full. Read the project [vision](VISION.md) and [architecture](ARCHITECTURE.md)
before changing scope, contracts, dependency direction, or evidence claims.

## Supported environment

The supported development environment and current CI parity boundary is the
`dev` service in `compose.yaml`. Its image contains:

- the `nightly-2026-06-07` Rust toolchain declared by both `Dockerfile` and
  `rust-toolchain.toml`;
- `rust-src`, `rustfmt`, `clippy`, and `llvm-tools-preview`;
- the `wasm32-unknown-unknown`, `x86_64-unknown-none`, and
  `aarch64-unknown-linux-gnu` targets;
- Node 24.15.0 with V8 13.6.233.17-node.48, installed from the official
  architecture-specific archive after SHA-256 verification;
- on linux/amd64 image builds, the official Go 1.26.5 archive plus the
  source-lock-bound Wacogo module zip and offline module-cache seed used only by
  the x86-64 Linux Strict Stage 2 gate;
- QEMU and OVMF for the current x86_64 kernel runner;
- the GNU AArch64 cross-C toolchain, the AArch64 glibc development sysroot at
  `/usr/aarch64-linux-gnu`, and QEMU-user `qemu-x86_64`/`qemu-aarch64` for the
  bounded Stage 4 matrix; and
- the C, autotools, and Linux packages used by the LTP helpers.

The Node x64 and arm64 archive digests are copied from the official
[`v24.15.0` checksum list](https://nodejs.org/dist/v24.15.0/SHASUMS256.txt).
The Rust toolchain is date-pinned because later nightly compiler changes can
break the bootloader dependency independently of vISA source. The
`debian:stable-slim` base image is not digest-pinned, so this environment still
provides local/CI parity rather than a bit-reproducible release toolchain.
Release claims require all inputs pinned.

Host-native Cargo commands are useful for short edit cycles, but the host is
not the CI parity boundary. A host workflow must independently provide the
declared Rust toolchain, targets, cross linker, target glibc sysroot,
QEMU/OVMF or QEMU-user when required, and any external workload dependencies.
The bounded Stage 4 aggregate additionally fails closed unless its raw
`/usr/bin/uname -s -r -m` receipt identifies an x86_64 Linux orchestrator
execution environment.

On SELinux hosts, Compose disables container labeling so the workspace remains
accessible. After changing Docker group membership, start a new login session.

## Build and enter the development image

For the usual UID and GID of 1000:

```sh
docker compose build dev
docker compose run --rm dev
```

On a host with different user IDs, build the image with matching values so
bind-mounted outputs remain owned by the developer:

```sh
VISA_DOCKER_UID="$(id -u)" VISA_DOCKER_GID="$(id -g)" \
  docker compose build dev
```

The repository is mounted at `/workspace`. Cargo and LTP caches use Docker
volumes by default.

## Repository gates

The repository exposes two cumulative repository tiers, the Stage 1/2/3
standalone system gates, one Stage 3 aggregate, and one complete bounded Stage
4 aggregate with two edit-loop aliases, plus one bounded joint-handoff gate.
Run the ordinary edit-loop gate with:

```sh
scripts/run-docker-ci-gate.sh fast
```

Run the pull-request gate with:

```sh
scripts/run-docker-ci-gate.sh full
```

Run the Stage 1 reference system gate with:

```sh
scripts/run-docker-ci-gate.sh system
```

Run the Stage 2b JcoNode reference cell with:

```sh
scripts/run-docker-ci-gate.sh system-jco-node
```

Run the complete four-direction Stage 2c matrix with:

```sh
scripts/run-docker-ci-gate.sh system-stage2
```

Run the locked Strict Stage 2 Wasmtime/Wacogo matrix with:

```sh
scripts/run-docker-ci-gate.sh system-stage2-strict
```

Run the bounded Stage 3A regular-file gate with:

```sh
scripts/run-docker-ci-gate.sh system-stage3a
```

Run the bounded Stage 3B logical-request gate with:

```sh
scripts/run-docker-ci-gate.sh system-stage3b
```

Run both Stage 3 profiles in sequence with:

```sh
scripts/run-docker-ci-gate.sh system-stage3
```

Run the complete bounded Stage 4 target/substrate and emulated cross-ISA matrix
with:

```sh
scripts/run-docker-ci-gate.sh system-stage4
```

`system-stage4-target` and `system-stage4-isa` are names for focused edit
loops, not smaller claim gates. Both currently fail closed by running the same
complete seven-cell aggregate:

```sh
scripts/run-docker-ci-gate.sh system-stage4-target
scripts/run-docker-ci-gate.sh system-stage4-isa
```

Run the bounded joint-handoff vISA/reference cell with:

```sh
scripts/run-docker-ci-gate.sh system-joint-handoff
```

This tier deliberately requires a clean worktree at an exact vISA Git SHA. It
validates remote-accepted neutral implementation
`f4a8211f0e5fde13e0f6101be3c3322854458c79` at tree
`a65f264bb7eaf390cbd6285d791b4f7f43e9be25`. The vendored bundle SHA-256 is
`afe0fdfba1d2e47f5b6ee582833c03befca8e436f3a3d09d0b5df27612549e31`
and the complete source-lock SHA-256 is
`e8894d79ba2b3f164e94451d14139313a477481dc11c94d84a76a7ef774b9d50`.
The implementation's downloaded exact-SHA artifact passed independent
verification; `be250c30...` is its receipt lineage. The tier runs 16
production-reducer traces, executes 16 normative reference ownership/effect
cases plus one supplemental retained-tombstone recovery, reopens the durable
SQLite projection, and executes the HostSubstrate commit and abort verticals.
The Host cell retains exact 14-record commit and 9-record abort transcripts,
including canonical pre-call bytes for seven peer-invocation classes. The
independent verifier recomputes those transcripts, receipts, peer relations,
local journals, leases, checkpoints, and terminal states. The tier publishes an
exact two-file bundle and verifies it again after relocation.

The source-locked neutral refinement map still declares
`adapter_qualification=false`; it is a mapping baseline, not Nexus execution
evidence. The separate Nexus-local lane
is driven by:

```sh
scripts/run-nexus-handoff-qualification.sh \
  --checkout <clean-nexus-checkout> \
  --artifact-root <new-artifact-root>
```

That lane is locked to Nexus revision
`8e5123c46569e8ebdaba9f4f56bea6584ab58586`, source fingerprint
`017c681b...`, matrix `9f3f1579...`, and v2 qualification-lock SHA-256
`21b5404bc5c1ad1f48c4ffe37cf455d104acac8ab9deca98f326d7c9b06072d9`.
The receipt records `production_registry_refinement_checked=true`. Its SHA-256
is specific to one generated run and is recorded only in a corresponding
validation receipt.

Run the standalone exact-binary process publisher with:

```sh
scripts/run-nexus-process-joint-cell.sh \
  --nexus-checkout <clean-nexus-checkout> \
  --nexus-bin <exact-nexus-effect-peer> \
  --artifact-root <new-final-artifact-root>
```

Exact-binary process tests cover raw-chain replay, Registered-effect abort preservation, the bounded
process qualification scenarios, and the real logical-request dual-lost-ack
cell. The latter is supplemental: it performs a post-durable ownership Commit acknowledgement loss
and a terminal Nexus response loss before adapter acceptance; both recover via
exact query/retry without duplicate execution or publication, but does not run
vISA freeze/fence/activation or put Nexus admission before the external effect.

The standalone runner validates both locks and the Nexus receipt, publishes an
exact three-file process artifact containing the executed binary, verifies it in
a second process, relocates it, and verifies the same bytes in a third. The
supplemental logical runner publishes five files: manifest, report, two SQLite
databases, and the same content-identified binary. Download verification accepts
artifact-service mode normalization, does not re-execute the binary, and does
not claim reproducible source-to-binary derivation. The accepted clean artifacts
bind exact vISA implementation
`d3b07f1114cb49e26dd62fb252a895022ac2a743`; their local, Docker, exact-SHA CI,
relocation, and post-download closure is recorded in the
[joint-handoff closure receipt](VALIDATION.md#joint-handoff-closure-receipt).

The Host refinement requires `exclusive_trusted_coordinator_api=true`: bypass
through a second raw `Coordinator`/provider handle or hostile public-projection
caller is outside the bounded TCB. None of these local lanes qualifies Registry
replacement, real OSTD, IRQ/SMP, the production retained-tombstone path,
cross-host, host-reboot, Byzantine-ownership, cryptographic,
anti-rollback/freshness, TEE/KMS, or Stage 5 behavior; their crash boundary is
same-boot.

With no tier argument the wrapper runs `full`. It validates the Compose
configuration, builds the image, then invokes the same `scripts/ci-gate.sh`
implementation used by CI. `--skip-build` reuses an existing image.
`--ci-cache` overlays `compose.ci.yaml`. It bind-mounts Cargo and LTP build state
below `.ci-cache/`, places system evidence below `.ci-artifacts/`, and disables
Cargo incremental compilation to match GitHub Actions. Inside the container,
the artifact mount is exposed at the ignored `/workspace/evidence` alias so a
clean-checking qualification gate cannot mistake its own output root for source.

The strict Docker wrapper retains its gate root, locked Wacogo sidecar and build
receipt, Docker log, and exit receipt together below `.ci-artifacts/strict-stage2/`
by default. `--artifact-parent DIR` selects another parent. For a direct Host
run, provide the prefetched inputs named by `VISA_WACOGO_GO_ARCHIVE`,
`VISA_WACOGO_GO`, `VISA_WACOGO_MODULE_ZIP`, and
`VISA_WACOGO_GOMODCACHE`, then run:

```sh
scripts/ci-gate.sh system-stage2-strict
```

Both entries converge on `scripts/run-strict-stage2-local-gate.sh`; the Docker
path supplies the same locked inputs from the development image rather than
using a second implementation of the gate.

`fast` checks locked metadata, formatting, strict active-spine dependency
direction, the Stage 1 legacy-deletion/oracle boundary, first-party Rust file
sizes (including not-yet-added files), the build/cache/evidence CI contract, the
schema-valid but deliberately not-yet-release-ready
[vISA 0.1 exact-version target contract](../specs/release/visa-0.1.md), the
locked JcoNode Cargo/source/Node/V8 identity, strict Clippy for active-spine
targets, and active-spine tests. `full`
includes `fast`, then adds shell parsing,
default-feature workspace tests, every current opt-in feature, active no-std
compilation, selected Wasm packages, the kernel target, benchmark compilation,
and report/artifact fixture gates. Every `system*` tier is standalone and does
not repeat `fast` or `full`. See [VALIDATION.md](VALIDATION.md) for the exact
proof boundary.

Run the dependency-direction check directly with:

```sh
python3 scripts/check-dependency-direction.py
```

It rejects dependencies that point against the accepted contract -> reducer ->
coordinator -> adapter/tool direction. Oracle packages remain buildable under
`full`, but they cannot enter the protected production spine.

Check the frozen vISA 0.1 target separately with:

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

The first command is part of `fast` and validates the immutable target plus its
target-digest-bound mutable development readiness ledger. The target admits at
most five resident product roles plus one mutating CLI holding the exclusive
controller-operation lease under `systemd --user`: two direct-execution Wasmtime agents, one
independent ownership service, one Nexus adapter service, and its one native-v1
peer child. Concurrent read-only CLI diagnostics are not controller roles. The existing
systemd user manager, D-Bus daemon, and library threads are host infrastructure,
not product-role processes; the CLI uses the typed user-bus Manager interface
instead of spawning `systemctl`. `cohort-create` and `cohort-retire` are local
pre-RPC launch/supervision operations and never issue authority receipts. The
lease lives directly under the pre-existing `${XDG_RUNTIME_DIR}`, so first-use
parent-directory creation cannot precede lease admission. Its first mutation is
an `O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK` flat-path open followed by
regular/euid/nlink/mode checks and nonblocking `flock`; the file is never
unlinked. The
controller/agent, agent/ownership, and agent/Nexus schemas remain independent
user-bus D-Bus interfaces implemented with zbus. Each uses `Execute(ay) -> ay`
with a canonical Postcard 1.1.3 inner payload capped at 1 MiB; names, object
paths, interfaces, signatures, credential-bound executable admission, and
inner bytes are locked, while outer D-Bus bytes are not. Large artifacts remain
digest-plus-secure-path references. The 0.1 admission profile requires
effect-closure provider protocol 2.1 and fault-matrix v2; protocol 2.0 and
fault-matrix v1 remain historical contracts. The Nexus child boundary stays
native-v1 JSONL, with the historical freeze origin kept distinct from the
merged release-component source pin. The artifact inventory separately records
that component source revision and the exact tagged workflow revision that
produced the Nexus-owned attestation; a later producer commit may build the
pinned component checkout without being relabelled as its source. That record
is not the cross-pin proof. The component Git bundle must also contain the
tagged producer revision, exact workflow source, and full-SHA action pins, not
only the older component checkout.

The `nexus-native-v1-wire-artifact` verifier gets seven closed inputs: the
archived component bundle, closed source graph, exported corpus, artifact
inventory, binary, standard build-provenance bundle, and separate in-toto Link
v0.3 bundle. The outer checker verifies the exact binary subject twice. It
requires the default `actions/attest` SLSA v1
`https://actions.github.io/buildtypes/workflow/v1` predicate for producer
identity, cross-checking its OIDC-derived source, workflow, repository IDs,
hosted runner, builder, and invocation with the verified certificate. A strict
Link profile separately binds the same binary and run invocation to the exact
component revision, build argv/record, and prebuilt bundle/graph/corpus
digests. The exact bundle bytes handed to `gh` are hashed against their
inventory/runtime bindings before verification. The typed verifier closes
producer workflow/action-pin checks, component and freeze ancestry, graph and
corpus equivalence, and build-record and binary identity.

The exact-tag Nexus producer is a no-input `push` workflow with every action
pinned by full SHA. Build and qualification jobs are GitHub-hosted and declare
an exact job-level permission map containing only `contents: read`. A separate
GitHub-hosted attestation job declares exactly `contents: read`,
`id-token: write`, and `attestations: write`; every other scope is `none`. It
downloads and validates outputs but never executes component code. This is a
locked producer profile, not a SLSA-level, hermetic-build, or reproducibility
claim.

The second command verifies the authenticated `rc-admitted` archive; the third
additionally requires the annotated final tag and the attested post-tag receipt.
Both operate from the explicit evidence-self-contained archive and source Git
bundle, reject path aliases/symlinks/hardlinks and duplicate JSON keys, and
require closed typed verifier receipts plus fixed GitHub/Sigstore workflow and
source identities. They also require independent pins for the archived exact,
security-floor-compliant `gh` binary and custom trusted root. The initial index
attestation must pass before any archived dispatcher is executed, and
final-stage verification also authenticates the post-tag receipt before cloning
its final bundle. The RC and final annotated tag objects must exactly match the
separately trusted checkout, not merely peel to the same commit.

Each dispatcher invocation receives a fresh private `tagged-source/` plus
`archive/` input snapshot generated from the exact receipt, never the original
archive root. It runs with Python `-I -S`; the snapshot and dispatcher are
rehashed afterward, and the dispatcher is not colocated with the private
`gh`/trusted-root copies. This is input closure within the trusted host, not
hostile same-UID process confinement. The build inventory is per product root
and retains the reachable locked graph/features; the supply-chain verifier
rebuilds those graphs offline with archived Cargo/Rustc plus
`cargo vendor --locked --versioned-dirs` inputs. The release image producer is
pinned to Buildx 0.35.0 and BuildKit 0.31.2, uses a fresh `tar=false` OCI
directory, and archives every layout file through an owned file-set inventory.
The layout permits at most 4,096 files and
the vISA canonical regular-file profile permits only `oci-layout`, `index.json`,
and `blobs/sha256/*`. OCI itself permits extra files; empty BuildKit-internal
directories carry no identity, while files beneath them are rejected by the
vISA profile. Offline verification does not rerun Docker during
verification or claim source-to-binary reproducibility. The artifact inventory binds all executables,
systemd units, hashes, build argv, component source revisions, attestation
producer revisions, and subject attestations; an external component's
source-to-binary relationship remains a separate authenticated-material and
typed-verifier obligation. Updating the development ledger never
closes either external gate. Development receipts list selected reproduction
anchors, not every ambient source read by the full checker, so only a fresh
current-checkout checker run can support those development-only satisfied IDs.

For the pending typed OCI verifier, apply the build-vs-reuse rule: reuse the
OCI project's `image-spec/schema` and `specs-go/v1` definitions plus
`opencontainers/go-digest` streaming validation in a pinned helper, while vISA
owns only its stricter regular-file profile, reachable-closure walk, release
bindings, and resource bounds. A pinned `umoci` run may serve as a differential
interop oracle, not admission authority. No existing upstream helper covers
that complete composition, so the profile/closure layer remains small
vISA-owned code rather than a second general OCI implementation.

For the three pending local RPCs, the same build-vs-reuse rule selects zbus
5.18.0 for user-bus transport, Postcard 1.1.3 for the bounded inner bytes,
`postcard-schema` 0.2.5 for reflection, and
`serde_json_canonicalizer` 0.3.2 for
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) artifact bytes. The
transport-independent `visa_local_rpc` crate owns only vISA's three concrete
families, request-paired response APIs, field-level authority bindings, strict
decode/re-encode rule, and exact replay records. Its generic codec remains
crate-private, and agent-control response acceptance also binds the verified
Source/Destination endpoint role. Neutral receipt carriers recompute the exact
joint-handoff receipt digest with an exhaustive kind/tag/content-schema map;
this is byte-carrier consistency, not typed receipt or issuer authentication.
The service/adapter readiness slices must apply the `joint_handoff_core` typed
decode/re-encode, full header/key/request-binding, and authentication verifier
before receipt adoption or mutation. The std-only JCS implementation remains in
`visa-conformance`; it does not enter the wire crate. Owned schema is not
treated as a wire-compatibility proof: static gates reject unsupported Serde
shape attributes, floats, unordered collections, sibling-family imports, and
manual serialization, while three Rust-constructed all-variant corpora lock
the actual bytes and execute paired request/response/replay malformed and
binding substitutions. Neutral key/reference shapes, receipt tags, and receipt
digest behavior are checked against `joint_handoff_core`. Run
`cargo run --locked -p visa-conformance --bin visa-local-rpc-artifacts -- --check`
to rederive all six checked-in artifacts. This pure-wire slice does not yet
satisfy any local-RPC readiness ID; zbus transport, bus-controlled credential
admission, service-owned durable replay, and process/restart evidence remain
separate gates.

The O3 supervised-process refinement follows the same rule. It reuses the
release contract's existing systemd `GetUnit` method plus Unit `Id`, Unit
`InvocationID`, and Service `MainPID` properties through a minimal
zbus-generated proxy. rustix retains the local pidfd and performs secure
`/proc/<pid>/exe` observation. vISA owns only the exact role-to-unit mapping,
stable-agent identity policy, generation cursor, and fail-closed composition
with its admission barrier. A broad generated systemd API crate, another D-Bus
codec, or a generic retry/RPC framework would add a second compatibility
surface without replacing any vISA-owned semantics. The product agent must use
the same user-bus connection both to own its frozen role name and to call
ownership/Nexus services; a second connection has a different bus-controlled
unique name and is not the admitted role owner.

Admission calls `GetUnit` with the exact frozen role unit, verifies the returned
object's primary Unit `Id` and invocation ID, and requires Service `MainPID` to
equal the bus-controlled live process. The pidfd is never sent to systemd; it
brackets both property observations and stays retained through the final
synchronous liveness check immediately before queue insertion. This does not
relax the no-file-descriptor rule on any vISA `Execute(ay) -> ay` business
interface. systemd attests the live invocation ID used as process nonce, while
the agent store remains the sole allocator of the durable process generation
and the ownership caller cursor rejects stale or conflicting pairs at commit.
The composition does not claim an atomic snapshot spanning procfs, the bus
daemon, systemd, and the ownership queue, nor does it cover a hostile same-UID
process that preserves a bus socket across executable substitution.

The next bounded O1 slice now lives in `visa_ownership_service`. It is a
transport-independent product ownership authority core, not the final
`visa-ownershipd` process. The service-owned SQLite transaction performs exact
request-ID admission, ownership mutation, request-paired response construction,
and exact response persistence atomically under `BEGIN IMMEDIATE`. Create-new
and reopen-existing are distinct fail-closed paths; the store persists its
cohort/boot/runtime/issuer/receipt-policy identity, retains active-cohort replay
rows without TTL, retains a gap-free process-generation/nonce history with
completion-order boundaries, audits its exact schema and authority history, and
rebuilds a shadow projection by replaying the durable exact RPC ledger at
startup. The same ledger now rebuilds per-role agent caller cursors: a current
process tuple may continue, or a later generation with a new nonce may advance
only when its terminal exchange commits; rollback, nonce reuse, and stable
logical-incarnation substitution fail closed without a second table. Seal
admission reuses the `joint_handoff_core` reducer for the typed neutral chain.
First creation converges through an audited, checkpointed, explicitly closed,
sidecar-free temporary SQLite database followed by `RENAME_NOREPLACE` and
file/parent fsync. Orphan initialization files are never adopted, while an
existing malformed final path or foreign SQLite sidecar fails closed without
replacement. This closes the partial-first-start window but is not the later
process kill/restart/lost-ACK evidence gate.
The fixed local issuer policy remains only a same-UID trusted-binary TCB pin:
without an authenticated neutral envelope it is not cryptographic or
request-bound authenticity. O1 alone changes no readiness-ledger status; the
zbus/credential/fence/sd-notify process slice and the real agent vertical remain
required before any ownership RPC or service ID can become satisfied.

The bounded O2 candidate adds the real `visa-ownershipd` executable without
introducing a second authority implementation. It reuses exact zbus 5.18.0,
rustix 1.1.4, `sd-notify` 0.5.0, and the O1 SQLite store. A digest-pinned,
secure-opened canonical bootstrap supplies the exact store/peer inventory; it
is an explicit launch input, not release provenance or a trust root. Each
`Execute(ay) -> ay` call rechecks the bus-controlled sender, role-name owner,
UID/PID, ProcessFD or double-query pidfd fallback, and `/proc/<pid>/exe`
identity/digest before the name-loss commit barrier admits it to the bounded
single-writer queue. READY is delivered only after store audit, interface
export, watcher installation, exact no-replace name acquisition, and gate
activation. A private-session-bus test locks the introspected method signature,
READY visibility, and DoNotQueue/no-replace behavior. O2 still changes no
readiness-ledger status: the installed artifact inventory, systemd user unit,
real Source/Destination agents, process kill/restart/lost-ACK verifier, and
Ubuntu 24.04 compatibility cell remain O3 work.

The implemented `system` tier creates a private artifact root, runs all 31 Stage
1 registry cases through isolated source and destination worker processes,
writes an execution evidence bundle, then invokes the independent
`visa-conformance stage1` validator. Direct Host and normal Compose runs default
to `target/visa-system/`; `VISA_EVIDENCE_PARENT` selects another parent, and the
CI-cache overlay fixes it at the host-visible `.ci-artifacts/` mount. The command
prints the retained artifact root and bundle path on success and preserves them
on failure for diagnosis.

On Linux, the verifier requires race-safe descriptor-relative artifact opens;
it never falls back to `canonicalize` followed by an ambient pathname read.
Digest and semantic validation share one captured byte view, and Stage 2 reuses
that view for its inner audits and normalization. Secure artifact inputs are
limited to 256 MiB per file and 128 MiB of retained Stage 1 bytes per cell;
digest-only executable provenance is streamed. An unavailable `openat2`, a
kernel-reported unstable resolution after bounded retries, a
symlink/magic-link/mount escape, a non-regular file, or an exceeded limit is a
gate failure.

`system-jco-node` applies the same 31-case and independent Stage 1 verification
flow to an explicitly selected JcoNode-to-JcoNode pair. `system-stage2` creates
one root containing all four Wasmtime/JcoNode source-destination cells, runs
124 cases, then invokes the independent Stage 2 verifier over the outer bundle.
This legacy v2 matrix retains its `cross-execution-path-portability` claim and
does not become independent-runtime evidence.

`system-stage2-strict` verifies the official Go toolchain, byte-exact Wacogo
source lock and module input, fixed Component, seven selected-runtime
qualification gates, and two byte-identical sidecar builds. It then runs the
focused live-sidecar and real-Wacogo tests, independently verifies the
Wacogo-to-Wacogo Stage 1 cell, and executes the strict v3 matrix in this exact
order: Wasmtime-to-Wasmtime, Wacogo-to-Wacogo, Wasmtime-to-Wacogo, and
Wacogo-to-Wasmtime. A pass covers 124/124 executions and 31/31 normalized
equality groups and earns only `strict-cross-runtime-continuity` on x86-64
Linux with the timer/KV profile. Both Stage 2 matrix gates are intentionally
expensive and are not part of `full`.

The locked dev-profile Component was qualified with Cargo incremental mode.
The Strict gate therefore canonicalizes and records `CARGO_INCREMENTAL=1`
before building it, even though the general CI overlay uses `0` to reduce the
size and cross-run coupling of ephemeral target trees. Ambient CI settings
cannot silently select different Component bytes.

`system-stage3a` creates a private root under the same configurable evidence
parent, runs the fixed 12-case regular-file registry through the Stage 3A
Component, Wasmtime adapter, coordinator, scoped Linux file provider, handoff,
and evidence writer, then invokes `visa-conformance stage3a` independently over
the retained bundle.
Qualification requires Linux `openat2` and a filesystem that reports
`STATX_BTIME`. The provider compares device, inode, and birth time for both the
opened root and file; missing birth time is an unsupported capability with no
device/inode-only fallback. Its external-mutation cases detect identity,
content, or version drift already observable before a provider operation, and
provider tests deterministically race the final SQLite authority/lease/pre-state
fence against handoff commit. Lock/lease conflict behavior applies only to
writers participating in the same advisory protocol; the gate does not
establish atomic compare-and-mutate against an uncooperative writer that
bypasses it. Birth time is not a cryptographic identity or a Stage 5
host-attestation mechanism.

`system-stage3b` follows the same two-step runner/verifier shape for the fixed
14-case logical-request registry. It uses a real bounded loopback TCP
protocol/peer and a durable provider operation ledger, but it preserves logical
request identity and reconnect/replay state rather than a raw live transport.
The `VISALR03` handshake authenticates the configured peer with a fresh nonce
and HMAC-SHA-256 before sending an application request frame; credential
material is not transmitted, and Lookup/Cancel also authenticate the expected
request digest. Every application send performs a final authority, lease, and
binding check under the SQLite handoff transaction lock. Execute is bound by a
digest derived from the authenticated request bytes, while Lookup/Cancel carry
the expected digest. An immediate-transaction revision compare-and-save rejects
stale terminal/cursor/cleanup rollback. This bounded local admission fence is
not a general encrypted-channel or remote-effect atomicity claim.
`system-stage3` runs these two standalone gates in sequence and retains one
artifact root per profile.

The Stage 3 conformance commands are independent **structural bundle
verifiers**. The executable runner evaluates the case semantics; the verifier
then fixes the accepted registry and assertion shape, checks scope and runtime
identities, and revalidates the published artifact sizes and digests. Unlike
the typed Stage 2 normalizer, it does not recompute every semantic assertion
from the raw trace and request/response bytes.

Both Stage 3 gates currently use separate source and destination Wasmtime
stores, coordinators, and provider instances backed by local SQLite continuity
within one OS system-runner process on x86-64 Linux. This validates the current
local-rebinding profiles, not dual-worker process isolation, cross-host
transport, or a target change. Their bundles require
`independent_runtime_coverage=false` and list Wacogo as unsupported. Run
`system-stage2-strict` separately when checking the independent-runtime
timer/KV control; its conclusion does not transfer to Stage 3. The Stage 3 gates
do not claim arbitrary directory trees, devices, FIFOs, open fds, arbitrary
live TCP, socket state, generic future/stream continuation, or a general async
runtime.

`system-stage4` holds the Wasmtime implementation, timer/KV profile, and
31-case Stage 1 registry fixed while varying three target execution endpoints:

```text
Hx = artifact-owned x86_64-unknown-linux-gnu worker, executed natively
Qx = the same artifact-owned x86-64 worker under the artifact-owned
     qemu-x86_64 executable with -cpu max and the identified / sysroot
Qa = artifact-owned aarch64-unknown-linux-gnu worker under the artifact-owned
     qemu-aarch64 executable with -cpu max and the identified
     /usr/aarch64-linux-gnu sysroot
```

It cross-builds release x86-64 runner/worker/verifier binaries and the release
AArch64 worker, executes these seven unique cells, and independently verifies
the result:

```text
Hx -> Hx   Hx -> Qx   Qx -> Hx   Qx -> Qx
Qx -> Qa   Qa -> Qx   Qa -> Qa
```

That is 217 case executions, seven independently verified inner Stage 1
bundles, and 31 normalized observable groups compared across all seven cells.
The Stage 4 release build locks its own Component byte digest; it uses the same
Stage 1 source/WIT contract but is intentionally a different build artifact
from Strict Stage 2's dev-profile Component. The Stage 4 common input uses its
v2 schema to retain the same typed 3 Pending / 22 Precompleted / 6
ScenarioControlled timer-strategy partition as the Stage 2 common input; the
verifier checks both the snapshot disposition and authoritative final branch.
The aggregate publishes only `named-target-substrate-continuity-v1` for the
four Hx/Qx cells and `emulated-cross-isa-continuity-v1` for the four Qx/Qa
cells; the shared `Qx -> Qx` cell belongs to both claims. Workers, QEMU
executables, launcher/build/sysroot receipts, raw nonce-bound target hellos,
resolved loader-dependency digests, and the raw `uname` host receipt are
retained in the artifact root. Together with Hx's direct launcher, the host
receipt binds the run to an execution environment reporting x86-64 Linux and a
kernel release. It is not hardware attestation, bare-metal evidence, proof that
no outer virtualization/binfmt layer exists, or a cross-host proof.

The Stage 4 writer starts with `stage4-incomplete` and keeps
`stage4-status.json` after its initial status write succeeds. Runner failures
before publication normally retain those diagnostics; an earlier status-write
failure may retain only the marker. A success removes the status file, verifies
the complete staged artifact graph, and removes the incomplete marker only when
publication commits. A subsequent independent-verifier or relocation failure
is represented by the outer gate exit/log and does not recreate those runner
diagnostics. The separate
`visa-conformance stage4` process then checks all inner evidence, independently
recomputes normalization, validates the exact artifact set, and rejects native
fallback or claim expansion. The gate next renames the complete directory to
an unused `-relocated` path without rewriting any JSON and runs the verifier a
second time. `matrix.json` deliberately retains the historical execution root
for launcher-argv provenance while artifact lookup uses the new verifier root.
Unit negative coverage adds an unmanifested file, together with temporary,
symlink, hardlink, and special entries, and requires exact-set rejection.

The shared `performance-observations` input remains the original 50 ms timer.
Raw steady-state measurements are target-speed-dependent, so the runner now
waits for that timer outside the measured interruption interval, requires the
`Completed` safe-point branch before freeze, and verifies that restore does not
recreate it. This removes the observed QEMU-dependent Pending-versus-Completed
flake without lengthening or silently replacing the Stage 1 workload input.

This bounded matrix does not qualify real AArch64 hardware, the legacy
no-std/reference kernel, real-device enforcement, either Stage 3 resource
profile across targets, a second Stage 4 runtime, AOT binary portability,
cross-host execution, 32-bit or big-endian targets, hostile-host
confidentiality, performance, or production readiness. The Strict Stage 2
Wasmtime/Wacogo result remains a separate independent-runtime control and is
not inherited by Stage 4.

After one current image build, the stage-closing local control sweep is:

```sh
scripts/run-docker-ci-gate.sh --ci-cache --skip-build full
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-jco-node
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage2
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage2-strict
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage3a
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage3b
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-stage4
scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-joint-handoff
```

`full` and every `system*` tier are standalone; no green tier implies one of
the omitted controls. The two Stage 4 aliases need not be repeated because they
execute the same aggregate.

## Host Cargo commands

The repository defines these target-specific aliases in `.cargo/config.toml`:

```sh
cargo check-wasm
cargo wasm
cargo kernel
cargo run-vm --verbose
```

- `check-wasm` checks the selected Wasm-target packages for
  `wasm32-unknown-unknown`.
- `wasm` builds those packages.
- `kernel` builds the kernel for `x86_64-unknown-none`.
- `run-vm` runs the current QEMU runner and forwards following arguments.

For a changed package, prefer a focused command such as
`cargo test -p <package>` before a broader gate. Record the exact command and
result; do not describe a host-only check as equivalent to the Docker gate.

## Script hierarchy

The shell scripts are a transitional implementation surface, not a stable
public API. Use them according to their current role:

1. **Repository gate:** `run-docker-ci-gate.sh` is the supported outer entry;
   `ci-gate.sh` implements cumulative `fast`/`full`, the standalone system
   gates, the Stage 3 aggregate, and the complete Stage 4 aggregate inside the
   development environment, plus the joint-handoff vISA/reference gate.
2. **System evidence:** `ci-gate.sh system`, `system-jco-node`, and
   `system-stage2` preserve the Stage 1 and legacy v2 paths;
   `system-stage2-strict` adds the unified locked Wasmtime/Wacogo v3 path;
   `system-stage3a` and `system-stage3b` add the two bounded Wasmtime-only
   resource profiles, while `system-stage3` invokes both. `system-stage4`
   supplies the bounded native/QEMU-user target and cross-ISA aggregate;
   `system-stage4-target` and `system-stage4-isa` currently invoke that same
   full matrix. `system-joint-handoff` source-locks the neutral contract, runs
   production-reducer replay plus reference ownership/effect peers, and executes
   the separately reported HostSubstrate vertical. It is the accepted
   vISA/reference axis of the bounded qualification, not Nexus execution
   evidence. All orchestrate runners followed by independent verifier processes.
   Invoke the binaries directly only when investigating a retained artifact
   root.
3. **Report checks:** `run-report-gates.sh` and
   `check-conformance-report.sh` exercise report and artifact rules without
   proving external workload execution. `run-visa-bench-conformance.sh` runs
   Criterion and gates the produced performance bundle.
4. **vISA-backed LTP:** `build-visa-ltp-static-syscalls.sh` prepares static
   binaries; `run-visa-ltp-conformance.sh` is the strict selected-suite entry;
   `run-visa-ltp-single.sh` is its per-case worker. The manifest runner is for
   larger exploratory runs and is not the stable strict gate.
5. **Reference-only LTP:** `run-host-ltp-log-adapter.sh` preserves logs from an
   external host `runltp`. Those logs do not prove execution through vISA.
6. **Structural maintenance:** `check-file-size.sh` scans tracked and
   not-yet-added first-party Rust sources and runs as part of `fast`. Hard-limit
   violations in active-spine sources fail the gate; oracle/reference and other
   out-of-spine findings remain informational.

Read each script's usage text, using `--help` where supported. Keep specialist
runners behind a small developer-facing surface.

## Outputs and caches

`target/`, `.ci-cache/`, `.ci-artifacts/`, and the CI-only `evidence/` bind alias
are ignored, but they have distinct lifecycles. The CI-cache overlay stores Cargo
registry/git state, transient Cargo target output, and the LTP build cache below
`.ci-cache/`; GitHub Actions restores only Cargo registry/git state across runs,
never the full target tree. The
quality job owns publication of that shared dependency cache, while claim lanes
restore it without publishing duplicates. Current CI does not run or cache an
external LTP build. CI sets `CARGO_INCREMENTAL=0`. The normal Compose
configuration uses named volumes. LTP build helpers default to an XDG or home
cache outside repository build output because their artifacts can be large.

`.ci-artifacts/` contains retained system evidence and gate logs. Keeping it
outside the Cargo target tree allows evidence to be uploaded, diagnosed, or
deleted without changing the build-cache lifecycle.

A successful joint-handoff run ends below a
`joint-handoff-reference-*/reference-relocated/` root with exactly
`joint-handoff-evidence.json` and `production-replay.json`. The outer CI
artifact may also contain `joint-handoff-reference-ci.log`; those names predate
the HostSubstrate subcell. The evidence intentionally keeps the fixed reference
peer trace lane separate from the HostSubstrate receipts, peer invocations,
journals, leases, checkpoints, and durable projection windows. It is not a
Nexus qualification artifact.

For a direct run, Stage 4 output defaults to `target/visa-system/`; a successful
run ends in `stage4-*-relocated/` because relocation is part of the gate, not a
cleanup rename. With `--ci-cache`, the evidence root is host-visible below
`.ci-artifacts/`. A prepublication runner failure normally leaves a partial root
with its marker and, after initialization, status diagnostics; a later gate
failure may instead leave a marker-free published root. The GitHub Stage 4 job
additionally tees gate output to `.ci-artifacts/stage4-ci.log`; `--ci-cache` and
the local Docker wrapper do not create that log by themselves. When rechecking a
downloaded Actions artifact, pass the inner `stage4-*-relocated/` directory and
its `stage4-evidence.json` to `visa-conformance stage4`; do not pass the artifact
parent, which also contains `stage4-ci.log`.

Local LTP binaries, generated manifests, logs, reports, and other runner output
must use a scenario-specific path below `target/<scenario>/` or a location
outside the repository. Do not create catch-all `output/`, `manifest/`, or log
directories beside source code and then hide them with broad ignore rules.

Do not commit generated logs, reports, binaries, or caches merely because a
runner produced them. Commit an evidence artifact only when a maintained
validation contract explicitly requires it and its provenance is recorded.

## Change and validation discipline

Before editing, inspect `git status --short --branch`. The worktree may contain
unrelated or uncommitted work; preserve it and keep the current change
reviewable. Do not reset, regenerate, or reformat unrelated files.

Choose validation based on the claim affected by the change:

- documentation only: check links and Markdown structure, then run
  `git diff --check`;
- manifests or repository metadata: add `metadata` and `fmt` as applicable;
- Rust behavior: run focused package tests, then the relevant target gate;
- Compose or Docker changes: run `docker compose config --quiet`, rebuild the
  image, and run the affected named gates;
- shell changes: run `bash -n` on changed scripts plus their smallest real
  invocation; and
- conformance claims: execute the named workload on the stated runtime, ISA,
  substrate, resource profile, authority boundary, and fault boundary.

Report what was run, what passed, what was skipped, and why. A green existing
gate must not be generalized beyond the proof boundary listed above.

Bounded Roadmap Stage 4 is complete only for its two named claims. Accepted
qualification revision `457ae1d64915c0b3febd84e136d08be53063210f` passed all
eight independent qualification jobs and the exact-SHA closure in Actions run
`29386011420`; the downloaded Stage 4 artifact passed independent verification
at a different root. The complete receipt is recorded in
[validation](VALIDATION.md#stage-4-closure-receipt).

Current CI separates repository quality from claim qualification. One job runs
`full`; six matrix lanes independently run Stage 1, JcoNode, legacy Stage 2,
Strict Stage 2, Stage 3A, and Stage 3B; a separate lane runs the complete Stage 4
aggregate, one separate Docker lane runs the bounded reference/HostSubstrate
joint-handoff cell, and one host-built lane runs the clean exact-SHA Nexus-local
and process qualification. A final `Exact-SHA qualification closure` job fails
unless all ten prerequisite job executions succeed for the same source SHA,
making eleven jobs including closure. The reference-only lane does not qualify
Nexus, and neither joint lane substitutes for the other. Every Docker image is
built from that checkout and tagged `visa-dev:<SHA>`. Claim evidence and logs
upload from `.ci-artifacts/` on gate success or failure. Pull-request artifacts
are retained for 3 days and push artifacts for 14 days.

Accepted implementation `d3b07f1114cb49e26dd62fb252a895022ac2a743`
completed the clean local and Docker gates, the same-revision eleven-job CI
closure, and independent post-download verification of both joint artifacts.
Exact run, job, artifact, digest, expiry, and verifier receipts are kept in the
[joint-handoff closure receipt](VALIDATION.md#joint-handoff-closure-receipt),
not duplicated in this command guide.

## Next validation expansion

`fast`, `full`, the Stage 1/2/3 standalone gates, the Stage 3 aggregate, the
bounded Stage 4 aggregate, and the bounded joint-handoff gate are the
implemented root interface. The legacy
JcoNode v2 matrix proves a second
translated execution path, not a fully independent Component Model
implementation. The separate source-lock-bound Wasmtime/Wacogo v3 matrix
supplies that independence and only the x86-64 Linux timer/KV
`strict-cross-runtime-continuity` claim. Stage 3A and Stage 3B add only the two
bounded Wasmtime-to-Wasmtime regular-file and logical-request claims. Completed
Stage 4 adds only the named native/QEMU-user target-substrate and emulated
x86-64/AArch64 timer/KV claims described above. The joint-handoff gates support
only the accepted `bounded-joint-handoff-refinement-v1`: the vISA/reference,
Nexus-local, exact-binary process, and supplemental logical-request axes remain
separate, but their clean-artifact, local/Docker, exact-SHA CI, relocation, and
post-download obligations are closed for the accepted implementation recorded
in [validation](VALIDATION.md#joint-handoff-closure-receipt). This is a
bounded same-boot qualification, not evidence for the excluded Stage 5 or
production behaviors listed above.
A second Stage 3 runtime, broader file/network families,
cross-process Stage 3 workers, real hardware/reference-kernel/device cells,
cross-host execution, confidential, release, performance, and production
claims remain unavailable until their exact cells and provenance inputs
execute.
