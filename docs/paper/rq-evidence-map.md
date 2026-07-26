# RQ Evidence Map and Novelty Positioning Draft

Status: working note, not a canonical truth source. Not part of the seven
canonical documents.

Last reviewed: 2026-07-26.

This note prepares paper material by re-reading what the canonical documents
already state. It introduces no claim, no evidence, and no scope. Where this
note and [RESEARCH](../RESEARCH.md), [ROADMAP](../ROADMAP.md),
[VALIDATION](../VALIDATION.md), [README](../../README.md), or
[`claims/registry.json`](../../claims/registry.json) disagree, those sources
win and this file is wrong.

Every coverage verdict below is a reading of already-recorded evidence. None of
them is a new qualification, and none of them widens a registered claim.

## Evidence inventory used by this note

These short names are used only inside this file.

| Tag | Executable evidence | Registered claim | Hard boundary |
| --- | --- | --- | --- |
| `S1` | 31 Stage 1 lifecycle/fault cases through isolated source and destination Wasmtime worker processes with a durable SQLite timer/KV provider | `cooperative-stateful-component-handoff` | x86-64 Linux, single runtime, timer/KV only |
| `S2legacy` | Four Wasmtime/JcoNode direction cells, 124 executions, four inner validations, one normalized outer comparison | `cross-execution-path-portability` | Shared `wasmtime-environ` translator lineage is disclosed, so this is not independent-implementation evidence |
| `S2strict` | Four Wasmtime/Wacogo direction cells, 124/124 executions, 31/31 normalized equality groups, exact lineage and no-fallback proof, fresh Host and Docker runs | `strict-cross-runtime-continuity` | x86-64/amd64 Linux, timer/KV only; the qualified subject is the source-lock-bound Wacogo derivative, not unmodified upstream wacogo |
| `S3A` | 12 bounded regular-file cases, scoped `openat2` rebinding, `STATX_BTIME` identity tuple, SQLite admission fence | `bounded-regular-file-continuity` | Wasmtime-to-Wasmtime, one OS runner process, `independent_runtime_coverage=false` |
| `S3B` | 14 bounded logical-request cases over a real `VISALR03` loopback peer with a durable operation ledger | `bounded-logical-request-continuity` | Wasmtime-to-Wasmtime, one OS runner process, raw live TCP explicitly rejected, `independent_runtime_coverage=false` |
| `S4` | Seven Hx/Qx/Qa cells, 217/217 executions, seven inner Stage 1 validations, 31/31 normalized groups, closure receipt at `457ae1d6...` | `named-target-substrate-continuity-v1`, `emulated-cross-isa-continuity-v1` | Wasmtime and timer/KV held fixed; Qa is QEMU-user on the same host kernel; real AArch64 hardware is recorded `not-run` |
| `J1` | Neutral 16-case registry, TLA+ safety/progress, independent oracle, 10 corrupted-trace mutations, vISA HostSubstrate 14-record commit / 9-record abort vertical, locked Nexus-local refinement, exact-binary process artifact, supplemental logical-request dual-lost-ACK artifact | `bounded-joint-handoff-refinement-v1` (earned) | Same-boot only; `exclusive_trusted_coordinator_api=true` is a declared TCB assumption; the axes stay distinct and no axis substitutes for another |
| `J2` | Every `J1` axis plus one admission-ordered 19-step logical-request commit witness in a strict seven-file artifact | `bounded-joint-handoff-refinement-v2` (candidate) | Not earned; promotion is blocked on the governance-SHA run, immutable release, Zenodo record, manifest, and closure receipt |

Two facts constrain how any of these may be cited in a paper. First, the
matrix is additive: `S2strict` independence does not enter `S3A`/`S3B`, and
`S4` does not inherit the cross-runtime result. Second, the joint-handoff
evidence is a bounded composition; no monolithic execution runs all axes end to
end.

## 1. RQ-to-evidence map

### RQ1: Minimal semantic state

> Can canonical logical state plus target-side rebinding preserve the same
> observable effect trace without serializing native resource bindings?

RESEARCH asks for coverage over real timers, durable key-value state, files,
and eventually network resources, across multiple adapters, with handoff
injected during pending I/O, timeout, cancellation, error, and cleanup paths.

| RQ1 sub-question | Verdict | Evidence | Boundary |
| --- | --- | --- | --- |
| Timers and durable KV preserve the observable trace | Covered | `S1`, `S2legacy`, `S2strict`, `S4` | x86-64 Linux for `S1`/`S2`; `S4` adds QEMU-user endpoints only. The paused-duration timer profile makes no wall-clock deadline-continuity claim. |
| Regular files | Partially covered | `S3A`, 12 cases | Wasmtime-to-Wasmtime, one OS runner process. Excludes directory trees, devices, FIFOs, arbitrary already-open fds, and atomic compare-and-mutate against a writer that bypasses the advisory lock/lease protocol. |
| Network resources | Partially covered | `S3B`, 14 cases | The unit of continuity is a *logical request over a reconnectable session*, not a connection. Raw live TCP is an explicit typed rejection, and socket sequence state, credential bytes, and runtime future state are absent from portable state. A general network-resource result is open. |
| Multiple independent adapters | Partially covered | `S2strict` gives two independent-lineage Component Model runtimes | Only for timer/KV. Both Stage 3 profiles record `independent_runtime_coverage=false` and list Wacogo as unsupported, so the richest resource evidence sits on the weakest runtime evidence. This is the sharpest RQ1 gap. |
| Handoff injected during pending I/O, timeout, cancellation, error, cleanup | Covered within each named profile | `S1` failure/recovery matrix, `S3A` and `S3B` case registries | Coverage is per-profile. There is no cell in which one component holds timer, KV, file, and request resources simultaneously across a single handoff. |
| Native bindings are not serialized | Covered as negative evidence | Stage 1 portable snapshot excludes fd, socket, native pointer, PC/SP, credential, and runtime-private objects; `S3A` excludes device, inode, birth time, fd, and the absolute provider root; `S3B` excludes socket/TCP sequence state and credential material | This is enforced structurally per profile. It is not a measurement. |
| Falsifier: the core keeps expanding until it duplicates runtime, Linux, or device state | Partially covered (measured, one growth step) | Static repository measurement, 2026-07-26; see "Measured core growth" below | Doubling the resource-family count (2 to 4) cost the canonical core +67 lines, one new type, and one new opaque `EffectKind` variant, against 5,748 provider-side lines for the same two families. The typed extension layer (`visa_profile`) grew by ~1,900 lines and must be disclosed alongside. Only one measurement step exists because both Stage 3 families landed in a single commit, so this is a two-point observation, not a curve. |

Overall RQ1: **partially covered.** The timer/KV axis is strong and replicated
across runtimes and emulated targets. Files and requests are each one bounded
Wasmtime-only profile. The composition case and the general network case are
open; the core-growth falsifier now has one measured data point (below).

#### Measured core growth (static measurement, 2026-07-26)

Measurement taken at four commits: `be7b7591` (Stage 1 complete, two
resource families: timer, KV), `5ceaa78c` (strict Stage 2, same two
families), `620dda73` (both Stage 3 families landed — regular file and
logical request arrived in this single commit, so the family count moves 2
to 4 in one step), and `90d54173` (current HEAD). Line counts are
`git show <sha>:<file> | wc -l` sums over `git ls-tree`; type and variant
counts are grep/awk over the same blobs. `crates/oracle/` is excluded
throughout.

Canonical core (`crates/core/contract_core/src`), family count 2 to 4:

| Metric | Stage 1 | Stage 3 | HEAD | Delta over the family doubling |
| --- | --- | --- | --- | --- |
| Total lines | 1,046 | 1,113 | 1,116 | +67 (+6.4%) |
| `pub struct` + `pub enum` | 57 | 58 | 58 | +1 |
| `EventKind` variants | 17 | 17 | 18 | 0 (the HEAD +1 is the joint-handoff refinement, not a resource family) |
| `EffectKind` variants | 5 | 6 | 6 | +1 |
| `CommandKind` variants / `CanonicalState` fields / `SnapshotBody` fields | 16 / 18 / 16 | 16 / 18 / 16 | 16 / 18 / 16 | 0 / 0 / 0 |

The single new `EffectKind` variant is the opaque extension escape hatch
(`EffectKind::Profile { profile, access, payload }`), whose doc comment
states the design intent directly: it "keeps file, request, and provider
verbs out of the canonical effect vocabulary."

Where the Stage 3 commit's 8,576 inserted lines actually landed:

| Layer | Lines added |
| --- | --- |
| `contract_core` (canonical vocabulary) | 71 |
| `semantic_core` reducers | 70 (non-test lines +52, +2.9%, comparable Stage 2 to Stage 3 baseline) |
| `visa_profile` (typed extension payloads, still under `crates/core/`) | 1,911 |
| `substrate_host` (provider implementations) | 5,670 |
| WIT worlds | 311 |

At HEAD the two Stage 3 families occupy 5,748 provider-side lines
(`regular_file.rs` 2,680 + `logical_request.rs` 3,068) against the +67
canonical-core lines — roughly 86:1. Structurally, all three core crates
are `#![no_std]`, a word-boundary grep for native-binding types
(`RawFd`, `TcpStream`, `SocketAddr`, `std::fs`, `std::net`, `statx`)
returns zero hits in `contract_core`, `semantic_core`, and `visa_profile`
against 85 hits in `substrate_host`, and the native file-identity tuple
(`NativeObjectIdentity`) appears in exactly one provider file.

Honest limits of this measurement: it is a single 2-to-4 step, not a
curve, because both families landed in one commit; the ~1,900-line
`visa_profile` growth is real semantic surface (typed claim/state records
of 8–11 fields per family) even though it contains no native state and
the canonical reducer treats its payloads opaquely; and line counts are a
proxy — the falsifier's real test is whether any *native* state class
leaks into the portable vocabulary, which the grep evidence addresses
more directly than the line counts do.

### RQ2: Authority continuity

> Can handoff preserve all five properties under crash, retry, reorder,
> rollback, replay, and concurrent revocation?

| Property | Verdict | Evidence | Boundary |
| --- | --- | --- | --- |
| `authority_after <= compatible(authority_before)` | Covered | `S1` cases for sufficient narrower authority, missing/insufficient destination authority rejection before any destination effect, and adapter-returns-broader-authority attenuation; replicated through `S2strict` and `S4` | Timer/KV profile. `S3A` and `S3B` each add a reauthorization-denial case in their own profile. |
| `revoked_before => unusable_after` | Covered | `S1` revoked-capability case with its exact prescribed destination lifecycle and single audit dump; stale-generation and revoked-capability rejection | The case fixes an exact response lifecycle, which makes it a strong assertion, but it is still one profile. |
| `one fencing epoch => at most one active writer` | Partially covered | `S1` post-commit stale source attempt and source-racing-with-commit cases; `S3A` deterministic provider race test; `S3B` real-TCP greeting-barrier test; `J1` HostSubstrate lease and generation lineage | Three qualifications. The `S3A`/`S3B` race tests are *provider* tests, not published case assertions, and the structural verifiers do not recompute them. Concurrent writers are ordered or rejected only inside the same advisory lock/lease protocol. `J1` declares `exclusive_trusted_coordinator_api=true`, so a second raw coordinator/provider handle is outside the model. |
| `failed pre-commit handoff => no destination authority` | Covered | `S1` destination-crash-before-commit, duplicate/lost prepare, corrupt/incompatible snapshot, and profile-mismatch cases, under the global rule that no destination may be active after a pre-commit failure | Same-boot process faults. |
| `committed handoff => source cannot act` | Covered | `S1` post-commit stale source attempt, destination-crash-after-commit, duplicate restore and stale epoch replay; `J1` source fence preceding guarded destination activation | Same-boot. Host reboot and permanent source loss are not covered. |
| Fault dimension: crash | Partially covered | Same-boot process crash and SQLite reopen throughout `S1` and `J1` | Host-reboot and permanent-source-loss recovery are explicitly not established. |
| Fault dimensions: retry, reorder, replay, concurrent revocation | Covered | `S1` matrix, `J1` 16 neutral schedules and concrete cases | Within the named boundaries above. |
| Fault dimension: rollback | Partially covered | `S1` pre-commit abort and indeterminate protocol; `J1` expected rollback counterexample in the neutral model | Hostile-storage anti-rollback and state freshness are explicitly not established. Protocol-level rollback and adversarial rollback are different questions and only the first has evidence. |
| Falsifier: undeclared global trusted coordinator | Covered in the honest sense; not eliminated | `J1` declares `exclusive_trusted_coordinator_api=true` in the evidence itself | The coordinator assumption is declared rather than hidden, which satisfies the letter of the falsifier. It is not provider- or kernel-enforced, so the property holds against a non-Byzantine orchestrator only. A paper must state this as an assumption in the theorem statement, not a footnote. |

Overall RQ2: **covered for four of five properties within the named same-boot
timer/KV boundary, partially covered for the fencing property, and bounded
throughout by a declared and unenforced coordinator TCB assumption.** The
honest one-line summary is that vISA has executable evidence that the five
properties hold for a non-Byzantine orchestrator on one boot, not that they
hold under adversarial in-process bypass.

### RQ3: Evidence as a semantic leak detector

> Can a compact bundle of artifact/profile identity, pre/post state roots,
> authority lineage, binding receipts, and canonical trace detect externally
> visible adapter divergence?

| RQ3 sub-question | Verdict | Evidence | Boundary |
| --- | --- | --- | --- |
| An independent verifier exists at every stage | Covered | Stage 1 inner artifact-aware verifier; Stage 2 outer typed normalizer that recomputes normalization rather than trusting the publisher cache; Stage 3A/3B structural bundle verifiers; Stage 4 verifier that reconstructs the common input and re-runs all seven inner validations; `J1` neutral verifier with its own oracle | Verifier independence differs sharply by stage. See the next row. |
| The verifier independently reimplements the semantic decision | Covered for Stage 1/2/4 and the joint neutral axis; **not** covered for Stage 3 | VALIDATION states plainly that Stage 3 evidence is "runner-produced semantic evidence plus independent structural verification, not a second independent semantic implementation" | The Stage 3 verifiers fix schema, registry, order, terminal classes, assertion shape, digests, epochs, and identities, but do not recompute case assertions from `trace.json` and the raw bytes. `S3B` peer/credential negative assertions are runner-produced and the raw frames are not published. Profile/config JSON is byte-checked but not semantically parsed. |
| Detection of injected semantic defects is measured | Partially covered | The neutral verifier executes 10 corrupted semantic-trace mutations | This is the closest thing in the repository to a detector-efficacy experiment, and it exists on the joint-handoff axis only. The Nexus lock structurally binds 11 named falsifier classes, and RESEARCH is explicit that this catalog is **not** eleven independently source-mutated Nexus builds. There is no cross-stage injected-defect corpus and no measured detection rate. |
| Specific injections named in RQ3 | Partially covered | Stale-generation acceptance, missing source fencing, and silent authority downgrade map onto `S1` cases and `J1` verifier checks; omitted events map onto exact-inventory and publication-completeness checks, including a negative Stage 4 unit test that adds an extra file plus temporary, symlink, hardlink, and socket entries and requires rejection; lost cancellation, duplicate close, incorrect error mapping, and late profile checks map onto `S1`/`S3` cases | These are *scenarios the system handles*, not *defects deliberately introduced into a verifier-under-test and then measured for detection*. The distinction matters for RQ3 specifically, because RQ3 is a claim about the detector, not about the system. |
| Falsifier: an observable semantic error passes verification | Open | — | Cannot be answered without the systematic injected-defect corpus above. |
| Falsifier: detection requires recording nearly all native execution state | Partially covered | The exclusion lists under RQ1 show that detection currently works without fds, sockets, PC/SP, credentials, socket sequence state, or device/inode metadata; one `SnapshotSize` sample exists per Stage 1 run | There is no evidence-size-versus-detection-coverage curve, which is the quantitative form of this falsifier. |

Overall RQ3: **partially covered, and it is the weakest of the four for paper
purposes.** The infrastructure is strong and the boundary documentation is
unusually honest. What is missing is the experiment that would turn RQ3 from an
architecture description into a result: a systematic corpus of injected
semantic defects with a measured detection rate and a stated evidence budget.

### RQ4: Minimal semantic handoff across authority domains

> Given a durable non-equivocating ownership decision and fail-closed recovery,
> can reversible vISA freeze and irreversible native effect closure preserve
> both at-most-one execution authority and complete accounting of the frozen
> effect cohort, without serializing native device state?

| RQ4 sub-question | Verdict | Evidence | Boundary |
| --- | --- | --- | --- |
| The composition holds for the named fault matrix | Covered for the earned v1 boundary | `J1`: 16 abstract schedules, 16 concrete cases plus one supplemental retained-tombstone recovery, TLA+ safety and conditional progress, HostSubstrate 14-record commit and 9-record abort verticals with seven canonical peer-invocation classes, exact-SHA CI and post-download reverification | Same-boot process crash is the *first* evaluation boundary and remains the only one. |
| No adapter maintains a second ownership ledger | Covered as a structural kill condition | `J1` kill condition 1; the neutral mapping declares `adapter_qualification=false` | This is enforced by review and by the refinement map, not by a mechanism. |
| Thaw requires the exact durable abort decision and the exact freeze-generation thaw | Covered | `J1` kill condition 2, abort transcripts, retained-tombstone scenario | Same-boot. |
| Admission precedes the external effect | Covered only by the v2 candidate | `J2`: the 19-step admission-ordered cell stages Register/Prepare/Commit through the production Nexus Registry before the external Wasmtime operation is emitted; counters stay at zero external executions before Commit and one after Reconcile | Candidate, not earned. One commit trace, not the full fault matrix. The older supplemental cell explicitly does *not* establish this: its external request completes before Register/Prepare/Commit and runs no vISA freeze, fence, or activation. |
| Lost-acknowledgement recovery on both boundaries | Covered | `J1` supplemental cell loses the durable ownership Commit ACK after durability and separately discards the terminal Nexus child response before adapter acceptance; `J2` recovers a suppressed Nexus Commit ACK by byte-identical same-request-ID replay in the same live child and a durable ownership Commit ACK after SQLite reopen | The `J2` Nexus replay happens in a **live child**. This does not prove Nexus process-death or restart durability. |
| WAL-before-effect ordering | Covered, but not by TLC | The TLA+ `BeginFreeze` action deliberately makes gate close, source freeze, generation advance, and boundary capture one atomic abstract step | TLC checks the abstract safety and conditional-progress relation only. The concrete ordering is a *separate* refinement argument from the Rust durable session, SQLite append/reopen evidence, exact pre-call peer-invocation bytes, and independent transcript replay. A paper must not present the TLA+ result as covering the concrete ordering. |
| Native device state is not serialized | Covered | Portable continuity plus native closure, with no device-state transfer anywhere in the composition | Real OSTD, IRQ, SMP, and DMA execution are explicitly not established, so "does not serialize device state" is currently a statement about a system that also does not touch real devices. |
| Cross-host, reboot, permanent source loss | Open | — | Explicitly excluded from both v1 and candidate v2. |
| Adversarial and cryptographic dimensions | Open | — | Byzantine ownership-service behavior, cryptographic receipt authenticity, hostile-storage anti-rollback, and freshness are all explicitly excluded. |
| Dual Stage 3 workers/processes, production adapter, Registry replacement, production retained-tombstone path | Open | — | Explicitly excluded. |

Overall RQ4: **covered for the earned v1 same-boot bounded composition, with the
admission-ordering half resting on a candidate claim that is not yet closed.**
The most important framing constraint for a paper is that acceptance is a
*bounded composition result*: no monolithic, cross-host, or production
execution cell runs all evidence axes end to end.

### Cross-cutting boundary list

These qualifiers apply to every RQ above and should appear once, prominently,
in any paper rather than being repeated per result.

- x86-64/amd64 Linux for all natively executed evidence.
- Wasmtime-to-Wasmtime for both Stage 3 resource profiles.
- Same-boot for all joint-handoff evidence.
- `exclusive_trusted_coordinator_api=true` as a declared TCB assumption on the
  HostSubstrate axis.
- QEMU-user, same host kernel, for the emulated cross-ISA endpoint; real
  AArch64 hardware is recorded `not-run`.
- The source-lock-bound Wacogo derivative is the qualified subject; unmodified
  upstream wacogo is a recorded no-go.
- `bounded-joint-handoff-refinement-v2` is `candidate`, not `earned`.
- No performance claim is earned anywhere.

## 2. Novelty positioning draft

Each entry gives one candidate delta sentence and a confidence label. The
labels are:

- **Documented delta** — the neighbor's own published material or the
  comparison already recorded in RESEARCH supports the distinction.
- **Asserted delta** — plausible from the current reading but not yet
  confirmed against the literature. Every asserted delta is blocked on the
  systematic literature review in section 3.

RESEARCH already states the governing constraint: the current implementation
combines runtime-external resource semantics, authority continuity, explicit
handoff failure, and executable cross-adapter evidence, and *that implementation
does not by itself establish paper novelty*. Nothing below overrides that.

### Core thesis candidates

**Candidate A — the composition.** The contribution is the combination of
runtime-external semantic state, authority continuity across a rebinding
boundary, and executable evidence as one contract, rather than any of the three
alone.

Assessment: this is the natural framing and it is also the hardest to defend,
because each ingredient has strong prior art and the claim reduces to "the
combination is new." It cannot survive review without the systematic literature
review, and it needs an argument for why the combination is more than additive.
The strongest available such argument is that authority continuity and evidence
are *what make* runtime-external state safe to rebind: without reauthorization
the external state is a capability leak, and without a canonical trace the
rebinding is unverifiable. That argument should be made explicitly if Candidate
A is chosen.

**Candidate B — the equivalence-evidence methodology.** The contribution is a
method for showing that two independently implemented runtimes preserve the
same observable continuity envelope: one immutable common input binding
Component, WIT world, profile, configuration, policy, case registry, fault
schedules, typed timer strategies, and schema identities; four direction cells;
complete inner validation per cell; a versioned typed normalization recomputed
by an independent outer verifier; exact requested-to-prepared-to-live runtime
identity chains; and explicit no-fallback proof. The result is 124/124
executions and 31/31 normalized equality groups across Wasmtime and an
independent-lineage Wacogo derivative.

Assessment: **this is the more defensible primary contribution.** It is a
methodology claim backed by a complete executable matrix, it has a crisp
falsification story (a normalization version may exclude only its declared
non-portable observations and cannot expand exclusions to conceal a
difference), and it does not depend on the joint-handoff track closing. Its
weakness is scope: it holds for the timer/KV profile only.

Recommendation: lead with Candidate B as the concrete methodological result and
position Candidate A as the architectural thesis that the methodology serves.
Do not lead with cross-runtime or cross-ISA execution as such; RESEARCH already
records that this is a validation dimension and not sufficient novelty on its
own.

### Per-neighbor deltas

**Nomad (IC2E 2021) — cross-platform WebAssembly offloading and migration.**
Delta: Nomad establishes that WebAssembly compute state can be moved across
platforms; vISA takes the movement of compute state as given and asks the
different question of what happens to the component's *external resource
bindings and authority* at the same boundary, answering it with typed
dispositions and a rebinding contract rather than a transfer mechanism.
*Asserted delta* — needs confirmation of how Nomad handles external resources
and whether it reauthorizes on restore.

**Stateful VM Migration Among Heterogeneous WebAssembly Runtimes (EdgeSys
2024) — WasmEdge to WAMR.** Delta: the EdgeSys prototype migrates runtime VM
state between two runtimes; vISA transfers no runtime state at all and instead
re-derives destination bindings from a portable logical envelope, so its
contribution against this neighbor is the *equivalence-evidence methodology*
(unchanged 31-case registry, independent outer normalizer, 31/31 equality
groups, exact lineage and no-fallback proof) rather than the fact of
cross-runtime movement. *Asserted delta* — the specific question for the review
is whether any prior cross-runtime WebAssembly work published an independently
recomputed normalized-equivalence verifier as opposed to reporting successful
migration.

**Bringing Together Cross-ISA Checkpoint/Restoration and AOT Compilation
(MPLR 2025) — on-stack replacement.** Delta: MPLR'25 bridges ISA-dependent
machine state through OSR; vISA Stage 4 deliberately carries *no* machine state
across ISAs, holding the Component fixed and using separately cross-built
target-native workers, so the two are complementary carriers rather than
competitors. Honesty constraint that must accompany this delta: vISA's
cross-ISA endpoint is QEMU-user on the same host kernel, which is a *weaker*
setup than a real cross-ISA checkpoint result. This asymmetry must be stated as
a limitation in the same paragraph, not deferred. *Documented delta* on the
mechanism difference; the comparative strength claim is not available.

**Self-Hosted WebAssembly Runtime for Runtime-Neutral Checkpoint/Restore
(2025).** Delta: this system normalizes execution-state representation by
placing a runtime inside WebAssembly, and its author material identifies WASI
execution state *outside* the runtime as future work; vISA addresses precisely
that named gap, with explicit per-resource dispositions and executable evidence
for two external-resource families. *Documented delta* — this is the strongest
positioning in the list because the neighbor's own material names the gap. The
review must still confirm nothing filled it between that publication and
submission.

**Lightweight and Highly Portable Migration of Extreme Edge Workloads (CCNC
2026) — Asyncify.** Delta: Asyncify captures stack and CPU-related state without
modifying the host runtime, which under the vISA framing is a *replaceable
compute-state carrier beneath the handoff protocol* rather than a competing
system; the delta is the carrier-agnostic protocol layer, not a better capture
technique. *Documented delta* — RESEARCH already records the replaceable-carrier
position. Note that no vISA cell currently uses an Asyncify carrier, so this is
a design position rather than a demonstrated integration.

**CRIU external resources.** Delta: CRIU's external-resource model explicitly
requires caller help when part of a resource lives outside the dumped
container, and leaves the policy to the caller; vISA supplies the missing
semantic contract that decides whether an external resource is portable,
recreated, reconnected, reattached, proxied, replayed, or a blocker, and
produces per-disposition executable evidence. Honesty constraint: vISA has
executed exactly two external-resource families, both Wasmtime-only and both in
one OS runner process, so the taxonomy is far broader than the evidence.
*Documented delta* on the division of responsibility; *asserted delta* on
novelty of the disposition taxonomy itself, which the review must check against
CRIU plugin and container-migration literature.

**QEMU migration.** Delta: vISA reuses QEMU's established vocabulary — versioned
modeled state, compatibility, conditional state, source preservation before
commit, migration blockers — and moves it up a layer, so that the modeled state
is component and authority state and a "blocker" becomes a typed profile
rejection carrying evidence rather than a device-model version check.
*Asserted delta, and weak on its own.* This neighbor should be cited as reused
practice rather than as a target the paper differentiates against; claiming
novelty here would be hard to defend.

**Temporal and Restate — durable execution.** Delta: durable execution places
journaling, deterministic replay constraints, and idempotency in the
application's programming model; vISA places continuity below the application,
so the component remains an unmodified WIT/WASI component and continuity is a
property of the runtime and authority layer. A second delta on the joint track:
vISA composes with an externally owned non-equivocating decision service under
an explicit kill condition that no adapter may maintain a second ownership
ledger. *Asserted delta* — the review must check whether transaction and
durable-execution literature already contains an equivalent "no second ledger"
refinement obligation, since two-phase commit, presumed-abort recovery,
idempotency keys, and fencing leases are all named in RESEARCH as existing
vocabulary that vISA must not claim to invent.

**CHERI and Capsicum.** Delta: both provide authority attenuation and
unforgeability *within* one machine and one address space or process lineage;
vISA's narrower question is authority continuity *across a rebinding boundary*,
where the component receives entirely new native bindings on another substrate,
and the specific hazard is stale-capability resurrection rather than in-process
forgery. Honesty constraint that must accompany this delta: vISA offers no
architectural or kernel enforcement whatsoever — its current guard is a declared
TCB assumption (`exclusive_trusted_coordinator_api=true`) and is explicitly not
provider- or kernel-enforced. The comparison is about the *question asked*, not
about strength of enforcement, and must be written that way. *Documented delta*
on the question; the enforcement gap is documented and must be conceded.

**in-toto and IETF RATS.** Delta: these define supply-chain provenance and
attestation roles over builds and boots; vISA evidence is about a *runtime
continuity episode* — pre/post state roots, authority lineage, binding receipts,
canonical trace — and RESEARCH's stated position is that vISA should compose
with in-toto statement/provenance formats and RATS roles rather than invent an
isolated security-attestation claim. Honesty constraint: vISA evidence is not
currently emitted in in-toto statement format and carries no cryptographic
authenticity, so this is an unimplemented design position, not a result.
*Documented delta* on intent; no implementation delta exists to claim.

### Deltas requiring literature review before use

Every entry labelled *asserted delta* above is blocked. Concretely, the review
must resolve at minimum:

1. whether any prior WebAssembly migration work publishes an independently
   recomputed normalized-equivalence verifier across independent runtime
   lineages (blocks Candidate B, the recommended primary contribution);
2. whether a typed external-resource disposition taxonomy with executable
   per-disposition evidence already exists in the CRIU plugin, container
   migration, or serverless snapshot literature (blocks the CRIU delta);
3. whether the "no second ownership ledger" refinement obligation is already
   standard in distributed-transaction or durable-execution literature (blocks
   the Temporal/Restate delta and part of the RQ4 framing);
4. whether authority continuity across a rebinding boundary has been posed as a
   distinct problem in capability-systems literature (blocks the CHERI/Capsicum
   delta);
5. whether the combination in Candidate A has been assembled before under a
   different name — the most likely places are confidential VM migration,
   stateful serverless, and edge-continuum work.

## 3. Paper gap list, by priority

### P0 — blocks submission

**P0.1 Systematic literature review.** Section 2 is currently a set of
hypotheses. Nothing in it can appear in a paper as a novelty claim until the
five questions above are answered against the literature. RESEARCH's
maintenance rule deliberately keeps detailed reading notes outside the
repository, so the review output belongs in the paper draft rather than in
`docs/`. This is the single highest-value remaining task, and it gates the
choice of primary contribution.

**P0.2 Close `bounded-joint-handoff-refinement-v2`.** Any RQ4 result that
includes admission-before-send depends on the candidate. The recorded blocking
facts are concrete: as rechecked on 2026-07-18, vISA has no GitHub Release and
repository Immutable Releases are disabled, so the gate cannot currently be
satisfied. Promotion requires a final governance revision passing the complete
exact-SHA workflow on **attempt 1** (closure accepts only attempt 1 because
GitHub's run-level artifact response carries no attempt identity), both joint
ZIPs downloaded and semantically reverified, one fixed-inventory evidence tar as
the sole asset of an immutable release, the same tar as the sole file of a
version-specific Zenodo record bound to that version DOI, a committed archive
manifest enumerating every member by size, SHA-256, role, source revision,
evidence axis, and verifier, and a content-addressed closure receipt whose
commit is a strict descendant of the accepted governance SHA.

If P0.2 slips, the fallback is to write RQ4 against earned v1 only and describe
admission ordering as ongoing work. That fallback is viable and should be
planned for rather than discovered late.

### P1 — needed for a credible evaluation chapter

**P1.1 Performance and cost metrics — the largest concrete gap.**

What exists today is three metrics from exactly one of 31 Stage 1 cases
(`performance-observations`, `crates/testing/visa-system/src/runner/scenarios/success.rs`):

- `SteadyStateCost`: five samples, each the wall-clock duration of one
  source-side KV `Read` round trip, in nanoseconds;
- `SnapshotSize`: one sample, the length in bytes of the JSON-serialized
  snapshot envelope;
- `HandoffInterruption`: one sample, nanoseconds from handoff start to
  destination resume (`crates/testing/visa-system/src/runner/harness.rs:639`).

Every canonical document states that these are raw target-speed-dependent
observations recorded specifically *without* being converted into a performance
claim, and Stage 2's strict model records `performance: NotClaimed`.

**`crates/benchmarks/visa-bench` is not usable for the paper.** Its nine
Criterion benches depend on `semantic-oracle`, `substrate-oracle`,
`runtime-oracle`, and `visa_profile` — the comparison-oracle and pre-reset model
packages that VALIDATION explicitly classifies as compiled by `full` but *not*
production-spine truth and barred from the active dependency graph. Six of the
nine (`block_iops`, `network_throughput`, `framebuffer_throughput`,
`simd_speedup`, `simd_context_switch`, `preemption_latency`) measure mutation
throughput on pre-reset object-graph models for a device/scheduler design that
the current spine does not implement. The three topically relevant ones
(`activation_start`, `hostcall_latency`, `snapshot_restore`) still run against
the oracle runtime rather than the Wasmtime adapter and coordinator. Separately,
`full` only *compiles* benchmarks; nothing in CI executes them, so no results
are retained anywhere.

Consequently the evaluation chapter needs a purpose-built harness on the
production spine. Minimum useful set:

- steady-state overhead of the coordinator/journal path against a
  no-continuity baseline, with repetitions and dispersion, not five samples;
- handoff interruption decomposed into quiesce, export, validate, reauthorize,
  rebind, commit, and resume, so the cost attribution is visible;
- snapshot and evidence-bundle size per handoff as a function of resource-family
  count, which also supplies the quantitative answer to the RQ3 falsifier about
  evidence budget;
- **a restart-plus-external-storage baseline.** RESEARCH's own demand-validation
  section names this as the alternative that would make vISA unnecessary. A
  paper that does not measure against it leaves the obvious reviewer question
  unanswered.

For bundle size, the only figures currently available are whole-CI-artifact ZIPs
recorded in VALIDATION — the Stage 4 artifact at 120,726,772 bytes covering 217
executions with a 1,789-file inventory, the joint reference two-file bundle at
377,480 bytes, and the host qualification artifact at 13,906,689 bytes. These
include worker and QEMU binaries and are compressed, so they are not per-handoff
evidence sizes and should not be presented as such.

**P1.2 Real ARM hardware.** `Qa` is QEMU-user on the same host kernel and real
AArch64 hardware is recorded `not-run`. Any use of the phrase "cross-ISA" in the
paper needs the emulation qualifier attached at every occurrence, including the
abstract. Real hardware would remove a standing reviewer objection and is
already tracked as separate preparation work.

**P1.3 Stage 3 independent-runtime coverage.** Both resource profiles record
`independent_runtime_coverage=false`. This is the structural weakness in RQ1:
the strongest runtime-independence evidence (`S2strict`) and the richest
resource evidence (`S3A`/`S3B`) do not overlap. Running either Stage 3 profile
through the Wacogo derivative would close the most-asked question about the RQ1
result. This is a large engineering task and may not be feasible before
submission; if not, the limitation should be stated as a named future cell
rather than glossed.

### P2 — improves the paper substantially

**P2.1 RQ3 detector-efficacy experiment.** As analysed in section 1, RQ3 is
currently an architecture description rather than a result. What would change
that is a systematic corpus of injected semantic defects spanning the eight
injection classes RESEARCH names, applied across stages rather than only on the
joint-handoff axis, with a measured detection rate and an explicit statement of
which defects the Stage 3 structural verifiers cannot catch by construction.
The existing 10 neutral mutations are the template. Being explicit about the
Stage 3 structural-only boundary would strengthen rather than weaken the paper.

**P2.2 Composed-resource cell.** No current cell holds timer, KV, file, and
request resources across one handoff. A single composed profile would add a
third data point to the now-measured RQ1 core-growth observation (see
"Measured core growth" above) and exercise the composition case; it is
likely cheaper than P1.3.

**P2.3 WASI and Component Model continuity-profile positioning.** RESEARCH
states that active WASI proposals define no general checkpoint,
state-continuity, cross-host resource-rebinding, or handoff protocol, and that
vISA must define continuity profiles around existing WIT/WASI interfaces rather
than inventing another IDL or handle system. A short standards-positioning
subsection turns this from a constraint into a contribution framing. Separate
discussion-draft work is already tracked for this.

### P2 — writing-layer artifacts

Figures and tables the draft will need. None of these require new evidence;
all are re-presentations of what the canonical documents already contain.

| ID | Artifact | Purpose | Source |
| --- | --- | --- | --- |
| F1 | Vertical-slice dependency chain, component through evidence | Establishes the architecture in one image and shows that every stage crosses the full chain | ROADMAP "Why a vertical slice" |
| F2 | Evidence matrix: claim × runtime × ISA/substrate × resource profile × fault boundary, with covered / unsupported / not-run cells rendered distinctly | The honesty centrepiece. Makes the additive-matrix rule visible and preempts overreading | VALIDATION claim-evidence matrix plus the per-stage boundaries |
| F3 | Handoff lifecycle state machine with the ten-step path, the fence point, and the pre-commit/post-commit divide annotated | Needed for RQ2; the pre/post-commit divide is where four of the five properties live | VALIDATION "Required successful path" and the failure/recovery matrix |
| F4 | Authority timeline: generation, lease epoch, attenuation, revocation, and fence, with the five RQ2 properties placed on it | Turns the five-line property block into something a reader can check against the timeline | RQ2 definition plus Stage 1 authority cases |
| F5 | Joint-handoff sequence diagram for the 19-step admission-ordered cell, marking both lost-acknowledgement recovery points and the source fence | Carries RQ4; the ordering is the whole result and prose does not convey it | ROADMAP joint track, VALIDATION admission-ordered section |
| F6 | Evidence-bundle anatomy, annotated with what each verifier independently recomputes versus what it checks structurally | Supports RQ3 and makes the Stage 3 structural-only boundary explicit rather than buried | VALIDATION verifier sections |
| T1 | Condensed RQ-to-evidence table with covered / partially covered / open and a one-clause boundary per row | Section 1 of this note, compressed to roughly one page | This note |
| T2 | Nearest-neighbour delta table | Section 2 of this note, compressed; only survives the literature review | This note |

A caption discipline worth adopting: every figure and table that reports a
result should name its execution boundary in the caption itself, so that no
figure can be lifted out of context and read as a broader claim than it is.

## Open questions for the team

1. Does the paper target RQ1 through RQ3 with RQ4 as a bounded research track,
   or all four as equal contributions? The answer determines whether P0.2 is
   blocking or merely desirable.
2. Is Candidate B accepted as the primary contribution framing? If so, the
   literature review should prioritise question 1 in the list above.
3. Is the restart-plus-external-storage baseline in scope for the evaluation?
   Recommended yes — RESEARCH raises it first, so a reviewer will too.
