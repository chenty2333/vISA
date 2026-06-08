# The Linux ABI Is the System Center: What Building a Semantic Kernel Taught Us About Why Beautiful Abstractions Don't Matter

**Experience Report — Draft v0**

---

## Abstract

We designed and implemented a Semantic Virtual ISA — a kernel-as-virtual-ISA that makes
system semantics (authority, lifetime, waiting, fault handling, cleanup, memory mapping)
portable, explicit, and auditable. The implementation spans 225,000 lines of Rust across 36 crates, runs
on bare-metal x86_64 and QEMU riscv64, and serves over 110 Linux syscalls through a frontend
personality that has been systematically expanded through LTP-driven development. We conclude that the core premise — that making kernel semantics portable
and explicit is a useful goal — does not hold against the reality of the Linux ABI
ecosystem. The Linux ABI is the de facto system center, and any design that treats it as
an optional frontend eventually discovers that the compatibility layer becomes the
system. Our experience parallels Zircon's: a technically sound design whose value is
erased by the compatibility layer that makes it usable. Some design patterns —
generation-based object identity, profile compatibility matrices, explicit edge modes for
contract validation, and small authority trait surfaces — survive the system they were
built for and can be extracted independently.

---

## 1. Introduction

Operating systems research has a recurring pattern: a team designs a cleaner, safer, more
principled kernel architecture; they implement it; they demonstrate its technical merits;
and then Linux continues to dominate. seL4 proved that a microkernel can be formally
verified down to the binary [Klein et al. 2009]. Zircon shipped a capability-based design
with explicit resource handles and clean lifecycle management [Fuchsia 2016]. Singularity
demonstrated that type-safe managed code can eliminate the kernel/user address space
split [Hunt and Larus 2007]. None of them displaced Linux.

The standard explanation is that Linux benefits from network effects: decades of driver
development, application compatibility testing, and institutional knowledge. This
explanation is correct but incomplete. It does not answer a deeper question: *even if a
new kernel could magically run every Linux application, would its internal design
improvements matter?*

This paper answers that question through an experiment in the opposite direction. Rather
than designing a better kernel *for applications*, we designed a kernel as a virtual ISA
— a Semantic Virtual ISA (vISA) — whose primary purpose is to make *kernel semantics
itself* portable, auditable, and explicit. The vISA models system semantics (authority,
lifetime, waiting, fault handling, cleanup, memory mapping) as a set of instruction-like
operation families backed by a contract ledger. Linux applications run through an
optional frontend personality that translates Linux syscalls into vISA effects. The
design intent was that the vISA, not the Linux ABI, would be the system center.

We implemented this design in VMOS, a capability-oriented Semantic Virtual ISA backed by
Wasm execution infrastructure. The implementation spans 225,000 lines of Rust across 36
crates, including a bare-metal x86_64 kernel, a contract ledger with explicit ObjectRef
identity and generation tracking, a frontend that dispatches over 110 Linux syscalls into vISA
effects, and a contract graph validator that checks invariants across live, historical,
and cleanup-effect edges.

The experiment produced four findings:

1. **The Linux ABI is the true system center, regardless of internal architecture.** Any
   system that runs Linux applications eventually serves the Linux ABI through a
   compatibility layer. That compatibility layer — not the semantic core — becomes the
   most complete, most exercised, and most valuable code path. The internal abstractions
   become pass-through infrastructure. Our experience expanding from 28 to over 110
   syscalls under LTP-driven development only deepened this finding: each new syscall
   family (clock, process, extended filesystem operations) pulled more complexity into the
   frontend and left the vISA core unchanged.

2. **Semantic explicitness without independent consumers provides only self-referential
   value.** Our contract ledger records authority grants, capability checks, wait tokens,
   trap attribution, and cleanup effects as explicit, generation-bearing objects. But the
   only consumer of these records is our own validator, and the only workloads whose
   invariants it checks are workloads we wrote ourselves. The ledger proves nothing to an
   external observer.

3. **LTP-driven development is a practical ramp for syscall coverage, but it does not
   validate architectural value.** Systematically running Linux Test Project binaries
   through the VMOS frontend forced the implementation to handle real — sometimes
   adversarial — syscall patterns. This expanded coverage from 28 to over 110 syscalls
   across 10 development increments. However, the LTP tests exercise the Linux frontend
   personality, not the vISA itself. Passing more LTP tests demonstrates Linux
   compatibility, not architectural soundness.

4. **Some design patterns survive the system they were built for.** Generation-based
   object identity, profile compatibility matrices, explicit edge modes for contract
   validation, and small authority trait surfaces are engineering patterns that can be
   extracted and reused independently of the vISA architecture.

This paper is not a success story. We built what we set out to build, and we conclude
that the core premise — that making kernel semantics portable and explicit is a useful
goal — does not hold against the reality of the Linux ABI ecosystem. We present the
design in detail, report what worked and what did not, and extract lessons for future
systems research.

The remainder of this paper is organized as follows. Section 2 presents the design of the
Semantic Virtual ISA. Section 3 describes the implementation. Section 4 evaluates what
aspects of the design worked. Section 5 analyzes the fundamental tensions that emerged.
Section 6 discusses implications for systems research. Section 7 concludes.

---

## 2. Design of the Semantic Virtual ISA

The Semantic Virtual ISA is organized around four architectural axes, nine operation
families, and a contract ledger that makes system effects explicit. This section
describes each in turn.

### 2.1 Four ISA Axes

Traditional operating systems conflate four distinct concerns that the vISA separates:

- **Host ISA** — the real target architecture and board profile (riscv64, x86_64,
  aarch64, QEMU profiles, SoC variants). This axis absorbs hardware differences that are
  invisible to portable system semantics.

- **Wasm execution ISA** — the mature virtual execution substrate providing modules,
  imports/exports, linear memory, structured control flow, traps, sandboxing, and
  AOT/interpreter/JIT implementations. Wasm solves the hardest problems in virtual
  execution: sandbox isolation, trap safety, and cross-platform code delivery.

- **Semantic Virtual ISA** — the system-level semantics defined by VMOS: authority,
  capability, generation, lifetime, wait, trap, cleanup, artifact identity, hostcall
  attribution, and profile requirements. This is the system center in the design; it
  defines what "running a system" means in portable terms.

- **Guest ISA / ABI** — the optional frontend surface: Linux ELF, WASI, JS/runtime ABI,
  or custom compatibility personalities. These are adapters, not the system center.

The design places the Semantic Virtual ISA at the center. Host ISA differences are
absorbed through substrate profiles; guest ABI differences are absorbed through frontend
personalities. The primary execution path is:

```
vISA artifact → Semantic Virtual ISA operation → contract ledger → substrate trait backend → host ISA / hardware
```

An optional frontend path exists for compatibility:

```
Linux ELF / WASI / custom ABI → personality artifact → Semantic Virtual ISA operation → same contract ledger / substrate path
```

The separation of these axes is the foundational design decision. It means that Linux is
not the system center — it is one of several possible frontends. Substrate traits are not
Wasm ABIs — they are backend interfaces that absorb hardware differences. The contract
ledger is not a Linux /proc replacement — it is the canonical record of vISA effects.

### 2.2 Operation Families

The Semantic Virtual ISA is defined by operation families, not by Linux syscall breadth
or service implementation shape. Nine canonical families partition the design space:

**Wasm compute and memory.** Module load, store, call, branch, linear memory access, and
trap. Inherited from Wasm; the vISA does not redefine these.

**Artifact and code identity.** TargetArtifactImage is the only loadable unit. It binds
payload bytes, manifest facts, profile requirements, section hashes, signature status,
and schema version. Code publication creates a CodeObject with generation, immutable
published bytes, PcRange records, and TrapMap attribution. Changing executable bytes
creates a new CodeObject generation; published code is never mutated in place. W^X is
mandatory.

**Authority.** Capability check, grant, delegate, attenuate, revoke, handle generation
validation, and manifest-proven authority declaration. Authority is ledger-backed:
`CapabilityLedger[StoreRef][slot]`. The handle carries slot, generation, and an optional
unguessable tag. A global object id alone is not a safe capability.

**Machine authority.** Console, timer, event queue, code publish, guest memory, DMW, DMA,
MMIO, IRQ, and snapshot/replay extraction. Each is a separate substrate trait. Default
behavior for unsupported operations is an explicit Unsupported event, not a silent error
or a crash.

**Lifetime.** Object create, close, generation bump, tombstone creation, Store
start/degrade/reboot, Activation enter/exit, and FaultDomain lifecycle. Dead or retired
objects leave tombstones. Live references must not point to dead or tombstoned
generations.

**Async.** WaitToken create, resolve, cancel, restart, pending, resume, and event bridge.
No operation should block invisibly inside a hostcall or adapter. A pending operation
creates a WaitToken; resolve, cancel, and restart are event-visible. A dead owner
generation cancels its waits.

**Fault and cleanup.** Trap attribution (target PC → PcRange → CodeObject offset →
TrapRecord), trap classification, cleanup begin/step/commit, cleanup-effect edges, and
post-cleanup reuse rejection. Cleanup is a transaction over a specific Store generation.
State digest after cleanup once must match state digest after cleanup twice.

**Observability.** EventLog emission, stable ViewV1 extraction, contract graph
validation, and no_std panic/log/osctl extraction. Views are machine-readable JSON;
debug text is auxiliary only. The osctl control plane is read-only.

**Profile and compatibility.** Required, optional, and forbidden feature sets; substrate
discovery; load-time compatibility checking; and event-visible degradation. An artifact
may run only when its required profile is satisfied by the enforced profile. Profile
checking happens before code runs.

Each operation family has an explicit ownership boundary. The semantic-virtual-isa spec
names the families and states which boundaries must remain stable. The semantic-contract
spec encodes the effects, ObjectRefs, generations, edges, events, and views. The
target-runtime-abi carries the artifact, code, hostcall, trap, profile, and extraction
records. The substrate-api provides backend trait families for machine authority.
Frontend personality artifacts implement guest-visible behavior by emitting vISA effects.

### 2.3 The Contract Ledger

The contract ledger is the effect language of the Semantic Virtual ISA. It defines how
vISA operations are named, related, validated, and exported. It is the encoding and
validation layer, not the vISA itself.

**Object identity and references.** Every durable semantic object is identified by three
components: `(kind, id, generation)`. The `id` names logical identity — what the object
is. The `generation` names an incarnation — which version of it exists now. Reuse of an
`id` is allowed only when policy dictates that the logical object survived across
incarnations, such as a Store reboot. Otherwise, a new `id` is allocated.

The generation field is not metadata; it is structural. Generation is part of authority:
a capability granted for generation N is not valid for generation N+1. Generation is part
of cleanup targeting: a cleanup transaction targets a specific Store generation and must
not mutate a newer one. Generation is part of tombstone semantics: dead objects leave
tombstones; live references must not point to tombstoned generations.

This design prevents an entire class of use-after-free errors at the semantic level. A
stale object reference — one that names the correct `id` but an old `generation` — is
rejected by the contract validator as a generation mismatch violation, not as a runtime
panic or undefined behavior.

**Edge modes.** The contract graph is a directed graph where edges explain why one
semantic object references another. Four edge modes are defined:

- **Live**: current authority, ownership, blocking, binding, or scheduling relation. Live
  edges cannot target tombstoned objects, dead Stores, or dead Activations. Live edge
  generation must match target generation.

- **Historical**: audit relation from trace, trap, hostcall, event, or tombstone
  evidence. Historical edges may reference dead or tombstoned generations. Traps and
  hostcalls create historical references to their Store, Activation, and CodeObject; they
  do not create live ownership.

- **CleanupEffect**: effect produced by a cleanup transaction. Cleanup effects must not
  become live ownership and must not authorize new operations.

- **External**: declared object outside the internal contract graph, with explicit
  provider and class metadata.

The mode distinction is critical for validation. A validator that sees a mixed list of
edges without mode information cannot distinguish "this trap recorded the Store that was
active when it fired" (historical) from "this capability gives the Store authority over
the device" (live). The former should always be valid; the latter must be rejected if the
Store is dead.

**Capability and authority.** Capability is explicit authority over a generation-bearing
object. Authority is represented as a tuple: `(subject Store/Activation generation,
capability slot/handle, target ObjectRef generation, rights/operation set, state,
manifest declaration)`. Debug labels are not authority. The string
`"requires_capability"` is not an authorization check.

For handle-style ABIs — which is how guest-facing code interacts with the system —
authority is ledger-backed: `CapabilityLedger[StoreRef][slot]`. The handle carries a
slot, generation, and optional unguessable tag. Guest code cannot gain authority by
guessing a global object id. The same label with a different ObjectRef is rejected. A
revoked capability is rejected. Attenuation cannot amplify rights.

**WaitToken.** Blocking, pending, cancellation, and resume are represented as WaitToken
objects with explicit state: `(owner Store/Activation generation, kind, blockers, state ∈
{pending, resolved, cancelled, restarted}, cancel reason, restart policy, event
attribution)`. No operation should block invisibly inside a hostcall or adapter. A
pending operation creates a WaitToken; resolve, cancel, and restart are event-visible
transitions. A dead owner generation cancels its waits. A cancelled wait cannot resume.
Resume validates Store, Activation, and CodeObject generations before proceeding.

Frontend wait mechanisms — Linux `epoll_wait`, `futex` with `FUTEX_WAIT`, timerfd — are
represented as WaitToken records with stable kind, owner, blocker, restart, state, and
cancellation fields. The frontend wait-service mapping is explicit: an `epoll_wait` call
creates a WaitToken with `kind = Epoll`, the `epoll_create1` return value names the epoll
instance as blocker, and the saved context names the frontend operation. The stable
WaitToken fields are what the contract validator checks; the frontend context is
auxiliary.

**Store, FaultDomain, and Cleanup.** Store is the restartable fault-domain incarnation.
Cleanup is a transaction over a specific Store generation with canonical ordering,
generation-safe targeting, idempotent state effect, contract-verifiable postconditions,
and osctl-visible steps. The required effects are: stop new activations, cancel waits,
revoke capabilities, release leases and resources, drop or unbind runtime bindings, mark
Store generation dead, and emit tombstones and historical references.

Cleanup idempotence is proven by state digest equality: the semantic state digest after
executing cleanup once must match the digest after executing it twice. The digest covers
Store, Activation, CodeObject, DMW lease, and CapabilityLedger state; it is not an
EventLog hash. A stale-generation cleanup records the unchanged digest and
skipped-stale-generation effects rather than mutating live state.

Store reboot rules: the same logical fault domain may reuse a StoreId; reboot bumps the
generation; old cleanup cannot mutate the new generation; old capabilities and waits do
not cross reboot; the new generation receives new grants through policy.

**Guest memory as semantic objects.** Guest memory is modeled as semantic state, not as
substrate-owned page table truth. The object hierarchy is: `GuestAddressSpace →
VmaRegion → PageObject`. `GuestAddressSpace` is the logical guest address space with
generation. `VmaRegion` is a guest VA range with permissions, flags, backing reference,
and generation. `PageObject` is the backing memory object with COW state and dirty
generation. Substrate mappings, DMW windows, TLBs, and shadow page tables are disposable
execution bindings. The model resembles Zircon's VMO/VMAR split but lives in the contract
ledger, not in a native kernel.

### 2.4 Profile Matrix

Profiles are Semantic Virtual ISA feature sets. They are load and conformance contracts,
not marketing labels. Artifacts declare required, optional, and forbidden profile
features. Targets report enforceable capability before load. The loader rejects an
artifact when required features are missing or forbidden features are requested.

Five stable profile levels are defined:

| Level | Name | Description |
|-------|------|-------------|
| 0 | Reference Harness | Semantic model only; contract effects can be validated without proving real substrate authority. |
| 1 | Base Machine Authority | Console, timer, event queue, basic hostcall/trap attribution, and visible unsupported events. |
| 2 | Memory Authority | GuestAddressSpace, VmaRegion, PageObject, logical DMW, and generation-safe user-buffer checks. |
| 3 | Device Authority | MMIO, IRQ, DMA, queues, descriptors, device capability gates, and generation visibility for mediated device operations. |
| 4 | Snapshot and Replay | Snapshot barriers, deterministic replay support, migration-package roots, no active non-migratable leases, and stable osctl extraction. |

Profile levels are monotonic for load compatibility (level N satisfies all requirements
of level N-1), but individual feature values still carry fine-grained distinctions. For
example, `DmaSupport::BounceBuffer` and `DmaSupport::IommuStrict` are both device-capable
modes (level 3), but they are not identical enforcement claims. The compatibility rule
is:

```
artifact may run only when required profile ≤ enforced profile
optional feature missing → event-visible degraded mode
forbidden feature present and requested → policy rejection
unexpected runtime use → Unsupported event
```

Every profile claim must name an enforcement path: manifest requirement,
`SubstrateCapabilitySet` report, loader compatibility decision, capability and generation
gate, EventLog and stable view evidence, and substrate trait behavior or explicit
Unsupported event.

The profile matrix separates two concerns that are often conflated: what the machine
*can* do (substrate capability) and what the artifact *is allowed* to do (capability and
generation gate). A target that reports `DmaSupport::Mediated` at level 3 does not grant
DMA access to every driver. The driver must still present a valid capability handle with
the correct generation for the specific DMA buffer it wants to access.

### 2.5 Substrate Traits

The substrate is the backend authority provider that maps virtual ISA operations to real
hardware mechanisms. It is defined as a set of small Rust traits, not as a monolithic
`Substrate` interface:

```
ConsoleAuthority    TimerAuthority    EventQueueAuthority
GuestMemoryAuthority  DmwAuthority    ArtifactAuthority
CodePublisherAuthority  MmioAuthority  DmaAuthority
IrqAuthority          SnapshotAuthority
```

Each trait defaults every operation to `Unsupported`. Hardware ports implement only the
authorities they can provide. Missing authorities are reported at startup and become
load-time incompatibilities, optional degradation, or runtime `Unsupported` events.

A critical design rule: **trait availability is not permission.** Implementing
`DmaAuthority` means the machine can provide DMA. It does not mean any driver may use
DMA. Access still requires a valid capability and generation check. The substrate trait
answers "can the machine do this?"; the capability ledger answers "may this artifact do
this now?"

Rust substrate traits are engineering boundaries, not security boundaries. Security
derives from manifest requirements, capability checks, generation validation, EventLog
records, and trap/cleanup policy layered above the traits. Substrate traits are never
exposed as Wasm ABI; artifacts interact with the system through hostcalls that pass
through validation and semantic recording before reaching any substrate trait call.

---

## 3. Implementation

VMOS is implemented in 225,000 lines of Rust across 36 crates organized under a Cargo
workspace. The implementation spans four architectural layers mirroring the spec
structure.

**contract_core** (1 file, `no_std`). The stable encoding layer for vISA effects. Defines
`ObjectRef (kind, id, generation)`, `ObjectKind` (~130 variants covering core
abstractions, IO objects, network objects, display objects, scheduler/SMP objects, SIMD
objects, memory objects, and integrated scenario objects), `RefMode` (Live, Historical,
CleanupEffect, External), `ContractEdge`, `EvidenceBoundaryLevel` (5 levels from
SemanticModel to RealTargetSubstrate), stable view schemas (`StoreViewV1`,
`CapabilityViewV1`, `WaitViewV1`, `CleanupViewV1`, `ContractViolationViewV1`), and typed
reference wrappers (e.g., `StoreRef`, `CapabilityRef`, `WaitTokenRef`) that enforce kind
correctness at the type level. All identity-bearing types carry generation.

**semantic_core** (~200 files). The in-memory effect ledger and verifier. Central types:
`SemanticGraph` wraps `SemanticDomains` + `EventLog` + `CommandResult` queue. The graph
module exposes ~130 object record types organized by domain (block IO objects, network
objects, display/framebuffer objects, scheduler/SMP objects, SIMD objects, device/driver
objects, integrated scenario objects, and core abstractions). `ContractGraphValidator`
checks invariants over a `ContractGraphSnapshot`: live edges must not target tombstones,
live edge generations must match target generations, cleanup-effect edges must not create
live ownership, external edges must have declarations, evidence boundary claims must be
attainable. `ContractGraphSnapshot::portable_subset()` defines which record categories
are portable across host ISAs and which are host-specific binding state that must be
dropped, rebuilt, or replayed on migration.

**kernel** (~60 files). A bare-metal x86_64 kernel that boots via UEFI (bootloader
crate), initializes a 32 MiB heap, UART serial output, and x86 interrupt handling, then
runs the supervisor runtime. The supervisor instantiates 18 Wasm service modules
(compiled to `wasm32-unknown-unknown` at build time via a `build.rs` that also computes
SHA-256 hashes, ABI fingerprints, and manifest binding hashes), bootstraps a
`SemanticGraph`, creates a `StoreManager` that tracks Store lifecycle (Loaded → Running →
Draining → Restarting → Dead) and micro-reboot with generation bump, and dispatches guest
operations through a `LinuxFrontend` that maps Linux syscalls to vISA Plans. The kernel
runs on QEMU x86_64 virt and targets riscv64-qemu-virt-singlehart as the default research
profile.

**Linux syscall frontend.** Over 110 Linux syscalls are dispatched through 126 match arms
in `bridge.rs`, covering eight functional families:

- **File operations**: `read, write, writev, readv, lseek, open, openat, creat, close,
  close_range, dup, dup2, dup3, fstat, stat, lstat, newfstatat, fstatfs, statfs, access,
  faccessat, faccessat2, getdents64, readlinkat, getcwd, truncate, ftruncate, fallocate,
  mkdir, mkdirat, mknodat, rmdir, unlink, unlinkat, chdir, chmod, fchmodat, chown, lchown,
  fchownat, chroot, umask, symlink, symlinkat, pipe, pipe2, mount, umount2`
- **Memory**: `mmap, munmap, mprotect, msync, brk`
- **Process/thread**: `exit, exit_group, clone3, vfork, wait4, getpid, getppid, gettid,
  getuid, geteuid, getgid, getegid, getresuid, getresgid, getgroups, setuid, setgid,
  setreuid, setregid, setgroups, setpgid, set_robust_list, set_tid_address, kill, tgkill,
  rt_sigaction, rt_sigprocmask, prctl, prlimit64, sched_getaffinity, rseq, arch_prctl`
- **Time**: `nanosleep, clock_nanosleep, clock_gettime, clock_getres, clock_settime,
  clock_adjtime, time, gettimeofday, pause`
- **Polling/I/O multiplexing**: `poll, pselect6, epoll_create, epoll_create1, epoll_ctl,
  epoll_wait, epoll_pwait, epoll_pwait2`
- **Sockets**: `socket, socketpair, bind, listen, accept, accept4, connect, sendto,
  recvfrom, setsockopt, getsockopt, getpeername, getsockname`
- **Futex/synchronization**: `futex` (wait/wake operations), `eventfd, eventfd2`
- **Miscellaneous**: `uname, fcntl, ioctl, getrandom, execve, execveat, bpf, keyctl,
  add_key, fsetxattr, fremovexattr, alarm, capget, capset`

Each syscall is dispatched through `dispatch_linux_syscall` → `dispatch_linux_syscall_raw` →
`execute_linux_step` → `execute_linux_plan`. The Plan variants map syscall semantics to
service calls (VFS for filesystem operations, futex_service for futex operations,
epoll_service for epoll operations, net_core and linux_socket_service for socket
operations, console_service for stdio). Blocking operations (epoll_wait, futex_wait,
nanosleep) create WaitTokens and return Pending; the scheduler resolves them when the
wait condition is satisfied or the timer expires.

The frontend additionally tracks file descriptor state (`status_flags` distinguishing
access mode, append, and nonblocking bits), supports userspace credentials (uid/gid for
file creation), and handles edge-triggered epoll semantics, `O_DIRECTORY` enforcement,
and `/proc` synthetic filesystem lookups through a dedicated procfs service.

**target_executor.** A host-side validation binary that drives vISA execution without a
real target substrate. It loads verified artifact images, publishes code objects through
the CodeObject lifecycle (AllocatedRw → Filled → Sealed → PublishedRx → BoundToStore),
creates Store and Activation records, grants manifest-declared capabilities, runs
activation harnesses for smoke hostcalls, trap classification, SIMD vector state,
framebuffer/display, and integrated scenarios (SMP preemption+cleanup, SMP network fault,
disk preempt fault, SIMD migration, network+disk IO, display+scheduler load,
snapshot+IO lease barrier, code publish+SMP workload, display panic, osctl trace replay),
validates snapshot barriers against active DMW leases and pending transactions, and
produces a contract graph snapshot for validation. The executor records all effects —
hostcall traces, trap records, cleanup transactions, capability grants — as
contract-visible evidence.

**substrate_api.** 11 authority traits, each defaulting to `Unsupported`.
`SubstrateCapabilitySet` reports enforceable authority; `SubstrateCompatibilityReport`
compares reported capabilities against artifact requirements. `visa_profile` defines the
stable profile levels and the compatibility matrix (`AuthorityRequirementSet`,
`SubstrateProfile`, `check_profile_compatibility`).

**osctl-view.** Read-only control plane over stable views. Exports contract graph state
as JSON ViewV1 records with explicit schema versions. Hostcall JSON exposes gate outcomes
(`gate.status`, `gate.denial_reason`, `capability_handle_count`) without collapsing
reasons into debug prose. Trap and cleanup JSON expose attribution status and state
digests without requiring debug-string parsing.

The implementation compiles on Rust nightly with `wasm32-unknown-unknown` and
`x86_64-unknown-none` targets. The kernel is deployed via a UEFI disk image built by the
`runner` crate.

**Test infrastructure.** The implementation includes 1,034 tests across all crates
(`cargo test --workspace`), with the largest concentration in `semantic_core` (~500 tests,
~15,000 lines of test code). The `semantic_core` test suite exercises every semantic
object type through a command-application harness that records effects in a
`SemanticGraph`, then asserts both the expected outcome and the continued validity of
~110 structural checks (106 domain-specific invariant functions plus 4 top-level
cross-domain checks). These checks span eight categories: structural (task↔resource
bidirectional references, store↔fault-domain consistency), scheduler (16 families
including hart lifecycle, timer interrupts, IPI events, SMP barriers), integrated
scenarios (10 families combining multiple domains), device IO (13 families), network
(21 families covering packet devices through socket operations), block and filesystem
(24 families), SIMD and display (19 families), and general-purpose (wait, cleanup,
preemption latency, and hart event attribution invariants).
Every test calls the invariant checker after each command application,
providing continual validation that the design's structural rules are preserved.

The `contract_validate` crate contributes 136 additional tests that validate 400+
semantic root/count pairs in migration packages, ensuring that artifact manifests and
runtime evidence remain consistent. The `osctl-view` crate adds 107 tests verifying that
stable JSON views preserve schema versions, generation fields, and machine-readable
denial reasons.

**LTP-driven syscall expansion.** The Linux syscall surface grew from 28 to over 110
syscalls through 10 incremental development rounds driven by the Linux Test Project
(LTP). Each round followed a pattern: select a batch of LTP syscall test binaries via a
manifest (`run-vmos-ltp-manifest.sh`), execute them under the VMOS QEMU runner
(`run-vmos-ltp-single.sh`), capture serial output and extract LTP result logs and VMOS
execution traces, then validate the combined evidence through a conformance gate
(`run-ltp-conformance.sh`). Failed tests drove targeted frontend hardening: adding
missing syscall dispatchers, correcting flag handling (e.g., `O_DIRECTORY`, status flag
tracking), implementing credential-aware filesystem operations, and adding realtime
clock behavior. Static LTP binaries are built via `build-vmos-ltp-static-syscalls.sh`
using a Docker-based cross-compilation toolchain, keeping LTP build artifacts outside
the repository. The conformance framework distinguishes between host-native LTP results
(reference data) and VMOS-backed LTP results (system-under-test evidence), producing
comparable trace artifacts that gate on VMOS-specific execution evidence.

---

## 4. What Worked

Several design elements withstood implementation and testing:

**Generation-based identity.** The `(kind, id, generation)` triple for object identity —
with generation embedded in capability handles, Store records, Activation records,
WaitToken handles, and resource handles — prevented stale-reference errors that would be
use-after-free in a traditional kernel. This pattern is exercised pervasively: of 873
tests in the codebase, ~500 in the `semantic_core` suite verify generation-aware state
transitions after every command application. The contract graph validator checks
generation consistency on every cross-object edge, treating `GenerationMismatch` as a
first-class violation type alongside dangling edges and tombstone violations. The store
lifecycle test demonstrates the concrete security property: after a Store is dropped
(generation 1), rebound (generation 2), and dropped again, a capability handle carrying
generation 1 is rejected with `GenerationMismatch { expected: 1, actual: Some(3) }`, not
a silent use-after-free. The pattern generalizes beyond vISA to any system with mutable
resources and multiple references.

**Profile compatibility before execution.** The profile matrix's linear ordering (0→4)
combined with fine-grained feature requirements (e.g., `DmaRequirement::MediatedOrBetter`)
provides a clear compatibility check that completes before any code runs. The
`substrate_api` conformance tests exercise the full profile hierarchy against a mock
backend implementing all 11 authority traits: each profile level
(`SemanticHarness` through `SnapshotReplayCapable`) is tested with the mock backend's
capability set, verifying that required authorities are satisfied, optional absences
produce structured degradation evidence, and forbidden authorities trigger rejection.
Rejected artifacts produce structured rejection evidence (`SubstrateCompatibilityReport`
with `missing_required`, `degraded_optional`, `forbidden_present` vectors) rather than a
binary pass/fail or a runtime crash on first unsupported operation. The `visa_profile`
crate is 942 lines and has no dependencies beyond `alloc`; the profile model could be
extracted into a standalone library.

**Explicit edge modes.** Distinguishing Live from Historical from CleanupEffect from
External edges allows the contract validator to enforce different rules for different
relationship types. A trap creating a historical reference to a now-dead Store is valid;
a capability creating a live reference to a tombstoned Store is not. The `ContractGraphValidator`
implements 44 validation methods covering every object domain, each systematically
calling `check_generation_edge` and `check_contract_ref_edge` with kind-specific
validation. The 10 violation types it detects (Table 1) — from `DanglingEdge` through
`EvidenceBoundaryOverclaim` — are enumerated as a complete matrix.

**Table 1.** Contract graph violation types detected by the validator.

| Violation Kind | Description |
|---|---|
| `DanglingEdge` | Object reference points to a non-existent target |
| `GenerationMismatch` | Reference uses a stale generation counter |
| `LiveObjectReferencesDeadObject` | Live object points to a tombstoned or dead object |
| `LiveEdgeReferencesInactiveObject` | Live edge references an inactive target |
| `TombstoneReferencedByLiveEdge` | Tombstoned object has a live incoming edge |
| `HistoricalEdgeMissingGeneration` | Historical edge lacks a generation field |
| `CleanupEffectCreatesLiveOwnership` | Cleanup effect creates live ownership instead of history |
| `ExternalEdgeMissingDeclaration` | External reference lacks a provider/class declaration |
| `ExternalEdgeMetadataMismatch` | External edge metadata differs from its declaration |
| `EvidenceBoundaryOverclaim` | Edge claims a stronger evidence level than the snapshot allows | Without
mode-distinguished edges, the validator would need domain-specific knowledge that is
currently explicit in the edge label. The `osctl-view` tests additionally verify that
the mode distinction is preserved in stable JSON output, ensuring that consumers of the
control plane can distinguish live ownership from audit history without parsing debug
strings.

**Small authority traits with explicit unsupported defaults.** The 11-trait design (each
with 1-3 methods, each defaulting to `SubstrateError::unsupported`) is mechanically small
and composition-friendly. A target that only needs Console and Timer implements two traits
and ignores ten. A target that adds MMIO support later adds one trait without changing
existing code. The default-Unsupported pattern means that forgetting to implement an
authority produces an explicit event, not a linker error or a runtime panic.

**Wasm as the execution substrate.** Using Wasm as the base virtual ISA was the correct
decision. Wasm provides mature sandbox isolation, structured trap semantics,
cross-platform AOT/JIT compilation, and a growing Component Model ecosystem. The vISA
design adds system semantics on top of this foundation without reinventing code delivery,
memory safety, or trap handling. The design choice to separate Wasm (execution ISA) from
vISA (system semantics) is arguably the most reusable architectural insight in the
project.

**Linux `epoll` implementation.** The frontend path for `epoll` demonstrates that the
WaitToken model can express non-trivial blocking semantics cleanly. `epoll_create1`
creates an epoll instance object with generation. `epoll_ctl(ADD)` registers an fd
interest as a WaitToken blocker reference tracked against the epoll instance.
`epoll_ctl(DEL)` removes the blocker. `epoll_wait` creates a WaitToken with kind Epoll,
blockers pointing at the epoll instance, and saved context naming `epoll_wait`. When an
fd becomes ready, the scheduler resolves the WaitToken and the frontend returns the
ready event list. Edge-triggered semantics are enforced by clearing readiness after
delivery. This is not a novel `epoll` implementation, but it shows that the WaitToken
abstraction is capable of hosting a real, complex blocking primitive without bypassing
the semantic model.

---

## 5. Fundamental Tensions and What Didn't Work

The implementation surfaced tensions that the design did not anticipate.

### Tension 1: The Compatibility Layer Becomes the System

Section 2.1 described Linux as an "optional frontend personality." In practice, the Linux
frontend became the most complete, most exercised, and most valuable code path in the
kernel. Of the over 110 dispatched syscalls, the most complex dispatch logic —
`epoll_ctl`'s edge-triggered semantics, `futex`'s wait/wake with userspace word
comparison, socket operations with protocol family dispatch, filesystem operations with
credential tracking — lives in the frontend. The vISA contract ledger records the
effects, but the semantic content (what does it mean to `epoll_wait` on an fd? what
constitutes a valid `openat` with `O_CREAT`?) is implemented in the Linux personality.
The vISA is pass-through infrastructure for Linux semantics, not the semantic center the
design intended.

The LTP-driven expansion made this tension quantifiable. Adding 80+ syscalls across 10
development increments required changes almost exclusively in the frontend personality
(`bridge.rs`, `linux_fd.rs`, `linux_fs_dispatch.rs`, `linux_epoll_dispatch.rs`,
`linux_socket_dispatch.rs`) and associated services. The vISA core — contract ledger,
capability model, generation tracking, profile matrix — was effectively static: it
neither needed to change nor benefited from the expanded Linux surface. The compatibility
layer absorbed all the growth; the semantic core was a fixed-cost substrate.

When every application interaction enters through the Linux frontend, the vISA's internal
type system (~130 ObjectKind variants, generation-bearing references, explicit edge
modes) becomes a translation layer, not a protection layer. The application sees fds, not
capability handles. The application uses `epoll_wait`, not `WaitToken::create`. The
semantic explicitness of the ledger is invisible to the only consumer that matters: the
application developer.

This reproduces Zircon's dilemma. Zircon's kernel object model — processes, threads,
VMOs, VMARs, channels, sockets, event pairs, I/O ports, interrupts, timers — is
technically sound and mechanically well-defined. Fuchsia's Starnix layer translates Linux
syscalls into Zircon kernel objects, preserving the design's internal purity. But the
existence of Starnix means that application developers target Linux, not Zircon. The
kernel object model becomes infrastructure, not interface. The design's internal quality
does not translate to external value. VMOS reproduces this pattern: the Linux frontend
translates over 110 syscalls into vISA effects; application developers target Linux, not
vISA; the contract ledger, capability model, and generation tracking are infrastructure,
not interface.

### Tension 2: The Contract Validator Has No Independent Consumer

The contract graph validator is mechanically sound. It checks 10 violation types across
44 validation methods (spread across `validator_core`, `validator_display`,
`validator_integrated`, `validator_lookup`, and `validator_runtime`), covering every
object domain from device IO to network to block storage to SIMD to display to SMP
scheduling. Its input — a `ContractGraphSnapshot`
containing stores, activations, capabilities, waits, traps, hostcalls, tombstones, and
external objects — is systematically validated for generation consistency, edge mode
correctness, and evidence-boundary adherence. Every one of the ~500 `semantic_core` tests
calls the invariant checker after each state transition, and the result is invariably
no violations — which is expected, since the workload and the validator are
self-consistent by construction.

This is precisely the problem. The validator's input is a `ContractGraphSnapshot`
produced by the same codebase that implements the operations being validated. The
stores, activations, capabilities, waits, traps, and hostcalls in the snapshot are
created by the `semantic_core` graph methods, called by the kernel's supervisor, which
drives the workload. The validator checks invariants over data produced by code sharing
the same authors, the same assumptions, and the same bugs. The ~110 invariant checks, the 10
violation types, the 44 validation methods — this is a substantial engineering
investment in self-consistency checking that produces zero external security evidence.
It is type-checking at a larger scale.

For the contract ledger to function as the "source of truth" the design claims, an
independent consumer is required — a security monitor that reads the EventLog from a
separate privilege domain, an external auditor that replays contract events to
reconstruct authority flow, or a formal verifier that checks the ledger against a
machine-checked specification. Without one, the ledger is a write-only data structure:
records are produced in large volume by a single codebase, and validated by that same
codebase.

### Tension 3: Semantic Explicitness Has an Unobserved Cost

Recording every capability grant, every hostcall trace, every wait creation/resolution,
every trap attribution, and every cleanup step as explicit contract-ledger objects
produces a large volume of semantic records. In the design, these records enable auditing,
replay, migration, and debugging. In practice, the event log tail is printed as debug
output; the migration package is written to disk during host-side validation; and the
contract violations report confirms zero violations — which is expected, since the
workload is self-consistent by construction.

The code to produce these records exists. The code to consume them for any purpose other
than "print summary" does not. The cost (implementation complexity, memory overhead,
cognitive load of maintaining ~130 object record types) is paid; the benefit (external
auditability, cross-ISA replay verification, semantic debugging) is not realized.

### Tension 4: Cross-ISA Portability Solves a Problem Nobody Has

The vISA design devotes significant architecture to cross-ISA portability: the
`portable_subset()` method classifies which semantic records are portable and which are
host-specific; the migration package bundles portable state with a rebuild policy for
host-specific bindings; the profile matrix ensures destination compatibility before
migration.

But cross-ISA migration of running kernel state is a problem that the industry has chosen
not to solve at the VM layer. Cloud providers achieve cross-architecture flexibility
through application-level redundancy — multi-replica deployments, load-balanced services,
and stateless design. When an application can be moved by redirecting traffic to an
ARM-based replica, the ability to live-migrate a running VM from x86 to ARM has no buyer.
The engineering investment in portable semantic state, while technically coherent, was
directed at a non-problem.

### Tension 5: Wasm/WASI Programs Are Better Served by Existing Runtimes

A vISA artifact running inside VMOS incurs layers of translation: Wasm execution →
HostcallFrame → vISA capability check → contract ledger recording → eventual substrate
trait call. A Wasm/WASI program running directly on a Wasmtime-based runtime — or a
unikernel Wasm runtime — bypasses all of these layers. The hostcall attribution,
capability validation, and contract recording that the vISA provides are not valued by
Wasm application developers, who already have sandbox isolation from Wasm itself. The vISA
adds overhead without adding value that the target audience recognizes.

The performance gap is not merely a constant factor. The vISA's semantic recording
(EventLog append, contract graph edge creation, generation validation) is on the critical
path for every hostcall. For Wasm programs that make frequent hostcalls — filesystem
operations, network I/O, timer management — this overhead accumulates. Mature Wasm
runtimes have undergone years of optimization; the vISA's semantic recording path has
not, and the design provides no obvious way to eliminate the overhead without eliminating
the semantic recording itself.

---

## 6. Lessons for Systems Research

Our experience with VMOS suggests several lessons that extend beyond this specific
project.

**The true system center is the compatibility interface, not the internal architecture.**
Any OS project that aims to run existing applications must eventually serve the ABI those
applications expect. That ABI — not the internal object model, not the capability system,
not the contract ledger — is what the system *is* to its users. Designs that treat the
compatibility interface as "optional" or "a frontend concern" are optimized for the wrong
metric. The compatibility interface is the product; the internal architecture is an
implementation detail. Our LTP expansion demonstrated this concretely: growing from 28 to
over 110 syscalls required work almost entirely in the Linux frontend personality. The
vISA core — the architecture the project was designed around — was a fixed-cost substrate
that neither drove the growth nor benefited from it.

**Semantic recording without independent verification is overhead, not security.** A
capability ledger that records every authorization decision provides security value only
if an independent observer can detect when a decision was wrong. A self-consistent ledger
(produced and consumed by the same codebase) is a write-only data structure. The
implication for future designs is that semantic recording should be paired with an
independent verification consumer from the start, or omitted entirely.

**Compatibility layers erase design value.** When a compatibility layer (Linux frontend,
WASI adapter, Starnix) sits between applications and a kernel's internal object model,
the internal design's properties — capability security, explicit lifetimes, formal
verification — are invisible to applications. The compatibility layer absorbs the
design's constraints and presents the legacy interface that applications expect. The
internal design may be better, but no one experiences it. This is not a failure of
engineering; it is a structural property of layered compatibility. If Linux
compatibility is the goal, just use Linux.

**Generation-based identity is a portable engineering pattern.** The `(kind, id,
generation)` object identity model, with generation embedded in handles and validated
before use, can be extracted into any resource-management system. It is small (the core
types — `ObjectRef`, `ContractEdge`, `RefMode`, `EvidenceBoundaryLevel`, and the typed
reference wrappers — fit in a single 789-line `no_std` file in `contract_core`). The
pattern prevents stale-reference errors mechanically and requires no runtime support
beyond integer comparison. The empirical evidence — ~500 tests exercising
generation-aware state transitions, 10 contract violation types systematically
enforcing generation consistency on every cross-object edge, and ~110 structural
invariant checks after every state mutation — demonstrates that the pattern works at
scale. This pattern is arguably more valuable than the vISA architecture it was built to
serve.

**Profile matrices can decouple hardware capability from software requirements.** The
required/optional/forbidden + linear ladder model, with fine-grained feature granularity
(e.g., `DmaRequirement::BounceBufferOrBetter` is distinct from `DmaRequirement::IommuStrict`),
is a design pattern that addresses a real problem in heterogeneous hardware deployment.
It can be extracted independently of the vISA.

**The "kernel as virtual ISA" framing is intellectually productive but practically
unsustainable.** Conceptualizing system semantics as ISA-like operation families
produced a clean design and forced clarity about ownership boundaries. But the framing
also created distance from the actual engineering problem — running applications — that
the system was ultimately judged by. A framing that stays closer to the compatibility
surface (e.g., "explicit resource accounting for Linux workloads") would have produced
different and potentially more useful tradeoffs.

**Research contributions can outlive the systems they were built to demonstrate.**
The contract_core types, the profile matrix, the generation-based identity pattern,
and the explicit edge mode classification do not require the vISA architecture to be
useful. Extracting these patterns into standalone libraries or design documents may
create more value than the integrated system ever could.

---

## 7. Conclusion

We designed and implemented a Semantic Virtual ISA — a kernel-as-virtual-ISA that makes
system semantics (authority, lifetime, waiting, fault handling, cleanup, memory mapping)
portable, explicit, and auditable. The implementation spans 225,000 lines of Rust, runs
on bare-metal x86_64 and QEMU riscv64, and serves over 110 Linux syscalls through a
frontend personality that maps Linux ABI calls into vISA contract-ledger effects. The
Linux surface was expanded from 28 to over 110 syscalls through 10 rounds of LTP-driven
development, providing a practical ramp for syscall coverage.

We conclude that the core premise — that making kernel semantics portable and explicit is
a useful goal — does not hold against the reality of the Linux ABI ecosystem. The Linux
ABI is the de facto system center, and any design that treats it as an optional frontend
eventually discovers that the compatibility layer becomes the system. The LTP expansion
quantified this: 80+ additional syscalls required changes almost exclusively in the
frontend personality, while the vISA semantic core remained static. The compatibility
layer absorbed all the growth. Semantic explicitness without independent consumers
provides only self-referential value, and the cost of producing explicit records is paid
without the benefit of external verification.

Some design patterns survive the system they were built for: generation-based object
identity, profile compatibility matrices, explicit edge modes for contract validation,
and small authority trait surfaces. These can be extracted and reused independently.

Our experience parallels Zircon's: a technically sound design whose value is erased by
the compatibility layer that makes it usable. The pattern generalizes: systems research
that optimizes internal architecture without accounting for the weight of existing
compatibility interfaces is optimizing against the wrong constraint. The Linux ABI is the
system center, not because it is well-designed, but because it is everywhere.

---

## References

- [Klein et al. 2009] Klein, G., Elphinstone, K., Heiser, G., et al. "seL4: Formal
  Verification of an OS Kernel." SOSP 2009.
- [Fuchsia 2016] Google. "Fuchsia." https://fuchsia.dev
- [Hunt and Larus 2007] Hunt, G. C. and Larus, J. R. "Singularity: Rethinking the
  Software Stack." ACM SIGOPS Operating Systems Review, 2007.
- [Zircon] Fuchsia Project. "Zircon Kernel." https://fuchsia.dev/fuchsia-src/concepts/kernel
- [Wasmtime] Bytecode Alliance. "Wasmtime: A WebAssembly Runtime."
  https://wasmtime.dev
