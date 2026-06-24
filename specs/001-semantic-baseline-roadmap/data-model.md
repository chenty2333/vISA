# Data Model: Semantic Baseline Roadmap

## Semantic Baseline

**Purpose**: The Phase 1 fact source for accepted vISA terminology,
boundaries, roadmap phases, validation expectations, and the first downstream
planning target.

**Fields**:
- `identity_statement`: vISA is a cross-ISA Semantic Virtual ISA for portable
  system semantics.
- `scope_exclusions`: Linux compatibility layer, WASI implementation, OS
  service framework, semantic contract database, standalone migration tool,
  archived workflow migration, and runtime behavior changes for Phase 1.
- `semantic_families`: artifact identity, object identity, generation,
  authority, capability, lifetime, wait, event, trap, cleanup, guest memory,
  profile compatibility, frontend normalization, and evidence boundaries.
- `boundary_owns`: artifact identity, semantic object identity, generations,
  authority, capabilities, lifetime, waits, events, traps, cleanup effects,
  guest-memory object state, profile compatibility, and evidence records.
- `boundary_excludes`: raw host page tables, raw register frames, native
  pointers, private execution-engine state, DMA/MMIO bindings, frontend ABI
  handles, Linux syscall breadth, WASI API breadth, debugger output, benchmark
  performance, and reference-service private state as semantic truth.
- `frontend_normalization_rule`: frontend behavior is conforming only after it
  becomes vISA-visible identity, authority, wait, trap, cleanup, profile, event,
  view, and evidence records where applicable.
- `guest_memory_truth_rule`: GuestAddressSpace, VmaRegion, PageObject, memory
  operations, and generations are semantic truth; substrate mappings and DMW
  windows are execution bindings.
- `profile_compatibility_rule`: required, optional, forbidden, reported, and
  enforced profile features gate load and conformance claims before execution
  claims begin.
- `validation_level`: semantic model and source-backed review, backed by
  existing repository checks appropriate to changed artifacts.
- `first_increment`: Phase 1 semantic-baseline package.

**Relationships**:
- Contains one Layer Ownership Map.
- Contains six Roadmap Phases.
- Defines the Evidence Claim rules used by every phase.
- Contains a Semantic Claim Traceability Register.
- References Historical Sources, Current Code Anchors, and documented
  assumptions for traceability.

**Validation rules**:
- Must not require runtime behavior changes.
- Must not promote archived workflow material into active process.
- Must cover every semantic family listed in `SC-003`.
- Every accepted semantic claim must trace to at least one current code anchor,
  historical source marked as background, or documented assumption.

## Layer Ownership Map

**Purpose**: The responsibility split that prevents future features from
placing semantic truth in the wrong layer.

**Fields**:
- `system_center`: Semantic Virtual ISA boundary and operation families.
- `effect_contract`: stable effect language, object refs, commands, events,
  views, and invariants.
- `artifact_runtime_carrier`: artifact envelope, code identity, hostcall frame,
  trap attribution, profile records, and extraction boundary.
- `substrate_authority`: machine authority reporting and trait-backed
  enforcement.
- `frontend_personality`: Linux, WASI, services, and future guest-facing
  adapters that normalize behavior into vISA-visible effects.
- `stable_views`: read-only evidence and inspection outputs.
- `validation_conformance`: checks that name the weakest evidence boundary.

**Relationships**:
- Each Roadmap Phase names the layer or layers it primarily advances.
- Each Evidence Claim names the layer where the claim is observed.

**Validation rules**:
- Frontend handles, raw host pointers, raw registers, page tables, DMA/MMIO
  bindings, and private execution-engine state must not become semantic truth.
- Frontend/personality adapters own guest-visible compatibility only after
  normalizing behavior into contract-visible effects and evidence.
- Substrate authority owns enforceable machine capability reporting, not
  authorization policy.

## Roadmap Phase

**Purpose**: A staged, independently useful slice of long-term semantic
evolution.

**Fields**:
- `name`: Phase 1 through Phase 6 name.
- `purpose`: why the phase exists.
- `semantic_families`: families addressed by the phase.
- `entry_condition`: what must be true before planning the phase.
- `exit_condition`: what must be true before the phase is considered complete.
- `expected_evidence_boundary`: weakest evidence level the phase may claim.

**Relationships**:
- Ordered after earlier phases unless a later plan explicitly narrows scope and
  preserves the earlier gates.
- Produces or strengthens Evidence Claims.

**Validation rules**:
- Must include all six fields above.
- Must not claim stronger evidence than its validation path exercises.

**State transitions**:
- `proposed` -> `planned` when accepted in Spec Kit plan artifacts.
- `planned` -> `tasked` when `/speckit-tasks` creates scoped tasks.
- `tasked` -> `validated` when the phase exit condition and evidence checks
  pass.

## Roadmap Phase Instances

| Phase | Primary layers | Included semantic families | Evidence boundary |
|-------|----------------|----------------------------|-------------------|
| Phase 1 Semantic Baseline | system center, validation, conformance evidence | all baseline families at classification level: artifact identity, object identity, generation, capability authority, wait state, event evidence, trap attribution, cleanup, guest memory, profile compatibility, frontend normalization, evidence boundaries | semantic model and source-backed review plus applicable existing checks |
| Phase 2 Contract Core Stabilization | effect contract, stable views, validation | object identity, generation, graph edges, capability authority, wait state, events, traps, cleanup, guest-memory object truth, graph validation | semantic model with stable machine-readable evidence |
| Phase 3 Artifact And Profile Gate | artifact/runtime carrier, validation, conformance evidence | artifact identity, code identity, hostcall attribution, trap attribution, profile compatibility, package roots, artifact evidence | reference artifact harness |
| Phase 4 Personality Normalization | frontend/personality adapters, effect contract, stable views | frontend normalization, guest-visible resources, capability gates, waits, events, traps, cleanup, profile interface requirements, stable personality traces | reference service or reference artifact harness |
| Phase 5 Substrate Authority Expansion | substrate authority, artifact/runtime carrier, conformance evidence | guest-memory enforcement, DMW, DMA, MMIO, IRQ, event queue, code publish, unsupported/degraded authority, extraction evidence | portable artifact execution for portable claims; real target substrate for hardware claims |
| Phase 6 Snapshot And Cross-ISA Portability | artifact/runtime carrier, substrate authority, stable views, conformance evidence | migration package roots, snapshot barriers, semantic state preservation, artifact/profile compatibility, wait and cleanup quiescence, host-specific binding exclusion, stable portability evidence | portable artifact execution, rising to real target substrate evidence when real targets are claimed |

## Evidence Claim

**Purpose**: A statement about vISA behavior paired with the weakest exercised
evidence boundary and stable evidence roots.

**Fields**:
- `claim`: behavior being asserted.
- `evidence_boundary`: semantic model, reference service, reference artifact
  harness, portable artifact execution, or real target substrate.
- `stable_roots`: spec artifact, code anchor, event/view/package evidence, or
  existing repository check supporting the claim.
- `traceability_source`: current code anchor, historical source, or documented
  assumption used to justify the claim.
- `claim_limit`: strongest claim permitted by the evidence boundary.
- `exclusions`: host-specific state or unvalidated shortcuts not covered by
  the claim.

**Relationships**:
- Every Roadmap Phase has an expected evidence boundary.
- Every First Increment validation result is an Evidence Claim at Phase 1 level.

**Validation rules**:
- Stronger claims require stronger evidence in later phases.
- Prose logs alone are not stable evidence roots.
- A Phase 1 claim may not exceed semantic-model/source-backed review evidence.

## Historical Source

**Purpose**: Archived vision or specification material used only as semantic
background.

**Fields**:
- `path`: archived document path under `docs/archive/achieve/`.
- `used_for`: semantic invariant, terminology, phase candidate, or boundary
  example.
- `active_status`: always historical for this feature.

**Relationships**:
- Can support Semantic Baseline traceability.
- Cannot define active workflow on its own.

**Validation rules**:
- Any current decision derived from a Historical Source must be restated in the
  active Spec Kit artifacts.

## Current Code Anchor

**Purpose**: Existing repository structure or behavior used as observed
evidence for the baseline.

**Fields**:
- `path`: current repository path.
- `observed_fact`: what the code or script currently demonstrates.
- `validation_check`: applicable existing check, if any.
- `claim_limit`: maximum evidence level this anchor supports.

**Relationships**:
- Supports Semantic Baseline traceability and quickstart checks.
- Does not automatically create a semantic commitment without baseline
  acceptance.

**Validation rules**:
- Must not be used to claim runtime behavior beyond the exercised check.

## Semantic Claim Traceability Register

| Claim | Historical source | Current code anchor | Accepted Phase 1 limit |
|-------|-------------------|---------------------|------------------------|
| vISA is a cross-ISA Semantic Virtual ISA, not a Linux/WASI/service/migration center. | `docs/archive/achieve/specs/semantic-virtual-isa-v0/00-overview.md`, `docs/archive/achieve/vision/semantic-virtual-isa.md`, `docs/archive/achieve/vision/semantic-visa-v0.md` | `crates/core/semantic_core/src/lib.rs`, `crates/core/contract_core/src/lib.rs` | Identity baseline only; no new runtime behavior. |
| The core boundary owns artifact identity, object identity, generation, authority, capability, wait, event, trap, cleanup, guest memory, profile compatibility, and evidence. | `docs/archive/achieve/specs/semantic-contract-v0.1/00-overview.md`, `docs/archive/achieve/specs/semantic-virtual-isa-v0/02-operation-families.md` | `crates/core/semantic_core/src/lib.rs`, `crates/core/contract_core/src/lib.rs`, `crates/core/artifact_manifest/src/target_runtime.rs` | Semantic model/source-backed classification. |
| Raw page tables, raw registers, native pointers, private runtime state, DMA/MMIO bindings, and frontend handles are not semantic truth. | `docs/archive/achieve/specs/semantic-virtual-isa-v0/00-overview.md`, `docs/archive/achieve/specs/semantic-contract-v0.1/12-guest-memory-object-model.md`, `docs/archive/achieve/vision/cross-isa-migration.md` | `crates/backend/substrate_api/src/traits.rs`, `crates/core/semantic_core/src/guest_memory.rs` | Exclusion rule only; no substrate claim. |
| Frontend/personality behavior must normalize into vISA-visible effects before it is conforming. | `docs/archive/achieve/specs/semantic-contract-v0.1/11-frontend-personality-boundary.md`, `docs/archive/achieve/specs/semantic-virtual-isa-v0/05-frontend-personality-boundary.md` | `crates/services/linux_syscall/Cargo.toml`, `crates/services/futex_service/Cargo.toml`, `crates/services/epoll_service/Cargo.toml`, `crates/host/kernel/src/frontends/linux_elf/bridge.rs` | Existing frontend code is a code anchor, not a portable-artifact claim. |
| Guest memory is semantic object state, not substrate-owned page table truth. | `docs/archive/achieve/specs/semantic-contract-v0.1/12-guest-memory-object-model.md`, `docs/archive/achieve/vision/cross-isa-migration.md` | `crates/core/semantic_core/src/guest_memory.rs`, `crates/core/semantic_core/src/graph/guest_memory.rs`, `crates/core/contract_validate/src/tests/roots_guest_memory.rs` | Semantic model and validation anchor; no real MMU claim. |
| Profile compatibility is a load/conformance contract with required, optional, forbidden, reported, and enforced distinctions. | `docs/archive/achieve/specs/semantic-virtual-isa-v0/03-profile-matrix.md`, `docs/archive/achieve/specs/target-runtime-abi/05-target-profile-and-runtime-package.md`, `docs/archive/achieve/specs/substrate-api-v0/02-capability-discovery-profiles.md` | `crates/core/visa_profile/src/lib.rs`, `crates/core/semantic_core/src/graph/profile.rs`, `crates/core/contract_validate/src/lib.rs` | Profile taxonomy and gate semantics; no stronger target execution claim. |
| Artifact/runtime carrier work owns TargetArtifactImage, CodeObject, HostcallFrame, TrapMap, package roots, and profile records without redefining semantic policy. | `docs/archive/achieve/specs/target-runtime-abi/00-overview.md`, `docs/archive/achieve/specs/target-runtime-abi/01-target-artifact-image.md`, `docs/archive/achieve/specs/target-runtime-abi/03-hostcall-frame.md`, `docs/archive/achieve/specs/target-runtime-abi/04-trap-map-and-attribution.md` | `crates/core/artifact_manifest/src/target_runtime.rs`, `crates/core/artifact_manifest/src/lib.rs` | Roadmap ownership only; no new artifact execution. |
| Substrate authority is backend enforceability reporting, not authorization policy or frontend semantics. | `docs/archive/achieve/specs/substrate-api-v0/00-overview.md`, `docs/archive/achieve/specs/substrate-api-v0/01-authority-traits.md` | `crates/backend/substrate_api/src/traits.rs`, `crates/backend/substrate_api/src/profiles.rs`, `crates/core/visa_profile/src/lib.rs` | Authority taxonomy only; hardware claims require later evidence. |
| Evidence claims must name the weakest exercised boundary. | `docs/archive/achieve/specs/semantic-virtual-isa-v0/06-conformance-and-evidence-boundary.md` | `crates/core/contract_core/src/lib.rs`, `crates/testing/visa-conformance/README.md`, `scripts/run-report-gates.sh` | Phase 1 can claim only semantic-model/source-backed review plus docs checks. |
| Cross-ISA migration is a conformance test for semantic state survival, not a standalone feature. | `docs/archive/achieve/vision/cross-isa-migration.md`, `docs/archive/achieve/specs/semantic-virtual-isa-v0/06-conformance-and-evidence-boundary.md` | `crates/core/artifact_manifest/src/semantic_snapshot.rs`, `crates/core/contract_validate/src/migration.rs` | Later roadmap target; no migration implementation in Phase 1. |
| The first increment is a documentation and validation package. | Current specification clarification and plan. | `specs/001-semantic-baseline-roadmap/quickstart.md`, `.specify/feature.json`, `AGENTS.md` | Existing docs/artifact checks only; no code or harness change. |

## First Increment

**Purpose**: The smallest downstream implementation plan that preserves the
baseline and prepares future task generation.

**Fields**:
- `name`: Phase 1 semantic-baseline package.
- `artifact_set`: spec, plan, research, data model, contract, quickstart,
  tasks, checklist, and AGENTS plan pointer.
- `completion_checks`: artifact presence, marker scans, scope drift scan, and
  whitespace validation.
- `excluded_work`: runtime behavior changes, new validation harnesses, and
  portable artifact execution claims.

**Relationships**:
- Implements the Semantic Baseline.
- Produces validation inputs for `/speckit-tasks`.

**Validation rules**:
- Must pass existing repository checks appropriate to changed artifacts.
- Must leave stronger evidence boundaries to later roadmap phases.
