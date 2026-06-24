# Feature Specification: Semantic Baseline Roadmap

**Feature Branch**: `not branch-bound`

**Created**: 2026-06-23

**Status**: Draft

**Input**: User description: "Based on docs/archive/achieve/specs/, docs/archive/achieve/vision/, and current code, establish vISA's long-term semantic evolution roadmap and first-phase semantic baseline. Extract old ideas into the current executable Spec Kit fact source: clarify vISA's core semantic boundary, long-term module layering, phased feature slicing, validation method, and first implementable increment. Do not carry over the old workflow and do not implement code directly."

## Clarifications

### Session 2026-06-23

- Q: What validation level is required for Phase 1 completion? -> A: Source-backed traceability plus existing repository checks appropriate to changed artifacts; no new runtime behavior.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Establish Semantic Baseline (Priority: P1)

As a vISA maintainer, I need one current Spec Kit source that states what vISA is, what it is not, which semantic facts are stable enough to plan against, and what first increment can be built next.

**Why this priority**: Without a baseline, future work can drift back into archived workflow notes, Linux-compatibility breadth, or substrate-specific shortcuts instead of building the Semantic Virtual ISA.

**Independent Test**: A reviewer can read the baseline and answer the identity, boundary, layer ownership, validation level, and first-increment questions without opening historical workflow notes.

**Acceptance Scenarios**:

1. **Given** the archived architecture material and current repository state, **When** the baseline is reviewed, **Then** it distinguishes current Spec Kit facts from historical background and does not treat archived workflow structure as active process.
2. **Given** a proposed vISA change, **When** the maintainer checks it against the baseline, **Then** the change can be classified as inside or outside the core Semantic Virtual ISA boundary.
3. **Given** a future planning session, **When** the first implementable increment is selected, **Then** the selected increment is small enough to validate without changing runtime behavior first.

---

### User Story 2 - Plan Long-Term Semantic Evolution (Priority: P2)

As a feature implementer, I need the roadmap split into phases so that artifact, contract, profile, personality, substrate, evidence, and migration work can be planned in coherent increments.

**Why this priority**: The archived documents contain useful semantic ideas, but they mix future goals, current contracts, and old terminology. The roadmap must convert those ideas into staged, testable feature slices.

**Independent Test**: A planned feature can be mapped to one roadmap phase, one primary semantic layer, and one expected evidence boundary.

**Acceptance Scenarios**:

1. **Given** a feature involving object identity, capability, waits, cleanup, guest memory, artifacts, profiles, or evidence, **When** the roadmap is consulted, **Then** the feature has an obvious owning phase and does not require inventing a parallel workflow.
2. **Given** a feature that spans several semantic families, **When** it is planned, **Then** the roadmap identifies the earliest independently useful slice and defers later substrate or personality breadth.
3. **Given** a feature proposed only to increase Linux, WASI, or service compatibility breadth, **When** it is evaluated, **Then** the roadmap requires normalization into vISA-visible effects before treating it as core semantic progress.

---

### User Story 3 - Validate Semantic Claims (Priority: P3)

As a reviewer, I need each phase and baseline claim to state the evidence required before the project can claim semantic, portable-artifact, substrate, or migration behavior.

**Why this priority**: vISA's value depends on explicit evidence boundaries. A reference service, fake harness, or host-only shortcut must not be reported as stronger portable execution.

**Independent Test**: A reviewer can classify a claim by evidence level and reject claims that lack the required machine-readable evidence.

**Acceptance Scenarios**:

1. **Given** a conformance claim, **When** the validation rules are applied, **Then** the claim names the weakest boundary exercised and does not overstate portability.
2. **Given** runtime or control-plane evidence, **When** it is reviewed, **Then** stable views, event records, graph validation, or package facts are preferred over prose logs.
3. **Given** a cross-ISA or migration claim, **When** it is reviewed, **Then** the claim proves semantic state can survive substrate changes without treating host-specific bindings as semantic truth.

### Edge Cases

- Archived documents describe a section as "active", but current governance says archived material is historical background.
- Current code contains broader experiments than the first baseline should bless as stable semantic truth.
- Linux syscall breadth, WASI support, services, or debugger output are mistaken for vISA core completeness.
- A reference service or harness proves an effect but does not exercise portable artifact execution.
- A feature wants to use raw host page tables, raw registers, native pointers, DMA/MMIO bindings, or private execution-engine state as semantic truth.
- A validation path is useful operationally but does not emit stable, machine-readable evidence.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The specification MUST define vISA as a cross-ISA Semantic Virtual ISA for portable system semantics, not as a Linux compatibility layer, WASI implementation, OS service framework, semantic contract database, or standalone migration tool.
- **FR-002**: The baseline MUST define the core semantic boundary in terms of artifact identity, object identity, generation, authority, capability, lifetime, wait, event, trap, cleanup, guest memory, profile compatibility, and evidence.
- **FR-003**: The baseline MUST state what the semantic boundary owns and does not own, including clear exclusion of raw host page tables, raw register frames, private execution-engine state, native DMA/MMIO bindings, and frontend ABI handles as semantic truth.
- **FR-004**: The specification MUST define long-term layer ownership for the system center, effect contract, artifact/runtime carrier, substrate authority, frontend/personality adapters, stable views, validation, and conformance evidence.
- **FR-005**: The roadmap MUST split long-term evolution into ordered phases with a purpose, included semantic families, entry condition, exit condition, and expected evidence boundary for each phase.
- **FR-006**: Phase 1 MUST be a semantic baseline phase that produces current Spec Kit facts and validation criteria without requiring new runtime behavior.
- **FR-007**: The first implementable increment MUST be a documentation and validation increment: establish the accepted baseline, roadmap, evidence taxonomy, traceability to current code and archived background, and the existing repository checks that apply to changed artifacts before code implementation begins.
- **FR-008**: The roadmap MUST require future feature work to identify the owning phase, semantic layer, evidence level, and current validation path before implementation planning.
- **FR-009**: The roadmap MUST prevent historical workflow migration by using archived material only as background and by keeping active decisions in current Spec Kit artifacts.
- **FR-010**: The validation model MUST distinguish semantic model evidence, reference/native service evidence, reference artifact harness evidence, portable artifact execution evidence, and real target substrate evidence.
- **FR-011**: The validation model MUST require claims to name the weakest exercised evidence boundary and the stable evidence roots that support the claim.
- **FR-012**: The baseline MUST define how frontend/personality behavior becomes conforming only after it is normalized into vISA-visible effects with stable identity, authority, wait, trap, cleanup, profile, and evidence records where applicable.
- **FR-013**: The baseline MUST define guest memory as semantic object state rather than substrate-owned page table truth.
- **FR-014**: The baseline MUST define profile compatibility as a load and conformance contract, including required, optional, forbidden, reported, and enforced capability distinctions.
- **FR-015**: The specification MUST identify the first downstream planning target as a semantic-baseline implementation plan that verifies the baseline and prepares only the smallest accepted code or documentation change set needed by that plan.

### Core Semantic Boundary

The Phase 1 accepted boundary is the Semantic Virtual ISA boundary. It owns
portable system semantics that can be expressed as artifact identity, semantic
object identity, generation-bearing references, authority, capabilities,
lifetime, waits, events, trap attribution, cleanup effects, guest-memory object
state, profile compatibility, and evidence boundaries.

The boundary does not own raw host page tables, raw register frames, native
pointers, private execution-engine state, native DMA/MMIO bindings, frontend ABI
handles, Linux syscall breadth, WASI API breadth, debugger output, benchmark
performance, or reference-service private state as semantic truth. Those facts
can support future work only after they are normalized into vISA-visible effects
with stable identity, authority, generation, event, view, profile, and evidence
records.

Frontend/personality behavior becomes conforming when guest-visible behavior is
translated into the same vISA semantic effects. Linux, WASI, services,
filesystem, socket, futex, epoll, signal, debugger, or future ABI work is not
core progress merely because the frontend surface expands.

Guest memory is accepted as semantic object state: GuestAddressSpace, VmaRegion,
PageObject, guest-memory operations, and generation checks are the semantic
truth. Substrate mappings, page tables, DMW windows, TLBs, and raw host
pointers are execution bindings and must not be reported as portable truth.

Profile compatibility is accepted as a load and conformance contract.
Artifacts name required, optional, and forbidden features. Targets report what
they claim to provide, loaders/substrate checks establish what is enforceable,
missing required support rejects the artifact, missing optional support must be
event-visible degradation, and forbidden requested support is rejected before
execution claims begin.

### Roadmap Phases

- **Phase 1: Semantic Baseline**: Establish the current Spec Kit source of truth, semantic boundary, layer ownership, evidence taxonomy, and first planning target. Semantic families: all baseline families at source-backed classification level: artifact identity, object identity, generation, capability authority, wait state, event evidence, trap attribution, cleanup, guest memory, profile compatibility, frontend normalization, and evidence boundaries. Entry condition: archived sources and current code are available for review. Exit condition: maintainers can classify proposed work by boundary, layer, phase, and evidence level, and changed artifacts pass the existing repository checks that apply to them. Expected evidence boundary: semantic model and source-backed review, backed by applicable existing checks rather than new runtime behavior.
- **Phase 2: Contract Core Stabilization**: Stabilize identity, generation, graph edges, commands, events, stable views, capability authority, wait state, cleanup transactions, and guest memory object truth. Semantic families: object identity, generation, capability authority, wait state, event evidence, trap attribution, cleanup, guest memory, stable views, and graph validation. Entry condition: Phase 1 baseline accepted. Exit condition: all baseline semantic families have positive and negative validation coverage. Expected evidence boundary: semantic model with stable machine-readable evidence.
- **Phase 3: Artifact And Profile Gate**: Align artifact identity, load compatibility, code identity, hostcall attribution, trap attribution, and profile enforcement with the semantic contract. Semantic families: artifact identity, code identity, hostcall attribution, trap attribution, profile compatibility, package roots, and artifact evidence. Entry condition: core effect families have stable validation. Exit condition: artifact claims cannot start before profile compatibility and identity checks are validated. Expected evidence boundary: reference artifact harness.
- **Phase 4: Personality Normalization**: Normalize Linux, WASI, service, filesystem, socket, futex, epoll, signal, and future frontend behavior into vISA-visible semantic effects. Semantic families: frontend normalization, guest-visible resources, capability gates, waits, events, traps, cleanup, profile interface requirements, and stable personality traces. Entry condition: artifact/profile gate can classify frontend requirements separately from substrate authority. Exit condition: frontend breadth is evaluated by semantic effects, not by frontend API count. Expected evidence boundary: reference service or reference artifact harness, depending on the path exercised.
- **Phase 5: Substrate Authority Expansion**: Expand enforceable machine authority for memory, code publish, device, DMA, MMIO, IRQ, event queue, snapshot, and extraction while preserving capability and generation gates. Semantic families: substrate authority, guest-memory enforcement, DMW, DMA, MMIO, IRQ, event queue, code publish, unsupported/degraded authority, and extraction evidence. Entry condition: profile reports and semantic gates are stable enough to reject unsupported authority visibly. Exit condition: missing or degraded authority produces explicit evidence and cannot be hidden behind untyped failure. Expected evidence boundary: portable artifact execution for portable claims and real target substrate evidence for hardware claims.
- **Phase 6: Snapshot And Cross-ISA Portability**: Validate that semantic state, profile requirements, artifact identity, waits, cleanup, and stable views survive substrate changes while host-specific bindings are dropped, rebuilt, or replayed. Semantic families: migration package roots, snapshot barriers, semantic state preservation, artifact/profile compatibility, wait and cleanup quiescence, host-specific binding exclusion, and stable portability evidence. Entry condition: snapshot barriers and substrate authority reporting are stable. Exit condition: migration packages prove compatibility without treating raw host state as semantic truth. Expected evidence boundary: portable artifact execution, rising to real target substrate evidence when real targets are claimed.

### First Implementable Increment

The first implementable increment is the Phase 1 semantic-baseline package. It is complete when the active Spec Kit artifacts define the accepted semantic boundary, roadmap phases, layer ownership, validation taxonomy, and next planning target with source-backed traceability, then pass the existing repository checks appropriate to the changed artifacts. It does not change runtime behavior and does not bless any archived workflow as active process.

### Key Entities

- **Semantic Boundary**: The accepted line between vISA semantic truth and frontend, runtime, substrate, or host-specific implementation facts.
- **Layer Ownership Map**: The long-term responsibility split across system center, effect contract, artifact/runtime carrier, substrate authority, frontend/personality adapters, stable views, validation, and conformance evidence.
- **Roadmap Phase**: A staged feature slice with a purpose, semantic families, entry condition, exit condition, and expected evidence boundary.
- **Semantic Baseline**: The Phase 1 fact source that defines current accepted terminology, invariants, scope exclusions, and first planning target.
- **Evidence Claim**: A statement about behavior paired with the weakest exercised evidence boundary and stable evidence roots.
- **Historical Source**: Archived vision or specification material used as background only, never as an active workflow ledger.
- **Current Code Anchor**: Existing repository behavior or structure used as observed evidence, subject to the accepted semantic boundary and validation level.
- **First Increment**: The smallest downstream plan that can validate and preserve the baseline before broader semantic implementation work begins.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of roadmap phases include a purpose, included semantic families, entry condition, exit condition, and expected evidence boundary.
- **SC-002**: A maintainer can classify a proposed change as inside or outside the core vISA semantic boundary in under 10 minutes using the baseline alone.
- **SC-003**: The Phase 1 baseline covers all required semantic families: artifact identity, object identity, generation, capability authority, wait state, event evidence, trap attribution, cleanup, guest memory, profile compatibility, frontend normalization, and evidence boundaries.
- **SC-004**: Every semantic claim in the baseline is traceable to current repository evidence, archived background explicitly marked as historical, or a documented assumption.
- **SC-005**: No roadmap phase claims a stronger evidence level than the weakest validation boundary defined for that phase.
- **SC-006**: The next planning command can derive a first implementation plan without asking whether the project should copy archived workflow structure, implement runtime behavior immediately, or create a new validation harness for Phase 1.
- **SC-007**: Reviewers can reject at least five common drift cases from the Edge Cases section using explicit baseline rules rather than personal interpretation.

## Assumptions

- Current Spec Kit artifacts are the active source of truth for feature work.
- Material under `docs/archive/achieve/specs/` and `docs/archive/achieve/vision/` is useful semantic background but not an active workflow ledger.
- Current code is evidence of what exists and what can be validated, but the baseline decides which facts are accepted semantic commitments.
- Phase 1 is intentionally documentation and validation oriented; source-code implementation belongs to a later plan after the baseline is accepted.
- Validation command details remain documented outside this spec; Phase 1 uses the existing repository checks appropriate to changed artifacts and defines what claims must be validated and what evidence level they may claim.
- No branch-creation hook was configured for this specification run, so the feature directory is independent of the current git branch.
