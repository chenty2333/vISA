# Feature Specification: Contract Core Stabilization

**Feature Branch**: `not branch-bound`

**Created**: 2026-06-24

**Status**: Draft

**Input**: User description: "Implement the complete contract core. Treat the broad Phase 2-6 goal as the long-term direction, but begin with a Spec Kit feature for the first executable slice: Phase 2 Contract Core Stabilization."

## Clarifications

### Session 2026-06-24

- Q: What carrier should Phase 2 use for stable machine-readable validation evidence? -> A: Reuse existing artifact or migration package structures as the evidence carrier for Phase 2, without claiming artifact/runtime execution or migration behavior.
- Q: What validation coverage depth is required for Phase 2 completion? -> A: Exhaustive semantic coverage across every relevant object kind, edge mode, command area, and state transition, with positive and negative validation.
- Q: What compatibility commitment applies to the Phase 2 evidence shape? -> A: Feature-local only; the evidence shape may change during Feature 002 and no post-completion compatibility policy is declared by this feature.
- Q: Which surface determines the exhaustive Phase 2 coverage units? -> A: Phase 2-owned units only: object identity, generation, graph edges, capability, wait, event, trap, cleanup, guest memory, stable views, and graph validation.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Stabilize Contract Effect Language (Priority: P1)

As a vISA maintainer, I need the contract core to define one stable,
machine-readable language for vISA-visible effects so that semantic objects,
references, events, views, validation results, and evidence boundaries can be
shared without relying on private runtime or frontend state.

**Why this priority**: Phase 2 is the foundation for the user's long-term
"complete contract core" goal. Later artifact, personality, substrate, and
migration work cannot make reliable claims until the core effect language is
stable and hard to misuse.

**Independent Test**: A reviewer can inspect the Phase 2 contract surface and
confirm that every baseline family assigned to Phase 2 can be represented as
stable contract facts without importing raw runtime, frontend, substrate, or
host-specific details.

**Acceptance Scenarios**:

1. **Given** a semantic object with an identity and generation, **When** it is
   represented through the contract core, **Then** the representation includes
   a stable object kind, nonzero identity, generation, and evidence boundary.
2. **Given** a vISA-visible effect involving a command, event, view, or
   validation result, **When** it crosses a semantic ownership boundary,
   **Then** the receiving side can interpret the effect without reading
   private runtime implementation state.
3. **Given** a proposed contract fact that contains raw host page tables,
   register frames, native pointers, private execution-engine state, substrate
   handles, frontend ABI handles, or CLI-only formatting, **When** it is
   reviewed against this feature, **Then** it is rejected as outside the
   contract core boundary.

---

### User Story 2 - Validate Phase 2 Semantic Families (Priority: P2)

As a semantic-contract reviewer, I need positive and negative validation
coverage for the Phase 2 semantic families so that identity, generation, graph
edges, authority, waits, events, traps, cleanup, guest memory, and stable views
can be trusted as machine-readable evidence.

**Why this priority**: Contract records without validation still allow hidden
semantic drift. Phase 2 is complete only when accepted contract facts can prove
the invariants they claim and reject common invalid shapes.

**Independent Test**: A reviewer can run the relevant validation path and see
valid examples accepted and invalid examples rejected for every relevant Phase
2 object kind, edge mode, command area, and state transition, with structured
reasons for each rejection.

**Acceptance Scenarios**:

1. **Given** a contract graph containing live, historical, cleanup-effect, and
   external references, **When** validation runs, **Then** live ownership cannot
   target tombstones or stale generations, historical references keep exact
   generations, cleanup effects cannot create authority, and external
   references require declarations.
2. **Given** a command that fails a precondition, **When** it is applied
   through the contract transaction boundary, **Then** semantic state remains
   unchanged and the result records a structured rejection reason.
3. **Given** capability, wait, trap, cleanup, or guest-memory evidence, **When**
   it is validated, **Then** the evidence is checked through stable object
   identities, generations, event records, views, and violation records rather
   than prose logs or private implementation assumptions.
4. **Given** a Phase 2-owned object kind, edge mode, command area, or state
   transition has no positive or negative validation scenario, **When** the
   feature is reviewed for completion, **Then** it is rejected as incomplete.

---

### User Story 3 - Preserve Roadmap Boundaries For The Full Goal (Priority: P3)

As the maintainer planning the broader "complete contract core" direction, I
need this feature to make clear which parts of the broad goal are included in
Phase 2 and which remain in later roadmap phases.

**Why this priority**: The user selected the broad implementation direction,
but Feature 001 split that direction into phases. This feature must deliver
the first executable slice without silently pulling in artifact/profile,
frontend/personality, substrate-authority, or migration scope.

**Independent Test**: A reviewer can classify any proposed addition as Phase 2
contract-core work or as a later roadmap-phase dependency in under 10 minutes.

**Acceptance Scenarios**:

1. **Given** a proposed change involving artifact load compatibility,
   CodeObject publication, HostcallFrame details, TrapMap completeness, package
   roots, or profile gates, **When** it is reviewed for this feature, **Then**
   it is accepted only if it stabilizes generic contract facts and is otherwise
   deferred to the artifact/profile gate.
2. **Given** a proposed change involving Linux, WASI, filesystem, socket,
   futex, epoll, signal, or service breadth, **When** it is reviewed for this
   feature, **Then** it is accepted only if it normalizes into contract-visible
   effects and is otherwise deferred to personality normalization.
3. **Given** a proposed change involving DMW, DMA, MMIO, IRQ, event queue,
   hardware authority, snapshot restoration, or cross-ISA migration, **When**
   it is reviewed for this feature, **Then** it is accepted only as a contract
   evidence shape and is otherwise deferred to substrate or portability phases.
4. **Given** Phase 2 validation evidence stored in an artifact or migration
   package-shaped carrier, **When** it is reviewed for this feature, **Then**
   the carrier is accepted only as a contract evidence envelope and does not
   imply artifact execution, profile-gate completion, migration restoration, or
   portability claims.
5. **Given** the Phase 2 evidence shape changes before Feature 002 is
   complete, **When** the feature is still in progress, **Then** reviewers
   evaluate only the current shape and do not require this feature to preserve
   compatibility with earlier in-feature evidence drafts.

### Edge Cases

- A live edge points at a tombstone, dead store, dead activation, stale
  generation, or missing object.
- A historical edge omits the exact generation it claims to audit.
- A cleanup effect is reused as live ownership or authorization.
- A rejected command partially mutates state or emits success-like evidence.
- A non-Phase 2 object kind is pulled into exhaustive coverage only because it
  is visible in current code, despite belonging to artifact/profile,
  frontend/personality, substrate, or portability phases.
- Validation stops at the first violation and hides additional independent
  contract problems.
- A prose log, debugger view, benchmark result, or CLI output is treated as
  stable contract evidence.
- An artifact or migration package-shaped evidence carrier is mistaken for a
  Phase 3 artifact execution claim or Phase 6 migration claim.
- An in-feature evidence draft is treated as a stable post-completion schema
  compatibility promise.
- Raw host page tables, register frames, native pointers, substrate bindings,
  frontend ABI handles, or private runtime state are recorded as semantic
  truth.
- Artifact/profile, frontend/personality, substrate-authority, or migration
  work is added under the label "contract core" without respecting the roadmap
  phase boundary.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The feature MUST implement the Phase 2 Contract Core
  Stabilization slice from the accepted semantic-baseline roadmap, not the full
  Phase 3-6 roadmap.
- **FR-002**: The feature MUST define the contract core as the stable language
  for vISA-visible effects, including object references, generations, edge
  modes, command outcomes, event evidence, stable views, validation violations,
  evidence boundaries, and package-level evidence records.
- **FR-002a**: Phase 2 machine-readable validation evidence MUST reuse existing
  artifact or migration package structures as the evidence carrier, while
  treating that carrier only as a contract evidence envelope for this feature.
- **FR-002b**: The Phase 2 evidence shape MAY change during Feature 002, and
  this feature MUST NOT declare a post-completion compatibility policy for that
  shape.
- **FR-003**: The contract core boundary MUST exclude graph mutation policy,
  runtime execution, substrate trait behavior, artifact execution mechanics,
  frontend ABI behavior, control-plane formatting, and adapter-private service
  state as semantic truth.
- **FR-004**: Every contract-visible object reference MUST make object kind,
  identity, and generation validation-visible, and invalid zero identities or
  missing internal generations MUST be rejected.
- **FR-005**: Contract graph edges MUST distinguish live, historical,
  cleanup-effect, and external relations, with validation rules for stale
  generations, tombstones, dead owners, missing declarations, and authority
  misuse.
- **FR-006**: Command transactions MUST expose precondition, mutation, event
  emission, postcondition, structured status, effect list, and violation
  reporting semantics; rejected commands MUST leave semantic state unchanged.
- **FR-007**: Event and stable-view records MUST be sufficient for reviewers
  to inspect semantic state and validation outcomes without relying on prose
  logs or private implementation details.
- **FR-008**: Capability authority validation MUST cover grant, delegation,
  attenuation, revocation, stale handle rejection, generation checks, and
  authority provenance at the semantic model evidence boundary.
- **FR-009**: Wait-state validation MUST cover wait creation, pending state,
  resolution, cancellation, restart, resume eligibility, owner generation, and
  event bridge evidence.
- **FR-010**: Trap evidence validation MUST cover semantic attribution and
  evidence records without requiring Phase 3 artifact/profile load gates,
  HostcallFrame completeness, or target TrapMap execution claims.
- **FR-011**: Cleanup validation MUST cover begin, step, commit, generation-safe
  targeting, idempotence, cleanup-effect edges, wait cancellation, capability
  revocation, tombstone interaction, and post-cleanup live-leak rejection.
- **FR-012**: Guest-memory validation MUST treat GuestAddressSpace, VmaRegion,
  PageObject, memory operations, and generation-bearing history as semantic
  object truth while excluding substrate page tables, DMW windows, TLBs, and
  host pointers as portable truth.
- **FR-013**: The validation path MUST include accepted and rejected examples
  for every Phase 2-owned object kind, edge mode, command area, and state
  transition covered by object identity, generation, graph edges, capability
  authority, wait state, event evidence, trap attribution, cleanup, guest
  memory, stable views, and graph validation.
- **FR-013a**: Exhaustive coverage MUST NOT include object kinds, command
  areas, or state transitions solely because they exist in current code when
  their semantic ownership belongs to artifact/profile, frontend/personality,
  substrate-authority, or portability phases.
- **FR-014**: Validation results MUST report structured reasons and MUST expose
  all independently detectable violations rather than hiding later failures
  behind the first detected issue.
- **FR-015**: Every claim produced by this feature MUST name its weakest
  exercised evidence boundary and MUST NOT claim reference artifact execution,
  portable artifact execution, real target substrate behavior, frontend
  compatibility breadth, or cross-ISA migration behavior.
- **FR-015a**: Reusing artifact or migration package structures MUST NOT by
  itself satisfy artifact/profile gates, target execution claims, migration
  restoration claims, or cross-ISA portability claims.
- **FR-016**: Historical material under `docs/archive/achieve/` MAY be used as
  semantic background, but all active requirements, exclusions, and validation
  expectations MUST be restated in current Spec Kit artifacts before planning.

### Key Entities

- **Contract Core**: The stable effect language for vISA-visible semantic
  facts, not a runtime executor or frontend compatibility surface.
- **Object Reference**: A contract-visible identity consisting of object kind,
  identity, and generation.
- **Contract Edge**: A typed relation between semantic objects with live,
  historical, cleanup-effect, or external mode.
- **Command Transaction**: The visible mutation boundary that records
  preconditions, effects, events, status, and validation failures.
- **Event Evidence**: A stable record proving that a semantic effect became
  visible at an evidence boundary.
- **Stable View**: A read-only inspection record derived from contract state.
- **Validation Violation**: A structured rejection reason tied to a subject,
  relation, expected fact, and observed fact.
- **Evidence Boundary**: The weakest validated level that a claim may report.
- **Contract Evidence Carrier**: An existing artifact or migration
  package-shaped structure used to store Phase 2 contract facts, stable views,
  validation violations, and evidence-boundary metadata without upgrading the
  evidence claim.
- **Feature-Local Evidence Shape**: The current evidence layout used during
  Feature 002; it is validated for this feature but does not create a forward
  compatibility promise.
- **Phase 2 Semantic Family**: One of the semantic groups assigned to Contract
  Core Stabilization by Feature 001.
- **Phase 2 Coverage Unit**: A Phase 2-owned object kind, edge mode, command
  area, or state transition from object identity, generation, graph edges,
  capability authority, wait state, event evidence, trap attribution, cleanup,
  guest memory, stable views, or graph validation that must have positive and
  negative validation before Feature 002 can be complete.
- **Roadmap Deferral**: A deliberate exclusion of artifact/profile,
  frontend/personality, substrate-authority, or migration behavior from this
  feature unless represented only as generic contract evidence shape.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of Phase 2 coverage units have explicit contract facts,
  validation expectations, and positive and negative scenarios before the
  feature is considered complete.
- **SC-002**: A reviewer can classify proposed work as inside Phase 2 or
  deferred to a later roadmap phase in under 10 minutes using this spec and the
  Feature 001 baseline.
- **SC-003**: 100% of validation claims emitted by this feature name the
  weakest exercised evidence boundary and avoid stronger Phase 3-6 claims.
- **SC-004**: A valid contract evidence package can be reviewed without opening
  private runtime, frontend, substrate, or CLI formatting state.
- **SC-005**: A deliberately invalid contract evidence package containing
  stale generations, live tombstone ownership, cleanup-authority misuse,
  rejected-command mutation, or guest-memory substrate truth is rejected with
  structured reasons.
- **SC-006**: The implementation plan derived from this spec can proceed
  without asking whether artifact/profile gates, frontend compatibility,
  substrate hardware authority, or cross-ISA migration are part of this feature.

## Assumptions

- Feature 001 is the accepted baseline and roadmap fact source for this work.
- "Complete contract core" for this feature means complete Phase 2 Contract
  Core Stabilization, while the broader C direction remains a sequence of later
  Spec Kit features.
- Phase 2 coverage is intentionally exhaustive for the accepted contract-core
  surface; planning may split the work, but completion requires all coverage
  units to pass.
- Current contract-visible object kinds that are owned by later roadmap phases
  are excluded from exhaustive Feature 002 coverage unless they are needed only
  as generic evidence shapes for a Phase 2-owned unit.
- Feature 002 does not define a long-term schema compatibility policy for the
  Phase 2 evidence shape; later features may establish one if needed.
- Current code is evidence of existing structure and may be changed by the
  later implementation plan, but this specification does not bless private
  implementation details as semantic truth.
- The maximum evidence boundary for this feature is semantic model evidence
  with stable machine-readable records.
- Existing repository validation guidance will be selected during planning
  based on the files changed by implementation.
- Archived semantic-contract documents are historical background only; they do
  not define active workflow outside the current Spec Kit artifacts.
