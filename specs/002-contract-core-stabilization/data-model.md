# Data Model: Contract Core Stabilization

## Contract Core

**Purpose**: Stable effect language for vISA-visible semantic facts.

**Fields**:
- `schema_anchor`: current semantic contract schema/version identifier.
- `object_ref_language`: object kind, identity, and generation rules.
- `edge_modes`: live, historical, cleanup-effect, and external relation modes.
- `command_result_language`: command id, issuer, status, effects, events, and
  violations.
- `event_evidence_language`: stable event and evidence-boundary records.
- `view_language`: stable read-only views and validation views.
- `violation_language`: structured validation failure records.
- `evidence_boundary_language`: weakest exercised evidence boundary.

**Relationships**:
- Uses Object References, Contract Edges, Command Transactions, Event Evidence,
  Stable Views, Validation Violations, and Evidence Boundaries.
- Is consumed by Semantic Ledger behavior and Contract Validation.

**Validation rules**:
- Must not own graph mutation, runtime execution, substrate trait behavior,
  frontend ABI behavior, artifact execution mechanics, or CLI formatting.
- Must expose enough stable structure for later validation and review without
  private runtime state.

## Object Reference

**Purpose**: Contract-visible identity for semantic objects.

**Fields**:
- `kind`: stable semantic object kind.
- `id`: nonzero object identity.
- `generation`: nonzero internal generation.
- `evidence_boundary`: weakest evidence level supporting the reference.

**Relationships**:
- Appears in Contract Edges, Command Transactions, Event Evidence, Stable
  Views, Validation Violations, and Contract Evidence Carriers.

**Validation rules**:
- Internal object references with `id = 0` reject.
- Internal object references with missing or zero generation reject.
- References must not imply authority unless paired with capability evidence.

**State transitions**:
- `unknown` -> `live` when recorded by accepted contract evidence.
- `live` -> `historical` when retired, tombstoned, or preserved as audit
  evidence.
- `live` -> `rejected` when generation or identity validation fails.

## Contract Edge

**Purpose**: Explains why one semantic object references another.

**Fields**:
- `from`: source Object Reference.
- `to`: target Object Reference or declared external target.
- `mode`: live, historical, cleanup-effect, or external.
- `label`: semantic relationship.
- `epoch`: ordering point.
- `evidence_boundary`: weakest boundary supporting the edge.

**Relationships**:
- References Object References.
- Produces Validation Violations when invariant checks fail.

**Validation rules**:
- Live edges cannot target tombstones, dead stores, dead activations, stale
  generations, or missing objects.
- Historical edges must preserve exact generation.
- Cleanup-effect edges cannot create authority or live ownership.
- External edges require declared external object metadata.

## Command Transaction

**Purpose**: Visible mutation boundary for semantic effects.

**Fields**:
- `command_id`: nonzero command identity.
- `issuer`: semantic issuer label.
- `command_area`: Phase 2-owned command area.
- `preconditions`: required facts before mutation.
- `effects`: contract-visible effects.
- `events`: emitted event identities.
- `postconditions`: required facts after mutation.
- `status`: applied, noop, or rejected.
- `violations`: structured rejection reasons.

**Relationships**:
- Uses Object References and Contract Edges.
- Emits Event Evidence and Stable Views.
- Produces Validation Violations.

**Validation rules**:
- Failed preconditions leave semantic state unchanged.
- Rejected commands must expose structured reasons.
- Applied commands must have event evidence and postcondition checks when they
  mutate semantic state.

**State transitions**:
- `submitted` -> `applied` when preconditions, mutation, events, and
  postconditions pass.
- `submitted` -> `noop` when the command is valid but changes no semantic
  state.
- `submitted` -> `rejected` when preconditions fail; no state mutation occurs.

## Event Evidence

**Purpose**: Machine-readable proof that a semantic effect became visible.

**Fields**:
- `event_id`: stable event identity.
- `kind`: event family.
- `subject`: affected Object Reference.
- `epoch`: ordering point.
- `evidence_boundary`: weakest boundary supporting the event.
- `claim_limit`: strongest behavior claim allowed by the event.

**Relationships**:
- Linked from Command Transactions and Stable Views.
- Stored in Contract Evidence Carriers.

**Validation rules**:
- Prose logs, debugger output, benchmark output, and CLI formatting are not
  sufficient event evidence.
- Events that mention later roadmap domains must still name semantic-model
  evidence unless stronger evidence is actually exercised by a later feature.

## Stable View

**Purpose**: Read-only inspection record derived from contract state.

**Fields**:
- `view_schema`: view schema identifier.
- `subject`: viewed Object Reference or validation report.
- `state`: semantic state string or typed state.
- `references`: Contract Edges visible through the view.
- `last_transition`: optional semantic transition name.
- `last_error`: optional structured error summary.

**Relationships**:
- Derived from Object References, Contract Edges, Command Transactions, and
  Validation Violations.
- May be carried by package-shaped evidence.

**Validation rules**:
- Must not expose unstable private runtime fields as semantic truth.
- Must remain sufficient for review of Phase 2 claims.

## Validation Violation

**Purpose**: Structured reason for rejecting invalid contract evidence.

**Fields**:
- `kind`: violation code.
- `subject`: Object Reference or edge under review.
- `relation`: relationship being validated.
- `expected`: expected semantic fact.
- `actual`: observed semantic fact.
- `severity`: validation severity.
- `message`: short reviewer-facing explanation.

**Relationships**:
- Produced by Contract Edge, Command Transaction, Guest Memory, Cleanup, Wait,
  Capability, Trap, Stable View, and Graph Validation checks.

**Validation rules**:
- Validation must expose all independently detectable violations, not only the
  first failure.
- Violation reasons must be machine-readable enough to support negative
  validation scenarios.

## Evidence Boundary

**Purpose**: Weakest exercised level a claim may report.

**Fields**:
- `level`: semantic model, reference service, reference artifact harness,
  portable artifact execution, or real target substrate.
- `stable_roots`: records or checks supporting the level.
- `claim_limit`: maximum claim allowed by the level.
- `exclusions`: stronger behaviors not proven.

**Relationships**:
- Attached to Object References, Contract Edges, Event Evidence, Stable Views,
  Validation Violations, and Contract Evidence Carriers.

**Validation rules**:
- Feature 002 claims must not exceed semantic-model evidence.
- Carrier reuse must not upgrade evidence to artifact/profile, substrate,
  frontend, or migration behavior.

## Contract Evidence Carrier

**Purpose**: Existing artifact or migration package-shaped structure reused to
store Feature 002 machine-readable contract evidence.

**Fields**:
- `carrier_kind`: artifact-shaped or migration-shaped.
- `feature_id`: Feature 002 identifier.
- `evidence_shape_status`: feature-local.
- `contract_facts`: object refs, edges, commands, events, views, violations,
  and evidence boundaries.
- `coverage_matrix`: Phase 2 Coverage Units with positive and negative
  scenarios.
- `overclaim_guards`: exclusions for Phase 3 through Phase 6 behavior.

**Relationships**:
- Contains Event Evidence, Stable Views, Validation Violations, and the Phase 2
  Coverage Matrix.
- References artifact or migration package structures as a carrier only.

**Validation rules**:
- Must not imply artifact execution, profile-gate completion, migration
  restoration, cross-ISA portability, real substrate behavior, or frontend
  compatibility.
- Evidence shape may change during Feature 002 and does not define a long-term
  compatibility policy.

**State transitions**:
- `draft` -> `current` while Feature 002 implementation iterates.
- `current` -> `validated` when all Phase 2 coverage units pass.
- Earlier draft shapes are not compatibility commitments.

## Phase 2 Coverage Unit

**Purpose**: Exhaustive validation unit for Feature 002 completion.

**Fields**:
- `unit_id`: stable planning identifier.
- `family`: Phase 2 semantic family.
- `surface`: object kind, edge mode, command area, or state transition.
- `positive_scenario`: accepted evidence scenario.
- `negative_scenario`: rejected evidence scenario.
- `carrier_location`: package-shaped evidence location.
- `status`: uncovered, positive-only, negative-only, covered, or deferred.
- `deferral_reason`: only allowed when the unit is not Phase 2-owned.

**Relationships**:
- Belongs to one Phase 2 Semantic Family.
- Produces Contract Evidence Carrier records.
- Supports Success Criteria `SC-001`.

**Validation rules**:
- Every Phase 2-owned unit must have positive and negative scenarios before
  completion.
- Units owned by later roadmap phases are excluded unless needed only as
  generic evidence shapes for a Phase 2-owned unit.

**State transitions**:
- `uncovered` -> `positive-only` when accepted evidence exists.
- `uncovered` -> `negative-only` when rejected evidence exists.
- `positive-only` or `negative-only` -> `covered` when both exist.
- `uncovered` -> `deferred` only when roadmap ownership is outside Phase 2.

## Phase 2 Coverage Matrix

| Family | Owned surfaces | Required positive evidence | Required negative evidence |
|--------|----------------|----------------------------|----------------------------|
| Object identity | Object kind, id, generation, tombstone/historical identity | Valid nonzero identity and generation | Zero identity, missing generation, stale generation |
| Generation | Current vs historical generation-bearing refs | Matching generation and exact historical refs | Live stale generation, historical edge without exact generation |
| Graph edges | Live, historical, cleanup-effect, external | Valid relation by mode | Live tombstone target, cleanup authority misuse, missing external declaration |
| Capability authority | Grant, delegate, attenuate, revoke, stale handle rejection | Ledger-backed authority and provenance | Guessed id authority, stale/revoked/amplified capability |
| Wait state | Create, pending, resolve, cancel, restart, resume | Event-visible wait lifecycle | Invisible block, cancelled resume, owner-generation mismatch |
| Event evidence | Event ids, epochs, event kinds, claim limits | Event-backed semantic effect | Prose/debug/CLI-only evidence |
| Trap attribution | Semantic trap attribution records | Attributed trap evidence at semantic-model level | Raw target PC or artifact TrapMap claim without Phase 3 evidence |
| Cleanup | Begin, step, commit, idempotence, tombstone, effects | Generation-safe cleanup with stable digest/effects | Cleanup mutates new generation or leaves live leaks |
| Guest memory | GuestAddressSpace, VmaRegion, PageObject, operations | Semantic object-state memory evidence | Page table, DMW, TLB, host pointer, stale VMA/Page generation as truth |
| Stable views | Read-only view and validation view records | View exposes sufficient contract facts | View exposes private runtime state or hides validation failure |
| Graph validation | Batch validation and violation collection | All valid facts accepted | Independent violations are all reported |

## Roadmap Deferral

**Purpose**: Explicitly keeps later roadmap behavior out of Feature 002.

**Fields**:
- `deferred_phase`: Phase 3, 4, 5, or 6.
- `deferred_surface`: artifact/profile, frontend/personality, substrate, or
  portability behavior.
- `allowed_feature_002_use`: generic contract evidence shape only.
- `disallowed_claim`: behavior claim not allowed in this feature.

**Validation rules**:
- Artifact/profile gates, target execution claims, frontend compatibility
  breadth, real substrate behavior, and migration restoration claims must be
  rejected during Feature 002 review.
