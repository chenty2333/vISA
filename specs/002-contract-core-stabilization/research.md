# Research: Contract Core Stabilization

## Decision: Limit implementation scope to Phase 2-owned contract units

**Rationale**: Feature 001 assigns Phase 2 to object identity, generation,
graph edges, capability authority, wait state, event evidence, trap
attribution, cleanup, guest memory, stable views, and graph validation. The
user confirmed exhaustive coverage, then clarified that the exhaustive surface
is Phase 2-owned units only. This preserves the broad long-term "complete
contract core" direction without pulling in artifact/profile, personality,
substrate, or portability implementation.

**Alternatives considered**:
- Cover every current `ObjectKind` visible in code. Rejected because many
  kinds are owned by later roadmap phases or domain-specific experiments.
- Cover only already implemented tests. Rejected because it would allow known
  Phase 2 gaps to remain out of scope.

## Decision: Reuse existing artifact or migration package structures as the evidence carrier

**Rationale**: The user selected reuse of existing package-shaped structures
for stable machine-readable validation evidence. This keeps evidence close to
current repository mechanisms such as semantic snapshots, migration package
records, boundary reports, command results, and validation violations, while
still treating the carrier only as a Phase 2 contract evidence envelope.

**Alternatives considered**:
- Create a minimal new Contract Evidence Package. Rejected by clarification.
- Keep validation in memory only. Rejected by clarification and by the need for
  reviewer-inspectable evidence.

## Decision: Treat the Phase 2 evidence shape as feature-local

**Rationale**: The user selected a feature-local compatibility commitment:
evidence shape may change during Feature 002, and this feature will not define
a long-term post-completion schema compatibility policy. The implementation
plan must still validate the final feature shape, but later features may define
compatibility/versioning if needed.

**Alternatives considered**:
- Versioned additive stability. Rejected by clarification.
- Strict freeze after Feature 002. Rejected by clarification and too costly for
  an early contract-core stabilization slice.

## Decision: Require exhaustive positive and negative coverage for Phase 2 coverage units

**Rationale**: The user selected exhaustive semantic coverage. The design
therefore models a coverage unit as each Phase 2-owned object kind, edge mode,
command area, or state transition. Every unit must have a positive validation
scenario and a negative validation scenario before completion.

**Alternatives considered**:
- One positive and one negative scenario per semantic family. Rejected by
  clarification as too weak.
- Target only named invariants. Rejected by clarification as insufficiently
  exhaustive.

## Decision: Preserve current crate ownership boundaries

**Rationale**: Current code already separates stable effect language
(`contract_core`), in-memory semantic ledger and graph validation
(`semantic_core`), package and compatibility validation (`contract_validate`),
and package-shaped records (`artifact_manifest`). The plan should strengthen
this shape rather than move runtime execution, substrate traits, frontend
semantics, or CLI formatting into contract core.

**Alternatives considered**:
- Move graph mutation into `contract_core`. Rejected because archived boundary
  notes and current crate docs state that `contract_core` is an encoding layer,
  not a state mutator.
- Let `contract_validate` define semantic policy. Rejected because validation
  should check stable contract facts, not create a parallel semantic source of
  truth.

## Decision: Use semantic-model evidence as the strongest Phase 2 claim

**Rationale**: Feature 002 validates the semantic model with
machine-readable records. It may reuse artifact or migration package-shaped
carriers, but it does not exercise artifact/profile gates, portable artifact
execution, real target substrate behavior, frontend compatibility breadth, or
cross-ISA migration restoration.

**Alternatives considered**:
- Claim reference artifact harness evidence because package-shaped carriers
  are reused. Rejected because carrier reuse is not execution evidence.
- Claim migration behavior because migration package structures are reused.
  Rejected because Phase 6 semantics remain out of scope.

## Decision: Validate with focused core crate tests and Docker gates when parity matters

**Rationale**: Implementation will affect core Rust crates and potentially
conformance-facing package records. Focused cargo tests should validate local
logic quickly. Docker validation from `docs/DOCKER.md` becomes required when
changed files or conformance claims need workspace parity, target components,
or the `visa-conformance` gate.

**Alternatives considered**:
- Host-only validation for all changes. Rejected when parity-sensitive crates
  or conformance evidence are touched.
- Full Docker gate for every edit. Rejected as unnecessary for narrow
  documentation-only changes, but appropriate for Rust implementation tasks.

## Decision: Defer later roadmap behavior even when evidence shapes reference it

**Rationale**: Artifact/profile gates, frontend/personality normalization,
substrate authority, and migration portability remain later roadmap phases.
Feature 002 may model generic evidence shapes that mention those domains, but
must not report their behavior as completed.

**Alternatives considered**:
- Implement Phase 2 through Phase 6 as one feature. Rejected because it would
  erase evidence boundaries and make completion untestable.
