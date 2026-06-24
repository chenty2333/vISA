# Phase 0 Research: Semantic Baseline Roadmap

## Decision: Phase 1 remains documentation and validation only

**Rationale**: The feature spec explicitly requires the first implementable
increment to establish the accepted baseline, roadmap, evidence taxonomy, and
traceability before code implementation begins. This avoids mixing roadmap
agreement with runtime changes and keeps downstream task generation narrow.

**Alternatives considered**:
- Implement runtime behavior immediately: rejected because it would bypass the
  accepted Phase 1 scope and increase semantic drift risk.
- Create a new validation harness first: rejected because the clarified Phase 1
  answer requires existing repository checks, not new runtime or harness work.

## Decision: Phase 1 evidence boundary is source-backed semantic review plus applicable checks

**Rationale**: The clarified spec selects source-backed traceability plus
existing repository checks appropriate to changed artifacts. This satisfies
Evidence Before Claims without overstating portable artifact execution or real
substrate evidence.

**Alternatives considered**:
- Source-backed review only: rejected because it would not exercise the
  existing repository checks required by the clarification.
- Portable artifact execution: rejected because it belongs to later roadmap
  phases and would incorrectly expand Phase 1.

## Decision: Archived material is background, not a workflow source

**Rationale**: The constitution and spec both state that `docs/archive/` is
historical background. The active planning path must therefore extract stable
semantic ideas while leaving old workflow/task structures behind.

**Alternatives considered**:
- Copy archived workflow sections into current planning: rejected because it
  conflicts with Spec Kit First and the user's explicit instruction.
- Ignore archived material entirely: rejected because the feature requires
  extracting stable semantic boundaries from the archive.

## Decision: Use a Markdown artifact contract instead of an API schema

**Rationale**: Phase 1 exposes a package of planning artifacts to maintainers
and future Spec Kit commands, not a runtime API, network endpoint, or library
interface. A Markdown contract can state required artifacts, scope exclusions,
validation expectations, and traceability rules without inventing an
implementation surface.

**Alternatives considered**:
- OpenAPI or protocol contract: rejected because there is no service endpoint.
- Rust trait or crate API contract: rejected because no runtime code is in
  scope for Phase 1.

## Decision: Validation guide distinguishes documentation checks from Docker gates

**Rationale**: `docs/DOCKER.md` is the authoritative Docker validation guide
when Rust, Cargo, kernel, or parity-relevant files change. For this docs-only
baseline, the applicable checks are artifact presence, unresolved-marker scans,
`AGENTS.md` pointer verification, scope drift detection, and `git diff --check`.

**Alternatives considered**:
- Always run full Docker gates for Phase 1: rejected as disproportionate for
  documentation-only changes.
- Never mention Docker gates: rejected because the constitution prefers Docker
  validation paths when parity matters.

## Decision: Roadmap ownership is phase and semantic-family based

**Rationale**: The roadmap needs to classify future work by semantic boundary,
layer, phase, and evidence level. A phase/family ownership model keeps Linux,
WASI, substrate, artifact, and migration work from being treated as generic
compatibility breadth.

**Alternatives considered**:
- Organize by crate names only: rejected because crate structure can change and
  does not by itself define semantic ownership.
- Organize by guest interface breadth: rejected because frontend breadth is not
  the vISA system center.

## Decision: Phase 1 traceability is claim-level and source-backed

**Rationale**: The clarified Phase 1 validation level requires source-backed
traceability plus existing repository checks appropriate to changed artifacts.
The implementation therefore records every accepted semantic claim against one
or more current code anchors, archived sources explicitly treated as historical
background, or documented assumptions. This makes the baseline reviewable
without promoting archived workflow text into the active process.

**Alternatives considered**:
- Path inventory only: rejected because a list of files does not prove which
  semantic claims each source supports.
- Runtime proof first: rejected because Phase 1 explicitly excludes new runtime
  behavior and stronger validation harness work.
