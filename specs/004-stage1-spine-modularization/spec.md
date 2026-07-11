# Feature Specification: Stage 1 Spine Modularization

Status: accepted

This maintenance slice makes the completed Stage 1 production spine physically
match its accepted ownership boundaries before an independent runtime adapter is
added. It changes source organization, not capability, schema, behavior, or
claims.

## Scope

- Split `visa-system` runner transport, registry, provenance, orchestration,
  harness, scenarios, finalization, and artifact derivation into private
  modules behind the existing `visa_system::runner` public surface.
- Split `semantic_core` preflight, transition, authority, effect, handoff,
  timer, restore, replay, and tests into private modules behind the existing
  crate-root API.
- Remove obsolete repository-local agent instructions and keep the repository
  free of generated workflow integrations and project-local skill trees.
- Make the Rust file-size maintenance check operate on tracked first-party
  sources and report the active Stage 1 spine separately from oracle/reference
  code.

## Requirements

- **FR-001**: `contract_core` remains the only portable schema owner.
- **FR-002**: `semantic_core` remains one reducer authority with one exhaustive
  `CommandKind` dispatcher and one exhaustive `EventKind` transition path.
- **FR-003**: Existing crate-root `semantic_core` and
  `visa_system::runner` public paths continue to compile.
- **FR-004**: No command, event, state, snapshot, journal, worker protocol,
  evidence schema, profile, or digest algorithm changes.
- **FR-005**: All 31 Stage 1 case IDs, outcomes, normalized traces,
  state/replay digests, authority/fencing results, fault schedules, and
  assertions remain semantically identical.
- **FR-006**: Source provenance, bundle IDs, timestamps, process IDs, and whole
  bundle hashes may change because source paths and run identities change.
- **FR-007**: Runner modules only orchestrate, observe, audit, and derive
  evidence; they cannot become a semantic write authority.
- **FR-008**: No new public module tree, generic scenario framework, reducer
  plugin, duplicate schema, or compatibility workaround is introduced.
- **FR-009**: Local and Docker `full` and `system` gates pass after the move.

## Non-goals

- Adding a second runtime, resource profile, ISA, transport, or security
  profile.
- Changing Stage 1 behavior or widening its public claim.
- Refactoring isolated oracle, kernel, Linux personality, or later-stage
  reference implementations.
- Restoring `.specify/`, `.agents/`, OpenSpec, or project-local skill
  integrations.

## Completion Rule

The slice is complete only when the two large files are replaced by bounded
private modules, compatibility paths remain intact, all focused tests and
no-std checks pass, the 31-case system bundle passes the independent verifier,
Docker agrees, and the final diff contains no semantic or evidence-contract
change.
