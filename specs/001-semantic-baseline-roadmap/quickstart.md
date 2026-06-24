# Quickstart: Validate Phase 1 Semantic Baseline Package

This guide validates the Phase 1 planning package. It does not build or run
vISA runtime behavior.

## Prerequisites

- Run commands from the repository root: `/home/ava/Desktop/vISA`.
- Use the active feature directory:
  `specs/001-semantic-baseline-roadmap/`.
- Use Docker gates from `docs/DOCKER.md` only when later tasks touch Rust,
  Cargo, kernel, substrate, or parity-relevant files.

## 1. Verify Required Artifacts Exist

```sh
test -f specs/001-semantic-baseline-roadmap/spec.md
test -f specs/001-semantic-baseline-roadmap/plan.md
test -f specs/001-semantic-baseline-roadmap/research.md
test -f specs/001-semantic-baseline-roadmap/data-model.md
test -f specs/001-semantic-baseline-roadmap/contracts/semantic-baseline-package.md
test -f specs/001-semantic-baseline-roadmap/quickstart.md
test -f specs/001-semantic-baseline-roadmap/tasks.md
test -f specs/001-semantic-baseline-roadmap/checklists/requirements.md
```

Expected outcome: every command exits successfully.

## 2. Verify Agent Context Points To This Plan

```sh
rg -n "specs/001-semantic-baseline-roadmap/plan.md" AGENTS.md
```

Expected outcome: one match inside the managed Spec Kit block.

## 3. Check For Unresolved Template Or Clarification Markers

```sh
if rg -n \
  -e 'NEEDS CLARIFICATION' \
  -e 'ACTION REQUIRED' \
  -e 'TODO' \
  -e 'TBD' \
  -e '\[FEATURE NAME\]' \
  -e '\[DATE\]' \
  -e '\[###' \
  -e '\$ARGUMENTS' \
  specs/001-semantic-baseline-roadmap/spec.md \
  specs/001-semantic-baseline-roadmap/plan.md \
  specs/001-semantic-baseline-roadmap/research.md \
  specs/001-semantic-baseline-roadmap/data-model.md \
  specs/001-semantic-baseline-roadmap/tasks.md \
  specs/001-semantic-baseline-roadmap/contracts \
  AGENTS.md; then
  exit 1
fi
```

Expected outcome: no matches and exit status 0.

## 4. Check Phase 1 Scope Has Not Drifted Into Runtime Code

```sh
if git status --short --untracked-files=all | awk '{print $2}' | rg '^(crates/|scripts/|Dockerfile|Cargo\\.toml|Cargo\\.lock|compose)'; then
  echo "Phase 1 scope drift: runtime or build files changed"
  exit 1
fi
```

Expected outcome: no matches and exit status 0 for the Phase 1 baseline
package.

## 5. Check Whitespace On Changed Artifacts

```sh
git diff --check -- \
  specs/001-semantic-baseline-roadmap \
  .specify/feature.json \
  AGENTS.md
```

Expected outcome: no output and exit status 0.

## 6. Re-run Stronger Repository Gates Only When Needed

If a later task expands scope beyond documentation or agent context files, use
the Docker validation commands documented in `docs/DOCKER.md`, for example:

```sh
scripts/run-docker-ci-gate.sh metadata fmt
```

Expected outcome: all selected gates print `ok:` lines. This is not required
for the current docs-only Phase 1 package unless the implementation scope
changes.
