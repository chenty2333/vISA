# Documentation Policy

## Purpose

Long-lived docs preserve durable project knowledge.

They are not task logs.

## Routing

Use task files for temporary working state.

Use long-lived docs only for information that should survive the task:

- `docs/DECISIONS.md`: durable decisions
- `docs/ASSUMPTIONS.md`: assumptions future work may rely on
- `docs/EVIDENCE.md`: verification conclusions worth preserving
- `docs/DEBUG.md`: reusable debugging observations
- `docs/BUG_HISTORY.md`: bugs likely to recur or teach a contract lesson
- `docs/PROPOSALS.md`: valuable ideas outside current accepted scope

## Writing style

Write the shortest entry that preserves the useful information.

Prefer facts, decisions, risks, and next actions.

Avoid routine history, repeated context, command dumps, and explanation that does not change future work.
