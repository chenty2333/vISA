# Execution Policy

## Purpose

This policy keeps agent work continuous, scoped, and complete.

Task files are for maintaining live working state across context drift.  
They are not logs.

## Execution plan

For each non-trivial task, create or update a task file under:

`tasks/active/`

The active task file should maintain these live fields:

- Goal
- Accepted Scope
- Current Plan
- Progress
- Next Actions
- Risks

These fields describe the current state of the task.  
Edit them in place instead of appending routine history.

When the task is complete, compress the final state into a short result and move the file to:

`tasks/done/`

## Scope rule

Work should complete the accepted scope.

Do not silently reduce scope.  
If scope changes, update `Accepted Scope`, `Next Actions`, or `Risks`.

Do not use placeholder, toy, or partial implementations as completion unless the task is explicitly a spike.

## Progress rule

After each meaningful work chunk, update the active task file only when one of these changed:

- current progress
- next actions
- risks
- accepted scope

Do not record routine command output or mechanical steps unless they affect future work.

## Context-drift rule

Before resuming work, read the active task file.

Continue from `Next Actions`.

If `Next Actions` is stale, rewrite it before continuing.

## Completion rule

A task is complete when:

- accepted scope is done;
- remaining risks are stated;
- verification confidence is recorded somewhere appropriate.

The final task result should be brief.
