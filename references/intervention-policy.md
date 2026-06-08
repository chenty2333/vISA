# Intervention Policy

## Purpose

This policy decides when the agent should proceed, record, propose, or involve the user.

The agent should own most engineering decisions.

User involvement is reserved for decisions that change project intent, core semantics, security boundaries, or long-term direction.

## Default

Proceed without asking when the decision stays inside the accepted scope and preserves existing semantic intent.

This includes local APIs, helper APIs, module APIs, naming, layout, refactoring, test structure, instrumentation, implementation strategy, and ordinary bug fixes.

Do not stop just because there are multiple reasonable implementation choices.

## Record

Record the decision in the active task file when it may matter later.

Use long-lived docs only when the decision is durable beyond the current task.

## Strengthen evidence

If the change affects observable behavior but still preserves existing intent, proceed and strengthen verification.

This applies to runtime behavior around artifact, activation, hostcall, trap, wait, cleanup, authority, capability, generation, lifetime, or profile behavior.

Do not ask the user merely because the change is important.  
First try to make the result trustworthy through tests, contract checks, traces, or other evidence.

## Propose

Create a proposal when the agent discovers a valuable idea outside the accepted scope.

A proposal is appropriate when the idea introduces a new concept, changes a milestone, adds a major subsystem, or changes how future work should be organized.

Do not silently merge proposal-level ideas into normal implementation work.

## Ask

Ask the user only when proceeding would change one of these:

- project direction
- core vISA semantic contract
- authority model
- capability meaning
- lifetime or generation semantics
- artifact identity semantics
- trap, wait, or cleanup contract
- security boundary
- persistent format
- long-term roadmap

## Uncertainty rule

When unsure, prefer this order:

1. continue with stronger evidence;
2. record the decision;
3. write a proposal;
4. ask the user.

Do not use uncertainty as a reason to stop on local engineering choices.
