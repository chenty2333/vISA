# Contract Graph Edges

Edges explain why one semantic object references another.

## Edge Modes

```text
Live
    Current authority, ownership, blocking, binding, or scheduling relation.

Historical
    Audit relation from trace, trap, hostcall, event, or tombstone evidence.

CleanupEffect
    Effect produced by cleanup. It must not become live ownership.

External
    Declared object outside the internal graph.
```

## Hard Rules

```text
Live edge cannot target tombstone.
Live edge cannot target dead Store or dead Activation.
Live edge generation must match target generation.
Historical edge may target dead/tombstoned generation.
CleanupEffect cannot authorize or keep an object live.
Dead Store cannot retain live activation/capability/wait ownership.
Dead Store may still appear in trap/hostcall/cleanup history.
```

## Review Smell

```text
same edge list mixes live and history without mode
trap or hostcall creates live ownership
cleanup effect is reused as authority
validator stops at first violation instead of reporting all
```
