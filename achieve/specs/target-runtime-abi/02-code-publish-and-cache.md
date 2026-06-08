# Code Publish And Cache

CodeObject publication turns verified payload bytes into executable target
identity.

## State Machine

```text
Parsed
AllocatedWritable
Copied
Relocated
PublishedRx
Registered
Live
Retired
Tombstoned
```

## Rules

```text
never RWX
published code is immutable
changes create a new CodeObject generation
retired code remains historically referencable
retired code cannot be a live call target
PcRange and TrapMap register before code becomes live
I-cache sync is part of CodePublishAuthority
```

Single-hart fake/reference targets may no-op cache maintenance only because the
profile says so. Real targets must implement architecture-specific publish and
cache rules.

## Review Smell

```text
payload bytes become executable without CodeObject record
live activation points at retired CodeObject
publish path skips TrapMap registration
cache sync is hidden instead of profile-visible
```
