# Unsupported Events And Conformance

Unsupported machine authority must be observable. A missing trait or operation
is not just a Rust error.

## Required Shape

```text
authority name
operation name
subject artifact/store/activation when known
capability or requested object when known
reason
event id
osctl-visible view
```

## Conformance

A substrate port should prove:

```text
reports a precise capability set
returns Unsupported for absent optional authorities
rejects missing required authorities at load time
emits semantic events for runtime unsupported use
does not require rewriting personality semantics
```

## Review Smell

```text
Unsupported is swallowed by adapter
osctl cannot explain why artifact did not start
conformance tests only check happy path
```
