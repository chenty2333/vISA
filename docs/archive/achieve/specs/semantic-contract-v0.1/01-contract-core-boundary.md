# Contract Core Boundary

`contract_core` is the stable language of the Semantic Virtual ISA effect
ledger. It should be boring, small, and hard to misuse.

It is the encoding layer for vISA-visible effects, not the full vISA
specification and not a runtime implementation.

## Owns

```text
schema/version anchors
ObjectRef and typed ids
edge modes
view schemas
command/event record shapes
validation error codes
package/evidence schemas
```

## Does Not Own

```text
graph mutation
runtime execution
substrate traits
Wasmtime or .cwasm internals
osctl CLI behavior
adapter/private service state
```

## Rule

If a type is needed by `semantic_core`, `target_executor`, and `osctl` to agree
on identity or evidence, it belongs in `contract_core`.

If a type mutates state, calls hardware, formats CLI output, or stores private
runtime detail, it does not.

## Review Smell

```text
contract_core imports runtime crates
contract_core serializes private implementation structs
semantic_core exposes unstable records as stable views
target_executor invents ids not expressible as ObjectRef
```
