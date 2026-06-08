# Artifact Execution Model

The Semantic Virtual ISA executes artifacts through target-runtime objects that
make identity, attribution, capability, and trap behavior explicit.

## Loadable Unit

`TargetArtifactImage` is the only target-loadable unit. It binds payload bytes,
manifest facts, profile requirements, section hashes, signature status, and
schema version.

```text
package
  -> TargetArtifactImage
  -> CodeObject
  -> Store
  -> Activation
```

Package verification creates a load plan only. It does not publish code, enter a
Store, or call substrate traits.

## Code Publish

Code publication creates a `CodeObject` with generation, immutable published
bytes, PcRange records, and TrapMap attribution. W^X and icache synchronization
are target-runtime/substrate responsibilities, but their effects must be
visible to the contract ledger.

Changing executable bytes creates a new CodeObject generation. Published code is
never mutated in place.

## Hostcall Path

```text
Activation
  -> HostcallFrame
  -> caller identity check
  -> capability handle generation check
  -> Semantic Virtual ISA operation
  -> EventLog / contract graph effect
  -> optional substrate_api trait call
```

`HostcallFrame` is a wire ABI. It is not a Rust helper-call convention and not a
frontend ABI. It carries enough stable information to attribute a privileged
operation to Store, Activation, CodeObject, capability handle, and scratch
memory state.

## Trap Path

```text
target PC
  -> PcRange
  -> TrapMap
  -> CodeObject offset
  -> TrapRecord
  -> historical refs to Store / Activation / CodeObject
```

Unknown PC, stale code, bad attribution, or hostcall frame mismatch becomes a
target/runtime fault with contract-visible evidence.

## Boundary To Child Specs

The detailed binary layout and status codes live in `../target-runtime-abi/`.
The detailed effect encoding and validation rules live in
`../semantic-contract-v0.1/`. The substrate trait calls live in
`../substrate-api-v0/`.

## Review Smells

```text
naked Wasm/.cwasm/native blob is loaded as if it were a vISA artifact
hostcall bypasses HostcallFrame attribution
trap uses raw target PC without TrapMap edge
capability handle omits object generation
published code is mutated in place
package verification directly executes code or calls hardware
```
