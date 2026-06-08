# Hostcall Frame

`HostcallFrameV1` is the target/runtime wire ABI for privileged virtual ISA
operations. It is not an internal Rust helper call.

## Entry Convention

```text
a0 = HostcallFrameV1* frame
```

FakeAotBlob may pass:

```text
a1 = trampoline pointer
```

Real AOT resolves the trampoline through import/relocation metadata.

## Frame Must Carry

```text
magic/version/frame_len
hostcall id
caller Store ObjectRef
caller Activation ObjectRef
caller CodeObject ObjectRef
capability handle/ObjectRef when required
scalar args and return slots
status and reason
event epoch
scratch region metadata
```

## Validation

The executor derives and checks caller identity from active semantic state. It
must not trust frame-provided identity by itself.

Validate:

```text
frame pointer is non-null, aligned, and inside activation scratch
version and frame size
hostcall id exists in import table
caller Store/Activation/CodeObject generations are live
capability handle is live and authorized
argument shape matches hostcall signature
pending return does not leak forbidden leases
```

Denied, unsupported, invalid-frame, and generation-mismatch statuses are
contract-visible trace outcomes.

Hostcall trace evidence must carry:

```text
subject_source = active-store-activation-code-object
gate_status: exit / denied / trap
denial_reason when gate_status != exit
Store / Activation / CodeObject / Artifact generations
CapabilityHandle slot / generation / tag / rights evidence when present
```

An unsupported hostcall id is not a silent dispatch miss. It records an
`unsupported-call` hostcall trace, a hostcall trap, and an osctl-visible denial
reason.

## Review Smell

```text
hostcall subject comes from guest-provided frame only
capability args are debug trace fields
ABI mismatch returns Err without trap/trace evidence
hostcall returns Pending while retaining active DMW lease
```
