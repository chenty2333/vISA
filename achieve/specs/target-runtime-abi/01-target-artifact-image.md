# Target Artifact Image

`TargetArtifactImage` is the only target-loadable artifact envelope. Do not load
naked `.cwasm`, Wasmtime serialized modules, or native code blobs.

## Envelope Owns

```text
fixed header
section table
manifest section
contract metadata
code payload section
hostcall import table
PcRange / TrapMap sections
profile requirements
hash and signature metadata
```

## Required Validation

```text
magic and schema
section bounds and alignment
required section set
per-section hashes
canonical zero-field image hash
manifest hash
profile requirements
signature policy
unsupported relocation rejection
```

## FakeAotBlob

Reference AOT payload exists to validate the runtime boundary without depending
on real Wasmtime target execution.

It contains:

```text
FakeAotHeader
EntryTable
HostcallStubTable
TrapStubTable
CodeBytes
PcRangeTable
TrapMap
DebugLite
```

Pinned RV64I stubs:

```text
entry_return_ok:
    13 05 00 00
    67 80 00 00

entry_hostcall_tail:
    67 80 05 00

entry_trap_ebreak:
    73 00 10 00
```

`entry_hostcall_tail` uses `a0 = HostcallFrameV1*` and fake-only
`a1 = trampoline_ptr`. Real AOT must use HostcallImportTable plus loader-owned
import/relocation handling.

## Relocation Boundary

Default profile supports only data patches into non-code sections:

```text
U64LeAbs
U32LeAbs
```

Code patching and complex RISC-V relocations are rejected with
`UnsupportedRelocation`.

The ABI still names:

```text
ImportDescriptorV1
RelocationEntryV1
```

so real AOT support can be added without changing the envelope concept.

## Signature Boundary

Unsigned research artifacts are allowed only when policy says signature
enforcement is disabled. They may be hash-verified, but must not be reported as
signature-verified.

Dev signatures use Ed25519 shape:

```text
public key = 32 bytes
signature = 64 bytes
```

## Review Smell

```text
loader trusts payload format directly
signature section missing from artifact shape
image hash ignores section table or offsets
unsigned artifact shown as verified
code section patched by fake loader
```
