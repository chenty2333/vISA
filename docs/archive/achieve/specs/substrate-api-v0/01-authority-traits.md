# Authority Traits

Substrate traits are small machine-authority providers. Do not define one giant
`Substrate` trait.

## Trait Families

```text
ConsoleAuthority
TimerAuthority
EventQueueAuthority
GuestMemoryAuthority
DmwAuthority
ArtifactAuthority
CodePublishAuthority
MmioAuthority
DmaAuthority
IrqAuthority
SnapshotAuthority
OsctlExtract
TargetLogSink
TargetAllocator
```

## Rules

```text
default unsupported behavior is explicit
trait availability is not permission
capability checks happen before trait calls
generation checks happen before trait calls
errors become semantic events when externally visible
```

## Review Smell

```text
driver can use DMA because DmaAuthority exists
Wasm artifact depends on Rust trait ABI
unsupported operation is silent Err only
machine authority trait encodes Linux/WASI policy
```
