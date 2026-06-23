# no_std Control Plane

Target execution must be inspectable without `std`, a filesystem, or reliable
heap allocation.

## Boundaries

```text
TargetAllocator
    allocation by class: metadata, graph, event log, code staging, guest memory,
    DMW metadata, DMA metadata.

TargetLogSink
    EventLog is stable evidence; DebugLog is not.

Panic path
    may write minimal emergency records and halt/rescue.
    must not allocate, call Wasm, run normal osctl serialization, or mutate
    arbitrary graph state.
```

## JSONL Extraction

Default bridge:

```text
target-to-host only
one complete JSON object per line
no raw text mixed into the channel
normal max line = 16 KiB
hard max line = 64 KiB
panic max line = 4 KiB
```

Cursor string:

```text
v1:e=17:s=event-log:q=42:ev=900:v=12
```

Rules:

```text
cursor advances only after complete frame write
truncated frame does not advance cursor
panic-ring dump does not advance event-log cursor
oversized output emits truncated-frame-v1, never partial JSON
```

## Panic Ring

```text
ring size = 64 KiB
alignment = 4 KiB
max record = 4 KiB
overwrite oldest when full
increment lost_count for overwritten records
oversized record becomes TruncatedPanicRecord
no allocation
no Wasm calls
no graph mutation
```

Records are committed after payload and crc32 are written. Dump skips
uncommitted or corrupt records and reports them.

## Review Smell

```text
debug text treated as evidence
panic path allocates or calls Wasm
osctl extraction mutates graph
JSONL frame can be partially emitted
cursor advances after truncated frame
```
