# Historical Archive: Migration Notes

Status: historical entry only.

The old migration note described how to move from a native Rust kernel-shaped
prototype toward the vISA layering. The stable version of that decision is now:

```text
semantic_core
    owns semantic truth and verification.

target_executor
    bridges artifact/runtime ABI events to semantic effects.

substrate_api
    exposes backend machine authority as traits.

osctl
    renders stable read-only views.
```

For current migration and refactor work, use:

```text
references/vision/semantic-virtual-isa.md
references/specs/semantic-contract-v0.1/00-overview.md
references/specs/substrate-api-v0/00-overview.md
references/specs/target-runtime-abi/00-overview.md
```

Local full-text snapshot for this cleanup pass:

```text
/home/dia/.codex/tmp/visa-reference-archive-20260429/archive/migration.md
```
