# Target Runtime Implementation Gates

Status: retained as a compact implementation boundary summary. Completed work
narratives do not belong in this spec.

Implementation work should preserve these gates:

```text
1. Artifact gate
   Parse TargetArtifactImage, validate section bounds, hashes, manifest hash,
   signature policy, and required sections before accepting payload bytes.

2. CodeObject gate
   Publish code only through the CodeObject lifecycle. Preserve W^X,
   immutability, generation, PcRange, and TrapMap registration.

3. Hostcall gate
   Enter services through HostcallFrame. Derive caller identity from active
   Store / Activation / CodeObject state and validate CapabilityHandle
   generation before dispatch.

4. Trap gate
   Attribute target PC to CodeObject offset and TrapMap entry. Unknown or stale
   code execution becomes a target fault.

5. Profile gate
   Compare artifact requirements with the current target profile before code
   runs. Unsupported required features reject the artifact.

6. Extraction gate
   osctl extraction is read-only, JSONL/framed, cursor-safe, and panic-safe.
   It must not allocate on panic paths, call Wasm, or mutate the graph.
```

Current tests pin these defaults:

```text
riscv64 QEMU virt research profile
FakeAotBlob exact RV64I stubs
canonical zero-field image hash plus per-section hashes
unsigned-research and dev-ed25519 signature shapes
target-to-host JSONL ViewV1
64 KiB panic ring with 4 KiB max records
single-hart local icache profile
```

Do not add external work plans or progress logs here. Sequencing belongs in the
current task prompt or issue tracker; this file only keeps runtime boundary
rules.
