# Semantic Virtual ISA Architecture

Status: narrative summary. The normative system spec lives in
`../specs/semantic-virtual-isa-v0/00-overview.md`.

vISA is:

```text
a cross-ISA Semantic Virtual ISA for portable system semantics
```

Wasm is the base execution virtual ISA. vISA extends that execution substrate
with authority, capability, generation, lifetime, wait, event, trap, cleanup,
artifact identity, hostcall attribution, and target profile semantics.

This is closer to `kernel-as-virtual-ISA` than to a traditional kernel-as-ABI
design. vISA artifacts target the Semantic Virtual ISA. Optional frontend
personalities such as Linux ELF, WASI, JS/runtime ABIs, driver kits, debuggers,
or snapshot services adapt guest-visible behavior into the same vISA operation
path. Hardware targets the substrate backend traits and profile contract.

Primary path:

```text
vISA artifact
  -> Semantic Virtual ISA operation
  -> contract ledger
  -> substrate trait backend
  -> host ISA / hardware
```

Optional frontend path:

```text
Linux ELF / WASI / JS ABI / future guest ABI
  -> personality artifact
  -> Semantic Virtual ISA operation
  -> same contract ledger / substrate path
```

Short form:

```text
Wasm provides mature virtual execution infrastructure.
Semantic Virtual ISA makes system semantics portable across host ISAs.
Frontend personalities are optional adapters, not the system center.
```

Read the formal spec stack in this order:

```text
../specs/semantic-virtual-isa-v0/00-overview.md
../specs/semantic-virtual-isa-v0/01-isa-axes-and-execution-model.md
../specs/semantic-virtual-isa-v0/02-operation-families.md
../specs/semantic-virtual-isa-v0/03-profile-matrix.md
../specs/semantic-virtual-isa-v0/04-artifact-execution-model.md
../specs/semantic-virtual-isa-v0/05-frontend-personality-boundary.md
../specs/semantic-virtual-isa-v0/06-conformance-and-evidence-boundary.md
```

Review question:

```text
Does this strengthen the Semantic Virtual ISA boundary, or does it add another
native stand-in workload, frontend shortcut, or substrate-specific leak?
```
