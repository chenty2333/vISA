# References Index

Current source of truth:

```text
1. specs/semantic-virtual-isa-v0/00-overview.md
   Canonical system spec: vISA as a cross-ISA Semantic Virtual ISA.

2. specs/semantic-virtual-isa-v0/01-isa-axes-and-execution-model.md
   Host ISA, Wasm execution ISA, Semantic vISA, and optional guest ABI axes.

3. specs/semantic-virtual-isa-v0/02-operation-families.md
   vISA operation families and ownership boundaries.

4. specs/semantic-virtual-isa-v0/03-profile-matrix.md
   Profile levels, feature matrix, and load compatibility rules.

5. specs/semantic-virtual-isa-v0/04-artifact-execution-model.md
   vISA artifact execution path through TargetArtifactImage, CodeObject,
   Activation, HostcallFrame, and TrapMap.

6. specs/semantic-virtual-isa-v0/05-frontend-personality-boundary.md
   Optional Linux/WASI/custom frontend personalities and their normalization
   boundary.

7. specs/semantic-virtual-isa-v0/06-conformance-and-evidence-boundary.md
   Evidence levels, cross-ISA conformance, and review smells.

8. specs/semantic-contract-v0.1/00-overview.md
   Contract ledger: ObjectRef, capability, wait, cleanup, views, validation.

9. specs/target-runtime-abi/00-overview.md
   Runtime ABI: TargetArtifactImage, CodeObject, HostcallFrame, TrapMap,
   profile, no_std extraction.

10. specs/substrate-api-v0/00-overview.md
   Backend traits: machine authority discovery, profiles, conformance.

11. Current task prompt / issue tracker
   Engineering sequence is operational state, not a permanent spec.
```

Legacy and background:

```text
vision/semantic-visa-v0.md
    Old Semantic vISA entry point. Kept as a redirect to the vISA framing.

vision/semantic-virtual-isa.md
    Narrative summary retained for orientation. The normative vISA spec lives
    under specs/semantic-virtual-isa-v0/.

vision/cross-isa-migration.md
    Portability and migration notes. Cross-ISA portability is a conformance
    test for the vISA boundary, not a separate product center.

paper/plos-draft.md
    Non-authoritative narrative draft.

archive/
    Historical notes only.
```

## Terminology

```text
Semantic Virtual ISA
    Cross-ISA virtual ISA backed by Wasm execution infrastructure and extended
    with authority, lifetime, wait, event, trap, cleanup, artifact identity,
    hostcall attribution, and target profiles.

Personality Artifact
    Portable service, host, driver, or frontend implementation targeting the
    Semantic Virtual ISA.

Task
    Schedulable semantic execution object when a frontend/personality exposes
    task-like behavior.

Resource
    Generation-bearing semantic object that can be referenced, authorized,
    waited on, snapshotted, or exported as a view.

Contract Ledger
    Explicit, inspectable record of Semantic vISA effects.

FastPathPlan
    Cached execution plan derived from semantic refs and generations. It is not
    semantic truth and must be invalidated on generation or policy change.

Substrate
    Backend authority provider that maps virtual machine operations to real
    hardware mechanisms.

target_executor
    Bridge from artifact/runtime ABI events to contract-visible effects and
    substrate trait calls.

osctl
    Read-only control plane over stable views.
```

## Maintenance Rule

Keep specs short. If a document starts accumulating completed work history,
long test lists, paper claims, run notes, or repeated examples, move that
material outside the mainline specs and keep only the boundary rule.
