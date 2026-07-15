# Feature 009 Quickstart

The implementation gate will use one entry point:

```text
scripts/ci-gate.sh system-joint-handoff
```

The gate is not available until the protocol core, reference peers, system
runner, independent verifier, formal model, and Nexus adapter are all wired.
The stage remains active if any substitute/mock-only lane is the strongest
available evidence.

During implementation, focused checks should run the smallest affected crate
before the aggregate gate. The final closing sequence must include ordinary
`fast` and `full` gates, the unchanged Stage 1-4 claim gates, the joint gate,
Docker execution, artifact relocation verification, and exact-SHA pushed CI.
