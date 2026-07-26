# Legacy kernel-personality service crates

Status: frozen legacy leaves. No crate in the workspace depends on any crate
in this directory, and the reference kernel under `crates/host/kernel` does
not link them; its supervisor carries its own service implementations. These
crates last changed at the 2026-07-12 restructuring point and are kept as
workspace members so they continue to compile under `cargo test --workspace`
and the `x86_64-unknown-none` checks.

They are not comparison oracles (that role is reserved for
`crates/oracle/`), and they are not part of the active spine gated by
`scripts/ci-gate.sh` clippy/tests. Treat them as retained history: do not
grow them, and do not wire new dependencies onto them without a Roadmap
decision that reactivates the kernel-personality path.

Disposition options are recorded in
`docs/notes/structure-and-governance-disposition.md`.
