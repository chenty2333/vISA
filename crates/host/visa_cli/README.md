# vISA user CLI

This crate is the local, non-authoritative controller surface for vISA 0.1.
The current slice implements the durable `cohort-create` preparation phase:

1. acquire the flat controller operation lease;
2. read or create the same-boot runtime session;
3. create or exactly match the persistent launch manifest;
4. create/audit the source and destination generation-zero agent stores; and
5. create or exactly match the active launch manifest.

Systemd Manager activation (`Subscribe`/`StartUnit` and health observation) is a
separate layer and is intentionally not claimed by this slice yet. No CLI
operation issues an ownership, effect, or Nexus receipt.
