# vISA user CLI

This crate is the local, non-authoritative controller surface for vISA 0.1.
The current slice implements the durable `cohort-create` preparation phase:

1. acquire the flat controller operation lease;
2. read or create the same-boot runtime session;
3. create or exactly match the persistent launch manifest;
4. create/audit the source and destination generation-zero agent stores; and
5. create or exactly match the active launch manifest.

The `systemd_activation` module now contains the separately testable typed
zbus 5.18 Manager/JobRemoved choreography and a pure five-unit state
evaluator. It is deliberately not wired into `cohort-create` or the readiness
ledger yet: no CLI operation issues an ownership, effect, or Nexus receipt,
and the caller still has to bind the unit result to product RPC health.
