# vISA Nexus adapter core

`visa_nexus_service` is the transport-independent core of the planned
`visa-nexusd` process. It owns the local adapter store and the durable
dispatch-grant ledger; it does not own D-Bus, systemd, the Nexus Registry, or
profile I/O.

The [`NativePeer`] trait is the narrow seam for the Nexus-owned native-v1
process. A peer implementation must return a verified native commit receipt
for the exact prepared request bytes. The core persists those bytes before
calling the peer, so a response loss or adapter restart retries the same
native request identity rather than minting a second Registry transition.

This crate is an N1 implementation slice. The product D-Bus service, registry
attempt marker, executable identity checks, and the real Nexus process client
remain later gates. No readiness ledger item is closed by this crate alone.
