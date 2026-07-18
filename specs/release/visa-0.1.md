# vISA 0.1 exact-version release contract

Status: frozen target contract; not release-ready.

The machine authority is [`visa-0.1.toml`](visa-0.1.toml). It defines one
exact product cell: vISA `0.1.0`, same host and same boot, Linux x86-64, two
distinct vISA agent processes, a separate controller, and a separate
`nexus-effect-peer` process. It is a target for release admission, not evidence
that these product surfaces already exist.

The internal Stage 3 worker hop is `visa-agent-local-v1`, bounded JSON Lines
over stdio. The product CLI-to-agent hop is a filesystem Unix-domain socket,
mode `0600`, admitted only after Linux `SO_PEERCRED` reports the same UID. These
are separate transport scopes; neither admits a network control endpoint.

Product SemVer does not replace any internal namespace. Cargo crate versions,
the portable contract, joint protocol, profiles/extensions, WIT package
versions, neutral wire, Nexus native wire, and the provider SPI evolve under
their own rules. In particular, the current `EffectClosureProvider` v2 surface
is an in-tree Rust preview, not a promised Rust ABI or a substitute for the
versioned Nexus process adapter.

The pinned Nexus native-v1 freeze is an exact source contract at its freeze
commit; it is not described as a Nexus `v0.1.0` released API. A lightweight,
independently consumable wire crate or release artifact is a separate pending
closure item for the vISA release. The upstream freeze bytes also require a
local byte-exact source lock; the remote path and recorded digest alone do not
close release admission.

The contract locks the three WIT package IDs and their exact source bytes. WIT
already has package SemVer, and `wkg`/OCI can distribute packages later; vISA
does not define another package format for 0.1. The release-supply-chain work
must decide and verify publication separately.

Four release semantic vectors lock exact Postcard bytes and SHA-256 digests for
a handoff command, event, journal entry, and snapshot envelope. A Rust test
constructs those values from the real `contract_core` types; the contract
checker binds the manifest values to that test rather than treating copied
bytes as execution evidence.

Two checks deliberately have different meanings:

```sh
python3 scripts/check-release-contract.py
python3 scripts/check-release-contract.py --release-ready
```

The first verifies schema shape and every currently frozen local version,
digest, WIT byte sequence, provider identity requirement, and wire/mapping
boundary. It runs in `ci-gate.sh fast`. The second additionally requires every
release closure item to be satisfied. It currently fails because the public
CLI/agent typed status, run, handoff, and reconcile outcomes plus exit-code
policy, dual-process Stage 3 path, production Nexus adapter and provider fence,
local Nexus freeze lock, consumable Nexus wire artifact, exact neutral mapping
v2, release-quality expansion, external workload, and exact-tag evidence are
still pending. Command spelling is not frozen while the public surfaces remain
unimplemented.

Changing a frozen byte or identifier requires an explicit versioned successor;
changing a pending item to satisfied requires its exact release evidence. A
schema-valid contract is never itself release evidence.
