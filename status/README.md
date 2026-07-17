# Current capability status

This directory records moving implementation checkpoints without rewriting the
accepted Stage 1-4 or `bounded-joint-handoff-refinement-v1` evidence. A current
checkpoint points backwards to an exact claims revision and its evidence. It is
not a claim that later repository revisions inherited the same result.

`current-capabilities.toml` is the machine-readable ledger. It keeps the
accepted joint-handoff result separate from the newer admission-ordered
engineering checkpoint:

- the accepted result retains its original implementation identity and its
  supplemental post-hoc logical-request boundary;
- the current checkpoint records that Nexus admission preceded the external
  logical request in one same-host process cell;
- neither checkpoint qualifies a production Nexus adapter, real OSTD, retained
  device recovery, reboot recovery, or cross-host execution.

The neutral joint-handoff wire v1 and Nexus native wire v1 remain frozen source
contracts. New provider capabilities use the v2 provider SPI or an explicitly
versioned extension; they do not silently widen either v1 evidence boundary.

The repository CI contract checker validates this ledger:

```sh
python3 scripts/check-ci-contract.py
```

Updating the ledger requires an exact claims revision, capability and boundary
sets, CI identity, and archive status. GitHub Actions artifacts are transport,
not long-term archives.
