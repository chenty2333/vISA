# vISA local RPC wire contracts

`visa_local_rpc` is the transport-independent wire crate for the three vISA
0.1 same-host process boundaries:

- controller to source/destination agent;
- agent to the independent ownership service; and
- agent to the Nexus adapter service.

The families share only mechanical identifiers, bounded payload references,
strict Postcard codec helpers, and validation errors. Each family has its own
serialized 16-byte family ID, concrete request/response/error/replay types,
digest domains, schema/corpus IDs, and D-Bus namespace constants. Postcard type
names are not serialized, so the family marker is validated from the bytes
rather than inferred from a Rust type.

Each family exposes its own request decoder, request-paired response
encoder/decoder, and replay encoder/decoder. The generic codec is crate-private,
so a client cannot accidentally treat a structurally valid response for the
wrong request as accepted. Agent-control response decoding additionally takes
the verified Source or Destination endpoint role. The decoder caps input before
allocation-heavy decoding, rejects trailing bytes, re-encodes and compares
exact bytes to reject non-minimal encodings, and then performs structural and
request/response binding validation. A concrete `ReplayRecord` retains each
exact request and response byte string plus their domain-separated digests;
replay validation decodes both sides and repeats the full paired check.

`ReceiptArtifact` is a bounded carrier for exact neutral receipt bytes. Its
validation uses the neutral v1 domain, explicit receipt-kind tag, byte length,
and exact payload bytes to recompute `ReceiptRef.digest`; every one of the 14
receipt kinds also has a distinct payload content schema. This proves
reference/carrier byte self-consistency, not a typed or authenticated neutral
receipt. Before adopting a receipt or mutating state, the future ownership and
Nexus services must still use the neutral typed verifier to decode and
re-encode the selected receipt type and validate its header, full handoff key,
issuer lineage, request binding, and authentication.

`postcard-schema` 0.2.5 supplies reflection only. The std-only RFC 8785 JCS
serializer stays in `visa-conformance`, which generates and independently
recomputes three checked-in owned-schema artifacts and three Rust-constructed
all-variant golden corpora. `schemas/local-rpc/index.json` binds the exact six
files while explicitly remaining development wire evidence rather than RPC or
release readiness:

```console
cargo run --locked -p visa-conformance \
  --bin visa-local-rpc-artifacts -- --check
```

Use `--write` only when intentionally changing a frozen wire shape. Static
gates reject sibling-family imports, floats, unordered maps/sets, unsupported
Serde shape attributes, manual serialization, dependency drift, noncanonical
schema JSON, corpus drift, and executable request/response/replay
malformed/binding substitutions. Conformance also checks the parallel neutral
key/reference shapes, all receipt-kind tags, and the receipt digest algorithm
against `joint_handoff_core`.

This crate does **not** implement D-Bus transport, peer credential admission,
durable replay storage, mutation sequencing, ownership decisions, Nexus native
translation, typed receipt adoption, or provider-enforced effect dispatch.
Consequently its presence
does not satisfy `cli-agent-rpc-v1`, `agent-ownership-rpc-v1`, or
`agent-nexus-rpc-v1`; those readiness IDs remain pending until the zbus
transport, services, persistence, restart tests, and process-level evidence
consume these exact bytes.
