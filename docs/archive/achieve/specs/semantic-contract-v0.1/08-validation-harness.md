# Validation Harness

Status: active test boundary.

Validation proves current code behavior against the stable contract. It is not
an archive of work logs and not a substitute for real tests.

## Required Test Shape

Every semantic object family should have current tests for:

```text
positive path
negative path
generation mismatch / stale ref rejection
capability denial when applicable
wait/trap/cleanup visibility when applicable
osctl JSON shape when the object is exported
contract graph validation when graph edges are involved
```

Fixtures are allowed only when a test directly consumes them. A fixture should
be small, stable, and named by the behavior it tests. Do not keep historical
run logs, benchmark claims, or old transcripts as mainline test inputs.

## Normal Gate

Use ordinary Rust and CLI checks as the repository gate:

```text
cargo fmt --all -- --check
cargo test --workspace
targeted cargo run smoke commands when a CLI path changes
```

Additional shell wrappers are allowed as convenience entry points, but they must
only run current tests or current static checks. They must not depend on
historical report directories.

## Evidence Boundary

Runtime evidence means current, machine-readable state emitted by the system:

```text
EventLog records
contract graph validation output
osctl ViewV1 JSON
semantic package manifests
target/runtime profile views
```

Run notes and generated experiment logs are operational artifacts. They may live
in `.codex/tmp`, CI artifacts, or external archives, but they are not
source-of-truth contract inputs.

## Boundary Claims

Tests and docs must preserve the execution boundary being claimed:

```text
semantic model
reference service
reference AOT harness
portable artifact execution
real target substrate
```

Do not report a lower boundary as a higher one. In particular, a reference
service or fake harness test does not prove portable artifact execution.
