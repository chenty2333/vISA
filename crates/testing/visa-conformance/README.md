# visa-conformance

`visa-conformance` defines and validates vISA conformance catalogs, reports,
and linked evidence artifacts. It is an internal testing tool, not the vISA
runtime and not an implementation of the behaviors listed in its catalog.

Project-level claim and validation policy lives in
[docs/VALIDATION.md](../../../docs/VALIDATION.md).

## Responsibilities

The crate provides:

- typed report, result, evidence-artifact, and validation records;
- catalogs for vISA semantics, substrate profiles, personalities, and
  performance claims;
- structural and claim-boundary validation;
- artifact path, digest, and type-specific checks;
- adapters that turn LTP logs and Criterion output into report records; and
- sample reports used as schema and catalog fixtures.

It does not automatically execute every catalog entry. A passing report is
meaningful only when a real runner produced the required evidence and the
artifact gate validated it.

## Common commands

Run the crate tests:

```sh
cargo test -p visa-conformance
```

Validate catalog wiring and sample report shapes:

```sh
cargo run -p visa-conformance -- validate-sample
```

This is a structural fixture check. It is not executable evidence of runtime,
substrate, migration, Linux, or performance behavior.

Validate a report and its linked local artifacts:

```sh
cargo run -p visa-conformance -- \
  validate-report-with-artifacts <report.json> <artifact-root>
```

Specialized LTP, benchmark, and target runners live under `scripts/`. They must
preserve their raw outputs and identify the actual runtime, ISA, substrate,
resource profile, and evidence boundary exercised.

## Claim rule

Report validity, executable behavior, portability, real-target enforcement,
and performance are separate claims. A schema-valid sample must never be
promoted into a stronger claim, and missing required evidence must remain
`not-run` or fail validation rather than being hidden as success.
