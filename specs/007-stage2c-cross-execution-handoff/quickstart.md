# Stage 2c Cross-Execution-Path Matrix Verification

## Entry Baseline

Finish `005-stage2a-runtime-adapter-contract` and
`006-stage2b-jco-node-reference-cell`. Retain fresh successful entry evidence
for both same-path cells:

```text
Wasmtime -> Wasmtime   31/31, independent Stage 1 verifier passed
JcoNode  -> JcoNode    31/31, independent Stage 1 verifier passed
```

Record the original Component, world, profile, configuration, policy, case-
registry, component-state codec, and toolchain identities. Stage 2c acceptance
must generate one immutable common-input manifest before execution, bind its
identity to all four freshly regenerated cells, and prove their inputs against
it afterward; the entry bundles establish a baseline but cannot be copied into
the final matrix.

## Verify the Locked JcoNode Path

Verify only the checked-in Cargo/source locks and selected Node toolchain:

```sh
python3 scripts/check-jco-node-toolchain.py
```

The expected Stage 2b baseline remains:

```text
Jco                         1.25.2
js-component-bindgen        2.0.11
wasmtime-environ lineage    45.0.1
Node                        v24.15.0
V8                          13.6.233.17-node.48
```

The `wasmtime-environ` value is mandatory translator-lineage disclosure. It
neither means the Node/V8 guest executes on Wasmtime nor permits a claim of a
fully independent Component Model implementation.

## Focused Edit Loop

```sh
cargo fmt --all --check
cargo check --locked -p visa_component_adapter -p visa_wasmtime \
  -p visa_jco_node -p visa-system -p visa-conformance
cargo test --locked -p visa_component_adapter -p visa_wasmtime \
  -p visa_jco_node -p visa-system -p visa-conformance
cargo clippy --locked -p visa_component_adapter -p visa_wasmtime \
  -p visa_jco_node -p visa-system -p visa-conformance \
  --all-targets -- -D warnings
python3 scripts/check-dependency-direction.py
python3 scripts/check-stage1-deletions.py
python3 scripts/check-jco-node-toolchain.py
```

Focused tests must establish:

- exactly four stable cell IDs map to the four explicit selector pairs;
- the orchestrator creates and hashes the common manifest before the first
  cell, every cell records `stage2-common-input-identity-bound`, and the outer
  verifier proves byte-identical Component/world/profile/config/policy within
  that matrix run plus identical ordered case/fault inputs; workers do not parse
  the manifest JSON;
- a cell receives fresh workers, provider state, runtime instances, Node
  processes when selected, and execution-local handles;
- requested and preflight identities agree with both bundles, while typed
  instantiation is inferred from successful bootstrap or post-commit resume
  after adapter-internal startup validation in both mixed directions;
- a JcoNode failure never invokes Wasmtime and a Wasmtime failure never invokes
  JcoNode;
- mixed destination preflight still precedes coordinator restore/preparation/
  commit, and destination instantiation still follows durable commit;
- portable component state moves directly between adapters without a pair-
  specific converter;
- the normalizer rejects unverified Stage 1 input, an unknown field, an
  unsupported schema, missing artifacts, and a runner cache mismatch; and
- an independent process composes four complete Stage 1 validations rather
  than trusting outer pass flags.

## Normalized Trace Mutation Check

`visa-stage2-normalized-observable-trace-v1` must be tested as a strict typed
projection. Mutating only one of these eligible metadata categories may leave
the canonical trace unchanged:

```text
observation timestamp or elapsed-time sample
raw performance timing or raw serialized snapshot-size sample
operating-system PID
filesystem/generated-artifact path
human engine/translator diagnostic, worker message, or assertion detail text
one valid positive remaining duration changed to another positive value
```

Every semantic mutation below must change V1 and fail four-way verification:

```text
execution/handoff/snapshot identity, per-case input digest, outcome, or fault order
source/destination branch or journal-entry order
effect result, denial, conflict, unavailable, or indeterminate status
structured worker error code/retryable/provider/adapter/workload kind, role, or order
resource identity/generation or required/exposed rights
authority root, lease epoch, fencing epoch, ownership, or source-fenced state
binding disposition/receipt semantics
safe point, cancellation, rollback, abort, retry, cleanup, or no-resurrection
final/replay state or portable snapshot semantics
initial source TimerArm requested duration or any non-profiled timer semantic
remaining logical duration changed between zero and positive
assertion name or assertion order
```

Before applying this mutation table, the complete Stage 1 verifier checks all
raw timer values and content-derived integrity fields. V1 preserves the source
`TimerArm` request exactly but represents elapsed freeze/restore/rearm remaining
duration as `zero` or `positive`. It replaces already-verified journal state,
request, evidence, and snapshot integrity digests with the declared V1 marker,
then recomputes enclosing normalized-content digests; it does not delete
arbitrary integrity failures. Raw timing/size observations remain available in
inner evidence, while V1 records normalized portable-envelope serialized size.

Assertion names and order remain in V1, but human assertion details do not.
The outer typed verifier separately validates common-input identity and
runtime/translation provenance.

Runtime/toolchain identities, artifact hashes, bundle IDs, RPC/handle IDs, and
typed instantiation observations are checked outside normalized trace equality;
they are not fields the normalizer erases to obtain equality. Adapter startup
handshakes are validated and rejection-tested internally; their envelopes are
not retained for outer inspection.

## Run the Full Matrix

The completed slice exposes one locked matrix gate:

```sh
scripts/ci-gate.sh system-stage2
```

For a retained manual run, use the explicit Stage 2 CLI:

```sh
mkdir -p "$PWD/target/visa-system"
artifact_root="$(umask 077; mktemp -d \
  "$PWD/target/visa-system/stage2-XXXXXX")"
cargo run --locked -p visa-system --bin visa-system -- \
  stage2 "$artifact_root"
cargo run --locked -p visa-conformance --bin visa-conformance -- \
  stage2 "$artifact_root/stage2-evidence.json" "$artifact_root"
```

The operation runs these exact cells without defaults or fallback:

```text
wasmtime-to-wasmtime   31/31
jco-node-to-jco-node   31/31
wasmtime-to-jco-node   31/31
jco-node-to-wasmtime   31/31
total                 124/124
```

The outer root must contain four standalone Stage 1 roots:

```text
stage2-root/
  stage2-common-input.json
  inputs/
    component.wasm
    world.wit
    profile.json
    configuration.json
    authority-policy.json
  stage2-matrix-manifest.json
  stage2-evidence.json
  normalized/
    wasmtime-to-wasmtime.json
    jco-node-to-jco-node.json
    wasmtime-to-jco-node.json
    jco-node-to-wasmtime.json
  cells/
    wasmtime-to-wasmtime/stage1-evidence.json
    jco-node-to-jco-node/stage1-evidence.json
    wasmtime-to-jco-node/stage1-evidence.json
    jco-node-to-wasmtime/stage1-evidence.json
```

The Stage 2 verifier must first run full existing Stage 1 structural/artifact
validation over each cell root. Only after all four pass may it verify common
inputs, identities, provenance, no fallback, and 31 groups of four exactly
equal recomputed V1 traces. The four normalized files are typed per-cell
aggregates with 31 cases each; outer evidence carries 31 per-case comparison
digests, not 124 cache files.

## Diagnose One Inner Cell

When the outer verifier reports a cell failure, validate that complete Stage 1
bundle directly before investigating cross-cell equality:

```sh
cargo run --locked -p visa-conformance --bin visa-conformance -- \
  stage1 \
  "$artifact_root/cells/wasmtime-to-jco-node/stage1-evidence.json" \
  "$artifact_root/cells/wasmtime-to-jco-node"
```

Repeat with the exact failed cell ID. A Stage 1 failure is not a normalized
trace mismatch and must not be bypassed by regenerating only the outer summary.

For an actual equality finding, inspect the verifier-recomputed V1 artifacts
for the named case. Do not add an exclusion until the value is proven to fit an
explicit V1 exclusion or equivalence rule above. Differences in outcomes,
events, effects, structured errors, assertion name/order, timer class, rights,
epochs, ownership, or cleanup are portability bugs or failed hypotheses.

## Local and Docker Acceptance

Run all local tiers:

```sh
scripts/ci-gate.sh fast
scripts/ci-gate.sh full
scripts/ci-gate.sh system
scripts/ci-gate.sh system-jco-node
scripts/ci-gate.sh system-stage2
```

Then run the locked container tiers:

```sh
scripts/run-docker-ci-gate.sh full
scripts/run-docker-ci-gate.sh system
scripts/run-docker-ci-gate.sh system-jco-node
scripts/run-docker-ci-gate.sh system-stage2
```

`system-stage2` must execute all 124 cases inside the declared environment and
invoke a separate Stage 2 conformance process. A skipped cell, a fixture outer
bundle, 62 same-path cases plus mixed smoke tests, or a fallback execution is a
failed gate. This matrix remains on the one declared ISA and earns no cross-ISA
claim.

## Evidence Checks

For a retained Stage 2 root, verify and record:

- outer manifest/evidence schema, IDs, SHA-256 values, root containment, and
  exact four-cell table;
- one common-input manifest and byte-identical Component/world/profile/config/
  policy artifacts within that retained matrix root, plus identical per-case
  digests/fault schedules, with the same pre-run identity bound by
  `stage2-common-input-identity-bound` in every cell rather than a claim that
  workers read the JSON;
- four execution-kind Stage 1 bundles with 31 unique required cases each;
- four independent Stage 1 verifier successes before the outer comparison;
- requested/preflight/bundled identities and typed instantiation inferred from
  successful protocol progression for each source and destination, including
  honest not-instantiated markers where case design stops early;
- exact Wasmtime and Jco/Node/V8 toolchain/translation provenance and no
  Wasmtime fallback in either selected JcoNode direction;
- 124 independently recomputed V1 case projections, four byte-checked typed
  aggregate caches, and 31 exactly equal four-cell comparison groups;
- selected outcome equality, not merely allowed-outcome membership;
- preserved event/effect order, rights, epochs, ownership/fencing,
  cancellation/rollback/cleanup, structured worker errors, assertion name/
  order, portable state, and normalized final/replay state;
- exact initial timer-arm duration, zero-versus-positive elapsed-remaining
  profile, explicit derived-integrity markers with recomputed enclosing
  normalized-content digests, and normalized portable-envelope serialized
  size;
- all four runner aggregate caches byte-equal to verifier recomputation; and
- only the outer `cross-execution-path-portability` claim, with strict
  Component Model independence, current-roadmap cross-runtime portability,
  cross-ISA, transparent migration, performance, and production explicitly
  unclaimed.

## Completion Evidence to Record

- common-input manifest path, schema, and SHA-256;
- Stage 2 matrix manifest/evidence paths, IDs, and SHA-256 values;
- each inner cell's root, bundle ID, bundle SHA-256, and 31/31 count;
- original Component/profile/configuration/policy and case-registry digests;
- requested and preflight-verified Wasmtime/Jco/Node/V8 identities, typed
  instantiation observations, Jco translator lineage, and generated-graph
  aggregate hashes;
- four independent Stage 1 verifier results;
- Stage 2 verifier result, 124/124 count, and 31 V1 equality-group digests;
- focused tests, strict Clippy, dependency/deletion/toolchain gates;
- local and Docker full-matrix results; and
- transcript/provenance/no-fallback/overclaim audit results.

The completion statement is:

> The named cooperative stateful handoff profile preserves normalized
> observable behavior across the Wasmtime path and Jco-translated Node/V8 path
> in all four source/destination cells.

Do not replace it with “two fully independent Component Model runtimes,”
“generic cross-runtime portability,” or “cross-ISA portability.”

## Accepted Roadmap Decision

The accepted boundary retains the genuinely independent Component Model
implementation criterion. Stage 2c is complete, but Jco's disclosed
`wasmtime-environ` translator lineage means strict Roadmap Stage 2 remains in
progress. Report:

```text
Stage 2a runtime-neutral adapter contract: complete
Stage 2b JcoNode execution cell: complete
Stage 2c cross-execution-path matrix: complete
Strict Roadmap Stage 2: in progress (not closed)
Strict cross-runtime portability: not claimed
Stage 3 file/network resources: not started
Stage 4 cross-ISA: not started
Stage 5 confidential profile: not started
Production readiness: not claimed
```

## Final Stage 2c Evidence

All final host and Docker gates passed with the pinned
`nightly-2026-06-07` toolchain. The host `system-stage2` result is:

```text
root: target/visa-system/stage2-w3glkT
outer bundle id: stage2-8c0190bcaad94084610a5f82
outer evidence sha256: 570394604edfcb3b37081778d65121e10b0f9aaba73beb8488a7ee57ba71eb0f
matrix manifest sha256: 8c0190bcaad94084610a5f82b15084d4974b7a6f9cc343ff88d431229ab63ad5
common-input sha256: e80ee1692844d19d55b63063afcdeed30605ce68f3b81a1a049f877ba245ee0b
normalized aggregate sha256: 1622eff949794d559be2620df0730a2e6095d67f594aa71acba484bd159e786c
derived comparison-set sha256: 5d38daca7009238496a03efa12ae5d45613f30dd56709d64966a808ea40bbca7
executions: 124/124
inner verifiers: 4/4 passed
outer verifier: passed
equality groups: 31/31 equal
```

Host inner bundles:

| Cell | Bundle ID | Evidence SHA-256 |
| --- | --- | --- |
| Wasmtime to Wasmtime | `stage1-1783810626022-06da27e97f68c1d4` | `ec1f37eed52835d1de1f6a88005bd6950de25d59f512f70796d9a5a762afb57e` |
| JcoNode to JcoNode | `stage1-1783810722204-06da27e97f68c1d4` | `1678ad1b3cbf03d52bc2091e9396669d60a601b3d492b689fc3fbfa94f520440` |
| Wasmtime to JcoNode | `stage1-1783811372413-06da27e97f68c1d4` | `061cc43bc1977ebfea115120a903ff0d97908beb81bf3f999af7d2cb1f8bc3ea` |
| JcoNode to Wasmtime | `stage1-1783811735806-06da27e97f68c1d4` | `01a421453ba8bae24b4a2edbf0678b65868c81cf9d64756eab5e0ea0a7ce0077` |

The Docker `system-stage2` result is:

```text
root: /workspace/target/visa-system/stage2-2JUfEQ
outer bundle id: stage2-5829874cf4652b813257fa5d
outer evidence sha256: c3158af881d61c61c567bd7ec8b41b47ecbf1a914ff58373c2ce0a827da83637
matrix manifest sha256: 5829874cf4652b813257fa5d48ac9a6f7910845ece2201500e04d7d1bfa49773
common-input sha256: b83e0ecf80858631a6207d5ed4ed7f6091ac123461b522a056b58ce918d3e109
normalized aggregate sha256: 96e2f1f01453154c1d6816490972305eb8283730a30f9e0681f0b8bf2b0bec03
derived comparison-set sha256: 9b387f2e37aebafe4c519dc4d3435af3472dfbd1038df5e4d66a621d6a080812
executions: 124/124
inner verifiers: 4/4 passed
outer verifier: passed
equality groups: 31/31 equal
```

Docker inner bundles:

| Cell | Bundle ID | Evidence SHA-256 |
| --- | --- | --- |
| Wasmtime to Wasmtime | `stage1-1783811317859-06da27e97f68c1d4` | `7c10301af3ad9cd6389a78ac8c2f4502f930060ebd06003592012d7da99c85fb` |
| JcoNode to JcoNode | `stage1-1783811412315-06da27e97f68c1d4` | `fdc2fa93da40a97501cb79cede6065041487a9f7354e6e53d5369a266ab6533e` |
| Wasmtime to JcoNode | `stage1-1783812062319-06da27e97f68c1d4` | `54be5f55a3a0b87c120514e416c080945be8f0570d8bc853333923e338b04ad2` |
| JcoNode to Wasmtime | `stage1-1783812418742-06da27e97f68c1d4` | `d46de7c466050db2da0345f14b2483d2b8f0a6094f978182512f485c0d08375e` |

The Docker root is retained in the default Compose named volume. Raw provider
isolation observations bind the execution path, so the evidence is reverified
at the exact `/workspace` path rather than through a substituted host path.

The final outer bundles were independently rechecked with:

```sh
target/debug/visa-conformance stage2 \
  target/visa-system/stage2-w3glkT/stage2-evidence.json \
  target/visa-system/stage2-w3glkT
docker compose -f compose.yaml run --rm -T dev \
  /workspace/target/debug/visa-conformance stage2 \
  /workspace/target/visa-system/stage2-2JUfEQ/stage2-evidence.json \
  /workspace/target/visa-system/stage2-2JUfEQ
```

The derived comparison-set hashes above are reproducible reporting digests,
computed with:

```sh
python3 -c '
import json, sys
data = json.load(open(sys.argv[1]))
print(json.dumps(data["case_comparisons"], sort_keys=True, separators=(",", ":")))
' stage2-evidence.json | sha256sum
```

The authoritative evidence also carries every one of the 31 per-case
`normalized_case_sha256` values. In each environment all four normalized
aggregate files are byte-identical to the recorded aggregate SHA-256.

Shared locks and execution identities:

```text
registry sha256: 95e05af67ff122ca4be0a94823340bcf5ad368f05be8946ca0a26a47816ecfd9
WIT world: visa:continuity/cooperative-handoff@0.1.0
WIT sha256: 709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920
Wasmtime: visa_wasmtime 0.2.0 / wasmtime 43.0.2
Jco / bindgen / translator: 1.25.2 / 2.0.11 / wasmtime-environ 45.0.1
Jco adapter-private RPC protocol: 3
Node / V8: 24.15.0 / 13.6.233.17-node.48
Rust: 1.98.0-nightly, commit 61d7280f3c4c63fa24c56bdaa9a446151b5a30dc
source sha256: c1fe1818a110d6dcf858e4072b7ff58427324da56490d005f2339763fcf3f656
toolchain sha256: 33bd760b0d42eee90cf79af2bd3a30df1de6535fb53d34ebbb2542625adc9bf3
preflight.mjs: 235 bytes / sha256:171a57d9b2f036159c439c8f71760cb3ace41c6e519af1d12f7c8d1fd0f485be
Docker image: sha256:ca7c91e726c7fbce36cb152fcf56b8bc89d7c773ef7d4e3817cd8ad5051bfce0
Docker platform: linux/amd64
```

The final common-input records bind these exact input identities:

```text
Host component artifact SHA-256:    4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b
Docker component artifact SHA-256:  d4f1a2e8bfacb0659d26569850a0f489c861a021ecad4cf068ca5d67748e04eb
Shared profile artifact SHA-256:    ffca9e41e4c60e602cc8e387119e3497b314a6e11f737475f0ed9fed8af6a646
Shared profile digest:                 da6babca82e0e34ac32c591d9494fb77d8d2c6f7b4201c7feb67669400da2241
Shared configuration artifact SHA-256: a2d52c5c6213fd144256dd420b3345200976b5c7575dcda24d940cbd2c48ea9e
Shared configuration digest:        06da27e97f68c1d45919dcacf70b7d92ef1bae0cafbfa3ad8e0ddef9128eb07b
Shared authority-policy artifact SHA-256: afef31ce3d8dfe242f8b048e8705ae6d9512dfc54b26e076a11196a24b2e0df6
Shared authority-policy digest:     853697466509d7b106bf7f099e870a934c42047c42d85f9750ca21d4a3c6ab3e
```

The outer manifests machine-check the exact retained Jco translation
provenance:

| Environment | Node path | Generated tree SHA-256 | Driver SHA-256 | Ordered core-module SHA-256 values |
| --- | --- | --- | --- | --- |
| Host | `/home/ava/.nvm/versions/node/v24.15.0/bin/node` | `0ba4c9f4b0a14b4264cd19600dd283bcf3beac0845e6476ca891b6f1a2167da9` | `fe3f73f5f39c7e6a7cb12d175b95744dabe0d243a5f99704b95586696b3c8473` | `bebc950891f8c4290b0592e5ab6ae408b29f5683a114983657fb2d2c1aaa62b9`, `12e182b97bffc401f5e54a493fd45c14a22030d958acfdf1f74303103d4d6394`, `4a010b325d525856b8e71cc4cc9cb42cfe12c395ebcc8aee9d44b9fc83e66029` |
| Docker linux/amd64 | `/usr/local/bin/node` | `039daddf7e531c250959aa55885055e3a6dd54cf383c16748ef91325a288d4fc` | `fe3f73f5f39c7e6a7cb12d175b95744dabe0d243a5f99704b95586696b3c8473` | `049d81294171d2458051d47a4efbe471d904d6109906f79b89b4961ab20d675d`, `12e182b97bffc401f5e54a493fd45c14a22030d958acfdf1f74303103d4d6394`, `4a010b325d525856b8e71cc4cc9cb42cfe12c395ebcc8aee9d44b9fc83e66029` |

Both paths bind Node executable SHA-256
`d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c`,
RPC protocol 3 with a matching terminal `settled` frame, and this exact
`translation_options` string:

```json
{"schema":"visa-jco-node-transpile-options-v1","name":"handoff-component.component","no_typescript":true,"instantiation_mode":"sync","import_bindings":"js","nodejs_compat_disabled":false,"base64_cutoff":0,"tla_compat":false,"valid_lifting_optimization":false,"tracing":false,"no_namespaced_exports":true,"multi_memory":false,"guest":false,"strict":true,"asmjs":false}
```

The host and Docker component bytes are not identical: this test component
embeds environment-specific absolute Rust toolchain and registry source paths.
Each environment's four-cell matrix binds one exact component artifact, while
the profile, configuration, and authority-policy identities above remain
shared. No cross-environment Component byte-identity claim is made.

Both outer bundles contain exactly
`["cross-execution-path-portability"]`. They explicitly record strict
Component Model runtime independence as `not-proven`, and current-roadmap
cross-runtime, cross-ISA, transparent migration, performance, and production
as `not-claimed`. All four cells report no fallback, no incomplete marker
exists, and every current source/destination ISA observation is x86-64.
