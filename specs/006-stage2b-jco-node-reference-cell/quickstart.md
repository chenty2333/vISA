# Stage 2b Jco/Node Reference Cell Verification

## Entry Baseline

Finish `005-stage2a-runtime-adapter-contract` first. Retain its latest
Wasmtime-to-Wasmtime 31/31 bundle, independent-verifier result, component and
profile digests, portable-state bytes, normalized traces, final/replay state
digests, authority/fencing observations, and dependency audit.

The feasibility spike is not the acceptance run. Stage 2b must build the path
inside the repository, run the unchanged registry, and produce new evidence.

## Verify the Pinned Execution Toolchain

Verify the checked-in Cargo lock, source constants, and selected Node binary:

```sh
python3 scripts/check-jco-node-toolchain.py
```

The accepted baseline is:

```text
Jco                         1.25.2
js-component-bindgen        2.0.11
wasmtime-environ lineage    45.0.1
adapter-private RPC         protocol 3
Node                        v24.15.0
V8                          13.6.233.17-node.48
```

The check verifies the exact `js-component-bindgen` and `wasmtime-environ`
Cargo pins/checksums, the adapter's source constants, the Docker archive pins,
and the exact Node executable used by the adapter. There is no npm install or
Jco CLI fallback. The `wasmtime-environ` entry is required disclosure about
translation lineage; it is not evidence that the Node guest executes on
Wasmtime.

## Focused Edit Loop

```sh
cargo fmt --all --check
cargo check --locked -p visa_component_adapter -p visa_jco_node \
  -p visa_wasmtime -p visa-system -p visa-conformance
cargo test --locked -p visa_component_adapter -p visa_jco_node \
  -p visa_wasmtime -p visa-system -p visa-conformance
cargo clippy --locked -p visa_component_adapter -p visa_jco_node \
  -p visa_wasmtime -p visa-system -p visa-conformance \
  --all-targets -- -D warnings
python3 scripts/check-dependency-direction.py
python3 scripts/check-stage1-deletions.py
python3 scripts/check-jco-node-toolchain.py
```

Focused tests must establish:

- the Jco input bytes and digest are identical to the Wasmtime Component input;
- translation is deterministic in meaning and every generated file is bound by
  a sorted runtime-local manifest, even when non-semantic paths make aggregate
  generated-tree digests vary;
- preflight does not import/instantiate the guest or mutate provider,
  coordinator, journal, bindings, or canonical state;
- destination Node import/instantiation occurs only after durable commit;
- pre-spawn revalidation binds the exact driver and generated graph selected by
  preflight, while the adapter internally validates the actual Node/V8 `ready`
  envelope without retaining it;
- all WIT `u64`, byte-list, option, result, and error values round-trip without
  JavaScript precision loss;
- malformed, duplicate, out-of-order, missing/mismatched terminal-settlement,
  trailing-frame, oversized, and EOF RPC paths produce structured failures
  rather than engine-text assertions; production timeout policy remains outside
  this research-cell claim;
- KV/timer host calls reach the shared Rust host bridge and coordinator exactly
  once, with no Node provider access or second effect derivation;
- owned resource methods and explicit drops update the Rust typed table, freeze
  observes an empty table, and rollback recreates fresh IDs;
- source and destination use different Rust/Node processes and handle
  namespaces; and
- selecting JcoNode can never instantiate or retry through `visa_wasmtime`.

## Run the Named Cell

The completed slice adds a dedicated locked gate:

```sh
scripts/ci-gate.sh system-jco-node
```

For a retained manual run, use the explicit runtime pair exposed by the
completed runner and validate the resulting Stage 1 bundle in a separate
process:

```sh
mkdir -p "$PWD/target/visa-system"
artifact_root="$(umask 077; mktemp -d \
  "$PWD/target/visa-system/jco-node-XXXXXX")"
cargo run --locked -p visa-system --bin visa-system -- \
  cell jco-node jco-node "$artifact_root"
cargo run --locked -p visa-conformance --bin visa-conformance -- \
  stage1 "$artifact_root/stage1-evidence.json" "$artifact_root"
```

The explicit cell selector requires a `JcoNode -> JcoNode` pair, never a
default or fallback. The run must contain all 31 registered cases. Cases whose
accepted behavior rejects before destination instantiation must say so; they
must not fabricate a destination typed instantiation observation.

## Regression and Container Acceptance

Run the existing gates and both system cells:

```sh
scripts/ci-gate.sh fast
scripts/ci-gate.sh full
scripts/ci-gate.sh system
scripts/ci-gate.sh system-jco-node
scripts/run-docker-ci-gate.sh full
scripts/run-docker-ci-gate.sh system
scripts/run-docker-ci-gate.sh system-jco-node
```

The ordinary `system` tier retains the Wasmtime-to-Wasmtime 31-case reference
cell. `system-jco-node` runs JcoNode-to-JcoNode and invokes the independent
validator. Neither tier may silently run the other adapter.

## Evidence Checks

For the retained JcoNode bundle, verify:

- 31/31 case IDs and accepted outcomes;
- the original Component/profile digests match the Wasmtime baseline;
- `VISACS01` portable state, normalized traces, final/replay state digests,
  authority/fencing, receipts, and fault schedules satisfy the same rules;
- source and destination identities came from worker preflight, not a runner
  constant;
- positive cases include typed instantiation inferred from successful protocol
  progression after adapter-internal Node/V8 startup validation;
- toolchain and matrix manifests name and hash Jco, the translator dependency
  lineage, Node/V8, the Cargo/archive locks, driver/RPC sources, the aggregate
  generated tree, the driver, and the ordered core-module digest list;
- raw transcripts show synchronous host calls returning through the Rust
  coordinator and explicit owned-resource drops;
- no selected JcoNode transcript, dependency, or identity shows a Wasmtime
  guest fallback; and
- the only claim is cooperative stateful component handoff, with strict
  Component Model runtime independence explicitly marked not proven.

Bundle IDs, timestamps, process/RPC/handle IDs, generated paths, diagnostics,
and whole-bundle hashes are not equality targets across the two paths.
The retained bundle contains neither the runtime-local per-file manifest nor
the adapter-consumed `ready` envelope.

## Completion Evidence to Record

- exact Cargo/archive-lock and toolchain-check hashes;
- preflight-verified Jco, `js-component-bindgen`, disclosed
  `wasmtime-environ`, Node, and V8 identities;
- original Component digest, aggregate generated-tree digest, driver digest,
  and ordered core-module digest list;
- focused test, strict-Clippy, and dependency results;
- retained local and Docker JcoNode bundle paths, IDs, SHA-256 values, and
  31/31 counts;
- independent JcoNode verifier results;
- retained Wasmtime regression bundle paths, IDs, hashes, 31/31 counts, and
  verifier results; and
- the explicit claim statement: Stage 2b proves one Jco-translated Component
  same-path execution cell; Stage 2c separately proves the mixed execution
  paths, while strict independent Component Model runtime portability remains
  unproven.

## Final Stage 2b Evidence

The final host and Docker JcoNode system gates passed all 31 cases and the
generic independent Stage 1 artifact verifier:

| Environment | Root | Bundle ID | Evidence SHA-256 | Result |
| --- | --- | --- | --- | --- |
| Host | `target/visa-system/jco-node-zPFIRg` | `stage1-1783809975021-06da27e97f68c1d4` | `2696a869fb12dc41e5302fddb3ed41f4a4db1c073f5c64a840982eee8be708da` | 31/31; generic Stage 1 verifier passed |
| Docker linux/amd64 | `/workspace/target/visa-system/jco-node-MhDDS6` | `stage1-1783810642577-06da27e97f68c1d4` | `684dafb523c50d8eefb431cc64efc9ec375666d1cbb117f9bc867b4cccc52a24` | 31/31; generic Stage 1 verifier passed |

The final Wasmtime regression bundles are the host
`target/visa-system/stage1-ucuQ5F` and Docker
`/workspace/target/visa-system/stage1-8erIDc` records in the Stage 2a
quickstart; both are 31/31 and independently verified.

Stage 2b acceptance is deliberately composed. The generic Stage 1 verifier
checks bundle structure, referenced artifacts, and semantic evidence. The
locked Jco toolchain gate separately checks the accepted toolchain and source
constants. The standalone Stage 1 verifier alone does not prove the exact Jco
initialize provenance. Stage 2c's outer verifier later cross-checks raw
initialize observations against exact Jco/Node identities, translation
options, Node executable path/hash, RPC protocol 3, and no-fallback fields.

The two generic bundles were independently rechecked at their native paths:

```sh
target/debug/visa-conformance stage1 \
  target/visa-system/jco-node-zPFIRg/stage1-evidence.json \
  target/visa-system/jco-node-zPFIRg
docker compose -f compose.yaml run --rm -T dev \
  /workspace/target/debug/visa-conformance stage1 \
  /workspace/target/visa-system/jco-node-MhDDS6/stage1-evidence.json \
  /workspace/target/visa-system/jco-node-MhDDS6
```

The accepted execution identity is:

```text
Jco compatibility identity    1.25.2
js-component-bindgen          2.0.11
wasmtime-environ lineage      45.0.1
adapter-private RPC protocol  3
Node                          24.15.0
V8                            13.6.233.17-node.48
Node executable SHA-256       d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c
Rust toolchain channel        nightly-2026-06-07
```

Protocol 3 requires every terminal response to be followed by its matching
`settled` frame; missing, mismatched, trailing, or EOF boundaries fail closed.

The retained runtime observations use these exact Node executables:

| Environment | Canonical Node path | Node executable SHA-256 |
| --- | --- | --- |
| Host | `/home/ava/.nvm/versions/node/v24.15.0/bin/node` | `d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c` |
| Docker linux/amd64 | `/usr/local/bin/node` | `d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c` |

Both environments record the exact locked `translation_options` string:

```json
{"schema":"visa-jco-node-transpile-options-v1","name":"handoff-component.component","no_typescript":true,"instantiation_mode":"sync","import_bindings":"js","nodejs_compat_disabled":false,"base64_cutoff":0,"tla_compat":false,"valid_lifting_optimization":false,"tracing":false,"no_namespaced_exports":true,"multi_memory":false,"guest":false,"strict":true,"asmjs":false}
```

The retained aggregate translation provenance is environment-specific:

| Environment | Generated tree SHA-256 | Driver SHA-256 | Ordered core-module SHA-256 values |
| --- | --- | --- | --- |
| Host | `0ba4c9f4b0a14b4264cd19600dd283bcf3beac0845e6476ca891b6f1a2167da9` | `fe3f73f5f39c7e6a7cb12d175b95744dabe0d243a5f99704b95586696b3c8473` | `bebc950891f8c4290b0592e5ab6ae408b29f5683a114983657fb2d2c1aaa62b9`, `12e182b97bffc401f5e54a493fd45c14a22030d958acfdf1f74303103d4d6394`, `4a010b325d525856b8e71cc4cc9cb42cfe12c395ebcc8aee9d44b9fc83e66029` |
| Docker linux/amd64 | `039daddf7e531c250959aa55885055e3a6dd54cf383c16748ef91325a288d4fc` | `fe3f73f5f39c7e6a7cb12d175b95744dabe0d243a5f99704b95586696b3c8473` | `049d81294171d2458051d47a4efbe471d904d6109906f79b89b4961ab20d675d`, `12e182b97bffc401f5e54a493fd45c14a22030d958acfdf1f74303103d4d6394`, `4a010b325d525856b8e71cc4cc9cb42cfe12c395ebcc8aee9d44b9fc83e66029` |

Host and Docker aggregate/core digests may differ because generated modules can
embed non-semantic absolute build paths. The runtime-local manifest still binds
every file within each run; no cross-environment generated-byte identity is
claimed.

The retained bundles share source digest
`c1fe1818a110d6dcf858e4072b7ff58427324da56490d005f2339763fcf3f656`,
toolchain digest
`33bd760b0d42eee90cf79af2bd3a30df1de6535fb53d34ebbb2542625adc9bf3`,
profile digest
`da6babca82e0e34ac32c591d9494fb77d8d2c6f7b4201c7feb67669400da2241`,
configuration digest
`06da27e97f68c1d45919dcacf70b7d92ef1bae0cafbfa3ad8e0ddef9128eb07b`,
and authority-policy digest
`853697466509d7b106bf7f099e870a934c42047c42d85f9750ca21d4a3c6ab3e`.
Their source manifests bind the 235-byte `preflight.mjs` bootstrap at SHA-256
`171a57d9b2f036159c439c8f71760cb3ace41c6e519af1d12f7c8d1fd0f485be`.
Their Component digests are respectively
`4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b`
and
`d4f1a2e8bfacb0659d26569850a0f489c861a021ecad4cf068ca5d67748e04eb`.

The pinned Docker image is
`sha256:ca7c91e726c7fbce36cb152fcf56b8bc89d7c773ef7d4e3817cd8ad5051bfce0`.
Focused protocol/resource/preflight/no-fallback tests, strict Clippy, and host
and Docker `full` gates all passed. Stage 2c separately supplies the mixed
execution-path result; strict independent Component Model runtime portability
remains unproven.
