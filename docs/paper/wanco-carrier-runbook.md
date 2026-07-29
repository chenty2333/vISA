# Wanco AOT regular-file carrier composition runbook

Status: implementation complete; a canonical result is earned only by the
clean exact-SHA `system-wanco-carrier` lane at the integrated revision. A dirty
development build or smoke run is a non-claim check.

Last reviewed: 2026-07-29.

## Question and boundary

This experiment asks one composition question: when Wanco preserves Wasm
compute progress across a real checkpoint/restore handoff, does the canonical
vISA regular-file endpoint preserve the resource semantics that the compute
carrier does not preserve by itself?

The registered profile has exactly two cases:

| Case | Observable relation |
| --- | --- |
| `read-write-offset` | Reads, writes, and the logical offset continue without replaying or skipping an operation. |
| `append-continuity` | The source append, its idempotent replay, and the destination append occur exactly once and in logical order. |

Each run creates one uninterrupted control for both comparisons. It then
evaluates two candidate routes against that same control:

| Route | Handoff behavior | Required oracle result |
| --- | --- | --- |
| `carrier-only` | Wanco completes its checkpoint/restore lifecycle and restores compute progress in a fresh process, but no vISA handoff lifecycle or destination binding is performed. The first resource access fails closed. | Rejected; both registered projections must diverge. |
| `visa-plus-carrier` | Wanco restores compute progress while a fresh canonical destination restores, validates, and resumes the portable resource state. | Accepted; both registered projections must equal the uninterrupted control. |

Only these two candidate routes belong to the canonical matrix. The Wanco host
endpoint has no raw-fd or pathname fallback. Missing the canonical endpoint is
an observed fail-closed condition, not an alternate file implementation.

This is a same-host, native x86-64 Linux Wanco experiment. It does not use the
physical AArch64 `Ha` endpoint and does not establish Wanco cross-host or
cross-ISA behavior. The native Wasmtime `Hx->Hx`, `Hx->Ha`, `Ha->Hx`, and
`Ha->Ha` matrix is a separate Stage 4 evaluation documented in
`docs/paper/arm-stage4-runbook.md`.

## Locked carrier and thin host import

`third_party/wanco/source-lock.json` pins official Wanco upstream revision
`3c2e400dda5ce51d78333223f6fcbde08e6b198a` and tree
`a84f6f0d15de11b24a7b9566874c4cae3c53474e`. Its retained patches are build-only
Debian/LLVM fixes; they do not modify Wanco compiler or checkpoint semantics.
`scripts/check-wanco-carrier-source.py` verifies the source lock, patch order,
patch digests, and patched Dockerfile before the carrier image can be used.

The locked image compiles both WAT workloads with Wanco checkpoint support.
`crates/runtime/visa_wanco_carrier/guest/visa_ha_endpoint.cc` is a thin host
import: it sends typed `OPEN`, `READ`, `WRITE`, and `APPEND` requests over a Unix
socket and records the exact response events. It never opens the subject file,
stores a native file descriptor, or fabricates a rebinding result. Wanco itself
still produces `checkpoint.pb` on `SIGUSR1` and starts a fresh executable with
`--restore /work/checkpoint.pb`.

The source process completes progress 4 before capture. The restored process
continues at progress 5 and completes progress 12. Per-case progress receipts
must prove source `[0,1,2,3,4]`, destination `[5,6,7,8,9,10,11,12]`, and one
combined logical sequence `[0..12]`.

The Wanco process is not privileged and does not use host networking or host
devices. Docker's SELinux process label is disabled for these workload
containers because they must connect to an unconfined host-side Unix-socket
peer; the evidence environment records that setting explicitly.

## Canonical vISA endpoint

`crates/runtime/visa_wanco_carrier/src/canonical.rs` is the resource endpoint.
It uses the repository's real `Coordinator<SqliteProvider>`, `ProfileBinding`,
regular-file profile state, provider execution path, authority/lease state,
operation ledger, and lifecycle calls. It is a direct canonical resource
endpoint, not a producer-side reconstruction of vISA behavior.

For `visa-plus-carrier`, the order is:

1. Source resource operations execute through the canonical source endpoint.
2. `SAFE_POINT` performs begin-quiesce, prepare-safe-point, portable-state
   encode/decode validation, freeze-runtime, and commit-safe-point.
3. Only then does the runner send `SIGUSR1` to make the Wanco compute
   checkpoint.
4. `EXPORT` publishes the canonical snapshot, portable regular-file state, and
   a separately identified storage image.
5. A destination endpoint starts with a fresh SQLite database and a distinct
   node-local root/file object, then performs prepare-destination and
   commit-handoff.
6. A fresh Wanco `--restore` process reaches progress 5 but is held at a resume
   gate. The runner issues canonical `RESUME`, which validates/restores the
   portable state and activates the destination, before releasing compute.
7. Destination resource operations execute through that endpoint, followed by
   endpoint shutdown and receipt publication.

The transfer is portable by construction: it contains no absolute path,
source/destination root, device number, inode number, or native object identity.
The deployment/storage image is explicit and separate from the canonical
profile payload. The runner and recorder both verify that source and destination
use different databases, roots, root identities, file identities, and node
identities while retaining the same logical cell, component digest, profile
digest, workload, and regular-file resource identity.

The `carrier-only` source still uses the same canonical source endpoint before
capture. Its restored Wanco process receives no destination resource binding;
the thin host import therefore records `lost-process-local-binding` and returns
an error at the first destination resource call. This is the carrier-alone
baseline the positive composition must improve upon. Wanco's successful
checkpoint/restore lifecycle is a compute-carrier fact; it is not evidence that
the nine-action vISA resource-handoff lifecycle occurred. The carrier-only
observation therefore intentionally contains no successful committed vISA
lifecycle, while `visa-plus-carrier` records that lifecycle through the
canonical source and destination endpoints.

## Observation and independent verdict

`visa-wanco-carrier record` is a verdict-free observation producer. It reads the
actual endpoint event streams, process status/stdout, checkpoint bytes, final
subject, and canonical source/destination receipts. It does not infer resource
facts from progress or route names. Successful raw events must match a typed
canonical operation receipt exactly, including request, result, before/after
state, version, digest, offset, lease/binding, and ledger observations.

For the positive route, recording fails if the source and destination receipts
do not agree on `cell_id`, component digest, profile digest, workload, portable
profile state, and logical resource identity, or if their native node/root/file
identities are not genuinely distinct. Protocol events are transcribed from the
recorded lifecycle actions/results rather than a secondary synthetic event
source.

The separate `visa-regular-file-oracle` executable validates each observation,
recomputes its raw-observable projection, and compares the candidate with the
shared uninterrupted control. In strict carrier-probe mode it additionally
checks the route, artifact root, locked Wanco revision, checkpoint/artifact
closure, and topology. Producer independence here means independence from
producer summaries, caches, and verdicts; it does not claim independently
authored software or hostile-host attestation.

The carrier-only negative is deliberately projection-bearing rather than
structurally unreadable. For each of the two cases, its candidate validation
must contain exactly
`invalid-committed-handoff-lifecycle`, `unexpected-derived-terminal`, and
`semantic-assertion-failed`: no successful vISA handoff lifecycle was observed,
the derived terminal cannot be a committed handoff, and the resource-continuity
relation fails. The outer comparison must then contain exactly one
`observable-projection-mismatch` per case. Conversely, `visa-plus-carrier` must
have zero candidate-validation and outer findings.

## Canonical execution and expected closure

Run from a clean native x86-64 Linux checkout with Docker. `HEAD` must equal the
requested GitHub SHA and the worktree must remain clean for the whole run:

```sh
GITHUB_SHA="$(git rev-parse HEAD)" \
  scripts/run-docker-ci-gate.sh --ci-cache --skip-build system-wanco-carrier
```

The lane rebuilds/verifies the locked Wanco image, compiles both AOT workloads,
and performs three independent runs. Each run has one shared uninterrupted
control and both required candidate routes. The required aggregate is:

```text
carrier-only:       3/3 rejected, with exactly two outer projection mismatches
                    and the exact three-finding lifecycle/terminal/semantic
                    triplet for each case per run
visa-plus-carrier:  3/3 accepted, with no oracle findings
```

The runner seals `HEAD` and worktree cleanliness again after execution. It then
moves the complete evidence tree from `wanco-carrier` to a previously unused
`wanco-carrier-relocated` path and reruns every strict oracle comparison there.
All observation/checkpoint/canonical-receipt/transfer references are
content-addressed and must resolve under the relocated artifact root. Finally,
`visa-evidence-matrix` validates the typed expected and observed semantic
outcomes against the canonical six-dimensional evidence matrix.

The principal receipts are:

```text
.ci-artifacts/wanco-carrier-relocated/matrix-receipt.json
.ci-artifacts/wanco-carrier-relocated/relocation-receipt.json
.ci-artifacts/wanco-carrier-relocated/evidence-matrix-run.json
```

The workflow artifact is named
`wanco-regular-file-carrier-system-evidence`. A permanent archive is not a claim
prerequisite: this bounded run tree can be retained for exact-byte audit or
regenerated from its clean exact revision.

## Non-claim development smoke

Before integration, it is useful to compile the current C++ host import and both
WAT workloads in the locked Wanco image and to run focused Rust tests. Such a
smoke may write only generated files under `target/.ci-cache`; it must not bypass
the runner's clean-tree guard, publish matrix receipts, update the evidence
matrix, or be cited by the paper as an earned result. Only the clean exact-SHA
lane above can close the claim.

## Explicit non-claims

This cell does not prove:

- arbitrary Wanco applications, resources, or regular-file relations beyond
  the two registered cases;
- migration of kernel file descriptors or ambient process resources;
- Wanco cross-host, AArch64, or cross-ISA execution;
- provider-, kernel-, or hostile-host-enforced vISA authority;
- independence of verifier authorship or freedom from a shared specification
  error; or
- performance or production migration-service readiness.
