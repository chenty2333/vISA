# Native AArch64 Stage 4 supporting-evaluation runbook

Status: completed and reproducible supporting evaluation. This note is not a
canonical truth source and does not create or close a registry claim.

Last reviewed: 2026-07-29.

## Result and scope

Revision `e88b844e0c9f5f9fef507c456a3001b046f054db` completed the native
Stage 4 matrix identified in evidence as
`native-arm-cross-isa-continuity-v1`. In paper and evidence-map shorthand this
is **S4-N**. It supplements, but does not replace or widen, the closed
**S4-Q** `named-target-substrate-continuity-v1` and
`emulated-cross-isa-continuity-v1` claims.

S4-N fixes Wasmtime, the Stage 1 timer/KV Component, common input, 31-case
registry, and semantic normalizer while varying the source and destination
native ISA/host:

| Endpoint | Native target | Retained host identity |
| --- | --- | --- |
| `Hx` | `x86_64-unknown-linux-gnu` | Physical x86-64 Linux host; kernel `7.1.4-204.fc44.x86_64`; `systemd-detect-virt` returned `none` |
| `Ha` | `aarch64-unknown-linux-gnu` | Raspberry Pi Zero 2 W Rev 1.0; AArch64 Linux kernel `6.18.34+rpt-rpi-v8`; device-tree model retained; `systemd-detect-virt` returned `none` |

These controlled-host observations and native launchers are not cryptographic
hardware attestation or proof against an undisclosed lower virtualization
layer.

The four cells `Hx->Hx`, `Hx->Ha`, `Ha->Hx`, and `Ha->Ha` each passed all 31
cases: 124/124 completed executions, four independently verified inner Stage 1
bundles, and 31/31 normalized observable groups equal across all cells. The
outer verifier accepted the complete inventory at the original root and after
the entire directory was moved without rewriting its JSON.

## Provider and transport topology

The provider does not move with the worker. One Hx-native service owns the real
`substrate_host::SqliteProvider` and its SQLite databases:

```text
Hx worker -- local Unix stream -----+
                                    +--> Hx provider service --> SQLite
Ha worker -- SSH reverse Unix stream+
```

For every primary case, source, destination, restart, and audit requests use
one logical database identifier and therefore one provider transaction domain.
The `evidence-verification` case's four supplemental fault domains are
independently reconstructed and bound to their exact eight worker lineages.

This topology establishes native x86-64/AArch64 and cross-host Wasmtime
execution against a shared provider domain. It does not establish provider
cross-ISA execution, provider migration, or a provider running on Ha.

SSH is part of the measured launcher/transport boundary, not a trusted claim
shortcut. The runner requires a separately preconfirmed ED25519 host-key
fingerprint, sets `StrictHostKeyChecking=yes` and `IdentitiesOnly=yes`, copies
the identity into a mode-0600 temporary directory, and never publishes the
private key. The temporary identity, remote worker directory, provider sockets,
database service, and tunnel are removed on exit.

## Prerequisites

- The recorded worker source is revision
  `e88b844e0c9f5f9fef507c456a3001b046f054db`, whose complete declared source
  set is bound by the manifest check below. Use the current runner when
  re-executing: its later SSH identity-plumbing hardening is outside the 40
  worker source roots and does not change that source manifest.
- Hx must have the repository toolchain, Docker Compose, the GNU AArch64
  cross-linker used by `.cargo/config.toml`, OpenSSH client tools, and enough
  local space for the transient evidence tree.
- Ha must be a little-endian LP64 `aarch64-unknown-linux-gnu` system reachable
  by key-based SSH on port 22. `/usr/bin/uname`, `/usr/bin/systemd-detect-virt`,
  `sha256sum`, `chmod`, and `mktemp` must be present.
- The SSH private key must be a non-symlink regular file inaccessible to group
  and other users.
- Obtain the ED25519 host-key SHA-256 fingerprint through an already trusted
  channel before the run. Do not derive the expected value from the same
  unauthenticated connection that the run will use.

## Re-run

From the repository root:

```sh
scripts/run-stage4-native-hardware.sh \
  --identity-file /secure/path/to/id_ed25519 \
  --host-key-sha256 SHA256:<preconfirmed-ed25519-fingerprint> \
  <user>@<aarch64-host>
```

Use `--artifact-parent <directory>` to redirect evidence. Use
`--skip-image-build` only when the exact current Docker development image is
already built. The script:

1. builds release Hx worker/verifier and Ha worker from the current exact
   source;
2. verifies the remote host key, creates a fresh remote `/tmp` root, deploys
   the Ha worker, and checks its SHA-256;
3. records both hosts and target-native launchers;
4. starts the Hx provider service and SSH reverse StreamLocal transport;
5. runs all four cells and all 31 cases per cell;
6. independently verifies the published bundle;
7. moves the complete evidence directory to a new `-relocated` path and
   verifies it again; and
8. prints the relocated artifact root, evidence-bundle path, retained
   `known_hosts` digest, and observed host-key fingerprint.

The final two successful verifier invocations print:

```text
Stage 4 native evidence verified: <artifact-root>/stage4-native-evidence.json
```

To recheck a retained tree independently:

```sh
.ci-cache/stage4-native-hx-target/x86_64-unknown-linux-gnu/release/visa-conformance \
  stage4-native \
  <artifact-root>/stage4-native-evidence.json \
  <artifact-root>
```

## Recorded receipt

The completed run has bundle ID
`stage4-native-6df5cde713c63611703e999f51553f5cc485585213d1957672de18a86ef31206`.

| Artifact or identity | SHA-256 |
| --- | --- |
| Evidence bundle | `b9e67d69c2c6d1095e8bb9ad9539ca60943b955159a3174c60f3795257dec0d1` |
| Matrix | `6df5cde713c63611703e999f51553f5cc485585213d1957672de18a86ef31206` |
| Provider receipt | `0e1b7688ca15dc7507d1429eeaa0bae1b414c242a5dbf2a25ee08ea3120ce0a9` |
| Common input | `a66347ba03a6e3e687abcd2c1d0bd0da6d64692d4a22c78a6e30586e6374ff25` |
| Stage 1 registry | `d306c21c404ea83a91eff9c4b73399d210c75b7e1b6c0c4e0788bc68134ba3d6` |
| All four normalized observables | `45ebae531a31b2c2a31415b88279e621820652ea2a21503a5776744ae59557d9` |
| Hx worker | `a06391a7caca18db6a48abe57ffaa3ca6eeade79a4fbe3f0243ec8751cecd47b` |
| Ha worker | `6a04d5eb4e39ee1c33ce3263347e693bc63ef8156017d37a654cc9a6493b9467` |
| Shared build source | `9426a9d893a9b4bc8551720059bf3faa6a5b6a71c0f9f64ddd0e346515035673` |
| Shared toolchain | `33bd760b0d42eee90cf79af2bd3a30df1de6535fb53d34ebbb2542625adc9bf3` |

An independent post-run check matched all 268 entries in the retained build
source manifest, including each byte count and SHA-256, to the complete Git
tree selected by the 40 declared source roots at revision
`e88b844e0c9f5f9fef507c456a3001b046f054db`.

The independently verified Stage 1 child-bundle hashes are:

| Cell | SHA-256 |
| --- | --- |
| `Hx->Hx` | `536428216ad4c36eb6b5983246b2c19055b6dd7dad87ca3f87cbe5e9684bef8f` |
| `Hx->Ha` | `bd83c880af371c48920ecd0e308de507b7f210401357a1ef4ca8576cb079e857` |
| `Ha->Hx` | `a44138ddd047686e95e39f1c5ed087fa8b7733f5ecd0ba3fdecc034f921d0094` |
| `Ha->Ha` | `433551b4c36c809707741e03731b572e0469746816833ec49a94b197a89f9d0e` |

The full evidence tree is transient evaluation output, not a permanent archive
requirement. Retain it only when exact-byte re-verification is needed; the
script can regenerate a fresh, independently verifiable run. A fresh run uses
new nonces and paths, so it is expected to produce new bundle hashes even when
its semantic result is the same.

## Explicit non-claims

S4-N is a verified supporting profile, not a closed or earned registry claim.
It does not prove:

- provider-substrate cross-ISA execution or provider migration;
- AOT binary portability or transfer of native code, stacks, registers, or
  process checkpoints;
- a second runtime lineage;
- Stage 3 regular-file or logical-request continuity across ISA;
- hostile-host or hostile-transport security, cryptographic attestation, or
  confidentiality;
- no-std/reference-kernel, real-device, 32-bit, or big-endian behavior; or
- performance or production readiness.
