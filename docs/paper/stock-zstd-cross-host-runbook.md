# Stock-zstd cross-host clean-handoff supporting cell

Status: runner and independent validator implemented; no result is claimed until
an exact-revision receipt has passed the commands below on two distinct native
x86-64 Linux hosts.

## Scope

This cell performs one stock zstd 1.5.7 handoff after successful Preview 1
`fd_write` occurrence 64. The source uses the canonical
`checkpoint_source()` implementation from
`scripts/run-stock-zstd-migration-matrix.py`; there is no byte-counter or signal
approximation. The controller freezes and exports the source provider, transfers
the Wanco checkpoint and vISA resource capsule, restores a fresh provider on the
remote host, fences the source, and only then activates and resumes the remote
Wanco process.

The retained compressed bytes are fetched to the controller. The standalone
validator ignores producer verdicts, runs a caller-selected package-owned native
zstd CLI, regenerates the canonical 24 MiB input, decompresses the retained
bytes, and compares their SHA-256 and size with the uninterrupted control.

This is a single correctness-supporting run. It is not a statistical performance
result and does not establish cross-ISA execution, distributed fencing,
crash/reboot or partition recovery, hostile-host security, arbitrary workloads,
SQLite cross-host execution, or production orchestration.

## Endpoint requirements

The destination must provide:

- native x86-64 Linux and Python 3;
- OpenSSH access to a fresh per-run `/tmp` directory;
- a separately confirmed ED25519 host-key SHA-256 fingerprint; and
- enough space for the checkpoint, capsule, exact Wanco runtime-library closure,
  and approximately 24 MiB compressed output.

Docker and a repository checkout are not required remotely. The controller
extracts the exact runtime-library closure from the source-locked Wanco image and
transfers the release provider/proof binaries. Password authentication, if used,
is handled directly by OpenSSH on the controlling terminal; the runner never
reads, stores, prints, or publishes the password.

The Raspberry Pi Zero 2 W Stage-4 endpoint is intentionally unsuitable for this
cell: the current Wanco stock-zstd AOT carrier is x86-64-only. Do not emulate the
x86-64 AOT on that endpoint and label it native cross-host execution.

## Run

Start from a clean exact revision. Obtain the expected host-key fingerprint over
an already trusted channel, then run:

```sh
python3 scripts/run-stock-zstd-cross-host.py \
  --artifact-root target/final-stock-zstd-build \
  --stock-zstd /usr/bin/zstd \
  --remote user@destination.example \
  --port 22 \
  --host-key-sha256 SHA256:<preconfirmed-ed25519-fingerprint> \
  --output target/final-stock-zstd-cross-host/receipt.json \
  --skip-build
```

For key authentication, add `--identity-file /secure/path/to/id_ed25519`. The
identity must be a non-symlink regular file inaccessible to group and other
users. `--keep-work` may retain private diagnostics for a failed run; it is not
part of the paper artifact.

The runner refuses a dirty checkout, an existing output root, a host-key
mismatch, a non-x86-64 remote endpoint, an incomplete transfer manifest, an
invalid checkpoint/capsule/proof, source/destination endpoint identity reuse,
remote process failure, provider non-progress, native decompression failure, or
compressed bytes different from uninterrupted execution.

## Verify

```sh
revision=$(git rev-parse HEAD)
python3 scripts/stock_zstd_cross_host.py validate \
  target/final-stock-zstd-cross-host/receipt.json \
  --expected-revision "$revision" \
  --stock-zstd /usr/bin/zstd
python3 scripts/test-stock-zstd-cross-host.py
```

The v1 receipt above is the private execution authority. It retains the pinned
SSH witness and endpoint details needed to audit the original operation and
must not be copied into a paper package or Zenodo deposit.

## Public derivative

Create an explicitly named public v2 projection only after v1 validates. The
projection does not rerun the workload:

```sh
python3 scripts/make-stock-zstd-cross-host-public-receipt.py create \
  target/final-stock-zstd-cross-host-316b8d7 \
  target/stock-zstd-cross-host-public-v2 \
  --expected-revision 316b8d78cbe2ad9f341efe96d3bf4b0b9477847e \
  --stock-zstd /usr/bin/zstd
python3 scripts/make-stock-zstd-cross-host-public-receipt.py validate \
  target/stock-zstd-cross-host-public-v2/receipt.json \
  --expected-revision 316b8d78cbe2ad9f341efe96d3bf4b0b9477847e \
  --stock-zstd /usr/bin/zstd
python3 scripts/test-stock-zstd-cross-host-public-receipt.py
```

The v2 allowlist retains the receipt, controller timing, process streams,
control oracle, shared compressed output, transfer manifest, and redacted
endpoint/status observations. It binds the private v1 receipt by SHA-256 but
does not retain a hostname, address, kernel/OS fingerprint, legacy endpoint
identifier, SSH key/fingerprint, or `raw/known_hosts`. Checkpoint bytes,
capsule bytes, provider state, runtime libraries, credentials, and temporary
remote directories remain private.
