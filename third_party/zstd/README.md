# Stock zstd carrier fixture

This directory locks and builds the unmodified upstream zstd v1.5.7 CLI as
the first stock-application workload for the vISA/Wanco migration path.

`zero upstream source patches` has a precise meaning here:

- the checkout must be the exact PGP-signed annotated `v1.5.7` tag object,
  peeled commit, and commit tree;
- the checkout must be clean before it is archived into the build sandbox;
- `source-lock.json` contains an empty `source_patches` array;
- the compatibility object under `abi/` is an additional guest object and
  does not edit, replace, or generate an upstream zstd source file.

The native Wanco hostcall bridge is built in the isolated
`bridge-workspace.toml` workspace with its own `bridge-Cargo.lock`.  It
contains only `visa_wasi_protocol` and `visa_wanco_wasi`; both workspace and
resolved dependencies are content-locked here, and the build uses the exact
Rust toolchain from the canonical Wanco source lock.  This avoids accidentally
inheriting unrelated nightly-only members from the main development workspace.

The tag-object ID binds the signature bytes, but the checker deliberately does
not claim a local Web-of-Trust decision about the signing key.  The source lock
also content-pins the build recipe, compatibility object, Dockerfile, exact
Debian package payloads, expected Wasm digest, import list, and Wanco source
lock.  A retained build receipt additionally binds the bridge, carrier
compiler/runtime, container images, and every published artifact.

## Metadata ABI

wasi-libc leaves zstd's POSIX `chmod` and `chown` calls as imports in module
`env`.  Resolving those names while linking Wanco's native AOT output is
unsafe: Wanco prepends `ExecEnv *`, while glibc exports incompatible native
functions with the same names.

`abi/visa_zstd_posix_compat.c` resolves the POSIX calls inside WebAssembly and
uses these collision-safe imports:

```text
visa_wasi_metadata_v1::visa_wasi_metadata_path_chmod
visa_wasi_metadata_v1::visa_wasi_metadata_path_chown
```

Both imports are length-delimited, use root preopen fd 3, and return a WASI
Preview1 errno.  Wanco lowers them to native functions with an `ExecEnv *`
first argument.  The vISA Wanco bridge owns those exact symbols.

The formal build never uses `--allow-undefined`.  The source-lock checker also
rejects any final Wasm module that retains `env::chmod` or `env::chown`.

## Current carrier qualification

Run:

```bash
python3 scripts/check-zstd-source.py
python3 scripts/test-check-zstd-source.py
scripts/build-stock-zstd.sh
scripts/run-stock-zstd-migration-matrix.py --skip-build
```

The source lock states the one optimization level that the build is allowed to
publish.  An environment override cannot silently change that level.

The first stock-zstd `-O1` capture exposed and failed closed on a Wanco
stackmap lookup defect:

```text
The difference between pc_offset and the instruction offset in the stackmap
record is too big
```

The canonical Wanco v2 patch set now contains a narrowly validated x86-64
stack-adjustment fix for that defect and validated exact-length LZ4 checkpoint
decoding.  This source lock therefore selects only the content-pinned Wanco v2
`-O1` carrier.  That carrier qualification is not itself an application-level
migration result: stock zstd is qualified separately by the transparent
migration matrix. The v3 runner pre-arms exact successful `fd_write`
occurrences on `output.zst`, waits until the durable response has been written
back into guest memory, releases Wanco to checkpoint, and binds that barrier
token into the provider freeze. It does not poll byte counters or signal the
container to choose a cut. The matrix also uses a fresh provider/process,
external native-zstd byte comparison, and negative cells. The build script
rejects optimization overrides so an `-O0` diagnostic cannot be mislabeled as
the qualified matrix input. The matrix v3 runner also resolves the live Wanco
Docker image ID and cross-checks it through both build receipts and both source
locks before it is allowed to state that artifact bindings were verified.
