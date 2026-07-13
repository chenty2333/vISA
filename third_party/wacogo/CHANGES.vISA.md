# vISA downstream wacogo derivative

This directory locks the source inputs for
`partite-ai/wacogo v0.0.0-20260617023329-3de16a61796c + vISA downstream
patchset v1`. The upstream source archive is deliberately not vendored. A
production build must supply the byte-exact Go module zip and apply the
committed patch series with `scripts/wacogo-prepare-source.py`.

The qualified object is this pinned derivative, not unmodified upstream
wacogo. Unmodified upstream fails the unchanged vISA Component while resolving
a named key-value error type. No upstream support or merge status is implied.

The three ordered changes are:

1. Preserve named root host `Builder.AddType` declarations through parser
   instance types, runtime type slots, and live exports.
2. Expose typed host-created `own<R>` values and stop their cleanup hooks after
   valid ownership transfer or drop.
3. Expose `Component.CheckInstantiation`, which performs the same required
   import, kind, and subtype checks as real instantiation without executing the
   component plan or a core start function.

The `AddType` change is intentionally qualified only for a host component's
root scope. It is not a claim of complete nested host-scope support. The locked
profile remains x86-64 timer/KV continuity; file/network resources, cross-ISA,
TEE, attestation, and confidential continuity are outside this derivative's
current qualification.

The durable [Runtime B qualification record](../runtime-b-qualification/README.md)
retains the candidate decision, exact input identities, and executable probes.

`source-lock.json` is the machine-readable authority for the upstream module
sum, revision, module-zip digest, ordered patch digests, patched-tree digest,
official Go distribution, and redistribution files. The committed `LICENSE`
is wacogo's upstream Apache-2.0 text. `licenses/` retains the license and NOTICE
files needed by the current runtime dependency closure.

Builds use caller-supplied, pre-fetched inputs with `GOPROXY=off`,
`GOSUMDB=off`, `GOTOOLCHAIN=local`, `GOVCS=*:off`, `GOENV=off`, `GOWORK=off`,
`GOTELEMETRY=off`, `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`, and
`GOAMD64=v1`. Production Go binaries are built with
`-mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid='`. No Cargo
`build.rs` downloads or compiles this runtime.

`scripts/wacogo-build-sidecar.sh` is the supported production build entry
point. It accepts only a pre-fetched official Go archive/toolchain, the locked
wacogo module zip, and a local module cache. It prepares two independent
staging roots, tests the sidecar, checks its public-import and executable-module
lineage, and requires byte-identical static linux/amd64 binaries before it
publishes `target/visa-wacogo/visa-wacogo-runtime` and a build receipt. The
expected binary identity and the committed generated-binding identities are
under `production_artifacts.sidecar` in `source-lock.json`.

Production execution also has locked Linux host requirements. The Rust adapter
copies the verified sidecar into an anonymous executable memfd created with
`MFD_CLOEXEC | MFD_ALLOW_SEALING`, applies and reads back `F_SEAL_WRITE`,
`F_SEAL_GROW`, `F_SEAL_SHRINK`, and `F_SEAL_SEAL`, and executes it through
`/proc/self/fd/<fd>`. The host must mount `/proc/self/fd` and permit that
execution; its kernel and security policy (including SELinux or another LSM)
must allow executable memfds. The adapter requests `MFD_EXEC` where supported
and retries only when `EINVAL` identifies a kernel with the legacy
executable-by-default memfd behavior. A host that cannot satisfy these
requirements fails closed as `UnsupportedRuntimeFeature`; there is no mutable
on-disk execution fallback. The machine-readable form is
`production_artifacts.sidecar.execution_host_requirements` in the source lock
and is copied into every production build receipt.
