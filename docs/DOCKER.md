# Docker Development Environment

The development image contains the nightly Rust toolchain declared by
`rust-toolchain.toml`, including `rust-src`, `rustfmt`, `clippy`,
`llvm-tools-preview`, `wasm32-unknown-unknown`, and `x86_64-unknown-none`.
It also includes QEMU/OVMF for the kernel runner and the C/autotools packages
used by the LTP helper scripts.

Build the image:

```sh
docker compose build dev
```

Open a shell:

```sh
docker compose run --rm dev
```

On SELinux-enabled hosts, `compose.yaml` disables container labeling for the
development service so the bind-mounted workspace remains readable inside the
container. If the current user was just added to the host `docker` group, open
a new login session before running Docker without `sudo`.

Useful checks:

```sh
docker compose run --rm dev cargo metadata --no-deps --format-version 1
docker compose run --rm dev cargo fmt --all --check
docker compose run --rm dev cargo test -p visa-conformance
docker compose run --rm dev cargo test -p visa_runtime
docker compose run --rm dev cargo test -p visa_wasmtime
docker compose run --rm dev cargo check-wasm
docker compose run --rm dev cargo check -p kernel --target x86_64-unknown-none
```

Inside the container, `VISA_LTP_BUILD_BACKEND=host` is set so
`scripts/build-visa-ltp-static-syscalls.sh` uses the container's own toolchain
instead of starting nested Docker.
