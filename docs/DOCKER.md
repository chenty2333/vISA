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
scripts/run-docker-ci-gate.sh
scripts/run-docker-ci-gate.sh metadata fmt
scripts/run-docker-ci-gate.sh check-wasm visa-conformance kernel
```

`scripts/run-docker-ci-gate.sh` builds the same development image and runs
`scripts/ci-gate.sh` inside it. CI uses the same gate script through
`compose.yaml` plus `compose.ci.yaml`, so Rust, target components, QEMU/OVMF,
and LTP helper dependencies come from the Docker image rather than from the host
runner. `compose.ci.yaml` bind-mounts `.ci-cache/` directories for Cargo
registry, Cargo git checkouts, target artifacts, and the LTP cache so GitHub
Actions can persist them with `actions/cache`. The GitHub Actions workflow also
builds `visa-dev:latest` with Docker Buildx and the GitHub Actions build cache,
then uses Compose only to run gates against that image.

Individual gate names are:

```sh
metadata
fmt
check-wasm
visa-conformance
kernel
```

Inside the container, `VISA_LTP_BUILD_BACKEND=host` is set so
`scripts/build-visa-ltp-static-syscalls.sh` uses the container's own toolchain
instead of starting nested Docker.
