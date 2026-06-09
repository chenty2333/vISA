# vISA CI Docker Parity Result

## Goal
Make CI match the Docker development environment so local Docker validation is repeatable in CI.

## Result
Completed. CI now builds `visa-dev:latest` from the project `Dockerfile`, then runs the required gates through the Docker development image with `scripts/ci-gate.sh`. Local developers can run the same gates with `scripts/run-docker-ci-gate.sh`.

The workflow uses Docker Buildx GitHub Actions cache for image layers and `actions/cache` for bind-mounted `.ci-cache/` Cargo registry, Cargo git, target, and LTP cache directories. The Dockerfile accepts explicit runner uid/gid and reuses an existing group id if needed, so the container can write to checkout/cache bind mounts without relying on host Rust or implicit local toolchain state.

## Evidence
Verified:

- shell syntax for `scripts/ci-gate.sh` and `scripts/run-docker-ci-gate.sh`
- workflow YAML shape includes Docker image build, cache steps, and all required gates
- `docker compose -f compose.yaml -f compose.ci.yaml config --quiet`
- Docker image rebuild after the uid/gid Dockerfile change
- `scripts/run-docker-ci-gate.sh --ci-cache metadata`
- `scripts/run-docker-ci-gate.sh --ci-cache --skip-build all`
- legacy-name literal scan outside git metadata, `target`, and `.ci-cache`
- legacy filename scan outside git metadata, `target`, and `.ci-cache`
- `git diff --check`

The complete Docker gate set ran metadata, format, wasm check, `visa-conformance`, and kernel target check in the dev container. The kernel target check still emits existing dead-code warnings.

## Remaining Risk
First CI runs after Dockerfile, lockfile, or toolchain changes can still be slow while Buildx and Cargo caches warm. The workflow has been locally validated for syntax, Compose config, and container execution, but remote GitHub Actions must still run on the hosted runner to prove hosted-cache behavior.
