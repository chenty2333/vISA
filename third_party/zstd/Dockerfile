ARG WANCO_BASE=visa-wanco-carrier:3c2e400dda5c-597c7b2fd9a3
FROM ${WANCO_BASE}

ARG WASI_LIBC_VERSION
ARG WASI_LIBC_SHA256
ARG CLANG_RT_WASM32_VERSION
ARG CLANG_RT_WASM32_SHA256

SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

# Download exact package versions and verify the package payloads before
# installation.  Version pinning alone is not treated as a content identity.
RUN mkdir -p /opt/visa-zstd-toolchain && \
    cd /opt/visa-zstd-toolchain && \
    apt-get update && \
    apt-get download "wasi-libc=${WASI_LIBC_VERSION}" && \
    apt-get download "libclang-rt-17-dev-wasm32=${CLANG_RT_WASM32_VERSION}" && \
    wasi_deb=$(find . -maxdepth 1 -type f -name 'wasi-libc_*.deb' -print -quit) && \
    clang_rt_deb=$(find . -maxdepth 1 -type f -name 'libclang-rt-17-dev-wasm32_*.deb' -print -quit) && \
    test -n "${wasi_deb}" && \
    test -n "${clang_rt_deb}" && \
    echo "${WASI_LIBC_SHA256}  ${wasi_deb}" | sha256sum --check --strict && \
    echo "${CLANG_RT_WASM32_SHA256}  ${clang_rt_deb}" | sha256sum --check --strict && \
    dpkg --install "${wasi_deb}" "${clang_rt_deb}" && \
    test "$(dpkg-query -W -f='${Version}' wasi-libc)" = "${WASI_LIBC_VERSION}" && \
    test "$(dpkg-query -W -f='${Version}' libclang-rt-17-dev-wasm32)" = \
        "${CLANG_RT_WASM32_VERSION}"
