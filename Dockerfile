FROM debian:stable-slim

ARG RUST_TOOLCHAIN=nightly-2026-06-07
ARG USERNAME=visa
ARG USER_UID=1000
ARG USER_GID=1000

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:${PATH}
ENV CARGO_TERM_COLOR=always
ENV VISA_LTP_BUILD_BACKEND=host
ENV VISA_NODE_VERSION=24.15.0
ENV VISA_NODE_V8_VERSION=13.6.233.17-node.48
ENV VISA_NODE_BIN=/usr/local/bin/node

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        bash \
        bison \
        build-essential \
        ca-certificates \
        clang \
        coreutils \
        curl \
        file \
        findutils \
        flex \
        gawk \
        git \
        grep \
        less \
        libc6-dev \
        linux-libc-dev \
        llvm \
        lld \
        m4 \
        make \
        ovmf \
        perl \
        pkgconf \
        python3 \
        python3-yaml \
        qemu-system-x86 \
        sed \
        sudo \
        tar \
        xz-utils \
        zsh \
    && rm -rf /var/lib/apt/lists/*

# Node is a runtime input to the JcoNode reference cell, not a convenience
# package. Install the official release archive and verify the architecture-
# specific digest published in Node's v24.15.0 SHASUMS256.txt.
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) \
            node_arch='x64'; \
            node_sha256='472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6' \
            ;; \
        arm64) \
            node_arch='arm64'; \
            node_sha256='f3d5a797b5d210ce8e2cb265544c8e482eaedcb8aa409a8b46da7e8595d0dda0' \
            ;; \
        *) \
            printf 'unsupported architecture for pinned Node: %s\n' "$(dpkg --print-architecture)" >&2; \
            exit 1 \
            ;; \
    esac; \
    node_archive="node-v${VISA_NODE_VERSION}-linux-${node_arch}.tar.xz"; \
    curl --proto '=https' --tlsv1.2 --fail --show-error --location \
        "https://nodejs.org/dist/v${VISA_NODE_VERSION}/${node_archive}" \
        --output "/tmp/${node_archive}"; \
    printf '%s  %s\n' "${node_sha256}" "/tmp/${node_archive}" | sha256sum -c -; \
    tar --extract --xz --file "/tmp/${node_archive}" \
        --directory /usr/local --strip-components=1; \
    rm "/tmp/${node_archive}"; \
    test "$(node --version)" = "v${VISA_NODE_VERSION}"; \
    test "$(node -p 'process.versions.v8')" = "${VISA_NODE_V8_VERSION}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain none \
    && rustup toolchain install "${RUST_TOOLCHAIN}" \
        --profile minimal \
        --component clippy \
        --component llvm-tools-preview \
        --component rust-src \
        --component rustfmt \
        --target wasm32-unknown-unknown \
        --target x86_64-unknown-none \
    && rustup default "${RUST_TOOLCHAIN}" \
    && printf '%s\n' 'export PATH=/usr/local/cargo/bin:$PATH' >/etc/profile.d/visa-rust.sh

ENV VISA_WACOGO_GO_ARCHIVE=/opt/visa-wacogo/go1.26.5.linux-amd64.tar.gz
ENV VISA_WACOGO_GO=/opt/visa-wacogo/go/bin/go
ENV VISA_WACOGO_MODULE_ZIP=/opt/visa-wacogo/wacogo-module.zip
ENV VISA_WACOGO_GOMODCACHE=/opt/visa-wacogo/gomodcache
ENV VISA_WACOGO_GOMODCACHE_SEED=/opt/visa-wacogo/gomodcache.tar.gz

# Strict Stage 2 uses an exact official linux/amd64 Go distribution and an
# offline module cache. The source lock remains the identity authority: this
# layer checks every duplicated build-time constant against it before fetching
# anything. arm64 remains usable for the other development tiers, but receives
# no Wacogo inputs, so the strict gate fails closed instead of falling back to a
# system Go installation or another ISA.
COPY third_party/wacogo/source-lock.json /tmp/visa-wacogo/source-lock.json
COPY crates/runtime/visa_wacogo/sidecar/go.mod /tmp/visa-wacogo/module/go.mod
COPY crates/runtime/visa_wacogo/sidecar/go.sum /tmp/visa-wacogo/module/go.sum
COPY third_party/runtime-b-qualification/qualification/wacogo-probe/go.mod /tmp/visa-wacogo/qualification/go.mod
COPY third_party/runtime-b-qualification/qualification/wacogo-probe/go.sum /tmp/visa-wacogo/qualification/go.sum
RUN set -eux; \
    python3 -c 'import json, pathlib; lock=json.loads(pathlib.Path("/tmp/visa-wacogo/source-lock.json").read_text()); go=lock["build_toolchain"]["go"]; upstream=lock["upstream"]; assert go == {"distribution":"official-go.dev-release","version":"go1.26.5","os":"linux","arch":"amd64","archive_name":"go1.26.5.linux-amd64.tar.gz","archive_size":66879095,"archive_sha256":"5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053","archive_url":"https://go.dev/dl/go1.26.5.linux-amd64.tar.gz","archive_binary_path":"go/bin/go","binary_sha256":"8da5fd321795754b994c64e3eb8a5a14ff47bd285559a7e876f3c79abafc67f9","version_output":"go version go1.26.5 linux/amd64"}; assert upstream["module"] == "github.com/partite-ai/wacogo"; assert upstream["version"] == "v0.0.0-20260617023329-3de16a61796c"; assert upstream["module_zip"]["size"] == 8838002; assert upstream["module_zip"]["sha256"] == "ffc2004ea59076ef619d3043d4ae4400338cf3a8d2c67b294e582715ce5f26f4"'; \
    mkdir -p /opt/visa-wacogo; \
    if [ "$(dpkg --print-architecture)" = amd64 ]; then \
        curl --proto '=https' --tlsv1.2 --fail --show-error --location \
            --retry 5 --retry-all-errors --retry-delay 2 \
            'https://go.dev/dl/go1.26.5.linux-amd64.tar.gz' \
            --output "${VISA_WACOGO_GO_ARCHIVE}"; \
        test "$(wc -c <"${VISA_WACOGO_GO_ARCHIVE}" | tr -d '[:space:]')" = 66879095; \
        printf '%s  %s\n' \
            '5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053' \
            "${VISA_WACOGO_GO_ARCHIVE}" | sha256sum -c -; \
        tar --extract --gzip --file "${VISA_WACOGO_GO_ARCHIVE}" \
            --directory /opt/visa-wacogo; \
        printf '%s  %s\n' \
            '8da5fd321795754b994c64e3eb8a5a14ff47bd285559a7e876f3c79abafc67f9' \
            "${VISA_WACOGO_GO}" | sha256sum -c -; \
        test "$("${VISA_WACOGO_GO}" version)" = 'go version go1.26.5 linux/amd64'; \
        mkdir -p "${VISA_WACOGO_GOMODCACHE}" /tmp/visa-wacogo/home /tmp/visa-wacogo/go-build; \
        printf '%s  %s\n' \
            '6215baed9e8f18c090dbd4ad5d3262af2e1fa9e6ca44ab7c2eba6ff418569bd9' \
            /tmp/visa-wacogo/qualification/go.mod | sha256sum -c -; \
        printf '%s  %s\n' \
            '4eba5686a0fc26a1955537b059ac41f1ffd892d64bc275273e5d2102b42d4b9f' \
            /tmp/visa-wacogo/qualification/go.sum | sha256sum -c -; \
        for module_dir in \
            /tmp/visa-wacogo/module \
            /tmp/visa-wacogo/qualification; do \
            cd "$module_dir"; \
            env \
                HOME=/tmp/visa-wacogo/home \
                GOCACHE=/tmp/visa-wacogo/go-build \
                GOMODCACHE="${VISA_WACOGO_GOMODCACHE}" \
                GOENV=off \
                GOSUMDB=sum.golang.org \
                GOTELEMETRY=off \
                GOTOOLCHAIN=local \
                GOPROXY=https://proxy.golang.org \
                GOVCS='*:off' \
                GOWORK=off \
                "${VISA_WACOGO_GO}" mod download all; \
        done; \
        cp \
            "${VISA_WACOGO_GOMODCACHE}/cache/download/github.com/partite-ai/wacogo/@v/v0.0.0-20260617023329-3de16a61796c.zip" \
            "${VISA_WACOGO_MODULE_ZIP}"; \
        test "$(wc -c <"${VISA_WACOGO_MODULE_ZIP}" | tr -d '[:space:]')" = 8838002; \
        printf '%s  %s\n' \
            'ffc2004ea59076ef619d3043d4ae4400338cf3a8d2c67b294e582715ce5f26f4' \
            "${VISA_WACOGO_MODULE_ZIP}" | sha256sum -c -; \
        for module_dir in \
            /tmp/visa-wacogo/module \
            /tmp/visa-wacogo/qualification; do \
            cd "$module_dir"; \
            env \
                HOME=/tmp/visa-wacogo/home \
                GOCACHE=/tmp/visa-wacogo/go-build \
                GOMODCACHE="${VISA_WACOGO_GOMODCACHE}" \
                GOENV=off \
                GOSUMDB=off \
                GOTELEMETRY=off \
                GOTOOLCHAIN=local \
                GOPROXY=off \
                GOVCS='*:off' \
                GOWORK=off \
                "${VISA_WACOGO_GO}" mod download all; \
            env \
                GOMODCACHE="${VISA_WACOGO_GOMODCACHE}" \
                GOENV=off \
                GOSUMDB=off \
                GOTELEMETRY=off \
                GOTOOLCHAIN=local \
                GOPROXY=off \
                GOVCS='*:off' \
                GOWORK=off \
                "${VISA_WACOGO_GO}" mod verify; \
        done; \
        tar --create --file /opt/visa-wacogo/gomodcache.tar \
            --directory "${VISA_WACOGO_GOMODCACHE}" .; \
        gzip -n /opt/visa-wacogo/gomodcache.tar; \
        tar --list --gzip --file "${VISA_WACOGO_GOMODCACHE_SEED}" \
            | grep -Fqx './github.com/regclient/regclient@v0.8.3/testdata/.wh.layer2.txt'; \
        tar --list --gzip --file "${VISA_WACOGO_GOMODCACHE_SEED}" \
            | grep -Fqx './github.com/regclient/regclient@v0.8.3/testdata/exdir/.wh..wh..opq'; \
        rm -rf "${VISA_WACOGO_GOMODCACHE}"; \
        chmod -R a-w /opt/visa-wacogo; \
    else \
        printf '%s\n' \
            'Strict Stage 2 Wacogo inputs are unavailable: image is not linux/amd64.' \
            >/opt/visa-wacogo/UNSUPPORTED-ISA; \
        chmod a-w /opt/visa-wacogo/UNSUPPORTED-ISA; \
    fi; \
    rm -rf /tmp/visa-wacogo

# The image layer stores the verified cache as one archive because overlay
# layer export treats dependency files named .wh.* as whiteout metadata. The
# Docker gate materializes this seed into a fresh container-private directory.
ENV VISA_WACOGO_GOMODCACHE=/tmp/visa-wacogo-gomodcache

# Stage 4 is an independent gate layered on the existing development image.
# Keep its relatively large cross toolchain in a late layer so changes here do
# not invalidate the pinned Node and Strict Stage 2 Wacogo acquisition layers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc-aarch64-linux-gnu \
        libc6-dev-arm64-cross \
        qemu-user \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add \
        --toolchain "${RUST_TOOLCHAIN}" \
        aarch64-unknown-linux-gnu

# The bundled SQLite build must use target tools rather than silently emitting
# host objects for the AArch64 worker.
ENV CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
ENV AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar

RUN set -eux; \
    if getent group "${USER_GID}" >/dev/null; then \
        group_name="$(getent group "${USER_GID}" | cut -d: -f1)"; \
    else \
        groupadd --gid "${USER_GID}" "${USERNAME}"; \
        group_name="${USERNAME}"; \
    fi; \
    useradd --uid "${USER_UID}" --gid "${group_name}" -m -s /bin/bash "${USERNAME}"; \
    mkdir -p \
        /workspace/target \
        /usr/local/cargo/git \
        /usr/local/cargo/registry \
        /home/"${USERNAME}"/.cache/visa-ltp; \
    chown -R "${USERNAME}:${group_name}" \
        /workspace \
        /usr/local/cargo \
        /usr/local/rustup \
        /home/"${USERNAME}"/.cache; \
    echo "${USERNAME} ALL=(root) NOPASSWD:ALL" >/etc/sudoers.d/"${USERNAME}"; \
    chmod 0440 /etc/sudoers.d/"${USERNAME}"

USER ${USERNAME}
WORKDIR /workspace

CMD ["bash"]
