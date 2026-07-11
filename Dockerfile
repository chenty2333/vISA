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
