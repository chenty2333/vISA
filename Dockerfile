FROM debian:stable-slim

ARG RUST_TOOLCHAIN=nightly
ARG USERNAME=visa
ARG USER_UID=1000
ARG USER_GID=1000

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:${PATH}
ENV CARGO_TERM_COLOR=always
ENV VISA_LTP_BUILD_BACKEND=host

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

RUN groupadd --gid "${USER_GID}" "${USERNAME}" \
    && useradd --uid "${USER_UID}" --gid "${USER_GID}" -m -s /bin/bash "${USERNAME}" \
    && mkdir -p \
        /workspace/target \
        /usr/local/cargo/git \
        /usr/local/cargo/registry \
        /home/"${USERNAME}"/.cache/visa-ltp \
    && chown -R "${USERNAME}:${USERNAME}" \
        /workspace \
        /usr/local/cargo \
        /usr/local/rustup \
        /home/"${USERNAME}"/.cache \
    && echo "${USERNAME} ALL=(root) NOPASSWD:ALL" >/etc/sudoers.d/"${USERNAME}" \
    && chmod 0440 /etc/sudoers.d/"${USERNAME}"

USER ${USERNAME}
WORKDIR /workspace

CMD ["bash"]
