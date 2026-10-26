#
# HostFuzz container image.
#
#   docker build -t hostfuzz .              # usermode + ESP32 + source/native backends
#   docker build -t hostfuzz:full --target full .   # adds the Fuzzware runtime
#
# The build is multi-stage: the Rust/QEMU toolchain never reaches the runtime
# image, and the Fuzzware Python environment is only installed for the `full`
# target.

FROM ubuntu:24.04 AS toolchain

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    CARGO_BUILD_JOBS=8

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gpg; \
    mkdir -p /etc/apt/keyrings; \
    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /etc/apt/keyrings/llvm.gpg; \
    echo "deb [signed-by=/etc/apt/keyrings/llvm.gpg] http://apt.llvm.org/noble/ llvm-toolchain-noble-20 main" > /etc/apt/sources.list.d/llvm20.list; \
    rm -rf /var/lib/apt/lists/*

RUN dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y --no-install-recommends \
        bash \
        bc \
        bison \
        build-essential \
        ca-certificates \
        clang-20 \
        cmake \
        curl \
        file \
        flex \
        git \
        libc6:i386 \
        libclang-20-dev \
        libffi-dev \
        libgcrypt20-dev \
        libglib2.0-dev \
        libgpg-error-dev \
        libpixman-1-dev \
        libsdl2-dev \
        libslirp-dev \
        libssl-dev \
        libstdc++6:i386 \
        lld-20 \
        llvm-20 \
        llvm-20-dev \
        make \
        ninja-build \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv \
        python3-yaml \
        wget \
        zlib1g-dev \
    && ln -sf /usr/bin/clang-20 /usr/local/bin/clang \
    && ln -sf /usr/bin/clang++-20 /usr/local/bin/clang++ \
    && ln -sf /usr/bin/lld-20 /usr/local/bin/lld \
    && ln -sf /usr/bin/llvm-config-20 /usr/local/bin/llvm-config \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain "1.90.0" && \
    rustc --version | grep -F "rustc 1.90.0 (1159e78c4 2025-09-14)" && \
    cargo --version

# --------------------------------------------------------------------------- #
# Rust fuzzers + QEMU
# --------------------------------------------------------------------------- #
FROM toolchain AS builder

WORKDIR /src

COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY apps ./apps
COPY deps ./deps

# The repository .cargo/config.toml points LIBAFL_QEMU_DIR at the vendored QEMU.
# Build sequentially: the QEMU build directory is reconfigured per target.
RUN set -eux; \
    cd /src/apps/src_fuzzer && cargo build --release; \
    cd /src/apps/fuzzware_fuzzer && cargo build --release; \
    cd /src/apps/simulator && cargo build --release; \
    cd /src/apps/usermode_fuzzer && CARGO_TARGET_DIR=./target-x86_64 cargo build --release --features x86_64; \
    cd /src/apps/esp32_fuzzer && cargo build --release; \
    mkdir -p /out; \
    cp /src/apps/usermode_fuzzer/target-x86_64/release/usermode_fuzzer /out/; \
    cp /src/apps/usermode_fuzzer/target-x86_64/release/rq4_input_dump /out/; \
    cp /src/apps/usermode_fuzzer/target-x86_64/release/rq4_input_patch /out/; \
    cp /src/apps/esp32_fuzzer/target/release/esp32_fuzzer /out/; \
    cp /src/apps/src_fuzzer/target/release/src_fuzzer /out/; \
    cp /src/apps/fuzzware_fuzzer/target/release/fuzzware_fuzzer /out/; \
    cp /src/apps/simulator/target/release/simulator /out/

# --------------------------------------------------------------------------- #
# Optional Fuzzware runtime (used by the nRF52 / Zephyr case)
# --------------------------------------------------------------------------- #
FROM toolchain AS fuzzware-env

ENV FUZZWARE_ROOT=/opt/fuzzware \
    FUZZWARE_ENVS=/opt/venvs \
    FUZZWARE_HARNESS_PYTHON=/opt/venvs/fuzzware/bin/python \
    FUZZWARE_MODELING_PYTHON=/opt/venvs/fuzzware-modeling/bin/python \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN set -eux; \
    mkdir -p "${FUZZWARE_ROOT}" "${FUZZWARE_ENVS}"; \
    python3 -m venv "${FUZZWARE_ENVS}/fuzzware"; \
    python3 -m venv "${FUZZWARE_ENVS}/fuzzware-modeling"; \
    git clone --depth 1 --recursive --shallow-submodules https://github.com/fuzzware-fuzzer/fuzzware "${FUZZWARE_ROOT}"; \
    cd "${FUZZWARE_ROOT}"; \
    git submodule update --init --recursive; \
    "${FUZZWARE_HARNESS_PYTHON}" -m pip install --upgrade pip 'setuptools<81' wheel cython; \
    "${FUZZWARE_MODELING_PYTHON}" -m pip install --upgrade pip 'setuptools<81' wheel; \
    test -d "${FUZZWARE_ROOT}/emulator/unicorn/fuzzware-unicorn"; \
    "${FUZZWARE_HARNESS_PYTHON}" -m pip install -r "${FUZZWARE_ROOT}/emulator/requirements.txt"; \
    PYTHON=/usr/bin/python3 UNICORN_ARCHS="arm" make -C "${FUZZWARE_ROOT}/emulator/unicorn/fuzzware-unicorn" clean all; \
    (cd "${FUZZWARE_ROOT}/emulator/unicorn/fuzzware-unicorn/bindings/python" && UNICORN_ARCHS="arm" "${FUZZWARE_HARNESS_PYTHON}" setup.py install); \
    make -C "${FUZZWARE_ROOT}/emulator/harness/fuzzware_harness/native" clean all; \
    "${FUZZWARE_HARNESS_PYTHON}" -m pip install -e "${FUZZWARE_ROOT}/emulator/harness"; \
    "${FUZZWARE_HARNESS_PYTHON}" -m pip install -r "${FUZZWARE_ROOT}/pipeline/requirements.txt"; \
    "${FUZZWARE_HARNESS_PYTHON}" -m pip install -e "${FUZZWARE_ROOT}/pipeline"; \
    "${FUZZWARE_MODELING_PYTHON}" -m pip install -r "${FUZZWARE_ROOT}/modeling/requirements.txt"; \
    "${FUZZWARE_MODELING_PYTHON}" -m pip install -e "${FUZZWARE_ROOT}/modeling"; \
    "${FUZZWARE_MODELING_PYTHON}" -m pip install --upgrade 'pycparser<3'; \
    "${FUZZWARE_HARNESS_PYTHON}" -m pip install --upgrade 'setuptools<81'; \
    "${FUZZWARE_MODELING_PYTHON}" -m pip install --upgrade 'setuptools<81'; \
    "${FUZZWARE_HARNESS_PYTHON}" -c "import fuzzware_harness"; \
    "${FUZZWARE_MODELING_PYTHON}" -c "import fuzzware_modeling"

# --------------------------------------------------------------------------- #
# Runtime image
# --------------------------------------------------------------------------- #
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    HOSTFUZZ_ROOT=/opt/hostfuzz \
    HOSTFUZZ_BIN_DIR=/opt/hostfuzz/bin \
    HOSTFUZZ_OUTPUT=/outputs

RUN dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        file \
        iproute2 \
        libc6:i386 \
        libgcrypt20 \
        libgcc-s1:i386 \
        libglib2.0-0t64 \
        libgpg-error0 \
        libpixman-1-0 \
        libsdl2-2.0-0 \
        libslirp0 \
        libstdc++6 \
        libstdc++6:i386 \
        procps \
        python3 \
        python3-matplotlib \
        python3-numpy \
        python3-yaml \
        tcpdump \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hostfuzz

COPY --from=builder /out/ ./bin/
COPY demo ./demo
COPY experiments ./experiments
COPY scripts ./scripts
COPY docs ./docs
COPY README.md README.zh-CN.md LICENSE-MIT LICENSE-APACHE NOTICE CITATION.cff ./
COPY docker/entrypoint.sh /usr/local/bin/hostfuzz-entrypoint

RUN chmod +x /usr/local/bin/hostfuzz-entrypoint /opt/hostfuzz/bin/* && \
    mkdir -p /outputs && \
    ln -s /opt/hostfuzz/bin/usermode_fuzzer /usr/local/bin/usermode_fuzzer && \
    ln -s /opt/hostfuzz/bin/esp32_fuzzer /usr/local/bin/esp32_fuzzer && \
    ln -s /opt/hostfuzz/bin/src_fuzzer /usr/local/bin/src_fuzzer && \
    ln -s /opt/hostfuzz/bin/fuzzware_fuzzer /usr/local/bin/fuzzware_fuzzer && \
    ln -s /opt/hostfuzz/bin/rq4_input_dump /usr/local/bin/rq4_input_dump && \
    ln -s /opt/hostfuzz/bin/rq4_input_patch /usr/local/bin/rq4_input_patch

VOLUME ["/outputs"]
WORKDIR /outputs
ENTRYPOINT ["/usr/local/bin/hostfuzz-entrypoint"]
CMD ["list"]

# Full image: adds the Fuzzware harness used by the nRF52 case.
# Build with: docker build --target full -t hostfuzz:full .
FROM runtime AS full
COPY --from=fuzzware-env /opt/fuzzware /opt/fuzzware
COPY --from=fuzzware-env /opt/venvs /opt/venvs
ENV PATH=/opt/venvs/fuzzware/bin:/opt/venvs/fuzzware-modeling/bin:$PATH

# Default target: the lightweight runtime (no Fuzzware Python environment).
# This must be the last stage so that a plain `docker build .` is fast.
FROM runtime AS default
