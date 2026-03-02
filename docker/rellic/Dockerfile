# Rellic decompiler: LLVM bitcode → structured C
# Build: docker build -t pvm-rellic-decomp docker/rellic/
# Run:   docker run --rm -v /tmp/pvm-decompile:/work pvm-rellic-decomp /work/input.ll /work/output.c
#
# Uses plain ubuntu:22.04 base. build.sh downloads the pre-built
# cxx-common/vcpkg tarball (~1.3GB) containing LLVM 16 + all deps.

FROM ubuntu:22.04 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    curl \
    ca-certificates \
    python3 \
    xz-utils \
    libc6-dev \
    liblzma-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /rellic
RUN git clone --depth 1 https://github.com/lifting-bits/rellic.git . && \
    git submodule update --init --recursive

# build.sh downloads vcpkg_ubuntu-22.04_llvm-16_{arch}.tar.xz,
# configures with vcpkg CMake toolchain, and builds with Ninja.
RUN ./scripts/build.sh \
    --llvm-version 16 \
    --prefix /opt/trailofbits \
    --extra-cmake-args "-DCMAKE_BUILD_TYPE=Release -DRELLIC_ENABLE_TESTING=OFF" \
    --install

# ── Runtime stage (slim) ─────────────────────────────────────────────
FROM ubuntu:22.04

COPY --from=build /opt/trailofbits /opt/trailofbits
ENV PATH="/opt/trailofbits/llvm/bin:/opt/trailofbits/bin:${PATH}"

# Entrypoint wrapper: accepts either .ll or .bc input
# If given a .ll file, assembles it with llvm-as first
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
