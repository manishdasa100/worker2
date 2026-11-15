# Executor image: one per slot, run under runsc with --network=none (ADR-0001).
# Holds nsjail, the toolchains and the executor; no secrets.
#
#   docker build -t codinglemons-executor .

FROM ubuntu:24.04 AS nsjail
# nsjail tag 3.6
ARG NSJAIL_COMMIT=f78475530b46d0186111a9096b30725f816b55fe
RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf bison ca-certificates flex g++ gcc git libnl-route-3-dev \
        libprotobuf-dev libtool make pkg-config protobuf-compiler \
 && git clone https://github.com/google/nsjail.git /nsjail \
 && git -C /nsjail checkout "$NSJAIL_COMMIT" \
 && git -C /nsjail submodule update --init \
 && make -C /nsjail -j2

FROM ubuntu:24.04 AS go
# Go 1.24, the official release, checked against go.dev's published sha256. The
# standard library is compiled once here (CGO off, so every binary links static)
# into its own cache, with an importcfg naming each package's archive: jobs
# compile and link against it read-only and never share a writable build cache.
ARG GO_VERSION=1.24.13
ARG GO_SHA256=1fc94b57134d51669c72173ad5d49fd62afb0f1db9bf3f798fd98ee423f8d730
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL -o /go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
 && echo "${GO_SHA256}  /go.tgz" | sha256sum -c - \
 && tar -C /usr/local -xzf /go.tgz \
 && mkdir -p /opt/go-std \
 && env -i PATH=/usr/local/go/bin:/usr/bin:/bin HOME=/tmp GOCACHE=/opt/go-std/cache \
        GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-trimpath \
        go list -export -f '{{if .Export}}packagefile {{.ImportPath}}={{.Export}}{{end}}' std \
        > /opt/go-std/importcfg

FROM ubuntu:24.04 AS node
# Node 22 LTS, the official release, checked against nodejs.org's SHASUMS256.txt.
# Only the node binary is kept: no npm, no bundled node_modules.
ARG NODE_VERSION=22.23.5
ARG NODE_SHA256=cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && curl -fsSL -o /node.txz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
 && echo "${NODE_SHA256}  /node.txz" | sha256sum -c - \
 && mkdir -p /opt/node/bin \
 && tar -xJf /node.txz -C /opt/node/bin --strip-components=2 "node-v${NODE_VERSION}-linux-x64/bin/node"

FROM ubuntu:24.04 AS rust
# Rust stable, exactly pinned: just rustc and the x86_64 gnu standard library, from
# static.rust-lang.org's tarballs, checked against their published sha256.
ARG RUST_VERSION=1.100.0
ARG RUSTC_SHA256=f1d0b1dec81dab6f523cd098507763487b0d4bd7fd2c87582f154128719be03b
ARG RUST_STD_SHA256=4591b6486594ded52ecd6135db95bf9355bbd3ca7a380888b141528bbcf9a5d4
ARG RUST_DIST=https://static.rust-lang.org/dist
ARG RUST_TARGET=x86_64-unknown-linux-gnu
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && cd /tmp \
 && curl -fsSL -o rustc.txz "${RUST_DIST}/rustc-${RUST_VERSION}-${RUST_TARGET}.tar.xz" \
 && echo "${RUSTC_SHA256}  rustc.txz" | sha256sum -c - \
 && curl -fsSL -o rust-std.txz "${RUST_DIST}/rust-std-${RUST_VERSION}-${RUST_TARGET}.tar.xz" \
 && echo "${RUST_STD_SHA256}  rust-std.txz" | sha256sum -c - \
 && tar -xJf rustc.txz && tar -xJf rust-std.txz \
 && "rustc-${RUST_VERSION}-${RUST_TARGET}/install.sh" --prefix=/opt/rust --disable-ldconfig \
 && "rust-std-${RUST_VERSION}-${RUST_TARGET}/install.sh" --prefix=/opt/rust --disable-ldconfig
# Keep rustc, its shared libraries and the standard library. Jobs link with the
# system gcc, so rust-lld (rustlib/*/bin) goes too.
RUN cd /opt/rust && rm -rf share etc libexec bin/rust-gdb bin/rust-gdbgui bin/rust-lldb bin/rustdoc \
        lib/rustlib/etc lib/rustlib/x86_64-unknown-linux-gnu/bin lib/rustlib/[!x]*

FROM ubuntu:24.04
# Toolchains, pinned by major version through the 24.04 package names: Python 3.12
# (python3), GCC 13 for C and C++ (g++-13 brings gcc-13 and the static libc and
# libstdc++), Java 21.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 g++-13 openjdk-21-jdk-headless libnl-route-3-200 libprotobuf32t64 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=nsjail /nsjail/nsjail /usr/local/bin/nsjail
# Only what a job's compile needs: the compiler, the linker and the prebuilt standard library.
COPY --from=go /usr/local/go/pkg/tool/linux_amd64/compile /usr/local/go/pkg/tool/linux_amd64/link \
     /usr/local/go/pkg/tool/linux_amd64/
COPY --from=go /opt/go-std /opt/go-std
COPY --from=node /opt/node /opt/node
COPY --from=rust /opt/rust /opt/rust

WORKDIR /opt/executor
COPY *.py ./
COPY languages/ languages/
COPY sandbox/ sandbox/

ENV NSJAIL_PATH=/usr/local/bin/nsjail \
    NSJAIL_RUN_CONFIG_PATH=/opt/executor/sandbox/run.cfg \
    NSJAIL_COMPILE_CONFIG_PATH=/opt/executor/sandbox/compile.cfg \
    EXECUTOR_SOCKET=/run/executor/executor.sock

CMD ["python3", "-u", "executor.py"]
