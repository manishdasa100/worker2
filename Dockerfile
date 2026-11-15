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

WORKDIR /opt/executor
COPY *.py ./
COPY languages/ languages/
COPY sandbox/ sandbox/

ENV NSJAIL_PATH=/usr/local/bin/nsjail \
    NSJAIL_RUN_CONFIG_PATH=/opt/executor/sandbox/run.cfg \
    NSJAIL_COMPILE_CONFIG_PATH=/opt/executor/sandbox/compile.cfg \
    EXECUTOR_SOCKET=/run/executor/executor.sock

CMD ["python3", "-u", "executor.py"]
