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

FROM ubuntu:24.04
# python3 is 3.12 on 24.04. `time` is the GNU time run wrapper (removed in 10).
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 time libnl-route-3-200 libprotobuf32t64 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=nsjail /nsjail/nsjail /usr/local/bin/nsjail

WORKDIR /opt/executor
COPY *.py ./
COPY languages/ languages/
COPY sandbox/ sandbox/

ENV NSJAIL_PATH=/usr/local/bin/nsjail \
    NSJAIL_RUN_CONFIG_PATH=/opt/executor/sandbox/run.cfg \
    NSJAIL_COMPILE_CONFIG_PATH=/opt/executor/sandbox/compile.cfg \
    EXECUTOR_SOCKET=/run/executor/executor.sock

CMD ["python3", "-u", "executor.py"]
